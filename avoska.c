#include <event.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

//#include "config.h"
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/signal.h>
#include <sys/resource.h>
#include <sys/uio.h>

/* some POSIX systems need the following definition
 * to get mlockall flags out of sys/mman.h.  */
#ifndef _P1003_1B_VISIBLE
#define _P1003_1B_VISIBLE
#endif
/* need this to get IOV_MAX on some platforms. */
#ifndef __need_IOV_MAX
#define __need_IOV_MAX
#endif
#include <pwd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <assert.h>
#include <limits.h>

#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif


#include "avoska.h"

/* FreeBSD 4.x doesn't have IOV_MAX exposed. */
#ifndef IOV_MAX
#if defined(__FreeBSD__)
# define IOV_MAX 1024
#endif
#endif

#define TRANSMIT_COMPLETE   0
#define TRANSMIT_INCOMPLETE 1
#define TRANSMIT_SOFT_ERROR 2
#define TRANSMIT_HARD_ERROR 3

int l_socket=0;

struct stats stats;
struct settings settings;


void settings_init( void ) {
    settings.port = 11211;
    settings.interface.s_addr = htonl(INADDR_ANY);
    settings.verbose = 0;
    settings.maxbytes = 64*1024*1024; /* default is 64MB */
    settings.factor = 1.25;
}

int *buckets = 0; /* bucket->generation array for a managed instance */

#define REALTIME_MAXDELTA 60*60*24*30
rel_time_t realtime(time_t exptime) {
    /* no. of seconds in 30 days - largest possible delta exptime */

    if (exptime == 0) return 0; /* 0 means never expire */

    if (exptime > REALTIME_MAXDELTA)
        return (rel_time_t) (exptime - stats.started);
    else {
        return (rel_time_t) (exptime + current_time);
    }
}

/*
 * Reallocates memory and updates a buffer size if successful.
 */
int do_realloc(void **orig, int newsize, int bytes_per_item, int *size) {
    void *newbuf = realloc(*orig, newsize * bytes_per_item);
    if (newbuf) {
        *orig = newbuf;
        *size = newsize;
       return 1;
    }
    return 0;
}

 /*
 * Shrinks a connection's buffers if they're too big.  This prevents
 * periodic large "get" requests from permanently chewing lots of server
 * memory.
 *
 * This should only be called in between requests since it can wipe output
 * buffers!
 */
void conn_shrink(conn *c) {
    if (c->rsize > READ_BUFFER_HIGHWAT && c->rbytes < DATA_BUFFER_SIZE) {
       do_realloc((void **)&c->rbuf, DATA_BUFFER_SIZE, 1, &c->rsize);
    }
/*
    if (c->isize > ITEM_LIST_HIGHWAT) {
        do_realloc((void **)&c->ilist, ITEM_LIST_INITIAL, sizeof(c->ilist[0]), &c->isize);
    }

    if (c->msgsize > MSG_LIST_HIGHWAT) {
        do_realloc((void **)&c->msglist, MSG_LIST_INITIAL, sizeof(c->msglist[0]), &c->msgsize);
    }

    if (c->iovsize > IOV_LIST_HIGHWAT) {
        do_realloc((void **)&c->iov, IOV_LIST_INITIAL, sizeof(c->iov[0]), &c->iovsize);
    }
*/
}

void conn_set_state(conn *c, int state) {
    if (state != c->state) {
        if (state == conn_read) {
            conn_shrink(c);
        }
        c->state = state;
    }
}

void out_string(conn *c, char *str) {
    int len;

    if (settings.verbose > 1)
        fprintf(stderr, ">%d %s\n", c->sfd, str);

    len = strlen(str);
    if (len + 2 > c->wsize) {
        /* ought to be always enough. just fail for simplicity */
        str = "SERVER_ERROR output line too long";
        len = strlen(str);
    }

    strcpy(c->wbuf, str);
    strcpy(c->wbuf + len, "\r\n");
    c->wbytes = len + 2;
    c->wcurr = c->wbuf;

    conn_set_state(c, conn_write);
    c->write_and_go = conn_read;
    return;
}

int item_delete_lock_over (item *it) {
    assert(it->it_flags & ITEM_DELETED);
    return (current_time >= it->exptime);
}

/* wrapper around assoc_find which does the lazy expiration/deletion logic */
item *get_item_notedeleted(char *key, int *delete_locked) {
    item *it = assoc_find(key);
    if (delete_locked) *delete_locked = 0;
    if (it && (it->it_flags & ITEM_DELETED)) {
        if (! item_delete_lock_over(it)) {
            if (delete_locked) *delete_locked = 1;
            it = 0;
        }
    }
    if (it && settings.oldest_live && settings.oldest_live <= current_time &&
        it->time <= settings.oldest_live) {
        item_unlink(it);
        it = 0;
    }
    if (it && it->exptime && it->exptime <= current_time) {
        item_unlink(it);
        it = 0;
    }

    return it;
}

void conn_cleanup(conn *c) {
    if (c->item) {
        item_free(c->item);
        c->item = 0;
    }

}

void conn_close(conn *c) {
    event_del(&c->event);

    if (settings.verbose > 1)
        fprintf(stderr, "<%d connection closed.\n", c->sfd);

    close(c->sfd);
    conn_cleanup(c);

}

void complete_nread(conn *c) {
    item *it = c->item;
    int comm = c->item_comm;
    item *old_it;
    int delete_locked = 0;
    char *key = ITEM_key(it);

    stats.set_cmds++;

    if (strncmp(ITEM_data(it) + it->nbytes - 2, "\r\n", 2) != 0) {
        out_string(c, "CLIENT_ERROR bad data chunk");
        goto err;
    }

    old_it = get_item_notedeleted(key, &delete_locked);

    if (old_it && comm == NREAD_ADD) {
        item_update(old_it);
        out_string(c, "NOT_STORED");
        goto err;
    }

    if (!old_it && comm == NREAD_REPLACE) {
        out_string(c, "NOT_STORED");
        goto err;
    }

    if (delete_locked) {
        if (comm == NREAD_REPLACE || comm == NREAD_ADD) {
            out_string(c, "NOT_STORED");
            goto err;
        }

        /* but "set" commands can override the delete lock
         window... in which case we have to find the old hidden item
         that's in the namespace/LRU but wasn't returned by
         get_item.... because we need to replace it (below) */
        old_it = assoc_find(key);
    }

    if (old_it)
        item_replace(old_it, it);
    else
        item_link(it);

    c->item = 0;
    out_string(c, "STORED");
    return;

err:
     item_free(it);
     c->item = 0;
     return;
}

int update_event(conn *c, int new_flags) {
    if (c->ev_flags == new_flags)
        return 1;
    if (event_del(&c->event) == -1) return 0;
    event_set(&c->event, c->sfd, new_flags, event_handler, (void *)c);
    c->ev_flags = new_flags;
    if (event_add(&c->event, 0) == -1) return 0;
    return 1;
}

int new_socket() {
    int sfd;
    int flags;

    if ((sfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket()");
        return -1;
    }

    if ((flags = fcntl(sfd, F_GETFL, 0)) < 0 ||
       fcntl(sfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("setting O_NONBLOCK");
        close(sfd);
        return -1;
    }

    return sfd;
}

int server_socket(int port) {
    int sfd;
    int flags = 1;
    struct linger ling = {0, 0};
    struct sockaddr_in addr;

    if((sfd = new_socket()) == -1) {
        perror("socket()");
        return -1;
    }

    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &flags, sizeof(flags));
    setsockopt(sfd, SOL_SOCKET, SO_KEEPALIVE, &flags, sizeof(flags));
    setsockopt(sfd, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling));
    setsockopt(sfd, IPPROTO_TCP, TCP_NODELAY, &flags, sizeof(flags));

    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr = settings.interface;

    if (bind(sfd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
        perror("bind()");
        close(sfd);
        return -1;
    }

    if(listen(sfd, 1024) == -1) {
        perror("listen()");
        close(sfd);
        return -1;
    }

    return sfd;
}

conn **freeconns;
int freetotal;
int freecurr;

void conn_init(void) {
    freetotal = 200;
    freecurr = 0;
    freeconns = (conn **)malloc(sizeof (conn *)*freetotal);
    return;
}

void stats_init(void) {
    stats.curr_conns = stats.total_conns = stats.conn_structs = 0;

    stats.started = time(0) - 1;
    stats.bytes_read = 0;
}

conn* conn_new(int sfd, int init_state, int event_flags, int read_buffer_size) {
    conn *c;

    /* do we have a free conn structure from a previous close? */
    if (freecurr > 0) {
        c = freeconns[--freecurr];
    } else { /* allocate a new one */
       if (!(c = (conn *)malloc(sizeof(conn)))) {
            perror("malloc()");
            return 0;
        }
        c->rbuf = c->wbuf = 0;
        c->iov = 0;
        c->msglist = 0;
        c->hdrbuf = 0;

        c->rsize = read_buffer_size;
        c->wsize = DATA_BUFFER_SIZE;
        c->isize = ITEM_LIST_INITIAL;
        c->iovsize = IOV_LIST_INITIAL;
        c->msgsize = MSG_LIST_INITIAL;
        c->hdrsize = 0;

        c->rbuf = (char *) malloc(c->rsize);
        c->wbuf = (char *) malloc(c->wsize);
        c->ilist = (item **) malloc(sizeof(item *) * c->isize);
        c->iov = (struct iovec *) malloc(sizeof(struct iovec) * c->iovsize);
        c->msglist = (struct msghdr *) malloc(sizeof(struct msghdr) * c->msgsize);

        if (c->rbuf == 0 || c->wbuf == 0 ||
                c->msglist == 0) {
            if (c->rbuf != 0) free(c->rbuf);
            if (c->wbuf != 0) free(c->wbuf);
            if (c->msglist != 0) free(c->msglist);
            free(c);
            perror("malloc()");
            return 0;
        }

        stats.conn_structs++;
    }

    if (settings.verbose > 1) {
        if (init_state == conn_listening)
            fprintf(stderr, "<%d server listening\n", sfd);
        else
            fprintf(stderr, "<%d new client connection\n", sfd);
    }

    c->sfd = sfd;
    c->state = init_state;
    c->rlbytes = 0;
    c->rbytes = c->wbytes = 0;
    c->wcurr = c->wbuf;
    c->rcurr = c->rbuf;
    c->ritem = 0;
    c->ileft = 0;
    c->iovused = 0;
    c->msgcurr = 0;
    c->msgused = 0;

    c->write_and_go = conn_read;
    c->write_and_free = 0;
    c->item = 0;
    c->bucket = -1;
    c->gen = 0;

    event_set(&c->event, sfd, event_flags, event_handler, (void *)c);

    c->ev_flags = event_flags;

    if (event_add(&c->event, 0) == -1) {
        if(freecurr < freetotal) {
            freeconns[freecurr++] = c;
        } else {
            if (c->hdrbuf)
                free (c->hdrbuf);
            free (c->msglist);
            free (c->rbuf);
            free (c->wbuf);
            free (c->iov);
            free (c);
        }

        return 0;
    }

    stats.curr_conns++;
    stats.total_conns++;

    return c;
}

int add_msghdr(conn *c)
{
    struct msghdr *msg;

    if (c->msgsize == c->msgused) {
        msg = realloc(c->msglist, c->msgsize * 2 * sizeof(struct msghdr));
        if (! msg)
            return -1;
        c->msglist = msg;
        c->msgsize *= 2;
    }

    msg = c->msglist + c->msgused;

    memset(msg, 0, sizeof(struct msghdr));

    msg->msg_iov = &c->iov[c->iovused];
    msg->msg_name = &c->request_addr;
    msg->msg_namelen = c->request_addr_size;

    c->msgbytes = 0;
    c->msgused++;

    return 0;
}

int ensure_iov_space(conn *c) {
    if (c->iovused >= c->iovsize) {
        int i, iovnum;
        struct iovec *new_iov = (struct iovec *) realloc(c->iov,
                                (c->iovsize * 2) * sizeof(struct iovec));
        if (! new_iov)
            return -1;
        c->iov = new_iov;
        c->iovsize *= 2;

        for (i = 0, iovnum = 0; i < c->msgused; i++) {
            c->msglist[i].msg_iov = &c->iov[iovnum];
            iovnum += c->msglist[i].msg_iovlen;
        }
    }
    return 0;
}

int add_iov(conn *c, const void *buf, int len) {
    struct msghdr *m;
    int i;

    m = &c->msglist[c->msgused - 1];

    if (m->msg_iovlen == IOV_MAX) {
        add_msghdr(c);
        m = &c->msglist[c->msgused - 1];
    }

    if (ensure_iov_space(c))
        return -1;

    m = &c->msglist[c->msgused - 1];

    m->msg_iov[m->msg_iovlen].iov_base = (void*) buf;
    m->msg_iov[m->msg_iovlen].iov_len = len;

    c->msgbytes += len;
    c->iovused++;
    m->msg_iovlen++;

    buf = ((char *)buf) + len;

    return 0;
}

void drive_machine(conn *c) {
    int exit = 0;
    int sfd, flags = 1;
    socklen_t addrlen;
    struct sockaddr addr;
    conn *newc;
    int res;

    while(!exit) {
        switch(c->state) {
        case conn_listening:
            addrlen = sizeof(addr);
            if((sfd = accept(c->sfd, &addr, &addrlen)) == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    exit = 1;
                    break;
                } else {
                    perror("accept()");
                }
                break;
            }
            if((flags = fcntl(sfd, F_GETFL, 0)) < 0 ||
               fcntl(sfd, F_SETFL, flags | O_NONBLOCK) < 0) {
                perror("setting O_NONBLOCK");
                close(sfd);
                break;
            }
            newc = conn_new(sfd, conn_read, EV_READ | EV_PERSIST, DATA_BUFFER_SIZE);
            if (!newc) {
                if (settings.verbose > 0)
                    fprintf(stderr, "couldn't create new connection\n");
                close(sfd);
                break;
            }

            break;
        case conn_read:
            if(try_read_command(c)) {
                //continue;
            }

            if(try_read_network(c)) {
                continue;
            }

            if (!update_event(c, EV_READ | EV_PERSIST)) {
                if (settings.verbose > 0)
                    fprintf(stderr, "Couldn't update event\n");
                conn_set_state(c, conn_closing);
                break;
            }
            exit = 1;
            break;
        case conn_nread:
            if (c->rlbytes == 0) {
                complete_nread(c);
                break;
            }
            if (c->rbytes > 0) {
                int tocopy = c->rbytes > c->rlbytes ? c->rlbytes : c->rbytes;
                memcpy(c->ritem, c->rcurr, tocopy);
                c->ritem += tocopy;
                c->rlbytes -= tocopy;
                c->rcurr += tocopy;
                c->rbytes -= tocopy;
                break;
            }

            res = read(c->sfd, c->ritem, c->rlbytes);
            if(res > 0) {
                stats.bytes_read += res;
                c->ritem += res;
                c->rlbytes -= res;
                break;
            }
            if(res == 0) {
                conn_set_state(c, conn_closing);
                break;
            }
            if(res == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                if(!update_event(c, EV_READ | EV_PERSIST)) {
                    if (settings.verbose > 0)
                        fprintf(stderr, "Couldn't update event\n");
                    conn_set_state(c, conn_closing);
                    break;
                }
                exit = 1;
                break;
            }
            if (settings.verbose > 0)
                fprintf(stderr, "Failed to read, and not due to blocking\n");
            conn_set_state(c, conn_closing);
            break;

        case conn_swallow:
            break;
        case conn_write:
            if (c->iovused == 0) {
                if (add_iov(c, c->wcurr, c->wbytes)) {
                    if (settings.verbose > 0)
                        fprintf(stderr, "Couldn't build response\n");
                    conn_set_state(c, conn_closing);
                    break;
                }
            }
        case conn_closing:
            conn_close(c);
            exit = 1;
            break;
        }
    }

    return;
}

void event_handler(int fd, short which, void *arg) {
    conn *c;

    c = (conn *)arg;
    c->which = which;

    if (fd != c->sfd) {
        printf("close\n");
        return;
    }
    printf("drive_machine %d\n", fd);

    /* do as much I/O as possible until we block */
    drive_machine(c);

    /* wait for next event */
    return;
}

int try_read_command(conn *c) {
    char *el, *cont;

    if(!c->rbytes)
        return 0;
    el = memchr(c->rcurr, '\n', c->rbytes);
    if(!el)
        return 0;
    cont = el + 1;
    if(el - c->rcurr > 1 && *(el - 1) == '\r') {
        el--;
    }
    *el = '\0';

    process_command(c, c->rcurr);

    c->rbytes -= (cont - c->rcurr);
    c->rcurr = cont;

    return 1;
}

void process_command(conn *c, char *command) {
    int comm = 0;

    if(settings.verbose > 1)
        fprintf(stderr, "<%d %s\n", c->sfd, command);

    c->msgcurr = 0;
    c->msgused = 0;
    c->iovused = 0;
    if(add_msghdr(c)) {
        out_string(c, "SERVER_ERROR out of memory");
        return;
    }

    if((strncmp(command, "add ", 4) == 0 && (comm = NREAD_ADD)) ||
       (strncmp(command, "set ", 4) == 0 && (comm = NREAD_SET)) ||
       (strncmp(command, "replace ", 8) == 0 && (comm = NREAD_REPLACE))) {

        char key[251];
        int flags;
        time_t expire;
        int len, res;
        item *it;

        res = sscanf(command, "%*s %250s %u %ld %d\n", key, &flags, &expire, &len);

        if(res != 4 || strlen(key) == 0) {
            out_string(c, "CLIENT_ERROR bad command line format");
            return;
        }

        expire = realtime(expire);
        it = item_alloc(key, flags, expire, len+2);

        c->item_comm = comm;
        c->item = it;
        c->ritem = ITEM_data(it);
        c->rlbytes = it->nbytes;
        conn_set_state(c, conn_nread);
        return;
    }
}

int try_read_network(conn *c) {
    int gotdata = 0;
    int res;

    if(c->rcurr != c->rbuf) {
        if(c->rbytes != 0)
            memmove(c->rbuf, c->rcurr, c->rbytes);
        c->rcurr = c->rbuf;
    }

    while(1) {
        if(c->rbytes >= c->rsize) {
            char *new_buf = realloc(c->rbuf, c->rsize * 2);
            if(!new_buf) {
                if (settings.verbose > 0)
                    fprintf(stderr, "Couldn't realloc input buffer\n");
                c->rbytes = 0;
                out_string(c, "SERVER_ERROR out of memory");
                c->write_and_go = conn_closing;
                return 1;
            }
            c->rcurr = c->rbuf = new_buf;
            c->rsize *= 2;
        }

        res = read(c->sfd, c->rbuf + c->rbytes, c->rsize - c->rbytes);
        if(res > 0) {
            stats.bytes_read += res;
            gotdata = 1;
            c->rbytes += res;
            continue;
        }
        if(res == 0) {
            conn_set_state(c, conn_closing);
            return 1;
        }
        if(res == -1) {
            if(errno == EAGAIN || errno == EWOULDBLOCK) break;
            else return 0;
        }
    }

    return gotdata;
}

struct event deleteevent;

void delete_handler(int fd, short which, void *arg) {
    struct timeval t;
    static int initialized = 0;

    if (initialized) {
        /* some versions of libevent don't like deleting events that don't exist,
           so only delete once we know this event has been added. */
        evtimer_del(&deleteevent);
    } else {
        initialized = 1;
    }

    evtimer_set(&deleteevent, delete_handler, 0);
    t.tv_sec = 5; t.tv_usec=0;
    evtimer_add(&deleteevent, &t);
}

volatile rel_time_t current_time;
struct event clockevent;

/* time-sensitive callers can call it by hand with this, outside the normal ever-1-second timer */
void set_current_time () {
    current_time = (rel_time_t) (time(0) - stats.started);
}

void clock_handler(int fd, short which, void *args) {
    struct timeval t;
    static int initialized = 0;

    if (initialized) {
        /* only delete the event if it's actually there. */
        event_del(&clockevent);
    } else {
        initialized = 1;
    }

    evtimer_set(&clockevent, clock_handler, 0);
    t.tv_sec = 1;
    t.tv_usec = 0;
    evtimer_add(&clockevent, &t);

    set_current_time();
}

void sig_handler(int sig) {
    printf("SIGINT handled.\n");
    exit(0);
}

int main(int argc, char **argv) {
    int c;
    conn *l_conn;
    struct passwd *pw;
    char *username = 0;

    /* handle SIGINT */
    signal(SIGINT, sig_handler);

    settings_init();

    /* set stderr non-buffering (for running under, say, daemontools) */
    setbuf(stderr, NULL);

    while ((c = getopt(argc, argv, "vshp:")) != -1) {
        switch(c) {
        case 'v':
            settings.verbose++;
            break;
        case 'p':
            settings.port = atoi(optarg);
            break;
        }
    }

    if((l_socket = server_socket(settings.port)) == -1) {
        fprintf(stderr, "failed to listen\n");
        exit(1);
    }

    /* lose root privileges if we have them */
    if (getuid()== 0 || geteuid()==0) {
        if (username==0 || *username=='\0') {
            fprintf(stderr, "can't run as root without the -u switch\n");
            return 1;
        }
        if ((pw = getpwnam(username)) == 0) {
            fprintf(stderr, "can't find the user %s to switch to\n", username);
            return 1;
        }
        if (setgid(pw->pw_gid)<0 || setuid(pw->pw_uid)<0) {
            fprintf(stderr, "failed to assume identity of user %s\n", username);
            return 1;
        }
    }

    event_init();
    stats_init();
    conn_init();
    item_init();
    assoc_init();
    slabs_init(settings.maxbytes, settings.factor);

    if(!conn_new(l_socket, conn_listening, EV_READ | EV_PERSIST, 1)) {
        fprintf(stderr, "failed to create listening connection\n");
        exit(1);
    }

    clock_handler(0, 0, 0);

    delete_handler(0,0,0);

    event_loop(0);

    return 0;
}