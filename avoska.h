#define DATA_BUFFER_SIZE 2048

/* Initial size of list of items being returned by "get". */
#define ITEM_LIST_INITIAL 200

/* Initial size of the sendmsg() scatter/gather array. */
#define IOV_LIST_INITIAL 400

/* Initial number of sendmsg() argument structures to allocate. */
#define MSG_LIST_INITIAL 10

/* High water marks for buffer shrinking */
#define READ_BUFFER_HIGHWAT 8192
#define ITEM_LIST_HIGHWAT 400
#define IOV_LIST_HIGHWAT 600
#define MSG_LIST_HIGHWAT 100

/* Time relative to server start. Smaller than time_t on 64-bit systems. */
typedef unsigned int rel_time_t;


struct settings
{
	size_t maxbytes;
	int port;
	struct in_addr interface;
	int verbose;
    rel_time_t oldest_live;
    char *socketpath;
	int chunk_size;
	double factor;
};

#define ITEM_LINKED 1
#define ITEM_DELETED 2

/* temp */
#define ITEM_SLABBED 4

typedef struct _stritem {
    struct _stritem *next;
    struct _stritem *prev;
    struct _stritem *h_next;    /* hash chain next */
    rel_time_t      time;       /* least recent access */
    rel_time_t      exptime;    /* expire time */
    int             nbytes;     /* size of data */
    unsigned short  refcount;
    unsigned char   nsuffix;    /* length of flags-and-length string */
    unsigned char   it_flags;   /* ITEM_* above */
    unsigned char   slabs_clsid;/* which slab class we're in */
    unsigned char   nkey;       /* key length, w/terminating null and padding */
    void * end[0];
    /* then null-terminated key */
    /* then " flags length\r\n" (no terminating null) */
    /* then data with terminating \r\n (no terminating null; it's binary!) */
} item;

typedef struct {
    int    sfd;
    int    state;
    struct event event;
    short  ev_flags;
    short  which;   /* which events were just triggered */

    char   *rbuf;   /* buffer to read commands into */
    char   *rcurr;  /* but if we parsed some already, this is where we stopped */
    int    rsize;   /* total allocated size of rbuf */
    int    rbytes;  /* how much data, starting from rcur, do we have unparsed */

    char   *wbuf;
    char   *wcurr;
    int    wsize;
    int    wbytes;
    int    write_and_go; /* which state to go into after finishing current write */
    void   *write_and_free; /* free this memory after finishing writing */

    char   *ritem;  /* when we read in an item's value, it goes here */
    int    rlbytes;

    /* data for the nread state */

    /*
     * item is used to hold an item structure created after reading the command
     * line of set/add/replace commands, but before we finished reading the actual
     * data. The data is read into ITEM_data(item) to avoid extra copying.
     */

    void   *item;     /* for commands set/add/replace  */
    int    item_comm; /* which one is it: set/add/replace */

    /* data for the swallow state */
    int    sbytes;    /* how many bytes to swallow */

    /* data for the mwrite state */
    struct iovec *iov;
    int    iovsize;   /* number of elements allocated in iov[] */
    int    iovused;   /* number of elements used in iov[] */

    struct msghdr *msglist;
    int    msgsize;   /* number of elements allocated in msglist[] */
    int    msgused;   /* number of elements used in msglist[] */
    int    msgcurr;   /* element in msglist[] being transmitted now */
    int    msgbytes;  /* number of bytes in current msg */

    item   **ilist;
    int    isize;
    item   **icurr;
    int    ileft;

    /* data for UDP clients */
    int    request_id; /* Incoming UDP request ID, if this is a UDP "connection" */
    struct sockaddr request_addr; /* Who sent the most recent request */
    socklen_t request_addr_size;
    unsigned char *hdrbuf; /* udp packet headers */
    int    hdrsize;   /* number of headers' worth of space is allocated */

    int    binary;    /* are we in binary mode */
    int    bucket;    /* bucket number for the next command, if running as
                         a managed instance. -1 (_not_ 0) means invalid. */
    int    gen;       /* generation requested for the bucket */
} conn;

enum conn_states {
    conn_listening,  /* the socket which listens for connections */
    conn_read,       /* reading in a command line */
    conn_write,      /* writing out a simple response */
    conn_nread,      /* reading in a fixed number of bytes */
    conn_swallow,    /* swallowing unnecessary bytes w/o storing */
    conn_closing,    /* closing this connection */
    conn_mwrite      /* writing out many items sequentially */
};

#define NREAD_ADD 1
#define NREAD_SET 2
#define NREAD_REPLACE 3

struct stats {
    unsigned int  curr_items;
    unsigned int  total_items;
	time_t        started;          /* when the process was started */
	unsigned int  curr_conns;
    unsigned int  total_conns;
    unsigned long long curr_bytes;
	unsigned int  conn_structs;
    unsigned long long bytes_read;
    unsigned long long  get_cmds;
    unsigned long long  set_cmds;
    unsigned long long  get_hits;
    unsigned long long  get_misses;
    unsigned long long bytes_written;
};

#define ITEM_key(item) ((char*)&((item)->end[0]))

#define ITEM_suffix(item) ((char*) &((item)->end[0]) + (item)->nkey)
#define ITEM_data(item) ((char*) &((item)->end[0]) + (item)->nkey + (item)->nsuffix)


/* current time of day (updated periodically) */
extern volatile rel_time_t current_time;

extern struct stats stats;
extern struct settings settings;

/* Allocate object of given length. 0 on error */
void *slabs_alloc(size_t size);
void slabs_init(size_t limit, double factor);
unsigned int slabs_clsid(size_t size);

/* event handling, network IO */
void event_handler(int fd, short which, void *arg);
conn *conn_new(int sfd, int init_state, int event_flags, int read_buffer_size);
void conn_close(conn *c);
int try_read_command(conn *c);
void process_command(conn *c, char *command);
int try_read_network(conn *c);
int add_msghdr(conn *c);
int add_iov(conn *c, const void *buf, int len);
item *item_alloc(char *key, int flags, rel_time_t exptime, int nbytes);
void item_init(void);
void item_free(item *it);
void item_update(item *it);   /* update LRU time to current and reposition */
void item_unlink(item *it);
int item_replace(item *it, item *new_it);
int item_link(item *it);
void item_remove(item *it);

int ensure_iov_space(conn *c);

void complete_nread(conn *c);
void assoc_init(void);
item *assoc_find(char *key);
void assoc_delete(char *key);
int assoc_insert(char *key, item *item);


