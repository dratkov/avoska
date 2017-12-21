#include <netinet/in.h>
#include <time.h>
#include <string.h>
#include <event.h>
#include <assert.h>

#include "avoska.h"

#define LARGEST_ID 255

#define ITEM_ntotal(item) (sizeof(struct _stritem) + (item)->nkey + (item)->nsuffix + (item)->nbytes)

static item *heads[LARGEST_ID];
static item *tails[LARGEST_ID];
unsigned int sizes[LARGEST_ID];

void item_init(void) {
    int i;
    for(i=0; i<LARGEST_ID; i++) {
        heads[i]=0;
        tails[i]=0;
        sizes[i]=0;
    }
}


int item_make_header(char *key, int flags, int nbytes,
                     char *sufficx, int *nsuffix, int *keylen) {
    *keylen = strlen(key + 1);
    if(*keylen % 4)
        *keylen += 4 - (*keylen % 4);
    *nsuffix = sprintf(sufficx, " %u %u\r\n", flags, nbytes - 2);
    return sizeof(item) + *keylen + *nsuffix + nbytes;
}

item *item_alloc(char *key, int flags, rel_time_t exptime, int nbytes) {
    int nsuffix, len, ntotal;
    item *it;
    unsigned int id;
    char suffix[40];

    ntotal = item_make_header(key, flags, nbytes, suffix, &nsuffix, &len);

    id = slabs_clsid(ntotal);

    it = slabs_alloc(ntotal);

    it->slabs_clsid = id;

    it->next = it->prev = it->h_next = 0;
    it->refcount = 0;
    it->it_flags = 0;
    it->nkey = len;
    it->nbytes = nbytes;
    strcpy(ITEM_key(it), key);
    it->exptime = exptime;
    memcpy(ITEM_suffix(it), suffix, nsuffix);
    it->nsuffix = nsuffix;

    return it;
}

void item_unlink_q(item *it) {
    item **head, **tail;

    head = &heads[it->slabs_clsid];
    tail = &tails[it->slabs_clsid];

    if(*head == it) {
        assert(it->prev == 0);
        *head = it->next;
    }
    if(*tail == it) {
        assert(it->next == 0);
        *tail = it->prev;
    }
    assert(it->next != it);
    assert(it->prev != it);

}

void item_link_q(item *it) {
    item **head, **tail;

    assert((it->it_flags & ITEM_SLABBED) == 0);

    head = &heads[it->slabs_clsid];
    tail = &tails[it->slabs_clsid];
    assert(it != *head);
    assert((*head && *tail) || (*head == 0 && *tail == 0));
    it->prev = 0;
    it->next = *head;
    if (it->next) it->next->prev = it;
    *head = it;
    if (*tail == 0) *tail = it;
    sizes[it->slabs_clsid]++;
    return;
}

void item_free(item *it) {

}

void item_update(item *it) {
    assert((it->it_flags & ITEM_SLABBED) == 0);

    item_unlink_q(it);
    it->time = current_time;
    item_link_q(it);
}

void item_unlink(item *it) {
    if (it->it_flags & ITEM_LINKED) {
        it->it_flags &= ~ITEM_LINKED;
        stats.curr_bytes -= ITEM_ntotal(it);
        stats.curr_items -= 1;
        assoc_delete(ITEM_key(it));
        item_unlink_q(it);
    }
    if (it->refcount == 0) item_free(it);
}

int item_replace(item *it, item *new_it) {
    assert((it->it_flags & ITEM_SLABBED) == 0);

    item_unlink(it);
    return item_link(new_it);
}

int item_link(item *it) {
    assert((it->it_flags & (ITEM_LINKED|ITEM_SLABBED)) == 0);
    assert(it->nbytes < 1048576);
    it->it_flags |= ITEM_LINKED;
    it->time = current_time;
    assoc_insert(ITEM_key(it), it);

    stats.curr_bytes += ITEM_ntotal(it);
    stats.curr_items += 1;
    stats.total_items += 1;

    item_link_q(it);

    return 1;
}

void item_remove(item *it) {
    assert((it->it_flags & ITEM_SLABBED) == 0);
    if (it->refcount) it->refcount--;
    assert((it->it_flags & ITEM_DELETED) == 0 || it->refcount);
    if (it->refcount == 0 && (it->it_flags & ITEM_LINKED) == 0) {
        item_free(it);
    }
}

