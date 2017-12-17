#include <netinet/in.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <event.h>
#include <assert.h>

#include "avoska.h"

typedef  unsigned long  int  ub4;   /* unsigned 4-byte quantities */
typedef  unsigned       char ub1;   /* unsigned 1-byte quantities */

#define HASHPOWER  20

#define hashsize(n) ((ub4)1<<(n))
#define hashmask(n) (hashsize(n)-1)

#define mix(a,b,c) \
{ \
  a -= b; a -= c; a ^= (c>>13); \
  b -= c; b -= a; b ^= (a<<8); \
  c -= a; c -= b; c ^= (b>>13); \
  a -= b; a -= c; a ^= (c>>12);  \
  b -= c; b -= a; b ^= (a<<16); \
  c -= a; c -= b; c ^= (b>>5); \
  a -= b; a -= c; a ^= (c>>3);  \
  b -= c; b -= a; b ^= (a<<10); \
  c -= a; c -= b; c ^= (b>>15); \
}

static item** hashtable = 0;

ub4 hash( k, length, initval)
     register ub1 *k;        /* the key */
     register ub4  length;   /* the length of the key */
     register ub4  initval;  /* the previous hash, or an arbitrary value */
{
    register ub4 a,b,c,len;

    /* Set up the internal state */
    len = length;
    a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
    c = initval;         /* the previous hash value */

    while (len >= 12)
    {
        a += (k[0] +((ub4)k[1]<<8) +((ub4)k[2]<<16) +((ub4)k[3]<<24));
        b += (k[4] +((ub4)k[5]<<8) +((ub4)k[6]<<16) +((ub4)k[7]<<24));
        c += (k[8] +((ub4)k[9]<<8) +((ub4)k[10]<<16)+((ub4)k[11]<<24));
        mix(a,b,c);
        k += 12; len -= 12;
    }

    c += length;
    switch(len)              /* all the case statements fall through */
    {
        case 11: c+=((ub4)k[10]<<24);
        case 10: c+=((ub4)k[9]<<16);
        case 9 : c+=((ub4)k[8]<<8);
            /* the first byte of c is reserved for the length */
        case 8 : b+=((ub4)k[7]<<24);
        case 7 : b+=((ub4)k[6]<<16);
        case 6 : b+=((ub4)k[5]<<8);
        case 5 : b+=k[4];
        case 4 : a+=((ub4)k[3]<<24);
        case 3 : a+=((ub4)k[2]<<16);
        case 2 : a+=((ub4)k[1]<<8);
        case 1 : a+=k[0];
            /* case 0: nothing left to add */
    }
    mix(a,b,c);

    return c;
}

void assoc_init(void) {
    unsigned int hash_size = hashsize(HASHPOWER) * sizeof(void*);
    hashtable = malloc(hash_size);
    if (! hashtable) {
        fprintf(stderr, "Failed to init hashtable.\n");
        exit(1);
    }
    memset(hashtable, 0, hash_size);
}

item *assoc_find(char *key) {
    ub4 hv = hash((unsigned char *)key, strlen(key), 0) & hashmask(HASHPOWER);
    item *it = hashtable[hv];

    while (it) {
        if (strcmp(key, ITEM_key(it)) == 0)
            return it;
        it = it->h_next;
    }
    return 0;
}

static item** _hashitem_before (char *key) {
    ub4 hv = hash((unsigned char *)key, strlen(key), 0) & hashmask(HASHPOWER);
    item **pos = &hashtable[hv];

    while(*pos && strcmp(key, ITEM_key(*pos))) {
        pos = &(*pos)->h_next;
    }
    return pos;
}

void assoc_delete(char *key) {
    item **before = _hashitem_before(key);
    if (*before) {
        item *nxt = (*before)->h_next;
        (*before)->h_next = 0;
        *before = nxt;
        return;
    }
    assert(*before != 0);
}

int assoc_insert(char *key, item *it) {
    ub4 hv;
    assert(assoc_find(key) == 0);
    hv = hash((unsigned char *)key, strlen(key), 0) & hashmask(HASHPOWER);
    it->h_next = hashtable[hv];
    hashtable[hv] = it;
    return 1;
}