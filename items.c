#include <netinet/in.h>
#include <time.h>
#include <string.h>
#include <event.h>

#include "avoska.h"

#define LARGEST_ID 255
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
	*nsuffix = sprintf(sufficx, "%u %u\r\n", flags, nbytes);
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