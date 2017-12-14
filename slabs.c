#include <netinet/in.h>
#include <time.h>
#include <string.h>
#include <event.h>
#include <stdlib.h>

#include "avoska.h"

#define CHUNK_ALIGN_BYTES (sizeof(void *))
#define POWER_BLOCK 1048576

#define POWER_SMALLEST 1
#define POWER_LARGEST  200

/* powers-of-N allocation structures */

typedef struct {
    unsigned int size;      /* sizes of items */
    unsigned int perslab;   /* how many items per slab */

    void **slots;           /* list of item ptrs */
    unsigned int sl_total;  /* size of previous array */
    unsigned int sl_curr;   /* first free slot */

    void *end_page_ptr;         /* pointer to next free item at end of page, or 0 */
    unsigned int end_page_free; /* number of items remaining at end of last alloced page */

    unsigned int slabs;     /* how many slabs were allocated for this class */

    void **slab_list;       /* array of slab pointers */
    unsigned int list_size; /* size of prev array */

    unsigned int killing;  /* index+1 of dying slab, or zero if none */
} slabclass_t;

static slabclass_t slabclass[POWER_LARGEST+1];
static size_t mem_limit = 0;
static size_t mem_malloced = 0;
static int power_largest;

void slabs_init(size_t limit, double factor) {
	int i = POWER_SMALLEST - 1;
	unsigned int size = sizeof(item) + settings.chunk_size;

    /* Factor of 2.0 means use the default memcached behavior */
    if (factor == 2.0 && size < 128)
        size = 128;

    mem_limit = limit;
    memset(slabclass, 0, sizeof(slabclass));

    while(++i < POWER_LARGEST && size <= POWER_BLOCK / 2) {
    	if(size % CHUNK_ALIGN_BYTES)
    		size += CHUNK_ALIGN_BYTES - ( size % CHUNK_ALIGN_BYTES );

    	slabclass[i].size = size;
    	slabclass[i].perslab = POWER_BLOCK / slabclass[i].size;
    	size *= factor;
    	if (settings.verbose > 1) {
            fprintf(stderr, "slab class %3d: chunk size %6d perslab %5d\n",
                    i, slabclass[i].size, slabclass[i].perslab);
        }
    }

    power_largest = i;
    slabclass[power_largest].size = POWER_BLOCK;
    slabclass[power_largest].perslab = 1;

}

unsigned int slabs_clsid(size_t size) {
	int res = POWER_SMALLEST;

	if(size==0)
        return 0;
    while (size > slabclass[res].size)
        if (res++ == power_largest)
            return 0;
    return res;
}

void *slabs_alloc(size_t size) {
	slabclass_t *p;

	unsigned char id = slabs_clsid(size);
	if (id < POWER_SMALLEST || id > power_largest)
        return 0;
    p = &slabclass[id];

    if (mem_limit && mem_malloced + size > mem_limit)
        return 0;
    mem_malloced += size;
    return malloc(size);
}