#include "memlib.h"
#include "mm.h"
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    uint32_t allocated : 1;
    uint32_t block_size : 31;
    uint32_t _;
} header_t;

typedef header_t footer_t;

typedef struct block_t {
    uint32_t allocated : 1;
    uint32_t block_size : 31;
    uint32_t _;
    union {
        struct {
            struct block_t* next;
            struct block_t* prev;
        };
        int payload[0]; 
    } body;
} block_t;

enum block_state { FREE, ALLOC };

#define CHUNKSIZE (1 << 16) /* initial heap size (bytes) */
#define OVERHEAD (sizeof(header_t) + sizeof(footer_t)) /* overhead of the header and footer of an allocated block */
#define MIN_BLOCK_SIZE (32) /* the minimum block size needed to keep in a freelist (header + footer + next pointer + prev pointer) */
#define NUM_BUCKETS 14

/* Global variables */
static block_t *prologue; /* pointer to first block */
static block_t **seglist; /* pointer to first seg list pointer */

/* function prototypes for internal helper routines */
static block_t *extend_heap(size_t words);
static block_t* place(block_t *block, size_t asize);
static block_t *find_fit(size_t asize);
static block_t *coalesce(block_t *block);
static footer_t *get_footer(block_t *block);
static void printblock(block_t *block);
static void checkblock(block_t *block);

static void setnull(void);
static block_t* first_not_null(block_t** bucket, int numBucket);
static int get_bucket(size_t asize);
static void splice(block_t* block, size_t block_size);
static void insert_into_bucket(block_t* block);

/*
 * mm_init - Initialize the memory manager
 */
/* $begin mminit */
int mm_init(void) {
	/* create seglist pointer for bucket array (before prologue) */
	if ((seglist = (block_t**) mem_sbrk(NUM_BUCKETS * sizeof(void*))) == (void*)-1)
		return -1;
	setnull();	

    /* create the initial empty heap */
    if ((prologue = mem_sbrk(CHUNKSIZE)) == (void*)-1)
        return -1;
    /* initialize the prologue */
    prologue->allocated = ALLOC;
    prologue->block_size = sizeof(header_t);

    /* initialize the first free block */
    block_t *init_block = (void *)prologue + sizeof(header_t);
    init_block->allocated = FREE;
    init_block->block_size = CHUNKSIZE - OVERHEAD;
    footer_t *init_footer = get_footer(init_block);
    init_footer->allocated = FREE;
    init_footer->block_size = init_block->block_size;
	
	/* initialize next/prev pointers of first free block */
	init_block->body.next = NULL;
	init_block->body.prev = NULL;
	
	/* set largest bucket to point to initial block */
	seglist[NUM_BUCKETS-1] = init_block;	

    /* initialize the epilogue - block size 0 will be used as a terminating condition */
    block_t *epilogue = (void *)init_block + init_block->block_size;
    epilogue->allocated = ALLOC;
    epilogue->block_size = 0;
    return 0;
}
/* $end mminit */

/*
 * mm_malloc - Allocate a block with at least size bytes of payload
 */
/* $begin mmmalloc */
void *mm_malloc(size_t size) {
    uint32_t asize;       /* adjusted block size */
    uint32_t extendsize;  /* amount to extend heap if no fit */
    uint32_t extendwords; /* number of words to extend heap if no fit */
    block_t *block;

    /* Ignore spurious requests */
    if (size == 0)
        return NULL;

    /* Adjust block size to include overhead and alignment reqs. */
    size += OVERHEAD;

    asize = ((size + 7) >> 3) << 3; /* align to multiple of 8 */
    
    if (asize < MIN_BLOCK_SIZE) {
        asize = MIN_BLOCK_SIZE;
    }

    /* Search the free list for a fit */
    if ((block = find_fit(asize)) != NULL) {
        block_t* alloc = place(block, asize);
        return alloc->body.payload;
    }

    /* No fit found. Get more memory and place the block */
    extendsize = (asize > CHUNKSIZE) // extend by the larger of the two
                     ? asize
                     : CHUNKSIZE;
    extendwords = extendsize >> 3; // extendsize/8
    if ((block = extend_heap(extendwords)) != NULL) {
        block_t* alloc = place(block, asize);
        return alloc->body.payload;
    }
    /* no more memory :( */
    return NULL;
}
/* $end mmmalloc */

/*
 * mm_free - Free a block
 */
/* $begin mmfree */
void mm_free(void *payload) {
    block_t *block = payload - sizeof(header_t);
    block->allocated = FREE;
    footer_t *footer = get_footer(block);
    footer->allocated = FREE;
    coalesce(block);
}
/* $end mmfree */

/*
 * mm_realloc - naive implementation of mm_realloc
 * NO NEED TO CHANGE THIS CODE!
 */
void *mm_realloc(void *ptr, size_t size) {
    void *newp;
    size_t copySize;

    if ((newp = mm_malloc(size)) == NULL) {
        printf("ERROR: mm_malloc failed in mm_realloc\n");
        exit(1);
    }
    block_t* block = ptr - sizeof(header_t);
    copySize = block->block_size;
    if (size < copySize)
        copySize = size;
    memcpy(newp, ptr, copySize);
    mm_free(ptr);
    return newp;
}

/*
 * mm_checkheap - Check the heap for consistency
 */
void mm_checkheap(int verbose) {
    block_t *block = prologue;

    if (verbose)
        printf("Heap (%p):\n", prologue);

    if (block->block_size != sizeof(header_t) || !block->allocated)
        printf("Bad prologue header\n");
    checkblock(prologue);

    /* iterate through the heap (both free and allocated blocks will be present) */
    for (block = (void*)prologue+prologue->block_size; block->block_size > 0; block = (void *)block + block->block_size) {
        if (verbose)
            printblock(block);
        checkblock(block);
    }
	
	if(verbose)
		printf("Looping through free list now\n");
	/* iterate through free list of each bucket */
	for(int bucket = 0; bucket < NUM_BUCKETS; ++bucket){
		printf("bucket #%d\n", bucket);
		for (block_t* temp_block = seglist[bucket]; temp_block != NULL; temp_block = (void*) temp_block->body.next){
			if(verbose)
				printblock(temp_block);
			if(temp_block->allocated){
				printf("Block in free list is allocated\n");
			}
		}
	}

    if (verbose)
        printblock(block);
    if (block->block_size != 0 || !block->allocated)
        printf("Bad epilogue header\n");
}

/* The remaining routines are internal helper routines */

/*
 * extend_heap - Extend heap with free block and return its block pointer
 */
/* $begin mmextendheap */
static block_t *extend_heap(size_t words) {
    block_t *block;
    uint32_t size;
    size = words << 3; // words*8
    if (size == 0 || (block = mem_sbrk(size)) == (void *)-1)
        return NULL;
    /* The newly acquired region will start directly after the epilogue block */ 
    /* Initialize free block header/footer and the new epilogue header */
    /* use old epilogue as new free block header */
    block = (void *)block - sizeof(header_t);
    block->allocated = FREE;
    block->block_size = size;
    
	/* free block footer */
    footer_t *block_footer = get_footer(block);
    block_footer->allocated = FREE;
    block_footer->block_size = block->block_size;
    
	/* new epilogue header */
    header_t *new_epilogue = (void *)block_footer + sizeof(header_t);
    new_epilogue->allocated = ALLOC;
    new_epilogue->block_size = 0;
    
	/* Coalesce if the previous block was free */
    return coalesce(block);
}
/* $end mmextendheap */

/*
 * place - Place block of asize bytes at start of free block block
 *         and split if remainder would be at least minimum block size
 */
/* $begin mmplace */
static block_t* place(block_t *block, size_t asize) {
	/* strategy: smaller blocks allocated in front, larger blocks allocated in back */
    size_t split_size = block->block_size - asize;
	block_t* ret = NULL;
    if (split_size >= MIN_BLOCK_SIZE) {
		//printf("Splitting\n");
        /* split the block by updating the header and marking it allocated*/
		if(asize < 100){
			//split size is smaller, put allocated block in back of free black
			size_t temp_size = block->block_size;
            block->block_size = split_size;
            block->allocated = FREE;
 
            /* set footer of free block*/
            footer_t *footer = get_footer(block);
            footer->block_size = split_size;
            footer->allocated = FREE;
 
            /* update the header of the new allocated block */
            block_t *new_block = (void *)block + block->block_size;
            new_block->block_size = asize;
            new_block->allocated = ALLOC;
 
            /* update the footer of the new allocated block */
            footer_t *new_footer = get_footer(new_block);
            new_footer->block_size = asize;
            new_footer->allocated = ALLOC;
 
            splice(block, temp_size);
            insert_into_bucket(block);
            ret= new_block;

		} else {
			//split size is larger, put allocated block in front of free block
			size_t temp_size = block->block_size;
			block->block_size = asize;
        	block->allocated = ALLOC;
        
			/* set footer of allocated block*/
        	footer_t *footer = get_footer(block);
        	footer->block_size = asize;
        	footer->allocated = ALLOC;
        
			/* update the header of the new free block */
        	block_t *new_block = (void *)block + block->block_size;
        	new_block->block_size = split_size;
        	new_block->allocated = FREE;
        
			/* update the footer of the new free block */
        	footer_t *new_footer = get_footer(new_block);
        	new_footer->block_size = split_size;
        	new_footer->allocated = FREE;

			/* if necessary, connect previous/next free block to new free block */
			new_block->body.next = NULL;
			new_block->body.prev = NULL;

			splice(block, temp_size);
			insert_into_bucket(new_block);
			ret= block;
		}
    } else {
		//printf("No splitting\n");
        /* splitting the block will cause a splinter so we just include it in the allocated block */
        block->allocated = ALLOC;
        footer_t *footer = get_footer(block);
        footer->allocated = ALLOC;

		/* if necessary, connect previous free block to next free block */
		splice(block, block->block_size);
	
		/* splice handles edge cases with setting front of bucket, NULLs */
    	ret = block;
	}	

	/* set allocated block next/prev pointers just to be safe  */
	block->body.next = NULL;
	block->body.prev = NULL;
	
	//printf("Calling checkheap in place\n");
	//mm_checkheap(1);
	return ret;	
}
/* $end mmplace */

/*
 * find_fit - Find a fit for a block with asize bytes
 */
static block_t *find_fit(size_t asize) {
    /* first fit search */
	int bucketNum = get_bucket(asize);
	block_t **temp = &seglist[bucketNum];
	//printf("size: %ld, seglist bucket %p, bucketNum %d\n", asize, *temp, bucketNum);
    block_t *b = *temp != NULL ? *temp : first_not_null(temp, bucketNum);
    //printf("after first first_not_null %p\n", b);
	for (int i = 0; b != NULL && i < 10; b = b->body.next, i++) {
        /* block must be free and the size must be large enough to hold the request */
        if (asize <= b->block_size) {
            //printf("Returning %p from find_fit\n", b);
			return b;
        }
    }

	/* couldn't find block in corresponding bucket, check next valid bucket */
	block_t **backup = bucketNum+1 < NUM_BUCKETS ? &seglist[bucketNum+1] : NULL;
	if(backup == NULL) return NULL;	
	
	b = *backup != NULL ? *backup : first_not_null(backup, bucketNum+1);
	if(b != NULL) return b;

	//printf("Returning NULL from find_fit\n");
    return NULL; /* no fit */
}

/*
 * coalesce - boundary tag coalescing. Return ptr to coalesced block
 */
static block_t *coalesce(block_t *block) {
	/* remember that epilogue/prologue are allocated blocks */

    footer_t *prev_footer = (void *)block - sizeof(header_t);
    header_t *next_header = (void *)block + block->block_size;
    bool prev_alloc = prev_footer->allocated;
    bool next_alloc = next_header->allocated;

    if (prev_alloc && next_alloc) { /* Case 1 */
		//printf("coalesce case 1\n");
        /* no coalesceing, but insert freed block at root of free list */
		block->body.next = NULL;
		block->body.prev = NULL; // possibly redundant

		insert_into_bucket(block);
    }

    else if (prev_alloc && !next_alloc) { /* Case 2 */
        //printf("coalesce case 2\n");
		/* Update header of current block to include next block's size */
        block_t* next_block = (void *)block + block->block_size;
		block->block_size += next_header->block_size;
        
		/* Update footer of next block to reflect new size */
        footer_t *next_footer = get_footer(block);
        next_footer->block_size = block->block_size;

		/* Update pointers */
		splice(next_block, next_block->block_size);
		insert_into_bucket(block);			

	}
    else if (!prev_alloc && next_alloc) { /* Case 3 */
        //printf("coalesce case 3\n");
		/* Update header of prev block to include current block's size */
        block_t *prev_block = (void *)prev_footer - prev_footer->block_size + sizeof(header_t);
        size_t temp_size = prev_block->block_size;
		prev_block->block_size += block->block_size;
        
		/* Update footer of current block to reflect new size */
        footer_t *footer = get_footer(prev_block);
        footer->block_size = prev_block->block_size;
        block = prev_block;

		/* update pointers */
		splice(block, temp_size);
		insert_into_bucket(block);
    }

    else { /* Case 4 */
       	//printf("coalesce case 4\n");
		/* Update header of prev block to include current and next block's size */
        block_t *prev_block = (void *)prev_footer - prev_footer->block_size + sizeof(header_t);
        block_t *next_block = (void *)block + block->block_size;
		size_t temp_size_prev = prev_block->block_size;
		prev_block->block_size += block->block_size + next_header->block_size;
        
		/* Update footer of next block to reflect new size */
        footer_t *next_footer = get_footer(prev_block);
        next_footer->block_size = prev_block->block_size;
        block = prev_block;

		/* update pointers */
		splice(prev_block, temp_size_prev);
		splice(next_block, next_block->block_size);
		insert_into_bucket(block);
    }
	
	//printf("calling checkheap in coalesce\n");
	//mm_checkheap(1);
    return block;
}

static footer_t* get_footer(block_t *block) {
    return (void*)block + block->block_size - sizeof(footer_t);
}

static void printblock(block_t *block) {
    uint32_t hsize, halloc, fsize, falloc;

    hsize = block->block_size;
    halloc = block->allocated;
    footer_t *footer = get_footer(block);
    fsize = footer->block_size;
    falloc = footer->allocated;

    if (hsize == 0) {
        printf("%p: EOL\n", block);
        return;
    }
	if(halloc || falloc)
    	printf("%p: header: [%d:%c] footer: [%d:%c]\n", block, hsize,
           (halloc ? 'a' : 'f'), fsize, (falloc ? 'a' : 'f'));
	else 
		printf("%p: header: [%d:%c] footer: [%d:%c] prev: %p next: %p\n", block, hsize,
			(halloc ? 'a' : 'f'), fsize, (falloc ? 'a' : 'f'), block->body.prev, block->body.next);
}

static void checkblock(block_t *block) {
    if ((uint64_t)block->body.payload % 8) {
        printf("Error: payload for block at %p is not aligned\n", block);
    }
    footer_t *footer = get_footer(block);
    if (block->block_size != footer->block_size) {
        printf("Error: header does not match footer\n");
    }

	if( (void*) block < mem_heap_lo() || (void*) block > mem_heap_hi()){
		printf("Error: block is outside of heap range");
	}

	/* for free blocks, check valid next/prev pointers */
	if(!block->allocated && block->body.next != NULL && ((void*) block->body.next < mem_heap_lo() || (void*) block->body.next > mem_heap_hi())){
		printf("Error: free block next pointer is outside of heap range, %p\n", block);	
	}  
	if(!block->allocated && block->body.prev != NULL && ((void*)block->body.prev < mem_heap_lo() || (void*) block->body.prev > mem_heap_hi())){
		printf("Error: free block prev pointer is outside of heap range, %p\n", block);
	}

	if( (void*) footer < mem_heap_lo() || (void*) footer > mem_heap_hi()){
    	printf("Error: block's footer is outside of heap range, %p\n", block);
    }

	if( !block->allocated && (block == block->body.prev || block == block->body.next)){
		printf("Error: free block prev|next pointer pointers to the block itself\n");
	}

}

/* initialize all buckets to NULL */
static void setnull(){
	for(int bucket = 0; bucket < NUM_BUCKETS; bucket++){
		seglist[bucket] = NULL;
	}
}

/* get appropriate bucket for a given size */
static int get_bucket(size_t asize){
	switch(asize){
    	case 32 ... 63:
        	//return &seglist[0];
        	return 0;
        case 64 ... 127:
           	//return &seglist[1];
           	return 1;
        case 128 ... 143:
            //return &seglist[2];
            return 2;	
		case 144 ... 255:
			return 3;
        case 256 ... 511:
            //return &seglist[3];
            return 4;
        case 512 ... 1023:
            //return &seglist[4];
            return 5;
        case 1024 ... 2047:
            //return &seglist[5];
            return 6;
        case 2048 ... 4095:
            //return &seglist[6];
           	return 7;
        case 4096 ... 8191:
            //return &seglist[7];
            return 8;
        case 8192 ... 16383:
            //return &seglist[8];
            return 9;
		case 16384 ... 21000:
			return 10;
		case 21001 ... 24400:
			return 11;
        case 24401 ... 32000:
			return 12;
		default:
            //return &seglist[9];
           	return 13;
     }
}

/* starting from bucket, find first bucket not null. Return null if all successive buckets null */
static block_t* first_not_null(block_t** bucket, int bucketNum){
	if(*bucket != NULL) return *bucket;
	//printf("inside first_not_null %p, %d\n", *bucket, bucketNum); 
	while(*bucket == NULL && ++bucketNum < NUM_BUCKETS){
		++bucket;
		//printf("inside first_not_null %p, %d\n", *bucket, bucketNum);
		if(*bucket != NULL) return *bucket;
	}
	return NULL;
}

/* insert block in front of bucket */
static void insert_into_bucket(block_t* block){
	block_t** bucket = &seglist[get_bucket(block->block_size)];
	if(*bucket != NULL){
		(*bucket)->body.prev = block;
		block->body.next = *bucket;	
	} else {
		block->body.next = NULL;
	}	 
	block->body.prev = NULL;
	*bucket = block;	
}

/* disconnect block from its next/free pointers */
/* still have to handle edge cases around setting first in list */
static void splice(block_t* block, size_t block_size){
	int bucketNum = get_bucket(block_size);
	if(block->body.next != NULL){
		block->body.next->body.prev = block->body.prev;		
	}
	if(block->body.prev != NULL){
		block->body.prev->body.next = block->body.next;
	}
	
	// handle edge cases
	if(block->body.prev == NULL && block->body.next != NULL){
    	seglist[bucketNum] = block->body.next;  
    } else if(block->body.next == NULL && block->body.prev != NULL){
    	block->body.prev->body.next = NULL;
    } else if(block->body.prev == NULL && block->body.next == NULL){
		seglist[bucketNum] = NULL;
    }
}
