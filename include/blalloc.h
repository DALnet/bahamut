/************************************************************************* 
 * File:   blalloc.h
 * Owner:  jolo
 *************************************************************************/

/* $Id: blalloc.h 1303 2006-12-07 03:23:17Z epiphani $ */

#ifndef BLALLOC_H
#define BLALLOC_H
/* INCLUDES */
#include <stddef.h>

/* DEFINES */
#define BlockHeapALLOC(bh, type)	((type *) BlockHeapAlloc(bh))

/* TYPEDEFS */

/* Block contains status information for an allocated block in our heap. */

typedef struct Block 
{
    void          *elems;		/* Points to allocated memory */
    void          *endElem;		/* Points to last elem for boundck */
    int            freeElems;	    	/* Number of available elems */
    struct Block  *next;		/* Next in our chain of blocks */
    unsigned long *allocMap;	    	/* Bitmap of allocated blocks */
} Block;

/* BlockHeap contains the information for the root node of the memory heap. */

typedef struct BlockHeap 
{
    size_t         elemSize;	       	/* Size of each element to be stored */
    int            elemsPerBlock; 	/* Number of elements per block */
    int            numlongs;	       	/* Size of Block's allocMap array */
    int            blocksAllocated; 	/* Number of blocks allocated */
    int            freeElems;	    	/* Number of free elements */
    Block         *base;       	 	/* Pointer to first block */
} BlockHeap;

/* FUNCTION PROTOTYPES */

BlockHeap        *BlockHeapCreate(size_t elemsize, int elemsperblock);
int               BlockHeapDestroy(BlockHeap *bh);
void             *BlockHeapAlloc(BlockHeap *bh);
int               BlockHeapFree(BlockHeap *bh, void *ptr);

#endif
