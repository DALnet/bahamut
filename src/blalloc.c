/************************************************************************
 *
 * File:   blalloc.c
 * Owner:  Wohali (Joan Touzet)
 * Hacked up for use in ircd by Dianora                             
 *************************************************************************/

/* INCLUDES */
#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "numeric.h"
#include "blalloc.h"
#include "memcount.h"

/* FUNCTION PROTOTYPES (LOCAL FUNCTIONS ONLY) */
static int  newblock(BlockHeap *bh);

/* FUNCTION PROTOTYPES (EXTERN FUNCTIONS ONLY) */
extern void outofmemory();	/* defined in list.c */

/* FUNCTION DOCUMENTATION:
 *
 * newblock
 *  Description:
 *   mallocs a new block for addition to a blockheap
 *  Parameters:
 *   bh (IN): Pointer to parent blockheap.
 *  Returns:
 *   0 if successful, 1 if not
 */
static int newblock(BlockHeap *bh)
{
    Block      *b;
    int         i;
    /* Setup the initial data structure.  */
    b = (Block *) MyMalloc(sizeof(Block));
    if (b == NULL)
	return 1;
    b->freeElems = bh->elemsPerBlock;
    b->next = bh->base;
    b->allocMap = (unsigned long *) MyMalloc(sizeof(unsigned long) * (bh->numlongs + 1));
    memset((void *) b->allocMap, '\0', (bh->numlongs + 1) * sizeof(unsigned long));
    if (b->allocMap == NULL)
    {
	MyFree(b);
	return 1;
    }
    /* Now allocate the memory for the elems themselves. */
    b->elems = (void *) MyMalloc(bh->elemsPerBlock * bh->elemSize);
    if (b->elems == NULL)
    {
	MyFree(b->allocMap);
	MyFree(b);
	return 1;
    }
    b->endElem = (void *) ((unsigned long) b->elems +
			   (unsigned long) ((bh->elemsPerBlock - 1) * 
					    bh->elemSize));
    /* Mark all blocks as free */
    for (i = 0; i < bh->numlongs; i++)
	b->allocMap[i] = 0L;
    /* Finally, link it in to the heap. */
    ++bh->blocksAllocated;
    bh->freeElems += bh->elemsPerBlock;
    bh->base = b;
    return 0;
}

/* FUNCTION DOCUMENTATION:
 *
 * BlockHeapCreate
 *
 * Description:
 *  Creates a new blockheap from which smaller blocks can be allocated.
 *   Intended to be used instead of multiple calls to malloc() when
 *   performance is an issue.
 * Parameters:
 *  elemsize (IN):  Size of the basic element to be stored
 *  elemsperblock (IN):  Number of elements to be stored in a single
 *   block of memory.  When the blockheap runs out of free memory, it will  
 *   allocate elemsize * elemsperblock more.                          
 * Returns:
 *  Pointer to new BlockHeap, or NULL if unsuccessful
 */
BlockHeap *BlockHeapCreate(size_t elemsize, int elemsperblock)
{
    BlockHeap  *bh;
    /* Catch idiotic requests up front */
    if ((elemsize <= 0) || (elemsperblock <= 0))
    {
	outofmemory();		/* die.. out of memory */
    }
    /* Allocate our new BlockHeap */
    bh = (BlockHeap *) MyMalloc(sizeof(BlockHeap));
    if (bh == NULL)
    {
	outofmemory();		/* die.. out of memory */
    }
    elemsize = elemsize + (elemsize & (sizeof(void *) - 1));
    bh->elemSize = elemsize;
    bh->elemsPerBlock = elemsperblock;
    bh->blocksAllocated = 0;
    bh->freeElems = 0;
    bh->numlongs = (bh->elemsPerBlock / (sizeof(unsigned long) * 8)) + 1;
    if ((bh->elemsPerBlock % (sizeof(unsigned long) * 8)) == 0)
	bh->numlongs--;
    bh->base = NULL;
  
    /* Be sure our malloc was successful */
    if (newblock(bh))
    {
	MyFree(bh);
	outofmemory();		/* die.. out of memory */
    }
    /* DEBUG */
    if (bh == NULL)
    {
	outofmemory();		/* die.. out of memory */
    }
    return bh;
}

/* FUNCTION DOCUMENTATION:
 *
 * BlockHeapAlloc
 *
 * Description:
 *  Returns a pointer to a struct within our BlockHeap that's free for
 *  the taking.
 * Parameters:
 *  bh (IN):  Pointer to the Blockheap.
 * Returns:
 *  Pointer to a structure (void *), or NULL if unsuccessful.
 */

void *BlockHeapAlloc(BlockHeap *bh)
{
    Block      *walker;
    int         unit;
    unsigned long mask;
    unsigned long ctr;
    if (bh == NULL) return ((void *) NULL);
    if (bh->freeElems == 0)	/* Allocate new block and assign */
    {
	/* newblock returns 1 if unsuccessful, 0 if not */
	if (newblock(bh))
	{
	    return ((void *) NULL);
	}
	else
	{
	    walker = bh->base;
	    walker->allocMap[0] = 0x1L;
	    walker->freeElems--;
	    bh->freeElems--;
	    if (bh->base->elems == NULL)
		return ((void *) NULL);
	}
	return ((bh->base)->elems);	/* ...and take the first elem. */
    }
    for (walker = bh->base; walker != NULL; walker = walker->next)
    {
	if (walker->freeElems > 0)
	{
	    mask = 0x1L;
	    ctr = 0;
	    unit = 0;
	    while (unit < bh->numlongs)
	    {
		if ((mask == 0x1L) && (walker->allocMap[unit] == (unsigned long) ~0))
		{
		    /* Entire subunit is used, skip to next one. */
		    unit++;
		    ctr = 0;
		    continue;
		}
		/* Check the current element, if free allocate block */
		if (!(mask & walker->allocMap[unit]))
		{
		    walker->allocMap[unit] |= mask;   /* Mark block as used */
		    walker->freeElems--;
		    bh->freeElems--;
		    /* And return the pointer
		     * 
		     * Address arithemtic is always ca-ca have to make sure
		     * the the bit pattern for the base address is converted
		     * into the same number of bits in an integer type, that
		     * has at least sizeof(unsigned long) at least ==
		     * sizeof(void *) -Dianora
		     */
	  
		    return ((void *) ((unsigned long) walker->elems +
				      ((unit * sizeof(unsigned long) *
					8 + ctr) *
				       (unsigned long) bh->elemSize)));
		}
		/* Step up to the next unit */
		mask <<= 1;
		ctr++;
		if (!mask)
		{
		    mask = 0x1L;
		    unit++;
		    ctr = 0;
		}
	    }			/* while */
	}				/* if */
    }				/* for */
    
    return ((void *) NULL);	/* If you get here, something bad happened ! */
}

/* FUNCTION DOCUMENTATION:
 *
 * BlockHeapFree
 *
 * Description: 
 *  Returns an element to the free pool, does not free()
 * Parameters:
 *  bh (IN): Pointer to BlockHeap containing element
 *  ptr (in):  Pointer to element to be "freed"
 * Returns:
 *  0 if successful, 1 if element not contained within BlockHeap.
 */

int BlockHeapFree(BlockHeap *bh, void *ptr)
{
    Block      *walker;
    unsigned long ctr;
    unsigned long bitmask;
    if (bh == NULL)
    {
#if defined(USE_SYSLOG) && defined(SYSLOG_BLOCK_ALLOCATOR)
	syslog(LOG_DEBUG, "blalloc.c bh == NULL");
#endif
	return 1;
    }
    for (walker = bh->base; walker != NULL; walker = walker->next)
    {
	if ((ptr >= walker->elems) && (ptr <= walker->endElem))
	{
	    ctr = ((unsigned long) ptr - (unsigned long) (walker->elems)) /
		(unsigned long) bh->elemSize;
	    bitmask = 1L << (ctr % (sizeof(unsigned long) * 8));
	    ctr = ctr / (sizeof(unsigned long) * 8);
	    /* Flip the right allocation bit
	     *
	     * Complain if the bit is already clear, something is wrong
	     * (typically, someone freed the same block twice)
	     */
	    if ((walker->allocMap[ctr] & bitmask) == 0)
	    {
		abort(); /* This is more useful than some random complaining */
#if defined(USE_SYSLOG) && defined(SYSLOG_BLOCK_ALLOCATOR)
		syslog(LOG_DEBUG, "blalloc.c bit already clear in map!");
#endif
		sendto_ops("blalloc.c bit already clear in map!");
		sendto_ops("Please report to the bahamut team!"
			   "bahamut-bugs@bahamut.net");
	    }
	    else
	    {
		walker->allocMap[ctr] = walker->allocMap[ctr] & ~bitmask;
		walker->freeElems++;
		bh->freeElems++;
	    }
	    return 0;
	}
    }
    return 1;
}
/* FUNCTION DOCUMENTATION:
 *
 * BlockHeapGarbageCollect
 *
 * Description:
 *  Performs garbage colletion on the block heap.  Any blocks that are
 *  completely unallocated are removed from the heap.  Garbage
 *  collection will never remove the root node of the heap.
 * Parameters:
 *  bh (IN):  Pointer to the BlockHeap to be cleaned up
 * Returns:
 *  0 if successful, 1 if bh == NULL
 */
int BlockHeapGarbageCollect(BlockHeap *bh)
{
    Block      *walker, *last;
  
    if (bh == NULL) return 1;
  
    if (bh->freeElems < bh->elemsPerBlock)
    {
	/* There couldn't possibly be an entire free block.  Return. */
	return 0;
    }
  
    last = NULL;
    walker = bh->base;
    while (walker)
    {
	/* This section rewritten Dec 10 1998 - Dianora */
	int i;
	for (i = 0; i < bh->numlongs; i++)
	{
	    if (walker->allocMap[i])
		break;
	}
	if (i == bh->numlongs)
	{
	    /* This entire block is free.  Remove it. */
	    MyFree(walker->elems);
	    MyFree(walker->allocMap);
	    if (last)
	    {
		last->next = walker->next;
		MyFree(walker);
		walker = last->next;
	    }
	    else
	    {
		bh->base = walker->next;
		MyFree(walker);
		walker = bh->base;
	    }
	    bh->blocksAllocated--;
	    bh->freeElems -= bh->elemsPerBlock;
	}
	else
	{
	    last = walker;
	    walker = walker->next;
	}
    }
    return 0;
}

/* FUNCTION DOCUMENTATION:
 *
 * BlockHeapDestroy
 *
 * Description:
 *  Completely free()s a BlockHeap.  Use for cleanup.
 * Parameters:
 *  bh (IN):  Pointer to the BlockHeap to be destroyed.
 * Returns:
 *  0 if successful, 1 if bh == NULL
 */
int BlockHeapDestroy(BlockHeap *bh)
{
    Block      *walker, *next;
    if (bh == NULL) return 1;
    for (walker = bh->base; walker != NULL; walker = next)
    {
	next = walker->next;
	MyFree(walker->elems);
	MyFree(walker->allocMap);
	MyFree(walker);
    }
    MyFree(bh);	
    return 0;
}

u_long
memcount_BlockHeap(BlockHeap *bh, MCBlockHeap *mc)
{
    mc->file = __FILE__;

    mc->blocks.c = bh->blocksAllocated;
    mc->blocks.m = sizeof(Block) * mc->blocks.c;
    mc->blocks.m += (sizeof(unsigned long) * (bh->numlongs + 1))
                    * mc->blocks.c;
    mc->pool.c = bh->blocksAllocated * bh->elemsPerBlock;
    mc->pool.m = mc->pool.c * bh->elemSize;
    mc->objects.c = mc->pool.c - bh->freeElems;
    mc->objects.m = mc->objects.c * bh->elemSize;

    mc->management.c = mc->blocks.c + 1;
    mc->management.m = mc->blocks.m + sizeof(*bh);

    mc->total.c = mc->management.c + mc->pool.c;
    mc->total.m = mc->management.m + mc->pool.m;

    mc->objsize = bh->elemSize;

    return mc->total.m;
}

u_long
memcount_blalloc(MCblalloc *mc)
{
    mc->file = __FILE__;

    return 0;
}

