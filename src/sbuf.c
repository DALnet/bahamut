/************************************************************************
 *   IRC - Internet Relay Chat, src/sbuf.c
 *   Copyright (C) 2004 David Parton
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * $Id$
 */

#include "sbuf.h"
#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"

#include <stdio.h>
#include <stdlib.h>

extern void outofmemory(void);

typedef struct _SBuffer 
{
    struct _SBuffer *next;
    int        bufsize;
    int        refcount;
    char       *end;
} SBuffer;

typedef struct _SBufBlock
{
    int        num;
    SBuffer*   bufs;
    struct _SBufBlock *next;
} SBufBlock;

typedef struct _SBufUser
{
    char       *start;
    SBuffer    *buf;
    struct _SBufUser *next;
} SBufUser;

typedef struct _SBufUserBlock
{
    int        num;
    SBufUser   *users;
    struct _SBufUserBlock *next;
} SBufUserBlock;

SBuffer             *largesbuf_pool = NULL, *smallsbuf_pool = NULL;
SBufUser            *user_pool = NULL;
SBufBlock           *sbuf_blocks = NULL;
SBufUserBlock       *sbufuser_blocks = NULL;


#define SBUF_BASE				sizeof(SBuffer)
#define SBUF_LARGE_TOTAL		(SBUF_BASE + SBUF_LARGE_BUFFER)
#define SBUF_SMALL_TOTAL        (SBUF_BASE + SBUF_SMALL_BUFFER)


int sbuf_allocblock_general(int theMemorySize, int num, SBuffer** thePool)
{
    SBufBlock*    block;
    SBuffer*      bufs;
    int           i;
    
    block = (SBufBlock*)malloc(sizeof(SBufBlock));
    if (!block)
        outofmemory();
        
    block->bufs = (SBuffer*)malloc(theMemorySize * num);
    if (!block->bufs)
        outofmemory();
        
    block->num = num;
    block->next = sbuf_blocks;
    sbuf_blocks = block;
    
    bufs = block->bufs;
    for (i = 0; i < block->num - 1; ++i)
    {
        bufs->bufsize = theMemorySize - SBUF_BASE;
        bufs->next = (SBuffer*)(((char*)bufs) + theMemorySize);
        bufs = bufs->next;
    }
    bufs->bufsize = theMemorySize - SBUF_BASE;
    bufs->next = *thePool;
    *thePool = block->bufs;
    
    return 0;
}
    
int sbuf_allocblock_small(int theMemorySize)
{
    if (theMemorySize % SBUF_SMALL_TOTAL != 0)
        theMemorySize = (theMemorySize + SBUF_SMALL_TOTAL);
        
    return sbuf_allocblock_general(SBUF_SMALL_TOTAL, theMemorySize / SBUF_SMALL_TOTAL, &smallsbuf_pool);
}

int sbuf_allocblock_large(int theMemorySize)
{
    if (theMemorySize % SBUF_LARGE_TOTAL != 0)
        theMemorySize = (theMemorySize + SBUF_LARGE_TOTAL);
    
    return sbuf_allocblock_general(SBUF_LARGE_TOTAL, theMemorySize / SBUF_LARGE_TOTAL, &largesbuf_pool);
}

int sbuf_allocblock_users(int theCount)
{
    SBufUserBlock* block;
    SBufUser*      users;
    int            i;
    
    block = (SBufUserBlock*)malloc(sizeof(SBufUserBlock));
    if (!block)
        outofmemory();
        
    block->users = (SBufUser*)malloc(sizeof(SBufUser) * theCount);
    if (!block->users)
        outofmemory();
        
    block->num = theCount;
    block->next = sbufuser_blocks;
    sbufuser_blocks = block;
    
    users = block->users;
    for (i = 0; i < block->num - 1; ++i)
    {
        users->next = users+1;
        users++;
    }
    users->next = user_pool;
    user_pool = block->users;

    return 0;
}
    

int sbuf_init()
{
    sbuf_allocblock_small(INITIAL_SBUFS_SMALL);
    sbuf_allocblock_large(INITIAL_SBUFS_LARGE);
    sbuf_allocblock_users(INITIAL_SBUFS_USERS);
    return 0;
}

int sbuf_free(SBuffer* buf)
{
    switch (buf->bufsize)
    {
    case SBUF_LARGE_BUFFER:
        buf->next = largesbuf_pool;
        largesbuf_pool = buf;
        break;
        
    case SBUF_SMALL_BUFFER:
        buf->next = smallsbuf_pool;
        smallsbuf_pool = buf;
        break;
        
    default:
        return -1;
    }
    return 0;
}

int sbuf_user_free(SBufUser* user)
{
    user->next = user_pool;
    user_pool = user;
    return 0;
}
       
SBuffer* sbuf_alloc(int theSize)
{
    SBuffer* buf;
    
    if ((theSize + 1) >= SBUF_SMALL_BUFFER)
    {
        buf = largesbuf_pool;
        if (!buf) {
            sbuf_allocblock_large(INITIAL_SBUFS_LARGE);
            buf = largesbuf_pool;
            if (!buf) return NULL;
        }
        largesbuf_pool = largesbuf_pool->next;
        
        buf->bufsize = SBUF_LARGE_BUFFER;
        buf->refcount = 0;
        buf->end = ((char*)buf) + SBUF_BASE;
        buf->next = NULL;
        return buf;
    }
    else
    {
        buf = smallsbuf_pool;
        if (!buf) {
            sbuf_allocblock_small(INITIAL_SBUFS_SMALL);
            buf = smallsbuf_pool;
            if (!buf) return sbuf_alloc(SBUF_SMALL_BUFFER+1); /* attempt to substitute a large buffer instead */
        }
        smallsbuf_pool = smallsbuf_pool->next;
        
        buf->bufsize = SBUF_SMALL_BUFFER;
        buf->refcount = 0;
        buf->end = ((char*)buf) + SBUF_BASE;
        buf->next = NULL;
        return buf;
    }
}

SBufUser* sbuf_user_alloc()
{
    SBufUser* user;
    
    user = user_pool;
    if (!user)
    {
        sbuf_allocblock_users(INITIAL_SBUFS_USERS);
        user = user_pool;
        if (!user) return NULL;
    }
    user_pool = user_pool->next;
    
    user->next = NULL;
    user->start = NULL;
    user->buf = NULL;
    return user;
}
        

int sbuf_alloc_error()
{
    outofmemory();
    return -1;
}

/* Global functions */

int sbuf_begin_share(const char* theData, int theLength, void **thePtr)
{
    SBuffer *s;
    
    s = sbuf_alloc(theLength);
    if (!s || theLength + 2 > s->bufsize) return sbuf_alloc_error();
    
    memcpy(s->end, theData, theLength);
    s->end += theLength;
    *s->end++ = '\r';
    *s->end++ = '\n';
    s->refcount = 0;
    
    *thePtr = (void*)s;
    return 1;
}

int sbuf_put_share(SBuf* theBuf, void* theSBuffer)
{
    SBufUser *user;
    SBuffer  *s = (SBuffer*)theSBuffer;
    
    if (!s) return -1;
    
    s->refcount++;
    user = sbuf_user_alloc();
    user->buf = s;
    user->start = (char*)(user->buf) + SBUF_BASE;
    
    if (theBuf->length == 0)
        theBuf->head = theBuf->tail = user;
    else
    {
        theBuf->tail->next = user;
        theBuf->tail = user;
    }
    theBuf->length += user->buf->end - user->start;
    return 1;
}
        
int sbuf_put(SBuf* theBuf, const char* theData, int theLength)
{
    SBufUser        **user, *u;
    int             chunk;
    
    if (theBuf->length == 0)
        user = &theBuf->head;
    else
        user = &theBuf->tail;
        
    if ((u = *user) != NULL && u->buf->refcount > 1)
    {
        u->next = sbuf_user_alloc();
        u = u->next;
        if (!u) return sbuf_alloc_error();
        *user = u; /* tail = u */
        
        u->buf = sbuf_alloc(theLength);
        u->buf->refcount = 1;
        u->start = u->buf->end;
    }
    
    theBuf->length += theLength;
    
    for (; theLength > 0; user = &(u->next))
    {
        if ((u = *user) == NULL)
        {
            u = sbuf_user_alloc();
            if (!u) return sbuf_alloc_error();
            *user = u;
            theBuf->tail = u;
            
            u->buf = sbuf_alloc(theLength);
            u->buf->refcount = 1;
            u->start = u->buf->end;
        }
        chunk = (((char*)u->buf) + SBUF_BASE + u->buf->bufsize) - u->buf->end;
        if (chunk)
        {
            if (chunk > theLength) chunk = theLength;
            memcpy(u->buf->end, theData, chunk);
           
            u->buf->end += chunk; 
            theData     += chunk;
            theLength   -= chunk;
        }
    }
    return 1;
}    

int sbuf_delete(SBuf* theBuf, int theLength)
{
    if (theLength > theBuf->length) theLength = theBuf->length;
    
    theBuf->length -= theLength;
    
    while (theLength)
    {
        int chunk = theBuf->head->buf->end - theBuf->head->start;
        if (chunk > theLength) chunk = theLength;
        
        theBuf->head->start += chunk;
        theLength           -= chunk;
        
        if (theBuf->head->start == theBuf->head->buf->end)
        {
            SBufUser *tmp = theBuf->head;
            theBuf->head = theBuf->head->next;
            
            tmp->buf->refcount--;
            if (tmp->buf->refcount == 0)
                sbuf_free(tmp->buf);
            sbuf_user_free(tmp);
        }
    }
    if (theBuf->head == NULL) theBuf->tail = NULL;
    return 1;
}

char* sbuf_map(SBuf* theBuf, int* theLength)
{
    if (theBuf->length != 0)
    {
        *theLength = theBuf->head->buf->end - theBuf->head->start;
        return theBuf->head->start;
    }
    *theLength = 0;
    return NULL;
}

int sbuf_flush(SBuf* theBuf)
{
    SBufUser *tmp;
    
    if (theBuf->length == 0) return 0;
    
    while (theBuf->head)
    {
        char *ptr = theBuf->head->start;
        while (ptr < theBuf->head->buf->end && IsEol(*ptr)) ptr++;
        
        theBuf->length -= ptr - theBuf->head->start;
        theBuf->head->start = ptr;
        if (ptr < theBuf->head->buf->end) break;
        
        tmp = theBuf->head;
        theBuf->head = tmp->next;
        
        tmp->buf->refcount--;
        if (tmp->buf->refcount == 0)
            sbuf_free(tmp->buf);
        sbuf_user_free(tmp);
    }
    if (theBuf->head == NULL) theBuf->tail = NULL;
    return theBuf->length;   
}

int sbuf_getmsg(SBuf* theBuf, char* theData, int theLength)
{
    SBufUser    *user;
    int         copied;
    
    if (sbuf_flush(theBuf) == 0) return 0;
    
    copied = 0;
    for (user = theBuf->head; user && theLength; user = user->next)
    {
        char *ptr, *max = user->start + theLength; 
        if (max > user->buf->end) max = user->buf->end;
        
        for (ptr = user->start; ptr < max && !IsEol(*ptr); )
            *theData++ = *ptr++;
            
        copied    += ptr - user->start;
        theLength -= ptr - user->start;
        
        if (ptr < max)
        {
            *theData = 0;
            sbuf_delete(theBuf, copied);
            sbuf_flush(theBuf);
            return copied;
        }
    }
    return 0;
}    

int sbuf_get(SBuf* theBuf, char* theData, int theLength)
{
    char   *buf;
    int    chunk, copied;
    
    if (theBuf->length == 0) return 0;
    
    copied = 0;
    while (theLength && (buf = sbuf_map(theBuf, &chunk)) != NULL)
    {
        if (chunk > theLength) chunk = theLength;
        
        memcpy(theData, buf, chunk);
        copied    += chunk;
        theData   += chunk;
        theLength -= chunk;
        sbuf_delete(theBuf, chunk);
    }
    return copied;
}
        
        
