/************************************************************************
 *   IRC - Internet Relay Chat, src/dbuf.c
 *   Copyright (C) 1990 Markku Savela
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
 *
 * For documentation of the *global* functions implemented here,
 * see the header file (dbuf.h).
 *
 *
 * $Id$
 */

#include "dbuf.h"
#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"

#include <stdio.h>
#include <stdlib.h>


/*
 * And this 'DBufBuffer' should never be referenced outside the
 * implementation of 'dbuf'--would be "hidden" if C had such
 * keyword...
 * doh!!! ya just gotta know how to do it ;-)
 */
/*
 * DBUF_SIZE must be a power of 2 so we can mask for the offset
 */
#define DBUF_SIZE 2048

struct DBufBuffer {
  struct DBufBuffer* next;             /* Next data buffer, NULL if last */
  char*              start;            /* data starts here */
  char*              end;              /* data ends here */ 
  char               data[DBUF_SIZE];  /* Actual data stored here */
};

struct DBufBlock {
  struct DBufBuffer *buf;
  int num;
  struct DBufBlock *next;
};

int                       DBufUsedCount = 0;
int                       DBufCount = 0;
static struct DBufBuffer* dbufFreeList = NULL;
static struct DBufBlock *dbuf_blocks = NULL;

void count_dbuf_memory(size_t* allocated, size_t* used)
{
  *allocated = DBufCount     * sizeof(struct DBufBuffer);
  *used      = DBufUsedCount * sizeof(struct DBufBuffer);
}

/* 
 * dbuf_init--initialize a stretch of memory as dbufs.
 * Doing this early on should save virtual memory if not real memory..
 * at the very least, we get more control over what the server is doing 
 * 
 * mika@cs.caltech.edu 6/24/95
 *
 * XXX - Unfortunately this makes cleanup impossible because the block 
 * pointer isn't saved and dbufs are not allocated in chunks anywhere else.
 *
 * Not anymore -- now we allocate dbufs in chunks so we don't fragment
 * memory to hell and back - lucas
 */

void dbuf_allocblock(int num)
{
  struct DBufBlock *dblock;
  struct DBufBuffer *dfree, *dbp;
  int i;

  dblock = (struct DBufBlock *) MyMalloc(sizeof(struct DBufBlock));  
  dblock->num = num;
  dblock->next = dbuf_blocks;
  dbuf_blocks = dblock;

  dbp = (struct DBufBuffer *) MyMalloc(sizeof(struct DBufBuffer) * num);
  dblock->buf = dbp;

  dfree = dbp;

  for(i = 0; i < (num - 1); i++)
  {
    dfree->next = (dfree + 1);
    dfree++;
  }

  dfree->next = dbufFreeList;

  dbufFreeList = dbp;

  DBufCount += num;
}

void dbuf_init()
{
  /* allocate one block of the initial size */

  dbuf_allocblock(INITIAL_DBUFS);
}

/*
 * dbuf_alloc - allocates a struct DBufBuffer structure either from 
 * dbufFreeList or create a new one.
 */
static struct DBufBuffer* dbuf_alloc()
{
  struct DBufBuffer* db = dbufFreeList;

/*
 * At present, do NOT define this.  It will cause you to drop users on
 * largish nets.
 * 
 * We are allocating dbufs unlimitedly to deal with large channels on
 * splits and other known issue.
 * 
 * Once again, define the following only for testing purposes
 * - Raistlin
 */

#undef DBUFS_WORKING_CORRECTLY
   
#ifdef DBUFS_WORKING_CORRECTLY  
  if (DBufUsedCount * DBUF_SIZE >= BUFFERPOOL)
    return NULL;
#endif
   
  if (!db)
  {
    dbuf_allocblock(INITIAL_DBUFS);
    db = dbufFreeList;
    if(!db) 
      return NULL;
  }

  dbufFreeList = dbufFreeList->next;

  ++DBufUsedCount;

  db->next  = 0;
  db->start = db->end = db->data;
  return db;
}

/*
 * dbuf_free - return a struct DBufBuffer structure to the dbufFreeList
 */
static void dbuf_free(struct DBufBuffer* ptr)
{
  DBufUsedCount--;
  ptr->next = dbufFreeList;
  dbufFreeList = ptr;
}
/*
** This is called when malloc fails. Scrap the whole content
** of dynamic buffer and return -1. (malloc errors are FATAL,
** there is no reason to continue this buffer...). After this
** the "dbuf" has consistent EMPTY status... ;)
*/
static int dbuf_malloc_error(struct DBuf* dyn)
{
  struct DBufBuffer* db;

  dyn->length = 0;
  while (0 != (db = dyn->head)) {
    dyn->head = db->next;
    dbuf_free(db);
  }
  dyn->tail = 0;
  return 0;
}

/*
 * dbuf_put - put a sequence of bytes in a dbuf
 */
int dbuf_put(struct DBuf* dyn, const char* buf, size_t length)
{
  struct DBufBuffer** h;
  struct DBufBuffer*  d;
  int                 chunk;

  /*
   * Locate the last non-empty buffer. If the last buffer is
   * full, the loop will terminate with 'd==NULL'. This loop
   * assumes that the 'dyn->length' field is correctly
   * maintained, as it should--no other check really needed.
   */
  if (0 == dyn->length)
    h = &(dyn->head);
  else
    h = &(dyn->tail);
  /*
   * Append users data to buffer, allocating buffers as needed
   */
  dyn->length += length;

  for ( ; length > 0; h = &(d->next)) {
    if (0 == (d = *h)) {
      if (0 == (d = dbuf_alloc()))
        return dbuf_malloc_error(dyn);

      dyn->tail = d;
      *h        = d;        /* prev->next = d */
    }
    chunk = (d->data + DBUF_SIZE) - d->end;
    if (chunk) {
      if (chunk > length)
        chunk = length;
      
      memcpy(d->end, buf, chunk);

      length -= chunk;
      buf    += chunk;
      d->end += chunk;
    }
  }
  return 1;
}


char* dbuf_map(struct DBuf* dyn, size_t* length)
{
  if (0 == dyn->length) {
    *length   = 0;
    return 0;
  }

  *length = dyn->head->end - dyn->head->start;
  return dyn->head->start;
}


void dbuf_delete(struct DBuf* dyn, size_t length)
{
  struct DBufBuffer* db;
  size_t             chunk;

  if (length > dyn->length)
    length = dyn->length;

  while (length > 0) {
    if (0 == (db = dyn->head))
      break;
    chunk = db->end - db->start; 
    if (chunk > length)
      chunk = length;

    length      -= chunk;
    dyn->length -= chunk;
    db->start   += chunk;

    if (db->start == db->end) {
      dyn->head = db->next;
      dbuf_free(db);
    }
  }
  if (0 == dyn->head) {
    dyn->tail   = 0;
    dyn->length = 0;
  }
}

size_t dbuf_get(struct DBuf* dyn, char* buf, size_t length)
{
  size_t      moved = 0;
  size_t      chunk;
  const char* b;

  while (length > 0 && (b = dbuf_map(dyn, &chunk)) != 0) {
    if (chunk > length)
      chunk = length;

    memcpy(buf, b, chunk);
    dbuf_delete(dyn, chunk);

    buf    += chunk;
    length -= chunk;
    moved  += chunk;
  }
  return moved;
}

static size_t dbuf_flush(struct DBuf* dyn)
{
  struct DBufBuffer* db = dyn->head;
  
  if (0 == db)
    return 0;

  /*
   * flush extra line terms
   */
  while (IsEol(*db->start)) {
    if (++db->start == db->end) {
      dyn->head = db->next;
      dbuf_free(db);
      if (0 == (db = dyn->head)) {
        dyn->tail   = 0;
        dyn->length = 0;
        break;
      }
    }
    --dyn->length;
  }
  return dyn->length;
}

/*
 * dbuf_getmsg
 *
 * Check the buffers to see if there is a string which is terminated with
 * either a \r or \n present.  If so, copy as much as possible (determined by
 * length) into buf and return the amount copied - else return 0.
 *
 * There may be cr/lf pairs or leading garbage in the dbuf to start with
 *
 * case 1:
 *   data starts at buf + offset, entire message fits in a dbuf
 * case 2:
 *   data starts at buf + offset, more than one dbuf is spanned
 */
int dbuf_getmsg(struct DBuf* dyn, char* buf, size_t length)
{
  struct DBufBuffer* db;
  char*              start;
  char*              end;
  size_t             count;
  size_t             copied = 0;

  if (0 == dbuf_flush(dyn))
    return 0;

  db    = dyn->head;
  start = db->start;

  if (length > dyn->length)
    length = dyn->length;
  /*
   * might as well copy it while we're here
   */
  while (length > 0) {
    end = IRCD_MIN(db->end, (start + length));
    while (start < end && !IsEol(*start))
      *buf++ = *start++;

    count = start - db->start;
    if (start < end) {
      *buf = '\0';
      copied += count;
      dbuf_delete(dyn, copied);
      dbuf_flush(dyn);
      return copied;
    } 
    if (0 == (db = db->next))
      break;
    copied += count;
    length -= count;
    start = db->start;
  }
  return 0;  
}
