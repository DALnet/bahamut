/************************************************************************
 *   IRC - Internet Relay Chat, include/dbuf.h
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
 */
/* $Id: dbuf.h 1303 2006-12-07 03:23:17Z epiphani $ */
#ifndef INCLUDED_dbuf_h
#define INCLUDED_dbuf_h
#ifndef INCLUDED_config_h
#include "config.h"
#endif
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif

#define IsEol(c) (c==10||c==13)
/*
** dbuf is a collection of functions which can be used to
** maintain a dynamic buffering of a byte stream.
** Functions allocate and release memory dynamically as
** required [Actually, there is nothing that prevents
** this package maintaining the buffer on disk, either]
*/
struct DBufBuffer;

/*
** These structure definitions are only here to be used
** as a whole, *DO NOT EVER REFER TO THESE FIELDS INSIDE
** THE STRUCTURES*! It must be possible to change the internal
** implementation of this package without changing the
** interface.
*/
struct DBuf 
{
    struct DBufBuffer* head;   /* First data buffer, if length > 0 */
    struct DBufBuffer* tail;   /* last data buffer, if length > 0 */
    size_t             length; /* Current number of bytes stored */
};

extern int DBufCount;
extern int DBufUsedCount;

/*
** dbuf_put
**      Append the number of bytes to the buffer, allocating more
**      memory as needed. Bytes are copied into internal buffers
**      from users buffer.
**
**      returns > 0, if operation successfull
**              < 0, if failed (due memory allocation problem)
*/
extern int dbuf_put(struct DBuf* dyn, const char* buf, size_t len);

/*
** dbuf_get
**      Remove number of bytes from the buffer, releasing dynamic
**      memory, if applicaple. Bytes are copied from internal buffers
**      to users buffer.
**
**      returns the number of bytes actually copied to users buffer,
**              if >= 0, any value less than the size of the users
**              buffer indicates the dbuf became empty by this operation.
**
**              Return 0 indicates that buffer was already empty.
**
**              Negative return values indicate some unspecified
**              error condition, rather fatal...
*/
extern size_t dbuf_get(struct DBuf* dbuf, char* buf, size_t len);

/*
** dbuf_map, dbuf_delete
**      These functions are meant to be used in pairs and offer
**      a more efficient way of emptying the buffer than the
**      normal 'dbuf_get' would allow--less copying needed.
**
**      map     returns a pointer to a largest contiguous section
**              of bytes in front of the buffer, the length of the
**              section is placed into the indicated "long int"
**              variable. Returns NULL *and* zero length, if the
**              buffer is empty.
**
**      delete  removes the specified number of bytes from the
**              front of the buffer releasing any memory used for them.
**
**      Example use (ignoring empty condition here ;)
**
**              buf = dbuf_map(&dyn, &count);
**              <process N bytes (N <= count) of data pointed by 'buf'>
**              dbuf_delete(&dyn, N);
**
**      Note:   delete can be used alone, there is no real binding
**              between map and delete functions...
*/
/*
 * dyn - Dynamic buffer header
 * len - Return number of bytes accessible 
 */
extern char* dbuf_map(struct DBuf* dyn, size_t* len);
extern void        dbuf_delete(struct DBuf* dyn, size_t len);

/*
** DBufLength
**      Return the current number of bytes stored into the buffer.
**      (One should use this instead of referencing the internal
**      length field explicitly...)
*/
#define DBufLength(dyn) ((dyn)->length)

/*
** DBufClear
**      Scratch the current content of the buffer. Release all
**      allocated buffers and make it empty.
*/
#define DBufClear(dyn)  dbuf_delete((dyn), DBufLength(dyn))

extern int  dbuf_getmsg(struct DBuf* dyn, char* buf, size_t len);
extern void dbuf_init(void);
extern void count_dbuf_memory(size_t* allocated, size_t* used);

#endif /* INCLUDED_dbuf_h */
