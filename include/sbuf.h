/************************************************************************
 *   IRC - Internet Relay Chat, include/sbuf.h
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
 */
/* $Id$ */

#ifndef SBUF_H
#define SBUF_H

/* Definitions */
#define SBUF_LARGE_BUFFER			512
#define SBUF_SMALL_BUFFER			256

/* Macros */
#define IsEol(c)                    ((c) == '\r' || (c) == '\n')
#define SBufLength(s)				((s)->length)
#define SBufClear(s)				sbuf_delete((s), (s)->length)

/* forward declaration */
struct _SBufUser;
struct _SBuf;


typedef struct _SBuf
{
    int       length;
    struct _SBufUser *head, *tail;
} SBuf;

/* function protoypes */

extern int			sbuf_init();
extern int			sbuf_begin_share(const char* theData, int theLength, void** thePtr);
extern int          sbuf_end_share(void** thePtr, int theNum);
extern int          sbuf_put_share(SBuf* theBuf, void *theSBuffer);
extern int			sbuf_put(SBuf* theBuf, const char* theData, int theLength);
extern int			sbuf_delete(SBuf* theBuf, int theLength);
extern char*		sbuf_map(SBuf* theBuf, int* theLength);
extern int          sbuf_flush(SBuf* theBuf);
extern int          sbuf_getmsg(SBuf* theBuf, char* theData, int theLength);
extern int          sbuf_get(SBuf* theBuf, char* theData, int theLength);

#ifdef WRITEV_IOV
extern int          sbuf_mapiov(SBuf *, struct iovec *);
#endif

#endif /* #ifndef SBUF_H */
