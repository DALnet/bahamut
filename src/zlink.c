/************************************************************************
 *   IRC - Internet Relay Chat, src/zlink.c
 *   Copyright (C) 2000 Lucas Madar
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

/* $Id: zlink.c 1303 2006-12-07 03:23:17Z epiphani $ */

/*
 * This streaming ircd zlib implementation was
 * inspired mostly by dianora's example in hybrid-6
 * - lucas
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zlib.h"
#include "memcount.h"

#define COMPRESSION_LEVEL 	3 	/* 0 to 9, 0 = none */
#define ZIP_MIN_BLOCK		1024	/* smallest block to compress */
#define ZIP_MAX_BLOCK 		8192	/* largest block to compress */

/*
 * This shouldn't be necessary.
 * The outbuf should never be larger than 
 * the maximum block.. should it?
 * I'll account for any weirdness in zlib.
 *
 * WARNING:
 * Please be aware that if you are using both encryption
 * and ziplinks, rc4buf in send.c MUST be the same size
 * as zipOutBuf in zlink.c!
 */
#define zipOutBufSize (ZIP_MAX_BLOCK * 2)
static char zipOutBuf[zipOutBufSize];

/*
 * 64k overflowed every now and then.
 * This isn't that important, an overflow is 
 * non-fatal, but causes more calls to deflate()
 * 96k seems to overflow a lot now.
 */
#define zipInBufSize (131072) /* 128K */
static char zipInBuf[zipInBufSize];

/* opaque "out" data structure */
struct zipped_link_out 
{
    z_stream    stream;             /* zip stream data */
    char        buf[ZIP_MAX_BLOCK]; /* zipped buffer */
    int         bufsize;            /* size of inbuf content */
};

/* opaque "in" data structure */
struct zipped_link_in 
{
    z_stream    stream;             /* zip stream data */
};

/* returns a pointer to a setup opaque input session */
void *zip_create_input_session()
{
    struct zipped_link_in *zip;

    zip = (struct zipped_link_in *) MyMalloc(sizeof(struct zipped_link_in));

    memset(zip, 0, sizeof(struct zipped_link_in));

    zip->stream.zalloc = NULL;
    zip->stream.zfree = NULL;
    zip->stream.data_type = Z_ASCII;

    if(inflateInit(&zip->stream) != Z_OK)
	return NULL;

    return (void *) zip;
}

/* returns a pointer to an opaque output session */
void *zip_create_output_session()
{
    struct zipped_link_out *zip;

    zip = (struct zipped_link_out *) MyMalloc(sizeof(struct zipped_link_out));

    memset(zip, 0, sizeof(struct zipped_link_out));

    zip->stream.zalloc = NULL;
    zip->stream.zfree = NULL;
    zip->stream.data_type = Z_ASCII;

    if(deflateInit(&zip->stream, COMPRESSION_LEVEL) != Z_OK)
	return NULL;

    return (void *) zip;
}

/*
 * zip_input()
 *
 * session - opaque in-session pointer
 * buffer - compressed buffer
 * len - length of buffer (will change)
 * err - numeric error if length is -1 on return
 * nbuf - set if this function needs to be called again
 * nbuflen - if nbuf is set, length to call with again.
 *  -- nbuf, if set, should call zip_input when done processing
 *     first return, with buffer set to nbuf.
 * returns:
 * len > -1:
 *   compressed data
 * len == -1:
 *   error message
 */
char *zip_input(void *session, char *buffer, int *len, int *err,
		char **nbuf, int *nbuflen)
{
    struct zipped_link_in *z = (struct zipped_link_in *) session;
    z_stream *zin = &z->stream;
    int ret;

    *nbuf = NULL;
    *err = 0;

    zin->next_in = buffer;
    zin->avail_in = *len;
    zin->next_out = zipInBuf;
    zin->avail_out = zipInBufSize;   

    ret = inflate(zin, Z_SYNC_FLUSH);

    switch(ret)
    {
    case Z_OK:
        if(zin->avail_in) /* grrr, didn't take all the input */
        {
	    if(zin->avail_out != 0) /* but there was still output left??? */
	    {
		*len = -1;
		return zin->msg ? zin->msg : "????";
	    }
	    *nbuf = zin->next_in;
	    *nbuflen = zin->avail_in;
	    *len = zipInBufSize - zin->avail_out;
	    return zipInBuf;
        }
        else
        {
	    *len = zipInBufSize - zin->avail_out;
	    return zipInBuf;
        }

    default:
	*len = -1;
	*err = ret;
	return zin->msg ? zin->msg : "????";
    }
}

/* returns the amount of data waiting in the outgoing buffer */
int zip_is_data_out(void *session)
{
    struct zipped_link_out *z = (struct zipped_link_out *) session;

    return z->bufsize;
}

/*
 * zip_output():
 * session is opaque session pointer.
 * buffer is buffer to compress.
 * len is length of buffer, will change.
 * forceflush forces inflate to return a buffer, even if it has
 * not optimally compressed something.
 * Largedata should be nonzero during a split.
 * largedata is also an error number, it is set if len is -1.
 * if len is -1, returns null terminated error string.
 */
char *zip_output(void *session, char *buffer, int *len,
		 int forceflush, int *largedata)
{
    struct zipped_link_out *z = (struct zipped_link_out *) session;
    z_stream *zout = &z->stream;
    int ret;

    if(buffer)
    {
	memcpy(z->buf + z->bufsize, buffer, *len);
	z->bufsize += *len;
    }

    if( !forceflush && ((z->bufsize < ZIP_MIN_BLOCK) || 
			(largedata && (z->bufsize < (ZIP_MAX_BLOCK - 512)))))
    {
	*len = 0;
	return NULL;
    }
    
    zout->next_in = z->buf;
    zout->avail_in = z->bufsize;
    zout->next_out = zipOutBuf;
    zout->avail_out = zipOutBufSize;
   
    /*
     * We do our own internal buffering,
     * so flush all the time.
     */
    ret = deflate(zout, Z_SYNC_FLUSH);

    if(ret == Z_OK)
    {
	z->bufsize = 0;
	*len = zipOutBufSize - zout->avail_out;
	return zipOutBuf;
    }   

    *len = -1;
    *largedata = ret;
    return zout->msg ? zout->msg : "???";
}

/* if *insiz is zero, there are no stats available for this session. */
void zip_out_get_stats(void *session, unsigned long *insiz,
		       unsigned long *outsiz, double *ratio)
{
    struct zipped_link_out *z = (struct zipped_link_out *) session;
    
    *insiz = z->stream.total_in;
    *outsiz = z->stream.total_out;

    if(*insiz)
	*ratio = ((100.0 * (double)z->stream.total_out) /
		  (double) z->stream.total_in);
}

void zip_in_get_stats(void *session, unsigned long *insiz, 
		      unsigned long *outsiz, double *ratio)
{
   struct zipped_link_in *z = (struct zipped_link_in *) session;

   *insiz = z->stream.total_in;
   *outsiz = z->stream.total_out;

   if(*outsiz)
	*ratio = ((100.0 * (double)z->stream.total_in) / 
		  (double) z->stream.total_out);
}

void zip_destroy_output_session(void *session)
{
    struct zipped_link_out *z = (struct zipped_link_out *) session;

    deflateEnd(&z->stream);
    MyFree(session);
}

void zip_destroy_input_session(void *session)
{
    struct zipped_link_in *z = (struct zipped_link_in *) session;

    inflateEnd(&z->stream);
    MyFree(session);
}

u_long
memcount_zlink(MCzlink *mc)
{
    mc->file = __FILE__;

    mc->m_insession_size = sizeof(struct zipped_link_in);
    mc->m_outsession_size = sizeof(struct zipped_link_out);

    mc->s_bufs.c++;
    mc->s_bufs.m += sizeof(zipOutBuf);
    mc->s_bufs.c++;
    mc->s_bufs.m += sizeof(zipInBuf);

    return 0;
}

