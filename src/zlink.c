#include <stdio.h>
#include <stdlib.h>
#include "zlib.h"

#define COMPRESSION_LEVEL 	3 	/* 0 to 9, 0 = none */
#define ZIP_MIN_BLOCK		1024	/* smallest block to compress */
#define ZIP_MAX_BLOCK 		8192	/* largest block to compress */

struct zipped_link_out {
   z_stream    stream;             /* zip stream data */
   char        buf[ZIP_MAX_BLOCK]; /* zipped buffer */
   int         bufsize;            /* size of inbuf content */
};

struct zipped_link_in {
   z_stream    stream;             /* zip stream data */
};

void *zip_create_input_session()
{
   struct zipped_link_in *zip;

   zip = (struct zipped_link_in *) malloc(sizeof(struct zipped_link_in));

   memset(zip, 0, sizeof(struct zipped_link_in));

   zip->stream.zalloc = NULL;
   zip->stream.zfree = NULL;
   zip->stream.data_type = Z_ASCII;

   if(inflateInit(&zip->stream) != Z_OK)
      return NULL;

   return (void *) zip;
}

void *zip_create_output_session()
{
   struct zipped_link_out *zip;

   zip = (struct zipped_link_out *) malloc(sizeof(struct zipped_link_out));

   memset(zip, 0, sizeof(struct zipped_link_out));

   zip->stream.zalloc = NULL;
   zip->stream.zfree = NULL;
   zip->stream.data_type = Z_ASCII;

   if(deflateInit(&zip->stream, COMPRESSION_LEVEL) != Z_OK)
      return NULL;

   return (void *) zip;
}

#define zipInBufSize (65536)
static char zipInBuf[zipInBufSize];

char *zip_input(void *session, char *buffer, int *len, int *err, char **nbuf, int *nbuflen)
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

/* This shouldn't be necessary... but be safe? */
#define zipOutBufSize (ZIP_MAX_BLOCK * 2)
static char zipOutBuf[zipOutBufSize];

/*
 * session is opaque session pointer.
 * buffer is buffer to compress.
 * len will change.
 * forceflush forces inflate to return a buffer, even if it has
 * not optimally compressed something.
 * Largedata should be nonzero during a split.
 * largedata is also an error indicator, it is set if len is -1.
 * if len is -1, returns null terminated error string.
 */

int zip_is_data_out(void *session)
{
   struct zipped_link_out *z = (struct zipped_link_out *) session;

   return z->bufsize;
}

char *zip_output(void *session, char *buffer, int *len, int forceflush, int *largedata)
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
       (largedata && (z->bufsize < (ZIP_MAX_BLOCK - 512) ) ) ) 
     )
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

void zip_out_get_stats(void *session, unsigned long *insiz, unsigned long *outsiz, double *ratio)
{
   struct zipped_link_out *z = (struct zipped_link_out *) session;

   *insiz = z->stream.total_in;
   *outsiz = z->stream.total_out;

   if(*insiz)
      *ratio = ((100.0 * (double)z->stream.total_out) / (double) z->stream.total_in);
}

void zip_destroy_output_session(void *session)
{
   struct zipped_link_out *z = (struct zipped_link_out *) session;

   deflateEnd(&z->stream);
   free(session);
}

void zip_destroy_input_session(void *session)
{
   struct zipped_link_in *z = (struct zipped_link_in *) session;

   inflateEnd(&z->stream);
   free(session);
}

