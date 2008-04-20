#ifndef THROTTLE_H
#define THROTTLE_H
/*
 * Copyright 2000, 2001 Chip Norkus
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 
 * 2a. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 * 2b. Redistribution in binary form requires specific prior written
 *     authorization of the maintainer.
 * 
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgement:
 *    This product includes software developed by Chip Norkus.
 * 
 * 4. The names of the maintainer, developers and contributors may not be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE MAINTAINER, DEVELOPERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
 * BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE DEVELOPERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* define functions with throttling enabled, then add other definitions later
 * in case throttling was removed at compile time to speed along the system ;)
 * the functions are pretty simple, externally.  throttle_check is given
 * an IP in string dotted quad form, and returns 1 if it should be allowed,
 * or 0 if it is to be throttled and dropped.  this should be done at the same
 * time as the z:line check.  throttle_timer() should be called once per i/o
 * loop to expire throttles and Z:lines.  All other structures and functions
 * can be found in src/throttle.c as they should not be accessed outside of it.
 *
 * additionally, throttle_init() should be called once at initialization stage
 * to setup hash tables and what-have-you
 */

/* setting bits */
extern int throttle_enable, throttle_tcount, throttle_ttime, throttle_rtime;
void throttle_force(char *host);


#ifdef THROTTLE_ENABLE
int throttle_check(char *ip, int fd, time_t sotime);
void throttle_remove(char *host);
void throttle_timer(time_t now);

void throttle_init(void);
void throttle_rehash(void);
void throttle_resize(int size);
void throttle_stats(aClient *cptr, char *name);

#else

#define throttle_check(x,y,z) ((int)1)
#define throttle_remove(x) ((void)0)
#define throttle_timer(x) ((void)0)

#define throttle_init() ((void)0)
#define throttle_rehash() ((void)0)
#define throttle_resize(x) ((void)0)
#define throttle_stats(x,y) ((void)0)
#endif


#include "queue.h"

SLIST_HEAD(hashent_list_t, hashent_t);
typedef struct hashent_list_t hashent_list;

typedef struct hashent_t
{
    void    *ent;
    SLIST_ENTRY(hashent_t) lp;
} hashent;

typedef struct hash_table_t
{
    int     size;           /* this should probably always be prime :) */
    hashent_list *table;    /* our table */
    size_t  keyoffset;      /* this stores the offset of the key from the
        given structure */
    size_t  keylen;         /* the length of the key. if 0, assume key
        is a NULL terminated string */

#define HASH_FL_NOCASE 0x1      /* ignore case (ToLower before hash) */
#define HASH_FL_STRING 0x2      /* key is a nul-terminated string, treat len
    as a maximum length to hash */
    int     flags;
    /* our comparison function, used in hash_find_ent().  this behaves much
        * like the the compare function is used in qsort().  This means that a
        * return of 0 (ZERO) means success! (this lets you use stuff like
                                             * strncmp easily) */
    int     (*cmpfunc)(void *, void *);
} hash_table;

/* this function creates a hashtable with 'elems' buckets (elems should be
* prime for best efficiency).  'offset' is the offset of the key from
* structures being added (this should be obtained with the 'offsetof()'
                          * function).  len is the length of the key, and flags are any flags for the
* table (see above).  cmpfunc is the function which should be used for
* comparison when calling 'hash_find' */
hash_table *create_hash_table(int elems, size_t offset, size_t len, int flags,
                              int (*cmpfunc)(void *, void *));
/* this function destroys a previously created hashtable */
void destroy_hash_table(hash_table *table);
/* this function resizes a hash-table to the new size given with 'elems'.
* this is not in any way inexpensive, and should really not be done very
* often.  */
void resize_hash_table(hash_table *table, int elems);
/* this function gets the hash value of a given key, relative to the size of
* the hashtable */
unsigned int hash_get_key_hash(hash_table *table, void *key, size_t offset);
/* these functions do what you would expect, adding/deleting/finding items
* in a hash table */
int hash_insert(hash_table *table, void *ent);
int hash_delete(hash_table *table, void *ent);
void *hash_find(hash_table *table, void *key);

#endif /* THROTTLE_H */
/* vi:set ts=8 sts=4 sw=4 tw=79: */
