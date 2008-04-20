/************************************************************************
 *   IRC - Internet Relay Chat, src/rc4.c
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

/* $Id: rc4.c 1303 2006-12-07 03:23:17Z epiphani $ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "memcount.h"

/*
 * Transparent rc4 implementation
 * Based upon sample in crypto++ library,
 * which was based upon an anonymous usenet posting.
 * Implemented by Lucas Madar <lucas@dal.net>
 *
 * Remember that it is IMPERITAVE to generate a new key
 * for each state. DO NOT USE THE SAME KEY FOR ANY TWO STATES.
 */

typedef unsigned char RC4BYTE;
typedef unsigned int RC4DWORD;

struct rc4_state
{
    RC4BYTE mstate[256];
    RC4BYTE x;
    RC4BYTE y;
};

void *rc4_initstate(unsigned char *key, int keylen)
{
   RC4DWORD i;
   RC4BYTE tmp, idx1, idx2;
   struct rc4_state *rc4;
   
   if(sizeof(RC4BYTE) != 1)  abort(); /* MUST BE 1 BYTE! */
   if(sizeof(RC4DWORD) != 4) abort(); /* MUST BE 4 BYTES! */
   
   rc4 = (struct rc4_state *) MyMalloc(sizeof(struct rc4_state));
   memset(rc4, 0, sizeof(struct rc4_state));
   
   for(i = 0; i < 256; i++) /* initialize our state array */
       rc4->mstate[i] = (RC4BYTE) i;
   
   for(i = 0, idx1 = idx2 = 0; i < 256; i++)
   {
       idx2 = (key[idx1++] + rc4->mstate[i] + idx2);
       
      tmp = rc4->mstate[i];
      rc4->mstate[i] = rc4->mstate[idx2];
      rc4->mstate[idx2] = tmp;
      
      if(idx1 >= keylen)
	  idx1 = 0;
   }
   
   return (void *) rc4;
}

void rc4_process_stream(void *rc4_context, unsigned char *istring,
			unsigned int stringlen)
{
    struct rc4_state *rc4 = (struct rc4_state *) rc4_context;
    RC4BYTE *s = rc4->mstate;
    RC4DWORD x = rc4->x, y = rc4->y;
    
    while(stringlen--)
    {
	RC4DWORD a, b;
	
	x = (x+1) & 0xFF;
	a = s[x];
	y = (y+a) & 0xFF;
	b = s[y];
	s[x] = b;
	s[y] = a;
	*istring++ ^= s[(a + b) & 0xFF];
    }
    
    rc4->x = (RC4BYTE) x;
    rc4->y = (RC4BYTE) y;
}

void rc4_process_stream_to_buf(void *rc4_context, 
			       const unsigned char *istring, 
                               unsigned char *ostring, unsigned int stringlen)
{
    struct rc4_state *rc4 = (struct rc4_state *) rc4_context;
    RC4BYTE *s = rc4->mstate;
    RC4DWORD x = rc4->x, y = rc4->y;
    
    while(stringlen--)
    {
	RC4DWORD a, b;
	
	x = (x+1) & 0xFF;
	a = s[x];
	y = (y+a) & 0xFF;
	b = s[y];
	s[x] = b;
	s[y] = a;
	*ostring++ = *istring++ ^ s[(a + b) & 0xFF];
    }
    
    rc4->x = (RC4BYTE) x;
    rc4->y = (RC4BYTE) y;
}

void rc4_destroystate(void *a)
{
    memset(a, 0, sizeof(struct rc4_state));
    MyFree(a);
}

u_long
memcount_rc4(MCrc4 *mc)
{
    mc->file = __FILE__;

    mc->m_rc4state_size = sizeof(struct rc4_state);

    return 0;
}

