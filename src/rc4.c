#include <stdio.h>
#include <stdlib.h>

/*
 * Transparent rc4 implementation
 * based upon crypto++ library,
 * which was based upon an anonymous usenet posting.
 * Implemented by lucas madar <lucas at negaverse dot org>
 *
 * Remember that it is IMPERITAVE to generate a new key
 * for each state. DO NOT USE THE SAME KEY FOR ANY TWO STATES.
 */

typedef unsigned char RC4BYTE;
typedef unsigned int RC4DWORD;

struct rc4_state {
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

   rc4 = (struct rc4_state *) malloc(sizeof(struct rc4_state));
   memset(rc4, 0, sizeof(struct rc4_state));

   for(i = 0; i < 256; i++) /* initialize our state array */
      rc4->mstate[i] = (RC4BYTE) i;

   for(i = 0, idx1 = idx2 = 0; i < 256; i++)
   {
      idx2 = (key[idx1++] + rc4->mstate[i] + idx2);

      if(idx2 > 255)
         abort(); /* let the braindead compiler die here instead of causing memleaks */

      tmp = rc4->mstate[i];
      rc4->mstate[i] = rc4->mstate[idx2];
      rc4->mstate[idx2] = tmp;

      if(idx1 >= keylen)
         idx1 = 0;
   }

   return (void *) rc4;
}

void rc4_process_stream(void *rc4_context, unsigned char *istring, unsigned int stringlen)
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

void rc4_destroystate(void *a)
{
   memset(a, 0, sizeof(struct rc4_state));
   free(a);
}
