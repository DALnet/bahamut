/************************************************************************
 *   IRC - Internet Relay Chat, src/clientlist.c
 *   Copyright (C) 2003 Lucas Madar
 */

/* $Id$ */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "numeric.h"
#include "blalloc.h"

Link *server_list = NULL;
Link *oper_list = NULL;

void add_to_list(Link **list, aClient *cptr) 
{
   Link *lp = make_link();
  
   lp->value.cptr = cptr;
   lp->next = *list;
   *list = lp;
}

void remove_from_list(Link **list, aClient *cptr)
{
   Link *lp, *prev;

   for(lp = *list, prev = NULL; lp; prev = lp, lp = lp->next)
   {
      if(lp->value.cptr == cptr)
      {
         if(prev)
            prev->next = lp->next;
         else
            *list = lp->next;
         free_link(lp);
         return;
      }
   }

   sendto_realops("remove_from_list(%x, %x) failed!!", (int) list, (int) cptr);
}
