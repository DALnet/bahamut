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

DLink *server_list = NULL;
DLink *oper_list = NULL;

/* Clients currently doing a /list */
DLink *listing_clients = NULL;
DLink *recvq_clients = NULL;

int get_list_memory(DLink *list)
{
   DLink *lp;
   int count = 0;

   for(lp = list; lp; lp = lp->next)
      count++;

   return count;
}

void print_list_memory(aClient *cptr)
{
   int lc;

   lc = get_list_memory(server_list);
   sendto_one(cptr, ":%s %d %s :   server_list %d(%d)",
              me.name, RPL_STATSDEBUG, cptr->name, lc, lc * sizeof(DLink));

   lc = get_list_memory(oper_list);
   sendto_one(cptr, ":%s %d %s :   oper_list %d(%d)",
              me.name, RPL_STATSDEBUG, cptr->name, lc, lc * sizeof(DLink));

   lc = get_list_memory(listing_clients);
   sendto_one(cptr, ":%s %d %s :   listing_clients %d(%d)",
              me.name, RPL_STATSDEBUG, cptr->name, lc, lc * sizeof(DLink));

   lc = get_list_memory(recvq_clients);
   sendto_one(cptr, ":%s %d %s :   recvq_clients %d(%d)",
              me.name, RPL_STATSDEBUG, cptr->name, lc, lc * sizeof(DLink));
}

void add_to_list(DLink **list, aClient *cptr) 
{
   DLink *lp = make_dlink();
  
   lp->value.cptr = cptr;
   lp->next = *list;
   lp->prev = NULL;
   if(lp->next)
      lp->next->prev = lp;
   *list = lp;
}

static inline void remove_dlink_list(DLink **list, DLink *link)
{
   if(link->next)
     link->next->prev = link->prev;

   if(link->prev)
      link->prev->next = link->next;
   else
   {
      *list = link->next;
      if(*list)
         (*list)->prev = NULL;
   }

   free_dlink(link);
}

void remove_from_list(DLink **list, aClient *cptr, DLink *link)
{
   DLink *lp;

   if(link)
   {
      remove_dlink_list(list, link);
      return;
   }

   for(lp = *list; lp; lp = lp->next)
   {
      if(lp->value.cptr == cptr)
      {
         remove_dlink_list(list, lp);
         return;
      }
   }

   sendto_realops("remove_from_list(%x, %x) failed!!", (int) list, (int) cptr);
}
