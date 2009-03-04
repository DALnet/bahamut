/************************************************************************
 *   IRC - Internet Relay Chat, src/clientlist.c
 *   Copyright (C) 2003 Lucas Madar
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "numeric.h"
#include "blalloc.h"
#include "memcount.h"

DLink *server_list = NULL;
DLink *oper_list = NULL;

/* Clients currently doing a /list */
DLink *listing_clients = NULL;
DLink *recvq_clients = NULL;

DLink *add_to_list(DLink **list, void *ptr) 
{
   DLink *lp = make_dlink();
  
   lp->value.cp = (char *) ptr;
   lp->next = *list;
   lp->prev = NULL;
   if(lp->next)
      lp->next->prev = lp;
   *list = lp;

   return lp;
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

void remove_from_list(DLink **list, void *ptr, DLink *link)
{
   DLink *lp;

   if(link)
   {
      remove_dlink_list(list, link);
      return;
   }

   for(lp = *list; lp; lp = lp->next)
   {
      if(lp->value.cp == (char *) ptr)
      {
         remove_dlink_list(list, lp);
         return;
      }
   }

   sendto_realops("remove_from_list(%x, %x) failed!!", (u_long) list, (u_long) ptr);
}

u_long
memcount_clientlist(MCclientlist *mc)
{
    mc->file = __FILE__;

    mc->e_server_dlinks = mc_dlinks(server_list);
    mc->e_oper_dlinks = mc_dlinks(oper_list);
    mc->e_recvq_dlinks = mc_dlinks(recvq_clients);
    /* listing_clients is handled in channel.c */

    return 0;
}

