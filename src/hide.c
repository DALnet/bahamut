/************************************************************************
 *   IRC - Internet Relay Chat, src/hide.c
 *   Copyright (C) 2003 Lucas Madar
 *
 *   hide.c - code for hiding information
 *
 */

/* $Id$ */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "fds.h"
#include "numeric.h"

/* This is how we maintain a 'fake' list of servers */

struct fakelinkserver {
   char *name;
   char *description;
};

static Link *lserver_list = NULL;

static struct fakelinkserver *fakelinkserver_find(char *name)
{
   Link *lp;
   struct fakelinkserver *ls;

   for(lp = lserver_list; lp; lp = lp->next)
   {
      ls = (struct fakelinkserver *) lp->value.cp;
      if(mycmp(name, ls->name) == 0)
         return ls;
   }
   return NULL;
}

/*
 * Delete the entire list
 */
void fakelinkserver_reset()
{
   Link *lp;
   struct fakelinkserver *ls;

   while((lp = lserver_list))
   {
      lserver_list = lp->next;

      ls = (struct fakelinkserver *) lp->value.cp;
      MyFree(ls->name);
      MyFree(ls->description);
      MyFree(ls);
      free_link(lp);
   }
}

static void fakelinkserver_delete(char *name)
{
   Link *lp, *lpprev, *lpn;
   struct fakelinkserver *ls;

   for(lp = lserver_list, lpprev = NULL; lp; lpprev = lp, lp = lpn)
   {
      lpn = lp->next;
      ls = (struct fakelinkserver *) lp->value.cp;
      if(mycmp(name, ls->name) == 0)
      {
         if(lpprev)
            lpprev->next = lp->next;
         else
            lserver_list = lp->next;

         MyFree(ls->name);
         MyFree(ls->description);
         MyFree(ls);
         free_link(lp);
         return;
      }
   }
}

static void fakelinkserver_add(char *name, char *desc)
{
   struct fakelinkserver *ls;
   Link *lp;

   if(fakelinkserver_find(name))
      return;

   ls = (struct fakelinkserver *) MyMalloc(sizeof(struct fakelinkserver));
   ls->name = (char *) MyMalloc(strlen(name) + 1);
   strcpy(ls->name, name);
   ls->description = (char *) MyMalloc(strlen(desc) + 1);
   strcpy(ls->description, desc);

   lp = make_link();
   lp->value.cp = (char *) ls;
   lp->next = lserver_list;
   lserver_list = lp;
}

/*
 * update the server's description 
 */
void fakelinkserver_update(char *name, char *desc)
{
   struct fakelinkserver *ls;

   if(!(ls = fakelinkserver_find(name)))
      return;

   MyFree(ls->description);
   ls->description = (char *) MyMalloc(strlen(desc) + 1);
   strcpy(ls->description, desc);
}

int fakelinkscontrol(int parc, char *parv[])
{
   if(parc < 1)
      return 0;

   if(parc > 0 && mycmp(parv[0], "RESET") == 0)
   {
      fakelinkserver_reset();
      return 0;
   }

   if(parc > 1 && mycmp(parv[0], "+") == 0)
   {
      char *servername = parv[1];
      aClient *acptr = find_server(servername, NULL);
      char *desc = (parc > 2) ? parv[2] : HIDDEN_SERVER_DESC;

      if(strchr(servername, '.') == NULL)
         return 0;

      if(strchr(servername, ' ') != NULL)
         return 0;

      fakelinkserver_add(servername, acptr ? acptr->info : desc);
   }

   if(parc > 1 && mycmp(parv[0], "-") == 0)
   {
      char *servername = parv[1];

      fakelinkserver_delete(servername);
   }

   return 0;
}

void fakeserver_list(aClient *sptr)
{
   Link *lp;

   for (lp = lserver_list; lp; lp = lp->next)
   {
      struct fakelinkserver *ls = (struct fakelinkserver *) lp->value.cp;

      sendto_one(sptr, rpl_str(RPL_LINKS), me.name, sptr->name,
                 ls->name, ls->name, 0, ls->description);
   }
}

void fakeserver_sendserver(aClient *sptr)
{
   Link *lp;

   sendto_one(sptr, ":%s LINKS CONTROL RESET", me.name);

   for (lp = lserver_list; lp; lp = lp->next)
   {
      struct fakelinkserver *ls = (struct fakelinkserver *) lp->value.cp;

      sendto_one(sptr, ":%s LINKS CONTROL + %s :%s",
                 me.name, ls->name, ls->description);
   }
}
