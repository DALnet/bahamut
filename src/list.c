/************************************************************************
 *   IRC - Internet Relay Chat, src/list.c
 *   Copyright (C) 1990 Jarkko Oikarinen and
 *                      University of Oulu, Finland
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

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "numeric.h"
#include "blalloc.h"

extern int  BlockHeapGarbageCollect(BlockHeap *);

/*
 * locally defined functions 
 */

/*
 * re-written to use Wohali (joant@cadence.com) block allocator
 * routines. very nicely done Wohali
 * 
 * -Dianora
 * 
 */
/*
 * Number of Link's to pre-allocate at a time for Efnet 1000 seems
 * reasonable, for smaller nets who knows? -Dianora
 */

#define LINK_PREALLOCATE 1024
#define CHANMEMBER_PREALLOCATE 1024
/*
 * Number of aClient structures to preallocate at a time for Efnet 1024
 * is reasonable for smaller nets who knows? -Dianora
 */
/*
 * This means you call MyMalloc 30 some odd times, rather than 30k
 * times -Dianora
 */

#define CLIENTS_PREALLOCATE 1024

/* Number of channels to allocate per block, 1024 sounds nice. */

#define CHANNELS_PREALLOCATE 1024

void        outofmemory();

int         numclients = 0;

/*
 * for jolo's block allocator 
 */
BlockHeap  *free_local_aClients;
BlockHeap  *free_Links;
BlockHeap  *free_chanMembers;
BlockHeap  *free_remote_aClients;
BlockHeap  *free_anUsers;
BlockHeap  *free_channels;

#ifdef FLUD
BlockHeap  *free_fludbots;

#endif /*
        * FLUD 
        */

void
initlists()
{
   /*
    * Might want to bump up LINK_PREALLOCATE if FLUD is defined 
    */
   free_Links = BlockHeapCreate((size_t) sizeof(Link), LINK_PREALLOCATE);
   free_chanMembers = BlockHeapCreate((size_t) sizeof(chanMember), CHANMEMBER_PREALLOCATE);

   /*
    * start off with CLIENTS_PREALLOCATE for now... on typical efnet
    * these days, it can get up to 35k allocated
    */

   free_remote_aClients =
      BlockHeapCreate((size_t) CLIENT_REMOTE_SIZE, CLIENTS_PREALLOCATE);

   /*
    * Can't EVER have more than MAXCONNECTIONS number of local aClients 
    */

   free_local_aClients = BlockHeapCreate((size_t) CLIENT_LOCAL_SIZE,
					 MAXCONNECTIONS);
   /*
    * anUser structs are used by both local aClients, and remote
    * aClients
    */

   free_anUsers = BlockHeapCreate((size_t) sizeof(anUser),
				CLIENTS_PREALLOCATE + MAXCONNECTIONS);

   /* channels are a very frequent thing in ircd. :) */

   free_channels = BlockHeapCreate((size_t) sizeof(aChannel),
				CHANNELS_PREALLOCATE);


#ifdef FLUD
   /*
    * fludbot structs are used to track CTCP Flooders 
    */
   free_fludbots = BlockHeapCreate((size_t) sizeof(struct fludbot),
				   MAXCONNECTIONS);

#endif /*
        * FLUD 
        */
}

/*
 * outofmemory()
 * 
 * input                - NONE output           - NONE side effects     -
 * simply try to report there is a problem I free all the memory in the
 * kline lists hoping to free enough memory so that a proper report can
 * be made. If I was already here (was_here) then I got called twice,
 * and more drastic measures are in order. I'll try to just abort() at
 * least. -Dianora
 */

void
outofmemory()
{
static int  was_here = 0;

   if (was_here)
      abort();

   was_here = YES;
   clear_conf_list(&KList1);
   clear_conf_list(&KList2);
   clear_conf_list(&KList3);

   Debug((DEBUG_FATAL, "Out of memory: restarting server..."));
   restart("Out of Memory");
}

/*
 * * Create a new aClient structure and set it to initial state. *
 * 
 *      from == NULL,   create local client (a client connected *
 * o a socket). *
 * 
 *      from,   create remote client (behind a socket *
 * ssociated with the client defined by *
 *  ('from' is a local client!!).
 *
 * uplink is this client's uplink connection to the network. - lucas
 */
aClient    *make_client(aClient *from, aClient *uplink)
{
   aClient *cptr = NULL;

   if (!from) {			/*
				 * from is NULL 
				 */
   cptr = BlockHeapALLOC(free_local_aClients, aClient);

      if (cptr == (aClient *) NULL)
	 outofmemory();

      memset((char *) cptr, '\0' ,CLIENT_LOCAL_SIZE);

      /*
       * Note:  structure is zero (calloc) 
       */
      cptr->from = cptr;	/*
				 * 'from' of local client is self! 
				 */
      /*
       * commenting out unnecessary assigns, but leaving them for
       * documentation. REMEMBER the fripping struct is already zeroed
       * up above =DUH= -Dianora
       */

      /*
       * cptr->next = NULL; 
       */
      /*
       * cptr->prev = NULL; 
       */
      /*
       * cptr->hnext = NULL; 
       */
      /*
       * cptr->user = NULL; 
       */
      /*
       * cptr->serv = NULL; 
       */
      cptr->status = STAT_UNKNOWN;
      cptr->fd = -1;
      cptr->uplink = uplink;
      (void) strcpy(cptr->username, "unknown");
      cptr->since = cptr->lasttime = cptr->firsttime = timeofday;
      /*
       * cptr->confs = NULL; 
       */
      /*
       * cptr->sockhost[0] = '\0'; 
       */
      /*
       * cptr->buffer[0] = '\0'; 
       */
      /*
       * cptr->username[0] = '\0'; 
       */
      cptr->authfd = -1;
      cptr->sendqlen = MAXSENDQLENGTH;
      return (cptr);
   }
   else {			/*
				 * from is not NULL 
				 */
   cptr = BlockHeapALLOC(free_remote_aClients, aClient);

      if (cptr == (aClient *) NULL)
	 outofmemory();

      memset((char *) cptr, '\0', CLIENT_REMOTE_SIZE);

      /*
       * Note:  structure is zero (calloc) 
       */
      cptr->from = from;	/*
				 * 'from' of local client is self! 
				 */
      /*
       * cptr->next = NULL; 
       */
      /*
       * cptr->prev = NULL; 
       */
      /*
       * cptr->hnext = NULL; 
       */
      /*
       * cptr->user = NULL; 
       */
      /*
       * cptr->serv = NULL; 
       */
      cptr->status = STAT_UNKNOWN;
      cptr->fd = -1;
      cptr->uplink = uplink;
      (void) strcpy(cptr->username, "unknown");
      return (cptr);
   }
}

void
free_client(aClient *cptr)
{
   int         retval = 0;

   if (cptr->fd == -2) {
      retval = BlockHeapFree(free_local_aClients, cptr);
   }
   else {
      retval = BlockHeapFree(free_remote_aClients, cptr);
   }
   if (retval) {
      /*
       * Looks "unprofessional" maybe, but I am going to leave this
       * sendto_ops in it should never happen, and if it does, the
       * hybrid team wants to hear about it
       */
      sendto_ops("list.c couldn't BlockHeapFree(free_remote_aClients,cptr) cptr = %lX", cptr);
      sendto_ops("Please report to the hybrid team! bahamut-bugs@bahamut.net");

#if defined(USE_SYSLOG) && defined(SYSLOG_BLOCK_ALLOCATOR)
      syslog(LOG_DEBUG, "list.c couldn't BlockHeapFree(free_remote_aClients,cptr) cptr = %lX", cptr);
#endif
   }
}

/*
 * make_channel() free_channel()
 * functions to maintain blockheap of channels.
 */

aChannel *make_channel()
{
   aChannel *chan;

   chan = BlockHeapALLOC(free_channels, aChannel);

   if(chan == NULL)
      outofmemory();

   memset((char *)chan, '\0', sizeof(aChannel));

   return chan;
}

void free_channel(aChannel *chan)
{
   if (BlockHeapFree(free_channels, chan)) {
      sendto_ops("list.c couldn't BlockHeapFree(free_channels,chan) chan = %lX", chan);
      sendto_ops("Please report to the hybrid team!");
   }
}

/*
 * * 'make_user' add's an User information block to a client * if it
 * was not previously allocated.
 */
anUser     *
make_user(aClient *cptr)
{
   anUser *user;

   user = cptr->user;
   if (!user) {
   user = BlockHeapALLOC(free_anUsers, anUser);

      if (user == (anUser *) NULL)
	 outofmemory();
      user->away = NULL;
      *user->username = '\0';	/*
				 * Initialize this crap 
				 */
      *user->host = '\0';
      user->server = (char *) NULL;	/*
					 * scache server name 
					 */
      user->joined = 0;
      user->channel = NULL;
      user->invited = NULL;
      user->silence = NULL;
      cptr->user = user;
   }
   return user;
}

aServer    *
make_server(aClient *cptr)
{
   aServer *serv = cptr->serv;

   if (!serv) {
      serv = (aServer *) MyMalloc(sizeof(aServer));

      *serv->bynick = '\0';
      *serv->byuser = '\0';
      *serv->byhost = '\0';
      serv->up = (char *) NULL;
      cptr->serv = serv;
   }
   return cptr->serv;
}
/*
 * * free_user *      Decrease user reference count by one and
 * release block, *     if count reaches 0
 */
void
free_user(anUser *user, aClient *cptr)
{
   if (user->away)
      MyFree((char *) user->away);
   /*
    * sanity check
    */
   if (user->joined || user->invited || user->channel)
      sendto_ops("* %#x user (%s!%s@%s) %#x %#x %#x %d *",
                  cptr, cptr ? cptr->name : "<noname>",
                  user->username, user->host, user,
                  user->invited, user->channel, user->joined);

   if (BlockHeapFree(free_anUsers, user)) 
   {
      sendto_ops("list.c couldn't BlockHeapFree(free_anUsers,user) user = %lX", user);
      sendto_ops("Please report to the hybrid team! bahamut-bugs@bahamut.net");
#if defined(USE_SYSLOG) && defined(SYSLOG_BLOCK_ALLOCATOR)
      syslog(LOG_DEBUG, "list.c couldn't BlockHeapFree(free_anUsers,user) user = %lX", user);
#endif
   }
}
/*
 * taken the code from ExitOneClient() for this and placed it here. -
 * avalon
 */
void
remove_client_from_list(aClient *cptr)
{
   if (IsServer(cptr))
      Count.server--;
   else if (IsClient(cptr)) {
      Count.total--;
      if (IsAnOper(cptr)) {
	 Count.oper--;
      }
   }
   if (IsInvisible(cptr))
      Count.invisi--;
   checklist();
   if (cptr->prev)
      cptr->prev->next = cptr->next;
   else {
      client = cptr->next;
      client->prev = NULL;
   }
   if (cptr->next)
      cptr->next->prev = cptr->prev;
   if (IsPerson(cptr) && cptr->user) {
      add_history(cptr, 0);
      off_history(cptr);
   }
   if (cptr->user)
      (void) free_user(cptr->user, cptr);	/*
						 * try this here 
						 */
   if (cptr->serv) {
      MyFree((char *) cptr->serv);
   }
   /*
    * YEUCK... This is telling me the only way of knowing that a cptr
    * was pointing to a remote aClient or not is by checking to see if
    * its fd is not -2, that is, unless you look at FLAGS_LOCAL
    * 
    * -Dianora
    * 
    */
   /*
    * if (cptr->fd == -2) cloc.inuse--; else crem.inuse--;
    */

#ifdef FLUD
   if (MyFludConnect(cptr))
      free_fluders(cptr, NULL);
   free_fludees(cptr);
#endif

   (void) free_client(cptr);
   /*
    * WTF is this?!#  -Taner 
    */
   /*
    * numclients--; 
    */
   return;
}
/*
 * although only a small routine, it appears in a number of places as a
 * collection of a few lines...functions like this *should* be in this
 * file, shouldnt they ?  after all, this is list.c, isnt it ? -avalon
 */
void
add_client_to_list(aClient *cptr)
{
   /*
    * since we always insert new clients to the top of the list, this
    * should mean the "me" is the bottom most item in the list.
    */
   cptr->next = client;
   client = cptr;
   if (cptr->next)
      cptr->next->prev = cptr;
   return;
}
/*
 * Look for ptr in the linked listed pointed to by link.
 */
chanMember *find_user_member(chanMember *cm, aClient *ptr)
{
   if (ptr)
      while (cm) {
	 if (cm->cptr == ptr)
	    return (cm);
	 cm = cm->next;
      }
   return ((chanMember *) NULL);
}

Link       *
find_channel_link(Link *lp, aChannel *chptr)
{
   if (chptr)
      for (; lp; lp = lp->next)
	 if (lp->value.chptr == chptr)
	    return lp;
   return ((Link *) NULL);
}

/*
 * Look for a match in a list of strings. Go through the list, and run
 * match() on it. Side effect: if found, this link is moved to the top of
 * the list.
 */
Link	   *
find_str_link(Link *lp, char *charptr)
{	
	if (!charptr)
		return ((Link *)NULL);
	while(lp!=NULL) {
		if(!match(lp->value.cp, charptr))
		  return lp;
		lp=lp->next;
	}
	return ((Link *)NULL);
}

Link       *
make_link()
{
Link   *lp;
lp = BlockHeapALLOC(free_Links, Link);

   if (lp == (Link *) NULL)
      outofmemory();

   lp->next = (Link *) NULL;	/*
				 * just to be paranoid... 
				 */

   return lp;
}

void
free_link(Link *lp)
{
   if (BlockHeapFree(free_Links, lp)) {
      sendto_ops("list.c couldn't BlockHeapFree(free_Links,lp) lp = %lX", lp);
      sendto_ops("Please report to the hybrid team!");
   }
}

chanMember *make_chanmember()
{
chanMember   *mp;
mp = BlockHeapALLOC(free_chanMembers, chanMember);

   if (mp == (chanMember *) NULL)
      outofmemory();

   return mp;
}

void
free_chanmember(chanMember *mp)
{
   if (BlockHeapFree(free_chanMembers, mp)) {
      sendto_ops("list.c couldn't BlockHeapFree(free_chanMembers,mp) mp = %lX", mp);
      sendto_ops("Please report to the hybrid team!");
   }
}

aClass     *
make_class()
{
aClass *tmp;

   tmp = (aClass *) MyMalloc(sizeof(aClass));
   return tmp;
}

void
free_class(tmp)
     aClass *tmp;
{
   MyFree((char *) tmp);
}

aConfItem  *
make_conf()
{
aConfItem *aconf;
   aconf = (struct ConfItem *) MyMalloc(sizeof(aConfItem));
   memset((char *) aconf, '\0', sizeof(aConfItem));

   /*
    * aconf->next = NULL; 
    */
   /*
    * aconf->host = aconf->passwd = aconf->name = NULL; 
    */
   aconf->status = CONF_ILLEGAL;
   /*
    * aconf->clients = 0; 
    */
   /*
    * aconf->port = 0; 
    */
   /*
    * aconf->hold = 0; 
    */
Class       (aconf) = 0;

   return (aconf);
}

void
delist_conf(aConfItem *aconf)
{
   if (aconf == conf)
      conf = conf->next;
   else {
   aConfItem  *bconf;

      for (bconf = conf; aconf != bconf->next; bconf = bconf->next);
      bconf->next = aconf->next;
   }
   aconf->next = NULL;
}

void
free_conf(aConfItem *aconf)
{
   del_queries((char *) aconf);
   MyFree(aconf->host);
   if (aconf->passwd)
      memset(aconf->passwd, '\0', strlen(aconf->passwd));
   MyFree(aconf->passwd);
   MyFree(aconf->name);
   MyFree((char *) aconf);
   return;
}

/*
 * Attempt to free up some block memory
 * 
 * list_garbage_collect
 * 
 * inputs               - NONE output           - NONE side effects     -
 * memory is possibly freed up
 */

void
block_garbage_collect()
{
   BlockHeapGarbageCollect(free_Links);
   BlockHeapGarbageCollect(free_chanMembers);
   BlockHeapGarbageCollect(free_local_aClients);
   BlockHeapGarbageCollect(free_remote_aClients);
   BlockHeapGarbageCollect(free_anUsers);
   BlockHeapGarbageCollect(free_channels);
#ifdef FLUD
   BlockHeapGarbageCollect(free_fludbots);
#endif /*
        * FLUD 
        */
}
