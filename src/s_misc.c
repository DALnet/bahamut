/************************************************************************
 *   IRC - Internet Relay Chat, src/s_misc.c
 *   Copyright (C) 1990 Jarkko Oikarinen and
 *                      University of Oulu, Computing Center
 *
 *   See file AUTHORS in IRC package for additional names of
 *   the programmers.
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

#include <sys/time.h>
#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include <sys/stat.h>
#include <fcntl.h>
#if !defined(ULTRIX) && !defined(SGI) && !defined(sequent) && \
    !defined(__convex__)
#include <sys/param.h>
#endif
#if defined(AIX) || defined(SVR3)
#include <time.h>
#endif
#include "h.h"
#include "fdlist.h"
extern fdlist serv_fdlist;

#ifdef NO_CHANOPS_WHEN_SPLIT
extern int  server_was_split;
extern time_t server_split_time;
#endif

#ifdef ALWAYS_SEND_DURING_SPLIT
int currently_processing_netsplit = NO;
#endif

static void exit_one_client(aClient *, aClient *, aClient *, char *);

static char *months[] =
{
   "January", "February", "March", "April",
   "May", "June", "July", "August",
   "September", "October", "November", "December"
};

static char *weekdays[] =
{
   "Sunday", "Monday", "Tuesday", "Wednesday",
   "Thursday", "Friday", "Saturday"
};

/*
 * stats stuff
 */
struct stats ircst, *ircstp = &ircst;

char       *
date(time_t clock)
{
static char buf[80], plus;
struct tm *lt, *gm;
struct tm   gmbuf;
int         minswest;

   if (!clock)
      time(&clock);
   gm = gmtime(&clock);
   memcpy((char *) &gmbuf, (char *) gm, sizeof(gmbuf));
   gm = &gmbuf;
   lt = localtime(&clock);

   if (lt->tm_yday == gm->tm_yday)
      minswest = (gm->tm_hour - lt->tm_hour) * 60 +
	 (gm->tm_min - lt->tm_min);
   else if (lt->tm_yday > gm->tm_yday)
      minswest = (gm->tm_hour - (lt->tm_hour + 24)) * 60;
   else
      minswest = ((gm->tm_hour + 24) - lt->tm_hour) * 60;

   plus = (minswest > 0) ? '-' : '+';
   if (minswest < 0)
      minswest = -minswest;

   (void) ircsprintf(buf, "%s %s %d %04d -- %02d:%02d %c%02d:%02d",
	       weekdays[lt->tm_wday], months[lt->tm_mon], lt->tm_mday,
		     lt->tm_year + 1900, lt->tm_hour, lt->tm_min,
		     plus, minswest / 60, minswest % 60);

   return buf;
}
/*
 */
char       *
smalldate(time_t clock)
{
static char buf[MAX_DATE_STRING];
struct tm *lt, *gm;
struct tm   gmbuf;

   if (!clock)
      time(&clock);
   gm = gmtime(&clock);
   memcpy((char *) &gmbuf, (char *) gm, sizeof(gmbuf));
   gm = &gmbuf;
   lt = localtime(&clock);

   (void) ircsprintf(buf, "%04d/%02d/%02d %02d.%02d",
		     lt->tm_year + 1900, lt->tm_mon + 1, lt->tm_mday,
		     lt->tm_hour, lt->tm_min);

   return buf;
}
/**
 ** myctime()
 **   This is like standard ctime()-function, but it zaps away
 **   the newline from the end of that string. Also, it takes
 **   the time value as parameter, instead of pointer to it.
 **   Note that it is necessary to copy the string to alternate
 **   buffer (who knows how ctime() implements it, maybe it statically
 **   has newline there and never 'refreshes' it -- zapping that
 **   might break things in other places...)
 **
 **/

char       *
myctime(time_t value)
{
static char buf[28];
char   *p;

   (void) strcpy(buf, ctime(&value));
   if ((p = (char *) strchr(buf, '\n')) != NULL)
      *p = '\0';

   return buf;
}
/*
 * * check_registered_user is used to cancel message, if the *
 * originator is a server or not registered yet. In other * words,
 * passing this test, *MUST* guarantee that the * sptr->user exists
 * (not checked after this--let there * be coredumps to catch bugs...
 * this is intentional --msa ;) *
 * 
 * There is this nagging feeling... should this NOT_REGISTERED * error
 * really be sent to remote users? This happening means * that remote
 * servers have this user registered, although this * one has it not...
 * Not really users fault... Perhaps this * error message should be
 * restricted to local clients and some * other thing generated for
 * remotes...
 */
int
check_registered_user(aClient *sptr)
{
   if (!IsRegisteredUser(sptr)) {
      sendto_one(sptr, err_str(ERR_NOTREGISTERED), me.name, "*");
      return -1;
   }
   return 0;
}
/*
 * * check_registered user cancels message, if 'x' is not * registered
 * (e.g. we don't know yet whether a server * or user)
 */
int
check_registered(aClient *sptr)
{
   if (!IsRegistered(sptr)) {
      sendto_one(sptr, err_str(ERR_NOTREGISTERED), me.name, "*");
      return -1;
   }
   return 0;
}
/*
 * * get_client_name *      Return the name of the client for various
 * tracking and *      admin purposes. The main purpose of this
 * function is to *      return the "socket host" name of the client,
 * if that *    differs from the advertised name (other than case). *
 * But, this can be used to any client structure. *
 * 
 *      Returns: *        "name[user@ip#.port]" if 'showip' is true; *
 * "name[sockethost]", if name and sockhost are different and *
 * showip is false; else *        "name". *
 * 
 * NOTE 1: *    Watch out the allocation of "nbuf", if either
 * sptr->name * or sptr->sockhost gets changed into pointers instead of *
 * directly allocated within the structure... *
 * 
 * NOTE 2: *    Function return either a pointer to the structure
 * (sptr) or *  to internal buffer (nbuf). *NEVER* use the returned
 * pointer *    to modify what it points!!!
 */
char       *
get_client_name(aClient *sptr, int showip)
{
   static char nbuf[HOSTLEN * 2 + USERLEN + 5];

   if (MyConnect(sptr)) {
      switch (showip) {
	 case TRUE:
#ifdef SHOW_UH
	    (void) ircsprintf(nbuf, "%s[%s%s@%s]",
			      sptr->name,
			      (!(sptr->flags & FLAGS_GOTID)) ? "" :
			      "(+)",
			      sptr->user ? sptr->user->username :
			      sptr->username,
			      inetntoa((char *) &sptr->ip));
#else
	    (void) sprintf(nbuf, "%s[%s@%s]",
			   sptr->name,
			   (!(sptr->flags & FLAGS_GOTID)) ? "" :
			   sptr->username,
			   inetntoa((char *) &sptr->ip));
#endif
	    break;
	 case HIDEME:
#ifdef SHOW_UH
	    (void) ircsprintf(nbuf, "%s[%s%s@%s]",
			      sptr->name,
			      (!(sptr->flags & FLAGS_GOTID)) ? "" :
			      "(+)",
			      sptr->user ? sptr->user->username :
			      sptr->username,
			      "0.0.0.0");
#else
	    (void) sprintf(nbuf, "%s[%s@%s]",
			   sptr->name,
			   (!(sptr->flags & FLAGS_GOTID)) ? "" :
			   sptr->username,
			   "0.0.0.0");
#endif
	    break;
	 default:
	    if (mycmp(sptr->name, sptr->sockhost))
#ifdef USERNAMES_IN_TRACE
	       (void) ircsprintf(nbuf, "%s[%s@%s]",
				 sptr->name,
				 sptr->user ? sptr->user->username :
				 sptr->username, sptr->sockhost);
#else
	       (void) ircsprintf(nbuf, "%s[%s]",
				 sptr->name, sptr->sockhost);
#endif
	    else
	       return sptr->name;
      }
      return nbuf;
   }
   return sptr->name;
}

char       *
get_client_host(aClient *cptr)
{
   static char nbuf[HOSTLEN * 2 + USERLEN + 5];

   if (!MyConnect(cptr))
      return cptr->name;
   if (!cptr->hostp)
      return get_client_name(cptr, FALSE);
   else
      (void) ircsprintf(nbuf, "%s[%-.*s@%-.*s]",
			cptr->name, USERLEN,
		 (!(cptr->flags & FLAGS_GOTID)) ? "" : cptr->username,
			HOSTLEN, cptr->hostp->h_name);
   return nbuf;
}

/*
 * Form sockhost such that if the host is of form user@host, only the
 * host portion is copied.
 */
void
get_sockhost(aClient *cptr, char *host)
{
   char   *s;

   if ((s = (char *) strchr(host, '@')))
      s++;
   else
      s = host;
   strncpyzt(cptr->sockhost, s, sizeof(cptr->sockhost));
}
/*
 * Return wildcard name of my server name according to given config
 * entry --Jto
 */
char       *
my_name_for_link(char *name, aConfItem *aconf)
{
   static char namebuf[HOSTLEN];
   int count = aconf->port;
   char *start = name;

   if (count <= 0 || count > 5)
      return start;

   while (count-- && name) {
      name++;
      name = (char *) strchr(name, '.');
   }
   if (!name)
      return start;

   namebuf[0] = '*';
   (void) strncpy(&namebuf[1], name, HOSTLEN - 1);
   namebuf[HOSTLEN - 1] = '\0';
   return namebuf;
}

int remove_dcc_references(aClient *sptr)
{  
   aClient *acptr;
   Link *lp, *nextlp;
   Link **lpp, *tmp;
   int found;
            
   lp = sptr->user->dccallow;
            
   while(lp)
   {  
      nextlp = lp->next;
      acptr = lp->value.cptr;
      for(found = 0, lpp = &(acptr->user->dccallow); *lpp; lpp=&((*lpp)->next))
      {  
         if(lp->flags == (*lpp)->flags)
            continue; /* match only opposite types for sanity */
         if((*lpp)->value.cptr == sptr)
         {
            if((*lpp)->flags == DCC_LINK_ME)
            {  
               sendto_one(acptr, ":%s %d %s :%s has been removed from your DCC allow list for signing off",
                          me.name, RPL_DCCINFO, acptr->name, sptr->name);
            }
            tmp = *lpp;
            *lpp = tmp->next;
            free_link(tmp);
            found++;
            break;
         }
      }
         
      if(!found)
         sendto_realops_lev(DEBUG_LEV, "rdr(): %s was in dccallowme list[%d] of %s but not in dccallowrem list!",
                            acptr->name, lp->flags, sptr->name);
      free_link(lp);
      lp = nextlp;
   }
   return 0;
}  

#ifdef USE_NOQUIT

/*
 * NOQUIT
 * a method of reducing the stress on the network during server splits
 * by sending only a simple "SQUIT" message for the server that is dropping,
 * instead of thousands upon thousands of QUIT messages for each user,
 * plus an SQUIT for each server behind the dead link.
 *
 * Original idea by Cabal95, implementation by lucas
 */

void exit_one_client_in_split(aClient *cptr, aClient *dead, char *reason)
{
   Link *lp;

   /* send all the quit reasons to all the non-noquit servers we have */

   /* yikes. We only want to do this if dead was OUR server. */
   /* erm, no, that's not true. Doing that breaks things. 
    * If a non-noquit server is telling us a server has split,
    * we will have already recieved hundreds of QUIT messages
    * from it, which will be passed anyway, and this procedure
    * will never be called. - lucas
    */

   sendto_noquit_servs_butone(0, dead, ":%s QUIT :%s", cptr->name, reason);

   sendto_common_channels(cptr, ":%s QUIT :%s", cptr->name, reason);

   while ((lp = cptr->user->channel))
      remove_user_from_channel(cptr, lp->value.chptr);
   while ((lp = cptr->user->invited))
      del_invite(cptr, lp->value.chptr);
   while ((lp = cptr->user->silence))
      del_silence(cptr, lp->value.cp);

   remove_dcc_references(cptr);

   del_from_client_hash_table(cptr->name, cptr); 

   hash_check_watch(cptr, RPL_LOGOFF);

   remove_client_from_list(cptr);
}

/* exit_one_server
 *
 * recursive function!
 * therefore, we pass dead and reason to ourselves.
 * in the beginning, dead == cptr, so it will be the one
 *  out of the loop last. therefore, dead should remain a good pointer.
 * cptr: the server being exited
 * dead: the actual server that split (if this belongs to us, we
 *       absolutely CANNOT send to it)
 * from: the client that caused this split
 * lcptr: the local client that initiated this
 * spinfo: split reason, as generated in exit_server
 * comment: comment provided
 */

void exit_one_server(aClient *cptr, aClient *dead, aClient *from, aClient *lcptr, char *spinfo, char *comment)
{
   aClient *acptr, *next;
   int i, j;

   /* okay, this is annoying.
    * first off, we need two loops.
    * one: to remove all the clients.
    * two: to remove all the servers.
    * HOWEVER! removing a server may cause removal of more servers and more clients.
    *  and this may make our pointer to next bad. therefore, we have to restart
    *  the server loop each time we find a server.
    * We _NEED_ two different loops: all clients must be removed before the server is
    *  removed. Otherwise, bad things (tm) can happen.
    */

   Debug((DEBUG_NOTICE, "server noquit: %s", cptr->name));

   for (acptr = client; acptr; acptr = next) 
   {
      next = acptr->next; /* we might destroy this client record in the loop. */

      if(acptr->uplink != cptr || !IsPerson(acptr)) 
         continue;

      exit_one_client_in_split(acptr, dead, spinfo);
   }

   for (acptr = client; acptr; acptr = next) 
   {
      next = acptr->next; /* we might destroy this client record in the loop. */

      if(acptr->uplink != cptr || !IsServer(acptr)) 
         continue;

      exit_one_server(acptr, dead, from, lcptr, spinfo, comment);
      next = client; /* restart the loop */
   }

   Debug((DEBUG_NOTICE, "done exiting server: %s", cptr->name));

   for (i = serv_fdlist.entry[j = 1]; j <= serv_fdlist.last_entry; i = serv_fdlist.entry[++j]) 
   {
      if (!(acptr = local[i]) || acptr == cptr || IsMe(acptr) || acptr == dead || acptr == lcptr)
         continue;

      /* if the server is noquit, we only want to send it information about 'dead' */
      /* if it's not, this server gets split information for ALL dead servers. */

      if(IsNoQuit(acptr) && cptr != dead)
         continue;

      if (cptr->from == acptr) /* "upstream" squit */
	    sendto_one(acptr, ":%s SQUIT %s :%s", from->name, cptr->name, comment);
	 else 
	    sendto_one(acptr, "SQUIT %s :%s", cptr->name, comment);
   }

   del_from_client_hash_table(cptr->name, cptr); 
   hash_check_watch(cptr, RPL_LOGOFF);
   remove_client_from_list(cptr);
}

/* exit_server
 *
 * lcptr: the local client that initiated this
 * cptr: the server that is being dropped.
 * from: the client/server that caused this to happen
 * comment: reason this is happening
 * we then call exit_one_server, the recursive function.
 */

void exit_server(aClient *lcptr, aClient *cptr, aClient *from, char *comment)
{
   char splitname[HOSTLEN + HOSTLEN + 2];

   ircsprintf(splitname, "%s %s", cptr->uplink->name, cptr->name);

   Debug((DEBUG_NOTICE, "exit_server(%s, %s, %s)", cptr->name, from->name, comment));

   exit_one_server(cptr, cptr, from, lcptr, splitname, comment);
}

#endif /* USE_NOQUIT */

/*
 * * exit_client *    This is old "m_bye". Name  changed, because
 * this is not a *      protocol function, but a general server utility
 * function. *
 * 
 *      This function exits a client of *any* type (user, server, etc) *
 * from this server. Also, this generates all necessary prototol *
 * messages that this exit may cause. *
 * 
 *   1) If the client is a local client, then this implicitly * exits
 * all other clients depending on this connection (e.g. *       remote
 * clients having 'from'-field that points to this. *
 * 
 *   2) If the client is a remote client, then only this is exited. *
 * 
 * For convenience, this function returns a suitable value for *
 * m_function return value: *
 * 
 *      FLUSH_BUFFER    if (cptr == sptr) *     0               if
 * (cptr != sptr)
 */
int
exit_client(
	      aClient *cptr,	/*
				 * * The local client originating the
				 * * exit or NULL, if this * exit is
				 * * generated by this server for
				 * * internal reasons. * This will not
				 * * get any of the generated messages.
				 * * 
				 */
	      aClient *sptr,	/*
				 * Client exiting 
				 */
	      aClient *from,	/*
				 * Client firing off this Exit, never
				 * * NULL! 
				 */
	      char *comment	/*
				 * Reason for the exit 
				 */
)
{

#ifndef USE_NOQUIT
   aClient *acptr;
   aClient *next;
   char        comment1[HOSTLEN + HOSTLEN + 2];
#endif

#ifdef	FNAME_USERLOG
   time_t      on_for;

#endif

   if (MyConnect(sptr)) {
      if (sptr->flags & FLAGS_IPHASH)
		  remove_one_ip(sptr->ip.s_addr);
      if (IsAnOper(sptr)) {
			delfrom_fdlist(sptr->fd, &oper_fdlist);
      }
      if (IsClient(sptr))
		  Count.local--;
      if (IsServer(sptr)) {
			Count.myserver--;
                        if (IsULine(sptr))
                           Count.myulined--;
			delfrom_fdlist(sptr->fd, &serv_fdlist);
#ifdef NO_CHANOPS_WHEN_SPLIT
			if (serv_fdlist.entry[1] <= serv_fdlist.last_entry) {
				server_was_split = YES;
				server_split_time = NOW;
			}
#endif
      }
      sptr->flags |= FLAGS_CLOSING;
      if (IsPerson(sptr)) {
			Link *lp, *next;
			LOpts *lopt=sptr->user->lopt;
			/* poof goes their watchlist! */
			hash_del_watch_list(sptr);
			/* if they have listopts, axe those, too */
			if(lopt!=NULL) {
				for (lp = lopt->yeslist; lp; lp = next) {
					next = lp->next;
					free_link(lp);
				}
				for (lp = lopt->nolist; lp; lp = next) {
					next = lp->next;
					free_link(lp);
				}
				
				MyFree(sptr->user->lopt);
				sptr->user->lopt = NULL;
			}
			sendto_realops_lev(CCONN_LEV, "Client exiting: %s (%s@%s) [%s] [%s]",
									 sptr->name, sptr->user->username,
									 sptr->user->host,
									 (sptr->flags & FLAGS_NORMALEX) ?
									 "Client Quit" : comment,
									 sptr->hostip);
      }
#ifdef FNAME_USERLOG
      on_for = timeofday - sptr->firsttime;
#endif
#if defined(USE_SYSLOG) && defined(SYSLOG_USERS)
      if (IsPerson(sptr))
		  syslog(LOG_NOTICE, "%s (%3d:%02d:%02d): %s!%s@%s %d/%d\n",
					myctime(sptr->firsttime),
					on_for / 3600, (on_for % 3600) / 60,
					on_for % 60, sptr->name,
					sptr->user->username, sptr->user->host,
					sptr->sendK, sptr->receiveK);
#endif
#if defined(FNAME_USERLOG)
		  {
			  char        linebuf[300];
			  static int  logfile = -1;
			  static long lasttime;
			  
			  /*
				* This conditional makes the logfile active only after it's
				* been created - thus logging can be turned off by removing
				* the file.
				* 
				* stop NFS hangs...most systems should be able to open a file in
				* 3 seconds. -avalon (curtesy of wumpus)
				* 
				* Keep the logfile open, syncing it every 10 seconds -Taner
				*/
			  if (IsPerson(sptr)) {
				  if (logfile == -1) {
					  (void) alarm(3);
					  logfile = open(FNAME_USERLOG, O_WRONLY | O_APPEND);
					  (void) alarm(0);
				  }
				  (void) ircsprintf(linebuf,
										  "%s (%3d:%02d:%02d): %s!%s@%s %d/%d\n",
										  myctime(sptr->firsttime), on_for / 3600,
										  (on_for % 3600) / 60, on_for % 60,
										  sptr->name,
										  sptr->user->username,
										  sptr->user->host,
										  sptr->sendK,
										  sptr->receiveK);
				  (void) alarm(3);
				  (void) write(logfile, linebuf, strlen(linebuf));
				  (void) alarm(0);
				  /*
					* Resync the file evey 10 seconds
					*/
				  if (timeofday - lasttime > 10) {
					  (void) alarm(3);
					  (void) close(logfile);
					  (void) alarm(0);
					  logfile = -1;
					  lasttime = timeofday;
				  }
			  }
		  }
#endif
      if (sptr->fd >= 0) {
			if (cptr != NULL && sptr != cptr)
			  sendto_one(sptr, "ERROR :Closing Link: %s %s (%s)",
							 sptr->sockhost,
							 sptr->name, comment);
			else
			  sendto_one(sptr, "ERROR :Closing Link: %s (%s)",
							 sptr->sockhost,
							 comment);
      }
      /*
       * * Currently only server connections can have * depending
       * remote clients here, but it does no * harm to check for all
       * local clients. In * future some other clients than servers
       * might * have remotes too... *
       * 
       * Close the Client connection first and mark it * so that no
       * messages are attempted to send to it. *, The following *must*
		 * make MyConnect(sptr) == FALSE!). * It also makes sptr->from ==
       * NULL, thus it's unnecessary * to test whether "sptr != acptr"
       * in the following loops.
       */
      if (IsServer(sptr)) {
			sendto_ops("%s was connected for %lu seconds.  %lu/%lu sendK/recvK.",
						  sptr->name, timeofday - sptr->firsttime,
						  sptr->sendK, sptr->receiveK);
#ifdef USE_SYSLOG
			syslog(LOG_NOTICE, "%s was connected for %lu seconds.  %lu/%lu sendK/recvK.", sptr->name, timeofday - sptr->firsttime, sptr->sendK, sptr->receiveK);
#endif
			close_connection(sptr);

			sptr->flags |= FLAGS_DEADSOCKET;

			/*
			 * * First QUIT all NON-servers which are behind this link *
			 * 
			 * Note        There is no danger of 'cptr' being exited in *  the
			 * following loops. 'cptr' is a *local* client, *      all
			 * dependants are *remote* clients.
			 */
			/*
			 * This next bit is a a bit ugly but all it does is take the *
			 * name of us.. me.name and tack it together with the name of *
			 * the server sptr->name that just broke off and puts this *
			 * together into exit_one_client() to provide some useful *
			 * information about where the net is broken.      Ian
			 */
#ifndef USE_NOQUIT
# ifdef ALWAYS_SEND_DURING_SPLIT
			currently_processing_netsplit = YES;
# endif
			(void) strcpy(comment1, me.name);
			(void) strcat(comment1, " ");
			(void) strcat(comment1, sptr->name);
			for (acptr = client; acptr; acptr = next) {
				next = acptr->next;
				if (!IsServer(acptr) && acptr->from == sptr)
				  exit_one_client(sptr, acptr, &me, comment1);
			}
			/*
			 * * Second SQUIT all servers behind this link
			 */
			for (acptr = client; acptr; acptr = next) {
				next = acptr->next;
				if (IsServer(acptr) && acptr->from == sptr)
				  exit_one_client(sptr, acptr, &me, me.name);
			}
# ifdef ALWAYS_SEND_DURING_SPLIT
			currently_processing_netsplit = NO;
# endif
#endif
      }
      else
      {
		  close_connection(sptr);
		  sptr->flags |= FLAGS_DEADSOCKET;
      }
		
   }
   exit_one_client(cptr, sptr, from, comment);
   return cptr == sptr ? FLUSH_BUFFER : 0;
}
/*
 * * Exit one client, local or remote. Assuming all dependants have *
 * been already removed, and socket closed for local client.
 */
static void
exit_one_client(aClient *cptr,
		aClient *sptr,
		aClient *from,
		char *comment)
{
#ifndef USE_NOQUIT
   aClient *acptr;
   int     i;
#endif
   Link   *lp;

   /*
    * *  For a server or user quitting, propogate the information to *
    * other servers (except to the one where is came from (cptr))
    */
   if (IsMe(sptr)) {
      sendto_ops("ERROR: tried to exit me! : %s", comment);
      return;			/*
				 * ...must *never* exit self!! 
				 */
   }
   else if (IsServer(sptr)) {
#ifdef USE_NOQUIT
# ifdef ALWAYS_SEND_DURING_SPLIT
      currently_processing_netsplit = YES;
# endif

      exit_server(cptr, sptr, from, comment);

# ifdef ALWAYS_SEND_DURING_SPLIT
      currently_processing_netsplit = NO;
# endif
      return;
#else
      /*
       * * Old sendto_serv_but_one() call removed because we now * need
       * to send different names to different servers * (domain name
       * matching)
       */
      for (i = 0; i <= highest_fd; i++) {
   aConfItem *aconf;

	 if (!(acptr = local[i]) || !IsServer(acptr) ||
	     acptr == cptr || IsMe(acptr))
	    continue;
	 if ((aconf = acptr->serv->nline) &&
	     (match(my_name_for_link(me.name, aconf),
		      sptr->name) == 0))
	    continue;
	 /*
	  * * SQUIT going "upstream". This is the remote * squit still
	  * hunting for the target. Use prefixed * form. "from" will be
	  * either the oper that issued * the squit or some server
	  * along the path that * didn't have this fix installed. --msa
	  */
	 if (sptr->from == acptr) {
	    sendto_one(acptr, ":%s SQUIT %s :%s",
		       from->name, sptr->name, comment);
	 }
	 else {
	    sendto_one(acptr, "SQUIT %s :%s",
		       sptr->name, comment);
	 }
      }
#endif /* USE_NOQUIT */
   }
   else if (!(IsPerson(sptr)))
      /*
       * ...this test is *dubious*, would need * some thought.. but for
       * now it plugs a * nasty hole in the server... --msa
       */
      ;				/*
				 * Nothing 
				 */
   else if (sptr->name[0]) {	/*
				 * ...just clean all others with
				 * * QUIT... 
				 */
      /*
       * * If this exit is generated from "m_kill", then there * is no
       * sense in sending the QUIT--KILL's have been * sent instead.
       */
      if ((sptr->flags & FLAGS_KILLED) == 0) {
	 sendto_serv_butone(cptr, ":%s QUIT :%s",
			    sptr->name, comment);
      }
      /*
       * * If a person is on a channel, send a QUIT notice * to every
       * client (person) on the same channel (so * that the client can
       * show the "**signoff" message). * (Note: The notice is to the
       * local clients *only*)
       */
      if (sptr->user) {
	  send_quit_to_common_channels(sptr, comment);
	  send_part_to_common_channels(sptr);
	  while ((lp = sptr->user->channel))
	      remove_user_from_channel(sptr, lp->value.chptr);

	 /*
	  * Clean up invitefield 
	  */
	 while ((lp = sptr->user->invited))
	    del_invite(sptr, lp->value.chptr);
	 /* Clean up silences */
	 while ((lp = sptr->user->silence)) (void)del_silence(sptr, lp->value.cp);
         remove_dcc_references(sptr);
	 /*
	  * again, this is all that is needed 
	  */
      }
   }

   /*
    * Remove sptr from the client list 
    */
   if (del_from_client_hash_table(sptr->name, sptr) != 1) {
      /*
       * This is really odd - oh well, it just generates noise...
       * -Taner
       * 
       * sendto_realops("%#x !in tab %s[%s]", sptr, sptr->name, sptr->from
       * ? sptr->from->sockhost : "??host"); sendto_realops("from =
       * %#x", sptr->from); sendto_realops("next = %#x", sptr->next);
       * sendto_realops("prev = %#x", sptr->prev); sendto_realops("fd =
       * %d  status = %d", sptr->fd, sptr->status);
       * sendto_realops("user = %#x", sptr->user);
       */

      Debug((DEBUG_ERROR, "%#x !in tab %s[%s] %#x %#x %#x %d %d %#x",
	     sptr, sptr->name,
	     sptr->from ? sptr->from->sockhost : "??host",
	     sptr->from, sptr->next, sptr->prev, sptr->fd,
	     sptr->status, sptr->user));
   }
	/* remove user from watchlists */
	if(IsRegistered(sptr))
	  hash_check_watch(sptr, RPL_LOGOFF);
   remove_client_from_list(sptr);
   return;
}

void
checklist()
{
aClient *acptr;
int     i, j;

   if (!(bootopt & BOOT_AUTODIE))
      return;
   for (j = i = 0; i <= highest_fd; i++)
      if (!(acptr = local[i]))
	 continue;
      else if (IsClient(acptr))
	 j++;
   if (!j) {
#ifdef	USE_SYSLOG
      syslog(LOG_WARNING, "ircd exiting: checklist() s_misc.c autodie");
#endif
      exit(0);
   }
   return;
}

void
initstats()
{
   memset((char *) &ircst, '\0', sizeof(ircst));
}

void
tstats(aClient *cptr, char *name)
{
   aClient *acptr;
   int     i;
   struct stats *sp;
   struct stats tmp;

   sp = &tmp;
   memcpy((char *) sp, (char *) ircstp, sizeof(*sp));
   for (i = 0; i < highest_fd; i++) {
      if (!(acptr = local[i]))
	 continue;
      if (IsServer(acptr)) {
	 sp->is_sbs += acptr->sendB;
	 sp->is_sbr += acptr->receiveB;
	 sp->is_sks += acptr->sendK;
	 sp->is_skr += acptr->receiveK;
	 sp->is_sti += timeofday - acptr->firsttime;
	 sp->is_sv++;
	 if (sp->is_sbs > 1023) {
	    sp->is_sks += (sp->is_sbs >> 10);
	    sp->is_sbs &= 0x3ff;
	 }
	 if (sp->is_sbr > 1023) {
	    sp->is_skr += (sp->is_sbr >> 10);
	    sp->is_sbr &= 0x3ff;
	 }

      }
      else if (IsClient(acptr)) {
	 sp->is_cbs += acptr->sendB;
	 sp->is_cbr += acptr->receiveB;
	 sp->is_cks += acptr->sendK;
	 sp->is_ckr += acptr->receiveK;
	 sp->is_cti += timeofday - acptr->firsttime;
	 sp->is_cl++;
	 if (sp->is_cbs > 1023) {
	    sp->is_cks += (sp->is_cbs >> 10);
	    sp->is_cbs &= 0x3ff;
	 }
	 if (sp->is_cbr > 1023) {
	    sp->is_ckr += (sp->is_cbr >> 10);
	    sp->is_cbr &= 0x3ff;
	 }

      }
      else if (IsUnknown(acptr))
	 sp->is_ni++;
   }

   sendto_one(cptr, ":%s %d %s :accepts %u refused %u",
	      me.name, RPL_STATSDEBUG, name, sp->is_ac, sp->is_ref);
   sendto_one(cptr, ":%s %d %s :unknown commands %u prefixes %u",
	      me.name, RPL_STATSDEBUG, name, sp->is_unco, sp->is_unpf);
   sendto_one(cptr, ":%s %d %s :nick collisions %u unknown closes %u",
	      me.name, RPL_STATSDEBUG, name, sp->is_kill, sp->is_ni);
   sendto_one(cptr, ":%s %d %s :wrong direction %u empty %u",
	      me.name, RPL_STATSDEBUG, name, sp->is_wrdi, sp->is_empt);
   sendto_one(cptr, ":%s %d %s :numerics seen %u mode fakes %u",
	      me.name, RPL_STATSDEBUG, name, sp->is_num, sp->is_fake);
   sendto_one(cptr, ":%s %d %s :auth successes %u fails %u",
	      me.name, RPL_STATSDEBUG, name, sp->is_asuc, sp->is_abad);
   sendto_one(cptr, ":%s %d %s :local connections %u udp packets %u",
	      me.name, RPL_STATSDEBUG, name, sp->is_loc, sp->is_udp);
   sendto_one(cptr, ":%s %d %s :Client Server",
	      me.name, RPL_STATSDEBUG, name);
   sendto_one(cptr, ":%s %d %s :connected %u %u",
	      me.name, RPL_STATSDEBUG, name, sp->is_cl, sp->is_sv);
   sendto_one(cptr, ":%s %d %s :bytes sent %u.%uK %u.%uK",
	      me.name, RPL_STATSDEBUG, name,
	      sp->is_cks, sp->is_cbs, sp->is_sks, sp->is_sbs);
   sendto_one(cptr, ":%s %d %s :bytes recv %u.%uK %u.%uK",
	      me.name, RPL_STATSDEBUG, name,
	      sp->is_ckr, sp->is_cbr, sp->is_skr, sp->is_sbr);
   sendto_one(cptr, ":%s %d %s :time connected %u %u",
	      me.name, RPL_STATSDEBUG, name, sp->is_cti, sp->is_sti);
#ifdef FLUD
   sendto_one(cptr, ":%s %d %s :CTCP Floods Blocked %u",
	      me.name, RPL_STATSDEBUG, name, sp->is_flud);
#endif /*
        * FLUD 
        */
}

/*
 * Retarded - so sue me :-P
 */
#define	_1MEG	(1024.0)
#define	_1GIG	(1024.0*1024.0)
#define	_1TER	(1024.0*1024.0*1024.0)
#define	_GMKs(x)	( (x > _1TER) ? "Terabytes" : ((x > _1GIG) ? "Gigabytes" : \
			((x > _1MEG) ? "Megabytes" : "Kilobytes")))
#define	_GMKv(x)	( (x > _1TER) ? (float)(x/_1TER) : ((x > _1GIG) ? \
			(float)(x/_1GIG) : ((x > _1MEG) ? (float)(x/_1MEG) : (float)x)))

void
serv_info(aClient *cptr, char *name)
{
   static char Lformat[] = ":%s %d %s %s %u %u %u %u %u :%u %u %s";
   int         i = 0, j, fd;
   long        sendK, receiveK, uptime;
   fdlist      l;
   aClient    *acptr;

   l = serv_fdlist;

   sendK = receiveK = 0;

   for (fd = l.entry[j = 1]; j <= l.last_entry; fd = l.entry[++j]) {
      if (!(acptr = local[fd]))
	 continue;
#ifdef HIDEULINEDSERVS
      if (IsULine(acptr) && !IsAnOper(cptr))
	 continue;
#endif
      sendK += acptr->sendK;
      receiveK += acptr->receiveK;
      sendto_one(cptr, Lformat, me.name, RPL_STATSLINKINFO,
		 name, get_client_name(acptr, HIDEME),
		 (int) DBufLength(&acptr->sendQ),
		 (int) acptr->sendM, (int) acptr->sendK,
		 (int) acptr->receiveM, (int) acptr->receiveK,
		 timeofday - acptr->firsttime,
		 timeofday - acptr->since,
		 IsServer(acptr) ? (DoesTS(acptr) ?
				    "TS" : "NoTS") : "-");
      i++;
   }
   sendto_one(cptr, ":%s %d %s :%u total server%s",
	      me.name, RPL_STATSDEBUG, name, i, (i == 1) ? "" : "s");

   sendto_one(cptr, ":%s %d %s :Sent total : %7.2f %s",
	   me.name, RPL_STATSDEBUG, name, _GMKv(sendK), _GMKs(sendK));
   sendto_one(cptr, ":%s %d %s :Recv total : %7.2f %s",
     me.name, RPL_STATSDEBUG, name, _GMKv(receiveK), _GMKs(receiveK));

   uptime = (timeofday - me.since);
   sendto_one(cptr, ":%s %d %s :Server send: %7.2f %s (%4.1f K/s)",
      me.name, RPL_STATSDEBUG, name, _GMKv(me.sendK), _GMKs(me.sendK),
	      (float) ((float) me.sendK / (float) uptime));
   sendto_one(cptr, ":%s %d %s :Server recv: %7.2f %s (%4.1f K/s)",
	      me.name, RPL_STATSDEBUG, name, _GMKv(me.receiveK), _GMKs(me.receiveK),
	      (float) ((float) me.receiveK / (float) uptime));
}

void
show_opers(aClient *cptr, char *name)
{
   aClient *cptr2;
   int     i, j = 0, fd;
   fdlist     *l;

   l = &oper_fdlist;
   for (fd = l->entry[i = 1]; i <= l->last_entry; fd = l->entry[++i]) {
      if (!(cptr2 = local[fd]))
	 continue;
      if (!IsClient(cptr2)) {
	 sendto_one(cptr, ":%s %d %s :Weird fd %d(%d) - not client (%d)",
		    me.name, RPL_STATSDEBUG, name, fd, cptr2->fd,
		    cptr2->status);
	 continue;
      }
		if (!IsAnOper(cptr2)) {
			delfrom_fdlist(cptr2->fd, &oper_fdlist);
			continue;
		}
			if (!IsAnOper(cptr)) {
				 if (cptr2->umode & UMODE_h) {
						sendto_one(cptr, ":%s %d %s :%s (%s@%s) Idle: %d",
											 me.name, RPL_STATSDEBUG, name, cptr2->name,
											 cptr2->user->username, cptr2->user->host,
											 timeofday - cptr2->user->last);
						j++;
				 }
			} else {
				 sendto_one(cptr, ":%s %d %s :%s (%s@%s) Idle: %d",
										me.name, RPL_STATSDEBUG, name, cptr2->name,
										cptr2->user->username, cptr2->user->host,
										timeofday - cptr2->user->last);
				 j++;
			}
   }
   sendto_one(cptr, ":%s %d %s :%d OPER%s", me.name, RPL_STATSDEBUG,
	      name, j, (j == 1) ? "" : "s");
}

void
show_servers(aClient *cptr, char *name)
{
   aClient *cptr2;
   int     i, j = 0, fd;
   fdlist     *l;

   l = &serv_fdlist;
   for (fd = l->entry[i = 1]; i <= l->last_entry; fd = l->entry[++i]) {
      if (!(cptr2 = local[fd]))
	 continue;
      if (!IsServer(cptr2)) {
			sendto_one(cptr, ":%s %d %s :Weird fd %d(%d) - not server (%d)",
						  me.name, RPL_STATSDEBUG, name, fd, cptr2->fd,
						  cptr2->status);
			continue;
      }
#ifdef HIDEULINEDSERVS
      if(IsULine(cptr2) && !IsAnOper(cptr))
         continue;
#endif
      j++;
      sendto_one(cptr, ":%s %d %s :%s (%s!%s@%s) Idle: %d",
		 me.name, RPL_STATSDEBUG, name, cptr2->name,
		 (cptr2->serv->bynick[0] ? cptr2->serv->bynick : "Remote."),
	      (cptr2->serv->byuser[0] ? cptr2->serv->byuser : "*"),
		 (cptr2->serv->byhost[0] ? cptr2->serv->byhost : "*"),
		 timeofday - cptr2->lasttime);
   }
   sendto_one(cptr, ":%s %d %s :%d Server%s", me.name, RPL_STATSDEBUG,
	      name, j, (j == 1) ? "" : "s");
}
