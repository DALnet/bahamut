/************************************************************************
 *   IRC - Internet Relay Chat, src/s_debug.c
 *   Copyright (C) 1990 Jarkko Oikarinen and
 *                      University of Oulu, Computing Center
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
#include "patchlevel.h"
#include "blalloc.h"
extern void count_whowas_memory(int *, u_long *);
extern u_long cres_mem(aClient *);
extern void count_ip_hash(int *, u_long *);	/*

						 * defined in s_conf.c 
						 */
/*
 * Option string.  Must be before #ifdef DEBUGMODE.
 */
/*
 * I took out a lot of options that really aren't optional anymore,
 * note also that at the end we denote what our release status is
 */
char        serveropts[] =
{
#ifdef	CMDLINE_CONFIG
   'C',
#endif
#ifdef        DO_ID
   'd',
#endif
#ifdef	DEBUGMODE
   'D',
#endif
#ifdef	HUB
   'H',
#endif
#ifdef	SHOW_INVISIBLE_LUSERS
   'i',
#endif
#ifndef	NO_DEFAULT_INVISIBLE
   'I',
#endif
#ifdef	CRYPT_OPER_PASSWORD
   'p',
#endif
#ifdef	IRCII_KLUDGE
   'u',
#endif
#ifdef	USE_SYSLOG
   'Y',
#endif
   ' ',
   'T',
   'S',
#ifdef TS_CURRENT
   '0' + TS_CURRENT,
#endif
   /*
    * th+hybrid servers ONLY do TS 
    */
   /*
    * th+hybrid servers ALWAYS do TS_WARNINGS 
    */
   'o',
   'w',
#ifdef BRANCHSTATUS
	'-', 'r', '[',
# if BRANCHSTATUS == CURRENT
	'C','U','R','R','E','N','T',
# elif BRANCHSTATUS == RELEASE
	'R','E','L','E','A','S','E',
# elif BRANCHSTATUS == STABLE
	'S','T','A','B','L','E',
# elif BRANCHSTATUS == BETA
	'B','E','T','A',
# else
	'U','N','K','N','O','W','N',
# endif
	']',
#endif
	'\0'
};

#include "numeric.h"
#include "common.h"
#include "sys.h"
/*
 * #include "whowas.h" 
 */
#include "hash.h"
#include <sys/file.h>
#if !defined(ULTRIX) && !defined(SGI) && !defined(sequent) && \
    !defined(__convex__)
#include <sys/param.h>
#endif
#if defined( HAVE_GETRUSAGE )
#ifdef SOL20
#include <sys/time.h>
/*
 * #  include <sys/rusage.h>
 */
#endif
#include <sys/resource.h>
#else
#if defined( HAVE_TIMES )
#include <sys/times.h>
#endif
#endif /*
        * HAVE_GETRUSAGE 
        */
#include "h.h"

#ifndef ssize_t
#define ssize_t unsigned int
#endif

/*
 * extern char *sys_errlist[]; 
 */

/*
 * #ifdef DEBUGMODE 
 */
#if defined(DNS_DEBUG) || defined(DEBUGMODE)
static char debugbuf[1024];

void
debug(int level, char *pattern, ...)
{
   va_list      vl;
   int         err = errno;

   va_start(vl, pattern);
   (void) vsprintf(debugbuf, pattern, vl);
   va_end(vl);

#ifdef USE_SYSLOG
   if (level == DEBUG_ERROR)
      syslog(LOG_ERR, debugbuf);
#endif

   if ((debuglevel >= 0) && (level <= debuglevel)) {

      if (local[2]) {
	 local[2]->sendM++;
	 local[2]->sendB += strlen(debugbuf);
      }
      (void) fprintf(stderr, "%s", debugbuf);
      (void) fputc('\n', stderr);
   }
   errno = err;
}

/*
 * This is part of the STATS replies. There is no offical numeric for
 * this since this isnt an official command, in much the same way as
 * HASH isnt. It is also possible that some systems wont support this
 * call or have different field names for "struct rusage". -avalon
 */
void
send_usage(aClient *cptr, char *nick)
{

#if defined( HAVE_GETRUSAGE )
   struct rusage rus;
   time_t      secs, rup;

#ifdef	hz
#define hzz hz
#else
#ifdef HZ
#define hzz HZ
#else
   int         hzz = 1;

#endif
#endif

   if (getrusage(RUSAGE_SELF, &rus) == -1) {
      sendto_one(cptr, ":%s NOTICE %s :Getruseage error: %s.",
		 me.name, nick, sys_errlist[errno]);
      return;
   }
   secs = rus.ru_utime.tv_sec + rus.ru_stime.tv_sec;
   rup = timeofday - me.since;
   if (secs == 0)
      secs = 1;

   sendto_one(cptr,
	      ":%s %d %s :CPU Secs %d:%d User %d:%d System %d:%d",
	      me.name, RPL_STATSDEBUG, nick, secs / 60, secs % 60,
	      rus.ru_utime.tv_sec / 60, rus.ru_utime.tv_sec % 60,
	      rus.ru_stime.tv_sec / 60, rus.ru_stime.tv_sec % 60);
   sendto_one(cptr, ":%s %d %s :RSS %d ShMem %d Data %d Stack %d",
	      me.name, RPL_STATSDEBUG, nick, rus.ru_maxrss,
	      rus.ru_ixrss / (rup * hzz), rus.ru_idrss / (rup * hzz),
	      rus.ru_isrss / (rup * hzz));
   sendto_one(cptr, ":%s %d %s :Swaps %d Reclaims %d Faults %d",
	      me.name, RPL_STATSDEBUG, nick, rus.ru_nswap,
	      rus.ru_minflt, rus.ru_majflt);
   sendto_one(cptr, ":%s %d %s :Block in %d out %d",
	      me.name, RPL_STATSDEBUG, nick, rus.ru_inblock,
	      rus.ru_oublock);
   sendto_one(cptr, ":%s %d %s :Msg Rcv %d Send %d",
	 me.name, RPL_STATSDEBUG, nick, rus.ru_msgrcv, rus.ru_msgsnd);
   sendto_one(cptr, ":%s %d %s :Signals %d Context Vol. %d Invol %d",
	      me.name, RPL_STATSDEBUG, nick, rus.ru_nsignals,
	      rus.ru_nvcsw, rus.ru_nivcsw);
#else
#if defined( HAVE_TIMES )
   struct tms  tmsbuf;
   time_t      secs, mins;
   int         hzz = 1, ticpermin;
   int         umin, smin, usec, ssec;

   ticpermin = hzz * 60;

   umin = tmsbuf.tms_utime / ticpermin;
   usec = (tmsbuf.tms_utime % ticpermin) / (float) hzz;
   smin = tmsbuf.tms_stime / ticpermin;
   ssec = (tmsbuf.tms_stime % ticpermin) / (float) hzz;
   secs = usec + ssec;
   mins = (secs / 60) + umin + smin;
   secs %= hzz;

   if (times(&tmsbuf) == -1) {
      sendto_one(cptr, ":%s %d %s :times(2) error: %s.",
		 me.name, RPL_STATSDEBUG, nick, strerror(errno));
      return;
   }
   secs = tmsbuf.tms_utime + tmsbuf.tms_stime;

   sendto_one(cptr,
	      ":%s %d %s :CPU Secs %d:%d User %d:%d System %d:%d",
	      me.name, RPL_STATSDEBUG, nick, mins, secs, umin, usec,
	      smin, ssec);
#endif /*
        * HAVE_TIMES 
        */
#endif /*
        * HAVE_GETRUSAGE 
        */
   sendto_one(cptr, ":%s %d %s :Reads %d Writes %d",
	      me.name, RPL_STATSDEBUG, nick, readcalls, writecalls);
   sendto_one(cptr, ":%s %d %s :DBUF alloc %d used %d",
	      me.name, RPL_STATSDEBUG, nick, DBufCount, DBufUsedCount);
   sendto_one(cptr,
	      ":%s %d %s :Writes:  <0 %d 0 %d <16 %d <32 %d <64 %d",
	      me.name, RPL_STATSDEBUG, nick,
	      writeb[0], writeb[1], writeb[2], writeb[3], writeb[4]);
   sendto_one(cptr,
	      ":%s %d %s :<128 %d <256 %d <512 %d <1024 %d >1024 %d",
	      me.name, RPL_STATSDEBUG, nick,
	      writeb[5], writeb[6], writeb[7], writeb[8], writeb[9]);
   return;
}
#endif

void count_memory(aClient *cptr, char *nick)
{
   extern aChannel *channel;
   extern aClass *classes;
   extern aConfItem *conf;

   extern BlockHeap *free_local_aClients;
   extern BlockHeap *free_Links;
   extern BlockHeap *free_remote_aClients;
   extern BlockHeap *free_anUsers;
   extern BlockHeap *free_channels;
   extern BlockHeap *free_chanMembers;
#ifdef FLUD
   extern BlockHeap *free_fludbots;
#endif

   extern aMotd      *motd;
#ifdef SHORT_MOTD
   extern aMotd      *shortmotd;
#endif
   extern aMotd      *helpfile;

   extern int num_msg_trees;

   Reg aClient *acptr;
   Reg Link   *link;
   Reg chanMember *cm;
   Reg aBan   *bp;
   Reg aChannel *chptr;
   Reg aConfItem *aconf;
   Reg aClass *cltmp;
   Reg aMotd *amo;

   int         lc = 0;		/*
				 * local clients 
				 */
   int         ch = 0;		/*

				 * channels 
				 */
   int         lcc = 0;		/*
				 * local client conf links 
				 */
   int         rc = 0;		/*
				 * remote clients 
				 */
   int         us = 0;		/*
				 * user structs 
				 */
   int         chu = 0;		/*
				 * channel users 
				 */
   int         chi = 0;		/*
				 * channel invites 
				 */
   int         chb = 0;		/*
				 * channel bans 
				 */
   int         wwu = 0;		/*
				 * whowas users 
				 */
   int         cl = 0;		/*
				 * classes 
				 */
   int         co = 0;		/*
				 * conf lines 
				 */
   int         usi = 0;		/*
				 * users invited 
				 */
   int         usc = 0;		/*
				 * users in channels 
				 */
	 
   int         uss = 0;         /* silenced users */
   int         aw = 0;		/*
				 * aways set 
				 */

   int         number_ips_stored;	/*
					 * number of ip addresses hashed 
					 */
   int         number_servers_cached;	/*
					 * number of servers cached by
					 * * scache 
					 */

   u_long      chbm = 0;	/*
				 * memory used by channel bans 
				 */
   u_long      lcm = 0;		/*
				 * memory used by local clients 
				 */
   u_long      rcm = 0;		/*
				 * memory used by remote clients 
				 */
   u_long      awm = 0;		/*
				 * memory used by aways 
				 */
   u_long      wwm = 0;		/*
				 * whowas array memory used 
				 */
   u_long      com = 0;		/*
				 * memory used by conf lines 
				 */
   size_t      db = 0, db2 = 0;	/*
				 * memory used by dbufs 
				 */
   u_long      rm = 0;		/*
				 * res memory used 
				 */
   u_long      mem_servers_cached;	/*
					 * memory used by scache 
					 */
   u_long      mem_ips_stored;	/*
				 * memory used by ip address hash 
				 */

   u_long      totcl = 0;
   u_long      totch = 0;
   u_long      totww = 0;
   u_long      totmisc = 0;
   u_long      tothash = 0;
   u_long      tot = 0;

   int wlh=0, wle=0; /* watch headers/entries */
   u_long wlhm=0; /* memory used by watch */

   int lcalloc = 0; 	/* local clients allocated */
   int rcalloc = 0; 	/* remote clients allocated */
   int useralloc = 0; 	/* allocated users */
   int linkalloc = 0; 	/* allocated links */
   int totallinks = 0; /* total links used */
   int chanalloc = 0; /* total channels alloc'd */
   int cmemballoc = 0;
   u_long lcallocsz = 0, rcallocsz = 0; /* size for stuff above */
   u_long userallocsz = 0, linkallocsz = 0, chanallocsz = 0, cmemballocsz = 0;

   int fludalloc = 0;
   u_long fludallocsz = 0;
   int fludlink = 0;

   int motdlen = 0;

   int servn = 0;
	
   count_whowas_memory(&wwu, &wwm);	/*
					 * no more away memory to count 
					 */

   count_watch_memory(&wlh, &wlhm);
   for (acptr = client; acptr; acptr = acptr->next) {
      if (MyConnect(acptr)) {
	 lc++;
	 wle += acptr->watches;
	 for (link = acptr->confs; link; link = link->next)
	    lcc++;
      }
      else
	 rc++;

#ifdef FLUD
      for (link = acptr->fludees; link;
	   link = link->next)
         fludlink++;
#endif
      if (acptr->serv) {
         servn++;
      }

      if (acptr->user) {
	 us++;
	 for (link = acptr->user->invited; link;
	      link = link->next)
	    usi++;
	 for (link = acptr->user->channel; link;
	      link = link->next)
	    usc++;
	 for (link = acptr->user->silence; link;
	      link = link->next)
	    uss++;
	 if (acptr->user->away) {
	    aw++;
	    awm += (strlen(acptr->user->away) + 1);
	 }
      }
   }

   lcm = lc * CLIENT_LOCAL_SIZE;
   rcm = rc * CLIENT_REMOTE_SIZE;

   for (chptr = channel; chptr; chptr = chptr->nextch) {
      ch++;

      for (cm = chptr->members; cm; cm = cm->next)
	 chu++;
      for (link = chptr->invites; link; link = link->next)
	 chi++;
      for (bp = chptr->banlist; bp; bp = bp->next) {
	 chb++;
	 chbm += (strlen(bp->who) + strlen(bp->banstr) + 2 + sizeof(aBan));
      }
   }

   for (aconf = conf; aconf; aconf = aconf->next) {
      co++;
      com += aconf->host ? strlen(aconf->host) + 1 : 0;
      com += aconf->passwd ? strlen(aconf->passwd) + 1 : 0;
      com += aconf->name ? strlen(aconf->name) + 1 : 0;
      com += sizeof(aConfItem);
   }

   for (cltmp = classes; cltmp; cltmp = cltmp->next)
      cl++;

   for (amo = motd; amo; amo = amo->next)
      motdlen++;
#ifdef SHORT_MOTD
   for (amo = shortmotd; amo; amo = amo->next)
      motdlen++;
#endif
   for (amo = helpfile; amo; amo = amo->next)
      motdlen++;

   lcalloc = free_local_aClients->blocksAllocated * free_local_aClients->elemsPerBlock;
   lcallocsz = lcalloc * free_local_aClients->elemSize;

   rcalloc = free_remote_aClients->blocksAllocated * free_remote_aClients->elemsPerBlock;
   rcallocsz = rcalloc * free_remote_aClients->elemSize;

   useralloc = free_anUsers->blocksAllocated * free_anUsers->elemsPerBlock;
   userallocsz = useralloc * free_anUsers->elemSize;

   linkalloc = free_Links->blocksAllocated * free_Links->elemsPerBlock;
   linkallocsz = linkalloc * free_Links->elemSize;

   chanalloc = free_channels->blocksAllocated * free_channels->elemsPerBlock;
   chanallocsz = chanalloc * free_channels->elemSize;

   cmemballoc = free_chanMembers->blocksAllocated * free_chanMembers->elemsPerBlock;
   cmemballocsz = cmemballoc * free_chanMembers->elemSize;

#ifdef FLUD
   fludalloc = free_fludbots->blocksAllocated * free_fludbots->elemsPerBlock;
   fludallocsz = fludalloc * free_fludbots->elemSize;
#endif

   totallinks = lcc + usi +  uss + usc + chi + wle + fludlink;

   sendto_one(cptr, ":%s %d %s :Memory Use Summary",
	      me.name, RPL_STATSDEBUG, nick);
   sendto_one(cptr, ":%s %d %s :Client usage %d(%d) ALLOC %d(%d)",
	      me.name, RPL_STATSDEBUG, nick, lc + rc, lcm + rcm, 
	      lcalloc + rcalloc, lcallocsz + rcallocsz);
   sendto_one(cptr, ":%s %d %s :   Local %d(%d) ALLOC %d(%d)",
	      me.name, RPL_STATSDEBUG, nick, lc, lcm, lcalloc, lcallocsz);
   sendto_one(cptr, ":%s %d %s :   Remote %d(%d) ALLOC %d(%d)",
	      me.name, RPL_STATSDEBUG, nick, rc, rcm, rcalloc, rcallocsz);
   sendto_one(cptr, ":%s %d %s :Users %d(%d) ALLOC %d(%d)",
	      me.name, RPL_STATSDEBUG, nick, us, us * sizeof(anUser), useralloc, userallocsz);

   totcl = lcallocsz + rcallocsz + userallocsz;

   sendto_one(cptr, ":%s %d %s :Links %d(%d) ALLOC %d(%d)",
	      me.name, RPL_STATSDEBUG, nick, totallinks, totallinks * sizeof(Link), 
              linkalloc, linkallocsz);
   sendto_one(cptr, ":%s %d %s :   UserInvites %d(%d) ChanInvites %d(%d)",
	  me.name, RPL_STATSDEBUG, nick, usi, usi * sizeof(Link), chi, chi * sizeof(Link));
   sendto_one(cptr, ":%s %d %s :   UserChannels %d(%d)",
	      me.name, RPL_STATSDEBUG, nick, usc, usc * sizeof(Link));
   sendto_one(cptr, ":%s %d %s :   WATCH entries %d(%d)",
	      me.name, RPL_STATSDEBUG, nick, wle, wle*sizeof(Link));
   sendto_one(cptr, ":%s %d %s :   Attached confs %d(%d)",
	      me.name, RPL_STATSDEBUG, nick, lcc, lcc*sizeof(Link));
   sendto_one(cptr, ":%s %d %s :   Fludees %d(%d)",
	      me.name, RPL_STATSDEBUG, nick, fludlink, fludlink*sizeof(Link));
	
   sendto_one(cptr, ":%s %d %s :WATCH headers %d(%d)",
	      me.name, RPL_STATSDEBUG, nick, wlh, wlhm);
   sendto_one(cptr, ":%s %d %s :Conflines %d(%d)",
	      me.name, RPL_STATSDEBUG, nick, co, com);
   sendto_one(cptr, ":%s %d %s :Classes %d(%d)",
	      me.name, RPL_STATSDEBUG, nick, cl, cl * sizeof(aClass));
   sendto_one(cptr, ":%s %d %s :Away Messages %d(%d)",
	      me.name, RPL_STATSDEBUG, nick, aw, awm);
   sendto_one(cptr, ":%s %d %s :MOTD structs %d(%d)",
	      me.name, RPL_STATSDEBUG, nick, motdlen, motdlen * sizeof(aMotd));
   sendto_one(cptr, ":%s %d %s :Servers %d(%d)",
	      me.name, RPL_STATSDEBUG, nick, servn, servn * sizeof(aServer));
   sendto_one(cptr, ":%s %d %s :Message Trees %d(%d)",
	      me.name, RPL_STATSDEBUG, nick, num_msg_trees, num_msg_trees * sizeof(MESSAGE_TREE));

   totmisc = wlhm + com + (cl * sizeof(aClass)) + awm + (motdlen * sizeof(aMotd))
             + (servn * sizeof(aServer)) + (num_msg_trees * sizeof(MESSAGE_TREE));

   sendto_one(cptr, ":%s %d %s :Fludbots ALLOC %d(%d)",
	      me.name, RPL_STATSDEBUG, nick, fludalloc, fludallocsz);

   sendto_one(cptr, ":%s %d %s :Channels %d(%d) ALLOC %d(%d) Bans %d(%d) Members %d(%d) ALLOC %d(%d)",
	      me.name, RPL_STATSDEBUG, nick, ch, ch * sizeof(aChannel), 
	      chanalloc, chanallocsz, chb, chbm,
              chu, chu * sizeof(chanMember), cmemballoc, cmemballocsz);

   totch = chanallocsz + cmemballocsz + chbm;

   sendto_one(cptr, ":%s %d %s :Whowas users %d(%d)",
	    me.name, RPL_STATSDEBUG, nick, wwu, wwu * sizeof(anUser));
   sendto_one(cptr, ":%s %d %s :Whowas array %d(%d)",
	   me.name, RPL_STATSDEBUG, nick, NICKNAMEHISTORYLENGTH, wwm);

   totww = wwu * sizeof(anUser) + wwm;

   sendto_one(cptr, ":%s %d %s :Hash: client %d(%d) chan %d(%d) whowas %d(%d) watch %d(%d)",
				  me.name, RPL_STATSDEBUG, nick,
				  U_MAX, sizeof(aHashEntry) * U_MAX,
				  CH_MAX, sizeof(aHashEntry) * CH_MAX,
				  WW_MAX, sizeof(aWhowas *) * WW_MAX,
				  WATCHHASHSIZE, sizeof(aWatch *) * WATCHHASHSIZE);

   count_dbuf_memory(&db, &db2);
   sendto_one(cptr, ":%s %d %s :Dbuf blocks %d(%d) MAX %d(%d)",
	      me.name, RPL_STATSDEBUG, nick, DBufUsedCount, db2,
	      DBufCount, db);

   rm = cres_mem(cptr);

   count_scache(&number_servers_cached, &mem_servers_cached);

   sendto_one(cptr, ":%s %d %s :scache %d(%d)",
	      me.name, RPL_STATSDEBUG, nick,
	      number_servers_cached,
	      mem_servers_cached);

   count_ip_hash(&number_ips_stored, &mem_ips_stored);
   sendto_one(cptr, ":%s %d %s :iphash %d(%d)",
	      me.name, RPL_STATSDEBUG, nick,
	      number_ips_stored,
	      mem_ips_stored);

   totmisc += (mem_ips_stored + mem_servers_cached);

   tothash = (sizeof(aHashEntry)*U_MAX)+(sizeof(aHashEntry)*CH_MAX) +
             (sizeof(aWatch *)*WATCHHASHSIZE) + (sizeof(aWhowas *)*WW_MAX);

   tot = totww + totch + totcl + totmisc + db + rm + tothash + linkallocsz + fludallocsz;

   sendto_one(cptr, ":%s %d %s :whowas %d chan %d client/user %d misc %d dbuf %d hash %d res %d link %d flud %d",
	 me.name, RPL_STATSDEBUG, nick, totww, totch, totcl, totmisc, db, tothash, rm, linkallocsz, fludallocsz);

   sendto_one(cptr, ":%s %d %s :TOTAL: %d sbrk(0)-etext: %u",
	      me.name, RPL_STATSDEBUG, nick, tot,
	      (u_int) sbrk((size_t) 0) - (u_int) sbrk0);

   return;
}
