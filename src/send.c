/************************************************************************
 *   IRC - Internet Relay Chat, src/send.c
 *   Copyright (C) 1990 Jarkko Oikarinen and
 *		      University of Oulu, Computing Center
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
#include <stdio.h>
#include "numeric.h"

void        sendto_fdlist();

#ifdef	IRCII_KLUDGE
#define	NEWLINE	"\n"
#else
#define NEWLINE	"\r\n"
#endif

static char sendbuf[2048];
static int  send_message(aClient *, char *, int);

static int  sentalong[MAXCONNECTIONS];

int
            format(char *, char *, char *, char *, char *, char *, char *, char *,
		   char *, char *, char *, char *, char *, char *);

/*
 * dead_link 
 *     
 * An error has been detected. The link *must* be closed, 
 * but *cannot* call ExitClient (m_bye) from here. 
 *
 * Instead, mark it with FLAGS_DEADSOCKET. This should 
 * generate ExitClient from the main loop.
 * 
 * If 'notice' is not NULL, it is assumed to be a format for a
 * message to local opers. I can contain only one '%s', which
 * will be replaced by the sockhost field of the failing link.
 * 
 * Also, the notice is skipped for "uninteresting" cases, 
 * like Persons and yet unknown connections...
 */

static int
dead_link(aClient *to, char *notice)
{
   to->flags |= FLAGS_DEADSOCKET;
   /*
    * If because of BUFFERPOOL problem then clean dbuf's now so that
    * notices don't hurt operators below.
    */
   DBufClear(&to->recvQ);
   DBufClear(&to->sendQ);
   if (IsServer(to) && !(to->flags & FLAGS_CLOSING))
   {
      char fbuf[512];

      /* 
       * ick! what we have here is a server coming in as a dead link.
       * we need to tell the entire network, as well as local operators, 
       * just exactly why the server linked to us is dying. - lucas
       */
 
      ircsprintf(fbuf, "from %s: %s", me.name, notice);
      send_globops(fbuf, get_client_name(to, HIDEME));
      ircsprintf(fbuf, ":%s GLOBOPS :%s", me.name, notice);
      sendto_serv_butone(to, fbuf, get_client_name(to, HIDEME));
   }
   Debug((DEBUG_ERROR, notice, get_client_name(to, FALSE)));
   return -1;
}

/*
 * * flush_connections *      Used to empty all output buffers for
 * all connections. Should only *       be called once per scan of
 * connections. There should be a select in *   here perhaps but that
 * means either forcing a timeout or doing a poll. *    When flushing,
 * all we do is empty the obuffer array for each local *        client
 * and try to send it. if we cant send it, it goes into the sendQ *
 * -avalon
 */
void
flush_connections(int fd)
{
   Reg int     i;
   Reg aClient *cptr;

   if (fd == me.fd) {
      for (i = highest_fd; i >= 0; i--)
	 if ((cptr = local[i]) && DBufLength(&cptr->sendQ) > 0)
	    (void) send_queued(cptr);
   }
   else if (fd >= 0 && (cptr = local[fd]) && DBufLength(&cptr->sendQ) > 0)
      (void) send_queued(cptr);
}

/*
 * * send_message *   Internal utility which delivers one message
 * buffer to the *      socket. Takes care of the error handling and
 * buffering, if *      needed.
 */
static int
send_message(aClient *to, char *msg, int len)
/*
 * if msg is a null pointer, we are flushing connection 
 */
{
   static int  SQinK;

#ifdef DUMP_DEBUG
	fprintf(dumpfp, "-> %s: %s", (to->name ? to->name : "*"), msg);
#endif
	if (to->from)
	  to = to->from;   /* shouldn't be necessary */
	
	if (IsMe(to)) {
		sendto_ops("Trying to send to myself! [%s]", msg);
		return 0;
	}
	
   
	if (IsDead(to))
      return 0;
   if (DBufLength(&to->sendQ) > get_sendq(to)) {
      if (IsServer(to))
		  sendto_ops_butone(to, "Max SendQ limit exceeded for %s: %d > %d",
								  get_client_name(to, (IsServer(to) ? HIDEME : FALSE)),
								  DBufLength(&to->sendQ), get_sendq(to));
      if (IsClient(to))
		  to->flags |= FLAGS_SENDQEX;
      return dead_link(to, "Max SendQ exceeded for %s, closing link");
   }
   else if (dbuf_put(&to->sendQ, msg, len) < 0)
      return dead_link(to, "Buffer allocation error for %s, closing link");
   /*
    * * Update statistics. The following is slightly incorrect *
    * because it counts messages even if queued, but bytes * only
    * really sent. Queued bytes get updated in SendQueued.
    */
   to->sendM += 1;
   me.sendM += 1;
   if (to->acpt != &me)
      to->acpt->sendM += 1;
   /*
    * * This little bit is to stop the sendQ from growing too large
    * when * there is no need for it to. Thus we call send_queued()
    * every time * 2k has been added to the queue since the last
    * non-fatal write. * Also stops us from deliberately building a
    * large sendQ and then * trying to flood that link with data
    * (possible during the net * relinking done by servers with a large
    * load).
    */
   /*
    * Well, let's try every 4k for clients, and immediately for servers
    * -Taner
    */
   SQinK = DBufLength(&to->sendQ) / 1024;
   if (IsServer(to)) {
      if (SQinK > to->lastsq)
		  send_queued(to);
   }
   else {
      if (SQinK > (to->lastsq + 4))
		  send_queued(to);
   }
   return 0;
}


/*
 * * send_queued *    This function is called from the main
 * select-loop (or whatever) *  when there is a chance the some output
 * would be possible. This *    attempts to empty the send queue as far
 * as possible...
 */
int
send_queued(aClient *to)
{
   char       *msg;
   int         len, rlen;

   /*
    * * Once socket is marked dead, we cannot start writing to it, *
    * even if the error is removed...
    */
   if (IsDead(to)) {
      /*
       * * Actually, we should *NEVER* get here--something is * not
       * working correct if send_queued is called for a * dead
       * socket... --msa
       */
      return -1;
   }
   while (DBufLength(&to->sendQ) > 0) {
      msg = dbuf_map(&to->sendQ, &len);
      /*
       * Returns always len > 0 
       */
      if ((rlen = deliver_it(to, msg, len)) < 0)
	 return dead_link(to, "Write error to %s, closing link");
      (void) dbuf_delete(&to->sendQ, rlen);
      to->lastsq = DBufLength(&to->sendQ) / 1024;
      if (rlen < len)
	 /*
	  * ..or should I continue until rlen==0? 
	  */
	 /*
	  * no... rlen==0 means the send returned EWOULDBLOCK... 
	  */
	 break;
   }

   return (IsDead(to)) ? -1 : 0;
}
/*
 * * send message to single client
 */
#ifndef	USE_VARARGS
/*
 * VARARGS 
 */
void
sendto_one(to, pattern, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, p12)
     aClient    *to;
     char       *pattern, *p1, *p2, *p3, *p4, *p5, *p6, *p7, *p8,
                *p9, *p10, *p11, *p12;
{
#else
void
sendto_one(to, pattern, va_alist)
     aClient    *to;
     char       *pattern;
     va_dcl
{
va_list     vl;

#endif

int         len;		/*

				 * used for the length of the current message 
				 */
#ifdef	USE_VARARGS
   va_start(vl);
   (void) vsprintf(sendbuf, pattern, vl);
   va_end(vl);
#else
   len = format(sendbuf, pattern, p1, p2, p3, p4, p5, p6,
		p7, p8, p9, p10, p11, p12);
#endif
   Debug((DEBUG_SEND, "Sending [%s] to %s", sendbuf, to->name));

   if (to->from)
      to = to->from;
   if (to->fd < 0) {
      Debug((DEBUG_ERROR,
	     "Local socket %s with negative fd... AARGH!",
	     to->name));
   }
   else if (IsMe(to)) {
      sendto_ops("Trying to send [%s] to myself!", sendbuf);
      return;
   }

#ifdef USE_VARARGS
   (void) strcat(sendbuf, NEWLINE);
#ifndef	IRCII_KLUDGE
   sendbuf[510] = '\r';
#endif
   sendbuf[511] = '\n';
   sendbuf[512] = '\0';
   len = strlen(sendbuf);
#endif /*
        * use_varargs 
        */
   (void) send_message(to, sendbuf, len);
}

#ifndef	USE_VARARGS
/*
 * VARARGS 
 */
void
sendto_channel_butone(one, from, chptr, pattern,
		      p1, p2, p3, p4, p5, p6, p7, p8)
     aClient    *one, *from;
     aChannel   *chptr;
     char       *pattern, *p1, *p2, *p3, *p4, *p5, *p6, *p7, *p8;
{
#else
void
sendto_channel_butone(one, from, chptr, pattern, va_alist)
     aClient    *one, *from;
     aChannel   *chptr;
     char       *pattern;
     va_dcl
{
va_list     vl;

#endif
Reg Link   *lp;
Reg aClient *acptr;
Reg int     i;

#ifdef	USE_VARARGS
   va_start(vl);
#endif
   /*
    * for (i = 0; i < MAXCONNECTIONS; i++) sentalong[i] = 0;
    */

   memset((char *) sentalong, '\0', sizeof(sentalong));
   for (lp = chptr->members; lp; lp = lp->next) {
      acptr = lp->value.cptr;
      if (acptr->from == one)
	 continue;		/*
				 * ...was the one I should skip 
				 */
      i = acptr->from->fd;
      if (MyConnect(acptr) && IsRegisteredUser(acptr)) {
#ifdef	USE_VARARGS
	 sendto_prefix_one(acptr, from, pattern, vl);
#else
	 sendto_prefix_one(acptr, from, pattern, p1, p2,
			   p3, p4, p5, p6, p7, p8);
#endif
	 sentalong[i] = 1;
      }
      else {
	 /*
	  * Now check whether a message has been sent to this remote
	  * link already
	  */
	 if (sentalong[i] == 0) {
#ifdef	USE_VARARGS
	    sendto_prefix_one(acptr, from, pattern, vl);
#else
	    sendto_prefix_one(acptr, from, pattern,
			      p1, p2, p3, p4,
			      p5, p6, p7, p8);
#endif
	    sentalong[i] = 1;
	 }
      }
   }
#ifdef	USE_VARARGS
   va_end(vl);
#endif
   return;
}
/*
 * sendto_server_butone
 * 
 * Send a message to all connected servers except the client 'one'.
 */
#ifndef	USE_VARARGS
/*
 * VARARGS 
 */
void
sendto_serv_butone(one, pattern, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10)
     aClient    *one;
     char       *pattern, *p1, *p2, *p3, *p4, *p5, *p6, *p7, *p8, *p9, *p10;
{
#else
void
sendto_serv_butone(one, pattern, va_alist)
     aClient    *one;
     char       *pattern;
     va_dcl
{
va_list     vl;

#endif
Reg int     i;
Reg aClient *cptr;
register int j, k = 0;
fdlist      send_fdlist;

#ifdef	USE_VARARGS
   va_start(vl);
#endif

   for (i = serv_fdlist.entry[j = 1];
	j <= serv_fdlist.last_entry; i = serv_fdlist.entry[++j]) {
      if (!(cptr = local[i]) || (one && cptr == one->from))
	 continue;
      /*
       * if (IsServer(cptr)) 
       */
#ifdef	USE_VARARGS
      sendto_one(cptr, pattern, vl);
   }
   va_end(vl);
#else
      /*
       * sendto_one(cptr, pattern, p1, p2, p3, p4, p5, p6, p7, p8);
       */
      send_fdlist.entry[++k] = i;
   }
   send_fdlist.last_entry = k;
   if (k)
      sendto_fdlist(&send_fdlist, pattern, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10);
#endif
   return;
}
#ifdef DF_COMPATIBILITY
/*
 * sendto_df_butone
 * 
 * Send a message to all df servers except the client 'one'.
 */
#ifndef	USE_VARARGS
/*
 * VARARGS 
 */
void
sendto_df_butone(one, pattern, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10)
     aClient    *one;
     char       *pattern, *p1, *p2, *p3, *p4, *p5, *p6, *p7, *p8, *p9, *p10;
{
#else
void
sendto_df_butone(one, pattern, va_alist)
     aClient    *one;
     char       *pattern;
     va_dcl
{
va_list     vl;

#endif
Reg int     i;
Reg aClient *cptr;
register int j, k = 0;
fdlist      send_fdlist;

#ifdef	USE_VARARGS
   va_start(vl);
#endif

   for (i = serv_fdlist.entry[j = 1];
	j <= serv_fdlist.last_entry; i = serv_fdlist.entry[++j]) {
      if (!(cptr = local[i]) || (one && cptr == one->from) ||
	  (IsHybrid(cptr)))
	 continue;
      /*
       * if (IsServer(cptr)) 
       */
#ifdef	USE_VARARGS
      sendto_one(cptr, pattern, vl);
   }
   va_end(vl);
#else
      /*
       * sendto_one(cptr, pattern, p1, p2, p3, p4, p5, p6, p7, p8);
       */
      send_fdlist.entry[++k] = i;
   }
   send_fdlist.last_entry = k;
   if (k)
      sendto_fdlist(&send_fdlist, pattern, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10);
#endif
   return;
}
/*
 * sendto_hybrid_butone
 * 
 * Send a message to all connected hybrid servers except the client 'one'.
 */
#ifndef	USE_VARARGS
/*
 * VARARGS 
 */
void
sendto_hybrid_butone(one, pattern, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10)
     aClient    *one;
     char       *pattern, *p1, *p2, *p3, *p4, *p5, *p6, *p7, *p8, *p9, *p10;
{
#else
void
sendto_hybrid_butone(one, pattern, va_alist)
     aClient    *one;
     char       *pattern;
     va_dcl
{
va_list     vl;

#endif
Reg int     i;
Reg aClient *cptr;
register int j, k = 0;
fdlist      send_fdlist;

#ifdef	USE_VARARGS
   va_start(vl);
#endif

   for (i = serv_fdlist.entry[j = 1];
	j <= serv_fdlist.last_entry; i = serv_fdlist.entry[++j]) {
      if (!(cptr = local[i]) || (one && cptr == one->from) ||
	  (IsDf(cptr)))
	 continue;
      /*
       * if (IsServer(cptr)) 
       */
#ifdef	USE_VARARGS
      sendto_one(cptr, pattern, vl);
   }
   va_end(vl);
#else
      /*
       * sendto_one(cptr, pattern, p1, p2, p3, p4, p5, p6, p7, p8);
       */
      send_fdlist.entry[++k] = i;
   }
   send_fdlist.last_entry = k;
   if (k)
      sendto_fdlist(&send_fdlist, pattern, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10);
#endif
   return;
}
#endif
/*
 * sendto_common_channels()
 * 
 * Sends a message to all people (inclusing user) on local server who are
 * in same channel with user.
 */
#ifndef	USE_VARARGS
/*
 * VARARGS 
 */
void
sendto_common_channels(user, pattern, p1, p2, p3, p4,
		       p5, p6, p7, p8)
     aClient    *user;
     char       *pattern, *p1, *p2, *p3, *p4, *p5, *p6, *p7, *p8;
{
#else
void
sendto_common_channels(user, pattern, va_alist)
     aClient    *user;
     char       *pattern;
     va_dcl
{
va_list     vl;

#endif
register Link *channels;
register Link *users;
register aClient *cptr;

#ifdef	USE_VARARGS
   va_start(vl);
#endif
   memset((char *) sentalong, '\0', sizeof(sentalong));
   if (user->fd >= 0)
      sentalong[user->fd] = 1;
   if (user->user)
      for (channels = user->user->channel; channels; channels = channels->next)
	 for (users = channels->value.chptr->members; users; users = users->next) {
	    cptr = users->value.cptr;
	    if (!MyConnect(cptr) || sentalong[cptr->fd])
	       continue;
	    sentalong[cptr->fd]++;
#ifdef	USE_VARARGS
	    sendto_prefix_one(cptr, user, pattern, vl);
#else
	    sendto_prefix_one(cptr, user, pattern,
			      p1, p2, p3, p4, p5, p6, p7, p8);
#endif
	 }
   if (MyConnect(user))
#ifdef	USE_VARARGS
      sendto_prefix_one(user, user, pattern, vl);
   va_end(vl);
#else
      sendto_prefix_one(user, user, pattern, p1, p2, p3, p4,
			p5, p6, p7, p8);
#endif
   return;
}
#ifdef FLUD
#ifndef USE_VARARGS
void
sendto_channel_butlocal(one, from, chptr, pattern,
			p1, p2, p3, p4, p5, p6, p7, p8)
     aClient    *one, *from;
     aChannel   *chptr;
     char       *pattern, *p1, *p2, *p3, *p4, *p5, *p6, *p7, *p8;
{
#else
void
sendto_channel_butlocal(one, from, chptr, pattern, va_alist)
     aClient    *one, *from;
     aChannel   *chptr;
     char       *pattern;
     va_dcl
{
va_list     vl;

#endif
Reg Link   *lp;
Reg aClient *acptr;
Reg int     i;
int         sentalong[MAXCONNECTIONS];

#ifdef USE_VARARGS
   va_start(vl);
#endif
   memset((char *) sentalong, '\0', sizeof(sentalong));
   for (lp = chptr->members; lp; lp = lp->next) {
      acptr = lp->value.cptr;
      if (acptr->from == one)
	 continue;		/*
				 * ...was the one I should skip 
				 */
      i = acptr->from->fd;
      if (!MyFludConnect(acptr)) {
	 /*
	  * Now check whether a message has been sent to this remote
	  * link already
	  */
	 if (sentalong[i] == 0) {
#ifdef USE_VARARGS
	    sendto_prefix_one(acptr, from, pattern, vl);
#else
	    sendto_prefix_one(acptr, from, pattern,
			      p1, p2, p3, p4,
			      p5, p6, p7, p8);
#endif
	    sentalong[i] = 1;
	 }
      }
   }
#ifdef USE_VARARGS
   va_end(vl);
#endif
   return;
}
#endif /*
        * FLUD 
        */

/*
 * sendto_channel_butserv
 * 
 * Send a message to all members of a channel that are connected to this
 * server.
 */
#ifndef	USE_VARARGS
/*
 * VARARGS 
 */
void
sendto_channel_butserv(chptr, from, pattern, p1, p2, p3,
		       p4, p5, p6, p7, p8)
     aChannel   *chptr;
     aClient    *from;
     char       *pattern, *p1, *p2, *p3, *p4, *p5, *p6, *p7, *p8;
{
#else
void
sendto_channel_butserv(chptr, from, pattern, va_alist)
     aChannel   *chptr;
     aClient    *from;
     char       *pattern;
     va_dcl
{
va_list     vl;

#endif
Reg Link   *lp;
Reg aClient *acptr;

#ifdef	USE_VARARGS
   for (va_start(vl), lp = chptr->members; lp; lp = lp->next)
      if (MyConnect(acptr = lp->value.cptr))
	 sendto_prefix_one(acptr, from, pattern, vl);
   va_end(vl);
#else
   for (lp = chptr->members; lp; lp = lp->next)
      if (MyConnect(acptr = lp->value.cptr))
	 sendto_prefix_one(acptr, from, pattern,
			   p1, p2, p3, p4,
			   p5, p6, p7, p8);
#endif

   return;
}
/*
 * * send a msg to all ppl on servers/hosts that match a specified mask *
 * (used for enhanced PRIVMSGs) *
 * 
 * addition -- Armin, 8jun90 (gruner@informatik.tu-muenchen.de)
 */

static int
match_it(aClient *one, char *mask, int what)
{
   if (what == MATCH_HOST)
      return (match(mask, one->user->host) == 0);
   else
      return (match(mask, one->user->server) == 0);
}
/*
 * sendto_match_servs
 * 
 * send to all servers which match the mask at the end of a channel name
 * (if there is a mask present) or to all if no mask.
 */
#ifndef	USE_VARARGS
/*
 * VARARGS 
 */
void
sendto_match_servs(chptr, from, format, p1, p2, p3, p4, p5, p6, p7, p8, p9)
     aChannel   *chptr;
     aClient    *from;
     char       *format, *p1, *p2, *p3, *p4, *p5, *p6, *p7, *p8,
                *p9;
{
#else
void
sendto_match_servs(chptr, from, format, va_alist)
     aChannel   *chptr;
     aClient    *from;
     char       *format;
     va_dcl
{
va_list     vl;

#endif
register int j, k = 0;
fdlist      send_fdlist;
Reg int     i;
Reg aClient *cptr;

#ifdef	USE_VARARGS
   va_start(vl);
#endif

   if (chptr) {
      if (*chptr->chname == '&')
	 return;
   }

   /*
    * for (i = 0; i <= highest_fd; i++) 
    */
   for (i = serv_fdlist.entry[j = 1]; j <= serv_fdlist.last_entry; i = serv_fdlist.entry[++j]) {
      if (!(cptr = local[i]))
	 continue;
      if (cptr == from)
	 continue;
#ifdef	USE_VARARGS
      sendto_one(cptr, format, vl);
   }
   va_end(vl);
#else
      /*
       * sendto_one(cptr, format, p1, p2, p3, p4, p5, p6, p7, p8, p9); 
       */
      send_fdlist.entry[++k] = i;
   }
   send_fdlist.last_entry = k;
   if (k)
      sendto_fdlist(&send_fdlist, format, p1, p2, p3, p4, p5, p6, p7, p8, p9);
#endif
   return;
}
#ifdef DF_COMPATIBILITY
/*
 * sendto_match_df
 * 
 * send to all df servers which match the mask at the end of a channel
 * name (if there is a mask present) or to all if no mask.
 */
#ifndef	USE_VARARGS
/*
 * VARARGS 
 */
void
sendto_match_df(chptr, from, format, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10)
     aChannel   *chptr;
     aClient    *from;
     char       *format, *p1, *p2, *p3, *p4, *p5, *p6, *p7, *p8, *p9, *p10;
{
#else
void
sendto_match_df(chptr, from, format, va_alist)
     aChannel   *chptr;
     aClient    *from;
     char       *format;
     va_dcl
{
va_list     vl;

#endif
Reg int     i;
Reg aClient *cptr;
char       *mask;

#ifdef	USE_VARARGS
   va_start(vl);
#endif

#ifdef NPATH
   check_command((long) 3, format, p1, p2, p3);
#endif
   if (chptr) {
      if (*chptr->chname == '&')
	 return;
      if ((mask = (char *) strrchr(chptr->chname, ':')))
	 mask++;
   }
   else
      mask = (char *) NULL;

   for (i = 0; i <= highest_fd; i++) {
      if (!(cptr = local[i]))
	 continue;
      if ((cptr == from) || !IsServer(cptr))
	 continue;
      if ((!BadPtr(mask) && IsServer(cptr) &&
	   match(mask, cptr->name)) || IsHybrid(cptr))
	 continue;
#ifdef	USE_VARARGS
      sendto_one(cptr, format, vl);
   }
   va_end(vl);
#else
      sendto_one(cptr, format, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10);
   }
#endif
}
/*
 * sendto_match_hybrid
 * 
 * send to all hybrid servers which match the mask at the end of a channel
 * name (if there is a mask present) or to all if no mask.
 */
#ifndef	USE_VARARGS
/*
 * VARARGS 
 */
void
sendto_match_hybrid(chptr, from, format, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10)
     aChannel   *chptr;
     aClient    *from;
     char       *format, *p1, *p2, *p3, *p4, *p5, *p6, *p7, *p8, *p9, *p10;
{
#else
void
sendto_match_hybrid(chptr, from, format, va_alist)
     aChannel   *chptr;
     aClient    *from;
     char       *format;
     va_dcl
{
va_list     vl;

#endif
Reg int     i;
Reg aClient *cptr;
char       *mask;

#ifdef	USE_VARARGS
   va_start(vl);
#endif

#ifdef NPATH
   check_command((long) 3, format, p1, p2, p3);
#endif
   if (chptr) {
      if (*chptr->chname == '&')
	 return;
      if ((mask = (char *) strrchr(chptr->chname, ':')))
	 mask++;
   }
   else
      mask = (char *) NULL;

   for (i = 0; i <= highest_fd; i++) {
      if (!(cptr = local[i]))
	 continue;
      if ((cptr == from) || !IsServer(cptr))
	 continue;
      if ((!BadPtr(mask) && IsServer(cptr) &&
	   match(mask, cptr->name)) || IsDf(cptr))
	 continue;
#ifdef	USE_VARARGS
      sendto_one(cptr, format, vl);
   }
   va_end(vl);
#else
      sendto_one(cptr, format, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10);
   }
#endif
}
#endif
/*
 * sendto_match_butone
 * 
 * Send to all clients which match the mask in a way defined on 'what';
 * either by user hostname or user servername.
 */
#ifndef	USE_VARARGS
/*
 * VARARGS 
 */
void
sendto_match_butone(one, from, mask, what, pattern,
		    p1, p2, p3, p4, p5, p6, p7, p8)
     aClient    *one, *from;
     int         what;
     char       *mask, *pattern, *p1, *p2, *p3, *p4, *p5, *p6, *p7,
                *p8;
{
#else
void
sendto_match_butone(one, from, mask, what, pattern, va_alist)
     aClient    *one, *from;
     int         what;
     char       *mask, *pattern;
     va_dcl
{
va_list     vl;

#endif
Reg int     i;
Reg aClient *cptr, *acptr;
char cansendlocal, cansendglobal;
#ifdef	USE_VARARGS
   va_start(vl);
#endif
	 if (MyConnect(from)) {
			cansendlocal = (OPCanLNotice(from)) ? 1 : 0;
			cansendglobal = (OPCanGNotice(from)) ? 1 : 0;
	 } else cansendlocal = cansendglobal = 1;
   for (i = 0; i <= highest_fd; i++) {
      if (!(cptr = local[i]))
	 continue;		/*
				 * that clients are not mine 
				 */
      if (cptr == one)		/*
				 * must skip the origin !! 
				 */
	 continue;
      if (IsServer(cptr)) {
				 if (!cansendglobal) continue;
				 for (acptr = client; acptr; acptr = acptr->next)
					 if (IsRegisteredUser(acptr)
							 && match_it(acptr, mask, what)
							 && acptr->from == cptr)
						 break;
				 /*
					* a person on that server matches the mask, so we * send *one*
					* msg to that server ...
					*/
				 if (acptr == NULL)
					 continue;
				 /*
					* ... but only if there *IS* a matching person 
					*/
      }
      /*
       * my client, does he match ? 
       */
      else if (!cansendlocal || !(IsRegisteredUser(cptr) &&
		 match_it(cptr, mask, what)))
	 continue;
#ifdef	USE_VARARGS
      sendto_prefix_one(cptr, from, pattern, vl);
   }
   va_end(vl);
#else
      sendto_prefix_one(cptr, from, pattern,
			p1, p2, p3, p4, p5, p6, p7, p8);
   }
#endif
   return;
}
/*
 * sendto_all_butone.
 * 
 * Send a message to all connections except 'one'. The basic wall type
 * message generator.
 */
#ifndef	USE_VARARGS
/*
 * VARARGS 
 */
void
sendto_all_butone(one, from, pattern, p1, p2, p3, p4, p5, p6, p7, p8)
     aClient    *one, *from;
     char       *pattern, *p1, *p2, *p3, *p4, *p5, *p6, *p7, *p8;
{
#else
void
sendto_all_butone(one, from, pattern, va_alist)
     aClient    *one, *from;
     char       *pattern;
     va_dcl
{
va_list     vl;

#endif
Reg int     i;
Reg aClient *cptr;

#ifdef	USE_VARARGS
   for (va_start(vl), i = 0; i <= highest_fd; i++)
      if ((cptr = local[i]) && !IsMe(cptr) && one != cptr)
	 sendto_prefix_one(cptr, from, pattern, vl);
   va_end(vl);
#else
   for (i = 0; i <= highest_fd; i++)
      if ((cptr = local[i]) && !IsMe(cptr) && one != cptr)
	 sendto_prefix_one(cptr, from, pattern,
			   p1, p2, p3, p4, p5, p6, p7, p8);
#endif

   return;
}
/*
 * sendto_ops_lev
 * 
 * Send to *local* ops only at a certain level... 0 = normal +s 1 = client
 * connect/disconnect   (+c) [IRCOPS ONLY] 2 = bot rejection
 * (+r) 3 = server kills                      (+k)
 */
#ifndef       USE_VARARGS
/*
 * VARARGS 
 */
void
sendto_ops_lev(lev, pattern, p1, p2, p3, p4, p5, p6, p7, p8)
     int         lev;
     char       *pattern, *p1, *p2, *p3, *p4, *p5, *p6, *p7, *p8;
{
#else
void
sendto_ops_lev(lev, pattern, va_alist)
     int         lev;
     char       *pattern;
     va_dcl
{
va_list     vl;

#endif
Reg aClient *cptr;
Reg int     i;
char        nbuf[1024];

#ifdef        USE_VARARGS
   va_start(vl);
#endif

	for (i = 0; i <= highest_fd; i++)
		if ((cptr = local[i]) && !IsServer(cptr) && !IsMe(cptr)) {
			switch (lev) {
			 case CCONN_LEV:
				if (!SendCConnNotice(cptr) || !IsAnOper(cptr))
					continue;
				break;
			 case REJ_LEV:
				if (!SendRejNotice(cptr) || !IsAnOper(cptr))
					continue;
				break;
			 case SKILL_LEV:
				if (!SendSkillNotice(cptr))
					continue;
				break;
			 case SPY_LEV:
				if (!SendSpyNotice(cptr) || !IsAnOper(cptr))
					continue;
				break;
			 case FLOOD_LEV:
				if (!SendFloodNotice(cptr) || !IsAnOper(cptr))
					continue;
				break;
			 case DEBUG_LEV:
				if (!SendDebugNotice(cptr) || !IsAnOper(cptr))
					continue;
				break;
				
			 default:		/*
									 * this is stupid, but oh well 
									 */
				if (!SendServNotice(cptr))
					continue;
			}
			(void) ircsprintf(nbuf, ":%s NOTICE %s :*** Notice -- ",
												me.name, cptr->name);
			(void) strncat(nbuf, pattern,
										 sizeof(nbuf) - strlen(nbuf));
#ifdef        USE_VARARGS
			sendto_one(cptr, nbuf, va_alist);
#else
			sendto_one(cptr, nbuf, p1, p2, p3, p4, p5, p6, p7, p8);
#endif
		}
	return;
}				/*
				 * sendto_ops_lev 
				 */
/*
 * sendto_ops
 * 
 * Send to *local* ops only.
 */
#ifndef	USE_VARARGS
/*
 * VARARGS 
 */
void
sendto_ops(pattern, p1, p2, p3, p4, p5, p6, p7, p8)
     char       *pattern, *p1, *p2, *p3, *p4, *p5, *p6, *p7, *p8;
{
#else
void
sendto_ops(pattern, va_alist)
     char       *pattern;
     va_dcl
{
va_list     vl;

#endif
Reg aClient *cptr;
Reg int     i;
char        nbuf[1024];

#ifdef	USE_VARARGS
   va_start(vl);
#endif
   for (i = 0; i <= highest_fd; i++)
      if ((cptr = local[i]) && !IsServer(cptr) && !IsMe(cptr) &&
	  IsAnOper(cptr) && SendServNotice(cptr)) {
	 (void) ircsprintf(nbuf, ":%s NOTICE %s :*** Notice -- ",
			   me.name, cptr->name);
	 (void) strncat(nbuf, pattern,
			sizeof(nbuf) - strlen(nbuf));
#ifdef	USE_VARARGS
	 sendto_one(cptr, nbuf, va_alist);
#else
	 sendto_one(cptr, nbuf, p1, p2, p3, p4, p5, p6, p7, p8);
#endif
      }
   return;
}

/*
 * * sendto_ops_butone *      Send message to all operators. * one -
 * client not to send message to * from- client which message is from
 * *NEVER* NULL!!
 */
#ifndef	USE_VARARGS
/*
 * VARARGS 
 */
void
sendto_ops_butone(one, from, pattern, p1, p2, p3, p4, p5, p6, p7, p8)
     aClient    *one, *from;
     char       *pattern, *p1, *p2, *p3, *p4, *p5, *p6, *p7, *p8;
{
#else
void
sendto_ops_butone(one, from, pattern, va_alist)
     aClient    *one, *from;
     char       *pattern;
     va_dcl
{
va_list     vl;

#endif
Reg int     i;
Reg aClient *cptr;

#ifdef	USE_VARARGS
   va_start(vl);
#endif
   memset((char *) sentalong, '\0', sizeof(sentalong));
   for (cptr = client; cptr; cptr = cptr->next) {
      if (!SendWallops(cptr))
	 continue;
      /*
       * we want wallops if (MyClient(cptr) && !(IsServer(from) ||
       * IsMe(from))) continue;
       */
      i = cptr->from->fd;	/*
				 * find connection oper is on 
				 */
      if (sentalong[i])		/*
				 * sent message along it already ? 
				 */
	 continue;
      if (cptr->from == one)
	 continue;		/*
				 * ...was the one I should skip 
				 */
      sentalong[i] = 1;
#ifdef	USE_VARARGS
      sendto_prefix_one(cptr->from, from, pattern, vl);
   }
   va_end(vl);
#else
      sendto_prefix_one(cptr->from, from, pattern,
			p1, p2, p3, p4, p5, p6, p7, p8);
   }
#endif
   return;
}
/*
 * * sendto_wallops_butone *      Send message to all operators. * one
 * - client not to send message to * from- client which message is from
 * *NEVER* NULL!!
 */
#ifndef USE_VARARGS
/*
 * VARARGS 
 */
void
sendto_wallops_butone(one, from, pattern, p1, p2, p3, p4, p5, p6, p7, p8)
     aClient    *one, *from;
     char       *pattern, *p1, *p2, *p3, *p4, *p5, *p6, *p7, *p8;
{
#else
void
sendto_wallops_butone(one, from, pattern, va_alist)
     aClient    *one, *from;
     char       *pattern;
     va_dcl
{
va_list     vl;

#endif
Reg int     i;
Reg aClient *cptr;

#ifdef  USE_VARARGS
   va_start(vl);
#endif
   memset((char *) sentalong, '\0', sizeof(sentalong));
   for(i=0;i<=highest_fd;i++) {
      if((cptr=local[i])!=NULL) {
         if(!(IsRegistered(cptr) && (SendWallops(cptr) || IsServer(cptr))) || cptr==one)
            continue;
      sendto_prefix_one(cptr, from, pattern,
			p1, p2, p3, p4, p5, p6, p7, p8);
      }
   }
   return;
}

#ifndef USE_VARARGS
void
send_globops(pattern, p1, p2, p3, p4, p5, p6, p7, p8)
     char       *pattern, *p1, *p2, *p3, *p4, *p5, *p6, *p7, *p8;
{
#else
void
send_globops(pattern, va_alist)
     char       *pattern;
     va_dcl
{
va_list     vl;

#endif
aClient    *cptr;
int         i;
char        nbuf[1024];

#ifdef  USE_VARARGS
   va_start(vl);
#endif
   for (i = 0; i <= highest_fd; i++)
      if ((cptr = local[i]) && !IsServer(cptr) && IsAnOper(cptr) &&
	  !IsMe(cptr) && SendGlobops(cptr)) {
	 (void) ircsprintf(nbuf, ":%s NOTICE %s :*** Global -- ",
			me.name, cptr->name);
	 (void) strncat(nbuf, pattern,
			sizeof(nbuf) - strlen(nbuf));
#ifdef  USE_VARARGS
	 sendto_one(cptr, nbuf, va_alist);
#else
	 sendto_one(cptr, nbuf, p1, p2, p3, p4, p5, p6, p7, p8);
#endif
      }
   return;
}
#ifndef USE_VARARGS
void
send_chatops(pattern, p1, p2, p3, p4, p5, p6, p7, p8)
     char       *pattern, *p1, *p2, *p3, *p4, *p5, *p6, *p7, *p8;
{
#else
void
send_chatops(pattern, va_alist)
     char       *pattern;
     va_dcl
{
va_list     vl;

#endif
aClient    *cptr;
int         i;
char        nbuf[1024];

#ifdef  USE_VARARGS
   va_start(vl);
#endif
   for (i = 0; i <= highest_fd; i++)
      if ((cptr = local[i]) && !IsServer(cptr) && IsAnOper(cptr) &&
	  !IsMe(cptr) && SendChatops(cptr)) {
	 (void) sprintf(nbuf, ":%s NOTICE %s :*** ChatOps -- ",
			me.name, cptr->name);
	 (void) strncat(nbuf, pattern,
			sizeof(nbuf) - strlen(nbuf));
#ifdef  USE_VARARGS
	 sendto_one(cptr, nbuf, va_alist);
#else
	 sendto_one(cptr, nbuf, p1, p2, p3, p4, p5, p6, p7, p8);
#endif
      }
   return;
}
/*
 * to - destination client from - client which message is from
 * 
 * NOTE: NEITHER OF THESE SHOULD *EVER* BE NULL!! -avalon
 */
#ifndef	USE_VARARGS
/*
 * VARARGS 
 */
void
sendto_prefix_one(to, from, pattern, p1, p2, p3, p4, p5, p6, p7, p8)
     Reg aClient *to;
     Reg aClient *from;
     char       *pattern, *p1, *p2, *p3, *p4, *p5, *p6, *p7, *p8;
{
#else
void
sendto_prefix_one(to, from, pattern, va_alist)
     Reg aClient *to;
     Reg aClient *from;
     char       *pattern;
     va_dcl
{
va_list     vl;

#endif
static char sender[HOSTLEN + NICKLEN + USERLEN + 5];
Reg anUser *user;
char       *par;
static char temp[1024];
int         flag = 0;

#ifdef	USE_VARARGS
   va_start(vl);
par = va_arg(vl, char *);

#else
   par = p1;
#endif
   /*
    * Optimize by checking if (from && to) before everything 
    */
   if (to && from) {
      if (!MyClient(from) && IsPerson(to) && (to->from == from->from)) {
	 if (IsServer(from)) {
#ifdef	USE_VARARGS
	    (void) ircsprintf(temp, pattern, par, vl);
	    va_end(vl);
#else
	    (void) ircsprintf(temp, pattern, par, p2, p3,
			      p4, p5, p6, p7, p8);
#endif
	    sendto_ops("Send message (%s) to %s[%s] dropped from %s(Fake Dir)", temp,
		       to->name, to->from->name, from->name);
	    return;
	 }
	 sendto_ops("Ghosted: %s[%s@%s] from %s[%s@%s] (%s)",
		    to->name, to->user->username, to->user->host,
		    from->name, from->user->username, from->user->host,
		    to->from->name);
	 sendto_serv_butone(NULL, ":%s KILL %s :%s (%s[%s@%s] Ghosted %s)",
			    me.name, to->name, me.name, to->name,
		  to->user->username, to->user->host, to->from->name);
	 to->flags |= FLAGS_KILLED;
	 (void) exit_client(NULL, to, &me, "Ghosted client");
	 if (IsPerson(from))
	    sendto_one(from, err_str(ERR_GHOSTEDCLIENT),
		    me.name, from->name, to->name, to->user->username,
		       to->user->host, to->from);
	 return;
      }
      if (MyClient(to) && IsPerson(from) && !mycmp(par, from->name)) {
	 user = from->user;
	 (void) strcpy(sender, from->name);
	 if (user) {
	    if (*user->username) {
	       (void) strcat(sender, "!");
	       (void) strcat(sender, user->username);
	    }
	    if (*user->host && !MyConnect(from)) {
	       (void) strcat(sender, "@");
	       (void) strcat(sender, user->host);
	       flag = 1;
	    }
	 }
	 /*
	  * * flag is used instead of index(sender, '@') for speed and *
	  * also since username/nick may have had a '@' in them.
	  * -avalon
	  */
	 if (!flag && MyConnect(from) && *user->host) {
	    (void) strcat(sender, "@");
	    (void) strcat(sender, from->sockhost);
	 }
	 par = sender;
      }
   }				/*
				 * if (from && to) 
				 */
#ifdef	USE_VARARGS
   sendto_one(to, pattern, par, vl);
   va_end(vl);
#else
   sendto_one(to, pattern, par, p2, p3, p4, p5, p6, p7, p8);
#endif
}

int
format(char *outp, char *formp, char *in0p, char *in1p, char *in2p,
       char *in3p, char *in4p, char *in5p, char *in6p, char *in7p,
       char *in8p, char *in9p, char *in10p, char *in11p)
{
   /*
    * rp for Reading, wp for Writing, fp for the Format string 
    */
   char       *inp[12];		/*

				 * we could hack this if we know the format of
				 * * the stack 
				 */
   register char *rp, *fp, *wp;
   register char f;
   register int i = 0;

   inp[0] = in0p;
   inp[1] = in1p;
   inp[2] = in2p;
   inp[3] = in3p;
   inp[4] = in4p;
   inp[5] = in5p;
   inp[6] = in6p;
   inp[7] = in7p;
   inp[8] = in8p;
   inp[9] = in9p;
   inp[10] = in10p;
   inp[11] = in11p;
   fp = formp;
   wp = outp;

   rp = inp[i];			/* start with the first input string */
   /*
    * just scan the format string and puke out whatever is necessary
    * along the way...
    */

   while ((f = *(fp++))) {

      if (f != '%')
	 *(wp++) = f;
      else
	 switch (*(fp++)) {
	    case 's':		/*
				 * put the most common case at the top 
				 */
	       if (rp) {
		  while (*rp)
		     *wp++ = *rp++;
		  *wp = '\0';
	       }
	       else {
		  *wp++ = '{';
		  *wp++ = 'n';
		  *wp++ = 'u';
		  *wp++ = 'l';
		  *wp++ = 'l';
		  *wp++ = '}';
		  *wp++ = '\0';
	       }
	       rp = inp[++i];	/*
				 * get the next parameter 
				 */
	       break;
	    case 'd':
	       {
   register int myint, quotient;

		  myint = (int) rp;
		  if (myint > 999 || myint < 0)
		     goto barf;
		  if ((quotient = myint / 100)) {
		     *(wp++) = (char) (quotient + (int) '0');
		     myint %= 100;
		     *(wp++) = (char) (myint / 10 + (int) '0');
		  }
		  else {
		     myint %= 100;
		     if ((quotient = myint / 10))
			*(wp++) = (char) (quotient + (int) '0');
		  }
		  myint %= 10;
		  *(wp++) = (char) ((myint) + (int) '0');

		  rp = inp[++i];
	       }
	       break;
	    case 'u':
	       {
   register unsigned int myuint;

		  myuint = (unsigned int) rp;

		  if (myuint < 100 || myuint > 999)
		     goto barf;

		  *(wp++) = (char) ((myuint / 100) + (unsigned int) '0');
		  myuint %= 100;
		  *(wp++) = (char) ((myuint / 10) + (unsigned int) '0');
		  myuint %= 10;
		  *(wp++) = (char) ((myuint) + (unsigned int) '0');
		  rp = inp[++i];
	       }
	       break;
	    case '%':
	       *(wp++) = '%';
	       break;
	    default:
	       /*
	        * oh shit 
	        */
	       goto barf;
	       break;
	 }
   }
#ifndef IRCII_KLUDGE
   *(wp++) = '\r';
#endif
   *(wp++) = '\n';
   *wp = '\0';			/*
				 * leaves wp pointing to the
				 * * terminating NULL in the string 
				 */
   {
   register int len;

#ifndef IRCII_KLUDGE
      if ((len = wp - outp) >= 510)
	 len = 512;
      outp[510] = '\r';
#else
      if ((len = wp - outp) >= 511)
	 len = 512;
#endif
      outp[511] = '\n';
      outp[512] = '\0';
      return len;

   }
 barf:
   /*
    * don't call ircsprintf here... that's stupid.. 
    */
   sprintf(outp, formp, in0p, in1p, in2p, in3p, in4p, in5p, in6p, in7p, in8p,
	   in9p, in10p, in11p);
   strcat(outp, NEWLINE);
#ifndef IRCII_KLUDGE
   outp[510] = '\r';
#endif
   outp[511] = '\n';
   outp[512] = '\0';
   return strlen(outp);
}

void
sendto_fdlist(listp, formp, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10)
     fdlist     *listp;
     char       *formp;
     char       *p1, *p2, *p3, *p4, *p5, *p6, *p7, *p8, *p9, *p10;
{
register int len, j, fd;

   len = format(sendbuf, formp, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10,
		(char *) NULL, (char *) NULL);

   for (fd = listp->entry[j = 1]; j <= listp->last_entry; fd = listp->entry[++j])
      send_message(local[fd], sendbuf, len);
}
/*
 * sendto_realops
 * 
 * Send to *local* ops only but NOT +s nonopers.
 * If it's to local ops only and not +s nonopers, then SendServNotice is
 * wrong. Changed to IsAnOper. -mjs
 */
#ifndef       USE_VARARGS
void
sendto_realops(pattern, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10)
     char       *pattern, *p1, *p2, *p3, *p4, *p5, *p6, *p7, *p8,
                *p9, *p10;
{
#else
void
sendto_realops(pattern, va_alist)
     char       *pattern;
     va_dcl
{
va_list     vl;

#endif
Reg aClient *cptr;
Reg int     i;
char        nbuf[1024];
fdlist     *l;
int         fd;

#ifdef        USE_VARARGS
   va_start(vl);
#endif
   l = &oper_fdlist;
   for (fd = l->entry[i = 1]; i <= l->last_entry; fd = l->entry[++i]) {
      if (!(cptr = local[fd]))
	 continue;
      if (IsAnOper(cptr)) {
	 (void) ircsprintf(nbuf, ":%s NOTICE %s :*** Notice -- ",
			   me.name, cptr->name);
	 (void) strncat(nbuf, pattern,
			sizeof(nbuf) - strlen(nbuf));
#ifdef        USE_VARARGS
	 sendto_one(cptr, nbuf, va_alist);
#else
	 sendto_one(cptr, nbuf, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10);
#endif
      }
   }
#ifdef        USE_VARARGS
   va_end(vl);
#endif
   return;
}

/*
 * sendto_realops_lev
 * 
 * Send to *local* ops only but NOT +s nonopers at a certain level
 */
#ifndef       USE_VARARGS
void
sendto_realops_lev(lev, pattern, p1, p2, p3, p4, p5, p6, p7, p8)
     int         lev;
     char       *pattern, *p1, *p2, *p3, *p4, *p5, *p6, *p7, *p8;
{
#else
void
sendto_realops_lev(lev, pattern, va_alist)
     int         lev;
     char       *pattern;
     va_dcl
{
va_list     vl;

#endif
Reg aClient *cptr;
Reg int     i;
char        nbuf[1024];
fdlist     *l;
int         fd;

#ifdef        USE_VARARGS
   va_start(vl);
#endif
   l = &oper_fdlist;
   for (fd = l->entry[i = 1]; i <= l->last_entry; fd = l->entry[++i]) {
      if (!(cptr = local[fd]))
	 continue;
      switch (lev) {
	 case CCONN_LEV:
	    if (!SendCConnNotice(cptr))
	       continue;
	    break;
	 case REJ_LEV:
	    if (!SendRejNotice(cptr))
	       continue;
	    break;
	 case SKILL_LEV:	/*
				 * This should not be sent, since this
				 * * can go to normal people 
				 */
				if (!SendSkillNotice(cptr))
					continue;
				break;
			 case SPY_LEV:
				if (!SendSpyNotice(cptr))
					continue;
				break;
			 case FLOOD_LEV:
				if (!SendFloodNotice(cptr))
					continue;
				break;
			 case DEBUG_LEV:
				if (!SendDebugNotice(cptr))
					continue;
				break;
      }
      (void) ircsprintf(nbuf, ":%s NOTICE %s :*** Notice -- ",
			me.name, cptr->name);
      (void) strncat(nbuf, pattern,
		     sizeof(nbuf) - strlen(nbuf));
#ifdef        USE_VARARGS
      sendto_one(cptr, nbuf, va_alist);
#else
      sendto_one(cptr, nbuf, p1, p2, p3, p4, p5, p6, p7, p8);
#endif
   }
#ifdef        USE_VARARGS
   va_end(vl);
#endif
   return;
}

/*
 * * ts_warn *      Call sendto_ops, with some flood checking (at most
 * 5 warnings *      every 5 seconds)
 */

#ifndef USE_VARARGS
/*
 * VARARGS 
 */
void
ts_warn(pattern, p1, p2, p3, p4, p5, p6, p7, p8)
     char       *pattern, *p1, *p2, *p3, *p4, *p5, *p6, *p7, *p8;
{
#else
void
ts_warn(pattern, va_alist)
     char       *pattern;
     va_dcl
{
va_list     vl;

#endif
static ts_val last = 0;
static int  warnings = 0;
register ts_val now;

#ifdef  USE_VARARGS
   va_start(vl);
#endif
   /*
    * * if we're running with TS_WARNINGS enabled and someone does *
    * something silly like (remotely) connecting a nonTS server, *
    * we'll get a ton of warnings, so we make sure we don't send * more
    * than 5 every 5 seconds.  -orabidoo
    */
   /*
    * th+hybrid servers always do TS_WARNINGS -Dianora
    */
   now = time(NULL);
   if (now - last < 5) {
      if (++warnings > 5)
	 return;
   }
   else {
      last = now;
      warnings = 0;
   }

#ifdef  USE_VARARGS
   sendto_realops(pattern, va_alist);
#else
   sendto_realops(pattern, p1, p2, p3, p4, p5, p6, p7, p8);
#endif
   return;
}
/*
 * sendto_locops
 */
#ifndef       USE_VARARGS
void
sendto_locops(pattern, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10)
     char       *pattern, *p1, *p2, *p3, *p4, *p5, *p6, *p7, *p8,
                *p9, *p10;
{
#else
void
sendto_locops(pattern, va_alist)
     char       *pattern;
     va_dcl
{
va_list     vl;

#endif
Reg aClient *cptr;
Reg int     i;
char        nbuf[1024];
fdlist     *l;
int         fd;

#ifdef        USE_VARARGS
   va_start(vl);
#endif
   l = &oper_fdlist;
   for (fd = l->entry[i = 1]; i <= l->last_entry; fd = l->entry[++i]) {
      if (!(cptr = local[fd]))
	 continue;
      if (SendGlobops(cptr)) {
	 (void) ircsprintf(nbuf, ":%s NOTICE %s :*** LocOps -- ",
			   me.name, cptr->name);
	 (void) strncat(nbuf, pattern,
			sizeof(nbuf) - strlen(nbuf));
#ifdef        USE_VARARGS
	 sendto_one(cptr, nbuf, va_alist);
#else
	 sendto_one(cptr, nbuf, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10);
#endif
      }
   }
#ifdef        USE_VARARGS
   va_end(vl);
#endif
   return;
}
/*
 * sendto_gnotice used to send to all local ops, +g. the only change
 * from _locops is the outputted string. chances are, using
 * sendto_locops in s_serv.c will be just fine. however. ported from
 * df465 -mjs
 */
#ifndef USE_VARARGS
/*
 * VARARGS 
 */
void
sendto_gnotice(pattern, p1, p2, p3, p4, p5, p6, p7, p8)
     char       *pattern, *p1, *p2, *p3, *p4, *p5, *p6, *p7, *p8;
{
#else
void
sendto_gnotice(pattern, va_alist)
     char       *pattern;
     va_dcl
{
va_list     vl;

#endif
Reg aClient *cptr;
Reg int     i;
char        nbuf[1024];
fdlist     *l;
int         fd;

#ifdef  USE_VARARGS
   va_start(vl);
#endif
   l = &oper_fdlist;
   for (fd = l->entry[i = 1]; i <= l->last_entry; fd = l->entry[++i]) {
      if (!(cptr = local[fd]))
	 continue;
      if (SendGlobops(cptr)) {

	 (void) ircsprintf(nbuf, ":%s NOTICE %s :*** Global -- ",
			   me.name, cptr->name);
	 (void) strncat(nbuf, pattern,
			sizeof(nbuf) - strlen(nbuf));
#ifdef  USE_VARARGS
	 sendto_one(cptr, nbuf, va_alist);
#else
	 sendto_one(cptr, nbuf, p1, p2, p3, p4, p5, p6, p7, p8);
#endif
	 return;
      }
   }
#ifdef        USE_VARARGS
   va_end(vl);
#endif
   return;
}

/*
 * sendto_channelops_butone
 *   Send a message to all OPs in channel chptr that
 *   are directly on this server and sends the message
 *   on to the next server if it has any OPs.
 */
#ifndef VARARGS
void 
sendto_channelops_butone(one, from, chptr, pattern,
			 p1, p2, p3, p4, p5, p6, p7, p8)
     aClient    *one, *from;
     aChannel   *chptr;
     char       *pattern, *p1, *p2, *p3, *p4, *p5, *p6, *p7, *p8;
{
#else
void 
sendto_channelops_butone(one, from, chptr, pattern, va_alist)
     aClient    *one, *from;
     aChannel   *chptr;
     char       *pattern;
     va_dcl
{
va_list     vl;

#endif
Reg Link   *lp;
Reg aClient *acptr;
Reg int     i;

#ifdef USE_VARARGS
   va_start(vl);
#endif
   memset((char *) sentalong, '\0', sizeof(sentalong));
   for (lp = chptr->members; lp; lp = lp->next) {
      acptr = lp->value.cptr;
      if (acptr->from == one ||
	  !(lp->flags & CHFL_CHANOP))
	 continue;
      i = acptr->from->fd;
      if (MyConnect(acptr) && IsRegisteredUser(acptr)) {
#ifdef USE_VARARGS
	 sendto_prefix_one(acptr, from, pattern, vl);
#else
	 sendto_prefix_one(acptr, from, pattern, p1, p2,
			   p3, p4, p5, p6, p7, p8);
#endif
	 sentalong[i] = 1;
      }
      else {
	 /*
	  * Now check whether a message has been sent to this
	  * *      * remote link already 
	  */
	 if (sentalong[i] == 0) {
#ifdef USE_VARARGS
	    sendto_prefix_one(acptr, from, pattern, vl);
#else
	    sendto_prefix_one(acptr, from, pattern,
			      p1, p2, p3, p4,
			      p5, p6, p7, p8);
#endif
	    sentalong[i] = 1;
	 }
      }
   }
#ifdef USE_VARARGS
   va_end(vl);
#endif
   return;
}
/*
 * sendto_channelvoice_butone
 *   Send a message to all voiced users in channel chptr that
 *   are directly on this server and sends the message
 *   on to the next server if it has any voiced users.
 */
#ifndef VARARGS
void 
sendto_channelvoice_butone(one, from, chptr, pattern,
			   p1, p2, p3, p4, p5, p6, p7, p8)
     aClient    *one, *from;
     aChannel   *chptr;
     char       *pattern, *p1, *p2, *p3, *p4, *p5, *p6, *p7, *p8;
{
#else
void 
sendto_channelvoice_butone(one, from, chptr, pattern, va_alist)
     aClient    *one, *from;
     aChannel   *chptr;
     char       *pattern;
     va_dcl
{
va_list     vl;

#endif
Reg Link   *lp;
Reg aClient *acptr;
Reg int     i;

#ifdef USE_VARARGS
   va_start(vl);
#endif
   memset((char *) sentalong, '\0', sizeof(sentalong));
   for (lp = chptr->members; lp; lp = lp->next) {
      acptr = lp->value.cptr;
      if (acptr->from == one ||
	  !(lp->flags & CHFL_VOICE))
	 continue;
      i = acptr->from->fd;
      if (MyConnect(acptr) && IsRegisteredUser(acptr)) {
#ifdef USE_VARARGS
	 sendto_prefix_one(acptr, from, pattern, vl);
#else
	 sendto_prefix_one(acptr, from, pattern, p1, p2,
			   p3, p4, p5, p6, p7, p8);
#endif
	 sentalong[i] = 1;
      }
      else {
	 /*
	  * Now check whether a message has been sent to this
	  * *      * remote link already 
	  */
	 if (sentalong[i] == 0) {
#ifdef USE_VARARGS
	    sendto_prefix_one(acptr, from, pattern, vl);
#else
	    sendto_prefix_one(acptr, from, pattern,
			      p1, p2, p3, p4,
			      p5, p6, p7, p8);
#endif
	    sentalong[i] = 1;
	 }
      }
   }
#ifdef USE_VARARGS
   va_end(vl);
#endif
   return;
}
/*
 * sendto_channelvoiceops_butone
 *   Send a message to all OPs or voiced users in channel chptr that
 *   are directly on this server and sends the message
 *   on to the next server if it has any OPs or voiced users.
 */
#ifndef VARARGS
void 
sendto_channelvoiceops_butone(one, from, chptr, pattern,
			      p1, p2, p3, p4, p5, p6, p7, p8)
     aClient    *one, *from;
     aChannel   *chptr;
     char       *pattern, *p1, *p2, *p3, *p4, *p5, *p6, *p7, *p8;
{
#else
void 
sendto_channelvoiceops_butone(one, from, chptr, pattern, va_alist)
     aClient    *one, *from;
     aChannel   *chptr;
     char       *pattern;
     va_dcl
{
va_list     vl;

#endif
Reg Link   *lp;
Reg aClient *acptr;
Reg int     i;

#ifdef USE_VARARGS
   va_start(vl);
#endif
   memset((char *) sentalong, '\0', sizeof(sentalong));
   for (lp = chptr->members; lp; lp = lp->next) {
      acptr = lp->value.cptr;
      if (acptr->from == one ||
	  !((lp->flags & CHFL_VOICE) || (lp->flags & CHFL_CHANOP)))
	 continue;
      i = acptr->from->fd;
      if (MyConnect(acptr) && IsRegisteredUser(acptr)) {
#ifdef USE_VARARGS
	 sendto_prefix_one(acptr, from, pattern, vl);
#else
	 sendto_prefix_one(acptr, from, pattern, p1, p2,
			   p3, p4, p5, p6, p7, p8);
#endif
	 sentalong[i] = 1;
      }
      else {
	 /*
	  * Now check whether a message has been sent to this
	  * *      * remote link already 
	  */
	 if (sentalong[i] == 0) {
#ifdef USE_VARARGS
	    sendto_prefix_one(acptr, from, pattern, vl);
#else
	    sendto_prefix_one(acptr, from, pattern,
			      p1, p2, p3, p4,
			      p5, p6, p7, p8);
#endif
	    sentalong[i] = 1;
	 }
      }
   }
#ifdef USE_VARARGS
   va_end(vl);
#endif
   return;
}

/*
 * * flush_fdlist_connections
 */

void
flush_fdlist_connections(listp)
     fdlist     *listp;
{
Reg int     i, fd;
Reg aClient *cptr;

   for (fd = listp->entry[i = 1]; i <= listp->last_entry;
	fd = listp->entry[++i])
      if ((cptr = local[fd]) && DBufLength(&cptr->sendQ) > 0)
	 (void) send_queued(cptr);
}
