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
#include "dh.h"
#include "zlink.h"

#ifdef ALWAYS_SEND_DURING_SPLIT
extern int currently_processing_netsplit;
#endif

static char sendbuf[2048];
static char remotebuf[2048];
static int  send_message(aClient *, char *, int);

#ifdef HAVE_ENCRYPTION_ON
static char rc4buf[768];
#endif

static int  sentalong[MAXCONNECTIONS];
static int  sent_serial;

void init_send()
{
   memset(sentalong, 0, sizeof(int) * MAXCONNECTIONS);
   sent_serial = 0;
}

/* This routine increments our serial number so it will
 * be unique from anything in sentalong, no need for a memset
 * except for every MAXINT calls - lucas
 */

/* This should work on any OS where an int is 32 bit, I hope.. */

#define HIGHEST_SERIAL INT_MAX

#define INC_SERIAL if(sent_serial == HIGHEST_SERIAL) \
   { memset(sentalong, 0, sizeof(sentalong)); sent_serial = 0; } \
   sent_serial++;


/*
 * dead_link
 *
 * somewhere along the lines of sending out, there was an error.
 * we can't close it from the send loop, so mark it as dead
 * and close it from the main loop.
 *
 * if this link is a server, tell routing people.
 */

static int dead_link(aClient *to, char *notice, int sockerr) 
{
    int errtmp = errno;  /* so we don't munge this later */
    
    to->sockerr = sockerr;
    to->flags |= FLAGS_DEADSOCKET;
    /*
     * If because of BUFFERPOOL problem then clean dbuf's now so that
     * notices don't hurt operators below.
     */
    DBufClear(&to->recvQ);
    DBufClear(&to->sendQ);
    /* Ok, if the link we're dropping is a server, send a routing
     * notice..
     */
    if (IsServer(to) && !(to->flags & FLAGS_CLOSING))
    {
	char fbuf[512];

	ircsprintf(fbuf, "from %s: %s", me.name, notice);
	sendto_gnotice(fbuf, get_client_name(to, HIDEME), strerror(errtmp));
	ircsprintf(fbuf, ":%s GNOTICE :%s", me.name, notice);
	sendto_serv_butone(to, fbuf, get_client_name(to, HIDEME),
			   strerror(errtmp));
    }  
 
    return -1;
}

/*
 * send_message 
 * Internal utility which delivers one message buffer to the 
 * socket. Takes care of the error handling and buffering, ifneeded.
 */
static int send_message(aClient *to, char *msg, int len) 
{
    static int  SQinK;
    
#ifdef DUMP_DEBUG
    fprintf(dumpfp, "-> %s: %s\n", (to->name ? to->name : "*"), msg);
#endif

    if (to->from)
	to = to->from;   /* shouldn't be necessary */

    if(IsServer(to) || IsNegoServer(to))
    {
	if(len>510) 
        {
	    msg[511]='\n';
	    msg[512]='\0';
	    len=512;
	}
	else 
        {
	    msg[len] = '\n';
	    msg[len+1] = '\0';
	    len++;
	}   
    }
    else
    {
	if(len>509) 
        {
	    msg[510]='\r';
	    msg[511]='\n';
	    msg[512]='\0';
	    len=512;
	}
	else {
	    msg[len] = '\r';
	    msg[len+1] = '\n';
	    msg[len+2] = '\0';
	    len+=2;
	}   
    }
   
    if (IsMe(to)) 
    {
	sendto_ops("Trying to send to myself! [%s]", msg);
	return 0;
    }
   
    if (IsDead(to))
	return 0;

    if (DBufLength(&to->sendQ) > to->sendqlen) 
    {
	/* this would be a duplicate notice, but it contains some useful 
	 * information thatwould be spamming the rest of the network.
	 * Kept in. - lucas
	 */
	if (IsServer(to)) 
	    sendto_ops("Max SendQ limit exceeded for %s: %d > %d",
		       get_client_name(to, HIDEME), DBufLength(&to->sendQ),
		       get_sendq(to));
	to->flags |= FLAGS_SENDQEX;
	return dead_link(to, "Max Sendq exceeded for %s, closing link", 0);
    }
    
    if(ZipOut(to))
    {
	int ldata = (to->flags & FLAGS_BURST);

	msg = zip_output(to->serv->zip_out, msg, &len, 0, &ldata);
	if(len == -1)
	{
	    sendto_realops("Zipout error for %s: (%d) %s\n", to->name, ldata,
			   msg);
	    return dead_link(to, "Zip output error for %s", IRCERR_ZIP);
	}
	
	if(len == 0)
	    return 0;
    }

#ifdef HAVE_ENCRYPTION_ON
    if(IsRC4OUT(to))
    {
	/* don't destroy the data in 'msg' */
	rc4_process_stream_to_buf(to->serv->rc4_out, msg, rc4buf, len);
	msg = rc4buf;
    }
#endif

    if (dbuf_put(&to->sendQ, msg, len) < 0)
	return dead_link(to, "Buffer allocation error for %s, closing link",
			 IRCERR_BUFALLOC);
    /*
     * Update statistics. The following is slightly incorrect
     * because it counts messages even if queued, but bytes only
     * really sent. Queued bytes get updated in SendQueued.
     */
    to->sendM += 1;
    me.sendM += 1;
    if (to->acpt != &me)
	to->acpt->sendM += 1;
    /*
     * This little bit is to stop the sendQ from growing too large
     * when there is no need for it to. Thus we call send_queued()
     * every time 2k has been added to the queue since the last
     * non-fatal write. Also stops us from deliberately building a
     * large sendQ and then trying to flood that link with data
     * (possible during the net relinking done by servers with a large
     * load).
     */
    /*
     * Well, let's try every 4k for clients, and immediately for servers
     * -Taner
     */

#ifdef ALWAYS_SEND_DURING_SPLIT
    if (currently_processing_netsplit && !(to->flags & FLAGS_BLOCKED))
    {
	send_queued(to);
	return 0;
    }
#endif

    SQinK = (DBufLength(&to->sendQ) >> 10);
    if (IsServer(to)) 
    {
	if (SQinK > to->lastsq)
	    send_queued(to);
    }
    else 
    {
	if (SQinK > (to->lastsq + 4))
	    send_queued(to);
    }
    return 0;
}


/*
 * send_queued 
 * This function is called from the main select-loop (or whatever) 
 * when there is a chance the some output would be possible. This 
 * attempts to empty the send queue as far as possible...
 */
int send_queued(aClient *to)
{
    char       *msg;
    int         len, rlen;
    int more_data = 0; /* the hybrid approach.. */
	
    /*
     * Once socket is marked dead, we cannot start writing to it,
     * even if the error is removed...
     */
    if (IsDead(to)) 
    {
	/*
	 * Actually, we should *NEVER* get here--something is not
	 * working correct if send_queued is called for a dead
	 * socket... --msa
	 */
	return -1;
    }

    if(ZipOut(to) && zip_is_data_out(to->serv->zip_out))
    {
	if(DBufLength(&to->sendQ))
	    more_data = 1;
	else
	{
	    int ldata = (to->flags & FLAGS_BURST);

	    msg = zip_output(to->serv->zip_out, NULL, &len, 1, &ldata);
	    if(len == -1)
	    {
		sendto_realops("Zipout error for %s: (%d) %s\n", to->name,
			       ldata, msg);
		return dead_link(to, "Zip output error for %s", IRCERR_ZIP);
	    }

#ifdef HAVE_ENCRYPTION_ON
	    if(IsRC4OUT(to))
		rc4_process_stream(to->serv->rc4_out, msg, len);
#endif
	    /* silently stick this on the sendq... */
	    if (!dbuf_put(&to->sendQ, msg, len))
		return dead_link(to, "Buffer allocation error for %s",
				 IRCERR_BUFALLOC);
	}
    }
   
    while (DBufLength(&to->sendQ) > 0) 
    {
	msg = dbuf_map(&to->sendQ, &len);
	/* Returns always len > 0 */
	if ((rlen = deliver_it(to, msg, len)) < 0)
	    return dead_link(to, "Write error to %s, closing link (%s)",
			     errno);
	(void) dbuf_delete(&to->sendQ, rlen);
	to->lastsq = (DBufLength(&to->sendQ) >> 10);
	if (rlen < len)
	    /* ..or should I continue until rlen==0? */
	    /* no... rlen==0 means the send returned EWOULDBLOCK... */
	    break;

	if(more_data && DBufLength(&to->sendQ) == 0)
	{
	    int ldata = (to->flags & FLAGS_BURST);
	    
	    more_data = 0;
	    
	    msg = zip_output(to->serv->zip_out, NULL, &len, 1, &ldata);
	    if(len == -1)
	    {
		sendto_realops("Zipout error for %s: (%d) %s\n", to->name,
			       ldata, msg);
		return dead_link(to, "Zip output error for %s", IRCERR_ZIP);
	    }
	    
#ifdef HAVE_ENCRYPTION_ON
	    if(IsRC4OUT(to))
		rc4_process_stream(to->serv->rc4_out, msg, len);
#endif
	    /* silently stick this on the sendq... */
	    if (!dbuf_put(&to->sendQ, msg, len))
		return dead_link(to, "Buffer allocation error for %s",
				 IRCERR_BUFALLOC);        
	}
    }
    
    if ((to->flags & FLAGS_SOBSENT) && IsBurst(to) &&
	DBufLength(&to->sendQ) < 20480) 
    {
	if (!(to->flags & FLAGS_BURST))
	{
	    to->flags &= (~FLAGS_SOBSENT);
	    sendto_one(to, "BURST %d", DBufLength(&to->sendQ));
	    if (!(to->flags & FLAGS_EOBRECV)) /* hey we're the last to synch */
	    { 
#ifdef HTM_LOCK_ON_NETBURST
		HTMLOCK = NO;
#endif
	    }
	}
    }
    return (IsDead(to)) ? -1 : 0;
}

/* send message to single client */
void sendto_one(aClient *to, char *pattern, ...) 
{
    va_list vl;
    int len;		/* used for the length of the current message */
    
    va_start(vl, pattern);
    len = ircvsprintf(sendbuf, pattern, vl);
   
    if (to->from)
	to = to->from;
    if (IsMe(to)) 
    {
	sendto_ops("Trying to send [%s] to myself!", sendbuf);
	return;
    }
    send_message(to, sendbuf, len);
    va_end(vl);
}

void vsendto_one(aClient *to, char *pattern, va_list vl) 
{
    int len;		/* used for the length of the current message */
   
    len = ircvsprintf(sendbuf, pattern, vl);
   
    if (to->from)
	to = to->from;
    if (IsMe(to) && to->fd >= 0) 
    {
	sendto_ops("Trying to send [%s] to myself!", sendbuf);
	return;
    }
    send_message(to, sendbuf, len);
}

/* prefix_buffer
 *
 * take varargs and dump prefixed message into a buffer
 * remote: 1 if client is remote, 0 if local
 * from: the client sending the message
 * prefix: the prefix as specified (parv[0] usually)
 * buffer: the buffer to dump this into (NO BOUNDS CHECKING!)
 * pattern: varargs pattern
 * vl: varargs variable list with one arg taken already
 */
static inline int prefix_buffer(int remote, aClient *from, char *prefix,
				char *buffer, char *pattern, va_list vl)
{
    char *p;      /* temp pointer */
    int msglen;   /* the length of the message we end up with */
    int sidx = 1; /* start at offset 1 */

    *buffer = ':';

    if(!remote && IsPerson(from))
    {
	int flag = 0;
	anUser *user = from->user;

	for(p = from->name; *p; p++)
	    buffer[sidx++] = *p;

	if (user)
	{
	    if (*user->username) 
	    {
		buffer[sidx++] = '!';
		for(p = user->username; *p; p++)
		    buffer[sidx++] = *p;
	    }
	    if (*user->host && !MyConnect(from)) 
	    {
		buffer[sidx++] = '@';
		for(p = user->host; *p; p++)
		    buffer[sidx++] = *p;
		flag = 1;
	    }
	}
   
	if (!flag && MyConnect(from) && *user->host) 
	{
	    buffer[sidx++] = '@';
	    for(p = from->sockhost; *p; p++)
		buffer[sidx++] = *p;
	}
    }
    else
    {
	for(p = prefix; *p; p++)
	    buffer[sidx++] = *p;
    }

    msglen = ircvsprintf(&buffer[sidx], pattern + 3, vl);
    msglen += sidx;

    return msglen;
}

static inline int check_fake_direction(aClient *from, aClient *to)
{
    if (!MyClient(from) && IsPerson(to) && (to->from == from->from)) 
    {
	if (IsServer(from)) 
	{
	    sendto_ops("Message to %s[%s] dropped from %s (Fake Direction)",
		       to->name, to->from->name, from->name);
	    return -1;
	}

	sendto_ops("Ghosted: %s[%s@%s] from %s[%s@%s] (%s)", to->name,
		   to->user->username, to->user->host, from->name,
		   from->user->username, from->user->host, to->from->name);
	sendto_serv_butone(NULL, ":%s KILL %s :%s (%s[%s@%s] Ghosted %s)",
			   me.name, to->name, me.name, to->name,
			   to->user->username, to->user->host, to->from->name);
	
	to->flags |= FLAGS_KILLED;
	exit_client(NULL, to, &me, "Ghosted client");

	if (IsPerson(from))
	    sendto_one(from, err_str(ERR_GHOSTEDCLIENT), me.name, from->name,
		       to->name, to->user->username, to->user->host, to->from);
	return -1;
    }

    return 0;
}


void sendto_channel_butone(aClient *one, aClient *from, aChannel *chptr,
			   char *pattern, ...) 
{
    chanMember *cm;
    aClient *acptr;
    int i;
    int didlocal = 0, didremote = 0;
    va_list vl;
    char *pfix;
   
    va_start(vl, pattern);

    pfix = va_arg(vl, char *);

    INC_SERIAL
    for (cm = chptr->members; cm; cm = cm->next) 
    {
	acptr = cm->cptr;
	if (acptr->from == one)
	    continue; /* ...was the one I should skip */
	i = acptr->from->fd;
	if (MyClient(acptr)) 
	{
	    if(!didlocal)
		didlocal = prefix_buffer(0, from, pfix, sendbuf, pattern, vl);
	    
	    if(check_fake_direction(from, acptr))
		continue;
	    
	    send_message(acptr, sendbuf, didlocal);
	    sentalong[i] = sent_serial;
	}
	else 
	{
	    /*
	     * Now check whether a message has been sent to this remote
	     * link already
	     */
	    if(!didremote)
		didremote = prefix_buffer(1, from, pfix, remotebuf,
					  pattern, vl);
	    
	    if(check_fake_direction(from, acptr))
		continue;
	    
	    if (sentalong[i] != sent_serial) 
	    {
		send_message(acptr, remotebuf, didremote);
		sentalong[i] = sent_serial;
	    }
	}
    }
    
    va_end(vl);
    return;
}

/*
 * sendto_server_butone
 * 
 * Send a message to all connected servers except the client 'one'.
 */
void sendto_serv_butone(aClient *one, char *pattern, ...) 
{
    int i;
    aClient *cptr;
    int j, k = 0;
    fdlist send_fdlist;
    va_list vl;
	
    va_start(vl, pattern);
    for (i = serv_fdlist.entry[j = 1];
	 j <= serv_fdlist.last_entry; i = serv_fdlist.entry[++j]) 
    {
	if (!(cptr = local[i]) || (one && cptr == one->from))
	    continue;
	send_fdlist.entry[++k] = i;
    }
    send_fdlist.last_entry = k;
    if (k)
	vsendto_fdlist(&send_fdlist, pattern, vl);
    va_end(vl);
    return;
}

/*
 * sendto_noquit_servs_butone
 * 
 * Send a message to all noquit servs if noquit = 1,
 * or all non-noquit servs if noquit = 0
 * we omit "one", too.
 */
void sendto_noquit_servs_butone(int noquit, aClient *one, char *pattern, ...) 
{
    int i;
    aClient *cptr;
    int j, k = 0;
    fdlist send_fdlist;
    va_list vl;
	
    va_start(vl, pattern);
    for (i = serv_fdlist.entry[j = 1];
	 j <= serv_fdlist.last_entry; i = serv_fdlist.entry[++j]) 
    {
	if (!(cptr = local[i]) || 
	    (noquit && !IsNoQuit(cptr)) || 
	    (!noquit && IsNoQuit(cptr)) || 
            one == cptr)
	    continue;

	send_fdlist.entry[++k] = i;
    }
    send_fdlist.last_entry = k;
    if (k)
	vsendto_fdlist(&send_fdlist, pattern, vl);
    va_end(vl);
    return;
}

/*
 * sendto_nickip_servs_butone
 * 
 * Send a message to all nickip servs if nickip = 1,
 * or all non-nickip servs if nickip = 0
 * we omit "one", too.
 * Lame reuse of code because the current system blows.
 */
void sendto_nickip_servs_butone(int nickip, aClient *one, char *pattern, ...) 
{
    int i;
    aClient *cptr;
    int j, k = 0;
    fdlist send_fdlist;
    va_list vl;
	
    va_start(vl, pattern);
    for (i = serv_fdlist.entry[j = 1];
	 j <= serv_fdlist.last_entry; i = serv_fdlist.entry[++j]) 
    {
	if (!(cptr = local[i]) || 
	    (nickip && !IsNICKIP(cptr)) || 
	    (!nickip && IsNICKIP(cptr)) || 
            one == cptr)
	    continue;

	send_fdlist.entry[++k] = i;
    }
    send_fdlist.last_entry = k;
    if (k)
	vsendto_fdlist(&send_fdlist, pattern, vl);
    va_end(vl);
    return;
}

/*
 * sendto_common_channels()
 * 
 * Sends a message to all people (inclusing user) on local server who are
 * in same channel with user.
 */
void sendto_common_channels(aClient *from, char *pattern, ...)
{
    Link *channels;
    chanMember *users;
    aClient *cptr;
    va_list vl;
    char *pfix;
    int msglen = 0;

    va_start(vl, pattern);

    pfix = va_arg(vl, char *);

    INC_SERIAL

    if(from->fd >= 0)
	sentalong[from->fd] = sent_serial;
    
    if (from->user)
    {
	for (channels = from->user->channel; channels;
	     channels = channels->next)
	{
	    for (users = channels->value.chptr->members; users;
		 users = users->next) 
	    {
		cptr = users->cptr;
		
		if (!MyConnect(cptr) || sentalong[cptr->fd] == sent_serial)
		    continue;
		
		sentalong[cptr->fd] = sent_serial;
		if(!msglen)
		    msglen = prefix_buffer(0, from, pfix, sendbuf,
					   pattern, vl);
		if(check_fake_direction(from, cptr))
		    continue;
		send_message(cptr, sendbuf, msglen);
	    }
	}
    }
    
    if(MyConnect(from))
    {
	if(!msglen)
	    msglen = prefix_buffer(0, from, pfix, sendbuf, pattern, vl);
	send_message(from, sendbuf, msglen);
    }

    va_end(vl);
    return;
}

/*
 * send_quit_to_common_channels()
 * 
 * Sends a message to all people (inclusing user) on local server who are
 * in same channel with user if the user can send to this channel.
 */
void send_quit_to_common_channels(aClient *from, char *reason)
{
    Link *channels;
    chanMember *users;
    aClient *cptr;
    int msglen;
    INC_SERIAL
    
    msglen=sprintf(sendbuf,":%s!%s@%s QUIT :%s", from->name,
		   from->user->username,from->user->host, reason);	
    
    if(from->fd >= 0)
	sentalong[from->fd] = sent_serial;    
    for (channels = from->user->channel; channels; 
	 channels = channels->next)
    {
	if (!can_send(from, channels->value.chptr)) 
	{
	    for (users = channels->value.chptr->members; 
		 users; users = users->next) 
	    {
		cptr = users->cptr;
		
		if (!MyConnect(cptr) || sentalong[cptr->fd] == sent_serial)
		    continue;
		
		sentalong[cptr->fd] = sent_serial;
		if(check_fake_direction(from, cptr))
		    continue;
		send_message(cptr, sendbuf, msglen);
	    }
	}
    }
    return;
}

/*
 * send_part_to_common_channels()
 * 
 * Sends a message to all people (inclusing user) on local server who are
 * in same channel with user if the user cannot send to the channel.
 */
void send_part_to_common_channels(aClient *from)
{
    Link *channels;
    chanMember *users;
    aClient *cptr;
    int msglen = 0;
    
    INC_SERIAL

    if(from->fd >= 0)
	sentalong[from->fd] = sent_serial;
    
    for (channels = from->user->channel; channels;
	 channels = channels->next)
    {
	if (can_send(from, channels->value.chptr)) 
	{
	    msglen=sprintf(sendbuf,":%s!%s@%s PART %s",
			   from->name,from->user->username,from->user->host,
			   channels->value.chptr->chname);
	    for (users = channels->value.chptr->members;
		 users; users = users->next) 
	    {
		cptr = users->cptr;
		
		if (!MyConnect(cptr) || sentalong[cptr->fd] == sent_serial)
		    continue;
		
		sentalong[cptr->fd] = sent_serial;
		if(check_fake_direction(from, cptr))
		    continue;
		send_message(cptr, sendbuf, msglen);
	    }
	}
    }
    return;
}

#ifdef FLUD
void sendto_channel_butlocal(aClient *one, aClient *from, aChannel *chptr,
			     char *pattern, ...)
{
    chanMember *cm;
    aClient *acptr;
    int i;
    va_list vl;
	  
    va_start(vl, pattern);

    INC_SERIAL
    
    for (cm = chptr->members; cm; cm = cm->next) 
    {
	acptr = cm->cptr;
	if (acptr->from == one)
	    continue;		/* ...was the one I should skip */
	i = acptr->from->fd;
	if (!MyFludConnect(acptr)) 
	{
	    /*
	     * Now check whether a message has been sent to this remote
	     * link already
	     */
	    if (sentalong[i] != sent_serial) 
	    {
		vsendto_prefix_one(acptr, from, pattern, vl);
		sentalong[i] = sent_serial;
	    }
	}
    }
    va_end(vl);
    return;
}
#endif /* FLUD */

/*
 * sendto_channel_butserv
 * 
 * Send a message to all members of a channel that are connected to this
 * server.
 */
void sendto_channel_butserv(aChannel *chptr, aClient *from, char *pattern, ...)
{
    chanMember  *cm;
    aClient *acptr;
    va_list vl;
    int didlocal = 0;
    char *pfix;

    va_start(vl, pattern);
    
    pfix = va_arg(vl, char *);

    for (cm = chptr->members; cm; cm = cm->next)
    {
	if (MyConnect(acptr = cm->cptr))
	{
	    if(!didlocal)
		didlocal = prefix_buffer(0, from, pfix, sendbuf, pattern, vl);
	    
	    if(check_fake_direction(from, acptr))
		continue;

	    send_message(acptr, sendbuf, didlocal);

	    /* vsendto_prefix_one(acptr, from, pattern, vl); */
	}
    }
    va_end(vl);
    return;
}

/*
 * sendto_ssjoin_servs
 * 
 * send to all servers with ssjoin capability (or not)
 * 
 */
void sendto_ssjoin_servs(int ssjoin, aChannel *chptr, aClient *from, 
			 char *pattern, ...)
{
    int j, k = 0;
    fdlist      send_fdlist;
    int     i;
    aClient *cptr;
    va_list vl;
	
    if (chptr) 
    {
	if (*chptr->chname == '&')
	    return;
    }
    va_start(vl, pattern);
    for (i = serv_fdlist.entry[j = 1]; j <= serv_fdlist.last_entry;
	 i = serv_fdlist.entry[++j]) 
    {
	if (!(cptr = local[i]) || 
	    (cptr == from) ||
	    (ssjoin && !IsSSJoin(cptr)) ||
	    (!ssjoin && IsSSJoin(cptr)))
	    continue;
	
	send_fdlist.entry[++k] = i;
    }
    send_fdlist.last_entry = k;
    if (k)
	vsendto_fdlist(&send_fdlist, pattern, vl);
    va_end(vl);
    return;
}


/*
 * * send a msg to all ppl on servers/hosts that match a specified mask *
 * (used for enhanced PRIVMSGs) *
 * 
 * addition -- Armin, 8jun90 (gruner@informatik.tu-muenchen.de)
 */
static int match_it(aClient *one, char *mask, int what)
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
void sendto_match_servs(aChannel *chptr, aClient *from, char *pattern, ...)
{
    int j, k = 0;
    fdlist      send_fdlist;
    int     i;
    aClient *cptr;
    va_list vl;
    if (chptr) 
    {
	if (*chptr->chname == '&')
	    return;
    }
    va_start(vl, pattern);
    for (i = serv_fdlist.entry[j = 1]; j <= serv_fdlist.last_entry;
	 i = serv_fdlist.entry[++j]) 
    {
	if (!(cptr = local[i]))
	    continue;
	if (cptr == from)
	    continue;
	send_fdlist.entry[++k] = i;
    }
    send_fdlist.last_entry = k;
    if (k)
	vsendto_fdlist(&send_fdlist, pattern, vl);
    va_end(vl);
    return;
}

/*
 * sendto_match_butone
 * 
 * Send to all clients which match the mask in a way defined on 'what';
 * either by user hostname or user servername.
 */
void sendto_match_butone(aClient *one, aClient *from, char *mask, int what, 
			 char *pattern, ...)
{
    int     i;
    aClient *cptr, *acptr;
    char cansendlocal, cansendglobal;
    va_list vl;
	
    va_start(vl, pattern);
    if (MyConnect(from)) 
    {
	cansendlocal = (OPCanLNotice(from)) ? 1 : 0;
	cansendglobal = (OPCanGNotice(from)) ? 1 : 0;
    } 
    else 
	cansendlocal = cansendglobal = 1;
    for (i = 0; i <= highest_fd; i++) 
    {
	if (!(cptr = local[i]))
	    continue;		/* that clients are not mine */
	if (cptr == one)		/* must skip the origin !! */
	    continue;
	if (IsServer(cptr)) 
	{
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
	    /* ... but only if there *IS* a matching person */
	}
	/* my client, does he match ? */
	else if (!cansendlocal || !(IsRegisteredUser(cptr) &&
				    match_it(cptr, mask, what)))
	    continue;
	vsendto_prefix_one(cptr, from, pattern, vl);
    }
    va_end(vl);
    return;
}

/*
 * sendto_all_butone.
 * 
 * Send a message to all connections except 'one'. The basic wall type
 * message generator.
 */
void sendto_all_butone(aClient *one, aClient *from, char *pattern, ...)
{
    int     i;
    aClient *cptr;
    va_list vl;
	
    va_start(vl, pattern);
    for (i = 0; i <= highest_fd; i++)
	if ((cptr = local[i]) && !IsMe(cptr) && one != cptr)
	    vsendto_prefix_one(cptr, from, pattern, vl);
    va_end(vl);
    return;
}

/*
 * sendto_ops_lev
 * 
 * Send to *local* ops only at a certain level... 0 = normal +s 1 = client
 * connect/disconnect   (+c) [IRCOPS ONLY] 2 = bot rejection
 * (+r) 3 = server kills                      (+k)
 */
void sendto_ops_lev(int lev, char *pattern, ...)
{
    aClient *cptr;
    int     i;
    char        nbuf[1024];
    va_list vl;
	
    va_start(vl,pattern);
    for (i = 0; i <= highest_fd; i++)
	if ((cptr = local[i]) && !IsServer(cptr) && !IsMe(cptr)) 
	{
	    switch (lev) 
	    {
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
	    case DCCSEND_LEV:
		if (!SendDCCNotice(cptr) || !IsAnOper(cptr))
		    continue;
		break;
	    case FLOOD_LEV:
		if (!SendFloodNotice(cptr) || !IsAnOper(cptr))
		    continue;
		break;
	    case SPAM_LEV:
		if (!SendSpamNotice(cptr) || !IsAnOper(cptr))
		    continue;
		break;
	    case DEBUG_LEV:
		if (!SendDebugNotice(cptr) || !IsAnOper(cptr))
		    continue;
		break;
			  
	    default:		/* this is stupid, but oh well */
		if (!SendServNotice(cptr))
		    continue;
	    }
	    (void) ircsprintf(nbuf, ":%s NOTICE %s :*** Notice -- ",
			      me.name, cptr->name);
	    (void) strncat(nbuf, pattern,
			   sizeof(nbuf) - strlen(nbuf));
	    vsendto_one(cptr, nbuf, vl);
	}
    va_end(vl);
    return;
}				

/*
 * sendto_ops
 * 
 * Send to *local* ops only.
 */
void sendto_ops(char *pattern, ...)
{
    aClient *cptr;
    int     i;
    char        nbuf[1024];
    va_list vl;
	
    va_start(vl, pattern);
    for (i = 0; i <= highest_fd; i++)
	if ((cptr = local[i]) && !IsServer(cptr) && !IsMe(cptr) &&
	    IsAnOper(cptr) && SendServNotice(cptr)) 
	{
	    (void) ircsprintf(nbuf, ":%s NOTICE %s :*** Notice -- ",
			      me.name, cptr->name);
	    (void) strncat(nbuf, pattern,
			   sizeof(nbuf) - strlen(nbuf));
	    vsendto_one(cptr, nbuf, vl);
	}
    va_end(vl);
    return;
}

/*
 * sendto_ops_butone 
 * Send message to all operators. 
 * one - client not to send message to 
 * from- client which message is from *NEVER* NULL!!
 */
void sendto_ops_butone(aClient *one, aClient *from, char *pattern, ...)
{
    int     i;
    aClient *cptr;
    va_list vl;
	   
    va_start(vl, pattern);

    INC_SERIAL

    for (cptr = client; cptr; cptr = cptr->next)
    {
	if (!SendWallops(cptr))
	    continue;
	/*
	 * we want wallops if (MyClient(cptr) && !(IsServer(from) ||
	 * IsMe(from))) continue;
	 */
	i = cptr->from->fd;	/* find connection oper is on */
	if (sentalong[i] == sent_serial) /* sent message along it already ? */
	    continue;
	if (cptr->from == one)
	    continue;		/* ...was the one I should skip */
	sentalong[i] = sent_serial;
	vsendto_prefix_one(cptr->from, from, pattern, vl);
    }
    va_end(vl);
    return;
}

/*
 * * sendto_wallops_butone *      Send message to all operators. * one
 * - client not to send message to * from- client which message is from
 * *NEVER* NULL!!
 */
void sendto_wallops_butone(aClient *one, aClient *from, char *pattern, ...)
{
    int     i;
    aClient *cptr;
    va_list vl;
	
    va_start(vl, pattern);
    for(i=0;i<=highest_fd;i++)
    {
	if((cptr=local[i])!=NULL)
	{
	    if(!(IsRegistered(cptr) && (SendWallops(cptr) ||
					IsServer(cptr))) || cptr==one)
		continue;
	    vsendto_prefix_one(cptr, from, pattern, vl);
	}
    }
    va_end(vl);
    return;
}

void send_globops(char *pattern, ...)
{
    aClient    *cptr;
    int         i;
    char        nbuf[1024];
    va_list vl;
	
    va_start(vl, pattern);
    for (i = 0; i <= highest_fd; i++)
	if ((cptr = local[i]) && !IsServer(cptr) && IsAnOper(cptr) &&
	    !IsMe(cptr) && SendGlobops(cptr)) 
	{
	    (void) ircsprintf(nbuf, ":%s NOTICE %s :*** Global -- ",
			      me.name, cptr->name);
	    (void) strncat(nbuf, pattern,
			   sizeof(nbuf) - strlen(nbuf));
	    vsendto_one(cptr, nbuf, vl);
	}
    va_end(vl);
    return;
}

void send_chatops(char *pattern, ...)
{
    aClient    *cptr;
    int         i;
    char        nbuf[1024];
    va_list vl;
    
    va_start(vl, pattern);
    for (i = 0; i <= highest_fd; i++)
	if ((cptr = local[i]) && !IsServer(cptr) && IsAnOper(cptr) &&
	    !IsMe(cptr) && SendChatops(cptr)) 
	{
	    (void) ircsprintf(nbuf, ":%s NOTICE %s :*** ChatOps -- ",
			      me.name, cptr->name);
	    (void) strncat(nbuf, pattern,
			   sizeof(nbuf) - strlen(nbuf));
	    vsendto_one(cptr, nbuf, vl);
	}
    va_end(vl);
    return;
}

/*
 * to - destination client from - client which message is from
 * 
 * NOTE: NEITHER OF THESE SHOULD *EVER* BE NULL!! -avalon
 */
void sendto_prefix_one(aClient *to, aClient *from, char *pattern, ...)
{
    static char sender[HOSTLEN + NICKLEN + USERLEN + 5];
    static char temp[1024];
    anUser *user;
    char *idx;
    char *par;
    int flag = 0, sidx = 0;
    va_list vl, vl2;

    va_start(vl, pattern);
    vl2 = vl;

    par = va_arg(vl, char *);
    /*
     * Optimize by checking if (from && to) before everything 
     * uhh, there's _always_ going to be a to!
     */
    if (from) 
    {
	if (!MyClient(from) && IsPerson(to) && (to->from == from->from)) 
	{
	    if (IsServer(from)) 
	    {
		ircvsprintf(temp, pattern, vl2);
		sendto_ops("Send message (%s) to %s[%s] dropped from "
			   "%s(Fake Dir)", temp, to->name, to->from->name,
			   from->name);
		va_end(vl);
		return;
	    }
	    
	    sendto_ops("Ghosted: %s[%s@%s] from %s[%s@%s] (%s)", to->name,
		       to->user->username, to->user->host, from->name,
		       from->user->username, from->user->host, to->from->name);
	    sendto_serv_butone(NULL, ":%s KILL %s :%s (%s[%s@%s] Ghosted %s)",
			       me.name, to->name, me.name, to->name,
			       to->user->username, to->user->host,
			       to->from->name);

	    to->flags |= FLAGS_KILLED;
	    exit_client(NULL, to, &me, "Ghosted client");
	    if (IsPerson(from))
		sendto_one(from, err_str(ERR_GHOSTEDCLIENT), me.name,
			   from->name, to->name, to->user->username,
			   to->user->host, to->from);
	    va_end(vl);
	    return;
	}

	if (MyClient(to) && IsPerson(from) && !mycmp(par, from->name)) 
	{
	    user = from->user;

	    for(idx = from->name; *idx; idx++)
		sender[sidx++] = *idx;

	    if (user)
	    {
		if (*user->username) 
		{
		    sender[sidx++] = '!';
		    for(idx = user->username; *idx; idx++)
			sender[sidx++] = *idx;
		}
		if (*user->host && !MyConnect(from)) 
		{
		    sender[sidx++] = '@';
		    for(idx = user->host; *idx; idx++)
			sender[sidx++] = *idx;
		    flag = 1;
		}
	    }

	    /*
	     * flag is used instead of index(sender, '@') for speed and
	     * also since username/nick may have had a '@' in them.
	     * -avalon
	     */

	    if (!flag && MyConnect(from) && *user->host) 
	    {
		sender[sidx++] = '@';
		for(idx = from->sockhost; *idx; idx++)
		    sender[sidx++] = *idx;
	    }

	    sender[sidx] = '\0';
	    par = sender;

	}
    }

    temp[0] = ':';
    sidx = 1;

    /*
     * okay, we more or less know that our sendto_prefix crap is going 
     * to be :%s <blah>, so it's easy to fix these lame problems...joy 
     */

    for(idx = par; *idx; idx++)
	temp[sidx++] = *idx;
    for(idx = (pattern + 3); *idx; idx++)
	temp[sidx++] = *idx;

    temp[sidx] = '\0'; 

    vsendto_one(to, temp, vl);
    va_end(vl);
}

/* this is an incredibly expensive function. 
 * removed all strcat() calls. - lucas */
void vsendto_prefix_one(aClient *to, aClient *from, char *pattern, va_list vl)
{
    static char sender[HOSTLEN + NICKLEN + USERLEN + 5];
    static char temp[1024];
    anUser *user;
    char *idx;
    char *par;
    int flag = 0, sidx = 0;
    va_list vl2 = vl;
	
    par = va_arg(vl2, char *);
    /*
     * Optimize by checking if (from && to) before everything 
     * uhh, there's _always_ going to be a to!
     */
    if (from) 
    {
	if (!MyClient(from) && IsPerson(to) && (to->from == from->from)) 
	{
	    if (IsServer(from)) 
	    {
		ircvsprintf(temp, pattern, vl);
		sendto_ops("Send message (%s) to %s[%s] dropped from "
			   "%s(Fake Dir)", temp,
			   to->name, to->from->name, from->name);
		return;
	    }

	    sendto_ops("Ghosted: %s[%s@%s] from %s[%s@%s] (%s)", to->name,
		       to->user->username, to->user->host, from->name,
		       from->user->username, from->user->host, to->from->name);
	    sendto_serv_butone(NULL, ":%s KILL %s :%s (%s[%s@%s] Ghosted %s)",
			       me.name, to->name, me.name, to->name,
			       to->user->username, to->user->host,
			       to->from->name);

	    to->flags |= FLAGS_KILLED;
	    exit_client(NULL, to, &me, "Ghosted client");
	    if (IsPerson(from))
		sendto_one(from, err_str(ERR_GHOSTEDCLIENT), me.name,
			   from->name, to->name, to->user->username,
			   to->user->host, to->from);
	    return;
	}

	if (MyClient(to) && IsPerson(from) && !mycmp(par, from->name)) 
	{
	    user = from->user;

	    for(idx = from->name; *idx; idx++)
		sender[sidx++] = *idx;

	    if (user)
	    {
		if (*user->username) 
		{
		    sender[sidx++] = '!';
		    for(idx = user->username; *idx; idx++)
			sender[sidx++] = *idx;
		}
		if (*user->host && !MyConnect(from)) 
		{
		    sender[sidx++] = '@';
		    for(idx = user->host; *idx; idx++)
			sender[sidx++] = *idx;
		    flag = 1;
		}
	    }

	    /*
	     * flag is used instead of index(sender, '@') for speed and
	     * also since username/nick may have had a '@' in them.
	     * -avalon
	     */

	    if (!flag && MyConnect(from) && *user->host) 
	    {
		sender[sidx++] = '@';
		for(idx = from->sockhost; *idx; idx++)
		    sender[sidx++] = *idx;
	    }

	    sender[sidx] = '\0';
	    par = sender;

	}
    }

    temp[0] = ':';
    sidx = 1;

    /* 
     * okay, we more or less know that our sendto_prefix crap is 
     * going to be :%s <blah>, so it's easy to fix these lame problems...joy
     */

    for(idx = par; *idx; idx++)
	temp[sidx++] = *idx;
    for(idx = (pattern + 3); *idx; idx++)
	temp[sidx++] = *idx;

    temp[sidx] = '\0'; 

    vsendto_one(to, temp, vl2);
}

void sendto_fdlist(fdlist *listp, char *pattern, ...)
{
    int len, j, fd;
    va_list vl;
    
    va_start(vl, pattern);
    len = ircvsprintf(sendbuf, pattern, vl);
	
    for (fd = listp->entry[j = 1]; j <= listp->last_entry;
	 fd = listp->entry[++j])
	send_message(local[fd], sendbuf, len);
    va_end(vl);
}

void vsendto_fdlist(fdlist *listp, char *pattern, va_list vl)
{
    int len, j, fd;
    len = ircvsprintf(sendbuf, pattern, vl);
	
    for (fd = listp->entry[j = 1]; j <= listp->last_entry;
	 fd = listp->entry[++j])
	send_message(local[fd], sendbuf, len);
}

/*
 * sendto_realops
 * 
 * Send to *local* ops only but NOT +s nonopers.
 * If it's to local ops only and not +s nonopers, then SendServNotice is
 * wrong. Changed to IsAnOper. -mjs
 */
void sendto_realops(char *pattern, ...)
{
    aClient *cptr;
    int     i;
    char        nbuf[1024];
    fdlist     *l;
    int         fd;
    va_list vl;
	  
    va_start(vl, pattern);
    l = &oper_fdlist;
    for (fd = l->entry[i = 1]; i <= l->last_entry; fd = l->entry[++i])
    {
	if (!(cptr = local[fd]))
	    continue;
	if (IsAnOper(cptr))
	{
	    (void) ircsprintf(nbuf, ":%s NOTICE %s :*** Notice -- %s",
			      me.name, cptr->name, pattern);
	    vsendto_one(cptr, nbuf, vl);
	}
    }
    va_end(vl);
    return;
}

void vsendto_realops(char *pattern, va_list vl)
{
    aClient *cptr;
    int     i;
    char        nbuf[1024];
    fdlist     *l;
    int         fd;

    l = &oper_fdlist;
    for (fd = l->entry[i = 1]; i <= l->last_entry; fd = l->entry[++i])
    {
	if (!(cptr = local[fd]))
	    continue;
	if (IsAnOper(cptr))
	{
	    (void) ircsprintf(nbuf, ":%s NOTICE %s :*** Notice -- %s",
			      me.name, cptr->name, pattern);
	    vsendto_one(cptr, nbuf, vl);
	}
    }
    return;
}

/*
 * sendto_realops_lev
 * 
 * Send to *local* ops only but NOT +s nonopers at a certain level
 */
void sendto_realops_lev(int lev, char *pattern, ...)
{
    aClient *cptr;
    int     i;
    char        nbuf[1024];
    fdlist     *l;
    int         fd;
    va_list vl;
	
    l = &oper_fdlist;
    va_start(vl, pattern);
    for (fd = l->entry[i = 1]; i <= l->last_entry; fd = l->entry[++i])
    {
	if (!(cptr = local[fd]))
	    continue;
	switch (lev)
	{
	case CCONN_LEV:
	    if (!SendCConnNotice(cptr))
		continue;
	    break;
	case REJ_LEV:
	    if (!SendRejNotice(cptr))
		continue;
	    break;
	case SKILL_LEV:	/* This should not be sent, since this 
			 * can go to normal people 
			 */
	    if (!SendSkillNotice(cptr))
		continue;
	    break;
	case SPY_LEV:
	    if (!SendSpyNotice(cptr))
		continue;
	    break;
	case DCCSEND_LEV:
	    if (!SendDCCNotice(cptr) || !IsAnOper(cptr))
		continue;
	    break;
	case FLOOD_LEV:
	    if (!SendFloodNotice(cptr))
		continue;
	    break;
	case SPAM_LEV:
	    if (!SendSpamNotice(cptr))
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
	vsendto_one(cptr, nbuf, vl);
    }
    va_end(vl);
    return;
}

/*
 * ts_warn
 * Call sendto_ops, with some flood checking (at most 5 warnings 
 * every 5 seconds)
 */

void ts_warn(char * pattern, ...)
{
    static ts_val last = 0;
    static int  warnings = 0;
    ts_val now;
    va_list vl;
	
    va_start(vl, pattern);
    /*
     * if we're running with TS_WARNINGS enabled and someone does
     * something silly like (remotely) connecting a nonTS server,
     * we'll get a ton of warnings, so we make sure we don't send more
     * than 5 every 5 seconds.  -orabidoo
     */
    now = time(NULL);
    if (now - last < 5)
    {
	if (++warnings > 5)
	    return;
    }
    else
    {
	last = now;
	warnings = 0;
    }

    vsendto_realops(pattern, vl);
    va_end(vl);
    return;
}

/*
 * sendto_locops
 */
void sendto_locops(char *pattern, ...)
{
    aClient *cptr;
    int     i;
    char        nbuf[1024];
    fdlist     *l;
    int         fd;
    va_list vl;
	
    va_start(vl, pattern);
    l = &oper_fdlist;
    for (fd = l->entry[i = 1]; i <= l->last_entry; fd = l->entry[++i])
    {
	if (!(cptr = local[fd]))
	    continue;
	if (SendGlobops(cptr))
	{
	    (void) ircsprintf(nbuf, ":%s NOTICE %s :*** LocOps -- ",
			      me.name, cptr->name);
	    (void) strncat(nbuf, pattern,
			   sizeof(nbuf) - strlen(nbuf));
	    vsendto_one(cptr, nbuf, vl);
	}
    }
    va_end(vl);
    return;
}

/* sendto_gnotice - send a routing notice to all local +n users. */
void sendto_gnotice(char *pattern, ...)
{
    aClient *cptr;
    int     i;
    char        nbuf[1024];
    va_list vl;
	
    va_start(vl, pattern);

    for (i = 0; i <= highest_fd; i++)
    {
	if ((cptr = local[i]) && !IsServer(cptr) && !IsMe(cptr) &&
	    SendRnotice(cptr)) {
	    
	    (void) ircsprintf(nbuf, ":%s NOTICE %s :*** Routing -- ",
			      me.name, cptr->name);
	    (void) strncat(nbuf, pattern,
			   sizeof(nbuf) - strlen(nbuf));
	    vsendto_one(cptr, nbuf, vl);
	}
    }
    va_end(vl);
    return;
}

/*
 * sendto_channelops_butone
 *   Send a message to all OPs in channel chptr that
 *   are directly on this server and sends the message
 *   on to the next server if it has any OPs.
 */
void sendto_channelops_butone(aClient *one, aClient *from, aChannel *chptr, 
			      char *pattern, ...)
{
    chanMember   *cm;
    aClient *acptr;
    int     i;
    va_list vl;
	
    va_start(vl, pattern);

    INC_SERIAL
    for (cm = chptr->members; cm; cm = cm->next)
    {
	acptr = cm->cptr;
	if (acptr->from == one ||
	    !(cm->flags & CHFL_CHANOP))
	    continue;
	i = acptr->from->fd;
	if (MyConnect(acptr) && IsRegisteredUser(acptr)) {
	    vsendto_prefix_one(acptr, from, pattern, vl);
	    sentalong[i] = sent_serial;
	}
	else
	{
	    /*
	     * Now check whether a message has been sent to this
	     * remote link already 
	     */
	    if (sentalong[i] != sent_serial)
	    {
		vsendto_prefix_one(acptr, from, pattern, vl);
		
		sentalong[i] = sent_serial;
	    }
	}
    }
    va_end(vl);
    return;
}

/*
 * sendto_channelvoice_butone
 *   Send a message to all voiced users in channel chptr that
 *   are directly on this server and sends the message
 *   on to the next server if it has any voiced users.
 */
void sendto_channelvoice_butone(aClient *one, aClient *from, aChannel *chptr, 
				char *pattern, ...)
{
    chanMember   *cm;
    aClient *acptr;
    int     i;
    va_list vl;
	
    va_start(vl, pattern);

    INC_SERIAL

    for (cm = chptr->members; cm; cm = cm->next)
    {
	acptr = cm->cptr;
	if (acptr->from == one ||
		!(cm->flags & CHFL_VOICE))
	    continue;
	i = acptr->from->fd;
	if (MyConnect(acptr) && IsRegisteredUser(acptr))
	{
	    vsendto_prefix_one(acptr, from, pattern, vl);
	    sentalong[i] = sent_serial;
	}
	else
	{
	    /*
	     * Now check whether a message has been sent to this
	     * remote link already 
	     */
	    if (sentalong[i] != sent_serial)
	    {
		vsendto_prefix_one(acptr, from, pattern, vl);
		sentalong[i] = sent_serial;
	    }
	}
    }
    va_end(vl);
    return;
}

/*
 * sendto_channelvoiceops_butone
 *   Send a message to all OPs or voiced users in channel chptr that
 *   are directly on this server and sends the message
 *   on to the next server if it has any OPs or voiced users.
 */
void sendto_channelvoiceops_butone(aClient *one, aClient *from, aChannel 
				   *chptr, char *pattern, ...)
{
    chanMember   *cm;
    aClient *acptr;
    int     i;
    va_list vl;
	
    va_start(vl, pattern);

    INC_SERIAL

    for (cm = chptr->members; cm; cm = cm->next)
    {
	acptr = cm->cptr;
	if (acptr->from == one || !((cm->flags & CHFL_VOICE) ||
				    (cm->flags & CHFL_CHANOP)))
	    continue;
	i = acptr->from->fd;
	if (MyConnect(acptr) && IsRegisteredUser(acptr)) {
	    vsendto_prefix_one(acptr, from, pattern, vl);
	    sentalong[i] = sent_serial;
	}
	else /* remote link */
	{
	    if (sentalong[i] != sent_serial) 
	    {
		vsendto_prefix_one(acptr, from, pattern, vl);
		sentalong[i] = sent_serial;
	    }
	}
    }
    return;
}

/*******************************************
 * Flushing functions (empty queues)
 *******************************************/

/*
 * flush_connections
 * Empty only buffers for clients without FLAGS_BLOCKED
 * dump_connections 
 * Unintelligently try to empty all buffers.
 */
void flush_connections(int fd) 
{
    int     i;
    aClient *cptr;
    
    if (fd == me.fd) 
    {
	for (i = highest_fd; i >= 0; i--)
	    if ((cptr = local[i]) && !(cptr->flags & FLAGS_BLOCKED) &&
		DBufLength(&cptr->sendQ) > 0)
		send_queued(cptr);
    }
    else if (fd >= 0 && (cptr = local[fd]) &&
	     !(cptr->flags & FLAGS_BLOCKED) && DBufLength(&cptr->sendQ) > 0)
	send_queued(cptr);
}

void dump_connections(int fd) 
{
    int     i;
    aClient *cptr;
    
    if (fd == me.fd) 
    {
	for (i = highest_fd; i >= 0; i--)
	    if ((cptr = local[i]) && DBufLength(&cptr->sendQ) > 0)
		send_queued(cptr);
    }
    else if (fd >= 0 && (cptr = local[fd]) && DBufLength(&cptr->sendQ) > 0)
	send_queued(cptr);
}

/* flush an fdlist intelligently */
void flush_fdlist_connections(fdlist *listp)
{
    int i, fd;
    aClient *cptr;
	
    for (fd = listp->entry[i = 1]; i <= listp->last_entry;
	 fd = listp->entry[++i])
	if ((cptr = local[fd]) && !(cptr->flags & FLAGS_BLOCKED) &&
	    DBufLength(&cptr->sendQ) > 0)
	    send_queued(cptr);
}
