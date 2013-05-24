/************************************************************************
 *   IRC - Internet Relay Chat, src/send.c
 *   Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
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

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include <stdio.h>
#include "numeric.h"
#include "dh.h"
#include "zlink.h"
#include "fds.h"
#include "memcount.h"

/*
 * STOP_SENDING_ON_SHORT_SEND:
 * Treat a short send as a blocked socket
 * Might not always be a good idea, esp. if using something that's
 * Edge triggered (ie, kqueue, epoll, etc)
 */
#undef STOP_SENDING_ON_SHORT_SEND

#ifdef ALWAYS_SEND_DURING_SPLIT
extern int currently_processing_netsplit;
#endif

static char sendbuf[2048];
static char remotebuf[2048];
static char selfbuf[256];
static int  send_message(aClient *, char *, int, void*);

#ifdef HAVE_ENCRYPTION_ON
/*
 * WARNING:
 * Please be aware that if you are using both encryption
 * and ziplinks, rc4buf in send.c MUST be the same size
 * as zipOutBuf in zlink.c!
 */
static char rc4buf[16384];
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
    SBufClear(&to->recvQ);
    SBufClear(&to->sendQ);
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
static int send_message(aClient *to, char *msg, int len, void* sbuf) 
{
    static int  SQinK;
    int flag;
    
#ifdef DUMP_DEBUG
    fprintf(dumpfp, "-> %s: %s\n", (to->name ? to->name : "*"), msg);
#endif

    if (to->from)
        to = to->from;

    flag = (!sbuf || ZipOut(to) || IsRC4OUT(to)) ? 1 : 0;

    if (flag == 1)
    {
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
            else 
            {
                msg[len] = '\r';
                msg[len+1] = '\n';
                msg[len+2] = '\0';
                len+=2;
            }   
        }
    }

    if (IsMe(to)) 
    {
        strncpyzt(selfbuf, msg, sizeof(selfbuf));
        sendto_ops("Trying to send to myself! [%s]", selfbuf);
        return 0;
    }
   
    if (IsDead(to))
        return 0;

    if (to->class && (SBufLength(&to->sendQ) > to->class->maxsendq))
    {
        /* this would be a duplicate notice, but it contains some useful 
         * information thatwould be spamming the rest of the network.
         * Kept in. - lucas
         */
        if (IsServer(to)) 
            sendto_ops("Max SendQ limit exceeded for %s: %d > %ld",
                       get_client_name(to, HIDEME), SBufLength(&to->sendQ),
                       to->class->maxsendq);
        to->flags |= FLAGS_SENDQEX;
        return dead_link(to, "Max Sendq exceeded for %s, closing link", 0);
    }
    
    /*
     * Update statistics. The following is slightly incorrect
     * because it counts messages even if queued, but bytes only
     * really sent. Queued bytes get updated in SendQueued.
     */
    to->sendM += 1;
    me.sendM += 1;
    if (to->lstn)
        to->lstn->sendM += 1;

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

    if (!sbuf || flag)
    {
        if (sbuf_put(&to->sendQ, msg, len) < 0)
            return dead_link(to, "Buffer allocation error for %s,"
                                 " closing link", IRCERR_BUFALLOC);
    }
    else
    {
        if (sbuf_put_share(&to->sendQ, sbuf) < 0)
            return dead_link(to, "Buffer allocation error for %s,"
                                 " closing link", IRCERR_BUFALLOC);
    }

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
    /*
     * Let's not waste time trying this on anyone who has a blocking socket.
     * Also, let's send every 8k for servers, since there's lots of traffic
     * there and we'd like to make it more efficient. - lucas
     */

    if(to->flags & FLAGS_BLOCKED)
       return 0;

#ifdef ALWAYS_SEND_DURING_SPLIT
    if (currently_processing_netsplit)
    {
        send_queued(to);
        return 0;
    }
#endif

    SQinK = (SBufLength(&to->sendQ) >> 10);
    if (IsServer(to)) 
    {
        if (SQinK > (to->lastsq + 8))
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
#ifdef WRITEV_IOV
    struct iovec iov[WRITEV_IOV];
#endif
        
    /*
     * Once socket is marked dead, we cannot start writing to it,
     * even if the error is removed...
     * this should never happen.
     */
    if (IsDead(to)) 
        return -1;

    if(ZipOut(to) && zip_is_data_out(to->serv->zip_out))
    {
        if(SBufLength(&to->sendQ))
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
            if (!sbuf_put(&to->sendQ, msg, len))
                return dead_link(to, "Buffer allocation error for %s",
                                 IRCERR_BUFALLOC);
        }
    }
   
    while (SBufLength(&to->sendQ) > 0) 
    {
#ifdef WRITEV_IOV
        len = sbuf_mapiov(&to->sendQ, iov);
        if ((rlen = deliver_it(to, iov, len)) < 0)
#else
        msg = sbuf_map(&to->sendQ, &len);
        if ((rlen = deliver_it(to, msg, len)) < 0)
#endif
            return dead_link(to, "Write error to %s, closing link (%s)", errno);
        sbuf_delete(&to->sendQ, rlen);
        to->lastsq = (SBufLength(&to->sendQ) >> 10);

#ifdef STOP_SENDING_ON_SHORT_SEND
        if (rlen < len)
        {
            /* Treat this socket as blocking */
            to->flags |= FLAGS_BLOCKED;
            set_fd_flags(to->fd, FDF_WANTWRITE);
#else
        if (rlen == 0)
        {
            /* Socket is blocking... */
#endif
            break;
        }

        if(more_data && SBufLength(&to->sendQ) == 0)
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
            if (!sbuf_put(&to->sendQ, msg, len))
                return dead_link(to, "Buffer allocation error for %s",
                                 IRCERR_BUFALLOC);        
        }
    }
    
    if ((to->flags & FLAGS_SOBSENT) && IsBurst(to)
         && SBufLength(&to->sendQ) < 20480) 
    {
        if (!(to->flags & FLAGS_BURST))
        {
            to->flags &= (~FLAGS_SOBSENT);
            sendto_one(to, "BURST %d", SBufLength(&to->sendQ));
        }
    }
    return (IsDead(to)) ? -1 : 0;
}

/* send message to single client */
void sendto_one(aClient *to, char *pattern, ...) 
{
    va_list vl;
    int len;            /* used for the length of the current message */
    
    va_start(vl, pattern);
    len = ircvsprintf(sendbuf, pattern, vl);
   
    if (to->from)
        to = to->from;
    if (IsMe(to)) 
    {
        strncpyzt(selfbuf, sendbuf, sizeof(selfbuf));
        sendto_ops("Trying to send [%s] to myself!", selfbuf);
        return;
    }
    send_message(to, sendbuf, len, NULL);
    va_end(vl);
}

/* send to an aliased super target */
void sendto_alias(AliasInfo *ai, aClient *from, char *pattern, ...)
{
    aClient *to;
    va_list  vl;
    int      len;

    va_start(vl, pattern);
    to = ai->client->from;

    /* use shortforms only for non-super servers or capable super servers */
    if (!IsULine(to) || ((confopts & FLAGS_SERVHUB)
                         && (to->serv->uflags & ULF_SFDIRECT)))
        len = ircsprintf(sendbuf, ":%s %s :", from->name, ai->shortform);
    else
#ifdef PASS_SERVICES_MSGS
        /* target distinguishes between nick@server and nick */
        len = ircsprintf(sendbuf, ":%s PRIVMSG %s@%s :", from->name, ai->nick,
                         ai->server);
#else
        len = ircsprintf(sendbuf, ":%s PRIVMSG %s :", from->name, ai->nick);
#endif

    len += ircvsprintf(sendbuf+len, pattern, vl);
    send_message(to, sendbuf, len, NULL);
    va_end(vl);
}

void vsendto_one(aClient *to, char *pattern, va_list vl) 
{
    int len;            /* used for the length of the current message */
   
    len = ircvsprintf(sendbuf, pattern, vl);
   
    if (to->from)
        to = to->from;
    if (IsMe(to) && to->fd >= 0) 
    {
        strncpyzt(selfbuf, sendbuf, sizeof(selfbuf));
        sendto_ops("Trying to send [%s] to myself!", selfbuf);
        return;
    }
    send_message(to, sendbuf, len, NULL);
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
    va_list vl2; /* copy of vl */

    *buffer = ':';
    VA_COPY(vl2, vl);

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

    msglen = ircvsprintf(&buffer[sidx], pattern + 3, vl2);
    msglen += sidx;

    va_end(vl2);
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
    void *share_bufs[2] = { 0, 0 };
   
    va_start(vl, pattern);

    pfix = va_arg(vl, char *);

    INC_SERIAL
    for (cm = chptr->members; cm; cm = cm->next) 
    {
        acptr = cm->cptr;
        if (acptr->from == one)
            continue; /* ...was the one I should skip */

        if((confopts & FLAGS_SERVHUB) && IsULine(acptr) && (acptr->uplink->serv->uflags & ULF_NOCHANMSG))
            continue; /* Don't send channel traffic to super servers */

        i = acptr->from->fd;
        if (MyClient(acptr)) 
        {
            if(!didlocal)
            {
                didlocal = prefix_buffer(0, from, pfix, sendbuf, 
                                         pattern, vl);
                sbuf_begin_share(sendbuf, didlocal, &share_bufs[0]);
            }
            if(check_fake_direction(from, acptr))
                    continue;
            
            send_message(acptr, sendbuf, didlocal, share_bufs[0]);
            sentalong[i] = sent_serial;
        }
        else 
        {
            /*
             * Now check whether a message has been sent to this remote
             * link already
             */
            if(!didremote)
            {
                didremote = prefix_buffer(1, from, pfix, remotebuf, 
                                          pattern, vl);
                sbuf_begin_share(remotebuf, didremote, &share_bufs[1]);
            }
            
            if(check_fake_direction(from, acptr))
                    continue;
            
            if (sentalong[i] != sent_serial) 
            {
                send_message(acptr, remotebuf, didremote, share_bufs[1]);
                sentalong[i] = sent_serial;
            }
        }
    }
    
    sbuf_end_share(share_bufs, 2);    
    va_end(vl);
    return;
}

/*
 * Like sendto_channel_butone, but sends to all servers but 'one'
 * that have clients in this channel.
 */
void sendto_channel_remote_butone(aClient *one, aClient *from, aChannel *chptr,
                                  char *pattern, ...) 
{
    chanMember *cm;
    aClient *acptr;
    int i;
    int didremote = 0;
    va_list vl;
    char *pfix;
    void *share_buf = NULL;
   
    va_start(vl, pattern);

    pfix = va_arg(vl, char *);

    INC_SERIAL
    for (cm = chptr->members; cm; cm = cm->next) 
    {
        acptr = cm->cptr;
        if (acptr->from == one)
            continue; /* ...was the one I should skip */

        if((confopts & FLAGS_SERVHUB) && IsULine(acptr) && (acptr->uplink->serv->uflags & ULF_NOCHANMSG))
            continue; /* Don't send channel traffic to super servers */

        i = acptr->from->fd;
        if (!MyClient(acptr)) 
        {
            /*
             * Now check whether a message has been sent to this remote
             * link already
             */
            if(!didremote)
            {
                didremote = prefix_buffer(1, from, pfix, remotebuf,
                                          pattern, vl);
                sbuf_begin_share(remotebuf, didremote, &share_buf);
            }
            
            if(check_fake_direction(from, acptr))
                    continue;
            
            if (sentalong[i] != sent_serial) 
            {
                send_message(acptr, remotebuf, didremote, share_buf);
                sentalong[i] = sent_serial;
            }
        }
    }
    
    sbuf_end_share(&share_buf, 1);
    
    va_end(vl);
    return;
}

/*
 * sendto_server_butone_services
 *
 * Send a message to all connected servers except the client 'one' and super
 * servers with the specified flag (if in SERVHUB mode).
 */
void sendto_serv_butone_super(aClient *one, int flag, char *pattern, ...)
{
    aClient *cptr;
    int k = 0;
    fdlist send_fdlist;
    va_list vl;
    DLink *lp;


    va_start(vl, pattern);
    for (lp = server_list; lp; lp = lp->next)
    {
        cptr = lp->value.cptr;

        if ((confopts & FLAGS_SERVHUB) && IsULine(cptr)
            && (!flag || (cptr->serv->uflags & flag)))
            continue;

        if (one && cptr == one->from)
            continue;
        send_fdlist.entry[++k] = cptr->fd;
    }
    send_fdlist.last_entry = k;
    if (k)
        vsendto_fdlist(&send_fdlist, pattern, vl);
    va_end(vl);
    return;
}

#ifdef NOQUIT
/*
 * sendto_non_noquit_servs_butone
 *
 * Send a message to all non-noquit servs
 */
void sendto_non_noquit_servs_butone(aClient *one, char *pattern, ...)
{
    aClient *cptr;
    int k = 0;
    fdlist send_fdlist;
    va_list vl;
    DLink *lp;

    va_start(vl, pattern);
    for(lp = server_list; lp; lp = lp->next)
    {
        cptr = lp->value.cptr;

        if (IsNoquit(cptr) || (one == cptr))
            continue;

        send_fdlist.entry[++k] = cptr->fd;
    }
    send_fdlist.last_entry = k;
    if (k)
        vsendto_fdlist(&send_fdlist, pattern, vl);
    va_end(vl);
    return;
}
#endif

/*
 * sendto_server_butone_nickipstr
 *
 * Send a message to all connected servers except the client 'one'. Also select
 * servers that do or do not have the NICKIPSTR capability.
 */
void sendto_serv_butone_nickipstr(aClient *one, int flag, char *pattern, ...)
{
    aClient *cptr;
    int k = 0;
    fdlist send_fdlist;
    va_list vl;
    DLink *lp;

    va_start(vl, pattern);
    for(lp = server_list; lp; lp = lp->next)
    {
        cptr = lp->value.cptr;
        if (one && cptr == one->from)
            continue;
	if (flag && !IsNickIPStr(cptr))
	    continue;
	if (!flag && IsNickIPStr(cptr))
	    continue;
        send_fdlist.entry[++k] = cptr->fd;
    }
    send_fdlist.last_entry = k;
    if (k)
        vsendto_fdlist(&send_fdlist, pattern, vl);
    va_end(vl);
    return;
}

/* sendto_capab_serv_butone - Send a message to all servers with "include" capab and without "exclude" capab */
void sendto_capab_serv_butone(aClient *one, int include, int exclude, char *pattern, ...)
{
    aClient *cptr;
    int k = 0;
    fdlist send_fdlist;
    va_list vl;
    DLink *lp;

    va_start(vl, pattern);
    for(lp = server_list; lp; lp = lp->next)
    {
        cptr = lp->value.cptr;

        if ((one==cptr) ||
            (include && !(cptr->capabilities & include)) ||
            (exclude && (cptr->capabilities & exclude)))
            continue;

        send_fdlist.entry[++k] = cptr->fd;
    }
    send_fdlist.last_entry = k;
    if (k)
        vsendto_fdlist(&send_fdlist, pattern, vl);
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
    aClient *cptr;
    int k = 0;
    fdlist send_fdlist;
    va_list vl;
    DLink *lp;
        
    va_start(vl, pattern);
    for(lp = server_list; lp; lp = lp->next)
    {
        cptr = lp->value.cptr;
        if (one && cptr == one->from)
            continue;
        send_fdlist.entry[++k] = cptr->fd;
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
    void *share_buf = NULL;

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

                if((channels->value.chptr->mode.mode & MODE_AUDITORIUM) && (cptr != from) &&
                   !is_chan_opvoice(cptr, channels->value.chptr) && !is_chan_opvoice(from, channels->value.chptr)) continue;
            
                sentalong[cptr->fd] = sent_serial;
                if (!msglen)
                {
                    msglen = prefix_buffer(0, from, pfix, sendbuf,
                                           pattern, vl);
                    sbuf_begin_share(sendbuf, msglen, &share_buf);
                }
                if (check_fake_direction(from, cptr))
                    continue;
                send_message(cptr, sendbuf, msglen, share_buf);
            }
        }
    }
    
    if(MyConnect(from))
    {
        if(!msglen)
            msglen = prefix_buffer(0, from, pfix, sendbuf, pattern, vl);
        /* send the share buf if others are using it too */
        send_message(from, sendbuf, msglen, share_buf);
    }
    
    sbuf_end_share(&share_buf, 1);

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
    void *share_buf = NULL;

    INC_SERIAL
    
    msglen=sprintf(sendbuf,":%s!%s@%s QUIT :%s", from->name,
                   from->user->username,from->user->host, reason);      
    sbuf_begin_share(sendbuf, msglen, &share_buf);
   
    if(from->fd >= 0)
        sentalong[from->fd] = sent_serial;    
    for (channels = from->user->channel; channels; channels = channels->next)
    {
        if (!can_send(from, channels->value.chptr, reason)) 
        {
            for (users = channels->value.chptr->members; users; 
                 users = users->next) 
            {
                cptr = users->cptr;
                if (!MyConnect(cptr) || sentalong[cptr->fd] == sent_serial)
                    continue;
                if((channels->value.chptr->mode.mode & MODE_AUDITORIUM) && (cptr != from) &&
                   !is_chan_opvoice(cptr, channels->value.chptr) && !is_chan_opvoice(from, channels->value.chptr)) continue;
                sentalong[cptr->fd] = sent_serial;
                if (check_fake_direction(from, cptr))
                    continue;
                send_message(cptr, sendbuf, msglen, share_buf);
            }
        }
    }
    sbuf_end_share(&share_buf, 1);
}

/*
 * send_part_to_common_channels()
 * 
 * Sends a message to all people (inclusing user) on local server who are
 * in same channel with user if the user cannot send to the channel.
 */
void send_part_to_common_channels(aClient *from, char *reason)
{
    Link *channels;
    chanMember *users;
    aClient *cptr;
    int msglen = 0;
    void *share_buf = NULL;
    
    for (channels = from->user->channel; channels; channels = channels->next)
    {
        if (can_send(from, channels->value.chptr, reason)) 
        {
            msglen = sprintf(sendbuf,":%s!%s@%s PART %s",
                             from->name,from->user->username,from->user->host,
                             channels->value.chptr->chname);
            sbuf_begin_share(sendbuf, msglen, &share_buf);

            INC_SERIAL

            if (from->fd >= 0)
                sentalong[from->fd] = sent_serial;

            for (users = channels->value.chptr->members; users; 
                 users = users->next) 
            {
                cptr = users->cptr;
              
                if (!MyConnect(cptr) || sentalong[cptr->fd] == sent_serial)
                    continue;

                if((channels->value.chptr->mode.mode & MODE_AUDITORIUM) && (cptr != from) &&
                   !is_chan_opvoice(cptr, channels->value.chptr) && !is_chan_opvoice(from, channels->value.chptr)) continue;
                
                sentalong[cptr->fd] = sent_serial;
                if (check_fake_direction(from, cptr))
                    continue;
                send_message(cptr, sendbuf, msglen, share_buf);
            }
            sbuf_end_share(&share_buf, 1);
        }
    }
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
            continue;           /* ...was the one I should skip */
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
    void *share_buf = NULL;

    va_start(vl, pattern);
    
    pfix = va_arg(vl, char *);

    for (cm = chptr->members; cm; cm = cm->next)
    {
        if (MyConnect(acptr = cm->cptr))
        {
            if((chptr->mode.mode & MODE_AUDITORIUM) && (acptr != from) && !is_chan_opvoice(acptr, chptr) &&
               !is_chan_opvoice(from, chptr)) continue;
            if(!didlocal)
            {
                didlocal = prefix_buffer(0, from, pfix, sendbuf, pattern, vl);
                sbuf_begin_share(sendbuf, didlocal, &share_buf);
            }
            
            if (check_fake_direction(from, acptr))
                continue;

            send_message(acptr, sendbuf, didlocal, share_buf);

            /* vsendto_prefix_one(acptr, from, pattern, vl); */
        }
    }
    sbuf_end_share(&share_buf, 1);
    va_end(vl);
}

/*
 * sendto_channel_butserv_noopvoice
 * 
 * Send a message to all members of a channel that are connected to this
 * server and aren't opped or voiced.
 */
void sendto_channel_butserv_noopvoice(aChannel *chptr, aClient *from, char *pattern, ...)
{
    chanMember  *cm;
    aClient *acptr;
    va_list vl;
    int didlocal = 0;
    char *pfix;
    void *share_buf = NULL;

    va_start(vl, pattern);
    
    pfix = va_arg(vl, char *);

    for (cm = chptr->members; cm; cm = cm->next)
    {
        if (MyConnect(acptr = cm->cptr))
        {
            if((acptr == from) || is_chan_opvoice(acptr, chptr)) continue;
            if(!didlocal)
            {
                didlocal = prefix_buffer(0, from, pfix, sendbuf, pattern, vl);
                sbuf_begin_share(sendbuf, didlocal, &share_buf);
            }
            
            if (check_fake_direction(from, acptr))
                continue;

            send_message(acptr, sendbuf, didlocal, share_buf);

            /* vsendto_prefix_one(acptr, from, pattern, vl); */
        }
    }
    sbuf_end_share(&share_buf, 1);
    va_end(vl);
}

/*
 * sendto_channel_butserv_me
 * 
 * Send a message to all members of a channel that are connected to this
 * server. Possibly hide the origin, if it's a server, with me.name if certain paranoia is on.
 */
void sendto_channel_butserv_me(aChannel *chptr, aClient *from, char *pattern, ...)
{
    chanMember  *cm;
    aClient *acptr;
    va_list vl;
    int didlocal = 0;
    char *pfix;
    void *share_buf = NULL;

    va_start(vl, pattern);
    
    pfix = va_arg(vl, char *);

#ifdef HIDE_SERVERMODE_ORIGINS
    if(IsServer(from) && !IsULine(from))
    {
       from = &me;
       pfix = me.name;
    }
#endif

    for (cm = chptr->members; cm; cm = cm->next)
    {
        if (MyConnect(acptr = cm->cptr))
        {
            if((chptr->mode.mode & MODE_AUDITORIUM) && !is_chan_opvoice(acptr, chptr)) continue;
            if (!didlocal)
            {
                didlocal = prefix_buffer(0, from, pfix, sendbuf, pattern, vl);
                sbuf_begin_share(sendbuf, didlocal, &share_buf);
            }
            
            if(check_fake_direction(from, acptr))
                continue;

            send_message(acptr, sendbuf, didlocal, share_buf);

        }
    }
    sbuf_end_share(&share_buf, 1);
    va_end(vl);
}

/*
 * sendto_channelopvoice_butserv_me
 * 
 * Send a message to all members of a channel that are connected to this
 * server. Possibly hide the origin, if it's a server, with me.name if certain paranoia is on.
 */
void sendto_channelopvoice_butserv_me(aChannel *chptr, aClient *from, char *pattern, ...)
{
    chanMember  *cm;
    aClient *acptr;
    va_list vl;
    int didlocal = 0;
    char *pfix;
    void *share_buf = NULL;

    va_start(vl, pattern);
    
    pfix = va_arg(vl, char *);

#ifdef HIDE_SERVERMODE_ORIGINS
    if(IsServer(from) && !IsULine(from))
    {
       from = &me;
       pfix = me.name;
    }
#endif

    for (cm = chptr->members; cm; cm = cm->next)
    {
        if (MyConnect(acptr = cm->cptr))
        {
            if(!is_chan_opvoice(acptr, chptr)) continue;
            if (!didlocal)
            {
                didlocal = prefix_buffer(0, from, pfix, sendbuf, pattern, vl);
                sbuf_begin_share(sendbuf, didlocal, &share_buf);
            }
            
            if(check_fake_direction(from, acptr))
                continue;

            send_message(acptr, sendbuf, didlocal, share_buf);

        }
    }
    sbuf_end_share(&share_buf, 1);
    va_end(vl);
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
 * sendto_all_servmask
 *
 * Send to all servers that match the specified mask, and to all local
 * clients if I match the mask.  Replaces sendto_match_butone().
 *   -Quension [Jul 2004]
 */
void sendto_all_servmask(aClient *from, char *mask, char *pattern, ...)
{
    fdlist   send_fdlist;
    void    *share_buf;
    char    *pfix;
    aClient *cptr;
    DLink   *lp;
    int      i;
    int      k;
    va_list  vl, vl2;

    va_start(vl, pattern);

    /* send to matching servers */
    k = 0;
    for (lp = server_list; lp; lp = lp->next)
    {
        cptr = lp->value.cptr;
        if (cptr == from->from)
            continue;
        if (!match(mask, cptr->name))
            send_fdlist.entry[++k] = cptr->fd;
    }
    if (k)
    {
        VA_COPY(vl2, vl);
        send_fdlist.last_entry = k;
        vsendto_fdlist(&send_fdlist, pattern, vl2);
        va_end(vl2);
    }

    /* send to my clients if I match */
    if (!match(mask, me.name))
    {
        VA_COPY(vl2, vl);
        pfix = va_arg(vl2, char *);
        k = prefix_buffer(0, from, pfix, sendbuf, pattern, vl2);
        va_end(vl2);

        sbuf_begin_share(sendbuf, k, &share_buf);
        for (i = 0; i <= highest_fd; i++)
        {
            if (!(cptr = local[i]))
                continue;
            if (!IsClient(cptr))
                continue;
            send_message(cptr, sendbuf, k, share_buf);
        }
        sbuf_end_share(&share_buf, 1);
    }
    va_end(vl);
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
    va_list vl, vl2;
    char *tmsg;

#ifdef NICER_UMODENOTICE_SEPARATION
    switch(lev)
    {
       case CCONN_LEV:
          tmsg = "Client";
          break;

       case DEBUG_LEV:
          tmsg = "Debug";
          break;

       case SPY_LEV:
          tmsg = "Spy";
          break;

       case SPAM_LEV:
          tmsg = "Spam";
          break;

       case FLOOD_LEV:
          tmsg = "Flood";
          break;

       case DCCSEND_LEV:
          tmsg = "DCCAllow";
          break;

       case ADMIN_LEV:
          tmsg = "Admin";
          break;

       default:
          tmsg = "Notice";
    }
#else
    tmsg = "Notice";
#endif
        
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
            case USKILL_LEV:
                if (!SendSUkillNotice(cptr) || !IsAnOper(cptr))
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
            case ADMIN_LEV:
                if (!IsAdmin(cptr) || !SendServNotice(cptr))
                    continue;
                break;
                          
            default:            /* this is stupid, but oh well */
                if (!SendServNotice(cptr))
                    continue;
        }
        VA_COPY(vl2, vl);
        ircsprintf(nbuf, ":%s NOTICE %s :*** %s -- ", me.name, 
                   cptr->name, tmsg);
        strncat(nbuf, pattern, sizeof(nbuf) - strlen(nbuf));
        vsendto_one(cptr, nbuf, vl2);
        va_end(vl2);
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
    va_list vl;
        
    va_start(vl, pattern);
    vsendto_realops(pattern, vl);
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
        i = cptr->from->fd;     /* find connection oper is on */
        if (sentalong[i] == sent_serial) /* sent message along it already ? */
            continue;
        if (cptr->from == one)
            continue;           /* ...was the one I should skip */
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
    aClient *cptr;
    char nbuf[1024];
    va_list vl, vl2;
    DLink *lp;
          
    va_start(vl, pattern);
    for (lp = oper_list; lp; lp = lp->next)
    {
        cptr = lp->value.cptr;
        if (!SendGlobops(cptr) || !IsAnOper(cptr))
            continue;

        if (IsAnOper(cptr))
        {
            VA_COPY(vl2, vl);
            ircsprintf(nbuf, ":%s NOTICE %s :*** Global -- %s",
                       me.name, cptr->name, pattern);
            vsendto_one(cptr, nbuf, vl2);
            va_end(vl2);
        }
    }
    va_end(vl);
    return;
}

void send_chatops(char *pattern, ...)
{
    aClient *cptr;
    char nbuf[1024];
    va_list vl, vl2;
    DLink *lp;
          
    va_start(vl, pattern);
    for (lp = oper_list; lp; lp = lp->next)
    {
        cptr = lp->value.cptr;
        if (!SendChatops(cptr) || !IsAnOper(cptr))
            continue;

        if (IsAnOper(cptr))
        {
            VA_COPY(vl2, vl);
            ircsprintf(nbuf, ":%s NOTICE %s :*** ChatOps -- %s",
                       me.name, cptr->name, pattern);
            vsendto_one(cptr, nbuf, vl2);
            va_end(vl2);
        }
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
    VA_COPY(vl2, vl);

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
                va_end(vl2);
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
    va_list vl2;
    VA_COPY(vl2, vl);
        
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
    void *share_buf = NULL;
    
    va_start(vl, pattern);
    len = ircvsprintf(sendbuf, pattern, vl);
    sbuf_begin_share(sendbuf, len, &share_buf);
        
    for (fd = listp->entry[j = 1]; j <= listp->last_entry;
         fd = listp->entry[++j])
        send_message(local[fd], sendbuf, len, share_buf);
    sbuf_end_share(&share_buf, 1);
    va_end(vl);
}

void vsendto_fdlist(fdlist *listp, char *pattern, va_list vl)
{
    int len, j, fd;
    void *share_buf = NULL;
    len = ircvsprintf(sendbuf, pattern, vl);
    sbuf_begin_share(sendbuf, len, &share_buf);
        
    for (fd = listp->entry[j = 1]; j <= listp->last_entry;
         fd = listp->entry[++j])
        send_message(local[fd], sendbuf, len, share_buf);
    sbuf_end_share(&share_buf, 1);
}


void vsendto_realops(char *pattern, va_list vl)
{
    aClient *cptr;
    char nbuf[1024];
    DLink *lp;
    va_list vl2;

    for (lp = oper_list; lp; lp = lp->next)
    {
        cptr = lp->value.cptr;
        if (IsAnOper(cptr))
        {
            VA_COPY(vl2, vl);
            ircsprintf(nbuf, ":%s NOTICE %s :*** Notice -- %s",
                       me.name, cptr->name, pattern);
            vsendto_one(cptr, nbuf, vl2);
            va_end(vl2);
        }
    }
    return;
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
    va_list vl;
          
    va_start(vl, pattern);
    vsendto_realops(pattern, vl);
    va_end(vl);
}

/*
 * sendto_realops_lev
 * 
 * Send to *local* ops only but NOT +s nonopers at a certain level
 */
void sendto_realops_lev(int lev, char *pattern, ...)
{
    aClient *cptr;
    char nbuf[1024];
    va_list vl, vl2;
    DLink *lp;
    char *tmsg;

    va_start(vl, pattern);

#ifdef NICER_UMODENOTICE_SEPARATION
    switch(lev)
    {
       case CCONN_LEV:
          tmsg = "Client";
          break;

       case DEBUG_LEV:
          tmsg = "Debug";
          break;

       case SPY_LEV:
          tmsg = "Spy";
          break;

       case SPAM_LEV:
          tmsg = "Spam";
          break;

       case FLOOD_LEV:
          tmsg = "Flood";
          break;

       case DCCSEND_LEV:
          tmsg = "DCCAllow";
          break;

       case ADMIN_LEV:
          tmsg = "Admin";
          break;

       default:
          tmsg = "Notice";
    }
#else
    tmsg = "Notice";
#endif

    for (lp = oper_list; lp; lp = lp->next)
    {
        cptr = lp->value.cptr;
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
            case SKILL_LEV:
                if (!SendSkillNotice(cptr))
                    continue;
                break;
            case USKILL_LEV:
                if (!SendSUkillNotice(cptr))
                    continue;
                break;
            case SPY_LEV:
                if (!SendSpyNotice(cptr))
                    continue;
                break;
            case DCCSEND_LEV:
                if (!SendDCCNotice(cptr))
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
            case ADMIN_LEV:
                if (!IsAdmin(cptr))
                    continue;
                break;
        }
        VA_COPY(vl2, vl);
        ircsnprintf(nbuf, 1024, ":%s NOTICE %s :*** %s -- %s",
                    me.name, cptr->name, tmsg, pattern);
        vsendto_one(cptr, nbuf, vl2);
        va_end(vl2);
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
    char nbuf[1024];
    va_list vl, vl2;
    DLink *lp;

    va_start(vl, pattern);

    for (lp = oper_list; lp; lp = lp->next)
    {
        cptr = lp->value.cptr;

        if (SendGlobops(cptr))
        {
            VA_COPY(vl2, vl);
            ircsprintf(nbuf, ":%s NOTICE %s :*** LocOps -- %s",
                       me.name, cptr->name, pattern);
            vsendto_one(cptr, nbuf, vl2);
            va_end(vl2);
        }
    }
    va_end(vl);
    return;
}

/* sendto_gnotice - send a routing notice to all local +n users. */
void sendto_gnotice(char *pattern, ...)
{
    aClient *cptr;
    char nbuf[1024];
    va_list vl, vl2;
    DLink *lp;
        
    va_start(vl, pattern);

    for (lp = oper_list; lp; lp = lp->next)
    {
        cptr = lp->value.cptr;
        if (SendRnotice(cptr)) 
        {
            VA_COPY(vl2, vl);
            ircsprintf(nbuf, ":%s NOTICE %s :*** Routing -- %s",
                       me.name, cptr->name, pattern);
            vsendto_one(cptr, nbuf, vl2);
            va_end(vl2);
        }
    }
    va_end(vl);
    return;
}

/*
 * sendto_channelflags_butone
 *  Send a message to all channel members with the specified flags, both
 *  local and remote.
 */
void sendto_channelflags_butone(aClient *one, aClient *from, aChannel *chptr,
                                int flags, char *pattern, ...)
{
    chanMember *cm;
    aClient *acptr;
    int fd;
    char *pfix;
    va_list vl;
    int didlocal = 0;
    int didremote = 0;
    void *share_buf[2] = {0};

    va_start(vl, pattern);
    pfix = va_arg(vl, char *);

    INC_SERIAL

    for (cm = chptr->members; cm; cm = cm->next)
    {
        acptr = cm->cptr;

        if (acptr->from == one || !(cm->flags & flags))
            continue;

        if((confopts & FLAGS_SERVHUB) && IsULine(acptr) && (acptr->uplink->serv->uflags & ULF_NOCHANMSG))
            continue; /* Don't send channel traffic to super servers */

        if (MyConnect(acptr))
        {
            if (!didlocal)
            {
                didlocal = prefix_buffer(0, from, pfix, sendbuf, pattern, vl);
                sbuf_begin_share(sendbuf, didlocal, &share_buf[0]);
            }
            send_message(acptr, sendbuf, didlocal, share_buf[0]);
        }
        else
        {
            fd = acptr->from->fd;

            if (sentalong[fd] == sent_serial)
                continue;

            if (!didremote)
            {
                didremote = prefix_buffer(1, from, pfix, remotebuf, pattern,
                                          vl);
                sbuf_begin_share(remotebuf, didremote, &share_buf[1]);
            }
            send_message(acptr, remotebuf, didremote, share_buf[1]);
            sentalong[fd] = sent_serial;
        }
    }

    sbuf_end_share(share_buf, 2);
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
        {
            if (!(cptr = local[i]))
               continue;
            if(!(cptr->flags & FLAGS_BLOCKED) &&
                (SBufLength(&cptr->sendQ) > 0 ||
                (ZipOut(cptr) && zip_is_data_out(cptr->serv->zip_out))))
                send_queued(cptr);
        }
    }
    else if (fd >= 0 && (cptr = local[fd]) &&
             !(cptr->flags & FLAGS_BLOCKED) && 
             (SBufLength(&cptr->sendQ) > 0 || 
             (ZipOut(cptr) && zip_is_data_out(cptr->serv->zip_out))))
        send_queued(cptr);
}

void dump_connections(int fd) 
{
    int     i;
    aClient *cptr;
    
    if (fd == me.fd) 
    {
        for (i = highest_fd; i >= 0; i--)
            if ((cptr = local[i]) && 
                (SBufLength(&cptr->sendQ) > 0 || 
                (ZipOut(cptr) && zip_is_data_out(cptr->serv->zip_out))))
                send_queued(cptr);
    }
    else if (fd >= 0 && (cptr = local[fd]) && 
        (SBufLength(&cptr->sendQ) > 0 || 
        (ZipOut(cptr) && zip_is_data_out(cptr->serv->zip_out))))
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
            (SBufLength(&cptr->sendQ) > 0 ||
            (ZipOut(cptr) && zip_is_data_out(cptr->serv->zip_out))))
            send_queued(cptr);
}

u_long
memcount_send(MCsend *mc)
{
    mc->file = __FILE__;

    mc->s_bufs.c++;
    mc->s_bufs.m += sizeof(sendbuf);
    mc->s_bufs.c++;
    mc->s_bufs.m += sizeof(remotebuf);
    mc->s_bufs.c++;
    mc->s_bufs.m += sizeof(selfbuf);
#ifdef HAVE_ENCRYPTION_ON
    mc->s_bufs.c++;
    mc->s_bufs.m += sizeof(rc4buf);
#endif

    return 0;
}

