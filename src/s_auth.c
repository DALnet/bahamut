/************************************************************************
 *   IRC - Internet Relay Chat, src/s_auth.c
 *   Copyright (C) 1992 Darren Reed
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
#include "res.h"
#include "numeric.h"
#include "patchlevel.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#if defined(__hpux)
#include "inet.h"
#endif
#include <fcntl.h>
#include "sock.h"    /* If FD_ZERO isn't define up to this point */
/* define it (BSD4.2 needs this) */
#include "h.h"
#include "fdlist.h"

static void authsenderr(aClient *);

/*
 * start_auth
 * 
 * Flag the client to show that an attempt to contact the ident server on
 * the client's host.  The connect and subsequently the socket are all
 * put into 'non-blocking' mode.  Should the connect or any later phase
 * of the identifing process fail, it is aborted and the user is given
 * a username of "unknown".
 */
void start_auth(aClient *cptr)
{
    struct sockaddr_in sock;
    struct sockaddr_in localaddr;
    int         locallen;

    Debug((DEBUG_NOTICE, "start_auth(%x) fd %d status %d",
	   cptr, cptr->fd, cptr->status));
    if ((cptr->authfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
#ifdef	USE_SYSLOG
	syslog(LOG_ERR, "Unable to create auth socket for %s:%m",
	       get_client_name(cptr, TRUE));
#endif
	if (!DoingDNS(cptr))
	    SetAccess(cptr);
	ircstp->is_abad++;
	return;
    }
    if (cptr->authfd >= MAXCONNECTIONS)
    {
	sendto_realops_lev(DEBUG_LEV,"Can't allocate fd for auth on %s",
		   get_client_name(cptr, (IsServer(cptr) ? HIDEME : TRUE)));
	(void) close(cptr->authfd);
	return;
    }
#ifdef SHOW_HEADERS
    send(cptr->fd, REPORT_DO_ID, R_do_id, 0);
#endif
    set_non_blocking(cptr->authfd, cptr);
    /*
     * get the local address of the client and bind to that to make the
     * auth request.  This used to be done only for ifdef VIRTTUAL_HOST,
     * but needs to be done for all clients since the ident request must
     * originate from that same address-- and machines with multiple IP
     * addresses are common now
     */
    locallen = sizeof(struct sockaddr_in);

    memset(&localaddr, '\0', locallen);
    getsockname(cptr->fd, (struct sockaddr *) &localaddr, &locallen);
    localaddr.sin_port = htons(0);

    if (bind(cptr->authfd, (struct sockaddr *) &localaddr,
	     sizeof(localaddr)) == -1) 
    {
	report_error("binding auth stream socket %s:%s", cptr);
	(void) close(cptr->fd);
	return;
    }
    
    memcpy((char *) &sock.sin_addr, (char *) &cptr->ip,
	   sizeof(struct in_addr));

    sock.sin_port = htons(113);
    sock.sin_family = AF_INET;

    if (connect(cptr->authfd, (struct sockaddr *) &sock,
		sizeof(sock)) == -1 && errno != EINPROGRESS)
    {
	ircstp->is_abad++;
	/* No error report from this... */
	(void) close(cptr->authfd);
	cptr->authfd = -1;
	if (!DoingDNS(cptr))
	    SetAccess(cptr);
#ifdef SHOW_HEADERS
	send(cptr->fd, REPORT_FAIL_ID, R_fail_id, 0);
#endif
	return;
    }

    cptr->flags |= (FLAGS_WRAUTH | FLAGS_AUTH);
    if (cptr->authfd > highest_fd)
	highest_fd = cptr->authfd;
    return;
}

/*
 * send_authports
 * 
 * Send the ident server a query giving "theirport , ourport". The write
 * is only attempted *once* so it is deemed to be a fail if the entire
 * write doesn't write all the data given.  This shouldnt be a problem
 * since the socket should have a write buffer far greater than this
 * message to store it in should problems arise. -avalon
 */
void send_authports(aClient *cptr)
{
    struct sockaddr_in us, them;
    char        authbuf[32];
    int         ulen, tlen;

    Debug((DEBUG_NOTICE, "write_authports(%x) fd %d authfd %d stat %d",
	   cptr, cptr->fd, cptr->authfd, cptr->status));
    tlen = ulen = sizeof(us);

    if (getsockname(cptr->fd, (struct sockaddr *) &us, &ulen) ||
	getpeername(cptr->fd, (struct sockaddr *) &them, &tlen))
    {
#ifdef	USE_SYSLOG
	syslog(LOG_DEBUG, "auth get{sock,peer}name error for %s:%m",
	       get_client_name(cptr, TRUE));
#endif
	authsenderr(cptr);
	return;
    }

    (void) ircsprintf(authbuf, "%u , %u\r\n",
		      (unsigned int) ntohs(them.sin_port),
		      (unsigned int) ntohs(us.sin_port));
    
    Debug((DEBUG_SEND, "sending [%s] to auth port %s.113",
	   authbuf, inetntoa((char *) &them.sin_addr)));

    if (write(cptr->authfd, authbuf, strlen(authbuf)) != strlen(authbuf)) {
	authsenderr(cptr);
	return;
    }
    
    cptr->flags &= ~FLAGS_WRAUTH;
    
    return;
}

/*
 * authsenderr() *  
 * input - pointer to aClient output
 */
static void authsenderr(aClient *cptr)
{
    ircstp->is_abad++;

    (void) close(cptr->authfd);
    if (cptr->authfd == highest_fd)
	while (!local[highest_fd])
	    highest_fd--;
    cptr->authfd = -1;
    cptr->flags &= ~(FLAGS_AUTH | FLAGS_WRAUTH);
#ifdef SHOW_HEADERS
    send(cptr->fd, REPORT_FAIL_ID, R_fail_id, 0);
#endif

    if (!DoingDNS(cptr))
	SetAccess(cptr);

    return;
}

/*
 * read_authports
 * 
 * read the reply (if any) from the ident server we connected to. The
 * actual read processing here is pretty weak - no handling of the
 * reply if it is fragmented by IP.
 * 
 * This is really broken and needs to be rewritten.  Somehow len is
 * nonzero on failed connects() on Solaris (and maybe others?).  I
 * relocated the REPORT_FIN_ID to hide the problem.  --Rodder
 * 
 */
void read_authports(aClient *cptr)
{
    char   *s, *t;
    int     len;
    char        ruser[USERLEN + 1], tuser[USERLEN + 1];
    u_short     remp = 0, locp = 0;

    *ruser = '\0';
    Debug((DEBUG_NOTICE, "read_authports(%x) fd %d authfd %d stat %d",
	   cptr, cptr->fd, cptr->authfd, cptr->status));
    /*
     * Nasty.  Cant allow any other reads from client fd while we're
     * waiting on the authfd to return a full valid string.  Use the
     * client's input buffer to buffer the authd reply. Oh. this is
     * needed because an authd reply may come back in more than 1 read!
     * -avalon
     */
    if ((len = read(cptr->authfd, cptr->buffer + cptr->count,
		    sizeof(cptr->buffer) - 1 - cptr->count)) >= 0)
    {
	cptr->count += len;
	cptr->buffer[cptr->count] = '\0';
    }

    if ((len > 0) && (cptr->count != sizeof(cptr->buffer) - 1) &&
	(sscanf(cptr->buffer, "%hd , %hd : USERID : %*[^:]: %10s",
		&remp, &locp, tuser) == 3) &&
	(s = strrchr(cptr->buffer, ':')))
    {
	for (++s, t = ruser; *s && (t < ruser + sizeof(ruser)); s++)
	    if (!isspace(*s) && *s != ':' && *s != '@')
		*t++ = *s;
	*t = '\0';
	Debug((DEBUG_INFO, "auth reply ok"));
    }
    else if (len != 0) 
    {
	*ruser = '\0';
    }

    (void) close(cptr->authfd);
    if (cptr->authfd == highest_fd)
	while (!local[highest_fd])
	    highest_fd--;
    cptr->count = 0;
    cptr->authfd = -1;
    ClearAuth(cptr);
    if (!DoingDNS(cptr))
	SetAccess(cptr);
    if (len > 0)
	Debug((DEBUG_INFO, "ident reply: [%s]", cptr->buffer));
    if (!locp || !remp || !*ruser)
    {
	ircstp->is_abad++;
	(void) strcpy(cptr->username, "unknown");
	return;
    }
#ifdef SHOW_HEADERS
    else
	send(cptr->fd, REPORT_FIN_ID, R_fin_id, 0);
#endif

    ircstp->is_asuc++;
    strncpyzt(cptr->username, ruser, USERLEN + 1);
    cptr->flags |= FLAGS_GOTID;
    Debug((DEBUG_INFO, "got username [%s]", ruser));
    return;
}
