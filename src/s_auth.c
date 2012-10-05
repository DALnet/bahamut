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
#include "fds.h"

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
    union
    {
	struct sockaddr sa;
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
    } sock;
    union
    {
	struct sockaddr sa;
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
    } localaddr;
    unsigned int locallen;

    Debug((DEBUG_NOTICE, "start_auth(%x) fd %d status %d",
	   cptr, cptr->fd, cptr->status));
    if ((cptr->authfd = socket(cptr->ip_family, SOCK_STREAM, 0)) == -1)
    {
#ifdef	USE_SYSLOG
	syslog(LOG_ERR, "Unable to create auth socket for %s:%m",
	       get_client_name(cptr, IsServer(cptr) ? HIDEME : TRUE));
#endif
	ircstp->is_abad++;
	return;
    }
    if (cptr->authfd >= MAXCONNECTIONS)
    {
	sendto_realops_lev(DEBUG_LEV,"Can't allocate fd for auth on %s",
		   get_client_name(cptr, (IsServer(cptr) ? HIDEME : TRUE)));
	close(cptr->authfd);
        cptr->authfd = -1;
	return;
    }
#ifdef SHOW_HEADERS
    sendto_one(cptr, "%s", REPORT_DO_ID);
#endif
    set_non_blocking(cptr->authfd, cptr);

    /*
     * get the local address of the client and bind to that to make the
     * auth request.  This used to be done only for ifdef VIRTTUAL_HOST,
     * but needs to be done for all clients since the ident request must
     * originate from that same address-- and machines with multiple IP
     * addresses are common now
     */
    locallen = sizeof(localaddr);
    memset(&localaddr, '\0', sizeof(localaddr));
    getsockname(cptr->fd, &localaddr.sa, &locallen);
    if (localaddr.sa.sa_family == AF_INET)
    {
	localaddr.addr4.sin_port = htons(0);
	locallen = sizeof(localaddr.addr4);
    }
    else if (localaddr.sa.sa_family == AF_INET6)
    {
	localaddr.addr6.sin6_port = htons(0);
	locallen = sizeof(localaddr.addr6);
    }

    if (bind(cptr->authfd, &localaddr.sa, locallen) == -1)
    {
	report_error("binding auth stream socket %s:%s", cptr);
	close(cptr->authfd);
        cptr->authfd = -1;
	return;
    }

    memset(&sock, '\0', sizeof(sock));
    if (cptr->ip_family == AF_INET)
    {
	memcpy((char *) &sock.addr4.sin_addr, (char *) &cptr->ip.ip4,
	       sizeof(struct in_addr));
	sock.addr4.sin_port = htons(113);
	sock.addr4.sin_family = AF_INET;
    }
    else if (cptr->ip_family == AF_INET6)
    {
	memcpy((char *) &sock.addr6.sin6_addr, (char *) &cptr->ip.ip6,
	       sizeof(struct in6_addr));
	sock.addr6.sin6_port = htons(113);
	sock.addr6.sin6_family = AF_INET6;
    }

    if (connect(cptr->authfd, &sock.sa,
		locallen) == -1 && errno != EINPROGRESS)
    {
	ircstp->is_abad++;
	/* No error report from this... */
	close(cptr->authfd);
	cptr->authfd = -1;
#ifdef SHOW_HEADERS
	sendto_one(cptr, "%s", REPORT_FAIL_ID);
#endif
	return;
    }

    cptr->flags |= (FLAGS_WRAUTH | FLAGS_AUTH);
    if (cptr->authfd > highest_fd)
	highest_fd = cptr->authfd;

    add_fd(cptr->authfd, FDT_AUTH, cptr);
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
    union
    {
	struct sockaddr sa;
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
    } us;
    union
    {
	struct sockaddr sa;
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
    } them;
    char        authbuf[32];
    unsigned int ulen = sizeof(us), tlen = sizeof(them);
    int slen;

    Debug((DEBUG_NOTICE, "write_authports(%x) fd %d authfd %d stat %d",
	   cptr, cptr->fd, cptr->authfd, cptr->status));

    if (getsockname(cptr->fd, &us.sa, &ulen) ||
	getpeername(cptr->fd, &them.sa, &tlen))
    {
#ifdef	USE_SYSLOG
	syslog(LOG_DEBUG, "auth get{sock,peer}name error for %s:%m",
	       get_client_name(cptr, IsServer(cptr) ? HIDEME : TRUE));
#endif
	authsenderr(cptr);
	return;
    }

    if (us.sa.sa_family == AF_INET)
    {
	(void) ircsprintf(authbuf, "%u , %u\r\n",
			  (unsigned int) ntohs(them.addr4.sin_port),
			  (unsigned int) ntohs(us.addr4.sin_port));
	Debug((DEBUG_SEND, "sending [%s] to auth port %s.113",
	       authbuf, inetntoa((char *) &them.sin_addr)));
    }
    else if (us.sa.sa_family == AF_INET6)
    {
	(void) ircsprintf(authbuf, "%u , %u\r\n",
			  (unsigned int) ntohs(them.addr6.sin6_port),
			  (unsigned int) ntohs(us.addr6.sin6_port));
	Debug((DEBUG_SEND, "sending [%s] to auth port %s.113",
	       authbuf, inet6ntoa((char *) &them.sin_addr)));
    }

    slen = strlen(authbuf);
    if (send(cptr->authfd, authbuf, slen, 0) != slen) {
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

    del_fd(cptr->authfd);

    close(cptr->authfd);
    if (cptr->authfd == highest_fd)
	while (!local[highest_fd])
	    highest_fd--;
    cptr->authfd = -1;
    cptr->flags &= ~(FLAGS_AUTH | FLAGS_WRAUTH);
#ifdef SHOW_HEADERS
    sendto_one(cptr, "%s", REPORT_FAIL_ID);
#endif

    return;
}

/*
 * read_authports
 *
 * read the reply (if any) from the ident server we connected to. The
 * actual read processing here is pretty weak - no handling of the
 * reply if it is fragmented by IP.
 *
 * Whoever wrote this code should be shot.
 * Looks like it's trouncing on memory it shouldn't be.
 * Rewriting, some credit goes to wd for saving me time with his code.
 * - lucas
 */

#define AUTHBUFLEN 128

void read_authports(aClient *cptr)
{
   char buf[AUTHBUFLEN], usern[USERLEN + 1];
   int len, userncnt;
   char *userid = "", *s, *reply, *os, *tmp;
   int rejected = 0;

   len = recv(cptr->authfd, buf, AUTHBUFLEN, 0);

   if(len > 0)
   {
      do
      {
         if(buf[len - 1] != '\n')
            break;

         buf[--len] = '\0';

         if(len == 0)
            break;

         if(buf[len - 1] == '\r')
            buf[--len] = '\0';

         if(len == 0)
            break;

         s = strchr(buf, ':');
         if(!s)
            break;
         s++;

         while(IsSpace(*s))
            s++;

         reply = s;
         if(strncmp(reply, "USERID", 6))
            break;

         s = strchr(reply, ':');
         if(!s)
            break;
         s++;

         while(IsSpace(*s))
            s++;

         os = s;

         s = strchr(os, ':');
         if(!s)
            break;
         s++;

         while(IsSpace(*s))
            s++;
         
         /* hack to reject pidentd encryption */
         if (strlen(s) == 34)
         {
             rejected = 1;
             break;
         }

         userid = tmp = usern;
         /* s is the pointer to the beginning of the userid field */
         for(userncnt = USERLEN; *s && userncnt; s++)
         {
            if(*s == '@')
               break;

            if(!IsSpace(*s) && *s != ':')
            {
               *tmp++ = *s;
               userncnt--;
            }
         }
         *tmp = '\0';

      } while(0);
   }

   del_fd(cptr->authfd);
   close(cptr->authfd);
   if (cptr->authfd == highest_fd)
      while (!local[highest_fd])
         highest_fd--;
   cptr->authfd = -1;
   ClearAuth(cptr);

   if (rejected || !*userid)
   {
      ircstp->is_abad++;
      strcpy(cptr->username, "unknown");
#ifdef SHOW_HEADERS
      sendto_one(cptr, "%s", rejected ? REPORT_REJECT_ID : REPORT_FAIL_ID);
#endif
      return;
   }
#ifdef SHOW_HEADERS
   else
      sendto_one(cptr, "%s", REPORT_FIN_ID);
#endif

   ircstp->is_asuc++;
   strncpyzt(cptr->username, userid, USERLEN + 1);
   cptr->flags |= FLAGS_GOTID;
   return;
}

