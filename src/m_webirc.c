/* m_webirc.c
 *
 *   Copyright (C) 2012 Ned T. Crigler
 *
 *   See file AUTHORS in IRC package for additional names of
 *   the programmers.
 *
 *   This program is free softwmare; you can redistribute it and/or modify
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
#include "numeric.h"
#include "h.h"
#include "throttle.h"
#include "userban.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

/*
 * m_webirc
 * parv[0] = sender prefix
 * parv[1] = password that authenticates the WEBIRC command from this client
 * parv[2] = username or client requesting spoof (cgiirc defaults to cgiirc)
 * parv[3] = hostname of user
 * parv[4] = IP address of user
 */
int m_webirc(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    char oldusername[USERLEN + 1];
    struct userBan *ban;
    int i;

    if (parc < 5 || *parv[1] == '\0' || *parv[2] == '\0' ||
	*parv[3] == '\0' || *parv[4] == '\0')
    {
	sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0], "WEBIRC");
	return 0;
    }
    if (!MyConnect(sptr) || !IsUnknown(cptr) || cptr->receiveM != 1)
    {
	sendto_one(sptr, err_str(ERR_ALREADYREGISTRED), me.name, parv[0]);
	return 0;
    }

    strncpyzt(oldusername, cptr->username, USERLEN + 1);
    make_user(cptr);
    if (!(cptr->flags & FLAGS_GOTID))
	strcpy(cptr->username, "webirc");
    i = attach_Iline(cptr, cptr->hostp, cptr->sockhost);
    if (i == 0)
    {
	aAllow *pwaconf = sptr->user->allow;

	if (BadPtr(pwaconf->passwd) ||
	    strncmp(pwaconf->passwd, "webirc.", strlen("webirc.")) != 0)
	{
	    sendto_one(sptr, "NOTICE * :Not a CGI:IRC auth block");
	    i = -1;
	}
	else if (!StrEq(parv[1], pwaconf->passwd + strlen("webirc.")))
	{
	    sendto_one(sptr, "NOTICE * :CGI:IRC password incorrect");
	    i = -1;
	}
	else if (pwaconf->flags & CONF_FLAGS_NOTHROTTLE)
	    throttle_remove(cptr->sockhost);
    }
    clear_conflinks(cptr);
    free_user(cptr->user, cptr);
    cptr->user = NULL;
    cptr->flags &= ~FLAGS_DOID;
    strncpyzt(cptr->username, oldusername, USERLEN + 1);
    if (i != 0)
	return 0;

    if (inet_pton(AF_INET, parv[4], &cptr->ip.ip4))
	cptr->ip_family = AF_INET;
    else if (inet_pton(AF_INET6, parv[4], &cptr->ip.ip6))
	cptr->ip_family = AF_INET6;
    else
    {
	sendto_one(sptr, "NOTICE * :Invalid IP");
	return 0;
    }

    if (cptr->flags & FLAGS_GOTID)
    {
	cptr->webirc_username = MyMalloc(strlen(cptr->username) + 1);
	strcpy(cptr->webirc_username, cptr->username);
    }
    else
    {
	cptr->webirc_username = MyMalloc(strlen(parv[2]) + 1);
	strcpy(cptr->webirc_username, parv[2]);
    }
    cptr->webirc_ip = MyMalloc(strlen(cptr->sockhost) + 1);
    strcpy(cptr->webirc_ip, cptr->sockhost);

    if(strlen(parv[3]) > HOSTLEN)
        get_sockhost(cptr, parv[4]); /* IP (because host is too long) */
    else
        get_sockhost(cptr, parv[3]); /* host */
    cptr->hostp = NULL;

    /*
     * Acknowledge that WEBIRC was accepted, and flush the client's send queue
     * to make debugging easier.
     */
    sendto_one(sptr, ":%s NOTICE AUTH :*** CGI:IRC host/IP set to %s %s",
	       me.name, cptr->sockhost, parv[4]);
    dump_connections(cptr->fd);

    /* if they are throttled, drop them silently. */
    if (throttle_check(parv[4], cptr->fd, NOW) == 0)
    {
	cptr->flags |= FLAGS_DEADSOCKET;

	ircstp->is_ref++;
	ircstp->is_throt++;
	return exit_client(cptr, sptr, &me, "Client throttled");
    }

    ban = check_userbanned(cptr, UBAN_IP|UBAN_CIDR4|UBAN_WILDUSER, 0);
    if(ban)
    {
	int loc = (ban->flags & UBAN_LOCAL) ? 1 : 0;

	ircstp->is_ref++;
	ircstp->is_ref_2++;
	return exit_banned_client(cptr, loc, loc ? 'K' : 'A', ban->reason, 0);
    }
    return 0;
}
