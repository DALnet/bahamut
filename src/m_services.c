/* m_services.c - Because s_user.c was just crazy.
 *   Copyright (C) 1990 Jarkko Oikarinen and
 *                      University of Oulu, Computing Center
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

/* $Id$ */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "msg.h"
#include "channel.h"
#include <sys/stat.h>
#include <utmp.h>
#include <fcntl.h>
#include "h.h"

/* Externally defined stuffs */
extern int user_modes[];
extern unsigned long my_rand();

/* internally defined stuffs */




/*
 * the services aliases. *
 *
 * NICKSERV     - /nickserv * CHANSERV  - /chanserv * OPERSERV  -
 * /operserv * MEMOSERV         - /memoserv * SERVICES  - /services *
 * IDENTIFY     - /identify * taz's code -mjs
 */

/* m_ns */
int m_ns(aClient *cptr, aClient *sptr, int parc, char *parv[]) 
{
    aClient    *acptr;

    if (check_registered_user(sptr))
	return 0;
    if (parc < 2 || *parv[1] == '\0')
    {
        if(MyClient(sptr))
	  sendto_one(sptr, err_str(ERR_NOTEXTTOSEND), me.name, parv[0]);
	return -1;
    }
    if ((acptr = find_server(SERVICES_NAME, NULL)))
#ifdef SERVICESHUB
	sendto_one(acptr, ":%s NS :%s", parv[0], parv[1]);
#else
	sendto_one(acptr, ":%s PRIVMSG %s@%s :%s", 
		parv[0], NICKSERV, SERVICES_NAME, parv[1]);
#endif
    else
	sendto_one(sptr, err_str(ERR_SERVICESDOWN), me.name,
		   parv[0], NICKSERV);
    return 0;
}

/* m_cs */
int m_cs(aClient *cptr, aClient *sptr, int parc, char *parv[]) 
{
    aClient    *acptr;

    if (check_registered_user(sptr))
	return 0;
    if (parc < 2 || *parv[1] == '\0')
    {
        if(MyClient(sptr))
	  sendto_one(sptr, err_str(ERR_NOTEXTTOSEND), me.name, parv[0]);
	return -1;
    }
    if ((acptr = find_server(SERVICES_NAME, NULL)))
#ifdef SERVICESHUB
	sendto_one(acptr, ":%s CS :%s", parv[0], parv[1]);
#else
	sendto_one(acptr, ":%s PRIVMSG %s@%s :%s", 
		parv[0], CHANSERV, SERVICES_NAME, parv[1]);
#endif
    else
	sendto_one(sptr, err_str(ERR_SERVICESDOWN), me.name,
		   parv[0], CHANSERV);
    return 0;
}

/* m_ms */
int m_ms(aClient *cptr, aClient *sptr, int parc, char *parv[]) 
{
    aClient    *acptr;

    if (check_registered_user(sptr))
	return 0;
    if (parc < 2 || *parv[1] == '\0')
    {
        if(MyClient(sptr))
	  sendto_one(sptr, err_str(ERR_NOTEXTTOSEND), me.name, parv[0]);
	return -1;
    }
    if ((acptr = find_server(SERVICES_NAME, NULL)))
#ifdef SERVICESHUB
	sendto_one(acptr, ":%s MS :%s", parv[0], parv[1]);
#else
	sendto_one(acptr, ":%s PRIVMSG %s@%s :%s", 
		parv[0], MEMOSERV, SERVICES_NAME, parv[1]);
#endif
    else
	sendto_one(sptr, err_str(ERR_SERVICESDOWN), me.name,
		   parv[0], MEMOSERV);
    return 0;
}

/* m_rs */
int m_rs(aClient *cptr, aClient *sptr, int parc, char *parv[]) 
{
    aClient    *acptr;

    if (check_registered_user(sptr))
	return 0;
    if (parc < 2 || *parv[1] == '\0')
    {
        if(MyClient(sptr))
	  sendto_one(sptr, err_str(ERR_NOTEXTTOSEND), me.name, parv[0]);
	return -1;
    }
    if ((acptr = find_server(SERVICES_NAME, NULL)))
#ifdef SERVICESHUB
	sendto_one(acptr, ":%s RS :%s", parv[0], parv[1]);
#else
	sendto_one(acptr, ":%s PRIVMSG %s@%s :%s", 
		parv[0], ROOTSERV, SERVICES_NAME, parv[1]);
#endif
    else
	sendto_one(sptr, err_str(ERR_SERVICESDOWN), me.name,
		   parv[0], ROOTSERV);
    return 0;
}

/* m_os */
int m_os(aClient *cptr, aClient *sptr, int parc, char *parv[]) 
{
    aClient    *acptr;

    if (check_registered_user(sptr))
	return 0;
    if (parc < 2 || *parv[1] == '\0')
    {
        if(MyClient(sptr))
	  sendto_one(sptr, err_str(ERR_NOTEXTTOSEND), me.name, parv[0]);
	return -1;
    }
    if ((acptr = find_server(STATS_NAME, NULL)))
#ifdef SERVICESHUB
	sendto_one(acptr, ":%s OS :%s", parv[0], parv[1]);
#else
	sendto_one(acptr, ":%s PRIVMSG %s@%s :%s", 
		parv[0], OPERSERV, STATS_NAME, parv[1]);
#endif
    else
	sendto_one(sptr, err_str(ERR_SERVICESDOWN), me.name,
		   parv[0], OPERSERV);
    return 0;
}

/* m_ss */
int m_ss(aClient *cptr, aClient *sptr, int parc, char *parv[]) 
{
    aClient    *acptr;

    if (check_registered_user(sptr))
	return 0;
    if (parc < 2 || *parv[1] == '\0')
    {
        if(MyClient(sptr))
	  sendto_one(sptr, err_str(ERR_NOTEXTTOSEND), me.name, parv[0]);
	return -1;
    }
    if ((acptr = find_server(STATS_NAME, NULL)))
#ifdef SERVICESHUB
	sendto_one(acptr, ":%s SS :%s", parv[0], parv[1]);
#else
	sendto_one(acptr, ":%s PRIVMSG %s@%s :%s", 
		parv[0], STATSERV, STATS_NAME, parv[1]);
#endif
    else
	sendto_one(sptr, err_str(ERR_SERVICESDOWN), me.name,
		   parv[0], STATSERV);
    return 0;
}

/* m_hs */
int m_hs(aClient *cptr, aClient *sptr, int parc, char *parv[]) 
{
    aClient    *acptr;

    if (check_registered_user(sptr))
	return 0;
    if (parc < 2 || *parv[1] == '\0')
    {
        if(MyClient(sptr))
	  sendto_one(sptr, err_str(ERR_NOTEXTTOSEND), me.name, parv[0]);
	return -1;
    }
    if ((acptr = find_server(STATS_NAME, NULL)))
#ifdef SERVICESHUB
	sendto_one(acptr, ":%s HS :%s", parv[0], parv[1]);
#else
	sendto_one(acptr, ":%s PRIVMSG %s@%s :%s", 
		parv[0], HELPSERV, STATS_NAME, parv[1]);
#endif
    else
	sendto_one(sptr, err_str(ERR_SERVICESDOWN), me.name,
		   parv[0], HELPSERV);
    return 0;
}

/* m_services -- see df465+taz */
int m_services(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    char       *tmps;

    if (check_registered_user(sptr))
	return 0;

    if (parc < 2 || *parv[1] == '\0')
    {
	sendto_one(sptr, err_str(ERR_NOTEXTTOSEND), me.name, parv[0]);
	return -1;
    }
    if ((strlen(parv[1]) >= 4) && (!myncmp(parv[1], "help", 4)))
    {
	sendto_one(sptr, ":services!service@%s NOTICE %s :For ChanServ "
		   "help use: /chanserv help", SERVICES_NAME,
		   sptr->name);
	sendto_one(sptr, ":services!service@%s NOTICE %s :For NickServ "
		   "help use: /nickserv help", SERVICES_NAME,
		   sptr->name);
	sendto_one(sptr, ":services!service@%s NOTICE %s :For MemoServ "
		   "help use: /memoserv help", SERVICES_NAME,
		   sptr->name);
	return 0;
    }
    if ((tmps = (char *) strchr(parv[1], ' ')))
    {
	for(; *tmps == ' '; tmps++); /* er.. before this for loop, the next
				      * comparison would always compare '#' 
				      * with ' '.. oops. - lucas
				      */
	if (*tmps == '#')
	    return m_cs(cptr, sptr, parc, parv);
	else
	    return m_ns(cptr, sptr, parc, parv);
    }
    return m_ns(cptr, sptr, parc, parv);
}

/* m_identify  df465+taz */
int m_identify(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    char       buf[BUFSIZE+1];
    char       *myparv[parc];

    if (check_registered_user(sptr))
	return 0;

    if (parc < 2 || *parv[1] == '\0')
    {
	sendto_one(sptr, err_str(ERR_NOTEXTTOSEND), me.name, parv[0]);
	return -1;
    }
    (void) ircsnprintf(buf, BUFSIZE, "IDENTIFY %s", parv[1]);

    myparv[0]=parv[0];
    myparv[1]=buf;

    if (*parv[1] == '#')
      return m_cs(cptr, sptr, parc, myparv);
    else
      return m_ns(cptr, sptr, parc, myparv);

    return 0;
}

/* s_svsnick - Pretty straight forward.  Mostly straight outta df
 *  - Raistlin
 * parv[0] = sender
 * parv[1] = old nickname
 * parv[2] = new nickname
 * parv[3] = timestamp
 */
int m_svsnick(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aClient *acptr, *ocptr;
    char newnick[NICKLEN + 1];

    if (!IsULine(sptr)||parc < 4||(strlen(parv[2]) > NICKLEN)) 
	return 0;

    if(hunt_server(cptr, sptr, ":%s SVSNICK %s %s :%s", 1, parc, parv) != HUNTED_ISME)
	return 0;

    /* can't find them? oh well. */
    if ((acptr = find_person(parv[1], NULL)) == NULL)
	return 0;

    strncpyzt(newnick, parv[2], NICKLEN+1);

    /* does the nick we're changing them to already exist? */
    /* Try to make a unique nickname */
    if((ocptr = find_client(newnick, NULL)) != NULL)
    {
        char servprefix[HOSTLEN + 1], *pptr;
        int tries = 0, nprefix;

        strncpyzt(servprefix, me.name, NICKLEN+1);
        pptr = strchr(servprefix, '.');
        if(pptr)
           *pptr = '\0';

        do 
        {
	    nprefix = my_rand() % 999;
  	    ircsnprintf(newnick, NICKLEN, "%s-%d[%s]", parv[2], nprefix, servprefix);
            tries++;
        } while (((ocptr = find_client(newnick, NULL)) != NULL) && (tries < 10));

	/* well, we tried.. */
        if(ocptr)
        {
           if(IsUnknown(ocptr))
              return exit_client(ocptr, ocptr, &me, "SVSNICK Override");
           else
              return exit_client(acptr, acptr, &me, "SVSNICK Collide");
        }
    }

    acptr->umode &= ~UMODE_r;
    acptr->tsinfo = atoi(parv[3]);
#ifdef ANTI_NICK_FLOOD
    acptr->last_nick_change = atoi(parv[3]);
#endif
    sendto_common_channels(acptr, ":%s NICK :%s", parv[1], newnick);
    if(!IsUmodeI(acptr))
	add_history(acptr, 1);
    sendto_serv_butone(NULL, ":%s NICK %s :%d", parv[1], newnick,
		       acptr->tsinfo);
    if(acptr->name[0]) 
	del_from_client_hash_table(acptr->name, acptr);
    strcpy(acptr->name, newnick);
    add_to_client_hash_table(acptr->name, acptr);

    return 0;
}

/* channel_svsmode:
 * parv[0] sender
 * parv[1] channel
 * parv[2] modes
 * parv[3] nick
 * parv[4] nickts
 * currently, only a mode of -b is supported.
 * services should use MODE for regular channel modes.
 * 2/5/00 lucas
 * preconditions: parc >= 3, sptr is ulined
 */
int channel_svsmode(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aChannel *chptr;
    aClient *acptr = NULL;
    char *m, *nick = NULL;
    char change = '+';
    ts_val nickts = 0;
    int sendmsg = 1;

    if(!(chptr = find_channel(parv[1], NULL)))
	return 0;

    if(parc >= 4)
    {
	nick = parv[3];
	if(parc > 4)
	    nickts = atol(parv[4]);
    }

    if(nick)
    {
	acptr = find_person(nick, NULL);
	if(!acptr || (nickts && acptr->tsinfo != nickts))
	    return 0;
    }

    for(m = parv[2]; *m; m++)
	switch(*m)
	{
	case '+':
	case '-':
            change = *m;
            break;

	case 'b':
            if(nick && MyClient(acptr) && change == '-')
            {
		remove_matching_bans(chptr, acptr, &me);
		sendmsg--;
            }
            break;

	default:
            sendmsg++;
            break;
	}

    if(!sendmsg) return 0;

    if(nick)
	sendto_serv_butone(cptr, ":%s SVSMODE %s %s %s %ld", parv[0], parv[1],
			   parv[2], nick, acptr->tsinfo);
    else
	sendto_serv_butone(cptr, ":%s SVSMODE %s %s", parv[0], parv[1], 
			   parv[2]);

    return 0;
}

/* m_svsmode - df function integrated
 *  - Raistlin
 * -- Behaviour changed - Epi (11/30/99)
 * parv[0] - sender
 * parv[1] - nick
 * parv[2] - TS (or mode, depending on svs version)
 * parv[3] - mode (or services id if old svs version)
 * parv[4] - optional arguement (services id)
 */
int m_svsmode(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    int            flag, *s, what, oldumode;
    char          *m, *modes, *optarg;
    aClient       *acptr;
    ts_val         ts = 0;

    if (!IsULine(sptr) || (parc < 3))
	return 0;

    if (parv[1][0] == '#')
	return channel_svsmode(cptr, sptr, parc, parv);

    if ((parc >= 4) && ((parv[3][0] == '+') || (parv[3][0] == '-')))
    {
	ts = atol(parv[2]);
	modes = parv[3];
	optarg = (parc > 4) ? parv[4] : NULL;
    }
    else
    {
	modes = parv[2];
	optarg = (parc > 3) ? parv[3] : NULL;
    }

    if (!(acptr = find_person(parv[1], NULL)))
	return 0;

    if (ts && (ts != acptr->tsinfo))
	return 0;

    what = MODE_ADD;
    oldumode = acptr->umode;
    for (m = modes; *m; m++)
	switch(*m)
	{
	case '+':
	    what = MODE_ADD;
	    break;
	case '-':
	    what = MODE_DEL;
	    break;
	case ' ':
	case '\n':
	case '\r':
	case '\t':
	    break;
	case 'd':
	    if (optarg && isdigit(*optarg))
		acptr->user->servicestamp = strtoul(optarg, NULL, 0);
	    break;
	default:
	    for (s = user_modes; (flag = *s); s += 2)
	    {
		if (*m == (char)(*(s+1)))
		{
		    if (what == MODE_ADD)
			acptr->umode |= flag;
		    else
			acptr->umode &= ~flag;

		    /* If this SVSMODE removed their oper status,
		     * remove them from the oper fd list */
		    if(MyConnect(acptr) && what == MODE_DEL && 
                       (flag == UMODE_o || flag == UMODE_O) && 
		       !IsAnOper(acptr)) 
			remove_from_list(&oper_list, acptr, NULL);

		    break;
		}
	    }
	    break;
	}

    if (optarg)
	sendto_serv_butone(cptr, ":%s SVSMODE %s %ld %s %s",
			   parv[0], parv[1], acptr->tsinfo, modes, optarg);
    else
	sendto_serv_butone(cptr, ":%s SVSMODE %s %ld %s",
			   parv[0], parv[1], acptr->tsinfo, modes);

    if (MyClient(acptr))
    {
        char buf[BUFSIZE];
        send_umode(acptr, acptr, oldumode, ALL_UMODES, buf);
    }

    return 0;
}

