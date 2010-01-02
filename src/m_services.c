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
#include "userban.h"
#include "clones.h"
#include "memcount.h"

/* Externally defined stuffs */
extern int user_modes[];

int svspanic = 0; /* Services panic */

/*
 * the services aliases. *
 *
 * NICKSERV     - /nickserv * CHANSERV  - /chanserv * OPERSERV  -
 * /operserv * MEMOSERV         - /memoserv * SERVICES  - /services *
 * IDENTIFY     - /identify * taz's code -mjs
 */

/* Code provided by orabidoo */
/*
 * a random number generator loosely based on RC5; assumes ints are at
 * least 32 bit
 */

static unsigned long 
my_rand()
{
    static unsigned long s = 0, t = 0, k = 12345678;
    int         i;

    if (s == 0 && t == 0)
    {
        s = (unsigned long) getpid();
        t = (unsigned long) time(NULL);
    }
    for (i = 0; i < 12; i++)
    {
        s = (((s ^ t) << (t & 31)) | ((s ^ t) >> (31 - (t & 31)))) + k;
        k += s + t;
        t = (((t ^ s) << (s & 31)) | ((t ^ s) >> (31 - (s & 31)))) + k;
        k += s + t;
    }
    return s;
}

/* alias message handler */
int m_aliased(aClient *cptr, aClient *sptr, int parc, char *parv[], AliasInfo *ai)
{
    if (parc < 2 || *parv[1] == 0)
    {
        sendto_one(sptr, err_str(ERR_NOTEXTTOSEND), me.name, parv[0]);
        return -1;
    }

    /* second check is to avoid message loops when admins get stupid */
    if (!ai->client || ai->client->from == sptr->from)
    {
        sendto_one(sptr, err_str(ERR_SERVICESDOWN), me.name, parv[0],
                   ai->nick);
        return 0;
    }

    if((svspanic>1 && !IsOper(sptr)) || (svspanic>0 && !IsARegNick(sptr) && !IsOper(sptr)))
    {
        if(MyClient(sptr))
            sendto_one(sptr, err_str(ERR_SERVICESDOWN), me.name, parv[0],
                       ai->nick);
        return 0;
    }

    sendto_alias(ai, sptr, "%s", parv[1]);

    return 0;
}

/* m_services -- see df465+taz */
int m_services(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    char       *tmps;
    int         aidx = AII_NS;

    if (parc < 2 || *parv[1] == '\0')
    {
	sendto_one(sptr, err_str(ERR_NOTEXTTOSEND), me.name, parv[0]);
	return -1;
    }
    if ((strlen(parv[1]) >= 4) && (!myncmp(parv[1], "help", 4)))
    {
	sendto_one(sptr, ":services!service@%s NOTICE %s :For ChanServ "
		   "help use: /chanserv help", Services_Name,
		   sptr->name);
	sendto_one(sptr, ":services!service@%s NOTICE %s :For NickServ "
		   "help use: /nickserv help", Services_Name,
		   sptr->name);
	sendto_one(sptr, ":services!service@%s NOTICE %s :For MemoServ "
		   "help use: /memoserv help", Services_Name,
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
        aidx = AII_CS;
    }
    return m_aliased(cptr, sptr, parc, parv, &aliastab[aidx]);
}

/* m_identify  df465+taz */
int m_identify(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    int aidx = AII_NS;

    if (parc < 2 || *parv[1] == '\0')
    {
	sendto_one(sptr, err_str(ERR_NOTEXTTOSEND), me.name, parv[0]);
	return -1;
    }

    if (*parv[1] == '#')
        aidx = AII_CS;

    if (!aliastab[aidx].client)
    {
        sendto_one(sptr, err_str(ERR_SERVICESDOWN), me.name, parv[0],
                   aliastab[aidx].nick);
        return 0;
    }

    sendto_alias(&aliastab[aidx], sptr, "IDENTIFY %s", parv[1]);

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
        int tries = 0, nprefix;

        do 
        {
	    nprefix = my_rand() % 99999;
  	    ircsnprintf(newnick, NICKLEN, "%s-%d", parv[2], nprefix);
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

    if(acptr->umode & UMODE_r)
    {
	unsigned int oldumode;
	char mbuf[BUFSIZE];

	oldumode = acptr->umode;
	acptr->umode &= ~UMODE_r;

        send_umode(acptr, acptr, oldumode, ALL_UMODES, mbuf);
    }

    acptr->tsinfo = atoi(parv[3]);
#ifdef ANTI_NICK_FLOOD
    acptr->last_nick_change = atoi(parv[3]);
#endif
    sendto_common_channels(acptr, ":%s NICK :%s", parv[1], newnick);
    add_history(acptr, 1);
    sendto_serv_butone(NULL, ":%s NICK %s :%ld", parv[1], newnick,
		       (long)acptr->tsinfo);
    if(acptr->name[0]) 
    {
        del_from_client_hash_table(acptr->name, acptr);
        hash_check_watch(acptr, RPL_LOGOFF);
    }
    strcpy(acptr->name, newnick);
    add_to_client_hash_table(acptr->name, acptr);
    hash_check_watch(acptr, RPL_LOGON);
    flush_user_banserial(acptr);

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

#ifdef EXEMPT_LISTS
    case 'e':
            if (nick && MyClient(acptr) && change == '-')
            {
                remove_matching_exempts(chptr, acptr, &me);
                sendmsg--;
            }
            break;
#endif

#ifdef INVITE_LISTS
    case 'I':
            if (nick && MyClient(acptr) && change == '-')
            {
                remove_matching_invites(chptr, acptr, &me);
                sendmsg--;
            }
            break;
#endif

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
	    if (optarg && IsDigit(*optarg))
		acptr->user->servicestamp = strtoul(optarg, NULL, 0);
	    break;
	case 'T':
	    if (optarg && IsDigit(*optarg))
		acptr->user->servicetype = strtoul(optarg, NULL, 0);
	    break;
	default:
	    for (s = user_modes; (flag = *s); s += 2)
	    {
		if (*m == (char)(*(s+1)))
		{
            if (what == MODE_ADD)
            {
                /* no opering this way */
                if (flag & (UMODE_o|UMODE_O))
                    break;
                acptr->umode |= flag;
            }
            else if (acptr->umode & flag)
            {
                acptr->umode &= ~flag;

                /* deopering ok */
                if (MyConnect(acptr) && (flag & (UMODE_o|UMODE_O))
                    && !IsAnOper(acptr))
                {
                    acptr->oflag = 0;
                    remove_from_list(&oper_list, acptr, NULL);
                }
            }

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

    if (MyClient(acptr) && (oldumode != acptr->umode))
    {
        char buf[BUFSIZE];
        send_umode(acptr, acptr, oldumode, ALL_UMODES, buf);
    }

    return 0;
}

/* m_svshold
 *   Adds a temporary local nick ban.
 * parv[0] - sender
 * parv[1] - nick
 * parv[2] - duration (0 to remove existing ban)
 * parv[3] - optional reason
 */
int m_svshold(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    struct simBan *ban, *oban;
    char *reason, *mask;
    int length;

    if(!IsULine(sptr) || parc < 3)
        return 0;

    mask = parv[1];
    length = strtol(parv[2], NULL, 0);
    reason = (parc < 4) ? "Nickname is reserved, try again later" : parv[3];

    /* marked local so netbursts don't propagate it */
    ban = make_simpleban(SBAN_LOCAL|SBAN_NICK|SBAN_TEMPORARY|SBAN_SVSHOLD, parv[1]);
    if(!ban)
    {
	sendto_realops_lev(DEBUG_LEV, "make_simpleban(%s) failed on svshold", mask);
	return 0;
    }
    ban->reason = NULL;
    
    if((oban = find_simban_exact(ban)) != NULL)
    {
	simban_free(ban);
	ban = NULL;

	if(length <= 0)
	{
	    remove_simban(oban);
        simban_free(oban);
	}
	else
	{
	    if(oban->reason)
		MyFree(oban->reason);
	    oban->reason = (char *) MyMalloc(strlen(reason) + 1);
	    strcpy(oban->reason, reason);
	    oban->timeset = NOW;
	    oban->duration = length;
	}
    }
    else if(length > 0)
    {
	ban->reason = (char *) MyMalloc(strlen(reason) + 1);
	strcpy(ban->reason, reason);
	ban->timeset = NOW;
	ban->duration = length;
	add_simban(ban);
    }
    else
	simban_free(ban);

    if(parc < 4)
	sendto_serv_butone(cptr, ":%s SVSHOLD %s %s", sptr->name, parv[1], parv[2]);
    else
	sendto_serv_butone(cptr, ":%s SVSHOLD %s %s :%s", sptr->name, parv[1], parv[2], parv[3]);

    return 0;
}


/* m_svsclone
*   Sets a clone limit for an IP mask (1.2.3.4 or 1.2.3.*).
* parv[0] - sender
* parv[1] - mask
* parv[2] - duration (0 to revert to default limit)
*/
int
m_svsclone(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    int d;

    if (parc != 3)
        return 0;

    if (!(IsServer(sptr) || IsULine(sptr)))
        return 0;

    d = atoi(parv[2]);
    clones_set(parv[1], CLIM_HARD_GLOBAL, d);
    sendto_serv_butone(cptr, ":%s SVSCLONE %s %s", parv[0], parv[1], parv[2]);

    return 0;
}


/* m_svspanic
 *   Stops users from sending commands to u:lined servers.
 * parv[0] - sender
 * parv[1] - 2/1/0 (0 - all users can use services, 1 - only +r users can use services, 2 - only opers (+o) can use services)
 */
int m_svspanic(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    if(!IsULine(sptr) || parc < 2)
        return 0;

    svspanic = atoi(parv[1]);

    sendto_serv_butone(cptr, ":%s SVSPANIC %s", sptr->name, parv[1]);

    return 0;
}

/* m_chankill
 *   Destroy a channel completely, removing all local users
 *   with a kick and propegating the chankill out.  The user will
 *   not see anyone else get kicked before they do.
 * parv[0] - sender (Ulined client)
 * parv[1] - channel
 * parv[2] - kick reason
 */
int m_chankill(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aChannel *chptr = NULL;
    chanMember *cur = NULL, *next = NULL;

    if(!IsULine(sptr) || parc < 2)  /* we can kick without a reason. */
        return 0;
    if(!(chptr = find_channel(parv[1], NULL)))
        return 0;
    cur = chptr->members;
    while(cur)
    {
        next = cur->next;
        if(MyClient(cur->cptr)) /* tell our clients that the channel is gone */
            sendto_prefix_one(cur->cptr, sptr, ":%s KICK %s %s :%s", parv[0],
                              parv[1], cur->cptr->name,
                              (parc == 3) ? parv[2] : "");
        remove_user_from_channel(cur->cptr, chptr);
        cur = next;
    }
    /* at this point, the channel should not exist locally */
    sendto_serv_butone(cptr, ":%s CHANKILL %s :%s", parv[0], parv[1],
                       (parc == 3) ? parv[2] : "");
    return 0;
}


u_long
memcount_m_services(MCm_services *mc)
{
    mc->file = __FILE__;

    return 0;
}

