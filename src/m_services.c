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
#include <fcntl.h>
#include "h.h"
#include "userban.h"
#include "clones.h"
#include "memcount.h"

/* Externally defined stuffs */
extern int user_modes[];
extern int check_channelname(aClient *, unsigned char *); /* for m_aj */
extern aChannel *get_channel(aClient *, char *, int, int *); /* for m_aj */
extern Link *find_channel_link(Link *, aChannel *); /* for m_aj */
extern void add_user_to_channel(aChannel *, aClient *, int); /* for m_aj */
extern void read_motd(char *); /* defined in s_serv.c */
extern void read_shortmotd(char *); /* defined in s_serv.c */

int svspanic = 0; /* Services panic */
int svsnoop = 0; /* Services disabled all o:lines (off by default) */
int uhm_type = 0; /* User host-masking type (off by default) */
int services_jr = 0; /* Redirect join requests to services (disabled by default) */

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

        send_umode(acptr, acptr, oldumode, ALL_UMODES, mbuf, sizeof(mbuf));
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
                if((flag & (UMODE_o|UMODE_O)) && !IsAnOper(acptr))
                {
                     Count.oper++;
                     if(MyConnect(acptr))
                         add_to_list(&oper_list, acptr);
                }
                if((flag & (UMODE_o|UMODE_O|UMODE_a|UMODE_A)) && optarg && MyConnect(acptr))
                {
                     if(*optarg == '+')
                         acptr->oflag |= atol(optarg);
                     else if(*optarg == '-')
                         acptr->oflag &= ~(atol(optarg) * -1);
                     else
                         acptr->oflag = atol(optarg);
                }
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
        send_umode(acptr, acptr, oldumode, ALL_UMODES, buf, sizeof(buf));
    }

    return 0;
}

/* m_svshold
 *   Adds a temporary local nick ban.
 * parv[0] - sender
 * parv[1] - nick/channel
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
    if(*mask == '#')
        ban = make_simpleban(SBAN_LOCAL|SBAN_CHAN|SBAN_TEMPORARY|SBAN_SVSHOLD, parv[1]);
    else
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

/* m_svshost - Lets services change a user's host.
 * -Kobi_S 30/01/2010
 */
int m_svshost(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aClient *acptr;

    if(!IsServer(sptr) || parc<3 || *parv[2]==0)
        return 0; /* Not a server or not enough parameters */

    if(!(acptr = find_person(parv[1], NULL)))
        return 0; /* Target user doesn't exist */

    if(!IsULine(sptr))
    {
        if(cptr->from!=acptr->from)
            return 0; /* Wrong direction */
    }

    if(strlen(parv[2]) > HOSTLEN)
        return 0; /* The requested host is too long */

#ifdef USER_HOSTMASKING
    strcpy(acptr->user->mhost, parv[2]); /* Set the requested (masked) host */
    acptr->flags |= FLAGS_SPOOFED;
#else
    /* Save the real hostname if it's a local client */
    if(MyClient(acptr))
    {
        if(!acptr->user->real_oper_host)
        {
            acptr->user->real_oper_host =
                MyMalloc(strlen(acptr->user->host) + 1);
            strcpy(acptr->user->real_oper_host, acptr->user->host);
        }
        if(!acptr->user->real_oper_username)
        {
            acptr->user->real_oper_username =
                MyMalloc(strlen(acptr->user->username) + 1);
            strcpy(acptr->user->real_oper_username, acptr->user->username);
        }
        if(!acptr->user->real_oper_ip)
        {
            acptr->user->real_oper_ip =
                MyMalloc(strlen(acptr->hostip) + 1);
            strcpy(acptr->user->real_oper_ip, acptr->hostip);
        }
        strcpy(acptr->sockhost, parv[2]);
    }
    strcpy(acptr->user->host, parv[2]); /* Set the requested host */
#endif

    /* Pass it to all the other servers */
    sendto_serv_butone(cptr, ":%s SVSHOST %s %s", parv[0], parv[1], parv[2]);

    return 0;
}

/* m_svsnoop - Let services (temporary) disable all o:lines on a given server.
 * parv[1] = server name
 * parv[2] = +/-
 */
int m_svsnoop(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    if(!IsULine(sptr) || parc<3)
        return 0; /* Not a u:lined server or not enough parameters */

    if(hunt_server(cptr, sptr, ":%s SVSNOOP %s :%s", 1, parc, parv) != HUNTED_ISME)
        return 0;

    if(parv[2][0] == '+')
        svsnoop = 1;
    else
        svsnoop = 0;

    return 0;
}

/* m_svstag - Lets services add "tags" to users
 * parv[1] = nick
 * parv[2] = ts
 * parv[3] = [-][raw]
 * parv[4] = required umode(s) to see the tag
 * parv[5] = tag line
 * -Kobi_S 23/03/2013
 */
int m_svstag(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aClient *acptr;
    ServicesTag *servicestag;
    int *s, flag;
    char *m;
    long ts;

    if(!IsServer(sptr) || parc<4)
        return 0; /* Not a server or not enough parameters */

    if(!(acptr = find_person(parv[1], NULL)))
        return 0; /* Target user doesn't exist */

    if(!IsULine(sptr))
    {
        if(cptr->from!=acptr->from)
            return 0; /* Wrong direction (from a non-u:lined server) */
    }

    ts = atol(parv[2]);
    if (ts && (ts != acptr->tsinfo))
        return 0; /* TS info doesn't match the client */

    if(*parv[3] == '-')
    {
        /* Remove all current tags */
        while(acptr->user->servicestag) {
            servicestag = acptr->user->servicestag;
            acptr->user->servicestag = servicestag->next;
            MyFree(servicestag->tag);
            MyFree(servicestag);
        }

        if(parv[3][1] == '\0')
        {
            /* If we only got "SVSTAG nick ts -", we'll just pass it to the other servers (we already cleared the old tags) */
            sendto_serv_butone(cptr, ":%s SVSTAG %s %s %s", parv[0], parv[1], parv[2], parv[3]);
            return 0;
        }
    }

    if(parc<6) return 0; /* Not enough parameters (sanity check) */

    servicestag = acptr->user->servicestag;
    if(servicestag)
    {
        while(servicestag->next) {
            servicestag = servicestag->next;
        }
    }

    if(servicestag)
    {
        /* The user already has a servicestag */
        servicestag->next = MyMalloc(sizeof(ServicesTag));
        servicestag = servicestag->next;
    }
    else
    {
        /* This is the first servicestag for the user... */
        acptr->user->servicestag = MyMalloc(sizeof(ServicesTag));
        servicestag = acptr->user->servicestag;
    }
    servicestag->raw = abs(atoi(parv[3]));
    servicestag->umode = 0;

    /* parse the usermodes (stolen from m_nick) */
    m = &parv[4][0];
    if(*m == '+') m++; /* Skip the first plus... */
    while (*m)
    {
        for (s = user_modes; (flag = *s); s += 2)
            if (*m == *(s + 1))
            {
                servicestag->umode |= flag;
                break;
            }
        m++;
    }

    servicestag->tag =  MyMalloc(strlen(parv[5]) + 1);
    strcpy(servicestag->tag, parv[5]);
    servicestag->next = NULL;

    /* Pass it to all the other servers */
    sendto_serv_butone(cptr, ":%s SVSTAG %s %s %s %s :%s", parv[0], parv[1], parv[2], parv[3], parv[4], parv[5]);

    return 0;
}

/* m_svsuhm
 *   Define the running user host-masking type
 * parv[0] - sender
 * parv[1] - host-masking type (number)
 */
int m_svsuhm(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    if(!IsServer(sptr) || parc < 2)
        return 0;

    if(!IsULine(sptr))
    {
        if(aliastab[AII_OS].client && aliastab[AII_OS].client->from!=cptr->from)
            return 0; /* Wrong direction (from a non-u:lined server) */
    }

    uhm_type = atoi(parv[1]);

    sendto_serv_butone(cptr, ":%s SVSUHM %s", sptr->name, parv[1]);

    return 0;
}

struct FlagList xflags_list[] =
{
  { "NO_NOTICE",         XFLAG_NO_NOTICE         },
  { "NO_CTCP",           XFLAG_NO_CTCP           },
  { "NO_PART_MSG",       XFLAG_NO_PART_MSG       },
  { "NO_QUIT_MSG",       XFLAG_NO_QUIT_MSG       },
  { "EXEMPT_OPPED",      XFLAG_EXEMPT_OPPED      },
  { "EXEMPT_VOICED",     XFLAG_EXEMPT_VOICED     },
  { "EXEMPT_IDENTD",     XFLAG_EXEMPT_IDENTD     },
  { "EXEMPT_REGISTERED", XFLAG_EXEMPT_REGISTERED },
  { "EXEMPT_INVITES",    XFLAG_EXEMPT_INVITES    },
  { "HIDE_MODE_LISTS",   XFLAG_HIDE_MODE_LISTS   },
  { "NO_NICK_CHANGE",    XFLAG_NO_NICK_CHANGE    },
  { "NO_UTF8",           XFLAG_NO_UTF8           },
  { "SJR",               XFLAG_SJR               },
  { "USER_VERBOSE",      XFLAG_USER_VERBOSE      },
  { "USER_VERBOSEV2",    XFLAG_USER_VERBOSE      },
  { "OPER_VERBOSE",      XFLAG_OPER_VERBOSE      },
  { "OPER_VERBOSEV2",    XFLAG_OPER_VERBOSE      },
  { NULL,                0                       }
};

/* m_svsxcf
 *   Control eXtended Channel Flags.
 * parv[0] - sender
 * parv[1] - channel
 * parv[2] - optional setting:value or DEFAULT
 * parv[3] - optional setting:value
 * ...
 * parv[parc-1] - optional setting:value
 *
 * Settings:
 *   JOIN_CONNECT_TIME - Number of seconds the user must be online to be able to join
 *   TALK_CONNECT_TIME - Number of seconds the user must be online to be able to talk on the channel
 *   TALK_JOIN_TIME    - Number of seconds the user must be on the channel to be able to tlak on the channel
 *   MAX_BANS          - Will let us increase the ban limit for specific channels
 *   MAX_INVITES       - Will let us increase the invite limit for specific channels
 *
 * 1/0 (on/off) options:
 *   NO_NOTICE         - no notices can be sent to the channel (on/off)
 *   NO_CTCP           - no ctcps can be sent to the channel (on/off)
 *   NO_PART_MSG       - no /part messages (on/off)
 *   NO_QUIT_MSG       - no /quit messages (on/off)
 *   HIDE_MODE_LISTS   - hide /mode #channel +b/+I/+e lists from non-ops (on/off)
 *   SJR               - enable services join request for this channel (must also be enabled globally) 
 *   NO_NICK_CHANGE    - no nick changes allowed on this channel (on/off)
 *   EXEMPT_OPPED      - exempt opped users (on/off)
 *   EXEMPT_VOICED     - exempt voiced users (on/off)
 *   EXEMPT_IDENTD     - exempt users with identd (on/off)
 *   EXEMPT_REGISTERED - exempt users with umode +r (on/off)
 *   EXEMPT_INVITES    - exempt users who are +I'ed (on/off)
 *   USER_VERBOSE      - send failed command messages to #channel-relay (on/off)
 *   OPER_VERBOSE      - send failed command messages to +f opers (on/off)
 *
 * Special option:
 *   GREETMSG - A message that will be sent when a user joins the channel
 */
int m_svsxcf(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aChannel *chptr;
    char *opt, *value;
    struct FlagList *xflag;
    int i; /* Counter for the option:value loop */
    char pbuf[512];

    if(!IsServer(sptr) || parc < 2)
        return 0;

    if(!(chptr = find_channel(parv[1], NULL)))
        return 0;

    if(!IsULine(sptr))
    {
        if(aliastab[AII_CS].client && aliastab[AII_CS].client->from!=cptr->from)
        {
            /*
             * We don't accept commands from a non-services direction.
             * Also, we remove non-existed xflagss if they come from this location.
             * Note: we don't need to worry about existed xflags on the other side
             * because they will be overrided anyway.
             */
            if(!(chptr->xflags & XFLAG_SET))
            {
                sendto_one(cptr, ":%s SVSXCF %s", me.name, parv[1]);
            }
            return 0; /* Wrong direction (from a non-u:lined server) */
        }
    }

    make_parv_copy(pbuf, parc, parv);
    sendto_serv_butone(cptr, ":%s SVSXCF %s", parv[0], pbuf);

    i = 2;

    if(parc<3 || !strcasecmp(parv[2],"DEFAULT"))
    {
        /* Reset all the extended channel flags back to their defaults... */
        chptr->join_connect_time = 0;
        chptr->talk_connect_time = 0;
        chptr->talk_join_time = 0;
        chptr->max_bans = MAXBANS;
        chptr->max_invites = MAXINVITELIST;
        chptr->xflags = 0;
        if(chptr->greetmsg)
          MyFree(chptr->greetmsg);
        i++;
    }

    for(; i<parc; i++)
    {
        opt = parv[i];
        if((value = strchr(parv[i],':')))
        {
            *value = '\0';
            value++;
            if(!*value) continue; /* Just in case someone does something like option: with no value */
            if(!parv[i][0]) continue; /* Just in case someone does something like :value with no option */
            if(!strcasecmp(opt,"JOIN_CONNECT_TIME")) { chptr->join_connect_time = atoi(value); chptr->xflags |= XFLAG_SET; }
            else if(!strcasecmp(opt,"TALK_CONNECT_TIME")) { chptr->talk_connect_time = atoi(value); chptr->xflags |= XFLAG_SET; }
            else if(!strcasecmp(opt,"TALK_JOIN_TIME")) { chptr->talk_join_time = atoi(value); chptr->xflags |= XFLAG_SET; }
            else if(!strcasecmp(opt,"MAX_BANS")) { chptr->max_bans = atoi(value); chptr->xflags |= XFLAG_SET; }
            else if(!strcasecmp(opt,"MAX_INVITES")) { chptr->max_invites = atoi(value); chptr->xflags |= XFLAG_SET; }
            else if(!strcasecmp(opt,"MAX_MSG_TIME"))
            {
                char *mmt_value;
                mmt_value = opt;

                if ((mmt_value = strchr(value, ':')))
                {
                    *mmt_value = '\0';
                    mmt_value++;

                    chptr->max_messages = atoi(value);
                    chptr->max_messages_time = atoi(mmt_value);
                    chptr->xflags |= XFLAG_SET;
                }
            }

            else
            {
                for(xflag = xflags_list; xflag->option; xflag++)
                {
                    if(!strcasecmp(opt,xflag->option))
                    {
                        if((atoi(value) == 1) || !strcasecmp(value,"on"))
                        {
                          chptr->xflags |= xflag->flag;
                          chptr->xflags |= XFLAG_SET;
                        }
                        else
                          chptr->xflags &= ~(xflag->flag);
                    }
                }
            }
        }
        else if(!strcasecmp(parv[i],"GREETMSG"))
        {
            i++;
            if(i > parc)
            {
                if(chptr->greetmsg)
                  MyFree(chptr->greetmsg);
                break;
            }
            chptr->greetmsg = (char *)MyMalloc(strlen(parv[i]) + 1);
            strcpy(chptr->greetmsg, parv[i]);
            chptr->xflags |= XFLAG_SET;
        }
    }

    return 0;
}

/* m_aj - Approve channel join by services (mostly stolen from bahamut-irctoo)
 * parv[1] = [@+]nick
 * parv[2] = nick TS
 * parv[3] = channel
 * parv[4] = optional channel TS
 * -Kobi_S 16/07/2005
 */
int m_aj(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aClient *acptr;
    aChannel *chptr;
    Link *lp;
    int flags = 0;
    ts_val newts;
    int created;
    char *fnick;
    char *nick;
    ts_val nickts;

    if(!IsULine(sptr))
        return 0; /* Only to be used by u:lined servers */

    if(parc < 4 || *parv[1] == 0)
        return 0;

    fnick = nick = parv[1];
    nickts = atol(parv[2]);

    while(*nick == '@' || *nick == '+')
    {
        switch(*nick)
        {
            case '@':
                flags |= CHFL_CHANOP;
                break;
            case '+':
                flags |= CHFL_VOICE;
                break;
        }
        nick++;
    }

    if(!(acptr = find_client(nick, NULL)))
        return 0; /* Can't find the target nick */

    if(nickts && acptr->tsinfo != nickts)
        return 0; /* tsinfo doesn't match */

    if(*parv[2] == '0' && !atoi(parv[3]))
    {
        if(acptr->user->channel == NULL)
            return 0; /* Target nick isn't on any channels */
        while ((lp = acptr->user->channel))
        {
            chptr = lp->value.chptr;
            sendto_channel_butserv(chptr, acptr, ":%s PART %s", acptr->name, chptr->chname);
            remove_user_from_channel(acptr, chptr);
        }
    }
    else
    {
        if(!check_channelname(acptr, (unsigned char *)parv[3]))
            return 0; /* Invalid channel name */
        chptr = get_channel(acptr, parv[3], CREATE, &created);
        if(!chptr)
            return 0; /* Shouldn't happen! */
        if(parc>4)
        {
            newts = atol(parv[4]);
            if(created || newts < chptr->channelts)
                chptr->channelts = newts;
        }
        if(!IsMember(acptr, chptr))
        {
            add_user_to_channel(chptr, acptr, flags);
            sendto_channel_butserv(chptr, acptr, ":%s JOIN :%s", acptr->name, parv[3]);
            if(MyClient(acptr))
            {
                del_invite(acptr, chptr);
                if(chptr->topic[0] != '\0')
                {
                    sendto_one(acptr, rpl_str(RPL_TOPIC), me.name, acptr->name,
                               chptr->chname, chptr->topic);
                    sendto_one(acptr, rpl_str(RPL_TOPICWHOTIME), me.name, acptr->name,
                               chptr->chname, chptr->topic_nick, chptr->topic_time);
                }
                parv[0] = acptr->name;
                parv[1] = chptr->chname;
                m_names(acptr, acptr, 2, parv);
                if(chptr->greetmsg)
                {
                    sendto_one(sptr, ":%s!%s@%s PRIVMSG %s :%s", Network_Name, Network_Name, DEFAULT_STAFF_ADDRESS, chptr->chname, chptr->greetmsg);
                }
            }
            if(flags)
            {
                if(flags & CHFL_CHANOP)
                 sendto_channel_butserv(chptr, sptr, ":%s MODE %s +o %s", sptr->name,
                                        chptr->chname, acptr->name);
                if(flags & CHFL_VOICE)
                 sendto_channel_butserv(chptr, sptr, ":%s MODE %s +v %s", sptr->name,
                                        chptr->chname, acptr->name);
            }
        }
    }

    /* Pass it to all the other servers... */
    if(parc>4)
        sendto_serv_butone(cptr, ":%s AJ %s %ld %s %ld", sptr->name, fnick, nickts, chptr->chname, chptr->channelts);
    else
        sendto_serv_butone(cptr, ":%s AJ %s %ld %s", sptr->name, fnick, nickts, chptr->chname);

    return 0;
}

/* m_sjr - Check the join (request) with services (mostly stolen from bahamut-irctoo)
 * -Kobi_S 16/07/2005
 */
int m_sjr(aClient *cptr, aClient *sptr, int parc, char *parv[], AliasInfo *ai)
{
    if(MyClient(sptr))
        return 0; /* Don't let local users use it without permission */

    if(parc < 3 || *parv[2] == 0)
        return 0;

    if(!ai->client || ai->client->from == sptr->from)
        return 0; /* Check to avoid message loops when admins get stupid */

    if(parc<4)
        sendto_one(ai->client->from, ":%s SJR %s %s", sptr->name, parv[1], parv[2]);
    else
        sendto_one(ai->client->from, ":%s SJR %s %s :%s", sptr->name, parv[1], parv[2], parv[3]);

    return 0;
}

u_long
memcount_m_services(MCm_services *mc)
{
    mc->file = __FILE__;

    return 0;
}

