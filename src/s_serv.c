/************************************************************************
 *   IRC - Internet Relay Chat, src/s_serv.c
 *   Copyright (C) 1990 Jarkko Oikarinen and
 *                      University of Oulu, Computing Center
 *
 *   See file AUTHORS in IRC package for additional names of
 *   the programmers.
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
#include "numeric.h"
#include "msg.h"
#include "channel.h"
#include "nameser.h"
#include "resolv.h"
#include "dh.h"
#include "zlink.h"
#include "userban.h"
#include "simban.h"
#include "gcosban.h"

#if defined(AIX) || defined(SVR3)
#include <time.h>
#endif
#include <sys/stat.h>
#include <fcntl.h>
#include <utmp.h>
#include "h.h"
#if defined( HAVE_STRING_H )
#include <string.h>
#else
/* older unices don't have strchr/strrchr .. help them out */
#include <strings.h>
#undef strchr
#define strchr index
#endif
#include "fdlist.h"
#include "throttle.h"
#include "clones.h"
#include "memcount.h"

static char buf[BUFSIZE];
extern int  rehashed;
extern int  forked;

/* external variables */

/* external functions */

extern char *smalldate(time_t); /* defined in s_misc.c */
extern void outofmemory(void);  /* defined in list.c */
extern void s_die(void);
extern int  match(char *, char *);      /* defined in match.c */

/* Local function prototypes */

int         send_motd(aClient *, aClient *, int, char **);
void        read_motd(char *);
void        read_shortmotd(char *);

char        motd_last_changed_date[MAX_DATE_STRING]; /* enough room for date */ 

void fakeserver_list(aClient *);
int fakelinkscontrol(int, char **);
void fakelinkserver_update(char *, char *);
void fakeserver_sendserver(aClient *);

int is_luserslocked();
void send_fake_users(aClient *);
void send_fake_lusers(aClient *);
void fakelusers_sendlock(aClient *);

/*
 * m_functions execute protocol messages on this server: *
 * 
 * cptr: 
 ** always NON-NULL, pointing to a *LOCAL* client
 ** structure (with an open socket connected!). This 
 ** is the physical socket where the message originated (or
 ** which caused the m_function to be executed--some
 ** m_functions may call others...). 
 * 
 * sptr:
 ** the source of the message, defined by the
 ** prefix part of the message if present. If not or
 ** prefix not found, then sptr==cptr. 
 * 
 *      *Always* true (if 'parse' and others are working correct): 
 * 
 *      1)      sptr->from == cptr  (note: cptr->from == cptr) 
 * 
 *      2)      MyConnect(sptr) <=> sptr == cptr (e.g. sptr 
 * cannot be a local connection, unless it's actually cptr!). 
 *
 * MyConnect(x) should probably  be defined as (x == x->from) --msa
 * 
 * parc:    
 ** number of variable parameter strings (if zero, 
 ** parv is allowed to be NULL)
 * 
 * parv:    
 ** a NULL terminated list of parameter pointers,
 *** parv[0], sender (prefix string), if not present his points to 
 *** an empty string.
 *
 ** [parc-1]:
 *** pointers to additional parameters 
 *** parv[parc] == NULL, *always* 
 * 
 * note:   it is guaranteed that parv[0]..parv[parc-1] are all
 *         non-NULL pointers.
 */

/*
 * * m_version 
 *      parv[0] = sender prefix 
 *      parv[1] = remote server
 */
int 
m_version(aClient *cptr, aClient *sptr, int parc, char *parv[])
{

    if (hunt_server(cptr, sptr, ":%s VERSION :%s", 1, parc, parv) ==
        HUNTED_ISME)
        send_rplversion(sptr);

    return 0;
}

/*
 * m_squit
 * there are two types of squits: those going downstream (to the target server)
 * and those going back upstream (from the target server).
 * previously, it wasn't necessary to distinguish between these two types of 
 * squits because they neatly echoed back all of the QUIT messages during
 * an squit.  This, however, is no longer practical.
 * 
 * To clarify here, DOWNSTREAM signifies an SQUIT heading towards the target
 * server UPSTREAM signifies an SQUIT which has successfully completed,
 * heading out everywhere.
 *
 * acptr is the server being squitted.
 * a DOWNSTREAM squit is where the notice did not come from acptr->from.
 * an UPSTREAM squit is where the notice DID come from acptr->from.
 *
 *        parv[0] = sender prefix 
 *        parv[1] = server name 
 *        parv[2] = comment
 */
int 
m_squit(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aConnect *aconn;
    char *server;
    aClient *acptr;
    char *comment = (parc > 2) ? parv[2] : sptr->name;

    if (!IsPrivileged(sptr)) 
    {
        sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
        return 0;
    }

    if (parc > 1) 
    {
        server = parv[1];
        /* To accomodate host masking, a squit for a masked server
         * name is expanded if the incoming mask is the same as the
         * server name for that link to the name of link.
         */
        while ((*server == '*') && IsServer(cptr))
        {
            aconn = cptr->serv->aconn;
            if (!aconn)
                break;
            if (!mycmp(server, my_name_for_link(me.name, aconn)))
                server = cptr->name;
            break;                      /* WARNING is normal here */
            /* NOTREACHED */
        }
        /*
         * The following allows wild cards in SQUIT. Only useful when
         * the command is issued by an oper.
         */
        for (acptr = client; (acptr = next_client(acptr, server)); 
             acptr = acptr->next)
            if (IsServer(acptr) || IsMe(acptr))
                break;
        if (acptr && IsMe(acptr)) 
        {
            acptr = cptr;
            server = cptr->sockhost;
        }
    }
    else
    {
        /* This is actually protocol error. But, well, closing the
         * link is very proper answer to that...
         */
        server = cptr->sockhost;
        acptr = cptr;
    }

    if (!acptr) 
    {
        sendto_one(sptr, err_str(ERR_NOSUCHSERVER),
                   me.name, parv[0], server);
        return 0;
    }

    if (MyClient(sptr) && ((!OPCanGRoute(sptr) && !MyConnect(acptr)) || 
                           (!OPCanLRoute(sptr) && MyConnect(acptr)))) 
    {
        sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
        return 0;
    }

    /* If the server is mine, we don't care about upstream or downstream,
       just kill it and do the notice. */
    
    if (MyConnect(acptr)) 
    {
        sendto_gnotice("from %s: Received SQUIT %s from %s (%s)",
                       me.name, acptr->name, get_client_name(sptr, HIDEME),
                       comment);
        sendto_serv_butone(NULL, ":%s GNOTICE :Received SQUIT %s from %s (%s)",
                           me.name, server, get_client_name(sptr, HIDEME),
                           comment);
        
#if defined(USE_SYSLOG) && defined(SYSLOG_SQUIT)
        syslog(LOG_DEBUG, "SQUIT From %s : %s (%s)",
               parv[0], server, comment);
#endif
        /* I am originating this squit! Not cptr! */
        /* ack, but if cptr is squitting itself.. */
        if(cptr == sptr)
        {
            exit_client(&me, acptr, sptr, comment);
            return FLUSH_BUFFER; /* kludge */
        }
        return exit_client(&me, acptr, sptr, comment);
    }
    
    /* the server is not connected to me. Determine whether this is an upstream
       or downstream squit */
    
    if(sptr->from == acptr->from) /* upstream */
    {
        sendto_realops_lev(DEBUG_LEV,
                           "Exiting server %s due to upstream squit by %s [%s]",
                           acptr->name, sptr->name, comment);
        return exit_client(cptr, acptr, sptr, comment);
    }

    /* fallthrough: downstream */

    if(!(IsUnconnect(acptr->from))) /* downstream not unconnect capable */
    {
        sendto_realops_lev(DEBUG_LEV,
                    "Exiting server %s due to non-unconnect server %s [%s]",
                    acptr->name, acptr->from->name, comment);
        return exit_client(&me, acptr, sptr, comment);
    }

    
    sendto_realops_lev(DEBUG_LEV, "Passing along SQUIT for %s by %s [%s]",
                       acptr->name, sptr->name, comment);
    sendto_one(acptr->from, ":%s SQUIT %s :%s", parv[0], acptr->name, comment);

    return 0;
}

/*
 * m_svinfo 
 *       parv[0] = sender prefix 
 *       parv[1] = TS_CURRENT for the server 
 *       parv[2] = TS_MIN for the server 
 *       parv[3] = server is standalone or connected to non-TS only 
 *       parv[4] = server's idea of UTC time
 */
int m_svinfo(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    time_t      deltat, tmptime, theirtime;
    
    if (!IsServer(sptr) || !MyConnect(sptr))
        return 0;

    if(parc == 2 && mycmp(parv[1], "ZIP") == 0)
    {
        SetZipIn(sptr);
        sptr->serv->zip_in = zip_create_input_session();
        sendto_gnotice("from %s: Input from %s is now compressed",
                       me.name, get_client_name(sptr, HIDEME));
        sendto_serv_butone(sptr,
                           ":%s GNOTICE :Input from %s is now compressed",
                           me.name, get_client_name(sptr, HIDEME));
        return ZIP_NEXT_BUFFER;
    }
    
    if(parc < 5 || !DoesTS(sptr))
        return 0;
    
    if (TS_CURRENT < atoi(parv[2]) || atoi(parv[1]) < TS_MIN) 
    {
        /* a server with the wrong TS version connected; since we're
         * TS_ONLY we can't fall back to the non-TS protocol so we drop
         * the link  -orabidoo
         */
        sendto_ops("Link %s dropped, wrong TS protocol version (%s,%s)",
                   get_client_name(sptr, HIDEME), parv[1], parv[2]);
        return exit_client(sptr, sptr, sptr, "Incompatible TS version");
    }
    
    tmptime = time(NULL);
    theirtime = atol(parv[4]);
    deltat = abs(theirtime - tmptime);
    
    if (deltat > tsmaxdelta) 
    {
        sendto_gnotice("from %s: Link %s dropped, excessive TS delta (my "
                       "TS=%d, their TS=%d, delta=%d)",
                       me.name, get_client_name(sptr, HIDEME), tmptime,
                       theirtime, deltat);
        sendto_serv_butone(sptr, ":%s GNOTICE :Link %s dropped, excessive "
                           "TS delta (delta=%d)",
                           me.name, get_client_name(sptr, HIDEME), deltat);
        return exit_client(sptr, sptr, sptr, "Excessive TS delta");
    }

    if (deltat > tswarndelta) 
    {
        sendto_realops("Link %s notable TS delta (my TS=%d, their TS=%d, "
                       "delta=%d)", get_client_name(sptr, HIDEME), tmptime,
                       theirtime, deltat);
    }

    return 0;
}

/* 
 * m_burst
 *      parv[0] = sender prefix
 *      parv[1] = SendQ if an EOB
 */
int 
m_burst(aClient *cptr, aClient *sptr, int parc, char *parv[]) 
{
  
    if (!IsServer(sptr) || sptr != cptr || parc > 2 || !IsBurst(sptr))
        return 0;
    if (parc == 2) { /* This is an EOB */
        sptr->flags &= ~(FLAGS_EOBRECV);
        if (sptr->flags & (FLAGS_SOBSENT|FLAGS_BURST)) return 0;
        
        /* we've already sent our EOB.. we synched first
         * no need to check IsBurst because we shouldn't receive a BURST if 
         * they're not BURST capab
         */
        
        sendto_gnotice("from %s: synch to %s in %d %s at %s sendq", me.name,
                       *parv, (timeofday-sptr->firsttime), 
                       (timeofday-sptr->firsttime)==1?"sec":"secs", parv[1]);
        sendto_serv_butone(NULL,
                           ":%s GNOTICE :synch to %s in %d %s at %s sendq",
                           me.name, sptr->name, (timeofday-sptr->firsttime),
                           (timeofday-sptr->firsttime)==1?"sec":"secs",
                           parv[1]);
        
    }
    else
    {
        sptr->flags |= FLAGS_EOBRECV;
    }
    return 0;
}

/*
 * * m_info 
 *      parv[0] = sender prefix 
 *      parv[1] = servername
 */
int 
m_info(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    char      **text = infotext;

    static time_t last_used = 0L;
    if (hunt_server(cptr,sptr,":%s INFO :%s",1,parc,parv) == HUNTED_ISME) 
    {
        if(!IsULine(sptr) && !IsServer(sptr))
        {
            sendto_realops_lev(SPY_LEV, "INFO requested by %s (%s@%s) [%s]",
                               sptr->name, sptr->user->username, sptr->user->host,
                               sptr->user->server);
                        
            if (!IsAnOper(sptr)) 
            {
                if (IsSquelch(sptr)) {
                    sendto_one(sptr, rpl_str(RPL_ENDOFINFO), me.name, parv[0]);
                    return 0;
                }
                if (!MyConnect(sptr))
                    return 0;
                if ((last_used + MOTD_WAIT) > NOW) 
                    return 0;
                else 
                    last_used = NOW;
            }
        }
        while (*text)
            sendto_one(sptr, rpl_str(RPL_INFO),
                       me.name, parv[0], *text++);
                        
        sendto_one(sptr, rpl_str(RPL_INFO), me.name, parv[0], "");

        /* I am -definately- going to come up with a replacement for this! */
        /* you didnt, so i removed it.. kinda stupid anyway.  -epi */
        
        sendto_one(sptr,
                   ":%s %d %s :Birth Date: %s, compile #%s",
                   me.name, RPL_INFO, parv[0], creation, generation);
        sendto_one(sptr, ":%s %d %s :On-line since %s",
                   me.name, RPL_INFO, parv[0],
                   myctime(me.firsttime));
        sendto_one(sptr, rpl_str(RPL_ENDOFINFO), me.name, parv[0]);
    }
 
    return 0;
}

/*
 * * m_links 
 *      parv[0] = sender prefix 
 *      parv[1] = servername mask 
 * or 
 *      parv[0] = sender prefix 
 *      parv[1] = server to query 
 *      parv[2] = servername mask
 */
int 
m_links(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    char       *mask;
    aClient    *acptr;
    char        clean_mask[(2 * HOSTLEN) + 1];
    char       *s;
    char       *d;
    int         n;

    /* reject non-local requests */
    if (IsServer(sptr) || (!IsAnOper(sptr) && !MyConnect(sptr)))
        return 0;

    mask = (parc < 2) ? NULL : parv[1];
    
    /*
     * * sigh* Before the kiddies find this new and exciting way of
     * * annoying opers, lets clean up what is sent to all opers
     * * -Dianora
     */

    if (mask) 
    {      /* only necessary if there is a mask */
        s = mask;
        d = clean_mask;
        n = (2 * HOSTLEN) - 2;
        while (*s && n > 0) 
        {
            /* Is it a control character? */
            if ((unsigned char) *s < (unsigned char) ' ') 
            {
                *d++ = '^';
                /* turn it into a printable */
                *d++ = (char) ((unsigned char)*s + 0x40); 
                s++;
                n -= 2;
            }
            else if ((unsigned char) *s > (unsigned char) '~') 
            {
                *d++ = '.';
                s++;
                n--;
            }
            else 
            {
                *d++ = *s++;
                n--;
            }
        }
        *d = '\0';
    }

    if (MyConnect(sptr))
        sendto_realops_lev(SPY_LEV,
                           "LINKS %s requested by %s (%s@%s) [%s]",
                           mask ? clean_mask : "all",
                           sptr->name, sptr->user->username,
                           sptr->user->host, sptr->user->server);

    if(!(confopts & FLAGS_SHOWLINKS) && !IsAnOper(sptr))
        fakeserver_list(sptr);
    else
    for (acptr = client, (void) collapse(mask); acptr; acptr = acptr->next) 
    {
        if (!IsServer(acptr) && !IsMe(acptr))
            continue;
        if (!BadPtr(mask) && match(mask, acptr->name))
            continue;
#ifdef HIDEULINEDSERVS
        if (!IsOper(sptr) && IsULine(acptr))
            continue;
#endif
        sendto_one(sptr, rpl_str(RPL_LINKS),
                   me.name, parv[0], acptr->name, acptr->serv->up,
                   acptr->hopcount, (acptr->info[0] ? acptr->info :
                                     "(Unknown Location)"));
    }
    sendto_one(sptr, rpl_str(RPL_ENDOFLINKS), me.name, parv[0],
               BadPtr(mask) ? "*" : clean_mask);
    return 0;
}

/*
 * * m_users 
 *        parv[0] = sender prefix 
 *        parv[1] = servername
 */
int 
m_users(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    if (hunt_server(cptr, sptr, ":%s USERS :%s", 1, parc, parv) == HUNTED_ISME) 
    {
        if(is_luserslocked())
        {
            send_fake_users(sptr);
            return 0;
        }
        /* No one uses this any more... so lets remap it..   -Taner */
        sendto_one(sptr, rpl_str(RPL_LOCALUSERS), me.name, parv[0],
                   Count.local, Count.max_loc);
        sendto_one(sptr, rpl_str(RPL_GLOBALUSERS), me.name, parv[0],
                   Count.total, Count.max_tot);
    }
    return 0;
}

/*
 * * Note: At least at protocol level ERROR has only one parameter, 
 * although this is called internally from other functions  --msa 
 *
 *      parv[0] = sender prefix 
 *      parv[*] = parameters
 */
int 
m_error(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    char   *para;

    para = (parc > 1 && *parv[1] != '\0') ? parv[1] : "<>";

    Debug((DEBUG_ERROR, "Received ERROR message from %s: %s",
           sptr->name, para));
    /*
     * * Ignore error messages generated by normal user clients 
     * (because ill-behaving user clients would flood opers screen
     * otherwise). Pass ERROR's from other sources to the local
     * operator...
     */
    if (IsPerson(cptr) || IsUnknown(cptr))
        return 0;
    if (cptr == sptr)
        sendto_ops("ERROR :from %s -- %s",
                   get_client_name(cptr, HIDEME), para);
    else
        sendto_ops("ERROR :from %s via %s -- %s", sptr->name,
                   get_client_name(cptr, HIDEME), para);
    return 0;
}

/*
 * m_help
 * parv[0] = sender prefix
 * 
 * Forward help requests to HelpServ if defined, and is invoked
 * by non-opers, otherwise sends opers.txt to opers (if present),
 * or sends a big list of commands to non-opers (and opers if
 * opers.txt is not present). -srd
 */
int 
m_help(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    int         i;
    aMotd *helpfile_ptr;

    static time_t last_used = 0L;

#ifdef HELP_FORWARD_HS
    if (!IsAnOper(sptr))
    {
       if (parc < 2 || *parv[1] == '\0')
       {
          sendto_one(sptr, ":%s NOTICE %s :For a list of help topics, type "
                     "/%s %s", me.name, sptr->name, HELPSERV, DEF_HELP_CMD);
          return -1;
       }
        return m_aliased(cptr, sptr, parc, parv, &aliastab[AII_HS]);
 
       return 0;
    }
#endif
    
    if (!IsAnOper(sptr))
    {
       /* reject non local requests */
       if ((last_used + MOTD_WAIT) > NOW)
          return 0;   
       else
          last_used = NOW;
    }

    if (!IsAnOper(sptr) || (helpfile == (aMotd *) NULL))
    {
        for (i = 0; msgtab[i].cmd; i++)
            sendto_one(sptr, ":%s NOTICE %s :%s",
                       me.name, parv[0], msgtab[i].cmd);
        return 0;
    }
       
    helpfile_ptr = helpfile;
    while (helpfile_ptr)
    {
        sendto_one(sptr,
                   ":%s NOTICE %s :%s",
                   me.name, parv[0], helpfile_ptr->line);
        helpfile_ptr = helpfile_ptr->next;
    }
       
    return 0;
}

/*
 * parv[0] = sender parv[1] = host/server mask. 
 * parv[2] = server to query
 * 
 * 199970918 JRL hacked to ignore parv[1] completely and require parc > 3
 * to cause a force
 *
 * Now if parv[1] is anything other than *, it forces a recount.
 *    -Quension [May 2005]
 */
int 
m_lusers(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    int send_lusers(aClient *, aClient *, int, char **);

    if (parc > 2) 
    {
        if (hunt_server(cptr, sptr, ":%s LUSERS %s :%s", 2, parc, parv) !=
            HUNTED_ISME)
            return 0;
    }

    if(!IsAnOper(sptr) && is_luserslocked())
    {
       send_fake_lusers(sptr);
       return 0;
    }           

    return send_lusers(cptr,sptr,parc,parv);
}

/*
 * send_lusers
 *     parv[0] = sender
 *     parv[1] = anything but "*" to force a recount
 *     parv[2] = server to query
 */
int send_lusers(aClient *cptr, aClient *sptr, int parc, char *parv[]) 
{
    /* forced recount */
    if (IsAnOper(sptr) && (parc > 1) && (*parv[1] != '*')) 
    {
        int s_count = 0;
        int c_count = 0;
        int u_count = 0;
        int i_count = 0;
        int o_count = 0;
        int m_client = 0;
        int m_server = 0;
        int m_ulined = 0;
        aClient *acptr;
        
        for (acptr = client; acptr; acptr = acptr->next) 
        {
            switch (acptr->status) 
            {
            case STAT_SERVER:
                if (MyConnect(acptr))
                {
                    m_server++;
                    if(IsULine(acptr))
                        m_ulined++;
                }
            case STAT_ME:
                s_count++;
                break;
            case STAT_CLIENT:
                if (IsAnOper(acptr))
                    o_count++;
#ifdef  SHOW_INVISIBLE_LUSERS
                if (MyConnect(acptr))
                    m_client++;
                if (!IsInvisible(acptr))
                    c_count++;
                else
                    i_count++;
#else
                if (MyConnect(acptr)) 
                {
                    if (IsInvisible(acptr)) 
                    {
                        if (IsAnOper(sptr))
                            m_client++;
                    }
                    else
                        m_client++;
                }
                if (!IsInvisible(acptr))
                    c_count++;
                else
                    i_count++;
#endif
                break;
            default:
                u_count++;
                break;
            }
        }

        /* sanity check */
        if (m_server != Count.myserver)
        {
            sendto_realops_lev(DEBUG_LEV, "Local server count off by %d",
                               Count.myserver - m_server);
            Count.myserver = m_server;
        }
        if (m_ulined != Count.myulined)
        {
            sendto_realops_lev(DEBUG_LEV, "Local superserver count off by %d",
                               Count.myulined - m_ulined);
            Count.myulined = m_ulined;
        }
        if (s_count != Count.server)
        {
            sendto_realops_lev(DEBUG_LEV, "Server count off by %d",
                               Count.server - s_count);
            Count.server = s_count;
        }
        if (i_count != Count.invisi)
        {
            sendto_realops_lev(DEBUG_LEV, "Invisible client count off by %d",
                               Count.invisi - i_count);
            Count.invisi = i_count;
        }
        if ((c_count + i_count) != Count.total)
        {
            sendto_realops_lev(DEBUG_LEV, "Total client count off by %d",
                               Count.total - (c_count + i_count));
            Count.total = c_count + i_count;
        }
        if (m_client != Count.local)
        {
            sendto_realops_lev(DEBUG_LEV, "Local client count off by %d",
                               Count.local - m_client);
            Count.local = m_client;
        }
        if (o_count != Count.oper)
        {
            sendto_realops_lev(DEBUG_LEV, "Oper count off by %d",
                               Count.oper - o_count);
            Count.oper = o_count;
        }
        if (u_count != Count.unknown)
        {
            sendto_realops_lev(DEBUG_LEV, "Unknown connection count off by %d",
                               Count.unknown - u_count);
            Count.unknown = u_count;
        }
    }   /* Recount loop */

    /* save stats */
    if ((timeofday - last_stat_save) > 3600)
    {
        FILE *fp;
        char tmp[PATH_MAX];
        
        last_stat_save = timeofday;
        ircsprintf(tmp, "%s/.maxclients", dpath);
        fp = fopen(tmp, "w");
        if (fp != NULL)
        {
            fprintf(fp, "%d %d %li %li %li %ld %ld %ld %ld", Count.max_loc,
                    Count.max_tot, Count.weekly, Count.monthly,
                    Count.yearly, Count.start, Count.week, Count.month,
                    Count.year);
            fclose(fp);
            sendto_realops_lev(DEBUG_LEV, "Saved maxclient statistics");
        }
    }
    
    
#ifndef SHOW_INVISIBLE_LUSERS
    if (IsAnOper(sptr) && Count.invisi)
#endif
        sendto_one(sptr, rpl_str(RPL_LUSERCLIENT), me.name, parv[0],
                   Count.total - Count.invisi, Count.invisi, Count.server);
#ifndef SHOW_INVISIBLE_LUSERS
    else
        sendto_one(sptr,
                   ":%s %d %s :There are %d users on %d servers", me.name,
                   RPL_LUSERCLIENT, parv[0], Count.total - Count.invisi,
                   Count.server);
#endif

    if (Count.oper)
        sendto_one(sptr, rpl_str(RPL_LUSEROP), me.name, parv[0], Count.oper);

    if (IsAnOper(sptr) && Count.unknown)
        sendto_one(sptr, rpl_str(RPL_LUSERUNKNOWN), me.name, parv[0],
                   Count.unknown);
    
    /* This should be ok */
    if (Count.chan > 0)
        sendto_one(sptr, rpl_str(RPL_LUSERCHANNELS),
                   me.name, parv[0], Count.chan);
    sendto_one(sptr, rpl_str(RPL_LUSERME),
#ifdef HIDEULINEDSERVS
               me.name, parv[0], Count.local, 
               IsOper(sptr) ? Count.myserver : Count.myserver - Count.myulined);
#else
               me.name, parv[0], Count.local, Count.myserver);
#endif

    sendto_one(sptr, rpl_str(RPL_LOCALUSERS), me.name, parv[0],
                   Count.local, Count.max_loc);
    sendto_one(sptr, rpl_str(RPL_GLOBALUSERS), me.name, parv[0],
               Count.total, Count.max_tot);
    return 0;
}

/***********************************************************************
 * m_connect() - Added by Jto 11 Feb 1989
 ***********************************************************************/
/*
 * * m_connect 
 *      parv[0] = sender prefix 
 *      parv[1] = servername 
 *      parv[2] = port number 
 *      parv[3] = remote server
 */
int 
m_connect(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    int         port, tmpport, retval;
    aConnect   *aconn;
    aClient    *acptr;

    if (!IsPrivileged(sptr))
    {
        sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
        return -1;
    }
    
    if ((MyClient(sptr) && !OPCanGRoute(sptr) && parc > 3) ||
        (MyClient(sptr) && !OPCanLRoute(sptr) && parc <= 3))
    {
        sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
        return 0;
    }
    
    if (hunt_server(cptr, sptr, ":%s CONNECT %s %s :%s",
                    3, parc, parv) != HUNTED_ISME)
        return 0;

    if (parc < 2 || *parv[1] == '\0') 
    {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
                   me.name, parv[0], "CONNECT");
        return -1;
    }

    if ((acptr = find_server(parv[1], NULL)))
    {
        sendto_one(sptr, ":%s NOTICE %s :Connect: Server %s %s %s.",
                   me.name, parv[0], parv[1], "already exists from",
                   acptr->from->name);
        return 0;
    }

    if (!(aconn = find_aConnect(parv[1])))
    {
        sendto_one(sptr, "NOTICE %s :Connect: No Connect block found for %s.",
                   parv[0], parv[1]);
        return 0;
    }
    /*
     * * Get port number from user, if given. If not specified, use
     * the default form configuration structure. If missing from
     * there, then use the precompiled default.
     */
    tmpport = port = aconn->port;
    if (parc > 2 && !BadPtr(parv[2])) 
    {
        if ((port = atoi(parv[2])) <= 0) 
        {
            sendto_one(sptr,
                       "NOTICE %s :Connect: Illegal port number",
                       parv[0]);
            return 0;
        }
    }
    else if (port <= 0 && (port = PORTNUM) <= 0) 
    {
        sendto_one(sptr, ":%s NOTICE %s :Connect: missing port number",
                   me.name, parv[0]);
        return 0;
    }
    /*
     * * Notify all operators about remote connect requests
     * Let's notify about local connects, too. - lucas
     * sendto_ops_butone -> sendto_serv_butone(), like in df. -mjs
     */
    sendto_gnotice("from %s: %s CONNECT %s %s from %s",
                   me.name,  IsAnOper(cptr) ? "Local" : "Remote", 
                   parv[1], parv[2] ? parv[2] : "",
                   sptr->name);
    sendto_serv_butone(NULL, ":%s GNOTICE :%s CONNECT %s %s from %s", 
                       me.name, IsAnOper(cptr) ? "Local" : "Remote",
                       parv[1], parv[2] ? parv[2] : "",
                       sptr->name);

#if defined(USE_SYSLOG) && defined(SYSLOG_CONNECT)
    syslog(LOG_DEBUG, "CONNECT From %s : %s %s", parv[0], parv[1], 
           parv[2] ? parv[2] : "");
#endif
    
    aconn->port = port;
    switch (retval = connect_server(aconn, sptr, NULL))
    {
        case 0:
            sendto_one(sptr, ":%s NOTICE %s :*** Connecting to %s.",
                       me.name, parv[0], aconn->name);
            break;
        case -1:
            sendto_one(sptr, ":%s NOTICE %s :*** Couldn't connect to %s.",
                       me.name, parv[0], aconn->name);
            break;
        case -2:
            sendto_one(sptr, ":%s NOTICE %s :*** Host %s is unknown.",
                       me.name, parv[0], aconn->name);
            break;
        default:
            sendto_one(sptr, ":%s NOTICE %s :*** Connection to %s failed: %s",
                       me.name, parv[0], aconn->name, strerror(retval));
    }
    aconn->port = tmpport;
    return 0;
}

/*
 * * m_wallops (write to *all* opers currently online) 
 *      parv[0] = sender prefix 
 *      parv[1] = message text
 */
int 
m_wallops(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    char       *message = parc > 1 ? parv[1] : NULL;
    
    if (BadPtr(message)) 
    {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
                   me.name, parv[0], "WALLOPS");
        return 0;
    }
    
    if (!IsServer(sptr) && MyConnect(sptr) && !OPCanWallOps(sptr)) 
    {
        sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
        return (0);
    }
    
    sendto_wallops_butone(IsServer(cptr) ? cptr : NULL, sptr,
                          ":%s WALLOPS :%s", parv[0], message);
    return 0;
}

/*
 * * m_locops (write to *all* local opers currently online) 
 *      parv[0] = sender prefix 
 *      parv[1] = message text
 */
int 
m_locops(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    char       *message = parc > 1 ? parv[1] : NULL;

    if (BadPtr(message)) 
    {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
                   me.name, parv[0], "LOCOPS");
        return 0;
    }

    if (!IsServer(sptr) && MyConnect(sptr) && !OPCanLocOps(sptr)) 
    {
        sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
        return (0);
    }
    sendto_locops("from %s: %s", parv[0], message);
    return (0);
}

/*
 * m_goper  (Russell) sort of like wallop, but only to ALL +o clients
 * on every server. 
 *      parv[0] = sender prefix 
 *      parv[1] = message text 
 * Taken from df465, ported to hybrid. -mjs
 */
int 
m_goper(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    char       *message = parc > 1 ? parv[1] : NULL;

    if (BadPtr(message)) 
    {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
                   me.name, parv[0], "GOPER");
        return 0;
    }
    if (!IsServer(sptr) || !IsULine(sptr)) 
    {
        sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
        return 0;
    }

    sendto_serv_butone_super(cptr, 0, ":%s GOPER :%s", parv[0], message);
    sendto_ops("from %s: %s", parv[0], message);
    return 0;
}

/*
 * m_gnotice  (Russell) sort of like wallop, but only to +g clients on *
 * this server. 
 *      parv[0] = sender prefix 
 *      parv[1] = message text 
 * ported from df465 to hybrid -mjs
 *
 * This function itself doesnt need any changes for the move to +n routing
 * notices, to sendto takes care of it.  Now only sends to +n clients -epi
 */
int 
m_gnotice(aClient *cptr, aClient *sptr, int parc, char *parv[])
{

    char       *message = parc > 1 ? parv[1] : NULL;
    
    if (BadPtr(message)) 
    {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
                   me.name, parv[0], "GNOTICE");
        return 0;
    }
    if (!IsServer(sptr) && MyConnect(sptr)) 
    {
        sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
        return 0;
    }

    sendto_serv_butone_super(cptr, 0, ":%s GNOTICE :%s", parv[0], message);
    sendto_gnotice("from %s: %s", parv[0], message);
    return 0;
}

int 
m_globops(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    char       *message = parc > 1 ? parv[1] : NULL;

    /* a few changes, servers weren't able to globop -mjs */

    if (BadPtr(message)) 
    {
        if (MyClient(sptr))
            sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
                       me.name, parv[0], "GLOBOPS");
        return 0;
    }

    if (MyClient(sptr) && !OPCanGlobOps(sptr)) 
    {
        sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
        return 0;
    }
    if (strlen(message) > TOPICLEN)
        message[TOPICLEN] = '\0';
    sendto_serv_butone_super(cptr, 0, ":%s GLOBOPS :%s", parv[0], message);
    send_globops("from %s: %s", parv[0], message);
    return 0;
}

int 
m_chatops(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    char       *message = parc > 1 ? parv[1] : NULL;

    if (BadPtr(message)) 
    {
        if (MyClient(sptr))
            sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
                       me.name, parv[0], "CHATOPS");
        return 0;
    }

    if (MyClient(sptr) && (!IsAnOper(sptr) || !SendChatops(sptr))) 
    {
        sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
        return 0;
    }
    
    if (strlen(message) > TOPICLEN)
        message[TOPICLEN] = '\0';
    sendto_serv_butone_super(cptr, 0, ":%s CHATOPS :%s", parv[0], message);
    send_chatops("from %s: %s", parv[0], message);
    return 0;
}

/*
 * * m_time 
 *       parv[0] = sender prefix 
 *       parv[1] = servername
 */

int 
m_time(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    if (hunt_server(cptr, sptr, ":%s TIME :%s", 1, parc, parv) == HUNTED_ISME)
        sendto_one(sptr, rpl_str(RPL_TIME), me.name,
                   parv[0], me.name, NOW, date((long) 0));
    return 0;
}

/*
 * * m_admin 
 *        parv[0] = sender prefix 
 *        parv[1] = servername
 */
int 
m_admin(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    
    if (hunt_server(cptr, sptr, ":%s ADMIN :%s", 1, parc, parv) != HUNTED_ISME)
        return 0;
    
    if (IsPerson(sptr))
        sendto_realops_lev(SPY_LEV, "ADMIN requested by %s (%s@%s) [%s]",
                           sptr->name, sptr->user->username, sptr->user->host,
                           sptr->user->server);
    
        sendto_one(sptr, rpl_str(RPL_ADMINME),
                   me.name, parv[0], me.name);
        sendto_one(sptr, rpl_str(RPL_ADMINLOC1),
                   me.name, parv[0], MeLine->admin[0] ? MeLine->admin[0] : "");
        sendto_one(sptr, rpl_str(RPL_ADMINLOC2),
                   me.name, parv[0], MeLine->admin[1] ? MeLine->admin[1] : "");
        sendto_one(sptr, rpl_str(RPL_ADMINEMAIL),
                   me.name, parv[0], MeLine->admin[2] ? MeLine->admin[2] : "");
    return 0;
}

/* Shadowfax's server side, anti flood code */
#ifdef FLUD
extern int  flud_num;
extern int  flud_time;
extern int  flud_block;
#endif

#ifdef ANTI_SPAMBOT
extern int  spam_num;
extern int  spam_time;
#endif

/* m_set - set options while running */
int 
m_set(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    char       *command;

    if (!MyClient(sptr) || !IsOper(sptr)) 
    {
        sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
        return 0;
    }

    if (parc > 1) 
    {
        command = parv[1];
        if (!strncasecmp(command, "MAX", 3)) 
        {
            if (parc > 2) 
            {
                int new_value = atoi(parv[2]);

                if (new_value > MAX_ACTIVECONN) 
                {
                    sendto_one(sptr,
                               ":%s NOTICE %s :You cannot set MAXCLIENTS "
                               "above the compiled FD limit (%d)", me.name,
                               parv[0], MAX_ACTIVECONN);
                    return 0;
                }
                if (new_value < 0)
                    new_value = 0;
                MAXCLIENTS = new_value;
                sendto_one(sptr, ":%s NOTICE %s :NEW MAXCLIENTS = %d (Current "
                           "= %d)", me.name, parv[0], MAXCLIENTS, Count.local);
                sendto_realops("%s!%s@%s set new MAXCLIENTS to %d "
                               "(%d current)", parv[0], sptr->user->username,
                               sptr->sockhost, MAXCLIENTS, Count.local);
                return 0;
            }
            sendto_one(sptr, ":%s NOTICE %s :MAXCLIENTS is %d (%d online)",
                       me.name, parv[0], MAXCLIENTS, Count.local);
            return 0;
        }
#ifdef FLUD
        else if (!strncasecmp(command, "FLUDNUM", 7)) 
        {
            if (parc > 2) 
            {
                int newval = atoi(parv[2]);
                if (newval <= 0) 
                {
                    sendto_one(sptr, ":%s NOTICE %s :flud NUM must be > 0",
                               me.name, parv[0]);
                    return 0;
                }
                flud_num = newval;
                sendto_ops("%s has changed flud NUM to %i", parv[0], flud_num);
                sendto_one(sptr, ":%s NOTICE %s :flud NUM is now set to %i",
                           me.name, parv[0], flud_num);
                return 0;
            }
            else
            {
                sendto_one(sptr, ":%s NOTICE %s :flud NUM is currently %i",
                           me.name, parv[0], flud_num);
                return 0;
            }
        }
        else if (!strncasecmp(command, "FLUDTIME", 8)) 
        {
            if (parc > 2) 
            {
                int newval = atoi(parv[2]);
                if (newval <= 0) 
                {
                    sendto_one(sptr, ":%s NOTICE %s :flud TIME must be > 0",
                               me.name, parv[0]);
                    return 0;
                }
                flud_time = newval;
                sendto_ops("%s has changed flud TIME to %i", parv[0],
                           flud_time);
                sendto_one(sptr, ":%s NOTICE %s :flud TIME is now set to %i",
                           me.name, parv[0], flud_time);
                return 0;
            }
            else 
            {
                sendto_one(sptr, ":%s NOTICE %s :flud TIME is currently %i",
                           me.name, parv[0], flud_time);
                return 0;
            }
        }
        else if (!strncasecmp(command, "FLUDBLOCK", 9)) 
        {
            if (parc > 2) 
            {
                int newval = atoi(parv[2]);
                if (newval < 0) 
                {
                    sendto_one(sptr, ":%s NOTICE %s :flud BLOCK must be >= 0",
                               me.name, parv[0]);
                    return 0;
                }
                flud_block = newval;
                if (flud_block == 0)
                {
                    sendto_ops("%s has disabled flud detection/protection",
                               parv[0]);
                    sendto_one(sptr, ":%s NOTICE %s :flud detection disabled",
                               me.name, parv[0]);
                }
                else
                {
                    sendto_ops("%s has changed flud BLOCK to %i",
                               parv[0], flud_block);
                    sendto_one(sptr, ":%s NOTICE %s :flud BLOCK is now set "
                               "to %i", me.name, parv[0], flud_block);
                }
                return 0;
            }
            else
            {
                sendto_one(sptr, ":%s NOTICE %s :flud BLOCK is currently %i",
                           me.name, parv[0], flud_block);
                return 0;
            }
        }
#endif
#ifdef ANTI_SPAMBOT
        /* int spam_time = MIN_JOIN_LEAVE_TIME; 
         * int spam_num = MAX_JOIN_LEAVE_COUNT;
         */
        else if (!strncasecmp(command, "SPAMNUM", 7)) 
        {
            if (parc > 2) 
            {
                int newval = atoi(parv[2]);
                if (newval <= 0) 
                {
                    sendto_one(sptr, ":%s NOTICE %s :spam NUM must be > 0",
                               me.name, parv[0]);
                    return 0;
                }
                if (newval < MIN_SPAM_NUM)
                    spam_num = MIN_SPAM_NUM;
                else
                    spam_num = newval;
                sendto_ops("%s has changed spam NUM to %i", parv[0], spam_num);
                sendto_one(sptr, ":%s NOTICE %s :spam NUM is now set to %i",
                           me.name, parv[0], spam_num);
                return 0;
            }
            else 
            {
                sendto_one(sptr, ":%s NOTICE %s :spam NUM is currently %i",
                           me.name, parv[0], spam_num);
                return 0;
            }
        }
        else if (!strncasecmp(command, "SPAMTIME", 8)) 
        {
            if (parc > 2) 
            {
                int newval = atoi(parv[2]);
                if (newval <= 0) 
                {
                    sendto_one(sptr, ":%s NOTICE %s :spam TIME must be > 0",
                               me.name, parv[0]);
                    return 0;
                }
                if (newval < MIN_SPAM_TIME)
                    spam_time = MIN_SPAM_TIME;
                else
                    spam_time = newval;
                sendto_ops("%s has changed spam TIME to %i", parv[0],
                           spam_time);
                sendto_one(sptr, ":%s NOTICE %s :SPAM TIME is now set to %i",
                           me.name, parv[0], spam_time);
                return 0;
            }
            else 
            {
                sendto_one(sptr, ":%s NOTICE %s :spam TIME is currently %i",
                           me.name, parv[0], spam_time);
                return 0;
            }
        }

#endif
#ifdef THROTTLE_ENABLE
        else if (!strncasecmp(command, "THROTTLE", 8))  
        {
           char *changed = NULL;
           char *to = NULL;
           /* several values available:
            * ENABLE [on|off] to enable the code
            * COUNT [n] to set a max count, must be > 1
            * TIME [n] to set a max time before expiry, must be > 5
            * RECORDTIME [n] to set a time for the throttle records to expire
            * HASH [n] to set the size of the hash table, must be bigger than
            *          the default */


           /* only handle individual settings if parc > 3 (they're actually
            * changing stuff) */
           if (parc > 3) {
               if (!strcasecmp(parv[2], "ENABLE"))  {
                  changed = "ENABLE";
                  if (ToLower(*parv[3]) == 'y' || !strcasecmp(parv[3], "on")) {
                     throttle_enable = 1;
                     to = "ON";
                  } else if (ToLower(*parv[3]) == 'n' ||
                           !strcasecmp(parv[3], "off")) {
                     throttle_enable = 0;
                     to = "OFF";
                  }
               } else if (!strcasecmp(parv[2], "COUNT")) {
                  int cnt;
                  changed = "COUNT";
                  cnt = atoi(parv[3]);
                  if (cnt > 1) {
                     throttle_tcount = cnt;
                     to = parv[3];
                  }
               } else if (!strcasecmp(parv[2], "TIME")) {
                  int cnt;
                  changed = "TIME";
                  cnt = atoi(parv[3]);
                  if (cnt >= 5) {
                     throttle_ttime = cnt;
                     to = parv[3];
                  } 
               } else if (!strcasecmp(parv[2], "RECORDTIME")) {
                  int cnt;
                  changed = "RECORDTIME";
                  cnt = atoi(parv[3]);
                  if (cnt >= 30) {
                     throttle_rtime = cnt;
                     to = parv[3];
                  }
               } else if (!strcasecmp(parv[2], "HASH")) {
                  int cnt;
                  changed = "HASH";
                  cnt = atoi(parv[3]);
                  if (cnt >= THROTTLE_HASHSIZE) {
                     throttle_resize(cnt);
                     to = parv[3];
                  }
               }

               if (to != NULL) {
                  sendto_ops("%s has changed throttle %s to %s", parv[0],
                        changed, to);
                  sendto_one(sptr, ":%s NOTICE %s :set throttle %s to %s",
                        me.name, parv[0], changed, to);
               }
           } else {
              /* report various things, we cannot easily get the hash size, so
               * leave that alone. */
              sendto_one(sptr, ":%s NOTICE %s :THROTTLE %s", me.name, parv[0],
                    throttle_enable ? "enabled" : "disabled");
              sendto_one(sptr, ":%s NOTICE %s :THROTTLE COUNT=%d", me.name,
                    parv[0], throttle_tcount);
              sendto_one(sptr, ":%s NOTICE %s :THROTTLE TIME=%d sec", me.name,
                    parv[0], throttle_ttime);
              sendto_one(sptr, ":%s NOTICE %s :THROTTLE RECORDTIME=%d sec", me.name,
                    parv[0], throttle_rtime);
           }
        }
        else if (!strncasecmp(command, "LCLONES", 3))
        {
            if (parc > 3)
            {
                int limit, rval;

                limit = atoi(parv[3]);
                rval = clones_set(parv[2], CLIM_SOFT_LOCAL, limit);

                if (rval < 0)
                    sendto_one(sptr, ":%s NOTICE %s :Invalid IP or limit.",
                               me.name, parv[0]);
                else if (rval > 0 && limit == 0)
                {
                    sendto_ops("%s removed soft local clone limit for %s",
                               parv[0], parv[2]);
                    sendto_one(sptr, ":%s NOTICE %s :removed soft local clone"
                               " limit for %s", me.name, parv[0], parv[2]);
                }
                else if (rval > 0)
                {
                    sendto_ops("%s changed soft local clone limit for %s from"
                               " %d to %d", parv[0], parv[2], rval, limit);
                    sendto_one(sptr, ":%s NOTICE %s :changed soft local clone"
                               " limit for %s from %d to %d", me.name, parv[0],
                               parv[2], rval, limit);
                }
                else if (limit == 0)
                {
                    sendto_one(sptr, ":%s NOTICE %s :no soft local clone limit"
                               " for %s", me.name, parv[0], parv[2]);
                }
                else
                {
                    sendto_ops("%s set soft local clone limit for %s to %d",
                               parv[0], parv[2], limit);
                    sendto_one(sptr, ":%s NOTICE %s :set soft local clone"
                               " limit for %s to %d", me.name, parv[0],
                               parv[2], limit);
                }
            }
            else if (parc > 2)
            {
                int hglimit, sglimit, sllimit;

                clones_get(parv[2], &hglimit, &sglimit, &sllimit);

                if (!sllimit)
                    sendto_one(sptr, ":%s NOTICE %s :no soft local clone limit"
                               " for %s", me.name, parv[0], parv[2]);
                else
                    sendto_one(sptr, ":%s NOTICE %s :soft local clone limit"
                               " for %s is %d", me.name, parv[0], parv[2],
                               sllimit);
            }
            else
                sendto_one(sptr, ":%s NOTICE %s :Usage: LCLONES <ip> [<limit>]",
                           me.name, parv[0]);
        }
        else if (!strncasecmp(command, "GCLONES", 3))
        {
            int hglimit, sglimit, sllimit, limit, rval;

            if (parc > 3)
            {
                limit = atoi(parv[3]);
                clones_get(parv[2], &hglimit, &sglimit, &sllimit);

                if (hglimit && limit > hglimit)
                    sendto_one(sptr, ":%s NOTICE %s :Cannot set soft global"
                               " clone limit for %s above services-set hard"
                               " limit (%d)", me.name, parv[0], parv[2],
                               hglimit);
                else
                {
                    rval = clones_set(parv[2], CLIM_SOFT_GLOBAL, limit);

                    if (rval < 0)
                        sendto_one(sptr, ":%s NOTICE %s :Invalid IP or limit.",
                                   me.name, parv[0]);
                    else if (rval > 0 && limit == 0)
                    {
                        sendto_ops("%s removed soft global clone limit for %s",
                                   parv[0], parv[2]);
                        sendto_one(sptr, ":%s NOTICE %s :removed soft global"
                                   " clone limit for %s", me.name, parv[0],
                                   parv[2]);
                    }
                    else if (rval > 0)
                    {
                        sendto_ops("%s changed soft global clone limit for %s"
                                   " from %d to %d", parv[0], parv[2], rval,
                                   limit);
                        sendto_one(sptr, ":%s NOTICE %s :changed soft global"
                                   " clone limit for %s from %d to %d",
                                   me.name, parv[0], parv[2], rval, limit);
                    }
                    else if (limit == 0)
                    {
                        sendto_one(sptr, ":%s NOTICE %s :no soft global clone"
                                   " limit for %s", me.name, parv[0], parv[2]);
                    }
                    else
                    {
                        sendto_ops("%s set soft global clone limit for %s to"
                                   " %d", parv[0], parv[2], limit);
                        sendto_one(sptr, ":%s NOTICE %s :set soft global clone"
                                   " limit for %s to %d", me.name, parv[0],
                                   parv[2], limit);
                    }
                }
            }
            else if (parc > 2)
            {
                clones_get(parv[2], &hglimit, &sglimit, &sllimit);

                if (sglimit)
                    sendto_one(sptr, ":%s NOTICE %s :soft global clone limit"
                               " for %s is %d", me.name, parv[0], parv[2],
                               sglimit);
                else
                    sendto_one(sptr, ":%s NOTICE %s :no soft global clone"
                               " limit for %s", me.name, parv[0], parv[2]);

                if (hglimit)
                    sendto_one(sptr, ":%s NOTICE %s :hard global clone limit"
                               " for %s is %d", me.name, parv[0], parv[2],
                               hglimit);
            }
            else
                sendto_one(sptr, ":%s NOTICE %s :Usage: GCLONES <ip> [<limit>]",
                           me.name, parv[0]);
        }
        else if (!strncasecmp(command, "DEFLCLONE", 6))
        {
            char *eptr;

            if (parc > 2)
            {
                local_ip_limit = strtol(parv[2], &eptr, 10);
                if (*eptr != 0)
                    local_ip24_limit = atoi(eptr+1);

                if (local_ip_limit < 1)
                    local_ip_limit = DEFAULT_LOCAL_IP_CLONES;
                if (local_ip24_limit < 1)
                    local_ip24_limit = DEFAULT_LOCAL_IP24_CLONES;

                sendto_ops("%s set default local clone limit to %d:%d"
                           " (host:site)", parv[0], local_ip_limit,
                           local_ip24_limit);
                sendto_one(sptr, ":%s NOTICE %s :set default local clone limit"
                           " to %d:%d (host:site)", me.name, parv[0],
                           local_ip_limit, local_ip24_limit);
            }
            else
                sendto_one(sptr, ":%s NOTICE %s :default local clone limit is"
                           " %d:%d (host:site)", me.name, parv[0],
                           local_ip_limit, local_ip24_limit);
        }
        else if (!strncasecmp(command, "DEFGCLONE", 6))
        {
            char *eptr;

            if (parc > 2)
            {
                global_ip_limit = strtol(parv[2], &eptr, 10);
                if (*eptr != 0)
                    global_ip24_limit = atoi(eptr+1);

                if (global_ip_limit < 1)
                    global_ip_limit = DEFAULT_GLOBAL_IP_CLONES;
                if (global_ip24_limit < 1)
                    global_ip24_limit = DEFAULT_GLOBAL_IP24_CLONES;

                sendto_ops("%s set default global clone limit to %d:%d"
                           " (host:site)", parv[0], global_ip_limit,
                           global_ip24_limit);
                sendto_one(sptr, ":%s NOTICE %s :set default global clone"
                           " limit to %d:%d (host:site)", me.name, parv[0],
                           global_ip_limit, global_ip24_limit);
            }
            else
                sendto_one(sptr, ":%s NOTICE %s :default global clone limit is"
                           " %d:%d (host:site)", me.name, parv[0],
                           global_ip_limit, global_ip24_limit);
        }
#endif
    }
    else 
    {
        sendto_one(sptr, ":%s NOTICE %s :Options: MAX",
                   me.name, parv[0]);
#ifdef FLUD
        sendto_one(sptr, ":%s NOTICE %s :Options: FLUDNUM, FLUDTIME, "
                   "FLUDBLOCK", me.name, parv[0]);
#endif

#ifdef ANTI_SPAMBOT
        sendto_one(sptr, ":%s NOTICE %s :Options: SPAMNUM, SPAMTIME",
                   me.name, parv[0]);
#endif

#ifdef THROTTLE_ENABLE
        sendto_one(sptr, ":%s NOTICE %s :Options: THROTTLE "
              "<ENABLE|COUNT|TIME|RECORDTIME|HASH> [setting]", me.name, parv[0]);
        sendto_one(sptr, ":%s NOTICE %s :Options: LCLONES, GCLONES, "
                   "DEFLCLONES, DEFGCLONES", me.name, parv[0]);
#endif
    }
    return 0;
}

/* m_rehash */
int 
m_rehash(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    if (!OPCanRehash(sptr)) 
    {
        sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
        return 0;
    }
        
    if (parc > 1) 
    {
        if (mycmp(parv[1], "DNS") == 0) 
        {
            sendto_one(sptr, rpl_str(RPL_REHASHING), me.name, parv[0], "DNS");
            flush_cache();              /* flush the dns cache */
            res_init();         /* re-read /etc/resolv.conf */
            sendto_ops("%s is rehashing DNS while whistling innocently",
                       parv[0]);
            return 0;
        }
#if 0
        else if (mycmp(parv[1], "TKLINES") == 0)
        {
            sendto_one(sptr, rpl_str(RPL_REHASHING), me.name, parv[0],
                       "temp klines");
            remove_userbans_match_flags(UBAN_LOCAL|UBAN_TEMPORARY, 0);
            sendto_ops("%s is clearing temp klines while whistling innocently",
                       parv[0]);
            return 0;
        }
#endif
        else if (mycmp(parv[1], "GC") == 0) 
        {
            sendto_one(sptr, rpl_str(RPL_REHASHING), me.name, parv[0],
                       "garbage collecting");
            block_garbage_collect();
            sendto_ops("%s is garbage collecting while whistling innocently",
                       parv[0]);
            return 0;
        }
        else if (mycmp(parv[1], "MOTD") == 0) 
        {
            sendto_ops("%s is forcing re-reading of MOTD file", parv[0]);
            read_motd(MOTD);
        if(confopts & FLAGS_SMOTD)
                read_shortmotd(SHORTMOTD);
            return (0);
        }
#if 0
        else if(mycmp(parv[1], "AKILLS") == 0) 
        {
            sendto_one(sptr, rpl_str(RPL_REHASHING), me.name, parv[0],
                       "akills");
            remove_userbans_match_flags(UBAN_NETWORK, 0);
            sendto_ops("%s is rehashing akills", parv[0]);
            return 0;
        }
#endif
        else if(mycmp(parv[1], "THROTTLES") == 0) {
            sendto_one(sptr, rpl_str(RPL_REHASHING), me.name, parv[0],
                 "throttles");
            throttle_rehash();
            sendto_ops("%s is rehashing throttles", parv[0]);
            return 0;
        }
#if 0
        else if(mycmp(parv[1], "SQLINES") == 0) {
            sendto_one(sptr, rpl_str(RPL_REHASHING), me.name, parv[0],
                 "sqlines");
            sendto_ops("%s is rehashing sqlines", parv[0]);
            remove_simbans_match_flags(SBAN_NICK|SBAN_NETWORK, 0);
            remove_simbans_match_flags(SBAN_CHAN|SBAN_NETWORK, 0);
            return 0;
        }
        else if(mycmp(parv[1], "SGLINES") == 0) {
            sendto_one(sptr, rpl_str(RPL_REHASHING), me.name, parv[0],
                 "sglines");
            sendto_ops("%s is rehashing sglines", parv[0]);
            remove_simbans_match_flags(SBAN_GCOS|SBAN_NETWORK, 0);
            return 0;
        }
        else if(mycmp(parv[1], "TSQGLINES") == 0) {
            sendto_one(sptr, rpl_str(RPL_REHASHING), me.name, parv[0],
                 "tsqglines");
            sendto_ops("%s is rehashing temporary sqlines/glines", parv[0]);
            remove_simbans_match_flags(SBAN_GCOS|SBAN_TEMPORARY, 0);
            remove_simbans_match_flags(SBAN_NICK|SBAN_TEMPORARY, 0);
            remove_simbans_match_flags(SBAN_CHAN|SBAN_TEMPORARY, 0);
            return 0;
        }
#endif
    }
    else 
    {
        sendto_one(sptr, rpl_str(RPL_REHASHING), me.name, parv[0], configfile);
        sendto_ops("%s is rehashing Server config file while whistling "
                   "innocently", parv[0]);
# ifdef USE_SYSLOG
        syslog(LOG_INFO, "REHASH From %s\n", get_client_name(sptr, FALSE));
# endif
        return rehash(cptr, sptr, 
                      (parc > 1) ? ((*parv[1] == 'q') ? 2 : 0) : 0);
    }
    return 0;                   /* shouldn't ever get here */
}

/* m_restart */
int 
m_restart(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    char       *pass = NULL;
    
    if (!OPCanRestart(sptr))
    {
        sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
        return 0;
    }
    /*
     * m_restart is now password protected as in df465 only change --
     * this one doesn't allow a reason to be specified. future changes:
     * crypt()ing of password, reason to be re-added -mjs
     */
    if ((pass = MeLine->restartpass)) 
    {
        if (parc < 2) 
        {
            sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0],
                       "RESTART");
            return 0;
        }
        if (strcmp(pass, parv[1])) 
        {
            sendto_one(sptr, err_str(ERR_PASSWDMISMATCH), me.name, parv[0]);
            return 0;
        }
    }
    
#ifdef USE_SYSLOG
    syslog(LOG_WARNING, "Server RESTART by %s\n",
           get_client_name(sptr, FALSE));
#endif
    sprintf(buf, "Server RESTART by %s", get_client_name(sptr, FALSE));
    restart(buf);
    return 0;                   /* NOT REACHED */
}

/*
 * * m_trace 
 *        parv[0] = sender prefix 
 *        parv[1] = servername
 */
int 
m_trace(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    int      i;
    aClient *acptr=NULL;
    aClass      *cltmp;
    char        *tname;
    int          doall, link_s[MAXCONNECTIONS], link_u[MAXCONNECTIONS];
    int          wilds = 0, dow = 0;
        
    tname = (parc > 1) ? parv[1] : me.name;

#ifdef NO_USER_TRACE
    if(!IsAnOper(sptr))
    {
        sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
        return 0;
    }
#endif

#ifdef HIDEULINEDSERVS
    if((acptr = next_client_double(client, tname)))
    {
        if (!(IsAnOper(sptr)) && IsULine(acptr))
        {
            sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
            return 0;
        }
        acptr = NULL; /* shrug, we borrowed it, reset it just in case */
    }
#endif
    
    if (parc > 2)
        if (hunt_server(cptr, sptr, ":%s TRACE %s :%s", 2, parc, parv))
            return 0;

    switch (hunt_server(cptr, sptr, ":%s TRACE :%s", 1, parc, parv)) 
    {
        case HUNTED_PASS:   /*  note: gets here only if parv[1] exists */
        {
            aClient    *ac2ptr = next_client_double(client, tname);
            if (ac2ptr)
                sendto_one(sptr, rpl_str(RPL_TRACELINK), me.name, parv[0],
                           version, debugmode, tname, 
                           ac2ptr->from->name);
            else
                sendto_one(sptr, rpl_str(RPL_TRACELINK), me.name, parv[0],
                           version, debugmode, tname, 
                           "ac2ptr_is_NULL!!");
            return 0;
        }
        case HUNTED_ISME:
            break;
        default:
            return 0;
    }
    if(!IsAnOper(sptr)) 
    {
        if (parv[1] && !strchr(parv[1],'.') && 
            (strchr(parv[1], '*') || strchr(parv[1], '?'))) 
            /* bzzzt, no wildcard nicks for nonopers */
        {
            sendto_one(sptr, rpl_str(RPL_ENDOFTRACE),me.name,
                       parv[0], parv[1]);
            return 0;        
        }
    }
    sendto_realops_lev(SPY_LEV, "TRACE requested by %s (%s@%s) [%s]",
                       sptr->name, sptr->user->username, sptr->user->host,
                       sptr->user->server);
        
    doall = (parv[1] && (parc > 1)) ? !match(tname, me.name) : TRUE;
    wilds = !parv[1] || strchr(tname, '*') || strchr(tname, '?');
    dow = wilds || doall;
    if(!IsAnOper(sptr) || !dow) /* non-oper traces must be full nicks */
        /* lets also do this for opers tracing nicks */
    {
        char      *name, *class;
        acptr = hash_find_client(tname,(aClient *)NULL);
        if(!acptr || !IsPerson(acptr)) 
        {
            /* this should only be reached if the matching
               target is this server */
            sendto_one(sptr, rpl_str(RPL_ENDOFTRACE),me.name,
                       parv[0], tname);
            return 0;
                          
        }
        if(acptr->class)
            class = acptr->class->name;
        else
            class = "NONE";
        name = get_client_name(acptr,FALSE);
        if (IsAnOper(acptr)) 
        {
            sendto_one(sptr, rpl_str(RPL_TRACEOPERATOR),
                       me.name, parv[0], class, name,
                       timeofday - acptr->lasttime);
        }
        else
        {
            sendto_one(sptr,rpl_str(RPL_TRACEUSER),
                       me.name, parv[0], class, name,
                       timeofday - acptr->lasttime);
        }
        sendto_one(sptr, rpl_str(RPL_ENDOFTRACE),me.name,
                   parv[0], tname);
        return 0;        
    }

    memset((char *) link_s, '\0', sizeof(link_s));
    memset((char *) link_u, '\0', sizeof(link_u));
    /* Count up all the servers and clients in a downlink. */
    if (doall)
        for (acptr = client; acptr; acptr = acptr->next) 
        {
            if (IsPerson(acptr) && (!IsInvisible(acptr) || IsAnOper(sptr)))
                link_u[acptr->from->fd]++;
            else if (IsServer(acptr))
#ifdef HIDEULINEDSERVS
                if (IsOper(sptr) || !IsULine(acptr))
#endif
                    link_s[acptr->from->fd]++;
        }
                
        
    /* report all direct connections */
        
    for (i = 0; i <= highest_fd; i++) 
    {
        char       *name, *class;
                
        if (!(acptr = local[i]))        /* Local Connection? */
            continue;
#ifdef HIDEULINEDSERVS
        if (!IsOper(sptr) && IsULine(acptr))
            continue;
#endif
        if (IsInvisible(acptr) && dow &&
            !(MyConnect(sptr) && IsAnOper(sptr)) &&
            !IsAnOper(acptr) && (acptr != sptr))
            continue;
        if (!doall && wilds && match(tname, acptr->name))
            continue;
        if (!dow && mycmp(tname, acptr->name))
            continue;
        /* only show IPs of unknowns or clients to opers */
        if (IsAnOper(sptr) && 
                (acptr->status == STAT_CLIENT || acptr->status == STAT_UNKNOWN))
            name = get_client_name(acptr, FALSE);
        else
            name = get_client_name(acptr, HIDEME);
        if(acptr->class)
            class = acptr->class->name;
        else
            class = "NONE";
                
        switch (acptr->status) 
        {
            case STAT_CONNECTING:
                sendto_one(sptr, rpl_str(RPL_TRACECONNECTING), me.name,
                           parv[0], class, name);
                break;
            case STAT_HANDSHAKE:
                sendto_one(sptr, rpl_str(RPL_TRACEHANDSHAKE), me.name,
                           parv[0], class, name);
                break;
            case STAT_ME:
                break;
            case STAT_UNKNOWN:
                /* added time -Taner */
                sendto_one(sptr, rpl_str(RPL_TRACEUNKNOWN),
                          me.name, parv[0], class, name,
                          acptr->firsttime ? timeofday - acptr->firsttime : -1);
                break;
            case STAT_CLIENT:
                /*
                 * Only opers see users if there is a wildcard but
                 * anyone can see all the opers.
                 */
                if (((IsAnOper(sptr) && (MyClient(sptr))) 
                        || !(dow && IsInvisible(acptr))) || !dow || 
                    IsAnOper(acptr)) 
                {
                    if (IsAnOper(acptr))
                        sendto_one(sptr, rpl_str(RPL_TRACEOPERATOR),
                               me.name, parv[0], class, name,
                               timeofday - acptr->lasttime);
                }
                break;
            case STAT_SERVER:
                sendto_one(sptr, rpl_str(RPL_TRACESERVER),
                           me.name, parv[0], class, link_s[i],
                           link_u[i], name, 
                           *(acptr->serv->bynick) ? acptr->serv->bynick : "*", 
                           *(acptr->serv->byuser) ? acptr->serv->byuser : "*", 
                           *(acptr->serv->byhost) ? acptr->serv->byhost : 
                           me.name);
                break;
            case STAT_LOG:
                sendto_one(sptr, rpl_str(RPL_TRACELOG), me.name,
                           parv[0], LOGFILE, acptr->port);
                break;
            default:                /* ...we actually shouldn't come here... */
                sendto_one(sptr, rpl_str(RPL_TRACENEWTYPE), me.name,
                           parv[0], name);
                break;
        }
    }

    /* let the user have some idea that its at the end of the trace */
    sendto_one(sptr, rpl_str(RPL_TRACESERVER),
                me.name, parv[0], "NONE", link_s[me.fd],
                link_u[me.fd], me.name, "*", "*", me.name,
                acptr ? timeofday - acptr->lasttime : 0);
#ifdef HIDEULINEDSERVS
    if (IsOper(sptr))
#endif
        for (cltmp = classes; doall && cltmp; cltmp = cltmp->next)
            if (cltmp->links > 0)
                sendto_one(sptr, rpl_str(RPL_TRACECLASS), me.name,
                           parv[0], cltmp->name, cltmp->links);
        
    sendto_one(sptr, rpl_str(RPL_ENDOFTRACE), me.name, parv[0], tname);
    return 0;
}

/*
 * * m_motd 
 *       parv[0] = sender prefix 
 *       parv[1] = servername
 */
int 
m_motd(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    static time_t last_used = 0L;
    if (hunt_server(cptr, sptr, ":%s MOTD :%s", 1, parc, parv) != HUNTED_ISME)
        return 0;
    if(!IsAnOper(sptr)) 
    {
        if (IsSquelch(sptr)) 
        {
            sendto_one(sptr, rpl_str(RPL_ENDOFMOTD), me.name, parv[0]);
            return 0;
        }
        if ((last_used + MOTD_WAIT) > NOW)
            return 0;
        else
            last_used = NOW;

    }
    sendto_realops_lev(SPY_LEV, "MOTD requested by %s (%s@%s) [%s]",
                       sptr->name, sptr->user->username, sptr->user->host,
                       sptr->user->server);
    send_motd(cptr, sptr, parc, parv);
    return 0;
}

/*
** send_motd
**  parv[0] = sender prefix
**  parv[1] = servername
**
** This function split off so a server notice could be generated on a
** user requested motd, but not on each connecting client.
** -Dianora
*/
int 
send_motd(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aMotd *temp;
    
    if (motd == (aMotd *) NULL) 
    {
        sendto_one(sptr, err_str(ERR_NOMOTD), me.name, parv[0]);
        return 0;
    }
    sendto_one(sptr, rpl_str(RPL_MOTDSTART), me.name, parv[0], me.name);

    sendto_one(sptr, ":%s %d %s :-%s", me.name, RPL_MOTD, parv[0], 
               motd_last_changed_date);

    temp = motd;
    while (temp) 
    {
        sendto_one(sptr, rpl_str(RPL_MOTD),  me.name, parv[0], temp->line);
        temp = temp->next;
    }
    sendto_one(sptr, rpl_str(RPL_ENDOFMOTD), me.name, parv[0]);
    return 0;
}

/*
 * read_motd() - From CoMSTuD, added Aug 29, 1996
 */
void 
read_motd(char *filename)
{
    aMotd *temp, *last;
    struct tm *motd_tm;
    struct stat sb;
    char        buffer[MOTDLINELEN], *tmp;
    int         fd;

    /* Clear out the old MOTD */

    while (motd) 
    {
        temp = motd->next;
        MyFree(motd);
        motd = temp;
    }
    fd = open(filename, O_RDONLY);
    if (fd == -1)
    {
        if(!forked)
                printf("WARNING:  MOTD file %s could not be found.  "
                       "Skipping MOTD load.\n", filename);
        return;
    }
    fstat(fd, &sb);
    motd_tm = localtime(&sb.st_mtime);
    last = (aMotd *) NULL;

    while (dgets(fd, buffer, MOTDLINELEN - 1) > 0) 
    {
        if ((tmp = (char *) strchr(buffer, '\n')))
            *tmp = '\0';
        if ((tmp = (char *) strchr(buffer, '\r')))
            *tmp = '\0';
        temp = (aMotd *) MyMalloc(sizeof(aMotd));

        strncpyzt(temp->line, buffer, MOTDLINELEN);
        temp->next = (aMotd *) NULL;
        if (!motd)
            motd = temp;
        else
            last->next = temp;
        last = temp;
    }
    close(fd);

    sprintf(motd_last_changed_date, "%d/%d/%d %d:%02d", motd_tm->tm_mday,
            motd_tm->tm_mon + 1, 1900 + motd_tm->tm_year, motd_tm->tm_hour,
            motd_tm->tm_min);
}

void 
read_shortmotd(char *filename)
{
    aMotd *temp, *last;
    char        buffer[MOTDLINELEN], *tmp;
    int         fd;

    /* Clear out the old MOTD */

    while (shortmotd)
    {
        temp = shortmotd->next;
        MyFree(shortmotd);
        shortmotd = temp;
    }
    fd = open(filename, O_RDONLY);
    if (fd == -1)
    {
        if(!forked)
                printf("WARNING:  sMOTD file %s could not be found.  "
                       "Skipping sMOTD load.\n", filename);
        return;
    }
    
    last = (aMotd *) NULL;

    while (dgets(fd, buffer, MOTDLINELEN - 1) > 0) 
    {
        if ((tmp = (char *) strchr(buffer, '\n')))
            *tmp = '\0';
        if ((tmp = (char *) strchr(buffer, '\r')))
            *tmp = '\0';
        temp = (aMotd *) MyMalloc(sizeof(aMotd));

        strncpyzt(temp->line, buffer, MOTDLINELEN);
        temp->next = (aMotd *) NULL;
        if (!shortmotd)
            shortmotd = temp;
        else
            last->next = temp;
        last = temp;
    }
    close(fd);
}

/*
 * read_help() - modified from from CoMSTuD's read_motd added Aug 29,
 * 1996 modifed  Aug 31 1997 - Dianora
 * 
 * Use the same idea for the oper helpfile
 */
void 
read_help(char *filename)
{
    aMotd *temp, *last;
    char        buffer[MOTDLINELEN], *tmp;
    int         fd;

    /* Clear out the old HELPFILE */

    while (helpfile) 
    {
        temp = helpfile->next;
        MyFree(helpfile);
        helpfile = temp;
    }

    fd = open(filename, O_RDONLY);
    if (fd == -1)
    {
        if(!forked)
                printf("WARNING:  Help file %s could not be found.  "
                       "Skipping Help file load.\n", filename);
        return;
    }

    last = (aMotd *) NULL;

    while (dgets(fd, buffer, MOTDLINELEN - 1) > 0) 
    {
        if ((tmp = (char *) strchr(buffer, '\n')))
            *tmp = '\0';
        if ((tmp = (char *) strchr(buffer, '\r')))
            *tmp = '\0';
        temp = (aMotd *) MyMalloc(sizeof(aMotd));

        strncpyzt(temp->line, buffer, MOTDLINELEN);
        temp->next = (aMotd *) NULL;
        if (!helpfile)
            helpfile = temp;
        else
            last->next = temp;
        last = temp;
    }
    close(fd);
}

/* m_close - added by Darren Reed Jul 13 1992. */
int 
m_close(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aClient *acptr;
    int     i;
    int         closed = 0;

    if (!MyOper(sptr)) 
    {
        sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
        return 0;
    }

    for (i = highest_fd; i; i--) 
    {
        if (!(acptr = local[i]))
            continue;
        if (!IsUnknown(acptr) && !IsConnecting(acptr) &&
            !IsHandshake(acptr))
            continue;
        sendto_one(sptr, rpl_str(RPL_CLOSING), me.name, parv[0],
                   get_client_name(acptr, TRUE), acptr->status);
        exit_client(acptr, acptr, acptr, "Oper Closing");
        closed++;
    }
    sendto_one(sptr, rpl_str(RPL_CLOSEEND), me.name, parv[0], closed);
    return 0;
}

int 
m_die(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aClient *acptr;
    int     i;
    char       *pass = NULL;

    if (!OPCanDie(sptr))
    {
        sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
        return 0;
    }
    /* X line -mjs */

    if ((pass = MeLine->diepass))
    {
        if (parc < 2) 
        {
            sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name,
                       parv[0], "DIE");
            return 0;
        }
        if (strcmp(pass, parv[1])) 
        {
            sendto_one(sptr, err_str(ERR_PASSWDMISMATCH), me.name, parv[0]);
            return 0;
        }
    }

    for (i = 0; i <= highest_fd; i++) 
    {
        if (!(acptr = local[i]))
            continue;
        if (IsClient(acptr))
            sendto_one(acptr,
                       ":%s NOTICE %s :Server Terminating. %s",
                       me.name, acptr->name,
                       get_client_name(sptr, FALSE));
        else if (IsServer(acptr))
            sendto_one(acptr, ":%s ERROR :Terminated by %s",
                       me.name, get_client_name(sptr, TRUE));
    }
    s_die();
    return 0;
}

/*
 * m_capab 
 * Communicate what I can do to another server 
 * This has to be able to be sent and understood while
 * the client is UNREGISTERED. Therefore, we
 * absolutely positively must not check to see if
 * this is a server or a client. It's probably an unknown!
 */
int 
m_capab(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    int         i;

    /* If it's not local, or it has already set capabilities,
     * silently ignore it.
     * Dont ignore clients where we have set some capabilities already
     * that would suck for connecting TO servers.
     */
    
    if(cptr != sptr)
        return 0;

    for (i = 1; i < parc; i++) 
    {
        if (strcmp(parv[i], "BURST") == 0)
            SetBurst(sptr);
        else if (strcmp(parv[i], "UNCONNECT") == 0)
            SetUnconnect(cptr);
        else if (strcmp(parv[i], "DKEY") == 0)
            SetDKEY(cptr);
        else if (strcmp(parv[i], "ZIP") == 0)
            SetZipCapable(cptr);
#ifdef NOQUIT
        else if (strcmp(parv[i], "NOQUIT") == 0)
            SetNoquit(cptr);
#endif
        else if (strcmp(parv[i], "BH19") == 0)
            SetBH19(cptr);
    }

    return 0;
}

/* m_svskill - Just about the same as outta df
 *  - Raistlin
 * parv[0] = servername
 * parv[1] = client
 * parv[2] = nick stamp
 * parv[3] = kill message
 */
         
int 
m_svskill(aClient *cptr, aClient *sptr, int parc, char *parv[]) 
{
    aClient *acptr;
    char *comment;
    char reason[TOPICLEN + 1];
    ts_val ts = 0;

    if (parc < 2)
        return 0;

    if (parc > 3) 
    {
        comment = parv[3] ? parv[3] : parv[0];
        ts = atol(parv[2]);
    }
    else
        comment = (parc > 2 && parv[2]) ? parv[2] : parv[0];
      
    if(!IsULine(sptr)) return -1;
    if((acptr = find_client(parv[1], NULL)) && (!ts || ts == acptr->tsinfo))
    {
        if(MyClient(acptr))
        {
            strcpy(reason, "SVSKilled: ");
            strncpy(reason + 11, comment, TOPICLEN - 11);
            reason[TOPICLEN] = '\0';
            exit_client(acptr, acptr, sptr, reason);
            return (acptr == cptr) ? FLUSH_BUFFER : 0;
        }
        if(acptr->from == cptr)
        {
            sendto_realops_lev(DEBUG_LEV, "Received wrong-direction SVSKILL"
                               " for %s (behind %s) from %s", 
                               acptr->name, cptr->name,
                               get_client_name(sptr, HIDEME));
            return 0;
        }
        else if(ts == 0) 
            sendto_one(acptr->from, ":%s SVSKILL %s :%s", parv[0], parv[1],
                               comment);
        else
            sendto_one(acptr->from, ":%s SVSKILL %s %ld :%s", parv[0], parv[1],
                               ts, comment);
    }
    return 0;
}
         
/* m_akill -
 * Parse AKILL command
 * parv[1]=host 
 * parv[2]=user
 * parv[3]=length
 * parv[4]=akiller
 * parv[5]=time set
 * parv[6]=reason
 */      
int 
m_akill(aClient *cptr, aClient *sptr, int parc, char *parv[]) 
{
    char mbuf[BUFSIZE];
    char *user, *host, *reason, *akiller;
    time_t length=0, timeset=0;
    time_t expirets;
    int rv;

    if(!IsServer(sptr) || (parc < 6))
        return 0;
        
    if(!IsULine(sptr)) 
    {
        sendto_serv_butone(&me,":%s GLOBOPS :Non-ULined server %s trying to "
                           "AKILL!", me.name, sptr->name);
        send_globops("From %s: Non-ULined server %s trying to AKILL!", me.name,
                     sptr->name);
        return 0;
    }
        
    host=parv[1];
    user=parv[2];
    akiller=parv[4];
    length=atoi(parv[3]);
    timeset=atoi(parv[5]);
    reason=(parv[6] ? parv[6] : "<no reason>");

    if(length == 0) /* a "permanent" akill? */
       length = (86400 * 7); /* hold it for a week */

    expirets = timeset + length;

    /* is this an old bogus akill? */
    if(expirets <= NOW)
       return 0;

    ircsprintf(mbuf, "%s@%s", user, host);
    rv = userban_add(mbuf, reason, expirets, UBAN_UPDATE, NULL);

    /* complain but pass along invalid bans, all servers will yell */
    if (rv == UBAN_ADD_INVALID)
        sendto_realops("AKILL: invalid ban %s from %s (%s) ignored", mbuf,
                       parv[0], akiller);

    /* send it off to any other servers! */
    sendto_serv_butone(cptr, ":%s AKILL %s %s %d %s %d :%s",
                       sptr->name, host, user, length, akiller,
                       timeset, reason);

    return 0;
}
  
int 
m_rakill(aClient *cptr, aClient *sptr, int parc, char *parv[]) 
{
    char mbuf[BUFSIZE];

    if(!IsServer(sptr))
        return 0;

    /* just quickly find the akill and be rid of it! */
    if(parc<3) 
    {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0],
                   "RAKILL");
        return 0;
    }

    if(!IsULine(sptr)) 
    {
        sendto_serv_butone(&me, ":%s GLOBOPS :Non-ULined server %s trying to "
                           "RAKILL!",  me.name, sptr->name);
        send_globops("From %s: Non-ULined server %s trying to RAKILL!",
                     me.name,
                     sptr->name);
        return 0;
    }

    ircsprintf(mbuf, "%s@%s", parv[2], parv[1]);
    userban_del(mbuf, 0, NULL);

    sendto_serv_butone(cptr, ":%s RAKILL %s %s", sptr->name, parv[1], parv[2]);
    return 0;
}

        
/*
 * RPL_NOWON   - Online at the moment (Succesfully added to WATCH-list)
 * RPL_NOWOFF  - Offline at the moement (Succesfully added to WATCH-list)
 * RPL_WATCHOFF   - Succesfully removed from WATCH-list.
 * ERR_TOOMANYWATCH - Take a guess :>  Too many WATCH entries.
 */
static void 
show_watch(aClient *cptr, char *name, int rpl1, int rpl2) 
{
    aClient *acptr;     
    
    if ((acptr = find_person(name, NULL)))
        sendto_one(cptr, rpl_str(rpl1), me.name, cptr->name,
                   acptr->name, acptr->user->username,
                   acptr->user->host, acptr->lasttime);
    else
        sendto_one(cptr, rpl_str(rpl2), me.name, cptr->name,
                   name, "*", "*", 0);
}
        
/* m_watch */
int 
m_watch(aClient *cptr, aClient *sptr, int parc, char *parv[]) 
{
    aClient  *acptr;
    char  *s, *p, *user;
    char def[2] = "l";
    int listreq = 0;
    int listcount = 0;
        
    if (parc < 2) 
    {
        /* Default to 'l' - list who's currently online */
        parc = 2;
        parv[1] = def;
    }
    
    for (p = NULL, s = strtoken(&p, parv[1], ", "); s;
         s = strtoken(&p, NULL, ", ")) 
    {
        if ((user = (char *)strchr(s, '!')))
            *user++ = '\0'; /* Not used */
                
        /*
         * Prefix of "+", they want to add a name to their WATCH
         * list. 
         */
        if (*s == '+') 
        {
            if (*(s+1)) 
            {
                if ((sptr->watches >= MAXWATCH) && !IsAnOper(sptr))
                {
                    sendto_one(sptr, err_str(ERR_TOOMANYWATCH),
                               me.name, cptr->name, s+1);                                       
                    continue;
                }                               
                add_to_watch_hash_table(s+1, sptr);
            }
            show_watch(sptr, s+1, RPL_NOWON, RPL_NOWOFF);
            listcount++;
            continue;
        }
        
        /*
         * Prefix of "-", coward wants to remove somebody from their
         * WATCH list.  So do it. :-)
         */
        if (*s == '-') 
        {
            del_from_watch_hash_table(s+1, sptr);
            show_watch(sptr, s+1, RPL_WATCHOFF, RPL_WATCHOFF);
            listcount++;
            continue;
        }
                                        
        /*
         * Fancy "C" or "c", they want to nuke their WATCH list and start
         * over, so be it.
         */
        if (*s == 'C' || *s == 'c') 
        {
            hash_del_watch_list(sptr);
            continue;
        }
                
        /*
         * Now comes the fun stuff, "S" or "s" returns a status report of
         * their WATCH list.  I imagine this could be CPU intensive if its
         * done alot, perhaps an auto-lag on this?
         */
        if (*s == 'S' || *s == 's') 
        {
            Link *lp;
            aWatch *anptr;
            int  count = 0;
            
            /* only allowed once per command */
            if (listreq & 0x1)
                continue;
            listreq |= 0x1;
                                                        
            /*
             * Send a list of how many users they have on their WATCH list
             * and how many WATCH lists they are on.
             */
            anptr = hash_get_watch(sptr->name);
            if (anptr)
                for (lp = anptr->watch, count = 1; (lp = lp->next); count++);
            sendto_one(sptr, rpl_str(RPL_WATCHSTAT), me.name, parv[0],
                       sptr->watches, count);
                        
            /*
             * Send a list of everybody in their WATCH list. Be careful
             * not to buffer overflow.
             */
            if ((lp = sptr->watch) == NULL) 
            {
                sendto_one(sptr, rpl_str(RPL_ENDOFWATCHLIST), me.name, parv[0],
                           *s);
                continue;
            }
            *buf = '\0';
            strcpy(buf, lp->value.wptr->nick);
            count = strlen(parv[0])+strlen(me.name)+10+strlen(buf);
            while ((lp = lp->next)) 
            {
                if (count+strlen(lp->value.wptr->nick)+1 > BUFSIZE - 2) 
                {
                    sendto_one(sptr, rpl_str(RPL_WATCHLIST), me.name,
                               parv[0], buf);
                    listcount++;
                    *buf = '\0';
                    count = strlen(parv[0])+strlen(me.name)+10;
                }
                strcat(buf, " ");
                strcat(buf, lp->value.wptr->nick);
                count += (strlen(lp->value.wptr->nick)+1);
            }
            sendto_one(sptr, rpl_str(RPL_WATCHLIST), me.name, parv[0], buf);
            sendto_one(sptr, rpl_str(RPL_ENDOFWATCHLIST), me.name, parv[0],
                       *s);
            listcount++;
            continue;
        }
                
        /*
         * Well that was fun, NOT.  Now they want a list of everybody in
         * their WATCH list AND if they are online or offline? Sheesh,
         * greedy arn't we?
         */
        if (*s == 'L' || *s == 'l') 
        {
            Link *lp = sptr->watch;
                        
            /* only allowed once per command */
            if (listreq & 0x2)
                continue;
            listreq |= 0x2;

            while (lp) 
            {
                if ((acptr = find_person(lp->value.wptr->nick, NULL)))
                    sendto_one(sptr, rpl_str(RPL_NOWON), me.name, parv[0],
                               acptr->name, acptr->user->username,
                               acptr->user->host, acptr->tsinfo);
                /*
                 * But actually, only show them offline if its a capital
                 * 'L' (full list wanted).
                 */
                else if (IsUpper(*s))
                    sendto_one(sptr, rpl_str(RPL_NOWOFF), me.name, parv[0],
                               lp->value.wptr->nick, "*", "*",
                               lp->value.wptr->lasttime);
                lp = lp->next;
                listcount++;
            }
                        
            sendto_one(sptr, rpl_str(RPL_ENDOFWATCHLIST), me.name, parv[0],
                       *s);
            continue;
        }
        /* Hmm.. unknown prefix character.. Ignore it. :-) */
    }
        
    /* discourage repetitive listings */
#ifdef NO_OPER_FLOOD
    if (!IsAnOper(sptr))
#endif
    if (!NoMsgThrottle(sptr))
        sptr->since += listcount/4;
    
    return 0;
}

int 
m_sqline(aClient *cptr, aClient *sptr, int parc, char *parv[]) 
{
    int flags;
    char *reason;

    if(!(IsServer(sptr) || IsULine(sptr)))
        return 0;

    if(parc < 2) 
    {
        /* we should not get malformed sqlines.  complain loud */
        sendto_realops("%s attempted to add sqline with insufficient params!"
                       " (ignored) Contact coders!", sptr->name);
        return 0;
    }

    reason = BadPtr(parv[2]) ? "Reserved" : parv[2];

    flags = SBAN_PERSIST|SBAN_COMPAT|SBAN_UPDATE;
    if (parv[1][0] == '#')
       flags |= SBAN_CHAN;

    /* complain but pass along invalid bans, all servers will yell */
    if (simban_add(parv[1], reason, 0, 0, flags) == SBAN_ADD_INVALID)
        sendto_realops("SQLINE: invalid ban %s from %s ignored", parv[1],
                       parv[0]);

    sendto_serv_butone(cptr, ":%s SQLINE %s :%s", sptr->name, parv[1],
                       reason);
    return 0;
}
        
int 
m_unsqline(aClient *cptr, aClient *sptr, int parc, char *parv[]) 
{
    int matchit = 0;
    u_int chfl = 0;
    char *mask;
    
    if(!(IsServer(sptr) || IsULine(sptr)))
        return 0;
    
    if(parc < 2) 
    {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0],
                   "UNSQLINE");
        return 0;
    }

    if (parc == 3) 
    {
        matchit = atoi(parv[1]);
        mask = parv[2];
    }
    else
        mask = parv[1];

    if (mask[0] == '#')
        chfl |= SBAN_CHAN;

    if (matchit)
    {
        u_int flags = SBAN_PERSIST|SBAN_COMPAT;
        u_int flagset = SBAN_PERSIST|SBAN_COMPAT|SBAN_CONF;

        /* "UNSQLINE 1 *" deletes all sqlines, nick and chan */
        if (!mycmp(mask, "*"))
            simban_massdel(0, flags, flagset, NULL);
        else
            simban_massdel(0, flags|chfl, flagset|SBAN_CHAN, mask);
    }
    else
        simban_del(mask, chfl);

    if (parc == 3) 
        sendto_serv_butone(cptr, ":%s UNSQLINE %d %s", sptr->name, matchit,
                           mask);
    else
        sendto_serv_butone(cptr, ":%s UNSQLINE %s", sptr->name, mask);
    return 0;
}

int m_sgline(aClient *cptr, aClient *sptr, int parc, char *parv[]) 
{
    int len;
    char *mask, *reason;
    
    if(!(IsServer(sptr) || IsULine(sptr)))
        return 0;

    if(parc<3) 
    {
        sendto_realops("%s attempted to add sgline with insufficient params!"
                       " (ignored) Contact coders!", sptr->name);
        return 0;
    }
        
    len=atoi(parv[1]);
    mask=parv[2];
    if ((strlen(mask) > len) && (mask[len])==':') 
    {
        mask[len] = '\0';
        reason = mask+len+1;
    } 
    else 
    { /* Bogus */
        return 0;
    }
    
    if(BadPtr(reason))
       reason = "Reserved";

    /* complain but pass along invalid bans, all servers will yell */
    if (gcosban_add(0, mask, reason) == GCBAN_ADD_INVALID)
        sendto_realops("SGLINE: invalid ban from %s ignored: %s", parv[0],
                       mask);

    sendto_serv_butone(cptr, ":%s SGLINE %d :%s:%s", sptr->name, len,
                       mask, reason);
    return 0;
}
        
int 
m_unsgline(aClient *cptr, aClient *sptr, int parc, char *parv[]) 
{
    int matchit=0;
    char *mask;
   
    if(!(IsServer(sptr) || IsULine(sptr)))
        return 0;
   
    if(parc<2) 
    {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0],
                   "UNSGLINE");
        return 0;
    }

    if (parc==3) 
    {
        matchit=atoi(parv[1]);
        mask=parv[2];
    }
    else
        mask=parv[1];

    if (matchit)
    {
        if (!mycmp(mask, "*"))
            gcosban_massdel(0, NULL);
        else
            gcosban_massdel(0, mask);
    }
    else
        gcosban_del(0, mask);
    
    if (parc==3)
        sendto_serv_butone(cptr, ":%s UNSGLINE %d :%s", sptr->name, matchit,
                           mask);
    else
        sendto_serv_butone(cptr, ":%s UNSGLINE :%s",sptr->name,mask);
    return 0;
}

u_long
memcount_s_serv(MCs_serv *mc)
{
    aMotd *m;

    mc->file = __FILE__;

    for (m = motd; m; m = m->next)
    {
        mc->motd.c++;
        mc->motd.m += sizeof(*m);
    }
    mc->total.c += mc->motd.c;
    mc->total.m += mc->motd.m;

    for (m = shortmotd; m; m = m->next)
    {
        mc->shortmotd.c++;
        mc->shortmotd.m += sizeof(*m);
    }
    mc->total.c += mc->shortmotd.c;
    mc->total.m += mc->shortmotd.m;

    for (m = helpfile; m; m = m->next)
    {
        mc->help.c++;
        mc->help.m += sizeof(*m);
    }
    mc->total.c += mc->help.c;
    mc->total.m += mc->help.m;

    return mc->total.m;
}

