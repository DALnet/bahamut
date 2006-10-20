/* m_stats.c
 * Copyright (c) 2004, The Bahamut Development Team and Aaron Wiebe
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
#include "zlink.h"
#include "userban.h"
#include "blalloc.h"
#include "throttle.h"
#include "whowas.h"
#include "res.h"
#include "sbuf.h"
#include "clones.h"
#include "memcount.h"

#if defined(DEBUGMODE) && defined(HAVE_GETRUSAGE)
#include <sys/time.h>
#include <sys/resource.h>
#endif

extern float curSendK, curRecvK;
extern aWhowas WHOWAS[];
extern aCache *cachetop;
#ifdef DEBUGMODE
extern void report_fds(aClient *);
#endif
extern char *oflagtotext(int oflags); /* For stats o */

/* internal function defines */

static void show_opers(aClient *, char *);
static void show_servers(aClient *, char *);
#ifdef DEBUGMODE
static void send_usage(aClient *, char *);
#endif
static void serv_info(aClient *, char *);
static void tstats(aClient *, char *);

/* support functions */
/* show_opers
 * replies to stats p requests
 */


#ifdef DEBUGMODE
static void
send_usage(aClient *cptr, char *nick)
{

#if defined( HAVE_GETRUSAGE )
    struct rusage rus;
    time_t      secs, rup;

#ifdef  hz
#define hzz hz
#else
#ifdef HZ
#define hzz HZ
#else
    int         hzz = 1;

#endif
#endif

    if (getrusage(RUSAGE_SELF, &rus) == -1) {
        sendto_one(cptr, ":%s NOTICE %s :Getruseage error: %s.",
                   me.name, nick, sys_errlist[errno]);
        return;
    }
    secs = rus.ru_utime.tv_sec + rus.ru_stime.tv_sec;
    rup = timeofday - me.since;
    if (secs == 0)
        secs = 1;

    sendto_one(cptr,
               ":%s %d %s :CPU Secs %d:%d User %d:%d System %d:%d",
               me.name, RPL_STATSDEBUG, nick, secs / 60, secs % 60,
               rus.ru_utime.tv_sec / 60, rus.ru_utime.tv_sec % 60,
               rus.ru_stime.tv_sec / 60, rus.ru_stime.tv_sec % 60);
    sendto_one(cptr, ":%s %d %s :RSS %d ShMem %d Data %d Stack %d",
               me.name, RPL_STATSDEBUG, nick, rus.ru_maxrss,
               rus.ru_ixrss / (rup * hzz), rus.ru_idrss / (rup * hzz),
               rus.ru_isrss / (rup * hzz));
    sendto_one(cptr, ":%s %d %s :Swaps %d Reclaims %d Faults %d",
               me.name, RPL_STATSDEBUG, nick, rus.ru_nswap,
               rus.ru_minflt, rus.ru_majflt);
    sendto_one(cptr, ":%s %d %s :Block in %d out %d",
               me.name, RPL_STATSDEBUG, nick, rus.ru_inblock,
               rus.ru_oublock);
    sendto_one(cptr, ":%s %d %s :Msg Rcv %d Send %d",
               me.name, RPL_STATSDEBUG, nick, rus.ru_msgrcv, rus.ru_msgsnd);
    sendto_one(cptr, ":%s %d %s :Signals %d Context Vol. %d Invol %d",
               me.name, RPL_STATSDEBUG, nick, rus.ru_nsignals,
               rus.ru_nvcsw, rus.ru_nivcsw);
#else
#if defined( HAVE_TIMES )
    struct tms  tmsbuf;
    time_t      secs, mins;
    int         hzz = 1, ticpermin;
    int         umin, smin, usec, ssec;

    ticpermin = hzz * 60;

    umin = tmsbuf.tms_utime / ticpermin;
    usec = (tmsbuf.tms_utime % ticpermin) / (float) hzz;
    smin = tmsbuf.tms_stime / ticpermin;
    ssec = (tmsbuf.tms_stime % ticpermin) / (float) hzz;
    secs = usec + ssec;
    mins = (secs / 60) + umin + smin;
    secs %= hzz;
    if (times(&tmsbuf) == -1) {
        sendto_one(cptr, ":%s %d %s :times(2) error: %s.",
                   me.name, RPL_STATSDEBUG, nick, strerror(errno));
        return;
    }
    secs = tmsbuf.tms_utime + tmsbuf.tms_stime;

    sendto_one(cptr,
               ":%s %d %s :CPU Secs %d:%d User %d:%d System %d:%d",
               me.name, RPL_STATSDEBUG, nick, mins, secs, umin, usec,
               smin, ssec);
#endif /* HAVE_TIMES */
#endif /* HAVE_GETRUSAGE */
    sendto_one(cptr, ":%s %d %s :Reads %d Writes %d",
               me.name, RPL_STATSDEBUG, nick, readcalls, writecalls);
/*    sendto_one(cptr, ":%s %d %s :DBUF alloc %d used %d",
               me.name, RPL_STATSDEBUG, nick, DBufCount, DBufUsedCount);
               */
    sendto_one(cptr,
               ":%s %d %s :Writes:  <0 %d 0 %d <16 %d <32 %d <64 %d",
               me.name, RPL_STATSDEBUG, nick,
               writeb[0], writeb[1], writeb[2], writeb[3], writeb[4]);
    sendto_one(cptr,
               ":%s %d %s :<128 %d <256 %d <512 %d <1024 %d >1024 %d",
               me.name, RPL_STATSDEBUG, nick,
               writeb[5], writeb[6], writeb[7], writeb[8], writeb[9]);
    return;
}
#endif  /* DEBUGMODE */


static void 
show_opers(aClient *cptr, char *name) 
{
    aClient *cptr2;
    DLink *lp;
    int j = 0;

    for (lp = oper_list; lp; lp = lp->next)
    {
    cptr2 = lp->value.cptr;

    if (!IsAnOper(cptr))
    {
        if (cptr2->umode & UMODE_h)
        {
        sendto_one(cptr, ":%s %d %s :%s (%s@%s) Idle: %d",
               me.name, RPL_STATSDEBUG, name, cptr2->name,
               cptr2->user->username, cptr2->user->host,
               timeofday - cptr2->user->last);
        j++;
        }
    }
    else
    {
        sendto_one(cptr, ":%s %d %s :%s (%s@%s) Idle: %d",
               me.name, RPL_STATSDEBUG, name, cptr2->name,
               cptr2->user->username, cptr2->user->host,
               timeofday - cptr2->user->last);
        j++;
    }
    }
    sendto_one(cptr, ":%s %d %s :%d OPER%s", me.name, RPL_STATSDEBUG,
           name, j, (j == 1) ? "" : "s");
}

/* show_servers
 * replies to stats v requests
 */
static void 
show_servers(aClient *cptr, char *name)
{
    aClient *cptr2;
    DLink *lp;
    int j = 0;

    for (lp = server_list; lp; lp = lp->next)
    {
    cptr2 = lp->value.cptr;

#ifdef HIDEULINEDSERVS
    if(IsULine(cptr2) && !IsAnOper(cptr))
        continue;
#endif
    j++;
    sendto_one(cptr, ":%s %d %s :%s (%s!%s@%s) Idle: %d",
           me.name, RPL_STATSDEBUG, name, cptr2->name,
           (cptr2->serv->bynick[0] ? cptr2->serv->bynick : "Remote."),
           (cptr2->serv->byuser[0] ? cptr2->serv->byuser : "*"),
           (cptr2->serv->byhost[0] ? cptr2->serv->byhost : "*"),
           timeofday - cptr2->lasttime);
    }
    sendto_one(cptr, ":%s %d %s :%d Server%s", me.name, RPL_STATSDEBUG,
           name, j, (j == 1) ? "" : "s");
}

/* serv_info
 * replies to stats ? requests
 */

#define _1MEG   (1024.0)
#define _1GIG   (1024.0*1024.0)
#define _1TER   (1024.0*1024.0*1024.0)
#define _GMKs(x)    ((x > _1TER) ? "Terabytes" : ((x > _1GIG) ? \
                        "Gigabytes" : \
            ((x > _1MEG) ? "Megabytes" : "Kilobytes")))
#define _GMKv(x)    ( (x > _1TER) ? (float)(x/_1TER) : ((x > _1GIG) ? \
            (float)(x/_1GIG) : ((x > _1MEG) ? (float)(x/_1MEG) :\
                        (float)x)))

static void 
serv_info(aClient *cptr, char *name)
{
    static char Lformat[] = ":%s %d %s %s %u %u %u %u %u :%u %u %s";
    long        sendK, receiveK, uptime;
    aClient    *acptr;
    DLink      *lp;
    int         i = 0;

    sendK = receiveK = 0;

    for (lp = server_list; lp; lp = lp->next)
    {
        acptr = lp->value.cptr;

#ifdef HIDEULINEDSERVS
        if (IsULine(acptr) && !IsAnOper(cptr))
            continue;
#endif
        sendK += acptr->sendK;
        receiveK += acptr->receiveK;
        sendto_one(cptr, Lformat, me.name, RPL_STATSLINKINFO,
                    name, ( (MyClient(cptr) && IsAdmin(cptr))
                            ? get_client_name(acptr, FALSE)
                            : get_client_name(acptr, HIDEME) ),
                    (int) SBufLength(&acptr->sendQ),
                    (int) acptr->sendM, (int) acptr->sendK,
                    (int) acptr->receiveM, (int) acptr->receiveK,
                    timeofday - acptr->firsttime, timeofday - acptr->since,
                    IsServer(acptr) ? (DoesTS(acptr) ? "TS" : "NoTS") : "-");


        if(RC4EncLink(acptr))
            sendto_one(cptr, ":%s %d %s : - RC4 encrypted", me.name, 
                        RPL_STATSDEBUG, name);

        if(ZipOut(acptr))
        {
            unsigned long ib, ob;
            double rat;

            zip_out_get_stats(acptr->serv->zip_out, &ib, &ob, &rat);
            if(ib)
            {
                sendto_one(cptr, ":%s %d %s : - [O] Zip inbytes %d, "
                            "outbytes %d (%3.2f%%)", me.name, RPL_STATSDEBUG,
                             name, ib, ob, rat);
            }
        }

        if(ZipIn(acptr))
        {
            unsigned long ib, ob;
            double rat;

            zip_in_get_stats(acptr->serv->zip_in, &ib, &ob, &rat);
            if(ob)
            {
                sendto_one(cptr, ":%s %d %s : - [I] Zip inbytes %d, "
                            "outbytes %d (%3.2f%%)", me.name, RPL_STATSDEBUG,
                             name, ib, ob, rat);
            }
        }
        i++;
    }
    sendto_one(cptr, ":%s %d %s :%u total server%s",
           me.name, RPL_STATSDEBUG, name, i, (i == 1) ? "" : "s");
    sendto_one(cptr, ":%s %d %s :Sent total : %7.2f %s",
           me.name, RPL_STATSDEBUG, name, _GMKv(sendK), _GMKs(sendK));
    sendto_one(cptr, ":%s %d %s :Recv total : %7.2f %s",
           me.name, RPL_STATSDEBUG, name, _GMKv(receiveK),
           _GMKs(receiveK));

    uptime = (timeofday - me.since);
    sendto_one(cptr, ":%s %d %s :Server send: %7.2f %s (%4.1f K/s total,"
                     " %4.1f K/s current)", me.name, RPL_STATSDEBUG, name,
                     _GMKv(me.sendK), _GMKs(me.sendK), 
                    (float) ((float) me.sendK / (float) uptime), curSendK);
    sendto_one(cptr, ":%s %d %s :Server recv: %7.2f %s (%4.1f K/s total,"
                     " %4.1f K/s current)", me.name, RPL_STATSDEBUG, name, 
                    _GMKv(me.receiveK), _GMKs(me.receiveK),
                    (float) ((float) me.receiveK / (float) uptime), curRecvK);
}

/* tstats
 * responced to stats t requests (oddly enough)
 */

static void 
tstats(aClient *cptr, char *name)
{
    aClient *acptr;
    int     i;
    struct stats *sp;
    struct stats tmp;

    sp = &tmp;
    memcpy((char *) sp, (char *) ircstp, sizeof(*sp));
    for (i = 0; i <= highest_fd; i++)
    {
        if (!(acptr = local[i]))
            continue;
        if (IsServer(acptr))
        {
            sp->is_sbs += acptr->sendB;
            sp->is_sbr += acptr->receiveB;
            sp->is_sks += acptr->sendK;
            sp->is_skr += acptr->receiveK;
            sp->is_sti += timeofday - acptr->firsttime;
            sp->is_sv++;
            if (sp->is_sbs > 1023)
            {
                sp->is_sks += (sp->is_sbs >> 10);
                sp->is_sbs &= 0x3ff;
            }
            if (sp->is_sbr > 1023)
            {
                sp->is_skr += (sp->is_sbr >> 10);
                sp->is_sbr &= 0x3ff;
            }

        }
        else if (IsClient(acptr))
        {
            sp->is_cbs += acptr->sendB;
            sp->is_cbr += acptr->receiveB;
            sp->is_cks += acptr->sendK;
            sp->is_ckr += acptr->receiveK;
            sp->is_cti += timeofday - acptr->firsttime;
            sp->is_cl++;
            if (sp->is_cbs > 1023)
            {
                sp->is_cks += (sp->is_cbs >> 10);
                sp->is_cbs &= 0x3ff;
            }
            if (sp->is_cbr > 1023)
            {
                sp->is_ckr += (sp->is_cbr >> 10);
                sp->is_cbr &= 0x3ff;
            }

        }
        else if (IsUnknown(acptr))
            sp->is_ni++;
    }

    sendto_one(cptr, ":%s %d %s :accepts %u refused %u",
               me.name, RPL_STATSDEBUG, name, sp->is_ac, sp->is_ref);
    sendto_one(cptr, ":%s %d %s :unknown commands %u prefixes %u",
               me.name, RPL_STATSDEBUG, name, sp->is_unco, sp->is_unpf);
    sendto_one(cptr, ":%s %d %s :nick collisions %u unknown closes %u",
               me.name, RPL_STATSDEBUG, name, sp->is_kill, sp->is_ni);
    sendto_one(cptr, ":%s %d %s :wrong direction %u empty %u",
               me.name, RPL_STATSDEBUG, name, sp->is_wrdi, sp->is_empt);
    sendto_one(cptr, ":%s %d %s :numerics seen %u mode fakes %u",
               me.name, RPL_STATSDEBUG, name, sp->is_num, sp->is_fake);
    sendto_one(cptr, ":%s %d %s :auth successes %u fails %u",
               me.name, RPL_STATSDEBUG, name, sp->is_asuc, sp->is_abad);
    sendto_one(cptr, ":%s %d %s :drones refused %u throttled rejections %u",
               me.name, RPL_STATSDEBUG, name, sp->is_drone, sp->is_throt);
    sendto_one(cptr, ":%s %d %s :banned users refused before ident/dns"
                     " %u after ident/dns %u", me.name, RPL_STATSDEBUG, 
                     name, sp->is_ref_1, sp->is_ref_2);
    sendto_one(cptr, ":%s %d %s :Client Server", 
                     me.name, RPL_STATSDEBUG, name);
    sendto_one(cptr, ":%s %d %s :connected %u %u",
               me.name, RPL_STATSDEBUG, name, sp->is_cl, sp->is_sv);
    sendto_one(cptr, ":%s %d %s :bytes sent %u.%uK %u.%uK",
               me.name, RPL_STATSDEBUG, name,
               sp->is_cks, sp->is_cbs, sp->is_sks, sp->is_sbs);
    sendto_one(cptr, ":%s %d %s :bytes recv %u.%uK %u.%uK",
               me.name, RPL_STATSDEBUG, name,
               sp->is_ckr, sp->is_cbr, sp->is_skr, sp->is_sbr);
    sendto_one(cptr, ":%s %d %s :time connected %u %u",
               me.name, RPL_STATSDEBUG, name, sp->is_cti, sp->is_sti);
#ifdef FLUD
    sendto_one(cptr, ":%s %d %s :CTCP Floods Blocked %u",
               me.name, RPL_STATSDEBUG, name, sp->is_flud);
#endif /* FLUD */
}


/*  m_stats and friends
 *  Carved off from s_serv.c in Feb04 by epiphani
 *  This mess of routines seemed to go better by themselves, seeing
 *  as how s_serv.c is getting massive.
 *
 * m_stats
 *      parv[0] = sender prefix
 *      parv[1] = statistics selector (defaults to Message frequency)
 *      parv[2] = server name (current server defaulted, if omitted)
 */

int m_stats(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    static char Lformat[] = ":%s %d %s %s %u %u %u %u %u :%u %u %s";
    static char Sformat[] = ":%s %d %s Name SendQ SendM SendBytes RcveM "
                            "RcveBytes :Open_since Idle TS";

    struct Message  *mptr;
    aClient         *acptr;
    char             stat = parc > 1 ? parv[1][0] : '\0';
    int              i, doall = 0, wilds = 0;
    char            *name;
    time_t           sincetime;
    static time_t   last_used = 0L;

#ifdef NO_USER_STATS
    if (!IsAnOper(sptr))
    {
        sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
        return 0;
    }
#else
#ifdef NO_LOCAL_USER_STATS
    if (!IsAnOper(sptr) && !MyConnect(sptr))
    {
        sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
        return 0;
    }
#endif
#endif

    if (hunt_server(cptr, sptr, ":%s STATS %s :%s", 2, parc, parv) != 
                    HUNTED_ISME)
        return 0;

    if (IsSquelch(sptr))
        return 0;

    if (!IsAnOper(sptr) && !IsULine(sptr))
    {
        /* allow remote stats p l ? u */
        if (!((stat == 'p') || (stat == 'P') || (stat=='?') || (stat=='u') ||
              (stat=='l') || (stat=='L')) && !MyConnect(sptr))
            return 0;

        /* if they're my user, penalize them. */
        if (MyConnect(sptr))
            sptr->since += 5;

        if ((last_used + MOTD_WAIT) > NOW)
            return 0;
        else
            last_used = NOW;
    }

    if (parc > 2)
    {
        name = parv[2];
        if (!mycmp(name, me.name))
            doall = 2;
        else if (match(name, me.name) == 0)
            doall = 1;
        if (strchr(name, '*') || strchr(name, '?'))
            wilds = 1;
    }
    else
        name = me.name;

    if (stat != (char) 0 && !IsULine(sptr) && !IsServer(sptr))
        sendto_realops_lev(SPY_LEV, "STATS %c requested by %s (%s@%s) [%s]",
               stat, sptr->name, sptr->user->username,
               sptr->user->host, sptr->user->server);
    switch (stat)
    {
        case 'L':
        case 'l':
        /* changed behavior totally.  This is what we do now:
         * #1: if the user is not opered, never return ips for anything
         * #2: we DON'T deny /stats l for opers.  Ever heard of /sping?
         *     it's easy to see if you're lagging a server, why restrict
         *     something used 99% of the time for good when you're not
         *     doing any harm?
         * #3: NEVER return all users on a server, UGH, just like
         *     /trace, this was fiercely obnoxious.  If you don't
         *     add an argument, you get all SERVER links.
         */
        sendto_one(sptr, Sformat, me.name, RPL_STATSLINKINFO, parv[0]);
        if ((parc > 2) && !(doall || wilds))
        {         /* Single client lookup */
            if (!(acptr = find_person(name, NULL)))
            break;
            /*
             * sincetime might be greater than timeofday,
             * store a new value here to avoid sending
             * negative since-times. -Rak
             */
            sincetime = (acptr->since > timeofday) ? 0 : 
                                timeofday - acptr->since;
            sendto_one(sptr, Lformat, me.name, RPL_STATSLINKINFO, parv[0],
                        get_client_name(acptr, TRUE),
                        (int) SBufLength(&acptr->sendQ),
                        (int) acptr->sendM, (int) acptr->sendK,
                        (int) acptr->receiveM, (int) acptr->receiveK,
                        timeofday - acptr->firsttime, sincetime,
                        IsServer(acptr) ? (DoesTS(acptr) ?
                        "TS" : "NoTS") : "-");
        }
        else
        {
            for (i = 0; i <= highest_fd; i++)
            {
                if (!(acptr = local[i]))
                    continue;
                if(!IsServer(acptr))
                    continue; /* nothing but servers */
#ifdef HIDEULINEDSERVS
                if(IsULine(acptr) && !IsAnOper(sptr))
                    continue;
#endif
                sincetime = (acptr->since > timeofday) ? 0 : 
                             timeofday - acptr->since;
                sendto_one(sptr, Lformat, me.name, RPL_STATSLINKINFO, parv[0],
                        ( (MyClient(sptr) && IsAdmin(sptr))
                          ? get_client_name(acptr, FALSE)
                          : get_client_name(acptr, HIDEME) ),
                        (int) SBufLength(&acptr->sendQ),
                        (int) acptr->sendM, (int) acptr->sendK,
                        (int) acptr->receiveM, (int) acptr->receiveK,
                        timeofday - acptr->firsttime, sincetime,
                        IsServer(acptr) ? (DoesTS(acptr) ?
                        "TS" : "NoTS") : "-");
            }
        }
        break;
        case 'C':
        case 'c':
        /* this should be fixed and combined into a more reasonable
         * single responce.  Will work on this later -epi
         */
#ifdef HIDEULINEDSERVS
        if (!IsAnOper(sptr))
            sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name,  parv[0]);
        else
#endif
        {
            aConnect *tmp;
            if(!connects)
                break;
            for(tmp = connects; tmp; tmp = tmp->next)
            {
                if (tmp->legal == -1)
                    continue;

                if(IsULine(sptr) || (MyClient(sptr) && IsAdmin(sptr)))
                {
                    sendto_one(sptr, rpl_str(RPL_STATSCLINE), me.name,
                           sptr->name, "C", tmp->host, tmp->name, tmp->port,
                           tmp->class->name);
                    sendto_one(sptr, rpl_str(RPL_STATSNLINE), me.name,
                           sptr->name, "N", tmp->host, tmp->name, tmp->flags,
                           tmp->class->name);
                }
                else
                {
                    sendto_one(sptr, rpl_str(RPL_STATSCLINE), me.name,
                               sptr->name, "C", "*", tmp->name, tmp->port,
                               tmp->class->name);
                    sendto_one(sptr, rpl_str(RPL_STATSNLINE), me.name,
                               sptr->name, "N", "*", tmp->name, tmp->flags,
                               tmp->class->name);
                }
            }
        }
        break;

        case 'D':
            if (!IsAnOper(sptr))
                sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
            else
            {
                CloneEnt *ce;

                for (ce = clones_list; ce; ce = ce->next)
                    if (ce->limit || ce->sllimit || ce->sglimit)
                        sendto_one(sptr, rpl_str(RPL_STATSCLONE), me.name,
                                   parv[0], ce->ent, ce->sllimit, ce->sglimit,
                                   ce->limit);
            }
            break;

        case 'd':
            if (!IsAnOper(sptr))
                sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
            else
            {
                CloneEnt *ce;
                int entries = 0;
#ifdef THROTTLE_ENABLE
                int sllimits = 0;
                int sglimits = 0;
                int hlimits = 0;
                int active = 0;
                int sites = 0;
                unsigned long rtot;
#endif

                for (ce = clones_list; ce; ce = ce->next)
                {
                    entries++;
#ifdef THROTTLE_ENABLE
                    if (ce->sllimit)
                        sllimits++;
                    if (ce->sglimit)
                        sglimits++;
                    if (ce->limit)
                        hlimits++;
                    if (ce->gcount)
                    {
                        active++;
                        /* blah, but not important enough for its own flag */
                        if (!ce->clients)
                            sites++;
                    }
#endif
                }

#ifdef THROTTLE_ENABLE
                rtot = clones_stat.rlh + clones_stat.rls
                     + clones_stat.rgh + clones_stat.rgs;

                sendto_one(sptr, ":%s %d %s :Default local host limit: %d"
                           "  site: %d", me.name, RPL_STATSDEBUG, parv[0],
                           local_ip_limit, local_ip24_limit);
                sendto_one(sptr, ":%s %d %s :Default global host limit: %d"
                           "  site: %d", me.name, RPL_STATSDEBUG, parv[0],
                           global_ip_limit, global_ip24_limit);
#endif
                sendto_one(sptr, ":%s %d %s :Clone entries: %d", me.name,
                           RPL_STATSDEBUG, parv[0], entries);
#ifdef THROTTLE_ENABLE
                sendto_one(sptr, ":%s %d %s :    Active hosts: %d  sites: %d",
                           me.name, RPL_STATSDEBUG, parv[0], active-sites,
                           sites);
                sendto_one(sptr, ":%s %d %s :    Soft local limits: %d"
                           "  global: %d", me.name, RPL_STATSDEBUG, parv[0],
                           sllimits, sglimits);
                sendto_one(sptr, ":%s %d %s :    Hard global limits: %d",
                           me.name, RPL_STATSDEBUG, parv[0], hlimits);
                sendto_one(sptr, ":%s %d %s :Rejected connections: %lu",
                           me.name, RPL_STATSDEBUG, parv[0], rtot);
                sendto_one(sptr, ":%s %d %s :    Local hosts: %lu  sites: %lu",
                           me.name, RPL_STATSDEBUG, parv[0],
                           clones_stat.rlh, clones_stat.rls);
                sendto_one(sptr, ":%s %d %s :    Global hosts: %lu  sites: %lu",
                           me.name, RPL_STATSDEBUG, parv[0],
                           clones_stat.rgh, clones_stat.rgs);
#endif
            }
            break;

#if 0
        case 'G':
            if(IsAnOper(sptr))
                report_simbans_match_flags(sptr, SBAN_GCOS|SBAN_LOCAL, 0);
            else
                sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name,  parv[0]);
            break;
        case 'g':
            if(IsAnOper(sptr))
                report_simbans_match_flags(sptr, SBAN_GCOS|SBAN_NETWORK, 0);
            else
                sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name,  parv[0]);
            break;
#endif

        case 'I':
        case 'i':
        {
            aAllow *tmp;
            if(!allows)
                break;
            for(tmp = allows; tmp; tmp = tmp->next)
            {
                if (tmp->passwd && !(IsAnOper(sptr) || IsULine(sptr)))
                    continue;
                sendto_one(sptr, rpl_str(RPL_STATSILINE), me.name,
                           sptr->name, (tmp->legal == -1 ? "Ix" : "I"),
                           tmp->ipmask, tmp->flags, tmp->hostmask, tmp->port,
                           tmp->class->name);
            }
            break;
        }
#if 0
        case 'k':
            if(IsAnOper(sptr))
                report_userbans_match_flags(sptr, UBAN_TEMPORARY|UBAN_LOCAL, 0);
            else
                sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name,  parv[0]);
            break;

        case 'K':
            if (IsAnOper(sptr))
                report_userbans_match_flags(sptr, UBAN_LOCAL, UBAN_TEMPORARY);
            else
                sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name,  parv[0]);
            break;

        case 'A':
        case 'a':
            if(IsAnOper(sptr))
                report_userbans_match_flags(sptr, UBAN_NETWORK, 0);
            else
                sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name,  parv[0]);
            break;
#endif

        case 'M':
        case 'm':
        /*
         * original behaviour was not to report the command, if
         * the command hadn't been used. I'm going to always
         * report the command instead -Dianora
         * Why would users want to see this?  Made Oper only.
         */
            if(IsAnOper(sptr))
                for (mptr = msgtab; mptr->cmd; mptr++)
                    sendto_one(sptr, rpl_str(RPL_STATSCOMMANDS), me.name, 
                            parv[0], mptr->cmd, mptr->count, mptr->bytes);
            break;

        case 'N':
        case 'n':
            sendto_one(sptr, rpl_str(RPL_STATSCOUNT), me.name, parv[0],
                        "User Connects Today: ", Count.today);
            sendto_one(sptr, rpl_str(RPL_STATSCOUNT), me.name, parv[0],
                        "User Connects past week: ", Count.weekly);
            sendto_one(sptr, rpl_str(RPL_STATSCOUNT), me.name, parv[0],
                        "User Connects past month: ", Count.monthly);
            sendto_one(sptr, rpl_str(RPL_STATSCOUNT), me.name, parv[0],
                        "User Connects past year: ", Count.yearly);
            break;
        case 'o':
        case 'O':
        {
            aOper *tmp;
            int i = 0;
            if(!opers)
                break;
            if (IsAnOper(sptr) || IsULine(sptr))
            {
                for(tmp = opers; tmp; tmp = tmp->next)
                    for(i = 0; tmp->hosts[i]; i++)
                        sendto_one(sptr, rpl_str(RPL_STATSOLINE), me.name,
                                sptr->name, (tmp->legal == -1 ? "Ox" : "O"),
                                tmp->hosts[i], tmp->nick, oflagtotext(tmp->flags),
                                tmp->class->name);
            }
            else
            {
                for(tmp = opers; tmp; tmp = tmp->next)
                {
                    if (tmp->legal == -1)
                        continue;
                    sendto_one(sptr, rpl_str(RPL_STATSOLINE), me.name,
                            sptr->name, "O", "*", tmp->nick, oflagtotext(tmp->flags),
                            tmp->class->name);
                }
            }
            break;
        }

        case 'p':
        case 'P':
            show_opers(sptr, parv[0]);
            break;

#if 0
        case 'Q':
            if(IsAnOper(sptr))
            {
                report_simbans_match_flags(sptr, SBAN_NICK|SBAN_LOCAL, 0);
                report_simbans_match_flags(sptr, SBAN_CHAN|SBAN_LOCAL, 0);
            }
            else
                sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name,  parv[0]);
            break;
        case 'q':
            if(IsAnOper(sptr))
            {
                report_simbans_match_flags(sptr, SBAN_NICK|SBAN_NETWORK, 0);
                report_simbans_match_flags(sptr, SBAN_CHAN|SBAN_NETWORK, 0);
            }
            else
                sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name,  parv[0]);
            break;
#endif

        case 'R':
        case 'r':
#ifdef DEBUGMODE
            send_usage(sptr, parv[0]);
#endif
            break;

        case 'S':
        case 's':
            if (IsAnOper(sptr))
                list_scache(cptr, sptr, parc, parv);
            else
                sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name,  parv[0]);
            break;

        case 'T':
            if (IsAnOper(sptr)) 
                throttle_stats(sptr, parv[0]);
            else
                sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name,  parv[0]);
            break;

        case 't':
            if (IsAnOper(sptr))
                tstats(sptr, parv[0]);
            else
                sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name,  parv[0]);
            break;

        case 'U':
#ifdef HIDEULINEDSERVS
            if (!IsOper(sptr))
                sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name,  parv[0]);
            else
#endif
            {
                int i;
                for(i = 0; uservers[i]; i++)
                    sendto_one(sptr, rpl_str(RPL_STATSULINE), me.name,
                    sptr->name, "U", "*", uservers[i], 0, 0);
            }
            break;

        case 'u':
        {
            time_t now;

            now = timeofday - me.since;
            sendto_one(sptr, rpl_str(RPL_STATSUPTIME), me.name, parv[0],
                now / 86400, (now / 3600) % 24, (now / 60) % 60, now % 60);
            break;
        }

        case 'v':
        case 'V':
            show_servers(sptr, parv[0]);
            break;

#ifdef DEBUGMODE
        case 'w':
        case 'W':
            if(IsAnOper(sptr))
                report_fds(sptr);
            else
                sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name,  parv[0]);
            break;
#endif

        case 'Y':
        case 'y':
        {
            aClass *tmp;
            if(!classes)
                break;
            for(tmp = classes; tmp; tmp = tmp->next)
                sendto_one(sptr, rpl_str(RPL_STATSYLINE), me.name,
                           sptr->name, 'Y', tmp->name, tmp->pingfreq,
                           tmp->connfreq, tmp->ip24clones, tmp->maxlinks,
                           tmp->maxsendq);
            break;
        }

        case 'Z':
            if (IsAnOper(sptr))
                report_memory_usage(sptr, 1);
            else
                sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
            break;

        case 'z':
            if (IsAnOper(sptr))
                report_memory_usage(sptr, 0);
            else
                sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
            break;

        case '?':
            serv_info(sptr, parv[0]);
            break;

        default:
            stat = '*';
            break;
    }
    sendto_one(sptr, rpl_str(RPL_ENDOFSTATS), me.name, parv[0], stat);
    return 0;
}

