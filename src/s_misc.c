/************************************************************************
 *   IRC - Internet Relay Chat, src/s_misc.c
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

#include <sys/time.h>
#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "zlink.h"
#include "hooks.h"
#include "clones.h"
#include <sys/stat.h>
#include <fcntl.h>
#if !defined(ULTRIX) && !defined(SGI) && !defined(sequent) && \
    !defined(__convex__)
#include <sys/param.h>
#endif
#if defined(AIX) || defined(SVR3) || \
   ((__GNU_LIBRARY__ == 6) && (__GLIBC__ >=2) && (__GLIBC_MINOR__ >= 2))
#include <time.h>
#endif
#include "h.h"
#include "fdlist.h"

extern float curSendK, curRecvK;

extern int  server_was_split;

#ifdef ALWAYS_SEND_DURING_SPLIT
int currently_processing_netsplit = NO;
#endif

static void exit_one_client(aClient *, aClient *, aClient *, char *);

static char *months[] =
{
    "January", "February", "March", "April",
    "May", "June", "July", "August",
    "September", "October", "November", "December"
};

static char *weekdays[] =
{
    "Sunday", "Monday", "Tuesday", "Wednesday",
    "Thursday", "Friday", "Saturday"
};

/* stats stuff */
struct stats ircst, *ircstp = &ircst;

char *
date(time_t clock)
{
    static char buf[80], plus;
    struct tm *lt, *gm;
    struct tm   gmbuf;
    int         minswest;

    if (!clock)
        time(&clock);
    gm = gmtime(&clock);
    memcpy((char *) &gmbuf, (char *) gm, sizeof(gmbuf));
    gm = &gmbuf;
    lt = localtime(&clock);

    if (lt->tm_yday == gm->tm_yday)
        minswest = (gm->tm_hour - lt->tm_hour) * 60 + (gm->tm_min - lt->tm_min);
    else if (lt->tm_yday > gm->tm_yday)
        minswest = (gm->tm_hour - (lt->tm_hour + 24)) * 60;
    else
        minswest = ((gm->tm_hour + 24) - lt->tm_hour) * 60;

    plus = (minswest > 0) ? '-' : '+';
    if (minswest < 0)
        minswest = -minswest;
    
    ircsprintf(buf, "%s %s %d %04d -- %02d:%02d %c%02d:%02d",
               weekdays[lt->tm_wday], months[lt->tm_mon], lt->tm_mday,
               lt->tm_year + 1900, lt->tm_hour, lt->tm_min,
               plus, minswest / 60, minswest % 60);

    return buf;
}

char *
smalldate(time_t clock)
{
    static char buf[MAX_DATE_STRING];
    struct tm *lt, *gm;
    struct tm   gmbuf;

    if (!clock)
        time(&clock);
    gm = gmtime(&clock);
    memcpy((char *) &gmbuf, (char *) gm, sizeof(gmbuf));
    gm = &gmbuf;
    lt = localtime(&clock);

    ircsprintf(buf, "%04d/%02d/%02d %02d.%02d", lt->tm_year + 1900, 
               lt->tm_mon + 1, lt->tm_mday, lt->tm_hour, lt->tm_min);

    return buf;
}

/**
 ** myctime()
 **   This is like standard ctime()-function, but it zaps away
 **   the newline from the end of that string. Also, it takes
 **   the time value as parameter, instead of pointer to it.
 **   Note that it is necessary to copy the string to alternate
 **   buffer (who knows how ctime() implements it, maybe it statically
 **   has newline there and never 'refreshes' it -- zapping that
 **   might break things in other places...)
 **
 **/
char *
myctime(time_t value)
{
    static char buf[28];
    char   *p;

    strcpy(buf, ctime(&value));
    if ((p = (char *) strchr(buf, '\n')) != NULL)
        *p = '\0';

    return buf;
}

/*
 * * check_registered_user is used to cancel message, if the *
 * originator is a server or not registered yet. In other * words,
 * passing this test, *MUST* guarantee that the * sptr->user exists
 * (not checked after this--let there * be coredumps to catch bugs...
 * this is intentional --msa ;) *
 * 
 * There is this nagging feeling... should this NOT_REGISTERED * error
 * really be sent to remote users? This happening means * that remote
 * servers have this user registered, although this * one has it not...
 * Not really users fault... Perhaps this * error message should be
 * restricted to local clients and some * other thing generated for
 * remotes...
 */
inline int 
check_registered_user(aClient *sptr)
{
    if (!IsRegisteredUser(sptr)) 
    {
        sendto_one(sptr, err_str(ERR_NOTREGISTERED), me.name, "*");
        return -1;
    }
    return 0;
}

/*
 * * check_registered user cancels message, if 'x' is not * registered
 * (e.g. we don't know yet whether a server * or user)
 */
inline int 
check_registered(aClient *sptr)
{
    if (!IsRegistered(sptr))
    {
        sendto_one(sptr, err_str(ERR_NOTREGISTERED), me.name, "*");
        return -1;
    }
    return 0;
}

inline char *
get_listener_name(aListener *lptr)
{
   static char nbuf[HOSTLEN * 2 + USERLEN + 5];

   ircsprintf(nbuf, "%s[@%s.%d][%s]", me.name, BadPtr(lptr->vhost_string) ?
              "0.0.0.0" : lptr->vhost_string, lptr->port, 
               BadPtr(lptr->allow_string) ?  "*" : lptr->allow_string);

   return nbuf;
}

/*
 * get_client_name
 *
 * Return the name of the client for various tracking and admin purposes.
 * The main purpose of this function is to  return the "socket host" name of
 * the client, if that differs from the advertised name (other than case).
 * But, this can be used on any client structure.
 *
 * Returns:
 *     "name" for remote clients
 *     "name" for local connections when showip is HIDEME
 *     "nick!user@host" for local clients when showip is TRUE or FALSE
 *     "name[host]" for local servers when showip is TRUE or FALSE
 *     "<unnamed>([F]ident@ip)" for unregistered connections
 *     "nick([F]ident@ip)" for incomplete client when showip is TRUE or FALSE
 *         where "F" is ident status:
 *             '?' lookup in progress, ident is "unknown"
 *             '+' identd response, ident is valid
 *             '-' no identd response, ident is "unknown"
 * 
 * NOTE: Function return either a pointer to the structure (sptr) or to
 * internal buffer (nbuf). *NEVER* use the returned pointer to modify what
 * it points!!!
 */
char *
get_client_name(aClient *sptr, int showip)
{
    static char nbuf[HOSTLEN * 2 + USERLEN + 7];
    char *s = nbuf;

    if (MyConnect(sptr)) 
    {
        if (sptr->name[0])
            s += ircsprintf(s, "%s", sptr->name);
        else
            s += ircsprintf(s, "<unnamed>", sptr->name);

        if (IsServer(sptr))
        {
            if (showip == TRUE)
                s += ircsprintf(s, "[%s]", inetntoa((char *)&sptr->ip));
            else if (showip != HIDEME)
                s += ircsprintf(s, "[%s]", sptr->sockhost);
        }
        else if (IsClient(sptr))
        {
            if (showip == TRUE)
                s += ircsprintf(s, "!%s@%s", sptr->user->username,
                                inetntoa((char *)&sptr->ip));
            else if (showip != HIDEME)
                s += ircsprintf(s, "!%s@%s", sptr->user->username,
                                sptr->user->host);
        }
        else
        {
            if (showip != HIDEME)
            {
                s += ircsprintf(s, "([");

                if (DoingAuth(sptr))
                    *s++ = '?';
                else if (sptr->flags & FLAGS_GOTID)
                    *s++ = '+';
                else
                    *s++ = '-';

                if (showip == TRUE)
                    s += ircsprintf(s, "]%s@%s)", sptr->username,
                                    inetntoa((char *)&sptr->ip));
                else
                    s += ircsprintf(s, "]%s@%s)", sptr->username,
                                    sptr->sockhost);
            }
        }

        return nbuf;
    }

    return sptr->name;
}

/*
 * Form sockhost such that if the host is of form user@host, only the
 * host portion is copied.
 */
void 
get_sockhost(aClient *cptr, char *host)
{
    char *s;

    if ((s = (char *) strchr(host, '@')))
        s++;
    else
        s = host;
    strncpyzt(cptr->sockhost, s, sizeof(cptr->sockhost));
}

/*
 * Return wildcard name of my server name according to given config
 * entry --Jto
 */
char *
my_name_for_link(char *name, aConnect *aconn)
{
    static char namebuf[HOSTLEN];
    int count = aconn->port;
    char *start = name;

    if (count <= 0 || count > 5)
        return start;

    while (count-- && name) 
    {
        name++;
        name = (char *) strchr(name, '.');
    }
    if (!name)
        return start;

    namebuf[0] = '*';
    strncpy(&namebuf[1], name, HOSTLEN - 1);
    namebuf[HOSTLEN - 1] = '\0';
    return namebuf;
}

int remove_dcc_references(aClient *sptr)
{  
    aClient *acptr;
    Link *lp, *nextlp;
    Link **lpp, *tmp;
    int found;
            
    lp = sptr->user->dccallow;
            
    while(lp)
    {  
        nextlp = lp->next;
        acptr = lp->value.cptr;
        for(found = 0, lpp = &(acptr->user->dccallow); 
            *lpp; lpp=&((*lpp)->next))
        {  
            if(lp->flags == (*lpp)->flags)
                continue; /* match only opposite types for sanity */
            if((*lpp)->value.cptr == sptr)
            {
                if((*lpp)->flags == DCC_LINK_ME)
                {  
                    sendto_one(acptr, ":%s %d %s :%s has been removed from "
                               "your DCC allow list for signing off",
                               me.name, RPL_DCCINFO, acptr->name, sptr->name);
                }
                tmp = *lpp;
                *lpp = tmp->next;
                free_link(tmp);
                found++;
                break;
            }
        }
         
        if(!found)
            sendto_realops_lev(DEBUG_LEV, "rdr(): %s was in dccallowme "
                               "list[%d] of %s but not in dccallowrem list!",
                               acptr->name, lp->flags, sptr->name);
        free_link(lp);
        lp = nextlp;
    }
    return 0;
}  

/*
 * NOQUIT
 * a method of reducing the stress on the network during server splits
 * by sending only a simple "SQUIT" message for the server that is dropping,
 * instead of thousands upon thousands of QUIT messages for each user,
 * plus an SQUIT for each server behind the dead link.
 *
 * Original idea by Cabal95, implementation by lucas
 */

void 
exit_one_client_in_split(aClient *cptr, aClient *dead, char *reason)
{
    Link *lp;

    /* send all the quit reasons to all the non-noquit servers we have */
    
    /* yikes. We only want to do this if dead was OUR server. */
    /* erm, no, that's not true. Doing that breaks things. 
     * If a non-noquit server is telling us a server has split,
     * we will have already recieved hundreds of QUIT messages
     * from it, which will be passed anyway, and this procedure
     * will never be called. - lucas
     */

#ifdef NOQUIT
    sendto_non_noquit_servs_butone(dead, ":%s QUIT :%s", cptr->name, reason);
#endif

    sendto_common_channels(cptr, ":%s QUIT :%s", cptr->name, reason);
    
    while ((lp = cptr->user->channel))
        remove_user_from_channel(cptr, lp->value.chptr);
    while ((lp = cptr->user->invited))
        del_invite(cptr, lp->value.chptr);
    while ((lp = cptr->user->silence))
        del_silence(cptr, lp->value.cp);
    if (cptr->user->alias)
        cptr->user->alias->client = NULL;

    if (cptr->ip.s_addr)
        clones_remove(cptr);

#ifdef RWHO_PROBABILITY
    probability_remove(cptr);
#endif

    remove_dcc_references(cptr);

    del_from_client_hash_table(cptr->name, cptr); 

    hash_check_watch(cptr, RPL_LOGOFF);

    remove_client_from_list(cptr);
}

/* exit_one_server
 *
 * recursive function!
 * therefore, we pass dead and reason to ourselves.
 * in the beginning, dead == cptr, so it will be the one
 *  out of the loop last. therefore, dead should remain a good pointer.
 * cptr: the server being exited
 * dead: the actual server that split (if this belongs to us, we
 *       absolutely CANNOT send to it)
 * from: the client that caused this split
 * lcptr: the local client that initiated this
 * spinfo: split reason, as generated in exit_server
 * comment: comment provided
 */

void 
exit_one_server(aClient *cptr, aClient *dead, aClient *from, 
                aClient *lcptr, char *spinfo, char *comment)
{
    aClient *acptr, *next;
    DLink *lp;

    /* okay, this is annoying.
     * first off, we need two loops.
     * one: to remove all the clients.
     * two: to remove all the servers.
     * HOWEVER! removing a server may cause removal of more servers 
     * and more clients.
     * and this may make our pointer to next bad. therefore, we have to restart
     *  the server loop each time we find a server.
     * We _NEED_ two different loops: all clients must be removed "
     * before the server is
     *  removed. Otherwise, bad things (tm) can happen.
     */

    Debug((DEBUG_NOTICE, "server noquit: %s", cptr->name));

    for (acptr = client; acptr; acptr = next) 
    {
        next = acptr->next; /* we might destroy this client record 
                             * in the loop. */
        
        if(acptr->uplink != cptr || !IsPerson(acptr)) 
            continue;

        exit_one_client_in_split(acptr, dead, spinfo);
    }

    for (acptr = client; acptr; acptr = next) 
    {
        next = acptr->next; /* we might destroy this client record in 
                             * the loop. */

        if(acptr->uplink != cptr || !IsServer(acptr)) 
            continue;

        exit_one_server(acptr, dead, from, lcptr, spinfo, comment);
        next = client; /* restart the loop */
    }

    Debug((DEBUG_NOTICE, "done exiting server: %s", cptr->name));

    for (lp = server_list; lp; lp = lp->next)
    {
        acptr = lp->value.cptr;

        if (acptr == cptr || IsMe(acptr) ||
            acptr == dead || acptr == lcptr)
            continue;

        /* if the server is noquit, we only want to send it
         *  information about 'dead'
         * if it's not, this server gets split information for ALL
         * dead servers.
         */

#ifdef NOQUIT
        if(IsNoquit(acptr))
#endif
        if(cptr != dead)
            continue;

        if (cptr->from == acptr) /* "upstream" squit */
            sendto_one(acptr, ":%s SQUIT %s :%s", from->name, cptr->name,
                       comment);
        else 
            sendto_one(acptr, "SQUIT %s :%s", cptr->name, comment);
    }

    del_from_client_hash_table(cptr->name, cptr); 
    hash_check_watch(cptr, RPL_LOGOFF);
    remove_client_from_list(cptr);
}

/* exit_server
 *
 * lcptr: the local client that initiated this
 * cptr: the server that is being dropped.
 * from: the client/server that caused this to happen
 * comment: reason this is happening
 * we then call exit_one_server, the recursive function.
 */

void exit_server(aClient *lcptr, aClient *cptr, aClient *from, char *comment)
{
    char splitname[HOSTLEN + HOSTLEN + 2];

#ifdef HIDE_SPLIT_SERVERS
    ircsprintf(splitname, "%s %s", HIDDEN_SERVER_NAME, HIDDEN_SERVER_NAME);
#else
    ircsprintf(splitname, "%s %s", cptr->uplink->name, cptr->name);
#endif

    Debug((DEBUG_NOTICE, "exit_server(%s, %s, %s)", cptr->name, from->name,
           comment));

    exit_one_server(cptr, cptr, from, lcptr, splitname, comment);
}

/*
 *  exit_client 
 * This is old "m_bye". Name  changed, because this is not a
 * protocol function, but a general server utility function.
 * 
 *      This function exits a client of *any* type (user, server, etc) 
 * from this server. Also, this generates all necessary prototol 
 * messages that this exit may cause. 
 * 
 *   1) If the client is a local client, then this implicitly exits
 * all other clients depending on this connection (e.g. remote
 * clients having 'from'-field that points to this. 
 * 
 *   2) If the client is a remote client, then only this is exited. 
 * 
 * For convenience, this function returns a suitable value for 
 * m_function return value: 
 * 
 *      FLUSH_BUFFER    if (cptr == sptr) 
 *      0 if (cptr != sptr)
 */
int 
exit_client(aClient *cptr, aClient *sptr, aClient *from, char *comment)
{
#ifdef  FNAME_USERLOG
    time_t on_for;
#endif
    
    if (MyConnect(sptr)) 
    {
        call_hooks(CHOOK_SIGNOFF, sptr);

        if (IsUnknown(sptr))
            Count.unknown--;
        if (IsAnOper(sptr)) 
            remove_from_list(&oper_list, sptr, NULL);
        if (sptr->flags & FLAGS_HAVERECVQ)
        {
            /* mark invalid, will be deleted in do_recvqs() */
            DLink *lp = find_dlink(recvq_clients, sptr);
            if (lp)
                lp->flags = -1;
        }
        if (IsClient(sptr))
            Count.local--;
        if (IsNegoServer(sptr))
            sendto_realops("Lost server %s during negotiation: %s", 
                           sptr->name, comment);
        
        if (IsServer(sptr)) 
        {
            Count.myserver--;
            if (IsULine(sptr))
                Count.myulined--;
            remove_from_list(&server_list, sptr, NULL);
            if (server_list == NULL) 
                server_was_split = YES;
        }
        sptr->flags |= FLAGS_CLOSING;
        if (IsPerson(sptr)) 
        {
            Link *lp, *next;
            LOpts *lopt = sptr->user->lopt;
            /* poof goes their watchlist! */
            hash_del_watch_list(sptr);
            /* if they have listopts, axe those, too */
            if(lopt != NULL) 
            {
                remove_from_list(&listing_clients, sptr, NULL);
                for (lp = lopt->yeslist; lp; lp = next) 
                {
                    next = lp->next;
                    MyFree(lp->value.cp);
                    free_link(lp);
                }
                for (lp = lopt->nolist; lp; lp = next) 
                {
                    next = lp->next;
                    MyFree(lp->value.cp);
                    free_link(lp);
                }
                                
                MyFree(sptr->user->lopt);
                sptr->user->lopt = NULL;
            }
            sendto_realops_lev(CCONN_LEV,
                               "Client exiting: %s (%s@%s) [%s] [%s]",
                               sptr->name, sptr->user->username,
                               sptr->user->host,
                               (sptr->flags & FLAGS_NORMALEX) ?
                               "Client Quit" : comment,
                               sptr->hostip);
        }
#ifdef FNAME_USERLOG
        on_for = timeofday - sptr->firsttime;
#endif
#if defined(USE_SYSLOG) && defined(SYSLOG_USERS)
        if (IsPerson(sptr))
            syslog(LOG_NOTICE, "%s (%3d:%02d:%02d): %s!%s@%s %d/%d\n",
                   myctime(sptr->firsttime),
                   on_for / 3600, (on_for % 3600) / 60,
                   on_for % 60, sptr->name,
                   sptr->user->username, sptr->user->host,
                   sptr->sendK, sptr->receiveK);
#endif
#if defined(FNAME_USERLOG)
        {
            char        linebuf[300];
            static int  logfile = -1;
            static long lasttime;
            
            /*
             * This conditional makes the logfile active only after it's
             * been created - thus logging can be turned off by removing
             * the file.
             * 
             * stop NFS hangs...most systems should be able to open a file in
             * 3 seconds. -avalon (curtesy of wumpus)
             * 
             * Keep the logfile open, syncing it every 10 seconds -Taner
             */
            if (IsPerson(sptr)) 
            {
                if (logfile == -1) 
                {
                    alarm(3);
                    logfile = open(FNAME_USERLOG, O_WRONLY | O_APPEND);
                    alarm(0);
                }
                ircsprintf(linebuf, "%s (%3d:%02d:%02d): %s!%s@%s %d/%d\n",
                           myctime(sptr->firsttime), on_for / 3600,
                           (on_for % 3600) / 60, on_for % 60,
                           sptr->name, sptr->user->username,
                           sptr->user->host, sptr->sendK, sptr->receiveK);
                alarm(3);
                write(logfile, linebuf, strlen(linebuf));
                alarm(0);
                /* Resync the file evey 10 seconds*/
                if (timeofday - lasttime > 10) 
                {
                    alarm(3);
                    close(logfile);
                    alarm(0);
                    logfile = -1;
                    lasttime = timeofday;
                }
            }
        }
#endif
        if (sptr->fd >= 0) 
        {
            if (cptr != NULL && sptr != cptr)
                sendto_one(sptr, "ERROR :Closing Link: %s %s (%s)",
                           IsPerson(sptr) ? sptr->sockhost : "0.0.0.0", 
                           sptr->name, comment);
            else
                sendto_one(sptr, "ERROR :Closing Link: %s (%s)",
                           IsPerson(sptr) ? sptr->sockhost : "0.0.0.0", 
                           comment);
        }
        /*
         * * Currently only server connections can have * depending
         * remote clients here, but it does no * harm to check for all
         * local clients. In * future some other clients than servers
         * might * have remotes too... *
         * 
         * Close the Client connection first and mark it * so that no
         * messages are attempted to send to it. *, The following *must*
         * make MyConnect(sptr) == FALSE!). * It also makes sptr->from ==
         * NULL, thus it's unnecessary * to test whether "sptr != acptr"
         * in the following loops.
         */
        if (IsServer(sptr)) 
        {
            sendto_ops("%s was connected for %lu seconds.  %lu/%lu "
                       "sendK/recvK.", sptr->name, timeofday - sptr->firsttime,
                       sptr->sendK, sptr->receiveK);
#ifdef USE_SYSLOG
            syslog(LOG_NOTICE, "%s was connected for %lu seconds.  %lu/%lu "
                   "sendK/recvK.", sptr->name, 
                        (u_long) timeofday - sptr->firsttime,
                   sptr->sendK, sptr->receiveK);
#endif
            close_connection(sptr);
            sptr->sockerr = 0;
            sptr->flags |= FLAGS_DEADSOCKET;
        }
        else
        {
            close_connection(sptr);
            sptr->sockerr = 0;
            sptr->flags |= FLAGS_DEADSOCKET;
        }
                
    }
    exit_one_client(cptr, sptr, from, comment);
    return cptr == sptr ? FLUSH_BUFFER : 0;
}

/*
 * Exit one client, local or remote. Assuming all dependants have
 * been already removed, and socket closed for local client.
 */
static void 
exit_one_client(aClient *cptr, aClient *sptr, aClient *from, char *comment)
{
    Link   *lp;
    
    /*
     * For a server or user quitting, propogate the information to
     * other servers (except to the one where is came from (cptr))
     */
    if (IsMe(sptr))
    {
        sendto_ops("ERROR: tried to exit me! : %s", comment);
        return;                 /* ...must *never* exit self!! */
    }
    else if (IsServer(sptr))
    {
#ifdef ALWAYS_SEND_DURING_SPLIT
        currently_processing_netsplit = YES;
#endif

        exit_server(cptr, sptr, from, comment);
        
#ifdef ALWAYS_SEND_DURING_SPLIT
        currently_processing_netsplit = NO;
#endif
        return;
    }
    else if (!(IsPerson(sptr)))
        /*
         * ...this test is *dubious*, would need * some thought.. but for
         * now it plugs a * nasty hole in the server... --msa
         */
        ;                               /* Nothing */
    else if (sptr->name[0])
    {   
        /* ...just clean all others with QUIT... */
        /*
         * If this exit is generated from "m_kill", then there is no
         * sense in sending the QUIT--KILL's have been sent instead.
         */
        if ((sptr->flags & FLAGS_KILLED) == 0) 
        {
            sendto_serv_butone(cptr, ":%s QUIT :%s",
                               sptr->name, comment);
        }
        /*
         * * If a person is on a channel, send a QUIT notice * to every
         * client (person) on the same channel (so * that the client can
         * show the "**signoff" message). * (Note: The notice is to the
         * local clients *only*)
         */
        if (sptr->user)
        {
            send_part_to_common_channels(sptr, comment);
            send_quit_to_common_channels(sptr, comment);
            while ((lp = sptr->user->channel))
                remove_user_from_channel(sptr, lp->value.chptr);

            if (sptr->ip.s_addr)
                clones_remove(sptr);

#ifdef RWHO_PROBABILITY
            probability_remove(sptr);
#endif
            
            /* Clean up invitefield */
            while ((lp = sptr->user->invited))
                del_invite(sptr, lp->value.chptr);
            /* Clean up silences */
            while ((lp = sptr->user->silence)) 
                del_silence(sptr, lp->value.cp);
            remove_dcc_references(sptr);
            /* again, this is all that is needed */
        }
    }

    /* Remove sptr from the client list */
    if (del_from_client_hash_table(sptr->name, sptr) != 1) 
    {
        Debug((DEBUG_ERROR, "%#x !in tab %s[%s] %#x %#x %#x %d %d %#x",
               sptr, sptr->name,
               sptr->from ? sptr->from->sockhost : "??host",
               sptr->from, sptr->next, sptr->prev, sptr->fd,
               sptr->status, sptr->user));
    }
    /* remove user from watchlists */
    if(IsRegistered(sptr))
        hash_check_watch(sptr, RPL_LOGOFF);
    remove_client_from_list(sptr);
    return;
}

void 
initstats()
{
    memset((char *) &ircst, '\0', sizeof(ircst));
}

char *
make_parv_copy(char *pbuf, int parc, char *parv[])
{
   int pbpos = 0, i;

   for(i = 1; i < parc; i++)
   {
      char *tmp = parv[i];

      if(i != 1)
         pbuf[pbpos++] = ' ';
      if(i == (parc - 1))
         pbuf[pbpos++] = ':';

      while(*tmp)
         pbuf[pbpos++] = *(tmp++);
   }
   pbuf[pbpos] = '\0';

   return pbuf;
}
