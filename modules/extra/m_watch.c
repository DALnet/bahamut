/* modules/extra/m_watch.c
 *
 * WATCH command — track nick on/offline notifications.
 * Extracted from src/s_serv.c.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "numeric.h"
#include "mapi.h"

static int m_watch(struct MsgBuf *, aClient *, aClient *, int, char **);

static const struct mapi_cmd_av2 watch_cmds[] = {
    { "WATCH", 0, {
        { mg_unreg, 0 }, { m_watch, 0 }, { m_watch, 0 },
        { m_watch,  0 }, { m_watch, 0 } }},
    { NULL }
};

DECLARE_MODULE("m_watch", "2.0", "WATCH list", 0, watch_cmds, NULL);

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
#ifdef USER_HOSTMASKING
                   IsUmodeH(acptr)?acptr->user->mhost:
#endif
                                                      acptr->user->host,
                   acptr->lasttime);
    else
        sendto_one(cptr, rpl_str(rpl2), me.name, cptr->name,
                   name, "*", "*", 0);
}

/* m_watch */
static int
m_watch(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr, int parc, char *parv[])
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
            char wbuf[BUFSIZE];

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
            *wbuf = '\0';
            strcpy(wbuf, lp->value.wptr->nick);
            count = strlen(parv[0])+strlen(me.name)+10+strlen(wbuf);
            while ((lp = lp->next))
            {
                if (count+strlen(lp->value.wptr->nick)+1 > BUFSIZE - 2)
                {
                    sendto_one(sptr, rpl_str(RPL_WATCHLIST), me.name,
                               parv[0], wbuf);
                    listcount++;
                    *wbuf = '\0';
                    count = strlen(parv[0])+strlen(me.name)+10;
                }
                strcat(wbuf, " ");
                strcat(wbuf, lp->value.wptr->nick);
                count += (strlen(lp->value.wptr->nick)+1);
            }
            sendto_one(sptr, rpl_str(RPL_WATCHLIST), me.name, parv[0], wbuf);
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
#ifdef USER_HOSTMASKING
                               IsUmodeH(acptr)?acptr->user->mhost:
#endif
                                                                  acptr->user->host,
                               acptr->tsinfo);
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
