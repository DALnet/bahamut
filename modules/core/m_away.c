/* modules/core/m_away.c
 *
 * AWAY and USERS commands.
 * m_away extracted from src/s_user.c; m_users from src/s_serv.c.
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
#include "send.h"
#include "spamfilter.h"
#include "mapi.h"

extern int  is_luserslocked(void);
extern void send_fake_users(aClient *);

static int m_away(struct MsgBuf *, aClient *, aClient *, int, char **);
static int m_users(struct MsgBuf *, aClient *, aClient *, int, char **);

static const struct mapi_cmd_av2 away_cmds[] = {
    { "AWAY", 0, {
        { mg_unreg, 0 },           /* HANDLER_UNREG   */
        { m_away,   0 },           /* HANDLER_CLIENT  */
        { m_away,   0 },           /* HANDLER_REMOTE  */
        { m_away,   0 },           /* HANDLER_SERVER  */
        { m_away,   0 },           /* HANDLER_OPER    */
    }},
    { "USERS", 0, {
        { mg_unreg, 0 },           /* HANDLER_UNREG   */
        { m_users,  0 },           /* HANDLER_CLIENT  */
        { m_users,  0 },           /* HANDLER_REMOTE  */
        { m_users,  0 },           /* HANDLER_SERVER  */
        { m_users,  0 },           /* HANDLER_OPER    */
    }},
    { NULL }
};

DECLARE_CORE_MODULE("m_away", "2.0", "AWAY and USERS", away_cmds, NULL);

/*
 * m_away
 * parv[0] = sender prefix
 * parv[1] = away message
 */
static int
m_away(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    char   *away, *awy2 = parv[1];
    /* make sure the user exists */
    if (!(sptr->user))
    {
        sendto_realops_lev(DEBUG_LEV, "Got AWAY from nil user, from %s (%s)\n",
                           cptr->name, sptr->name);
        return 0;
    }

    away = sptr->user->away;

#ifdef NO_AWAY_FLUD
    if(MyClient(sptr))
    {
        if ((sptr->alas + MAX_AWAY_TIME) < NOW)
            sptr->acount = 0;
        sptr->alas = NOW;
        sptr->acount++;
    }
#endif

    if (parc < 2 || !*awy2)
    {
        /* Marking as not away */
        if (away)
        {
            MyFree(away);
            sptr->user->away = NULL;
            /* Don't spam unaway unless they were away - lucas */
            sendto_serv_butone_super(cptr, ULF_NOAWAY, ":%s AWAY", parv[0]);
            call_hooks(CHOOK_AWAY, sptr, 0, NULL);
        }

        if (MyConnect(sptr))
            sendto_one(sptr, rpl_str(RPL_UNAWAY), me.name, parv[0]);
        return 0;
    }

    /* Marking as away */
#ifdef NO_AWAY_FLUD
    /* we dont care if they are just unsetting away, hence this is here */
    /* only care about local non-opers */
    if (MyClient(sptr) && (sptr->acount > MAX_AWAY_COUNT) && !IsAnOper(sptr))
    {
        sendto_one(sptr, err_str(ERR_TOOMANYAWAY), me.name, parv[0]);
        return 0;
    }
#endif
    if (strlen(awy2) > (size_t) TOPICLEN)
        awy2[TOPICLEN] = '\0';

#ifdef SPAMFILTER
    if(MyClient(sptr) && check_sf(sptr, awy2, "away", SF_CMD_AWAY, sptr->name))
        return FLUSH_BUFFER;
#endif

    sendto_serv_butone_super(cptr, ULF_NOAWAY, ":%s AWAY :%s", parv[0], parv[1]);

    if (away)
        MyFree(away);

    away = (char *) MyMalloc(strlen(awy2) + 1);
    strcpy(away, awy2);

    sptr->user->away = away;

    call_hooks(CHOOK_AWAY, sptr, 1, away);

    if (MyConnect(sptr))
        sendto_one(sptr, rpl_str(RPL_NOWAWAY), me.name, parv[0]);

    return 0;
}

/*
 * m_users
 * parv[0] = sender prefix
 * parv[1] = servername
 */
static int
m_users(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr, int parc, char *parv[])
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
