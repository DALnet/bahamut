/* modules/extra/m_check.c
 *
 * CHECK command — oper check of nick/channel simban status.
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
#include "channel.h"
#include "userban.h"
#include "mapi.h"

extern struct FlagList xflags_list[];

static int m_check(struct MsgBuf *, aClient *, aClient *, int, char **);

static const struct mapi_cmd_av2 check_cmds[] = {
    { "CHECK", 0, {
        { mg_unreg, 0 }, { m_check, 0 }, { m_check, 0 },
        { m_check,  0 }, { m_check, 0 } }},
    { NULL }
};

DECLARE_MODULE("m_check", "2.0", "CHECK nick/channel", 0, check_cmds, NULL);

static int
m_check(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    struct simBan *ban;

    if (!IsAnOper(sptr))
    {
        sendto_one(sptr, getreply(ERR_NOPRIVILEGES), me.name, parv[0]);
        return 0;
    }

    if (parc < 3 || (mycmp(parv[1], "nick") && mycmp(parv[1], "channel")))
    {
        sendto_one(sptr, "NOTICE %s :Syntax: CHECK NICK <nickname>", parv[0]);
        sendto_one(sptr, "NOTICE %s :Syntax: CHECK CHANNEL <channel>", parv[0]);
        return 0;
    }

    if(!mycmp(parv[1], "nick"))
    {
        if ((ban = check_mask_simbanned(parv[2], SBAN_NICK)))
        {
            char *reason = ban->reason ? ban->reason : "<no reason>";

            if (ban->flags & SBAN_TEMPORARY)
                sendto_one(sptr, "NOTICE %s :CHECK NICK: %s [expires in %ldm]: %s",
                           parv[0], ban->mask,
                            (long)((ban->timeset + ban->duration - NOW) / 60),
                           reason);
             else
                sendto_one(sptr, "NOTICE %s :CHECK NICK: %s [permanent]: %s",
                           parv[0], ban->mask, reason);
        }
        else
        {
            sendto_one(sptr, "NOTICE %s :CHECK NICK: no match", parv[0]);
        }
    }
    if(!mycmp(parv[1], "channel"))
    {
        aChannel *chptr;
        struct FlagList *xflag;

        if((chptr = find_channel(parv[2], NULL)))
        {
            sendto_one(sptr, "NOTICE %s :CHECK CHANNEL: %s", parv[0], chptr->chname);
            sendto_one(sptr, "NOTICE %s :JOIN_CONNECT_TIME: %d", parv[0], chptr->join_connect_time);
            sendto_one(sptr, "NOTICE %s :TALK_CONNECT_TIME: %d", parv[0], chptr->talk_connect_time);
            sendto_one(sptr, "NOTICE %s :TALK_JOIN_TIME: %d", parv[0], chptr->talk_join_time);
            sendto_one(sptr, "NOTICE %s :MAX_BANS: %d", parv[0], chptr->max_bans);
            sendto_one(sptr, "NOTICE %s :MAX_INVITES: %d", parv[0], chptr->max_invites);
            sendto_one(sptr, "NOTICE %s :MAX_MSG_TIME: %d:%d", parv[0], chptr->max_messages, chptr->max_messages_time);
            sendto_one(sptr, "NOTICE %s :GREETMSG: %s", parv[0], chptr->greetmsg?chptr->greetmsg:"<NONE>");
            for(xflag = xflags_list; xflag->option; xflag++)
            {
                if(!strcmp(xflag->option,"USER_VERBOSE") || !strcmp(xflag->option,"OPER_VERBOSE")) continue;
                sendto_one(sptr, "NOTICE %s :%s: %s", parv[0], xflag->option, (chptr->xflags & xflag->flag)?"On":"Off");
            }
            sendto_one(sptr, "NOTICE %s :*** End of Check ***", parv[0]);
        }
        else
        {
            sendto_one(sptr, "NOTICE %s :CHECK CHANNEL: no match", parv[0]);
        }
    }

    return 0;
}
