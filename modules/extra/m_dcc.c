/* modules/extra/m_dcc.c
 *
 * DCC-related commands — DCCALLOW allow list management.
 * Extracted from src/s_user.c.
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

/* del_dccallow lives in s_user.c and is used by exit_client; declare it here */
extern int del_dccallow(aClient *, aClient *, int);

static int m_dccallow(struct MsgBuf *, aClient *, aClient *, int, char **);

static const struct mapi_cmd_av2 dcc_cmds[] = {
    { "DCCALLOW", 0, {
        { mg_unreg,   0 }, { m_dccallow, 0 }, { m_dccallow, 0 },
        { m_dccallow, 0 }, { m_dccallow, 0 } }},
    { NULL }
};

DECLARE_MODULE("m_dcc", "2.0", "DCC allow list", 0, dcc_cmds, NULL);

static int
add_dccallow(aClient *sptr, aClient *optr)
{
    Link *lp;
    int cnt = 0;

    for(lp = sptr->user->dccallow; lp; lp = lp->next)
    {
        if(lp->flags != DCC_LINK_ME)
            continue;
        if((++cnt >= MAXDCCALLOW) && !IsAnOper(sptr))
        {
            sendto_one(sptr, err_str(ERR_TOOMANYDCC), me.name, sptr->name,
                       optr->name, MAXDCCALLOW);
            return 0;
        }
        else if(lp->value.cptr == optr)
            return 0;
    }

    lp = make_link();
    lp->value.cptr = optr;
    lp->flags = DCC_LINK_ME;
    lp->next = sptr->user->dccallow;
    sptr->user->dccallow = lp;

    lp = make_link();
    lp->value.cptr = sptr;
    lp->flags = DCC_LINK_REMOTE;
    lp->next = optr->user->dccallow;
    optr->user->dccallow = lp;

    sendto_one(sptr, rpl_str(RPL_DCCSTATUS), me.name, sptr->name, optr->name,
               "added to");
    return 0;
}

static int
m_dccallow(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    Link *lp;
    char *p, *s;
    char *cn;
    aClient *acptr, *lastcptr = NULL;
    int didlist = 0, didhelp = 0, didanything = 0;
    char **ptr;
    static char *dcc_help[] =
        {
            "/DCCALLOW [<+|->nick[,<+|->nick, ...]] [list] [help]",
            "You may allow DCCs of filetypes which are otherwise blocked by "
            "the IRC server",
            "by specifying a DCC allow for the user you want to recieve files "
            "from.",
            "For instance, to allow the user bob to send you file.exe, you "
            "would type:",
            "/dccallow +bob",
            "and bob would then be able to send you files. bob will have to "
            "resend the file",
            "if the server gave him an error message before you added him to "
            "your allow list.",
            "/dccallow -bob",
            "Will do the exact opposite, removing him from your dcc allow "
            "list.",
            "/dccallow list",
            "Will list the users currently on your dcc allow list.",
            NULL
        };

    if(!MyClient(sptr))
        return 0;

    if(parc < 2)
    {
        sendto_one(sptr, ":%s NOTICE %s :No command specified for DCCALLOW. "
                   "Type /dccallow help for more information.", me.name,
                   sptr->name);
        return 0;
    }

    for (p = NULL, s = strtoken(&p, parv[1], ", "); s;
         s = strtoken(&p, NULL, ", "))
    {
        if(*s == '+')
        {
            didanything++;
            cn = s + 1;
            if(*cn == '\0')
                continue;

            acptr = find_person(cn, NULL);

            if(acptr == sptr) continue;

            if(!acptr)
            {
                sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name,
                           sptr->name, cn);
                continue;
            }

            if(lastcptr == acptr)
                sendto_realops_lev(SPY_LEV, "User %s (%s@%s) may be flooding "
                                   "dccallow: add %s", sptr->name,
                                   sptr->user->username, sptr->user->host,
                                   acptr->name);
            lastcptr = acptr;
            add_dccallow(sptr, acptr);
        }
        else if(*s == '-')
        {
            didanything++;
            cn = s + 1;
            if(*cn == '\0')
                continue;

            acptr = find_person(cn, NULL);
            if(acptr == sptr)
                continue;

            if(!acptr)
            {
                sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name,
                           sptr->name, cn);
                continue;
            }

            if(lastcptr == acptr)
                sendto_realops_lev(SPY_LEV, "User %s (%s@%s) may be flooding "
                                   "dccallow: del %s", sptr->name,
                                   sptr->user->username, sptr->user->host,
                                   acptr->name);

            lastcptr = acptr;
            del_dccallow(sptr, acptr, 0);
        }
        else
        {
            if(!didlist && myncmp(s, "list", 4) == 0)
            {
                didanything++;
                didlist++;
                sendto_one(sptr, ":%s %d %s :The following users are on your "
                           "dcc allow list:", me.name, RPL_DCCINFO,
                           sptr->name);
                for(lp = sptr->user->dccallow; lp; lp = lp->next)
                {
                    if(lp->flags == DCC_LINK_REMOTE)
                        continue;
                    sendto_one(sptr, ":%s %d %s :%s (%s@%s)", me.name,
                               RPL_DCCLIST, sptr->name, lp->value.cptr->name,
                               lp->value.cptr->user->username,
#ifdef USER_HOSTMASKING
                               IsUmodeH(lp->value.cptr)?lp->value.cptr->user->mhost:
#endif
                               lp->value.cptr->user->host);
                }
                sendto_one(sptr, rpl_str(RPL_ENDOFDCCLIST), me.name,
                           sptr->name, s);
            }
            else if(!didhelp && myncmp(s, "help", 4) == 0)
            {
                didanything++;
                didhelp++;
                for(ptr = dcc_help; *ptr; ptr++)
                    sendto_one(sptr, ":%s %d %s :%s", me.name, RPL_DCCINFO,
                               sptr->name, *ptr);
                sendto_one(sptr, rpl_str(RPL_ENDOFDCCLIST), me.name,
                           sptr->name, s);
            }
        }
    }

    if(!didanything)
    {
        sendto_one(sptr, ":%s NOTICE %s :Invalid syntax for DCCALLOW. Type "
                   "/dccallow help for more information.", me.name,
                   sptr->name);
        return 0;
    }

    return 0;
}
