/* modules/core/m_privmsg.c
 *
 * PRIVMSG and NOTICE command handlers.
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
#include "channel.h"
#include "send.h"
#include "spamfilter.h"
#include "mapi.h"
#include "session.h"

/* Helpers defined in s_user.c not yet covered by public headers */
extern int  is_aliastab_recipient(char *recipient);
extern void send_msg_error(aClient *, char **, char *, int, aChannel *);
extern int  msg_has_utf8(char *);
extern int  check_for_ctcp(char *, char **);
extern int  check_for_flud(aClient *, aClient *, aChannel *, int);
extern int  check_target_limit(aClient *, aClient *);
extern int  is_silenced(aClient *, aClient *);
extern int  check_dccsend(aClient *, aClient *, char *);

/* check_for_ctcp return values (defined locally in s_user.c) */
#define CTCP_NONE    0
#define CTCP_YES     1
#define CTCP_DCC     2
#define CTCP_DCCSEND 3

/* Defined in channel.c, used by several modules */
extern int  is_xflags_exempted(aClient *, aChannel *);
extern int  verbose_to_relaychan(aClient *, aChannel *, char *, char *);

/* Defined in m_services.c */
extern int  svspanic;

static int m_private(struct MsgBuf *, aClient *, aClient *, int, char **);
static int m_notice(struct MsgBuf *, aClient *, aClient *, int, char **);

static const struct mapi_cmd_av2 privmsg_cmds[] = {
    { "PRIVMSG", 1, {              /* reset_idle=1 */
        { mg_unreg,   0 },         /* HANDLER_UNREG   */
        { m_private,  2 },         /* HANDLER_CLIENT  */
        { m_private,  2 },         /* HANDLER_REMOTE  */
        { m_private,  2 },         /* HANDLER_SERVER  */
        { m_private,  2 },         /* HANDLER_OPER    */
    }},
    { "NOTICE", 0, {
        { mg_unreg,  0 },          /* HANDLER_UNREG   */
        { m_notice,  2 },          /* HANDLER_CLIENT  */
        { m_notice,  2 },          /* HANDLER_REMOTE  */
        { m_notice,  2 },          /* HANDLER_SERVER  */
        { m_notice,  2 },          /* HANDLER_OPER    */
    }},
    { NULL }
};

DECLARE_CORE_MODULE("m_privmsg", "2.0", "PRIVMSG and NOTICE", privmsg_cmds, NULL);

/*
 * m_message (used in m_private() and m_notice()) the general
 * function to deliver MSG's between users/channels
 *
 * parv[0] = sender prefix
 * parv[1] = receiver list
 * parv[2] = message text
 *
 * massive cleanup * rev argv 6/91
 * again -Quension [Jul 2004]
 *
 */
static int
m_message(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr, int parc, char *parv[], int notice)
{
    aClient *acptr;
    aChannel *chptr;
    char *cmd;
    int ismine;
    int ret;
    char *s;
    char *p = NULL;
    char *target;
    char *dccmsg;
    int tleft = MAXRECIPIENTS;  /* targets left */
    char channel[CHANNELLEN + 1]; /* for the auditorium mode -Kobi. */

    cmd = notice ? MSG_NOTICE : MSG_PRIVATE;
    ismine = MyClient(sptr);

    /* Compute outbound IRCv3 tags once; shared for all targets of this message */
    const char *out_tags = build_outbound_tags();

    if (parc < 2 || *parv[1] == 0)
    {
        sendto_one(sptr, err_str(ERR_NORECIPIENT), me.name, parv[0], cmd);
        return -1;
    }

    if (parc < 3 || *parv[2] == 0)
    {
        sendto_one(sptr, err_str(ERR_NOTEXTTOSEND), me.name, parv[0]);
        return -1;
    }

    if (ismine)
    {
        /* if squelched or spamming, allow only messages to self or to the services and stats addresses */
        if ((IsSquelch(sptr)
#if defined(ANTI_SPAMBOT) && !defined(ANTI_SPAMBOT_WARN_ONLY)
            || (sptr->join_leave_count >= MAX_JOIN_LEAVE_COUNT)
#endif
            ) && mycmp(parv[0], parv[1]) && !is_aliastab_recipient(parv[1]))
        {
            if (IsWSquelch(sptr) && !notice)
                sendto_one(sptr, ":%s NOTICE %s :You are currently squelched."
                            "  Message not sent.", me.name, parv[0]);
            return 0;
        }

        if (call_hooks(CHOOK_MSG, sptr, notice, parv[2]) == FLUSH_BUFFER)
            return FLUSH_BUFFER;

        parv[1] = canonize(parv[1]);
    }

    /* loop on comma-separated targets, until tleft is gone */
    for (target = strtoken(&p, parv[1], ",");
         target && tleft--;
         target = strtoken(&p, NULL, ","))
    {
        int chflags = 0;    /* channel op/voice prefixes */

        /* additional penalty for lots of targets */
        if (ismine && tleft < (MAXRECIPIENTS/2) && !NoMsgThrottle(sptr))
#ifdef NO_OPER_FLOOD
            if (!IsAnOper(sptr))
#endif
                sptr->since += 4;

        /* [@][+]#channel preprocessing */
        s = target;
        while (1)
        {
            if (*s == '@')
                chflags |= CHFL_CHANOP;
#ifdef USE_HALFOPS
            else if (*s == '%')
                chflags |= CHFL_HALFOP;
#endif
            else if (*s == '+')
                chflags |= CHFL_VOICE;
            else
                break;
            s++;
        }

        /* target is a channel */
        if (IsChannelName(s))
        {
            if (!(chptr = find_channel(s, NULL)))
            {
                if (ismine && !notice)
                    sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name, parv[0],
                               target);
                continue;
            }

            if (ismine && call_hooks(CHOOK_CHANMSG, sptr, chptr, notice,
                                     parv[2]) == FLUSH_BUFFER)
                    return FLUSH_BUFFER;

#ifdef SPAMFILTER
            if(!(chptr->mode.mode & MODE_PRIVACY))
            {
                if(ismine && check_sf(sptr, parv[2], notice?"notice":"msg", SF_CMD_CHANNEL, chptr->chname))
                    return FLUSH_BUFFER;
            }
#endif

            /* servers and super sources get free sends */
            if (IsClient(sptr) && !IsULine(sptr))
            {
                if ((ret = can_send(sptr, chptr, parv[2])))
                {
                    if (ismine && !notice)
                        send_msg_error(sptr, parv, target, ret, chptr);
                    if(chptr->xflags & XFLAG_USER_VERBOSE)
                        verbose_to_relaychan(sptr, chptr, notice?"notice":"message", parv[2]);
                    if(chptr->xflags & XFLAG_OPER_VERBOSE)
                        verbose_to_opers(sptr, chptr, notice?"notice":"message", parv[2]);
                    continue;
                }

                if (notice && (chptr->xflags & XFLAG_NO_NOTICE) && !is_xflags_exempted(sptr,chptr))
                {
                    if(chptr->xflags & XFLAG_USER_VERBOSE)
                        verbose_to_relaychan(sptr, chptr, "notice", parv[2]);
                    if(chptr->xflags & XFLAG_OPER_VERBOSE)
                        verbose_to_opers(sptr, chptr, "notice", parv[2]);
                    continue;
                }

                if ((chptr->xflags & XFLAG_NO_UTF8) && msg_has_utf8(parv[2]) && !is_xflags_exempted(sptr,chptr))
                {
                    if (ismine && !notice)
                        sendto_one(sptr, err_str(ERR_CANNOTSENDTOCHAN), me.name, parv[0], target);
                    if(chptr->xflags & XFLAG_USER_VERBOSE)
                        verbose_to_relaychan(sptr, chptr, notice?"utf8-notice":"utf8-message", parv[2]);
                    if(chptr->xflags & XFLAG_OPER_VERBOSE)
                        verbose_to_opers(sptr, chptr, notice?"utf8-notice":"utf8-message", parv[2]);
                    continue;
                }

                if((chptr->mode.mode & MODE_AUDITORIUM) && !is_chan_opvoice(sptr, chptr))
                {
                    /* Channel is in auditorium mode! */
                    if(strlen(chptr->chname)+6 > CHANNELLEN) continue; /* Channel is too long.. we must be able to add
                                                                           -relay to it... */
                    strcpy(channel, chptr->chname);
                    strcat(channel, "-relay");
                    if(!(chptr = find_channel(channel, NULL))) continue; /* Can't find the relay channel... */
                    /* I originally thought it's a good idea to enforce #chan-relay modes but then I figured out we
                       would most likely want to have it +snt and only accept messages from #chan members... -Kobi.
                    if ((ret = can_send(sptr, chptr, parv[2])))
                    {
                        if (ismine && !notice)
                            send_msg_error(sptr, parv, target, ret, chptr);
                        continue;
                    }
                    */
                    s = target = chptr->chname; /* We want ops to see the message coming to #chan-relay and not to #chan */
                }

                if (!notice)
                {
                    switch (check_for_ctcp(parv[2], NULL))
                    {
                        case CTCP_NONE:
                            break;

                        case CTCP_DCCSEND:
                        case CTCP_DCC:
                            if (ismine)
                                sendto_one(sptr, ":%s NOTICE %s :You may not"
                                           " send a DCC command to a channel"
                                           " (%s)", me.name, parv[0], target);
                            continue;
#ifdef FLUD
                        default:
                            if (check_for_flud(sptr, NULL, chptr, 1))
                                return 0;
#endif
                            if ((chptr->xflags & XFLAG_NO_CTCP) && !is_xflags_exempted(sptr,chptr))
                            {
                                if(chptr->xflags & XFLAG_USER_VERBOSE)
                                    verbose_to_relaychan(cptr, chptr, "ctcp", "xflag_no_ctcp");
                                if(chptr->xflags & XFLAG_OPER_VERBOSE)
                                    verbose_to_opers(cptr, chptr, "ctcp", "xflag_no_ctcp");
                                continue;
                            }
                    }
                }
            }

            if (chflags)
            {
                /* don't let clients do stuff like @+@@+++@+@@@#channel */
                if (chflags & CHFL_VOICE)
                    *--s = '+';
#ifdef USE_HALFOPS
                if (chflags & CHFL_HALFOP)
                    *--s = '%';
#endif
                if (chflags & CHFL_CHANOP)
                    *--s = '@';

                sendto_channelflags_butone(cptr, sptr, chptr, chflags,
                                           ":%s %s %s :%s", parv[0], cmd, s,
                                           parv[2]);
            }
            else
                sendto_channel_butone_tags(cptr, sptr, chptr, out_tags,
                                           ":%s %s %s :%s",
                                           parv[0], cmd, target, parv[2]);

            /* next target */
            continue;
        }

        /* prefixes are only valid for channel targets */
        if (s != target)
        {
            if (!notice)
                sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name, parv[0],
                       target);
            continue;
        }

        /* target is a $servermask */
        if (*target == '$')
        {
            s++;

            /* allow $$servermask */
            if (*s == '$')
                s++;

            if (ismine)
            {
                /* need appropriate privs */
                if (!OPCanLNotice(sptr) ||
                    (mycmp(me.name, s) && !OPCanGNotice(sptr)))
                {
                    sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name,
                               parv[0], target);
                    continue;
                }
            }

            sendto_all_servmask(sptr, s, ":%s %s %s :%s", parv[0], cmd,
                                target, parv[2]);

            /* next target */
            continue;
        }

        /* target is a nick@server */
        if ((s = strchr(target, '@')))
            *s = 0;

        /* target is a client */
        if ((acptr = find_client(target, NULL)))
        {
            if (s)
                *s++ = '@';

            if (ismine && IsMe(acptr))
            {
                if (call_hooks(CHOOK_MYMSG, sptr, notice, parv[2])
                    == FLUSH_BUFFER)
                    return FLUSH_BUFFER;

                continue;
            }

            if (!IsClient(acptr))
                acptr = NULL;
        }

        /* nonexistent client or wrong @server */
        if (!acptr || (s && mycmp(acptr->user->server, s)))
        {
            /* Phase S4: if the nick belongs to a session, queue the message
             * instead of returning ERR_NOSUCHNICK (local sessions only). */
            if (!s && !notice && ismine)
            {
                Session *sess = session_find_by_nick(target);
                if (sess && sess->is_local)
                {
                    session_queue_msg(sess, parv[0], parv[2], notice);
                    continue;   /* silently queued */
                }
            }
            if (!notice)
                sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name, parv[0],
                           target);
            continue;
        }

        /* super targets get special treatment */
        if (IsULine(acptr))
        {
            AliasInfo *ai;

            if (notice && (confopts & FLAGS_SERVHUB) && (acptr->uplink->serv->uflags & ULF_NONOTICE))
                continue;

            if (ismine && !notice && (ai = acptr->user->alias))
            {
#ifdef DENY_SERVICES_MSGS
                if (!s && !mycmp(ai->server, Services_Name))
                {
                    sendto_one(sptr, err_str(ERR_MSGSERVICES), me.name,
                               parv[0], ai->nick, ai->nick, ai->server,
                               ai->nick);
                    continue;
                }
#endif
#ifdef PASS_SERVICES_MSGS
                if (s)  /* if passing, skip this and use generic send below */
#endif
                {
                    sendto_alias(ai, sptr, "%s", parv[2]);
                    continue;
                }
            }

            if((svspanic>1 || (svspanic>0 && !IsARegNick(sptr))) && !IsOper(sptr))
            {
                if(MyClient(sptr))
                    sendto_one(sptr, err_str(ERR_SERVICESDOWN), me.name, parv[0],
                               acptr->name);
                continue;
            }

            /* no flood/dcc/whatever checks, just send */
            sendto_one(acptr, ":%s %s %s :%s", parv[0], cmd, target,
                       parv[2]);
            continue;
        }
#ifdef SUPER_TARGETS_ONLY
        else if (s && ismine)
        {
            if (!notice)
                sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name, parv[0],
                       target);
            continue;
        }
#endif

        if (ismine)
        {
            if (call_hooks(CHOOK_USERMSG, sptr, acptr, notice, parv[2])
                == FLUSH_BUFFER)
                return FLUSH_BUFFER;

#ifdef MSG_TARGET_LIMIT
            if (check_target_limit(sptr, acptr))
                continue;
#endif

#ifdef SPAMFILTER
            if(!IsUmodeP(acptr) && sptr!=acptr && check_sf(sptr, parv[2], notice?"notice":"msg", notice?SF_CMD_NOTICE:SF_CMD_PRIVMSG, acptr->name))
                return FLUSH_BUFFER;
#endif
        }

        /* servers and super sources skip flood/silence checks */
        if (IsClient(sptr) && !IsULine(sptr))
        {
            if (IsNoNonReg(acptr) && !IsRegNick(sptr) && !IsOper(sptr))
            {
                if (ismine && !notice)
                    sendto_one(sptr, err_str(ERR_NONONREG), me.name, parv[0],
                           target);
                continue;
            }
            if (IsUmodeC(acptr) && !IsOper(sptr) && (!IsNoNonReg(acptr) || IsRegNick(sptr)) && acptr->user->joined && !find_shared_chan(sptr, acptr))
            {
                if (ismine && !notice)
                    sendto_one(sptr, err_str(ERR_NOSHAREDCHAN), me.name, parv[0],
                           target);
                continue;
            }
            if (ismine && IsNoNonReg(sptr) && !IsRegNick(acptr) && !IsOper(acptr))
            {
                if (!notice)
                    sendto_one(sptr, err_str(ERR_OWNMODE), me.name, parv[0],
                           acptr->name, "+R");
                continue;
            }
            if (ismine && IsUmodeC(sptr) && !IsOper(sptr) && (!IsNoNonReg(sptr) || IsRegNick(acptr)) && sptr->user->joined && !find_shared_chan(sptr, acptr))
            {
                if (!notice)
                    sendto_one(sptr, err_str(ERR_OWNMODE), me.name, parv[0],
                           acptr->name, "+C");
                continue;
            }

#ifdef FLUD
            if (!notice && MyFludConnect(acptr))
#else
            if (!notice && MyConnect(acptr))
#endif
            {
                switch (check_for_ctcp(parv[2], &dccmsg))
                {
                    case CTCP_NONE:
                        break;

                    case CTCP_DCCSEND:
#ifdef FLUD
                        if (check_for_flud(sptr, acptr, NULL, 1))
                            return 0;
#endif
                        if (check_dccsend(sptr, acptr, dccmsg))
                            continue;
                        break;

#ifdef FLUD
                    default:
                        if (check_for_flud(sptr, acptr, NULL, 1))
                            return 0;
#endif
                }
            }

            if (is_silenced(sptr, acptr))
                continue;
        }

        if (!notice && ismine && acptr->user->away)
            sendto_one(sptr, rpl_str(RPL_AWAY), me.name, parv[0], acptr->name,
                       acptr->user->away);

        if (MyConnect(acptr) && (acptr->cap_bits & tag_delivery_caps))
            sendto_one_tags(acptr, out_tags, ":%s %s %s :%s",
                            parv[0], cmd, target, parv[2]);
        else
            sendto_prefix_one(acptr, sptr, ":%s %s %s :%s", parv[0], cmd, target,
                              parv[2]);

        /* next target */
        continue;
    }

    /* too many targets */
    if (target)
    {
        if (!notice)
            sendto_one(sptr, err_str(ERR_TOOMANYTARGETS), me.name, parv[0],
                   target);

        if (sptr->user)
            sendto_realops_lev(SPY_LEV, "User %s (%s@%s) tried to %s more than"
                               " %d targets", sptr->name, sptr->user->username,
                               sptr->user->host, notice ? "notice" : "msg",
                               MAXRECIPIENTS);
    }

    return 0;
}

/*
 * m_private
 * parv[0] = sender prefix
 * parv[1] = receiver list
 * parv[2] = message text
 */
static int
m_private(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    return m_message(msgbuf, cptr, sptr, parc, parv, 0);
}

/*
 * m_notice
 * parv[0] = sender prefix
 * parv[1] = receiver list
 * parv[2] = notice text
 */
static int
m_notice(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    return m_message(msgbuf, cptr, sptr, parc, parv, 1);
}
