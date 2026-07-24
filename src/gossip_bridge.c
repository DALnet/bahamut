/*
 * IRC - Internet Relay Chat, src/gossip_bridge.c
 * Copyright (C) 2024 Bahamut IRC Server Project
 *
 * Phase S3: Legacy Bridge — translate gossip NetworkEvents to TS5 wire
 * commands for legacy servers, and synthesise gossip state during bursts.
 *
 * Outbound translation (gossip → legacy):
 *
 *   EVT_SERVER_LINK  → :<me> SERVER <name> 2 :Gossip peer
 *   EVT_SERVER_SPLIT → :<me> SQUIT <name> :Gossip peer disconnected
 *   EVT_USER_JOIN    → NICK <nick> 2 <ts> + <user> <host> <server> 0 0.0.0.0 :<real>
 *   EVT_USER_QUIT    → :<nick> QUIT :<reason>
 *   EVT_USER_NICK    → :<oldnick> NICK <newnick> <ts>
 *   EVT_USER_AWAY    → :<nick> AWAY [:<msg>]
 *   EVT_CHAN_JOIN     → :<me> SJOIN <ts> <channel> + :[@+]<nick>
 *   EVT_CHAN_PART     → :<nick> PART <channel> :<reason>
 *   EVT_CHAN_KICK     → :<kicker> KICK <channel> <target> :<reason>
 *   EVT_CHAN_MODE     → :<nick> MODE <channel> <modes> [<params>]
 *   EVT_CHAN_TOPIC    → :<nick> TOPIC <channel> <setter> <ts> :<topic>
 *
 * Gossip users are introduced with hop=2, serviceid=0, ip="0.0.0.0".
 * We always use the string IP format (NICKIPSTR) since all modern Bahamut
 * enables it by default.
 */

#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <time.h>

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "send.h"
#include "gossip_event.h"
#include "eventlog.h"
#include "gossip_peer.h"
#include "gossip_bridge.h"

/* -------------------------------------------------------------------------
 * Direct peer introduction / split
 * Called for directly-connected gossip peers (ms_ghello / gopeer_handle_disconnect).
 * Events from OTHER gossip peers are handled by bridge_apply_event().
 * ---------------------------------------------------------------------- */

/*
 * sanitize_param — defence-in-depth for the TS5 trust boundary.
 *
 * Truncate a string at the first space or control byte (incl. CR/LF) so it
 * is safe to emit as a single positional TS5 parameter.  Gossip payload
 * identifier fields are already space-free (gossip parse tokenises on ' ')
 * and CR/LF-free (events arrive as IRC lines, so framing strips line
 * terminators), so injection via this path is not currently possible.  But
 * the bridge is the boundary to legacy TS5 servers, and relying on a distant
 * parse invariant for safety at the wire-emit point is fragile: a future EVT
 * type or parse change could slip a space/control char into a positional
 * field, which a TS5 server would read as extra parameters (or, for CR/LF, a
 * second command).  Only positional slots are sanitised; trailing ":%s"
 * params (realname, reason, topic) and space-separated MODE params
 * legitimately contain spaces and are left intact.
 */
static void
sanitize_param(char *s)
{
    for (; *s; s++)
        if ((unsigned char)*s <= ' ')
        {
            *s = '\0';
            break;
        }
}

void
bridge_introduce_server(const char *name)
{
    char safe[HOSTLEN + 1];
    strncpyzt(safe, name, sizeof(safe));
    sanitize_param(safe);
    sendto_serv_butone(NULL, ":%s SERVER %s 2 :Gossip peer",
                       me.name, safe);
}

void
bridge_split_server(const char *name)
{
    char safe[HOSTLEN + 1];
    strncpyzt(safe, name, sizeof(safe));
    sanitize_param(safe);
    sendto_serv_butone(NULL, ":%s SQUIT %s :Gossip peer disconnected",
                       me.name, safe);
}

/* -------------------------------------------------------------------------
 * Ongoing event bridging
 * Called from ms_gevent() for each inbound GEVENT after dedup+apply.
 * ---------------------------------------------------------------------- */

void
bridge_apply_event(const NetworkEvent *ev)
{
    switch (ev->type)
    {
        case EVT_SERVER_LINK:
        {
            const EvPayloadServerLink *p = &ev->payload.server_link;
            bridge_introduce_server(p->name);
            break;
        }
        case EVT_SERVER_SPLIT:
        {
            const EvPayloadServerLink *p = &ev->payload.server_link;
            bridge_split_server(p->name);
            break;
        }
        case EVT_USER_JOIN:
        {
            /* Introduce gossip user to legacy servers.
             * hopcount=2, serviceid=0, ip="0.0.0.0" (NICKIPSTR string format).
             * umode sent as "+" — legacy servers will learn actual modes
             * when EVT_USER_MODE events arrive as MODE commands. */
            EvPayloadUserJoin p = ev->payload.user_join;  /* mutable copy */
            sanitize_param(p.nick);
            sanitize_param(p.username);
            sanitize_param(p.host);
            sanitize_param(p.server);
            sendto_serv_butone(NULL,
                "NICK %s 2 %ld + %s %s %s 0 0.0.0.0 :%s",
                p.nick, (long)p.ts,
                p.username, p.host, p.server,
                p.realname);
            break;
        }
        case EVT_USER_QUIT:
        {
            EvPayloadUserQuit p = ev->payload.user_quit;  /* mutable copy */
            sanitize_param(p.nick);
            sendto_serv_butone(NULL, ":%s QUIT :%s", p.nick, p.reason);
            break;
        }
        case EVT_USER_NICK:
        {
            EvPayloadUserNick p = ev->payload.user_nick;  /* mutable copy */
            sanitize_param(p.oldnick);
            sanitize_param(p.newnick);
            sendto_serv_butone(NULL, ":%s NICK %s %ld",
                               p.oldnick, p.newnick, (long)p.ts);
            break;
        }
        case EVT_USER_AWAY:
        {
            EvPayloadUserAway p = ev->payload.user_away;  /* mutable copy */
            sanitize_param(p.nick);
            if (p.setting)
                sendto_serv_butone(NULL, ":%s AWAY :%s",
                                   p.nick, p.message);
            else
                sendto_serv_butone(NULL, ":%s AWAY", p.nick);
            break;
        }
        case EVT_CHAN_JOIN:
        {
            EvPayloadChanJoin p = ev->payload.chan_join;  /* mutable copy */
            char prefix[3] = {'\0', '\0', '\0'};
            sanitize_param(p.channel);
            sanitize_param(p.nick);  /* member token in the SJOIN list */
            if (p.flags & CHFL_CHANOP)
                prefix[0] = '@';
            else if (p.flags & CHFL_HALFOP)
                prefix[0] = '%';
            else if (p.flags & CHFL_VOICE)
                prefix[0] = '+';
            sendto_serv_butone(NULL,
                ":%s SJOIN %ld %s + :%s%s",
                me.name, (long)p.ts, p.channel, prefix, p.nick);
            break;
        }
        case EVT_CHAN_PART:
        {
            EvPayloadChanPart p = ev->payload.chan_part;  /* mutable copy */
            sanitize_param(p.nick);
            sanitize_param(p.channel);
            sendto_serv_butone(NULL, ":%s PART %s :%s",
                               p.nick, p.channel, p.reason);
            break;
        }
        case EVT_CHAN_KICK:
        {
            EvPayloadChanKick p = ev->payload.chan_kick;  /* mutable copy */
            sanitize_param(p.kicker);
            sanitize_param(p.channel);
            sanitize_param(p.target);
            sendto_serv_butone(NULL, ":%s KICK %s %s :%s",
                               p.kicker, p.channel,
                               p.target, p.reason);
            break;
        }
        case EVT_CHAN_MODE:
        {
            EvPayloadChanMode p = ev->payload.chan_mode;  /* mutable copy */
            sanitize_param(p.nick);
            sanitize_param(p.channel);
            /* modebuf is mode letters; parabuf is space-separated MODE
             * params (legitimately contains spaces) — left intact. */
            if (p.parabuf[0])
                sendto_serv_butone(NULL, ":%s MODE %s %s %s",
                                   p.nick, p.channel,
                                   p.modebuf, p.parabuf);
            else
                sendto_serv_butone(NULL, ":%s MODE %s %s",
                                   p.nick, p.channel, p.modebuf);
            break;
        }
        case EVT_CHAN_TOPIC:
        {
            EvPayloadChanTopic p = ev->payload.chan_topic;  /* mutable copy */
            sanitize_param(p.nick);
            sanitize_param(p.channel);
            sanitize_param(p.setter);
            sendto_serv_butone(NULL,
                ":%s TOPIC %s %s %ld :%s",
                p.nick, p.channel, p.setter,
                (long)p.ts, p.topic);
            break;
        }
        case EVT_AKILL:
        {
            EvPayloadAkill p = ev->payload.akill;  /* mutable copy */
            sanitize_param(p.host);
            sanitize_param(p.user);
            sanitize_param(p.setter);
            sendto_serv_butone(NULL, ":%s AKILL %s %s %ld %s %ld :%s",
                               me.name, p.host, p.user, (long)p.length,
                               p.setter, (long)p.timeset, p.reason);
            break;
        }
        case EVT_RAKILL:
        {
            EvPayloadRakill p = ev->payload.rakill;  /* mutable copy */
            sanitize_param(p.host);
            sanitize_param(p.user);
            sendto_serv_butone(NULL, ":%s RAKILL %s %s",
                               me.name, p.host, p.user);
            break;
        }
        case EVT_SQLINE:
        {
            EvPayloadSqline p = ev->payload.sqline;  /* mutable copy */
            sanitize_param(p.mask);
            sendto_serv_butone(NULL, ":%s SQLINE %s :%s",
                               me.name, p.mask, p.reason);
            break;
        }
        case EVT_UNSQLINE:
        {
            const EvPayloadUnsqline *p = &ev->payload.unsqline;
            sendto_serv_butone(NULL, ":%s UNSQLINE :%s",
                               me.name, p->mask);
            break;
        }
        case EVT_SGLINE:
        {
            const EvPayloadSgline *p = &ev->payload.sgline;
            sendto_serv_butone(NULL, ":%s SGLINE %d :%s:%s",
                               me.name, p->bodylen, p->mask, p->reason);
            break;
        }
        case EVT_UNSGLINE:
        {
            const EvPayloadUnsgline *p = &ev->payload.unsgline;
            sendto_serv_butone(NULL, ":%s UNSGLINE :%s",
                               me.name, p->mask);
            break;
        }
        default:
            break;
    }
}

/* -------------------------------------------------------------------------
 * Burst: send current gossip state to a newly connected legacy server.
 *
 * Walks live materialized state (aClient/aChannel lists) to send gossip
 * users and channels to the TS5 peer.  This is reliable regardless of
 * event log ring buffer wrapping.
 * ---------------------------------------------------------------------- */

void
bridge_burst_gossip_to_server(aClient *cptr)
{
    aClient  *acptr;
    aChannel *chptr;
    Link     *lp;

    /*
     * Walk live materialized state instead of replaying the event log.
     * This is reliable regardless of ring buffer wrapping.
     *
     * Order: SERVER introductions → NICK → SJOIN → TOPIC
     */

    /* 1. Introduce all gossip-materialized servers */
    for (acptr = client; acptr; acptr = acptr->next)
    {
        if (!IsServer(acptr) || !IsGossipMaterialized(acptr))
            continue;
        sendto_one(cptr, ":%s SERVER %s 2 :Gossip peer",
                   me.name, acptr->name);
    }

    /* 2. Introduce all gossip-materialized users */
    for (acptr = client; acptr; acptr = acptr->next)
    {
        if (!IsClient(acptr) || !IsGossipMaterialized(acptr) || !acptr->user)
            continue;
        sendto_one(cptr,
            "NICK %s 2 %ld + %s %s %s 0 0.0.0.0 :%s",
            acptr->name, (long)acptr->tsinfo,
            acptr->user->username, acptr->user->host,
            acptr->user->server ? acptr->user->server : me.name,
            acptr->info ? acptr->info : "");
    }

    /* 3. Send channel memberships for gossip-materialized users */
    for (acptr = client; acptr; acptr = acptr->next)
    {
        if (!IsClient(acptr) || !IsGossipMaterialized(acptr) || !acptr->user)
            continue;

        for (lp = acptr->user->channel; lp; lp = lp->next)
        {
            chanMember *cm;
            char prefix[2] = {'\0', '\0'};

            chptr = lp->value.chptr;
            if (!chptr)
                continue;

            /* Find this user's flags in the channel */
            for (cm = chptr->members; cm; cm = cm->next)
                if (cm->cptr == acptr)
                {
                    if (cm->flags & CHFL_CHANOP)       prefix[0] = '@';
                    else if (cm->flags & CHFL_HALFOP) prefix[0] = '%';
                    else if (cm->flags & CHFL_VOICE)  prefix[0] = '+';
                    break;
                }

            sendto_one(cptr,
                ":%s SJOIN %ld %s + :%s%s",
                me.name, (long)chptr->channelts,
                chptr->chname, prefix, acptr->name);
        }
    }

    /* 4. Send channel modes and bans for channels with gossip members */
    for (chptr = channel; chptr; chptr = chptr->nextch)
    {
        chanMember *cm;
        aBan *ban;
        int has_gossip = 0;
        char mbuf[64], pbuf[256];
        char *mp = mbuf, *pp = pbuf;

        for (cm = chptr->members; cm; cm = cm->next)
            if (IsGossipMaterialized(cm->cptr))
            { has_gossip = 1; break; }

        if (!has_gossip)
            continue;

        /* Send channel modes */
        *pp = '\0';
        *mp++ = '+';
        if (chptr->mode.mode & MODE_SECRET)      *mp++ = 's';
        if (chptr->mode.mode & MODE_PRIVATE)     *mp++ = 'p';
        if (chptr->mode.mode & MODE_MODERATED)   *mp++ = 'm';
        if (chptr->mode.mode & MODE_TOPICLIMIT)  *mp++ = 't';
        if (chptr->mode.mode & MODE_INVITEONLY)   *mp++ = 'i';
        if (chptr->mode.mode & MODE_NOPRIVMSGS)  *mp++ = 'n';
        if (chptr->mode.mode & MODE_REGONLY)     *mp++ = 'R';
        if (chptr->mode.mode & MODE_NOCTRL)      *mp++ = 'c';
        if (chptr->mode.mode & MODE_SSLONLY)     *mp++ = 'S';
        if (chptr->mode.limit)
        {
            *mp++ = 'l';
            ircsprintf(pp, "%d", chptr->mode.limit);
            pp += strlen(pp);
        }
        if (*chptr->mode.key)
        {
            *mp++ = 'k';
            if (pp != pbuf) *pp++ = ' ';
            strncpy(pp, chptr->mode.key, sizeof(pbuf) - (pp - pbuf) - 1);
            pp += strlen(pp);
        }
        *mp = '\0';

        if (mbuf[1])  /* modes beyond bare '+' */
        {
            if (pbuf[0])
                sendto_one(cptr, ":%s MODE %s %ld %s %s",
                           me.name, chptr->chname,
                           (long)chptr->channelts, mbuf, pbuf);
            else
                sendto_one(cptr, ":%s MODE %s %ld %s",
                           me.name, chptr->chname,
                           (long)chptr->channelts, mbuf);
        }

        /* Send ban list */
        for (ban = chptr->banlist; ban; ban = ban->next)
        {
            sendto_one(cptr, ":%s MODE %s %ld +b %s",
                       me.name, chptr->chname,
                       (long)chptr->channelts, ban->banstr);
        }
    }

    /* 5. Send topics for channels that have gossip-materialized members */
    for (chptr = channel; chptr; chptr = chptr->nextch)
    {
        chanMember *cm;
        int has_gossip = 0;

        if (!chptr->topic[0])
            continue;

        for (cm = chptr->members; cm; cm = cm->next)
            if (IsGossipMaterialized(cm->cptr))
            { has_gossip = 1; break; }

        if (has_gossip)
            sendto_one(cptr, ":%s TOPIC %s %s %lu :%s",
                       me.name, chptr->chname, chptr->topic_nick,
                       (unsigned long)chptr->topic_time, chptr->topic);
    }
}
