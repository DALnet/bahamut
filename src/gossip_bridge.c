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

void
bridge_introduce_server(const char *name)
{
    sendto_serv_butone(NULL, ":%s SERVER %s 2 :Gossip peer",
                       me.name, name);
}

void
bridge_split_server(const char *name)
{
    sendto_serv_butone(NULL, ":%s SQUIT %s :Gossip peer disconnected",
                       me.name, name);
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
            const EvPayloadUserJoin *p = &ev->payload.user_join;
            sendto_serv_butone(NULL,
                "NICK %s 2 %ld + %s %s %s 0 0.0.0.0 :%s",
                p->nick, (long)p->ts,
                p->username, p->host, p->server,
                p->realname);
            break;
        }
        case EVT_USER_QUIT:
        {
            const EvPayloadUserQuit *p = &ev->payload.user_quit;
            sendto_serv_butone(NULL, ":%s QUIT :%s", p->nick, p->reason);
            break;
        }
        case EVT_USER_NICK:
        {
            const EvPayloadUserNick *p = &ev->payload.user_nick;
            sendto_serv_butone(NULL, ":%s NICK %s %ld",
                               p->oldnick, p->newnick, (long)p->ts);
            break;
        }
        case EVT_USER_AWAY:
        {
            const EvPayloadUserAway *p = &ev->payload.user_away;
            if (p->setting)
                sendto_serv_butone(NULL, ":%s AWAY :%s",
                                   p->nick, p->message);
            else
                sendto_serv_butone(NULL, ":%s AWAY", p->nick);
            break;
        }
        case EVT_CHAN_JOIN:
        {
            const EvPayloadChanJoin *p = &ev->payload.chan_join;
            char prefix[3] = {'\0', '\0', '\0'};
            if (p->flags & CHFL_CHANOP)
                prefix[0] = '@';
            else if (p->flags & CHFL_VOICE)
                prefix[0] = '+';
            sendto_serv_butone(NULL,
                ":%s SJOIN %ld %s + :%s%s",
                me.name, (long)p->ts, p->channel, prefix, p->nick);
            break;
        }
        case EVT_CHAN_PART:
        {
            const EvPayloadChanPart *p = &ev->payload.chan_part;
            sendto_serv_butone(NULL, ":%s PART %s :%s",
                               p->nick, p->channel, p->reason);
            break;
        }
        case EVT_CHAN_KICK:
        {
            const EvPayloadChanKick *p = &ev->payload.chan_kick;
            sendto_serv_butone(NULL, ":%s KICK %s %s :%s",
                               p->kicker, p->channel,
                               p->target, p->reason);
            break;
        }
        case EVT_CHAN_MODE:
        {
            const EvPayloadChanMode *p = &ev->payload.chan_mode;
            if (p->parabuf[0])
                sendto_serv_butone(NULL, ":%s MODE %s %s %s",
                                   p->nick, p->channel,
                                   p->modebuf, p->parabuf);
            else
                sendto_serv_butone(NULL, ":%s MODE %s %s",
                                   p->nick, p->channel, p->modebuf);
            break;
        }
        case EVT_CHAN_TOPIC:
        {
            const EvPayloadChanTopic *p = &ev->payload.chan_topic;
            sendto_serv_butone(NULL,
                ":%s TOPIC %s %s %ld :%s",
                p->nick, p->channel, p->setter,
                (long)p->ts, p->topic);
            break;
        }
        default:
            break;
    }
}

/* -------------------------------------------------------------------------
 * Burst: send current gossip state to a newly connected legacy server.
 *
 * Walks the event log once to reconstruct current state (which gossip
 * servers are up, which gossip users are online, what channels they're in).
 * Skips events from our own server (me.name) — the normal burst already
 * sent those users and channels to the new server.
 *
 * State tables are stack-allocated with fixed upper limits suited for the
 * target network size of 10–50 servers.
 * ---------------------------------------------------------------------- */

/* Maximum items tracked during a bridge burst */
#define BURST_MAX_SERVERS  64
#define BURST_MAX_USERS    512
#define BURST_MAX_MEMBERS  2048

typedef struct {
    char name[HOSTLEN + 1];
    int  split;
} BurstServer;

typedef struct {
    char   nick[NICKLEN + 1];
    char   username[USERLEN + 1];
    char   host[HOSTLEN + 1];
    char   realname[REALLEN + 1];
    char   server[HOSTLEN + 1];
    time_t ts;
    int    quit;
} BurstUser;

typedef struct {
    char   nick[NICKLEN + 1];
    char   channel[CHANNELLEN + 1];
    time_t ts;
    int    flags;
    int    parted;
} BurstMember;

static int
find_burst_server(BurstServer *servers, int n, const char *name)
{
    int i;
    for (i = 0; i < n; i++)
        if (strncmp(servers[i].name, name, HOSTLEN) == 0)
            return i;
    return -1;
}

static int
find_burst_user(BurstUser *users, int n, const char *nick)
{
    int i;
    for (i = 0; i < n; i++)
        if (strncmp(users[i].nick, nick, NICKLEN) == 0)
            return i;
    return -1;
}

static int
find_burst_member(BurstMember *members, int n, const char *nick, const char *chan)
{
    int i;
    for (i = 0; i < n; i++)
        if (strncmp(members[i].nick, nick, NICKLEN) == 0 &&
            strncmp(members[i].channel, chan, CHANNELLEN) == 0)
            return i;
    return -1;
}

void
bridge_burst_gossip_to_server(aClient *cptr)
{
    /*
     * These static arrays are safe because Bahamut is single-threaded
     * and server bursts are serialised.  We memset them at the start of
     * each call so state does not bleed between invocations.
     */
    static BurstServer servers[BURST_MAX_SERVERS];
    static BurstUser   users[BURST_MAX_USERS];
    static BurstMember members[BURST_MAX_MEMBERS];
    int ns = 0, nu = 0, nm = 0;
    int i, idx;
    EventClock    zero;
    NetworkEvent *buf[EVENT_LOG_SIZE];
    int           n;

    memset(servers, 0, sizeof(servers));
    memset(users,   0, sizeof(users));
    memset(members, 0, sizeof(members));
    memset(&zero,   0, sizeof(zero));

    /* Fetch all events from the log */
    n = get_events_since(&zero, buf, EVENT_LOG_SIZE);

    /* ---------------------------------------------------------------
     * Pass 1: build current-state tables from the event log.
     * ------------------------------------------------------------- */
    for (i = 0; i < n; i++)
    {
        const NetworkEvent *ev = buf[i];

        switch (ev->type)
        {
            case EVT_SERVER_LINK:
            {
                const EvPayloadServerLink *p = &ev->payload.server_link;
                /* Skip self — we're already the introducing server */
                if (strncmp(p->name, me.name, HOSTLEN) == 0)
                    break;
                idx = find_burst_server(servers, ns, p->name);
                if (idx < 0 && ns < BURST_MAX_SERVERS)
                {
                    strncpy(servers[ns].name, p->name, HOSTLEN);
                    servers[ns].split = 0;
                    ns++;
                }
                else if (idx >= 0)
                {
                    servers[idx].split = 0; /* re-linked */
                }
                break;
            }
            case EVT_SERVER_SPLIT:
            {
                const EvPayloadServerLink *p = &ev->payload.server_link;
                idx = find_burst_server(servers, ns, p->name);
                if (idx >= 0)
                    servers[idx].split = 1;
                break;
            }
            case EVT_USER_JOIN:
            {
                const EvPayloadUserJoin *p = &ev->payload.user_join;
                /* Skip local users — normal burst already sent them */
                if (strncmp(p->server, me.name, HOSTLEN) == 0)
                    break;
                idx = find_burst_user(users, nu, p->nick);
                if (idx < 0 && nu < BURST_MAX_USERS)
                    idx = nu++;
                if (idx >= 0 && idx < BURST_MAX_USERS)
                {
                    strncpy(users[idx].nick,     p->nick,     NICKLEN);
                    strncpy(users[idx].username, p->username, USERLEN);
                    strncpy(users[idx].host,     p->host,     HOSTLEN);
                    strncpy(users[idx].realname, p->realname, REALLEN);
                    strncpy(users[idx].server,   p->server,   HOSTLEN);
                    users[idx].ts   = p->ts;
                    users[idx].quit = 0;
                }
                break;
            }
            case EVT_USER_QUIT:
            {
                const EvPayloadUserQuit *p = &ev->payload.user_quit;
                idx = find_burst_user(users, nu, p->nick);
                if (idx >= 0)
                    users[idx].quit = 1;
                break;
            }
            case EVT_USER_NICK:
            {
                const EvPayloadUserNick *p = &ev->payload.user_nick;
                idx = find_burst_user(users, nu, p->oldnick);
                if (idx >= 0)
                {
                    int j;
                    /* Update nick in membership table too */
                    for (j = 0; j < nm; j++)
                        if (strncmp(members[j].nick, p->oldnick, NICKLEN) == 0)
                            strncpy(members[j].nick, p->newnick, NICKLEN);
                    strncpy(users[idx].nick, p->newnick, NICKLEN);
                }
                break;
            }
            case EVT_CHAN_JOIN:
            {
                const EvPayloadChanJoin *p = &ev->payload.chan_join;
                /* Only track memberships for known gossip users */
                if (find_burst_user(users, nu, p->nick) < 0)
                    break;
                idx = find_burst_member(members, nm, p->nick, p->channel);
                if (idx < 0 && nm < BURST_MAX_MEMBERS)
                    idx = nm++;
                if (idx >= 0 && idx < BURST_MAX_MEMBERS)
                {
                    strncpy(members[idx].nick,    p->nick,    NICKLEN);
                    strncpy(members[idx].channel, p->channel, CHANNELLEN);
                    members[idx].ts     = p->ts;
                    members[idx].flags  = p->flags;
                    members[idx].parted = 0;
                }
                break;
            }
            case EVT_CHAN_PART:
            {
                const EvPayloadChanPart *p = &ev->payload.chan_part;
                idx = find_burst_member(members, nm, p->nick, p->channel);
                if (idx >= 0)
                    members[idx].parted = 1;
                break;
            }
            case EVT_CHAN_KICK:
            {
                const EvPayloadChanKick *p = &ev->payload.chan_kick;
                idx = find_burst_member(members, nm, p->target, p->channel);
                if (idx >= 0)
                    members[idx].parted = 1;
                break;
            }
            default:
                break;
        }
    }

    /* ---------------------------------------------------------------
     * Pass 2: send synthesised state to cptr.
     *
     * Order: SERVER introductions → NICK → SJOIN
     * Legacy TS synchronisation will resolve any mode conflicts.
     * ------------------------------------------------------------- */

    /* Introduce all currently-up gossip servers */
    for (i = 0; i < ns; i++)
    {
        if (!servers[i].split)
            sendto_one(cptr, ":%s SERVER %s 2 :Gossip peer",
                       me.name, servers[i].name);
    }

    /* Introduce all currently-online gossip users */
    for (i = 0; i < nu; i++)
    {
        if (!users[i].quit)
            sendto_one(cptr,
                "NICK %s 2 %ld + %s %s %s 0 0.0.0.0 :%s",
                users[i].nick, (long)users[i].ts,
                users[i].username, users[i].host, users[i].server,
                users[i].realname);
    }

    /* Send channel memberships */
    for (i = 0; i < nm; i++)
    {
        char prefix[3] = {'\0', '\0', '\0'};
        int  uidx;

        if (members[i].parted)
            continue;

        uidx = find_burst_user(users, nu, members[i].nick);
        if (uidx < 0 || users[uidx].quit)
            continue;

        if (members[i].flags & CHFL_CHANOP)
            prefix[0] = '@';
        else if (members[i].flags & CHFL_VOICE)
            prefix[0] = '+';

        sendto_one(cptr,
            ":%s SJOIN %ld %s + :%s%s",
            me.name, (long)members[i].ts,
            members[i].channel, prefix, members[i].nick);
    }
}
