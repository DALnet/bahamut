/*
 * IRC - Internet Relay Chat, src/gossip.c
 * Copyright (C) 2024 Bahamut IRC Server Project
 *
 * Phase S2: Gossip Multi-Uplink — fanout propagation engine.
 *
 * Events are propagated to min(GOSSIP_FANOUT, n_peers-1) peers selected
 * by rank-permutation on ev->id.seq.  This spreads load across links without
 * flooding while ensuring eventual delivery.
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "send.h"
#include "gossip_event.h"
#include "eventlog.h"
#include "gossip_peer.h"
#include "gossip_dedup.h"
#include "gossip.h"
#include "session.h"

/* -------------------------------------------------------------------------
 * Gossip payload serialisation
 *
 * Compact text format, fields separated by spaces.
 * Tokenised by strtoken() on the receiver side.
 *
 * Per-type format (after "type"):
 *   EVT_USER_JOIN:   nick username host realname server ts modes
 *   EVT_USER_QUIT:   nick :reason
 *   EVT_USER_NICK:   oldnick newnick ts
 *   EVT_USER_MODE:   nick old_umode new_umode
 *   EVT_USER_AWAY:   nick setting :message
 *   EVT_CHAN_JOIN:   nick channel flags ts
 *   EVT_CHAN_PART:   nick channel :reason
 *   EVT_CHAN_KICK:   kicker target channel :reason
 *   EVT_CHAN_MODE:   nick channel modebuf :parabuf
 *   EVT_CHAN_TOPIC:  nick channel setter ts :topic
 *   EVT_SERVER_LINK:    name server_id
 *   EVT_SERVER_SPLIT:   name
 *   EVT_SESSION_CREATE: key nick username host realname umode ts :away_msg
 *   EVT_SESSION_DESTROY:key
 * ---------------------------------------------------------------------- */

static void
serialise_payload(char *buf, size_t buflen, const NetworkEvent *ev)
{
    switch (ev->type)
    {
        case EVT_USER_JOIN:
        {
            const EvPayloadUserJoin *p = &ev->payload.user_join;
            ircsnprintf(buf, buflen, "%s %s %s %s %s %ld %lu",
                        p->nick, p->username, p->host, p->realname,
                        p->server, (long)p->ts, p->umode);
            break;
        }
        case EVT_USER_QUIT:
        {
            const EvPayloadUserQuit *p = &ev->payload.user_quit;
            ircsnprintf(buf, buflen, "%s :%s", p->nick, p->reason);
            break;
        }
        case EVT_USER_NICK:
        {
            const EvPayloadUserNick *p = &ev->payload.user_nick;
            ircsnprintf(buf, buflen, "%s %s %ld",
                        p->oldnick, p->newnick, (long)p->ts);
            break;
        }
        case EVT_USER_MODE:
        {
            const EvPayloadUserMode *p = &ev->payload.user_mode;
            ircsnprintf(buf, buflen, "%s %lu %lu",
                        p->nick, p->old_umode, p->new_umode);
            break;
        }
        case EVT_USER_AWAY:
        {
            const EvPayloadUserAway *p = &ev->payload.user_away;
            ircsnprintf(buf, buflen, "%s %d :%s",
                        p->nick, p->setting, p->message);
            break;
        }
        case EVT_CHAN_JOIN:
        {
            const EvPayloadChanJoin *p = &ev->payload.chan_join;
            ircsnprintf(buf, buflen, "%s %s %d %ld",
                        p->nick, p->channel, p->flags, (long)p->ts);
            break;
        }
        case EVT_CHAN_PART:
        {
            const EvPayloadChanPart *p = &ev->payload.chan_part;
            ircsnprintf(buf, buflen, "%s %s :%s",
                        p->nick, p->channel, p->reason);
            break;
        }
        case EVT_CHAN_KICK:
        {
            const EvPayloadChanKick *p = &ev->payload.chan_kick;
            ircsnprintf(buf, buflen, "%s %s %s :%s",
                        p->kicker, p->target, p->channel, p->reason);
            break;
        }
        case EVT_CHAN_MODE:
        {
            const EvPayloadChanMode *p = &ev->payload.chan_mode;
            ircsnprintf(buf, buflen, "%s %s %s :%s",
                        p->nick, p->channel, p->modebuf, p->parabuf);
            break;
        }
        case EVT_CHAN_TOPIC:
        {
            const EvPayloadChanTopic *p = &ev->payload.chan_topic;
            ircsnprintf(buf, buflen, "%s %s %s %ld :%s",
                        p->nick, p->channel, p->setter,
                        (long)p->ts, p->topic);
            break;
        }
        case EVT_SERVER_LINK:
        {
            const EvPayloadServerLink *p = &ev->payload.server_link;
            ircsnprintf(buf, buflen, "%s %u", p->name, (unsigned)p->id);
            break;
        }
        case EVT_SERVER_SPLIT:
        {
            const EvPayloadServerLink *p = &ev->payload.server_link;
            ircsnprintf(buf, buflen, "%s", p->name);
            break;
        }
        case EVT_SESSION_CREATE:
        {
            const EvPayloadSessionCreate *p = &ev->payload.session_create;
            ircsnprintf(buf, buflen, "%s %s %s %s %s %lu %ld :%s",
                        p->key, p->nick, p->username, p->host, p->realname,
                        p->umode, (long)p->expires_at, p->away_msg);
            break;
        }
        case EVT_SESSION_DESTROY:
        {
            const EvPayloadSessionDestroy *p = &ev->payload.session_destroy;
            ircsnprintf(buf, buflen, "%s", p->key);
            break;
        }
        default:
            ircsnprintf(buf, buflen, "unknown");
            break;
    }
}

/* -------------------------------------------------------------------------
 * Wire serialisation
 * ---------------------------------------------------------------------- */

void
gossip_send_event(aClient *peer, const NetworkEvent *ev)
{
    char sclock[EVENTCLOCK_SPARSE_LEN];
    char payload[1024];
    GossipPeer *gp = (GossipPeer *)peer->serv;

    clock_encode_sparse(&ev->clock, sclock, sizeof(sclock));
    serialise_payload(payload, sizeof(payload), ev);

    sendto_one(peer,
               "@gossip-id=%u:%llu;gossip-clock=%s :%s GEVENT %d :%s",
               (unsigned)ev->id.server,
               (unsigned long long)ev->id.seq,
               sclock,
               me.name,
               (int)ev->type,
               payload);

    /* Update our sent clock for this peer */
    if (gp)
        gp->sent_clock.slot[ev->id.server] = ev->id.seq;
}

/* -------------------------------------------------------------------------
 * Fanout propagation
 * ---------------------------------------------------------------------- */

void
gossip_event(const NetworkEvent *ev, aClient *exclude_link)
{
    DLink *lp;
    int    n_peers = 0;
    int    n_sent  = 0;
    int    fanout  = gossip_fanout;

    /* Count eligible peers */
    for (lp = gopeer_list; lp; lp = lp->next)
    {
        aClient    *peer = lp->value.cptr;
        GossipPeer *gp   = (GossipPeer *)peer->serv;
        if (peer == exclude_link)
            continue;
        if (!gp || !gp->burst_complete)
            continue;
        n_peers++;
    }

    if (n_peers == 0 || fanout <= 0)
        return;

    if (fanout > n_peers)
        fanout = n_peers;

    /*
     * Rank-permuted peer selection:
     * Assign rank = (ev->id.seq + peer_index) mod n_peers to each peer.
     * Select the fanout peers with the smallest rank.
     *
     * Simple implementation: iterate all peers, send to those with
     * rank < fanout.  This is equivalent to taking the first `fanout`
     * peers in a rotation anchored on ev->id.seq mod n_peers.
     */
    {
        int peer_idx = 0;
        int rotation = (int)(ev->id.seq % (uint64_t)n_peers);

        for (lp = gopeer_list; lp && n_sent < fanout; lp = lp->next)
        {
            aClient    *peer = lp->value.cptr;
            GossipPeer *gp   = (GossipPeer *)peer->serv;
            int         rank;

            if (peer == exclude_link)
                continue;
            if (!gp || !gp->burst_complete)
                continue;

            rank = (peer_idx - rotation + n_peers) % n_peers;
            if (rank < fanout)
            {
                gossip_send_event(peer, ev);
                n_sent++;
            }
            peer_idx++;
        }
    }
}

/* -------------------------------------------------------------------------
 * Event parsing (inbound GEVENT)
 * ---------------------------------------------------------------------- */

int
gossip_parse_event(NetworkEvent *ev, NetEventType type, const char *payload,
                   ServerId origin_id, LocalSeq origin_seq,
                   const EventClock *clock)
{
    ev->id.server  = origin_id;
    ev->id.seq     = origin_seq;
    ev->wall_time  = time(NULL);
    ev->type       = type;
    ev->next       = NULL;
    memcpy(&ev->clock, clock, sizeof(EventClock));
    memset(&ev->payload, 0, sizeof(ev->payload));

    /* Payload is a strtoken-friendly space-delimited string.
     * We copy it to a mutable buffer for parsing. */
    char buf[1024];
    char *p = NULL, *tok;

    strncpy(buf, payload, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    switch (type)
    {
        case EVT_USER_JOIN:
        {
            EvPayloadUserJoin *pl = &ev->payload.user_join;
            tok = strtoken(&p, buf, " "); if (!tok) return -1;
            strncpy(pl->nick, tok, NICKLEN);
            tok = strtoken(&p, NULL, " "); if (!tok) return -1;
            strncpy(pl->username, tok, USERLEN);
            tok = strtoken(&p, NULL, " "); if (!tok) return -1;
            strncpy(pl->host, tok, HOSTLEN);
            tok = strtoken(&p, NULL, " "); if (!tok) return -1;
            strncpy(pl->realname, tok, REALLEN);
            tok = strtoken(&p, NULL, " "); if (!tok) return -1;
            strncpy(pl->server, tok, HOSTLEN);
            tok = strtoken(&p, NULL, " "); if (!tok) return -1;
            pl->ts = (time_t)atol(tok);
            tok = strtoken(&p, NULL, " ");
            if (tok) pl->umode = strtoul(tok, NULL, 10);
            break;
        }
        case EVT_USER_QUIT:
        {
            EvPayloadUserQuit *pl = &ev->payload.user_quit;
            tok = strtoken(&p, buf, " "); if (!tok) return -1;
            strncpy(pl->nick, tok, NICKLEN);
            tok = strtoken(&p, NULL, ":");
            if (tok) strncpy(pl->reason, tok, sizeof(pl->reason) - 1);
            break;
        }
        case EVT_USER_NICK:
        {
            EvPayloadUserNick *pl = &ev->payload.user_nick;
            tok = strtoken(&p, buf, " "); if (!tok) return -1;
            strncpy(pl->oldnick, tok, NICKLEN);
            tok = strtoken(&p, NULL, " "); if (!tok) return -1;
            strncpy(pl->newnick, tok, NICKLEN);
            tok = strtoken(&p, NULL, " ");
            if (tok) pl->ts = (time_t)atol(tok);
            break;
        }
        case EVT_USER_MODE:
        {
            EvPayloadUserMode *pl = &ev->payload.user_mode;
            tok = strtoken(&p, buf, " "); if (!tok) return -1;
            strncpy(pl->nick, tok, NICKLEN);
            tok = strtoken(&p, NULL, " ");
            if (tok) pl->old_umode = strtoul(tok, NULL, 10);
            tok = strtoken(&p, NULL, " ");
            if (tok) pl->new_umode = strtoul(tok, NULL, 10);
            break;
        }
        case EVT_USER_AWAY:
        {
            EvPayloadUserAway *pl = &ev->payload.user_away;
            tok = strtoken(&p, buf, " "); if (!tok) return -1;
            strncpy(pl->nick, tok, NICKLEN);
            tok = strtoken(&p, NULL, " ");
            if (tok) pl->setting = atoi(tok);
            tok = strtoken(&p, NULL, ":");
            if (tok) strncpy(pl->message, tok, TOPICLEN);
            break;
        }
        case EVT_CHAN_JOIN:
        {
            EvPayloadChanJoin *pl = &ev->payload.chan_join;
            tok = strtoken(&p, buf, " "); if (!tok) return -1;
            strncpy(pl->nick, tok, NICKLEN);
            tok = strtoken(&p, NULL, " "); if (!tok) return -1;
            strncpy(pl->channel, tok, CHANNELLEN);
            tok = strtoken(&p, NULL, " ");
            if (tok) pl->flags = atoi(tok);
            tok = strtoken(&p, NULL, " ");
            if (tok) pl->ts = (time_t)atol(tok);
            break;
        }
        case EVT_CHAN_PART:
        {
            EvPayloadChanPart *pl = &ev->payload.chan_part;
            tok = strtoken(&p, buf, " "); if (!tok) return -1;
            strncpy(pl->nick, tok, NICKLEN);
            tok = strtoken(&p, NULL, " "); if (!tok) return -1;
            strncpy(pl->channel, tok, CHANNELLEN);
            tok = strtoken(&p, NULL, ":");
            if (tok) strncpy(pl->reason, tok, sizeof(pl->reason) - 1);
            break;
        }
        case EVT_CHAN_KICK:
        {
            EvPayloadChanKick *pl = &ev->payload.chan_kick;
            tok = strtoken(&p, buf, " "); if (!tok) return -1;
            strncpy(pl->kicker, tok, NICKLEN);
            tok = strtoken(&p, NULL, " "); if (!tok) return -1;
            strncpy(pl->target, tok, NICKLEN);
            tok = strtoken(&p, NULL, " "); if (!tok) return -1;
            strncpy(pl->channel, tok, CHANNELLEN);
            tok = strtoken(&p, NULL, ":");
            if (tok) strncpy(pl->reason, tok, sizeof(pl->reason) - 1);
            break;
        }
        case EVT_CHAN_MODE:
        {
            EvPayloadChanMode *pl = &ev->payload.chan_mode;
            tok = strtoken(&p, buf, " "); if (!tok) return -1;
            strncpy(pl->nick, tok, NICKLEN);
            tok = strtoken(&p, NULL, " "); if (!tok) return -1;
            strncpy(pl->channel, tok, CHANNELLEN);
            tok = strtoken(&p, NULL, " "); if (!tok) return -1;
            strncpy(pl->modebuf, tok, sizeof(pl->modebuf) - 1);
            tok = strtoken(&p, NULL, ":");
            if (tok) strncpy(pl->parabuf, tok, sizeof(pl->parabuf) - 1);
            break;
        }
        case EVT_CHAN_TOPIC:
        {
            EvPayloadChanTopic *pl = &ev->payload.chan_topic;
            tok = strtoken(&p, buf, " "); if (!tok) return -1;
            strncpy(pl->nick, tok, NICKLEN);
            tok = strtoken(&p, NULL, " "); if (!tok) return -1;
            strncpy(pl->channel, tok, CHANNELLEN);
            tok = strtoken(&p, NULL, " "); if (!tok) return -1;
            strncpy(pl->setter, tok, sizeof(pl->setter) - 1);
            tok = strtoken(&p, NULL, " ");
            if (tok) pl->ts = (time_t)atol(tok);
            tok = strtoken(&p, NULL, ":");
            if (tok) strncpy(pl->topic, tok, TOPICLEN);
            break;
        }
        case EVT_SERVER_LINK:
        case EVT_SERVER_SPLIT:
        {
            EvPayloadServerLink *pl = &ev->payload.server_link;
            tok = strtoken(&p, buf, " "); if (!tok) return -1;
            strncpy(pl->name, tok, HOSTLEN);
            tok = strtoken(&p, NULL, " ");
            if (tok) pl->id = (ServerId)atoi(tok);
            break;
        }
        case EVT_SESSION_CREATE:
        {
            EvPayloadSessionCreate *pl = &ev->payload.session_create;
            tok = strtoken(&p, buf, " "); if (!tok) return -1;
            strncpy(pl->key,      tok, SESSION_KEY_LEN);
            tok = strtoken(&p, NULL, " "); if (!tok) return -1;
            strncpy(pl->nick,     tok, NICKLEN);
            tok = strtoken(&p, NULL, " "); if (!tok) return -1;
            strncpy(pl->username, tok, USERLEN);
            tok = strtoken(&p, NULL, " "); if (!tok) return -1;
            strncpy(pl->host,     tok, HOSTLEN);
            tok = strtoken(&p, NULL, " "); if (!tok) return -1;
            strncpy(pl->realname, tok, REALLEN);
            tok = strtoken(&p, NULL, " ");
            if (tok) pl->umode = strtoul(tok, NULL, 10);
            tok = strtoken(&p, NULL, " ");
            if (tok) pl->expires_at = (time_t)atol(tok);
            tok = strtoken(&p, NULL, ":");
            if (tok) strncpy(pl->away_msg, tok, TOPICLEN);
            break;
        }
        case EVT_SESSION_DESTROY:
        {
            EvPayloadSessionDestroy *pl = &ev->payload.session_destroy;
            tok = strtoken(&p, buf, " "); if (!tok) return -1;
            strncpy(pl->key, tok, SESSION_KEY_LEN);
            break;
        }
        default:
            break;
    }

    return 0;
}

/* -------------------------------------------------------------------------
 * Event application — update local state from a received event.
 * This is Phase S2 stub; full implementation in Phase S3 bridge.
 * ---------------------------------------------------------------------- */

void
gossip_apply_event(const NetworkEvent *ev)
{
    /* Record in event log (advance clock). */
    clock_advance(&ev->clock);
    /* The event was already deduplicated; store a copy in the log. */
    emit_event(ev->type, &ev->payload, sizeof(ev->payload));

    /* Phase S4: apply session events to local session table. */
    switch (ev->type)
    {
        case EVT_SESSION_CREATE:
        {
            const EvPayloadSessionCreate *p = &ev->payload.session_create;
            session_apply_create(p->key, p->nick, p->username, p->host,
                                 p->realname, p->umode,
                                 p->away_msg, p->expires_at);
            break;
        }
        case EVT_SESSION_DESTROY:
        {
            const EvPayloadSessionDestroy *p = &ev->payload.session_destroy;
            session_apply_destroy(p->key);
            break;
        }
        default:
            break;
    }
}

/* -------------------------------------------------------------------------
 * Initialisation
 * ---------------------------------------------------------------------- */

void
gossip_init(void)
{
    dedup_init();
    gopeer_count_configured();
    gopeer_set_start_time();
    fprintf(stderr, " - Gossip subsystem initialised"
                    " (fanout=%d sync_window=%d configured_peers=%d)\n",
            gossip_fanout, gossip_sync_window, gopeer_configured_count);
}
