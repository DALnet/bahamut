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
#include "channel.h"
#include "gossip_event.h"
#include "eventlog.h"
#include "gossip_peer.h"
#include "gossip_dedup.h"
#include "numeric.h"
#include "blalloc.h"

/* Externs for functions not declared in headers */
extern aChannel *make_channel(char *name);
extern void add_user_to_channel(aChannel *, aClient *, int);
extern Link *find_channel_link(Link *, aChannel *);
extern void del_invite(aClient *, aChannel *);
extern void remove_client_from_list(aClient *);
extern BlockHeap *free_anUsers;
extern BlockHeap *free_remote_aClients;
extern int add_to_channel_hash_table(char *, aChannel *);
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
        case EVT_PRIVMSG:
        {
            const EvPayloadPrivmsg *p = &ev->payload.privmsg;
            ircsnprintf(buf, buflen, "%s %s %d :%s",
                        p->sender, p->target, p->is_notice, p->text);
            break;
        }
        case EVT_CHANMSG:
        {
            const EvPayloadChanmsg *p = &ev->payload.chanmsg;
            ircsnprintf(buf, buflen, "%s %s %d :%s",
                        p->sender, p->channel, p->is_notice, p->text);
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
        case EVT_PRIVMSG:
        {
            EvPayloadPrivmsg *pl = &ev->payload.privmsg;
            tok = strtoken(&p, buf, " "); if (!tok) return -1;
            strncpy(pl->sender, tok, NICKLEN);
            tok = strtoken(&p, NULL, " "); if (!tok) return -1;
            strncpy(pl->target, tok, NICKLEN);
            tok = strtoken(&p, NULL, " "); if (!tok) return -1;
            pl->is_notice = atoi(tok);
            tok = strtoken(&p, NULL, "");
            if (tok) {
                if (*tok == ':') tok++;
                strncpy(pl->text, tok, sizeof(pl->text) - 1);
            }
            break;
        }
        case EVT_CHANMSG:
        {
            EvPayloadChanmsg *pl = &ev->payload.chanmsg;
            tok = strtoken(&p, buf, " "); if (!tok) return -1;
            strncpy(pl->sender, tok, NICKLEN);
            tok = strtoken(&p, NULL, " "); if (!tok) return -1;
            strncpy(pl->channel, tok, CHANNELLEN);
            tok = strtoken(&p, NULL, " "); if (!tok) return -1;
            pl->is_notice = atoi(tok);
            tok = strtoken(&p, NULL, "");
            if (tok) {
                if (*tok == ':') tok++;
                strncpy(pl->text, tok, sizeof(pl->text) - 1);
            }
            break;
        }
        default:
            break;
    }

    return 0;
}

/* -------------------------------------------------------------------------
 * Phase S6: Gossip state materialization.
 *
 * When a gossip event arrives, create/update/remove real aClient and aChannel
 * entries so remote users are visible (LUSERS, WHOIS, PRIVMSG, channels).
 *
 * Key invariants:
 * - Events from me.name are skipped (already in local state).
 * - Materialized clients have FLAGS_GOSSIP_MAT set.
 * - Double-emission is prevented by the guard in m_gossip_eventlog.c.
 * - gossip_remove_user() does NOT call sendto_serv_butone (bridge handles TS5).
 * ---------------------------------------------------------------------- */

/* --- S6c: Server materialization ---------------------------------------- */

static aClient *
gossip_materialize_server(const char *name, int id)
{
    aClient *acptr;

    acptr = find_server((char *)name, NULL);
    if (acptr)
        return acptr;

    acptr = make_client(&me, NULL);
    make_server(acptr);
    acptr->hopcount = 1;
    SetServer(acptr);
    SetGossipMaterialized(acptr);
    strncpyzt(acptr->name, name, sizeof(acptr->name));
    acptr->serv->up = find_or_add(me.name);

    add_client_to_list(acptr);
    add_to_client_hash_table(acptr->name, acptr);
    Count.server++;
    return acptr;
}

static void gossip_remove_user(aClient *acptr, const char *reason);

static void
gossip_split_server(const char *name)
{
    aClient *acptr, *next;

    /* Remove all users belonging to this server */
    for (acptr = client; acptr; acptr = next)
    {
        next = acptr->next;
        if (!IsClient(acptr) || !IsGossipMaterialized(acptr))
            continue;
        if (!acptr->user || !acptr->user->server)
            continue;
        if (mycmp(acptr->user->server, name) != 0)
            continue;
        gossip_remove_user(acptr, "*.net *.split");
    }

    /* Remove the server entry */
    acptr = find_server((char *)name, NULL);
    if (acptr && IsGossipMaterialized(acptr))
    {
        del_from_client_hash_table(acptr->name, acptr);
        remove_client_from_list(acptr);
        Count.server--;
        if (acptr->serv)
            MyFree(acptr->serv);
        free_client(acptr);
    }
}

/* --- S6d: User materialization ------------------------------------------ */

static aClient *
gossip_materialize_user(const EvPayloadUserJoin *p)
{
    aClient *acptr, *server;

    /* Skip events originating from our own server */
    if (mycmp(p->server, me.name) == 0)
        return NULL;

    /* Nick collision / idempotency check */
    acptr = find_client(p->nick, NULL);
    if (acptr)
    {
        /* If the existing client is a gossip-materialized user from the
         * same server with the same TS, this is a duplicate (burst replay).
         * Skip silently to avoid double-materialization. */
        if (IsGossipMaterialized(acptr) && acptr->user &&
            mycmp(acptr->user->server, p->server) == 0 &&
            acptr->tsinfo == p->ts)
            return acptr;

        if (!p->ts || !acptr->tsinfo || p->ts == acptr->tsinfo)
        {
            /* Equal or missing TS — kill both */
            if (IsGossipMaterialized(acptr))
                gossip_remove_user(acptr, "Nick collision (gossip)");
            else
                exit_client(acptr, acptr, &me, "Nick collision (gossip)");
            return NULL;
        }
        else if (p->ts > acptr->tsinfo)
        {
            /* Incoming is newer — drop it */
            return NULL;
        }
        else
        {
            /* Incoming is older — kill existing */
            if (IsGossipMaterialized(acptr))
                gossip_remove_user(acptr, "Nick collision (gossip)");
            else
                exit_client(acptr, acptr, &me, "Nick collision (gossip)");
        }
    }

    /* Ensure server exists */
    server = find_server((char *)p->server, NULL);
    if (!server)
        server = gossip_materialize_server(p->server, 0);

    /* Create the user (remote allocation — from != NULL) */
    acptr = make_client(server, NULL);
    acptr->hopcount = 2;
    acptr->tsinfo = p->ts;
    acptr->umode = p->umode & SEND_UMODES;
    SetGossipMaterialized(acptr);
    strncpyzt(acptr->name, p->nick, NICKLEN + 1);

    add_client_to_list(acptr);
    add_to_client_hash_table(acptr->name, acptr);

    /* Initialize user struct */
    {
        anUser *user = make_user(acptr);
        user->server = find_or_add(p->server);
        strncpyzt(user->username, p->username, USERLEN + 1);
        strncpyzt(user->host, p->host, HOSTLEN + 1);
    }
    strncpyzt(acptr->info, p->realname, REALLEN + 1);

    /* Gossip users get 0.0.0.0 */
    acptr->ip_family = 0;

    SetClient(acptr);

    if (++Count.total > Count.max_tot)
        Count.max_tot = Count.total;
    if (acptr->umode & UMODE_i)
        Count.invisi++;

    hash_check_watch(acptr, RPL_LOGON);
    return acptr;
}

static void
gossip_remove_user(aClient *acptr, const char *reason)
{
    Link *lp;

    if (!acptr || !IsClient(acptr))
        return;

    /* Send QUIT to local channel members */
    if (acptr->user && acptr->user->channel)
    {
        for (lp = acptr->user->channel; lp; lp = lp->next)
        {
            sendto_channel_butserv(lp->value.chptr, acptr,
                ":%s QUIT :%s", acptr->name, reason ? reason : "");
        }
        while ((lp = acptr->user->channel))
            remove_user_from_channel(acptr, lp->value.chptr);
    }

    if (acptr->user)
    {
        while ((lp = acptr->user->invited))
            del_invite(acptr, lp->value.chptr);
    }

    del_from_client_hash_table(acptr->name, acptr);
    if (IsRegistered(acptr))
        hash_check_watch(acptr, RPL_LOGOFF);

    /* Update counts */
    if (IsClient(acptr))
    {
        Count.total--;
        if (IsInvisible(acptr))
            Count.invisi--;
    }

    /* Unlink from client list */
    if (acptr->prev)
        acptr->prev->next = acptr->next;
    else
    {
        client = acptr->next;
        if (client)
            client->prev = NULL;
    }
    if (acptr->next)
        acptr->next->prev = acptr->prev;

    /* Free user struct via the proper BlockHeap free */
    if (acptr->user)
    {
        if (acptr->user->away)
            MyFree(acptr->user->away);
        BlockHeapFree(free_anUsers, acptr->user);
        acptr->user = NULL;
    }

    /* Free client block */
    BlockHeapFree(free_remote_aClients, acptr);
}

/* --- S6e: Channel materialization --------------------------------------- */

static void
gossip_apply_chan_join(const EvPayloadChanJoin *p)
{
    aClient  *acptr;
    aChannel *chptr;

    acptr = find_client(p->nick, NULL);
    if (!acptr || !IsGossipMaterialized(acptr))
        return;

    chptr = find_channel(p->channel, NullChn);
    if (!chptr)
    {
        chptr = make_channel((char *)p->channel);
        if (!chptr) return;
        strncpyzt(chptr->chname, p->channel, sizeof(chptr->chname));
        chptr->channelts = p->ts ? p->ts : timeofday;
        chptr->max_bans = 200;     /* MAXBANS default */
        chptr->max_invites = 100;  /* MAXINVITELIST default */
        /* Link into global channel list and hash */
        if (channel)
            channel->prevch = chptr;
        chptr->prevch = NULL;
        chptr->nextch = channel;
        channel = chptr;
        add_to_channel_hash_table(chptr->chname, chptr);
        Count.chan++;
    }
    else if (p->ts && p->ts < chptr->channelts)
        chptr->channelts = p->ts;

    /* Already on channel? */
    if (find_channel_link(acptr->user->channel, chptr))
        return;

    add_user_to_channel(chptr, acptr, p->flags);

    sendto_channel_butserv(chptr, acptr, ":%s JOIN :%s",
                           acptr->name, chptr->chname);
}

static void
gossip_apply_chan_part(const EvPayloadChanPart *p)
{
    aClient  *acptr;
    aChannel *chptr;

    acptr = find_client(p->nick, NULL);
    if (!acptr || !IsGossipMaterialized(acptr))
        return;

    chptr = find_channel(p->channel, NullChn);
    if (!chptr)
        return;

    sendto_channel_butserv(chptr, acptr, ":%s PART %s :%s",
                           acptr->name, chptr->chname,
                           p->reason[0] ? p->reason : "");
    remove_user_from_channel(acptr, chptr);
}

static void
gossip_apply_chan_kick(const EvPayloadChanKick *p)
{
    aClient  *kicker, *target;
    aChannel *chptr;

    target = find_client(p->target, NULL);
    chptr  = find_channel(p->channel, NullChn);

    if (!target || !chptr)
        return;
    if (!IsGossipMaterialized(target))
        return;

    kicker = find_client(p->kicker, NULL);

    sendto_channel_butserv(chptr, kicker ? kicker : &me,
        ":%s KICK %s %s :%s",
        kicker ? kicker->name : me.name,
        chptr->chname, target->name,
        p->reason[0] ? p->reason : "");
    remove_user_from_channel(target, chptr);
}

static void
gossip_apply_chan_mode(const EvPayloadChanMode *p)
{
    aClient  *acptr;
    aChannel *chptr;

    chptr = find_channel(p->channel, NullChn);
    if (!chptr)
        return;

    acptr = find_client(p->nick, NULL);

    if (p->parabuf[0])
        sendto_channel_butserv(chptr, acptr ? acptr : &me,
            ":%s MODE %s %s %s",
            acptr ? acptr->name : me.name,
            chptr->chname, p->modebuf, p->parabuf);
    else
        sendto_channel_butserv(chptr, acptr ? acptr : &me,
            ":%s MODE %s %s",
            acptr ? acptr->name : me.name,
            chptr->chname, p->modebuf);
}

static void
gossip_apply_chan_topic(const EvPayloadChanTopic *p)
{
    aChannel *chptr;

    chptr = find_channel(p->channel, NullChn);
    if (!chptr)
        return;

    strncpyzt(chptr->topic, p->topic, TOPICLEN + 1);
    strncpyzt(chptr->topic_nick, p->setter, sizeof(chptr->topic_nick));
    chptr->topic_time = p->ts;

    sendto_channel_butserv(chptr, &me,
        ":%s TOPIC %s :%s", p->setter, chptr->chname, p->topic);
}

/* --- S6f: Remaining user events ----------------------------------------- */

static void
gossip_apply_user_quit(const EvPayloadUserQuit *p)
{
    aClient *acptr = find_client(p->nick, NULL);
    if (!acptr || !IsGossipMaterialized(acptr))
        return;
    gossip_remove_user(acptr, p->reason[0] ? p->reason : "Quit");
}

static void
gossip_apply_user_nick(const EvPayloadUserNick *p)
{
    aClient *acptr, *existing;

    acptr = find_client(p->oldnick, NULL);
    if (!acptr || !IsGossipMaterialized(acptr))
        return;

    existing = find_client(p->newnick, NULL);
    if (existing && existing != acptr)
    {
        if (p->ts >= existing->tsinfo)
        {
            gossip_remove_user(acptr, "Nick collision (gossip)");
            return;
        }
        else
        {
            if (IsGossipMaterialized(existing))
                gossip_remove_user(existing, "Nick collision (gossip)");
            else
                exit_client(existing, existing, &me, "Nick collision (gossip)");
        }
    }

    sendto_common_channels(acptr, ":%s NICK :%s",
                           acptr->name, p->newnick);

    del_from_client_hash_table(acptr->name, acptr);
    hash_check_watch(acptr, RPL_LOGOFF);
    strncpyzt(acptr->name, p->newnick, NICKLEN + 1);
    add_to_client_hash_table(acptr->name, acptr);
    hash_check_watch(acptr, RPL_LOGON);
    acptr->tsinfo = p->ts;
}

static void
gossip_apply_user_mode(const EvPayloadUserMode *p)
{
    aClient *acptr = find_client(p->nick, NULL);
    if (!acptr || !IsGossipMaterialized(acptr))
        return;

    unsigned long old = acptr->umode;
    acptr->umode = p->new_umode & SEND_UMODES;

    if ((old & UMODE_i) && !(acptr->umode & UMODE_i))
        Count.invisi--;
    else if (!(old & UMODE_i) && (acptr->umode & UMODE_i))
        Count.invisi++;
}

static void
gossip_apply_user_away(const EvPayloadUserAway *p)
{
    aClient *acptr = find_client(p->nick, NULL);
    if (!acptr || !IsGossipMaterialized(acptr))
        return;

    if (acptr->user)
    {
        if (p->setting && p->message[0])
        {
            if (acptr->user->away)
                MyFree(acptr->user->away);
            acptr->user->away = (char *)MyMalloc(strlen(p->message) + 1);
            strcpy(acptr->user->away, p->message);
        }
        else
        {
            if (acptr->user->away)
            {
                MyFree(acptr->user->away);
                acptr->user->away = NULL;
            }
        }
    }
}

/* --- S6g: Wire up gossip_apply_event() ---------------------------------- */

void
gossip_apply_event(const NetworkEvent *ev)
{
    /* Record in event log (advance clock). */
    clock_advance(&ev->clock);
    emit_event(ev->type, &ev->payload, sizeof(ev->payload));

    switch (ev->type)
    {
        case EVT_SERVER_LINK:
        {
            const EvPayloadServerLink *p = &ev->payload.server_link;
            if (mycmp(p->name, me.name) != 0)
                gossip_materialize_server(p->name, p->id);
            break;
        }
        case EVT_SERVER_SPLIT:
        {
            const EvPayloadServerLink *p = &ev->payload.server_link;
            if (mycmp(p->name, me.name) != 0)
                gossip_split_server(p->name);
            break;
        }
        case EVT_USER_JOIN:
            gossip_materialize_user(&ev->payload.user_join);
            break;
        case EVT_USER_QUIT:
            gossip_apply_user_quit(&ev->payload.user_quit);
            break;
        case EVT_USER_NICK:
            gossip_apply_user_nick(&ev->payload.user_nick);
            break;
        case EVT_USER_MODE:
            gossip_apply_user_mode(&ev->payload.user_mode);
            break;
        case EVT_USER_AWAY:
            gossip_apply_user_away(&ev->payload.user_away);
            break;
        case EVT_CHAN_JOIN:
            gossip_apply_chan_join(&ev->payload.chan_join);
            break;
        case EVT_CHAN_PART:
            gossip_apply_chan_part(&ev->payload.chan_part);
            break;
        case EVT_CHAN_KICK:
            gossip_apply_chan_kick(&ev->payload.chan_kick);
            break;
        case EVT_CHAN_MODE:
            gossip_apply_chan_mode(&ev->payload.chan_mode);
            break;
        case EVT_CHAN_TOPIC:
            gossip_apply_chan_topic(&ev->payload.chan_topic);
            break;
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
        case EVT_PRIVMSG:
        {
            const EvPayloadPrivmsg *p = &ev->payload.privmsg;
            aClient *target = find_client(p->target, NULL);
            aClient *sender = find_client(p->sender, NULL);
            if (target && MyConnect(target))
            {
                const char *cmd = p->is_notice ? "NOTICE" : "PRIVMSG";
                if (sender)
                    sendto_one(target, ":%s %s %s :%s",
                               sender->name, cmd, target->name, p->text);
                else
                    sendto_one(target, ":%s %s %s :%s",
                               p->sender, cmd, target->name, p->text);
            }
            break;
        }
        case EVT_CHANMSG:
        {
            const EvPayloadChanmsg *p = &ev->payload.chanmsg;
            aChannel *chptr = find_channel(p->channel, NullChn);
            aClient *sender = find_client(p->sender, NULL);
            if (chptr)
            {
                const char *cmd = p->is_notice ? "NOTICE" : "PRIVMSG";
                /* Deliver to local channel members only */
                sendto_channel_butserv(chptr,
                    sender ? sender : &me,
                    ":%s %s %s :%s",
                    sender ? sender->name : p->sender,
                    cmd, chptr->chname, p->text);
            }
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
