/*
 * IRC - Internet Relay Chat, src/s_gopeer.c
 * Copyright (C) 2024 Bahamut IRC Server Project
 *
 * Phase S2: Gossip Multi-Uplink — gopeer connection lifecycle.
 *
 * Handles: outbound connect, GHELLO handshake, burst exchange,
 * and clean disconnect without cascading QUITs.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

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
#include "gossip_bridge.h"
#include "channel.h"
#include "fds.h"
#include "session.h"

extern Link *find_channel_link(Link *, aChannel *);

/* -------------------------------------------------------------------------
 * Global state
 * ---------------------------------------------------------------------- */

DLink      *gopeer_list       = NULL;
int         gossip_fanout     = 3;
int         gossip_sync_window = 30;
aGoPeerConf *gopeer_conf_list = NULL;

/* Partition detection (CODERS-33) */
int         gopeer_configured_count = 0;
int         gopeer_connected_count  = 0;

#define GOSSIP_GRACE_SECONDS 60
static time_t gossip_start_time = 0;

/* -------------------------------------------------------------------------
 * Partition detection (CODERS-33)
 * ---------------------------------------------------------------------- */

void
gopeer_count_configured(void)
{
    aGoPeerConf *conf;
    int count = 0;

    for (conf = gopeer_conf_list; conf; conf = conf->next)
        count++;

    gopeer_configured_count = count;
}

void
gopeer_set_start_time(void)
{
    gossip_start_time = time(NULL);
}

int
gossip_is_partitioned(void)
{
    /* Standalone server (no gossip peers configured) — no risk */
    if (gopeer_configured_count == 0)
        return 0;

    /* Has at least one burst-complete peer — not partitioned */
    if (gopeer_connected_count > 0)
        return 0;

    /* Within startup grace period — allow bootstrap */
    if (gossip_start_time > 0 &&
        (time(NULL) - gossip_start_time) < GOSSIP_GRACE_SECONDS)
        return 0;

    /* Partitioned: has configured peers but none connected */
    return 1;
}

/* -------------------------------------------------------------------------
 * Lifecycle
 * ---------------------------------------------------------------------- */

GossipPeer *
gopeer_attach(aClient *cptr, ServerId peer_id, const char *name)
{
    GossipPeer *gp;

    gp = (GossipPeer *) MyMalloc(sizeof(GossipPeer));
    memset(gp, 0, sizeof(*gp));

    strncpy(gp->name, name, HOSTLEN);
    gp->peer_id      = peer_id;
    gp->connected_at = time(NULL);
    gp->last_ping    = time(NULL);

    /* Store in cptr->serv — reuses the aServer pointer slot */
    cptr->serv = (aServer *) gp;

    /* Add to global gopeer list */
    add_to_list(&gopeer_list, cptr);

    return gp;
}

void
gopeer_handle_disconnect(aClient *cptr)
{
    GossipPeer *gp = (GossipPeer *)cptr->serv;

    if (!gp)
        return;

    /* Decrement connected count if this peer had completed burst */
    if (gp->burst_complete)
        gopeer_connected_count--;

    sendto_realops("Gossip peer %s disconnected", gp->name);

    /* Emit server split event */
    {
        EvPayloadServerLink pl;
        memset(&pl, 0, sizeof(pl));
        strncpy(pl.name, gp->name, HOSTLEN);
        pl.id = gp->peer_id;
        emit_event(EVT_SERVER_SPLIT, &pl, sizeof(pl));
    }

    /* Phase S3: notify legacy TS5 servers that this gossip peer is gone.
     * TS5 servers need SQUIT + QUIT storms — they don't understand gossip.
     * This sends SQUIT to all connected TS5 links. */
    bridge_split_server(gp->name);

    /* Remove from gopeer list and free GossipPeer struct */
    remove_from_list(&gopeer_list, cptr, NULL);
    MyFree(gp);
    cptr->serv = NULL;

    /* Sable-inspired: do NOT call gossip_split_server() here.
     * Materialized users and the server entry persist — they represent
     * state that may still be reachable via other mesh paths or will
     * resync when the peer reconnects.  Users are only removed when
     * an explicit EVT_USER_QUIT event arrives through the gossip mesh.
     * This eliminates netsplit QUIT storms on the gossip side while
     * legacy TS5 servers still get proper SQUIT via the bridge above. */
}

/* Sequence counter for synthetic burst events — each needs a unique seq
 * to pass through the receiver's dedup table. We use a high range
 * (starting at 0x80000000) to avoid colliding with real event sequences. */
static LocalSeq burst_seq_counter = 0x80000000UL;

/* Send a synthesized event directly to a single peer (not to the ring). */
static void
burst_send_event(aClient *peer, NetEventType type, void *payload, size_t len)
{
    NetworkEvent ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = type;
    ev.id.server = g_event_log.my_id;
    ev.id.seq = burst_seq_counter++;
    ev.wall_time = timeofday;
    memcpy(&ev.payload, payload, len);
    gossip_send_event(peer, &ev);
}

/* S6i: Send full current state to a fresh gossip peer.
 * Synthesizes events for all servers, users, channel memberships,
 * topics, away statuses, and sessions. */
static void
gopeer_burst_full_state(aClient *peer)
{
    aClient  *acptr;
    aChannel *chptr;

    /* 1. Introduce our own server */
    {
        EvPayloadServerLink pl;
        memset(&pl, 0, sizeof(pl));
        strncpy(pl.name, me.name, HOSTLEN);
        pl.id = g_event_log.my_id;
        burst_send_event(peer, EVT_SERVER_LINK, &pl, sizeof(pl));
    }

    /* 2. Introduce all gossip-materialized servers */
    for (acptr = client; acptr; acptr = acptr->next)
    {
        if (!IsServer(acptr) || !IsGossipMaterialized(acptr))
            continue;
        EvPayloadServerLink pl;
        memset(&pl, 0, sizeof(pl));
        strncpy(pl.name, acptr->name, HOSTLEN);
        burst_send_event(peer, EVT_SERVER_LINK, &pl, sizeof(pl));
    }

    /* 3. Introduce all users (local + gossip-materialized) */
    for (acptr = client; acptr; acptr = acptr->next)
    {
        Link *lp;
        if (!IsClient(acptr) || !acptr->user)
            continue;

        /* USER_JOIN */
        {
            EvPayloadUserJoin pl;
            memset(&pl, 0, sizeof(pl));
            strncpy(pl.nick, acptr->name, NICKLEN);
            strncpy(pl.username, acptr->user->username, USERLEN);
            strncpy(pl.host, acptr->user->host, HOSTLEN);
            strncpy(pl.realname, acptr->info, REALLEN);
            if (acptr->user->server)
                strncpy(pl.server, acptr->user->server, HOSTLEN);
            else
                strncpy(pl.server, me.name, HOSTLEN);
            if (acptr->hostip[0])
                strncpy(pl.ipstr, acptr->hostip, HOSTLEN);
            pl.umode = acptr->umode;
            pl.ts = acptr->tsinfo;
            burst_send_event(peer, EVT_USER_JOIN, &pl, sizeof(pl));
        }

        /* Channel memberships */
        for (lp = acptr->user->channel; lp; lp = lp->next)
        {
            aChannel *ch = lp->value.chptr;
            chanMember *cm;
            int flags = 0;

            for (cm = ch->members; cm; cm = cm->next)
                if (cm->cptr == acptr) { flags = cm->flags; break; }

            EvPayloadChanJoin pl;
            memset(&pl, 0, sizeof(pl));
            strncpy(pl.nick, acptr->name, NICKLEN);
            strncpy(pl.channel, ch->chname, CHANNELLEN);
            pl.flags = flags;
            pl.ts = ch->channelts;
            burst_send_event(peer, EVT_CHAN_JOIN, &pl, sizeof(pl));
        }

        /* Away status */
        if (acptr->user->away)
        {
            EvPayloadUserAway pl;
            memset(&pl, 0, sizeof(pl));
            strncpy(pl.nick, acptr->name, NICKLEN);
            pl.setting = 1;
            strncpy(pl.message, acptr->user->away, TOPICLEN);
            burst_send_event(peer, EVT_USER_AWAY, &pl, sizeof(pl));
        }
    }

    /* 4. Send channel modes */
    for (chptr = channel; chptr; chptr = chptr->nextch)
    {
        char mbuf[64], pbuf[256];
        char *mp = mbuf, *pp = pbuf;

        *pp = '\0';
        *mp++ = '+';
        if (chptr->mode.mode & MODE_SECRET)      *mp++ = 's';
        if (chptr->mode.mode & MODE_PRIVATE)     *mp++ = 'p';
        if (chptr->mode.mode & MODE_MODERATED)   *mp++ = 'm';
        if (chptr->mode.mode & MODE_TOPICLIMIT)  *mp++ = 't';
        if (chptr->mode.mode & MODE_INVITEONLY)   *mp++ = 'i';
        if (chptr->mode.mode & MODE_NOPRIVMSGS)  *mp++ = 'n';
        if (chptr->mode.mode & MODE_REGISTERED)  *mp++ = 'r';
        if (chptr->mode.mode & MODE_REGONLY)     *mp++ = 'R';
        if (chptr->mode.mode & MODE_NOCTRL)      *mp++ = 'c';
        if (chptr->mode.mode & MODE_OPERONLY)    *mp++ = 'O';
        if (chptr->mode.mode & MODE_MODREG)     *mp++ = 'M';
        if (chptr->mode.mode & MODE_SSLONLY)     *mp++ = 'S';
        if (chptr->mode.mode & MODE_AUDITORIUM)  *mp++ = 'A';
        if (chptr->mode.mode & MODE_PRIVACY)     *mp++ = 'P';
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
        if (chptr->mode.mode & MODE_JOINRATE)
        {
            *mp++ = 'j';
            if (pp != pbuf) *pp++ = ' ';
            ircsprintf(pp, "%d:%d", chptr->mode.jr_num, chptr->mode.jr_time);
            pp += strlen(pp);
        }
        *mp = '\0';

        /* Only emit if there are modes beyond the bare '+' */
        if (mbuf[1])
        {
            EvPayloadChanMode pl;
            memset(&pl, 0, sizeof(pl));
            strncpy(pl.nick, me.name, NICKLEN);
            strncpy(pl.channel, chptr->chname, CHANNELLEN);
            strncpy(pl.modebuf, mbuf, sizeof(pl.modebuf) - 1);
            strncpy(pl.parabuf, pbuf, sizeof(pl.parabuf) - 1);
            burst_send_event(peer, EVT_CHAN_MODE, &pl, sizeof(pl));
        }
    }

    /* 5. Send channel topics */
    for (chptr = channel; chptr; chptr = chptr->nextch)
    {
        if (chptr->topic[0])
        {
            EvPayloadChanTopic pl;
            memset(&pl, 0, sizeof(pl));
            strncpy(pl.channel, chptr->chname, CHANNELLEN);
            strncpy(pl.topic, chptr->topic, TOPICLEN);
            strncpy(pl.setter, chptr->topic_nick, sizeof(pl.setter) - 1);
            pl.ts = chptr->topic_time;
            burst_send_event(peer, EVT_CHAN_TOPIC, &pl, sizeof(pl));
        }
    }

    /* 5. Send active sessions */
    session_burst_to_peer(peer);
}

void
gopeer_start_burst(aClient *cptr)
{
    GossipPeer   *gp = (GossipPeer *)cptr->serv;
    NetworkEvent *buf[256];
    int           n, i;

    if (!gp)
        return;

    /* Send GSYNCING to signal start of burst */
    {
        char sclock[EVENTCLOCK_SPARSE_LEN];
        clock_encode_sparse(&g_event_log.local_clock, sclock, sizeof(sclock));
        sendto_one(cptr, ":%s GSYNCING %s %s",
                   me.name, me.name, sclock);
    }

    /* S6i: full-state burst for fresh peers */
    {
        int is_fresh = 1, slot;
        for (slot = 0; slot < VC_SLOTS; slot++)
            if (gp->peer_clock.slot[slot] != 0) { is_fresh = 0; break; }

        if (is_fresh)
            gopeer_burst_full_state(cptr);
    }

    /* Replay events the peer hasn't seen (catches events during burst) */
    n = get_events_since(&gp->peer_clock, buf, 256);
    for (i = 0; i < n; i++)
        gossip_send_event(cptr, buf[i]);

    /* Mark burst complete from our side */
    sendto_one(cptr, ":%s GSYNCED %s", me.name, me.name);
}

/* Check if an IP address matches any configured gopeer host */
int
gopeer_is_configured_host(const char *ip)
{
    aGoPeerConf *conf;
    for (conf = gopeer_conf_list; conf; conf = conf->next)
    {
        if (conf->host && strcmp(conf->host, ip) == 0)
            return 1;
    }
    return 0;
}

/* Find a gopeer config entry by name */
aGoPeerConf *
gopeer_find_conf(const char *name)
{
    aGoPeerConf *conf;
    for (conf = gopeer_conf_list; conf; conf = conf->next)
    {
        if (conf->name && mycmp(conf->name, (char *)name) == 0)
            return conf;
    }
    return NULL;
}

/* Check if a gossip peer is already connected (by name) */
int
gopeer_is_connected(const char *name)
{
    DLink *lp;
    for (lp = gopeer_list; lp; lp = lp->next)
    {
        aClient *cptr = lp->value.cptr;
        GossipPeer *gp = (GossipPeer *)cptr->serv;
        if (gp && mycmp(gp->name, (char *)name) == 0)
            return 1;
    }
    return 0;
}

void
gopeer_try_connect(void)
{
    aGoPeerConf *conf;
    extern SSL_CTX *server_ssl_ctx;

    for (conf = gopeer_conf_list; conf; conf = conf->next)
    {
        struct sockaddr_in sa4;
        int fd, ret;
        aClient *cptr;

        if (!conf->host || !conf->host[0])
            continue;

        /* Skip if already connected */
        if (gopeer_is_connected(conf->name))
            continue;

        /* Simple IPv4 resolve — use inet_pton for numeric addresses */
        memset(&sa4, 0, sizeof(sa4));
        sa4.sin_family = AF_INET;
        sa4.sin_port   = htons(conf->port);
        if (inet_pton(AF_INET, conf->host, &sa4.sin_addr) != 1)
        {
            /* Non-numeric host — try gethostbyname */
            struct hostent *hp = gethostbyname(conf->host);
            if (!hp || hp->h_addrtype != AF_INET)
            {
                sendto_realops("Gossip: cannot resolve %s", conf->host);
                continue;
            }
            memcpy(&sa4.sin_addr, hp->h_addr_list[0], hp->h_length);
        }

        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
        {
            sendto_realops("Gossip: socket() failed for %s", conf->name);
            continue;
        }

        cptr = make_client(NULL, &me);
        cptr->fd = fd;
        strncpyzt(cptr->name, conf->name, sizeof(cptr->name));
        strncpyzt(cptr->sockhost, conf->host, sizeof(cptr->sockhost));

        set_non_blocking(fd, cptr);
        {
            int opt = 1;
            setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
        }

        ret = connect(fd, (struct sockaddr *)&sa4, sizeof(sa4));

        if (ret < 0 && errno != EINPROGRESS)
        {
            sendto_realops("Gossip: connect() to %s failed: %s",
                           conf->name, strerror(errno));
            close(fd);
            cptr->fd = -2;
            free_client(cptr);
            continue;
        }

        cptr->status = STAT_CONNECTING;
        local[fd] = cptr;
        add_client_to_list(cptr);
        add_fd(fd, FDT_CLIENT, cptr);
        if (fd > highest_fd)
            highest_fd = fd;
        cptr->flags |= FLAGS_BLOCKED;
        set_fd_flags(fd, FDF_WANTREAD|FDF_WANTWRITE);

        /* TLS for outbound gossip peer */
        if (conf->tls && server_ssl_ctx)
        {
            cptr->ssl = SSL_new(server_ssl_ctx);
            if (cptr->ssl)
            {
                SSL_set_fd(cptr->ssl, fd);
                /* Don't set SSL_set_ex_data — gopeer has no aConnect.
                 * ssl_verify_callback handles NULL ex_data gracefully
                 * (accepts self-signed certs unconditionally). */
                SetSSL(cptr);
                cptr->flags |= FLAGS_SSL_OUTBOUND;
                /* TLS handshake is initiated in completed_connection()
                 * after the TCP connect completes (EINPROGRESS → ready). */
            }
        }

        sendto_realops("Gossip: connecting to %s (%s:%d%s)",
                       conf->name, conf->host, conf->port,
                       conf->tls ? " TLS" : "");
    }
}
