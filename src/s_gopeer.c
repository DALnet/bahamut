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
#include "fds.h"

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

    /* Phase S3: notify legacy servers that this gossip peer is gone */
    bridge_split_server(gp->name);

    /* Remove from gopeer list */
    remove_from_list(&gopeer_list, cptr, NULL);

    /* Free GossipPeer */
    MyFree(gp);
    cptr->serv = NULL;

    /* NOTE: We intentionally do NOT call exit_one_server() here.
     * Users reachable through gossip peers are NOT in the spanning tree.
     * Their presence is maintained by the event log, not link topology.
     * No cascading QUITs — that is the whole point. */
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

    /* Replay events the peer hasn't seen */
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
                SetSSL(cptr);
            }
        }

        sendto_realops("Gossip: connecting to %s (%s:%d%s)",
                       conf->name, conf->host, conf->port,
                       conf->tls ? " TLS" : "");
    }
}
