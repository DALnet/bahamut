/*
 * IRC - Internet Relay Chat, include/gossip_peer.h
 * Copyright (C) 2024 Bahamut IRC Server Project
 *
 * Phase S2: Gossip Multi-Uplink — per-link gossip state.
 */

#ifndef GOSSIP_PEER_H
#define GOSSIP_PEER_H

#include "gossip_event.h"
#include "struct.h"

/* -------------------------------------------------------------------------
 * GossipPeer — per-link gossip state attached to a STAT_GOPEER aClient.
 *
 * Stored via (GossipPeer *)aClient.serv when IsGoPeer(cptr).
 * This reuses the aClient.serv pointer without changing aClient layout.
 * ---------------------------------------------------------------------- */

/* Bloom filter size for per-link fast dedup (probabilistic pre-filter).
 * 8192 bytes = 65536 bits → ~1% false-positive rate at 500 events.
 * False positives are safe (we just re-process); false negatives are
 * prevented by the exact dedup hash. */
#define GOPEER_BLOOM_BYTES  8192

typedef struct GossipPeer {
    char       name[HOSTLEN + 1];    /* remote server name               */
    ServerId   peer_id;              /* remote server's ServerId         */
    EventClock peer_clock;           /* last clock ACKed by this peer    */
    EventClock sent_clock;           /* clock of events we have sent     */
    int        burst_complete;       /* 1 after GSYNCED received         */
    uint8_t    seen_bloom[GOPEER_BLOOM_BYTES]; /* per-link bloom filter  */
    uint32_t   bloom_generation;     /* incremented on bloom reset       */
    time_t     last_ping;            /* time of last GPING sent          */
    time_t     connected_at;         /* when this link was established   */
} GossipPeer;

/* Global list of active gossip peer connections */
extern DLink *gopeer_list;

/* Global gossip configuration (fanout, sync_window) */
extern int gossip_fanout;
extern int gossip_sync_window;

/* Global list of configured (but potentially not yet connected) peers */
extern aGoPeerConf *gopeer_conf_list;

/* Partition detection counters (CODERS-33) */
extern int gopeer_configured_count;
extern int gopeer_connected_count;

/* -------------------------------------------------------------------------
 * Gossip peer lifecycle API (src/s_gopeer.c)
 * ---------------------------------------------------------------------- */

/*
 * gopeer_attach — attach a GossipPeer to a freshly negotiated aClient.
 * Allocates GossipPeer, sets cptr->serv = (aServer *)gp, adds to gopeer_list.
 */
GossipPeer *gopeer_attach(aClient *cptr, ServerId peer_id, const char *name);

/*
 * gopeer_handle_disconnect — clean up when a gopeer link drops.
 * Removes from gopeer_list, emits EVT_SERVER_SPLIT.  Does NOT call
 * exit_one_server() — that cascading behaviour is exactly what we avoid.
 */
void gopeer_handle_disconnect(aClient *cptr);

/*
 * gopeer_start_burst — send our state to a newly connected peer.
 * Replays events from the event log that the peer hasn't seen yet.
 */
void gopeer_start_burst(aClient *cptr);

/*
 * gopeer_is_configured_host — check if an IP matches any gopeer config host.
 * Used to exempt gopeer connections from connection throttle.
 */
int gopeer_is_configured_host(const char *ip);

/*
 * gopeer_is_connected — check if a gossip peer is already connected by name.
 * Used to prevent duplicate connections.
 */
int gopeer_is_connected(const char *name);

/*
 * gopeer_find_conf — find a gopeer config entry by server name.
 * Returns NULL if not found.
 */
aGoPeerConf *gopeer_find_conf(const char *name);

/*
 * gopeer_try_connect — attempt outbound connections to all configured peers.
 * Called from the periodic 10-second timer.
 */
void gopeer_try_connect(void);

/*
 * gopeer_count_configured — count gopeer_conf_list entries.
 * Called after config parse to set gopeer_configured_count.
 */
void gopeer_count_configured(void);

/*
 * gopeer_set_start_time — record startup time for grace period.
 * Called from gossip_init().
 */
void gopeer_set_start_time(void);

/*
 * gossip_is_partitioned — returns 1 if this server has gossip peers
 * configured but none connected (and grace period has expired).
 * Used to gate services mutations when partitioned.
 */
int gossip_is_partitioned(void);

#endif /* GOSSIP_PEER_H */
