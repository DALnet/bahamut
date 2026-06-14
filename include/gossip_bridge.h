/*
 * IRC - Internet Relay Chat, include/gossip_bridge.h
 * Copyright (C) 2024 Bahamut IRC Server Project
 *
 * Phase S3: Legacy Bridge — translate gossip events to TS5 IRC commands
 * and synthesise gossip state during legacy server bursts.
 *
 * The bridge is transparent: any gossip-capable Bahamut that also has
 * legacy C/N lines loaded m_legacy_bridge.c will automatically translate
 * between the two protocols.
 */

#ifndef GOSSIP_BRIDGE_H
#define GOSSIP_BRIDGE_H

#include "gossip_event.h"

/*
 * bridge_introduce_server — tell all legacy servers about a newly connected
 * gossip peer.  Called from ms_ghello() when a direct gopeer link comes up.
 * Does nothing if no legacy servers are connected.
 */
void bridge_introduce_server(const char *name);

/*
 * bridge_split_server — tell all legacy servers that a gossip peer has
 * disconnected.  Called from gopeer_handle_disconnect() before cleanup.
 */
void bridge_split_server(const char *name);

/*
 * bridge_apply_event — translate one inbound gossip event to legacy IRC
 * commands and send them to all connected legacy servers via
 * sendto_serv_butone(NULL, ...).
 *
 * Called from ms_gevent() in m_gossip.c after dedup and apply.
 * Never called for events originating locally (those are already sent
 * to legacy servers via the normal command handlers).
 */
void bridge_apply_event(const NetworkEvent *ev);

/*
 * bridge_burst_gossip_to_server — synthesise the current gossip state
 * (servers, users, channel memberships) and send it to a specific legacy
 * server that is completing its burst handshake.
 *
 * Called from the CHOOK_SENDBURST handler in m_legacy_bridge.c.
 * Skips users/servers that originated locally (already sent via normal burst).
 */
void bridge_burst_gossip_to_server(aClient *cptr);

#endif /* GOSSIP_BRIDGE_H */
