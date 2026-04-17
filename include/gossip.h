/*
 * IRC - Internet Relay Chat, include/gossip.h
 * Copyright (C) 2024 Bahamut IRC Server Project
 *
 * Phase S2: Gossip Multi-Uplink — fanout propagation API.
 */

#ifndef GOSSIP_H
#define GOSSIP_H

#include "gossip_event.h"
#include "gossip_peer.h"

/*
 * gossip_event — propagate a NetworkEvent to GOSSIP_FANOUT peers.
 *
 * Selects min(fanout, n_peers-1) peers by rank-permutation on ev->id.seq.
 * This pseudo-random selection is deterministic but varies per message so
 * load spreads across links.  Skips non-burst_complete peers and exclude_link.
 * Serialises the event to wire format using the MsgBuf/send infrastructure.
 *
 * exclude_link: the peer we received this event from (to avoid echo); NULL if
 * we originated the event.
 */
void gossip_event(const NetworkEvent *ev, aClient *exclude_link);

/*
 * gossip_send_event — serialise one event to one peer.
 * Called internally by gossip_event(); also used by burst code.
 *
 * Wire format:
 *   @gossip-id=<server>:<seq>;gossip-clock=<b64clock> :<me.name> GEVENT <type> :<payload>
 */
void gossip_send_event(aClient *peer, const NetworkEvent *ev);

/*
 * gossip_parse_event — deserialise a GEVENT payload string into a NetworkEvent.
 * Returns 0 on success, -1 on parse error.
 */
int gossip_parse_event(NetworkEvent *ev, NetEventType type, const char *payload,
                       ServerId origin_id, LocalSeq origin_seq,
                       const EventClock *clock);

/*
 * gossip_apply_event — apply a received event to local state.
 * Called after dedup_check_and_set() confirms the event is new.
 * Does NOT call gossip_event() — the caller does that after apply.
 */
void gossip_apply_event(const NetworkEvent *ev);

/*
 * gossip_split_server — remove all materialized users/channels for a server.
 * Called from gopeer_handle_disconnect() when a gossip peer disconnects.
 */
void gossip_split_server(const char *name);

/*
 * gossip_emit_user_quit — emit EVT_USER_QUIT for a user and propagate to peers.
 * Used when a gossip-materialized user is killed (m_kill), since the normal
 * SIGNOFF hook skips gossip-materialized users to prevent loops.
 */
void gossip_emit_user_quit(const char *nick, const char *reason);

/*
 * gossip_emit_event — emit any event type and propagate to gossip peers.
 * Generic helper for code that needs to emit events directly (e.g., AKILL).
 */
void gossip_emit_event(int type, void *payload, size_t len);

/*
 * gossip_init — initialise gossip subsystem.
 * Called from ircd.c after eventlog_init().
 */
void gossip_init(void);

#endif /* GOSSIP_H */
