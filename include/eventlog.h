/*
 * IRC - Internet Relay Chat, include/eventlog.h
 * Copyright (C) 2024 Bahamut IRC Server Project
 *
 * Phase S1: Event Foundation — EventLog API.
 *
 * All functions are defined in src/gossip_event.c.
 */

#ifndef EVENTLOG_H
#define EVENTLOG_H

#include "gossip_event.h"

/*
 * eventlog_init — initialise the EventLog singleton.
 *
 * Reads server_id from the gossip{} config block if present, otherwise
 * derives a 6-bit FNV-1a hash of me.name as a development fallback.
 * Must be called after initconf() so me.name is available.
 */
void eventlog_init(void);

/*
 * emit_event — record an event in the ring buffer.
 *
 * Assigns the next (server, seq) EventId, advances the local vector clock,
 * and writes the event into the ring.  If the ring is full the oldest
 * entry is overwritten (head wraps).
 *
 * Returns a pointer to the stored event (valid until overwritten).
 * The pointer MUST NOT be stored persistently; it is only valid until the
 * next call that would wrap the ring past this slot.
 */
NetworkEvent *emit_event(NetEventType type, const void *payload, size_t payload_size);

/*
 * get_events_since — retrieve events newer than the given clock.
 *
 * Fills 'out' with up to 'max_out' pointers to events in the ring whose
 * id.seq is greater than clock->slot[id.server].  Events are returned
 * in ascending seq order.  Returns the number of events written.
 *
 * This is used during gossip burst to re-send missing events to a peer.
 */
int get_events_since(const EventClock *clock, NetworkEvent **out, int max_out);

/*
 * clock_advance — merge a remote clock into our local clock.
 *
 * For each slot i, sets local_clock.slot[i] = max(local, remote).
 * Call this when receiving a GACK or GSYNCED message.
 */
void clock_advance(const EventClock *remote);

/*
 * clock_encode_b64 / clock_decode_b64 — compact base-64 serialisation.
 *
 * Each slot is 8 bytes; 64 slots = 512 bytes raw → ~684 chars base64.
 * buf must be at least EVENTCLOCK_B64_LEN bytes.
 *
 * WARNING: base64 encoding exceeds BUFSIZE (512).  Use the sparse
 * encoding below for data transmitted over the IRC protocol.
 */
#define EVENTCLOCK_B64_LEN  700   /* safe upper bound */

void clock_encode_b64(const EventClock *clock, char *buf, int buflen);
int  clock_decode_b64(EventClock *clock, const char *buf);

/*
 * clock_encode_sparse / clock_decode_sparse — sparse decimal encoding.
 *
 * Only non-zero slots are emitted: "slot.seq,slot.seq,...".
 * An all-zero clock is encoded as "0".
 *
 * This fits comfortably within BUFSIZE for typical cluster sizes
 * (up to ~15 active servers).
 */
#define EVENTCLOCK_SPARSE_LEN  400  /* safe upper bound for ~15 servers */

void clock_encode_sparse(const EventClock *clock, char *buf, int buflen);
int  clock_decode_sparse(EventClock *clock, const char *buf);

#endif /* EVENTLOG_H */
