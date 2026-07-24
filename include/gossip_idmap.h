/*
 * IRC - Internet Relay Chat, include/gossip_idmap.h
 * Copyright (C) 2024 Bahamut IRC Server Project
 *
 * Issue #260: server identity registry.
 *
 * The canonical gossip identity of a server is its NAME (unique on IRC).
 * Internally, every EventClock slot, dedup key, and ServerId is a DENSE LOCAL
 * INDEX assigned by this registry on first sighting of a name.  Indices are
 * local to this process and never put on the wire — the name is the wire
 * identity — so two servers can never collide the way the old 6-bit FNV-1a
 * hash did.  The only limit is MAX_GOSSIP_SERVERS, and exhausting it fails
 * loudly rather than silently corrupting state.
 */

#ifndef GOSSIP_IDMAP_H
#define GOSSIP_IDMAP_H

#include "gossip_event.h"   /* ServerId, MAX_GOSSIP_SERVERS, SRVIDX_NONE */

/* srvidx_get — map a server name to its local index, allocating one on first
 * sight.  Returns SRVIDX_NONE (and emits a loud snotice) if the table is full. */
ServerId    srvidx_get(const char *name);

/* srvidx_find — like srvidx_get but never allocates; SRVIDX_NONE if unknown. */
ServerId    srvidx_find(const char *name);

/* srvidx_name — reverse lookup: local index -> name.  "" if out of range. */
const char *srvidx_name(ServerId idx);

#endif /* GOSSIP_IDMAP_H */
