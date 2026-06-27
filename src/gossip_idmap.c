/*
 * IRC - Internet Relay Chat, src/gossip_idmap.c
 * Copyright (C) 2024 Bahamut IRC Server Project
 *
 * Issue #260: server identity registry — name <-> dense local index.
 *
 * Replaces the old 6-bit FNV-1a ServerId (only 64 values, silent birthday
 * collisions that conflated two servers' (server, seq) and corrupted dedup +
 * clock reconciliation).  The server NAME is now the canonical identity; this
 * table assigns each name a dense local index used to key the EventClock, the
 * dedup table, and my_id.  Indices never appear on the wire.
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "send.h"        /* sendto_realops */
#include "gossip_event.h"
#include "gossip_idmap.h"

static char srvidx_names[MAX_GOSSIP_SERVERS][HOSTLEN + 1];
static int  srvidx_count = 0;

ServerId
srvidx_find(const char *name)
{
    int i;

    if (!name || !*name)
        return SRVIDX_NONE;
    for (i = 0; i < srvidx_count; i++)
        if (mycmp(srvidx_names[i], (char *)name) == 0)
            return (ServerId)i;
    return SRVIDX_NONE;
}

ServerId
srvidx_get(const char *name)
{
    ServerId idx;

    if (!name || !*name)
        return SRVIDX_NONE;

    idx = srvidx_find(name);
    if (idx != SRVIDX_NONE)
        return idx;

    if (srvidx_count >= MAX_GOSSIP_SERVERS)
    {
        /* Loud, never silent — this is the failure the 6-bit hash hid. */
        sendto_realops("Gossip: server-index table full (%d entries) — cannot "
                       "track %s; raise MAX_GOSSIP_SERVERS", MAX_GOSSIP_SERVERS,
                       name);
        return SRVIDX_NONE;
    }

    strncpyzt(srvidx_names[srvidx_count], (char *)name, HOSTLEN + 1);
    return (ServerId)srvidx_count++;
}

const char *
srvidx_name(ServerId idx)
{
    if (idx < (ServerId)srvidx_count)
        return srvidx_names[idx];
    return "";
}
