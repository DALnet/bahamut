/*
 * IRC - Internet Relay Chat, src/gossip_dedup.c
 * Copyright (C) 2024 Bahamut IRC Server Project
 *
 * Phase S2: Gossip Multi-Uplink — exact event deduplication hash table.
 *
 * 65536-slot open-addressing hash table.  Probing: linear.
 * Key: (ServerId, LocalSeq).  No false positives.
 *
 * Hash: fold (server * 2654435761u) XOR (uint32_t)(seq ^ seq>>32) to 16 bits.
 */

#include <string.h>
#include <stdint.h>

#include "gossip_dedup.h"

DedupTable g_dedup_table;

void
dedup_init(void)
{
    memset(&g_dedup_table, 0, sizeof(g_dedup_table));
}

static uint32_t
dedup_hash(ServerId server, LocalSeq seq)
{
    uint32_t h = (uint32_t)server * 2654435761u;
    h ^= (uint32_t)(seq ^ (seq >> 32));
    return h & DEDUP_MASK;
}

int
dedup_check_and_set(ServerId server, LocalSeq seq)
{
    uint32_t idx = dedup_hash(server, seq);
    uint32_t i;

    /* Linear probe */
    for (i = 0; i < DEDUP_TABLE_SIZE; i++)
    {
        uint32_t    slot = (idx + i) & DEDUP_MASK;
        DedupEntry *e    = &g_dedup_table.slots[slot];

        if (!e->occupied)
        {
            /* Empty slot — event is new; insert */
            e->server   = server;
            e->seq      = seq;
            e->occupied = 1;
            g_dedup_table.count++;
            return 0;
        }

        if (e->server == server && e->seq == seq)
            return 1;   /* duplicate */
    }

    /*
     * Table completely full (65536 events without reset).
     * Evict the slot at hash position (oldest-ish entry).
     * This is safe: worst case we re-process an event harmlessly.
     */
    {
        DedupEntry *e = &g_dedup_table.slots[idx];
        e->server   = server;
        e->seq      = seq;
        e->occupied = 1;
    }
    return 0;
}

void
dedup_reset(void)
{
    memset(&g_dedup_table, 0, sizeof(g_dedup_table));
}
