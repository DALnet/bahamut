/*
 * IRC - Internet Relay Chat, include/gossip_dedup.h
 * Copyright (C) 2024 Bahamut IRC Server Project
 *
 * Phase S2: Gossip Multi-Uplink — exact event deduplication.
 *
 * 65536-slot open-addressing hash table keyed on EventId.
 * No false positives.  Hash: (server * 2654435761u) ^ (uint32_t)(seq ^ seq>>32)
 * folded to 65535.
 */

#ifndef GOSSIP_DEDUP_H
#define GOSSIP_DEDUP_H

#include "gossip_event.h"

#define DEDUP_TABLE_SIZE 65536   /* must be a power of 2 */
#define DEDUP_MASK       (DEDUP_TABLE_SIZE - 1)

typedef struct DedupEntry {
    ServerId server;
    LocalSeq seq;
    int      occupied;   /* 1 if this slot has a valid entry */
} DedupEntry;

typedef struct DedupTable {
    DedupEntry slots[DEDUP_TABLE_SIZE];
    uint32_t   count;    /* number of occupied slots */
} DedupTable;

extern DedupTable g_dedup_table;

/* dedup_init — zero the global dedup table */
void dedup_init(void);

/*
 * dedup_check_and_set — returns 1 if the event has been seen before
 * (duplicate), 0 if it is new (and inserts it into the table).
 */
int dedup_check_and_set(ServerId server, LocalSeq seq);

/*
 * dedup_reset — clear all entries (e.g. after a full sync).
 * Normally not needed; the table wraps gracefully.
 */
void dedup_reset(void);

#endif /* GOSSIP_DEDUP_H */
