/*
 * IRC - Internet Relay Chat, src/gossip_event.c
 * Copyright (C) 2024 Bahamut IRC Server Project
 *
 * Phase S1: Event Foundation — EventLog ring buffer implementation.
 *
 * The EventLog is a fixed-size ring buffer (8192 slots) of NetworkEvent
 * records.  Each event has a globally unique (ServerId, LocalSeq) ID and a
 * causal vector clock.
 *
 * Thread safety: the ircd is single-threaded; no locking is needed.
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#include "struct.h"
#include "common.h"
#include "gossip_event.h"
#include "eventlog.h"
#include "h.h"          /* me.name */

/* -------------------------------------------------------------------------
 * Global singleton
 * ---------------------------------------------------------------------- */

EventLog g_event_log;

/* -------------------------------------------------------------------------
 * Internal helpers
 * ---------------------------------------------------------------------- */

/*
 * fnv1a_6bit — FNV-1a hash of a string, folded to 6 bits (0-63).
 * Used as a development-only ServerId fallback.
 */
static ServerId
fnv1a_6bit(const char *s)
{
    uint32_t h = 2166136261u;
    while (*s)
    {
        h ^= (unsigned char)*s++;
        h *= 16777619u;
    }
    return (ServerId)(h & 0x3F);
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

void
eventlog_init(void)
{
    memset(&g_event_log, 0, sizeof(g_event_log));

    /*
     * Derive ServerId.  In production, this is overridden by
     * "server_id = N;" in the gopeer{} config block.  For development
     * we use a FNV-1a hash of the server name.
     */
    g_event_log.my_id   = fnv1a_6bit(me.name);
    g_event_log.next_seq = 1;

    fprintf(stderr, " - EventLog initialised: server_id=%u name=%s"
                    " (ring=%d slots)\n",
            (unsigned)g_event_log.my_id, me.name, EVENT_LOG_SIZE);
}

NetworkEvent *
emit_event(NetEventType type, const void *payload, size_t payload_size)
{
    EventLog    *el  = &g_event_log;
    NetworkEvent *ev = &el->ring[el->head & (EVENT_LOG_SIZE - 1)];

    /* Assign identity */
    ev->id.server  = el->my_id;
    ev->id.seq     = el->next_seq++;

    /* Advance our own slot in the vector clock */
    el->local_clock.slot[el->my_id] = ev->id.seq;

    /* Snapshot the clock into the event */
    memcpy(&ev->clock, &el->local_clock, sizeof(EventClock));

    ev->wall_time = time(NULL);
    ev->type      = type;
    ev->next      = NULL;

    /* Copy payload */
    if (payload && payload_size > 0)
    {
        if (payload_size > sizeof(ev->payload))
            payload_size = sizeof(ev->payload);
        memcpy(&ev->payload, payload, payload_size);
    }
    else
    {
        memset(&ev->payload, 0, sizeof(ev->payload));
    }

    /* Advance ring head */
    el->head++;
    if (el->count < EVENT_LOG_SIZE)
        el->count++;

    return ev;
}

int
get_events_since(const EventClock *clock, NetworkEvent **out, int max_out)
{
    EventLog *el = &g_event_log;
    int       n  = 0;
    uint32_t  i;

    /* Walk the ring from oldest to newest */
    uint32_t start = (el->count < EVENT_LOG_SIZE)
                     ? 0
                     : (el->head & (EVENT_LOG_SIZE - 1));

    for (i = 0; i < el->count && n < max_out; i++)
    {
        uint32_t  idx = (start + i) & (EVENT_LOG_SIZE - 1);
        NetworkEvent *ev = &el->ring[idx];

        /* Include event if receiver hasn't seen this seq from this server */
        if (ev->id.seq > clock->slot[ev->id.server])
            out[n++] = ev;
    }

    return n;
}

void
clock_advance(const EventClock *remote)
{
    EventClock *local = &g_event_log.local_clock;
    int i;

    for (i = 0; i < VC_SLOTS; i++)
    {
        if (remote->slot[i] > local->slot[i])
            local->slot[i] = remote->slot[i];
    }
}

/* -------------------------------------------------------------------------
 * Base-64 clock serialisation
 *
 * We use the standard RFC 4648 alphabet.  Each 3-byte group → 4 chars.
 * 512 bytes raw → 684 base-64 chars + NUL.
 * ---------------------------------------------------------------------- */

static const char b64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const signed char b64_dec[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 0x00-0x0F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 0x10-0x1F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,  /* 0x20-0x2F */
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,  /* 0x30-0x3F */
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14, /* 0x40-0x4F */
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,  /* 0x50-0x5F */
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40, /* 0x60-0x6F */
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,  /* 0x70-0x7F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 0x80-0x8F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 0x90-0x9F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 0xA0-0xAF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 0xB0-0xBF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 0xC0-0xCF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 0xD0-0xDF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 0xE0-0xEF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 0xF0-0xFF */
};

void
clock_encode_b64(const EventClock *clock, char *buf, int buflen)
{
    const unsigned char *src = (const unsigned char *)clock->slot;
    int                  slen = VC_SLOTS * 8;  /* 512 bytes */
    int                  i    = 0;
    int                  o    = 0;

    while (i < slen && o + 4 < buflen - 1)
    {
        unsigned int b0 = src[i++];
        unsigned int b1 = (i < slen) ? src[i++] : 0;
        unsigned int b2 = (i < slen) ? src[i++] : 0;

        buf[o++] = b64_chars[(b0 >> 2) & 0x3F];
        buf[o++] = b64_chars[((b0 & 0x03) << 4) | ((b1 >> 4) & 0x0F)];
        buf[o++] = b64_chars[((b1 & 0x0F) << 2) | ((b2 >> 6) & 0x03)];
        buf[o++] = b64_chars[b2 & 0x3F];
    }
    buf[o] = '\0';
}

int
clock_decode_b64(EventClock *clock, const char *buf)
{
    unsigned char *dst = (unsigned char *)clock->slot;
    int            dlen = VC_SLOTS * 8;  /* 512 bytes */
    int            i    = 0;
    int            o    = 0;

    memset(clock, 0, sizeof(*clock));

    while (buf[i] && buf[i+1] && buf[i+2] && buf[i+3] && o + 2 < dlen)
    {
        signed char c0 = b64_dec[(unsigned char)buf[i++]];
        signed char c1 = b64_dec[(unsigned char)buf[i++]];
        signed char c2 = b64_dec[(unsigned char)buf[i++]];
        signed char c3 = b64_dec[(unsigned char)buf[i++]];

        if (c0 < 0 || c1 < 0 || c2 < 0 || c3 < 0)
            return -1;

        dst[o++] = (unsigned char)((c0 << 2) | (c1 >> 4));
        if (o < dlen) dst[o++] = (unsigned char)((c1 << 4) | (c2 >> 2));
        if (o < dlen) dst[o++] = (unsigned char)((c2 << 6) | c3);
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * Sparse clock encoding — only non-zero slots
 *
 * Format: "slot.seq,slot.seq,..."  or  "0" for all-zero clock.
 * ---------------------------------------------------------------------- */

void
clock_encode_sparse(const EventClock *clock, char *buf, int buflen)
{
    int i, pos = 0;

    for (i = 0; i < VC_SLOTS && pos < buflen - 25; i++)
    {
        if (clock->slot[i] == 0)
            continue;
        if (pos > 0 && pos < buflen - 1)
            buf[pos++] = ',';
        pos += snprintf(buf + pos, buflen - pos, "%d.%llu",
                        i, (unsigned long long)clock->slot[i]);
    }

    if (pos == 0)
    {
        buf[0] = '0';
        pos = 1;
    }
    buf[pos] = '\0';
}

int
clock_decode_sparse(EventClock *clock, const char *buf)
{
    const char *p;
    char       *dot;
    char        tmp[EVENTCLOCK_SPARSE_LEN];

    memset(clock, 0, sizeof(*clock));

    if (!buf || !*buf || (buf[0] == '0' && (buf[1] == '\0' || buf[1] == ',')))
        return 0;

    strncpy(tmp, buf, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    /* Walk comma-separated entries: "slot.seq" */
    {
        char *save = NULL;
        char *tok;
        for (tok = strtoken(&save, tmp, ","); tok; tok = strtoken(&save, NULL, ","))
        {
            dot = strchr(tok, '.');
            if (!dot)
                continue;
            *dot = '\0';
            {
                int      slot = atoi(tok);
                uint64_t seq  = (uint64_t)strtoull(dot + 1, NULL, 10);
                if (slot >= 0 && slot < VC_SLOTS)
                    clock->slot[slot] = seq;
            }
        }
    }
    return 0;
}
