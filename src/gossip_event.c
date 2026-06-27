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
#include "gossip_idmap.h"
#include "eventlog.h"
#include "h.h"          /* me.name */

/* -------------------------------------------------------------------------
 * Global singleton
 * ---------------------------------------------------------------------- */

EventLog g_event_log;

/* -------------------------------------------------------------------------
 * Internal helpers
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

void
eventlog_init(void)
{
    memset(&g_event_log, 0, sizeof(g_event_log));

    /*
     * Our gossip identity is our NAME; the local index registry assigns it
     * slot 0 here (we are the first server it sees).  The name — not this
     * index — is what travels on the wire (issue #260), so it cannot collide
     * with another server the way the old 6-bit FNV-1a hash could.
     */
    g_event_log.my_id   = srvidx_get(me.name);
    g_event_log.next_seq = 1;

    fprintf(stderr, " - EventLog initialised: server=%s idx=%u"
                    " (ring=%d slots)\n",
            me.name, (unsigned)g_event_log.my_id, EVENT_LOG_SIZE);
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
 * Sparse clock encoding — only non-zero slots, NAME-keyed (issue #260)
 *
 * Wire format: "name:seq,name:seq,..."  or  "0" for an all-zero clock.
 * The slot index is local to each server, so each entry carries the server
 * NAME (resolved via the index registry); the receiver maps it back to its
 * own local index.  Server names contain no ':' or ',', so the format is
 * unambiguous.  (A clock with very many non-zero slots can exceed the IRC
 * line limit — that is issue #261; in practice the clock is sparse, with only
 * a handful of non-zero slots since the ring is dominated by our own id.)
 * ---------------------------------------------------------------------- */

void
clock_encode_sparse(const EventClock *clock, char *buf, int buflen)
{
    int i, pos = 0;

    for (i = 0; i < MAX_GOSSIP_SERVERS; i++)
    {
        const char *name;

        if (clock->slot[i] == 0)
            continue;
        name = srvidx_name((ServerId)i);
        if (!name[0])
            continue;                          /* unknown index — skip */
        /* need room for ",name:seq" + NUL; stop cleanly if near the end */
        if (pos + (int)strlen(name) + 24 >= buflen)
            break;
        if (pos > 0)
            buf[pos++] = ',';
        pos += snprintf(buf + pos, buflen - pos, "%s:%llu",
                        name, (unsigned long long)clock->slot[i]);
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
    char  tmp[EVENTCLOCK_SPARSE_LEN];
    char *save = NULL;
    char *tok;

    memset(clock, 0, sizeof(*clock));

    if (!buf || !*buf || (buf[0] == '0' && (buf[1] == '\0' || buf[1] == ',')))
        return 0;

    strncpy(tmp, buf, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    /* Walk comma-separated "name:seq" entries (names have no ':' or ','). */
    for (tok = strtoken(&save, tmp, ","); tok; tok = strtoken(&save, NULL, ","))
    {
        char    *colon = strchr(tok, ':');
        ServerId idx;
        uint64_t seq;

        if (!colon)
            continue;
        *colon = '\0';
        idx = srvidx_get(tok);                 /* allocate a local slot if new */
        if (idx == SRVIDX_NONE || idx >= MAX_GOSSIP_SERVERS)
            continue;                          /* table full — already logged */
        seq = (uint64_t)strtoull(colon + 1, NULL, 10);
        clock->slot[idx] = seq;
    }
    return 0;
}
