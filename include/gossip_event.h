/*
 * IRC - Internet Relay Chat, include/gossip_event.h
 * Copyright (C) 2024 Bahamut IRC Server Project
 *
 * Phase S1: Event Foundation — type definitions for the gossip event log.
 *
 * An immutable NetworkEvent is created for every state change.  Events have
 * a globally unique (ServerId, LocalSeq) identifier and a vector clock for
 * causal ordering.  They accumulate in the EventLog ring buffer.
 */

#ifndef GOSSIP_EVENT_H
#define GOSSIP_EVENT_H

#include <stdint.h>
#include <time.h>

#include "struct.h"   /* NICKLEN, USERLEN, HOSTLEN, CHANNELLEN, REALLEN,
                       * TOPICLEN, aClient, aChannel */

/* -------------------------------------------------------------------------
 * Identifier types
 * ---------------------------------------------------------------------- */

/* ServerId: 0-63.  Assigned explicitly in gopeer{} config.
 * 6 bits is sufficient for 64 servers; the FNV-1a hash is a dev fallback. */
typedef uint8_t  ServerId;

/* LocalSeq: monotonically increasing per-server event counter. */
typedef uint64_t LocalSeq;

/* EventId: globally unique event identifier. */
typedef struct EventId {
    ServerId server;   /* which server originated this event */
    LocalSeq seq;      /* sequence number on that server     */
} EventId;

/* -------------------------------------------------------------------------
 * Vector clock
 * ---------------------------------------------------------------------- */

#define VC_SLOTS 64   /* must equal max number of servers */

/* EventClock: causal vector clock.
 * slot[i] = highest LocalSeq from server i that we have processed.
 * 64 × 8 = 512 bytes — fits two cache lines. */
typedef struct EventClock {
    LocalSeq slot[VC_SLOTS];
} EventClock;

/* -------------------------------------------------------------------------
 * Event types
 * ---------------------------------------------------------------------- */

typedef enum NetEventType {
    /* User lifecycle */
    EVT_USER_JOIN    = 1,   /* user connects and registers */
    EVT_USER_QUIT    = 2,   /* user disconnects (or is killed) */
    EVT_USER_NICK    = 3,   /* user changes nick */
    EVT_USER_MODE    = 4,   /* user mode change */
    EVT_USER_AWAY    = 5,   /* user sets or clears away */

    /* Channel activity */
    EVT_CHAN_JOIN    = 6,   /* user joins a channel */
    EVT_CHAN_PART    = 7,   /* user parts a channel */
    EVT_CHAN_KICK    = 8,   /* user is kicked from a channel */
    EVT_CHAN_MODE    = 9,   /* channel mode change */
    EVT_CHAN_TOPIC   = 10,  /* channel topic change */

    /* Server topology */
    EVT_SERVER_LINK  = 11,  /* new gossip peer established */
    EVT_SERVER_SPLIT = 12,  /* gossip peer disconnected */

    /* Persistent sessions (Phase S4) */
    EVT_SESSION_CREATE  = 20,
    EVT_SESSION_DESTROY = 21,

} NetEventType;

/* -------------------------------------------------------------------------
 * Per-event payload structs
 * ---------------------------------------------------------------------- */

typedef struct EvPayloadUserJoin {
    char nick[NICKLEN + 1];
    char username[USERLEN + 1];
    char host[HOSTLEN + 1];
    char realname[REALLEN + 1];
    char server[HOSTLEN + 1];
    unsigned long umode;
    time_t ts;
} EvPayloadUserJoin;

typedef struct EvPayloadUserQuit {
    char nick[NICKLEN + 1];
    char reason[512];
} EvPayloadUserQuit;

typedef struct EvPayloadUserNick {
    char oldnick[NICKLEN + 1];
    char newnick[NICKLEN + 1];
    time_t ts;
} EvPayloadUserNick;

typedef struct EvPayloadUserMode {
    char nick[NICKLEN + 1];
    unsigned long old_umode;
    unsigned long new_umode;
} EvPayloadUserMode;

typedef struct EvPayloadUserAway {
    char nick[NICKLEN + 1];
    int  setting;              /* 1 = away, 0 = back */
    char message[TOPICLEN + 1];
} EvPayloadUserAway;

typedef struct EvPayloadChanJoin {
    char nick[NICKLEN + 1];
    char channel[CHANNELLEN + 1];
    int  flags;                /* CHFL_CHANOP | CHFL_VOICE etc. */
    time_t ts;
} EvPayloadChanJoin;

typedef struct EvPayloadChanPart {
    char nick[NICKLEN + 1];
    char channel[CHANNELLEN + 1];
    char reason[512];
} EvPayloadChanPart;

typedef struct EvPayloadChanKick {
    char kicker[NICKLEN + 1];
    char target[NICKLEN + 1];
    char channel[CHANNELLEN + 1];
    char reason[512];
} EvPayloadChanKick;

typedef struct EvPayloadChanMode {
    char nick[NICKLEN + 1];
    char channel[CHANNELLEN + 1];
    char modebuf[64];
    char parabuf[256];
} EvPayloadChanMode;

typedef struct EvPayloadChanTopic {
    char nick[NICKLEN + 1];
    char channel[CHANNELLEN + 1];
    char topic[TOPICLEN + 1];
    char setter[NICKLEN + USERLEN + HOSTLEN + 3];
    time_t ts;
} EvPayloadChanTopic;

typedef struct EvPayloadServerLink {
    char name[HOSTLEN + 1];
    ServerId id;
} EvPayloadServerLink;

/* Session token length (hex chars, not counting NUL). */
#define SESSION_KEY_LEN 32

typedef struct EvPayloadSessionCreate {
    char          key[SESSION_KEY_LEN + 1];
    char          nick[NICKLEN + 1];
    char          username[USERLEN + 1];
    char          host[HOSTLEN + 1];
    char          realname[REALLEN + 1];
    unsigned long umode;
    char          away_msg[TOPICLEN + 1];
    time_t        expires_at;
} EvPayloadSessionCreate;

typedef struct EvPayloadSessionDestroy {
    char key[SESSION_KEY_LEN + 1];
} EvPayloadSessionDestroy;

/* -------------------------------------------------------------------------
 * The immutable event record
 * ---------------------------------------------------------------------- */

typedef struct NetworkEvent {
    EventId      id;
    EventClock   clock;
    time_t       wall_time;
    NetEventType type;
    union {
        EvPayloadUserJoin       user_join;
        EvPayloadUserQuit       user_quit;
        EvPayloadUserNick       user_nick;
        EvPayloadUserMode       user_mode;
        EvPayloadUserAway       user_away;
        EvPayloadChanJoin       chan_join;
        EvPayloadChanPart       chan_part;
        EvPayloadChanKick       chan_kick;
        EvPayloadChanMode       chan_mode;
        EvPayloadChanTopic      chan_topic;
        EvPayloadServerLink     server_link;
        EvPayloadSessionCreate  session_create;
        EvPayloadSessionDestroy session_destroy;
    } payload;
    /* per-record version for services events (0 for non-versioned) */
    uint64_t record_version;
    /* ring linkage — not serialised over the wire */
    struct NetworkEvent *next;
} NetworkEvent;

/* -------------------------------------------------------------------------
 * EventLog — bounded ring buffer (global singleton)
 * ---------------------------------------------------------------------- */

#define EVENT_LOG_SIZE 8192   /* power of 2; holds hours of traffic */

typedef struct EventLog {
    NetworkEvent ring[EVENT_LOG_SIZE];
    uint32_t     head;       /* index of next slot to write        */
    uint32_t     count;      /* number of valid entries            */
    LocalSeq     next_seq;   /* next sequence number to assign     */
    EventClock   local_clock; /* our own vector clock               */
    ServerId     my_id;      /* this server's ServerId             */
} EventLog;

extern EventLog g_event_log;

#endif /* GOSSIP_EVENT_H */
