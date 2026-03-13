/*
 * IRC - Internet Relay Chat, include/session.h
 * Copyright (C) 2024 Bahamut IRC Server Project
 *
 * Phase S4: Persistent sessions.
 *
 * A Session is created when a local client disconnects.  It preserves
 * identity and (for local sessions) channel membership and pending
 * messages.  Clients can RESUME a session within SESSION_TIMEOUT seconds.
 *
 * Sessions are gossiped as EVT_SESSION_CREATE / EVT_SESSION_DESTROY so
 * that any server on the mesh can accept a RESUME command.  Remote
 * sessions carry identity only (no channel or message data).
 */

#ifndef SESSION_H
#define SESSION_H

#include <time.h>
#include "gossip_event.h"   /* SESSION_KEY_LEN, structs shared with gossip */

/* -------------------------------------------------------------------------
 * Tunables
 * ---------------------------------------------------------------------- */

#define SESSION_TIMEOUT    300   /* seconds until an unclaimed session expires */
#define SESSION_MAX        512   /* pre-allocated slab — hard upper bound      */
#define SESSION_HASH      1024   /* hash table buckets (must be power of 2)    */
#define SESSION_MAX_CHANS   20   /* channels stored per local session          */
#define SESSION_MAX_MSGS    20   /* pending-message ring size                  */

/* -------------------------------------------------------------------------
 * Embedded data types
 * ---------------------------------------------------------------------- */

typedef struct SessionChannel {
    char name[CHANNELLEN + 1];
    int  flags;
} SessionChannel;

typedef struct SessionMsg {
    char from[NICKLEN + USERLEN + HOSTLEN + 3];
    char text[512];
    int  is_notice;
} SessionMsg;

/* -------------------------------------------------------------------------
 * The Session record
 * ---------------------------------------------------------------------- */

typedef struct Session {
    /* Identity */
    char   key[SESSION_KEY_LEN + 1];
    char   nick[NICKLEN + 1];
    char   username[USERLEN + 1];
    char   host[HOSTLEN + 1];
    char   realname[REALLEN + 1];
    unsigned long umode;
    char   away_msg[TOPICLEN + 1];
    time_t expires_at;

    /* 1 = session was created locally (has channel and message data)
     * 0 = remote session received via gossip (identity only)        */
    int is_local;

    /* Channel snapshot — local sessions only */
    SessionChannel channels[SESSION_MAX_CHANS];
    int            num_channels;

    /* Pending-message ring — local sessions only.
     * msg_head = index of next write slot (0..SESSION_MAX_MSGS-1).
     * msg_count = number of valid entries (0..SESSION_MAX_MSGS).   */
    SessionMsg msgs[SESSION_MAX_MSGS];
    int        msg_head;
    int        msg_count;

    /* Slab / hash linkage */
    int             in_use;
    struct Session *key_hnext;
    struct Session *nick_hnext;
    struct Session *free_next;
} Session;

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

/* Initialise slab and hash tables (called from ircd.c or session module). */
void     session_init(void);

/* Snapshot a local client's state into a new session.
 * If preassigned_key is non-NULL and non-empty, it is used as the session
 * token instead of generating a random one.
 * Returns the new Session (token is readable as sess->key), or NULL if
 * the slab is exhausted.                                                */
Session *session_create(aClient *sptr, const char *preassigned_key);

/* Generate a random session key (SESSION_KEY_LEN hex chars + NUL).
 * buf must be at least SESSION_KEY_LEN + 1 bytes.                       */
void     session_generate_key(char *buf);

/* Remove a session from the nick hash table (but keep it alive).
 * Used during pre-registration RESUME so the restored nick doesn't
 * collide with the session's own reservation.                           */
void     session_unhash_nick(Session *sess);

/* Lookup by token (case-sensitive). */
Session *session_find_by_key(const char *key);

/* Lookup by nick (case-insensitive). */
Session *session_find_by_nick(const char *nick);

/* Destroy a session and return its slab slot to the free list. */
void     session_destroy(Session *sess);

/* Called every ~10 seconds; destroys sessions past their expiry time. */
void     session_expire_check(void);

/* Append a message to the session's pending ring (local sessions only). */
void     session_queue_msg(Session *sess, const char *from,
                           const char *text, int is_notice);

/* Apply a gossiped EVT_SESSION_CREATE from a remote server.
 * Creates a remote (is_local=0) session, or refreshes if already known. */
Session *session_apply_create(const char *key, const char *nick,
                               const char *username, const char *host,
                               const char *realname, unsigned long umode,
                               const char *away_msg, time_t expires_at);

/* Apply a gossiped EVT_SESSION_DESTROY: destroy session by token. */
void     session_apply_destroy(const char *key);

#endif /* SESSION_H */
