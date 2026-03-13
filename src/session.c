/*
 * IRC - Internet Relay Chat, src/session.c
 * Copyright (C) 2024 Bahamut IRC Server Project
 *
 * Phase S4: Persistent sessions.
 *
 * 512-entry pre-allocated slab with two chained hash tables:
 *   key_htab[]  — keyed on session token (case-sensitive hex string)
 *   nick_htab[] — keyed on nick (case-insensitive, mirrors IRC convention)
 *
 * Local sessions (created when a local client disconnects) carry full
 * channel and pending-message snapshots.  Remote sessions (received via
 * gossip) carry identity only and allow cross-server RESUME.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "send.h"
#include "eventlog.h"
#include "session.h"

/* -------------------------------------------------------------------------
 * Storage
 * ---------------------------------------------------------------------- */

static Session  slab[SESSION_MAX];
static Session *free_list;
static Session *key_htab[SESSION_HASH];
static Session *nick_htab[SESSION_HASH];

/* -------------------------------------------------------------------------
 * Hash helpers
 * ---------------------------------------------------------------------- */

static unsigned int
hash_str(const char *s)
{
    unsigned int h = 5381;
    while (*s)
        h = h * 33 + (unsigned char)*s++;
    return h & (SESSION_HASH - 1);
}

/* Case-insensitive nick hash: A-Z → a-z, then djb2. */
static unsigned int
hash_nick_ci(const char *nick)
{
    unsigned int h = 5381;
    const char *p;
    for (p = nick; *p; p++)
    {
        unsigned char c = (unsigned char)*p;
        if (c >= 'A' && c <= 'Z')
            c += 32;
        h = h * 33 + c;
    }
    return h & (SESSION_HASH - 1);
}

/* -------------------------------------------------------------------------
 * Token generation (SESSION_KEY_LEN hex chars from /dev/urandom)
 * ---------------------------------------------------------------------- */

void
session_generate_key(char *buf)
{
    static const char hex[] = "0123456789abcdef";
    unsigned char     raw[SESSION_KEY_LEN / 2];
    size_t            i;
    int               fd;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0)
    {
        ssize_t r = read(fd, raw, sizeof(raw));
        close(fd);
        if (r != (ssize_t)sizeof(raw))
        {
            /* Partial read: fill remainder with rand() */
            size_t filled = (r > 0) ? (size_t)r : 0;
            for (i = filled; i < sizeof(raw); i++)
                raw[i] = (unsigned char)rand();
        }
    }
    else
    {
        for (i = 0; i < sizeof(raw); i++)
            raw[i] = (unsigned char)rand();
    }

    for (i = 0; i < SESSION_KEY_LEN; i++)
        buf[i] = hex[(raw[i / 2] >> ((i & 1) ? 0 : 4)) & 0x0f];
    buf[SESSION_KEY_LEN] = '\0';
}

/* -------------------------------------------------------------------------
 * Slab allocation
 * ---------------------------------------------------------------------- */

static Session *
session_alloc(void)
{
    Session *s = free_list;
    if (!s)
        return NULL;    /* slab exhausted */
    free_list = s->free_next;
    memset(s, 0, sizeof(*s));
    s->in_use = 1;
    return s;
}

static void
session_free(Session *s)
{
    s->in_use    = 0;
    s->free_next = free_list;
    free_list    = s;
}

/* -------------------------------------------------------------------------
 * Hash table operations
 * ---------------------------------------------------------------------- */

static void
htab_add_key(Session *s)
{
    unsigned int h = hash_str(s->key);
    s->key_hnext   = key_htab[h];
    key_htab[h]    = s;
}

static void
htab_del_key(Session *s)
{
    unsigned int  h  = hash_str(s->key);
    Session     **pp = &key_htab[h];
    while (*pp)
    {
        if (*pp == s) { *pp = s->key_hnext; return; }
        pp = &(*pp)->key_hnext;
    }
}

static void
htab_add_nick(Session *s)
{
    unsigned int h = hash_nick_ci(s->nick);
    s->nick_hnext  = nick_htab[h];
    nick_htab[h]   = s;
}

static void
htab_del_nick(Session *s)
{
    unsigned int  h  = hash_nick_ci(s->nick);
    Session     **pp = &nick_htab[h];
    while (*pp)
    {
        if (*pp == s) { *pp = s->nick_hnext; return; }
        pp = &(*pp)->nick_hnext;
    }
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

void
session_init(void)
{
    int i;
    memset(slab,     0, sizeof(slab));
    memset(key_htab, 0, sizeof(key_htab));
    memset(nick_htab,0, sizeof(nick_htab));
    free_list = NULL;
    for (i = SESSION_MAX - 1; i >= 0; i--)
    {
        slab[i].free_next = free_list;
        free_list         = &slab[i];
    }
}

Session *
session_create(aClient *sptr, const char *preassigned_key)
{
    Session *s;
    Link    *lp;
    int      i;

    if (!sptr->user)
        return NULL;

    s = session_alloc();
    if (!s)
        return NULL;

    if (preassigned_key && preassigned_key[0])
    {
        strncpy(s->key, preassigned_key, SESSION_KEY_LEN);
        s->key[SESSION_KEY_LEN] = '\0';
    }
    else
    {
        session_generate_key(s->key);
    }
    strncpy(s->nick,     sptr->name,            NICKLEN);
    strncpy(s->username, sptr->user->username,  USERLEN);
    strncpy(s->host,     sptr->user->host,      HOSTLEN);
    strncpy(s->realname, sptr->info,            REALLEN);
    s->umode      = sptr->umode;
    s->expires_at = time(NULL) + SESSION_TIMEOUT;
    s->is_local   = 1;

    if (sptr->user->away)
        strncpy(s->away_msg, sptr->user->away, TOPICLEN);

    /* Snapshot channel membership */
    i = 0;
    for (lp = sptr->user->channel; lp && i < SESSION_MAX_CHANS; lp = lp->next)
    {
        aChannel *chptr = lp->value.chptr;
        strncpy(s->channels[i].name, chptr->chname, CHANNELLEN);
        s->channels[i].flags = lp->flags;
        i++;
    }
    s->num_channels = i;

    htab_add_key(s);
    htab_add_nick(s);
    return s;
}

Session *
session_find_by_key(const char *key)
{
    unsigned int h = hash_str(key);
    Session *s;
    for (s = key_htab[h]; s; s = s->key_hnext)
        if (strcmp(s->key, key) == 0)
            return s;
    return NULL;
}

Session *
session_find_by_nick(const char *nick)
{
    unsigned int h = hash_nick_ci(nick);
    Session *s;
    for (s = nick_htab[h]; s; s = s->nick_hnext)
        if (mycmp(s->nick, (char *)nick) == 0)   /* case-insensitive */
            return s;
    return NULL;
}

void
session_destroy(Session *sess)
{
    htab_del_key(sess);
    htab_del_nick(sess);
    session_free(sess);
}

void
session_expire_check(void)
{
    int    i;
    time_t now = time(NULL);
    for (i = 0; i < SESSION_MAX; i++)
    {
        if (!slab[i].in_use)
            continue;
        if (slab[i].expires_at > 0 && slab[i].expires_at <= now)
            session_destroy(&slab[i]);
    }
}

void
session_queue_msg(Session *sess, const char *from, const char *text, int is_notice)
{
    SessionMsg *m;

    if (!sess->is_local)
        return;   /* remote sessions don't buffer messages */

    m = &sess->msgs[sess->msg_head];
    strncpy(m->from,  from, sizeof(m->from) - 1);
    strncpy(m->text,  text, sizeof(m->text) - 1);
    m->from[sizeof(m->from) - 1] = '\0';
    m->text[sizeof(m->text) - 1] = '\0';
    m->is_notice = is_notice;

    sess->msg_head = (sess->msg_head + 1) % SESSION_MAX_MSGS;
    if (sess->msg_count < SESSION_MAX_MSGS)
        sess->msg_count++;
}

Session *
session_apply_create(const char *key, const char *nick,
                     const char *username, const char *host,
                     const char *realname, unsigned long umode,
                     const char *away_msg, time_t expires_at)
{
    Session *s;

    /* Refresh if we already know this session */
    s = session_find_by_key(key);
    if (s)
    {
        s->expires_at = expires_at;
        return s;
    }

    s = session_alloc();
    if (!s)
        return NULL;

    strncpy(s->key,      key,      SESSION_KEY_LEN);
    strncpy(s->nick,     nick,     NICKLEN);
    strncpy(s->username, username, USERLEN);
    strncpy(s->host,     host,     HOSTLEN);
    strncpy(s->realname, realname, REALLEN);
    s->umode      = umode;
    s->expires_at = expires_at;
    s->is_local   = 0;

    if (away_msg && away_msg[0])
        strncpy(s->away_msg, away_msg, TOPICLEN);

    htab_add_key(s);
    htab_add_nick(s);
    return s;
}

void
session_apply_destroy(const char *key)
{
    Session *s = session_find_by_key(key);
    if (s)
        session_destroy(s);
}

void
session_unhash_nick(Session *sess)
{
    htab_del_nick(sess);
}
