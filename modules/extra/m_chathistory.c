/* modules/extra/m_chathistory.c
 *
 * IRCv3 draft/chathistory — in-memory per-channel message history playback.
 *
 * Stores the last HIST_RING_SIZE messages per channel in a ring buffer,
 * keyed by a hash table on channel name. Clients with the draft/chathistory
 * cap can query history via the CHATHISTORY command.
 *
 * Hooks:
 *   CHOOK_CHANMSG  — capture every PRIVMSG/NOTICE to a channel
 *   CHOOK_10SEC    — garbage-collect rings for destroyed channels
 */

#define _GNU_SOURCE   /* for timegm() */
#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "h.h"
#include "hooks.h"
#include "hash.h"
#include "channel.h"
#include "send.h"
#include "cap.h"
#include "mapi.h"

#include <sys/time.h>
#include <time.h>
#include <string.h>

/* needed for IsMember() */
extern Link *find_channel_link(Link *, aChannel *);

/* -------------------------------------------------------------------------
 * Tunables
 * ---------------------------------------------------------------------- */

#define HIST_RING_SIZE   128     /* msgs per channel, power of 2 */
#define HIST_RING_MASK   (HIST_RING_SIZE - 1)
#define HIST_HASH_SIZE   1024    /* hash buckets, power of 2 */
#define HIST_HASH_MASK   (HIST_HASH_SIZE - 1)
#define HIST_MAX_LIMIT   50      /* max msgs per CHATHISTORY request */
#define HIST_MSGID_LEN   128
#define HIST_TEXT_LEN    512
#define HIST_SENDER_LEN  (NICKLEN + 1 + USERLEN + 1 + HOSTLEN + 1)

/* -------------------------------------------------------------------------
 * Data structures
 * ---------------------------------------------------------------------- */

typedef struct HistEntry {
    struct timeval tv;                      /* wall-clock timestamp */
    char           msgid[HIST_MSGID_LEN];   /* raw msgid value */
    char           sender[HIST_SENDER_LEN]; /* nick!user@host */
    char           text[HIST_TEXT_LEN];
    int            is_notice;
} HistEntry;

typedef struct HistRing {
    char            chname[CHANNELLEN + 1];
    HistEntry       ring[HIST_RING_SIZE];
    unsigned int    head;       /* next write index */
    unsigned int    count;      /* valid entries (0..HIST_RING_SIZE) */
    struct timeval  last_msg;   /* timestamp of newest message */
    struct HistRing *hnext;     /* hash chain */
} HistRing;

static HistRing *hist_hash[HIST_HASH_SIZE];
static int       hist_count = 0;

/* -------------------------------------------------------------------------
 * Hash helpers
 * ---------------------------------------------------------------------- */

static unsigned int
hist_hash_name(const char *name)
{
    unsigned int h = 5381;
    while (*name)
    {
        h = (h << 5) + h + (unsigned char)ToLower(*name);
        name++;
    }
    return h & HIST_HASH_MASK;
}

static HistRing *
hist_find(char *chname)
{
    unsigned int h = hist_hash_name(chname);
    HistRing *hr;

    for (hr = hist_hash[h]; hr; hr = hr->hnext)
        if (mycmp(chname, hr->chname) == 0)
            return hr;
    return NULL;
}

static HistRing *
hist_create(const char *chname)
{
    unsigned int h = hist_hash_name(chname);
    HistRing *hr = (HistRing *)MyMalloc(sizeof(HistRing));

    memset(hr, 0, sizeof(HistRing));
    strncpy(hr->chname, chname, CHANNELLEN);
    hr->chname[CHANNELLEN] = '\0';
    hr->hnext = hist_hash[h];
    hist_hash[h] = hr;
    hist_count++;
    return hr;
}

/* -------------------------------------------------------------------------
 * Ring buffer helpers
 * ---------------------------------------------------------------------- */

/* Get the i-th logical entry (0 = oldest, count-1 = newest) */
static HistEntry *
hist_entry(HistRing *hr, int i)
{
    int real;
    if (i < 0 || (unsigned int)i >= hr->count)
        return NULL;
    if (hr->count < HIST_RING_SIZE)
        real = i;
    else
        real = (hr->head + i) & HIST_RING_MASK;
    return &hr->ring[real];
}

/* -------------------------------------------------------------------------
 * msgid extraction from outbound tags
 * ---------------------------------------------------------------------- */

static void
extract_msgid(const char *tags, char *out, size_t outlen)
{
    const char *p;

    out[0] = '\0';
    if (!tags || !*tags) return;

    /* look for "msgid=" either at start or after a semicolon */
    p = tags;
    while (p)
    {
        if (strncmp(p, "msgid=", 6) == 0)
        {
            const char *val = p + 6;
            const char *end = strchr(val, ';');
            size_t      len = end ? (size_t)(end - val) : strlen(val);
            if (len >= outlen) len = outlen - 1;
            memcpy(out, val, len);
            out[len] = '\0';
            return;
        }
        p = strchr(p, ';');
        if (p) p++;
    }
}

/* -------------------------------------------------------------------------
 * ISO 8601 timestamp formatting + parsing
 * ---------------------------------------------------------------------- */

static void
format_iso8601(const struct timeval *tv, char *buf, size_t buflen)
{
    struct tm tm;
    gmtime_r(&tv->tv_sec, &tm);
    snprintf(buf, buflen, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec,
             (int)(tv->tv_usec / 1000));
}

/* Parse "YYYY-MM-DDThh:mm:ss.sssZ" into struct timeval.
 * Returns 1 on success, 0 on failure. */
static int
parse_iso8601(const char *str, struct timeval *tv)
{
    struct tm tm;
    int ms = 0;

    memset(&tm, 0, sizeof(tm));
    /* Try with milliseconds first */
    if (sscanf(str, "%d-%d-%dT%d:%d:%d.%dZ",
               &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
               &tm.tm_hour, &tm.tm_min, &tm.tm_sec, &ms) >= 6)
    {
        tm.tm_year -= 1900;
        tm.tm_mon -= 1;
        tv->tv_sec = timegm(&tm);
        tv->tv_usec = ms * 1000;
        return 1;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * Message reference parsing
 * ---------------------------------------------------------------------- */

typedef enum { REF_NONE, REF_STAR, REF_TIMESTAMP, REF_MSGID } RefType;

typedef struct {
    RefType        type;
    struct timeval tv;
    char           msgid[HIST_MSGID_LEN];
} MsgRef;

/* Parse a message reference string. Returns 1 on success, 0 on failure. */
static int
parse_msgref(const char *str, MsgRef *ref)
{
    ref->type = REF_NONE;
    memset(&ref->tv, 0, sizeof(ref->tv));
    ref->msgid[0] = '\0';

    if (!str || !*str) return 0;

    if (strcmp(str, "*") == 0)
    {
        ref->type = REF_STAR;
        return 1;
    }
    if (strncmp(str, "timestamp=", 10) == 0)
    {
        if (!parse_iso8601(str + 10, &ref->tv))
            return 0;
        ref->type = REF_TIMESTAMP;
        return 1;
    }
    if (strncmp(str, "msgid=", 6) == 0)
    {
        strncpy(ref->msgid, str + 6, HIST_MSGID_LEN - 1);
        ref->msgid[HIST_MSGID_LEN - 1] = '\0';
        ref->type = REF_MSGID;
        return 1;
    }
    return 0;
}

/* Compare timeval: -1, 0, +1 */
static int
tv_cmp(const struct timeval *a, const struct timeval *b)
{
    if (a->tv_sec < b->tv_sec)  return -1;
    if (a->tv_sec > b->tv_sec)  return 1;
    if (a->tv_usec < b->tv_usec) return -1;
    if (a->tv_usec > b->tv_usec) return 1;
    return 0;
}

/* Find the logical index matching a MsgRef.
 * For timestamp: find the entry closest to (<=) the timestamp.
 * For msgid: exact string match.
 * Returns -1 if not found. */
static int
hist_find_ref(HistRing *hr, MsgRef *ref)
{
    int i;

    if (hr->count == 0) return -1;

    if (ref->type == REF_TIMESTAMP)
    {
        /* Binary search: find rightmost entry with tv <= ref->tv */
        int lo = 0, hi = (int)hr->count - 1, best = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) / 2;
            HistEntry *ent = hist_entry(hr, mid);
            if (tv_cmp(&ent->tv, &ref->tv) <= 0)
            {
                best = mid;
                lo = mid + 1;
            }
            else
            {
                hi = mid - 1;
            }
        }
        return best;
    }
    else if (ref->type == REF_MSGID)
    {
        /* Linear scan from newest to oldest for faster typical hits */
        for (i = (int)hr->count - 1; i >= 0; i--)
        {
            HistEntry *ent = hist_entry(hr, i);
            if (ent->msgid[0] && strcmp(ent->msgid, ref->msgid) == 0)
                return i;
        }
        return -1;
    }
    return -1;
}

/* -------------------------------------------------------------------------
 * CHOOK_CHANMSG — capture messages
 * ---------------------------------------------------------------------- */

static int
hook_chanmsg(aClient *sptr, aChannel *chptr, int is_notice, char *text)
{
    HistRing  *hr;
    HistEntry *ent;
    const char *tags;
    int        pos;

    if (!sptr || !chptr || !text) return 0;
    if (!sptr->user) return 0;

    hr = hist_find(chptr->chname);
    if (!hr)
        hr = hist_create(chptr->chname);

    pos = hr->head & HIST_RING_MASK;
    ent = &hr->ring[pos];

    gettimeofday(&ent->tv, NULL);
    hr->last_msg = ent->tv;

    snprintf(ent->sender, sizeof(ent->sender), "%.*s!%.*s@%.*s",
             NICKLEN, sptr->name,
             USERLEN, sptr->user->username,
             HOSTLEN, sptr->user->host);

    strncpy(ent->text, text, HIST_TEXT_LEN - 1);
    ent->text[HIST_TEXT_LEN - 1] = '\0';

    ent->is_notice = is_notice;

    /* Extract msgid from current outbound tags (cached per dispatch_serial) */
    tags = build_outbound_tags();
    extract_msgid(tags, ent->msgid, HIST_MSGID_LEN);

    hr->head = (hr->head + 1) & HIST_RING_MASK;
    if (hr->count < HIST_RING_SIZE)
        hr->count++;

    return 0;
}

/* -------------------------------------------------------------------------
 * CHOOK_10SEC — garbage-collect rings for destroyed channels
 * ---------------------------------------------------------------------- */

static void
hook_10sec(void)
{
    int i;
    for (i = 0; i < HIST_HASH_SIZE; i++)
    {
        HistRing **pp = &hist_hash[i];
        while (*pp)
        {
            HistRing *hr = *pp;
            if (!find_channel(hr->chname, NullChn))
            {
                *pp = hr->hnext;
                MyFree(hr);
                hist_count--;
            }
            else
            {
                pp = &hr->hnext;
            }
        }
    }
}

/* -------------------------------------------------------------------------
 * Replay helper — send history range inside a BATCH
 * ---------------------------------------------------------------------- */

#include "batch.h"

static void
hist_replay(aClient *sptr, HistRing *hr, int start, int end, const char *target)
{
    char ref[32];
    int  i;

    batch_genref(ref, sizeof(ref));
    batch_start(sptr, ref, "chathistory", target);

    for (i = start; i < end; i++)
    {
        HistEntry *ent = hist_entry(hr, i);
        char       tsbuf[64];
        char       tagbuf[512];
        const char *cmd;

        if (!ent) continue;

        format_iso8601(&ent->tv, tsbuf, sizeof(tsbuf));
        cmd = ent->is_notice ? "NOTICE" : "PRIVMSG";

        if (ent->msgid[0])
            snprintf(tagbuf, sizeof(tagbuf), "batch=%s;time=%s;msgid=%s",
                     ref, tsbuf, ent->msgid);
        else
            snprintf(tagbuf, sizeof(tagbuf), "batch=%s;time=%s",
                     ref, tsbuf);

        sendto_one_tags(sptr, tagbuf,
                        ":%s %s %s :%s",
                        ent->sender, cmd, target, ent->text);
    }

    batch_end(sptr, ref);
}

/* -------------------------------------------------------------------------
 * Target validation
 * ---------------------------------------------------------------------- */

static unsigned long chathistory_bit = 0;

static int
validate_target(aClient *sptr, char *sub, char *target,
                aChannel **chptr_out, HistRing **hr_out)
{
    aChannel *chptr;

    if (!IsChannelName(target))
    {
        sendto_one(sptr,
                   ":%s FAIL CHATHISTORY INVALID_TARGET %s :Not a channel name",
                   me.name, target);
        return 0;
    }

    chptr = find_channel(target, NullChn);
    if (!chptr)
    {
        sendto_one(sptr,
                   ":%s FAIL CHATHISTORY INVALID_TARGET %s :No such channel",
                   me.name, target);
        return 0;
    }

    if (!IsMember(sptr, chptr))
    {
        sendto_one(sptr,
                   ":%s FAIL CHATHISTORY INVALID_TARGET %s :You are not on that channel",
                   me.name, target);
        return 0;
    }

    *chptr_out = chptr;
    *hr_out = hist_find(chptr->chname);
    return 1;
}

/* -------------------------------------------------------------------------
 * Subcommand handlers
 * ---------------------------------------------------------------------- */

static int
clamp_limit(const char *s)
{
    int n = atoi(s);
    if (n < 1) n = 1;
    if (n > HIST_MAX_LIMIT) n = HIST_MAX_LIMIT;
    return n;
}

/* CHATHISTORY LATEST <target> <ref|*> <limit> */
static int
cmd_latest(aClient *sptr, int parc, char *parv[])
{
    aChannel *chptr;
    HistRing *hr;
    MsgRef    ref;
    int       limit, start, end;

    if (parc < 5)
    {
        sendto_one(sptr,
                   ":%s FAIL CHATHISTORY INVALID_PARAMS LATEST :Syntax: CHATHISTORY LATEST <target> <ref|*> <limit>",
                   me.name);
        return 0;
    }

    if (!validate_target(sptr, "LATEST", parv[2], &chptr, &hr))
        return 0;

    if (!hr || hr->count == 0)
    {
        /* send empty batch */
        char rbuf[32];
        batch_genref(rbuf, sizeof(rbuf));
        batch_start(sptr, rbuf, "chathistory", parv[2]);
        batch_end(sptr, rbuf);
        return 0;
    }

    if (!parse_msgref(parv[3], &ref))
    {
        sendto_one(sptr,
                   ":%s FAIL CHATHISTORY INVALID_PARAMS LATEST :Invalid message reference",
                   me.name);
        return 0;
    }

    limit = clamp_limit(parv[4]);
    end = (int)hr->count;

    if (ref.type == REF_STAR)
    {
        start = end - limit;
        if (start < 0) start = 0;
    }
    else
    {
        int idx = hist_find_ref(hr, &ref);
        if (idx < 0)
        {
            start = end - limit;
            if (start < 0) start = 0;
        }
        else
        {
            start = idx + 1;
            if (end - start > limit)
                start = end - limit;
        }
    }

    hist_replay(sptr, hr, start, end, parv[2]);
    return 0;
}

/* CHATHISTORY BEFORE <target> <ref> <limit> */
static int
cmd_before(aClient *sptr, int parc, char *parv[])
{
    aChannel *chptr;
    HistRing *hr;
    MsgRef    ref;
    int       limit, start, end, idx;

    if (parc < 5)
    {
        sendto_one(sptr,
                   ":%s FAIL CHATHISTORY INVALID_PARAMS BEFORE :Syntax: CHATHISTORY BEFORE <target> <ref> <limit>",
                   me.name);
        return 0;
    }

    if (!validate_target(sptr, "BEFORE", parv[2], &chptr, &hr))
        return 0;

    if (!hr || hr->count == 0)
    {
        char rbuf[32];
        batch_genref(rbuf, sizeof(rbuf));
        batch_start(sptr, rbuf, "chathistory", parv[2]);
        batch_end(sptr, rbuf);
        return 0;
    }

    if (!parse_msgref(parv[3], &ref) || ref.type == REF_STAR)
    {
        sendto_one(sptr,
                   ":%s FAIL CHATHISTORY INVALID_PARAMS BEFORE :Invalid message reference",
                   me.name);
        return 0;
    }

    limit = clamp_limit(parv[4]);
    idx = hist_find_ref(hr, &ref);

    if (idx < 0)
    {
        /* ref not found — no results */
        char rbuf[32];
        batch_genref(rbuf, sizeof(rbuf));
        batch_start(sptr, rbuf, "chathistory", parv[2]);
        batch_end(sptr, rbuf);
        return 0;
    }

    end = idx;       /* exclusive */
    start = end - limit;
    if (start < 0) start = 0;

    hist_replay(sptr, hr, start, end, parv[2]);
    return 0;
}

/* CHATHISTORY AFTER <target> <ref> <limit> */
static int
cmd_after(aClient *sptr, int parc, char *parv[])
{
    aChannel *chptr;
    HistRing *hr;
    MsgRef    ref;
    int       limit, start, end, idx;

    if (parc < 5)
    {
        sendto_one(sptr,
                   ":%s FAIL CHATHISTORY INVALID_PARAMS AFTER :Syntax: CHATHISTORY AFTER <target> <ref> <limit>",
                   me.name);
        return 0;
    }

    if (!validate_target(sptr, "AFTER", parv[2], &chptr, &hr))
        return 0;

    if (!hr || hr->count == 0)
    {
        char rbuf[32];
        batch_genref(rbuf, sizeof(rbuf));
        batch_start(sptr, rbuf, "chathistory", parv[2]);
        batch_end(sptr, rbuf);
        return 0;
    }

    if (!parse_msgref(parv[3], &ref) || ref.type == REF_STAR)
    {
        sendto_one(sptr,
                   ":%s FAIL CHATHISTORY INVALID_PARAMS AFTER :Invalid message reference",
                   me.name);
        return 0;
    }

    limit = clamp_limit(parv[4]);
    idx = hist_find_ref(hr, &ref);

    if (idx < 0)
    {
        char rbuf[32];
        batch_genref(rbuf, sizeof(rbuf));
        batch_start(sptr, rbuf, "chathistory", parv[2]);
        batch_end(sptr, rbuf);
        return 0;
    }

    start = idx + 1;  /* exclusive of ref */
    end = start + limit;
    if (end > (int)hr->count) end = (int)hr->count;

    hist_replay(sptr, hr, start, end, parv[2]);
    return 0;
}

/* CHATHISTORY AROUND <target> <ref> <limit> */
static int
cmd_around(aClient *sptr, int parc, char *parv[])
{
    aChannel *chptr;
    HistRing *hr;
    MsgRef    ref;
    int       limit, start, end, idx, half;

    if (parc < 5)
    {
        sendto_one(sptr,
                   ":%s FAIL CHATHISTORY INVALID_PARAMS AROUND :Syntax: CHATHISTORY AROUND <target> <ref> <limit>",
                   me.name);
        return 0;
    }

    if (!validate_target(sptr, "AROUND", parv[2], &chptr, &hr))
        return 0;

    if (!hr || hr->count == 0)
    {
        char rbuf[32];
        batch_genref(rbuf, sizeof(rbuf));
        batch_start(sptr, rbuf, "chathistory", parv[2]);
        batch_end(sptr, rbuf);
        return 0;
    }

    if (!parse_msgref(parv[3], &ref) || ref.type == REF_STAR)
    {
        sendto_one(sptr,
                   ":%s FAIL CHATHISTORY INVALID_PARAMS AROUND :Invalid message reference",
                   me.name);
        return 0;
    }

    limit = clamp_limit(parv[4]);
    idx = hist_find_ref(hr, &ref);

    if (idx < 0)
    {
        char rbuf[32];
        batch_genref(rbuf, sizeof(rbuf));
        batch_start(sptr, rbuf, "chathistory", parv[2]);
        batch_end(sptr, rbuf);
        return 0;
    }

    half = limit / 2;
    start = idx - half;
    end = start + limit;

    if (start < 0)
    {
        start = 0;
        end = limit;
    }
    if (end > (int)hr->count)
    {
        end = (int)hr->count;
        start = end - limit;
        if (start < 0) start = 0;
    }

    hist_replay(sptr, hr, start, end, parv[2]);
    return 0;
}

/* CHATHISTORY BETWEEN <target> <ref1> <ref2> <limit> */
static int
cmd_between(aClient *sptr, int parc, char *parv[])
{
    aChannel *chptr;
    HistRing *hr;
    MsgRef    ref1, ref2;
    int       limit, start, end, idx1, idx2, tmp;

    if (parc < 6)
    {
        sendto_one(sptr,
                   ":%s FAIL CHATHISTORY INVALID_PARAMS BETWEEN :Syntax: CHATHISTORY BETWEEN <target> <ref1> <ref2> <limit>",
                   me.name);
        return 0;
    }

    if (!validate_target(sptr, "BETWEEN", parv[2], &chptr, &hr))
        return 0;

    if (!hr || hr->count == 0)
    {
        char rbuf[32];
        batch_genref(rbuf, sizeof(rbuf));
        batch_start(sptr, rbuf, "chathistory", parv[2]);
        batch_end(sptr, rbuf);
        return 0;
    }

    if (!parse_msgref(parv[3], &ref1) || ref1.type == REF_STAR ||
        !parse_msgref(parv[4], &ref2) || ref2.type == REF_STAR)
    {
        sendto_one(sptr,
                   ":%s FAIL CHATHISTORY INVALID_PARAMS BETWEEN :Invalid message reference",
                   me.name);
        return 0;
    }

    limit = clamp_limit(parv[5]);

    idx1 = hist_find_ref(hr, &ref1);
    idx2 = hist_find_ref(hr, &ref2);

    if (idx1 < 0 || idx2 < 0)
    {
        char rbuf[32];
        batch_genref(rbuf, sizeof(rbuf));
        batch_start(sptr, rbuf, "chathistory", parv[2]);
        batch_end(sptr, rbuf);
        return 0;
    }

    /* Ensure idx1 < idx2 */
    if (idx1 > idx2)
    {
        tmp = idx1;
        idx1 = idx2;
        idx2 = tmp;
    }

    /* exclusive of both bounds */
    start = idx1 + 1;
    end = idx2;

    if (end - start > limit)
        end = start + limit;

    hist_replay(sptr, hr, start, end, parv[2]);
    return 0;
}

/* CHATHISTORY TARGETS <ref1> <ref2> <limit> */
static int
cmd_targets(aClient *sptr, int parc, char *parv[])
{
    MsgRef    ref1, ref2;
    int       limit, i, n;
    char      ref[32];
    struct timeval tv_lo, tv_hi, tmp_tv;

    /* parv[1]="TARGETS" parv[2]=ref1 parv[3]=ref2 parv[4]=limit */
    if (parc < 5)
    {
        sendto_one(sptr,
                   ":%s FAIL CHATHISTORY INVALID_PARAMS TARGETS :Syntax: CHATHISTORY TARGETS <ref1> <ref2> <limit>",
                   me.name);
        return 0;
    }

    if (!parse_msgref(parv[2], &ref1) || !parse_msgref(parv[3], &ref2))
    {
        sendto_one(sptr,
                   ":%s FAIL CHATHISTORY INVALID_PARAMS TARGETS :Invalid message reference",
                   me.name);
        return 0;
    }

    /* For TARGETS, * means "now" or "beginning of time" */
    if (ref1.type == REF_STAR)
    {
        ref1.tv.tv_sec = 0;
        ref1.tv.tv_usec = 0;
    }
    if (ref2.type == REF_STAR)
    {
        gettimeofday(&ref2.tv, NULL);
    }

    tv_lo = ref1.tv;
    tv_hi = ref2.tv;
    if (tv_cmp(&tv_lo, &tv_hi) > 0)
    {
        tmp_tv = tv_lo;
        tv_lo = tv_hi;
        tv_hi = tmp_tv;
    }

    limit = clamp_limit(parv[4]);

    /* Collect matching channels.
     * Simple approach: walk all rings, filter by membership + time range,
     * then sort by last_msg descending. */
    {
        typedef struct { HistRing *hr; } TargetHit;
        TargetHit hits[HIST_MAX_LIMIT];

        n = 0;
        for (i = 0; i < HIST_HASH_SIZE && n < limit; i++)
        {
            HistRing *hr;
            for (hr = hist_hash[i]; hr && n < limit; hr = hr->hnext)
            {
                aChannel *ch = find_channel(hr->chname, NullChn);
                if (!ch || !IsMember(sptr, ch))
                    continue;
                if (hr->count == 0)
                    continue;
                /* Check if last_msg falls in range */
                if (tv_cmp(&hr->last_msg, &tv_lo) < 0 ||
                    tv_cmp(&hr->last_msg, &tv_hi) > 0)
                    continue;
                hits[n].hr = hr;
                n++;
            }
        }

        /* Sort by last_msg descending (simple insertion sort for small n) */
        {
            int j;
            for (i = 1; i < n; i++)
            {
                TargetHit t = hits[i];
                j = i - 1;
                while (j >= 0 && tv_cmp(&hits[j].hr->last_msg, &t.hr->last_msg) < 0)
                {
                    hits[j + 1] = hits[j];
                    j--;
                }
                hits[j + 1] = t;
            }
        }

        /* Send chathistory-targets batch */
        batch_genref(ref, sizeof(ref));
        batch_start(sptr, ref, "chathistory-targets", NULL);

        for (i = 0; i < n; i++)
        {
            HistRing *hr = hits[i].hr;
            char tsbuf[64];
            char tagbuf[256];

            format_iso8601(&hr->last_msg, tsbuf, sizeof(tsbuf));
            snprintf(tagbuf, sizeof(tagbuf), "batch=%s;time=%s", ref, tsbuf);
            sendto_one_tags(sptr, tagbuf,
                            ":%s PRIVMSG %s :*",
                            me.name, hr->chname);
        }

        batch_end(sptr, ref);
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * CHATHISTORY command dispatcher
 * ---------------------------------------------------------------------- */

static int
m_chathistory(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr,
              int parc, char *parv[])
{
    char *sub;

    if (!HasCap(sptr, chathistory_bit))
    {
        sendto_one(sptr,
                   ":%s FAIL CHATHISTORY NEED_CAPABILITY * :Capability not enabled",
                   me.name);
        return 0;
    }

    sub = parv[1];

    if (mycmp(sub, "LATEST") == 0)
        return cmd_latest(sptr, parc, parv);
    if (mycmp(sub, "BEFORE") == 0)
        return cmd_before(sptr, parc, parv);
    if (mycmp(sub, "AFTER") == 0)
        return cmd_after(sptr, parc, parv);
    if (mycmp(sub, "AROUND") == 0)
        return cmd_around(sptr, parc, parv);
    if (mycmp(sub, "BETWEEN") == 0)
        return cmd_between(sptr, parc, parv);
    if (mycmp(sub, "TARGETS") == 0)
        return cmd_targets(sptr, parc, parv);

    sendto_one(sptr,
               ":%s FAIL CHATHISTORY INVALID_PARAMS %s :Unknown subcommand",
               me.name, sub);
    return 0;
}

/* -------------------------------------------------------------------------
 * Module unregister — free all allocations
 * ---------------------------------------------------------------------- */

static void
chathistory_unregister(void)
{
    int i;
    for (i = 0; i < HIST_HASH_SIZE; i++)
    {
        HistRing *hr = hist_hash[i];
        while (hr)
        {
            HistRing *next = hr->hnext;
            MyFree(hr);
            hr = next;
        }
        hist_hash[i] = NULL;
    }
    hist_count = 0;
}

/* -------------------------------------------------------------------------
 * Module declaration
 * ---------------------------------------------------------------------- */

static const struct mapi_cmd_av2 chathistory_cmds[] = {
    { "CHATHISTORY", 0, {
        { mg_unreg,       0 },   /* HANDLER_UNREG */
        { m_chathistory,  2 },   /* HANDLER_CLIENT */
        { mg_ignore,      0 },   /* HANDLER_REMOTE */
        { mg_ignore,      0 },   /* HANDLER_SERVER */
        { m_chathistory,  2 },   /* HANDLER_OPER */
    }},
    { NULL }
};

static const struct mapi_hook_av1 chathistory_hooks[] = {
    { CHOOK_CHANMSG, hook_chanmsg },
    { CHOOK_10SEC,   hook_10sec   },
    { 0, NULL }
};

static struct mapi_cap_av1 chathistory_caps[] = {
    { "draft/chathistory", NULL, &chathistory_bit, NULL, NULL },
    { NULL }
};

DECLARE_MODULE_CAPS_RU("m_chathistory", "1.0",
                       "IRCv3 draft/chathistory",
                       0, chathistory_cmds, chathistory_hooks, chathistory_caps,
                       NULL, chathistory_unregister);
