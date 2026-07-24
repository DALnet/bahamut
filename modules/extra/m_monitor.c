/* modules/extra/m_monitor.c
 *
 * IRCv3 MONITOR command — online/offline notification for nick lists.
 * Own hash table separate from WATCH (WATCH is legacy DALnet, MONITOR is
 * the IRCv3 standard).
 *
 * Commands: MONITOR + nicks, MONITOR - nicks, MONITOR C, MONITOR L, MONITOR S
 * Hooks: CHOOK_POSTREGISTER, CHOOK_SIGNOFF, CHOOK_NICK
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "h.h"
#include "hooks.h"
#include "hash.h"
#include "send.h"
#include "mapi.h"

/* Max monitored nicks per client */
#define MONITOR_MAX 128

/* Hash table size (power of 2) */
#define MON_HASH_SIZE 1024
#define MON_HASH_MASK (MON_HASH_SIZE - 1)

/* A watcher entry in a MonEntry's watcher list */
typedef struct MonWatch {
    aClient          *cptr;       /* watching client */
    struct MonWatch  *next;       /* next watcher */
} MonWatch;

/* A monitored nick entry in the hash table */
typedef struct MonEntry {
    char              nick[NICKLEN + 1];
    MonWatch         *watchers;   /* linked list of watchers */
    struct MonEntry  *hnext;      /* hash chain */
} MonEntry;

/* Per-client reverse index: linked list of nicks this client monitors.
 * Stored in an fd-indexed array for O(1) lookup. */
typedef struct MonClient {
    char              nick[NICKLEN + 1];
    struct MonClient *next;
} MonClient;

static MonEntry   *mon_hash[MON_HASH_SIZE];
static MonClient  *client_mons[MAXCONNECTIONS];
static int         client_mon_count[MAXCONNECTIONS];

/* Simple case-insensitive hash for nicks */
static unsigned int
mon_hash_nick(const char *nick)
{
    unsigned int h = 0;
    while (*nick)
    {
        h = (h << 5) + h + (unsigned char)ToLower(*nick);
        nick++;
    }
    return h & MON_HASH_MASK;
}

/* Find a MonEntry by nick (case-insensitive) */
static MonEntry *
mon_find(const char *nick)
{
    unsigned int h = mon_hash_nick(nick);
    MonEntry *mon;

    for (mon = mon_hash[h]; mon; mon = mon->hnext)
        if (mycmp(nick, mon->nick) == 0)
            return mon;
    return NULL;
}

/* Create a MonEntry for nick */
static MonEntry *
mon_create(const char *nick)
{
    unsigned int h = mon_hash_nick(nick);
    MonEntry *mon = MyMalloc(sizeof(MonEntry));

    memset(mon, 0, sizeof(*mon));
    strncpy(mon->nick, nick, NICKLEN);
    mon->nick[NICKLEN] = '\0';
    mon->hnext = mon_hash[h];
    mon_hash[h] = mon;
    return mon;
}

/* Add watcher to a MonEntry */
static void
mon_add_watcher(MonEntry *mon, aClient *cptr)
{
    MonWatch *w;

    /* Check if already watching */
    for (w = mon->watchers; w; w = w->next)
        if (w->cptr == cptr)
            return;

    w = MyMalloc(sizeof(MonWatch));
    w->cptr = cptr;
    w->next = mon->watchers;
    mon->watchers = w;
}

/* Remove watcher from a MonEntry. Free MonEntry if watchers list becomes empty. */
static void
mon_del_watcher(MonEntry *mon, aClient *cptr)
{
    MonWatch **wp, *w;

    for (wp = &mon->watchers; *wp; wp = &(*wp)->next)
    {
        if ((*wp)->cptr == cptr)
        {
            w = *wp;
            *wp = w->next;
            MyFree(w);
            break;
        }
    }

    /* Garbage collect empty entries */
    if (!mon->watchers)
    {
        unsigned int h = mon_hash_nick(mon->nick);
        MonEntry **mep;
        for (mep = &mon_hash[h]; *mep; mep = &(*mep)->hnext)
        {
            if (*mep == mon)
            {
                *mep = mon->hnext;
                MyFree(mon);
                break;
            }
        }
    }
}

/* Add nick to client's reverse index */
static void
client_mon_add(aClient *cptr, const char *nick)
{
    MonClient *mc;
    int fd = cptr->fd;

    if (fd < 0 || fd >= MAXCONNECTIONS)
        return;

    mc = MyMalloc(sizeof(MonClient));
    strncpy(mc->nick, nick, NICKLEN);
    mc->nick[NICKLEN] = '\0';
    mc->next = client_mons[fd];
    client_mons[fd] = mc;
    client_mon_count[fd]++;
}

/* Remove nick from client's reverse index */
static void
client_mon_del(aClient *cptr, const char *nick)
{
    MonClient **mcp, *mc;
    int fd = cptr->fd;

    if (fd < 0 || fd >= MAXCONNECTIONS)
        return;

    for (mcp = &client_mons[fd]; *mcp; mcp = &(*mcp)->next)
    {
        if (mycmp((*mcp)->nick, nick) == 0)
        {
            mc = *mcp;
            *mcp = mc->next;
            MyFree(mc);
            client_mon_count[fd]--;
            return;
        }
    }
}

/* Clear all monitor entries for a client (on disconnect) */
static void
mon_clear_client(aClient *cptr)
{
    MonClient *mc, *next;
    int fd = cptr->fd;

    if (fd < 0 || fd >= MAXCONNECTIONS)
        return;

    for (mc = client_mons[fd]; mc; mc = next)
    {
        MonEntry *entry = mon_find(mc->nick);
        next = mc->next;
        if (entry)
            mon_del_watcher(entry, cptr);
        MyFree(mc);
    }
    client_mons[fd] = NULL;
    client_mon_count[fd] = 0;
}

/* Notify watchers that a nick came online */
static void
mon_check_online(const char *nick)
{
    MonEntry *mon = mon_find(nick);
    MonWatch *w;
    aClient *acptr;
    char nuh[NICKLEN + USERLEN + HOSTLEN + 3];

    if (!mon)
        return;

    acptr = hash_find_client((char *)nick, NULL);
    if (!acptr || !IsPerson(acptr))
        return;

#ifdef USER_HOSTMASKING
    snprintf(nuh, sizeof(nuh), "%s!%s@%s",
             acptr->name, acptr->user->username,
             IsUmodeH(acptr) ? acptr->user->mhost : acptr->user->host);
#else
    snprintf(nuh, sizeof(nuh), "%s!%s@%s",
             acptr->name, acptr->user->username, acptr->user->host);
#endif

    for (w = mon->watchers; w; w = w->next)
    {
        if (MyClient(w->cptr))
            sendto_one(w->cptr, ":%s 730 %s :%s",
                       me.name, w->cptr->name, nuh);
    }
}

/* Notify watchers that a nick went offline */
static void
mon_check_offline(const char *nick)
{
    MonEntry *mon = mon_find(nick);
    MonWatch *w;

    if (!mon)
        return;

    for (w = mon->watchers; w; w = w->next)
    {
        if (MyClient(w->cptr))
            sendto_one(w->cptr, ":%s 731 %s :%s",
                       me.name, w->cptr->name, nick);
    }
}

/* -------------------------------------------------------------------------
 * MONITOR command handler
 * ------------------------------------------------------------------------- */
static int
m_monitor(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    char *subcmd;

    if (!MyClient(sptr))
        return 0;

    if (parc < 2)
    {
        sendto_one(sptr, ":%s 421 %s MONITOR :Not enough parameters",
                   me.name, sptr->name);
        return 0;
    }

    subcmd = parv[1];

    if (subcmd[0] == '+' && parc >= 3)
    {
        /* MONITOR + nick[,nick2,...] */
        char *p = NULL, *nick;
        char *nicks = parv[2];
        char online_buf[512], offline_buf[512];
        int on_len, off_len;
        int fd = sptr->fd;

        on_len = snprintf(online_buf, sizeof(online_buf),
                          ":%s 730 %s :", me.name, sptr->name);
        off_len = snprintf(offline_buf, sizeof(offline_buf),
                           ":%s 731 %s :", me.name, sptr->name);

        for (nick = strtoken(&p, nicks, ","); nick;
             nick = strtoken(&p, NULL, ","))
        {
            MonEntry *me_entry;
            aClient *acptr;
            int already = 0;
            MonClient *mc;

            if (!*nick)
                continue;

            /* Check if already monitoring this nick */
            if (fd >= 0 && fd < MAXCONNECTIONS)
            {
                for (mc = client_mons[fd]; mc; mc = mc->next)
                {
                    if (mycmp(mc->nick, nick) == 0)
                    {
                        already = 1;
                        break;
                    }
                }
            }

            if (!already)
            {
                if (fd >= 0 && fd < MAXCONNECTIONS &&
                    client_mon_count[fd] >= MONITOR_MAX)
                {
                    sendto_one(sptr, getreply(ERR_MONLISTFULL), me.name,
                               sptr->name, MONITOR_MAX, nick);
                    continue;
                }

                me_entry = mon_find(nick);
                if (!me_entry)
                    me_entry = mon_create(nick);
                mon_add_watcher(me_entry, sptr);
                client_mon_add(sptr, nick);
            }

            /* Check if online now */
            acptr = hash_find_client((char *)nick, NULL);
            if (acptr && IsPerson(acptr))
            {
                char nuh[NICKLEN + USERLEN + HOSTLEN + 3];
#ifdef USER_HOSTMASKING
                snprintf(nuh, sizeof(nuh), "%s!%s@%s",
                         acptr->name, acptr->user->username,
                         IsUmodeH(acptr) ? acptr->user->mhost : acptr->user->host);
#else
                snprintf(nuh, sizeof(nuh), "%s!%s@%s",
                         acptr->name, acptr->user->username, acptr->user->host);
#endif
                if (on_len + (int)strlen(nuh) + 2 > (int)sizeof(online_buf))
                {
                    sendto_one(sptr, "%s", online_buf);
                    on_len = snprintf(online_buf, sizeof(online_buf),
                                      ":%s 730 %s :", me.name, sptr->name);
                }
                if (online_buf[on_len - 1] != ':')
                    online_buf[on_len++] = ',';
                on_len += snprintf(online_buf + on_len,
                                   sizeof(online_buf) - on_len, "%s", nuh);
            }
            else
            {
                if (off_len + (int)strlen(nick) + 2 > (int)sizeof(offline_buf))
                {
                    sendto_one(sptr, "%s", offline_buf);
                    off_len = snprintf(offline_buf, sizeof(offline_buf),
                                       ":%s 731 %s :", me.name, sptr->name);
                }
                if (offline_buf[off_len - 1] != ':')
                    offline_buf[off_len++] = ',';
                off_len += snprintf(offline_buf + off_len,
                                    sizeof(offline_buf) - off_len, "%s", nick);
            }
        }

        /* Flush accumulated online/offline replies */
        if (online_buf[on_len - 1] != ':')
            sendto_one(sptr, "%s", online_buf);
        if (offline_buf[off_len - 1] != ':')
            sendto_one(sptr, "%s", offline_buf);

        return 0;
    }
    else if (subcmd[0] == '-' && parc >= 3)
    {
        /* MONITOR - nick[,nick2,...] */
        char *p = NULL, *nick;
        char *nicks = parv[2];

        for (nick = strtoken(&p, nicks, ","); nick;
             nick = strtoken(&p, NULL, ","))
        {
            MonEntry *me_entry;

            if (!*nick)
                continue;

            me_entry = mon_find(nick);
            if (me_entry)
                mon_del_watcher(me_entry, sptr);
            client_mon_del(sptr, nick);
        }
        return 0;
    }
    else if (mycmp(subcmd, "C") == 0)
    {
        /* MONITOR C — clear all */
        mon_clear_client(sptr);
        return 0;
    }
    else if (mycmp(subcmd, "L") == 0)
    {
        /* MONITOR L — list all monitored nicks */
        MonClient *mc;
        int fd = sptr->fd;
        char buf[512];
        int len;

        if (fd < 0 || fd >= MAXCONNECTIONS)
            goto endlist;

        len = snprintf(buf, sizeof(buf), ":%s 732 %s :", me.name, sptr->name);

        for (mc = client_mons[fd]; mc; mc = mc->next)
        {
            if (len + (int)strlen(mc->nick) + 2 > (int)sizeof(buf))
            {
                sendto_one(sptr, "%s", buf);
                len = snprintf(buf, sizeof(buf), ":%s 732 %s :",
                               me.name, sptr->name);
            }
            if (buf[len - 1] != ':')
                buf[len++] = ',';
            len += snprintf(buf + len, sizeof(buf) - len, "%s", mc->nick);
        }
        if (buf[len - 1] != ':')
            sendto_one(sptr, "%s", buf);

endlist:
        sendto_one(sptr, getreply(RPL_ENDOFMONLIST), me.name, sptr->name);
        return 0;
    }
    else if (mycmp(subcmd, "S") == 0)
    {
        /* MONITOR S — show status (online/offline) of all monitored nicks */
        MonClient *mc;
        int fd = sptr->fd;
        char online_buf[512], offline_buf[512];
        int on_len, off_len;

        if (fd < 0 || fd >= MAXCONNECTIONS)
            goto endstatus;

        on_len = snprintf(online_buf, sizeof(online_buf),
                          ":%s 730 %s :", me.name, sptr->name);
        off_len = snprintf(offline_buf, sizeof(offline_buf),
                           ":%s 731 %s :", me.name, sptr->name);

        for (mc = client_mons[fd]; mc; mc = mc->next)
        {
            aClient *acptr = hash_find_client(mc->nick, NULL);
            if (acptr && IsPerson(acptr))
            {
                char nuh[NICKLEN + USERLEN + HOSTLEN + 3];
#ifdef USER_HOSTMASKING
                snprintf(nuh, sizeof(nuh), "%s!%s@%s",
                         acptr->name, acptr->user->username,
                         IsUmodeH(acptr) ? acptr->user->mhost : acptr->user->host);
#else
                snprintf(nuh, sizeof(nuh), "%s!%s@%s",
                         acptr->name, acptr->user->username, acptr->user->host);
#endif
                if (on_len + (int)strlen(nuh) + 2 > (int)sizeof(online_buf))
                {
                    sendto_one(sptr, "%s", online_buf);
                    on_len = snprintf(online_buf, sizeof(online_buf),
                                      ":%s 730 %s :", me.name, sptr->name);
                }
                if (online_buf[on_len - 1] != ':')
                    online_buf[on_len++] = ',';
                on_len += snprintf(online_buf + on_len,
                                   sizeof(online_buf) - on_len, "%s", nuh);
            }
            else
            {
                if (off_len + (int)strlen(mc->nick) + 2 > (int)sizeof(offline_buf))
                {
                    sendto_one(sptr, "%s", offline_buf);
                    off_len = snprintf(offline_buf, sizeof(offline_buf),
                                       ":%s 731 %s :", me.name, sptr->name);
                }
                if (offline_buf[off_len - 1] != ':')
                    offline_buf[off_len++] = ',';
                off_len += snprintf(offline_buf + off_len,
                                    sizeof(offline_buf) - off_len, "%s", mc->nick);
            }
        }

        if (online_buf[on_len - 1] != ':')
            sendto_one(sptr, "%s", online_buf);
        if (offline_buf[off_len - 1] != ':')
            sendto_one(sptr, "%s", offline_buf);

endstatus:
        return 0;
    }

    return 0;
}

/* -------------------------------------------------------------------------
 * Hooks
 * ------------------------------------------------------------------------- */

/* CHOOK_POSTREGISTER: check if newly registered nick is monitored */
static void
hook_postregister(aClient *sptr)
{
    if (sptr && sptr->name[0])
        mon_check_online(sptr->name);
}

/* CHOOK_SIGNOFF: notify watchers, clear client's monitor list */
static void
hook_signoff(aClient *sptr)
{
    if (sptr && sptr->name[0])
        mon_check_offline(sptr->name);
    mon_clear_client(sptr);
}

/* CHOOK_NICK: old nick goes offline, new nick comes online */
static void
hook_nick(aClient *sptr, const char *oldnick, const char *newnick)
{
    mon_check_offline(oldnick);
    mon_check_online(newnick);
}

/* -------------------------------------------------------------------------
 * Module declaration
 * ------------------------------------------------------------------------- */

static const struct mapi_cmd_av2 monitor_cmds[] = {
    { "MONITOR", 0, {
        { mg_unreg,   0 },   /* HANDLER_UNREG */
        { m_monitor,  2 },   /* HANDLER_CLIENT */
        { mg_ignore,  0 },   /* HANDLER_REMOTE */
        { mg_ignore,  0 },   /* HANDLER_SERVER */
        { m_monitor,  2 },   /* HANDLER_OPER */
    }},
    { NULL }
};

static const struct mapi_hook_av1 monitor_hooks[] = {
    { CHOOK_POSTREGISTER, hook_postregister },
    { CHOOK_SIGNOFF,      hook_signoff },
    { CHOOK_NICK,         hook_nick },
    { 0, NULL }
};

DECLARE_MODULE("m_monitor", "1.0", "IRCv3 MONITOR command",
               0, monitor_cmds, monitor_hooks);
