/************************************************************************
 *   IRC - Internet Relay Chat, src/userban.c
 *   Copyright (C) 2002 Lucas Madar and
 *                      the DALnet coding team
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/* $Id$ */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "numeric.h"
#include "userban.h"
#include "patricia.h"
#include "ircstrings.h"
#include "memcount.h"


/*
 * Took the original implementation by Lucas and diced it up a bit.
 *
 * Userbans are stored in 4 containers: a hashtable for full hostnames, a list
 * for wildcard hostname masks, a list for no hostmasks at all (username masks
 * only), and a PATRICIA tree for IPs (CIDR and full).  Wildcard IP masks are
 * no longer supported.
 *
 * Nodes are used directly; there is no longer a separate uBanEnt.
 *
 *     -Quension [Aug 2006]
 */

typedef struct UserBan UserBan;

struct UserBan {
    u_short  flags;     /* general flags */
    u_short  priority;  /* ban priority level (0..1066) */
    time_t   expirets;  /* expiration timestamp */
    char    *mask;      /* user, host, or user@host mask */
    char    *reason;    /* ban reason */
    UserBan *next;      /* linked list entry */
};


/* flags to look at during duplicate checks */
#define UB_DUPFLAGS   (UBAN_LOCAL|UBAN_EXEMPT)

#define USERBAN_HASH_SIZE   3217    /* prime */

static UserBan *ubl_hostnames[USERBAN_HASH_SIZE];
static UserBan *ubl_hostmasks;
static UserBan *ubl_wildhosts;

static Patricia *ub_iptree;

static char ub_maskbuf[USERLEN + HOSTLEN + 40];
static char ub_userbuf[USERLEN + 10];


/* used during mass deletions */
typedef struct {
    time_t  ts;
    u_short flags;
    u_short flagset;
} UBMassDel;

/* used during matching */
typedef struct {
    char    *what;
    UserBan *network;
    UserBan *local;
} UBMatch;


static UserBan *
ub_alloc(u_short flags, u_short priority, time_t expirets, char *reason)
{
    UserBan *b = MyMalloc(sizeof(*b));

    memset(b, 0, sizeof(*b));

    b->flags = flags;
    b->priority = priority;
    b->expirets = expirets;
    DupString(b->reason, reason);

    return b;
}

static void
ub_free(UserBan *b)
{
    MyFree(b->mask);
    MyFree(b->reason);
    MyFree(b);
}

static unsigned int
ub_hash(char *n)
{
    unsigned int hv = 0;

    while(*n)
    {
        hv <<= 5;
        hv |= (ToUpper(*n) - 65) & 0xFF;
        n++;
    }

    return hv;
}

/* isolate user and host masks, fills in ub_maskbuf and ub_userbuf */
static int
ub_isolate(char *mask, char **user, char **host)
{
    size_t len;
    char *s;

    /* scrubbed user@host mask goes in ub_maskbuf */
    if ((len = strlen(mask)) >= sizeof(ub_maskbuf))
        return 0;

    memcpy(ub_maskbuf, mask, len+1);    /* XXX replace with collapser */

    /* scrubbed user mask goes in ub_userbuf */
    if (!(s = strchr(mask, '@')))
        return 0;

    if ((len = s - mask) >= sizeof(ub_userbuf))
        return 0;

    memcpy(ub_userbuf, mask, len);
    ub_userbuf[len] = 0;

    *user = ub_userbuf;
    *host = ub_maskbuf + len + 1;

    return 1;
}


/* callback for adding a userban to a list */
static int
ubcb_add(void *carg, void **slot)
{
    UserBan *data;
    UserBan *b;
    u_short dflags;

    data = carg;
    dflags = data->flags & UB_DUPFLAGS;

    for (b = *slot; b; b = b->next)
    {
        if ((b->flags & UB_DUPFLAGS) != dflags)
            continue;

        if ((!b->mask && !data->mask)
            || (b->mask && data->mask && !mycmp(b->mask, data->mask)))
        {
            if (data->flags & UBAN_UPDATE)
            {
                /* update the existing userban */
                b->flags = (data->flags & ~UBAN_UPDATE);
                b->expirets = data->expirets;
                MyFree(b->reason);
                DupString(b->reason, data->reason);
            }
            else
            {
                /* return the duplicate ban's information */
                data->flags = b->flags;
                data->expirets = b->expirets;
                data->mask = b->mask;
                data->reason = b->reason;
            }

            return UBAN_ADD_DUPLICATE;
        }
    }

    data->flags &= ~UBAN_UPDATE;
    b = ub_alloc(data->flags, data->priority, data->expirets, data->reason);
    if (data->mask)
        DupString(b->mask, data->mask);

    if (!(b->flags & UBAN_EXEMPT))
        userban_updates++;

    b->next = *slot;
    *slot = b;

    return 0;
}

/* callback for deleting a specific ban from a list */
static int
ubcb_del(void *carg, void **slot)
{
    UserBan *data;
    UserBan *b;
    UserBan **pbs;

    data = carg;
    pbs = (UserBan **)slot;

    for (b = *pbs; b; b = b->next)
    {
        if ((b->flags & UB_DUPFLAGS) == data->flags)
        {
            if (!b->mask && !data->mask)
                break;

            if (b->mask && data->mask && !mycmp(b->mask, data->mask))
                break;
        }

        pbs = &b->next;
    }

    if (!b)
        return UBAN_DEL_NOTFOUND;

    data->flags = b->flags;
    data->expirets = b->expirets;

    if (b->flags & UBAN_CONF)
    {
        data->mask = b->mask;
        data->reason = b->reason;

        return UBAN_DEL_INCONF;
    }

    if (b->flags & UBAN_EXEMPT)
        userban_updates++;

    *pbs = b->next;
    ub_free(b);

    return 0;
}

/* callback for mass deletions from a list */
static void
ubcb_massdel(void *carg, u_int unused1, int unused2, void **slot)
{
    UBMassDel *ubmd;
    UserBan *b;
    UserBan *next;
    UserBan **pbs;

    ubmd = carg;
    pbs = (UserBan **)slot;

    for (b = *pbs; b; b = next)
    {
        next = b->next;

        if (b->expirets < ubmd->ts ||
            (ubmd->flagset && (b->flags & ubmd->flagset) == ubmd->flags))
        {
            if (b->flags & UBAN_EXEMPT)
                userban_updates++;

            *pbs = b->next;
            ub_free(b);
            continue;
        }

        pbs = &b->next;
    }
}

/* callback for matching a mask against a list of userbans */
static void
ubcb_match(void *carg, void *list)
{
    UserBan *b;
    UserBan *lb;
    UserBan *nb;
    UBMatch *ubm = carg;
    char *what;

    what = ubm->what;
    lb = ubm->local;
    nb = ubm->network;

    for (b = list; b; b = b->next)
    {
        if (!b->mask || !match(b->mask, what))
        {
            if (b->flags & UBAN_LOCAL)
            {
                if (!lb || b->priority > lb->priority)
                    lb = b;
            }
            else
            {
                if (!nb || b->priority > nb->priority)
                    nb = b;
            }
        }
    }

    ubm->local = lb;
    ubm->network = nb;
}


/*
 * Add a new userban.  Requires user@host mask, a reason, an expiration time,
 * and optional flags.  An expiration time of 0 creates a permanent ban.
 * Returns UBAN_ADD_INVALID for an invalid mask, or UBAN_ADD_DUPLICATE if this
 * ban already exists; 0 otherwise.
 * For duplicate and successfully added bans, UserBanInfo is filled in.
 */
int
userban_add(char *mask, char *reason, time_t expirets, u_short flags, UserBanInfo *ubi)
{
    int hrv;
    int upri = 0;
    int hpri = 0;
    int prefix;
    u_int rawip;
    int result = UBAN_ADD_INVALID;
    UserBan pcb = {0};
    char *user;
    char *host;
    char *s;

    pcb.flags = flags;
    pcb.expirets = expirets ? expirets : INT_MAX;   /* INT_MAX is permanent */
    pcb.reason = reason;

    if (!ub_isolate(mask, &user, &host))
        return UBAN_ADD_INVALID;

    if (!validate_user(user, VALIDATE_MASK))
        return UBAN_ADD_INVALID;

    /* set user mask priority */
    for (s = user; *s; s++)
        if (*s != '*')
            upri++;

    hrv = categorize_host(host, &rawip, &prefix, VALIDATE_DOT);

    switch (hrv)
    {
        case HMT_IP:
        case HMT_IPCIDR:
            if (rawip == 0) /* bans that match hostmasking are not allowed */
                return UBAN_ADD_INVALID;

            pcb.mask = upri ? user : NULL;
            hpri = prefix * (USERLEN + 1);
            pcb.priority = hpri + upri;

            result = patricia_add(&ub_iptree, rawip, prefix, ubcb_add, &pcb);

            if (ubi)
                ircsprintf(ub_maskbuf, "%s@%s", user,
                           cidr2string(rawip, prefix, 0));
            break;
            
        case HMT_WILD:
            if (!upri)  /* bans that match anything are not allowed */
                return UBAN_ADD_INVALID;

            pcb.mask = user;
            pcb.priority = upri;

            result = ubcb_add(&pcb, (void **)&ubl_wildhosts);

            if (ubi)
                ircsprintf(ub_maskbuf, "%s@*", pcb.mask);
            break;

        case HMT_NAME:
            hrv = ub_hash(host) % USERBAN_HASH_SIZE;
            pcb.mask = ub_maskbuf;

            /* host priority levels are above CIDR levels */
            hpri = (33 + HOSTLEN) * (USERLEN + 1);
            pcb.priority = hpri + upri;

            result = ubcb_add(&pcb, (void **)&ubl_hostnames[hrv]);
            break;

        case HMT_NAMEMASK:
            pcb.mask = ub_maskbuf;

            /* host priority levels are above CIDR levels */
            hpri = 33;
            for (s = host; *s; s++)
                if (*s != '*')
                    hpri++;
            hpri *= (USERLEN + 1);
            pcb.priority = hpri + upri;

            result = ubcb_add(&pcb, (void **)&ubl_hostmasks);
            break;
    }

    if (ubi && result != UBAN_ADD_INVALID)
    {
        ubi->flags = pcb.flags;
        ubi->mask = ub_maskbuf;
        ubi->reason = pcb.reason;
        ubi->expirets = (pcb.expirets != INT_MAX ? pcb.expirets : 0);
    }

    return result;
}

/*
 * Delete a userban.  Requires user@host mask and flags indicating the type
 * (local/exemption).  Returns UBAN_DEL_NOTFOUND if the ban does not exist,
 * or UBAN_DEL_INCONF if it is specified in ircd.conf; 0 otherwise.
 * If a ban is found, UserBanInfo is filled in.
 * NOTE: Filled UserBanInfo does not contain a valid reason.
 */
int
userban_del(char *mask, u_short flags, UserBanInfo *ubi)
{
    u_int rawip;
    int prefix;
    int rv;
    int result = UBAN_DEL_NOTFOUND;
    int userwild = 0;
    UserBan pcb = {0};
    char *user;
    char *host;

    flags &= UB_DUPFLAGS;
    pcb.flags = flags;

    if (!ub_isolate(mask, &user, &host))
        return UBAN_DEL_NOTFOUND;

    if (!validate_user(user, VALIDATE_MASK))
        return UBAN_DEL_NOTFOUND;

    if (!strcmp(user, "*"))
        userwild = 1;

    rv = categorize_host(host, &rawip, &prefix, VALIDATE_DOT);

    switch (rv)
    {
        case HMT_IP:
        case HMT_IPCIDR:
            if (!userwild)
                pcb.mask = user;

            result = patricia_del(&ub_iptree, rawip, prefix, ubcb_del, &pcb);

            if (ubi)
                ircsprintf(ub_maskbuf, "%s@%s", user,
                           cidr2string(rawip, prefix, 0));
            break;

        case HMT_WILD:
            if (userwild)
                return UBAN_DEL_NOTFOUND;
            pcb.mask = user;

            result = ubcb_del(&pcb, (void **)&ubl_wildhosts);

            if (ubi)
                ircsprintf(ub_maskbuf, "%s@*", user);
            break;

        case HMT_NAME:
            rv = ub_hash(host) % USERBAN_HASH_SIZE;
            pcb.mask = ub_maskbuf;

            result = ubcb_del(&pcb, (void **)&ubl_hostnames[rv]);
            break;

        case HMT_NAMEMASK:
            pcb.mask = ub_maskbuf;

            result = ubcb_del(&pcb, (void **)&ubl_hostmasks);
            break;
    }

    /* we return NOTFOUND for invalid masks too, so can't fill ubi */
    if (ubi && result != UBAN_DEL_NOTFOUND)
    {
        ubi->flags = pcb.flags;
        ubi->mask = ub_maskbuf;
        ubi->expirets = (pcb.expirets != INT_MAX ? pcb.expirets : 0);
        ubi->reason = NULL;
    }

    return result;
}

/*
 * Mass delete userbans based on expiration time and/or specific flags.
 * A zero timestamp ignores expiration time; zero flagset ignores flags.
 */
void
userban_massdel(time_t ts, u_short flags, u_short flagset)
{
    int i;
    UBMassDel ubmd;

    if (!ts)
        ts = INT_MAX;   /* not expiring anything */
    flags &= flagset;

    ubmd.ts = ts;
    ubmd.flags = flags;
    ubmd.flagset = flagset;

    ubcb_massdel(&ubmd, 0, 0, (void **)&ubl_wildhosts);
    ubcb_massdel(&ubmd, 0, 0, (void **)&ubl_hostmasks);

    for (i = 0; i < USERBAN_HASH_SIZE; i++)
        if (ubl_hostnames[i])
            ubcb_massdel(&ubmd, 0, 0, (void **)&ubl_hostnames[i]);

    patricia_walk(&ub_iptree, ubcb_massdel, &ubmd);
}


/* common workhorse for checkclient() and checkserver() */
static UserBanInfo *
ub_check(char *user, char *host, u_int ip)
{
    static UserBanInfo ubi;
    UserBan *ban = NULL;
    UBMatch ubm = {0};

    if (ubl_wildhosts)
    {
        ubm.what = user;
        ubcb_match(&ubm, ubl_wildhosts);
    }

    if (host)
    {
        int hv = ub_hash(host) % USERBAN_HASH_SIZE;
        ircsprintf(ub_maskbuf, "%s@%s", user, host);
        ubm.what = ub_maskbuf;

        if (ubl_hostmasks)
            ubcb_match(&ubm, ubl_hostmasks);

        if (ubl_hostnames[hv])
            ubcb_match(&ubm, ubl_hostnames[hv]);
    }

    if (ub_iptree)
    {
        ubm.what = user;
        patricia_search(ub_iptree, ip, ubcb_match, &ubm);
    }

    if (ubm.network && !(ubm.network->flags & UBAN_EXEMPT))
        ban = ubm.network;
    else if (ubm.local && !(ubm.local->flags & UBAN_EXEMPT))
        ban = ubm.local;

    if (ban)
    {
        ubi.flags = ban->flags;
        ubi.reason = ban->reason;
        ubi.expirets = (ban->expirets != INT_MAX) ? ban->expirets : 0;
        return &ubi;
    }

    return NULL;
}

/*
 * Checks whether a client matches any userbans.  Returns a pointer to a
 * static UserBanInfo if there is a match; NULL otherwise.
 * NOTE: Returned UserBanInfo does not contain a valid mask.
 */
UserBanInfo *
userban_checkclient(aClient *cptr)
{
    return ub_check(cptr->user->username,
                    (cptr->flags & FLAGS_HOSTNAME) ? cptr->user->host : NULL,
                    cptr->ip.s_addr);
}

/*
 * Checks whether a server matches any userbans.  Returns a pointer to a
 * static UserBanInfo if there is a match; NULL otherwise.
 * NOTE: Returned UserBanInfo does not contain a valid mask.
 */
UserBanInfo *
userban_checkserver(aClient *cptr)
{
    return ub_check(cptr->username, NULL, cptr->ip.s_addr);
}


/*
 * Runs a userban sweep against all connections, to enforce ban
 * additions or exemption removals.
 */
void
userban_sweep(void)
{
    char rbuf[512];
    UserBanInfo *ubi;
    aClient *acptr;
    char *btext;
    char *ntext;
    int i;

    for (i = highest_fd; i >= 0; i--)
    {
        if (!(acptr = local[i]) || !IsRegistered(acptr))
            continue;

        ubi = IsClient(acptr)
            ? userban_checkclient(acptr)
            : userban_checkserver(acptr);

        if (!ubi)
            continue;

        if (ubi->flags & UBAN_LOCAL)
        {
            btext = LOCAL_BANNED_NAME;
            ntext = LOCAL_BAN_NAME;
        }
        else
        {
            btext = NETWORK_BANNED_NAME;
            ntext = NETWORK_BAN_NAME;
        }

        ircsprintf(rbuf, "%s: %s", btext, ubi->reason);
        sendto_ops("%s active for %s", ntext, get_client_name(acptr, FALSE));
        exit_client(acptr, acptr, &me, rbuf);
    }
}



/* XXX stats */
/* XXX memcount */
/* XXX clean up register_user, fix remote FLAGS_HOSTNAME */



/* struct for iteration data */
typedef struct {
    int type;
    u_short flags;
    u_short flagset;
    void (*callback)(void *);
    void *carg;
    UserBanInfo *ubi;
} UBIter;

/* callback used by ub_iterate */
static void
ubcb_iterator(void *carg, u_int rawip, int prefix, void **slot)
{
    UBIter *iter;
    UserBan *b;
    UserBanInfo *ubi;

    iter = carg;
    ubi = iter->ubi;

    for (b = *slot; b; b = b->next)
    {
        if ((b->flags & iter->flagset) == iter->flags)
        {
            ubi->flags = b->flags;
            ubi->mask = b->mask;
            ubi->reason = b->reason;
            ubi->expirets = (b->expirets == INT_MAX) ? 0 : b->expirets;

            if (iter->type == HMT_WILD)
            {
                ircsprintf(ub_maskbuf, "%s@*", b->mask);
                ubi->mask = ub_maskbuf;
            }
            else if (iter->type == HMT_IPCIDR)
            {
                ircsprintf(ub_maskbuf, "%s@%s", b->mask ? b->mask : "*",
                           cidr2string(rawip, prefix, 0));
                ubi->mask = ub_maskbuf;
            }

            iter->callback(iter->carg);
        }
    }
}

/* iterates over bans that match the specified flags */
static void
ub_iterate(u_short flags, u_short flagset, UserBanInfo *ubi, void (*callback)(void *), void *carg)
{
    UBIter iter;
    int i;

    iter.flags = flags & flagset;
    iter.flagset = flagset;
    iter.ubi = ubi;
    iter.callback = callback;
    iter.carg = carg;

    iter.type = HMT_WILD;
    ubcb_iterator(&iter, 0, 0, (void **)&ubl_wildhosts);

    iter.type = HMT_NAMEMASK;
    ubcb_iterator(&iter, 0, 0, (void **)&ubl_hostmasks);

    iter.type = HMT_NAME;
    for (i = 0; i < USERBAN_HASH_SIZE; i++)
        if (ubl_hostnames[i])
            ubcb_iterator(&iter, 0, 0, (void **)&ubl_hostnames[i]);

    iter.type = HMT_IPCIDR;
    patricia_walk(&ub_iptree, ubcb_iterator, &iter);
}


/* used with ks_dumpklines */
typedef struct {
    int fd;
    UserBanInfo *ubi;
} KSDump;

/* callback for ks_dumpklines */
static void
kscb_dumpkline(void *carg)
{
    KSDump *dump = carg;

    /* klines.c */
    extern void ks_write(int, char, UserBanInfo *);

    ks_write(dump->fd, '+', dump->ubi);
}

/*
 * Called from klines.c during a journal compaction.
 */
void
ks_dumpklines(int fd)
{
    KSDump ksd;
    UserBanInfo ubi;

    ksd.fd = fd;
    ksd.ubi = &ubi;

    /* find all bans that are local and persistent, but not in conf */
    ub_iterate(UBAN_LOCAL|UBAN_CONF|UBAN_PERSIST, UBAN_LOCAL|UBAN_PERSIST,
               &ubi, kscb_dumpkline, &ksd);
}    


/* used with userban_sendburst */
typedef struct {
    aClient *cptr;
    UserBanInfo *ubi;
} UBSend;

/* callback for userban_sendburst */
static void
ubcb_sendone(void *carg)
{
    UBSend *ubs;
    UserBanInfo *ubi;
    char flags[5] = {'+','N','P', 0, 0};

    ubs = carg;
    ubi = ubs->ubi;

    if (ubi->flags & UBAN_EXEMPT)
        flags[3] = 'E';

    sendto_one(ubs->cptr, ":%s USERBAN %s %s %d :%s", me.name, flags,
               ubi->mask, ubi->expirets, ubi->reason);
}

/*
 * Send all persistent network bans and ban exemptions to a server.
 * Called from m_server.c during netbursts.
 */
void
userban_sendburst(aClient *cptr)
{
    UBSend ubs;
    UserBanInfo ubi;

    ubs.cptr = cptr;
    ubs.ubi = &ubi;

    /* find all non-local persistent bans */
    ub_iterate(UBAN_PERSIST, UBAN_LOCAL|UBAN_PERSIST, &ubi, ubcb_sendone,
               &ubs);
}


/*
 * m_userban
 * Add or remove a network ban or ban exemption.
 *
 * parv[1]  - flags
 * parv[2]  - user@host mask
 *
 * Adds only:
 * parv[3]  - expiration timestamp
 * parv[4]  - reason (optional)
 */
int
m_userban(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    UserBanInfo ubi;
    int flags = UBAN_UPDATE;
    int adding;
    int rv = 0;
    char *reason = "<no reason>";
    char *mask;
    char *s;
    time_t expirets;

    if (!IsServer(cptr) || parc < 3)
        return 0;

    s = parv[1];

    switch (*s)
    {
        case '+': adding = 1; break;
        case '-': adding = 0; break;
        default: return 0;
    }

    while (*++s)
    {
        switch (*s)
        {
            case 'P': flags |= UBAN_PERSIST; break;
            case 'E': flags |= UBAN_EXEMPT; break;
            case 'N': flags &= ~UBAN_UPDATE; break;
        }
    }

    mask = parv[2];

    if (!adding)
    {
        /* pass along sanitized mask if possible */
        if (userban_del(mask, flags, &ubi) != UBAN_DEL_NOTFOUND)
            mask = ubi.mask;

        sendto_serv_butone(cptr, ":%s USERBAN %s %s", parv[0], parv[1], mask);
        return 0;
    }

    if (parc < 4)
        return 0;

    expirets = strtol(parv[3], NULL, 0);

    if (parc > 4 && !BadPtr(parv[4]))
        reason = parv[4];

    if (expirets < 0)
        expirets = 0;

    rv = userban_add(mask, reason, expirets, flags, &ubi);

    /* don't propagate duplicates from netbursts */
    if (rv == UBAN_ADD_DUPLICATE && !(flags & UBAN_UPDATE))
        return 0;

    /* complain but pass along invalid bans, all servers will yell */
    if (rv == UBAN_ADD_INVALID)
        sendto_realops("USERBAN: invalid ban %s %s from %s ignored", parv[1],
                       mask, parv[0]);
    else
        mask = ubi.mask;

    sendto_serv_butone(cptr, ":%s USERBAN %s %s %d :%s", parv[0], parv[1],
                       mask, expirets, reason);

    return 0;
}

