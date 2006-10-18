/************************************************************************
 *   IRC - Internet Relay Chat, src/simban.c
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

#include "simban.h"
#include "ircstrings.h"

/*
 * Took the original implementation by Lucas and diced it up a bit.
 *
 * Simbans are stored in 3 containers: a combined hashtable for full nick/chan,
 * and a list each for wildcard masks.
 *
 * Nodes are used directly; there is no longer a separate uBanEnt.
 *
 *     -Quension [Aug 2006]
 */

typedef struct SimBan SimBan;

struct SimBan {
    u_int    flags;     /* general flags */
    time_t   expirets;  /* expiration timestamp */
    int      maxslide;  /* max duration for sliding expiry times */
    char    *mask;      /* name or mask */
    char    *reason;    /* ban reason */
    SimBan  *next;      /* linked list entry */
};


#define SIMBAN_HASH_SIZE    7979    /* prime */

SimBan *sbl_names[SIMBAN_HASH_SIZE];
SimBan *sbl_wildnicks;
SimBan *sbl_wildchans;


/* flags to look at during duplicate checks */
#define SB_DUPFLAGS (SBAN_CHAN|SBAN_CONF)


/* allocate a simban */
static SimBan *
sb_alloc(u_int flags, time_t expirets, char *reason)
{
    SimBan *b = MyMalloc(sizeof(*b));

    memset(b, sizeof(*b), 0);

    b->flags = flags;
    b->expirets = expirets;
    DupString(b->reason, reason);

    return b;
}

/* free a simban */
static void
sb_free(SimBan *b)
{
    MyFree(b->mask);
    MyFree(b->reason);
    MyFree(b);
}

/* non-wildcard hash */
static unsigned int
sb_hash(char *n)
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


/* callback for adding a simban to a list */
static int
sbcb_add(SimBan **list, u_int flags, time_t expirets, int maxslide, char *mask, char *reason)
{
    SimBan *b;

    for (b = *list; b; b = b->next)
    {
        if ((b->flags & SB_DUPFLAGS) == (flags & SB_DUPFLAGS)
            && !mycmp(b->mask, mask))
        {
            if (flags & SBAN_UPDATE)
            {
                /* update the existing ban */
                b->flags = (flags & ~SBAN_UPDATE);
                b->expirets = expirets;
                b->maxslide = maxslide;
                MyFree(b->reason);
                DupString(b->reason, reason);
            }

            /* ban exists, we're done */
            return SBAN_ADD_DUPLICATE;
        }
    }

    /* no existing ban, create a new one */
    flags &= ~SBAN_UPDATE;
    b = sb_alloc(flags, expirets, reason);
    b->maxslide = maxslide;
    DupString(b->mask, mask);
    b->next = *list;
    *list = b;

    return 0;
}

/* callback for removing a simban from a list */
static void
sbcb_del(SimBan **list, u_int flags, char *mask)
{
    SimBan *b;
    SimBan *prev = NULL;

    for (b = *list; b; b = b->next)
    {
        if ((b->flags & SB_DUPFLAGS) == flags && !mycmp(b->mask, mask))
        {
            if (prev)
                prev->next = b->next;
            else
                *list = b->next;

            sb_free(b);
            break;
        }

        prev = b;
    }
}

/* callback for mass deletions from a list */
static void
sbcb_massdel(SimBan **list, time_t ts, u_int flags, u_int flagset, char *wm)
{
    SimBan *b;
    SimBan *next;
    SimBan *prev = NULL;

    for (b = *list; b; b = next)
    {
        next = b->next;

        if (b->expirets < ts
            && (b->flags & flagset) == flags
            && (!wm || !match(wm, b->mask)))
        {

            if (prev)
                prev->next = next;
            else
                *list = next;

            sb_free(b);
            continue;
        }
        
        prev = b;
    }
}


/*
 * Add a new simban.  Requires a nick or channel mask, a reason, and
 * expiration time, a maximum expiration penalty time, and optional flags.
 * An expiration time of 0 creates a permanent ban.
 * Returns SBAN_ADD_INVALID for an invalid mask, or SBAN_ADD_DUPLICATE if
 * this ban already exists; 0 otherwise.
 */
int
simban_add(char *mask, char *reason, time_t expirets, int slide, u_int flags)
{
    unsigned int idx;
    SimBan **list = NULL;
    int opts = 0;

    if (!expirets)
        expirets = INT_MAX; /* INT_MAX is permanent */

    /* penalty duration is capped at 24 hours */
    if (slide < 0)
        slide = 0;
    if (slide > 24*60*60)
        slide = 24*60*60;

    if (strchr(mask, '*') || strchr(mask, '?'))
        opts = VALIDATE_MASK;

    if (flags & SBAN_CHAN)
    {
        if (!validate_channel(mask, opts))
            return SBAN_ADD_INVALID;

        if (opts)
            list = &sbl_wildchans;
    }
    else
    {
        if (!validate_nick(mask, opts))
            return SBAN_ADD_INVALID;

        if (opts)
            list = &sbl_wildnicks;
    }

    if (!list)
    {
        idx = sb_hash(mask) % SIMBAN_HASH_SIZE;
        list = &sbl_names[idx];
    }

    return sbcb_add(list, flags, expirets, slide, mask, reason);
}

/*
 * Delete a simban.  Requires nick/channel ban mask and flags indicating
 * the type.
 */
void
simban_del(char *mask, u_int flags)
{
    unsigned int idx;

    flags &= SB_DUPFLAGS;

    if (strchr(mask, '*') || strchr(mask, '?'))
    {
        if (flags & SBAN_CHAN)
            sbcb_del(&sbl_wildchans, flags, mask);
        else
            sbcb_del(&sbl_wildnicks, flags, mask);
        return;
    }

    idx = sb_hash(mask) % SIMBAN_HASH_SIZE;
    sbcb_del(&sbl_names[idx], flags, mask);
}

/*
 * Mass delete simbans based on expiration time and/or specific flags
 * and/or a matching wildcard mask.  A zero timestamp ignores expiration
 * time; zero flagset ignores flags; NULL wildmatch ignores ban masks.
 */
void
simban_massdel(time_t ts, u_int flags, u_int flagset, char *wildmatch)
{
    int i;

    if (!ts)
        ts = INT_MAX;
    flags &= flagset;

    sbcb_massdel(&sbl_wildchans, ts, flags, flagset, wildmatch);
    sbcb_massdel(&sbl_wildnicks, ts, flags, flagset, wildmatch);

    for (i = 0; i < SIMBAN_HASH_SIZE; i++)
        if (sbl_names[i])
            sbcb_massdel(&sbl_names[i], ts, flags, flagset, wildmatch);
}


/* common workhorse for checknick() and checkchannel() */
static SimBanInfo *
sb_check(char *what, u_int flags)
{
    static SimBanInfo sbi;
    unsigned int idx;
    SimBan *b;

    idx = sb_hash(what) % SIMBAN_HASH_SIZE;
    for (b = sbl_names[idx]; b; b = b->next)
        if (!mycmp(b->mask, what))
            break;

    if (!b)
    {
        if (flags & SBAN_CHAN)
        {
            for (b = sbl_wildchans; b; b = b->next)
                if (!match(b->mask, what))
                    break;
        }
        else
        {
            for (b = sbl_wildnicks; b; b = b->next)
                if (!match(b->mask, what))
                    break;
        }
    }

    if (b)
    {
        sbi.mask = b->mask;
        sbi.reason = b->reason;
        sbi.punish = 0;
        sbi.plimit = 0;

        /* slide expiration time according to use attempts */
        if (b->maxslide)
        {
            /* maximum expiration time for penalty slides */
            time_t maxts = NOW + b->maxslide;

            /* A typical use case would have a large expiration time and a
             * small max penalty duration.  Trying to apply sliding too soon
             * would result in lowering the original expiration time, hence
             * this check. */
            if (b->expirets <= maxts)
            {
                /* continous hold point is one attempt every 9 seconds */
                if ((maxts - b->expirets) >= 9)
                    b->expirets += 9;
                else
                {
                    b->expirets = maxts;
                    sbi.plimit = 1;
                }
            }
        }

        if (b->flags & SBAN_PUNISH)
            sbi.punish = 1;
        
        return &sbi;
    }

    return NULL;
}

/*
 * Checks whether a nick matches any simbans.  Returns a pointer to a static
 * SimBanInfo if there's a match; NULL otherwise.
 */
SimBanInfo *
simban_checknick(char *nick)
{
    return sb_check(nick, 0);
}

/*
 * Checks whether a channel name matches and simbans.  Returns a pointer
 * to a static SimBanInfo if there's a match; NULL otherwise.
 */
SimBanInfo *
simban_checkchannel(char *name)
{
    return sb_check(name, SBAN_CHAN);
}


/* used during simban iteration */
typedef struct {
    u_int flags;
    u_int flagset;
    void (*callback)(void *, SimBan *);
    void *carg;
} SBIter;

/* callback for iteration */
static void
sbcb_iterator(SBIter *iter, SimBan *list)
{
    SimBan *b;

    for (b = list; b; b = b->next)
        if ((b->flags & iter->flagset) == iter->flags)
            iter->callback(iter->carg, b);
}

/* iterate over simbans that match flags */
static void
sb_iterate(u_int flags, u_int flagset, void (*callback)(void *, SimBan *), void *carg)
{
    SBIter iter;
    int i;

    iter.flags = flags & flagset;
    iter.flagset = flagset;
    iter.callback = callback;
    iter.carg = carg;

    for (i = 0; i < SIMBAN_HASH_SIZE; i++)
        if (sbl_names[i])
            sbcb_iterator(&iter, sbl_names[i]);

    sbcb_iterator(&iter, sbl_wildnicks);
    sbcb_iterator(&iter, sbl_wildchans);
}


/* callback to send a simban to a server during netburst */
static void
sbcb_sendone(void *arg, SimBan *b)
{
    aClient *cptr = arg;
    char flags[6];
    int i = 0;

    if (b->flags & SBAN_COMPAT)
    {
        sendto_one(cptr, ":%s SQLINE %s :%s", me.name, b->mask, b->reason);
        return;
    }

    flags[i++] = '+';
    flags[i++] = 'N';
    flags[i++] = 'P';
    if (b->flags & SBAN_CHAN)
        flags[i++] = 'C';
    if (b->flags & SBAN_PUNISH)
        flags[i++] = 'S';
    flags[i] = 0;

    sendto_one(cptr, ":%s SIMBAN %s %s %d %d :%s", flags, b->mask,
               (b->expirets == INT_MAX) ? 0 : b->expirets,
               b->maxslide, b->reason);
}

/*
 * Sends all persistent simbans to a server.
 * Called from m_server.c during netbursts.
 */
void
simban_sendburst(aClient *cptr)
{
    sb_iterate(SBAN_PERSIST, SBAN_CONF|SBAN_PERSIST, sbcb_sendone, cptr);
}


/*
 * m_simban
 * Add or remove a nick or channel ban.
 *
 * parv[1]  - flags
 * parv[2]  - mask
 *
 * Adds only:
 * parv[3]  - expiration timestamp
 * parv[4]  - maximum expiration penalty time in seconds
 * parv[5]  - reason (optional)
 */
int
m_simban(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    u_int flags = SBAN_UPDATE;
    time_t expirets;
    int maxslide;
    int adding;
    int wild = 0;
    int rv;
    char *reason = "reserved";
    char *mask;
    char *s;

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
            case 'C': flags |= SBAN_CHAN; break;
            case 'P': flags |= SBAN_PERSIST; break;
            case 'S': flags |= SBAN_PUNISH; break;
            case 'N': flags &= ~SBAN_UPDATE; break;
            case 'W': wild = 1; break;
        }
    }

    mask = parv[2];

    if (!adding)
    {
        if (wild)
            simban_massdel(0, flags, SBAN_CHAN, mask);
        else
            simban_del(mask, flags);

        sendto_serv_butone(cptr, ":%s SIMBAN %s %s", parv[0], parv[1], parv[2]);
        return 0;
    }

    if (parc < 5)
        return 0;

    expirets = strtol(parv[3], NULL, 0);
    maxslide = strtol(parv[4], NULL, 0);

    if (parc > 5 && !BadPtr(parv[5]))
        reason = parv[5];

    if (expirets < 0)
        expirets = 0;

    rv = simban_add(mask, reason, expirets, maxslide, flags);

    /* don't propagate duplicates from netbursts */
    if (rv == SBAN_ADD_DUPLICATE && !(flags & SBAN_UPDATE))
        return 0;

    /* complain but pass along invalid bans, all servers will yell */
    if (rv == SBAN_ADD_INVALID)
        sendto_realops("SIMBAN: invalid ban %s %s from %s ignored", parv[1],
                       mask, parv[0]);

    sendto_serv_butone(cptr, ":%s SIMBAN %s %s %d %d :%s", parv[0], parv[1],
                       mask, expirets, maxslide, reason);

    return 0;
}

