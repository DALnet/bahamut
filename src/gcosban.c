/************************************************************************
 *   IRC - Internet Relay Chat, src/gcosban.c
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

#include "gcosban.h"

/*
 * Took the original implementation by Lucas and diced it up a bit.
 *
 * Gcosbans are stored in 2 containers: a hashtable for full gcos, and a list
 * for wildcard masks.
 *
 * Nodes are used directly; there is no longer a separate uBanEnt.
 *
 *     -Quension [Aug 2006]
 */

typedef struct GcosBan GcosBan;

struct GcosBan {
    u_int    flags;     /* general flags */
    char     *mask;     /* gcos mask */
    char     *reason;   /* ban reason */
    GcosBan  *next;     /* linked list entry */
};


#define GCOSBAN_HASH_SIZE   257     /* prime */

GcosBan *gbl_full[GCOSBAN_HASH_SIZE];
GcosBan *gbl_wild;


static GcosBan *
gb_alloc(u_int flags, char *mask, char *reason)
{
    GcosBan *b = MyMalloc(sizeof(*b));

    memset(b, sizeof(*b), 0);

    b->flags = flags;
    DupString(b->mask, mask);
    DupString(b->reason, reason);

    return b;
}

static void
gb_free(GcosBan *b)
{
    MyFree(b->mask);
    MyFree(b->reason);
    MyFree(b);
}

static unsigned int
gb_hash(char *n)
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


static void
gbcb_add(GcosBan **list, u_int flags, char *mask, char *reason)
{
    GcosBan *b;

    for (b = *list; b; b = b->next)
    {
        if (b->flags == flags && !mycmp(b->mask, mask))
        {
            /* for duplicates, just update the ban reason */
            MyFree(b->reason);
            DupString(b->reason, reason);
            return;
        }
    }

    b = gb_alloc(flags, mask, reason);
    b->next = *list;
    *list = b;
}

static void
gbcb_del(GcosBan **list, u_int flags, char *mask)
{
    GcosBan *b;
    GcosBan *prev = NULL;

    for (b = *list; b; b = b->next)
    {
        if (b->flags == flags && !mycmp(b->mask, mask))
        {
            if (prev)
                prev->next = b->next;
            else
                *list = b->next;

            gb_free(b);
            break;
        }

        prev = b;
    }
}

static void
gbcb_massdel(GcosBan **list, u_int flags, char *wm)
{
    GcosBan *b;
    GcosBan *next;
    GcosBan *prev = NULL;

    for (b = *list; b; b = next)
    {
        next = b->next;

        if (b->flags == flags && (!wm || !match(wm, b->mask)))
        {
            if (prev)
                prev->next = next;
            else
                *list = next;

            gb_free(b);
            continue;
        }

        prev = b;
    }
}


int
gcosban_add(u_int flags, char *mask, char *reason)
{
    unsigned int idx;

    if (strlen(mask) > REALLEN)
        return GCBAN_ADD_INVALID;

    if (strchr(mask, '*') || strchr(mask, '?'))
        gbcb_add(&gbl_wild, flags, mask, reason);
    else
    {
        idx = gb_hash(mask) % GCOSBAN_HASH_SIZE;
        gbcb_add(&gbl_full[idx], flags, mask, reason);
    }

    return 0;
}

void
gcosban_del(u_int flags, char *mask)
{
    unsigned int idx;

    if (strchr(mask, '*') || strchr(mask, '?'))
        gbcb_del(&gbl_wild, flags, mask);
    else
    {
        idx = gb_hash(mask) % GCOSBAN_HASH_SIZE;
        gbcb_del(&gbl_full[idx], flags, mask);
    }
}

void
gcosban_massdel(u_int flags, char *wildmatch)
{
    int i;

    gbcb_massdel(&gbl_wild, flags, wildmatch);

    for (i = 0; i < GCOSBAN_HASH_SIZE; i++)
        if (gbl_full[i])
            gbcb_massdel(&gbl_full[i], flags, wildmatch);
}

char *
gcosban_check(char *gcos)
{
    GcosBan *b;
    unsigned int idx;

    idx = gb_hash(gcos) % GCOSBAN_HASH_SIZE;

    for (b = gbl_full[idx]; b; b = b->next)
        if (!mycmp(b->mask, gcos))
            return b->reason;

    for (b = gbl_wild; b; b = b->next)
        if (!match(b->mask, gcos))
            return b->reason;

    return NULL;
}


static void
gbcb_sendlist(aClient *cptr, GcosBan *b)
{
    int len;

    while (b)
    {
        len = strlen(b->mask);

        sendto_one(cptr, ":%s SGLINE %d :%s:%s", me.name, len, b->mask,
                   b->reason);

        b = b->next;
    }
}

void
gcosban_sendburst(aClient *cptr)
{
    int i;

    for (i = 0; i < GCOSBAN_HASH_SIZE; i++)
        gbcb_sendlist(cptr, gbl_full[i]);

    gbcb_sendlist(cptr, gbl_wild);
}

