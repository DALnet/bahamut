/*
 *   clones.c - Clone detection and limiting
 *   Copyright (C) 2004 Trevor Talbot and
 *                      the DALnet coding team
 *
 *   See file AUTHORS in IRC package for additional names of
 *   the programmers.
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

/*
 * WARNING: code is chummy with throttle.c
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "blalloc.h"
#include "numeric.h"
#include "channel.h"

#include "throttle.h"
#include "clones.h"


#ifndef THROTTLE_ENABLE
extern BlockHeap *hashent_freelist;
#endif


static BlockHeap *cloneent_freelist;
static void *clones_hashtable;

CloneEnt *clones_list;


static CloneEnt *
get_clone(char *key, int create)
{
    CloneEnt *ce;

    if (!(ce = hash_find(clones_hashtable, key)) && create)
    {
        ce = BlockHeapALLOC(cloneent_freelist, CloneEnt);
        memset(ce, 0, sizeof(*ce));
        strcpy(ce->ent, key);
        hash_insert(clones_hashtable, ce);
        ce->next = clones_list;
        if (clones_list)
            clones_list->prev = ce;
        clones_list = ce;
    }

    return ce;
}

static void
del_clone(CloneEnt *ce)
{
    if (ce->next)
        ce->next->prev = ce->prev;
    if (ce->prev)
        ce->prev->next = ce->next;
    else
        clones_list = ce->next;
    hash_delete(clones_hashtable, ce);
    BlockHeapFree(cloneent_freelist, ce);
}


#ifdef THROTTLE_ENABLE
static void
get_clones(aClient *cptr, CloneEnt **ceip, CloneEnt **ce24, int create)
{
    char ip24[HOSTIPLEN+1];
    char *s;

    strcpy(ip24, cptr->hostip);
    /* deliberate core if strrchr fails -- we need a valid IP string */
    s = strrchr(ip24, '.');
    *++s = '*';
    *++s = 0;

    *ceip = get_clone(cptr->hostip, create);
    *ce24 = get_clone(ip24, create);
}

static int
report_clone(aClient *cptr, CloneEnt *ce, int limit, int global, int is24)
{
    if (global)
        sendto_realops_lev(REJ_LEV, "local clone %s!%s@%s (%s %d/%d global)",
                           cptr->name, cptr->user->username, cptr->user->host,
                           ce->ent, ce->gcount + 1, limit);
    else
        sendto_realops_lev(REJ_LEV, "local clone %s!%s@%s (%s %d/%d local %s)",
                           cptr->name, cptr->user->username, cptr->user->host,
                           ce->ent, ce->lcount + 1, limit,
                           cptr->user->allow->class->name);

    throttle_force(cptr->hostip);

    return (is24 ? 2 : 1);
}


/*
 * Checks a local client against the clone limits.
 * Returns 1 if IP/32 limit hit, 2 if IP/24 limit hit, 0 otherwise.
 */
int
clones_check(aClient *cptr)
{
    CloneEnt *ceip;
    CloneEnt *ce24;
    int       limit;

    get_clones(cptr, &ceip, &ce24, 0);

    if (ceip)
    {
        if (!(limit = cptr->user->allow->class->connfreq))
            limit = local_ip_limit;
        if (ceip->lcount >= limit)
            return report_clone(cptr, ceip, limit, 0, 0);

        if (!(limit = ceip->limit))
            limit = global_ip_limit;
        if (ceip->gcount >= limit)
            return report_clone(cptr, ceip, limit, 1, 0);
    }

    if (ce24)
    {
        if (!(limit = cptr->user->allow->class->ip24clones))
            limit = local_ip24_limit;
        if (ce24->lcount >= limit)
            return report_clone(cptr, ce24, limit, 0, 1);

        if (!(limit = ce24->limit))
            limit = global_ip24_limit;
        if (ce24->gcount >= limit)
            return report_clone(cptr, ce24, limit, 1, 1);
    }
    
    return 0;
}

/*
 * Adds a client to the clone list.
 */
void
clones_add(aClient *cptr)
{
    CloneEnt *ceip;
    CloneEnt *ce24;

    get_clones(cptr, &ceip, &ce24, 1);

    cptr->clone.prev = NULL;
    cptr->clone.next = ceip->clients;
    if (ceip->clients)
        ceip->clients->clone.prev = cptr;
    ceip->clients = cptr;

    ceip->gcount++;
    ce24->gcount++;

    if (MyConnect(cptr))
    {
        ceip->lcount++;
        ce24->lcount++;
    }
}

/*
 * Removes a client from the clone list.
 */
void
clones_remove(aClient *cptr)
{
    CloneEnt *ceip;
    CloneEnt *ce24;

    get_clones(cptr, &ceip, &ce24, 0);

    if (cptr->clone.next)
        cptr->clone.next->clone.prev = cptr->clone.prev;
    if (cptr->clone.prev)
        cptr->clone.prev->clone.next = cptr->clone.next;
    else
        ceip->clients = cptr->clone.next;

    ceip->gcount--;
    ce24->gcount--;

    /* !$%#&*%@ user state handling! */
    if (cptr->uplink == &me)
    {
        ceip->lcount--;
        ce24->lcount--;
    }

    if (!ceip->gcount && !ceip->limit)
        del_clone(ceip);

    if (!ce24->gcount && !ce24->limit)
        del_clone(ce24);
}
#endif  /* THROTTLE_ENABLE */

/*
 * Sets a global clone limit.  A limit of 0 reverts to default settings.
 */
void
clones_set(char *ent, int limit)
{
    CloneEnt *ce;

    if (strlen(ent) > HOSTIPLEN)
        return;

    if (limit < 1)
        limit = 0;

    ce = get_clone(ent, 1);
    ce->limit = limit;

    if (!ce->gcount && !ce->limit)
        del_clone(ce);
}


/*
 * Propagate global clone limits.
 */
void
clones_send(aClient *cptr)
{
    CloneEnt *ce;

    for (ce = clones_list; ce; ce = ce->next)
    {
        if (!ce->limit)
            continue;
        sendto_one(cptr, ":%s SVSCLONE %s %d", me.name, ce->ent, ce->limit);
    }
}

/*
 * Must be called AFTER throttle_init()
 */
void
clones_init(void)
{
#ifndef THROTTLE_ENABLE
    hashent_freelist = BlockHeapCreate(sizeof(hashent), 1024);
#endif
    cloneent_freelist = BlockHeapCreate(sizeof(CloneEnt), 1024);
    clones_hashtable = create_hash_table(THROTTLE_HASHSIZE,
                                         offsetof(CloneEnt, ent), HOSTIPLEN,
                                         2, (void *)strcmp);
}

