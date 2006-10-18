/*
 *   patricia.c - IPv4 PATRICIA / Crit-Bit trie
 *   Copyright (C) 2005 Trevor Talbot and
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

/*
 * This implements a compressed binary tree for longest-prefix matching of
 * IPv4 addresses.  It's not quite a generic implementation: it contains
 * functionality oriented toward the userbans and clones code.
 *
 * All IPv4 addresses must be in network byte order.
 *
 * A tree node contains two critical pieces of information: a prefix length,
 * and a pre-masked key.  The nodes are arranged in a binary search tree,
 * sorted by key from shortest prefix to longest.  The prefix is stored at each
 * node to allow for tree compression -- nodes without values or branches are
 * omitted.
 *
 * During a search, the search key is masked with the node prefix and compared
 * to the node key.  If they are unequal, there is no match; the search is
 * aborted.  If there is a match, the value of the node (if any) is acted upon,
 * then the next branch is sought.  The next bit (prefix + 1) is tested in the
 * search key, and the 0 or 1 branch of the node is taken appropriately.
 *
 *     node key/prefix        search key 127.203.15.2
 * ------------------------   -------------------------------------------
 *          127/8             compare 127.203.15.2/8 (127) to 127
 *            |               match, so branch:
 *     0------+------1        test 9th prefix bit of 127.203.15.2 (1)
 *     |             |        take branch 1 to node 127.128/9
 * 127.0/16      127.128/9    compare 127.203.15.2/9 (127.128) to 127.128
 *                            match, so ...
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "inet.h"

#include "patricia.h"


/* a tree node */
struct Patricia {
    u_int        key;       /* prefix-masked IP key */
    int          prefix;    /* key prefix length (0 - 32) */
    void        *value;     /* user value if there is an entry here */
    Patricia    *parent;    /* parent node */
    Patricia    *branch0;   /* branch on 0 bit test */
    Patricia    *branch1;   /* branch on 1 bit test */
};


/* prefix to netmask map */
static u_int prefixmask[33];

/* bit number to value mask map */
static u_int branchmask[33];


/* find the longest common prefix for two keys */
static int
patricia_commonprefix(u_int key1, u_int key2)
{
    int count = 32;
    u_int mask;

    mask = ntohl(key1) ^ ntohl(key2);

    while (mask)
    {
        mask >>= 1;
        count--;
    }

    return count;
}

/* allocate a node */
static Patricia *
patricia_alloc(u_int key, int prefix, Patricia *parent)
{
    Patricia *p = MyMalloc(sizeof(*p));

    memset(p, 0, sizeof(*p));

    p->key = key;
    p->prefix = prefix;
    p->parent = parent;

    return p;
}

/* create a new node below the specified one */
static Patricia *
patricia_createbelow(Patricia *node, u_int key, int prefix)
{
    Patricia *new = patricia_alloc(key, prefix, node);

    if (key & branchmask[node->prefix])
        node->branch1 = new;
    else
        node->branch0 = new;

    return new;
}    

/* create a new node above the specified one */
static Patricia *
patricia_createabove(Patricia **root, Patricia *node, u_int key, int prefix)
{
    Patricia *new = patricia_alloc(key, prefix, node->parent);

    if (new->parent)
    {
        if (key & branchmask[new->parent->prefix])
            new->parent->branch1 = new;
        else
            new->parent->branch0 = new;
    }
    else
        *root = new;

    if (node->key & branchmask[prefix])
        new->branch1 = node;
    else
        new->branch0 = node;

    node->parent = new;

    return new;
}

/* delete the specified node, returning a pointer to deepest remaining node */
static Patricia *
patricia_destroynode(Patricia **root, Patricia *node)
{
    Patricia *parent = node;
    Patricia *child;

    /* delete loop */
    while (1)
    {
        /* contains a value */
        if (node->value)
            break;

        /* full branch */
        if (node->branch0 && node->branch1)
            break;

        parent = node->parent;
        child = node->branch0 ? node->branch0 : node->branch1;

        /* cut self out, relink parent and child if present */
        if (parent)
        {
            if (node->key & branchmask[parent->prefix])
                parent->branch1 = child;
            else
                parent->branch0 = child;
        }
        else
            *root = child;

        if (child)
            child->parent = parent;

        MyFree(node);

        /* if there was a child, we're done */
        if (child)
            break;

        /* no child, so parent might be redundant too -- delete it next loop */
        if (!(node = parent))
            break;
    }

    return parent;
}


/*
 * Generic search of the tree for all values that match the supplied key.
 * Calls the supplied callback with carg for each value, in order of shortest
 * prefix to longest.
 */
void
patricia_search(Patricia *node, u_int key, void (*callback)(void *, void *), void *carg)
{
    while (node)
    {
        if ((key & prefixmask[node->prefix]) != node->key)
            break;

        if (node->value)
            callback(carg, node->value);

        node = (key & branchmask[node->prefix])
               ? node->branch1 : node->branch0;
    }
}

/*
 * Generic add of a new value for a key/prefix to the tree.  Calls the supplied
 * callback with carg and a pointer to the value storage slot.  Return value is
 * that of the callback.
 */
int
patricia_add(Patricia **root, u_int key, int prefix, int (*callback)(void *, void **), void *carg)
{
    Patricia *node = *root;
    Patricia *next = NULL;

    /* sanity check, since we record the key */
    key &= prefixmask[prefix];

    /* easiest case, empty tree */
    if (!node)
    {
        node = patricia_alloc(key, prefix, NULL);
        *root = node;
        return callback(carg, &node->value);
    }

    /* populated tree, search for a place */
    while (1)
    {
        /* this node is too deep */
        if (node->prefix > prefix)
        {
            next = patricia_createabove(root, node, key, prefix);
            return callback(carg, &next->value);
        }

        /* this node is on the wrong branch */
        if ((key & prefixmask[node->prefix]) != node->key)
        {
            u_int nk;
            int np;

            /* create a new branch */
            np = patricia_commonprefix(key, node->key);
            nk = key & prefixmask[np];
            node = patricia_createabove(root, node, nk, np);

            /* create our new node on that branch */
            next = patricia_createbelow(node, key, prefix);
            return callback(carg, &next->value);
        }

        /* exact match */
        if (node->prefix == prefix)
            return callback(carg, &node->value);

        next = (key & branchmask[node->prefix])
               ? node->branch1 : node->branch0;

        /* no more nodes below, we'll be the first */
        if (!next)
        {
            next = patricia_createbelow(node, key, prefix);
            return callback(carg, &next->value);
        }

        /* continue the loop */
        node = next;
    }
}

/*
 * Generic delete of a value for a key/prefix from the tree.  Calls the
 * supplied callback with carg and a pointer to the value slot.  Return value
 * is PATDEL_NOTFOUND if the key/prefix is not found; the return value of the
 * callback otherwise.
 */
int
patricia_del(Patricia **root, u_int key, int prefix, int (*callback)(void *, void **), void *carg)
{
    Patricia *node = *root;
    int rv = PATDEL_NOTFOUND;

    /* search loop */
    while (node)
    {
        if (node->prefix > prefix)
            break;

        if ((key & prefixmask[node->prefix]) != node->key)
            break;

        if (node->prefix == prefix)
        {
            if (!node->value)
                break;

            rv = callback(carg, &node->value);

            if (!node->value)
                patricia_destroynode(root, node);

            break;
        }

        node = (key & branchmask[node->prefix])
               ? node->branch1 : node->branch0;
    }

    return rv;
}

/*
 * Generic walk of the tree.  Calls the supplied callback with carg, the key,
 * prefix, and a pointer to the value slot.  Values may be deleted during the
 * walk.
 */
void
patricia_walk(Patricia **root, void (*callback)(void *, u_int, int, void **), void *carg)
{
    struct {
        Patricia *node;
        int       branch;
    } stack[33];
    int idx = 0;
    Patricia *n = *root;

    while (idx >= 0)
    {
        /* go deep on branch0, callback on values */
        while (n)
        {
            stack[idx].node = n;
            stack[idx].branch = 0;

            if (n->value)
            {
                callback(carg, n->key, n->prefix, &n->value);

                /* callback deleted value */
                if (!n->value)
                {
                    n = patricia_destroynode(root, n);

                    /* no remaining node, restart from root */
                    if (!n)
                    {
                        idx = 0;
                        n = *root;
                        continue;
                    }

                    /* move up to remaining node to start digging again */
                    while (stack[idx].node != n)
                        idx--;
                }
            }

            /* branch0 */
            n = n->branch0;
            idx++;
        }

        /* up stack, branch1 */
        while (--idx >= 0)
        {
            if (!stack[idx].branch && stack[idx].node->branch1)
            {
                stack[idx].branch = 1;
                n = stack[idx].node->branch1;
                idx++;
                break;
            }
        }
    }
}


void
patricia_init(void)
{
    int i;
    u_int bitval;

    /* Set up netmask-style prefixmask[], and bitmask-style branchmask[].
       prefixmask[0] = 0, branchmask[32] = 0 */
    for (i = 1; i < 33; i++)
    {
        bitval = 1 << (32 - i);
        prefixmask[i] = htonl(0xFFFFFFFF - bitval + 1);
        branchmask[i - 1] = htonl(bitval);
    }
}

