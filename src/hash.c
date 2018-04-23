/************************************************************************
 *   IRC - Internet Relay Chat, src/hash.c
 *   Copyright (C) 1991 Darren Reed
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

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "hash.h"
#include "h.h"
#include "memcount.h"

static aHashEntry clientTable[U_MAX];
static aHashEntry channelTable[CH_MAX];

/*
 * look in whowas.c for the missing ...[WW_MAX]; entry - Dianora
 *
 * Hashing.
 * 
 * The server uses a chained hash table to provide quick and efficient
 * hash table mantainence (providing the hash function works evenly
 * over the input range).  The hash table is thus not susceptible to
 * problems of filling all the buckets or the need to rehash. It is
 * expected that the hash table would look somehting like this during
 * use: +-----+    +-----+    +-----+   +-----+ 
 *   ---| 224 |----| 225 |----| 226 |---| 227 |--- 
 *      +-----+    +-----+    +-----+   +-----+ 
 *         |          |          | 
 *      +-----+    +-----+    +-----+ 
 *      |  A  |    |  C  |    |  D  | 
 *      +-----+    +-----+    +-----+ 
 *         | 
 *      +-----+ 
 *      |  B  | 
 *      +-----+
 * 
 * A - GOPbot, B - chang, C - hanuaway, D - *.mu.OZ.AU
 * 
 * The order shown above is just one instant of the server.  Each time a
 * lookup is made on an entry in the hash table and it is found, the
 * entry is moved to the top of the chain.
 * 
 * ^^^^^^^^^^^^^^^^ **** Not anymore - Dianora
 * 
 */

unsigned hash_nick_name(char *nname)
{
    unsigned hash = 0;
    int     hash2 = 0;
    int     ret;
    char    lower;

    while (*nname)
    {
	lower = ToLower(*nname);
	hash = (hash << 1) + lower;
	hash2 = (hash2 >> 1) + lower;
	nname++;
    }
    ret = ((hash & U_MAX_INITIAL_MASK) << BITS_PER_COL) +
	(hash2 & BITS_PER_COL_MASK);
    return ret;
}

/*
 * hash_channel_name
 * 
 * calculate a hash value on at most the first 30 characters of the
 * channel name. Most names are short than this or dissimilar in this
 * range. There is little or no point hashing on a full channel name
 * which maybe 255 chars long.
 */
int hash_channel_name(char *name)
{
    unsigned int hash = 0;
    int hash2 = 0;
    char lower;

    while (*name)
    {
	lower = ToLower(*name);
	hash = (hash << 1) + lower;
	hash2 = (hash2 >> 1) + lower;
	name++;
    }
    return ((hash & CH_MAX_INITIAL_MASK) << BITS_PER_COL) +
	(hash2 & BITS_PER_COL_MASK);
}

unsigned int hash_whowas_name(char *name)
{
    unsigned char *nname = (unsigned char *) name;
    unsigned int hash = 0;
    int hash2 = 0;
    int ret;
    char lower;

    while (*nname)
    {
	lower = ToLower(*nname);
	hash = (hash << 1) + lower;
	hash2 = (hash2 >> 1) + lower;
	nname++;
    }
    ret = ((hash & WW_MAX_INITIAL_MASK) << BITS_PER_COL) +
	(hash2 & BITS_PER_COL_MASK);
    return ret;
}

/*
 * clear_*_hash_table
 * 
 * Nullify the hashtable and its contents so it is completely empty.
 */

void clear_client_hash_table()
{
    memset((char *) clientTable, '\0', sizeof(aHashEntry) * U_MAX);
}

void clear_channel_hash_table()
{
    memset((char *) channelTable, '\0', sizeof(aHashEntry) * CH_MAX);
}

/* add_to_client_hash_table */
int add_to_client_hash_table(char *name, aClient *cptr)
{
    int     hashv;
    
    hashv = hash_nick_name(name);
    cptr->hnext = (aClient *) clientTable[hashv].list;
    clientTable[hashv].list = (void *) cptr;
    clientTable[hashv].links++;
    clientTable[hashv].hits++;
    return 0;
}

/* add_to_channel_hash_table */
int add_to_channel_hash_table(char *name, aChannel *chptr)
{
    int     hashv;

    hashv = hash_channel_name(name);
    chptr->hnextch = (aChannel *) channelTable[hashv].list;
    channelTable[hashv].list = (void *) chptr;
    channelTable[hashv].links++;
    channelTable[hashv].hits++;
    return 0;
}

/* del_from_client_hash_table */
int
del_from_client_hash_table(char *name, aClient *cptr)
{
    aClient *tmp, *prev = NULL;
    int     hashv;

    hashv = hash_nick_name(name);
    for (tmp = (aClient *) clientTable[hashv].list; tmp; tmp = tmp->hnext)
    {
	if (tmp == cptr)
	{
	    if (prev)
		prev->hnext = tmp->hnext;
	    else
		clientTable[hashv].list = (void *) tmp->hnext;
	    tmp->hnext = NULL;
	    if (clientTable[hashv].links > 0)
	    {
		clientTable[hashv].links--;
		return 1;
	    }
	    else
		/*
		 * Should never actually return from here and if we do it
		 * is an error/inconsistency in the hash table.
		 */
		return -1;
	}
	prev = tmp;
    }
    return 0;
}

/* del_from_channel_hash_table */
int del_from_channel_hash_table(char *name, aChannel *chptr)
{
    aChannel *tmp, *prev = NULL;
    int     hashv;
    
    hashv = hash_channel_name(name);
    for (tmp = (aChannel *) channelTable[hashv].list; tmp;
	 tmp = tmp->hnextch)
    {
	if (tmp == chptr)
	{
	    if (prev)
		prev->hnextch = tmp->hnextch;
	    else
		channelTable[hashv].list = (void *) tmp->hnextch;
	    tmp->hnextch = NULL;
	    if (channelTable[hashv].links > 0)
	    {
		channelTable[hashv].links--;
		return 1;
	    }
	    else
		return -1;
	}
	prev = tmp;
    }
    return 0;
}

/* hash_find_client */
aClient *hash_find_client(char *name, aClient *cptr)
{
    aClient *tmp;
    aHashEntry *tmp3;
    int hashv;
    
    hashv = hash_nick_name(name);
    tmp3 = &clientTable[hashv];
    /* Got the bucket, now search the chain. */
    for (tmp = (aClient *) tmp3->list; tmp; tmp = tmp->hnext)
	if (mycmp(name, tmp->name) == 0) 
	{
	    return (tmp);
	}
    return (cptr);
    /*
     * If the member of the hashtable we found isnt at the top of its
     * chain, put it there.  This builds a most-frequently used order
     * into the chains of the hash table, giving speedier lookups on
     * those nicks which are being used currently.  This same block of
     * code is also used for channels and servers for the same
     * performance reasons.
     * 
     * I don't believe it does.. it only wastes CPU, lets try it and
     * see....
     * 
     * - Dianora
     */
}

/*
 * hash_find_nickserver
 */
aClient *hash_find_nickserver(char *name, aClient *cptr)
{
    aClient *tmp;
    aHashEntry *tmp3;
    int hashv;
    char *serv;

    serv = strchr(name, '@');
    *serv++ = '\0';
    hashv = hash_nick_name(name);
    tmp3 = &clientTable[hashv];
    /* Got the bucket, now search the chain. */
    for (tmp = (aClient *) tmp3->list; tmp; tmp = tmp->hnext)
	if (mycmp(name, tmp->name) == 0 && tmp->user &&
	    mycmp(serv, tmp->user->server) == 0)
	{
	    *--serv = '\0';
	    return (tmp);
	}
    
    *--serv = '\0';
    return (cptr);
}

/* hash_find_server*/
aClient *hash_find_server(char *server, aClient *cptr)
{
    aClient *tmp;
    aHashEntry *tmp3;
    
    int         hashv;
    
    hashv = hash_nick_name(server);
    tmp3 = &clientTable[hashv];

    for (tmp = (aClient *) tmp3->list; tmp; tmp = tmp->hnext)
    {
	if (!IsServer(tmp) && !IsMe(tmp))
	    continue;
	if (mycmp(server, tmp->name) == 0)
	{
	    return (tmp);
	}
    }
    
    /*
     * Whats happening in this next loop ? Well, it takes a name like
     * foo.bar.edu and proceeds to earch for *.edu and then *.bar.edu.
     * This is for checking full server names against masks although it
     * isnt often done this way in lieu of using matches().
     */
    return (cptr);
}

/* hash_find_channel */
aChannel *hash_find_channel(char *name, aChannel *chptr)
{
    int         hashv;
    aChannel *tmp;
    aHashEntry *tmp3;
    
    hashv = hash_channel_name(name);
    tmp3 = &channelTable[hashv];
    
    for (tmp = (aChannel *) tmp3->list; tmp; tmp = tmp->hnextch)
	if (mycmp(name, tmp->chname) == 0)
	{
	    return (tmp);
	}
    return chptr;
}

/*
 * NOTE: this command is not supposed to be an offical part of the ircd
 * protocol.  It is simply here to help debug and to monitor the
 * performance of the hash functions and table, enabling a better
 * algorithm to be sought if this one becomes troublesome. -avalon
 * 
 * Needs rewriting for DOUGH_HASH, consider this a place holder until
 * thats done. Hopefully for hybrid-5, if not. tough. - Dianora
 * 
 */

int m_hash(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    return 0;
}

/*
 * Rough figure of the datastructures for notify:
 *
 * NOTIFY HASH      cptr1
 *   |                |- nick1
 * nick1-|- cptr1     |- nick2
 *   |   |- cptr2                cptr3
 *   |   |- cptr3   cptr2          |- nick1
 *   |                |- nick1
 * nick2-|- cptr2     |- nick2
 *       |- cptr1
 *
 * add-to-notify-hash-table:
 * del-from-notify-hash-table:
 * hash-del-notify-list:
 * hash-check-notify:
 * hash-get-notify:
 */

static   aWatch  *watchTable[WATCHHASHSIZE];

void clear_watch_hash_table(void)
{
    memset((char *)watchTable, '\0', sizeof(watchTable));
}


/* add_to_watch_hash_table */
int   add_to_watch_hash_table(char *nick, aClient *cptr)
{
    int   hashv;
    aWatch  *anptr;
    Link  *lp;
    
    
    /* Get the right bucket... */
    hashv = hash_nick_name(nick)%WATCHHASHSIZE;
    
    /* Find the right nick (header) in the bucket, or NULL... */
    if ((anptr = (aWatch *)watchTable[hashv]))
	while (anptr && mycmp(anptr->nick, nick))
	    anptr = anptr->hnext;
    
    /* If found NULL (no header for this nick), make one... */
    if (!anptr)
    {
	anptr = (aWatch *)MyMalloc(sizeof(aWatch)+strlen(nick));
	anptr->lasttime = timeofday;
	strcpy(anptr->nick, nick);
	
	anptr->watch = NULL;
	
	anptr->hnext = watchTable[hashv];
	watchTable[hashv] = anptr;
    }
    /* Is this client already on the watch-list? */
    if ((lp = anptr->watch))
	while (lp && (lp->value.cptr != cptr))
	    lp = lp->next;
    
    /* No it isn't, so add it in the bucket and client addint it */
    if (!lp)
    {
	lp = anptr->watch;
	anptr->watch = make_link();
	anptr->watch->value.cptr = cptr;
	anptr->watch->next = lp;
	
	lp = make_link();
	lp->next = cptr->watch;
	lp->value.wptr = anptr;
	cptr->watch = lp;
	cptr->watches++;
    }
    
    return 0;
}

/* hash_check_watch */
int hash_check_watch(aClient *cptr, int reply)
{
    int   hashv;
    aWatch  *anptr;
    Link  *lp;
    
    
    /* Get us the right bucket */
    hashv = hash_nick_name(cptr->name)%WATCHHASHSIZE;
	
    /* Find the right header in this bucket */
    if ((anptr = (aWatch *)watchTable[hashv]))
	while (anptr && mycmp(anptr->nick, cptr->name))
	    anptr = anptr->hnext;
    if (!anptr)
	return 0;   /* This nick isn't on watch */
    
    /* Update the time of last change to item */
    anptr->lasttime = NOW;
    
    /* Send notifies out to everybody on the list in header */
    for (lp = anptr->watch; lp; lp = lp->next)
	sendto_one(lp->value.cptr, rpl_str(reply), me.name,
		   lp->value.cptr->name, cptr->name,
		   (IsPerson(cptr)?cptr->user->username:"<N/A>"),
#ifdef USER_HOSTMASKING
		   (IsPerson(cptr)?IsUmodeH(cptr)?cptr->user->mhost:cptr->user->host:"<N/A>"),
#else
		   (IsPerson(cptr)?cptr->user->host:"<N/A>"),
#endif
		   anptr->lasttime, cptr->info);
    
    return 0;
}

/* hash_get_watch */
aWatch  *hash_get_watch(char *name)
{
    int   hashv;
    aWatch  *anptr;
    
    
    hashv = hash_nick_name(name)%WATCHHASHSIZE;
    
    if ((anptr = (aWatch *)watchTable[hashv]))
	while (anptr && mycmp(anptr->nick, name))
	    anptr = anptr->hnext;
    
    return anptr;
}

/* del_from_watch_hash_table */
int   del_from_watch_hash_table(char *nick, aClient *cptr)
{
    int   hashv;
    aWatch  *anptr, *nlast = NULL;
    Link  *lp, *last = NULL;
    
    
    /* Get the bucket for this nick... */
    hashv = hash_nick_name(nick)%WATCHHASHSIZE;
    
    /* Find the right header, maintaining last-link pointer... */
    if ((anptr = (aWatch *)watchTable[hashv]))
	while (anptr && mycmp(anptr->nick, nick))
	{
	    nlast = anptr;
	    anptr = anptr->hnext;
	}
    if (!anptr)
	return 0;   /* No such watch */
    
    /* Find this client from the list of notifies... with last-ptr. */
    if ((lp = anptr->watch))
	while (lp && (lp->value.cptr != cptr))
	{
	    last = lp;
	    lp = lp->next;
	}
    if (!lp)
	return 0;   /* No such client to watch */
    
    /* Fix the linked list under header, then remove the watch entry */
    if (!last)
	anptr->watch = lp->next;
    else
	last->next = lp->next;
    free_link(lp);
    
    /* Do the same regarding the links in client-record... */
    last = NULL;
    if ((lp = cptr->watch))
	while (lp && (lp->value.wptr != anptr))
	{
	    last = lp;
	    lp = lp->next;
	}
    
    /*
     * Give error on the odd case... probobly not even neccessary
     * No error checking in ircd is unneccessary ;) -Cabal95
     */
    if (!lp)
	sendto_ops("WATCH debug error: del_from_watch_hash_table "
		   "found a watch entry with no client "
		   "counterpoint processing nick %s on client %s!",
		   nick, get_client_name(cptr, HIDEME));
    else
    {
	if (!last) /* First one matched */
	    cptr->watch = lp->next;
	else
	    last->next = lp->next;
	free_link(lp);
    }
    /* In case this header is now empty of notices, remove it */
    if (!anptr->watch)
    {
	if (!nlast)
	    watchTable[hashv] = anptr->hnext;
	else
	    nlast->hnext = anptr->hnext;
	MyFree(anptr);
    }
    
    /* Update count of notifies on nick */
    cptr->watches--;
    
    return 0;
}

/* hash_del_watch_list */
int   hash_del_watch_list(aClient *cptr)
{
    int   hashv;
    aWatch  *anptr;
    Link  *np, *lp, *last;
    
    
    if (!(np = cptr->watch))
	return 0;   /* Nothing to do */
    
    cptr->watch = NULL; /* Break the watch-list for client */
    while (np)
    {
	/* Find the watch-record from hash-table... */
	anptr = np->value.wptr;
	last = NULL;
	for (lp = anptr->watch; lp && (lp->value.cptr != cptr);
	     lp = lp->next)
	    last = lp;
	
	/* Not found, another "worst case" debug error */
	if (!lp)
	    sendto_ops("WATCH Debug error: hash_del_watch_list "
		       "found a WATCH entry with no table "
		       "counterpoint processing client %s!",
		       cptr->name);
	else
	{
	    /* Fix the watch-list and remove entry */
	    if (!last)
		anptr->watch = lp->next;
	    else
		last->next = lp->next;
	    free_link(lp);
	    
	    /*
	     * If this leaves a header without notifies,
	     * remove it. Need to find the last-pointer!
	     */
	    if (!anptr->watch)
	    {
		aWatch  *np2, *nl;
		
		hashv = hash_nick_name(anptr->nick)%WATCHHASHSIZE;
		
		nl = NULL;
		np2 = watchTable[hashv];
		while (np2 != anptr)
		{
		    nl = np2;
		    np2 = np2->hnext;
		}
		
		if (nl)
		    nl->hnext = anptr->hnext;
		else
		    watchTable[hashv] = anptr->hnext;
		MyFree(anptr);
	    }
	}
	
	lp = np; /* Save last pointer processed */
	np = np->next; /* Jump to the next pointer */
	free_link(lp); /* Free the previous */
    }
    
    cptr->watches = 0;
    
    return 0;
}

aChannel *hash_get_chan_bucket(int hashv)
{
    if (hashv > CH_MAX)
	return NULL;
    return (aChannel *)channelTable[hashv].list;
}

u_long
memcount_hash(MChash *mc)
{
    aWatch  *wptr;
    Link    *lp;
    int      i;

    mc->file = __FILE__;

    for (i = 0; i < WATCHHASHSIZE; i++)
    {
        for (wptr = watchTable[i]; wptr; wptr = wptr->hnext)
        {
            mc->watches.c++;
            mc->watches.m += sizeof(*wptr) + strlen(wptr->nick);

            for (lp = wptr->watch; lp; lp = lp->next)
                mc->e_links++;
        }
    }
    mc->total.c += mc->watches.c;
    mc->total.m += mc->watches.m;

    mc->s_clienthash.c = sizeof(clientTable)/sizeof(clientTable[0]);
    mc->s_clienthash.m = sizeof(clientTable);
    mc->s_channelhash.c = sizeof(channelTable)/sizeof(channelTable[0]);
    mc->s_channelhash.m = sizeof(channelTable);
    mc->s_watchhash.c = sizeof(watchTable)/sizeof(watchTable[0]);
    mc->s_watchhash.m = sizeof(watchTable);

    return mc->total.m;
}

