#ifndef MEMCOUNT_H
#define MEMCOUNT_H
/*
 *   memcount.h - Memory usage/accounting
 *   Copyright (C) 2005 Trevor Talbot and
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

#include "struct.h"
#include "h.h"
#include "blalloc.h"
#include "throttle.h"

typedef struct {
    int     c;
    u_long  m;
} MemCount;


#ifdef MEMTRACE
typedef struct {
    int dummy; /* fucking gcc */
    MemCount allocated;
    MemCount management;
} TracedCount;
#endif


/* BlockHeap */
typedef struct {
    const char *file;

    MemCount blocks;
    MemCount objects;
    MemCount pool;
    MemCount management;
    MemCount total;

    u_long objsize;
    int knownobjs;  /* used during reporting */
} MCBlockHeap;

/* GenericHash */
typedef struct {
    const char *file;

    MemCount hashtable;
    MemCount buckets;
    MemCount total;

    int e_hashents;
} MCGenericHash;


/* blalloc.c */
typedef struct {
    const char *file;

    /* MEMTRACE: block heap allocator */
} MCblalloc;

/* channel.c */
typedef struct {
    const char *file;

    /* file local */
    MemCount bans;
#ifdef EXEMPT_LISTS
    MemCount exempts;
#endif
#ifdef INVITE_LISTS
    MemCount invites;
#endif
    MemCount lopts;
    MemCount total;

    /* static resources */
    MemCount s_scratch;

    /* external resources */
    int e_channels;
    int e_chanmembers;
    int e_inv_links;
    int e_lopt_links;
    int e_dlinks;
#ifdef FLUD
    int e_fludbots;
#endif
} MCchannel;

/* clientlist.c */
typedef struct {
    const char *file;

    /* external resources */
    int e_server_dlinks;
    int e_oper_dlinks;
    int e_recvq_dlinks;
} MCclientlist;

/* clones.c */
typedef struct {
    const char *file;

    /* external resources */
    int        e_cloneents;
    BlockHeap *e_heap;
    void      *e_hash;
} MCclones;

#ifdef HAVE_ENCRYPTION_ON
/* dh.c */
typedef struct {
    const char *file;

    /* referenced externally */
    u_long m_dhsession_size;
} MCdh;
#endif

/* fds.c */
typedef struct {
    const char *file;

    /* static resources */
    MemCount s_fdlist;
} MCfds;

/* hash.c */
typedef struct {
    const char *file;

    /* file local */
    MemCount watches;
    MemCount total;

    /* static resources */
    MemCount s_clienthash;
    MemCount s_channelhash;
    MemCount s_watchhash;

    /* external resources */
    int e_links;
} MChash;

/* hide.c */
typedef struct {
    const char *file;

    /* file local */
    MemCount fakelinks;
    MemCount total;

    /* external resources */
    int e_links;
} MChide;

/* ircd.c */
typedef struct {
    const char *file;

    /* static resources */
    MemCount s_confbuf;
} MCircd;

/* list.c */
typedef struct {
    const char *file;

    /* external resources */
    BlockHeap *e_localclients_heap;
    BlockHeap *e_remoteclients_heap;
    BlockHeap *e_links_heap;
    BlockHeap *e_dlinks_heap;
    BlockHeap *e_chanmembers_heap;
    BlockHeap *e_users_heap;
    BlockHeap *e_channels_heap;
#ifdef FLUD
    BlockHeap *e_fludbots_heap;
#endif

    /* MEMTRACE: allocates servers, classes, opers, connects, allows, ports,
       and conf_me */
} MClist;

/* m_services.c */
typedef struct {
    const char *file;

    /* MEMTRACE: allocates simban reasons */
} MCm_services;

/* modules.c */
typedef struct {
    const char *file;

#ifdef USE_HOOKMODULES
    MemCount modules;
    MemCount hooks;
    MemCount total;

    int e_dlinks;

    /* MEMTRACE: module allocator interface */
#endif
} MCmodules;

/* parse.c */
typedef struct {
    const char *file;

    /* file local */
    MemCount msgnodes;
    MemCount total;

    /* static resources */
    MemCount s_bufs;
    MemCount s_msgtab;
} MCparse;

#ifdef RWHO_PROBABILITY
/* probability.c */
typedef struct {
    const char *file;

    /* static resources */
    MemCount s_prob;
} MCprobability;
#endif

#ifdef HAVE_ENCRYPTION_ON
/* rc4.c */
typedef struct {
    const char *file;

    /* referenced externally */
    u_long m_rc4state_size;
} MCrc4;
#endif

/* res.c */
typedef struct {
    const char *file;

    /* file local */
    MemCount cached;
    MemCount requests;
    MemCount total;

    /* static resources */
    MemCount s_cachehash;
    MemCount s_requesthash;
} MCres;

/* s_bsd.c */
typedef struct {
    const char *file;

    /* file local */
    MemCount listeners;
    MemCount total;

    /* static resources */
    MemCount s_readbuf;
    MemCount s_local;
} MCs_bsd;

/* s_conf.c */
typedef struct {
    const char *file;

    /* file local */
    MemCount connects;
    MemCount allows;
    MemCount me;
    MemCount opers;
    MemCount ports;
    MemCount classes;
    MemCount uservers;
    MemCount modules;
    MemCount total;

    /* MEMTRACE: subtract resources from list.c
       allocates simban/userban reasons */
} MCs_conf;

/* s_serv.c */
typedef struct {
    const char *file;

    /* file local */
    MemCount motd;
    MemCount shortmotd;
    MemCount help;
    MemCount total;

    /* MEMTRACE: allocates simban and userban reasons */
} MCs_serv;

/* s_user.c */
typedef struct {
    const char *file;

    /* file local */
    MemCount aways;
    MemCount silences;
#if (RIDICULOUS_PARANOIA_LEVEL>=1)
    MemCount opermasks;
#endif
    MemCount servers;
    MemCount total;

    /* external resources */
    int e_local_clients;
    int e_remote_clients;
    int e_users;
#ifdef FLUD
    int e_fludbots;
    int e_flud_links;
#endif
    int e_channel_links;
    int e_watch_links;
    int e_invite_links;
    int e_silence_links;
    int e_dccallow_links;
#ifdef HAVE_ENCRYPTION_ON
    int e_dh_sessions;
    int e_rc4states;
#endif
    int e_zipin_sessions;
    int e_zipout_sessions;

    /* MEMTRACE: subtract resources from list.c */
} MCs_user;

/* sbuf.c */
typedef struct {
    const char *file;

    /* file local */
    MemCount smallbufpool;
    MemCount smallbufs;
    MemCount largebufpool;
    MemCount largebufs;
    MemCount userpool;
    MemCount users;
    MemCount bufblocks;
    MemCount userblocks;
    MemCount bufheaders;
    MemCount management;
    MemCount total;
} MCsbuf;

/* scache.c */
typedef struct {
    const char *file;

    /* file local */
    MemCount cached;
    MemCount total;

    /* static resources */
    MemCount s_hash;
} MCscache;

/* send.c */
typedef struct {
    const char *file;

    /* local resources */
    MemCount s_bufs;
} MCsend;

/* throttle.c */
typedef struct {
    const char *file;

    /* external resources */
    BlockHeap *e_hashent_heap;
#ifdef THROTTLE_ENABLE
    BlockHeap *e_throttle_heap;
    void      *e_throttle_hash;
    int        e_throttles;
#endif

    /* MEMTRACE: generic hash allocator */
} MCthrottle;

/* userban.c */
typedef struct {
    const char *file;

    /* local resources */
    MemCount lists;
    MemCount entries;
    MemCount cidr4big_userbans;
    MemCount cidr4_userbans;
    MemCount hosthash_userbans;
    MemCount hostwild_userbans;
    MemCount iphash_userbans;
    MemCount ipwild_userbans;
    MemCount userbans;
    MemCount nickhash_simbans;
    MemCount nickwild_simbans;
    MemCount chanhash_simbans;
    MemCount chanwild_simbans;
    MemCount gcoshash_simbans;
    MemCount gcoswild_simbans;
    MemCount simbans;
    MemCount total;
} MCuserban;

/* whowas.c */
typedef struct {
    const char *file;

    /* static resources */
    MemCount s_whowas;
    MemCount s_hash;
} MCwhowas;

/* zlink.c */
typedef struct {
    const char *file;

    /* static resources */
    MemCount s_bufs;

    /* referenced externally */
    u_long m_insession_size;
    u_long m_outsession_size;
} MCzlink;


#ifdef MEMTRACE
/* implemented in support.c */
u_long memtrace_count(TracedCount *, const char *);
void memtrace_report(aClient *, const char *);
void memtrace_reset(void);
#endif

void report_memory_usage(aClient *, int);

int mc_links(Link *);
int mc_dlinks(DLink *);

u_long memcount_BlockHeap(BlockHeap *, MCBlockHeap *);
u_long memcount_GenericHash(hash_table *, MCGenericHash *);

u_long memcount_blalloc(MCblalloc *);
u_long memcount_channel(MCchannel *);
u_long memcount_clientlist(MCclientlist *);
u_long memcount_clones(MCclones *);
#ifdef HAVE_ENCRYPTION_ON
u_long memcount_dh(MCdh *);
#endif
u_long memcount_fds(MCfds *);
u_long memcount_hash(MChash *);
u_long memcount_hide(MChide *);
u_long memcount_ircd(MCircd *);
u_long memcount_list(MClist *);
u_long memcount_m_services(MCm_services *);
u_long memcount_modules(MCmodules *);
u_long memcount_parse(MCparse *);
#ifdef RWHO_PROBABILITY
u_long memcount_probability(MCprobability *);
#endif
#ifdef HAVE_ENCRYPTION_ON
u_long memcount_rc4(MCrc4 *);
#endif
u_long memcount_res(MCres *);
u_long memcount_s_bsd(MCs_bsd *);
u_long memcount_s_conf(MCs_conf *);
u_long memcount_s_serv(MCs_serv *);
u_long memcount_s_user(MCs_user *);
u_long memcount_sbuf(MCsbuf *);
u_long memcount_scache(MCscache *);
u_long memcount_send(MCsend *);
u_long memcount_throttle(MCthrottle *);
u_long memcount_userban(MCuserban *);
u_long memcount_whowas(MCwhowas *);
u_long memcount_zlink(MCzlink *);


#endif  /* MEMCOUNT_H */
