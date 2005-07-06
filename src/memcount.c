/*
 *   memcount.c - Memory usage/accounting
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
 *   GNU General Public License for more detail.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/* $Id$ */

#include "memcount.h"
#include "numeric.h"


int mc_links(Link *lp)
{
    int c = 0;

    while (lp)
    {
        c++;
        lp = lp->next;
    }

    return c;
}

int mc_dlinks(DLink *lp)
{
    int c = 0;

    while (lp)
    {
        c++;
        lp = lp->next;
    }

    return c;
}

/*
 * A very long and involved function to report memory usage, along with leak
 * checking.
 */
void report_memory_usage(aClient *cptr, int detail)
{
    /* ":me.name RPL_STATSDEBUG cptr->name :" */
    char pfxbuf[1+HOSTLEN+1+3+1+NICKLEN+1+1+1];

    /* per file counters */
    MCblalloc       mc_blalloc = {0};
    MCchannel       mc_channel = {0};
    MCclientlist    mc_clientlist = {0};
    MCclones        mc_clones = {0};
    MCfds           mc_fds = {0};
    MChash          mc_hash = {0};
    MChide          mc_hide = {0};
    MCircd          mc_ircd = {0};
    MClist          mc_list = {0};
    MCm_services    mc_m_services = {0};
    MCmodules       mc_modules = {0};
    MCparse         mc_parse = {0};
#ifdef RWHO_PROBABILITY
    MCprobability   mc_probability = {0};
#endif
    MCres           mc_res = {0};
    MCs_bsd         mc_s_bsd = {0};
    MCs_conf        mc_s_conf = {0};
    MCs_serv        mc_s_serv = {0};
    MCs_user        mc_s_user = {0};
    MCsbuf          mc_sbuf = {0};
    MCscache        mc_scache = {0};
    MCsend          mc_send = {0};
    MCthrottle      mc_throttle = {0};
    MCuserban       mc_userban = {0};
    MCwhowas        mc_whowas = {0};
    MCzlink         mc_zlink = {0};
#ifdef HAVE_ENCRYPTION_ON
    MCdh            mc_dh = {0};
    MCrc4           mc_rc4 = {0};
#endif

    /* per block heap counters */
    MCBlockHeap     mcbh_clones = {0};
    MCBlockHeap     mcbh_local_clients = {0};
    MCBlockHeap     mcbh_remote_clients = {0};
    MCBlockHeap     mcbh_links = {0};
    MCBlockHeap     mcbh_dlinks = {0};
    MCBlockHeap     mcbh_chanmembers = {0};
    MCBlockHeap     mcbh_users = {0};
    MCBlockHeap     mcbh_channels = {0};
    MCBlockHeap     mcbh_hashents = {0};
#ifdef FLUD
    MCBlockHeap     mcbh_fludbots = {0};
#endif
#ifdef THROTTLE_ENABLE
    MCBlockHeap     mcbh_throttles = {0};
#endif

    /* per generic hash counters */
    MCGenericHash   mcgh_clones = {0};
#ifdef THROTTLE_ENABLE
    MCGenericHash   mcgh_throttles = {0};
#endif

    /* general counters */
    u_long          use_heap = 0;     /* used from block heaps, enumerated */
    u_long          use_hash = 0;     /* used from hashtables, enumerated */
    u_long          use_total = 0;    /* total bytes in use by enumeration */

    u_long          alloc_heap = 0;   /* allocated from block heaps */
    u_long          alloc_total = 0;  /* total bytes known to be allocated */

    u_long          rep_total = 0;    /* total bytes individually reported */
    u_long          subtotal;         /* used during detail reports */

#ifdef MEMTRACE
    /* per file trace counters */
    TracedCount     tc_blalloc = {0};
    TracedCount     tc_channel = {0};
    TracedCount     tc_hash = {0};
    TracedCount     tc_hide = {0};
    TracedCount     tc_list = {0};
    TracedCount     tc_m_services = {0};
    TracedCount     tc_parse = {0};
    TracedCount     tc_res = {0};
    TracedCount     tc_s_bsd = {0};
    TracedCount     tc_s_conf = {0};
    TracedCount     tc_s_serv = {0};
    TracedCount     tc_s_user = {0};
    TracedCount     tc_sbuf = {0};
    TracedCount     tc_scache = {0};
    TracedCount     tc_throttle = {0};
    TracedCount     tc_userban = {0};
    TracedCount     tc_zlink = {0};
#ifdef HAVE_ENCRYPTION_ON
    TracedCount     tc_dh = {0};
    TracedCount     tc_rc4 = {0};
#endif
    TracedCount     tc_unverified = {0};

    /* general trace counters */
    u_long          traced_total = 0;
    u_long          traced_subtotal;    /* used during detail reports */
#endif  /* MEMTRACE */


    /* prep buffer */
    ircsprintf(pfxbuf, ":%s %d %s :", me.name, RPL_STATSDEBUG, cptr->name);

    /* file local allocations */
    alloc_total += memcount_blalloc(&mc_blalloc);
    alloc_total += memcount_channel(&mc_channel);
    alloc_total += memcount_clientlist(&mc_clientlist);
    alloc_total += memcount_clones(&mc_clones);
    alloc_total += memcount_fds(&mc_fds);
    alloc_total += memcount_hash(&mc_hash);
    alloc_total += memcount_hide(&mc_hide);
    alloc_total += memcount_ircd(&mc_ircd);
    alloc_total += memcount_list(&mc_list);
    alloc_total += memcount_m_services(&mc_m_services);
    alloc_total += memcount_modules(&mc_modules);
    alloc_total += memcount_parse(&mc_parse);
#ifdef RWHO_PROBABILITY
    alloc_total += memcount_probability(&mc_probability);
#endif
    alloc_total += memcount_res(&mc_res);
    alloc_total += memcount_s_bsd(&mc_s_bsd);
    alloc_total += memcount_s_conf(&mc_s_conf);
    alloc_total += memcount_s_serv(&mc_s_serv);
    alloc_total += memcount_s_user(&mc_s_user);
    alloc_total += memcount_sbuf(&mc_sbuf);
    alloc_total += memcount_scache(&mc_scache);
    alloc_total += memcount_send(&mc_send);
    alloc_total += memcount_throttle(&mc_throttle);
    alloc_total += memcount_userban(&mc_userban);
    alloc_total += memcount_whowas(&mc_whowas);
    alloc_total += memcount_zlink(&mc_zlink);
#ifdef HAVE_ENCRYPTION_ON
    alloc_total += memcount_dh(&mc_dh);
    alloc_total += memcount_rc4(&mc_rc4);
#endif

    use_total = alloc_total;

    /* remove free sbufs from the active total */
    use_total -= mc_sbuf.smallbufpool.m - mc_sbuf.smallbufs.m;
    use_total -= mc_sbuf.largebufpool.m - mc_sbuf.largebufs.m;
    use_total -= mc_sbuf.userpool.m - mc_sbuf.users.m;

    /* block heaps */
    alloc_heap += memcount_BlockHeap(mc_clones.e_heap, &mcbh_clones);
    alloc_heap += memcount_BlockHeap(mc_list.e_localclients_heap,
                                     &mcbh_local_clients);
    alloc_heap += memcount_BlockHeap(mc_list.e_remoteclients_heap,
                                     &mcbh_remote_clients);
    alloc_heap += memcount_BlockHeap(mc_list.e_links_heap, &mcbh_links);
    alloc_heap += memcount_BlockHeap(mc_list.e_dlinks_heap, &mcbh_dlinks);
    alloc_heap += memcount_BlockHeap(mc_list.e_chanmembers_heap,
                                     &mcbh_chanmembers);
    alloc_heap += memcount_BlockHeap(mc_list.e_users_heap, &mcbh_users);
    alloc_heap += memcount_BlockHeap(mc_list.e_channels_heap, &mcbh_channels);
    alloc_heap += memcount_BlockHeap(mc_throttle.e_hashent_heap,
                                     &mcbh_hashents);
#ifdef FLUD
    alloc_heap += memcount_BlockHeap(mc_list.e_fludbots_heap, &mcbh_fludbots);
#endif
#ifdef THROTTLE_ENABLE
    alloc_heap += memcount_BlockHeap(mc_throttle.e_throttle_heap,
                                     &mcbh_throttles);
#endif

    /* block heaps maintain a free pool much like sbufs */
    use_heap += mcbh_clones.objects.m + mcbh_clones.management.m;
    use_heap += mcbh_local_clients.objects.m + mcbh_local_clients.management.m;
    use_heap += mcbh_remote_clients.objects.m+mcbh_remote_clients.management.m;
    use_heap += mcbh_links.objects.m + mcbh_links.management.m;
    use_heap += mcbh_dlinks.objects.m + mcbh_dlinks.management.m;
    use_heap += mcbh_chanmembers.objects.m + mcbh_chanmembers.management.m;
    use_heap += mcbh_users.objects.m + mcbh_users.management.m;
    use_heap += mcbh_channels.objects.m + mcbh_channels.management.m;
    use_heap += mcbh_hashents.objects.m + mcbh_hashents.management.m;
#ifdef FLUD
    use_heap += mcbh_fludbots.objects.m + mcbh_fludbots.management.m;
#endif
#ifdef THROTTLE_ENABLE
    use_heap += mcbh_throttles.objects.m + mcbh_throttles.management.m;
#endif

    alloc_total += alloc_heap;
    use_total += use_heap;

    /* generic hashes */
    use_hash += memcount_GenericHash(mc_clones.e_hash, &mcgh_clones);
#ifdef THROTTLE_ENABLE
    use_hash += memcount_GenericHash(mc_throttle.e_throttle_hash,
                                     &mcgh_throttles);
#endif

    use_total += use_hash;
    alloc_total += use_hash;

    /* oddballs */
#ifdef HAVE_ENCRYPTION_ON
    alloc_total += mc_s_user.e_dh_sessions * mc_dh.m_dhsession_size;
    alloc_total += mc_s_user.e_rc4states * mc_rc4.m_rc4state_size;
#endif
    alloc_total += mc_s_user.e_zipin_sessions * mc_zlink.m_insession_size;
    alloc_total += mc_s_user.e_zipout_sessions * mc_zlink.m_outsession_size;


    /*
     * At this point we have some general statistics:
     *    alloc_total    - total bytes allocated from system heap
     *    use_total      - total bytes in active use
     *        the difference of the above is the inactive pool cache
     *    alloc_heap     - total bytes allocated from block heaps
     *      use_heap     - total bytes in active use from block heaps
     *      use_hash     - total bytes allocated / in use from generic hashes
     *
     * Now we dig into details, reporting them if the caller wanted us to.
     * rep_total is incremented as we go, to make sure we report everything we
     * know about.
     * The block heaps get .knownobjs incremented also, to make sure we don't
     * have a subleak within a pool.
     *
     * The general statistics and some final checking is done at the end, along
     * with traced leak checks if compiled with MEMTRACE.
     */

    /*
     * Detail client-related memory.
     */
    if (detail)
        sendto_one(cptr, "%sClients", pfxbuf);
    subtotal = 0;
    if (detail && mc_s_user.e_local_clients)
        sendto_one(cptr, "%s    local clients: %d (%lu bytes)", pfxbuf,
                   mc_s_user.e_local_clients,
                   mc_s_user.e_local_clients * mcbh_local_clients.objsize);
    subtotal += mc_s_user.e_local_clients * mcbh_local_clients.objsize;
    if (detail && mc_s_user.e_remote_clients)
        sendto_one(cptr, "%s    remote clients: %d (%lu bytes)", pfxbuf,
                   mc_s_user.e_remote_clients,
                   mc_s_user.e_remote_clients * mcbh_remote_clients.objsize);
    subtotal += mc_s_user.e_remote_clients * mcbh_remote_clients.objsize;
    if (detail && mc_s_user.e_users)
        sendto_one(cptr, "%s    users: %d (%lu bytes)", pfxbuf,
                   mc_s_user.e_users,
                   mc_s_user.e_users * mcbh_users.objsize);
    subtotal += mc_s_user.e_users * mcbh_users.objsize;
    if (detail && mc_hash.watches.c)
        sendto_one(cptr, "%s    watches: %d (%lu bytes)", pfxbuf,
                   mc_hash.watches.c, mc_hash.watches.m);
    subtotal += mc_hash.watches.m;
    if (detail && mc_s_user.aways.c)
        sendto_one(cptr, "%s    away messages: %d (%lu bytes)", pfxbuf,
                   mc_s_user.aways.c, mc_s_user.aways.m);
    subtotal += mc_s_user.aways.m;
    if (detail && mc_s_user.silences.c)
        sendto_one(cptr, "%s    silences: %d (%lu bytes)", pfxbuf,
                   mc_s_user.silences.c, mc_s_user.silences.m);
    subtotal += mc_s_user.silences.m;
#if (RIDICULOUS_PARANOIA_LEVEL>=1)
    if (detail && mc_s_user.opermasks.c)
        sendto_one(cptr, "%s    opermasks: %d (%lu bytes)", pfxbuf,
                   mc_s_user.opermasks.c, mc_s_user.opermasks.m);
    subtotal += mc_s_user.opermasks.m;
#endif
#ifdef FLUD
    if (detail && mc_s_user.e_fludbots)
        sendto_one(cptr, "%s    fludbots: %d (%lu bytes)", pfxbuf,
                   mc_s_user.e_fludbots,
                   mc_s_user.e_fludbots * mcbh_fludbots.objsize);
    subtotal += mc_s_user.e_fludbots * mcbh_fludbots.objsize;
    if (detail && mc_s_user.e_flud_links)
        sendto_one(cptr, "%s    flud links: %d (%lu bytes)", pfxbuf,
                   mc_s_user.e_flud_links,
                   mc_s_user.e_flud_links * mcbh_links.objsize);
    subtotal += mc_s_user.e_flud_links * mcbh_links.objsize;
#endif
    if (detail && mc_s_user.e_channel_links)
        sendto_one(cptr, "%s    channel links: %d (%lu bytes)", pfxbuf,
                   mc_s_user.e_channel_links,
                   mc_s_user.e_channel_links * mcbh_links.objsize);
    subtotal += mc_s_user.e_channel_links * mcbh_links.objsize;
    if (detail && mc_s_user.e_invite_links)
        sendto_one(cptr, "%s    invite links: %d (%lu bytes)", pfxbuf,
                   mc_s_user.e_invite_links,
                   mc_s_user.e_invite_links * mcbh_links.objsize);
    subtotal += mc_s_user.e_invite_links * mcbh_links.objsize;
    if (detail && mc_s_user.e_silence_links)
        sendto_one(cptr, "%s    silence links: %d (%lu bytes)", pfxbuf,
                   mc_s_user.e_silence_links,
                   mc_s_user.e_silence_links * mcbh_links.objsize);
    subtotal += mc_s_user.e_silence_links * mcbh_links.objsize;
    if (detail && mc_s_user.e_dccallow_links)
        sendto_one(cptr, "%s    dccallow links: %d (%lu bytes)", pfxbuf,
                   mc_s_user.e_dccallow_links,
                   mc_s_user.e_dccallow_links * mcbh_links.objsize);
    subtotal += mc_s_user.e_dccallow_links * mcbh_links.objsize;
    if (detail && mc_s_user.e_watch_links)
        sendto_one(cptr, "%s    client-watch links: %d (%lu bytes)", pfxbuf,
                   mc_s_user.e_watch_links,
                   mc_s_user.e_watch_links * mcbh_links.objsize);
    subtotal += mc_s_user.e_watch_links * mcbh_links.objsize;
    if (detail && mc_hash.e_links)
        sendto_one(cptr, "%s    watch-client links: %d (%lu bytes)", pfxbuf,
                   mc_hash.e_links, mc_hash.e_links * mcbh_links.objsize);
    subtotal += mc_hash.e_links * mcbh_links.objsize;
    if (detail && mc_clientlist.e_oper_dlinks)
        sendto_one(cptr, "%s    operlist dlinks: %d (%lu bytes)", pfxbuf,
                   mc_clientlist.e_oper_dlinks,
                   mc_clientlist.e_oper_dlinks * mcbh_dlinks.objsize);
    subtotal += mc_clientlist.e_oper_dlinks * mcbh_dlinks.objsize;
    if (detail && mc_clientlist.e_recvq_dlinks)
        sendto_one(cptr, "%s    recvqlist dlinks: %d (%lu bytes)", pfxbuf,
                   mc_clientlist.e_recvq_dlinks,
                   mc_clientlist.e_recvq_dlinks * mcbh_dlinks.objsize);
    subtotal += mc_clientlist.e_recvq_dlinks * mcbh_dlinks.objsize;

    if (detail)
        sendto_one(cptr, "%s    TOTAL: %lu bytes", pfxbuf, subtotal);
    else
        sendto_one(cptr, "%sClients: %lu bytes", pfxbuf, subtotal);
    rep_total += subtotal;

    mcbh_local_clients.knownobjs += mc_s_user.e_local_clients;
    mcbh_remote_clients.knownobjs += mc_s_user.e_remote_clients;
    mcbh_users.knownobjs += mc_s_user.e_users;
#ifdef FLUD
    mcbh_fludbots.knownobjs += mc_s_user.e_fludbots;
    mcbh_links.knownobjs += mc_s_user.e_flud_links;
#endif
    mcbh_links.knownobjs += mc_s_user.e_channel_links;
    mcbh_links.knownobjs += mc_s_user.e_invite_links;
    mcbh_links.knownobjs += mc_s_user.e_silence_links;
    mcbh_links.knownobjs += mc_s_user.e_dccallow_links;
    mcbh_links.knownobjs += mc_s_user.e_watch_links;
    mcbh_links.knownobjs += mc_hash.e_links;
    mcbh_dlinks.knownobjs += mc_clientlist.e_oper_dlinks;
    mcbh_dlinks.knownobjs += mc_clientlist.e_recvq_dlinks;


    /*
     * Detail server-related memory.
     */
    if (detail)
        sendto_one(cptr, "%sServers", pfxbuf);
    subtotal = 0;
    if (detail && mc_s_user.servers.c)
        sendto_one(cptr, "%s    servers: %d (%lu bytes)", pfxbuf,
                   mc_s_user.servers.c, mc_s_user.servers.m);
    subtotal += mc_s_user.servers.m;
    if (detail && mc_clientlist.e_server_dlinks)
        sendto_one(cptr, "%s    serverlist dlinks: %d (%lu bytes)", pfxbuf,
                   mc_clientlist.e_server_dlinks,
                   mc_clientlist.e_server_dlinks * mcbh_dlinks.objsize);
    subtotal += mc_clientlist.e_server_dlinks * mcbh_dlinks.objsize;
#ifdef HAVE_ENCRYPTION_ON
    if (detail && mc_s_user.e_dh_sessions)
        sendto_one(cptr, "%s    DH sessions: %d (%lu bytes)", pfxbuf,
                   mc_s_user.e_dh_sessions,
                   mc_s_user.e_dh_sessions * mc_dh.m_dhsession_size);
    subtotal += mc_s_user.e_dh_sessions * mc_dh.m_dhsession_size;
    if (detail && mc_s_user.e_rc4states)
        sendto_one(cptr, "%s    RC4 states: %d (%lu bytes)", pfxbuf,
                   mc_s_user.e_rc4states,
                   mc_s_user.e_rc4states * mc_rc4.m_rc4state_size);
    subtotal += mc_s_user.e_rc4states * mc_rc4.m_rc4state_size;
#endif
    if (detail && mc_s_user.e_zipin_sessions)
        sendto_one(cptr, "%s    zip input sessions: %d (%lu bytes)", pfxbuf,
                   mc_s_user.e_zipin_sessions,
                   mc_s_user.e_zipin_sessions * mc_zlink.m_insession_size);
    subtotal += mc_s_user.e_zipin_sessions * mc_zlink.m_insession_size;
    if (detail && mc_s_user.e_zipout_sessions)
        sendto_one(cptr, "%s    zip output sessions: %d (%lu bytes)", pfxbuf,
                   mc_s_user.e_zipout_sessions,
                   mc_s_user.e_zipout_sessions * mc_zlink.m_outsession_size);
    subtotal += mc_s_user.e_zipout_sessions * mc_zlink.m_outsession_size;

    if (detail)
        sendto_one(cptr, "%s    TOTAL: %lu bytes", pfxbuf, subtotal);
    else
        sendto_one(cptr, "%sServers: %lu bytes", pfxbuf, subtotal);
    rep_total += subtotal;

    mcbh_dlinks.knownobjs += mc_clientlist.e_server_dlinks;


    /*
     * Detail channel-related memory.
     */
    if (detail)
        sendto_one(cptr, "%sChannels", pfxbuf);
    subtotal = 0;
    if (detail && mc_channel.e_channels)
        sendto_one(cptr, "%s    channels: %d (%lu bytes)", pfxbuf,
                   mc_channel.e_channels,
                   mc_channel.e_channels * mcbh_channels.objsize);
    subtotal += mc_channel.e_channels * mcbh_channels.objsize;
    if (detail && mc_channel.bans.c)
        sendto_one(cptr, "%s    bans: %d (%lu bytes)", pfxbuf,
                   mc_channel.bans.c, mc_channel.bans.m);
    subtotal += mc_channel.bans.m;
#ifdef EXEMPT_LISTS
    if (detail && mc_channel.exempts.c)
        sendto_one(cptr, "%s    ban exceptions: %d (%lu bytes)", pfxbuf,
                   mc_channel.exempts.c, mc_channel.exempts.m);
    subtotal += mc_channel.exempts.m;
#endif
#ifdef INVITE_LISTS
    if (detail && mc_channel.invites.c)
        sendto_one(cptr, "%s    invite exceptions: %d (%lu bytes)", pfxbuf,
                   mc_channel.invites.c, mc_channel.invites.m);
    subtotal += mc_channel.invites.m;
#endif
    if (detail && mc_channel.lopts.c)
        sendto_one(cptr, "%s    active list options: %d (%lu bytes)", pfxbuf,
                   mc_channel.lopts.c, mc_channel.lopts.m);
    subtotal += mc_channel.lopts.m;
    if (detail && mc_channel.e_chanmembers)
        sendto_one(cptr, "%s    channel members: %d (%lu bytes)", pfxbuf,
                   mc_channel.e_chanmembers,
                   mc_channel.e_chanmembers * mcbh_chanmembers.objsize);
    subtotal += mc_channel.e_chanmembers * mcbh_chanmembers.objsize;
#ifdef FLUD
    if (detail && mc_channel.e_fludbots)
        sendto_one(cptr, "%s    fludbots: %d (%lu bytes)", pfxbuf,
                   mc_channel.e_fludbots,
                   mc_channel.e_fludbots * mcbh_fludbots.objsize);
    subtotal += mc_channel.e_fludbots * mcbh_fludbots.objsize;
#endif
    if (detail && mc_channel.e_inv_links)
        sendto_one(cptr, "%s    invite links: %d (%lu bytes)", pfxbuf,
                   mc_channel.e_inv_links,
                   mc_channel.e_inv_links * mcbh_links.objsize);
    subtotal += mc_channel.e_inv_links * mcbh_links.objsize;
    if (detail && mc_channel.e_lopt_links)
        sendto_one(cptr, "%s    lopt links: %d (%lu bytes)", pfxbuf,
                   mc_channel.e_lopt_links,
                   mc_channel.e_lopt_links * mcbh_links.objsize);
    subtotal += mc_channel.e_lopt_links * mcbh_links.objsize;
    if (detail && mc_channel.e_dlinks)
        sendto_one(cptr, "%s    dlinks: %d (%lu bytes)", pfxbuf,
                   mc_channel.e_dlinks,
                   mc_channel.e_dlinks * mcbh_dlinks.objsize);
    subtotal += mc_channel.e_dlinks * mcbh_dlinks.objsize;

    if (detail)
        sendto_one(cptr, "%s    TOTAL: %lu bytes", pfxbuf, subtotal);
    else
        sendto_one(cptr, "%sChannels: %lu bytes", pfxbuf, subtotal);
    rep_total += subtotal;

    mcbh_channels.knownobjs += mc_channel.e_channels;
    mcbh_chanmembers.knownobjs += mc_channel.e_chanmembers;
#ifdef FLUD
    mcbh_fludbots.knownobjs += mc_channel.e_fludbots;
#endif
    mcbh_links.knownobjs += mc_channel.e_inv_links;
    mcbh_links.knownobjs += mc_channel.e_lopt_links;
    mcbh_dlinks.knownobjs += mc_channel.e_dlinks;


    /*
     * Detail ban-related memory.
     */
    if (detail)
        sendto_one(cptr, "%sBans", pfxbuf);
    subtotal = 0;
    if (detail && mc_userban.lists.c)
        sendto_one(cptr, "%s    lists: %d (%lu bytes)", pfxbuf,
                   mc_userban.lists.c, mc_userban.lists.m);
    subtotal += mc_userban.lists.m;
    if (detail && mc_userban.entries.c)
        sendto_one(cptr, "%s    entries: %d (%lu bytes)", pfxbuf,
                   mc_userban.entries.c, mc_userban.entries.m);
    subtotal += mc_userban.entries.m;
    if (detail && mc_userban.userbans.c)
        sendto_one(cptr, "%s    userbans: %d (%lu bytes)", pfxbuf,
                   mc_userban.userbans.c, mc_userban.userbans.m);
    subtotal += mc_userban.userbans.m;
    if (detail && mc_userban.userbans.c)
    {
        sendto_one(cptr, "%s        CIDR4 big: %d (%lu bytes)", pfxbuf,
                   mc_userban.cidr4big_userbans.c,
                   mc_userban.cidr4big_userbans.m);
        sendto_one(cptr, "%s        CIDR4:     %d (%lu bytes)", pfxbuf,
                   mc_userban.cidr4_userbans.c,
                   mc_userban.cidr4_userbans.m);
        sendto_one(cptr, "%s        host:      %d (%lu bytes)", pfxbuf,
                   mc_userban.hosthash_userbans.c,
                   mc_userban.hosthash_userbans.m);
        sendto_one(cptr, "%s        host wild: %d (%lu bytes)", pfxbuf,
                   mc_userban.hostwild_userbans.c,
                   mc_userban.hostwild_userbans.m);
        sendto_one(cptr, "%s        IP:        %d (%lu bytes)", pfxbuf,
                   mc_userban.iphash_userbans.c,
                   mc_userban.iphash_userbans.m);
        sendto_one(cptr, "%s        IP wild:   %d (%lu bytes)", pfxbuf,
                   mc_userban.ipwild_userbans.c,
                   mc_userban.ipwild_userbans.m);
    }
    if (detail && mc_userban.simbans.c)
        sendto_one(cptr, "%s    simbans: %d (%lu bytes)", pfxbuf,
                   mc_userban.simbans.c, mc_userban.simbans.m);
    subtotal += mc_userban.simbans.m;
    if (detail && mc_userban.simbans.c)
    {
        sendto_one(cptr, "%s        nick:      %d (%lu bytes)", pfxbuf,
                   mc_userban.nickhash_simbans.c,
                   mc_userban.nickhash_simbans.m);
        sendto_one(cptr, "%s        nick wild: %d (%lu bytes)", pfxbuf,
                   mc_userban.nickwild_simbans.c,
                   mc_userban.nickwild_simbans.m);
        sendto_one(cptr, "%s        chan:      %d (%lu bytes)", pfxbuf,
                   mc_userban.chanhash_simbans.c,
                   mc_userban.chanhash_simbans.m);
        sendto_one(cptr, "%s        chan wild: %d (%lu bytes)", pfxbuf,
                   mc_userban.chanwild_simbans.c,
                   mc_userban.chanwild_simbans.m);
        sendto_one(cptr, "%s        gcos:      %d (%lu bytes)", pfxbuf,
                   mc_userban.gcoshash_simbans.c,
                   mc_userban.gcoshash_simbans.m);
        sendto_one(cptr, "%s        gcos wild: %d (%lu bytes)", pfxbuf,
                   mc_userban.gcoswild_simbans.c,
                   mc_userban.gcoswild_simbans.m);
    }

    if (detail)
        sendto_one(cptr, "%s    TOTAL: %lu bytes", pfxbuf, subtotal);
    else
        sendto_one(cptr, "%sBans: %lu bytes", pfxbuf, subtotal);
    rep_total += subtotal;


    /*
     * Detail configuration-related memory.
     */
    if (detail)
        sendto_one(cptr, "%sConfiguration", pfxbuf);
    subtotal = 0;
    if (detail && mc_s_conf.me.c)
        sendto_one(cptr, "%s    global: %d (%lu bytes)", pfxbuf,
                   mc_s_conf.me.c, mc_s_conf.me.m);
    subtotal += mc_s_conf.me.m;
    if (detail && mc_s_conf.connects.c)
        sendto_one(cptr, "%s    connects: %d (%lu bytes)", pfxbuf,
                   mc_s_conf.connects.c, mc_s_conf.connects.m);
    subtotal += mc_s_conf.connects.m;
    if (detail && mc_s_conf.allows.c)
        sendto_one(cptr, "%s    allows: %d (%lu bytes)", pfxbuf,
                   mc_s_conf.allows.c, mc_s_conf.allows.m);
    subtotal += mc_s_conf.allows.m;
    if (detail && mc_s_conf.opers.c)
        sendto_one(cptr, "%s    opers: %d (%lu bytes)", pfxbuf,
                   mc_s_conf.opers.c, mc_s_conf.opers.m);
    subtotal += mc_s_conf.opers.m;
    if (detail && mc_s_conf.classes.c)
        sendto_one(cptr, "%s    classes: %d (%lu bytes)", pfxbuf,
                   mc_s_conf.classes.c, mc_s_conf.classes.m);
    subtotal += mc_s_conf.classes.m;
    if (detail && mc_s_conf.ports.c)
        sendto_one(cptr, "%s    ports: %d (%lu bytes)", pfxbuf,
                   mc_s_conf.ports.c, mc_s_conf.ports.m);
    subtotal += mc_s_conf.ports.m;
    if (detail && mc_s_conf.uservers.c)
        sendto_one(cptr, "%s    superservers: %d (%lu bytes)", pfxbuf,
                   mc_s_conf.uservers.c, mc_s_conf.uservers.m);
    subtotal += mc_s_conf.uservers.m;
    if (detail && mc_s_conf.modules.c)
        sendto_one(cptr, "%s    modules: %d (%lu bytes)", pfxbuf,
                   mc_s_conf.modules.c, mc_s_conf.modules.m);
    subtotal += mc_s_conf.modules.m;
    if (detail && mc_s_serv.motd.c)
        sendto_one(cptr, "%s    motd lines: %d (%lu bytes)", pfxbuf,
                   mc_s_serv.motd.c, mc_s_serv.motd.m);
    subtotal += mc_s_serv.motd.m;
    if (detail && mc_s_serv.shortmotd.c)
        sendto_one(cptr, "%s    smotd lines: %d (%lu bytes)", pfxbuf,
                   mc_s_serv.shortmotd.c, mc_s_serv.shortmotd.m);
    subtotal += mc_s_serv.shortmotd.m;
    if (detail && mc_s_serv.help.c)
        sendto_one(cptr, "%s    help lines: %d (%lu bytes)", pfxbuf,
                   mc_s_serv.help.c, mc_s_serv.help.m);
    subtotal += mc_s_serv.help.m;

    if (detail)
        sendto_one(cptr, "%s    TOTAL: %lu bytes", pfxbuf, subtotal);
    else
        sendto_one(cptr, "%sConfiguration: %lu bytes", pfxbuf, subtotal);
    rep_total += subtotal;


    /*
     * Detail clones-related memory.
     */
    if (detail)
        sendto_one(cptr, "%sClones", pfxbuf);
    subtotal = 0;
    if (detail && mc_clones.e_cloneents)
        sendto_one(cptr, "%s    clone entries: %d (%lu bytes)", pfxbuf,
                   mc_clones.e_cloneents,
                   mc_clones.e_cloneents * mcbh_clones.objsize);
    subtotal += mc_clones.e_cloneents * mcbh_clones.objsize;
    if (detail && mcgh_clones.hashtable.c)
        sendto_one(cptr, "%s    hashtable: %d (%lu bytes)", pfxbuf,
                   mcgh_clones.hashtable.c, mcgh_clones.hashtable.m);
    subtotal += mcgh_clones.hashtable.m;
    if (detail && mcgh_clones.buckets.c)
        sendto_one(cptr, "%s    hash buckets: %d (%lu bytes)", pfxbuf,
                   mcgh_clones.buckets.c, mcgh_clones.buckets.m);
    subtotal += mcgh_clones.buckets.m;
    if (detail && mcgh_clones.e_hashents)
        sendto_one(cptr, "%s    hash entries: %d (%lu bytes)", pfxbuf,
                   mcgh_clones.e_hashents,
                   mcgh_clones.e_hashents * mcbh_hashents.objsize);
    subtotal += mcgh_clones.e_hashents * mcbh_hashents.objsize;

    if (detail)
        sendto_one(cptr, "%s    TOTAL: %lu bytes", pfxbuf, subtotal);
    else
        sendto_one(cptr, "%sClones: %lu bytes", pfxbuf, subtotal);
    rep_total += subtotal;

    mcbh_clones.knownobjs += mc_clones.e_cloneents;
    mcbh_hashents.knownobjs += mcgh_clones.e_hashents;


#ifdef THROTTLE_ENABLE
    /*
     * Detail throttles-related memory.
     */
    if (detail)
        sendto_one(cptr, "%sThrottles", pfxbuf);
    subtotal = 0;
    if (detail && mc_throttle.e_throttles)
        sendto_one(cptr, "%s    throttle entries: %d (%lu bytes)", pfxbuf,
                   mc_throttle.e_throttles,
                   mc_throttle.e_throttles * mcbh_throttles.objsize);
    subtotal += mc_throttle.e_throttles * mcbh_throttles.objsize;
    if (detail && mcgh_throttles.hashtable.c)
        sendto_one(cptr, "%s    hashtable: %d (%lu bytes)", pfxbuf,
                   mcgh_throttles.hashtable.c, mcgh_throttles.hashtable.m);
    subtotal += mcgh_throttles.hashtable.m;
    if (detail && mcgh_throttles.buckets.c)
        sendto_one(cptr, "%s    hash buckets: %d (%lu bytes)", pfxbuf,
                   mcgh_throttles.buckets.c, mcgh_throttles.buckets.m);
    subtotal += mcgh_throttles.buckets.m;
    if (detail && mcgh_throttles.e_hashents)
        sendto_one(cptr, "%s    hash entries: %d (%lu bytes)", pfxbuf,
                   mcgh_throttles.e_hashents,
                   mcgh_throttles.e_hashents * mcbh_hashents.objsize);
    subtotal += mcgh_throttles.e_hashents * mcbh_hashents.objsize;

    if (detail)
        sendto_one(cptr, "%s    TOTAL: %lu bytes", pfxbuf, subtotal);
    else
        sendto_one(cptr, "%sThrottles: %lu bytes", pfxbuf, subtotal);
    rep_total += subtotal;

    mcbh_throttles.knownobjs += mc_throttle.e_throttles;
    mcbh_hashents.knownobjs += mcgh_throttles.e_hashents;
#endif


    /*
     * Detail miscellaneous memory.
     */
    if (detail)
        sendto_one(cptr, "%sMiscellaneous", pfxbuf);
    subtotal = 0;
    if (detail && mc_hide.fakelinks.c)
        sendto_one(cptr, "%s    fakelink servers: %d (%lu bytes)", pfxbuf,
                   mc_hide.fakelinks.c, mc_hide.fakelinks.m);
    subtotal += mc_hide.fakelinks.m;
    if (detail && mc_hide.e_links)
        sendto_one(cptr, "%s    fakelink links: %d (%lu bytes)", pfxbuf,
                   mc_hide.e_links, mc_hide.e_links * mcbh_links.objsize);
    subtotal += mc_hide.e_links * mcbh_links.objsize;
#ifdef USE_HOOKMODULES
    if (detail && mc_modules.modules.c)
        sendto_one(cptr, "%s    modules: %d (%lu bytes)", pfxbuf,
                   mc_modules.modules.c, mc_modules.modules.m);
    subtotal += mc_modules.modules.m;
    if (detail && mc_modules.hooks.c)
        sendto_one(cptr, "%s    module hooks: %d (%lu bytes)", pfxbuf,
                   mc_modules.hooks.c, mc_modules.hooks.m);
    subtotal += mc_modules.hooks.m;
    if (detail && mc_modules.e_dlinks)
        sendto_one(cptr, "%s    module dlinks: %d (%lu bytes)", pfxbuf,
                   mc_modules.e_dlinks,
                   mc_modules.e_dlinks * mcbh_dlinks.objsize);
    subtotal += mc_modules.e_dlinks * mcbh_dlinks.objsize;
#endif
    if (detail && mc_parse.msgnodes.c)
        sendto_one(cptr, "%s    parser nodes: %d (%lu bytes)", pfxbuf,
                   mc_parse.msgnodes.c, mc_parse.msgnodes.m);
    subtotal += mc_parse.msgnodes.m;
    if (detail && mc_res.cached.c)
        sendto_one(cptr, "%s    dns cache entries: %d (%lu bytes)", pfxbuf,
                   mc_res.cached.c, mc_res.cached.m);
    subtotal += mc_res.cached.m;
    if (detail && mc_res.requests.c)
        sendto_one(cptr, "%s    dns active requests: %d (%lu bytes)", pfxbuf,
                   mc_res.requests.c, mc_res.requests.m);
    subtotal += mc_res.requests.m;
    if (detail && mc_s_bsd.listeners.c)
        sendto_one(cptr, "%s    listeners: %d (%lu bytes)", pfxbuf,
                   mc_s_bsd.listeners.c, mc_s_bsd.listeners.m);
    subtotal += mc_s_bsd.listeners.m;
#ifdef MAXBUFFERS
    if (detail && mc_s_bsd.s_readbuf.c)
        sendto_one(cptr, "%s    read buffer: %lu bytes", pfxbuf,
                   mc_s_bsd.s_readbuf.m);
    subtotal += mc_s_bsd.s_readbuf.m;
#endif
    if (detail && mc_scache.cached.c)
        sendto_one(cptr, "%s    scache: %d (%lu bytes)", pfxbuf,
                   mc_scache.cached.c, mc_scache.cached.m);
    subtotal += mc_scache.cached.m;

    if (detail)
        sendto_one(cptr, "%s    TOTAL: %lu bytes", pfxbuf, subtotal);
    else
        sendto_one(cptr, "%sMiscellaneous: %lu bytes", pfxbuf, subtotal);
    rep_total += subtotal;

    mcbh_links.knownobjs += mc_hide.e_links;
#ifdef USE_HOOKMODULES
    mcbh_dlinks.knownobjs += mc_modules.e_dlinks;
#endif


    /*
     * Detail block allocator memory.
     */
    if (detail)
        sendto_one(cptr, "%sBlock Allocators", pfxbuf);
    subtotal = 0;
    if (detail)
    {
        sendto_one(cptr, "%s    local clients:", pfxbuf);
        sendto_one(cptr, "%s        objects: %d (%lu bytes)"
                   " [pool: %d (%lu bytes)]", pfxbuf,
                   mcbh_local_clients.objects.c, mcbh_local_clients.objects.m,
                   mcbh_local_clients.pool.c, mcbh_local_clients.pool.m);
        sendto_one(cptr, "%s        overhead: %lu bytes"
                   " [blocks: %d (%lu bytes)]", pfxbuf,
                   mcbh_local_clients.management.m,
                   mcbh_local_clients.blocks.c, mcbh_local_clients.blocks.m);
    }
    /* allocated objects were reported by the section they were used in */
    subtotal += mcbh_local_clients.total.m - mcbh_local_clients.objects.m;
    if (detail)
    {
        sendto_one(cptr, "%s    remote clients:", pfxbuf);
        sendto_one(cptr, "%s        objects: %d (%lu bytes)"
                   " [pool: %d (%lu bytes)]", pfxbuf,
                   mcbh_remote_clients.objects.c,
                   mcbh_remote_clients.objects.m,
                   mcbh_remote_clients.pool.c,
                   mcbh_remote_clients.pool.m);
        sendto_one(cptr, "%s        overhead: %lu bytes"
                   " [blocks: %d (%lu bytes)]", pfxbuf,
                   mcbh_remote_clients.management.m,
                   mcbh_remote_clients.blocks.c, mcbh_remote_clients.blocks.m);
    }
    subtotal += mcbh_remote_clients.total.m - mcbh_remote_clients.objects.m;
    if (detail)
    {
        sendto_one(cptr, "%s    users:", pfxbuf);
        sendto_one(cptr, "%s        objects: %d (%lu bytes)"
                   " [pool: %d (%lu bytes)]", pfxbuf,
                   mcbh_users.objects.c, mcbh_users.objects.m,
                   mcbh_users.pool.c, mcbh_users.pool.m);
        sendto_one(cptr, "%s        overhead: %lu bytes"
                   " [blocks: %d (%lu bytes)]", pfxbuf,
                   mcbh_users.management.m,
                   mcbh_users.blocks.c, mcbh_users.blocks.m);
    }
    subtotal += mcbh_users.total.m - mcbh_users.objects.m;
    if (detail)
    {
        sendto_one(cptr, "%s    channels:", pfxbuf);
        sendto_one(cptr, "%s        objects: %d (%lu bytes)"
                   " [pool: %d (%lu bytes)]", pfxbuf,
                   mcbh_channels.objects.c, mcbh_channels.objects.m,
                   mcbh_channels.pool.c, mcbh_channels.pool.m);
        sendto_one(cptr, "%s        overhead: %lu bytes"
                   " [blocks: %d (%lu bytes)]", pfxbuf,
                   mcbh_channels.management.m,
                   mcbh_channels.blocks.c, mcbh_channels.blocks.m);
    }
    subtotal += mcbh_channels.total.m - mcbh_channels.objects.m;
    if (detail)
    {
        sendto_one(cptr, "%s    channel members:", pfxbuf);
        sendto_one(cptr, "%s        objects: %d (%lu bytes)"
                   " [pool: %d (%lu bytes)]", pfxbuf,
                   mcbh_chanmembers.objects.c, mcbh_chanmembers.objects.m,
                   mcbh_chanmembers.pool.c, mcbh_chanmembers.pool.m);
        sendto_one(cptr, "%s        overhead: %lu bytes"
                   " [blocks: %d (%lu bytes)]", pfxbuf,
                   mcbh_chanmembers.management.m,
                   mcbh_chanmembers.blocks.c, mcbh_chanmembers.blocks.m);
    }
    subtotal += mcbh_chanmembers.total.m - mcbh_chanmembers.objects.m;
    if (detail)
    {
        sendto_one(cptr, "%s    links:", pfxbuf);
        sendto_one(cptr, "%s        objects: %d (%lu bytes)"
                   " [pool: %d (%lu bytes)]", pfxbuf,
                   mcbh_links.objects.c, mcbh_links.objects.m,
                   mcbh_links.pool.c, mcbh_links.pool.m);
        sendto_one(cptr, "%s        overhead: %lu bytes"
                   " [blocks: %d (%lu bytes)]", pfxbuf,
                   mcbh_links.management.m,
                   mcbh_links.blocks.c, mcbh_links.blocks.m);
    }
    subtotal += mcbh_links.total.m - mcbh_links.objects.m;
    if (detail)
    {
        sendto_one(cptr, "%s    dlinks:", pfxbuf);
        sendto_one(cptr, "%s        objects: %d (%lu bytes)"
                   " [pool: %d (%lu bytes)]", pfxbuf,
                   mcbh_dlinks.objects.c, mcbh_dlinks.objects.m,
                   mcbh_dlinks.pool.c, mcbh_dlinks.pool.m);
        sendto_one(cptr, "%s        overhead: %lu bytes"
                   " [blocks: %d (%lu bytes)]", pfxbuf,
                   mcbh_dlinks.management.m,
                   mcbh_dlinks.blocks.c, mcbh_dlinks.blocks.m);
    }
    subtotal += mcbh_dlinks.total.m - mcbh_dlinks.objects.m;
#ifdef FLUD
    if (detail)
    {
        sendto_one(cptr, "%s    fludbots:", pfxbuf);
        sendto_one(cptr, "%s        objects: %d (%lu bytes)"
                   " [pool: %d (%lu bytes)]", pfxbuf,
                   mcbh_fludbots.objects.c, mcbh_fludbots.objects.m,
                   mcbh_fludbots.pool.c, mcbh_fludbots.pool.m);
        sendto_one(cptr, "%s        overhead: %lu bytes"
                   " [blocks: %d (%lu bytes)]", pfxbuf,
                   mcbh_fludbots.management.m,
                   mcbh_fludbots.blocks.c, mcbh_fludbots.blocks.m);
    }
    subtotal += mcbh_fludbots.total.m - mcbh_fludbots.objects.m;
#endif
    if (detail)
    {
        sendto_one(cptr, "%s    clones:", pfxbuf);
        sendto_one(cptr, "%s        objects: %d (%lu bytes)"
                   " [pool: %d (%lu bytes)]", pfxbuf,
                   mcbh_clones.objects.c, mcbh_clones.objects.m,
                   mcbh_clones.pool.c, mcbh_clones.pool.m);
        sendto_one(cptr, "%s        overhead: %lu bytes"
                   " [blocks: %d (%lu bytes)]", pfxbuf,
                   mcbh_clones.management.m,
                   mcbh_clones.blocks.c, mcbh_clones.blocks.m);
    }
    subtotal += mcbh_clones.total.m - mcbh_clones.objects.m;
#ifdef THROTTLE_ENABLE
    if (detail)
    {
        sendto_one(cptr, "%s    throttles:", pfxbuf);
        sendto_one(cptr, "%s        objects: %d (%lu bytes)"
                   " [pool: %d (%lu bytes)]", pfxbuf,
                   mcbh_throttles.objects.c, mcbh_throttles.objects.m,
                   mcbh_throttles.pool.c, mcbh_throttles.pool.m);
        sendto_one(cptr, "%s        overhead: %lu bytes"
                   " [blocks: %d (%lu bytes)]", pfxbuf,
                   mcbh_throttles.management.m,
                   mcbh_throttles.blocks.c, mcbh_throttles.blocks.m);
    }
    subtotal += mcbh_throttles.total.m - mcbh_throttles.objects.m;
#endif
    if (detail)
    {
        sendto_one(cptr, "%s    hash entries:", pfxbuf);
        sendto_one(cptr, "%s        objects: %d (%lu bytes)"
                   " [pool: %d (%lu bytes)]", pfxbuf,
                   mcbh_hashents.objects.c, mcbh_hashents.objects.m,
                   mcbh_hashents.pool.c, mcbh_hashents.pool.m);
        sendto_one(cptr, "%s        overhead: %lu bytes"
                   " [blocks: %d (%lu bytes)]", pfxbuf,
                   mcbh_hashents.management.m,
                   mcbh_hashents.blocks.c, mcbh_hashents.blocks.m);
    }
    subtotal += mcbh_hashents.total.m - mcbh_hashents.objects.m;

    /* subtotal does not recount allocated objects, so sum of displayed
       subtotals matches final total */
    if (detail)
        sendto_one(cptr, "%s    TOTAL: %lu bytes", pfxbuf, subtotal);
    else
        sendto_one(cptr, "%sBlock heaps: %lu bytes", pfxbuf, subtotal);
    rep_total += subtotal;


    /*
     * Detail shared buffer-related memory.
     */
    if (detail)
        sendto_one(cptr, "%sShared Buffers", pfxbuf);
    subtotal = 0;
    if (detail)
        sendto_one(cptr, "%s    small buffers: %d (%lu bytes)"
                   " [pool: %d (%lu bytes)]", pfxbuf,
                   mc_sbuf.smallbufs.c, mc_sbuf.smallbufs.m,
                   mc_sbuf.smallbufpool.c, mc_sbuf.smallbufpool.m);
    subtotal += mc_sbuf.smallbufpool.m;
    if (detail)
        sendto_one(cptr, "%s    large buffers: %d (%lu bytes)"
                   " [pool: %d (%lu bytes)]", pfxbuf,
                   mc_sbuf.largebufs.c, mc_sbuf.largebufs.m,
                   mc_sbuf.largebufpool.c, mc_sbuf.largebufpool.m);
    subtotal += mc_sbuf.largebufpool.m;
    if (detail)
    {
        sendto_one(cptr, "%s    overhead: %lu bytes", pfxbuf,
                   mc_sbuf.management.m);
        sendto_one(cptr, "%s        headers: %d (%lu bytes)", pfxbuf,
                   mc_sbuf.bufheaders.c, mc_sbuf.bufheaders.m);
        sendto_one(cptr, "%s        users: %d (%lu bytes)"
                   " [pool: %d (%lu bytes)]", pfxbuf,
                   mc_sbuf.users.c, mc_sbuf.users.m,
                   mc_sbuf.userpool.c, mc_sbuf.userpool.m);
        sendto_one(cptr, "%s        user blocks: %d (%lu bytes)", pfxbuf,
                   mc_sbuf.userblocks.c, mc_sbuf.userblocks.m);
        sendto_one(cptr, "%s        buffer blocks: %d (%lu bytes)", pfxbuf,
                   mc_sbuf.bufblocks.c, mc_sbuf.bufblocks.m);
    }
    subtotal += mc_sbuf.management.m;

    if (detail)
        sendto_one(cptr, "%s    TOTAL: %lu bytes", pfxbuf, subtotal);
    else
        sendto_one(cptr, "%sShared buffers: %lu bytes", pfxbuf, subtotal);
    rep_total += subtotal;


    /*
     * Detail static resources.  Not counted in the general statistics.
     */
    if (detail)
    {
        sendto_one(cptr, "%sStatic Resources (not part of total)", pfxbuf);
        subtotal = 0;
        sendto_one(cptr, "%s    client hashtable: %d (%lu bytes)", pfxbuf,
                   mc_hash.s_clienthash.c, mc_hash.s_clienthash.m);
        subtotal += mc_hash.s_clienthash.m;
        sendto_one(cptr, "%s    channel hashtable: %d (%lu bytes)", pfxbuf,
                   mc_hash.s_channelhash.c, mc_hash.s_channelhash.m);
        subtotal += mc_hash.s_channelhash.m;
        sendto_one(cptr, "%s    dns cache hashtable: %d (%lu bytes)", pfxbuf,
                   mc_res.s_cachehash.c, mc_res.s_cachehash.m);
        subtotal += mc_res.s_cachehash.m;
        sendto_one(cptr, "%s    dns request hashtable: %d (%lu bytes)",
                   pfxbuf, mc_res.s_requesthash.c, mc_res.s_requesthash.m);
        subtotal += mc_res.s_requesthash.m;
        sendto_one(cptr, "%s    scache hashtable: %d (%lu bytes)", pfxbuf,
                   mc_scache.s_hash.c, mc_scache.s_hash.m);
        subtotal += mc_scache.s_hash.m;
        sendto_one(cptr, "%s    watch hashtable: %d (%lu bytes)", pfxbuf,
                   mc_hash.s_watchhash.c, mc_hash.s_watchhash.m);
        subtotal += mc_hash.s_watchhash.m;
        sendto_one(cptr, "%s    whowas hashtable: %d (%lu bytes)", pfxbuf,
                   mc_whowas.s_hash.c, mc_whowas.s_hash.m);
        subtotal += mc_whowas.s_hash.m;
        sendto_one(cptr, "%s    whowas array: %d (%lu bytes)", pfxbuf,
                   mc_whowas.s_whowas.c, mc_whowas.s_whowas.m);
        subtotal += mc_whowas.s_whowas.m;
        sendto_one(cptr, "%s    fd master table: %d (%lu bytes)", pfxbuf,
                   mc_fds.s_fdlist.c, mc_fds.s_fdlist.m);
        subtotal += mc_fds.s_fdlist.m;
        sendto_one(cptr, "%s    local connection table: %d (%lu bytes)",
                   pfxbuf, mc_s_bsd.s_local.c, mc_s_bsd.s_local.m);
        subtotal += mc_s_bsd.s_local.m;
        sendto_one(cptr, "%s    msgtab entries: %d (%lu bytes)", pfxbuf,
                   mc_parse.s_msgtab.c, mc_parse.s_msgtab.m);
        subtotal += mc_parse.s_msgtab.m;
#ifdef RWHO_PROBABILITY
        sendto_one(cptr, "%s    rwho probability map: %lu bytes", pfxbuf,
                   mc_probability.s_prob.m);
        subtotal += mc_probability.s_prob.m;
#endif
        sendto_one(cptr, "%s    channel scratch buffers: %d (%lu bytes)",
                   pfxbuf, mc_channel.s_scratch.c, mc_channel.s_scratch.m);
        subtotal += mc_channel.s_scratch.m;
        sendto_one(cptr, "%s    configuration buffers: %d (%lu bytes)",
                   pfxbuf, mc_ircd.s_confbuf.c, mc_ircd.s_confbuf.m);
        subtotal += mc_ircd.s_confbuf.m;
        sendto_one(cptr, "%s    parse buffers: %d (%lu bytes)", pfxbuf,
                   mc_parse.s_bufs.c, mc_parse.s_bufs.m);
        subtotal += mc_parse.s_bufs.m;
#ifndef MAXBUFFERS
        sendto_one(cptr, "%s    read buffer: %lu bytes", pfxbuf,
                   mc_s_bsd.s_readbuf.m);
        subtotal += mc_s_bsd.s_readbuf.m;
#endif
        sendto_one(cptr, "%s    send buffers: %d (%lu bytes)", pfxbuf,
                   mc_send.s_bufs.c, mc_send.s_bufs.m);
        subtotal += mc_send.s_bufs.m;
        sendto_one(cptr, "%s    zip buffers: %d (%lu bytes)", pfxbuf,
                   mc_zlink.s_bufs.c, mc_zlink.s_bufs.m);
        subtotal += mc_zlink.s_bufs.m;
        sendto_one(cptr, "%s    TOTAL: %lu bytes", pfxbuf, subtotal);
    }


    /*
     * Ok, we're done with details.  Now some sanity checks.
     *
     * First, verify that we actually reported everything we know about.
     * Then some untraced leak checks against the block allocator, followed
     * up with leak checks against the tracer (if MEMTRACE).
     *
     * Finally we print a nice summary, and the (old) usage report from the OS.
     */

    sendto_one(cptr, "%s-----", pfxbuf);

    if (rep_total != alloc_total)
    {
        sendto_one(cptr, "%sUNREPORTED: %ld bytes", pfxbuf,
                   alloc_total - rep_total);
    }

    /*
     * Untraced leak check: block heaps
     */
    if (mcbh_clones.knownobjs != mcbh_clones.objects.c)
    {
        int diff = mcbh_clones.objects.c - mcbh_clones.knownobjs;
        sendto_one(cptr, "%sLEAK: %d objects (%lu bytes)"
                   " from clones blockheap", pfxbuf, diff,
                   diff * mcbh_clones.objsize);
    }

    if (mcbh_local_clients.knownobjs != mcbh_local_clients.objects.c)
    {
        int diff = mcbh_local_clients.objects.c - mcbh_local_clients.knownobjs;
        sendto_one(cptr, "%sLEAK: %d objects (%lu bytes)"
                   " from local clients blockheap", pfxbuf, diff,
                   diff * mcbh_local_clients.objsize);
    }

    if (mcbh_remote_clients.knownobjs != mcbh_remote_clients.objects.c)
    {
        int diff = mcbh_remote_clients.objects.c
                   - mcbh_remote_clients.knownobjs;
        sendto_one(cptr, "%sLEAK: %d objects (%lu bytes)"
                   " from remote clients blockheap", pfxbuf, diff,
                   diff * mcbh_remote_clients.objsize);
    }

    if (mcbh_links.knownobjs != mcbh_links.objects.c)
    {
        int diff = mcbh_links.objects.c - mcbh_links.knownobjs;
        sendto_one(cptr, "%sLEAK: %d objects (%lu bytes)"
                   " from links blockheap", pfxbuf, diff,
                   diff * mcbh_links.objsize);
    }

    if (mcbh_dlinks.knownobjs != mcbh_dlinks.objects.c)
    {
        int diff = mcbh_dlinks.objects.c - mcbh_dlinks.knownobjs;
        sendto_one(cptr, "%sLEAK: %d objects (%lu bytes)"
                   " from dlinks blockheap", pfxbuf, diff,
                   diff * mcbh_dlinks.objsize);
    }

    if (mcbh_chanmembers.knownobjs != mcbh_chanmembers.objects.c)
    {
        int diff = mcbh_chanmembers.objects.c - mcbh_chanmembers.knownobjs;
        sendto_one(cptr, "%sLEAK: %d objects (%lu bytes)"
                   " from chanmembers blockheap", pfxbuf, diff,
                   diff * mcbh_chanmembers.objsize);
    }

    if (mcbh_users.knownobjs != mcbh_users.objects.c)
    {
        int diff = mcbh_users.objects.c - mcbh_users.knownobjs;
        sendto_one(cptr, "%sLEAK: %d objects (%lu bytes)"
                   " from users blockheap", pfxbuf, diff,
                   diff * mcbh_users.objsize);
    }

    if (mcbh_channels.knownobjs != mcbh_channels.objects.c)
    {
        int diff = mcbh_channels.objects.c - mcbh_channels.knownobjs;
        sendto_one(cptr, "%sLEAK: %d objects (%lu bytes)"
                   " from channels blockheap", pfxbuf, diff,
                   diff * mcbh_channels.objsize);
    }

    if (mcbh_hashents.knownobjs != mcbh_hashents.objects.c)
    {
        int diff = mcbh_hashents.objects.c - mcbh_hashents.knownobjs;
        sendto_one(cptr, "%sLEAK: %d objects (%lu bytes)"
                   " from hashents blockheap", pfxbuf, diff,
                   diff * mcbh_hashents.objsize);
    }

#ifdef FLUD
    if (mcbh_fludbots.knownobjs != mcbh_fludbots.objects.c)
    {
        int diff = mcbh_fludbots.objects.c - mcbh_fludbots.knownobjs;
        sendto_one(cptr, "%sLEAK: %d objects (%lu bytes)"
                   " from fludbots blockheap", pfxbuf, diff,
                   diff * mcbh_fludbots.objsize);
    }
#endif

#ifdef THROTTLE_ENABLE
    if (mcbh_throttles.knownobjs != mcbh_throttles.objects.c)
    {
        int diff = mcbh_throttles.objects.c - mcbh_throttles.knownobjs;
        sendto_one(cptr, "%sLEAK: %d objects (%lu bytes)"
                   " from throttles blockheap", pfxbuf, diff,
                   diff * mcbh_throttles.objsize);
    }
#endif

    
#ifdef MEMTRACE
    /*
     * Traced leak check
     */

    /* blalloc.c */
    traced_total += memtrace_count(&tc_blalloc, mc_blalloc.file);
    if (alloc_heap != tc_blalloc.allocated.m)
    {
        sendto_one(cptr, "%sLEAK: %ld bytes from block allocator", pfxbuf,
                   tc_blalloc.allocated.m - alloc_heap);
        if (detail)
            memtrace_report(cptr, mc_blalloc.file);
    }

    /* channel.c */
    traced_total += memtrace_count(&tc_channel, mc_channel.file);
    if (mc_channel.total.m != tc_channel.allocated.m)
    {
        sendto_one(cptr, "%sLEAK: %ld bytes from channels", pfxbuf,
                   tc_channel.allocated.m - mc_channel.total.m);
        if (detail)
            memtrace_report(cptr, mc_channel.file);
    }

    /* hash.c */
    traced_total += memtrace_count(&tc_hash, mc_hash.file);
    if (mc_hash.total.m != tc_hash.allocated.m)
    {
        sendto_one(cptr, "%sLEAK: %ld bytes from watch hash", pfxbuf,
                   tc_hash.allocated.m - mc_hash.total.m);
        if (detail)
            memtrace_report(cptr, mc_hash.file);
    }

    /* hide.c */
    traced_total += memtrace_count(&tc_hide, mc_hide.file);
    if (mc_hide.total.m != tc_hide.allocated.m)
    {
        sendto_one(cptr, "%sLEAK: %ld bytes from fake links", pfxbuf,
                   tc_hide.allocated.m - mc_hide.total.m);
        if (detail)
            memtrace_report(cptr, mc_hide.file);
    }

    /* list.c */
    traced_total += memtrace_count(&tc_list, mc_list.file);
    subtotal = 0;
    subtotal += mc_s_conf.connects.c * sizeof(aConnect);
    subtotal += mc_s_conf.allows.c * sizeof(aAllow);
    subtotal += mc_s_conf.me.c * sizeof(Conf_Me);
    subtotal += mc_s_conf.opers.c * sizeof(aOper);
    subtotal += mc_s_conf.ports.c * sizeof(aPort);
    subtotal += mc_s_conf.classes.c * sizeof(aClass);
    subtotal += mc_s_user.servers.c * sizeof(aServer);
    if (subtotal != tc_list.allocated.m)
    {
        sendto_one(cptr, "%sLEAK: %ld bytes from confs/servers", pfxbuf,
                   tc_list.allocated.m - subtotal);
        if (detail)
            memtrace_report(cptr, mc_list.file);
    }

    /* parse.c */
    traced_total += memtrace_count(&tc_parse, mc_parse.file);
    if (mc_parse.total.m != tc_parse.allocated.m)
    {
        sendto_one(cptr, "%sLEAK: %ld bytes from parser", pfxbuf,
                   tc_parse.allocated.m - mc_parse.total.m);
        if (detail)
            memtrace_report(cptr, mc_parse.file);
    }

    /* res.c */
    traced_total += memtrace_count(&tc_res, mc_res.file);
    if (mc_res.total.m != tc_res.allocated.m)
    {
        sendto_one(cptr, "%sLEAK: %ld bytes from resolver", pfxbuf,
                   tc_res.allocated.m - mc_res.total.m);
        if (detail)
            memtrace_report(cptr, mc_res.file);
    }

    /* s_bsd.c */
    traced_total += memtrace_count(&tc_s_bsd, mc_s_bsd.file);
    if (mc_s_bsd.total.m != tc_s_bsd.allocated.m)
    {
        sendto_one(cptr, "%sLEAK: %ld bytes from listeners", pfxbuf,
                   tc_s_bsd.allocated.m - mc_s_bsd.total.m);
        if (detail)
            memtrace_report(cptr, mc_s_bsd.file);
    }

    /* s_user.c */
    traced_total += memtrace_count(&tc_s_user, mc_s_user.file);
    subtotal = mc_s_user.total.m;
    subtotal -= mc_s_user.servers.c * sizeof(aServer);
    if (subtotal != tc_s_user.allocated.m)
    {
        sendto_one(cptr, "%sLEAK: %ld bytes from users", pfxbuf,
                   tc_s_user.allocated.m - mc_s_user.total.m);
        if (detail)
            memtrace_report(cptr, mc_s_user.file);
    }

    /* sbuf.c */
    traced_total += memtrace_count(&tc_sbuf, mc_sbuf.file);
    if (mc_sbuf.total.m != tc_sbuf.allocated.m)
    {
        sendto_one(cptr, "%sLEAK: %ld bytes from sbuf", pfxbuf,
                   tc_sbuf.allocated.m - mc_sbuf.total.m);
        if (detail)
            memtrace_report(cptr, mc_sbuf.file);
    }

    /* scache.c */
    traced_total += memtrace_count(&tc_scache, mc_scache.file);
    if (mc_scache.total.m != tc_scache.allocated.m)
    {
        sendto_one(cptr, "%sLEAK: %ld bytes from scache", pfxbuf,
                   tc_scache.allocated.m - mc_scache.total.m);
        if (detail)
            memtrace_report(cptr, mc_scache.file);
    }

    /* throttle.c */
    traced_total += memtrace_count(&tc_throttle, mc_throttle.file);
    subtotal = mcgh_clones.total.m;
#ifdef THROTTLE_ENABLE
    subtotal += mcgh_throttles.total.m;
#endif
    if (subtotal != tc_throttle.allocated.m)
    {
        sendto_one(cptr, "%sLEAK: %ld bytes from generic hash", pfxbuf,
                   tc_throttle.allocated.m - subtotal);
        if (detail)
            memtrace_report(cptr, mc_throttle.file);
    }

    /* zlink.c */
    traced_total += memtrace_count(&tc_zlink, mc_zlink.file);
    subtotal = 0;
    subtotal += mc_s_user.e_zipin_sessions * mc_zlink.m_insession_size;
    subtotal += mc_s_user.e_zipout_sessions * mc_zlink.m_outsession_size;
    if (subtotal != tc_zlink.allocated.m)
    {
        sendto_one(cptr, "%sLEAK: %ld bytes from zlink", pfxbuf,
                   tc_zlink.allocated.m - subtotal);
        if (detail)
            memtrace_report(cptr, mc_zlink.file);
    }

#ifdef HAVE_ENCRYPTION_ON
    /* dh.c */
    traced_total += memtrace_count(&tc_dh, mc_dh.file);
    subtotal = mc_s_user.e_dh_sessions * mc_dh.m_dhsession_size;
    if (subtotal != tc_dh.allocated.m)
    {
        sendto_one(cptr, "%sLEAK: %ld bytes from DH sessions", pfxbuf,
                   tc_dh.allocated.m - subtotal);
        if (detail)
            memtrace_report(cptr, mc_dh.file);
    }

    /* rc4.c */
    traced_total += memtrace_count(&tc_rc4, mc_rc4.file);
    subtotal = mc_s_user.e_rc4states * mc_rc4.m_rc4state_size;
    if (subtotal != tc_rc4.allocated.m)
    {
        sendto_one(cptr, "%sLEAK: %ld bytes from RC4 states", pfxbuf,
                   tc_rc4.allocated.m - subtotal);
        if (detail)
            memtrace_report(cptr, mc_rc4.file);
    }
#endif

    /* grouped: m_services.c s_conf.c s_serv.c userban.c */
    /* yeah, this is screwy... */
    traced_total += memtrace_count(&tc_m_services, mc_m_services.file);
    traced_total += memtrace_count(&tc_s_conf, mc_s_conf.file);
    traced_total += memtrace_count(&tc_s_serv, mc_s_serv.file);
    traced_total += memtrace_count(&tc_userban, mc_userban.file);
    subtotal = mc_s_conf.total.m + mc_s_serv.total.m + mc_userban.total.m;
    subtotal -= mc_s_conf.connects.c * sizeof(aConnect);
    subtotal -= mc_s_conf.allows.c * sizeof(aAllow);
    subtotal -= mc_s_conf.me.c * sizeof(Conf_Me);
    subtotal -= mc_s_conf.opers.c * sizeof(aOper);
    subtotal -= mc_s_conf.ports.c * sizeof(aPort);
    subtotal -= mc_s_conf.classes.c * sizeof(aClass);
    traced_subtotal = tc_m_services.allocated.m;
    traced_subtotal += tc_s_conf.allocated.m;
    traced_subtotal += tc_s_serv.allocated.m;
    traced_subtotal += tc_userban.allocated.m;
    if (subtotal != traced_subtotal)
    {
        sendto_one(cptr, "%sLEAK: %ld bytes from conf/motd/bans", pfxbuf,
                   traced_subtotal - subtotal);
        if (detail)
        {
            memtrace_report(cptr, mc_m_services.file);
            memtrace_report(cptr, mc_s_conf.file);
            memtrace_report(cptr, mc_s_serv.file);
            memtrace_report(cptr, mc_userban.file);
        }
    }

    traced_total += memtrace_count(&tc_unverified, NULL);
    if (tc_unverified.allocated.m)
    {
        sendto_one(cptr, "%sWARNING: %lu bytes in %d objects have not been"
                   " verified", pfxbuf, tc_unverified.allocated.m,
                   tc_unverified.allocated.c);
        if (detail)
            memtrace_report(cptr, NULL);
    }
#endif  /* MEMTRACE */


    /* the grand summary */
    sendto_one(cptr, "%sTOTAL: %lu bytes (%lu active, %lu cached)",
               pfxbuf, alloc_total, use_total, alloc_total - use_total);


#ifdef MEMTRACE
    /* some tracer statistics, including trace overhead */
    subtotal = tc_blalloc.management.m;
    subtotal += tc_channel.management.m;
    subtotal += tc_hash.management.m;
    subtotal += tc_hide.management.m;
    subtotal += tc_list.management.m;
    subtotal += tc_m_services.management.m;
    subtotal += tc_parse.management.m;
    subtotal += tc_res.management.m;
    subtotal += tc_s_bsd.management.m;
    subtotal += tc_s_conf.management.m;
    subtotal += tc_s_serv.management.m;
    subtotal += tc_s_user.management.m;
    subtotal += tc_sbuf.management.m;
    subtotal += tc_scache.management.m;
    subtotal += tc_throttle.management.m;
    subtotal += tc_userban.management.m;
    subtotal += tc_zlink.management.m;
#ifdef HAVE_ENCRYPTION_ON
    subtotal += tc_dh.management.m;
    subtotal += tc_rc4.management.m;
#endif
    subtotal += tc_unverified.management.m;

    sendto_one(cptr, "%sTraced %lu bytes (%ld leaked)", pfxbuf,
               traced_total, traced_total - alloc_total);
    sendto_one(cptr, "%sTracer overhead is %lu bytes", pfxbuf, subtotal);

    memtrace_reset();
#endif  /* MEMTRACE */

    sendto_one(cptr, "%ssbrk(0)-etext: %u", pfxbuf,
               (u_int) sbrk((size_t) 0) - (u_int) sbrk0);    
}

