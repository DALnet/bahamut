/* Bahamut IRCd, src/m_server.c
 * Copyright (c) 2004, Aaron Wiebe and the Bahamut Team
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
#include "numeric.h"
#include "h.h"
#include "dh.h"
#include "userban.h"
#include "zlink.h"
#include "throttle.h"
#include "clones.h"

/* externally defined functions */

extern void fakelinkserver_update(char *, char *);
extern void fakeserver_sendserver(aClient *);
extern void fakelusers_sendlock(aClient *);
extern void reset_sock_opts(int, int);

/* internal functions */

static void sendnick_TS(aClient *cptr, aClient *acptr)
{
    static char ubuf[12];

    if (IsPerson(acptr))
    {
        send_umode(NULL, acptr, 0, SEND_UMODES, ubuf);
        if (!*ubuf)     /* trivial optimization - Dianora */
        {
            ubuf[0] = '+';
            ubuf[1] = '\0';
        }
        sendto_one(cptr, "NICK %s %d %ld %s %s %s %s %lu %lu :%s",
                       acptr->name, acptr->hopcount + 1, acptr->tsinfo, ubuf,
                       acptr->user->username, acptr->user->host,
                       acptr->user->server, acptr->user->servicestamp,
                       htonl(acptr->ip.s_addr), acptr->info);
    }
}

static int
do_server_estab(aClient *cptr)
{
    aClient *acptr;
    aConnect *aconn;
    aChannel *chptr;
    int i;
    /* "refresh" inpath with host  */
    char *inpath = get_client_name(cptr, HIDEME);

    SetServer(cptr);

    Count.server++;
    Count.myserver++;

    if(IsZipCapable(cptr) && DoZipThis(cptr))
    {
        sendto_one(cptr, "SVINFO ZIP");
        SetZipOut(cptr);
        cptr->serv->zip_out = zip_create_output_session();
    }

#ifdef MAXBUFFERS
    /* let's try to bump up server sock_opts... -Taner */
    reset_sock_opts(cptr->fd, 1);
#endif

    /* adds to server list */
    add_to_list(&server_list, cptr);

    set_effective_class(cptr);

    /* Check one more time for good measure... is it there? */
    if ((acptr = find_name(cptr->name, NULL)))
    {
        char        nbuf[HOSTLEN * 2 + USERLEN + 5];
        aClient *bcptr;

        /*
         * While negotiating stuff, another copy of this server appeared.
         *
         * Rather than KILL the link which introduced it, KILL the
         * youngest of the two links. -avalon
         */

        bcptr = (cptr->firsttime > acptr->from->firsttime) ? cptr :
            acptr->from;
        sendto_one(bcptr, "ERROR :Server %s already exists", cptr->name);
        if (bcptr == cptr)
        {
            sendto_gnotice("from %s: Link %s cancelled, server %s already "
                           "exists (final phase)", me.name,
                           get_client_name(bcptr, HIDEME), cptr->name);
            sendto_serv_butone(bcptr, ":%s GNOTICE :Link %s cancelled, "
                                "server %s already exists (final phase)",
                                me.name, get_client_name(bcptr, HIDEME),
                                cptr->name);
            return exit_client(bcptr, bcptr, &me,
                               "Server Exists (final phase)");
        }
        /* inform all those who care (set +n) -epi */

        strcpy(nbuf, get_client_name(bcptr, HIDEME));
        sendto_gnotice("from %s: Link %s cancelled, server %s reintroduced "
                       "by %s (final phase)", me.name, nbuf, cptr->name,
                       get_client_name(cptr, HIDEME));
        sendto_serv_butone(bcptr, ":%s GNOTICE :Link %s cancelled, server %s "
                           "reintroduced by %s (final phase)", me.name, nbuf,
                           cptr->name, get_client_name(cptr, HIDEME));
        exit_client(bcptr, bcptr, &me, "Server Exists (final phase)");
    }

    /* error, error, error! if a server is U:'d, and it connects to us,
     * we need to figure that out! So, do it here. - lucas
     */

    if (find_aUserver(cptr->name))
    {
        Count.myulined++;
        cptr->flags |= FLAGS_ULINE;

        /* special flags (should really be in conf) */
        if (!mycmp(cptr->name, Services_Name))
            cptr->serv->uflags |=
                (ULF_SFDIRECT|ULF_REQTARGET|ULF_NOBTOPIC|ULF_NOAWAY);
        else if (!mycmp(cptr->name, Stats_Name))
            cptr->serv->uflags |= ULF_NOBTOPIC;
    }

    fakelinkserver_update(cptr->name, cptr->info);

    sendto_gnotice("from %s: Link with %s established, states:%s%s%s%s",
                   me.name, inpath, ZipOut(cptr) ? " Output-compressed" : "",
                   RC4EncLink(cptr) ? " encrypted" : "",
                   IsULine(cptr) ? " ULined" : "",
                   DoesTS(cptr) ? " TS" : " Non-TS");

    /*
     * Notify everyone of the fact that this has just linked: the entire
     * network should get two of these, one explaining the link between
     * me->serv and the other between serv->me
     */

    sendto_serv_butone(NULL, ":%s GNOTICE :Link with %s established: %s",
                       me.name, inpath,
                       DoesTS(cptr) ? "TS link" : "Non-TS link!");

    add_to_client_hash_table(cptr->name, cptr);

    /* add it to scache */

    find_or_add(cptr->name);

    /*
     * Old sendto_serv_but_one() call removed because we now need to
     * send different names to different servers (domain name
     * matching) Send new server to other servers.
     */
    for (i = 0; i <= highest_fd; i++)
    {
        if (!(acptr = local[i]) || !IsServer(acptr) || acptr == cptr ||
            IsMe(acptr))
            continue;
        if ((aconn = acptr->serv->aconn) &&
            !match(my_name_for_link(me.name, aconn), cptr->name))
            continue;
        sendto_one(acptr, ":%s SERVER %s 2 :%s", me.name, cptr->name,
                   cptr->info);
    }

    /*
     * Pass on my client information to the new server
     *
     * First, pass only servers (idea is that if the link gets
     * cancelled beacause the server was already there, there are no
     * NICK's to be cancelled...). Of course, if cancellation occurs,
     * all this info is sent anyway, and I guess the link dies when a
     * read is attempted...? --msa
     *
     * Note: Link cancellation to occur at this point means that at
     * least two servers from my fragment are building up connection
     * this other fragment at the same time, it's a race condition,
     * not the normal way of operation...
     *
     * ALSO NOTE: using the get_client_name for server names-- see
     * previous *WARNING*!!! (Also, original inpath is
     * destroyed...)
     */

    aconn = cptr->serv->aconn;
    for (acptr = &me; acptr; acptr = acptr->prev)
    {
        if (acptr->from == cptr)
            continue;
        if (IsServer(acptr))
        {
            if (match(my_name_for_link(me.name, aconn), acptr->name) == 0)
                continue;
            sendto_one(cptr, ":%s SERVER %s %d :%s",
                       acptr->serv->up, acptr->name,
                       acptr->hopcount + 1, acptr->info);
        }
    }

    /* send out our SQLINES and SGLINES too */
    send_simbans(cptr, SBAN_CHAN|SBAN_NETWORK);
    send_simbans(cptr, SBAN_NICK|SBAN_NETWORK);
    send_simbans(cptr, SBAN_GCOS|SBAN_NETWORK);

    /* Send out fake server list and other 'fake' stuff */
    fakeserver_sendserver(cptr);

    /* send clone list */
    clones_send(cptr);

    /* Bursts are about to start.. send a BURST */
    if (IsBurst(cptr))
        sendto_one(cptr, "BURST");

    /*
     * * Send it in the shortened format with the TS, if it's a TS
     * server; walk the list of channels, sending all the nicks that
     * haven't been sent yet for each channel, then send the channel
     * itself -- it's less obvious than sending all nicks first, but
     * on the receiving side memory will be allocated more nicely
     * saving a few seconds in the handling of a split -orabidoo
     */
    {
        chanMember       *cm;
        static char nickissent = 1;

        nickissent = 3 - nickissent;
        /*
         * flag used for each nick to check if we've sent it yet - must
         * be different each time and !=0, so we alternate between 1 and
         * 2 -orabidoo
         */
        for (chptr = channel; chptr; chptr = chptr->nextch)
        {
            for (cm = chptr->members; cm; cm = cm->next)
            {
                acptr = cm->cptr;
                if (acptr->nicksent != nickissent)
                {
                    acptr->nicksent = nickissent;
                    if (acptr->from != cptr)
                        sendnick_TS(cptr, acptr);
                }
            }
            send_channel_modes(cptr, chptr);
        }
        /* also send out those that are not on any channel */
        for (acptr = &me; acptr; acptr = acptr->prev)
            if (acptr->nicksent != nickissent)
            {
                acptr->nicksent = nickissent;
                if (acptr->from != cptr)
                    sendnick_TS(cptr, acptr);
            }
    }

    if(confopts & FLAGS_HUB)
        fakelusers_sendlock(cptr);

    if(ZipOut(cptr))
    {
        unsigned long inb, outb;
        double rat;

        zip_out_get_stats(cptr->serv->zip_out, &inb, &outb, &rat);

        if(inb)
        {
            sendto_gnotice("from %s: Connect burst to %s: %lu bytes normal, "
                           "%lu compressed (%3.2f%%)", me.name,
                           get_client_name(cptr, HIDEME), inb, outb, rat);
            sendto_serv_butone(cptr, ":%s GNOTICE :Connect burst to %s: %lu "
                               "bytes normal, %lu compressed (%3.2f%%)",
                               me.name, get_client_name(cptr, HIDEME), inb,
                               outb, rat);
        }
    }

    /* stuff a PING at the end of this burst so we can figure out when
       the other side has finished processing it. */
    cptr->flags |= FLAGS_BURST|FLAGS_PINGSENT;
    if (IsBurst(cptr)) cptr->flags |= FLAGS_SOBSENT;
    sendto_one(cptr, "PING :%s", me.name);

    return 0;
}

static int
m_server_estab(aClient *cptr)
{
    aConnect *aconn;

    char       *inpath, *host, *s, *encr;
    int         split;

    inpath = get_client_name(cptr, HIDEME);  /* "refresh" inpath with host  */
    split = mycmp(cptr->name, cptr->sockhost);
    host = cptr->name;

    if (!(aconn = cptr->serv->aconn))
    {
        ircstp->is_ref++;
        sendto_one(cptr, "ERROR :Access denied. No Connect block for server %s",
                   inpath);
        sendto_ops("Access denied. No Connect block for server %s", inpath);
        return exit_client(cptr, cptr, cptr, "No Connect block for server");
    }

    encr = cptr->passwd;
    if (*aconn->apasswd && !StrEq(aconn->apasswd, encr))
    {
        ircstp->is_ref++;
        sendto_one(cptr, "ERROR :No Access (passwd mismatch) %s", inpath);
        sendto_ops("Access denied (passwd mismatch) %s", inpath);
        return exit_client(cptr, cptr, cptr, "Bad Password");
    }
    memset(cptr->passwd, '\0', sizeof(cptr->passwd));

    if(!(confopts & FLAGS_HUB))
    {
        int i;
        for (i = 0; i <= highest_fd; i++)
            if (local[i] && IsServer(local[i]))
            {
                ircstp->is_ref++;
                sendto_one(cptr, "ERROR :I'm a leaf not a hub");
                return exit_client(cptr, cptr, cptr, "I'm a leaf");
            }
    }

    /* aconf->port is a CAPAB field, kind-of. kludge. mm, mm. */
    /* no longer! this should still get better though */
    if((aconn->flags & CONN_ZIP))
        SetZipCapable(cptr);
    if((aconn->flags & CONN_DKEY))
        SetWantDKEY(cptr);
    if (IsUnknown(cptr))
    {
        if (aconn->cpasswd[0])
            sendto_one(cptr, "PASS %s :TS", aconn->cpasswd);

        /* Pass my info to the new server */

#ifdef HAVE_ENCRYPTION_ON
        if(!WantDKEY(cptr))
            sendto_one(cptr, "CAPAB SSJOIN NOQUIT BURST UNCONNECT ZIP "
                       "NICKIP TSMODE");
        else
            sendto_one(cptr, "CAPAB SSJOIN NOQUIT BURST UNCONNECT DKEY "
                       "ZIP NICKIP TSMODE");
#else
        sendto_one(cptr, "CAPAB SSJOIN NOQUIT BURST UNCONNECT ZIP NICKIP TSMODE");
#endif

        sendto_one(cptr, "SERVER %s 1 :%s",
                   my_name_for_link(me.name, aconn),
                   (me.info[0]) ? (me.info) : "IRCers United");
    }
    else 
    {
        s = (char *) strchr(aconn->host, '@');
        *s = '\0';      /* should never be NULL -- wanna bet? -Dianora */

        Debug((DEBUG_INFO, "Check Usernames [%s]vs[%s]", aconn->host,
               cptr->username));
        if (match(aconn->host, cptr->username))
        {
            *s = '@';
            ircstp->is_ref++;
            sendto_ops("Username mismatch [%s]v[%s] : %s",
                       aconn->host, cptr->username,
                       get_client_name(cptr, HIDEME));
            sendto_one(cptr, "ERROR :No Username Match");
            return exit_client(cptr, cptr, cptr, "Bad User");
        }
        *s = '@';
    }

    /* send routing notice, this should never happen anymore */
    if (!DoesTS(cptr))
    {
        sendto_gnotice("from %s: Warning: %s linked, non-TS server",
                       me.name, get_client_name(cptr, TRUE));
        sendto_serv_butone(cptr,
                           ":%s GNOTICE :Warning: %s linked, non-TS server",
                           me.name, get_client_name(cptr, TRUE));
    }

    sendto_one(cptr, "SVINFO %d %d 0 :%ld", TS_CURRENT, TS_MIN,
               (ts_val) timeofday);

    /* sendto one(cptr, "CAPAB ...."); moved to after PASS but before SERVER
     * now in two places.. up above and in s_bsd.c. - lucas
     * This is to make sure we pass on our capabilities before we establish
     * a server connection
     */

    /*
     * *WARNING*
     *   In the following code in place of plain
     * server's name we send what is returned by
     * get_client_name which may add the "sockhost" after the name.
     * It's *very* *important* that there is a SPACE between
     * the name and sockhost (if present). The receiving server
     * will start the information field from this first blank and
     * thus puts the sockhost into info. ...a bit tricky, but
     * you have been warned, besides code is more neat this way...
     * --msa
     */

    cptr->serv->up = me.name;
    cptr->serv->aconn = aconn;

    throttle_remove(inetntoa((char *)&cptr->ip));

    /* now fill out the servers info so nobody knows dink about it. */
    memset((char *)&cptr->ip, '\0', sizeof(struct in_addr));
    strcpy(cptr->hostip, "127.0.0.1");
    strcpy(cptr->sockhost, "localhost");

#ifdef HAVE_ENCRYPTION_ON
    if(!CanDoDKEY(cptr) || !WantDKEY(cptr))
        return do_server_estab(cptr);
    else
    {
        SetNegoServer(cptr); /* VERY IMPORTANT THAT THIS IS HERE */
        sendto_one(cptr, "DKEY START");
    }
#else
    return do_server_estab(cptr);
#endif

    return 0;
}

/*
 *  m_server
 *       parv[0] = sender prefix
 *       parv[1] = servername
 *       parv[2] = serverinfo/hopcount
 *       parv[3] = serverinfo
 */
int m_server(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    int     i;
    char        info[REALLEN + 1], *inpath, *host;
    aClient    *acptr, *bcptr;
    aConnect   *aconn;
    int         hop;
    char        nbuf[HOSTLEN * 2 + USERLEN + 5]; /* same size as in s_misc.c */

    info[0] = '\0';
    inpath = get_client_name(cptr, HIDEME);

    if (parc < 2 || *parv[1] == '\0')
    {
        sendto_one(cptr, "ERROR :No servername");
        return 0;
    }

    hop = 0;
    host = parv[1];
    if (parc > 3 && atoi(parv[2]))
    {
        hop = atoi(parv[2]);
        strncpyzt(info, parv[3], REALLEN);
    }
    else if (parc > 2)
    {
        strncpyzt(info, parv[2], REALLEN);
        if ((parc > 3) && ((i = strlen(info)) < (REALLEN - 2)))
        {
            strcat(info, " ");
            strncat(info, parv[3], REALLEN - i - 2);
            info[REALLEN] = '\0';
        }
    }
    /*
     * July 5, 1997
     * Rewritten to throw away server cruft from users,
     * combined the hostname validity test with cleanup of host name,
     * so a cleaned up hostname can be returned as an error if
     * necessary. - Dianora
     */

    /* yes, the if(strlen) below is really needed!! */
    if (strlen(host) > HOSTLEN)
        host[HOSTLEN] = '\0';

    if (IsPerson(cptr))
    {
        /* A local link that has been identified as a USER tries
         * something fishy... ;-)
         */
        sendto_one(cptr, err_str(ERR_UNKNOWNCOMMAND),
                   me.name, parv[0], "SERVER");

        return 0;
    }
    else
        /* hostile servername check */
    {
        /*
         * Lets check for bogus names and clean them up we don't bother
         * cleaning up ones from users, becasuse we will never see them
         * any more - Dianora
         */

        int bogus_server = 0;
        int found_dot = 0;
        char clean_host[(2 * HOSTLEN) + 1];
        char *s;
        char *d;
        int n;

        s = host;
        d = clean_host;
        n = (2 * HOSTLEN) - 2;

        while (*s && n > 0)
        {
            if ((unsigned char) *s < (unsigned char) ' ')
                /* Is it a control character? */
            {
                bogus_server = 1;
                *d++ = '^';
                *d++ = (char) ((unsigned char) *s + 0x40);
                /* turn it into a printable */
                n -= 2;
            }
            else if ((unsigned char) *s > (unsigned char) '~')
            {
                bogus_server = 1;
                *d++ = '.';
                n--;
            }
            else
            {
                if (*s == '.')
                    found_dot = 1;
                *d++ = *s;
                n--;
            }
            s++;
        }
        *d = '\0';

        if ((!found_dot) || bogus_server)
        {
            sendto_one(sptr, "ERROR :Bogus server name (%s)",
                       clean_host);
            return exit_client(cptr, cptr, cptr, "Bogus server name");
        }
    }

    /*
     * check to see this host even has an N line before bothering
     * anyone about it. Its only a quick sanity test to stop the
     * conference room and win95 ircd dorks. Sure, it will be
     * redundantly checked again in m_server_estab() *sigh* yes there
     * will be wasted CPU as the conf list will be scanned twice. But
     * how often will this happen? - Dianora
     *
     * This should (will be) be recoded to check the IP is valid as well,
     * with a pointer to the valid N line conf kept for later, saving an
     * extra lookup.. *sigh* - Dianora
     */
    if (!IsServer(cptr))
    {
        if (!find_aConnect(host))
        {

#ifdef WARN_NO_NLINE
            sendto_realops("Link %s dropped, no Connect block",
                           get_client_name(cptr, TRUE));
#endif

            return exit_client(cptr, cptr, cptr, "No Connect block");
        }
    }

    if ((acptr = find_name(host, NULL)))
    {
        /*
         * * This link is trying feed me a server that I already have
         * access through another path -- multiple paths not accepted
         * currently, kill this link immediately!!
         *
         * Rather than KILL the link which introduced it, KILL the
         * youngest of the two links. -avalon
         */

        bcptr = (cptr->firsttime > acptr->from->firsttime) ? cptr :
            acptr->from;
        sendto_one(bcptr, "ERROR :Server %s already exists", host);
        if (bcptr == cptr)
        {
            /* Don't complain for servers that are juped */
            /* (don't complain if the server that already exists is U: lined,
                unless I actually have a .conf U: line for it */
            if(!IsULine(acptr) || find_aUserver(acptr->name))
            {
                sendto_gnotice("from %s: Link %s cancelled, server %s already "
                               "exists", me.name, get_client_name(bcptr, HIDEME),
                               host);
                sendto_serv_butone(bcptr, ":%s GNOTICE :Link %s cancelled, "
                                   "server %s already exists", me.name,
                                   get_client_name(bcptr, HIDEME), host);
            }
            return exit_client(bcptr, bcptr, &me, "Server Exists");
        }
        /* inform all those who care (set +n) -epi */
        strcpy(nbuf, get_client_name(bcptr, HIDEME));
        sendto_gnotice("from %s: Link %s cancelled, server %s reintroduced "
                       "by %s", me.name, nbuf, host,
                       get_client_name(cptr, HIDEME));
        sendto_serv_butone(bcptr, ":%s GNOTICE :Link %s cancelled, server %s "
                           "reintroduced by %s", me.name, nbuf, host,
                           get_client_name(cptr, HIDEME));
        exit_client(bcptr, bcptr, &me, "Server Exists");
    }
    /*
     * The following if statement would be nice to remove since user
     * nicks never have '.' in them and servers must always have '.' in
     * them. There should never be a server/nick name collision, but it
     * is possible a capricious server admin could deliberately do
     * something strange.
     *
     * -Dianora
     */

    if ((acptr = find_client(host, NULL)) && acptr != cptr)
    {
        /*
         * * Server trying to use the same name as a person. Would
         * cause a fair bit of confusion. Enough to make it hellish for
         * a while and servers to send stuff to the wrong place.
         */
        sendto_one(cptr, "ERROR :Nickname %s already exists!", host);
        strcpy(nbuf, get_client_name(cptr, HIDEME));
        sendto_gnotice("from %s: Link %s cancelled, servername/nick collision",
                       me.name, nbuf);
        sendto_serv_butone(cptr, ":%s GNOTICE :Link %s cancelled, "
                           "servername/nick collision", me.name, nbuf);
        return exit_client(cptr, cptr, cptr, "Nick as Server");
    }

    if (IsServer(cptr))
    {
        /*
         * * Server is informing about a new server behind this link.
         * Create REMOTE server structure, add it to list and propagate
         * word to my other server links...
         */
        if (parc == 1 || info[0] == '\0')
        {
            sendto_one(cptr, "ERROR :No server info specified for %s", host);
            return 0;
        }
        /*
         * * See if the newly found server is behind a guaranteed leaf
         * (L-line). If so, close the link.
         *
         * Depreciated.  Kinda redundant with Hlines. -epi
         */
        if (!(cptr->serv->aconn->flags & CONN_HUB))
        {
            aconn = cptr->serv->aconn;
            sendto_gnotice("from %s: Non-Hub link %s introduced %s",
                           me.name, get_client_name(cptr, HIDEME), host);
            sendto_serv_butone(cptr,":%s GNOTICE :Non-Hub link %s introduced "
                               "%s", me.name, get_client_name(cptr, HIDEME),
                               host);
            sendto_one(cptr, "ERROR :You're not a hub (introducing %s)",
                       host);
            return exit_client(cptr, cptr, cptr, "Too many servers");
        }

        acptr = make_client(cptr, sptr);
        make_server(acptr);
        acptr->hopcount = hop;
        strncpyzt(acptr->name, host, sizeof(acptr->name));
        strncpyzt(acptr->info, info, REALLEN);
        acptr->serv->up = find_or_add(parv[0]);

        fakelinkserver_update(acptr->name, acptr->info);
        SetServer(acptr);

        /*
         * if this server is behind a U-lined server, make it U-lined as
         * well. - lucas
         */

        if (IsULine(sptr) || find_aUserver(acptr->name))
        {
            acptr->flags |= FLAGS_ULINE;
            sendto_realops_lev(DEBUG_LEV, "%s introducing super server %s",
                               cptr->name, acptr->name);
        }

        Count.server++;

        add_client_to_list(acptr);
        add_to_client_hash_table(acptr->name, acptr);
        /*
         * Old sendto_serv_but_one() call removed because we now need
         * to send different names to different servers (domain name matching)
         */
        for (i = 0; i <= highest_fd; i++)
        {
            if (!(bcptr = local[i]) || !IsServer(bcptr) || bcptr == cptr ||
                IsMe(bcptr))
                continue;
            if (!(aconn = bcptr->serv->aconn))
            {
                sendto_gnotice("from %s: Lost Connect block for %s on %s."
                               " Closing", me.name,
                               get_client_name(cptr, HIDEME), host);
                sendto_serv_butone(cptr, ":%s GNOTICE :Lost Connect block for"
                                   " %s on %s. Closing", me.name,
                                   get_client_name(cptr, HIDEME), host);
                return exit_client(cptr, cptr, cptr, "Lost Connect block");
            }
            if (match(my_name_for_link(me.name, aconn), acptr->name) == 0)
                continue;
            sendto_one(bcptr, ":%s SERVER %s %d :%s",
                       parv[0], acptr->name, hop + 1, acptr->info);
        }
        return 0;
    }

    if (!IsUnknown(cptr) && !IsHandshake(cptr))
        return 0;

    /*
     * * A local link that is still in undefined state wants to be a
     * SERVER. Check if this is allowed and change status
     * accordingly...
     */
    /*
     * * Reject a direct nonTS server connection if we're TS_ONLY
     * -orabidoo
     */

    strncpyzt(cptr->name, host, sizeof(cptr->name));
    strncpyzt(cptr->info, info[0] ? info : me.name, REALLEN);
    cptr->hopcount = hop;

    switch (check_server_init(cptr))
    {
        case 0:
            return m_server_estab(cptr);
        case 1:
            sendto_ops("Access check for %s in progress",
                       get_client_name(cptr, HIDEME));
            return 1;
        default:
            ircstp->is_ref++;
            sendto_ops("Received unauthorized connection from %s.",
                       get_client_host(cptr));
            return exit_client(cptr, cptr, cptr, "No Connect block");
    }
}

/* m_dkey
 * lucas's code, i assume.
 * moved here from s_serv.c due to its integration in the encrypted 
 * server negotiation stuffs. -epi
 */

#define DKEY_GOTIN  0x01
#define DKEY_GOTOUT 0x02

#define DKEY_DONE(x) (((x) & (DKEY_GOTIN|DKEY_GOTOUT)) == \
                      (DKEY_GOTIN|DKEY_GOTOUT))

int m_dkey(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    if(!(IsNegoServer(sptr) && parc > 1))
    {
        if(IsPerson(sptr))
            return 0;
        return exit_client(sptr, sptr, sptr, "Not negotiating now");
    }
#ifdef HAVE_ENCRYPTION_ON
    if(mycmp(parv[1], "START") == 0)
    {
        char keybuf[1024];

        if(parc != 2)
            return exit_client(sptr, sptr, sptr, "DKEY START failure");

        if(sptr->serv->sessioninfo_in != NULL &&
           sptr->serv->sessioninfo_out != NULL)
            return exit_client(sptr, sptr, sptr, "DKEY START duplicate?!");

        sptr->serv->sessioninfo_in = dh_start_session();
        sptr->serv->sessioninfo_out = dh_start_session();

        sendto_realops("Initiating diffie-hellman key exchange with %s",
                       sptr->name);

        dh_get_s_public(keybuf, 1024, sptr->serv->sessioninfo_in);
        sendto_one(sptr, "DKEY PUB I %s", keybuf);

        dh_get_s_public(keybuf, 1024, sptr->serv->sessioninfo_out);
        sendto_one(sptr, "DKEY PUB O %s", keybuf);
        return 0;
    }

    if(mycmp(parv[1], "PUB") == 0)
    {
        char keybuf[1024];
        int keylen;

        if(parc != 4 || !sptr->serv->sessioninfo_in ||
           !sptr->serv->sessioninfo_out)
            return exit_client(sptr, sptr, sptr, "DKEY PUB failure");

        if(mycmp(parv[2], "O") == 0) /* their out is my in! */
        {
            if(!dh_generate_shared(sptr->serv->sessioninfo_in, parv[3]))
                return exit_client(sptr, sptr, sptr, "DKEY PUB O invalid");
            sptr->serv->dkey_flags |= DKEY_GOTOUT;
        }
        else if(mycmp(parv[2], "I") == 0) /* their out is my in! */
        {
            if(!dh_generate_shared(sptr->serv->sessioninfo_out, parv[3]))
                return exit_client(sptr, sptr, sptr, "DKEY PUB I invalid");
            sptr->serv->dkey_flags |= DKEY_GOTIN;
        }
        else
            return exit_client(sptr, sptr, sptr, "DKEY PUB bad option");

        if(DKEY_DONE(sptr->serv->dkey_flags))
        {
            sendto_one(sptr, "DKEY DONE");
            SetRC4OUT(sptr);

            keylen = 1024;
            if(!dh_get_s_shared(keybuf, &keylen, sptr->serv->sessioninfo_in))
                return exit_client(sptr, sptr, sptr,
                                   "Could not setup encrypted session");
            sptr->serv->rc4_in = rc4_initstate(keybuf, keylen);

            keylen = 1024;
            if(!dh_get_s_shared(keybuf, &keylen, sptr->serv->sessioninfo_out))
                return exit_client(sptr, sptr, sptr,
                                   "Could not setup encrypted session");
            sptr->serv->rc4_out = rc4_initstate(keybuf, keylen);

            dh_end_session(sptr->serv->sessioninfo_in);
            dh_end_session(sptr->serv->sessioninfo_out);

            sptr->serv->sessioninfo_in = sptr->serv->sessioninfo_out = NULL;
            return 0;
        }

        return 0;
    }


    if(mycmp(parv[1], "DONE") == 0)
    {
        if(!((sptr->serv->sessioninfo_in == NULL &&
              sptr->serv->sessioninfo_out == NULL) &&
             (sptr->serv->rc4_in != NULL && sptr->serv->rc4_out != NULL)))
            return exit_client(sptr, sptr, sptr, "DKEY DONE when not done!");
        SetRC4IN(sptr);
        sendto_realops("Diffie-Hellman exchange with %s complete, connection "
                       "encrypted.", sptr->name);
        sendto_one(sptr, "DKEY EXIT");
        return RC4_NEXT_BUFFER;
    }

    if(mycmp(parv[1], "EXIT") == 0)
    {
        if(!(IsRC4IN(sptr) && IsRC4OUT(sptr)))
            return exit_client(sptr, sptr, sptr, "DKEY EXIT when not in "
                               "proper stage");
        ClearNegoServer(sptr);
        return do_server_estab(sptr);
    }
#endif
    return 0;
}

