/*
 *   m_rwho.c - Regular expression enabled WHO
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

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "numeric.h"
#include "channel.h"
#include "inet.h"
#include "clones.h"

#include "pcre.h"

extern int user_modes[];
extern unsigned int cidr_to_netmask(unsigned int);
extern Link *find_channel_link(Link *, aChannel *);

/* max capturing submatches to allow in all fields combined */
#define MAX_SUBMATCHES  9

/* for pcre_exec(), don't touch */
#define NVEC        ((MAX_SUBMATCHES+1)*3)

/* PCRE matched fields */
#define RWHO_NICK   1
#define RWHO_USER   2
#define RWHO_GCOS   3
#define RWHO_AWAY   4
#define RWHO_COUNT  5

/* other matched fields */
#define RWM_AWAY    0x0001
#define RWM_HOST    0x0002
#define RWM_IP      0x0004
#define RWM_MODES   0x0008
#define RWM_SERVER  0x0010
#define RWM_TS      0x0020
#define RWM_STYPE   0x0040
#define RWM_JOINS   0x0080
#define RWM_CLONES  0x0100
#define RWM_MATCHES 0x0200
#define RWM_CHANNEL 0x0400

/* whois compatibility */
#define RWC_SHOWIP  0x0001
#define RWC_CHANNEL 0x0002

/* output options */
#define RWO_NICK    0x0001
#define RWO_USER    0x0002
#define RWO_HOST    0x0004
#define RWO_IP      0x0008
#define RWO_MODES   0x0010
#define RWO_FLAGS   0x0020
#define RWO_SERVER  0x0040
#define RWO_TS      0x0080
#define RWO_STYPE   0x0100
#define RWO_GCOS    0x0200
#define RWO_AWAY    0x0400
#define RWO_JOINS   0x0800
#define RWO_CLONES  0x1000
#define RWO_MATCHES 0x2000
#define RWO_CHANNEL 0x4000


static const char *rwho_help[] = {
    "RWHO <[+|-]matchflags>[/<outputflags>[:<cookie>]] <args>",
    "Match flags are specified like channel modes,",
    "'+' being a positive match and '-' being a negative one:",
    "  a             - user is (not) away",
    "  c <channel>   - user is on channel <channel> (+ only)",
    "  d <clones>    - there are N or more (less) users per host",
    "  D <matches>   - there are N or more (less) matching users per host",
    "  h <host>      - user's host does (not) match wildcard mask",
    "  i <ip>        - user's IP does (not) match CIDR <ip>",
    "  j <channels>  - user is in N or more (less) channels",
    "  m <usermodes> - user is (not) using modes <usermodes>",
    "  s <server>    - user is (not) on server <server>",
    "  t <seconds>   - user has been online N or more (less) seconds",
    "  T <type>      - user is (not) type <type> as set by services",
    "  C             - for compatibility with WHO, use discouraged",
    "  I             - for compatibility with WHO, use discouraged",
    "The following match flags are compiled into a single regular expression",
    "in the order you specify, so later flags can use backreferences to",
    "submatches in the flags prior:",
    "  A <away>      - user's away reason matches regexp pattern (implies +a)",
    "  g <gcos/name> - user's real name matches regexp pattern",
    "  n <nick>      - user's nick matches regexp pattern",
    "  u <username>  - user's username matches regexp pattern",
    "The regular expression flags do not support negative matches.",
    "The optional output flags cause replies to be sent using numeric 354 and",
    "contain only the fields associated with the flags in the order below:",
    "  :<cookie>     - supplied cookie (useful for scripts)",
    "  n             - user's nick",
    "  u             - user's username",
    "  h             - user's host",
    "  i             - user's IP",
    "  s             - user's server",
    "  f             - standard WHO flags (GH*%@+)",
    "  c             - user's most recently joined channel",
    "  j             - number of joined channels",
    "  d             - number of clones on user's IP",
    "  D             - number of matches on user's IP (see below)",
    "  t             - user's signon timestamp",
    "  T             - user's type (set by services)",
    "  m             - user's modes",
    "  g             - user's gcos/real name (mutually exclusive with 'a')",
    "  a             - user's away reason (mutually exclusive with 'g')",
    "There are three special output flags:",
    "  L<count>      - limit to N results (no space between L and <count>)",
    "  C             - no results, just supply match count in RPL_ENDOFWHO",
    "  D             - returns only one matching result per host (summarize)",
    NULL
};

static struct {
    unsigned  check[2];         /* things to try match */
    unsigned  rplfields;        /* fields to include in the response */
    unsigned  compat;           /* WHO compatibility flags */
    char     *rplcookie;        /* response cookie */
    int       countonly;        /* counting only, no results */
    int       limit;            /* max number of results */
    int       spat[RWHO_COUNT]; /* match string build pattern */
    pcre     *re;               /* regex pattern */
    aClient  *server;           /* server */
    aChannel *chptr;            /* search in channel */
    char     *host_pat[2];      /* wildcard host pattern */
    int      (*host_func[2])(); /* host match function */
    int       umodes[2];        /* usermodes */
    unsigned  stype;            /* services type */
    unsigned  ip_mask[2];       /* IP netmask */
    unsigned  ip_addr[2];       /* IP address */
    char     *ip_str[2];        /* IP string if CIDR is invalid */
    ts_val    ts[2];            /* signon timestamp */
    int       joined[2];        /* min/max joined chans */
    int       clones[2];        /* min/max clones */
    int       matches[2];       /* min/max clone matches */
    int       thisclones;       /* number of clones on this host */
    int       thismatches;      /* number of matches on this host */
} rwho_opts;

static char rwhobuf[1024];
static char scratch[1024];


/*
 * Send a syntax error message.
 */
static void rwho_synerr(aClient *sptr, char *msg)
{
    sendto_one(sptr, getreply(ERR_WHOSYNTAX), me.name, sptr->name, "RWHO",
               "rwho");
    if (msg)
        sendto_one(sptr, getreply(RPL_COMMANDSYNTAX), me.name, sptr->name,msg);
}

/*
 * Build the regular expression to use for nick/user/gcos/away matching.
 * Returns 1 on success, 0 on failure.
 */
static int rwho_compile(aClient *cptr, char *remap[])
{
    const char *es;
    int         ei;
    char       *s;
    int         i, j;
    char        arg = 0;

    s = rwhobuf;
    for (i = 0; rwho_opts.spat[i]; i++)
        s += ircsprintf(s, "(?>(?:%s)\\x00)", remap[rwho_opts.spat[i]]);

    rwho_opts.re = pcre_compile(rwhobuf,
                                PCRE_EXTRA|PCRE_ANCHORED|PCRE_UNGREEDY,
                                &es, &ei, NULL);

    if (!rwho_opts.re)
    {
        rwho_synerr(cptr, NULL);

        /* the things we do for error messages... */
        for (i = 0; rwho_opts.spat[i]; i++)
        {
            rwho_opts.re = pcre_compile(remap[rwho_opts.spat[i]],
                                        PCRE_EXTRA|PCRE_ANCHORED|PCRE_UNGREEDY,
                                        &es, &ei, NULL);
            if (rwho_opts.re)
            {
                free(rwho_opts.re);
                continue;
            }

            if (es)
            {
                j = 0;
                s = remap[rwho_opts.spat[i]];

                switch (rwho_opts.spat[i])
                {
                    case RWHO_AWAY: arg = 'A'; break;
                    case RWHO_GCOS: arg = 'g'; break;
                    case RWHO_NICK: arg = 'n'; break;
                    case RWHO_USER: arg = 'u'; break;
                }

                while (*s)
                {
                    if (ei == j)
                    {
                        scratch[j++] = 037;
                        scratch[j++] = *s++;
                        scratch[j++] = 037;
                    }
                    else
                        scratch[j++] = *s++;
                }
                scratch[j] = 0;

                ircsprintf(rwhobuf, "Invalid flag %c expression %s", arg,
                           scratch);
                sendto_one(cptr, getreply(RPL_COMMANDSYNTAX), me.name,
                           cptr->name, rwhobuf);
                sendto_one(cptr, getreply(RPL_COMMANDSYNTAX), me.name,
                           cptr->name, es);
                break;
            }
        }

        return 0;
    }

    pcre_fullinfo(rwho_opts.re, NULL, PCRE_INFO_CAPTURECOUNT, &ei);
    if (ei > MAX_SUBMATCHES)
    {
        rwho_synerr(cptr, "too many capturing submatches, use (?:)");
        free(rwho_opts.re);
        return 0;
    }

    return 1;
}

/*
 * Parse the options to the RWHO command.
 * Returns 1 on success, 0 on failure.
 */
static int rwho_parseopts(aClient *sptr, int parc, char *parv[])
{
    char       *remap[RWHO_COUNT] = {0};
    char       *sfl;
    char       *s;
    int         spatidx = 0;
    int         neg = 0;
    int         arg = 2;
    int         i;
    ts_val      ts;
    unsigned    ui;

    memset(&rwho_opts, 0, sizeof(rwho_opts));

    if (parc < 2)
    {
        sendto_one(sptr, getreply(ERR_WHOSYNTAX), me.name, sptr->name, "RWHO",
                   "rwho");
        return 0;
    }

    if (*parv[1] == '?')
    {
        const char **ptr;
        for (ptr = rwho_help; *ptr; ptr++)
            sendto_one(sptr, getreply(RPL_COMMANDSYNTAX), me.name,
                       parv[0], *ptr);
        sendto_one(sptr, getreply(RPL_ENDOFWHO), me.name, parv[0], "?","RWHO");
        return 0;
    }

    /* parse match options */
    for (sfl = parv[1]; *sfl; sfl++)
    {
        if (*sfl == '/')
        {
            sfl++;
            break;
        }

        switch (*sfl)
        {
            case '+':
                neg = 0;
                break;

            case '-':
                neg = 1;
                break;

            case 'a':
                if (rwho_opts.check[!neg] & RWM_AWAY)
                {
                    rwho_synerr(sptr, "cannot use both +a and -a in match");
                    return 0;
                }
                rwho_opts.check[neg] |= RWM_AWAY;
                break;

            case 'c':
                if (!parv[arg])
                {
                    rwho_synerr(sptr, "missing argument for match flag c");
                    return 0;
                }
                if (neg)
                {
                    rwho_synerr(sptr, "negative match not supported for match"
                                " flag c");
                    return 0;
                }
                rwho_opts.chptr = find_channel(parv[arg], NULL);
                if (!rwho_opts.chptr)
                {
                    sendto_one(sptr, getreply(ERR_NOSUCHCHANNEL), me.name,
                               parv[0], parv[arg]);
                    return 0;
                }
                rwho_opts.check[neg] |= RWM_CHANNEL;
                arg++;
                break;

            case 'C':
                rwho_opts.compat |= RWC_CHANNEL;
                break;

            case 'd':
                if (!parv[arg])
                {
                    rwho_synerr(sptr, "missing argument for match flag d");
                    return 0;
                }
                i = strtol(parv[arg], &s, 0);
                if (*s != 0 || i < 1)
                {
                    rwho_synerr(sptr, "invalid number of clones for match"
                                " flag d");
                    return 0;
                }
                rwho_opts.clones[neg] = i;
                rwho_opts.check[neg] |= RWM_CLONES;
                arg++;
                break;

            case 'D':
                if (!parv[arg])
                {
                    rwho_synerr(sptr, "missing argument for match flag D");
                    return 0;
                }
                i = strtol(parv[arg], &s, 0);
                if (*s != 0 || i < 1)
                {
                    rwho_synerr(sptr, "invalid number of matches for match"
                                " flag D");
                    return 0;
                }
                rwho_opts.matches[neg] = i;
                rwho_opts.check[neg] |= RWM_MATCHES;
                arg++;
                break;

            case 'h':
                if (!parv[arg])
                {
                    rwho_synerr(sptr, "missing argument for match flag h");
                    return 0;
                }
                if (strchr(parv[arg], '*') || strchr(parv[arg], '?'))
                    rwho_opts.host_func[neg] = match;
                else
                    rwho_opts.host_func[neg] = mycmp;
                rwho_opts.host_pat[neg] = parv[arg];
                rwho_opts.check[neg] |= RWM_HOST;
                arg++;
                break;

            case 'i':
                if (!parv[arg])
                {
                    rwho_synerr(sptr, "missing argument for match flag i");
                    return 0;
                }
                if ((s = strchr(parv[arg], '/')))
                {
                    *s++ = 0;
                    i = strtol(s, &s, 10);
                    if (*s == 0 && 1 < i && i < 32)
                        rwho_opts.ip_mask[neg] = htonl(cidr_to_netmask(i));
                }
                else
                    rwho_opts.ip_mask[neg] = ~0;
                rwho_opts.ip_addr[neg] = inet_addr(parv[arg]);
                if (!rwho_opts.ip_mask[neg] ||
                    (rwho_opts.ip_mask[neg] != ~0 &&
                     rwho_opts.ip_addr[neg] == 0xFFFFFFFF))
                {
                    rwho_synerr(sptr, "invalid CIDR IP for match flag i");
                    return 0;
                }
                if (rwho_opts.ip_addr[neg] == 0xFFFFFFFF)
                    rwho_opts.ip_str[neg] = parv[arg];
                else
                    rwho_opts.ip_addr[neg] &= rwho_opts.ip_mask[neg];
                rwho_opts.check[neg] |= RWM_IP;
                arg++;
                break;

            case 'I':
                rwho_opts.compat |= RWC_SHOWIP;
                break;

            case 'j':
                if (!parv[arg])
                {
                    rwho_synerr(sptr, "missing argument for match flag s");
                    return 0;
                }
                i = strtol(parv[arg], &s, 0);
                if (*s != 0 || i < 0)
                {
                    rwho_synerr(sptr, "invalid number of channels for match"
                                " flag j");
                    return 0;
                }
                rwho_opts.joined[neg] = i;
                rwho_opts.check[neg] |= RWM_JOINS;
                arg++;
                break;

            case 'm':
                if (!parv[arg])
                {
                    rwho_synerr(sptr, "missing argument for match flag m");
                    return 0;
                }
                for (s = parv[arg]; *s; s++)
                    for (i = 1; user_modes[i]; i+=2)
                        if (*s == user_modes[i])
                        {
                            rwho_opts.umodes[neg] |= user_modes[i-1];
                            break;
                        }
                rwho_opts.check[neg] |= RWM_MODES;
                arg++;
                break;

            case 's':
                if (!parv[arg])
                {
                    rwho_synerr(sptr, "missing argument for match flag s");
                    return 0;
                }
                if (rwho_opts.check[!neg] & RWM_SERVER)
                {
                    rwho_synerr(sptr, "cannot use both +s and -s in match");
                    return 0;
                }
                rwho_opts.server = find_server(parv[arg], NULL);
                if (!rwho_opts.server)
                {
                    sendto_one(sptr, getreply(ERR_NOSUCHSERVER), me.name,
                               sptr->name, parv[arg]);
                    return 0;
                }
                rwho_opts.check[neg] |= RWM_SERVER;
                arg++;
                break;

            case 't':
                if (!parv[arg])
                {
                    rwho_synerr(sptr, "missing argument for match flag t");
                    return 0;
                }
                ts = strtol(parv[arg], &s, 0);
                if (*s != 0 || ts <= 0)
                {
                    rwho_synerr(sptr, "invalid number of seconds for match"
                                " flag t");
                    return 0;
                }
                rwho_opts.ts[neg] = NOW - ts;
                rwho_opts.check[neg] |= RWM_TS;
                arg++;
                break;

            case 'T':
                if (!parv[arg])
                {
                    rwho_synerr(sptr, "missing argument for match flag T");
                    return 0;
                }
                if (rwho_opts.check[!neg] & RWM_STYPE)
                {
                    rwho_synerr(sptr, "cannot use both +T and -T in match");
                    return 0;
                }
                ui = strtoul(parv[arg], &s, 0);
                if (*s != 0)
                {
                    rwho_synerr(sptr, "invalid type for match flag T");
                    return 0;
                }
                rwho_opts.stype = ui;
                rwho_opts.check[neg] |= RWM_STYPE;
                arg++;
                break;

            case 'A':
                if (!parv[arg])
                {
                    rwho_synerr(sptr, "missing argument for match flag A");
                    return 0;
                }
                if (remap[RWHO_AWAY])
                {
                    rwho_synerr(sptr, "flags may not be used more than once");
                    return 0;
                }
                if (neg)
                {
                    rwho_synerr(sptr, "negative match not supported for match"
                                " flag A");
                    return 0;
                }
                if (rwho_opts.check[!neg] & RWM_AWAY)
                {
                    rwho_synerr(sptr, "cannot use both +A and -a in match");
                    return 0;
                }
                remap[RWHO_AWAY] = parv[arg];
                rwho_opts.spat[spatidx++] = RWHO_AWAY;
                rwho_opts.check[neg] |= RWM_AWAY;    /* implicit +a */
                arg++;
                break;

            case 'g':
                if (!parv[arg])
                {
                    rwho_synerr(sptr, "missing argument for match flag g");
                    return 0;
                }
                if (remap[RWHO_GCOS])
                {
                    rwho_synerr(sptr, "flags may not be used more than once");
                    return 0;
                }
                if (neg)
                {
                    rwho_synerr(sptr, "negative match not supported for match"
                                " flag g");
                    return 0;
                }
                remap[RWHO_GCOS] = parv[arg];
                rwho_opts.spat[spatidx++] = RWHO_GCOS;
                arg++;
                break;

            case 'n':
                if (!parv[arg])
                {
                    rwho_synerr(sptr, "missing argument for match flag n");
                    return 0;
                }
                if (remap[RWHO_NICK])
                {
                    rwho_synerr(sptr, "flags may not be used more than once");
                    return 0;
                }
                if (neg)
                {
                    rwho_synerr(sptr, "negative match not supported for match"
                                " flag n");
                    return 0;
                }
                remap[RWHO_NICK] = parv[arg];
                rwho_opts.spat[spatidx++] = RWHO_NICK;
                arg++;
                break;

            case 'u':
                if (!parv[arg])
                {
                    rwho_synerr(sptr, "missing argument for match flag u");
                    return 0;
                }
                if (remap[RWHO_USER])
                {
                    rwho_synerr(sptr, "flags may not be used more than once");
                    return 0;
                }
                if (neg)
                {
                    rwho_synerr(sptr, "negative match not supported for match"
                                " flag u");
                    return 0;
                }
                remap[RWHO_USER] = parv[arg];
                rwho_opts.spat[spatidx++] = RWHO_USER;
                arg++;
                break;
                
            default:
                ircsprintf(scratch, "unknown match flag %c", *sfl);
                rwho_synerr(sptr, scratch);
                return 0;
        }
    }

    /* parse output options */
    while (*sfl)
    {
        if (*sfl == ':')
        {
            if (!*++sfl)
            {
                rwho_synerr(sptr, NULL);
                return 0;
            }
            rwho_opts.rplcookie = sfl;
            break;
        }

        switch (*sfl)
        {
            case 'n': rwho_opts.rplfields |= RWO_NICK; sfl++; break;
            case 'u': rwho_opts.rplfields |= RWO_USER; sfl++; break;
            case 'h': rwho_opts.rplfields |= RWO_HOST; sfl++; break;
            case 'i': rwho_opts.rplfields |= RWO_IP; sfl++; break;
            case 's': rwho_opts.rplfields |= RWO_SERVER; sfl++; break;
            case 'f': rwho_opts.rplfields |= RWO_FLAGS; sfl++; break;
            case 'c': rwho_opts.rplfields |= RWO_CHANNEL; sfl++; break;
            case 'j': rwho_opts.rplfields |= RWO_JOINS; sfl++; break;
            case 'd': rwho_opts.rplfields |= RWO_CLONES; sfl++; break;
            case 'D': rwho_opts.rplfields |= RWO_MATCHES; sfl++; break;
            case 't': rwho_opts.rplfields |= RWO_TS; sfl++; break;
            case 'T': rwho_opts.rplfields |= RWO_STYPE; sfl++; break;
            case 'm': rwho_opts.rplfields |= RWO_MODES; sfl++; break;
            case 'g': rwho_opts.rplfields |= RWO_GCOS; sfl++; break;
            case 'a': rwho_opts.rplfields |= RWO_AWAY; sfl++; break;

            case 'C': rwho_opts.countonly = 1; sfl++; break;

            case 'L':
                rwho_opts.limit = strtol(sfl+1, &sfl, 10);
                if (rwho_opts.limit < 1)
                {
                    rwho_synerr(sptr, "invalid limit for output flag L");
                    return 0;
                }
                break;

            default:
                ircsprintf(scratch, "unknown output flag %c", *sfl);
                rwho_synerr(sptr, scratch);
                return 0;
        }
    }

    if ((rwho_opts.rplfields & (RWO_GCOS|RWO_AWAY)) == (RWO_GCOS|RWO_AWAY))
    {
        rwho_synerr(sptr, "output flags g and a may not be used together");
        return 0;
    }

    if ((rwho_opts.check[0] & rwho_opts.check[1] & RWM_CLONES)
        && (rwho_opts.clones[0] > rwho_opts.clones[1]))
    {
        rwho_synerr(sptr, "values for match flags +d and -d will never match");
        return 0;
    }

    if ((rwho_opts.check[0] & rwho_opts.check[1] & RWM_MATCHES)
        && (rwho_opts.matches[0] > rwho_opts.matches[1]))
    {
        rwho_synerr(sptr, "values for match flags +D and -D will never match");
        return 0;
    }

    if ((rwho_opts.check[0] & rwho_opts.check[1] & RWM_JOINS)
        && (rwho_opts.joined[0] > rwho_opts.joined[1]))
    {
        rwho_synerr(sptr, "values for match flags +j and -j will never match");
        return 0;
    }

    if ((rwho_opts.check[0] & rwho_opts.check[1] & RWM_TS)
        && (rwho_opts.ts[0] < rwho_opts.ts[1]))
    {
        rwho_synerr(sptr, "values for match flags +t and -t will never match");
        return 0;
    }

    if (spatidx && !rwho_compile(sptr, remap))
        return 0;

    return 1;
}

/*
 * See if a client matches the search parameters.
 * Returns 1 on match, 0 on no match.
 * Fills in failcode and failclient upon unexpected PCRE error.
 */
static int rwho_match(aClient *cptr, int *failcode, aClient **failclient)
{
    char *s;
    char *b;
    int   i;
    int   ovec[NVEC];

    if ((rwho_opts.check[0] & RWM_SERVER) &&
        (cptr->uplink != rwho_opts.server))
        return 0;
    else if ((rwho_opts.check[1] & RWM_SERVER) &&
        (cptr->uplink == rwho_opts.server))
        return 0;

    if ((rwho_opts.check[0] & RWM_TS) && (cptr->tsinfo > rwho_opts.ts[0]))
        return 0;

    if ((rwho_opts.check[1] & RWM_TS) && (cptr->tsinfo < rwho_opts.ts[1]))
        return 0;

    if ((rwho_opts.check[0] & RWM_AWAY) && !cptr->user->away)
        return 0;
    else if ((rwho_opts.check[1] & RWM_AWAY) && cptr->user->away)
        return 0;

    if ((rwho_opts.check[0] & RWM_STYPE) &&
        (cptr->user->servicetype != rwho_opts.stype))
        return 0;
    else if ((rwho_opts.check[1] & RWM_STYPE) &&
        (cptr->user->servicetype == rwho_opts.stype))
        return 0;

    if ((rwho_opts.check[0] & RWM_JOINS) &&
        (cptr->user->joined < rwho_opts.joined[0]))
        return 0;

    if ((rwho_opts.check[1] & RWM_JOINS) &&
        (cptr->user->joined > rwho_opts.joined[1]))
        return 0;

    if ((rwho_opts.check[0] & RWM_MODES) &&
        ((cptr->umode & rwho_opts.umodes[0]) != rwho_opts.umodes[0]))
        return 0;

    if ((rwho_opts.check[1] & RWM_MODES) &&
        (cptr->umode & rwho_opts.umodes[1]))
        return 0;

    if ((rwho_opts.check[0] & RWM_CHANNEL) && !IsMember(cptr, rwho_opts.chptr))
        return 0;

    if (rwho_opts.check[0] & RWM_IP)
    {
        if (rwho_opts.ip_str[0])
        {
            if (match(rwho_opts.ip_str[0], cptr->hostip))
                return 0;
        }
        else if ((cptr->ip.s_addr & rwho_opts.ip_mask[0])
                 != rwho_opts.ip_addr[0])
            return 0;
    }

    if (rwho_opts.check[1] & RWM_IP)
    {
        if (rwho_opts.ip_str[1])
        {
            if (!match(rwho_opts.ip_str[1], cptr->hostip))
                return 0;
        }
        else if ((cptr->ip.s_addr & rwho_opts.ip_mask[1])
                 == rwho_opts.ip_addr[1])
            return 0;
    }

    if ((rwho_opts.check[0] & RWM_HOST) &&
        rwho_opts.host_func[0](rwho_opts.host_pat[0], cptr->user->host))
        return 0;

    if ((rwho_opts.check[1] & RWM_HOST) &&
        !rwho_opts.host_func[1](rwho_opts.host_pat[1], cptr->user->host))
        return 0;
    
    if (rwho_opts.re)
    {
        s = scratch;
        for (i = 0; rwho_opts.spat[i]; i++)
        {
            switch (rwho_opts.spat[i])
            {
                case RWHO_NICK:
                    b = cptr->name;
                    while ((*s++ = *b++));
                    /* note: deliberately using zero terminator */
                    break;

                case RWHO_USER:
                    b = cptr->user->username;
                    while ((*s++ = *b++));
                    break;

                case RWHO_GCOS:
                    b = cptr->info;
                    while ((*s++ = *b++));
                    break;

                /* will core if RWM_AWAY wasn't implicitly set */
                case RWHO_AWAY:
                    b = cptr->user->away;
                    while ((*s++ = *b++));
                    break;
            }
        }

        i = pcre_exec(rwho_opts.re, NULL, scratch, s - scratch, 0, 0, ovec,
                      NVEC);

        if (i < 0)
        {
            if (i == PCRE_ERROR_NOMATCH)
                return 0;

            *failcode = i;
            *failclient = cptr;
            return 0;
        }
    }

    return 1;
}

/*
 * Prepare rwhobuf for response text.
 * Returns a pointer to space for rwho_reply().
 */
static char *rwho_prepbuf(aClient *cptr)
{
    char *s = rwhobuf;

    if (!rwho_opts.rplfields)
        return s;

    s += ircsprintf(s, getreply(RPL_RWHOREPLY), me.name, cptr->name);

    if (rwho_opts.rplcookie)
        s += ircsprintf(s, " %s", rwho_opts.rplcookie);

    return s;
}

/*
 * Build response text in supplied buffer.
 */
static void rwho_reply(aClient *cptr, aClient *ac, char *buf, chanMember *cm)
{
    char     *src;
    char     *dst;
    aChannel *chptr = NULL;

    dst = buf;

    if (ac->user->channel)
        chptr = ac->user->channel->value.chptr;

    /* use standard RPL_WHOREPLY if no output flags */
    if (!rwho_opts.rplfields)
    {
        char status[5];
        char chname[CHANNELLEN+2] = "*";

        if (!cm && (rwho_opts.compat & RWC_CHANNEL) && chptr)
        {
            for (cm = chptr->members; cm; cm = cm->next)
                if (cm->cptr == ac)
                    break;
        }

        dst = status;
        if (ac->user->away)
            *dst++ = 'G';
        else
            *dst++ = 'H';
        if (IsAnOper(ac))
            *dst++ = '*';
        else if (IsInvisible(ac))
            *dst++ = '%';
        if (cm)
        {
            if (cm->flags & CHFL_CHANOP)
                *dst++ = '@';
            else if (cm->flags & CHFL_VOICE)
                *dst++ = '+';
        }
        *dst = 0;

        if (!rwho_opts.chptr && (rwho_opts.compat & RWC_CHANNEL) && chptr)
        {
            dst = chname;
            if (!PubChannel(chptr))
                *dst++ = '%';
            if (PubChannel(chptr) || IsAdmin(cptr))
                strcpy(dst, chptr->chname);
        }

        if (rwho_opts.compat & RWC_SHOWIP)
            src = ac->hostip;
        else
            src = ac->user->host;

        ircsprintf(buf, getreply(RPL_WHOREPLY), me.name, cptr->name,
                   rwho_opts.chptr ? rwho_opts.chptr->chname : chname,
                   ac->user->username, src, ac->user->server,
                   ac->name, status, ac->hopcount, ac->info);
        return;
    }

    if (rwho_opts.rplfields & RWO_NICK)
    {
        src = ac->name;
        *dst++ = ' ';
        while (*src)
            *dst++ = *src++;
    }

    if (rwho_opts.rplfields & RWO_USER)
    {
        src = ac->user->username;
        *dst++ = ' ';
        while (*src)
            *dst++ = *src++;
    }

    if (rwho_opts.rplfields & RWO_HOST)
    {
        src = ac->user->host;
        *dst++ = ' ';
        while (*src)
            *dst++ = *src++;
    }

    if (rwho_opts.rplfields & RWO_IP)
    {
        src = ac->hostip;
        *dst++ = ' ';
        while (*src)
            *dst++ = *src++;
    }

    if (rwho_opts.rplfields & RWO_SERVER)
    {
        src = ac->user->server;
        *dst++ = ' ';
        while (*src)
            *dst++ = *src++;
    }

    if (rwho_opts.rplfields & RWO_FLAGS)
    {
        *dst++ = ' ';
        if (ac->user->away)
            *dst++ = 'G';
        else
            *dst++ = 'H';
        if (IsAnOper(ac))
            *dst++ = '*';
        if (IsInvisible(ac))
            *dst++ = '%';

        if (!cm && (rwho_opts.rplfields & RWO_CHANNEL) && chptr)
        {
            for (cm = chptr->members; cm; cm = cm->next)
                if (cm->cptr == cptr)
                    break;
        }

        if (cm)
        {
            if (cm->flags & CHFL_CHANOP)
                *dst++ = '@';
            if (cm->flags & CHFL_VOICE)
                *dst++ = '+';
        }
    }

    if (rwho_opts.rplfields & RWO_CHANNEL)
    {
        *dst++ = ' ';

        if (!chptr)
            *dst++ = '*';
        else
        {
            if (!PubChannel(chptr))
                *dst++ = '%';
            if (PubChannel(chptr) || IsAdmin(cptr))
            {
                src = chptr->chname;
                while (*src)
                    *dst++ = *src++;
            }
        }
    }

    if (rwho_opts.rplfields & RWO_JOINS)
        dst += ircsprintf(dst, " %d", ac->user->joined);

    if (rwho_opts.rplfields & RWO_CLONES)
        dst += ircsprintf(dst, " %d", rwho_opts.thisclones);

    if (rwho_opts.rplfields & RWO_MATCHES)
        dst += ircsprintf(dst, " %d", rwho_opts.thismatches);

    if (rwho_opts.rplfields & RWO_TS)
        dst += ircsprintf(dst, " %d", ac->tsinfo);

    if (rwho_opts.rplfields & RWO_STYPE)
        dst += ircsprintf(dst, " %d", ac->user->servicetype);

    if (rwho_opts.rplfields & RWO_MODES)
    {
        int i;

        *dst++ = ' ';
        *dst++ = '+';
        for (i = 0; user_modes[i]; i += 2)
        {
            if (ac->umode & user_modes[i])
                *dst++ = user_modes[i+1];
        }
    }

    if (rwho_opts.rplfields & RWO_GCOS)
    {
        src = ac->info;
        *dst++ = ' ';
        *dst++ = ':';
        while (*src)
            *dst++ = *src++;
    }
    else if (rwho_opts.rplfields & RWO_AWAY)
    {
        src = ac->user->away;
        *dst++ = ' ';
        *dst++ = ':';
        if (src)
            while (*src)
                *dst++ = *src++;
    }

    *dst = 0;
}

/*
 * m_rwho - flexible client search with regular expression support
 * parv[0] - sender
 * parv[1] - flags
 * parv[2] - arguments
 */
int m_rwho(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    chanMember *cm;
    aClient    *ac;
    aClient    *failclient = NULL;
    int         failcode = 0;
    int         results = 0;
    int         left;
    char       *fill;

    if (!IsAnOper(sptr))
    {
        sendto_one(sptr, getreply(ERR_NOPRIVILEGES), me.name, parv[0]);
        return 0;
    }

    if (!rwho_parseopts(sptr, parc, parv))
        return 0;

    left = rwho_opts.limit ? rwho_opts.limit : INT_MAX;

    fill = rwho_prepbuf(sptr);

    if (rwho_opts.chptr && !IsAdmin(sptr) && !ShowChannel(sptr, rwho_opts.chptr))
        rwho_opts.countonly = 1;

    if (((rwho_opts.check[0] | rwho_opts.check[1]) & (RWM_CLONES|RWM_MATCHES))
        || (rwho_opts.rplfields & (RWO_CLONES|RWO_MATCHES)))
    {
        CloneEnt *ce;
        aClient *fm;

        for (ce = clones_list; ce; ce = ce->next)
        {
            if (!ce->clients)
                continue;

            if ((rwho_opts.check[0] & RWM_CLONES) &&
                (ce->gcount < rwho_opts.clones[0]))
                continue;

            if ((rwho_opts.check[1] & RWM_CLONES) &&
                (ce->gcount > rwho_opts.clones[1]))
                continue;

            fm = NULL;
            rwho_opts.thismatches = 0;
            rwho_opts.thisclones = ce->gcount;

            /* if using match flag D or summarizing, we need the match count */
            if (((rwho_opts.check[0] | rwho_opts.check[1]) & RWM_MATCHES)
                || (rwho_opts.rplfields & RWO_MATCHES))
            {
                for (ac = ce->clients; ac; ac = ac->clone.next)
                {
                    if (!rwho_match(ac, &failcode, &failclient))
                        continue;

                    if (!fm)
                        fm = ac;

                    rwho_opts.thismatches++;
                }

                /* we know no matches, so no need to process further */
                if (!rwho_opts.thismatches)
                    continue;

                if ((rwho_opts.check[0] & RWM_MATCHES) &&
                    (rwho_opts.thismatches < rwho_opts.matches[0]))
                    continue;

                if ((rwho_opts.check[1] & RWM_MATCHES) &&
                    (rwho_opts.thismatches > rwho_opts.matches[1]))
                    continue;
            }

            /* if summarizing, we cached from the sweep above */
            if (rwho_opts.rplfields & RWO_MATCHES)
            {
                if (!left)
                {
                    sendto_one(sptr, getreply(ERR_WHOLIMEXCEED), me.name,
                               parv[0], rwho_opts.limit, "RWHO");
                    break;
                }

                if (!rwho_opts.countonly)
                {
                    rwho_reply(sptr, fm, fill, NULL);
                    sendto_one(sptr, "%s", rwhobuf);
                }

                results++;
                left--;
                continue;
            }

            /* not summarizing, so send each match */
            for (ac = ce->clients; ac; ac = ac->clone.next)
            {
                if (!rwho_match(ac, &failcode, &failclient))
                    continue;

                if (!left)
                {
                    sendto_one(sptr, getreply(ERR_WHOLIMEXCEED), me.name,
                               parv[0], rwho_opts.limit, "RWHO");
                    break;
                }

                if (!rwho_opts.countonly)
                {
                    rwho_reply(sptr, ac, fill, NULL);
                    sendto_one(sptr, "%s", rwhobuf);
                }

                results++;
                left--;
            }
        }
    }
    else if (rwho_opts.chptr)
    {
        rwho_opts.check[0] &= ~RWM_CHANNEL;

        for (cm = rwho_opts.chptr->members; cm; cm = cm->next)
        {
            ac = cm->cptr;

            if (!rwho_match(ac, &failcode, &failclient))
                continue;

            if (!left)
            {
                sendto_one(sptr, getreply(ERR_WHOLIMEXCEED), me.name, parv[0],
                           rwho_opts.limit, "RWHO");
                break;
            }

            if (!rwho_opts.countonly)
            {
                rwho_reply(sptr, ac, fill, cm);
                sendto_one(sptr, "%s", rwhobuf);
            }

            results++;
            left--;
        }
    }
    else
    {
        for (ac = client; ac; ac = ac->next)
        {
            if (!IsClient(ac))
                continue;

            if (!rwho_match(ac, &failcode, &failclient))
                continue;

            if (!left)
            {
                sendto_one(sptr, getreply(ERR_WHOLIMEXCEED), me.name, parv[0],
                           rwho_opts.limit, "RWHO");
                break;
            }

            if (!rwho_opts.countonly)
            {
                rwho_reply(sptr, ac, fill, NULL);
                sendto_one(sptr, "%s", rwhobuf);
            }

            results++;
            left--;
        }
    }

    if (rwho_opts.compat)
        sendto_one(sptr, getreply(RPL_COMMANDSYNTAX), me.name, sptr->name,
                   "NOTE: match flags C and I are deprecated");

    ircsprintf(rwhobuf, "%d", results);
    sendto_one(sptr, getreply(RPL_ENDOFWHO), me.name, parv[0], rwhobuf,"RWHO");

    if (failcode)
    {
        sendto_one(sptr, ":%s NOTICE %s :RWHO: Internal error %d during "
                   "match, notify coders!", me.name, parv[0], failcode);
        sendto_one(sptr, ":%s NOTICE %s :RWHO: Match target was: %s %s "
                   "[%s] [%s]", me.name, parv[0], failclient->name,
                   failclient->user->username, failclient->info,
                   failclient->user->away ? failclient->user->away : "");
    }

    free(rwho_opts.re);

    return 0;
}

