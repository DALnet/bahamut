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

#include "pcre.h"

extern int user_modes[];
extern unsigned int cidr_to_netmask(unsigned int);
extern Link *find_channel_link(Link *, aChannel *);

/* max capturing submatches to allow in all fields combined */
#define MAX_SUBMATCHES  10

/* for pcre_exec(), don't touch */
#define NVEC        (MAX_SUBMATCHES+1*3)

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


static const char *rwho_help[] = {
    "RWHO <[+|-]matchflags>[/<outputflags>[:<cookie>]] <args>",
    "Match flags are specified like channel modes,",
    "'+' being a positive match and '-' being a negative one:",
    "  a             - user is (not) away",
    "  c <channel>   - user is on channel <channel> (+ only)",
    "  h <host>      - user's host does (not) match wildcard mask",
    "  i <ip>        - user's IP does (not) match CIDR <ip>",
    "  m <usermodes> - user is (not) using modes <usermodes>",
    "  s <server>    - user is (not) on server <server>",
    "  t <seconds>   - user has been online (not) more than <seconds>",
    "  T <type>      - user is (not) type <type> as set by services",
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
    "  t             - user's signon timestamp",
    "  T             - user's type (set by services)",
    "  m             - user's modes",
    "  g             - user's gcos/real name (mutually exclusive with 'a')",
    "  a             - user's away reason (mutually exclusive with 'g')",
    "There are two special output flags:",
    "  L<count>      - limit to N results (no space between L and <count>)",
    "  C             - no results, just supply match count in RPL_ENDOFWHO",
    NULL
};

static struct {
    unsigned  check;            /* things to try match */
    unsigned  check_pos;        /* things to match positively */
    unsigned  rplfields;        /* fields to include in the response */
    char     *rplcookie;        /* response cookie */
    int       countonly;        /* counting only, no results */
    int       limit;            /* max number of results */
    int       spat[RWHO_COUNT]; /* match string build pattern */
    pcre     *re;               /* regex pattern */
    aChannel *chptr;            /* search in channel */
    aClient  *server;           /* server */
    char     *host_pat;         /* wildcard host pattern */
    int      (*host_func)();    /* host match function */
    int       umodes;           /* usermodes */
    unsigned  stype;            /* services type */
    unsigned  ip_mask;          /* IP netmask */
    unsigned  ip_addr;          /* IP address */
    ts_val    ts;               /* signon timestamp */
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
    unsigned    flags[2] = { 0 };
    int         spatidx = 0;
    int         plus = 1;
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
                plus = 1;
                break;

            case '-':
                plus = 0;
                break;

            case 'a':
                flags[plus] |= RWM_AWAY;
                break;

            case 'c':
                if (!parv[arg])
                {
                    rwho_synerr(sptr, "missing argument for match flag c");
                    return 0;
                }
                if (!plus)
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
                arg++;
                break;

            case 'h':
                if (!parv[arg])
                {
                    rwho_synerr(sptr, "missing argument for match flag h");
                    return 0;
                }
                if (strchr(parv[arg], '*') || strchr(parv[arg], '?'))
                    rwho_opts.host_func = match;
                else
                    rwho_opts.host_func = mycmp;
                rwho_opts.host_pat = parv[arg];
                flags[plus] |= RWM_HOST;
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
                        rwho_opts.ip_mask = htonl(cidr_to_netmask(i));
                }
                else
                    rwho_opts.ip_mask = ~0;
                rwho_opts.ip_addr = inet_addr(parv[arg]);
                if (rwho_opts.ip_addr == 0xFFFFFFFF || !rwho_opts.ip_mask)
                {
                    rwho_synerr(sptr, "invalid CIDR IP for match flag i");
                    return 0;
                }
                rwho_opts.ip_addr &= rwho_opts.ip_mask;
                flags[plus] |= RWM_IP;
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
                            rwho_opts.umodes |= user_modes[i-1];
                            break;
                        }
                flags[plus] |= RWM_MODES;
                arg++;
                break;

            case 's':
                if (!parv[arg])
                {
                    rwho_synerr(sptr, "missing argument for match flag s");
                    return 0;
                }
                rwho_opts.server = find_server(parv[arg], NULL);
                if (!rwho_opts.server)
                {
                    sendto_one(sptr, getreply(ERR_NOSUCHSERVER), me.name,
                               sptr->name, parv[arg]);
                    return 0;
                }
                flags[plus] |= RWM_SERVER;
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
                rwho_opts.ts = NOW - ts;
                flags[plus] |= RWM_TS;
                arg++;
                break;

            case 'T':
                if (!parv[arg])
                {
                    rwho_synerr(sptr, "missing argument for match flag T");
                    return 0;
                }
                ui = strtoul(parv[arg], &s, 0);
                if (*s != 0)
                {
                    rwho_synerr(sptr, "invalid type for match flag T");
                    return 0;
                }
                rwho_opts.stype = ui;
                flags[plus] |= RWM_STYPE;
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
                if (!plus)
                {
                    rwho_synerr(sptr, "negative match not supported for match"
                                " flag A");
                    return 0;
                }
                remap[RWHO_AWAY] = parv[arg];
                rwho_opts.spat[spatidx++] = RWHO_AWAY;
                flags[plus] |= RWM_AWAY;    /* implicit +a */
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
                if (!plus)
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
                if (!plus)
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
                if (!plus)
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

    /* need something to match on*/
    if (!(flags[0] || flags[1] || spatidx || rwho_opts.chptr))
    {
        rwho_synerr(sptr, NULL);
        return 0;
    }

    if (flags[0] & flags[1])
    {
        rwho_synerr(sptr, "flags may not specified more than once");
        return 0;
    }

    rwho_opts.check = (flags[0] | flags[1]);
    rwho_opts.check_pos = flags[1];

    if ((rwho_opts.rplfields & (RWO_GCOS|RWO_AWAY)) == (RWO_GCOS|RWO_AWAY))
    {
        rwho_synerr(sptr, "output flags g and a may not be used together");
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
    int   i;
    int   m1, m2;
    int   ovec[NVEC];

    if (rwho_opts.check & RWM_SERVER)
    {
        m1 = !(rwho_opts.check_pos & RWM_SERVER);
        m2 = !(cptr->uplink == rwho_opts.server);

        if (m1 != m2)
            return 0;
    }

    if (rwho_opts.check & RWM_TS)
    {
        m1 = !(rwho_opts.check_pos & RWM_TS);
        m2 = !(cptr->tsinfo < rwho_opts.ts);

        if (m1 != m2)
            return 0;
    }

    if (rwho_opts.check & RWM_AWAY)
    {
        m1 = !(rwho_opts.check_pos & RWM_AWAY);
        m2 = !cptr->user->away;

        if (m1 != m2)
            return 0;
    }

    if (rwho_opts.check & RWM_STYPE)
    {
        m1 = !(rwho_opts.check_pos & RWM_STYPE);
        m2 = !(cptr->user->servicetype == rwho_opts.stype);

        if (m1 != m2)
            return 0;
    }

    if (rwho_opts.check & RWM_IP)
    {
        m1 = !(rwho_opts.check_pos & RWM_IP);
        m2 = !((cptr->ip.s_addr & rwho_opts.ip_mask) == rwho_opts.ip_addr);

        if (m1 != m2)
            return 0;
    }

    if (rwho_opts.check & RWM_MODES)
    {
        if (rwho_opts.check_pos & RWM_MODES)
        {
            if ((cptr->umode & rwho_opts.umodes) != rwho_opts.umodes)
                return 0;
        }
        else if (cptr->umode & rwho_opts.umodes)
            return 0;
    }

    if (rwho_opts.check & RWM_HOST)
    {
        m1 = !(rwho_opts.check_pos & RWM_HOST);
        m2 = !!rwho_opts.host_func(rwho_opts.host_pat, cptr->user->host);

        if (m1 != m2)
            return 0;
    }

    if (rwho_opts.re)
    {
        s = scratch;
        for (i = 0; rwho_opts.spat[i]; i++)
        {
            switch (rwho_opts.spat[i])
            {
                case RWHO_NICK:
                    s += ircsprintf(s, "%s", cptr->name);
                    s++;    /* deliberately using zero terminator */
                    break;

                case RWHO_USER:
                    s += ircsprintf(s, "%s", cptr->user->username);
                    s++;
                    break;

                case RWHO_GCOS:
                    s += ircsprintf(s, "%s", cptr->info);
                    s++;
                    break;

                    /* will core if RWM_AWAY wasn't implicitly set */
                case RWHO_AWAY:
                    s += ircsprintf(s, "%s", cptr->user->away);
                    s++;
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
    char *src;
    char *dst;

    dst = buf;

    /* use standard RPL_WHOREPLY if no output flags */
    if (!rwho_opts.rplfields)
    {
        char status[5];

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
        
        ircsprintf(buf, getreply(RPL_WHOREPLY), me.name, cptr->name,
                   rwho_opts.chptr ? rwho_opts.chptr->chname : "*",
                   ac->user->username, ac->user->host, ac->user->server,
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
        if (cm)
        {
            if (cm->flags & CHFL_CHANOP)
                *dst++ = '@';
            if (cm->flags & CHFL_VOICE)
                *dst++ = '+';
        }
    }

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

    if (rwho_opts.chptr)
    {
        if (!IsAdmin(sptr) && !ShowChannel(sptr, rwho_opts.chptr))
            rwho_opts.countonly = 1;

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

