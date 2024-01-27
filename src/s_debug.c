/************************************************************************
 *   IRC - Internet Relay Chat, src/s_debug.c
 *   Copyright (C) 1990 Jarkko Oikarinen and
 *                      University of Oulu, Computing Center
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
#include "h.h"
#include "patchlevel.h"
#include "numeric.h"
#include "channel.h"

/* This file is hereby declared the nexus of all things ugly and preprocessed */

static char rplisupport1[BUFSIZE];
static char rplisupport2[BUFSIZE];
static char rplisupportoper[BUFSIZE];
static char rplversion[BUFSIZE];
static char scratchbuf[BUFSIZE];

/* send cached RPL_ISUPPORT */
void send_rplisupport(aClient *acptr)
{
    sendto_one(acptr, rplisupport1, acptr->name);
    sendto_one(acptr, rplisupport2, acptr->name);
}

/* send cached RPL_ISUPPORT for oper limits */
void send_rplisupportoper(aClient *acptr)
{
    sendto_one(acptr, rplisupportoper, acptr->name);
}

/* send cached RPL_VERSION */
void send_rplversion(aClient *acptr)
{
    sendto_one(acptr, rplversion, acptr->name);
}


/* build and cache complex strings */
void build_rplcache(void)
{
    char *s;

    /* build RPL_ISUPPORT */

    /* Most of this tracks draft-brocklesby-irc-isupport-03, with a
    * few differences:
    * STD is not sent since there is no RFC
    * MAXCHANNELS and MAXBANS are sent for compatibility with old clients
    * SILENCE WATCH and ELIST are sent but not documented
    */

    /* put MAXBANS and MAXCHANNELS first so better tokens override them */
    ircsprintf(scratchbuf,"NETWORK=%s SAFELIST MAXBANS=%i MAXCHANNELS=%i "
               "CHANNELLEN=%i KICKLEN=%i NICKLEN=%i TOPICLEN=%i MODES=%i "
               "CHANTYPES=# CHANLIMIT=#:%i "
#ifdef USE_HALFOPS
               "PREFIX=(ohv)@%%%%+ STATUSMSG=@%%%%+",
#else
               "PREFIX=(ov)@+ STATUSMSG=@+",
#endif
               Network_Name, MAXBANS, maxchannelsperuser, CHANNELLEN,
               TOPICLEN, NICKLEN, TOPICLEN, MAXMODEPARAMSUSER,
               maxchannelsperuser);

    ircsprintf(rplisupport1, rpl_str(RPL_ISUPPORT), me.name, "%s", scratchbuf);

    ircsprintf(scratchbuf,"WATCH=65535 MAXCHANNELS=%i CHANLIMIT=#:%i",
               (maxchannelsperuser * 3), (maxchannelsperuser * 3));
    ircsprintf(rplisupportoper, rpl_str(RPL_ISUPPORT), me.name, "%s", scratchbuf);

    s = scratchbuf;
    s += ircsprintf(s, "CASEMAPPING=ascii WATCH=%i SILENCE=%i ELIST=CT",
                    MAXWATCH, MAXSILES);
#ifdef EXEMPT_LISTS
    s += ircsprintf(s, " EXCEPTS");
#endif
#ifdef INVITE_LISTS
    s += ircsprintf(s, " INVEX");
#endif
    s += ircsprintf(s, " CHANMODES=b");
#ifdef EXEMPT_LISTS
    *s++ = 'e';
#endif
#ifdef INVITE_LISTS
    *s++ = 'I';
#endif
    s += ircsprintf(s, ",k,jl,ci");
#ifdef USE_CHANMODE_L
    *s++ = 'L';
#endif
#ifdef SPAMFILTER
    *s++ = 'P';
#endif
    s += ircsprintf(s, "AmMnOprRsSt MAXLIST=b:%i", MAXBANS);
#ifdef EXEMPT_LISTS
    s += ircsprintf(s, ",e:%i", MAXEXEMPTLIST);
#endif
#ifdef INVITE_LISTS
    s += ircsprintf(s, ",I:%i", MAXINVITELIST);
#endif
    s += ircsprintf(s, " TARGMAX=DCCALLOW:,JOIN:,KICK:4,KILL:20,NOTICE:%i,"
                    "PART:,PRIVMSG:%i,WHOIS:,WHOWAS:", MAXRECIPIENTS,
                    MAXRECIPIENTS);

    ircsprintf(rplisupport2, rpl_str(RPL_ISUPPORT), me.name, "%s", scratchbuf);


    /* build RPL_VERSION */
    s = scratchbuf;

#ifdef ANTI_SPAMBOT
    *s++ = 'a';
#endif
#ifdef ALWAYS_SEND_DURING_SPLIT
    *s++ = 'A';
#endif
#ifdef MAXBUFFERS
    *s++ = 'B';
#endif
#ifdef CMDLINE_CONFIG
    *s++ = 'C';
#endif
#ifdef DO_IDENTD
    *s++ = 'd';
#endif
#ifdef DEBUGMODE
    *s++ = 'D';
#endif
#ifdef HAVE_ENCRYPTION_ON
    *s++ = 'E';
#endif
#ifdef FLUD
    *s++ = 'F';
#endif
#ifdef SHOW_HEADERS
    *s++ = 'h';
#endif
#ifdef SHOW_INVISIBLE_LUSERS
    *s++ = 'i';
#endif
#ifdef NO_DEFAULT_INVISIBLE
    *s++ = 'I';
#endif
#ifdef NO_DEFAULT_JOINRATE
    *s++ = 'J';
#endif
#ifdef USE_HOOKMODULES
    *s++ = 'M';
#endif
#ifdef DNS_DEBUG
    *s++ = 'N';
#endif
#ifdef DENY_SERVICES_MSGS
    *s++ = 'r';
#endif
#ifdef SUPER_TARGETS_ONLY
    *s++ = 's';
#endif
#ifdef MSG_TARGET_LIMIT
    *s++ = 't';
#endif
#ifdef THROTTLE_ENABLE
    *s++ = 'T';
#endif
#ifdef IRCII_KLUDGE
    *s++ = 'u';
#endif
#ifdef USE_SYSLOG
    *s++ = 'Y';
#endif
    *s++ = '/';
    if (confopts & FLAGS_HUB)
        *s++ = 'H';
    if (confopts & FLAGS_SMOTD)
        *s++ = 'm';
    if (confopts & FLAGS_SPLITOPOK)
        *s++ = 'o';
    if (confopts & FLAGS_CRYPTPASS)
        *s++ = 'p';
    if (confopts & FLAGS_SERVHUB)
        *s++ = 'S';
    if ((confopts & FLAGS_WGMON) == FLAGS_WGMON)
        *s++ = 'w';
    
    s += ircsprintf(s, " TS%iow", TS_CURRENT);

#ifdef RIDICULOUS_PARANOIA_LEVEL
    s += ircsprintf(s, " RPL%i", RIDICULOUS_PARANOIA_LEVEL);
#endif

    s += ircsprintf(s, " NP[");
#ifdef FORCE_EVERYONE_HIDDEN
    *s++ = 'A';
#endif
#ifdef ALLOW_HIDDEN_OPERS
    *s++ = 'I';
#endif
#ifdef HIDE_KILL_ORIGINS
    *s++ = 'K';
#endif
#ifdef NO_USER_SERVERKILLS
    *s++ = 'k';
#endif
    if (!(confopts & FLAGS_SHOWLINKS))
        *s++ = 'L';
#ifdef HIDE_SERVERMODE_ORIGINS
    *s++ = 'M';
#endif
#ifdef HIDE_NUMERIC_SOURCE
    *s++ = 'N';
#endif
#ifdef NO_USER_OPERTARGETED_COMMANDS
    *s++ = 'O';
#endif
#ifdef HIDE_SPLIT_SERVERS
    *s++ = 'P';
#endif
#ifdef NO_USER_STATS
    *s++ = 'S';
#endif
#ifdef NO_USER_OPERKILLS
    *s++ = 's';
#endif
#ifdef NO_USER_TRACE
    *s++ = 'T';
#endif
#ifdef HIDEULINEDSERVS
    *s++ = 'U';
#endif
    *s++ = ']';
    *s++ = 0;

    ircsprintf(rplversion, rpl_str(RPL_VERSION), me.name, "%s", version,
                    debugmode, me.name, scratchbuf);
}


#if defined(DNS_DEBUG) || defined(DEBUGMODE)
static char debugbuf[1024];

void debug(int level, char *pattern, ...)
{
    va_list      vl;
    int         err = errno;
    
    va_start(vl, pattern);
    (void) vsprintf(debugbuf, pattern, vl);
    va_end(vl);

#ifdef USE_SYSLOG
    if (level == DEBUG_ERROR)
        syslog(LOG_ERR, "%s", debugbuf);
#endif

    if ((debuglevel >= 0) && (level <= debuglevel)) {

        if (local[2]) {
            local[2]->sendM++;
            local[2]->sendB += strlen(debugbuf);
        }
        (void) fprintf(stderr, "%s", debugbuf);
        (void) fputc('\n', stderr);
    }
    errno = err;
}

#endif
