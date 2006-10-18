/*
 *   klines.c - Kline interface and storage
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
 * This is a simple K-Line journal implementation.  When a K-Line with a
 * duration of KLINE_MIN_STORE_TIME or more is added, it is written to the
 * journal file (.klines):
 *   + expireTS user@hostmask reason
 * 
 * When a K-Line is manually removed, it also results in a journal entry:
 *   - user@hostmask
 * 
 * This allows K-Lines to be saved across restarts and rehashes.
 *
 * To keep the journal from getting larger than it needs to be, it is
 * periodically compacted: all active K-Lines are dumped into a new file, which
 * then replaces the active journal.  This is done on startup as well as every
 * KLINE_STORE_COMPACT_THRESH journal entries.
 */
 

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"

#include <fcntl.h>

#include "userban.h"
#include "numeric.h"
#include "ircstrings.h"

static int journal = -1;
static char journalfilename[512];
static int journalcount;

void klinestore_add(UserBanInfo *);
void klinestore_remove(UserBanInfo *);

/* ircd.c */
extern int forked;

/* s_misc.c */
extern char *smalldate(time_t);

typedef struct {
    int iflags;
    int defmins;
    char *cmd;
    char *ban;
    char *banned;
} KLData;


/* worker for adding local userbans */
static int
kl_add(KLData *kldata, aClient *sptr, int parc, char *parv[])
{
    char rbuf[BUFSIZE];
    char mbuf[BUFSIZE];
    char *mask;
    char *reason;
    int tkminutes;
    time_t expirets;
    u_short flags;
    long lval;
    int rv;
    UserBanInfo ubi;

    reason = "<no reason>";
    tkminutes = kldata->defmins;
    flags = UBAN_LOCAL | kldata->iflags;

    if (!OPCanKline(sptr))
    {
        sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
        return 0;
    }

    if (parc < 2)
    {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0],
                   kldata->cmd);
        return 0;
    }

    lval = strtol(parv[1], &mask, 10);
    if (*mask != 0)
    {
        mask = parv[1];

        if (parc > 2 && !BadPtr(parv[2]))
            reason = parv[2];
    }
    else
    {
        /* valid expiration time */
        tkminutes = lval;

        if (parc < 3)
        {
            sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0],
                       kldata->cmd);
            return 0;
        }

        mask = parv[2];

        if (parc > 3 && !BadPtr(parv[3]))
            reason = parv[3];
    }

    /* negative times, or times greater than a year, are permanent */
    if (tkminutes < 0 || tkminutes > (365 * 24 * 60))
        tkminutes = 0;

    if (tkminutes)
    {
        expirets = NOW + (tkminutes * 60);
        if (tkminutes >= KLINE_MIN_STORE_TIME)
            flags |= UBAN_PERSIST;
    }
    else
    {
        expirets = 0;
        flags |= UBAN_PERSIST;
    }

    /* if it looks like a nickname, make a user@host from the online client */
    if (validate_nick(mask, 0))
    {
        aClient *acptr;
        char *user;

        if (!(acptr = find_client(mask, NULL)))
        {
            sendto_one(sptr, ":%s NOTICE %s :%s: no such nick %s",
                       me.name, parv[0], kldata->cmd, mask);
            return 0;
        }

        user = acptr->user->username;
        if (*user == '~')
            user++;

        ircsprintf(mbuf, "*%s@%s/24", user, acptr->hostip);
        mask = mbuf;

        /* if the username is USERLEN, slice it with another star */
        if (strlen(user) == USERLEN)
            mbuf[USERLEN] = '*';
    }
    else
    {
        /* convert hostmask to *@hostmask */
        if (!strchr(mask, '@'))
        {
            ircsprintf(mbuf, "*@%s", mask);
            mask = mbuf;
        }
    }

    ircsprintf(rbuf, "%s (%s)", reason, smalldate(0));
    reason = rbuf;

    rv = userban_add(mask, reason, expirets, flags, &ubi);

    if (rv == UBAN_ADD_INVALID)
    {
        sendto_one(sptr, ":%s NOTICE %s :%s: invalid mask %s",
                   me.name, parv[0], kldata->cmd, mask);
        return 0;
    }

    if (rv == UBAN_ADD_DUPLICATE)
    {
        sendto_one(sptr, ":%s NOTICE %s :%s: %s is already %s: %s",
                   me.name, parv[0], kldata->cmd, ubi.mask, kldata->banned,
                   ubi.reason);
        return 0;
    }

    if (tkminutes)
        sendto_realops("%s added %d minute %s for %s: %s", parv[0], tkminutes,
                       kldata->ban, ubi.mask, reason);
    else
        sendto_realops("%s added permanent %s for %s: %s", parv[0],
                       kldata->ban, ubi.mask, reason);

    if (flags & UBAN_PERSIST)
        klinestore_add(&ubi);

    return 0;
}


/* worker for removing local userbans */
int
kl_del(KLData *kldata, aClient *sptr, int parc, char *parv[])
{
    char mbuf[BUFSIZE];
    char *mask;
    int rv;
    UserBanInfo ubi;

    if (!OPCanUnKline(sptr))
    {
        sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
        return 0;
    }

    if (parc < 2)
    {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0],
                   kldata->cmd);
        return 0;
    }

    mask = parv[1];

    /* convert hostmask into *@hostmask */
    if (!strchr(mask, '@'))
    {
        ircsprintf(mbuf, "*@%s", mask);
        mask = mbuf;
    }

    rv = userban_del(mask, UBAN_LOCAL|kldata->iflags, &ubi);

    if (rv == UBAN_DEL_NOTFOUND)
    {
        sendto_one(sptr, ":%s NOTICE %s :%s: %s is not %s",
                   me.name, parv[0], kldata->cmd, mask, kldata->banned);
        return 0;
    }

    if (rv == UBAN_DEL_INCONF)
    {
        sendto_one(sptr, ":%s NOTICE %s :%s: %s is specified in the"
                   " configuration file and cannot be removed online", me.name,
                   parv[0], kldata->cmd, ubi.mask);
        return 0;
    }

    sendto_ops("%s removed %s for %s", parv[0], kldata->ban, ubi.mask);

    if (ubi.flags & UBAN_PERSIST)
        klinestore_remove(&ubi);

    return 0;
}


/*
 * m_kline
 * Add a local user@host ban.
 *
 *    parv[0] = sender
 *    parv[1] = duration in minutes (optional)
 *    parv[2] = nick or user@host mask
 *    parv[3] = reason (optional)
 */
int
m_kline(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    KLData kldata = {
        0,
        DEFAULT_KLINE_TIME,
        "KLINE",
        LOCAL_BAN_NAME,
        LOCAL_BANNED_NAME
    };

    return kl_add(&kldata, sptr, parc, parv);
}

/*
 * m_kexempt
 * Add a local user@host ban exemption.
 *
 *    parv[0] = sender
 *    parv[1] = duration in minutes (optional)
 *    parv[2] = nick or user@host mask
 *    parv[3] = reason (optional)
 */
int
m_kexempt(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    KLData kldata = {
        UBAN_EXEMPT,
        0,
        "KEXEMPT",
        LOCAL_EXEMPT_NAME,
        LOCAL_EXEMPTED_NAME
    };

    return kl_add(&kldata, sptr, parc, parv);
}

/*
 * m_unkline
 * Remove a local user@host ban.
 *
 *     parv[0] = sender
 *     parv[1] = user@host mask
 */
int m_unkline(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    KLData kldata = {
        0,
        0,
        "UNKLINE",
        LOCAL_BAN_NAME,
        LOCAL_BANNED_NAME
    };

    return kl_del(&kldata, sptr, parc, parv);
}

/*
 * m_unkexempt
 * Remove a local user@host ban exemption.
 *
 *     parv[0] = sender
 *     parv[1] = user@host mask
 */
int m_unkexempt(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    KLData kldata = {
        UBAN_EXEMPT,
        0,
        "UNKEXEMPT",
        LOCAL_EXEMPT_NAME,
        LOCAL_EXEMPTED_NAME
    };

    return kl_del(&kldata, sptr, parc, parv);
}


static void
ks_error(char *msg)
{
    if (!forked)
        puts(msg);
    else
        sendto_ops("%s", msg);
}

/*
 * Writes a K-Line to the appropriate file.
 */
void
ks_write(int f, char type, UserBanInfo *ubi)
{
    char outbuf[1024];
    int len;

    if (type == '+')
        len = ircsprintf(outbuf, "+%s %d %s %s\n",
                         (ubi->flags & UBAN_EXEMPT) ? "E" : "",
                         ubi->expirets, ubi->mask, ubi->reason);
    else
        len = ircsprintf(outbuf, "-%s %s\n",
                         (ubi->flags & UBAN_EXEMPT) ? "E" : "",
                         ubi->mask);

    write(f, outbuf, len);
}

/*
 * Parses a K-Line entry from a storage journal line.
 * Returns 0 on invalid input, 1 otherwise.
 */
static int
ks_read(char *s)
{
    char type;
    char *mask;
    time_t expirets = 0;
    u_short flags = UBAN_LOCAL|UBAN_PERSIST;
    char *reason = "<no reason>";

    type = *s++;

    /* bad type */
    if (type != '+' && type != '-')
        return 0;

    if (*s == 'E')
    {
        flags |= UBAN_EXEMPT;
        s++;
    }

    /* malformed */
    if (*s++ != ' ')
        return 0;

    if (type == '+')
    {
        expirets = strtol(s, &s, 0);

        /* already expired */
        if (expirets && NOW >= expirets)
            return 1;

        /* malformed */
        if (*s++ != ' ')
            return 0;
    }

    /* user mask */
    mask = s;
    while (*s && *s != ' ')
        s++;

    if (*s)
    {
        /* malformed */
        if (*s != ' ')
            return 0;

        *s++ = 0;
    }

    if (type == '+')
    {
        /* reason is the only thing left */
        reason = s;
    }

    if (type == '+')
        userban_add(mask, reason, expirets, flags, NULL);
    else
        userban_del(mask, flags, NULL);

    return 1;
}

/*
 * Compact K-Line store: dump active klines to a new file and remove the
 * current journal.
 * Returns 1 on success, 0 on failure.
 */
int
klinestore_compact(void)
{
    char buf1[512];
    int newfile;

    /* userban.c */
    extern void ks_dumpklines(int);

    if (forked)
        sendto_ops_lev(DEBUG_LEV, "Compacting K-Line store...");
    journalcount = 0;

    /* open a compaction file to dump all active klines to */
    ircsnprintf(buf1, sizeof(buf1), "%s/.klines_c", dpath);
    newfile = open(buf1, O_WRONLY|O_CREAT|O_TRUNC, 0700);
    if (newfile < 0)
    {
        ircsnprintf(buf1, sizeof(buf1), "ERROR: Unable to create K-Line"
                    " compaction file .klines_c: %s",
                    strerror(errno));
        ks_error(buf1);
        return 0;
    }

    /* do the dump */
    ks_dumpklines(newfile);
    close(newfile);

    /* close active storage file, rename compaction file, and reopen */
    if (journal >= 0)
    {
        close(journal);
        journal = -1;
    }
    if (rename(buf1, journalfilename) < 0)
    {
        ircsnprintf(buf1, sizeof(buf1), "ERROR: Unable to rename K-Line"
                    " compaction file .klines_c to .klines: %s",
                    strerror(errno));
        ks_error(buf1);
        return 0;
    }
    journal = open(journalfilename, O_WRONLY|O_APPEND, 0700);
    if (journal < 0)
    {
        ircsnprintf(buf1, sizeof(buf1), "ERROR: Unable to reopen K-Line"
                    " storage file .klines: %s", strerror(errno));
        ks_error(buf1);
        return 0;
    }

    return 1;
}

/*
 * Add a K-Line to the active store.
 */
void
klinestore_add(UserBanInfo *ubi)
{
    if (journal >= 0)
        ks_write(journal, '+', ubi);

    if (++journalcount > KLINE_STORE_COMPACT_THRESH)
        klinestore_compact();
}

/*
 * Remove a K-Line from the active store.
 */
void
klinestore_remove(UserBanInfo *ubi)
{
    if (journal >= 0)
        ks_write(journal, '-', ubi);

    if (++journalcount > KLINE_STORE_COMPACT_THRESH)
        klinestore_compact();
}

/*
 * Initialize K-Line storage.  Pass 1 when klines don't need to be reloaded.
 * Returns 0 on failure, 1 otherwise.
 */
int
klinestore_init(int alreadyloaded)
{
    char buf1[1024];
    FILE *jf;

    ircsnprintf(journalfilename, sizeof(journalfilename), "%s/.klines", dpath);

    if (journal >= 0)
    {
        if (alreadyloaded)
            return 1;

        close(journal);
        journal = -1;
    }

    /* "a+" to create if it doesn't exist */
    jf = fopen(journalfilename, "a+");
    if (!jf)
    {
        ircsnprintf(buf1, sizeof(buf1), "ERROR: Unable to open K-Line storage"
                    " file .klines: %s", strerror(errno));
        ks_error(buf1);
        return 0;
    }
    rewind(jf);

    /* replay journal */
    while (fgets(buf1, sizeof(buf1), jf))
    {
        char *s = strchr(buf1, '\n');

        /* no newline, consider it malformed and stop here */
        if (!s)
            break;

        *s = 0;

        if (!ks_read(buf1))
            break;
    }

    fclose(jf);

    /* this will reopen the journal for appending */
    return klinestore_compact();
}

