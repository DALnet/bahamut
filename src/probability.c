/*
 *   probability.c - Client identifier probability engine
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
#include "common.h"
#include "sys.h"
#include "h.h"
#include "memcount.h"

#ifdef RWHO_PROBABILITY

/* minimum and maximum character values to calculate probability for */
#define PMINCHAR 0x20
#define PMAXCHAR 0x7e

#define BASESIZE (PMAXCHAR+1-PMINCHAR)

#define PCS_NICK 0x1
#define PCS_USER 0x2
#define PCS_GCOS 0x4

/* number of times each character pair currently appears on the network */
static int probabilities[BASESIZE][BASESIZE];

/* map of characters to scale for */
static char pcharset[256];

/* nick/user/gcos count->percent scale factors */
static double nscale;
static double uscale;
static double gscale;

/* nick/user/gcos unscaled averages */
static int navg;
static int uavg;
static int gavg;

/* state flags */
static char ploadedsets;
static char pfoldedsets;

/* averaging functions */
static int (*navgfunc)(unsigned char *, int);
static int (*uavgfunc)(unsigned char *, int);
static int (*gavgfunc)(unsigned char *, int);

#if 0  /* currently unused */
static void pload_adjacent(char *s, int inc)
{
    unsigned char c1, c2;

    while (1)
    {
        c1 = *s++;
        c2 = *s;

        if (!c1 || !c2)
            break;

        if (c2 < PMINCHAR || c2 > PMAXCHAR)
        {
            s++;
            continue;
        }
        if (c1 < PMINCHAR || c1 > PMAXCHAR)
            continue;

        c1 -= PMINCHAR;
        c2 -= PMINCHAR;
        probabilities[c1][c2] += inc;
    }
}
#endif

static void pload(char *s, int inc)
{
    unsigned char c1, c2;

    while (*s)
    {
        c1 = *s++;

        if (c1 < PMINCHAR || c1 > PMAXCHAR)
            continue;

        /* skip only the low range */
        for (c2 = *s; c2; c2 = *++s)
            if (c2 >= PMINCHAR)
                break;

        if (!c2)
            break;

        if (c2 > PMAXCHAR)
        {
            s++;
            continue;
        }

        c1 -= PMINCHAR;
        c2 -= PMINCHAR;
        probabilities[c1][c2] += inc;
    }
}

static int pavg_adjacent(unsigned char *s, int type)
{
    unsigned char c1, c2, lc1, lc2;
    int count = 0;
    int total = 0;

    if (pfoldedsets & type)
    {
        while(1)
        {
            c1 = *s++;
            c2 = *s;

            if (!c1 || !c2)
                break;

            if (!(pcharset[c2] & type))
            {
                s++;
                continue;
            }
            if (!(pcharset[c2] & type))
                continue;

            lc1 = ToLower(c1) - PMINCHAR;
            lc2 = ToLower(c2) - PMINCHAR;
            c1 = ToUpper(c1) - PMINCHAR;
            c2 = ToUpper(c2) - PMINCHAR;

            count++;
            total += probabilities[c1][c2];
            if (lc1 != c1)
            {
                total += probabilities[lc1][c2];
                if (lc2 != c2)
                    total += probabilities[lc1][lc2];
            }
            if (lc2 != c2)
                total += probabilities[c1][lc2];
        }
    }
    else
    {
        while(1)
        {
            c1 = *s++;
            c2 = *s;

            if (!c1 || !c2)
                break;

            if (!(pcharset[c2] & type))
            {
                s++;
                continue;
            }
            if (!(pcharset[c2] & type))
                continue;

            c1 -= PMINCHAR;
            c2 -= PMINCHAR;
            total += probabilities[c1][c2];
            count++;
        }
    }

    if (!count)
        return -1;

    return (total/count);
}

static int pavg_skip(unsigned char *s, int type)
{
    unsigned char c1, c2, lc1, lc2;
    int count = 0;
    int total = 0;

    if (pfoldedsets & type)
    {
        while(*s)
        {
            c1 = *s++;

            if (!(pcharset[c1] & type))
                continue;

            for (c2 = *s; c2; c2 = *++s)
                if (pcharset[c2] & type)
                    break;

            if (!c2)
                break;

            lc1 = ToLower(c1) - PMINCHAR;
            lc2 = ToLower(c2) - PMINCHAR;
            c1 = ToUpper(c1) - PMINCHAR;
            c2 = ToUpper(c2) - PMINCHAR;

            count++;
            total += probabilities[c1][c2];
            if (lc1 != c1)
            {
                total += probabilities[lc1][c2];
                if (lc2 != c2)
                    total += probabilities[lc1][lc2];
            }
            if (lc2 != c2)
                total += probabilities[c1][lc2];
        }
    }
    else
    {
        while (*s)
        {
            c1 = *s++;

            if (!(pcharset[c1] & type))
                continue;

            for (c2 = *s; c2; c2 = *++s)
                if (pcharset[c2] & type)
                    break;

            if (!c2)
                break;

            c1 -= PMINCHAR;
            c2 -= PMINCHAR;
            total += probabilities[c1][c2];
            count++;
        }
    }

    if (!count)
        return -1;

    return (total/count);
}

static void set_probabilities(void)
{
    int ncount = 0;
    int ucount = 0;
    int gcount = 0;
    unsigned int ntotal = 0;
    unsigned int utotal = 0;
    unsigned int gtotal = 0;
    int nmax = 0;
    int umax = 0;
    int gmax = 0;
    int i;
    aClient *ac;

    for (ac = client; ac; ac = ac->next)
    {
        if (!IsPerson(ac))
            continue;

        i = navgfunc(ac->name, PCS_NICK);
        if (i >= 0)
        {
            ncount++;
            ntotal += i;
            if (i > nmax)
                nmax = i;
        }

        i = uavgfunc(ac->user->username, PCS_USER);
        if (i >= 0)
        {
            ucount++;
            utotal += i;
            if (i > umax)
                umax = i;
        }

        i = gavgfunc(ac->info, PCS_GCOS);
        if (i >= 0)
        {
            gcount++;
            gtotal += i;
            if (i > gmax)
                gmax = i;
        }
    }

    if (ntotal)
    {
        navg = ntotal / ncount;
        nscale = 100.0 / nmax;
    }

    if (utotal)
    {
        uavg = utotal / ucount;
        uscale = 100.0 / umax;
    }

    if (gtotal)
    {
        gavg = gtotal / gcount;
        gscale = 100.0 / gmax;
    }
}


void probability_add(aClient *ac)
{
    pload(ac->name, 1);
    pload(ac->user->username, 1);
    pload(ac->info, 1);
}

void probability_remove(aClient *ac)
{
    pload(ac->name, -1);
    pload(ac->user->username, -1);
    pload(ac->info, -1);
}

void probability_change(char *old, char *new)
{
    pload(old, -1);
    pload(new, 1);
}


/* Initialize tables.  Call before setting custom charsets. */
void probability_init(void)
{
    ploadedsets = 0;
    pfoldedsets = 0;
    memset(pcharset, 0, 256);
    navg = 50;
    uavg = 50;
    gavg = 50;
    nscale = 1.0;
    uscale = 1.0;
    gscale = 1.0;
    navgfunc = pavg_skip;
    uavgfunc = pavg_skip;
    gavgfunc = pavg_skip;
}

/* Parse a custom charset. */
int probability_loadsets(char *text)
{
    char *s, *end;
    int val, val2, set, i;

    s = text;
    while (*s)
    {
        switch (*s)
        {
            case 'n':
                pfoldedsets |= PCS_NICK;
            case 'N':
                set = PCS_NICK;
                if (s[1] == 'a')
                {
                    navgfunc = pavg_adjacent;
                    s++;
                }
                break;

            case 'u':
                pfoldedsets |= PCS_USER;
            case 'U':
                set = PCS_USER;
                if (s[1] == 'a')
                {
                    uavgfunc = pavg_adjacent;
                    s++;
                }
                break;

            case 'g':
                pfoldedsets |= PCS_GCOS;
            case 'G':
                set = PCS_GCOS;
                if (s[1] == 'a')
                {
                    gavgfunc = pavg_adjacent;
                    s++;
                }
                break;

            default:
                return 0;
        }
        ploadedsets |= set;

        while (*s)
        {
            /* parse first value */
            s++;
            val = strtol(s, &end, 0);
            if (end == s)
                return 0;
            if (val < PMINCHAR || val > PMAXCHAR)
                return 0;
            pcharset[val] |= set;
            s = end;

            /* if it's a range, parse second value */
            if (*s == '-')
            {
                s++;
                val2 = strtol(s, &end, 0);
                if (end == s)
                    return 0;
                if (val2 < PMINCHAR || val2 > PMAXCHAR)
                    return 0;
                if (val2 < val)
                    return 0;
                s = end;
                for (i = val+1; i <= val2; i++)
                    pcharset[i] |= set;
            }

            /* if there are no more listed values, break out to next set */
            if (*s != ',')
                break;
        }
    }

    return 1;
}

/* Finialize tables.  Call after setting custom charsets (if any). */
void probability_fini(void)
{
    /* load default sets if no custom ones loaded */
    if (!(ploadedsets & PCS_NICK))
        probability_loadsets("n48-57,65-90,97-122");
    if (!(ploadedsets & PCS_USER))
        probability_loadsets("u48-57,65-90,97-122");
    if (!(ploadedsets & PCS_GCOS))
        probability_loadsets("g65-90,97-122");

    /* calculate scales and averages */
    set_probabilities();
}

/* Get nick/user/gcos probabilities for client. */
void get_probabilities(aClient *ac, int *np, int *up, int *gp)
{
    int p;

    p = navgfunc(ac->name, PCS_NICK);
    *np = (p < 0 ? navg : p) * nscale;

    p = uavgfunc(ac->user->username, PCS_USER);
    *up = (p < 0 ? uavg : p) * uscale;

    p = gavgfunc(ac->info, PCS_GCOS);
    *gp = (p < 0 ? gavg : p) * gscale;
}

u_long
memcount_probability(MCprobability *mc)
{
    mc->file = __FILE__;

    mc->s_prob.c = 1;
    mc->s_prob.m += sizeof(probabilities);

    return 0;
}

#endif  /* RWHO_PROBABILITY */

