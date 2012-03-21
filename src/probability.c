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

/* $Id: probability.c 1303 2006-12-07 03:23:17Z epiphani $ */

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
static double nscale_lo, nscale_hi;
static double uscale_lo, uscale_hi;
static double gscale_lo, gscale_hi;

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
        nscale_lo = 50.0 / navg;
        nscale_hi = 50.0 / (nmax - navg);
    }

    if (utotal)
    {
        uavg = utotal / ucount;
        uscale_lo = 50.0 / uavg;
        uscale_hi = 50.0 / (umax - uavg);
    }

    if (gtotal)
    {
        gavg = gtotal / gcount;
        gscale_lo = 50.0 / gavg;
        gscale_hi = 50.0 / (gmax - gavg);
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
    nscale_hi = nscale_lo = 0.5;
    uscale_hi = uscale_lo = 0.5;
    gscale_hi = gscale_lo = 0.5;
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
    if (p < 0)
        p = navg;
    *np = (p > navg) ? ((p - navg) * nscale_hi + 50) : (p * nscale_lo);

    p = uavgfunc(ac->user->username, PCS_USER);
    if (p < 0)
        p = uavg;
    *up = (p > uavg) ? ((p - uavg) * uscale_hi + 50) : (p * uscale_lo);

    p = gavgfunc(ac->info, PCS_GCOS);
    if (p < 0)
        p = gavg;
    *gp = (p > gavg) ? ((p - gavg) * gscale_hi + 50) : (p * gscale_lo);
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

