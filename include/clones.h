#ifndef CLONES_H
#define CLONES_H
/*
 *   clones.h - Clone detection and limiting
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


typedef struct SCloneEnt CloneEnt;

struct SCloneEnt
{
    CloneEnt *prev;
    CloneEnt *next;
    aClient  *clients;
    int       lcount;
    int       gcount;
    int       limit;
    char      ent[HOSTIPLEN+1];
};

extern void *clones_hashtable;

void clones_init(void);
void clones_set(char *, int);
void clones_send(aClient *);

#ifdef THROTTLE_ENABLE

int  clones_check(aClient *);
void clones_add(aClient *);
void clones_remove(aClient *);

#else   /* THROTTLE_ENABLE */

#define clones_check(x)     (0)
#define clones_add(x)       ((void)0)
#define clones_remove(x)    ((void)0)

#endif

#endif  /* CLONES_H */
