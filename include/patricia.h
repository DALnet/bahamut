#ifndef PATRICIA_H
#define PATRICIA_H
/*
 *   patricia.h - IPv4 PATRICIA / Crit-Bit trie
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

#define PATDEL_NOTFOUND     (-1)

typedef struct Patricia Patricia;

void patricia_search(Patricia *, u_int, void (*)(void *, void *), void *);
int patricia_add(Patricia **, u_int, int, int (*)(void *, void **), void *);
int patricia_del(Patricia **, u_int, int, int (*)(void *, void **), void *);
void patricia_walk(Patricia **, void (*)(void *, u_int, int, void **), void *);

void patricia_init(void);

#endif  /* PATRICIA_H */
