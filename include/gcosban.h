#ifndef IRC_GCOSBAN_H
#define IRC_GCOSBAN_H
/************************************************************************
 *   IRC - Internet Relay Chat, include/gcosban.h
 *   Copyright (C) 2002 Lucas Madar
 *                      and the DALnet coding team
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

#define GCBAN_CONF      0x01    /* came from ircd.conf */

#define GCBAN_ADD_INVALID   1

int gcosban_add(u_int, char *, char *);
void gcosban_del(u_int, char *);
void gcosban_massdel(u_int, char *);
char *gcosban_check(char *);
void gcosban_sendburst(aClient *);

#endif  /* IRC_GCOSBAN_H */
