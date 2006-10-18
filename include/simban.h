#ifndef IRC_SIMBAN_H
#define IRC_SIMBAN_H
/************************************************************************
 *   IRC - Internet Relay Chat, include/simban.h
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

#define SBAN_CHAN       0x01    /* channel ban (else nick) */
#define SBAN_CONF       0x02    /* came from ircd.conf */
#define SBAN_PERSIST    0x04    /* persistent, sent in netbursts */
#define SBAN_COMPAT     0x08    /* use old commands for persistence */
#define SBAN_PUNISH     0x10    /* punish clients for use attempts */

#define SBAN_UPDATE     0x80    /* update any existing ban when adding */

#define SBAN_ADD_INVALID    1
#define SBAN_ADD_DUPLICATE  2

typedef struct SimBanInfo SimBanInfo;

struct SimBanInfo {
    char    *mask;      /* ban name or mask */
    char    *reason;    /* ban reason */
    int      punish;    /* punish client for use attempts */
    int      plimit;    /* expiration penalty is at its limit */
};

int simban_add(char *, char *, time_t, int, u_int);
void simban_del(char *, u_int);
void simban_massdel(time_t, u_int, u_int, char *);
SimBanInfo *simban_checknick(char *);
SimBanInfo *simban_checkchannel(char *);
void simban_sendburst(aClient *);

#endif  /* IRC_SIMBAN_H */
