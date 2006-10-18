#ifndef IRC_USERBAN_H
#define IRC_USERBAN_H
/************************************************************************
 *   IRC - Internet Relay Chat, include/userban.h
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

#include "patricia.h"


#define UBAN_LOCAL      0x01    /* local ban (K-Line) */
#define UBAN_CONF       0x02    /* came from ircd.conf */
#define UBAN_EXEMPT     0x04    /* ban exemption */
#define UBAN_PERSIST    0x08    /* sent in netbursts or stored in journal */

#define UBAN_UPDATE     0x80    /* update any existing ban when adding */

#define UBAN_ADD_INVALID    1
#define UBAN_ADD_DUPLICATE  2

#define UBAN_DEL_NOTFOUND   PATDEL_NOTFOUND
#define UBAN_DEL_INCONF     1

typedef struct UserBanInfo UserBanInfo;

struct UserBanInfo {
    u_short  flags;     /* ban flags */
    char    *mask;      /* ban mask */
    char    *reason;    /* ban reason */
    time_t   expirets;	/* expiration timestamp */
};

int userban_add(char *, char *, time_t, u_short, UserBanInfo *);
int userban_del(char *, u_short, UserBanInfo *);
void userban_massdel(time_t, u_short, u_short);
UserBanInfo *userban_checkclient(aClient *);
UserBanInfo *userban_checkserver(aClient *);
void userban_sweep(void);
void userban_sendburst(aClient *);

#endif  /* IRC_USERBAN_H */
