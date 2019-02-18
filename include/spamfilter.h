/************************************************************************
 *   Bahamut IRCd, include/spamfilter.h
 *   Copyright (C) 2005-2018, Kobi Shmueli
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

extern int load_spamfilter();
extern int save_spamfilter();
extern void stripcolors(char new[512], char *org);
extern void stripall(char new[512], char *org);
extern int check_sf(aClient *cptr, char *text, char *caction, int action, char *target);
extern struct spam_filter *new_sf(char *text, long flags, char *reason, char *target);
extern void spamfilter_sendserver(aClient *acptr);

#define SF_FLAG_NONE      000000
#define SF_FLAG_STRIPCTRL 0x0001
#define SF_FLAG_STRIPALL  0x0002
#define SF_FLAG_REGEXP    0x0004
#define SF_FLAG_BREAK     0x0008
#define SF_FLAG_MATCHREG  0x20000

#define SF_CMD_PRIVMSG    0x0010
#define SF_CMD_NOTICE     0x0020
#define SF_CMD_KICK       0x0040
#define SF_CMD_QUIT       0x0080
#define SF_CMD_TOPIC      0x0100
#define SF_CMD_AWAY       0x0200
#define SF_CMD_PART       0x0400
#define SF_CMD_CHANNEL    0x0800

#define SF_ACT_WARN       0x1000
#define SF_ACT_LAG        0x2000
#define SF_ACT_REPORT     0x4000
#define SF_ACT_BLOCK      0x8000
#define SF_ACT_KILL       0x10000
#define SF_ACT_AKILL      0x40000
