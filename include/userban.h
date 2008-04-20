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

/* $Id: userban.h 1303 2006-12-07 03:23:17Z epiphani $ */

#define UBAN_LOCAL     0x001   /* formerly known as a K: or Z: line */
#define UBAN_NETWORK   0x002   /* formerly known as an autokill or an SZline */

#define UBAN_CONF      0x004   /* this ban came from ircd.conf */

#define UBAN_HOST      0x010   /* this ban matches against the user's resolved host */
#define UBAN_IP        0x020   /* this ban matches against the user's IP address */

#define UBAN_WILD      0x040   /* this ban has wildcards */

#define UBAN_CIDR4     0x080   /* this ban is an IPv4 CIDR ban */
#define UBAN_CIDR4BIG  0x100   /* this ban is an IPv4 CIDR ban for something greater than a /16 */

#define UBAN_WILDUSER  0x200   /* Username is just '*' */
#define UBAN_WILDHOST  0x400   /* Hostname is just '*.*' or '*' -- this ban is a user@* ban */

#define UBAN_TEMPORARY 0x800   /* userban is temporary */

#define SBAN_LOCAL     0x001   
#define SBAN_NETWORK   0x002   
#define SBAN_NICK      0x004   /* sban on the nick field */
#define SBAN_GCOS      0x008   /* sban on the gcos field */
#define SBAN_CHAN      0x010   /* sban on the chname field */
#define SBAN_WILD      0x020   /* sban mask contains wildcards */
#define SBAN_TEMPORARY 0x040   /* sban is temporary */

struct userBan {
   unsigned int flags;
   char *u;                    /* username */
   char *h;                    /* host or IP or GECOS or NICK */

   unsigned int cidr4ip;       /* cidr4 IP */   
   unsigned int cidr4mask;     /* cidr4 mask */   

   char *reason;
   time_t timeset;             /* time this ban was set */
   time_t duration;            /* length of this ban, in seconds, or 0xFFFFFFFF for permanent */   

   void *internal_ent;         /* internal -- pointer to banlist entry tag */
};

struct simBan {
   unsigned int flags;
   char *mask;

   char *reason;
   time_t timeset;
   time_t duration;

   void *internal_ent;         /* internal -- pointer to banlist entry tag */
};


void init_userban();

struct userBan *make_hostbased_ban(char *, char *);

void add_hostbased_userban(struct userBan *);
void remove_userban(struct userBan *);
void userban_free(struct userBan *);

struct userBan *check_userbanned(aClient *, unsigned int, unsigned int);
struct userBan *find_userban_exact(struct userBan *, unsigned int);

void expire_userbans();
void remove_userbans_match_flags(unsigned int, unsigned int);
void report_userbans_match_flags(aClient *cptr, unsigned int, unsigned int);

int user_match_ban(aClient *, struct userBan *);
char *get_userban_host(struct userBan *, char *, int);

void userban_sweep(struct userBan *);

/* Simban Calls */

struct simBan *make_simpleban(unsigned int, char *);
void add_simban(struct simBan *);
void remove_simban(struct simBan *);
struct simBan *find_simban_exact(struct simBan *);
int user_match_simban(aClient *, struct simBan *);
struct simBan *check_mask_simbanned(char *, unsigned int);
void simban_free(struct simBan *);
void remove_simban(struct simBan *);
void remove_simbans_match_flags(unsigned int, unsigned int);
void remove_simbans_match_mask(unsigned int, char *, int);
void report_simbans_match_flags(aClient *, unsigned int, unsigned int);
void expire_simbans();
void send_simbans(aClient *, unsigned int);
void remove_simban(struct simBan *);
