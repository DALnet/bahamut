/************************************************************************
 *   IRC - Internet Relay Chat, include/h.h
 *   Copyright (C) 1992 Darren Reed
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
/*
 * "send.h". - Headers file.
 * 
 * all the send* functions are declared here.
 */

#ifndef SEND_H
#define SEND_H

/* send all queued crap to aClient */
extern int  send_queued(aClient *);

#include <stdarg.h>
#include "fdlist.h"

extern void init_send(void);

#ifndef ATTRIBUTE_PRINTF
#if defined(__GNUC__) && __GNUC__ >= 4
#define ATTRIBUTE_PRINTF(fnum, anum) __attribute__((nonnull(fnum))) \
	__attribute__((__format__(__printf__, fnum, anum)))
#else
#define ATTRIBUTE_PRINTF(format, arg)
#endif
#endif

extern void send_chatops(char *pattern, ...) ATTRIBUTE_PRINTF(1, 2);
extern void send_globops(char *pattern, ...) ATTRIBUTE_PRINTF(1, 2);
extern void send_operwall(aClient *, char *, char *);

extern void sendto_all_butone(aClient *one, aClient *from, char *pattern, ...) ATTRIBUTE_PRINTF(3, 4);
extern void sendto_all_servmask(aClient *from, char *mask, char *pattern, ...) ATTRIBUTE_PRINTF(3, 4);
extern void sendto_channel_butone(aClient *one, aClient *from, 
				  aChannel *chptr, char *pattern, ...) ATTRIBUTE_PRINTF(4, 5);
extern void sendto_channel_remote_butone(aClient *one, aClient *from, 
				         aChannel *chptr, char *pattern, ...) ATTRIBUTE_PRINTF(4, 5);
extern void sendto_channel_butserv(aChannel *chptr, aClient *from,
				   char *pattern, ...) ATTRIBUTE_PRINTF(3, 4);
extern void sendto_channel_butserv_noopvoice(aChannel *chptr, aClient *from, char *pattern, ...) ATTRIBUTE_PRINTF(3, 4);

extern void sendto_channel_butserv_me(aChannel *chptr, aClient *from,
				      char *pattern, ...) ATTRIBUTE_PRINTF(3, 4);
extern void sendto_channelopvoice_butserv_me(aChannel *chptr, aClient *from,
				             char *pattern, ...) ATTRIBUTE_PRINTF(3, 4);
extern void sendto_channelflags_butone(aClient *, aClient *, aChannel *,
                                       int, char *, ...) ATTRIBUTE_PRINTF(5, 6);
extern void sendto_common_channels(aClient *user, char *pattern, ...) ATTRIBUTE_PRINTF(2, 3);
extern void send_quit_to_common_channels(aClient *from, char *reason);
extern void send_part_to_common_channels(aClient *from, char *reason);
extern void sendto_fdlist(fdlist *listp, char *pattern, ...) ATTRIBUTE_PRINTF(2, 3);
extern void sendto_locops(char *pattern, ...) ATTRIBUTE_PRINTF(1, 2);
extern void sendto_one(aClient *to, char *pattern, ...) ATTRIBUTE_PRINTF(2, 3);
extern void sendto_alias(AliasInfo *ai, aClient *from, char *pattern, ...) ATTRIBUTE_PRINTF(3, 4);
extern void sendto_ops(char *pattern, ...) ATTRIBUTE_PRINTF(1, 2);
extern void sendto_ops_butone(aClient *one, aClient *from, char *pattern, ...) ATTRIBUTE_PRINTF(3, 4);
extern void sendto_ops_lev(int lev, char *pattern, ...) ATTRIBUTE_PRINTF(2, 3);
extern void sendto_prefix_one(aClient *to, aClient *from, char *pattern, ...) ATTRIBUTE_PRINTF(3, 4);

extern void sendto_realops_lev(int lev, char *pattern, ...) ATTRIBUTE_PRINTF(2, 3);
extern void sendto_realops(char *pattern, ...) ATTRIBUTE_PRINTF(1, 2);
extern void sendto_non_noquit_servs_butone(aClient *one, char *pattern, ...) ATTRIBUTE_PRINTF(2, 3);
extern void sendto_serv_butone(aClient *one, char *pattern, ...) ATTRIBUTE_PRINTF(2, 3);
extern void sendto_serv_butone_nickipstr(aClient *one, int flag, char *pattern, ...) ATTRIBUTE_PRINTF(3, 4);
extern void sendto_serv_butone_super(aClient *one, int flag, char *pattern, ...) ATTRIBUTE_PRINTF(3, 4);
extern void sendto_wallops_butone(aClient *one, aClient *from,
				  char *pattern, ...) ATTRIBUTE_PRINTF(3, 4);
extern void sendto_gnotice(char *pattern, ...) ATTRIBUTE_PRINTF(1, 2);

extern void ts_warn(char *pattern, ...) ATTRIBUTE_PRINTF(1, 2);

extern void vsendto_fdlist(fdlist *listp, char *pattern, va_list vl);
extern void vsendto_one(aClient *to, char *pattern, va_list vl);
extern void vsendto_prefix_one(aClient *to, aClient *from,
			       char *pattern, va_list vl);
extern void vsendto_realops(char *pattern, va_list vl);

extern void flush_connections(int fd);
extern void dump_connections(int fd);
extern void free_fluders(aClient *cptr, aChannel *chptr);
extern void free_fludees(aClient *cptr);

/* IRCv3 tagged point-to-point send */
extern void sendto_one_tags(aClient *to, const char *tags,
                            const char *pattern, ...) ATTRIBUTE_PRINTF(3, 4);

/* Returns a static "time=YYYY-MM-DDTHH:MM:SS.sssZ" string (cached per dispatch_serial) */
extern const char *server_time_tag(void);

/* Outbound tag generator registry */
typedef const char *(*outbound_tag_fn)(void); /* returns "key=val" or NULL/"" */
extern void          register_outbound_tag(outbound_tag_fn fn, unsigned long cap_bit);
extern void          unregister_outbound_tag(outbound_tag_fn fn, unsigned long cap_bit);
extern const char   *build_outbound_tags(void); /* returns "key=val;key2=val2" or "" */
extern unsigned long tag_delivery_caps;         /* OR of all registered cap bits */

/* Tagged channel delivery (plain shared buf for plain clients, unshared for tagged) */
extern void sendto_channel_butone_tags(aClient *one, aClient *from,
                                       aChannel *chptr, const char *tags,
                                       char *pattern, ...) ATTRIBUTE_PRINTF(5, 6);

/* Dedup helpers — also used by modules */
extern int  sent_serial;
extern int  sentalong[];    /* size MAXCONNECTIONS */
#include <limits.h>
#define INC_SERIAL do { \
    if (sent_serial == INT_MAX) { \
        memset(sentalong, 0, sizeof(int) * MAXCONNECTIONS); \
        sent_serial = 0; \
    } \
    sent_serial++; \
} while (0);

#endif
