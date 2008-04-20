/* include/structfunc.h
 * Copyright(c) 2003, Aaron Wiebe
 * Bahamut Development Team
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

/* $Id: structfunc.h 1303 2006-12-07 03:23:17Z epiphani $ */

/* This file includes external function defines for aClient (and possibly
 * other) structure references. */

extern aClient *ac_next(aClient *);
extern aClient *ac_prev(aClient *);
extern anUser *ac_user(aClient *);
extern aServer *ac_server(aClient *);
extern aWhowas *ac_whowas(aClient *);
extern aClient *ac_from(aClient *);
extern aClient *ac_uplink(aClient *);
extern time_t ac_lasttime(aClient *);
extern time_t ac_firsttime(aClient *);
extern time_t ac_since(aClient *);
extern ts_val ac_tsinfo(aClient *);
extern int ac_fd(aClient *);
extern int ac_hopcount(aClient *);
extern short ac_status(aClient *);
extern char ac_nicksent(aClient *);
extern char *ac_name(aClient *);
extern char *ac_info(aClient *);
#ifdef FLUD
extern Link *ac_fludees(aClient *);
#endif
extern struct in_addr ac_ip(aClient *);
extern char *ac_hostip(aClient *);
extern Link *ac_watch(aClient *);
extern int ac_watches(aClient *);
/******************************************
 * These are the local functions...
 ******************************************/
extern int ac_count(aClient *);
#ifdef FLUD
extern time_t ac_fludblock(aClient *);
extern struct fludbot *ac_fluders(aClient *);
#endif
#ifdef ANTI_SPAMBOT
extern time_t ac_last_join_time(aClient *);
extern time_t ac_last_leave_time(aClient *);
extern int ac_join_leave_count(aClient *);
extern int ac_oper_warn_count_down(aClient *);
#endif
extern char *ac_buffer(aClient *);
extern short ac_lastsq(aClient *);
extern SBuf *ac_sendQ(aClient *);
extern SBuf *ac_recvQ(aClient *);
extern long ac_sendM(aClient *);
extern long ac_sendK(aClient *);
extern long ac_recieveM(aClient *);
extern long ac_recieveK(aClient *);
extern u_short ac_sendB(aClient *);
extern u_short ac_recieveB(aClient *);
extern long ac_lastrecvM(aClient *);
extern int ac_priority(aClient *);
extern aListener *ac_lstn(aClient *);
extern Link *ac_confs(aClient *);
extern int ac_authfd(aClient *);
extern char *ac_username(aClient *);
extern unsigned short ac_port(aClient *);
extern struct hostent *ac_hostp(aClient *);
#ifdef ANTI_NICK_FLOOD
extern time_t ac_last_nick_change(aClient *);
extern int ac_number_of_nick_changes(aClient *);
#endif
#ifdef NO_AWAY_FLUD
extern time_t ac_alas(aClient *);
extern int ac_acount(aClient *);
#endif
extern char *ac_sockhost(aClient *);
extern char *ac_passwd(aClient *);
extern int ac_oflag(aClient *);
extern int ac_sockerr(aClient *);
extern int ac_capabilities(aClient *);
extern int ac_pingval(aClient *);
extern int ac_sendqlen(aClient *);
/********************************
 * These are channel access functions
 ********************************/
extern aChannel *ch_next(aChannel *);
extern aChannel *ch_prev(aChannel *);
extern aChannel *ch_hnext(aChannel *);
extern int ch_hashv(aChannel *);
extern Mode ch_mode(aChannel *);
extern char *ch_topic(aChannel *);
extern char *ch_topic_nick(aChannel *);
extern time_t ch_topic_time(aChannel *);
extern int ch_users(aChannel *);
extern chanMember *ch_members(aChannel *);
extern Link *ch_invites(aChannel *);
extern aBan *ch_banlist(aChannel *);
#ifdef INVITE_LISTS
extern anInvite *ch_invite_list(aChannel *);
#endif
#ifdef EXEMPT_LISTS
extern aBanExempt *ch_banexempt_list(aChannel *);
#endif
extern ts_val ch_channelts(aChannel *);
#ifdef FLUD
extern time_t ch_fludblock(aChannel *);
extern struct fludbot *ch_fluders(aChannel *);
#endif
extern char *ch_chname(aChannel *);
