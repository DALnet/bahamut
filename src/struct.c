/* src/struct.c
 * Copyright(c) 2003, Aaron Wiebe
 * Bahamut development team
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

/* This file contains quick and dirty functions for retriving information
 * from structures. */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "msg.h"
#include "channel.h"
#include "throttle.h"

aClient *ac_next(aClient *cptr)
{
	return cptr->next;
}

aClient *ac_prev(aClient *cptr)
{
	return cptr->prev;
}

anUser *ac_user(aClient *cptr)
{
	return cptr->user;
}

aServer *ac_server(aClient *cptr)
{
	return cptr->serv;
}

aWhowas *ac_whowas(aClient *cptr)
{
	return cptr->whowas;
}

aClient *ac_from(aClient *cptr)
{
	return cptr->from;
}

aClient *ac_uplink(aClient *cptr)
{
	return cptr->uplink;
}

time_t ac_lasttime(aClient *cptr)
{
	return cptr->lasttime;
}

time_t ac_firsttime(aClient *cptr)
{
	return cptr->firsttime;
}

time_t ac_since(aClient *cptr)
{
	return cptr->since;
}

ts_val ac_tsinfo(aClient *cptr)
{
	return cptr->tsinfo;
}

int ac_fd(aClient *cptr)
{
	return cptr->fd;
}

int ac_hopcount(aClient *cptr)
{
	return cptr->hopcount;
}

short ac_status(aClient *cptr)
{
	return cptr->status;
}

char ac_nicksent(aClient *cptr)
{
	return cptr->nicksent;
}

char *ac_name(aClient *cptr)
{
	return cptr->name;
}

char *ac_info(aClient *cptr)
{
	return cptr->info;
}

#ifdef FLUD
Link *ac_fludees(aClient *cptr)
{
	return cptr->fludees;
}
#endif

struct in_addr ac_ip(aClient *cptr)
{
	return cptr->ip;
}

char *ac_hostip(aClient *cptr)
{
	return cptr->hostip;
}

Link *ac_watch(aClient *cptr)
{
	return cptr->watch;
}

int ac_watches(aClient *cptr)
{
	return cptr->watches;
}

/*************************************
 * local only stuff starts here 
 *************************************/

int ac_count(aClient *cptr)
{
	if(cptr->fd == -1)
		abort();
	return cptr->count;
}

#ifdef FLUD
time_t ac_fludblock(aClient *cptr)
{
        if(cptr->fd == -1)
                abort();
        return cptr->fludblock;
}

struct fludbot *ac_fluders(aClient *cptr)
{
        if(cptr->fd == -1)
                abort();
        return cptr->fluders;
}
#endif
#ifdef ANTI_SPAMBOT
time_t ac_last_join_time(aClient *cptr)
{
        if(cptr->fd == -1)
                abort();
        return cptr->last_join_time;
}

time_t ac_last_leave_time(aClient *cptr)
{
        if(cptr->fd == -1)
                abort();
        return cptr->last_leave_time;
}

int ac_join_leave_count(aClient *cptr)
{
        if(cptr->fd == -1)
                abort();
        return cptr->join_leave_count;
}

int ac_oper_warn_count_down(aClient *cptr)
{
        if(cptr->fd == -1)
                abort();
        return cptr->oper_warn_count_down;
}
#endif

char *ac_buffer(aClient *cptr)
{
        if(cptr->fd == -1)
                abort();
        return cptr->buffer;
}

short ac_lastsq(aClient *cptr)
{
        if(cptr->fd == -1)
                abort();
        return cptr->lastsq;
}

struct DBuf *ac_sendQ(aClient *cptr)
{
        if(cptr->fd == -1)
                abort();
        return &cptr->sendQ;
}

struct DBuf *ac_recvQ(aClient *cptr)
{
        if(cptr->fd == -1)
                abort();
        return &cptr->recvQ;
}

long ac_sendM(aClient *cptr)
{
        if(cptr->fd == -1)
                abort();
        return cptr->sendM;
}

long ac_sendK(aClient *cptr)
{
        if(cptr->fd == -1)
                abort();
        return cptr->sendK;
}

long ac_receiveM(aClient *cptr)
{
        if(cptr->fd == -1)
                abort();
        return cptr->receiveM;
}

long ac_receiveK(aClient *cptr)
{
	if(cptr->fd == -1)
		abort();
	return cptr->receiveK;
}

u_short ac_sendB(aClient *cptr)
{
        if(cptr->fd == -1)
                abort();
        return cptr->sendB;
}

u_short ac_receiveB(aClient *cptr)
{
        if(cptr->fd == -1)
                abort();
        return cptr->receiveB;
}

long ac_lastrecvM(aClient *cptr)
{
        if(cptr->fd == -1)
                abort();
        return cptr->lastrecvM;
}

int ac_priority(aClient *cptr)
{
        if(cptr->fd == -1)
                abort();
        return cptr->priority;
}

aListener *ac_lstn(aClient *cptr)
{
        if(cptr->fd == -1)
                abort();
        return cptr->lstn;
}

CLink *ac_confs(aClient *cptr)
{
        if(cptr->fd == -1)
                abort();
        return cptr->confs;
}

int ac_authfd(aClient *cptr)
{
        if(cptr->fd == -1)
                abort();
        return cptr->authfd;
}

char *ac_username(aClient *cptr)
{
        if(cptr->fd == -1)
                abort();
        return cptr->username;
}

unsigned short ac_port(aClient *cptr)
{
        if(cptr->fd == -1)
                abort();
        return cptr->port;
}

struct hostent *ac_hostp(aClient *cptr)
{
        if(cptr->fd == -1)
                abort();
        return cptr->hostp;
}

#ifdef ANTI_NICK_FLOOD
time_t ac_last_nick_change(aClient *cptr)
{
        if(cptr->fd == -1)
                abort();
        return cptr->last_nick_change;
}

int ac_number_of_nick_changes(aClient *cptr)
{
        if(cptr->fd == -1)
                abort();
        return cptr->number_of_nick_changes;
}
#endif
#ifdef NO_AWAY_FLUD
time_t ac_alas(aClient *cptr)
{
        if(cptr->fd == -1)
                abort();
        return cptr->alas;
}

int ac_acount(aClient *cptr)
{
        if(cptr->fd == -1)
                abort();
        return cptr->acount;
}

#endif

char *ac_sockhost(aClient *cptr)
{
        if(cptr->fd == -1)
                abort();
        return cptr->sockhost;
}

char *ac_passwd(aClient *cptr)
{
        if(cptr->fd == -1)
                abort();
        return cptr->passwd;
}

int ac_oflag(aClient *cptr)
{
        if(cptr->fd == -1)
                abort();
        return cptr->oflag;
}

int ac_sockerr(aClient *cptr)
{
        if(cptr->fd == -1)
                abort();
        return cptr->sockerr;
}

int ac_capabilities(aClient *cptr)
{
        if(cptr->fd == -1)
                abort();
        return cptr->capabilities;
}

int ac_pingval(aClient *cptr)
{
        if(cptr->fd == -1)
                abort();
        return cptr->pingval;
}

int ac_sendqlen(aClient *cptr)
{
        if(cptr->fd == -1)
                abort();
        return cptr->sendqlen;
}
