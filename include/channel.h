/************************************************************************
 *   IRC - Internet Relay Chat, ircd/channel.h
 *   Copyright (C) 1990 Jarkko Oikarinen
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

#ifndef	__channel_include__
#define __channel_include__
#define find_channel(chname, chptr) (hash_find_channel(chname, chptr))
#define CREATE 1		/* whether a channel should be created or just
                                 * tested for existance */
#define MODEBUFLEN		200    /* max modebuf we consider from users */
#define REALMODEBUFLEN		512    /* max actual modebuf */
#define NullChn 		((aChannel *) NULL)
#define ChannelExists(n) 	(find_channel(n, NullChn) != NullChn)
#include "msg.h"
#define	MAXMODEPARAMS	(MAXPARA-4) /* parv[0] .. parv[3] */
#define	MAXTSMODEPARAMS	(MAXPARA-5) /* parv[0] .. parv[4] */
#define MAXMODEPARAMSUSER 6
#endif
