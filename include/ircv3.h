/************************************************************************
 *   IRC - Internet Relay Chat, include/ircv3.h
 *   Copyright (C) 2024 Emilio Escobar
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
 *
 *
 */

#ifndef __ircv3_include__
#define __ircv3_include__
#ifdef IRCV3

#include "config.h"
#if !defined(CONFIG_H_LEVEL_184)
#error Incorrect config.h for this revision of ircd.
#endif

#include "struct.h"
#include "msg.h"
#include "sys.h"


#define CAPAB_AWAYNOTIFY_NAME "away-notify"
#define CAPAB_SASL_NAME "sasl"

/* IRCv3 capabilities of the ircd or clients */
struct IRCV3Capabilities
{
    long capability;
    char *name;

};

struct IRCV3Capabilities ircv3_capabilities[] =
{
    { CAPAB_AWAYNOTIFY, CAPAB_AWAYNOTIFY_NAME },
    { CAPAB_SASL, CAPAB_SASL_NAME },
    { 0, NULL }
};


#define HasCapability(x, y) ((x)->capabilities & y)

/* ircv3 capabilities */
#define WantsIRCv3(x)   ((x)->wants_ircv3_caps = 1)
#define SetAwayNotify(x) ((x)->capabilities |= CAPAB_AWAYNOTIFY)

#define HasCapabilities(x) ((x)->capabilities)


#define IsAwayNotify(x)  ((x)->capabilities & CAPAB_AWAYNOTIFY)

//SASL section
typedef struct {
    char ip[HOSTIPLEN + 1];
    time_t first_attempt;
    int attempts;
} SASLRateLimit;

// Add SASL state tracking to client structure
#define SASL_STATE_INIT 0
#define SASL_STATE_STARTED 1
#define SASL_STATE_AUTHENTICATED 2
#define SASL_STATE_FAILED 3

typedef struct {
    char *mechanism;
    unsigned int state;
    time_t timeout;
} SASLState;

#endif //IRCV3
#endif //__ircv3_include__