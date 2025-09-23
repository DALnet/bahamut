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


#define IRCV3_CAP_AWAYNOTIFY_NAME "away-notify"
#define IRCV3_CAP_SASL_NAME "sasl"
#define IRCV3_CAP_CAPNOTIFY_NAME "cap-notify"

/* IRCv3 capabilities of the ircd or clients */
struct IRCV3Capabilities
{
    long capability;
    char *name;
};

/* IRCv3 capability definitions - separate from Bahamut's CAPAB system */
#define IRCV3_CAP_AWAYNOTIFY 0x000100 /* away-notify support */
#define IRCV3_CAP_SASL       0x000200 /* sasl support */
#define IRCV3_CAP_CAPNOTIFY  0x000400 /* cap-notify support */

struct IRCV3Capabilities ircv3_capabilities[] =
{
    { IRCV3_CAP_AWAYNOTIFY, IRCV3_CAP_AWAYNOTIFY_NAME },
    { IRCV3_CAP_SASL, IRCV3_CAP_SASL_NAME },
    { IRCV3_CAP_CAPNOTIFY, IRCV3_CAP_CAPNOTIFY_NAME },
    { 0, NULL }
};


/* IRCv3 capability macros - separate from Bahamut's CAPAB system */
#define HasIRCV3Capability(x, y) ((x)->capabilities & y)

/* ircv3 capabilities */
#define WantsIRCv3(x)   ((x)->wants_ircv3_caps = 1)
#define SetAwayNotify(x) ((x)->capabilities |= IRCV3_CAP_AWAYNOTIFY)
#define SetSASL(x) ((x)->capabilities |= IRCV3_CAP_SASL)

#define HasIRCV3Capabilities(x) ((x)->capabilities)

#define IsAwayNotify(x)  ((x)->capabilities & IRCV3_CAP_AWAYNOTIFY)
#define IsSASL(x)        ((x)->capabilities & IRCV3_CAP_SASL)
#define IsCapNotify(x)   ((x)->capabilities & IRCV3_CAP_CAPNOTIFY)

/* cap-notify functions */
void send_cap_notify(aClient *cptr, const char *cap, const char *action);
void send_cap_new(aClient *cptr, const char *cap);
void send_cap_del(aClient *cptr, const char *cap);

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