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

extern int ircv3_hook(enum c_ircv3_hooktype hooktype, ...);

/*
 * Methods to handle the different IRCv3 capabilities
*/

int m_awaynotify(aClient *cptr, aClient *sptr, char *away);

/* IRCv3 capabilities of the ircd or clients */
struct IRCV3Capabilities
{
    long capability;
    char *name;
    int (*func)();

};

struct IRCV3Capabilities ircv3_capabilities[] =
{
    { CAPAB_AWAYNOTIFY, CAPAB_AWAYNOTIFY_NAME, m_awaynotify },
    { CAPAB_SASL, "sasl", NULL },
    { 0, NULL }
};

enum c_ircv3_hooktype
{
    IRCV3_HOOK_AWAYNOTIFY_AWAY,
    IRCV3_HOOK_AWAYNOTIFY_BACK,
    IRCV3_HOOK_AWAYNOTIFY_JOIN,
};

#define HasCapability(x, y) ((x)->capabilities & y)

/* ircv3 capabilities */
#define WantsIRCv3(x)   ((x)->wants_ircv3_caps = 1)
#define SetAwayNotify(x) ((x)->capabilities |= CAPAB_AWAYNOTIFY)

#define HasCapabilities(x) ((x)->capabilities)


#define IsAwayNotify(x)  ((x)->capabilities & CAPAB_AWAYNOTIFY)

// Add SASL state tracking to client structure
typedef struct {
    char *mechanism;
    unsigned int state;
    time_t timeout;
} SASLState;

#define AII_SASL 7  /* Add after AII_HS which is 6 */

#endif //IRCV3
#endif //__ircv3_include__