/*
 *   IRC - Internet Relay Chat, include/caps.h
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

#ifndef CAPS_H
#define CAPS_H

/*
 * IRCv3 client capabilities (CAP).
 *
 * To add a capability: define a new CAP_ bit here, add an entry to
 * clientcaps[] in caps.c, and check it with HasCap() where the
 * capability changes behavior.
 */

#define CAP_CAP_NOTIFY  (1ULL << 0)  /* cap-notify */

#define CAPF_STICKY_302 0x0001      /* cannot be disabled after CAP LS 302 */

typedef struct ClientCap aClientCap;

struct ClientCap
{
    char         *name;
    uint64_t      bit;
    char         *value;   /* advertised as name=value with CAP LS 302 */
    int           flags;
};

#define HasCap(x, c)          (MyConnect(x) && ((x)->caps & (c)))
#define IsCapNegotiating(x)   (MyConnect(x) && (x)->cap_negotiating)

extern int m_cap(aClient *, aClient *, int, char **);

#endif
