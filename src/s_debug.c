/************************************************************************
 *   IRC - Internet Relay Chat, src/s_debug.c
 *   Copyright (C) 1990 Jarkko Oikarinen and
 *                      University of Oulu, Computing Center
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

#include "struct.h"
#include "patchlevel.h"
#include "blalloc.h"
/* Option string.  Must be before #ifdef DEBUGMODE.
 * I took out a lot of options that really aren't optional anymore,
 * note also that at the end we denote what our release status is
 */
char        serveropts[] =
{
#ifdef CMDLINE_CONFIG
    'C',
#endif
#ifdef DO_ID
    'd',
#endif
#ifdef DEBUGMODE
    'D',
#endif
#ifdef HUB
    'H',
#endif
#ifdef SHOW_INVISIBLE_LUSERS
    'i',
#endif
#ifndef NO_DEFAULT_INVISIBLE
    'I',
#endif
#ifdef CRYPT_OPER_PASSWORD
    'p',
#endif
#ifdef IRCII_KLUDGE
    'u',
#endif
#ifdef USE_SYSLOG
    'Y',
#endif
#ifdef USE_DRONEMODULE
    'M',
#endif
    ' ',
    'T',
    'S',
#ifdef TS_CURRENT
    '0' + TS_CURRENT,
#endif
    /* th+hybrid servers ONLY do TS */
    /* th+hybrid servers ALWAYS do TS_WARNINGS */
    'o',
    'w',
#ifdef BRANCHSTATUS
    '-', 'r', '[',
# if BRANCHSTATUS == CURRENT
    'C','U','R','R','E','N','T',
# elif BRANCHSTATUS == RELEASE
    'R','E','L','E','A','S','E',
# elif BRANCHSTATUS == STABLE
    'S','T','A','B','L','E',
# elif BRANCHSTATUS == BETA
    'B','E','T','A',
# else
    'U','N','K','N','O','W','N',
# endif
    ']',
#endif
    '\0'
};

#include "numeric.h"
#include "common.h"
#include "sys.h"
#include "hash.h"
#include <sys/file.h>
#include <sys/param.h>
#if defined( HAVE_GETRUSAGE )
#ifdef SOL20
#include <sys/time.h>
#endif
#include <sys/resource.h>
#else
#if defined( HAVE_TIMES )
#include <sys/times.h>
#endif
#endif /* HAVE_GETRUSAGE */
#include "h.h"
#include "userban.h"

#ifndef ssize_t
#define ssize_t unsigned int
#endif

#if defined(DNS_DEBUG) || defined(DEBUGMODE)
static char debugbuf[1024];

void debug(int level, char *pattern, ...)
{
    va_list      vl;
    int         err = errno;
    
    va_start(vl, pattern);
    (void) vsprintf(debugbuf, pattern, vl);
    va_end(vl);

#ifdef USE_SYSLOG
    if (level == DEBUG_ERROR)
        syslog(LOG_ERR, "%s", debugbuf);
#endif

    if ((debuglevel >= 0) && (level <= debuglevel)) {

        if (local[2]) {
            local[2]->sendM++;
            local[2]->sendB += strlen(debugbuf);
        }
        (void) fprintf(stderr, "%s", debugbuf);
        (void) fputc('\n', stderr);
    }
    errno = err;
}

#endif
