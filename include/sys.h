/************************************************************************
 *   IRC - Internet Relay Chat, include/sys.h
 *   Copyright (C) 1990 University of Oulu, Computing Center
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
 */

/* $Id$ */

#ifndef	__sys_include__
#define __sys_include__
#ifdef ISC202
#include <net/errno.h>
#else
#include <sys/errno.h>
#endif
#include "setup.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>

#if defined( HAVE_UNISTD_H )
#include <unistd.h>
#endif

#if defined( HAVE_STDLIB_H )
#include <stdlib.h>
#endif

#if defined( HAVE_STRINGS_H )
#include <strings.h>
#endif

#if defined( HAVE_STRING_H )
#include <string.h>
#endif

#if defined( HAVE_LIMITS_H )
#include <limits.h>
#endif

#define	strcasecmp	mycmp
#define	strncasecmp	myncmp

#if !defined( HAVE_INDEX )
#define   index   strchr
#define   rindex  strrchr
#endif

#ifdef AIX
#include <sys/select.h>
#include <time.h>
#include <sys/time.h>
#endif

#if ((__GNU_LIBRARY__ == 6) && (__GLIBC__ >=2) && (__GLIBC_MINOR__ >= 2))
#include <time.h>
#endif

#define MyFree(x)       if ((x) != NULL) free(x)

extern void dummy();

#ifdef	NO_U_TYPES

typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned long u_long;
typedef unsigned int u_int;

#endif

#endif /* __sys_include__ */
