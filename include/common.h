/************************************************************************
 *   IRC - Internet Relay Chat, include/common.h
 *   Copyright (C) 1990 Armin Gruner
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

#ifndef	__common_include__
#define __common_include__
#define IRCD_MIN(a, b)  ((a) < (b) ? (a) : (b))
#if defined( HAVE_PARAM_H )
#include <sys/param.h>
#endif
#ifndef NULL
#define NULL 0
#endif
#ifdef TRUE
#undef TRUE
#endif
#ifdef FALSE
#undef FALSE
#endif
#define FALSE (0)
#define TRUE  (!FALSE)
#define HIDEME 2
/* Blah. I use these a lot. -Dianora */
#ifdef YES
#undef YES
#endif
#define YES 1
#ifdef NO
#undef NO
#endif
#define NO  0
#ifdef FOREVER
#undef FOREVER
#endif
#define FOREVER for(;;)
/* -Dianora */
#if !defined(STDC_HEADERS)
char        *malloc(), *calloc();
void        free();
#else
#ifdef MALLOCH
#include MALLOCH
#endif
#endif
extern void flush_fdlist_connections();
extern int  match(char *, char *);
extern int  mycmp(char *, char *);
extern int  mycmp_diff(char *, char *);
extern int  myncmp(char *, char *, int);
#if !defined( HAVE_STRTOK )
extern char *strtok(char *, char *);
#endif
#if !defined( HAVE_STRTOKEN )
extern char *strtoken(char **, char *, char *);
#endif
#if !defined( HAVE_INET_ADDR )
extern unsigned long inet_addr(char *);
#endif
#if !defined(HAVE_INET_NTOA) || !defined(HAVE_INET_NETOF)
#include <netinet/in.h>
#endif
#if !defined( HAVE_INET_NTOA )
extern char *inet_ntoa(struct in_addr);
#endif
#if !defined( HAVE_INET_NETOF )
extern int  inet_netof(struct in_addr);
#endif
extern char *myctime(time_t);
extern char *strtoken(char **, char *, char *);
#if !defined(HAVE_MINMAX)
#ifndef MAX
#define MAX(a, b)	((a) > (b) ? (a) : (b))
#endif
#ifndef MIN
#define MIN(a, b)	((a) < (b) ? (a) : (b))
#endif
#endif /* !HAVE_MINMAX */
#define DupString(x,y) do{x=MyMalloc(strlen(y)+1);(void)strcpy(x,y);}while(0)
extern unsigned char tolowertab[];
#undef tolower
#define tolower(c) (tolowertab[(u_char)(c)])
extern unsigned char touppertab[];
#undef toupper
#define toupper(c) (touppertab[(u_char)(c)])
#undef isalpha
#undef isdigit
#undef isxdigit
#undef isalnum
#undef isprint
#undef isascii
#undef isgraph
#undef ispunct
#undef islower
#undef isupper
#undef isspace
#undef iscntrl
extern unsigned char char_atribs[];
#define PRINT 1
#define CNTRL 2
#define ALPHA 4
#define PUNCT 8
#define DIGIT 16
#define SPACE 32
#define	iscntrl(c) (char_atribs[(u_char)(c)]&CNTRL)
#define isalpha(c) (char_atribs[(u_char)(c)]&ALPHA)
#define isspace(c) (char_atribs[(u_char)(c)]&SPACE)
#define islower(c) ((char_atribs[(u_char)(c)]&ALPHA) && ((u_char)(c) > 0x5f))
#define isupper(c) ((char_atribs[(u_char)(c)]&ALPHA) && ((u_char)(c) < 0x60))
#define isdigit(c) (char_atribs[(u_char)(c)]&DIGIT)
#define	isxdigit(c) (isdigit(c) || 'a' <= (c) && (c) <= 'f' || \
                      'A' <= (c) && (c) <= 'F')
#define isalnum(c) (char_atribs[(u_char)(c)]&(DIGIT|ALPHA))
#define isprint(c) (char_atribs[(u_char)(c)]&PRINT)
#define isascii(c) ((u_char)(c) >= 0 && (u_char)(c) <= 0x7f)
#define isgraph(c) ((char_atribs[(u_char)(c)]&PRINT) && ((u_char)(c) != 0x32))
#define ispunct(c) (!(char_atribs[(u_char)(c)]&(CNTRL|ALPHA|DIGIT)))
extern struct SLink *find_user_link();
#endif /* common_include */
