#ifndef IRCSPRINTF_H
#define IRCSPRINTF_H
#include <stdarg.h>
#include <stdio.h>
#include "setup.h"

/* define this if you intend to use ircsnprintf or ircvsnprintf */
/* It's not used, and sNprintf functions are not in all libraries */
#define WANT_SNPRINTF
#define ircsprintf sprintf
#define ircvsprintf vsprintf

#ifdef WANT_SNPRINTF
#define ircvsnprintf vsnprintf
#define ircsnprintf snprintf
#endif
/* This code contributed by Rossi 'vejeta' Marcello <vjt@users.sourceforge.net>
 * Originally in va_copy.h, however there wasnt much there, so i stuck it in
 * here.  Thanks Rossi!  -epi
 */

/* va_copy hooks for IRCd */

#if defined(__powerpc__)
# if defined(__NetBSD__)
#  define VA_COPY va_copy
# elif defined(__FreeBSD__) || defined(__linux__)
#  define VA_COPY __va_copy
# endif
#elif defined (__x86_64)
# define VA_COPY __va_copy
#else
# define VA_COPY(x, y) x = y
#endif

#endif


