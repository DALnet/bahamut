#ifndef IRCSPRINTF_H
#define IRCSPRINTF_H
#include <stdarg.h>
#include <stdio.h>

/* define this if you intend to use ircsnprintf or ircvsnprintf */
/* It's not used, and sNprintf functions are not in all libraries */
#define WANT_SNPRINTF

int ircsprintf(char *str, const char *format, ...);
int ircvsprintf(char *str, const char *format, va_list ap);
#ifdef WANT_SNPRINTF
int ircvsnprintf(char *str, size_t size, const char *format, va_list ap);
int ircsnprintf(char *str, size_t size, const char *format, ...);
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


