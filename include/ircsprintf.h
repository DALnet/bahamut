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
#endif
