#ifndef IRCSPRINTF_H
#define IRCSPRINTF_H
#include <stdarg.h>
#include <stdio.h>

int ircsprintf(char *str, const char *format, ...);
int ircsnprintf(char *str, size_t size, const char *format, ...);
int ircvsprintf(char *str, const char *format, va_list ap);
int ircvsnprintf(char *str, size_t size, const char *format, va_list ap);
int irc_printf(char *buf, size_t size, const char *format, va_list ap);
#endif
