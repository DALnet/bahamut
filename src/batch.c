/* src/batch.c
 *
 * IRCv3 batch helper implementation.
 * Provides batch_genref(), batch_start(), and batch_end() for use by
 * modules that need to wrap responses in a BATCH envelope.
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "batch.h"
#include <stdio.h>

void
batch_genref(char *buf, size_t size)
{
    static unsigned long seq = 0;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    snprintf(buf, size, "%lx%06lx",
             (unsigned long)tv.tv_usec, ++seq & 0xFFFFFFUL);
}

void
batch_start(aClient *to, const char *ref, const char *type, const char *params)
{
    if (params && *params)
        sendto_one(to, ":%s BATCH +%s %s %s", me.name, ref, type, params);
    else
        sendto_one(to, ":%s BATCH +%s %s", me.name, ref, type);
}

void
batch_end(aClient *to, const char *ref)
{
    sendto_one(to, ":%s BATCH -%s", me.name, ref);
}
