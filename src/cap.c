/*
 * src/cap.c - IRCv3 capability registry for Bahamut IRC Server
 *
 * Maintains a hash table of registered capabilities and provides
 * cap_add() / cap_del() / cap_find() / cap_iterate() helpers used
 * by src/m_cap.c and src/modules.c.
 *
 * cap_init() registers the two built-in capabilities:
 *   "multi-prefix"  — no value, no callbacks
 *   "cap-notify"    — no value; on_enable fires CAP NEW for all current caps
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "mapi.h"
#include "cap.h"
#include "send.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* -----------------------------------------------------------------------
 * Internal state
 * ----------------------------------------------------------------------- */

#define CAP_HASH_SIZE  32   /* power-of-two; expected < 30 caps registered */

static struct capability *cap_table[CAP_HASH_SIZE];
static unsigned long      next_cap_bit = 0x1UL;

/* Bit reserved for cap-notify itself, populated during cap_init() */
static unsigned long cap_notify_bit = 0;

/* -----------------------------------------------------------------------
 * Hash helper
 * ----------------------------------------------------------------------- */

static unsigned int
cap_hash(const char *name)
{
    unsigned int h = 5381;
    while (*name)
        h = h * 33 ^ (unsigned char)*name++;
    return h & (CAP_HASH_SIZE - 1);
}

/* -----------------------------------------------------------------------
 * Forward declarations for internal helpers
 * ----------------------------------------------------------------------- */
static void cap_send_new(struct capability *cap);
static void cap_send_del(struct capability *cap);
static void on_enable_cap_notify(aClient *cptr);

/* -----------------------------------------------------------------------
 * cap_add() — register a capability from an av1 descriptor.
 * ----------------------------------------------------------------------- */
int
cap_add(const struct mapi_cap_av1 *av1)
{
    struct capability *cap;
    unsigned int       slot;

    if (!av1 || !av1->name || !av1->name[0])
        return -1;

    /* Duplicate check */
    if (cap_find(av1->name))
        return -1;

    /* Out of bits? (unsigned long is 64 bits on 64-bit Linux) */
    if (next_cap_bit == 0)
        return -1;   /* shifted all 64 bits through */

    cap = (struct capability *) MyMalloc(sizeof(struct capability));
    memset(cap, 0, sizeof(*cap));

    strncpy(cap->name, av1->name, sizeof(cap->name) - 1);
    if (av1->value && av1->value[0])
        strncpy(cap->value, av1->value, sizeof(cap->value) - 1);

    cap->bit        = next_cap_bit;
    cap->on_enable  = av1->on_enable;
    cap->on_disable = av1->on_disable;

    next_cap_bit <<= 1;   /* advance; wraps to 0 after 64 bits */

    /* Write the assigned bit back to the module's flag variable */
    if (av1->cap_flag)
        *av1->cap_flag = cap->bit;

    /* Insert into hash table */
    slot      = cap_hash(cap->name);
    cap->next = cap_table[slot];
    cap_table[slot] = cap;

    /* Notify cap-notify clients about the new cap */
    cap_send_new(cap);

    return 0;
}

/* -----------------------------------------------------------------------
 * cap_del() — unregister a capability.
 * Sends CAP DEL to cap-notify clients, clears the bit from every connected
 * client's cap_bits.  on_disable is NOT fired (module is already gone).
 * ----------------------------------------------------------------------- */
void
cap_del(const char *name)
{
    unsigned int       slot;
    struct capability *cap, *prev;
    aClient           *cptr;

    if (!name || !name[0])
        return;

    slot = cap_hash(name);
    prev = NULL;
    cap  = cap_table[slot];

    while (cap)
    {
        if (strcmp(cap->name, name) == 0)
            break;
        prev = cap;
        cap  = cap->next;
    }

    if (!cap)
        return;   /* not found */

    /* Unlink from hash chain */
    if (prev)
        prev->next = cap->next;
    else
        cap_table[slot] = cap->next;

    /* Send CAP DEL to cap-notify clients and clear bit from all clients */
    cap_send_del(cap);

    /* Clear the bit from every connected local client */
    for (cptr = client; cptr; cptr = cptr->next)
    {
        if (MyConnect(cptr) && (cptr->cap_bits & cap->bit))
            cptr->cap_bits &= ~cap->bit;
    }

    MyFree(cap);
}

/* -----------------------------------------------------------------------
 * cap_find() — look up by name.
 * ----------------------------------------------------------------------- */
struct capability *
cap_find(const char *name)
{
    struct capability *cap;
    unsigned int       slot;

    if (!name || !name[0])
        return NULL;

    slot = cap_hash(name);
    for (cap = cap_table[slot]; cap; cap = cap->next)
    {
        if (strcmp(cap->name, name) == 0)
            return cap;
    }
    return NULL;
}

/* -----------------------------------------------------------------------
 * cap_iterate() — call fn for every registered capability.
 * ----------------------------------------------------------------------- */
void
cap_iterate(cap_iter_fn fn, void *ud)
{
    int i;
    struct capability *cap;

    for (i = 0; i < CAP_HASH_SIZE; i++)
        for (cap = cap_table[i]; cap; cap = cap->next)
            fn(cap, ud);
}

/* -----------------------------------------------------------------------
 * Internal: send CAP * NEW :name[=value] to all cap-notify clients.
 * ----------------------------------------------------------------------- */
static void
cap_send_new(struct capability *cap)
{
    aClient *cptr;
    char     capstr[200];

    if (!cap_notify_bit)
        return;   /* cap-notify not yet registered; skip */

    if (cap->value[0])
        snprintf(capstr, sizeof(capstr), "%s=%s", cap->name, cap->value);
    else
        strncpy(capstr, cap->name, sizeof(capstr) - 1);

    for (cptr = client; cptr; cptr = cptr->next)
    {
        if (MyConnect(cptr) && HasCap(cptr, cap_notify_bit))
            sendto_one(cptr, ":%s CAP %s NEW :%s",
                       me.name,
                       *cptr->name ? cptr->name : "*",
                       capstr);
    }
}

/* -----------------------------------------------------------------------
 * Internal: send CAP * DEL :name to cap-notify clients.
 * ----------------------------------------------------------------------- */
static void
cap_send_del(struct capability *cap)
{
    aClient *cptr;

    if (!cap_notify_bit)
        return;

    for (cptr = client; cptr; cptr = cptr->next)
    {
        if (MyConnect(cptr) && HasCap(cptr, cap_notify_bit))
            sendto_one(cptr, ":%s CAP %s DEL :%s",
                       me.name,
                       *cptr->name ? cptr->name : "*",
                       cap->name);
    }
}

/* -----------------------------------------------------------------------
 * on_enable_cap_notify callback — when a client enables cap-notify, send
 * it CAP NEW for every cap currently registered.
 * ----------------------------------------------------------------------- */

struct cap_notify_ctx {
    aClient *cptr;
    /* accumulate into a line to batch-send; cap names are short so one line
     * is almost always sufficient, but we flush at BUFSIZE/2 to be safe */
    char  buf[512];
    int   len;
};

static void
cap_notify_send_one(struct capability *cap, void *ud)
{
    struct cap_notify_ctx *ctx = (struct cap_notify_ctx *) ud;
    char capstr[200];
    int  clen;

    if (cap->value[0])
        snprintf(capstr, sizeof(capstr), "%s=%s", cap->name, cap->value);
    else
        strncpy(capstr, cap->name, sizeof(capstr) - 1);

    clen = (int)strlen(capstr);

    /* Flush if adding this cap would overflow; leave room for trailing space */
    if (ctx->len + clen + 2 > (int)sizeof(ctx->buf) - 1)
    {
        if (ctx->len > 0)
        {
            sendto_one(ctx->cptr, ":%s CAP %s NEW :%s",
                       me.name,
                       *ctx->cptr->name ? ctx->cptr->name : "*",
                       ctx->buf);
        }
        ctx->len = 0;
        ctx->buf[0] = '\0';
    }

    if (ctx->len > 0)
        ctx->buf[ctx->len++] = ' ';
    memcpy(ctx->buf + ctx->len, capstr, clen);
    ctx->len += clen;
    ctx->buf[ctx->len] = '\0';
}

static void
on_enable_cap_notify(aClient *cptr)
{
    struct cap_notify_ctx ctx;

    memset(&ctx, 0, sizeof(ctx));
    ctx.cptr = cptr;

    cap_iterate(cap_notify_send_one, &ctx);

    /* Flush any remaining */
    if (ctx.len > 0)
        sendto_one(cptr, ":%s CAP %s NEW :%s",
                   me.name,
                   *cptr->name ? cptr->name : "*",
                   ctx.buf);
}

/* -----------------------------------------------------------------------
 * cap_init() — register built-in caps.
 * Called from ircd.c after init_modules().
 * ----------------------------------------------------------------------- */

unsigned long cap_multi_prefix_bit      = 0;
unsigned long cap_userhost_in_names_bit = 0;  /* set when m_userhost_in_names loads */
unsigned long cap_extended_join_bit     = 0;  /* set when m_extended_join loads */

static struct mapi_cap_av1 builtin_multi_prefix = {
    "multi-prefix", NULL, &cap_multi_prefix_bit, NULL, NULL
};

static unsigned long cap_notify_flag_storage = 0;
static const struct mapi_cap_av1 builtin_cap_notify = {
    "cap-notify", NULL, &cap_notify_flag_storage, on_enable_cap_notify, NULL
};

void
cap_init(void)
{
    cap_add(&builtin_multi_prefix);
    cap_add(&builtin_cap_notify);
    /* Store the bit so cap_send_new/del can use it */
    cap_notify_bit = cap_notify_flag_storage;
}
