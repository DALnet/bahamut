/*
 * src/m_cap.c - IRCv3 CAP command handler for Bahamut IRC Server
 *
 * Compiled-in (not a loadable module) because it must be available during
 * the client registration flow (before any module is loaded) and interacts
 * directly with s_user.c / m_nick.c.
 *
 * Handles: CAP LS, CAP LIST, CAP REQ, CAP END
 *
 * Reference: https://ircv3.net/specs/extensions/capability-negotiation.html
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "msg.h"
#include "h.h"
#include "cap.h"

#include <string.h>
#include <stdlib.h>
#include <ctype.h>

/* strtoken is declared in common.h:
 *   char *strtoken(char **save, char *orig, char *sep);
 * First call: strtoken(&p, str, " ")
 * Subsequent: strtoken(&p, NULL, " ")
 */

/* register_user() is defined in s_user.c */
extern int register_user(aClient *cptr, aClient *sptr, char *nick,
                         char *username, char *hostip);

/* -----------------------------------------------------------------------
 * Helpers
 * ----------------------------------------------------------------------- */

static void
upcase(char *s)
{
    while (*s) { *s = toupper((unsigned char)*s); s++; }
}

/* -----------------------------------------------------------------------
 * CAP LS helpers
 * ----------------------------------------------------------------------- */

#define CAP_LS_LIMIT 400

struct ls_ctx {
    aClient *cptr;
    int      version;
    char     buf[512];
    int      len;
};

static void
ls_collect(struct capability *cap, void *ud)
{
    struct ls_ctx *ctx = (struct ls_ctx *)ud;
    char entry[200];
    int  elen;

    if (cap->value[0] && ctx->version >= 302)
        snprintf(entry, sizeof(entry), "%s=%s", cap->name, cap->value);
    else
        strncpy(entry, cap->name, sizeof(entry) - 1);
    entry[sizeof(entry) - 1] = '\0';

    elen = (int)strlen(entry);

    /* Flush intermediate page for CAP 302 pagination */
    if (ctx->len > 0 && ctx->len + elen + 2 > CAP_LS_LIMIT)
    {
        sendto_one(ctx->cptr, ":%s CAP %s LS * :%s",
                   me.name,
                   *ctx->cptr->name ? ctx->cptr->name : "*",
                   ctx->buf);
        ctx->len = 0;
        ctx->buf[0] = '\0';
    }

    if (ctx->len > 0)
        ctx->buf[ctx->len++] = ' ';
    memcpy(ctx->buf + ctx->len, entry, elen);
    ctx->len += elen;
    ctx->buf[ctx->len] = '\0';
}

/* -----------------------------------------------------------------------
 * CAP LIST helpers
 * ----------------------------------------------------------------------- */

struct list_ctx {
    aClient *cptr;
    char     buf[512];
    int      len;
};

static void
list_collect(struct capability *cap, void *ud)
{
    struct list_ctx *ctx = (struct list_ctx *)ud;
    int elen;

    /* Only include caps the client has enabled */
    if (!HasCap(ctx->cptr, cap->bit))
        return;

    elen = (int)strlen(cap->name);
    if (ctx->len + elen + 2 > (int)sizeof(ctx->buf) - 1)
        return;   /* shouldn't happen; buf is large enough for all caps */

    if (ctx->len > 0)
        ctx->buf[ctx->len++] = ' ';
    memcpy(ctx->buf + ctx->len, cap->name, elen);
    ctx->len += elen;
    ctx->buf[ctx->len] = '\0';
}

/* -----------------------------------------------------------------------
 * cap_cmd_ls
 * ----------------------------------------------------------------------- */

static void
cap_cmd_ls(aClient *cptr, const char *ver_str)
{
    struct ls_ctx ctx;

    if (ver_str && atoi(ver_str) >= 302)
        cptr->cap_ls_version = 302;

    cptr->cap_neg = 1;   /* delay registration until CAP END */

    memset(&ctx, 0, sizeof(ctx));
    ctx.cptr    = cptr;
    ctx.version = cptr->cap_ls_version;

    cap_iterate(ls_collect, &ctx);

    /* Flush final (or only) line — no trailing '*' means this is the last */
    sendto_one(cptr, ":%s CAP %s LS :%s",
               me.name,
               *cptr->name ? cptr->name : "*",
               ctx.buf);
}

/* -----------------------------------------------------------------------
 * cap_cmd_list
 * ----------------------------------------------------------------------- */

static void
cap_cmd_list(aClient *cptr)
{
    struct list_ctx ctx;

    memset(&ctx, 0, sizeof(ctx));
    ctx.cptr = cptr;

    cap_iterate(list_collect, &ctx);

    sendto_one(cptr, ":%s CAP %s LIST :%s",
               me.name,
               *cptr->name ? cptr->name : "*",
               ctx.buf);
}

/* -----------------------------------------------------------------------
 * cap_cmd_req
 * ----------------------------------------------------------------------- */

static void
cap_cmd_req(aClient *cptr, const char *caplist)
{
    char  work[512];
    char *tok, *saveptr;
    int   ok = 1;

    if (!caplist || !*caplist)
    {
        sendto_one(cptr, ":%s CAP %s NAK :",
                   me.name, *cptr->name ? cptr->name : "*");
        return;
    }

    /* Strip leading ':' if present (shouldn't be after parse, but be safe) */
    if (*caplist == ':')
        caplist++;

    /* First pass: validate all caps exist */
    strncpy(work, caplist, sizeof(work) - 1);
    work[sizeof(work) - 1] = '\0';

    saveptr = NULL;
    tok = strtoken(&saveptr, work, " ");
    while (tok)
    {
        const char *cname = tok;
        if (*cname == '+' || *cname == '-')
            cname++;
        if (*cname && !cap_find(cname))
        {
            ok = 0;
            break;
        }
        tok = strtoken(&saveptr, NULL, " ");
    }

    if (!ok)
    {
        sendto_one(cptr, ":%s CAP %s NAK :%s",
                   me.name,
                   *cptr->name ? cptr->name : "*",
                   caplist);
        return;
    }

    /* Second pass: apply changes and fire callbacks */
    strncpy(work, caplist, sizeof(work) - 1);
    work[sizeof(work) - 1] = '\0';

    saveptr = NULL;
    tok = strtoken(&saveptr, work, " ");
    while (tok)
    {
        int  enable = 1;
        const char *cname = tok;
        struct capability *cap;

        if (*cname == '+')       { enable = 1; cname++; }
        else if (*cname == '-')  { enable = 0; cname++; }

        if (*cname && (cap = cap_find(cname)))
        {
            if (enable)
            {
                if (!(cptr->cap_bits & cap->bit))
                {
                    cptr->cap_bits |= cap->bit;
                    if (cap->on_enable)
                        cap->on_enable(cptr);
                }
            }
            else
            {
                if (cptr->cap_bits & cap->bit)
                {
                    cptr->cap_bits &= ~cap->bit;
                    if (cap->on_disable)
                        cap->on_disable(cptr);
                }
            }
        }

        tok = strtoken(&saveptr, NULL, " ");
    }

    sendto_one(cptr, ":%s CAP %s ACK :%s",
               me.name,
               *cptr->name ? cptr->name : "*",
               caplist);
}

/* -----------------------------------------------------------------------
 * cap_cmd_end
 * ----------------------------------------------------------------------- */

static void
cap_cmd_end(aClient *cptr)
{
    cptr->cap_neg = 0;

    /* Complete registration if NICK and USER were already received */
    if (IsUnknown(cptr) && cptr->name[0] && cptr->user
        && cptr->user->username[0])
    {
        register_user(cptr, cptr, cptr->name, cptr->user->username, NULL);
    }
}

/* -----------------------------------------------------------------------
 * m_cap — main entry point
 *
 * parv[0] = sender prefix (nick or * for pre-registration)
 * parv[1] = subcommand
 * parv[2] = optional argument
 * ----------------------------------------------------------------------- */

int
m_cap(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr,
      int parc, char *parv[])
{
    char subcmd[16];

    /* CAP only applies to local connections */
    if (!MyConnect(sptr))
        return 0;

    if (parc < 2 || BadPtr(parv[1]))
    {
        sendto_one(sptr, ":%s 461 %s CAP :Not enough parameters",
                   me.name, *parv[0] ? parv[0] : "*");
        return 0;
    }

    strncpy(subcmd, parv[1], sizeof(subcmd) - 1);
    subcmd[sizeof(subcmd) - 1] = '\0';
    upcase(subcmd);

    if (strcmp(subcmd, "LS") == 0)
        cap_cmd_ls(sptr, (parc > 2 && !BadPtr(parv[2])) ? parv[2] : NULL);
    else if (strcmp(subcmd, "LIST") == 0)
        cap_cmd_list(sptr);
    else if (strcmp(subcmd, "REQ") == 0)
        cap_cmd_req(sptr, (parc > 2 && !BadPtr(parv[2])) ? parv[2] : NULL);
    else if (strcmp(subcmd, "END") == 0)
        cap_cmd_end(sptr);
    else
    {
        /* 410 ERR_INVALIDCAPCMD */
        sendto_one(sptr, ":%s 410 %s %s :Invalid CAP subcommand",
                   me.name,
                   *parv[0] ? parv[0] : "*",
                   parv[1]);
    }

    return 0;
}
