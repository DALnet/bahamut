/* modules/extra/m_put.c
 *
 * PUT and POST commands — reject HTTP proxy connections.
 * Extracted from src/s_user.c.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "numeric.h"
#include "mapi.h"

static int m_put(struct MsgBuf *, aClient *, aClient *, int, char **);
static int m_post(struct MsgBuf *, aClient *, aClient *, int, char **);

static const struct mapi_cmd_av2 put_cmds[] = {
    { "PUT", 0, {                  /* accessible before registration */
        { m_put,  0 }, { m_put,  0 }, { m_put,  0 },
        { m_put,  0 }, { m_put,  0 } }},
    { "POST", 0, {
        { m_post, 0 }, { m_post, 0 }, { m_post, 0 },
        { m_post, 0 }, { m_post, 0 } }},
    { NULL }
};

DECLARE_MODULE("m_put", "2.0", "HTTP proxy rejection", 0, put_cmds, NULL);

/* used by m_put, m_post */
static int
reject_proxy(aClient *cptr, char *cmd, char *args)
{
    sendto_realops_lev(REJ_LEV, "proxy attempt from %s: %s %s",
                       cipntoa(cptr), cmd, args ? args : "");
    return exit_client(cptr, cptr, &me, "relay connection");
}

static int
m_put(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    /* HTTP PUT proxy */
    if (!IsRegistered(cptr) && cptr->receiveM == 1)
        return reject_proxy(cptr, "PUT", parv[1]);

    return 0;
}

static int
m_post(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    /* HTTP POST proxy */
    if (!IsRegistered(cptr) && cptr->receiveM == 1)
        return reject_proxy(cptr, "POST", parv[1]);

    return 0;
}
