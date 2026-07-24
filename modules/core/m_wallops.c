/* modules/core/m_wallops.c
 *
 * WALLOPS, LOCOPS, CHATOPS, GLOBOPS, GOPER, GNOTICE commands.
 * Extracted from src/s_serv.c.
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
#include "send.h"
#include "mapi.h"

static int m_wallops(struct MsgBuf *, aClient *, aClient *, int, char **);
static int m_locops(struct MsgBuf *, aClient *, aClient *, int, char **);
static int m_goper(struct MsgBuf *, aClient *, aClient *, int, char **);
static int m_gnotice(struct MsgBuf *, aClient *, aClient *, int, char **);
static int m_globops(struct MsgBuf *, aClient *, aClient *, int, char **);
static int m_chatops(struct MsgBuf *, aClient *, aClient *, int, char **);

static const struct mapi_cmd_av2 wallops_cmds[] = {
    { "WALLOPS", 0, {
        { mg_unreg,   0 }, { m_wallops,  0 }, { m_wallops,  0 },
        { m_wallops,  0 }, { m_wallops,  0 } }},
    { "LOCOPS", 0, {
        { mg_unreg,   0 }, { m_locops,   0 }, { m_locops,   0 },
        { m_locops,   0 }, { m_locops,   0 } }},
    { "CHATOPS", 0, {
        { mg_unreg,   0 }, { m_chatops,  0 }, { m_chatops,  0 },
        { m_chatops,  0 }, { m_chatops,  0 } }},
    { "GLOBOPS", 0, {
        { mg_unreg,   0 }, { m_globops,  0 }, { m_globops,  0 },
        { m_globops,  0 }, { m_globops,  0 } }},
    { "GOPER", 0, {
        { mg_unreg,   0 }, { m_goper,    0 }, { m_goper,    0 },
        { m_goper,    0 }, { m_goper,    0 } }},
    { "GNOTICE", 0, {
        { mg_unreg,   0 }, { m_gnotice,  0 }, { m_gnotice,  0 },
        { m_gnotice,  0 }, { m_gnotice,  0 } }},
    { NULL }
};

DECLARE_CORE_MODULE("m_wallops", "2.0", "WALLOPS and oper broadcasts",
                    wallops_cmds, NULL);

/*
 * m_wallops (write to *all* opers currently online)
 *      parv[0] = sender prefix
 *      parv[1] = message text
 */
static int
m_wallops(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    char *message = parc > 1 ? parv[1] : NULL;

    if (BadPtr(message))
    {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
                   me.name, parv[0], "WALLOPS");
        return 0;
    }

    if (!IsServer(sptr) && MyConnect(sptr) && !OPCanWallOps(sptr))
    {
        sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
        return 0;
    }

    sendto_wallops_butone(IsServer(cptr) ? cptr : NULL, sptr,
                          ":%s WALLOPS :%s", parv[0], message);
    return 0;
}

/*
 * m_locops (write to *all* local opers currently online)
 *      parv[0] = sender prefix
 *      parv[1] = message text
 */
static int
m_locops(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    char *message = parc > 1 ? parv[1] : NULL;

    if (BadPtr(message))
    {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
                   me.name, parv[0], "LOCOPS");
        return 0;
    }

    if (!IsServer(sptr) && MyConnect(sptr) && !OPCanLocOps(sptr))
    {
        sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
        return 0;
    }
    sendto_locops("from %s: %s", parv[0], message);
    return 0;
}

/*
 * m_goper — sort of like wallop, but only to ALL +o clients on every server.
 *      parv[0] = sender prefix
 *      parv[1] = message text
 */
static int
m_goper(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    char *message = parc > 1 ? parv[1] : NULL;

    if (BadPtr(message))
    {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
                   me.name, parv[0], "GOPER");
        return 0;
    }
    if (!IsServer(sptr) || !IsULine(sptr))
    {
        sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
        return 0;
    }

    sendto_serv_butone_super(cptr, 0, ":%s GOPER :%s", parv[0], message);
    sendto_ops("from %s: %s", parv[0], message);
    return 0;
}

/*
 * m_gnotice — sort of like wallop, but only to +g clients on this server.
 *      parv[0] = sender prefix
 *      parv[1] = message text
 */
static int
m_gnotice(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    char *message = parc > 1 ? parv[1] : NULL;

    if (BadPtr(message))
    {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
                   me.name, parv[0], "GNOTICE");
        return 0;
    }
    if (!IsServer(sptr) && MyConnect(sptr))
    {
        sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
        return 0;
    }

    sendto_serv_butone_super(cptr, 0, ":%s GNOTICE :%s", parv[0], message);
    sendto_gnotice("from %s: %s", parv[0], message);
    return 0;
}

static int
m_globops(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    char *message = parc > 1 ? parv[1] : NULL;

    if (BadPtr(message))
    {
        if (MyClient(sptr))
            sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
                       me.name, parv[0], "GLOBOPS");
        return 0;
    }

    if (MyClient(sptr) && !OPCanGlobOps(sptr))
    {
        sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
        return 0;
    }
    if (strlen(message) > TOPICLEN)
        message[TOPICLEN] = '\0';
    sendto_serv_butone_super(cptr, ULF_NOGLOBOPS, ":%s GLOBOPS :%s", parv[0], message);
    send_globops("from %s: %s", parv[0], message);
    return 0;
}

static int
m_chatops(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    char *message = parc > 1 ? parv[1] : NULL;

    if (BadPtr(message))
    {
        if (MyClient(sptr))
            sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
                       me.name, parv[0], "CHATOPS");
        return 0;
    }

    if (MyClient(sptr) && (!IsAnOper(sptr) || !SendChatops(sptr)))
    {
        sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
        return 0;
    }

    if (strlen(message) > TOPICLEN)
        message[TOPICLEN] = '\0';
    sendto_serv_butone_super(cptr, 0, ":%s CHATOPS :%s", parv[0], message);
    send_chatops("from %s: %s", parv[0], message);
    return 0;
}
