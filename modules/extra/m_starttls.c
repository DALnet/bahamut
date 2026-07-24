/*
 * modules/extra/m_starttls.c
 *
 * IRCv3 STARTTLS — mid-stream TLS upgrade for plaintext connections.
 *
 * Registers the "tls" CAP (boolean) and the STARTTLS command.
 * Only works pre-registration; already-TLS or already-registered
 * clients receive an error.
 *
 * On success, sets FLAGS_PENDTLS. The main I/O loop (s_bsd.c)
 * detects this flag and initiates the SSL handshake before reading
 * further data.
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "numeric.h"
#include "mapi.h"
#include "send.h"
#include "cap.h"

extern int ssl_capable;

static unsigned long tls_cap_bit = 0;

static int
m_starttls(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr,
           int parc, char *parv[])
{
    const char *nick = sptr->name[0] ? sptr->name : "*";

    if (IsSSL(sptr))
    {
        sendto_one(sptr, getreply(ERR_STARTTLS), me.name, nick);
        return 0;
    }

    if (!ssl_capable)
    {
        sendto_one(sptr, getreply(ERR_STARTTLS), me.name, nick);
        return 0;
    }

    sendto_one(sptr, getreply(RPL_STARTTLS), me.name, nick);
    sptr->flags |= FLAGS_PENDTLS;

    return 0;
}

static const struct mapi_cmd_av2 starttls_cmds[] = {
    { "STARTTLS", 0, {
        { m_starttls, 1 },   /* HANDLER_UNREG   — pre-registration only */
        { mg_reg,     0 },   /* HANDLER_CLIENT  — too late */
        { mg_ignore,  0 },   /* HANDLER_REMOTE  */
        { mg_ignore,  0 },   /* HANDLER_SERVER  */
        { mg_reg,     0 },   /* HANDLER_OPER    — too late */
    }},
    { NULL }
};

static struct mapi_cap_av1 starttls_caps[] = {
    { "tls", NULL, &tls_cap_bit, NULL, NULL },
    { NULL }
};

DECLARE_MODULE_CAPS("m_starttls", "1.0",
                    "IRCv3 STARTTLS mid-stream TLS upgrade",
                    0, starttls_cmds, NULL, starttls_caps);
