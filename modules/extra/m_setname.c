/* modules/extra/m_setname.c
 *
 * IRCv3 setname extension.
 * Registers the "setname" capability and adds the SETNAME command.
 * SETNAME :new real name — updates sptr->info (the GECOS/realname field).
 * Channel members who have the cap enabled receive the SETNAME notification.
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "h.h"
#include "mapi.h"
#include "cap.h"
#include "send.h"
#include "hooks.h"

static unsigned long setname_bit = 0;

static struct mapi_cap_av1 setname_caps[] = {
    { "setname", NULL, &setname_bit, NULL, NULL },
    { NULL }
};

static int
m_setname(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr,
          int parc, char *parv[])
{
    Link       *lp;
    aChannel   *chptr;
    chanMember *cm;

    if (!MyClient(sptr) || !sptr->user)
        return 0;

    if (parc < 2 || BadPtr(parv[1]) || !*parv[1])
    {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0],
                   "SETNAME");
        return 0;
    }

    if ((int)strlen(parv[1]) > REALLEN)
    {
        sendto_one(sptr,
                   ":%s FAIL SETNAME INVALID_REALNAME :Realname is too long",
                   me.name);
        return 0;
    }

    /* Update the stored realname */
    strncpy(sptr->info, parv[1], REALLEN);
    sptr->info[REALLEN] = '\0';

    /* Confirm to the sender */
    sendto_one(sptr, ":%s!%s@%s SETNAME :%s",
               sptr->name, sptr->user->username,
               sptr->user->host, sptr->info);

    /* Notify cap-enabled channel members (dedup via sent_serial) */
    INC_SERIAL

    for (lp = sptr->user->channel; lp; lp = lp->next)
    {
        chptr = lp->value.chptr;
        for (cm = chptr->members; cm; cm = cm->next)
        {
            aClient *target = cm->cptr;

            if (!MyClient(target) || target == sptr)
                continue;
            if (!HasCap(target, setname_bit))
                continue;
            if (sentalong[target->fd] == sent_serial)
                continue;
            sentalong[target->fd] = sent_serial;

            sendto_one(target, ":%s!%s@%s SETNAME :%s",
                       sptr->name, sptr->user->username,
                       sptr->user->host, sptr->info);
        }
    }

    /* Fire hook for other modules */
    call_hooks(CHOOK_SETNAME, sptr, (const char *)sptr->info);

    return 0;
}

static const struct mapi_cmd_av2 setname_cmds[] = {
    { "SETNAME", 0, {
        { mg_unreg,  0 },   /* HANDLER_UNREG  */
        { m_setname, 2 },   /* HANDLER_CLIENT */
        { mg_ignore, 0 },   /* HANDLER_REMOTE */
        { mg_ignore, 0 },   /* HANDLER_SERVER */
        { m_setname, 2 },   /* HANDLER_OPER   */
    }},
    { NULL }
};

DECLARE_MODULE_CAPS("m_setname", "1.0",
                    "setname IRCv3 extension",
                    0, setname_cmds, NULL, setname_caps);
