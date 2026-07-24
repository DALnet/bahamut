/* modules/extra/m_account_notify.c
 *
 * IRCv3 account-notify extension.
 * When a user logs into or out of an account, all clients sharing a
 * channel with them who have this cap enabled receive:
 *   :<nick>!<user>@<host> ACCOUNT <accountname>   (login)
 *   :<nick>!<user>@<host> ACCOUNT *                (logout)
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "numeric.h"
#include "mapi.h"
#include "send.h"
#include "hooks.h"
#include "cap.h"

static unsigned long account_notify_bit = 0;

/*
 * Send ACCOUNT message to all local clients sharing a channel with sptr
 * who have the account-notify cap enabled.
 */
static void
send_account_notify(aClient *sptr, const char *acctname)
{
    Link       *lp;
    aChannel   *chptr;
    chanMember *cm;
    aClient    *target;

    if (!sptr->user)
        return;

    INC_SERIAL

    for (lp = sptr->user->channel; lp; lp = lp->next)
    {
        chptr = lp->value.chptr;
        for (cm = chptr->members; cm; cm = cm->next)
        {
            target = cm->cptr;
            if (!MyClient(target) || target == sptr)
                continue;
            if (!HasCap(target, account_notify_bit))
                continue;
            if (sentalong[target->fd] == sent_serial)
                continue;
            sentalong[target->fd] = sent_serial;

            sendto_one(target, ":%s!%s@%s ACCOUNT %s",
                       sptr->name,
                       sptr->user->username,
                       sptr->user->host,
                       acctname);
        }
    }
}

static void
hook_account_login(aClient *sptr)
{
    if (!sptr->user || !sptr->user->account_name[0])
        return;
    send_account_notify(sptr, sptr->user->account_name);
}

static void
hook_account_logout(aClient *sptr)
{
    /* On logout, account_name may already be cleared (explicit logout)
     * or still set (signoff path).  Either way, send ACCOUNT * */
    send_account_notify(sptr, "*");
}

static const struct mapi_cmd_av2 account_notify_cmds[] = {
    { NULL }
};

static const struct mapi_hook_av1 account_notify_hooks[] = {
    { CHOOK_ACCOUNT_LOGIN,  &hook_account_login  },
    { CHOOK_ACCOUNT_LOGOUT, &hook_account_logout },
    { 0, NULL }
};

static struct mapi_cap_av1 account_notify_caps[] = {
    { "account-notify", NULL, &account_notify_bit, NULL, NULL },
    { NULL }
};

DECLARE_MODULE_CAPS("m_account_notify", "1.0",
                    "IRCv3 account-notify extension",
                    0, account_notify_cmds, account_notify_hooks,
                    account_notify_caps);
