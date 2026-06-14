/* modules/extra/m_chghost.c
 *
 * IRCv3 chghost extension.
 * Notifies cap-enabled channel members when a user's visible host changes
 * (via SVSHOST).  Sends ":nick!olduser@oldhost CHGHOST newuser newhost".
 *
 * Pattern follows m_away_notify.c (iterate channels, dedup with INC_SERIAL).
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "mapi.h"
#include "cap.h"
#include "send.h"

static unsigned long chghost_bit = 0;

static struct mapi_cap_av1 chghost_caps[] = {
    { "chghost", NULL, &chghost_bit, NULL, NULL },
    { NULL }
};

static void
hook_chghost(aClient *sptr, const char *old_user, const char *old_host)
{
    Link       *lp;
    aChannel   *chptr;
    chanMember *member;
    const char *new_user;
    const char *new_host;

    if (!sptr->user)
        return;

    new_user = sptr->user->username;
#ifdef USER_HOSTMASKING
    new_host = sptr->user->mhost;
#else
    new_host = sptr->user->host;
#endif

    INC_SERIAL

    /* Notify the user themselves if they have the cap */
    if (MyClient(sptr) && HasCap(sptr, chghost_bit))
    {
        sentalong[sptr->fd] = sent_serial;
        sendto_one(sptr, ":%s!%s@%s CHGHOST %s %s",
                   sptr->name, old_user, old_host,
                   new_user, new_host);
    }

    for (lp = sptr->user->channel; lp; lp = lp->next)
    {
        chptr = lp->value.chptr;
        for (member = chptr->members; member; member = member->next)
        {
            aClient *target = member->cptr;

            if (!MyClient(target))
                continue;
            if (!HasCap(target, chghost_bit))
                continue;
            if (sentalong[target->fd] == sent_serial)
                continue;
            sentalong[target->fd] = sent_serial;

            sendto_one(target, ":%s!%s@%s CHGHOST %s %s",
                       sptr->name, old_user, old_host,
                       new_user, new_host);
        }
    }
}

static const struct mapi_hook_av1 chghost_hooks[] = {
    { CHOOK_CHGHOST, hook_chghost },
    { 0, NULL }
};

DECLARE_MODULE_CAPS("m_chghost", "1.0",
                    "IRCv3 chghost extension",
                    0, NULL, chghost_hooks, chghost_caps);
