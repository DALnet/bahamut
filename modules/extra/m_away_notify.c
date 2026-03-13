/* modules/extra/m_away_notify.c
 *
 * IRCv3 away-notify extension.
 * Registers the "away-notify" capability and notifies cap-enabled channel
 * members when a local client sets or clears their away status.
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "mapi.h"
#include "cap.h"
#include "send.h"

static unsigned long away_notify_bit = 0;

static struct mapi_cap_av1 away_notify_caps[] = {
    { "away-notify", NULL, &away_notify_bit, NULL, NULL },
    { NULL }
};

static void
hook_away(aClient *sptr, int setting, char *message)
{
    Link       *lp;
    aChannel   *chptr;
    chanMember *member;

    if (!MyClient(sptr) || !sptr->user)
        return;

    INC_SERIAL

    for (lp = sptr->user->channel; lp; lp = lp->next)
    {
        chptr = lp->value.chptr;
        for (member = chptr->members; member; member = member->next)
        {
            aClient *target = member->cptr;

            if (!MyClient(target) || target == sptr)
                continue;
            if (!HasCap(target, away_notify_bit))
                continue;
            if (sentalong[target->fd] == sent_serial)
                continue;
            sentalong[target->fd] = sent_serial;

            if (setting && message && *message)
                sendto_one(target, ":%s!%s@%s AWAY :%s",
                           sptr->name, sptr->user->username,
                           sptr->user->host, message);
            else
                sendto_one(target, ":%s!%s@%s AWAY",
                           sptr->name, sptr->user->username,
                           sptr->user->host);
        }
    }
}

static const struct mapi_hook_av1 away_notify_hooks[] = {
    { CHOOK_AWAY, hook_away },
    { 0, NULL }
};

DECLARE_MODULE_CAPS("m_away_notify", "1.0",
                    "away-notify IRCv3 extension",
                    0, NULL, away_notify_hooks, away_notify_caps);
