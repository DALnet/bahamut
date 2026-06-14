/* modules/extra/m_invite_notify.c
 *
 * IRCv3 invite-notify extension.
 * Registers the "invite-notify" capability.  When someone is invited to a
 * channel, all members who have the cap enabled receive an INVITE message
 * from the server, not just the target.
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "mapi.h"
#include "cap.h"
#include "send.h"

static unsigned long invite_notify_bit = 0;

static struct mapi_cap_av1 invite_notify_caps[] = {
    { "invite-notify", NULL, &invite_notify_bit, NULL, NULL },
    { NULL }
};

static void
hook_invite(aClient *inviter, aClient *target, aChannel *chptr)
{
    chanMember *cm;

    if (!chptr || !inviter->user)
        return;

    INC_SERIAL

    for (cm = chptr->members; cm; cm = cm->next)
    {
        aClient *member = cm->cptr;

        if (!MyClient(member))
            continue;
        if (!HasCap(member, invite_notify_bit))
            continue;
        if (sentalong[member->fd] == sent_serial)
            continue;
        sentalong[member->fd] = sent_serial;

        sendto_one(member, ":%s!%s@%s INVITE %s :%s",
                   inviter->name, inviter->user->username,
                   inviter->user->host, target->name, chptr->chname);
    }
}

static const struct mapi_hook_av1 invite_notify_hooks[] = {
    { CHOOK_INVITE, hook_invite },
    { 0, NULL }
};

DECLARE_MODULE_CAPS("m_invite_notify", "1.0",
                    "invite-notify IRCv3 extension",
                    0, NULL, invite_notify_hooks, invite_notify_caps);
