/* modules/extra/m_echo_message.c
 *
 * IRCv3 echo-message extension.
 * Registers the "echo-message" capability and echoes PRIVMSG/NOTICE
 * back to the sender with outbound tags (server-time, msgid, etc.) and
 * the @label= value when labeled-response is active.
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "mapi.h"
#include "cap.h"
#include "send.h"

static unsigned long echo_message_bit = 0;

static struct mapi_cap_av1 echo_message_caps[] = {
    { "echo-message", NULL, &echo_message_bit, NULL, NULL },
    { NULL }
};

/*
 * build_echo_tags - combine outbound tags with @label= (if present).
 * Returns a static string like "label=abc;time=...;msgid=..." or just
 * the outbound tags if no label is set.
 */
static const char *
build_echo_tags(void)
{
    static char echo_tags[512];
    const char *base = build_outbound_tags();

    if (current_dispatch_label[0])
    {
        snprintf(echo_tags, sizeof(echo_tags), "label=%s%s%s",
                 current_dispatch_label, base[0] ? ";" : "", base);
    }
    else
    {
        strncpy(echo_tags, base, sizeof(echo_tags) - 1);
        echo_tags[sizeof(echo_tags) - 1] = '\0';
    }
    return echo_tags;
}

static void
hook_chanmsg(aClient *source, aChannel *chptr, int type, char *text)
{
    const char *cmd = (type == 1) ? "NOTICE" : "PRIVMSG";

    if (!MyClient(source) || !HasCap(source, echo_message_bit))
        return;
    if (!source->user)
        return;

    if (current_dispatch_label[0])
        lr_echo_sent = 1;
    sendto_one_tags(source, build_echo_tags(),
                    ":%s!%s@%s %s %s :%s",
                    source->name, source->user->username,
                    source->user->host, cmd, chptr->chname, text);
}

static void
hook_usermsg(aClient *source, aClient *target, int type, char *text)
{
    const char *cmd = (type == 1) ? "NOTICE" : "PRIVMSG";

    if (!MyClient(source) || !HasCap(source, echo_message_bit))
        return;
    if (!source->user)
        return;

    if (current_dispatch_label[0])
        lr_echo_sent = 1;
    sendto_one_tags(source, build_echo_tags(),
                    ":%s!%s@%s %s %s :%s",
                    source->name, source->user->username,
                    source->user->host, cmd, target->name, text);
}

static const struct mapi_hook_av1 echo_message_hooks[] = {
    { CHOOK_CHANMSG, hook_chanmsg },
    { CHOOK_USERMSG, hook_usermsg },
    { 0, NULL }
};

DECLARE_MODULE_CAPS("m_echo_message", "2.0",
                    "echo-message IRCv3 extension (with label support)",
                    0, NULL, echo_message_hooks, echo_message_caps);
