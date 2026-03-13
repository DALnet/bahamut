/* modules/extra/m_account_tag.c
 *
 * IRCv3 account-tag extension.
 * Adds an "account=<name>" tag (or "account=*" if not logged in) to
 * outbound messages (PRIVMSG, NOTICE, TAGMSG, etc.) for clients that
 * have the account-tag cap enabled.
 *
 * Uses current_dispatch_source (set by parse.c) to determine the
 * sender's account name.
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "mapi.h"
#include "send.h"

static unsigned long account_tag_bit = 0;

static const char *
account_tag(void)
{
    static char cache[NICKLEN + 16]; /* "account=" + name */
    static int  cached_serial = -1;
    aClient    *sptr;

    if (cached_serial == dispatch_serial)
        return cache;
    cached_serial = dispatch_serial;

    sptr = current_dispatch_source;
    if (sptr && sptr->user && sptr->user->account_name[0])
        ircsnprintf(cache, sizeof(cache), "account=%s",
                    sptr->user->account_name);
    else
        strcpy(cache, "account=*");

    return cache;
}

static void
account_tag_register(void)
{
    register_outbound_tag(account_tag, account_tag_bit);
}

static void
account_tag_unregister(void)
{
    unregister_outbound_tag(account_tag, account_tag_bit);
}

static struct mapi_cap_av1 account_tag_caps[] = {
    { "account-tag", NULL, &account_tag_bit, NULL, NULL },
    { NULL }
};

DECLARE_MODULE_CAPS_RU("m_account_tag", "1.0",
                       "IRCv3 account-tag extension",
                       0, NULL, NULL, account_tag_caps,
                       account_tag_register, account_tag_unregister);
