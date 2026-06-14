/* modules/extra/m_bot_mode.c
 *
 * IRCv3 draft/bot tag extension.
 * Adds a boolean "draft/bot" tag to outbound messages when the
 * sender has user mode +B (UMODE_B, bot mode).
 *
 * Pattern follows m_tls_tag.c (boolean outbound tag).
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "mapi.h"
#include "send.h"

static unsigned long bot_tag_bit = 0;

static const char *
bot_tag(void)
{
    static const char tag_val[] = "draft/bot";
    static const char *cached;
    static int cached_serial = -1;
    aClient *sptr;

    if (cached_serial == dispatch_serial)
        return cached;
    cached_serial = dispatch_serial;

    sptr = current_dispatch_source;
    if (sptr && IsBot(sptr))
        cached = tag_val;
    else
        cached = "";

    return cached;
}

static void
bot_tag_register(void)
{
    register_outbound_tag(bot_tag, bot_tag_bit);
}

static void
bot_tag_unregister(void)
{
    unregister_outbound_tag(bot_tag, bot_tag_bit);
}

static struct mapi_cap_av1 bot_tag_caps[] = {
    { "draft/bot", NULL, &bot_tag_bit, NULL, NULL },
    { NULL }
};

DECLARE_MODULE_CAPS_RU("m_bot_mode", "1.0",
                       "IRCv3 draft/bot tag extension",
                       0, NULL, NULL, bot_tag_caps,
                       bot_tag_register, bot_tag_unregister);
