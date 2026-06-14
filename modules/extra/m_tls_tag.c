/* modules/extra/m_tls_tag.c
 *
 * IRCv3 draft/tls connection tag extension.
 * Adds a boolean "draft/tls" tag to outbound messages when the
 * sender (current_dispatch_source) is connected over TLS.
 *
 * Pattern follows m_account_tag.c exactly.
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "mapi.h"
#include "send.h"

static unsigned long tls_tag_bit = 0;

static const char *
tls_tag(void)
{
    static const char tag_val[] = "draft/tls";
    static const char *cached;
    static int cached_serial = -1;
    aClient *sptr;

    if (cached_serial == dispatch_serial)
        return cached;
    cached_serial = dispatch_serial;

    sptr = current_dispatch_source;
    if (sptr && IsUmodeS(sptr))
        cached = tag_val;
    else
        cached = "";

    return cached;
}

static void
tls_tag_register(void)
{
    register_outbound_tag(tls_tag, tls_tag_bit);
}

static void
tls_tag_unregister(void)
{
    unregister_outbound_tag(tls_tag, tls_tag_bit);
}

static struct mapi_cap_av1 tls_tag_caps[] = {
    { "draft/tls", NULL, &tls_tag_bit, NULL, NULL },
    { NULL }
};

DECLARE_MODULE_CAPS_RU("m_tls_tag", "1.0",
                       "IRCv3 draft/tls connection tag",
                       0, NULL, NULL, tls_tag_caps,
                       tls_tag_register, tls_tag_unregister);
