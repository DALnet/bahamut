/* modules/extra/m_msgid.c
 *
 * IRCv3 message-ids extension.
 * Registers both "draft/message-ids" (legacy) and "msgid" (ratified) caps
 * and hooks a msgid generator into the outbound tag registry so
 * PRIVMSG/NOTICE carry a @msgid= tag.
 *
 * The msgid is cached per dispatch_serial so all recipients of a single
 * message receive the same identifier.
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "mapi.h"
#include "send.h"

static unsigned long  msgid_bit_draft = 0;   /* draft/message-ids */
static unsigned long  msgid_bit_std   = 0;   /* msgid (ratified)  */
static int            msgid_serial = -1;
static char           msgid_cache[320]; /* server name (≤63) + /ts.ms/counter */

static const char *
msgid_tag(void)
{
    static unsigned long counter = 0;
    struct timeval tv;

    if (msgid_serial == dispatch_serial)
        return msgid_cache;
    msgid_serial = dispatch_serial;

    gettimeofday(&tv, NULL);
    snprintf(msgid_cache, sizeof(msgid_cache), "msgid=%s/%ld%03d/%06lu",
             me.name, (long)tv.tv_sec, (int)(tv.tv_usec / 1000), counter++);
    return msgid_cache;
}

static void
msgid_register(void)
{
    register_outbound_tag(msgid_tag, msgid_bit_draft | msgid_bit_std);
}

static void
msgid_unregister(void)
{
    unregister_outbound_tag(msgid_tag, msgid_bit_draft | msgid_bit_std);
}

static struct mapi_cap_av1 msgid_caps[] = {
    { "draft/message-ids", NULL, &msgid_bit_draft, NULL, NULL },
    { "msgid",             NULL, &msgid_bit_std,   NULL, NULL },
    { NULL }
};

DECLARE_MODULE_CAPS_RU("m_msgid", "2.0",
                       "IRCv3 message-ids extension",
                       0, NULL, NULL, msgid_caps,
                       msgid_register, msgid_unregister);
