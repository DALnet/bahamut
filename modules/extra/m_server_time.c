/* modules/extra/m_server_time.c
 *
 * IRCv3 server-time cap + tagged delivery registration.
 * Phase 5: registers the capability and hooks server_time_tag() into the
 * outbound tag generator registry so channel/user messages carry @time=.
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "mapi.h"
#include "send.h"

static unsigned long server_time_bit = 0;

static struct mapi_cap_av1 server_time_caps[] = {
    { "server-time", NULL, &server_time_bit, NULL, NULL },
    { NULL }
};

static void
server_time_register(void)
{
    register_outbound_tag(server_time_tag, server_time_bit);
}

static void
server_time_unregister(void)
{
    unregister_outbound_tag(server_time_tag, server_time_bit);
}

DECLARE_MODULE_CAPS_RU("m_server_time", "2.0",
                       "server-time IRCv3 cap + tagged delivery",
                       0, NULL, NULL, server_time_caps,
                       server_time_register, server_time_unregister);
