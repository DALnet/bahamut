/* modules/extra/m_userhost_in_names.c
 *
 * IRCv3 userhost-in-names extension.
 * Registers the "userhost-in-names" capability.  When a client enables this
 * cap, RPL_NAMREPLY entries are sent as "nick!user@host" instead of "nick".
 * The actual NAMES output change is in src/channel.c (m_names); it checks
 * HasCap(sptr, cap_userhost_in_names_bit).
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "mapi.h"
#include "cap.h"

/* Defined in src/cap.c so channel.c (ircd binary) can reference it */
extern unsigned long cap_userhost_in_names_bit;

static struct mapi_cap_av1 uhin_caps[] = {
    { "userhost-in-names", NULL, &cap_userhost_in_names_bit, NULL, NULL },
    { NULL }
};

DECLARE_MODULE_CAPS("m_userhost_in_names", "1.0",
                    "userhost-in-names IRCv3 extension",
                    0, NULL, NULL, uhin_caps);
