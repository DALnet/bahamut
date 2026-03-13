/* modules/extra/m_extended_join.c
 *
 * IRCv3 extended-join extension.
 * Clients with this cap receive augmented JOIN messages:
 *   :<nick>!<user>@<host> JOIN <channel> <account> :<realname>
 * instead of the plain:
 *   :<nick> JOIN :<channel>
 *
 * The cap bit is defined in src/cap.c (cap_extended_join_bit) because
 * it is referenced from src/channel.c (core binary code).  This module
 * simply registers the cap name so clients can request it.
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "mapi.h"
#include "cap.h"

static struct mapi_cap_av1 extended_join_caps[] = {
    { "extended-join", NULL, &cap_extended_join_bit, NULL, NULL },
    { NULL }
};

DECLARE_MODULE_CAPS("m_extended_join", "1.0",
                    "IRCv3 extended-join extension",
                    0, NULL, NULL, extended_join_caps);
