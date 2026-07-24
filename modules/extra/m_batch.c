/* modules/extra/m_batch.c
 *
 * IRCv3 batch cap registration.
 * Registers the "batch" capability.  The helper functions (batch_genref,
 * batch_start, batch_end) live in src/batch.c (ircd binary) and are
 * available to modules via dlopen symbol resolution.
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "mapi.h"

static unsigned long batch_bit = 0;

static struct mapi_cap_av1 batch_caps[] = {
    { "batch", NULL, &batch_bit, NULL, NULL },
    { NULL }
};

DECLARE_MODULE_CAPS("m_batch", "1.0",
                    "batch IRCv3 cap",
                    0, NULL, NULL, batch_caps);
