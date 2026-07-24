/* modules/extra/m_labeled_response.c
 *
 * IRCv3 labeled-response cap + ACK mechanism.
 *
 * Registers the "labeled-response" capability.  The @label= value from
 * incoming messages is extracted by parse.c into current_dispatch_label[].
 * m_echo_message.c includes the label in echo replies and sets lr_echo_sent.
 *
 * When a labeled command completes without an echo being sent back to the
 * originator, this module's CHOOK_POSTDISPATCH hook sends an empty BATCH
 * envelope so the client knows the command completed:
 *
 *   @label=xxx :server BATCH +ref labeled-response
 *   :server BATCH -ref
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "mapi.h"
#include "cap.h"
#include "send.h"
#include "batch.h"

static unsigned long labeled_response_bit = 0;

static struct mapi_cap_av1 lr_caps[] = {
    { "labeled-response", NULL, &labeled_response_bit, NULL, NULL },
    { NULL }
};

static int
hook_postdispatch(aClient *sptr)
{
    char labeltag[280];
    char ref[32];

    if (!current_dispatch_label[0])
        return 0;
    if (!MyClient(sptr) || !IsRegistered(sptr))
        return 0;
    if (!HasCap(sptr, labeled_response_bit))
        return 0;
    if (lr_echo_sent)
        return 0;   /* echo already carried the label */

    snprintf(labeltag, sizeof(labeltag), "label=%s", current_dispatch_label);
    batch_genref(ref, sizeof(ref));
    sendto_one_tags(sptr, labeltag,
                    ":%s BATCH +%s labeled-response", me.name, ref);
    sendto_one(sptr, ":%s BATCH -%s", me.name, ref);
    return 0;
}

static const struct mapi_hook_av1 lr_hooks[] = {
    { CHOOK_POSTDISPATCH, hook_postdispatch },
    { 0, NULL }
};

DECLARE_MODULE_CAPS_RU("m_labeled_response", "2.0",
                       "labeled-response IRCv3 cap + ACK",
                       0, NULL, lr_hooks, lr_caps, NULL, NULL);
