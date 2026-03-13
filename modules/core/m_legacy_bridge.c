/* modules/core/m_legacy_bridge.c
 *
 * Phase S3: Legacy Bridge — CHOOK_SENDBURST hook.
 *
 * This module is loaded on "bridge servers" — gossip-capable Bahamut nodes
 * that also hold legacy TS5 C/N lines.  It intercepts the server burst hook
 * and injects current gossip state (servers, users, channels) into the burst
 * being sent to each newly connected LEGACY server.
 *
 * Gossip peers use gopeer_start_burst() directly (see s_gopeer.c), so this
 * hook is a no-op for IsGoPeer connections.
 *
 * Usage:
 *   Load this module on any server that bridges gossip ↔ legacy.
 *   Remove it from the autoload list once all servers in the network have
 *   been upgraded to gossip-only mode — no code changes required.
 *
 * DECLARE_CORE_MODULE refuses unload to prevent accidental mid-session
 * removal of the bridge during a live migration.
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "mapi.h"
#include "gossip_peer.h"
#include "gossip_bridge.h"

/* -------------------------------------------------------------------------
 * CHOOK_SENDBURST — fires at the end of do_server_estab() for each new
 * incoming server connection.
 * ---------------------------------------------------------------------- */

static void
hook_sendburst(aClient *cptr)
{
    /* Gossip peers have their own burst path (gopeer_start_burst).
     * Only inject gossip state into legacy server bursts. */
    if (IsGoPeer(cptr))
        return;

    bridge_burst_gossip_to_server(cptr);
}

/* -------------------------------------------------------------------------
 * Module declaration
 * ---------------------------------------------------------------------- */

static const struct mapi_hook_av1 bridge_hooks[] = {
    { CHOOK_SENDBURST, hook_sendburst },
    { 0, NULL }
};

DECLARE_CORE_MODULE("m_legacy_bridge", "1.0",
                    "Phase S3: gossip→legacy bridge (remove after full migration)",
                    NULL, bridge_hooks);
