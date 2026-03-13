/* modules/core/m_gossip.c
 *
 * Phase S2: Gossip Multi-Uplink — wire protocol command handlers.
 *
 * Commands: GHELLO, GSYNCING, GSYNCED, GEVENT, GACK, GPING, GPONG
 *
 * All commands are accessible from unregistered connections (pre-GHELLO)
 * or from registered gopeer connections.  They are NOT accessible from
 * regular clients.
 *
 * Wire format:
 *   GHELLO   <server-name> <server-id> <version>
 *   GSYNCING <server-name> <clock-b64>
 *   GSYNCED  <server-name>
 *   GEVENT   <type> :<payload>    (tagged: @gossip-id=S:seq;gossip-clock=b64)
 *   GACK     <server> <seq>
 *   GPING    :<nonce>
 *   GPONG    :<nonce>
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "mapi.h"
#include "send.h"
#include "gossip_event.h"
#include "eventlog.h"
#include "gossip_peer.h"
#include "gossip_dedup.h"
#include "gossip.h"
#include "gossip_bridge.h"
#include "hooks.h"

/* -------------------------------------------------------------------------
 * GHELLO — initial handshake
 *
 * Server-to-server: :<name> GHELLO <server-name> <server-id> <version>
 *
 * On receipt, if we accept the peer:
 *   1. Send our own GHELLO
 *   2. Set cptr status to STAT_GOPEER
 *   3. Start burst exchange (gopeer_start_burst)
 * ---------------------------------------------------------------------- */

static int
ms_ghello(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr,
          int parc, char *parv[])
{
    const char *peer_name    = parv[1];
    int         peer_id_raw  = atoi(parv[2]);
    /* parv[3] is version string — ignore for now */

    if (peer_id_raw < 0 || peer_id_raw > 63)
    {
        sendto_one(cptr, "ERROR :Invalid server_id %d (must be 0-63)", peer_id_raw);
        return exit_client(cptr, cptr, &me, "Invalid server_id");
    }

    if (IsGoPeer(cptr))
    {
        /* Already registered — ignore duplicate GHELLO */
        return 0;
    }

    /* Reject if we already have a connection to this peer (prevents
     * duplicate links when both sides initiate outbound connections) */
    if (gopeer_is_connected(peer_name))
    {
        sendto_one(cptr, "ERROR :Already connected to %s", peer_name);
        return exit_client(cptr, cptr, &me, "Duplicate gossip peer");
    }

    /* Accept the peer */
    SetGoPeer(cptr);
    gopeer_attach(cptr, (ServerId)peer_id_raw, peer_name);
    cptr->capabilities |= CAPAB_GOSSIP;

    sendto_realops("Gossip peer %s (id=%d) established", peer_name, peer_id_raw);

    /* Phase S3: introduce this gossip peer to any connected legacy servers */
    bridge_introduce_server(peer_name);

    /* Emit server link event */
    {
        EvPayloadServerLink pl;
        memset(&pl, 0, sizeof(pl));
        strncpy(pl.name, peer_name, HOSTLEN);
        pl.id = (ServerId)peer_id_raw;
        emit_event(EVT_SERVER_LINK, &pl, sizeof(pl));
    }

    /* Send our GHELLO back if this was an inbound connection */
    if (MyConnect(cptr) && cptr->fd >= 0)
        sendto_one(cptr, ":%s GHELLO %s %u 1",
                   me.name, me.name,
                   (unsigned)g_event_log.my_id);

    /* Start burst */
    gopeer_start_burst(cptr);

    return 0;
}

/* -------------------------------------------------------------------------
 * GSYNCING — peer is starting to send burst events
 * ---------------------------------------------------------------------- */

static int
ms_gsyncing(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr,
            int parc, char *parv[])
{
    GossipPeer *gp = (GossipPeer *)cptr->serv;

    if (!gp)
        return 0;

    /* Decode peer's clock from parv[2] (sparse format) */
    if (parc >= 3 && parv[2] && parv[2][0])
        clock_decode_sparse(&gp->peer_clock, parv[2]);

    sendto_realops("Gossip peer %s is syncing...", gp->name);
    return 0;
}

/* -------------------------------------------------------------------------
 * GSYNCED — peer has finished sending burst
 * ---------------------------------------------------------------------- */

static int
ms_gsynced(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr,
           int parc, char *parv[])
{
    GossipPeer *gp = (GossipPeer *)cptr->serv;

    if (!gp)
        return 0;

    gp->burst_complete = 1;
    gopeer_connected_count++;
    sendto_realops("Gossip peer %s sync complete", gp->name);
    return 0;
}

/* -------------------------------------------------------------------------
 * GEVENT — receive a gossip event
 *
 * @gossip-id=<server>:<seq>;gossip-clock=<b64> :<origin> GEVENT <type> :<payload>
 * ---------------------------------------------------------------------- */

static int
ms_gevent(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr,
          int parc, char *parv[])
{
    const char  *type_str  = parv[1];
    const char  *payload   = parc >= 3 ? parv[2] : "";
    NetEventType type;
    ServerId     origin_id  = g_event_log.my_id;
    LocalSeq     origin_seq = 0;
    EventClock   clock;
    NetworkEvent ev;
    const char  *id_tag, *clock_tag, *ver_tag;

    type = (NetEventType)atoi(type_str);
    if (type <= 0)
        return 0;

    /* Extract @gossip-id, @gossip-clock, and @gossip-ver from MsgBuf tags */
    memset(&clock, 0, sizeof(clock));
    id_tag    = msgbuf ? msgbuf_get_tag(msgbuf, "gossip-id")    : NULL;
    clock_tag = msgbuf ? msgbuf_get_tag(msgbuf, "gossip-clock") : NULL;
    ver_tag   = msgbuf ? msgbuf_get_tag(msgbuf, "gossip-ver")   : NULL;

    if (id_tag)
    {
        /* Parse "server:seq" */
        char  idbuf[64];
        char *colon;
        strncpy(idbuf, id_tag, sizeof(idbuf) - 1);
        colon = strchr(idbuf, ':');
        if (colon)
        {
            *colon     = '\0';
            origin_id  = (ServerId)atoi(idbuf);
            origin_seq = (LocalSeq)strtoull(colon + 1, NULL, 10);
        }
    }

    if (clock_tag)
        clock_decode_sparse(&clock, clock_tag);

    /* Dedup check */
    if (dedup_check_and_set(origin_id, origin_seq))
        return 0;   /* already seen */

    /* Parse gossip-ver tag for services event versioning */
    ev.record_version = 0;
    if (ver_tag)
        ev.record_version = (uint64_t)strtoull(ver_tag, NULL, 10);

    /* Parse payload */
    if (gossip_parse_event(&ev, type, payload, origin_id, origin_seq, &clock) < 0)
        return 0;

    /* Apply event to local state */
    gossip_apply_event(&ev);

    /* Phase S3: translate event to legacy TS5 commands for legacy servers */
    bridge_apply_event(&ev);

    /* Forward to other peers (fanout) */
    gossip_event(&ev, cptr);

    return 0;
}

/* -------------------------------------------------------------------------
 * GACK — acknowledge receipt of events up to <seq>
 * ---------------------------------------------------------------------- */

static int
ms_gack(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr,
        int parc, char *parv[])
{
    GossipPeer *gp      = (GossipPeer *)cptr->serv;
    ServerId    server  = (ServerId)atoi(parv[1]);
    LocalSeq    seq     = (LocalSeq)strtoull(parv[2], NULL, 10);

    if (!gp)
        return 0;

    if (server < VC_SLOTS && seq > gp->peer_clock.slot[server])
        gp->peer_clock.slot[server] = seq;

    return 0;
}

/* -------------------------------------------------------------------------
 * GPING / GPONG — keepalive
 * ---------------------------------------------------------------------- */

static int
ms_gping(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr,
         int parc, char *parv[])
{
    const char *nonce = parc >= 2 ? parv[1] : "";
    sendto_one(cptr, ":%s GPONG :%s", me.name, nonce);
    return 0;
}

static int
ms_gpong(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr,
         int parc, char *parv[])
{
    GossipPeer *gp = (GossipPeer *)cptr->serv;
    if (gp)
        gp->last_ping = time(NULL);
    return 0;
}

/* -------------------------------------------------------------------------
 * Command table
 * ---------------------------------------------------------------------- */

static const struct mapi_cmd_av2 gossip_cmds[] = {
    { "GHELLO",   0, {
        { ms_ghello,   3 },   /* UNREG  — handshake before registration */
        { mg_ignore,   0 },   /* CLIENT */
        { mg_ignore,   0 },   /* REMOTE */
        { ms_ghello,   3 },   /* SERVER */
        { mg_ignore,   0 },   /* OPER   */
    }},
    { "GSYNCING", 0, {
        { mg_ignore,   0 },   /* UNREG  */
        { mg_ignore,   0 },   /* CLIENT */
        { mg_ignore,   0 },   /* REMOTE */
        { ms_gsyncing, 2 },   /* SERVER / GOPEER */
        { mg_ignore,   0 },   /* OPER   */
    }},
    { "GSYNCED",  0, {
        { mg_ignore,   0 },
        { mg_ignore,   0 },
        { mg_ignore,   0 },
        { ms_gsynced,  2 },
        { mg_ignore,   0 },
    }},
    { "GEVENT",   0, {
        { mg_ignore,   0 },
        { mg_ignore,   0 },
        { mg_ignore,   0 },
        { ms_gevent,   2 },
        { mg_ignore,   0 },
    }},
    { "GACK",     0, {
        { mg_ignore,   0 },
        { mg_ignore,   0 },
        { mg_ignore,   0 },
        { ms_gack,     3 },
        { mg_ignore,   0 },
    }},
    { "GPING",    0, {
        { mg_ignore,   0 },
        { mg_ignore,   0 },
        { mg_ignore,   0 },
        { ms_gping,    1 },
        { mg_ignore,   0 },
    }},
    { "GPONG",    0, {
        { mg_ignore,   0 },
        { mg_ignore,   0 },
        { mg_ignore,   0 },
        { ms_gpong,    1 },
        { mg_ignore,   0 },
    }},
    { NULL }
};

/* -------------------------------------------------------------------------
 * CHOOK_10SEC — periodic gopeer reconnection
 * ---------------------------------------------------------------------- */

static int
hook_10sec(int hooktype, void *data)
{
    gopeer_try_connect();
    return 0;
}

static const struct mapi_hook_av1 gossip_hooks[] = {
    { CHOOK_10SEC, &hook_10sec },
    { 0, NULL }
};

DECLARE_CORE_MODULE("m_gossip", "1.0",
                    "Phase S2: gossip S2S protocol commands",
                    gossip_cmds, gossip_hooks);
