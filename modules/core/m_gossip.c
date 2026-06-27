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
 *   GHELLO   <server-name> <version> [:<secret>]   (name IS the identity)
 *   GSYNCING <server-name> <clock-sparse>
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
#include "gossip_idmap.h"
#include "eventlog.h"
#include "gossip_peer.h"
#include "gossip_dedup.h"
#include "gossip.h"
#include "gossip_bridge.h"
#include "hooks.h"

extern char *crypt();   /* libc; see s_user.c oper password check */

/* ct_streq — constant-time string equality, so the cleartext-secret compare
 * doesn't leak the secret prefix via strcmp's early-exit timing.  Length
 * mismatch fails without scanning the longer string. */
static int
ct_streq(const char *a, const char *b)
{
    size_t la = strlen(a), lb = strlen(b), n = (la < lb) ? la : lb, i;
    volatile unsigned char diff = (la == lb) ? 0 : 1;

    for (i = 0; i < n; i++)
        diff |= (unsigned char)(a[i] ^ b[i]);
    return diff == 0;
}

/* -------------------------------------------------------------------------
 * gopeer_secret_ok — verify a peer-supplied link secret against a configured
 * gopeer{} password.
 *
 * The secret always travels in cleartext (over TLS); FLAGS_CRYPTPASS only
 * governs how it is stored AT REST.  So accept either form transparently:
 *   1. cleartext-at-rest  → direct constant-time compare;
 *   2. crypt(3)-at-rest   → crypt the supplied secret with the stored hash
 *                           (salt = first two chars) and compare, as the oper
 *                           password check does (s_user.c).
 * Trying the cleartext compare FIRST means enabling crypt_oper_pass for opers
 * never silently breaks a link whose gopeer secret is stored in cleartext (the
 * dialing side must store it plain — it has to send it).  Empty never matches.
 * ---------------------------------------------------------------------- */

static int
gopeer_secret_ok(const char *sent, const char *stored)
{
    if (!stored || !*stored || !sent || !*sent)
        return 0;

    if (ct_streq(sent, stored))
        return 1;                         /* cleartext-at-rest */

    if (confopts & FLAGS_CRYPTPASS)
    {
        char *encr = crypt((char *)sent, (char *)stored);
        if (encr && ct_streq(encr, stored))
            return 1;                     /* crypt(3)-at-rest */
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * GHELLO — initial handshake
 *
 * Server-to-server: GHELLO <server-name> <version> [:<secret>]
 * (the server NAME is the identity — no numeric server-id on the wire, #260)
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
    const char *peer_name = parv[1];
    /* parv[2] is the version string — ignored.  There is no numeric server id
     * on the wire any more: the NAME is the identity (issue #260). */

    if (IsGoPeer(cptr))
    {
        /* Already registered — ignore duplicate GHELLO */
        return 0;
    }

    /* ---- Authentication (fail-closed for inbound peers) ----------------
     * Distinguish the two handshake directions by a server-controlled fact —
     * whether WE dialed this connection out (gopeer_is_outbound, an fd-indexed
     * flag set in gopeer_try_connect).  This must NOT key on cptr->name: an
     * unregistered inbound client can pre-set its name via NICK and would
     * otherwise be mistaken for a trusted dialer, bypassing the whole check.
     *   - We dialed OUT (gopeer_is_outbound): this GHELLO is the listener's
     *     reply; we already proved ourselves and trust the link (we chose the
     *     host, over TLS), so no secret is required here.
     *   - INBOUND (not our dial): we MUST authenticate it — require TLS, a
     *     matching gopeer{} block with a passwd, and a correct shared secret
     *     (parv[3]).  This is what closes the open-mesh hole; it also forces a
     *     legacy TS5 link that happens to share a gopeer{} name to present the
     *     gossip secret before it can join the mesh.
     */
    if (!gopeer_is_outbound(cptr->fd))
    {
        aGoPeerConf *conf;
        const char  *secret = (parc >= 4 && parv[3]) ? parv[3] : "";

        if (!IsSSL(cptr))
        {
            sendto_realops("Gossip: rejected peer %s [%s] — TLS required",
                           peer_name, cptr->sockhost);
            sendto_one(cptr, "ERROR :gossip link requires TLS");
            return exit_client(cptr, cptr, &me, "Gossip requires TLS");
        }

        conf = gopeer_find_conf(peer_name);
        if (!conf || !conf->password || !conf->password[0])
        {
            sendto_realops("Gossip: rejected unauthorized peer %s [%s] "
                           "(no matching gopeer{} block)",
                           peer_name, cptr->sockhost);
            sendto_one(cptr, "ERROR :unauthorized gossip peer");
            return exit_client(cptr, cptr, &me, "Unauthorized gossip peer");
        }

        if (!gopeer_secret_ok(secret, conf->password))
        {
            sendto_realops("Gossip: rejected peer %s [%s] — bad link password",
                           peer_name, cptr->sockhost);
            sendto_one(cptr, "ERROR :bad gossip link password");
            return exit_client(cptr, cptr, &me, "Bad gossip link password");
        }
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
    gopeer_attach(cptr, peer_name);
    cptr->capabilities |= CAPAB_GOSSIP;

    sendto_realops("Gossip peer %s established", peer_name);

    /* Phase S3: introduce this gossip peer to any connected legacy servers */
    bridge_introduce_server(peer_name);

    /* Emit server link event */
    {
        EvPayloadServerLink pl;
        memset(&pl, 0, sizeof(pl));
        strncpy(pl.name, peer_name, HOSTLEN);
        emit_event(EVT_SERVER_LINK, &pl, sizeof(pl));
    }

    /* Send our GHELLO back if this was an inbound connection */
    if (MyConnect(cptr) && cptr->fd >= 0)
        sendto_one(cptr, ":%s GHELLO %s 1", me.name, me.name);

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

    /* Guard against a duplicate GSYNCED inflating the connected count:
     * gopeer_connected_count feeds gossip_is_partitioned(), and the
     * matching decrement in gopeer_handle_disconnect() runs only once. */
    if (!gp->burst_complete)
    {
        gp->burst_complete = 1;
        gopeer_connected_count++;
    }
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
        /* Parse "name:seq" — the origin is a server NAME (issue #260), mapped
         * to a local index via the registry.  Names contain no ':'. */
        char  idbuf[HOSTLEN + 32];
        char *colon;
        strncpy(idbuf, id_tag, sizeof(idbuf) - 1);
        idbuf[sizeof(idbuf) - 1] = '\0';
        colon = strchr(idbuf, ':');
        if (colon)
        {
            *colon     = '\0';
            origin_id  = srvidx_get(idbuf);
            origin_seq = (LocalSeq)strtoull(colon + 1, NULL, 10);
        }
    }

    /* If the index table is full we cannot dedup/track this origin safely —
     * drop the event rather than alias it onto another server's slot. */
    if (origin_id == SRVIDX_NONE)
        return 0;

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
 *
 * Wire: GACK <server-name> <seq> (the server is identified by name, mapped
 * to a local index — issue #260).
 * ---------------------------------------------------------------------- */

static int
ms_gack(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr,
        int parc, char *parv[])
{
    GossipPeer *gp      = (GossipPeer *)cptr->serv;
    ServerId    server  = srvidx_find(parv[1]);
    LocalSeq    seq     = (LocalSeq)strtoull(parv[2], NULL, 10);

    if (!gp)
        return 0;

    if (server < MAX_GOSSIP_SERVERS && seq > gp->peer_clock.slot[server])
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
    {
        gp->last_pong = time(NULL);
        /* The nonce is the millisecond timestamp we stamped into our GPING,
         * echoed back verbatim — so RTT = now - nonce, both on our clock
         * (no clock-skew between peers). */
        if (parc >= 2 && parv[1][0])
        {
            struct timeval tv;
            unsigned long long now_ms, sent_ms;
            gettimeofday(&tv, NULL);
            now_ms  = (unsigned long long)tv.tv_sec * 1000ULL + tv.tv_usec / 1000ULL;
            sent_ms = strtoull(parv[1], NULL, 10);
            if (sent_ms && now_ms >= sent_ms && (now_ms - sent_ms) < 600000ULL)
                gp->rtt_ms = (int)(now_ms - sent_ms);
        }
    }
    return 0;
}

/*
 * gopeer_send_pings — stamp a GPING with our current ms timestamp and send it
 * to every burst-complete gossip peer.  The peer echoes it in a GPONG, letting
 * ms_gpong() compute the round-trip time.  Called from the 10s timer.
 */
static void
gopeer_send_pings(void)
{
    DLink         *lp;
    struct timeval tv;
    char           nonce[32];

    gettimeofday(&tv, NULL);
    /* NB: standard snprintf, not ircsnprintf — the latter mishandles %llu. */
    snprintf(nonce, sizeof(nonce), "%llu",
             (unsigned long long)tv.tv_sec * 1000ULL + tv.tv_usec / 1000ULL);

    for (lp = gopeer_list; lp; lp = lp->next)
    {
        aClient    *cptr = lp->value.cptr;
        GossipPeer *gp   = cptr ? (GossipPeer *)cptr->serv : NULL;

        if (!cptr || !IsGoPeer(cptr) || cptr->fd < 0)
            continue;
        if (gp && !gp->burst_complete)
            continue;                 /* don't ping until the link has synced */
        if (gp)
            gp->last_ping = time(NULL);
        sendto_one(cptr, ":%s GPING :%s", me.name, nonce);
    }
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
    gopeer_send_pings();
    return 0;
}

static const struct mapi_hook_av1 gossip_hooks[] = {
    { CHOOK_10SEC, &hook_10sec },
    { 0, NULL }
};

DECLARE_CORE_MODULE("m_gossip", "1.0",
                    "Phase S2: gossip S2S protocol commands",
                    gossip_cmds, gossip_hooks);
