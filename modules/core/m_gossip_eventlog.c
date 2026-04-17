/* modules/extra/m_gossip_eventlog.c
 *
 * Phase S1/S6: Gossip Event Foundation — event instrumentation module.
 *
 * Hooks all state-change events and calls emit_event() to record them in
 * the EventLog ring buffer.  This module has no IRC commands and no IRCv3
 * capabilities; it is a pure observer.
 *
 * Guards: every hook checks IsGossipMaterialized() to prevent double-emission
 * when materializing gossip events triggers hooks on the local server.
 *
 * Load via: autoload = "m_gossip_eventlog";
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "mapi.h"
#include "channel.h"
#include "eventlog.h"
#include "gossip.h"

/* Helper: emit an event and propagate to gossip peers */
static inline void
emit_and_gossip(int type, void *payload, size_t len)
{
    NetworkEvent *ev = emit_event(type, payload, len);
    if (ev)
        gossip_event(ev, NULL);
}

/* -------------------------------------------------------------------------
 * Hook implementations
 * ---------------------------------------------------------------------- */

/* CHOOK_POSTREGISTER → EVT_USER_JOIN */
static int
hook_postregister(aClient *sptr)
{
    EvPayloadUserJoin p;

    if (!sptr->user || IsGossipMaterialized(sptr))
        return 0;

    memset(&p, 0, sizeof(p));
    strncpy(p.nick,     sptr->name,            NICKLEN);
    strncpy(p.username, sptr->user->username,  USERLEN);
    strncpy(p.host,     sptr->user->host,      HOSTLEN);
    strncpy(p.realname, sptr->info,            REALLEN);
    if (sptr->user->server)
        strncpy(p.server, sptr->user->server, HOSTLEN);
    else
        strncpy(p.server, me.name, HOSTLEN);
    /* Include client IP for network-wide clone tracking */
    if (sptr->hostip[0])
        strncpy(p.ipstr, sptr->hostip, HOSTLEN);
    p.umode = sptr->umode;
    p.ts    = sptr->tsinfo;

    emit_and_gossip(EVT_USER_JOIN, &p, sizeof(p));
    return 0;
}

/* CHOOK_SIGNOFF → EVT_USER_QUIT */
static void
hook_signoff(aClient *sptr)
{
    EvPayloadUserQuit p;

    if (!sptr->user || IsGossipMaterialized(sptr))
        return;

    memset(&p, 0, sizeof(p));
    strncpy(p.nick, sptr->name, NICKLEN);

    emit_and_gossip(EVT_USER_QUIT, &p, sizeof(p));
}

/* CHOOK_JOIN → EVT_CHAN_JOIN */
static int
hook_join(aClient *sptr, aChannel *chptr)
{
    EvPayloadChanJoin p;
    chanMember *cm;
    int flags = 0;

    if (!sptr->user || !chptr || IsGossipMaterialized(sptr))
        return 0;

    /* Look up channel member flags (op/voice) — the member has already
     * been added to the channel by the time this hook fires. */
    for (cm = chptr->members; cm; cm = cm->next)
        if (cm->cptr == sptr) { flags = cm->flags; break; }

    memset(&p, 0, sizeof(p));
    strncpy(p.nick,    sptr->name,    NICKLEN);
    strncpy(p.channel, chptr->chname, CHANNELLEN);
    p.flags = flags;
    p.ts    = chptr->channelts;

    emit_and_gossip(EVT_CHAN_JOIN, &p, sizeof(p));
    return 0;
}

/* CHOOK_AWAY → EVT_USER_AWAY */
static void
hook_away(aClient *sptr, int setting, char *message)
{
    EvPayloadUserAway p;

    if (!sptr->user || IsGossipMaterialized(sptr))
        return;

    memset(&p, 0, sizeof(p));
    strncpy(p.nick, sptr->name, NICKLEN);
    p.setting = setting;
    if (setting && message)
        strncpy(p.message, message, TOPICLEN);

    emit_and_gossip(EVT_USER_AWAY, &p, sizeof(p));
}

/* CHOOK_NICK → EVT_USER_NICK */
static void
hook_nick(aClient *sptr, const char *oldnick, const char *newnick)
{
    EvPayloadUserNick p;

    if (IsGossipMaterialized(sptr))
        return;

    memset(&p, 0, sizeof(p));
    strncpy(p.oldnick, oldnick, NICKLEN);
    strncpy(p.newnick, newnick, NICKLEN);
    p.ts = sptr->tsinfo;

    emit_and_gossip(EVT_USER_NICK, &p, sizeof(p));
}

/* CHOOK_PART → EVT_CHAN_PART */
static void
hook_part(aClient *sptr, aChannel *chptr, const char *reason)
{
    EvPayloadChanPart p;

    if (!sptr->user || !chptr || IsGossipMaterialized(sptr))
        return;

    memset(&p, 0, sizeof(p));
    strncpy(p.nick,    sptr->name,    NICKLEN);
    strncpy(p.channel, chptr->chname, CHANNELLEN);
    if (reason)
        strncpy(p.reason, reason, sizeof(p.reason) - 1);

    emit_and_gossip(EVT_CHAN_PART, &p, sizeof(p));
}

/* CHOOK_CHANMODE → EVT_CHAN_MODE */
static void
hook_chanmode(aClient *sptr, aChannel *chptr, const char *modebuf,
              const char *parabuf)
{
    EvPayloadChanMode p;

    if (!chptr || IsGossipMaterialized(sptr))
        return;

    memset(&p, 0, sizeof(p));
    strncpy(p.nick,    sptr->name,    NICKLEN);
    strncpy(p.channel, chptr->chname, CHANNELLEN);
    strncpy(p.modebuf, modebuf,       sizeof(p.modebuf) - 1);
    if (parabuf)
        strncpy(p.parabuf, parabuf,   sizeof(p.parabuf) - 1);

    emit_and_gossip(EVT_CHAN_MODE, &p, sizeof(p));
}

/* CHOOK_TOPIC → EVT_CHAN_TOPIC */
static void
hook_topic(aClient *sptr, aChannel *chptr, const char *topic)
{
    EvPayloadChanTopic p;

    if (!chptr || IsGossipMaterialized(sptr))
        return;

    memset(&p, 0, sizeof(p));
    strncpy(p.nick,    sptr->name,      NICKLEN);
    strncpy(p.channel, chptr->chname,   CHANNELLEN);
    strncpy(p.setter,  chptr->topic_nick,
            sizeof(p.setter) - 1);
    if (topic)
        strncpy(p.topic, topic, TOPICLEN);
    p.ts = chptr->topic_time;

    emit_and_gossip(EVT_CHAN_TOPIC, &p, sizeof(p));
}

/* CHOOK_UMODE → EVT_USER_MODE */
static void
hook_umode(aClient *sptr, unsigned long old_umode)
{
    EvPayloadUserMode p;

    if (!sptr->user || IsGossipMaterialized(sptr))
        return;

    memset(&p, 0, sizeof(p));
    strncpy(p.nick, sptr->name, NICKLEN);
    p.old_umode = old_umode;
    p.new_umode = sptr->umode;

    emit_and_gossip(EVT_USER_MODE, &p, sizeof(p));
}

/* CHOOK_KICK → EVT_CHAN_KICK */
static void
hook_kick(aClient *kicker, aClient *target, aChannel *chptr, const char *reason)
{
    EvPayloadChanKick p;

    if (!chptr)
        return;
    /* Only skip if the kick originated from gossip (kicker is materialized).
     * If a local user kicks a gossip-materialized target, we must emit
     * EVT_CHAN_KICK so other gossip peers learn about it. */
    if (IsGossipMaterialized(kicker))
        return;

    memset(&p, 0, sizeof(p));
    strncpy(p.kicker,  kicker->name,  NICKLEN);
    strncpy(p.target,  target->name,  NICKLEN);
    strncpy(p.channel, chptr->chname, CHANNELLEN);
    if (reason)
        strncpy(p.reason, reason, sizeof(p.reason) - 1);

    emit_and_gossip(EVT_CHAN_KICK, &p, sizeof(p));
}

/* CHOOK_USERMSG → EVT_PRIVMSG (for gossip-materialized targets) */
static int
hook_usermsg(aClient *source, aClient *target, int is_notice, char *text)
{
    EvPayloadPrivmsg p;

    if (!target || !IsGossipMaterialized(target))
        return 0;  /* not a gossip target — let normal delivery handle it */
    if (IsGossipMaterialized(source))
        return 0;  /* gossip-to-gossip — already propagated */

    memset(&p, 0, sizeof(p));
    strncpy(p.sender, source->name, NICKLEN);
    strncpy(p.target, target->name, NICKLEN);
    if (text)
        strncpy(p.text, text, sizeof(p.text) - 1);
    p.is_notice = is_notice;

    emit_and_gossip(EVT_PRIVMSG, &p, sizeof(p));
    return 0;
}

/* CHOOK_CHANMSG → EVT_CHANMSG (if channel has gossip members) */
static int
hook_chanmsg(aClient *source, aChannel *chptr, int is_notice, char *text)
{
    EvPayloadChanmsg p;

    if (!chptr || !source)
        return 0;
    if (IsGossipMaterialized(source))
        return 0;  /* message from gossip user — already propagated */

    /* Only emit if the channel has gossip-materialized members */
    {
        extern Link *find_channel_link(Link *, aChannel *);
        chanMember *cm;
        int has_gossip = 0;
        for (cm = chptr->members; cm; cm = cm->next)
        {
            if (IsGossipMaterialized(cm->cptr))
            {
                has_gossip = 1;
                break;
            }
        }
        if (!has_gossip)
            return 0;
    }

    memset(&p, 0, sizeof(p));
    strncpy(p.sender, source->name, NICKLEN);
    strncpy(p.channel, chptr->chname, CHANNELLEN);
    if (text)
        strncpy(p.text, text, sizeof(p.text) - 1);
    p.is_notice = is_notice;

    emit_and_gossip(EVT_CHANMSG, &p, sizeof(p));
    return 0;
}

/* -------------------------------------------------------------------------
 * Hook table (no IRC commands; no caps)
 * ---------------------------------------------------------------------- */

static const struct mapi_hook_av1 eventlog_hooks[] = {
    { CHOOK_POSTREGISTER, hook_postregister },
    { CHOOK_SIGNOFF,      hook_signoff      },
    { CHOOK_POSTJOIN,     hook_join         },
    { CHOOK_AWAY,         hook_away         },
    { CHOOK_NICK,         hook_nick         },
    { CHOOK_PART,         hook_part         },
    { CHOOK_CHANMODE,     hook_chanmode     },
    { CHOOK_TOPIC,        hook_topic        },
    { CHOOK_UMODE,        hook_umode        },
    { CHOOK_KICK,         hook_kick         },
    { CHOOK_USERMSG,      hook_usermsg      },
    { CHOOK_CHANMSG,      hook_chanmsg      },
    { 0, NULL }
};

DECLARE_CORE_MODULE("m_gossip_eventlog", "1.0",
                    "Gossip state propagation hooks",
                    NULL, eventlog_hooks);
