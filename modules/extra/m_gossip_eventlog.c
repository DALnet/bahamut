/* modules/extra/m_gossip_eventlog.c
 *
 * Phase S1: Gossip Event Foundation — event instrumentation module.
 *
 * Hooks all state-change events and calls emit_event() to record them in
 * the EventLog ring buffer.  This module has no IRC commands and no IRCv3
 * capabilities; it is a pure observer.
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

/* -------------------------------------------------------------------------
 * Hook implementations
 * ---------------------------------------------------------------------- */

/* CHOOK_POSTREGISTER → EVT_USER_JOIN */
static int
hook_postregister(aClient *sptr)
{
    EvPayloadUserJoin p;

    if (!sptr->user)
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
    p.umode = sptr->umode;
    p.ts    = sptr->tsinfo;

    emit_event(EVT_USER_JOIN, &p, sizeof(p));
    return 0;
}

/* CHOOK_SIGNOFF → EVT_USER_QUIT */
static void
hook_signoff(aClient *sptr)
{
    EvPayloadUserQuit p;

    if (!sptr->user)
        return;

    memset(&p, 0, sizeof(p));
    strncpy(p.nick, sptr->name, NICKLEN);
    /* Quit reason is not passed by CHOOK_SIGNOFF; leave empty */

    emit_event(EVT_USER_QUIT, &p, sizeof(p));
}

/* CHOOK_JOIN → EVT_CHAN_JOIN */
static int
hook_join(aClient *sptr, aChannel *chptr)
{
    EvPayloadChanJoin p;

    if (!sptr->user || !chptr)
        return 0;

    memset(&p, 0, sizeof(p));
    strncpy(p.nick,    sptr->name,    NICKLEN);
    strncpy(p.channel, chptr->chname, CHANNELLEN);
    p.flags = 0;   /* flags determined post-join via SJOIN; not available here */
    p.ts    = chptr->channelts;

    emit_event(EVT_CHAN_JOIN, &p, sizeof(p));
    return 0;
}

/* CHOOK_AWAY → EVT_USER_AWAY */
static void
hook_away(aClient *sptr, int setting, char *message)
{
    EvPayloadUserAway p;

    if (!sptr->user)
        return;

    memset(&p, 0, sizeof(p));
    strncpy(p.nick, sptr->name, NICKLEN);
    p.setting = setting;
    if (setting && message)
        strncpy(p.message, message, TOPICLEN);

    emit_event(EVT_USER_AWAY, &p, sizeof(p));
}

/* CHOOK_NICK → EVT_USER_NICK */
static void
hook_nick(aClient *sptr, const char *oldnick, const char *newnick)
{
    EvPayloadUserNick p;

    memset(&p, 0, sizeof(p));
    strncpy(p.oldnick, oldnick, NICKLEN);
    strncpy(p.newnick, newnick, NICKLEN);
    p.ts = sptr->tsinfo;

    emit_event(EVT_USER_NICK, &p, sizeof(p));
}

/* CHOOK_PART → EVT_CHAN_PART */
static void
hook_part(aClient *sptr, aChannel *chptr, const char *reason)
{
    EvPayloadChanPart p;

    if (!sptr->user || !chptr)
        return;

    memset(&p, 0, sizeof(p));
    strncpy(p.nick,    sptr->name,    NICKLEN);
    strncpy(p.channel, chptr->chname, CHANNELLEN);
    if (reason)
        strncpy(p.reason, reason, sizeof(p.reason) - 1);

    emit_event(EVT_CHAN_PART, &p, sizeof(p));
}

/* CHOOK_CHANMODE → EVT_CHAN_MODE */
static void
hook_chanmode(aClient *sptr, aChannel *chptr, const char *modebuf,
              const char *parabuf)
{
    EvPayloadChanMode p;

    if (!chptr)
        return;

    memset(&p, 0, sizeof(p));
    strncpy(p.nick,    sptr->name,    NICKLEN);
    strncpy(p.channel, chptr->chname, CHANNELLEN);
    strncpy(p.modebuf, modebuf,       sizeof(p.modebuf) - 1);
    if (parabuf)
        strncpy(p.parabuf, parabuf,   sizeof(p.parabuf) - 1);

    emit_event(EVT_CHAN_MODE, &p, sizeof(p));
}

/* CHOOK_TOPIC → EVT_CHAN_TOPIC */
static void
hook_topic(aClient *sptr, aChannel *chptr, const char *topic)
{
    EvPayloadChanTopic p;

    if (!chptr)
        return;

    memset(&p, 0, sizeof(p));
    strncpy(p.nick,    sptr->name,      NICKLEN);
    strncpy(p.channel, chptr->chname,   CHANNELLEN);
    strncpy(p.setter,  chptr->topic_nick,
            sizeof(p.setter) - 1);
    if (topic)
        strncpy(p.topic, topic, TOPICLEN);
    p.ts = chptr->topic_time;

    emit_event(EVT_CHAN_TOPIC, &p, sizeof(p));
}

/* CHOOK_UMODE → EVT_USER_MODE */
static void
hook_umode(aClient *sptr, unsigned long old_umode)
{
    EvPayloadUserMode p;

    if (!sptr->user)
        return;

    memset(&p, 0, sizeof(p));
    strncpy(p.nick, sptr->name, NICKLEN);
    p.old_umode = old_umode;
    p.new_umode = sptr->umode;

    emit_event(EVT_USER_MODE, &p, sizeof(p));
}

/* -------------------------------------------------------------------------
 * Hook table (no IRC commands; no caps)
 * ---------------------------------------------------------------------- */

static const struct mapi_hook_av1 eventlog_hooks[] = {
    { CHOOK_POSTREGISTER, hook_postregister },
    { CHOOK_SIGNOFF,      hook_signoff      },
    { CHOOK_JOIN,         hook_join         },
    { CHOOK_AWAY,         hook_away         },
    { CHOOK_NICK,         hook_nick         },
    { CHOOK_PART,         hook_part         },
    { CHOOK_CHANMODE,     hook_chanmode     },
    { CHOOK_TOPIC,        hook_topic        },
    { CHOOK_UMODE,        hook_umode        },
    { 0, NULL }
};

DECLARE_MODULE("m_gossip_eventlog", "1.0",
               "Phase S1: gossip event log instrumentation",
               0, NULL, eventlog_hooks);
