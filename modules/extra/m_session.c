/* modules/extra/m_session.c
 *
 * Phase S5: Persistent sessions with draft/resume-0.5.
 *
 * Commands:
 *   RESUME <key>    — pre-registration: restore session (with cap)
 *   RESUME <key>    — post-registration: restore session (backward compat)
 *
 * Hooks:
 *   CHOOK_SIGNOFF       — snapshot client state to a session on disconnect
 *   CHOOK_POSTREGISTER  — apply resumed state + deliver tokens
 *   CHOOK_10SEC         — periodically expire stale sessions
 *
 * Protocol flow (draft/resume-0.5):
 *   1. Client negotiates draft/resume-0.5 via CAP REQ.
 *   2. On first registration, server sends "RESUME TOKEN <key>" after welcome.
 *      Client saves the token.
 *   3. On disconnect, server creates a session using the pre-assigned token.
 *   4. On reconnect, client sends "RESUME <token>" before CAP END.
 *      Server validates, swaps nick, stashes session for post-registration.
 *   5. After register_user() completes, CHOOK_POSTREGISTER applies state
 *      (umodes, away, channel list, queued messages) and issues a new token.
 *
 * Backward compatibility:
 *   Clients without the cap still receive a NOTICE with the token on signoff
 *   (best-effort) and can RESUME post-registration as before.
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "numeric.h"
#include "mapi.h"
#include "send.h"
#include "hooks.h"
#include "eventlog.h"
#include "gossip_event.h"
#include "gossip.h"
#include "session.h"
#include "cap.h"
#include "config.h"

/* Umodes that are safe to restore without re-authing (non-privileged). */
#define SESSION_SAFE_UMODES  (UMODE_i | UMODE_w | UMODE_s)

/* -------------------------------------------------------------------------
 * draft/resume-0.5 capability
 * ---------------------------------------------------------------------- */

static unsigned long cap_resume_bit = 0;

static const struct mapi_cap_av1 session_caps[] = {
    { "draft/resume-0.5", NULL, &cap_resume_bit, NULL, NULL },
    { NULL }
};

/* -------------------------------------------------------------------------
 * Module-local side tables (indexed by client fd)
 *
 * token_table:  Pre-assigned session token for each connected client with
 *               the draft/resume-0.5 cap.  Allocated on registration,
 *               freed on signoff.
 *
 * resume_table: Pending session to restore after register_user() completes.
 *               Set by pre-registration RESUME, consumed by POSTREGISTER.
 * ---------------------------------------------------------------------- */

static char    *token_table[MAXCONNECTIONS];
static Session *resume_table[MAXCONNECTIONS];

/* -------------------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------------- */

/* Emit EVT_SESSION_CREATE and gossip it to peers. */
static void
gossip_session_create(Session *sess)
{
    EvPayloadSessionCreate pl;
    NetworkEvent          *ev;

    memset(&pl, 0, sizeof(pl));
    strncpy(pl.key,      sess->key,      SESSION_KEY_LEN);
    strncpy(pl.nick,     sess->nick,     NICKLEN);
    strncpy(pl.username, sess->username, USERLEN);
    strncpy(pl.host,     sess->host,     HOSTLEN);
    strncpy(pl.realname, sess->realname, REALLEN);
    pl.umode      = sess->umode;
    pl.expires_at = sess->expires_at;
    strncpy(pl.away_msg, sess->away_msg, TOPICLEN);

    ev = emit_event(EVT_SESSION_CREATE, &pl, sizeof(pl));
    if (ev)
        gossip_event(ev, NULL);
}

/* Emit EVT_SESSION_DESTROY and gossip it to peers, then destroy session. */
static void
destroy_and_gossip_session(Session *sess)
{
    EvPayloadSessionDestroy pl;
    NetworkEvent           *ev;
    char                    key_copy[SESSION_KEY_LEN + 1];

    strncpy(key_copy, sess->key, SESSION_KEY_LEN);
    key_copy[SESSION_KEY_LEN] = '\0';

    session_destroy(sess);

    memset(&pl, 0, sizeof(pl));
    strncpy(pl.key, key_copy, SESSION_KEY_LEN);

    ev = emit_event(EVT_SESSION_DESTROY, &pl, sizeof(pl));
    if (ev)
        gossip_event(ev, NULL);
}

/* Apply restored session state to a freshly-registered client.
 * Extracted from m_resume() for reuse by both pre-reg and post-reg paths. */
static void
apply_resumed_state(aClient *sptr, Session *sess)
{
    int i;

    /* --- Restore safe umodes --- */
    if (sess->umode & SESSION_SAFE_UMODES)
    {
        unsigned long old_umode = sptr->umode;
        char ubuf[BUFSIZE];

        sptr->umode |= (sess->umode & SESSION_SAFE_UMODES);
        if (sptr->umode != old_umode)
            send_umode(sptr, sptr, old_umode, ALL_UMODES, ubuf, sizeof(ubuf));
    }

    /* --- Restore away --- */
    if (sess->away_msg[0] && sptr->user && !sptr->user->away)
    {
        sptr->user->away = (char *)MyMalloc(strlen(sess->away_msg) + 1);
        strcpy(sptr->user->away, sess->away_msg);
        sendto_one(sptr, ":%s 306 %s :You have been marked as being away",
                   me.name, sptr->name);
    }

    /* --- Channel list (local sessions) --- */
    if (sess->is_local && sess->num_channels > 0)
    {
        char chanlist[512];
        int  pos = 0;

        for (i = 0; i < sess->num_channels; i++)
        {
            int len = (int)strlen(sess->channels[i].name);
            if (i && pos < (int)sizeof(chanlist) - 1)
                chanlist[pos++] = ',';
            if (pos + len < (int)sizeof(chanlist) - 1)
            {
                strcpy(chanlist + pos, sess->channels[i].name);
                pos += len;
            }
        }
        chanlist[pos] = '\0';
        sendto_one(sptr,
                   ":%s NOTICE %s :Channels from your session: %s "
                   "(rejoin manually)",
                   me.name, sptr->name, chanlist);
    }

    /* --- Replay queued messages (local sessions) --- */
    if (sess->is_local && sess->msg_count > 0)
    {
        int start = (sess->msg_head - sess->msg_count + SESSION_MAX_MSGS)
                    % SESSION_MAX_MSGS;

        sendto_one(sptr,
                   ":%s NOTICE %s :--- %d message(s) received while away ---",
                   me.name, sptr->name, sess->msg_count);

        for (i = 0; i < sess->msg_count; i++)
        {
            int        slot = (start + i) % SESSION_MAX_MSGS;
            SessionMsg *m   = &sess->msgs[slot];

            sendto_one(sptr, ":%s %s %s :%s",
                       m->from,
                       m->is_notice ? "NOTICE" : "PRIVMSG",
                       sptr->name,
                       m->text);
        }
    }
}

/* Perform a nick change on behalf of RESUME (post-registration path).
 * Returns 1 if the nick was changed, 0 if it could not be changed. */
static int
resume_nick_change(aClient *cptr, aClient *sptr, const char *new_nick)
{
    char oldnick[NICKLEN + 1];

    if (mycmp(sptr->name, (char *)new_nick) == 0)
        return 1;   /* already using that nick */

    /* Fail silently if nick is in use by a live client or another session */
    if (find_client((char *)new_nick, NULL) || session_find_by_nick(new_nick))
        return 0;

    strncpy(oldnick, sptr->name, NICKLEN);
    oldnick[NICKLEN] = '\0';

    /* Notify channels and servers (same pattern as m_nick.c) */
    sendto_common_channels(sptr, ":%s NICK :%s", sptr->name, new_nick);
    if (sptr->user)
    {
        add_history(sptr, 1);
        sendto_serv_butone(cptr, ":%s NICK %s :%ld",
                           sptr->name, new_nick, (long)timeofday);
    }

    del_from_client_hash_table(sptr->name, sptr);
    strncpy(sptr->name, new_nick, NICKLEN);
    sptr->name[NICKLEN] = '\0';
    add_to_client_hash_table(sptr->name, sptr);

    hash_check_watch(sptr, RPL_LOGON);
    call_hooks(CHOOK_NICK, sptr, oldnick, sptr->name);
    return 1;
}

/* -------------------------------------------------------------------------
 * RESUME <key> — pre-registration handler (clients with draft/resume-0.5)
 * ---------------------------------------------------------------------- */

static int
m_resume_unreg(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr,
               int parc, char *parv[])
{
    Session    *sess;
    const char *key = parv[1];

    /* Only allow if client negotiated the cap */
    if (!HasCap(sptr, cap_resume_bit))
    {
        sendto_one(sptr,
                   "FAIL RESUME REGISTRATION_IS_COMPLETED "
                   ":Negotiate draft/resume-0.5 first");
        return 0;
    }

    /* Already resuming? */
    if (sptr->fd >= 0 && resume_table[sptr->fd])
    {
        sendto_one(sptr, "FAIL RESUME CANNOT_RESUME :Already resuming");
        return 0;
    }

    sess = session_find_by_key(key);
    if (!sess)
    {
        sendto_one(sptr,
                   "FAIL RESUME INVALID_TOKEN :No session found for that token");
        return 0;
    }

    /* Session nick is taken by a live client — can't resume to it */
    {
        aClient *existing = find_client(sess->nick, NULL);
        if (existing && existing != sptr)
        {
            sendto_one(sptr,
                       "FAIL RESUME CANNOT_RESUME :Nick is in use");
            return 0;
        }
    }

    /* Remove current nick from hash, set session nick */
    del_from_client_hash_table(sptr->name, sptr);
    strncpy(sptr->name, sess->nick, NICKLEN);
    sptr->name[NICKLEN] = '\0';
    add_to_client_hash_table(sptr->name, sptr);

    /* Remove session's nick reservation so it doesn't block registration */
    session_unhash_nick(sess);

    /* Stash session for post-registration application */
    if (sptr->fd >= 0)
        resume_table[sptr->fd] = sess;

    /* Tell client resume was accepted */
    sendto_one(sptr, "RESUME %s", sess->nick);

    return 0;
}

/* -------------------------------------------------------------------------
 * RESUME <key> — post-registration handler (backward compat)
 * ---------------------------------------------------------------------- */

static int
m_resume(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr,
         int parc, char *parv[])
{
    Session    *sess;
    const char *key = parv[1];

    sess = session_find_by_key(key);
    if (!sess)
    {
        sendto_one(sptr, ":%s NOTICE %s :No session found for that key.",
                   me.name, sptr->name);
        return 0;
    }

    sendto_one(sptr, ":%s NOTICE %s :Resuming session...",
               me.name, sptr->name);

    /* Nick change */
    resume_nick_change(cptr, sptr, sess->nick);

    /* Apply restored state */
    apply_resumed_state(sptr, sess);

    /* Destroy session (token is one-time) */
    destroy_and_gossip_session(sess);

    sendto_one(sptr, ":%s NOTICE %s :Session resumed.", me.name, sptr->name);
    return 0;
}

/* -------------------------------------------------------------------------
 * CHOOK_POSTREGISTER — apply resumed state + deliver tokens
 * ---------------------------------------------------------------------- */

static int
hook_postregister(aClient *sptr)
{
    if (!MyClient(sptr) || sptr->fd < 0)
        return 0;

    /* --- Pending resume: apply restored state --- */
    if (resume_table[sptr->fd])
    {
        Session *sess = resume_table[sptr->fd];
        resume_table[sptr->fd] = NULL;

        apply_resumed_state(sptr, sess);

        /* Destroy session (one-time token) */
        destroy_and_gossip_session(sess);

        sendto_one(sptr, ":%s NOTICE %s :Session resumed.",
                   me.name, sptr->name);
    }

    /* --- Token delivery for clients with the cap --- */
    if (HasCap(sptr, cap_resume_bit))
    {
        char token[SESSION_KEY_LEN + 1];
        session_generate_key(token);

        /* Free any leftover from a previous connection on this fd */
        if (token_table[sptr->fd])
            MyFree(token_table[sptr->fd]);

        token_table[sptr->fd] = (char *)MyMalloc(SESSION_KEY_LEN + 1);
        memcpy(token_table[sptr->fd], token, SESSION_KEY_LEN + 1);

        sendto_one(sptr, "RESUME TOKEN %s", token);
    }

    return 0;
}

/* -------------------------------------------------------------------------
 * CHOOK_SIGNOFF — create session snapshot when a local user disconnects
 * ---------------------------------------------------------------------- */

static void
hook_signoff(aClient *sptr)
{
    Session    *sess;
    const char *preassigned = NULL;

    /* Only snapshot local, registered users */
    if (!MyClient(sptr) || !sptr->user || !IsRegisteredUser(sptr))
        goto cleanup;

    /* Use pre-assigned token if available (cap clients) */
    if (sptr->fd >= 0 && token_table[sptr->fd])
        preassigned = token_table[sptr->fd];

    sess = session_create(sptr, preassigned);
    if (!sess)
    {
        sendto_realops("session: slab full, cannot create session for %s",
                       sptr->name);
        goto cleanup;
    }

    /* For clients WITHOUT the cap: best-effort NOTICE (backward compat) */
    if (!HasCap(sptr, cap_resume_bit))
    {
        sendto_one(sptr, ":%s NOTICE %s :Session token: %s",
                   me.name, sptr->name, sess->key);
    }
    /* Cap clients already have the token — no need to send anything */

    /* Gossip EVT_SESSION_CREATE so remote servers can service RESUME */
    gossip_session_create(sess);

cleanup:
    /* Free the pre-assigned token */
    if (sptr->fd >= 0 && token_table[sptr->fd])
    {
        MyFree(token_table[sptr->fd]);
        token_table[sptr->fd] = NULL;
    }

    /* Clear any stale resume entry */
    if (sptr->fd >= 0)
        resume_table[sptr->fd] = NULL;
}

/* -------------------------------------------------------------------------
 * CHOOK_10SEC — expire stale sessions
 * ---------------------------------------------------------------------- */

static void
hook_10sec(void)
{
    session_expire_check();
}

/* -------------------------------------------------------------------------
 * Module registration
 * ---------------------------------------------------------------------- */

static const struct mapi_cmd_av2 session_cmds[] = {
    { "RESUME", 0, {
        { m_resume_unreg, 2 },   /* UNREG   — pre-registration resume       */
        { m_resume,       2 },   /* CLIENT  — post-registration (compat)    */
        { mg_ignore,      0 },   /* REMOTE  — remote users not allowed      */
        { mg_ignore,      0 },   /* SERVER  — servers don't RESUME          */
        { m_resume,       2 },   /* OPER    — opers can RESUME too          */
    }},
    { NULL }
};

static const struct mapi_hook_av1 session_hooks[] = {
    { CHOOK_SIGNOFF,       &hook_signoff       },
    { CHOOK_POSTREGISTER,  &hook_postregister  },
    { CHOOK_10SEC,         &hook_10sec         },
    { 0, NULL }
};

static void
mapi_register(void)
{
    session_init();
    memset(token_table,  0, sizeof(token_table));
    memset(resume_table, 0, sizeof(resume_table));
}

DECLARE_MODULE_CAPS_RU("m_session", "2.0",
                       "Phase S5: persistent sessions with draft/resume-0.5",
                       0, session_cmds, session_hooks, session_caps,
                       mapi_register, NULL);
