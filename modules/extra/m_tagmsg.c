/* modules/extra/m_tagmsg.c
 *
 * IRCv3 message-tags cap + TAGMSG command.
 * TAGMSG has no text body — only tags (used for typing notifications, etc.).
 * Only clients with the "message-tags" cap receive TAGMSG relays; clients
 * without the cap receive nothing (the message is silently dropped for them).
 *
 * Also registers draft/typing cap (no special server-side handling needed;
 * the +typing client tag passes through TAGMSG relay automatically).
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "h.h"
#include "mapi.h"
#include "cap.h"
#include "send.h"
#include "channel.h"
#include "msgbuf.h"
#include "hooks.h"

extern Link *find_channel_link(Link *, aChannel *);

static unsigned long message_tags_bit = 0;
static unsigned long typing_bit       = 0;

static struct mapi_cap_av1 tagmsg_caps[] = {
    { "message-tags", NULL, &message_tags_bit, NULL, NULL },
    { "draft/typing", NULL, &typing_bit,       NULL, NULL },
    { NULL }
};

/*
 * build_client_tags - collect +prefixed (client-originated) tags from msgbuf
 * into a static buffer.  Returns "" if no client tags are present.
 */
static const char *
build_client_tags(struct MsgBuf *msgbuf)
{
    static char tagbuf[512];
    int  i, pos = 0;

    if (!msgbuf || msgbuf->n_tags == 0)
        return "";

    for (i = 0; i < msgbuf->n_tags; i++)
    {
        const char *key = msgbuf->tags[i].key;
        const char *val = msgbuf->tags[i].value;

        if (key[0] != '+')
            continue;  /* skip server-generated tags */

        if (pos > 0)
            tagbuf[pos++] = ';';

        pos += snprintf(tagbuf + pos, sizeof(tagbuf) - pos, "%s", key);
        if (val && *val)
            pos += snprintf(tagbuf + pos, sizeof(tagbuf) - pos, "=%s", val);
        if (pos >= (int)sizeof(tagbuf) - 2)
            break;
    }
    tagbuf[pos] = '\0';
    return tagbuf;
}

static int
m_tagmsg(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr,
         int parc, char *parv[])
{
    aChannel   *chptr;
    aClient    *target;
    chanMember *cm;
    const char *tags;

    if (!MyClient(sptr) || !sptr->user)
        return 0;

    if (parc < 2 || BadPtr(parv[1]))
    {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0],
                   "TAGMSG");
        return 0;
    }

    tags = build_client_tags(msgbuf);

    if (*parv[1] == '#' || *parv[1] == '&')
    {
        /* Channel target */
        if (!(chptr = find_channel(parv[1], NULL)))
        {
            sendto_one(sptr, err_str(ERR_NOSUCHCHANNEL), me.name, parv[0],
                       parv[1]);
            return 0;
        }

        if (!IsMember(sptr, chptr))
        {
            sendto_one(sptr, err_str(ERR_NOTONCHANNEL), me.name, parv[0],
                       parv[1]);
            return 0;
        }

        INC_SERIAL

        for (cm = chptr->members; cm; cm = cm->next)
        {
            aClient *tgt = cm->cptr;

            if (!MyClient(tgt) || tgt == sptr)
                continue;
            if (!HasCap(tgt, message_tags_bit))
                continue;
            if (sentalong[tgt->fd] == sent_serial)
                continue;
            sentalong[tgt->fd] = sent_serial;

            sendto_one_tags(tgt, tags,
                            ":%s!%s@%s TAGMSG %s",
                            sptr->name, sptr->user->username,
                            sptr->user->host, chptr->chname);
        }

        call_hooks(CHOOK_TAGMSG, sptr, (void *)chptr, 1, tags);
    }
    else
    {
        /* User target */
        if (!(target = find_person(parv[1], NULL)))
        {
            sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name, parv[0],
                       parv[1]);
            return 0;
        }

        if (!MyClient(target) || !HasCap(target, message_tags_bit))
            return 0;  /* silently drop — target lacks cap */

        sendto_one_tags(target, tags,
                        ":%s!%s@%s TAGMSG %s",
                        sptr->name, sptr->user->username,
                        sptr->user->host, target->name);

        call_hooks(CHOOK_TAGMSG, sptr, (void *)target, 0, tags);
    }

    return 0;
}

static const struct mapi_cmd_av2 tagmsg_cmds[] = {
    { "TAGMSG", 0, {
        { mg_unreg,  0 },   /* HANDLER_UNREG  */
        { m_tagmsg,  2 },   /* HANDLER_CLIENT */
        { mg_ignore, 0 },   /* HANDLER_REMOTE */
        { mg_ignore, 0 },   /* HANDLER_SERVER */
        { m_tagmsg,  2 },   /* HANDLER_OPER   */
    }},
    { NULL }
};

DECLARE_MODULE_CAPS("m_tagmsg", "1.0",
                    "message-tags + TAGMSG IRCv3 extension",
                    0, tagmsg_cmds, NULL, tagmsg_caps);
