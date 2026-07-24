/* modules/extra/m_silence.c
 *
 * SILENCE command — client-side ignore list.
 * Extracted from src/s_user.c.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "numeric.h"
#include "mapi.h"

static int m_silence(struct MsgBuf *, aClient *, aClient *, int, char **);

static const struct mapi_cmd_av2 silence_cmds[] = {
    { "SILENCE", 0, {
        { mg_unreg,  0 }, { m_silence, 0 }, { m_silence, 0 },
        { m_silence, 0 }, { m_silence, 0 } }},
    { NULL }
};

DECLARE_MODULE("m_silence", "2.0", "SILENCE list", 0, silence_cmds, NULL);

static int add_silence(aClient *sptr, char *mask)
{
    Link *lp;
    int cnt=0, len=0;
    for (lp=sptr->user->silence;lp;lp=lp->next)
    {
        len += strlen(lp->value.cp);
        if (MyClient(sptr))
        {
            if ((len > MAXSILELENGTH) || (++cnt >= MAXSILES))
            {
                sendto_one(sptr, err_str(ERR_SILELISTFULL), me.name,
                           sptr->name, mask);
                return -1;
            }
            else
            {
                if (!match(lp->value.cp, mask))
                    return -1;
            }
        }
        else if (!mycmp(lp->value.cp, mask))
            return -1;
    }
    lp = make_link();
    lp->next = sptr->user->silence;
    lp->value.cp = (char *)MyMalloc(strlen(mask)+1);
    strcpy(lp->value.cp, mask);
    sptr->user->silence = lp;
    return 0;
}

/* m_silence
 * parv[0] = sender prefix
 * From local client:
 * parv[1] = mask (NULL sends the list)
 * From remote client:
 * parv[1] = nick that must be silenced
 * parv[2] = mask
 */
static int
m_silence(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    Link *lp;
    aClient *acptr=NULL;
    char c, *cp;

    if (MyClient(sptr))
    {
        acptr = sptr;
        if (parc < 2 || *parv[1]=='\0' || (acptr = find_person(parv[1], NULL)))
        {
            if (!(acptr->user))
                return 0;

            for (lp = acptr->user->silence; lp; lp = lp->next)
                sendto_one(sptr, rpl_str(RPL_SILELIST), me.name,
                           sptr->name, acptr->name, lp->value.cp);

            sendto_one(sptr, rpl_str(RPL_ENDOFSILELIST), me.name, acptr->name);
            return 0;
        }
        cp = parv[1];
        c = *cp;
        if (c=='-' || c=='+')
            cp++;
        else if (!(strchr(cp, '@') || strchr(cp, '.') ||
                   strchr(cp, '!') || strchr(cp, '*')))
        {
            sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name, parv[0],
                       parv[1]);
            return 0;
        }
        else c = '+';
        cp = pretty_mask(cp);
        if ((c=='-' && !del_silence(sptr,cp)) ||
            (c!='-' && !add_silence(sptr,cp)))
        {
            sendto_prefix_one(sptr, sptr, ":%s SILENCE %c%s", parv[0], c, cp);
            if (c=='-')
                sendto_serv_butone(NULL, ":%s SILENCE * -%s", sptr->name, cp);
        }
    }
    else if (parc < 3 || *parv[2]=='\0')
    {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0],
                   "SILENCE");
        return -1;
    }
    else if ((c = *parv[2])=='-' || (acptr = find_person(parv[1], NULL)))
    {
        if (c=='-')
        {
            if (!del_silence(sptr,parv[2]+1))
                sendto_serv_butone(cptr, ":%s SILENCE %s :%s",
                                   parv[0], parv[1], parv[2]);
        }
        else
        {
            add_silence(sptr,parv[2]);
            if (!MyClient(acptr))
                sendto_one(acptr, ":%s SILENCE %s :%s",
                           parv[0], parv[1], parv[2]);
        }
    }
    else
    {
        sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name, parv[0], parv[1]);
        return 0;
    }
    return 0;
}
