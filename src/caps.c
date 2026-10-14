/*
 *   IRC - Internet Relay Chat, src/caps.c
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
 * IRCv3 client capability negotiation.
 * See https://ircv3.net/specs/extensions/capability-negotiation
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "h.h"
#include "caps.h"

extern int register_user(aClient *, aClient *, char *, char *, char *);

/* leave room for ":server CAP nick LS * :" within the 512 byte limit */
#define CAP_LINELEN 400

static aClientCap clientcaps[] =
{
    { "cap-notify", CAP_CAP_NOTIFY, NULL, CAPF_STICKY_302 },
    { NULL, 0, NULL, 0 }
};

static aClientCap *
find_cap(char *name)
{
    aClientCap *cap;

    for (cap = clientcaps; cap->name; cap++)
        if (!strcmp(cap->name, name))
            return cap;
    return NULL;
}

static char *
cap_nick(aClient *sptr)
{
    return *sptr->name ? sptr->name : "*";
}

/*
 * send_caps - send the capabilities in mask as CAP <subcmd>, split over
 * several lines if needed.  CAP 302 clients get a "*" continuation
 * marker on all but the last line and name=value pairs.
 */
static void
send_caps(aClient *sptr, char *subcmd, unsigned int mask)
{
    char buf[BUFSIZE], tok[BUFSIZE];
    aClientCap *cap;
    int v302 = (sptr->cap_version >= 302);
    int len = 0, n;

    *buf = '\0';
    for (cap = clientcaps; cap->name; cap++)
    {
        if (!(mask & cap->bit))
            continue;

        if (v302 && cap->value)
            ircsnprintf(tok, sizeof(tok), "%s=%s", cap->name, cap->value);
        else
            strncpyzt(tok, cap->name, sizeof(tok));
        n = strlen(tok);

        if (len && len + 1 + n > CAP_LINELEN)
        {
            sendto_one(sptr, ":%s CAP %s %s %s:%s", me.name, cap_nick(sptr),
                       subcmd, v302 ? "* " : "", buf);
            len = 0;
            *buf = '\0';
        }

        if (len)
            buf[len++] = ' ';
        strcpy(buf + len, tok);
        len += n;
    }

    sendto_one(sptr, ":%s CAP %s %s :%s", me.name, cap_nick(sptr), subcmd,
               buf);
}

static int
cap_ls(aClient *sptr, int parc, char *parv[])
{
    if (!IsRegistered(sptr))
        sptr->cap_negotiating = 1;

    if (parc > 2 && atoi(parv[2]) >= 302 && sptr->cap_version < 302)
    {
        sptr->cap_version = 302;
        sptr->caps |= CAP_CAP_NOTIFY;
    }

    send_caps(sptr, "LS", ~0U);
    return 0;
}

static int
cap_list(aClient *sptr)
{
    send_caps(sptr, "LIST", sptr->caps);
    return 0;
}

/*
 * cap_req - the request is applied atomically: either every capability
 * in it is changed and the whole request is ACKed, or none are and it
 * is NAKed.
 */
static int
cap_req(aClient *sptr, int parc, char *parv[])
{
    char reqbuf[BUFSIZE], *tok, *p = NULL;
    unsigned int add = 0, del = 0;
    aClientCap *cap;
    int neg;

    if (parc < 3 || BadPtr(parv[2]))
    {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name,
                   cap_nick(sptr), "CAP");
        return 0;
    }

    if (!IsRegistered(sptr))
        sptr->cap_negotiating = 1;

    strncpyzt(reqbuf, parv[2], sizeof(reqbuf));
    for (tok = strtoken(&p, reqbuf, " "); tok; tok = strtoken(&p, NULL, " "))
    {
        neg = (*tok == '-');
        if (neg)
            tok++;

        cap = find_cap(tok);
        if (!cap || (neg && (cap->flags & CAPF_STICKY_302) &&
                     sptr->cap_version >= 302))
        {
            sendto_one(sptr, ":%s CAP %s NAK :%s", me.name, cap_nick(sptr),
                       parv[2]);
            return 0;
        }

        if (neg)
        {
            del |= cap->bit;
            add &= ~cap->bit;
        }
        else
        {
            add |= cap->bit;
            del &= ~cap->bit;
        }
    }

    sptr->caps = (sptr->caps | add) & ~del;
    sendto_one(sptr, ":%s CAP %s ACK :%s", me.name, cap_nick(sptr), parv[2]);
    return 0;
}

static int
cap_end(aClient *cptr, aClient *sptr)
{
    if (IsRegistered(sptr) || !sptr->cap_negotiating)
        return 0;

    sptr->cap_negotiating = 0;

    /* NICK and USER already received, finish registration now */
    if (*sptr->name && sptr->user)
        return register_user(cptr, sptr, sptr->name, sptr->user->username,
                             NULL);
    return 0;
}

/*
 * m_cap
 * parv[0] = sender prefix
 * parv[1] = subcommand (LS, LIST, REQ, END)
 * parv[2] = LS version or REQ capability list
 */
int
m_cap(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    if (!MyConnect(sptr) || IsServer(sptr))
        return 0;

    if (parc < 2 || BadPtr(parv[1]))
    {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name,
                   cap_nick(sptr), "CAP");
        return 0;
    }

    if (!mycmp(parv[1], "LS"))
        return cap_ls(sptr, parc, parv);
    if (!mycmp(parv[1], "LIST"))
        return cap_list(sptr);
    if (!mycmp(parv[1], "REQ"))
        return cap_req(sptr, parc, parv);
    if (!mycmp(parv[1], "END"))
        return cap_end(cptr, sptr);

    sendto_one(sptr, err_str(ERR_INVALIDCAPCMD), me.name, cap_nick(sptr),
               parv[1]);
    return 0;
}
