/************************************************************************
 *   IRC - Internet Relay Chat, src/s_ircv3.c
 *   Copyright (C) 1990 Jarkko Oikarinen and
 *                      University of Oulu, Computing Center
 *
 *   See file AUTHORS in IRC package for additional names of
 *   the programmers.
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

#include "config.h"
#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "msg.h"
#include "h.h"

#if defined( HAVE_STRING_H )
#include <string.h>
#else
/* older unices don't have strchr/strrchr .. help them out */
#include <strings.h>
#undef strchr
#define strchr index
#endif

#ifdef IRCV3
#include "ircv3.h"

int cap_set(aClient *, long);
int cap_unset(aClient *, long);


/*
 * m_cap
 * IRCv3 support for capability negotiation
 * We will only support the LS, REQ and END subcommands.
 * Plans are to fully add cap-notify capability - skill
 */
int
m_cap(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    int         i;

    /* If it's not local, or it has already set capabilities,
     * silently ignore it.
     * Dont ignore clients where we have set some capabilities already
     * that would suck for connecting TO servers.
     */

    if(cptr != sptr)
        return 0;

    if (parc < 2)
    {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, sptr->name, "CAP");
        return 0;
    }
    /* Only clients will be sending us IRCv3 CAPAB subcommands */
    if (!IsServer(cptr))
    {
      if (strcmp(parv[1], "LS") == 0)
      {
        /* If we currently support no IRCv3 capabilities, return nothing */
        if (sizeof(ircv3_capabilities) > 0)
        {
          char buf[BUFSIZE];
          memset(buf, 0, sizeof(buf));

          for (i = 0; ircv3_capabilities[i].name; i++)
          {
            strcat(buf, ircv3_capabilities[i].name);
            if (ircv3_capabilities[i + 1].name)
              strncat(buf, " ", 1);
          }

          /* We identify the client as wanting IRCv3 capabilities
           * so that we only call register_user after CAPAB END is received
          */
         sptr->wants_ircv3_caps = 1;

         sendto_one(sptr, ":%s CAP * LS :%s", me.name, buf);
        }
      }
      else if (strcmp(parv[1], "REQ") == 0)
      {
        char buf[BUFSIZE];
        char smbcmd[3] = "ACK";

        memset(buf, 0, sizeof(buf));



        for (i = 2; i < parc; i++)
        {
          int add = 1;

          if (parv[i][0] == '-')
          {
            add = 0;
          }

          Debug((DEBUG_DEBUG, "CAP REQ: %s", parv[i]));
          for (int j = 0; ircv3_capabilities[j].name; j++)
          {
            if (strcmp(parv[i], ircv3_capabilities[j].name) == 0)
            {
              if (add)
              {
                if (!cap_set(sptr, ircv3_capabilities[j].capability))
                {
                  strcat(buf, ircv3_capabilities[j].name);

                } else {
                  Debug((DEBUG_DEBUG, "CAP REQ: %s not supported", parv[i]));
                  strcpy(smbcmd, "NAK");
                  strcat(buf, ircv3_capabilities[j].name);
                }
              } else {
                cap_unset(sptr, ircv3_capabilities[j].capability);
                strcat(buf, ircv3_capabilities[j].name);
              }

              if (i < parc - 1)
                strncat(buf, " ", 1);

              break;
            }
          }
        }

        sendto_one(sptr, ":%s CAP * %s :%s", me.name, subcmd, buf);
      }
      else if (strcmp(parv[1], "END") == 0)
      {
        /* End capabilities negotiation, register user now
        * but only if NICK and USER were already received. If not,
        * we will let those commands handle it - skill
        */
        if (sptr->name[0] && sptr->user && sptr->user->username[0])
          return register_user(cptr, sptr, sptr->name, sptr->user->username, sptr->hostip);
      }
    } else {
      sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, "CAP");
    }

    return 0;
}

/*
 * cap_set
 * Set an IRCV3 capability for a client
*/
int cap_set(aClient *cptr, unsigned int capability)
{
  int set = 0;
  if (cptr->wants_ircv3_caps)
  {
    int i = 0;
    for (i = 0; ircv3_capabilities[i].name; i++)
    {
      if (ircv3_capabilities[i].capability == capability)
      {
        cptr->capabilities |= capability;
        set = 1;
        break;
      }
    }
  }

  return set;
}
/*
  * cap_unset
  * Unset an IRCV3 capability for a client
*/
int cap_unset(aClient *cptr, unsigned int capability)
{
  if (cptr->wants_ircv3_caps)
  {
    for (int i = 0; ircv3_capabilities[i].name; i++)
    {
      if (ircv3_capabilities[i].capability == capability)
      {
        cptr->capabilities &= ~capability;
        break;
      }
    }
  }

  return 0;
}

/*
 * These methods allow the registration of different IRCv3 capabilities and the selection of what
 * IRC messages they want to support. - skill
*/

int ircv3_hook(enum c_ircv3_hooktype hooktype, ...)
{
    va_list vl;
    int ret = 0;


    va_start(vl, hooktype);

    switch(hooktype)
    {
        case IRCV3_HOOK_AWAYNOTIFY_AWAY:
                aClient *cptr = va_arg(vl, aClient *);
                aClient *sptr = va_arg(vl, aClient *);
                char    *message = va_arg(vl, char *);

                for (int i = 0; ircv3_capabilities[i].name; i++)
                {
                    if (ircv3_capabilities[i].capability == CAPAB_AWAYNOTIFY)
                    {
                        int (*rfunc) (aClient *, aClient *, int, char *) = ircv3_capabilities[i].func;
                        if ((ret = (*rfunc)(cptr, sptr, 0, message)) == FLUSH_BUFFER)
                            break;
                    }
                }
                break;
        case IRCV3_HOOK_AWAYNOTIFY_BACK:
                aClient *cptr = va_arg(vl, aClient *);
                aClient *sptr = va_arg(vl, aClient *);

                for (int i = 0; ircv3_capabilities[i].name; i++)
                {
                    if (ircv3_capabilities[i].capability == CAPAB_AWAYNOTIFY)
                    {
                        int (*rfunc) (aClient *, aClient *, int, char *) = ircv3_capabilities[i].func;
                        if ((ret = (*rfunc)(cptr, sptr, 0, NULL)) == FLUSH_BUFFER)
                            break;
                    }
                }
                break;

        default:
          sendto_realops_lev(DEBUG_LEV, "Call for unknown hook type %d",
                hooktype);
            break;

    }

    va_end(vl);

    return ret;
}

typedef struct HashEntry {
    aClient *client;
    struct HashEntry *next;
    // Possibly other members...
} HashEntry;

unsigned int hash_nick(const char *name, unsigned int size)
{
    unsigned int hash = 0;

    while (*name)
    {
        hash = (hash * 33) + (unsigned char)*name++;
    }

    return hash % size;
}

// ... existing code ...
// Check if a client has been notified
static inline int IsNotified(HashEntry *notified_clients, aClient *acptr)
{
    unsigned int hashv = hash_nick(acptr->name, HASHSIZE);
    HashEntry *hptr = &notified_clients[hashv];

    while (hptr)
    {
        if (hptr->client == acptr)
            return 1;
        hptr = hptr->next;
    }
    return 0;
}

// Mark a client as notified
static inline void SetNotified(HashEntry *notified_clients, aClient *acptr)
{
    unsigned int hashv = hash_nick(acptr->name, HASHSIZE);
    HashEntry *hptr = &notified_clients[hashv];

    while (hptr->client && hptr->next)
        hptr = hptr->next;

    if (!hptr->client)
        hptr->client = acptr;
    else
    {
        hptr->next = (HashEntry *)MyMalloc(sizeof(HashEntry));
        hptr->next->client = acptr;
        hptr->next->next = NULL;
    }
}

/*
 * Below section will be to register the methods used to handle the different IRC messages
 * we want to extend IRCv3 capabilites for
*/

/*
 * m_awaynotify
 * Handle the IRCv3 away-notify capability, this is used to notify clients when a user goes
 * away or returns from away. Also, notify channel if user joins with away message set.
 *
 * I can't think of any other way to do this besides iterating through all the channels
 * the user is in and notifying the members. This is ugly, while it saves on bandwidth
 * since clients don't have to do /WHO on join, it's still noisy just like NICK/USER commands. - skill
 * TODO: Find a better way. - skill (2024-07-28)
 * Params:
 *  cptr - The client that is sending the message
 *  sptr - The client that is receiving the message
 *  join - 1 if this is triggered by a JOIN command
 *  away - The away message
*/
int m_awaynotify(aClient *cptr, aClient *sptr, int join, char *away)
{
    Link *lp;
    aClient *acptr;
    int fd;

    // Prepare the AWAY message once
    char away_msg[BUFSIZE];
    if (away)
        snprintf(away_msg, sizeof(away_msg), ":%s!%s@%s AWAY :%s",
                 cptr->name, cptr->user->username, cptr->user->host, away);
    else
        snprintf(away_msg, sizeof(away_msg), ":%s!%s@%s AWAY",
                 cptr->name, cptr->user->username, cptr->user->host);

    // Create a temporary hash table to track notified clients
    HashEntry notified_clients[HASHSIZE];
    memset(notified_clients, 0, sizeof(notified_clients));

    // Iterate through all channels the client is a member of
    for (lp = cptr->user->channel; lp; lp = lp->next)
    {
        aChannel *chptr = lp->value.chptr;

        // Iterate through all members of the channel
        for (fd = 0; fd <= highest_fd; fd++)
        {
            if (!(acptr = local[fd]) || !IsRegistered(acptr) || acptr == cptr)
                continue;

            if (IsMember(acptr, chptr) && !IsNotified(notified_clients, acptr))
            {
                if (HasCapability(acptr, CAPAB_AWAYNOTIFY))
                {
                    sendto_one(acptr, "%s", away_msg);
                }
                SetNotified(notified_clients, acptr);
            }
        }
    }

    return 0;
}


#endif //IRCV3