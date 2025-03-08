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

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "msg.h"
#include "ircv3.h"

#if defined( HAVE_STRING_H )
#include <string.h>
#else
/* older unices don't have strchr/strrchr .. help them out */
#include <strings.h>
#undef strchr
#define strchr index
#endif

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
        if (ircv3_capabilities && ircv3_capabilities[0].name)
        {
          char buf[BUFSIZE];
          memset(buf, 0, sizeof(buf));

          for (i = 0; ircv3_capabilities[i].name; i++)
          {
            strcat(buf, ircv3_capabilities[i].name);
            if (ircv3_capabilities[i + 1].name)
              strncat(buf, " ", 1);
          }
          strcat(buf, " sasl");

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

        if (strstr(parv[2], "sasl")) {
            sptr->sasl.state = 1;
            sptr->sasl.timeout = NOW + SASL_Timeout;
            sptr->sasl.mechanism = NULL;
        }

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

        sendto_one(sptr, ":%s CAP * %s :%s", me.name, smbcmd, buf);
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