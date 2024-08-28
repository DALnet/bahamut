/************************************************************************
 *   IRC - Internet Relay Chat, src/s_capab.c
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

#if defined( HAVE_STRING_H )
#include <string.h>
#else
/* older unices don't have strchr/strrchr .. help them out */
#include <strings.h>
#undef strchr
#define strchr index
#endif

/*
 * m_capab
 * Updated CAPAB implementation to support IRCv3.1
 * The function will parse basic CAPAB commands
 * and set the appropriate flags in the client structure.
 *
 * CAPAB <sub command> :<cap1> <cap2> ... <capN>
 *
 * Server responds to LS, REQ, and END subcommands.
 */
int
m_capab(aClient *cptr, aClient *sptr, int parc, char *parv[])
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
        sendto_one(sptr, form_str(ERR_NEEDMOREPARAMS), me.name, sptr->name, "CAPAB");
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
          snprintf(buf, sizeof(buf), ":%s CAPAB * LS :", sptr->name);

          for (int i = 0; ircv3_capabilities[i].name; i++)
          {
            strncat(buf, client_capabilities[i].name, sizeof(buf) - strlen(buf) - 1);
            if (i < (sizeof(client_capabilities) / sizeof(client_capabilities[0]) - 1))
              strncat(buf, " ", sizeof(buf) - strlen(buf) - 1);
          }

          /* We identify the client as wanting IRCv3 capabilities
           * so that we only call register_user after CAPAB END is received
          */
         sptr->wants_ircv3_caps = 1;

          sendto_one(sptr, buf);
        }
      }
      else if (strcmp(parv[1], "REQ") == 0)
      {
        for (i = 2; i < parc; i++)
        {
          Debug((DEBUG_DEBUG, "CAPAB REQ: %s", parv[i]));
          for (int j = 0; ircv3_capabilities[j].name; j++)
          {
            if (strcmp(parv[i], ircv3_capabilities[j].name) == 0)
            {
              if (ircv3_capabilities[j].set)
                ircv3_capabilities[j].set(cptr, ircv3_capabilities.capability);
              break;
            }
          }
        }
      }
      else if (strcmp(parv[1], "END") == 0)
      {
        /* End capabilities negotiation, register user now
        * but only if NICK and USER were already received. If not,
        * we will let those commands handle it - skill
        */
        if (stpr->name[0] && stpr->user && stpr->user->username[0])
          return register_user(cptr, sptr, sptr->name, stpr->user->username, sptr->hostip);
      }
    } else {
      for (i = 1; i < parc; i++)
      {
          if (strcmp(parv[i], "BURST") == 0)
              SetBurst(sptr);
          else if (strcmp(parv[i], "UNCONNECT") == 0)
              SetUnconnect(cptr);
          else if (strcmp(parv[i], "DKEY") == 0)
              SetDKEY(cptr);
          else if (strcmp(parv[i], "ZIP") == 0)
              SetZipCapable(cptr);
  #ifdef NOQUIT
          else if (strcmp(parv[i], "NOQUIT") == 0)
              SetNoquit(cptr);
  #endif
    else if (strcmp(parv[i], "NICKIPSTR") == 0)
        SetNickIPStr(cptr);
      }
    }

    return 0;
}