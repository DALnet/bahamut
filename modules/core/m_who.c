/* modules/core/m_who.c
 *
 * WHO, WHOIS, WHOWAS, USERHOST, USERIP, ISON commands.
 * Extracted from src/m_who.c, src/whowas.c, src/s_user.c.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "inet.h"
#include "channel.h"
#include "h.h"
#include "hooks.h"
#include "hash.h"
#include "send.h"
#include "mapi.h"
#include "cap.h"

/* Externs not covered by public headers */
extern int      user_modes[];
extern Link    *find_channel_link(Link *, aChannel *);
extern unsigned int hash_whowas_name(char *);
extern aWhowas *WHOWASHASH[];

/* File-scope buffer shared by whois/userhost/userip/ison */
static char buf[BUFSIZE], buf2[BUFSIZE];

/* Forward declarations for WHO helpers */
static int  build_searchopts(aClient *, int, char **);
static int  chk_who(aClient *, aClient *, int);
static void who_reply(aClient *sptr, aClient *ac, const char *channel,
                      const char *status);

/* ---------------------------------------------------------------------------
 * WHOX (extended WHO) field bits and state
 * ---------------------------------------------------------------------------*/
#define WHOX_TOKEN    0x001   /* t — query token */
#define WHOX_CHANNEL  0x002   /* c — channel name */
#define WHOX_USER     0x004   /* u — username */
#define WHOX_IP       0x008   /* i — IP address */
#define WHOX_HOST     0x010   /* h — hostname */
#define WHOX_SERVER   0x020   /* s — server name */
#define WHOX_NICK     0x040   /* n — nickname */
#define WHOX_FLAGS    0x080   /* f — flags (HG*@+ etc) */
#define WHOX_HOPS     0x100   /* d — hop count (distance) */
#define WHOX_IDLE     0x200   /* l — idle time */
#define WHOX_ACCOUNT  0x400   /* a — account name */
#define WHOX_REALNAME 0x800   /* r — realname (info) */

static unsigned int whox_fields;      /* 0 = standard WHO; else WHOX active */
static char         whox_token[16];   /* optional query token from %fields,token */

/* Parse a "%tcuihsnfdlar,TOKEN" field string.
 * Sets whox_fields and whox_token.  Returns 1 on success, 0 on parse error. */
static int
parse_whox_fields(const char *s)
{
    const char *p;

    whox_fields = 0;
    whox_token[0] = '\0';

    if (*s != '%')
        return 0;
    s++;

    for (p = s; *p && *p != ','; p++)
    {
        switch (*p)
        {
            case 't': whox_fields |= WHOX_TOKEN;    break;
            case 'c': whox_fields |= WHOX_CHANNEL;  break;
            case 'u': whox_fields |= WHOX_USER;     break;
            case 'i': whox_fields |= WHOX_IP;       break;
            case 'h': whox_fields |= WHOX_HOST;     break;
            case 's': whox_fields |= WHOX_SERVER;   break;
            case 'n': whox_fields |= WHOX_NICK;     break;
            case 'f': whox_fields |= WHOX_FLAGS;    break;
            case 'd': whox_fields |= WHOX_HOPS;     break;
            case 'l': whox_fields |= WHOX_IDLE;     break;
            case 'a': whox_fields |= WHOX_ACCOUNT;  break;
            case 'r': whox_fields |= WHOX_REALNAME; break;
            default:  break;  /* ignore unknown fields */
        }
    }

    if (*p == ',')
    {
        p++;
        strncpy(whox_token, p, sizeof(whox_token) - 1);
        whox_token[sizeof(whox_token) - 1] = '\0';
    }

    return (whox_fields != 0);
}

/* Forward declarations for handlers */
static int m_who(struct MsgBuf *, aClient *, aClient *, int, char **);
static int m_whois(struct MsgBuf *, aClient *, aClient *, int, char **);
static int m_whowas(struct MsgBuf *, aClient *, aClient *, int, char **);
static int m_userhost(struct MsgBuf *, aClient *, aClient *, int, char **);
static int m_userip(struct MsgBuf *, aClient *, aClient *, int, char **);
static int m_ison(struct MsgBuf *, aClient *, aClient *, int, char **);

static const struct mapi_cmd_av2 who_cmds[] = {
    { "WHO", 0, {
        { mg_unreg,   0 }, { m_who,      0 }, { m_who,      0 },
        { m_who,      0 }, { m_who,      0 } }},
    { "WHOIS", 0, {
        { mg_unreg,   0 }, { m_whois,    0 }, { m_whois,    0 },
        { m_whois,    0 }, { m_whois,    0 } }},
    { "WHOWAS", 0, {
        { mg_unreg,   0 }, { m_whowas,   0 }, { m_whowas,   0 },
        { m_whowas,   0 }, { m_whowas,   0 } }},
    { "USERHOST", 0, {
        { mg_unreg,   0 }, { m_userhost, 0 }, { m_userhost, 0 },
        { m_userhost, 0 }, { m_userhost, 0 } }},
    { "USERIP", 0, {
        { mg_unreg,   0 }, { m_userip,   0 }, { m_userip,   0 },
        { m_userip,   0 }, { m_userip,   0 } }},
    { "ISON", 0, {
        { mg_unreg,   0 }, { m_ison,     0 }, { m_ison,     0 },
        { m_ison,     0 }, { m_ison,     0 } }},
    { NULL }
};

DECLARE_CORE_MODULE("m_who", "2.0",
                    "WHO, WHOIS, WHOWAS, USERHOST, USERIP, ISON",
                    who_cmds, NULL);

/* ---------------------------------------------------------------------------
 * WHO implementation (from src/m_who.c)
 * ---------------------------------------------------------------------------*/

static SOpts wsopts;

static int (*gchkfn)(char *, char *);
static int (*nchkfn)(char *, char *);
static int (*uchkfn)(char *, char *);
static int (*hchkfn)(char *, char *);
static int (*ichkfn)(char *, char *);

static int
build_searchopts(aClient *sptr, int parc, char *parv[])
{
  static char *who_oper_help[] =
  {
#ifdef USER_HOSTMASKING
      "/WHO [+|-][acghilmnstuCHIMR] [args]",
#else
      "/WHO [+|-][acghilmnstuCIM] [args]",
#endif
      "Flags are specified like channel modes,",
      "The flags cghimnsu all have arguments",
      "Flags are set to a positive check by +, a negative check by -",
      "The flags work as follows:",
      "Flag a: user is away",
      "Flag c <channel>: user is on <channel>,",
      "                  no wildcards accepted",
      "Flag g <gcos/realname>: user has string <gcos> in their GCOS,",
      "                        wildcards accepted, oper only",
      "Flag h <host>: user has string <host> in their hostname,",
      "               wildcards accepted",
      "Flag i <ip>: user is from <ip>, wildcards and cidr accepted,",
      "Flag m <usermodes>: user has <usermodes> set on them",
      "Flag n <nick>: user has string <nick> in their nickname,",
      "               wildcards accepted",
      "Flag s <server>: user is on server <server>,",
      "                 wildcards not accepted",
      "Flag t <seconds>: (+t) show nicks in use for more than or equal to <seconds> seconds",
      "                  (-t) show nicks in use for less than <seconds> seconds",
      "Flag u <user>: user has string <user> in their username,",
      "               wildcards accepted",
      "Flag T <type>: user is of type <type>, where type is assigned",
      "               by services.",
      "Behavior flags:",
      "Flag C: show first visible channel user is in",
      "Flag M: check for user in channels I am a member of",
      "Flag I: always show IPs instead of hosts",
#ifdef USER_HOSTMASKING
      "Flag H: show the masked host even if the user's host is not masked (umode -H)",
      "Flag R: show the real host even if the user's host is masked (umode +H)",
#endif
      NULL
  };

  static char *who_user_help[] =
  {
      "/WHO [+|-][achmnsuCM] [args]",
      "Flags are specified like channel modes,",
      "The flags cghimnsu all have arguments",
      "Flags are set to a positive check by +, a negative check by -",
      "The flags work as follows:",
      "Flag a: user is away",
      "Flag c <channel>: user is on <channel>,",
      "                  no wildcards accepted",
      "Flag h <host>: user has string <host> in their hostname,",
      "               wildcards accepted",
      "Flag m <usermodes>: user has <usermodes> set on them,",
      "                    only usermodes o/O/a/A will return a result",
      "Flag n <nick>: user has string <nick> in their nickname,",
      "               wildcards accepted",
      "Flag s <server>: user is on server <server>,",
      "                 wildcards not accepted",
      "Flag u <user>: user has string <user> in their username,",
      "               wildcards accepted",
      "Behavior flags:",
      "Flag C: show first visible channel user is in",
      "Flag M: check for user in channels I am a member of",
      NULL
  };

  char *flags, change=1, *s, *err;
  int args=1, i, rval;

  memset((char *)&wsopts, '\0', sizeof(SOpts));
  if(parc < 1 || parv[0][0]=='?')
  {
      char **ptr = NULL;

      if (!IsAnOper(sptr))
       ptr = who_user_help;
      else
       ptr = who_oper_help;

      for (; *ptr; ptr++)
	  sendto_one(sptr, getreply(RPL_COMMANDSYNTAX), me.name,
		     sptr->name, *ptr);
      sendto_one(sptr, getreply(RPL_ENDOFWHO), me.name, sptr->name, "?","WHO");
      return 0;
  }
  else if(parv[0][0]=='0' && parv[0][1]==0)
  {
      if(parc>1 && *parv[1]=='o')
      {
	  wsopts.check_umode=1;
	  wsopts.umode_plus=1;
	  wsopts.umodes=UMODE_o;
      }
      wsopts.host_plus=1;
      wsopts.host="*";
      return 1;
  }
  else if(parv[0][0]!='+' && parv[0][0]!='-')
  {
      if(parv[0][0]=='#' || parv[0][0]=='&')
      {
	  wsopts.channel=find_channel(parv[0],NullChn);
	  if(wsopts.channel==NULL)
	  {
	      sendto_one(sptr, getreply(ERR_NOSUCHCHANNEL), me.name,
			 sptr->name, parv[0]);
	      return 0;
	  }
      }
      else if (IsAnOper(sptr))
      {
	  int bits;

	  bits = inet_parse_cidr(AF_INET, parv[0],
				 &wsopts.cidr_ip, sizeof(wsopts.cidr_ip));
	  if (bits > 0)
	  {
	      wsopts.cidr_family = AF_INET;
	      wsopts.cidr_bits = bits;
	      wsopts.cidr_plus = 1;
	  }
	  else
	  {
	      bits = inet_parse_cidr(AF_INET6, parv[0],
				     &wsopts.cidr_ip, sizeof(wsopts.cidr_ip));
	      if (bits > 0)
	      {
		  wsopts.cidr_family = AF_INET6;
		  wsopts.cidr_bits = bits;
		  wsopts.cidr_plus = 1;
	      }
	      else
	      {
		  if (strchr(parv[0], ':'))
		  {
		      wsopts.ip_plus = 1;
		      wsopts.ip = parv[0];
		  }
		  else if (strchr(parv[0], '.'))
		  {
		      wsopts.host_plus = 1;
		      wsopts.host = parv[0];
		  }
		  else
		  {
		      wsopts.nick_plus = 1;
		      wsopts.nick = parv[0];
		  }
	      }
	  }
      }
      else
      {
	  if (strchr(parv[0], '.') || strchr(parv[0], ':'))
	  {
	      wsopts.host_plus = 1;
	      wsopts.host = parv[0];
	  }
	  else
	  {
	      wsopts.nick_plus = 1;
	      wsopts.nick = parv[0];
	  }
      }
      return 1;
  }
  flags=parv[0];
  while(*flags)
  {
      switch(*flags)
      {
      case '+':
      case '-':
	  change=(*flags=='+' ? 1 : 0);
	  break;
      case 'a':
	  if(change)
	      wsopts.away_plus=1;
	  else
	      wsopts.away_plus=0;
	  wsopts.check_away=1;
	  break;
      case 'C':
	  wsopts.show_chan = change;
	  break;
      case 'M':
	  wsopts.search_chan = change;
	  break;
      case 'c':
	  if(parv[args]==NULL || !change)
	  {
	      sendto_one(sptr, getreply(ERR_WHOSYNTAX), me.name,
			 sptr->name, "WHO", "who");
	      return 0;
	  }
	  if(*parv[args] == '@' || *parv[args] == '+')
	  {
	      char *cname = parv[args] + 1;

              if(*parv[args] == '@')
	      {
		  wsopts.channelflags = CHFL_CHANOP;
		  if(*cname == '+')
		  {
		      wsopts.channelflags |= CHFL_VOICE;
		      cname++;
		  }
	      }
	      else
		  wsopts.channelflags = CHFL_VOICE;

	      wsopts.channel=find_channel(cname, NullChn);
	  }
	  else
	  {
	      wsopts.channelflags = 0;
	      wsopts.channel=find_channel(parv[args],NullChn);
	  }

	  if(wsopts.channel==NULL)
	  {
	      sendto_one(sptr, getreply(ERR_NOSUCHCHANNEL), me.name,
			 sptr->name, parv[args]);
	      return 0;
	  }
	  wsopts.chan_plus=change;
	  args++;
	  break;
      case 'g':
          if(parv[args]==NULL)
          {
              sendto_one(sptr, getreply(ERR_WHOSYNTAX), me.name,
                         sptr->name, "WHO", "who");
              return 0;
          }
          else if(!IsAnOper(sptr))
          {
              sendto_one(sptr, getreply(ERR_NOPRIVILEGES), me.name, parv[0]);
              return 0;
          }
          wsopts.gcos=parv[args];
          wsopts.gcos_plus=change;
          args++;
          break;
      case 'h':
	  if(parv[args]==NULL)
	  {
	      sendto_one(sptr, getreply(ERR_WHOSYNTAX), me.name,
			 sptr->name, "WHO", "who");
	      return 0;
	  }
	  wsopts.host=parv[args];
	  wsopts.host_plus=change;
	  args++;
	  break;
       case 't':
          if(parv[args]==NULL || (rval = strtol(parv[args], &err, 0)) == 0 || *err != '\0')
          {
              sendto_one(sptr, getreply(ERR_WHOSYNTAX), me.name,
                         sptr->name, "WHO", "who");
              return 0;
          }
          else if(!IsAnOper(sptr))
          {
              sendto_one(sptr, getreply(ERR_NOPRIVILEGES), me.name, parv[0]);
              return 0;
          }
          wsopts.ts = rval;
          wsopts.ts_value = change ? 2 : 1;
          args++;
          break;
       case 'T':
          if(parv[args]==NULL || (rval = strtol(parv[args], &err, 0)) == 0 || *err != '\0')
          {
              sendto_one(sptr, getreply(ERR_WHOSYNTAX), me.name,
                         sptr->name, "WHO", "who");
              return 0;
          }
          else if(!IsAnOper(sptr))
          {
              sendto_one(sptr, getreply(ERR_NOPRIVILEGES), me.name, parv[0]);
              return 0;
          }
          wsopts.client_type = rval;
          wsopts.client_type_plus = change ? 1 : 0;
          args++;
          break;
      case 'I':
          if(!IsAnOper(sptr))
          {
              sendto_one(sptr, getreply(ERR_NOPRIVILEGES), me.name, parv[0]);
              return 0;
          }
          wsopts.ip_show = change;
          break;
#ifdef USER_HOSTMASKING
      case 'H':
          if(!IsAnOper(sptr))
          {
              sendto_one(sptr, getreply(ERR_NOPRIVILEGES), me.name, parv[0]);
              return 0;
          }
          wsopts.maskhost_show = change;
          break;
      case 'R':
          if(!IsAnOper(sptr))
          {
              sendto_one(sptr, getreply(ERR_NOPRIVILEGES), me.name, parv[0]);
              return 0;
          }
          wsopts.realhost_show = change;
          break;
#endif
      case 'i':
          if(parv[args]==NULL)
          {
              sendto_one(sptr, getreply(ERR_WHOSYNTAX), me.name,
                         sptr->name, "WHO", "who");
              return 0;
          }
          else if(!IsAnOper(sptr))
          {
              sendto_one(sptr, getreply(ERR_NOPRIVILEGES), me.name, parv[0]);
              return 0;
          }
          else
          {
	      if (strchr(parv[args], '/'))
	      {
		  int bits;

		  bits = inet_parse_cidr(AF_INET, parv[args],
					 &wsopts.cidr_ip,
					 sizeof(wsopts.cidr_ip));
		  if (bits > 0)
		      wsopts.cidr_family = AF_INET;
		  else
		  {
		      bits = inet_parse_cidr(AF_INET6, parv[args],
					     &wsopts.cidr_ip,
					     sizeof(wsopts.cidr_ip));
		      if (bits > 0)
			  wsopts.cidr_family = AF_INET6;
		  }
		  if (bits > 0)
		  {
		      wsopts.cidr_bits = bits;
		      wsopts.cidr_plus = change;
		  }
		  else
                  {
                      sendto_one(sptr, getreply(ERR_WHOSYNTAX), me.name,
                                 sptr->name, "WHO", "who");
                      return 0;
                  }
		  args++;
	      }
              else
              {
                  wsopts.ip=parv[args];
                  wsopts.ip_plus=change;
                  args++;
              }
          }
          break;
      case 'm':
	  if(parv[args]==NULL)
	  {
	      sendto_one(sptr, getreply(ERR_WHOSYNTAX), me.name,
			 sptr->name, "WHO", "who");
	      return 0;
	  }
	  s=parv[args];
	  while(*s)
	  {
	      for(i=1;user_modes[i]!=0x0;i+=2)
	      {
		  if(*s==(char)user_modes[i])
		  {
		      wsopts.umodes|=user_modes[i-1];
		      break;
		  }
	      }
              if(!user_modes[i])
              {
                  sendto_one(sptr, getreply(ERR_WHOSYNTAX), me.name,
                             sptr->name, "WHO", "who");
                  return 0;
              }
	      s++;
	  }
	  if(!IsAnOper(sptr))
	      wsopts.umodes=(wsopts.umodes&(UMODE_o|UMODE_O|UMODE_a|UMODE_A));
	  wsopts.umode_plus=change;
	  if(wsopts.umodes)
	      wsopts.check_umode=1;
	  args++;
	  break;
      case 'n':
	  if(parv[args]==NULL)
	  {
	      sendto_one(sptr, getreply(ERR_WHOSYNTAX), me.name,
			 sptr->name, "WHO", "who");
	      return 0;
	  }
	  wsopts.nick=parv[args];
	  wsopts.nick_plus=change;
	  args++;
	  break;
      case 's':
	  if(parv[args]==NULL || !change)
	  {
	      sendto_one(sptr, getreply(ERR_WHOSYNTAX), me.name,
			 sptr->name, "WHO", "who");
	      return 0;
	  }
	  wsopts.server=find_server(parv[args],NULL);
	  if(wsopts.server==NULL)
	  {
	      sendto_one(sptr, getreply(ERR_NOSUCHSERVER), me.name,
			 sptr->name, parv[args]);
	      return 0;
	  }
	  wsopts.serv_plus=change;
	  args++;
	  break;
      case 'u':
	  if(parv[args]==NULL)
	  {
	      sendto_one(sptr, getreply(ERR_WHOSYNTAX), me.name,
			 sptr->name, "WHO", "who");
	      return 0;
	  }
	  wsopts.user=parv[args];
	  wsopts.user_plus=change;
	  args++;
	  break;
      default:
	  sendto_one(sptr, getreply(ERR_WHOSYNTAX), me.name,
		     sptr->name, "WHO", "who");
	  return 0;
      }
      flags++;
  }

  if(wsopts.search_chan && !(wsopts.check_away || wsopts.gcos_plus ||
			     wsopts.host_plus || wsopts.check_umode ||
			     wsopts.serv_plus || wsopts.nick_plus ||
			     wsopts.user_plus || wsopts.ts_value ||
                 wsopts.client_type_plus || wsopts.ip_plus))
  {
      if(parv[args]==NULL || wsopts.channel || wsopts.nick ||
	 parv[args][0] == '#' || parv[args][0] == '&')
      {
	  sendto_one(sptr, getreply(ERR_WHOSYNTAX), me.name, sptr->name, "WHO",
                 "who");
	  return 0;
      }

      if (strchr(parv[args], '.'))
      {
	  wsopts.host_plus=1;
	  wsopts.host=parv[args];
      }
      else
      {
	  sendto_one(sptr, getreply(ERR_WHOSYNTAX), me.name, sptr->name, "WHO",
                 "who");
	  return 0;
      }
  }
  else if(wsopts.show_chan && !(wsopts.check_away || wsopts.gcos_plus ||
			       wsopts.host_plus || wsopts.check_umode ||
			       wsopts.serv_plus || wsopts.nick_plus ||
			       wsopts.user_plus || wsopts.ts_value ||
                   wsopts.client_type_plus || wsopts.ip_plus ||
                   wsopts.chan_plus || wsopts.cidr_bits))
  {
      if(parv[args]==NULL)
      {
	  sendto_one(sptr, getreply(ERR_WHOSYNTAX), me.name, sptr->name, "WHO",
                     "who");
	  return 0;
      }

      if (strchr(parv[args], '.'))
      {
	  wsopts.host_plus=1;
	  wsopts.host=parv[args];
      }
      else
      {
	  wsopts.nick_plus=1;
	  wsopts.nick=parv[args];
      }
  }

  if(parc > args)
  {
      sendto_one(sptr, getreply(ERR_WHOSYNTAX), me.name, sptr->name, "WHO",
             "who");
      return 0;
  }

  return 1;
}

static int
chk_who(aClient *ac, aClient *sptr, int showall)
{
    if(!IsClient(ac))
	return 0;
    if(IsInvisible(ac) && !showall)
	return 0;

    if(wsopts.client_type_plus &&
	wsopts.client_type != ac->user->servicetype)
	return 0;

    if(wsopts.check_umode)
	if((wsopts.umode_plus &&
	    !((ac->umode&wsopts.umodes)==wsopts.umodes)) ||
	   (!wsopts.umode_plus && ((ac->umode&wsopts.umodes)==wsopts.umodes)))
	    return 0;

    if(wsopts.check_away)
	if((wsopts.away_plus && ac->user->away==NULL) ||
	   (!wsopts.away_plus && ac->user->away!=NULL))
	    return 0;

    if(wsopts.serv_plus)
    {
	if(wsopts.server != ac->uplink)
	    return 0;
	if(IsUmodeI(ac) && !showall)
	    return 0;
    }
    if(wsopts.user!=NULL)
	if((wsopts.user_plus && uchkfn(wsopts.user, ac->user->username)) ||
	   (!wsopts.user_plus && !uchkfn(wsopts.user, ac->user->username)))
	    return 0;

    if(wsopts.nick!=NULL)
        if((wsopts.nick_plus && nchkfn(wsopts.nick, ac->name)) ||
           (!wsopts.nick_plus && !nchkfn(wsopts.nick, ac->name)))
            return 0;

    if(wsopts.host!=NULL)
    {
#ifdef USER_HOSTMASKING
        if(IsAnOper(sptr))
        {
	    if((wsopts.host_plus && hchkfn(wsopts.host, ac->user->host) && hchkfn(wsopts.host, ac->user->mhost)) ||
	       (!wsopts.host_plus && (!hchkfn(wsopts.host, ac->user->host) || !hchkfn(wsopts.host, ac->user->mhost))))
	        return 0;
        }
        else
        {
	    if((wsopts.host_plus && hchkfn(wsopts.host, IsUmodeH(ac)?ac->user->mhost:ac->user->host)) ||
	       (!wsopts.host_plus && !hchkfn(wsopts.host, IsUmodeH(ac)?ac->user->mhost:ac->user->host)))
	        return 0;
        }
#else
        if((wsopts.host_plus && hchkfn(wsopts.host, ac->user->host)) ||
           (!wsopts.host_plus && !hchkfn(wsopts.host, ac->user->host)))
            return 0;
#endif
    }

    if(wsopts.cidr_plus)
	if(ac->ip_family != wsopts.cidr_family ||
	   bitncmp(&ac->ip, &wsopts.cidr_ip, wsopts.cidr_bits) != 0)
	    return 0;

    if(wsopts.ip_plus)
	if(ichkfn(wsopts.ip, ac->hostip))
	    return 0;

    if(wsopts.gcos!=NULL)
	if((wsopts.gcos_plus && gchkfn(wsopts.gcos, ac->info)) ||
	   (!wsopts.gcos_plus && !gchkfn(wsopts.gcos, ac->info)))
	    return 0;

    if(wsopts.ts_value == 2 && NOW - ac->tsinfo < wsopts.ts)
        return 0;
    else if(wsopts.ts_value == 1 && NOW - ac->tsinfo >= wsopts.ts)
        return 0;

    return 1;
}

static inline char *
first_visible_channel(aClient *cptr, aClient *sptr)
{
    Link *lp;
    int secret = 0;
    aChannel *chptr = NULL;
    static char chnbuf[CHANNELLEN + 2];

    if(cptr->user->channel)
    {
	if(IsAdmin(sptr))
	{
	    chptr = cptr->user->channel->value.chptr;
	    if(!(ShowChannel(sptr, chptr)))
		secret = 1;
	}
	else
	{
	    for(lp = cptr->user->channel; lp; lp = lp->next)
	    {
		if(ShowChannel(sptr, lp->value.chptr))
		    break;
	    }
	    if(lp)
		chptr = lp->value.chptr;
	}

	if(chptr)
	{
	    if(!secret)
		return chptr->chname;
	    ircsprintf(chnbuf, "%%%s", chptr->chname);
	    return chnbuf;
	}
    }
    return "*";
}

#define MAXWHOREPLIES 200
#define WHO_HOPCOUNT(s, a) \
    (((IsULine((a)) || IsUmodeI((a))) && !IsAnOper((s))) ? 0 : (a)->hopcount)
#define WHO_SERVER(s, a) \
    ((IsUmodeI((a)) && !IsAnOper((s))) ? HIDDEN_SERVER_NAME : (a)->user->server)
#ifdef USER_HOSTMASKING
#define WHO_HOST(s, a) \
    ((wsopts.ip_show) ? (a)->hostip \
     : ((IsUmodeH((a)) && !wsopts.realhost_show) || wsopts.maskhost_show) \
       ? (a)->user->mhost : (a)->user->host)
#else
#define WHO_HOST(s, a) ((wsopts.ip_show) ? (a)->hostip : (a)->user->host)
#endif

/* ---------------------------------------------------------------------------
 * who_reply() — send either standard RPL_WHOREPLY (352) or WHOX (354)
 * depending on whox_fields.
 * ---------------------------------------------------------------------------*/
static void
who_reply(aClient *sptr, aClient *ac, const char *channel, const char *status)
{
    if (whox_fields == 0)
    {
        /* Standard WHO reply */
        sendto_one(sptr, getreply(RPL_WHOREPLY), me.name, sptr->name,
                   channel, ac->user->username,
                   WHO_HOST(sptr, ac), WHO_SERVER(sptr, ac), ac->name, status,
                   WHO_HOPCOUNT(sptr, ac),
                   ac->info);
        return;
    }

    /* WHOX reply — build RPL_WHOSPCRPL (354) dynamically */
    {
        char reply[512];
        int pos;

        pos = snprintf(reply, sizeof(reply), ":%s 354 %s",
                       me.name, sptr->name);

        if ((whox_fields & WHOX_TOKEN) && whox_token[0])
            pos += snprintf(reply + pos, sizeof(reply) - pos,
                            " %s", whox_token);
        if (whox_fields & WHOX_CHANNEL)
            pos += snprintf(reply + pos, sizeof(reply) - pos,
                            " %s", channel);
        if (whox_fields & WHOX_USER)
            pos += snprintf(reply + pos, sizeof(reply) - pos,
                            " %s", ac->user->username);
        if (whox_fields & WHOX_IP)
            pos += snprintf(reply + pos, sizeof(reply) - pos,
                            " %s", IsAnOper(sptr) ? ac->hostip : "255.255.255.255");
        if (whox_fields & WHOX_HOST)
            pos += snprintf(reply + pos, sizeof(reply) - pos,
                            " %s", WHO_HOST(sptr, ac));
        if (whox_fields & WHOX_SERVER)
            pos += snprintf(reply + pos, sizeof(reply) - pos,
                            " %s", WHO_SERVER(sptr, ac));
        if (whox_fields & WHOX_NICK)
            pos += snprintf(reply + pos, sizeof(reply) - pos,
                            " %s", ac->name);
        if (whox_fields & WHOX_FLAGS)
            pos += snprintf(reply + pos, sizeof(reply) - pos,
                            " %s", status);
        if (whox_fields & WHOX_HOPS)
            pos += snprintf(reply + pos, sizeof(reply) - pos,
                            " %d", WHO_HOPCOUNT(sptr, ac));
        if (whox_fields & WHOX_IDLE)
        {
            if (MyClient(ac) && ac->user)
                pos += snprintf(reply + pos, sizeof(reply) - pos,
                                " %ld", (long)(timeofday - ac->user->last));
            else
                pos += snprintf(reply + pos, sizeof(reply) - pos, " 0");
        }
        if (whox_fields & WHOX_ACCOUNT)
        {
            const char *acct = (ac->user->account_name[0])
                                ? ac->user->account_name : "0";
            pos += snprintf(reply + pos, sizeof(reply) - pos,
                            " %s", acct);
        }
        if (whox_fields & WHOX_REALNAME)
            pos += snprintf(reply + pos, sizeof(reply) - pos,
                            " :%s", ac->info);

        (void)pos;
        sendto_one(sptr, "%s", reply);
    }
}

static int
m_who(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aClient *ac;
    chanMember *cm;
    Link *lp;
    int shown=0, i=0, showall=IsAnOper(sptr);
    char status[8];
    int whox_arg = 0;  /* index of %fields arg, if found */

    if(!MyClient(sptr))
	return 0;

    /* Scan for a WHOX %fields argument before build_searchopts */
    whox_fields = 0;
    whox_token[0] = '\0';
    {
        int j;
        for (j = 1; j < parc; j++)
        {
            if (parv[j] && parv[j][0] == '%')
            {
                parse_whox_fields(parv[j]);
                whox_arg = j;
                break;
            }
        }
        /* Remove the %fields arg from parv so build_searchopts doesn't see it */
        if (whox_arg)
        {
            for (j = whox_arg; j < parc - 1; j++)
                parv[j] = parv[j + 1];
            parv[parc - 1] = NULL;
            parc--;
        }
    }

    if(!build_searchopts(sptr, parc-1, parv+1))
	return 0;

    if(wsopts.gcos!=NULL && (strchr(wsopts.gcos, '?'))==NULL &&
       (strchr(wsopts.gcos, '*'))==NULL)
	gchkfn=mycmp;
    else
	gchkfn=match;
    if(wsopts.nick!=NULL && (strchr(wsopts.nick, '?'))==NULL &&
       (strchr(wsopts.nick, '*'))==NULL)
	nchkfn=mycmp;
    else
	nchkfn=match;
    if(wsopts.user!=NULL && (strchr(wsopts.user, '?'))==NULL &&
       (strchr(wsopts.user, '*'))==NULL)
	uchkfn=mycmp;
    else
	uchkfn=match;
    if(wsopts.host!=NULL && (strchr(wsopts.host, '?'))==NULL &&
       (strchr(wsopts.host, '*'))==NULL)
	hchkfn=mycmp;
    else
	hchkfn=match;
    if(wsopts.ip!=NULL && (strchr(wsopts.ip, '?'))==NULL &&
       (strchr(wsopts.ip, '*'))==NULL)
	ichkfn=mycmp;
    else
	ichkfn=match;

    if(wsopts.channel!=NULL)
    {
	if(IsMember(sptr,wsopts.channel) && (!(wsopts.channel->mode.mode & MODE_AUDITORIUM) ||
           is_chan_opvoice(sptr, wsopts.channel) || IsAnOper(sptr)))
	    showall=1;
	else if(SecretChannel(wsopts.channel) && IsAdmin(sptr))
	    showall=1;
	else if(!SecretChannel(wsopts.channel) && IsAnOper(sptr))
	    showall=1;
	else
	    showall=0;
	if(showall || !SecretChannel(wsopts.channel))
	{
	    for(cm=wsopts.channel->members; cm; cm=cm->next)
	    {
		ac=cm->cptr;
		i=0;
		if(!chk_who(ac,sptr,showall))
		    continue;
		if(wsopts.channelflags && ((cm->flags & wsopts.channelflags) == 0))
		    continue;
		status[i++] = (ac->user->away == NULL ? 'H' : 'G');
		if (IsAnOper(ac))
		    status[i++] = '*';
		else if (IsInvisible(ac) && IsOper(sptr))
		    status[i++] = '%';
		if (HasCap(sptr, cap_multi_prefix_bit))
		{
		    if (cm->flags & CHFL_CHANOP)   status[i++] = '@';
#ifdef USE_HALFOPS
		    if (cm->flags & CHFL_HALFOP)   status[i++] = '%';
#endif
		    if (cm->flags & CHFL_VOICE)    status[i++] = '+';
		}
		else
		{
		    if (cm->flags & CHFL_CHANOP)        status[i++] = '@';
#ifdef USE_HALFOPS
		    else if (cm->flags & CHFL_HALFOP)   status[i++] = '%';
#endif
		    else if (cm->flags & CHFL_VOICE)    status[i++] = '+';
		}
		status[i] = 0;
		who_reply(sptr, ac, wsopts.channel->chname, status);
	    }
	}
	sendto_one(sptr, getreply(RPL_ENDOFWHO), me.name, sptr->name,
		   wsopts.channel->chname, "WHO");
	return 0;
    }
    else if(nchkfn==mycmp)
    {
	ac=find_person(wsopts.nick,NULL);
	if(ac!=NULL)
	{
	    if(!chk_who(ac,sptr,1))
	    {
		sendto_one(sptr, getreply(RPL_ENDOFWHO), me.name, sptr->name,
			   wsopts.host!=NULL ? wsopts.host : wsopts.nick, "WHO");
		return 0;
	    }
	    else
	    {
		status[0]=(ac->user->away==NULL ? 'H' : 'G');
		status[1]=(IsAnOper(ac) ? '*' : (IsInvisible(ac) &&
						 IsAnOper(sptr) ? '%' : 0));
		status[2]=0;
		who_reply(sptr, ac,
			  wsopts.show_chan ? first_visible_channel(ac, sptr) : "*",
			  status);
		sendto_one(sptr, getreply(RPL_ENDOFWHO), me.name, sptr->name,
			   wsopts.host!=NULL ? wsopts.host : wsopts.nick, "WHO");
		return 0;
	    }
	}
	sendto_one(sptr, getreply(RPL_ENDOFWHO), me.name, sptr->name,
		   wsopts.host!=NULL ? wsopts.host : wsopts.nick, "WHO");
	return 0;
    }

    if(wsopts.search_chan)
    {
	for(lp = sptr->user->channel; lp; lp = lp->next)
	{
	    for(cm = lp->value.chptr->members; cm; cm = cm->next)
	    {
		ac = cm->cptr;
		if(!chk_who(ac, sptr, 1))
		    continue;

		if(shown==MAXWHOREPLIES && !IsAnOper(sptr))
		{
		    sendto_one(sptr, getreply(ERR_WHOLIMEXCEED), me.name,
			       sptr->name, MAXWHOREPLIES, "WHO");
		    break;
		}

		i = 0;
		status[i++] = (ac->user->away == NULL ? 'H' : 'G');
		if (IsAnOper(ac))
		    status[i++] = '*';
		else if (IsInvisible(ac) && IsOper(sptr))
		    status[i++] = '%';
		if (HasCap(sptr, cap_multi_prefix_bit))
		{
		    if (cm->flags & CHFL_CHANOP)   status[i++] = '@';
#ifdef USE_HALFOPS
		    if (cm->flags & CHFL_HALFOP)   status[i++] = '%';
#endif
		    if (cm->flags & CHFL_VOICE)    status[i++] = '+';
		}
		else
		{
		    if (cm->flags & CHFL_CHANOP)        status[i++] = '@';
#ifdef USE_HALFOPS
		    else if (cm->flags & CHFL_HALFOP)   status[i++] = '%';
#endif
		    else if (cm->flags & CHFL_VOICE)    status[i++] = '+';
		}
		status[i] = 0;
		who_reply(sptr, ac, lp->value.chptr->chname, status);
		shown++;
	    }
	}
    }
    else
    {
	for(ac=client;ac;ac=ac->next)
	{
	    if(!chk_who(ac,sptr,showall))
		continue;
	    if(shown==MAXWHOREPLIES && !IsAnOper(sptr))
	    {
		sendto_one(sptr, getreply(ERR_WHOLIMEXCEED), me.name,
			   sptr->name, MAXWHOREPLIES, "WHO");
		break;
	    }
	    status[0]=(ac->user->away==NULL ? 'H' : 'G');
	    status[1]=(IsAnOper(ac) ? '*' : (IsInvisible(ac) &&
					     IsAnOper(sptr) ? '%' : 0));
	    status[2]=0;
	    who_reply(sptr, ac,
		      wsopts.show_chan ? first_visible_channel(ac, sptr) : "*",
		      status);
	    shown++;
	}
    }
    sendto_one(sptr, getreply(RPL_ENDOFWHO), me.name, sptr->name,
	       (wsopts.host!=NULL ? wsopts.host :
		(wsopts.nick!=NULL ? wsopts.nick :
		 (wsopts.user!=NULL ? wsopts.user :
		  (wsopts.gcos!=NULL ? wsopts.gcos :
		   (wsopts.server!=NULL ? wsopts.server->name :
		    "*"))))), "WHO");
    return 0;
}

/* ---------------------------------------------------------------------------
 * WHOIS (from src/s_user.c)
 * ---------------------------------------------------------------------------*/

static int
m_whois(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    Link   *lp;
    anUser *user;
    aClient    *acptr, *a2cptr;
    aChannel   *chptr;
    char       *nick, *tmp, *name;
    char       *p = NULL;
    ServicesTag *servicestag;
    int         len, mlen;

    if (parc < 2)
    {
        sendto_one(sptr, err_str(ERR_NONICKNAMEGIVEN),
                   me.name, parv[0]);
        return 0;
    }

    if (parc > 2)
    {
#ifdef NO_USER_OPERTARGETED_COMMANDS
        if(!IsAnOper(sptr))
        {
            acptr = hash_find_client(parv[2], (aClient *) NULL);
            if (!acptr || !IsPerson(acptr))
            {
                sendto_one(sptr, err_str(ERR_NOSUCHNICK),
                           me.name, parv[0], parv[2]);
                return 0;
            }

            if(IsUmodeI(acptr))
            {
                if(mycmp(parv[1], parv[2]) == 0)
                    parv[1] = acptr->user->server;
                else if(MyClient(sptr))
                {
                    sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name,
                               parv[0]);
                    return 0;
                }
            }
        }
#endif
        if (hunt_server(cptr, sptr, ":%s WHOIS %s :%s", 1, parc, parv) !=
            HUNTED_ISME)
            return 0;
        parv[1] = parv[2];
    }

    for (p = NULL, tmp = parv[1]; (nick = strtoken(&p, tmp, ",")); tmp = NULL)
    {
        int showchan;

        acptr = hash_find_client(nick, (aClient *) NULL);
        if (!acptr || !IsPerson(acptr))
        {
            sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name, parv[0], nick);
            continue;
        }

        if (call_hooks(CHOOK_WHOIS, sptr, acptr) == FLUSH_BUFFER) continue;

        user = acptr->user;
        name = (!*acptr->name) ? "?" : acptr->name;

        a2cptr = acptr->uplink;

        sendto_one(sptr, rpl_str(RPL_WHOISUSER), me.name, parv[0], name,
                   user->username,
#ifdef USER_HOSTMASKING
                   IsUmodeH(acptr)?user->mhost:
#endif
                   user->host, acptr->info);
        if(IsUmodeH(acptr) && (sptr==acptr || IsAnOper(sptr)))
        {
            sendto_one(sptr, rpl_str(RPL_WHOISACTUALLY), me.name,
                       sptr->name, name, user->username, user->host,
                       acptr->hostip);
        }
#if (RIDICULOUS_PARANOIA_LEVEL>=1)
#if (RIDICULOUS_PARANOIA_LEVEL==1)
        if(MyConnect(acptr) && user->real_oper_host &&
                (IsAdmin(sptr) || (sptr == acptr)))
            sendto_one(sptr, rpl_str(RPL_WHOISACTUALLY), me.name, sptr->name,
                       name, user->real_oper_username, user->real_oper_host,
                       user->real_oper_ip);
#endif
#if (RIDICULOUS_PARANOIA_LEVEL==2)
        if(MyConnect(acptr) && user->real_oper_host &&
                (IsAdmin(sptr) || (sptr == acptr)) && MyConnect(sptr))
            sendto_one(sptr, rpl_str(RPL_WHOISACTUALLY), me.name, sptr->name,
                       name, user->real_oper_username, user->real_oper_host,
                       user->real_oper_ip);
#endif
#endif
        mlen = strlen(me.name) + strlen(parv[0]) + 9 + strlen(name);
        for (len = 0, *buf = '\0', lp = user->channel; lp; lp = lp->next)
        {
            chptr = lp->value.chptr;
            showchan=ShowChannel(sptr,chptr);
            if (showchan || IsAdmin(sptr))
            {
                if (len + strlen(chptr->chname) > (size_t) BUFSIZE - 4 - mlen)
                {
                    sendto_one(sptr, rpl_str(RPL_WHOISCHANNELS), me.name, parv[0], name, buf);
                    *buf = '\0';
                    len = 0;
                }
                if(!showchan)
#ifdef USE_HALFOPS
                    *(buf + len++) = '~';
#else
                    *(buf + len++) = '%';
#endif
                if (is_chan_op(acptr, chptr))
                    *(buf + len++) = '@';
#ifdef USE_HALFOPS
                else if (is_chan_halfop(acptr, chptr))
                    *(buf + len++) = '%';
#endif
                else if (has_voice(acptr, chptr))
                    *(buf + len++) = '+';
                if (len)
                    *(buf + len) = '\0';
                strcpy(buf + len, chptr->chname);
                len += strlen(chptr->chname);
                strcat(buf + len, " ");
                len++;
            }
        }
        if (buf[0] != '\0')
            sendto_one(sptr, rpl_str(RPL_WHOISCHANNELS), me.name,
                       parv[0], name, buf);
        if(!(IsUmodeI(acptr) && !IsAnOper(sptr)) || (acptr == sptr))
        {
             sendto_one(sptr, rpl_str(RPL_WHOISSERVER), me.name, parv[0], name,
                     user->server, a2cptr ? a2cptr->info : "*Not On This Net*");
        }
        else
        {
             sendto_one(sptr, rpl_str(RPL_WHOISSERVER), me.name, parv[0],
                        name, HIDDEN_SERVER_NAME, HIDDEN_SERVER_DESC);
        }

        if(IsAnOper(sptr) && IsSquelch(acptr))
            sendto_one(sptr, rpl_str(RPL_WHOISTEXT), me.name, parv[0], name,
                       IsWSquelch(acptr) ?  "User is squelched (warned)" :
                       "User is squelched (silent)");

        if(IsRegNick(acptr))
            sendto_one(sptr, rpl_str(RPL_WHOISREGNICK), me.name, parv[0], name);
        if (user->away)
            sendto_one(sptr, rpl_str(RPL_AWAY), me.name, parv[0], name,
                       user->away);
        if(IsUmodeS(acptr))
            sendto_one(sptr, rpl_str(RPL_USINGSSL), me.name, parv[0], name);
        if(MyConnect(acptr) && acptr->certfp[0])
            sendto_one(sptr, rpl_str(RPL_WHOISCERTFP), me.name, parv[0], name, acptr->certfp);

        buf[0] = '\0';
        if (IsAnOper(acptr))
            strcat(buf, "an IRC Operator");
        if (IsAdmin(acptr))
            strcat(buf, " - Server Administrator");
        else if (IsSAdmin(acptr))
            strcat(buf, " - Services Administrator");
        if (buf[0] && (!acptr->user->servicestag || acptr->user->servicestag->raw!=RPL_WHOISOPERATOR))
            sendto_one(sptr, rpl_str(RPL_WHOISOPERATOR), me.name, parv[0],
                       name, buf);

        if(acptr->user->servicestag)
        {
            servicestag = acptr->user->servicestag;
            while(servicestag)
            {
                if(*servicestag->tag && (!servicestag->umode || (sptr->umode & servicestag->umode)))
                    sendto_one(sptr, ":%s %d %s %s :%s", me.name,
                               servicestag->raw, parv[0], name, servicestag->tag);
                servicestag = servicestag->next;
            }
        }

	if (MyConnect(acptr) && acptr->webirc_ip && IsAdmin(sptr))
	{
            sendto_one(sptr, ":%s 337 %s %s :%s (%s@%s)",
		       me.name, parv[0], name,
		       "User connected using a webirc gateway",
		       acptr->webirc_username, acptr->webirc_ip);
	}
	else if (MyConnect(acptr) && acptr->webirc_ip && IsAnOper(sptr))
	{
            sendto_one(sptr, ":%s 337 %s %s :%s (%s)",
		       me.name, parv[0], name,
		       "User connected using a webirc gateway",
		       acptr->webirc_username);
	}

        if(IsAdmin(sptr))
        {
            buf2[0]='\0';
            send_umode(NULL, acptr, 0, ALL_UMODES, buf2, sizeof(buf2));
            if (!*buf2)
            {
                buf2[0] = '+';
                buf2[1] = '\0';
            }
            sendto_one(sptr, rpl_str(RPL_WHOISMODES), me.name, parv[0], name, buf2);
        }

        if (acptr->user && MyConnect(acptr) && ((sptr == acptr) ||
                !IsUmodeI(acptr) || (parc > 2) || IsAnOper(sptr)))
            sendto_one(sptr, rpl_str(RPL_WHOISIDLE), me.name, parv[0], name,
                       timeofday - user->last, acptr->firsttime);

        continue;
    }
    sendto_one(sptr, rpl_str(RPL_ENDOFWHOIS), me.name, parv[0], parv[1]);
    return 0;
}

/* ---------------------------------------------------------------------------
 * WHOWAS (from src/whowas.c)
 * ---------------------------------------------------------------------------*/

/*
 * m_whowas
 * parv[0] = sender prefix
 * parv[1] = nickname queried
 */
static int
m_whowas(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aWhowas *temp;
    int cur = 0;
    int         max = -1, found = 0;
    char       *p, *nick, *s;

    if (parc < 2)
    {
	sendto_one(sptr, err_str(ERR_NONICKNAMEGIVEN),
		   me.name, parv[0]);
	return 0;
    }
    if (parc > 2)
	max = atoi(parv[2]);
    if (parc > 3)
	if (hunt_server(cptr, sptr, ":%s WHOWAS %s %s :%s", 3, parc, parv))
	    return 0;

    parv[1] = canonize(parv[1]);
    if (!MyConnect(sptr) && (max > 20))
	max = 20;
    for (s = parv[1]; (nick = strtoken(&p, s, ",")); s = NULL)
    {
	temp = WHOWASHASH[hash_whowas_name(nick)];
	found = 0;
	for (; temp; temp = temp->next)
	{
	    if (!mycmp(nick, temp->name))
	    {
		sendto_one(sptr, rpl_str(RPL_WHOWASUSER),
			   me.name, parv[0], temp->name,
			   temp->username,
#ifdef USER_HOSTMASKING
			   (temp->umode & UMODE_H)?temp->mhostname:
#endif
                                                                   temp->hostname,
			   temp->realname);
#ifdef USER_HOSTMASKING
                if((temp->umode & UMODE_H) && IsAnOper(sptr))
                {
                    sendto_one(sptr, rpl_str(RPL_WHOISACTUALLY), me.name, sptr->name,
                               temp->name, "*", temp->hostname, temp->hostip);
                }
#endif
		if((temp->umode & UMODE_I) && !IsAnOper(sptr))
		    sendto_one(sptr, rpl_str(RPL_WHOISSERVER),
			       me.name, parv[0], temp->name,
			       HIDDEN_SERVER_NAME, myctime(temp->logoff));
		else
		    sendto_one(sptr, rpl_str(RPL_WHOISSERVER),
			       me.name, parv[0], temp->name,
			       temp->servername, myctime(temp->logoff));
		cur++;
		found++;
	    }
	    if (max > 0 && cur >= max)
		break;
	}
	if (!found)
	    sendto_one(sptr, err_str(ERR_WASNOSUCHNICK),
		       me.name, parv[0], nick);
	if (p)
	    p[-1] = ',';
    }
    sendto_one(sptr, rpl_str(RPL_ENDOFWHOWAS), me.name, parv[0], parv[1]);
    return 0;
}

/* ---------------------------------------------------------------------------
 * USERHOST, USERIP, ISON (from src/s_user.c)
 * ---------------------------------------------------------------------------*/

/*
 * m_userhost added by Darren Reed 13/8/91 to aid clients and reduce
 * the need for complicated requests like WHOIS.
 */
static int
m_userhost(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    char *s, *p = NULL;
    aClient *acptr;
    int i, len, res = 0;

    ircsprintf(buf, rpl_str(RPL_USERHOST), me.name, parv[0]);
    len = strlen(buf);

    for (i = 5, s = strtoken(&p, parv[1], " "); i && s;
         s = strtoken(&p, (char *) NULL, " "), i--)
        if ((acptr = find_person(s, NULL)))
        {
            if (++res > 1)
                buf[len++] = ' ';
            len += ircsnprintf(buf + len, sizeof(buf) - (len + 1),
                               "%s%s=%c%s@%s", acptr->name,
                              IsAnOper(acptr) ? "*" : "",
                              (acptr->user->away) ? '-' : '+',
                              acptr->user->username,
#ifdef USER_HOSTMASKING
                              (IsUmodeH(acptr) && sptr!=acptr)?acptr->user->mhost:
#endif
                              acptr->user->host);
        }
    sendto_one(sptr, "%s", buf);
    return 0;
}

static int
m_userip(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    char *s, *p = NULL;
    aClient *acptr;
    int i, len, res = 0;

    ircsprintf(buf, rpl_str(RPL_USERHOST), me.name, parv[0]);
    len = strlen(buf);

    for (i = 5, s = strtoken(&p, parv[1], " "); i && s;
         s = strtoken(&p, (char *) NULL, " "), i--)
        if ((acptr = find_person(s, NULL)))
        {
            if (++res > 1)
               buf[len++] = ' ';
            len += ircsnprintf(buf + len, sizeof(buf) - (len + 1),
                               "%s%s=%c%s@%s", acptr->name,
                              IsAnOper(acptr) ? "*" : "",
                              (acptr->user->away) ? '-' : '+',
                              acptr->user->username,
                              IsULine(acptr) ? "0.0.0.0" :
                              (IsUmodeH(acptr) && sptr!=acptr) ? "127.0.0.1" : acptr->hostip);
        }
    sendto_one(sptr, "%s", buf);
    return 0;
}

/*
 * m_ison added by Darren Reed 13/8/91 to act as an efficient user
 * indicator with respect to cpu/bandwidth used.
 *
 * format: ISON :nicklist
 */
static int
m_ison(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aClient *acptr;
    char   *s, **pav = parv;
    char       *p = (char *) NULL;
    size_t     len, len2;

    if (parc < 2)
    {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0], "ISON");
        return 0;
    }

    ircsprintf(buf, rpl_str(RPL_ISON), me.name, *parv);
    len = strlen(buf);
    if (!IsOper(cptr))
        cptr->priority += 20;
    for (s = strtoken(&p, *++pav, " "); s;
         s = strtoken(&p, (char *) NULL, " "))
        if ((acptr = find_person(s, NULL)))
        {
            len2 = strlen(acptr->name);
            if ((len + len2 + 5) < sizeof(buf))
            {
                strcat(buf, acptr->name);
                len += len2;
                strcat(buf, " ");
                len++;
            }
            else
                break;
        }
    sendto_one(sptr, "%s", buf);
    return 0;
}
