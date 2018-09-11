/*
 *   IRC - Internet Relay Chat, src/channel.c
 *   Copyright (C) 1990 Jarkko Oikarinen and
 *                      University of Oulu, Co Center
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
#include "channel.h"
#include "h.h"
#include "userban.h"
#include "memcount.h"
#include "hooks.h"
#include "spamfilter.h"

int         server_was_split = YES;

aChannel   *channel = NullChn;

#ifdef USER_HOSTMASKING
#define GET_USER_HOST IsUmodeH(cptr)?cptr->user->mhost:cptr->user->host
#else
#define GET_USER_HOST cptr->user->host
#endif

#ifdef INVITE_LISTS
/* +I list functions */
int       add_invite_id(aClient*, aChannel*, char*);
int       del_invite_id(aChannel*, char*);
anInvite* is_invited(aClient*, aChannel*);
#endif

#ifdef EXEMPT_LISTS
/* +e list functions */
int       add_exempt_id(aClient*, aChannel*, char*);
int       del_exempt_id(aChannel*, char*);
#endif

static int  add_banid(aClient *, aChannel *, char *);
static int  can_join(aClient *, aChannel *, char *);
static void channel_modes(aClient *, char *, char *, aChannel *);
static int  del_banid(aChannel *, char *);
static int  is_banned(aClient *, aChannel *, chanMember *);
static int  set_mode(aClient *, aClient *, aChannel *, int, 
                     int, char **, char *, char *);
static void sub1_from_channel(aChannel *);

int         check_channelname(aClient *, unsigned char *);
void        clean_channelname(unsigned char *);
static void add_invite(aClient *, aChannel *);
void        del_invite(aClient *, aChannel *);

#ifdef ORATIMING
struct timeval tsdnow, tsdthen;
unsigned long tsdms;
#endif

/* number of seconds to add to all readings of time() when making TS's */

static char *PartFmt = ":%s PART %s";
static char *PartFmt2 = ":%s PART %s :%s";

/* server <-> server SJOIN format  */
static char *SJOINFmt = ":%s SJOIN %ld %s %s %s :%s";
/* NP means no paramaters, don't send the extra space there */
static char *SJOINFmtNP = ":%s SJOIN %ld %s %s :%s";
/* client SJOIN format, for no channel creation */
static char *CliSJOINFmt = ":%s SJOIN %ld %s";

/* some buffers for rebuilding channel/nick lists with ,'s */
static char nickbuf[BUFSIZE], buf[BUFSIZE];
static char modebuf[REALMODEBUFLEN], parabuf[REALMODEBUFLEN];

/* externally defined function */
extern Link *find_channel_link(Link *, aChannel *);     /* defined in list.c */
extern int is_silenced(aClient *sptr, aClient *acptr); /* defined in s_user.c */
extern struct FlagList xflags_list[]; /* for send_topic_burst() */
#ifdef ANTI_SPAMBOT
extern int  spam_num;           /* defined in s_serv.c */
extern int  spam_time;          /* defined in s_serv.c */
#endif

/* return the length (>=0) of a chain of links. */
static int list_length(Link *lp)
{
    int     count = 0;
    
    for (; lp; lp = lp->next)
        count++;
    return count;
}

/* check to see if the message has any control chars in it. */
static int
msg_has_ctrls(char *msg)
{
    unsigned char *c;

    if (msg == NULL)
        return 0;

    for (c = (unsigned char *)msg; *c; c++)
    {
        /* not a control code */
        if (*c > 31)
            continue;

        /* ctcp */
        if (*c == 1)
            continue;

        /* escape */
        if (*c == 27)
        {
            /* ISO 2022 charset shift sequence */
            if (c[1] == '$' || c[1] == '(')
            {
                c++;
                continue;
            }
        }

        /* control code */
        break;
    }
    if(*c)
        return 1;
    return 0;
}

/*
 * find_chasing 
 *   Find the client structure for a nick name (user) using history 
 *   mechanism if necessary. If the client is not found, an error message 
 *   (NO SUCH NICK) is generated. If the client was found through the 
 *   history, chasing will be 1 and otherwise 0.
 */
aClient *find_chasing(aClient *sptr, char *user, int *chasing)
{
    aClient *who = find_client(user, (aClient *) NULL);
    
    if (chasing)
        *chasing = 0;
    if (who)
        return who;
    if (!(who = get_history(user, (long) KILLCHASETIMELIMIT)))
    {
        sendto_one(sptr, err_str(ERR_NOSUCHNICK),
                   me.name, sptr->name, user);
        return ((aClient *) NULL);
    }
    if (chasing)
        *chasing = 1;
    return who;
}

/*
 * Fixes a string so that the first white space found becomes an end of
 * string marker (`\-`).  returns the 'fixed' string or "*" if the
 * string was NULL length or a NULL pointer.
 */
static char * check_string(char *s)
{
    static char star[2] = "*";
    char       *str = s;
    
    if (BadPtr(s))
        return star;
    
    for (; *s; s++)
        if (IsSpace(*s))
        {
            *s = '\0';
            break;
        }
    
    return (BadPtr(str)) ? star : str;
}
/*
 * create a string of form "foo!bar@fubar" given foo, bar and fubar as
 * the parameters.  If NULL, they become "*".
 */
static char *make_nick_user_host(char *nick, char *name, char *host)
{
    static char namebuf[NICKLEN + USERLEN + HOSTLEN + 6];
    int         n;
    char   *ptr1, *ptr2;
    
    ptr1 = namebuf;
    for (ptr2 = check_string(nick), n = NICKLEN; *ptr2 && n--;)
        *ptr1++ = *ptr2++;
    *ptr1++ = '!';
    for (ptr2 = check_string(name), n = USERLEN; *ptr2 && n--;)
        *ptr1++ = *ptr2++;
    *ptr1++ = '@';
    for (ptr2 = check_string(host), n = HOSTLEN; *ptr2 && n--;)
        *ptr1++ = *ptr2++;
    *ptr1 = '\0';
    return (namebuf);
}

/* Determine whether a client matches a CIDR banstr. */
static int client_matches_cidrstr(aClient *cptr, char *banstr)
{
    char cidrbuf[NICKLEN + USERLEN + HOSTLEN + 6];
    char ipbuf[16];
    char *s;
    int bits;

    if (!strchr(banstr, '/'))
	return 0;

    s = strchr(banstr, '@');
    if (s)
	s++;
    else
	return 0;

    bits = inet_parse_cidr(cptr->ip_family, s, ipbuf, sizeof(ipbuf));
    if (bits > 0 && bitncmp(&cptr->ip, ipbuf, bits) == 0)
    {
	/* Check the wildcards in the rest of the string. */
	snprintf(cidrbuf, sizeof(cidrbuf), "%s!%s@%s",
		 check_string(cptr->name),
		 check_string(cptr->user->username),
		 s);
	if (match(banstr, cidrbuf) == 0)
	    return 1;
    }
    return 0;
}

#ifdef EXEMPT_LISTS
/* Exempt list functions (+e) */

int add_exempt_id(aClient* cptr, aChannel* chptr, char* exempt_id)
{
    aBanExempt*   exempt = NULL;
    int           cnt = 0;

    for (exempt = chptr->banexempt_list; exempt; exempt = exempt->next)
    {
        if (MyClient(cptr))
        {
            if (++cnt >= MAXEXEMPTLIST)
            {
                sendto_one(cptr, getreply(ERR_BANLISTFULL), me.name, cptr->name,
                    chptr->chname, exempt_id, "exempt");
                return -1;
            }
            if (!match(exempt->banstr, exempt_id))
                return -1;
        }
        else if (!mycmp(exempt->banstr, exempt_id))
            return -1;
    }
    exempt = (aBanExempt*)MyMalloc(sizeof(aBanExempt));
    exempt->banstr = (char*)MyMalloc(strlen(exempt_id)+1);
    strcpy(exempt->banstr, exempt_id);
    exempt->when = timeofday;
    exempt->next = chptr->banexempt_list;
    chptr->banexempt_list = exempt;
    chptr->banserial++;

    if (IsPerson(cptr))
    {
        exempt->who = (char *) MyMalloc(strlen(cptr->name) +
                                     strlen(cptr->user->username) +
                                     strlen(GET_USER_HOST) + 3);
        (void) ircsprintf(exempt->who, "%s!%s@%s",
                          cptr->name, cptr->user->username, GET_USER_HOST);
    }
    else
    {
        exempt->who = (char *) MyMalloc(strlen(cptr->name) + 1);
        (void) strcpy(exempt->who, cptr->name);
    }

    /* determine type for less matching later */
    if(exempt_id[0] == '*' && exempt_id[1] == '!')
    {
        if(exempt_id[2] == '*' && exempt_id[3] == '@')
            exempt->type = MTYP_HOST;
        else
            exempt->type = MTYP_USERHOST;
    }
    else
        exempt->type = MTYP_FULL;

    return 0;
}

int del_exempt_id(aChannel* chptr, char* exempt_id)
{
   aBanExempt**  exempt;
   aBanExempt*   tmp;

   if (!exempt_id)
       return -1;
   for (exempt = &chptr->banexempt_list; *exempt; exempt = &((*exempt)->next))
   {
       if (mycmp(exempt_id, (*exempt)->banstr) == 0)
       {
           tmp = *exempt;
           *exempt = tmp->next;

           chptr->banserial++;

           MyFree(tmp->banstr);
           MyFree(tmp->who);
           MyFree(tmp);
           
           break;
       }
   }
   return 0;
}

#endif

#ifdef INVITE_LISTS
/* Invite list functions (+I) */

int add_invite_id(aClient* cptr, aChannel* chptr, char* invite_id)
{
    anInvite*     invite;
    int           cnt = 0;
    
    for (invite = chptr->invite_list; invite; invite = invite->next)
    {
        if (MyClient(cptr))
        {
            if (++cnt >= MAXINVITELIST)
            {
                sendto_one(cptr, getreply(ERR_BANLISTFULL), me.name, cptr->name,
                    chptr->chname, invite_id, "invite");
                return -1;
            }
            if (!match(invite->invstr, invite_id))
                return -1;
        }
        else if (!mycmp(invite->invstr, invite_id))
            return -1;
    }

    invite = (anInvite*)MyMalloc(sizeof(anInvite));
    invite->invstr = (char*)MyMalloc(strlen(invite_id)+1);
    strcpy(invite->invstr, invite_id);
    invite->when = timeofday;
    invite->next = chptr->invite_list;
    chptr->invite_list = invite;
    
    if (IsPerson(cptr))
    {
        invite->who = (char *) MyMalloc(strlen(cptr->name) +
                                     strlen(cptr->user->username) +
                                     strlen(GET_USER_HOST) + 3);
        (void) ircsprintf(invite->who, "%s!%s@%s",
                          cptr->name, cptr->user->username, GET_USER_HOST);
    }
    else
    {
        invite->who = (char *) MyMalloc(strlen(cptr->name) + 1);
        (void) strcpy(invite->who, cptr->name);
    }
    return 0;
}

int del_invite_id(aChannel* chptr, char* invite_id)
{
   anInvite**    invite;
   anInvite*     tmp;

   if (!invite_id)
       return -1;
   for (invite = &chptr->invite_list; *invite; invite = &((*invite)->next))
   {
       if (mycmp(invite_id, (*invite)->invstr) == 0)
       {
           tmp = *invite;
           *invite = tmp->next;
           
           MyFree(tmp->invstr);
           MyFree(tmp->who);
           MyFree(tmp);
           
           break;
       }
   }
   return 0;
}

anInvite* is_invited(aClient* cptr, aChannel* chptr)
{
    char         s[NICKLEN + USERLEN + HOSTLEN + 6];
#ifdef USER_HOSTMASKING
    char         s3[NICKLEN + USERLEN + HOSTLEN + 6];
#endif
    char        *s2;
    anInvite*    invite;

    strcpy(s, make_nick_user_host(cptr->name, cptr->user->username,
                                  cptr->user->host));
#ifdef USER_HOSTMASKING
    strcpy(s3, make_nick_user_host(cptr->name, cptr->user->username,
                                   cptr->user->mhost));
#endif
    s2 = make_nick_user_host(cptr->name, cptr->user->username,
                             cptr->hostip);

    for (invite = chptr->invite_list; invite; invite = invite->next)
    {
        if (!match(invite->invstr, s) || !match(invite->invstr, s2) ||
#ifdef USER_HOSTMASKING
            !match(invite->invstr, s3) ||
#endif
	    client_matches_cidrstr(cptr, invite->invstr))
            break;
    }
    return invite;
}

#endif

/* Ban functions to work with mode +b */
/* add_banid - add an id to be banned to the channel  (belongs to cptr) */

static int add_banid(aClient *cptr, aChannel *chptr, char *banid)
{
    aBan        *ban;
    int          cnt = 0;
    
    for (ban = chptr->banlist; ban; ban = ban->next)
    {
        /* Begin unbreaking redundant ban checking.  First step is to allow
         * ALL non-duplicates from remote servers.  Local clients are still
         * subject to the flawed redundancy check for compatibility with
         * older servers.  This check can be corrected later.  -Quension */
        if (MyClient(cptr))
        {
            if (++cnt >= chptr->max_bans)
            {
                sendto_one(cptr, getreply(ERR_BANLISTFULL), me.name, cptr->name,
                        chptr->chname, banid, "ban");
                return -1;
            }
            if (!match(ban->banstr, banid))
                return -1;
        }
        else if (!mycmp(ban->banstr, banid))
            return -1;
    }

    ban = (aBan *) MyMalloc(sizeof(aBan));
    ban->banstr = (char *) MyMalloc(strlen(banid) + 1);
    (void) strcpy(ban->banstr, banid);
    ban->next = chptr->banlist;
    
    if (IsPerson(cptr))
    {
        ban->who = (char *) MyMalloc(strlen(cptr->name) +
                                     strlen(cptr->user->username) +
                                     strlen(GET_USER_HOST) + 3);
        (void) ircsprintf(ban->who, "%s!%s@%s",
                          cptr->name, cptr->user->username, GET_USER_HOST);
    }
    else
    {
        ban->who = (char *) MyMalloc(strlen(cptr->name) + 1);
        (void) strcpy(ban->who, cptr->name);
    }
    
    /* determine what 'type' of mask this is, for less matching later */
    
    if(banid[0] == '*' && banid[1] == '!')
    {
        if(banid[2] == '*' && banid[3] == '@')
            ban->type = MTYP_HOST;
        else
            ban->type = MTYP_USERHOST;
    }
    else
        ban->type = MTYP_FULL;

    ban->when = timeofday;
    chptr->banlist = ban;
    chptr->banserial++;
    
    return 0;
}

/*
 * del_banid - delete an id belonging to cptr if banid is null,
 * deleteall banids belonging to cptr.
 */
static int del_banid(aChannel *chptr, char *banid)
{
   aBan        **ban;
   aBan         *tmp;

   if (!banid)
       return -1;
   for (ban = &(chptr->banlist); *ban; ban = &((*ban)->next))
       if (mycmp(banid, (*ban)->banstr) == 0)
       {
           tmp = *ban;
           *ban = tmp->next;

           chptr->banserial++;

           MyFree(tmp->banstr);
           MyFree(tmp->who);
           MyFree(tmp);
           
           break;
       }
   return 0;
}

/*
 * is_banned - returns CHFL_BANNED if banned else 0
 * 
 * caches banned status in chanMember for can_send()
 *   -Quension [Jun 2004]
 */

static int is_banned(aClient *cptr, aChannel *chptr, chanMember *cm)
{
    aBan       *ban;
#ifdef EXEMPT_LISTS
    aBanExempt *exempt;
#endif
    char        s[NICKLEN + USERLEN + HOSTLEN + 6];
#ifdef USER_HOSTMASKING
    char        s3[NICKLEN + USERLEN + HOSTLEN + 6];
#endif
    char       *s2;
    
    if (!IsPerson(cptr))
        return 0;

    /* if cache is valid, use it */
    if (cm)
    {
        if (cm->banserial == chptr->banserial)
            return (cm->flags & CHFL_BANNED);
        cm->banserial = chptr->banserial;
        cm->flags &= ~CHFL_BANNED;
    }

    strcpy(s, make_nick_user_host(cptr->name, cptr->user->username,
                                  cptr->user->host));
#ifdef USER_HOSTMASKING
    strcpy(s3, make_nick_user_host(cptr->name, cptr->user->username,
                                   cptr->user->mhost));
#endif
    s2 = make_nick_user_host(cptr->name, cptr->user->username,
                             cptr->hostip);

#ifdef EXEMPT_LISTS
    for (exempt = chptr->banexempt_list; exempt; exempt = exempt->next)
        if (!match(exempt->banstr, s) || !match(exempt->banstr, s2) ||
#ifdef USER_HOSTMASKING
            !match(exempt->banstr, s3) ||
#endif
	    client_matches_cidrstr(cptr, exempt->banstr))
            return 0;
#endif

    for (ban = chptr->banlist; ban; ban = ban->next)
        if ((match(ban->banstr, s) == 0) ||
            (match(ban->banstr, s2) == 0) ||
#ifdef USER_HOSTMASKING
            (match(ban->banstr, s3) == 0) ||
#endif
	    client_matches_cidrstr(cptr, ban->banstr))
            break;

    if (ban)
    {
        if (cm)
            cm->flags |= CHFL_BANNED;
        return CHFL_BANNED;
    }

    return 0;
}

/*
 * Forces the cached banned status for a user to be flushed in all the channels
 * they are in.
 */
void flush_user_banserial(aClient *cptr)
{
	Link *ptr;

	if (!IsPerson(cptr))
		return;
	for (ptr = cptr->user->channel; ptr; ptr = ptr->next)
	{
		aChannel *chptr = ptr->value.chptr;
		chanMember *cm = find_user_member(chptr->members, cptr);

		if (cm)
			cm->banserial = chptr->banserial - 1;
	}
}

aBan *nick_is_banned(aChannel *chptr, char *nick, aClient *cptr)
{
    aBan *ban;
#ifdef EXEMPT_LISTS
    aBanExempt *exempt;
#endif
    char *s, s2[NICKLEN+USERLEN+HOSTLEN+6];
#ifdef USER_HOSTMASKING
    char s3[NICKLEN+USERLEN+HOSTLEN+6];
#endif
    
    if (!IsPerson(cptr)) return NULL;
    
    strcpy(s2, make_nick_user_host(nick, cptr->user->username,
                                   cptr->user->host));
#ifdef USER_HOSTMASKING
    strcpy(s3, make_nick_user_host(nick, cptr->user->username,
                                   cptr->user->mhost));
#endif
    s = make_nick_user_host(nick, cptr->user->username, cptr->hostip);

#ifdef EXEMPT_LISTS
    for (exempt = chptr->banexempt_list; exempt; exempt = exempt->next)
        if (exempt->type == MTYP_FULL &&
            ((match(exempt->banstr, s2) == 0) ||
#ifdef USER_HOSTMASKING
             (match(exempt->banstr, s3) == 0) ||
#endif
             (match(exempt->banstr, s) == 0) ||
	     client_matches_cidrstr(cptr, exempt->banstr)))
            return NULL;
#endif

    for (ban = chptr->banlist; ban; ban = ban->next)
        if (ban->type == MTYP_FULL &&        /* only check applicable bans */
            ((match(ban->banstr, s2) == 0) ||    /* check host before IP */
#ifdef USER_HOSTMASKING
             (match(ban->banstr, s3) == 0) ||
#endif
             (match(ban->banstr, s) == 0) ||
	     client_matches_cidrstr(cptr, ban->banstr)))
            break;
    return (ban);
}

void remove_matching_bans(aChannel *chptr, aClient *cptr, aClient *from) 
{
    aBan *ban, *bnext;
    char targhost[NICKLEN+USERLEN+HOSTLEN+6];
#ifdef USER_HOSTMASKING
    char targmhost[NICKLEN+USERLEN+HOSTLEN+6];
#endif
    char targip[NICKLEN+USERLEN+HOSTLEN+6];
    char *m;
    int count = 0, send = 0;
    
    if (!IsPerson(cptr)) return;
    
    strcpy(targhost, make_nick_user_host(cptr->name, cptr->user->username,
                                         cptr->user->host));
#ifdef USER_HOSTMASKING
    strcpy(targmhost, make_nick_user_host(cptr->name, cptr->user->username,
                                          cptr->user->mhost));
#endif
  strcpy(targip, make_nick_user_host(cptr->name, cptr->user->username,
                                     cptr->hostip));
  
  m = modebuf;  
  *m++ = '-';
  *m = '\0'; 
  
  *parabuf = '\0';
  
  ban = chptr->banlist;
  
  while(ban)
  {
      bnext = ban->next;
      if((match(ban->banstr, targhost) == 0) ||
#ifdef USER_HOSTMASKING
         (match(ban->banstr, targmhost) == 0) ||
#endif
         (match(ban->banstr, targip) == 0) ||
	 client_matches_cidrstr(cptr, ban->banstr))
      {
          if (strlen(parabuf) + strlen(ban->banstr) + 10 < (size_t) MODEBUFLEN)
          {
              if(*parabuf)
                  strcat(parabuf, " ");
              strcat(parabuf, ban->banstr);
              count++;
              *m++ = 'b';
              *m = '\0';
          }
          else 
              if(*parabuf)
                  send = 1;
          
          if(count == MAXTSMODEPARAMS)
              send = 1;
          
          if(send)
          {
              sendto_channel_butserv_me(chptr, from, ":%s MODE %s %s %s", 
                                        from->name, chptr->chname, modebuf,
                                        parabuf);
              sendto_serv_butone(from, ":%s MODE %s %ld %s %s", from->name,
                                 chptr->chname, chptr->channelts, modebuf,
                                 parabuf);
              send = 0;
              *parabuf = '\0';
              m = modebuf;
              *m++ = '-';
              if(count != MAXTSMODEPARAMS)
              {
                  strcpy(parabuf, ban->banstr);
                  *m++ = 'b';
                  count = 1;
              }
              else
                  count = 0;
              *m = '\0';
          }
          
          del_banid(chptr, ban->banstr);
      }
      ban = bnext;
  }
  
  if(*parabuf)
  {
      sendto_channel_butserv_me(chptr, from, ":%s MODE %s %s %s", from->name,
                                chptr->chname, modebuf, parabuf);
      sendto_serv_butone(from, ":%s MODE %s %ld %s %s", from->name,
                         chptr->chname, chptr->channelts, modebuf, parabuf);
  }
  
  return;
}

#ifdef EXEMPT_LISTS
void remove_matching_exempts(aChannel *chptr, aClient *cptr, aClient *from)
{
    aBanExempt *ex, *enext;
    char targhost[NICKLEN+USERLEN+HOSTLEN+6];
#ifdef USER_HOSTMASKING
    char targmhost[NICKLEN+USERLEN+HOSTLEN+6];
#endif
    char targip[NICKLEN+USERLEN+HOSTLEN+6];
    char *m;
    int count = 0, send = 0;

    if (!IsPerson(cptr)) return;

    strcpy(targhost, make_nick_user_host(cptr->name, cptr->user->username,
                                         cptr->user->host));
#ifdef USER_HOSTMASKING
    strcpy(targmhost, make_nick_user_host(cptr->name, cptr->user->username,
                                          cptr->user->mhost));
#endif
    strcpy(targip, make_nick_user_host(cptr->name, cptr->user->username,
                                       cptr->hostip));

    m = modebuf;
    *m++ = '-';
    *m = '\0';

    *parabuf = '\0';

    ex = chptr->banexempt_list;

    while(ex)
    {
        enext = ex->next;
        if((match(ex->banstr, targhost) == 0) ||
#ifdef USER_HOSTMASKING
           (match(ex->banstr, targmhost) == 0) ||
#endif
           (match(ex->banstr, targip) == 0) ||
	   client_matches_cidrstr(cptr, ex->banstr))
        {
            if (strlen(parabuf) + strlen(ex->banstr) + 10 < (size_t) MODEBUFLEN)
            {
                if(*parabuf)
                    strcat(parabuf, " ");
                strcat(parabuf, ex->banstr);
                count++;
                *m++ = 'e';
                *m = '\0';
            }
            else
                if(*parabuf)
                    send = 1;

            if(count == MAXTSMODEPARAMS)
                send = 1;

            if(send)
            {
                sendto_channel_butserv_me(chptr, from, ":%s MODE %s %s %s",
                                          from->name, chptr->chname, modebuf,
                                          parabuf);
                sendto_serv_butone(from, ":%s MODE %s %ld %s %s", from->name,
                                   chptr->chname, chptr->channelts, modebuf,
                                   parabuf);
                send = 0;
                *parabuf = '\0';
                m = modebuf;
                *m++ = '-';
                if(count != MAXTSMODEPARAMS)
                {
                    strcpy(parabuf, ex->banstr);
                    *m++ = 'e';
                    count = 1;
                }
                else
                    count = 0;
                *m = '\0';
            }

            del_exempt_id(chptr, ex->banstr);
        }
        ex = enext;
    }

    if(*parabuf)
    {
        sendto_channel_butserv_me(chptr, from, ":%s MODE %s %s %s", from->name,
                                  chptr->chname, modebuf, parabuf);
        sendto_serv_butone(from, ":%s MODE %s %ld %s %s", from->name,
                           chptr->chname, chptr->channelts, modebuf, parabuf);
    }

    return;
}
#endif

#ifdef INVITE_LISTS
void remove_matching_invites(aChannel *chptr, aClient *cptr, aClient *from)
{
    anInvite *inv, *inext;
    char targhost[NICKLEN+USERLEN+HOSTLEN+6];
#ifdef USER_HOSTMASKING
    char targmhost[NICKLEN+USERLEN+HOSTLEN+6];
#endif
    char targip[NICKLEN+USERLEN+HOSTLEN+6];
    char *m;
    int count = 0, send = 0;

    if (!IsPerson(cptr)) return;

    strcpy(targhost, make_nick_user_host(cptr->name, cptr->user->username,
                                         cptr->user->host));
#ifdef USER_HOSTMASKING
    strcpy(targmhost, make_nick_user_host(cptr->name, cptr->user->username,
                                          cptr->user->mhost));
#endif
    strcpy(targip, make_nick_user_host(cptr->name, cptr->user->username,
                                       cptr->hostip));

    m = modebuf;
    *m++ = '-';
    *m = '\0';

    *parabuf = '\0';

    inv = chptr->invite_list;

    while(inv)
    {
        inext = inv->next;
        if((match(inv->invstr, targhost) == 0) ||
#ifdef USER_HOSTMASKING
           (match(inv->invstr, targmhost) == 0) ||
#endif
           (match(inv->invstr, targip) == 0))
        {
            if (strlen(parabuf) + strlen(inv->invstr) + 10 < (size_t) MODEBUFLEN)
            {
                if(*parabuf)
                    strcat(parabuf, " ");
                strcat(parabuf, inv->invstr);
                count++;
                *m++ = 'I';
                *m = '\0';
            }
            else
                if(*parabuf)
                    send = 1;

            if(count == MAXTSMODEPARAMS)
                send = 1;

            if(send)
            {
                sendto_channel_butserv_me(chptr, from, ":%s MODE %s %s %s",
                                          from->name, chptr->chname, modebuf,
                                          parabuf);
                sendto_serv_butone(from, ":%s MODE %s %ld %s %s", from->name,
                                   chptr->chname, chptr->channelts, modebuf,
                                   parabuf);
                send = 0;
                *parabuf = '\0';
                m = modebuf;
                *m++ = '-';
                if(count != MAXTSMODEPARAMS)
                {
                    strcpy(parabuf, inv->invstr);
                    *m++ = 'I';
                    count = 1;
                }
                else
                    count = 0;
                *m = '\0';
            }

            del_invite_id(chptr, inv->invstr);
        }
        inv = inext;
    }

    if(*parabuf)
    {
        sendto_channel_butserv_me(chptr, from, ":%s MODE %s %s %s", from->name,
                                  chptr->chname, modebuf, parabuf);
        sendto_serv_butone(from, ":%s MODE %s %ld %s %s", from->name,
                           chptr->chname, chptr->channelts, modebuf, parabuf);
    }

    return;
}
#endif


/* refill join rate warning token bucket, and count a join attempt */
static void
jrw_update(aChannel *chptr, int local)
{
    int adj_delta;
    int bkt_delta;

    if (chptr->jrw_bucket < DEFAULT_JOIN_SIZE && NOW > chptr->jrw_last)
    {
        adj_delta = NOW - chptr->jrw_last;
        bkt_delta = DEFAULT_JOIN_SIZE - chptr->jrw_bucket;
        
        /* avoid overflow for long timespans */
        if (adj_delta < bkt_delta)
            adj_delta *= DEFAULT_JOIN_NUM;
        
        if (adj_delta > bkt_delta)
            adj_delta = bkt_delta;
        
        chptr->jrw_bucket += adj_delta;
        
        /* bucket has a free fill (not join) slot, reset debt counter */
        if (chptr->jrw_bucket >= DEFAULT_JOIN_NUM)
        {
            chptr->jrw_debt_ctr = 0;
            chptr->jrw_debt_ts = 0;
        }
    }
    
    if (chptr->jrw_bucket >= -(DEFAULT_JOIN_SIZE - DEFAULT_JOIN_TIME))
        chptr->jrw_bucket -= DEFAULT_JOIN_TIME;
    
    /* warning bucket is always current, which pins it at the rate limit */
    chptr->jrw_last = NOW;
    
    /* for statistical purposes, keep count of local join attempts */
    if (local)
        chptr->jrw_debt_ctr++;

    /* statistical timestamp reflects all joins */
    if (chptr->jrw_debt_ts == 0)
        chptr->jrw_debt_ts = NOW;
}

/* refill join rate throttling token bucket */
static void
jrl_update(aChannel *chptr)
{
    int adj_delta;
    int bkt_delta;
    int jnum, jsize;

    jnum = chptr->mode.jr_num;
    jsize = chptr->mode.jrl_size;
    
    /* throttling disabled */
    if (!jsize)
        return;
    
    if (chptr->jrl_bucket < jsize && NOW > chptr->jrl_last)
    {
        adj_delta = NOW - chptr->jrl_last;
        bkt_delta = jsize - chptr->jrl_bucket;

        /* avoid overflow for long timespans */
        if (adj_delta < bkt_delta)
            adj_delta *= jnum;

        if (adj_delta > bkt_delta)
            adj_delta = bkt_delta;

        chptr->jrl_bucket += adj_delta;
        chptr->jrl_last = NOW;
    }
}

/*
 * Do pre-JOIN updates.  Called for local joins only.
 */
static void
joinrate_prejoin(aChannel *chptr)
{
    jrl_update(chptr);
    jrw_update(chptr, 1);
}

/*
 * Check if a join would be allowed, warning if appropriate.
 * Called for local joins only.
 */
static int
joinrate_check(aChannel *chptr, aClient *cptr, int warn)
{
    int jnum, jtime, jsize;
    
    jnum = chptr->mode.jr_num;
    jtime = chptr->mode.jr_time;
    jsize = chptr->mode.jrl_size;
    
    /* join throttling disabled */
    if (!jsize)
        return 1;
    
    /* free slot in bucket */
    if (chptr->jrl_bucket >= jtime)
        return 1;
    
    /* throttled */
    if (warn)
    {
        if (call_hooks(CHOOK_THROTTLE, cptr, chptr, 1, jnum, jtime) != FLUSH_BUFFER)
            sendto_realops_lev(DEBUG_LEV, "Join rate throttling on %s for"
                               " %s!%s@%s (%d%s in %d)", chptr->chname,
                               cptr->name, cptr->user->username, cptr->user->host,
                               jnum, (chptr->jrl_bucket < 0) ? "+" : "", jtime);
    }
    return 0;
}

/*
 * Do post-JOIN updates.  Called for both local and remote joins.
 */
static void
joinrate_dojoin(aChannel *chptr, aClient *cptr)
{
    int jtime, jsize;
    int local;
    
    local = MyConnect(cptr);
    jtime = chptr->mode.jr_time;
    jsize = chptr->mode.jrl_size;
    
    if (!local)
    {
        jrw_update(chptr, 0);
        jrl_update(chptr);
    }
    else if (chptr->jrw_bucket <= 0 && chptr->jrw_debt_ctr)
    {
        if (call_hooks(CHOOK_THROTTLE, cptr, chptr, 2, chptr->jrw_debt_ctr, NOW - chptr->jrw_debt_ts) != FLUSH_BUFFER)
            sendto_realops_lev(DEBUG_LEV, "Join rate warning on %s for %s!%s@%s"
                               " (%d in %ld) [joined]", chptr->chname,
                               cptr->name, cptr->user->username, cptr->user->host,
                               chptr->jrw_debt_ctr, (long)(NOW - chptr->jrw_debt_ts));
    }

    /* remote joins cause negative penalty here (distributed throttling) */
    /* WARNING: joinrate_check must have allowed a local join */
    if (jsize)
    {
        if (local || chptr->jrl_bucket >= -(jsize - jtime))
        {
            chptr->jrl_bucket -= jtime;
            chptr->jrl_last = NOW;
        }
    }
}

/*
 * Send a warning notice if appropriate.  Called for local failed joins.
 */
static void
joinrate_warn(aChannel *chptr, aClient *cptr)
{
    /* no slots free */
    if (chptr->jrw_bucket <= 0 && chptr->jrw_debt_ctr)
    {
        if (call_hooks(CHOOK_THROTTLE, cptr, chptr, 3, chptr->jrw_debt_ctr, NOW - chptr->jrw_debt_ts) != FLUSH_BUFFER)
            sendto_realops_lev(DEBUG_LEV, "Join rate warning on %s for %s!%s@%s"
                               " (%d in %ld) [failed]", chptr->chname,
                               cptr->name, cptr->user->username,
                               cptr->user->host,
                               chptr->jrw_debt_ctr, (long)(NOW - chptr->jrw_debt_ts));
    }
}


/*
 * adds a user to a channel by adding another link to the channels
 * member chain.
 */
static void add_user_to_channel(aChannel *chptr, aClient *who, int flags)
{
    Link   *ptr;
    chanMember *cm;
    
#ifdef DUMP_DEBUG
    fprintf(dumpfp,"Add to channel %s: %p:%s\n",chptr->chname,who,who->name);
#endif
    
    if (who->user)
    {
        cm = make_chanmember();
        cm->flags = flags;
        cm->cptr = who;
        cm->next = chptr->members;
        cm->banserial = chptr->banserial;
        cm->when = NOW;

        chptr->members = cm;
        chptr->users++;
        
        ptr = make_link();
        ptr->value.chptr = chptr;
        ptr->next = who->user->channel;
        who->user->channel = ptr;
        who->user->joined++;
    }
}

void remove_user_from_channel(aClient *sptr, aChannel *chptr)
{
    chanMember  **curr, *tmp;
    Link           **lcurr, *ltmp;
    
    for (curr = &chptr->members; (tmp = *curr); curr = &tmp->next)
        if (tmp->cptr == sptr)
        {
            *curr = tmp->next;
            free_chanmember(tmp);
            break;
        }

    for (lcurr = &sptr->user->channel; (ltmp = *lcurr); lcurr = &ltmp->next)
        if (ltmp->value.chptr == chptr)
        {
            *lcurr = ltmp->next;
            free_link(ltmp);
            break;
        }
    sptr->user->joined--;
    sub1_from_channel(chptr);
}

int is_chan_op(aClient *cptr, aChannel *chptr)
{
    chanMember   *cm;
    
    if (chptr)
        if ((cm = find_user_member(chptr->members, cptr)))
            return (cm->flags & CHFL_CHANOP);
    
    return 0;
}

int is_chan_opvoice(aClient *cptr, aChannel *chptr)
{
    chanMember   *cm;
    
    if (chptr)
        if ((cm = find_user_member(chptr->members, cptr)))
            return ((cm->flags & CHFL_CHANOP) || (cm->flags & CHFL_VOICE));
    
    return 0;
}

int is_deopped(aClient *cptr, aChannel *chptr)
{
    chanMember   *cm;
    
    if (chptr)
        if ((cm = find_user_member(chptr->members, cptr)))
            return (cm->flags & CHFL_DEOPPED);
    
    return 0;
}

int has_voice(aClient *cptr, aChannel *chptr)
{
    chanMember   *cm;
    
    if (chptr)
        if ((cm = find_user_member(chptr->members, cptr)))
            return (cm->flags & CHFL_VOICE);
    
    return 0;
}

time_t get_user_jointime(aClient *cptr, aChannel *chptr)
{
    chanMember   *cm;

    if (chptr)
        if ((cm = find_user_member(chptr->members, cptr)))
            return cm->when;

    return 0;
}

/* is_xflags_exempted - Check if a user is exempted from the channel's xflags */
int is_xflags_exempted(aClient *sptr, aChannel *chptr)
{
    if(IsAnOper(sptr)) return 1; /* IRC Operators are always exempted */
    if((chptr->xflags & XFLAG_EXEMPT_OPPED) && (chptr->xflags & XFLAG_EXEMPT_VOICED))
    {
      if(is_chan_opvoice(sptr,chptr)) return 1;
    }
    else
    {
      if((chptr->xflags & XFLAG_EXEMPT_OPPED) && is_chan_op(sptr,chptr)) return 1;
      if((chptr->xflags & XFLAG_EXEMPT_VOICED) && has_voice(sptr,chptr)) return 1;
    }
    if((chptr->xflags & XFLAG_EXEMPT_REGISTERED) && IsRegNick(sptr)) return 1;
    if((chptr->xflags & XFLAG_EXEMPT_IDENTD) && sptr->user && sptr->user->username[0]!='~') return 1;
    return 0;
}

int can_send(aClient *cptr, aChannel *chptr, char *msg)
{
    chanMember   *cm;
    int           ismine;
    
    if (IsServer(cptr) || IsULine(cptr))
        return 0;
    
    cm = find_user_member(chptr->members, cptr);
    ismine = MyClient(cptr);
    
    if(!cm)
    {
        if (chptr->mode.mode & MODE_MODERATED)
            return (MODE_MODERATED);
        if(chptr->mode.mode & MODE_NOPRIVMSGS)
            return (MODE_NOPRIVMSGS);
        if ((chptr->mode.mode & MODE_MODREG) && !IsRegNick(cptr))
            return (ERR_NEEDREGGEDNICK);
        if (ismine)
        {
            if ((chptr->mode.mode & MODE_NOCTRL) && msg_has_ctrls(msg))
                return (ERR_NOCTRLSONCHAN);
            if (is_banned(cptr, chptr, NULL))
                return (MODE_BAN); /*
                                * channel is -n and user is not there;
                                * we need to bquiet them if we can
                                */
        }
    }
    else
    {
        /* ops and voices can talk through everything except NOCTRL */
        if (!(cm->flags & (CHFL_CHANOP | CHFL_VOICE)))
        {
            if (chptr->mode.mode & MODE_MODERATED)
                return (MODE_MODERATED);
            if (is_banned(cptr, chptr, cm))
                return (MODE_BAN);
            if ((chptr->mode.mode & MODE_MODREG) && !IsRegNick(cptr))
                return (ERR_NEEDREGGEDNICK);
        }
        if ((chptr->mode.mode & MODE_NOCTRL) && msg_has_ctrls(msg))
            return (ERR_NOCTRLSONCHAN);
        if(ismine)
        {
            if (chptr->talk_connect_time && (cptr->firsttime + chptr->talk_connect_time > NOW) && !is_xflags_exempted(cptr,chptr))
                return (ERR_NEEDTOWAIT);
            if (chptr->talk_join_time && (cm->when + chptr->talk_join_time > NOW) && !is_xflags_exempted(cptr,chptr))
                return (ERR_NEEDTOWAIT);
        }
    }
    
    return 0;
}

/*
 * write the "simple" list of channel modes for channel chptr onto
 * buffer mbuf with the parameters in pbuf.
 */
static void channel_modes(aClient *cptr, char *mbuf, char *pbuf,
                          aChannel *chptr)
{
    pbuf[0] = '\0';
    *mbuf++ = '+';
    if (chptr->mode.mode & MODE_SECRET)
        *mbuf++ = 's';
    if (chptr->mode.mode & MODE_PRIVATE)
        *mbuf++ = 'p';
    if (chptr->mode.mode & MODE_MODERATED)
        *mbuf++ = 'm';
    if (chptr->mode.mode & MODE_TOPICLIMIT)
        *mbuf++ = 't';
    if (chptr->mode.mode & MODE_INVITEONLY)
        *mbuf++ = 'i';
    if (chptr->mode.mode & MODE_NOPRIVMSGS)
        *mbuf++ = 'n';
    if (chptr->mode.mode & MODE_REGISTERED)
        *mbuf++ = 'r';
    if (chptr->mode.mode & MODE_REGONLY)
        *mbuf++ = 'R';
    if (chptr->mode.mode & MODE_NOCTRL)
        *mbuf++ = 'c';
    if (chptr->mode.mode & MODE_OPERONLY)
        *mbuf++ = 'O';
    if (chptr->mode.mode & MODE_MODREG)
        *mbuf++ = 'M';
    if (chptr->mode.mode & MODE_SSLONLY)
        *mbuf++ = 'S';
    if (chptr->mode.mode & MODE_AUDITORIUM)
        *mbuf++ = 'A';
    if (chptr->mode.mode & MODE_PRIVACY)
        *mbuf++ = 'P';
#ifdef USE_CHANMODE_L
    if (chptr->mode.mode & MODE_LISTED)
        *mbuf++ = 'L';
#endif
    if (chptr->mode.limit) 
    {
        *mbuf++ = 'l';
        if (IsMember(cptr, chptr) || IsServer(cptr) || IsULine(cptr) || IsAnOper(cptr))
            ircsprintf(pbuf, "%d", chptr->mode.limit);
    }
    if (chptr->mode.mode & MODE_JOINRATE)
    {
        *mbuf++ = 'j';

        if (IsMember(cptr, chptr) || IsServer(cptr) || IsULine(cptr) || IsAnOper(cptr))
        {
            char tmp[16];
            if(pbuf[0] != '\0')
                strcat(pbuf, " ");

            if(chptr->mode.jr_num == 0 || chptr->mode.jr_time == 0)
                ircsprintf(tmp, "0");
            else
                ircsprintf(tmp, "%d:%d", chptr->mode.jr_num, 
                            chptr->mode.jr_time);

            strcat(pbuf, tmp);
        }
    }
    if (*chptr->mode.key)
    {
        *mbuf++ = 'k';
        if (IsMember(cptr, chptr) || IsServer(cptr) || IsULine(cptr))
        {
            if(pbuf[0] != '\0')
                strcat(pbuf, " ");
            strcat(pbuf, chptr->mode.key);
        } else if (IsOper(cptr)) {
            if(pbuf[0] != '\0')
                strcat(pbuf, " ");
            strcat(pbuf, "*");
        }
    }
    *mbuf++ = '\0';
    return;
}

static void send_channel_lists(aClient *cptr, aChannel *chptr)
{
    aBan   *bp;
#ifdef EXEMPT_LISTS
    aBanExempt *exempt;
#endif
#ifdef INVITE_LISTS
    anInvite *inv;
#endif            
    char   *cp;
    int         count = 0, send = 0;

    cp = modebuf + strlen(modebuf);

    if (*parabuf) /* mode +l or +k xx */
        count = 1;

    for (bp = chptr->banlist; bp; bp = bp->next) 
    {
        if (strlen(parabuf) + strlen(bp->banstr) + 20 < (size_t) MODEBUFLEN) 
        {
            if(*parabuf)
                strcat(parabuf, " ");
            strcat(parabuf, bp->banstr);
            count++;
            *cp++ = 'b';
            *cp = '\0';
        }
        else if (*parabuf)
            send = 1;

        if (count == MAXTSMODEPARAMS)
            send = 1;

        if (send) 
        {
            sendto_one(cptr, ":%s MODE %s %ld %s %s", me.name, chptr->chname,
                           chptr->channelts, modebuf, parabuf);
            send = 0;
            *parabuf = '\0';
            cp = modebuf;
            *cp++ = '+';
            if (count != MAXTSMODEPARAMS) 
            {
                strcpy(parabuf, bp->banstr);
                *cp++ = 'b';
                count = 1;
            }
            else
                count = 0;
            *cp = '\0';
        }
    }
#ifdef EXEMPT_LISTS
    for (exempt = chptr->banexempt_list; exempt; exempt = exempt->next)
    {
        if (strlen(parabuf) + strlen(exempt->banstr) + 20 < (size_t)MODEBUFLEN)
        {
            if (*parabuf) strcat(parabuf, " ");
            strcat(parabuf, exempt->banstr);
            count++;
            *cp++ = 'e';
            *cp = 0;
        }
        else if (*parabuf)
            send = 1;
        
        
        if (count == MAXTSMODEPARAMS)
            send = 1;
        
        if (send)
        {
            sendto_one(cptr, ":%s MODE %s %ld %s %s", me.name, chptr->chname,
                           chptr->channelts, modebuf, parabuf);
            send = 0;
            *parabuf = 0;
            cp = modebuf;
            *cp++ = '+';
            if (count != MAXTSMODEPARAMS)
            {
                strcpy(parabuf, exempt->banstr);
                *cp++ = 'e';
                count = 1;
            }
            else count = 0;
            *cp = 0;
        }
    }
#endif    
#ifdef INVITE_LISTS
    for (inv = chptr->invite_list; inv; inv = inv->next)
    {
        if (strlen(parabuf) + strlen(inv->invstr) + 20 < (size_t)MODEBUFLEN)
        {
            if (*parabuf) strcat(parabuf, " ");
            strcat(parabuf, inv->invstr);
            count++;
            *cp++ = 'I';
            *cp = 0;
        }
        else if (*parabuf)
            send = 1;
        
        
        if (count == MAXTSMODEPARAMS)
            send = 1;
        
        if (send)
        {
            sendto_one(cptr, ":%s MODE %s %ld %s %s", me.name, chptr->chname,
                           chptr->channelts, modebuf, parabuf);
            send = 0;
            *parabuf = 0;
            cp = modebuf;
            *cp++ = '+';
            if (count != MAXTSMODEPARAMS)
            {
                strcpy(parabuf, inv->invstr);
                *cp++ = 'I';
                count = 1;
            }
            else count = 0;
            *cp = 0;
        }
    }
#endif    
    
}

/* send "cptr" a full list of the modes for channel chptr. */
void send_channel_modes(aClient *cptr, aChannel *chptr)
{
    chanMember       *l, *anop = NULL, *skip = NULL;
    int         n = 0;
    char       *t;

    if (*chptr->chname != '#')
        return;

    *modebuf = *parabuf = '\0';
    channel_modes(cptr, modebuf, parabuf, chptr);

    ircsprintf(buf, ":%s SJOIN %ld %s %s %s :", me.name,
               chptr->channelts, chptr->chname, modebuf, parabuf);
    t = buf + strlen(buf);
    for (l = chptr->members; l; l = l->next)
        if (l->flags & MODE_CHANOP)
        {
            anop = l;
            break;
        }
    /*
     * follow the channel, but doing anop first if it's defined *
     * -orabidoo
     */
    l = NULL;
    for (;;)
    {
        if (anop)
        {
            l = skip = anop;
            anop = NULL;
        }
        else
        {
            if (l == NULL || l == skip)
                l = chptr->members;
            else
                l = l->next;
            if (l && l == skip)
                l = l->next;
            if (l == NULL)
                break;
        }
        if (l->flags & MODE_CHANOP)
            *t++ = '@';
        if (l->flags & MODE_VOICE)
            *t++ = '+';
        strcpy(t, l->cptr->name);
        t += strlen(t);
        *t++ = ' ';
        n++;
        if (t - buf > BUFSIZE - 80)
        {
            *t++ = '\0';
            if (t[-1] == ' ')
                t[-1] = '\0';
            sendto_one(cptr, "%s", buf);
            sprintf(buf, ":%s SJOIN %ld %s 0 :", me.name,
                    chptr->channelts, chptr->chname);
            t = buf + strlen(buf);
            n = 0;
        }
    }

    if (n)
    {
        *t++ = '\0';
        if (t[-1] == ' ')
            t[-1] = '\0';
        sendto_one(cptr, "%s", buf);
    }
    *parabuf = '\0';
    *modebuf = '+';
    modebuf[1] = '\0';
    send_channel_lists(cptr, chptr);
    if (modebuf[1] || *parabuf)
        sendto_one(cptr, ":%s MODE %s %ld %s %s",
                me.name, chptr->chname, chptr->channelts, modebuf, parabuf);
}

/* m_mode parv[0] - sender parv[1] - channel */

int m_mode(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    int         mcount = 0, chanop=0;
    aChannel   *chptr;
    int subparc = 2;
    
    /* Now, try to find the channel in question */
    if (parc > 1)
    {
        chptr = find_channel(parv[1], NullChn);
        if (chptr == NullChn)
            return m_umode(cptr, sptr, parc, parv);
    }
    else
    {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
                   me.name, parv[0], "MODE");
        return 0;
    }
    
    if (!check_channelname(sptr, (unsigned char *) parv[1]))
        return 0;

    if (MyClient(sptr))
    {
        if (is_chan_op(sptr, chptr))
            chanop = 1;
    }
    else
        chanop = 2;
        
    if (parc < 3)
    {
        *modebuf = *parabuf = '\0';
        modebuf[1] = '\0';
        channel_modes(sptr, modebuf, parabuf, chptr);
        sendto_one(sptr, rpl_str(RPL_CHANNELMODEIS), me.name, parv[0],
                   chptr->chname, modebuf, parabuf);
        sendto_one(sptr, rpl_str(RPL_CREATIONTIME), me.name, parv[0],
                   chptr->chname, chptr->channelts);
        return 0;
    }

    if(IsServer(cptr) && IsDigit(parv[2][0]))
    {
        ts_val modets = atol(parv[2]);
        if(modets != 0 && (modets > chptr->channelts))
            return 0;
        subparc++;
    }

    mcount = set_mode(cptr, sptr, chptr, chanop, parc - subparc, parv + subparc,
                      modebuf, parabuf);

    if (strlen(modebuf) > (size_t) 1)
        switch (mcount)
        {
            case 0:
                break;
            case -1:
                if (MyClient(sptr))
                    sendto_one(sptr,
                           err_str(ERR_CHANOPRIVSNEEDED),
                           me.name, parv[0], chptr->chname);
                else
                    ircstp->is_fake++;
                break;
            default:
                if(chptr->mode.mode & MODE_AUDITORIUM)
                    sendto_channelopvoice_butserv_me(chptr, sptr,
                                          ":%s MODE %s %s %s", parv[0],
                                          chptr->chname, modebuf,
                                          parabuf);
                else
                    sendto_channel_butserv_me(chptr, sptr,
                                          ":%s MODE %s %s %s", parv[0],
                                          chptr->chname, modebuf,
                                          parabuf);
                sendto_serv_butone(cptr, ":%s MODE %s %ld %s %s", parv[0],
                                   chptr->chname, chptr->channelts, modebuf,
                                   parabuf);
        }
    return 0;
}

/* the old set_mode was pissing me off with it's disgusting
 * hackery, so I rewrote it.  Hope this works. }:> --wd
 * Corrected a 4-year-old mistake: the max modes limit applies to
 * the number of parameters, not mode changes. -Quension [Apr 2004]
 */
static int set_mode(aClient *cptr, aClient *sptr, aChannel *chptr,
                    int level, int parc, char *parv[], char *mbuf, char *pbuf) 
{
#define SM_ERR_NOPRIVS 0x0001 /* is not an op */
#define SM_ERR_MOREPARMS 0x0002 /* needs more parameters */     
#define SM_ERR_RESTRICTED 0x0004 /* not allowed to op others or be op'd */      
#define SM_ERR_NOTOPER    0x0008 /* not an irc op */
#define SM_MAXMODES MAXMODEPARAMSUSER

/* this macro appends to pbuf */
#define ADD_PARA(p) pptr = p; if(pidx) pbuf[pidx++] = ' '; while(*pptr) \
                    pbuf[pidx++] = *pptr++;
    
    static int flags[] = 
    {
        MODE_PRIVATE, 'p', MODE_SECRET, 's',
        MODE_MODERATED, 'm', MODE_NOPRIVMSGS, 'n',
        MODE_TOPICLIMIT, 't', MODE_REGONLY, 'R',
        MODE_INVITEONLY, 'i', MODE_NOCTRL, 'c', MODE_OPERONLY, 'O',
        MODE_MODREG, 'M', MODE_SSLONLY, 'S', MODE_AUDITORIUM, 'A',
#ifdef SPAMFILTER
        MODE_PRIVACY, 'P',
#endif
#ifdef USE_CHANMODE_L
        MODE_LISTED, 'L',
#endif
        0x0, 0x0
    };
    
    Link *lp; /* for walking lists */
    chanMember *cm; /* for walking channel member lists */
    aBan *bp; /* for walking banlists */
    char *modes=parv[0]; /* user's idea of mode changes */
    int args; /* counter for what argument we're on */
    int anylistsent = IsServer(sptr) ? 1 : 0; /* Only send 1 list and not to servers */
    char change='+'; /* by default we + things... */
    int errors=0; /*
                   * errors returned, set with bitflags
                   * so we only return them once
                   */
    /* from remote servers, ungodly numbers of modes can be sent, but
     * from local users only SM_MAXMODES are allowed */
    int maxparams=((IsServer(sptr) || IsULine(sptr)) ? 512 : SM_MAXMODES);
    int nmodes=0; /* how many modes we've set so far */
    int nparams=0; /* how many modes with parameters we've set so far */
    aClient *who = NULL; /* who we're doing a mode for */
    int chasing = 0;
    int i=0;
    char moreparmsstr[]="MODE   ";
    char nuhbuf[NICKLEN + USERLEN + HOSTLEN + 6]; /* for bans */
    char tmp[128]; /* temporary buffer */
    int pidx = 0; /* index into pbuf */
    char *pptr; /* temporary paramater pointer */
    char *morig = mbuf; /* beginning of mbuf */
    /* :cptr-name MODE chptr->chname [MBUF] [PBUF] (buflen - 3 max and NULL) */
    /* added another 11 bytes to this, for TSMODE -epi */
    int prelen = strlen(cptr->name) + strlen(chptr->chname) + 27;
    /* drop duplicates in the same mode change -- yeah, this is cheap, but real
       duplicate checking will have to wait for a protocol change to kill
       desyncs */
    int seenalready = 0;


    args=1;
        
    if(parc<1)
        return 0;

    *mbuf++='+'; /* add the plus, even if they don't */
    /* go through once to clean the user's mode string so we can
     * have a simple parser run through it...*/

    while(*modes) 
    {
        switch(*modes) 
        {
        case '+':
            if(*(mbuf-1)=='-') 
            {
                *(mbuf-1)='+'; /* change it around now */
                change='+';
                break;
            }
            else if(change=='+') /* we're still doing a +, we don't care */
                break;
            change=*modes;
            *mbuf++='+';
            break;

        case '-':
            if(*(mbuf-1)=='+') 
            {
                *(mbuf-1)='-'; /* change it around now */
                change='-';
                break;
            }
            else if(change=='-')
                break; /* we're still doing a -, we don't care */
            change=*modes;
            *mbuf++='-';
            break;

        case 'O':
            if (level<1)
            {
                errors |= SM_ERR_NOPRIVS;
                break;
            }
            else if (MyClient(sptr) && !IsOper(sptr))
            {
                errors |= SM_ERR_NOTOPER;
                break;
            } 
            else 
            {
                if (change=='+')
                    chptr->mode.mode|=MODE_OPERONLY;
                else
                    chptr->mode.mode&=~MODE_OPERONLY;
                *mbuf++ = *modes;
                nmodes++;
            }
            break;
        case 'o':
        case 'v':
            if(level<1) 
            {
                errors |= SM_ERR_NOPRIVS;
                break;
            }
            if(parv[args]==NULL)
            {
                /* silently drop the spare +o/v's */
                break;
            }
            if(++nparams > maxparams)
            {
                /* too many modes with params, eat this one */
                args++;
                break;
            }
                        
            who = find_chasing(sptr, parv[args], &chasing);
            cm = find_user_member(chptr->members, who);
            if(cm == NULL) 
            {
                sendto_one(sptr, err_str(ERR_USERNOTINCHANNEL),
                           me.name, cptr->name, parv[args], chptr->chname);
                /* swallow the arg */
                args++;
                break;
            }
            /* if we're going to overflow our mode buffer,
             * drop the change instead */
            if((prelen + (mbuf - morig) + pidx + NICKLEN + 1) > 
               REALMODEBUFLEN) 
            {
                args++;
                break;
            }
            
            /* if we have the user, set them +/-[vo] */
            if(change=='+')
            {
                int resend_nicklist = (chptr->mode.mode & MODE_AUDITORIUM) && MyClient(who) && !((cm->flags & CHFL_CHANOP) || (cm->flags & CHFL_VOICE));
                cm->flags|=(*modes=='o' ? CHFL_CHANOP : CHFL_VOICE);
                if (resend_nicklist)
                {
                    char *fake_parv[3];

                    sendto_one(who, ":%s KICK %s %s :%s",
                               me.name, chptr->chname, who->name, "Resending nicklist...");
                    sendto_prefix_one(who, who, ":%s JOIN :%s", who->name, chptr->chname);

                    if(chptr->topic[0] != '\0')
                    {
                        sendto_one(who, rpl_str(RPL_TOPIC), me.name, who->name,
                                   chptr->chname, chptr->topic);
                        sendto_one(who, rpl_str(RPL_TOPICWHOTIME), me.name, who->name,
                                   chptr->chname, chptr->topic_nick, chptr->topic_time);
                    }

                    fake_parv[0] = who->name;
                    fake_parv[1] = chptr->chname;
                    fake_parv[2] = NULL;

                    m_names(who, who, 2, fake_parv);
                }
                if(chptr->mode.mode & MODE_AUDITORIUM) sendto_channel_butserv_noopvoice(chptr, who, ":%s JOIN :%s", who->name, chptr->chname);
            }
            else
            {
                cm->flags&=~((*modes=='o' ? CHFL_CHANOP : CHFL_VOICE));
                if(chptr->mode.mode & MODE_AUDITORIUM) sendto_channel_butserv_noopvoice(chptr, who, PartFmt, who->name, chptr->chname);
            }
            
            /* we've decided their mode was okay, cool */
            *mbuf++ = *modes;
            ADD_PARA(cm->cptr->name)
                args++;
            nmodes++;
            if (IsServer(sptr) && *modes == 'o' && change=='+') 
            {
                chptr->channelts = 0;
                sendto_ops("Server %s setting +o and blasting TS on %s",
                           sptr->name, chptr->chname);
            }
            break;

#ifdef INVITE_LISTS
        case 'I':
            if (level < 1 && parv[args] != NULL)
            {
                errors |= SM_ERR_NOPRIVS;
                break;
            }
            else if (parv[args] == NULL)
            {
                anInvite    *invite;

                if (anylistsent) /* don't send the list if they have received one */
                    break;

                for (invite = chptr->invite_list; invite; invite = invite->next)
                    sendto_one(sptr, rpl_str(RPL_INVITELIST), me.name, cptr->name,
                               chptr->chname, invite->invstr, invite->who, invite->when);
                sendto_one(cptr, rpl_str(RPL_ENDOFINVITELIST), me.name,
                           cptr->name, chptr->chname);
                anylistsent = 1;
                break;
            }
            if(++nparams > maxparams)
            {
                /* too many modes with params, eat this one */
                args++;
                break;
            }
            
            if (*parv[args] == ':' || *parv[args] == '\0')
            {
                args++; 
                break;
            }

#ifdef NO_LOCAL_CIDR_CHANNELBANS
            if(MyClient(sptr) && strchr(parv[args],'/'))
            {
                sendto_one(sptr,":%s NOTICE %s :*** Notice -- CIDR channel bans/invites/exempts are not supported yet.",
                           me.name, sptr->name);
                args++;
                break;
            }
#endif

            strcpy(nuhbuf, collapse(pretty_mask(parv[args])));
            parv[args] = nuhbuf;
            /* if we're going to overflow our mode buffer,
             * drop the change instead */
            if((prelen + (mbuf - morig) + pidx + strlen(nuhbuf) + 1) > 
               REALMODEBUFLEN) 
            {
                args++;
                break;
            }
            /* if we can't add or delete (depending) the ban, change is
             * worthless anyhow */
            
            if(!(change=='+' && !add_invite_id(sptr, chptr, parv[args])) && 
               !(change=='-' && !del_invite_id(chptr, parv[args])))
            {
                args++;
                break;
            }
            
            *mbuf++ = 'I';
            ADD_PARA(parv[args])
                args++;
            nmodes++;
            break;
#endif

#ifdef EXEMPT_LISTS
        case 'e':
            if (level < 1 && parv[args] != NULL)
            {
                errors |= SM_ERR_NOPRIVS;
                break;
            }
            else if (parv[args] == NULL)
            {
                aBanExempt*    exempt;
                
                if (anylistsent) /* don't send the list if they have received one */
                    break;
                for (exempt = chptr->banexempt_list; exempt; exempt = exempt->next)
                    sendto_one(sptr, rpl_str(RPL_EXEMPTLIST), me.name, cptr->name,
                               chptr->chname, exempt->banstr, exempt->who, exempt->when);
                sendto_one(cptr, rpl_str(RPL_ENDOFEXEMPTLIST), me.name,
                           cptr->name, chptr->chname);
                anylistsent = 1;
                break;
            }
            if(++nparams > maxparams)
            {
                /* too many modes with params, eat this one */
                args++;
                break;
            }
            
            if (*parv[args] == ':' || *parv[args] == '\0')
            {
                args++; 
                break;
            }

#ifdef NO_LOCAL_CIDR_CHANNELBANS
            if(MyClient(sptr) && strchr(parv[args],'/'))
            {
                sendto_one(sptr,":%s NOTICE %s :*** Notice -- CIDR channel bans/invites/exempts are not supported yet.",
                           me.name, sptr->name);
                args++;
                break;
            }
#endif

            strcpy(nuhbuf, collapse(pretty_mask(parv[args])));
            parv[args] = nuhbuf;
            /* if we're going to overflow our mode buffer,
             * drop the change instead */
            if((prelen + (mbuf - morig) + pidx + strlen(nuhbuf) + 1) > 
               REALMODEBUFLEN) 
            {
                args++;
                break;
            }
            /* if we can't add or delete (depending) the exempt, change is
             * worthless anyhow */
            
            if(!(change=='+' && !add_exempt_id(sptr, chptr, parv[args])) && 
               !(change=='-' && !del_exempt_id(chptr, parv[args])))
            {
                args++;
                break;
            }

            *mbuf++ = 'e';
            ADD_PARA(parv[args])
                args++;
            nmodes++;
            break;
#endif
    
        case 'b':
            /* if the user has no more arguments, then they just want
             * to see the bans, okay, cool. */
            if(level < 1 && parv[args] != NULL)
            {
                errors |= SM_ERR_NOPRIVS;
                break;
            }
            /* show them the bans, woowoo */
            if(parv[args]==NULL)
            {
                if (anylistsent)
                    break;
                for(bp=chptr->banlist;bp;bp=bp->next)
                    sendto_one(sptr, rpl_str(RPL_BANLIST), me.name, cptr->name,
                               chptr->chname, bp->banstr, bp->who, bp->when);
                sendto_one(cptr, rpl_str(RPL_ENDOFBANLIST), me.name,
                           cptr->name, chptr->chname);
                anylistsent = 1;
                break; /* we don't pass this along, either.. */
            }
            if(++nparams > maxparams)
            {
                /* too many modes with params, eat this one */
                args++;
                break;
            }
            
            /* do not allow : in bans, or a null ban */
            if(*parv[args]==':' || *parv[args] == '\0') 
            {
                args++;
                break;
            }

#ifdef NO_LOCAL_CIDR_CHANNELBANS
            if(MyClient(sptr) && strchr(parv[args],'/'))
            {
                sendto_one(sptr,":%s NOTICE %s :*** Notice -- CIDR channel bans/invites/exempts are not supported yet.",
                           me.name, sptr->name);
                args++;
                break;
            }
#endif

            /* make a 'pretty' ban mask here, then try and set it */
            /* okay kids, let's do this again.
             * the buffer returned by pretty_mask is from 
             * make_nick_user_host. This buffer is eaten by add/del banid.
             * Thus, some poor schmuck gets himself on the banlist.
             * Fixed. - lucas */
            strcpy(nuhbuf, collapse(pretty_mask(parv[args])));
            parv[args] = nuhbuf;
            /* if we're going to overflow our mode buffer,
             * drop the change instead */
            if((prelen + (mbuf - morig) + pidx + strlen(nuhbuf) + 1) > 
               REALMODEBUFLEN) 
            {
                args++;
                break;
            }
            /* if we can't add or delete (depending) the ban, change is
             * worthless anyhow */
            
            if(!(change=='+' && !add_banid(sptr, chptr, parv[args])) && 
               !(change=='-' && !del_banid(chptr, parv[args])))
            {
                args++;
                break;
            }
            
            *mbuf++ = 'b';
            ADD_PARA(parv[args])
                args++;
            nmodes++;
            break;

        case 'j':
#ifdef JOINRATE_SERVER_ONLY
            if (MyClient(sptr)) 
            {
                sendto_one(sptr, err_str(ERR_ONLYSERVERSCANCHANGE),
                           me.name, cptr->name, chptr->chname);
                break;
            }
#endif

            if(level<1) 
            {
                errors |= SM_ERR_NOPRIVS;
                break;
            }

            /* if it's a -, just change the flag, we have no arguments */
            if(change=='-')
            {
                if (MyClient(sptr) && (seenalready & MODE_JOINRATE))
                    break;
                seenalready |= MODE_JOINRATE;

                if((prelen + (mbuf - morig) + pidx + 1) > REALMODEBUFLEN) 
                    break;
                *mbuf++ = 'j';
                chptr->mode.mode &= ~MODE_JOINRATE;
                chptr->mode.jr_num = DEFAULT_JOIN_NUM;
                chptr->mode.jr_time = DEFAULT_JOIN_TIME;
                chptr->mode.jrl_size = DEFAULT_JOIN_SIZE;
                chptr->jrl_bucket = 0;
                chptr->jrl_last = NOW;  /* slow start */
                nmodes++;
                break;
            }
            else 
            {
                char *tmpa, *tmperr;
                int j_num, j_time, tval;

                if(parv[args] == NULL) 
                {
                    errors|=SM_ERR_MOREPARMS;
                    break;
                }
                if(++nparams > maxparams)
                {
                    /* too many modes with params, eat this one */
                    args++;
                    break;
                }
                if (MyClient(sptr) && (seenalready & MODE_JOINRATE))
                {
                    args++;
                    break;
                }
                seenalready |= MODE_JOINRATE;

                tmpa = strchr(parv[args], ':');
                if(tmpa)
                {
                    *tmpa = '\0';
                    tmpa++;
                    j_time = strtol(tmpa, &tmperr, 10);
                    if(*tmperr != '\0' || j_time < 0)
                    {
                        /* error, user specified something 
                         * invalid, just bail. */
                        args++;
                        break;
                    }
                }
                else
                    j_time = 0;

                j_num = strtol(parv[args], &tmperr, 10);
                if(*tmperr != '\0' || j_num < 0)
                {
                    args++;
                    break;
                }
                
                /* safety cap */
                if (j_num > 127)
                    j_num = 127;
                if (j_time > 127)
                    j_time = 127;

                /* range limit for local non-samodes */
                if (MyClient(sptr) && level < 2)
                {
                    /* static limits: time <= 60, 2 <= num <= 20 */
                    if (j_time > 60)
                        j_time = 60;
                    if (j_num > 20)
                        j_num = 20;
                    if (j_num < 2)
                        j_num = 2;

                    /* adjust number to time using min rate 1/8 */
                    tval = (j_time-1)/8+1;
                    if (j_num < tval)
                        j_num = tval;

                    /* adjust time to number using max rate 2/1 */
                    tval = j_num/2;
                    if (j_time < tval)
                        j_time = tval;
                }

                if(j_num == 0 || j_time == 0)
                {
                    j_num = j_time = 0;
                    ircsprintf(tmp, "0");
                }
                else
                    ircsprintf(tmp, "%d:%d", j_num, j_time);

                /* if we're going to overflow our mode buffer,
                 * drop the change instead */
                if((prelen + (mbuf - morig) + pidx + strlen(tmp)) > REALMODEBUFLEN) 
                {
                    args++;
                    break;
                }

                chptr->mode.mode |= MODE_JOINRATE;
                chptr->mode.jr_num = j_num;
                chptr->mode.jr_time = j_time;
                chptr->mode.jrl_size = j_num * j_time;
                chptr->jrl_bucket = 0;
                chptr->jrl_last = NOW;  /* slow start */
                *mbuf++ = 'j';
                ADD_PARA(tmp);
                args++;
                nmodes++;
                break;
            }

        case 'l':
            if(level<1) 
            {
                errors |= SM_ERR_NOPRIVS;
                break;
            }

            /* if it's a -, just change the flag, we have no arguments */
            if(change=='-')
            {
                if (MyClient(sptr) && (seenalready & MODE_LIMIT))
                    break;
                seenalready |= MODE_LIMIT;

                if((prelen + (mbuf - morig) + pidx + 1) > REALMODEBUFLEN) 
                    break;
                *mbuf++ = 'l';
                chptr->mode.mode &= ~MODE_LIMIT;
                chptr->mode.limit = 0;
                nmodes++;
                break;
            }
            else 
            {
                if(parv[args] == NULL) 
                {
                    errors|=SM_ERR_MOREPARMS;
                    break;
                }
                if(++nparams > maxparams)
                {
                    /* too many modes with params, eat this one */
                    args++;
                    break;
                }
                if (MyClient(sptr) && (seenalready & MODE_LIMIT))
                {
                    args++;
                    break;
                }
                seenalready |= MODE_LIMIT;

                /* if we're going to overflow our mode buffer,
                 * drop the change instead */
                if((prelen + (mbuf - morig) + pidx + 16) > REALMODEBUFLEN) 
                {
                    args++;
                    break;
                }
               
                i = atoi(parv[args]);

                /* toss out invalid modes */
                if(i < 1)
                {
                    args++;
                    break;
                }
                ircsprintf(tmp, "%d", i);
                chptr->mode.limit = i;
                chptr->mode.mode |= MODE_LIMIT;
                *mbuf++ = 'l';
                ADD_PARA(tmp);
                args++;
                nmodes++;
                break;
            }

        case 'k':
            if(level<1) 
            {
                errors |= SM_ERR_NOPRIVS;
                break;
            }
            if(parv[args]==NULL)
                break;
            if(++nparams > maxparams)
            {
                /* too many modes with params, eat this one */
                args++;
                break;
            }
            if (MyClient(sptr) && (seenalready & MODE_KEY))
            {
                args++;
                break;
            }
            seenalready |= MODE_KEY;

            /* do not allow keys to start with :! ack! - lucas */
            /* another ack: don't let people set null keys! */
            /* and yet a third ack: no spaces in keys -epi  */
            if(*parv[args]==':' || *parv[args] == '\0' ||
               strchr(parv[args], ' '))
            {
                args++;
                break;
            }
            
            /* Do not let *'s in keys in preperation for key hiding - Raist
             * Also take out ",", which makes a channel unjoinable - lucas
             */
            
            if (strchr(parv[args], '*') != NULL || 
                strchr(parv[args], ',') != NULL) 
            {
                args++;
                break;
            }
            
            /* if we're going to overflow our mode buffer,
             * drop the change instead */
            if((prelen + (mbuf - morig) + pidx + KEYLEN+2) > REALMODEBUFLEN) 
            {
                args++;
                break;
            }
            
            /* if they're an op, they can futz with the key in
             * any manner they like, we're not picky */
            if(change=='+') 
            {
                strncpy(chptr->mode.key,parv[args],KEYLEN);
                ADD_PARA(chptr->mode.key)
            }
            else 
            {
                char *sendkey = chptr->mode.key;
                if (!*sendkey)
                    sendkey = parv[args];
                ADD_PARA(sendkey)
                *chptr->mode.key = '\0';
            }
            *mbuf++='k';
            args++;
            nmodes++;
            break;

        case 'r':
            if (MyClient(sptr) && (seenalready & MODE_REGISTERED))
                break;
            seenalready |= MODE_REGISTERED;
            if (!IsServer(sptr) && !IsULine(sptr)) 
            {
                sendto_one(sptr, err_str(ERR_ONLYSERVERSCANCHANGE),
                           me.name, cptr->name, chptr->chname);
                break;
            }
            else 
            {
                if((prelen + (mbuf - morig) + pidx + 1) > REALMODEBUFLEN) 
                    break;
                
                if(change=='+')
                    chptr->mode.mode|=MODE_REGISTERED;
                else
                    chptr->mode.mode&=~MODE_REGISTERED;
            }
            *mbuf++='r';
            nmodes++;
            break;

        case 'A':
            if (MyClient(sptr) && (seenalready & MODE_AUDITORIUM))
                break;
            seenalready |= MODE_AUDITORIUM;
            if (MyClient(sptr))
            {
                sendto_one(sptr, err_str(ERR_ONLYSERVERSCANCHANGE),
                           me.name, cptr->name, chptr->chname);
                break;
            }
            else
            {       
                if((prelen + (mbuf - morig) + pidx + 1) > REALMODEBUFLEN)
                    break;
             
                if(change=='+')
                    chptr->mode.mode|=MODE_AUDITORIUM;
                else
                    chptr->mode.mode&=~MODE_AUDITORIUM;
            }
            *mbuf++='A';
            nmodes++;
            break;

        case 'L':
            if (MyClient(sptr) && (seenalready & MODE_LISTED))
                break;
            seenalready |= MODE_LISTED;
            if (MyClient(sptr))
            {
                sendto_one(sptr, err_str(ERR_ONLYSERVERSCANCHANGE),
                           me.name, cptr->name, chptr->chname);
                break;
            }
            else
            {       
                if((prelen + (mbuf - morig) + pidx + 1) > REALMODEBUFLEN)
                    break;
             
                if(change=='+')
                    chptr->mode.mode|=MODE_LISTED;
                else
                    chptr->mode.mode&=~MODE_LISTED;
            }
            *mbuf++='L';
            nmodes++;
            break;
            
        case 'i':
            if(level < 1) 
            {
                errors |= SM_ERR_NOPRIVS;
                break;
            }
            if(change=='-')
                while ((lp=chptr->invites))
                    del_invite(lp->value.cptr, chptr);
            /* fall through to default case */

        default:
            /* phew, no more tough modes. }:>, the rest are all
             * covered in one step 
             * with the above array */
            if(level<1) 
            {
                errors |= SM_ERR_NOPRIVS;
                break;
            }
            for(i=1;flags[i]!=0x0;i+=2) 
            {
                if((prelen + (mbuf - morig) + pidx + 1) > REALMODEBUFLEN) 
                    break;
                
                if(*modes==(char)flags[i]) 
                {
                    if (MyClient(sptr) && (seenalready & flags[i-1]))
                        break;
                    seenalready |= flags[i-1];
                    
                    if(change=='+')
                        chptr->mode.mode |= flags[i-1];
                    else
                        chptr->mode.mode &= ~flags[i-1];
                    *mbuf++=*modes;
                    nmodes++;
                    break;
                }
            }
            /* unknown mode.. */
            if(flags[i]==0x0) 
            {
                /* we still spew lots of unknown mode bits...*/
                /* but only to our own clients, silently ignore bogosity
                 * from other servers... */
                if(MyClient(sptr))
                    sendto_one(sptr, err_str(ERR_UNKNOWNMODE), me.name,
                               sptr->name, *modes);
                        
            }
            break;
        }
        
        /* spit out more parameters error here */
        if(errors & SM_ERR_MOREPARMS && MyClient(sptr)) 
        {
            moreparmsstr[5]=change;
            moreparmsstr[6]=*modes;
            sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name,
                       sptr->name, moreparmsstr);
            errors &= ~SM_ERR_MOREPARMS; /* oops, kill it in this case */
        }
        modes++;
    }
    /* clean up the end of the string... */
    if(*(mbuf-1) == '+' || *(mbuf-1) == '-')
        *(mbuf-1) = '\0';
    else
        *mbuf = '\0';
    pbuf[pidx] = '\0';
    if(MyClient(sptr)) 
    {
        if(errors & SM_ERR_NOPRIVS)
            sendto_one(sptr, err_str(ERR_CHANOPRIVSNEEDED), me.name,
                       sptr->name, chptr->chname);        
        if(errors & SM_ERR_NOTOPER)
            sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, sptr->name);
        if(errors & SM_ERR_RESTRICTED)
            sendto_one(sptr,":%s NOTICE %s :*** Notice -- You are "
                       "restricted and cannot chanop others",
                       me.name, sptr->name);
    }
    /* all done! */
    return nmodes;
#undef ADD_PARA
}

static int can_join(aClient *sptr, aChannel *chptr, char *key)
{
    Link   *lp;
    int invited = 0;
    int error = 0;
    int jrl = 0;
    char *r = NULL;

    for(lp = sptr->user->invited; lp; lp = lp->next)
    {
        if(lp->value.chptr == chptr)
        {
            invited = 1;
            break;
        }
    }

    if (invited)
        return 1;
    
    joinrate_prejoin(chptr);

    if (chptr->join_connect_time && (sptr->firsttime + chptr->join_connect_time > NOW) && !is_xflags_exempted(sptr,chptr))
    {
        r = "+X";
        error = ERR_NEEDTOWAIT;
    }
    else if (chptr->mode.mode & MODE_INVITEONLY)
    {
        r = "+i";
        error = ERR_INVITEONLYCHAN;
    }
    else if (chptr->mode.mode & MODE_OPERONLY && !IsOper(sptr))
    {
        r = "+O";
        error = ERR_INVITEONLYCHAN;
    }
    else if (chptr->mode.limit && chptr->users >= chptr->mode.limit)
    {
        r = "+l";
        error = ERR_CHANNELISFULL;
    }
    else if (chptr->mode.mode & MODE_SSLONLY && !IsSSL(sptr))
    {
        r = "+S";
        error = ERR_NOSSL;
    }
    else if (chptr->mode.mode & MODE_REGONLY && !IsRegNick(sptr))
        error = ERR_NEEDREGGEDNICK;
    else if (*chptr->mode.key && (BadPtr(key) || mycmp(chptr->mode.key, key)))
        error = ERR_BADCHANNELKEY;
    else if (!joinrate_check(chptr, sptr, 1))
    {
        r = "+j";
        error = ERR_CHANNELISFULL;
        jrl = 1;
    }

#ifdef INVITE_LISTS
    if (error && !jrl && is_invited(sptr, chptr) && (error!=ERR_NEEDTOWAIT || (chptr->xflags & XFLAG_EXEMPT_INVITES)))
        error = 0;
#endif

    if (!error && is_banned(sptr, chptr, NULL))
        error = ERR_BANNEDFROMCHAN;

    if (error)
    {
        if (!jrl)
            joinrate_warn(chptr, sptr);

        if(error==ERR_NEEDTOWAIT)
        {
            sendto_one(sptr,":%s NOTICE %s :*** Notice -- You must wait %ld seconds before you will be able to join %s", me.name, sptr->name, (sptr->firsttime + chptr->join_connect_time - NOW), chptr->chname);
            /* Let's also fake a nice reject message most clients will recognize -Kobi. */
            if(chptr->xflags & XFLAG_EXEMPT_REGISTERED)
                error = ERR_NEEDREGGEDNICK;
            else
                error = ERR_INVITEONLYCHAN;
        }

        if (error==ERR_NEEDREGGEDNICK)
            sendto_one(sptr, getreply(ERR_NEEDREGGEDNICK), me.name, sptr->name,
                       chptr->chname, "join", aliastab[AII_NS].nick,
                       aliastab[AII_NS].server, NS_Register_URL);
        else
            sendto_one(sptr, getreply(error), me.name, sptr->name,
                       chptr->chname, r);
        return 0;
    }

    return 1;
}

/*
 * can_join_whynot:
 * puts a list of the modes preventing us from joining in reasonbuf
 * ret is number of matched modes
 */
static int 
can_join_whynot(aClient *sptr, aChannel *chptr, char *key, char *reasonbuf)
{
    Link   *lp;
    int invited = 0;
    int rbufpos = 0;

    for(lp = sptr->user->invited; lp; lp = lp->next) 
    {
        if(lp->value.chptr == chptr) 
        {
            invited = 1;
            break;
        }
    }

    if (invited)
        return 0;
    
    joinrate_prejoin(chptr);

    if (chptr->mode.mode & MODE_INVITEONLY)
        reasonbuf[rbufpos++] = 'i';
    if (chptr->mode.mode & MODE_REGONLY && !IsRegNick(sptr))
        reasonbuf[rbufpos++] = 'R';
    if (chptr->mode.mode & MODE_OPERONLY && !IsOper(sptr))
        reasonbuf[rbufpos++] = 'O';
    if (*chptr->mode.key && (BadPtr(key) || mycmp(chptr->mode.key, key)))
        reasonbuf[rbufpos++] = 'k';
    if (chptr->mode.limit && chptr->users >= chptr->mode.limit) 
        reasonbuf[rbufpos++] = 'l';
    if (!joinrate_check(chptr, sptr, 0))
        reasonbuf[rbufpos++] = 'j';

#ifdef INVITE_LISTS
    if (rbufpos && is_invited(sptr, chptr))
        rbufpos = 0;
#endif

    if (is_banned(sptr, chptr, NULL))
        reasonbuf[rbufpos++] = 'b';

    reasonbuf[rbufpos] = '\0';
    return rbufpos;
}

/*
 * Remove bells and commas from channel name
 */
void clean_channelname(unsigned char *cn)
{
    for (; *cn; cn++)
        /*
         * All characters >33 are allowed, except commas, and the weird
         * fake-space character mIRCers whine about -wd
         */
        if (*cn < 33 || *cn == ',' || (*cn == 160))
        {
            *cn = '\0';
            return;
        }
    return;
}

/* we also tell the client if the channel is invalid. */
int check_channelname(aClient *cptr, unsigned char *cn)
{
    if(!MyClient(cptr))
        return 1;
    for(;*cn;cn++) 
    {
        if(*cn<33 || *cn == ',' || *cn==160) 
        {
            sendto_one(cptr, getreply(ERR_BADCHANNAME), me.name, cptr->name,
                       cn);
            return 0;
        }
    }
    return 1;
}

/*
 * *  Get Channel block for chname (and allocate a new channel *
 * block, if it didn't exist before).
 */
static aChannel *
get_channel(aClient *cptr, char *chname, int flag, int *created)
{
    aChannel *chptr;
    int         len;

    if(created)
        *created = 0;

    if (BadPtr(chname))
        return NULL;

    len = strlen(chname);
    if (MyClient(cptr) && len > CHANNELLEN)
    {
        len = CHANNELLEN;
        *(chname + CHANNELLEN) = '\0';
    }
    if ((chptr = find_channel(chname, (aChannel *) NULL)))
        return (chptr);
    if (flag == CREATE)
    {
        chptr = make_channel();

        if(created)
            *created = 1;
        
        strncpyzt(chptr->chname, chname, len + 1);
        if (channel)
            channel->prevch = chptr;
        chptr->prevch = NULL;
        chptr->nextch = channel;
        channel = chptr;
        chptr->channelts = timeofday;
        chptr->max_bans = MAXBANS;
        (void) add_to_channel_hash_table(chname, chptr);
        Count.chan++;
    }
    return chptr;
}

static void add_invite(aClient *cptr, aChannel *chptr)
{
    Link   *inv, **tmp;
    
    del_invite(cptr, chptr);
    /*
     * delete last link in chain if the list is max length
     */
    if (list_length(cptr->user->invited) >= maxchannelsperuser)
    {
        /*
         * This forgets the channel side of invitation     -Vesa inv =
         * cptr->user->invited; cptr->user->invited = inv->next;
         * free_link(inv);
         */
        del_invite(cptr, cptr->user->invited->value.chptr);
        
    }
    
    /*
     * add client to channel invite list
     */
    inv = make_link();
    inv->value.cptr = cptr;
    inv->next = chptr->invites;
    chptr->invites = inv;
    /*
     * add channel to the end of the client invite list
     */
    for (tmp = &(cptr->user->invited); *tmp; tmp = &((*tmp)->next));
    inv = make_link();
    inv->value.chptr = chptr;
    inv->next = NULL;
    (*tmp) = inv;
}

/*
 * Delete Invite block from channel invite list and client invite list
 */
void del_invite(aClient *cptr, aChannel *chptr)
{
    Link  **inv, *tmp;

    for (inv = &(chptr->invites); (tmp = *inv); inv = &tmp->next)
        if (tmp->value.cptr == cptr)
        {
            *inv = tmp->next;
            free_link(tmp);
            break;
        }
    
    for (inv = &(cptr->user->invited); (tmp = *inv); inv = &tmp->next)
        if (tmp->value.chptr == chptr)
        {
            *inv = tmp->next;
            free_link(tmp);
            break;
        }
}

/*
 * *  Subtract one user from channel i (and free channel *  block, if
 * channel became empty).
 */
static void sub1_from_channel(aChannel *chptr)
{
    Link   *tmp;
    aBan              *bp, *bprem;
#ifdef INVITE_LISTS
    anInvite          *invite, *invrem;
#endif
#ifdef EXEMPT_LISTS
    aBanExempt        *exempt, *exrem;
#endif
    
    if (--chptr->users <= 0) 
    {
        /*
         * Now, find all invite links from channel structure
         */
        while ((tmp = chptr->invites))
            del_invite(tmp->value.cptr, chptr);

        bp = chptr->banlist;
        while (bp)
        {
            bprem = bp;
            bp = bp->next;
            MyFree(bprem->banstr);
            MyFree(bprem->who);
            MyFree(bprem);
        }
#ifdef INVITE_LISTS
        invite = chptr->invite_list;
        while (invite)
	 {
            invrem = invite;
            invite = invite->next;
            MyFree(invrem->invstr);
            MyFree(invrem->who);
            MyFree(invrem);
        }
#endif
#ifdef EXEMPT_LISTS
        exempt = chptr->banexempt_list;
        while (exempt)
        {
            exrem = exempt;
            exempt = exempt->next;
            MyFree(exrem->banstr);
            MyFree(exrem->who);
            MyFree(exrem);
        }
#endif

        if (chptr->prevch)
            chptr->prevch->nextch = chptr->nextch;
        else
            channel = chptr->nextch;
        if (chptr->nextch)
            chptr->nextch->prevch = chptr->prevch;
        (void) del_from_channel_hash_table(chptr->chname, chptr);
#ifdef FLUD
        free_fluders(NULL, chptr);
#endif
        if(chptr->greetmsg) MyFree(chptr->greetmsg);
        free_channel(chptr);
        Count.chan--;
    }
}

/*
 * m_join 
 * parv[0] = sender prefix
 * parv[1] = channel
 * parv[2] = channel password (key)
 */
int m_join(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    static char jbuf[BUFSIZE];
    Link   *lp;
    struct simBan *ban;
    aChannel *chptr;
    char   *name, *key = NULL;
    int         i, flags = 0, chanlen=0;        
    int         allow_op = YES;
    char       *p = NULL, *p2 = NULL;
        
#ifdef ANTI_SPAMBOT
    int         successful_join_count = 0;      
    /* Number of channels successfully joined */
#endif
        
    if (!(sptr->user))
    {
        /* something is *fucked* - bail */
        return 0;
    }
        
    if (parc < 2 || *parv[1] == '\0')
    {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
                   me.name, parv[0], "JOIN");
        return 0;
    }

    if (MyClient(sptr))
        parv[1] = canonize(parv[1]);
        
    *jbuf = '\0';
    /*
     * * Rebuild list of channels joined to be the actual result of the *
     * JOIN.  Note that "JOIN 0" is the destructive problem.
     */
    for (i = 0, name = strtoken(&p, parv[1], ","); name;
         name = strtoken(&p, (char *) NULL, ","))
    {
        /*
         * pathological case only on longest channel name. * If not dealt
         * with here, causes desynced channel ops * since ChannelExists()
         * doesn't see the same channel * as one being joined. cute bug.
         * Oct 11 1997, Dianora/comstud
         */
        if(!check_channelname(sptr, (unsigned char *) name))
            continue;
        
        chanlen=strlen(name);
        
        if (chanlen > CHANNELLEN) /* same thing is done in get_channel() */
        {
            name[CHANNELLEN] = '\0';
            chanlen=CHANNELLEN;
        }
        if (*name == '0' && !atoi(name))
            *jbuf = '\0';
        else if (!IsChannelName(name))
        {
            if (MyClient(sptr))
                sendto_one(sptr, err_str(ERR_NOSUCHCHANNEL),
                           me.name, parv[0], name);
            continue;
        }
        if (*jbuf)
            (void) strcat(jbuf, ",");
        (void) strncat(jbuf, name, sizeof(jbuf) - i - 1);
        i += chanlen + 1;
    }
    
    p = NULL;
    if (parv[2])
        key = strtoken(&p2, parv[2], ",");
    parv[2] = NULL;             /*
                                 * for m_names call later, parv[parc]
                                 * * must == NULL 
                                 */
    for (name = strtoken(&p, jbuf, ","); name;
         key = (key) ? strtoken(&p2, NULL, ",") : NULL,
             name = strtoken(&p, NULL, ","))
    {
        /*
         * JOIN 0 sends out a part for all channels a user * has
         * joined.
         */
        if (*name == '0' && !atoi(name))
        {
            if (sptr->user->channel == NULL)
                continue;
            while ((lp = sptr->user->channel))
            {
                chptr = lp->value.chptr;
                sendto_channel_butserv(chptr, sptr, PartFmt,
                                       parv[0], chptr->chname);
                remove_user_from_channel(sptr, chptr);
            }
            /*
             * Added /quote set for SPAMBOT
             * 
             * int spam_time = MIN_JOIN_LEAVE_TIME; int spam_num =
             * MAX_JOIN_LEAVE_COUNT;
             */
#ifdef ANTI_SPAMBOT             /* Dianora */
                        
            if (MyConnect(sptr) && !IsAnOper(sptr))
            {
                if (sptr->join_leave_count >= spam_num)
                {
                    sendto_realops_lev(SPAM_LEV, "User %s (%s@%s) is a "
                                   "possible spambot", sptr->name,
                                   sptr->user->username, sptr->user->host);
                    sptr->oper_warn_count_down = OPER_SPAM_COUNTDOWN;
                }
                else
                {
                    int         t_delta;
                    
                    if ((t_delta = (NOW - sptr->last_leave_time)) >
                        JOIN_LEAVE_COUNT_EXPIRE_TIME)
                    {
                        int         decrement_count;
                        
                        decrement_count = (t_delta /
                                           JOIN_LEAVE_COUNT_EXPIRE_TIME);
                        
                        if (decrement_count > sptr->join_leave_count)
                            sptr->join_leave_count = 0;
                        else
                            sptr->join_leave_count -= decrement_count;
                    }
                    else
                    {
                        if ((NOW - (sptr->last_join_time)) < spam_time)
                        {
                            /* oh, its a possible spambot */
                            sptr->join_leave_count++;
                        }
                    }
                    sptr->last_leave_time = NOW;
                }
            }
#endif
            sendto_serv_butone(cptr, ":%s JOIN 0", parv[0]);
            continue;
        }
        
        if (MyConnect(sptr))
        {
            /* have we quarantined this channel? */
            if(!IsOper(sptr) && (ban = check_mask_simbanned(name, SBAN_CHAN)))
            {
                sendto_one(sptr, getreply(ERR_CHANBANREASON), me.name, parv[0], name,
                        BadPtr(ban->reason) ? "Reserved channel" :      
                        ban->reason);
                if (call_hooks(CHOOK_FORBID, cptr, name, ban) != FLUSH_BUFFER)
                    sendto_realops_lev(REJ_LEV,
                                       "Forbidding restricted channel %s from %s",
                                       name, get_client_name(cptr, FALSE));
                continue;
            }

            /*
             * local client is first to enter previously nonexistent *
             * channel so make them (rightfully) the Channel * Operator.
             */
            flags = (ChannelExists(name)) ? 0 : CHFL_CHANOP;

            if (!IsAnOper(sptr) && server_was_split
                && !(confopts & FLAGS_SPLITOPOK))
                    allow_op = NO;
            
            if ((sptr->user->joined >= maxchannelsperuser) &&
                (!IsAnOper(sptr) || (sptr->user->joined >= 
                                     maxchannelsperuser * 3)))
            {
                sendto_one(sptr, err_str(ERR_TOOMANYCHANNELS),
                           me.name, parv[0], name);
#ifdef ANTI_SPAMBOT
                if (successful_join_count)
                    sptr->last_join_time = NOW;
#endif
                return 0;
            }
#ifdef ANTI_SPAMBOT             /*
                                 * Dianora 
                                 */
            if (flags == 0)     /* if channel doesn't exist, don't penalize */
                successful_join_count++;
            if (sptr->join_leave_count >= spam_num)
            {
                                /* Its already known as a possible spambot */
                
                if (sptr->oper_warn_count_down > 0)  /* my general paranoia */
                    sptr->oper_warn_count_down--;
                else
                    sptr->oper_warn_count_down = 0;
                
                if (sptr->oper_warn_count_down == 0)
                {
                    sendto_realops_lev(SPAM_LEV, "User %s (%s@%s) trying to "
                                   "join %s is a possible spambot",
                                   sptr->name,
                                   sptr->user->username,
                                   sptr->user->host,
                                   name);
                    sptr->oper_warn_count_down = OPER_SPAM_COUNTDOWN;
                }
# ifndef ANTI_SPAMBOT_WARN_ONLY
                return 0;               /* Don't actually JOIN anything, but
                                         * don't let spambot know that */
# endif
            }
#endif
        }
        else
        {
            /*
             * complain for remote JOINs to existing channels * (they
             * should be SJOINs) -orabidoo
             */
            if (!ChannelExists(name))
                ts_warn("User on %s remotely JOINing new channel",
                        sptr->user->server);
        }

        chptr = get_channel(sptr, name, CREATE, NULL);

        if (chptr && IsMember(sptr, chptr))
            continue;

        if (call_hooks(CHOOK_JOIN, sptr, chptr) == FLUSH_BUFFER)
            continue; /* Let modules reject JOINs */

        
        if (!chptr || (MyConnect(sptr) && !can_join(sptr, chptr, key)))
        {
#ifdef ANTI_SPAMBOT
            if (successful_join_count > 0)
                successful_join_count--;
#endif
            continue;
        }
        
/* only complain when the user can join the channel, the channel is
 * being created by this user, and this user is not allowed to be an op.
 * - lucas 
 */

        if (flags && !allow_op)
            sendto_one(sptr, ":%s NOTICE %s :*** Notice -- Due to a network "
                       "split, you can not obtain channel operator status in "
                       "a new channel at this time.", me.name, sptr->name);
        
        /* Complete user entry to the new channel (if any) */
        if (allow_op)
            add_user_to_channel(chptr, sptr, flags);
        else
            add_user_to_channel(chptr, sptr, 0);
        joinrate_dojoin(chptr, sptr);
        /* Set timestamp if appropriate, and propagate */
        if (MyClient(sptr) && flags == CHFL_CHANOP) 
        {
            chptr->channelts = timeofday;
            
            /* we keep channel "creations" to the server sjoin format,
               so we can bounce modes and stuff if our ts is older. */
            
            if (allow_op)
                sendto_serv_butone(cptr, ":%s SJOIN %ld %s + :@%s", me.name,
                                   chptr->channelts, name, parv[0]);
            else
                sendto_serv_butone(cptr, ":%s SJOIN %ld %s + :%s", me.name,
                                   chptr->channelts, name, parv[0]);
        }
        else if (MyClient(sptr)) 
            sendto_serv_butone(cptr, CliSJOINFmt, parv[0], chptr->channelts,
                               name);
        else 
            sendto_serv_butone(cptr, ":%s JOIN :%s", parv[0], name);

        /* notify all other users on the new channel */
        sendto_channel_butserv(chptr, sptr, ":%s JOIN :%s", parv[0], name);
                
        if (MyClient(sptr)) 
        {
            del_invite(sptr, chptr);
            if (chptr->topic[0] != '\0') 
            {
                sendto_one(sptr, rpl_str(RPL_TOPIC), me.name,
                           parv[0], name, chptr->topic);
                sendto_one(sptr, rpl_str(RPL_TOPICWHOTIME),
                           me.name, parv[0], name,
                           chptr->topic_nick,
                           chptr->topic_time);
            }
            parv[1] = name;
            (void) m_names(cptr, sptr, 2, parv);
            if(chptr->greetmsg)
            {
                sendto_one(sptr, ":%s!%s@%s PRIVMSG %s :%s", Network_Name, Network_Name, DEFAULT_STAFF_ADDRESS, name, chptr->greetmsg);
            }
        }
    }
        
#ifdef ANTI_SPAMBOT
    if (MyConnect(sptr) && successful_join_count)
        sptr->last_join_time = NOW;
#endif
    return 0;
}

/* m_sajoin
 * join a channel regardless of modes.
 */

int m_sajoin(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
        aChannel        *chptr;
        char            *name;
        int              i;
        char            errmodebuf[128];

        /* Remote sajoin? nope. */
        if(!MyClient(sptr))
                return 0;

        if(!IsSAdmin(sptr))
        {
                sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
                return 0;
        }

        if (parc < 2 || *parv[1] == '\0')
        {
                sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
                           me.name, parv[0], "SAJOIN");
                return 0;
        }

        name = parv[1];

        chptr = find_channel(name, NULL);
        if(!chptr)
        {
                sendto_one(sptr, err_str(ERR_NOSUCHCHANNEL),
                           me.name, parv[0], name);
                return 0;
        }

        /* bail if they're already in the channel */
        if(IsMember(sptr, chptr))
                return 0;

        if((i = can_join_whynot(sptr, chptr, NULL, errmodebuf)))
        {
            send_globops("from %s: %s used SAJOIN (%s +%s)",
                         me.name, sptr->name, chptr->chname, errmodebuf);
            sendto_serv_butone(NULL, ":%s GLOBOPS :%s used SAJOIN (%s +%s)",
                               me.name, sptr->name, chptr->chname, errmodebuf);
        }
        else
            sendto_one(sptr, ":%s NOTICE %s :You didn't need to use"
                       " /SAJOIN for %s", me.name, parv[0], chptr->chname);

        add_user_to_channel(chptr, sptr, 0);
        sendto_serv_butone(cptr, CliSJOINFmt, parv[0], chptr->channelts, name);
        sendto_channel_butserv(chptr, sptr, ":%s JOIN :%s", parv[0], name);
        if(MyClient(sptr))
        {
            if(chptr->topic[0] != '\0')
            {
                sendto_one(sptr, rpl_str(RPL_TOPIC), me.name, parv[0], 
                            name, chptr->topic);
                sendto_one(sptr, rpl_str(RPL_TOPICWHOTIME), me.name, parv[0], 
                            name, chptr->topic_nick, chptr->topic_time);
            }
            parv[1] = name;
            parv[2] = NULL;
            m_names(cptr, sptr, 2, parv);
        }
        return 0;
}

/*
 * m_part 
 * parv[0] = sender prefix 
 * parv[1] = channel
 * parv[2] = Optional part reason
 */
int m_part(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aChannel *chptr;
    char       *p, *name;
    char *reason = (parc > 2 && parv[2]) ? parv[2] : NULL;

    if (parc < 2 || parv[1][0] == '\0')
    {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
                   me.name, parv[0], "PART");
        return 0;
    }
    
    name = strtoken(&p, parv[1], ",");
    
#ifdef ANTI_SPAMBOT             /* Dianora */
    /* if its my client, and isn't an oper */
    
    if (name && MyConnect(sptr) && !IsAnOper(sptr))
    {
        if (sptr->join_leave_count >= spam_num)
        {
            sendto_realops_lev(SPAM_LEV, "User %s (%s@%s) is a possible"
                        " spambot", sptr->name, sptr->user->username, 
                        sptr->user->host);
            sptr->oper_warn_count_down = OPER_SPAM_COUNTDOWN;
        }
        else
        {
            int         t_delta;

            if ((t_delta = (NOW - sptr->last_leave_time)) >
                JOIN_LEAVE_COUNT_EXPIRE_TIME)
            {
                int         decrement_count;

                decrement_count = (t_delta / JOIN_LEAVE_COUNT_EXPIRE_TIME);

                if (decrement_count > sptr->join_leave_count)
                    sptr->join_leave_count = 0;
                else
                    sptr->join_leave_count -= decrement_count;
            }
            else
            {
                if ((NOW - (sptr->last_join_time)) < spam_time)
                {
                    /* oh, its a possible spambot */
                    sptr->join_leave_count++;
                }
            }
            sptr->last_leave_time = NOW;
        }
    }
#endif

    while (name)
    {
        chptr = get_channel(sptr, name, 0, NULL);
        if (!chptr)
        {
            sendto_one(sptr, err_str(ERR_NOSUCHCHANNEL),
                       me.name, parv[0], name);
            name = strtoken(&p, (char *) NULL, ",");
            continue;
        }

        if (!IsMember(sptr, chptr))
        {
            sendto_one(sptr, err_str(ERR_NOTONCHANNEL),
                       me.name, parv[0], name);
            name = strtoken(&p, (char *) NULL, ",");
            continue;
        }

#ifdef SPAMFILTER
        if(MyClient(sptr) && reason && !(chptr->mode.mode & MODE_PRIVACY) && check_sf(sptr, reason, "part", SF_CMD_PART, chptr->chname))
            return FLUSH_BUFFER;
#endif

        /* Remove user from the old channel (if any) */

        if (parc < 3 || can_send(sptr,chptr,reason) || IsSquelch(sptr) || ((chptr->xflags & XFLAG_NO_PART_MSG) && !is_xflags_exempted(sptr,chptr)))
        {
            sendto_serv_butone(cptr, PartFmt, parv[0], name);
            sendto_channel_butserv(chptr, sptr, PartFmt, parv[0], name);
        }
        else
        {
            sendto_serv_butone(cptr, PartFmt2, parv[0], name, reason);
            sendto_channel_butserv(chptr, sptr, PartFmt2, parv[0], name,
                                   reason);
        }
        remove_user_from_channel(sptr, chptr);
        name = strtoken(&p, (char *) NULL, ",");
    }
    return 0;
}

/*
 * m_kick
 * parv[0] = sender prefix
 * parv[1] = channel
 * parv[2] = client to kick
 * parv[3] = kick comment
 */
int m_kick(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aClient    *who;
    aChannel   *chptr;
    int         chasing = 0;
    int         user_count;     /* count nicks being kicked, only allow 4 */
    char       *comment, *name, *p = NULL, *user, *p2 = NULL;

    if (parc < 3 || *parv[1] == '\0')
    {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
                   me.name, parv[0], "KICK");
        return 0;
    }
    if (IsServer(sptr) && !IsULine(sptr))
        sendto_ops("KICK from %s for %s %s",
                   parv[0], parv[1], parv[2]);
    comment = (BadPtr(parv[3])) ? parv[0] : parv[3];
    if (strlen(comment) > (size_t) TOPICLEN)
        comment[TOPICLEN] = '\0';
    
    *nickbuf = *buf = '\0';
    name = strtoken(&p, parv[1], ",");
    
    while (name)
    {
        chptr = get_channel(sptr, name, !CREATE, NULL);
        if (!chptr)
        {
            sendto_one(sptr, err_str(ERR_NOSUCHCHANNEL),
                       me.name, parv[0], name);
            name = strtoken(&p, (char *) NULL, ",");
            continue;
        }

        /*
         * You either have chan op privs, or you don't -Dianora 
         *
         * orabidoo and I discussed this one for a while... I hope he
         * approves of this code, users can get quite confused...
         * -Dianora
         */

        if (!IsServer(sptr) && !is_chan_op(sptr, chptr) && !IsULine(sptr))
        {
            /* was a user, not a server and user isn't seen as a chanop here */

            if (MyConnect(sptr))
            {
                /* user on _my_ server, with no chanops.. so go away */

                sendto_one(sptr, err_str(ERR_CHANOPRIVSNEEDED),
                           me.name, parv[0], chptr->chname);
                name = strtoken(&p, (char *) NULL, ",");
                continue;
            }
            
            if (chptr->channelts == 0)
            {
                /* If its a TS 0 channel, do it the old way */

                sendto_one(sptr, err_str(ERR_CHANOPRIVSNEEDED),
                           me.name, parv[0], chptr->chname);
                name = strtoken(&p, (char *) NULL, ",");
                continue;
            }
            /*
             * Its a user doing a kick, but is not showing as chanop
             * locally its also not a user ON -my- server, and the channel
             * has a TS. There are two cases we can get to this point
             * then...
             * 
             * 1) connect burst is happening, and for some reason a legit op
             * has sent a KICK, but the SJOIN hasn't happened yet or been
             * seen. (who knows.. due to lag...)
             * 
             * 2) The channel is desynced. That can STILL happen with TS
             * 
             * Now, the old code roger wrote, would allow the KICK to go
             * through. Thats quite legit, but lets weird things like
             * KICKS by users who appear not to be chanopped happen, or
             * even neater, they appear not to be on the channel. This
             * fits every definition of a desync, doesn't it? ;-) So I
             * will allow the KICK, otherwise, things are MUCH worse. But
             * I will warn it as a possible desync.
             * 
             * -Dianora
             *
             * sendto_one(sptr, err_str(ERR_DESYNC), me.name, parv[0],
             * chptr->chname);
             *
             * After more discussion with orabidoo...
             * 
             * The code was sound, however, what happens if we have +h (TS4)
             * and some servers don't understand it yet? we will be seeing
             * servers with users who appear to have no chanops at all,
             * merrily kicking users.... -Dianora
             * 
             */
        }

        user = strtoken(&p2, parv[2], ",");
        user_count = 4;
        while (user && user_count)
        {
            user_count--;
            if (!(who = find_chasing(sptr, user, &chasing)))
            {
                user = strtoken(&p2, (char *) NULL, ",");
                continue;               /* No such user left! */
            }

            if (IsMember(who, chptr))
            {
#ifdef SPAMFILTER
                if(MyClient(sptr))
                {
                    if(!(chptr->mode.mode & MODE_PRIVACY) && check_sf(sptr, comment, "kick", SF_CMD_KICK, chptr->chname))
                        return FLUSH_BUFFER;
                }
#endif
                if((chptr->mode.mode & MODE_AUDITORIUM) && !is_chan_opvoice(who, chptr))
                {
                    sendto_channelopvoice_butserv_me(chptr, sptr,
                                                     ":%s KICK %s %s :%s", parv[0],
                                                     name, who->name, comment);
                    sendto_one(who, ":%s KICK %s %s :%s", parv[0], name, who->name, comment);
                }
                else
                    sendto_channel_butserv(chptr, sptr,
                                           ":%s KICK %s %s :%s", parv[0],
                                           name, who->name, comment);
                sendto_serv_butone(cptr, ":%s KICK %s %s :%s", parv[0], name,
                                   who->name, comment);
                remove_user_from_channel(who, chptr);
            }
            else
                sendto_one(sptr, err_str(ERR_USERNOTINCHANNEL),
                           me.name, parv[0], user, name);
            user = strtoken(&p2, (char *) NULL, ",");
        }                               /* loop on parv[2] */

        name = strtoken(&p, (char *) NULL, ",");
    }                           /* loop on parv[1] */

    return (0);
}

int count_channels(aClient *sptr)
{
    aChannel *chptr;
    int     count = 0;

    for (chptr = channel; chptr; chptr = chptr->nextch)
        count++;
    return (count);
}

void send_topic_burst(aClient *cptr)
{
    aChannel *chptr;
    aClient *acptr;
    struct FlagList *xflag;
    char *tmpptr;            /* Temporary pointer to remove the user@host part from tnick for non-NICKIPSTR servers */
    char tnick[NICKLEN + 1]; /* chptr->topic_nick without the user@host part for non-NICKIPSTR servers */
    int len;                 /* tnick's length */

    if (!(confopts & FLAGS_SERVHUB) || !(cptr->serv->uflags & ULF_NOBTOPIC))
        for (chptr = channel; chptr; chptr = chptr->nextch)
        {
            if(chptr->topic[0] != '\0')
            {
                if(cptr->capabilities & CAPAB_NICKIPSTR)
                    sendto_one(cptr, ":%s TOPIC %s %s %ld :%s", me.name, chptr->chname,
                               chptr->topic_nick, (long)chptr->topic_time,
			       chptr->topic);
                else
                {
                    /* This is a non-NICKIPSTR server, we need to remove the user@host part before we send it */
                    tmpptr = chptr->topic_nick;
                    len = 0;
                    while(*tmpptr && *tmpptr!='!')
                        tnick[len++] = *(tmpptr++);
                    tnick[len] = '\0';
                    sendto_one(cptr, ":%s TOPIC %s %s %ld :%s", me.name, chptr->chname,
                               tnick, (long)chptr->topic_time,
			       chptr->topic);
                }
            }
            if(chptr->xflags & XFLAG_SET)
            {
                /* Not very optimized but we'll survive... -Kobi. */
                sendto_one(cptr, ":%s SVSXCF %s JOIN_CONNECT_TIME:%d TALK_CONNECT_TIME:%d TALK_JOIN_TIME:%d", me.name, chptr->chname, chptr->join_connect_time, chptr->talk_connect_time, chptr->talk_join_time);
                for(xflag = xflags_list; xflag->option; xflag++)
                {
                    sendto_one(cptr, ":%s SVSXCF %s:%d", me.name, xflag->option, (chptr->xflags & xflag->flag)?1:0);
                }
                if(chptr->greetmsg && (chptr->max_bans != MAXBANS))
                    sendto_one(cptr, ":%s SVSXCF %s MAX_BANS:%d GREETMSG :%s", me.name, chptr->chname, chptr->max_bans, chptr->greetmsg);
                else if(chptr->greetmsg)
                    sendto_one(cptr, ":%s SVSXCF %s GREETMSG :%s", me.name, chptr->chname, chptr->greetmsg);
                else if(chptr->max_bans != MAXBANS)
                    sendto_one(cptr, ":%s SVSXCF %s MAX_BANS:%d", me.name, chptr->chname, chptr->max_bans);
            }
        }

    if (!(confopts & FLAGS_SERVHUB) || !(cptr->serv->uflags & ULF_NOBAWAY))
        for (acptr = client; acptr; acptr = acptr->next)
        {
            if(!IsPerson(acptr) || acptr->from == cptr)
                continue;
            if(acptr->user->away)
                sendto_one(cptr, ":%s AWAY :%s", acptr->name, acptr->user->away);
        }
}

/*
 * m_topic 
 * parv[0] = sender prefix 
 * parv[1] = topic text
 */
int m_topic(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aChannel   *chptr = NullChn;
    char       *topic = NULL, *name, *tnick;
    char       *tmpptr; /* Temporary pointer to remove the user@host part from tnick for non-NICKIPSTR servers */
    time_t     ts = timeofday;
    int        member;  

    if (parc < 2) 
    {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0],
                   "TOPIC");
        return 0;
    }
        
    name = parv[1];
    chptr = find_channel(name, NullChn);
    if(!chptr) 
    {
        sendto_one(sptr, err_str(ERR_NOSUCHCHANNEL), me.name, parv[0], name);
        return 0;
    }
    
    member = IsMember(sptr, chptr);
    
    if (parc == 2) /* user is requesting a topic */ 
    {   
        char *namep = chptr->chname;
        char tempchname[CHANNELLEN + 2];

        if(!member && !(ShowChannel(sptr, chptr)))
        {
            if(IsAdmin(sptr))
            {
                tempchname[0] = '%';
                strcpy(&tempchname[1], chptr->chname);
                namep = tempchname;
            }
            else
            {
                sendto_one(sptr, err_str(ERR_NOTONCHANNEL), me.name, parv[0],
                           name);
                return 0;
            }
        }

        if (chptr->topic[0] == '\0')
            sendto_one(sptr, rpl_str(RPL_NOTOPIC), me.name, parv[0], namep);
        else 
        {
            sendto_one(sptr, rpl_str(RPL_TOPIC), me.name, parv[0], namep,
                       chptr->topic);
            sendto_one(sptr, rpl_str(RPL_TOPICWHOTIME), me.name, parv[0],
                       namep, chptr->topic_nick, chptr->topic_time);
        }
        return 0;
    }

    topic = parv[2];

    if (MyClient(sptr))
    {
        if (!member)
        {
            sendto_one(sptr, err_str(ERR_NOTONCHANNEL), me.name, parv[0],name);
            return 0;
        }

        if ((chptr->mode.mode & MODE_TOPICLIMIT) && !is_chan_op(sptr, chptr))
        {
            sendto_one(sptr, err_str(ERR_CHANOPRIVSNEEDED), me.name, parv[0],
                       chptr->chname);
            return 0;
        }
#ifdef SPAMFILTER
        if(!(chptr->mode.mode & MODE_PRIVACY) && check_sf(sptr, topic, "topic", SF_CMD_TOPIC, chptr->chname))
            return FLUSH_BUFFER;
#endif

        /* if -t and banned, you can't change the topic */
        if (!(chptr->mode.mode & MODE_TOPICLIMIT) && !is_chan_op(sptr, chptr) && is_banned(sptr, chptr, NULL))
        {
            sendto_one(sptr, err_str(ERR_CHANOPRIVSNEEDED), me.name, parv[0], chptr->chname);
            return 0;
        }

        tnick = make_nick_user_host(sptr->name, sptr->user->username, sptr->user->host);
    }
    else
    {
        /* extended info */
        if (parc > 3)
        {
            topic = (parc > 4 ? parv[4] : "");
            tnick = parv[2];
            ts = atoi(parv[3]);
        }
        else tnick = sptr->name;

        /* ignore old topics during burst/race */
        if (!IsULine(sptr) && chptr->topic[0] && chptr->topic_time >= ts)
            return 0;
    }

    strncpyzt(chptr->topic, topic, TOPICLEN + 1);
    strcpy(chptr->topic_nick, tnick);
    chptr->topic_time = ts;

    /* in this case I think it's better that we send all the info that df
     * sends with the topic, so I changed everything to work like that.
     * -wd */

    sendto_capab_serv_butone(cptr, CAPAB_NICKIPSTR, 0, ":%s TOPIC %s %s %lu :%s", parv[0],
                             chptr->chname, chptr->topic_nick,
                             (unsigned long)chptr->topic_time, chptr->topic);
    if((tmpptr = strchr(tnick, '!')))
        *tmpptr = '\0'; /* Remove the user@host part before we send it to non-NICKIPSTR servers */
    sendto_capab_serv_butone(cptr, 0, CAPAB_NICKIPSTR, ":%s TOPIC %s %s %lu :%s", parv[0],
                             chptr->chname, tnick,
                             (unsigned long)chptr->topic_time, chptr->topic);
    sendto_channel_butserv_me(chptr, sptr, ":%s TOPIC %s :%s", parv[0],
                              chptr->chname, chptr->topic);
        
    return 0;
}

/*
 * m_invite 
 * parv[0] - sender prefix 
 * parv[1] - user to invite 
 * parv[2] - channel name
 */
int m_invite(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aClient    *acptr;
    aChannel   *chptr = NULL;
    
    if (parc < 3 || *parv[1] == 0)
    {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0],
                   "INVITE");
        return -1;
    }

    if (!(acptr = find_person(parv[1], NULL)))
    {
        sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name, parv[0], parv[1]);
        return 0;
    }

    if (MyClient(sptr))
    {
        if (!(chptr = find_channel(parv[2], NULL)))
        {
            sendto_one(sptr, err_str(ERR_NOSUCHCHANNEL), me.name, parv[0],
                       parv[2]);
            return 0;
        }

        if (!IsMember(sptr, chptr))
        {
            sendto_one(sptr, err_str(ERR_NOTONCHANNEL), me.name, parv[0],
                       parv[2]);
            return 0;
        }

        if (IsMember(acptr, chptr))
        {
            sendto_one(sptr, err_str(ERR_USERONCHANNEL), me.name, parv[0],
                       parv[1], chptr->chname);
            return 0;
        }

        if (!is_chan_op(sptr, chptr))
        {
            sendto_one(sptr, err_str(ERR_CHANOPRIVSNEEDED), me.name, parv[0],
                       chptr->chname);
            return 0;
        }

        if (!IsULine(sptr) && !IsOper(sptr))
        {
            if (IsNoNonReg(acptr) && !IsRegNick(sptr))
            {
                sendto_one(sptr, err_str(ERR_NONONREG), me.name, parv[0], acptr->name);
                return 0;
            }

            if (IsUmodeC(acptr) && (!IsNoNonReg(acptr) || IsRegNick(sptr)) && acptr->user->joined && !find_shared_chan(sptr, acptr))
            {
                sendto_one(sptr, err_str(ERR_NOSHAREDCHAN), me.name, parv[0], acptr->name);
                return 0;
            }
        }

        sendto_one(sptr, rpl_str(RPL_INVITING), me.name, parv[0], acptr->name,
                   chptr->chname);

        if (acptr->user->away)
            sendto_one(sptr, rpl_str(RPL_AWAY), me.name, parv[0], acptr->name,
                       acptr->user->away);
    }

    if (MyClient(acptr))
    {
        /* stuff already done above */
        if (!MyClient(sptr))
        {
            if (!(chptr = find_channel(parv[2], NullChn)))
                return 0;

            if (IsMember(acptr, chptr))
                return 0;
        }

        add_invite(acptr, chptr);

        if (!is_silenced(sptr, acptr))
            sendto_prefix_one(acptr, sptr, ":%s INVITE %s :%s", parv[0],
                              acptr->name, chptr->chname);
        sendto_channelflags_butone(NULL, &me, chptr, CHFL_CHANOP,
                                   ":%s NOTICE @%s :%s invited %s into "
                                   "channel %s", me.name, chptr->chname,
                                   parv[0], acptr->name, chptr->chname);

        return 0;
    }

    sendto_one(acptr, ":%s INVITE %s :%s", parv[0], parv[1], parv[2]);

    return 0;
}


/*
 * The function which sends the actual channel list back to the user.
 * Operates by stepping through the hashtable, sending the entries back if
 * they match the criteria.
 * cptr = Local client to send the output back to.
 * numsend = Number (roughly) of lines to send back. Once this number has
 * been exceeded, send_list will finish with the current hash bucket,
 * and record that number as the number to start next time send_list
 * is called for this user. So, this function will almost always send
 * back more lines than specified by numsend (though not by much,
 * assuming CH_MAX is was well picked). So be conservative in your choice
 * of numsend. -Rak
 */

void send_list(aClient *cptr, int numsend)
{
    aChannel    *chptr;
    LOpts       *lopt = cptr->user->lopt;
    int         hashnum;
    
    for (hashnum = lopt->starthash; hashnum < CH_MAX; hashnum++)
    {
        if (numsend > 0)
        {
            for (chptr = (aChannel *)hash_get_chan_bucket(hashnum); 
                 chptr; chptr = chptr->hnextch)
            {
                if (SecretChannel(chptr) && !IsAdmin(cptr)
                    && !IsMember(cptr, chptr))
                    continue;
#ifdef USE_CHANMODE_L
                if (lopt->only_listed && !(chptr->mode.mode & MODE_LISTED))
                    continue;
#endif
                if ((!lopt->showall) && ((chptr->users < lopt->usermin) ||
                                         ((lopt->usermax >= 0) && 
                                          (chptr->users > lopt->usermax)) ||
                                         ((chptr->channelts) < 
                                          lopt->chantimemin) ||
                                         (chptr->topic_time < 
                                          lopt->topictimemin) ||
                                         (chptr->channelts > 
                                          lopt->chantimemax) ||
                                         (chptr->topic_time > 
                                          lopt->topictimemax) ||
                                         (lopt->nolist && 
                                          find_str_link(lopt->nolist, 
                                                        chptr->chname)) ||
                                         (lopt->yeslist && 
                                          !find_str_link(lopt->yeslist, 
                                                         chptr->chname))))
                    continue;

                /* Seem'd more efficent to seperate into two commands 
                 * then adding an or to the inline. -- Doc.
                 */
                if (IsAdmin(cptr))
                {
                    char tempchname[CHANNELLEN + 2], *altchname;

                    if (SecretChannel(chptr))
                    {
                        tempchname[0] = '%';
                        strcpy(&tempchname[1], chptr->chname);
                        altchname = &tempchname[0];
                    } 
                    else 
                        altchname = chptr->chname;

                    sendto_one(cptr, rpl_str(RPL_LIST), me.name, cptr->name,
                               altchname, chptr->users, chptr->topic);
                } 
                else 
                {
                    sendto_one(cptr, rpl_str(RPL_LIST), me.name, cptr->name,
                               ShowChannel(cptr, chptr) ? chptr->chname : "*",
                               chptr->users,
                               ShowChannel(cptr, chptr) ? chptr->topic : "");
                }
                numsend--;
            }
        }
        else
            break;
    }
    
    /* All done */
    if (hashnum == CH_MAX)
    {
        Link *lp, *next;
        sendto_one(cptr, rpl_str(RPL_LISTEND), me.name, cptr->name);
        for (lp = lopt->yeslist; lp; lp = next)
        {
            next = lp->next;
            MyFree(lp->value.cp);
            free_link(lp);
        }
        for (lp = lopt->nolist; lp; lp = next)
        {
            next = lp->next;
            MyFree(lp->value.cp);
            free_link(lp);
        }
        
        MyFree(cptr->user->lopt);
        cptr->user->lopt = NULL;
        remove_from_list(&listing_clients, cptr, NULL);
        return;
    }
    
    /* 
     * We've exceeded the limit on the number of channels to send back
     * at once.
     */
    lopt->starthash = hashnum;
    return;
}


/*
 * m_list 
 * parv[0] = sender prefix
 * parv[1] = channel
 */
int m_list(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aChannel    *chptr;
    time_t      currenttime = time(NULL);
    char        *name, *p = NULL;
    LOpts       *lopt = NULL;
    Link        *lp, *next;
    int         usermax, usermin, error = 0, doall = 0, only_listed = 1;
    int         x;
    time_t      chantimemin, chantimemax;
    ts_val      topictimemin, topictimemax;
    Link        *yeslist = NULL, *nolist = NULL;
    
    static char *usage[] = {
        "   Usage: /raw LIST options (on mirc) or /quote LIST options (ircII)",
        "",
        "If you don't include any options, the default is to send you the",
        "entire unfiltered list of channels. Below are the options you can",
        "use, and what channels LIST will return when you use them.",
        ">number  List channels with more than <number> people.",
        "<number  List channels with less than <number> people.",
        "C>number List channels created between now and <number> minutes ago.",
        "C<number List channels created earlier than <number> minutes ago.",
        "T>number List channels whose topics are older than <number> minutes",
        "         (Ie, they have not changed in the last <number> minutes.",
        "T<number List channels whose topics are not older than <number> "
        "minutes.",
        "*mask*   List channels that match *mask*",
        "!*mask*  List channels that do not match *mask*",
        NULL
    };

    /* Some starting san checks -- No interserver lists allowed. */
    if (cptr != sptr || !sptr->user) return 0;

    if (IsSquelch(sptr)) 
    {
        sendto_one(sptr, rpl_str(RPL_LISTEND), me.name, parv[0]);
        return 0;
    }

    /* If a /list is in progress, then another one will cancel it */
    if ((lopt = sptr->user->lopt)!=NULL)
    {
        sendto_one(sptr, rpl_str(RPL_LISTEND), me.name, parv[0]);
        for (lp = lopt->yeslist; lp; lp = next)
        {
            next = lp->next;
            MyFree(lp->value.cp);
            free_link(lp);
        }
        for (lp = lopt->nolist; lp; lp = next)
        {
            next = lp->next;
            MyFree(lp->value.cp);
            free_link(lp);
        }
        MyFree(sptr->user->lopt);
        sptr->user->lopt = NULL;
        remove_from_list(&listing_clients, sptr, NULL);
        return 0;
    }

    if (parc < 2 || BadPtr(parv[1]))
    {

        sendto_one(sptr, rpl_str(RPL_LISTSTART), me.name, parv[0]);
        lopt = sptr->user->lopt = (LOpts *) MyMalloc(sizeof(LOpts));
        memset(lopt, '\0', sizeof(LOpts));

        lopt->showall = 1;
#ifdef USE_CHANMODE_L
        lopt->only_listed = 1;
#endif

        add_to_list(&listing_clients, sptr);

        if (SBufLength(&cptr->sendQ) < 2048)
            send_list(cptr, 64);

        return 0;
    }

    if ((parc == 2) && (parv[1][0] == '?') && (parv[1][1] == '\0'))
    {
        char **ptr = usage;
        for (; *ptr; ptr++)
            sendto_one(sptr, rpl_str(RPL_COMMANDSYNTAX), me.name,
                       cptr->name, *ptr);
        return 0;
    }

    sendto_one(sptr, rpl_str(RPL_LISTSTART), me.name, parv[0]);

    chantimemax = topictimemax = currenttime + 86400;
    chantimemin = topictimemin = 0;
    usermin = 0;
    usermax = -1; /* No maximum */

    for (name = strtoken(&p, parv[1], ","); name && !error;
         name = strtoken(&p, (char *) NULL, ","))
    {

        switch (*name)
        {
            case '<':
                usermax = atoi(name+1) - 1;
                doall = 1;
                break;
            case '>':
                usermin = atoi(name+1) + 1;
                doall = 1;
                break;
#ifdef USE_CHANMODE_L
            case '-':
                if(!strcasecmp(++name,"all")) 
                {
                    only_listed = 0;
                    doall = 1;
                }
                break;                          
#endif
            case 'C':
            case 'c': /* Channel TS time -- creation time? */
                ++name;
                switch (*name++)
                {
                    case '<':
                        chantimemax = currenttime - 60 * atoi(name);
                        doall = 1;
                        break;
                    case '>':
                        chantimemin = currenttime - 60 * atoi(name);
                        doall = 1;
                        break;
                    default:
                        sendto_one(sptr, err_str(ERR_LISTSYNTAX), me.name, 
                                cptr->name);
                        error = 1;
                }
                break;
            case 'T':
            case 't':
                ++name;
                switch (*name++)
                {
                    case '<':
                        topictimemax = currenttime - 60 * atoi(name);
                        doall = 1;
                        break;
                    case '>':
                        topictimemin = currenttime - 60 * atoi(name);
                        doall = 1;
                        break;
                    default:
                        sendto_one(sptr, err_str(ERR_LISTSYNTAX), me.name, 
                                cptr->name);
                        error = 1;
                }
                break;
            default: /* A channel, possibly with wildcards.
                      * Thought for the future: Consider turning wildcard
                      * processing on the fly.
                      * new syntax: !channelmask will tell ircd to ignore
                      * any channels matching that mask, and then
                      * channelmask will tell ircd to send us a list of
                      * channels only masking channelmask. Note: Specifying
                      * a channel without wildcards will return that
                      * channel even if any of the !channelmask masks
                      * matches it.
                      */
                if (*name == '!')
                {
                    doall = 1;
                    lp = make_link();
                    lp->next = nolist;
                    nolist = lp;
                    DupString(lp->value.cp, name+1);
                }
                else if (strchr(name, '*') || strchr(name, '?'))
                {
                    doall = 1;
                    lp = make_link();
                    lp->next = yeslist;
                    yeslist = lp;
                    DupString(lp->value.cp, name);
                }
                else /* Just a normal channel */
                {
                    chptr = find_channel(name, NullChn);
                    if (chptr && ((x = ShowChannel(sptr, chptr)) || 
                                    IsAdmin(sptr)))
                    {
                        char *nameptr = name;
                        char channame[CHANNELLEN + 2];

                        if(!x && IsAdmin(sptr))
                        {
                            channame[0] = '%';
                            strcpy(&channame[1], chptr->chname);
                            nameptr = channame;
                        }

                        sendto_one(sptr, rpl_str(RPL_LIST), me.name, parv[0],
                               nameptr, chptr->users, chptr->topic);
                    }
                }
        } /* switch */
    } /* while */

    if (doall)
    {
        lopt = sptr->user->lopt = (LOpts *) MyMalloc(sizeof(LOpts));
        memset(lopt, '\0', sizeof(LOpts));
        lopt->usermin = usermin;
        lopt->usermax = usermax;
        lopt->topictimemax = topictimemax;
        lopt->topictimemin = topictimemin;
        lopt->chantimemax = chantimemax;
        lopt->chantimemin = chantimemin;
        lopt->nolist = nolist;
        lopt->yeslist = yeslist;
        lopt->only_listed = only_listed;

        add_to_list(&listing_clients, sptr);

        if (SBufLength(&cptr->sendQ) < 2048)
            send_list(cptr, 64);
        return 0;
    }

    sendto_one(sptr, rpl_str(RPL_LISTEND), me.name, parv[0]);

    return 0;
}



/************************************************************************
 * m_names() - Added by Jto 27 Apr 1989
 * 12 Feb 2000 - geesh, time for a rewrite -lucas
 ************************************************************************/
/*
 * m_names 
 * parv[0] = sender prefix 
 * parv[1] = channel
 */

/* maximum names para to show to opers when abuse occurs */
#define TRUNCATED_NAMES 64

int m_names(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    int mlen = strlen(me.name) + NICKLEN + 7;
    aChannel *chptr;
    aClient *acptr;
    int member;
    chanMember *cm;
    int idx, flag = 1, spos;
    char *s, *para = parv[1];

    if (parc < 2 || !MyConnect(sptr)) 
    {
        sendto_one(sptr, rpl_str(RPL_ENDOFNAMES), me.name, parv[0], "*");
        return 0;
    }

    for(s = para; *s; s++) 
    {
        if(*s == ',') 
        {
            if(strlen(para) > TRUNCATED_NAMES)
                para[TRUNCATED_NAMES] = '\0';
            sendto_realops("names abuser %s %s", get_client_name(sptr, FALSE),
                           para);
            sendto_one(sptr, err_str(ERR_TOOMANYTARGETS), me.name, sptr->name,
                       "NAMES");
            return 0;
        }
    }

    if(!check_channelname(sptr, (unsigned char *)para))
        return 0;
     
    chptr = find_channel(para, (aChannel *) NULL);

    if (!chptr || !ShowChannel(sptr, chptr))
    {
        sendto_one(sptr, rpl_str(RPL_ENDOFNAMES), me.name, parv[0], para);
        return 0;
    }

    /* cache whether this user is a member of this channel or not */
    member = IsMember(sptr, chptr);
    
    if(PubChannel(chptr))
        buf[0] = '=';
    else if(SecretChannel(chptr))
        buf[0] = '@';
    else
        buf[0] = '*';

    idx = 1;
    buf[idx++] = ' ';
    for(s = chptr->chname; *s; s++)
        buf[idx++] = *s;
    buf[idx++] = ' ';
    buf[idx++] = ':';

    /* If we go through the following loop and never add anything,
       we need this to be empty, otherwise spurious things from the
       LAST /names call get stuck in there.. - lucas */
    buf[idx] = '\0';

    spos = idx; /* starting point in buffer for names!*/

    for (cm = chptr->members; cm; cm = cm->next) 
    {
        acptr = cm->cptr;
        if(IsInvisible(acptr) && !member)
            continue;
        if(cm->flags & CHFL_CHANOP)
            buf[idx++] = '@';
        else if(cm->flags & CHFL_VOICE)
            buf[idx++] = '+';
        else if((chptr->mode.mode & MODE_AUDITORIUM) && (sptr != acptr) && !is_chan_opvoice(sptr, chptr) && !IsAnOper(sptr)) continue;
        for(s = acptr->name; *s; s++)
            buf[idx++] = *s;
        buf[idx++] = ' ';
        buf[idx] = '\0';
        flag = 1;
        if(mlen + idx + NICKLEN > BUFSIZE - 3)
        {
            sendto_one(sptr, rpl_str(RPL_NAMREPLY), me.name, parv[0], buf);
            idx = spos;
            flag = 0;
        }
    }

    if (flag) 
        sendto_one(sptr, rpl_str(RPL_NAMREPLY), me.name, parv[0], buf);
    
    sendto_one(sptr, rpl_str(RPL_ENDOFNAMES), me.name, parv[0], para);
    
    return 0;
}
 
void send_user_joins(aClient *cptr, aClient *user)
{
    Link   *lp;
    aChannel *chptr;
    int     cnt = 0, len = 0;
    size_t  clen;
    char       *mask;

    *buf = ':';
    (void) strcpy(buf + 1, user->name);
    (void) strcat(buf, " JOIN ");
    len = strlen(user->name) + 7;

    for (lp = user->user->channel; lp; lp = lp->next)
    {
        chptr = lp->value.chptr;
        if (*chptr->chname == '&')
            continue;
        if ((mask = strchr(chptr->chname, ':')))
            if (match(++mask, cptr->name))
                continue;
        clen = strlen(chptr->chname);
        if (clen > (size_t) BUFSIZE - 7 - len)
        {
            if (cnt)
                sendto_one(cptr, "%s", buf);
            *buf = ':';
            (void) strcpy(buf + 1, user->name);
            (void) strcat(buf, " JOIN ");
            len = strlen(user->name) + 7;
            cnt = 0;
        }
        (void) strcpy(buf + len, chptr->chname);
        cnt++;
        len += clen;
        if (lp->next)
        {
            len++;
            (void) strcat(buf, ",");
        }
    }
    if (*buf && cnt)
        sendto_one(cptr, "%s", buf);

    return;
}

void kill_ban_list(aClient *cptr, aChannel *chptr)
{  
    void        *pnx;
    aBan        *bp;
#ifdef EXEMPT_LISTS
    aBanExempt  *ep;
#endif
#ifdef INVITE_LISTS
    anInvite   *ip;
#endif
    char       *cp;
    int         count = 0, send = 0;

    cp = modebuf;  
    *cp++ = '-';
    *cp = '\0';      

    *parabuf = '\0';

    for (bp = chptr->banlist; bp; bp = bp->next)
    {  
        if (strlen(parabuf) + strlen(bp->banstr) + 10 < (size_t) MODEBUFLEN)
        {  
            if(*parabuf)
                strcat(parabuf, " ");
            strcat(parabuf, bp->banstr);
            count++;   
            *cp++ = 'b';
            *cp = '\0';
        }
        else if (*parabuf)
            send = 1;
   
        if (count == MAXMODEPARAMS)
            send = 1;
    
        if (send) {
            sendto_channel_butserv_me(chptr, cptr, ":%s MODE %s %s %s",
                         cptr->name, chptr->chname, modebuf, parabuf);
            send = 0;
            *parabuf = '\0';
            cp = modebuf;
            *cp++ = '-';
            if (count != MAXMODEPARAMS)
            {
                strcpy(parabuf, bp->banstr);
                *cp++ = 'b';
                count = 1;
            }
            else
                count = 0; 
            *cp = '\0';
        }
    }

#ifdef EXEMPT_LISTS
    for (ep = chptr->banexempt_list; ep; ep = ep->next)
    {
        if (strlen(parabuf) + strlen(ep->banstr) + 10 < (size_t) MODEBUFLEN)
        {
            if(*parabuf)
                strcat(parabuf, " ");
            strcat(parabuf, ep->banstr);
            count++;
            *cp++ = 'e';
            *cp = '\0';
        }
        else if (*parabuf)
            send = 1;

        if (count == MAXMODEPARAMS)
            send = 1;

        if (send) {
            sendto_channel_butserv_me(chptr, cptr, ":%s MODE %s %s %s",
                                      cptr->name, chptr->chname, modebuf, parabuf);
            send = 0;
            *parabuf = '\0';
            cp = modebuf;
            *cp++ = '-';
            if (count != MAXMODEPARAMS)
            {
                strcpy(parabuf, ep->banstr);
                *cp++ = 'e';
                count = 1;
            }
            else
                count = 0;
            *cp = '\0';
        }
    }
#endif

#ifdef INVITE_LISTS
    for (ip = chptr->invite_list; ip; ip = ip->next)
    {
        if (strlen(parabuf) + strlen(ip->invstr) + 10 < (size_t) MODEBUFLEN)
        {
            if(*parabuf)
                strcat(parabuf, " ");
            strcat(parabuf, ip->invstr);
            count++;
            *cp++ = 'I';
            *cp = '\0';
        }
        else if (*parabuf)
            send = 1;

        if (count == MAXMODEPARAMS)
            send = 1;

        if (send) {
            sendto_channel_butserv_me(chptr, cptr, ":%s MODE %s %s %s",
                                      cptr->name, chptr->chname, modebuf, parabuf);
            send = 0;
            *parabuf = '\0';
            cp = modebuf;
            *cp++ = '-';
            if (count != MAXMODEPARAMS)
            {
                strcpy(parabuf, ip->invstr);
                *cp++ = 'I';
                count = 1;
            }
            else
                count = 0;
            *cp = '\0';
        }
    }
#endif

    if(*parabuf)
    {
        sendto_channel_butserv_me(chptr, cptr, ":%s MODE %s %s %s", cptr->name,
                                  chptr->chname, modebuf, parabuf);
    }

    /* physically destroy channel ban list */   

    bp = chptr->banlist;
    while(bp)
    {
        pnx = bp->next;
        MyFree(bp->banstr);
        MyFree(bp->who);
        MyFree(bp);
        bp = pnx;
    }
    chptr->banlist = NULL;

#ifdef EXEMPT_LISTS
    ep = chptr->banexempt_list;
    while(ep)
    {
        pnx = ep->next;
        MyFree(ep->banstr);
        MyFree(ep->who);
        MyFree(ep);
        ep = pnx;
    }
    chptr->banexempt_list = NULL;
#endif

#ifdef INVITE_LISTS
    ip = chptr->invite_list;
    while(ip)
    {
        pnx = ip->next;
        MyFree(ip->invstr);
        MyFree(ip->who);
        MyFree(ip);
        ip = pnx;
    }
    chptr->invite_list = NULL;
#endif

    /* reset bquiet cache */
    chptr->banserial++;
}

static inline void sjoin_sendit(aClient *cptr, aClient *sptr,
                                aChannel *chptr, char *from)
{
    sendto_channel_butserv_me(chptr, sptr, ":%s MODE %s %s %s", from,
                              chptr->chname, modebuf, parabuf);
}

/* m_resynch
 *
 * parv[0] = sender
 * parv[1] = #channel
 *
 * Sent from a server I am directly connected to that is requesting I resend
 * EVERYTHING I know about #channel.
 */
int m_resynch(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aChannel *chptr;

    if(!MyConnect(sptr) || !IsServer(sptr) || parc < 2)
        return 0;

    chptr = find_channel(parv[1], NullChn);

    sendto_realops_lev(DEBUG_LEV, "%s is requesting a resynch of %s%s", 
                       parv[0], parv[1], (chptr == NullChn) ? " [failed]" : "");

    if (chptr != NullChn)
        send_channel_modes(sptr, chptr);
    return 0;
}

/*
 * m_sjoin 
 * parv[0] - sender 
 * parv[1] - TS 
 * parv[2] - channel 
 * parv[3] - modes + n arguments (key and/or limit) 
 * parv[4+n] - flags+nick list (all in one parameter)
 * 
 * process a SJOIN, taking the TS's into account to either ignore the
 * incoming modes or undo the existing ones or merge them, and JOIN all
 * the specified users while sending JOIN/MODEs to non-TS servers and
 * to clients
 */

#define INSERTSIGN(x,y) \
if (what != x) { \
*mbuf++=y; \
what = x; \
}

#define SJ_MODEPLUS(x, y) \
   if(((y) & mode.mode) && !((y) & oldmode->mode)) \
   { \
      INSERTSIGN(1, '+') \
      *mbuf++ = (x); \
   }

#define SJ_MODEMINUS(x, y) \
   if(((y) & oldmode->mode) && !((y) & mode.mode)) \
   { \
      INSERTSIGN(-1, '-') \
      *mbuf++ = (x); \
   }

#define SJ_MODEADD(x, y) case (x): mode.mode |= (y); break

#define ADD_PARA(p) para = p; if(pbpos) parabuf[pbpos++] = ' '; \
                     while(*para) parabuf[pbpos++] = *para++; 
#define ADD_SJBUF(p) para = p; if(sjbufpos) sjbuf[sjbufpos++] = ' '; \
                     while(*para) sjbuf[sjbufpos++] = *para++; 
        
int m_sjoin(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aChannel    *chptr;
    aClient     *acptr;
    ts_val      newts, oldts, tstosend;
    static Mode mode, *oldmode;
    chanMember  *cm;
    int         args = 0, haveops = 0, keepourmodes = 1, keepnewmodes = 1,
                what = 0, pargs = 0, fl, people = 0,
                isnew, clientjoin = 0, pbpos, sjbufpos, created = 0;
    char        *s, *s0, *para;
    static char numeric[16], sjbuf[BUFSIZE];
    char        keep_modebuf[REALMODEBUFLEN], keep_parabuf[REALMODEBUFLEN];
    char        *mbuf = modebuf, *p;

    /* if my client is SJOINing, it's just a local user being a dufus. 
     *  Ignore him.
     * parc >= 5 (new serv<->serv SJOIN format)
     * parc >= 6 (old serv<->serv SJOIN format)
     * parc == 3 (new serv<->serv cliSJOIN format)
     */

    if (MyClient(sptr) || (parc < 5 && IsServer(sptr)) ||
        (parc < 3 && IsPerson(sptr)))
        return 0;
    
    if(parc == 3 && IsPerson(sptr))
        clientjoin = 1;
    else 
        if(IsDigit(parv[2][0]))
        {
            int i;
            
            if(parc < 6) 
                return 0;
            
            for(i = 2; i < (parc - 1); i++)
                parv[i] = parv[i+1];

            parc--;
        }

    if (!IsChannelName(parv[2]))
        return 0;

    newts = atol(parv[1]);
        
    isnew = ChannelExists(parv[2]) ? 0 : 1;
    chptr = get_channel(sptr, parv[2], CREATE, &created);
    oldts = chptr->channelts;

    for (cm = chptr->members; cm; cm = cm->next)
        if (cm->flags & MODE_CHANOP)
        {
            haveops++;
            break;
        }

    if(clientjoin) /* we have a good old client sjoin, with timestamp */
    {
        if (isnew)
            chptr->channelts = tstosend = newts;
        else if (newts == 0 || oldts == 0)
            chptr->channelts = tstosend = 0;
        else if (newts == oldts)
            tstosend = oldts;
        else if (newts < oldts) 
        {
#ifdef OLD_WEIRD_CHANOP_NEGOTIATION
            if (haveops)
                tstosend = oldts;
            else
                chptr->channelts = tstosend = newts;
#else
            chptr->channelts = tstosend = newts;
            if (!IsULine(sptr))
            sendto_realops_lev(DEBUG_LEV, "Changing TS for %s from %ld to %ld on"
                               " client SJOIN", chptr->chname, (long)oldts, (long)newts);
#endif
        }
        else 
            tstosend = oldts;

        /* parv[0] is the client that is joining. parv[0] == sptr->name */

        if (!IsMember(sptr, chptr)) 
        {
            add_user_to_channel(chptr, sptr, 0);
            joinrate_dojoin(chptr, sptr);
            sendto_channel_butserv(chptr, sptr, ":%s JOIN :%s", parv[0],
                                   parv[2]);
        }

        sendto_serv_butone(cptr, CliSJOINFmt, parv[0], tstosend, parv[2]);

        /* if the channel is created in client sjoin, 
         * we lost some channel modes. */
        if(created)
        {
            sendto_realops_lev(DEBUG_LEV, "Requesting resynch of %s from "
                                "%s (%s!%s@%s[%s] created)", chptr->chname, 
                                cptr->name, sptr->name, sptr->user->username,
                                sptr->user->host, sptr->hostip);
            sendto_one(cptr, "RESYNCH %s", chptr->chname);
        }

        return 0;
    }

    memset((char *) &mode, '\0', sizeof(mode));

    s = parv[3];
    while (*s)
    {
        switch (*(s++))
        {
            SJ_MODEADD('i', MODE_INVITEONLY);
            SJ_MODEADD('n', MODE_NOPRIVMSGS);
            SJ_MODEADD('p', MODE_PRIVATE);
            SJ_MODEADD('s', MODE_SECRET);
            SJ_MODEADD('m', MODE_MODERATED);
            SJ_MODEADD('t', MODE_TOPICLIMIT);
            SJ_MODEADD('r', MODE_REGISTERED);
            SJ_MODEADD('R', MODE_REGONLY);
            SJ_MODEADD('M', MODE_MODREG);
            SJ_MODEADD('c', MODE_NOCTRL);
            SJ_MODEADD('O', MODE_OPERONLY);
            SJ_MODEADD('S', MODE_SSLONLY);
            SJ_MODEADD('A', MODE_AUDITORIUM);
            SJ_MODEADD('P', MODE_PRIVACY);
#ifdef USE_CHANMODE_L
            SJ_MODEADD('L', MODE_LISTED);
#endif
            case 'k':
                strncpyzt(mode.key, parv[4 + args], KEYLEN + 1);
                args++;
                if (parc < 5 + args)
                    return 0;
                break;

            case 'j':
                {
                    char *tmpa, *tmpb;

                    mode.mode |= MODE_JOINRATE;
                    tmpa = parv[4 + args];

                    tmpb = strchr(tmpa, ':');
                    if(tmpb)
                    {
                        *tmpb = '\0';
                        tmpb++;
                        mode.jr_time = atoi(tmpb);
                    }
                    else
                        mode.jr_time = 0;

                    mode.jr_num = atoi(tmpa);
                    mode.jrl_size = mode.jr_num * mode.jr_time;

                    args++;
                    if (parc < 5 + args)
                        return 0;
                }
                break;

            case 'l':
                mode.limit = atoi(parv[4 + args]);
                args++;
                if (parc < 5 + args)
                    return 0;
                break;
        }
    }

    oldmode = &chptr->mode;

    /* newts is the ts the remote server is providing */ 
    /* oldts is our channel TS */ 
    /* whichever TS is smaller wins. */ 
        
    if (isnew)
        chptr->channelts = tstosend = newts;
    else if (newts == 0 || oldts == 0)
        chptr->channelts = tstosend = 0;
    else if (newts == oldts)
        tstosend = oldts;
#ifdef OLD_WEIRD_CHANOP_NEGOTIATION
    else if (newts < oldts)
    {
        int doesop = (parv[4 + args][0] == '@' || parv[4 + args][1] == '@');

        /* if remote ts is older, and they have ops, don't keep our modes. */
        if (doesop)   
        {
            kill_ban_list(sptr, chptr);
            keepourmodes = 0;
        }
        if (haveops && !doesop)
            tstosend = oldts;
        else
            chptr->channelts = tstosend = newts;
    }
    else /* if our TS is older, and we have ops, don't keep their modes */
    {
        int doesop = (parv[4 + args][0] == '@' || parv[4 + args][1] == '@');

        if (haveops)
            keepnewmodes = 0;
        if (doesop && !haveops)
        {
            chptr->channelts = tstosend = newts;
            if (MyConnect(sptr) && !IsULine(sptr))
                ts_warn("Hacked ops on opless channel: %s", chptr->chname);
        }
        else
            tstosend = oldts;
    }
#else 
   else if (newts < oldts) 
   { 
      /* if remote ts is older, don't keep our modes. */ 
      kill_ban_list(sptr, chptr);
      keepourmodes = 0; 
      chptr->channelts = tstosend = newts; 
   } 
   else /* if our TS is older, don't keep their modes */ 
   { 
      keepnewmodes = 0; 
      tstosend = oldts; 
   } 
#endif
        
    if (!keepnewmodes)
        mode = *oldmode;
    else if (keepourmodes)
    {
        /* check overriding modes first */
        if (oldmode->limit > mode.limit)
            mode.limit = oldmode->limit;
        if(*oldmode->key && *mode.key && strcmp(mode.key, oldmode->key) > 0)
            strcpy(mode.key, oldmode->key);
        else if(*oldmode->key && *mode.key == '\0')
            strcpy(mode.key, oldmode->key);
        if (oldmode->mode & MODE_JOINRATE)
        {
            if ((mode.mode & MODE_JOINRATE) && !mode.jr_num)
                /* 0 wins */ ;
            else if (oldmode->jr_num && mode.jr_num > oldmode->jr_num)
                /* more joins wins */ ;
            else if (mode.jr_num == oldmode->jr_num &&
                     mode.jr_time < oldmode->jr_time)
                /* same joins in less time wins */ ;
            else
            {
                /* our settings win */
                mode.jr_num = oldmode->jr_num;
                mode.jr_time = oldmode->jr_time;
                mode.jrl_size = oldmode->jrl_size;
            }
        }

        /* now merge */
        mode.mode |= oldmode->mode;
    }
    
    pbpos = 0;
    
    /*
     * since the most common case is that the modes are exactly the same,
     *  this if will skip over the most common case... :)
     * 
     * this would look prettier in a for loop, but it's unrolled here
     *  so it's a bit faster.   - lucas
     * 
     * pass +: go through and add new modes that are in mode and not oldmode
     * pass -: go through and delete old modes that are in oldmode and not mode
     */
    
    if(mode.mode != oldmode->mode)
    {
        SJ_MODEPLUS('p', MODE_PRIVATE);
        SJ_MODEPLUS('s', MODE_SECRET);
        SJ_MODEPLUS('m', MODE_MODERATED);
        SJ_MODEPLUS('n', MODE_NOPRIVMSGS);
        SJ_MODEPLUS('t', MODE_TOPICLIMIT);
        SJ_MODEPLUS('i', MODE_INVITEONLY);
        SJ_MODEPLUS('r', MODE_REGISTERED);
        SJ_MODEPLUS('R', MODE_REGONLY);
        SJ_MODEPLUS('M', MODE_MODREG);
        SJ_MODEPLUS('c', MODE_NOCTRL);
        SJ_MODEPLUS('O', MODE_OPERONLY);
        SJ_MODEPLUS('S', MODE_SSLONLY);
        SJ_MODEPLUS('A', MODE_AUDITORIUM);
        SJ_MODEPLUS('P', MODE_PRIVACY);
#ifdef USE_CHANMODE_L
        SJ_MODEPLUS('L', MODE_LISTED);
#endif

        SJ_MODEMINUS('p', MODE_PRIVATE);
        SJ_MODEMINUS('s', MODE_SECRET);
        SJ_MODEMINUS('m', MODE_MODERATED);
        SJ_MODEMINUS('n', MODE_NOPRIVMSGS);
        SJ_MODEMINUS('t', MODE_TOPICLIMIT);
        SJ_MODEMINUS('i', MODE_INVITEONLY);
        SJ_MODEMINUS('r', MODE_REGISTERED);
        SJ_MODEMINUS('R', MODE_REGONLY);
        SJ_MODEMINUS('M', MODE_MODREG);
        SJ_MODEMINUS('c', MODE_NOCTRL);
        SJ_MODEMINUS('O', MODE_OPERONLY);
        SJ_MODEMINUS('S', MODE_SSLONLY);
        SJ_MODEMINUS('A', MODE_AUDITORIUM);
        SJ_MODEMINUS('P', MODE_PRIVACY);
#ifdef USE_CHANMODE_L
        SJ_MODEMINUS('L', MODE_LISTED);
#endif

    }

    if ((oldmode->mode & MODE_JOINRATE) && !(mode.mode & MODE_JOINRATE))
    {
        INSERTSIGN(-1,'-')
        *mbuf++ = 'j';
    }

    if ((mode.mode & MODE_JOINRATE) && (!(oldmode->mode & MODE_JOINRATE) ||
            (oldmode->jr_num != mode.jr_num || 
            oldmode->jr_time != mode.jr_time)))
    {
        char tmp[128];

        INSERTSIGN(1,'+')
        *mbuf++ = 'j';
        
        if(mode.jr_num == 0 || mode.jr_time == 0)
            ircsprintf(tmp, "0");
        else
            ircsprintf(tmp, "%d:%d", mode.jr_num, mode.jr_time);
        ADD_PARA(tmp)
        pargs++;
    }

    if (oldmode->limit && !mode.limit)
    {
        INSERTSIGN(-1,'-')
        *mbuf++ = 'l';
    }

    if (mode.limit && oldmode->limit != mode.limit)
    {
        INSERTSIGN(1,'+')
        *mbuf++ = 'l';
        sprintf(numeric, "%-15d", mode.limit);
        if ((s = strchr(numeric, ' ')))
        *s = '\0';
        ADD_PARA(numeric);
        pargs++;
    }

    if (oldmode->key[0] && !mode.key[0])
    {
        INSERTSIGN(-1,'-')
        *mbuf++ = 'k';
        ADD_PARA(oldmode->key)
        pargs++;
    }

    if (mode.key[0] && strcmp(oldmode->key, mode.key))
    {
        INSERTSIGN(1,'+')
        *mbuf++ = 'k';
        ADD_PARA(mode.key)
        pargs++;
    }
        
    chptr->mode = mode;
    chptr->jrl_bucket = 0;
    chptr->jrl_last = NOW;  /* slow start */
        
    if (!keepourmodes) /* deop and devoice everyone! */
    {
        what = 0;
        for (cm = chptr->members; cm; cm = cm->next) 
        {
            if (cm->flags & MODE_CHANOP) 
            {
                INSERTSIGN(-1,'-')
                    *mbuf++ = 'o';
                ADD_PARA(cm->cptr->name)
                    pargs++;
                if (pargs >= MAXMODEPARAMS) 
                {
                    *mbuf = '\0';
                    parabuf[pbpos] = '\0';
                    sjoin_sendit(cptr, sptr, chptr, parv[0]);
                    mbuf = modebuf;
                    *mbuf = '\0';
                    pargs = pbpos = what = 0;
                }
                cm->flags &= ~MODE_CHANOP;
            }

            if (cm->flags & MODE_VOICE) 
            {
                INSERTSIGN(-1,'-')
                    *mbuf++ = 'v';
                ADD_PARA(cm->cptr->name)
                    pargs++;
                if (pargs >= MAXMODEPARAMS) 
                {
                    *mbuf = '\0';
                    parabuf[pbpos] = '\0';
                    sjoin_sendit(cptr, sptr, chptr, parv[0]);
                    mbuf = modebuf;
                    *mbuf = '\0';
                    pargs = pbpos = what = 0;
                }
                cm->flags &= ~MODE_VOICE;
            }
        }
        /* 
         * We know if we get here, and we're in a sync, we haven't sent our topic 
         * to sptr yet. (since topic burst is sent after sjoin burst finishes) 
         */ 
        if(chptr->topic[0]) 
        { 
            chptr->topic[0] = '\0'; 
            sendto_channel_butserv_me(chptr, sptr, ":%s TOPIC %s :%s", 
                                sptr->name, chptr->chname, chptr->topic);
        }
        sendto_channel_butserv(chptr, &me,
                               ":%s NOTICE %s :*** Notice -- TS for %s "
                               "changed from %ld to %ld",
                               me.name, chptr->chname, chptr->chname,
                               oldts, newts);
    }
    
    if (mbuf != modebuf) 
    {
        *mbuf = '\0';
        parabuf[pbpos] = '\0';
        sjoin_sendit(cptr, sptr, chptr, parv[0]);
    }
    
    *modebuf = '\0';
    parabuf[0] = '\0';
    if (parv[3][0] != '0' && keepnewmodes)
        channel_modes(sptr, modebuf, parabuf, chptr);
    else 
    {
        modebuf[0] = '0';
        modebuf[1] = '\0';
    }
    
    /* We do this down below now, so we can send out for two sjoin formats.
     * sprintf(t, ":%s SJOIN %ld %ld %s %s %s :", parv[0], tstosend, tstosend,
     *                    parv[2], modebuf, parabuf);
     * t += strlen(t);
     * the pointer "t" has been removed and is now replaced with an 
     * index into sjbuf for faster appending
     */
    
    strcpy(keep_modebuf, modebuf);
    strcpy(keep_parabuf, parabuf);
    
    sjbufpos = 0;
    mbuf = modebuf;
    pbpos = 0;
    pargs = 0;
    *mbuf++ = '+';
    
    for (s = s0 = strtoken(&p, parv[args + 4], " "); s;
         s = s0 = strtoken(&p, (char *) NULL, " ")) 
    {
        fl = 0;
        if (*s == '@' || s[1] == '@')
            fl |= MODE_CHANOP;
        if (*s == '+' || s[1] == '+')
            fl |= MODE_VOICE;
        if (!keepnewmodes) 
        {
            if (fl & MODE_CHANOP)
                fl = MODE_DEOPPED;
            else
                fl = 0;
        }
        while (*s == '@' || *s == '+')
            s++;
        if (!(acptr = find_chasing(sptr, s, NULL)))
            continue;
        if (acptr->from != cptr)
            continue;
        people++;
        if (!IsMember(acptr, chptr)) 
        {
            add_user_to_channel(chptr, acptr, fl);
            sendto_channel_butserv(chptr, acptr, ":%s JOIN :%s", s, parv[2]);
        }
        if (keepnewmodes)
        {
            ADD_SJBUF(s0)
        }
        else
        {
            ADD_SJBUF(s)
        }
        if (fl & MODE_CHANOP) 
        {
            *mbuf++ = 'o';
            ADD_PARA(s)
            pargs++;
            if (pargs >= MAXMODEPARAMS) 
            {
                *mbuf = '\0';
                parabuf[pbpos] = '\0';
                sjoin_sendit(cptr, sptr, chptr, parv[0]);
                mbuf = modebuf;
                *mbuf++ = '+';
                pargs = pbpos = 0;
            }
        }
        if (fl & MODE_VOICE) 
        {
            *mbuf++ = 'v';
            ADD_PARA(s)
            pargs++;
            if (pargs >= MAXMODEPARAMS) 
            {
                *mbuf = '\0';
                parabuf[pbpos] = '\0';
                sjoin_sendit(cptr, sptr, chptr, parv[0]);
                mbuf = modebuf;
                *mbuf++ = '+';
                pargs = pbpos = 0;
            }
        }
    }

    parabuf[pbpos] = '\0';

    *mbuf = '\0';
    if (pargs)
        sjoin_sendit(cptr, sptr, chptr, parv[0]);
    if (people) 
    {
        sjbuf[sjbufpos] = '\0';

        if(keep_parabuf[0] != '\0')
            sendto_serv_butone(cptr, SJOINFmt, parv[0], tstosend, parv[2],
                               keep_modebuf, keep_parabuf, sjbuf);
        else
            sendto_serv_butone(cptr, SJOINFmtNP, parv[0], tstosend, parv[2],
                               keep_modebuf, sjbuf);
    }
    else if(created && chptr->users == 0) 
       sub1_from_channel(chptr);
    return 0;
}
#undef INSERTSIGN
#undef ADD_PARA
#undef ADD_SJBUF

/* m_samode - Just bout the same as df
 *  - Raistlin 
 * parv[0] = sender
 * parv[1] = channel
 * parv[2] = modes
 */
int m_samode(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aChannel *chptr;

    if (!MyClient(sptr))
        return 0;

    if (!IsAnOper(sptr) || !IsSAdmin(sptr)) 
    {
        sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
        return 0;
    }

    if(parc < 3)
    {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
                   me.name, parv[0], "SAMODE");
        return 0;
    }

    if((chptr = find_channel(parv[1], NullChn)) == NullChn)
        return 0;

    if(!check_channelname(sptr, (unsigned char *)parv[1]))
        return 0;

    set_mode(cptr, sptr, chptr, 2, parc - 2, parv + 2, modebuf, parabuf);
        
    if (strlen(modebuf) > (size_t)1)
    {
        sendto_channel_butserv(chptr, sptr, ":%s MODE %s %s %s",
                               parv[0], chptr->chname, modebuf, parabuf);
        sendto_serv_butone(cptr, ":%s MODE %s 0 %s %s", parv[0], chptr->chname,
                           modebuf, parabuf);
        if(MyClient(sptr))
        {
            sendto_serv_butone(NULL, ":%s GLOBOPS :%s used SAMODE (%s %s%s%s)",
                               me.name, sptr->name, chptr->chname, modebuf,
                               (*parabuf!=0 ? " " : ""), parabuf);
            send_globops("from %s: %s used SAMODE (%s %s%s%s)",
                         me.name, sptr->name, chptr->chname, modebuf, 
                         (*parabuf!=0 ? " " : ""), parabuf);
        }
    }
    return 0;
}

char  *pretty_mask(char *mask)
{
    char  *cp, *user, *host;
    
    if ((user = strchr((cp = mask), '!')))
        *user++ = '\0';
    if ((host = strrchr(user ? user : cp, '@')))
    {
        *host++ = '\0';
        if (!user)
            return make_nick_user_host(NULL, cp, host);
    }
    else if (!user && strchr(cp, '.'))
        return make_nick_user_host(NULL, NULL, cp);
    return make_nick_user_host(cp, user, host);
}

/* Check if two users share a common channel */
int find_shared_chan(aClient *cptr1, aClient *cptr2)
{
    Link *l1, *l2;

    for(l1 = cptr1->user->channel; l1; l1 = l1->next)
    {
        for(l2 = cptr2->user->channel; l2; l2 = l2->next)
        {
            if(l1->value.chptr == l2->value.chptr)
                return 1; /* Found a shared channel */
        }
    }

    return 0; /* No shared channels */
}

u_long
memcount_channel(MCchannel *mc)
{
    aChannel    *chptr;
    aBan        *ban;
#ifdef EXEMPT_LISTS
    aBanExempt  *exempt;
#endif
#ifdef INVITE_LISTS
    anInvite    *invite;
#endif
    DLink       *lp;
    Link        *lp2;
    chanMember  *cm;
#ifdef FLUD
    struct fludbot *fb;
#endif

    mc->file = __FILE__;

    for (chptr = channel; chptr; chptr = chptr->nextch)
    {
        mc->e_channels++;

        for (ban = chptr->banlist; ban; ban = ban->next)
        {
            mc->bans.c++;
            mc->bans.m += sizeof(*ban);
            mc->bans.m += strlen(ban->banstr) + 1;
            mc->bans.m += strlen(ban->who) + 1;
        }
#ifdef EXEMPT_LISTS
        for (exempt = chptr->banexempt_list; exempt; exempt = exempt->next)
        {
            mc->exempts.c++;
            mc->exempts.m += sizeof(*exempt);
            mc->exempts.m += strlen(exempt->banstr) + 1;
            mc->exempts.m += strlen(exempt->who) + 1;
        }
#endif
#ifdef INVITE_LISTS
        for (invite = chptr->invite_list; invite; invite = invite->next)
        {
            mc->invites.c++;
            mc->invites.m += sizeof(*invite);
            mc->invites.m += strlen(invite->invstr) + 1;
            mc->invites.m += strlen(invite->who) + 1;
        }
#endif
        for (cm = chptr->members; cm; cm = cm->next)
            mc->e_chanmembers++;

#ifdef FLUD
        for (fb = chptr->fluders; fb; fb = fb->next)
            mc->e_fludbots++;
#endif

        mc->e_inv_links += mc_links(chptr->invites);
    }

    for (lp = listing_clients; lp; lp = lp->next)
    {
        mc->lopts.c++;
        mc->lopts.m += sizeof(LOpts);
        mc->e_dlinks++;
        for (lp2 = lp->value.cptr->user->lopt->yeslist; lp2; lp2 = lp2->next)
        {
            mc->lopts.m += strlen(lp2->value.cp) + 1;
            mc->e_lopt_links++;
        }
        for (lp2 = lp->value.cptr->user->lopt->nolist; lp2; lp2 = lp2->next)
        {
            mc->lopts.m += strlen(lp2->value.cp) + 1;
            mc->e_lopt_links++;
        }
    }

    mc->total.c = mc->bans.c;
    mc->total.m = mc->bans.m;
#ifdef EXEMPT_LISTS
    mc->total.c += mc->exempts.c;
    mc->total.m += mc->exempts.m;
#endif
#ifdef INVITE_LISTS
    mc->total.c += mc->invites.c;
    mc->total.m += mc->invites.m;
#endif
    mc->total.c += mc->lopts.c;
    mc->total.m += mc->lopts.m;

    mc->s_scratch.c++;
    mc->s_scratch.m += sizeof(nickbuf);
    mc->s_scratch.c++;
    mc->s_scratch.m += sizeof(buf);
    mc->s_scratch.c++;
    mc->s_scratch.m += sizeof(modebuf);
    mc->s_scratch.c++;
    mc->s_scratch.m += sizeof(parabuf);

    return mc->total.m;
}

