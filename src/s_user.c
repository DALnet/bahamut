/************************************************************************
 *   IRC - Internet Relay Chat, src/s_user.c
 *   Copyright (C) 1990 Jarkko Oikarinen and
 *                      University of Oulu, Computing Center
 *
 *   See file AUTHORS in IRC package for additional names of
 *   the programmers.
 *
 *   This program is free softwmare; you can redistribute it and/or modify
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

/* $Id$ */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "msg.h"
#include "channel.h"
#include <sys/stat.h>
#include <utmp.h>
#include <fcntl.h>
#include "h.h"
#ifdef FLUD
#include "blalloc.h"
#endif /*
        * FLUD 
        */

#if defined( HAVE_STRING_H)
#include <string.h>
#else
#include <strings.h>
#endif

int
            do_user(char *, aClient *, aClient *, char *, char *, char *,
		    unsigned long, char *);

int         botwarn(char *, char *, char *, char *);

extern char motd_last_changed_date[];
extern int  send_motd(aClient *, aClient *, int, char **);
extern void send_topic_burst(aClient *);
extern void outofmemory(void);	/*

				 * defined in list.c 
				 */
#ifdef MAXBUFFERS
extern void reset_sock_opts();
extern int send_lusers(aClient *,aClient *,int, char **);

#endif
extern int  lifesux;

#ifdef WINGATE_NOTICE
extern char ProxyMonURL[TOPICLEN + 1];
extern char ProxyMonHost[HOSTLEN + 1];
#endif

static char buf[BUFSIZE], buf2[BUFSIZE];
static int  user_modes[] =
{UMODE_o, 'o',
 UMODE_O, 'O',
 UMODE_i, 'i',
 UMODE_w, 'w',
 UMODE_s, 's',
 UMODE_c, 'c',
 UMODE_r, 'r',
 UMODE_R, 'R',
 UMODE_k, 'k',
 UMODE_y, 'y',
 UMODE_d, 'd',
 UMODE_e, 'e',
 UMODE_g, 'g',
 UMODE_b, 'b',
 UMODE_a, 'a',
 UMODE_A, 'A',
 UMODE_f, 'f',
 UMODE_n, 'n',
 UMODE_m, 'm',
 UMODE_h, 'h',	 
 0, 0};

/*
 * internally defined functions 
 */
int         botreject(char *);
unsigned long my_rand(void);	/*

				 * provided by orabidoo 
				 */
/*
 * externally defined functions 
 */
void  send_svsmode_out (aClient*, aClient *, aClient *, int);
extern int  find_fline(aClient *);	/*

					 * defined in s_conf.c 
					 */
extern Link *find_channel_link(Link *, aChannel *);	/*

							 * defined in list.c 
							 */
#ifdef FLUD
int         flud_num = FLUD_NUM;
int         flud_time = FLUD_TIME;
int         flud_block = FLUD_BLOCK;
extern BlockHeap *free_fludbots;
extern BlockHeap *free_Links;

void        announce_fluder(aClient *, aClient *, aChannel *, int);
struct fludbot *remove_fluder_reference(struct fludbot **, aClient *);
Link       *remove_fludee_reference(Link **, void *);
int         check_for_fludblock(aClient *, aClient *, aChannel *, int);
int         check_for_flud(aClient *, aClient *, aChannel *, int);
void        free_fluders(aClient *, aChannel *);
void        free_fludees(aClient *);
#endif
int      check_for_ctcp(char *, char **);
int      allow_dcc(aClient *, aClient *);
static int      is_silenced(aClient *, aClient *);

#ifdef ANTI_SPAMBOT
int         spam_time = MIN_JOIN_LEAVE_TIME;
int         spam_num = MAX_JOIN_LEAVE_COUNT;
#endif

/* defines for check_ctcp results */
#define CTCP_NONE 	0
#define CTCP_YES	1
#define CTCP_DCC	2
#define CTCP_DCCSEND 	3


/*
 * * m_functions execute protocol messages on this server: *
 * 
 *      cptr    is always NON-NULL, pointing to a *LOCAL* client *
 * tructure (with an open socket connected!). This *
 * es the physical socket where the message *           originated (or
 * which caused the m_function to be *          executed--some
 * m_functions may call others...). *
 * 
 *      sptr    is the source of the message, defined by the *
 * refix part of the message if present. If not *               or
 * prefix not found, then sptr==cptr. *
 * 
 *              (!IsServer(cptr)) => (cptr == sptr), because *
 * refixes are taken *only* from servers... *
 * 
 *              (IsServer(cptr)) *                      (sptr == cptr)
 * => the message didn't *                      have the prefix. *
 * 
 *                      (sptr != cptr && IsServer(sptr) means *
 * he prefix specified servername. (?) *
 * 
 *                      (sptr != cptr && !IsServer(sptr) means *
 * hat message originated from a remote *                       user
 * (not local). *
 * 
 *              combining *
 * 
 *              (!IsServer(sptr)) means that, sptr can safely *
 * aken as defining the target structure of the *               message
 * in this server. *
 * 
 *      *Always* true (if 'parse' and others are working correct): *
 * 
 *      1)      sptr->from == cptr  (note: cptr->from == cptr) *
 * 
 *      2)      MyConnect(sptr) <=> sptr == cptr (e.g. sptr *
 * annot* be a local connection, unless it's *          actually
 * cptr!). [MyConnect(x) should probably *              be defined as
 * (x == x->from) --msa ] *
 * 
 *      parc    number of variable parameter strings (if zero, *
 * arv is allowed to be NULL) *
 * 
 *      parv    a NULL terminated list of parameter pointers, *
 * 
 *                      parv[0], sender (prefix string), if not present *
 * his points to an empty string. *
 * arc-1] *                             pointers to additional
 * parameters *                 parv[parc] == NULL, *always* *
 * 
 *              note:   it is guaranteed that parv[0]..parv[parc-1] are
 * all *                        non-NULL pointers.
 */
/*
 * * next_client *    Local function to find the next matching
 * client. The search * can be continued from the specified client
 * entry. Normal *      usage loop is: *
 * 
 *      for (x = client; x = next_client(x,mask); x = x->next) *
 * andleMatchingClient; *
 * 
 */
aClient    *
next_client(aClient *next,	/*
				 * First client to check 
				 */
	    char *ch)
{				/*
				 * search string (may include wilds) 
				 */
   aClient *tmp = next;

   next = find_client(ch, tmp);
   if (tmp && tmp->prev == next)
      return ((aClient *) NULL);

   if (next != tmp)
      return next;
   for (; next; next = next->next) {
      if (!match(ch, next->name))
	 break;
   }
   return next;
}

/*
 * this slow version needs to be used for hostmasks *sigh * 
 */

aClient    *
next_client_double(aClient *next,	/*
					 * First client to check 
					 */
		   char *ch)
{				/*
				 * search string (may include wilds) 
				 */
   aClient *tmp = next;

   next = find_client(ch, tmp);
   if (tmp && tmp->prev == next)
      return NULL;
   if (next != tmp)
      return next;
   for (; next; next = next->next) {
      if (!match(ch, next->name) || !match(next->name, ch))
	 break;
   }
   return next;
}
/*
 * * hunt_server *
 * 
 *      Do the basic thing in delivering the message (command) *
 * across the relays to the specific server (server) for *
 * actions. *
 * 
 *      Note:   The command is a format string and *MUST* be *
 * f prefixed style (e.g. ":%s COMMAND %s ..."). *              Command
 * can have only max 8 parameters. *
 * 
 *      server  parv[server] is the parameter identifying the *
 * arget server. *
 * 
 *      *WARNING* *             parv[server] is replaced with the
 * pointer to the *             real servername from the matched client
 * (I'm lazy *          now --msa). *
 * 
 *      returns: (see #defines)
 */
int
hunt_server(aClient *cptr,
	    aClient *sptr,
	    char *command,
	    int server,
	    int parc,
	    char *parv[])
{
   aClient    *acptr;
   int         wilds;

   /*
    * * Assume it's me, if no server
    */
   if (parc <= server || BadPtr(parv[server]) ||
       match(me.name, parv[server]) == 0 ||
       match(parv[server], me.name) == 0)
      return (HUNTED_ISME);
   /*
    * * These are to pickup matches that would cause the following *
    * message to go in the wrong direction while doing quick fast *
    * non-matching lookups.
    */
   if ((acptr = find_client(parv[server], NULL)))
      if (acptr->from == sptr->from && !MyConnect(acptr))
	 acptr = NULL;
   if (!acptr && (acptr = find_server(parv[server], NULL)))
      if (acptr->from == sptr->from && !MyConnect(acptr))
	 acptr = NULL;

   (void) collapse(parv[server]);
   wilds = (strchr(parv[server], '?') || strchr(parv[server], '*'));
   /*
    * Again, if there are no wild cards involved in the server name,
    * use the hash lookup - Dianora
    */

   if (!acptr) {
      if (!wilds) {
	 acptr = find_name(parv[server], (aClient *) NULL);
	 if (!acptr || !IsRegistered(acptr) || !IsServer(acptr)) {
	    sendto_one(sptr, err_str(ERR_NOSUCHSERVER), me.name,
		       parv[0], parv[server]);
	    return (HUNTED_NOSUCH);
	 }
      }
      else {
	 for (acptr = client;
	      (acptr = next_client(acptr, parv[server]));
	      acptr = acptr->next) {
	    if (acptr->from == sptr->from && !MyConnect(acptr))
	       continue;
	    /*
	     * Fix to prevent looping in case the parameter for some
	     * reason happens to match someone from the from link --jto
	     */
	    if (IsRegistered(acptr) && (acptr != cptr))
	       break;
	 }
      }
   }

   if (acptr) {
      if (IsMe(acptr) || MyClient(acptr))
	 return HUNTED_ISME;
      if (match(acptr->name, parv[server]))
	 parv[server] = acptr->name;
      sendto_one(acptr, command, parv[0],
		 parv[1], parv[2], parv[3], parv[4],
		 parv[5], parv[6], parv[7], parv[8]);
      return (HUNTED_PASS);
   }
   sendto_one(sptr, err_str(ERR_NOSUCHSERVER), me.name,
	      parv[0], parv[server]);
   return (HUNTED_NOSUCH);
}
/*
 * * 'do_nick_name' ensures that the given parameter (nick) is * really
 * a proper string for a nickname (note, the 'nick' * may be modified
 * in the process...) *
 * 
 *      RETURNS the length of the final NICKNAME (0, if *
 * nickname is illegal) *
 * 
 *  Nickname characters are in range *  'A'..'}', '_', '-', '0'..'9' *
 * anything outside the above set will terminate nickname. *  In
 * addition, the first character cannot be '-' *  or a Digit. *
 * 
 *  Note: *     '~'-character should be allowed, but *  a change should
 * be global, some confusion would *    result if only few servers
 * allowed it...
 */

static int
do_nick_name(char *nick)
{
   char   *ch;

   if (*nick == '-' || isdigit(*nick))	/*
					 * first character in [0..9-] 
					 */
      return 0;

   for (ch = nick; *ch && (ch - nick) < NICKLEN; ch++)
      if (!isvalid(*ch) || isspace(*ch))
	 break;

   *ch = '\0';

   return (ch - nick);
}

/*
 * * canonize *
 * 
 * reduce a string of duplicate list entries to contain only the unique *
 * items.  Unavoidably O(n^2).
 */
char       *
canonize(char *buffer)
{
   static char cbuf[BUFSIZ];
   char *s, *t, *cp = cbuf;
   int l = 0;
   char       *p = NULL, *p2;

   *cp = '\0';

   for (s = strtoken(&p, buffer, ","); s; s = strtoken(&p, NULL, ",")) {
      if (l) {
	 for (p2 = NULL, t = strtoken(&p2, cbuf, ","); t;
	      t = strtoken(&p2, NULL, ","))
	    if (!mycmp(s, t))
	       break;
	    else if (p2)
	       p2[-1] = ',';
      }
      else
	 t = NULL;

      if (!t) {
	 if (l)
	    *(cp - 1) = ',';
	 else
	    l = 1;
	 (void) strcpy(cp, s);
	 if (p)
	    cp += (p - s);
      }
      else if (p2)
	 p2[-1] = ',';
   }
   return cbuf;
}

/*
 * * register_user *  This function is called when both NICK and USER
 * messages *   have been accepted for the client, in whatever order.
 * Only *       after this, is the USER message propagated. *
 * 
 *      NICK's must be propagated at once when received, although *
 * it would be better to delay them too until full info is *
 * available. Doing it is not so simple though, would have *    to
 * implement the following: *
 * 
 *      (actually it has been implemented already for a while)
 * -orabidoo *
 * 
 *      1) user telnets in and gives only "NICK foobar" and waits *
 * 2) another user far away logs in normally with the nick *
 * "foobar" (quite legal, as this server didn't propagate *        it). *
 * 3) now this server gets nick "foobar" from outside, but *       has
 * already the same defined locally. Current server *      would just
 * issue "KILL foobar" to clean out dups. But, *           this is not
 * fair. It should actually request another *      nick from local user
 * or kill him/her...
 */

static int
register_user(aClient *cptr,
	      aClient *sptr,
	      char *nick,
	      char *username)
{
	aClient *nsptr;
   aConfItem *aconf = NULL, *pwaconf = NULL;
   char       *parv[3];
   static char ubuf[12];
   char       *p;
   short       oldstatus = sptr->status;
   anUser     *user = sptr->user;
#ifdef SHORT_MOTD
   aMotd      *smotd;
#endif
   int         i, dots;
   int         bad_dns;		/*

				 * flag a bad dns name 
				 */
#ifdef ANTI_SPAMBOT
   char        spamchar = '\0';

#endif
   char        tmpstr2[512];

   user->last = timeofday;
   parv[0] = sptr->name;
   parv[1] = parv[2] = NULL;
	  
   if (MyConnect(sptr)) {
      p = inetntoa((char *) &sptr->ip);
      strncpyzt(sptr->hostip, p, HOSTIPLEN + 1);
      if ((i = check_client(sptr))) {
			/*
			 * -2 is a socket error, already reported.
			 */
			if (i != -2) {
				if (i == -4) {
					ircstp->is_ref++;
					return exit_client(cptr, sptr, &me,
											 "Too many connections from your hostname");
				}
				else if (i == -3)
				  sendto_realops_lev(SPY_LEV, "%s for %s [%s] ",
											"I-line is full", get_client_host(sptr),p);
				else
				  sendto_realops_lev(CCONN_LEV, "%s from %s [%s]",
											"Unauthorized client connection", get_client_host(sptr),p);
				ircstp->is_ref++;
				return exit_client(cptr, sptr, &me, i == -3 ?
										 "No more connections allowed in your connection class" :
										 "You are not authorized to use this server");
			}
			else
			  return exit_client(cptr, sptr, &me, "Socket Error");
		}
	
#ifdef ANTI_SPAMBOT
		/*
		 * This appears to be broken 
		 */
		/*
		 * Check for single char in user->host -ThemBones 
		 */
		if (*(user->host + 1) == '\0')
		  spamchar = *user->host;
#endif
		
      strncpyzt(user->host, sptr->sockhost, HOSTLEN);
		
      dots = 0;
      p = user->host;
      bad_dns = NO;
      while (*p) {
			if (!isalnum(*p)) {
#ifdef RFC1035_ANAL
				if ((*p != '-') && (*p != '.'))
#else
				  if ((*p != '-') && (*p != '.') && (*p != '_') && (*p != '/'))
#endif /*
					 * RFC1035_ANAL 
        */
					 bad_dns = YES;
			}
			if (*p == '.')
			  dots++;
			p++;
      }
      /*
       * Check that the hostname has AT LEAST ONE dot (.) in it. If
       * not, drop the client (spoofed host) -ThemBones
       */
      if (!dots) {
			sendto_realops(
								"Invalid hostname for %s, dumping user %s",
								sptr->hostip, sptr->name);
			return exit_client(cptr, sptr, &me, "Invalid hostname");
      }
		
      if (bad_dns) {
			sendto_one(sptr, ":%s NOTICE %s :*** Notice -- You have a bad character in your hostname",
						  me.name, cptr->name);
			strcpy(user->host, sptr->hostip);
			strcpy(sptr->sockhost, sptr->hostip);
      }
		
      pwaconf = sptr->confs->value.aconf;
      if (sptr->flags & FLAGS_DOID && !(sptr->flags & FLAGS_GOTID)) {
			/*
			 * because username may point to user->username 
			 */
			char        temp[USERLEN + 1];
			
			strncpyzt(temp, username, USERLEN + 1);
			*user->username = '~';
			(void) strncpy(&user->username[1], temp, USERLEN);
			user->username[USERLEN] = '\0';
#ifdef IDENTD_COMPLAIN
			/*
			 * tell them to install identd -Taner 
			 */
			sendto_one(sptr, ":%s NOTICE %s :*** Notice -- It seems that you don't have identd installed on your host.",
						  me.name, cptr->name);
			sendto_one(sptr, ":%s NOTICE %s :*** Notice -- If you wish to have your username show up without the ~ (tilde),",
						  me.name, cptr->name);
			sendto_one(sptr, ":%s NOTICE %s :*** Notice -- then install identd.",
						  me.name, cptr->name);
			/*
			 * end identd hack 
			 */
#endif
      }
#ifndef FOLLOW_IDENT_RFC
      else if (sptr->flags & FLAGS_GOTID && *sptr->username != '-')
		  strncpyzt(user->username, sptr->username, USERLEN + 1);
#endif
      else
		  strncpyzt(user->username, username, USERLEN + 1);
		
      if (!BadPtr(pwaconf->passwd) &&
			 !StrEq(sptr->passwd, pwaconf->passwd)) {
			ircstp->is_ref++;
			sendto_one(sptr, err_str(ERR_PASSWDMISMATCH),
						  me.name, parv[0]);
			return exit_client(cptr, sptr, &me, "Bad Password");
      }
		
      
		/*
       * following block for the benefit of time-dependent K:-lines
       */
      if ((aconf = find_kill(sptr))) {
			char       *reason;
			char	   *ktype;
			int         kline;
			
			kline = (aconf->status == CONF_KILL) ? 1 : 0;
			ktype = kline ? "K-lined" : "Autokilled";
			reason = aconf->passwd ? aconf->passwd : ktype;
			
#ifdef RK_NOTICES
			sendto_realops("%s %s@%s. for %s", ktype, sptr->user->username,
								sptr->sockhost, reason);
#endif
			sendto_one(sptr, err_str(ERR_YOUREBANNEDCREEP),
				   me.name, sptr->name, ktype);
			sendto_one(sptr, ":%s NOTICE %s :*** You are not welcome on this %s.",
				   me.name, sptr->name,
				   kline ? "server" : "network");
			sendto_one(sptr, ":%s NOTICE %s :*** %s for %s",
                                   me.name, sptr->name, ktype, reason);
                        sendto_one(sptr, ":%s NOTICE %s :*** Your hostmask is %s!%s@%s",
                                   me.name, sptr->name, sptr->name, sptr->user->username, sptr->sockhost);
			sendto_one(sptr, ":%s NOTICE %s :*** For more information, please mail %s and include everything shown here.",
				   me.name, sptr->name,
				   kline ? SERVER_KLINE_ADDRESS : NETWORK_KLINE_ADDRESS);

#ifdef USE_REJECT_HOLD
			cptr->flags |= FLAGS_REJECT_HOLD;
#endif
			ircstp->is_ref++;

#ifndef USE_REJECT_HOLD			
			return exit_client(cptr, sptr, &me, reason);
#endif
      }
		
      /*
       * Limit clients 
       */
      /*
       * We want to be able to have servers and F-line clients connect,
       * so save room for "buffer" connections. Smaller servers may
       * want to decrease this, and it should probably be just a
       * percentage of the MAXCLIENTS... -Taner
       */
      /*
       * Except "F:" clients 
       */
      if ((
			  (sptr->fd >= (MAXCLIENTS + MAX_BUFFER))) || ((sptr->fd >= (MAXCLIENTS - 5)) && !(find_fline(sptr)))) {
			sendto_realops_lev(SPY_LEV, "Too many clients, rejecting %s[%s].",
									 nick, sptr->sockhost);
			ircstp->is_ref++;
			return exit_client(cptr, sptr, &me,
									 "Sorry, server is full - try later");
      }
		
#ifdef ANTI_SPAMBOT
      /*
       * It appears, this is catching normal clients 
       */
      /*
       * Reject single char user-given user->host's 
       */
      if (spamchar == 'x') {
			sendto_realops_lev(REJ_LEV, "Rejecting possible Spambot: %s (Single char user-given userhost: %c)",
									 get_client_name(sptr, FALSE), spamchar);
			ircstp->is_ref++;
			return exit_client(cptr, sptr, sptr, "Spambot detected, rejected.");
      }
#endif
		

      if (oldstatus == STAT_MASTER && MyConnect(sptr))
		  (void) m_oper(&me, sptr, 1, parv);

      /* hostile username checks begin here */

		  {
			  char *tmpstr;
			  u_char      c, cc;
			  int lower, upper, special;
			  
			  lower = upper = special = cc = 0;
			  
			  /*
				* check for "@" in identd reply -Taner 
				*/
			  if ((strchr(user->username, '@') != NULL) || (strchr(username, '@') != NULL)) {
				  sendto_realops_lev(REJ_LEV,
											"Illegal \"@\" in username: %s (%s)",
											get_client_name(sptr, FALSE), username);
				  ircstp->is_ref++;
				  (void) ircsprintf(tmpstr2, "Invalid username [%s] - '@' is not allowed!",
										  username);
				  return exit_client(cptr, sptr, sptr, tmpstr2);
			  }
			  /*
				* First check user->username...
				*/
#ifdef IGNORE_FIRST_CHAR
			  tmpstr = (user->username[0] == '~' ? &user->username[2] :
							&user->username[1]);
			  /*
				* Ok, we don't want to TOTALLY ignore the first character. We
				* should at least check it for control characters, etc -
				* ThemBones
				*/
			  cc = (user->username[0] == '~' ? user->username[1] :
					  user->username[0]);
			  if ((!isalnum(cc) && !strchr(" -_.", cc)) || (cc > 127))
				 special++;
#else
			  tmpstr = (user->username[0] == '~' ? &user->username[1] :
							user->username);
#endif /* IGNORE_FIRST_CHAR */
			  
			  while (*tmpstr) {
				  c = *(tmpstr++);
				  if (islower(c)) {
					  lower++;
					  continue;
				  }
				  if (isupper(c)) {
					  upper++;
					  continue;
				  }
				  if ((!isalnum(c) && !strchr(" -_.", c)) || (c > 127) || (c<32))
					 special++;
			  }
#ifdef NO_MIXED_CASE
			  if (lower && upper) {
				  sendto_realops_lev(REJ_LEV, "Invalid username: %s (%s@%s)",
											nick, user->username, user->host);
				  ircstp->is_ref++;
				  (void) ircsprintf(tmpstr2, "Invalid username [%s]", user->username);
				  return exit_client(cptr, sptr, &me, tmpstr2);
			  }
#endif /* NO_MIXED_CASE */
			  if (special) {
				  sendto_realops_lev(REJ_LEV, "Invalid username: %s (%s@%s)",
											nick, user->username, user->host);
				  ircstp->is_ref++;
				  (void) ircsprintf(tmpstr2, "Invalid username [%s]",
										  user->username);
				  return exit_client(cptr, sptr, &me, tmpstr2);
			  }
		  /* Ok, now check the username they provided, if different */
			  lower = upper = special = cc = 0;
			  
			  if (strcmp(user->username, username)) {
				  
#ifdef IGNORE_FIRST_CHAR
				  tmpstr = (username[0] == '~' ? &username[2] : &username[1]);
				  /*
					* Ok, we don't want to TOTALLY ignore the first character.
					* We should at least check it for control charcters, etc
					* -ThemBones
					*/
				  cc = (username[0] == '~' ? username[1] : username[0]);
				  
				  if ((!isalnum(cc) && !strchr(" -_.", cc)) || (cc > 127))
					 special++;
#else
				  tmpstr = (username[0] == '~' ? &username[1] : username);
#endif /* IGNORE_FIRST_CHAR */
				  while (*tmpstr) {
					  c = *(tmpstr++);
					  if (islower(c)) {
						  lower++;
						  continue;
					  }
					  if (isupper(c)) {
						  upper++;
						  continue;
					  }
					  if ((!isalnum(c) && !strchr(" -_.", c)) || (c > 127))
						 special++;
				  }
#ifdef NO_MIXED_CASE
				  if (lower && upper) {
					  sendto_realops_lev(REJ_LEV, "Invalid username: %s (%s@%s)",
												nick, username, user->host);
					  ircstp->is_ref++;
					  (void) ircsprintf(tmpstr2, "Invalid username [%s]",
											  username);
					  return exit_client(cptr, sptr, &me, tmpstr2);
				  }
#endif / * NO_MIXED_CASE */
				  if (special) {
					  sendto_realops_lev(REJ_LEV, "Invalid username: %s (%s@%s)",
												nick, username, user->host);
					  ircstp->is_ref++;
					  (void) ircsprintf(tmpstr2, "Invalid username [%s]",
											  username);
					  return exit_client(cptr, sptr, &me, tmpstr2);
				  }
			  }			/* usernames different  */
		  }

      /*
       * reject single character usernames which aren't alphabetic i.e.
       * reject jokers who have '?@somehost' or '.@somehost'
       * 
       * -Dianora
       */
		
      if ((user->username[1] == '\0') && !isalpha(user->username[0])) {
			sendto_realops_lev(REJ_LEV, "Invalid username: %s (%s@%s)",
									 nick, user->username, user->host);
			ircstp->is_ref++;
			(void) ircsprintf(tmpstr2, "Invalid username [%s]",
									user->username);
			return exit_client(cptr, sptr, &me, tmpstr2);
      }
		
      sendto_realops_lev(CCONN_LEV,
								 "Client connecting: %s (%s@%s) [%s] {%d}",
								 nick,
								 user->username,
								 user->host,
								 sptr->hostip,
								 get_client_class(sptr));
      if ((++Count.local) > Count.max_loc) {
			Count.max_loc = Count.local;
			if (!(Count.max_loc % 10))
			  sendto_ops("New Max Local Clients: %d",
							 Count.max_loc);
      }
      if ((NOW - Count.day) > 86400) {
	Count.today = 0;
	Count.day = NOW;
      }
      if ((NOW - Count.week) > 604800) {
	Count.weekly = 0;
	Count.week = NOW;
      }
      if ((NOW - Count.month) > 2592000) {
	Count.monthly = 0;
	Count.month = NOW;
      }
      if ((NOW - Count.year) > 31536000) {
	Count.yearly = 0;
        Count.year = NOW;
      }
      Count.today++;
      Count.weekly++;
      Count.monthly++;
      Count.yearly++;
      
   }
   else
	  strncpyzt(user->username, username, USERLEN + 1);

   SetClient(sptr);
   /*
    * Increment our total user count here 
    */
   if (++Count.total > Count.max_tot)
	  Count.max_tot = Count.total;

   if(IsInvisible(sptr)) Count.invisi++;
	
   if (MyConnect(sptr)) {
      sptr->pingval = get_client_ping(sptr);
      sptr->sendqlen = get_sendq(sptr);
#ifdef MAXBUFFERS
      /*
       * Let's try changing the socket options for the client here...
       * -Taner
       */
      reset_sock_opts(sptr->fd, 0);
      /*
       * End sock_opt hack 
       */
#endif
      sendto_one(sptr, rpl_str(RPL_WELCOME), me.name, nick, nick, 
					  sptr->user->username, sptr->user->host);
      /*
       * This is a duplicate of the NOTICE but see below...
       * um, why were we hiding it? they did make it on to the
       * server and all..;) -wd
       */
      sendto_one(sptr, rpl_str(RPL_YOURHOST), me.name, nick,
			  get_client_name(&me, TRUE), version);
#ifdef	IRCII_KLUDGE
      /*
       * * Don't mess with this one - IRCII needs it! -Avalon
       */
      sendto_one(sptr, "NOTICE %s :*** Your host is %s, running version %s",
					  nick, get_client_name(&me, TRUE), version);
#endif
      sendto_one(sptr, rpl_str(RPL_CREATED), me.name, nick, creation);
      sendto_one(sptr, rpl_str(RPL_MYINFO), me.name, parv[0],
					  me.name, version);
		sendto_one(sptr, rpl_str(RPL_PROTOCTL), me.name, parv[0]);
      (void) send_lusers(sptr, sptr, 1, parv);
		
      sendto_one(sptr, ":%s NOTICE %s :*** Notice -- motd was last changed at %s",
			me.name, nick, motd_last_changed_date);
#ifdef SHORT_MOTD
      sendto_one(sptr, ":%s NOTICE %s :*** Notice -- Please read the motd if you haven't read it",
			me.name, nick);
		
      sendto_one(sptr, rpl_str(RPL_MOTDSTART),
					  me.name, parv[0], me.name);
      if((smotd = shortmotd) == NULL)
      {
         sendto_one(sptr,
					  rpl_str(RPL_MOTD),
					  me.name, parv[0],
					  "*** This is the short motd ***"
					  );
      }
      else {
         while (smotd) {
            sendto_one(sptr, rpl_str(RPL_MOTD), me.name, parv[0], smotd->line);
            smotd = smotd->next;
         }
      }
		
      sendto_one(sptr, rpl_str(RPL_ENDOFMOTD),
					  me.name, parv[0]);
#else
      (void) send_motd(sptr, sptr, 1, parv);
#endif
#ifdef WINGATE_NOTICE
      sendto_one(sptr, ":%s NOTICE %s :*** Notice -- This server runs an open proxy/wingate detection monitor.", 
		 me.name, nick);
      sendto_one(sptr, ":%s NOTICE %s :*** Notice -- If you see a port 1080 or port 23 connection from %s", me.name, 
		 nick, ProxyMonHost);
      sendto_one(sptr, ":%s NOTICE %s :*** Notice -- please disregard it, as it is the detector in action.",
		 me.name, nick);
      sendto_one(sptr, ":%s NOTICE %s :*** Notice -- For more information please see %s", 
		 me.name, nick, ProxyMonURL);
#endif
#ifdef LITTLE_I_LINES
      if (sptr->confs && sptr->confs->value.aconf &&
			 (sptr->confs->value.aconf->flags
			  & CONF_FLAGS_LITTLE_I_LINE)) {
			SetRestricted(sptr);
			sendto_one(sptr, ":%s NOTICE %s :*** Notice -- You are in a restricted access mode", me.name, nick);
			sendto_one(sptr, ":%s NOTICE %s :*** Notice -- You can not be chanopped", me.name, nick);
      }
#endif
		
   }
   else if (IsServer(cptr)) {
		aClient    *acptr;
		
      if ((acptr = find_server(user->server, NULL)) &&
			 acptr->from != sptr->from) {
			sendto_realops_lev(DEBUG_LEV,
									 "Bad User [%s] :%s USER %s@%s %s, != %s[%s]",
									 cptr->name, nick, user->username,
									 user->host, user->server,
									 acptr->name, acptr->from->name);
			sendto_one(cptr,
						  ":%s KILL %s :%s (%s != %s[%s] USER from wrong direction)",
						  me.name, sptr->name, me.name, user->server,
						  acptr->from->name, acptr->from->sockhost);
			sptr->flags |= FLAGS_KILLED;
			return exit_client(sptr, sptr, &me,
									 "USER server wrong direction");
			
      }
      /*
       * Super GhostDetect: If we can't find the server the user is
       * supposed to be on, then simply blow the user away.     -Taner
       */
      if (!acptr) {
			sendto_one(cptr,
						  ":%s KILL %s :%s GHOST (no server %s on the net)",
						  me.name,
						  sptr->name, me.name, user->server);
			sendto_realops("No server %s for user %s[%s@%s] from %s",
								user->server,
								sptr->name, user->username,
								user->host, sptr->from->name);
			sptr->flags |= FLAGS_KILLED;
			return exit_client(sptr, sptr, &me, "Ghosted Client");
      }
   }
   send_umode(NULL, sptr, 0, SEND_UMODES, ubuf);
   if (!*ubuf) {
      ubuf[0] = '+';
      ubuf[1] = '\0';
   }
   hash_check_watch(sptr, RPL_LOGON);
   sendto_serv_butone(cptr, "NICK %s %d %ld %s %s %s %s %lu :%s",
							 nick, sptr->hopcount + 1, sptr->tsinfo, ubuf,
							 user->username, user->host, user->server, sptr->user->servicestamp,
							 sptr->info);

   if(MyClient(sptr)) {
     /* if the I:line doesn't have a password and the user does, send it over to NickServ */
     if(BadPtr(pwaconf->passwd) && sptr->passwd[0] && (nsptr=find_person(NickServ,NULL))!=NULL) {
        sendto_one(nsptr,":%s PRIVMSG %s@%s :SIDENTIFY %s", sptr->name, NickServ, SERVICES_NAME, sptr->passwd);
     }

     if(sptr->passwd[0])
        memset(sptr->passwd, '\0', PASSWDLEN);
     
     if (ubuf[1]) send_umode(cptr, sptr, 0, ALL_UMODES, ubuf);
   }

   return 0;
}

/*
 * 
 * m_nick 
 * parv[0] = sender prefix 
 * parv[1] = nickname 
 * parv[2] = hopcount when new user; TS when nick change 
 * parv[3] = TS
 * ---- new user only below ---- 
 * parv[4] = umode 
 * parv[5] = username 
 * parv[6] = hostname 
 * parv[7] = server 
 * parv[8] = serviceid
 * parv[9] = ircname
 */
int m_nick(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
   aConfItem  *aconf;
   aClient    *acptr, *uplink;
   Link       *lp;
   char        nick[NICKLEN + 2];
   ts_val      newts = 0;
   int         sameuser = 0, samenick = 0;
        
   if (parc < 2) {
      sendto_one(sptr, err_str(ERR_NONICKNAMEGIVEN),
                                          me.name, parv[0]);
      return 0;
   }
        
   if (!IsServer(sptr) && IsServer(cptr) && parc > 2)
          newts = atol(parv[2]);
   else if (IsServer(sptr) && parc > 3)
          newts = atol(parv[3]);
   else
          parc = 2;
   /*
    * parc == 2 on a normal client sign on (local) and a normal client nick change 
    * parc == 4 on a normal server-to-server client nick change
    * parc == 10 on a normal TS style server-to-server NICK introduction
    */
   if ((IsServer(sptr) || (parc > 4)) && (parc < 10))
   {
      /*
       * We got the wrong number of params. Someone is trying to trick
       * us. Kill it. -ThemBones As discussed with ThemBones, not much
       * point to this code now sending a whack of global kills would
       * also be more annoying then its worth, just note the problem,
       * and continue -Dianora
       */
      sendto_realops("IGNORING BAD NICK: %s[%s@%s] on %s (from %s)", parv[1],
                     (parc >= 6) ? parv[5] : "-",
                     (parc >= 7) ? parv[6] : "-",
                     (parc >= 8) ? parv[7] : "-", parv[0]);
      return 0;
                
   }
        
   if ((parc == 10) && (!strchr(parv[6], '.')))
   {
      /*
       * Ok, we got the right number of params, but there isn't a
       * single dot in the hostname, which is suspicious. Don't fret
       * about it just kill it. - ThemBones
       */
      sendto_realops("BAD HOSTNAME: %s[%s@%s] on %s (from %s)",
                     parv[0], parv[5], parv[6], parv[7], parv[0]);
   }
        
   strncpyzt(nick, parv[1], NICKLEN + 1);
   /*
    * if do_nick_name() returns a null name OR if the server sent a
    * nick name and do_nick_name() changed it in some way (due to rules
    * of nick creation) then reject it. If from a server and we reject
    * it, and KILL it. -avalon 4/4/92
    */
   if (do_nick_name(nick) == 0 || (IsServer(cptr) && strcmp(nick, parv[1])))
   {
      sendto_one(sptr, err_str(ERR_ERRONEUSNICKNAME),
                          me.name, parv[0], parv[1]);
                
      if (IsServer(cptr))
      {
        ircstp->is_kill++;
        sendto_realops_lev(DEBUG_LEV, "Bad Nick: %s From: %s %s",
                            parv[1], parv[0],
                            get_client_name(cptr, FALSE));
        sendto_one(cptr, ":%s KILL %s :%s (%s <- %s[%s])",
                            me.name, parv[1], me.name, parv[1],
                            nick, cptr->name);
        if (sptr != cptr) /* bad nick change */
        {     
          sendto_serv_butone(cptr,
                              ":%s KILL %s :%s (%s <- %s!%s@%s)",
                              me.name, parv[0], me.name,
                              get_client_name(cptr, FALSE),
                              parv[0],
                              sptr->user ? sptr->username : "",
                              sptr->user ? sptr->user->server :
                              cptr->name);
          sptr->flags |= FLAGS_KILLED;
          return exit_client(cptr, sptr, &me, "BadNick");
        }
      }
      return 0;
   }
   /*
    * * Check against nick name collisions. *
    * 
    * Put this 'if' here so that the nesting goes nicely on the screen
    * :) * We check against server name list before determining if the
    * nickname * is present in the nicklist (due to the way the below
    * for loop is * constructed). -avalon
    */
   do {

   if ((acptr = find_server(nick, NULL)))
          if (MyConnect(sptr))
          {
             sendto_one(sptr, err_str(ERR_NICKNAMEINUSE), me.name,
                        BadPtr(parv[0]) ? "*" : parv[0], nick);
             return 0;
          }
        
   /* 
    * acptr already has result from find_server
    * Well. unless we have a capricious server on the net, a nick can
    * never be the same as a server name - Dianora
    * That's not the only case; maybe someone broke do_nick_name
    * or changed it so they could use "." in nicks on their network - sedition
    */

   if (acptr)
   {
      /*
       * * We have a nickname trying to use the same name as * a
       * server. Send out a nick collision KILL to remove * the
       * nickname. As long as only a KILL is sent out, * there is no
       * danger of the server being disconnected. * Ultimate way to
       * jupiter a nick ? >;-). -avalon
       */
      sendto_ops_lev(SKILL_LEV, "Nick collision on %s(%s <- %s)",
                 sptr->name, acptr->from->name,
                 get_client_name(cptr, FALSE));
      ircstp->is_kill++;
      sendto_one(cptr, ":%s KILL %s :%s (%s <- %s)",
                 me.name, sptr->name, me.name, acptr->from->name,
                 get_client_name(cptr, FALSE));
      sptr->flags |= FLAGS_KILLED;
      return exit_client(cptr, sptr, &me, "Nick/Server collision");
   }

   if (!(acptr = find_client(nick, NULL)))
     break;

   /*
    * * If acptr == sptr, then we have a client doing a nick * change
    * between *equivalent* nicknames as far as server * is concerned
    * (user is changing the case of his/her * nickname or somesuch)
    */
   if (acptr == sptr)
   {
      if (strcmp(acptr->name, nick) != 0)
        break;
      else
         /*
          * * This is just ':old NICK old' type thing. * Just forget
          * the whole thing here. There is * no point forwarding it to
          * anywhere, * especially since servers prior to this *
          * version would treat it as nick collision.
          */
        return 0;
   }

   /*
    * * Note: From this point forward it can be assumed that * acptr !=
    * sptr (point to different client structures).
    */
   /*
    * * If the older one is "non-person", the new entry is just *
    * allowed to overwrite it. Just silently drop non-person, * and
    * proceed with the nick. This should take care of the * "dormant
    * nick" way of generating collisions...
    */
   if (IsUnknown(acptr))
   {
      if (MyConnect(acptr))
      {
         exit_client(NULL, acptr, &me, "Overridden");
         break;
      }
      else if (!(acptr->user))
      {
         sendto_ops_lev(SKILL_LEV,
                "Nick Collision on %s(%s(NOUSER) <- %s!%s@%s)(TS:%s)",
                acptr->name, acptr->from->name, parv[1], parv[5], parv[6],
                cptr->name);
         sendto_serv_butone(NULL,
                ":%s KILL %s :%s (%s(NOUSER) <- %s!%s@%s)(TS:%s)", me.name,
                acptr->name, me.name, acptr->from->name, parv[1], parv[5],
                parv[6], cptr->name);
         acptr->flags |= FLAGS_KILLED;

         /* Having no USER struct should be ok... */
         return exit_client(cptr, acptr, &me,
                "Got TS NICK before Non-TS USER");
      }
   }

   if (!IsServer(cptr))
   {
      /*
       * * NICK is coming from local client connection. Just * send
       * error reply and ignore the command.
       * parv[0] is empty on connecting clients
       */
      sendto_one(sptr, err_str(ERR_NICKNAMEINUSE),
                 me.name, BadPtr(parv[0]) ? "*" : parv[0], nick);
      return 0;
   }
   /*
    * * NICK was coming from a server connection. Means that the same *
    * nick is registered for different users by different server. *
    * This is either a race condition (two users coming online about *
    * same time, or net reconnecting) or just two net fragments
    * becoming * joined and having same nicks in use. We cannot have
    * TWO users with * same nick--purge this NICK from the system with
    * a KILL... >;)
    */
   /*
    * * Changed to something reasonable like IsServer(sptr) * (true if
    * "NICK new", false if ":old NICK new") -orabidoo
    */

   if (IsServer(sptr))
   {
      /*
       * * A new NICK being introduced by a neighbouring * server (e.g.
       * message type "NICK new" received)
       */
      if (!newts || !acptr->tsinfo
          || (newts == acptr->tsinfo))
      {

         sendto_ops_lev(SKILL_LEV, "Nick collision on %s(%s <- %s)(both killed)",
                    acptr->name, acptr->from->name,
                    get_client_name(cptr, FALSE));
         ircstp->is_kill++;
         sendto_one(acptr, err_str(ERR_NICKCOLLISION),
                    me.name, acptr->name, acptr->name);
         sendto_serv_butone(NULL, ":%s KILL %s :%s (%s <- %s)",
                    me.name, acptr->name, me.name,
                    acptr->from->name,
                    get_client_name(cptr, FALSE));
         acptr->flags |= FLAGS_KILLED;
         return exit_client(cptr, acptr, &me, "Nick collision");
      }
      else
      {
         sameuser = (acptr->user) &&
            mycmp(acptr->user->username, parv[5]) == 0 &&
            mycmp(acptr->user->host, parv[6]) == 0;
         if ((sameuser && newts < acptr->tsinfo) ||
             (!sameuser && newts > acptr->tsinfo))
            return 0;
         else
         {
            if (sameuser)
               sendto_ops_lev(SKILL_LEV,
                          "Nick collision on %s(%s <- %s)(older killed)",
                          acptr->name, acptr->from->name,
                          get_client_name(cptr, FALSE));
            else
               sendto_ops_lev(SKILL_LEV,
                          "Nick collision on %s(%s <- %s)(newer killed)",
                          acptr->name, acptr->from->name,
                          get_client_name(cptr, FALSE));

            ircstp->is_kill++;
            sendto_one(acptr, err_str(ERR_NICKCOLLISION),
                       me.name, acptr->name, acptr->name);
            sendto_serv_butone(sptr,
                       ":%s KILL %s :%s (%s <- %s)",
                       me.name, acptr->name, me.name,
                       acptr->from->name,
                       get_client_name(cptr, FALSE));
            acptr->flags |= FLAGS_KILLED;
            (void) exit_client(cptr, acptr, &me, "Nick collision");
            break;
         }
      }
   }
   /*
    * * A NICK change has collided (e.g. message type * ":old NICK
    * new". This requires more complex cleanout. * Both clients must be
    * purged from this server, the "new" * must be killed from the
    * incoming connection, and "old" must * be purged from all outgoing
    * connections.
    */
   if (!newts || !acptr->tsinfo || (newts == acptr->tsinfo) ||
       !sptr->user)
   {
      sendto_ops_lev(SKILL_LEV,
                 "Nick change collision from %s to %s(%s <- %s)(both killed)",
                 sptr->name, acptr->name, acptr->from->name,
                 get_client_name(cptr, FALSE));
      ircstp->is_kill++;
      sendto_one(acptr, err_str(ERR_NICKCOLLISION),
                 me.name, acptr->name, acptr->name);
      sendto_serv_butone(NULL,
                 ":%s KILL %s :%s (%s(%s) <- %s)",
                 me.name, sptr->name, me.name, acptr->from->name,
                 acptr->name, get_client_name(cptr, FALSE));
      ircstp->is_kill++;
      sendto_serv_butone(NULL,
                 ":%s KILL %s :%s (%s <- %s(%s))",
                 me.name, acptr->name, me.name, acptr->from->name,
                 get_client_name(cptr, FALSE), sptr->name);
      acptr->flags |= FLAGS_KILLED;
      (void) exit_client(NULL, acptr, &me, "Nick collision(new)");
      sptr->flags |= FLAGS_KILLED;
      return exit_client(cptr, sptr, &me, "Nick collision(old)");
   }
   else
   {
      sameuser = mycmp(acptr->user->username,
                       sptr->user->username) == 0 &&
         mycmp(acptr->user->host, sptr->user->host) == 0;
      if ((sameuser && newts < acptr->tsinfo) ||
          (!sameuser && newts > acptr->tsinfo))
      {
         if (sameuser)
            sendto_ops_lev(SKILL_LEV,
                       "Nick change collision from %s to %s(%s <- %s)(older killed)",
                       sptr->name, acptr->name, acptr->from->name,
                       get_client_name(cptr, FALSE));
         else
            sendto_ops_lev(SKILL_LEV,
                       "Nick change collision from %s to %s(%s <- %s)(newer killed)",
                       sptr->name, acptr->name, acptr->from->name,
                       get_client_name(cptr, FALSE));
         ircstp->is_kill++;
         sendto_serv_butone(cptr,
                       ":%s KILL %s :%s (%s(%s) <- %s)",
                       me.name, sptr->name, me.name, acptr->from->name,
                       acptr->name, get_client_name(cptr, FALSE));
         sptr->flags |= FLAGS_KILLED;
         if (sameuser)
            return exit_client(cptr, sptr, &me, "Nick collision(old)");
         else
            return exit_client(cptr, sptr, &me, "Nick collision(new)");
      }
      else
      {
         if (sameuser)
            sendto_ops_lev(SKILL_LEV,
                       "Nick collision on %s(%s <- %s)(older killed)",
                       acptr->name, acptr->from->name,
                       get_client_name(cptr, FALSE));
         else
            sendto_ops_lev(SKILL_LEV,
                       "Nick collision on %s(%s <- %s)(newer killed)",
                       acptr->name, acptr->from->name,
                       get_client_name(cptr, FALSE));

         ircstp->is_kill++;
         sendto_one(acptr, err_str(ERR_NICKCOLLISION),
                       me.name, acptr->name, acptr->name);
         sendto_serv_butone(sptr,
                       ":%s KILL %s :%s (%s <- %s)",
                       me.name, acptr->name, me.name,
                       acptr->from->name,
                       get_client_name(cptr, FALSE));
         acptr->flags |= FLAGS_KILLED;
         (void) exit_client(cptr, acptr, &me, "Nick collision");
      }
   }
   } while (0);

   if (IsServer(sptr))
   {
      uplink = find_server(parv[7], NULL);
      if(!uplink)
      {
         /* if we can't find the server this nick is on, complain loudly and ignore it. - lucas */
         sendto_realops("Remote nick %s on UNKNOWN server %s\n", nick, parv[7]);
         return 0;
      }
      sptr = make_client(cptr, uplink);

      /* If this is on a U: lined server, it's a U: lined client. */
      if(IsULine(uplink))
         sptr->flags|=FLAGS_ULINE;
                
      add_client_to_list(sptr);
      if (parc > 2)
         sptr->hopcount = atoi(parv[2]);
      if (newts)
         sptr->tsinfo = newts;
      else
      {
         newts = sptr->tsinfo = (ts_val) timeofday;
         ts_warn("Remote nick %s introduced without a TS", nick);
      }
      /*
       * copy the nick in place 
       */
      (void) strcpy(sptr->name, nick);
      (void) add_to_client_hash_table(nick, sptr);
      if (parc == 10)
      {
         int    *s, flag;
         char   *m;
                        
         /* parse the usermodes -orabidoo */
         m = &parv[4][1];
         while (*m)
         {
            for (s = user_modes; (flag = *s); s += 2)
               if (*m == *(s + 1))
               {
                  if ((flag == UMODE_o) || (flag == UMODE_O))
                     Count.oper++;
                  sptr->umode |= flag & SEND_UMODES;
                  break;
               }
            m++;
         }
                                
         return do_user(nick, cptr, sptr, parv[5], parv[6],
                        parv[7], strtoul(parv[8], NULL, 0), parv[9]);
      }
   }
   else if (sptr->name[0])
   {
      /*
       * * Client just changing his/her nick. If he/she is * on a
       * channel, send note of change to all clients * on that channel.
       * Propagate notice to other servers.
       */
#ifdef DONT_CHECK_QLINE_REMOTE
      if (MyConnect(sptr)) {
#endif
         if ((aconf = find_conf_name(nick, CONF_QUARANTINED_NICK)))
         {
#ifndef DONT_CHECK_QLINE_REMOTE
           if (!MyConnect(sptr))
               sendto_realops("Q:lined nick %s from %s on %s", nick,
                          (*sptr->name != 0 && !IsServer(sptr)) ?
			  sptr->name : "<unregistered>",
                          (sptr->user == NULL) ? ((IsServer(sptr)) ?
			  parv[6] : me.name) : sptr->user->server);
#endif
                                
            if (MyConnect(sptr) && (!IsServer(cptr)) && (!IsOper(cptr))
                && (!IsULine(sptr)))
            {
               sendto_one(sptr, err_str(ERR_ERRONEUSNICKNAME), me.name,
                           BadPtr(parv[0]) ? "*" : parv[0], nick,
                           BadPtr(aconf->passwd) ? "reason unspecified" :
                           aconf->passwd);
               sendto_realops("Forbidding Q:lined nick %s from %s.",
                              nick, get_client_name(cptr, FALSE));
               return 0;
            }
         }
#ifdef DONT_CHECK_QLINE_REMOTE
      }
#endif
      /*
       * if the nickname is different, set the TS
       * AND set it -r. No need to propogate MODE -r and spam
       * the network on registered nick changes. yuck. - lucas
       */
      
       if (mycmp(parv[0], nick))
       {
          sptr->tsinfo = newts ? newts : (ts_val) timeofday;
          sptr->umode&=~UMODE_r;
       }

       if (MyConnect(sptr))
       {
          if (IsRegisteredUser(sptr)) {

	       /* before we change their nick, make sure they're not banned
		* on any channels, and!! make sure they're not changing to
		* a banned nick -sed */
               /* a little cleaner - lucas */

 	        for (lp = sptr->user->channel; lp; lp = lp->next) 
                {
                  if (can_send(sptr, lp->value.chptr)) 
		  { 
		    sendto_one(sptr, err_str(ERR_BANNICKCHANGE), me.name,
			       sptr->name, lp->value.chptr->chname);
		    return 0;
		  }
		  if (nick_is_banned(lp->value.chptr, nick, sptr) != NULL) 
		  {
		    sendto_one(sptr, err_str(ERR_BANONCHAN), me.name,
			       sptr->name, nick, lp->value.chptr->chname);
		    return 0;
		  }
		}
			       

#ifdef ANTI_NICK_FLOOD
             if ((sptr->last_nick_change + MAX_NICK_TIME) < NOW)
                sptr->number_of_nick_changes = 0;
             sptr->last_nick_change = NOW;
             sptr->number_of_nick_changes++;
                                
             if (sptr->number_of_nick_changes <= MAX_NICK_CHANGES || IsAnOper(sptr))
             {
#endif
                sendto_common_channels(sptr, ":%s NICK :%s", parv[0], nick);
                if (sptr->user)
                {
                   add_history(sptr, 1);

                   sendto_serv_butone(cptr, ":%s NICK %s :%ld",
                                 parv[0], nick, sptr->tsinfo);
                }
#ifdef ANTI_NICK_FLOOD
             }
             else
             {
                sendto_one(sptr,
                           ":%s NOTICE %s :*** Notice -- Too many nick changes. Wait %d seconds before trying again.",
                           me.name, sptr->name, MAX_NICK_TIME);
                return 0;
             }
#endif
          }
       }
       else {
          sendto_common_channels(sptr, ":%s NICK :%s", parv[0], nick);
          if (sptr->user)
          {
             add_history(sptr, 1);
                                
             sendto_serv_butone(cptr, ":%s NICK %s :%ld",
                           parv[0], nick, sptr->tsinfo);
          }
       }
   }
   else
   {
      /*
       * Client setting NICK the first time 
       */
      if (MyConnect(sptr))
      {
         if ((aconf = find_conf_name(nick, CONF_QUARANTINED_NICK)))
         {
	    /* No need to spam with two notices - lucas
            sendto_realops("Q:lined nick %s from %s on %s", nick,
                           "<unregistered>", me.name);
	    */
                                
            if (MyConnect(sptr) && (!IsServer(cptr)) && (!IsOper(cptr))
                && (!IsULine(sptr)))
            {
               sendto_one(sptr, err_str(ERR_ERRONEUSNICKNAME), me.name,
                          BadPtr(parv[0]) ? "*" : parv[0], nick,
                          BadPtr(aconf->passwd) ? "reason unspecified" :
                          aconf->passwd);
               sendto_realops("Forbidding Q:lined nick %s from <unregistered>%s.",
                              nick, get_client_name(cptr, FALSE));
               return 0;
            }
         }
      }

      (void) strcpy(sptr->name, nick);
      sptr->tsinfo = timeofday;
      if (sptr->user)
      {
         /*
          * USER already received, now we have NICK. * *NOTE* For
          * servers "NICK" *must* precede the * user message (giving
          * USER before NICK is possible * only for local client
          * connection!). register_user * may reject the client and
          * call exit_client for it * --must test this and exit m_nick
          * too!!!
          */

          if (register_user(cptr, sptr, nick, sptr->user->username)
              == FLUSH_BUFFER)
             return FLUSH_BUFFER;
      }
   }
   /*
    * *  Finally set new nick name.
    */

   if (sptr->name[0])
   {
      (void) del_from_client_hash_table(sptr->name, sptr);
      samenick = mycmp(sptr->name, nick) ? 0 : 1;
      if (IsPerson(sptr) && !samenick)
         hash_check_watch(sptr, RPL_LOGOFF);
   }
   (void) strcpy(sptr->name, nick);
   (void) add_to_client_hash_table(nick, sptr);
   if (IsPerson(sptr) && !samenick)
      hash_check_watch(sptr, RPL_LOGON);
   return 0;

}

/*
 * Code provided by orabidoo 
 */
/*
 * a random number generator loosely based on RC5; assumes ints are at
 * least 32 bit
 */

unsigned long
my_rand()
{
static unsigned long s = 0, t = 0, k = 12345678;
int         i;

   if (s == 0 && t == 0) {
      s = (unsigned long) getpid();
      t = (unsigned long) time(NULL);
   }
   for (i = 0; i < 12; i++) {
      s = (((s ^ t) << (t & 31)) | ((s ^ t) >> (31 - (t & 31)))) + k;
      k += s + t;
      t = (((t ^ s) << (s & 31)) | ((t ^ s) >> (31 - (s & 31)))) + k;
      k += s + t;
   }
   return s;
}

char *exploits_2char[] = { "js", "pl", NULL };
char *exploits_3char[] = { "exe", "com", "bat", "dll", "ini", "vbs", "pif", "mrc", "scr", "doc", "xls", "lnk", "shs", NULL };

int check_dccsend(aClient *from, aClient *to, char *msg)
{
   /* we already know that msg will consist of "DCC SEND" so we can skip to the end */
   char *filename = msg + 8;
   char *ext;
   char **farray;
   int arraysz;
   int len = 0, extlen = 0, i;

   /* people can send themselves stuff all the like..
    * opers need to be able to send cleaner files 
    * sanity checks..
    */

   if(from == to || !IsPerson(from) || IsAnOper(from) || !MyClient(to)) 
      return 0;

   while(*filename == ' ')
      filename++;

   if(!(*filename)) return 0;

   while(*(filename + len) != ' ')
   {
      if(!(*(filename + len))) break;
      len++;
   }

   for(ext = filename + len;; ext--)
   {
      if(ext == filename)
          return 0;

      if(*ext == '.') 
      {
         ext++;
         extlen--;
         break;
      }
      extlen++;
   }

   switch(extlen)
   {
      case 2:
         farray = exploits_2char;
         arraysz = 2;
         break;

      case 3:
         farray = exploits_3char;
         arraysz = 3;
         break;

      /* no executable file here.. */
      default:
         return 0;
   }

   for(i = 0; farray[i]; i++)
   {
      if(myncmp(farray[i], ext, arraysz) == 0)
         break;
   }

   if(farray[i] == NULL)
      return 0;

   if(!allow_dcc(to, from))
   {
      char tmpext[8];
      char tmpfn[128];
      Link *tlp, *flp;
      aChannel *chptr = NULL;

      strncpy(tmpext, ext, extlen);
      tmpext[extlen] = '\0';

      if(len > 127) 
         len = 127;
      strncpy(tmpfn, filename, len);
      tmpfn[len] = '\0';

      /* use notices! 
       *   server notices are hard to script around.
       *   server notices are not ignored by clients.
       */ 

      sendto_one(from, ":%s NOTICE %s :The user %s is not accepting DCC sends of filetype *.%s from you."
                       " Your file %s was not sent.",
         me.name, from->name, to->name, tmpext, tmpfn);

      sendto_one(to, ":%s NOTICE %s :%s (%s@%s) has attempted to send you a file named %s, which was blocked.",
         me.name, to->name, from->name, from->user->username, from->user->host, tmpfn);

      if(!SeenDCCNotice(to))
      {
         SetDCCNotice(to);
 
         sendto_one(to, ":%s NOTICE %s :The majority of files sent of this type are malicious virii and trojan horses."
                        " In order to prevent the spread of this problem, we are blocking DCC sends of these types of"
                        " files by default.", me.name, to->name);
         sendto_one(to, ":%s NOTICE %s :If you trust %s, and want him/her to send you this file, you may obtain"
                        " more information on using the dccallow system by typing /dccallow help",
                        me.name, to->name, from->name, to->name);
      }

      for(tlp = to->user->channel; tlp && !chptr; tlp = tlp->next)
      {
         for(flp = from->user->channel; flp && !chptr; flp = flp->next)
         {
            if(tlp->value.chptr == flp->value.chptr)
               chptr = tlp->value.chptr;
         }
      }
      
      if(chptr)
         sendto_realops_lev(DCCSEND_LEV, "%s (%s@%s) sending forbidden filetyped file %s to %s (channel %s)", from->name, 
            from->user->username, from->user->host, tmpfn, to->name, chptr->chname); 
      else
         sendto_realops_lev(DCCSEND_LEV, "%s (%s@%s) sending forbidden filetyped file %s to %s", from->name, 
            from->user->username, from->user->host, tmpfn, to->name); 

      return 1;
   }

   return 0;
}

/* check to see if the message has any color chars in it. */
int msg_has_colors(char *msg)
{
   char *c = msg;

   while(*c)
   {
      if(*c == '\003' || *c == '\033')
         break;
      else
         c++;
   }

   if(*c)
      return 1;

   return 0;
}

/*
 * m_message (used in m_private() and m_notice()) the general
 * function to deliver MSG's between users/channels
 * 
 * parv[0] = sender prefix
 * parv[1] = receiver list
 * parv[2] = message text
 * 
 * massive cleanup * rev argv 6/91
 * 
 */

static inline int m_message(aClient *cptr, aClient *sptr, int parc, char *parv[], int notice)
{
   aClient *acptr;
   char *s;
   int i, ret, ischan;
   aChannel *chptr;
   char *nick, *server, *p, *cmd, *dccmsg;

   cmd = notice ? MSG_NOTICE : MSG_PRIVATE;

   if (parc < 2 || *parv[1] == '\0') 
   {
      sendto_one(sptr, err_str(ERR_NORECIPIENT),
		 me.name, parv[0], cmd);
      return -1;
   }

   if (parc < 3 || *parv[2] == '\0') 
   {
      sendto_one(sptr, err_str(ERR_NOTEXTTOSEND), me.name, parv[0]);
      return -1;
   }

   if (MyConnect(sptr)) 
   {
#ifdef ANTI_SPAMBOT
#ifndef ANTI_SPAMBOT_WARN_ONLY
      /*
       * if its a spambot, just ignore it 
       */
      if (sptr->join_leave_count >= MAX_JOIN_LEAVE_COUNT)
	 return 0;
#endif
#endif
      parv[1] = canonize(parv[1]);
   }

   for (p = NULL, nick = strtoken(&p, parv[1], ","), i = 0; nick && i<20 ;
		  nick = strtoken(&p, NULL, ",")) 
   {
      /*
       * If someone is spamming via "/msg nick1,nick2,nick3,nick4 SPAM"
       * (or even to channels) then subject them to flood control!
       * -Taner
       */
      if (i++ > 10)
#ifdef NO_OPER_FLOOD
         if (!IsAnOper(sptr) && !IsULine(sptr))	
#endif
            sptr->since += 4;		

      /*
       * channel msg?
       */
      ischan = IsChannelName(nick);
      if (ischan && (chptr=find_channel(nick,NullChn))) 
      {
         if (!notice)
            switch(check_for_ctcp(parv[2], NULL))
            {
               case CTCP_NONE:
                  break;

               case CTCP_DCCSEND:
               case CTCP_DCC:
                  sendto_one(sptr, "%s NOTICE %s :You may not send a DCC command to a channel (%s)", me.name, parv[0], nick);
                  continue;

               default:
#ifdef FLUD
                  if (check_for_flud(sptr, NULL, chptr, 1))
                     return 0;
#endif
                  break;
            }
         ret = IsULine(sptr) ? 0 : can_send(sptr, chptr);
         if(!ret && MyClient(sptr) && (chptr->mode.mode & MODE_NOCOLOR) && msg_has_colors(parv[2]))
         {
            if(!notice)
               sendto_one(sptr, err_str(ERR_NOCOLORSONCHAN), me.name, parv[0], nick, parv[2]);
               continue;
         }

         if(ret)
         {
            if(!notice)
               sendto_one(sptr, err_str(ERR_CANNOTSENDTOCHAN), me.name, parv[0], nick);
         }
         else
            sendto_channel_butone(cptr, sptr, chptr, ":%s %s %s :%s", parv[0], cmd, nick, parv[2]);
         continue;
      }

      /*
       * nickname addressed?
       */
      if (!ischan && (acptr = find_person(nick, NULL))) 
      {
#ifdef FLUD
         if (!notice && MyFludConnect(acptr))
#else
         if (!notice && MyConnect(acptr))
#endif
         {

            switch(check_for_ctcp(parv[2], &dccmsg))
            {
               case CTCP_NONE:
                  break;

               case CTCP_DCCSEND:
#ifdef FLUD
                  if (check_for_flud(sptr, acptr, NULL, 1))
                     return 0;
#endif

                  if(check_dccsend(sptr, acptr, dccmsg))
                     continue;
                  break;
                
               default:
#ifdef FLUD
                  if (check_for_flud(sptr, acptr, NULL, 1))
                     return 0;
#endif
                  break;
            }
         }

         if (!is_silenced(sptr, acptr)) 
         {				 
            if (!notice && MyClient(acptr) && acptr->user && acptr->user->away)
               sendto_one(sptr, rpl_str(RPL_AWAY), me.name, parv[0], acptr->name, acptr->user->away);
            sendto_prefix_one(acptr, sptr, ":%s %s %s :%s", parv[0], cmd, nick, parv[2]);
         }
         continue;
      }

      if (nick[1] == '#' && nick[0]!='#') 
      {
         if (nick[0] == '@') 
         {
            if ((chptr = find_channel(nick + 1, NullChn))) 
            {
               if (can_send(sptr, chptr) == 0 || IsULine(sptr))
                  sendto_channelops_butone(cptr, sptr, chptr, ":%s %s %s :%s", parv[0], cmd, nick, parv[2]);
               else if (!notice)
                  sendto_one(sptr, err_str(ERR_CANNOTSENDTOCHAN), me.name, parv[0], nick + 1);
            }
         }
         else if (nick[0] == '+') 
         {
            if ((chptr = find_channel(nick + 1, NullChn))) 
            {
               if (IsULine(sptr) || can_send(sptr, chptr) == 0)
                  sendto_channelvoice_butone(cptr, sptr, chptr, ":%s %s %s :%s", parv[0], cmd, nick, parv[2]);
               else if (!notice)
                  sendto_one(sptr, err_str(ERR_CANNOTSENDTOCHAN), me.name, parv[0], nick + 1);
            }
         }
         else
            sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name, parv[0], nick + 1);

         continue;
      }

      if (nick[0] == '@' && nick[1] == '+' && nick[2] == '#') 
      {
         if ((chptr = find_channel(nick + 2, NullChn))) 
         {
            if (IsULine(sptr) || can_send(sptr, chptr) == 0)
               sendto_channelvoiceops_butone(cptr, sptr, chptr, ":%s %s %s :%s", parv[0], cmd, nick, parv[2]);
            else if (!notice)
               sendto_one(sptr, err_str(ERR_CANNOTSENDTOCHAN), me.name, parv[0], nick + 1);
         }
         else
            sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name, parv[0], nick + 1);
         continue;
      }
		
      if(IsAnOper(sptr)) 
      {
         /*
          * the following two cases allow masks in NOTICEs
          * (for OPERs only) 
          * 
          * Armin, 8Jun90 (gruner@informatik.tu-muenchen.de)
          */
         if ((*nick == '$' || *nick == '#')) 
         {
            if (!(s = (char *) strrchr(nick, '.'))) 
            {
               sendto_one(sptr, err_str(ERR_NOTOPLEVEL), me.name, parv[0], nick);
               continue;
            }
            while (*++s)
               if (*s == '.' || *s == '*' || *s == '?')
                  break;
            if (*s == '*' || *s == '?') 
            {
               sendto_one(sptr, err_str(ERR_WILDTOPLEVEL), me.name, parv[0], nick);
               continue;
            }
            sendto_match_butone(IsServer(cptr) ? cptr : NULL, sptr, nick + 1, 
                                (*nick == '#') ? MATCH_HOST : MATCH_SERVER, ":%s %s %s :%s", parv[0],
                                cmd, nick, parv[2]);
            continue;
         }
      }
			
      /*
       * user@server addressed?
       */
      if (!ischan && (server = (char *) strchr(nick, '@')) && (acptr = find_server(server + 1, NULL))) 
      {
         int count = 0;
			
         /* Not destined for a user on me :-( */
         if (!IsMe(acptr)) 
         {
            sendto_one(acptr, ":%s %s %s :%s", parv[0], cmd, nick, parv[2]);
            continue;
         }
         *server = '\0';
			
         /*
          * Look for users which match the destination host 
          * (no host == wildcard) and if one and one only is found
          * connected to me, deliver message!
          */
         acptr = find_person(nick, NULL);
         if (server)
            *server = '@';
         if (acptr) 
         {
            if (count == 1)
               sendto_prefix_one(acptr, sptr, ":%s %s %s :%s", parv[0], cmd, nick, parv[2]);
            else if (!notice)
               sendto_one(sptr, err_str(ERR_TOOMANYTARGETS), me.name, parv[0], nick);
         }
         if (acptr)
            continue;
      }
      sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name, parv[0], nick);
   }
   if ((i > 20) && sptr->user)
      sendto_realops_lev(SPY_LEV, "User %s (%s@%s) tried to msg %d users",
                         sptr->name, sptr->user->username, sptr->user->host, i);
   return 0;
}
/*
 * * m_private *      parv[0] = sender prefix *       parv[1] =
 * receiver list *      parv[2] = message text
 */

int
m_private(aClient *cptr,
	  aClient *sptr,
	  int parc,
	  char *parv[])
{
   return m_message(cptr, sptr, parc, parv, 0);
}
/*
 * the services aliases. *
 * 
 * NICKSERV     - /nickserv * CHANSERV  - /chanserv * OPERSERV  -
 * /operserv * MEMOSERV         - /memoserv * SERVICES  - /services *
 * IDENTIFY     - /identify * taz's code -mjs
 */

int
m_chanserv(cptr, sptr, parc, parv)
     aClient    *cptr, *sptr;
     int         parc;
     char       *parv[];
{
aClient    *acptr;

   if (check_registered_user(sptr))
      return 0;
   if (parc < 2 || *parv[1] == '\0') {
      sendto_one(sptr, err_str(ERR_NOTEXTTOSEND), me.name, parv[0]);
      return -1;
   }
   if ((acptr = find_person(ChanServ, NULL)))
      sendto_one(acptr, ":%s PRIVMSG %s@%s :%s", parv[0],
		 ChanServ, SERVICES_NAME, parv[1]);
   else
      sendto_one(sptr, err_str(ERR_SERVICESDOWN), me.name,
		 parv[0], ChanServ);
   return 0;
}
/*
 * m_nickserv 
 */
int
m_nickserv(cptr, sptr, parc, parv)
     aClient    *cptr, *sptr;
     int         parc;
     char       *parv[];
{
aClient    *acptr;

   if (check_registered_user(sptr))
      return 0;
   if (parc < 2 || *parv[1] == '\0') {
      sendto_one(sptr, err_str(ERR_NOTEXTTOSEND), me.name, parv[0]);
      return -1;
   }
   if ((acptr = find_person(NickServ, NULL)))
      sendto_one(acptr, ":%s PRIVMSG %s@%s :%s", parv[0],
		 NickServ, SERVICES_NAME, parv[1]);
   else
      sendto_one(sptr, err_str(ERR_SERVICESDOWN), me.name,
		 parv[0], NickServ);
   return 0;
}
/*
 * m_memoserv 
 */
int
m_memoserv(cptr, sptr, parc, parv)
     aClient    *cptr, *sptr;
     int         parc;
     char       *parv[];
{
aClient    *acptr;

   if (check_registered_user(sptr))
      return 0;
   if (parc < 2 || *parv[1] == '\0') {
      sendto_one(sptr, err_str(ERR_NOTEXTTOSEND), me.name, parv[0]);
      return -1;
   }
   if ((acptr = find_person(MemoServ, NULL)))
      sendto_one(acptr, ":%s PRIVMSG %s@%s :%s", parv[0],
		 MemoServ, SERVICES_NAME, parv[1]);
   else
      sendto_one(sptr, err_str(ERR_SERVICESDOWN), me.name,
		 parv[0], MemoServ);
   return 0;
}
/*
 * m_operserv 
 */
int
m_operserv(cptr, sptr, parc, parv)
     aClient    *cptr, *sptr;
     int         parc;
     char       *parv[];
{
aClient    *acptr;

   if (check_registered_user(sptr))
      return 0;
   if (parc < 2 || *parv[1] == '\0') {
      sendto_one(sptr, err_str(ERR_NOTEXTTOSEND), me.name, parv[0]);
      return -1;
   }
   if ((acptr = find_person(OperServ, NULL)))
      sendto_one(acptr, ":%s PRIVMSG %s@%s :%s", parv[0],
		OperServ,
#ifdef OPERSERV_OTHER_HOST
		OPERSERV_OTHER_HOST,
#else 
		SERVICES_NAME,
#endif
		parv[1]);

   else
      sendto_one(sptr, err_str(ERR_SERVICESDOWN), me.name,
		 parv[0], OperServ);
   return 0;
}
/*
 * m_statserv 
 */
int
m_statserv(cptr, sptr, parc, parv)
     aClient    *cptr, *sptr;
     int         parc;
     char       *parv[];
{
aClient    *acptr;

   if (check_registered_user(sptr))
      return 0;
   if (parc < 2 || *parv[1] == '\0') {
      sendto_one(sptr, err_str(ERR_NOTEXTTOSEND), me.name, parv[0]);
      return -1;
   }
   if ((acptr = find_person(StatServ, NULL)))
      sendto_one(acptr, ":%s PRIVMSG %s@%s :%s", parv[0],
		StatServ,
#ifdef OPERSERV_OTHER_HOST
		OPERSERV_OTHER_HOST,
#else 
		SERVICES_NAME,
#endif
		parv[1]);

   else
      sendto_one(sptr, err_str(ERR_SERVICESDOWN), me.name,
		 parv[0], OperServ);
   return 0;
}
/*
 * m_services -- see df465+taz 
 */
int
m_services(cptr, sptr, parc, parv)
     aClient    *cptr, *sptr;
     int         parc;
     char       *parv[];
{
char       *tmps;

   if (check_registered_user(sptr))
      return 0;

   if (parc < 2 || *parv[1] == '\0') {
      sendto_one(sptr, err_str(ERR_NOTEXTTOSEND), me.name, parv[0]);
      return -1;
   }
   if ((strlen(parv[1]) >= 4) && (!myncmp(parv[1], "help", 4))) {
      sendto_one(sptr, ":services!service@%s NOTICE %s :For ChanServ "
		 "help use: /chanserv help", SERVICES_NAME,
		 sptr->name);
      sendto_one(sptr, ":services!service@%s NOTICE %s :For NickServ "
		 "help use: /nickserv help", SERVICES_NAME,
		 sptr->name);
      sendto_one(sptr, ":services!service@%s NOTICE %s :For MemoServ "
		 "help use: /memoserv help", SERVICES_NAME,
		 sptr->name);
      return 0;
   }
   if ((tmps = (char *) strchr(parv[1], ' '))) {
      for(; *tmps == ' '; tmps++); /* er.. before this for loop, the next 
                * comparison would always compare '#' with ' '.. oops. - lucas
		*/
      if (*tmps == '#')
	 return m_chanserv(cptr, sptr, parc, parv);
      else
	 return m_nickserv(cptr, sptr, parc, parv);
   }
   return m_nickserv(cptr, sptr, parc, parv);
}

/*
 * m_identify  df465+taz 
 */
int
m_identify(cptr, sptr, parc, parv)
     aClient    *cptr, *sptr;
     int         parc;
     char       *parv[];
{
aClient    *acptr;

   if (check_registered_user(sptr))
      return 0;

   if (parc < 2 || *parv[1] == '\0') {
      sendto_one(sptr, err_str(ERR_NOTEXTTOSEND), me.name, parv[0]);
      return -1;
   }
   if (*parv[1]) {
      if ((*parv[1] == '#') && ((char *) strchr(parv[1], ' '))) {
	 if ((acptr = find_person(ChanServ, NULL)))
	    sendto_one(acptr, ":%s PRIVMSG %s@%s :IDENTIFY %s "
		       ,parv[0], ChanServ,
		       SERVICES_NAME, parv[1]);
	 else
	    sendto_one(sptr, err_str(ERR_SERVICESDOWN), me.name, parv[0], ChanServ);
      }
      else {
	 if ((acptr = find_person(NickServ, NULL)))
	    sendto_one(acptr, ":%s PRIVMSG %s@%s :IDENTIFY %s", parv[0],
		       NickServ, SERVICES_NAME, parv[1]);
	 else
	    sendto_one(sptr, err_str(ERR_SERVICESDOWN), me.name,
		       parv[0], NickServ);
      }
   }
   return 0;
}

/*
 * * m_notice *       parv[0] = sender prefix *       parv[1] = receiver list *
 * parv[2] = notice text
 */

int
m_notice(aClient *cptr,
	 aClient *sptr,
	 int parc,
	 char *parv[])
{
   return m_message(cptr, sptr, parc, parv, 1);
}


/* the new m_who! -wd */

SOpts wsopts;
int build_searchopts(aClient *, int, char **);
int chk_who(aClient *, int);

int build_searchopts(aClient *sptr, int parc, char *parv[]) {
	static char *who_help[] = {
		"/WHO [[+|-][acghmnsu] [args]",
		"Flags are specified like channel modes, the flags cgmnsu all have arguments",
		"Flags are set to a positive check by +, a negative check by -",
		"The flags work as follows:",
		"Flag a: user is away",
		"Flag c <channel>: user is on <channel>,",
		"                  no wildcards accepted",
		"Flag g <gcos/realname>: user has string <gcos> in their GCOS,",
		"                        wildcards accepted, oper only",
		"Flag h <host>: user has string <host> in their hostname,",
		"               wildcards accepted",
		"Flag m <usermodes>: user has <usermodes> set on them,",
		"                    only o/A/a for nonopers",
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
	char *flags, change=1, *s;
	int args=1, i;
	
	memset((char *)&wsopts, '\0', sizeof(SOpts));
	/* if we got no extra arguments, send them the help. yeech. */
	/* if it's /who ?, send them the help */
	if(parc < 1 || parv[0][0]=='?') {
		char **ptr = who_help;
		for (; *ptr; ptr++)
		  sendto_one(sptr, getreply(RPL_COMMANDSYNTAX), me.name,
						 sptr->name, *ptr);
	          sendto_one(sptr, getreply(RPL_ENDOFWHO), me.name, sptr->name, "?");
		return 0;
	}
	/* backwards compatibility */
	else if(parv[0][0]=='0' && parv[0][1]==0) {
		if(parc>1 && *parv[1]=='o') {
			wsopts.check_umode=1;
			wsopts.umode_plus=1;
			wsopts.umodes=UMODE_o;
		}
		wsopts.host_plus=1;
		wsopts.host="*";
		return 1;
	}
	/* if the first argument isn't a list of stuff */
	else if(parv[0][0]!='+' && parv[0][0]!='-') {
		if(parv[0][0]=='#' || parv[0][0]=='&') {
			wsopts.channel=find_channel(parv[0],NullChn);
			if(wsopts.channel==NULL) {
				sendto_one(sptr, getreply(ERR_NOSUCHCHANNEL), me.name,
							  sptr->name, parv[0]);
				return 0;
			}
		}
		else {
			/* If the arguement has a . in it, treat it as an
			 * address. Otherwise treat it as a nick. -Rak */
			if (strchr(parv[0], '.'))
			{
			    wsopts.host_plus=1;
			    wsopts.host=parv[0];
			}
			else
			{
			    wsopts.nick_plus=1;
			    wsopts.nick=parv[0];
			}
		}
		return 1;
	}
	/* now walk the list (a lot like set_mode) and set arguments
	 * as appropriate. */
	flags=parv[0];
	while(*flags) {
		switch(*flags) {
		 case '+':
		 case '-':
			change=(*flags=='+' ? 1 : 0);
			break;
		 case 'a':
			if(change)
			  wsopts.away_plus=0; /* they want here people */
			else
			  wsopts.away_plus=1;
			wsopts.check_away=1;
			break;
                 case 'C':
                        wsopts.show_chan = change;
                        break;
                 case 'M':
                        wsopts.search_chan = change;
                        break;
		 case 'c':
			if(parv[args]==NULL || !change) {
				sendto_one(sptr, getreply(ERR_WHOSYNTAX), me.name,
							  sptr->name);
				return 0;
			}
			wsopts.channel=find_channel(parv[args],NullChn);
			if(wsopts.channel==NULL) {
				sendto_one(sptr, getreply(ERR_NOSUCHCHANNEL), me.name,
							  sptr->name, parv[args]);
				return 0;
			}
			wsopts.chan_plus=change;
			args++;
			break;
		 case 'g':
			if(parv[args]==NULL || !IsAnOper(sptr)) {
				sendto_one(sptr, getreply(ERR_WHOSYNTAX), me.name,
							  sptr->name);
				return 0;
			}
			wsopts.gcos=parv[args];
			wsopts.gcos_plus=change;
			args++;
			break;
		 case 'h':
			if(parv[args]==NULL) {
				sendto_one(sptr, getreply(ERR_WHOSYNTAX), me.name,
							  sptr->name);
				return 0;
			}
			wsopts.host=parv[args];
			wsopts.host_plus=change;
			args++;
			break;
		 case 'm':
			if(parv[args]==NULL) {
				sendto_one(sptr, getreply(ERR_WHOSYNTAX), me.name,
							  sptr->name);
				return 0;
			}
			s=parv[args];
			while(*s) {
				for(i=1;user_modes[i]!=0x0;i+=2) {
					if(*s==(char)user_modes[i]) {
						wsopts.umodes|=user_modes[i-1];
						break;
					}
				}
				s++;
			}
			if(!IsAnOper(sptr)) /* only let users search for +/-oOaA */
			  wsopts.umodes=(wsopts.umodes&(UMODE_o|UMODE_O|UMODE_a|UMODE_A));
			wsopts.umode_plus=change;
			if(wsopts.umodes)
                           wsopts.check_umode=1;
			args++;
			break;
		 case 'n':
			if(parv[args]==NULL) {
				sendto_one(sptr, getreply(ERR_WHOSYNTAX), me.name,
							  sptr->name);
				return 0;
			}
			wsopts.nick=parv[args];
			wsopts.nick_plus=change;
			args++;
			break;
		 case 's':
			if(parv[args]==NULL || !change) {
				sendto_one(sptr, getreply(ERR_WHOSYNTAX), me.name,
							  sptr->name);
				return 0;
			}
			wsopts.server=find_server(parv[args],NULL);
			if(wsopts.server==NULL) {
				sendto_one(sptr, getreply(ERR_NOSUCHSERVER), me.name,
							  sptr->name, parv[args]);
				return 0;
			}
			wsopts.serv_plus=change;
			args++;
			break;
		 case 'u':
			if(parv[args]==NULL) {
				sendto_one(sptr, getreply(ERR_WHOSYNTAX), me.name,
							  sptr->name);
				return 0;
			}
			wsopts.user=parv[args];
			wsopts.user_plus=change;
			args++;
			break;
		}
		flags++;
	}

	/* if we specified search_chan, we _must_ specify something useful to go with it.
         * specifying a channel makes no sense, and no params make no sense either, as does
         * specifying a nick. */

        if(wsopts.search_chan && !(wsopts.check_away || wsopts.gcos || wsopts.host || wsopts.check_umode ||
	     wsopts.server || wsopts.user))
	{
	   if(parv[args]==NULL || wsopts.channel || wsopts.nick || parv[args][0] == '#' || parv[args][0] == '&')
           {
	      sendto_one(sptr, getreply(ERR_WHOSYNTAX), me.name, sptr->name);
	      return 0;
	   }

	   if (strchr(parv[args], '.'))
	   {
	      wsopts.host_plus=1;
	      wsopts.host=parv[args];
	   }
	   else
	   {
	      sendto_one(sptr, getreply(ERR_WHOSYNTAX), me.name, sptr->name);
	      return 0;
	   }
	} else /* can't show_chan if nothing else is set! */
        if(wsopts.show_chan && !(wsopts.check_away || wsopts.gcos || wsopts.host || wsopts.check_umode ||
	     wsopts.server || wsopts.user || wsopts.nick || wsopts.channel))
	{
	   if(parv[args]==NULL)
           {
	      sendto_one(sptr, getreply(ERR_WHOSYNTAX), me.name, sptr->name);
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


	/* hey cool, it all worked! */
	return 1;
}

/* these four are used by chk_who to check gcos/nick/user/host
 * respectively */
int (*gchkfn)(char *, char *);
int (*nchkfn)(char *, char *);
int (*uchkfn)(char *, char *);
int (*hchkfn)(char *, char *);

int chk_who(aClient *ac, int showall) {
	if(!IsClient(ac))
	  return 0;
	if(IsInvisible(ac) && !showall)
	  return 0;
	if(wsopts.check_umode)
	  if((wsopts.umode_plus && !((ac->umode&wsopts.umodes)==wsopts.umodes)) ||
		  (!wsopts.umode_plus && ((ac->umode&wsopts.umodes)==wsopts.umodes)))
		 return 0;
	if(wsopts.check_away)
	  if((wsopts.away_plus && ac->user->away==NULL) ||
		  (!wsopts.away_plus && ac->user->away!=NULL))
		 return 0;
	/* while this is wasteful now, in the future
	 * when clients contain pointers to their servers
	 * of origin, this'll become a 4 byte check instead of a mycmp
	 * -wd */
        /* welcome to the future... :) - lucas */
	if(wsopts.serv_plus)
	  if(wsopts.server != ac->uplink)
		 return 0;
	/* we only call match once, since if the first condition
	 * isn't true, most (all?) compilers will never try the
	 * second...phew :) */
	if(wsopts.user!=NULL)
	  if((wsopts.user_plus && uchkfn(wsopts.user, ac->user->username)) ||
		  (!wsopts.user_plus && !uchkfn(wsopts.user, ac->user->username)))
		 return 0;
	
	if(wsopts.nick!=NULL)
	  if((wsopts.nick_plus && nchkfn(wsopts.nick, ac->name)) ||
		  (!wsopts.nick_plus && !nchkfn(wsopts.nick, ac->name)))
		 return 0;
	
	if(wsopts.host!=NULL)
	  if((wsopts.host_plus && hchkfn(wsopts.host, ac->user->host)) ||
		  (!wsopts.host_plus && !hchkfn(wsopts.host, ac->user->host)))
		 return 0;
	
	if(wsopts.gcos!=NULL)
	  if((wsopts.gcos_plus && gchkfn(wsopts.gcos, ac->info)) ||
		  (!wsopts.gcos_plus && !gchkfn(wsopts.gcos, ac->info)))
		 return 0;
	return 1;
}

inline char *first_visible_channel(aClient *cptr, aClient *sptr)
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

/* allow lusers only 200 replies from /who */
#define MAXWHOREPLIES 200
int m_who(aClient *cptr, aClient *sptr, int parc, char *parv[]) {
	aClient *ac;
        chanMember *cm;
        Link *lp;
	int shown=0, i=0, showall=IsAnOper(sptr);
	char status[4];
	
	/* drop nonlocal clients */
	if(!MyClient(sptr))
	  return 0;
	
	if(!build_searchopts(sptr, parc-1, parv+1))
	  return 0; /* /who was no good */
	
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

	
	if(wsopts.channel!=NULL) {
		if(IsMember(sptr,wsopts.channel))
		  showall=1;
		else if(SecretChannel(wsopts.channel) && IsAdmin(sptr))
		  showall=1;
		else if(!SecretChannel(wsopts.channel) && IsAnOper(sptr))
		  showall=1;
		else
		  showall=0;
		if(showall || !SecretChannel(wsopts.channel)) {
			for(cm=wsopts.channel->members; cm; cm=cm->next) {
				ac=cm->cptr;
				i=0;
				if(!chk_who(ac,showall))
				  continue;
				/* get rid of the pidly stuff first */
				/* wow, they passed it all, give them the reply...
				 * IF they haven't reached the max, or they're an oper */
				status[i++]=(ac->user->away==NULL ? 'H' : 'G');
				status[i]=(IsAnOper(ac) ? '*' : ((IsInvisible(ac) && IsOper(sptr)) ? '%' : 0));
				status[((status[i]) ? ++i : i)]=((cm->flags&CHFL_CHANOP) ? '@' : ((cm->flags&CHFL_VOICE) ? '+' : 0));
				status[++i]=0;
				sendto_one(sptr, getreply(RPL_WHOREPLY), me.name, sptr->name,
						  wsopts.channel->chname, ac->user->username, 
						  ac->user->host,ac->user->server, ac->name, status, 
						  ac->hopcount, ac->info);
			}
		}
		sendto_one(sptr, getreply(RPL_ENDOFWHO), me.name, sptr->name,
					  wsopts.channel->chname);
		return 0;
	}
	/* if (for whatever reason) they gave us a nick with no
	 * wildcards, just do a find_person, bewm! */
	else if(nchkfn==mycmp) {
		ac=find_person(wsopts.nick,NULL);
		if(ac!=NULL) {
			if(!chk_who(ac,1)) {
			sendto_one(sptr, getreply(RPL_ENDOFWHO), me.name, sptr->name,
						  wsopts.host!=NULL ? wsopts.host : wsopts.nick);
				return 0;
			}
			else {
				status[0]=(ac->user->away==NULL ? 'H' : 'G');
				status[1]=(IsAnOper(ac) ? '*' : (IsInvisible(ac) && IsAnOper(sptr) ? '%' : 0));
				status[2]=0;
				sendto_one(sptr, getreply(RPL_WHOREPLY), me.name, sptr->name,
							  wsopts.show_chan ? first_visible_channel(ac, sptr) : "*", 
							  ac->user->username, ac->user->host, 
							  ac->user->server, ac->name, status, ac->hopcount,
							  ac->info);
				sendto_one(sptr, getreply(RPL_ENDOFWHO), me.name, sptr->name,
							  wsopts.host!=NULL ? wsopts.host : wsopts.nick);
				return 0;
			}
		}
		sendto_one(sptr, getreply(RPL_ENDOFWHO), me.name, sptr->name,
					  wsopts.host!=NULL ? wsopts.host : wsopts.nick);
		return 0;
	}
	/* if HTM, drop this too */
	if(lifesux && !IsAnOper(sptr)) {
		sendto_one(sptr, rpl_str(RPL_LOAD2HI), me.name, sptr->name);
		return 0;
	}

        if(wsopts.search_chan)
        {
           for(lp = sptr->user->channel; lp; lp = lp->next)
           {
              for(cm = lp->value.chptr->members; cm; cm = cm->next)
              {
                 ac = cm->cptr;
                 if(!chk_who(ac, 1))
                    continue;

                 if(shown==MAXWHOREPLIES && !IsAnOper(sptr)) 
                 {
                    sendto_one(sptr, getreply(ERR_WHOLIMEXCEED), me.name, sptr->name, MAXWHOREPLIES);
                    break;
                 }

                 i = 0;
                 status[i++]=(ac->user->away==NULL ? 'H' : 'G');
                 status[i]=(IsAnOper(ac) ? '*' : ((IsInvisible(ac) && IsOper(sptr)) ? '%' : 0));
                 status[((status[i]) ? ++i : i)]=((cm->flags&CHFL_CHANOP) ? '@' : ((cm->flags&CHFL_VOICE) ? '+' : 0));
                 status[++i]=0;
                 sendto_one(sptr, getreply(RPL_WHOREPLY), me.name, sptr->name,
                            lp->value.chptr->chname, ac->user->username, ac->user->host,ac->user->server, ac->name,
                            status, ac->hopcount, ac->info);
                 shown++;
              }
           }
        }
        else
        {
	   for(ac=client;ac;ac=ac->next) {
		if(!chk_who(ac,showall))
		  continue;
		/* wow, they passed it all, give them the reply...
		 * IF they haven't reached the max, or they're an oper */
		if(shown==MAXWHOREPLIES && !IsAnOper(sptr)) {
			sendto_one(sptr, getreply(ERR_WHOLIMEXCEED), me.name, sptr->name,
						  MAXWHOREPLIES);
			break; /* break out of loop so we can send end of who */
		}
		status[0]=(ac->user->away==NULL ? 'H' : 'G');
		status[1]=(IsAnOper(ac) ? '*' : (IsInvisible(ac) && IsAnOper(sptr) ? '%' : 0));
		status[2]=0;
		sendto_one(sptr, getreply(RPL_WHOREPLY), me.name, sptr->name,
					  wsopts.show_chan ? first_visible_channel(ac, sptr) : "*", 
					  ac->user->username, ac->user->host, ac->user->server,
					  ac->name, status, ac->hopcount, ac->info);
		shown++;
	   }
        }
	sendto_one(sptr, getreply(RPL_ENDOFWHO), me.name, sptr->name,
				  (wsopts.host!=NULL ? wsopts.host : 
				  (wsopts.nick!=NULL ? wsopts.nick :
				  (wsopts.user!=NULL ? wsopts.user :
				  (wsopts.gcos!=NULL ? wsopts.gcos :
				  (wsopts.server!=NULL ? wsopts.server->name :
					 "*"))))));
	return 0;
}


/*
 * * m_whois *        parv[0] = sender prefix *       parv[1] = nickname
 * masklist
 */
int
m_whois(aClient *cptr,
	aClient *sptr,
	int parc,
	char *parv[])
{
   static anUser UnknownUser =
   {
      NULL,			/* channel */
      NULL,			/* invited */
		NULL,			/* away */
      0,			/* last */
      0,			/* joined */
      "<Unknown>",		/* user */
      "<Unknown>",		/* host */
      "<Unknown>",		/* server */
		0,  /* servicestamp */
		NULL /* silenced */
   };
	
   Link   *lp;
   anUser *user;
   aClient    *acptr, *a2cptr;
   aChannel   *chptr;
   char       *nick, *tmp, *name;
   char       *p = NULL;
   int         found, len, mlen;

   if (parc < 2) {
      sendto_one(sptr, err_str(ERR_NONICKNAMEGIVEN),
		 me.name, parv[0]);
      return 0;
   }

   if (parc > 2) {
      if (hunt_server(cptr, sptr, ":%s WHOIS %s :%s", 1, parc, parv) !=
			 HUNTED_ISME)
		  return 0;
      parv[1] = parv[2];    
	}
	
   for (tmp = parv[1]; (nick = strtoken(&p, tmp, ",")); tmp = NULL) {
		int         invis, member, showchan;
		
      found = 0;
      (void) collapse(nick);
		acptr = hash_find_client(nick, (aClient *) NULL);
		if (!acptr || !IsPerson(acptr)) {
			sendto_one(sptr, err_str(ERR_NOSUCHNICK),
						  me.name, parv[0], nick);
			continue;
		}
		
		user = acptr->user ? acptr->user : &UnknownUser;
		name = (!*acptr->name) ? "?" : acptr->name;
		invis = IsInvisible(acptr);
		member = (user->channel) ? 1 : 0;
		
		a2cptr = find_server(user->server, NULL);
		
		sendto_one(sptr, rpl_str(RPL_WHOISUSER), me.name,
					  parv[0], name,
					  user->username, user->host, acptr->info);
		
		mlen = strlen(me.name) + strlen(parv[0]) + 6 +
		  strlen(name);
		for (len = 0, *buf = '\0', lp = user->channel; lp;
			  lp = lp->next) {
			chptr = lp->value.chptr;
			showchan=ShowChannel(sptr,chptr);
			if (showchan || IsAdmin(sptr)) {
				if (len + strlen(chptr->chname)
					 > (size_t) BUFSIZE - 4 - mlen) {
					sendto_one(sptr,
								  ":%s %d %s %s :%s",
								  me.name,
								  RPL_WHOISCHANNELS,
								  parv[0], name, buf);
					*buf = '\0';
					len = 0;
				}
				if(!showchan) /* if we're not really supposed to show the chan
									* but do it anyways, mark it as such! */
				  *(buf + len++) = '%';
				if (is_chan_op(acptr, chptr))
				  *(buf + len++) = '@';
				else if (has_voice(acptr, chptr))
				  *(buf + len++) = '+';
				if (len)
				  *(buf + len) = '\0';
				(void) strcpy(buf + len, chptr->chname);
				len += strlen(chptr->chname);
				(void) strcat(buf + len, " ");
				len++;
			}
		}
		if (buf[0] != '\0')
		  sendto_one(sptr, rpl_str(RPL_WHOISCHANNELS),
						 me.name, parv[0], name, buf);
		
		sendto_one(sptr, rpl_str(RPL_WHOISSERVER),
					  me.name, parv[0], name, user->server,
					  a2cptr ? a2cptr->info : "*Not On This Net*");
		if(IsRegNick(acptr))
		  sendto_one(sptr, rpl_str(RPL_WHOISREGNICK),
						 me.name, parv[0], name);
		if (user->away)
		  sendto_one(sptr, rpl_str(RPL_AWAY), me.name,
						 parv[0], name, user->away);
		
		buf[0]='\0';
		if (IsAnOper(acptr))
		  strcat(buf, "an IRC Operator");
		if (IsAdmin(acptr))
		  strcat(buf, " - Server Administrator");
		else if (IsSAdmin(acptr))
		  strcat(buf, " - Services Administrator");
		if (buf[0])
		  sendto_one(sptr, rpl_str(RPL_WHOISOPERATOR),
						 me.name, parv[0], name, buf);
		
		if (acptr->user && MyConnect(acptr))
		  sendto_one(sptr, rpl_str(RPL_WHOISIDLE),
						 me.name, parv[0], name,
						 timeofday - user->last,
						 acptr->firsttime);
		
		continue;
      if (!found)
		  sendto_one(sptr, err_str(ERR_NOSUCHNICK),
						 me.name, parv[0], nick);
      if (p)
		  p[-1] = ',';
   }
   sendto_one(sptr, rpl_str(RPL_ENDOFWHOIS), me.name, parv[0], parv[1]);
	
   return 0;
}

/*
 * * m_user * parv[0] = sender prefix *       parv[1] = username
 * (login name, account) *      parv[2] = client host name (used only
 * from other servers) *        parv[3] = server host name (used only
 * from other servers) *        parv[4] = users real name info
 */
int
m_user(aClient *cptr,
       aClient *sptr,
       int parc,
       char *parv[])
{
#define	UFLAGS	(UMODE_i|UMODE_w|UMODE_s)
    char       *username, *host, *server, *realname;
    aConfItem *aconf;
    
    if (parc > 2 && (username = (char *) strchr(parv[1], '@')))
	*username = '\0';
    if (parc < 5 || *parv[1] == '\0' || *parv[2] == '\0' ||
	*parv[3] == '\0' || *parv[4] == '\0') {
	sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
		   me.name, parv[0], "USER");
	if (IsServer(cptr))
	    sendto_realops("bad USER param count for %s from %s",
			   parv[0], get_client_name(cptr, FALSE));
	else
	    return 0;
    }
    /* Copy parameters into better documenting variables */   
    username = (parc < 2 || BadPtr(parv[1])) ? "<bad-boy>" : parv[1];
    host = (parc < 3 || BadPtr(parv[2])) ? "<nohost>" : parv[2];
    server = (parc < 4 || BadPtr(parv[3])) ? "<noserver>" : parv[3];
    realname = (parc < 5 || BadPtr(parv[4])) ? "<bad-realname>" : parv[4];
    if ((aconf = find_conf_name(realname, CONF_GCOS))) {
	return exit_client(cptr, sptr, sptr, BadPtr(aconf->passwd) ?
			   "Bad GCOS: Reason unspecified" : aconf->passwd);
    }
    return do_user(parv[0], cptr, sptr, username, host, server, 0, realname);
}

/*
 * * do_user
 */
int
do_user(char *nick,
	aClient *cptr,
	aClient *sptr,
	char *username,
	char *host,
	char *server,
	unsigned long serviceid,			
	char *realname)
{
    anUser     *user;
    
    long        oflags;
    
    user = make_user(sptr);
    oflags = sptr->umode;
    
    /*
     * changed the goto into if-else...   -Taner 
     * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ GOOD FOR YOU Taner!!! - Dianora 
     */
    
    if (!MyConnect(sptr)) {
	user->server = find_or_add(server);
	strncpyzt(user->host, host, sizeof(user->host));
    } else {
	if (!IsUnknown(sptr)) {
	    sendto_one(sptr, err_str(ERR_ALREADYREGISTRED),
		       me.name, nick);
	    return 0;
	}
#ifndef	NO_DEFAULT_INVISIBLE
	sptr->umode |= UMODE_i;
#endif
	
	sptr->umode |= (UFLAGS & atoi(host));
	strncpyzt(user->host, host, sizeof(user->host));
	user->server = me.name;
    }
    strncpyzt(sptr->info, realname, sizeof(sptr->info));
    
    sptr->user->servicestamp = serviceid;
    if(MyConnect(sptr))
	sptr->oflag=0;
    if (sptr->name[0])		/*
				 * NICK already received, now I have USER... 
				 */
	return register_user(cptr, sptr, sptr->name, username);
    else
	strncpyzt(sptr->user->username, username, USERLEN + 1);
    return 0;
}
/*
 * * m_quit * parv[0] = sender prefix *       parv[1] = comment
 */
int
m_quit(aClient *cptr,
       aClient *sptr,
       int parc,
       char *parv[])
{
   char *reason = (parc > 1 && parv[1]) ? parv[1] : cptr->name;
   char        comment[TOPICLEN + 1];

   sptr->flags |= FLAGS_NORMALEX;
   if (!IsServer(cptr)) {
      strcpy(comment, "Quit: ");
      strncpy(comment + 6, reason, TOPICLEN - 6); 
      comment[TOPICLEN] = 0;
      return exit_client(cptr, sptr, sptr, comment);
   }
   else
      return exit_client(cptr, sptr, sptr, reason);
}
/*
 * * m_kill * parv[0] = sender prefix *       parv[1] = kill victim *
 * parv[2] = kill path
 */
int
m_kill(aClient *cptr,
       aClient *sptr,
       int parc,
       char *parv[])
{
   aClient    *acptr;
   char       *user, *path, *killer, *p, *nick;
   char mypath[TOPICLEN + 1];
	char       *unknownfmt = "<Unknown>";	/*
						 * AFAIK this shouldnt happen
						 * * but -Raist 
						 */
   int         chasing = 0, kcount = 0;
	
   if (parc < 2 || *parv[1] == '\0') {
      sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
					  me.name, parv[0], "KILL");
      return 0;
   }
	
   user = parv[1];
   path = parv[2];		/*
				 * Either defined or NULL (parc >= 2!!) 
				 */
	if(path==NULL)
	  path=")";
	
   if (!IsPrivileged(cptr)) {
      sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
      return 0;
   }
   if (IsAnOper(cptr)) {
      if (!BadPtr(path))
		  if (strlen(path) > (size_t) TOPICLEN)
			 path[TOPICLEN] = '\0';
   }
   if (MyClient(sptr))
	  user = canonize(user);
   for (p = NULL, nick = strtoken(&p, user, ","); nick;
		  nick = strtoken(&p, NULL, ",")) {
      chasing = 0;
      if (!(acptr = find_client(nick, NULL))) {
			/*
			 * * If the user has recently changed nick, we automaticly *
			 * rewrite the KILL for this new nickname--this keeps *
			 * servers in synch when nick change and kill collide
			 */
			if (!(acptr = get_history(nick, (long) KILLCHASETIMELIMIT))) {
				sendto_one(sptr, err_str(ERR_NOSUCHNICK),
							  me.name, parv[0], nick);
				return 0;
			}
			sendto_one(sptr, ":%s NOTICE %s :KILL changed from %s to %s",
						  me.name, parv[0], nick, acptr->name);
			chasing = 1;
      }
      if ((!MyConnect(acptr) && MyClient(cptr) && !OPCanGKill(cptr)) ||
			 (MyConnect(acptr) && MyClient(cptr) && 
			!OPCanLKill(cptr))) {
			sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
			continue;
      }
      if (IsServer(acptr) || IsMe(acptr)) {
			sendto_one(sptr, err_str(ERR_CANTKILLSERVER),
						  me.name, parv[0]);
			continue;
      }
      kcount++;
		if (!IsServer(sptr) && (kcount > MAXKILLS)) {
			sendto_one(sptr,":%s NOTICE %s :Too many targets, kill list was truncated. Maximum is %d.",
						  me.name, sptr->name, MAXKILLS);
			break;
		}
		
		if(MyClient(sptr)) {
			char myname[80], *s;
			strncpy(myname, me.name, 80);
			s=index(myname, '.');
			*s=0;
			/* okay, what the hell was all this shit in here before?
			 * I dunno but I cleaned it all up, it was annoying.
			 * kills are ':<thing> KILL <person> :<thinghost>!<thing> (<reason>)
			 * --wd */
			/* we no longer care about killpaths, there's really no point to them,
			 * so anything that wants a path will get it here. nifty eh? */
			if(!IsServer(sptr) && IsClient(sptr)) /* killer isn't aserver either */
			  ircsprintf(mypath, "%s!%s!%s (%s)", myname, sptr->user->host, sptr->name, path);
			else 
			  ircsprintf(mypath, "%s (%s)", sptr->name, path);
			mypath[TOPICLEN]='\0';
		}
		else
		  strncpy(mypath,path,TOPICLEN + 1);
		/*
		 * * Notify all *local* opers about the KILL, this includes the
		 * one * originating the kill, if from this server--the special
		 * numeric * reply message is not generated anymore. *
		 * 
		 * Note: "acptr->name" is used instead of "user" because we may *
		 * ave changed the target because of the nickname change.
		 */
		if (IsLocOp(sptr) && !MyConnect(acptr)) {
			sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
			return 0;
		}
		if (IsAnOper(sptr))
		  sendto_ops_lev(0, "Received KILL message for %s!%s@%s. From %s Path: %s",
						 acptr->name, acptr->user ? acptr->user->username : unknownfmt, acptr->user ? acptr->user->host : unknownfmt, parv[0], mypath);
		else
		  sendto_ops_lev(SKILL_LEV, "Received KILL message for %s!%s@%s. From %s Path: %s",
							  acptr->name, acptr->user ? acptr->user->username : unknownfmt, acptr->user ? acptr->user->host : unknownfmt, parv[0], mypath);
		
#if defined(USE_SYSLOG) && defined(SYSLOG_KILL)
		if (IsOper(sptr))
		  syslog(LOG_INFO, "KILL From %s!%s@%s For %s Path %s",
					parv[0], acptr->name, acptr->user ? acptr->user->username : unknownfmt, acptr->user ? acptr->user->host : unknownfmt, mypath);
#endif
		/*
		 * * And pass on the message to other servers. Note, that if KILL *
		 * was changed, the message has to be sent to all links, also *
		 * back. * Suicide kills are NOT passed on --SRB
		 */
		if (!MyConnect(acptr) || !MyConnect(sptr) || !IsAnOper(sptr)) {
			sendto_serv_butone(cptr, ":%s KILL %s :%s",
									 parv[0], acptr->name, mypath);
			if (chasing && IsServer(cptr))
			  sendto_one(cptr, ":%s KILL %s :%s",
							 me.name, acptr->name, mypath);
			acptr->flags |= FLAGS_KILLED;
		}
		/*
		 * * Tell the victim she/he has been zapped, but *only* if * the
		 * victim is on current server--no sense in sending the *
		 * notification chasing the above kill, it won't get far * anyway
		 * (as this user don't exist there any more either)
		 */
		if (MyConnect(acptr))
		  sendto_prefix_one(acptr, sptr, ":%s KILL %s :%s",
								  parv[0], acptr->name, mypath);
		/*
		 * * Set FLAGS_KILLED. This prevents exit_one_client from sending *
		 * the unnecessary QUIT for this. ,This flag should never be *
		 * set in any other place...
		 */
		if (MyConnect(acptr) && MyConnect(sptr) && IsAnOper(sptr))
		  (void) ircsprintf(buf2, "Local kill by %s (%s)", sptr->name,
								  BadPtr(parv[2]) ? sptr->name : parv[2]);
		else {
			killer = strchr(mypath, '(');
			if(killer==NULL)
			  killer="()";
			(void)ircsprintf(buf2, "Killed (%s %s)", sptr->name, killer);
		}
		if (exit_client(cptr, acptr, sptr, buf2) == FLUSH_BUFFER)
		  return FLUSH_BUFFER;
	}
	return 0;
}
/***********************************************************************
	 * m_away() - Added 14 Dec 1988 by jto.
 *            Not currently really working, I don't like this
 *            call at all...
 *
 *            ...trying to make it work. I don't like it either,
 *	      but perhaps it's worth the load it causes to net.
 *	      This requires flooding of the whole net like NICK,
 *	      USER, MODE, etc messages...  --msa
 *
 * 	      Added FLUD-style limiting for those lame scripts out there.
 ***********************************************************************/
/*
 * * m_away * parv[0] = sender prefix *       parv[1] = away message
 */
int
m_away(aClient *cptr,
       aClient *sptr,
       int parc,
       char *parv[])
{
   char   *away, *awy2 = parv[1];
   /*
    * make sure the user exists 
    */
   if (!(sptr->user)) {
      sendto_realops_lev(DEBUG_LEV, "Got AWAY from nil user, from %s (%s)\n", cptr->name, sptr->name);
      return 0;
   }

   away = sptr->user->away;

#ifdef NO_AWAY_FLUD
   if(MyClient(sptr))
   {
      if ((sptr->alas + MAX_AWAY_TIME) < NOW)
		sptr->acount = 0;
      sptr->alas = NOW;
      sptr->acount++;
   }
#endif 

   if (parc < 2 || !*awy2) {
      /*
       * Marking as not away 
       */

      if (away) {
	 MyFree(away);
	 sptr->user->away = NULL;
         /* Don't spam unaway unless they were away - lucas */
         sendto_serv_butone(cptr, ":%s AWAY", parv[0]);
      }
 
      if (MyConnect(sptr))
	 sendto_one(sptr, rpl_str(RPL_UNAWAY),
		    me.name, parv[0]);
      return 0;
   }

   /*
    * Marking as away 
    */
#ifdef NO_AWAY_FLUD
   /* we dont care if they are just unsetting away, hence this is here */
   /* only care about local non-opers */
   if (MyClient(sptr) && (sptr->acount > MAX_AWAY_COUNT) && !IsAnOper(sptr)) {
	sendto_one(sptr, err_str(ERR_TOOMANYAWAY), me.name, parv[0]);
	return 0;
   }
#endif
   if (strlen(awy2) > (size_t) TOPICLEN)
      awy2[TOPICLEN] = '\0';
   /*
    * some lamers scripts continually do a /away, hence making a lot of
    * unnecessary traffic. *sigh* so... as comstud has done, I've
    * commented out this sendto_serv_butone() call -Dianora
    * readded because of anti-flud stuffs -epi
    */

   sendto_serv_butone(cptr, ":%s AWAY :%s ", parv[0], parv[1]);

   if (away)
      MyFree(away);

   away = (char *) MyMalloc(strlen(awy2) + 1);
   strcpy(away, awy2);

   sptr->user->away = away;

   if (MyConnect(sptr))
      sendto_one(sptr, rpl_str(RPL_NOWAWAY), me.name, parv[0]);
   return 0;
}
/*
 * * m_ping * parv[0] = sender prefix *       parv[1] = origin *
 * parv[2] = destination
 */
int
m_ping(aClient *cptr,
       aClient *sptr,
       int parc,
       char *parv[])
{
   aClient    *acptr;
   char       *origin, *destination;

   if (parc < 2 || *parv[1] == '\0') {
      sendto_one(sptr, err_str(ERR_NOORIGIN), me.name, parv[0]);
      return 0;
   }
   origin = parv[1];
   destination = parv[2];	/*
				 * Will get NULL or pointer (parc >=
				 * * 2!!) 
				 */

   acptr = find_client(origin, NULL);
   if (!acptr)
      acptr = find_server(origin, NULL);
   if (acptr && acptr != sptr)
      origin = cptr->name;
   if (!BadPtr(destination) && mycmp(destination, me.name) != 0) {
      if ((acptr = find_server(destination, NULL)))
	 sendto_one(acptr, ":%s PING %s :%s", parv[0],
		    origin, destination);
      else {
	 sendto_one(sptr, err_str(ERR_NOSUCHSERVER),
		    me.name, parv[0], destination);
	 return 0;
      }
   }
   else
      sendto_one(sptr, ":%s PONG %s :%s", me.name,
		 (destination) ? destination : me.name, origin);
   return 0;
}

/*
 * * m_pong * parv[0] = sender prefix *       parv[1] = origin *
 * parv[2] = destination
 */
int
m_pong(aClient *cptr,
       aClient *sptr,
       int parc,
       char *parv[])
{
   aClient    *acptr;
   char       *origin, *destination;

   if (parc < 2 || *parv[1] == '\0') {
      sendto_one(sptr, err_str(ERR_NOORIGIN), me.name, parv[0]);
      return 0;
   }

   origin = parv[1];
   destination = parv[2];
   cptr->flags &= ~FLAGS_PINGSENT;
   sptr->flags &= ~FLAGS_PINGSENT;

   /* if it's my client and it's a server.. */
   if(sptr == cptr && IsServer(cptr))
   {
      if(sptr->flags & FLAGS_USERBURST)
      {
         sptr->flags &= ~FLAGS_USERBURST;
         sendto_gnotice("from %s: %s has processed user/channel burst, sending topic burst.",
			me.name, sptr->name);
         send_topic_burst(sptr);
	 sptr->flags |= FLAGS_PINGSENT|FLAGS_SOBSENT;
	 sendto_one(sptr, "PING :%s", me.name);
      }
      else if(sptr->flags & FLAGS_TOPICBURST)
      {
         sptr->flags &= ~FLAGS_TOPICBURST;
         sendto_gnotice("from %s: %s has processed topic burst (synched to network data).",
			me.name, sptr->name);
#ifdef HUB
	sendto_serv_butone(sptr, ":%s GNOTICE :%s has synched to network data.",
			me.name, sptr->name);
#endif
      }
   }

   /*
    * Now attempt to route the PONG, comstud pointed out routable PING
    * is used for SPING.  routable PING should also probably be left in
    * -Dianora That being the case, we will route, but only for
    * registered clients (a case can be made to allow them only from
    * servers). -Shadowfax
    */
   if (!BadPtr(destination) && mycmp(destination, me.name) != 0
       && IsRegistered(sptr)) {
      if ((acptr = find_client(destination, NULL)) ||
	  (acptr = find_server(destination, NULL)))
	 sendto_one(acptr, ":%s PONG %s %s",
		    parv[0], origin, destination);
      else {
	 sendto_one(sptr, err_str(ERR_NOSUCHSERVER),
		    me.name, parv[0], destination);
	 return 0;
      }
   }

#ifdef	DEBUGMODE
   else
      Debug((DEBUG_NOTICE, "PONG: %s %s", origin,
	     destination ? destination : "*"));
#endif
   return 0;
}

/*
 * * m_oper * parv[0] = sender prefix *       parv[1] = oper name *
 * parv[2] = oper password
 */
int
m_oper(aClient *cptr,
       aClient *sptr,
       int parc,
       char *parv[])
{
   aConfItem  *aconf;
   char       *name, *password, *encr;

#ifdef CRYPT_OPER_PASSWORD
   extern char *crypt();

#endif /*
        * CRYPT_OPER_PASSWORD 
        */

   name = parc > 1 ? parv[1] : (char *) NULL;
   password = parc > 2 ? parv[2] : (char *) NULL;

   if (!IsServer(cptr) && (BadPtr(name) || BadPtr(password))) {
      sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
					  me.name, parv[0], "OPER");
      return 0;
   }

   /* if message arrived from server, trust it, and set to oper */

   if ((IsServer(cptr) || IsMe(cptr)) && !IsOper(sptr)) {
#ifdef DEFAULT_HELP_MODE
      sptr->umode |= UMODE_o;
			sptr->umode |= UMODE_h;
      sendto_serv_butone(cptr, ":%s MODE %s :+oh", parv[0], parv[0]);
#else
			sptr->umode |= UMODE_o;
      sendto_serv_butone(cptr, ":%s MODE %s :+o", parv[0], parv[0]);
#endif
      Count.oper++;
      if (IsMe(cptr))
		  sendto_one(sptr, rpl_str(RPL_YOUREOPER),
						 me.name, parv[0]);
      return 0;
   }
   else if (IsAnOper(sptr)) {
      if (MyConnect(sptr))
		  sendto_one(sptr, rpl_str(RPL_YOUREOPER),
						 me.name, parv[0]);
      return 0;
   }
   if (!(aconf = find_conf_exact(name, sptr->username, sptr->sockhost,
											CONF_OPS)) &&
       !(aconf = find_conf_exact(name, sptr->username,
											cptr->hostip, CONF_OPS))) {
      sendto_one(sptr, err_str(ERR_NOOPERHOST), me.name, parv[0]);
		sendto_realops("Failed OPER attempt by %s (%s@%s)", parv[0],
							sptr->user->username, sptr->user->host);
      return 0;
   }
#ifdef CRYPT_OPER_PASSWORD
   /* use first two chars of the password they send in as salt */
   /* passwd may be NULL pointer. Head it off at the pass... */
   if (password && *aconf->passwd)
	  encr = crypt(password, aconf->passwd);
   else
	  encr = "";
#else
   encr = password;
#endif /* CRYPT_OPER_PASSWORD */
	
   if ((aconf->status & CONF_OPS) &&
       StrEq(encr, aconf->passwd) && !attach_conf(sptr, aconf)) {
		int         old = (sptr->umode & ALL_UMODES);
		char       *s;
		
      s = strchr(aconf->host, '@');
      if (s == (char *) NULL) {
			sendto_one(sptr, err_str(ERR_NOOPERHOST), me.name, parv[0]);
			sendto_realops("corrupt aconf->host = [%s]", aconf->host);
			return 0;
      }
      *s++ = '\0';
      if (!(aconf->port & OFLAG_ISGLOBAL))
		  SetLocOp(sptr);
		else
		  SetOper(sptr);
#ifdef DEFAULT_HELP_MODE			
			sptr->umode|=(UMODE_s|UMODE_g|UMODE_w|UMODE_n|UMODE_h);
#else			
			sptr->umode|=(UMODE_s|UMODE_g|UMODE_w|UMODE_n);
#endif
			sptr->oflag = aconf->port;
      Count.oper++;
      *--s = '@';
      addto_fdlist(sptr->fd, &oper_fdlist);
      sendto_ops("%s (%s@%s) is now operator (%c)", parv[0],
					  sptr->user->username, sptr->sockhost,
					  IsOper(sptr) ? 'O' : 'o');
			send_umode_out(cptr, sptr, old);
      sendto_one(sptr, rpl_str(RPL_YOUREOPER), me.name, parv[0]);
      sptr->pingval = get_client_ping(sptr);
#if !defined(CRYPT_OPER_PASSWORD) && (defined(FNAME_OPERLOG) ||\
    (defined(USE_SYSLOG) && defined(SYSLOG_OPER)))
      encr = "";
#endif
#if defined(USE_SYSLOG) && defined(SYSLOG_OPER)
      syslog(LOG_INFO, "OPER (%s) (%s) by (%s!%s@%s)",
				 name, encr,
				 parv[0], sptr->user->username, sptr->sockhost);
#endif
#if defined(FNAME_OPERLOG)
      {
			int         logfile;
			
			/*
			 * This conditional makes the logfile active only after it's
			 * been created - thus logging can be turned off by removing
			 * the file.
			 * 
			 * stop NFS hangs...most systems should be able to open a file in
			 * 3 seconds. -avalon (curtesy of wumpus)
			 */
			(void) alarm(3);
			if (IsPerson(sptr) &&
				 (logfile = open(FNAME_OPERLOG, O_WRONLY | O_APPEND)) != -1) {
				(void) alarm(0);
				(void) ircsprintf(buf, "%s OPER (%s) (%s) by (%s!%s@%s)\n",
										myctime(timeofday), name, encr,
										parv[0], sptr->user->username,
										sptr->sockhost);
				(void) alarm(3);
				(void) write(logfile, buf, strlen(buf));
				(void) alarm(0);
				(void) close(logfile);
			}
			(void) alarm(0);
			/*
			 * Modification by pjg 
			 */
      }
#endif
   }
   else {
      (void) detach_conf(sptr, aconf);
      sendto_one(sptr, err_str(ERR_PASSWDMISMATCH), me.name, parv[0]);
#ifdef FAILED_OPER_NOTICE
      sendto_realops("Failed OPER attempt by %s (%s@%s)",
							parv[0], sptr->user->username, sptr->sockhost);
#endif
   }
   return 0;
}
/***************************************************************************
 * m_pass() - Added Sat, 4 March 1989
 ***************************************************************************/
/*
 * * m_pass * parv[0] = sender prefix *       parv[1] = password *
 * parv[2] = optional extra version information
 */
int
m_pass(aClient *cptr,
       aClient *sptr,
       int parc,
       char *parv[])
{
   char       *password = parc > 1 ? parv[1] : NULL;

   if (BadPtr(password)) {
      sendto_one(cptr, err_str(ERR_NEEDMOREPARAMS),
		 me.name, parv[0], "PASS");
      return 0;
   }
   if (!MyConnect(sptr) || (!IsUnknown(cptr) && !IsHandshake(cptr))) {
      sendto_one(cptr, err_str(ERR_ALREADYREGISTRED),
		 me.name, parv[0]);
      return 0;
   }
   strncpyzt(cptr->passwd, password, sizeof(cptr->passwd));
   if (parc > 2) {
   int         l = strlen(parv[2]);

      if (l < 2)
	 return 0;
      /*
       * if (strcmp(parv[2]+l-2, "TS") == 0) 
       */
      if (parv[2][0] == 'T' && parv[2][1] == 'S')
	 cptr->tsinfo = (ts_val) TS_DOESTS;
   }
   return 0;
}
/*
 * m_userhost added by Darren Reed 13/8/91 to aid clients and reduce
 * the need for complicated requests like WHOIS. It returns user/host
 * information only (no spurious AWAY labels or channels).
 */
int
m_userhost(aClient *cptr,
	   aClient *sptr,
	   int parc,
	   char *parv[])
{
   char       *p = NULL;
   aClient    *acptr;
   char   *s;
   int     i, len;

   if (parc > 2)
      (void) m_userhost(cptr, sptr, parc - 1, parv + 1);

   if (parc < 2) {
      sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
		 me.name, parv[0], "USERHOST");
      return 0;
   }

   (void) ircsprintf(buf, rpl_str(RPL_USERHOST), me.name, parv[0]);
   len = strlen(buf);
   *buf2 = '\0';

   for (i = 5, s = strtoken(&p, parv[1], " "); i && s;
	s = strtoken(&p, (char *) NULL, " "), i--)
      if ((acptr = find_person(s, NULL))) {
	 if (*buf2)
	    (void) strcat(buf, " ");
	 (void) ircsprintf(buf2, "%s%s=%c%s@%s",
			   acptr->name,
			   IsAnOper(acptr) ? "*" : "",
			   (acptr->user->away) ? '-' : '+',
			   acptr->user->username,
			   acptr->user->host);

	 (void) strncat(buf, buf2, sizeof(buf) - len);
	 len += strlen(buf2);
      }
   sendto_one(sptr, "%s", buf);
   return 0;
}

/*
 * m_ison added by Darren Reed 13/8/91 to act as an efficent user
 * indicator with respect to cpu/bandwidth used. Implemented for NOTIFY
 * feature in clients. Designed to reduce number of whois requests. Can
 * process nicknames in batches as long as the maximum buffer length.
 * 
 * format: ISON :nicklist
 */
/*
 * Take care of potential nasty buffer overflow problem -Dianora
 * 
 */

int
m_ison(aClient *cptr,
       aClient *sptr,
       int parc,
       char *parv[])
{
   aClient *acptr;
   char   *s, **pav = parv;
   char       *p = (char *) NULL;
   int     len;
   int     len2;

   if (parc < 2) {
      sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
		 me.name, parv[0], "ISON");
      return 0;
   }

   (void) ircsprintf(buf, rpl_str(RPL_ISON), me.name, *parv);
   len = strlen(buf);
   if (!IsOper(cptr))
      cptr->priority += 20;	/*
				 * this keeps it from moving to 'busy'
				 * * list 
				 */
   for (s = strtoken(&p, *++pav, " "); s; s = strtoken(&p, (char *) NULL, " "))
      if ((acptr = find_person(s, NULL))) {
	 len2 = strlen(acptr->name);
	 if ((len + len2 + 5) < sizeof(buf)) {	/*
						 * make sure can never
						 * * overflow  
	     *//*
	     * allow for extra ' ','\0' etc. 
	     */
	    (void) strcat(buf, acptr->name);
	    len += len2;
	    (void) strcat(buf, " ");
	    len++;
	 }
	 else
	    break;
      }
   sendto_one(sptr, "%s", buf);
   return 0;
}
/*
 * m_umode() added 15/10/91 By Darren Reed. parv[0] - sender parv[1] -
 * username to change mode for parv[2] - modes to change
 */
int
m_umode(aClient *cptr,
	aClient *sptr,
	int parc,
	char *parv[])
{
   int     flag;
   int    *s;
   char  **p, *m;
   aClient    *acptr;
   int         what, setflags;
   int         badflag = NO;	/*

				 * Only send one bad flag notice
				 * * -Dianora 
				 */
   what = MODE_ADD;

   if (parc < 2) {
      sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
					  me.name, parv[0], "MODE");
      return 0;
   }
	
   if (!(acptr = find_person(parv[1], NULL))) {
      if (MyConnect(sptr))
		  sendto_one(sptr, err_str(ERR_NOSUCHCHANNEL),
						 me.name, parv[0], parv[1]);
      return 0;
   }
	
   if ((IsServer(sptr) ||
		  (sptr != acptr) || 
		  (acptr->from != sptr->from))) {
      if (!IsServer(cptr))
		  sendto_one(sptr, err_str(ERR_USERSDONTMATCH),
						 me.name, parv[0]);
      return 0;
   }
	
   
	if (parc < 3) {
      m = buf;
      *m++ = '+';
      for (s = user_modes; (flag = *s) && (m - buf < BUFSIZE - 4);
			  s += 2)
		  if (sptr->umode & flag)
			 *m++ = (char) (*(s + 1));
      *m = '\0';
      sendto_one(sptr, rpl_str(RPL_UMODEIS),
					  me.name, parv[0], buf);
      return 0;
   }
	
   /*
    * find flags already set for user 
    */
   setflags = 0;
   for (s = user_modes; (flag = *s); s += 2)
	  if (sptr->umode & flag)
		 setflags |= flag;
   /*
    * parse mode change string(s)
    */
   for (p = &parv[2]; p && *p; p++)
	  for (m = *p; *m; m++)
		 switch (*m) {
		  case '+':
	       what = MODE_ADD;
	       break;
		  case '-':
	       what = MODE_DEL;
	       break;
	       /*
	        * we may not get these, but they shouldnt be in
	        * default
	        */
		  case ' ':
		  case '\r':
		  case '\n':
		  case '\t':
			 break;
		  case 'r':
			 break; /* users can't set themselves +r! */
		  case 'A':
			 /* set auto +a if user is setting +A */
			 if (MyClient(sptr) && (what == MODE_ADD)) sptr->umode |= UMODE_a;
		  default:
	       for (s = user_modes; (flag = *s); s += 2)
				if (*m == (char) (*(s + 1))) {
					if (what == MODE_ADD)
					  sptr->umode |= flag;
					else
					  sptr->umode &= ~flag;
					break;
				}
	       if (flag == 0 && MyConnect(sptr))
				badflag = YES;
	       break;
		 }
	
   if (badflag)
	  sendto_one(sptr,
					 err_str(ERR_UMODEUNKNOWNFLAG),
					 me.name, parv[0]);

   /*
    * stop users making themselves operators too easily
    */
   if (!(setflags & UMODE_o) && IsOper(sptr) && !IsServer(cptr))
	  ClearOper(sptr);
	
   if (!(setflags & UMODE_O) && IsLocOp(sptr) && !IsServer(cptr))
	  sptr->umode &= ~UMODE_O;
	
   if ((setflags & (UMODE_o | UMODE_O)) && !IsAnOper(sptr) &&
       MyConnect(sptr)) {
                det_confs_butmask(sptr, CONF_CLIENT & ~CONF_OPS);
                sptr->sendqlen = get_sendq(sptr);
		sptr->oflag = 0;
	}



   if (!(setflags & (UMODE_o | UMODE_O)) && IsAnOper(sptr)) {
      Count.oper++;
   }
	
   if ((setflags & (UMODE_o | UMODE_O)) && !IsAnOper(sptr)) {
      Count.oper--;
      if (MyConnect(sptr))
		  delfrom_fdlist(sptr->fd, &oper_fdlist);
   }

  /*
    * We dont want non opers setting themselves +b - Raistlin
    */

   if (!(setflags & UMODE_b) && (!IsOper(sptr) && !IsLocOp(sptr))
       && !IsServer(cptr))
          sptr->umode &= ~UMODE_b;

   if (!(setflags & UMODE_R) && (!IsOper(sptr) && !IsLocOp(sptr))
	&& !IsServer(cptr))
	  sptr->umode &= ~UMODE_R;

   if (!(setflags & UMODE_e) && (!IsOper(sptr) && !IsLocOp(sptr))
	&& !IsServer(cptr))
	  sptr->umode &= ~UMODE_e;

   if (!(setflags & UMODE_y) && (!IsOper(sptr) && !IsLocOp(sptr))
       && !IsServer(cptr))
          sptr->umode &= ~UMODE_y;

   if (!(setflags & UMODE_n) && (!IsOper(sptr) && !IsLocOp(sptr))
       && !IsServer(cptr))
	  sptr->umode &= ~UMODE_n;

   if (!(setflags & UMODE_d) && (!IsOper(sptr) && !IsLocOp(sptr))
       && !IsServer(cptr))
          sptr->umode &= ~UMODE_d;

   if (!(setflags & UMODE_h) && (!IsOper(sptr) && !IsLocOp(sptr))
       && !IsServer(cptr))
          sptr->umode &= ~UMODE_h;

   if (!(setflags & UMODE_i) && IsInvisible(sptr))
	  Count.invisi++;
   if ((setflags & UMODE_i) && !IsInvisible(sptr))
	  Count.invisi--;
	
   /*
    * compare new flags with old flags and send string which will cause
    * servers to update correctly.
    */
	if (!IsAnOper(sptr) && !IsServer(sptr)) {
		if (IsAdmin(sptr)) ClearAdmin(sptr);
		if (IsSAdmin(sptr)) ClearSAdmin(sptr);
		if (IsUmodef(sptr)) ClearUmodef(sptr);
		if (IsUmodec(sptr)) ClearUmodec(sptr);
		if (IsUmodey(sptr)) ClearUmodey(sptr);
		if (IsUmoded(sptr)) ClearUmoded(sptr);
		if (IsUmodeb(sptr)) ClearUmodeb(sptr);
		if (IsUmoden(sptr)) ClearUmoden(sptr);
		if (IsUmodem(sptr)) ClearUmodem(sptr);
		if (IsRouting(sptr)) ClearRouting(sptr);
		if (IsUmodee(sptr)) ClearUmodee(sptr);
	}
	if(MyClient(sptr)) {
		if (IsAdmin(sptr) && !OPIsAdmin(sptr)) ClearAdmin(sptr);
		if (IsSAdmin(sptr) && !OPIsSAdmin(sptr)) ClearSAdmin(sptr);
		if (IsUmodef(sptr) && !OPSetUModeF(sptr)) ClearUmodef(sptr);
		if (IsUmodec(sptr) && !OPSetUModeC(sptr)) ClearUmodec(sptr);
		if (IsUmodey(sptr) && !OPSetUModeY(sptr)) ClearUmodey(sptr);
		if (IsUmoded(sptr) && !OPSetUModeD(sptr)) ClearUmoded(sptr);
		if (IsUmodeb(sptr) && !OPSetUModeB(sptr)) ClearUmodeb(sptr);
		if (IsRouting(sptr) && !OPIsRStaff(sptr)) ClearRouting(sptr);
	}
   send_umode_out(cptr, sptr, setflags);
	
   return 0;
}
/*
 * send the MODE string for user (user) to connection cptr -avalon
 */
void
send_umode(aClient *cptr,
	   aClient *sptr,
	   int old,
	   int sendmask,
	   char *umode_buf)
{
   int    *s, flag;
   char   *m;
   int         what = MODE_NULL;

   /*
    * build a string in umode_buf to represent the change in the user's
    * mode between the new (sptr->flag) and 'old'.
    */
   m = umode_buf;
   *m = '\0';
   for (s = user_modes; (flag = *s); s += 2) {
      if (MyClient(sptr) && !(flag & sendmask))
	 continue;
      if ((flag & old) && !(sptr->umode & flag)) {
	 if (what == MODE_DEL)
	    *m++ = *(s + 1);
	 else {
	    what = MODE_DEL;
	    *m++ = '-';
	    *m++ = *(s + 1);
	 }
      }
      else if (!(flag & old) && (sptr->umode & flag)) {
	 if (what == MODE_ADD)
	    *m++ = *(s + 1);
	 else {
	    what = MODE_ADD;
	    *m++ = '+';
	    *m++ = *(s + 1);
	 }
      }
   }
   *m = '\0';
   if (*umode_buf && cptr)
      sendto_one(cptr, ":%s MODE %s :%s",
		 sptr->name, sptr->name, umode_buf);
}
/*
 * added Sat Jul 25 07:30:42 EST 1992
 */
/*
 * extra argument evenTS added to send to TS servers or not -orabidoo
 * 
 * extra argument evenTS no longer needed with TS only th+hybrid server
 * -Dianora
 */
void
send_umode_out(aClient *cptr,
	       aClient *sptr,
	       int old)
{
   int     i, j;
   aClient *acptr;
   fdlist      fdl = serv_fdlist;

   send_umode(NULL, sptr, old, SEND_UMODES, buf);
   /*
    * Cycling through serv_fdlist here should be MUCH faster than
    * looping through every client looking for servers. -ThemBones
    */

   for (i = fdl.entry[j = 1]; j <= fdl.last_entry; i = fdl.entry[++j])
      if ((acptr = local[i]) && (acptr != cptr) &&
	  (acptr != sptr) && (*buf))
	 sendto_one(acptr, ":%s MODE %s :%s",
		    sptr->name, sptr->name, buf);

   if (cptr && MyClient(cptr))
      send_umode(cptr, sptr, old, ALL_UMODES, buf);
}

/**
 ** botreject(host)
 **   Reject a bot based on a fake hostname...
 **           -Taner
 **/
int
botreject(char *host)
{
   /*
    * Eggdrop Bots:   "USER foo 1 1 :foo" Vlad, Com, joh Bots:
    * "USER foo null null :foo" Annoy/OJNKbots: "user foo . . :foo"
    * (disabled) Spambots that are based on OJNK: "user foo x x :foo"
    */
#undef CHECK_FOR_ANNOYOJNK
   if (!strcmp(host, "1"))
      return 1;
   if (!strcmp(host, "null"))
      return 2;
   if (!strcmp(host, "x"))
      return 3;
#ifdef CHECK_FOR_ANNOYOJNK
   if (!strcmp(host, "."))
      return 4;
#endif
   return 0;
}
/**
 ** botwarn(host, nick, user, realhost)
 **     Warn that a bot MAY be connecting (added by ThemBones)
 **/
int
botwarn(char *host,
	char *nick,
	char *user,
	char *realhost)
{
   /*
    * Eggdrop Bots:      "USER foo 1 1 :foo" Vlad, Com, joh Bots:
    * "USER foo null null :foo" Annoy/OJNKbots:    "user foo . . :foo"
    * (disabled)
    */
#undef CHECK_FOR_ANNOYOJNK
   if (!strcmp(host, "1"))
      sendto_realops_lev(CCONN_LEV, "Possible Eggdrop: %s (%s@%s)",
			 nick, user, realhost);
   if (!strcmp(host, "null"))
      sendto_realops_lev(CCONN_LEV, "Possible ComBot: %s (%s@%s)",
			 nick, user, realhost);
   if (!strcmp(host, "x"))
      sendto_realops_lev(CCONN_LEV, "Possible SpamBot: %s (%s@%s)",
			 nick, user, realhost);
#ifdef CHECK_FOR_ANNOYOJNK
   if (!strcmp(host, "."))
      sendto_realops_lev(CCONN_LEV, "Possible AnnoyBot: %s (%s@%s)",
			 nick, user, realhost);
#endif
   return 0;
}

/*
 * This function checks to see if a CTCP message (other than ACTION) is
 * contained in the passed string.  This might seem easier than I am
 * doing it, but a CTCP message can be changed together, even after a
 * normal message.
 * 
 * If the message is found, and it's a DCC message, pass it back in
 * *dccptr.
 *
 * Unfortunately, this makes for a bit of extra processing in the
 * server.
 */

int check_for_ctcp(char *str, char **dccptr)
{
   char       *p = str;

   while ((p = strchr(p, 1)) != NULL) 
   {
      if (myncmp(++p, "DCC", 3) == 0)
      {
         if(dccptr)
            *dccptr = p;
         if(myncmp(p+3, " SEND", 5) == 0)
            return CTCP_DCCSEND;
         else
	    return CTCP_DCC;
      }
      if (myncmp(++p, "ACTION", 6) != 0)
	 return CTCP_YES;
      if ((p = strchr(p, 1)) == NULL)
	 return CTCP_NONE;
      if(!(*(++p)))
         break;;
   }
   return CTCP_NONE;
}

/*
 * Shadowfax's FLUD code 
 */

#ifdef FLUD

void
announce_fluder(aClient *fluder,	/*
					 * fluder, client being fluded 
					 */
		aClient *cptr,
		aChannel *chptr,	/*
					 * channel being fluded 
					 */
		int type)
{				/*
				 * for future use 
				 */
   char       *fludee;

   if (cptr)
      fludee = cptr->name;
   else
      fludee = chptr->chname;

   sendto_ops_lev(FLOOD_LEV, "Flooder %s [%s@%s] on %s target: %s",
	     fluder->name, fluder->user->username, fluder->user->host,
		  fluder->user->server, fludee);
}

/*
 * This is really just a "convenience" function.  I can only keep three
 * or * four levels of pointer dereferencing straight in my head.  This
 * remove * an entry in a fluders list.  Use this when working on a
 * fludees list :)
 */
struct fludbot *
remove_fluder_reference(struct fludbot **fluders,
			aClient *fluder)
{
   struct fludbot *current, *prev, *next;

   prev = NULL;
   current = *fluders;
   while (current) {
      next = current->next;
      if (current->fluder == fluder) {
	 if (prev)
	    prev->next = next;
	 else
	    *fluders = next;

	 BlockHeapFree(free_fludbots, current);
      }
      else
	 prev = current;
      current = next;
   }

   return (*fluders);
}

/*
 * Another function to unravel my mind. 
 */
Link       *
remove_fludee_reference(Link **fludees, void *fludee)
{
   Link       *current, *prev, *next;

   prev = NULL;
   current = *fludees;
   while (current) {
      next = current->next;
      if (current->value.cptr == (aClient *) fludee) {
	 if (prev)
	    prev->next = next;
	 else
	    *fludees = next;

	 BlockHeapFree(free_Links, current);
      }
      else
	 prev = current;
      current = next;
   }

   return (*fludees);
}

int
check_for_fludblock(aClient *fluder,	/*
					 * fluder being fluded 
					 */
		    aClient *cptr,	/*
					 * client being fluded 
					 */
		    aChannel *chptr,	/*
					 * channel being fluded 
					 */
		    int type)
{				/*
				 * for future use 
				 */
   time_t      now;
   int         blocking;

   /*
    * If it's disabled, we don't need to process all of this 
    */
   if (flud_block == 0)
      return 0;

   /*
    * It's either got to be a client or a channel being fluded 
    */
   if ((cptr == NULL) && (chptr == NULL))
      return 0;

   if (cptr && !MyFludConnect(cptr)) {
      sendto_ops("check_for_fludblock() called for non-local client");
      return 0;
   }

   /*
    * Are we blocking fluds at this moment? 
    */
   time(&now);
   if (cptr)
      blocking = (cptr->fludblock > (now - flud_block));
   else
      blocking = (chptr->fludblock > (now - flud_block));

   return (blocking);
}

int
check_for_flud(aClient *fluder,	/*
				 * fluder, client being fluded 
				 */
	       aClient *cptr,
	       aChannel *chptr,	/*
				 * channel being fluded 
				 */
	       int type)
{				/*
				 * for future use 
				 */
   time_t      now;
   struct fludbot *current, *prev, *next;
   int         blocking, count, found;
   Link       *newfludee;
	
   /*
    * If it's disabled, we don't need to process all of this 
    */
   if (flud_block == 0)
	  return 0;
	
   /*
    * It's either got to be a client or a channel being fluded 
    */
   if ((cptr == NULL) && (chptr == NULL))
	  return 0;
	
   if (cptr && !MyFludConnect(cptr)) {
      sendto_ops("check_for_flud() called for non-local client");
      return 0;
   }
	
   /*
    * Are we blocking fluds at this moment? 
    */
   time(&now);
   if (cptr)
	  blocking = (cptr->fludblock > (now - flud_block));
   else
	  blocking = (chptr->fludblock > (now - flud_block));
	
   /*
    * Collect the Garbage 
    */
   if (!blocking) {
      if (cptr)
		  current = cptr->fluders;
      else
		  current = chptr->fluders;
      prev = NULL;
      while (current) {
			next = current->next;
			if (current->last_msg < (now - flud_time)) {
				if (cptr)
				  remove_fludee_reference(&current->fluder->fludees,
												  (void *) cptr);
				else
				  remove_fludee_reference(&current->fluder->fludees,
												  (void *) chptr);
				
				if (prev)
				  prev->next = current->next;
				else if (cptr)
				  cptr->fluders = current->next;
				else
				  chptr->fluders = current->next;
				BlockHeapFree(free_fludbots, current);
			}
			else
			  prev = current;
			current = next;
      }
   }
   /*
    * Find or create the structure for the fluder, and update the
    * counter * and last_msg members.  Also make a running total count
    */
   if (cptr)
	  current = cptr->fluders;
   else
	  current = chptr->fluders;
   count = found = 0;
   while (current) {
      if (current->fluder == fluder) {
			current->last_msg = now;
			current->count++;
			found = 1;
      }
      if (current->first_msg < (now - flud_time))
		  count++;
      else
		  count += current->count;
      current = current->next;
   }
   if (!found) {
		if ((current = BlockHeapALLOC(free_fludbots, struct fludbot)) != NULL) {
			current->fluder = fluder;
			current->count = 1;
			current->first_msg = now;
			current->last_msg = now;
			if (cptr) {
				current->next = cptr->fluders;
				cptr->fluders = current;
			}
			else {
				current->next = chptr->fluders;
				chptr->fluders = current;
			}
			
			count++;
			
			if ((newfludee = BlockHeapALLOC(free_Links, Link)) != NULL) {
				if (cptr) {
					newfludee->flags = 0;
					newfludee->value.cptr = cptr;
				}
				else {
					newfludee->flags = 1;
					newfludee->value.chptr = chptr;
				}
				newfludee->next = fluder->fludees;
				fluder->fludees = newfludee;
			}
			else
			  outofmemory();
			/*
			 * If we are already blocking now, we should go ahead * and
			 * announce the new arrival
			 */
			if (blocking)
			  announce_fluder(fluder, cptr, chptr, type);
		}
		else
		  outofmemory();
   }
   /*
    * Okay, if we are not blocking, we need to decide if it's time to *
    * begin doing so.  We already have a count of messages received in *
    * the last flud_time seconds
    */
   if (!blocking && (count > flud_num)) {
      blocking = 1;
      ircstp->is_flud++;
      /*
       * if we are going to say anything to the fludee, now is the *
       * time to mention it to them.
       */
      if (cptr)
		  sendto_one(cptr,
						 ":%s NOTICE %s :*** Notice -- Server flood protection activated for %s",
						 me.name, cptr->name, cptr->name);
      else
		  sendto_channel_butserv(chptr, &me,
										 ":%s NOTICE %s :*** Notice -- Server flood protection activated for %s",
										 me.name,
										 chptr->chname,
										 chptr->chname);
      /*
       * Here we should go back through the existing list of * fluders
       * and announce that they were part of the game as * well.
       */
      if (cptr)
		  current = cptr->fluders;
      else
		  current = chptr->fluders;
      while (current) {
			announce_fluder(current->fluder, cptr, chptr, type);
			current = current->next;
      }
   }
   /*
    * update blocking timestamp, since we received a/another CTCP
    * message
    */
   if (blocking) {
      if (cptr)
		  cptr->fludblock = now;
      else
		  chptr->fludblock = now;
   }
	
   return (blocking);
}

void
free_fluders(aClient *cptr, aChannel *chptr)
{
   struct fludbot *fluders, *next;

   if ((cptr == NULL) && (chptr == NULL)) {
      sendto_ops("free_fluders(NULL, NULL)");
      return;
   }

   if (cptr && !MyFludConnect(cptr))
      return;

   if (cptr)
      fluders = cptr->fluders;
   else
      fluders = chptr->fluders;

   while (fluders) {
      next = fluders->next;

      if (cptr)
	 remove_fludee_reference(&fluders->fluder->fludees, (void *) cptr);
      else
	 remove_fludee_reference(&fluders->fluder->fludees, (void *) chptr);

      BlockHeapFree(free_fludbots, fluders);
      fluders = next;
   }
}

void
free_fludees(aClient *badguy)
{
   Link       *fludees, *next;

   if (badguy == NULL) {
      sendto_ops("free_fludees(NULL)");
      return;
   }
   fludees = badguy->fludees;
   while (fludees) {
      next = fludees->next;

      if (fludees->flags)
	 remove_fluder_reference(&fludees->value.chptr->fluders, badguy);
      else {
	 if (!MyFludConnect(fludees->value.cptr))
	    sendto_ops("free_fludees() encountered non-local client");
	 else
	    remove_fluder_reference(&fludees->value.cptr->fluders, badguy);
      }

      BlockHeapFree(free_Links, fludees);
      fludees = next;
   }
}
#endif /*
        * FLUD 
        */

/* s_svsnick - Pretty straight forward.  Mostly straight outta df
 *  - Raistlin
 * parv[0] = sender
 * parv[1] = old nickname
 * parv[2] = new nickname
 * parv[3] = timestamp
 */
int m_svsnick(aClient *cptr, aClient *sptr, int parc, char *parv[]) {
	aClient *acptr;
	 
	if (!IsULine(sptr)||parc < 4||(strlen(parv[2]) > NICKLEN)) return 0;
	/* if we can't SVSNICK them to something because the nick is in use, KILL them */
	acptr=find_person(parv[2], NULL);
	if(acptr!=NULL) {
		/* send a kill out for the person instead --wd */
		sendto_serv_butone(cptr, ":%s KILL %s :%s (SVSNICK Collide)",
								 sptr->name, parv[1], sptr->name);
		/* now send back a kill for the nick they were presumably changed to */
		sendto_one(cptr, ":%s KILL %s :%s (SVSNICK Collide)",
					  sptr->name, parv[2], sptr->name);
		return 0;
	}
	if (!hunt_server(cptr, sptr, ":%s SVSNICK %s %s :%s", 1, parc, parv) != HUNTED_ISME) {
			if ((acptr = find_person(parv[1], NULL))!=NULL) {
				 acptr->umode &= ~UMODE_r;
				 acptr->last_nick_change = atoi(parv[3]);
				 sendto_common_channels(acptr, ":%s NICK :%s", parv[1], parv[2]);
				 if (IsPerson(acptr)) add_history(acptr, 1);
				 sendto_serv_butone(NULL, ":%s NICK %s :%i", parv[1], parv[2], atoi(parv[3]));
				 if(acptr->name[0]) del_from_client_hash_table(acptr->name, acptr);
				 strcpy(acptr->name, parv[2]);
				 add_to_client_hash_table(parv[2], acptr);
			}
	 }
	return 0;
}

/* send_svsmode_out - Once again, a df function that fits in pretty nicely
 *  - Raistlin
 */
void send_svsmode_out(aClient *cptr, aClient *sptr, aClient *bsptr, int old) {
	send_umode(NULL, sptr, old, SEND_UMODES, buf);
	sendto_serv_butone(cptr, ":%s SVSMODE %s :%s", bsptr->name, 
							 sptr->name, buf);
}

/* channel_svsmode:
 * parv[0] sender
 * parv[1] channel
 * parv[2] modes
 * parv[3] nick
 * parv[4] nickts
 * currently, only a mode of -b is supported. 
 * services should use MODE for regular channel modes.
 * 2/5/00 lucas
 * preconditions: parc >= 3, sptr is ulined
 */
int channel_svsmode(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
   aChannel *chptr;
   aClient *acptr = NULL;
   char *m, *nick = NULL;
   char change = '+';
   ts_val nickts = 0;
   int sendmsg = 1;

   if(!(chptr = find_channel(parv[1], NULL)))
      return 0;

   if(parc >= 4)
   {
      nick = parv[3];
      if(parc > 4)
         nickts = atol(parv[4]);
   }

   if(nick)
   {
      acptr = find_person(nick, NULL);
      if(!acptr || (nickts && acptr->tsinfo != nickts))
         return 0;
   }

   for(m = parv[2]; *m; m++)
      switch(*m)
      {
         case '+':
         case '-':
            change = *m;
            break;

         case 'b':
            if(nick && MyClient(acptr) && change == '-')
            {
               remove_matching_bans(chptr, acptr, &me);
               sendmsg--;
            }
            break;

         default:
            sendmsg++;
            break;
      }

   if(!sendmsg) return 0;

   if(nick)
      sendto_serv_butone(cptr, ":%s SVSMODE %s %s %s %ld", parv[0], parv[1], parv[2], nick, acptr->tsinfo); 
   else
      sendto_serv_butone(cptr, ":%s SVSMODE %s %s", parv[0], parv[1], parv[2]); 

   return 0;
}
	 
/* m_svsmode - df function integrated
 *  - Raistlin
 * -- Behaviour changed - Epi (11/30/99)
 * parv[0] - sender
 * parv[1] - nick
 * parv[2] - TS (or mode, depending on svs version)
 * parv[3] - mode (or services id if old svs version)
 * parv[4] - optional arguement (services id)
 */
int m_svsmode(aClient *cptr, aClient *sptr, int parc, char *parv[]) {
	 int 		flag, *s, what, setflags;
	 char 	       *m, *modes, *optarg;
	 aClient       *acptr;
	 ts_val         ts = 0;

	 if (!IsULine(sptr) || (parc < 3))
	    	return 0;

	 if (parv[1][0] == '#')
	    return channel_svsmode(cptr, sptr, parc, parv);

	 if ((parc >= 4) && ((parv[3][0] == '+') || (parv[3][0] == '-')))
	 {
		ts = atol(parv[2]);
		modes = parv[3];
		optarg = (parc > 4) ? parv[4] : NULL;
	 }
	 else
	 {
		modes = parv[2];
		optarg = (parc > 3) ? parv[3] : NULL;
	 }

	 if (!(acptr = find_person(parv[1], NULL)))
		return 0;

	 if (ts && (ts != acptr->tsinfo))
		return 0;

	 what = MODE_ADD;
	 setflags = 0;

	 for (s = user_modes; (flag = *s); s += 2)
		 if (acptr->umode & flag)
			 setflags |= flag;

	 for (m = modes; *m; m++)
	    switch(*m) {
		 case '+':
			what = MODE_ADD;
			break;
		 case '-':
			what = MODE_DEL;
			break;
		 case ' ':
		 case '\n':
		 case '\r':
		 case '\t':
			break;
/* We don't do this yet (i broke this, and am too lazy to fix it -epi)
 *		 case 'l':
 *			if(parv[3] && isdigit(*parv[4])) max_global_count = atoi(parv[3]);
 *			break;
 */ 
		 case 'd':
			if (optarg && isdigit(*optarg))
			   acptr->user->servicestamp = strtoul(optarg, NULL, 0);
			break;
		 default:
			for (s = user_modes; (flag = *s); s += 2)
			{
			   if (*m == (char)(*(s+1))) 
			   {
			      if (what == MODE_ADD) 
			         acptr->umode |= flag;
			      else 
			         acptr->umode &= ~flag;
			      break;
			   }
			}
			break;
	 }

	 if (optarg)
		sendto_serv_butone(cptr, ":%s SVSMODE %s %ld %s %s",
			parv[0], parv[1], acptr->tsinfo, modes, optarg);
	 else
		sendto_serv_butone(cptr, ":%s SVSMODE %s %ld %s", 
			parv[0], parv[1], acptr->tsinfo, modes);

	 return 0;
}

/* is_silenced - Returns 1 if a sptr is silenced by acptr */
static int is_silenced(aClient *sptr, aClient *acptr) {
	 Link *lp;
	 anUser *user;
	 char sender[HOSTLEN+NICKLEN+USERLEN+5];
	 if (!(acptr->user)||!(lp=acptr->user->silence)||!(user=sptr->user))
		 return 0;
	 ircsprintf(sender,"%s!%s@%s",sptr->name,user->username,user->host);
	 for (;lp;lp=lp->next) {
			if (!match(lp->value.cp, sender)) {
				 if (!MyConnect(sptr)) {
						sendto_one(sptr->from, ":%s SILENCE %s :%s",acptr->name,
											 sptr->name, lp->value.cp);
						lp->flags=1; 
				 }
				 return 1;
			}
	 }
	 return 0;
}

int del_silence(aClient *sptr, char *mask) {
	Link **lp, *tmp;
	for (lp=&(sptr->user->silence);*lp;lp=&((*lp)->next))
	  if (mycmp(mask, (*lp)->value.cp)==0) {
		  tmp = *lp;
		  *lp = tmp->next;
		  MyFree(tmp->value.cp);
		  free_link(tmp);
		  return 0;
	  }
	return 1;
}

static int add_silence(aClient *sptr,char *mask) {
	Link *lp;
	int cnt=0, len=0;
	for (lp=sptr->user->silence;lp;lp=lp->next) {
		len += strlen(lp->value.cp);
		if (MyClient(sptr)) {
		  if ((len > MAXSILELENGTH) || (++cnt >= MAXSILES)) {
			  sendto_one(sptr, err_str(ERR_SILELISTFULL), me.name, sptr->name, mask);
			  return -1;
		  } else {
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
	(void)strcpy(lp->value.cp, mask);
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
int m_silence(aClient *cptr,aClient *sptr,int parc,char *parv[]) {
	 Link *lp;
	aClient *acptr=NULL;
	char c, *cp;
	if (check_registered_user(sptr)) return 0;
	if (MyClient(sptr)) {
		acptr = sptr;
		if (parc < 2 || *parv[1]=='\0' || (acptr = find_person(parv[1], NULL))) {
			if (!(acptr->user)) return 0;
			for (lp = acptr->user->silence; lp; lp = lp->next)
			  sendto_one(sptr, rpl_str(RPL_SILELIST), me.name,
							 sptr->name, acptr->name, lp->value.cp);
			sendto_one(sptr, rpl_str(RPL_ENDOFSILELIST), me.name, acptr->name);
			return 0;
		}
		cp = parv[1];
		c = *cp;
		if (c=='-' || c=='+') cp++;
		else if (!(strchr(cp, '@') || strchr(cp, '.') ||
					  strchr(cp, '!') || strchr(cp, '*'))) {
			sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name, parv[0], parv[1]);
			return 0;
		}
		else c = '+';
		cp = pretty_mask(cp);
		if ((c=='-' && !del_silence(sptr,cp)) ||
			 (c!='-' && !add_silence(sptr,cp))) {
			sendto_prefix_one(sptr, sptr, ":%s SILENCE %c%s", parv[0], c, cp);
			if (c=='-')
			  sendto_serv_butone(NULL, ":%s SILENCE * -%s", sptr->name, cp);
		}
	} else if (parc < 3 || *parv[2]=='\0') {
		sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0], "SILENCE");
		return -1;
	} else if ((c = *parv[2])=='-' || (acptr = find_person(parv[1], NULL))) {
		if (c=='-') {
			if (!del_silence(sptr,parv[2]+1))
			  sendto_serv_butone(cptr, ":%s SILENCE %s :%s",
										parv[0], parv[1], parv[2]);
		} else {
			(void)add_silence(sptr,parv[2]);
			if (!MyClient(acptr))
			  sendto_one(acptr, ":%s SILENCE %s :%s",
							 parv[0], parv[1], parv[2]);
		} 
	} else {
		sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name, parv[0], parv[1]);
		return 0;
	}
	return 0;
}

int add_dccallow(aClient *sptr, aClient *optr)
{
   Link *lp;
   int cnt = 0;

   for(lp = sptr->user->dccallow; lp; lp = lp->next)
   {
      if(lp->flags != DCC_LINK_ME)
         continue;
      if(++cnt >= MAXDCCALLOW)
      {
         sendto_one(sptr, err_str(ERR_TOOMANYDCC), me.name, sptr->name, optr->name, MAXDCCALLOW);
         return 0;
      }
      else if(lp->value.cptr == optr)
      {
         /* silently return */
         return 0;
      }
   }

   lp = make_link();
   lp->value.cptr = optr;
   lp->flags = DCC_LINK_ME;
   lp->next = sptr->user->dccallow;
   sptr->user->dccallow = lp;

   lp = make_link();
   lp->value.cptr = sptr;
   lp->flags = DCC_LINK_REMOTE;
   lp->next = optr->user->dccallow;
   optr->user->dccallow = lp;   

   sendto_one(sptr, rpl_str(RPL_DCCSTATUS), me.name, sptr->name, optr->name, "added to");
   return 0;
}

int del_dccallow(aClient *sptr, aClient *optr) 
{
   Link **lpp, *lp;
   int found = 0;

   for (lpp = &(sptr->user->dccallow); *lpp; lpp=&((*lpp)->next))
   {
      if((*lpp)->flags != DCC_LINK_ME)
         continue;

      if((*lpp)->value.cptr == optr)
      {
         lp = *lpp;
         *lpp = lp->next;
         free_link(lp);
         found++;
         break;
      }
   }

   if(!found)
   {
      sendto_one(sptr, ":%s %d %s :%s is not in your DCC allow list", me.name, RPL_DCCINFO, sptr->name, optr->name);
      return 0;
   }

   for (found = 0, lpp = &(optr->user->dccallow); *lpp; lpp=&((*lpp)->next))
   {
      if((*lpp)->flags != DCC_LINK_REMOTE)
         continue;

      if((*lpp)->value.cptr == sptr)
      {
         lp = *lpp;
         *lpp = lp->next;
         free_link(lp);
         found++;
         break;
      }
   }

   if(!found)
      sendto_realops_lev(DEBUG_LEV, "%s was in dccallowme list of %s but not in dccallowrem list!",
                         optr->name, sptr->name);

   sendto_one(sptr, rpl_str(RPL_DCCSTATUS), me.name, sptr->name, optr->name, "removed from");

   return 0;
}

int allow_dcc(aClient *to, aClient *from)
{
   Link *lp;

   for(lp = to->user->dccallow; lp; lp = lp->next)
   {
      if(lp->flags == DCC_LINK_ME && lp->value.cptr == from)
         return 1;
   }
   return 0;
}

int m_dccallow(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
   Link *lp;
   char *p, *s;
   char *cn;
   aClient *acptr, *lastcptr = NULL;
   int didlist = 0, didhelp = 0, didanything = 0;
   char **ptr;
   static char *dcc_help[] = {
      "/DCCALLOW [<+|->nick[,<+|->nick, ...]] [list] [help]",
      "You may allow DCCs of filetypes which are otherwise blocked by the IRC server",
      "by specifying a DCC allow for the user you want to recieve files from.",
      "For instance, to allow the user bob to send you file.exe, you would type:",
      "/dccallow +bob",
      "and bob would then be able to send you files. bob will have to resend the file",
      "if the server gave him an error message before you added him to your allow list.",
      "/dccallow -bob",
      "Will do the exact opposite, removing him from your dcc allow list.",
      "/dccallow list",
      "Will list the users currently on your dcc allow list.",
      NULL };

   if(!MyClient(sptr)) return 0; /* don't accept dccallows from servers or clients that aren't mine.. */

   if(parc < 2)
   {
      sendto_one(sptr, ":%s NOTICE %s :No command specified for DCCALLOW. Type /dccallow help for more information.",
                 me.name, sptr->name);
      return 0;
   }

   for (p = NULL, s = strtoken(&p, parv[1], ", "); s; s = strtoken(&p, NULL, ", "))
   {
      if(*s == '+')
      {
         didanything++;
         cn = s + 1;
         if(*cn == '\0')
            continue;

         acptr = find_person(cn, NULL);

         if(acptr == sptr) continue;

         if(!acptr)
         {
            sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name, sptr->name, cn);
            continue;
         }

         if(lastcptr == acptr)
            sendto_realops_lev(SPY_LEV, "User %s (%s@%s) may be flooding dccallow: add %s", 
                               sptr->name, sptr->user->username, sptr->user->host, acptr->name);

         lastcptr = acptr;
         add_dccallow(sptr, acptr);
      }
      else if(*s == '-')
      {
         didanything++;
         cn = s + 1;
         if(*cn == '\0')
            continue;

         acptr = find_person(cn, NULL);

         if(acptr == sptr) continue;

         if(!acptr)
         {
            sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name, sptr->name, cn);
            continue;
         }

         if(lastcptr == acptr)
            sendto_realops_lev(SPY_LEV, "User %s (%s@%s) may be flooding dccallow: del %s", 
                               sptr->name, sptr->user->username, sptr->user->host, acptr->name);

         lastcptr = acptr;
         del_dccallow(sptr, acptr);
      }
      else
      {
         if(!didlist && myncmp(s, "list", 4) == 0)
         {
            didanything++;
            didlist++;
            sendto_one(sptr, ":%s %d %s :The following users are on your dcc allow list:", 
                       me.name, RPL_DCCINFO, sptr->name);
            for(lp = sptr->user->dccallow; lp; lp = lp->next)
            {
               if(lp->flags == DCC_LINK_REMOTE) 
                  continue;
               sendto_one(sptr, ":%s %d %s :%s (%s@%s)", me.name, RPL_DCCLIST, sptr->name, 
                          lp->value.cptr->name, lp->value.cptr->user->username, lp->value.cptr->user->host);
            }
            sendto_one(sptr, rpl_str(RPL_ENDOFDCCLIST), me.name, sptr->name, s);
         }
         else if(!didhelp && myncmp(s, "help", 4) == 0)
         {
            didanything++;
            didhelp++;
            for(ptr = dcc_help; *ptr; ptr++)
               sendto_one(sptr, ":%s %d %s :%s", me.name, RPL_DCCINFO, sptr->name, *ptr);
            sendto_one(sptr, rpl_str(RPL_ENDOFDCCLIST), me.name, sptr->name, s);
         }
      }
   }

   if(!didanything)
   {
      sendto_one(sptr, ":%s NOTICE %s :Invalid syntax for DCCALLOW. Type /dccallow help for more information.",
                 me.name, sptr->name);
      return 0;
   }

   return 0;
}
