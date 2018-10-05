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

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "msg.h"
#include "channel.h"
#include "throttle.h"
#include "clones.h"
#include <sys/stat.h>
#include <fcntl.h>
#include "h.h"
#ifdef FLUD
#include "blalloc.h"
#endif /* FLUD */
#include "userban.h"
#include "hooks.h"
#include "memcount.h"
#include "inet.h"
#include "spamfilter.h"

#if defined( HAVE_STRING_H)
#include <string.h>
#else
#include <strings.h>
#endif

int do_user(char *, aClient *, aClient *, char *, char *, char *,
            unsigned long, char *, char *);
extern char motd_last_changed_date[];
extern int  send_motd(aClient *, aClient *, int, char **);
extern void send_topic_burst(aClient *);
extern void outofmemory(void);  /* defined in list.c */
#ifdef MAXBUFFERS
extern void reset_sock_opts();
extern int send_lusers(aClient *,aClient *,int, char **);
#endif
extern int is_xflags_exempted(aClient *sptr, aChannel *chptr); /* for m_message() */
extern int verbose_to_relaychan(aClient *sptr, aChannel *chptr, char *cmd, char *reason); /* for m_message() */
extern inline void verbose_to_opers(aClient *sptr, aChannel *chptr, char *cmd, char *reason); /* for m_message() */
extern time_t get_user_jointime(aClient *cptr, aChannel *chptr); /* for send_msg_error() */
extern int server_was_split;
extern int svspanic;
extern int svsnoop;
extern int uhm_type;

static char buf[BUFSIZE], buf2[BUFSIZE];
int  user_modes[] =
{
    UMODE_o, 'o',
    UMODE_O, 'O',
    UMODE_i, 'i',
    UMODE_w, 'w',
    UMODE_s, 's',
    UMODE_c, 'c',
    UMODE_C, 'C',
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
#ifdef USER_HOSTMASKING
    UMODE_H, 'H',
#endif
#ifdef NO_OPER_FLOOD
    UMODE_F, 'F',
#endif
    UMODE_x, 'x',
    UMODE_X, 'X',
    UMODE_j, 'j',
    UMODE_S, 'S',
    UMODE_K, 'K',
    UMODE_I, 'I',
#ifdef SPAMFILTER
    UMODE_P, 'P',
#endif
    0, 0
};

/* externally defined functions */
extern Link *find_channel_link(Link *, aChannel *);     /* defined in list.c */
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

#ifdef ANTI_SPAMBOT
int         spam_time = MIN_JOIN_LEAVE_TIME;
int         spam_num = MAX_JOIN_LEAVE_COUNT;
#endif

/* defines for check_ctcp results */
#define CTCP_NONE       0
#define CTCP_YES        1
#define CTCP_DCC        2
#define CTCP_DCCSEND    3


/*
 * cptr:
 ** always NON-NULL, pointing to a *LOCAL* client
 ** structure (with an open socket connected!). This
 ** is the physical socket where the message originated (or
 ** which caused the m_function to be executed--some
 ** m_functions may call others...).
 *
 * sptr:
 ** the source of the message, defined by the
 ** prefix part of the message if present. If not or
 ** prefix not found, then sptr==cptr.
 *
 *      *Always* true (if 'parse' and others are working correct):
 *
 *      1      sptr->from == cptr  (note: cptr->from == cptr)
 *
 *      2      MyConnect(sptr) <=> sptr == cptr (e.g. sptr
 * cannot be a local connection, unless it's actually cptr!).
 *
 * MyConnect(x) should probably  be defined as (x == x->from) --msa
 *
 * parc:
 ** number of variable parameter strings (if zero,
 ** parv is allowed to be NULL)
 *
 * parv:
 ** a NULL terminated list of parameter pointers,
 *** parv[0], sender (prefix string), if not present his points to
 *** an empty string.
 *
 ** [parc-1]:
 *** pointers to additional parameters
 *** parv[parc] == NULL, *always*
 *
 * note:   it is guaranteed that parv[0]..parv[parc-1] are all
 *         non-NULL pointers.
 */
/*
 * * next_client 
 * Local function to find the next matching
 * client. The search can be continued from the specified client
 * entry. Normal usage loop is: 
 * 
 *      for (x = client; x = next_client(x,mask); x = x->next) 
 *          HandleMatchingClient; 
 * 
 */
aClient *
next_client(aClient *next, char *ch)
{                               
    /* search string (may include wilds) */
    aClient *tmp = next;
    
    next = find_client(ch, tmp);
    if (tmp && tmp->prev == next)
        return ((aClient *) NULL);

    if (next != tmp)
        return next;
    while(next) 
    {
        if (!match(ch, next->name))
            break;
        next = next->next;
    }
    return next;
}

/* this slow version needs to be used for hostmasks *sigh * */

aClient *
next_client_double(aClient *next, char *ch)
{                               
    /* search string (may include wilds) */
    aClient *tmp = next;

    next = find_client(ch, tmp);
    if (tmp && tmp->prev == next)
        return NULL;
    if (next != tmp)
        return next;
    while(next) 
    {
        if (!match(ch, next->name) || !match(next->name, ch))
            break;
        next = next->next;
    }
    return next;
}

/*
 * hunt_server
 * 
 *      Do the basic thing in delivering the message (command)
 * across the relays to the specific server (server) for
 * actions.
 * 
 *      Note:   The command is a format string and *MUST* be
 * of prefixed style (e.g. ":%s COMMAND %s ...").
 * Command can have only max 8 parameters.
 * 
 * server  parv[server] is the parameter identifying the target server.
 * 
 *      *WARNING* 
 * parv[server] is replaced with the pointer to the 
 * real servername from the matched client
 * I'm lazy now --msa
 *
 * intelligence rewrite  -Quension [May 2005]
 * 
 *      returns: (see #defines)
 */
int 
hunt_server(aClient *cptr, aClient *sptr, char *command, int server,
                int parc, char *parv[])
{
    aClient    *acptr = NULL;

    /* Assume it's me, if no server */
    if (parc <= server || BadPtr(parv[server]))
        return (HUNTED_ISME);

    collapse(parv[server]);

    /* check self first, due to the weirdness of STAT_ME */
    if (!match(parv[server], me.name))
        return HUNTED_ISME;

    if (strchr(parv[server], '?') || strchr(parv[server], '*'))
    {
        /* it's a mask, find the server manually */
        for (acptr = client; acptr; acptr = acptr->next)
        {
            if (!IsServer(acptr))
                continue;

            if (!match(parv[server], acptr->name))
            {
                parv[server] = acptr->name;
                break;
            }
        }
    }
    else
    {
        /* no wildcards, hash lookup */
        acptr = find_client(parv[server], NULL);

        if (acptr && !IsRegistered(acptr))
            acptr = NULL;
    }

    if (!acptr)
    {
        sendto_one(sptr, err_str(ERR_NOSUCHSERVER), me.name, parv[0],
                   parv[server]);
        return HUNTED_NOSUCH;
    }

#ifdef NO_USER_OPERTARGETED_COMMANDS
    if (MyClient(sptr) && !IsAnOper(sptr) && IsUmodeI(acptr))
    {
        sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
        return HUNTED_NOSUCH;
    }
#endif

    if(IsULine(acptr) && (svspanic>1 || (svspanic>0 && !IsARegNick(sptr))) && !IsOper(sptr))
    {
        if(MyClient(sptr))
            sendto_one(sptr, err_str(ERR_SERVICESDOWN), me.name, parv[0],
                       acptr->name);
        return HUNTED_NOSUCH;
    }

    if (MyClient(acptr))
        return HUNTED_ISME;

    sendto_one(acptr, command, parv[0], parv[1], parv[2], parv[3], parv[4],
               parv[5], parv[6], parv[7], parv[8]);
    return HUNTED_PASS;
}

/*
 * canonize
 * 
 * reduce a string of duplicate list entries to contain only the unique
 * items.  Unavoidably O(n^2).
 */
char *
canonize(char *buffer)
{
    static char cbuf[BUFSIZ];
    char *s, *t, *cp = cbuf;
    int l = 0;
    char *p = NULL, *p2;

    *cp = '\0';
    
    for (s = strtoken(&p, buffer, ","); s; s = strtoken(&p, NULL, ",")) 
    {
        if (l) 
        {
            for (p2 = NULL, t = strtoken(&p2, cbuf, ","); t;
                 t = strtoken(&p2, NULL, ","))
                if (!mycmp(s, t))
                    break;
                else if (p2)
                    p2[-1] = ',';
        }
        else
            t = NULL;

        if (!t) 
        {
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

#if (RIDICULOUS_PARANOIA_LEVEL>=1)
static int
check_oper_can_mask(aClient *sptr, char *name, char *password, char **onick)
{
    aOper *aoper;
    char *encr;
    extern char *crypt();

    if(!(aoper = find_oper(name, sptr->user->username, sptr->user->host,
                           sptr->hostip)))
    {
        sendto_ops_lev(ADMIN_LEV, "Failed OPERMASK attempt by %s (%s@%s) [Unknown Account %s]",
                       sptr->name, sptr->user->username, sptr->user->host, name);
        sendto_realops("Failed OPERMASK attempt by %s [Unknown account %s]",
                       sptr->name, name);

        return 0;
    }

    /* use first two chars of the password they send in as salt */
    /* passwd may be NULL pointer. Head it off at the pass... */
    if(confopts & FLAGS_CRYPTPASS)
    {
        if (password && *aoper->passwd)
            encr = crypt(password, aoper->passwd);
        else
            encr = "";
    }
    else
        encr = password;

    if(StrEq(encr, aoper->passwd))
    {
#ifdef USE_SYSLOG
        syslog(LOG_INFO, "OPERMASK: %s (%s!%s@%s)", aoper->nick, sptr->name,
               sptr->user->username, sptr->user->host);
#endif
        *onick = aoper->nick;
        sendto_realops("%s [%s] (%s@<hidden>) has masked their hostname.",
                       sptr->name, aoper->nick, sptr->user->username);
        return 1;
    }

    sendto_ops_lev(ADMIN_LEV, "Failed OPERMASK attempt by %s (%s@%s) [Bad Password for %s]",
                   sptr->name, sptr->user->username, sptr->user->host, name);
    sendto_realops("Failed OPERMASK attempt by %s [Bad Password for %s]", sptr->name, name);

    return 0;
}
#endif


/* used by m_user, m_put, m_post */
static int
reject_proxy(aClient *cptr, char *cmd, char *args)
{
    sendto_realops_lev(REJ_LEV, "proxy attempt from %s: %s %s",
                       cipntoa(cptr), cmd, args ? args : "");
    return exit_client(cptr, cptr, &me, "relay connection");
}


/* mask_host - Gets a normal host or ip and return them masked.
 * -Kobi_S 19/12/2015
 */
char *mask_host(char *orghost, int type)
{
    static char newhost[HOSTLEN + 1];

    if(!type) type = uhm_type;

    if (call_hooks(CHOOK_MASKHOST, orghost, &newhost, type) == UHM_SUCCESS) return newhost;

    return orghost; /* I guess the user won't be host-masked after all... :( */
}


/*
 * * register_user 
 *  This function is called when both NICK and USER messages 
 *  have been accepted for the client, in whatever order.  Only 
 *  after this, is the USER message propagated.
 * 
 *      NICK's must be propagated at once when received, although
 * it would be better to delay them too until full info is
 * available. Doing it is not so simple though, would have to
 * implement the following:
 * 
 *      (actually it has been implemented already for a while)
 * -orabidoo
 * 
 * 1 user telnets in and gives only "NICK foobar" and waits
 * 2 another user far away logs in normally with the nick
 * "foobar" quite legal, as this server didnt propagate it.
 * 3 now this server gets nick "foobar" from outside, but has
 * already the same defined locally. Current server would just
 * issue "KILL foobar" to clean out dups. But, this is not
 * fair. It should actually request another nick from local user
 * or kill him/her...
 */

int 
register_user(aClient *cptr, aClient *sptr, char *nick, char *username,
	      char *hostip)
{
    aAllow  *pwaconf = NULL;
    char       *parv[3];
    static char ubuf[12];
    char       *p;
    anUser     *user = sptr->user;
    struct userBan    *ban;
    aMotd      *smotd;
    int         i, dots;
    int         bad_dns;                /* flag a bad dns name */
#ifdef ANTI_SPAMBOT
    char        spamchar = '\0';

#endif
    char        tmpstr2[512];

    user->last = timeofday;
    parv[0] = sptr->name;
    parv[1] = parv[2] = NULL;
          
    p = hostip ? hostip : cipntoa(sptr);
    strncpyzt(sptr->hostip, p, HOSTIPLEN + 1);
    if (MyConnect(sptr)) 
    {
        if ((i = check_client(sptr))) 
        {
            switch (i)
            {
                case -1:
                    ircstp->is_ref++;
                    sendto_realops_lev(REJ_LEV, "%s from %s [Unauthorized"
                                       " client connection]",
                                       get_client_name(sptr, FALSE), p);
                    return exit_client(cptr, sptr, &me, "You are not"
                                       " authorized to use this server");

                case -2:
                    return exit_client(cptr, sptr, &me, "Socket Error");

                case -3:
                    ircstp->is_ref++;
                    sendto_realops_lev(REJ_LEV, "%s for %s [Allow class is"
                                       " full (server is full)]",
                                       get_client_name(sptr, FALSE), p);
                    return exit_client(cptr, sptr, &me, "No more connections"
                                       " allowed in your connection class (the"
                                       " server is full)");

                default:
                    sendto_realops_lev(DEBUG_LEV, "I don't know why I dropped"
                                       " %s (%d)", get_client_name(sptr,FALSE),
                                       i);
                    return exit_client(cptr, sptr, &me, "Internal error");
            }
        }

        if (sptr->user->allow->flags & CONF_FLAGS_NOTHROTTLE)
            throttle_remove(cptr->hostip);

        if (sptr->user->allow->flags & CONF_FLAGS_FORCEFLOOD)
            SetNoMsgThrottle(sptr);

#ifdef ANTI_SPAMBOT
        /* This appears to be broken */
        /* Check for single char in user->host -ThemBones */
        if (*(user->host + 1) == '\0')
            spamchar = *user->host;
#endif
                
        strncpyzt(user->host, sptr->sockhost, HOSTLEN + 1);
                
        dots = 0;
        p = user->host;
        bad_dns = NO;
        while (*p) 
        {
            if (!IsAlnum(*p)) 
            {
#ifdef RFC1035_ANAL
                if ((*p != '-') && (*p != '.'))
#else
                    if ((*p != '-') && (*p != '.') && (*p != '_') &&
                        (*p != '/'))
#endif /* RFC1035_ANAL */
                        bad_dns = YES;
            }
            if (*p == '.')
                dots++;
            p++;
        }
        /*
         * Check that the hostname has AT LEAST ONE dot (.) in it. If
         * not, drop the client (spoofed host) -ThemBones
	 *
	 * allow valid IPv6 addresses, though.
         */
	if (sptr->ip_family == AF_INET6 &&
	    inet_pton(AF_INET6, user->host, tmpstr2) == 1)
	{
	    bad_dns = NO;
	    dots = 1;
	}

	if (!dots) 
        {
            sendto_realops("Invalid hostname for %s, dumping user %s",
                           sptr->hostip, sptr->name);
            return exit_client(cptr, sptr, &me, "Invalid hostname");
        }
        
        if (bad_dns) 
        {
            sendto_one(sptr, ":%s NOTICE %s :*** Notice -- You have a bad "
                       "character in your hostname", me.name, cptr->name);
            strcpy(user->host, sptr->hostip);
            strcpy(sptr->sockhost, sptr->hostip);
        }

#ifdef USER_HOSTMASKING
        strncpyzt(user->mhost, mask_host(user->host,0), HOSTLEN + 1);
#endif
        
        pwaconf = sptr->user->allow;

        if (sptr->flags & FLAGS_DOID && !(sptr->flags & FLAGS_GOTID)) 
        {
            /* because username may point to user->username */
            char        temp[USERLEN + 1];
            
            strncpyzt(temp, username, USERLEN + 1);
            *user->username = '~';
            (void) strncpy(&user->username[1], temp, USERLEN);
            user->username[USERLEN] = '\0';
#ifdef IDENTD_COMPLAIN
            /* tell them to install identd -Taner */
            sendto_one(sptr, ":%s NOTICE %s :*** Notice -- It seems that you "
                       "don't have identd installed on your host.",
                       me.name, cptr->name);
            sendto_one(sptr, ":%s NOTICE %s :*** Notice -- If you wish to "
                       "have your username show up without the ~ (tilde),",
                       me.name, cptr->name);
            sendto_one(sptr, ":%s NOTICE %s :*** Notice -- then install "
                       "identd.", me.name, cptr->name);
            /* end identd hack */
#endif
        }
        else if (sptr->flags & FLAGS_GOTID && *sptr->username != '-')
            strncpyzt(user->username, sptr->username, USERLEN + 1);
        else if(username != user->username) /* don't overlap */
            strncpyzt(user->username, username, USERLEN + 1);

        if (!BadPtr(pwaconf->passwd))
        {
            char *tmpptr = strchr(sptr->passwd, ':');
            char tmppwd[PASSWDLEN + 1];

            /*
             * If there's a : in the password, fix it so after this function,
             * sptr->passwd changes from:
             * moo:cow:test:asdf
             * to
             * cow:test:asdf
             */

            if(tmpptr)
            {
                *tmpptr++ = '\0';
                strcpy(tmppwd, tmpptr);
            }

            if(!StrEq(sptr->passwd, pwaconf->passwd)) 
            {
                ircstp->is_ref++;
                sendto_one(sptr, err_str(ERR_PASSWDMISMATCH),
                           me.name, parv[0]);
                return exit_client(cptr, sptr, &me, "Bad Password");
            }
            if(tmpptr)
                strcpy(sptr->passwd, tmppwd);
            else
                sptr->passwd[0] = '\0';
        }

                
        /* Limit clients */
        /*
         * We want to be able to have servers and F-line clients connect,
         * so save room for "buffer" connections. Smaller servers may
         * want to decrease this, and it should probably be just a
         * percentage of the MAXCLIENTS... -Taner
         * Flines are now no different than Elines
         * And now there are no special clients, and this is the only thing
         * MAXCLIENTS is checked against.  So no more buffer space.
         */
        if (Count.local > MAXCLIENTS)
        { 
            sendto_realops_lev(SPY_LEV, "Too many clients, rejecting %s[%s].",
                               nick, sptr->sockhost);
            ircstp->is_ref++;
            return exit_client(cptr, sptr, &me,
                               "Sorry, server is full - try later");
        }
        
#ifdef ANTI_SPAMBOT
        /* It appears, this is catching normal clients */
        /* Reject single char user-given user->host's */
        if (spamchar == 'x') 
        {
            sendto_realops_lev(REJ_LEV, "Rejecting possible Spambot: %s "
                               "(Single char user-given userhost: %c)",
                               get_client_name(sptr, FALSE), spamchar);
            ircstp->is_ref++;
            return exit_client(cptr, sptr, sptr, "Spambot detected, "
                               "rejected.");
        }
#endif
                

        /* hostile username checks begin here */
        
        {
            char *tmpstr;
            u_char      c, cc;
            int lower, upper, special;
            
            lower = upper = special = cc = 0;
                          
            /* check for "@" in identd reply -Taner */
            if ((strchr(user->username, '@') != NULL) ||
                (strchr(username, '@') != NULL)) 
            {
                sendto_realops_lev(REJ_LEV,
                                   "Illegal \"@\" in username: %s (%s)",
                                   get_client_name(sptr, FALSE), username);
                ircstp->is_ref++;
                (void) ircsprintf(tmpstr2,
                                  "Invalid username [%s] - '@' is not allowed",
                                  username);
                return exit_client(cptr, sptr, sptr, tmpstr2);
            }
            /* First check user->username... */
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
            if ((!IsAlnum(cc) && !strchr(" -_.", cc)) || (cc > 127))
                special++;
#else
            tmpstr = (user->username[0] == '~' ? &user->username[1] :
                      user->username);
#endif /* IGNORE_FIRST_CHAR */
            
            while (*tmpstr) 
            {
                c = *(tmpstr++);
                if (IsLower(c)) 
                {
                    lower++;
                    continue;
                }
                if (IsUpper(c)) 
                {
                    upper++;
                    continue;
                }
                if ((!IsAlnum(c) && !strchr(" -_.", c)) || (c > 127) || (c<32))
                    special++;
            }
            if (special) 
            {
                sendto_realops_lev(REJ_LEV, "Invalid username: %s (%s@%s)",
                                   nick, user->username, user->host);
                ircstp->is_ref++;
                ircsprintf(tmpstr2, "Invalid username [%s]", user->username);
                return exit_client(cptr, sptr, &me, tmpstr2);
            }
            /* Ok, now check the username they provided, if different */
            lower = upper = special = cc = 0;
                          
            if (strcmp(user->username, username)) 
            {
                                  
#ifdef IGNORE_FIRST_CHAR
                tmpstr = (username[0] == '~' ? &username[2] : &username[1]);
                /*
                 * Ok, we don't want to TOTALLY ignore the first character.
                 * We should at least check it for control charcters, etc
                 * -ThemBones
                 */
                cc = (username[0] == '~' ? username[1] : username[0]);
                                  
                if ((!IsAlnum(cc) && !strchr(" -_.", cc)) || (cc > 127))
                    special++;
#else
                tmpstr = (username[0] == '~' ? &username[1] : username);
#endif /* IGNORE_FIRST_CHAR */
                while (*tmpstr) 
                {
                    c = *(tmpstr++);
                    if (IsLower(c)) 
                    {
                        lower++;
                        continue;
                    }
                    if (IsUpper(c)) 
                    {
                        upper++;
                        continue;
                    }
                    if ((!IsAlnum(c) && !strchr(" -_.", c)) || (c > 127))
                        special++;
                }
#ifdef NO_MIXED_CASE
                if (lower && upper) 
                {
                    sendto_realops_lev(REJ_LEV, "Invalid username: %s (%s@%s)",
                                       nick, username, user->host);
                    ircstp->is_ref++;
                    ircsprintf(tmpstr2, "Invalid username [%s]", username);
                    return exit_client(cptr, sptr, &me, tmpstr2);
                }
#endif /* NO_MIXED_CASE */
                if (special) 
                {
                    sendto_realops_lev(REJ_LEV, "Invalid username: %s (%s@%s)",
                                       nick, username, user->host);
                    ircstp->is_ref++;
                    ircsprintf(tmpstr2, "Invalid username [%s]", username);
                    return exit_client(cptr, sptr, &me, tmpstr2);
                }
            }                   /* usernames different  */
        }

        /*
         * reject single character usernames which aren't alphabetic i.e.
         * reject jokers who have '?@somehost' or '.@somehost'
         * 
         * -Dianora
         */
                
        if ((user->username[1] == '\0') && !IsAlpha(user->username[0])) 
        {
            sendto_realops_lev(REJ_LEV, "Invalid username: %s (%s@%s)",
                               nick, user->username, user->host);
            ircstp->is_ref++;
            ircsprintf(tmpstr2, "Invalid username [%s]", user->username);
            return exit_client(cptr, sptr, &me, tmpstr2);
        }

        if (!(user->allow->flags & CONF_FLAGS_SKIPCLONES) &&
            (i = clones_check(cptr)))
        {
            ircstp->is_ref++;
            return exit_client(cptr, sptr, &me, i == 1
                               ? "Too many connections from your host"
                               : "Too many connections from your site");
        }

        if(!(ban = check_userbanned(sptr, UBAN_IP|UBAN_CIDR4, UBAN_WILDUSER)))
            ban = check_userbanned(sptr, UBAN_HOST, 0);

        if(ban)
        {
            int loc = (ban->flags & UBAN_LOCAL) ? 1 : 0;
            
            ircstp->is_ref++;
            ircstp->is_ref_2++;
            return exit_banned_client(cptr, loc, loc?'K':'A', ban->reason, 0);
        }

        if(call_hooks(CHOOK_POSTACCESS, sptr) == FLUSH_BUFFER)
            return FLUSH_BUFFER;

        Count.unknown--;

        if ((++Count.local) > Count.max_loc) 
        {
            Count.max_loc = Count.local;
            if (!(Count.max_loc % 10))
                sendto_ops("New Max Local Clients: %d", Count.max_loc);
        }
        if ((NOW - Count.day) > 86400) 
        {
            Count.today = 0;
            Count.day = NOW;
        }
        if ((NOW - Count.week) > 604800) 
        {
            Count.weekly = 0;
            Count.week = NOW;
        }
        if ((NOW - Count.month) > 2592000) 
        {
            Count.monthly = 0;
            Count.month = NOW;
        }
        if ((NOW - Count.year) > 31536000) 
        {
            Count.yearly = 0;
            Count.year = NOW;
        }
        Count.today++;
        Count.weekly++;
        Count.monthly++;
        Count.yearly++;
        if(sptr->flags & FLAGS_BAD_DNS) 
            sendto_realops_lev(SPY_LEV, "DNS lookup: %s (%s@%s) is a possible "
                               "cache polluter", sptr->name, 
                               sptr->user->username, sptr->user->host); 
    }
    else
        strncpyzt(user->username, username, USERLEN + 1);

    SetClient(sptr);
    /* Increment our total user count here */
    if (++Count.total > Count.max_tot)
        Count.max_tot = Count.total;

    if(IsInvisible(sptr)) Count.invisi++;
        
    if (MyConnect(sptr))
    {
        set_effective_class(sptr);
#ifdef MAXBUFFERS
        /* Let's try changing the socket options for the client here... */
        reset_sock_opts(sptr->fd, 0);
        /* End sock_opt hack */
#endif
        sendto_one(sptr, rpl_str(RPL_WELCOME), me.name, nick, Network_Name,
                   nick, sptr->user->username, sptr->user->host);
        /*
         * This is a duplicate of the NOTICE but see below...
         * um, why were we hiding it? they did make it on to the
         * server and all.. -wd
         */
        sendto_one(sptr, rpl_str(RPL_YOURHOST), me.name, nick, me.name,
                   version);
#ifdef  IRCII_KLUDGE
        /* Don't mess with this one - IRCII needs it! -Avalon */
        sendto_one(sptr, "NOTICE %s :*** Your host is %s, running version %s",
                   nick, me.name, version);
#endif
        sendto_one(sptr, rpl_str(RPL_CREATED), me.name, nick, creation);
        sendto_one(sptr, rpl_str(RPL_MYINFO), me.name, parv[0],
                   me.name, version);

        send_rplisupport(sptr);

#ifdef FORCE_EVERYONE_HIDDEN
        sptr->umode |= UMODE_I;
#endif

#if (RIDICULOUS_PARANOIA_LEVEL>=1)
        if(!BadPtr(sptr->passwd) && (pwaconf->flags & CONF_FLAGS_I_OPERPORT))
            do 
            {
                char *onptr = sptr->passwd;
                char *opptr;
                char *onick;
                char *tmpptr;
                char tmppwd[PASSWDLEN + 1];
                
                if(!(opptr = strchr(onptr, ':')))
                    break;
                
                *opptr++ = '\0';
                if((tmpptr = strchr(opptr, ':')))
                    *tmpptr++ = '\0';
                if(check_oper_can_mask(sptr, onptr, opptr, &onick) != 0)
                {
                    sendto_one(sptr, ":%s NOTICE %s :*** Your hostname has "
                               "been masked.",
                               me.name, sptr->name);

#ifdef DEFAULT_MASKED_HIDDEN
                    sptr->umode |= UMODE_I;
#endif

                    throttle_remove(sptr->hostip);
                    sptr->user->real_oper_host = 
                        MyMalloc(strlen(sptr->user->host) + 1);
                    sptr->user->real_oper_username = 
                        MyMalloc(strlen(sptr->user->username) + 1);
                    sptr->user->real_oper_ip = 
                        MyMalloc(strlen(sptr->hostip) + 1);
                    strcpy(sptr->user->real_oper_host, sptr->user->host);
                    strcpy(sptr->user->real_oper_username, sptr->user->username);
                    strcpy(sptr->user->real_oper_ip, sptr->hostip);
                    strncpyzt(sptr->user->host, Staff_Address, HOSTLEN + 1);
                    strncpyzt(sptr->user->username, onick, USERLEN + 1);
                    strncpyzt(sptr->username, onick, USERLEN + 1);
                    sptr->flags |= FLAGS_GOTID; /* fake ident */
		    sptr->ip_family = AF_INET;
                    memset(&sptr->ip, 0, sizeof(sptr->ip));
                    strcpy(sptr->hostip, "0.0.0.0");
                    strncpy(sptr->sockhost, Staff_Address, HOSTLEN + 1);
#ifdef USER_HOSTMASKING
                    strncpyzt(sptr->user->mhost, mask_host(Staff_Address,0), HOSTLEN + 1);
                    if(uhm_type > 0) sptr->umode &= ~UMODE_H; /* It's already masked anyway */
#endif
                }

                if(tmpptr)
                {
                    strcpy(tmppwd, tmpptr);
                    strcpy(sptr->passwd, tmppwd);
                }
                else
                    sptr->passwd[0] = '\0';
            } while(0);
#endif

        sendto_realops_lev(CCONN_LEV, "Client connecting: %s (%s@%s) [%s] {%s}%s",
                           nick, user->username, user->host, sptr->hostip,
                           sptr->class->name, IsSSL(sptr) ? " SSL" : "");

        send_lusers(sptr, sptr, 1, parv);
        
        if(motd != NULL)
        {
            sendto_one(sptr, ":%s NOTICE %s :*** Notice -- motd was last"
                       " changed at %s", me.name, nick, motd_last_changed_date);
        }
        
        if(confopts & FLAGS_SMOTD)
        {
            if(motd != NULL)
            {
                sendto_one(sptr, ":%s NOTICE %s :*** Notice -- Please read the"
                                 " motd if you haven't read it", me.name, nick);
            }
            
            sendto_one(sptr, rpl_str(RPL_MOTDSTART), me.name, parv[0], me.name);
            if((smotd = shortmotd) == NULL)
                sendto_one(sptr, rpl_str(RPL_MOTD), me.name, parv[0],
                                    "*** This is the short motd ***");
            else 
                while (smotd) 
                {
                    sendto_one(sptr, rpl_str(RPL_MOTD), me.name, parv[0], 
                                smotd->line);
                    smotd = smotd->next;
                }
        
            sendto_one(sptr, rpl_str(RPL_ENDOFMOTD), me.name, parv[0]);
        }
        else
            send_motd(sptr, sptr, 1, parv);

        if((confopts & FLAGS_WGMON) == FLAGS_WGMON)
        {
            sendto_one(sptr, ":%s NOTICE %s :*** Notice -- This server runs an "
                    "open proxy monitor to prevent abuse.", me.name, nick);
            sendto_one(sptr, ":%s NOTICE %s :*** Notice -- If you see"
                    " connections on various ports from %s", me.name, 
                    nick, ProxyMonHost);
            sendto_one(sptr, ":%s NOTICE %s :*** Notice -- please disregard"
                    " them, as they are the monitor in action.", me.name, 
                    nick);
            sendto_one(sptr, ":%s NOTICE %s :*** Notice -- For more information"
                    " please visit %s", me.name, nick, ProxyMonURL);
        }

        /* do this late because of oper masking */
	clones_add(sptr);
    }
    else if (IsServer(cptr)) 
    {
        aClient    *acptr;

        /* do this early because exit_client() calls clones_remove() */
	clones_add(sptr);
        
        if ((acptr = find_server(user->server, NULL)) &&
            acptr->from != sptr->from)
        {
            sendto_realops_lev(DEBUG_LEV,
                               "Bad User [%s] :%s USER %s@%s %s, != %s[%s]",
                               cptr->name, nick, user->username,
                               user->host, user->server,
                               acptr->name, acptr->from->name);
            sendto_one(cptr, ":%s KILL %s :%s (%s != %s USER from wrong "
                       "direction)", me.name, sptr->name, me.name,
                       user->server, acptr->from->name);
            sptr->flags |= FLAGS_KILLED;
            return exit_client(sptr, sptr, &me, "USER server wrong direction");
                        
        }
        /*
         * Super GhostDetect: If we can't find the server the user is
         * supposed to be on, then simply blow the user away.     -Taner
         */
        if (!acptr)
        {
            sendto_one(cptr,
                       ":%s KILL %s :%s GHOST (no server %s on the net)",
                       me.name, sptr->name, me.name, user->server);
            sendto_realops("No server %s for user %s[%s@%s] from %s",
                           user->server, sptr->name, user->username,
                           user->host, sptr->from->name);
            sptr->flags |= FLAGS_KILLED;
            return exit_client(sptr, sptr, &me, "Ghosted Client");
        }

        /* scan for aliases too */
        if(IsULine(sptr))
        {
            AliasInfo *ai;

            for (ai = aliastab; ai->nick; ai++)
            {
                if (!mycmp(ai->server, user->server)
                    && !mycmp(ai->nick, sptr->name))
                {
                    user->alias = ai;
                    ai->client = sptr;
                    break;
                }
            }
        }
    }
    send_umode(NULL, sptr, 0, SEND_UMODES, ubuf);
    if (!*ubuf)
    {
        ubuf[0] = '+';
        ubuf[1] = '\0';
    }
    hash_check_watch(sptr, RPL_LOGON);

    sendto_serv_butone_nickipstr(cptr, 1, "NICK %s %d %ld %s %s %s %s %lu %s :%s",
				 nick, sptr->hopcount + 1, sptr->tsinfo, ubuf,
				 user->username, user->host, user->server,
				 sptr->user->servicestamp,
				 cipntoa(sptr), sptr->info);
    sendto_serv_butone_nickipstr(cptr, 0, "NICK %s %d %ld %s %s %s %s %lu %u :%s",
				 nick, sptr->hopcount + 1, sptr->tsinfo, ubuf,
				 user->username, user->host, user->server,
				 sptr->user->servicestamp,
				 (sptr->ip_family == AF_INET) ?
				 htonl(sptr->ip.ip4.s_addr) : 1, sptr->info);

    if(MyClient(sptr))
    {
        /* if the I:line doesn't have a password and the user does
         * send it over to NickServ
         */
        if (sptr->passwd[0] && aliastab[AII_NS].client && !svspanic)
            sendto_alias(&aliastab[AII_NS], sptr, "SIDENTIFY %s",sptr->passwd);

        memset(sptr->passwd, '\0', PASSWDLEN);
        
        if (ubuf[1]) send_umode(cptr, sptr, 0, ALL_UMODES, ubuf);

        if(call_hooks(CHOOK_POSTMOTD, sptr) == FLUSH_BUFFER)
            return FLUSH_BUFFER;
    }

#ifdef RWHO_PROBABILITY
    probability_add(sptr);
#endif

    return 0;
}

char *exploits_2char[] =
{
    "js",
    "pl",
    NULL
};
char *exploits_3char[] = 
{
    "exe",
    "com",
    "bat",
    "dll",
    "ini",
    "vbs",
    "pif",
    "mrc",
    "scr",
    "doc",
    "xls",
    "lnk",
    "shs",
    "htm",
    "zip",
    "rar",
    NULL
};

char *exploits_4char[] =
{
    "html",
    NULL
};

static int
allow_dcc(aClient *to, aClient *from)
{
    Link *lp;

    for(lp = to->user->dccallow; lp; lp = lp->next)
    {
        if(lp->flags == DCC_LINK_ME && lp->value.cptr == from)
            return 1;
    }
    return 0;
}

static int 
check_dccsend(aClient *from, aClient *to, char *msg)
{
    /*
     * we already know that msg will consist of "DCC SEND" so we can skip
     * to the end
     */
    char *filename = msg + 8;
    char *ext;
    char **farray = NULL;
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

    if(*filename == '"')
    {
        filename++;

        if(!(*filename)) return 0;

        while(*(filename + len) != '"')
        {
            if(!(*(filename + len))) break;
            len++;
        }
    }
    else
    {
        while(*(filename + len) != ' ')
        {
            if(!(*(filename + len))) break;
            len++;
        }
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
        case 0:
            arraysz = 0;
            break;

        case 2:
            farray = exploits_2char;
            arraysz = 2;
            break;

        case 3:
            farray = exploits_3char;
            arraysz = 3;
            break;

        case 4:
            farray = exploits_4char;
            arraysz = 4;
            break;

        /* no executable file here.. */
        default:
            return 0;
    }

    if (arraysz != 0)
    {
        for(i = 0; farray[i]; i++)
        {
            if(myncmp(farray[i], ext, arraysz) == 0)
            break;
        }

        if(farray[i] == NULL)
            return 0;
    }

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

        sendto_one(from, ":%s NOTICE %s :The user %s is not accepting DCC "
                   "sends of filetype *.%s from you.  Your file %s was not "
                   "sent.", me.name, from->name, to->name, tmpext, tmpfn);

        sendto_one(to, ":%s NOTICE %s :%s (%s@%s) has attempted to send you a "
                   "file named %s, which was blocked.", me.name, to->name,
                   from->name, from->user->username,
#ifdef USER_HOSTMASKING
                   IsUmodeH(from)?from->user->mhost:
#endif
                                                    from->user->host,
                   tmpfn);

        if(!SeenDCCNotice(to))
        {
            SetDCCNotice(to);
 
            sendto_one(to, ":%s NOTICE %s :The majority of files sent of this "
                       "type are malicious viruses and trojan horses."
                       " In order to prevent the spread of this problem, we "
                       "are blocking DCC sends of these types of"
                       " files by default.", me.name, to->name);
            sendto_one(to, ":%s NOTICE %s :If you trust %s, and want him/her "
                       "to send you this file, you may obtain"
                       " more information on using the dccallow system by "
                       "typing /dccallow help",
                       me.name, to->name, from->name);
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
            sendto_realops_lev(DCCSEND_LEV, "%s (%s@%s) sending forbidden "
                               "filetyped file %s to %s (channel %s)",
                               from->name, from->user->username,
                               from->user->host, tmpfn, to->name,
                               chptr->chname); 
        else
            sendto_realops_lev(DCCSEND_LEV, "%s (%s@%s) sending forbidden "
                               "filetyped file %s to %s", from->name, 
                               from->user->username, from->user->host, tmpfn,
                               to->name); 

        return 1;
    }
    return 0;
}

/*
 * check target limit: message target rate limiting
 * anti spam control!
 * should only be called for local PERSONS!
 * sptr: client sending message
 * acptr: client receiving message
 *
 * return value:
 * 1: block
 * 0: do nothing
 */

#ifdef MSG_TARGET_LIMIT
int check_target_limit(aClient *sptr, aClient *acptr)
{
    int ti;
    int max_targets;
    time_t tmin = MSG_TARGET_TIME;  /* minimum time to wait before
                                    * another message can be sent */

    /* don't limit opers, people talking to themselves,
     * or people talking to services */
    if(IsOper(sptr) || sptr == acptr || IsULine(acptr) || NoMsgThrottle(sptr))
        return 0;

    max_targets = ((NOW - sptr->firsttime) > MSG_TARGET_MINTOMAXTIME) 
                 ? MSG_TARGET_MAX : MSG_TARGET_MIN;

    for(ti = 0; ti < max_targets; ti++)
    {
        if (sptr->targets[ti].cli == NULL || sptr->targets[ti].cli == acptr || 
            sptr->targets[ti].sent < (NOW - MSG_TARGET_TIME))
        {
            sptr->targets[ti].cli = acptr;
            sptr->targets[ti].sent = NOW;
            break;
        }
        else if((NOW - sptr->targets[ti].sent) < tmin)
            tmin = NOW - sptr->targets[ti].sent;
    }

    if(ti == max_targets)
    {
        sendto_one(sptr, err_str(ERR_TARGETTOFAST), me.name, sptr->name,
                   acptr->name, MSG_TARGET_TIME - tmin);
        if(call_hooks(CHOOK_SPAMWARN, sptr, 1, max_targets, NULL) != FLUSH_BUFFER)
        {
            sptr->since += 2; /* penalize them 2 seconds for this! */
            sptr->num_target_errors++;

            if(sptr->last_target_complain + 60 <= NOW)
            {
                sendto_realops_lev(SPAM_LEV, "Target limited: %s (%s@%s)"
                                   " [%d failed targets]", sptr->name,
                                    sptr->user->username, sptr->user->host, 
                                    sptr->num_target_errors);
                sptr->num_target_errors = 0;
                sptr->last_target_complain = NOW;
            }
        }
        return 1;
    }

    return 0;
}
#endif


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
static int 
check_for_ctcp(char *str, char **dccptr)
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
        /* p was increased twice. 'ACTION' could not be found. -- nicobn */
        if (myncmp(p, "ACTION", 6) != 0)
            return CTCP_YES;
        if ((p = strchr(p, 1)) == NULL)
            return CTCP_NONE;
        if(!(*(++p)))
            break;;
    }
    return CTCP_NONE;
}

/* is_silenced - Returns 1 if a sptr is silenced by acptr */
int
is_silenced(aClient *sptr, aClient *acptr)
{
    Link *lp;
    anUser *user;
    char sender[HOSTLEN+1+USERLEN+1+HOSTLEN+1];

    if (!(acptr->user)||!(lp=acptr->user->silence)||!(user=sptr->user))
        return 0;
    ircsprintf(sender,"%s!%s@%s",sptr->name,user->username,user->host);
    while(lp)
    {
        if (!match(lp->value.cp, sender))
        {
            if (!MyConnect(sptr))
            {
                sendto_one(sptr->from, ":%s SILENCE %s :%s",acptr->name,
                           sptr->name, lp->value.cp);
                lp->flags = 1;
            }
            return 1;
        }
        lp = lp->next;
    }
    return 0;
}

static inline time_t get_highest(time_t val1, time_t val2)
{
    if(val1 > val2) return val1;
    else return val2;
}

static inline void 
send_msg_error(aClient *sptr, char *parv[], char *nick, int ret, aChannel *chptr) 
{
    if(ret == ERR_NOCTRLSONCHAN)
        sendto_one(sptr, err_str(ERR_NOCTRLSONCHAN), me.name,
                   parv[0], nick, parv[2]);
    else if(ret == ERR_NEEDTOWAIT)
    {
        sendto_one(sptr, err_str(ERR_NEEDTOWAIT), me.name,
                   parv[0], get_highest((sptr->firsttime + chptr->talk_connect_time - NOW), get_user_jointime(sptr, chptr) + chptr->talk_join_time - NOW), chptr->chname);
    }
    else if(ret == ERR_NEEDREGGEDNICK)
        sendto_one(sptr, err_str(ERR_NEEDREGGEDNICK), me.name,
                   parv[0], nick, "speak in", aliastab[AII_NS].nick,
                   aliastab[AII_NS].server, NS_Register_URL);
    else
        sendto_one(sptr, err_str(ERR_CANNOTSENDTOCHAN), me.name,
                   parv[0], nick);
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
 * again -Quension [Jul 2004]
 * 
 */
static int
m_message(aClient *cptr, aClient *sptr, int parc, char *parv[], int notice)
{
    aClient *acptr;
    aChannel *chptr;
    char *cmd;
    int ismine;
    int ret;
    char *s;
    char *p = NULL;
    char *target;
    char *dccmsg;
    int tleft = MAXRECIPIENTS;  /* targets left */
    char channel[CHANNELLEN + 1]; /* for the auditorium mode -Kobi. */

    cmd = notice ? MSG_NOTICE : MSG_PRIVATE;
    ismine = MyClient(sptr);

    if (parc < 2 || *parv[1] == 0)
    {
        sendto_one(sptr, err_str(ERR_NORECIPIENT), me.name, parv[0], cmd);
        return -1;
    }

    if (parc < 3 || *parv[2] == 0)
    {
        sendto_one(sptr, err_str(ERR_NOTEXTTOSEND), me.name, parv[0]);
        return -1;
    }

    if (ismine)
    {
        /* if squelched or spamming, allow only messages to self */
        if ((IsSquelch(sptr)
#if defined(ANTI_SPAMBOT) && !defined(ANTI_SPAMBOT_WARN_ONLY)
            || (sptr->join_leave_count >= MAX_JOIN_LEAVE_COUNT)
#endif
            ) && mycmp(parv[0], parv[1]))
        {
            if (IsWSquelch(sptr) && !notice)
                sendto_one(sptr, ":%s NOTICE %s :You are currently squelched."
                            "  Message not sent.", me.name, parv[0]);
            return 0;
        }

        if (call_hooks(CHOOK_MSG, sptr, notice, parv[2]) == FLUSH_BUFFER)
            return FLUSH_BUFFER;

        parv[1] = canonize(parv[1]);
    }

    /* loop on comma-separated targets, until tleft is gone */
    for (target = strtoken(&p, parv[1], ",");
         target && tleft--;
         target = strtoken(&p, NULL, ","))
    {
        int chflags = 0;    /* channel op/voice prefixes */

        /* additional penalty for lots of targets */
        if (ismine && tleft < (MAXRECIPIENTS/2) && !NoMsgThrottle(sptr))
#ifdef NO_OPER_FLOOD
            if (!IsAnOper(sptr))
#endif
                sptr->since += 4;

        /* [@][+]#channel preprocessing */
        s = target;
        while (1)
        {
            if (*s == '@')
                chflags |= CHFL_CHANOP;
            else if (*s == '+')
                chflags |= CHFL_VOICE;
            else
                break;
            s++;
        }

        /* target is a channel */
        if (IsChannelName(s))
        {
            if (!(chptr = find_channel(s, NULL)))
            {
                if (ismine && !notice)
                    sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name, parv[0],
                               target);
                continue;
            }

            if (ismine && call_hooks(CHOOK_CHANMSG, sptr, chptr, notice,
                                     parv[2]) == FLUSH_BUFFER)
                    return FLUSH_BUFFER;

#ifdef SPAMFILTER
            if(!(chptr->mode.mode & MODE_PRIVACY))
            {
                if(ismine && check_sf(sptr, parv[2], notice?"notice":"msg", SF_CMD_CHANNEL, chptr->chname))
                    return FLUSH_BUFFER;
            }
#endif

            /* servers and super sources get free sends */
            if (IsClient(sptr) && !IsULine(sptr))
            {
                if ((ret = can_send(sptr, chptr, parv[2])))
                {
                    if (ismine && !notice)
                        send_msg_error(sptr, parv, target, ret, chptr);
                    if(chptr->xflags & XFLAG_USER_VERBOSE)
                        verbose_to_relaychan(sptr, chptr, notice?"notice":"message", parv[2]);
                    if(chptr->xflags & XFLAG_OPER_VERBOSE)
                        verbose_to_opers(sptr, chptr, notice?"notice":"message", parv[2]);
                    continue;
                }

                if (notice && (chptr->xflags & XFLAG_NO_NOTICE) && !is_xflags_exempted(sptr,chptr))
                {
                    if(chptr->xflags & XFLAG_USER_VERBOSE)
                        verbose_to_relaychan(sptr, chptr, "notice", parv[2]);
                    if(chptr->xflags & XFLAG_OPER_VERBOSE)
                        verbose_to_opers(sptr, chptr, "notice", parv[2]);
                    continue;
                }

                if((chptr->mode.mode & MODE_AUDITORIUM) && !is_chan_opvoice(sptr, chptr))
                {
                    /* Channel is in auditorium mode! */
                    if(strlen(chptr->chname)+6 > CHANNELLEN) continue; /* Channel is too long.. we must be able to add
                                                                           -relay to it... */
                    strcpy(channel, chptr->chname);
                    strcat(channel, "-relay");
                    if(!(chptr = find_channel(channel, NULL))) continue; /* Can't find the relay channel... */
                    /* I originally thought it's a good idea to enforce #chan-relay modes but then I figured out we
                       would most likely want to have it +snt and only accept messages from #chan members... -Kobi.
                    if ((ret = can_send(sptr, chptr, parv[2])))
                    {
                        if (ismine && !notice)
                            send_msg_error(sptr, parv, target, ret, chptr);
                        continue;
                    }
                    */
                    s = target = chptr->chname; /* We want ops to see the message coming to #chan-relay and not to #chan */
                }

                if (!notice)
                {
                    switch (check_for_ctcp(parv[2], NULL))
                    {
                        case CTCP_NONE:
                            break;

                        case CTCP_DCCSEND:
                        case CTCP_DCC:
                            if (ismine)
                                sendto_one(sptr, ":%s NOTICE %s :You may not"
                                           " send a DCC command to a channel"
                                           " (%s)", me.name, parv[0], target);
                            continue;
#ifdef FLUD
                        default:
                            if (check_for_flud(sptr, NULL, chptr, 1))
                                return 0;
#endif
                            if ((chptr->xflags & XFLAG_NO_CTCP) && !is_xflags_exempted(sptr,chptr))
                            {
                                if(chptr->xflags & XFLAG_USER_VERBOSE)
                                    verbose_to_relaychan(cptr, chptr, "ctcp", "xflag_no_ctcp");
                                if(chptr->xflags & XFLAG_OPER_VERBOSE)
                                    verbose_to_opers(cptr, chptr, "ctcp", "xflag_no_ctcp");
                                continue;
                            }
                    }
                }
            }

            if (chflags)
            {
                /* don't let clients do stuff like @+@@+++@+@@@#channel */
                if (chflags & CHFL_VOICE)
                    *--s = '+';
                if (chflags & CHFL_CHANOP)
                    *--s = '@';

                sendto_channelflags_butone(cptr, sptr, chptr, chflags,
                                           ":%s %s %s :%s", parv[0], cmd, s,
                                           parv[2]);
            }
            else
                sendto_channel_butone(cptr, sptr, chptr, ":%s %s %s :%s",
                                      parv[0], cmd, target, parv[2]);

            /* next target */
            continue;
        }

        /* prefixes are only valid for channel targets */
        if (s != target)
        {
            if (!notice)
                sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name, parv[0],
                       target);
            continue;
        }

        /* target is a $servermask */
        if (*target == '$')
        {
            s++;

            /* allow $$servermask */
            if (*s == '$')
                s++;

            if (ismine)
            {
                /* need appropriate privs */
                if (!OPCanLNotice(sptr) ||
                    (mycmp(me.name, s) && !OPCanGNotice(sptr)))
                {
                    sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name,
                               parv[0], target);
                    continue;
                }
            }

            sendto_all_servmask(sptr, s, ":%s %s %s :%s", parv[0], cmd,
                                target, parv[2]);

            /* next target */
            continue;
        }

        /* target is a nick@server */
        if ((s = strchr(target, '@')))
            *s = 0;

        /* target is a client */
        if ((acptr = find_client(target, NULL)))
        {
            if (s)
                *s++ = '@';

            if (ismine && IsMe(acptr))
            {
                if (call_hooks(CHOOK_MYMSG, sptr, notice, parv[2])
                    == FLUSH_BUFFER)
                    return FLUSH_BUFFER;

                continue;
            }

            if (!IsClient(acptr))
                acptr = NULL;
        }

        /* nonexistent client or wrong @server */
        if (!acptr || (s && mycmp(acptr->user->server, s)))
        {
            if (!notice)
                sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name, parv[0],
                           target);
            continue;
        }

        /* super targets get special treatment */
        if (IsULine(acptr))
        {
            AliasInfo *ai;

            if (notice && (confopts & FLAGS_SERVHUB) && (acptr->uplink->serv->uflags & ULF_NONOTICE))
                continue;

            if (ismine && !notice && (ai = acptr->user->alias))
            {
#ifdef DENY_SERVICES_MSGS
                if (!s && !mycmp(ai->server, Services_Name))
                {
                    sendto_one(sptr, err_str(ERR_MSGSERVICES), me.name,
                               parv[0], ai->nick, ai->nick, ai->server,
                               ai->nick);
                    continue;
                }
#endif
#ifdef PASS_SERVICES_MSGS
                if (s)  /* if passing, skip this and use generic send below */
#endif
                {
                    sendto_alias(ai, sptr, "%s", parv[2]);
                    continue;
                }
            }

            if((svspanic>1 || (svspanic>0 && !IsARegNick(sptr))) && !IsOper(sptr))
            {
                if(MyClient(sptr))
                    sendto_one(sptr, err_str(ERR_SERVICESDOWN), me.name, parv[0],
                               acptr->name);
                continue;
            }

            /* no flood/dcc/whatever checks, just send */
            sendto_one(acptr, ":%s %s %s :%s", parv[0], cmd, target,
                       parv[2]);
            continue;
        }
#ifdef SUPER_TARGETS_ONLY
        else if (s && ismine)
        {
            if (!notice)
                sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name, parv[0],
                       target);
            continue;
        }
#endif

        if (ismine)
        {
            if (call_hooks(CHOOK_USERMSG, sptr, acptr, notice, parv[2])
                == FLUSH_BUFFER)
                return FLUSH_BUFFER;

#ifdef MSG_TARGET_LIMIT
            if (check_target_limit(sptr, acptr))
                continue;
#endif

#ifdef SPAMFILTER
            if(!IsUmodeP(acptr) && check_sf(sptr, parv[2], notice?"notice":"msg", notice?SF_CMD_NOTICE:SF_CMD_PRIVMSG, acptr->name))
                return FLUSH_BUFFER;
#endif
        }

        /* servers and super sources skip flood/silence checks */
        if (IsClient(sptr) && !IsULine(sptr))
        {
            if (IsNoNonReg(acptr) && !IsRegNick(sptr) && !IsOper(sptr))
            {
                if (ismine && !notice)
                    sendto_one(sptr, err_str(ERR_NONONREG), me.name, parv[0],
                           target);
                continue;
            }
            if (IsUmodeC(acptr) && !IsOper(sptr) && (!IsNoNonReg(acptr) || IsRegNick(sptr)) && acptr->user->joined && !find_shared_chan(sptr, acptr))
            {
                if (ismine && !notice)
                    sendto_one(sptr, err_str(ERR_NOSHAREDCHAN), me.name, parv[0],
                           target);
                continue;
            }
            if (ismine && IsNoNonReg(sptr) && !IsRegNick(acptr) && !IsOper(acptr))
            {
                if (!notice)
                    sendto_one(sptr, err_str(ERR_OWNMODE), me.name, parv[0],
                           acptr->name, "+R");
                continue;
            }
            if (ismine && IsUmodeC(sptr) && !IsOper(sptr) && (!IsNoNonReg(sptr) || IsRegNick(acptr)) && sptr->user->joined && !find_shared_chan(sptr, acptr))
            {
                if (!notice)
                    sendto_one(sptr, err_str(ERR_OWNMODE), me.name, parv[0],
                           acptr->name, "+C");
                continue;
            }

#ifdef FLUD
            if (!notice && MyFludConnect(acptr))
#else
            if (!notice && MyConnect(acptr))
#endif
            {
                switch (check_for_ctcp(parv[2], &dccmsg))
                {
                    case CTCP_NONE:
                        break;

                    case CTCP_DCCSEND:
#ifdef FLUD
                        if (check_for_flud(sptr, acptr, NULL, 1))
                            return 0;
#endif
                        if (check_dccsend(sptr, acptr, dccmsg))
                            continue;
                        break;

#ifdef FLUD
                    default:
                        if (check_for_flud(sptr, acptr, NULL, 1))
                            return 0;
#endif
                }
            }

            if (is_silenced(sptr, acptr))
                continue;
        }

        if (!notice && ismine && acptr->user->away)
            sendto_one(sptr, rpl_str(RPL_AWAY), me.name, parv[0], acptr->name,
                       acptr->user->away);

        sendto_prefix_one(acptr, sptr, ":%s %s %s :%s", parv[0], cmd, target,
                          parv[2]);

        /* next target */
        continue;
    }

    /* too many targets */
    if (target)
    {
        if (!notice)
            sendto_one(sptr, err_str(ERR_TOOMANYTARGETS), me.name, parv[0],
                   target);

        if (sptr->user)
            sendto_realops_lev(SPY_LEV, "User %s (%s@%s) tried to %s more than"
                               " %d targets", sptr->name, sptr->user->username,
                               sptr->user->host, notice ? "notice" : "msg",
                               MAXRECIPIENTS);
    }

    return 0;
}

/*
 * m_private 
 * parv[0] = sender prefix 
 * parv[1] = receiver list 
 * parv[2] = message text
 */

int 
m_private(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    return m_message(cptr, sptr, parc, parv, 0);
}

/*
 * m_notice *
 * parv[0] = sender prefix 
 * parv[1] = receiver list
 * parv[2] = notice text
 */

int 
m_notice(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    return m_message(cptr, sptr, parc, parv, 1);
}


/*
 * m_whois 
 * parv[0] = sender prefix 
 * parv[1] = nickname masklist
 */
int 
m_whois(aClient *cptr, aClient *sptr, int parc, char *parv[])
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
        /*
         * Block /whois <anything> <nick1,nick2,nick3>
         * Also block /whois <server> <nick> for +I users
         */
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
                /* allow /whois nick nick, but nothing else */
                if(mycmp(parv[1], parv[2]) == 0)
                    parv[1] = acptr->user->server; /* And kludge it */
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
        mlen = strlen(me.name) + strlen(parv[0]) + 6 + strlen(name);
        for (len = 0, *buf = '\0', lp = user->channel; lp; lp = lp->next)
        {
            chptr = lp->value.chptr;
            showchan=ShowChannel(sptr,chptr);
            if (showchan || IsAdmin(sptr))
            {
                if (len + strlen(chptr->chname) > (size_t) BUFSIZE - 4 - mlen)
                {
                    sendto_one(sptr, ":%s %d %s %s :%s", me.name, 
                               RPL_WHOISCHANNELS, parv[0], name, buf);
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
        else /* hidden oper! */
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
        
        buf[0] = '\0';
        if (IsAnOper(acptr))
            strcat(buf, "an IRC Operator");
        if (IsAdmin(acptr))
            strcat(buf, " - Server Administrator");
        else if (IsSAdmin(acptr))
            strcat(buf, " - Services Administrator");
        /* We don't go through the services tag list here by design, only the first services tag entry
           may change RPL_WHOISOPERATOR -Kobi_S. */
        if (buf[0] && (!acptr->user->servicestag || acptr->user->servicestag->raw!=RPL_WHOISOPERATOR))
            sendto_one(sptr, rpl_str(RPL_WHOISOPERATOR), me.name, parv[0], 
                       name, buf);

        if(acptr->user->servicestag)
        {
            servicestag = acptr->user->servicestag;
            while(servicestag)
            {
                if(*servicestag->tag && (!servicestag->umode || (sptr->umode & servicestag->umode))) sendto_one(sptr, ":%s %d %s %s :%s", me.name, servicestag->raw, parv[0], name, servicestag->tag);
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

        /* don't give away that this oper is on this server if they're hidden! */
        if (acptr->user && MyConnect(acptr) && ((sptr == acptr) || 
                !IsUmodeI(acptr) || (parc > 2) || IsAnOper(sptr)))
            sendto_one(sptr, rpl_str(RPL_WHOISIDLE), me.name, parv[0], name,
                       timeofday - user->last, acptr->firsttime);
        
        continue;
    }
    sendto_one(sptr, rpl_str(RPL_ENDOFWHOIS), me.name, parv[0], parv[1]);
    return 0;
}

/*
 * m_user 
 * parv[0] = sender prefix
 * parv[1] = username (login name, account) 
 * parv[2] = client host name (used only from other servers) 
 * parv[3] = server host name (used only from other servers)
 * parv[4] = users real name info
 */
int 
m_user(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    char       *username, *host, *server, *realname;
    struct simBan *ban;

    /* FTP proxy */
    if (!IsRegistered(cptr) && parc == 2 && cptr->receiveM == 1)
        return reject_proxy(cptr, "USER", parv[1]);
    
    if (parc > 2 && (username = (char *) strchr(parv[1], '@')))
        *username = '\0';
    if (parc < 5 || *parv[1] == '\0' || *parv[2] == '\0' ||
        *parv[3] == '\0' || *parv[4] == '\0')
    {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0], "USER");
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
    if ((ban = check_mask_simbanned(realname, SBAN_GCOS))) 
    {
        int loc = (ban->flags & SBAN_LOCAL) ? 1 : 0;
        return exit_banned_client(cptr, loc, 'G', ban->reason, 0);
    }
    if(call_hooks(CHOOK_ONACCESS, cptr, username, host, server, realname) == FLUSH_BUFFER) return 0;
    return do_user(parv[0], cptr, sptr, username, host, server, 0,0, realname);
}

/* do_user */
int 
do_user(char *nick, aClient *cptr, aClient *sptr, char *username, char *host, 
        char *server, unsigned long serviceid, char *ip, char *realname)
{
    anUser     *user;
    
    user = make_user(sptr);
    
    /*
     * changed the goto into if-else...   -Taner 
     * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ GOOD FOR YOU Taner!!! - Dianora 
     */
    
    if (!MyConnect(sptr))
    {
        user->server = find_or_add(server);
        strncpyzt(user->host, host, sizeof(user->host));
#ifdef USER_HOSTMASKING
        strncpyzt(user->mhost, mask_host(host,0), HOSTLEN + 1);
#endif
    } 
    else
    {
        if (!IsUnknown(sptr))
        {
            sendto_one(sptr, err_str(ERR_ALREADYREGISTRED),
                       me.name, nick);
            return 0;
        }
        sptr->umode |= (USER_UMODES & atoi(host));
#ifndef NO_DEFAULT_INVISIBLE
        sptr->umode |= UMODE_i;
#endif
#ifdef USE_SSL
        if(IsSSL(sptr))
            sptr->umode |= UMODE_S;
#endif
#ifdef NO_USER_SERVERKILLS
        sptr->umode &= ~UMODE_k;
#endif
#ifdef NO_USER_OPERKILLS
        sptr->umode &= ~UMODE_s;
#endif
        strncpyzt(user->host, host, sizeof(user->host));
#ifdef USER_HOSTMASKING
        if(uhm_type > 0) sptr->umode |= UMODE_H;
        else sptr->umode &= ~UMODE_H;
#endif
        user->server = me.name;
    }
    strncpyzt(sptr->info, realname, sizeof(sptr->info));
    
    sptr->user->servicestamp = serviceid;
    if (!MyConnect(sptr))  
    {
	if (inet_pton(AF_INET, ip, &sptr->ip.ip4) == 1)
	{
	    if (sptr->ip.ip4.s_addr != htonl(1))
		sptr->ip_family = AF_INET;
	    else
		sptr->ip_family = 0;
	}
	else if (inet_pton(AF_INET6, ip, &sptr->ip.ip6) == 1)
	    sptr->ip_family = AF_INET6;
	else
	{
	    char *end;
	    unsigned long l;

	    l = ntohl(strtoul(ip, &end, 10));
	    if (*ip != '\0' && *end == '\0')
	    {
		if (l != htonl(1))
		    sptr->ip_family = AF_INET;
		else
		    sptr->ip_family = 0;

		sptr->ip.ip4.s_addr = l;
		ip = inetntoa((char *)&sptr->ip);
	    }
	    else
		sptr->ip_family = 0;
	}

        /* add non-local clients to the throttle checker.  obviously, we only
         * do this for REMOTE clients!@$$@!  throttle_check() is called
         * elsewhere for the locals! -wd */
#ifdef THROTTLE_ENABLE
	if (sptr->ip_family == 0)
	    ;
	else if (sptr->ip_family == AF_INET && sptr->ip.ip4.s_addr == 0)
	    ;
	else
	    throttle_check(ip, -1, sptr->tsinfo);
#endif
    }
    if(MyConnect(sptr))
        sptr->oflag=0;
    if (sptr->name[0])          /* NICK already received, now I have USER... */
        return register_user(cptr, sptr, sptr->name, username, ip);
    else
        strncpyzt(sptr->user->username, username, USERLEN + 1);
    return 0;
}

/*
 * m_quit 
 * parv[0] = sender prefix 
 * parv[1] = comment
 */
int 
m_quit(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    char *reason = (parc > 1 && parv[1]) ? parv[1] : cptr->name;
    char  comment[TOPICLEN + 1];
    int blocked;
    aChannel *chptr;
    Link *lp, *lpn;
    
    sptr->flags |= FLAGS_NORMALEX;
    if (!IsServer(cptr))
    {
        if(IsSquelch(sptr))
            reason = cptr->name;
        strcpy(comment, "Quit: ");
        strncpy(comment + 6, reason, TOPICLEN - 6); 
        comment[TOPICLEN] = 0;
#ifdef SPAMFILTER
        if(IsPerson(sptr))
        {
            if((blocked = check_sf(sptr, reason, "quit", SF_CMD_QUIT, sptr->name)))
            {
                for(lp = sptr->user->channel; lp; lp = lpn)
                {
                    lpn = lp->next;
                    chptr = lp->value.chptr;
                    if(!(chptr->mode.mode & MODE_PRIVACY))
                    {
                        sendto_serv_butone(cptr, ":%s PART %s", parv[0], chptr->chname);
                        sendto_channel_butserv(chptr, sptr, ":%s PART %s", parv[0], chptr->chname);
                        remove_user_from_channel(sptr, chptr);
                    }
                }
            }
            else
            {
                for(lp = sptr->user->channel; lp; lp = lpn)
                {
                    lpn = lp->next;
                    chptr = lp->value.chptr;
                    if((chptr->xflags & XFLAG_NO_QUIT_MSG) && !is_xflags_exempted(sptr,chptr))
                    {
                        if(chptr->xflags & XFLAG_USER_VERBOSE)
                            verbose_to_relaychan(cptr, chptr, "quit_msg", comment);
                        if(chptr->xflags & XFLAG_OPER_VERBOSE)
                            verbose_to_opers(cptr, chptr, "quit_msg", comment);
                        sendto_serv_butone(cptr, ":%s PART %s", parv[0], chptr->chname);
                        sendto_channel_butserv(chptr, sptr, ":%s PART %s", parv[0], chptr->chname);
                        remove_user_from_channel(sptr, chptr);
                    }
                }
            }
        }
#endif

        return exit_client(cptr, sptr, sptr, comment);
    }
    else
        return exit_client(cptr, sptr, sptr, reason);
}

/*
 * m_kill 
 * parv[0] = sender prefix 
 * parv[1] = kill victim 
 * parv[2] = kill path
 */
int 
m_kill(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aClient    *acptr;
    char       *user, *path, *p, *nick, *reason;
    char        mypath[KILLLEN + 1];
    char        mymsg[KILLLEN + 1];
    char       *unknownfmt = "<Unknown>";       /*
                                                 * AFAIK this shouldnt happen
                                                 * but -Raist 
                                                 */
    int         chasing = 0, kcount = 0;
    
    if (parc < 2 || *parv[1] == '\0')
    {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0], "KILL");
        return 0;
    }
    
    user = parv[1];
    path = parv[2];             /* Either defined or NULL (parc >= 2!!) */
    
    if (!IsPrivileged(cptr))
    {
        sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
        return 0;
    }

    if (!BadPtr(path))
        if (strlen(path) > (size_t) KILLLEN)
            path[KILLLEN] = '\0';

    if (MyClient(sptr))
        user = canonize(user);
    for (p = NULL, nick = strtoken(&p, user, ","); nick; 
         nick = strtoken(&p, NULL, ","))
    {
        chasing = 0;
        if (!(acptr = find_client(nick, NULL)))
        {
            /*
             * If the user has recently changed nick, we automaticly
             * rewrite the KILL for this new nickname--this keeps
             * servers in synch when nick change and kill collide
             */
            if (!(acptr = get_history(nick, (long) KILLCHASETIMELIMIT)))
            {
                sendto_one(sptr, err_str(ERR_NOSUCHNICK),
                           me.name, parv[0], nick);
                return 0;
            }
            sendto_one(sptr, ":%s NOTICE %s :KILL changed from %s to %s",
                       me.name, parv[0], nick, acptr->name);
            chasing = 1;
        }
        if((!MyConnect(acptr) && MyClient(cptr) && !OPCanGKill(cptr)) ||
            (MyConnect(acptr) && MyClient(cptr) && !OPCanLKill(cptr)))
        {
            sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
            continue;
        }
        if(IsServer(acptr) || IsMe(acptr) || (MyClient(sptr) && IsULine(acptr)))
        {
            sendto_one(sptr, err_str(ERR_CANTKILLSERVER),
                       me.name, parv[0]);
            continue;
        }
        kcount++;
        if (!IsServer(sptr) && (kcount > MAXKILLS))
        {
            sendto_one(sptr,":%s NOTICE %s :Too many targets, kill list was "
                       "truncated. Maximum is %d.", me.name, sptr->name,
                       MAXKILLS);
            break;
        }
        if(MyClient(sptr)) 
        {
            char myname[HOSTLEN+1], *s;

            if(!BadPtr(path))
            {
                ircsnprintf(mymsg, KILLLEN + 1, "(%s)", path);
                reason = mymsg;
            }
            else
                reason = "(No reason specified)";

            strncpy(myname, me.name, HOSTLEN + 1);
            if((s = strchr(myname, '.')))
                *s = 0;
            
            ircsnprintf(mypath, KILLLEN + 1, "%s!%s!%s", myname, 
#ifdef USER_HOSTMASKING
                        IsUmodeH(sptr)?sptr->user->mhost:
#endif
                        sptr->user->host,
                        sptr->user->username); 
        }
        else
        {
            if(BadPtr(path) || !(reason = strchr(path, ' ')))
            {
                path = sptr->name;
                reason = "(No reason specified)";
            }
            else
            {
                *reason = '\0';
                reason++;
            }
            strncpyzt(mypath, path, KILLLEN + 1);
        }
        /*
         * Notify all *local* opers about the KILL, this includes the
         * one originating the kill, if from this server--the special
         * numeric reply message is not generated anymore.
         * 
         * Note: "acptr->name" is used instead of "user" because we may
         * have changed the target because of the nickname change.
         */
        if (IsLocOp(sptr) && !MyConnect(acptr)) 
        {
            sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
            return 0;
        }
        if(IsULine(sptr))
            sendto_realops_lev(USKILL_LEV, 
                           "Received KILL message for %s!%s@%s. "
                           "From %s Path: %s %s", acptr->name,
                           acptr->user ? acptr->user->username : unknownfmt,
                           acptr->user ?
#ifdef USER_HOSTMASKING
                             IsUmodeH(acptr)?acptr->user->mhost:
#endif
                             acptr->user->host : unknownfmt,
                           parv[0], mypath, reason);
        else if (IsAnOper(sptr))
            sendto_ops_lev(0,
                           "Received KILL message for %s!%s@%s. From %s "
                           "Path: %s %s", acptr->name, 
                           acptr->user ? acptr->user->username : unknownfmt,
                           acptr->user ?
#ifdef USER_HOSTMASKING
                             IsUmodeH(acptr)?acptr->user->mhost:
#endif
                             acptr->user->host : unknownfmt,
                           parv[0], mypath, reason);
        else
            sendto_ops_lev(SKILL_LEV, 
                           "Received KILL message for %s!%s@%s. "
                           "From %s Path: %s %s", acptr->name,
                           acptr->user ? acptr->user->username : unknownfmt,
                           acptr->user ?
#ifdef USER_HOSTMASKING
                             IsUmodeH(acptr)?acptr->user->mhost:
#endif
                             acptr->user->host : unknownfmt,
                           parv[0], mypath, reason);
                
#if defined(USE_SYSLOG) && defined(SYSLOG_KILL)
        if (IsOper(sptr))
            syslog(LOG_INFO, "KILL From %s!%s@%s For %s Path %s %s",
                  parv[0], acptr->name,
                  acptr->user ? acptr->user->username : unknownfmt,
                  acptr->user ? acptr->user->host : unknownfmt, mypath, reason);
#endif
        /*
         * And pass on the message to other servers. Note, that if KILL
         * was changed, the message has to be sent to all links, also
         * back. Suicide kills are NOT passed on --SRB
         */
        /*
         * Set FLAGS_KILLED. This prevents exit_one_client from sending
         * the unnecessary QUIT for this. ,This flag should never be
         * set in any other place...
         */
        if(!MyConnect(acptr) || !MyConnect(sptr) || !IsAnOper(sptr))
        {
            sendto_serv_butone(cptr, ":%s KILL %s :%s %s",
                               parv[0], acptr->name, mypath, reason);
            if (chasing && IsServer(cptr))
                sendto_one(cptr, ":%s KILL %s :%s %s",
                           me.name, acptr->name, mypath, reason);
            acptr->flags |= FLAGS_KILLED;
        }
        /*
         * Tell the victim she/he has been zapped, but *only* if the
         * victim is on current server--no sense in sending the
         * notification chasing the above kill, it won't get far anyway
         * as this user don't exist there any more either
         */
#ifndef HIDE_KILL_ORIGINS
        if (MyConnect(acptr))
            sendto_prefix_one(acptr, sptr, ":%s KILL %s :%s %s",
                              parv[0], acptr->name, mypath, reason);

        if (MyConnect(acptr) && MyConnect(sptr) && IsAnOper(sptr))
            ircsprintf(buf2, "Local kill by %s %s", sptr->name, reason);
        else 
            ircsprintf(buf2, "Killed (%s %s)", sptr->name, reason);
#else
        if (MyConnect(acptr))
            sendto_one(acptr, ":%s KILL %s :%s %s",
                       HIDDEN_SERVER_NAME, acptr->name,
                       HIDDEN_SERVER_NAME, reason);

        ircsprintf(buf2, "Killed (%s %s)", HIDDEN_SERVER_NAME, reason);
#endif

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
 *            but perhaps it's worth the load it causes to net.
 *            This requires flooding of the whole net like NICK,
 *            USER, MODE, etc messages...  --msa
 *
 *            Added FLUD-style limiting for those lame scripts out there.
 ***********************************************************************/
/*
 * m_away 
 * parv[0] = sender prefix 
 * parv[1] = away message
 */
int 
m_away(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    char   *away, *awy2 = parv[1];
    /* make sure the user exists */
    if (!(sptr->user)) 
    {
        sendto_realops_lev(DEBUG_LEV, "Got AWAY from nil user, from %s (%s)\n",
                           cptr->name, sptr->name);
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
    
    if (parc < 2 || !*awy2)
    {
        /* Marking as not away */
        if (away) 
        {
            MyFree(away);
            sptr->user->away = NULL;
            /* Don't spam unaway unless they were away - lucas */
            sendto_serv_butone_super(cptr, ULF_NOAWAY, ":%s AWAY", parv[0]);
        }
        
        if (MyConnect(sptr))
            sendto_one(sptr, rpl_str(RPL_UNAWAY), me.name, parv[0]);
        return 0;
    }

    /* Marking as away */
#ifdef NO_AWAY_FLUD
    /* we dont care if they are just unsetting away, hence this is here */
    /* only care about local non-opers */
    if (MyClient(sptr) && (sptr->acount > MAX_AWAY_COUNT) && !IsAnOper(sptr))
    {
        sendto_one(sptr, err_str(ERR_TOOMANYAWAY), me.name, parv[0]);
        return 0;
    }
#endif
    if (strlen(awy2) > (size_t) TOPICLEN)
        awy2[TOPICLEN] = '\0';

#ifdef SPAMFILTER
    if(MyClient(sptr) && check_sf(sptr, awy2, "away", SF_CMD_AWAY, sptr->name))
        return FLUSH_BUFFER;
#endif

    /*
     * some lamers scripts continually do a /away, hence making a lot of
     * unnecessary traffic. *sigh* so... as comstud has done, I've
     * commented out this sendto_serv_butone() call -Dianora
     * readded because of anti-flud stuffs -epi
     */
    
    sendto_serv_butone_super(cptr, ULF_NOAWAY, ":%s AWAY :%s", parv[0], parv[1]);

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
 * m_ping 
 * parv[0] = sender prefix 
 * parv[1] = origin
 * parv[2] = destination
 */
int 
m_ping(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aClient    *acptr;
    char       *origin, *destination;
    
    if (parc < 2 || *parv[1] == '\0')
    {
        sendto_one(sptr, err_str(ERR_NOORIGIN), me.name, parv[0]);
        return 0;
    }
    origin = parv[1];
    destination = parv[2];      /* Will get NULL or pointer (parc >= 2!!) */
    
    acptr = find_client(origin, NULL);
    if (!acptr)
        acptr = find_server(origin, NULL);
    if (acptr && acptr != sptr)
        origin = cptr->name;
    if (!BadPtr(destination) && mycmp(destination, me.name) != 0)
    {
        if ((acptr = find_server(destination, NULL)))
            sendto_one(acptr, ":%s PING %s :%s", parv[0], origin, destination);
        else
        {
            sendto_one(sptr, err_str(ERR_NOSUCHSERVER), me.name, parv[0], 
                       destination);
            return 0;
        }
    }
    else
        sendto_one(sptr, ":%s PONG %s :%s", me.name,
                   (destination) ? destination : me.name, origin);
    return 0;
}

/*
 * m_pong 
 * parv[0] = sender prefix 
 * parv[1] = origin
 * parv[2] = destination
 */
int 
m_pong(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aClient    *acptr;
    char       *origin, *destination;

    if (parc < 2 || *parv[1] == '\0')
    {
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
            sendto_gnotice("from %s: %s has processed user/channel burst, "
                           "sending topic burst.", me.name, sptr->name);
            send_topic_burst(sptr);
            sptr->flags |= FLAGS_PINGSENT|FLAGS_SOBSENT;
            sendto_one(sptr, "PING :%s", me.name);
        }
        else if(sptr->flags & FLAGS_TOPICBURST)
        {
            sptr->flags &= ~FLAGS_TOPICBURST;
            sendto_gnotice("from %s: %s has processed topic burst (synched "
                           "to network data).", me.name, sptr->name);

            if(server_was_split)
                server_was_split = NO;

            if(confopts & FLAGS_HUB)
                sendto_serv_butone(sptr, ":%s GNOTICE :%s has synched to"
                               " network data.", me.name, sptr->name);
                /* Kludge: Get the "sync" message on small networks 
                 * immediately */ 
            sendto_one(sptr, "PING :%s", me.name);
        }
    }

    /*
     * Now attempt to route the PONG, comstud pointed out routable PING
     * is used for SPING.  routable PING should also probably be left in
     * -Dianora That being the case, we will route, but only for
     * registered clients (a case can be made to allow them only from
     * servers). -Shadowfax
     */
    if (!BadPtr(destination) && (mycmp(destination, me.name) != 0)
        && IsRegistered(sptr))
    {
        if ((acptr = find_client(destination, NULL)) ||
            (acptr = find_server(destination, NULL)))
            sendto_one(acptr, ":%s PONG %s %s", parv[0], origin, destination);
        else
        {
            sendto_one(sptr, err_str(ERR_NOSUCHSERVER), me.name, parv[0], 
                       destination);
            return 0;
        }
    }
#ifdef  DEBUGMODE
    else
        Debug((DEBUG_NOTICE, "PONG: %s %s", origin, 
               destination ? destination : "*"));
#endif
    return 0;
}

/* added Sat Jul 25 07:30:42 EST 1992 */
/*
 * extra argument evenTS added to send to TS servers or not -orabidoo
 *
 * extra argument evenTS no longer needed with TS only th+hybrid server
 * -Dianora
 */
static inline void
send_umode_out(aClient *cptr, aClient *sptr, int old)
{
    aClient *acptr;
    DLink *lp;

    send_umode(NULL, sptr, old, SEND_UMODES, buf);

    if(*buf)
    {
        for(lp = server_list; lp; lp = lp->next)
        {
            acptr = lp->value.cptr;
            if((acptr != cptr) && (acptr != sptr))
                sendto_one(acptr, ":%s MODE %s :%s", sptr->name,
                           sptr->name, buf);
        }
    }

    if (cptr && MyClient(cptr))
        send_umode(cptr, sptr, old, ALL_UMODES, buf);
}

/*
 * m_oper 
 * parv[0] = sender prefix 
 * parv[1] = oper name 
 * parv[2] = oper password
 */
int m_oper(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aOper       *aoper;
    char        *name, *password, *encr, *oper_ip;
    extern char *crypt();

    name = parc > 1 ? parv[1] : (char *) NULL;
    password = parc > 2 ? parv[2] : (char *) NULL;

    if (!IsServer(cptr) && (BadPtr(name) || BadPtr(password)))
    {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0], "OPER");
        return 0;
    }

    /* if message arrived from server, trust it, and set to oper */
    /* an OPER message should never come from a server. complain */

    if ((IsServer(cptr) || IsMe(cptr)) && !IsOper(sptr))
    {
        sendto_realops("Why is %s sending me an OPER? Contact Coders",
                        cptr->name);

        /* sanity */
        if (!IsPerson(sptr))
            return 0;

#ifdef DEFAULT_HELP_MODE
        sptr->umode |= UMODE_o;
        sptr->umode |= UMODE_h;
        sendto_serv_butone(cptr, ":%s MODE %s :+oh", parv[0], parv[0]);
#else
        sptr->umode |= UMODE_o;
        sendto_serv_butone(cptr, ":%s MODE %s :+o", parv[0], parv[0]);
#endif
#ifdef ALL_OPERS_HIDDEN
        sptr->umode |= UMODE_I;
        sendto_serv_butone(cptr, ":%s MODE %s :+I", parv[0], parv[0]);
#endif
#if defined(SPAMFILTER) && defined(DEFAULT_OPER_SPAMFILTER_DISABLED)
        sptr->umode |= UMODE_P;
        sendto_serv_butone(cptr, ":%s MODE %s :+P", parv[0], parv[0]);
#endif
        Count.oper++;
        if (IsMe(cptr))
            sendto_one(sptr, rpl_str(RPL_YOUREOPER), me.name, parv[0]);
        return 0;
    }
    else if (IsAnOper(sptr) && MyConnect(sptr))
    {
        send_rplisupportoper(sptr);
        sendto_one(sptr, rpl_str(RPL_YOUREOPER), me.name, parv[0]);
        return 0;
    }
#if (RIDICULOUS_PARANOIA_LEVEL>=1)
    if(!sptr->user->real_oper_host)
    {
#endif
        if(!(aoper = find_oper(name, sptr->user->username, sptr->user->host, 
                               sptr->hostip)))
        {
            sendto_one(sptr, err_str(ERR_NOOPERHOST), me.name, parv[0]);
            sendto_ops_lev(ADMIN_LEV, "Failed OPER attempt by %s (%s@%s) [Unknown Account %s]",
                           parv[0], sptr->user->username, sptr->user->host, name);
            sendto_realops("Failed OPER attempt by %s [Unknown Account %s]", parv[0], name);
            return 0;
        }
        oper_ip = sptr->hostip;
#if (RIDICULOUS_PARANOIA_LEVEL>=1)
    }
    else
    {
        if (!(aoper = find_oper(name, sptr->user->real_oper_username,
                                      sptr->user->real_oper_host,
                                      sptr->user->real_oper_ip))) 
        {
            sendto_one(sptr, err_str(ERR_NOOPERHOST), me.name, parv[0]);
            sendto_ops_lev(ADMIN_LEV, "Failed OPER attempt by %s (%s@%s) [Unknown Account %s]",
                           parv[0], sptr->user->username, sptr->user->host, name);
            sendto_realops("Failed OPER attempt by %s [Unknown account %s]", parv[0], name);
            return 0;
        }
        oper_ip = sptr->user->real_oper_ip;
    }
#endif
    /* use first two chars of the password they send in as salt */
    /* passwd may be NULL pointer. Head it off at the pass... */
    if(confopts & FLAGS_CRYPTPASS)
    {
        if (password && *aoper->passwd)
                encr = crypt(password, aoper->passwd);
        else
                encr = "";
    }
    else 
        encr = password;
    
    if (StrEq(encr, aoper->passwd))
    {
        int old = (sptr->umode & ALL_UMODES);

        if(svsnoop)
        {
            sendto_one(sptr, err_str(ERR_NOOPERHOST), me.name, parv[0]);
            sendto_ops_lev(ADMIN_LEV, "Failed OPER attempt by %s (%s@%s) [svsnoop is enabled]",
                           parv[0], sptr->user->username, sptr->user->host);
            return 0;
        }

        /* attach our conf */
        sptr->user->oper = aoper;
        aoper->opers++;
        if (!(aoper->flags & OFLAG_ISGLOBAL))
            SetLocOp(sptr);
        else
            SetOper(sptr);
#ifdef DEFAULT_HELP_MODE                        
        sptr->umode|=(UMODE_s|UMODE_g|UMODE_w|UMODE_n|UMODE_h);
#else
        sptr->umode|=(UMODE_s|UMODE_g|UMODE_w|UMODE_n);
#endif
#if defined(SPAMFILTER) && defined(DEFAULT_OPER_SPAMFILTER_DISABLED)
        sptr->umode|=UMODE_P;
#endif
        sptr->oflag = aoper->flags;
        Count.oper++;
        add_to_list(&oper_list, sptr);
        throttle_remove(oper_ip);
        sendto_ops("%s (%s!%s@%s) is now operator (%c)", aoper->nick,
                   sptr->name, sptr->user->username, sptr->sockhost,
                   IsOper(sptr) ? 'O' : 'o');
        send_umode_out(cptr, sptr, old);
        send_rplisupportoper(sptr);
        sendto_one(sptr, rpl_str(RPL_YOUREOPER), me.name, parv[0]);
        set_effective_class(sptr);
#if defined(USE_SYSLOG) && defined(SYSLOG_OPER)
        syslog(LOG_INFO, "OPER (%s) (%s) by (%s!%s@%s)",
               name, encr, parv[0], sptr->user->username, sptr->sockhost);
#endif
#ifdef MAXBUFFERS
        /* give them server-sized socket buffers, throughput++ */
        reset_sock_opts(sptr->fd, 1);
#endif
#if defined(FNAME_OPERLOG)
        {
            int logfile;
                        
            /*
             * This conditional makes the logfile active only after it's
             * been created - thus logging can be turned off by removing
             * the file.
             * 
             * stop NFS hangs...most systems should be able to open a file in
             * 3 seconds. -avalon (curtesy of wumpus)
             */
            alarm(3);
            if (IsPerson(sptr) &&
                (logfile = open(FNAME_OPERLOG, O_WRONLY | O_APPEND)) != -1)
            {
                alarm(0);
                ircsprintf(buf, "%s OPER (%s) (%s) by (%s!%s@%s)\n",
                                  myctime(timeofday), name, encr,
                                  parv[0], sptr->user->username,
                                  sptr->sockhost);
                alarm(3);
                write(logfile, buf, strlen(buf));
                alarm(0);
                close(logfile);
            }
            alarm(0);
            /* Modification by pjg */
        }
#endif
    }
    else 
    {
        sendto_one(sptr, err_str(ERR_PASSWDMISMATCH), me.name, parv[0]);
#ifdef FAILED_OPER_NOTICE
        sendto_ops_lev(ADMIN_LEV, "Failed OPER attempt by %s (%s@%s) [Bad Password for %s]",
                       parv[0], sptr->user->username, sptr->sockhost, name);
        sendto_realops("Failed OPER attempt by %s [Bad Password for %s]", parv[0], name);
#endif
    }
    return 0;
}

/***************************************************************************
 * m_pass() - Added Sat, 4 March 1989
 ***************************************************************************/
/*
 * m_pass 
 * parv[0] = sender prefix 
 * parv[1] = password
 * parv[2] = optional extra version information
 */
int 
m_pass(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    char *password = parc > 1 ? parv[1] : NULL;
    
    if (BadPtr(password))
    {
        sendto_one(cptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0], "PASS");
        return 0;
    }
    if (!MyConnect(sptr) || (!IsUnknown(cptr) && !IsHandshake(cptr)))
    {
        sendto_one(cptr, err_str(ERR_ALREADYREGISTRED), me.name, parv[0]);
        return 0;
    }
    strncpyzt(cptr->passwd, password, sizeof(cptr->passwd));
    if (parc > 2)
    {
        int l = strlen(parv[2]);
        
        if (l < 2)
            return 0;
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
m_userhost(aClient *cptr, aClient *sptr, int parc, char *parv[])
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
                              (IsUmodeH(acptr) && sptr!=acptr && !IsAnOper(sptr))?acptr->user->mhost:
#endif
                              acptr->user->host);
        }
    sendto_one(sptr, "%s", buf);
    return 0;
}

int 
m_userip(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    char *s, *p = NULL;
    aClient *acptr;
    int i, len, res = 0;

    if(!IsAnOper(sptr))
    {
        sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
        return 0;
    }
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
                              IsULine(acptr) ? "0.0.0.0" : acptr->hostip);
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
/* Take care of potential nasty buffer overflow problem -Dianora */

int 
m_ison(aClient *cptr, aClient *sptr, int parc, char *parv[])
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
        cptr->priority += 20;   /* this keeps it from moving to 'busy' list  */
    for (s = strtoken(&p, *++pav, " "); s;
         s = strtoken(&p, (char *) NULL, " "))
        if ((acptr = find_person(s, NULL))) 
        {
            len2 = strlen(acptr->name);
            if ((len + len2 + 5) < sizeof(buf)) /* make sure can never */
            {                                   /* overflow */
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

/*
 * m_umode() added 15/10/91 By Darren Reed.
 * parv[0] - sender
 * parv[1] - username to change mode for
 * parv[2] - modes to change
 */
int 
m_umode(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    int     flag, *s, setflags, what = MODE_ADD, badflag = NO;
    char  **p, *m;
    aClient    *acptr;
    
    if (parc < 2)
    {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, parv[0], "MODE");
        return 0;
    }

    if(IsServer(sptr))
        return 0;
    
    if (!(acptr = find_person(parv[1], NULL)))
    {
        if (MyConnect(sptr))
            sendto_one(sptr, err_str(ERR_NOSUCHCHANNEL), me.name, parv[0], 
                       parv[1]);
        return 0;
    }

    if ((sptr != acptr) || (acptr->from != sptr->from))
    {
        sendto_one(sptr, err_str(ERR_USERSDONTMATCH), me.name, parv[0]);
        return 0;
    }
    
   
    if (parc < 3)
    {
        m = buf;
        *m++ = '+';
        for (s = user_modes; (flag = *s) && (m - buf < BUFSIZE - 4); s += 2)
        {
            if (sptr->umode & (flag & ALL_UMODES))
                *m++ = (char) (*(s + 1));
        }
        *m = '\0';
        sendto_one(sptr, rpl_str(RPL_UMODEIS), me.name, parv[0], buf);
        return 0;
    }
        
    /* find flags already set for user */
    setflags = 0;
    for (s = user_modes; (flag = *s); s += 2)
        if (sptr->umode & flag)
            setflags |= flag;
    /* parse mode change string(s) */
    for (p = &parv[2]; p && *p; p++)
        for (m = *p; *m; m++)
            switch (*m)
            {
                case '+':
                    what = MODE_ADD;
                    break;
                case '-':
                    what = MODE_DEL;
                    break;
                    /* we may not get these, but they shouldnt be in default */
                case ' ':
                case '\r':
                case '\n':
                case '\t':
                    break;
                case 'r':
                case 'x':
                case 'X':
                case 'S':
                    break; /* users can't set themselves +r,+x,+X or +S! */
                case 'H':
                    if ((uhm_type > 0) && (what == MODE_ADD))
                        sptr->umode |= UMODE_H;
                    else
                        sptr->umode &= ~UMODE_H;
                    break;
                case 'A':
                    /* set auto +a if user is setting +A */
                    if (MyClient(sptr) && (what == MODE_ADD))
                        sptr->umode |= UMODE_a;
                default:
                    for (s = user_modes; (flag = *s); s += 2)
                        if (*m == (char) (*(s + 1)))
                        {
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
        sendto_one(sptr, err_str(ERR_UMODEUNKNOWNFLAG), me.name, parv[0]);

    /* stop users making themselves operators too easily */
    if (!(setflags & UMODE_o) && IsOper(sptr) && !IsServer(cptr))
        ClearOper(sptr);
        
    if (!(setflags & UMODE_O) && IsLocOp(sptr) && !IsServer(cptr))
        sptr->umode &= ~UMODE_O;
        
    if ((setflags & (UMODE_o | UMODE_O)) && !IsAnOper(sptr) && MyConnect(sptr))
    {
        set_effective_class(sptr);
        sptr->oflag = 0;
    }

    if (!(setflags & (UMODE_o | UMODE_O)) && IsAnOper(sptr))
        Count.oper++;
        
    if ((setflags & (UMODE_o | UMODE_O)) && !IsAnOper(sptr))
    {
        Count.oper--;
        if (MyConnect(sptr))
        {
            remove_from_list(&oper_list, sptr, NULL);

            /*
             * Now that the user is no longer opered, let's return
             * them back to the appropriate Y:class -srd
             */
            sptr->user->oper->opers--;
            sptr->user->oper = NULL;
            set_effective_class(sptr);
        }
    }
    
    if (!(setflags & UMODE_i) && IsInvisible(sptr))
        Count.invisi++;
    if ((setflags & UMODE_i) && !IsInvisible(sptr))
        Count.invisi--;
    
    /*
     * compare new flags with old flags and send string which will cause
     * servers to update correctly.
     */
    if (!IsAnOper(sptr) && !IsServer(cptr))
    {
        sptr->umode &= ~OPER_UMODES;
#ifdef NO_USER_SERVERKILLS
        sptr->umode &= ~UMODE_k;
#endif
#ifdef NO_USER_OPERKILLS
        sptr->umode &= ~UMODE_s;
#endif
    }
    if(MyClient(sptr))
    {
        if (IsAdmin(sptr) && !OPIsAdmin(sptr)) ClearAdmin(sptr);
        if (IsSAdmin(sptr) && !OPIsSAdmin(sptr)) ClearSAdmin(sptr);
        if (IsUmodef(sptr) && !OPCanUModef(sptr)) ClearUmodef(sptr);
        if (IsUmodec(sptr) && !OPCanUModec(sptr)) ClearUmodec(sptr);
        if (IsUmodej(sptr) && !OPCanUModec(sptr)) ClearUmodej(sptr);
        if (IsUmodey(sptr) && !OPCanUModey(sptr)) ClearUmodey(sptr);
        if (IsUmoded(sptr) && !OPCanUModed(sptr)) ClearUmoded(sptr);
        if (IsUmodeb(sptr) && !OPCanUModeb(sptr)) ClearUmodeb(sptr);
        if (NoMsgThrottle(sptr) && !OPCanUModeF(sptr)) ClearNoMsgThrottle(sptr);
#ifdef ALLOW_HIDDEN_OPERS
# ifdef FORCE_EVERYONE_HIDDEN
        sptr->umode |= UMODE_I;
# else
#  if (RIDICULOUS_PARANOIA_LEVEL>=1)
        if (IsUmodeI(sptr) && !(sptr->user->real_oper_host || IsAnOper(sptr))) 
            ClearUmodeI(sptr);
#  endif

#  ifdef FORCE_OPERS_HIDDEN
        if (IsAnOper(sptr)
#   if (RIDICULOUS_PARANOIA_LEVEL>=1)
            || (sptr->user->real_oper_host != NULL)
#   endif
           ) sptr->umode |= UMODE_I;
#  endif /* FORCE_OPERS_HIDDEN */
# endif /* FORCE_EVERYONE_HIDDEN */
#else /* ALLOW_HIDDEN_OPERS */
        if (IsUmodeI(sptr)) ClearUmodeI(sptr);
#endif
        if (sptr->user->allow->flags & CONF_FLAGS_FORCEFLOOD)
            SetNoMsgThrottle(sptr);
    }
    send_umode_out(cptr, sptr, setflags);
    
    return 0;
}

/* send the MODE string for user (user) to connection cptr -avalon */
void 
send_umode(aClient *cptr, aClient *sptr, int old, int sendmask, char *umode_buf)
{
    int *s, flag, what = MODE_NULL;
    char *m;

    /*
     * build a string in umode_buf to represent the change in the user's
     * mode between the new (sptr->flag) and 'old'.
     */
    m = umode_buf;
    *m = '\0';
    for (s = user_modes; (flag = *s); s += 2)
    {
        if (MyClient(sptr) && !(flag & sendmask))
            continue;
        if ((flag & old) && !(sptr->umode & flag))
        {
            if (what == MODE_DEL)
                *m++ = *(s + 1);
            else
            {
                what = MODE_DEL;
                *m++ = '-';
                *m++ = *(s + 1);
            }
        }
        else if (!(flag & old) && (sptr->umode & flag))
        {
            if (what == MODE_ADD)
                *m++ = *(s + 1);
            else
            {
                what = MODE_ADD;
                *m++ = '+';
                *m++ = *(s + 1);
            }
        }
    }
    *m = '\0';
    if (*umode_buf && cptr)
        sendto_one(cptr, ":%s MODE %s :%s", sptr->name, sptr->name, umode_buf);
}

/* Shadowfax's FLUD code */
#ifdef FLUD
void 
announce_fluder(aClient *fluder, aClient *cptr, aChannel *chptr, int type)
{                               
    char *fludee;
    
    if (cptr)
        fludee = cptr->name;
    else
        fludee = chptr->chname;
    
    if(call_hooks(CHOOK_FLOODWARN, fluder, chptr, 3, fludee, NULL) != FLUSH_BUFFER)
        sendto_realops_lev(FLOOD_LEV, "Flooder %s [%s@%s] on %s target: %s",
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
remove_fluder_reference(struct fludbot **fluders, aClient *fluder)
{
    struct fludbot *current, *prev, *next;
    
    prev = NULL;
    current = *fluders;
    while (current)
    {
        next = current->next;
        if (current->fluder == fluder)
        {
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

/* Another function to unravel my mind. */
Link *
remove_fludee_reference(Link **fludees, void *fludee)
{
    Link *current, *prev, *next;

    prev = NULL;
    current = *fludees;
    while (current)
    {
        next = current->next;
        if (current->value.cptr == (aClient *) fludee)
        {
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
check_for_fludblock(aClient *fluder, aClient *cptr, aChannel *chptr, int type)
{                               
    time_t now;
    int blocking;

    /* If it's disabled, we don't need to process all of this */
    if ((confopts & FLAGS_HUB) || (flud_block == 0))
        return 0;

    /* It's either got to be a client or a channel being fluded */
    if ((cptr == NULL) && (chptr == NULL))
        return 0;

    if (cptr && !MyFludConnect(cptr))
    {
        sendto_ops("check_for_fludblock() called for non-local client");
        return 0;
    }

    /* Are we blocking fluds at this moment? */
    time(&now);
    if (cptr)
        blocking = (cptr->fludblock > (now - flud_block));
    else
        blocking = (chptr->fludblock > (now - flud_block));

    return (blocking);
}

int 
check_for_flud(aClient *fluder, aClient *cptr, aChannel *chptr, int type)
{                               
    time_t      now;
    struct fludbot *current, *prev, *next;
    int         blocking, count, found;
    Link       *newfludee;
    
    /* If it's disabled, we don't need to process all of this */
    if ((confopts & (FLAGS_HUB|FLAGS_SERVHUB)) || (flud_block == 0))
        return 0;
        
    /* It's either got to be a client or a channel being fluded */
    if ((cptr == NULL) && (chptr == NULL))
        return 0;
        
    if (cptr && !MyFludConnect(cptr)) 
    {
        sendto_ops("check_for_flud() called for non-local client");
        return 0;
    }
        
    /* Are we blocking fluds at this moment? */
    time(&now);
    if (cptr)
        blocking = (cptr->fludblock > (now - flud_block));
    else
        blocking = (chptr->fludblock > (now - flud_block));
        
    /* Collect the Garbage */
    if (!blocking) 
    {
        if (cptr)
            current = cptr->fluders;
        else
            current = chptr->fluders;
        prev = NULL;
        while (current) 
        {
            next = current->next;
            if (current->last_msg < (now - flud_time))
            {
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
    while (current) 
    {
        if (current->fluder == fluder)
        {
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
    if (!found) 
    {
        if ((current = BlockHeapALLOC(free_fludbots, struct fludbot)) != NULL) 
        {
            current->fluder = fluder;
            current->count = 1;
            current->first_msg = now;
            current->last_msg = now;
            if (cptr) 
            {
                current->next = cptr->fluders;
                cptr->fluders = current;
            }
            else 
            {
                current->next = chptr->fluders;
                chptr->fluders = current;
            }
                        
            count++;
                        
            if ((newfludee = BlockHeapALLOC(free_Links, Link)) != NULL) 
            {
                if (cptr) 
                {
                    newfludee->flags = 0;
                    newfludee->value.cptr = cptr;
                }
                else 
                {
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
    if (!blocking && (count > flud_num)) 
    {
        blocking = 1;
        ircstp->is_flud++;
        /*
         * if we are going to say anything to the fludee, now is the *
         * time to mention it to them.
         */
        if (cptr)
            sendto_one(cptr,
                       ":%s NOTICE %s :*** Notice -- Server flood protection "
                       "activated for %s", me.name, cptr->name, cptr->name);
        else
            sendto_channel_butserv(chptr, &me,
                                   ":%s NOTICE %s :*** Notice -- Server "
                                   "flood protection activated for %s",
                                   me.name, chptr->chname, chptr->chname);
        /*
         * Here we should go back through the existing list of * fluders
         * and announce that they were part of the game as * well.
         */
        if (cptr)
            current = cptr->fluders;
        else
            current = chptr->fluders;
        while (current) 
        {
            announce_fluder(current->fluder, cptr, chptr, type);
            current = current->next;
        }
    }
    /*
     * update blocking timestamp, since we received a/another CTCP
     * message
     */
    if (blocking) 
    {
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

    if ((cptr == NULL) && (chptr == NULL)) 
    {
        sendto_ops("free_fluders(NULL, NULL)");
        return;
    }

    if (cptr && !MyFludConnect(cptr))
        return;

    if (cptr)
        fluders = cptr->fluders;
    else
        fluders = chptr->fluders;

    while (fluders) 
    {
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

    if (badguy == NULL) 
    {
        sendto_ops("free_fludees(NULL)");
        return;
    }
    fludees = badguy->fludees;
    while (fludees) 
    {
        next = fludees->next;

        if (fludees->flags)
            remove_fluder_reference(&fludees->value.chptr->fluders, badguy);
        else 
        {
            if (!MyFludConnect(fludees->value.cptr))
                sendto_ops("free_fludees() encountered non-local client");
            else
                remove_fluder_reference(&fludees->value.cptr->fluders, badguy);
        }

        BlockHeapFree(free_Links, fludees);
        fludees = next;
    }
}
#endif /* FLUD */


int del_silence(aClient *sptr, char *mask) 
{
    Link **lp, *tmp;
    for (lp=&(sptr->user->silence);*lp;lp=&((*lp)->next))
        if (mycmp(mask, (*lp)->value.cp)==0) 
        {
            tmp = *lp;
            *lp = tmp->next;
            MyFree(tmp->value.cp);
            free_link(tmp);
            return 0;
        }
    return 1;
}

static int add_silence(aClient *sptr,char *mask) 
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
int 
m_silence(aClient *cptr,aClient *sptr,int parc,char *parv[]) 
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

static int 
add_dccallow(aClient *sptr, aClient *optr)
{
    Link *lp;
    int cnt = 0;

    for(lp = sptr->user->dccallow; lp; lp = lp->next)
    {
        if(lp->flags != DCC_LINK_ME)
            continue;
        if((++cnt >= MAXDCCALLOW) && !IsAnOper(sptr))
        {
            sendto_one(sptr, err_str(ERR_TOOMANYDCC), me.name, sptr->name,
                       optr->name, MAXDCCALLOW);
            return 0;
        }
        else if(lp->value.cptr == optr)
            return 0;
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

    sendto_one(sptr, rpl_str(RPL_DCCSTATUS), me.name, sptr->name, optr->name,
               "added to");
    return 0;
}

int
del_dccallow(aClient *sptr, aClient *optr, int silent) 
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
        sendto_one(sptr, ":%s %d %s :%s is not in your DCC allow list",
                   me.name, RPL_DCCINFO, sptr->name, optr->name);
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
        sendto_realops_lev(DEBUG_LEV, "%s was in dccallowme list of %s but "
                           "not in dccallowrem list!", optr->name, sptr->name);

    if(!silent)
        sendto_one(sptr, rpl_str(RPL_DCCSTATUS), me.name, sptr->name, optr->name,
                   "removed from");
    
    return 0;
}

int 
m_dccallow(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    Link *lp;
    char *p, *s;
    char *cn;
    aClient *acptr, *lastcptr = NULL;
    int didlist = 0, didhelp = 0, didanything = 0;
    char **ptr;
    static char *dcc_help[] = 
        {
            "/DCCALLOW [<+|->nick[,<+|->nick, ...]] [list] [help]",
            "You may allow DCCs of filetypes which are otherwise blocked by "
            "the IRC server",
            "by specifying a DCC allow for the user you want to recieve files "
            "from.",
            "For instance, to allow the user bob to send you file.exe, you "
            "would type:",
            "/dccallow +bob",
            "and bob would then be able to send you files. bob will have to "
            "resend the file",
            "if the server gave him an error message before you added him to "
            "your allow list.",
            "/dccallow -bob",
            "Will do the exact opposite, removing him from your dcc allow "
            "list.",
            "/dccallow list",
            "Will list the users currently on your dcc allow list.",
            NULL 
        };

    if(!MyClient(sptr)) 
        return 0;
    
    if(parc < 2)
    {
        sendto_one(sptr, ":%s NOTICE %s :No command specified for DCCALLOW. "
                   "Type /dccallow help for more information.", me.name,
                   sptr->name);
        return 0;
    }

    for (p = NULL, s = strtoken(&p, parv[1], ", "); s;
         s = strtoken(&p, NULL, ", "))
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
                sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name,
                           sptr->name, cn);
                continue;
            }

            if(lastcptr == acptr)
                sendto_realops_lev(SPY_LEV, "User %s (%s@%s) may be flooding "
                                   "dccallow: add %s", sptr->name,
                                   sptr->user->username, sptr->user->host,
                                   acptr->name);
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
            if(acptr == sptr) 
                continue;

            if(!acptr)
            {
                sendto_one(sptr, err_str(ERR_NOSUCHNICK), me.name, 
                           sptr->name, cn);
                continue;
            }

            if(lastcptr == acptr)
                sendto_realops_lev(SPY_LEV, "User %s (%s@%s) may be flooding "
                                   "dccallow: del %s", sptr->name,
                                   sptr->user->username, sptr->user->host,
                                   acptr->name);
            
            lastcptr = acptr;
            del_dccallow(sptr, acptr, 0);
        }
        else
        {
            if(!didlist && myncmp(s, "list", 4) == 0)
            {
                didanything++;
                didlist++;
                sendto_one(sptr, ":%s %d %s :The following users are on your "
                           "dcc allow list:", me.name, RPL_DCCINFO,
                           sptr->name);
                for(lp = sptr->user->dccallow; lp; lp = lp->next)
                {
                    if(lp->flags == DCC_LINK_REMOTE) 
                        continue;
                    sendto_one(sptr, ":%s %d %s :%s (%s@%s)", me.name,
                               RPL_DCCLIST, sptr->name, lp->value.cptr->name,
                               lp->value.cptr->user->username,
#ifdef USER_HOSTMASKING
                               IsUmodeH(lp->value.cptr)?lp->value.cptr->user->mhost:
#endif
                               lp->value.cptr->user->host);
                }
                sendto_one(sptr, rpl_str(RPL_ENDOFDCCLIST), me.name,
                           sptr->name, s);
            }
            else if(!didhelp && myncmp(s, "help", 4) == 0)
            {
                didanything++;
                didhelp++;
                for(ptr = dcc_help; *ptr; ptr++)
                    sendto_one(sptr, ":%s %d %s :%s", me.name, RPL_DCCINFO,
                               sptr->name, *ptr);
                sendto_one(sptr, rpl_str(RPL_ENDOFDCCLIST), me.name,
                           sptr->name, s);
            }
        }
    }

    if(!didanything)
    {
        sendto_one(sptr, ":%s NOTICE %s :Invalid syntax for DCCALLOW. Type "
                   "/dccallow help for more information.", me.name,
                   sptr->name);
        return 0;
    }
    
    return 0;
}

int
m_put(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    /* HTTP PUT proxy */
    if (!IsRegistered(cptr) && cptr->receiveM == 1)
        return reject_proxy(cptr, "PUT", parv[1]);

    return 0;
}

int
m_post(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    /* HTTP POST proxy */
    if (!IsRegistered(cptr) && cptr->receiveM == 1)
        return reject_proxy(cptr, "POST", parv[1]);

    return 0;
}

u_long
memcount_s_user(MCs_user *mc)
{
    aClient *acptr;
    Link *lp;
#ifdef FLUD
    struct fludbot *fb;
#endif

    mc->file = __FILE__;

    for (acptr = client; acptr; acptr = acptr->next)
    {
        if (!IsMe(acptr))   /* me is static */
        {
            if (acptr->from == acptr)
                mc->e_local_clients++;
            else
                mc->e_remote_clients++;
        }

        if (acptr->user)
        {
            mc->e_users++;

            if (acptr->user->away)
            {
                mc->aways.c++;
                mc->aways.m += strlen(acptr->user->away) + 1;
            }
            for (lp = acptr->user->silence; lp; lp = lp->next)
            {
                mc->silences.c++;
                mc->silences.m += strlen(lp->value.cp) + 1;
                mc->e_silence_links++;
            }
            mc->e_channel_links += mc_links(acptr->user->channel);
            mc->e_invite_links += mc_links(acptr->user->invited);
            mc->e_dccallow_links += mc_links(acptr->user->dccallow);

#if (RIDICULOUS_PARANOIA_LEVEL>=1)
            if (acptr->user->real_oper_host)
            {
                mc->opermasks.c++;
                mc->opermasks.m += strlen(acptr->user->real_oper_host) + 1;
                mc->opermasks.m += strlen(acptr->user->real_oper_username) + 1;
                mc->opermasks.m += strlen(acptr->user->real_oper_ip) + 1;
            }
#endif
        }

        if (acptr->serv)
        {
            mc->servers.c++;
            mc->servers.m += sizeof(aServer);

#ifdef HAVE_ENCRYPTION_ON
            if (acptr->serv->rc4_in)
                mc->e_rc4states++;
            if (acptr->serv->rc4_out)
                mc->e_rc4states++;
#endif
            if (acptr->serv->zip_in)
                mc->e_zipin_sessions++;
            if (acptr->serv->zip_out)
                mc->e_zipout_sessions++;
        }

        mc->e_watch_links += mc_links(acptr->watch);

#ifdef FLUD
        mc->e_flud_links += mc_links(acptr->fludees);

        if (acptr->from == acptr)   /* local client */
            for (fb = acptr->fluders; fb; fb = fb->next)
                mc->e_fludbots++;
#endif
    }

    mc->total.c = mc->aways.c + mc->silences.c + mc->servers.c;
    mc->total.m = mc->aways.m + mc->silences.m + mc->servers.m;
#if (RIDICULOUS_PARANOIA_LEVEL>=1)
    mc->total.c += mc->opermasks.c;
    mc->total.m += mc->opermasks.m;
#endif

    return mc->total.m;
}

