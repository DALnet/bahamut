/************************************************************************
 *   IRC - Internet Relay Chat, src/s_conf.c
 *   Copyright (C) 1990 Jarkko Oikarinen and
 *                      University of Oulu, Computing Center
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

/* $Id$ */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "inet.h"
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/wait.h>
#ifdef __hpux
#include "inet.h"
#endif
#if defined(AIX) || defined(SVR3)
#include <time.h>
#endif

#include <signal.h>
#include "h.h"
#include "dich_conf.h"

extern int  rehashed;

struct sockaddr_in vserv;
char        specific_virtual_host;


/* internally defined functions  */

static int  		lookup_confhost(aConfItem *);
static int  		attach_iline(aClient *, aConfItem *, char *, int);
static aConfItem       *temporary_klines = (aConfItem *) NULL;
static aConfItem       *szlines = (aConfItem *) NULL;

/* externally defined functions  */

extern void outofmemory(void);	/* defined in list.c */

/*
 * usually, with hash tables, you use a prime number... but in this
 * case I am dealing with ip addresses, not ascii strings.
 */

#define IP_HASH_SIZE 0x1000

typedef struct ip_entry
{
    unsigned long ip;
    int         count;
    struct ip_entry *next;
} IP_ENTRY;

IP_ENTRY   *ip_hash_table[IP_HASH_SIZE];

void        	 init_ip_hash(void);
static int  	 hash_ip(unsigned long);
static IP_ENTRY *find_or_add_ip(unsigned long);

/* externally defined routines */

int         find_conf_match(aClient *, aConfList *, aConfList *, aConfList *);
int         find_fline(aClient *);
extern void delist_conf(aConfItem *);

#ifdef WINGATE_NOTICE
extern char ProxyMonURL[TOPICLEN+1];
extern char ProxyMonHost[HOSTLEN+1];
#endif

aConfItem  *conf = ((aConfItem *) NULL);

#ifdef LOCKFILE
extern void do_pending_klines(void);
#endif

/*
 * remove all conf entries from the client except those which match the
 * status field mask.
 */
void det_confs_butmask(aClient *cptr, int mask)
{
    Link   *tmp, *tmp2;
    
    for (tmp = cptr->confs; tmp; tmp = tmp2) 
    {
	tmp2 = tmp->next;
	if ((tmp->value.aconf->status & mask) == 0)
	    (void) detach_conf(cptr, tmp->value.aconf);
    }
}

/* find the first (best) I line to attach. */
int attach_Iline(aClient *cptr, struct hostent *hp, char *sockhost)
{
    aConfItem *aconf;
    char   *hname;
    int     i, ulen, uhost_has_at;
    static char uhost[HOSTLEN + USERLEN + 3];
    static char uhost2[HOSTLEN + USERLEN + 3];
    static char fullname[HOSTLEN + 1];

    for (aconf = conf; aconf; aconf = aconf->next) 
    {
	if (aconf->status != CONF_CLIENT)
	    continue;

	if (aconf->port && aconf->port != cptr->acpt->port)
	    continue;

	if (!aconf->host || !aconf->name)
	    return (attach_iline(cptr, aconf, uhost, 0));

	if (hp)
	    for (i = 0, hname = hp->h_name; hname; hname = hp->h_aliases[i++]) 
	    {
		strncpy(fullname, hname, sizeof(fullname) - 1);
		add_local_domain(fullname, HOSTLEN - strlen(fullname));
		Debug((DEBUG_DNS, "a_il: %s->%s", sockhost, fullname));
		if (aconf->flags & CONF_FLAGS_I_NAME_HAS_AT)
		{
		    uhost_has_at = 1;
		    ulen = ircsprintf(uhost, "%s@", cptr->username);
		    strcpy(uhost2, uhost);
		}
		else 
		{
		    uhost_has_at = 0;
		    ulen = 0;
		    *uhost = '\0';
		    *uhost2 = '\0';
		}
		strncat(uhost, fullname, sizeof(uhost) - ulen);
		strncat(uhost2, sockhost, sizeof(uhost2) - ulen);
		if ((!match(aconf->name, uhost)) ||
		    (!match(aconf->name, uhost2)))
		    return (attach_iline(cptr, aconf, uhost, uhost_has_at));
	    }
	
	if (aconf->flags & CONF_FLAGS_I_HOST_HAS_AT)
	{
	    uhost_has_at = 1;
	    ulen = ircsprintf(uhost, "%s@", cptr->username);
	}
	else
	{
	    uhost_has_at = 0;
	    ulen = 0;
	    *uhost = '\0';
	}

	strncat(uhost, sockhost, sizeof(uhost) - ulen);

	if (match(aconf->host, uhost) == 0)
	    return (attach_iline(cptr, aconf, uhost, uhost_has_at));
    }
    
    return -1;			/* no match */
}

/*
 * rewrote to remove the "ONE" lamity *BLEH* I agree with comstud on
 * this one. - Dianora
 */
static int attach_iline(aClient *cptr, aConfItem *aconf, char *uhost, int doid)
{
    IP_ENTRY   *ip_found;
    
    if (doid)
	cptr->flags |= FLAGS_DOID;
    get_sockhost(cptr, uhost);
    
    /* every conf when created, has a class pointer set up. if it isn't,
     * well.  *BOOM* ! */

    ip_found = find_or_add_ip(cptr->ip.s_addr);
    cptr->flags |= FLAGS_IPHASH;
    ip_found->count++;
    
    /* only check it if its non zero  */

    if ((aconf->class->conFreq) && (ip_found->count > aconf->class->conFreq))
	return -4;		/* Already at maximum allowed ip#'s  */

    return (attach_conf(cptr, aconf));
}

/* link list of free IP_ENTRY's */

static IP_ENTRY *free_ip_entries;

/*
 * init_ip_hash()
 * 
 * input 		- NONE output           - NONE side effects     - clear
 * the ip hash table
 * 
 * stole the link list pre-allocator from list.c
 */
void clear_ip_hash_table()
{
    void       *block_IP_ENTRIES;	/* block of IP_ENTRY's  */
    IP_ENTRY   *new_IP_ENTRY;	/* new IP_ENTRY being made */
    IP_ENTRY   *last_IP_ENTRY;	/* last IP_ENTRY in chain */
    int         size,  n_left_to_allocate = MAXCONNECTIONS;

    /*
     * ok. if the sizeof the struct isn't aligned with that of the
     * smallest guaranteed valid pointer (void *), then align it ya. you
     * could just turn 'size' into a #define. do it. :-)
     * 
     * -Dianora
     */

    size = sizeof(IP_ENTRY) + (sizeof(IP_ENTRY) & (sizeof(void *) - 1));

    block_IP_ENTRIES = (void *) MyMalloc((size * n_left_to_allocate));

    free_ip_entries = (IP_ENTRY *) block_IP_ENTRIES;
    last_IP_ENTRY = free_ip_entries;

    /*
     * *shudder* pointer arithmetic 
     */
    while (--n_left_to_allocate) 
    {
	block_IP_ENTRIES = (void *) ((unsigned long) block_IP_ENTRIES +
				     (unsigned long) size);
	new_IP_ENTRY = (IP_ENTRY *) block_IP_ENTRIES;
	last_IP_ENTRY->next = new_IP_ENTRY;
	new_IP_ENTRY->next = (IP_ENTRY *) NULL;
	last_IP_ENTRY = new_IP_ENTRY;
    }
    memset((char *) ip_hash_table, '\0', sizeof(ip_hash_table));
}

/*
 * find_or_add_ip()
 * 
 * inputs               - unsigned long IP address value output         -
 * pointer to an IP_ENTRY element side effects  -
 * 
 * If the ip # was not found, a new IP_ENTRY is created, and the ip count
 * set to 0.
 */

static IP_ENTRY *find_or_add_ip(unsigned long ip_in)
{
    int         hash_index;
    IP_ENTRY   *ptr, *newptr;

    newptr = (IP_ENTRY *) NULL;
    ptr = ip_hash_table[hash_index = hash_ip(ip_in)];
    while (ptr) 
    {
	if (ptr->ip == ip_in)
	    return (ptr);
	else
	    ptr = ptr->next;
    }

    if ((ptr = ip_hash_table[hash_index]) != (IP_ENTRY *) NULL) 
    {
	if (free_ip_entries == (IP_ENTRY *) NULL) 	/* it might be */
	{	 					/* recoverable */
	    sendto_ops("s_conf.c free_ip_entries was found NULL in "
		       "find_or_add");
	    sendto_ops("rehash_ip was done, this is an error.");
	    sendto_ops("Please report to the bahamut team! "
		       "bahamut-bugs@bahamut.net");
	    rehash_ip_hash();
	    if (free_ip_entries == (IP_ENTRY *) NULL)
		outofmemory();
	}
	
	newptr = ip_hash_table[hash_index] = free_ip_entries;
	free_ip_entries = newptr->next;
	
	newptr->ip = ip_in;
	newptr->count = 0;
	newptr->next = ptr;
	return (newptr);
    }
    else 
    {
	if (free_ip_entries == (IP_ENTRY *) NULL) 	/* it might be */
	{						/* recoverable */
	    sendto_ops("s_conf.c free_ip_entries was found NULL in "
		       "find_or_add");
	    sendto_ops("rehash_ip was done, this is an error.");
	    sendto_ops("Please report to the bahamut team! "
		       "bahamut-bugs@bahamut.net");
	    rehash_ip_hash();
	    if (free_ip_entries == (IP_ENTRY *) NULL)
		outofmemory();
	}

	ptr = ip_hash_table[hash_index] = free_ip_entries;
	free_ip_entries = ptr->next;
	ptr->ip = ip_in;
	ptr->count = 0;
	ptr->next = (IP_ENTRY *) NULL;
	return (ptr);
    }
}

/*
 * remove_one_ip
 * 
 * inputs               - unsigned long IP address value output         - NONE
 * side effects - ip address listed, is looked up in ip hash table and
 * number of ip#'s for that ip decremented. if ip # count reaches 0,
 * the IP_ENTRY is returned to the free_ip_enties link list.
 */
void remove_one_ip(unsigned long ip_in)
{
    int         hash_index;
    IP_ENTRY   *last_ptr, *ptr, *old_free_ip_entries;

    last_ptr = ptr = ip_hash_table[hash_index = hash_ip(ip_in)];
    while (ptr) 
    {
	if (ptr->ip == ip_in) 
	{
	    if (ptr->count != 0)
		ptr->count--;
	    if (ptr->count == 0) 
	    {
		if (ip_hash_table[hash_index] == ptr)
		    ip_hash_table[hash_index] = ptr->next;
		else
		    last_ptr->next = ptr->next;

		if (free_ip_entries != (IP_ENTRY *) NULL) 
		{
		    old_free_ip_entries = free_ip_entries;
		    free_ip_entries = ptr;
		    ptr->next = old_free_ip_entries;
		}
		else 
		{
		    free_ip_entries = ptr;
		    ptr->next = (IP_ENTRY *) NULL;
		}
	    }
	    return;
	}
	else 
	{
	    last_ptr = ptr;
	    ptr = ptr->next;
	}
    }
    sendto_ops("s_conf.c couldn't find ip# in hash table in remove_one_ip()");
    sendto_ops("Please report to the bahamut team! bahamut-bugs@bahamut.net");
    return;
}

/*
 * hash_ip()
 * 
 * input                - unsigned long ip address output               -
 * integer value used as index into hash table side effects     -
 * hopefully, none
 */
static int hash_ip(unsigned long ip)
{
    int         hash;

    ip = ntohl(ip);
    hash = ((ip >>= 12) + ip) & (IP_HASH_SIZE - 1);
    return (hash);
}

/*
 * count_ip_hash
 * 
 * inputs               - pointer to counter of number of ips hashed - pointer
 * to memory used for ip hash output            - returned via pointers
 * input side effects   - NONE
 * 
 * number of hashed ip #'s is counted up, plus the amount of memory used
 * in the hash.
 * Added so s_debug could check memory usage in here -Dianora 
 */
void count_ip_hash(int *number_ips_stored, u_long *mem_ips_stored)
{
    IP_ENTRY   *ip_hash_ptr;
    int         i;

    *number_ips_stored = 0;
    *mem_ips_stored = 0;

    for (i = 0; i < IP_HASH_SIZE; i++) 
    {
	ip_hash_ptr = ip_hash_table[i];
	while (ip_hash_ptr) 
	{
	    *number_ips_stored = *number_ips_stored + 1;
	    *mem_ips_stored = *mem_ips_stored +
		sizeof(IP_ENTRY);

	    ip_hash_ptr = ip_hash_ptr->next;
	}
    }
}

/*
 * rehash_ip_hash
 * 
 * inputs               - NONE output           - NONE side effects     -
 * 
 * This function clears the ip hash table, then re-enters all the ip's
 * found in local clients.
 * 
 * N.B. This should never have to be called, and hopefully, we can remove
 * this function in future versions of hybrid. i.e. if everything is
 * working right, there should never ever be a case where an IP is
 * still in the ip_hash table and the corresponding client isn't.
 * 
 */
void rehash_ip_hash()
{
    IP_ENTRY   *ip_hash_ptr;
    IP_ENTRY   *tmp_ip_hash_ptr;
    IP_ENTRY   *old_free_ip_entries;
    int         i;

    /* first, clear the ip hash */

    for (i = 0; i < IP_HASH_SIZE; i++) 
    {
	ip_hash_ptr = ip_hash_table[i];
	while (ip_hash_ptr) 
	{
	    tmp_ip_hash_ptr = ip_hash_ptr->next;
	    if (free_ip_entries) 
	    {
		old_free_ip_entries = free_ip_entries;
		free_ip_entries = ip_hash_ptr;
		ip_hash_ptr->next = old_free_ip_entries;
	    }
	    else 
	    {
		free_ip_entries = ip_hash_ptr;
		ip_hash_ptr->next = (IP_ENTRY *) NULL;
	    }
	    ip_hash_ptr = tmp_ip_hash_ptr;
	}
	ip_hash_table[i] = (IP_ENTRY *) NULL;
    }

    for (i = highest_fd; i >= 0; i--) 
    {
	if (local[i] && MyClient(local[i])) 
	{
	    if ((local[i]->fd >= 0) && (local[i]->flags & FLAGS_IPHASH)) 
	    {
		ip_hash_ptr = find_or_add_ip(local[i]->ip.s_addr);
		ip_hash_ptr->count++;
	    }
	}
    }
}

/*
 * Find the single N line and return pointer to it (from list). If more
 * than one then return NULL pointer.
 */
aConfItem *count_cnlines(Link *lp)
{
    aConfItem *aconf, *cline = NULL, *nline = NULL;

    for (; lp; lp = lp->next) 
    {
	aconf = lp->value.aconf;
	if (!(aconf->status & CONF_SERVER_MASK))
	    continue;
	if (aconf->status == CONF_CONNECT_SERVER && !cline)
	    cline = aconf;
	else if (aconf->status == CONF_NOCONNECT_SERVER && !nline)
	    nline = aconf;
    }
    return nline;
}

/*
 * detach_conf 
 *    Disassociate configuration from the client. 
 *    Also removes a class from the list if marked for deleting.
 */
int detach_conf(aClient *cptr, aConfItem *aconf)
{
    Link  **lp, *tmp;

    lp = &(cptr->confs);

    while (*lp) 
    {
	if ((*lp)->value.aconf == aconf) 
	{
	    if ((aconf) && (Class (aconf))) 
	    {
		if (aconf->status & CONF_CLIENT_MASK)
		    if (ConfLinks(aconf) > 0)
			--ConfLinks(aconf);
		if (ConfMaxLinks(aconf) == -1 && ConfLinks(aconf) == 0) 
		{
		    free_class(Class (aconf));
		    Class       (aconf) = NULL;
		}
	    }
	    if (aconf && !--aconf->clients && IsIllegal(aconf))
		free_conf(aconf);
	    tmp = *lp;
	    *lp = tmp->next;
	    free_link(tmp);
	    return 0;
	}
	else
	    lp = &((*lp)->next);
    }
    return -1;
}

static int is_attached(aConfItem *aconf, aClient *cptr)
{
    Link   *lp;
    
    for (lp = cptr->confs; lp; lp = lp->next)
	if (lp->value.aconf == aconf)
	    break;

    return (lp) ? 1 : 0;
}

/*
 * * attach_conf 
 *    Associate a specific configuration entry to a *local* 
 *    client (this is the one which used in accepting the 
 *    connection). Note, that this automatically changes the 
 *    attachment if there was an old one...
 */
int attach_conf(aClient *cptr, aConfItem *aconf)
{
    Link   *lp;

    if (is_attached(aconf, cptr)) 
    {
	return 1;
    }
    if (IsIllegal(aconf)) 
	return -1;

    /*
     * By using "ConfLinks(aconf) >= ConfMaxLinks(aconf).... the client
     * limit is set by the Y line, connection class, not by the
     * individual client count in each I line conf.
     *
     * If the requested change, is to turn them into an OPER, then they
     * are already attached to a fd there is no need to check for max in
     * a class now is there?
     * 
     * If OLD_Y_LIMIT is defined the code goes back to the old way I
     * lines used to work, i.e. number of clients per I line not total
     * in Y 
     * -Dianora
     */

#ifdef OLD_Y_LIMIT
    if ((aconf->status & (CONF_LOCOP | CONF_OPERATOR | CONF_CLIENT)) &&
	aconf->clients >= ConfMaxLinks(aconf) && ConfMaxLinks(aconf) > 0)
#else
	if ((aconf->status & (CONF_LOCOP | CONF_OPERATOR)) == 0) {
	    if ((aconf->status & CONF_CLIENT) &&
		ConfLinks(aconf) >= ConfMaxLinks(aconf) &&
		ConfMaxLinks(aconf) > 0)
#endif
	    {
		if (!find_fline(cptr)) 
		    return -3;	 /* Use this for printing error message */
		else {
		    send(cptr->fd,
			 "NOTICE FLINE :I: line is full, but you have an "
			 "F: line!\n",
			 56, 0);
		}
	    }
#ifndef OLD_Y_LIMIT
	}
#endif

    lp = make_link();
    lp->next = cptr->confs;
    lp->value.aconf = aconf;
    cptr->confs = lp;
    aconf->clients++;
    if (aconf->status & CONF_CLIENT_MASK)
	ConfLinks(aconf)++;
    return 0;
}

aConfItem  *find_admin()
{
    aConfItem *aconf;
    
    for (aconf = conf; aconf; aconf = aconf->next)
	if (aconf->status & CONF_ADMIN)
	    break;

    return (aconf);
}

/*
 * die/restart passes, like in df465 -mjs aconf->host =
 * X:<*PASSWORD*>:<password> aconf->passwd = X:<password>:<*PASSWORD*>
 */
char *find_diepass()
{
    aConfItem *aconf;

    for (aconf = conf; aconf; aconf = aconf->next)
	if (aconf->status & CONF_DRPASS)
	    return (aconf->host);

    return NULL;
}

char *find_restartpass()
{
    aConfItem *aconf;
    
    for (aconf = conf; aconf; aconf = aconf->next)
	if (aconf->status & CONF_DRPASS)
	    return (aconf->passwd);

    return NULL;
}

aConfItem *find_me()
{
    aConfItem *aconf;

    for (aconf = conf; aconf; aconf = aconf->next)
	if (aconf->status & CONF_ME)
	    return (aconf);

    return ((aConfItem *) NULL);	
}

/*
 * attach_confs Attach a CONF line to a client if the name passed
 * matches that for the conf file (for non-C/N lines) or is an exact
 * match (C/N lines only).  The difference in behaviour is to stop
 * C:*::* and N:*::*.
 */
aConfItem *attach_confs(aClient *cptr, char *name, int statmask)
{
    aConfItem *tmp;
    aConfItem  *first = NULL;
    int         len = strlen(name);

    if (!name || len > HOSTLEN)
	return ((aConfItem *) NULL);

    for (tmp = conf; tmp; tmp = tmp->next) 
    {
	if ((tmp->status & statmask) && !IsIllegal(tmp) &&
	    ((tmp->status & (CONF_SERVER_MASK | CONF_HUB)) == 0) &&
	    tmp->name && !match(tmp->name, name)) 
	{
	    if (!attach_conf(cptr, tmp) && !first)
		first = tmp;
	}
	else if ((tmp->status & statmask) && !IsIllegal(tmp) &&
		 (tmp->status & (CONF_SERVER_MASK | CONF_HUB)) &&
		 tmp->name && !mycmp(tmp->name, name)) 
	{
	    if (!attach_conf(cptr, tmp) && !first)
		first = tmp;
	}
    }
    return (first);
}

/* Added for new access check meLazy */
aConfItem *attach_confs_host(aClient *cptr, char *host, int statmask)
{
    aConfItem *tmp;
    aConfItem  *first = NULL;
    int         len = strlen(host);

    if (!host || len > HOSTLEN)
	return ((aConfItem *) NULL);

    for (tmp = conf; tmp; tmp = tmp->next) 
    {
	if ((tmp->status & statmask) && !IsIllegal(tmp) &&
	    (tmp->status & CONF_SERVER_MASK) == 0 &&
	    (!tmp->host || match(tmp->host, host) == 0)) 
	{
	    if (!attach_conf(cptr, tmp) && !first)
		first = tmp;
	}
	else if ((tmp->status & statmask) && !IsIllegal(tmp) &&
		 (tmp->status & CONF_SERVER_MASK) &&
		 (tmp->host && mycmp(tmp->host, host) == 0)) 
	{
	    if (!attach_conf(cptr, tmp) && !first)
		first = tmp;
	}
    }
    return (first);
}

/* find a conf entry which matches the hostname and has the same name. */
aConfItem *find_conf_exact(char *name, char *user, char *host, int statmask)
{
    aConfItem *tmp;
    char        userhost[USERLEN + HOSTLEN + 3];

    (void) ircsprintf(userhost, "%s@%s", user, host);

    for (tmp = conf; tmp; tmp = tmp->next) 
    {
	if (!(tmp->status & statmask) || !tmp->name || !tmp->host ||
	    mycmp(tmp->name, name))
	    continue;
	
	/* Accept if the *real* hostname (usually sockecthost) socket
	 * host) matches *either* host or name field of the configuration.
	 */

	if (match(tmp->host, userhost))
	    continue;
	if (tmp->status & (CONF_OPERATOR | CONF_LOCOP)) 
	{
	    if (tmp->clients < MaxLinks(Class (tmp)))
		return tmp;
	    
	    else
		continue;
	}
	else
	    return tmp;
    }
    return ((aConfItem *) NULL);
}

/*
 * find_conf_name()
 * 
 * 
 * Accept if the *real* hostname (usually sockecthost) * matches *either*
 * host or name field of the configuration.
 */

aConfItem *find_conf_name(char *name, int statmask)
{
    aConfItem *tmp;

    for (tmp = conf; tmp; tmp = tmp->next) 
    {
	if ((tmp->status & statmask) && (!tmp->name ||
					 match(tmp->name, name) == 0))
	    return tmp;
    }
    return ((aConfItem *) NULL);
}

aConfItem *find_conf(Link *lp, char *name, int statmask)
{
    aConfItem  *tmp;
    int         namelen = name ? strlen(name) : 0;

    if (namelen > HOSTLEN)
	return ((aConfItem *) NULL);

    for (; lp; lp = lp->next) 
    {
	tmp = lp->value.aconf;
	if ((tmp->status & statmask) &&
	    (((tmp->status & (CONF_SERVER_MASK | CONF_HUB)) &&
	      tmp->name && !mycmp(tmp->name, name)) ||
	     ((tmp->status & (CONF_SERVER_MASK | CONF_HUB)) == 0 &&
	      tmp->name && !match(tmp->name, name))))
	    return tmp;
    }
    return ((aConfItem *) NULL);
}

/* Added for new access check    meLazy */
aConfItem *find_conf_host(Link *lp, char *host, int statmask)
{
    aConfItem  *tmp;
    int         hostlen = host ? strlen(host) : 0;

    if (hostlen > HOSTLEN || BadPtr(host))
	return ((aConfItem *) NULL);
    for (; lp; lp = lp->next) 
    {
	tmp = lp->value.aconf;
	if (tmp->status & statmask &&
	    (!(tmp->status & CONF_SERVER_MASK || tmp->host) ||
	     (tmp->host && !match(tmp->host, host))))
	    return tmp;
    }
    return ((aConfItem *) NULL);
}

/* Added for CPU friendly U line checks - Raistlin */
aConfItem *find_uline(Link *lp, char *host) 
{
    aConfItem *tmp;
    int hostlen = host ? strlen(host) : 0;

    if (hostlen > HOSTLEN || BadPtr(host))
	return ((aConfItem *) NULL);

    for (; lp; lp = lp->next) 
    {
	tmp = lp->value.aconf;
	if (tmp->status & CONF_ULINE && (tmp->host && !mycmp(tmp->host, host)))
	    return tmp;
    }
    return ((aConfItem *) NULL);
}

aConfItem *find_is_ulined(char *host) 
{
    aConfItem *tmp;
    int hostlen = host ? strlen(host) : 0;

    if (hostlen > HOSTLEN || BadPtr(host))
	return ((aConfItem *) NULL);

    for (tmp = conf; tmp; tmp = tmp->next) 
    {
	if (tmp->status & CONF_ULINE && (tmp->host && !mycmp(tmp->host, host)))
	    return tmp;
    }

    return ((aConfItem *) NULL);
}

/*
 * find_conf_ip
 * 
 * Find a conf line using the IP# stored in it to search upon. Added
 * 1/8/92 by Avalon.
 */
aConfItem *find_conf_ip(Link *lp, char *ip, char *user, int statmask)
{
    aConfItem *tmp;
    char      *s;

    for (; lp; lp = lp->next) 
    {
	tmp = lp->value.aconf;
	if (!(tmp->status & statmask))
	    continue;
	s = strchr(tmp->host, '@');
	if (s == (char *) NULL)
	    continue;
	*s = '\0';
	if (match(tmp->host, user)) 
	{
	    *s = '@';
	    continue;
	}
	*s = '@';
	if (!memcmp((char *) &tmp->ipnum, ip, sizeof(struct in_addr)))
	    return tmp;
    }
    return ((aConfItem *) NULL);
}


/*
 * find_conf_entry
 * 
 * - looks for a match on all given fields.
 */
aConfItem *find_conf_entry(aConfItem *aconf, int mask)
{
    aConfItem *bconf;

    for (bconf = conf, mask &= ~CONF_ILLEGAL; bconf; bconf = bconf->next) 
    {
	if (!(bconf->status & mask) || (bconf->port != aconf->port))
	    continue;

	if ((BadPtr(bconf->host) && !BadPtr(aconf->host)) ||
	    (BadPtr(aconf->host) && !BadPtr(bconf->host)))
	    continue;
	if (!BadPtr(bconf->host) && mycmp(bconf->host, aconf->host))
	    continue;

	if ((BadPtr(bconf->passwd) && !BadPtr(aconf->passwd)) ||
	    (BadPtr(aconf->passwd) && !BadPtr(bconf->passwd)))
	    continue;
	if (!BadPtr(bconf->passwd) &&
	    mycmp(bconf->passwd, aconf->passwd))
	    continue;

	if ((BadPtr(bconf->name) && !BadPtr(aconf->name)) ||
	    (BadPtr(aconf->name) && !BadPtr(bconf->name)))
	    continue;
	if (!BadPtr(bconf->name) && mycmp(bconf->name, aconf->name))
	    continue;
	break;
    }
    return bconf;
}

/*
 * rehash
 * 
 * Actual REHASH service routine. Called with sig == 0 if it has been
 * called as a result of an operator issuing this command, else assume
 * it has been called as a result of the server receiving a HUP signal.
 */
int rehash(aClient *cptr, aClient *sptr, int sig)
{
    aConfItem **tmp = &conf, *tmp2;
    aClass     *cltmp;
    aClient    *acptr;
    int         i,  ret = 0, fd;

    if (sig == SIGHUP) 
    {
	sendto_ops("Got signal SIGHUP, reloading ircd conf. file");
#ifdef	ULTRIX
	if (fork() > 0)
	    exit(0);
	write_pidfile();
#endif
	do_rehash_akills();
    }

    if ((fd = openconf(configfile)) == -1) 
    {
	sendto_ops("Can't open %s file aborting rehash!", configfile);
	return -1;
    }

    /* Shadowfax's LOCKFILE code */
#ifdef LOCKFILE
    do_pending_klines();
#endif

    for (i = 0; i <= highest_fd; i++)
	if ((acptr = local[i]) && !IsMe(acptr)) 
	{
	    /*
	     * Nullify any references from client structures to this host
	     * structure which is about to be freed. Could always keep
	     * reference counts instead of this....-avalon
	     */
	    acptr->hostp = NULL;
	}
	
    while ((tmp2 = *tmp)) 
    {
	if (tmp2->clients || tmp2->status & CONF_LISTEN_PORT) 
	{
	    /* Configuration entry is still in use by some local
	     * clients, cannot delete it--mark it so that it will be
	     * deleted when the last client exits...
	     */
	    if (!(tmp2->status & (CONF_LISTEN_PORT | CONF_CLIENT))) 
	    {
		*tmp = tmp2->next;
		tmp2->next = NULL;
	    }
	    else
		tmp = &tmp2->next;
	    tmp2->status |= CONF_ILLEGAL;
	}
	else if(tmp2->status & CONF_SQLINE) 
	{
	    tmp = &tmp2->next;
	}
	else 
	{
	    *tmp = tmp2->next;
	    free_conf(tmp2);
	}
    }
    /*
     * We don't delete the class table, rather mark all entries for
     * deletion. The table is cleaned up by check_class. - avalon
     */

    for (cltmp = NextClass(FirstClass()); cltmp; cltmp = NextClass(cltmp))
	MaxLinks(cltmp) = -1;

    if (sig != SIGINT)
	flush_cache();		/* Flush DNS cache */
	
    clear_conf_list(&KList1);
    clear_conf_list(&KList2);
    clear_conf_list(&KList3);
	
    clear_conf_list(&ZList1);	/* Only z lines of this form allowed */

    /* Don't clear SZLine list */
   
    clear_conf_list(&EList1);
    clear_conf_list(&EList2);
    clear_conf_list(&EList3);
	
    clear_conf_list(&FList1);
    clear_conf_list(&FList2);
    clear_conf_list(&FList3);
	
    (void) initconf(0, fd);

#ifdef SEPARATE_QUOTE_KLINES_BY_DATE
    {
	char        timebuffer[20];
	char        filenamebuf[1024];
	struct tm  *tmptr;
		  
	tmptr = localtime(&NOW);
	(void) strftime(timebuffer, 20, "%y%m%d", tmptr);
	ircsprintf(filenamebuf, "%s.%s", klinefile, timebuffer);
		  
	if ((fd = openconf(filenamebuf)) == -1)
	    sendto_ops("Can't open %s file klines could be missing!",
		       filenamebuf);
	else
	    (void) initconf(0, fd);
    }
#else
# ifdef KLINEFILE
    if ((fd = openconf(klinefile)) == -1)
	sendto_ops("Can't open %s file klines could be missing!", klinefile);
    else
	(void) initconf(0, fd);
# endif
#endif

    close_listeners();

    /* flush out deleted I and P lines although still in use. */

    for (tmp = &conf; (tmp2 = *tmp);)
	if (!(tmp2->status & CONF_ILLEGAL))
	    tmp = &tmp2->next;
	else 
	{
	    *tmp = tmp2->next;
	    tmp2->next = NULL;
	    if (!tmp2->clients)
		free_conf(tmp2);
	}
    rehashed = 1;

    for (i = 0; i <= highest_fd; i++)
    {

	/* our Y: lines could have changed, rendering our client ping
	   cache invalid. Reset it here. - lucas */

	if ((acptr = local[i]) && !IsMe(acptr))
	{
	    if(IsRegistered(acptr)) 
		acptr->pingval = get_client_ping(acptr);
	    acptr->sendqlen = get_sendq(acptr);
	}
    }

    return ret;
}

/*
 * openconf
 * 
 * returns -1 on any error or else the fd opened from which to read the
 * configuration file from.  This may either be the file direct or one
 * end of a pipe from m4.
 */
int openconf(char *filename)
{
    return open(filename, O_RDONLY);
}

extern char *getfield();

static int server_info[] =
{
    CAPAB_DOZIP, 'Z',
    CAPAB_DODKEY, 'E', 
    0, 0
};

static int oper_access[] =
{
    ~(OFLAG_ADMIN|OFLAG_SADMIN|OFLAG_ZLINE|OFLAG_ADMIN), '*',
    OFLAG_LOCAL,   'o',
    OFLAG_GLOBAL,  'O',
    OFLAG_REHASH,  'r',
    OFLAG_DIE,     'D',
    OFLAG_RESTART, 'R',
    OFLAG_GLOBOP,  'h',
    OFLAG_WALLOP,  'w',
    OFLAG_LOCOP,   'l',
    OFLAG_LROUTE,  'c',
    OFLAG_GROUTE,  'C',
    OFLAG_LKILL,   'k',
    OFLAG_GKILL,   'K',
    OFLAG_KLINE,   'b',
    OFLAG_UNKLINE, 'B',
    OFLAG_LNOTICE, 'n',
    OFLAG_GNOTICE, 'N',
    OFLAG_ADMIN,   'A',
    OFLAG_SADMIN,  'a',
    OFLAG_UMODEc,  'u',
    OFLAG_UMODEf,  'f',
    OFLAG_ZLINE,   'z',
    0, 0 };

/*
 * initconf() 
 *    Read configuration file. 
 * 
 * - file descriptor pointing to config file to use returns -1, 
 * if file cannot be opened, 0 if file opened
 */

#define MAXCONFLINKS 150

int
initconf(int opt, int fd)
{
    static char quotes[9][2] =
    {
	{'b', '\b'},
	{'f', '\f'},
	{'n', '\n'},
	{'r', '\r'},
	{'t', '\t'},
	{'v', '\v'},
	{'\\', '\\'},
	{0, 0}
    };
    
    char       *tmp, *s;
    int         i, dontadd;
    char        line[512], c[80];
    int         ccount = 0, ncount = 0;
    u_long      vaddr;

    aConfItem  *aconf = NULL;

    (void) dgets(-1, NULL, 0);	/* make sure buffer is at empty pos  */

    while ((i = dgets(fd, line, sizeof(line) - 1)) > 0) 
    {
	line[i] = '\0';
	if ((tmp = (char *) strchr(line, '\n')))
	    *tmp = '\0';
	else
	    while (dgets(fd, c, sizeof(c) - 1) > 0)
		if ((tmp = (char *) strchr(c, '\n'))) 
		{
		    *tmp = '\0';
		    break;
		}
	
	/* Do quoting of characters detection. */

	for (tmp = line; *tmp; tmp++) 
	{
	    if (*tmp == '\\') 
	    {
		for (i = 0; quotes[i][0]; i++)
		    if (quotes[i][0] == *(tmp + 1)) 
		    {
			*tmp = quotes[i][1];
			break;
		    }
		if (!quotes[i][0])
		    *tmp = *(tmp + 1);
		if (!*(tmp + 1))
		    break;
		else
		    for (s = tmp; (*s = *(s + 1)); s++);
	    }
	}

	if (!*line || line[0] == '#' || line[0] == '\n' ||
	    line[0] == ' ' || line[0] == '\t')
	    continue;

	/* Could we test if it's conf line at all?        -Vesa */

	if (line[1] != ':') 
	{
	    Debug((DEBUG_ERROR, "Bad config line: %s", line));
	    continue;
	}

	if (aconf)
	    free_conf(aconf);
	aconf = make_conf();

	tmp = getfield(line);
	if (!tmp)
	    continue;
	dontadd = 0;
	switch (*tmp) 
	{
	case 'A':		
	case 'a':		/* Administrative info */
	    aconf->status = CONF_ADMIN;
	    break;

	case 'C':		/* Server where I should try to connect */
	case 'c':		
	    ccount++;
	    aconf->status = CONF_CONNECT_SERVER;
	    break;

	case 'Z':		/* Zap lines (immediate refusal)  */
	case 'z':
	    aconf->status = CONF_ZLINE;
	    break;

	case 'E':		/* kline exception lines */
	case 'e':		
	    aconf->status = CONF_ELINE;
	    break;

	case 'F':		/* Super-Exempt hosts */
	case 'f':
	    aconf->status = CONF_FLINE;
	    break;

	case 'G':		/* restricted gcos */
	case 'g':
	    aconf->status = CONF_GCOS;
	    break;

	case 'H':		/* Hub server line */
	case 'h':
	    aconf->status = CONF_HUB;
	    break;

	case 'i':		/* to connect me */
	case 'I':		
	    aconf->status = CONF_CLIENT;
	    break;
	case 'K':		/* the infamous klines */
	case 'k':
	    aconf->status = CONF_KILL;
	    break;
	    
	    /*
	     * Me. Host field is name used for this host 
	     * and port number is the number of the port 
	     */
	case 'M':
	case 'm':
	    aconf->status = CONF_ME;
	    break;
	    
	case 'N':		
	case 'n':

	    /* Server where I should NOT try to       
	     * connect in case of lp failures 
	     * but which tries to connect ME  
	     */
	    ++ncount;
	    aconf->status = CONF_NOCONNECT_SERVER;
	    break;


	case 'O':		/* Operator line */
	case 'o':		
	    aconf->status = CONF_OPERATOR;
	    break;

	case 'P':		/* listen port line */
	case 'p':
	    aconf->status = CONF_LISTEN_PORT;
	    break;

	case 'Q':		/* restricted nicknames */
	case 'q':
	    aconf->status = CONF_QUARANTINED_NICK;
	    break;
 
	case 'T':
	case 't':
	    aconf->status = CONF_MONINFO;
	    break;

	case 'U':		/* Ultimate Servers (aka God) */
	case 'u':
	    aconf->status = CONF_ULINE;
	    break;

	case 'X':		/* die/restart pass line */
	case 'x':
	    aconf->status = CONF_DRPASS;
	    break;
	    
	case 'Y':		/* Class line */
	case 'y':
	    aconf->status = CONF_CLASS;
	    break;

	default:
	    Debug((DEBUG_ERROR, "Error in config file: %s", line));
	    break;
	}

	if (IsIllegal(aconf))
	    continue;

	for (;;)      /* Fake loop, that I can use break here --msa  */
	{
	    if ((tmp = getfield(NULL)) == NULL)
		break;
	    
	    DupString(aconf->host, tmp);
	    
	    if ((tmp = getfield(NULL)) == NULL)
		break;
	    
	    DupString(aconf->passwd, tmp);
	    
	    if ((tmp = getfield(NULL)) == NULL)
		break;
	    
	    DupString(aconf->name, tmp);
	    
	    if ((tmp = getfield(NULL)) == NULL)
		break;

	    if (aconf->status & CONF_OPS) 
	    {
		int *i, flag;
		char *m = "*";
		for (m=(*tmp) ? tmp : m; *m; m++) 
		{
		    for (i=oper_access; (flag = *i); i+=2)
			if (*m==(char)(*(i+1))) 
			{
			    aconf->port |= flag;
			    break;
			}
		}
	        if (!(aconf->port & OFLAG_ISGLOBAL)) 
		    aconf->status = CONF_LOCOP;
	    } 
	    else if(aconf->status & CONF_NOCONNECT_SERVER)
	    {
            	int *i, flag;
		char *m = "*";
		for (m=(*tmp) ? tmp : m; *m; m++) 
		{
		    for (i=server_info; (flag = *i); i+=2)
			if (*m==(char)(*(i+1))) 
			{
			    aconf->port |= flag;
			    break;
			}
		}
	    }
	    else 
	    {
		aconf->port=atoi(tmp);
	    }
	    
	    if ((tmp = getfield(NULL)) == NULL)
		break;							

	    Class       (aconf) = find_class(atoi(tmp));

	    if (aconf->status & CONF_CONNECT_SERVER)
	    {
		if ((tmp = getfield(NULL)) == NULL)
		    break;

		DupString(aconf->localhost, tmp);
	    }

	    break;

	    /* NOTREACHED */
	}

	if(aconf->status & CONF_QUARANTINE)
	{
	    if(*aconf->name && *aconf->name == '#')
		aconf->status = CONF_QUARANTINED_CHAN;
	}
	
	/*
	 * If conf line is a class definition, create a class entry
	 * for it and make the conf_line illegal and delete it.
	 */
	if (aconf->status & CONF_CLASS) 
	{
	    add_class(atoi(aconf->host), atoi(aconf->passwd),
		      atoi(aconf->name), aconf->port,
		      tmp ? atoi(tmp) : 0);
	    continue;
	}
	/*
	 * associate each conf line with a class by using a pointer
	 * to the correct class record. -avalon
	 */
	if (aconf->status & (CONF_CLIENT_MASK | CONF_LISTEN_PORT)) 
	{
	    if (Class (aconf) == 0)
		Class       (aconf) = find_class(0);
	    if (MaxLinks(Class (aconf)) < 0)
		Class       (aconf) = find_class(0);
	}

	if (aconf->status & CONF_CLIENT)
	{
	    if(strchr(aconf->host, '@'))
		aconf->flags |= CONF_FLAGS_I_HOST_HAS_AT;
	    if(strchr(aconf->name, '@'))
		aconf->flags |= CONF_FLAGS_I_NAME_HAS_AT;
#if (RIDICULOUS_PARANOIA_LEVEL>=1)
	    if(myncmp(aconf->passwd, "oper", 4) == 0)
	    {
		if((aconf->passwd[4] == '.') || (aconf->passwd[4] == '\0'))
		{
		    char *tmpd = aconf->passwd;
		    char *tmp = aconf->passwd + 4;

		    aconf->flags |= CONF_FLAGS_I_OPERPORT;
		    if(*tmp)
			tmp++;
		    DupString(aconf->passwd, tmp);
		    MyFree(tmpd);
		}
	    }
#endif
	}

	if (aconf->status & (CONF_LISTEN_PORT | CONF_CLIENT)) 
	{
	    aConfItem  *bconf;

	    if ((bconf = find_conf_entry(aconf, aconf->status))) 
	    {
		delist_conf(bconf);
		bconf->status &= ~CONF_ILLEGAL;
		if (aconf->status == CONF_CLIENT) 
		{
		    bconf->class->links -= bconf->clients;
		    bconf->class = aconf->class;
		    bconf->class->links += bconf->clients;
		}
		free_conf(aconf);
		aconf = bconf;
	    }
	    else if (aconf->host &&
		     aconf->status == CONF_LISTEN_PORT)
		(void) add_listener(aconf);
	}
	if (aconf->status & CONF_SERVER_MASK)
	    if (ncount > MAXCONFLINKS || ccount > MAXCONFLINKS ||
		!aconf->host || strchr(aconf->host, '*') ||
		strchr(aconf->host, '?') || !aconf->name)
		continue;
	
	if (aconf->status & (CONF_SERVER_MASK | CONF_LOCOP | CONF_OPERATOR))
	    if (!strchr(aconf->host, '@') && *aconf->host != '/') 
	    {
		char       *newhost;
		int         len = 3;
				/* *@\0 = 3 */
		len += strlen(aconf->host);
		newhost = (char *) MyMalloc(len);
		(void) ircsprintf(newhost, "*@%s", aconf->host);
		MyFree(aconf->host);
		aconf->host = newhost;
	    }
	if (aconf->status & CONF_SERVER_MASK) 
	{
	    if (BadPtr(aconf->passwd))
		continue;
	    else if (!(opt & BOOT_QUICK))
		(void) lookup_confhost(aconf);
	}

	/*
	 * Own port and name cannot be changed after the startup.  (or
	 * could be allowed, but only if all links are closed  first). 
	 * Configuration info does not override the name and port  if
	 * previously defined. Note, that "info"-field can be changed
	 * by "/rehash". Can't change vhost mode/address either
	 */
	
	if (aconf->status == CONF_ME) 
	{
	    strncpyzt(me.info, aconf->name, sizeof(me.info));
	    
	    if (me.name[0] == '\0' && aconf->host[0]) 
	    {
		strncpyzt(me.name, aconf->host,
			  sizeof(me.name));
		if ((aconf->passwd[0] != '\0') && (aconf->passwd[0] != '*')) 
		{
		    memset((char *) &vserv, '\0', sizeof(vserv));
		    vserv.sin_family = AF_INET;
		    vaddr = inet_addr(aconf->passwd);
		    memcpy((char *) &vserv.sin_addr, (char *) &vaddr, 
			   sizeof(struct in_addr));
		    specific_virtual_host = 1;
		}
	    }

	    if (portnum < 0 && aconf->port >= 0)
		portnum = aconf->port;

	}

#ifdef WINGATE_NOTICE
	if (aconf->status == CONF_MONINFO)
	{
	    if(!aconf->host || aconf->host[0] == '\0')
		strncpyzt(ProxyMonHost, MONITOR_HOST, sizeof(ProxyMonHost));
	    else
		strncpyzt(ProxyMonHost, aconf->host, sizeof(ProxyMonHost));
	    
	    strcpy(ProxyMonURL, "http://");

	    if(!aconf->passwd || aconf->passwd[0] == '\0')
		strncpyzt((ProxyMonURL + 7), DEFAULT_PROXY_INFO_URL,
			  sizeof(ProxyMonURL) - 7);
	    else
		strncpyzt((ProxyMonURL + 7), aconf->passwd,
			  sizeof(ProxyMonURL) - 7);
	    
	    continue; /* no need to keep this as a conf entry.. */
	} 
#endif
	
	if ((aconf->status & CONF_KILL) && aconf->host) 
	{
	    char       *host = host_field(aconf);

	    dontadd = 1;
	    switch (sortable(host)) 
	    {
	    case 0:
		l_addto_conf_list(&KList3, aconf, host_field);
		break;
	    case 1:
		addto_conf_list(&KList1, aconf, host_field);
		break;
	    case -1:
		addto_conf_list(&KList2, aconf, rev_host_field);
		break;
	    }

	    MyFree(host);
	}

	if (aconf->host && (aconf->status & CONF_ZLINE)) 
	{
	    char       *host = host_field(aconf);

	    dontadd = 1;
	    switch (sortable(host)) 
	    {
	    case 0:
		break;
	    case 1:
		addto_conf_list(&ZList1, aconf, host_field);
		break;
	    case -1:
		break;
	    }
	    
	    MyFree(host);
	}

	if (aconf->host && (aconf->status & CONF_ELINE)) 
	{
	    char       *host = host_field(aconf);

	    dontadd = 1;
	    switch (sortable(host)) 
	    {
	    case 0:
		l_addto_conf_list(&EList3, aconf, host_field);
		break;
	    case 1:
		addto_conf_list(&EList1, aconf, host_field);
		break;
	    case -1:
		addto_conf_list(&EList2, aconf, rev_host_field);
		break;
	    }
	    MyFree(host);
	}

	if (aconf->host && (aconf->status & CONF_FLINE)) 
	{
	    char       *host = host_field(aconf);

	    dontadd = 1;
	    switch (sortable(host)) 
	    {
	    case 0:
		l_addto_conf_list(&FList3, aconf, host_field);
		break;
	    case 1:
		addto_conf_list(&FList1, aconf, host_field);
		break;
	    case -1:
		addto_conf_list(&FList2, aconf, rev_host_field);
		break;
	    }
	    MyFree(host);
	}

	(void) collapse(aconf->host);
	(void) collapse(aconf->name);
	Debug((DEBUG_NOTICE,
	       "Read Init: (%d) (%s) (%s) (%s) (%d) (%d)",
	       aconf->status, aconf->host, aconf->passwd,
	       aconf->name, aconf->port, Class (aconf)));
	if (!dontadd) 
	{
	    aconf->next = conf;
	    conf = aconf;
	}
	aconf = NULL;
    }
    if (aconf)
	free_conf(aconf);
    (void) dgets(-1, NULL, 0);	/* make sure buffer is at empty pos */
    (void) close(fd);
    check_class();
    nextping = nextconnect = time(NULL);
    return 0;
}

/*
 * lookup_confhost Do (start) DNS lookups of all hostnames in the conf
 * line and convert an IP addresses in a.b.c.d number for to IP#s.
 * 
 * cleaned up Aug 3'97 - Dianora
 */
static int lookup_confhost(aConfItem *aconf)
{
    char   *s;
    struct hostent *hp;
    Link        ln;
    if (BadPtr(aconf->host) || BadPtr(aconf->name)) 
    {
	if (aconf->ipnum.s_addr == -1)
	    memset((char *) &aconf->ipnum, '\0', sizeof(struct in_addr));

	Debug((DEBUG_ERROR, "Host/server name error: (%s) (%s)",
	       aconf->host, aconf->name));
	return -1;
    }
    if ((s = strchr(aconf->host, '@')))
	s++;
    else
	s = aconf->host;
    /*
     * Do name lookup now on hostnames given and store the ip
     * numbers in conf structure.
     */
    if (!isalpha(*s) && !isdigit(*s)) 
    {
	if (aconf->ipnum.s_addr == -1)
	    memset((char *) &aconf->ipnum, '\0', sizeof(struct in_addr));

	Debug((DEBUG_ERROR, "Host/server name error: (%s) (%s)",
	       aconf->host, aconf->name));
	return -1;
    }
    /*
     * Prepare structure in case we have to wait for a reply which
     * we get later and store away.
     */
    ln.value.aconf = aconf;
    ln.flags = ASYNC_CONF;
    
    if (isdigit(*s))
	aconf->ipnum.s_addr = inet_addr(s);
    else if ((hp = gethost_byname(s, &ln)))
	memcpy((char *) &(aconf->ipnum), hp->h_addr,
	       sizeof(struct in_addr));

    if (aconf->ipnum.s_addr == -1)
	memset((char *) &aconf->ipnum, '\0', sizeof(struct in_addr));
    {
	Debug((DEBUG_ERROR, "Host/server name error: (%s) (%s)",
	       aconf->host, aconf->name));
	return -1;
    }
    /* NOTREACHED */
    return 0;
}

int find_eline(aClient *cptr)
{
    return find_conf_match(cptr, &EList1, &EList2, &EList3);
}

int find_fline(aClient *cptr)
{
    return find_conf_match(cptr, &FList1, &FList2, &FList3);
}

/*
 * find_kill
 * 
 * See if this user is klined already, and if so, return aConfItem pointer
 * to the entry for this kline. This wildly changes the way find_kill
 * works -Dianora
 * 
 */
aConfItem *find_kill(aClient *cptr)
{
    char       *host, *name;
    aConfItem  *ret;
    if (!cptr->user)
	return 0;

    host = cptr->sockhost;
    name = cptr->user->username;

    if (strlen(host) > (size_t) HOSTLEN ||
	(name ? strlen(name) : 0) > (size_t) HOSTLEN)
	return (0);

    if (find_eline(cptr))
	return 0;
   
    ret=find_is_klined(host, name);
    if (ret!=NULL) return ret;
    host=cptr->hostip;
    return (find_is_klined(host, name));
}

aConfItem *find_kill_perm(aClient *cptr)
{
    char       *host, *name;
    aConfItem  *ret;
    if (!cptr->user)
	return 0;

    host = cptr->sockhost;
    name = cptr->user->username;

    if (strlen(host) > (size_t) HOSTLEN ||
	(name ? strlen(name) : 0) > (size_t) HOSTLEN)
	return (0);

    if (find_eline(cptr))
	return 0;
   
    ret=find_is_klined_perm(host, name);
    if (ret!=NULL) return ret;
    host=cptr->hostip;
    return (find_is_klined_perm(host, name));
}

/*
 * WARNING, no sanity checking on length of name,host etc. thats
 * expected to be done by caller.... *sigh* -Dianora
 */
aConfItem *find_is_klined(char *host, char *name)
{
    aConfList  *list;
    char        rev[HOSTLEN + 1];	
    aConfItem  *kill_list_ptr;	/* used for the link list only  */
    aConfItem  *last_list_ptr;
    aConfItem  *tmp_list_ptr;
    aConfItem  *tmp;

    /*
     * Temporary kline handling... I expect this list to be very tiny.
     * (crosses fingers) so CPU time in this, should be minimum.
     * -Dianora
     */
    
    if (temporary_klines) 
    {
	kill_list_ptr = last_list_ptr = temporary_klines;
	
	while (kill_list_ptr) 
	{
	    if (kill_list_ptr->hold <= NOW && kill_list_ptr->hold!=0xFFFFFFFF) 
	    {			/* a kline has expired */
		if (temporary_klines == kill_list_ptr) 
		{
		    /*
		     * Its pointing to first one in link list 
		     * so, bypass this one, remember bad things can happen
		     * if you try to use an already freed pointer..
		     */
		    
		    temporary_klines = last_list_ptr = tmp_list_ptr =
			kill_list_ptr->next;
		}
		else 
		{
		    /* its in the middle of the list, so link around it */
		    tmp_list_ptr = last_list_ptr->next = kill_list_ptr->next;
		}

		MyFree(kill_list_ptr->host);
		MyFree(kill_list_ptr->name);
		MyFree(kill_list_ptr->passwd);
		MyFree(kill_list_ptr);
		kill_list_ptr = tmp_list_ptr;
	    }
	    else 
	    {
		if ((kill_list_ptr->name && 
		     (!name || !match(kill_list_ptr->name, name))) && 
		    (kill_list_ptr->host && 
		     (!host || !match(kill_list_ptr->host, host))))
		    return (kill_list_ptr);
		last_list_ptr = kill_list_ptr;
		kill_list_ptr = kill_list_ptr->next;
	    }
	}
    }
    
    reverse(rev, host);

    /*
     * I have NEVER seen a kline with a port field, have you? I have
     * removed the testing of the port number from here -Dianora
     */
    /* Start with hostnames of the form "*word" (most frequent) -Sol */

    list = &KList2;
    while ((tmp = find_matching_conf(list, rev)) != NULL) 
    {
	if (tmp->name && (!name || !match(tmp->name, name)))
	    return (tmp);
	list = NULL;
    }

    /* Try hostnames of the form "word*" -Sol */
    
    list = &KList1;
    while ((tmp = find_matching_conf(list, host)) != NULL) 
    {
	if (tmp->name && (!name || !match(tmp->name, name)))
	    return (tmp);
	list = NULL;
    }

    /* If none of the above worked, try non-sorted entries -Sol */

    list = &KList3;
    while ((tmp = l_find_matching_conf(list, host)) != NULL) 
    {
	if (tmp->host && tmp->name && (!name || !match(tmp->name, name)))
	    return (tmp);
	list = NULL;
    }
    return ((aConfItem *) NULL);
}

aConfItem *find_is_klined_perm(char *host, char *name)
{
    aConfList  *list;
    aConfItem  *tmp;
    char        rev[HOSTLEN + 1];	
    
    reverse(rev, host);

    /*
     * I have NEVER seen a kline with a port field, have you? I have
     * removed the testing of the port number from here -Dianora
     */
    /* Start with hostnames of the form "*word" (most frequent) -Sol */

    list = &KList2;
    while ((tmp = find_matching_conf(list, rev)) != NULL) 
    {
	if (tmp->name && (!name || !match(tmp->name, name)))
	    return (tmp);
	list = NULL;
    }

    /* Try hostnames of the form "word*" -Sol */
    
    list = &KList1;
    while ((tmp = find_matching_conf(list, host)) != NULL) 
    {
	if (tmp->name && (!name || !match(tmp->name, name)))
	    return (tmp);
	list = NULL;
    }

    /* If none of the above worked, try non-sorted entries -Sol */

    list = &KList3;
    while ((tmp = l_find_matching_conf(list, host)) != NULL) 
    {
	if (tmp->host && tmp->name && (!name || !match(tmp->name, name)))
	    return (tmp);
	list = NULL;
    }
    return ((aConfItem *) NULL);
}

/*
 * report_matching_host_klines
 * 
 * inputs               - aClient pointer pointing to user who requested stats
 * k output             - NONE side effects     -
 * 
 * report klines that are in the same "close" domain as user
 * 
 * -Dianora
 */
void report_matching_host_klines(aClient *cptr, char *host)
{
    char       *pass;
    char       *name = (char *) NULL;
    char       *found_host = (char *) NULL;
    aConfItem  *tmp;
    aConfList  *list;
    static char null[] = "<NULL>";
    char        rev[HOSTLEN + 1];	

    if (strlen(host) > (size_t) HOSTLEN ||
	(name ? strlen(name) : 0) > (size_t) HOSTLEN)
	return;

    reverse(rev, host);
    
    /*  Start with hostnames of the form "*word" (most frequent) -Sol */

    list = &KList2;
    while ((tmp = find_matching_conf(list, rev)) != NULL) 
    {
	pass = BadPtr(tmp->passwd) ? null : tmp->passwd;
	name = BadPtr(tmp->name) ? null : tmp->name;
	found_host = BadPtr(tmp->host) ? null : tmp->host;
	if (tmp->status == CONF_KILL)
	    sendto_one(cptr, rpl_str(RPL_STATSKLINE), me.name,
		       cptr->name, 'K', found_host,
		       name, 0, pass);
	list = NULL;
    }

    /* Try hostnames of the form "word*" -Sol */

    list = &KList1;
    while ((tmp = find_matching_conf(list, host)) != NULL) 
    {
	pass = BadPtr(tmp->passwd) ? null : tmp->passwd;
	name = BadPtr(tmp->name) ? null : tmp->name;
	found_host = BadPtr(tmp->host) ? null : tmp->host;
	if (tmp->status == CONF_KILL)
	    sendto_one(cptr, rpl_str(RPL_STATSKLINE), me.name,
		       cptr->name, 'K', found_host,
		       name, 0, pass);
	list = NULL;
    }

    /* If none of the above worked, try non-sorted entries -Sol */

    list = &KList3;
    while ((tmp = l_find_matching_conf(list, host)) != NULL) 
    {
	pass = BadPtr(tmp->passwd) ? null : tmp->passwd;
	name = BadPtr(tmp->name) ? null : tmp->name;
	found_host = BadPtr(tmp->host) ? null : tmp->host;
	if (tmp->status == CONF_KILL)
	    sendto_one(cptr, rpl_str(RPL_STATSKLINE), me.name,
		       cptr->name, 'K', found_host,
		       name, 0, pass);
	list = NULL;
    }
}

/*
 * find_zkill is only called when a /quote zline is applied all quote
 * zlines are sortable, of the form nnn.nnn.nnn.* or nnn.nnn.nnn.nnn
 * There is no reason to check for all three possible formats as in
 * klines
 * 
 * - Dianora
 * 
 * inputs               - client pointer output         - return 1 if match is
 * found, and loser should die return 0 if no match is found and loser
 * shouldn't die side effects   - only sortable zline tree is searched
 */

aConfItem *find_zkill(aClient *cptr)
{
    char       *host;

    if (!cptr->user)
	return 0;
    
    host = cptr->hostip;		/* guaranteed to always be less than
					 * HOSTIPLEN - Dianora 
					 */

    if (find_eline(cptr))
	return 0;

    return (find_is_zlined(host));
}

aConfItem *find_zkill_perm(aClient *cptr)
{
    char       *host;

    if (!cptr->user)
	return 0;
    
    host = cptr->hostip;		/* guaranteed to always be less than
					 * HOSTIPLEN - Dianora 
					 */

    if (find_eline(cptr))
	return 0;

    return (find_is_zlined_perm(host));
}

/*
 * find_is_zlined
 * 
 * inputs               - pointer to host ip# output            - pointer to
 * aConfItem if found, NULL pointer if not side effects -
 */

aConfItem *find_is_zlined(char *host)
{
    aConfItem  *tmp;

    /*
     * This code is almost identical to find_zline but in the case of an
     * active quote zline, the loser deserves to know why they are being
     * zlined don't they? - Dianora
     */
   
    if (szlines) {
	tmp=szlines;
	while(tmp) {
	    if (match(tmp->host,host)==0) return tmp;
	    tmp=tmp->next;
	}
    }

    if ((tmp = find_matching_conf(&ZList1, host))) 
	if (tmp!=NULL) return (tmp);
    return NULL;
}

aConfItem *find_is_zlined_perm(char *host)
{
    aConfItem  *tmp;

    /*
     * This code is almost identical to find_zline but in the case of an
     * active quote zline, the loser deserves to know why they are being
     * zlined don't they? - Dianora
     */
   
    if ((tmp = find_matching_conf(&ZList1, host))) 
	if (tmp!=NULL) return (tmp);
    return NULL;
}

int find_conf_match(aClient *cptr, aConfList *List1, aConfList *List2,
		    aConfList *List3)
{
    char       *host, *name;
    aConfItem  *tmp;
    char        rev[HOSTLEN + 1];	
    aConfList  *list;

    if (!cptr->user)
	return 0;

    host = cptr->sockhost;
    name = cptr->user->username;

    if (strlen(host) > (size_t) HOSTLEN ||
	(name ? strlen(name) : 0) > (size_t) HOSTLEN)
	return (0);
    
    reverse(rev, host);

    /* Start with hostnames of the form "*word" (most frequent) -Sol */

    list = List2;
    while ((tmp = find_matching_conf(list, rev)) != NULL) 
    {
	if (tmp->name && (!name || !match(tmp->name, name))) 
	    return (tmp ? -1 : 0);
	list = NULL;
    }

    /* Try hostnames of the form "word*" -Sol */
    
    list = List1;
    while ((tmp = find_matching_conf(list, host)) != NULL) 
    {
	if (tmp->name && (!name || !match(tmp->name, name))) 
	    return (tmp ? -1 : 0);
	list = NULL;
    }

    /* If none of the above worked, try non-sorted entries -Sol */
    list = List3;
    while ((tmp = l_find_matching_conf(list, host)) != NULL) 
    {
	if (tmp->host && tmp->name && (!name || !match(tmp->name, name))) 
	    return (tmp ? -1 : 0);
	list = NULL;
    }

    return (tmp ? -1 : 0);
}

void add_szline(aConfItem *aconf)
{
    aconf->next = szlines;
    szlines=aconf;
}

void remove_szline(char *mask, int m) {
    aConfItem *aconf, *ac2, *ac3;
    ac2 = ac3 = aconf = szlines;
    while(aconf)
    {
        if((aconf->status & (CONF_ZLINE))
           && (aconf->status & (CONF_SZLINE)) &&
           aconf->host && (m==1 ? !match(mask, aconf->host) 
			   : !mycmp(mask, aconf->host)))
        {
            if (aconf == szlines)
                ac2 = ac3 = szlines = aconf->next;
            else
                ac2 = ac3->next = aconf->next;
            MyFree(aconf->passwd);
            MyFree(aconf->host);
            MyFree(aconf);
            aconf=ac2;
        }
	else
	{
            ac3=aconf;
            aconf=aconf->next;
        }
    }
}

void report_szlines(aClient *sptr)
{
    aConfItem *tmp;
    tmp=szlines;
    while(tmp)
    {
	sendto_one(sptr, rpl_str(RPL_STATSZLINE), me.name,
		   sptr->name, 'z' , tmp->host, 
		   BadPtr(tmp->passwd) ? "No Reason" : tmp->passwd);
	tmp=tmp->next;
    }
}

void send_szlines(aClient *cptr)
{
    aConfItem *tmp;
    tmp=szlines;
    while (tmp)
    {
	sendto_one(cptr, ":%s SZLINE %s :%s", me.name, tmp->host, tmp->passwd);
	tmp=tmp->next;
    }
}

/*
 * add_temp_kline
 * 
 * inputs               - pointer to aConfItem output           - none Side
 * effects      - links in given aConfItem into temporary kline link
 * list
 * 
 * -Dianora
 */

void add_temp_kline(aConfItem *aconf)
{
    aconf->next = temporary_klines;
    temporary_klines = aconf;
}

/*
 * flush_temp_klines
 * 
 * inputs               - NONE output           - NONE side effects     - All
 * temporary klines are flushed out. really should be used only for
 * cases of extreme goof up for now.
 */
void flush_temp_klines()
{
    aConfItem  *kill_list_ptr;

    if ((kill_list_ptr = temporary_klines)) 
    {
	while (kill_list_ptr) 
	{
	    temporary_klines = kill_list_ptr->next;
	    MyFree(kill_list_ptr->host);
	    MyFree(kill_list_ptr->name);
	    MyFree(kill_list_ptr->passwd);
	    MyFree(kill_list_ptr);
	    kill_list_ptr = temporary_klines;
	}
    }
}

/*
 * report_temp_klines
 * 
 * inputs               - aClient pointer output                - NONE side
 * effects      -
 * 
 */
void report_temp_klines(aClient *sptr) 
{
    aConfItem  *kill_list_ptr;
    aConfItem  *last_list_ptr;
    aConfItem  *tmp_list_ptr;
    char       *host, *name, *reason, type;
    int         len;
	
    if (temporary_klines) 
    {
	kill_list_ptr = last_list_ptr = temporary_klines;
		
	while (kill_list_ptr) 
	{
	    if (kill_list_ptr->hold <= NOW && kill_list_ptr->hold!=0xFFFFFFFF) 
	    {	
				/* kline has expired */
		if (temporary_klines == kill_list_ptr) 
		{
		    temporary_klines = last_list_ptr = tmp_list_ptr =
			kill_list_ptr->next;
		}
		else 
		{
		    tmp_list_ptr = last_list_ptr->next = kill_list_ptr->next;
		}
			
		MyFree(kill_list_ptr->host);
		MyFree(kill_list_ptr->name);
		MyFree(kill_list_ptr->passwd);
		MyFree(kill_list_ptr);
		kill_list_ptr = tmp_list_ptr;
	    }
	    else 
	    {
		if (kill_list_ptr->host)
		    host = kill_list_ptr->host;
		else
		    host = "*";
			
		if (kill_list_ptr->name)
		    name = kill_list_ptr->name;
		else
		    name = "*";
			
		if (kill_list_ptr->passwd)
		    reason = kill_list_ptr->passwd;
		else
		    reason = "No Reason";

		len = (kill_list_ptr->hold - NOW) / 60;
				
		if(kill_list_ptr->status==CONF_KILL)
		    type='k';
		else if(kill_list_ptr->status==CONF_AKILL &&
			kill_list_ptr->hold==0xFFFFFFFF)
		{
		    len = 0;
		    type='A';
		}
		else
		    type='a';
				
		sendto_one(sptr, rpl_str(RPL_STATSKLINE), me.name,
			   sptr->name, type, host, name, len, reason);
				
		last_list_ptr = kill_list_ptr;
		kill_list_ptr = kill_list_ptr->next;
	    }
	}
    }
}


/* a few handy functions */
/* third param (type):
 * 0: remove anything matching
 * CONF_AKILL: remove only CONF_AKILL
 * CONF_KILL: remove only CONF_KILL
 * or whatever.   - lucas
 * also returns number removed. - lucas
*/

int remove_temp_kline(char *host, char *user, int type) 
{
    aConfItem  *kill_list_ptr;
    aConfItem  *last_list_ptr;
    aConfItem  *tmp_list_ptr;
    int num_removed = 0;
	
    if (temporary_klines) 
    {
	kill_list_ptr = last_list_ptr = temporary_klines;
		
	while (kill_list_ptr) 
	{
	    if (!mycmp(kill_list_ptr->host, host) && 
		!mycmp(kill_list_ptr->name, user) &&
		(!type || type == kill_list_ptr->status)) 
	    {	/* kline has expired */
		if (temporary_klines == kill_list_ptr) 
		    temporary_klines = last_list_ptr = 
			tmp_list_ptr = kill_list_ptr->next;
		else 
		    tmp_list_ptr = last_list_ptr->next = kill_list_ptr->next;
		
		MyFree(kill_list_ptr->host);
		MyFree(kill_list_ptr->name);
		MyFree(kill_list_ptr->passwd);
		MyFree(kill_list_ptr);
		kill_list_ptr = tmp_list_ptr;
		num_removed++;
	    }
	    else 
	    {
		last_list_ptr = kill_list_ptr;
		kill_list_ptr = kill_list_ptr->next;
	    }                               
	}
    }
    return num_removed;
}

void do_rehash_akills(void) 
{
    aConfItem  *kill_list_ptr;
    aConfItem  *last_list_ptr;
    aConfItem  *tmp_list_ptr;
   
    if (temporary_klines) 
    {
	kill_list_ptr = last_list_ptr = temporary_klines;
		
	while (kill_list_ptr) 
	{
	    if (kill_list_ptr->hold <= NOW || kill_list_ptr->hold==0xFFFFFFFF) 
	    {			/* kline has expired */		
		if (temporary_klines == kill_list_ptr) 
		    temporary_klines = last_list_ptr =
			tmp_list_ptr = kill_list_ptr->next;
		else 
		    tmp_list_ptr = last_list_ptr->next = kill_list_ptr->next;
				
		MyFree(kill_list_ptr->host);
		MyFree(kill_list_ptr->name);
		MyFree(kill_list_ptr->passwd);
		MyFree(kill_list_ptr);
		kill_list_ptr = tmp_list_ptr;
	    }
	    else 
	    {
		last_list_ptr = kill_list_ptr;
		kill_list_ptr = kill_list_ptr->next;
	    }                               
	}
    }
}

/* m_svsnoop - Remove all ops from a server
 *  Once again pretty much straight outt df
 *    - Raistlin
 * parv[0] = sender prefix
 * parv[1] = server
 * parv[2] = +/-
 */

int m_svsnoop(aClient *cptr, aClient *sptr, int parc, char *parv[]) 
{
    aConfItem *aconf;

    if (!(IsULine(sptr) && parc > 2)) 
	return 0;

    if (hunt_server(cptr, sptr, ":%s SVSNOOP %s :%s", 1, parc, parv)
	== HUNTED_ISME) {
	if (parv[2][0] == '+') for(aconf=conf;aconf;aconf=aconf->next) 
	{
	    if (aconf->status & CONF_OPERATOR || aconf->status & CONF_LOCOP) 
		aconf->status = CONF_ILLEGAL;
	} 
	else 
	    rehash(&me, &me, 2);
    }
    return 0;
}
