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
#include "userban.h"

extern int  rehashed;
extern int  forked;

struct sockaddr_in vserv;
char        specific_virtual_host;


/* internally defined functions  */

static int          lookup_confhost(aConnect *);
static int          attach_iline(aClient *, aAllow *, char *, int);

/* externally defined functions  */

extern aOper        *make_oper();
extern aConnect     *make_connect();
extern aAllow       *make_allow();
extern struct Conf_Me   *make_me();
extern aPort        *make_port();
extern aUserv       *make_userv();

/* externally defined routines */

#ifdef WINGATE_NOTICE
extern char ProxyMonURL[TOPICLEN+1];
extern char ProxyMonHost[HOSTLEN+1];
#endif

aConnect   *connects  = ((aConnect *) NULL);    /* connects, C/N pairs  */
aAllow     *allows    = ((aAllow *) NULL);  /* allows  - I lines    */
Conf_Me    *MeLine    = ((Conf_Me *) NULL); /* meline - only one    */
aOper      *opers     = ((aOper *) NULL);   /* opers - Olines   */
aPort      *ports     = ((aPort *) NULL);   /* ports - P/M lines    */
aUserv     *uservers  = ((aUserv *) NULL);  /* Uservs - Ulined  */

#ifdef LOCKFILE
extern void do_pending_klines(void);
#endif

/* free_ routines
 * free the requested conf structure
 * feb.04 -epi
 */

void
free_connect(aConnect *ptr)
{
    MyFree(ptr->host);
    MyFree(ptr->apasswd);
    MyFree(ptr->cpasswd);
    MyFree(ptr->source);
    MyFree(ptr->name);
    MyFree(ptr);
    return;
}

void
free_allow(aAllow *ptr)
{
    MyFree(ptr->ipmask);
    MyFree(ptr->passwd);
    MyFree(ptr->hostmask);
    MyFree(ptr);
    return;
}

void
free_oper(aOper *ptr)
{
    MyFree(ptr->hostmask);
    MyFree(ptr->passwd);
    MyFree(ptr->nick);
    MyFree(ptr);
    return;
}

void
free_port(aPort *ptr)
{
    MyFree(ptr->allow);
    MyFree(ptr->address);
    MyFree(ptr);
    return;
}


/* clear_conflinks()
 * remove associated confs from this client
 * and free the conf if it is scheduled to be deleted
 * Feb04 -epi
 */

void
clear_conflinks(aClient *cptr)
{
    CLink *clp;
    if(!(clp = cptr->confs))
        return;
    if(clp->aconn)
    {
        clp->aconn->class->links--;
        clp->aconn->acpt = NULL;
        if(clp->aconn->legal == -1)     /* scheduled for removal? */
        {
            aConnect *aconn = NULL, *aconnl;
            for(aconnl = connects; aconnl; aconnl = aconnl->next)
            {
                if(aconnl == clp->aconn)
                {
                    if(aconn)
                        aconn->next = aconnl->next;
                    else
                        connects = aconnl->next;
                    free_connect(aconnl);
                    break;
                }
                aconn = aconnl;
            }
        }
    }
    if(clp->allow)
    {
        clp->allow->class->links--;
        clp->allow->clients--;
        if((clp->allow->clients <= 0) && (clp->allow->legal == -1))
        {
            /* remove this allow now that its empty */
            aAllow *allow = NULL, *allowl;
            for(allowl = allows; allowl; allowl = allowl->next)
            {
                if((allowl == clp->allow))
                {
                    if(allow)
                        allow->next = allowl->next;
                    else
                        allows = allowl->next;
                    free_allow(allowl);
                    break;
                }
                allow = allowl;
            }
        }
    }
    if(clp->aoper)
    {
        clp->aoper->class->links--;
        clp->aoper->opers--;
        if((clp->aoper->legal == -1))      /* and.. scheduled for removal */
        {
            aOper *oper = NULL, *operl;
            for(operl = opers; operl; operl = operl->next)
            {
                if(operl == clp->aoper)
                {
                    if(oper)
                        oper->next = operl->next;
                    else
                        opers = operl->next;
                    free_oper(operl);
                    break;
                }
                oper = operl;
            }
        }
    }
    MyFree(clp);
    return;
}

/* find the appropriate conf and return it */

aConnect *
find_aConnect(char *name)
{
    aConnect *tmp;
    for(tmp = connects; tmp; tmp = tmp->next)
        if(!match(name, tmp->name))
            break;
    return tmp;
}

aPort *
find_port(int port)
{
    aPort *tmp;
    for(tmp = ports; tmp; tmp = tmp->next)
        if(tmp->port == port)
            break;
    return tmp;
}

aConnect *
find_aConnect_match(char *name, char *username, char *host)
{
    aConnect *aconn;
    char userhost[USERLEN + HOSTLEN + 3];

    (void) ircsprintf(userhost, "%s@%s", username, host);

    for(aconn = connects; aconn; aconn = aconn->next)
        if(!mycmp(name, aconn->name) && !match(userhost, aconn->host))
            break;
    return aconn;
}

aUserv *
find_aUserver(char *name)
{
    aUserv *tmp;
    for(tmp = uservers; tmp; tmp = tmp->next)
        if(!mycmp(name, tmp->name))
            break;
    return tmp;
}

aOper *
find_oper(char *name, char *username, char *sockhost, char *hostip)
{
    aOper *aoper;
    char userhost[USERLEN + HOSTLEN + 3];
    char userip[USERLEN + HOSTLEN + 3];

    /* sockhost OR hostip must match our host field */


    (void) ircsprintf(userhost, "%s@%s", username, sockhost);
    (void) ircsprintf(userip, "%s@%s", username, sockhost);

    for(aoper = opers; aoper; aoper = aoper->next)
        if(!(mycmp(name, aoper->nick) && (match(userhost, aoper->hostmask) ||
           match(userip, aoper->hostmask))))
                break;
    return aoper;
}

aOper *
find_oper_byname(char *name)
{
    aOper *aoper;
    for(aoper = opers; aoper; aoper = aoper->next)
        if(!mycmp(name, aoper->nick))
            break;
    return aoper;
}

/* find the first (best) I line to attach.
 * rewritten in feb04 for the overdue death of aConfItem
 * and all the shit that came with it.  -epi
 */
int attach_Iline(aClient *cptr, struct hostent *hp, char *sockhost)
{
    aAllow *allow;
    char   *hname;
    int     i, ulen, uhost_has_at;
    static char uhost[HOSTLEN + USERLEN + 3];
    static char uhost2[HOSTLEN + USERLEN + 3];
    static char fullname[HOSTLEN + 1];

    for (allow = allows; allow; allow = allow->next) 
    {
        if(allow->legal == -1)
            continue;

        if (allow->port && (allow->port != cptr->lstn->port))
            continue;

        if (!allow->ipmask || !allow->hostmask)
            return (attach_iline(cptr, allow, uhost, 0));

        if (hp)
            for (i = 0, hname = hp->h_name; hname; hname = hp->h_aliases[i++]) 
            {
                strncpy(fullname, hname, sizeof(fullname) - 1);
                add_local_domain(fullname, HOSTLEN - strlen(fullname));
                if (allow->flags & CONF_FLAGS_I_NAME_HAS_AT)
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
                if ((!match(allow->hostmask, uhost)) ||
                    (!match(allow->hostmask, uhost2)))
                    return (attach_iline(cptr, allow, uhost, uhost_has_at));
            }
    
        if (allow->flags & CONF_FLAGS_I_HOST_HAS_AT)
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

        if (match(allow->ipmask, uhost) == 0)
            return (attach_iline(cptr, allow, uhost, uhost_has_at));
    }
    
    return -1;          /* no match */
}

/*
 * rewrote to remove the "ONE" lamity *BLEH* I agree with comstud on
 * this one. - Dianora
 */
static int attach_iline(aClient *cptr, aAllow *allow, char *uhost, int doid)
{
    CLink       *clp;
    
    if (doid)
        cptr->flags |= FLAGS_DOID;
    get_sockhost(cptr, uhost);
    
    /* only check it if its non zero  */

    if((clp = cptr->confs))
    {
        if(clp->allow == allow)
            return 1;       /* already linked */
    }
    else
        clp = make_clink(); 
    clp->allow = allow;
    allow->clients++;
    allow->class->links++;
    cptr->confs = clp;

    return 0;
}

/* rehasing routines
 * clear_* removes currently unused entries and
 * sets used ones for removal.
 */

void
clear_allows()
{
    aAllow *allow, *ptr;
    int keep = 0;

    allow = allows;
    allows = NULL;
    while(allow)
    {
        if(allow->clients > 0)
        {
            allow->legal = -1;
            if(!keep)
            {
                ptr = allow->next;
                allows = allow;
                allows->next = NULL;    /* last in this list */
                keep++;
                allow = ptr;
                continue;
            }
            ptr = allow->next;
            allow->next = allows;
            allows = allow;
            allow = ptr;
        }
        else
        {
            ptr = allow->next;
            free_allow(allow);
            allow = ptr;
        }
    }
    return;
}

void
clear_connects()
{
    aConnect *aconn, *ptr;
    int keep = 0;

    aconn = connects;
    connects = NULL;
    while(aconn)
        if(aconn->acpt)
        {
            /* in use */
            aconn->legal = -1;
            if(!keep)
            {
                ptr = aconn->next;
                connects = aconn;
                connects->next = NULL;
                keep++;
                aconn = ptr;
                continue;
            }
            ptr = aconn->next;
            aconn->next = connects;
            connects = aconn;
            aconn = ptr;
        }
        else
        {
            ptr = aconn->next;
            free_connect(aconn);
            aconn = ptr;
        }
    return;
}

void
clear_opers()
{
    aOper *aoper, *ptr;
    int keep = 0;

    aoper = opers;
    opers = NULL;
    while(aoper)
        if((aoper->opers > 0))
        {
            aoper->legal = -1;
            if(!keep)
            {
                ptr = aoper->next;
                opers = aoper;
                opers->next = NULL;     /* last in the list */
                keep++;
                aoper = ptr;
                continue;
            }
            ptr = aoper->next;
            aoper->next = opers;
            opers = aoper;
            aoper = ptr;
        }
        else
        {
            ptr = aoper->next;
            free_oper(aoper);
            aoper = ptr;
        }
    return;
}

/* confadd_ functions
 * add a config item
 * Feb.15/04 -epi
 */
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
    OFLAG_UMODEF,  'F',
    0, 0 };


void
confadd_oper(char *name, char *host, char *passwd, char *flags, char *class)
{
    aOper *x;
    int *i, flag, new;
    char *m = "*";

    if((x = find_oper_byname(name)))
    {
        MyFree(x->hostmask);
        MyFree(x->passwd);
        x->flags = 0;
        new = 0;
    }
    else
    {
        x = make_oper();
        DupString(x->nick, name);
        new = 1;
    }
    x->legal = 1;
    DupString(x->hostmask, host);
    DupString(x->passwd, passwd);
    for (m=(*flags) ? flags : m; *m; m++)
    {
        for (i=oper_access; (flag = *i); i+=2)
            if (*m==(char)(*(i+1)))
            {
                x->flags |= flag;
                break;
            }
    }
    if(class)
        x->class = find_class(atoi(class));
    else
        x->class = find_class(0);
    if (!strchr(x->hostmask, '@') && *x->hostmask != '/')
    {
        char       *newhost;
        int         len = 3;
        len += strlen(x->hostmask);
        newhost = (char *) MyMalloc(len);
        (void) ircsprintf(newhost, "*@%s", x->hostmask);
        MyFree(x->hostmask);
        x->hostmask = newhost;
    }
    if(new)
    {
        x->next = opers;
        opers = x;
    }
    return;
}

static int server_info[] =
{
    CONN_ZIP, 'Z',
    CONN_DKEY, 'E',
    CONN_HUB, 'H',
    0, 0
};

void
confadd_connect(char *name, char *host, char *apasswd, char *cpasswd,
                int port, char *flags, char *source, char *class)
{
    aConnect *x;
    int *i, flag, new = 0;
    char *m = "*";

    if(!(x = find_aConnect(name)))
    {
        x = make_connect();
        DupString(x->name, name);
        x->port = 0;
        new = 1;
    }
    x->legal = 1;
    if(host)
    {
        MyFree(x->host);
        DupString(x->host, host);
        if (!strchr(x->host, '@') && *x->host != '/')
        {
            char       *newhost;
            int         len = 3;
            len += strlen(x->host);
            newhost = (char *) MyMalloc(len);
            (void) ircsprintf(newhost, "*@%s", x->host);
            MyFree(x->host);
            x->host = newhost;
        }
        (void) lookup_confhost(x);
    }
    if(class)
        x->class = find_class(atoi(class));
    else
        x->class = find_class(0);
    if(port)
        x->port = port;
    if(apasswd)
    {
        MyFree(x->apasswd);
        DupString(x->apasswd, apasswd);
    }
    if(cpasswd)
    {
        MyFree(x->cpasswd);
        DupString(x->cpasswd, cpasswd);
    }
    if(flags)
    {
        x->flags = 0;
        for (m=(*flags) ? flags : m; *m; m++)
        {
            for (i=server_info; (flag = *i); i+=2)
            if (*m==(char)(*(i+1)))
            {
                x->flags |= flag;
                break;
            }
        }
    }
    if(source)
    {
        MyFree(x->source);
        DupString(x->source, source);
    }
    if(new)
    {
        x->next = connects;
        connects = x;
    }
    return;
}

void
confadd_allow(char *ipmask, char *passwd, char *hostmask, int port, char *class)
{
    aAllow *x;
    /* Currently, Allows are the only config types without
     * easy identifiers - so we dont worry about duplicate types.
     * this will change once a new config parser is written
     * -epi
     */

    x = make_allow();
    if(ipmask)
        DupString(x->ipmask, ipmask);
    if(passwd)
        DupString(x->passwd, passwd);
    if(hostmask)
        DupString(x->hostmask, hostmask);
    if(port)
        x->port = port;
    else
        x->port = 0;
    if(class)
        x->class = find_class(atoi(class));
    else
        x->class = find_class(0);
    if(strchr(x->ipmask, '@'))
        x->flags |= CONF_FLAGS_I_HOST_HAS_AT;
    if(strchr(x->hostmask, '@'))
        x->flags |= CONF_FLAGS_I_NAME_HAS_AT;
#if (RIDICULOUS_PARANOIA_LEVEL>=1)
    if(myncmp(x->passwd, "oper", 4) == 0)
    {
        if((x->passwd[4] == '.') || (x->passwd[4] == '\0'))
        {
            char *tmpd = x->passwd;
            char *tmp = x->passwd + 4;

            x->flags |= CONF_FLAGS_I_OPERPORT;
            if(*tmp)
                tmp++;
            DupString(x->passwd, tmp);
            MyFree(tmpd);
        }
    }
#endif
    /* would help if we added it to our list, eh */
    x->next = allows;
    allows = x;
    return;
}

void
confadd_port(int port, char *allow, char *address)
{
    aPort *x;
    int    new;

    if((x = find_port(port)))
    {
        MyFree(x->allow);
        MyFree(x->address);
        x->legal = 1;
        new = 0;
    }
    else
    {
        x = make_port();
        x->port = port;
        new = 1;
    }
    DupString(x->allow, allow);
    DupString(x->address, address);
    if(new)
    {
        x->next = ports;
        ports = x;
    }
    return;
}

void
confadd_me(char *servername, char *info, char *dpass, char *rpass, 
            char *aline1, char *aline2, char *aline3)
{
    if(!MeLine)
        MeLine = make_me();
    if(me.name[0] == '\0' && servername)
    {
        DupString(MeLine->servername, servername);
        strncpyzt(me.name, servername, sizeof(me.name));
    }
    if(info)
    {
        MyFree(MeLine->info);
        DupString(MeLine->info, info);
        strncpyzt(me.info, MeLine->info, sizeof(me.info));
    }
    if(aline1)
    {
        MyFree(MeLine->aline1);
        DupString(MeLine->aline1, aline1);
    }
    if(aline2)
    {
        MyFree(MeLine->aline2);
        DupString(MeLine->aline2, aline2);
    }
    if(aline3)
    {
        MyFree(MeLine->aline3);
        DupString(MeLine->aline3, aline3);
    }
    if(dpass)
    {
        MyFree(MeLine->diepass);
        DupString(MeLine->diepass, dpass);
    }
    if(rpass)
    {
        MyFree(MeLine->restartpass);
        DupString(MeLine->restartpass, rpass);
    }
    return;
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
    aClass     *cltmp;
    aClient    *acptr;
    int         i,  ret = 0, fd;

    if (sig == SIGHUP) 
    {
        sendto_ops("Got signal SIGHUP, reloading ircd conf. file");
        remove_userbans_match_flags(UBAN_NETWORK, 0);
        remove_userbans_match_flags(UBAN_LOCAL|UBAN_TEMPORARY, 0);
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

    clear_allows();
    clear_connects();
    clear_opers();
    close_listeners();

    /*
     * We don't delete the class table, rather mark all entries for
     * deletion. The table is cleaned up by check_class. - avalon
     */

    for (cltmp = NextClass(FirstClass()); cltmp; cltmp = NextClass(cltmp))
    MaxLinks(cltmp) = -1;

    if (sig != SIGINT)
    flush_cache();      /* Flush DNS cache */

    /* remove perm klines */
    remove_userbans_match_flags(UBAN_LOCAL, UBAN_TEMPORARY);

    /* our close_listeners() above seems to thrash our fd - reset it
     * kludgy.. really kludgy, but works -epi
     */
    close(fd);
    if ((fd = openconf(configfile)) == -1)
    {
        sendto_ops("Can't open %s file aborting rehash!", configfile);
        return -1;
    }


    (void) initconf(0, fd, sptr);

#ifdef KLINEFILE
    if ((fd = openconf(klinefile)) == -1)
    sendto_ops("Can't open %s file klines could be missing!", klinefile);
    else
    (void) initconf(0, fd, sptr);
#endif

    open_listeners();

    rehashed = 1;

    for (i = 0; i <= highest_fd; i++)
    {

        /* our Y: lines could have changed, rendering our client ping
         * cache invalid. Reset it here. - lucas */

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

/*
 * initconf() 
 *    Read configuration file. 
 * 
 * - file descriptor pointing to config file to use returns -1, 
 * if file cannot be opened, 0 if file opened
 * almost completely rewritten when killing aConfItem, feb04 -epi 
 */

#define MAXCONFLINKS 150

int
initconf(int opt, int fd, aClient *rehasher)
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
    int         i;
    char        line[512], c[80];

    /* temp variables just til we complete the rest of the 
     * switch to separate conf structures.  if this is still
     * here in 2006, find me and beat me up.  -epi
     * there shouldnt be more than 5 fields per line
     */

    int     t_status;
    char    *t_host;
    char    *t_passwd;
    char    *t_name;
    char    *t_flags;
    char    *t_class;


    (void) dgets(-1, NULL, 0);  /* make sure buffer is at empty pos  */

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
            if(!forked)
                printf("\nBad config line: \"%s\" - Ignored\n", line);
            continue;
        }

        tmp = getfield(line);
        if (!tmp)
            continue;
        switch (*tmp) 
        {
            case 'A':       
            case 'a':       /* Administrative info */
                t_status = CONF_ADMIN;
                break;

            case 'C':       /* Server I should try to connect */
            case 'c':       
                t_status = CONF_CONNECT_SERVER;
                break;

            case 'G':       /* restricted gcos */
            case 'g':
                t_status = CONF_GCOS;
                break;

            case 'H':       /* Hub server line */
            case 'h':
                t_status = CONF_HUB;
                break;

            case 'i':       /* to connect me */
            case 'I':       
                t_status = CONF_CLIENT;
                break;
            case 'K':       /* the infamous klines */
            case 'k':
                t_status = CONF_KILL;
                break;
        
            /*
             * Me. Host field is name used for this host 
             * and port number is the number of the port 
             */
            case 'M':
            case 'm':
                t_status = CONF_ME;
                break;
        
            case 'N':       
            case 'n':

            /* Server where I should NOT try to       
             * connect in case of lp failures 
             * but which tries to connect ME  
             */
                t_status = CONF_NOCONNECT_SERVER;
                break;

            case 'O':       /* Operator line */
            case 'o':       
                t_status = CONF_OPERATOR;
                break;

            case 'P':       /* listen port line */
            case 'p':
                t_status = CONF_LISTEN_PORT;
                break;

            case 'Q':       /* restricted nicknames */
            case 'q':
                t_status = CONF_QUARANTINE;
                break;
 
            case 'T':
            case 't':
                t_status = CONF_MONINFO;
                break;

            case 'U':       /* Ultimate Servers (aka God) */
            case 'u':
                t_status = CONF_ULINE;
                break;

            case 'X':       /* die/restart pass line */
            case 'x':
                t_status = CONF_DRPASS;
                break;
        
            case 'Y':       /* Class line */
            case 'y':
                t_status = CONF_CLASS;
                break;

            default:
                t_status = CONF_ILLEGAL;
                Debug((DEBUG_ERROR, "Error in config file: %s", line));
                if(!forked)
                    printf("Bad config line: \"%s\" - Ignored\n", line);
                break;
        }

        if(t_status & CONF_ILLEGAL) /* skip this line */
            continue;

        t_host = getfield(NULL);
        t_passwd = getfield(NULL);
        t_name = getfield(NULL);
        t_flags = getfield(NULL);
        t_class = getfield(NULL);

        /* from this point, every configuration line
         * is taken care of within its own if statement.
         * Everything should be contained. -epi
         */

        if(t_status & CONF_ADMIN)
        {
            confadd_me(0,0,0,0, t_host, t_passwd, t_name);
            continue;
        }
        if (t_status & CONF_OPS) 
        {
            confadd_oper(t_name, t_host, t_passwd, t_flags, t_class);
            continue;
        }
        if(t_status & CONF_NOCONNECT_SERVER)
        {
            confadd_connect(t_name, t_host, t_passwd, 0, 0, t_flags, 0,
                            t_class);
            continue;
        }
        if (t_status & CONF_CONNECT_SERVER)
        {
            confadd_connect(t_name, t_host, 0, t_passwd, atoi(t_flags), 0,
                            t_class, 0);
            continue;
        }
        if (t_status & CONF_CLASS) 
        {
            add_class(atoi(t_host), atoi(t_passwd), atoi(t_name), 
                            atoi(t_flags), atoi(t_class));
            continue;
        }

        if (t_status & CONF_CLIENT)
        {
            confadd_allow(t_host, t_passwd, t_name, atoi(t_flags), t_class);
            continue;
        }
        if(t_status & CONF_LISTEN_PORT)
        {
            confadd_port(atoi(t_flags), t_host, t_passwd);
            continue;
        }

        /*
         * Own port and name cannot be changed after the startup.  (or
         * could be allowed, but only if all links are closed  first). 
         * Configuration info does not override the name and port  if
         * previously defined. Note, that "info"-field can be changed
         * by "/rehash". Can't change vhost mode/address either
         */
    
        if (t_status == CONF_ME) 
        {
            confadd_me(t_host, t_name, 0, 0, 0, 0, 0);
            continue;
        }

#ifdef WINGATE_NOTICE
        if (t_status == CONF_MONINFO)
        {
            if(!t_host || t_host[0] == '\0')
                strncpyzt(ProxyMonHost, MONITOR_HOST, sizeof(ProxyMonHost));
            else
                strncpyzt(ProxyMonHost, t_host, sizeof(ProxyMonHost));
        
            strcpy(ProxyMonURL, "http://");

            if(!t_passwd || t_passwd[0] == '\0')
                strncpyzt((ProxyMonURL + 7), DEFAULT_PROXY_INFO_URL,
                          sizeof(ProxyMonURL) - 7);
            else
                strncpyzt((ProxyMonURL + 7), t_passwd, sizeof(ProxyMonURL) - 7);
        
            continue;
        } 
#endif

        if (t_status & CONF_QUARANTINE)
        {
            struct simBan *ban;
            unsigned int flags;
            char *sb_m, *sb_r;

            if(BadPtr(t_name))
                continue;

            flags = SBAN_LOCAL;
            if(t_name[0] == '#')
            {
                flags |= SBAN_CHAN;
                sb_r = BadPtr(t_passwd) ? "Reserved Channel" : t_passwd;
            }
            else
            {
                flags |= SBAN_NICK;
                sb_r = BadPtr(t_passwd) ? "Reserved Nickname" : t_passwd;
            }

            sb_m = t_name;

            ban = make_simpleban(flags, sb_m);
            if(!ban)
                continue;

            ban->reason = (char *) MyMalloc(strlen(sb_r) + 1);
            strcpy(ban->reason, sb_r);
            ban->timeset = NOW;

            add_simban(ban);
            continue;
        }

        if (t_status & CONF_GCOS)
        {
            struct simBan *ban;
            unsigned int flags;
            char *sb_m, *sb_r;

            if(BadPtr(t_name))
                continue;

            flags = SBAN_LOCAL|SBAN_GCOS;
            sb_r = BadPtr(t_passwd) ? "Bad GCOS" : t_passwd;

            sb_m = t_name;

            ban = make_simpleban(flags, sb_m);
            if(!ban)
                continue;

            ban->reason = (char *) MyMalloc(strlen(sb_r) + 1);
            strcpy(ban->reason, sb_r);
            ban->timeset = NOW;

            add_simban(ban);
                continue;
        }

        if (t_status & CONF_KILL)
        {
            struct userBan *ban;
            char *ub_u, *ub_r;
            int ii;
            char fbuf[512];
            aClient *ub_acptr;

            if(BadPtr(t_host))
                continue;

            ub_u = BadPtr(t_name) ? "*" : t_name;
            ub_r = BadPtr(t_passwd) ? "<No Reason>" : t_passwd;

            ban = make_hostbased_ban(ub_u, t_host);
            if(!ban)
                continue;

            ban->flags |= UBAN_LOCAL;
            ban->reason = (char *) MyMalloc(strlen(ub_r) + 1);
            strcpy(ban->reason, ub_r);
            ban->timeset = NOW;
        
            add_hostbased_userban(ban);

            /* Check local users against it */
            for (ii = 0; ii <= highest_fd; ii++)
            {
                if (!(ub_acptr = local[i]) || IsMe(ub_acptr) || 
                      IsLog(ub_acptr) || ub_acptr == rehasher)
                    continue;
        
                if (IsPerson(ub_acptr) && user_match_ban(ub_acptr, ban))
                {
                    sendto_ops(LOCAL_BAN_NAME " active for %s",
                               get_client_name(ub_acptr, FALSE));
                    ircsprintf(fbuf, LOCAL_BANNED_NAME ": %s", ub_r);
                    exit_client(ub_acptr, ub_acptr, &me, fbuf);
                    ii--;
                }
            }
            continue;
        }
        if (t_status & CONF_ULINE)
        {
            aUserv *x;
            if((x = find_aUserver(t_host)))
                continue;
            x = make_userv();
            DupString(x->name, t_host);
            x->next = uservers;
            uservers = x;
            continue;
        }
        if(t_status & CONF_DRPASS)
        {
            confadd_me(0,0, t_host, t_passwd, 0, 0, 0);
            continue;
        }
        /* oh shit! */
        if(!forked)
            printf("Error parsing config file!\n");
        abort();
    
    }
    (void) dgets(-1, NULL, 0);  /* make sure buffer is at empty pos */
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
 * rewritten to kill aConfItem, Feb/04 - epi
 */
static int lookup_confhost(aConnect *aconn)
{
    char   *s;
    struct hostent *hp;
    Link        ln;
    if (BadPtr(aconn->host) || BadPtr(aconn->name)) 
    {
    if (aconn->ipnum.s_addr == -1)
        memset((char *) &aconn->ipnum, '\0', sizeof(struct in_addr));

    Debug((DEBUG_ERROR, "Host/server name error: (%s) (%s)",
           aconn->host, aconn->name));
    return -1;
    }
    if ((s = strchr(aconn->host, '@')))
    s++;
    else
    s = aconn->host;
    /*
     * Do name lookup now on hostnames given and store the ip
     * numbers in conf structure.
     */
    if (!isalpha(*s) && !isdigit(*s)) 
    {
    if (aconn->ipnum.s_addr == -1)
        memset((char *) &aconn->ipnum, '\0', sizeof(struct in_addr));

    Debug((DEBUG_ERROR, "Host/server name error: (%s) (%s)",
           aconn->host, aconn->name));
    return -1;
    }
    /*
     * Prepare structure in case we have to wait for a reply which
     * we get later and store away.
     */
    ln.value.aconn = aconn;
    ln.flags = ASYNC_CONF;
    
    if (isdigit(*s))
    aconn->ipnum.s_addr = inet_addr(s);
    else if ((hp = gethost_byname(s, &ln)))
    memcpy((char *) &(aconn->ipnum), hp->h_addr,
           sizeof(struct in_addr));

    if (aconn->ipnum.s_addr == -1)
    memset((char *) &aconn->ipnum, '\0', sizeof(struct in_addr));
    {
    Debug((DEBUG_ERROR, "Host/server name error: (%s) (%s)",
           aconn->host, aconn->name));
    return -1;
    }
    /* NOTREACHED */
    return 0;
}
