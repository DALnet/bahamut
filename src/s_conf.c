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
#include <signal.h>
#include "h.h"
#include "userban.h"

/* This entire file has basically been rewritten from scratch with the
 * exception of lookup_confhost and attach_Iline/attach_iline fucntions
 * Feb04 -epi
 */

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

/* externally defined routines */

#ifdef WINGATE_NOTICE
extern char ProxyMonURL[TOPICLEN+1];
extern char ProxyMonHost[HOSTLEN+1];
#endif

#define MAXUSERVS 24

aConnect   *connects  = ((aConnect *) NULL);    /* connects, C/N pairs  */
aAllow     *allows    = ((aAllow *) NULL);  /* allows  - I lines    */
Conf_Me    *MeLine    = ((Conf_Me *) NULL); /* meline - only one    */
aOper      *opers     = ((aOper *) NULL);   /* opers - Olines   */
aPort      *ports     = ((aPort *) NULL);   /* ports - P/M lines    */
aClass     *classes;
char       *uservers[MAXUSERVS];

#ifdef LOCKFILE
extern void do_pending_klines(void);
#endif

/* initclass()
 * initialize the default class
 */

void initclass()
{
    classes = (aClass *) make_class();

    DupString(classes->name, "default");
    classes->connfreq = CONNECTFREQUENCY;
    classes->pingfreq = PINGFREQUENCY;
    classes->maxlinks = MAXIMUM_LINKS;
    classes->maxsendq = MAXSENDQLENGTH;
    classes->links = 0;
    classes->next = NULL;
}

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
    if(IsServer(cptr))
    {
        aConnect *x;
        if((x = cptr->serv->aconn))
        {
            x->class->links--;
            x->acpt = NULL;
            if(x->legal == -1)     /* scheduled for removal? */
            {
                aConnect *aconn = NULL, *aconnl;
                for(aconnl = connects; aconnl; aconnl = aconnl->next)
                {
                    if(aconnl == x)
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
            cptr->serv->aconn = NULL;
        }
    }
    else
    {
        aAllow *x;
        aOper *y;
        if((x = cptr->user->allow))
        {
            x->class->links--;
            x->clients--;
            if((x->clients <= 0) && (x->legal == -1))
            {
                /* remove this allow now that its empty */
                aAllow *allow = NULL, *allowl;
                for(allowl = allows; allowl; allowl = allowl->next)
                {
                    if((allowl == x))
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
            cptr->user->allow = NULL;
        }
        if((y = cptr->user->oper))
        {
            y->class->links--;
            y->opers--;
            if((y->legal == -1) && (y->opers <= 0))
            {
                aOper *oper = NULL, *operl;
                for(operl = opers; operl; operl = operl->next)
                {
                    if(operl == y)
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
            cptr->user->oper = NULL;
        }
    }
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

int
find_aUserver(char *name)
{
    int i;
    for(i = 0; uservers[i]; i++)
    {
        if(!mycmp(name, uservers[i]))
            return 1;
    }
    return 0;
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

aClass *
find_class(char *name)
{
    aClass *tmp;
    for(tmp = classes; tmp; tmp = tmp->next)
        if(!mycmp(name, tmp->name))
            break;
    return tmp;
}

/* set_effective_class
 * sets the class for cptr properly
 */

void
set_effective_class(aClient *cptr)
{
    if(IsServer(cptr))
    {
        if(cptr->serv->aconn->class)
            cptr->class = cptr->serv->aconn->class;
        else
            cptr->class = find_class("default");
    }
    else
    {
        if(cptr->user->oper)
            cptr->class = cptr->user->oper->class;
        else if(cptr->user->allow)
            cptr->class = cptr->user->allow->class;
        else
            cptr->class = find_class("default");
    }
    return;
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
    
    if (doid)
        cptr->flags |= FLAGS_DOID;
    get_sockhost(cptr, uhost);
    
    /* only check it if its non zero  */

    cptr->user->allow = allow;
    allow->clients++;
    allow->class->links++;

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

/* this used to be check_class - revamped and moved here 
 * to rip out all those shitty obfuscation macros that whoever
 * whote it was so fond of.
 * -epi
 */

void 
clear_classes()
{
    aClass *cltmp, *cltmp2;

    for (cltmp2 = cltmp = classes; cltmp; cltmp = cltmp2->next)
        if (cltmp->maxlinks < 0)
        {
            cltmp2->next = cltmp->next;;
            if (cltmp->links <= 0)
                free_class(cltmp);
        }
        else
            cltmp2 = cltmp;
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
        x->class = find_class(class);
    else
        x->class = find_class("default");
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
        x->class = find_class(class);
    else
        x->class = find_class("default");
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
     * -epi
     */

    x = make_allow();
    if(ipmask)
        DupString(x->ipmask, ipmask);
    else
        DupString(x->ipmask, "*@*");
    if(passwd)
        DupString(x->passwd, passwd);
    else
        DupString(x->passwd, "");
    if(hostmask)
        DupString(x->hostmask, hostmask);
    else
        DupString(x->hostmask, "*@*");
    if(port)
        x->port = port;
    else
        x->port = 0;
    if(class)
        x->class = find_class(class);
    else
        x->class = find_class("default");
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
    if(allow)
        DupString(x->allow, allow);
    else
        DupString(x->allow, "");
    if(address)
        DupString(x->address, address);
    else
        DupString(x->address, "");
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

void
confadd_class(char *name, int ping, int connfreq, int maxlinks, long sendq)
{
    aClass *x;
    int new = 0;

    if(!(x = find_class(name)))
    {
        x = make_class();
        DupString(x->name, name);
        new = 1;
    }
    x->pingfreq = ping;
    x->connfreq = connfreq;
    x->maxlinks = maxlinks;
    x->maxsendq = (sendq > 0) ? sendq : MAXSENDQLENGTH;
    if(new)
    {
        x->next = classes;
        classes = x;
    }
    return;
}

void
confadd_kill(char *user, char *host, char *reason)
{
    struct userBan *ban;
    int i;
    char *ub_u, *ub_r;
    char fbuf[512];
    aClient *ub_acptr;

    ub_u = BadPtr(user) ? "*" : user;
    ub_r = BadPtr(reason) ? "<No Reason>" : reason;

    ban = make_hostbased_ban(ub_u, host);
    if(!ban)
        return;

    ban->flags |= UBAN_LOCAL;
    DupString(ban->reason, ub_r);
    ban->timeset = NOW;

    add_hostbased_userban(ban);

    /* Check local users against it */
    for (i = 0; i <= highest_fd; i++)
    {
        if (!(ub_acptr = local[i]) || IsMe(ub_acptr) ||
              IsLog(ub_acptr))
            continue;

        if (IsPerson(ub_acptr) && user_match_ban(ub_acptr, ban))
        {
            sendto_ops(LOCAL_BAN_NAME " active for %s",
                       get_client_name(ub_acptr, FALSE));
            ircsprintf(fbuf, LOCAL_BANNED_NAME ": %s", ub_r);
            exit_client(ub_acptr, ub_acptr, &me, fbuf);
            i--;
        }
    }
    return;
}

void
confadd_uline(char *host)
{
    int i;
    if(!find_aUserver(host))
    {
        i = 0;
        while(uservers[i])
            i++;
        DupString(uservers[i], host);
        uservers[i+1] = NULL;
    }
    return;
}

void
confadd_restrict(int type, char *mask, char *reason)
{
    struct simBan *ban;

    ban = make_simpleban(type, mask);
    if(!ban)
        return;
    
    if(!reason)
    {
        if(type & SBAN_CHAN)
            reason = "Reserved Channel";
        else if(type & SBAN_NICK)
            reason = "Reserved Nick";
        else if(type & SBAN_GCOS)
            reason = "Bad GCOS";
        else
            return;
    }
    DupString(ban->reason, reason);
    ban->timeset = NOW;

    add_simban(ban);
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
    int         i,  ret = 0;

    if (sig == SIGHUP) 
    {
        sendto_ops("Got signal SIGHUP, reloading ircd conf. file");
        remove_userbans_match_flags(UBAN_NETWORK, 0);
        remove_userbans_match_flags(UBAN_LOCAL|UBAN_TEMPORARY, 0);
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

    for (cltmp = classes->next; cltmp; cltmp = cltmp->next)
        cltmp->maxlinks = -1;

    clear_classes();
    initclass();

    if (sig != SIGINT)
    flush_cache();      /* Flush DNS cache */

    /* remove perm klines */
    remove_userbans_match_flags(UBAN_LOCAL, UBAN_TEMPORARY);

    initconf(configfile);

    open_listeners();

    rehashed = 1;

    return ret;
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
