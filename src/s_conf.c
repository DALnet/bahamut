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
#include "confparse.h"

/* This entire file has basically been rewritten from scratch with the
 * exception of lookup_confhost and attach_Iline/attach_iline fucntions
 * Feb04 -epi
 */

extern int  rehashed;
extern int  forked;
extern tConf tconftab[];
extern sConf sconftab[];

/* internally defined functions  */

static int          lookup_confhost(aConnect *);
static int          attach_iline(aClient *, aAllow *, char *, int);

/* externally defined functions  */

extern aClass       *make_class();
extern aOper        *make_oper();
extern aConnect     *make_connect();
extern aAllow       *make_allow();
extern struct Conf_Me   *make_me();
extern aPort        *make_port();
extern void          read_shortmotd(char *);

/* these are our global lists of ACTIVE conf entries */

#define MAXUSERVS 24

aConnect   *connects  = NULL;       /* connects, C/N pairs  */
aAllow     *allows    = NULL;       /* allows  - I lines    */
Conf_Me    *MeLine    = NULL;       /* meline - only one    */
aOper      *opers     = NULL;       /* opers - Olines       */
aPort      *ports     = NULL;       /* ports - P/M lines    */
aClass     *classes   = NULL;;      /* classes - Ylines     */
char       *uservers[MAXUSERVS];    /* uservers = Ulines    */
Conf_Modules *modules = NULL;

/* this set of lists is used for loading and rehashing the config file */

aConnect    *new_connects   = NULL;
aAllow      *new_allows     = NULL;
Conf_Me     *new_MeLine     = NULL;
aOper       *new_opers      = NULL;
aPort       *new_ports      = NULL;
aClass      *new_classes    = NULL;
char        *new_uservers[MAXUSERVS+1];    /* null terminated array */
Conf_Modules *new_modules       = NULL;

#ifdef LOCKFILE
extern void do_pending_klines(void);
#endif
extern void confparse_error(char *, int);

/* initclass()
 * initialize the default class
 */

void initclass()
{
    new_classes = make_class();

    DupString(new_classes->name, "default");
    new_classes->connfreq = CONNECTFREQUENCY;
    new_classes->pingfreq = PINGFREQUENCY;
    new_classes->maxlinks = MAXIMUM_LINKS;
    new_classes->maxsendq = MAXSENDQLENGTH;
    new_classes->links = 0;
}

/* init_globals
 * initialize our major globals to the defaults first
 */

void init_globals()
{
    strncpyzt(ProxyMonURL, DEFAULT_WGMON_URL, sizeof(ProxyMonURL));
    strncpyzt(ProxyMonHost, DEFAULT_WGMON_HOST, sizeof(ProxyMonHost));
    strncpyzt(Network_Name, DEFAULT_NETWORK, sizeof(Network_Name));
    strncpyzt(Services_Name, DEFAULT_SERVICES_NAME, sizeof(Services_Name));
    strncpyzt(Stats_Name, DEFAULT_STATS_NAME, sizeof(Stats_Name));
    snprintf(NS_Services_Name, sizeof(NS_Services_Name), "%s@%s", 
                NICKSERV, Services_Name);
    snprintf(CS_Services_Name, sizeof(CS_Services_Name), "%s@%s", 
                CHANSERV, Services_Name);
    snprintf(MS_Services_Name, sizeof(MS_Services_Name), "%s@%s", 
                MEMOSERV, Services_Name);
    snprintf(RS_Services_Name, sizeof(RS_Services_Name), "%s@%s", 
                ROOTSERV, Services_Name);
    snprintf(OS_Stats_Name, sizeof(OS_Stats_Name), "%s@%s", 
                OPERSERV, Stats_Name);
    snprintf(SS_Stats_Name, sizeof(SS_Stats_Name), "%s@%s", 
                STATSERV, Stats_Name);
    snprintf(HS_Stats_Name, sizeof(HS_Stats_Name), "%s@%s", 
                HELPSERV, Stats_Name);
    strncpyzt(NS_Register_URL, DEFAULT_NS_REGISTER_URL,
              sizeof(NS_Register_URL));
    strncpyzt(Network_Kline_Address, DEFAULT_NKLINE_ADDY,
                                            sizeof(Network_Kline_Address));
    strncpyzt(Local_Kline_Address, DEFAULT_LKLINE_ADDY,
                                            sizeof(Local_Kline_Address));
    strncpyzt(Staff_Address, DEFAULT_STAFF_ADDRESS, sizeof(Staff_Address));
    maxchannelsperuser = DEFAULT_MAXCHANNELSPERUSER;
    tsmaxdelta = DEFAULT_TSMAXDELTA;
    tswarndelta = DEFAULT_TSWARNDELTA;
    local_ip_limit = DEFAULT_LOCAL_IP_CLONES;
    local_ip24_limit = DEFAULT_LOCAL_IP24_CLONES;
    global_ip_limit = DEFAULT_GLOBAL_IP_CLONES;
    global_ip24_limit = DEFAULT_GLOBAL_IP24_CLONES;
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
    MyFree(ptr->class_name);
    MyFree(ptr);
    return;
}

void
free_allow(aAllow *ptr)
{
    MyFree(ptr->ipmask);
    MyFree(ptr->passwd);
    MyFree(ptr->hostmask);
    MyFree(ptr->class_name);
    MyFree(ptr);
    return;
}

void
free_oper(aOper *ptr)
{
    int i = 0;
    while(ptr->hosts[i])
    {
        MyFree(ptr->hosts[i]);
        i++;
    }
    MyFree(ptr->passwd);
    MyFree(ptr->nick);
    MyFree(ptr->class_name);
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

void
free_class(aClass *ptr)
{
    MyFree(ptr->name);
    MyFree(ptr);
    return;
}

void expire_class(aClass *cl)
{
    aClass *ccl, *pcl = NULL;
    if (cl->refs == 0 && cl->maxlinks == -1)
    {
        for (ccl = classes; ccl; ccl = ccl->next)
        {
            if (ccl == cl)
            {
                if (pcl)
                    pcl->next = ccl->next;
                else
                    classes = ccl->next;
                free_class(ccl);
                break;
            }
            pcl = ccl;
        }
    }
}

/* clear_conflinks()
 * remove associated confs from this client
 * and free the conf if it is scheduled to be deleted
 * Feb04 -epi
 */

void
clear_conflinks(aClient *cptr)
{
    if (cptr->class)
    {
        cptr->class->links--;
        cptr->class->refs--;
        expire_class(cptr->class);
    }
    if(IsServer(cptr))
    {
        aConnect *x;
        if((x = cptr->serv->aconn))
        {
            x->acpt = NULL;
            if (x->legal == -1)     /* scheduled for removal? */
            {
                aConnect *aconn = NULL;

                if (x == connects)
                    connects = x->next;
                else
                {
                    for (aconn = connects;
                         aconn != NULL && aconn->next != x;
                         aconn = aconn->next);
                    if (aconn != NULL)
                        aconn->next = x->next;
                    else
                        sendto_realops_lev(DEBUG_LEV, "Deleting scheduled "
                                           "connect, but it isn't in the "
                                           "list?? [%s]", x->name);
                }
                x->class->refs--;
                expire_class(x->class);
                free_connect(x);
            }
            cptr->serv->aconn = NULL;
        }
    }
    else if (cptr->user != NULL)
    {
        aAllow *x;
        aOper *y;
        if((x = cptr->user->allow))
        {
            x->clients--;
            if(x->clients <= 0 && x->legal == -1)
            {
                /* remove this allow now that its empty */
                aAllow *allow = NULL;
                if (allows == x)
                    allows = x->next;
                else
                {
                    for (allow = allows;
                         allow != NULL && allow->next != x;
                         allow = allow->next);
                    if (allow != NULL)
                        allow->next = x->next;
                    else
                        sendto_realops_lev(DEBUG_LEV, "Deleting scheduled "
                                           "allow, but it isn't in the list?? "
                                           "[%s / %s]", x->ipmask,x->hostmask);
                }
                x->class->refs--;
                expire_class(x->class);
                free_allow(x);
            }
            cptr->user->allow = NULL;
        }
        if((y = cptr->user->oper))
        {
            y->opers--;
            if(y->legal == -1 && y->opers <= 0)
            {
                aOper *oper = NULL;
                if (opers == y)
                    opers = y->next;
                else
                {
                    for (oper = opers;
                         oper != NULL && oper->next != y;
                         oper = oper->next);
                    if (oper != NULL)
                        oper->next = y->next;
                    else
                        sendto_realops_lev(DEBUG_LEV, "Deleting scheduled "
                                           "oper, but it isn't in the list?? "
                                           "[%s]", y->nick);
                }
                y->class->refs--;
                expire_class(y->class);
                free_oper(y);
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

static inline aPort *
find_port(int port, char *bind)
{
    aPort *tmp;
    for(tmp = ports; tmp; tmp = tmp->next)
        if (tmp->port == port)
        {
            if (tmp->address == bind)  /* both NULL */
                break;
            if (tmp->address && bind && !mycmp(tmp->address, bind))
                break;
        }
    return tmp;
}

aConnect *
find_aConnect_match(char *name, char *username, char *host)
{
    aConnect *aconn;
    char userhost[USERLEN + HOSTLEN + 3];

    ircsprintf(userhost, "%s@%s", username, host);

    for(aconn = connects; aconn; aconn = aconn->next)
    {
        if (aconn->legal == -1)
            continue;
        if(!mycmp(name, aconn->name) && !match(userhost, aconn->host))
            break;
    }
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
    int i;

    /* sockhost OR hostip must match our host field */


    ircsprintf(userhost, "%s@%s", username, sockhost);
    ircsprintf(userip, "%s@%s", username, hostip);

    for(aoper = opers; aoper; aoper = aoper->next)
    {
        if (aoper->legal == -1)
            continue;

        for(i = 0; aoper->hosts[i]; i++)
        {
            if(!mycmp(name, aoper->nick) && (!match(aoper->hosts[i], userhost) 
                    || !match(aoper->hosts[i], userip)))
                return aoper;
        }
    }
    return NULL;
}

static inline aOper *
find_oper_byname(char *name)
{
    aOper *aoper;
    for(aoper = opers; aoper; aoper = aoper->next)
        if(!mycmp(name, aoper->nick))
            break;
    return aoper;
}

static inline aClass *
find_class(char *name)
{
    aClass *tmp;
    if(!name)
        return find_class("default");
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
    if (cptr->class)
    {
        cptr->class->links--;
        cptr->class->refs--;
        expire_class(cptr->class);
    }
    if(IsServer(cptr))
    {
        if(cptr->serv->aconn->class)
            cptr->class = cptr->serv->aconn->class;
        else
            cptr->class = find_class("default");
    }
    else
    {
        if(cptr->user && cptr->user->oper)
            cptr->class = cptr->user->oper->class;
        else if(cptr->user && cptr->user->allow)
            cptr->class = cptr->user->allow->class;
        else
            cptr->class = find_class("default");
    }
    cptr->class->refs++;
    cptr->class->links++;
    return;
}
    

/* find the first (best) I line to attach.
 * rewritten in feb04 for the overdue death of aConfItem
 * and all the shit that came with it.  -epi
 * Rewritten again in Mar04 to optimize and get rid of deceptive logic.
 * Whoever wrote this originally must have been drunk...  -Quension
 */
int 
attach_Iline(aClient *cptr, struct hostent *hp, char *sockhost)
{
    aAllow *allow;

    static char useriphost[USERLEN + 1 + HOSTLEN + 1];
    static char usernamehost[USERLEN + 1 + HOSTLEN + 1];
    char   *iphost;
    char   *namehost = NULL;    /* squish compiler warning */
    int     len;

    /* user@host in both buffers, plus pointers to host only */
    len = ircsprintf(useriphost, "%s@", cptr->username);
    iphost = useriphost + len;
    strcpy(iphost, sockhost);
    if (hp)
    {
        memcpy(usernamehost, useriphost, USERLEN+2);
        namehost = usernamehost + len;
        len = sizeof(usernamehost) - len;
        strncpy(namehost, hp->h_name, len);
        add_local_domain(namehost, len - strlen(namehost));
    }

    for (allow = allows; allow; allow = allow->next) 
    {
        if(allow->legal == -1)
            continue;

        if (allow->port && (allow->port != cptr->lstn->port))
            continue;

        if (!allow->ipmask || !allow->hostmask)
            return (attach_iline(cptr, allow, iphost, 0));

        /* match hostmask against both resolved name and IP, prefer name */
        if (allow->flags & CONF_FLAGS_I_MATCH_NAME)
        {
            if (allow->flags & CONF_FLAGS_I_NAME_HAS_AT)
            {
                if (hp && !match(allow->hostmask, usernamehost))
                    return (attach_iline(cptr, allow, namehost, 1));
                if (!match(allow->hostmask, useriphost))
                    return (attach_iline(cptr, allow, hp?namehost:iphost, 1));
            }
            else
            {
                if (hp && !match(allow->hostmask, namehost))
                    return (attach_iline(cptr, allow, namehost, 0));
                if (!match(allow->hostmask, iphost))
                    return (attach_iline(cptr, allow, hp?namehost:iphost, 0));
            }
        }

        if (allow->flags & CONF_FLAGS_I_MATCH_HOST)
        {
            if (allow->flags & CONF_FLAGS_I_HOST_HAS_AT)
            {
                if (!match(allow->ipmask, useriphost))
                    return (attach_iline(cptr, allow, iphost, 1));
            }
            else
            {
                if (!match(allow->ipmask, iphost))
                    return (attach_iline(cptr, allow, iphost, 0));
            }
        }
    }
    return -1;          /* no match */
}

/*
 * rewrote to remove the "ONE" lamity *BLEH* I agree with comstud on
 * this one. - Dianora
 */
static int 
attach_iline(aClient *cptr, aAllow *allow, char *uhost, int doid)
{
    if(allow->class->links >= allow->class->maxlinks)
        return -3;

    if (doid)
        cptr->flags |= FLAGS_DOID;
    get_sockhost(cptr, uhost);
    
    cptr->user->allow = allow;
    allow->clients++;

    return 0;
}

/* confadd_ functions
 * add a config item
 * Feb.15/04 -epi
 */
static int oper_access[] =
{
    ~(OFLAG_ADMIN|OFLAG_SADMIN), '*',
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
    OFLAG_UMODEF,  'F',
    0, 0 };

int
confadd_oper(cVar *vars[], int lnum)
{
    cVar *tmp;
    aOper *x = make_oper();
    int *i, flag, c = 0, hc = 0;
    char *m = "*";

    for(tmp = vars[c]; tmp; tmp = vars[++c])
    {
        if(tmp->type && (tmp->type->flag & SCONFF_NAME))
        {
            if(x->nick)
            {
                confparse_error("Multiple name definitions", lnum);
                free_oper(x);
                return -1;
            }
            tmp->type = NULL;
            DupString(x->nick, tmp->value);
        }
        else if(tmp->type && (tmp->type->flag & SCONFF_HOST))
        {
            if((hc+1) > MAXHOSTS)
            {
                confparse_error("Excessive host definitions", lnum);
                free_oper(x);
                return -1;
            }
            tmp->type = NULL;
            if (!strchr(tmp->value, '@') && *tmp->value != '/')
            {
                char       *newhost;
                int         len = 3;
                len += strlen(tmp->value);
                newhost = (char *) MyMalloc(len);
                ircsprintf(newhost, "*@%s", tmp->value);
                x->hosts[hc] = newhost;
            }
            else
                DupString(x->hosts[hc], tmp->value);
            hc++;
        }
        else if(tmp->type && (tmp->type->flag & SCONFF_PASSWD))
        {
            if(x->passwd)
            {
                confparse_error("Multiple password definitions", lnum);
                free_oper(x);
                return -1;
            }
            tmp->type = NULL;
            DupString(x->passwd, tmp->value);
        }
        else if(tmp->type && (tmp->type->flag & SCONFF_ACCESS))
        {
            if(x->flags > 0)
            {
                confparse_error("Multiple access definitions", lnum);
                free_oper(x);
                return -1;
            }
            for (m=(*tmp->value) ? tmp->value : m; *m; m++)
            {
                for (i=oper_access; (flag = *i); i+=2)
                    if (*m==(char)(*(i+1)))
                    {
                        x->flags |= flag;
                        break;
                    }
            }
        }
        else if(tmp->type && (tmp->type->flag & SCONFF_CLASS))
        {
            if(x->class_name)
            {
                confparse_error("Multiple class definitions", lnum);
                free_oper(x);
                return -1;
            }
            tmp->type = NULL;
            DupString(x->class_name, tmp->value);
        }
    }
    if(!x->nick)
    {
        confparse_error("Lacking name in oper block", lnum);
        free_oper(x);
        return -1;
    }
    if(!x->hosts[0])
    {
        confparse_error("Lacking host in oper block", lnum);
        free_oper(x);
        return -1;
    }
    if(!x->passwd)
    {
        confparse_error("Lacking passwd in oper block", lnum);
        free_oper(x);
        return -1;
    }
    if(x->flags == 0)
    {
        confparse_error("Lacking access in oper block", lnum);
        free_oper(x);
        return -1;
    }
    x->next = new_opers;
    new_opers = x;
    return lnum;
}

static int server_info[] =
{
    CONN_ZIP, 'Z',
    CONN_DKEY, 'E',
    CONN_HUB, 'H',
    0, 0
};

int
confadd_connect(cVar *vars[], int lnum)
{
    cVar *tmp;
    aConnect *x = make_connect();
    int *i, flag, c = 0;
    char *m = "*";

    for(tmp = vars[c]; tmp; tmp = vars[++c])
    {
        if(tmp->type && (tmp->type->flag & SCONFF_NAME))
        {
            if(x->name)
            {
                confparse_error("Multiple name definitions", lnum);
                free_connect(x);
                return -1;
            }
            tmp->type = NULL;
            DupString(x->name, tmp->value);
        }
        else if(tmp->type && (tmp->type->flag & SCONFF_HOST))
        {
            if(x->host)
            {
                confparse_error("Multiple host definitions", lnum);
                free_connect(x);
                return -1;
            }
            tmp->type = NULL;
            if (!strchr(tmp->value, '@') && *tmp->value != '/')
            {
                char       *newhost;
                int         len = 3;
                len += strlen(tmp->value);
                newhost = (char *) MyMalloc(len);
                ircsprintf(newhost, "*@%s", tmp->value);
                x->host = newhost;
            }
            else
                DupString(x->host, tmp->value);
        }
        else if(tmp->type && (tmp->type->flag & SCONFF_APASSWD))
        {
            if(x->apasswd)
            {
                confparse_error("Multiple apasswd definitions", lnum);
                free_connect(x);
                return -1;
            }
            tmp->type = NULL;
            DupString(x->apasswd, tmp->value);
        }
        else if(tmp->type && (tmp->type->flag & SCONFF_CPASSWD))
        {
            if(x->cpasswd)
            {
                confparse_error("Multiple cpasswd definitions", lnum);
                free_connect(x);
                return -1;
            }
            tmp->type = NULL;
            DupString(x->cpasswd, tmp->value);
        }
        else if(tmp->type && (tmp->type->flag & SCONFF_FLAGS))
        {
            if(x->flags > 0)
            {
                confparse_error("Multiple flag definitions", lnum);
                free_connect(x);
                return -1;
            }
            tmp->type = NULL;
            x->flags = 0;
            for (m=(*tmp->value) ? tmp->value : m; *m; m++)
            {
                for (i=server_info; (flag = *i); i+=2)
                if (*m==(char)(*(i+1)))
                {
                    x->flags |= flag;
                    break;
                }
            }
        }
        else if(tmp->type && (tmp->type->flag & SCONFF_PORT))
        {
            if(x->port > 0)
            {
                confparse_error("Multiple port definitions", lnum);
                free_connect(x);
                return -1;
            }
            tmp->type = NULL;
            x->port = atoi(tmp->value);
        }
        else if(tmp->type && (tmp->type->flag & SCONFF_BIND))
        {
            if(x->source)
            {
                confparse_error("Multiple source definitions", lnum);
                free_connect(x);
                return -1;
            }
            tmp->type = NULL;
            DupString(x->source, tmp->value);
        }
        else if(tmp->type && (tmp->type->flag & SCONFF_CLASS))
        {
            if(x->class_name)
            {
                confparse_error("Multiple class definitions", lnum);
                free_connect(x);
                return -1;
            }
            tmp->type = NULL;
            DupString(x->class_name, tmp->value);
        }
    }
    if(!x->name)
    {
        confparse_error("Lacking name in connect block", lnum);
        free_connect(x);
        return -1;
    }
    if(!x->apasswd)
    {
        confparse_error("Lacking apasswd in connect block", lnum);
        free_connect(x);
        return -1;
    }
    if(!x->cpasswd)
    {
        confparse_error("Lacking cpasswd in connect block", lnum);
        free_connect(x);
        return -1;
    }
    if(!x->host)
    {
        confparse_error("Lacking host in connect block", lnum);
        free_connect(x);
        return -1;
    }
    x->next = new_connects;
    new_connects = x;
    return lnum;
}

int
confadd_options(cVar *vars[], int lnum)
{
    cVar *tmp;
    int c = 0;
    char ctmp[512];
    char *s;

    /* here, because none of the option peice are interdependent
     * all the items are added immediately.   Makes life easier
     * ...except the option flags, which are handled specially -Quension
     */

    for(tmp = vars[c]; tmp; tmp = vars[++c])
    {
        if(tmp->type && (tmp->type->flag & OPTF_NETNAME))
        {
            tmp->type = NULL;
            strncpyzt(Network_Name, tmp->value, sizeof(Network_Name));
        }
        else if(tmp->type && (tmp->type->flag & OPTF_SERVNAME))
        {
            tmp->type = NULL;
            strncpyzt(Services_Name, tmp->value, sizeof(Services_Name));
            sprintf(ctmp, "%s@%s", NICKSERV, Services_Name);
            strncpyzt(NS_Services_Name, ctmp, sizeof(NS_Services_Name));
            sprintf(ctmp, "%s@%s", CHANSERV, Services_Name);
            strncpyzt(CS_Services_Name, ctmp, sizeof(CS_Services_Name));
            sprintf(ctmp, "%s@%s", MEMOSERV, Services_Name);
            strncpyzt(MS_Services_Name, ctmp, sizeof(MS_Services_Name));
            sprintf(ctmp, "%s@%s", ROOTSERV, Services_Name);
            strncpyzt(RS_Services_Name, ctmp, sizeof(RS_Services_Name));
        }
        else if(tmp->type && (tmp->type->flag & OPTF_STATSNAME))
        {
            tmp->type = NULL;
            strncpyzt(Stats_Name, tmp->value, sizeof(Stats_Name));
            sprintf(ctmp, "%s@%s", OPERSERV, Stats_Name);
            strncpyzt(OS_Stats_Name, ctmp, sizeof(OS_Stats_Name));
            sprintf(ctmp, "%s@%s", STATSERV, Stats_Name);
            strncpyzt(SS_Stats_Name, ctmp, sizeof(SS_Stats_Name));
            sprintf(ctmp, "%s@%s", HELPSERV, Stats_Name);
            strncpyzt(HS_Stats_Name, ctmp, sizeof(HS_Stats_Name));
        }
        else if(tmp->type && (tmp->type->flag & OPTF_WGMONHOST))
        {
            tmp->type = NULL;
            new_confopts |= FLAGS_WGMONHOST;
            strncpyzt(ProxyMonHost, tmp->value, sizeof(ProxyMonHost));
        }
        else if(tmp->type && (tmp->type->flag & OPTF_WGMONURL))
        {
            tmp->type = NULL;
            new_confopts |= FLAGS_WGMONURL;
            strncpyzt(ProxyMonURL, tmp->value, sizeof(ProxyMonURL));
        }
        else if(tmp->type && (tmp->type->flag & OPTF_NSREGURL))
        {
            tmp->type = NULL;
            strncpyzt(NS_Register_URL, tmp->value, sizeof(NS_Register_URL));
        }
        else if(tmp->type && (tmp->type->flag & OPTF_MAXCHAN))
        {
            tmp->type = NULL;
            maxchannelsperuser = atoi(tmp->value);
        }
        else if(tmp->type && (tmp->type->flag & OPTF_SERVTYPE))
        {
            tmp->type = NULL;
            if(!mycmp("HUB", tmp->value))
            {
                new_confopts |= FLAGS_HUB;
                new_confopts &= ~FLAGS_SERVHUB;
            }
            else if(!mycmp("SERVICESHUB", tmp->value))
            {
                new_confopts |= FLAGS_SERVHUB;
                new_confopts |= FLAGS_HUB;
            }
            else if(!mycmp("CLIENT", tmp->value))
                new_confopts &= ~(FLAGS_HUB|FLAGS_SERVHUB);
            else
            {
                confparse_error("Unknown servtype in option block", lnum);
                return -1;
            }
        }
        else if(tmp->type && (tmp->type->flag & OPTF_NKLINEADDY))
        {
            tmp->type = NULL;
            strncpyzt(Network_Kline_Address, tmp->value,
                                    sizeof(Network_Kline_Address));
        }
        else if(tmp->type && (tmp->type->flag & OPTF_LKLINEADDY))
        {
            tmp->type = NULL;
            strncpyzt(Local_Kline_Address, tmp->value,
                                    sizeof(Local_Kline_Address));
        }
        else if(tmp->type && (tmp->type->flag & OPTF_STAFFADDY))
        {
            tmp->type = NULL;
            strncpyzt(Staff_Address, tmp->value, sizeof(Staff_Address));
        }
        else if(tmp->type && (tmp->type->flag & OPTF_LCLONES))
        {
            tmp->type = NULL;
            local_ip_limit = strtol(tmp->value, &s, 10);
            if (*s == ':')
                local_ip24_limit = atoi(s+1);
            if (local_ip_limit < 1)
                local_ip_limit = DEFAULT_LOCAL_IP_CLONES;
            if (local_ip24_limit < 1)
                local_ip24_limit = DEFAULT_LOCAL_IP24_CLONES;
        }
        else if(tmp->type && (tmp->type->flag & OPTF_GCLONES))
        {
            tmp->type = NULL;
            global_ip_limit = strtol(tmp->value, &s, 10);
            if (*s == ':')
                global_ip24_limit = atoi(s+1);
            if (global_ip_limit < 1)
                global_ip_limit = DEFAULT_GLOBAL_IP_CLONES;
            if (global_ip24_limit < 1)
                global_ip24_limit = DEFAULT_GLOBAL_IP24_CLONES;
        }
        else if(tmp->type && (tmp->type->flag & OPTF_SMOTD))
        {
            tmp->type = NULL;
            new_confopts |= FLAGS_SMOTD;
        }
        else if(tmp->type && (tmp->type->flag & OPTF_SMOTD))
        {
            tmp->type = NULL;
            new_confopts |= FLAGS_SMOTD;
        }
        else if(tmp->type && (tmp->type->flag & OPTF_CRYPTPASS))
        {
            tmp->type = NULL;
            new_confopts |= FLAGS_CRYPTPASS;
        }
        else if(tmp->type && (tmp->type->flag & OPTF_SHOWLINKS))
        {
            tmp->type = NULL;
            new_confopts |= FLAGS_SHOWLINKS;
        }
        else if(tmp->type && (tmp->type->flag & OPTF_SPLITOPOK))
        {
            tmp->type = NULL;
            new_confopts |= FLAGS_SPLITOPOK;
        }
        else if(tmp->type && (tmp->type->flag & OPTF_TSMAXDELTA))
        {
            tmp->type = NULL;
            tsmaxdelta = atoi(tmp->value);
        }
        else if(tmp->type && (tmp->type->flag & OPTF_TSWARNDELTA))
        {
            tmp->type = NULL;
            tswarndelta = atoi(tmp->value);
        }
    }
    return lnum;
}

int
confadd_allow(cVar *vars[], int lnum)
{
    cVar *tmp;
    aAllow *x = make_allow();
    int c = 0;
    /* Currently, Allows are the only config types without
     * easy identifiers - so we dont worry about duplicate types.
     * -epi
     */

    for(tmp = vars[c]; tmp; tmp = vars[++c])
    {
        if(tmp->type && (tmp->type->flag & SCONFF_IPMASK))
        {
            if(x->ipmask)
            {
                confparse_error("Multiple ipmask definitions", lnum);
                free_allow(x);
                return -1;
            }
            tmp->type = NULL;
            DupString(x->ipmask, tmp->value);
            if(strchr(x->ipmask, '@'))
                x->flags |= CONF_FLAGS_I_HOST_HAS_AT;
            x->flags |= CONF_FLAGS_I_MATCH_HOST;
        }
        else if(tmp->type && (tmp->type->flag & SCONFF_HOST))
        {
            if(x->hostmask)
            {
                confparse_error("Multiple host definitions", lnum);
                free_allow(x);
                return -1;
            }
            tmp->type = NULL;
            DupString(x->hostmask, tmp->value);
            if(strchr(x->hostmask, '@'))
                x->flags |= CONF_FLAGS_I_NAME_HAS_AT;
            x->flags |= CONF_FLAGS_I_MATCH_NAME;
        }
        else if(tmp->type && (tmp->type->flag & SCONFF_PASSWD))
        {
            if(x->passwd)
            {
                confparse_error("Multiple passwd definitions", lnum);
                free_allow(x);
                return -1;
            }
            tmp->type = NULL;
            DupString(x->passwd, tmp->value);
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
        }
        else if(tmp->type && (tmp->type->flag & SCONFF_PORT))
        {
            if(x->port > 0)
            {
                confparse_error("Multiple host definitions", lnum);
                free_allow(x);
                return -1;
            }
            tmp->type = NULL;
            x->port = atoi(tmp->value);
        }
        else if(tmp->type && (tmp->type->flag & SCONFF_CLASS))
        {
            if(x->class_name)
            {
                confparse_error("Multiple class definitions", lnum);
                free_allow(x);
                return -1;
            }
            tmp->type = NULL;
            DupString(x->class_name, tmp->value);
        }
    }
    if(!x->ipmask && !x->hostmask)
    {
        confparse_error("Lacking both ipmask and host for allow", lnum);
        free_allow(x);
        return -1;
    }
    if(!x->ipmask)
        DupString(x->ipmask, "-");
    if(!x->hostmask)
        DupString(x->hostmask, "-");
    x->next = new_allows;
    new_allows = x;
    return lnum;
}

int
confadd_port(cVar *vars[], int lnum)
{
    cVar *tmp;
    aPort *x;
    int    c = 0;

    x = make_port();
    for(tmp = vars[c]; tmp; tmp = vars[++c])
    {
        if(tmp->type && (tmp->type->flag & SCONFF_IPMASK))
        {
            if(x->allow)
            {
                confparse_error("Multiple ipmask definitions", lnum);
                free_port(x);
                return -1;
            }
            tmp->type = NULL;
            DupString(x->allow, tmp->value);
        }
        else if(tmp->type && (tmp->type->flag & SCONFF_BIND))
        {
            if(x->address)
            {
                confparse_error("Multiple bind definitions", lnum);
                free_port(x);
                return -1;
            }
            tmp->type = NULL;
            DupString(x->address, tmp->value);
        }
        else if(tmp->type && (tmp->type->flag & SCONFF_PORT))
        {
            if(x->port > 0)
            {
                confparse_error("Multiple port definitions", lnum);
                free_port(x);
                return -1;
            }
            tmp->type = NULL;
            x->port = atoi(tmp->value);
        }
    }
    if(!(x->port > 0))
    {
        confparse_error("Lacking port in port block", lnum);
        free_port(x);
        return -1;
    }
    x->next = new_ports;
    new_ports = x;
    return lnum;
}

int
confadd_global(cVar *vars[], int lnum)
{
    cVar *tmp;
    Conf_Me *x = new_MeLine;
    int c = 0;

    /* note:
     * we dont free this here because we'll do that if we pull out
     */

    if(!x)
    {
        x = make_me();
        new_MeLine = x;
    }

    for(tmp = vars[c]; tmp; tmp = vars[++c])
    {
        if(tmp->type && (tmp->type->flag & SCONFF_NAME))
        {
            unsigned char *s;
            int valid = 0;
            if(x->servername)
            {
                confparse_error("Multiple name definitions", lnum);
                return -1;
            }
            /* validate server name, based on m_server() */
            for (s = tmp->value; *s; s++)
            {
                if (*s < ' ' || *s > '~')
                {
                    valid = 0;
                    break;
                }
                if (*s == '.')
                    valid = 1;
            }
            if (!valid)
            {
                confparse_error("Invalid server name", lnum);
                return -1;
            }
            tmp->type = NULL;
            DupString(x->servername, tmp->value);
        }
        else if(tmp->type && (tmp->type->flag & SCONFF_INFO))
        {
            if(x->info)
            {
                confparse_error("Multiple info definitions", lnum);
                return -1;
            }
            tmp->type = NULL;
            DupString(x->info, tmp->value);
        }
        else if(tmp->type && (tmp->type->flag & SCONFF_DPASS))
        {
            if(x->diepass)
            {
                confparse_error("Multiple dpass definitions", lnum);
                return -1;
            }
            tmp->type = NULL;
            DupString(x->diepass, tmp->value);
        }
        else if(tmp->type && (tmp->type->flag & SCONFF_RPASS))
        {
            if(x->restartpass)
            {
                confparse_error("Multiple rpass definitions", lnum);
                return -1;
            }
            tmp->type = NULL;
            DupString(x->restartpass, tmp->value);
        }
    }
    if(!x->servername)
    {
        confparse_error("Lacking name definition in global block", lnum);
        return -1;
    }
    if(!x->info)
    {
        confparse_error("Lacking info definition in global block", lnum);
        return -1;
    }
    return lnum;
}

int
confadd_admin(cVar *vars[], int lnum)
{
    cVar *tmp;
    Conf_Me *x = new_MeLine;
    int c = 0;

    if(!x)
    {
        x = make_me();
        new_MeLine = x;
    }

    if (x->admin[0])
    {
        confparse_error("Multiple admin blocks", lnum);
        return -1;
    }

    for(tmp = vars[c]; tmp && (c != 3); tmp = vars[++c])
        DupString(x->admin[c], tmp->value);

    return lnum;
}

int
confadd_class(cVar *vars[], int lnum)
{
    cVar *tmp;
    aClass *x = make_class();
    int c = 0;
    char *s;

    for(tmp = vars[c]; tmp; tmp = vars[++c])
    {
        if(tmp->type && (tmp->type->flag & SCONFF_NAME))
        {
            if(x->name)
            {
                confparse_error("Multiple name definitions", lnum);
                free_class(x);
                return -1;
            }
            tmp->type = NULL;
            DupString(x->name, tmp->value);
        }
        else if(tmp->type && (tmp->type->flag & SCONFF_PINGFREQ))
        {
            if(x->pingfreq > 0)
            {
                confparse_error("Multiple pingfreq definitions", lnum);
                free_class(x);
                return -1;
            }
            tmp->type = NULL;
            x->pingfreq = atoi(tmp->value);
        }
        else if(tmp->type && (tmp->type->flag & SCONFF_CONNFREQ))
        {
            if(x->connfreq > 0)
            {
                confparse_error("Multiple maxclones/connfreq definitions",
                                lnum);
                free_class(x);
                return -1;
            }
            tmp->type = NULL;
            x->connfreq = strtol(tmp->value, &s, 10);
            if (*s == ':')
                x->ip24clones = atoi(s+1);
            if (x->connfreq < 1)
                x->connfreq = 0;
            if (x->ip24clones < 1)
                x->ip24clones = 0;
        }
        else if(tmp->type && (tmp->type->flag & SCONFF_MAXUSERS))
        {
            if(x->maxlinks > 0)
            {
                confparse_error("Multiple maxusers/maxlinks definitions"
                " (you can only have one or the other)",
                                lnum);
                free_class(x);
                return -1;
            }
            tmp->type = NULL;
            x->maxlinks = atoi(tmp->value);
        }
        else if(tmp->type && (tmp->type->flag & SCONFF_MAXSENDQ))
        {
            if(x->maxsendq > 0)
            {
                confparse_error("Multiple maxsendq definitions", lnum);
                free_class(x);
                return -1;
            }
            tmp->type = NULL;
            x->maxsendq = atoi(tmp->value);
        }
    }
    if(!x->name)
    {
        confparse_error("Lacking name definition", lnum);
        free_class(x);
        return -1;
    }
    if(!(x->maxsendq > 0))
    {
        confparse_error("Lacking maxsendq definition", lnum);
        free_class(x);
        return -1;
    }
    x->next = new_classes;
    new_classes = x;
    return lnum;
}

int
confadd_kill(cVar *vars[], int lnum)
{
    cVar *tmp;
    struct userBan *ban;
    int i, c = 0;
    char *ub_u = NULL, *ub_r = NULL, *host = NULL;
    char fbuf[512];
    aClient *ub_acptr;

    for(tmp = vars[c]; tmp; tmp = vars[++c])
    {
        if(tmp->type && (tmp->type->flag & SCONFF_MASK))
        {
            if(host)
            {
                confparse_error("Multiple mask definitions", lnum);
                return -1;
            }
            tmp->type = NULL;
            if((host = strchr(tmp->value, '@')))
            {
                *host = '\0';
                host++;
                ub_u = tmp->value;
            }
            else
                host = tmp->value;
        }
        if(tmp->type && (tmp->type->flag & SCONFF_REASON))
        {
            if(ub_r)
            {
                confparse_error("Multiple reason definitions", lnum);
                return -1;
            }
            tmp->type = NULL;
            ub_r = tmp->value;
            break;
        }
    }
    if(!host)
    {
        confparse_error("Lacking mask definition", lnum);
        return -1;
    }
    ub_u = BadPtr(ub_u) ? "*" : ub_u;
    ub_r = BadPtr(ub_r) ? "<No Reason>" : ub_r;

    ban = make_hostbased_ban(ub_u, host);
    if(!ban)
        return lnum;    /* this isnt a parser problem - dont pull out */

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
    return lnum;
}

int
confadd_super(cVar *vars[], int lnum)
{
    cVar *tmp;
    int c = 0;
    int i;

    /* If multiple super blocks are specified, set up to append */
    for (i = 0; new_uservers[i]; i++)
        ;

    for(tmp = vars[c]; tmp; tmp = vars[++c])
    {
        if (i == MAXUSERVS)
        {
            confparse_error("Excessive super server definitions", lnum);
            return -1;
        }
        DupString(new_uservers[i], tmp->value);
        i++;
    }
    new_uservers[i] = NULL;
    return lnum;
}

int
confadd_restrict(cVar *vars[], int lnum)
{
    cVar *tmp;
    int c = 0, type = 0;
    char *mask = NULL, *reason = NULL;
    struct simBan *ban;

    for(tmp = vars[c]; tmp; tmp = vars[++c])
    {
        if(tmp->type && (tmp->type->flag & SCONFF_TYPE))
        {
            if(type > 0)
            {
                confparse_error("Multiple type definitions", lnum);
                return -1;
            }
            tmp->type = NULL;
            if(!mycmp("CHAN", tmp->value))
                type = SBAN_CHAN;
            else if(!mycmp("NICK", tmp->value))
                type = SBAN_NICK;
            else if(!mycmp("GCOS", tmp->value))
                type = SBAN_GCOS;
            else
            {
                confparse_error("Unknown type in restrict block", lnum);
                return -1;
            }
            type |= SBAN_LOCAL;
        }
        else if(tmp->type && (tmp->type->flag & SCONFF_MASK))
        {
            if(mask)
            {
                confparse_error("Mutliple mask definitions", lnum);
                return -1;
            }
            tmp->type = NULL;
            mask = tmp->value;
        }
        else if(tmp->type && (tmp->type->flag & SCONFF_REASON))
        {
            if(reason)
            {
                confparse_error("Multiple reason definitions", lnum);
                return -1;
            }
            tmp->type = NULL;
            reason = tmp->value;
        }
    }
    if(!mask)
    {
        confparse_error("Missing mask in restrict block", lnum);
        return -1;
    }
    if(!(type > 0))
    {
        confparse_error("Missing type in restrict block", lnum);
        return -1;
    }
    ban = make_simpleban(type, mask);
    if(!ban)
        return lnum;
    if(find_simban_exact(ban) != NULL)  /* dont add duplicates */
    {
        simban_free(ban);
        return lnum;
    }
    if(!reason)
    {
        if(type & SBAN_CHAN)
            reason = "Reserved Channel";
        else if(type & SBAN_NICK)
            reason = "Reserved Nick";
        else if(type & SBAN_GCOS)
            reason = "Bad GCOS";
    }
    DupString(ban->reason, reason);
    ban->timeset = NOW;

    add_simban(ban);
    return lnum;
}

int
confadd_modules(cVar *vars[], int lnum)
{
    cVar *tmp;
    Conf_Modules *x = new_modules;
    int c = 0, ac = 0, oc = 0;

    /* this is like the global block - we dont free here because we do
     * it if we fail
     */

    if(!x)
    {
        x = (Conf_Modules *) MyMalloc(sizeof(Conf_Modules));
        memset((char *) x, '\0', sizeof(Conf_Modules));
        new_modules = x;
    }
    else
    {
        confparse_error("Multiple module blocks in config file", lnum);
        return -1;
    }

    for(tmp = vars[c]; tmp; tmp = vars[++c])
    {
        if(tmp->type && (tmp->type->flag & MBTF_PATH))
        {
            if(x->module_path)
            {
                confparse_error("Multiple module paths defined", lnum);
                return -1;
            }
            tmp->type = NULL;
            DupString(x->module_path, tmp->value);
        }
        else if(tmp->type && (tmp->type->flag & MBTF_AUTOLOAD))
        {
            if((ac+1) > 128)
            {
                confparse_error("Excessive autoloading modules (max 128)",
                                 lnum);
                return -1;
            }
            tmp->type = NULL;
            DupString(x->autoload[ac], tmp->value);
            ac++;
        }
        else if(tmp->type && (tmp->type->flag & MBTF_OPTLOAD))
        {
            if((oc+1) > 128)
            {
                confparse_error("Excessive optional modules (max 128)", lnum);
                return -1;
            }
            tmp->type = NULL;
            DupString(x->optload[oc], tmp->value);
            oc++;
        }
    }
    if(!x->autoload[0] && !x->optload[0])
    {
        confparse_error("No modules defined in module block", lnum);
        return -1;
    }
    return lnum;
}
    

/* set_classes
 * after loading the config into temporary lists, we must
 * set the appropriate classes for each conf.  If we run into
 * problems, then back out.
 */

static inline aClass *
find_new_class(char *name)
{
    aClass *tmp;
    if(!name)
        return find_new_class("default");
    for(tmp = new_classes; tmp; tmp = tmp->next)
        if(!mycmp(name, tmp->name))
            break;
    return tmp;
}

char *
set_classes(void)
{
    aConnect *aconn;
    aAllow   *allow;
    aOper    *aoper;

    /* Note:
     * You may be wondering why we're doing this here and appearently
     * again in our merge routines!  well, this is for sanity.  if
     * for whatever reason we dont have a class for each definition here,
     * back out of the conf load immediately and we wont have distroyed 
     * or overwritten any of our active data.
     * After we run our merge_classes() routine at the start of our
     * merge, then some of these classes will update currently active
     * classes and be free()'d - meaning some of these references are useless.
     * That is why we run it again inside the merge routines.
     * -epi
     */

    for(aconn = new_connects; aconn; aconn = aconn->next)
        if(!(aconn->class = find_new_class(aconn->class_name)))
            return aconn->class_name;
    for(allow = new_allows; allow; allow = allow->next)
        if(!(allow->class = find_new_class(allow->class_name)))
            return allow->class_name;
    for(aoper = new_opers; aoper; aoper = aoper->next)
        if(!(aoper->class = find_new_class(aoper->class_name)))
            return aoper->class_name;
    return NULL;
}


/* merge routines.  used to mirge together new lists and old lists
 * after a rehash. Feb27/04 -epi
 */

static void
merge_me()
{
    if(MeLine)
    {
        MyFree(MeLine->info);
        MyFree(MeLine->diepass);
        MyFree(MeLine->restartpass);
        MyFree(MeLine->admin[0]);
        MyFree(MeLine->admin[1]);
        MyFree(MeLine->admin[2]);
        /* MeLine->info is guaranteed to be replaced */
        MeLine->diepass = NULL;
        MeLine->restartpass = NULL;
        MeLine->admin[0] = NULL;
        MeLine->admin[1] = NULL;
        MeLine->admin[2] = NULL;
    }
    else
    {
        MeLine = new_MeLine;
        strncpyzt(me.name, MeLine->servername, sizeof(me.name));
        strncpyzt(me.info, MeLine->info, sizeof(me.info));
        new_MeLine = NULL;
        return;
    }
    DupString(MeLine->info, new_MeLine->info);
    strncpyzt(me.info, MeLine->info, sizeof(me.info));
    if(new_MeLine->diepass)
        DupString(MeLine->diepass, new_MeLine->diepass);
    if(new_MeLine->restartpass)
        DupString(MeLine->restartpass, new_MeLine->restartpass);
    if(new_MeLine->admin[0])
        DupString(MeLine->admin[0], new_MeLine->admin[0]);
    if(new_MeLine->admin[1])
        DupString(MeLine->admin[1], new_MeLine->admin[1]);
    if(new_MeLine->admin[2])
        DupString(MeLine->admin[2], new_MeLine->admin[2]);
    MyFree(new_MeLine->servername);
    MyFree(new_MeLine->info);
    MyFree(new_MeLine->diepass);
    MyFree(new_MeLine->restartpass);
    MyFree(new_MeLine->admin[0]);
    MyFree(new_MeLine->admin[1]);
    MyFree(new_MeLine->admin[2]);
    MyFree(new_MeLine);
    new_MeLine = NULL;
    return;
}

static void
merge_connects()
{
    aConnect    *aconn, *old_aconn, *ptr = NULL, *ptrn;

    /* first merge the list, then prune the list */

    /* set old as deletable */
    for(old_aconn = connects; old_aconn; old_aconn = old_aconn->next)
        old_aconn->legal = -1;
    /* update or add new */
    for (aconn = new_connects; aconn; aconn = ptrn)
    {
        ptrn = aconn->next;
        if ((old_aconn = find_aConnect(aconn->name)))
        {
            MyFree(old_aconn->host);
            MyFree(old_aconn->apasswd);
            MyFree(old_aconn->cpasswd);
            MyFree(old_aconn->source);
            MyFree(old_aconn->class_name);
            old_aconn->class->refs--;
            expire_class(old_aconn->class);

            old_aconn->host = aconn->host;
            old_aconn->apasswd = aconn->apasswd;
            old_aconn->cpasswd = aconn->cpasswd;
            old_aconn->source = aconn->source;
            old_aconn->class_name = aconn->class_name;
            old_aconn->port = aconn->port;
            old_aconn->flags = aconn->flags;
            old_aconn->class = find_class(aconn->class_name);
            old_aconn->class->refs++;
            old_aconn->legal = 1;
            lookup_confhost(old_aconn);

            MyFree(aconn->name);
            MyFree(aconn);
        }
        else
        {
            aconn->class = find_class(aconn->class_name);
            aconn->class->refs++;
            aconn->legal = 1;
            lookup_confhost(aconn);
            aconn->next = connects;
            connects = aconn;
        }
    }
    new_connects = NULL;

    ptr = NULL;
    /* and prune the active list */
    aconn = connects;
    while(aconn)
    {
        ptrn = aconn->next;
        if((aconn->legal == -1) && !aconn->acpt)
        {
            if(ptr)
                ptr->next = aconn->next;
            else
                connects = aconn->next;
            aconn->class->refs--;
            expire_class(aconn->class);
            free_connect(aconn);
        }
        else
            ptr = aconn;
        aconn = ptrn;
    }
    return;
}

static void
merge_allows()
{
    aAllow *allow, *ptr = NULL, *ptrn;

    for(allow = allows; allow; allow = allow->next)
        allow->legal = -1;
    allow = new_allows;
    while(allow)
    {
        allow->class = find_class(allow->class_name);
        allow->class->refs++;
        /* we dont really have to merge anything here.. */
        /* ..but we should avoid duplicates anyway */
        for (ptr = allows; ptr; ptr = ptr->next)
        {
            if (ptr->class != allow->class)
                continue;
            if (ptr->port != allow->port)
                continue;
            if (ptr->flags != allow->flags)
                continue;
            if (mycmp(ptr->ipmask, allow->ipmask))
                continue;
            if (mycmp(ptr->hostmask, allow->hostmask))
                continue;
            /* inverted logic below */
            if (ptr->passwd && allow->passwd
                && !mycmp(ptr->passwd, allow->passwd))
                break;
            if (ptr->passwd == allow->passwd)
                break;
        }
        /* if duplicate, mark for deletion but add anyway */
        if (ptr)
        {
            ptr->legal = 1;
            allow->legal = -1;
        }
        ptr = allow->next;
        allow->next = allows;
        allows = allow;
        allow = ptr;
    }
    new_allows = NULL;
    ptr = NULL;
    allow = allows;
    while(allow)
    {
        ptrn = allow->next;
        if((allow->legal == -1) && (allow->clients <= 0))
        {
            if(ptr)
                ptr->next = allow->next;
            else
                allows = allow->next;
            allow->class->refs--;
            expire_class(allow->class);
            free_allow(allow);
        }
        else
            ptr = allow;
        allow = ptrn;
    }
    return;     /* this one is easy */
}
    
static void
merge_opers()
{
    aOper *aoper, *old_oper, *ptrn = NULL, *ptr = NULL;

    for(old_oper = opers; old_oper; old_oper = old_oper->next)
        old_oper->legal = -1;

    /* add or merge and del new ones */
    for (aoper = new_opers; aoper; aoper = ptrn)
    {
        ptrn = aoper->next;
        if ((old_oper = find_oper_byname(aoper->nick)))
        {
            int i;

            for (i = 0; old_oper->hosts[i]; i++)
                MyFree(old_oper->hosts[i]);
            MyFree(old_oper->passwd);
            MyFree(old_oper->class_name);
            old_oper->class->refs--;
            expire_class(old_oper->class);

            for (i = 0; aoper->hosts[i]; i++)
                old_oper->hosts[i] = aoper->hosts[i];
            old_oper->hosts[i] = NULL;
            old_oper->passwd = aoper->passwd;
            old_oper->class_name = aoper->class_name;
            old_oper->class = find_class(aoper->class_name);
            old_oper->class->refs++;
            old_oper->flags = aoper->flags;
            old_oper->legal = 1;

            MyFree(aoper->nick);
            MyFree(aoper);
        }
        else
        {
            aoper->class = find_class(aoper->class_name);
            aoper->class->refs++;
            aoper->legal = 1;
            aoper->next = opers;
            opers = aoper;
        }
    }
    new_opers = NULL;

    /* del old ones */
    ptr = NULL;
    aoper = opers;
    while(aoper)
    {
        ptrn = aoper->next;
        if((aoper->legal == -1) && (aoper->opers <= 0))
        {
            if(ptr)
                ptr->next = aoper->next;
            else
                opers = aoper->next;
            free_oper(aoper);
        }
        else
            ptr = aoper;
        aoper = ptrn;
    }
    return;
}

static void
merge_ports()
{
    aPort *aport, *old_port, *ptrn;
    
    if(forked)
        close_listeners();      /* marks ports for deletion */

    /* add or merge and del new ones */
    for (aport = new_ports; aport; aport = ptrn)
    {
        ptrn = aport->next;
        if ((old_port = find_port(aport->port, aport->address)))
        {
            MyFree(old_port->allow);
            old_port->allow = aport->allow;
            old_port->legal = 1;
            MyFree(aport->address);
            MyFree(aport);
        }
        else
        {
            aport->next = ports;
            ports = aport;
        }
    }
    new_ports = NULL;

    if(forked)
        open_listeners();
    return;
}

static void
merge_classes()
{
    aClass  *class, *old_class, *ptr;

    for(old_class = classes; old_class; old_class = old_class->next)
        old_class->maxlinks = -1;

    for (class = new_classes; class; class = class->next)
    {
        if((old_class = find_class(class->name)))
        {
            old_class->connfreq = class->connfreq;
            old_class->pingfreq = class->pingfreq;
            old_class->maxlinks = class->maxlinks;
            old_class->maxsendq = class->maxsendq;
            old_class->ip24clones = class->ip24clones;
            class->maxlinks = -1;
        }
    }

    /* add classes from new_classes that are not maxlinks = -1 */
    for (class = new_classes; class; class = old_class)
    {
        old_class = class->next;
        if (class->maxlinks == -1)
            free_class(class);
        else
        {
            class->next = classes;
            classes = class;
        }
    }
    new_classes = NULL;

    /* now remove any classes from the list marked and w/o refs */
    for (class = classes; class; class = ptr)
    {
        ptr = class->next;
        expire_class(class);
    }
    return;
}

void
merge_options(void)
{
    if (forked && !(confopts & FLAGS_SMOTD) && (new_confopts & FLAGS_SMOTD))
        read_shortmotd(SHORTMOTD);
    confopts = new_confopts;
}

void
merge_confs()
{
    int i;

    merge_classes();        /* this should always be done first */
    merge_me();
    merge_connects();
    merge_allows();
    merge_opers();
    merge_ports();
    merge_options();
    for(i = 0; uservers[i]; i++)
        MyFree(uservers[i]);
    for(i = 0; new_uservers[i]; i++)
    {
        DupString(uservers[i], new_uservers[i]);
        MyFree(new_uservers[i]);
    }
    new_uservers[0] = NULL;
    /* dont worry about accually merging module data - its fairly
     * inactive and static data.  Just replace it.
     */
    if(modules)
    {
        MyFree(modules->module_path);
        for(i = 0; modules->autoload[i]; i++)
            MyFree(modules->autoload[i]);
        for(i = 0; modules->optload[i]; i++)
            MyFree(modules->optload[i]);
        MyFree(modules);
    }
    modules = new_modules;
    new_modules = NULL;
    return;
}

static void
clear_newconfs()
{
    aConnect *aconn = new_connects, *aconn_p;
    aClass   *class = new_classes, *class_p;
    aOper    *aoper = new_opers, *aoper_p;
    aPort    *aport = new_ports, *aport_p;
    aAllow   *allow = new_allows, *allow_p;
    int i = 0;

    while(aconn)
    {
        aconn_p = aconn->next;
        free_connect(aconn);
        aconn = aconn_p;
    }
    new_connects = NULL;
    while(class)
    {
        class_p = class->next;
        free_class(class);
        class = class_p;
    }
    new_classes = NULL;
    while(aoper)
    {
        aoper_p = aoper->next;
        free_oper(aoper);
        aoper = aoper_p;
    }
    new_opers = NULL;
    while(aport)
    {
        aport_p = aport->next;
        free_port(aport);
        aport = aport_p;
    }
    new_ports = NULL;
    while(allow)
    {
        allow_p = allow->next;
        free_allow(allow);
        allow = allow_p;
    }
    new_allows = NULL;
    if(new_MeLine)
    {
        MyFree(new_MeLine->servername);
        MyFree(new_MeLine->info);
        MyFree(new_MeLine->diepass);
        MyFree(new_MeLine->restartpass);
        MyFree(new_MeLine->admin[0]);
        MyFree(new_MeLine->admin[1]);
        MyFree(new_MeLine->admin[2]);
        MyFree(new_MeLine);
        new_MeLine = NULL;
    }
    while(new_uservers[i])
    {
        DupString(uservers[i], new_uservers[i]);
        MyFree(new_uservers[i]);
        i++;
    }
    new_uservers[0] = NULL;
    if(new_modules)
    {
        for(i = 0; new_modules->autoload[i]; i++)
            MyFree(new_modules->autoload[i]);
        for(i = 0; new_modules->optload[i]; i++)
            MyFree(new_modules->optload[i]);
        MyFree(new_modules->module_path);
        MyFree(new_modules);
        new_modules = NULL;
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
    aClient    *acptr;
    int         i;
    char       *conferr;

    if (sig == SIGHUP) 
    {
        sendto_ops("Got signal SIGHUP, reloading ircd conf. file");
        remove_userbans_match_flags(UBAN_NETWORK, 0);
        remove_userbans_match_flags(UBAN_LOCAL|UBAN_TEMPORARY, 0);
        remove_simbans_match_flags(SBAN_NICK|SBAN_LOCAL|SBAN_TEMPORARY, 0);
        remove_simbans_match_flags(SBAN_CHAN|SBAN_LOCAL|SBAN_TEMPORARY, 0);
        remove_simbans_match_flags(SBAN_GCOS|SBAN_LOCAL|SBAN_TEMPORARY, 0);

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

    if (sig != SIGINT)
        flush_cache();      /* Flush DNS cache */

    /* remove perm klines */
    remove_userbans_match_flags(UBAN_LOCAL, UBAN_TEMPORARY);
    remove_simbans_match_flags(SBAN_NICK|SBAN_LOCAL, SBAN_TEMPORARY);
    remove_simbans_match_flags(SBAN_CHAN|SBAN_LOCAL, SBAN_TEMPORARY);
    remove_simbans_match_flags(SBAN_GCOS|SBAN_LOCAL, SBAN_TEMPORARY);


    initclass();
    new_confopts = 0;

    if(initconf(configfile) == -1)
    {
        sendto_realops("Rehash Aborted");
        clear_newconfs();
        return 1;
    }

    conferr = finishconf();
    if (conferr)
    {
        sendto_realops("Rehash Aborted: %s", conferr);
        clear_newconfs();
        return 1;
    }
    
    merge_confs();
    build_rplcache();

    rehashed = 1;

    return 1;
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
    if (!IsAlpha(*s) && !IsDigit(*s)) 
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
    
    if (IsDigit(*s))
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
