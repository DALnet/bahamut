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

extern aOper        *make_oper();
extern aConnect     *make_connect();
extern aAllow       *make_allow();
extern struct Conf_Me   *make_me();
extern aPort        *make_port();

/* these are our global lists of ACTIVE conf entries */

#define MAXUSERVS 24

aConnect   *connects  = NULL;       /* connects, C/N pairs  */
aAllow     *allows    = NULL;       /* allows  - I lines    */
Conf_Me    *MeLine    = NULL;       /* meline - only one    */
aOper      *opers     = NULL;       /* opers - Olines       */
aPort      *ports     = NULL;       /* ports - P/M lines    */
aClass     *classes   = NULL;;      /* classes - Ylines     */
char       *uservers[MAXUSERVS];    /* uservers = Ulines    */

/* this set of lists is used for loading and rehashing the config file */

aConnect    *new_connects   = NULL;
aAllow      *new_allows     = NULL;
Conf_Me     *new_MeLine     = NULL;
aOper       *new_opers      = NULL;
aPort       *new_ports      = NULL;
aClass      *new_classes    = NULL;
char        *new_uservers[MAXUSERVS]; 

#ifdef LOCKFILE
extern void do_pending_klines(void);
#endif
extern void confparse_error(char *, int);

/* initclass()
 * initialize the default class
 */

void initclass()
{
    new_classes = (aClass *) make_class();

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
    strncpyzt(Network_Kline_Address, DEFAULT_NKLINE_ADDY,
                                            sizeof(Network_Kline_Address));
    strncpyzt(Local_Kline_Address, DEFAULT_LKLINE_ADDY,
                                            sizeof(Local_Kline_Address));
    strncpyzt(Staff_Address, DEFAULT_STAFF_ADDRESS, sizeof(Staff_Address));
    maxchannelsperuser = DEFAULT_MAXCHANNELSPERUSER;
    tsmaxdelta = DEFAULT_TSMAXDELTA;
    tswarndelta = DEFAULT_TSWARNDELTA;
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
    int i = 0;
    while(ptr->hosts[i])
    {
        MyFree(ptr->hosts[i]);
        i++;
    }
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

void
free_class(aClass *ptr)
{
    MyFree(ptr->name);
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
    else if (cptr->user != NULL)
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
    int i = 0, t = 0;

    /* sockhost OR hostip must match our host field */


    (void) ircsprintf(userhost, "%s@%s", username, sockhost);
    (void) ircsprintf(userip, "%s@%s", username, hostip);

    for(aoper = opers; aoper; aoper = aoper->next)
    {
        while(aoper->hosts[i])
        {
            if(!(mycmp(name, aoper->nick) && (!match(userhost, aoper->hosts[i]) 
                    || !match(userip, aoper->hosts[i]))))
            {
                t = 1;
                break;
            }
            i++;
        }
        if(t == 1)
            break;
    }
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
find_class(char *name, int i)
{
    aClass *tmp;
    if(i == 1)
    {
        for(tmp = new_classes; tmp; tmp = tmp->next)
            if(!mycmp(name, tmp->name))
                break;
    }
    else
    {
        for(tmp = classes; tmp; tmp = tmp->next)
            if(!mycmp(name, tmp->name))
                break;
    }

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
            cptr->class = find_class("default", 0);
    }
    else
    {
        if(cptr->user->oper)
            cptr->class = cptr->user->oper->class;
        else if(cptr->user->allow)
            cptr->class = cptr->user->allow->class;
        else
            cptr->class = find_class("default", 0);
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
                (void) ircsprintf(newhost, "*@%s", tmp->value);
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
            if(!(x->class = find_class(tmp->value, 1)))
                x->class = find_class("default", 1);
        }
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
    if(!x->class)
        x->class = find_class("default", 1);
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
    int *i, flag, new = 1, c = 0;
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
                (void) ircsprintf(newhost, "*@%s", tmp->value);
                x->host = newhost;
            }
            else
                DupString(x->host, tmp->value);
            (void) lookup_confhost(x);
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
            if(new && x->class)
            {
                confparse_error("Multiple class definitions", lnum);
                free_connect(x);
                return -1;
            }
            tmp->type = NULL;
            x->class = find_class(tmp->value, 1);
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
    if(!x->class)
        x->class = find_class("default", 1);
    x->next = new_connects;
    new_connects = x;
    return lnum;
}

int
confadd_options(cVar *vars[], int lnum)
{
    cVar *tmp;
    int c = 0;
    char *ctmp = NULL;

    /* here, because none of the option peice are interdependent
     * all the items are added immediately.   Makes life easier
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
            confopts |= FLAGS_WGMONURL;
            strncpyzt(ProxyMonHost, tmp->value, sizeof(ProxyMonHost));
        }
        else if(tmp->type && (tmp->type->flag & OPTF_WGMONURL))
        {
            tmp->type = NULL;
            confopts |= FLAGS_WGMONHOST;
            strncpyzt(ProxyMonURL, tmp->value, sizeof(ProxyMonURL));
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
                confopts |= FLAGS_HUB;
            else if(!mycmp("SERVICESHUB", tmp->value))
                confopts |= FLAGS_SERVHUB;
            else if(!mycmp("CLIENT", tmp->value))
                confopts &= ~(FLAGS_HUB|FLAGS_SERVHUB);
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
        else if(tmp->type && (tmp->type->flag & OPTF_SMOTD))
        {
            tmp->type = NULL;
            confopts |= FLAGS_SMOTD;
        }
        else if(tmp->type && (tmp->type->flag & OPTF_SMOTD))
        {
            tmp->type = NULL;
            confopts |= FLAGS_SMOTD;
        }
        else if(tmp->type && (tmp->type->flag & OPTF_CRYPTPASS))
        {
            tmp->type = NULL;
            confopts |= FLAGS_CRYPTPASS;
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
            if(x->class)
            {
                confparse_error("Multiple class definitions", lnum);
                free_allow(x);
                return -1;
            }
            tmp->type = NULL;
            x->class = find_class(tmp->value, 1);
        }
    }
    if(!x->ipmask && !x->hostmask)
    {
        confparse_error("Lacking both ipmask and host for allow", lnum);
        free_allow(x);
        return -1;
    }
    if(!x->ipmask)
    {
        DupString(x->ipmask, "*@*");
        x->flags |= CONF_FLAGS_I_HOST_HAS_AT;
    }
    if(!x->passwd)
        DupString(x->passwd, "");
    if(!x->hostmask)
    {
        DupString(x->hostmask, "*@*");
        x->flags |= CONF_FLAGS_I_NAME_HAS_AT;
    }
    if(!x->class)
        x->class = find_class("default", 1);
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
    if(!x->allow)
        DupString(x->allow, "");
    if(!x->address)
        DupString(x->address, "");
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
        x = make_me();

    for(tmp = vars[c]; tmp; tmp = vars[++c])
    {
        if(tmp->type && (tmp->type->flag & SCONFF_NAME))
        {
            if(x->servername)
            {
                confparse_error("Multiple name definitions", lnum);
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
    new_MeLine = x;
    return lnum;
}

int
confadd_admin(cVar *vars[], int lnum)
{
    cVar *tmp;
    Conf_Me *x = new_MeLine;
    int c = 0;

    if(!x)
        x = make_me();

    for(tmp = vars[c]; tmp && (c != 3); tmp = vars[++c])
        DupString(x->admin[c], tmp->value);

    new_MeLine = x;
    return lnum;
}

int
confadd_class(cVar *vars[], int lnum)
{
    cVar *tmp;
    aClass *x = make_class();
    int c = 0;

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
                confparse_error("Multiple connfreq definitions", lnum);
                free_class(x);
                return -1;
            }
            tmp->type = NULL;
            x->connfreq = atoi(tmp->value);
        }
        else if(tmp->type && (tmp->type->flag & SCONFF_MAXUSERS))
        {
            if(x->maxlinks > 0)
            {
                confparse_error("Multiple maxusers definitions", lnum);
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
                host = '\0';
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

    for(tmp = vars[c]; tmp; tmp = vars[++c])
        DupString(new_uservers[c], tmp->value);
    new_uservers[++c] = NULL;
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
            if(!strcmp("CHAN", tmp->value))
                type = SBAN_CHAN;
            else if(!strcmp("NICK", tmp->value))
                type = SBAN_NICK;
            else if(!strcmp("GCOS", tmp->value))
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
    aConnect    *aconn, *old_aconn, *ptr = NULL;

    /* first merge the list, then prune the list */

    /* set old as deletable */
    for(old_aconn = connects; old_aconn; old_aconn = old_aconn->next)
        old_aconn->legal = -1;
    /* update or add new */
    for(aconn = new_connects; aconn; )
        if((old_aconn = find_aConnect(aconn->name)))
        {
            /* update the old entry */
            MyFree(old_aconn->host);
            MyFree(old_aconn->apasswd);
            MyFree(old_aconn->cpasswd);
            MyFree(old_aconn->source);
            DupString(old_aconn->host, aconn->host);
            DupString(old_aconn->apasswd, aconn->apasswd);
            DupString(old_aconn->cpasswd, aconn->cpasswd);
            if(aconn->source)
                DupString(old_aconn->source, aconn->source);
            old_aconn->port = aconn->port;
            old_aconn->flags = aconn->flags;
            old_aconn->class = aconn->class;
            old_aconn->legal = 1;       /* the old entry is ok now */
            aconn->legal = -1;          /* new new entry is not */
            aconn = aconn->next;
        }
        else
        {   
            /* tag the new entry onto the begining of the list */
            ptr = aconn->next;
            aconn->legal = 1;
            aconn->next = connects;
            connects = aconn;
            aconn = ptr;
        }
    /* and prune old list */
    ptr = NULL;
    for(aconn = new_connects; aconn; aconn = aconn->next)
    {
        if(aconn->legal == -1)
        {
            if(ptr)
                ptr->next = aconn->next;
            else
                new_connects = aconn->next;
            free_connect(aconn);
        }
        ptr = aconn;
    }
    new_connects = NULL;
    ptr = NULL;
    /* and prune the active list */
    for(aconn = connects; aconn; aconn = aconn->next)
    {
        if((aconn->legal == -1) && !aconn->acpt)
        {
            if(ptr)
                ptr->next = aconn->next;
            else
                connects = aconn->next;
            free_connect(aconn);
        }
        ptr = aconn;
    }
    return;
}

static void
merge_allows()
{
    aAllow *allow, *ptr = NULL;

    for(allow = allows; allow; allow = allow->next)
        allow->legal = -1;
    for(allow = new_allows; allow; )
    {
        /* we dont really have to merge anything here.. */
        ptr = allow->next;
        allow->next = allows;
        allows = allow;
        allow = ptr;
    }
    new_allows = NULL;
    for(allow = allows; allow; allow = allow->next)
    {
        if((allow->legal == -1) && (allow->clients <= 0))
        {
            if(ptr)
                ptr->next = allow->next;
            else
                allows = allow->next;
            free_allow(allow);
        }
        ptr = allow;
    }
    return;     /* this one is easy */
}
    
static void
merge_opers()
{
    aOper *aoper, *old_oper, *ptr = NULL;

    for(old_oper = opers; old_oper; old_oper = old_oper->next)
        old_oper->legal = -1;
    for(aoper = new_opers; aoper; )
        if((old_oper = find_oper_byname(aoper->nick)))
        {
            int i = 0;
            while(old_oper->hosts[i])
            {
                MyFree(old_oper->hosts[i]);
                i++;
            }
            MyFree(old_oper->passwd);
            i = 0;
            while(aoper->hosts[i])
            {
                DupString(old_oper->hosts[i], aoper->hosts[i]);
                i++;
            }
            aoper->hosts[i] = NULL;
            DupString(old_oper->passwd, aoper->passwd);
            old_oper->flags = aoper->flags;
            old_oper->class = aoper->class;
            old_oper->legal = 1;
            aoper->legal = -1;
            aoper = aoper->next;
        }
        else
        {
            ptr = aoper->next;
            aoper->legal = 1;
            aoper->next = opers;
            opers = aoper;
            aoper = ptr;
        }
    ptr = NULL;
    for(aoper = new_opers; aoper; aoper = aoper->next)
    {
        if((aoper->legal == -1) && (aoper->opers <= 0))
        {
            if(ptr)
                ptr->next = aoper->next;
            else
                new_opers = aoper->next;
            free_oper(aoper);
        }
        ptr = aoper;
    }

    new_opers = NULL;
    ptr = NULL;
    for(aoper = opers; aoper; aoper = aoper->next)
    {
        if((aoper->legal == -1) && (aoper->opers <= 0))
        {
            if(ptr)
                ptr->next = aoper->next;
            else
                opers = aoper->next;
            free_oper(aoper);
        }
        ptr = aoper;
    }
    return;
}

static void
merge_ports()
{
    aPort *aport, *old_port, *ptr = NULL;
    
    if(forked)
        close_listeners();      /* marks ports for deletion */
    for(aport = new_ports; aport; )
        if((old_port = find_port(aport->port)))
        {
            MyFree(old_port->allow);
            MyFree(old_port->address);
            DupString(old_port->allow, aport->allow);
            DupString(old_port->address, aport->address);
            old_port->legal = 1;
            aport->legal = -1;
            aport = aport->next;
        }
        else
        {
            ptr = aport->next;
            aport->legal = 1;
            aport->next = ports;
            ports = aport;
            aport = ptr;
        }
    ptr = NULL;
    for(aport = new_ports; aport; aport = aport->next);
    {
        if(aport && (aport->legal == -1))
        {
            if(ptr)
                ptr->next = aport->next;
            else
                ports = aport->next;
            free_port(aport);
        }
        ptr = aport;
    }
    new_ports = NULL;
    if(forked)
        open_listeners();
    return;
}

static void
merge_classes()
{
    aClass  *class, *old_class, *ptr = NULL;

    for(old_class = classes; old_class; old_class = old_class->next)
        old_class->maxlinks = -1;
    for(class = new_classes; class; )
        if((old_class = find_class(class->name, 0)))
        {
            old_class->connfreq = class->connfreq;
            old_class->pingfreq = class->pingfreq;
            old_class->maxlinks = class->maxlinks;
            old_class->maxsendq = class->maxsendq;
            class->maxlinks = -1;
            class = class->next;
        }
        else
        {
            ptr = class->next;
            class->next = classes;
            classes = class;
            class = ptr;
        }
    ptr = NULL;
    for(class = new_classes; class; class = class->next)
    {
        if(class->maxlinks == -1)
        {
            if(ptr)
                ptr->next = class->next;
            else
                new_classes = class->next;
            free_class(class);
        }
        ptr = class;
    }
    new_classes = NULL;
    ptr = NULL;
    for(class = classes; class; class = class->next)
    {
        if((class->maxlinks == -1) && (class->links <= 0))
        {
            if(ptr)
                ptr->next = class->next;
            else
                classes = class->next;
            free_class(class);  
        }
        ptr = class;
    }
    return;
}

void
merge_confs()
{
    int i = 0;

    merge_me();
    merge_connects();
    merge_allows();
    merge_opers();
    merge_ports();
    merge_classes();
    while(uservers[i])
    {
        MyFree(uservers[i]);
        i++;
    }
    i = 0;
    while(new_uservers[i])
    {
        DupString(uservers[i], new_uservers[i]);
        MyFree(new_uservers[i]);
        i++;
    }
    new_uservers[0] = NULL;
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

    if (sig != SIGINT)
        flush_cache();      /* Flush DNS cache */

    /* remove perm klines */
    remove_userbans_match_flags(UBAN_LOCAL, UBAN_TEMPORARY);

    if(initconf(configfile) == -1)
    {
        sendto_realops("Rehash Aborted");
        clear_newconfs();
        return 1;
    }

    if(!new_ports)
    {
        sendto_one(sptr, "Rehash Aborted:  No ports defined");
        clear_newconfs();
        return 1;
    }
    
    merge_confs();

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
