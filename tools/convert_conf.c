/* tools/convert_conf.c
 * Copyright (c) 2004, Aaron Wiebe
 *              and The Bahamut Development Team
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

#define MyMalloc(x) malloc(x)
#define SBAN_LOCAL     0x001
#define SBAN_NETWORK   0x002
#define SBAN_NICK      0x004   /* sban on the nick field */
#define SBAN_GCOS      0x008   /* sban on the gcos field */
#define SBAN_CHAN      0x010   /* sban on the chname field */
#define SBAN_WILD      0x020   /* sban mask contains wildcards */
#define SBAN_TEMPORARY 0x040   /* sban is temporary */

#define MAX_USERVERS 32

aConnect   *connects  = ((aConnect *) NULL);    /* connects, C/N pairs  */
aAllow     *allows    = ((aAllow *) NULL);  /* allows  - I lines    */
Conf_Me    *MeLine    = ((Conf_Me *) NULL); /* meline - only one    */
aOper      *opers     = ((aOper *) NULL);   /* opers - Olines   */
aPort      *ports     = ((aPort *) NULL);   /* ports - P/M lines    */
aClass     *classes = NULL;
char*      uservers[MAX_USERVERS];

typedef struct _asimban SimBan;
typedef struct _ahostban HostBan;

struct _asimban
{
    int type;
    char *reason;
    char *target;
    SimBan *next;
};

struct _ahostban
{
    char *username;
    char *reason;
    char *target;
    HostBan *next;
};

SimBan *sbans = NULL;
HostBan *hbans = NULL;
char ProxyMonHost[HOSTLEN+1];
char ProxyMonURL[TOPICLEN+1];


int dgets(int fd, char *buf, int num)
{
    static char dgbuf[8192];
    static char *head = dgbuf, *tail = dgbuf;
    char *s, *t;
    int n, nr;

    /* Sanity checks. */
    if (head == tail)
    *head = '\0';

    if (!num)
    {
    head = tail = dgbuf;
    *head = '\0';
    return 0;
    }

    if (num > sizeof(dgbuf) - 1)
    num = sizeof(dgbuf) - 1;

    FOREVER
    {
    if (head > dgbuf)
    {
        for (nr = tail - head, s = head, t = dgbuf; nr > 0; nr--)
        *t++ = *s++;
        tail = t;
        head = dgbuf;
    }
    /* check input buffer for EOL and if present return string. */
    if (head < tail &&
        ((s = strchr(head, '\n')) ||
         (s = strchr(head, '\r'))) && s < tail)
    {
        n = MIN(s - head + 1, num); /* at least 1 byte */
        memcpy(buf, head, n);
        head += n;
        if (head == tail)
        head = tail = dgbuf;
        return n;
    }


    if (tail - head >= num)
    {      /* dgets buf is big enough */
        n = num;
        memcpy(buf, head, n);
        head += n;
        if (head == tail)
        head = tail = dgbuf;
        return n;
    }

    n = sizeof(dgbuf) - (tail - dgbuf) - 1;
    nr = read(fd, tail, n);
    if (nr == -1)
    {
        head = tail = dgbuf;
        return -1;
    }

    if (!nr)
    {
        if (tail > head)
        {
        n = MIN(tail - head, num);
        memcpy(buf, head, n);
        head += n;
        if (head == tail)
            head = tail = dgbuf;
        return n;
        }
        head = tail = dgbuf;
        return 0;
    }

    tail += nr;
    *tail = '\0';

    for (t = head; (s = strchr(t, '\n'));)
    {
        if ((s > head) && (s > dgbuf))
        {
        t = s - 1;
        for (nr = 0; *t == '\\'; nr++)
            t--;
        if (nr & 1)
        {
            t = s + 1;
            s--;
            nr = tail - t;
            while (nr--)
            *s++ = *t++;
            tail -= 2;
            *tail = '\0';
            }
        else
            s++;
        }
        else
        s++;
        t = s;
    }
    *tail = '\0';
    }
}


char *getfield(char *newline)
{
    static char *line = (char *) NULL;
    char       *end, *field;

    if (newline)
    line = newline;

    if (line == (char *) NULL)
    return ((char *) NULL);

    field = line;
    if ((end = strchr(line, ':')) == NULL)
    {
    line = (char *) NULL;
    if ((end = strchr(field, '\n')) == (char *) NULL)
        end = field + strlen(field);
    }
    else
    line = end + 1;
    *end = '\0';
    return (field);
}


aClass *make_class()
{
    aClass *tmp;

    tmp = (aClass *) MyMalloc(sizeof(aClass));
    return tmp;
}

void free_class(tmp)
    aClass *tmp;
{
    MyFree((char *) tmp);
}

aOper *make_oper()
{
    aOper *i;
    i = (struct Conf_Oper *) MyMalloc(sizeof(aOper));
    memset((char *) i, '\0', sizeof(aOper));
    return i;
}

SimBan *make_simban()
{
    SimBan *i;
    i = (struct _asimban *) MyMalloc(sizeof(SimBan));
    memset((char *) i, '\0', sizeof(SimBan));
    return i;
}

HostBan *make_hostban()
{
    HostBan *i;
    i = (struct _ahostban *) MyMalloc(sizeof(HostBan));
    memset((char *) i, '\0', sizeof(HostBan));
    return i;
}

aConnect *make_connect()
{
    aConnect *i;
    i = (struct Conf_Connect *) MyMalloc(sizeof(aConnect));
    memset((char *) i, '\0', sizeof(aConnect));
    return i;
}

aAllow *make_allow()
{
    aAllow *i;
    i = (struct Conf_Allow *) MyMalloc(sizeof(aAllow));
    memset((char *) i, '\0', sizeof(aAllow));
    return i;
}

aPort *make_port()
{
    aPort *i;
    i = (struct Conf_Port *) MyMalloc(sizeof(aPort));
    memset((char *) i, '\0', sizeof(aPort));
    return i;
}

Conf_Me *make_me()
{
    Conf_Me *i;
    i = (struct Conf_Me *) MyMalloc(sizeof(Conf_Me));
    memset((char *) i, '\0', sizeof(Conf_Me));
    return i;
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

    (void) sprintf(userhost, "%s@%s", username, host);

    for(aconn = connects; aconn; aconn = aconn->next)
        if(!mycmp(name, aconn->name) && !match(userhost, aconn->host))
            break;
    return aconn;
}

char *
find_aUserver(char *name)
{
    int i;
    
    for (i = 0; uservers[i]; ++i)
        if (mycmp(name, uservers[i]) == 0)
            break;
    return uservers[i];
}

aOper *
find_oper(char *name, char *username, char *sockhost, char *hostip)
{
    aOper *aoper;
    char userhost[USERLEN + HOSTLEN + 3];
    char userip[USERLEN + HOSTLEN + 3];
    int i;

    /* sockhost OR hostip must match our host field */


    (void) sprintf(userhost, "%s@%s", username, sockhost);
    (void) sprintf(userip, "%s@%s", username, sockhost);

    for(aoper = opers; aoper; aoper = aoper->next)
    {
        for (i = 0; aoper->hosts[i]; ++i)
        {
            if(!(mycmp(name, aoper->nick) && (match(userhost, aoper->hosts[i]) ||
                 match(userip, aoper->hosts[i]))))
                break;
        }
        if (aoper->hosts[i]) break;
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
find_class(char *name)
{
    aClass *tmp;
    for(tmp = classes; tmp; tmp = tmp->next)
        if(!mycmp(name, tmp->name))
            break;
    return tmp;
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
    int *i, flag, new, hostidx;
    char *m = "*";
    
    if (!strchr(host, '@') && *host != '/')
    {
        char       *newhost;
        int         len = 3;
        len += strlen(host);
        newhost = (char *) MyMalloc(len);
        (void) sprintf(newhost, "*@%s", host);
        host = newhost;
    }


    if((x = find_oper_byname(name)))
    {
        new = 0;
        for (hostidx = 0; x->hosts[hostidx]; ++hostidx)
        {
            if (mycmp(x->hosts[hostidx], host) == 0)
                break;
        }
        if (x->hosts[hostidx] == NULL)
        {
            DupString(x->hosts[hostidx], host);
            x->hosts[hostidx+1] = NULL;
        }
    }
    else
    {
        x = make_oper();
        DupString(x->nick, name);
        DupString(x->passwd, passwd);
        DupString(x->hosts[0], host);
        x->hosts[1] = NULL;
        new = 1;
    }
    x->legal = 1;
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
            (void) sprintf(newhost, "*@%s", x->host);
            MyFree(x->host);
            x->host = newhost;
        }
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
    if(servername)
    {
        DupString(MeLine->servername, servername);
    }
    if(info)
    {
        MyFree(MeLine->info);
        DupString(MeLine->info, info);
    }
    if(aline1)
    {
        MyFree(MeLine->admin[0]);
        DupString(MeLine->admin[0], aline1);
    }
    if(aline2)
    {
        MyFree(MeLine->admin[1]);
        DupString(MeLine->admin[1], aline2);
    }
    if(aline3)
    {
        MyFree(MeLine->admin[2]);
        DupString(MeLine->admin[2], aline3);
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
confadd_simban(int flags, char *mask, char *reason)
{
    SimBan *x;
    x = make_simban();
    x->type = flags;
    DupString(x->target, mask);
    DupString(x->reason, reason);
    x->next = sbans;
    sbans = x;
    return;
}
    
void
confadd_hostban(char *username, char *mask, char *reason)
{
    HostBan *x;
    x = make_hostban();
    DupString(x->username, username);
    DupString(x->target, mask);
    DupString(x->reason, reason);
    x->next = hbans;
    hbans = x;
    return;
}

void
confadd_uline(char *host)
{
    int i;
    
    if (find_aUserver(host) != NULL)
        return;
    
    for (i = 0; uservers[i]; ++i);
    
    DupString(uservers[i], host);
    uservers[i+1] = NULL;
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
                printf("// Bad config line: \"%s\" - Ignored\n", line);
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
        if(t_status & CONF_HUB)
        {
            aConnect *x = find_aConnect(t_name);
            if(!x)
                confadd_connect(t_name, 0, 0, 0, 0, t_flags, 0, 0);
            else
                x->flags |= CONN_HUB;
            continue;
        }
        if (t_status & CONF_CLASS)
        {
            confadd_class(t_host, atoi(t_passwd), atoi(t_name),
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
            int flags;
            char *sb_m, *sb_r;

            if(BadPtr(t_name))
                continue;

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

            confadd_simban(flags, sb_m, sb_r);

            continue;
        }

        if (t_status & CONF_GCOS)
        {
            unsigned int flags;
            char *sb_m, *sb_r;

            if(BadPtr(t_name))
                continue;

            flags = SBAN_LOCAL|SBAN_GCOS;
            sb_r = BadPtr(t_passwd) ? "Bad GCOS" : t_passwd;

            sb_m = t_name;

            confadd_simban(flags, sb_m, sb_r);
                continue;
        }

        if (t_status & CONF_KILL)
        {
            char *ub_u, *ub_r;

            if(BadPtr(t_host))
                continue;

            ub_u = BadPtr(t_name) ? "*" : t_name;
            ub_r = BadPtr(t_passwd) ? "<No Reason>" : t_passwd;

            confadd_hostban(ub_u, t_host, ub_r);

            continue;
        }
        if (t_status & CONF_ULINE)
        {
            confadd_uline(t_host);
            continue;
        }
        if(t_status & CONF_DRPASS)
        {
            confadd_me(0,0, t_host, t_passwd, 0, 0, 0);
            continue;
        }
        /* oh shit! */
        printf("Error parsing config file!\n");
        printf("line: %s", line);
        exit(-1);
    }
    (void) dgets(-1, NULL, 0);  /* make sure buffer is at empty pos */
    (void) close(fd);
    return 0;
}

void
printconf()
{
    /* print off the new config file */
    aClass *class;
    aAllow *allow;
    aOper  *aoper;
    aConnect *aconn;
    aPort   *aport;
    SimBan  *sban;
    HostBan *hban;

    printf("/* Generated by Bahamut's convert_conf */ \n");
    printf("\nglobal {\n");
    printf("    name \"%s\";\n", MeLine->servername);
    printf("    info \"%s\";\n", MeLine->info);
    printf("    admin {\n");
    printf("        \"%s\";\n", MeLine->admin[0]);
    printf("        \"%s\";\n", MeLine->admin[1]);
    printf("        \"%s\";\n", MeLine->admin[2]);
    printf("    };\n");
    if(MeLine->diepass && MeLine->diepass != "")
        printf("    dpass \"%s\";\n", MeLine->diepass);
    if(MeLine->restartpass && MeLine->restartpass != "")
        printf("    rpass \"%s\";\n", MeLine->restartpass);
    printf("};\n\n");
    printf("/* Class Definitions */\n\n");
    for(class = classes; class; class = class->next)
    {
        printf("class %s {\n", class->name);
        printf("    pingfreq %d;\n", class->pingfreq);
        printf("    maxlinks %d;\n", class->maxlinks);
        printf("    connectfreq %d;\n", class->connfreq);
        printf("    maxsendq %d;\n", class->maxsendq);
        printf("};\n\n");
    }
    printf("/* Allow definitions */\n\n");
    for(allow = allows; allow; allow = allow->next)
    {
        printf("allow {\n");
        printf("    ipmask \"%s\";\n", allow->ipmask);
        printf("    hostmask \"%s\";\n", allow->hostmask);
        if(allow->passwd && allow->passwd != "")
            printf("    passwd \"%s\";\n", allow->passwd);
        if(allow->port != 0)
            printf("    port %d;\n", allow->port);
        printf("};\n\n");
    }
    printf("/* Oper definitions */\n\n");
    for(aoper = opers; aoper; aoper = aoper->next)
    {
        int i;
        char oper_flags[32] = { 0 }, *ptr = oper_flags;
        printf("oper %s {\n", aoper->nick);
        for (i = 0; aoper->hosts[i]; ++i)
            printf("    host \"%s\";\n", aoper->hosts[i]);
        printf("    passwd \"%s\";\n", aoper->passwd);
        if(aoper->flags & OFLAG_ADMIN)
            *ptr++ = 'A';
        if(aoper->flags & OFLAG_SADMIN)
            *ptr++ = 'a';
        if(aoper->flags & OFLAG_GLOBAL)
            *ptr++ = 'O';
        else if(aoper->flags & OFLAG_LOCAL)
            *ptr++ = 'o';
        if (*ptr) printf("    flags %s;\n", oper_flags);
        printf("    class \"%s\";\n", aoper->class->name);
        printf("};\n\n");
    }
    printf("/* Connection Definitions */\n\n");
    for(aconn = connects; aconn; aconn = aconn->next)
    {
        if(!aconn->host || aconn->host == "")
            continue;
        printf("connect %s {\n", aconn->name);
        printf("    host \"%s\";\n", aconn->host);
        printf("    apasswd \"%s\";\n", aconn->apasswd);
        printf("    cpasswd \"%s\";\n", aconn->cpasswd);
        if(aconn->port > 0)
            printf("    port %d;\n", aconn->port);
        if(aconn->source && aconn->source != "")
            printf("    source \"%s\";\n", aconn->source);
        if(aconn->flags != 0)
            printf("    flags ");
        if(aconn->flags & CONN_ZIP)
            printf("Z");
        if(aconn->flags & CONN_DKEY)
            printf("E");
        if(aconn->flags & CONN_HUB)
            printf("H");
        if(aconn->flags != 0)
            printf(";\n");
        printf("    class \"%s\";\n", aconn->class->name);
        printf("};\n\n");
    }
    if (uservers[0])
    {
        int i;
        printf("/* Superservers */\n\n");
        printf("superservers (\n");
        for (i = 0; uservers[i]; ++i)
        {
            if (i != 0) printf(";\n");
            printf("    %s", uservers[i]);
        }
        printf("\n);\n\n");
    }
    printf("/* port configurations */\n\n");
    for(aport = ports; aport; aport = aport->next)
    {
        printf("port %d {\n", aport->port);
        if(aport->allow && aport->allow != "")
            printf("    allow \"%s\";\n", aport->allow);
        if(aport->address && aport->address != "")
            printf("    bind \"%s\";\n", aport->address);
        printf("};\n\n");
    }
    printf("/* Quarantines */\n\n");
    for(sban = sbans; sban; sban = sban->next)
    {
        printf("restrict {\n");
        printf("    type ");
        if(sban->type & SBAN_NICK)
            printf("NICK;\n");
        else if(sban->type & SBAN_GCOS)
            printf("GCOS;\n");
        else if(sban->type & SBAN_CHAN)
            printf("CHAN;\n");
        else
        {
            printf("\n\n\nPROBLEM READING QLINE TYPE \n\n");
            exit(-1);
        }
        printf("    mask \"%s\";\n", sban->target);
        printf("    reason \"%s\";\n", sban->reason);
        printf("};\n\n");
    }
    printf("/* kill definitions */\n\n");
    for(hban = hbans; hban; hban = hban->next)
    {
        printf("kill {\n");
        printf("    username \"%s\";\n", hban->username);
        printf("    host \"%s\";\n", hban->target);
        printf("    reason \"%s\";\n", hban->reason);
        printf("};\n\n");
    }
    return;
}
    


int main(int argc, char *argv[])
{
    char *file;
    int   fd;

    if(argc != 2)
    {
        printf("Useage:  ./convert_conf ircd.conf > ircd.conf.new\n");
        exit(0);
    }
    file = argv[1];
    
    if((fd = openconf(file)) == -1)
    {
        printf("Cannot locate file %s\n", file);
        exit(-1);
    }
    (void) initconf(0, fd, 0);
    
    /* so far so good */

    printconf();

    exit(1);
}
