/************************************************************************
 *   IRC - Internet Relay Chat, src/s_bsd.c
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
#include "res.h"
#include "numeric.h"
#include "patchlevel.h"
#include "zlink.h"
#include "throttle.h"
#include "userban.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#if defined(SOL20)
#include <sys/filio.h>
#include <sys/select.h>
#include <unistd.h>
#endif
#include "inet.h"
#include <stdio.h>
#include <signal.h>
#include <fcntl.h>
#include <utmp.h>
#include <sys/resource.h>
#include "hooks.h"

#ifdef  AIX
#include <time.h>
#include <arpa/nameser.h>
#else
#include "nameser.h"
#endif
#include "resolv.h"

/* If FD_ZERO isn't define up to this point,
 * define it (BSD4.2 needs this) */

#include "h.h"
#include "fdlist.h"
#include "fds.h"

extern void      engine_init();
extern fdlist default_fdlist;
extern int forked;
extern void free_port(aPort *);

#ifndef IN_LOOPBACKNET
#define IN_LOOPBACKNET  0x7f
#endif

#if defined(MAXBUFFERS)
int rcvbufmax = 0, sndbufmax = 0;
#endif

#ifdef MAXBUFFERS
void reset_sock_opts(int, int);
#endif

static void set_listener_sock_opts(int, aListener *);
static void set_listener_non_blocking(int, aListener *);
/* listener list, count */
aListener *listen_list = NULL;
int listen_count = 0;


aClient *local[MAXCONNECTIONS];
int highest_fd = 0, resfd = -1;
time_t timeofday;
static struct sockaddr_in mysk;

static struct sockaddr *connect_inet(aConnect *, aClient *, int *);
static int check_init(aClient *, char *);
static void set_sock_opts(int, aClient *);

#if defined(MAXBUFFERS)
static char *readbuf;
#else
static char readbuf[8192];
#endif

/* Silly macro to ignore certain report error statements */
#define silent_report_error(x,y)


/*
 * Try and find the correct name to use with getrlimit() for setting
 * the max. number of files allowed to be open by this process.
 */

#ifdef RLIMIT_FDMAX
#define RLIMIT_FD_MAX   RLIMIT_FDMAX
#else
#ifdef RLIMIT_NOFILE
#define RLIMIT_FD_MAX RLIMIT_NOFILE
#else
#ifdef RLIMIT_OPEN_MAX
#define RLIMIT_FD_MAX RLIMIT_OPEN_MAX
#else
#undef RLIMIT_FD_MAX
#endif
#endif
#endif

/*
 * add_local_domain() 
 * Add the domain to hostname, if it is missing
 * (as suggested by eps@TOASTER.SFSU.EDU)
 */

void add_local_domain(char *hname, int size)
{
#ifdef RES_INIT
    /* try to fix up unqualified name */
    if (!strchr(hname, '.')) 
    {
    if (!(_res.options & RES_INIT))
    {
        Debug((DEBUG_DNS, "res_init()"));
        res_init();
    }
    if (_res.defdname[0])
    {
        (void) strncat(hname, ".", size - 1);
        (void) strncat(hname, _res.defdname, size - 2);
    }
    }
#endif
    return;
}

/*
 * Cannot use perror() within daemon. stderr is closed in 
 * ircd and cannot be used. And, worse yet, it might have 
 * been reassigned to a normal connection...
 */

/*
 * report_error 
 * This a replacement for perror(). Record error to log and 
 * also send a copy to all *LOCAL* opers online. 
 * text    is a *format* string for outputting error. It must
 * contain only two '%s', the first will be replaced by the
 * sockhost from the cptr, and the latter will be taken from 
 * sys_errlist[errno].
 * 
 * cptr, if not NULL, is the *LOCAL* client associated with
 * the error.
 */

void report_error(char *text, aClient * cptr)
{
    int errtmp = errno;     /* debug may change 'errno' */
    char *host;
    int err, len = sizeof(err);
    extern char *strerror();

    host =
    (cptr) ? get_client_name(cptr,
                 (IsServer(cptr) ? HIDEME : FALSE)) : "";

    Debug((DEBUG_ERROR, text, host, strerror(errtmp)));
    /* 
     * Get the *real* error from the socket (well try to anyway..). This
     * may only work when SO_DEBUG is enabled but its worth the gamble
     * anyway.
     */

#ifdef  SO_ERROR
    if (!IsMe(cptr) && cptr->fd >= 0)
    if (!getsockopt(cptr->fd, SOL_SOCKET, SO_ERROR, (char *) &err, &len))
        if (err)
        errtmp = err;
#endif
    sendto_realops_lev(DEBUG_LEV, text, host, strerror(errtmp));
#ifdef USE_SYSLOG
    syslog(LOG_WARNING, text, host, strerror(errtmp));
    if (!forked)
    {
    fprintf(stderr, text, host, strerror(errtmp));
    fprintf(stderr, "\n");
    }
#endif
    return;
}

void report_listener_error(char *text, aListener *lptr)
{
   int errtmp = errno;          /* debug may change 'errno' */
   char *host;
   int err, len = sizeof(err);
   extern char *strerror();

   host = get_listener_name(lptr);

   Debug((DEBUG_ERROR, text, host, strerror(errtmp)));

#ifdef  SO_ERROR
   if (lptr->fd >= 0)
      if (!getsockopt(lptr->fd, SOL_SOCKET, SO_ERROR, (char *) &err, &len))
         if (err)
            errtmp = err;
#endif
   sendto_realops_lev(DEBUG_LEV, text, host, strerror(errtmp));
#ifdef USE_SYSLOG
   syslog(LOG_WARNING, text, host, strerror(errtmp));
#endif
   if (!forked) 
   {
      fprintf(stderr, text, host, strerror(errtmp));
      fprintf(stderr, "\n");
   }
   return;
}

/*
 * open_listeners()
 *
 * cycle through our entire ports list and open them if they
 * arent already open.
 * Added Feb/04 -epi
 */

void
open_listeners()
{
    aPort *tmp;
    aListener *lptr;
    if(!ports)
        sendto_realops("Lost all port configurations!");
    for(tmp = ports; tmp; tmp = tmp->next)
    {
        for(lptr = listen_list; lptr; lptr = lptr->next)
            if(tmp->port == lptr->port)
                break;
        if(lptr)
            continue;
        add_listener(tmp);
    }
    return;
}

/*
 * add_listener
 *
 * Create a new client which is essentially the stub like 'me' to be used
 * for a socket that is passive (listen'ing for connections to be
 * accepted).
 * Backported from defunct 1.6 and updated for aPort structure in Feb04.
 * I'm assuming lucas rewrote this originally. -epi
 */
int add_listener(aPort *aport)
{
   aListener *lptr;
   aListener lstn;
   struct sockaddr_in server;
   int ad[4], len = sizeof(server);
   char ipname[20];

   memset(&lstn, 0, sizeof(aListener));

   strncpyzt(lstn.allow_string, aport->allow, sizeof(lstn.allow_string));
   strncpyzt(lstn.vhost_string, aport->address, sizeof(lstn.vhost_string));

   if ((*aport->address != '\0') && (*aport->address != '*'))
   {
      lstn.vhost_ip.s_addr = inet_addr(aport->address);
      strncpyzt(lstn.vhost_string, aport->address, sizeof(lstn.vhost_string));
   }

   lstn.port = aport->port;

   if(lstn.port == 0) /* stop stupidity cold */
      return -1;

   ad[0] = ad[1] = ad[2] = ad[3] = 0;
   /*
    * do it this way because building ip# from separate values for each
    * byte requires endian knowledge or some nasty messing. Also means
    * easy conversion of "*" 0.0.0.0 or 134.* to 134.0.0.0 :-)
    */
   sscanf(lstn.allow_string, "%d.%d.%d.%d", &ad[0], &ad[1], &ad[2], &ad[3]);
   ircsprintf(ipname, "%d.%d.%d.%d", ad[0], ad[1], ad[2], ad[3]);
   lstn.allow_ip.s_addr = inet_addr(ipname);

   lstn.fd = socket(AF_INET, SOCK_STREAM, 0);
   if (lstn.fd < 0)
   {
      report_listener_error("opening stream socket %s:%s", &lstn);
      return -1;
   }

   set_listener_sock_opts(lstn.fd, &lstn);

   memset(&server, '\0', sizeof(server));
   server.sin_family = AF_INET;

   if (lstn.vhost_ip.s_addr)
      server.sin_addr.s_addr = lstn.vhost_ip.s_addr;
   else
      server.sin_addr.s_addr = INADDR_ANY;

   server.sin_port = htons(lstn.port);

   if (bind(lstn.fd, (struct sockaddr *) &server, sizeof(struct sockaddr_in)))
   {
         report_listener_error("binding stream socket %s:%s", &lstn);
         close(lstn.fd);
         return -1;
   }

   if (getsockname(lstn.fd, (struct sockaddr *) &server, &len)) 
   {
      report_listener_error("getsockname failed for %s:%s", &lstn);
      close(lstn.fd);
      return -1;
   }

   if (lstn.fd > highest_fd)
      highest_fd = lstn.fd;

#ifdef SOMAXCONN
   if(listen(lstn.fd, SOMAXCONN))
#else
   if(listen(lstn.fd, HYBRID_SOMAXCONN))
#endif
   {
        report_listener_error("error listening on FD %s:%s", &lstn);
        close(lstn.fd);
        return -1;
   }


   lptr = (aListener *) MyMalloc(sizeof(aListener));
   memcpy(lptr, &lstn, sizeof(aListener));

   if(local[lptr->fd])
   {
        report_listener_error("!!!! listener fd is held by client"
                  " in local[] array %s:%s", &lstn);
    abort();
   }

   lptr->aport = aport;
   aport->lstn = lptr;

   set_listener_non_blocking(lptr->fd, lptr);
   add_fd(lptr->fd, FDT_LISTENER, lptr);
   set_fd_flags(lptr->fd, FDF_WANTREAD);

   listen_count++;
   lptr->next = listen_list;
   listen_list = lptr;

   lptr->lasttime = timeofday;

   return 0;
}

void close_listener(aListener *lptr)
{
    aListener *alptr, *alptrprev = NULL;
    aPort *aport, *aportl, *aportn = NULL;

    del_fd(lptr->fd);
    close(lptr->fd);

    /* drop our conf link */
    aport = lptr->aport;
    aport->lstn = NULL;

    /* and now drop the conf itself */

    for(aportl = ports ; aportl ; aportl = aportl->next)
    {
        if(aportl == aport)
        {
            if(aportn)
                aportn->next = aportl->next;
            else
                ports = aportl->next;
            free_port(aportl);
            break;
        }
        aportn = aportl;
    }

    /* now drop the listener */

    for(alptr = listen_list; alptr; alptr = alptr->next)
    {
        if(alptr == lptr)
        {
            if(alptrprev)
                alptrprev->next = alptr->next;
            else
                listen_list = alptr->next;
            MyFree(lptr);
            listen_count--;
            break;
        }
        alptrprev = alptr;
    }
}

/*
 * close_listeners
 *
 * Close and free all clients which are marked as having their socket open
 * and in a state where they can accept connections.  Unix sockets have
 * the path to the socket unlinked for cleanliness.
 */
void close_listeners()
{
    aListener *lptr, *lptrnext;

    lptr = listen_list;

    while(lptr)
    {
        lptrnext = lptr->next;
        if(lptr->clients <= 0)
            close_listener(lptr);
        else                
            /* if we cant close it, mark it for closing
             * when we loose all of our connections */
            lptr->aport->legal = -1;
        lptr = lptrnext;
    }
}

/* init_sys */
void init_sys()
{
    int fd;

#ifdef RLIMIT_FD_MAX
    struct rlimit limit;

    if (!getrlimit(RLIMIT_FD_MAX, &limit))
    {
        if (limit.rlim_max < MAXCONNECTIONS)
        {
            printf("ircd fd table too big\n");
            printf("Hard Limit: %ld IRC max: %d\n",
                    (long) limit.rlim_max, MAXCONNECTIONS);
            printf("Fix MAXCONNECTIONS\n");
            printf("Aborting...\n");
            exit(-1);
        }
        limit.rlim_cur = limit.rlim_max;    /* make soft limit the max */
        if (setrlimit(RLIMIT_FD_MAX, &limit) == -1)
        {
            printf("error setting max fd's to %ld\n",
                (long) limit.rlim_cur);
            printf("Aborting...\n");
            exit(-1);
        }
#ifdef USE_SELECT
        if (MAXCONNECTIONS > FD_SETSIZE)
        {
            printf("FD_SETSIZE = %d MAXCONNECTIONS = %d\n",
                    FD_SETSIZE, MAXCONNECTIONS);
            printf("Make sure your kernel supports a larger "
                    "FD_SETSIZE then recompile with -DFD_SETSIZE=%d\n",
                    MAXCONNECTIONS);
            printf("Aborting...\n");
            exit(-1);
        }
#endif
    }
#endif

    printf("\nIrcd is now becoming a daemon.\n");

#if !defined(SOL20)
    (void) setlinebuf(stderr);
#endif

    for (fd = 3; fd < MAXCONNECTIONS; fd++)
    {
        (void) close(fd);
        local[fd] = NULL;
    }
    local[1] = NULL;

    if (bootopt & BOOT_TTY)
    {
        engine_init();

        /* debugging is going to a tty */
        resfd = init_resolver(0x1f);
        add_fd(resfd, FDT_RESOLVER, NULL);
        set_fd_flags(resfd, FDF_WANTREAD);
        return;
    }

    close(1);

    if (!(bootopt & BOOT_DEBUG) && !(bootopt & BOOT_STDERR))
        close(2);


    if ((isatty(0)) && !(bootopt & BOOT_OPER) && !(bootopt & BOOT_STDERR))
    {
        int pid;

        if ((pid = fork()) < 0)
        {
            if ((fd = open("/dev/tty", O_RDWR)) >= 0)
            write(fd, "Couldn't fork!\n", 15);  /* crude, but effective */
            exit(0);
        } 
        else if (pid > 0)
            exit(0);

        setsid();

        close(0);       /* fd 0 opened by inetd */
        local[0] = NULL;
    }

    engine_init();
    resfd = init_resolver(0x1f);
    add_fd(resfd, FDT_RESOLVER, NULL);
    set_fd_flags(resfd, FDF_WANTREAD);
    return;
}

void write_pidfile()
{
#ifdef IRCD_PIDFILE
    int fd;
    char buff[20];

    if ((fd = open(IRCD_PIDFILE, O_CREAT | O_WRONLY, 0600)) >= 0)
    {
    (void) ircsprintf(buff, "%5d\n", (int) getpid());
    if (write(fd, buff, strlen(buff)) == -1)
        Debug((DEBUG_NOTICE, "Error writing to pid file %s",
           IRCD_PIDFILE));
    (void) close(fd);
    return;
    }
#ifdef  DEBUGMODE
    else
    Debug((DEBUG_NOTICE, "Error opening pid file %s", IRCD_PIDFILE));
#endif
#endif
}

/*
 * Initialize the various name strings used to store hostnames. This is
 * set from either the server's sockhost (if client fd is a tty or
 * localhost) or from the ip# converted into a string. 0 = success, -1
 * = fail.
 */
static int check_init(aClient * cptr, char *sockn)
{
    struct sockaddr_in sk;
    int len = sizeof(struct sockaddr_in);

    /* If descriptor is a tty, special checking... * IT can't EVER be a tty */

    if (getpeername(cptr->fd, (struct sockaddr *) &sk, &len) == -1)
    {
    /*
     * This fills syslog, if on, and is just annoying.
     * Nobody needs it. -lucas
     *    report_error("connect failure: %s %s", cptr);
     */
    return -1;
    }
    (void) strcpy(sockn, (char *) inetntoa((char *) &sk.sin_addr));
    if (inet_netof(sk.sin_addr) == IN_LOOPBACKNET)
    {
    cptr->hostp = NULL;
    strncpyzt(sockn, me.sockhost, HOSTLEN);
    }
    memcpy((char *) &cptr->ip, (char *) &sk.sin_addr, sizeof(struct in_addr));
    
    cptr->port = (int) (ntohs(sk.sin_port));

    return 0;
}

/*
 * Ordinary client access check. Look for conf lines which have the
 * same status as the flags passed. 0 = Success -1 = Access denied -2 =
 * Bad socket.
 */
int check_client(aClient *cptr)
{
    static char sockname[HOSTLEN + 1];
    struct hostent *hp = NULL;
    int i;

    Debug((DEBUG_DNS, "ch_cl: check access for %s[%s]",
       cptr->name, inetntoa((char *) &cptr->ip)));

    if (check_init(cptr, sockname))
        return -2;

    hp = cptr->hostp;
    /* 
     * Verify that the host to ip mapping is correct both ways and that
     * the ip#(s) for the socket is listed for the host.
     */
    if (hp)
    {
        for (i = 0; hp->h_addr_list[i]; i++)
            if (!memcmp(hp->h_addr_list[i], (char *) &cptr->ip,
                    sizeof(struct in_addr))) 
                break;

        if (!hp->h_addr_list[i])
        {
            sendto_one(cptr, "NOTICE AUTH :*** Your forward and reverse"
                             " DNS do not match, ignoring hostname.");
            hp = NULL;
        }
    }

    if ((i = attach_Iline(cptr, hp, sockname)))
    {
        Debug((DEBUG_DNS, "ch_cl: access denied: %s[%s]",
                cptr->name, sockname));
        return i;
    }

    Debug((DEBUG_DNS, "ch_cl: access ok: %s[%s]", cptr->name, sockname));

    if (inet_netof(cptr->ip) == IN_LOOPBACKNET ||
    inet_netof(cptr->ip) == inet_netof(mysk.sin_addr))
    {
        ircstp->is_loc++;
        cptr->flags |= FLAGS_LOCAL;
    }
    return 0;
}

#define CFLAG   CONF_CONNECT_SERVER
#define NFLAG   CONF_NOCONNECT_SERVER

/*
 * check_server_init(), check_server() check access for a server given
 * its name (passed in cptr struct). Must check for all C/N lines which
 * have a name which matches the name given and a host which matches. A
 * host alias which is the same as the server name is also acceptable
 * in the host field of a C/N line. 0 = Success -1 = Access denied -2 =
 * Bad socket.
 *
 * This was terrible code.  Terrible!  Almost fucking scary! Rewritten into
 * a single function, much prettier.  Feb04 -epi
 */
int check_server_init(aClient * cptr)
{
    aConnect *aconn = NULL;
    struct hostent *hp = NULL;
    char sockname[HOSTLEN + 1], fullname[HOSTLEN + 1];
    char abuff[HOSTLEN + USERLEN + 2];
    int i = 0, ok = 0;

    if (check_init(cptr, sockname))
        return -2;

    if (!(aconn = find_aConnect(cptr->name)))
    {
        Debug((DEBUG_DNS, "No C/N lines for %s", name));
        return -1;
    }

    /* 
     * * If the servername is a hostname, either an alias (CNAME) or
     * real name, then check with it as the host. Use gethostbyname()
     * to check for servername as hostname.
     */
    if (!cptr->hostp)
    {
        char *s;
        Link lin;

        /* 
         * * Do a lookup for the CONF line *only* and not the server
         * connection else we get stuck in a nasty state since it
         * takes a SERVER message to get us here and we cant
         * interrupt that very well.
         */
        lin.value.aconn = aconn;
        lin.flags = ASYNC_CONF;
        nextdnscheck = 1;
        if ((s = strchr(aconn->host, '@')))
            s++;
        else
            s = aconn->host;
        Debug((DEBUG_DNS, "sv_ci:cache lookup (%s)", s));
        if((hp = gethost_byname(s, &lin)))
        {
            for (i = 0; hp->h_addr_list[i]; i++)
                if (!memcmp(hp->h_addr_list[i], (char *) &cptr->ip, 
                        sizeof(struct in_addr)))
                    break;
            if (!hp->h_addr_list[i])
            {
                sendto_realops_lev(DEBUG_LEV,
                    "Server IP# Mismatch: %s != %s[%08x]",
                    inetntoa((char *) &cptr->ip), hp->h_name,
                    *((unsigned long *) hp->h_addr));
                hp = NULL;
            }
        }
    }
    else
    {
        hp = cptr->hostp;
        for (i = 0; hp->h_addr_list[i]; i++)
            if (!memcmp(hp->h_addr_list[i], (char *) &cptr->ip,
                    sizeof(struct in_addr)))
                break;
    }

    if(hp)
    {
        strncpyzt(fullname, cptr->name, sizeof(fullname));
        add_local_domain(fullname, HOSTLEN - strlen(fullname));
        Debug((DEBUG_DNS, "sv_cl: gethostbyaddr: %s->%s",
                sockname, fullname));
        (void) ircsprintf(abuff, "%s@%s", cptr->username, fullname);
        get_sockhost(cptr, fullname);
        for (i = 0; hp->h_addr_list[i]; i++)
        {
            if(!memcmp((char *) &aconn->ipnum, (char *) hp->h_addr_list[i],
                        sizeof(struct in_addr)))
                ok = 1;
            else
                ok = 0;
        }
    }
    else
    {
        /* having no luck finding a host.. check against IP */
        if(!memcmp((char *) &aconn->ipnum, (char *) &cptr->ip,
                   sizeof(struct in_addr)))
            ok = 1;
        else
            ok = 0;
    }

    /* if they dont match up, then away with them */
    if (!ok)
    {
        get_sockhost(cptr, sockname);
        return -1;
    }
    /* check for Ulined access and link it if nessecary */
    if(find_aUserver(cptr->name))
        cptr->flags |= FLAGS_ULINE;
    (void) make_server(cptr);
    cptr->serv->aconn = aconn;
    aconn->class->links++;
    aconn->acpt = cptr;
    set_effective_class(cptr);

    if ((aconn->ipnum.s_addr == -1))
    memcpy((char *) &aconn->ipnum, (char *) &cptr->ip,
           sizeof(struct in_addr));

    get_sockhost(cptr, aconn->host);
    
    Debug((DEBUG_DNS, "sv_cl: access ok: %s[%s]", name, cptr->sockhost));
    return 0;
}

/*
 * completed_connection 
 * Complete non-blocking
 * connect()-sequence. Check access and *       terminate connection,
 * if trouble detected. *
 *
 *      Return  TRUE, if successfully completed *               FALSE,
 * if failed and ClientExit
 */
int completed_connection(aClient * cptr)
{
    aConnect *aconn;

    if(!(cptr->flags & FLAGS_BLOCKED))
       unset_fd_flags(cptr->fd, FDF_WANTWRITE);
    unset_fd_flags(cptr->fd, FDF_WANTREAD);

    SetHandshake(cptr);

    if (!(aconn = find_aConnect(cptr->name)))
    {
    sendto_realops("Lost Config for %s", get_client_name(cptr, HIDEME));
    return -1;
    }
    if (!BadPtr(aconn->cpasswd))
    sendto_one(cptr, "PASS %s :TS", aconn->cpasswd);

    /* pass on our capabilities to the server we /connect'd */
#ifdef HAVE_ENCRYPTION_ON
    if(!(aconn->flags & CONN_DKEY))
        sendto_one(cptr, "CAPAB SSJOIN NOQUIT BURST UNCONNECT ZIP"
                         " NICKIP TSMODE");
    else
    {
        sendto_one(cptr, "CAPAB SSJOIN NOQUIT BURST UNCONNECT DKEY"
                         " ZIP NICKIP TSMODE");
        cptr->capabilities |= CAPAB_DODKEY;
    }
#else
    sendto_one(cptr, "CAPAB SSJOIN NOQUIT BURST UNCONNECT ZIP NICKIP TSMODE");
#endif

    if(aconn->flags & CONN_ZIP)
        cptr->capabilities |= CAPAB_DOZIP;

    sendto_one(cptr, "SERVER %s 1 :%s",
           my_name_for_link(me.name, aconn), me.info);
#ifdef DO_IDENTD
    /* Is this the right place to do this?  dunno... -Taner */
    if (!IsDead(cptr))
    start_auth(cptr);
#endif

    check_client_fd(cptr);
    return (IsDead(cptr)) ? -1 : 0;
}

/*
 * close_connection *
 * Close the physical connection. This function must make 
 * MyConnect(cptr) == FALSE, and set cptr->from == NULL.
 */
void close_connection(aClient *cptr)
{
    aConnect *aconn;

    if (IsServer(cptr))
    {
        ircstp->is_sv++;
        ircstp->is_sbs += cptr->sendB;
        ircstp->is_sbr += cptr->receiveB;
        ircstp->is_sks += cptr->sendK;
        ircstp->is_skr += cptr->receiveK;
        ircstp->is_sti += timeofday - cptr->firsttime;
        if (ircstp->is_sbs > 2047)
        {
            ircstp->is_sks += (ircstp->is_sbs >> 10);
            ircstp->is_sbs &= 0x3ff;
        }
        if (ircstp->is_sbr > 2047)
        {
            ircstp->is_skr += (ircstp->is_sbr >> 10);
            ircstp->is_sbr &= 0x3ff;
        }
        /* schedule a quick reconnect if we've been connected a long time */
        if((aconn = find_aConnect_match(cptr->name, cptr->username,
                                    cptr->sockhost)))
        {
            aconn->hold = time(NULL);
            aconn->hold += (aconn->hold - cptr->since > HANGONGOODLINK) ?
                HANGONRETRYDELAY : aconn->class->connfreq;
            if (nextconnect > aconn->hold)
                nextconnect = aconn->hold;
        }
    } 
    else if (IsClient(cptr))
    {
        ircstp->is_cl++;
        ircstp->is_cbs += cptr->sendB;
        ircstp->is_cbr += cptr->receiveB;
        ircstp->is_cks += cptr->sendK;
        ircstp->is_ckr += cptr->receiveK;
        ircstp->is_cti += timeofday - cptr->firsttime;
        if (ircstp->is_cbs > 2047)
        {
            ircstp->is_cks += (ircstp->is_cbs >> 10);
            ircstp->is_cbs &= 0x3ff;
        }
        if (ircstp->is_cbr > 2047)
        {
            ircstp->is_ckr += (ircstp->is_cbr >> 10);
            ircstp->is_cbr &= 0x3ff;
        }
    } 
    else
        ircstp->is_ni++;

    /* remove outstanding DNS queries. */
    del_queries((char *) cptr);

    if (cptr->authfd >= 0)
    {
        del_fd(cptr->authfd);
        close(cptr->authfd);
        cptr->authfd = -1;
    }

    if (cptr->fd >= 0)
    {
        dump_connections(cptr->fd);
        local[cptr->fd] = NULL;
        del_fd(cptr->fd);
        close(cptr->fd);
        cptr->fd = -2;
        SBufClear(&cptr->sendQ);
        SBufClear(&cptr->recvQ);
        memset(cptr->passwd, '\0', sizeof(cptr->passwd));
        if(cptr->lstn)
            cptr->lstn->clients--;
    }
    for (; highest_fd > 0; highest_fd--)
    if (local[highest_fd])
        break;

    clear_conflinks(cptr);

    cptr->from = NULL;      /* ...this should catch them! >:) --msa */

    /* if we're the last socket open on this listener,
     * check to make sure the listener is even supposed to be
     * open, and close it if its not -epi
     */
     if (cptr->lstn && (cptr->lstn->clients <= 0) && 
                (cptr->lstn->aport->legal == -1))
        close_listener(cptr->lstn);

    return;
}

#ifdef MAXBUFFERS

/* reset_sock_opts type =  0 = client, 1 = server */
void reset_sock_opts(int fd, int type)
{
#define CLIENT_BUFFER_SIZE  4096
#define SEND_BUF_SIZE       2048
    int opt;

    opt = type ? rcvbufmax : CLIENT_BUFFER_SIZE;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *) &opt, sizeof(opt)) < 0) 
    sendto_realops("REsetsockopt(SO_RCVBUF) for fd %d (%s) failed",
               fd, type ? "server" : "client");
    opt = type ? sndbufmax : SEND_BUF_SIZE;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char *) &opt, sizeof(opt)) < 0) 
    sendto_realops("REsetsockopt(SO_SNDBUF) for fd %d (%s) failed",
               fd, type ? "server" : "client");
}

#endif              /* MAXBUFFERS */

/* set_sock_opts */
static void set_sock_opts(int fd, aClient * cptr)
{
    int opt;
    
#ifdef SO_REUSEADDR
    opt = 1;
    if (setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, (char *) &opt,
            sizeof(opt)) < 0)
    silent_report_error("setsockopt(SO_REUSEADDR) %s:%s", cptr);
#endif
#if  defined(SO_DEBUG) && defined(DEBUGMODE) && 0
    /* Solaris with SO_DEBUG writes to syslog by default */
#if !defined(SOL20) || defined(USE_SYSLOG)
    opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_DEBUG, (char *) &opt, sizeof(opt)) < 0)
    silent_report_error("setsockopt(SO_DEBUG) %s:%s", cptr);
#endif              /* SOL20 */
#endif
#ifdef  SO_USELOOPBACK
    opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_USELOOPBACK, (char *) &opt,
           sizeof(opt)) < 0)
    silent_report_error("setsockopt(SO_USELOOPBACK) %s:%s", cptr);
#endif
#ifdef  SO_RCVBUF
#if defined(MAXBUFFERS)
    if (rcvbufmax == 0)
    {
    int optlen;

    optlen = sizeof(rcvbufmax);
    getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *) &rcvbufmax, &optlen);
    while ((rcvbufmax < 16385) &&
           (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, 
               (char *) (char *) &rcvbufmax,optlen) >= 0))
        rcvbufmax += 1024;
    getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *) &rcvbufmax, &optlen);
    readbuf = (char *) malloc(rcvbufmax * sizeof(char));
    }
    if (IsServer(cptr))
    opt = rcvbufmax;
    else
    opt = 4096;
#else
    opt = 8192;
#endif
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *) &opt, sizeof(opt)) < 0)
    silent_report_error("setsockopt(SO_RCVBUF) %s:%s", cptr);
#endif
#ifdef  SO_SNDBUF
#if defined(MAXBUFFERS)
    if (sndbufmax == 0)
    {
    int optlen;
    
    optlen = sizeof(sndbufmax);
    getsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char *) &sndbufmax, &optlen);
    while ((sndbufmax < 16385) && (setsockopt (fd, SOL_SOCKET, SO_SNDBUF,
                           (char *) &sndbufmax,
                           optlen) >= 0))
        sndbufmax += 1024;
    getsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char *) &sndbufmax, &optlen);
    }
    if (IsServer(cptr))
    opt = sndbufmax;
    else
    opt = 4096;
#else
    opt = 8192;
#endif
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char *) &opt, sizeof(opt)) < 0)
    silent_report_error("setsockopt(SO_SNDBUF) %s:%s", cptr);
#endif
#if defined(IP_OPTIONS) && defined(IPPROTO_IP)
    {
#if defined(MAXBUFFERS)
    char *s = readbuf, *t = readbuf + (rcvbufmax * sizeof(char)) / 2;
    opt = (rcvbufmax * sizeof(char)) / 8;
#else
    char *s = readbuf, *t = readbuf + sizeof(readbuf) / 2;
    
    opt = sizeof(readbuf) / 8;
#endif
    if (getsockopt(fd, IPPROTO_IP, IP_OPTIONS, t, &opt) < 0)
        silent_report_error("getsockopt(IP_OPTIONS) %s:%s", cptr);
    else if (opt > 0)
    {
        for (*readbuf = '\0'; opt > 0; opt--, s += 3)
        (void) ircsprintf(s, "%02.2x:", *t++);
        *s = '\0';
        sendto_realops("Connection %s using IP opts: (%s)",
               get_client_name(cptr, HIDEME), readbuf);
    }
    if (setsockopt(fd, IPPROTO_IP, IP_OPTIONS, (char *) NULL, 0) < 0)
        silent_report_error("setsockopt(IP_OPTIONS) %s:%s", cptr);
    }
#endif
}

static void set_listener_sock_opts(int fd, aListener *lptr)
{
   int opt;

#ifdef SO_REUSEADDR
   opt = 1;
   if (setsockopt
       (fd, SOL_SOCKET, SO_REUSEADDR, (char *) &opt, sizeof(opt)) < 0)
      report_listener_error("setsockopt(SO_REUSEADDR) %s:%s", lptr);
#endif
#if  defined(SO_DEBUG) && defined(DEBUGMODE) && 0
   /*
    * Solaris with SO_DEBUG writes to syslog by default
    */
# if !defined(SOL20) || defined(USE_SYSLOG)
   opt = 1;
   if (setsockopt(fd, SOL_SOCKET, SO_DEBUG, (char *) &opt, sizeof(opt)) <
       0) report_listener_error("setsockopt(SO_DEBUG) %s:%s", lptr);
# endif                         /*
                                 * SOL20
                                 */
#endif
#ifdef  SO_USELOOPBACK
   opt = 1;
   if (setsockopt
       (fd, SOL_SOCKET, SO_USELOOPBACK, (char *) &opt, sizeof(opt)) < 0)
      report_listener_error("setsockopt(SO_USELOOPBACK) %s:%s", lptr);
#endif
#ifdef  SO_RCVBUF
# if defined(MAXBUFFERS)
   if (rcvbufmax == 0) {
      int optlen;

      optlen = sizeof(rcvbufmax);
      getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *) &rcvbufmax, &optlen);
      while ((rcvbufmax < 16385)
             &&
             (setsockopt
              (fd, SOL_SOCKET, SO_RCVBUF, (char *) (char *) &rcvbufmax,
               optlen) >= 0)) rcvbufmax += 1024;
      getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *) &rcvbufmax, &optlen);
      readbuf = (char *) malloc(rcvbufmax * sizeof(char));
   }
   opt = 4096;
# else
   opt = 8192;
# endif
   if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *) &opt, sizeof(opt)) <
       0) report_listener_error("setsockopt(SO_RCVBUF) %s:%s", lptr);
#endif
#ifdef  SO_SNDBUF
# if defined(MAXBUFFERS)
   if (sndbufmax == 0) {
      int optlen;

      optlen = sizeof(sndbufmax);
      getsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char *) &sndbufmax, &optlen);
      while ((sndbufmax < 16385)
             &&
             (setsockopt
              (fd, SOL_SOCKET, SO_SNDBUF, (char *) &sndbufmax,
               optlen) >= 0)) sndbufmax += 1024;
      getsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char *) &sndbufmax, &optlen);
   }
   opt = 4096;
# else
   opt = 8192;
# endif
   if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char *) &opt, sizeof(opt)) <
       0) report_listener_error("setsockopt(SO_SNDBUF) %s:%s", lptr);
#endif
}


int get_sockerr(aClient * cptr)
{
    int errtmp = errno, err = 0, len = sizeof(err);
    
#ifdef  SO_ERROR
    if (cptr->fd >= 0)
    if (!getsockopt(cptr->fd, SOL_SOCKET, SO_ERROR, (char *) &err, &len))
        if (err)
        errtmp = err;
#endif
    return errtmp;
}

char *irc_get_sockerr(aClient *cptr)
{
    if(cptr->sockerr == 0)
    return "No error";
    
    if(cptr->sockerr > 0)
    return strerror(cptr->sockerr);
    
    switch(cptr->sockerr)
    { 
    case -1: /* this is the default */
    return "Unset error message [this is a bug!]";
    case IRCERR_BUFALLOC:
    return "dbuf allocation error";
    case IRCERR_ZIP:
    return "compression general failure";
    default:
    return "Unknown error!";
    }
    
    /* unreachable code, but the compiler is complaining.. */
    return NULL;
}

/*
 * * set_non_blocking *       Set the client connection into non-blocking
 * mode. If your *      system doesn't support this, you can make this
 * a dummy *    function (and get all the old problems that plagued the *
 * blocking version of IRC--not a problem if you are a *        lightly
 * loaded node...)
 */
void set_non_blocking(int fd, aClient * cptr)
{
    int res, nonb = 0;

    nonb |= O_NONBLOCK;
    if ((res = fcntl(fd, F_GETFL, 0)) == -1)
    silent_report_error("fcntl(fd, F_GETFL) failed for %s:%s", cptr);
    else if (fcntl(fd, F_SETFL, res | nonb) == -1)
    silent_report_error("fcntl(fd, F_SETL, nonb) failed for %s:%s", cptr);
    return;
}

void set_listener_non_blocking(int fd, aListener *lptr)
{
   int res, nonb = 0;

   nonb |= O_NONBLOCK;
   if ((res = fcntl(fd, F_GETFL, 0)) == -1)
      report_listener_error("fcntl(fd, F_GETFL) failed for %s:%s", lptr);
   else if (fcntl(fd, F_SETFL, res | nonb) == -1)
      report_listener_error("fcntl(fd, F_SETL, nonb) failed for %s:%s", lptr);
   return;
}


/*
 * Creates a client which has just connected to us on the given fd. The
 * sockhost field is initialized with the ip# of the host. The client
 * is added to the linked list of clients but isnt added to any hash
 * tables yuet since it doesnt have a name.
 */
aClient *add_connection(aListener *lptr, int fd)
{
    Link lin;
    aClient *acptr = NULL;
    char *s, *t;
    struct sockaddr_in addr;
    int len = sizeof(struct sockaddr_in);
    struct userBan *ban;
    
    if (getpeername(fd, (struct sockaddr *) &addr, &len) == -1)
    { 
    ircstp->is_ref++;
    close(fd);
    return NULL;
    }

    acptr = make_client(NULL, &me);

    /* 
     * Copy ascii address to 'sockhost' just in case. Then we have
     * something valid to put into error messages...
     */
    get_sockhost(acptr, (char *) inetntoa((char *) &addr.sin_addr));
    memcpy((char *) &acptr->ip, (char *) &addr.sin_addr,
    sizeof(struct in_addr));
    
    acptr->port = ntohs(addr.sin_port);
    /* 
     * Check that this socket (client) is allowed to accept
     * connections from this IP#.
     */
    for (s = (char *) &lptr->allow_ip, t = (char *) &acptr->ip, len = 4;
     len > 0; len--, s++, t++)
    {
    if (!*s)
        continue;
    if (*s != *t)
        break;
    }

    if (len)
    {
    ircstp->is_ref++;
    acptr->fd = -2;
    free_client(acptr);
    close(fd);
    return NULL;
    }

    lptr->ccount++;
    lptr->clients++;
    add_fd(fd, FDT_CLIENT, acptr);
    local[fd] = acptr;

    acptr->fd = fd;
    if (fd > highest_fd)
    highest_fd = fd;

    /* sockets inherit the options of their parents.. do we need these? */
    set_non_blocking(acptr->fd, acptr);
    set_sock_opts(acptr->fd, acptr);

    acptr->lstn = lptr;
    add_client_to_list(acptr);

    ban = check_userbanned(acptr, UBAN_IP|UBAN_CIDR4|UBAN_WILDUSER, 0);
    if(ban)
    {
    char *reason, *ktype;
    int local;

    local = (ban->flags & UBAN_LOCAL) ? 1 : 0;
    ktype = local ? LOCAL_BANNED_NAME : NETWORK_BANNED_NAME;
    reason = ban->reason ? ban->reason : ktype;

    sendto_one(acptr, err_str(ERR_YOUREBANNEDCREEP), me.name, "*", ktype);
    sendto_one(acptr, ":%s NOTICE * :*** You are not welcome on this %s.",
           me.name, local ? "server" : "network");
    sendto_one(acptr, ":%s NOTICE * :*** %s for %s", 
           me.name, ktype, reason);
    sendto_one(acptr, ":%s NOTICE * :*** Your IP is %s",
           me.name, inetntoa((char *)&acptr->ip.s_addr));
    sendto_one(acptr, ":%s NOTICE * :*** For assistance, please email %s and "
           "include everything shown here.", me.name, 
           local ? Local_Kline_Address : Network_Kline_Address);

    ircstp->is_ref++;
    ircstp->is_ref_1++;
    throttle_force(inetntoa((char *)&acptr->ip.s_addr));
    exit_client(acptr, acptr, &me, reason);

    return NULL;
    }

    if(call_hooks(CHOOK_PREACCESS, acptr) == FLUSH_BUFFER)
       return NULL;

#ifdef SHOW_HEADERS
    sendto_one(acptr, REPORT_DO_DNS);
#endif
    lin.flags = ASYNC_CLIENT;
    lin.value.cptr = acptr;
    Debug((DEBUG_DNS, "lookup %s", inetntoa((char *) &addr.sin_addr)));
    acptr->hostp = gethost_byaddr((char *) &acptr->ip, &lin);
    if (!acptr->hostp)
    SetDNS(acptr);
#ifdef SHOW_HEADERS
    else
    sendto_one(acptr, REPORT_FIN_DNSC);
#endif
    nextdnscheck = 1;
    
#ifdef DO_IDENTD
    start_auth(acptr);
#endif
    check_client_fd(acptr);
    return acptr;
}

/* handle taking care of the client's recvq here */
int do_client_queue(aClient *cptr)
{
    int dolen = 0, done;
    
    while (SBufLength(&cptr->recvQ) && !NoNewLine(cptr) &&
       ((cptr->status < STAT_UNKNOWN) || (cptr->since - timeofday < 10) ||
        IsNegoServer(cptr))) 
    {
    /* If it's become registered as a server, just parse the whole block */
    if (IsServer(cptr) || IsNegoServer(cptr)) 
    {
#if defined(MAXBUFFERS)
        dolen = sbuf_get(&cptr->recvQ, readbuf, rcvbufmax * sizeof(char));
#else
        dolen = sbuf_get(&cptr->recvQ, readbuf, sizeof(readbuf));
#endif
        if (dolen <= 0)
        break;
        if ((done = dopacket(cptr, readbuf, dolen)))
        return done;
        break;
    }
    
#if defined(MAXBUFFERS)
    dolen = sbuf_getmsg(&cptr->recvQ, readbuf, rcvbufmax * sizeof(char));
#else
    dolen = sbuf_getmsg(&cptr->recvQ, readbuf, sizeof(readbuf));
#endif
    
    if (dolen <= 0) 
    {
        if (dolen < 0)
        return exit_client(cptr, cptr, cptr, "sbuf_getmsg fail");
        
        if (SBufLength(&cptr->recvQ) < 510) 
        {
        cptr->flags |= FLAGS_NONL;
        break;
        }
        /* The buffer is full (more than 512 bytes) and it has no \n
         * Some user is trying to trick us. Kill their recvq. */
        SBufClear(&cptr->recvQ);
        break;
    }
    else if(client_dopacket(cptr, readbuf, dolen) == FLUSH_BUFFER)
        return FLUSH_BUFFER;
    }

    if(!(cptr->flags & FLAGS_HAVERECVQ) && SBufLength(&cptr->recvQ) && !NoNewLine(cptr))
    {
       add_to_list(&recvq_clients, cptr);
       cptr->flags |= FLAGS_HAVERECVQ;
    }

    return 1;
}

/*
 * read_packet
 *
 * Read a 'packet' of data from a connection and process it.  Read in 8k 
 * chunks to give a better performance rating (for server connections). 
 * Do some tricky stuff for client connections to make sure they don't
 * do any flooding >:-) -avalon
 */

#define MAX_CLIENT_RECVQ 8192

int read_packet(aClient * cptr)
{
    int length = 0, done;

    /* If data is ready, and the user is either not a person or
     * is a person and has a recvq of less than MAX_CLIENT_RECVQ,
     * read from this client
     */ 
    if (!(IsPerson(cptr) && SBufLength(&cptr->recvQ) > MAX_CLIENT_RECVQ)) 
    {
    errno = 0;
    
#if defined(MAXBUFFERS)
    if (IsPerson(cptr))
        length = recv(cptr->fd, readbuf, 8192 * sizeof(char), 0);
    else
        length = recv(cptr->fd, readbuf, rcvbufmax * sizeof(char), 0);
#else
    length = recv(cptr->fd, readbuf, sizeof(readbuf), 0);
#endif

    cptr->lasttime = timeofday;
    if (cptr->lasttime > cptr->since)
        cptr->since = cptr->lasttime;
    cptr->flags &= ~(FLAGS_PINGSENT | FLAGS_NONL);
    /* If not ready, fake it so it isnt closed */
    if (length == -1 && ((errno == EWOULDBLOCK) || (errno == EAGAIN)))
        return 1;
    if (length <= 0)
    {
        cptr->sockerr = length ? errno : 0;
        return length;
    }
    }

    /* 
     * For server connections, we process as many as we can without
     * worrying about the time of day or anything :)
     */
    if (IsServer(cptr) || IsConnecting(cptr) || IsHandshake(cptr) ||
    IsNegoServer(cptr)) 
    {
    if (length > 0)
        if ((done = dopacket(cptr, readbuf, length)))
        return done;
    } 
    else 
    {
    /* 
     * Before we even think of parsing what we just read, stick 
     * it on the end of the receive queue and do it when its turn
     * comes around. */
    if (sbuf_put(&cptr->recvQ, readbuf, length) < 0)
        return exit_client(cptr, cptr, cptr, "sbuf_put fail");
    
    if (IsPerson(cptr) &&
#ifdef NO_OPER_FLOOD
        !IsAnOper(cptr) &&
#endif
        SBufLength(&cptr->recvQ) > CLIENT_FLOOD)
    {
        sendto_realops_lev(FLOOD_LEV,
                   "Flood -- %s!%s@%s (%d) Exceeds %d RecvQ",
                   cptr->name[0] ? cptr->name : "*",
                   cptr->user ? cptr->user->username : "*",
                   cptr->user ? cptr->user->host : "*",
                   SBufLength(&cptr->recvQ), CLIENT_FLOOD);
        return exit_client(cptr, cptr, cptr, "Excess Flood");
    }
    return do_client_queue(cptr);
    }
    return 1;
}

void read_error_exit(aClient *cptr, int length, int err)
{
    char fbuf[512];
    char errmsg[512];
    
    if (IsServer(cptr) || IsHandshake(cptr) || IsConnecting(cptr)) 
    {
    if (length == 0) 
    {
        char *errtxt = "Server %s closed the connection";
        
        ircsprintf(fbuf, "from %s: %s", me.name, errtxt);
        sendto_gnotice(fbuf, get_client_name(cptr, HIDEME));
        ircsprintf(fbuf, ":%s GNOTICE :%s", me.name, errtxt);
        sendto_serv_butone(cptr, fbuf, get_client_name(cptr, HIDEME));
    }
    else 
    {
        char *errtxt = (IsConnecting(cptr) || IsHandshake(cptr)) ? 
        "Connect error to %s (%s)" : 
        "Read error from %s, closing link (%s)";

        ircsprintf(fbuf, "from %s: %s", me.name, errtxt);
        sendto_gnotice(fbuf, get_client_name(cptr, HIDEME), strerror(err));
        ircsprintf(fbuf, ":%s GNOTICE :%s", me.name, errtxt);
        sendto_serv_butone(cptr, fbuf, 
                   get_client_name(cptr, HIDEME), strerror(err));
    }
    }
    
    if (err)
    ircsprintf(errmsg, "Read error: %s", strerror(err));
    else
    ircsprintf(errmsg, "Client closed connection");
    
    exit_client(cptr, cptr, &me, errmsg);
}

void accept_connection(aListener *lptr)
{
    static struct sockaddr_in addr;
    int addrlen = sizeof(struct sockaddr_in);
    char host[HOSTLEN + 2];
    int newfd;
    int i;
    
    lptr->lasttime = timeofday;
    
    for (i = 0; i < 100; i++) /* accept up to 100 times per call to deal with high connect rates */
    {
        if((newfd = accept(lptr->fd, (struct sockaddr *) &addr, &addrlen)) < 0) 
        {
        switch(errno)
        {
#ifdef EMFILE
           case EMFILE:
              report_listener_error("Cannot accept connections %s:%s", lptr);
              break;
#endif
#ifdef ENFILE
           case ENFILE:
              report_listener_error("Cannot accept connections %s:%s", lptr);
              break;
#endif
        }

        return;
        }

        strncpyzt(host, (char *) inetntoa((char *) &addr.sin_addr), sizeof(host));

        /* if they are throttled, drop them silently. */
        if (throttle_check(host, newfd, NOW) == 0) {
           ircstp->is_ref++;
           ircstp->is_throt++;
           close(newfd);
           return;
        }

        if (newfd >= HARD_FDLIMIT - 10) 
        {
            ircstp->is_ref++;
            sendto_realops_lev(CCONN_LEV,"All connections in use. fd: %d (%s)",
                newfd,get_listener_name(lptr));
            send(newfd, "ERROR :All connections in use\r\n", 32, 0);
            close(newfd);
            return;
        }
        if((lptr->aport->legal == -1))
        {
            ircstp->is_ref++;
            send(newfd, "ERROR :This port is closed\r\n", 29, 0);
            close(newfd);
            return;
        }
        ircstp->is_ac++;

        add_connection(lptr, newfd);
#ifdef PINGNAZI
        nextping = timeofday;
#endif
    }
}

int readwrite_client(aClient *cptr, int isread, int iswrite)
{
   /*
    * NOTE
    * We now do this in a more logical way.
    * We request a write poll on a socket for two reasons
    * - the socket is waiting for a connect() call
    * - the socket is blocked
    */

   if(iswrite)
   {
      if (IsConnecting(cptr) && completed_connection(cptr))
      {
         char errmsg[512];

         ircsprintf(errmsg, "Connect Error: %s", irc_get_sockerr(cptr));
         return exit_client(cptr, cptr, &me, errmsg);
      }

      if(cptr->flags & FLAGS_BLOCKED)
      {
         cptr->flags &= ~FLAGS_BLOCKED;
         unset_fd_flags(cptr->fd, FDF_WANTWRITE);
      }
   }

   if (isread)
   {
      int length = read_packet(cptr);

      if(length == FLUSH_BUFFER)
         return length;

      if(length <= 0)
      {
         read_error_exit(cptr, length, cptr->sockerr);
         return FLUSH_BUFFER;
      }
   }

   if (IsDead(cptr))
   {
      char errmsg[512];

      ircsprintf(errmsg, "Write Error: %s",
                 (cptr->flags & FLAGS_SENDQEX) ?
                 "SendQ Exceeded" : irc_get_sockerr(cptr));
      return exit_client(cptr, cptr, &me, errmsg);
   }

   return 1;
}

/* connect_server */
int connect_server(aConnect *aconn, aClient * by, struct hostent *hp)
{
    struct sockaddr *svp;
    aClient *cptr, *c2ptr;
    char *s;
    int errtmp, len;

    Debug((DEBUG_NOTICE, "Connect to %s[%s] @%s",
       aconn->name, aconn->host, inetntoa((char *) &aconn->ipnum)));
    
    if ((c2ptr = find_server(aconn->name, NULL)))
    {
    sendto_ops("Server %s already present from %s",
           aconn->name, get_client_name(c2ptr, HIDEME));
    if (by && IsPerson(by) && !MyClient(by))
        sendto_one(by,
               ":%s NOTICE %s :Server %s already present from %s",
               me.name, by->name, aconn->name,
               get_client_name(c2ptr, HIDEME));
    return -1;
    }
    /* 
     * If we dont know the IP# for this host and itis a hostname and not
     * a ip# string, then try and find the appropriate host record.
     */
    if ((!aconn->ipnum.s_addr))
    {
    Link lin;

    lin.flags = ASYNC_CONNECT;
    lin.value.aconn = aconn;
    nextdnscheck = 1;
    s = (char *) strchr(aconn->host, '@');
    s++;            /* should NEVER be NULL */
    if ((aconn->ipnum.s_addr = inet_addr(s)) == -1) 
    {
        aconn->ipnum.s_addr = 0;
        hp = gethost_byname(s, &lin);
        Debug((DEBUG_NOTICE, "co_sv: hp %x ac %x na %s ho %s",
           hp, aconn, aconn->name, s));
        if (!hp)
        return 0;
        memcpy((char *) &aconn->ipnum, hp->h_addr, sizeof(struct in_addr));
    }
    }
    cptr = make_client(NULL, &me);
    cptr->hostp = hp;
    /* Copy these in so we have something for error detection. */
    strncpyzt(cptr->name, aconn->name, sizeof(cptr->name));
    strncpyzt(cptr->sockhost, aconn->host, HOSTLEN + 1);
    svp = connect_inet(aconn, cptr, &len);

    if (!svp)
    {
    if (cptr->fd >= 0)
        close(cptr->fd);
    cptr->fd = -2;
    free_client(cptr);
    return -1;
    }
    
    set_non_blocking(cptr->fd, cptr);
    set_sock_opts(cptr->fd, cptr);
    signal(SIGALRM, dummy);
    if (connect(cptr->fd, svp, len) < 0 && errno != EINPROGRESS) 
    {
    errtmp = errno;     /* other system calls may eat errno */
    report_error("Connect to host %s failed: %s", cptr);
    if (by && IsPerson(by) && !MyClient(by))
        sendto_one(by, ":%s NOTICE %s :Connect to server %s failed.",
               me.name, by->name, cptr->name);
    close(cptr->fd);
    cptr->fd = -2;
    free_client(cptr);
    errno = errtmp;
    if (errno == EINTR)
        errno = ETIMEDOUT;
    return -1;
    }
    
    (void) make_server(cptr);
    cptr->serv->aconn = aconn;
    
    /* The socket has been connected or connect is in progress. */
    if (by && IsPerson(by))
    {
    strcpy(cptr->serv->bynick, by->name);
    strcpy(cptr->serv->byuser, by->user->username);
    strcpy(cptr->serv->byhost, by->user->host);
    }
    else
    {
    strcpy(cptr->serv->bynick, "AutoConn.");
    *cptr->serv->byuser = '\0';
    *cptr->serv->byhost = '\0';
    }
    cptr->serv->up = me.name;
    if (cptr->fd > highest_fd)
    highest_fd = cptr->fd;
    local[cptr->fd] = cptr;
    SetConnecting(cptr);

    get_sockhost(cptr, aconn->host);
    add_client_to_list(cptr);
#ifdef PINGNAZI
    nextping = timeofday;
#endif

    add_fd(cptr->fd, FDT_CLIENT, cptr);
    set_fd_flags(cptr->fd, FDF_WANTREAD|FDF_WANTWRITE);

    return 0;
}

static struct sockaddr *
connect_inet(aConnect *aconn, aClient *cptr, int *lenp)
{
    static struct sockaddr_in server;
    struct hostent *hp;
    struct sockaddr_in sin;
    
    /* 
     * Might as well get sockhost from here, the connection is attempted
     * with it so if it fails its useless.
     */
    cptr->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (cptr->fd >= (HARD_FDLIMIT - 10))
    {
        sendto_realops("No more connections allowed (%s)", cptr->name);
        return NULL;
    }
    memset((char *) &server, '\0', sizeof(server));
    memset((char *) &sin, '\0', sizeof(sin));
    server.sin_family = sin.sin_family = AF_INET;
    get_sockhost(cptr, aconn->host);

    if (aconn->source)
        sin.sin_addr.s_addr = inet_addr(aconn->source);

    if (cptr->fd < 0)
    {
        report_error("opening stream socket to server %s:%s", cptr);
        cptr->fd = -2;
        return NULL;
    }
    /* 
     * Bind to a local IP# (with unknown port - let unix decide) so *
     * we have some chance of knowing the IP# that gets used for a host *
     * with more than one IP#.
     * 
     * No we don't bind it, not all OS's can handle connecting with an
     * already bound socket, different ip# might occur anyway leading to
     * a freezing select() on this side for some time.
     */
    if (aconn->source)
    {
    /* 
     * * No, we do bind it if we have virtual host support. If we
     * don't explicitly bind it, it will default to IN_ADDR_ANY and
     * we lose due to the other server not allowing our base IP
     * --smg
     */
        if (bind(cptr->fd, (struct sockaddr *) &sin, sizeof(sin)) == -1)
        {
            report_error("error binding to local port for %s:%s", cptr);
            close(cptr->fd);
            return NULL;
        }
    }
    /* 
     * By this point we should know the IP# of the host listed in the
     * conf line, whether as a result of the hostname lookup or the ip#
     * being present instead. If we dont know it, then the connect
     * fails.
     */
    if (isdigit(*aconn->host) && (aconn->ipnum.s_addr == -1))
        aconn->ipnum.s_addr = inet_addr(aconn->host);
    if (aconn->ipnum.s_addr == -1)
    {
        hp = cptr->hostp;
        if (!hp)
        {
            Debug((DEBUG_FATAL, "%s: unknown host", aconn->host));
            return NULL;
        }
        memcpy((char *) &aconn->ipnum, hp->h_addr, sizeof(struct in_addr));
    }
    memcpy((char *) &server.sin_addr, (char *) &aconn->ipnum, 
            sizeof(struct in_addr));
    
    memcpy((char *) &cptr->ip, (char *) &aconn->ipnum,
            sizeof(struct in_addr));

    server.sin_port = htons((aconn->port > 0) ? aconn->port : PORTNUM);
    *lenp = sizeof(server);
    return (struct sockaddr *) &server;
}

/*
 * find the real hostname for the host running the server (or one
 * which matches the server's name) and its primary IP#.  Hostname is
 * stored in the client structure passed as a pointer.
 */
void get_my_name(aClient * cptr, char *name, int len)
{
    static char tmp[HOSTLEN + 1];
    struct hostent *hp;

    /* 
     * The following conflicts with both AIX and linux prototypes oh
     * well, we can put up with the errors from other systems -Dianora
     */

    char *cname = cptr->name;
    
    /* Setup local socket structure to use for binding to. */
    memset((char *) &mysk, '\0', sizeof(mysk));
    mysk.sin_family = AF_INET;

    if (gethostname(name, len) == -1)
    return;
    name[len] = '\0';
    
    /* assume that a name containing '.' is a FQDN */
    if (!strchr(name, '.'))
    add_local_domain(name, len - strlen(name));
    /* 
     * If hostname gives another name than cname, then check if there
     * is a CNAME record for cname pointing to hostname. If so accept
     * cname as our name.   meLazy
     */
    if (BadPtr(cname))
    return;
    if ((hp = gethostbyname(cname)) || (hp = gethostbyname(name)))
    {
    char *hname;
    int i = 0;
    
    for (hname = hp->h_name; hname; hname = hp->h_aliases[i++])
    {
        strncpyzt(tmp, hname, sizeof(tmp));
        add_local_domain(tmp, sizeof(tmp) - strlen(tmp));
        /* 
         * Copy the matching name over and store the 'primary' IP#
         * as 'myip' which is used later for making the right one is
         * used for connecting to other hosts.
         */
        if (!mycmp(me.name, tmp))
        break;
    }
    if (mycmp(me.name, tmp))
        strncpyzt(name, hp->h_name, len);
    else
        strncpyzt(name, tmp, len);
    memcpy((char *) &mysk.sin_addr, hp->h_addr, sizeof(struct in_addr));

    Debug((DEBUG_DEBUG, "local name is %s", get_client_name(&me, TRUE)));
    }
    return;
}

/*
 * do_dns_async
 *
 * Called when the fd returned from init_resolver() has been selected for
 * reading.
 */
void do_dns_async()
{
    static Link ln;
    aClient *cptr;
    aConnect *aconn;
    struct hostent *hp;
    int bytes, packets = 0;

    do
    {
    ln.flags = -1;
    hp = get_res((char *) &ln);
    Debug((DEBUG_DNS, "%#x = get_res(%d,%#x)",
           hp, ln.flags, ln.value.cptr));

    switch (ln.flags)
    {
    case ASYNC_NONE:
        /* 
         * no reply was processed that was outstanding or had
         * a client still waiting.
         */
        break;
    case ASYNC_CLIENT:
        if ((cptr = ln.value.cptr))
        {
        del_queries((char *) cptr);
#ifdef SHOW_HEADERS
        sendto_one(cptr, REPORT_FIN_DNS);
#endif
        ClearDNS(cptr);
        cptr->hostp = hp;
        check_client_fd(cptr);
        }
        break;
    case ASYNC_CONNECT:
        aconn = ln.value.aconn;
        if (hp && aconn)
        {
        memcpy((char *) &aconn->ipnum, hp->h_addr,
               sizeof(struct in_addr));
        
        (void) connect_server(aconn, NULL, hp);
        } 
        else
        sendto_ops("Connect to %s failed: host lookup",
               (aconn) ? aconn->host : "unknown");
        break;
    case ASYNC_CONF:
        aconn = ln.value.aconn;
        if (hp && aconn)
        memcpy((char *) &aconn->ipnum, hp->h_addr,
               sizeof(struct in_addr));

        break;
    default:
        break;
    }
    if (ioctl(resfd, FIONREAD, &bytes) == -1)
        bytes = 0;
    packets++;
    }
    while ((bytes > 0) && (packets < 512));
}
