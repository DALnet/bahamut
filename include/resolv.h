#ifndef LOCAL_RESOLV_H
#define LOCAL_RESOLV_H 1

/*
 * Copyright (c) 1983, 1987, 1989 The Regents of the University of
 * California. All rights reserved.
 * 
 * Redistribution and use in source and binary forms are permitted
 * provided that: (1) source distributions retain this entire copyright
 * notice and comment, and (2) distributions including binaries display
 * the following acknowledgement:  ``This product includes software
 * developed by the University of California, Berkeley and its
 * contributors'' in the documentation or other materials provided with
 * the distribution and in all advertising materials mentioning
 * features or use of this software. Neither the name of the University
 * nor the names of its contributors may be used to endorse or promote
 * products derived from this software without specific prior written
 * permission. THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE.
 * 
 * @(#)resolv.h 5.10.1 (Berkeley) 6/1/90
 */
/*
 * Resolver configuration file. Normally not present, but may contain
 * the address of the inital name server(s) to query and the domain
 * search list.
 */

#ifndef	_PATH_RESCONF
#define _PATH_RESCONF        "/etc/resolv.conf"
#endif
/* Global defines and variables for resolver stub. */
#define	MAXNS		3	/* max # name servers we'll track */
#define	MAXDFLSRCH	3	/* # default domain levels to try */
#define	MAXDNSRCH	6	/* max # domains in search path */
#define	LOCALDOMAINPARTS 2	/* min levels in name that is "local" */
#define MAXSERVICES	2	/* max # of services to search */

#define	RES_TIMEOUT	5	/* min. seconds between retries */

#define RES_SERVICE_NONE	0
#define RES_SERVICE_BIND	1
#define RES_SERVICE_LOCAL	2
/* Resolver options */
#define RES_INIT	0x0001	/* address initialized */
#define RES_DEBUG	0x0002	/* print debug messages */
#define RES_AAONLY	0x0004	/* authoritative answers only */
#define RES_USEVC	0x0008	/* use virtual circuit */
#define RES_PRIMARY	0x0010	/* query primary server only */
#define RES_IGNTC	0x0020	/* ignore trucation errors */
#define RES_RECURSE	0x0040	/* recursion desired */
#define RES_DEFNAMES	0x0080	/* use default domain name */
#define RES_STAYOPEN	0x0100	/* Keep TCP socket open */
#define RES_DNSRCH	0x0200	/* search up local domain tree */

#define RES_DEFAULT	(RES_RECURSE | RES_DEFNAMES | RES_DNSRCH)

#if ((__GNU_LIBRARY__ == 6) && (__GLIBC__ >= 2) && (__GLIBC_MINOR__ >= 3)) || defined(__UCLIBC__)
# define MAXRESOLVSORT		10	/* number of net to sort on */

struct __res_state {
	int	retrans;	 	/* retransmition time interval */
	int	retry;			/* number of times to retransmit */
	u_long	options;		/* option flags - see below. */
	int	nscount;		/* number of name servers */
	struct sockaddr_in
		nsaddr_list[MAXNS];	/* address of name server */
# define nsaddr	nsaddr_list[0]		/* for backward compatibility */
	u_short	id;			/* current message id */
	char	*dnsrch[MAXDNSRCH+1];	/* components of domain to search */
	char	defdname[256];		/* default domain (deprecated) */
	u_long	pfcode;			/* RES_PRF_ flags - see below. */
	unsigned ndots:4;		/* threshold for initial abs. query */
	unsigned nsort:4;		/* number of elements in sort_list[] */
	char	unused[3];
	struct {
		struct in_addr	addr;
		u_int32_t	mask;
	} sort_list[MAXRESOLVSORT];
};

typedef struct __res_state *res_state;

extern struct __res_state *__res_state(void) __attribute__ ((__const__));
#define _res (*__res_state())

#else

struct state {
    int         retrans;		/* retransmition time interval */
    int         retry;		        /* number of times to retransmit */
    long        options;		/* option flags - see below. */
    int         nscount;		/* number of name servers */
    struct sockaddr_in nsaddr_list[MAXNS];	/* address of name server */
#define	nsaddr	nsaddr_list[0]	        /* for backward compatibility */
    unsigned short id;		        /* current packet id */
    char        defdname[MAXDNAME];	/* default domain */
    char       *dnsrch[MAXDNSRCH + 1];	/* components of domain to search */
    unsigned short order[MAXSERVICES + 1];	/* search service order */
};

extern struct state _res;
#endif

extern char *p_cdname(), *p_rr(), *p_type(), *p_class(), *p_time();

#if ((__GNU_LIBRARY__ == 6) && (__GLIBC__ >=2) && (__GLIBC_MINOR__ >= 2))
#define res_init __res_init
#define res_mkquery __res_mkquery
#define dn_expand __dn_expand
#endif

extern int  res_mkquery ();
extern int  dn_expand ();
extern int  res_init();
#endif
