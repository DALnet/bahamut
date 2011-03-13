/*
 * irc2.7.2/ircd/res.h (C)opyright 1992 Darren Reed.
 */

#ifndef	__res_include__
#define	__res_include__

#define	RES_INITLIST	1
#define	RES_CALLINIT	2
#define RES_INITSOCK	4
#define RES_INITDEBG	8
#define RES_INITCACH    16

#define MAXPACKET	1024
#define IRC_MAXALIASES	10
#define IRC_MAXADDRS	10

#define	AR_TTL		600	 /* TTL in seconds for dns cache entries */

struct res_in_addr
{
    char buf[16];
};

struct hent 
{
    char       *h_name;		    /* official name of host */
    char       *h_aliases[IRC_MAXALIASES];	/* alias list */
    int         h_addrtype;	    /* host address type */
    int         h_length;	    /* length of address */
    
    /* list of addresses from name server */
    struct res_in_addr h_addr_list[IRC_MAXADDRS];
    
#define	h_addr	h_addr_list[0]	    /* address, for backward compatiblity */
};

typedef struct reslist 
{
    int         id;
    int         sent;			/* number of requests sent */
    int         srch;
    time_t      ttl;
    char        type;
    char        retries;		/* retry counter */
    char        sends;			/* number of sends (>1 means resent) */
    char        resend;			/* send flag. 0 == dont resend */
    time_t      sentat;
    time_t      timeout;
    union
    {
	struct in_addr addr4;
    } addr;
    char       *name;
    Link        cinfo;
    struct hent he;
    int         has_rev;                /* is he_rev valid? */
    struct hent he_rev;

    struct reslist *next;
    struct reslist *id_hashnext;
    struct reslist *cp_hashnext;
} ResRQ;

typedef struct cache 
{
    time_t      expireat;
    time_t      ttl;
    struct hostent he;
    struct cache *hname_next, *hnum_next, *list_next;
} aCache;

typedef struct cachetable 
{
    aCache     *num_list;
    aCache     *name_list;
} CacheTable;

typedef struct reshash
{
    ResRQ *id_list;
    ResRQ *cp_list;
} ResHash;

#define ARES_CACSIZE	8192
#define ARES_IDCACSIZE  8192

#define	IRC_MAXCACHED	281

#endif /* __res_include__ */
