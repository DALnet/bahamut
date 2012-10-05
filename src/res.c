/*
 * src/res.c (C)opyright 1992 Darren Reed. All rights reserved. This
 * file may not be distributed without the author's permission in any
 * shape or form. The author takes no responsibility for any damage or
 * loss of property which results from the use of this software.
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "res.h"
#include "numeric.h"
#include "h.h"
#include "fds.h"
#include "memcount.h"

#include <signal.h>
#include <sys/time.h>
#include <sys/socket.h>
#include "nameser.h"
#include "resolv.h"
#include "inet.h"

/* ALLOW_CACHE_NAMES
 *
 * If enabled, this allows our resolver code to keep a hash table
 * of names, for which we find in gethost_byname calls.
 * This presents a few problems with anti-spoofing code.
 *
 * Since the majority of our host lookups are reverse, having
 * a cached record for reverse records (addresses) seems useful.
 * If, for some reason, you want this on, you may define it.
 */
#undef ALLOW_CACHE_NAMES

/* SEARCH_CACHE_ADDRESSES
 *
 * All of our records will probably only have one valid IP address.
 * If you want to search for multiple addresses, define this.
 * (In the current implementation, it should not really be possible
 * to get multiple addresses.)
 *
 * If not, it saves CPU as a cache miss does not traverse the
 * entire cache tree for a result.
 */
#undef SEARCH_CACHE_ADDRESSES

#define PROCANSWER_STRANGE   -2 /* invalid answer or query, try again */
#define PROCANSWER_MALICIOUS -3 /* obviously malicious reply, \
				                 * don't do DNS on this ip. */

#undef	DEBUG			/* because theres alot of debug code in here */

#define TYPE_SIZE  2
#define CLASS_SIZE 2
#define TTL_SIZE   4
#define DLEN_SIZE  2

#define RES_HOSTLEN 127 /* big enough to handle addresses in in6.arpa */

extern int  dn_expand(char *, char *, char *, char *, int);
extern int  dn_skipname(char *, char *);
extern int
res_mkquery(int, char *, int, int, char *, int,
	    struct rrec *, char *, int);

#ifndef AIX
extern int  errno, h_errno;
#endif
extern int  highest_fd;
extern aClient *local[];

static char hostbuf[RES_HOSTLEN + 1];
static int  incache = 0;
static CacheTable hashtable[ARES_CACSIZE];
static ResHash idcphashtable[ARES_IDCACSIZE];
aCache *cachetop = NULL;
static ResRQ *last, *first;

static void rem_cache(aCache *);
static void rem_request(ResRQ *);
static int  do_query_name(Link *, char *, ResRQ *, int);
static int  do_query_number(Link *, struct in_addr *, ResRQ *);
static int  do_query_number6(Link *, struct in6_addr *, ResRQ *);
static void resend_query(ResRQ *);
static int  proc_answer(ResRQ *, HEADER *, char *, char *);
static int  query_name(char *, int, int, ResRQ *);
static aCache *make_cache(ResRQ *);
static aCache *find_cache_name(char *);
static aCache *find_cache_number(ResRQ *, char *, int);
static int  add_request(ResRQ *);
static ResRQ *make_request(Link *, int);
static int  send_res_msg(char *, int, int);
static ResRQ *find_id(int);
static int  hash_number(unsigned char *, int);
static unsigned int hash_id(unsigned int);
static unsigned int hash_cp(char *);
static void update_list(ResRQ *, aCache *);
#ifdef ALLOW_CACHE_NAMES
static int  hash_name(char *);
#endif
static struct hostent *getres_err(ResRQ *, char *);

static struct cacheinfo
{
    int         ca_adds;
    int         ca_dels;
    int         ca_expires;
    int         ca_lookups;
    int         ca_na_hits;
    int         ca_nu_hits;
    int         ca_updates;
} cainfo;

static struct resinfo
{
    int         re_errors;
    int         re_nu_look;
    int         re_na_look;
    int         re_replies;
    int         re_requests;
    int         re_resends;
    int         re_sent;
    int         re_timeouts;
    int         re_shortttl;
    int         re_unkrep;
} reinfo;

static struct res_in_addr res_zeroaddr;

static const char *resntoa(char *ip, int family)
{
    if (family == AF_INET)
	return inetntoa(ip);
    else
	return "<unknown addrtype>";
}

int init_resolver(int op)
{
    int         ret = 0;
    
#ifdef	LRAND48
    srand48(timeofday);
#endif
    if (op & RES_INITLIST)
    {
	memset((char *) &reinfo, '\0', sizeof(reinfo));
	first = last = NULL;
    }
    if (op & RES_CALLINIT)
    {
	ret = res_init();
	if (!_res.nscount)
	{
	    _res.nscount = 1;
	    _res.nsaddr_list[0].sin_addr.s_addr = inet_addr("127.0.0.1");
	}
    }
    
    if (op & RES_INITSOCK)
    {
	int         on = 0;
	
	ret = resfd = socket(AF_INET, SOCK_DGRAM, 0);
	(void) setsockopt(ret, SOL_SOCKET, SO_BROADCAST,
			  (char *) &on, sizeof(on));
    }
#ifdef DEBUG
    if (op & RES_INITDEBG);
    _res.options |= RES_DEBUG;
#endif
    if (op & RES_INITCACH)
    {
	memset((char *) &cainfo, '\0', sizeof(cainfo));
	memset((char *) hashtable, '\0', sizeof(hashtable));
	memset((char *) idcphashtable, '\0', sizeof(idcphashtable));
    }
    if (op == 0)
	ret = resfd;
    return ret;
}

static int add_request(ResRQ * new)
{
    if (!new)
	return -1;
    if (!first)
	first = last = new;
    else {
	last->next = new;
	last = new;
    }
    new->next = NULL;
    reinfo.re_requests++;
    return 0;
}

static void rem_request_id(ResRQ *req)
{
   unsigned int hv = hash_id(req->id);
   ResRQ *rptr, *r2ptr = NULL;

   for(rptr = idcphashtable[hv].id_list; rptr; r2ptr = rptr, rptr = rptr->id_hashnext)
   {
      if(rptr != req)
         continue;

      if(r2ptr != NULL)
         r2ptr->id_hashnext = req->id_hashnext;
      else
         idcphashtable[hv].id_list = req->id_hashnext;
      break;
   }
}

static void add_request_id(ResRQ *req)
{
   unsigned int hv = hash_id(req->id);

   req->id_hashnext = idcphashtable[hv].id_list;
   idcphashtable[hv].id_list = req;
}

static ResRQ *find_request_id(int id)
{
   unsigned int hv = hash_id(id);
   ResRQ *res = idcphashtable[hv].id_list;
   
   while(res)
   {
      if(res->id == id)
         return res;
      res = res->id_hashnext;
   }
   return NULL;
}

static void rem_request_cp(ResRQ *req)
{
   unsigned int hv = hash_cp(req->cinfo.value.cp);
   ResRQ *rptr, *r2ptr = NULL;

   for(rptr = idcphashtable[hv].cp_list; rptr; r2ptr = rptr, rptr = rptr->cp_hashnext)
   {
      if(rptr != req)
         continue;

      if(r2ptr != NULL)
         r2ptr->cp_hashnext = req->cp_hashnext;
      else
         idcphashtable[hv].cp_list = req->cp_hashnext;
      break;
   }
}

static void add_request_cp(ResRQ *req)
{
   unsigned int hv = hash_cp(req->cinfo.value.cp);

   req->cp_hashnext = idcphashtable[hv].cp_list;
   idcphashtable[hv].cp_list = req;
}

static ResRQ *find_request_cp(char *cp)
{
   unsigned int hv = hash_cp(cp);
   ResRQ *res = idcphashtable[hv].cp_list;
   
   while(res)
   {
      if(res->cinfo.value.cp == cp)
         return res;
      res = res->cp_hashnext;
   }
   return NULL;
}

/*
 * remove a request from the list. This must also free any memory that
 * has been allocated for temporary storage of DNS results.
 */
static void rem_request(ResRQ * old)
{
    ResRQ **rptr, *r2ptr = NULL;
    int     i;
    char   *s;
    
    if (!old)
	return;

    if(old->id != -1)
    {
        rem_request_id(old);
        old->id = -1;
    }

    if(old->cinfo.value.cp != NULL)
       rem_request_cp(old);

    for (rptr = &first; *rptr; r2ptr = *rptr, rptr = &(*rptr)->next)
	if (*rptr == old)
	{
	    *rptr = old->next;
	    if (last == old)
		last = r2ptr;
	    break;
	}
#ifdef	DEBUG
    Debug((DEBUG_INFO, "rem_request:Remove %#x at %#x %#x",
	   old, *rptr, r2ptr));
#endif
    r2ptr = old;
    
    if (r2ptr->he.h_name)
	MyFree(r2ptr->he.h_name);
    for (i = 0; i < IRC_MAXALIASES; i++)
	if ((s = r2ptr->he.h_aliases[i]))
	    MyFree(s);
    
    if (r2ptr->he_rev.h_name)
	MyFree(r2ptr->he_rev.h_name);
    for (i = 0; i < IRC_MAXALIASES; i++)
	if ((s = r2ptr->he_rev.h_aliases[i]))
	    MyFree(s);
    
    if (r2ptr->name)
	MyFree(r2ptr->name);
    MyFree(r2ptr);

    return;
}

/* Create a DNS request record for the server. */
static ResRQ *make_request(Link *lp, int family)
{
    ResRQ  *nreq;
    
    nreq = (ResRQ *) MyMalloc(sizeof(ResRQ));
    memset((char *) nreq, '\0', sizeof(ResRQ));
    nreq->next = NULL;		/*  where NULL is non-zero */
    nreq->sentat = timeofday;
    nreq->retries = 3;
    nreq->resend = 1;
    nreq->srch = -1;
    nreq->id = -1;
    if (lp)
    {
	memcpy((char *) &nreq->cinfo, (char *) lp, sizeof(Link));
        add_request_cp(nreq);
    }
    else
	memset((char *) &nreq->cinfo, '\0', sizeof(Link));
    
    nreq->timeout = 4;		/* start at 4 and exponential inc. */
    nreq->he.h_addrtype = family;
    nreq->he.h_name = NULL;
    nreq->he.h_aliases[0] = NULL;
    (void) add_request(nreq);
    return nreq;
}

/*
 * Remove queries from the list which have been there too long without
 * being resolved.
 */
time_t timeout_query_list(time_t now)
{
    ResRQ  *rptr, *r2ptr;
    time_t  next = 0, tout;
    aClient    *cptr;

    Debug((DEBUG_DNS, "timeout_query_list at %s", myctime(now)));
    for (rptr = first; rptr; rptr = r2ptr)
    {
	r2ptr = rptr->next;
	tout = rptr->sentat + rptr->timeout;
	if (now >= tout)
	{
	    if (--rptr->retries <= 0)
	    {
#ifdef DEBUG
		Debug((DEBUG_ERROR, "timeout %x now %d cptr %x",
		       rptr, now, rptr->cinfo.value.cptr));
#endif
		reinfo.re_timeouts++;
		cptr = rptr->cinfo.value.cptr;
		switch (rptr->cinfo.flags)
		{
		case ASYNC_CLIENT:
#ifdef SHOW_HEADERS
		    sendto_one(cptr, "%s", REPORT_FAIL_DNS);
#endif
		    ClearDNS(cptr);
                    check_client_fd(cptr);
		    break;

		case ASYNC_CONNECT:
		    sendto_ops("Host %s unknown",
			       rptr->name);
		    break;
		}
		rem_request(rptr);
		continue;
	    }
	    else
	    {
		rptr->sentat = now;
		rptr->timeout += rptr->timeout;
		resend_query(rptr);
#ifdef DEBUG
		Debug((DEBUG_INFO, "r %x now %d retry %d c %x",
		       rptr, now, rptr->retries,
		       rptr->cinfo.value.cptr));
#endif
	    }
	}
	if (!next || tout < next)
	    next = tout;
    }
    return (next > now) ? next : (now + AR_TTL);
}

/*
 * del_queries - called by the server to cleanup outstanding queries
 * for which there no longer exist clients or conf lines.
 */
void del_queries(char *cp)
{
    ResRQ  *ret = find_request_cp(cp);

    if(ret)
       rem_request(ret);
}

/*
 * sends msg to all nameservers found in the "_res" structure. This
 * should reflect /etc/resolv.conf. We will get responses which arent
 * needed but is easier than checking to see if nameserver isnt
 * present. Returns number of messages successfully sent to nameservers
 * or -1 if no successful sends.
 */
static int send_res_msg(char *msg, int len, int rcount)
{
    int     i;
    int         sent = 0, max;

    if (!msg)
	return -1;
    
    max = MIN(_res.nscount, rcount);
    if (_res.options & RES_PRIMARY)
	max = 1;
    if (!max)
	max = 1;

    for (i = 0; i < max; i++)
    {
	_res.nsaddr_list[i].sin_family = AF_INET;
	if (sendto(resfd, msg, len, 0,
		   (struct sockaddr *) &(_res.nsaddr_list[i]),
		   sizeof(struct sockaddr)) == len)
	{
	    reinfo.re_sent++;
	    sent++;
	}
	else
	    Debug((DEBUG_ERROR, "s_r_m:sendto: %d on %d",
		   errno, resfd));
    }
    
    return (sent) ? sent : -1;
}

/* find a dns request id (id is determined by dn_mkquery) */
static ResRQ *find_id(int id)
{
    ResRQ  *ret = find_request_id(id);

    return ret;
}

struct hostent *gethost_byname(char *name, Link *lp, int family)
{
    aCache *cp;
    
    if (name == (char *) NULL)
	return ((struct hostent *) NULL);
    
    reinfo.re_na_look++;
    if ((cp = find_cache_name(name)))
	return (struct hostent *) &(cp->he);
    if (!lp)
	return NULL;
    (void) do_query_name(lp, name, NULL, family);
    return ((struct hostent *) NULL);
}

struct hostent *gethost_byaddr(char *addr, Link *lp, int family)
{
    aCache     *cp;

    if (addr == (char *) NULL)
	return ((struct hostent *) NULL);

    reinfo.re_nu_look++;
    if ((cp = find_cache_number(NULL, addr, family)))
	return (struct hostent *) &(cp->he);
    if (!lp)
	return NULL;
    if (family == AF_INET)
	(void) do_query_number(lp, (struct in_addr *) addr, NULL);
    else if (family == AF_INET6)
	(void) do_query_number6(lp, (struct in6_addr *) addr, NULL);
    return ((struct hostent *) NULL);
}

static int do_query_name(Link *lp, char *name, ResRQ * rptr, int family)
{
    char        hname[RES_HOSTLEN + 1];
    int         len;
    
    strncpyzt(hname, name, RES_HOSTLEN);
    len = strlen(hname);
    
    if (rptr && !strchr(hname, '.') && _res.options & RES_DEFNAMES)
    {
	if ((sizeof(hname) - len - 1) >= 2)
	{
	    (void) strncat(hname, ".", sizeof(hname) - len - 1);
	    len++;
	    if ((sizeof(hname) - len - 1) >= 1)
		(void) strncat(hname, _res.defdname, sizeof(hname) - len - 1);
	}
    }
    /*
     * Store the name passed as the one to lookup and generate other
     * host names to pass onto the nameserver(s) for lookups.
     */
    if (!rptr)
    {
	rptr = make_request(lp, family);
	rptr->type = (family == AF_INET6) ? T_AAAA : T_A;
	rptr->name = (char *) MyMalloc(strlen(name) + 1);
	(void) strcpy(rptr->name, name);
    }
    return (query_name(hname, C_IN, (family == AF_INET6) ? T_AAAA : T_A,
		       rptr));
}

/* Use this to do reverse IP# lookups. */
static int do_query_number(Link *lp, struct in_addr *numb, ResRQ * rptr)
{
    char        ipbuf[32];
    u_char *cp;

    cp = (u_char *) &numb->s_addr;
    (void) ircsprintf(ipbuf, "%u.%u.%u.%u.in-addr.arpa.",
		      (u_int) (cp[3]), (u_int) (cp[2]),
		      (u_int) (cp[1]), (u_int) (cp[0]));

    if (!rptr)
    {
	rptr = make_request(lp, AF_INET);
	rptr->type = T_PTR;
	rptr->addr.addr4.s_addr = numb->s_addr;
	memcpy((char *) &rptr->he.h_addr,
	       (char *) &numb->s_addr, sizeof(struct in_addr));
	rptr->he.h_length = sizeof(struct in_addr);
    }
    return (query_name(ipbuf, C_IN, T_PTR, rptr));
}

/* Use this to do reverse IP# lookups for IPv6 addresses. */
static int do_query_number6(Link *lp, struct in6_addr *numb, ResRQ * rptr)
{
    char        ipbuf[RES_HOSTLEN + 1];
    u_char *cp;

    cp = (u_char *) &numb->s6_addr;
    (void)ircsprintf(ipbuf,
		     "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.ip6.arpa.",
		     (u_int) (cp[15] & 0xf), (u_int) (cp[15] >> 4),
		     (u_int) (cp[14] & 0xf), (u_int) (cp[14] >> 4),
		     (u_int) (cp[13] & 0xf), (u_int) (cp[13] >> 4),
		     (u_int) (cp[12] & 0xf), (u_int) (cp[12] >> 4),
		     (u_int) (cp[11] & 0xf), (u_int) (cp[11] >> 4),
		     (u_int) (cp[10] & 0xf), (u_int) (cp[10] >> 4),
		     (u_int) (cp[ 9] & 0xf), (u_int) (cp[ 9] >> 4),
		     (u_int) (cp[ 8] & 0xf), (u_int) (cp[ 8] >> 4),
		     (u_int) (cp[ 7] & 0xf), (u_int) (cp[ 7] >> 4),
		     (u_int) (cp[ 6] & 0xf), (u_int) (cp[ 6] >> 4),
		     (u_int) (cp[ 5] & 0xf), (u_int) (cp[ 5] >> 4),
		     (u_int) (cp[ 4] & 0xf), (u_int) (cp[ 4] >> 4),
		     (u_int) (cp[ 3] & 0xf), (u_int) (cp[ 3] >> 4),
		     (u_int) (cp[ 2] & 0xf), (u_int) (cp[ 2] >> 4),
		     (u_int) (cp[ 1] & 0xf), (u_int) (cp[ 1] >> 4),
		     (u_int) (cp[ 0] & 0xf), (u_int) (cp[ 0] >> 4));

    if (!rptr)
    {
	rptr = make_request(lp, AF_INET6);
	rptr->type = T_PTR;
	memcpy((char *) &rptr->addr.addr6,
	       (char *) &numb->s6_addr, sizeof(struct in6_addr));
	memcpy((char *) &rptr->he.h_addr,
	       (char *) &numb->s6_addr, sizeof(struct in6_addr));
	rptr->he.h_length = sizeof(struct in6_addr);
    }
    return (query_name(ipbuf, C_IN, T_PTR, rptr));
}

/* generate a query based on class, type and name. */
static int query_name(char *name, int class, int type, ResRQ * rptr)
{
    struct timeval tv;
    char        buf[MAXPACKET];
    int         r, s, k = 0;
    HEADER     *hptr;

    memset(buf, '\0', sizeof(buf));
    r = res_mkquery(QUERY, name, class, type, NULL, 0, NULL,
		    buf, sizeof(buf));
    if (r <= 0)
    {
	h_errno = NO_RECOVERY;
	return r;
    }

    if(rptr->id != -1)
        rem_request_id(rptr);

    hptr = (HEADER *) buf;
#ifdef LRAND48
    do
    {
	hptr->id = htons(ntohs(hptr->id) + k + lrand48() & 0xffff);
#else
	(void) gettimeofday(&tv, NULL);
    do
    {
#if 0 /* emacs kludge */
    }
#endif
        hptr->id = htons(ntohs(hptr->id) + k +
			 (u_short) (tv.tv_usec & 0xffff));
#endif /* LRAND48 */
	k++;
    } while (find_id(ntohs(hptr->id)));
    rptr->id = ntohs(hptr->id);
    add_request_id(rptr);
    rptr->sends++;
    s = send_res_msg(buf, r, rptr->sends);
    if (s == -1)
    {
	h_errno = TRY_AGAIN;
	return -1;
    }
    else
	rptr->sent += s;
    return 0;
}
    
static void resend_query(ResRQ * rptr)
{
    if (rptr->resend == 0)
	return;
    reinfo.re_resends++;
    switch (rptr->type)
    {
    case T_PTR:
	if (rptr->he.h_addrtype == AF_INET)
	    (void) do_query_number(NULL, &rptr->addr.addr4, rptr);
	else if (rptr->he.h_addrtype == AF_INET6)
	    (void) do_query_number6(NULL, &rptr->addr.addr6, rptr);
	break;
    case T_A:
	(void) do_query_name(NULL, rptr->name, rptr, AF_INET);
	break;
    case T_AAAA:
	(void) do_query_name(NULL, rptr->name, rptr, AF_INET6);
	break;
    default:
	break;
    }
    return;
}

/* returns 0 on failure, nonzero on success */
int arpa_to_ip(char *arpastring, unsigned int *saddr)
{
    int idx = 0, onum = 0;
    char ipbuf[RES_HOSTLEN + 1];
    char *fragptr[4];
    u_char *ipptr;
         
    strcpy(ipbuf, arpastring);

    /* ipbuf should contain a string in the format of 4.3.2.1.in-addr.arpa */
    
    fragptr[onum++] = ipbuf;

    while(ipbuf[idx])
    {
	if(ipbuf[idx] == '.')
	{
	    ipbuf[idx++] = '\0';
	    if(onum == 4)
		break;
	    fragptr[onum++] = ipbuf + idx;
	}
	else
	    idx++;
    }

    if(onum != 4)
	return 0;

    if(mycmp(ipbuf + idx, "in-addr.arpa"))
	return 0;

    ipptr = (u_char *) saddr;

    ipptr[0] = (u_char) atoi(fragptr[3]);
    ipptr[1] = (u_char) atoi(fragptr[2]);
    ipptr[2] = (u_char) atoi(fragptr[1]);
    ipptr[3] = (u_char) atoi(fragptr[0]);
    return 1;
}

/* returns 0 on failure, nonzero on success */
int arpa6_to_ip(char *arpastring, unsigned char *addr6)
{
    int idx = 0, n = 16;
    unsigned char buf[16];

    while(arpastring[idx])
    {
	u_char c, x;

	c = arpastring[idx];
	if (c >= '0' && c <= '9')
	{
	    x = c - '0';
	    idx++;
	}
	else if (c >= 'a' && c <= 'f')
	{
	    x = (c - 'a') + 10;
	    idx++;
	}
	else if (c >= 'A' && c <= 'F')
	{
	    x = (c - 'A') + 10;
	    idx++;
	}
	else
	    return 0;

	c = arpastring[idx];
	if (c == '.')
	    idx++;
	else
	    return 0;

	c = arpastring[idx];
	if (c >= '0' && c <= '9')
	{
	    x |= (c - '0') << 4;
	    idx++;
	}
	else if (c >= 'a' && c <= 'f')
	{
	    x |= ((c - 'a') + 10) << 4;
	    idx++;
	}
	else if (c >= 'A' && c <= 'F')
	{
	    x |= ((c - 'A') + 10) << 4;
	    idx++;
	}
	else
	    return 0;

	buf[--n] = x;

	c = arpastring[idx];
	if (c == '.')
	    idx++;
	else
	    return 0;

	if (n == 0)
	    break;
    }

    if(n != 0)
	return 0;

    if(mycmp(arpastring + idx, "ip6.arpa"))
	return 0;

    memcpy(addr6, buf, sizeof(struct in6_addr));
    return 1;
}

#undef DNS_ANS_DEBUG_MAX
#undef DNS_ANS_DEBUG

#define MAX_ACCEPTABLE_ANS 10

static char acceptable_answers[MAX_ACCEPTABLE_ANS][RES_HOSTLEN + 1];
static int num_acc_answers = 0;

#define add_acceptable_answer(x) do { \
           if(num_acc_answers < MAX_ACCEPTABLE_ANS) \
           strcpy(acceptable_answers[num_acc_answers++], x); } while (0);
	   
static inline char *is_acceptable_answer(char *h)
{
    int i;

    for (i = 0; i < num_acc_answers; i++) 
    {
	if(mycmp(acceptable_answers[i], h) == 0)
	    return acceptable_answers[i];
    }
    return 0;
}

#ifdef DNS_ANS_DEBUG_MAX
static char dhostbuf[RES_HOSTLEN + 1];
#endif

/* process name server reply. */
static int proc_answer(ResRQ * rptr, HEADER *hptr, char *buf, char *eob)
{
    char   *cp, **alias, *acc;
    struct hent *hp;
    unsigned int dlen, len;
    int class, type, ans = 0, n, origtype = rptr->type;
    int adr = 0;

    num_acc_answers = 0;
    
    cp = buf + sizeof(HEADER);
    hp = (struct hent *) &(rptr->he);

    while (memcmp(&hp->h_addr_list[adr], &res_zeroaddr, hp->h_length) != 0 &&
	   adr < IRC_MAXADDRS)
	adr++;

    alias = hp->h_aliases;
    while (*alias)
	alias++;

    if(hptr->qdcount != 1)
    {
	sendto_realops_lev(DEBUG_LEV,
			   "DNS packet with question count of %d ",
			   hptr->qdcount);
	return -1;
    }

    /*
     * ensure the question we're getting a reply for
     * is a the right question.
     */

    if((n = dn_expand(buf, eob, cp, hostbuf, sizeof(hostbuf))) <= 0)
    {
	/* broken dns packet, toss it out */
	return -1;
    }
    else
    {
	int strangeness = 0;
	char tmphost[RES_HOSTLEN];

	hostbuf[RES_HOSTLEN] = '\0';
	cp += n;
	GETSHORT(type, cp);
	GETSHORT(class, cp);
	if(class != C_IN)
	{
	    sendto_realops_lev(DEBUG_LEV,
			       "Expected DNS packet class C_IN, got %d ",
			       class);
	    strangeness++;
	}

	if(type != rptr->type)
	{
	    sendto_realops_lev(DEBUG_LEV,
			       "Expected DNS packet type %d, got %d ",
			       rptr->type, type);
	    strangeness++;
	}

	if(rptr->type == T_A && rptr->name)
	{
	    strcpy(tmphost, rptr->name);
	}
	else if(rptr->type == T_AAAA && rptr->name)
	{
	    strcpy(tmphost, rptr->name);
	}
	else if(rptr->type == T_PTR)
	{
	    u_char *ipp;

	    if (rptr->he.h_addrtype == AF_INET)
	    {
		ipp = (u_char *) &rptr->addr.addr4.s_addr;
		ircsprintf(tmphost, "%u.%u.%u.%u.in-addr.arpa",
			   (u_int) (ipp[3]), (u_int) (ipp[2]),
			   (u_int) (ipp[1]), (u_int) (ipp[0]));
	    }
	    else if (hp->h_addrtype == AF_INET6)
	    {
		ipp = (u_char *) &rptr->addr.addr6.s6_addr;
		(void)ircsprintf(tmphost,
				 "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.ip6.arpa",
				 (u_int) (ipp[15] & 0xf), (u_int) (ipp[15] >> 4),
				 (u_int) (ipp[14] & 0xf), (u_int) (ipp[14] >> 4),
				 (u_int) (ipp[13] & 0xf), (u_int) (ipp[13] >> 4),
				 (u_int) (ipp[12] & 0xf), (u_int) (ipp[12] >> 4),
				 (u_int) (ipp[11] & 0xf), (u_int) (ipp[11] >> 4),
				 (u_int) (ipp[10] & 0xf), (u_int) (ipp[10] >> 4),
				 (u_int) (ipp[ 9] & 0xf), (u_int) (ipp[ 9] >> 4),
				 (u_int) (ipp[ 8] & 0xf), (u_int) (ipp[ 8] >> 4),
				 (u_int) (ipp[ 7] & 0xf), (u_int) (ipp[ 7] >> 4),
				 (u_int) (ipp[ 6] & 0xf), (u_int) (ipp[ 6] >> 4),
				 (u_int) (ipp[ 5] & 0xf), (u_int) (ipp[ 5] >> 4),
				 (u_int) (ipp[ 4] & 0xf), (u_int) (ipp[ 4] >> 4),
				 (u_int) (ipp[ 3] & 0xf), (u_int) (ipp[ 3] >> 4),
				 (u_int) (ipp[ 2] & 0xf), (u_int) (ipp[ 2] >> 4),
				 (u_int) (ipp[ 1] & 0xf), (u_int) (ipp[ 1] >> 4),
				 (u_int) (ipp[ 0] & 0xf), (u_int) (ipp[ 0] >> 4));
	    }
	    else
		*tmphost = '\0';
	}
	else
	{
	    sendto_realops_lev(DEBUG_LEV,
			       "rptr->type is unknown type %d! "
			       "(rptr->name == %p)",
			       rptr->type, rptr->name);
	    return -1;
	}    

	if(mycmp(tmphost, hostbuf) != 0)
	{
	    sendto_realops_lev(DEBUG_LEV, "Asked question for %s, but got "
			       "reply about question %s (!!!)",
			       tmphost, hostbuf);
	    strangeness++;
	}
	
	if(strangeness)
	    return PROCANSWER_STRANGE;
    }

    /* proccess each answer sent to us blech. */
    while (hptr->ancount-- > 0 && cp && cp < eob) 
    {
	n = dn_expand(buf, eob, cp, hostbuf, sizeof(hostbuf)-1);
	hostbuf[RES_HOSTLEN] = '\0';
	
	if (n <= 0)
	    break;
	cp += n;
	GETSHORT(type, cp);
	GETSHORT(class, cp);
	
	GETLONG(rptr->ttl, cp);
	GETSHORT(dlen, cp);
	
	/* Wait to set rptr->type until we verify this structure */

	len = strlen(hostbuf);
	/* name server never returns with trailing '.' */
	if (!strchr(hostbuf, '.') && (_res.options & RES_DEFNAMES))
	{
	    (void) strcat(hostbuf, ".");
	    len++;
	    if ((len + 2) < sizeof(hostbuf))
	    {
		strncpy(hostbuf, _res.defdname,
			sizeof(hostbuf) - 1 - len);
		hostbuf[RES_HOSTLEN] = '\0';
		len = MIN(len + strlen(_res.defdname),
			  sizeof(hostbuf)) - 1;
	    }
	}
	
#ifdef DNS_ANS_DEBUG_MAX
	strcpy(dhostbuf, hostbuf);
#endif
	
	switch (type)
	{
	case T_A:
	case T_AAAA:
	    if(rptr->name == NULL)
	    {
		sendto_realops_lev(DEBUG_LEV,"Received DNS_A answer, but null "
				   "rptr->name!");
		return PROCANSWER_STRANGE;
	    }
	    if(mycmp(rptr->name, hostbuf) != 0)
	    {
		if(!num_acc_answers || !(acc = is_acceptable_answer(hostbuf)))
		{
#ifdef DNS_ANS_DEBUG
		    sendto_realops_lev(DEBUG_LEV,
				       "Received DNS_A answer for %s, but "
				       "asked question for %s", hostbuf,
				       rptr->name);
#endif
		    return PROCANSWER_STRANGE;
		}
#ifdef DNS_ANS_DEBUG
		sendto_realops_lev(DEBUG_LEV,
				   "DNS_A answer from an acceptable (%s)",
				   acc);
#endif
	    }
	    hp->h_length = dlen;
	    if (ans == 1 && type == T_A)
		hp->h_addrtype = (class == C_IN) ? AF_INET : AF_UNSPEC;
	    else if (ans == 1 && type == T_AAAA)
		hp->h_addrtype = (class == C_IN) ? AF_INET6 : AF_UNSPEC;
	    /* from Christophe Kalt <kalt@stealth.net> */
	    if ((type == T_A && dlen != sizeof(struct in_addr)) ||
		(type == T_AAAA && dlen != sizeof(struct in6_addr)))
	    {
		sendto_realops("Bad IP length (%u) returned for %s",
			       dlen, hostbuf);
		Debug((DEBUG_DNS, "Bad IP length (%d) returned for %s",
		       dlen, hostbuf));
		return PROCANSWER_MALICIOUS;
	    }

	    if(adr < IRC_MAXADDRS)
	    {
		/* ensure we never go over the bounds of our adr array */
		memcpy((char *)&hp->h_addr_list[adr], cp, dlen);
		Debug((DEBUG_INFO, "got ip # %s for %s",
		       resntoa((char *) &hp->h_addr_list[adr],
			       hp->h_addrtype), hostbuf));
		
#ifdef DNS_ANS_DEBUG_MAX
		sendto_realops_lev(DEBUG_LEV, "%s A %s", dhostbuf,
				   resntoa((char *) &hp->h_addr_list[adr],
					   hp->h_addrtype));
#endif
		adr++;
	    }
	    
	    if (!hp->h_name) 
	    {
		hp->h_name = (char *) MyMalloc(len + 1);
		strcpy(hp->h_name, hostbuf);
	    }
	    ans++;
	    cp += dlen;
	    rptr->type = type;
	    break;
	    
	case T_PTR:
	    acc = NULL;
	    if(!num_acc_answers || !(acc = is_acceptable_answer(hostbuf)))
	    {
		union
		{
			struct in_addr addr4;
			struct in6_addr addr6;
		} ptrrep;

		if(arpa6_to_ip(hostbuf, ptrrep.addr6.s6_addr))
		{
		    if(rptr->he.h_addrtype != AF_INET6 ||
		       memcmp(&ptrrep.addr6.s6_addr, rptr->addr.addr6.s6_addr,
			      sizeof(struct in6_addr)) != 0)
		    {
#ifdef DNS_ANS_DEBUG
			char ipbuf[RES_HOSTLEN + 1];

			strcpy(ipbuf, inet6ntoa((char *)&ptrrep.addr6));
			sendto_realops_lev(DEBUG_LEV,
					   "Received DNS_PTR answer for %s, "
					   "but asked question for %s",
					   ipbuf, resntoa((char*)&rptr->addr,
							  rptr->he.h_addrtype));
#endif
			return PROCANSWER_STRANGE;
		    }
		}
		else if(!(arpa_to_ip(hostbuf, &ptrrep.addr4.s_addr)))
		{
#ifdef DNS_ANS_DEBUG
		    sendto_realops_lev(DEBUG_LEV, 
				       "Received strangely formed PTR answer "
				       "for %s (asked for %s) -- ignoring", 
				       hostbuf, resntoa((char *)&rptr->addr,
							rptr->he.h_addrtype));
#endif
		    return PROCANSWER_STRANGE;
		}
		else
		{
		    if(rptr->he.h_addrtype != AF_INET ||
		       ptrrep.addr4.s_addr != rptr->addr.addr4.s_addr)
		    {
#ifdef DNS_ANS_DEBUG
			char ipbuf[16];

			strcpy(ipbuf, inetntoa((char *)&ptrrep.addr4));
			sendto_realops_lev(DEBUG_LEV,
					   "Received DNS_PTR answer for %s, "
					   "but asked question for %s", 
					   ipbuf, resntoa((char*)&rptr->addr,
							  rptr->he.h_addrtype));
#endif
			return PROCANSWER_STRANGE;
		    }
		}
	    }
	    
#ifdef DNS_ANS_DEBUG
	    if(acc)
		sendto_realops_lev(DEBUG_LEV, 
				   "DNS_PTR from an acceptable (%s)", acc);
#endif
	    
	    if ((n = dn_expand(buf, eob, cp, hostbuf,
			       sizeof(hostbuf)-1)) < 0) 
	    {
		cp = NULL;
		break;
	    }
	    
	    /*
	     * This comment is based on analysis by Shadowfax,
	     * Jolo and johan, not me. (Dianora) I am only
	     * commenting it.
	     * 
	     * dn_expand is guaranteed to not return more than
	     * sizeof(hostbuf) but do all implementations of
	     * dn_expand also guarantee buffer is terminated with
	     * null byte? Lets not take chances. -Dianora
	     */
	    hostbuf[RES_HOSTLEN] = '\0';
	    cp += n;
	    len = strlen(hostbuf);
	    
#ifdef DNS_ANS_DEBUG_MAX
	    sendto_realops_lev(DEBUG_LEV, "%s PTR %s", dhostbuf, hostbuf);
#endif
	    
	    Debug((DEBUG_INFO, "got host %s", hostbuf));
	    /*
	     * copy the returned hostname into the host name or
	     * alias field if there is a known hostname already.
	     */
	    if (hp->h_name) 
	    {
		/*
		 * This is really fishy. In fact, so fishy,
		 * that I say we just don't do this in this case.
		 *
		 * seems to happen with a whole host of .my addresses.
		 * interesting. - lucas
		 */
		
		if (alias >= &(hp->h_aliases[IRC_MAXALIASES - 1]))
		    break;
		*alias = (char *) MyMalloc(len + 1);
		strcpy(*alias++, hostbuf);
		*alias = NULL;
	    }
	    else 
	    {
		hp->h_name = (char *) MyMalloc(len + 1);
		strcpy(hp->h_name, hostbuf);
	    }
	    ans++;
	    rptr->type = type;
	    break;
	    
	case T_CNAME:
	    acc = NULL;
	    
	    if(origtype == T_PTR)
	    {
		if(!num_acc_answers || !(acc = is_acceptable_answer(hostbuf)))
		{
		    struct in_addr ptrrep;

		    if(!(arpa_to_ip(hostbuf, &ptrrep.s_addr)))
		    {
#ifdef DNS_ANS_DEBUG
			sendto_realops_lev(DEBUG_LEV,
					   "Received strangely formed "
					   "CNAME(PTR) answer for %s (asked "
					   "for %s) -- ignoring", 
					   hostbuf,
					   resntoa((char *)&rptr->addr,
						   rptr->he.h_addrtype));
#endif
			return PROCANSWER_STRANGE;
		    }

		    if(rptr->he.h_addrtype != AF_INET &&
		       ptrrep.s_addr != rptr->addr.addr4.s_addr)
		    {
#ifdef DNS_ANS_DEBUG
			char ipbuf[16];
			
			strcpy(ipbuf, inetntoa((char *)&ptrrep));
			sendto_realops_lev(DEBUG_LEV, "Received "
					   "DNS_CNAME(PTR) answer for %s, "
					   "but asked question for %s", 
					   ipbuf, 
					   resntoa((char *)&rptr->addr,
						   rptr->he.h_addrtype));
#endif
			return PROCANSWER_STRANGE;
		    }
		}
#ifdef DNS_ANS_DEBUG
		if(acc)
		    sendto_realops_lev(DEBUG_LEV, "DNS_CNAME (PTR) answer "
				       "from an acceptable (%s)", acc);
#endif
	    }
	    else if(origtype == T_A || origtype == T_AAAA)
	    {
		if(mycmp(rptr->name, hostbuf) != 0)
		{
		    if(!num_acc_answers || !(acc = is_acceptable_answer(hostbuf)))
		    {
#ifdef DNS_ANS_DEBUG
			sendto_realops_lev(DEBUG_LEV, "Received DNS_CNAME(A) "
					   "answer for %s, but asked "
					   "question for %s", 
					   hostbuf, rptr->name);
#endif
			return PROCANSWER_STRANGE;
		    }
#ifdef DNS_ANS_DEBUG
		    sendto_realops_lev(DEBUG_LEV, "DNS_CNAME (A) answer from "
				       "an acceptable (%s)", acc);
#endif
		}
	    }
	    
	    Debug((DEBUG_INFO, "got cname %s", hostbuf));
	    
	    if (alias >= &(hp->h_aliases[IRC_MAXALIASES - 1]))
		break;
	    *alias = (char *) MyMalloc(len + 1);
	    strcpy(*alias++, hostbuf);
	    *alias = NULL;
	    ans++;
	    rptr->type = type;
	    
	    if ((n = dn_expand(buf, eob, cp, hostbuf, sizeof(hostbuf)-1)) < 0)
	    {
		cp = NULL;
		break;
	    }
	    
	    hostbuf[RES_HOSTLEN] = '\0';
	    cp += n;
	    
	    add_acceptable_answer(hostbuf);
	    
#ifdef DNS_ANS_DEBUG_MAX
	    sendto_realops_lev(DEBUG_LEV, "%s CNAME %s", dhostbuf, hostbuf);
#endif
	    
	    break;
	    
	default:
#ifdef DEBUG
	    Debug((DEBUG_INFO, "proc_answer: type:%d for:%s",
		   type, hostbuf));
#endif
	    break;
	}
    }
    return ans;
}

/*
 * read a dns reply from the nameserver and process it.
 */
struct hostent *get_res(char *lp)
{
    static char buf[sizeof(HEADER) + MAXPACKET];
    HEADER *hptr;
    ResRQ  *rptr = NULL;
    aCache     *cp = (aCache *) NULL;
    struct sockaddr_in sin;
    int         a, max;
    unsigned    len = sizeof(sin), rc;
    
    rc = recvfrom(resfd, buf, sizeof(buf), 0, (struct sockaddr *) &sin, &len);
    if (rc <= sizeof(HEADER))
	return getres_err(rptr, lp);
    
    /*
     * convert DNS reply reader from Network byte order to CPU byte
     * order.
     */
    hptr = (HEADER *) buf;
    hptr->id = ntohs(hptr->id);
    hptr->ancount = ntohs(hptr->ancount);
    hptr->qdcount = ntohs(hptr->qdcount);
    hptr->nscount = ntohs(hptr->nscount);
    hptr->arcount = ntohs(hptr->arcount);
#ifdef	DEBUG
    Debug((DEBUG_NOTICE, "get_res:id = %d rcode = %d ancount = %d",
	   hptr->id, hptr->rcode, hptr->ancount));
#endif
    reinfo.re_replies++;
    /*
     * response for an id which we have already received an answer for
     * just ignore this response.
     */
    rptr = find_id(hptr->id);
    if (!rptr)
	return getres_err(rptr, lp);
    /*
     * check against possibly fake replies
     */
    max = MIN(_res.nscount, rptr->sends);
    if (!max)
	max = 1;

    for (a = 0; a < max; a++)
	if (!_res.nsaddr_list[a].sin_addr.s_addr ||
	    !memcmp((char *) &sin.sin_addr,
		    (char *) &_res.nsaddr_list[a].sin_addr,
		    sizeof(struct in_addr)))
	    break;

    if (a == max) 
    {
	reinfo.re_unkrep++;
	return getres_err(rptr, lp);
    }

    if ((hptr->rcode != NOERROR) || (hptr->ancount == 0))
    {
	switch (hptr->rcode)
	{
	case NXDOMAIN:
	    h_errno = TRY_AGAIN;
	    break;
	case SERVFAIL:
	    h_errno = TRY_AGAIN;
	    break;
	case NOERROR:
	    h_errno = NO_DATA;
	    break;
	case FORMERR:
	case NOTIMP:
	case REFUSED:
	default:
	    h_errno = NO_RECOVERY;
	    break;
	}
	reinfo.re_errors++;
	/*
	 * If a bad error was returned, we stop here and dont send
	 * send any more (no retries granted).
	 */
	if (h_errno != TRY_AGAIN)
	{
	    Debug((DEBUG_DNS, "Fatal DNS error %d for %d",
		   h_errno, hptr->rcode));
	    rptr->resend = 0;
	    rptr->retries = 0;
	}
	return getres_err(rptr, lp);
    }
    a = proc_answer(rptr, hptr, buf, buf + rc);
    
#ifdef DEBUG
    Debug((DEBUG_INFO, "get_res:Proc answer = %d", a));
#endif

    switch(a)
    {
    case PROCANSWER_STRANGE:
	rptr->resend = 1;
	rptr->retries--;
	if(rptr->retries <= 0)
	{
	    h_errno = TRY_AGAIN; /* fail this lookup.. */
	    return getres_err(rptr, lp);
	}
	else 
	    resend_query(rptr);
	return NULL;
	
    case PROCANSWER_MALICIOUS:
	if (lp)
	    memcpy(lp, (char *) &rptr->cinfo, sizeof(Link));
	rem_request(rptr);
	return NULL;
	
    default:
	break;
    }
    
    if (a > 0 && rptr->type == T_PTR) 
    {
	struct hostent *hp2 = NULL;
	
	Debug((DEBUG_DNS, "relookup %s <-> %s",
	       rptr->he.h_name, resntoa((char *) &rptr->he.h_addr,
					rptr->he.h_addrtype)));
	/*
	 * Lookup the 'authoritive' name that we were given for the ip#.
	 * By using this call rather than regenerating the type we
	 * automatically gain the use of the cache with no extra kludges.
	 */
	if ((hp2 = gethost_byname(rptr->he.h_name, &rptr->cinfo,
				  rptr->he.h_addrtype)))
	    if (lp)
		memcpy(lp, (char *) &rptr->cinfo, sizeof(Link));
	
	if(!hp2)
	{
	    memcpy(&last->he_rev, &rptr->he, sizeof(struct hent));
	    memset(&rptr->he, 0, sizeof(struct hent));
	    last->has_rev = 1;
	}

	rem_request(rptr);
	return hp2;
    }

    if(a > 0 && (rptr->type == T_A || rptr->type == T_AAAA))
    {
	if(rptr->has_rev == 0)
	{
	    sendto_realops_lev(ADMIN_LEV, "Blindly accepting dns result for %s", 
			   rptr->he.h_name ? rptr->he.h_name : 
			   resntoa((char *)&rptr->addr, rptr->he.h_addrtype));
	}
	else
	{
	    int invalid_parms_name = 0;
	    int invalid_parms_ip = 0;
	    int found_match_ip = 0;
	    int nidx, tidx;
	    int numaddr, numnewaddr;
	    struct res_in_addr new_addr_list[IRC_MAXADDRS];

	    if(!(rptr->he.h_name && rptr->he_rev.h_name))
		invalid_parms_name++;
	    
	    if (memcmp(&rptr->he.h_addr_list[0], &res_zeroaddr,
		       rptr->he.h_length) == 0 &&
		memcmp(&rptr->he_rev.h_addr_list[0], &res_zeroaddr,
		       rptr->he_rev.h_length) != 0)
		invalid_parms_ip++;

	    if(invalid_parms_name || invalid_parms_ip)
	    {
		sendto_realops_lev(DEBUG_LEV, 
			       "DNS query missing things! name: %s ip: %s",
			       invalid_parms_name ? "MISSING" :
			       rptr->he.h_name,
			       invalid_parms_ip ? "MISSING" :
			       resntoa((char *)&rptr->he.h_addr_list[0],
				       rptr->he.h_addrtype));
		if (lp)
		    memcpy(lp, (char *) &rptr->cinfo, sizeof(Link));
		rem_request(rptr);
		return NULL;
	    }

	    /* 
	     * This must ensure that all IPs in the forward query (he)
	     * are also in the reverse query (he_rev).
	     * Those not in the reverse query must be zeroed out!
	     */
	    
	    for(numaddr = numnewaddr = nidx = 0; nidx < IRC_MAXADDRS; nidx++)
	    {
		int does_match;
		
		if (memcmp(&rptr->he.h_addr_list[nidx], &res_zeroaddr,
			   rptr->he.h_length) == 0)
		    break;
		
		numaddr++;
		
		for(tidx = does_match = 0; tidx < IRC_MAXADDRS; tidx++)
		{
		    if (memcmp(&rptr->he_rev.h_addr_list[tidx], &res_zeroaddr,
			       rptr->he_rev.h_length) == 0)
			break;
		    
		    if(rptr->he_rev.h_length == rptr->he.h_length &&
		       memcmp(&rptr->he_rev.h_addr_list[tidx],
			      &rptr->he.h_addr_list[nidx],
			      rptr->he.h_length) == 0) /* MATCH */
		    {
			found_match_ip++;
			does_match = 1;
			break;
		    }
		}
            
		if(does_match)
		{
		    /* RUNE */
		    memcpy(&new_addr_list[numnewaddr++],
			   &rptr->he.h_addr_list[nidx],
			   rptr->he.h_length);
		    memset(&new_addr_list[numnewaddr],
			   0,
			   sizeof(new_addr_list[numnewaddr]));
		}
	    }
         
	    if(!found_match_ip)
	    {
		char ntoatmp_r[64];
		char ntoatmp_f[64];

		strcpy(ntoatmp_f, resntoa((char *)&rptr->he.h_addr_list[0],
					  rptr->he.h_addrtype));
		strcpy(ntoatmp_r, resntoa((char *)&rptr->he_rev.h_addr_list[0],
					  rptr->he_rev.h_addrtype));
#ifdef DNS_ANS_DEBUG
		sendto_realops_lev(DEBUG_LEV, "Forward and Reverse queries do "
			       "not have matching IP! %s<>%s %s<>%s",
			       rptr->he.h_name, rptr->he_rev.h_name,
			       ntoatmp_f, ntoatmp_r);
#endif
		if(rptr->cinfo.flags == ASYNC_CLIENT && rptr->cinfo.value.cptr)
		{
		    sendto_one(rptr->cinfo.value.cptr,
			       ":%s NOTICE AUTH :*** Your forward and "
			       "reverse DNS do not match, "
			       "ignoring hostname. [%s != %s]",
			       me.name, ntoatmp_f, ntoatmp_r);
		}
		
		if (lp)
		    memcpy(lp, (char *) &rptr->cinfo, sizeof(Link));
		
		rem_request(rptr);
		return NULL;
	    }
	    
	    if(numnewaddr != numaddr)
	    {
		/* RUNE */
		memcpy(rptr->he.h_addr_list, new_addr_list,
		       sizeof(struct res_in_addr) * IRC_MAXADDRS);
#ifdef DNS_ANS_DEBUG
		sendto_realops_lev(DEBUG_LEV, "numaddr = %d, numnewaddr = %d",
			       numaddr, numnewaddr);
#endif
	    }
	    
	    /*
	     * Our DNS query was made based on the hostname, so the hostname
	     * part should be fine.
	     */
	}
    }
    
    if (a > 0)
    {
	if (lp)
	    memcpy(lp, (char *) &rptr->cinfo, sizeof(Link));

	cp = make_cache(rptr);
#ifdef	DEBUG
	Debug((DEBUG_INFO, "get_res:cp=%#x rptr=%#x (made)", cp, rptr));
#endif
	
	rem_request(rptr);
    }
    else if (!rptr->sent)
	rem_request(rptr);
    return cp ? (struct hostent *) &cp->he : NULL;
}

static struct hostent *getres_err(ResRQ * rptr, char *lp)
{
    /*
     * Reprocess an error if the nameserver didnt tell us to
     * "TRY_AGAIN".
     */
    if (rptr)
    {
	if (h_errno != TRY_AGAIN)
	{
	    /*
	     * If we havent tried with the default domain and its set,
	     * then give it a try next.
	     */
	    if (_res.options & RES_DEFNAMES && ++rptr->srch == 0)
	    {
		rptr->retries = _res.retry;
		rptr->sends = 0;
		rptr->resend = 1;
		resend_query(rptr);
	    }
	    else
		resend_query(rptr);
	}
	else if (lp)
	    memcpy(lp, (char *) &rptr->cinfo, sizeof(Link));
    }
    return (struct hostent *) NULL;
}

static int hash_number(unsigned char *ip, int len)
{
    u_int *p, *end;
    u_int   hashv = 0;

    for (p = (u_int *)ip, end = (u_int *)(ip + len); p < end; p++)
    {
	u_int h;

	/* Bob Jenkins 4-byte integer hash, full avalanche */
	h = hashv + *p;
	h = (h+0x7ed55d16) + (h<<12);
	h = (h^0xc761c23c) ^ (h>>19);
	h = (h+0x165667b1) + (h<<5);
	h = (h+0xd3a2646c) ^ (h<<9);
	h = (h+0xfd7046c5) + (h<<3);
	h = (h^0xb55a4f09) ^ (h>>16);
	hashv = h;
    }

    hashv %= ARES_CACSIZE;
    return (hashv);
}

#ifdef ALLOW_CACHE_NAMES
static int hash_name(char *name)
{
    u_int   hashv = 0;

    /* Bob Jenkins one-at-a-time hash */
    for (; *name && *name != '.'; name++)
    {
	hashv += *name;
	hashv += (hashv << 10);
	hashv ^= (hash >> 6);
    }
    hashv += (hashv << 3);
    hashv ^= (hashv >> 11);
    hashv += (hashv << 15);

    hashv %= ARES_CACSIZE;
    return (hashv);
}
#endif

static unsigned int hash_id(unsigned int id)
{
    /* Bob Jenkins 4-byte integer hash, full avalanche */
    id = (id+0x7ed55d16) + (id<<12);
    id = (id^0xc761c23c) ^ (id>>19);
    id = (id+0x165667b1) + (id<<5);
    id = (id+0xd3a2646c) ^ (id<<9);
    id = (id+0xfd7046c5) + (id<<3);
    id = (id^0xb55a4f09) ^ (id>>16);
   return id % ARES_IDCACSIZE;
}

static unsigned int hash_cp(char *cp)
{
   return ((unsigned long) cp) % ARES_IDCACSIZE;
}

/* Add a new cache item to the queue and hash table. */
static aCache *add_to_cache(aCache * ocp)
{
    aCache *cp = NULL;
    int     hashv;
    
#ifdef DEBUG
    Debug((DEBUG_INFO,
	   "add_to_cache:ocp %#x he %#x name %#x addrl %#x 0 %#x",
	   ocp, &ocp->he, ocp->he.h_name, ocp->he.h_addr_list,
	   ocp->he.h_addr_list[0]));
#endif
    ocp->list_next = cachetop;
    cachetop = ocp;
    /* Make sure non-bind resolvers don't blow up (Thanks to Yves) */
    if (!ocp)
	return NULL;
    if (!(ocp->he.h_name))
	return NULL;
    if (!(ocp->he.h_addr))
	return NULL;
    
#ifdef ALLOW_CACHE_NAMES
    hashv = hash_name(ocp->he.h_name);
    
    ocp->hname_next = hashtable[hashv].name_list;
    hashtable[hashv].name_list = ocp;
#endif
    
    hashv = hash_number((u_char *) ocp->he.h_addr, ocp->he.h_length);
    
    ocp->hnum_next = hashtable[hashv].num_list;
    hashtable[hashv].num_list = ocp;
    
#ifdef	DEBUG
    Debug((DEBUG_INFO, "add_to_cache:added %s[%08x] cache %#x.",
	   ocp->he.h_name, ocp->he.h_addr_list[0], ocp));
    Debug((DEBUG_INFO,
	   "add_to_cache:h1 %d h2 %x lnext %#x namnext %#x numnext %#x",
	   hash_name(ocp->he.h_name), hashv, ocp->list_next,
	   ocp->hname_next, ocp->hnum_next));
#endif
    /* LRU deletion of excessive cache entries. */
    if (++incache > IRC_MAXCACHED)
    {
	for (cp = cachetop; cp->list_next; cp = cp->list_next);
	rem_cache(cp);
    }
    cainfo.ca_adds++;

    return ocp;
}

/*
 * update_list does not alter the cache structure passed. It is
 * assumed that * it already contains the correct expire time, if it is
 * a new entry. Old * entries have the expirey time updated.
 */
static void update_list(ResRQ * rptr, aCache * cachep)
{
    aCache **cpp, *cp = cachep;
    char   *s, *t, **base;
    int     i, j;
    int     addrcount;

    /*
     * search for the new cache item in the cache list by hostname. *
     * If found, move the entry to the top of the list and return.
     */
    cainfo.ca_updates++;

    for (cpp = &cachetop; *cpp; cpp = &((*cpp)->list_next))
	if (cp == *cpp)
	    break;
    if (!*cpp)
	return;
    *cpp = cp->list_next;
    cp->list_next = cachetop;
    cachetop = cp;
    if (!rptr)
	return;
    
#ifdef	DEBUG
    Debug((DEBUG_DEBUG, "u_l:cp %#x na %#x al %#x ad %#x",
	   cp, cp->he.h_name, cp->he.h_aliases, cp->he.h_addr));
    Debug((DEBUG_DEBUG, "u_l:rptr %#x h_n %#x", rptr, rptr->he.h_name));
#endif
    /*
     * Compare the cache entry against the new record.  Add any
     * previously missing names for this entry.
     */
    for (i = 0; cp->he.h_aliases[i]; i++);
    addrcount = i;
    for (i = 0, s = rptr->he.h_name; s && i < IRC_MAXALIASES;
	 s = rptr->he.h_aliases[i++])
    {
	for (j = 0, t = cp->he.h_name; t && j < IRC_MAXALIASES;
	     t = cp->he.h_aliases[j++])
	    if (!mycmp(t, s))
		break;
	if (!t && j < IRC_MAXALIASES - 1)
	{
	    base = cp->he.h_aliases;
	    
	    addrcount++;
	    base = (char **) MyRealloc(base,
				       sizeof(char *) * (addrcount + 1));
	    
	    cp->he.h_aliases = base;
#ifdef	DEBUG
	    Debug((DEBUG_DNS, "u_l:add name %s hal %x ac %d",
		   s, cp->he.h_aliases, addrcount));
#endif
	    base[addrcount - 1] = s;
	    base[addrcount] = NULL;
	    if (i)
		rptr->he.h_aliases[i - 1] = NULL;
	    else
		rptr->he.h_name = NULL;
	}
    }
    for (i = 0; cp->he.h_addr_list[i]; i++);
    addrcount = i;
    /* Do the same again for IP#'s. */
    for (s = (char *) &rptr->he.h_addr;
	 memcmp(s, &res_zeroaddr, rptr->he.h_length) != 0;
	 s += sizeof(struct res_in_addr)) {
	for (i = 0; (t = cp->he.h_addr_list[i]); i++)
	    if (!memcmp(s, t, rptr->he.h_length))
		break;

	if (i >= IRC_MAXADDRS || addrcount >= IRC_MAXADDRS)
	    break;
	/*
	 * Oh man this is bad...I *HATE* it. -avalon
	 * 
	 * Whats it do ?  Reallocate two arrays, one of pointers to "char *"
	 * and the other of IP addresses.  Contents of the IP array *MUST*
	 * be preserved and the pointers into it recalculated.
	 */
	if (!t)
	{
	    base = cp->he.h_addr_list;
	    addrcount++;
	    t = (char *) MyRealloc(*base,
				   addrcount * sizeof(struct res_in_addr));
	    
	    base = (char **) MyRealloc(base,
				       (addrcount + 1) * sizeof(char *));
	    
	    cp->he.h_addr_list = base;
#ifdef	DEBUG
	    Debug((DEBUG_DNS, "u_l:add IP %x hal %x ac %d",
		   ntohl(((struct in_addr *) s)->s_addr),
		   cp->he.h_addr_list,
		   addrcount));
#endif
	    for (; addrcount; addrcount--)
	    {
		*base++ = t;
		t += sizeof(struct res_in_addr);
	    }
	    *base = NULL;
	    memcpy(*--base, s, sizeof(struct res_in_addr));
	}
    }
    return;
}

static aCache *find_cache_name(char *name)
{
#ifdef ALLOW_CACHE_NAMES
    aCache *cp;
    char   *s;
    int     hashv, i;
    
    if (name == (char *) NULL)
	return (aCache *) NULL;
    hashv = hash_name(name);
    
    cp = hashtable[hashv].name_list;
#ifdef	DEBUG
    Debug((DEBUG_DNS, "find_cache_name:find %s : hashv = %d", name, hashv));
#endif
    
    for (; cp; cp = cp->hname_next)
	for (i = 0, s = cp->he.h_name; s; s = cp->he.h_aliases[i++])
	    if (mycmp(s, name) == 0)
	    {
		cainfo.ca_na_hits++;
		update_list(NULL, cp);
		return cp;
	    }
    
    for (cp = cachetop; cp; cp = cp->list_next)
    {
	/*
	 * if no aliases or the hash value matches, we've already done
	 * this entry and all possiblilities concerning it.
	 */
	if (!*cp->he.h_aliases)
	    continue;
	if (cp->he.h_name == (char *) NULL)	/*
						 * don't trust anything
						 * -Dianora 
						 */
	    continue;
	if (hashv == hash_name(cp->he.h_name))
	    continue;
	for (i = 0, s = cp->he.h_aliases[i]; s && i < IRC_MAXALIASES; i++)
	    if (!mycmp(name, s))
	    {
		cainfo.ca_na_hits++;
		update_list(NULL, cp);
		return cp;
	    }
    }
#endif
    return NULL;
}

/* find a cache entry by ip# and update its expire time */
static aCache *
find_cache_number(ResRQ * rptr, char *numb, int family)
{
    aCache *cp;
    int     hashv, i, h_length;

    if ((u_char *) numb == (u_char *) NULL)
	return ((aCache *) NULL);
    if (family == AF_INET)
	h_length = sizeof(struct in_addr);
    else if (family == AF_INET6)
	h_length = sizeof(struct in6_addr);
    else
	h_length = 0;
    hashv = hash_number((u_char *) numb, h_length);
    cp = hashtable[hashv].num_list;
#ifdef DEBUG
    {
	Debug((DEBUG_DNS, "find_cache_number:find %s: hashv = %d",
	       resntoa(numb, family), hashv));
    }
#endif

    for (; cp; cp = cp->hnum_next)
    {
	for (i = 0; cp->he.h_addr_list[i]; i++)
	{
	    if (cp->he.h_length == h_length &&
		memcmp(cp->he.h_addr_list[i], numb, h_length) == 0)
	    {
		cainfo.ca_nu_hits++;
		update_list(NULL, cp);
		return cp;
	    }
	}
    }
    
#ifdef SEARCH_CACHE_ADDRESSES
    for (cp = cachetop; cp; cp = cp->list_next)
    {
	/*
	 * single address entry...would have been done by hashed search 
	 * above...
	 */
	if (!cp->he.h_addr_list[1])
	    continue;
	/*
	 * if the first IP# has the same hashnumber as the IP# we are
	 * looking for, its been done already.
	 */
	if (hashv == hash_number((u_char *) cp->he.h_addr_list[0],
				 cp->he.h_length))
	    continue;
	for (i = 1; cp->he.h_addr_list[i]; i++)
	    if (cp->he.h_length == h_length &&
		!memcmp(cp->he.h_addr_list[i], numb, h_length))
	    {
		cainfo.ca_nu_hits++;
		update_list(NULL, cp);
		return cp;
	    }
    }
#endif
    return NULL;
}

static aCache *make_cache(ResRQ * rptr)
{
    aCache *cp;
    int     i, n;
    struct hostent *hp;
    char   *s, **t;

    /* shouldn't happen but it just might... */
    if (!rptr->he.h_name ||
	memcmp(&rptr->he.h_addr, &res_zeroaddr, rptr->he.h_length) == 0)
	return NULL;
    /*
     * Make cache entry.  First check to see if the cache already
     * exists and if so, return a pointer to it.
     */
    if ((cp = find_cache_number(rptr, (char *) &rptr->he.h_addr,
				rptr->he.h_addrtype)))
	return cp;
    for (i = 1; memcmp(&rptr->he.h_addr_list[i], &res_zeroaddr,
		       rptr->he.h_length) != 0 && i < IRC_MAXADDRS; i++)
	if ((cp = 
	     find_cache_number(rptr,
			       (char *) &(rptr->he.h_addr_list[i]),
			       rptr->he.h_addrtype)))
	    return cp;
    /* a matching entry wasnt found in the cache so go and make one up. */
    cp = (aCache *) MyMalloc(sizeof(aCache));
    memset((char *) cp, '\0', sizeof(aCache));
    hp = &cp->he;
    for (i = 0; i < IRC_MAXADDRS; i++)
	if (memcmp(&rptr->he.h_addr_list[i], &res_zeroaddr,
		   rptr->he.h_length) == 0)
	    break;
    /* build two arrays, one for IP#'s, another of pointers to them. */
    t = hp->h_addr_list = (char **) MyMalloc(sizeof(char *) * (i + 1));
    memset((char *) t, '\0', sizeof(char *) * (i + 1));
    
    s = (char *) MyMalloc(sizeof(struct res_in_addr) * i);
    memset(s, '\0', sizeof(struct res_in_addr) * i);
    
    for (n = 0; n < i; n++, s += sizeof(struct res_in_addr))
    {
	*t++ = s;
	memcpy(s, (char *) &(rptr->he.h_addr_list[n]),
	       sizeof(struct res_in_addr));
    }
    *t = (char *) NULL;
    /* an array of pointers to CNAMEs. */
    for (i = 0; i < IRC_MAXALIASES; i++)
	if (!rptr->he.h_aliases[i])
	    break;
    i++;
    t = hp->h_aliases = (char **) MyMalloc(sizeof(char *) * i);
    
    for (n = 0; n < i; n++, t++)
    {
	*t = rptr->he.h_aliases[n];
	rptr->he.h_aliases[n] = NULL;
    }
    
    hp->h_addrtype = rptr->he.h_addrtype;
    hp->h_length = rptr->he.h_length;
    hp->h_name = rptr->he.h_name;
    if (rptr->ttl < 600)
    {
	reinfo.re_shortttl++;
	cp->ttl = 600;
    }
    else
	cp->ttl = rptr->ttl;
    cp->expireat = timeofday + cp->ttl;
    rptr->he.h_name = NULL;
#ifdef DEBUG
    Debug((DEBUG_INFO, "make_cache:made cache %#x", cp));
#endif
    return add_to_cache(cp);
}

/*
 * rem_cache delete a cache entry from the cache structures and lists
 * and return all memory used for the cache back to the memory pool.
 */
static void rem_cache(aCache * ocp)
{
    aCache **cp;
    struct hostent *hp = &ocp->he;
    int     hashv;
    aClient *cptr;
    
#ifdef	DEBUG
    Debug((DEBUG_DNS, "rem_cache: ocp %#x hp %#x l_n %#x aliases %#x",
	   ocp, hp, ocp->list_next, hp->h_aliases));
#endif
    /*
     * * Cleanup any references to this structure by destroying the *
     * pointer.
     */
    for (hashv = highest_fd; hashv >= 0; hashv--)
	if ((cptr = local[hashv]) && (cptr->hostp == hp))
	    cptr->hostp = NULL;
    /*
     * remove cache entry from linked list
     */
    for (cp = &cachetop; *cp; cp = &((*cp)->list_next))
	if (*cp == ocp)
	{
	    *cp = ocp->list_next;
	    break;
	}
    /* remove cache entry from hashed name lists */
    if (hp->h_name == (char *) NULL)
	return;
#ifdef ALLOW_CACHE_NAMES
    hashv = hash_name(hp->h_name);
    
# ifdef	DEBUG
    Debug((DEBUG_DEBUG, "rem_cache: h_name %s hashv %d next %#x first %#x",
	   hp->h_name, hashv, ocp->hname_next,
	   hashtable[hashv].name_list));
# endif
    for (cp = &hashtable[hashv].name_list; *cp; cp = &((*cp)->hname_next))
	if (*cp == ocp)
	{
	    *cp = ocp->hname_next;
	    break;
	}
#endif
    /* remove cache entry from hashed number list */
    hashv = hash_number((u_char *) hp->h_addr, hp->h_length);
    if (hashv < 0)
	return;
#ifdef	DEBUG
    /* RUNE */
    Debug((DEBUG_DEBUG, "rem_cache: h_addr %s hashv %d next %#x first %#x",
	   inetntoa(hp->h_addr), hashv, ocp->hnum_next,
	   hashtable[hashv].num_list));
#endif
    for (cp = &hashtable[hashv].num_list; *cp; cp = &((*cp)->hnum_next))
	if (*cp == ocp)
	{
	    *cp = ocp->hnum_next;
	    break;
	}
    /*
     * free memory used to hold the various host names and the array of
     * alias pointers.
     */
    if (hp->h_name)
	MyFree(hp->h_name);
    if (hp->h_aliases)
    {
	for (hashv = 0; hp->h_aliases[hashv]; hashv++)
	    MyFree(hp->h_aliases[hashv]);
	MyFree(hp->h_aliases);
    }
    /* free memory used to hold ip numbers and the array of them. */
    if (hp->h_addr_list)
    {
	if (*hp->h_addr_list)
	    MyFree(*hp->h_addr_list);
	MyFree(hp->h_addr_list);
    }
    
    MyFree(ocp);
    
    incache--;
    cainfo.ca_dels++;
    
    return;
}

/*
 * removes entries from the cache which are older than their expirey
 * times. returns the time at which the server should next poll the
 * cache.
 */
time_t expire_cache(time_t now)
{
    aCache *cp, *cp2;
    time_t  next = 0;
    time_t  mmax = now + AR_TTL;

    for (cp = cachetop; cp; cp = cp2)
    {
	cp2 = cp->list_next;
	
	if (now >= cp->expireat)
	{
	    cainfo.ca_expires++;
	    rem_cache(cp);
	}
	else if (!next || next > cp->expireat)
	    next = cp->expireat;
    }
    /*
     * don't let one DNS record that happens to be first
     * stop others from expiring.
     */
    return (next > now) ? (next < mmax ? next : mmax) : mmax;
}

/* remove all dns cache entries. */
void flush_cache()
{
    aCache *cp;
    
    while ((cp = cachetop))
	rem_cache(cp);
}

int m_dns(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aCache *cp;
    int     i;
    
    if (parv[1] && *parv[1] == 'l')
    {
        if (!MyClient(sptr) || !IsAdmin(sptr))
        {
          sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
          return 0;
        }
	for (cp = cachetop; cp; cp = cp->list_next)
	{
	    sendto_one(sptr, "NOTICE %s :Ex %ld ttl %ld host %s(%s)",
		       parv[0], (long)(cp->expireat - timeofday), (long)cp->ttl,
		       cp->he.h_name, resntoa(cp->he.h_addr,
					      cp->he.h_addrtype));
	    for (i = 0; cp->he.h_aliases[i]; i++)
		sendto_one(sptr, "NOTICE %s : %s = %s (CN)",
			   parv[0], cp->he.h_name,
			   cp->he.h_aliases[i]);
	    for (i = 1; cp->he.h_addr_list[i]; i++)
		sendto_one(sptr, "NOTICE %s : %s = %s (IP)",
			   parv[0], cp->he.h_name,
			   resntoa(cp->he.h_addr_list[i], cp->he.h_addrtype));
	}
	return 0;
    }
    sendto_one(sptr, "NOTICE %s :Ca %d Cd %d Ce %d Cl %d Ch %d:%d Cu %d",
	       sptr->name,
	       cainfo.ca_adds, cainfo.ca_dels, cainfo.ca_expires,
	       cainfo.ca_lookups,
	       cainfo.ca_na_hits, cainfo.ca_nu_hits, cainfo.ca_updates);
    
    sendto_one(sptr, "NOTICE %s :Re %d Rl %d/%d Rp %d Rq %d",
	       sptr->name, reinfo.re_errors, reinfo.re_nu_look,
	       reinfo.re_na_look, reinfo.re_replies, reinfo.re_requests);
    sendto_one(sptr, "NOTICE %s :Ru %d Rsh %d Rs %d(%d) Rt %d", sptr->name,
	       reinfo.re_unkrep, reinfo.re_shortttl, reinfo.re_sent,
	       reinfo.re_resends, reinfo.re_timeouts);
    return 0;
}

u_long
memcount_res(MCres *mc)
{
    ResRQ *rq;
    aCache *ce;
    int i;

    mc->file = __FILE__;

    for (rq = first; rq; rq = rq->next)
    {
        mc->requests.c++;
        mc->requests.m += sizeof(*rq);

        if (rq->name)
            mc->requests.m += strlen(rq->name) + 1;

        if (rq->he.h_name)
            mc->requests.m += strlen(rq->he.h_name) + 1;

        for (i = 0; rq->he.h_aliases[i]; i++)
            mc->requests.m += strlen(rq->he.h_aliases[i]) + 1;

        if (rq->he_rev.h_name)
            mc->requests.m += strlen(rq->he_rev.h_name) + 1;

        for (i = 0; rq->he_rev.h_aliases[i]; i++)
            mc->requests.m += strlen(rq->he_rev.h_aliases[i]) + 1;
    }

    for (ce = cachetop; ce; ce = ce->list_next)
    {
        mc->cached.c++;
        mc->cached.m += sizeof(*ce);

        if (ce->he.h_name)
            mc->cached.m += strlen(ce->he.h_name) + 1;

        if (ce->he.h_aliases)
        {
            for (i = 0; ce->he.h_aliases[i]; i++)
            {
                mc->cached.m += sizeof(char *);
                mc->cached.m += strlen(ce->he.h_aliases[i]) + 1;
            }
            mc->cached.m += sizeof(char *);
        }

        if (ce->he.h_addr_list)
        {
            for (i = 0; ce->he.h_addr_list[i]; i++)
            {
                mc->cached.m += sizeof(char *);
                mc->cached.m += ce->he.h_length;
            }
            mc->cached.m += sizeof(char *);
        }
    }

    mc->s_cachehash.c = sizeof(hashtable) / sizeof(hashtable[0]);
    mc->s_cachehash.m = sizeof(hashtable);
    mc->s_requesthash.c = sizeof(idcphashtable) / sizeof(idcphashtable[0]);
    mc->s_requesthash.m = sizeof(idcphashtable);

    mc->total.c = mc->requests.c + mc->cached.c;
    mc->total.m = mc->requests.m + mc->cached.m;

    return mc->total.m;
}

