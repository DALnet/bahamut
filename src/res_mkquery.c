/*
 * Copyright (c) 1985 Regents of the University of California. All
 * rights reserved.
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
 */

/* $Id$ */

#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "config.h"
#include "sys.h"
#include "nameser.h"
#include "resolv.h"

/* Form all types of queries. Returns the size of the result or -1. */
int res_mkquery(int op, char *dname, int class, int type, char *data,
		int datalen, struct rrec *newrr, char *buf, int buflen)
{
    HEADER *hp;
    char *cp;
    int n;
    char       *dnptrs[10], **dpp, **lastdnptr;
    
#ifdef DEBUG
    if (_res.options & RES_DEBUG)
	printf("res_mkquery(%d, %s, %d, %d)\n", op, dname, class, type);
#endif /* DEBUG */
    /* Initialize header fields. */
    if ((buf == NULL) || (buflen < sizeof(HEADER)))
	return (-1);
    memset(buf, '\0', sizeof(HEADER));

    hp = (HEADER *) buf;
    hp->id = htons(++_res.id);
    hp->opcode = op;
    hp->pr = (_res.options & RES_PRIMARY) != 0;
    hp->rd = (_res.options & RES_RECURSE) != 0;
    hp->rcode = NOERROR;
    cp = buf + sizeof(HEADER);
    buflen -= sizeof(HEADER);
    
    dpp = dnptrs;
    *dpp++ = buf;
    *dpp++ = NULL;
    lastdnptr = dnptrs + sizeof(dnptrs) / sizeof(dnptrs[0]);
    /* perform opcode specific processing */
    switch (op) 
    {
    case QUERY:
	if ((buflen -= QFIXEDSZ) < 0)
	    return (-1);
	if ((n = dn_comp(dname, cp, buflen, dnptrs, lastdnptr)) < 0)
	    return (-1);
	cp += n;
	buflen -= n;
	putshort(type, cp);
	cp += sizeof(u_short);
	
	putshort(class, cp);
	cp += sizeof(u_short);

	hp->qdcount = htons(1);
	if (op == QUERY || data == NULL)
	    break;
	/* Make an additional record for completion domain. */
	buflen -= RRFIXEDSZ;
	if ((n = dn_comp(data, cp, buflen, dnptrs, lastdnptr)) < 0)
	    return (-1);
	cp += n;
	buflen -= n;
	putshort(T_NULL, cp);
	cp += sizeof(u_short);
	
	putshort(class, cp);
	cp += sizeof(u_short);

	putlong(0, cp);
	cp += sizeof(u_long);

	putshort(0, cp);
	cp += sizeof(u_short);

	hp->arcount = htons(1);
	break;

    case IQUERY:
	/* Initialize answer section */
	if (buflen < 1 + RRFIXEDSZ + datalen)
	    return (-1);
	*cp++ = '\0';		/* no domain name */
	putshort(type, cp);
	cp += sizeof(u_short);
	
	putshort(class, cp);
	cp += sizeof(u_short);

	putlong(0, cp);
	cp += sizeof(u_long);

	putshort(datalen, cp);
	cp += sizeof(u_short);

	if (datalen)
	{
	    memcpy(cp, data, datalen);
	    cp += datalen;
	}
	hp->ancount = htons(1);
	break;
	
#ifdef ALLOW_UPDATES
	/*
	 * For UPDATEM/UPDATEMA, do UPDATED/UPDATEDA followed by
	 * UPDATEA (Record to be modified is followed by its
	 * replacement in msg.)
	 */
    case UPDATEM:
    case UPDATEMA:

    case UPDATED:
	/*
	 * The res code for UPDATED and UPDATEDA is the same;
	 * user calls them differently: specifies data for
	 * UPDATED; server ignores data if specified for
	 * UPDATEDA.
	 */
    case UPDATEDA:
	buflen -= RRFIXEDSZ + datalen;
	if ((n = dn_comp(dname, cp, buflen, dnptrs, lastdnptr)) < 0)
	    return (-1);
	cp += n;
	putshort(type, cp);
	cp += sizeof(u_short);

	putshort(class, cp);
	cp += sizeof(u_short);

	putlong(0, cp);
	cp += sizeof(u_long);

	putshort(datalen, cp);
	cp += sizeof(u_short);

	if (datalen)
	{
	    memcpy(cp, data, datalen);
	    cp += datalen;
	}
	if ((op == UPDATED) || (op == UPDATEDA))
	{
	    hp->ancount = htons(0);
	    break;
	}
	/* Else UPDATEM/UPDATEMA, so drop into code for UPDATEA */

    case UPDATEA:		/* Add new resource record */
	buflen -= RRFIXEDSZ + datalen;
	if ((n = dn_comp(dname, cp, buflen, dnptrs, lastdnptr)) < 0)
	    return (-1);
	cp += n;
	putshort(newrr->r_type, cp);
	cp += sizeof(u_short);

	putshort(newrr->r_class, cp);
	cp += sizeof(u_short);

	putlong(0, cp);
	cp += sizeof(u_long);

	putshort(newrr->r_size, cp);
	cp += sizeof(u_short);

	if (newrr->r_size)
	{
	    memcpy(cp, newrr->r_data, newrr->r_size);
	    cp += newrr->r_size;
	}
	hp->ancount = htons(0);
	break;

#endif /* ALLOW_UPDATES */
    }
    return (cp - buf);
}
