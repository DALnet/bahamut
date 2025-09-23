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

#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "config.h"
#include "sys.h"
#include "nameser.h"
#include "resolv.h"

/* Helper functions */
static void putshort(u_short s, char *cp)
{
    *cp++ = (s >> 8) & 0xff;
    *cp = s & 0xff;
}

/* Form all types of queries. Returns the size of the result or -1. */
int res_mkquery(int op, char *dname, int class, int type, char *data,
		int datalen, char *newrr, char *buf, int buflen)
{
    HEADER *hp;
    char *cp;
    int n;
    char       *dnptrs[10], **lastdnptr;
    
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
    hp->rcode = NOERROR;
    hp->rd = (_res.options & RES_RECURSE) != 0;
    hp->ra = 0;
    hp->tc = 0;
    hp->aa = 0;
    hp->qr = 0;

    /* Make sure the name we're querying for is valid. */
    if (dname == NULL || *dname == '\0') {
	hp->rcode = FORMERR;
	return (-1);
    }
    /* Initialize work pointers. */
    cp = buf + sizeof(HEADER);
    buflen -= sizeof(HEADER);

    /* Expand name and check length. */
    if ((n = dn_comp(dname, cp, buflen, dnptrs, lastdnptr)) < 0)
	return (-1);
    cp += n;
    buflen -= n;

    /* Add query type and class. */
    if (buflen < sizeof(u_short) * 2)
	return (-1);
    putshort(type, cp);
    cp += sizeof(u_short);
    putshort(class, cp);
    cp += sizeof(u_short);
    buflen -= sizeof(u_short) * 2;

    /* Add additional data if present. */
    if (data != NULL && datalen > 0) {
	if (buflen < datalen)
	    return (-1);
	memcpy(cp, data, datalen);
	cp += datalen;
	buflen -= datalen;
    }

    /* Set question count. */
    hp->qdcount = htons(1);
    hp->ancount = 0;
    hp->nscount = 0;
    hp->arcount = 0;

    return (cp - buf);
}