/*
 * IRC - Internet Relay Chat, src/class.c Copyright (C) 1990 Darren
 * Reed
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation,
 * Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/* $Id$ */

#include "struct.h"
#include "common.h"
#include "numeric.h"
#include "h.h"

#define BAD_CONF_CLASS		-1
#define BAD_PING		-2
#define BAD_CLIENT_CLASS	-3

aClass     *classes;

int get_client_class(aClient *acptr)
{
	return acptr->confs->allow->class->class;
}

int get_client_ping(aClient *acptr)
{
    int i;
    if(IsServer(acptr))
    {
	    if((i = acptr->confs->aconn->class->pingFreq))
		    return i;
	    return PINGFREQUENCY;
    }
    if((i = acptr->confs->allow->class->pingFreq))
	    return i;
    return PINGFREQUENCY;
}

int get_con_freq(aClass *clptr)
{
    if (clptr)
	    return (ConFreq(clptr));
	return (CONNECTFREQUENCY);
}

/*
 * When adding a class, check to see if it is already present first. if
 * so, then update the information for that class, rather than create a
 * new entry for it and later delete the old entry. if no present entry
 * is found, then create a new one and add it in immediately after the
 * first one (class 0).
 */
void add_class(int class, int ping, int confreq, int maxli, long sendq)
{
    aClass     *t, *p;
    
    t = find_class(class);
    if ((t == classes) && (class != 0))
    {
	p = (aClass *) make_class();
	NextClass(p) = NextClass(t);
	NextClass(t) = p;
    }
    else
    {
	p = t;
    }
    Debug((DEBUG_DEBUG,
	   "Add Class %d: p %x t %x - cf: %d pf: %d ml: %d sq: %l",
	   class, p, t, confreq, ping, maxli, sendq));
    Class (p) = class;
    
    ConFreq(p) = confreq;
    PingFreq(p) = ping;
    MaxLinks(p) = maxli;
    MaxSendq(p) = (sendq > 0) ? sendq : MAXSENDQLENGTH;
    if (p != t)
	Links(p) = 0;
}

aClass *find_class(int cclass)
{
    aClass     *cltmp;
    
    for (cltmp = FirstClass(); cltmp; cltmp = NextClass(cltmp))
	if (Class (cltmp) == cclass)
	    return cltmp;
    return classes;
}

void check_class()
{
    aClass *cltmp, *cltmp2;
    
    Debug((DEBUG_DEBUG, "Class check:"));

    for (cltmp2 = cltmp = FirstClass(); cltmp; cltmp = NextClass(cltmp2))
    {
	Debug((DEBUG_DEBUG,
	       "Class %d : CF: %d PF: %d ML: %d LI: %d SQ: %ld",
	       Class (cltmp), ConFreq(cltmp), PingFreq(cltmp),
	       MaxLinks(cltmp), Links(cltmp), MaxSendq(cltmp)));
	if (MaxLinks(cltmp) < 0)
	{
	    NextClass(cltmp2) = NextClass(cltmp);
	    if (Links(cltmp) <= 0)
		free_class(cltmp);
	}
	else
	{
	    cltmp2 = cltmp;
	}
    }
}

void initclass()
{
    classes = (aClass *) make_class();

    Class       (FirstClass()) = 0;

    ConFreq(FirstClass()) = CONNECTFREQUENCY;
    PingFreq(FirstClass()) = PINGFREQUENCY;
    MaxLinks(FirstClass()) = MAXIMUM_LINKS;
    MaxSendq(FirstClass()) = MAXSENDQLENGTH;
    Links(FirstClass()) = 0;
    NextClass(FirstClass()) = NULL;
}

void report_classes(aClient *sptr)
{
    aClass *cltmp;

    for (cltmp = FirstClass(); cltmp; cltmp = NextClass(cltmp))
	sendto_one(sptr, rpl_str(RPL_STATSYLINE), me.name, sptr->name,
		   'Y', Class  (cltmp), PingFreq(cltmp), ConFreq(cltmp),
		   MaxLinks    (cltmp), MaxSendq(cltmp));
}

long get_sendq(aClient *cptr)
{
    int     i;

    if(IsServer(cptr))
    {
    	if((i = cptr->confs->aconn->class->maxSendq))
		    return i;
	    else
		    return MAXSENDQLENGTH;
    }
    if((i = cptr->confs->allow->class->maxSendq))
	    return i;
    return MAXSENDQLENGTH;
}
