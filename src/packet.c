/************************************************************************
 *   IRC - Internet Relay Chat, src/packet.c
 *   Copyright (C) 1990  Jarkko Oikarinen and
 *                       University of Oulu, Computing Center
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
#include "msg.h"
#include "h.h"
#include "dh.h"
#include "zlink.h"

/*
 * * dopacket 
 * cptr - pointer to client structure for which the buffer
 * data applies. 
 * buffer - pointr to the buffer containing the newly read data 
 * length - number of valid bytes of data in the buffer
 * 
 * Note: 
 * It is implicitly assumed that dopacket is called only
 * with cptr of "local" variation, which contains all the
 * necessary fields (buffer etc..)
 */
int dopacket(aClient *cptr, char *buffer, int length)
{
    char   *ch1;
    char   *ch2;
    char *cptrbuf = cptr->buffer;
    aListener    *lptr = cptr->lstn;
    char *nbuf = NULL;
    int nlen;
    
#ifdef HAVE_ENCRYPTION_ON
    if(IsRC4IN(cptr))
	rc4_process_stream(cptr->serv->rc4_in, buffer, length);
#endif
    
    me.receiveB += length;	   /* Update bytes received */
    cptr->receiveB += length;
    
    if (cptr->receiveB & 0x0400) 
    {
	cptr->receiveK += (cptr->receiveB >> 10);
	cptr->receiveB &= 0x03ff;  /* 2^10 = 1024, 3ff = 1023 */
    }

    if (lptr) 
    {
	lptr->receiveB += length;
	if (lptr->receiveB & 0x0400)
	{
	    lptr->receiveK += (lptr->receiveB >> 10);
	    lptr->receiveB &= 0x03ff;
	}
    }
    else if (me.receiveB & 0x0400)
    {
	me.receiveK += (me.receiveB >> 10);
	me.receiveB &= 0x03ff;
    }
    
zcontinue:
    ch1 = cptrbuf + cptr->count;
    ch2 = buffer;   
    
    if(ZipIn(cptr))
    {
	int err;
	ch2 = zip_input(cptr->serv->zip_in, ch2, &length, &err, &nbuf, &nlen);

	if(length == -1)
	{
	    sendto_realops("Zipin error for %s: (%d) %s\n", cptr->name,
			   err, ch2);
	    return exit_client(cptr, cptr, &me, "fatal error in zip_input!");
	}
    }
    
    while (--length >= 0) 
    {
	char g;
	
	g = (*ch1 = *ch2++);
	/*
	 * Yuck.  Stuck.  To make sure we stay backward compatible, we
	 * must assume that either CR or LF terminates the message and
	 * not CR-LF.  By allowing CR or LF (alone) into the body of
	 * messages, backward compatibility is lost and major problems
	 * will arise. - Avalon
	 */
	if (g < '\16' && (g == '\n' || g == '\r')) {
	    if (ch1 == cptrbuf)
		continue;		/* Skip extra LF/CR's */
	    *ch1 = '\0';
	    me.receiveM += 1;	/* Update messages received */
	    cptr->receiveM += 1;
	    if (lptr)
		lptr->receiveM += 1;
	    cptr->count = 0;	/*
				 * ...just in case parse returns with
				 * FLUSH_BUFFER without removing the
				 * structure pointed by cptr... --msa 
				 */
	    switch (parse(cptr, cptr->buffer, ch1))
	    {
	    case FLUSH_BUFFER:
		return FLUSH_BUFFER;
		
	    case ZIP_NEXT_BUFFER:
		if(length)
		{
		    int err;
		    ch2 = zip_input(cptr->serv->zip_in, ch2, &length,
				    &err, &nbuf, &nlen);
		    
		    if(length == -1)
		    {
			sendto_realops("Zipin error for %s: (%d) %s\n",
				       cptr->name, err, ch2);
			return exit_client(cptr, cptr, &me,
					   "fatal error in zip_input!");
		    }
		}
		break;

#ifdef HAVE_ENCRYPTION_ON
	    case RC4_NEXT_BUFFER:
		if(length)
		    rc4_process_stream(cptr->serv->rc4_in, ch2, length);
		break;
#endif

	    default:
		break;
	    }
	    
	    /*
	     * Socket is dead so exit (which always returns with *
	     * FLUSH_BUFFER here).  - avalon
	     */
	    if (cptr->flags & FLAGS_DEADSOCKET)
		return exit_client(cptr, cptr, &me,
				   (cptr->flags & FLAGS_SENDQEX) ?
				   "SendQ exceeded" : "Dead socket");
	    ch1 = cptrbuf;
	}
	else if (ch1 < cptrbuf + (sizeof(cptr->buffer) - 1))
	    ch1++;			/* There is always room for the null */
    }
    cptr->count = ch1 - cptrbuf;
    
    if(nbuf)
    {
#if 0   /* this message is annoying and not quite that useful */
	static time_t last_complain = 0;
	static int numrepeat = 0;
	
	numrepeat++;
	
	if(NOW > (last_complain + 300)) /* if more than 5 mins have elapsed */
	{
	    if(last_complain == 0)
	    {
		sendto_realops("Overflowed zipInBuf! "
			       "If you see this a lot, you should increase "
			       "zipInBufSize in src/zlink.c.");
	    }
	    else
	    {
		sendto_realops("Overflowed zipInBuf %d time%s in the "
			       "last %d minutes. If you see this a lot, you "
			       "should increase zipInBufSize in src/zlink.c.",
			       numrepeat, numrepeat == 1 ? "" : "s",
			       (NOW - last_complain) / 60);
	    }
	    last_complain = NOW;
	    numrepeat = 0;
	}
#endif

	buffer = nbuf;
	length = nlen;
	nbuf = NULL;
	goto zcontinue; /* gross, but it should work.. */
    }   
    
    return 0;
}

int client_dopacket(aClient *cptr, char *buffer, int length)
{
    
    strncpy(cptr->buffer, buffer, BUFSIZE);
    length = strlen(cptr->buffer);
    
    /* Update messages received */
    ++me.receiveM;
    ++cptr->receiveM;
   
    /* Update bytes received */
    cptr->receiveB += length;
   
    if (cptr->receiveB > 1023)
    {
	cptr->receiveK += (cptr->receiveB >> 10);
	cptr->receiveB &= 0x03ff; /* 2^10 = 1024, 3ff = 1023 */
    }
    me.receiveB += length;
    
    if (me.receiveB > 1023)
    {
	me.receiveK += (me.receiveB >> 10);
	me.receiveB &= 0x03ff;
    }
    
    cptr->count = 0;    /* ...just in case parse returns with */
    if (FLUSH_BUFFER == parse(cptr, cptr->buffer, cptr->buffer + length))
    {
	/*
	 * CLIENT_EXITED means actually that cptr
	 * structure *does* not exist anymore!!! --msa
	 */
	return FLUSH_BUFFER;
    }
    else if (cptr->flags & FLAGS_DEADSOCKET)
    {
	/*
	 * Socket is dead so exit (which always returns with
	 * CLIENT_EXITED here).  - avalon
	 */
	return exit_client(cptr, cptr, &me,
			   (cptr->flags & FLAGS_SENDQEX) ?
			   "SendQ exceeded" : "Dead socket");
    }
    return 1;
}
