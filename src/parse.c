/************************************************************************
 *   IRC - Internet Relay Chat, src/parse.c
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
#define MSGTAB
#include "msg.h"
#undef MSGTAB
#include "sys.h"
#include "numeric.h"
#include "h.h"

#if defined( HAVE_STRING_H )
#include <string.h>
#else
#include <strings.h>
#endif

/* NOTE: parse() should not be called recursively by other functions! */
static char *para[MAXPARA + 1];
static int  cancel_clients(aClient *, aClient *, char *);
static void remove_unknown(aClient *, char *, char *);

static char sender[HOSTLEN + 1];
static int  cancel_clients(aClient *, aClient *, char *);
static void remove_unknown(aClient *, char *, char *);

static struct Message *do_msg_tree(MESSAGE_TREE *, char *, struct Message *);
static struct Message *tree_parse(char *);

int num_msg_trees = 0;

/*
 * parse a buffer.
 * 
 * NOTE: parse() should not be called recusively by any other functions!
 */

int parse(aClient *cptr, char *buffer, char *bufend)
{
    aClient *from = cptr;
    char *ch, *s;
    int i, numeric = 0, paramcount;
    struct Message *mptr;

#ifdef DUMP_DEBUG
    if(dumpfp!=NULL) 
    {
	fprintf(dumpfp, "<- %s: %s\n", (cptr->name ? cptr->name : "*"),
		buffer);
	fflush(dumpfp);
    }
#endif
    Debug((DEBUG_DEBUG, "Parsing %s: %s", get_client_name(cptr, TRUE),
	   buffer));
    
    if (IsDead(cptr))
	return -1;
    
    s = sender;
    *s = '\0';
    
    for (ch = buffer; *ch == ' '; ch++);	/* skip spaces */
    
    para[0] = from->name;
    if (*ch == ':') 
    {
	/*
	 * Copy the prefix to 'sender' assuming it terminates with
	 * SPACE (or NULL, which is an error, though).
	 */
	
	for (++ch; *ch && *ch != ' '; ++ch)
	    if (s < (sender + HOSTLEN))
		*s++ = *ch;		
	*s = '\0';
	
	/*
	 * Actually, only messages coming from servers can have the
	 * prefix--prefix silently ignored, if coming from a user
	 * client...
	 * 
	 * ...sigh, the current release "v2.2PL1" generates also null
	 * prefixes, at least to NOTIFY messages (e.g. it puts
	 * "sptr->nickname" as prefix from server structures where it's
	 * null--the following will handle this case as "no prefix" at
	 * all --msa  (": NOTICE nick ...")
	 */
	
	if (*sender && IsServer(cptr)) 
	{
	    from = find_client(sender, (aClient *) NULL);

	    /*
	     * okay, this doesn't seem to do much here.
	     * from->name _MUST_ be equal to sender. 
	     * That's what find_client does.
	     * find_client will find servers too, and since we don't use server
	     * masking, the find server call is useless (and very wasteful).
	     * now, there HAS to be a from and from->name and
	     * sender have to be the same
	     * for us to get to the next if. but the next if
	     * starts out with if(!from)
	     * so this is UNREACHABLE CODE! AGH! - lucas
	     *
	     *  if (!from || mycmp(from->name, sender))
	     *     from = find_server(sender, (aClient *) NULL);
	     *  else if (!from && strchr(sender, '@'))
	     *     from = find_nickserv(sender, (aClient *) NULL);
	     */

	    para[0] = sender;
	    /*
	     * Hmm! If the client corresponding to the prefix is not
	     * found--what is the correct action??? Now, I will ignore the
	     * message (old IRC just let it through as if the prefix just
	     * wasn't there...) --msa
	     */
	    if (!from) 
	    {
		Debug((DEBUG_ERROR, "Unknown prefix (%s)(%s) from (%s)",
		       sender, buffer, cptr->name));

		ircstp->is_unpf++;
		remove_unknown(cptr, sender, buffer);
		 
		return -1;
	    }

	    if (from->from != cptr) 
	    {
		ircstp->is_wrdi++;
		Debug((DEBUG_ERROR, "Message (%s) coming from (%s)",
		       buffer, cptr->name));
		
		return cancel_clients(cptr, from, buffer);
	    }
	}
	while (*ch == ' ')
	    ch++;
    }

    if (*ch == '\0') 
    {
	ircstp->is_empt++;
	Debug((DEBUG_NOTICE, "Empty message from host %s:%s",
	       cptr->name, from->name));
	return (-1);
    }
    /*
     * Extract the command code from the packet.  Point s to the end
     * of the command code and calculate the length using pointer
     * arithmetic.  Note: only need length for numerics and *all*
     * numerics must have parameters and thus a space after the command
     * code. -avalon
     * 
     * ummm???? - Dianora
     */

    /* check for numeric */
    if (*(ch + 3) == ' ' && IsDigit(*ch) && IsDigit(*(ch + 1)) &&
	IsDigit(*(ch + 2))) 
    {
	mptr = (struct Message *) NULL;
	numeric = (*ch - '0') * 100 + (*(ch + 1) - '0') *
	    10 + (*(ch + 2) - '0');
	paramcount = MAXPARA;
	ircstp->is_num++;
	s = ch + 3;
	*s++ = '\0';
    }
    else 
    {
	s = strchr(ch, ' ');
	
	if (s)
	    *s++ = '\0';
	
	mptr = tree_parse(ch);
	
	if (!mptr || !mptr->cmd) 
	{
	    /*
	     * only send error messages to things that actually sent
	     * buffers to us and only people, too.
	     */
	    if (buffer[0] != '\0') 
	    {
		if (IsPerson(from))
		    sendto_one(from, ":%s %d %s %s :Unknown command",
			       me.name, ERR_UNKNOWNCOMMAND, from->name, ch);
		Debug((DEBUG_ERROR, "Unknown (%s) from %s",
		       ch, get_client_name(cptr, TRUE)));
	    }
	    ircstp->is_unco++;
	    return -1;
	}
	
	paramcount = mptr->parameters;
	i = bufend - ((s) ? s : ch);
	mptr->bytes += i;
	/*
	 * Allow only 1 msg per 2 seconds (on average) to prevent
	 * dumping. to keep the response rate up, bursts of up to 5 msgs
	 * are allowed -SRB Opers can send 1 msg per second, burst of ~20
	 * -Taner
	 */
	if ((mptr->flags & 1) && !(IsServer(cptr))) 
	{
        if (!NoMsgThrottle(cptr))
        {
#ifdef NO_OPER_FLOOD
            if (IsAnOper(cptr))
                /* "randomly" (weighted) increase the since */
                cptr->since += (cptr->receiveM % 10) ? 1 : 0;
            else
#endif
                cptr->since += (2 + i / 120);
        }
    }
    }
    /*
     * Must the following loop really be so devious? On surface it
     * splits the message to parameters from blank spaces. But, if
     * paramcount has been reached, the rest of the message goes into
     * this last parameter (about same effect as ":" has...) --msa
     */

    /* Note initially true: s==NULL || *(s-1) == '\0' !! */
    
    i = 1;
    if (s) 
    {
	if (paramcount > MAXPARA)
	    paramcount = MAXPARA;
	for (;;) 
	{
	    while (*s == ' ')
		*s++ = '\0';
	    
	    if (*s == '\0')
		break;
	    if (*s == ':') 
	    {
		/* The rest is a single parameter */
		para[i++] = s + 1;
		break;
	    }
	    para[i++] = s;
	    if (i >= paramcount)
            {
                if(paramcount == MAXPARA && strchr(s, ' '))
                {
                   sendto_realops_lev(DEBUG_LEV, "Overflowed MAXPARA on %s from %s",
			   mptr ? mptr->cmd : "numeric",
			   get_client_name(cptr, (IsServer(cptr) ? HIDEME : TRUE)));
                }
		break;
            }
	    
	    while(*s && *s != ' ')
		s++;
	}
    }
    
    para[i] = NULL;
    if (mptr == (struct Message *) NULL)
	return (do_numeric(numeric, cptr, from, i, para));
    
    mptr->count++;
    
    /* patch to avoid server flooding from unregistered connects */
    /*
     * check allow_unregistered_use flag I've set up instead of function
     * comparing *yech* - Dianora
     */
    
    if (!IsRegistered(cptr) && !mptr->allow_unregistered_use) {
	sendto_one(from, ":%s %d %s %s :Register first.",
		   me.name, ERR_NOTREGISTERED, from->name, ch);
	return -1;
    }
    
    if (IsRegisteredUser(cptr) && mptr->reset_idle)
	from->user->last = timeofday;
    
    return (*mptr->func) (cptr, from, i, para);
}

/*
 * init_tree_parse()
 * 
 * inputs               - pointer to msg_table defined in msg.h output
 *  NONE side effects   - MUST MUST be called at startup ONCE before
 * any other keyword hash routine is used.
 * 
 * -Dianora, orabidoo
 */

/* for qsort'ing the msgtab in place -orabidoo */
static int mcmp(struct Message *m1, struct Message *m2)
{
    return strcmp(m1->cmd, m2->cmd);
}

/* Initialize the msgtab parsing tree -orabidoo */
void init_tree_parse(struct Message *mptr)
{
    int i;
    struct Message *mpt = mptr;
    
    for (i = 0; mpt->cmd; mpt++)
	i++;
    qsort((void *) mptr, i, sizeof(struct Message),
	  (int (*)(const void *, const void *)) mcmp);
    
    msg_tree_root = (MESSAGE_TREE *) MyMalloc(sizeof(MESSAGE_TREE));
    num_msg_trees++;
    mpt = do_msg_tree(msg_tree_root, "", mptr);
    /*
     * this happens if one of the msgtab entries included characters
     * other than capital letters  -orabidoo
     */
    if (mpt->cmd)
    {
	fprintf(stderr, "bad msgtab entry: ``%s''\n", mpt->cmd);
	exit(1);
    }
}

/* Recursively make a prefix tree out of the msgtab -orabidoo */
static struct Message *do_msg_tree(MESSAGE_TREE * mtree, char *prefix,
				   struct Message *mptr)
{
    char newpref[64];	/* must be longer than any command */
    int c, c2, lp;
    MESSAGE_TREE *mtree1;
    
    lp = strlen(prefix);
    if (!lp || !strncmp(mptr->cmd, prefix, lp))
    {
	if (!mptr[1].cmd || (lp && strncmp(mptr[1].cmd, prefix, lp)))
	{
	    /* non ambiguous, make a final case */
	    mtree->final = mptr->cmd + lp;
	    mtree->msg = mptr;
	    for (c = 0; c <= 25; c++)
		mtree->pointers[c] = NULL;
	    return mptr + 1;
	}
	else
	{
	    /* ambigous, make new entries for each of the letters that match */
	    if (!mycmp(mptr->cmd, prefix))
	    {
		mtree->final = (void *) 1;
		mtree->msg = mptr;
		mptr++;
	    }
	    else
		mtree->final = NULL;
	    
	    for (c = 'A'; c <= 'Z'; c++)
	    {
		if (mptr->cmd[lp] == c)
		{
		    mtree1 = (MESSAGE_TREE *) MyMalloc(sizeof(MESSAGE_TREE));
		    num_msg_trees++;
		    mtree1->final = NULL;
		    mtree->pointers[c - 'A'] = mtree1;
		    strcpy(newpref, prefix);
		    newpref[lp] = c;
		    newpref[lp + 1] = '\0';
		    mptr = do_msg_tree(mtree1, newpref, mptr);
		    if (!mptr->cmd || strncmp(mptr->cmd, prefix, lp))
		    {
			for (c2 = c + 1 - 'A'; c2 <= 25; c2++)
			    mtree->pointers[c2] = NULL;
			return mptr;
		    }
		}
		else
		{
		    mtree->pointers[c - 'A'] = NULL;
		}
	    }
	    return mptr;
	}
    }
    else
    {
	fprintf(stderr, "do_msg_tree: this should never happen!\n");
	exit(1);
    }
}

/*
 * tree_parse()
 * 
 * inputs               
 * - pointer to command in upper case output NULL pointer if not found 
 * struct Message pointer to command entry if found 
 * side effects        - NONE
 * 
 * -Dianora, orabidoo
 */
static struct Message *tree_parse(char *cmd)
{
    char    r;
    MESSAGE_TREE *mtree = msg_tree_root;
    
    while ((r = *cmd++))
    {
	r &= 0xdf;		/*
				 * some touppers have trouble w/ 
				 * lowercase, says Dianora 
				 */
	if (r < 'A' || r > 'Z')
	    return NULL;
	mtree = mtree->pointers[r - 'A'];
	if (!mtree)
	    return NULL;
	if (mtree->final == (void *) 1)
	{
	    if (!*cmd)
		return mtree->msg;
	}
	else if (mtree->final && !mycmp(mtree->final, cmd))
	    return mtree->msg;
    }
    return ((struct Message *) NULL);
}

/* field breakup for ircd.conf file. */
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

static int cancel_clients(aClient *cptr, aClient *sptr, char *cmd)
{
    /*
     * kill all possible points that are causing confusion here, I'm not
     * sure I've got this all right... - avalon
     * 
     * knowing avalon, probably not.
     */
    /*
     * with TS, fake prefixes are a common thing, during the connect
     * burst when there's a nick collision, and they must be ignored
     * rather than killed because one of the two is surviving.. so we
     * don't bother sending them to all ops everytime, as this could
     * send 'private' stuff from lagged clients. we do send the ones
     * that cause servers to be dropped though, as well as the ones
     * from * non-TS servers -orabidoo
     */
    /*
     * Incorrect prefix for a server from some connection.  If it is a
     * client trying to be annoying, just QUIT them, if it is a server
     * then the same deal.
    */
    if (IsServer(sptr) || IsMe(sptr))
    {
	/* Sorry, but at the moment this is just too much for even opers 
	   to see. -Rak */
	/* or we could just take out the message. <EG>  -wd */
	sendto_realops_lev(DEBUG_LEV, "Message for %s[%s] from %s",
			   sptr->name, sptr->from->name,
			   get_client_name(cptr, 
					   (IsServer(cptr) ? HIDEME : TRUE)));
	if (IsServer(cptr))
	{
	    sendto_realops_lev(DEBUG_LEV,
			       "Not dropping server %s (%s) for "
			       "Fake Direction", cptr->name, sptr->name);
	    return -1;
	}
	
	if (IsClient(cptr))
	    sendto_realops_lev(DEBUG_LEV,
			       "Would have dropped client %s (%s@%s) "
			       "[%s from %s]", cptr->name, 
			       cptr->user->username, cptr->user->host,
			       cptr->user->server, cptr->from->name);
	return -1;
    }
    /*
     * Ok, someone is trying to impose as a client and things are
     * confused.  If we got the wrong prefix from a server, send out a
     * kill, else just exit the lame client.
     */
    if (IsServer(cptr))
    {
	/*
	 * If the fake prefix is coming from a TS server, discard it
	 * silently -orabidoo
	 * also drop it if we're gonna kill services by not doing so }:/
	 */
	if (DoesTS(cptr))
	{
	    if (sptr->user)
		sendto_realops_lev(DEBUG_LEV,
				   "Message for %s[%s@%s!%s] from %s "
				   "(TS, ignored)", sptr->name,
				   sptr->user->username, sptr->user->host,
				   sptr->from->name,
				   get_client_name(cptr, TRUE));
	    return 0;
	}
	else
	{
	    if (sptr->user)
		sendto_realops_lev(DEBUG_LEV,
				   "Message for %s[%s@%s!%s] from %s",
				   sptr->name, sptr->user->username,
				   sptr->user->host,
				   sptr->from->name,
				   get_client_name(cptr, (IsServer(cptr) ? 
							  HIDEME : TRUE)));
	    if(IsULine(sptr))
	    {
		sendto_realops_lev(DEBUG_LEV,
				   "Would have killed U:lined client %s "
				   "for fake direction", sptr->name);
		return 0;
	    }
	    sendto_serv_butone(NULL,
			       ":%s KILL %s :%s (%s[%s] != %s, Fake Prefix)",
			       me.name, sptr->name, me.name,
			       sptr->name, sptr->from->name,
			       get_client_name(cptr, (IsServer(cptr) ?
						      HIDEME : TRUE)));
	    sptr->flags |= FLAGS_KILLED;
	    return exit_client(cptr, sptr, &me, "Fake Prefix");
	}
    }
    return exit_client(cptr, cptr, &me, "Fake prefix");
}

static void remove_unknown(aClient *cptr, char *sender, char *buffer)
{
    if (!IsRegistered(cptr))
	return;

    if (IsClient(cptr))
    {
	sendto_realops_lev(DEBUG_LEV,
			   "Weirdness: Unknown client prefix (%s) from %s, "
			   "Ignoring %s", buffer,
			   get_client_name(cptr, FALSE), sender);
	return;
    }
    /* Not from a server so don't need to worry about it. */
    if (!IsServer(cptr))
	return;
    /*
     * Do kill if it came from a server because it means there is a
     * ghost user on the other server which needs to be removed. -avalon
     * Tell opers about this. -Taner
     */
    if (!strchr(sender, '.'))
	sendto_one(cptr, ":%s KILL %s :%s (%s(?) <- %s)",
		   me.name, sender, me.name, sender,
		   get_client_name(cptr, FALSE));
    else
    {
	sendto_realops_lev(DEBUG_LEV, 
			   "Unknown prefix (%s) from %s, Squitting %s",
			   buffer, get_client_name(cptr, HIDEME), sender);
	sendto_one(cptr, ":%s SQUIT %s :(Unknown prefix (%s) from %s)",
		   me.name, sender, buffer, get_client_name(cptr, HIDEME));
    }
}
