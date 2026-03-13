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

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "h.h"
#define MSGTAB
#include "msg.h"
#undef MSGTAB
#include "mapi.h"
#include "cmds.h"
#include "hooks.h"
#include "memcount.h"

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

static struct Message *do_msg_tree(MESSAGE_TREE *, char *, struct Message *);
static struct Message *tree_parse(char *);

int num_msg_trees = 0;

/*
 * current_alias_info — set by parse() immediately before calling an alias
 * handler.  m_aliased() and m_sjr() read this to get their AliasInfo*.
 * Only valid during an alias handler call; NULL at all other times.
 */
AliasInfo *current_alias_info = NULL;

/*
 * dispatch_serial — incremented before each handler call.
 * Tag generators (server_time_tag, msgid_tag, etc.) use this to cache
 * a single value per message so all recipients of one dispatch get the
 * same tag value.
 */
int  dispatch_serial = 0;

/*
 * lr_echo_sent — set to 1 by m_echo_message when it sends an echo that
 * carries the @label= tag.  Cleared by parse() before each dispatch so
 * that m_labeled_response's CHOOK_POSTDISPATCH hook can decide whether
 * to send an empty BATCH ACK.
 */
int  lr_echo_sent = 0;

/*
 * current_dispatch_label — the value of the @label= IRCv3 tag from the
 * current incoming message, or "" if none.  Used by labeled-response.
 * Cleared after each handler returns.
 */
char current_dispatch_label[256] = "";

/*
 * current_dispatch_source — the source (sptr/from) of the current dispatch.
 * Used by outbound tag generators (e.g. account-tag) that need to know who
 * is sending.  Set before handler call, cleared after.
 */
aClient *current_dispatch_source = NULL;

/* ---------------------------------------------------------------------------
 * Generic sentinel handlers
 *
 * These are placed in mapi_cmd_av2 / msgtab handler slots to provide
 * uniform error responses without boilerplate in every module.
 * ---------------------------------------------------------------------------
 */

/* mg_ignore — silently drop the message */
int
mg_ignore(struct MsgBuf *mb, aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    (void)mb; (void)cptr; (void)sptr; (void)parc; (void)parv;
    return 0;
}

/* mg_unreg — send ERR_NOTREGISTERED */
int
mg_unreg(struct MsgBuf *mb, aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    (void)mb; (void)cptr; (void)parc;
    sendto_one(sptr, err_str(ERR_NOTREGISTERED), me.name,
               parv[0][0] ? parv[0] : "*");
    return -1;
}

/* mg_reg — send ERR_ALREADYREGISTRED */
int
mg_reg(struct MsgBuf *mb, aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    (void)mb; (void)cptr; (void)parc;
    sendto_one(sptr, err_str(ERR_ALREADYREGISTRED), me.name, parv[0]);
    return 0;
}

/* mg_not_oper — send ERR_NOPRIVILEGES */
int
mg_not_oper(struct MsgBuf *mb, aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    (void)mb; (void)cptr; (void)parc;
    sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
    return 0;
}

/* ---------------------------------------------------------------------------
 * Dynamic command registry
 *
 * A small open-addressing hash table that maps command names to Message
 * structs.  parse() checks this table whenever the static trie misses,
 * allowing loadable modules to register new IRC commands at runtime.
 * ---------------------------------------------------------------------------
 */

#define CMD_HASH_SIZE 64  /* power-of-two keeps the modulo cheap */

typedef struct dyn_cmd {
    char          name[32];  /* uppercase command name (key)        */
    struct Message msg;      /* embedded Message (no extra alloc)   */
    struct dyn_cmd *next;    /* chaining for collisions             */
} dyn_cmd_t;

static dyn_cmd_t *cmd_table[CMD_HASH_SIZE];

static unsigned int cmd_hash(const char *s)
{
    unsigned int h = 0;
    while (*s)
        h = h * 31u + (unsigned char)(*s++ & 0xdf);  /* fold to uppercase */
    return h % CMD_HASH_SIZE;
}

/* cmd_find_dynamic - called from parse() as trie fallback */
struct Message *cmd_find_dynamic(const char *cmd)
{
    unsigned int h = cmd_hash(cmd);
    dyn_cmd_t *e;
    for (e = cmd_table[h]; e; e = e->next)
        if (mycmp(e->name, cmd) == 0)
            return &e->msg;
    return NULL;
}

int cmd_add(const struct mapi_cmd_av2 *av2)
{
    char upper[32];
    unsigned int h;
    int i;
    dyn_cmd_t *e;

    if (!av2 || !av2->cmd)
        return -1;

    /* Convert to uppercase */
    for (i = 0; av2->cmd[i] && i < 31; i++)
        upper[i] = av2->cmd[i] & 0xdf;
    upper[i] = '\0';

    /* Refuse to shadow a static command */
    if (tree_parse(upper))
        return -1;

    /* Refuse duplicate dynamic registration */
    if (cmd_find_dynamic(upper))
        return -1;

    h = cmd_hash(upper);
    e = (dyn_cmd_t *) MyMalloc(sizeof(dyn_cmd_t));
    memset(e, 0, sizeof(*e));
    strncpy(e->name, upper, 31);
    e->msg.cmd        = e->name;
    e->msg.reset_idle = av2->reset_idle;
    e->msg.aliasidx   = -1;  /* modules never declare alias entries */
    memcpy(e->msg.handlers, av2->handlers, sizeof(av2->handlers));
    e->next           = cmd_table[h];
    cmd_table[h]      = e;
    return 0;
}

void cmd_del(const char *cmd)
{
    char upper[32];
    unsigned int h;
    int i;
    dyn_cmd_t *e, **prev;

    for (i = 0; cmd[i] && i < 31; i++)
        upper[i] = cmd[i] & 0xdf;
    upper[i] = '\0';

    h = cmd_hash(upper);
    prev = &cmd_table[h];
    for (e = cmd_table[h]; e; prev = &e->next, e = e->next) {
        if (mycmp(e->name, upper) == 0) {
            *prev = e->next;
            MyFree(e);
            return;
        }
    }
}

/*
 * parse a buffer.
 *
 * NOTE: parse() should not be called recursively by any other functions!
 */

int parse(aClient *cptr, char *buffer, char *bufend)
{
    aClient *from = cptr;
    char *ch, *s;
    int i, numeric = 0, paramcount;
    struct Message *mptr;
    struct MsgBuf msgbuf;
    HandlerType ht;
    MessageEntry *slot;
    mapi_cmd_fn fn;

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

    /* Initialize MsgBuf; tags will be filled if the line starts with '@' */
    memset(&msgbuf, 0, sizeof(msgbuf));

    for (ch = buffer; *ch == ' '; ch++);	/* skip leading spaces */

    /* --- IRCv3 message tags --- */
    if (*ch == '@')
    {
        ch = parse_msgbuf(&msgbuf, ch + 1);
        /* parse_msgbuf advances past the tag block and trailing spaces */
        while (*ch == ' ')
            ch++;
    }

    /* Extract @label= for labeled-response support */
    {
        const char *lv = msgbuf_get_tag(&msgbuf, "label");
        if (lv)
            strncpy(current_dispatch_label, lv, sizeof(current_dispatch_label) - 1);
        else
            current_dispatch_label[0] = '\0';
    }

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
	 */

	if (*sender && IsServer(cptr))
	{
	    from = find_client(sender, (aClient *) NULL);

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
	    mptr = cmd_find_dynamic(ch);

	if (!mptr || !mptr->cmd)
	{
	    sendto_realops_lev(DEBUG_LEV,
		"Unknown command '%s' from %s[%s]", ch,
		from->name, get_client_name(cptr, FALSE));
	    ircstp->is_unco++;
	    return -1;
	}

	paramcount = MAXPARA;
	i = bufend - ((s) ? s : ch);
	mptr->bytes += i;
	/*
	 * Allow only 1 msg per 2 seconds (on average) to prevent
	 * dumping.
	 */
	if (!IsServer(cptr))
	{
        if (!NoMsgThrottle(cptr))
        {
#ifdef NO_OPER_FLOOD
            if (IsAnOper(cptr))
                cptr->since += (cptr->receiveM % 10) ? 1 : 0;
            else
#endif
                cptr->since += (2 + i / 120);
        }
    }
    }
    /*
     * Split the message into parameters.
     */

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
			   get_client_name(cptr, (IsServer(cptr) ? HIDEME : FALSE)));
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

    /* ---------------------------------------------------------------
     * Per-HandlerType dispatch
     * --------------------------------------------------------------- */

    /* Determine the handler type from the connection state */
    if      (!IsRegistered(cptr))    ht = HANDLER_UNREG;
    else if (IsServer(cptr) ||
             IsGoPeer(cptr))         ht = HANDLER_SERVER;
    else if (!MyConnect(cptr))       ht = HANDLER_REMOTE;
    else if (IsAnOper(cptr))         ht = HANDLER_OPER;
    else                             ht = HANDLER_CLIENT;

    /* For alias commands, set current_alias_info before dispatch */
    if (mptr->aliasidx >= 0)
        current_alias_info = &aliastab[mptr->aliasidx];
    else
        current_alias_info = NULL;

    slot = &mptr->handlers[ht];
    fn   = slot->handler ? slot->handler : mg_ignore;

    if (fn == mg_ignore)
    {
        current_alias_info = NULL;
        return 0;
    }

    /* Minimum parameter count check */
    if (slot->min_para && i < slot->min_para)
    {
        sendto_one(from, err_str(ERR_NEEDMOREPARAMS), me.name,
                   para[0], mptr->cmd);
        current_alias_info = NULL;
        return 0;
    }

    /* Update idle timestamp for CLIENT and OPER if requested */
    if (mptr->reset_idle && (ht == HANDLER_CLIENT || ht == HANDLER_OPER)
        && from->user)
        from->user->last = timeofday;

    lr_echo_sent = 0;
    current_dispatch_source = from;
    dispatch_serial++;
    i = fn(&msgbuf, cptr, from, i, para);
    current_alias_info = NULL;
    if (current_dispatch_label[0])
        call_hooks(CHOOK_POSTDISPATCH, from);
    current_dispatch_label[0] = '\0';
    current_dispatch_source = NULL;
    return i;
}

/*
 * init_tree_parse()
 *
 * inputs               - pointer to msg_table defined in msg.h
 * side effects         - MUST be called at startup ONCE before
 * any other keyword hash routine is used.
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
	    /* ambiguous, make new entries for each of the letters that match */
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
 */
static struct Message *tree_parse(char *cmd)
{
    char    r;
    MESSAGE_TREE *mtree = msg_tree_root;

    while ((r = *cmd++))
    {
	r &= 0xdf;
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
    if (IsServer(sptr) || IsMe(sptr))
    {
	sendto_realops_lev(DEBUG_LEV, "Message for %s[%s] from %s",
			   sptr->name, sptr->from->name,
			   get_client_name(cptr,
					   (IsServer(cptr) ? HIDEME : FALSE)));
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
    if (IsServer(cptr))
    {
	if (DoesTS(cptr))
	{
	    if (sptr->user)
		sendto_realops_lev(DEBUG_LEV,
				   "Message for %s[%s@%s!%s] from %s "
				   "(TS, ignored)", sptr->name,
				   sptr->user->username, sptr->user->host,
				   sptr->from->name,
				   get_client_name(cptr, HIDEME));
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
				   get_client_name(cptr, HIDEME));
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
			       get_client_name(cptr, HIDEME));
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
    if (!IsServer(cptr))
	return;
    if (!strchr(sender, '.'))
	sendto_one(cptr, ":%s KILL %s :%s (%s(?) <- %s)",
		   me.name, sender, me.name, sender,
		   get_client_name(cptr, HIDEME));
    else
    {
	sendto_realops_lev(DEBUG_LEV,
			   "Unknown prefix (%s) from %s, Squitting %s",
			   buffer, get_client_name(cptr, HIDEME), sender);
	sendto_one(cptr, ":%s SQUIT %s :(Unknown prefix (%s) from %s)",
		   me.name, sender, buffer, get_client_name(cptr, HIDEME));
    }
}

static u_long
r_msgtree_memcount(MESSAGE_TREE *mptr, int *count)
{
    size_t  i;
    u_long  m = sizeof(*mptr);

    (*count)++;

    for (i = 0; i < sizeof(mptr->pointers)/sizeof(mptr->pointers[0]); i++)
        if (mptr->pointers[i])
            m += r_msgtree_memcount(mptr->pointers[i], count);

    return m;
}

u_long
memcount_parse(MCparse *mc)
{
    mc->file = __FILE__;

    mc->msgnodes.m = r_msgtree_memcount(msg_tree_root, &mc->msgnodes.c);

    mc->total.c += mc->msgnodes.c;
    mc->total.m += mc->msgnodes.m;

    mc->s_bufs.c++;
    mc->s_bufs.m += sizeof(para);
    mc->s_bufs.c++;
    mc->s_bufs.m += sizeof(sender);

    mc->s_msgtab.c = sizeof(msgtab)/sizeof(msgtab[0]);
    mc->s_msgtab.m = sizeof(msgtab);

    return mc->total.m;
}
