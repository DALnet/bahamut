/************************************************************************
 *   Bahamut IRCd, src/confparse.c
 *   Copyright (C) 2004, Aaron Wiebe
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
#include "confparse.h"
#include "h.h"
#include "userban.h"

/* notes on confparse.c
 * While this initial revision requires a fair bit of trimming down,
 * my primary goal right now was to build an extendable system that will
 * allow for fairly easy changes to the config file.
 * Heres a few notes on how to go about that.
 *
 * The parser works on two primary depths - blocks and tokens:
 *
 * block { 
 *      token value;
 *      token "string value";
 *      token 123;      # int value
 *      token;          # nonvar token
 * };
 *
 * It can also parse non-token blocks:
 *
 * block (
 *      "string string string";
 *      "string blah";
 * };
 *
 * Blocks are defined by tconftab (in confparse.h)
 * Tokens are defined by sconftab (^^^^^^^^^^^^^^)
 *
 * Each block must have a function that takes the values collected
 * and checks them against the requirements.  These functions are also
 * handy for getting variables out of the array that they are stored in.
 *
 * The array variables are placed in (an array of cVar structs) contains
 * all values for the the block, and the corrisponding sconftab item.
 *
 * I feel the need to rewrite large sections of this still, but I'll just
 * be happy to have it working for now.
 *
 * Feb 24/04
 * -epi
 */

extern int forked;

extern void confadd_oper(char *, char *, char *, char *, char *);
extern void confadd_connect(char *, char *, char *, char *, int, char *,
                            char *, char *);
extern void confadd_allow(char *, char *, char *, int, char *);
extern void confadd_port(int, char *, char *);
extern void confadd_me(char *, char *, char *, char *, char *, char *, char *);
extern void confadd_class(char *, int, int, int, long);
extern void confadd_restrict(int, char *, char *);
extern void confadd_kill(char *, char *, char *);
extern void confadd_uline(char *);

/* free_vars()
 * clear our temp variable array used by parse_block and children
 */

static void
free_vars(cVar *vars[])
{
    int i = 0;

    while(vars[i])
    {
        MyFree(vars[i]->value);
        MyFree(vars[i]);
        i++;
    }
}

/* error handler */

static void
confparse_error(char *problem, int line)
{
    if(!forked)
        printf("ERROR:  %s near line %d\n", problem, line);
    else
        sendto_realops("Conf Error:  %s near line %d", problem, line);
    return;
}

/* confparse_ functions
 * for each major block (see tconftab[] in confparse.h)
 * we have a function called to check the sanity of the block
 * after its read and before we add it to our lists
 */

static void
confparse_global(cVar *vars[], int lnum)
{
    cVar *tmp;
    int i = 0;
    char *name = NULL, *info = NULL, *dpass = NULL, *rpass = NULL;

    for(tmp = vars[i]; tmp; tmp = vars[++i])
        if(tmp->type->flag & SCONFF_NAME)
        {
            name = tmp->value;
            break;
        }
    i = 0;
    for(tmp = vars[i]; tmp; tmp = vars[++i])
        if(tmp->type->flag & SCONFF_INFO)
        {
            info = tmp->value;
            break;
        }
    i = 0;
    for(tmp = vars[i]; tmp; tmp = vars[++i])
        if(tmp->type->flag & SCONFF_DPASS)
        {
            dpass = tmp->value;
            break;
        }
    i = 0;
    for(tmp = vars[i]; tmp; tmp = vars[++i])
        if(tmp->type->flag & SCONFF_RPASS)
        {
            rpass = tmp->value;
            break;
        }
    if(!name)
    {
        confparse_error("Missing 'name' in global block", lnum);
        return;
    }
    if(!info)
    {
        confparse_error("Missing 'info' in global block", lnum);
        return;
    }
    confadd_me(name, info, dpass, rpass, 0, 0, 0);
    free_vars(vars);
    return;
}

static void
confparse_options(cVar *vars[], int lnum)
{
    free_vars(vars);
    return;
}

static void
confparse_class(cVar *vars[], int lnum)
{
    cVar *tmp;
    char *name = NULL;
    int pingfreq = 0, connfreq = 0, maxusers = 0;
    long maxsendq = 0;
    int i = 0;

    for(tmp = vars[i]; tmp; tmp = vars[++i])
        if(tmp->type->flag & SCONFF_NAME)
        {
            name = tmp->value;
            break;
        }
    i = 0;
    for(tmp = vars[i]; tmp; tmp = vars[++i])
        if(tmp->type->flag & SCONFF_PINGFREQ)
        {
            pingfreq = atoi(tmp->value);
            break;
        }
    i = 0;
    for(tmp = vars[i]; tmp; tmp = vars[++i])
        if(tmp->type->flag & SCONFF_CONNFREQ)
        {
            connfreq = atoi(tmp->value);
            break;
        }
    i = 0;
    for(tmp = vars[i]; tmp; tmp = vars[++i])
        if(tmp->type->flag & SCONFF_MAXUSERS)
        {
            maxusers = atoi(tmp->value);
            break;
        }
    i = 0;
    for(tmp = vars[i]; tmp; tmp = vars[++i])
        if(tmp->type->flag & SCONFF_MAXSENDQ)
        {
            maxsendq = atoi(tmp->value);
            break;
        }
    if(!name)
    {
        confparse_error("Missing 'name' in class block", lnum);
        return;
    }
    if(pingfreq == 0)
    {
        confparse_error("Missing 'pingfreq' in class block", lnum);
        return;
    }
    confadd_class(name, pingfreq, connfreq, maxusers, maxsendq);
    free_vars(vars);
    return;
}

static void
confparse_allow(cVar *vars[], int lnum)
{
    cVar *tmp;
    char *host = NULL, *passwd = NULL, *class = NULL, *ipmask = NULL;
    int   port = 0, i = 0;

    for(tmp = vars[i]; tmp; tmp = vars[++i])
        if(tmp->type->flag & SCONFF_HOST)
        {
            host = tmp->value;
            break;
        }

    for(tmp = vars[i]; tmp; tmp = vars[++i])
        if(tmp->type->flag & SCONFF_IPMASK)
        {
            ipmask = tmp->value;
            break;
        }

    i = 0;
    for(tmp = vars[i]; tmp; tmp = vars[++i])
        if(tmp->type->flag & SCONFF_PASSWD)
        {
            passwd = tmp->value;
            break;
        }

    i = 0;
    for(tmp = vars[i]; tmp; tmp = vars[++i])
        if(tmp->type->flag & SCONFF_CLASS)
        {
            class = tmp->value;
            break;
        }

    i = 0;
    for(tmp = vars[i]; tmp; tmp = vars[++i])
        if(tmp->type->flag & SCONFF_PORT)
        {
            port = atoi(tmp->value);
            break;
        }
    if(!host && !ipmask)
    {
        confparse_error("Missing 'host' or 'ipmask' in allow block", lnum);
        return;
    }
    if(!class)
        class = "default";
    confadd_allow(ipmask, passwd, host, port, class);
    free_vars(vars);
    return;
}

static void
confparse_oper(cVar *vars[], int lnum)
{
    cVar *tmp;
    int i;
    char *name = NULL, *host = NULL, *passwd = NULL, *access = NULL, 
         *class = NULL;

    i = 0;
    for(tmp = vars[i]; tmp; tmp = vars[++i])
        if(tmp->type->flag & SCONFF_NAME)
        {
            name = tmp->value;
            break;
        }

    i = 0;
    for(tmp = vars[i]; tmp; tmp = vars[++i])
        if(tmp->type->flag & SCONFF_HOST)
        {
            host = tmp->value;
            break;
        }
    i = 0;
    for(tmp = vars[i]; tmp; tmp = vars[++i])
        if(tmp->type->flag & SCONFF_PASSWD)
        {
            passwd = tmp->value;
            break;
        }
    i = 0;
    for(tmp = vars[i]; tmp; tmp = vars[++i])
        if(tmp->type->flag & SCONFF_ACCESS)
        {
            access = tmp->value;
            break;
        }
    i = 0;
    for(tmp = vars[i]; tmp; tmp = vars[++i])
        if(tmp->type->flag & SCONFF_CLASS)
        {
            class = tmp->value;
            break;
        }

    if(!name)
    {
        confparse_error("Missing 'name' in oper block", lnum);
        return;
    }
    if(!host)
    {
        confparse_error("Missing 'host' in oper block", lnum);
        return;
    }
    if(!passwd)
    {
        confparse_error("Missing 'passwd' in oper block", lnum);
        return;
    }
    if(!access)
    {
        confparse_error("Missing 'access' in oper block", lnum);
        return;
    }
    if(!class)
        class = "default";
    confadd_oper(name, host, passwd, access, class);
    free_vars(vars);
    return;
}
    
static void
confparse_connect(cVar *vars[], int lnum)
{
    cVar *tmp;
    int i, port = 0;
    char *name = NULL, *host = NULL, *apasswd = NULL, *cpasswd = NULL, 
         *flags = NULL, *class = NULL, *bind = NULL;

    i = 0;
    for(tmp = vars[i]; tmp; tmp = vars[++i])
        if(tmp->type->flag & SCONFF_NAME)
        {
            name = tmp->value;
            break;
        }
    i = 0;
    for(tmp = vars[i]; tmp; tmp = vars[++i])
        if(tmp->type->flag & SCONFF_HOST)
        {
            host = tmp->value;
            break;
        }
    i = 0;
    for(tmp = vars[i]; tmp; tmp = vars[++i])
        if(tmp->type->flag & SCONFF_APASSWD)
        {
            apasswd = tmp->value;
            break;
        }
    i = 0;
    for(tmp = vars[i]; tmp; tmp = vars[++i])
        if(tmp->type->flag & SCONFF_CPASSWD)
        {
            cpasswd = tmp->value;
            break;
        }
    i = 0;
    for(tmp = vars[i]; tmp; tmp = vars[++i])
        if(tmp->type->flag & SCONFF_FLAGS)
        {
            flags = tmp->value;
            break;
        }
    i = 0;
    for(tmp = vars[i]; tmp; tmp = vars[++i])
        if(tmp->type->flag & SCONFF_CLASS)
        {
            class = tmp->value;
            break;
        }
    i = 0;
    for(tmp = vars[i]; tmp; tmp = vars[++i])
        if(tmp->type->flag & SCONFF_PORT)
        {
            port = atoi(tmp->value);
            break;
        }
    i = 0;
    for(tmp = vars[i]; tmp; tmp = vars[++i])
        if(tmp->type->flag & SCONFF_BIND)
        {
            bind = tmp->value;
            break;
        }
    if(!name)
    {
        confparse_error("Missing 'name' in connect block", lnum);
        return;
    }
    if(!host)
    {
        confparse_error("Missing 'host' in connect block", lnum);
        return;
    }
    if(!apasswd)
    {
        confparse_error("Missing 'apasswd' in connect block", lnum);
        return;
    }
    if(!cpasswd)
    {
        confparse_error("Missing 'cpasswd' in connect block", lnum);
        return;
    }
    if(!class)
        class = "default";
    confadd_connect(name, host, apasswd, cpasswd, port, flags, bind, class);
    free_vars(vars);
    return;
}

static void
confparse_port(cVar *vars[], int lnum)
{
    cVar *tmp;
    int port = 0, i;
    char *bind = NULL, *ipmask = NULL;
    i = 0;
    for(tmp = vars[i]; tmp; tmp = vars[++i])
        if(tmp->type->flag & SCONFF_IPMASK)
        {
            ipmask = tmp->value;
            break;
        }
    i = 0;
    for(tmp = vars[i]; tmp; tmp = vars[++i])
        if(tmp->type->flag & SCONFF_BIND)
        {
            bind = tmp->value;
            break;
        }
    i = 0;
    for(tmp = vars[i]; tmp; tmp = vars[++i])
        if(tmp->type->flag & SCONFF_PORT)
        {
            port = atoi(tmp->value);
            break;
        }
    if(port == 0)
    {
        confparse_error("Lacking 'port' in port block", lnum);
        return;
    }
    confadd_port(port, ipmask, bind);
    free_vars(vars);
    return;
}


static void
confparse_kill(cVar *vars[], int lnum)
{
    cVar *tmp;
    int i;
    char *user = NULL, *host = NULL, *reason = NULL;

    i = 0;
    for(tmp = vars[i]; tmp; tmp = vars[++i])
        if(tmp->type->flag & SCONFF_MASK)
        {
            if((host = strchr(tmp->value, '@')))
            {
                host = '\0';
                host++;
                user = tmp->value;
            }   
            else
                host = tmp->value;
            break;
        }
    i = 0;
    for(tmp = vars[i]; tmp; tmp = vars[++i])
        if(tmp->type->flag & SCONFF_REASON)
        {
            reason = tmp->value;
            break;
        }
    if(!host)
    {
        confparse_error("Missing 'mask' in kill block", lnum);
        return;
    }
    confadd_kill(user, host, reason);
    free_vars(vars);
    return;
}

static void
confparse_restrict(cVar *vars[], int lnum)
{
    cVar *tmp;
    int i, t2 = 0;
    char *type = NULL, *mask = NULL, *reason = NULL;

    i = 0;
    for(tmp = vars[i]; tmp; tmp = vars[++i])
        if(tmp->type->flag & SCONFF_TYPE)
        {
            type = tmp->value;
            break;
        }
    i = 0;
    for(tmp = vars[i]; tmp; tmp = vars[++i])
        if(tmp->type->flag & SCONFF_MASK)
        {
            mask = tmp->value;
            break;
        }
    i = 0;
    for(tmp = vars[i]; tmp; tmp = vars[++i])
        if(tmp->type->flag & SCONFF_REASON)
        {
            reason = tmp->value;
            break;
        }
    if(!type)
    {
        confparse_error("Missing 'type' in restrict block", lnum);
        return;
    }
    else if(!strcmp("CHAN", type))
        t2 |= SBAN_CHAN;
    else if(!strcmp("NICK", type))
        t2 |= SBAN_NICK;
    else if(!strcmp("GCOS", type))
        t2 |= SBAN_GCOS;
    else
    {
        confparse_error("Unknown 'type' in restrict block", lnum);
        return;
    }
    t2 |= SBAN_LOCAL;
    if(!mask)
    {
        confparse_error("Missing 'mask' in oper block", lnum);
        return;
    }
    confadd_restrict(t2, mask, reason);
    free_vars(vars);
    return;
}

static void
confparse_admin(cVar *vars[], int lnum)
{
    char *l1 = NULL, *l2 = NULL, *l3 = NULL;

    if(vars[0]->value)
        l1 = vars[0]->value;
    else
        l1 = "";
    if(vars[1]->value)
        l2 = vars[1]->value;
    else
        l2 = "";
    if(vars[2]->value)
        l3 = vars[2]->value;
    else
        l3 = "";

    confadd_me(0, 0, 0, 0, l1, l2, l3);
    free_vars(vars);
    return;
}

static void
confparse_super(cVar *vars[], int lnum)
{
    int i = 0;

    while(vars[i] && vars[i]->value)
    {
        confadd_uline(vars[i]->value);
        i++;
    }
    free_vars(vars);
    return;
}
        

/* check_quote
 * this routine skips over any ignored items inside our file
 */

static int quote = 0;

static char *
check_quote(char *cur)
{
    if(quote)
    {
        while((cur = strchr(cur, '*')))
            if((*(++cur) == '/'))
            {
                cur++;
                quote = 0;
                break;
            }
        if(!cur)
            return cur;
    }
    while((*cur == ' ') || (*cur == '\t'))
        cur++;
    /* now we've hit something .. check for single line quotes */
    if (!*cur || *cur == '#' || *cur == '\n' ||
            (*cur == '/' && *(cur+1) == '/'))
        return NULL;
    /* check for multiple line quotes */
    if((*cur == '/') && (*(cur+1) == '*'))
    {
        cur += 2;
        quote++;
        while((cur = strchr(cur, '*')))
            if((*(++cur) == '/'))
            {
                cur++;
                quote = 0;
                break;
            }
        return cur;
    }
    return cur;
}

#define MAX_VALUES 128  /* maximum values per block */

static char *
parse_block(tConf *block, char *cur, FILE *file, int *lnum)
{
    char *tok, *var, *var2;
    char line[LINE_MAX];
    tConf *b2 = NULL;
    sConf *item = NULL;
    cVar  *vars[MAX_VALUES] = { 0 };
    int   vnum = 0, tlnum = 0, clear = 0, done = 0, skip = 0;

    if(block->subtok == SCONFF_STRING)
    {
        /* this subtype only takes freeform variables
         * dont bother looking for tokens
         */
        int i = 0;
        while(!BadPtr(cur) || ((fgets(line, LINE_MAX, file) != NULL) && 
                (*lnum)++ && (cur = line)))
        {
            cur = check_quote(cur);
            if(BadPtr(cur))
                continue;
            if(clear)
            {
                if(*cur != ';')
                    confparse_error("Missing semicolon (attempting to ignore)",
                                 *lnum);
                else
                    cur++;
                clear = 0;
                cur = check_quote(cur);
                if(BadPtr(cur))
                    continue;
            }
            if(done)
            {
                if(*cur != ';')
                    confparse_error("Missing block end semicolon (attempting"
                                    " to ignore)", *lnum);
                else
                    cur++;
                (*block->func) (vars, *lnum);
                return cur;
            }
            cur = check_quote(cur);
            if(BadPtr(cur))
                continue;
            if(*cur == '}')
            {
                done = 1;
                cur++;
                cur = check_quote(cur);
                if(BadPtr(cur))
                    continue;
                if(*cur != ';')
                    confparse_error("Missing block end semicolon (attempting"
                                    " to ignore)", *lnum);
                else
                    cur++;
                (*block->func) (vars, *lnum);
                return cur;
            }
            vars[vnum] = (cVar *) MyMalloc(sizeof(cVar));
            memset((char *) vars[vnum], '\0', sizeof(cVar));
            vars[vnum]->loaded = 1;
            vars[vnum]->type = NULL;
            tok = cur;
            if(*cur == '"')
            {
                i = 1;
                cur++;
            }
            var = cur;
            if(i == 1)
            {
                while(!BadPtr(cur) && (*cur != '"'))
                    cur++;
                if(BadPtr(cur))
                {
                    confparse_error("Cant find closequote (attempting to"
                                    " ignore)", *lnum);
                    continue;
                }
                *cur = '\0';
                cur++;
                while(!BadPtr(cur) && (*cur != ';'))
                    cur++;
            }
            else
            {
                while(!BadPtr(cur) && (*cur != ';'))
                {
                    if((*cur == ' '))
                    {
                        *cur = '\0';
                        if(vars[vnum]->loaded == 1)
                        {
                            DupString(vars[vnum]->value, var);
                            vars[vnum]->loaded = 2;
                        }
                    }
                    else if(vars[vnum]->loaded == 2)
                    {
                        confparse_error("Junk after value (attempting to"
                                " ignore)", *lnum);
                        continue;
                    }
                    cur++;
                }
            }
            tlnum = *lnum;
            if(BadPtr(cur))
            {
                clear = 1;
                continue;
            }
            *cur = '\0';
            if(vars[vnum]->loaded == 1)
                DupString(vars[vnum]->value, var);
            vars[vnum]->loaded = 3;
            vnum++;
        }
        confparse_error("Unexpected EOF: Syntax Error", tlnum);
        return NULL;
    }

    while(!BadPtr(cur) || ((fgets(line, LINE_MAX, file) != NULL) && (*lnum)++
             && (cur = line)))
    {
        cur = check_quote(cur);
        if(BadPtr(cur))
            continue;
        if(clear)
        {
            /* if we're looking for a closing semicolon, check for it first
             * if we cant find it, ignore it and hope for the best
             */
            if(*cur != ';')
                confparse_error("Missing semicolon (attempting to ignore)",
                                 *lnum);
            else
                cur++;
            clear = 0;
            if(vars[vnum])
            {
                vars[vnum]->loaded = 3;
                vnum++;
            }
            item = NULL;
            cur = check_quote(cur);
            if(BadPtr(cur))
                continue;
        }
        if(done)
        {
            /* we've found the end of our block, now we're looking for the
             * closing semicolon.  if we cant find it, ignore it and
             * hope for the best
             */
            if(*cur != ';')
                confparse_error("Missing block end semicolon (attempting to"
                                " ignore)", *lnum);
            else
                cur++;
            (*block->func) (vars, *lnum);
            return cur;
        }
        if(b2 && b2->tok)
        {
            /* we've identified a nested block in a previous loop.
             * we didnt get an openquote yet, so look for that.
             * we must find this.  keep looking til we do.
             */
            if(*cur != '{')
            {
                confparse_error("Junk after nested block token (attempting "
                                "to ignore)", *lnum);
                cur = strchr(cur, '{');
                if(BadPtr(cur))
                    continue;
            }
            cur++;
            cur = check_quote(cur);
            cur = parse_block(b2, cur, file, lnum);
            b2 = NULL;
            continue;
        }
        if(!item || !item->tok)
        {
            /* if we dont already have a specific token we're working on
             * find one here.
             */
            cur = check_quote(cur);
            if(BadPtr(cur))
                continue;
            tok = cur;
            tlnum = *lnum;
            if(*cur == '}')
            {
                /* if we've got a closebracket, then we've hit the end
                 * of our block.
                 */
                done = 1;
                cur++;
                cur = check_quote(cur);
                if(BadPtr(cur))
                    continue;
                if(*cur != ';')
                    confparse_error("Missing block end semicolon (attempting"
                                    " to ignore)", *lnum);
                else
                    cur++;
                (*block->func) (vars, *lnum);
                return cur;

            }
            /* our token ends where whitespace or a semicolon begins */
            while(!BadPtr(cur) && ((*cur != ' ') && (*cur != ';') &&
                   (*cur != '\t') && (*cur != '\n')))
                cur++;
            if(BadPtr(cur))
            {
                confparse_error("Unterminated token (attempting to ignore)", 
                                 *lnum);
            }
            else 
            {
                if(*cur == ';')
                    skip = 1;
                *cur = '\0';
            }
            cur++;
            if(block->nest)
            {
                /* we allow nested stuff inside here, so check for it. */
                for(b2 = tconftab; b2->tok; b2++)
                    if(!mycmp(b2->tok, tok))
                        break;
                if(b2 && b2->tok)
                    if(!(block->nest & b2->flag))
                        b2 = NULL;
                if(b2 && b2->tok)
                {
                    /* recurse through the block we found */
                    tlnum = *lnum;
                    if((cur = strchr(cur, '{')))
                    {
                        cur++;
                        cur = check_quote(cur);
                        cur = parse_block(b2, cur, file, lnum);
                        b2 = NULL;
                        continue;
                    }
                    if(BadPtr(cur))
                        continue;
                }
            }
            /* find our token */
            for(item = sconftab; item && item->tok; item++)
                if(!mycmp(item->tok, tok))
                    break;
            if(!item->tok)
            {
                confparse_error("Unknown token(ignored)", *lnum);
                clear = 0;
                continue;
            }
            if(!(block->subtok & item->flag))
            {
                confparse_error("token not permitted in block(ignored)", *lnum);
                clear = 1;
                continue;
            }
            /* create our variable */
            vars[vnum] = (cVar *) MyMalloc(sizeof(cVar));
            memset((char *) vars[vnum], '\0', sizeof(cVar));
            vars[vnum]->type = item;
            vars[vnum]->loaded = 1;
        }
        if(item->var & VARTYPE_NONE)
        {
            /* we dont need to grab a variable for this type 
             * just look for the closing semicolon, and move on */
            vars[vnum]->loaded = 2;
            if(!skip)   
            {
                /* we've already gotten our semicolon back
                 * at the end of our token.  dont look for it. */
                cur = check_quote(cur);
                while(!BadPtr(cur) && (*cur != ';'))
                    cur++;
                if(BadPtr(cur))
                {
                    clear = 1;
                    continue;
                }
                cur++;
            }
            skip = 0;
            vars[vnum]->loaded = 3;
            vnum++;
            item = NULL;
            continue;
        }
        if(item->var & VARTYPE_STRING)
        {
            /* we're looking for a string here, so we require
             * quotes around the string...
             */
            cur = check_quote(cur);
            while(!BadPtr(cur) && (*cur != '"'))
                cur++;
            if(BadPtr(cur))
                continue;
            cur++;
            var = cur;
            while(!BadPtr(cur) && (*cur != '"'))
                cur++;
            if(BadPtr(cur))
            {
                int x = 0;
                confparse_error("Unterminated quote (attempting to ignore)", 
                                *lnum);
                /* try to back up to most recent non-whitespace value */
                while(BadPtr(cur) || ((*cur == ' ') || *cur == '\t' ||
                        (*cur == '\n')))
                {
                    x++;
                    if(x > 80)  /* just in case */
                        break;
                    cur--;  
                }
            }
            *cur = '\0';
            cur++;
            DupString(vars[vnum]->value, var);
            vars[vnum]->loaded = 2;
            while(!BadPtr(cur) && (*cur != ';'))
                cur++;
            if(BadPtr(cur))
            {
                clear = 1;
                continue;
            }
            cur++;
            vars[vnum]->loaded = 3;
            vnum++;
            item = NULL;
            continue;
        }
        if(item->var & VARTYPE_INT)
        {
            cur = check_quote(cur);
            var = cur;
            while(!BadPtr(cur) && ((*cur != ';') && (*cur != '\t') &&
                    (*cur != '\n') && (*cur != ' ')))
                cur++;
            if(BadPtr(cur))
            {
                clear = 1;
                continue;
            }
            if(*cur != ';')
                clear = 1;
            *cur = '\0';
            cur++;
            var2 = var;
            while(*var) 
            {
                if(isdigit(*var))
                    var++;
                else
                {
                    confparse_error("Non-Numeric value in integer"
                                    " token(line skipped)", *lnum);
                    item = NULL;
                    MyFree(vars[vnum]);
                    vars[vnum] = NULL;
                    break;
                }
            }
            if(!item)
                continue;
            var = var2;
            DupString(vars[vnum]->value, var);
            vars[vnum]->loaded = 3;
            vnum++;
            item = NULL;
            continue;
        }
        if(item->var & VARTYPE_NAME)
        {
            cur = check_quote(cur);
            if(!BadPtr(cur) && (*cur == '"'))
                cur++;
            var = cur;
            while(!BadPtr(cur) && (*cur != ';'))
            {
                if((*cur == ' ') || (*cur == '"') || (*cur == '\t'))
                {
                    *cur = '\0';
                    if(vars[vnum]->loaded == 1)
                    {
                        DupString(vars[vnum]->value, var);
                        vars[vnum]->loaded = 2;
                    }
                }
                cur++;
            }
            if(BadPtr(cur))
            {
                clear = 1;
                continue;
            }
            *cur = '\0';
            if(vars[vnum]->loaded == 1)
                DupString(vars[vnum]->value, var);
            vars[vnum]->loaded = 3;
            vnum++;
            item = NULL;
            continue;
        }
        confparse_error("Unexpected EOF:  Syntax Error", tlnum);
        return NULL;
    }
    confparse_error("Unexpected EOF:  Syntax Error", tlnum);
    return NULL;
}
            


int
initconf(char *filename)
{
    int lnum = 0, blnum = 0, clear = 0;
    char line[LINE_MAX];
    char *cur = NULL;
    char *tok;
    tConf *block = NULL;
    FILE *file;

    if(!(file = fopen(filename, "r")))
    {
        if(forked)
            sendto_realops("Unable to open config file %s%s", file, "\n");
        else
            printf("Unable to open config file %s\n", filename);
        return -1;
    }
    
    while(!BadPtr(cur) || ((fgets(line, LINE_MAX, file) != NULL) && ++lnum
             && (cur = line)))
    {
        cur = check_quote(cur);
        if(BadPtr(cur))
            continue;
        /* now, we should be ok to get that token.. */
        if(!block)
        {
            tok = cur;
            while((*cur != ' ') && (*cur != '\n') && (*cur != '{'))
                cur++;      /* find the whitespace following the token */
            if(*cur == '{')
                clear = 1;
            *cur = '\0';
            cur++;
            if(!mycmp("INCLUDE", tok))
            {
                /* this is an include - find pull out the file name
                 * and parse this file now
                 */
                char *var;
                cur = check_quote(cur);
                if((*cur == '"') || *cur == '<')
                    cur++;
                var = cur;
                while((*cur != ' ') && (*cur != '"') && (*cur != '>') &&
                        (*cur != '\n') && (*cur != '\t'))
                    cur++;
                if(BadPtr(cur))
                {
                    confparse_error("Bad include line(ignored)", lnum);
                    cur = strchr(cur, ';');
                    cur++;
                    continue;
                }
                *cur = '\0';
                cur++;
                initconf(var);
                continue;
            }    
            for(block = tconftab; block->tok; block++)
                if(!mycmp(block->tok, tok))
                    break;
            if(!block->tok)
            {
                confparse_error("Unknown block type", lnum);
                continue;
            }
            blnum = lnum;
        }
        cur = check_quote(cur);
        if(BadPtr(cur))
            continue;
        if((*cur ==  '{') || clear)
            cur++;
        else
        {
            confparse_error("Junk after block name (attempting to ignore)", 
                             lnum);
            if(!(cur = strchr(cur, '{')))
            {
                clear = 0;
                continue;
            }
            cur++;
        }
        printf("parsing block %s\n", block->tok);
        cur = parse_block(block, cur, file, &lnum);
        clear = 0;
        block = NULL;
        continue;
    }
    if(clear)
    {
        confparse_error("Unexpected EOF:  Syntax error", blnum);
        return -1;
    }
    return 1;
}
