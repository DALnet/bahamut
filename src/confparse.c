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
#include "h.h"
#include "userban.h"
#define CONF_TABS
#include "confparse.h"

#ifndef LINE_MAX
#define LINE_MAX 256
#endif

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
extern int set_classes();
extern aPort *new_ports;
extern Conf_Me *new_MeLine;

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

static char *current_file = "unknown";

void
confparse_error(char *problem, int line)
{
    if(!forked)
        printf("ERROR:  %s near line %d of %s\n", problem, line, current_file);
    else
        sendto_realops("Conf Error:  %s near line %d of %s", problem, line,
                        current_file);
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
        quote = 1;
        while((cur = strchr(cur, '*')))
            if((*(++cur) == '/'))
            {
                cur++;
                quote = 0;
                break;
            }
        if(!cur)
            return cur;
        else
            return check_quote(cur);
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
    sConf *sconftab = block->subtok;
    cVar  *vars[MAX_VALUES] = { 0 };
    int   vnum = 0, tlnum = 0, clear = 0, done = 0, skip = 0;

    if((sconftab) && (sconftab->flag == SCONFF_STRING))
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
                {
                    confparse_error("Missing semicolon", *lnum);
                    free_vars(vars);
                    return NULL;
                }
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
                {
                    confparse_error("Missing block end semicolon", *lnum);
                    free_vars(vars);
                    return NULL;
                }
                else
                    cur++;
                if(((*block->func) (vars, *lnum)) == -1)
                {
                    free_vars(vars);
                    return NULL;
                }
                if(BadPtr(cur))
                    *cur = '#';     /* we cant return a bad pointer because
                                     * that will pull us out of the conf read
                                     * so this will just get ignored
                                     * kludgy, but effective */
                free_vars(vars);
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
                {
                    confparse_error("Missing block end semicolon", *lnum);
                    free_vars(vars);
                    return NULL;
                }
                else
                    cur++;
                if(((*block->func) (vars, *lnum)) == -1)
                {
                    free_vars(vars);
                    return NULL;
                }
                if(BadPtr(cur))
                    *cur = '#';     /* we cant return a bad pointer because
                                     * that will pull us out of the conf read
                                     * so this will just get ignored
                                     * kludgy, but effective */
                free_vars(vars);
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
                    confparse_error("Cant find closequote", *lnum);
                    free_vars(vars);
                    return NULL;
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
                        confparse_error("Junk after value", *lnum);
                        free_vars(vars);
                        return NULL;
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
            cur++;
            if(vars[vnum]->loaded == 1)
                DupString(vars[vnum]->value, var);
            vars[vnum]->loaded = 3;
            vnum++;
        }
        confparse_error("Unexpected EOF: Syntax Error", tlnum);
        free_vars(vars);
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
            {
                confparse_error("Missing semicolon ", *lnum);
                free_vars(vars);
                return NULL;
            }
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
            {
                confparse_error("Missing block end semicolon", *lnum);
                free_vars(vars);
                return NULL;
            }
            else
                cur++;
            if(((*block->func) (vars, *lnum)) == -1)
            {
                free_vars(vars);
                return NULL;
            }
            if(BadPtr(cur))
                *cur = '#';     /* we cant return a bad pointer because
                                 * that will pull us out of the conf read
                                 * so this will just get ignored
                                 * kludgy, but effective */
            free_vars(vars);
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
                confparse_error("Junk after nested block token", *lnum);
                free_vars(vars);
                return NULL;
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
                {
                    confparse_error("Missing block end semicolon", *lnum);
                    free_vars(vars);
                    return NULL;
                }
                else
                    cur++;
                if(((*block->func) (vars, *lnum)) == -1)
                {
                    free_vars(vars);
                    return NULL;
                }
                if(BadPtr(cur))
                    *cur = '#';     /* we cant return a bad pointer because
                                     * that will pull us out of the conf read
                                     * so this will just get ignored
                                     * kludgy, but effective */
                free_vars(vars);
                return cur;

            }
            /* our token ends where whitespace or a semicolon begins */
            while(!BadPtr(cur) && ((*cur != ' ') && (*cur != ';') &&
                   (*cur != '\t') && (*cur != '\n')))
                cur++;
            if(BadPtr(cur))
            {
                confparse_error("Unterminated token", *lnum);
                free_vars(vars);
                return NULL;
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
                confparse_error("Unknown token", *lnum);
                free_vars(vars);
                return NULL;
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
                confparse_error("Unterminated quote", *lnum);
                free_vars(vars);
                return NULL;
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
                if(IsDigit(*var))
                    var++;
                else
                {
                    confparse_error("Expecting integer value", *lnum);
                    free_vars(vars);
                    return NULL;
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
            cur++;
            if(vars[vnum]->loaded == 1)
                DupString(vars[vnum]->value, var);
            vars[vnum]->loaded = 3;
            vnum++;
            item = NULL;
            continue;
        }
        confparse_error("Unexpected EOF:  Syntax Error", tlnum);
        free_vars(vars);
        return NULL;
    }
    confparse_error("Unexpected EOF:  Syntax Error", tlnum);
    free_vars(vars);
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

    current_file = filename;

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
                    confparse_error("Bad include line", lnum);
                    return -1;
                }
                *cur = '\0';
                cur++;
                if(initconf(var) == -1)
                    return -1;
                current_file = filename;    /* reset */
                continue;
            }    
            for(block = tconftab; block->tok; block++)
                if(!mycmp(block->tok, tok))
                    break;
            if(!block->tok)
            {
                confparse_error("Unknown block type", lnum);
                return -1;
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
            confparse_error("Junk after block name", lnum);
            return -1;
        }
        if((cur = parse_block(block, cur, file, &lnum)) == NULL)
        {
            return -1;
        }
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

inline char *
finishconf(void)
{
    if (!new_MeLine || !new_MeLine->servername)
        return "Missing global block";
    if (!set_classes())
        return "Nonexistant class referenced";
    if (!new_ports)
        return "No ports defined";
    return NULL;
}
