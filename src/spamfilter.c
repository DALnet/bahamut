/************************************************************************
 *   Bahamut IRCd, src/spamfilter.c
 *   Copyright (C) 2005-2018, Kobi Shmueli
 *
 *   See file AUTHORS in IRC package for additional names of
 *   the programmers.
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
#include "numeric.h"
#include "channel.h"
#include "h.h"
#include "spamfilter.h"
#include "pcre.h"

#define PCRE_COMP_FLAGS PCRE_EXTRA|PCRE_ANCHORED|PCRE_UNGREEDY
#define SPAMFILTER_FILE "spamfilter.db"

struct spam_filter
{
    struct spam_filter *next;
    char *text;
    long flags;
    char *target;
    char *reason;
    char *id;
    pcre *re;
    unsigned int len;
};

struct spam_filter *spam_filters = NULL;
static char buf2[BUFSIZE];
time_t last_spamfilter_save = 0;

/* load_spamfilter - Load the spamfilters
 *                   Returns: 1 = Success
 *                            0 = Failure
 */
int load_spamfilter()
{
    FILE *fle;
    char line[1024];
    char *para[MAXPARA + 1];
    int parc;

    if(!(fle = fopen(SPAMFILTER_FILE, "r")))
        return 0; /* Can't open file! */

    while(fgets(line, sizeof(line), fle))
    {
        char *tmp = strchr(line, '\n');
        if(!tmp)
            break;
        *tmp = '\0';
        tmp = line;
        parc = 0;
        while(*tmp)
        {
            while(*tmp==' ')
             *tmp++ = '\0';

            if(*tmp==':')
            {
                para[parc++] = tmp + 1;
                break;
            }
            para[parc++] = tmp;
            while(*tmp && *tmp!=' ')
                tmp++;
        }
        para[parc + 1] = NULL;
        if(!mycmp(para[0],"SF"))
        {
            if(parc>4)
                new_sf(para[1], atol(para[2]), para[4], para[3]);
            else if(parc>3)
                new_sf(para[1], atol(para[2]), para[3], NULL);
        }
    }
    fclose(fle);

    return 1;
}

/* save_spamfilter - Save the spamfilters
 *                   Returns: 1 = Success
 *                            0 = Failure
 */
int save_spamfilter()
{
    FILE *fle;
    struct spam_filter *sf = spam_filters;

    fle = fopen(SPAMFILTER_FILE,"w");
    if(!fle)
        return 0;

    for(; sf; sf = sf->next)
    {
        if(sf->target)
            fprintf(fle, "SF %s %ld %s :%s\n", sf->text, sf->flags, sf->target, sf->reason);
        else
            fprintf(fle, "SF %s %ld :%s\n", sf->text, sf->flags, sf->reason);
    }

    fclose(fle);

    return 1;
}

/* spamfilter_sendserver - Send the spamfilter list on server connections */
void spamfilter_sendserver(aClient *acptr)
{
    struct spam_filter *sf;

    for(sf = spam_filters; sf; sf = sf->next)
    {
        if(sf->target)
            sendto_one(acptr, "SF %s %ld %s :%s", sf->text, sf->flags, sf->target, sf->reason);
        else
            sendto_one(acptr, "SF %s %ld :%s", sf->text, sf->flags, sf->reason);
    }
}

/* m_spamops - Send a SPAM_LEV notice to all local opers and propgate it to other servers
   parv[1] = message
 */
int m_spamops(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    char       *message = parc > 1 ? parv[1] : NULL;

    if (BadPtr(message))
    {
        return 0;
    }

    if (!IsServer(sptr))
    {
        sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
        return 0;
    }
    if (strlen(message) > TOPICLEN)
        message[TOPICLEN] = '\0';
    sendto_serv_butone_super(cptr, 0, ":%s SPAMOPS :%s", parv[0], message);
    sendto_realops_lev(SPAM_LEV, "from %s: %s", parv[0], message);

    return 0;
}

/* check_sf - checks if a text matches a spamfilter pattern
              Returns: 1 = User message has been blocked.
                       2 = User has been killed and the message has been blocked.
                       0 = User message was not blocked (but it doesn't mean we didn't have a non-block match).
 */
int check_sf(aClient *cptr, char *text, char *caction, int action, char *target)
{
    struct spam_filter *p = spam_filters;
    unsigned short blocked = 0;
    unsigned short reported = 0;
    unsigned short warned = 0;
    unsigned short matched;
    char stripamsg[512];
    char stripcmsg[512];
    unsigned int len = 0; /* For regexp */
    int ovector[30]; /* For regexp */
    char *action_text;
    char *textptr;

    if(IsAnOper(cptr))
        return 0;

    stripamsg[0] = '\0';
    stripcmsg[0] = '\0';

    for(; p; p = p->next)
    {
        if(!(p->flags & action))
            continue;
        if(IsRegNick(cptr) && !(p->flags & SF_FLAG_MATCHREG))
            continue;
        if(p->target && match(p->target,target))
            continue;
        if(p->flags & SF_FLAG_STRIPALL)
        {
            if(stripamsg[0]=='\0')
            {
                textptr = text;
                while(*textptr==' ') textptr++;
                if(*textptr && *target && !strncasecmp(textptr,target,strlen(target)))
                {
                    textptr += strlen(target);
                }
                stripall(stripamsg, textptr);
            }
            matched = !match(p->text,stripamsg);
        }
        else if(p->flags & SF_FLAG_STRIPCTRL)
        {
            if(stripcmsg[0]=='\0')
                stripcolors(stripcmsg, text);
            matched = !match(p->text,stripcmsg);
        }
        else if(p->flags & SF_FLAG_REGEXP)
        {
            if(!len)
                len = strlen(text);
            if(pcre_exec(p->re, NULL, text, len, 0, 0, ovector, 30) > 0)
                matched = 1;
            else
                matched = 0;

        }
        else matched = !match(p->text,text);
        if(matched) {
            if(p->flags & SF_ACT_LAG)
                cptr->since += 4;
            if(p->flags & SF_ACT_BLOCK)
                blocked = 1;
            if(!warned && (p->flags & SF_ACT_WARN))
            {
                sendto_one(cptr, ":%s NOTICE %s :*** Notice -- Your message has %s. Reason: %s",
                           me.name, cptr->name, blocked?"been blocked":"triggered a warning",
                           p->reason?p->reason:"<none>");
                sendto_one(cptr, ":%s NOTICE %s :*** Notice -- Please visit %s for more information.",
                           me.name, cptr->name, SpamFilter_URL);
                warned++;
            }
            if(!reported && (p->flags & SF_ACT_REPORT))
            {
                if((p->flags & SF_ACT_BLOCK) && (p->flags & SF_ACT_AKILL))
                    action_text = " (blocked+akilled)";
                else if(p->flags & SF_ACT_BLOCK)
                    action_text = " (blocked)";
                else if(p->flags & SF_ACT_AKILL)
                    action_text = " (akilled)";
                else
                    action_text = "";
                if(IsPerson(cptr))
                {
                    sendto_realops_lev(SPAM_LEV, "spamfilter %s: %s by %s!%s@%s to %s%s --> %s", p->id?p->id:p->text,
                                       caction, cptr->name, cptr->user->username, cptr->user->host,
                                       target, action_text, text);
                    sendto_serv_butone(NULL, ":%s SPAMOPS :spamfilter %s: %s by %s!%s@%s to %s%s --> %s",
                                       me.name, p->id?p->id:p->text, caction, cptr->name, cptr->user->username,
                                       cptr->user->host, target, action_text, text);
                }
                else
                {
                    sendto_realops_lev(SPAM_LEV, "spamfilter %s: %s by %s to %s%s --> %s", p->id?p->id:p->text,
                                       caction, cptr->name, target, action_text, text);
                    sendto_serv_butone(NULL, ":%s SPAMOPS :spamfilter %s: %s by %s to %s%s --> %s",
                                       me.name, p->id?p->id:p->text, caction, cptr->name, target, action_text, text);
                }
                reported++;
            }
            if(p->flags & SF_ACT_AKILL)
            {
                if(aliastab[AII_OS].client)
                    sendto_one(aliastab[AII_OS].client->from, ":%s OS SFAKILL %s!%s@%s %ld %s", me.name, cptr->name,
                               cptr->user?cptr->user->username:"<none>", cptr->hostip,
                               cptr->tsinfo, p->reason?p->reason:"<none>");
            }
            if(p->flags & SF_ACT_KILL)
            {
                blocked = 2;
                if(action!=SF_CMD_QUIT)
                {
                    ircsprintf(buf2, "Local kill by %s (%s)", me.name, p->reason?p->reason:"<none>");
                    exit_client(cptr, cptr, cptr, buf2);
                    return blocked;
                }
            }
            if(p->flags & SF_FLAG_BREAK)
                return blocked;
        }
    }

    return blocked;
}

struct spam_filter *find_sf(char *text)
{
    struct spam_filter *p = spam_filters;

    for(; p; p = p->next)
    {
        if(!mycmp(p->text,text))
            return p; /* Found! */
    }

    return NULL; /* Not found */
}

struct spam_filter *new_sf(char *text, long flags, char *reason, char *target)
{
    struct spam_filter *p;
    int erroroffset;
    const char *error;
    pcre *re;
    unsigned int len = 0; /* For the spamfilter id */

    if(flags & SF_FLAG_REGEXP)
    {
        re = pcre_compile(text, PCRE_COMP_FLAGS, &error, &erroroffset, NULL);
        if(!re)
            return NULL; /* error! */
    }
    else
        re = NULL;

    p = find_sf(text);
    if(p)
    {
        if(p->target)
            MyFree(p->target);
        if(p->reason)
            MyFree(p->reason);
        if(p->id)
            MyFree(p->id);
        if(p->re)
            pcre_free(p->re);
    }
    else
    {
        p = MyMalloc(sizeof(struct spam_filter));
        p->next = spam_filters;
        spam_filters = p;
        p->len = strlen(text); /* We only need the length for REGEXP entries so we won't check it every match-check but we use it for MyMalloc anyway so I put it here -Kobi. */
        p->text = MyMalloc(p->len + 1);
        strcpy(p->text, text);
    }
    p->flags = flags;
    p->re = re;
    if(reason)
    {
        p->reason = MyMalloc(strlen(reason) + 1);
        strcpy(p->reason, reason);
        len = 1;
        if(reason[0] == '[')
        {
            while(reason[len]!=']' && reason[len]!='\0')
                len++;
        }
        if(len > 1 && reason[len]==']')
        {
            p->id = MyMalloc(len);
            strncpy(p->id, &reason[1], len - 1);
            p->id[len] = '\0';
        }
        else p->id = NULL;
    }
    else
    {
        p->reason = NULL;
        p->id = NULL;
    }
    if(target)
    {
        p->target = MyMalloc(strlen(target) + 1);
        strcpy(p->target, target);
    }
    else p->target = NULL;

    return p;
}

int del_sf(char *text)
{
    struct spam_filter *p, *pprev, *pn;

    for(p = spam_filters, pprev = NULL; p; pprev = p, p = pn)
    {
        pn = p->next;
        if(!mycmp(p->text,text))
        {
            if(pprev)
                pprev->next = p->next;
            else
                spam_filters = p->next;
            if(p->text)
                MyFree(p->text);
            if(p->target)
                MyFree(p->target);
            if(p->reason)
                MyFree(p->reason);
            if(p->id)
                MyFree(p->id);
            if(p->re)
                pcre_free(p->re);
            MyFree(p);
            return 1; /* Success */
        }
    }

    return 0; /* Failure */
}

/* m_sf - Spam Filter
 * parv[1] - Text
 * parv[2] - Flags (0 to delete)
 * parv[3] - (Optional) Target
 * parv[4] or parv[3] - Reason
 */
int m_sf(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    AliasInfo *ai = &aliastab[AII_OS];

    if(!IsServer(sptr) || parc<3)
        return 0;

    if(!IsULine(sptr) && ai->client && ai->client->from!=cptr->from)
    {
        /*
         * We don't accept commands from a non-services direction.
         * Also, we remove non-existed spamfilters if they come from this location.
         * Note: we don't need to worry about existed spamfilters on the other side
         * because they will be overrided anyway.
         */
        if(!find_sf(parv[1]) && mycmp(parv[2], "0"))
            sendto_one(cptr, ":%s SF %s 0", me.name, parv[1]);
        return 0;
    }
    if(mycmp(parv[2], "0"))
    {
        if(parc>4)
            new_sf(parv[1], atol(parv[2]), parv[4], parv[3]);
        else
            new_sf(parv[1], atol(parv[2]), parv[3], NULL);
    }
    else
        del_sf(parv[1]);

    if(parc>4)
        sendto_serv_butone(cptr, ":%s SF %s %s %s :%s", parv[0], parv[1], parv[2], parv[3], parv[4]);
    else if(parc>3)
        sendto_serv_butone(cptr, ":%s SF %s %s :%s", parv[0], parv[1], parv[2], parv[3]);
    else
        sendto_serv_butone(cptr, ":%s SF %s %s", parv[0], parv[1], parv[2]);

    if(NOW > last_spamfilter_save + 300) {
      last_spamfilter_save = NOW;
      save_spamfilter();
    }

    return 0;
}

/* Strip colors and other control codes from a text */
void stripcolors(char new[512], char *org)
{
    int len = 0;

    for(; (*org && len<512); org++)
    {
        if(*org=='\003')
        {
            org++;
            while(IsDigit(*org) || *org==',')
                org++;
        }
        if(*org<32 && *org!=1)
            continue;
        new[len++] = *org;
    }
    new[len] = '\0';
}

/* Strip all "special" chars */
void stripall(char new[512], char *org)
{
#define fstripall(c) ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || IsDigit(c) || c == '-' || c == '/' || c == '.' || c== '$' || c == '(') /* to strip everything ;) */
    int len = 0;

    for(; (*org && len<512); org++)
    {
        if(*org=='\003')
        {
            org++;
            while(IsDigit(*org) || *org==',')
                org++;
        }
        if(!fstripall(*org))
            continue;
        new[len++] = *org;
    }
    new[len] = '\0';
}
