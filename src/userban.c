/************************************************************************
 *   IRC - Internet Relay Chat, src/userban.c
 *   Copyright (C) 2002 Lucas Madar and
 *                      the DALnet coding team
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
#include "numeric.h"
#include "inet.h"
#include "h.h"
#include "dich_conf.h"
#include "userban.h"
#include "queue.h"

#define HASH_SIZE (32749)    /* largest prime < 32768 */

LIST_HEAD(banlist_t, userBanEntry);
typedef struct banlist_t ban_list;

typedef struct userBanEntry {
   struct userBan *ban;
   LIST_ENTRY(userBanEntry) lp;
} uBanEnt;

typedef struct _abanlist {
   ban_list wild_list;

   int numbuckets;
   ban_list *hash_list;
} aBanList;

typedef struct userBan auserBan;

ban_list CIDR4BIG_bans = LIST_HEAD_INITIALIZER(CIDR4BIG_bans);
ban_list **CIDR4_bans; 

aBanList host_bans;
aBanList ip_bans;

struct userBan *userban_alloc();
uBanEnt *ubanent_alloc();
void ubanent_free(uBanEnt *);
void userban_free(struct userBan *);
unsigned int host_hash(char *n);
unsigned int ip_hash(char *n);


unsigned int cidr_to_netmask(unsigned int cidr)
{
   if (cidr == 0)
      return 0;

   return (0xFFFFFFFF - (1 << (32 - cidr)) + 1);
}

unsigned int netmask_to_cidr(unsigned int mask) 
{
   int tmp = 0;

   while (!(mask & (1 << tmp)) && tmp < 32) 
      tmp++;

   return (32 - tmp); 
}

void add_hostbased_userban(struct userBan *b)
{
   uBanEnt *bl;

   bl = ubanent_alloc();
   bl->ban = b;
   b->internal_ent = (void *) bl;

   if(b->flags & UBAN_CIDR4BIG)
   {
      LIST_INSERT_HEAD(&CIDR4BIG_bans, bl, lp);
      return;
   }

   if(b->flags & UBAN_CIDR4)
   {
      unsigned char *s = (unsigned char *) &bl->ban->cidr4ip;
      int a, b;

      a = (int) *s++;
      b = (int) *s;

      LIST_INSERT_HEAD(&CIDR4_bans[a][b], bl, lp);
      return;
   }

   if(b->flags & UBAN_IP)
   {
      if(b->flags & UBAN_WILD)
      {
         LIST_INSERT_HEAD(&ip_bans.wild_list, bl, lp);
      }
      else
      {
         unsigned int hv = ip_hash(b->h) % HASH_SIZE;

         LIST_INSERT_HEAD(&ip_bans.hash_list[hv], bl, lp);
      }

      return;
   }

   if(b->flags & UBAN_HOST)
   {
      if(b->flags & UBAN_WILD)
      {
         LIST_INSERT_HEAD(&host_bans.wild_list, bl, lp);
      }
      else
      {
         unsigned int hv = host_hash(b->h) % HASH_SIZE;

         LIST_INSERT_HEAD(&host_bans.hash_list[hv], bl, lp);
      }

      return;
   }

   /* unreachable code */
   abort();
}

void remove_userban(struct userBan *b)
{
   uBanEnt *bl = (uBanEnt *) b->internal_ent;

   LIST_REMOVE(bl, lp);

   ubanent_free(bl);

   return;
}

/*
 * user_match_ban -- be sure to call only for fully-initialized users
 * returns 0 on no match, 1 otherwise 
 */
int user_match_ban(aClient *cptr, struct userBan *ban)
{
   /* first match the 'user' portion */

   if((!(ban->flags & UBAN_WILDUSER)) && match(ban->u, cptr->user->username)) 
      return 0;

   if(ban->flags & UBAN_IP)
   {
      char iptmp[HOSTIPLEN + 1];

      strncpyzt(iptmp, inetntoa((char *)&cptr->ip), HOSTIPLEN + 1);
      if(ban->flags & UBAN_WILD)
      {
         if(match(ban->h, iptmp) == 0)
            return 1;
      }
      else
      {
         if(mycmp(ban->h, iptmp) == 0)
            return 1;
      }
      return 0;
   }

   if(ban->flags & UBAN_HOST)
   {
      if(!(ban->flags & UBAN_WILD))
      {
         if((ban->flags & UBAN_WILDHOST) || match(ban->h, cptr->user->host) == 0)
            return 1;
      }
      else
      {
         if(mycmp(ban->h, cptr->user->host) == 0)
            return 1;
      }
      return 0;
   }

   if(ban->flags & (UBAN_CIDR4|UBAN_CIDR4BIG))
   {
      if((cptr->ip.s_addr & ban->cidr4mask) == ban->cidr4ip)
         return 1;
      return 0;
   }

   return 0;
}

struct userBan *check_userbanned(aClient *cptr, unsigned int yflags, unsigned int nflags)
{
   char iptmp[HOSTIPLEN + 1];
   uBanEnt *bl;

   strncpyzt(iptmp, inetntoa((char *)&cptr->ip), HOSTIPLEN + 1);

   if(yflags & UBAN_IP)
   {
      unsigned int hv = ip_hash(iptmp) % HASH_SIZE;

      LIST_FOREACH(bl, &ip_bans.hash_list[hv], lp) 
      {
         if((bl->ban->flags & UBAN_TEMPORARY) && bl->ban->timeset + bl->ban->duration <= NOW)
            continue;

         if( ((yflags & UBAN_WILDUSER) && !(bl->ban->flags & UBAN_WILDUSER)) ||
             ((nflags & UBAN_WILDUSER) && (bl->ban->flags & UBAN_WILDUSER)))
            continue;

         if((!(bl->ban->flags & UBAN_WILDUSER)) && match(bl->ban->u, cptr->user->username)) 
            continue;

         if(mycmp(bl->ban->h, iptmp) == 0)
            return bl->ban;
      }

      LIST_FOREACH(bl, &ip_bans.wild_list, lp) 
      {
         if((bl->ban->flags & UBAN_TEMPORARY) && bl->ban->timeset + bl->ban->duration <= NOW)
            continue;

         if( ((yflags & UBAN_WILDUSER) && !(bl->ban->flags & UBAN_WILDUSER)) ||
             ((nflags & UBAN_WILDUSER) && (bl->ban->flags & UBAN_WILDUSER)))
            continue;

         if((!(bl->ban->flags & UBAN_WILDUSER)) && match(bl->ban->u, cptr->user->username)) 
            continue;

         if(match(bl->ban->h, iptmp) == 0)
            return bl->ban;
      }
   }

   if(yflags & UBAN_CIDR4)
   {
      unsigned char *s = (unsigned char *) &cptr->ip.s_addr;
      int a, b;

      a = (int) *s++;
      b = (int) *s;

      LIST_FOREACH(bl, &CIDR4_bans[a][b], lp) 
      {
         if((bl->ban->flags & UBAN_TEMPORARY) && bl->ban->timeset + bl->ban->duration <= NOW)
            continue;

         if( ((yflags & UBAN_WILDUSER) && !(bl->ban->flags & UBAN_WILDUSER)) ||
             ((nflags & UBAN_WILDUSER) && (bl->ban->flags & UBAN_WILDUSER)))
            continue;

         if((!(bl->ban->flags & UBAN_WILDUSER)) && match(bl->ban->u, cptr->user->username)) 
            continue;

         if((cptr->ip.s_addr & bl->ban->cidr4mask) == bl->ban->cidr4ip)
            return bl->ban;
      }

      LIST_FOREACH(bl, &CIDR4BIG_bans, lp) 
      {
         if((bl->ban->flags & UBAN_TEMPORARY) && bl->ban->timeset + bl->ban->duration <= NOW)
            continue;

         if( ((yflags & UBAN_WILDUSER) && !(bl->ban->flags & UBAN_WILDUSER)) ||
             ((nflags & UBAN_WILDUSER) && (bl->ban->flags & UBAN_WILDUSER)))
            continue;

         if((!(bl->ban->flags & UBAN_WILDUSER)) && match(bl->ban->u, cptr->user->username)) 
            continue;

         if((cptr->ip.s_addr & bl->ban->cidr4mask) == bl->ban->cidr4ip)
            return bl->ban;
      }
   }

   if(yflags & UBAN_HOST)
   {
      unsigned int hv = host_hash(cptr->user->host) % HASH_SIZE;

      LIST_FOREACH(bl, &host_bans.hash_list[hv], lp) 
      {
         if((bl->ban->flags & UBAN_TEMPORARY) && bl->ban->timeset + bl->ban->duration <= NOW)
            continue;

         if( ((yflags & UBAN_WILDUSER) && !(bl->ban->flags & UBAN_WILDUSER)) ||
             ((nflags & UBAN_WILDUSER) && (bl->ban->flags & UBAN_WILDUSER)))
            continue;

         if((!(bl->ban->flags & UBAN_WILDUSER)) && match(bl->ban->u, cptr->user->username)) 
            continue;

         if(mycmp(bl->ban->h, cptr->user->host) == 0)
            return bl->ban;
      }

      LIST_FOREACH(bl, &host_bans.wild_list, lp) 
      {
         if((bl->ban->flags & UBAN_TEMPORARY) && bl->ban->timeset + bl->ban->duration <= NOW)
            continue;

         if( ((yflags & UBAN_WILDUSER) && !(bl->ban->flags & UBAN_WILDUSER)) ||
             ((nflags & UBAN_WILDUSER) && (bl->ban->flags & UBAN_WILDUSER)))
            continue;

         if((!(bl->ban->flags & UBAN_WILDUSER)) && match(bl->ban->u, cptr->user->username)) 
            continue;

         if((bl->ban->flags & UBAN_WILDHOST) || match(bl->ban->h, cptr->user->host) == 0)
            return bl->ban;
      }
   }
   return NULL;
}

struct userBan *find_userban_exact(struct userBan *borig, unsigned int careflags)
{
   uBanEnt *bl;

   if(borig->flags & UBAN_CIDR4BIG)
   {
      LIST_FOREACH(bl, &CIDR4BIG_bans, lp) {
         /* must have same wilduser, etc setting */
         if((bl->ban->flags ^ borig->flags) & (UBAN_WILDUSER|careflags))
            continue;

         /* user fields do not match? */
         if(!(borig->flags & UBAN_WILDUSER) && mycmp(borig->u, bl->ban->u))
            continue;

         if(!((borig->cidr4ip == bl->ban->cidr4ip) && (borig->cidr4mask == bl->ban->cidr4mask)))
            continue;

         return bl->ban;
      }

      return NULL;
   }

   if(borig->flags & UBAN_CIDR4)
   {
      unsigned char *s = (unsigned char *) &borig->cidr4ip;
      int a, b;

      a = (int) *s++;
      b = (int) *s;

      LIST_FOREACH(bl, &CIDR4_bans[a][b], lp) {
         if((bl->ban->flags ^ borig->flags) & (UBAN_WILDUSER|careflags))
            continue;

         if(!(borig->flags & UBAN_WILDUSER) && mycmp(borig->u, bl->ban->u))
            continue;

         if(!((borig->cidr4ip == bl->ban->cidr4ip) && (borig->cidr4mask == bl->ban->cidr4mask)))
            continue;

         return bl->ban;
      }

      return NULL;
   }

   if(borig->flags & UBAN_IP)
   {
      if(borig->flags & UBAN_WILD)
      {
         LIST_FOREACH(bl, &ip_bans.wild_list, lp) {
            if((bl->ban->flags ^ borig->flags) & (UBAN_WILDUSER|careflags))
               continue;

            if(!(borig->flags & UBAN_WILDUSER) && mycmp(borig->u, bl->ban->u))
               continue;

            if(mycmp(borig->h, bl->ban->h))
               continue;

            return bl->ban;
         }
      }
      else
      {
         unsigned int hv = ip_hash(borig->h) % HASH_SIZE;

         LIST_FOREACH(bl, &ip_bans.hash_list[hv], lp) {
            if((bl->ban->flags ^ borig->flags) & (UBAN_WILDUSER|careflags))
               continue;

            if(!(borig->flags & UBAN_WILDUSER) && mycmp(borig->u, bl->ban->u))
               continue;

            if(mycmp(borig->h, bl->ban->h))
               continue;

            return bl->ban;
         }
      }

      return NULL;
   }

   if(borig->flags & UBAN_HOST)
   {
      if(borig->flags & UBAN_WILD)
      {
         LIST_FOREACH(bl, &host_bans.wild_list, lp) {
            if((bl->ban->flags ^ borig->flags) & (UBAN_WILDUSER|careflags))
               continue;

            if(!(borig->flags & UBAN_WILDUSER) && mycmp(borig->u, bl->ban->u))
               continue;

            if(mycmp(borig->h, bl->ban->h))
               continue;

            return bl->ban;
         }
      }
      else
      {
         unsigned int hv = host_hash(borig->h) % HASH_SIZE;

         LIST_FOREACH(bl, &host_bans.hash_list[hv], lp) {
            if((bl->ban->flags ^ borig->flags) & (UBAN_WILDUSER|careflags))
               continue;

            if(!(borig->flags & UBAN_WILDUSER) && mycmp(borig->u, bl->ban->u))
               continue;

            if(mycmp(borig->h, bl->ban->h))
               continue;

            return bl->ban;
         }
      }

      return NULL;
   }

   /* unreachable code */
   abort();
}

static inline void expire_list(uBanEnt *bl)
{
   uBanEnt *bln;
   struct userBan *ban;

   while(bl)
   {
      bln = LIST_NEXT(bl, lp);
      ban = bl->ban;

      if((ban->flags & UBAN_TEMPORARY) && ban->timeset + ban->duration <= NOW)
      {
         remove_userban(ban);
         userban_free(ban);
      }
      bl = bln;
   }
}

static inline void remove_list_match_flags(uBanEnt *bl, unsigned int flags, unsigned int nflags)
{
   uBanEnt *bln;
   struct userBan *ban;

   while(bl)
   {
      bln = LIST_NEXT(bl, lp);
      ban = bl->ban;

      if((flags == 0 && nflags == 0) || (((ban->flags & flags) == flags) && ((ban->flags & nflags) == 0)))
      {
         remove_userban(ban);
         userban_free(ban);
      }
      bl = bln;
   }
}

static inline void report_list_match_flags(aClient *cptr, uBanEnt *bl, unsigned int flags, unsigned int nflags, char rchar)
{
   struct userBan *ban;
   char kset[8];
   char host[128];

   while(bl)
   {
      ban = bl->ban;

      if((flags == 0 && nflags == 0) || (((ban->flags & flags) == flags) && ((ban->flags & nflags) == 0)))
      {
         if(ban->flags & UBAN_LOCAL)
         {
            if(ban->flags & UBAN_TEMPORARY)
               kset[0] = 'k';
            else
               kset[0] = 'K';
         }
         else
         {
            kset[0] = 'a';
         }
         kset[1] = rchar;
         kset[2] = '\0';

         if(ban->flags & (UBAN_CIDR4|UBAN_CIDR4BIG))
            snprintf(host, 128, "%s/%d", inetntoa((char *)&ban->cidr4ip), netmask_to_cidr(ntohl(ban->cidr4mask)));
         else
            strcpy(host, ban->h);

         sendto_one(cptr, rpl_str(RPL_STATSKLINE), me.name,
                    cptr->name, kset, host,
                    (ban->flags & UBAN_WILDUSER) ? "*" : ban->u, 
                    (ban->flags & UBAN_TEMPORARY) ? (((ban->timeset + ban->duration) - NOW) / 60) : -1, 
                    (ban->reason) ? ban->reason : "No reason");
      }

      bl = LIST_NEXT(bl, lp);
   }
}

void expire_userbans()
{
   uBanEnt *bl;
   int a, b;

   bl = LIST_FIRST(&CIDR4BIG_bans);
   expire_list(bl);

   for(a = 0; a < 256; a++)
   {
     for(b = 0; b < 256; b++)
     {
        bl = LIST_FIRST(&CIDR4_bans[a][b]);
        expire_list(bl);
     }
   }

   bl = LIST_FIRST(&host_bans.wild_list);
   expire_list(bl);
   bl = LIST_FIRST(&ip_bans.wild_list);
   expire_list(bl);

   for(a = 0; a < HASH_SIZE; a++)
   {
      bl = LIST_FIRST(&host_bans.hash_list[a]);
      expire_list(bl);
      bl = LIST_FIRST(&ip_bans.hash_list[a]);
      expire_list(bl);
   }
}

void remove_userbans_match_flags(unsigned int flags, unsigned int nflags)
{
   uBanEnt *bl;
   int a, b;

   bl = LIST_FIRST(&CIDR4BIG_bans);
   remove_list_match_flags(bl, flags, nflags);

   for(a = 0; a < 256; a++)
   {
     for(b = 0; b < 256; b++)
     {
        bl = LIST_FIRST(&CIDR4_bans[a][b]);
        remove_list_match_flags(bl, flags, nflags);
     }
   }

   bl = LIST_FIRST(&host_bans.wild_list);
   remove_list_match_flags(bl, flags, nflags);
   bl = LIST_FIRST(&ip_bans.wild_list);
   remove_list_match_flags(bl, flags, nflags);

   for(a = 0; a < HASH_SIZE; a++)
   {
      bl = LIST_FIRST(&host_bans.hash_list[a]);
      remove_list_match_flags(bl, flags, nflags);
      bl = LIST_FIRST(&ip_bans.hash_list[a]);
      remove_list_match_flags(bl, flags, nflags);
   }
}

void report_userbans_match_flags(aClient *cptr, unsigned int flags, unsigned int nflags)
{
   uBanEnt *bl;
   int a, b;

   bl = LIST_FIRST(&CIDR4BIG_bans);
   report_list_match_flags(cptr, bl, flags, nflags, 'C');

   for(a = 0; a < 256; a++)
   {
     for(b = 0; b < 256; b++)
     {
        bl = LIST_FIRST(&CIDR4_bans[a][b]);
        report_list_match_flags(cptr, bl, flags, nflags, 'c');
     }
   }

   bl = LIST_FIRST(&host_bans.wild_list);
   report_list_match_flags(cptr, bl, flags, nflags, 'h');
   bl = LIST_FIRST(&ip_bans.wild_list);
   report_list_match_flags(cptr, bl, flags, nflags, 'i');

   for(a = 0; a < HASH_SIZE; a++)
   {
      bl = LIST_FIRST(&host_bans.hash_list[a]);
      report_list_match_flags(cptr, bl, flags, nflags, 'H');
      bl = LIST_FIRST(&ip_bans.hash_list[a]);
      report_list_match_flags(cptr, bl, flags, nflags, 'I');
   }
}

char *get_userban_host(struct userBan *ban, char *buf, int buflen)
{
   *buf = '\0';

   if(ban->flags & (UBAN_CIDR4|UBAN_CIDR4BIG))
      snprintf(buf, buflen, "%s/%d", inetntoa((char *)&ban->cidr4ip), netmask_to_cidr(ntohl(ban->cidr4mask)));
   else
      snprintf(buf, buflen, "%s", ban->h);

   return buf;
}

/*
 * Fills in the following fields
 * of a userban structure, or returns NULL if invalid stuff is passed.
 *  - flags, u, h, cidr4ip, cidr4mask
 */
struct userBan *make_hostbased_ban(char *user, char *phost)
{
   char host[512];
   unsigned int flags = 0, c4h = 0, c4m = 0;
   int numcount, othercount, wildcount, dotcount, slashcount;
   char *tmp;
   struct userBan *b;

   strncpy(host, phost, 512);

   numcount = othercount = wildcount = dotcount = slashcount = 0;

   for(tmp = host; *tmp; tmp++)
   {
      switch(*tmp)
      {
         case '0':
         case '1':
         case '2':
         case '3':
         case '4':
         case '5':
         case '6':
         case '7':
         case '8':
         case '9':
            numcount++;
            break;

         case '*':
         case '?':
            wildcount++;
            break;

         case '.':
            dotcount++;
            break;

         case '/':
            slashcount++;
            break;

         default:
            othercount++;
            break;
      }      
   }

   if(wildcount && !numcount && !othercount)
   {
      if(!user || !*user || mycmp(user, "*") == 0)
         return NULL; /* all wildcards? aagh! */

      flags = (UBAN_HOST|UBAN_WILD);

      if(mycmp(host, "*.*") == 0 || mycmp(host, "*") == 0)
         flags |= UBAN_WILDHOST;

      goto success;
   }

   /* everything must have a dot. never more than one slash. */
   if(dotcount == 0 || slashcount > 1)
      return NULL;

   /* wildcarded IP address? -- can we convert it to a CIDR? */
   if(wildcount && numcount && !othercount)
   {
      char octet[4][8];
      int i1, i2;
      int gotwild;

      if(slashcount)
         return NULL; /* slashes and wildcards? */

      /* I see... more than 3 dots? */
      if(dotcount > 3)
         return NULL;

      i1 = i2 = 0;

      /* separate this thing into dotcount octets. */
      for(tmp = host; *tmp; tmp++)
      {
         if(*tmp == '.')
         {
            octet[i1][i2] = '\0';
            i2 = 0;
            i1++;
            continue;
         }
         if(i2 < 6)
         {
            octet[i1][i2++] = *tmp;
         }
      }
      octet[i1][i2] = '\0';

      /* verify that each octet is all numbers or just a '*' */
      /* bans that match 123.123.123.1?? are still valid, just not convertable to a CIDR */

      for(gotwild = i1 = 0; i1 < dotcount; i1++)
      {
         if(strcmp(octet[i1], "*") == 0)
         {
            gotwild++;
            continue;
         }

         /* ban in the format of 1.2.*.4 */
         if(gotwild)
         {
            flags = (UBAN_IP|UBAN_WILD);
            goto success;
         }

         for(i2 = 0; octet[i1][i2]; i2++)
         {
             switch(octet[i1][i2])
             {
                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9':
                   break;

                default:
                   flags = (UBAN_IP|UBAN_WILD);
                   goto success;
             }
         }
      }

      if(octet[0][0] == '*')
         return NULL; /* the first octet is a wildcard? what the hell? */

      if(octet[1][0] == '*')
      {
         sprintf(host, "%s.0.0.0/8", octet[0]);
         goto cidrforce;
      }
      else if(dotcount >= 2 && octet[2][0] == '*')
      {
         sprintf(host, "%s.%s.0.0/16", octet[0], octet[1]);
         goto cidrforce;
      }
      else if(dotcount >= 3 && octet[3][0] == '*')
      {
         sprintf(host, "%s.%s.%s.0/24", octet[0], octet[1], octet[2]);
         goto cidrforce;
      }

      return NULL; /* we should never get here. If we do, something is wrong. */
   }

   /* CIDR IP4 address? */
   if(!wildcount && numcount && !othercount && slashcount)
   {
      int sval;
      char *sep, *err;
      struct in_addr ia, na;

cidrforce:
      sep = strchr(host, '/'); /* guaranteed to be here because slashcount */
      *sep = '\0';
      sep++;
 
      if((ia.s_addr = inet_addr(host)) == 0xFFFFFFFF) /* invalid ip4 address! */
         return NULL;

      /* is there a problem with the / mask? */
      sval = strtol(sep, &err, 10);
      if(*err != '\0')
         return NULL;

      if(sval < 0 || sval > 32)
         return NULL;

      na.s_addr = htonl(cidr_to_netmask(sval));
      ia.s_addr &= na.s_addr;

      c4h = ia.s_addr;
      c4m = na.s_addr;
      
      flags = (sval < 16) ? UBAN_CIDR4BIG : UBAN_CIDR4;
      goto success;
   }

   if(slashcount)
      return NULL;
 
   if(!othercount)
   {
      flags = (UBAN_IP | (wildcount ? UBAN_WILD : 0));
      goto success;
   }

   flags = (UBAN_HOST | (wildcount ? UBAN_WILD : 0));

success:
   b = userban_alloc();
   if(!b)
      return NULL;

   b->reason = NULL;

   if(flags & (UBAN_CIDR4BIG|UBAN_CIDR4))
   {
      b->cidr4ip = c4h;
      b->cidr4mask = c4m;
      b->h = NULL;
   }
   else
   {
      b->cidr4ip = b->cidr4mask = 0;
      b->h = (char *)MyMalloc(strlen(host) + 1);
      strcpy(b->h, host);
   }

   if(!user || !*user || mycmp(user, "*") == 0)
   {
      flags |= UBAN_WILDUSER;
      b->u = NULL;
   }
   else
   {
      b->u = (char *)MyMalloc(strlen(user) + 1);
      strcpy(b->u, user);
   }

   b->flags = flags;

   return b;   
}

unsigned int ip_hash(char *n)
{
   unsigned int hv = 0;

   while(*n)
   {
      hv = hv * 33 + tolowertab[(unsigned char) *n++];
   }

   return hv;
}

unsigned int host_hash(char *n)
{
   unsigned int hv = 0;

   while(*n)
   {
      if(*n != '.') 
      {
         hv <<= 5;
         hv |= ((touppertab[(unsigned char) *n]) - 65) & 0xFF;
      }
      n++;
   }

   return hv;
}

void init_banlist(aBanList *a, int numbuckets)
{
   memset(a, 0, sizeof(aBanList));
   a->numbuckets = numbuckets;
   a->hash_list = (ban_list *) MyMalloc(numbuckets * sizeof(ban_list));
   memset(a->hash_list, 0, numbuckets * sizeof(ban_list));
}

void init_userban()
{
   int i;

   CIDR4_bans = (ban_list **) MyMalloc(256 * sizeof(ban_list *));
   for(i = 0; i < 256; i++)
   {
      CIDR4_bans[i] = (ban_list *) MyMalloc(256 * sizeof(ban_list));
      memset(CIDR4_bans[i], 0, 256 * sizeof(ban_list));
   }

   init_banlist(&host_bans, HASH_SIZE);
   init_banlist(&ip_bans, HASH_SIZE);
}

unsigned int userban_count = 0, ubanent_count = 0;

struct userBan *userban_alloc()
{
   struct userBan *b;

   b = (struct userBan *) MyMalloc(sizeof(struct userBan));
   if(b)
      userban_count++;
   return b;
}

void userban_free(struct userBan *b)
{
   if(b->u)
      MyFree(b->u);

   if(b->h)
      MyFree(b->h);

   if(b->reason)
      MyFree(b->reason);

   userban_count--;
   MyFree(b);
}

uBanEnt *ubanent_alloc()
{
   uBanEnt *b;

   b = (uBanEnt *) MyMalloc(sizeof(uBanEnt));
   if(b)
      ubanent_count++;
   return b;
}

void ubanent_free(uBanEnt *b)
{
   ubanent_count--;
   MyFree(b);
}
