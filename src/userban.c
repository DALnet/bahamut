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

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "inet.h"
#include "h.h"
#include "userban.h"
#include "queue.h"
#include "memcount.h"

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

aBanList gcos_bans;
aBanList nick_bans;
aBanList chan_bans;

struct userBan *userban_alloc();
struct simBan *simban_alloc();
uBanEnt *ubanent_alloc();
void ubanent_free(uBanEnt *);
void userban_free(struct userBan *);
void simban_free(struct simBan *);
unsigned int host_hash(char *n);
unsigned int ip_hash(char *n);

/* userban (akill/kline) functions */

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
      unsigned char *s = (unsigned char *) &bl->ban->cidr_ip;
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

      strncpyzt(iptmp, cipntoa(cptr), HOSTIPLEN + 1);
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
      if(ban->flags & UBAN_WILD)
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
       if (cptr->ip_family == ban->cidr_family &&
	   bitncmp(&cptr->ip, &ban->cidr_ip, ban->cidr_bits) == 0)
	   return 1;
       else
	   return 0;
   }

   return 0;
}

struct userBan *check_userbanned(aClient *cptr, unsigned int yflags, unsigned int nflags)
{
   char iptmp[HOSTIPLEN + 1];
   uBanEnt *bl;

   strncpyzt(iptmp, cipntoa(cptr), HOSTIPLEN + 1);

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

   if(yflags & UBAN_CIDR4 && cptr->ip_family == AF_INET)
   {
      unsigned char *s = (unsigned char *) &cptr->ip.ip4.s_addr;
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

	 if(cptr->ip_family == bl->ban->cidr_family &&
	    bitncmp(&cptr->ip, &bl->ban->cidr_ip, bl->ban->cidr_bits) == 0)
	     return bl->ban;
      }
   }

   if(yflags & UBAN_CIDR4)
   {
      LIST_FOREACH(bl, &CIDR4BIG_bans, lp) 
      {
         if((bl->ban->flags & UBAN_TEMPORARY) && bl->ban->timeset + bl->ban->duration <= NOW)
            continue;

         if( ((yflags & UBAN_WILDUSER) && !(bl->ban->flags & UBAN_WILDUSER)) ||
             ((nflags & UBAN_WILDUSER) && (bl->ban->flags & UBAN_WILDUSER)))
            continue;

         if((!(bl->ban->flags & UBAN_WILDUSER)) && match(bl->ban->u, cptr->user->username)) 
            continue;

	 if(cptr->ip_family == bl->ban->cidr_family &&
	    bitncmp(&cptr->ip, &bl->ban->cidr_ip, bl->ban->cidr_bits) == 0)
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

	 if (!(borig->cidr_family == bl->ban->cidr_family &&
	       memcmp(&borig->cidr_ip, &bl->ban->cidr_ip,
		      sizeof(borig->cidr_ip)) == 0 &&
	       borig->cidr_bits == bl->ban->cidr_bits))
            continue;

         return bl->ban;
      }

      return NULL;
   }

   if(borig->flags & UBAN_CIDR4)
   {
      unsigned char *s = (unsigned char *) &borig->cidr_ip;
      int a, b;

      a = (int) *s++;
      b = (int) *s;

      LIST_FOREACH(bl, &CIDR4_bans[a][b], lp) {
         if((bl->ban->flags ^ borig->flags) & (UBAN_WILDUSER|careflags))
            continue;

         if(!(borig->flags & UBAN_WILDUSER) && mycmp(borig->u, bl->ban->u))
            continue;

	 if (!(borig->cidr_family == bl->ban->cidr_family &&
	       memcmp(&borig->cidr_ip, &bl->ban->cidr_ip,
		      sizeof(borig->cidr_ip)) == 0 &&
	       borig->cidr_bits == bl->ban->cidr_bits))

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
	 {
	     if (ban->cidr_family == AF_INET)
	     {
		 snprintf(host, 128, "%s/%d",
			  inetntoa((char*)&ban->cidr_ip),
			  ban->cidr_bits);
	     }
	     else if (ban->cidr_family == AF_INET6)
	     {
		 snprintf(host, 128, "%s/%d",
			  inet6ntoa((char*)&ban->cidr_ip),
			  ban->cidr_bits);
	     }
	 }
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
   {
	 if (ban->cidr_family == AF_INET)
	 {
	     snprintf(buf, buflen, "%s/%d",
		      inetntoa((char*)&ban->cidr_ip),
		      ban->cidr_bits);
	 }
	 else if (ban->cidr_family == AF_INET6)
	 {
	     snprintf(buf, buflen, "%s/%d",
		      inet6ntoa((char*)&ban->cidr_ip),
		      ban->cidr_bits);
	 }
   }
   else
      snprintf(buf, buflen, "%s", ban->h);

   return buf;
}

/*
 * Fills in the following fields
 * of a userban structure, or returns NULL if invalid stuff is passed.
 *  - flags, u, h, cidr_*
 */
struct userBan *make_hostbased_ban(char *user, char *host)
{
   int cidr_family = 0;
   struct
   {
       char buf[16];
   } cidr_ip;		/* CIDR IP */
   int cidr_bits;	/* CIDR bits */
   unsigned int flags = 0;
   struct userBan *b;
   char *p;

   int has_colon, has_dot, has_ip4, has_wild, has_nonwild;

   /* check for an IP address with an optional CIDR or trailing .* */
   cidr_bits = inet_parse_cidr(AF_INET, host, &cidr_ip,
			       sizeof(struct in_addr));
   if (cidr_bits == 32)
   {
       flags = UBAN_IP;
       goto success;
   }
   else if (cidr_bits > 0)
   {
       cidr_family = AF_INET;
       flags = (cidr_bits < 16) ? UBAN_CIDR4BIG : UBAN_CIDR4;
       goto success;
   }
   else
   {
       cidr_bits = inet_parse_cidr(AF_INET6, host, &cidr_ip,
				   sizeof(struct in6_addr));
       if (cidr_bits == 128)
       {
	   flags = UBAN_IP;
	   goto success;
       }
       else if (cidr_bits > 0)
       {
	   cidr_family = AF_INET6;
	   flags = UBAN_CIDR4BIG;
	   goto success;
       }
   }

   has_colon = has_dot = has_wild = has_nonwild = 0;
   has_ip4 = 1;
   for (p = host; *p != '\0'; p++)
   {
       if (*p == '/')
	   return NULL;
       else if (*p == '.')
	   has_dot = 1;
       else if (*p == '*' || *p == '?')
	   has_wild = 1;
       else
       {
	   has_nonwild = 1;

	   if (*p == ':')
	       has_colon = 1;
	   if (!(*p >= '0' && *p <= '9'))
	       has_ip4 = 0;
       }
   }

   /* host is all wildcards? */
   if (has_wild && !has_nonwild)
   {
       if(!user || !*user || mycmp(user, "*") == 0)
	   return NULL;

       flags = (UBAN_HOST | UBAN_WILD);

       if(mycmp(host, "*.*") == 0 || mycmp(host, "*") == 0)
	   flags |= UBAN_WILDHOST;
   }

   /* everything must have a dot or colon. */
   else if (!has_dot && !has_colon)
       return NULL;

   /* an IPv6 address? */
   else if (has_colon)
   {
       /* it must have a wildcard; non-wildcards are handled above. */
       if (!has_wild)
	   return NULL;
       else
	   flags = (UBAN_IP | (has_wild ? UBAN_WILD : 0));
   }

   /* an IPv4 address? */
   else if (has_ip4)
       flags = (UBAN_IP | (has_wild ? UBAN_WILD : 0));

   /* or a hostname */
   else
       flags = (UBAN_HOST | (has_wild ? UBAN_WILD : 0));

success:
   b = userban_alloc();
   if(!b)
      return NULL;

   b->reason = NULL;

   if(flags & (UBAN_CIDR4BIG|UBAN_CIDR4))
   {
       b->cidr_family = cidr_family;
       memcpy(&b->cidr_ip, &cidr_ip, sizeof(cidr_ip));
       b->cidr_bits = cidr_bits;
       b->h = NULL;
   }
   else
   {
      b->cidr_family = 0;
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

/* simban (simple ban) functions */

/*
 * make_simpleban does only simple sanity checking.
 * You must pass it one of each of the following flags in 'flags', or'd together:
 * SBAN_GCOS (gline) or SBAN_NICK (qline) or SBAN_CHAN (channel qline)
 * SBAN_LOCAL or SBAN_NETWORK (self-explanatory)
 */
struct simBan *make_simpleban(unsigned int flags, char *mask) 
{
   char *tmp;
   struct simBan *b;
   int wildcount = 0, othercount = 0;

   for(tmp = mask; *tmp; tmp++)
   {
      switch(*tmp)
      {
         case '*':
         case '?':
            wildcount++;
            break;

         default:
            othercount++;
            break;
      }
   }

   if((flags & (SBAN_NETWORK|SBAN_LOCAL)) == 0)
      return NULL;

   if((flags & (SBAN_NICK|SBAN_GCOS|SBAN_CHAN)) == 0)
      return NULL;

   if(othercount == 0)
      return NULL; /* No bans consisting only of wildcards */

   if(wildcount)
      flags |= SBAN_WILD;

   b = simban_alloc();
   if(!b) 
      return NULL;

   b->reason = NULL;
   b->mask = (char *) MyMalloc(strlen(mask) + 1);
   strcpy(b->mask, mask);
   b->flags = flags;

   return b;
}

void add_simban(struct simBan *b)
{
   uBanEnt *bl;
   aBanList *banlist;
   ban_list *thelist;

   bl = ubanent_alloc();
   bl->ban = (struct userBan *) b;
   b->internal_ent = (void *) bl;

   if(b->flags & SBAN_NICK)
      banlist = &nick_bans;
   else if(b->flags & SBAN_CHAN)
      banlist = &chan_bans;
   else if(b->flags & SBAN_GCOS)
      banlist = &gcos_bans;
   else
      abort(); /* ack! */

   if(b->flags & SBAN_WILD)
   {
      thelist = &banlist->wild_list;
   }
   else
   {
      unsigned int hv = host_hash(b->mask) % HASH_SIZE;

      thelist = &banlist->hash_list[hv];
   }

   LIST_INSERT_HEAD(thelist, bl, lp);
}

void remove_simban(struct simBan *b)
{
   uBanEnt *bl = (uBanEnt *) b->internal_ent;

   LIST_REMOVE(bl, lp);

   ubanent_free(bl);

   return;
}

struct simBan *find_simban_exact(struct simBan *borig)
{
   uBanEnt *bl;
   struct simBan *ban;
   aBanList *banlist;
   ban_list *thelist;

   if(borig->flags & SBAN_NICK)
      banlist = &nick_bans;
   else if(borig->flags & SBAN_CHAN)
      banlist = &chan_bans;
   else if(borig->flags & SBAN_GCOS)
      banlist = &gcos_bans;
   else
      return NULL;

   if(borig->flags & SBAN_WILD)
   {
      thelist = &banlist->wild_list;
   }
   else
   {
      unsigned int hv = host_hash(borig->mask) % HASH_SIZE;

      thelist = &banlist->hash_list[hv];
   }
 
   LIST_FOREACH(bl, thelist, lp) 
   {
      ban = (struct simBan *) bl->ban;

      if(ban->flags != borig->flags)
         continue;

      if(mycmp(ban->mask, borig->mask))
         continue;

      return ban;
   }

   return NULL;
}

/* does cptr match the ban specified in b? 
 * return: 0 = no
 */
int user_match_simban(aClient *cptr, struct simBan *b)
{
   char *userinfo;
   int (*chkfnc)(char *, char *);

   if(b->flags & SBAN_NICK)
      userinfo = cptr->name;
   else if(b->flags & SBAN_CHAN)
      return 0; /* not applicable */
   else if(b->flags & SBAN_GCOS)
      userinfo = cptr->info;
   else
      abort(); /* aagh! */

   if(b->flags & SBAN_WILD)
      chkfnc = match;
   else
      chkfnc = mycmp;
 
   if(chkfnc(b->mask, userinfo) == 0)
      return 1;

   return 0;
}

struct simBan *check_mask_simbanned(char *mask, unsigned int flags)
{
   uBanEnt *bl;
   struct simBan *ban;
   aBanList *banlist;
   ban_list *thelist;
   int (*chkfnc)(char *, char *);
   unsigned int hv;

   if(flags & SBAN_NICK)
      banlist = &nick_bans;
   else if(flags & SBAN_CHAN)
      banlist = &chan_bans;
   else if(flags & SBAN_GCOS)
      banlist = &gcos_bans;
   else
      abort(); /* aagh! */

   hv = host_hash(mask) % HASH_SIZE;
   thelist = &banlist->hash_list[hv];
   chkfnc = mycmp;
   LIST_FOREACH(bl, thelist, lp) 
   {
      ban = (struct simBan *) bl->ban;

      if((ban->flags & SBAN_TEMPORARY) && ban->timeset + ban->duration <= NOW)
         continue;

      if(chkfnc(ban->mask, mask))
         continue;

      return ban;
   }

   thelist = &banlist->wild_list;
   chkfnc = match;
   LIST_FOREACH(bl, thelist, lp) 
   {
      ban = (struct simBan *) bl->ban;

      if((ban->flags & SBAN_TEMPORARY) && ban->timeset + ban->duration <= NOW)
         continue;

      if(chkfnc(ban->mask, mask))
         continue;

      return ban;
   }

   return NULL;
}

void report_simbans_match_flags(aClient *cptr, unsigned int flags, unsigned int nflags)
{
   uBanEnt *bl;
   struct simBan *ban;
   aBanList *banlist;
   ban_list *thelist;
   unsigned int hv;
   char sbuf[16];
   int slen;

   if(flags & SBAN_NICK)
      banlist = &nick_bans;
   else if(flags & SBAN_CHAN)
      banlist = &chan_bans;
   else if(flags & SBAN_GCOS)
      banlist = &gcos_bans;
   else
      abort(); /* aagh! */

   for(hv = 0; hv < HASH_SIZE; hv++)
   {
      thelist = &banlist->hash_list[hv];
      LIST_FOREACH(bl, thelist, lp)
      {
         ban = (struct simBan *) bl->ban;

         if((ban->flags & SBAN_TEMPORARY) && ban->timeset + ban->duration <= NOW)
            continue;

         if(((ban->flags & flags) == flags) && ((ban->flags & nflags) == 0))
         {
            int rpl = RPL_STATSQLINE;
            slen = 0;
            if(flags & SBAN_NICK)
            {
               sbuf[slen++] = (flags & SBAN_LOCAL) ? 'Q' : 'q';
               sbuf[slen++] = 'n';
            }
            else if(flags & SBAN_CHAN)
            {
               sbuf[slen++] = (flags & SBAN_LOCAL) ? 'Q' : 'q';
               sbuf[slen++] = 'c';
            }
            else if(flags & SBAN_GCOS)
            {
               rpl = RPL_STATSGLINE;
               sbuf[slen++] = (flags & SBAN_LOCAL) ? 'G' : 'g';
            }
            sbuf[slen] = '\0';

            sendto_one(cptr, rpl_str(rpl), me.name, cptr->name,
                       sbuf, 
                       ban->mask, 
                       (ban->flags & SBAN_TEMPORARY) ? (((ban->timeset + ban->duration) - NOW) / 60) : -1,
                       ban->reason ? ban->reason : "No Reason");
         }
      }
   }

   thelist = &banlist->wild_list;
   LIST_FOREACH(bl, thelist, lp)
   {
      ban = (struct simBan *) bl->ban;

      if((ban->flags & SBAN_TEMPORARY) && ban->timeset + ban->duration <= NOW)
         continue;

      if(((ban->flags & flags) == flags) && ((ban->flags & nflags) == 0))
      {
         int rpl = RPL_STATSQLINE;
         slen = 0;
         if(flags & SBAN_NICK)
         {
            sbuf[slen++] = (flags & SBAN_LOCAL) ? 'Q' : 'q';
            sbuf[slen++] = 'n';
         }
         else if(flags & SBAN_CHAN)
         {
            sbuf[slen++] = (flags & SBAN_LOCAL) ? 'Q' : 'q';
            sbuf[slen++] = 'c';
         }
         else if(flags & SBAN_GCOS)
         {
            rpl = RPL_STATSGLINE;
            sbuf[slen++] = (flags & SBAN_LOCAL) ? 'G' : 'g';
         }
         sbuf[slen++] = 'w';
         sbuf[slen] = '\0';

         sendto_one(cptr, rpl_str(rpl), me.name, cptr->name,
                    sbuf, 
                    ban->mask, 
                    (ban->flags & SBAN_TEMPORARY) ? (((ban->timeset + ban->duration) - NOW) / 60) : -1,
                    ban->reason ? ban->reason : "No Reason");
      }
   }   
}


void remove_simbans_match_flags(unsigned int flags, unsigned int nflags)
{
   uBanEnt *bl;
   struct simBan *ban;
   aBanList *banlist;
   ban_list *thelist;
   unsigned int hv;

   if(flags & SBAN_NICK)
      banlist = &nick_bans;
   else if(flags & SBAN_CHAN)
      banlist = &chan_bans;
   else if(flags & SBAN_GCOS)
      banlist = &gcos_bans;
   else
      abort(); /* aagh! */

   for(hv = 0; hv < HASH_SIZE; hv++)
   {
      thelist = &banlist->hash_list[hv];
      LIST_FOREACH(bl, thelist, lp)
      {
         ban = (struct simBan *) bl->ban;

         if((ban->flags & SBAN_TEMPORARY) && ban->timeset + ban->duration <= NOW)
            continue;

         if(((ban->flags & flags) == flags) && ((ban->flags & nflags) == 0))
         {
            /* Kludge it out! */
            ban->flags |= SBAN_TEMPORARY;
            ban->timeset = NOW - 5;
            ban->duration = 1;
         }
      }
   }

   thelist = &banlist->wild_list;
   LIST_FOREACH(bl, thelist, lp)
   {
      ban = (struct simBan *) bl->ban;

      if((ban->flags & SBAN_TEMPORARY) && ban->timeset + ban->duration <= NOW)
         continue;

      if(((ban->flags & flags) == flags) && ((ban->flags & nflags) == 0))
      {
         /* Kludge it out! */
         ban->flags |= SBAN_TEMPORARY;
         ban->timeset = NOW - 5;
         ban->duration = 1;
      }
   }   
}

void send_simbans(aClient *cptr, unsigned int flags)
{
   uBanEnt *bl;
   struct simBan *ban;
   aBanList *banlist;
   ban_list *thelist;
   unsigned int hv;

   if(flags & SBAN_NICK)
      banlist = &nick_bans;
   else if(flags & SBAN_CHAN)
      banlist = &chan_bans;
   else if(flags & SBAN_GCOS)
      banlist = &gcos_bans;
   else
      abort(); /* aagh! */

   for(hv = 0; hv < HASH_SIZE; hv++)
   {
      thelist = &banlist->hash_list[hv];
      LIST_FOREACH(bl, thelist, lp)
      {
         ban = (struct simBan *) bl->ban;

         if(ban->flags & SBAN_TEMPORARY)
            continue;

         if((ban->flags & flags) == flags)
         {
            if(ban->flags & SBAN_GCOS)
               sendto_one(cptr, ":%s SGLINE %d :%s:%s", me.name, (int)strlen(ban->mask),
                          ban->mask, ban->reason);
            else
               sendto_one(cptr, ":%s SQLINE %s :%s", me.name,
                          ban->mask, ban->reason);
         }
      }
   }

   thelist = &banlist->wild_list;
   LIST_FOREACH(bl, thelist, lp)
   {
      ban = (struct simBan *) bl->ban;

      if(ban->flags & SBAN_TEMPORARY)
         continue;

      if((ban->flags & flags) == flags)
      {
         if(ban->flags & SBAN_GCOS)
            sendto_one(cptr, ":%s SGLINE %d :%s:%s", me.name, (int)strlen(ban->mask),
                       ban->mask, ban->reason);
         else
            sendto_one(cptr, ":%s SQLINE %s :%s", me.name,
                       ban->mask, ban->reason);
      }
   }   
}

void remove_simbans_match_mask(unsigned int flags, char *mask, int wild)
{
   uBanEnt *bl;
   struct simBan *ban;
   aBanList *banlist;
   ban_list *thelist;
   unsigned int hv;
   int (*chkfnc)(char *, char *);

   chkfnc = wild ? match : mycmp;

   if(flags & SBAN_NICK)
      banlist = &nick_bans;
   else if(flags & SBAN_CHAN)
      banlist = &chan_bans;
   else if(flags & SBAN_GCOS)
      banlist = &gcos_bans;
   else
      abort(); /* aagh! */

   for(hv = 0; hv < HASH_SIZE; hv++)
   {
      thelist = &banlist->hash_list[hv];
      LIST_FOREACH(bl, thelist, lp)
      {
         ban = (struct simBan *) bl->ban;

         if((ban->flags & SBAN_TEMPORARY) && ban->timeset + ban->duration <= NOW)
            continue;

         if((ban->flags & flags) != flags)
            continue;

         if(chkfnc(mask, ban->mask) == 0)
         {
            /* Kludge it out! */
            ban->flags |= SBAN_TEMPORARY;
            ban->timeset = NOW - 5;
            ban->duration = 1;
         }
      }
   }

   thelist = &banlist->wild_list;
   LIST_FOREACH(bl, thelist, lp)
   {
      ban = (struct simBan *) bl->ban;

      if((ban->flags & SBAN_TEMPORARY) && ban->timeset + ban->duration <= NOW)
         continue;

      if((ban->flags & flags) != flags)
         continue;

      if(chkfnc(mask, ban->mask) == 0)
      {
         /* Kludge it out! */
         ban->flags |= SBAN_TEMPORARY;
         ban->timeset = NOW - 5;
         ban->duration = 1;
      }
   }   
}

static inline void expire_simlist(uBanEnt *bl)
{
   uBanEnt *bln;
   struct simBan *ban;

   while(bl)
   {
      bln = LIST_NEXT(bl, lp);
      ban = (struct simBan *)bl->ban;

      if((ban->flags & SBAN_TEMPORARY) && ban->timeset + ban->duration <= NOW)
      {
         remove_simban(ban);
         simban_free(ban);
      }
      bl = bln;
   }
}

void expire_simbans()
{
   uBanEnt *bl;
   int a;

   bl = LIST_FIRST(&nick_bans.wild_list);
   expire_simlist(bl);
   bl = LIST_FIRST(&chan_bans.wild_list);
   expire_simlist(bl);
   bl = LIST_FIRST(&gcos_bans.wild_list);
   expire_simlist(bl);

   for(a = 0; a < HASH_SIZE; a++)
   {
      bl = LIST_FIRST(&nick_bans.hash_list[a]);
      expire_simlist(bl);
      bl = LIST_FIRST(&chan_bans.hash_list[a]);
      expire_simlist(bl);
      bl = LIST_FIRST(&gcos_bans.hash_list[a]);
      expire_simlist(bl);
   }
}

/* Hash and init functions */

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

   init_banlist(&gcos_bans, HASH_SIZE);
   init_banlist(&nick_bans, HASH_SIZE);
   init_banlist(&chan_bans, HASH_SIZE);
}

unsigned int userban_count = 0, ubanent_count = 0, simban_count = 0;

struct userBan *userban_alloc()
{
   struct userBan *b;

   b = (struct userBan *) MyMalloc(sizeof(struct userBan));
   if(b)
   {
      memset(b, 0, sizeof(struct userBan));
      userban_count++;
   }
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
   {
      memset(b, 0, sizeof(uBanEnt));
      ubanent_count++;
   }
   return b;
}

void ubanent_free(uBanEnt *b)
{
   ubanent_count--;
   MyFree(b);
}

struct simBan *simban_alloc()
{
   struct simBan *b;

   b = (struct simBan *) MyMalloc(sizeof(struct simBan));
   if(b)
   {
      memset(b, 0, sizeof(struct simBan));
      simban_count++;
   }
   return b;
}

void simban_free(struct simBan *b)
{
   if(b->mask)
      MyFree(b->mask);

   if(b->reason)
      MyFree(b->reason);

   simban_count--;
   MyFree(b);
}

/*
 * Dump all local connections that match a userban.
 */
void userban_sweep(struct userBan *ban)
{
    int loc = (ban->flags & UBAN_LOCAL) ? 1 : 0;
    int clientonly = 1;
    aClient *acptr;
    char *ntext;
    int i;

    if (loc)
        ntext = LOCAL_BAN_NAME;
    else
        ntext = NETWORK_BAN_NAME;

    /* if it's purely IP based, dump unregistered and server connections too */
    if (ban->flags & UBAN_WILDUSER)
        if (ban->flags & (UBAN_IP|UBAN_CIDR4|UBAN_CIDR4BIG))
            clientonly = 0;

    for (i = 0; i <= highest_fd; i++)
    {
        if (!(acptr = local[i]) || acptr->status < STAT_UNKNOWN)
            continue;

        if (clientonly && !IsPerson(acptr))
            continue;

        if (user_match_ban(acptr, ban))
        {
            sendto_ops("%s active for %s", ntext,
                       get_client_name(acptr, FALSE));
            exit_banned_client(acptr, loc, loc ? 'K' : 'A', ban->reason, 1);
            i--;
        }
    }
}


/*
 * ks_dumpklines() helper
 */
static void
ks_dumplist(int f, uBanEnt *be)
{
    struct userBan *ub;

    /* klines.c */
    extern void ks_write(int, char, struct userBan *);

    for (; be; be = LIST_NEXT(be, lp))
    {
        ub = be->ban;

        /* must be local and not from conf */
        if ((ub->flags & (UBAN_LOCAL|UBAN_CONF)) != UBAN_LOCAL)
            continue;

        /* must be over the storage threshold duration */
        if ((ub->flags & UBAN_TEMPORARY)
            && ub->duration < (KLINE_MIN_STORE_TIME * 60))
            continue;

        ks_write(f, '+', ub);
    }
}

/*
 * Called from klines.c during a storage GC.
 */
void
ks_dumpklines(int f)
{
    int i, j;

    for (i = 0; i < 256; i++)
        for (j = 0; j < 256; j++)
            ks_dumplist(f, LIST_FIRST(&CIDR4_bans[i][j]));

    ks_dumplist(f, LIST_FIRST(&CIDR4BIG_bans));
    ks_dumplist(f, LIST_FIRST(&host_bans.wild_list));
    ks_dumplist(f, LIST_FIRST(&ip_bans.wild_list));

    for (i = 0; i < HASH_SIZE; i++)
    {
        ks_dumplist(f, LIST_FIRST(&host_bans.hash_list[i]));
        ks_dumplist(f, LIST_FIRST(&ip_bans.hash_list[i]));
    }
}

static void
mc_userlist(MemCount *mc, uBanEnt *be)
{
    struct userBan *ub;

    while (be)
    {
        ub = be->ban;

        mc->c++;
        mc->m += sizeof(*ub);

        if (ub->u)
            mc->m += strlen(ub->u) + 1;
        if (ub->h)
            mc->m += strlen(ub->h) + 1;
        if (ub->reason)
            mc->m += strlen(ub->reason) + 1;

        be = LIST_NEXT(be, lp);
    }
}

static void
mc_simlist(MemCount *mc, uBanEnt *be)
{
    struct simBan *sb;

    while (be)
    {
        sb = (struct simBan *)be->ban;

        mc->c++;
        mc->m += sizeof(*sb);

        if (sb->mask)
            mc->m += strlen(sb->mask) + 1;
        if (sb->reason)
            mc->m += strlen(sb->reason) + 1;

        be = LIST_NEXT(be, lp);
    }
}

u_long
memcount_userban(MCuserban *mc)
{
    int i;
    int j;

    mc->file = __FILE__;

    /* host, ip, gcos, chan, nick */
    mc->lists.c += 5 * HASH_SIZE;
    mc->lists.m += 5 * HASH_SIZE * sizeof(ban_list);

    /* CIDR4 table */
    mc->lists.c += 256;
    mc->lists.m += 256 * sizeof(ban_list *);

    /* CIDR4 subtables */
    mc->lists.c += 256 * 256;
    mc->lists.m += 256 * 256 * sizeof(ban_list);

    mc_userlist(&mc->cidr4big_userbans, LIST_FIRST(&CIDR4BIG_bans));

    for (i = 0; i < 256; i++)
        for (j = 0; j < 256; j++)
            mc_userlist(&mc->cidr4_userbans, LIST_FIRST(&CIDR4_bans[i][j]));

    mc_userlist(&mc->hostwild_userbans, LIST_FIRST(&host_bans.wild_list));
    mc_userlist(&mc->ipwild_userbans, LIST_FIRST(&ip_bans.wild_list));

    mc_simlist(&mc->nickwild_simbans, LIST_FIRST(&nick_bans.wild_list));
    mc_simlist(&mc->chanwild_simbans, LIST_FIRST(&chan_bans.wild_list));
    mc_simlist(&mc->gcoswild_simbans, LIST_FIRST(&gcos_bans.wild_list));

    for (i = 0; i < HASH_SIZE; i++)
    {
        mc_userlist(&mc->hosthash_userbans,
                    LIST_FIRST(&host_bans.hash_list[i]));
        mc_userlist(&mc->iphash_userbans, LIST_FIRST(&ip_bans.hash_list[i]));

        mc_simlist(&mc->nickhash_simbans, LIST_FIRST(&nick_bans.hash_list[i]));
        mc_simlist(&mc->chanhash_simbans, LIST_FIRST(&chan_bans.hash_list[i]));
        mc_simlist(&mc->gcoshash_simbans, LIST_FIRST(&gcos_bans.hash_list[i]));
    }

    mc->entries.c = ubanent_count;
    mc->entries.m = ubanent_count * sizeof(uBanEnt);

    mc->userbans.c = mc->cidr4big_userbans.c + mc->cidr4_userbans.c;
    mc->userbans.m = mc->cidr4big_userbans.m + mc->cidr4_userbans.m;
    mc->userbans.c += mc->hosthash_userbans.c + mc->hostwild_userbans.c;
    mc->userbans.m += mc->hosthash_userbans.m + mc->hostwild_userbans.m;
    mc->userbans.c += mc->iphash_userbans.c + mc->ipwild_userbans.c;
    mc->userbans.m += mc->iphash_userbans.m + mc->ipwild_userbans.m;

    mc->simbans.c = mc->nickhash_simbans.c + mc->nickwild_simbans.c;
    mc->simbans.m = mc->nickhash_simbans.m + mc->nickwild_simbans.m;
    mc->simbans.c += mc->chanhash_simbans.c + mc->chanwild_simbans.c;
    mc->simbans.m += mc->chanhash_simbans.m + mc->chanwild_simbans.m;
    mc->simbans.c += mc->gcoshash_simbans.c + mc->gcoswild_simbans.c;
    mc->simbans.m += mc->gcoshash_simbans.m + mc->gcoswild_simbans.m;

    mc->total.c = mc->lists.c + mc->entries.c + mc->userbans.c + mc->simbans.c;
    mc->total.m = mc->lists.m + mc->entries.m + mc->userbans.m + mc->simbans.m;

    return mc->total.m;
}

