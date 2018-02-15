/************************************************************************
 *   IRC - Internet Relay Chat, include/msg.h
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
 *
 */

#ifndef	__msg_include__
#define __msg_include__

#define MSG_PRIVATE  "PRIVMSG"		/* PRIV */
#define MSG_WHO      "WHO"	      	/* WHO  -> WHOC */
#define MSG_WHOIS    "WHOIS"	   	/* WHOI */
#define MSG_WHOWAS   "WHOWAS"	   	/* WHOW */
#define MSG_USER     "USER"	   	/* USER */
#define MSG_NICK     "NICK"	   	/* NICK */
#define MSG_SERVER   "SERVER"	   	/* SERV */
#define MSG_LIST     "LIST"	   	/* LIST */
#define MSG_TOPIC    "TOPIC"	   	/* TOPI */
#define MSG_INVITE   "INVITE"	   	/* INVI */
#define MSG_VERSION  "VERSION"		/* VERS */
#define MSG_QUIT     "QUIT"	   	/* QUIT */
#define MSG_SQUIT    "SQUIT"	   	/* SQUI */
#define MSG_KILL     "KILL"	   	/* KILL */
#define MSG_INFO     "INFO"	   	/* INFO */
#define MSG_LINKS    "LINKS"	   	/* LINK */
#define MSG_STATS    "STATS"	   	/* STAT */
#define MSG_USERS    "USERS"	   	/* USER -> USRS */
#define MSG_HELP     "HELP"	   	/* HELP */
#define MSG_ERROR    "ERROR"	   	/* ERRO */
#define MSG_AWAY     "AWAY"	   	/* AWAY */
#define MSG_CONNECT  "CONNECT"		/* CONN */
#define MSG_PING     "PING"	   	/* PING */
#define MSG_PONG     "PONG"	   	/* PONG */
#define MSG_OPER     "OPER"	   	/* OPER */
#define MSG_PASS     "PASS"	   	/* PASS */
#define MSG_WALLOPS  "WALLOPS"		/* WALL */
#define MSG_TIME     "TIME"	   	/* TIME */
#define MSG_NAMES    "NAMES"	   	/* NAME */
#define MSG_ADMIN    "ADMIN"	   	/* ADMI */
#define MSG_TRACE    "TRACE"	   	/* TRAC */
#define MSG_NOTICE   "NOTICE"	   	/* NOTI */
#define MSG_JOIN     "JOIN"	   	/* JOIN */
#define MSG_PART     "PART"	   	/* PART */
#define MSG_LUSERS   "LUSERS"	   	/* LUSE */
#define MSG_MOTD     "MOTD"	   	/* MOTD */
#define MSG_MODE     "MODE"	   	/* MODE */
#define MSG_KICK     "KICK"	   	/* KICK */
#define MSG_USERHOST "USERHOST"		/* USER -> USRH */
#define MSG_USERIP   "USERIP"		/* USER -> USRH */
#define MSG_ISON     "ISON"	   	/* ISON */
#define MSG_REHASH   "REHASH"	   	/* REHA */
#define MSG_RESTART  "RESTART"		/* REST */
#define MSG_CLOSE    "CLOSE"	   	/* CLOS */
#define MSG_SVINFO   "SVINFO"	   	/* SVINFO */
#define MSG_SJOIN    "SJOIN"	   	/* SJOIN */
#define MSG_DIE	     "DIE" 		/* DIE */
#define MSG_HASH     "HASH"	   	/* HASH */
#define MSG_DNS      "DNS"   	   	/* DNS  -> DNSS */
#define MSG_OPERWALL "OPERWALL"		/* OPERWALL */
#define MSG_GLOBOPS  "GLOBOPS"		/* GLOBOPS */
#define MSG_CHATOPS  "CHATOPS"		/* CHATOPS */
#define MSG_GOPER    "GOPER"	   	/* GOPER */
#define MSG_GNOTICE  "GNOTICE"		/* GNOTICE */
#define MSG_KLINE    "KLINE"	   	/* KLINE */
#define MSG_UNKLINE  "UNKLINE"		/* UNKLINE */
#define MSG_SET      "SET"	      	/* SET */
#define MSG_SAMODE   "SAMODE"    	/* SAMODE */
#define MSG_SAJOIN   "SAJOIN"		/* SAJOIN */
#define MSG_CHANSERV "CHANSERV"		/* CHANSERV */
#define MSG_NICKSERV "NICKSERV"		/* NICKSERV */
#define MSG_MEMOSERV "MEMOSERV"		/* MEMOSERV */
#define MSG_ROOTSERV "ROOTSERV"		/* MEMOSERV */
#define MSG_OPERSERV "OPERSERV"		/* OPERSERV */
#define MSG_STATSERV "STATSERV" 	/* STATSERV */
#define MSG_HELPSERV "HELPSERV" 	/* HELPSERV */
#define MSG_SERVICES "SERVICES"		/* SERVICES */
#define MSG_IDENTIFY "IDENTIFY"		/* IDENTIFY */
#define MSG_CAPAB    "CAPAB"	   	/* CAPAB */ 
#define MSG_LOCOPS   "LOCOPS"	   	/* LOCOPS */
#define MSG_SVSNICK  "SVSNICK"   	/* SVSNICK */
#define MSG_SVSNOOP  "SVSNOOP"   	/* SVSNOOP */
#define MSG_SVSKILL  "SVSKILL"   	/* SVSKILL */
#define MSG_SVSMODE  "SVSMODE"   	/* SVSMODE */
#define MSG_SVSHOLD  "SVSHOLD"		/* SVSHOLD */
#define MSG_AKILL    "AKILL"     	/* AKILL */
#define MSG_RAKILL   "RAKILL"    	/* RAKILL */
#define MSG_NBANRESET "NBANRESET" 	/* NBANRESET */
#define MSG_SILENCE  "SILENCE"   	/* SILENCE */
#define MSG_WATCH    "WATCH"     	/* WATCH */
#define MSG_SQLINE   "SQLINE" 		/* SQLINE */
#define MSG_UNSQLINE "UNSQLINE" 	/* UNSQLINE */
#define MSG_BURST    "BURST"     	/* BURST */
#define MSG_DCCALLOW "DCCALLOW"		/* dccallow */
#define MSG_SGLINE   "SGLINE"           /* sgline */
#define MSG_UNSGLINE "UNSGLINE"         /* unsgline */
#define MSG_DKEY     "DKEY"		/* diffie-hellman negotiation */
#define MSG_NS	     "NS"            	/* NickServ commands */
#define MSG_CS	     "CS"            	/* ChanServ commands */
#define MSG_MS	     "MS"            	/* MemoServ commands */
#define MSG_RS	     "RS"            	/* RootServ commands */
#define MSG_OS	     "OS"            	/* OperServ commands */
#define MSG_SS	     "SS"            	/* StatServ commands */
#define MSG_HS	     "HS"            	/* StatServ commands */
#define MSG_RESYNCH  "RESYNCH"		/* RESYNCH */
#define MSG_LUSERSLOCK "LUSERSLOCK"     /* Lusers LOCK */
#define MSG_LINKSCONTROL "LINKSCONTROL" /* LINKSCONTROL */
#define MSG_MODULE   "MODULE"		/* MODULE */
#define MSG_RWHO     "RWHO"         /* RWHO */
#define MSG_SVSCLONE "SVSCLONE"     /* SVSCLONE */
#define MSG_SVSPANIC "SVSPANIC"     /* SVSPANIC */
#define MSG_CHANKILL "CHANKILL"     /* CHANKILL */
#define MSG_SVSHOST  "SVSHOST"      /* SVSHOST */
#define MSG_SVSTAG   "SVSTAG"       /* SVSTAG */
#define MSG_SVSUHM   "SVSUHM"       /* SVSUHM */
#define MSG_PUT      "PUT"          /* PUT */
#define MSG_POST     "POST"         /* POST */
#define MSG_CHECK    "CHECK"        /* CHECK */

#define MSG_WEBIRC   "WEBIRC"       /* WEBIRC */

#define MAXPARA      15

extern int  m_kline(aClient *, aClient *, int, char **);
extern int  m_unkline(aClient *, aClient *, int, char **);
extern int  m_akill(aClient *, aClient *, int, char **);
extern int  m_rakill(aClient *, aClient *, int, char **);
extern int  m_nbanreset(aClient *, aClient *, int, char **);
extern int  m_locops(aClient *, aClient *, int, char **);
extern int  m_private(aClient *, aClient *, int, char **);
extern int  m_topic(aClient *, aClient *, int, char **);
extern int  m_join(aClient *, aClient *, int, char **);
extern int  m_part(aClient *, aClient *, int, char **);
extern int  m_mode(aClient *, aClient *, int, char **);
extern int  m_ping(aClient *, aClient *, int, char **);
extern int  m_pong(aClient *, aClient *, int, char **);
extern int  m_wallops(aClient *, aClient *, int, char **);
extern int  m_kick(aClient *, aClient *, int, char **);
extern int  m_nick(aClient *, aClient *, int, char **);
extern int  m_error(aClient *, aClient *, int, char **);
extern int  m_notice(aClient *, aClient *, int, char **);
extern int  m_invite(aClient *, aClient *, int, char **);
extern int  m_quit(aClient *, aClient *, int, char **);
extern int  m_kill(aClient *, aClient *, int, char **);
extern int  m_motd(aClient *, aClient *, int, char **);
extern int  m_who(aClient *, aClient *, int, char **);
extern int  m_whois(aClient *, aClient *, int, char **);
extern int  m_user(aClient *, aClient *, int, char **);
extern int  m_list(aClient *, aClient *, int, char **);
extern int  m_server(aClient *, aClient *, int, char **);
extern int  m_info(aClient *, aClient *, int, char **);
extern int  m_links(aClient *, aClient *, int, char **);
extern int  m_summon(aClient *, aClient *, int, char **);
extern int  m_stats(aClient *, aClient *, int, char **);
extern int  m_users(aClient *, aClient *, int, char **);
extern int  m_services(aClient *, aClient *, int, char **);
extern int  m_identify(aClient *, aClient *, int, char **);
extern int  m_aliased(aClient *, aClient *, int, char **, AliasInfo *);
extern int  m_svsnick(aClient *, aClient *, int, char **);
extern int  m_svskill(aClient *, aClient *, int, char **);
extern int  m_svsmode(aClient *, aClient *, int, char **);
extern int  m_svshold(aClient *, aClient *, int, char **);
extern int  m_version(aClient *, aClient *, int, char **);
extern int  m_help(aClient *, aClient *, int, char **);
extern int  m_squit(aClient *, aClient *, int, char **);
extern int  m_away(aClient *, aClient *, int, char **);
extern int  m_connect(aClient *, aClient *, int, char **);
extern int  m_oper(aClient *, aClient *, int, char **);
extern int  m_pass(aClient *, aClient *, int, char **);
extern int  m_trace(aClient *, aClient *, int, char **);
extern int  m_time(aClient *, aClient *, int, char **);
extern int  m_names(aClient *, aClient *, int, char **);
extern int  m_admin(aClient *, aClient *, int, char **);
extern int  m_lusers(aClient *, aClient *, int, char **);
extern int  m_umode(aClient *, aClient *, int, char **);
extern int  m_close(aClient *, aClient *, int, char **);
extern int  m_motd(aClient *, aClient *, int, char **);
extern int  m_whowas(aClient *, aClient *, int, char **);
extern int  m_userhost(aClient *, aClient *, int, char **);
extern int  m_userip(aClient *, aClient *, int, char **);
extern int  m_ison(aClient *, aClient *, int, char **);
extern int  m_svinfo(aClient *, aClient *, int, char **);
extern int  m_sjoin(aClient *, aClient *, int, char **);
extern int  m_samode(aClient *, aClient *, int, char **);
extern int  m_sajoin(aClient *, aClient *, int, char **);
extern int  m_globops(aClient *, aClient *, int, char **);
extern int  m_chatops(aClient *, aClient *, int, char **);
extern int  m_goper(aClient *, aClient *, int, char **);
extern int  m_gnotice(aClient *, aClient *, int, char **);
extern int  m_rehash(aClient *, aClient *, int, char **);
extern int  m_restart(aClient *, aClient *, int, char **);
extern int  m_die(aClient *, aClient *, int, char **);
extern int  m_hash(aClient *, aClient *, int, char **);
extern int  m_dns(aClient *, aClient *, int, char **);
extern int  m_set(aClient *, aClient *, int, char **);
extern int  m_capab(aClient *, aClient *, int, char **);
extern int  m_silence(aClient *, aClient *, int, char **);
extern int  m_watch(aClient *, aClient *, int, char **);
extern int  m_sqline(aClient *, aClient *, int, char **);
extern int  m_unsqline(aClient *, aClient *, int, char **);
extern int  m_burst(aClient *, aClient *, int, char **);
extern int  m_dccallow(aClient *, aClient *, int, char **);
extern int  m_sgline(aClient *, aClient *, int, char **);
extern int  m_unsgline(aClient *, aClient *, int, char **);
extern int  m_dkey(aClient *, aClient *, int, char **);
extern int  m_resynch(aClient *, aClient *, int, char **);
extern int  m_luserslock(aClient *, aClient *, int, char **);
extern int  m_linkscontrol(aClient *, aClient *, int, char **);
extern int  m_module(aClient *, aClient *, int, char **);
extern int  m_rwho(aClient *, aClient *, int, char **);
extern int  m_svsclone(aClient *, aClient *, int, char **);
extern int  m_svspanic(aClient *, aClient *, int, char **);
extern int  m_chankill(aClient *, aClient *, int, char **);
extern int  m_svshost(aClient *, aClient *, int, char **);
extern int  m_svsnoop(aClient *, aClient *, int, char **);
extern int  m_svstag(aClient *, aClient *, int, char **);
extern int  m_svsuhm(aClient *, aClient *, int, char **);
extern int  m_put(aClient *, aClient *, int, char **);
extern int  m_post(aClient *, aClient *, int, char **);
extern int  m_check(aClient *, aClient *, int, char **);
extern int  m_webirc(aClient *, aClient *, int, char **);

/* aliastab indexes */
#define AII_NS  0
#define AII_CS  1
#define AII_MS  2
#define AII_RS  3
#define AII_OS  4
#define AII_SS  5
#define AII_HS  6


#ifdef MSGTAB
AliasInfo aliastab[] =
{
    /* AII_NS */ {MSG_NS, NICKSERV, Services_Name},
    /* AII_CS */ {MSG_CS, CHANSERV, Services_Name},
    /* AII_MS */ {MSG_MS, MEMOSERV, Services_Name},
    /* AII_RS */ {MSG_RS, ROOTSERV, Services_Name},
    /* AII_OS */ {MSG_OS, OPERSERV, Stats_Name},
    /* AII_SS */ {MSG_SS, STATSERV, Stats_Name},
    /* AII_HS */ {MSG_HS, HELPSERV, Stats_Name},
    { 0 }
};

struct Message msgtab[] = 
{
    {MSG_PRIVATE,  m_private,  MAXPARA, MF_RIDLE, 0},
    {MSG_NICK,     m_nick,     MAXPARA, MF_UNREG, 0},
    {MSG_NOTICE,   m_notice,   MAXPARA, 0,        0},
    {MSG_JOIN,     m_join,     MAXPARA, 0,        0},
    {MSG_MODE,     m_mode,     MAXPARA, 0,        0},
    {MSG_SAMODE,   m_samode,   MAXPARA, 0,        0},
    {MSG_SAJOIN,   m_sajoin,   MAXPARA, 0,        0},
    {MSG_QUIT,     m_quit,     MAXPARA, MF_UNREG, 0},
    {MSG_PART,     m_part,     MAXPARA, 0,        0},
    {MSG_TOPIC,    m_topic,    MAXPARA, 0,        0},
    {MSG_INVITE,   m_invite,   MAXPARA, 0,        0},
    {MSG_KICK,     m_kick,     MAXPARA, 0,        0},
    {MSG_WALLOPS,  m_wallops,  MAXPARA, 0,        0},
    {MSG_LOCOPS,   m_locops,   MAXPARA, 0,        0},
    {MSG_PONG,     m_pong,     MAXPARA, 0,        0},
    {MSG_PING,     m_ping,     MAXPARA, 0,        0},
    {MSG_ERROR,    m_error,    MAXPARA, MF_UNREG, 0},
    {MSG_KILL,     m_kill,     MAXPARA, 0,        0},
    {MSG_USER,     m_user,     MAXPARA, MF_UNREG, 0},
    {MSG_AWAY,     m_away,     MAXPARA, 0,        0},
    {MSG_ISON,     m_ison,           1, 0,        0},
    {MSG_SERVER,   m_server,   MAXPARA, MF_UNREG, 0},
    {MSG_SQUIT,    m_squit,    MAXPARA, 0,        0},
    {MSG_WHOIS,    m_whois,    MAXPARA, 0,        0},
    {MSG_WHO,      m_who,      MAXPARA, 0,        0},
    {MSG_WHOWAS,   m_whowas,   MAXPARA, 0,        0},
    {MSG_LIST,     m_list,     MAXPARA, 0,        0},
    {MSG_NAMES,    m_names,    MAXPARA, 0,        0},
    {MSG_USERHOST, m_userhost,       1, 0,        0},
    {MSG_USERIP,   m_userip,         1, 0,        0},
    {MSG_TRACE,    m_trace,    MAXPARA, 0,        0},
    {MSG_PASS,     m_pass,     MAXPARA, MF_UNREG, 0},
    {MSG_LUSERS,   m_lusers,   MAXPARA, 0,        0},
    {MSG_TIME,     m_time,     MAXPARA, 0,        0},
    {MSG_OPER,     m_oper,     MAXPARA, 0,        0},
    {MSG_CONNECT,  m_connect,  MAXPARA, 0,        0},
    {MSG_VERSION,  m_version,  MAXPARA, MF_UNREG, 0},
    {MSG_STATS,    m_stats,    MAXPARA, 0,        0},
    {MSG_LINKS,    m_links,    MAXPARA, 0,        0},
    {MSG_ADMIN,    m_admin,    MAXPARA, MF_UNREG, 0},
    {MSG_USERS,    m_users,    MAXPARA, 0,        0},
    {MSG_HELP,     m_help,     MAXPARA, 0,        0},
    {MSG_INFO,     m_info,     MAXPARA, 0,        0},
    {MSG_MOTD,     m_motd,     MAXPARA, 0,        0},
    {MSG_SVINFO,   m_svinfo,   MAXPARA, MF_UNREG, 0},
    {MSG_SJOIN,    m_sjoin,    MAXPARA, 0,        0},
    {MSG_GLOBOPS,  m_globops,  MAXPARA, 0,        0},
    {MSG_CHATOPS,  m_chatops,  MAXPARA, 0,        0},
    {MSG_GOPER,    m_goper,    MAXPARA, 0,        0},
    {MSG_GNOTICE,  m_gnotice,  MAXPARA, 0,        0},
    {MSG_CLOSE,    m_close,    MAXPARA, 0,        0},
    {MSG_KLINE,    m_kline,    MAXPARA, 0,        0},
    {MSG_UNKLINE,  m_unkline,  MAXPARA, 0,        0},
    {MSG_HASH,     m_hash,     MAXPARA, 0,        0},
    {MSG_DNS,      m_dns,      MAXPARA, 0,        0},
    {MSG_REHASH,   m_rehash,   MAXPARA, 0,        0},
    {MSG_RESTART,  m_restart,  MAXPARA, 0,        0},
    {MSG_DIE,      m_die,      MAXPARA, 0,        0},
    {MSG_SET,      m_set,      MAXPARA, 0,        0},
    {MSG_CHANSERV, m_aliased,        1, MF_ALIAS, AII_CS},
    {MSG_NICKSERV, m_aliased,        1, MF_ALIAS, AII_NS},
    {MSG_MEMOSERV, m_aliased,        1, MF_ALIAS, AII_MS},
    {MSG_ROOTSERV, m_aliased,        1, MF_ALIAS, AII_RS},
    {MSG_OPERSERV, m_aliased,        1, MF_ALIAS, AII_OS},
    {MSG_STATSERV, m_aliased,        1, MF_ALIAS, AII_SS},
    {MSG_HELPSERV, m_aliased,        1, MF_ALIAS, AII_HS},
    {MSG_SERVICES, m_services,       1, 0,        0},
    {MSG_IDENTIFY, m_identify,       1, 0,        0},
    {MSG_SVSNICK,  m_svsnick,  MAXPARA, 0,        0},
    {MSG_SVSKILL,  m_svskill,  MAXPARA, 0,        0},
    {MSG_SVSMODE,  m_svsmode,  MAXPARA, 0,        0},
    {MSG_SVSHOLD,  m_svshold,  MAXPARA, 0,        0},
    {MSG_AKILL,    m_akill,    MAXPARA, 0,        0},
    {MSG_RAKILL,   m_rakill,   MAXPARA, 0,        0},
    {MSG_NBANRESET,m_nbanreset,      1, 0,        0},
    {MSG_SILENCE,  m_silence,  MAXPARA, 0,        0},
    {MSG_WATCH,    m_watch,          1, 0,        0},
    {MSG_DCCALLOW, m_dccallow,       1, 0,        0},
    {MSG_SQLINE,   m_sqline,   MAXPARA, 0,        0},
    {MSG_UNSQLINE, m_unsqline, MAXPARA, 0,        0},
    {MSG_CAPAB,    m_capab,    MAXPARA, MF_UNREG, 0},
    {MSG_BURST,    m_burst,    MAXPARA, 0,        0},
    {MSG_SGLINE,   m_sgline,   MAXPARA, 0,        0},
    {MSG_UNSGLINE, m_unsgline, MAXPARA, 0,        0},
    {MSG_DKEY,     m_dkey,     MAXPARA, MF_UNREG, 0},
    {MSG_NS,       m_aliased,        1, MF_ALIAS, AII_NS},
    {MSG_CS,       m_aliased,        1, MF_ALIAS, AII_CS},
    {MSG_MS,       m_aliased,        1, MF_ALIAS, AII_MS},
    {MSG_RS,       m_aliased,        1, MF_ALIAS, AII_RS},
    {MSG_OS,       m_aliased,        1, MF_ALIAS, AII_OS},
    {MSG_SS,       m_aliased,        1, MF_ALIAS, AII_SS},
    {MSG_HS,       m_aliased,        1, MF_ALIAS, AII_HS},
    {MSG_RESYNCH,  m_resynch,  MAXPARA, 0,        0},
    {MSG_MODULE,   m_module,   MAXPARA, 0,        0},
    {MSG_RWHO,     m_rwho,     MAXPARA, 0,        0},
    {MSG_SVSCLONE, m_svsclone, MAXPARA, 0,        0},
    {MSG_SVSPANIC, m_svspanic, MAXPARA, 0,        0},
    {MSG_CHANKILL, m_chankill, MAXPARA, 0,        0},
    {MSG_SVSHOST,  m_svshost,  MAXPARA, 0,        0},
    {MSG_SVSNOOP,  m_svsnoop,  MAXPARA, 0,        0},
    {MSG_SVSTAG,   m_svstag,   MAXPARA, 0,        0},
    {MSG_SVSUHM,   m_svsuhm,   MAXPARA, 0,        0},
    {MSG_PUT,      m_put,      2,       MF_UNREG, 0},
    {MSG_POST,     m_post,     2,       MF_UNREG, 0},
    {MSG_CHECK,    m_check,    MAXPARA, 0,        0},
    {MSG_LUSERSLOCK, m_luserslock, MAXPARA, 0,       0},
    {MSG_LINKSCONTROL, m_linkscontrol, MAXPARA, 0,      0},

    {MSG_WEBIRC,   m_webirc,   MAXPARA, MF_UNREG, 0},
    { 0 }
};

MESSAGE_TREE *msg_tree_root;
#else
extern AliasInfo aliastab[];
extern struct Message msgtab[];
extern MESSAGE_TREE *msg_tree_root;
#endif
#endif /* __msg_include__  */
