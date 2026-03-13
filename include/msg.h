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

#define MAXPARA      15

/*
 * Generic sentinel handlers (defined in src/parse.c).
 * Use these in mapi_cmd_av2 tables instead of NULL or real functions
 * when a particular handler type should be handled uniformly.
 *
 *   mg_ignore   — silently drop the message (return 0).
 *   mg_unreg    — send ERR_NOTREGISTERED and return -1.
 *   mg_reg      — send ERR_ALREADYREGISTRED and return 0.
 *   mg_not_oper — send ERR_NOPRIVILEGES and return 0.
 */
extern int mg_ignore  (struct MsgBuf *, aClient *, aClient *, int, char **);
extern int mg_unreg   (struct MsgBuf *, aClient *, aClient *, int, char **);
extern int mg_reg     (struct MsgBuf *, aClient *, aClient *, int, char **);
extern int mg_not_oper(struct MsgBuf *, aClient *, aClient *, int, char **);

/*
 * current_alias_info — set by parse() immediately before dispatching an alias
 * command.  m_aliased() and m_sjr() read this to get their AliasInfo*.
 * Only valid during an alias handler call.
 */
extern AliasInfo *current_alias_info;

/* Handler function declarations (new signature: MsgBuf* first) */
extern int  m_cap  (struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_kline(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_unkline(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_akill(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_rakill(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_nbanreset(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_topic(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_join(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_part(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_mode(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_ping(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_pong(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_kick(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_nick(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_error(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_invite(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_quit(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_kill(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_motd(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_user(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_list(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_server(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_info(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_links(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_summon(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_stats(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_services(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_identify(struct MsgBuf *, aClient *, aClient *, int, char **);
/* m_aliased uses current_alias_info set by parse() */
extern int  m_aliased(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_svsnick(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_svskill(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_svsmode(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_svshold(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_version(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_help(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_squit(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_connect(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_oper(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_pass(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_trace(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_time(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_names(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_admin(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_lusers(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_umode(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_close(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_svinfo(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_sjoin(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_samode(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_sajoin(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_rehash(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_restart(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_die(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_hash(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_dns(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_set(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_sqline(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_unsqline(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_burst(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_sgline(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_unsgline(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_resynch(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_luserslock(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_linkscontrol(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_module(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_svsclone(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_svspanic(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_chankill(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_svshost(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_svsnoop(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_svstag(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_svsuhm(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_spamops(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_sf(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_aj(struct MsgBuf *, aClient *, aClient *, int, char **);
/* m_sjr uses current_alias_info set by parse() */
extern int  m_sjr(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_svsxcf(struct MsgBuf *, aClient *, aClient *, int, char **);
extern int  m_svsctrl(struct MsgBuf *, aClient *, aClient *, int, char **);

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

/*
 * msgtab[] initialiser macros.
 *
 * M_UNREG  — accessible by unregistered connections; all handler slots
 *             point to the same function.
 * M_REG    — registered-only; HANDLER_UNREG → mg_unreg, rest → fn.
 * M_ALIAS  — services alias; aliasidx set; CLIENT/OPER → m_aliased;
 *             REMOTE/SERVER → mg_ignore; UNREG → mg_unreg.
 *             parse() sets current_alias_info before dispatch.
 * M_ALIAS_FN — like M_ALIAS but with a custom handler (for m_sjr).
 */
#define M_UNREG(cmd_, fn_) \
    { (cmd_), 0, 0, 0, 0, -1, {   \
        { (fn_), 0 },              \
        { (fn_), 0 },              \
        { (fn_), 0 },              \
        { (fn_), 0 },              \
        { (fn_), 0 },              \
    }}

#define M_REG(cmd_, fn_) \
    { (cmd_), 0, 0, 0, 0, -1, {   \
        { mg_unreg, 0 },           \
        { (fn_),    0 },           \
        { (fn_),    0 },           \
        { (fn_),    0 },           \
        { (fn_),    0 },           \
    }}

#define M_ALIAS(cmd_, aii_) \
    { (cmd_), 0, 0, 0, 0, (aii_), { \
        { mg_unreg,  0 },            \
        { m_aliased, 0 },            \
        { mg_ignore, 0 },            \
        { mg_ignore, 0 },            \
        { m_aliased, 0 },            \
    }}

#define M_ALIAS_FN(cmd_, aii_, fn_) \
    { (cmd_), 0, 0, 0, 0, (aii_), { \
        { mg_unreg, 0 },             \
        { (fn_),    0 },             \
        { mg_ignore, 0 },            \
        { mg_ignore, 0 },            \
        { (fn_),    0 },             \
    }}

struct Message msgtab[] =
{
    M_UNREG(MSG_NICK,    m_nick),
    M_REG  (MSG_JOIN,    m_join),
    M_REG  (MSG_MODE,    m_mode),
    M_REG  (MSG_SAMODE,  m_samode),
    M_REG  (MSG_SAJOIN,  m_sajoin),
    M_UNREG(MSG_QUIT,    m_quit),
    M_REG  (MSG_PART,    m_part),
    M_REG  (MSG_TOPIC,   m_topic),
    M_REG  (MSG_INVITE,  m_invite),
    M_REG  (MSG_KICK,    m_kick),
    M_REG  (MSG_PONG,    m_pong),
    M_REG  (MSG_PING,    m_ping),
    M_UNREG(MSG_ERROR,   m_error),
    M_REG  (MSG_KILL,    m_kill),
    M_UNREG(MSG_USER,    m_user),
    M_UNREG(MSG_SERVER,  m_server),
    M_REG  (MSG_SQUIT,   m_squit),
    M_REG  (MSG_LIST,    m_list),
    M_REG  (MSG_NAMES,   m_names),
    M_REG  (MSG_TRACE,   m_trace),
    M_UNREG(MSG_PASS,    m_pass),
    M_REG  (MSG_LUSERS,  m_lusers),
    M_REG  (MSG_TIME,    m_time),
    M_REG  (MSG_OPER,    m_oper),
    M_REG  (MSG_CONNECT, m_connect),
    M_UNREG(MSG_VERSION, m_version),
    M_REG  (MSG_STATS,   m_stats),
    M_REG  (MSG_LINKS,   m_links),
    M_UNREG(MSG_ADMIN,   m_admin),
    M_REG  (MSG_HELP,    m_help),
    M_REG  (MSG_INFO,    m_info),
    M_REG  (MSG_MOTD,    m_motd),
    M_UNREG(MSG_SVINFO,  m_svinfo),
    M_REG  (MSG_SJOIN,   m_sjoin),
    M_REG  (MSG_CLOSE,   m_close),
    M_REG  (MSG_KLINE,   m_kline),
    M_REG  (MSG_UNKLINE, m_unkline),
    M_REG  (MSG_HASH,    m_hash),
    M_REG  (MSG_DNS,     m_dns),
    M_REG  (MSG_REHASH,  m_rehash),
    M_REG  (MSG_RESTART, m_restart),
    M_REG  (MSG_DIE,     m_die),
    M_REG  (MSG_SET,     m_set),
    M_ALIAS(MSG_CHANSERV, AII_CS),
    M_ALIAS(MSG_NICKSERV, AII_NS),
    M_ALIAS(MSG_MEMOSERV, AII_MS),
    M_ALIAS(MSG_ROOTSERV, AII_RS),
    M_ALIAS(MSG_OPERSERV, AII_OS),
    M_ALIAS(MSG_STATSERV, AII_SS),
    M_ALIAS(MSG_HELPSERV, AII_HS),
    M_REG  (MSG_SERVICES, m_services),
    M_REG  (MSG_IDENTIFY, m_identify),
    M_REG  (MSG_SVSNICK,  m_svsnick),
    M_REG  (MSG_SVSKILL,  m_svskill),
    M_REG  (MSG_SVSMODE,  m_svsmode),
    M_REG  (MSG_SVSHOLD,  m_svshold),
    M_REG  (MSG_AKILL,    m_akill),
    M_REG  (MSG_RAKILL,   m_rakill),
    M_REG  (MSG_NBANRESET, m_nbanreset),
    M_REG  (MSG_SQLINE,   m_sqline),
    M_REG  (MSG_UNSQLINE, m_unsqline),
    M_REG  (MSG_BURST,    m_burst),
    M_REG  (MSG_SGLINE,   m_sgline),
    M_REG  (MSG_UNSGLINE, m_unsgline),
    M_ALIAS(MSG_NS, AII_NS),
    M_ALIAS(MSG_CS, AII_CS),
    M_ALIAS(MSG_MS, AII_MS),
    M_ALIAS(MSG_RS, AII_RS),
    M_ALIAS(MSG_OS, AII_OS),
    M_ALIAS(MSG_SS, AII_SS),
    M_ALIAS(MSG_HS, AII_HS),
    M_REG  (MSG_RESYNCH,       m_resynch),
    M_REG  (MSG_MODULE,        m_module),
    M_REG  (MSG_SVSCLONE,      m_svsclone),
    M_REG  (MSG_SVSPANIC,      m_svspanic),
    M_REG  (MSG_CHANKILL,      m_chankill),
    M_REG  (MSG_SVSHOST,       m_svshost),
    M_REG  (MSG_SVSNOOP,       m_svsnoop),
    M_REG  (MSG_SVSTAG,        m_svstag),
    M_REG  (MSG_SVSUHM,        m_svsuhm),
    M_REG  (MSG_LUSERSLOCK,    m_luserslock),
    M_REG  (MSG_LINKSCONTROL,  m_linkscontrol),
    M_REG  ("SPAMOPS",         m_spamops),
    M_REG  ("SF",              m_sf),
    M_REG  ("SVSXCF",          m_svsxcf),
    M_REG  ("SVSCTRL",         m_svsctrl),
    M_REG  ("AJ",              m_aj),
    M_ALIAS_FN("SJR", AII_NS, m_sjr),
    /* CAP — IRCv3 capability negotiation; available pre-registration */
    { "CAP", 0, 0, 0, 0, -1, {
        { m_cap,    2 },  /* HANDLER_UNREG   */
        { m_cap,    2 },  /* HANDLER_CLIENT  */
        { mg_ignore,0 },  /* HANDLER_REMOTE  */
        { mg_ignore,0 },  /* HANDLER_SERVER  */
        { m_cap,    2 },  /* HANDLER_OPER    */
    }},
    { NULL }
};

MESSAGE_TREE *msg_tree_root;
#else
extern AliasInfo aliastab[];
extern struct Message msgtab[];
extern MESSAGE_TREE *msg_tree_root;
#endif
#endif /* __msg_include__  */
