/************************************************************************
 *   IRC - Internet Relay Chat, include/config.h
 *   Copyright (C) 1990 Jarkko Oikarinen
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

/* $Id$ */

#ifndef	__config_include__
#define	__config_include__

#include "setup.h"

/*******************************************************************
 * Ok boys and girls, you can edit this file by hand, its totally 
 * up to you.  IF you want to do that, then undefine the next line. 
 * -Epi
 *******************************************************************/

#define OPTIONS_H

/* 
 * If you are using OPTIONS_H, you can ignore everything from here
 * until i tell you otherwise.  If not, go nuts. 
 */

#ifdef OPTIONS_H
#include "options.h"
#endif

#ifndef OPTIONS_H

/**** MAKE SURE THIS IS CORRECT ****/
/* ONLY EDIT "HARD_FDLIMIT_" and "INIT_MAXCLIENTS" */
#define HARD_FDLIMIT_   2048
#define INIT_MAXCLIENTS 2000

/*
 * This is how many 'buffer connections' we allow... Remember,
 * MAX_BUFFER + MAX_CLIENTS can't exceed HARD_FDLIMIT :)
 */
#define MAX_BUFFER	48


/* Also define this for SunOS 4.1.4_DBE */
#undef SUNDBE
#ifdef SUNDBE
#define FD_SETSIZE HARD_FDLIMIT_
#define NOFILE HARD_FDLIMIT_
#endif /* SUNDBE */

/*
 * DPATH SPATH CPATH MPATH KPATH - directoy and files locations Full
 * pathnames and defaults of irc system's support files. Please note
 * that these are only the recommended names and paths. Change as
 * needed. You must define these to something, even if you don't really
 * want them.
 * 
 * DPATH = directory, SPATH = server executable, CPATH = conf file, MPATH
 * = MOTD KPATH = kline conf file
 * 
 * For /restart to work, SPATH needs to be a full pathname (unless "." is
 * in your exec path). -Rodder Leave KPATH undefined if you want klines
 * in main conf file. HPATH is the opers help file, seen by opers on
 * /quote help.
 * 
 * -Dianora
 */
#define DPATH   "/usr/home/ircd/ircd/"
#define SPATH   "/usr/home/ircd/ircd/ircd"

/* STATS_NOTICE - See a notice when a user does a /stats */
#define STATS_NOTICE

/*
 * SHORT_MOTD There are client ignoring the FORCE_MOTD MOTD numeric,
 * there is no point forcing MOTD on connecting clients IMO. Give them
 * a short NOTICE telling them they should read the motd, and leave it
 * at that.
 */
#undef SHORT_MOTD

/*
 * NO_DEFAULT_INVISIBLE - clients not +i by default When defined, your
 * users will not automatically be attributed with user mode "i" (i ==
 * invisible). Invisibility means people dont showup in WHO or NAMES
 * unless they are on the same channel as you.
 */
#undef	NO_DEFAULT_INVISIBLE

/*
 * HUB - enable server-server routing If your server is running as a a
 * HUB Server then define this. A HUB Server has many servers connect
 * to it at the same as opposed to a leaf which just has 1 server
 * (typically the uplink). Define this correctly for performance
 * reasons.
 */
#undef HUB

/*
 * SERVICESHUB - Provides some filtering of data not needed by services
 */
#undef SERVICESHUB

/* The following two are defaults only and may be overridden
 * with T: lines in the configuration file
 */

/* Define this if you want a notice sent to connecting users
 * about wingate scanning bots.  A URL is included in the 
 * notice
 */
#define WINGATE_NOTICE
/* For this to compile, you must define the hostname of your 
 * wingate bot - which is included in the notice.
 */
#ifdef WINGATE_NOTICE
#define MONITOR_HOST "bots.someisp.com"
#endif

/*
 * USE_SYSLOG - log errors and such to syslog() If you wish to have the
 * server send 'vital' messages about server through syslog, define
 * USE_SYSLOG. Only system errors and events critical to the server are
 * logged although if this is defined with FNAME_USERLOG, syslog() is
 * used instead of the above file. It is not recommended that this
 * option is used unless you tell the system administrator beforehand
 * and obtain their permission to send messages to the system log
 * files.
 * 
 * IT IS STRONGLY RECOMMENDED THAT YOU *DO* USE SYSLOG.  Many fatal ircd
 * errors are only logged to syslog.
 */
#define	USE_SYSLOG
#ifdef	USE_SYSLOG
/*
 * SYSLOG_KILL SYSLOG_SQUIT SYSLOG_CONNECT SYSLOG_USERS SYSLOG_OPER If
 * you use syslog above, you may want to turn some (none) of the
 * spurious log messages for KILL,SQUIT,etc off.
 */
#undef	SYSLOG_KILL		/* log all operator kills */
#undef	SYSLOG_SQUIT	        /* log all remote squits */
#undef	SYSLOG_CONNECT	        /* log remote connect messages */
#undef	SYSLOG_USERS		/* send userlog stuff to syslog */
#undef	SYSLOG_OPER		/* log all users who successfully oper */
#undef   SYSLOG_BLOCK_ALLOCATOR /* debug block allocator */

/*
 * LOG_FACILITY - facility to use for syslog() Define the facility you
 * want to use for syslog().  Ask your sysadmin which one you should
 * use.
 */
#define LOG_FACILITY LOG_LOCAL4
#endif /* USE_SYSLOG */


/*
 * MAXSENDQLENGTH - Max amount of internal send buffering Max amount of
 * internal send buffering when socket is stuck (bytes)
 */
#define MAXSENDQLENGTH 5050000	/* Recommended value: 5050000 for efnet */

/*
 * BUFFERPOOL - the maximum size of the total of all sendq's.
 * Recommended value is four times MAXSENDQLENGTH.
 */
#define	BUFFERPOOL     (4 * MAXSENDQLENGTH)

/* 
 * HIDEULINEDSERVS 
 * Define this if you want to hide the location of U:lined servers (and 
 * then clients on them) from nonopers. With this defined, no non-oper 
 * should be able to find out which server the U:lined server is connected
 * to. If you are connected to the main DALnet network, you MUST have this
 * enabled.
 */
#define HIDEULINEDSERVS 1

/*
 * comstud and I have both noted that solaris 2.5 at least, takes a
 * hissy fit if you don't read a fd that becomes ready right away.
 * Unfortunately the dog3 priority code relies upon not having to read
 * a ready fd right away. If you have HTM mode set low as it is
 * normally, the server will eventually grind to a halt. Personally, I
 * think the server is faster without some of the CPU expensive
 * manipulation some of the priority code does. Your choice. but it has
 * to be defined for SOLARIS Try it and see. compare. Don't complain if
 * Solaris lags if you don't define this. I warned you.
 * 
 * -Dianora
 */
#ifdef OS_SOLARIS
#define NO_PRIORITY
#else
#undef NO_PRIORITY
#endif

/* Services Name */
#define SERVICES_NAME "services.dal.net"	/* DALnet services */

/*
 * CRYPT_OPER_PASSWORD - use crypted oper passwords in the ircd.conf
 * define this if you want to use crypted passwords for operators in
 * your ircd.conf file.
 */
#undef	CRYPT_OPER_PASSWORD

/*
 * MAXCHANNELSPERUSER - Max number of channels a user is allowed to
 * join.
 */
#define MAXCHANNELSPERUSER  10	/* Recommended value: 10 */

#define THROTTLE_ENABLE /* enable throttling, see below */

/*******************************************************/

#endif /** OPTIONS_H **/


/******  END OF AUTOMATIC CONFIG SCRIPT COVERAGE  ******/

/* these should be set to your local and global kline addresses */

#ifndef SERVER_KLINE_ADDRESS
#define SERVER_KLINE_ADDRESS "bad_admin@poorly.configured.server.com"
#endif

#ifndef NETWORK_KLINE_ADDRESS
#define NETWORK_KLINE_ADDRESS "bad_admin@poorly.configured.network.com"
#endif

/* OS Depentant ifdefs */

#ifdef SUNDBE
#define FD_SETSIZE HARD_FDLIMIT_
#define NOFILE HARD_FDLIMIT_
#endif /* SUNDBE */

#ifdef OS_SOLARIS
#define NO_PRIORITY
#else
#undef NO_PRIORITY
#endif

/* File names */
#define	CPATH	"ircd.conf"
#define KPATH   "kline.conf"
#define	MPATH	"ircd.motd"
#define	SMPATH	"ircd.smotd"
#define	LPATH	"ircd.log"
#define	PPATH	"ircd.pid"
#define HPATH	"opers.txt"


/* Services Definitions */
#define STATS_NAME "stats.dal.net"
#define CHANSERV "ChanServ"
#define NICKSERV "NickServ"
#define MEMOSERV "MemoServ"
#define ROOTSERV "RootServ"
#define OPERSERV "OperServ"
#define STATSERV "StatServ"
#define HELPSERV "HelpServ"
#define NICKSERVATSERVICES NICKSERV "@" SERVICES_NAME
#define CHANSERVATSERVICES CHANSERV "@" SERVICES_NAME
#define MEMOSERVATSERVICES MEMOSERV "@" SERVICES_NAME
#define ROOTSERVATSERVICES ROOTSERV "@" SERVICES_NAME
#define OPERSERVATSTATS    OPERSERV "@" STATS_NAME
#define STATSERVATSTATS    STATSERV "@" STATS_NAME
#define HELPSERVATSTATS    HELPSERV "@" STATS_NAME

/*
 * FNAME_USERLOG and FNAME_OPERLOG - logs of local USERS and OPERS
 * Define this filename to maintain a list of persons who log into this
 * server. Logging will stop when the file does not exist. Logging will
 * be disable also if you do not define this. FNAME_USERLOG just logs
 * user connections, FNAME_OPERLOG logs every successful use of /oper.
 * These are either full paths or files within DPATH.
 * 
 */

#undef FNAME_USERLOG
#undef FNAME_OPERLOG

/*
#define FNAME_USERLOG "/usr/local/ircd/users"	
#define FNAME_OPERLOG "/usr/local/ircd/opers"
*/

/* Don't change this... */
#define HARD_FDLIMIT	(HARD_FDLIMIT_ - 10)
#define MASTER_MAX	(HARD_FDLIMIT - MAX_BUFFER)

#include "defs.h"

/*
 * TS_MAX_DELTA and TS_WARN_DELTA -  allowed delta for TS when another
 * server connects.
 * 
 * If the difference between my clock and the other server's clock is
 * greater than TS_MAX_DELTA, I send out a warning and drop the links.
 * 
 * If the difference is less than TS_MAX_DELTA, I just sends out a warning
 * but don't drop the link.
 * 
 * TS_MAX_DELTA currently set to 30 minutes to deal with older timedelta
 * implementation.  Once pre-hybrid5.2 servers are eradicated, we can
 * drop this down to 90 seconds or so. --Rodder
 */
#define TS_MAX_DELTA 120	/* seconds */
#define TS_WARN_DELTA 15	/* seconds */

/*
 * DEFAULT_KLINE_TIME
 *
 * Define this to the default time for a kline (in minutes) for klines with
 * unspecified times. undefine this for all klines with unspecified times
 * to be perm. (if defined, a kline with zero time will be perm). -- lucas
 */
#define DEFAULT_KLINE_TIME 30

/*
 * Pretty self explanatory: These are shown in server notices and to the 
 * recipient of a "you are banned" message.
 */
#define LOCAL_BAN_NAME "k-line"
#define NETWORK_BAN_NAME "autokill"
#define LOCAL_BANNED_NAME "k-lined"
#define NETWORK_BANNED_NAME "autokilled"

/*
 * LOCKFILE - Exclusive use of ircd.conf and kline.conf during writes
 * 
 * This creates a lockfile prior to writes to ircd.conf or kline.conf, and
 * can be used in conjunction with viconf (included in the tools
 * directory). This prevents loss of data when klines are added while
 * someone is manually editting the file.  File writes will be retried
 * at the next KLINE, ZLINE, REHASH, or after CHECK_PENDING_KLINES
 * minutes have elapsed.
 * 
 * If you do not wish to use this feature, leave LOCKFILE #undef
 */
#define LOCKFILE "/tmp/ircd.conf.lock"
#define	CHECK_PENDING_KLINES	10	/* in minutes */

/*
 * FOLLOW_IDENT_RFC
 * 
 * From RFC 1413, "The Identification Protocol is not intended as an
 * authorization or access control protocol ... The use of the
 * information returned by this protocol for other than auditing is
 * strongly discouraged."
 * 
 * Defining this allows all users to set whatever username they wish,
 * despite what may be discovered by ident.  While we may get a valid
 * ident response with a different username than submitted by the
 * client, this option will cause the ident response to be discarded.
 */
#undef FOLLOW_IDENT_RFC

/*
 * NO_IDENT_SYSTYPE_OTHER
 *
 * From RFC1413:
 *
 * "OTHER" indicates the identifier is an unformatted
 * character string consisting of printable characters in
 * the specified character set.  "OTHER" should be
 * specified if the user identifier does not meet the
 * constraints of the previous paragraph.  Sending an
 * encrypted audit token, or returning other non-userid
 * information about a user (such as the real name and
 * phone number of a user from a UNIX passwd file) are
 * both examples of when "OTHER" should be used.
 *
 * However, it seems lots of programs actually default to
 * returning other as a system type. (stock identd with
 * redhat, for example)
 */
#undef NO_IDENT_SYSTYPE_OTHER

/*
 * RFC1035_ANAL Defining this causes ircd to reject hostnames with
 * non-compliant chars. undef'ing it will allow hostnames with _ or /
 * to connect
 */
#define RFC1035_ANAL

/*
 * NO_MIXED_CASE - reject mixed case usernames define this if you wish
 * to reject usernames like: FuckYou which don't have all one case
 */
#undef NO_MIXED_CASE

/*
 * IGNORE_FIRST_CHAR - define this for NO_MIXED_CASE if you wish to
 * ignore the first character
 */
#define IGNORE_FIRST_CHAR

/*
 * USERNAMES_IN_TRACE - show usernames in trace Define this if you want
 * to see usernames in /trace.
 */
#define USERNAMES_IN_TRACE

/*
 * DO_IDENTD - check identd if you undefine this, ircd will never check
 * identd regardless of @'s in I:lines.  You must still use @'s in your
 * I: lines to get ircd to do ident lookup even if you define this.
 */
#define DO_IDENTD

/* IDENTD_COMPLAIN - yell at users that don't have identd installed */
#undef IDENTD_COMPLAIN

/*
 * CLIENT_COUNT - keep a running count of Local & Global users also
 * redefine the /USERS command
 */
#define CLIENT_COUNT

/*
 * MOTD_WAIT - minimum seconds between use of MOTD, INFO, HELP, LINKS * 
 * before max use count is reset * -Dianora 
 */
#define MOTD_WAIT 10

/* MOTD_MAX * max use count before delay above comes into effect */
#define MOTD_MAX 3

/* SHOW_HEADERS - Shows messages like "looking up hostname" */
#define SHOW_HEADERS

/*
 * NO_OPER_FLOOD - disable flood control for opers define this to
 * remove flood control for opers
 */
#define NO_OPER_FLOOD

/* SHOW_UH - show the user@host everywhere */
#define SHOW_UH
#ifdef SHOW_UH
#define USERNAMES_IN_TRACE
#endif

/*
 * SHOW_INVISIBLE_LUSERS - show invisible clients in LUSERS As defined
 * this will show the correct invisible count for anyone who does
 * LUSERS on your server. On a large net this doesnt mean much, but on
 * a small net it might be an advantage to undefine it.
 */
#define	SHOW_INVISIBLE_LUSERS

/*
 * DEFAULT_HELP_MODE - default your opers to +h helper mode.  This
 * is strongly recommended
 */
#define DEFAULT_HELP_MODE

/*
 * NICER_UMODENOTICE_SEPARATION
 * By default, all usermode notices (+d, for instance) come as
 * :servername NOTICE nick :*** Notice -- blah blah
 * This makes them come as *** Debug, or *** Spy, etc.
 */
#define NICER_UMODENOTICE_SEPARATION

/*
 * MAXIMUM LINKS - max links for class 0 if no Y: line configured
 * 
 * This define is useful for leaf nodes and gateways. It keeps you from
 * connecting to too many places. It works by keeping you from
 * connecting to more than "n" nodes which you have C:blah::blah:6667
 * lines for.
 * 
 * Note that any number of nodes can still connect to you. This only
 * limits the number that you actively reach out to connect to.
 * 
 * Leaf nodes are nodes which are on the edge of the tree. If you want to
 * have a backup link, then sometimes you end up connected to both your
 * primary and backup, routing traffic between them. To prevent this,
 * #define MAXIMUM_LINKS 1 and set up both primary and secondary with
 * C:blah::blah:6667 lines. THEY SHOULD NOT TRY TO CONNECT TO YOU, YOU
 * SHOULD CONNECT TO THEM.
 * 
 * Gateways such as the server which connects Australia to the US can do a
 * similar thing. Put the American nodes you want to connect to in with
 * C:blah::blah:6667 lines, and the Australian nodes with C:blah::blah
 * lines. Have the Americans put you in with C:blah::blah lines. Then
 * you will only connect to one of the Americans.
 * 
 * This value is only used if you don't have server classes defined, and a
 * server is in class 0 (the default class if none is set).
 * 
 */
#define MAXIMUM_LINKS 1

/*
 * IRCII_KLUDGE - leave it defined Define this if you want the server
 * to accomplish ircII standard Sends an extra NOTICE in the beginning
 * of client connection
 */
#undef IRCII_KLUDGE

/* NOISY_HTM - should HTM be noisy by default should be YES or NO */
#define NOISY_HTM YES

/*
 * CLIENT_FLOOD - client excess flood threshold this controls the
 * number of bytes the server will allow a client to send to the server
 * without processing before disconnecting the client for flooding it.
 * Values greater than 8000 make no difference to the server.
 */
#define	CLIENT_FLOOD	2560

/*
 * NO_CHANOP_WHEN_SPLIT * When this is defined, users will not be
 * chanopped on empty channels * if there are no servers presently
 * connected to this server * opers are not affected. 
 */
#define NO_CHANOPS_WHEN_SPLIT

/*
 * CMDLINE_CONFIG - allow conf-file to be specified on command line
 * NOTE: defining CMDLINE_CONFIG and installing ircd SUID or SGID is a
 * MAJOR security problem - they can use the "-f" option to read any
 * files that the 'new' access lets them.
 */
#define	CMDLINE_CONFIG

/*
 * FAILED_OPER_NOTICE - send a notice to all opers when someone tries
 * to /oper and uses an incorrect password.
 */
#define FAILED_OPER_NOTICE

/*
 * ANTI_NICK_FLOOD - prevents nick flooding define if you want to block
 * local clients from nickflooding
 */
#define ANTI_NICK_FLOOD

/*
 * defaults allow 4 nick changes in 20 seconds 
 */
#define MAX_NICK_TIME 20
#define MAX_NICK_CHANGES 4

/* NO_AWAY_FLUD
 * reallow propregation of AWAY messages, but do not allow AWAY flooding
 * I reccomend a max of 5 AWAY's in 3 Minutes
 */
#define NO_AWAY_FLUD

#ifdef NO_AWAY_FLUD
# define MAX_AWAY_TIME 180  /* time in seconds */
# define MAX_AWAY_COUNT 5
#endif

/*
 * X_LINES_OPER_ONLY - Allow only local opers to see these stats
 * 
 * E_LINES - ComStud's E-lines (exception lines) 
 * F_LINES - Taner's F-lines (super-exception  lines) Any one with an F
 * line can almost always get on the server, as some file descriptors are
 * reserved for people with this F line especially useful for your opers
 */
#define E_LINES_OPER_ONLY
#define F_LINES_OPER_ONLY

/* If you want your server to save and restore the local/max client count,
 * define this here.  It's neat, non-load-producing, and makes you
 * appear more attractive to the opposite sex. --wd */
#define SAVE_MAXCLIENT_STATS

/* Define the time (in seconds) that you want to save the statistics after. 
 * Don't undef this unless you have undeffed SAVE_MAXCLIENT_STATS --sed */
#define SAVE_MAXCLIENT_STATS_TIME	3600

/*
 * UNKLINE - /quote unkline - remove klines on the fly if you choose to
 * support this, an oper can do a /quote UNKLINE of an exact matching
 * KLINE to remove the kline
 */
#define UNKLINE

/*
 * WARN_NO_NLINE Define this if you want ops to get noticed about
 * "things" trying to connect as servers that don't have N: lines.
 * Twits with misconfigured servers can get really annoying with
 * enabled.
 */
#define WARN_NO_NLINE

/*
 * USE_HTM
 * Define this if you want to use HTM (high traffic mode)
 * to limit expensive commands when outgoing traffic is very high.
 * This option has no effect on a hub.
 */
#undef USE_HTM

/* 
 * HTM_LOCK_ON_NETBURST Define this if you want your server to
 * stay in HTM while the server is synching to the network 
 * after a connect
 */
#undef HTM_LOCK_ON_NETBURST

/* DEFAULT_PROXY_INFO_URL
 * Rather self explanitory. If not specified in T: line,
 * we tell clients to go to "http://<this>"
 */
#define DEFAULT_PROXY_INFO_URL "kline.dal.net/proxy"

/*
 * STAFF_ADDRESS
 *
 * Hostmask for staff when oper hostmasking is used.
 * If you are actually a dalnet server, you should not change this.
 * The idea is to make it universal for the entire network.
 */
#define STAFF_ADDRESS "staff.dalnet"

/*
 * RIDICULOUS_PARANOIA_LEVEL
 *
 * This indicates the level of ridiculous paranoia the admin has.
 * The settings are as follows:
 *
 * 0 - No hostmasking is available.
 * 1 - All +A users can see the real IP.
 * 2 - Local +A can see the real IP.
 * 3 - Noone can see the real IP.  It is still logged.
 *
 * WARNING:
 * Running levels above 1 on DALnet will result in your server being juped
 * from the network if a security breech is suspected.
 *
 * If level 3 is selected, USE_SYSLOG must be defined.
 */
#define RIDICULOUS_PARANOIA_LEVEL 1
#if (RIDICULOUS_PARANOIA_LEVEL==3)
#ifndef USE_SYSLOG
#error "USE_SYSLOG MUST BE DEFINED FOR LEVEL 3"
#endif
#endif

/*
 * Forward /quote help to HelpServ
 *
 * If defined, any /quote help requests from users sent to the ircd
 * will forward the help message over to HelpServ if defined, as
 * well as the default HelpServ topic request command. -srd
 */
#define HELP_FORWARD_HS
#ifdef HELP_FORWARD_HS
# define DEF_HELP_CMD "?"
#endif

/*
 * For all of these options below, #define NETWORK_PARANOIA
 * and leave the individual ones alone.
 */
#define NETWORK_PARANOIA

/*
 * NO_USER_SERVERNOTICES
 * Remove +s and +k from modes that users can set
 *
 * NO_USER_STATS
 * Users can't get /stats from anything
 *
 * NO_LOCAL_USER_STATS
 * Local users can't get /stats from anything, each server does its own 
 * checking (not recommended)
 * No effect if NO_USER_STATS is defined 
 *
 * NO_USER_TRACE
 * Users can't use TRACE
 *
 * NO_USER_OPERTARGETED_COMMANDS
 * Users can't do /motd oper, /admin oper, /whois oper oper, 
 * /whois server.* oper on any oper that is set +I 
 * (see oper hiding section)
 *
 * HIDE_NUMERIC_SOURCE
 * All numerics going out to local clients come from the local server
 * Necessary for numerics from remote servers not giving information away
 * 
 * HIDE_KILL_ORIGINS
 * All /kills appear, from a user standpoint, to come from HIDDEN_SERVER_NAME
 * Note that NO_USER_SERVERNOTICES must be defined for this to actually 
 * provide any security.
 *
 * HIDE_SPLIT_SERVERS
 * Hide the names of servers during netsplits
 *
 * HIDE_LINKS
 * LINKS is a static list of servers, provided by services
 * (controlled with server<>server LINKS CONTROL cmd)
 *
 * HIDE_SERVERMODE_ORIGINS
 * Hide the origins of server modes (ie, in netjoins).
 * (They will all come from me.name)
 */
/* #undef NO_USER_SERVERNOTICES */
/* #undef NO_USER_STATS */
/* #undef NO_LOCAL_USER_STATS */
/* #undef NO_USER_TRACE */
/* #undef NO_USER_OPERTARGETED_COMMANDS */
/* #undef HIDE_NUMERIC_SOURCE */
/* #undef HIDE_KILL_ORIGINS */
/* #undef HIDE_SPLIT_SERVERS */
/* #undef HIDE_LINKS */
/* #undef HIDE_SERVERMODE_ORIGINS */

/***********************/
/* OPER HIDING SECTION */
/***********************/

/* 
 * ALLOW_HIDDEN_OPERS
 * 
 * Allow your opers to be set +I (hidden) -- required for the commands below
 * If not defined, everything below in the oper hiding section must be 
 * undefined.
 */
#define ALLOW_HIDDEN_OPERS

/*
 * DEFAULT_MASKED_HIDDEN
 * 
 * Makes all your opers that hostmasked +I (hidden) by default
 * ALLOW_HIDDEN_OPERS must be defined with this enabled.
 */
#define DEFAULT_MASKED_HIDDEN

/*
 * ALL_OPERS_HIDDEN
 * 
 * Makes all your opers on a 'hidden' server by default (sets +I at /oper)
 * ALLOW_HIDDEN_OPERS must be defined with this enabled.
 * DEFAULT_MASKED_HIDDEN is reccommended with this enabled.
 */
#undef ALL_OPERS_HIDDEN

/*
 * FORCE_OPERS_HIDDEN
 *
 * Makes it so that all opers can't set -I (not hidden)
 *
 * Define ALL_OPERS_HIDDEN, DEFAULT_MASKED_HIDDEN, ALLOW_HIDDEN_OPERS
 * with this as well, or things will not work properly
 */
#undef FORCE_OPERS_HIDDEN

/*
 * FORCE_EVERYONE_HIDDEN
 *
 * Makes it so that everyone on your server is set +I and can't set -I
 * 
 * Every other hidden option in the oper hiding section must be 
 * defined as well.
 */
#undef FORCE_EVERYONE_HIDDEN

/* 
 * Show these for hidden opers, self explanatory
 * DO NOT CHANGE ON A SERVER TO SERVER BASIS
 * THESE ARE NETWORK-WIDE!
 */
#define HIDDEN_SERVER_NAME "*.dal.net"
#define HIDDEN_SERVER_DESC "DALnet IRC Network"

/***************************/
/* END OPER HIDING SECTION */
/***************************/

#ifdef NETWORK_PARANOIA
# define NO_USER_SERVERNOTICES
# define NO_USER_STATS
# define NO_USER_TRACE
# define NO_USER_OPERTARGETED_COMMANDS
# define HIDE_NUMERIC_SOURCE
# define HIDE_KILL_ORIGINS
# define HIDE_SPLIT_SERVERS
# define HIDE_LINKS
# define HIDE_SERVERMODE_ORIGINS
#endif

/******************************************************************
 * STOP STOP STOP STOP STOP STOP STOP STOP STOP STOP STOP STOP STOP
 *
 * You shouldn't change anything below this line, unless absolutely
 * needed.
 */

/*
 * PING_NAZI
 *
 * be nazi-ish about pings (re-check every client connect, 
 * user registration, etc)
 */
#undef PING_NAZI

/*
 * ALWAYS_SEND_DURING_SPLIT
 * on a large network, if your server is carrying large amounts of clients,
 * and your server splits from the main network, the amount of allocated
 * dbufs will skyrocket as buffers fill up with QUIT messages. This code
 * attempts to combat this by sending out data whenever possible during a
 * split. - lucas
 */
#define ALWAYS_SEND_DURING_SPLIT

/* INITIAL_DBUFS - how many dbufs to preallocate */
#define INITIAL_DBUFS 1024	/* preallocate 2 megs of dbufs */

/*
 * MAXBUFFERS - increase socket buffers
 * 
 * Increase send & receive socket buffer up to 64k, keeps clients at 8K
 * and only raises servers to 64K
 */
#define MAXBUFFERS

/*
 * PORTNUM - default port where ircd resides Port where ircd resides.
 * NOTE: This *MUST* be greater than 1024 if you plan to run ircd under
 * any other uid than root.
 */
#define PORTNUM 7000 /* 7000 for DALnet */

/*
 * MAXCONNECTIONS - don't touch - change the HARD_FDLIMIT_ instead
 * Maximum number of network connections your server will allow.  This
 * should never exceed max. number of open file descrpitors and wont
 * increase this. Should remain LOW as possible. Most sites will
 * usually have under 30 or so connections. A busy hub or server may
 * need this to be as high as 50 or 60. Making it over 100 decreases
 * any performance boost gained from it being low. if you have a lot of
 * server connections, it may be worth splitting the load over 2 or
 * more servers. 1 server = 1 connection, 1 user = 1 connection. This
 * should be at *least* 3: 1 listen port, 1 dns port + 1 client
 *
 * Change the HARD_FDLIMIT_ instead 
 */
#define MAXCONNECTIONS	HARD_FDLIMIT

/*
 * NICKNAMEHISTORYLENGTH - size of WHOWAS array this defines the length
 * of the nickname history.  each time a user changes nickname or signs
 * off, their old nickname is added to the top of the list. NOTE: this
 * is directly related to the amount of memory ircd will use whilst
 * resident and running - it hardly ever gets swapped to disk!  Memory
 * will be preallocated for the entire whowas array when ircd is
 * started.
 */
#define NICKNAMEHISTORYLENGTH 2048

/*
 * TIMESEC - Time interval to wait and if no messages have been
 * received, then check for PINGFREQUENCY and CONNECTFREQUENCY
 */
#define TIMESEC  5		/* Recommended value: 5 */

/*
 * PINGFREQUENCY - ping frequency for idle connections If daemon
 * doesn't receive anything from any of its links within PINGFREQUENCY
 * seconds, then the server will attempt to check for an active link
 * with a PING message. If no reply is received within (PINGFREQUENCY *
 * 2) seconds, then the connection will be closed.
 */
#define PINGFREQUENCY    120	/* Recommended value: 120 */

/*
 * CONNECTFREQUENCY - time to wait before auto-reconencting If the
 * connection to to uphost is down, then attempt to reconnect every
 * CONNECTFREQUENCY  seconds.
 */
#define CONNECTFREQUENCY 600	/* Recommended value: 600 */

/*
 * HANGONGOODLINK and HANGONGOODLINK Often net breaks for a short time
 * and it's useful to try to establishing the same connection again
 * faster than CONNECTFREQUENCY would allow. But, to keep trying on bad
 * connection, we require that connection has been open for certain
 * minimum time (HANGONGOODLINK) and we give the net few seconds to
 * steady (HANGONRETRYDELAY). This latter has to be long enough that
 * the other end of the connection has time to notice it broke too.
 * 1997/09/18 recommended values by ThemBones for modern Efnet
 */

#define HANGONRETRYDELAY 60	/* Recommended value: 30-60 seconds */
#define HANGONGOODLINK 3600	/* Recommended value: 30-60 minutes */

/*
 * WRITEWAITDELAY - Number of seconds to wait for write to complete if
 * stuck.
 */
#define WRITEWAITDELAY     10	/* Recommended value: 15 */

/*
 * CONNECTTIMEOUT - Number of seconds to wait for a connect(2) call to
 * complete. NOTE: this must be at *LEAST* 10.  When a client connects,
 * it has CONNECTTIMEOUT - 10 seconds for its host to respond to an
 * ident lookup query and for a DNS answer to be retrieved.
 */
#define	CONNECTTIMEOUT	30	/* Recommended value: 30 */

/*
 * KILLCHASETIMELIMIT - Max time from the nickname change that still
 * causes KILL automaticly to switch for the current nick of that user.
 * (seconds)
 */
#define KILLCHASETIMELIMIT 90	/* Recommended value: 90 */

/*
 * FLUD - CTCP Flood Detection and Protection
 * 
 * This enables server CTCP flood detection and protection for local
 * clients. It works well against fludnets and flood clones.  The
 * effect of this code on server CPU and memory usage is minimal,
 * however you may not wish to take the risk, or be fundamentally
 * opposed to checking the contents of PRIVMSG's (though no privacy is
 * breached).  This code is not useful for routing only servers (ie,
 * HUB's with little or no local client base), and the hybrid team
 * strongly recommends that you do not use FLUD with HUB. The following
 * default thresholds may be tweaked, but these seem to work well.
 */
#define FLUD

/*
 * ANTI_SPAMBOT if ANTI_SPAMBOT is defined try to discourage spambots
 * The defaults =should= be fine for the timers/counters etc. but you
 * can play with them. -Dianora
 * 
 * Defining this also does a quick check whether the client sends us a
 * "user foo x x :foo" where x is just a single char.  More often than
 * not, it's a bot if it did. -ThemBones
 */
#define ANTI_SPAMBOT

/*
 * ANTI_SPAMBOT parameters, don't touch these if you don't understand
 * what is going on.
 * 
 * if a client joins MAX_JOIN_LEAVE_COUNT channels in a row, but spends
 * less than MIN_JOIN_LEAVE_TIME seconds on each one, flag it as a
 * possible spambot. disable JOIN for it and PRIVMSG but give no
 * indication to the client that this is happening. every time it tries
 * to JOIN OPER_SPAM_COUNTDOWN times, flag all opers on local server.
 * If a client doesn't LEAVE a channel for at least 2 minutes the
 * join/leave counter is decremented each time a LEAVE is done
 * 
 */
#define MIN_JOIN_LEAVE_TIME  60
#define MAX_JOIN_LEAVE_COUNT  25
#define OPER_SPAM_COUNTDOWN   5
#define JOIN_LEAVE_COUNT_EXPIRE_TIME 120

/*
 * If ANTI_SPAMBOT_WARN_ONLY is #define'd Warn opers about possible
 * spambots only, do not disable JOIN and PRIVMSG if possible spambot
 * is noticed Depends on your policies.
 */
#undef ANTI_SPAMBOT_WARN_ONLY

#ifdef HUB
# undef FLUD
#endif

#ifdef FLUD
# define FLUD_NUM	   4	/* Number of flud messages to trip alarm */
# define FLUD_TIME	3	/* Seconds in which FLUD_NUM msgs must occur */
# define FLUD_BLOCK	15	/* Seconds to block fluds */
#endif

/*
 * OLD_Y_LIMIT
 * 
 * #define this if you prefer the old behaviour of I lines the default
 * behaviour is to limit the total number of clients using the max
 * client limit in the corresponding Y line (class) The old behaviour
 * was to limit the client count per I line without regard to the total
 * class limit. Each have advantages and disadvantages. In an open I
 * line server, the default behaviour i.e. #undef OLD_Y_LIMIT makes
 * more sense, because you can limit the total number of clients in a
 * class. In a closed I line server The old behaviour can make more
 * sense.
 * 
 * -Dianora
 */
#undef OLD_Y_LIMIT

/*
 * If the OS has SOMAXCONN use that value, otherwise Use the value in
 * HYBRID_SOMAXCONN for the listen(); backlog try 5 or 25. 5 for AIX
 * and SUNOS, 25 should work better for other OS's
 */
#define HYBRID_SOMAXCONN 25

#define INET6  /* IPv6 support */

/*
 * Throttling support:
 * THROTTLE_ENABLE    - enable throttling code, if undefined, the functions
 *                      will be empty.  runtime settable.
 * THROTTLE_TRIGCOUNT - number of connections to triggle throttle action
 * THROTTLE_TRIGTIME  - number of seconds in which THROTTLE_TRIGCOUNT must
 *                      happen
 * THROTTLE_RECORDTIME- length to keep records for each ip (since last connect
                        from this ip)
 * THROTTLE_HASHSIZE  - size of the throttle hashtable, also tuneable
 *
 * Recommended values: 3, 15, 1800.  3+ connections in 15 or less seconds will
 * result in a connection throttle z:line.  These are also
 * z: line time grows, pseudo-exponentially 
 *  first zline : 2 minutes
 *  second zline: 5 minutes
 *  third zline : 15 minutes
 *  fourth zline: 30 minutes
 *  anything more is an hour
 * tuneable at runtime.  -wd */
/* part of options.h now #define THROTTLE_ENABLE */
#define THROTTLE_TRIGCOUNT 3
#define THROTTLE_TRIGTIME 15
#define THROTTLE_RECORDTIME 1800
#define THROTTLE_HASHSIZE 25147

/*
 * Message-throttling support.
 * MSG_TARGET_LIMIT: if defined, imposes limits on message targets
 * MSG_TARGET_MIN: initial number of message targets allowed (recommend 5 or less)
 * MSG_TARGET_MAX: maximum number of message targets stored (recommend 5 or
 *                 less)
 * MSG_TARGET_MINTOMAXTIME: number of seconds a user must be online
 *                          before given MSG_TARGET_MAX targets
 * MSG_TARGET_TIME: time before message targets expire (this is what you should
 *                  tweak)
 */

#define MSG_TARGET_LIMIT
#define MSG_TARGET_MIN  5
#define MSG_TARGET_MAX  8 /* MUST BE >= MSG_TARGET_MIN!!! */
#define MSG_TARGET_MINTOMAXTIME 300
#define MSG_TARGET_TIME 45

/*
 * Channel joining rate-throttling support
 *
 * DEFAULT_JOIN_NUM:  number of joins to allow, network-wide, in a period of
 *                    DEFAULT_JOIN_TIME seconds.
 * DEFAULT_JOIN_TIME: time to collect joins.
 * NO_DEFAULT_JOINRATE: No default, just let people use +j
 * JOINRATE_SERVER_ONLY: Only let servers/U: lined things set +j.
 *                       KEEP THIS IF USING A NETWORK WITH PRE-1.4.36 SERVERS!
 */
/* defaults are very forgiving. */
#define DEFAULT_JOIN_NUM  8
#define DEFAULT_JOIN_TIME 4
#undef NO_DEFAULT_JOINRATE
#define JOINRATE_SERVER_ONLY

/*
 * ----------------- archaic and/or broken secion -------------------- 
 */

/*
 * USE_REJECT_HOLD clients that reconnect but are k-lined will have
 * their connections "held" for REJECT_HOLD_TIME seconds, they cannot
 * PRIVMSG. The idea is to keep a reconnecting client from forcing the
 * ircd to re-scan dich_conf. There is one possible serious hitch with
 * this... If it is a mass cloner, your attacker can "REJECT_HOLD" a
 * number of local fd's on your server. Against normal bots this code
 * will be a "win", against mass cloners, it could lose.
 * 
 * this is still not working yet
 */
#undef USE_REJECT_HOLD
#define REJECT_HOLD_TIME 60

#undef DNS_DEBUG

/*
 * DEBUGMODE is used mostly for internal development, it is likely to
 * make your client server very sluggish. You usually shouldn't need
 * this. -Dianora
 *
 * Currently, DEBUGMODE is pretty much useless.
 * Don't use it. - lucas
 */
#undef  DEBUGMODE		/* define DEBUGMODE to enable */
#undef DUMP_DEBUG

/* DONT_CHECK_QLINE_REMOTE
 * Don't check for Q:lines on remote clients.  We can't do anything
 * if a remote client is using a nick q:lined locally, so
 * why check?  If you don't care about the wasted CPU, and you're
 * curious, feel free to #define this.  I recommend you don't
 * on a client server unless it's got a lot of power.
 * -wd */
#define DONT_CHECK_QLINE_REMOTE

/* ------------------------- END CONFIGURATION SECTION -------------------- */
#ifdef APOLLO
#define RESTARTING_SYSTEMCALLS
#endif /*
        * read/write are restarted after signals
        * defining this 1, gets siginterrupt call
        * compiled, which attempts to remove this
        * behaviour (apollo sr10.1/bsd4.3 needs this) 
        */

#define HELPFILE HPATH
#define MOTD MPATH
#define SHORTMOTD SMPATH
#define MYNAME SPATH
#define CONFIGFILE CPATH
#ifdef  KPATH
#define KLINEFILE  KPATH
#endif
#define IRCD_PIDFILE PPATH

#define MAX_CLIENTS INIT_MAXCLIENTS

#if defined(CLIENT_FLOOD) && ((CLIENT_FLOOD > 8000) || (CLIENT_FLOOD < 512))
#error CLIENT_FLOOD needs redefining.
#endif

#if !defined(CLIENT_FLOOD)
#error CLIENT_FLOOD undefined.
#endif

#if (defined(OPTIONS_H) && !defined(OPTIONS_H_14))
#error Using outdated include/options.h - run config
#endif

#if defined(DEBUGMODE) || defined(DNS_DEBUG)
extern void debug(int level, char *pattern, ...);
#define Debug(x) debug x
#define LOGFILE LPATH
#else
#define Debug(x) ;
#define LOGFILE "/dev/null"
#endif

#define CONFIG_H_LEVEL_12
#endif				/* __config_include__ */
