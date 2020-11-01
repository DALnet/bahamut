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

#ifndef	__config_include__
#define	__config_include__

#include "setup.h"
#include "defs.h"


/* READ THIS FIRST BEFORE EDITING!!!
 *
 * Most people will have no real reason to edit config.h, with the
 * exception of perhaps turning off certain things such as throttling
 * or flood protection options.  Most of the stuff you will have to edit
 * can be found in the ircd.conf - see doc/reference.conf for information
 * on that.
 */

/*
 * NO_DEFAULT_INVISIBLE - clients not +i by default When defined, your
 * users will not automatically be attributed with user mode "i" (i ==
 * invisible). Invisibility means people dont showup in WHO or NAMES
 * unless they are on the same channel as you.
 */
#undef	NO_DEFAULT_INVISIBLE

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
#ifdef HAVE_SYSLOG_H
#define	USE_SYSLOG
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
#undef  SYSLOG_BLOCK_ALLOCATOR /* debug block allocator */

/*
 * LOG_FACILITY - facility to use for syslog() Define the facility you
 * want to use for syslog().  Ask your sysadmin which one you should
 * use.
 */
#define LOG_FACILITY LOG_LOCAL4
#endif /* HAVE_SYSLOG_H  */

/* Defaults for things in option block of ircd.conf */

/* WGMON notices are sent to users to warn them about the proxy scans. */
#define DEFAULT_WGMON_URL "http://kline.dal.net/proxy/"
#define DEFAULT_WGMON_HOST "some.bot.host"

/* Hostmasking address */
#define DEFAULT_STAFF_ADDRESS "staff.dalnet"

/* Sent to users in 001 and 005 numerics */
#define DEFAULT_NETWORK "DALnet"

/* used for services aliases */
#define DEFAULT_SERVICES_NAME "services.dal.net"
#define DEFAULT_STATS_NAME "stats.dal.net"

/* sent to users when they have been klined from the server */
#define DEFAULT_NKLINE_ADDY "admin@badly.configured.server"
#define DEFAULT_LKLINE_ADDY "admin@badly.configured.server"

/* Sent to users when they encounter mode +R */
#define DEFAULT_NS_REGISTER_URL "http://docs.dal.net/docs/nsemail.html"

/* SpamFilter KB/Help URL (sent to users when they're getting warned/blocked by spamfilter) */
#define DEFAULT_SPAMFILTER_URL "http://www.dal.net/kb/view.php?kb=411"

/* self explanitory */
#define DEFAULT_MAXCHANNELSPERUSER 10

/* Default difference in time sync between servers before we complain */
#define DEFAULT_TSMAXDELTA 120
#define DEFAULT_TSWARNDELTA 15

/* default clone limits */
#define DEFAULT_LOCAL_IP_CLONES    10
#define DEFAULT_LOCAL_IP24_CLONES  60
#define DEFAULT_GLOBAL_IP_CLONES   25
#define DEFAULT_GLOBAL_IP24_CLONES 150

/* 
 * HIDEULINEDSERVS 
 * Define this if you want to hide the location of U:lined servers (and 
 * then clients on them) from nonopers. With this defined, no non-oper 
 * should be able to find out which server the U:lined server is connected
 * to. If you are connected to the main DALnet network, you MUST have this
 * enabled.
 */
#define HIDEULINEDSERVS 1

#define THROTTLE_ENABLE /* enable throttling, see below */

/*
 * RWHO_PROBABILITY
 * Define this to enable probability calculation support for RWHO.
 */
#define RWHO_PROBABILITY

/* File names
 * the server will look for these files
 */
#define	MPATH	"ircd.motd"
#define	SMPATH	"ircd.smotd"
#define	LPATH	"ircd.log"
#define	PPATH	"ircd.pid"
#define HPATH	"opers.txt"


/* Services Definitions */
#define CHANSERV "ChanServ"
#define NICKSERV "NickServ"
#define MEMOSERV "MemoServ"
#define ROOTSERV "RootServ"
#define OPERSERV "OperServ"
#define STATSERV "StatServ"
#define HELPSERV "HelpServ"

/*
 * DENY_SERVICES_MSGS
 * Define this to cause PRIVMSG <service> to be rejected with numeric 487,
 * explaining that "/msg <service>" is no longer supported, and to use
 * "/msg <service>@<services_name>" or "/<service>" instead.
 */
#define DENY_SERVICES_MSGS

/*
 * PASS_SERVICES_MSGS
 * Define this to cause PRIVMSG <service> to be passed to services as-is,
 * instead of being converted to the shortform ("PRIVMSG NickServ" -> "NS").
 * Useful if services behaves differently when it gets a target of <service>
 * instead of <service>@<server>.
 */
#define PASS_SERVICES_MSGS

/*
 * SUPER_TARGETS_ONLY
 * Define this to allow the nick@server form of PRIVMSG/NOTICE to target super
 * servers only.  If not defined, the target may be on any server.
 */
#define SUPER_TARGETS_ONLY

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

/* define this if you want to support non-noquit servers.  handy for
 * services that are not noquit compliant.
 */
#undef NOQUIT

/*
 * DEFAULT_KLINE_TIME
 *
 * Define this to the default time for a kline (in minutes) for klines with
 * unspecified times.  A time of 0 will create a permanent kline.
 */
#define DEFAULT_KLINE_TIME 30

/*
 * KLINE_MIN_STORE_TIME
 *
 * The minimum duration (in minutes) a kline must be before it will be stored
 * in the on-disk journal.
 */
#define KLINE_MIN_STORE_TIME 180

/*
 * KLINE_STORE_COMPACT_THRESH
 *
 * The maximum number of entries to write to the active kline storage journal
 * before compacting it.  This threshold prevents the journal from growing
 * indefinitely while klines are added and removed on a running server.
 */
#define KLINE_STORE_COMPACT_THRESH 1000

/*
 * Pretty self explanatory: These are shown in server notices and to the 
 * recipient of a "you are banned" message.
 */
#define LOCAL_BAN_NAME "k-line"
#define NETWORK_BAN_NAME "autokill"
#define LOCAL_BANNED_NAME "k-lined"
#define NETWORK_BANNED_NAME "autokilled"

/*
 * RFC1035_ANAL Defining this causes ircd to reject hostnames with
 * non-compliant chars. undef'ing it will allow hostnames with _ or /
 * to connect
 */
#define RFC1035_ANAL

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

/*
 * CLIENT_FLOOD - client excess flood threshold this controls the
 * number of bytes the server will allow a client to send to the server
 * without processing before disconnecting the client for flooding it.
 * Values greater than 8000 make no difference to the server.
 */
#define	CLIENT_FLOOD	2560

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
 * WARN_NO_NLINE Define this if you want ops to get noticed about
 * "things" trying to connect as servers that don't have N: lines.
 * Twits with misconfigured servers can get really annoying with
 * enabled.
 */
#define WARN_NO_NLINE

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
#undef NETWORK_PARANOIA

/*
 * NO_USER_SERVERKILLS
 * Users can't set mode +k
 *
 * NO_USER_OPERKILLS
 * Users can't set mode +s
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
 * Note that NO_USER_OPERKILLS and NO_USER_SERVERKILLS must be defined for
 * this to actually provide any security.
 *
 * HIDE_SPLIT_SERVERS
 * Hide the names of servers during netsplits
 *
 * HIDE_SERVERMODE_ORIGINS
 * Hide the origins of server modes (ie, in netjoins).
 * (They will all come from me.name)
 */
#define NO_USER_SERVERKILLS
/* #undef NO_USER_OPERKILLS */
/* #undef NO_USER_STATS */
/* #undef NO_LOCAL_USER_STATS */
/* #undef NO_USER_TRACE */
/* #undef NO_USER_OPERTARGETED_COMMANDS */
/* #undef HIDE_NUMERIC_SOURCE */
/* #undef HIDE_KILL_ORIGINS */
/* #undef HIDE_SPLIT_SERVERS */
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
#undef ALLOW_HIDDEN_OPERS

/*
 * DEFAULT_MASKED_HIDDEN
 * 
 * Makes all your opers that hostmasked +I (hidden) by default
 * ALLOW_HIDDEN_OPERS must be defined with this enabled.
 */
#undef DEFAULT_MASKED_HIDDEN

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
# define NO_USER_SERVERKILLS
# define NO_USER_OPERKILLS
# define NO_USER_STATS
# define NO_USER_TRACE
# define NO_USER_OPERTARGETED_COMMANDS
# define HIDE_NUMERIC_SOURCE
# define HIDE_KILL_ORIGINS
# define HIDE_SPLIT_SERVERS
# define HIDE_SERVERMODE_ORIGINS
#endif

/* EXEMPT_LISTS and INVITE_LISTS
 * Written by Sedition, Feb.04
 */
#define EXEMPT_LISTS
#define INVITE_LISTS

/*
 * USE_SSL - Add SSL support for users
 */
#ifdef HAVE_ENCRYPTION_ON
                        #define USE_SSL
                        #define IRCDSSL_KPATH "ircd.key"
                        #define IRCDSSL_CPATH "ircd.crt"
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


/* INITIAL_SBUFS_X - how many bytes of sbufs to preallocate */
#define INITIAL_SBUFS_SMALL 2 * (1 << 20) /* 2 meg */
#define INITIAL_SBUFS_LARGE 2 * (1 << 20) /* 2 meg */
#define INITIAL_SBUFS_USERS 256           /* number of sbuf user structs to pool */

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
 * NICKNAMEHISTORYLENGTH - size of WHOWAS array this defines the length
 * of the nickname history.  each time a user changes nickname or signs
 * off, their old nickname is added to the top of the list. NOTE: this
 * is directly related to the amount of memory ircd will use whilst
 * resident and running - it hardly ever gets swapped to disk!  Memory
 * will be preallocated for the entire whowas array when ircd is
 * started.
 */
#define NICKNAMEHISTORYLENGTH 8192

/*
 * TIMESEC - Time interval to wait and if no messages have been
 * received, then check for PINGFREQUENCY and CONNECTFREQUENCY
 */
#define TIMESEC  5		/* Recommended value: 5 */

/*
 * MAXSENDQLENGTH - Max amount of internal send buffering Max amount of
 * internal send buffering when socket is stuck (bytes)
 */
#define MAXSENDQLENGTH 5050000

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

#ifdef FLUD
# define FLUD_NUM	   4	/* Number of flud messages to trip alarm */
# define FLUD_TIME	3	/* Seconds in which FLUD_NUM msgs must occur */
# define FLUD_BLOCK	15	/* Seconds to block fluds */
#endif

/*
 * If the OS has SOMAXCONN use that value, otherwise Use the value in
 * HYBRID_SOMAXCONN for the listen(); backlog try 5 or 25. 5 for AIX
 * and SUNOS, 25 should work better for other OS's
 */
#define HYBRID_SOMAXCONN 25

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
 * JOINRATE_SERVER_ONLY: Only let servers/U: lined things set +j.
 *                       KEEP THIS IF USING A NETWORK WITH PRE-1.4.36 SERVERS!
 */
/* defaults are very forgiving. */
#define DEFAULT_JOIN_NUM  8
#define DEFAULT_JOIN_TIME 6
#undef JOINRATE_SERVER_ONLY

/*
 * Don't allow local clients to set CIDR channel bans/invites/exempts
 * until all servers and services are upgraded.
 */
#undef NO_LOCAL_CIDR_CHANNELBANS

/* Debugging configs */

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

/*
 * MEMTRACE enables additional memory accounting for display in STATS Z.
 * Requires GNU C extensions for expression blocks.
 */
#undef MEMTRACE

/* DONT_CHECK_QLINE_REMOTE
 * Don't check for Q:lines on remote clients.  We can't do anything
 * if a remote client is using a nick q:lined locally, so
 * why check?  If you don't care about the wasted CPU, and you're
 * curious, feel free to #define this.  I recommend you don't
 * on a client server unless it's got a lot of power.
 * -wd */
#define DONT_CHECK_QLINE_REMOTE

/* USER_HOSTMASKING is used to enable host-masking for users.
 * If you are connected to the main DALnet network, you should not
 * have this enabled yet.
 */
#define USER_HOSTMASKING

/* USER_HOSTMASKING_FALLBACK_TO_IP is used to hostmask using the user's IP
 * address if we are unable to hostmask using their hostname. This usually
 * happens if they're using a domain name without a lot of labels:
 * somehost.com or company.co.uk or similar.
 */
#ifdef USER_HOSTMASKING
#define USER_HOSTMASKING_FALLBACK_TO_IP
#endif

/* SPAMFILTER is used to enable spam filtering on the network.
 * If you are connected to the main DALnet network, you should
 * have this enabled.
 */
#define SPAMFILTER

/*
 * DEFAULT_OPER_SPAMFILTER_DISABLED - default your opers to +P, which disables spamfilter checking.  This
 * is strongly recommended so that users can report potential spam.
 */
#ifdef SPAMFILTER
#define DEFAULT_OPER_SPAMFILTER_DISABLED
#endif

/*
 * USE_HALFOPS is used to enable half-ops support
 * If you are connected to the main DALnet network, you should
 * have this enabled.
 */
#define USE_HALFOPS

/*
 * Don't allow local clients to use +h/-h until all servers and services are upgraded.
 */
#define NO_LOCAL_CMODE_h

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
#define IRCD_PIDFILE PPATH

/* token bucket size for join rate stuffs */
#define DEFAULT_JOIN_SIZE (DEFAULT_JOIN_NUM * DEFAULT_JOIN_TIME)

/* enforce a minimum, even though it'll probably break at runtime */
#if (MAXCONNECTIONS < 20)
# undef MAXCONNECTIONS
# define MAXCONNECTIONS 20
#endif

#if (MAXCONNECTIONS > 1000)
# define MAX_BUFFER (MAXCONNECTIONS / 100)
#else
# define MAX_BUFFER 10
#endif

#define MAX_ACTIVECONN (MAXCONNECTIONS - MAX_BUFFER)

#if defined(CLIENT_FLOOD) && ((CLIENT_FLOOD > 8000) || (CLIENT_FLOOD < 512))
#error CLIENT_FLOOD needs redefining.
#endif

#if !defined(CLIENT_FLOOD)
#error CLIENT_FLOOD undefined.
#endif

#if defined(DEBUGMODE) || defined(DNS_DEBUG)
extern void debug(int level, char *pattern, ...);
#define Debug(x) do { debug x } while (0);
#define LOGFILE LPATH
#else
#define Debug(x) do {} while (0);
#define LOGFILE "/dev/null"
#endif

#define CONFIG_H_LEVEL_184
#endif				/* __config_include__ */
