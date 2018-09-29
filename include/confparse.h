/* Bahamut IRCd - include/confparse.h
 * Copyright (c) 2004, Aaron Wiebe
 *
 * Apply the GPL here.
 */

/* our structures */

typedef struct TopConf tConf;
typedef struct SubConf sConf;
typedef struct ConfVar cVar;

/* our top level conf options */
struct TopConf
{
    char *tok;              /* our token string             */
    unsigned int   flag;    /* our token flag               */
    unsigned int   nest;    /* tokens we allow to nest here */
    sConf       *subtok;  /* sub-tokens allowed in here   */
    int         (*func) (); /* function to call to add this */
};

/* sub-token options */
struct SubConf
{
    char *tok;              /* our token string             */
    unsigned long  flag;    /* our token flag               */
    unsigned int   var;     /* our variable type            */
};

struct ConfVar
{
    sConf   *type;
    char    *value;
    int      loaded;        /* 1 - identified.  
                             * 2 - variable loaded
                             * 3 - delimited cleared */
};

/* tokens allowing subtokens */

#define CONFT_GLOBAL    "GLOBAL"
#define CONFF_GLOBAL                0x000001
#define CONFT_OPTIONS   "OPTIONS"
#define CONFF_OPTIONS               0x000002
#define CONFT_CLASS     "CLASS"
#define CONFF_CLASS                 0x000004
#define CONFT_ALLOW     "ALLOW"
#define CONFF_ALLOW                 0x000008
#define CONFT_OPER      "OPER"
#define CONFF_OPER                  0x000010
#define CONFT_CONNECT   "CONNECT"
#define CONFF_CONNECT               0x000020
#define CONFT_RESTRICT  "RESTRICT"
#define CONFF_RESTRICT              0x000040
#define CONFT_SUPER     "SUPER"
#define CONFF_SUPER                 0x000080
#define CONFT_KILL      "KILL"
#define CONFF_KILL                  0x000100
#define CONFT_ADMIN     "ADMIN"
#define CONFF_ADMIN                 0x000200
#define CONFT_PORT      "PORT"
#define CONFF_PORT                  0x000400
#define CONFT_MODULES   "MODULES"
#define CONFF_MODULES               0x000800

/* subtokens */

#define SCONFT_NAME     "NAME"
#define SCONFF_NAME                 0x000001
#define SCONFT_INFO     "INFO"
#define SCONFF_INFO                 0x000002
#define SCONFT_DPASS    "DPASS"
#define SCONFF_DPASS                0x000004
#define SCONFT_RPASS    "RPASS"
#define SCONFF_RPASS                0x000008
#define SCONFT_PINGFREQ "PINGFREQ"
#define SCONFF_PINGFREQ             0x000010
#define SCONFT_CONNFREQ "CONNFREQ"
#define SCONFF_CONNFREQ             0x000020
#define SCONFT_MAXUSERS "MAXUSERS"
#define SCONFF_MAXUSERS             0x000040
#define SCONFT_MAXSENDQ "MAXSENDQ"
#define SCONFF_MAXSENDQ             0x000080
#define SCONFT_CLASS     "CLASS"
#define SCONFF_CLASS                0x000100
#define SCONFT_HOST     "HOST"
#define SCONFF_HOST                 0x000200
#define SCONFT_PORT     "PORT"
#define SCONFF_PORT                 0x000800
#define SCONFT_PASSWD   "PASSWD"
#define SCONFF_PASSWD               0x001000
#define SCONFT_ACCESS   "ACCESS"
#define SCONFF_ACCESS               0x002000
#define SCONFT_BIND     "BIND"
#define SCONFF_BIND                 0x004000
#define SCONFT_APASSWD  "APASSWD"
#define SCONFF_APASSWD              0x008000
#define SCONFT_CPASSWD  "CPASSWD"
#define SCONFF_CPASSWD              0x010000
#define SCONFT_FLAGS    "FLAGS"
#define SCONFF_FLAGS                0x020000
#define SCONFT_REASON   "REASON"
#define SCONFF_REASON               0x040000
#define SCONFT_TYPE     "TYPE"
#define SCONFF_TYPE                 0x080000
#define SCONFT_MASK     "MASK"
#define SCONFF_MASK                 0x100000
#define SCONFT_IPMASK   "IPMASK"
#define SCONFF_IPMASK               0x200000
#define SCONFT_MAXRECVQ "MAXRECVQ"
#define SCONFF_MAXRECVQ             0x400000
#define SCONFT_UFLAGS   "UFLAGS"
#define SCONFF_UFLAGS               0x800000

#define SCONFF_STRING               0x1000000   /* allow freeform strings */

/* subtoken aliases */

#define SCONFT_MAXCLONE     "MAXCLONES"
#define SCONFT_MAXLINKS     "MAXLINKS"

/* these are the strings for options ONLY */

#define OPTT_NETNAME    "NETWORK_NAME"
#define OPTF_NETNAME                0x000002
#define OPTT_STAFFADDY  "STAFF_ADDRESS"
#define OPTF_STAFFADDY              0x000004
#define OPTT_SERVNAME   "SERVICES_NAME"
#define OPTF_SERVNAME               0x000010
#define OPTT_MAXCHAN    "MAXCHANNELS"
#define OPTF_MAXCHAN                0x000020
#define OPTT_WGMONHOST  "WGMONHOST"
#define OPTF_WGMONHOST              0x000040
#define OPTT_WGMONURL   "WGMONURL"
#define OPTF_WGMONURL               0x000080
#define OPTT_NKLINEADDY "NETWORK_KLINE"
#define OPTF_NKLINEADDY             0x000100
#define OPTT_LKLINEADDY "LOCAL_KLINE"
#define OPTF_LKLINEADDY             0x000200
#define OPTT_CRYPTPASS  "CRYPT_OPER_PASS"
#define OPTF_CRYPTPASS              0x000400
#define OPTT_SMOTD      "SHORT_MOTD"
#define OPTF_SMOTD                  0x000800
#define OPTT_SERVTYPE   "SERVTYPE"
#define OPTF_SERVTYPE               0x001000
#define OPTT_STATSNAME  "STATS_NAME"
#define OPTF_STATSNAME              0x002000
#define OPTT_TSMAXDELTA "TS_MAX_DELTA"
#define OPTF_TSMAXDELTA             0x004000
#define OPTT_TSWARNDELTA "TS_WARN_DELTA"
#define OPTF_TSWARNDELTA            0x008000
#define OPTT_NSREGURL   "NSHELPURL"
#define OPTF_NSREGURL               0x010000
#define OPTT_SHOWLINKS  "SHOW_LINKS"
#define OPTF_SHOWLINKS              0x020000
#define OPTT_SPLITOPOK  "ALLOW_SPLIT_OPS"
#define OPTF_SPLITOPOK              0x040000
#define OPTT_LCLONES    "LOCAL_CLONES"
#define OPTF_LCLONES                0x080000
#define OPTT_GCLONES    "GLOBAL_CLONES"
#define OPTF_GCLONES                0x100000
#define OPTT_SPAMFILTERURL "SPAMFILTERURL"
#define OPTF_SPAMFILTERURL          0x200000
#define OPTT_REMREHOK   "ALLOW_REMOTE_REHASH"
#define OPTF_REMREHOK               0x400000


/* module block definitions */

#define MBTT_PATH       "PATH"
#define MBTF_PATH                   0x0001
#define MBTT_AUTOLOAD   "AUTOLOAD"
#define MBTF_AUTOLOAD               0x0002
#define MBTT_OPTLOAD    "OPTLOAD"
#define MBTF_OPTLOAD                0x0004

/* our variable types */

#define VARTYPE_INT     0x0001  /* integers             */
#define VARTYPE_STRING  0x0002  /* freeform strings     */
#define VARTYPE_NAME    0x0004  /* non-free name        */
#define VARTYPE_NONE    0x0008  /* doesnt take any var  */

/* functions for parsing variables into appropriate variables */

#ifdef CONF_TABS

sConf confglobtab[] =
{
    {SCONFT_NAME, SCONFF_NAME, VARTYPE_NAME},
    {SCONFT_INFO, SCONFF_INFO, VARTYPE_STRING},
    {SCONFT_DPASS, SCONFF_DPASS, VARTYPE_NAME},
    {SCONFT_RPASS, SCONFF_RPASS, VARTYPE_NAME},
    {(char *) 0, 0, 0}
};

sConf confopttab[] =
{
    {OPTT_NETNAME, OPTF_NETNAME, VARTYPE_NAME},
    {OPTT_SERVNAME, OPTF_SERVNAME, VARTYPE_NAME},
    {OPTT_STATSNAME, OPTF_STATSNAME, VARTYPE_NAME},
    {OPTT_MAXCHAN, OPTF_MAXCHAN, VARTYPE_INT},
    {OPTT_WGMONHOST, OPTF_WGMONHOST, VARTYPE_NAME},
    {OPTT_WGMONURL, OPTF_WGMONURL, VARTYPE_NAME},
    {OPTT_NKLINEADDY, OPTF_NKLINEADDY, VARTYPE_NAME},
    {OPTT_LKLINEADDY, OPTF_LKLINEADDY, VARTYPE_NAME},
    {OPTT_CRYPTPASS, OPTF_CRYPTPASS, VARTYPE_NONE},
    {OPTT_SMOTD, OPTF_SMOTD, VARTYPE_NONE},
    {OPTT_SERVTYPE, OPTF_SERVTYPE, VARTYPE_NAME},
    {OPTT_TSMAXDELTA, OPTF_TSMAXDELTA, VARTYPE_INT},
    {OPTT_TSWARNDELTA, OPTF_TSWARNDELTA, VARTYPE_INT},
    {OPTT_STAFFADDY, OPTF_STAFFADDY, VARTYPE_NAME},
    {OPTT_NSREGURL, OPTF_NSREGURL, VARTYPE_NAME},
    {OPTT_SHOWLINKS, OPTF_SHOWLINKS, VARTYPE_NONE},
    {OPTT_SPLITOPOK, OPTF_SPLITOPOK, VARTYPE_NONE},
    {OPTT_LCLONES, OPTF_LCLONES, VARTYPE_NAME},
    {OPTT_GCLONES, OPTF_GCLONES, VARTYPE_NAME},
    {OPTT_SPAMFILTERURL, OPTF_SPAMFILTERURL, VARTYPE_NAME},
    {OPTT_REMREHOK, OPTF_REMREHOK, VARTYPE_NONE},
    {(char *) 0, 0, 0}
};

sConf confmoduletab[] =
{
    {MBTT_PATH, MBTF_PATH, VARTYPE_NAME},
    {MBTT_AUTOLOAD, MBTF_AUTOLOAD, VARTYPE_NAME},
    {MBTT_OPTLOAD, MBTF_OPTLOAD, VARTYPE_NAME},
    {(char *) 0, 0, 0}
};

sConf confclasstab[] =
{
    {SCONFT_NAME, SCONFF_NAME, VARTYPE_NAME},
    {SCONFT_PINGFREQ, SCONFF_PINGFREQ, VARTYPE_INT},
    {SCONFT_CONNFREQ, SCONFF_CONNFREQ, VARTYPE_INT},
    {SCONFT_MAXCLONE, SCONFF_CONNFREQ, VARTYPE_NAME},
    {SCONFT_MAXUSERS, SCONFF_MAXUSERS, VARTYPE_INT},
    {SCONFT_MAXLINKS, SCONFF_MAXUSERS, VARTYPE_INT},
    {SCONFT_MAXSENDQ, SCONFF_MAXSENDQ, VARTYPE_INT},
    {SCONFT_MAXRECVQ, SCONFF_MAXRECVQ, VARTYPE_INT},
    {(char *) 0, 0, 0}
};

sConf confallowtab[] =
{
    {SCONFT_HOST, SCONFF_HOST, VARTYPE_NAME},
    {SCONFT_IPMASK, SCONFF_IPMASK, VARTYPE_NAME},
    {SCONFT_PORT, SCONFF_PORT, VARTYPE_INT},
    {SCONFT_PASSWD, SCONFF_PASSWD, VARTYPE_NAME},
    {SCONFT_CLASS, SCONFF_CLASS, VARTYPE_NAME},
    {SCONFT_FLAGS, SCONFF_FLAGS, VARTYPE_NAME},
    {(char *) 0, 0, 0}
};

sConf confopertab[] =
{
    {SCONFT_NAME, SCONFF_NAME, VARTYPE_NAME},
    {SCONFT_HOST, SCONFF_HOST, VARTYPE_NAME},
    {SCONFT_PASSWD, SCONFF_PASSWD, VARTYPE_NAME},
    {SCONFT_ACCESS, SCONFF_ACCESS, VARTYPE_NAME},
    {SCONFT_CLASS, SCONFF_CLASS, VARTYPE_NAME},
    {(char *) 0, 0, 0}
};

sConf confconnecttab[] =
{
    {SCONFT_NAME, SCONFF_NAME, VARTYPE_NAME},
    {SCONFT_HOST, SCONFF_HOST, VARTYPE_NAME},
    {SCONFT_BIND, SCONFF_BIND, VARTYPE_NAME},
    {SCONFT_APASSWD, SCONFF_APASSWD, VARTYPE_NAME},
    {SCONFT_CPASSWD, SCONFF_CPASSWD, VARTYPE_NAME},
    {SCONFT_FLAGS, SCONFF_FLAGS, VARTYPE_NAME},
    {SCONFT_UFLAGS, SCONFF_UFLAGS, VARTYPE_NAME},
    {SCONFT_PORT, SCONFF_PORT, VARTYPE_INT},
    {SCONFT_CLASS, SCONFF_CLASS, VARTYPE_NAME},
    {(char *) 0, 0, 0}
};

sConf confrestricttab[] =
{
    {SCONFT_REASON, SCONFF_REASON, VARTYPE_STRING},
    {SCONFT_TYPE, SCONFF_TYPE, VARTYPE_NAME},
    {SCONFT_MASK, SCONFF_MASK, VARTYPE_NAME},
    {(char *) 0, 0, 0}
};

sConf confkilltab[] =
{
    {SCONFT_REASON, SCONFF_REASON, VARTYPE_STRING},
    {SCONFT_MASK, SCONFF_MASK, VARTYPE_NAME},
    {(char *) 0, 0, 0}
};

sConf confporttab[] =
{
    {SCONFT_PORT, SCONFF_PORT, VARTYPE_INT},
    {SCONFT_BIND, SCONFF_BIND, VARTYPE_NAME},
    {SCONFT_IPMASK, SCONFF_IPMASK, VARTYPE_NAME},
    {SCONFT_FLAGS, SCONFF_FLAGS, VARTYPE_NAME},
    {(char *) 0, 0, 0}
};


sConf confopentab[] =
{
    {0,SCONFF_STRING,0},
    {(char *) 0, 0, 0}
};

extern int confadd_global(cVar **, int);
extern int confadd_options(cVar **, int);
extern int confadd_class(cVar **, int);
extern int confadd_allow(cVar **, int);
extern int confadd_oper(cVar **, int);
extern int confadd_connect(cVar **, int);
extern int confadd_restrict(cVar **, int);
extern int confadd_super(cVar **, int);
extern int confadd_kill(cVar **, int);
extern int confadd_admin(cVar **, int);
extern int confadd_port(cVar **, int);
extern int confadd_modules(cVar **, int);

struct TopConf tconftab[] = 
{
    {CONFT_GLOBAL, CONFF_GLOBAL, CONFF_ADMIN, confglobtab, confadd_global},
    {CONFT_OPTIONS, CONFF_OPTIONS, 0, confopttab, confadd_options},
    {CONFT_CLASS, CONFF_CLASS, 0, confclasstab, confadd_class},
    {CONFT_ALLOW, CONFF_ALLOW, 0, confallowtab, confadd_allow},
    {CONFT_OPER, CONFF_OPER, 0, confopertab, confadd_oper},
    {CONFT_CONNECT, CONFF_CONNECT, 0, confconnecttab, confadd_connect},
    {CONFT_RESTRICT, CONFF_RESTRICT, 0, confrestricttab, confadd_restrict},
    {CONFT_KILL, CONFF_KILL, 0, confkilltab, confadd_kill},
    {CONFT_ADMIN, CONFF_ADMIN, 0, confopentab, confadd_admin},
    {CONFT_SUPER, CONFF_SUPER, 0, confopentab, confadd_super},
    {CONFT_PORT, CONFF_PORT, 0, confporttab, confadd_port},
    {CONFT_MODULES, CONFF_MODULES, 0, confmoduletab, confadd_modules},
    {(char *) 0, 0, 0, 0}
};


#endif
