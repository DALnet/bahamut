/* Bahamut IRCd - include/confparse.h
 * Copyright (c) 2004, Aaron Wiebe
 *
 * Apply the GPL here.
 */

/* $Id$ */

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
    unsigned long  subtok;  /* sub-tokens allowed in here   */
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

#define SCONFF_STRING               0x800000    /* allow freeform strings */

/* our variable types */

#define VARTYPE_INT     0x0001  /* integers             */
#define VARTYPE_STRING  0x0002  /* freeform strings     */
#define VARTYPE_NAME    0x0004  /* non-free name        */
#define VARTYPE_NONE    0x0008  /* doesnt take any var  */

/* functions for parsing variables into appropriate variables */

#ifdef CONF_TABS

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

struct TopConf tconftab[] = 
{
    {CONFT_GLOBAL, CONFF_GLOBAL, CONFF_ADMIN,
      (SCONFF_NAME|SCONFF_INFO|SCONFF_DPASS|SCONFF_RPASS), confadd_global},
    {CONFT_OPTIONS, CONFF_OPTIONS, 0, 0, confadd_options},
    {CONFT_CLASS, CONFF_CLASS, 0, (SCONFF_NAME|SCONFF_PINGFREQ|SCONFF_CONNFREQ
                                    |SCONFF_MAXUSERS|SCONFF_MAXSENDQ),
                                    confadd_class},
    {CONFT_ALLOW, CONFF_ALLOW, 0, (SCONFF_HOST|SCONFF_IPMASK|SCONFF_PORT
                                    |SCONFF_PASSWD|SCONFF_CLASS),
                                    confadd_allow},
    {CONFT_OPER, CONFF_OPER, 0, (SCONFF_NAME|SCONFF_HOST
                                    |SCONFF_PASSWD|SCONFF_ACCESS|SCONFF_CLASS),
                                    confadd_oper},
    {CONFT_CONNECT, CONFF_CONNECT, 0, (SCONFF_NAME|SCONFF_HOST|SCONFF_BIND
                                    |SCONFF_APASSWD|SCONFF_CPASSWD|SCONFF_FLAGS
                                    |SCONFF_PORT|SCONFF_CLASS),
                                    confadd_connect},
    {CONFT_RESTRICT, CONFF_RESTRICT, 0, (SCONFF_TYPE|SCONFF_MASK
                                    |SCONFF_REASON), confadd_restrict},
    {CONFT_KILL, CONFF_KILL, 0, (SCONFF_MASK|SCONFF_REASON), confadd_kill},
    {CONFT_ADMIN, CONFF_ADMIN, 0, SCONFF_STRING, confadd_admin},
    {CONFT_SUPER, CONFF_SUPER, 0, 0, confadd_super},
    {CONFT_PORT, CONFF_PORT, 0, (SCONFF_PORT|SCONFF_BIND|SCONFF_IPMASK),
                                confadd_port},
    {(char *) 0, 0, 0, 0}
};


struct SubConf sconftab[] =
{
    {SCONFT_NAME, SCONFF_NAME, VARTYPE_NAME},
    {SCONFT_INFO, SCONFF_INFO, VARTYPE_STRING},
    {SCONFT_DPASS, SCONFF_DPASS, VARTYPE_NAME},
    {SCONFT_RPASS, SCONFF_RPASS, VARTYPE_NAME},
    {SCONFT_PINGFREQ, SCONFF_PINGFREQ, VARTYPE_INT},
    {SCONFT_CONNFREQ, SCONFF_CONNFREQ, VARTYPE_INT},
    {SCONFT_MAXUSERS, SCONFF_MAXUSERS, VARTYPE_INT},
    {SCONFT_MAXSENDQ, SCONFF_MAXSENDQ, VARTYPE_INT},
    {SCONFT_CLASS, SCONFF_CLASS, VARTYPE_NAME},
    {SCONFT_HOST, SCONFF_HOST, VARTYPE_NAME},
    {SCONFT_PORT, SCONFF_PORT, VARTYPE_INT},
    {SCONFT_PASSWD, SCONFF_PASSWD, VARTYPE_NAME},
    {SCONFT_ACCESS, SCONFF_ACCESS, VARTYPE_NAME},
    {SCONFT_BIND, SCONFF_BIND, VARTYPE_NAME},
    {SCONFT_APASSWD, SCONFF_APASSWD, VARTYPE_NAME},
    {SCONFT_CPASSWD, SCONFF_CPASSWD, VARTYPE_NAME},
    {SCONFT_FLAGS, SCONFF_FLAGS, VARTYPE_NAME},
    {SCONFT_REASON, SCONFF_REASON, VARTYPE_STRING},
    {SCONFT_TYPE, SCONFF_TYPE, VARTYPE_NAME},
    {SCONFT_MASK, SCONFF_MASK, VARTYPE_NAME},
    {(char *) 0, 0, 0}
};

#endif
