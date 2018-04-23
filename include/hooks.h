/************************************************************************
 *   IRC - Internet Relay Chat, include/hooks.h
 *   Copyright (C) 2003 Lucas Madar
 *
 */

enum c_hooktype {
   CHOOK_10SEC,       /* Called every 10 seconds or so -- 
                       * not guaranteed to be 10 seconds *
                       * Params: None
                       * Returns void 
                       */
   CHOOK_PREACCESS,   /* Called before any access checks (dns, ident) 
                       * are done, acptr->ip is valid, 
                       * acptr->hostip is not "*"
                       * Params: 1: (aClient *) 
                       * Returns int
                       */
   CHOOK_POSTACCESS,  /* called after access checks are done 
                       * (right before client is put on network)
                       * Params: 1: (aClient *) 
                       * Returns int 
                       */
   CHOOK_POSTMOTD,    /* called after MOTD is shown to the client 
                       * Params: 1: (aClient *)
                       * Returns int 
                       */

   CHOOK_MSG,         /* called for every privmsg or notice
                       * Params: 3: (aClient *, int isnotice, char *msgtext), 
                       * Returns int 
                       */
   CHOOK_CHANMSG,     /* called for every privmsg or notice to a channel
                       * Params: 4: (aClient *source, aChannel *destination, 
                       *             int isnotice, char *msgtxt)
                       * Returns int
                       */
   CHOOK_USERMSG,     /* called for every privmsg or notice to a user
                       * Params: 4: (aClient *source, aClient *destination,
                       *             int isnotice, char *msgtxt)
                       * Returns int
                       */
   CHOOK_MYMSG,       /* called for every privmsg or notice to 'me.name' 
                       * Params: 3: (aClient *, int isnotice, char *msgtext)
                       * Returns int 
                       */
   CHOOK_JOIN,        /* called for local JOINs
                       * Params: 1: (aClient *, aChannel *)
                       * Returns int
                       */
   CHOOK_SENDBURST,   /* called from m_server.c during netbursts
                       * Params: 1: (aClient *)
                       * Returns void
                       */
   CHOOK_THROTTLE,    /* called from channel.c during throttle warnings
                       * Params: 3: (aClient *source, aChannel *channel,
                       *             int type, int jnum, int jtime)
                       * Returns void
                       */
   CHOOK_FORBID,      /* called from m_nick.c and channel.c when a user is
                       * attempting to use a forbidden nick or join a forbidden
                       * channel
                       * Params: 3: (aClient *source, char *name,
                       *             struct simBan *ban)
                       * Returns void
                       */
   CHOOK_WHOIS,       /* called from s_user.c when a user is
                       * doing a /whois
                       * Params: 2: (aClient *source, aClient *target)
                       * Returns int
                       */
   CHOOK_MASKHOST,    /* called from s_user.c when in order to
                       * mask a user host/IP
                       * Params: 3: (char *orghost, char **newhost, int type)
                       * Returns int
                       */
   CHOOK_SIGNOFF,     /* called on client exit (exit_client)
                       * Params: 1: (aClient *)
                       * Returns void */
   MHOOK_LOAD,        /* Called for modules loading and unloading */
   MHOOK_UNLOAD       /* Params: 2: (char *modulename, void *moduleopaque) */
};

extern int call_hooks(enum c_hooktype hooktype, ...);
extern int init_modules();

#define MODULE_INTERFACE_VERSION 1008 /* the interface version (hooks, modules.c commands, etc) */

#ifdef BIRCMODULE
extern void *bircmodule_add_hook(enum c_hooktype, void *, void *);
extern void bircmodule_del_hook();
extern int bircmodule_malloc(int);
extern void bircmodule_free(void *);
#endif

#define UHM_SUCCESS      1
#define UHM_SOFT_FAILURE 0
#define UHM_HARD_FAILURE FLUSH_BUFFER
