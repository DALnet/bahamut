/************************************************************************
 *   IRC - Internet Relay Chat, include/hooks.h
 *   Copyright (C) 2003 Lucas Madar
 *
 */

enum c_hooktype {
   CHOOK_10SEC,       /* Called every 10 seconds or so -- not guaranteed to be 10 seconds */
                      /* Params: 0, returns void */

   CHOOK_PREACCESS,   /* Called before any access checks (dns, ident) are done, acptr->ip is valid, 
                         acptr->hostip is not */
                      /* Params: 1: (aClient *), returns int */
                      
   CHOOK_POSTACCESS,  /* called after access checks are done (right before client is put on network) */
                      /* Params: 1: (aClient *), returns int */

   CHOOK_MSG,         /* called for every privmsg or notice */
                      /* Params: 3: (aClient *, int isnotice, char *msgtext), returns int */

   CHOOK_MYMSG,       /* called for every privmsg or notice to 'me.name' */
                      /* Params: 3: (aClient *, int isnotice, char *msgtext), returns int */

   CHOOK_SIGNOFF      /* called on client exit (exit_client) */
                      /* Params: 1: (aClient *), returns void */
};

extern int call_hooks(enum c_hooktype hooktype, ...);

#ifdef BIRCMODULE
extern void *bircmodule_add_hook(enum c_hooktype, void *, void *);
extern void bircmodule_del_hook();
extern int bircmodule_malloc(int);
extern int bircmodule_free(void *);
#endif
