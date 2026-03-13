/************************************************************************
 *   IRC - Internet Relay Chat, include/hooks.h
 *   Copyright (C) 2003 Lucas Madar
 *
 */

#ifndef HOOKS_H
#define HOOKS_H

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
   CHOOK_ONACCESS,    /* called during m_user 
                       * (after CHOOK_PREACCESS and before CHOOK_POSTACCESS)
                       * Params: 5: (aClient *, char *username, char *host,
                       *             char *server, char *realname) 
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
                       * Params: 4: (char *orghost, char *orgip, char **newhost, int type)
                       * Returns int
                       */
   CHOOK_FLOODWARN,   /* called during flood warnings to opers
                       * from channel.c, s_bsd.c and s_user.c
                       * Params: 5: (aClient *source, aChannel *channel,
                       *             int type, char *cmd, char *reason)
                       * Returns int
                       */
   CHOOK_SPAMWARN,    /* called from s_user.c and channel.c during spam warnings to opers
                       * Params: 4: (aClient *source, int type, int max_targets,
                       *             char *target_name)
                       * Returns int
                       */
   CHOOK_SIGNOFF,     /* called on client exit (exit_client)
                       * Params: 1: (aClient *)
                       * Returns void */
   MHOOK_LOAD,        /* Called for modules loading and unloading */
   MHOOK_UNLOAD,      /* Params: 2: (char *modulename, void *moduleopaque) */
   CHOOK_POSTREGISTER, /* called at the end of register_user(), after the
                       * client is fully on the network.
                       * Params: 1: (aClient *sptr)
                       * Returns int */
   CHOOK_AWAY,        /* called when a client sets or clears AWAY.
                       * Params: 3: (aClient *sptr, int setting, char *message)
                       * setting = 1: going away (message = away text)
                       * setting = 0: returning (message = NULL)
                       * Returns void */
   CHOOK_POSTDISPATCH, /* called after a command handler returns, before
                       * current_dispatch_label is cleared.
                       * Only fired when current_dispatch_label[0] != '\0'.
                       * Params: 1: (aClient *sptr) — originating client
                       * Returns int */
   CHOOK_INVITE,      /* called after a successful INVITE
                       * Params: 3: (aClient *inviter, aClient *target,
                       *             aChannel *chptr)
                       * Returns void */
   CHOOK_SETNAME,     /* called when a client changes realname via SETNAME
                       * Params: 2: (aClient *sptr, const char *newname)
                       * Returns void */
   CHOOK_TAGMSG,      /* called for every TAGMSG delivery
                       * Params: 4: (aClient *src, void *target,
                       *             int is_chan, const char *tags)
                       * Returns void */

   /* Phase S1: gossip event hooks */
   CHOOK_NICK,        /* called after a successful nick change
                       * Params: 3: (aClient *sptr, const char *oldnick,
                       *             const char *newnick)
                       * Returns void */
   CHOOK_PART,        /* called when a user parts a channel (after send,
                       * before remove_user_from_channel)
                       * Params: 3: (aClient *sptr, aChannel *chptr,
                       *             const char *reason)  — reason may be NULL
                       * Returns void */
   CHOOK_CHANMODE,    /* called after a channel mode change is propagated
                       * Params: 4: (aClient *sptr, aChannel *chptr,
                       *             const char *modebuf, const char *parabuf)
                       * Returns void */
   CHOOK_TOPIC,       /* called after a channel topic is set
                       * Params: 3: (aClient *sptr, aChannel *chptr,
                       *             const char *topic)
                       * Returns void */
   CHOOK_UMODE,       /* called after a user mode change is propagated
                       * Params: 2: (aClient *sptr, unsigned long old_umode)
                       * Returns void */

   /* Phase 8A: account system hooks */
   CHOOK_ACCOUNT_LOGIN, /* called after successful IDENTIFY
                       * Params: 1: (aClient *sptr)
                       * Returns void */
   CHOOK_ACCOUNT_LOGOUT, /* called on disconnect or explicit logout
                       * Params: 1: (aClient *sptr)
                       * Returns void */

   /* Phase 8B: channel registration */
   CHOOK_POSTJOIN,    /* called after join completes (add_user_to_channel
                       * + sendto_channel_join done)
                       * Params: 2: (aClient *sptr, aChannel *chptr)
                       * Returns void */

   CHOOK_CHGHOST      /* called when a user's visible host changes (SVSHOST)
                       * Params: 3: (aClient *sptr, const char *old_user,
                       *             const char *old_host)
                       * Returns void */
};

extern int call_hooks(enum c_hooktype hooktype, ...);
extern int init_modules();

#define MODULE_INTERFACE_VERSION 1011 /* the interface version (hooks, modules.c commands, etc) */

#ifdef BIRCMODULE
extern void *bircmodule_add_hook(enum c_hooktype, void *, void *);
extern void bircmodule_del_hook();
extern int bircmodule_malloc(int);
extern void bircmodule_free(void *);
#endif

#define UHM_SUCCESS      1
#define UHM_SOFT_FAILURE 0
#define UHM_HARD_FAILURE FLUSH_BUFFER

#endif /* HOOKS_H */
