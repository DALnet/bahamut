/*
 * include/mapi.h - Module API version 2 for Bahamut IRC Server
 *
 * Defines the MAPI v2 interface that loadable modules use to register
 * IRC commands (with per-HandlerType dispatch) and hook into server events.
 *
 * Usage in a module:
 *
 *   #include "struct.h"
 *   #include "mapi.h"
 *
 *   static int m_hello(struct MsgBuf *mb, aClient *cptr, aClient *sptr,
 *                      int parc, char *parv[]);
 *
 *   static const struct mapi_cmd_av2 hello_cmds[] = {
 *       { "HELLO", 0, {
 *           { mg_unreg,  0 },   // HANDLER_UNREG
 *           { m_hello,   2 },   // HANDLER_CLIENT
 *           { m_hello,   2 },   // HANDLER_REMOTE
 *           { m_hello,   2 },   // HANDLER_SERVER
 *           { m_hello,   2 },   // HANDLER_OPER
 *       }},
 *       { NULL }
 *   };
 *
 *   DECLARE_MODULE("m_hello", "2.0", "Example command", 0, hello_cmds, NULL);
 *
 *   static int m_hello(struct MsgBuf *mb, aClient *cptr, aClient *sptr,
 *                      int parc, char *parv[])
 *   { ... }
 */

#ifndef MAPI_H
#define MAPI_H

#include "hooks.h"

/* MAPI interface version.  Bumped on ABI-breaking changes. */
#define MAPI_VERSION   3
#define MAPI_VERSION_2 2
#define MAPI_VERSION_3 3

/* Binary ABI version — bump when struct layouts change in ways that affect modules */
#define IRCD_ABI_VERSION 1

/* Module flags (mod_flags field in mapi_module) */
#define MAPI_CORE 0x01     /* module cannot be unloaded via MODULE UNLOAD */

/*
 * MAXPARA fallback for module files that do not include msg.h.
 * msg.h defines the canonical value; this guard keeps modules independent.
 */
#ifndef MAXPARA
#define MAXPARA 15
#endif

/*
 * Generic sentinel handlers (defined in src/parse.c).
 * Available for use in mapi_cmd_av2 handler tables.
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
 * mapi_cmd_av2 - one command entry in a module's command table (av2).
 *
 * cmd:        IRC command name, uppercase (e.g. "HELLO").
 * reset_idle: 1 = update sptr->user->last on CLIENT/OPER dispatch.
 * handlers:   per-HandlerType dispatch array.
 *             Use mg_ignore to silently drop, mg_unreg to send
 *             ERR_NOTREGISTERED, mg_not_oper for ERR_NOPRIVILEGES.
 *             NULL is equivalent to mg_ignore.
 *
 * Terminate the array with an entry where cmd == NULL.
 */
struct mapi_cmd_av2 {
    const char   *cmd;
    int           reset_idle;
    MessageEntry  handlers[HANDLER_LAST]; /* indexed by HandlerType */
};

/*
 * mapi_hook_av1 - one hook entry in a module's hook table.
 * Terminate the array with an entry where fn == NULL.
 */
struct mapi_hook_av1 {
    enum c_hooktype hooktype; /* which event to hook                       */
    void           *fn;       /* function pointer, cast to correct type    */
};

/*
 * mapi_cap_av1 - one IRCv3 capability entry in a module's caps table.
 * Terminate the array with an entry where name == NULL.
 *
 * cap_add() will write the assigned bit mask into *cap_flag (if non-NULL).
 * on_enable / on_disable may be NULL if not needed.
 */
struct mapi_cap_av1 {
    const char   *name;             /* cap name, e.g. "away-notify"       */
    const char   *value;            /* optional value; NULL or "" if none  */
    unsigned long *cap_flag;        /* receives the assigned bit on load   */
    void (*on_enable)(aClient *);   /* called when a client enables this   */
    void (*on_disable)(aClient *);  /* called when a client disables this  */
};

/*
 * mapi_module - the module header struct.
 * A module declares exactly one of these as the global symbol "_mheader".
 * The server looks for this symbol when loading a shared library.
 */
struct mapi_module {
    int                         mapi_version;    /* must be MAPI_VERSION         */
    unsigned int                mod_flags;       /* MAPI_CORE or 0               */
    const char                 *name;            /* short module name            */
    const char                 *version;         /* version string               */
    const char                 *description;     /* human-readable description   */
    const struct mapi_cmd_av2  *cmds;            /* command table, or NULL       */
    const struct mapi_hook_av1 *hooks;           /* hook table, or NULL          */
    const struct mapi_cap_av1  *caps;            /* cap table, or NULL           */
    void                      (*mapi_register)(void);   /* called after load    */
    void                      (*mapi_unregister)(void); /* called before unload */

    /* MAPI v3 fields — zero-initialized by existing macros (C11 §6.7.9¶21) */
    int                        min_abi_version;   /* 0 = any; reject if > IRCD_ABI_VERSION */
    void                      (*mapi_serialize)(void);   /* save state before reload   */
    void                      (*mapi_deserialize)(void); /* restore state after reload */
};

/*
 * DECLARE_MODULE - convenience macro to declare the module header.
 * Place this at file scope (outside any function).
 *
 * flags_: MAPI_CORE or 0
 */
#define DECLARE_MODULE(name_, ver_, desc_, flags_, cmds_, hooks_)  \
    struct mapi_module _mheader = {                                \
        MAPI_VERSION, (flags_), (name_), (ver_), (desc_),         \
        (cmds_), (hooks_), NULL, NULL, NULL                        \
    }

/*
 * DECLARE_CORE_MODULE - shorthand for modules that set MAPI_CORE.
 * Core modules refuse MODULE UNLOAD.
 */
#define DECLARE_CORE_MODULE(name_, ver_, desc_, cmds_, hooks_)     \
    DECLARE_MODULE(name_, ver_, desc_, MAPI_CORE, cmds_, hooks_)

/*
 * DECLARE_MODULE_CAPS - like DECLARE_MODULE but also passes a caps table.
 */
#define DECLARE_MODULE_CAPS(name_, ver_, desc_, flags_, cmds_, hooks_, caps_) \
    struct mapi_module _mheader = {                                \
        MAPI_VERSION, (flags_), (name_), (ver_), (desc_),         \
        (cmds_), (hooks_), (caps_), NULL, NULL                     \
    }

/*
 * DECLARE_CORE_MODULE_CAPS - DECLARE_MODULE_CAPS with MAPI_CORE set.
 */
#define DECLARE_CORE_MODULE_CAPS(name_, ver_, desc_, flags_, cmds_, hooks_, caps_) \
    DECLARE_MODULE_CAPS((name_), (ver_), (desc_), (flags_) | MAPI_CORE, \
                        (cmds_), (hooks_), (caps_))

/*
 * DECLARE_MODULE_CAPS_RU - like DECLARE_MODULE_CAPS but also accepts
 * mapi_register and mapi_unregister callbacks.
 * Use this when a module needs to call register_outbound_tag() on load
 * and unregister_outbound_tag() on unload.
 */
#define DECLARE_MODULE_CAPS_RU(name_, ver_, desc_, flags_, cmds_, hooks_, caps_, reg_, unreg_) \
    struct mapi_module _mheader = {                                \
        MAPI_VERSION, (flags_), (name_), (ver_), (desc_),         \
        (cmds_), (hooks_), (caps_), (reg_), (unreg_)              \
    }

/*
 * DECLARE_MODULE_V3 - full v3 declaration with serialize/deserialize callbacks.
 *
 * Modules needing cross-reload state use mapi_serialize to save state into
 * module_reload_state before unload, and mapi_deserialize to restore it
 * after reload.
 */
#define DECLARE_MODULE_V3(name_, ver_, desc_, flags_, cmds_, hooks_, caps_, \
                          reg_, unreg_, ser_, deser_)                       \
    struct mapi_module _mheader = {                                         \
        MAPI_VERSION, (flags_), (name_), (ver_), (desc_),                   \
        (cmds_), (hooks_), (caps_), (reg_), (unreg_),                       \
        0, (ser_), (deser_)                                                 \
    }

/*
 * module_reload_state - opaque pointer for passing state across a module reload.
 *
 * Protocol:
 *   mapi_serialize:   MyMalloc a blob, store pointer in module_reload_state
 *   mapi_deserialize: read from module_reload_state, restore, MyFree, set to NULL
 *
 * Lives in the ircd binary's BSS, survives dlclose/dlopen.
 */
extern void *module_reload_state;

#endif /* MAPI_H */
