/*
 * include/cap.h - IRCv3 capability registry for Bahamut IRC Server
 *
 * Provides the capability registry (cap_add / cap_del / cap_find),
 * iteration helpers, and the HasCap() macro for per-client cap checks.
 *
 * cap_init() must be called after init_modules() in ircd.c to register
 * the built-in capabilities (multi-prefix, cap-notify).
 */

#ifndef CAP_H
#define CAP_H

/* Forward declarations — actual types defined in struct.h and mapi.h */
typedef struct Client aClient;
struct mapi_cap_av1;

struct capability {
    char          name[64];        /* e.g. "multi-prefix" */
    char          value[128];      /* optional value string; empty if none */
    unsigned long bit;             /* bitmask assigned by cap_add() */
    void (*on_enable)(aClient *);  /* called when a client enables this cap */
    void (*on_disable)(aClient *); /* called when a client disables this cap */
    struct capability *next;       /* hash chain */
};

/*
 * cap_add() — register a capability from a mapi_cap_av1 descriptor.
 * Assigns a unique bit, stores it in av1->cap_flag (if non-NULL),
 * and fires CAP NEW to connected cap-notify clients.
 * Returns 0 on success, -1 if already registered or out of bits.
 */
int                cap_add(const struct mapi_cap_av1 *av1);

/*
 * cap_del() — unregister a capability by name.
 * Sends CAP DEL to cap-notify clients and clears the bit from every
 * connected client's cap_bits.  on_disable is NOT fired (module is gone).
 */
void               cap_del(const char *name);

/*
 * cap_find() — look up a registered capability by name.
 * Returns NULL if not found.
 */
struct capability *cap_find(const char *name);

/*
 * cap_init() — register the built-in capabilities.
 * Must be called after init_modules().
 */
void               cap_init(void);

/*
 * cap_iterate() — call fn(cap, ud) for every registered capability.
 */
typedef void (*cap_iter_fn)(struct capability *, void *ud);
void               cap_iterate(cap_iter_fn fn, void *ud);

/*
 * HasCap(cptr, bit_) — true if client has the capability enabled.
 * Only meaningful for local clients (MyConnect()).
 */
#define HasCap(cptr, bit_)  (((cptr)->cap_bits & (bit_)) != 0)

/* Bit assigned to the built-in "multi-prefix" cap; set by cap_init() */
extern unsigned long cap_multi_prefix_bit;

/* Bit assigned to the "userhost-in-names" cap; set when module loads */
extern unsigned long cap_userhost_in_names_bit;

/* Bit assigned to the "extended-join" cap; set when module loads */
extern unsigned long cap_extended_join_bit;

#endif /* CAP_H */
