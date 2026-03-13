# Bahamut IRC Server — Developer Guide for Claude

## Workflow Orchestration

### 1. Plan Mode Default
- Enter plan mode for ANY non-trivial task (3+ steps or architectural decisions)
- If something goes sideways, STOP and re-plan immediately — don't keep pushing
- Use plan mode for verification steps, not just building
- Write detailed specs upfront to reduce ambiguity

### 2. Subagent Strategy
- Use subagents liberally to keep main context window clean
- Offload research, exploration, and parallel analysis to subagents
- For complex problems, throw more compute at it via subagents
- One task per subagent for focused execution

### 3. Self-Improvement Loop
- After ANY correction from the user: update `tasks/lessons.md` with the pattern
- Write rules for yourself that prevent the same mistake
- Ruthlessly iterate on these lessons until mistake rate drops
- Review lessons at session start for relevant project

### 4. Verification Before Done
- Never mark a task complete without proving it works
- Diff behavior between main and your changes when relevant
- Ask yourself: "Would a staff engineer approve this?"
- Run tests, check logs, demonstrate correctness

### 5. Demand Elegance (Balanced)
- For non-trivial changes: pause and ask "is there a more elegant way?"
- If a fix feels hacky: "Knowing everything I know now, implement the elegant solution"
- Skip this for simple, obvious fixes — don't over-engineer
- Challenge your own work before presenting it

### 6. Autonomous Bug Fixing
- When given a bug report: just fix it. Don't ask for hand-holding
- Point at logs, errors, failing tests — then resolve them
- Zero context switching required from the user
- Go fix failing CI tests without being told how

## Task Management

1. **Plan First**: Write plan to `tasks/todo.md` with checkable items
2. **Verify Plan**: Check in before starting implementation
3. **Track Progress**: Mark items complete as you go
4. **Explain Changes**: High-level summary at each step
5. **Document Results**: Add review section to `tasks/todo.md`
6. **Capture Lessons**: Update `tasks/lessons.md` after corrections

## Core Principles

- **Simplicity First**: Make every change as simple as possible. Impact minimal code.
- **No Laziness**: Find root causes. No temporary fixes. Senior developer standards.
- **Minimal Impact**: Changes should only touch what's necessary. Avoid introducing bugs.

---

## Build

```sh
# First-time setup
meson setup build -Dhookmodules=true

# Normal build
ninja -C build

# Full clean rebuild
ninja -C build -t clean && ninja -C build
```

## Testing

Integration tests live in `tests/` and use pytest with a custom harness that spawns real ircd processes.

```sh
# Prerequisites
pip install pytest  # Python 3.8+

# Run full suite
python3 -m pytest tests/ -v

# Run a specific suite
python3 -m pytest tests/suites/test_gossip.py -v

# Run a single test
python3 -m pytest tests/suites/test_gossip.py::TestGossip::test_gossip_link -v
```

### Architecture

- **`tests/harness/`** — Test infrastructure: `server.py` (BahamutServer process manager), `config.py` (ircd.conf generator), `irc_client.py` (line-based IRC client), `ws_client.py` (WebSocket client), `ports.py` (port allocator), `tls.py` (self-signed cert generator)
- **`tests/conftest.py`** — Shared pytest fixtures: `single_server`, `gossip_cluster` (2-node), `gossip_triangle` (3-node mesh), `client_factory`, `unique_nick`
- **`tests/suites/`** — Test files organized by feature (e.g. `test_nickserv.py`, `test_gossip.py`, `test_websocket.py`)

Each test fixture starts real ircd processes with generated configs in temporary directories. Gossip fixtures allocate multiple ports and configure gopeer blocks for server interconnection.

## Branch
Active development: `major-rewrite`

---

## Architecture (current state)

### Command dispatch — MAPI v2 / HandlerType

Every IRC command dispatched through `src/parse.c` → `parse()`. Before the handler
is called, the connection's registration state is classified into one of five slots:

```c
typedef enum HandlerType {
    HANDLER_UNREG,   /* pre-NICK/USER */
    HANDLER_CLIENT,  /* local registered user */
    HANDLER_REMOTE,  /* remote user via server link */
    HANDLER_SERVER,  /* server-to-server connection */
    HANDLER_OPER,    /* local IRC operator */
    HANDLER_LAST
} HandlerType;
```

Each `struct Message` carries `MessageEntry handlers[HANDLER_LAST]` where each slot
is `{mapi_cmd_fn handler; int min_para;}`. `min_para` is checked by the dispatch layer
before the handler is called — handlers do NOT need to recheck parc themselves.

### Generic sentinel handlers (defined in parse.c, declared in msg.h + mapi.h)

| Sentinel     | Effect                          |
|--------------|---------------------------------|
| `mg_ignore`  | Drop silently (return 0)        |
| `mg_unreg`   | Send ERR_NOTREGISTERED          |
| `mg_reg`     | Send ERR_ALREADYREGISTRED       |
| `mg_not_oper`| Send ERR_NOPRIVILEGES           |

Use these in command tables instead of NULL (NULL is also treated as mg_ignore but
prefer the explicit form for clarity).

### Handler function signature

```c
int m_example(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr, int parc, char *parv[]);
```

`msgbuf` is always a valid stack-allocated pointer (never NULL when called from
the normal dispatch path). If `msgbuf->n_tags == 0`, no IRCv3 tags were present.

**Internal calls** (one handler calling another directly) pass `NULL` for msgbuf:
```c
send_lusers(NULL, cptr, sptr, parc, parv);
m_names(NULL, acptr, acptr, 2, parv);
```

### MsgBuf

```c
/* include/msgbuf.h */
struct MsgBuf {
    char          raw[BUFSIZE + 1];
    int           n_tags;
    struct MsgTag tags[MAXMSGTAGS];   /* MAXMSGTAGS = 32 */
};
```

`parse_msgbuf()` in `src/msgbuf.c` tokenises `@key=val;key2;key3=val3` in-place.
`msgbuf_get_tag(mb, "key")` returns the value string (NULL if absent/boolean).

### Alias dispatch

`m_aliased()` and `m_sjr()` in `src/m_services.c` do NOT take an `AliasInfo *`
parameter. Instead, `parse.c` sets the global `AliasInfo *current_alias_info`
immediately before dispatch when `mptr->aliasidx >= 0`. These handlers read
`current_alias_info` directly. Any internal call site that calls `m_aliased`
directly must set `current_alias_info` first.

### reset_idle

`struct Message.reset_idle = 1` causes parse() to update `sptr->user->last` before
dispatch, for CLIENT and OPER handler types. Replaces the old `MF_RIDLE` flag.

### IRCv3 capability system

`include/cap.h` + `src/cap.c` provide the capability registry. `src/m_cap.c` is the
compiled-in CAP command handler (LS/LIST/REQ/END). Per-client state lives in
`aClient.cap_bits` / `cap_neg` / `cap_ls_version`. Modules declare caps via
`mapi_cap_av1` in their `DECLARE_MODULE` caps table; `modules.c` calls `cap_add()`/
`cap_del()` automatically on load/unload. `cap_init()` (called from `ircd.c` after
`init_modules()`) registers the built-in `multi-prefix` and `cap-notify` caps.

---

## Module authoring (MAPI v2)

### Command table

```c
#include "struct.h"
#include "h.h"
#include "mapi.h"

static int m_example(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr,
                     int parc, char *parv[]);

static const struct mapi_cmd_av2 example_cmds[] = {
    { "EXAMPLE", 0, {           /* reset_idle = 0 */
        { mg_unreg,   0 },      /* HANDLER_UNREG   — not allowed pre-reg */
        { m_example,  2 },      /* HANDLER_CLIENT  — min 2 params */
        { mg_ignore,  0 },      /* HANDLER_REMOTE  — ignore remote */
        { mg_ignore,  0 },      /* HANDLER_SERVER  — ignore from servers */
        { m_example,  2 },      /* HANDLER_OPER    — same as CLIENT */
    }},
    { NULL }
};

DECLARE_MODULE("example", "1.0", "Example module", 0, example_cmds, NULL);
/* or for a must-load module: DECLARE_CORE_MODULE(...) */
```

### Common handler patterns

| Command type            | UNREG      | CLIENT      | REMOTE      | SERVER      | OPER       |
|-------------------------|------------|-------------|-------------|-------------|------------|
| Normal user command     | mg_unreg   | m_fn        | mg_ignore   | mg_ignore   | m_fn       |
| Oper-only command       | mg_unreg   | mg_not_oper | mg_ignore   | ms_fn       | m_fn       |
| Pre-registration (e.g. WEBIRC) | m_fn | m_fn      | m_fn        | m_fn        | m_fn       |
| S2S only                | mg_unreg   | mg_ignore   | ms_fn       | ms_fn       | mg_ignore  |

### Lifecycle callbacks

```c
DECLARE_MODULE("name", "1.0", "desc", 0, cmds, NULL);
/*                                              ^^^^
   Replace NULL with a void (*)(void) to get mapi_register / mapi_unregister
   callbacks. mapi_register fires after cmd_add loop; mapi_unregister fires
   before cmd_del loop on unload.                                             */
```

### Declaring capabilities (Phase 3+)

```c
static unsigned long cap_away_notify = 0;

static const struct mapi_cap_av1 example_caps[] = {
    { "away-notify", NULL, &cap_away_notify, NULL, NULL },
    { NULL }
};

DECLARE_MODULE("example", "1.0", "Example", 0, example_cmds, example_caps);
```

`cap_away_notify` receives the assigned bit after `cap_add()`. Use `HasCap(cptr, cap_away_notify)`
to check if a client has it enabled.

### Module file location and build

- Core (must-load): `modules/core/m_name.c`
- Optional: `modules/extra/m_name.c`
- Add the `.c` filename to `modules/meson.build` in the correct `shared_library()` call.
- Use `DECLARE_CORE_MODULE` for core, `DECLARE_MODULE` for extra.
- Modules resolve symbols from the ircd binary at dlopen time (`b_lundef=false` in
  modules/meson.build — do NOT change this).

---

## Static msgtab[] helper macros (include/msg.h)

```c
M_UNREG(cmd, fn)          /* accessible pre-registration; all 5 slots → fn */
M_REG(cmd, fn)            /* registered-only; UNREG→mg_unreg, others→fn */
M_ALIAS(cmd, aii)         /* services alias; CLIENT+OPER→m_aliased, aliasidx=aii */
M_ALIAS_FN(cmd, aii, fn)  /* alias with custom handler fn */
```

---

## Key files

| File | Role |
|------|------|
| `include/struct.h` | Core data types: HandlerType, MessageEntry, mapi_cmd_fn, struct Message, aClient, aChannel, … |
| `include/mapi.h` | MAPI v2: mapi_cmd_av2, mapi_module, DECLARE_MODULE, mg_* externs, mapi_cap_av1 |
| `include/msg.h` | Handler externs, current_alias_info, M_UNREG/M_REG/M_ALIAS macros, static msgtab[] |
| `include/msgbuf.h` | MsgBuf, MsgTag structs; parse_msgbuf / msgbuf_get_tag declarations |
| `include/cap.h` | IRCv3 cap registry: cap_add/del/find/iterate, HasCap macro |
| `include/cmds.h` | Dynamic command registry: cmd_add(av2*), cmd_del, cmd_find_dynamic |
| `src/parse.c` | Dispatch engine, mg_* implementations, current_alias_info global |
| `src/msgbuf.c` | IRCv3 tag parser (in-place tokenisation) |
| `src/cap.c` | Capability registry: hash table, bit allocator, cap_init(), cap-notify logic |
| `src/m_cap.c` | CAP command handler (compiled-in): LS/LIST/REQ/END |
| `src/modules.c` | load_module / destroy_module / load_module_dir / init_modules |
| `src/s_bsd.c` | set_sock_opts(): TCP_NODELAY + SO_KEEPALIVE applied to every new socket |

---

## Lessons learned / error patterns

### 1. New source files MUST be added to src/meson.build

`src/msgbuf.c` was created but not added to `ircd_sources` in `src/meson.build`, causing
a linker "undefined reference to `parse_msgbuf`" error. Any new `.c` file must be listed
explicitly.

### 2. Broad automated signature replacement can hit non-handler function pointers

A bulk perl substitution on `(aClient *, aClient *, int, char **)` patterns also matched
the `module_globalcommand` typedef in `src/modules.c` (used for the old ABI, not the
new dispatch path). Always manually review what a regex replacement changed, especially
in typedef and function-pointer declarations that happen to share the parameter pattern.

### 3. Internal call sites need manual updating after signature changes

After changing `send_lusers`, `send_motd`, `m_umode`, `m_names`, `channel_svsmode`, and
`report_spamfilters` to the new 5-arg signature, every internal caller (in `s_serv.c`,
`s_user.c`, `channel.c`, `m_services.c`, `m_stats.c`) needed `NULL` prepended. The
compiler errors make these easy to find; the lesson is to search for all call sites before
declaring the signature migration complete.

### 4. h.h extern declarations must stay in sync

`include/h.h` contains extern declarations for some functions (e.g., `m_umode`, `m_names`)
in addition to the declarations in `msg.h`. If a function signature changes, check both
files. Stale declarations in h.h cause "conflicting types" errors even when msg.h is correct.

### 5. Module files use mapi.h for mg_* sentinels, not msg.h

Module source files include `mapi.h` (not `msg.h`). The `mg_*` sentinel externs are
declared in both `msg.h` (for core) and `mapi.h` (for modules). If you add a new sentinel,
add its extern to both headers.

### 6. meson setup vs ninja

`meson setup build` only needs to run once (or after `meson.build`/`meson_options.txt`
changes that meson cannot auto-detect). Normal development cycles use only `ninja -C build`.
After adding/removing source files in `meson.build`, ninja detects the change and
re-runs configure automatically — no manual `meson setup` needed.

### 7. Use strtoken(), not strtok_r()

The codebase declares `char *strtoken(char **save, char *orig, char *sep)` in `common.h`.
`strtok_r` is not declared and will produce implicit-function-declaration errors. Usage:
```c
char *p = NULL;
for (tok = strtoken(&p, str, " "); tok; tok = strtoken(&p, NULL, " "))
    ...
```

### 8. cap_table is private to cap.c — use cap_iterate() externally

`cap_table[]` is a static array in `src/cap.c`. External code that needs to walk all
registered capabilities must use the `cap_iterate(fn, ud)` API, not direct access.

### 9. cap bits referenced by core files must be defined in the ircd binary

If a core file (e.g. `channel.c`, `s_user.c`) checks `HasCap(x, some_cap_bit)`, the
`some_cap_bit` variable MUST be defined in the ircd binary (e.g. `src/cap.c`), not in
a module `.so`.  The linker resolves the binary at build time before any modules exist.
Pattern: define `unsigned long some_cap_bit = 0;` in `src/cap.c`, add `extern unsigned long
some_cap_bit;` to `include/cap.h`, and reference it from the module via `extern` (so the
module's `mapi_cap_av1.cap_flag` points at the binary-owned variable).

### 10. Modules that use IsMember() need to extern find_channel_link()

`IsMember(client, chan)` expands to `find_channel_link(...)` which is not declared in
any shared header. Module files that use `IsMember` must add:
```c
extern Link *find_channel_link(Link *, aChannel *);
```
See `modules/extra/m_tagmsg.c` and `modules/core/m_who.c` for precedent.

### 11. strncpyzt macro doesn't work with pointer arithmetic

The `strncpyzt(x, y, N)` macro expands `x[N-1]='\0'` which fails when `x` is
a pointer-arithmetic expression like `buf + pos` (GCC rejects the subscript).
Use `strncpy(buf + pos, src, len - 1); buf[sizeof(buf) - 1] = '\0';` instead.

### 12. aliastab/AII_NS not available in modules

`aliastab[]` and `AII_NS` are defined in `msg.h` inside an `#ifdef MSGTAB` guard
that modules don't set. Module files that need them must add:
```c
extern AliasInfo aliastab[];
#define AII_NS 0
```

### 13. Gossip propagation: emit_event vs gossip_event

`emit_event()` only adds to the local ring buffer. For immediate propagation to
gossip peers, call `gossip_event(ev, NULL)` on the returned `NetworkEvent *`.
Without this call, events only sync during burst (get_events_since).

### 14. Services alias local_handler signature

`aliastab[AII_*].local_handler` has type `int (*)(aClient *sptr, const char *text)`,
NOT the standard IRC handler signature. The dispatch function for /NS, /CS, /MS etc.
receives only the client and the raw text after the alias command. Do not use
`(aClient *, aClient *, int, char **)` — that causes an incompatible-pointer-types error.

### 15. Outbound gopeer connections need FLAGS_BLOCKED + write polling

`gopeer_try_connect()` must call `cptr->flags |= FLAGS_BLOCKED` and
`set_fd_flags(fd, FDF_WANTREAD|FDF_WANTWRITE)` after `add_fd()`. Without these,
the socket engine never polls for write-readiness and `completed_connection()` is
never called. This matches the pattern in `connect_server()` (s_bsd.c:2075-2076).

### 16. GoPeer clients have no aClass — check_pings must guard

Clients created by `gopeer_try_connect()` via `make_client(NULL, &me)` don't get
an `aClass` assigned. `check_pings()` in ircd.c dereferences `cptr->class->pingfreq`
for registered clients — must guard with `cptr->class != NULL` to prevent SIGSEGV.

### 17. EventClock must use sparse encoding — base64 exceeds BUFSIZE

`EventClock` has 64 slots × 8 bytes = 512 bytes raw → ~684 chars in base64. IRC
`BUFSIZE` is 512, so base64-encoded clocks truncate the IRC line, silently dropping
the command portion. Use `clock_encode_sparse()`/`clock_decode_sparse()` (format:
`slot.seq,slot.seq,...` for non-zero slots only). In practice, only 1-3 slots are
non-zero, yielding ~20 chars instead of ~684.

### 18. GVER full-sync events must use unique (server, seq) pairs

`emit_account_create()`/`emit_chanreg_create()`/`emit_memo_send()` in gossip.c must
increment `g_event_log.next_seq++` when building events for GVER_REQFULL responses.
Without `++`, all events share the same (server, seq) pair and the dedup table rejects
all but the first.

---

## Completed phases

| Phase | Status | Key deliverables |
|-------|--------|-----------------|
| Phase 1 | ✅ | Meson build, MAPI v1 module loader, WEBIRC as first module, CAPAB/DKEY removal |
| Phase 2 | ✅ | MAPI v2 (HandlerType dispatch, MsgBuf, av2 cmd tables, mapi_register/unregister), TCP_NODELAY, SO_KEEPALIVE, larger send buffers |
| Phase 3 | ✅ | IRCv3 CAP system (cap registry, m_cap handler, per-client cap_bits, mapi_cap_av1, CHOOK_POSTREGISTER) |
| Phase 4 | ✅ | multi-prefix (NAMES+WHO), away-notify, echo-message, server-time cap; CHOOK_AWAY; sendto_one_tags; server_time_tag; cap_multi_prefix_bit exported |
| Phase 5 | ✅ | Tagged channel delivery (sendto_channel_butone_tags), outbound tag registry, dispatch_serial, current_dispatch_label, message-ids, batch API, labeled-response cap |
| Phase 6 | ✅ | labeled-response ACK (CHOOK_POSTDISPATCH, lr_echo_sent); fixed CHOOK_POSTREGISTER + CHOOK_AWAY wiring in modules.c |
| Phase 7 | ✅ | userhost-in-names, invite-notify, setname, message-tags+TAGMSG; CHOOK_INVITE/SETNAME/TAGMSG hooks |
| Phase S1 | ✅ | Gossip event log (EventLog ring, EventId, EventClock, emit_event, m_gossip_eventlog module) |
| Phase S2 | ✅ | Gossip multi-uplink (STAT_GOPEER, GHELLO/GSYNCED/GEVENT/GACK, fanout, anti-netsplit in exit_client) |
| Phase S3 | ✅ | Legacy TS5 bridge (bridge_apply_event, bridge_burst_gossip_to_server, m_legacy_bridge CHOOK_SENDBURST) |
| Phase S4 | ✅ | Persistent sessions (session slab, RESUME command, CHOOK_SIGNOFF snapshot, gossip EVT_SESSION_CREATE/DESTROY, nick reservation, message queuing) |
| Phase 8A | ✅ | Account system + NickServ (account.h/c, account_crypto.c, accountstore.c, m_nickserv.c; PBKDF2-SHA256; gossip EVT_ACCOUNT_*; nick enforcement; CHOOK_ACCOUNT_LOGIN/LOGOUT; aliastab local_handler) |
| Phase 8B | ✅ | Channel registration + ChanServ (chanreg.h/c, chanregstore.c, m_chanserv.c; DALnet parity; gossip EVT_CHANREG_*; CHOOK_POSTJOIN) |
| Phase 8C | ✅ | Services state versioning (per-record uint64_t version; gossip-ver tag; version-aware conflict resolution; GVER_SUMMARY/GVER_REQFULL burst reconciliation; journal persistence) |
| Phase 9 | ✅ | MemoServ (memo.h/c, memostore.c, m_memoserv.c; SEND/LIST/READ/DEL/FORWARD/CSEND; gossip EVT_MEMO_*; journal persistence; CHOOK_ACCOUNT_LOGIN notification; memo expiry; CSEND channel access) |
| Phase 10A | ✅ | RootServ (m_rootserv.c; sra {} config blocks; SET/REMOVE/LIST/OFLAGS/HELP; gossip via EVT_ACCOUNT_MODIFY; SRA bootstrap at startup/rehash) |
| Phase 10B | ✅ | OperServ — native oper ban commands (AKILL/SQLINE/SGLINE oper paths in s_serv.c; m_operserv.c: GLOBAL/JUPE/MASSDEOP/MASSKICK/SILENCE via /OS alias) |
| Phase 10C | ✅ | StatServ (m_statserv.c; NETSTATS/SERVERS/MAP/UPTIME/COUNT/WHO/UINFO/CINFO/OPS via /SS alias) |
| Phase 11 | ✅ | SASL PLAIN + native account commands (base64.h/c; SASL numerics 900-908; sasl_account/sasl_buf on aClient; account_do_login/account_do_logout helpers in account.c; SASL pre-auth in register_user; m_sasl.c AUTHENTICATE+sasl cap; m_account_cmds.c REGISTER/LOGIN/LOGOUT) |
| Phase 12 | ✅ | TLS Enhancements: ssl {} config block; client cert fingerprint extraction (ssl_extract_certfp); account certfp + NickServ SET CERTFP; SASL EXTERNAL; STARTTLS (m_starttls.c + tls cap + RPL_STARTTLS 670/ERR_STARTTLS 691); gossip peer outbound TLS; draft/tls connection tag (m_tls_tag.c); WHOIS RPL_WHOISCERTFP 276 |
| CODERS-28 | ✅ | Hot-reloadable modules: MAPI v3 (IRCD_ABI_VERSION, min_abi_version, mapi_serialize/deserialize); MODULE RELOAD (core-safe); MODULE INFO; module_reload_state for cross-reload state; mod_path tracking; enhanced MODULE LIST with [core] flags |
| Phase S5 | ✅ | CAP-based session token delivery (draft/resume-0.5): pre-assigned tokens via RESUME TOKEN after registration; pre-registration RESUME command for reliable session restoration; fd-indexed side tables (token_table, resume_table); backward compat for non-cap clients; gossip propagation fix (emit_event + gossip_event) |
| Phase 13 | ✅ | IRCv3 Feature Round: msgid ratified cap (dual draft/standard); chghost cap (CHOOK_CHGHOST hook + m_chghost.c); umode widened to unsigned long; bot mode (UMODE_B + draft/bot tag); WHOX extended WHO (%fields,token → RPL_WHOSPCRPL 354); MONITOR command (own hash table, fd-indexed, 730-734 numerics) |
| CODERS-23 | ✅ | IRCv3 draft/chathistory: in-memory per-channel ring buffers (128 msgs/chan); CHATHISTORY command (LATEST/BEFORE/AFTER/AROUND/BETWEEN/TARGETS); chathistory + chathistory-targets batch types; CHOOK_CHANMSG capture + CHOOK_10SEC GC; ISUPPORT CHATHISTORY=50 MSGREFTYPES=timestamp,msgid |
| CODERS-24 | ✅ | WebSocket transport (RFC 6455): config-driven "W" port flag; WSState per-client state; HTTP upgrade handshake (SHA1+base64 accept); incremental frame parser (TEXT/PING/PONG/CLOSE); server→client unmasked TEXT framing in send_message(); WSS via SSL(WebSocket(IRC)) layering; auto-skip ident for WS ports |
| CODERS-33 | ✅ | Services read-only when gossip-partitioned: gopeer_configured_count/gopeer_connected_count tracking; gossip_is_partitioned() with 60s startup grace; NS/CS/MS/RS/REGISTER mutation gates (38 handlers); gopeer outbound connection lifecycle (CHOOK_10SEC retry, completed_connection GHELLO, FLAGS_BLOCKED polling, check_pings NULL guard, throttle exemption); 4 integration tests |
| CODERS-34 | ✅ | Gossip event propagation fix: parse_msgbuf space-after-tags bug; sparse clock encoding (base64 exceeded BUFSIZE); GVER dedup fix (next_seq increment); all 77 tests passing including 10 gossip tests |
