# Phase 10B: OperServ (Native Oper Ban Commands) + Phase 10C: StatServ

## Phase 10B — Completed

- [x] Add oper paths to `m_akill` in `src/s_serv.c` with safety checks
  - Oper syntax: `AKILL user@host <duration_min> :reason`
  - Requires IsAnOper + SACCESS_SADMIN or OFLAG_KALINE
  - Safety: mask must contain @, host must contain '.', CIDR minimums (/16 IPv4, /48 IPv6)
  - Duration capped at 7 days, default 1 day
- [x] Add oper path to `m_rakill` in `src/s_serv.c`
  - Oper syntax: `RAKILL user@host`
  - Same privilege requirements as AKILL
- [x] Add oper paths to `m_sqline` / `m_unsqline` in `src/s_serv.c`
  - Requires IsAnOper + SACCESS_SADMIN or OFLAG_SQLINE
  - Safety: bare wildcard * requires SRA
- [x] Add oper paths to `m_sgline` / `m_unsgline` in `src/s_serv.c`
  - Requires IsAnOper + SACCESS_SADMIN or OFLAG_SGLINE
- [x] Create `modules/core/m_operserv.c` — OperServ module
  - GLOBAL: network-wide notice to all users (SAdmin+)
  - JUPE/UNJUPE: server jupe management (SRA or OFLAG_JUPE)
  - MASSDEOP: deop all ops in a channel (SAdmin+)
  - MASSKICK: kick all users from a channel (SAdmin+)
  - SILENCE/UNSILENCE: set/remove +X squelch (SRA or OFLAG_SILENCE)
  - HELP: command reference
- [x] Add m_operserv to `modules/meson.build`
- [x] Clean build: 142/142 targets, 0 errors

## Phase 10C — Completed

- [x] Create `modules/core/m_statserv.c` — StatServ module
  - NETSTATS: network-wide statistics (any oper)
  - SERVERS: list all connected servers with hops/uplink
  - MAP: ASCII server tree
  - UPTIME: server uptime
  - COUNT: count users matching user@host mask (SOper+)
  - WHO: search users by nick!user@host mask (SOper+)
  - UINFO: full user information dump (SOper+)
  - CINFO: full channel inspection (SOper+)
  - OPS: list online IRC operators (SOper+)
  - HELP: command reference
- [x] Add m_statserv to `modules/meson.build`
- [x] Clean build: 142/142 targets, 0 errors

## Files Modified

| File | Change |
|------|--------|
| `src/s_serv.c` | Added `#include "account.h"`; oper paths for m_akill, m_rakill, m_sqline, m_unsqline, m_sgline, m_unsgline |
| `modules/core/m_operserv.c` | New: OperServ module (GLOBAL, JUPE, MASSDEOP, MASSKICK, SILENCE) |
| `modules/core/m_statserv.c` | New: StatServ module (NETSTATS, SERVERS, MAP, UPTIME, COUNT, WHO, UINFO, CINFO, OPS) |
| `modules/meson.build` | Added m_operserv, m_statserv to core module list |

## Architecture Notes

- Ban commands (AKILL/SQLINE/SGLINE) are native IRC commands, not behind a pseudoclient
- OperServ (/OS) dispatches GLOBAL, JUPE, MASSDEOP, MASSKICK, SILENCE via alias
- StatServ (/SS) dispatches all stat/inspection commands via alias
- JUPE is in-memory only (not persisted, not gossiped) — per-server
- Both modules use `aliastab[AII_OS/AII_SS].local_handler` pattern
- Privilege checks use services account system (account_find + saccess/oflags)

---

# Previous Phases

## Phase 10A: RootServ — Complete
## Phase 9: MemoServ — Complete
## Phase 8C: Services State Versioning — Complete
## Phase 8B: ChanServ — Complete
## Phase 8A: Account System (NickServ) — Complete
