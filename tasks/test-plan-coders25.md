# CODERS-25: Integration Testing & Hardening — Test Plan

## Automated Test Suites

Run all tests: `python3 -m pytest tests/ -v`

### test_basic.py (8 tests)
- [x] `test_connect_welcome` — TCP connect, receive 001-004
- [x] `test_registration` — NICK + USER, get welcome
- [x] `test_ping_pong` — server PING, client PONG, connection alive
- [x] `test_quit` — QUIT with message, connection closes
- [x] `test_multi_client` — 5 concurrent clients register
- [x] `test_invalid_nick` — bad nick chars → ERR_ERRONEUSNICKNAME (432)
- [x] `test_double_registration` — USER twice → ERR_ALREADYREGISTRED (462)
- [x] `test_oper` — OPER admin secret → RPL_YOUREOPER (381)

### test_cap.py (6 tests)
- [x] `test_cap_ls` — CAP LS 302 returns capabilities
- [x] `test_cap_req_single` — REQ multi-prefix → ACK
- [x] `test_cap_req_multi` — REQ multi-prefix+away-notify → ACK
- [x] `test_cap_req_unsupported` — REQ nonexistent → NAK
- [x] `test_cap_end` — CAP END completes registration
- [x] `test_known_caps` — all implemented caps present in LS

### test_channel.py (10 tests)
- [x] `test_join_part` — JOIN, NAMES, PART
- [x] `test_topic` — SET/GET TOPIC
- [x] `test_privmsg` — channel PRIVMSG delivery
- [x] `test_notice` — channel NOTICE delivery
- [x] `test_kick` — operator KICK
- [x] `test_mode_op` — +o/-o
- [x] `test_mode_ban` — +b prevents join
- [x] `test_mode_key` — +k requires key
- [x] `test_mode_limit` — +l capacity limit
- [x] `test_names_multiprefix` — NAMES with multi-prefix

### test_sasl.py (3 tests)
- [x] `test_sasl_plain_success` — SASL PLAIN → 903
- [x] `test_sasl_plain_fail` — wrong password → 904
- [x] `test_sasl_unknown_mech` — unknown mechanism → 908

### test_monitor.py (5 tests)
- [x] `test_monitor_add_offline` — MONITOR + → 731
- [x] `test_monitor_online` — target connects → 730
- [x] `test_monitor_offline` — target quits → 731
- [x] `test_monitor_clear` — MONITOR C clears list
- [x] `test_monitor_list` — MONITOR L lists targets

### test_whox.py (2 tests)
- [x] `test_whox_basic` — WHO %fields,token → 354
- [x] `test_who_standard` — WHO → 352

### test_chathistory.py (4 tests)
- [x] `test_latest` — CHATHISTORY LATEST → batch
- [x] `test_before` — CHATHISTORY BEFORE timestamp
- [x] `test_targets` — CHATHISTORY TARGETS
- [x] `test_cap_required` — chathistory requires cap

### test_nickserv.py (5 tests)
- [x] `test_register` — NS REGISTER
- [x] `test_identify` — LOGIN with correct password
- [x] `test_set_password` — NS SET PASSWORD + verify via LOGIN
- [x] `test_ghost` — NS GHOST kills ghost
- [x] `test_info` — NS INFO

### test_chanserv.py (5 tests)
- [x] `test_register` — CS REGISTER
- [x] `test_op_deop` — CS OP/DEOP
- [x] `test_set_topic` — CS SET TOPIC
- [x] `test_info` — CS INFO
- [x] `test_drop` — CS DROP

### test_memoserv.py (4 tests)
- [x] `test_send_list` — MS SEND + MS LIST
- [x] `test_read` — MS READ
- [x] `test_del` — MS DEL
- [x] `test_login_notification` — memo notification on login

### test_websocket.py (5 tests)
- [x] `test_ws_handshake` — HTTP upgrade → 101
- [x] `test_ws_registration` — NICK/USER over WS
- [x] `test_ws_privmsg` — PRIVMSG over WS
- [x] `test_ws_ping_pong` — WS PING → PONG
- [x] `test_ws_bad_handshake` — bad request rejected

### test_gossip.py (3 tests)
- [x] `test_gossip_link` — 2-node cluster link
- [x] `test_event_propagation` — action on srv1 visible on srv2
- [x] `test_anti_netsplit` — no cascading QUITs

### test_session.py (3 tests)
- [x] `test_token_delivery` — RESUME TOKEN after registration
- [x] `test_resume_success` — RESUME with valid token
- [x] `test_resume_invalid` — RESUME with bad token fails

### test_module_reload.py (3 tests)
- [x] `test_module_list` — MODULE LIST shows modules
- [x] `test_module_reload` — MODULE RELOAD succeeds
- [x] `test_core_no_unload` — core MODULE UNLOAD refused

**Total: 66 automated tests — ALL PASSING**

---

## Manual Test Checklist

These tests require manual verification or special environments:

### TLS / SSL
- [ ] Connect to SSL port (6697) with a real IRC client
- [ ] Verify certificate is presented
- [ ] STARTTLS upgrade on plain port
- [ ] Client cert fingerprint shown in WHOIS (RPL_WHOISCERTFP 276)
- [ ] SASL EXTERNAL with client cert

### Network Stress
- [ ] 100 concurrent connections from single IP
- [ ] Rapid connect/disconnect cycling (flood protection)
- [ ] Large message flood to a channel (throttling)
- [ ] Binary/malformed data injection (crash safety)

### Server Administration
- [ ] DIE command (requires dpass)
- [ ] RESTART command (requires rpass)
- [ ] REHASH (config reload)
- [ ] Remote REHASH
- [ ] OPER with various access flag combinations

### Gossip (Multi-Server)
- [ ] 3+ node mesh formation
- [ ] Channel registration propagation across all nodes
- [ ] Account modification on node A → visible on node B
- [ ] Memo delivery across nodes
- [ ] GVER reconciliation on burst

### OperServ
- [ ] AKILL add/remove
- [ ] SQLINE/SGLINE add/remove
- [ ] GLOBAL message broadcast
- [ ] JUPE a server name
- [ ] MASSDEOP/MASSKICK

### StatServ
- [ ] /SS NETSTATS
- [ ] /SS SERVERS
- [ ] /SS MAP
- [ ] /SS COUNT
- [ ] /SS OPS

### RootServ
- [ ] /RS SET account → SRA
- [ ] /RS REMOVE account
- [ ] /RS LIST
- [ ] /RS OFLAGS account

---

## Regression Checklist

Critical paths that must not break when merging to master:

### Phase 1-2 (Foundation)
- [ ] Meson build completes without errors
- [ ] All core modules load without undefined symbols
- [ ] All extra modules load via autoload

### Phase 3-7 (IRCv3)
- [ ] CAP LS/REQ/END flow completes
- [ ] All caps from EXPECTED_CAPS list present
- [ ] Message tags parsed and forwarded correctly
- [ ] Batch framing (start + content + end)
- [ ] Labeled-response ACK delivered
- [ ] echo-message echoes to sender

### Phase 8 (Services)
- [ ] NickServ REGISTER/IDENTIFY/GHOST all work
- [ ] ChanServ REGISTER/OP/DEOP/DROP all work
- [ ] MemoServ SEND/READ/DEL all work
- [ ] Account data persists in journal
- [ ] Channel reg data persists in journal

### Phase S1-S5 (Gossip + Sessions)
- [ ] Gossip peers connect and sync
- [ ] Event propagation within 2s
- [ ] Session resume with valid token
- [ ] Nick reservation during disconnect window

### Phase 11-12 (Auth + TLS)
- [ ] SASL PLAIN authentication
- [ ] SSL port accepts connections
- [ ] STARTTLS upgrade
- [ ] Cert fingerprint extraction

### Phase 13 (IRCv3 Feature Round)
- [ ] WHOX returns 354 with token
- [ ] MONITOR online/offline notifications
- [ ] Bot mode (+B) flag
- [ ] chghost cap delivers host changes

### CODERS-23-24 (Transport)
- [ ] CHATHISTORY subcommands return batches
- [ ] WebSocket handshake + IRC-over-WS
- [ ] WSS (TLS + WebSocket) if configured

### CODERS-28 (Module Hot Reload)
- [ ] MODULE RELOAD succeeds for extra modules
- [ ] Core modules refuse UNLOAD
- [ ] ABI version checked on reload

---

## Bug Fixes Found During Testing

### ircsprintf infinite recursion (SEGV on startup)
- **Root cause**: `include/ircsprintf.h` had `#define ircsprintf sprintf` macros that
  caused `ircsprintf.c` to define symbols named `sprintf`/`vsprintf`, shadowing libc.
  When `irc_printf` hit an unknown format specifier and called `vsprintf` as fallback,
  it recursed into itself → stack overflow.
- **Fix**: Replaced macros with proper function declarations.

### m_chanserv: undefined symbol `find_channel`
- **Root cause**: Module included `h.h` (which declares `find_channel` as extern function)
  but not `channel.h` (which `#define`s it to `hash_find_channel`).
- **Fix**: Added `#include "channel.h"` to `m_chanserv.c`.

### m_privmsg: undefined symbol `send_msg_error`
- **Root cause**: `send_msg_error()` in `s_user.c` was `static inline`, not visible to modules.
- **Fix**: Removed `static inline` qualifier.

### confadd_gopeer: SEGV on startup with gopeer config blocks
- **Root cause**: `Conf_GossipPeer` struct has `char *` pointer fields (host, name, password),
  but `confadd_gopeer()` used `strncpy(gp->host, ...)` on NULL pointers after memset(0).
  `sizeof(gp->host)` evaluates to `sizeof(char *)` = 8, so `strncpy(NULL, ..., 7)` crashes.
- **Fix**: Replaced `strncpy()` with `DupString()` (matching all other config block parsers).
  Added NULL checks in validation and proper cleanup in error path.

### WebSocket GUID mismatch (handshake validation failure)
- **Root cause**: `src/websocket.c` had wrong Sec-WebSocket-Accept magic GUID
  (`5AB0D183B9EB` instead of RFC 6455 standard `5AB5DC085B6A`).
- **Fix**: Updated `WS_MAGIC_GUID` to the correct RFC 6455 value.
