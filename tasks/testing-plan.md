# Bahamut Gossip Protocol — Testing Plan

## 1. Test Infrastructure

### 1.1 Minimum setup

You need at least two Bahamut instances to test Phase S2 (gossip multi-uplink)
and at least two to test Phase S4 (persistent sessions across servers).

```
Test topology (Phase S2 minimum):

  irc1 (server_id=1, port=6667) <——gopeer——> irc2 (server_id=2, port=6668)

Test topology (cross-server resume, Phase S4):

  irc1 <——gopeer——> irc2 <——gopeer——> irc3
```

### 1.2 Sample test configuration

**irc1.conf**
```
global {
    name = "irc1.test";
    info = "Test server 1";
};

port { port = 6667; };

gossip {
    fanout      = 3;
    sync_window = 30;
};

gopeer {
    host      = "127.0.0.1";
    port      = 6668;
    name      = "irc2.test";
    server_id = 2;
};
```

**irc2.conf**  (mirror: server_id=2, gopeer points back at port 6667)

### 1.3 Starting the servers

```sh
# Server 1
./build/src/ircd -f /path/to/irc1.conf -x 9   # debug level 9

# Server 2
./build/src/ircd -f /path/to/irc2.conf -x 9
```

Connect with any IRC client (netcat works fine for manual protocol testing):
```sh
nc 127.0.0.1 6667
NICK test1
USER test 0 * :Test User
```

---

## 2. Phase S2 — Gossip Multi-Uplink Testing

### 2.1 GHELLO / GSYNCED handshake

**Expected in server logs when gossip link comes up:**
```
Gossip peer irc2.test (id=2) established
Gossip peer irc2.test is syncing...
Gossip peer irc2.test sync complete
```

**Manual verification (netcat to server port, or add debug logging):**

In `ms_ghello` add a `sendto_realops` call (already present), then watch:
```
GHELLO irc1.test 1 1
```
You should see the reciprocal GHELLO back from irc1.

### 2.2 Event propagation (join/part/nick)

1. Connect two clients: client A to irc1, client B to irc2
2. Have client A join `#test`
3. Verify: `EVT_CHAN_JOIN` event emitted on irc1 (check debug output or
   add a debug hook to `m_gossip_eventlog.c`)
4. Verify: irc2 receives `GEVENT 7 :nick #test 0 <ts>` (EVT_CHAN_JOIN=7)
5. Have client B also `/join #test` and send a PRIVMSG — verify client A
   receives it only once (dedup working)

**Dedup check:**
- Temporarily set fanout=2 and use 3 servers
- Send one event from server A
- Verify it arrives exactly once at server C (which receives it from both
  B and from A directly)
- Check `g_dedup_table.count` via a debug stat (add a `/stats G` handler
  in a test module, or simply grep the count in a debug build)

### 2.3 Anti-netsplit — dropped link does NOT cascade QUITs

This is the core correctness test for Phase S2.

1. Connect client A to irc1, join `#test`
2. Establish gossip link irc1 ↔ irc2 (verify GSYNCED in logs)
3. Kill the gossip link (kill irc2 process or use `iptables -A OUTPUT -p tcp --dport 6668 -j DROP`)
4. **Expected behaviour on irc1:**
   - Log message: "Gossip peer irc2.test disconnected"
   - `EVT_SERVER_SPLIT` event emitted
   - Client A is **NOT** sent a QUIT message
   - Client A **remains** in `#test`
5. Restore the link — verify GSYNCED exchange and burst replay

**Negative test (legacy server — make sure cascade still works):**
- Connect a legacy server via C/N lines
- Kill the legacy link
- Verify the old cascading QUIT behaviour fires for users on that server

### 2.4 Burst synchronisation (catch-up)

1. Start irc1 alone; have 5 users join `#gossip-test`
2. Start irc2 and let the gopeer link come up
3. Verify in irc2 logs: GSYNCING received, events replayed (count matches
   events in irc1's event log), GSYNCED sent
4. Connect a client to irc2 and verify it can see users from irc1 in
   `#gossip-test` (requires Phase S3 bridge for IRC visibility, but the
   event log should be populated on irc2)

### 2.5 Fanout load distribution

- Use 5 servers in a partial mesh (each connected to 2 others)
- Set `fanout = 2`
- Inject 100 events from server 1
- Verify all 5 servers receive each event exactly once
- Check server logs for duplicate GEVENT messages (there should be none
  after dedup; dedup discards them silently)

### 2.6 GPING / GPONG keepalive

```sh
# Manually send GPING on an established gossip link
# (from the gopeer side):
:irc1.test GPING :test-nonce-1234
```
Expected: irc2 replies `GPONG :test-nonce-1234` and updates `last_ping`.

---

## 3. Phase S3 — Legacy Bridge Testing

### 3.1 Gossip user visible to legacy server

1. Connect legacy UnrealIRCd (or old Bahamut) to the bridge server via C/N
2. User on gossip mesh joins `#test`
3. Verify: legacy server receives synthesised `NICK` introduction + `SJOIN`
4. User on legacy server can send PRIVMSG to gossip user and vice versa

### 3.2 Legacy user visible on gossip mesh

1. User connects to legacy server
2. Verify: existing `CHOOK_POSTREGISTER` hook emits `EVT_USER_JOIN` event
3. Gossip mesh servers have the user in their event log

### 3.3 Bridge disconnect

1. Kill the bridge server
2. Verify: gossip-only servers do NOT cascade-QUIT gossip users
3. Verify: legacy server side does cascade-QUIT via spanning tree (expected
   legacy behaviour preserved)

---

## 4. Phase S4 — Persistent Sessions Testing

### Implementation notes (Phase S4 as built)

- Session token is sent as a **NOTICE** immediately before the connection
  closes (best-effort; may not be received if TCP is already shutting down).
  A future CAP-based delivery mechanism is planned for reliability.
- `RESUME` is a **CLIENT** command (post-registration). The client connects
  with any nick, completes registration, then sends `RESUME <token>`.
- Channels are **not** auto-rejoined. The server sends a `NOTICE` listing
  the channels from the session; the client rejoins manually.
- Message queuing applies to **local** sessions only. Cross-server RESUME
  restores identity (nick, umode, away) but not pending messages.
- The session slab holds up to **512** concurrent sessions. Full slab logs
  a `sendto_realops` warning and the session is not created.

### 4.1 Session creation on disconnect

1. Load `m_session` module (it is in `modules/extra/`; add to autoload or
   `MODULE LOAD m_session` at runtime)
2. Client connects, registers (nick + user)
3. Client sends QUIT
4. **Expected**: before the connection closes, the client receives:
   ```
   :irc1.test NOTICE mynick :Session token: a3f7b2c1...  (32 hex chars)
   ```
5. Run 10 connections concurrently — verify all tokens are distinct

### 4.2 Nick reservation

1. Client A connects, registers as `foo`, then disconnects
2. Within SESSION_TIMEOUT (5 min), client B tries `/nick foo`
3. **Expected**: `ERR_NICKNAMEINUSE` — nick held by session
4. After SESSION_TIMEOUT elapses, try again — should succeed

### 4.3 Message queuing during session

1. Client A connects, registers as `foo`, then disconnects
2. Client B sends `PRIVMSG foo :hello` (to the session-held nick)
3. **Expected**: no ERR_NOSUCHNICK — message silently queued
4. Client A reconnects, registers as `bar`, sends `RESUME <token>`
5. **Expected in order**:
   - Nick changes from `bar` to `foo`
   - `NOTICE :--- 1 message(s) received while away ---`
   - `:clientB!... PRIVMSG foo :hello` replayed

### 4.4 RESUME — same server

```
(Session 1)
NICK mynick
USER test 0 * :Test
AWAY :brb
JOIN #test
QUIT               ← server sends NOTICE with token

(Session 2 — reconnect within 5 min)
NICK mynick2
USER test2 0 * :Resumed
RESUME <token>
```
**Expected**:
- Nick changes from `mynick2` to `mynick`
- Away restored (`306` numeric)
- `NOTICE :Channels from your session: #test (rejoin manually)`
- `NOTICE :Session resumed.`

### 4.5 RESUME — different server (cross-server session)

1. Load `m_session` on both irc1 and irc2
2. Client connects to irc1, registers as `foo`, disconnects
3. Verify: irc2 received a `GEVENT 20` (`EVT_SESSION_CREATE`) in its logs
4. Client connects to irc2, registers as `bar`, sends `RESUME <token>`
5. **Expected**: nick changes to `foo`, umode/away restored; channels listed
   (but no message replay — cross-server messages not queued in Phase S4)
6. Verify: `GEVENT 21` (`EVT_SESSION_DESTROY`) propagated back to irc1;
   irc1's session table no longer holds the nick

### 4.6 Session expiry

1. Client connects, gets token, disconnects
2. Wait more than `SESSION_TIMEOUT` (300 s) without resuming
3. `CHOOK_10SEC` fires → `session_expire_check()` frees the slab slot
4. Verify: another client can now take the previously held nick
5. `EVT_SESSION_DESTROY` event propagated (expiry also calls emit_event)

### 4.7 Token is one-time use

1. Client A gets token, disconnects
2. Client B connects, registers, sends `RESUME <token>` — **succeeds**
3. Client C connects, registers, sends `RESUME <token>` — **expected**:
   `NOTICE :No session found for that key.`

---

## 5. Automated Testing Ideas

### 5.1 ircdtest script (shell / Python)

A simple Python script using `socket` can drive automated protocol tests:

```python
# Basic pattern:
import socket, time

def connect(host, port, nick, user):
    s = socket.socket()
    s.connect((host, port))
    s.sendall(f"NICK {nick}\r\nUSER {user} 0 * :Test\r\n".encode())
    return s

def read_until(s, pattern, timeout=5):
    s.settimeout(timeout)
    buf = b""
    while pattern.encode() not in buf:
        buf += s.recv(4096)
    return buf.decode()

# Test: anti-netsplit
c = connect("127.0.0.1", 6667, "testuser", "testuser")
read_until(c, "001")   # welcome
# ... etc.
```

Key automated test cases:
- `test_ghello_exchange` — verify both servers log GSYNCED
- `test_anti_netsplit` — kill link, confirm no QUIT for user
- `test_event_dedup` — inject duplicate GEVENT, confirm single delivery
- `test_session_resume_same_server`
- `test_session_resume_cross_server`
- `test_session_expiry`

### 5.2 Valgrind / ASan checks

```sh
# Build with address sanitizer
meson setup build-asan -Dhookmodules=true \
    -Db_sanitize=address -Db_lundef=false

ninja -C build-asan

# Run under valgrind
valgrind --leak-check=full --track-origins=yes \
    ./build-asan/src/ircd -f irc1.conf -x 1
```

Focus on:
- `gossip_dedup.c` — 65536-slot table, eviction path
- `gossip.c` — rank-permuted fanout loop
- `session.c` (Phase S4) — slab allocator

### 5.3 Fuzz testing the GEVENT parser

```sh
# gossip_parse_event() receives attacker-controlled payload strings
# Fuzz it with AFL or libFuzzer:
#
# Write a fuzz harness:
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    NetworkEvent ev;
    EventClock   clk = {0};
    char buf[1025];
    size_t n = size < 1024 ? size : 1024;
    memcpy(buf, data, n); buf[n] = '\0';
    gossip_parse_event(&ev, EVT_USER_JOIN, buf, 1, 1, &clk);
    return 0;
}
```

---

## 6. Regression Checklist (before each phase merge)

- [ ] `ninja -C build` produces 0 errors, 0 new warnings
- [ ] Two-server gossip link comes up cleanly (GHELLO/GSYNCED in logs)
- [ ] User join on server A appears in event log on server B
- [ ] Kill gossip link — no cascading QUITs on either server
- [ ] Re-establish gossip link — burst sync replays missed events
- [ ] Legacy C/N link still works normally (spanning tree behaviour unchanged)
- [ ] IRC client connect / register / join / part / quit all work as before
- [ ] PRIVMSG, NOTICE, TOPIC, MODE all work as before
- [ ] No double-delivery of events (dedup table functioning)
- [ ] `m_session` loads cleanly; `MODULE LIST` shows it
- [ ] Client disconnect produces `NOTICE :Session token: <32 hex chars>`
- [ ] Another client cannot take the session-held nick (ERR_NICKNAMEINUSE)
- [ ] PRIVMSG to session-held nick is silently queued (no ERR_NOSUCHNICK)
- [ ] `RESUME <valid-token>` restores nick, umode, away, lists channels, replays messages
- [ ] `RESUME <invalid-token>` returns `NOTICE :No session found for that key.`
- [ ] After SESSION_TIMEOUT, session expires and nick becomes available
