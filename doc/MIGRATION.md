# Migrating from Bahamut 2.x to 3.0

This guide covers everything an existing Bahamut operator needs to know when
upgrading to 3.0.

---

## Build System: autotools → Meson

Bahamut 3.0 replaces `./configure && make` with Meson + Ninja.

| Old (2.x) | New (3.0) |
|------------|-----------|
| `./configure --prefix=/usr/local/ircd` | `meson setup build --prefix=/usr/local/ircd` |
| `make` | `ninja -C build` |
| `make install` | `ninja -C build install` |
| `make clean` | `ninja -C build -t clean` |

The `configure` script and all Makefiles have been removed.  See `INSTALL` for
dependency installation on various platforms.

---

## Configuration Changes

### New config blocks

| Block | Purpose |
|-------|---------|
| `ssl {}` | TLS certificate and key paths |
| `gossip {}` | Gossip protocol tuning (fanout, sync_window) |
| `gopeer {}` | Gossip peer definitions (replaces connect{} for new deployments) |

### Port block: new flags

| Flag | Meaning |
|------|---------|
| `S` | Accept TLS/SSL connections (unchanged) |
| `W` | Accept WebSocket connections (new) |
| `WS` | WebSocket over TLS (new) |
| `n` | Skip DNS lookups (unchanged) |
| `i` | Skip ident lookups (unchanged) |

### Connect block: removed `E` flag

The `E` flag (Diffie-Hellman key exchange / RC4 encryption) has been removed.
Use the `S` flag (TLS) instead for encrypted server links.

### Options block

The `services_name` and `stats_name` tokens configure which server names are
recognized as U:lined services/stats servers.  Set these to match your external
services package (e.g. DALnet services, Anope, Atheme).

### Super block

The `super {}` block grants U:line privileges to external services servers,
allowing them to issue network management commands (SVSNICK, AKILL, etc.).

### Modules block: enhanced

The module system now supports:
- `optload` token (like `autoload` but silently skips missing modules)
- Core modules auto-loaded from `<dpath>/modules/core/` — no config needed
- Runtime management: `MODULE LOAD/UNLOAD/RELOAD/LIST/INFO`

---

## Server Linking: TS5 → Gossip

### Old model (TS5)

Bahamut 2.x uses hub/leaf topology with `connect {}` blocks and the TS5
protocol for state synchronization.

### New model (Gossip)

Bahamut 3.0 introduces a gossip-based protocol where servers form a mesh
cluster.  Each event (nick change, channel join, etc.) is assigned a unique ID and
replicated to peers.

**Advantages:**
- No single point of failure (mesh topology vs. hub/leaf)
- No cascading netsplits — gossip peers disconnect cleanly
- Automatic reconnection and state resynchronization
- Simpler configuration (no hub/leaf roles)

### Configuration

Replace `connect {}` blocks with `gossip {}` + `gopeer {}`:

```
# Old (2.x)
connect {
    name    hub.example.com;
    host    172.16.4.2;
    port    7325;
    apasswd secret;
    cpasswd secret;
    flags   HE;
    class   hub;
};

# New (3.0)
gossip {
    sync_window 30;   # optional; fanout defaults to 0 = flood all peers
};

gopeer {
    host      172.16.4.2;
    port      7325;
    name      hub.example.com;
    passwd    secret;
    tls;
};
```

A server's gossip identity **is** its name — there is no `server_id` to set.
Names are already unique on IRC, so just give every server a unique name
(which they already have) and list each peer in a `gopeer {}` block.  The
name is what travels on the wire; internally each server keeps a small
local index table (so identities can never collide).

### Authentication & TLS (required)

Gossip links are **authenticated** and require **TLS**.  This is a breaking
change from earlier 3.0 previews where the mesh was open:

- Every `gopeer {}` block needs a `passwd` — the shared link secret.  Put the
  **same secret** in the matching block on **both ends** of a link.
- The link must be TLS (`tls;` flag + an `ssl {}` block).  The secret is only
  sent over TLS, and an inbound non-TLS handshake is rejected.
- An inbound peer that does not match a configured `gopeer {}` block with the
  correct secret, over TLS, is **rejected** — this is what prevents an
  arbitrary host from joining the mesh and reading or forging network state.
- `host` is optional for an **accept-only** block (a node that is always
  connected *to* and never dials out): give it just a `name` + `passwd`.
- The dialing side must store the secret in cleartext (it has to send it); the
  accepting side may store it crypted at rest when `options { crypt_oper_pass }`
  is enabled, exactly like oper passwords.

Because this changes the wire handshake, a 3.0 node with auth will not link to
an older auth-less preview — upgrade and reconfigure both ends together.

> Defense-in-depth still to come: mutual proof (the dialer authenticating the
> listener) and pinning the peer's TLS certificate fingerprint.  Until then,
> keep the S2S port firewalled to known peers.

### Backwards compatibility

Legacy `connect {}` blocks still work for linking to Bahamut 2.x servers.
The `m_legacy_bridge` core module translates between TS5 and gossip events.
This allows a mixed 2.x/3.0 network during migration.

### Monitoring gossip peers

`/STATS l` lists gossip-peer links alongside any TS5 server links — one
line per peer, with that peer's own counters:

```
Name SendQ SendM SendBytes RcveM RcveBytes :OpenSince Idle <flag>
```

`SendM`/`RcveM` are message counts and `SendBytes`/`RcveBytes` are KB; the
counters are per connection, so with several peers you see how much each
one has exchanged.  The `<flag>` column is:

- `gossip/synced/rtt=<n>ms` — a gossip peer that has finished its burst,
  with the live GPING/GPONG round-trip time;
- `gossip/syncing/...` — still bursting (not yet caught up);
- `rtt=?` — connected but no GPING reply measured yet;
- `TS` / `NoTS` — a legacy TS5 server link.

Example (a hub with one gossip peer and one TS5 leaf):

```
gossip.example.net      0 35 2 35 2 :127 0 gossip/synced/rtt=160ms
legacy.example.net      0 16 0 14 0 :14 10 TS
```

---

## TLS

### New ssl {} block

TLS configuration now lives in a dedicated config block:

```
ssl {
    certificate ircd.crt;
    key         ircd.key;
};
```

### STARTTLS

Clients can upgrade plain connections to TLS using the STARTTLS command
(requires `m_starttls` module).  The `tls` IRCv3 capability is advertised
when STARTTLS is available.

### Client certificate fingerprints

The server automatically extracts SHA-256 fingerprints from client TLS
certificates.  Fingerprints are visible in WHOIS (numeric 276) and can be
used by external services for certificate-based authentication.

### Gossip peer TLS

Outbound gossip connections can be encrypted by adding the `tls` flag to a
`gopeer {}` block.

---

## Module System

### MAPI v2/v3

Modules use the MAPI v2 command table format with v3 extensions for
hot-reload (serialize/deserialize callbacks, ABI versioning).

### Core vs. extra modules

| Type | Location | Behavior |
|------|----------|----------|
| Core | `modules/core/` | Auto-loaded at startup, cannot be unloaded |
| Extra | `modules/extra/` | Loaded via `autoload` in config, fully unloadable |

### Core modules (auto-loaded)

`m_privmsg`, `m_away`, `m_wallops`, `m_who`, `m_gossip`, `m_legacy_bridge`

### Runtime management

```
/MODULE LIST              — List all loaded modules (core marked [core])
/MODULE LOAD <name>       — Load an extra module
/MODULE UNLOAD <name>     — Unload an extra module
/MODULE RELOAD <name>     — Hot-reload (preserves state, no client drop)
/MODULE INFO <name>       — Show version, ABI version, capabilities
```

`MODULE RELOAD` requires server administrator status (umode +A).

---

## IRCv3 Capabilities

All IRCv3 features are implemented as loadable modules.  Enable them by adding
`autoload` lines to the `modules {}` block.

| Capability | Module | Notes |
|------------|--------|-------|
| `account-notify` | m_account_notify | Notifies channel members of login/logout |
| `account-tag` | m_account_tag | Adds account name to message tags |
| `away-notify` | m_away_notify | Real-time AWAY status in channels |
| `batch` | m_batch | Batched message delivery |
| `cap-notify` | built-in | Dynamic capability change notification |
| `chghost` | m_chghost | Real-time host change notification |
| `draft/bot` | m_bot_mode | Bot user mode (+B) and tag |
| `draft/chathistory` | m_chathistory | Channel message history playback |
| `draft/resume-0.5` | m_session | Persistent session resumption |
| `echo-message` | m_echo_message | Echo sent messages back to sender |
| `extended-join` | m_extended_join | Account info in JOIN messages |
| `invite-notify` | m_invite_notify | Channel invite notifications |
| `labeled-response` | m_labeled_response | Request-response correlation |
| `message-tags` | m_tagmsg | IRCv3 message tags + TAGMSG command |
| `monitor` | m_monitor | Online status monitoring (MONITOR command) |
| `msgid` | m_msgid | Unique message identifiers |
| `multi-prefix` | built-in | Multiple status prefixes in NAMES/WHO |
| `server-time` | m_server_time | Server-side timestamps on messages |
| `setname` | m_setname | Change realname without reconnecting |
| `tls` | m_starttls | STARTTLS + TLS connection tag |
| `userhost-in-names` | m_userhost_in_names | Full user@host in NAMES reply |

---

## WebSocket Transport

Bahamut 3.0 supports WebSocket connections for browser-based IRC clients.

### Configuration

Add a port with the `W` flag:

```
port { port 8080; flags W; };       # ws://
port { port 8443; flags WS; };      # wss:// (requires ssl {} block)
```

### Protocol

Clients connect via standard HTTP WebSocket upgrade, then speak IRC over
text frames.  The server handles RFC 6455 masking, PING/PONG, and CLOSE.
Server-to-client frames do not include `\r\n` line terminators.

### Client compatibility

Any WebSocket-capable IRC client (e.g. Kiwi IRC, The Lounge, gamja) can
connect directly without a WebSocket proxy.
