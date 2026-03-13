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
| `sra {}` | Root server administrator account bootstrap |

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

### Options block: native services

The `services_name` and `stats_name` tokens are no longer needed for most
deployments, since Bahamut 3.0 includes built-in services.  Only set them if
you use external services packages (Anope, Atheme, etc.).

### Super block: external services only

The `super {}` block is only needed when linking external services servers.
Built-in services do not require U-line privileges.

### Modules block: enhanced

The module system now supports:
- `optload` token (like `autoload` but silently skips missing modules)
- Core modules auto-loaded from `<dpath>/modules/core/` — no config needed
- Runtime management: `MODULE LOAD/UNLOAD/RELOAD/LIST/INFO`

---

## Native Services

Bahamut 3.0 replaces external services (Anope, Atheme, etc.) with built-in
pseudoclients.  Account and channel data is stored in journal files on disk
and replicated across the cluster via the gossip protocol.

### Service pseudoclients

| Service | Alias | Purpose |
|---------|-------|---------|
| NickServ | `/NS` | Account registration, login, nick enforcement, cert fingerprints |
| ChanServ | `/CS` | Channel registration, access lists, mode locks |
| MemoServ | `/MS` | User-to-user and channel memos |
| RootServ | `/RS` | Root administrator management |
| OperServ | `/OS` | GLOBAL, JUPE, MASSDEOP, MASSKICK, SILENCE |
| StatServ | `/SS` | Network stats, server map, user/channel info |

### Data storage

Services data is stored as append-only journal files in the server's working
directory:

| File | Contents |
|------|----------|
| `accounts.journal` | NickServ accounts (passwords, emails, flags, certfps) |
| `channels.journal` | ChanServ registrations (access lists, settings) |
| `memos.journal` | MemoServ memos |

Journals are human-readable text.  They are compacted automatically when the
ratio of mutations to live records exceeds a threshold.

### Migration from external services

1. Remove `super {}`, services `connect {}`, and services `class {}` blocks
2. Remove `services_name` and `stats_name` from `options {}`
3. Users will need to re-register their accounts with `/NS REGISTER`
4. Channel registrations will need to be re-created with `/CS REGISTER`
5. Add `sra {}` blocks for root administrator accounts

There is no automated data import from Anope/Atheme databases.  For large
networks, consider running both systems in parallel during transition.

---

## Server Linking: TS5 → Gossip

### Old model (TS5)

Bahamut 2.x uses hub/leaf topology with `connect {}` blocks and the TS5
protocol for state synchronization.

### New model (Gossip)

Bahamut 3.0 introduces a gossip-based protocol where servers form a mesh
cluster.  Each event (nick change, channel join, services update, etc.) is
assigned a unique ID and replicated to peers.

**Advantages:**
- No single point of failure (mesh topology vs. hub/leaf)
- Automatic reconnection and state resynchronization
- Per-record versioning prevents conflicts in services data
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
    fanout      3;
    sync_window 30;
};

gopeer {
    host      172.16.4.2;
    port      7325;
    name      hub.example.com;
    server_id 1;
    passwd    secret;
    tls;
};
```

Each server in the cluster needs a unique `server_id` (0-255).

### Backwards compatibility

Legacy `connect {}` blocks still work for linking to Bahamut 2.x servers.
The `m_legacy_bridge` core module translates between TS5 and gossip events.
This allows a mixed 2.x/3.0 network during migration.

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
certificates.  Users can associate fingerprints with their NickServ account:

```
/NS SET CERTFP ADD
```

### SASL EXTERNAL

Clients with a TLS certificate whose fingerprint matches a registered account
can authenticate without a password using `SASL EXTERNAL`.

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

`m_privmsg`, `m_away`, `m_wallops`, `m_who`, `m_gossip`, `m_legacy_bridge`,
`m_nickserv`, `m_chanserv`, `m_memoserv`, `m_rootserv`, `m_operserv`,
`m_statserv`

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
| `sasl` | m_sasl | SASL PLAIN and EXTERNAL authentication |
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
