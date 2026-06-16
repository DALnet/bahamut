# Bahamut modules

Bahamut 3.0 uses a two-tier dynamic module system. Each module is a shared
object (`.so`) loaded by the ircd at runtime.

- **Core modules** live in `modules/core/`. They are auto-loaded at startup by
  scanning that directory — you do **not** list them in `ircd.conf`. They
  provide essential functionality and cannot be unloaded (only hot-reloaded
  with `MODULE RELOAD`).
- **Extra modules** live in `modules/extra/` (or whatever `path` the `modules {}`
  block specifies). They are loaded only when named with an `autoload` (or
  `optload`) token in `ircd.conf`, and may be loaded, unloaded, and reloaded at
  runtime.

## Managing modules at runtime

Modules are reconciled with the config on **rehash**: comment an `autoload`
line out and `REHASH` (or `kill -HUP`) and the module is unloaded; add one and
rehash and it is loaded. Core modules and modules loaded by hand with
`MODULE LOAD` are never touched by a rehash. Other commands:

```
MODULE LIST              # list loaded modules ([core] = cannot be unloaded)
MODULE LOAD   m_name     # load one by name (from the extra path)
MODULE UNLOAD m_name     # unload (refused for core modules)
MODULE RELOAD m_name     # hot-reload (works for core too)
MODULE INFO   m_name     # show version / description / path
```

---

## Core modules (`modules/core/`, auto-loaded)

| Module | Provides |
|--------|----------|
| `m_privmsg` | `PRIVMSG` / `NOTICE` delivery (incl. gossip channel-message bridging). |
| `m_away` | `AWAY` and `USERS`. |
| `m_wallops` | `WALLOPS` and operator broadcasts. |
| `m_who` | `WHO` / WHOX (`%fields` extended WHO). |
| `m_gossip` | Gossip server-to-server protocol (GHELLO/GEVENT/…), the 3.0 multi-uplink mesh. |
| `m_gossip_eventlog` | Hooks that emit gossip events (joins, quits, channel messages, …) onto the mesh. |
| `m_legacy_bridge` | Bridges gossip state to legacy TS5 server links. Remove once the whole network speaks gossip. |

---

## Extra modules (`modules/extra/`, opt-in via `autoload`)

### IRCv3 capabilities — ratified / stable (recommended)

| Module | Cap | Description |
|--------|-----|-------------|
| `m_tagmsg` | `message-tags`, `draft/typing` | Client-only message tags + the `TAGMSG` command. Needed for typing notifications and any tag-only message. |
| `m_server_time` | `server-time` | Adds a `time=` tag to delivered messages (accurate timestamps, history). |
| `m_batch` | `batch` | Groups related lines into a batch (used by chathistory, netjoin, etc.). |
| `m_labeled_response` | `labeled-response` | Correlates a client's command with the server's response via a `label` tag. |
| `m_msgid` | `msgid` (+ `draft/message-ids`) | Tags each message with a unique id (replies, history, reactions). |
| `m_echo_message` | `echo-message` | Echoes the sender's own `PRIVMSG`/`NOTICE` back to them. |
| `m_account_notify` | `account-notify` | Notifies subscribers when a user logs in/out of an account. |
| `m_account_tag` | `account-tag` | Adds an `account=` tag to messages from logged-in users. |
| `m_away_notify` | `away-notify` | Pushes away/back state changes to channel members. |
| `m_chghost` | `chghost` | Notifies clients of a user's user@host change instead of a quit/rejoin. |
| `m_extended_join` | `extended-join` | Adds account name and real name to `JOIN`. |
| `m_invite_notify` | `invite-notify` | Notifies channel members when someone is invited. |
| `m_setname` | `setname` | The `SETNAME` command — change real name without reconnecting. |
| `m_userhost_in_names` | `userhost-in-names` | Full `nick!user@host` in `NAMES` replies. |
| `m_monitor` | — | The `MONITOR` command (efficient server-side notify list). |

> `m_starttls` (`tls`) is a ratified cap but **off by default** — see "Optional / situational" below.

### Traditional commands

| Module | Provides |
|--------|----------|
| `m_silence` | `SILENCE` — per-user server-side ignore list. |
| `m_watch` | `WATCH` — notify list for nick online/offline. |
| `m_dcc` | `DCCALLOW` — per-user DCC allow list. |
| `m_put` | Rejects HTTP `PUT`/proxy probes that hit the client port. |
| `m_check` | `CHECK` — oper diagnostic for a nick/channel/server. |
| `m_rwho` | `RWHO` — regex/extended WHO for opers. |

### IRCv3 draft extensions (not finalised — off by default)

These work, but the specs are still `draft/` and may change. Enable per taste.

| Module | Cap | Description |
|--------|-----|-------------|
| `m_chathistory` | `draft/chathistory` | `CHATHISTORY` — replay recent channel/PM messages from a server-side ring buffer. |
| `m_tls_tag` | `draft/tls` | Marks TLS-connected users with a `draft/tls` tag (e.g. in WHOIS). Indication only; does not offer any TLS upgrade. |
| `m_session` | `draft/resume-0.5` | Persistent sessions / connection `RESUME` after a disconnect. |
| `m_bot_mode` | `draft/bot` | Bot user mode (`+B`) and the `draft/bot` tag marking bot accounts. |

### Optional / situational (off by default)

| Module | Cap | Provides |
|--------|-----|----------|
| `m_starttls` | `tls` | `STARTTLS` — opportunistic TLS upgrade of a **plaintext** connection. Gated only on the server having a certificate, so it is offered on non-`S` ports by design. **Off by default**: enable it if you want clients to be able to upgrade plaintext connections to TLS; leave it off to keep TLS on dedicated `S`-flagged ports only. |
| `m_webirc` | — | `WEBIRC` — lets a trusted web gateway pass the real client IP/host. Load only if you actually run such a gateway, and pair it with a matching `allow {}` for the gateway host. |
| `m_bot_mode` | `draft/bot` | See draft section — also fine to leave off unless your network wants a bot flag. |

---

See `doc/reference.conf` (the `modules {}` block) for a ready-to-edit template
with sensible defaults: stable caps and traditional commands enabled, draft
extensions and gateway modules commented out.
