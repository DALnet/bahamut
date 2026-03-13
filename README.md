# Bahamut IRC Server

Bahamut is a high-performance IRC server originally developed for the DALnet network.
Version 3.0 is a ground-up modernization: IRCv3 capabilities, gossip-based server
clustering, WebSocket transport, TLS everywhere, and a hot-reloadable module system.
Services (NickServ, ChanServ, etc.) are provided by external U:lined services packages.

---

## Features

### IRCv3 Capabilities
Extensive IRCv3 support via loadable modules:

| Capability | Module |
|------------|--------|
| `account-notify` | m_account_notify |
| `account-tag` | m_account_tag |
| `away-notify` | m_away_notify |
| `batch` | m_batch |
| `cap-notify` | built-in |
| `chghost` | m_chghost |
| `draft/bot` | m_bot_mode |
| `draft/chathistory` | m_chathistory |
| `draft/resume-0.5` | m_session |
| `echo-message` | m_echo_message |
| `extended-join` | m_extended_join |
| `invite-notify` | m_invite_notify |
| `labeled-response` | m_labeled_response |
| `message-tags` | m_tagmsg |
| `monitor` | m_monitor |
| `msgid` | m_msgid |
| `multi-prefix` | built-in |
| `server-time` | m_server_time |
| `setname` | m_setname |
| `tls` | m_starttls |
| `userhost-in-names` | m_userhost_in_names |

### Gossip Protocol
A modern event-based server-to-server protocol replacing traditional TS5 hub/leaf linking.
Servers form a mesh cluster with automatic reconnection and event fan-out.  No cascading
netsplits — gossip peers disconnect cleanly without dropping users.

### WebSocket Transport
RFC 6455 WebSocket support for browser IRC clients.  Configure a port with the `W` flag
(or `WS` for WebSocket over TLS).  No proxy required.

### TLS
Full TLS support: client connections (port flag `S`), STARTTLS upgrade, client certificate
fingerprints, and encrypted gossip peer links.

### Module System
MAPI v2/v3 module architecture with hot-reload capability.  Core modules (PRIVMSG, WHO,
gossip) are auto-loaded and cannot be unloaded.  Extra modules can be loaded, unloaded,
and reloaded at runtime without dropping clients.

### Persistent Sessions
Clients can resume disconnected sessions within a configurable window, preserving channel
membership, nick, and receiving queued messages (via the `draft/resume-0.5` capability).

---

## Building

### Dependencies

**Debian / Ubuntu**
```sh
sudo apt-get install build-essential meson ninja-build pkg-config \
    libssl-dev zlib1g-dev
```

**Fedora / RHEL**
```sh
sudo dnf install gcc meson ninja-build pkg-config openssl-devel zlib-devel
```

**FreeBSD / macOS (Homebrew)**
```sh
# FreeBSD
pkg install meson ninja pkgconf openssl

# macOS
brew install meson ninja pkg-config openssl
```

### Quick build

```sh
meson setup build
ninja -C build
```

The compiled binary is at `build/src/ircd`.

### Build options

| Option | Default | Description |
|--------|---------|-------------|
| `socketengine` | `auto` | I/O event backend: `auto`, `epoll`, `kqueue`, `poll`, `select`, `devpoll` |
| `maxconnections` | `32768` | Maximum simultaneous connections |
| `hookmodules` | `true` | Enable loadable hook modules |

Pass options with `-D`:

```sh
meson setup build -Dsocketengine=epoll -Dmaxconnections=65536
ninja -C build
```

### Install

```sh
meson setup build --prefix=/usr/local/ircd
ninja -C build
ninja -C build install
```

---

## Configuration

Copy the template config and edit it:

```sh
cp doc/template.conf /usr/local/ircd/ircd.conf
$EDITOR /usr/local/ircd/ircd.conf
```

See `doc/reference.conf` for detailed documentation of every config block.

If upgrading from Bahamut 2.x, see `doc/MIGRATION.md` for a complete migration guide.

### Generate TLS certificates

```sh
openssl req -x509 -newkey rsa:2048 -keyout ircd.key \
    -out ircd.crt -days 365 -nodes -subj "/CN=irc.example.com"
```

### Run

```sh
/usr/local/ircd/ircd
# or with an explicit config path:
/usr/local/ircd/ircd -f /path/to/ircd.conf
```

---

## Testing

The integration test suite uses pytest with a custom harness that spawns real ircd processes.

```sh
# Install pytest
pip install pytest

# Run all tests (51 tests across 11 suites)
python3 -m pytest tests/ -v

# Run a specific suite
python3 -m pytest tests/suites/test_gossip.py -v

# Run a single test
python3 -m pytest tests/suites/test_gossip.py::TestGossip::test_gossip_link -v
```

Test suites cover: registration, messaging, channels, operator commands, gossip
clustering, TLS, WebSocket, IRCv3 capabilities, MONITOR, chathistory, sessions,
and module hot-reload.

---

## Architecture

| Subsystem | Key files | Description |
|-----------|-----------|-------------|
| Core | `src/ircd.c`, `src/s_bsd.c` | Startup, event loop, socket I/O |
| Parsing | `src/parse.c`, `src/msgbuf.c` | Message parsing, IRCv3 tags, command dispatch |
| Channels | `src/channel.c` | Channel state, membership, modes |
| Users | `src/s_user.c` | Client registration, user modes |
| Sending | `src/send.c` | Outbound message queuing and delivery |
| Server links | `src/s_serv.c` | Legacy TS5 server-to-server protocol |
| Gossip | `src/s_gopeer.c`, `src/gossip_event.c` | Gossip protocol, event replication |
| Modules | `src/modules.c` | MAPI v2/v3 module loader, hot-reload |
| CAP system | `src/cap.c`, `src/m_cap.c` | IRCv3 capability negotiation |
| Services | `src/m_services.c` | U:line alias dispatch to external services |
| TLS | `src/ssl.c` | OpenSSL integration, cert fingerprints |
| WebSocket | `src/websocket.c` | RFC 6455 frame parser and writer |
| Config | `src/s_conf.c`, `src/confparse.c` | Configuration file parser |

---

## Reporting Bugs

Security issues: coders@dal.net

All other bugs: https://github.com/DALnet/bahamut/issues
