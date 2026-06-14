"""Shared utilities for topology test scenarios."""

import os
import sys
import time
import itertools

# Allow importing from the project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tests.harness.irc_client import IRCClient
from tests.harness.ports import allocate_ports


_nick_counter = itertools.count(1)


def unique_nick(prefix="u"):
    return f"{prefix}{next(_nick_counter)}"


def find_build_dir():
    """Locate the meson build directory."""
    root = os.path.join(os.path.dirname(__file__), "..")
    build = os.path.join(root, "build")
    if os.path.isfile(os.path.join(build, "src", "ircd")):
        return os.path.abspath(build)
    raise FileNotFoundError(
        "Build directory not found. Run: meson setup build && ninja -C build"
    )


def make_client(port, nick=None):
    """Create, connect, and register an IRC client."""
    nick = nick or unique_nick()
    c = IRCClient(port=port)
    c.connect()
    c.register(nick)
    return c, nick


def wait_for_mesh(seconds=5):
    """Wait for gossip/TS5 mesh to form."""
    print(f"  Waiting {seconds}s for mesh formation...")
    time.sleep(seconds)


def verify_lusers(client, nick, expected_min, label=""):
    """Send LUSERS and check global user count >= expected_min."""
    client.send("LUSERS")
    lines = client.collect_lines(duration=1.0)
    for line in lines:
        # 251 :There are N users and M invisible on X servers
        if " 251 " in line:
            parts = line.split()
            for i, p in enumerate(parts):
                if p == "are":
                    try:
                        visible = int(parts[i + 1])
                        # "and M invisible" — M is parts[i+3]
                        invisible = int(parts[i + 3])
                        total = visible + invisible
                        if total >= expected_min:
                            return True, total
                        return False, total
                    except (IndexError, ValueError):
                        pass
    return False, 0


def verify_privmsg(sender, sender_nick, receiver, receiver_nick):
    """Send a PRIVMSG from sender to receiver and verify delivery."""
    msg = f"hello-{time.monotonic()}"
    sender.send(f"PRIVMSG {receiver_nick} :{msg}")
    try:
        line = receiver.wait_for(msg, timeout=5)
        return True
    except TimeoutError:
        return False


def verify_channel_messaging(clients_and_nicks, channel="#test"):
    """All clients join a channel, one sends a message, others receive it."""
    for c, nick in clients_and_nicks:
        c.send(f"JOIN {channel}")
        c.wait_for("JOIN", timeout=5)

    # Let joins propagate
    time.sleep(1)
    # Drain any pending lines
    for c, _ in clients_and_nicks:
        c.collect_lines(duration=0.3)

    sender, sender_nick = clients_and_nicks[0]
    msg = f"chantest-{time.monotonic()}"
    sender.send(f"PRIVMSG {channel} :{msg}")

    ok = True
    for c, nick in clients_and_nicks[1:]:
        try:
            c.wait_for(msg, timeout=5)
        except TimeoutError:
            print(f"    FAIL: {nick} did not receive channel message")
            ok = False
    return ok


def verify_links(client, expected_servers):
    """Send LINKS and check that all expected server names appear."""
    client.send("LINKS")
    lines = client.collect_lines(duration=2.0)
    found = set()
    for line in lines:
        if " 364 " in line:  # RPL_LINKS
            parts = line.split()
            # :server 364 nick mask servername :hopcount info
            if len(parts) >= 5:
                found.add(parts[3])
    missing = set(expected_servers) - found
    return len(missing) == 0, found, missing


class ScenarioRunner:
    """Manages test execution with pass/fail tracking and cleanup."""

    def __init__(self, name):
        self.name = name
        self.servers = []
        self.clients = []
        self.results = []

    def add_server(self, srv):
        self.servers.append(srv)

    def add_client(self, client):
        self.clients.append(client)

    def test(self, name, result):
        status = "PASS" if result else "FAIL"
        print(f"  [{status}] {name}")
        self.results.append((name, result))

    def cleanup(self):
        for c in self.clients:
            try:
                c.disconnect()
            except Exception:
                pass
        for srv in reversed(self.servers):
            try:
                srv.stop()
            except Exception:
                pass

    def summary(self):
        passed = sum(1 for _, r in self.results if r)
        total = len(self.results)
        print(f"\n{'=' * 50}")
        print(f"  {self.name}: {passed}/{total} tests passed")
        print(f"{'=' * 50}")
        return passed == total
