#!/usr/bin/env python3
"""Scenario A: All-gossip 4-node cluster (2 hubs + 2 leafs).

Topology:
    Leaf1 <--gossip--> Hub1 <--gossip--> Hub2 <--gossip--> Leaf2

All servers run the new bahamut from the meson build directory.

Gossip peers share an event bus (session state, event propagation) but each
server maintains its own user/channel state. Cross-server user visibility
requires the legacy TS5 bridge. This scenario tests:
  - Gossip link establishment across 4 nodes
  - Local client functionality on each node
  - Cross-server session RESUME via gossip

Usage:
    python3 scenarios/scenario_a_gossip_cluster.py
"""

import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tests.harness.ports import allocate_ports
from tests.harness.server import BahamutServer
from tests.harness.irc_client import IRCClient
from scenarios.common import (
    find_build_dir,
    unique_nick,
    wait_for_mesh,
    ScenarioRunner,
)


def main():
    build_dir = find_build_dir()
    ports = allocate_ports(4)
    hub1_port, hub2_port, leaf1_port, leaf2_port = ports

    print("Scenario A: All-gossip cluster (2 hubs + 2 leafs)")
    print(f"  Hub1={hub1_port} Hub2={hub2_port} Leaf1={leaf1_port} Leaf2={leaf2_port}")

    runner = ScenarioRunner("Scenario A")

    try:
        # --- Configure servers ---
        hub1 = BahamutServer(
            build_dir=build_dir,
            server_name="hub1.test",
            irc_port=hub1_port,
            server_id=1,
            gopeer_configs=[
                {"host": "127.0.0.1", "port": hub2_port, "name": "hub2.test", "server_id": 2},
                {"host": "127.0.0.1", "port": leaf1_port, "name": "leaf1.test", "server_id": 3},
            ],
        )

        hub2 = BahamutServer(
            build_dir=build_dir,
            server_name="hub2.test",
            irc_port=hub2_port,
            server_id=2,
            gopeer_configs=[
                {"host": "127.0.0.1", "port": hub1_port, "name": "hub1.test", "server_id": 1},
                {"host": "127.0.0.1", "port": leaf2_port, "name": "leaf2.test", "server_id": 4},
            ],
        )

        leaf1 = BahamutServer(
            build_dir=build_dir,
            server_name="leaf1.test",
            irc_port=leaf1_port,
            server_id=3,
            gopeer_configs=[
                {"host": "127.0.0.1", "port": hub1_port, "name": "hub1.test", "server_id": 1},
            ],
        )

        leaf2 = BahamutServer(
            build_dir=build_dir,
            server_name="leaf2.test",
            irc_port=leaf2_port,
            server_id=4,
            gopeer_configs=[
                {"host": "127.0.0.1", "port": hub2_port, "name": "hub2.test", "server_id": 2},
            ],
        )

        # --- Start servers ---
        print("  Starting servers...")
        for srv in [hub1, hub2, leaf1, leaf2]:
            srv.start()
            runner.add_server(srv)

        wait_for_mesh(seconds=12)

        # --- Test 1: All servers accept local clients ---
        print("  Running tests...")
        clients = {}
        for name, port in [("hub1", hub1_port), ("hub2", hub2_port),
                           ("leaf1", leaf1_port), ("leaf2", leaf2_port)]:
            nick = unique_nick(name[:2])
            c = IRCClient(port=port)
            c.connect()
            try:
                c.register(nick)
                clients[name] = (c, nick)
                runner.add_client(c)
            except Exception as e:
                runner.test(f"Client connects to {name}", False)
                continue

        runner.test("All 4 servers accept client connections",
                    len(clients) == 4)

        # --- Test 2: Local LUSERS works on each server ---
        all_lusers_ok = True
        for name, (c, nick) in clients.items():
            c.send("LUSERS")
            lines = c.collect_lines(duration=1.0)
            ok = any(" 251 " in l for l in lines)
            if not ok:
                all_lusers_ok = False
        runner.test("LUSERS responds on all servers", all_lusers_ok)

        # Allow user materialization events to propagate through multi-hop gossip
        time.sleep(5)

        # --- Test 3: Cross-server PRIVMSG ---
        c_l1, n_l1 = clients["leaf1"]
        c_l2, n_l2 = clients["leaf2"]

        msg_cross = f"crossmsg-{time.monotonic()}"
        c_l1.send(f"PRIVMSG {n_l2} :{msg_cross}")
        try:
            c_l2.wait_for(msg_cross, timeout=5)
            runner.test("Cross-server PRIVMSG leaf1 -> leaf2", True)
        except TimeoutError:
            runner.test("Cross-server PRIVMSG leaf1 -> leaf2", False)

        # --- Test 4: Cross-server WHOIS ---
        c_l2.send(f"WHOIS {n_l1}")
        whois_lines = c_l2.collect_lines(duration=2.0)
        whois_ok = any(" 311 " in l and n_l1 in l for l in whois_lines)
        runner.test(f"Cross-server WHOIS from leaf2 for {n_l1}", whois_ok)

        # --- Test 5: Cross-server channel messaging ---
        for name, (c, nick) in clients.items():
            c.send("JOIN #crosstest")
            c.wait_for("JOIN", timeout=3)
        time.sleep(5)  # Allow JOIN events to propagate through multi-hop gossip
        for name, (c, nick) in clients.items():
            c.collect_lines(duration=0.3)

        chan_msg = f"channelcross-{time.monotonic()}"
        c_l1.send(f"PRIVMSG #crosstest :{chan_msg}")
        all_received = True
        for name, (c, nick) in clients.items():
            if name == "leaf1":
                continue
            try:
                c.wait_for(chan_msg, timeout=5)
            except TimeoutError:
                print(f"    {name} did not receive channel msg")
                all_received = False
        runner.test("Cross-server channel messaging (leaf1 -> all)", all_received)

        # --- Test 6 (renumbered): Local PRIVMSG on same server ---
        nick_a = unique_nick("la")
        nick_b = unique_nick("lb")
        ca = IRCClient(port=hub1_port)
        ca.connect()
        ca.register(nick_a)
        runner.add_client(ca)
        cb = IRCClient(port=hub1_port)
        cb.connect()
        cb.register(nick_b)
        runner.add_client(cb)

        msg = f"test-{time.monotonic()}"
        ca.send(f"PRIVMSG {nick_b} :{msg}")
        try:
            cb.wait_for(msg, timeout=3)
            runner.test("Local PRIVMSG on same server", True)
        except TimeoutError:
            runner.test("Local PRIVMSG on same server", False)

        # --- Test 4: Local channel messaging on same server ---
        ca.send("JOIN #local")
        ca.wait_for("JOIN", timeout=3)
        cb.send("JOIN #local")
        cb.wait_for("JOIN", timeout=3)
        time.sleep(0.5)
        cb.collect_lines(duration=0.3)

        msg2 = f"chanmsg-{time.monotonic()}"
        ca.send(f"PRIVMSG #local :{msg2}")
        try:
            cb.wait_for(msg2, timeout=3)
            runner.test("Local channel messaging", True)
        except TimeoutError:
            runner.test("Local channel messaging", False)

        # --- Test 5: Cross-server session RESUME ---
        nick_r = unique_nick("xr")
        cr = IRCClient(port=leaf1_port)
        cr.connect()
        cr.register_with_caps(nick_r, ["draft/resume-0.5"])
        runner.add_client(cr)

        # Get RESUME token
        token = None
        resume_lines = cr.collect_lines(duration=1.0)
        for l in cr.all_lines:
            if "RESUME" in l and "TOKEN" in l:
                parts = l.split()
                for i, p in enumerate(parts):
                    if p == "TOKEN" and i + 1 < len(parts):
                        token = parts[i + 1]
                        break
                if token:
                    break

        if not token:
            runner.test("RESUME token received on leaf1", False)
        else:
            runner.test("RESUME token received on leaf1", True)

            # Disconnect from leaf1 — triggers session creation event
            cr.disconnect()
            time.sleep(12)  # Wait for gossip propagation (multi-hop)

            # Try RESUME on leaf2 (different server) using CAP negotiation
            cr2 = IRCClient(port=leaf2_port)
            cr2.connect()
            cr2.send("CAP LS 302")
            cr2.wait_for("CAP", timeout=3)
            cr2.send("CAP REQ :draft/resume-0.5")
            cr2.wait_for("ACK", timeout=3)
            cr2.send(f"RESUME {token}")
            runner.add_client(cr2)

            resumed = False
            fail_reason = "timeout"
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                try:
                    p, line = cr2.wait_for_any(["RESUME", "001", "FAIL", "432", "433", "462"], timeout=3)
                    if p == "001":
                        resumed = True
                        break
                    elif p == "RESUME":
                        if "FAIL" in line:
                            fail_reason = line
                            break
                        elif "TOKEN" not in line:
                            resumed = True
                            break
                    else:
                        fail_reason = f"unexpected: {line}"
                        break
                except TimeoutError:
                    break
            if not resumed:
                debug_lines = cr2.collect_lines(duration=1.0)
                for l in cr2.all_lines[-3:]:
                    print(f"    RESUME debug: {l}")
            runner.test(f"Cross-server RESUME (known-flaky in 4-node, {fail_reason if not resumed else 'ok'})", resumed)

        # --- Test 6: Server survives peer disconnect ---
        leaf2.stop(keep_data=True)
        time.sleep(2)

        # Hub2 should still be operational
        c_check = IRCClient(port=hub2_port)
        c_check.connect()
        try:
            c_check.register(unique_nick("ch"))
            runner.test("Hub2 operational after leaf2 disconnect", True)
            runner.add_client(c_check)
        except Exception:
            runner.test("Hub2 operational after leaf2 disconnect", False)

    except Exception as e:
        print(f"  ERROR: {e}")
        import traceback
        traceback.print_exc()
    finally:
        runner.cleanup()

    success = runner.summary()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
