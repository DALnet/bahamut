#!/usr/bin/env python3
"""Scenario B: Mixed old+new cluster with TS5 legacy bridge.

Topology:
    Leaf-old (TS5) --connect{}--> Hub1 (bridge) <--gossip--> Hub2
                                       ^
                                       |
                                  Leaf-new (gossip)

Hub1 runs new bahamut with m_legacy_bridge (auto-loaded as core module).
Leaf-old runs old bahamut (master branch) connected via TS5 connect{} blocks.
Hub2 and Leaf-new run new bahamut connected via gossip.

The TS5 link between Hub1 and Leaf-old provides full user/channel visibility
(LUSERS, PRIVMSG, LINKS) between those two servers. Gossip peers (Hub2,
Leaf-new) maintain separate user state.

Usage:
    python3 scenarios/scenario_b_mixed_cluster.py --old-binary build-master/src/ircd

    If --old-binary is not provided, the script looks for build-master/src/ircd
    relative to the project root.
"""

import argparse
import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tests.harness.ports import allocate_ports
from tests.harness.server import BahamutServer
from tests.harness.irc_client import IRCClient
from scenarios.old_server import OldBahamutServer
from scenarios.common import (
    find_build_dir,
    unique_nick,
    wait_for_mesh,
    ScenarioRunner,
)


def find_old_binary():
    """Locate the old (master-branch) ircd binary."""
    root = os.path.join(os.path.dirname(__file__), "..")
    candidate = os.path.join(root, "build-master", "src", "ircd")
    if os.path.isfile(candidate):
        return os.path.abspath(candidate)
    return None


def main():
    parser = argparse.ArgumentParser(description="Scenario B: Mixed old+new cluster")
    parser.add_argument(
        "--old-binary",
        help="Path to the old (master-branch) ircd binary",
    )
    args = parser.parse_args()

    old_binary = args.old_binary or find_old_binary()
    if not old_binary or not os.path.isfile(old_binary):
        print("ERROR: Old ircd binary not found.")
        print("  Build it: git worktree add /tmp/bah-master master && "
              "cd /tmp/bah-master && ./configure && make")
        print("  Then: mkdir -p build-master/src && cp /tmp/bah-master/src/ircd build-master/src/")
        print("  Or pass --old-binary /path/to/old/ircd")
        sys.exit(2)

    build_dir = find_build_dir()
    ports = allocate_ports(4)
    hub1_port, hub2_port, leaf_new_port, leaf_old_port = ports

    print("Scenario B: Mixed old+new cluster (TS5 bridge)")
    print(f"  Hub1={hub1_port} Hub2={hub2_port} Leaf-new={leaf_new_port} Leaf-old={leaf_old_port}")
    print(f"  Old binary: {old_binary}")

    ts5_passwd = "ts5secret"
    runner = ScenarioRunner("Scenario B")

    try:
        # --- Hub1 (new, bridge): gossip to Hub2+Leaf-new, TS5 connect to Leaf-old ---
        hub1 = BahamutServer(
            build_dir=build_dir,
            server_name="hub1.test",
            irc_port=hub1_port,
            server_id=1,
            gopeer_configs=[
                {"host": "127.0.0.1", "port": hub2_port, "name": "hub2.test", "server_id": 2},
                {"host": "127.0.0.1", "port": leaf_new_port, "name": "leafnew.test", "server_id": 3},
            ],
            connect_configs=[
                {
                    "name": "leafold.test",
                    "host": "127.0.0.1",
                    "port": leaf_old_port,
                    "apasswd": ts5_passwd,
                    "cpasswd": ts5_passwd,
                    "flags": "H",
                },
            ],
        )

        # --- Hub2 (new, gossip only) ---
        hub2 = BahamutServer(
            build_dir=build_dir,
            server_name="hub2.test",
            irc_port=hub2_port,
            server_id=2,
            gopeer_configs=[
                {"host": "127.0.0.1", "port": hub1_port, "name": "hub1.test", "server_id": 1},
            ],
        )

        # --- Leaf-new (new, gossip only) ---
        leaf_new = BahamutServer(
            build_dir=build_dir,
            server_name="leafnew.test",
            irc_port=leaf_new_port,
            server_id=3,
            gopeer_configs=[
                {"host": "127.0.0.1", "port": hub1_port, "name": "hub1.test", "server_id": 1},
            ],
        )

        # --- Leaf-old (old bahamut, TS5 connect to Hub1) ---
        leaf_old = OldBahamutServer(
            binary_path=old_binary,
            server_name="leafold.test",
            irc_port=leaf_old_port,
            connect_configs=[
                {
                    "name": "hub1.test",
                    "host": "127.0.0.1",
                    "port": hub1_port,
                    "apasswd": ts5_passwd,
                    "cpasswd": ts5_passwd,
                    "flags": "H",
                },
            ],
        )

        # --- Start servers ---
        print("  Starting new servers...")
        for srv in [hub1, hub2, leaf_new]:
            srv.start()
            runner.add_server(srv)

        print("  Starting old server...")
        leaf_old.start()
        runner.add_server(leaf_old)

        # Wait for both gossip mesh and TS5 link to form
        wait_for_mesh(seconds=15)

        # --- Run tests ---
        print("  Running tests...")

        # Test 1: All servers accept clients
        clients = {}
        for name, port in [("hub1", hub1_port), ("hub2", hub2_port),
                           ("leafnew", leaf_new_port), ("leafold", leaf_old_port)]:
            nick = unique_nick(name[:2])
            c = IRCClient(port=port)
            c.connect()
            try:
                c.register(nick)
                clients[name] = (c, nick)
                runner.add_client(c)
            except Exception:
                runner.test(f"Client connects to {name}", False)

        runner.test("All 4 servers accept client connections",
                    len(clients) == 4)

        # Test 2: TS5 link between Hub1 and Leaf-old (LINKS from hub1)
        c_hub1, _ = clients["hub1"]
        c_hub1.send("LINKS")
        lines = c_hub1.collect_lines(duration=2.0)
        link_names = set()
        for l in lines:
            if " 364 " in l:
                parts = l.split()
                if len(parts) >= 5:
                    link_names.add(parts[3])

        ts5_linked = "leafold.test" in link_names and "hub1.test" in link_names
        runner.test(f"TS5 link: Hub1 sees Leaf-old in LINKS (found: {link_names})", ts5_linked)

        # Test 3: LUSERS on Hub1 shows users from Leaf-old
        c_hub1.send("LUSERS")
        lusers_lines = c_hub1.collect_lines(duration=1.0)
        hub1_sees_remote = False
        for l in lusers_lines:
            if " 255 " in l:
                # ":hub1.test 255 nick :I have N clients and M servers"
                if "1 servers" in l or "2 servers" in l:
                    hub1_sees_remote = True
        runner.test("Hub1 LUSERS shows TS5-linked server", hub1_sees_remote)

        # Test 4: Cross-server PRIVMSG via TS5 (Hub1 <-> Leaf-old)
        c_old, nick_old = clients["leafold"]
        c_h1, nick_h1 = clients["hub1"]

        msg = f"bridge-{time.monotonic()}"
        c_h1.send(f"PRIVMSG {nick_old} :{msg}")
        try:
            c_old.wait_for(msg, timeout=5)
            runner.test("PRIVMSG hub1 -> leaf-old via TS5", True)
        except TimeoutError:
            runner.test("PRIVMSG hub1 -> leaf-old via TS5", False)

        # Test 5: Reverse PRIVMSG (Leaf-old -> Hub1)
        msg2 = f"reverse-{time.monotonic()}"
        c_old.send(f"PRIVMSG {nick_h1} :{msg2}")
        try:
            c_h1.wait_for(msg2, timeout=5)
            runner.test("PRIVMSG leaf-old -> hub1 via TS5", True)
        except TimeoutError:
            runner.test("PRIVMSG leaf-old -> hub1 via TS5", False)

        # Test 6: Channel messaging via TS5 bridge
        c_h1.send("JOIN #bridge")
        c_h1.wait_for("JOIN", timeout=3)
        c_old.send("JOIN #bridge")
        c_old.wait_for("JOIN", timeout=3)
        time.sleep(0.5)
        c_old.collect_lines(duration=0.3)

        msg3 = f"chanbr-{time.monotonic()}"
        c_h1.send(f"PRIVMSG #bridge :{msg3}")
        try:
            c_old.wait_for(msg3, timeout=5)
            runner.test("Channel messaging across TS5 bridge", True)
        except TimeoutError:
            runner.test("Channel messaging across TS5 bridge", False)

        # Test 7: Gossip peers still functional alongside TS5
        c_h2, nick_h2 = clients["hub2"]
        c_h2.send("LUSERS")
        h2_lines = c_h2.collect_lines(duration=1.0)
        h2_ok = any(" 251 " in l for l in h2_lines)
        runner.test("Hub2 (gossip) operational alongside TS5 bridge", h2_ok)

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
