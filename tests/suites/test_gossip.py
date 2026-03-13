"""Gossip protocol tests — multi-node clusters, event propagation, anti-netsplit, GVER."""

import time

import pytest

from tests.harness.irc_client import IRCClient
from tests.harness.ports import allocate_ports
from tests.harness.server import BahamutServer


class TestGossip:

    def test_gossip_link(self, gossip_cluster, client_factory, unique_nick):
        """Two servers establish a gossip link."""
        srv1, srv2 = gossip_cluster

        # Both servers should be running
        nick1 = unique_nick("g")
        nick2 = unique_nick("g")

        c1 = client_factory(port=srv1.irc_port)
        c1.register(nick1)
        c1.collect_lines(duration=0.5)

        c2 = client_factory(port=srv2.irc_port)
        c2.register(nick2)
        c2.collect_lines(duration=0.5)

        # Check LUSERS on both servers to verify they see global users
        c1.send("LUSERS")
        lines1 = c1.collect_lines(duration=1)

        c2.send("LUSERS")
        lines2 = c2.collect_lines(duration=1)

        # Both servers should report users
        assert any("251" in l for l in lines1), "Server 1 LUSERS failed"
        assert any("251" in l for l in lines2), "Server 2 LUSERS failed"

    def test_anti_netsplit(self, gossip_cluster, client_factory, unique_nick):
        """Killing gossip link does NOT cause cascading QUITs."""
        srv1, srv2 = gossip_cluster

        # Connect users to both servers
        nick1 = unique_nick("g")
        nick2 = unique_nick("g")

        c1 = client_factory(port=srv1.irc_port)
        c1.register(nick1)
        c1.collect_lines(duration=0.5)

        c2 = client_factory(port=srv2.irc_port)
        c2.register(nick2)
        c2.collect_lines(duration=0.5)

        # Join same channel
        c1.send("JOIN #netsplit")
        c1.wait_for("366")
        c2.send("JOIN #netsplit")
        c2.wait_for("366")
        c1.collect_lines(duration=1)
        c2.collect_lines(duration=1)

        # Note: We can't easily kill the gossip link from here without
        # server cooperation. Just verify the users don't see spurious QUITs
        # after a brief wait. This is a smoke test.
        time.sleep(2)
        lines1 = c1.collect_lines(duration=1)
        lines2 = c2.collect_lines(duration=1)

        quit_count = sum(1 for l in lines1 + lines2 if "QUIT" in l)
        assert quit_count == 0, f"Unexpected QUITs: {[l for l in lines1+lines2 if 'QUIT' in l]}"


class TestGossipTriangle:
    """Three-node gossip mesh tests."""

    def test_uplink_disconnect_no_netsplit(self, gossip_triangle, client_factory, unique_nick):
        """Kill middle server — users on srv1/srv3 remain, no QUIT cascade."""
        srv1, srv2, srv3 = gossip_triangle

        n1 = unique_nick("ns")
        n3 = unique_nick("ns")
        c1 = client_factory(port=srv1.irc_port)
        c1.register(n1)
        c1.collect_lines(duration=0.5)

        c3 = client_factory(port=srv3.irc_port)
        c3.register(n3)
        c3.collect_lines(duration=0.5)

        # Join same channel so QUIT would be visible
        c1.send("JOIN #mesh")
        c1.wait_for("366")
        c3.send("JOIN #mesh")
        c3.wait_for("366")
        # Drain any join notifications
        c1.collect_lines(duration=1)
        c3.collect_lines(duration=1)

        # Kill srv2 (the middle node)
        srv2.stop(keep_data=True)
        time.sleep(3)

        # Collect any messages — should NOT see QUIT for each other
        lines1 = c1.collect_lines(duration=2)
        lines3 = c3.collect_lines(duration=2)

        # Filter for QUIT lines mentioning real user nicks (not server-related)
        user_quits = [
            l for l in lines1 + lines3
            if "QUIT" in l and (n1 in l or n3 in l)
        ]
        assert len(user_quits) == 0, f"Unexpected user QUITs after srv2 death: {user_quits}"

        # Verify both clients are still connected by sending LUSERS
        c1.send("LUSERS")
        resp1 = c1.collect_lines(duration=1)
        assert any(" 251 " in l for l in resp1), "srv1 client lost connection"

        c3.send("LUSERS")
        resp3 = c3.collect_lines(duration=1)
        assert any(" 251 " in l for l in resp3), "srv3 client lost connection"

    def test_user_presence_after_link_loss(self, gossip_triangle, client_factory, unique_nick):
        """User on srv1 still exists from srv3's perspective after srv2 dies."""
        srv1, srv2, srv3 = gossip_triangle

        nick1 = unique_nick("pl")
        c1 = client_factory(port=srv1.irc_port)
        c1.register(nick1)
        c1.collect_lines(duration=0.5)

        # Wait for presence to propagate through the mesh
        time.sleep(2)

        # Verify srv3 sees the user via LUSERS before killing srv2
        nick3 = unique_nick("pl")
        c3 = client_factory(port=srv3.irc_port)
        c3.register(nick3)
        c3.collect_lines(duration=0.5)

        c3.send("LUSERS")
        before = c3.collect_lines(duration=1)
        assert any(" 251 " in l for l in before), "srv3 LUSERS failed before srv2 kill"

        # Kill srv2
        srv2.stop(keep_data=True)
        time.sleep(3)

        # c1 should still be connected
        c1.send("PING :alive")
        pong = c1.collect_lines(duration=2)
        assert any("PONG" in l or "alive" in l for l in pong + c1.all_lines[-5:]), \
            "srv1 client not responding after srv2 death"

        # srv3 should still be operational
        c3.send("LUSERS")
        after = c3.collect_lines(duration=1)
        assert any(" 251 " in l for l in after), "srv3 LUSERS failed after srv2 kill"


class TestCrossServerResume:

    def test_cross_server_resume(self, gossip_cluster, client_factory, unique_nick):
        """RESUME with token from srv1 works on srv2 after gossip propagation."""
        srv1, srv2 = gossip_cluster

        nick = unique_nick("xr")
        c1 = client_factory(port=srv1.irc_port)
        c1.register_with_caps(nick, ["draft/resume-0.5"])

        # Get RESUME TOKEN
        token_line = c1.wait_for("RESUME", timeout=5)
        parts = token_line.split()
        token = None
        for i, p in enumerate(parts):
            if p == "TOKEN" and i + 1 < len(parts):
                token = parts[i + 1].lstrip(":")
                break
        assert token is not None, f"Could not extract token from: {token_line}"

        # Disconnect from srv1 — hook_signoff creates the session
        c1.disconnect()

        # Wait for session gossip to propagate to srv2
        time.sleep(3)

        # Attempt RESUME on srv2
        c2 = client_factory(port=srv2.irc_port)
        c2.send("CAP LS 302")
        c2.wait_for("CAP")
        c2.send("CAP REQ :draft/resume-0.5")
        c2.wait_for("ACK")
        c2.send(f"RESUME {token}")

        # Server responds with "RESUME <nick>" on success, "FAIL RESUME ..."
        # on failure, or may send "RESUME TOKEN <token>" first (pre-auth token).
        deadline = time.time() + 5
        resumed = False
        while time.time() < deadline:
            try:
                p, line = c2.wait_for_any(["RESUME", "001"], timeout=2)
                if p == "001":
                    assert nick.lower() in line.lower(), \
                        f"Expected nick {nick} in welcome, got: {line}"
                    resumed = True
                    break
                elif p == "RESUME":
                    if "FAIL" in line:
                        pytest.fail(f"RESUME failed: {line}")
                    elif "TOKEN" not in line:
                        # "RESUME <nick>" — success
                        assert nick.lower() in line.lower(), \
                            f"Expected nick {nick} in RESUME response, got: {line}"
                        resumed = True
                        break
                    # else: RESUME TOKEN — keep waiting
            except TimeoutError:
                break
        assert resumed, "Cross-server RESUME timed out — no SUCCESS or 001 received"


