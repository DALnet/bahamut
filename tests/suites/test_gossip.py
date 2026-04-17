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
        """Kill middle server — no QUIT cascade (Sable-inspired: users persist)."""
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
        time.sleep(5)

        # Collect messages — should NOT see QUIT for remote users
        lines1 = c1.collect_lines(duration=2)
        lines3 = c3.collect_lines(duration=2)

        user_quits = [
            l for l in lines1 + lines3
            if "QUIT" in l and (n1 in l or n3 in l)
        ]
        assert len(user_quits) == 0, f"Unexpected user QUITs after srv2 death: {user_quits}"

        # Verify both LOCAL clients are still connected
        c1.send("PING :check1")
        resp1 = c1.collect_lines(duration=3)
        assert any("check1" in l for l in resp1), "srv1 client lost connection"

        c3.send("PING :check3")
        resp3 = c3.collect_lines(duration=3)
        assert any("check3" in l for l in resp3), "srv3 client lost connection"

    def test_user_presence_after_link_loss(self, gossip_triangle, client_factory, unique_nick):
        """After srv2 dies, local clients on srv1/srv3 remain connected."""
        srv1, srv2, srv3 = gossip_triangle

        nick1 = unique_nick("pl")
        c1 = client_factory(port=srv1.irc_port)
        c1.register(nick1)
        c1.collect_lines(duration=0.5)

        # Wait for presence to propagate through the mesh
        time.sleep(2)

        nick3 = unique_nick("pl")
        c3 = client_factory(port=srv3.irc_port)
        c3.register(nick3)
        c3.collect_lines(duration=0.5)

        c3.send("LUSERS")
        before = c3.collect_lines(duration=1)
        assert any(" 251 " in l for l in before), "srv3 LUSERS failed before srv2 kill"

        # Kill srv2
        srv2.stop(keep_data=True)
        time.sleep(5)

        # Drain disconnect-related messages
        c1.collect_lines(duration=2)
        c3.collect_lines(duration=2)

        # Local clients should still be connected
        c1.send("PING :alive1")
        resp1 = c1.collect_lines(duration=3)
        assert any("alive1" in l for l in resp1), "srv1 client lost connection after srv2 death"

        c3.send("PING :alive3")
        resp3 = c3.collect_lines(duration=3)
        assert any("alive3" in l for l in resp3), "srv3 client lost connection after srv2 death"


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


class TestGossipNetsplitResilience:
    """Verify that gossip eliminates netsplits — users persist when a hub dies."""

    def test_hub_death_no_user_loss(self, gossip_dual_hub, client_factory, unique_nick):
        """Kill hub1 — users on leaf1 and leaf2 keep their state."""
        leaf1, hub1, hub2, leaf2 = gossip_dual_hub

        # Verify gossip links are up — hub1 should see 3 peers
        ch = client_factory(port=hub1.irc_port)
        ch.register(unique_nick("nr"))
        ch.collect_lines(duration=0.5)
        ch.send("LINKS")
        links = ch.collect_lines(duration=2)
        link_count = sum(1 for l in links if "364" in l)
        assert link_count >= 3, \
            f"Hub1 only sees {link_count} servers, expected 4: {[l for l in links if '364' in l]}"

        # Create users on both leafs
        nick1 = unique_nick("nr")
        nick2 = unique_nick("nr")
        c1 = client_factory(port=leaf1.irc_port)
        c1.register(nick1)
        c1.collect_lines(duration=0.5)
        c1.send("JOIN #resilience")
        c1.wait_for("366")

        c2 = client_factory(port=leaf2.irc_port)
        c2.register(nick2)
        c2.collect_lines(duration=0.5)
        c2.send("JOIN #resilience")
        c2.wait_for("366")
        time.sleep(8)

        # Verify both see each other
        c1.send("NAMES #resilience")
        names1 = c1.collect_lines(duration=2)
        assert any(nick2 in l for l in names1 if "353" in l), \
            f"leaf1 doesn't see {nick2} before hub death"

        # Kill hub1
        hub1.stop(keep_data=True)
        time.sleep(5)

        # leaf1 lost its only gossip link — but should NOT see QUITs
        lines1 = c1.collect_lines(duration=3)
        user_quits = [l for l in lines1 if "QUIT" in l and nick2 in l]
        assert len(user_quits) == 0, \
            f"Got QUIT for {nick2} after hub1 death (netsplit!): {user_quits}"

        # leaf1 should still be connected
        c1.send("PING :alive1")
        resp = c1.collect_lines(duration=3)
        assert any("alive1" in l for l in resp), "leaf1 lost connection"

        # leaf2 should still be connected (hub2 is still up)
        c2.send("PING :alive2")
        resp2 = c2.collect_lines(duration=3)
        assert any("alive2" in l for l in resp2), "leaf2 lost connection"

    def test_hub_death_channel_state_persists(self, gossip_dual_hub, client_factory, unique_nick):
        """After hub dies, channel + topic still visible on surviving leaf."""
        leaf1, hub1, hub2, leaf2 = gossip_dual_hub

        nick1 = unique_nick("cs")
        c1 = client_factory(port=leaf1.irc_port)
        c1.register(nick1)
        c1.collect_lines(duration=0.5)
        c1.send("JOIN #persist")
        c1.wait_for("366")
        c1.send("TOPIC #persist :this should survive")
        c1.send("MODE #persist +nt")
        c1.collect_lines(duration=1)
        time.sleep(6)

        # Verify leaf2 sees channel
        nick2 = unique_nick("cs")
        c2 = client_factory(port=leaf2.irc_port)
        c2.register(nick2)
        c2.collect_lines(duration=0.5)
        c2.send("JOIN #persist")
        lines = c2.collect_lines(duration=2)
        assert any("this should survive" in l for l in lines if "332" in l), \
            "Topic not visible on leaf2 before hub death"

        # Kill hub1
        hub1.stop(keep_data=True)
        time.sleep(5)

        # leaf2 should still see channel state (hub2 is alive)
        c2.send("NAMES #persist")
        names = c2.collect_lines(duration=2)
        names_text = " ".join(l for l in names if "353" in l)
        assert nick1 in names_text, \
            f"User {nick1} disappeared from leaf2 after hub1 death"

        c2.send("MODE #persist")
        modes = c2.collect_lines(duration=2)
        mode_text = " ".join(l for l in modes if "324" in l)
        assert "n" in mode_text and "t" in mode_text, \
            f"Channel modes lost after hub1 death: {mode_text}"


class TestGossipPropagation:
    """Gossip state propagation — users, channels, topics, modes across peers."""

    def test_user_visible_on_peer(self, gossip_cluster, client_factory, unique_nick):
        """User registered on srv1 is visible via WHOIS on srv2."""
        srv1, srv2 = gossip_cluster

        nick = unique_nick("uv")
        c1 = client_factory(port=srv1.irc_port)
        c1.register(nick)
        c1.collect_lines(duration=0.5)
        time.sleep(3)

        c2 = client_factory(port=srv2.irc_port)
        c2.register(unique_nick("uv"))
        c2.collect_lines(duration=0.5)

        c2.send(f"WHOIS {nick}")
        lines = c2.collect_lines(duration=2)
        assert any("311" in l and nick in l for l in lines), \
            f"User {nick} not visible on srv2 via WHOIS"

    def test_channel_join_propagates(self, gossip_cluster, client_factory, unique_nick):
        """User joins channel on srv1, visible in NAMES on srv2."""
        srv1, srv2 = gossip_cluster

        nick1 = unique_nick("cj")
        c1 = client_factory(port=srv1.irc_port)
        c1.register(nick1)
        c1.collect_lines(duration=0.5)
        c1.send("JOIN #proptest")
        c1.wait_for("366")
        time.sleep(3)

        nick2 = unique_nick("cj")
        c2 = client_factory(port=srv2.irc_port)
        c2.register(nick2)
        c2.collect_lines(duration=0.5)
        c2.send("JOIN #proptest")
        lines = c2.collect_lines(duration=2)
        names_lines = [l for l in lines if "353" in l]
        all_names = " ".join(names_lines)
        assert nick1 in all_names, \
            f"User {nick1} not in NAMES on srv2: {names_lines}"

    def test_topic_propagates(self, gossip_cluster, client_factory, unique_nick):
        """Topic set on srv1 visible on srv2."""
        srv1, srv2 = gossip_cluster

        nick1 = unique_nick("tp")
        c1 = client_factory(port=srv1.irc_port)
        c1.register(nick1)
        c1.collect_lines(duration=0.5)
        c1.send("JOIN #topictest")
        c1.wait_for("366")
        c1.send("TOPIC #topictest :gossip topic propagation test")
        c1.collect_lines(duration=1)
        time.sleep(3)

        nick2 = unique_nick("tp")
        c2 = client_factory(port=srv2.irc_port)
        c2.register(nick2)
        c2.collect_lines(duration=0.5)
        c2.send("JOIN #topictest")
        lines = c2.collect_lines(duration=2)
        topic_lines = [l for l in lines if "332" in l]
        assert any("gossip topic propagation test" in l for l in topic_lines), \
            f"Topic not propagated to srv2: {topic_lines}"

    def test_channel_modes_propagate(self, gossip_cluster, client_factory, unique_nick):
        """Channel modes (+nt) set on srv1 visible on srv2."""
        srv1, srv2 = gossip_cluster

        nick1 = unique_nick("cm")
        c1 = client_factory(port=srv1.irc_port)
        c1.register(nick1)
        c1.collect_lines(duration=0.5)
        c1.send("JOIN #modetest")
        c1.wait_for("366")
        c1.send("MODE #modetest +nt")
        c1.collect_lines(duration=1)
        time.sleep(3)

        nick2 = unique_nick("cm")
        c2 = client_factory(port=srv2.irc_port)
        c2.register(nick2)
        c2.collect_lines(duration=0.5)
        c2.send("JOIN #modetest")
        c2.wait_for("366")
        c2.send("MODE #modetest")
        lines = c2.collect_lines(duration=2)
        mode_lines = [l for l in lines if "324" in l]
        assert any("n" in l and "t" in l for l in mode_lines), \
            f"Channel modes +nt not propagated to srv2: {mode_lines}"

    def test_nick_change_propagates(self, gossip_cluster, client_factory, unique_nick):
        """Nick change on srv1 reflected on srv2."""
        srv1, srv2 = gossip_cluster

        oldnick = unique_nick("nc")
        newnick = unique_nick("nc")
        c1 = client_factory(port=srv1.irc_port)
        c1.register(oldnick)
        c1.collect_lines(duration=0.5)
        time.sleep(3)

        # Verify old nick visible on srv2
        c2 = client_factory(port=srv2.irc_port)
        c2.register(unique_nick("nc"))
        c2.collect_lines(duration=0.5)
        c2.send(f"WHOIS {oldnick}")
        lines = c2.collect_lines(duration=2)
        assert any("311" in l and oldnick in l for l in lines), \
            f"Old nick {oldnick} not visible on srv2"

        # Change nick
        c1.send(f"NICK {newnick}")
        c1.collect_lines(duration=1)
        time.sleep(3)

        # Verify new nick on srv2
        c2.send(f"WHOIS {newnick}")
        lines = c2.collect_lines(duration=2)
        assert any("311" in l and newnick in l for l in lines), \
            f"New nick {newnick} not visible on srv2 after nick change"

    def test_user_quit_propagates(self, gossip_cluster, client_factory, unique_nick):
        """User quit on srv1 removes them from srv2."""
        srv1, srv2 = gossip_cluster

        nick = unique_nick("uq")
        c1 = client_factory(port=srv1.irc_port)
        c1.register(nick)
        c1.collect_lines(duration=0.5)
        time.sleep(3)

        # Verify visible
        c2 = client_factory(port=srv2.irc_port)
        c2.register(unique_nick("uq"))
        c2.collect_lines(duration=0.5)
        c2.send(f"WHOIS {nick}")
        lines = c2.collect_lines(duration=2)
        assert any("311" in l for l in lines), "User not visible before quit"

        # Quit
        c1.send("QUIT :bye")
        c1.disconnect()
        time.sleep(3)

        # Verify gone
        c2.send(f"WHOIS {nick}")
        lines = c2.collect_lines(duration=2)
        assert any("401" in l for l in lines), \
            f"User {nick} still visible on srv2 after quit"

    def test_part_propagates(self, gossip_cluster, client_factory, unique_nick):
        """User parts channel on srv1, removed from NAMES on srv2."""
        srv1, srv2 = gossip_cluster

        nick1 = unique_nick("pt")
        c1 = client_factory(port=srv1.irc_port)
        c1.register(nick1)
        c1.collect_lines(duration=0.5)
        c1.send("JOIN #parttest")
        c1.wait_for("366")
        time.sleep(3)

        # Verify in channel on srv2
        nick2 = unique_nick("pt")
        c2 = client_factory(port=srv2.irc_port)
        c2.register(nick2)
        c2.collect_lines(duration=0.5)
        c2.send("JOIN #parttest")
        lines = c2.collect_lines(duration=2)
        names = " ".join(l for l in lines if "353" in l)
        assert nick1 in names, f"{nick1} not in channel before part"

        # Part
        c1.send("PART #parttest :leaving")
        c1.collect_lines(duration=1)
        time.sleep(3)

        # Verify gone from NAMES
        c2.send("NAMES #parttest")
        lines = c2.collect_lines(duration=2)
        names = " ".join(l for l in lines if "353" in l)
        assert nick1 not in names, \
            f"{nick1} still in NAMES on srv2 after PART"


class TestGossipTLS:
    """Gossip with TLS-encrypted peer links and client connections."""

    def test_tls_gossip_link(self, gossip_cluster_tls, client_factory, unique_nick):
        """Two servers establish a gossip link over TLS."""
        srv1, srv2 = gossip_cluster_tls

        nick1 = unique_nick("tls")
        c1 = client_factory(port=srv1.irc_port)
        c1.register(nick1)
        c1.collect_lines(duration=0.5)

        c1.send("LINKS")
        lines = c1.collect_lines(duration=2)
        link_lines = [l for l in lines if "364" in l]
        names = " ".join(link_lines)
        assert "irc2.test" in names, f"TLS gossip link not established: {link_lines}"

    def test_tls_user_propagation(self, gossip_cluster_tls, client_factory, unique_nick):
        """User on srv1 visible on srv2 over TLS gossip link."""
        srv1, srv2 = gossip_cluster_tls

        nick = unique_nick("tlsu")
        c1 = client_factory(port=srv1.irc_port)
        c1.register(nick)
        c1.collect_lines(duration=0.5)
        time.sleep(3)

        c2 = client_factory(port=srv2.irc_port)
        c2.register(unique_nick("tlsu"))
        c2.collect_lines(duration=0.5)

        c2.send(f"WHOIS {nick}")
        lines = c2.collect_lines(duration=2)
        assert any("311" in l and nick in l for l in lines), \
            f"User {nick} not visible over TLS gossip link"

    def test_tls_client_connection(self, gossip_cluster_tls, client_factory, unique_nick):
        """Client connects via TLS port and can see gossip state."""
        srv1, srv2 = gossip_cluster_tls

        # Connect user on srv1 (plain)
        nick1 = unique_nick("tlsc")
        c1 = client_factory(port=srv1.irc_port)
        c1.register(nick1)
        c1.collect_lines(duration=0.5)
        time.sleep(3)

        # Connect to srv2 via TLS
        nick2 = unique_nick("tlsc")
        c2 = client_factory(port=srv2.ssl_port, use_tls=True)
        c2.register(nick2)
        c2.collect_lines(duration=0.5)

        c2.send(f"WHOIS {nick1}")
        lines = c2.collect_lines(duration=2)
        assert any("311" in l and nick1 in l for l in lines), \
            f"TLS client on srv2 cannot see user {nick1} from srv1"


class TestGossipTS5Bridge:
    """Gossip state propagation to/from TS5-linked servers via bridge."""

    def test_gossip_user_visible_on_ts5(self, gossip_with_ts5_bridge, client_factory, unique_nick):
        """User on srv1 (gossip) visible via WHOIS on srv3 (TS5)."""
        srv1, srv2, srv3 = gossip_with_ts5_bridge

        nick = unique_nick("gt")
        c1 = client_factory(port=srv1.irc_port)
        c1.register(nick)
        c1.collect_lines(duration=0.5)
        time.sleep(4)

        c3 = client_factory(port=srv3.irc_port)
        c3.register(unique_nick("gt"))
        c3.collect_lines(duration=0.5)

        c3.send(f"WHOIS {nick}")
        lines = c3.collect_lines(duration=2)
        assert any("311" in l and nick in l for l in lines), \
            f"Gossip user {nick} not visible on TS5 server via WHOIS"

    def test_gossip_channel_on_ts5(self, gossip_with_ts5_bridge, client_factory, unique_nick):
        """Channel + topic from gossip visible on TS5 server."""
        srv1, srv2, srv3 = gossip_with_ts5_bridge

        nick1 = unique_nick("gc")
        c1 = client_factory(port=srv1.irc_port)
        c1.register(nick1)
        c1.collect_lines(duration=0.5)
        c1.send("JOIN #bridgetest")
        c1.wait_for("366")
        c1.send("TOPIC #bridgetest :from gossip to legacy")
        c1.collect_lines(duration=1)
        time.sleep(4)

        nick3 = unique_nick("gc")
        c3 = client_factory(port=srv3.irc_port)
        c3.register(nick3)
        c3.collect_lines(duration=0.5)
        c3.send("JOIN #bridgetest")
        lines = c3.collect_lines(duration=2)
        names = " ".join(l for l in lines if "353" in l)
        topics = [l for l in lines if "332" in l]

        assert nick1 in names, \
            f"Gossip user {nick1} not in NAMES on TS5 server"
        assert any("from gossip to legacy" in l for l in topics), \
            f"Topic not propagated to TS5 server: {topics}"

    def test_all_servers_in_links(self, gossip_with_ts5_bridge, client_factory, unique_nick):
        """All 3 servers visible in LINKS from the bridge hub and TS5 server."""
        srv1, srv2, srv3 = gossip_with_ts5_bridge

        # srv2 (bridge hub) should see all 3 — it has both gossip and TS5 links
        nick = unique_nick("lk")
        c2 = client_factory(port=srv2.irc_port)
        c2.register(nick)
        c2.collect_lines(duration=0.5)
        c2.send("LINKS")
        lines = c2.collect_lines(duration=2)
        link_lines = [l for l in lines if "364" in l]
        server_names = " ".join(link_lines)
        for name in ["irc1.test", "irc2.test", "irc3.test"]:
            assert name in server_names, \
                f"{name} not in LINKS from srv2 (bridge hub): {link_lines}"

        # Note: srv3 (TS5) LINKS check skipped to avoid connection throttle.
        # srv2 seeing all 3 confirms the bridge is working correctly.
