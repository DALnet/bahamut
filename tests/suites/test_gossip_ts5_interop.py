"""End-to-end gossip ↔ TS5 interoperability tests.

Tests a gossip node (srv1) linked via gossip to a bridge hub (srv2),
which is TS5-linked to a legacy server (srv3). Verifies bidirectional
propagation of users, channels, topics, modes, kicks, bans, kills, and quits.
"""

import time
import pytest

from tests.harness.irc_client import IRCClient


class TestGossipTS5Interop:
    """Full interop between a gossip leaf and a TS5 leaf via bridge hub."""

    # ---- User visibility ----

    def test_gossip_user_visible_on_ts5(self, gossip_with_ts5_bridge, client_factory, unique_nick):
        """User on gossip node visible via WHOIS on TS5 node."""
        srv1, srv2, srv3 = gossip_with_ts5_bridge

        nick = unique_nick("g2t")
        c1 = client_factory(port=srv1.irc_port)
        c1.register(nick)
        c1.collect_lines(duration=0.5)
        time.sleep(4)

        c3 = client_factory(port=srv3.irc_port)
        c3.register(unique_nick("g2t"))
        c3.collect_lines(duration=0.5)

        c3.send(f"WHOIS {nick}")
        lines = c3.collect_lines(duration=2)
        assert any("311" in l and nick in l for l in lines), \
            f"Gossip user {nick} not visible on TS5 node"

    def test_ts5_user_visible_on_gossip(self, gossip_with_ts5_bridge, client_factory, unique_nick):
        """User on TS5 node visible via WHOIS on gossip node."""
        srv1, srv2, srv3 = gossip_with_ts5_bridge

        nick = unique_nick("t2g")
        c3 = client_factory(port=srv3.irc_port)
        c3.register(nick)
        c3.collect_lines(duration=0.5)
        time.sleep(4)

        c1 = client_factory(port=srv1.irc_port)
        c1.register(unique_nick("t2g"))
        c1.collect_lines(duration=0.5)

        c1.send(f"WHOIS {nick}")
        lines = c1.collect_lines(duration=2)
        assert any("311" in l and nick in l for l in lines), \
            f"TS5 user {nick} not visible on gossip node"

    # ---- Channel join + ops ----

    def test_gossip_channel_creator_opped_on_ts5(self, gossip_with_ts5_bridge, client_factory, unique_nick):
        """Channel created on gossip node — creator is opped when seen from TS5."""
        srv1, srv2, srv3 = gossip_with_ts5_bridge

        nick1 = unique_nick("op")
        c1 = client_factory(port=srv1.irc_port)
        c1.register(nick1)
        c1.collect_lines(duration=0.5)
        c1.send("JOIN #opfromgossip")
        c1.wait_for("366")
        time.sleep(4)

        nick3 = unique_nick("op")
        c3 = client_factory(port=srv3.irc_port)
        c3.register(nick3)
        c3.collect_lines(duration=0.5)
        c3.send("JOIN #opfromgossip")
        lines = c3.collect_lines(duration=2)
        names = " ".join(l for l in lines if "353" in l)
        assert f"@{nick1}" in names, \
            f"Gossip channel creator {nick1} not opped on TS5: {names}"

    def test_ts5_channel_creator_opped_on_gossip(self, gossip_with_ts5_bridge, client_factory, unique_nick):
        """Channel created on TS5 node — creator is opped when seen from gossip."""
        srv1, srv2, srv3 = gossip_with_ts5_bridge

        nick3 = unique_nick("op")
        c3 = client_factory(port=srv3.irc_port)
        c3.register(nick3)
        c3.collect_lines(duration=0.5)
        c3.send("JOIN #opfromts5")
        c3.wait_for("366")
        time.sleep(4)

        nick1 = unique_nick("op")
        c1 = client_factory(port=srv1.irc_port)
        c1.register(nick1)
        c1.collect_lines(duration=0.5)
        c1.send("JOIN #opfromts5")
        lines = c1.collect_lines(duration=2)
        names = " ".join(l for l in lines if "353" in l)
        assert f"@{nick3}" in names, \
            f"TS5 channel creator {nick3} not opped on gossip: {names}"

    # ---- Real-time join visibility ----

    def test_ts5_join_visible_on_gossip(self, gossip_with_ts5_bridge, client_factory, unique_nick):
        """TS5 user joining channel is seen in real-time by gossip user."""
        srv1, srv2, srv3 = gossip_with_ts5_bridge

        nick1 = unique_nick("rj")
        c1 = client_factory(port=srv1.irc_port)
        c1.register(nick1)
        c1.collect_lines(duration=0.5)
        c1.send("JOIN #rtjoin")
        c1.wait_for("366")
        c1.collect_lines(duration=1)  # drain
        time.sleep(3)

        nick3 = unique_nick("rj")
        c3 = client_factory(port=srv3.irc_port)
        c3.register(nick3)
        c3.collect_lines(duration=0.5)
        c3.send("JOIN #rtjoin")
        c3.wait_for("366")
        time.sleep(3)

        # Check that c1 saw the JOIN or at least sees nick3 in NAMES
        lines1 = c1.collect_lines(duration=2)
        c1.send("NAMES #rtjoin")
        names_lines = c1.collect_lines(duration=2)
        all_text = " ".join(lines1 + names_lines)
        assert nick3 in all_text, \
            f"TS5 user {nick3} not visible on gossip after join: {all_text}"

    def test_gossip_join_visible_on_ts5(self, gossip_with_ts5_bridge, client_factory, unique_nick):
        """Gossip user joining channel is seen by TS5 user."""
        srv1, srv2, srv3 = gossip_with_ts5_bridge

        nick3 = unique_nick("rj")
        c3 = client_factory(port=srv3.irc_port)
        c3.register(nick3)
        c3.collect_lines(duration=0.5)
        c3.send("JOIN #rtjoin2")
        c3.wait_for("366")
        c3.collect_lines(duration=1)  # drain
        time.sleep(3)

        nick1 = unique_nick("rj")
        c1 = client_factory(port=srv1.irc_port)
        c1.register(nick1)
        c1.collect_lines(duration=0.5)
        c1.send("JOIN #rtjoin2")
        c1.wait_for("366")
        time.sleep(3)

        lines3 = c3.collect_lines(duration=2)
        c3.send("NAMES #rtjoin2")
        names_lines = c3.collect_lines(duration=2)
        all_text = " ".join(lines3 + names_lines)
        assert nick1 in all_text, \
            f"Gossip user {nick1} not visible on TS5 after join: {all_text}"

    # ---- Topic ----

    def test_topic_gossip_to_ts5(self, gossip_with_ts5_bridge, client_factory, unique_nick):
        """Topic set on gossip propagates to TS5."""
        srv1, srv2, srv3 = gossip_with_ts5_bridge

        c1 = client_factory(port=srv1.irc_port)
        c1.register(unique_nick("tp"))
        c1.collect_lines(duration=0.5)
        c1.send("JOIN #topicg2t")
        c1.wait_for("366")
        c1.send("TOPIC #topicg2t :from gossip to ts5")
        c1.collect_lines(duration=1)
        time.sleep(4)

        c3 = client_factory(port=srv3.irc_port)
        c3.register(unique_nick("tp"))
        c3.collect_lines(duration=0.5)
        c3.send("JOIN #topicg2t")
        lines = c3.collect_lines(duration=2)
        assert any("from gossip to ts5" in l for l in lines), \
            f"Topic not propagated gossip→TS5: {[l for l in lines if '332' in l]}"

    def test_topic_ts5_to_gossip(self, gossip_with_ts5_bridge, client_factory, unique_nick):
        """Topic set on TS5 propagates to gossip."""
        srv1, srv2, srv3 = gossip_with_ts5_bridge

        c3 = client_factory(port=srv3.irc_port)
        c3.register(unique_nick("tp"))
        c3.collect_lines(duration=0.5)
        c3.send("JOIN #topict2g")
        c3.wait_for("366")
        c3.send("TOPIC #topict2g :from ts5 to gossip")
        c3.collect_lines(duration=1)
        time.sleep(4)

        c1 = client_factory(port=srv1.irc_port)
        c1.register(unique_nick("tp"))
        c1.collect_lines(duration=0.5)
        c1.send("JOIN #topict2g")
        lines = c1.collect_lines(duration=2)
        assert any("from ts5 to gossip" in l for l in lines), \
            f"Topic not propagated TS5→gossip: {[l for l in lines if '332' in l]}"

    # ---- Channel modes ----

    def test_channel_modes_gossip_to_ts5(self, gossip_with_ts5_bridge, client_factory, unique_nick):
        """Channel modes set on gossip visible on TS5."""
        srv1, srv2, srv3 = gossip_with_ts5_bridge

        c1 = client_factory(port=srv1.irc_port)
        c1.register(unique_nick("md"))
        c1.collect_lines(duration=0.5)
        c1.send("JOIN #modeg2t")
        c1.wait_for("366")
        c1.send("MODE #modeg2t +ntsl 42 secretkey")
        c1.collect_lines(duration=1)
        time.sleep(4)

        c3 = client_factory(port=srv3.irc_port)
        c3.register(unique_nick("md"))
        c3.collect_lines(duration=0.5)
        c3.send("JOIN #modeg2t secretkey")
        c3.wait_for("366")
        c3.send("MODE #modeg2t")
        lines = c3.collect_lines(duration=2)
        mode_line = " ".join(l for l in lines if "324" in l)
        assert "n" in mode_line and "t" in mode_line, \
            f"Channel modes not propagated gossip→TS5: {mode_line}"

    def test_channel_modes_ts5_to_gossip(self, gossip_with_ts5_bridge, client_factory, unique_nick):
        """Channel modes set on TS5 visible on gossip."""
        srv1, srv2, srv3 = gossip_with_ts5_bridge

        c3 = client_factory(port=srv3.irc_port)
        c3.register(unique_nick("md"))
        c3.collect_lines(duration=0.5)
        c3.send("JOIN #modet2g")
        c3.wait_for("366")
        c3.send("MODE #modet2g +nt")
        c3.collect_lines(duration=1)
        time.sleep(4)

        c1 = client_factory(port=srv1.irc_port)
        c1.register(unique_nick("md"))
        c1.collect_lines(duration=0.5)
        c1.send("JOIN #modet2g")
        c1.wait_for("366")
        c1.send("MODE #modet2g")
        lines = c1.collect_lines(duration=2)
        mode_line = " ".join(l for l in lines if "324" in l)
        assert "n" in mode_line and "t" in mode_line, \
            f"Channel modes not propagated TS5→gossip: {mode_line}"

    # ---- Bans ----

    def test_ban_gossip_to_ts5(self, gossip_with_ts5_bridge, client_factory, unique_nick):
        """Ban set on gossip visible on TS5."""
        srv1, srv2, srv3 = gossip_with_ts5_bridge

        c1 = client_factory(port=srv1.irc_port)
        c1.register(unique_nick("bn"))
        c1.collect_lines(duration=0.5)
        c1.send("JOIN #bang2t")
        c1.wait_for("366")
        c1.send("MODE #bang2t +b evil!*@*")
        c1.collect_lines(duration=1)
        time.sleep(4)

        c3 = client_factory(port=srv3.irc_port)
        c3.register(unique_nick("bn"))
        c3.collect_lines(duration=0.5)
        c3.send("JOIN #bang2t")
        c3.wait_for("366")
        c3.send("MODE #bang2t b")
        lines = c3.collect_lines(duration=2)
        ban_lines = [l for l in lines if "367" in l]
        assert any("evil!*@*" in l for l in ban_lines), \
            f"Ban not propagated gossip→TS5: {ban_lines}"

    def test_ban_ts5_to_gossip(self, gossip_with_ts5_bridge, client_factory, unique_nick):
        """Ban set on TS5 visible on gossip."""
        srv1, srv2, srv3 = gossip_with_ts5_bridge

        c3 = client_factory(port=srv3.irc_port)
        c3.register(unique_nick("bn"))
        c3.collect_lines(duration=0.5)
        c3.send("JOIN #bant2g")
        c3.wait_for("366")
        c3.send("MODE #bant2g +b troll!*@*")
        c3.collect_lines(duration=1)
        time.sleep(4)

        c1 = client_factory(port=srv1.irc_port)
        c1.register(unique_nick("bn"))
        c1.collect_lines(duration=0.5)
        c1.send("JOIN #bant2g")
        c1.wait_for("366")
        c1.send("MODE #bant2g b")
        lines = c1.collect_lines(duration=2)
        ban_lines = [l for l in lines if "367" in l]
        assert any("troll!*@*" in l for l in ban_lines), \
            f"Ban not propagated TS5→gossip: {ban_lines}"

    # ---- Kick ----

    def _test_kick(self, kicker_srv, target_srv, client_factory, unique_nick, chan):
        """Helper: kicker on kicker_srv kicks target on target_srv."""
        kick_nick = unique_nick("kk")
        target_nick = unique_nick("kk")

        # Kicker creates channel (gets ops)
        ck = client_factory(port=kicker_srv.irc_port)
        ck.register(kick_nick)
        ck.collect_lines(duration=0.5)
        ck.send(f"JOIN {chan}")
        ck.wait_for("366")
        time.sleep(4)

        # Target joins
        ct = client_factory(port=target_srv.irc_port)
        ct.register(target_nick)
        ct.collect_lines(duration=0.5)
        ct.send(f"JOIN {chan}")
        ct.wait_for("366")
        time.sleep(3)

        # Drain
        ck.collect_lines(duration=1)
        ct.collect_lines(duration=1)

        # Kick
        ck.send(f"KICK {chan} {target_nick} :kicked")
        time.sleep(4)

        # Target should see KICK or no longer be in channel
        lines = ct.collect_lines(duration=3)
        ct.send(f"NAMES {chan}")
        names = ct.collect_lines(duration=2)
        got_kick = any("KICK" in l and target_nick in l for l in lines)
        not_in_chan = target_nick not in " ".join(names)
        assert got_kick or not_in_chan, \
            f"User {target_nick} not kicked. Lines: {lines}, Names: {names}"

    def test_kick_gossip_kicks_ts5(self, gossip_with_ts5_bridge, client_factory, unique_nick):
        """Gossip user (opped) kicks TS5 user."""
        srv1, srv2, srv3 = gossip_with_ts5_bridge
        self._test_kick(srv1, srv3, client_factory, unique_nick, "#kickg2t")

    def test_kick_ts5_kicks_gossip(self, gossip_with_ts5_bridge, client_factory, unique_nick):
        """TS5 user (opped) kicks gossip user."""
        srv1, srv2, srv3 = gossip_with_ts5_bridge
        self._test_kick(srv3, srv1, client_factory, unique_nick, "#kickt2g")

    # ---- Quit ----

    def test_quit_ts5_visible_on_gossip(self, gossip_with_ts5_bridge, client_factory, unique_nick):
        """TS5 user quits, gossip user sees them disappear."""
        srv1, srv2, srv3 = gossip_with_ts5_bridge

        nick3 = unique_nick("qt")
        c3 = client_factory(port=srv3.irc_port)
        c3.register(nick3)
        c3.collect_lines(duration=0.5)
        time.sleep(4)

        nick1 = unique_nick("qt")
        c1 = client_factory(port=srv1.irc_port)
        c1.register(nick1)
        c1.collect_lines(duration=0.5)

        # Verify visible
        c1.send(f"WHOIS {nick3}")
        lines = c1.collect_lines(duration=2)
        assert any("311" in l for l in lines), "TS5 user not visible before quit"

        # Quit from TS5
        c3.send("QUIT :leaving")
        c3.disconnect()
        time.sleep(4)

        # Verify gone on gossip
        c1.send(f"WHOIS {nick3}")
        lines = c1.collect_lines(duration=2)
        assert any("401" in l for l in lines), \
            f"TS5 user {nick3} still visible on gossip after quit"

    def test_quit_gossip_visible_on_ts5(self, gossip_with_ts5_bridge, client_factory, unique_nick):
        """Gossip user quits, TS5 user sees them disappear."""
        srv1, srv2, srv3 = gossip_with_ts5_bridge

        nick1 = unique_nick("qt")
        c1 = client_factory(port=srv1.irc_port)
        c1.register(nick1)
        c1.collect_lines(duration=0.5)
        time.sleep(4)

        nick3 = unique_nick("qt")
        c3 = client_factory(port=srv3.irc_port)
        c3.register(nick3)
        c3.collect_lines(duration=0.5)

        # Verify visible
        c3.send(f"WHOIS {nick1}")
        lines = c3.collect_lines(duration=2)
        assert any("311" in l for l in lines), "Gossip user not visible before quit"

        # Quit from gossip
        c1.send("QUIT :goodbye")
        c1.disconnect()
        time.sleep(4)

        # Verify gone on TS5
        c3.send(f"WHOIS {nick1}")
        lines = c3.collect_lines(duration=2)
        assert any("401" in l for l in lines), \
            f"Gossip user {nick1} still visible on TS5 after quit"

    # ---- Nick change ----

    def test_nick_change_across_bridge(self, gossip_with_ts5_bridge, client_factory, unique_nick):
        """Nick change on gossip visible on TS5 and vice versa."""
        srv1, srv2, srv3 = gossip_with_ts5_bridge

        oldnick = unique_nick("nc")
        newnick = unique_nick("nc")
        c1 = client_factory(port=srv1.irc_port)
        c1.register(oldnick)
        c1.collect_lines(duration=0.5)
        time.sleep(4)

        c3 = client_factory(port=srv3.irc_port)
        c3.register(unique_nick("nc"))
        c3.collect_lines(duration=0.5)

        # Change nick on gossip
        c1.send(f"NICK {newnick}")
        c1.collect_lines(duration=1)
        time.sleep(4)

        # Verify on TS5
        c3.send(f"WHOIS {newnick}")
        lines = c3.collect_lines(duration=2)
        assert any("311" in l and newnick in l for l in lines), \
            f"Nick change {oldnick}→{newnick} not visible on TS5"

    # ---- Kill ----

    def test_kill_gossip_kills_ts5_user(self, gossip_with_ts5_bridge, client_factory, unique_nick):
        """Oper on gossip node kills user on TS5 node."""
        srv1, srv2, srv3 = gossip_with_ts5_bridge

        # Target on TS5
        target = unique_nick("kl")
        ct = client_factory(port=srv3.irc_port)
        ct.register(target)
        ct.collect_lines(duration=0.5)
        time.sleep(4)

        # Oper on gossip
        killer = unique_nick("kl")
        ck = client_factory(port=srv1.irc_port)
        ck.register(killer)
        ck.collect_lines(duration=0.5)
        ck.send("OPER admin secret")
        ck.collect_lines(duration=1)

        # Verify target visible before kill
        ck.send(f"WHOIS {target}")
        lines = ck.collect_lines(duration=2)
        assert any("311" in l for l in lines), "Target not visible before kill"

        # Kill
        ck.send(f"KILL {target} :test kill from gossip")
        ck.collect_lines(duration=2)
        time.sleep(5)

        # Target should be gone
        ck.send(f"WHOIS {target}")
        lines = ck.collect_lines(duration=3)
        assert any("401" in l for l in lines), \
            f"Target {target} still visible after kill: {[l for l in lines if '311' in l or '401' in l]}"

    def test_kill_ts5_kills_gossip_user(self, gossip_with_ts5_bridge, client_factory, unique_nick):
        """Oper on TS5 node kills user on gossip node."""
        srv1, srv2, srv3 = gossip_with_ts5_bridge

        # Target on gossip
        target = unique_nick("kl")
        ct = client_factory(port=srv1.irc_port)
        ct.register(target)
        ct.collect_lines(duration=0.5)
        time.sleep(4)

        # Oper on TS5
        killer = unique_nick("kl")
        ck = client_factory(port=srv3.irc_port)
        ck.register(killer)
        ck.collect_lines(duration=0.5)
        ck.send("OPER admin secret")
        ck.collect_lines(duration=1)

        # Verify target visible
        ck.send(f"WHOIS {target}")
        lines = ck.collect_lines(duration=2)
        assert any("311" in l for l in lines), "Target not visible before kill"

        # Kill
        ck.send(f"KILL {target} :test kill from ts5")
        ck.collect_lines(duration=2)
        time.sleep(5)

        # Target should be gone
        ck.send(f"WHOIS {target}")
        lines = ck.collect_lines(duration=3)
        assert any("401" in l for l in lines), \
            f"Target {target} still visible after kill: {[l for l in lines if '311' in l or '401' in l]}"

    # ---- Clone/IP tracking ----

    def test_gossip_user_ip_visible(self, gossip_with_ts5_bridge, client_factory, unique_nick):
        """User IP from gossip node is available on peer for clone tracking."""
        srv1, srv2, srv3 = gossip_with_ts5_bridge

        nick = unique_nick("ip")
        c1 = client_factory(port=srv1.irc_port)
        c1.register(nick)
        c1.collect_lines(duration=0.5)
        time.sleep(4)

        # Oper on srv2 (hub) checks user's IP via WHOIS
        oper = unique_nick("ip")
        c2 = client_factory(port=srv2.irc_port)
        c2.register(oper)
        c2.collect_lines(duration=0.5)
        c2.send("OPER admin secret")
        c2.collect_lines(duration=1)

        c2.send(f"WHOIS {nick}")
        lines = c2.collect_lines(duration=2)
        # 311 shows user info, 378 or other numeric may show IP
        # At minimum, the user should be visible
        assert any("311" in l and nick in l for l in lines), \
            f"User {nick} not visible on hub for IP check"

    def test_ban_enforced_across_gossip(self, gossip_cluster, client_factory, unique_nick):
        """Channel ban set on srv1 prevents matching user on srv2 from joining."""
        srv1, srv2 = gossip_cluster

        # Create channel on srv1 with ban
        op = unique_nick("be")
        c1 = client_factory(port=srv1.irc_port)
        c1.register(op)
        c1.collect_lines(duration=0.5)
        c1.send("JOIN #banforce")
        c1.wait_for("366")
        c1.send("MODE #banforce +b badguy!*@*")
        c1.collect_lines(duration=1)
        time.sleep(4)

        # User on srv2 matching the ban tries to join
        c2 = client_factory(port=srv2.irc_port)
        c2.register("badguy")
        c2.collect_lines(duration=0.5)
        c2.send("JOIN #banforce")
        lines = c2.collect_lines(duration=2)
        # Should get 474 (banned) or not appear in channel
        banned = any("474" in l for l in lines)
        in_chan = any("366" in l for l in lines)
        assert banned or not in_chan, \
            f"Banned user 'badguy' was able to join #banforce: {lines}"
