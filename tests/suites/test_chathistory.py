"""IRCv3 draft/chathistory tests."""

import time

import pytest

from tests.harness.irc_client import IRCClient
from tests.harness.assertions import parse_irc_line


class TestChathistory:

    def _make_client(self, client_factory, single_server, unique_nick):
        nick = unique_nick("ch")
        c = client_factory(port=single_server.irc_port)
        c.register_with_caps(nick, ["draft/chathistory", "batch", "message-tags", "server-time"])
        c.collect_lines(duration=1)
        return c, nick

    def test_latest(self, single_server, client_factory, unique_nick):
        """CHATHISTORY LATEST returns recent messages in a batch."""
        c1, nick1 = self._make_client(client_factory, single_server, unique_nick)
        c2, nick2 = self._make_client(client_factory, single_server, unique_nick)

        c1.send("JOIN #chattest")
        c1.wait_for("366")
        c2.send("JOIN #chattest")
        c2.wait_for("366")
        c1.collect_lines(duration=0.5)
        c2.collect_lines(duration=0.5)

        # Send some messages
        for i in range(3):
            c1.send(f"PRIVMSG #chattest :message {i}")
            time.sleep(0.1)
        time.sleep(1)

        # Query history
        c2.send("CHATHISTORY LATEST #chattest * 10")
        # Should get a BATCH start
        batch_line = c2.wait_for("BATCH", timeout=5)
        assert "chathistory" in batch_line

        # Collect messages within the batch
        lines = c2.collect_lines(duration=2)
        msg_count = sum(1 for l in lines if "PRIVMSG" in l and "message" in l)
        assert msg_count >= 2, f"Expected at least 2 messages, got {msg_count}: {lines}"

    def test_before(self, single_server, client_factory, unique_nick):
        """CHATHISTORY BEFORE timestamp returns older messages."""
        c1, nick1 = self._make_client(client_factory, single_server, unique_nick)

        c1.send("JOIN #chatbefore")
        c1.wait_for("366")
        c1.collect_lines(duration=0.3)

        # Send messages
        for i in range(5):
            c1.send(f"PRIVMSG #chatbefore :msg {i}")
            time.sleep(0.1)
        time.sleep(1)

        # Use a far future timestamp to get all messages
        c1.send("CHATHISTORY BEFORE #chatbefore timestamp=2099-01-01T00:00:00.000Z 10")
        c1.wait_for("BATCH", timeout=5)
        lines = c1.collect_lines(duration=2)
        msg_count = sum(1 for l in lines if "PRIVMSG" in l and "msg" in l)
        assert msg_count >= 3, f"Expected at least 3 messages, got {msg_count}: {lines}"

    def test_targets(self, single_server, client_factory, unique_nick):
        """CHATHISTORY TARGETS lists channels with recent activity."""
        c1, nick1 = self._make_client(client_factory, single_server, unique_nick)

        c1.send("JOIN #targetstest")
        c1.wait_for("366")
        c1.collect_lines(duration=0.3)

        c1.send("PRIVMSG #targetstest :hello")
        time.sleep(1)

        c1.send("CHATHISTORY TARGETS timestamp=2020-01-01T00:00:00.000Z timestamp=2099-01-01T00:00:00.000Z 10")
        c1.wait_for("BATCH", timeout=5)
        lines = c1.collect_lines(duration=2)
        # Should see #targetstest in the results
        found = any("#targetstest" in l for l in lines)
        assert found, f"#targetstest not found in TARGETS output: {lines}"

    def test_cap_required(self, single_server, client_factory, unique_nick):
        """CHATHISTORY without the cap enabled should fail."""
        nick = unique_nick("ch")
        c = client_factory(port=single_server.irc_port)
        c.register(nick)  # No caps
        c.collect_lines(duration=0.5)
        c.send("JOIN #chatnocap")
        c.wait_for("366")

        c.send("CHATHISTORY LATEST #chatnocap * 10")
        # Should get an error (unknown command or permission denied)
        line = c.wait_for_any(["421", "CAP", "FAIL", "ERR"], timeout=3)
