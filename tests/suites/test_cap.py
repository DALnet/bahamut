"""IRCv3 CAP negotiation tests."""

import re

import pytest

from tests.harness.irc_client import IRCClient


# Caps we expect to be present (from completed phases)
EXPECTED_CAPS = [
    "multi-prefix",
    "away-notify",
    "echo-message",
    "server-time",
    "message-tags",
    "userhost-in-names",
    "invite-notify",
    "setname",
    "chghost",
    "batch",
    "labeled-response",
    "draft/chathistory",
    "account-notify",
    "account-tag",
    "extended-join",
]


class TestCap:
    """IRCv3 CAP LS/REQ/END tests."""

    def _get_cap_ls(self, client):
        """Send CAP LS 302 and collect all caps from (possibly multi-line) response."""
        client.send("CAP LS 302")
        caps = {}
        while True:
            line = client.wait_for("CAP")
            # Parse caps from the line
            # Format: :server CAP * LS [*] :cap1 cap2=val ...
            parts = line.split(" ", 5)
            # The last part (after :) contains the caps
            if ":" in line:
                cap_str = line.split(":", 2)[-1] if line.count(":") >= 2 else ""
                for cap in cap_str.split():
                    if "=" in cap:
                        name, val = cap.split("=", 1)
                        caps[name] = val
                    else:
                        caps[cap] = None
            # If "LS *" is in the line, there are more lines
            if " LS * :" not in line:
                break
        return caps

    def test_cap_ls(self, single_server, client_factory, unique_nick):
        """CAP LS 302 returns a list of capabilities."""
        c = client_factory(port=single_server.irc_port)
        caps = self._get_cap_ls(c)
        assert len(caps) > 0, "No capabilities returned"

    def test_cap_req_single(self, single_server, client_factory, unique_nick):
        """REQ multi-prefix gets ACK."""
        nick = unique_nick()
        c = client_factory(port=single_server.irc_port)
        c.send("CAP LS 302")
        c.wait_for("CAP")
        c.send("CAP REQ :multi-prefix")
        line = c.wait_for("ACK")
        assert "multi-prefix" in line

    def test_cap_req_multi(self, single_server, client_factory, unique_nick):
        """REQ multiple caps at once gets ACK."""
        nick = unique_nick()
        c = client_factory(port=single_server.irc_port)
        c.send("CAP LS 302")
        c.wait_for("CAP")
        c.send("CAP REQ :multi-prefix away-notify")
        line = c.wait_for("ACK")
        assert "multi-prefix" in line
        assert "away-notify" in line

    def test_cap_req_unsupported(self, single_server, client_factory, unique_nick):
        """REQ nonexistent-cap gets NAK."""
        nick = unique_nick()
        c = client_factory(port=single_server.irc_port)
        c.send("CAP LS 302")
        c.wait_for("CAP")
        c.send("CAP REQ :nonexistent-cap-xyz")
        line = c.wait_for("NAK")
        assert "nonexistent-cap-xyz" in line

    def test_cap_end(self, single_server, client_factory, unique_nick):
        """CAP END completes registration."""
        nick = unique_nick()
        c = client_factory(port=single_server.irc_port)
        c.send("CAP LS 302")
        c.wait_for("CAP")
        c.send(f"NICK {nick}")
        c.send(f"USER {nick} 0 * :{nick}")
        c.send("CAP END")
        c.wait_for("001")

    def test_known_caps(self, single_server, client_factory, unique_nick):
        """All implemented caps should be present in LS output."""
        c = client_factory(port=single_server.irc_port)
        caps = self._get_cap_ls(c)
        missing = []
        for cap in EXPECTED_CAPS:
            if cap not in caps:
                missing.append(cap)
        assert not missing, f"Missing capabilities: {missing}\nAvailable: {list(caps.keys())}"
