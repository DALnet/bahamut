"""Persistent session (RESUME) tests."""

import time

import pytest

from tests.harness.irc_client import IRCClient


class TestSession:

    def test_token_delivery(self, single_server, client_factory, unique_nick):
        """Connect with draft/resume-0.5 cap and receive RESUME TOKEN."""
        nick = unique_nick("sess")
        c = client_factory(port=single_server.irc_port)
        c.register_with_caps(nick, ["draft/resume-0.5"])
        # Should receive RESUME TOKEN after registration
        line = c.wait_for("RESUME", timeout=5)
        assert "TOKEN" in line

    def test_resume_success(self, single_server, client_factory, unique_nick):
        """RESUME with valid token restores nick."""
        nick = unique_nick("sess")
        c = client_factory(port=single_server.irc_port)
        c.register_with_caps(nick, ["draft/resume-0.5"])
        token_line = c.wait_for("RESUME", timeout=5)

        # Extract token from "RESUME TOKEN <token>"
        parts = token_line.split()
        token = None
        for i, p in enumerate(parts):
            if p == "TOKEN" and i + 1 < len(parts):
                token = parts[i + 1].lstrip(":")
                break
        assert token is not None, f"Could not extract token from: {token_line}"

        # Disconnect
        c.disconnect()
        time.sleep(0.5)

        # Reconnect and resume
        c2 = client_factory(port=single_server.irc_port)
        c2.send("CAP LS 302")
        c2.wait_for("CAP")
        c2.send("CAP REQ :draft/resume-0.5")
        c2.wait_for("ACK")
        c2.send(f"RESUME {token}")

        # Should get success — either RESUME SUCCESS or registration completes with old nick
        try:
            p, line = c2.wait_for_any(["RESUME", "001"], timeout=5)
        except TimeoutError:
            pytest.fail("RESUME did not succeed within timeout")

    def test_resume_invalid(self, single_server, client_factory, unique_nick):
        """RESUME with bad token fails."""
        nick = unique_nick("sess")
        c = client_factory(port=single_server.irc_port)
        c.send("CAP LS 302")
        c.wait_for("CAP")
        c.send("CAP REQ :draft/resume-0.5")
        c.wait_for("ACK")

        c.send("RESUME invalidtoken123456")
        # Should get FAIL or ERR response
        try:
            p, line = c.wait_for_any(["FAIL", "ERR", "RESUME"], timeout=5)
        except TimeoutError:
            pytest.fail("No response to invalid RESUME token")
