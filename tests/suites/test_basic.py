"""Basic IRC functionality tests — connect, register, PING/PONG, QUIT, OPER."""

import time

import pytest

from tests.harness.irc_client import IRCClient


class TestBasic:
    """Core connection and registration tests."""

    def test_connect_welcome(self, single_server, client_factory, unique_nick):
        """TCP connect and receive 001-004 welcome numerics."""
        nick = unique_nick()
        c = client_factory(port=single_server.irc_port)
        c.send(f"NICK {nick}")
        c.send(f"USER {nick} 0 * :{nick}")

        # Should receive RPL_WELCOME (001) through RPL_MYINFO (004)
        c.wait_for("001")
        c.wait_for("002")
        c.wait_for("003")
        c.wait_for("004")

    def test_registration(self, single_server, client_factory, unique_nick):
        """NICK + USER completes registration with welcome."""
        nick = unique_nick()
        c = client_factory(port=single_server.irc_port)
        welcome = c.register(nick)
        assert nick in welcome

    def test_ping_pong(self, single_server, client_factory, unique_nick):
        """Server PING is auto-responded to by client (keeping connection alive)."""
        nick = unique_nick()
        c = client_factory(port=single_server.irc_port)
        c.register(nick)
        # The IRCClient auto-responds to PING. Just verify connection stays alive
        # by sending a command and getting a response.
        c.send("VERSION")
        # We should get a version reply, not a connection drop
        c.wait_for("351")

    def test_quit(self, single_server, client_factory, unique_nick):
        """QUIT with message closes connection cleanly."""
        nick = unique_nick()
        c = client_factory(port=single_server.irc_port)
        c.register(nick)
        # Drain the welcome burst (002-005, 251, 265, 266, 422, MODE, etc.)
        c.collect_lines(duration=1)
        c.send("QUIT :goodbye")
        # Should get ERROR :Closing Link or connection close
        deadline = time.monotonic() + 3
        got_error = False
        while time.monotonic() < deadline:
            line = c.recv_line(timeout=1)
            if line is None:
                break
            if "ERROR" in line or "QUIT" in line:
                got_error = True
                break
        # Either we got an ERROR line or connection was closed (both valid)
        assert got_error or line is None

    def test_multi_client(self, single_server, client_factory, unique_nick):
        """Multiple clients can connect and register simultaneously."""
        clients = []
        nicks = []
        for _ in range(5):
            nick = unique_nick()
            nicks.append(nick)
            c = client_factory(port=single_server.irc_port)
            c.register(nick)
            clients.append(c)

        # All clients should be able to send LUSERS and get a response
        for c in clients:
            c.send("LUSERS")
            c.wait_for("251")

    def test_invalid_nick(self, single_server, client_factory):
        """Bad nick characters produce ERR_ERRONEUSNICKNAME (432)."""
        c = client_factory(port=single_server.irc_port)
        c.send("NICK @badnick")
        c.send("USER test 0 * :test")
        c.wait_for("432")

    def test_double_registration(self, single_server, client_factory, unique_nick):
        """Sending NICK/USER twice produces ERR_ALREADYREGISTRED (462)."""
        nick = unique_nick()
        c = client_factory(port=single_server.irc_port)
        c.register(nick)
        c.send(f"USER {nick} 0 * :{nick}")
        c.wait_for("462")

    def test_oper(self, single_server, client_factory, unique_nick):
        """OPER with valid credentials gives RPL_YOUREOPER (381)."""
        nick = unique_nick()
        c = client_factory(port=single_server.irc_port)
        c.register(nick)
        c.send("OPER admin secret")
        c.wait_for("381")
