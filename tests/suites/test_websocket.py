"""WebSocket transport (RFC 6455) tests."""

import base64
import hashlib
import os
import socket
import time

import pytest

from tests.harness.ws_client import WebSocketIRCClient

_WS_GUID = "258EAFA5-E914-47DA-95CA-5AB5DC085B6A"


class TestWebSocket:

    def test_ws_handshake(self, single_server):
        """HTTP upgrade → 101 with correct Sec-WebSocket-Accept header."""
        ws = WebSocketIRCClient(port=single_server.ws_port)
        response = ws.connect()
        assert "101" in response
        assert "Upgrade" in response or "upgrade" in response

        # Verify accept key
        expected = base64.b64encode(
            hashlib.sha1((ws._key + _WS_GUID).encode()).digest()
        ).decode()
        assert expected in response
        ws.disconnect()

    def test_ws_registration(self, single_server, unique_nick):
        """NICK + USER over WebSocket completes registration."""
        nick = unique_nick("ws")
        ws = WebSocketIRCClient(port=single_server.ws_port)
        ws.connect()
        welcome = ws.register(nick)
        assert "001" in welcome
        ws.disconnect()

    def test_ws_privmsg(self, single_server, unique_nick):
        """Send and receive PRIVMSG over WebSocket."""
        nick1 = unique_nick("ws")
        nick2 = unique_nick("ws")

        ws1 = WebSocketIRCClient(port=single_server.ws_port)
        ws1.connect()
        ws1.register(nick1)
        ws1.collect_lines = lambda duration=0.5: _ws_collect(ws1, duration)

        ws2 = WebSocketIRCClient(port=single_server.ws_port)
        ws2.connect()
        ws2.register(nick2)

        # Drain welcome bursts
        _ws_collect(ws1, 0.5)
        _ws_collect(ws2, 0.5)

        # Join a channel
        ws1.send("JOIN #wstest")
        ws1.wait_for("366")
        ws2.send("JOIN #wstest")
        ws2.wait_for("366")
        _ws_collect(ws1, 0.3)

        ws1.send("PRIVMSG #wstest :hello over websocket")
        line = ws2.wait_for("PRIVMSG")
        assert "hello over websocket" in line

        ws1.disconnect()
        ws2.disconnect()

    def test_ws_ping_pong(self, single_server, unique_nick):
        """WebSocket PING frame gets PONG response."""
        nick = unique_nick("ws")
        ws = WebSocketIRCClient(port=single_server.ws_port)
        ws.connect()
        ws.register(nick)
        _ws_collect(ws, 0.5)

        # Send WS PING
        ws.send_ws_ping(b"test_ping")
        # The recv_line handles WS PING/PONG internally
        # Just verify connection still works
        ws.send("VERSION")
        ws.wait_for("351")
        ws.disconnect()

    def test_ws_bad_handshake(self, single_server):
        """Invalid WebSocket handshake gets rejected."""
        sock = socket.create_connection(("127.0.0.1", single_server.ws_port), timeout=5)
        try:
            # Send a non-WebSocket HTTP request
            request = (
                "GET / HTTP/1.1\r\n"
                "Host: 127.0.0.1\r\n"
                "Connection: keep-alive\r\n"
                "\r\n"
            )
            sock.sendall(request.encode())
            response = b""
            sock.settimeout(2)
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass
            decoded = response.decode("utf-8", errors="replace")
            # Should get 400 or connection close (not 101)
            assert "101" not in decoded
        finally:
            sock.close()

    # ---- IRCv3 WebSocket subprotocol negotiation -------------------------

    def test_ws_subproto_text(self, single_server, unique_nick):
        """text.ircv3.net is accepted and echoed; registration works."""
        ws = WebSocketIRCClient(port=single_server.ws_port,
                                subprotocols=["text.ircv3.net"])
        ws.connect()
        assert ws.negotiated_subprotocol == "text.ircv3.net"
        assert "001" in ws.register(unique_nick("ws"))
        ws.disconnect()

    def test_ws_subproto_binary(self, single_server, unique_nick):
        """binary.ircv3.net is echoed; client using BINARY frames registers."""
        ws = WebSocketIRCClient(port=single_server.ws_port,
                                subprotocols=["binary.ircv3.net"], binary=True)
        ws.connect()
        assert ws.negotiated_subprotocol == "binary.ircv3.net"
        assert "001" in ws.register(unique_nick("ws"))
        ws.disconnect()

    def test_ws_subproto_legacy_irc(self, single_server, unique_nick):
        """Legacy 'irc' subprotocol still negotiates (back-compat)."""
        ws = WebSocketIRCClient(port=single_server.ws_port, subprotocols=["irc"])
        ws.connect()
        assert ws.negotiated_subprotocol == "irc"
        assert "001" in ws.register(unique_nick("ws"))
        ws.disconnect()

    def test_ws_subproto_preference_order(self, single_server, unique_nick):
        """Server honors the client's preference order, not its own.

        Both clients offer the same two subprotocols in opposite order; each
        must get its own first choice.  ws1 is registered before ws2 connects
        so the per-IP accept throttle (which counts every connection and is
        only cleared on registration under a NOTHROTTLE allow block) doesn't
        drop the second connection.
        """
        ws1 = WebSocketIRCClient(
            port=single_server.ws_port,
            subprotocols=["binary.ircv3.net", "text.ircv3.net"], binary=True)
        ws1.connect()
        assert ws1.negotiated_subprotocol == "binary.ircv3.net"
        ws1.register(unique_nick("ws"))

        ws2 = WebSocketIRCClient(
            port=single_server.ws_port,
            subprotocols=["text.ircv3.net", "binary.ircv3.net"])
        ws2.connect()
        assert ws2.negotiated_subprotocol == "text.ircv3.net"
        ws2.register(unique_nick("ws"))

        ws1.disconnect()
        ws2.disconnect()

    def test_ws_subproto_unknown_omitted(self, single_server, unique_nick):
        """An unsupported-only offer → no Sec-WebSocket-Protocol echoed, but
        the connection still upgrades and works (spec MAY continue)."""
        ws = WebSocketIRCClient(port=single_server.ws_port,
                                subprotocols=["chat.example.com"])
        ws.connect()
        assert ws.negotiated_subprotocol is None
        assert "001" in ws.register(unique_nick("ws"))
        ws.disconnect()

    def test_ws_text_utf8_scrub(self, single_server, unique_nick):
        """Server MUST NOT relay non-UTF-8 to a text client: invalid bytes are
        scrubbed to U+FFFD (EF BF BD), never passed raw."""
        a = WebSocketIRCClient(port=single_server.ws_port,
                               subprotocols=["text.ircv3.net"])
        a.connect()
        a.register(unique_nick("wsa"))

        b = WebSocketIRCClient(port=single_server.ws_port,
                               subprotocols=["binary.ircv3.net"], binary=True)
        b.connect()
        b.register(unique_nick("wsb"))

        _ws_collect(a, 0.5)
        _ws_collect(b, 0.5)
        a.send("JOIN #scrub"); a.wait_for("366")
        b.send("JOIN #scrub"); b.wait_for("366")
        _ws_collect(a, 0.3)

        # B injects a channel message containing raw non-UTF-8 bytes via a
        # BINARY frame (the server accepts binary input as line data).
        b.send_raw_frame(b"PRIVMSG #scrub :bad\xff\xfebytes")

        # A (text client) must receive it as valid UTF-8 with U+FFFD in place
        # of the invalid bytes.
        deadline = time.monotonic() + 5
        payload = None
        while time.monotonic() < deadline:
            p = a.recv_data_raw(timeout=deadline - time.monotonic())
            if p is not None and b"PRIVMSG" in p and b"#scrub" in p:
                payload = p
                break
        assert payload is not None, "text client never received the message"
        assert b"\xff" not in payload and b"\xfe" not in payload, \
            "raw non-UTF-8 bytes were relayed to a text client"
        assert b"\xef\xbf\xbd" in payload, "invalid bytes were not scrubbed to U+FFFD"
        payload.decode("utf-8")  # must not raise

        a.disconnect()
        b.disconnect()


def _ws_collect(ws, duration):
    """Collect lines from a WS client for a duration."""
    lines = []
    deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        line = ws.recv_line(timeout=deadline - time.monotonic())
        if line is not None:
            lines.append(line)
    return lines
