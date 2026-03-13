"""WebSocket IRC client (RFC 6455 framing) — pure stdlib."""

import base64
import hashlib
import os
import re
import socket
import struct
import time


# RFC 6455 magic GUID
_WS_GUID = "258EAFA5-E914-47DA-95CA-5AB5DC085B6A"


class WebSocketIRCClient:
    """IRC client over WebSocket (RFC 6455 TEXT frames)."""

    def __init__(self, host="127.0.0.1", port=8080, timeout=5):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.buf = b""
        self.line_buf = ""
        self.all_lines = []
        self._key = None

    def connect(self):
        """Perform TCP connect + WebSocket upgrade handshake."""
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.sock.settimeout(self.timeout)

        # Generate random key
        self._key = base64.b64encode(os.urandom(16)).decode()

        # Send HTTP upgrade request
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {self._key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Protocol: irc\r\n"
            f"\r\n"
        )
        self.sock.sendall(request.encode())

        # Read HTTP response
        response = self._read_http_response()
        if "101" not in response.split("\r\n")[0]:
            raise ConnectionError(f"WebSocket handshake failed: {response}")

        # Verify accept header
        expected_accept = base64.b64encode(
            hashlib.sha1((self._key + _WS_GUID).encode()).digest()
        ).decode()
        if expected_accept not in response:
            raise ConnectionError("Invalid Sec-WebSocket-Accept")

        return response

    def connect_raw(self):
        """Connect and return raw HTTP response (for testing bad handshakes)."""
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.sock.settimeout(self.timeout)
        return self.sock

    def disconnect(self):
        """Close the connection."""
        if self.sock:
            try:
                # Send WS close frame
                self._send_frame(0x8, b"")
            except OSError:
                pass
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.sock.close()
            self.sock = None

    def send(self, line):
        """Send an IRC line over a WebSocket TEXT frame.

        Per IRCv3 WS spec, the frame payload is the raw IRC line
        without \\r\\n — the server appends \\r\\n for the IRC parser.
        """
        line = line.rstrip("\r\n")
        self._send_frame(0x1, line.encode("utf-8"))

    def send_ws_ping(self, data=b"ping"):
        """Send a WebSocket PING frame."""
        self._send_frame(0x9, data)

    def recv_line(self, timeout=None):
        """Receive a single IRC line from WS TEXT frames.

        Auto-responds to IRC PINGs. Returns None on timeout.
        """
        deadline = time.monotonic() + (timeout or self.timeout)
        while time.monotonic() < deadline:
            # Check line buffer for complete line
            if "\r\n" in self.line_buf:
                line, self.line_buf = self.line_buf.split("\r\n", 1)
                self.all_lines.append(line)
                if line.startswith("PING "):
                    self.send("PONG " + line[5:])
                    continue
                return line

            # Read a WS frame
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            frame = self._recv_frame(timeout=remaining)
            if frame is None:
                continue
            opcode, payload = frame

            if opcode == 0x1:  # TEXT
                # Server sends IRC lines without \r\n in WS frames;
                # append \r\n so line_buf parsing finds complete lines
                text = payload.decode("utf-8", errors="replace")
                if not text.endswith("\r\n"):
                    text += "\r\n"
                self.line_buf += text
            elif opcode == 0x9:  # PING
                self._send_frame(0xA, payload)  # PONG
            elif opcode == 0x8:  # CLOSE
                return None
        return None

    def wait_for(self, pattern, timeout=None):
        """Wait for a line matching pattern. Same semantics as IRCClient."""
        deadline = time.monotonic() + (timeout or self.timeout)
        collected = []
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            line = self.recv_line(timeout=remaining)
            if line is None:
                continue
            collected.append(line)
            if self._matches(line, pattern):
                return line
        raise TimeoutError(
            f"Timed out waiting for {pattern!r}.\n"
            f"Lines received: {collected}"
        )

    def register(self, nick, user=None, realname=None):
        """Send NICK + USER and wait for 001."""
        user = user or nick
        realname = realname or nick
        self.send(f"NICK {nick}")
        self.send(f"USER {user} 0 * :{realname}")
        return self.wait_for("001")

    def _send_frame(self, opcode, payload):
        """Send a masked WebSocket frame (client must mask per RFC 6455)."""
        frame = bytearray()
        frame.append(0x80 | opcode)  # FIN + opcode

        length = len(payload)
        if length < 126:
            frame.append(0x80 | length)  # MASK bit + length
        elif length < 65536:
            frame.append(0x80 | 126)
            frame.extend(struct.pack("!H", length))
        else:
            frame.append(0x80 | 127)
            frame.extend(struct.pack("!Q", length))

        # Masking key
        mask = os.urandom(4)
        frame.extend(mask)

        # Apply mask to payload
        masked = bytearray(payload)
        for i in range(len(masked)):
            masked[i] ^= mask[i % 4]
        frame.extend(masked)

        self.sock.sendall(bytes(frame))

    def _recv_frame(self, timeout=None):
        """Receive a WebSocket frame. Returns (opcode, payload) or None."""
        try:
            self.sock.settimeout(timeout or self.timeout)

            # Read 2-byte header
            header = self._recv_exact(2)
            if header is None:
                return None

            opcode = header[0] & 0x0F
            masked = bool(header[1] & 0x80)
            length = header[1] & 0x7F

            if length == 126:
                ext = self._recv_exact(2)
                if ext is None:
                    return None
                length = struct.unpack("!H", ext)[0]
            elif length == 127:
                ext = self._recv_exact(8)
                if ext is None:
                    return None
                length = struct.unpack("!Q", ext)[0]

            mask_key = None
            if masked:
                mask_key = self._recv_exact(4)
                if mask_key is None:
                    return None

            payload = self._recv_exact(length) if length > 0 else b""
            if payload is None:
                return None

            if masked and mask_key:
                payload = bytearray(payload)
                for i in range(len(payload)):
                    payload[i] ^= mask_key[i % 4]
                payload = bytes(payload)

            return (opcode, payload)
        except socket.timeout:
            return None
        except OSError:
            return None

    def _recv_exact(self, n):
        """Read exactly n bytes from the socket."""
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def _read_http_response(self):
        """Read the HTTP upgrade response."""
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            response += chunk
        return response.decode("utf-8", errors="replace")

    def _matches(self, line, pattern):
        """Check if a line matches a pattern."""
        if isinstance(pattern, re.Pattern):
            return pattern.search(line) is not None
        if re.match(r"^\d{3}$", pattern):
            return f" {pattern} " in line
        return pattern in line

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.disconnect()
