"""Line-based IRC client for testing (TCP + optional TLS)."""

import re
import socket
import ssl
import time


class IRCClient:
    """Simple IRC client that sends/receives lines and auto-responds to PING."""

    def __init__(self, host="127.0.0.1", port=6667, use_tls=False, timeout=5):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.timeout = timeout
        self.sock = None
        self.buf = b""
        self.all_lines = []  # Full history for debugging
        self._connected = False

    def connect(self):
        """Connect to the IRC server."""
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self.sock = ctx.wrap_socket(raw, server_hostname=self.host)
        else:
            self.sock = raw
        self.sock.settimeout(self.timeout)
        self._connected = True

    def disconnect(self):
        """Close the connection."""
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.sock.close()
            self.sock = None
        self._connected = False

    def send(self, line):
        """Send a raw IRC line (CRLF appended automatically)."""
        if not line.endswith("\r\n"):
            line += "\r\n"
        self.sock.sendall(line.encode("utf-8"))

    def recv_line(self, timeout=None):
        """Receive a single IRC line, auto-responding to PING.

        Returns the line (without CRLF) or None on timeout.
        """
        deadline = time.monotonic() + (timeout or self.timeout)
        while time.monotonic() < deadline:
            # Check buffer for complete line
            if b"\r\n" in self.buf:
                line, self.buf = self.buf.split(b"\r\n", 1)
                decoded = line.decode("utf-8", errors="replace")
                self.all_lines.append(decoded)
                # Auto-respond to PING
                if decoded.startswith("PING "):
                    self.send("PONG " + decoded[5:])
                    continue
                return decoded

            # Read more data
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            self.sock.settimeout(max(remaining, 0.1))
            try:
                data = self.sock.recv(4096)
                if not data:
                    return None
                self.buf += data
            except socket.timeout:
                continue
            except OSError:
                return None
        return None

    def wait_for(self, pattern, timeout=None):
        """Wait for a line matching a pattern.

        Args:
            pattern: A string (matched as substring) or compiled regex.
                     If it looks like a 3-digit number, matches as IRC numeric.
            timeout: Override default timeout.

        Returns:
            The matching line, or raises TimeoutError.
        """
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

    def wait_for_any(self, patterns, timeout=None):
        """Wait for a line matching any of the given patterns.

        Returns (matched_pattern, line).
        """
        deadline = time.monotonic() + (timeout or self.timeout)
        collected = []
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            line = self.recv_line(timeout=remaining)
            if line is None:
                continue
            collected.append(line)
            for p in patterns:
                if self._matches(line, p):
                    return p, line
        raise TimeoutError(
            f"Timed out waiting for any of {patterns!r}.\n"
            f"Lines received: {collected}"
        )

    def collect_lines(self, duration=0.5):
        """Collect all lines received within a time window."""
        lines = []
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            line = self.recv_line(timeout=remaining)
            if line is not None:
                lines.append(line)
        return lines

    def expect_no(self, pattern, duration=0.5):
        """Assert that no line matching pattern arrives within duration."""
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            line = self.recv_line(timeout=remaining)
            if line is not None and self._matches(line, pattern):
                raise AssertionError(
                    f"Unexpected line matching {pattern!r}: {line}"
                )

    def register(self, nick, user=None, realname=None):
        """Send NICK + USER and wait for 001 welcome."""
        user = user or nick
        realname = realname or nick
        self.send(f"NICK {nick}")
        self.send(f"USER {user} 0 * :{realname}")
        return self.wait_for("001")

    def register_with_caps(self, nick, caps, user=None, realname=None):
        """Full CAP negotiation + registration.

        Args:
            nick: Nickname
            caps: List of cap names to request (e.g. ["multi-prefix", "sasl"])
            user: Username (defaults to nick)
            realname: Real name (defaults to nick)

        Returns:
            The 001 welcome line.
        """
        user = user or nick
        realname = realname or nick

        self.send("CAP LS 302")
        # Read CAP LS response(s)
        ls_lines = []
        while True:
            line = self.wait_for("CAP")
            ls_lines.append(line)
            if "LS *" not in line:
                break

        # Request caps
        if caps:
            self.send("CAP REQ :" + " ".join(caps))
            self.wait_for("ACK")

        self.send(f"NICK {nick}")
        self.send(f"USER {user} 0 * :{realname}")
        self.send("CAP END")
        return self.wait_for("001")

    def sasl_plain(self, nick, account, password, user=None, realname=None):
        """Full SASL PLAIN authentication flow.

        Args:
            nick: Nickname
            account: Account name for SASL
            password: Password for SASL
            user: Username (defaults to nick)
            realname: Real name (defaults to nick)

        Returns:
            The 001 welcome line.
        """
        import base64

        user = user or nick
        realname = realname or nick

        self.send("CAP LS 302")
        self.wait_for("CAP")

        self.send("CAP REQ :sasl")
        self.wait_for("ACK")

        self.send("AUTHENTICATE PLAIN")
        self.wait_for("AUTHENTICATE +")

        # SASL PLAIN: \0account\0password
        payload = f"\x00{account}\x00{password}"
        encoded = base64.b64encode(payload.encode()).decode()
        self.send(f"AUTHENTICATE {encoded}")

        # Wait for 903 (success) or 904 (failure)
        return self.wait_for_any(["903", "904"])

    def _matches(self, line, pattern):
        """Check if a line matches a pattern."""
        if isinstance(pattern, re.Pattern):
            return pattern.search(line) is not None
        # If pattern looks like a 3-digit numeric, match as IRC numeric
        if re.match(r"^\d{3}$", pattern):
            # Match as " 001 " in the line
            return f" {pattern} " in line
        return pattern in line

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.disconnect()
