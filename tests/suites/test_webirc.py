"""WEBIRC gateway tests, including the IRCv3 `secure` option.

The security invariant under test (IRCv3 WEBIRC spec MUST): a WEBIRC client is
treated as secure ONLY if it sent the `secure` option AND the gateway↔server
link is itself TLS.  `secure` over a plaintext gateway link must be ignored,
and a TLS gateway link without `secure` must be downgraded to not-secure.

Each test uses a single WEBIRC connection on a fresh server so the per-IP
accept throttle (3 connections / 15s from 127.0.0.1) never interferes.
"""

import socket
import ssl
import time

import pytest

from tests.harness.ports import allocate_ports
from tests.harness.server import BahamutServer

SECRET = "webircpass"
SPOOF_IP = "1.2.3.4"
SPOOF_HOST = "spoofed.example.org"


@pytest.fixture
def webirc_server(build_dir):
    """A server with dedicated plain + TLS WEBIRC gateway ports."""
    irc_port, plain_port, tls_port = allocate_ports(3)
    srv = BahamutServer(
        build_dir=build_dir,
        irc_port=irc_port,
        webirc={"secret": SECRET, "port": plain_port, "tls_port": tls_port},
    )
    srv.webirc_plain_port = plain_port
    srv.webirc_tls_port = tls_port
    srv.start()
    yield srv
    srv.stop()


def _recv_line(s, pred, timeout=6):
    s.settimeout(timeout)
    buf = ""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            data = s.recv(4096)
        except socket.timeout:
            break
        if not data:
            break
        buf += data.decode("latin1")
        while "\n" in buf:
            line, buf = buf.split("\n", 1)
            line = line.rstrip("\r")
            if line.startswith("PING "):
                s.sendall(("PONG " + line[5:] + "\r\n").encode())
                continue
            if pred(line):
                return line
    return None


def _webirc_register(port, use_tls, secure, nick):
    """Open a WEBIRC gateway connection, register, and return (umodes, host).

    umodes is the client's own +modes string (RPL_UMODEIS 221); host is the
    hostname the network sees (RPL_WHOISUSER 311), which confirms the spoof.
    """
    raw = socket.create_connection(("127.0.0.1", port), timeout=6)
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(raw, server_hostname="irc.test")
    else:
        s = raw
    try:
        opt = " :secure" if secure else ""
        # WEBIRC MUST be the first line the gateway sends.
        s.sendall(f"WEBIRC {SECRET} testgw {SPOOF_HOST} {SPOOF_IP}{opt}\r\n".encode())
        s.sendall(f"NICK {nick}\r\nUSER u 0 * :r\r\n".encode())
        if not _recv_line(s, lambda l: " 001 " in l):
            pytest.fail("WEBIRC client did not register (no 001)")

        s.sendall(f"WHOIS {nick}\r\n".encode())
        whois = _recv_line(s, lambda l: " 311 " in l)
        s.sendall(f"MODE {nick}\r\n".encode())
        umode = _recv_line(s, lambda l: " 221 " in l)

        assert whois, "no RPL_WHOISUSER (311)"
        assert umode, "no RPL_UMODEIS (221)"
        # 311 tail: "<me> <nick> <user> <host> * :<real>" — host is token index 3.
        host = whois.split(" 311 ", 1)[1].split()[3]
        # 221 tail: "<nick> <modestring>" — modes are the last token (so an 'S'
        # in the nick can't be mistaken for umode +S).
        modes = umode.split(" 221 ", 1)[1].split()[-1]
        return modes, host
    finally:
        s.close()


def _secure(modes):
    return "S" in modes  # UMODE_S == secure connection


class TestWebircSecure:

    def test_webirc_spoofs_host(self, webirc_server):
        """A valid WEBIRC replaces the client's apparent host (sanity)."""
        _modes, host = _webirc_register(
            webirc_server.webirc_plain_port, False, False, "wiHost")
        assert host == SPOOF_HOST, f"WEBIRC did not spoof host: {host!r}"

    def test_plaintext_secure_flag_ignored(self, webirc_server):
        """MUST: `secure` over a plaintext gateway link does NOT grant secure."""
        modes, host = _webirc_register(
            webirc_server.webirc_plain_port, False, True, "wiPlainSec")
        assert host == SPOOF_HOST                      # WEBIRC actually applied
        assert not _secure(modes), f"plaintext+secure wrongly secure: {modes!r}"

    def test_plaintext_no_secure(self, webirc_server):
        modes, host = _webirc_register(
            webirc_server.webirc_plain_port, False, False, "wiPlainNo")
        assert host == SPOOF_HOST
        assert not _secure(modes), modes

    def test_tls_secure_flag_honored(self, webirc_server):
        """TLS gateway link + `secure` → the user IS secure (+S)."""
        modes, host = _webirc_register(
            webirc_server.webirc_tls_port, True, True, "wiTlsSec")
        assert host == SPOOF_HOST
        assert _secure(modes), f"tls+secure not secure: {modes!r}"

    def test_tls_no_secure_downgrade(self, webirc_server):
        """MUST: a TLS gateway link WITHOUT `secure` is downgraded to not-secure.

        This is the strongest case — it only passes if WEBIRC applied (else a
        plain TLS client would be +S) AND the `secure` downgrade works.
        """
        modes, host = _webirc_register(
            webirc_server.webirc_tls_port, True, False, "wiTlsNo")
        assert host == SPOOF_HOST
        assert not _secure(modes), f"tls without secure wrongly secure: {modes!r}"
