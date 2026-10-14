"""Minimal blocking IRC client for testnet tests (stdlib only)."""

import itertools
import json
import os
import re
import socket
import ssl
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_RUN_DIR = os.path.join(HERE, "run")

_nick_counter = itertools.count(1)


def unique_nick(prefix="t"):
    return "%s%d%d" % (prefix, os.getpid() % 1000, next(_nick_counter))


def load_network(run_dir=None):
    """Return the network description written by `testnet.py up`."""
    run_dir = run_dir or os.environ.get("TESTNET_DIR", DEFAULT_RUN_DIR)
    with open(os.path.join(run_dir, "network.json")) as f:
        return json.load(f)


class Client(object):
    def __init__(self, port, tls=False, host="127.0.0.1", timeout=15):
        self.timeout = timeout
        sock = socket.create_connection((host, port), timeout=timeout)
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock)
        self.sock = sock
        self.buf = b""
        self.pending = []   # received, not yet consumed by expect()
        self.seen = []      # every line received
        self.nick = None

    def send(self, line):
        self.sock.sendall((line + "\r\n").encode())

    def _fill(self, deadline):
        self.sock.settimeout(max(0.05, min(0.5, deadline - time.time())))
        try:
            data = self.sock.recv(65536)
        except (socket.timeout, ssl.SSLWantReadError):
            return
        if not data:
            raise ConnectionError("connection closed; last lines: %r"
                                  % self.seen[-10:])
        self.buf += data
        while b"\n" in self.buf:
            raw, self.buf = self.buf.split(b"\n", 1)
            line = raw.rstrip(b"\r").decode("utf-8", "replace")
            self.seen.append(line)
            if line.startswith("PING "):
                self.send("PONG " + line[5:])
            self.pending.append(line)

    def expect(self, pattern, timeout=None):
        """Consume lines until one matches the regex; return that line."""
        rx = re.compile(pattern)
        deadline = time.time() + (timeout or self.timeout)
        while True:
            while self.pending:
                line = self.pending.pop(0)
                if rx.search(line):
                    return line
            if time.time() > deadline:
                raise AssertionError("timed out waiting for %r; last lines: %r"
                                     % (pattern, self.seen[-10:]))
            self._fill(deadline)

    def lines_until(self, pattern, timeout=None):
        """Like expect(), but return every consumed line (match last)."""
        start = len(self.seen) - len(self.pending)
        self.expect(pattern, timeout)
        consumed = len(self.seen) - len(self.pending)
        return self.seen[start:consumed]

    def register(self, nick=None, user="test"):
        self.nick = nick or unique_nick()
        self.send("NICK " + self.nick)
        self.send("USER %s 0 * :testnet %s" % (user, self.nick))
        return self.lines_until(r" (376|422) ", timeout=60)

    def sync(self):
        """Round-trip a PING so earlier replies have been received."""
        token = "sync%d" % next(_nick_counter)
        self.send("PING :" + token)
        self.expect(r"PONG .*%s" % token)

    def wait_for_nick(self, nick, timeout=30):
        """Wait until nick is visible here (it may still be bursting in)."""
        deadline = time.time() + timeout
        while True:
            self.send("WHOIS " + nick)
            line = self.expect(r" (311|401) %s %s " % (self.nick, nick))
            if " 311 " in line:
                self.expect(r" 318 ")
                return
            if time.time() > deadline:
                raise AssertionError("%s never became visible" % nick)
            time.sleep(0.5)

    def oper(self, net):
        self.send("OPER %s %s" % (net["oper"]["name"], net["oper"]["password"]))
        self.expect(r" 381 ")

    def close(self, message="bye"):
        try:
            self.send("QUIT :" + message)
        except OSError:
            pass
        self.sock.close()
