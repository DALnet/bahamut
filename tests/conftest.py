"""Pytest fixtures for Bahamut IRC integration tests."""

import os
import time

import pytest

from .harness.irc_client import IRCClient
from .harness.ws_client import WebSocketIRCClient
from .harness.ports import allocate_ports
from .harness.server import BahamutServer


def _find_build_dir():
    """Find the meson build directory."""
    # Look relative to the tests/ directory
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    build_dir = os.path.join(repo_root, "build")
    if os.path.isdir(build_dir) and os.path.exists(
        os.path.join(build_dir, "src", "ircd")
    ):
        return build_dir
    raise FileNotFoundError(
        f"Build directory not found at {build_dir}. Run 'ninja -C build' first."
    )


@pytest.fixture(scope="session")
def build_dir():
    """Path to the meson build directory."""
    return _find_build_dir()


@pytest.fixture
def server_factory(build_dir):
    """Factory fixture that creates and tracks BahamutServer instances.

    Returns a callable that creates servers. All servers are cleaned up
    after the test.
    """
    servers = []

    def _factory(
        server_name="irc.test",
        irc_port=None,
        ws_port=None,
        ssl_port=None,
        extra_modules=None,
        gopeer_configs=None,
        server_id=None,
    ):
        if irc_port is None:
            ports_needed = 1
            if ws_port is True:
                ports_needed += 1
            if ssl_port is True:
                ports_needed += 1
            ports = allocate_ports(ports_needed)
            irc_port = ports[0]
            idx = 1
            if ws_port is True:
                ws_port = ports[idx]
                idx += 1
            if ssl_port is True:
                ssl_port = ports[idx]

        srv = BahamutServer(
            build_dir=build_dir,
            server_name=server_name,
            irc_port=irc_port,
            ws_port=ws_port,
            ssl_port=ssl_port,
            extra_modules=extra_modules,
            gopeer_configs=gopeer_configs,
            server_id=server_id,
        )
        srv.start()
        servers.append(srv)
        return srv

    yield _factory

    for srv in servers:
        srv.stop()


@pytest.fixture
def single_server(server_factory):
    """A single running server with all features enabled.

    Provides a server with IRC, WebSocket, and SSL ports.
    """
    return server_factory(ws_port=True, ssl_port=True)


@pytest.fixture
def client_factory():
    """Factory that creates IRC clients and tracks them for cleanup."""
    clients = []

    def _factory(host="127.0.0.1", port=6667, use_tls=False, timeout=5):
        c = IRCClient(host=host, port=port, use_tls=use_tls, timeout=timeout)
        c.connect()
        clients.append(c)
        return c

    yield _factory

    for c in clients:
        try:
            c.disconnect()
        except Exception:
            pass


@pytest.fixture
def ws_client_factory():
    """Factory that creates WebSocket IRC clients."""
    clients = []

    def _factory(host="127.0.0.1", port=8080, timeout=5):
        c = WebSocketIRCClient(host=host, port=port, timeout=timeout)
        c.connect()
        clients.append(c)
        return c

    yield _factory

    for c in clients:
        try:
            c.disconnect()
        except Exception:
            pass


@pytest.fixture
def gossip_cluster(build_dir):
    """Two-server gossip cluster fixture.

    Returns (server1, server2) with gopeer blocks pointing at each other.
    Waits for gossip link establishment.
    """
    ports = allocate_ports(4)
    irc1, irc2 = ports[0], ports[1]
    ws1, ws2 = ports[2], ports[3]

    srv1 = BahamutServer(
        build_dir=build_dir,
        server_name="irc1.test",
        irc_port=irc1,
        ws_port=ws1,
        gopeer_configs=[{"host": "127.0.0.1", "port": irc2, "name": "irc2.test", "server_id": 2}],
        server_id=1,
    )
    srv2 = BahamutServer(
        build_dir=build_dir,
        server_name="irc2.test",
        irc_port=irc2,
        ws_port=ws2,
        gopeer_configs=[{"host": "127.0.0.1", "port": irc1, "name": "irc1.test", "server_id": 1}],
        server_id=2,
    )

    srv1.start()
    srv2.start()

    # Wait for gossip link establishment
    time.sleep(3)

    yield srv1, srv2

    srv1.stop()
    srv2.stop()


@pytest.fixture
def gossip_triangle(build_dir):
    """Three-server gossip mesh fixture.

    Returns (srv1, srv2, srv3) with full-mesh gopeer blocks.
    """
    ports = allocate_ports(6)
    irc1, irc2, irc3 = ports[0], ports[1], ports[2]
    ws1, ws2, ws3 = ports[3], ports[4], ports[5]

    srv1 = BahamutServer(
        build_dir=build_dir,
        server_name="irc1.test",
        irc_port=irc1,
        ws_port=ws1,
        gopeer_configs=[
            {"host": "127.0.0.1", "port": irc2, "name": "irc2.test", "server_id": 2},
            {"host": "127.0.0.1", "port": irc3, "name": "irc3.test", "server_id": 3},
        ],
        server_id=1,
    )
    srv2 = BahamutServer(
        build_dir=build_dir,
        server_name="irc2.test",
        irc_port=irc2,
        ws_port=ws2,
        gopeer_configs=[
            {"host": "127.0.0.1", "port": irc1, "name": "irc1.test", "server_id": 1},
            {"host": "127.0.0.1", "port": irc3, "name": "irc3.test", "server_id": 3},
        ],
        server_id=2,
    )
    srv3 = BahamutServer(
        build_dir=build_dir,
        server_name="irc3.test",
        irc_port=irc3,
        ws_port=ws3,
        gopeer_configs=[
            {"host": "127.0.0.1", "port": irc1, "name": "irc1.test", "server_id": 1},
            {"host": "127.0.0.1", "port": irc2, "name": "irc2.test", "server_id": 2},
        ],
        server_id=3,
    )

    srv1.start()
    srv2.start()
    srv3.start()

    # Wait for full mesh formation
    time.sleep(4)

    yield srv1, srv2, srv3

    srv1.stop()
    srv2.stop()
    srv3.stop()


# Counter for unique nicks across tests
_nick_counter = 0


@pytest.fixture
def unique_nick():
    """Generate unique nick names to avoid collisions between tests."""
    global _nick_counter

    def _gen(prefix="tst"):
        global _nick_counter
        _nick_counter += 1
        return f"{prefix}{_nick_counter}"

    return _gen
