"""Ephemeral port allocator — bind port 0 and read OS-assigned port."""

import socket


def allocate_port(host="127.0.0.1"):
    """Allocate a free ephemeral port by binding to port 0.

    Returns the port number. The socket is closed immediately, so there's a
    small race window, but it's fine for tests.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, 0))
        return s.getsockname()[1]


def allocate_ports(n, host="127.0.0.1"):
    """Allocate n distinct free ephemeral ports."""
    ports = []
    sockets = []
    try:
        for _ in range(n):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, 0))
            ports.append(s.getsockname()[1])
            sockets.append(s)
    finally:
        for s in sockets:
            s.close()
    return ports
