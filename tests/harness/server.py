"""BahamutServer process manager — start/stop/wait for readiness."""

import os
import signal
import socket
import subprocess
import tempfile
import time

from .config import generate_config
from .tls import generate_self_signed_cert


class BahamutServer:
    """Manages a single ircd process for testing."""

    def __init__(
        self,
        build_dir,
        server_name="irc.test",
        irc_port=6667,
        ws_port=None,
        ssl_port=None,
        extra_modules=None,
        gopeer_configs=None,
        server_id=None,
    ):
        self.build_dir = build_dir
        self.server_name = server_name
        self.irc_port = irc_port
        self.ws_port = ws_port
        self.ssl_port = ssl_port
        self.extra_modules = extra_modules
        self.gopeer_configs = gopeer_configs
        self.server_id = server_id
        self.process = None
        self.tmpdir = None
        self._tmpdir_obj = None

    def start(self, timeout=10):
        """Start the ircd process and wait for it to accept connections."""
        self._tmpdir_obj = tempfile.TemporaryDirectory(prefix="bahamut_test_")
        self.tmpdir = self._tmpdir_obj.name

        # Generate TLS certs (required even without SSL ports)
        generate_self_signed_cert(self.tmpdir)

        # Generate config
        conf_path = generate_config(
            tmpdir=self.tmpdir,
            build_dir=self.build_dir,
            server_name=self.server_name,
            irc_port=self.irc_port,
            ws_port=self.ws_port,
            ssl_port=self.ssl_port,
            extra_modules=self.extra_modules,
            gopeer_configs=self.gopeer_configs,
            server_id=self.server_id,
        )

        ircd_bin = os.path.join(self.build_dir, "src", "ircd")
        if not os.path.exists(ircd_bin):
            raise FileNotFoundError(f"ircd binary not found at {ircd_bin}")

        # Start ircd in foreground mode (-t)
        self.process = subprocess.Popen(
            [ircd_bin, "-f", conf_path, "-t"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.tmpdir,
        )

        # Wait for the IRC port to accept connections
        if not self._wait_for_port(self.irc_port, timeout):
            self.stop()
            raise RuntimeError(
                f"Server {self.server_name} failed to start on port {self.irc_port} "
                f"within {timeout}s"
            )

    def _wait_for_port(self, port, timeout):
        """Poll until the port accepts a TCP connection."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            # Check if process died
            if self.process.poll() is not None:
                stdout = self.process.stdout.read().decode(errors="replace")
                stderr = self.process.stderr.read().decode(errors="replace")
                raise RuntimeError(
                    f"Server {self.server_name} exited with code "
                    f"{self.process.returncode}\n"
                    f"stdout: {stdout}\nstderr: {stderr}"
                )
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    return True
            except (ConnectionRefusedError, OSError):
                time.sleep(0.1)
        return False

    def stop(self, keep_data=False):
        """Stop the ircd process and optionally preserve tmpdir.

        Args:
            keep_data: If True, keep tmpdir intact (for restart with journal data).
        """
        if self.process and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.process = None
        if not keep_data and self._tmpdir_obj:
            self._tmpdir_obj.cleanup()
            self._tmpdir_obj = None
            self.tmpdir = None

    def restart(self, timeout=10):
        """Stop the server and restart it, preserving tmpdir and journal data."""
        self.stop(keep_data=True)
        # Re-launch ircd using the existing tmpdir (config + journals intact)
        conf_path = os.path.join(self.tmpdir, "ircd.conf")
        ircd_bin = os.path.join(self.build_dir, "src", "ircd")
        self.process = subprocess.Popen(
            [ircd_bin, "-f", conf_path, "-t"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.tmpdir,
        )
        if not self._wait_for_port(self.irc_port, timeout):
            self.stop()
            raise RuntimeError(
                f"Server {self.server_name} failed to restart on port {self.irc_port} "
                f"within {timeout}s"
            )

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()
