"""OldBahamutServer — manages a master-branch (TS5-only) ircd process."""

import os
import tempfile

from tests.harness.server import BahamutServer
from tests.harness.config import generate_old_config
from tests.harness.tls import generate_self_signed_cert


class OldBahamutServer(BahamutServer):
    """BahamutServer variant for the old (master-branch) ircd.

    Key differences:
    - Uses generate_old_config() (no modules, no gossip, no ssl block)
    - Requires explicit binary_path (no meson build_dir layout)
    - No module symlink setup
    """

    def __init__(self, binary_path, server_name, irc_port, connect_configs=None):
        # Pass a dummy build_dir — we override start() entirely
        super().__init__(
            build_dir="",
            server_name=server_name,
            irc_port=irc_port,
            binary_path=binary_path,
            connect_configs=connect_configs,
        )

    def start(self, timeout=10):
        """Start the old ircd process."""
        import subprocess

        self._tmpdir_obj = tempfile.TemporaryDirectory(prefix="bahamut_old_")
        self.tmpdir = self._tmpdir_obj.name

        generate_self_signed_cert(self.tmpdir)

        conf_path = generate_old_config(
            tmpdir=self.tmpdir,
            server_name=self.server_name,
            irc_port=self.irc_port,
            connect_configs=self.connect_configs,
        )

        ircd_bin = self.binary_path
        if not os.path.exists(ircd_bin):
            raise FileNotFoundError(f"Old ircd binary not found at {ircd_bin}")

        self.process = subprocess.Popen(
            [ircd_bin, "-f", conf_path, "-t"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.tmpdir,
        )

        if not self._wait_for_port(self.irc_port, timeout):
            self.stop()
            raise RuntimeError(
                f"Old server {self.server_name} failed to start on port "
                f"{self.irc_port} within {timeout}s"
            )
