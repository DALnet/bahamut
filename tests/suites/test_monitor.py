"""MONITOR command tests (IRCv3 online/offline notifications)."""

import pytest

from tests.harness.irc_client import IRCClient


class TestMonitor:

    def _make_client(self, client_factory, single_server, unique_nick):
        nick = unique_nick("mon")
        c = client_factory(port=single_server.irc_port)
        c.register(nick)
        c.collect_lines(duration=0.5)
        return c, nick

    def test_monitor_add_offline(self, single_server, client_factory, unique_nick):
        """MONITOR + for offline nick gets RPL_MONOFFLINE (731)."""
        c, nick = self._make_client(client_factory, single_server, unique_nick)
        c.send("MONITOR + offlinenick")
        c.wait_for("731")  # RPL_MONOFFLINE

    def test_monitor_online(self, single_server, client_factory, unique_nick):
        """Target coming online sends RPL_MONONLINE (730)."""
        c, nick = self._make_client(client_factory, single_server, unique_nick)
        target_nick = unique_nick("target")

        # Monitor the target (offline)
        c.send(f"MONITOR + {target_nick}")
        c.wait_for("731")

        # Target connects
        c2 = client_factory(port=single_server.irc_port)
        c2.register(target_nick)

        # Should get 730 (online notification)
        c.wait_for("730", timeout=5)

    def test_monitor_offline(self, single_server, client_factory, unique_nick):
        """Target going offline sends RPL_MONOFFLINE (731)."""
        # Connect target first
        target_nick = unique_nick("target")
        c2 = client_factory(port=single_server.irc_port)
        c2.register(target_nick)
        c2.collect_lines(duration=0.5)

        # Monitor the target (online)
        c, nick = self._make_client(client_factory, single_server, unique_nick)
        c.send(f"MONITOR + {target_nick}")
        c.wait_for("730")  # RPL_MONONLINE (target is online)

        # Target disconnects
        c2.send("QUIT :bye")
        c2.collect_lines(duration=0.5)

        # Should get 731 (offline notification)
        c.wait_for("731", timeout=5)

    def test_monitor_clear(self, single_server, client_factory, unique_nick):
        """MONITOR C clears the monitor list."""
        c, nick = self._make_client(client_factory, single_server, unique_nick)
        c.send("MONITOR + somenick")
        c.wait_for("731")

        c.send("MONITOR C")
        # After clear, MONITOR L should return empty
        c.send("MONITOR L")
        c.wait_for("733")  # RPL_ENDOFMONLIST

    def test_monitor_list(self, single_server, client_factory, unique_nick):
        """MONITOR L lists monitored targets."""
        c, nick = self._make_client(client_factory, single_server, unique_nick)
        target = unique_nick("tgt")
        c.send(f"MONITOR + {target}")
        c.wait_for("731")

        c.send("MONITOR L")
        line = c.wait_for("732")  # RPL_MONLIST
        assert target.lower() in line.lower()
        c.wait_for("733")  # RPL_ENDOFMONLIST
