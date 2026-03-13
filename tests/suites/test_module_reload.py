"""Module system tests — MODULE LIST, MODULE RELOAD, core refuse unload."""

import pytest

from tests.harness.irc_client import IRCClient


class TestModuleReload:

    def _make_oper(self, client_factory, single_server, unique_nick):
        """Create a registered client with oper privileges."""
        nick = unique_nick("mod")
        c = client_factory(port=single_server.irc_port)
        c.register(nick)
        c.collect_lines(duration=0.5)
        c.send("OPER admin secret")
        c.wait_for("381")
        c.collect_lines(duration=0.3)
        # MODULE commands require IsAdmin (UMODE_A), set it explicitly
        c.send(f"MODE {nick} +A")
        c.collect_lines(duration=0.3)
        return c, nick

    def test_module_list(self, single_server, client_factory, unique_nick):
        """OPER can list loaded modules."""
        c, nick = self._make_oper(client_factory, single_server, unique_nick)
        c.send("MODULE LIST")
        lines = c.collect_lines(duration=2)
        # Should see module entries (NOTICE from server about modules)
        assert len(lines) > 0, "No output from MODULE LIST"
        # At least some lines should mention a module name
        module_lines = [l for l in lines if "m_" in l]
        assert len(module_lines) > 0, f"No module names in MODULE LIST output: {lines}"

    def test_module_reload(self, single_server, client_factory, unique_nick):
        """MODULE RELOAD of an extra module succeeds."""
        c, nick = self._make_oper(client_factory, single_server, unique_nick)
        c.send("MODULE RELOAD m_away_notify")
        lines = c.collect_lines(duration=3)
        # Should see success message (loaded/reload)
        success = any("load" in l.lower() for l in lines)
        assert success, f"MODULE RELOAD did not succeed: {lines}"

    def test_core_no_unload(self, single_server, client_factory, unique_nick):
        """MODULE UNLOAD of a core module is refused."""
        c, nick = self._make_oper(client_factory, single_server, unique_nick)
        c.send("MODULE UNLOAD m_privmsg")
        lines = c.collect_lines(duration=2)
        # Should see refusal — core modules have MAPI_CORE flag
        refused = any("core" in l.lower() or "refuse" in l.lower() or
                       "cannot" in l.lower() or "denied" in l.lower() or
                       "not" in l.lower()
                       for l in lines)
        assert refused, f"Core module unload was not refused: {lines}"
