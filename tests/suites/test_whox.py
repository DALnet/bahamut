"""WHOX (extended WHO) tests."""

import pytest

from tests.harness.irc_client import IRCClient
from tests.harness.assertions import parse_irc_line


class TestWhox:

    def _make_client(self, client_factory, single_server, unique_nick):
        nick = unique_nick("who")
        c = client_factory(port=single_server.irc_port)
        c.register(nick)
        c.collect_lines(duration=0.5)
        return c, nick

    def test_whox_basic(self, single_server, client_factory, unique_nick):
        """WHO #chan %cuhsnfdra,123 returns RPL_WHOSPCRPL (354)."""
        c, nick = self._make_client(client_factory, single_server, unique_nick)
        c.send("JOIN #testwho")
        c.wait_for("366")

        # Include 't' in the flags to request the token field
        c.send("WHO #testwho %tcuhsnfdra,123")
        line = c.wait_for("354")
        # 354 should be present (WHOX response, not standard 352)
        assert " 354 " in line
        c.wait_for("315")  # RPL_ENDOFWHO

    def test_who_standard(self, single_server, client_factory, unique_nick):
        """Standard WHO #chan returns RPL_WHOREPLY (352)."""
        c, nick = self._make_client(client_factory, single_server, unique_nick)
        c.send("JOIN #testwhostd")
        c.wait_for("366")

        c.send("WHO #testwhostd")
        line = c.wait_for("352")
        assert nick in line
        c.wait_for("315")  # RPL_ENDOFWHO
