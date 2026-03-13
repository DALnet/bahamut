"""Channel operation tests — JOIN/PART/TOPIC/MODE/KICK/PRIVMSG/NOTICE/NAMES."""

import pytest

from tests.harness.irc_client import IRCClient
from tests.harness.assertions import parse_irc_line


class TestChannel:

    def _make_client(self, client_factory, single_server, unique_nick, caps=None):
        """Helper: create a registered client."""
        nick = unique_nick()
        c = client_factory(port=single_server.irc_port)
        if caps:
            c.register_with_caps(nick, caps)
        else:
            c.register(nick)
        c.collect_lines(duration=0.5)
        return c, nick

    def test_join_part(self, single_server, client_factory, unique_nick):
        """JOIN #test, get JOIN echo + NAMES, then PART."""
        c, nick = self._make_client(client_factory, single_server, unique_nick)
        c.send("JOIN #testjoin")
        line = c.wait_for("JOIN")
        assert "#testjoin" in line
        # Should get NAMES
        c.wait_for("353")  # RPL_NAMREPLY
        c.wait_for("366")  # RPL_ENDOFNAMES

        c.send("PART #testjoin :bye")
        line = c.wait_for("PART")
        assert "#testjoin" in line

    def test_topic(self, single_server, client_factory, unique_nick):
        """Set and read TOPIC."""
        c, nick = self._make_client(client_factory, single_server, unique_nick)
        c.send("JOIN #testtopic")
        c.wait_for("366")

        c.send("TOPIC #testtopic :Hello world")
        line = c.wait_for("TOPIC")
        assert "Hello world" in line

        # Query topic
        c.send("TOPIC #testtopic")
        c.wait_for("332")  # RPL_TOPIC

    def test_privmsg(self, single_server, client_factory, unique_nick):
        """PRIVMSG to channel is received by other clients."""
        c1, nick1 = self._make_client(client_factory, single_server, unique_nick)
        c2, nick2 = self._make_client(client_factory, single_server, unique_nick)

        c1.send("JOIN #testmsg")
        c1.wait_for("366")
        c2.send("JOIN #testmsg")
        c2.wait_for("366")
        c1.collect_lines(duration=0.3)

        c1.send("PRIVMSG #testmsg :hello from c1")
        line = c2.wait_for("PRIVMSG")
        assert "hello from c1" in line

    def test_notice(self, single_server, client_factory, unique_nick):
        """NOTICE to channel is received by other clients."""
        c1, nick1 = self._make_client(client_factory, single_server, unique_nick)
        c2, nick2 = self._make_client(client_factory, single_server, unique_nick)

        c1.send("JOIN #testnotice")
        c1.wait_for("366")
        c2.send("JOIN #testnotice")
        c2.wait_for("366")
        c1.collect_lines(duration=0.3)

        c1.send("NOTICE #testnotice :notice from c1")
        line = c2.wait_for("NOTICE")
        assert "notice from c1" in line

    def test_kick(self, single_server, client_factory, unique_nick):
        """Channel operator can kick a user."""
        c1, nick1 = self._make_client(client_factory, single_server, unique_nick)
        c2, nick2 = self._make_client(client_factory, single_server, unique_nick)

        c1.send("JOIN #testkick")
        c1.wait_for("366")
        c2.send("JOIN #testkick")
        c2.wait_for("366")
        c1.collect_lines(duration=0.3)

        # c1 is op (first user in channel with allow_split_ops)
        c1.send(f"KICK #testkick {nick2} :goodbye")
        line = c2.wait_for("KICK")
        assert nick2 in line

    def test_mode_op(self, single_server, client_factory, unique_nick):
        """MODE +o/-o grants/removes operator status."""
        c1, nick1 = self._make_client(client_factory, single_server, unique_nick)
        c2, nick2 = self._make_client(client_factory, single_server, unique_nick)

        c1.send("JOIN #testmode")
        c1.wait_for("366")
        c2.send("JOIN #testmode")
        c2.wait_for("366")
        c1.collect_lines(duration=0.3)

        c1.send(f"MODE #testmode +o {nick2}")
        line = c1.wait_for("MODE")
        assert "+o" in line
        assert nick2 in line

    def test_mode_ban(self, single_server, client_factory, unique_nick):
        """MODE +b prevents user from joining."""
        c1, nick1 = self._make_client(client_factory, single_server, unique_nick)

        c1.send("JOIN #testban")
        c1.wait_for("366")

        # Ban all users matching *!*@*
        c1.send("MODE #testban +b *!*@*")
        c1.wait_for("MODE")

        # Second client tries to join
        c2, nick2 = self._make_client(client_factory, single_server, unique_nick)
        c2.send("JOIN #testban")
        c2.wait_for("474")  # ERR_BANNEDFROMCHAN

    def test_mode_key(self, single_server, client_factory, unique_nick):
        """MODE +k requires key to join."""
        c1, nick1 = self._make_client(client_factory, single_server, unique_nick)

        c1.send("JOIN #testkey")
        c1.wait_for("366")

        c1.send("MODE #testkey +k mysecret")
        c1.wait_for("MODE")

        # Without key
        c2, nick2 = self._make_client(client_factory, single_server, unique_nick)
        c2.send("JOIN #testkey")
        c2.wait_for("475")  # ERR_BADCHANNELKEY

        # With key
        c3, nick3 = self._make_client(client_factory, single_server, unique_nick)
        c3.send("JOIN #testkey mysecret")
        c3.wait_for("JOIN")

    def test_mode_limit(self, single_server, client_factory, unique_nick):
        """MODE +l limits channel capacity."""
        c1, nick1 = self._make_client(client_factory, single_server, unique_nick)

        c1.send("JOIN #testlimit")
        c1.wait_for("366")

        c1.send("MODE #testlimit +l 1")
        c1.wait_for("MODE")

        c2, nick2 = self._make_client(client_factory, single_server, unique_nick)
        c2.send("JOIN #testlimit")
        c2.wait_for("471")  # ERR_CHANNELISFULL

    def test_names_multiprefix(self, single_server, client_factory, unique_nick):
        """NAMES with multi-prefix cap shows @+ prefixes."""
        c1, nick1 = self._make_client(
            client_factory, single_server, unique_nick, caps=["multi-prefix"]
        )
        c2, nick2 = self._make_client(client_factory, single_server, unique_nick)

        c1.send("JOIN #testnames")
        c1.wait_for("366")
        c2.send("JOIN #testnames")
        c2.wait_for("366")

        # c1 is op, c2 is normal user
        c1.send("NAMES #testnames")
        line = c1.wait_for("353")
        # With multi-prefix, op should show @
        assert f"@{nick1}" in line
