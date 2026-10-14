"""IRCv3 client capability negotiation (CAP LS/LIST/REQ/END)."""

import unittest

from ircclient import Client, load_network, unique_nick


class CapTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.net = load_network()
        cls.port = cls.net["servers"][0]["port"]
        probe = Client(cls.port)
        try:
            probe.register()
            probe.send("CAP LS")
            if " 421 " in probe.expect(r" (CAP|421) "):
                raise unittest.SkipTest("server does not support CAP")
        finally:
            probe.close()

    def unregistered(self, *caps_cmds):
        """Connect, send CAP commands, then NICK/USER without CAP END."""
        c = Client(self.port)
        self.addCleanup(c.close)
        c.nick = unique_nick("cap")
        for cmd in caps_cmds:
            c.send(cmd)
        c.send("NICK " + c.nick)
        c.send("USER test 0 * :cap test")
        return c

    def cap_list(self, c):
        c.send("CAP LIST")
        return c.expect(r" CAP \S+ LIST ")

    def assert_not_registered(self, c):
        self.cap_list(c)  # round trip so a 001 would have arrived by now
        self.assertFalse(any(" 001 " in l for l in c.seen))

    def end_and_register(self, c):
        c.send("CAP END")
        c.expect(r" 001 %s " % c.nick, timeout=60)

    def test_ls_302_holds_registration_until_end(self):
        c = self.unregistered("CAP LS 302")
        line = c.expect(r" CAP \* LS ")
        self.assertIn("cap-notify", line.split(" :", 1)[1].split())
        self.assert_not_registered(c)
        self.end_and_register(c)

    def test_ls_302_enables_cap_notify_and_it_is_sticky(self):
        c = self.unregistered("CAP LS 302")
        self.assertTrue(self.cap_list(c).endswith(":cap-notify"))
        c.send("CAP REQ :-cap-notify")
        c.expect(r" CAP \S+ NAK :-cap-notify$")
        self.end_and_register(c)

    def test_req_ack_and_disable(self):
        c = self.unregistered("CAP LS")
        c.expect(r" CAP \S+ LS ")
        self.assertTrue(self.cap_list(c).endswith("LIST :"))
        c.send("CAP REQ :cap-notify")
        c.expect(r" CAP \S+ ACK :cap-notify$")
        self.assertTrue(self.cap_list(c).endswith(":cap-notify"))
        c.send("CAP REQ :-cap-notify")
        c.expect(r" CAP \S+ ACK :-cap-notify$")
        self.assertTrue(self.cap_list(c).endswith("LIST :"))
        self.end_and_register(c)

    def test_req_with_unknown_cap_naks_whole_request(self):
        c = self.unregistered("CAP LS")
        c.send("CAP REQ :cap-notify no-such-cap")
        c.expect(r" CAP \S+ NAK :cap-notify no-such-cap$")
        self.assertTrue(self.cap_list(c).endswith("LIST :"))
        self.end_and_register(c)

    def test_req_without_ls_holds_registration(self):
        c = self.unregistered("CAP REQ :cap-notify")
        c.expect(r" CAP \S+ ACK :cap-notify$")
        self.assert_not_registered(c)
        self.end_and_register(c)

    def test_invalid_and_missing_subcommand(self):
        c = self.unregistered("CAP LS")
        c.send("CAP FOO")
        c.expect(r" 410 \S+ FOO ")
        c.send("CAP")
        c.expect(r" 461 \S+ CAP ")
        self.end_and_register(c)

    def test_cap_after_registration(self):
        c = Client(self.port)
        self.addCleanup(c.close)
        c.register()
        c.send("CAP LS")
        c.expect(r" CAP %s LS :" % c.nick)
        c.send("CAP END")
        c.sync()
        self.assertEqual(1, sum(" 001 " in l for l in c.seen))

    def test_client_without_cap_registers_normally(self):
        c = Client(self.port)
        self.addCleanup(c.close)
        lines = c.register()
        self.assertTrue(any(" 001 %s " % c.nick in l for l in lines))


if __name__ == "__main__":
    unittest.main()
