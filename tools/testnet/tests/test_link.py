"""Server linking: bursts and propagation over plain+zip and TLS+zip links."""

import unittest

from ircclient import Client, load_network, unique_nick


class LinkTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.net = load_network()
        cls.hub, cls.leaf1, cls.leaf2 = [s["port"] for s in cls.net["servers"]]

    def client(self, port, tls=False):
        c = Client(port, tls=tls)
        c.register()
        self.addCleanup(c.close)
        return c

    def test_links_lists_every_server(self):
        c = self.client(self.hub)
        c.oper(self.net)
        c.send("LINKS")
        lines = c.lines_until(r" 365 ")
        found = {l.split()[3] for l in lines if " 364 " in l}
        for srv in self.net["servers"]:
            self.assertIn(srv["name"], found)

    def test_privmsg_between_leaves(self):
        a = self.client(self.leaf1)
        b = self.client(self.leaf2)
        a.wait_for_nick(b.nick)
        a.send("PRIVMSG %s :hello across the hub" % b.nick)
        b.expect(r"^:%s!\S+ PRIVMSG %s :hello across the hub" % (a.nick, b.nick))

    def test_whois_remote_user(self):
        a = self.client(self.hub)
        b = self.client(self.leaf2)
        a.wait_for_nick(b.nick)
        a.send("WHOIS " + b.nick)
        line = a.expect(r" 312 %s %s " % (a.nick, b.nick))
        self.assertIn("leaf2.test", line)

    def test_channel_join_topic_and_message(self):
        chan = "#" + unique_nick("c")
        a = self.client(self.leaf1)
        b = self.client(self.leaf2)
        a.send("JOIN " + chan)
        a.expect(r" 366 ")
        a.send("TOPIC %s :testnet topic" % chan)
        a.expect(r" TOPIC %s :testnet topic" % chan)
        b.wait_for_nick(a.nick)
        b.send("JOIN " + chan)
        joined = b.lines_until(r" 366 ")
        a.expect(r"^:%s!\S+ JOIN :?%s" % (b.nick, chan))
        # a's JOIN and TOPIC may still be propagating when b joins
        if not any(" 332 " in l and "testnet topic" in l for l in joined):
            b.expect(r" TOPIC %s :testnet topic" % chan)
        b.send("PRIVMSG %s :hi channel" % chan)
        a.expect(r"^:%s!\S+ PRIVMSG %s :hi channel" % (b.nick, chan))

    def test_nick_change_and_quit_propagate(self):
        chan = "#" + unique_nick("c")
        a = self.client(self.hub)
        b = self.client(self.leaf1)
        for c in (a, b):
            c.send("JOIN " + chan)
            c.expect(r" 366 ")
        a.expect(r"^:%s!\S+ JOIN :?%s" % (b.nick, chan))
        newnick = unique_nick("n")
        b.send("NICK " + newnick)
        a.expect(r"^:%s!\S+ NICK :?%s" % (b.nick, newnick))
        b.nick = newnick
        b.send("QUIT :leaving")
        a.expect(r"^:%s!\S+ QUIT :" % newnick)

    def test_tls_client_port(self):
        a = self.client(self.net["servers"][0]["tls_port"], tls=True)
        b = self.client(self.leaf1)
        a.wait_for_nick(b.nick)
        a.send("PRIVMSG %s :hello over tls" % b.nick)
        b.expect(r"^:%s!\S+ PRIVMSG %s :hello over tls" % (a.nick, b.nick))

if __name__ == "__main__":
    unittest.main()
