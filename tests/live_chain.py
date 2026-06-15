#!/usr/bin/env python3
"""Live propagation + IRCv3 test harness for the TestNet gossip chain.

Topology:  node1 (leaf) -> node2 (hub) -> node3 (hub) -> node4 (leaf)

Run from the Mac against the tailnet (use dangerouslyDisableSandbox).
Tests run primarily between the two CHAIN ENDS (node1 and node4) so a pass
proves propagation across the full 3-hop path.

Usage:
    python3 tests/live_chain.py smoke      # 3-node chain functional check
    python3 tests/live_chain.py burst      # node4 full-state burst on link-up
    python3 tests/live_chain.py ircv3      # all supported IRCv3 caps (no SASL)
    python3 tests/live_chain.py all
"""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "harness"))
from irc_client import IRCClient  # noqa: E402

# Tailnet IPs (avoid MagicDNS flakiness)
NODE = {
    "node1": ("100.78.132.90", 6667, 6697),   # (ip, plain, tls)
    "node2": ("100.102.142.81", 6667, 6697),
    "node3": ("100.117.44.12", 6667, 6697),
    "node4": ("100.86.10.20", 6667, 6697),
}

PASS = "\033[0;32mPASS\033[0m"
FAIL = "\033[0;31mFAIL\033[0m"
INFO = "\033[1;33mINFO\033[0m"

_results = []


def check(name, ok, detail=""):
    tag = PASS if ok else FAIL
    print(f"  [{tag}] {name}" + (f"  -- {detail}" if detail else ""))
    _results.append((name, bool(ok)))
    return ok


def info(name, detail=""):
    print(f"  [{INFO}] {name}" + (f"  -- {detail}" if detail else ""))


_last_connect = [0.0]
CONNECT_SPACING = 8.0   # stay under THROTTLE_TRIGCOUNT(3)/TRIGTIME(15s) per IP


def client(node, tls=False, timeout=8, pace=True):
    """Connect, pacing new connections to avoid the server's per-IP throttle."""
    if pace:
        wait = CONNECT_SPACING - (time.monotonic() - _last_connect[0])
        if wait > 0:
            time.sleep(wait)
    ip, plain, tlsp = NODE[node]
    port = tlsp if tls else plain
    c = IRCClient(host=ip, port=port, use_tls=tls, timeout=timeout)
    c.connect()
    _last_connect[0] = time.monotonic()
    return c


def uniq(p):
    return f"{p}{os.getpid() % 10000}{int(time.time()) % 1000}"


# ---------------------------------------------------------------------------
# Phase: smoke — verify the 3-node chain is functional end-to-end
# ---------------------------------------------------------------------------
def test_smoke():
    print("\n=== SMOKE: 3-node chain (node1 <-> node3 across node2) ===")
    a = client("node1")
    b = client("node3")
    try:
        na, nb = uniq("alice"), uniq("bob")
        a.register(na)
        b.register(nb)
        check("node1 client registers (001)", True)
        check("node3 client registers (001)", True)

        # LINKS from node1 should list all 3 gossip servers
        a.send("LINKS")
        links = a.collect_lines(4)
        seen = {n for n in ("node1.testnet", "node2.testnet", "node3.testnet")
                if any(n in l for l in links)}
        check("LINKS shows node1+node2+node3", len(seen) == 3, f"saw {sorted(seen)}")

        # Channel membership propagation across the chain
        chan = "#" + uniq("smoke")
        a.send(f"JOIN {chan}")
        a.wait_for("JOIN")
        b.send(f"JOIN {chan}")
        b.wait_for("JOIN")
        # a (node1) should be told bob (node3) joined -> membership crossed chain
        try:
            line = a.wait_for(f"{nb}", timeout=6)
            check("channel JOIN propagates node3->node1", "JOIN" in line, line)
        except TimeoutError as e:
            check("channel JOIN propagates node3->node1", False, str(e)[:80])

        # PRIVMSG across the chain
        b.send(f"PRIVMSG {chan} :hello-from-node3")
        try:
            line = a.wait_for("hello-from-node3", timeout=6)
            check("PRIVMSG propagates node3->node1", True, line[:70])
        except TimeoutError as e:
            check("PRIVMSG propagates node3->node1", False, str(e)[:80])

        # NICK change propagation
        na2 = uniq("alice2")
        a.send(f"NICK {na2}")
        try:
            line = b.wait_for("NICK", timeout=6)
            check("NICK change propagates node1->node3", na2 in line, line[:70])
        except TimeoutError as e:
            check("NICK change propagates node1->node3", False, str(e)[:80])

        # TOPIC propagation
        topic = "live-topic-" + uniq("t")
        a.send(f"TOPIC {chan} :{topic}")
        try:
            line = b.wait_for("TOPIC", timeout=6)
            check("TOPIC propagates node1->node3", topic in line, line[:70])
        except TimeoutError as e:
            check("TOPIC propagates node1->node3", False, str(e)[:80])
    finally:
        a.disconnect()
        b.disconnect()


def test_chain():
    """Live nick/topic/channel propagation across the FULL chain ends: node1<->node4."""
    print("\n=== CHAIN: live propagation node1 (leaf) <-> node4 (leaf), 3 hops ===")
    A = client("node1"); na = uniq("ca"); A.register(na)
    B = client("node4"); nb = uniq("cb"); B.register(nb)
    chan = "#chain" + str(os.getpid() % 1000)
    for cl in (A, B):
        cl.send(f"JOIN {chan}"); cl.wait_for("366")
    time.sleep(3)
    B.send(f"NAMES {chan}")
    names = " ".join(l for l in B.collect_lines(2) if " 353 " in l)
    check("node4 sees node1 user in channel (membership across 3 hops)",
          na in names, names[-50:] if names else "EMPTY")

    def obs(act, secs=4):
        B.collect_lines(0.3); B.send("PING :s")
        try: B.wait_for("s", timeout=3)
        except TimeoutError: pass
        act(); return B.collect_lines(secs)

    raw = obs(lambda: A.send(f"PRIVMSG {chan} :chain-msg"))
    check("channel PRIVMSG node1->node4 (live)", any("chain-msg" in l for l in raw),
          next((l[:55] for l in raw if "chain-msg" in l), "not delivered"))

    na2 = uniq("ca2")
    raw = obs(lambda: A.send(f"NICK {na2}"))
    check("NICK change node1->node4 (live)", any("NICK" in l and na2 in l for l in raw),
          next((l[:55] for l in raw if "NICK" in l), "no NICK"))

    topic = "chain-topic-" + uniq("t")
    raw = obs(lambda: A.send(f"TOPIC {chan} :{topic}"))
    check("TOPIC change node1->node4 (live)", any("TOPIC" in l and topic in l for l in raw),
          next((l[:55] for l in raw if "TOPIC" in l), "no TOPIC"))
    A.disconnect(); B.disconnect()


def numeric(lines, code, needle=None):
    return [l for l in lines if f" {code} " in l and (needle is None or needle in l)]


# ---------------------------------------------------------------------------
# Phase: burst — node4 must learn PRE-EXISTING state when its link comes up
# ---------------------------------------------------------------------------
def burst_setup(hold=100):
    """Create state on node1 (account, channel, topic, live membership) and
    hold the connection so the state is live when node4 links."""
    print("=== BURST SETUP on node1 (state created BEFORE node4 boots) ===")
    h = client("node1", timeout=10)
    nick = "burstuser"
    h.register(nick)
    # best-effort account registration (gossip services data)
    h.send("PRIVMSG NickServ :REGISTER burstpass123 burst@testnet")
    for l in h.collect_lines(3):
        if "NickServ" in l:
            print("   NS>", l.split("NOTICE", 1)[-1][:90])
    # live channel + topic (channel state, not services)
    h.send("JOIN #preexisting")
    h.wait_for("JOIN", timeout=6)
    h.send("TOPIC #preexisting :burst-topic-PRECREATED")
    h.collect_lines(1)
    # best-effort channel registration
    h.send("PRIVMSG ChanServ :REGISTER #preexisting burstpass123 :pre-existing chan")
    for l in h.collect_lines(3):
        if "ChanServ" in l:
            print("   CS>", l.split("NOTICE", 1)[-1][:90])
    print(f"   READY: {nick} online in #preexisting (topic set); holding {hold}s")
    sys.stdout.flush()
    time.sleep(hold)
    h.disconnect()


def diag(node):
    """Print what `node` knows about burstuser / #preexisting."""
    print(f"--- DIAG {node}: knowledge of burstuser / #preexisting ---")
    c = client(node, timeout=10)
    c.register(uniq("diag"))
    c.send("WHOIS burstuser")
    for l in c.collect_lines(3):
        if numeric([l], 311) or numeric([l], 312) or numeric([l], 319):
            print("   WHOIS>", l[:110])
    c.send("WHO #preexisting")
    whos = [l for l in c.collect_lines(3) if numeric([l], 352)]
    print(f"   WHO #preexisting -> {len(whos)} member line(s)")
    for l in whos:
        print("     ", l[:110])
    c.send("TOPIC #preexisting")
    for l in c.collect_lines(3):
        if numeric([l], 332) or numeric([l], 331) or numeric([l], 333):
            print("   TOPIC>", l[:120])
    c.send("LIST #preexisting")
    for l in c.collect_lines(3):
        if numeric([l], 322):
            print("   LIST>", l[:120])
    c.disconnect()


def burst_verify():
    """From node4 (freshly linked), verify it absorbed the pre-existing state."""
    print("\n=== BURST VERIFY from node4 (learned only via link-up burst) ===")
    c = client("node4", timeout=10)
    c.register(uniq("checker"))

    c.send("LINKS")
    links = c.collect_lines(4)
    seen = {n for n in ("node1.testnet", "node2.testnet", "node3.testnet",
                        "node4.testnet") if any(n in l for l in links)}
    check("node4 LINKS shows all 4 servers", len(seen) == 4, f"saw {sorted(seen)}")

    # Remote user that existed before node4 booted
    c.send("WHOIS burstuser")
    wl = c.collect_lines(5)
    check("node4 sees pre-existing remote user burstuser (WHOIS 311)",
          bool(numeric(wl, 311, "burstuser")))
    check("  ...reported on node1.testnet (WHOIS 312)",
          bool(numeric(wl, 312, "node1.testnet")), "remote origin preserved")

    # Channel membership burst
    c.send("WHO #preexisting")
    wh = c.collect_lines(5)
    check("node4 WHO #preexisting shows burstuser (membership burst)",
          bool(numeric(wh, 352, "burstuser")))

    # Joining the pre-existing channel: topic + names came via burst
    c.send("JOIN #preexisting")
    jl = c.collect_lines(5)
    check("node4 JOIN sees pre-existing topic (channel-state burst)",
          any("burst-topic-PRECREATED" in l for l in jl))
    check("node4 NAMES includes pre-existing member burstuser",
          any("burstuser" in l for l in numeric(jl, 353)))

    # Services data burst (best-effort INFO, account path)
    c.send("PRIVMSG NickServ :INFO burstuser")
    ns = c.collect_lines(3)
    if any("burstuser" in l for l in ns):
        info("node4 NickServ INFO burstuser resolved (services burst)", "ok")
    else:
        info("node4 NickServ INFO burstuser", "no/!registered (account reg may be gated)")
    c.disconnect()


EXPECTED_CAPS = [
    "multi-prefix", "away-notify", "account-notify", "extended-join",
    "chghost", "invite-notify", "setname", "userhost-in-names",
    "echo-message", "server-time", "batch", "labeled-response",
    "message-tags", "cap-notify",
]  # note: sasl intentionally NOT loaded on these nodes


def negotiate(c, want, nick):
    """CAP LS -> REQ advertised subset of `want` -> register. Returns (avail, acked)."""
    c.send("CAP LS 302")
    avail = {}
    while True:
        line = c.wait_for("CAP")
        seg = line.split(" LS ", 1)[1] if " LS " in line else ""
        more = seg.lstrip().startswith("*")
        payload = line.split(" :", 1)[1] if " :" in line else ""
        for t in payload.split():
            avail[t.split("=")[0]] = t
        if not more:
            break
    req = [x for x in want if x in avail]
    if req:
        c.send("CAP REQ :" + " ".join(req))
        c.wait_for_any(["ACK", "NAK"])
    c.send(f"NICK {nick}")
    c.send(f"USER {nick} 0 * :{nick} realname")
    c.send("CAP END")
    c.wait_for("001")
    return avail, req


OBS = ["server-time", "message-tags", "account-notify", "account-tag",
       "away-notify", "extended-join", "invite-notify", "setname", "chghost",
       "multi-prefix", "userhost-in-names", "echo-message", "batch",
       "labeled-response", "msgid", "draft/chathistory", "chathistory"]


def test_ircv3():
    print("\n=== IRCv3 capabilities (A=node1, B=node4, C=node2; reused conns) ===")

    # --- CAP advertisement on both chain ends ---
    for node in ("node1", "node4"):
        c = client(node)
        c.send("CAP LS 302")
        avail = {}
        while True:
            line = c.wait_for("CAP")
            seg = line.split(" LS ", 1)[1] if " LS " in line else ""
            more = seg.lstrip().startswith("*")
            payload = line.split(" :", 1)[1] if " :" in line else ""
            for t in payload.split():
                avail[t.split("=")[0]] = t
            if not more:
                break
        missing = [x for x in EXPECTED_CAPS if x not in avail]
        check(f"{node} advertises core caps (CAP LS)", not missing,
              f"{len(avail)} caps" + (f"; missing {missing}" if missing else ""))
        check(f"{node} advertises chathistory",
              "draft/chathistory" in avail or "chathistory" in avail)
        c.disconnect()

    A_CAPS = ["echo-message", "message-tags", "server-time", "setname",
              "labeled-response", "multi-prefix", "userhost-in-names"]
    A = client("node1"); negotiate(A, A_CAPS, uniq("A")); an = A_nick(A)
    B = client("node4"); negotiate(B, OBS, uniq("B")); bn = A_nick(B)
    C = client("node2"); negotiate(C, ["away-notify", "message-tags"], uniq("C")); cn = A_nick(C)
    chan = "#v" + str(os.getpid() % 1000)
    for cl in (A, B):
        cl.send(f"JOIN {chan}"); cl.wait_for("366")
    time.sleep(3)
    B.send(f"NAMES {chan}")
    _bn = " ".join(l for l in B.collect_lines(2) if " 353 " in l)
    print(f"  [setup] A={an} B={bn} C={cn}; B membership: {_bn.split('=',1)[-1][:60] if _bn else 'EMPTY'}")

    def observe(actor_send, seconds=4):
        """Sync B, run actor action, return B's raw lines for `seconds`."""
        B.collect_lines(0.4)
        B.send("PING :sync"); B.wait_for("sync", timeout=3)
        actor_send()
        return B.collect_lines(seconds)

    def tags_of(line):
        return line.split(" ", 1)[0] if line.startswith("@") else ""

    # server-time + msgid on cross-server channel PRIVMSG
    raw = observe(lambda: A.send(f"PRIVMSG {chan} :hello-tags"))
    msg = next((l for l in raw if "hello-tags" in l), None)
    check("cross-server PRIVMSG delivered to remote member", msg is not None,
          (msg or "not delivered")[:60])
    check("server-time tag present on relayed PRIVMSG", bool(msg) and "time=" in tags_of(msg),
          tags_of(msg) if msg else "")
    check("msgid tag present on relayed PRIVMSG", bool(msg) and "msgid=" in tags_of(msg),
          tags_of(msg) if msg else "")

    # echo-message (local)
    A.collect_lines(0.3)
    A.send(f"PRIVMSG {chan} :echo-check")
    try:
        line = A.wait_for("echo-check", timeout=5)
        check("echo-message returns sender's own message", "PRIVMSG" in line, tags_of(line)[:50])
    except TimeoutError as e:
        check("echo-message returns sender's own message", False, str(e)[:50])

    # away-notify (cross-server)
    raw = observe(lambda: A.send("AWAY :lunch"))
    check("away-notify: AWAY propagates node1->node4",
          any("AWAY" in l and "lunch" in l for l in raw),
          next((l[:55] for l in raw if "AWAY" in l), "no AWAY"))
    A.send("AWAY")

    # setname (cross-server)
    raw = observe(lambda: A.send("SETNAME :Brand New Name"))
    check("setname: SETNAME propagates node1->node4",
          any("SETNAME" in l and "Brand New Name" in l for l in raw),
          next((l[:55] for l in raw if "SETNAME" in l), "no SETNAME"))

    # invite-notify (cross-server): A invites C (real, online) to chan; B (member) observes
    raw = observe(lambda: A.send(f"INVITE {cn} {chan}"))
    check("invite-notify: channel members see INVITE",
          any("INVITE" in l and cn in l for l in raw),
          next((l[:55] for l in raw if "INVITE" in l), "no INVITE"))

    # tagmsg (cross-server)
    raw = observe(lambda: A.send(f"@+typing=active TAGMSG {chan}"))
    check("tagmsg: TAGMSG delivered to remote member",
          any("TAGMSG" in l for l in raw),
          next((l[:55] for l in raw if "TAGMSG" in l), "no TAGMSG"))
    check("tagmsg: client tag (+typing) preserved on relay",
          any("TAGMSG" in l and "typing" in l for l in raw),
          next((tags_of(l) for l in raw if "TAGMSG" in l), ""))

    # labeled-response (local)
    A.collect_lines(0.3)
    A.send("@label=zz9 PING :probe")
    try:
        line = A.wait_for("zz9", timeout=5)
        check("labeled-response: reply echoes @label", "label=zz9" in line, line[:55])
    except TimeoutError as e:
        check("labeled-response: reply echoes @label", False, str(e)[:50])

    # chathistory + batch (node4 buffers relayed channel msgs)
    A.collect_lines(0.3)
    for i in range(3):
        A.send(f"PRIVMSG {chan} :hist{i}")
    time.sleep(3)
    B.send(f"CHATHISTORY LATEST {chan} * 10")
    lines = B.collect_lines(5)
    check("chathistory: BATCH returned", any("BATCH" in l for l in lines))
    nh = sum(1 for l in lines if "hist" in l)
    check("chathistory: relayed messages present in history", nh >= 1, f"{nh} msgs")

    # extended-join (cross-server): B in #ej, A joins, B sees extended JOIN
    ej = "#ej" + str(os.getpid() % 1000)
    B.send(f"JOIN {ej}"); B.wait_for("366")
    raw = observe(lambda: A.send(f"JOIN {ej}"))
    jline = next((l for l in raw if "JOIN" in l and ej in l), None)
    check("extended-join: remote JOIN delivered", jline is not None,
          (jline or "not delivered")[:60])
    if jline:
        parts = jline.split(f"JOIN {ej} ", 1)
        check("extended-join: JOIN carries account+realname",
              len(parts) == 2 and " :" in parts[1], jline[:70])
    else:
        check("extended-join: JOIN carries account+realname", False, "")

    # multi-prefix + userhost-in-names (A op in fresh channel)
    pc = "#p" + str(os.getpid() % 1000)
    A.send(f"JOIN {pc}"); A.wait_for("366")
    A.send(f"MODE {pc} +v {an}")
    time.sleep(1)
    A.collect_lines(0.3)
    A.send(f"NAMES {pc}")
    names = " ".join(l for l in A.collect_lines(3) if " 353 " in l)
    check("multi-prefix: op+voice shown as @+ in NAMES", "@+" in names,
          names[-45:] if names else "no names")
    check("userhost-in-names: NAMES entries include user@host",
          ("!" in names and "@" in names), names[-45:] if names else "")

    # monitor (cross-server presence): B monitors C (online on node2)
    B.collect_lines(0.3)
    B.send(f"MONITOR + {cn}")
    mraw = B.collect_lines(4)
    check("monitor: RPL_MONONLINE for cross-server-online target (730)",
          any(" 730 " in l and cn in l for l in mraw),
          next((l[:55] for l in mraw if " 73" in l), "no 730/731"))

    # bot-mode (umode +B)
    A.collect_lines(0.3)
    A.send(f"MODE {an} +B")
    try:
        line = A.wait_for("MODE", timeout=5)
        check("bot-mode: umode +B accepted", "B" in line.rsplit(" ", 1)[-1], line[:55])
    except TimeoutError as e:
        check("bot-mode: umode +B accepted", False, str(e)[:50])

    # STARTTLS (fresh plain connection)
    s = client("node1")
    s.send("STARTTLS")
    try:
        pat, line = s.wait_for_any(["670", "691"], timeout=5)
        check("STARTTLS: server replies 670 (ready to begin TLS)", pat == "670", line[:55])
    except TimeoutError as e:
        check("STARTTLS: server replies 670 (ready to begin TLS)", False, str(e)[:50])
    s.disconnect()

    info("account-notify/account-tag advertised; cross-server login needs SASL/services (excluded)")
    info("chghost advertised; host-change trigger needs oper/services (not exercised)")

    A.disconnect(); B.disconnect(); C.disconnect()

def A_nick(c):
    """Best-effort: recover our own nick from the welcome line history."""
    for l in c.all_lines:
        if " 001 " in l:
            return l.split(" 001 ", 1)[1].split(" ", 1)[0]
    return "*"


def test_matrix():
    """One client per node joins #matrix; each reports which nicks it sees via
    NAMES. Reveals exactly where live multi-hop propagation breaks."""
    print("\n=== MATRIX: live user visibility across the chain ===")
    chan = "#matrix" + str(os.getpid() % 1000)
    nicks = {n: f"u_{n}_{os.getpid()%1000}" for n in ("node1", "node2", "node3", "node4")}
    cs = {}
    for n in ("node1", "node2", "node3", "node4"):
        c = client(n, timeout=10)
        c.register(nicks[n])
        c.send(f"JOIN {chan}")
        c.wait_for("JOIN", timeout=6)
        cs[n] = c
    time.sleep(4)  # let live events propagate across all hops
    hopdist = {"node1": 0, "node2": 1, "node3": 2, "node4": 3}
    print(f"   channel={chan}  nicks={ {k:v for k,v in nicks.items()} }")
    for n in ("node1", "node2", "node3", "node4"):
        c = cs[n]
        c.send(f"NAMES {chan}")
        names = " ".join(l for l in c.collect_lines(3) if " 353 " in l)
        seen = [m for m in ("node1", "node2", "node3", "node4")
                if nicks[m] in names]
        miss = [m for m in ("node1", "node2", "node3", "node4") if m not in seen]
        ok = len(seen) == 4
        check(f"{n} sees all 4 members in {chan}", ok,
              f"sees {seen}" + (f", MISSING {miss}" if miss else ""))
    for c in cs.values():
        c.disconnect()


def summary():
    print("\n=== SUMMARY ===")
    npass = sum(1 for _, ok in _results if ok)
    for name, ok in _results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    print(f"\n  {npass}/{len(_results)} passed")
    return npass == len(_results)


if __name__ == "__main__":
    phase = sys.argv[1] if len(sys.argv) > 1 else "smoke"
    if phase == "burst_setup":
        burst_setup(int(sys.argv[2]) if len(sys.argv) > 2 else 100)
        sys.exit(0)
    if phase == "burst_verify":
        burst_verify()
        sys.exit(0 if summary() else 1)
    if phase == "diag":
        diag(sys.argv[2] if len(sys.argv) > 2 else "node3")
        sys.exit(0)
    if phase == "matrix":
        test_matrix()
        sys.exit(0 if summary() else 1)
    if phase == "ircv3":
        test_ircv3()
        sys.exit(0 if summary() else 1)
    if phase == "chain":
        test_chain()
        sys.exit(0 if summary() else 1)
    if phase in ("smoke", "all"):
        test_smoke()
    if phase in ("chain", "all"):
        test_chain()
    if phase in ("matrix", "all"):
        test_matrix()
    if phase in ("ircv3", "all"):
        test_ircv3()
    ok = summary()
    sys.exit(0 if ok else 1)
