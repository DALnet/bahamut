#!/usr/bin/env python3
"""Start a small local bahamut network and run tests against it.

    tools/testnet/testnet.py up       # start hub + leaves, wait until linked
    tools/testnet/testnet.py test     # up (if needed), run tests/, down
    tools/testnet/testnet.py down     # stop every server

Only needs python3, the openssl CLI and a built src/ircd.
"""

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)

import ircclient  # noqa: E402

LINK_PASS = "linkpass"
OPER = {"name": "admin", "password": "operpass"}

# name, client port, server port, TLS server port, uplink (hub), link flags
SERVERS = [
    {"name": "hub.test", "port": 16667, "tls_port": 16697,
     "sport": 17000, "tls_sport": 17001, "uplink": None},
    {"name": "leaf1.test", "port": 16668, "tls_port": 16698,
     "sport": 17010, "tls_sport": 17011,
     "uplink": {"port": 17000, "flags": "HZ"}},          # plain + zip
    {"name": "leaf2.test", "port": 16669, "tls_port": 16699,
     "sport": 17020, "tls_sport": 17021,
     "uplink": {"port": 17001, "flags": "HSZ"}},         # TLS + zip
]


def server_conf(srv):
    lines = [
        'global { name %s; info "testnet %s"; '
        'admin { "testnet"; "testnet"; "testnet"; }; };' % (srv["name"], srv["name"]),
        'options { network_name testnet; servtype hub; local_kline a@b; '
        'network_kline a@b; services_name services.test; stats_name stats.test; '
        'nshelpurl "http://localhost"; spamfilterurl "http://localhost"; };',
        "port { port %d; bind 127.0.0.1; };" % srv["port"],
        "port { port %d; bind 127.0.0.1; flags S; };" % srv["tls_port"],
        "port { port %d; bind 127.0.0.1; };" % srv["sport"],
        "port { port %d; bind 127.0.0.1; flags S; };" % srv["tls_sport"],
        # T: exempt from connection throttling, tests reconnect quickly
        "allow { host *@*; class users; flags T; };",
        "class { name users; maxusers 500; pingfreq 90; maxsendq 100000; "
        "maxclones 500:500; };",
        "class { name servers; pingfreq 60; connfreq 5; maxsendq 5000000; "
        "maxlinks 10; };",
        "class { name opers; pingfreq 90; maxsendq 500000; };",
        "oper { name %s; passwd %s; access OAaRD; host *@*; class opers; };"
        % (OPER["name"], OPER["password"]),
    ]
    if srv["uplink"]:
        lines.append(
            "connect { name hub.test; host 127.0.0.1; apasswd %s; cpasswd %s; "
            "port %d; flags %s; class servers; };"
            % (LINK_PASS, LINK_PASS, srv["uplink"]["port"], srv["uplink"]["flags"]))
    else:
        for leaf in SERVERS[1:]:
            lines.append(
                "connect { name %s; host 127.0.0.1; apasswd %s; cpasswd %s; "
                "flags Z; class servers; };" % (leaf["name"], LINK_PASS, LINK_PASS))
    return "\n".join(lines) + "\n"


def port_open(port):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=1).close()
        return True
    except OSError:
        return False


def server_pids(run_dir):
    pids = []
    if not os.path.isdir(run_dir):
        return pids
    for name in sorted(os.listdir(run_dir)):
        pidfile = os.path.join(run_dir, name, "testnet.pid")
        if os.path.exists(pidfile):
            with open(pidfile) as f:
                pids.append(int(f.read().strip()))
    return pids


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def is_up(run_dir):
    pids = server_pids(run_dir)
    return len(pids) == len(SERVERS) and all(alive(p) for p in pids)


def control_client(port, timeout=60):
    """Connect as an oper and turn off connection throttling.

    Every client and server link comes from 127.0.0.1, so the default
    throttle (3 connections in 15s) would z-line the tests.  Refused
    connects don't count towards it, so retry until the server listens.
    """
    deadline = time.time() + timeout
    while True:
        try:
            c = ircclient.Client(port)
            break
        except ConnectionRefusedError:
            if time.time() > deadline:
                raise SystemExit("server on port %d never started" % port)
            time.sleep(0.5)
    c.register()
    c.oper({"oper": OPER})
    c.send("SET THROTTLE ENABLE off")
    c.expect(r"throttle ENABLE to OFF")
    return c


def wait_linked(c, net, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        c.send("LINKS")
        lines = c.lines_until(r" 365 ")
        found = {l.split()[3] for l in lines if " 364 " in l}
        if all(s["name"] in found for s in net["servers"]):
            return
        time.sleep(1)
    raise SystemExit("timed out waiting for servers to link")


def up(args):
    if is_up(args.dir):
        print("testnet already running in " + args.dir)
        return
    ircd = os.path.abspath(args.ircd)
    if not os.access(ircd, os.X_OK):
        raise SystemExit("ircd binary not found: %s (run make first)" % ircd)
    if shutil.which("openssl") is None:
        raise SystemExit("openssl CLI is required")
    for srv in SERVERS:
        if port_open(srv["port"]):
            raise SystemExit("port %d is already in use" % srv["port"])

    shutil.rmtree(args.dir, ignore_errors=True)
    try:
        start_servers(args, ircd)
    except BaseException:
        down(args)
        raise


def start_servers(args, ircd):
    os.makedirs(args.dir)
    net = {"servers": [{"name": s["name"], "port": s["port"],
                        "tls_port": s["tls_port"]} for s in SERVERS],
           "oper": OPER, "ircd": ircd}
    with open(os.path.join(args.dir, "network.json"), "w") as f:
        json.dump(net, f, indent=2)

    # the hub goes first so its throttle is off before the leaves link in
    hub_control = None
    for srv in SERVERS:
        sdir = os.path.join(args.dir, srv["name"])
        os.makedirs(sdir)
        with open(os.path.join(sdir, "ircd.conf"), "w") as f:
            f.write(server_conf(srv))
        with open(os.path.join(sdir, "ircd.motd"), "w") as f:
            f.write("testnet %s\n" % srv["name"])
        subprocess.check_call(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", "ircd.key", "-out", "ircd.crt", "-days", "30",
             "-subj", "/CN=" + srv["name"]],
            cwd=sdir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log = open(os.path.join(sdir, "testnet.log"), "w")
        proc = subprocess.Popen([ircd, "-t"], cwd=sdir, stdin=subprocess.DEVNULL,
                                stdout=log, stderr=subprocess.STDOUT,
                                start_new_session=True)
        with open(os.path.join(sdir, "testnet.pid"), "w") as f:
            f.write("%d\n" % proc.pid)
        c = control_client(srv["port"])
        if hub_control is None:
            hub_control = c
        else:
            c.close()

    print("servers started, waiting for links...")
    try:
        wait_linked(hub_control, net, 180)
    finally:
        hub_control.close()
    print("testnet up: " + ", ".join("%s:%d" % (s["name"], s["port"])
                                     for s in SERVERS))


def down(args):
    pids = server_pids(args.dir)
    for name in os.listdir(args.dir) if os.path.isdir(args.dir) else []:
        pidfile = os.path.join(args.dir, name, "testnet.pid")
        if os.path.exists(pidfile):
            os.unlink(pidfile)
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.time() + 10
    for pid in pids:
        while time.time() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.2)
        else:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    if pids:
        print("testnet down")


def test(args):
    started = not is_up(args.dir)
    os.environ["TESTNET_DIR"] = args.dir
    try:
        if started:
            up(args)
        loader = unittest.TestLoader()
        suite = loader.discover(os.path.join(HERE, "tests"),
                                pattern=args.pattern, top_level_dir=HERE)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    finally:
        if started and not args.keep:
            down(args)
    sys.exit(0 if result.wasSuccessful() else 1)


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("command", choices=["up", "down", "test"])
    p.add_argument("--ircd", default=os.path.join(REPO, "src", "ircd"),
                   help="ircd binary to run (default: src/ircd)")
    p.add_argument("--dir", default=ircclient.DEFAULT_RUN_DIR,
                   help="where server configs and logs are written")
    p.add_argument("--pattern", default="test_*.py",
                   help="test file pattern for the test command")
    p.add_argument("--keep", action="store_true",
                   help="leave the network running after test")
    args = p.parse_args()
    args.dir = os.path.abspath(args.dir)
    {"up": up, "down": down, "test": test}[args.command](args)


if __name__ == "__main__":
    main()
