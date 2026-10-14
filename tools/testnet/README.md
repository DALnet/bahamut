# testnet

Starts a small linked bahamut network on 127.0.0.1 and runs client tests
against it. Requires only `python3` (3.6+), the `openssl` CLI and a built
`src/ircd`, so it works the same on Linux, macOS, or CI.

```
hub.test    clients 16667, TLS clients 16697
 |-- leaf1.test   plain link, flags HZ   (clients 16668)
 `-- leaf2.test   TLS link,   flags HSZ  (clients 16669)
```

## Usage

From the repository root, after `./configure && make`:

```sh
tools/testnet/testnet.py test                 # start, run tests/, stop
tools/testnet/testnet.py test --pattern 'test_cap*'
tools/testnet/testnet.py test --keep          # leave it running afterwards
tools/testnet/testnet.py up                   # start only, then connect your client
tools/testnet/testnet.py down
tools/testnet/testnet.py test --ircd /path/to/other/ircd
```

Configs, certificates and logs are written to `tools/testnet/run/` (ignored
by git). The oper login is `admin` / `operpass`. Each server's oper control
connection turns off connection throttling at startup, since every client
comes from 127.0.0.1.

## Writing tests

Add a `tests/test_*.py` file using `unittest` and the helpers in
`ircclient.py`:

```python
import unittest

from ircclient import Client, load_network

class AwayNotifyTest(unittest.TestCase):
    def test_example(self):
        net = load_network()
        c = Client(net["servers"][1]["port"])   # leaf1
        c.send("CAP REQ :away-notify")
        c.expect(r" CAP \S+ ACK ")
        c.register()
```

- `expect(regex)` consumes lines until one matches and returns it.
- `lines_until(regex)` returns every line it consumed.
- `wait_for_nick(nick)` waits until a user on another server is visible.
  Use it before messaging them, because the NICK may still be propagating.
- `sync()` sends a PING and waits for the PONG, so every earlier reply has
  arrived before you assert that something did *not* happen.
