# Operations

Running the pieces, reading their logs, and the four failures that come up
most often.

---

## Starting and stopping

### The receiver

```sh
sudo systemctl start moesh-bridge
sudo systemctl stop moesh-bridge
sudo systemctl restart moesh-bridge
systemctl is-active moesh-bridge
```

The unit restarts the bridge if it exits, and writes its log to
`/var/log/moesh-bridge.log`:

```sh
tail -f /var/log/moesh-bridge.log
journalctl -u moesh-bridge -n 50
```

### The agent

With the example unit from [install.md](install.md):

```sh
sudo systemctl start moesh-agent
sudo systemctl restart moesh-agent
systemctl is-active moesh-agent
tail -f /var/log/moesh-agent.log
```

The agent can also run in the foreground while you set it up:

```sh
cd /opt/moesh
sudo /opt/moesh/.venv/bin/python /opt/moesh/moesh_tunnel_v2.py
```

Stopping the agent terminates the shells it owns (`SIGHUP`) and reaps them,
so no shell is left behind. A shell does **not** outlive its agent.

### The operator's client

```sh
python3 /opt/moesh/moesh_shell_v2.py -n 3
```

| you want | do this |
|---|---|
| leave the shell running, come back later | type `~.` (a tilde and a full stop, at the start of a line) |
| a brand-new shell | `python3 /opt/moesh/moesh_shell_v2.py -n 3 --fresh` |
| give up when the connection drops | `python3 /opt/moesh/moesh_shell_v2.py -n 3 --no-reconnect` |

The client exits with the remote shell's exit status.

---

## The log lines that matter

### The receiver

| line | meaning |
|---|---|
| `tunnel listening on 127.0.0.1:9447` | the tunnel listener is up |
| `operator-v2 listening on 127.0.0.1:44441` | the operator listener is up |
| `host tunnel v2 attached from ... host host-3` | an agent's tunnel arrived |
| `operator-v2[host-3] attached from ...` | an operator connection arrived |
| `pairing operator-v2[host-3] with a host` | the two were paired |
| `discarding stale operator-v2[host-3] tunnel` | a queued tunnel had died; it was dropped, not paired |
| `operator-v2[host-3] connected but no operator-v2[host-3] tunnel within 120s` | nobody answered within the wait |
| `tunnel queue full — dropping ...` | eight tunnels were already queued for that host |
| `refused handshake: ...` | the upgrade request was rejected |
| `bind 127.0.0.1:9447 failed: ...` | the port was already taken |

### The agent

| line | meaning |
|---|---|
| `agent static public key: <hex>` | the key this agent is using |
| `upgraded (HTTP/1.1 101 Switching Protocols, token moesh-tunnel-v2, host host-3)` | the receiver accepted the tunnel |
| `queued at the receiver; waiting for an authenticated operator` | the tunnel is in the receiver's queue |
| `tunnel established; waiting for an operator` | the tunnel is up and idle |
| `authenticated (peer static key matched the pin)` | the operator's key matched |
| `shell started (pid 1234, 24x80)` | a new shell was created |
| `attached to the running shell (pid 1234)` | an existing shell was re-attached |
| `replaying 136 buffered bytes` | output produced while nobody was attached |
| `session active: term=xterm-256color 24x80` | the session is running |
| `resized to 40x120` | the terminal was resized |
| `an operator detached; its shell keeps running` | a session ended; the shell lives on |
| `a shell exited; the others keep running` | one shell ended |
| `no traffic from the operator for 90s; detaching (the shell stays)` | the operator went silent |
| `AUTHENTICATION FAILED: ... — refusing to retry for 60s` | the pin did not match; the agent waits before trying again |

### The operator's client

| line | meaning |
|---|---|
| `waiting for host 'host-3' — the receiver is holding this connection while it attaches (it may be restarting)…` | the client is waiting for the agent |
| `authenticated (agent static key matched the pin)` | the agent's key matched |
| `a new shell was started` | a fresh shell was created |
| `re-attached to the running shell: the previous session continues` | the running shell was picked up again |
| `session active: 24x80 term=xterm-256color` | the session is running |
| `sent resize 40x120` | the local window changed |
| `the connection dropped; the remote shell keeps running` | the transport died; the shell is alive |
| `connection lost (...); re-attaching in 2s — the remote shell keeps running` | the client is retrying |
| `detached: the remote shell keeps running; run moesh-shell-v2 again to re-attach` | you typed `~.` |
| `remote shell exited (status 0)` | the shell ended |
| `agent closed the session (authenticated close)` | the agent ended the session cleanly |
| `session failed: ...` | the session could not start or ended in error |

The client logs to standard error; standard output carries your terminal.

---

## Common failures

### nginx answers `502 Bad Gateway`

The receiver could not be reached, or the proxy points at the wrong place.

```sh
systemctl is-active moesh-bridge
sudo nginx -t
ss -ltnp | grep -E '9447|44441'
sudo tail -n 50 /var/log/moesh-bridge.log
```

* If the bridge is not listening on `127.0.0.1:9447`, `proxy_pass` has the
  wrong address.
* If the bridge logged `bind ... failed`, another process holds the port.
* If nginx is fine but the agent cannot connect, check the firewall: the
  agent dials TCP 80 on the receiver.

### The keys do not match

```
AUTHENTICATION FAILED: peer static key mismatch: pinned ..., learned ...
```

on the agent, and on the client:

```
session failed: AuthenticationError('peer static key mismatch: pinned ..., learned ...')
```

The pin is not the key the other side is using. The agent waits 60 seconds
before trying again, so a fix does not take effect immediately.

```sh
# compare what each side believes
cat /etc/moesh/agent.key.pub
cat ~/.config/moesh/hosts.toml
```

Either the `agent_pub` in `hosts.toml` is stale, or the agent was given a new
key without the operator being told. See [keys.md](keys.md) for rotation.

### The operator connects and no prompt appears

The client waits for the agent to answer the handshake; the receiver holds
the connection for up to 120 seconds while it looks for one.

1. Is the agent running and queued?

   ```sh
   systemctl is-active moesh-agent
   sudo tail -n 20 /var/log/moesh-agent.log
   ```

   The line `tunnel established; waiting for an operator` means the agent is
   waiting for you. `queued at the receiver` means it reached the receiver
   but has not been handed a connection yet.

2. Did the receiver pair the two?

   ```sh
   sudo tail -n 20 /var/log/moesh-bridge.log
   ```

   `pairing operator-v2[host-3] with a host` means the pairing happened.

3. Did the operator ask for the right name? The client's `-n 3` becomes
   `host-3`; the agent's `MOESH_TUNNEL_V2_HOST=3` becomes `host-3` too. A
   mismatch means the receiver keeps two queues apart and never pairs them.

4. Did the session fail after the pairing? The client's own log says so
   directly (`session failed: ...`).

**Do not test the operator port with a plain connection.** The receiver pairs
any connection with a queued tunnel, so a test consumes one and the real
operator waits for the next. Read the receiver's log instead.

### A stale client is still running

A client left behind — in a terminal multiplexer, or in a disconnected
terminal that reconnected on its own — keeps retrying. Every attempt takes
one of the agent's concurrent slots (three by default), and the real operator
gets nothing.

```sh
tmux ls
```

Kill the stale session, then check the agent's log: the slots come back as
soon as the client stops retrying.

If you want the client to stop retrying by itself, run it with
`--no-reconnect` in the first place.

### The shell came back, but the state did not

Re-attaching restores the running shell, so the working directory, the
variables and the background jobs are the ones from before — but the
*output* produced while nobody was attached is kept in a bounded buffer
(256 KiB), and older output is dropped when that buffer is full.

One re-attach failure is known and intermittent: the prompt appears, but the
output produced after the re-attach does not come through. When a session
comes back wrong, reconnect with `--fresh` and start a new shell.

---

## Checking that things are alive

Never by connecting to the operator port. Use the logs and the processes:

```sh
systemctl is-active moesh-bridge
systemctl is-active moesh-agent
ss -ltnp | grep -E '9447|44441'
sudo tail -n 5 /var/log/moesh-bridge.log
sudo tail -n 5 /var/log/moesh-agent.log
```

An agent with `tunnel established; waiting for an operator` in its log is
ready to be attached to.
