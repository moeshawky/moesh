# Operations

Running the pieces, reading their logs, and diagnosing common operational issues.

---

## 1. Starting and stopping

### The receiver

```sh
sudo systemctl start moesh-bridge
sudo systemctl stop moesh-bridge
sudo systemctl restart moesh-bridge
systemctl is-active moesh-bridge
```

The systemd unit restarts the bridge automatically and writes logs to `/var/log/moesh-bridge.log`:

```sh
tail -f /var/log/moesh-bridge.log
journalctl -u moesh-bridge -n 50
```

### The agent

With the systemd unit from [install.md](install.md):

```sh
sudo systemctl start moesh-agent
sudo systemctl restart moesh-agent
systemctl is-active moesh-agent
tail -f /var/log/moesh-agent.log
```

Foreground run for interactive testing:

```sh
python3 /opt/moesh/moesh_tunnel.py
```

Stopping the agent terminates active shells (`SIGHUP`) and reaps child processes cleanly. A shell does not outlive its parent agent process.

### The operator's shell client (`moesh_shell.py` / `moesh`)

```sh
# Connect to host-3
moesh -n 3
# Or via python:
python3 /opt/moesh/moesh_shell.py -n 3
```

| action | how to do it |
|---|---|
| detach from shell (leaves it running) | type `~.` (tilde followed by dot at start of line) |
| request a brand-new shell | `moesh -n 3 --fresh` |
| disable automatic reconnect | `moesh -n 3 --no-reconnect` |

### Secure file copy (`moecp`)

```sh
# Upload a file to remote host-3
moecp weights.bin host-3:/opt/models/weights.bin

# Recursively download a directory
moecp -r host-3:/var/log/train ./logs/

# Preserve timestamps and permissions in quiet mode (ideal for scripts)
moecp -r -p -q ./dataset host-3:/data/
```

### Accelerator service relay (`moesh_relay.py`)

On remote GPU/TPU machines exposing background compute services:

```sh
python3 moesh_relay.py \
    --service vllm \
    --target 127.0.0.1:8001 \
    --receiver receiver.example.com
```

---

## 2. The log lines that matter

### The receiver (`/var/log/moesh-bridge.log`)

| log line | meaning |
|---|---|
| `tunnel listening on 127.0.0.1:9447` | agent ingress listener is active |
| `operator-v2 listening on 127.0.0.1:44441` | operator client listener is active |
| `relay[vllm] listening on 127.0.0.1:26429` | reverse relay listener for named service is active |
| `host tunnel v2 attached from ... host host-3` | an agent tunnel connection registered |
| `operator-v2[host-3] attached from ...` | an operator client connected |
| `pairing operator-v2[host-3] with a host` | operator client and agent tunnel spliced |
| `discarding stale operator-v2[host-3] tunnel` | a dead tunnel was pruned from the queue |
| `operator-v2[host-3] connected but no tunnel within 120s` | connection timed out waiting for an agent |
| `tunnel queue full — dropping ...` | queue reached maximum buffer capacity (8 slots) |
| `refused handshake: ...` | HTTP upgrade request was rejected |

### The agent (`/var/log/moesh-agent.log`)

| log line | meaning |
|---|---|
| `agent static public key: <hex>` | active static public key |
| `upgraded (HTTP/1.1 101 Switching Protocols, token moesh-tunnel-v2, host host-3)` | receiver accepted the tunnel connection |
| `queued at the receiver; waiting for an authenticated operator` | tunnel is queued and ready |
| `tunnel established; waiting for an operator` | tunnel socket is idle and listening |
| `authenticated (peer static key matched the pin)` | operator public key verified |
| `shell started (pid 1234, 24x80)` | fresh bash PTY spawned |
| `attached to the running shell (pid 1234)` | operator re-attached to existing shell |
| `replaying 136 buffered bytes` | sending output accumulated while detached |
| `session active: term=xterm-256color 24x80` | terminal streaming active |
| `resized to 40x120` | window dimensions synchronized (`SIGWINCH`) |
| `an operator detached; its shell keeps running` | operator disconnected; shell preserved |
| `no traffic from the operator for 45s; detaching` | silence limit hit; worker detached |
| `AUTHENTICATION FAILED: ... — refusing to retry for 60s` | peer key mismatch; agent delays retry |

### The operator client (stderr)

| log line | meaning |
|---|---|
| `waiting for host 'host-3' — the receiver is holding this connection...` | waiting for agent to connect/pair |
| `authenticated (agent static key matched the pin)` | agent static key verified |
| `a new shell was started` | fresh session started |
| `re-attached to the running shell: the previous session continues` | restored prior interactive shell |
| `session active: 24x80 term=xterm-256color` | session running |
| `sent resize 40x120` | local window resize transmitted |
| `the connection dropped; the remote shell keeps running` | transport interrupted; shell persists |
| `connection lost (...); re-attaching in 2s — the remote shell keeps running` | automatic reconnect initiated |
| `remote shell exited (status 0)` | remote shell exited normally |

---

## 3. Common failures

### nginx answers `502 Bad Gateway`

The receiver bridge is not running, or nginx cannot reach the local port.

```sh
systemctl is-active moesh-bridge
sudo nginx -t
ss -ltnp | grep -E '9447|44441'
sudo tail -n 50 /var/log/moesh-bridge.log
```

* If the bridge is not listening on `127.0.0.1:9447`, verify the systemd unit.
* If the bridge logged `bind ... failed`, another process holds the port.
* If nginx is fine but the remote agent cannot connect, check firewall rules on port 80.

### The keys do not match

```
AUTHENTICATION FAILED: peer static key mismatch: pinned ..., learned ...
```

The peer's static public key does not match any entry in `hosts.toml` or `MOESH_TUNNEL_OPERATOR_PUB`.

```sh
# Compare what each side expects:
cat ~/.config/moesh/hosts.toml
# On the agent:
cat /etc/moesh/agent.key.pub
```

* If using fleet master keys, ensure both sides share the exact same `MOESH_TUNNEL_MASTER` hex string.
* If rotating keys, use `legacy_agent_pub` in `hosts.toml` during the transition window.

### The operator connects and no prompt appears

1. **Check if the agent is running and queued:**
   ```sh
   systemctl is-active moesh-agent
   sudo tail -n 20 /var/log/moesh-agent.log
   ```
   `tunnel established; waiting for an operator` confirms the agent is ready.
2. **Check receiver pairing:**
   ```sh
   sudo tail -n 20 /var/log/moesh-bridge.log
   ```
   Look for `pairing operator-v2[host-3] with a host`.
3. **Verify host number alignment:**
   `-n 3` routes to `host-3`. Ensure the agent's `MOESH_TUNNEL_HOST=3` matches.
4. **Never probe the operator port with plain netcat/curl:**
   The bridge pairs connections FIFO; a plain probe consumes a queued tunnel and starves the operator.

### A stale client is still running

A client left running in a disconnected tmux or screen session keeps retrying, consuming tunnel workers and starving new connections.

```sh
tmux ls
```

Kill stale sessions; the agent's available slots will immediately replenish.

---

## 4. Checking system health

Check status and listening ports without connecting to operator sockets:

```sh
systemctl is-active moesh-bridge
systemctl is-active moesh-agent
ss -ltnp | grep -E '9447|44441|26429|26430'
sudo tail -n 10 /var/log/moesh-bridge.log
sudo tail -n 10 /var/log/moesh-agent.log
```
