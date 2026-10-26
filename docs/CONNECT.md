# CONNECT.md — Canonical Connection & Port Forwarding Guide

*An SSH/SCP/FRP replacement over outbound HTTP/1.1 Upgrade: `Noise_XX` mutual authentication, survivable remote shells, encrypted file copy (`moecp`), and collision-safe reverse TCP port forwarding (`moesh_relay.py`).*

---

## 1. Architecture Overview

```
Remote Host (VM / Notebook / Container)               Receiver Bridge (Public Ingress)            Operator / Client Host
┌──────────────────────────────────────────┐          ┌──────────────────────────────────┐        ┌──────────────────────────┐
│  A. Remote Shell Agent (moesh_tunnel.py) │ HTTP/1.1 │  Reverse Proxy (:80 / :443)      │        │  moesh / moecp           │
│  - Dials /__moesh/tunnel/<host-N>        │ Upgrade  │    │ /__moesh/tunnel/*           │        │  - moesh -n <N>          │
│  - Derives agent + operator keys from    │─────────▶│    │ /__relay/*                  │ :44441 │  - moecp -n <N> ...      │
│    MOESH_TUNNEL_MASTER                   │Ciphertext│    ▼                             │◀───────│  - Noise_XX Mutual Auth  │
│  - Holds exclusive lease on host-N       │          │  moesh-bridge.py (Blind Broker)  │        │  - Survivable PTY attach │
├──────────────────────────────────────────┤          │  - 0 keys held, 0 plaintext seen │        └──────────────────────────┘
│  B. TCP Port Relay (moesh_relay.py)      │ HTTP/1.1 │  - Returns 409 Conflict when a   │        ┌──────────────────────────┐
│  - Dials /__relay/<port|auto|label>      │ Upgrade  │    host slot or relay port/name  │ :26420 │  Any TCP Client          │
│  - Forwards receiver port 26420..26430   │─────────▶│    is already held by another    │  ..    │  - Connects to receiver  │
│    to local 127.0.0.1:<target_port>      │Raw Stream│    live carrier                  │ :26430 │    port 26420..26430     │
└──────────────────────────────────────────┘          └──────────────────────────────────┘◀───────└──────────────────────────┘
```

### Core Guarantees
1. **One Master Key (`MOESH_TUNNEL_MASTER`):** Any agent or operator with the 32-byte hex `MOESH_TUNNEL_MASTER` can start a remote shell daemon (`moesh_tunnel.py`), attach an interactive shell (`moesh_shell.py`), or copy files (`moecp.py`). Both the per-host static key (`host-<N>`) and the default operator static key are deterministically derived from `MOESH_TUNNEL_MASTER` via HKDF-SHA256 (`MOESH_TUNNEL_OPERATOR_PUB` remains supported as an optional additional pin).
2. **Explicit Conflict Detection (`409 Conflict`, Like `frps`/`frpc`):**
   - If two agents dial the same shell host slot (`host-<N>`), the second carrier receives `HTTP/1.1 409 Conflict` listing the currently active hosts and exits with code `3`.
   - If two relays request the same public relay port (`26420–26430`) or the same relay label, the second carrier receives `HTTP/1.1 409 Conflict` listing all free ports and exits with code `3`.
   - Active tunnels and relays never silently share a queue or steal traffic from one another.
3. **Non-Destructive Status Probing (`/__moesh/status`):**
   - **Never probe public relay ports (`26420–26430`) or operator ports (`44441`) with raw TCP connections to check availability** — connecting to a data port consumes a queued standby tunnel (Iron Law 4).
   - Always query `GET /__moesh/status` (or pass `--probe` to `moesh_tunnel.py` / `moesh_relay.py`) over standard HTTP port 80.

---

## 2. Step 1 — Probe Open Ports & Active Hosts Before Connecting

Before choosing a host number (`-n <N>`) or a public relay port (`26420–26430`), query the receiver's control-plane status endpoint over HTTP port 80:

### Using `curl`
```bash
curl -s http://<RECEIVER_HOST>/__moesh/status | python3 -m json.tool
```

Example response:
```json
{
  "ok": true,
  "hosts": {
    "in_use": ["host-2", "host-4"],
    "details": {
      "host-2": {"queued": 3, "active": 1},
      "host-4": {"queued": 3, "active": 0}
    }
  },
  "relay": {
    "ports_open": [26420, 26421, 26422, 26423, 26425, 26426, 26427, 26428, 26429, 26430],
    "ports_free": [26420, 26421, 26422, 26423, 26425, 26427, 26428, 26429],
    "ports_in_use": {
      "26426": {"name": "26426", "queued": 4, "active": 0, "since": 1793031512},
      "26430": {"name": "26430", "queued": 4, "active": 1, "since": 1793031400}
    },
    "ports_unavailable": {
      "26424": "Address already in use"
    },
    "names_in_use": {
      "26426": 26426,
      "26430": 26430
    }
  }
}
```

### Using the Built-In CLI Probes
```bash
# Probe from the tunnel agent CLI:
python3 moesh_tunnel.py --probe --receiver <RECEIVER_HOST>

# Probe from the TCP relay CLI:
python3 moesh_relay.py --probe --receiver <RECEIVER_HOST>
```

---

## 3. Step 2 — Expose a Remote Shell (`moesh_tunnel.py`)

Any remote Linux machine, container, or notebook only needs `MOESH_TUNNEL_RECEIVER` and `MOESH_TUNNEL_MASTER`.

### Minimal Environment Variables

| Variable | Required | Description |
|---|---|---|
| `MOESH_TUNNEL_RECEIVER` | **Yes** | Receiver hostname or IP address |
| `MOESH_TUNNEL_MASTER` | **Yes** | 32-byte (64-hex-char) master key shared across your fleet |
| `MOESH_TUNNEL_HOST` | Recommended | Host slot number (`1`, `2`, `3`, ...) or `auto` to claim the lowest free `host-<N>` |
| `MOESH_TUNNEL_RECEIVER_PORT` | No | Receiver HTTP port (default: `80`) |
| `MOESH_TUNNEL_OPERATOR_PUB` | No | Optional additional operator public key pin (64-hex-char); when omitted, the operator key derived from `MOESH_TUNNEL_MASTER` is used automatically |
| `MOESH_TUNNEL_SESSIONS` | No | Concurrent PTY sessions in the host pool (default: `3`) |

### A. Command-Line / VM / Container Quick Start

```bash
pip install -q noiseprotocol cryptography

export MOESH_TUNNEL_RECEIVER="<RECEIVER_HOST>"
export MOESH_TUNNEL_MASTER="<64-HEX-MASTER-KEY>"
export MOESH_TUNNEL_HOST="auto"   # or an explicit free slot number such as "3"

python3 moesh_tunnel.py
```

- If `MOESH_TUNNEL_HOST="auto"` (or `--host auto`), the agent queries `/__moesh/status` and claims the lowest unoccupied `host-<N>`.
- If you specify an explicit slot (e.g. `MOESH_TUNNEL_HOST="2"`) that is already held by another live machine, the receiver returns `HTTP/1.1 409 Conflict` and `moesh_tunnel.py` exits immediately with exit code `3`:
  ```
  moesh-tunnel: FATAL: host 'host-2' is already in use by another tunnel carrier (active hosts: ['host-2', 'host-4']); choose a different MOESH_TUNNEL_HOST number
  ```

### B. Notebook / Ephemeral Python Environment (Colab / Kaggle / Jupyter)

```python
import os, subprocess, sys

subprocess.run([sys.executable, "-m", "pip", "install", "-q", "noiseprotocol", "cryptography"], check=True)

env = os.environ.copy()
env.update({
    "MOESH_TUNNEL_RECEIVER": "<RECEIVER_HOST>",
    "MOESH_TUNNEL_MASTER": "<64-HEX-MASTER-KEY>",
    "MOESH_TUNNEL_HOST": "auto",  # or a specific free number e.g. "5"
})

proc = subprocess.Popen([sys.executable, "moesh_tunnel.py"], env=env)
print(f"moesh_tunnel started (PID {proc.pid})")
```

### C. Systemd Service (Persistent VM Daemon)

Create `/etc/systemd/system/moesh-agent.service`:

```ini
[Unit]
Description=moesh remote terminal agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ubuntu
Environment="MOESH_TUNNEL_RECEIVER=<RECEIVER_HOST>"
Environment="MOESH_TUNNEL_MASTER=<64-HEX-MASTER-KEY>"
Environment="MOESH_TUNNEL_HOST=1"
ExecStart=/usr/bin/python3 /opt/moesh/moesh_tunnel.py
Restart=on-failure
RestartPreventExitStatus=3
RestartSec=3

[Install]
WantedBy=multi-user.target
```

*(Note `RestartPreventExitStatus=3`: if the host number is in conflict, systemd stops immediately rather than looping on a taken slot.)*

---

## 4. Step 3 — Connect Interactive Shell (`moesh`) & Copy Files (`moecp`)

### Connecting with Only `MOESH_TUNNEL_MASTER` (Zero Config Files Required)

Any agent or operator on the receiver (or with local port `44441` forwarded) can connect using only `MOESH_TUNNEL_MASTER` in the environment:

```bash
export MOESH_TUNNEL_MASTER="<64-HEX-MASTER-KEY>"

# Open an interactive shell on host-3:
python3 moesh_shell.py -n 3

# Copy a file to host-3:
python3 moecp.py ./local_file.tar.gz host-3:/tmp/local_file.tar.gz

# Copy a directory from host-3 preserving permissions:
python3 moecp.py -r -p host-3:/var/log/app ./logs
```

### Connecting with `~/.config/moesh/hosts.toml` (Persistent Operator Setup)

If `~/.config/moesh/hosts.toml` stores `master = "<64-HEX-MASTER-KEY>"`, you do not need to export environment variables on each command:

```toml
# ~/.config/moesh/hosts.toml
prefix = "host"
master = "<64-HEX-MASTER-KEY>"
```

```bash
# Attach to host-3:
moesh -n 3

# Upload and download files with moecp:
moecp ./archive.tar.zst host-3:/tmp/
moecp -r host-3:/tmp/output ./output
```

- Disconnecting (`Ctrl+D` or network drop) leaves the remote PTY running. Re-running `moesh -n <N>` re-attaches to the same shell and replays recent output.
- `moecp` always negotiates an isolated transfer session (`fresh_session=True`), so file transfers never interfere with active interactive shells.

---

## 5. Step 4 — Forward Any TCP Port (`moesh_relay.py`, FRPC Replacement)

`moesh_relay.py` requires **only the Python 3 standard library** and exposes any local TCP port (`127.0.0.1:<PORT>`) on the remote host onto one of the receiver's public relay ports (`26420–26430` by default).

### 1. Check Available Relay Ports First
```bash
python3 moesh_relay.py --probe --receiver <RECEIVER_HOST>
```

### 2. Bind a Specific Free Relay Port (or `auto`)

```bash
# Bind a specific free port on the receiver (e.g. 26425) -> local 127.0.0.1:8000:
python3 moesh_relay.py \
  --receiver <RECEIVER_HOST> \
  --remote-port 26425 \
  --target 127.0.0.1:8000

# Or let the receiver automatically assign the lowest free port in 26420..26430:
python3 moesh_relay.py \
  --receiver <RECEIVER_HOST> \
  --remote-port auto \
  --target 127.0.0.1:8000
```

When the relay attaches, it logs the exact receiver port bound:
```
[2026-10-26 19:20:00] moesh-relay: bound receiver port <RECEIVER_HOST>:26425 -> local 127.0.0.1:8000
```

Clients can now connect directly to `<RECEIVER_HOST>:26425`.

### 3. Optional Service Label (`--service`)

You can optionally attach a human-readable label to your relay lease:
```bash
python3 moesh_relay.py \
  --receiver <RECEIVER_HOST> \
  --remote-port 26425 \
  --service node-a-http \
  --target 127.0.0.1:8000
```

### 4. Conflict Behavior (`409 Conflict`)

- If `--remote-port 26425` is already bound by another carrier (or unavailable on the host OS, such as a port bound by another daemon), or if `--service <label>` is already claimed by another carrier, the receiver immediately responds with `HTTP/1.1 409 Conflict` and lists all currently free ports:
  ```
  relay port 26425 is already in use by carrier a1b2c3d4e5f6 (label 'port-26425'); free ports: [26420, 26421, 26422, 26423, 26427, 26428, 26429]
  ```
- When `--claim-wait 0` is passed (recommended for automated scripts that want immediate fail-fast), `moesh_relay.py` exits immediately with code `3`. Otherwise it retries for up to `--claim-wait` seconds (default `45`s, to allow graceful handover when restarting your own relay) and then exits with code `3`.
- To preserve your own lease across process restarts without waiting for the 30-second grace window, pass a stable `--id <your-carrier-id>`.

### 5. Concurrent Keep-Alive Connections

`moesh_relay.py` decouples standby tunnel queuing from active TCP sessions: as soon as a client sends its first byte on a paired tunnel, the active session is handed off to a dedicated thread and the worker immediately dials a fresh standby tunnel. HTTP/1.1 keep-alive connection pools and long-lived streams will never exhaust the standby pairing queue.
