# CONNECT.md — Canonical Connection & Port Forwarding Guide

*An SSH/SCP/FRP replacement over outbound HTTP/1.1 Upgrade: `Noise_XX` mutual authentication, survivable remote shells, encrypted file copy (`moecp`), and collision-safe reverse TCP port forwarding (`moesh-relay`).*

---

## 1. Quick Installation

Install `moesh` from PyPI on both your local machine and your remote target:

```bash
# Standard installation:
pip install moesh

# Or using uv:
uv tool install moesh

# Or using pipx:
pipx install moesh
```

This installs the five CLI tools: `moesh`, `moecp`, `moesh-tunnel`, `moesh-relay`, and `moesh-bridge`.

---

## 2. Architecture Overview

```
Remote Host (VM / Notebook / Container)               Receiver Bridge (Public Ingress)            Operator / Client Host
┌──────────────────────────────────────────┐          ┌──────────────────────────────────┐        ┌──────────────────────────┐
│  A. Remote Shell Agent (moesh-tunnel)    │ HTTP/1.1 │  Reverse Proxy (:80 / :443)      │        │  moesh / moecp           │
│  - Dials /__moesh/tunnel/<host-N>        │ Upgrade  │    │ /__moesh/tunnel/*           │        │  - moesh -n <N>          │
│  - Derives agent + operator keys from    │─────────▶│    │ /__relay/*                  │ :44441 │  - moecp -n <N> ...      │
│    MOESH_TUNNEL_MASTER                   │Ciphertext│    ▼                             │◀───────│  - Noise_XX Mutual Auth  │
│  - Holds exclusive lease on host-N       │          │  moesh-bridge (Blind Broker)     │        │  - Survivable PTY attach │
├──────────────────────────────────────────┤          │  - 0 keys held, 0 plaintext seen │        └──────────────────────────┘
│  B. TCP Port Relay (moesh-relay)         │ HTTP/1.1 │  - Returns 409 Conflict when a   │        ┌──────────────────────────┐
│  - Dials /__relay/<port|auto|label>      │ Upgrade  │    host slot or relay port/name  │ :26420 │  Any TCP Client          │
│  - Forwards receiver port 26420..26430   │─────────▶│    is already held by another    │  ..    │  - Connects to receiver  │
│    to local 127.0.0.1:<target_port>      │Raw Stream│    live carrier                  │ :26430 │    port 26420..26430     │
└──────────────────────────────────────────┘          └──────────────────────────────────┘◀───────└──────────────────────────┘
```

### Core Guarantees
1. **One Master Key (`MOESH_TUNNEL_MASTER`):** Any agent or operator with the 32-byte hex `MOESH_TUNNEL_MASTER` can start a remote shell daemon (`moesh-tunnel`), attach an interactive shell (`moesh`), or copy files (`moecp`). Both the per-host static key (`host-<N>`) and the default operator static key are deterministically derived from `MOESH_TUNNEL_MASTER` via HKDF-SHA256.
2. **Explicit Conflict Detection (`409 Conflict`, Like `frps`/`frpc`):**
   - If two agents dial the same shell host slot (`host-<N>`), the second carrier receives `HTTP/1.1 409 Conflict` listing the currently active hosts and exits with code `3`.
   - If two relays request the same public relay port (`26420–26430`) or the same relay label, the second carrier receives `HTTP/1.1 409 Conflict` listing all free ports and exits with code `3`.
   - Active tunnels and relays never silently share a queue or steal traffic from one another.
3. **Non-Destructive Status Probing (`/__moesh/status`):**
   - **Never probe public relay ports (`26420–26430`) or operator ports (`44441`) with raw TCP connections to check availability** — connecting to a data port consumes a queued standby tunnel (Iron Law 4).
   - Always query `GET /__moesh/status` (or pass `--probe` to `moesh-tunnel` / `moesh-relay`) over standard HTTP port 80.

---

## 3. Step 1 — Probe Open Ports & Active Hosts Before Connecting

Before choosing a host number (`-n <N>`) or a public relay port (`26420–26430`), query the receiver's control-plane status endpoint over HTTP port 80:

### Using the Built-In CLI Probes
```bash
# Probe from the tunnel agent CLI:
moesh-tunnel --probe --receiver <RECEIVER_HOST>

# Probe from the TCP relay CLI:
moesh-relay --probe --receiver <RECEIVER_HOST>
```

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

---

## 4. Step 2 — Expose a Remote Shell (`moesh-tunnel`)

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
pip install moesh

export MOESH_TUNNEL_RECEIVER="<RECEIVER_HOST>"
export MOESH_TUNNEL_MASTER="<64-HEX-MASTER-KEY>"
export MOESH_TUNNEL_HOST="auto"   # or an explicit free slot number such as "3"

moesh-tunnel
```

- If `MOESH_TUNNEL_HOST="auto"` (or `--host auto`), the agent queries `/__moesh/status` and claims the lowest unoccupied `host-<N>`.
- If you specify an explicit slot (e.g. `MOESH_TUNNEL_HOST="2"`) that is already held by another live machine, the receiver returns `HTTP/1.1 409 Conflict` and `moesh-tunnel` exits immediately with exit code `3`:
  ```
  moesh-tunnel: FATAL: host 'host-2' is already in use by another tunnel carrier (active hosts: ['host-2', 'host-4']); choose a different MOESH_TUNNEL_HOST number
  ```

### B. Notebook / Ephemeral Python Environment (Colab / Kaggle / Jupyter)

```python
import os, subprocess, sys

# Install directly from PyPI
subprocess.run([sys.executable, "-m", "pip", "install", "-q", "moesh"], check=True)

env = os.environ.copy()
env.update({
    "MOESH_TUNNEL_RECEIVER": "<RECEIVER_HOST>",
    "MOESH_TUNNEL_MASTER": "<64-HEX-MASTER-KEY>",
    "MOESH_TUNNEL_HOST": "auto",  # or a specific free number e.g. "5"
})

proc = subprocess.Popen(["moesh-tunnel"], env=env)
print(f"moesh-tunnel started (PID {proc.pid})")
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
Environment="MOESH_TUNNEL_HOST=auto"
ExecStart=/usr/local/bin/moesh-tunnel
Restart=on-failure
RestartPreventExitStatus=3
RestartSec=3

[Install]
WantedBy=multi-user.target
```

*(Note `RestartPreventExitStatus=3`: if the host number is in conflict, systemd stops immediately rather than looping on a taken slot.)*

---

## 5. Step 3 — Connect Interactive Shell (`moesh`) & Copy Files (`moecp`)

### Connecting with Only `MOESH_TUNNEL_MASTER` (Zero Config Files Required)

Set `MOESH_TUNNEL_MASTER` in your environment (or pass `--keyfile`):

```bash
export MOESH_SHELL_ADDR="<RECEIVER_HOST>:44441"
export MOESH_TUNNEL_MASTER="<64-HEX-MASTER-KEY>"

# Open an interactive shell on host-3:
moesh -n 3

# Execute non-interactive command strings:
moesh -n 3 -c "uname -a && nvidia-smi"

# Execute command tokens with dashed flags:
moesh -n 3 ls -la /tmp

# Pipe binary streams with -q to keep stdout clean:
head -c 1048576 /dev/urandom | moesh -n 3 -q cat | sha256sum

# Copy a file to host-3 (numeric shorthand supported):
moecp ./weights.safetensors 3:/models/

# Copy a directory from host-3 preserving permissions and timestamps:
moecp -r -p 3:/var/log/app ./logs/
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
moecp ./archive.tar.zst 3:/tmp/
moecp -r 3:/tmp/output ./output
```

- Disconnecting (`Ctrl+D`, `~.`, or network drop) leaves the remote PTY running. Re-running `moesh -n <N>` re-attaches to the same shell and replays recent output.
- Non-interactive execution (`session_type="exec"`) executes in an isolated session with non-blocking stdin pipes, 1 MiB backpressure ceiling, and process group signal cleanup on client termination.
- `moecp` negotiates `session_type="transfer"` directly with the agent process, performing in-process streaming without borrowing interactive shells or spawning PTY subprocesses.
- Pre-compressed files (`.safetensors`, `.gguf`, `.pt`, `.zst`, `.tar.gz`, `.zip`, `.mp4`) automatically bypass CPU compression for maximum transfer speed.
- See [docs/cli.md](cli.md) for full syntax and option reference.

---

## 6. Step 4 — Forward Any TCP Port (`moesh-relay`, FRPC Replacement)

`moesh-relay` exposes any local TCP port (`127.0.0.1:<PORT>`) on the remote host onto one of the receiver's public relay ports (`26420–26430` by default).

### 1. Check Available Relay Ports First
```bash
moesh-relay --probe --receiver <RECEIVER_HOST>
```

### 2. Bind a Specific Free Relay Port (or `auto`)

```bash
# Bind a specific free port on the receiver (e.g. 26425) -> local 127.0.0.1:8000:
moesh-relay \
  --receiver <RECEIVER_HOST> \
  --remote-port 26425 \
  --target 127.0.0.1:8000

# Or let the receiver automatically assign the lowest free port in 26420..26430:
moesh-relay \
  --receiver <RECEIVER_HOST> \
  --remote-port auto \
  --target 127.0.0.1:8000
```

When the relay attaches, it logs the exact receiver port bound:
```
[2026-10-26 19:20:00] moesh-relay: bound receiver port <RECEIVER_HOST>:26425 -> local 127.0.0.1:8000
```

External clients can now connect directly to `<RECEIVER_HOST>:26425`.

### 3. Optional Service Label (`--service`)

You can optionally attach a human-readable label to your relay lease:
```bash
moesh-relay \
  --receiver <RECEIVER_HOST> \
  --remote-port auto \
  --service vllm-api \
  --target 127.0.0.1:8000
```

### 4. Conflict Behavior (`409 Conflict`)

- If `--remote-port 26425` is already bound by another carrier, or if `--service <label>` is already claimed, the receiver immediately responds with `HTTP/1.1 409 Conflict` and lists all currently free ports:
  ```
  relay port 26425 is already in use by carrier a1b2c3d4e5f6 (label 'port-26425'); free ports: [26420, 26421, 26422, 26423, 26427, 26428, 26429]
  ```
- When `--claim-wait 0` is passed, `moesh-relay` exits immediately with code `3`. Otherwise it retries for up to `--claim-wait` seconds (default `45`s, allowing graceful handover during relay restarts).
- To preserve your own lease across process restarts without waiting for the 30-second grace window, pass a stable `--id <your-carrier-id>`.

### 5. Concurrent Keep-Alive Connections

`moesh-relay` decouples standby tunnel queuing from active TCP sessions: as soon as a client sends its first byte on a paired tunnel, the active session is handed off to a dedicated thread and the worker immediately dials a fresh standby tunnel. HTTP/1.1 keep-alive connection pools and long-lived streams will never exhaust the standby pairing queue.
