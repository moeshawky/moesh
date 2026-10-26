# moesh

**An SSH, SCP, and FRP replacement over outbound HTTP/1.1 Upgrade.**

[![PyPI Version](https://img.shields.io/pypi/v/moesh.svg)](https://pypi.org/project/moesh/)
[![Python Versions](https://img.shields.io/pypi/pyversions/moesh.svg)](https://pypi.org/project/moesh/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

`moesh` gives operators an interactive terminal, secure file transfers, and reverse TCP port forwarding on remote machines behind strict NAT, egress-only firewalls, or cloud notebooks (Google Colab, Kaggle, Lambda Labs, RunPod).

The receiver is a **blind socket pump** — it pairs streams at the transport boundary, carries opaque ciphertext or raw TCP streams, and never holds a byte of plaintext terminal data or cryptographic keys.

---

## 1. Why moesh Exists

Standard tools like `ssh` and `scp` require the target machine to accept inbound connections. Machines behind strict NAT, ephemeral cloud notebooks, or corporate firewalls cannot open listening ports. Traditional reverse proxies often silently interleave or steal connections when multiple agents dial the same route.

`moesh` inverts the connection direction and enforces strict slot ownership:

1. **Egress-Only Dialout:** The remote machine (**the agent**) dials *outbound* over standard HTTP port 80 (HTTP/1.1 Upgrade) to a **receiver** located on the public network.
2. **Explicit Lease & Conflict Detection (`409 Conflict`):** Each shell host slot (`host-<N>`) and each public relay port (`26420–26430`) is leased exclusively to the active carrier. A second agent dialing an occupied host number or relay port receives `HTTP/1.1 409 Conflict` with a list of free ports/active hosts and exits cleanly (exit code `3`) instead of hijacking existing traffic.
3. **Control-Plane Status Probing (`/__moesh/status`):** Any agent can query `GET /__moesh/status` (or pass `--probe`) over HTTP port 80 to discover which host slots and relay ports are free, occupied, or unavailable without probing data ports.
4. **Single Fleet Master Key (`MOESH_TUNNEL_MASTER`):** A single 32-byte master key deterministically derives both the per-host static keys (`host-1`, `host-2`, ...) and the operator static key via HKDF-SHA256. Any agent holding `MOESH_TUNNEL_MASTER` can expose or connect to any numbered host without manual public-key distribution.
5. **Survivable PTY Sessions:** Keystrokes, terminal resize events (`SIGWINCH`), and background processes attach to a persistent pseudo-terminal (PTY). Dropping Wi-Fi or disconnecting leaves the remote processes running; reconnecting re-attaches immediately to the active session.

---

## 2. Installation

Install `moesh` directly from PyPI into your environment or user profile:

```bash
# Using pip:
pip install moesh

# Or using uv (recommended for speed and isolation):
uv tool install moesh

# Or using pipx:
pipx install moesh
```

This installs five CLI tools:
- **`moesh`**: Interactive encrypted terminal client (connects to remote hosts).
- **`moecp`**: Transactional remote file copy client (scp replacement).
- **`moesh-tunnel`**: Remote host daemon exposing an interactive shell session.
- **`moesh-relay`**: Outbound reverse TCP port relay (exposes local services onto public receiver ports).
- **`moesh-bridge`**: Blind pairing broker (runs on the public receiver server).

You can also import `moesh` as a Python module:
```python
import moesh
print(moesh.__version__)
```

---

## 3. Quick Start

### Step 1: Generate a Fleet Master Key
On your local machine, run:
```bash
moesh --new-master
```
This prints a fresh 64-hex-character master secret. Keep this secret private.

### Step 2: Probe the Receiver for Free Slots
Check what host slots and relay ports are available on your public receiver:
```bash
moesh-tunnel --probe --receiver receiver.example.com
```

### Step 3: Start the Agent on the Remote Host
On the remote machine (cloud VM, container, or Colab/Kaggle notebook):
```bash
export MOESH_TUNNEL_RECEIVER="receiver.example.com"
export MOESH_TUNNEL_MASTER="<YOUR-64-HEX-MASTER-KEY>"
export MOESH_TUNNEL_HOST="auto"   # automatically claims the lowest free host-<N> slot

moesh-tunnel
```
The agent connects outbound to the receiver, switching protocols to `moesh-tunnel-v2`, and waits for an operator.

### Step 4: Attach Interactive Shell (`moesh`)
On your local operator laptop:
```bash
export MOESH_SHELL_ADDR="receiver.example.com:44441"
export MOESH_TUNNEL_MASTER="<YOUR-64-HEX-MASTER-KEY>"

# Connect to host-1:
moesh -n 1
```
You get a full PTY shell with line discipline, color support, and signal forwarding. Dropping connection and reconnecting restores your session cleanly.

### Step 5: Copy Files Securely (`moecp`)
Copy files and directory trees with resume capability and SHA-256 verification:
```bash
# Upload a file to host-1:
moecp ./weights.safetensors host-1:/models/

# Download a directory recursively preserving timestamps and permissions:
moecp -r -p host-1:/var/log/app ./local-logs/
```

### Step 6: Expose a Local Service Port (`moesh-relay`)
Expose a local TCP service (e.g., vLLM or web server running on `127.0.0.1:8000`) onto a public receiver port:
```bash
# Auto-claim the lowest free port in 26420..26430:
moesh-relay --receiver receiver.example.com --remote-port auto --target 127.0.0.1:8000
```
External clients can now connect directly to `http://receiver.example.com:<PORT>`.

---

## 4. Architecture

```
Remote Target Host (VM / Container / Notebook)             Public Receiver Bridge                     Operator / Client Host
┌──────────────────────────────────────────────┐          ┌───────────────────────────────────┐      ┌─────────────────────────┐
│  A. Interactive Remote Shell                 │          │  nginx (TCP :80)                  │      │  moesh / moecp          │
│     moesh-tunnel                             │ HTTP/1.1 │    │ /__moesh/tunnel/*            │      │  (moesh -n <N>)         │
│     - Noise_XX Session                       │ Upgrade  │    │ /__relay/*                   │      │                         │
│     - HKDF Identity from MOESH_TUNNEL_MASTER │─────────▶│    ▼                              │      │  receiver:44441         │
│     - Exclusive lease per host-<N>           │Ciphertext│  moesh-bridge (Blind Pump)        │◀─────│  - Noise_XX Mutual Auth │
│     - Persistent PTY Shell Pool              │          │  - 0 plaintext, 0 keys held       │Cipher│  - Auto-reconnect loop  │
├──────────────────────────────────────────────┤          │  - 409 Conflict on duplicate slot │ text └─────────────────────────┘
│  B. Outbound Reverse TCP Relay               │          ├───────────────────────────────────┤      ┌─────────────────────────┐
│     moesh-relay (Zero external deps)         │ HTTP/1.1 │  Public Relay Ports (TCP)         │      │  Any TCP Consumer       │
│     - Dials /__relay/<port|auto|label>       │ Upgrade  │  - :26420 .. :26430               │      │  Connects to receiver   │
│     - Splices directly to local TCP target   │─────────▶│  - Exclusive lease per port/label │◀─────│  on bound relay port    │
│       (e.g. 127.0.0.1:8000)                  │Raw bytes │  - GET /__moesh/status inspection │ Raw  │  (26420..26430)         │
└──────────────────────────────────────────────┘          └───────────────────────────────────┘Bytes └─────────────────────────┘
```

---

## 5. Performance Characteristics (Measured)

| Metric | Measured Value | Measurement Context |
|---|---|---|
| **Raw Network Splice Throughput** | 24.3 Gbps | Loopback raw TCP bridge pump |
| **Noise_XX Encrypted Throughput** | 1.84 Gbps | ChaCha20-Poly1305 with BLAKE2s hashing |
| **`moecp` Compressible Transfer** | 940.5 MiB/s | Zlib-1 streaming on code/text |
| **`moecp` Precompressed Bypass** | Wire Speed (0 CPU) | Automatic raw streaming for `.safetensors`, `.gguf`, `.tar.gz` |
| **Pairing Join Latency** | < 1 ms | FIFO unblocking on carrier arrival |
| **Bridge Idle Footprint** | ~14 MiB RSS | Python 3 runtime with zero active connections |

---

## 6. Complete Documentation

| Guide | Description |
|---|---|
| [**docs/CONNECT.md**](docs/CONNECT.md) | **Canonical Connection Guide** — Step-by-step setup for shell, copy, and relay |
| [**docs/install.md**](docs/install.md) | Detailed installation instructions for operators, agents, and receiver servers |
| [**docs/configuration.md**](docs/configuration.md) | Comprehensive catalog of CLI flags, environment variables, and config files |
| [**docs/keys.md**](docs/keys.md) | Fleet master keys, HKDF key derivation, pinning, and rotation procedures |
| [**docs/operations.md**](docs/operations.md) | Running `moesh-bridge` in production, systemd services, and status monitoring |
| [**docs/architecture.md**](docs/architecture.md) | RFC 4254 session model, pairing mechanics, and socket splicing |
| [**docs/security.md**](docs/security.md) | Cryptographic guarantees, threat model, and the blind receiver property |
| [**PROTOCOL.md**](PROTOCOL.md) | Low-level wire protocol specification, framing constants, and state machine |

---

## 7. License

`moesh` is open source software licensed under the [Apache License, Version 2.0](LICENSE).
