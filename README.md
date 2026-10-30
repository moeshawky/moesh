# moesh

**An SSH, SCP, and FRP replacement over outbound HTTP/1.1 Upgrade.**

[![PyPI Version](https://img.shields.io/pypi/v/moesh.svg)](https://pypi.org/project/moesh/)
[![Python Versions](https://img.shields.io/pypi/pyversions/moesh.svg)](https://pypi.org/project/moesh/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/moeshawky/moesh/blob/master/LICENSE)

`moesh` gives operators an interactive terminal, non-interactive command execution, bidirectional stdin/stdout streaming, transactional file transfers, and reverse TCP port forwarding on remote machines behind strict NAT, egress-only firewalls, or cloud notebooks (Google Colab, Kaggle, Lambda Labs, RunPod).

The receiver is a **blind socket pump** — it pairs streams at the transport boundary, carries opaque ciphertext or raw TCP streams, and never holds a byte of plaintext terminal data, file contents, or cryptographic keys.

---

## 1. Why moesh Exists

Standard tools like `ssh` and `scp` require the target machine to accept inbound connections. Machines behind strict NAT, ephemeral cloud notebooks, or corporate firewalls cannot open listening ports. Traditional reverse proxies often silently interleave or steal connections when multiple agents dial the same route.

`moesh` inverts the connection direction and enforces strict slot ownership:

1. **Egress-Only Dialout:** The remote machine (**the agent**) dials *outbound* over standard HTTP port 80 (HTTP/1.1 Upgrade) to a **receiver** located on the public network.
2. **Explicit Lease & Conflict Detection (`409 Conflict`):** Each shell host slot (`host-<N>`) and each public relay port (`26420–26430`) is leased exclusively to the active carrier. A second agent dialing an occupied host number or relay port receives `HTTP/1.1 409 Conflict` with a list of free ports/active hosts and exits cleanly (exit code `3`) instead of hijacking existing traffic.
3. **Control-Plane Status Probing (`/__moesh/status`):** Any agent or client can query `GET /__moesh/status` (or pass `--probe`) over HTTP port 80 to discover which host slots and relay ports are free, occupied, or unavailable without probing data ports.
4. **Single Fleet Master Key (`MOESH_TUNNEL_MASTER`):** A single 32-byte master key deterministically derives both the per-host static keys (`host-1`, `host-2`, ...) and the operator static key via HKDF-SHA256 (`info=b"moesh-tunnel-v2/agent-static-key/v1/host-<N>"` and `b"moesh-tunnel-v2/agent-static-key/v1/operator"`). Any agent holding `MOESH_TUNNEL_MASTER` can expose or connect to any numbered host without manual public-key distribution.
5. **Survivable PTY Sessions & Direct Exec:** Interactive keystrokes, terminal resize events (`SIGWINCH`), and background processes attach to a persistent pseudo-terminal (PTY) that survives operator disconnects. Non-interactive commands run via `session_type="exec"` with non-blocking stdin pipes, 1 MiB backpressure bounds, and process-group signal cleanup.

---

## 2. Installation

Install `moesh` directly from PyPI into your environment or user profile:

```bash
# Using pip:
pip install moesh

# Or using uv (fastest):
uv tool install moesh

# Or using pipx:
pipx install moesh
```

This installs five CLI tools:
- **`moesh`**: Interactive encrypted terminal, non-interactive remote runner, and pipe client.
- **`moecp`**: Transactional remote file copy client (scp replacement).
- **`moesh-tunnel`**: Remote host daemon exposing persistent PTY shells, `exec` commands, and native transfers.
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
export MOESH_TUNNEL_HOST="auto"   # automatically claims lowest free host-<N> slot

moesh-tunnel
```
The agent connects outbound to the receiver, switching protocols to `moesh-tunnel-v2`, and waits for an operator.

### Step 4: Attach Interactive Shell (`moesh`)
On your local operator workstation:
```bash
export MOESH_SHELL_ADDR="receiver.example.com:44441"
export MOESH_TUNNEL_MASTER="<YOUR-64-HEX-MASTER-KEY>"

# Connect to host-1:
moesh -n 1
```
You get a full PTY shell with line discipline, color support, and signal forwarding. Dropping connection and reconnecting restores your session cleanly.

### Step 5: Execute Non-Interactive Commands & Pipelines (`moesh`)
Run commands on the remote host without opening an interactive PTY session:
```bash
# Execute command string with -c:
moesh -n 1 -c "nvidia-smi --query-gpu=name,memory.total --format=csv"

# Run command tokens directly (dashed flags are preserved automatically):
moesh -n 1 ls -la /tmp

# Stream 5 MiB binary payload through remote cat and verify hash:
head -c 5242880 /dev/urandom | tee /tmp/in.bin | moesh -n 1 -q cat > /tmp/out.bin
cmp -s /tmp/in.bin /tmp/out.bin && echo "byte-identical"
```

### Step 6: Copy Files Securely (`moecp`)
Copy files and directory trees with resume capability and streaming SHA-256 verification:
```bash
# Upload a file to host-1 using numeric shorthand:
moecp ./weights.safetensors 1:/models/weights.safetensors

# Download a directory recursively preserving timestamps and permissions in quiet mode:
moecp -r -p -q 1:/var/log/app ./local-logs/
```

### Step 7: Expose a Local Service Port (`moesh-relay`)
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
│  A. Remote Shell & Exec Agent                │          │  nginx (TCP :80)                  │      │  moesh / moecp          │
│     moesh-tunnel                             │ HTTP/1.1 │    │ /__moesh/tunnel/*            │      │  (moesh -n <N>)         │
│     - Noise_XX Session                       │ Upgrade  │    │ /__relay/*                   │      │                         │
│     - HKDF Identity from MOESH_TUNNEL_MASTER │─────────▶│    ▼                              │      │  receiver:44441         │
│     - Exclusive lease per host-<N>           │Ciphertext│  moesh-bridge (Blind Pump)        │◀─────│  - Noise_XX Mutual Auth │
│     - Persistent PTY Shell Pool (session=shell│          │  - 0 plaintext, 0 keys held       │Cipher│  - Auto-reconnect loop  │
│     - Direct Exec & Pipe Stream (session=exec)│          │  - 409 Conflict on duplicate slot │ text │  - Native file copy     │
│     - Native In-Process Copy (session=transfer│          │  - Dead tunnel early detection    │      └─────────────────────────┘
├──────────────────────────────────────────────┤          ├───────────────────────────────────┤      ┌─────────────────────────┐
│  B. Outbound Reverse TCP Relay               │          │  Public Relay Ports (TCP)         │      │  Any TCP Consumer       │
│     moesh-relay (Zero external deps)         │ HTTP/1.1 │  - :26420 .. :26430               │      │  Connects to receiver   │
│     - Dials /__relay/<port|auto|label>       │ Upgrade  │  - Exclusive lease per port/label │◀─────│  on bound relay port    │
│     - Splices directly to local TCP target   │─────────▶│  - GET /__moesh/status inspection │ Raw  │  (26420..26430)         │
│       (e.g. 127.0.0.1:8000)                  │Raw bytes │  - Optional relay token auth      │Bytes └─────────────────────────┘
└──────────────────────────────────────────────┘          └───────────────────────────────────┘
```

---

## 5. Performance Characteristics

Measured per stage, on a stated machine, with the command that produced each number. See [**docs/performance.md**](https://github.com/moeshawky/moesh/blob/master/docs/performance.md) for the full table, the methodology, and stage separation:

```sh
python3 bench/moesh_bench.py
```

| stage | what the number is | what it is not |
|---|---|---|
| raw socket pump | bytes copied between two sockets in one process | encryption, disk, or the network |
| Noise_XX records | encryption + framing over loopback | compression or file I/O |
| zlib level 1 | the codec alone, on transfer buffers | framing, crypto, disk, or the network |
| end-to-end PUSH | the real receiver committing and verifying a file over loopback | the network |

Effective throughput over a real link is bounded by the slowest stage plus the link. On the audit host the end-to-end PUSH stage was dominated not by cipher or compression but by the per-chunk SQLite WAL ledger record (43 % of wall clock for an uncompressed 256 MiB push), documented in [docs/performance.md](https://github.com/moeshawky/moesh/blob/master/docs/performance.md).

---

## 6. Complete Documentation

| Guide | Description |
|---|---|
| [**docs/cli.md**](https://github.com/moeshawky/moesh/blob/master/docs/cli.md) | **CLI Reference** — Complete options, exit codes, and examples for all 5 executables |
| [**docs/CONNECT.md**](https://github.com/moeshawky/moesh/blob/master/docs/CONNECT.md) | **Canonical Connection Guide** — Step-by-step setup for shell, copy, and relay |
| [**docs/install.md**](https://github.com/moeshawky/moesh/blob/master/docs/install.md) | Detailed installation instructions for operators, agents, and receiver servers |
| [**docs/configuration.md**](https://github.com/moeshawky/moesh/blob/master/docs/configuration.md) | Comprehensive catalog of CLI flags, environment variables, and config files |
| [**docs/keys.md**](https://github.com/moeshawky/moesh/blob/master/docs/keys.md) | Fleet master keys, HKDF key derivation, pinning, and rotation procedures |
| [**docs/operations.md**](https://github.com/moeshawky/moesh/blob/master/docs/operations.md) | Running `moesh-bridge` in production, systemd services, and status monitoring |
| [**docs/architecture.md**](https://github.com/moeshawky/moesh/blob/master/docs/architecture.md) | RFC 4254 session model, pairing mechanics, and socket splicing |
| [**docs/performance.md**](https://github.com/moeshawky/moesh/blob/master/docs/performance.md) | Per-stage benchmark methodology, measured reference run, and known bottlenecks |
| [**docs/security.md**](https://github.com/moeshawky/moesh/blob/master/docs/security.md) | Cryptographic guarantees, threat model, and the blind receiver property |
| [**PROTOCOL.md**](https://github.com/moeshawky/moesh/blob/master/PROTOCOL.md) | Low-level wire protocol specification, framing constants, and state machine |
| [**CHANGELOG.md**](https://github.com/moeshawky/moesh/blob/master/CHANGELOG.md) | Release notes, engineering audit logs, and version history |

---

## 7. License

`moesh` is open source software licensed under the [Apache License, Version 2.0](https://github.com/moeshawky/moesh/blob/master/LICENSE).
