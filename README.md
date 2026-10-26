# moesh

**An SSH, SCP, and FRP replacement over outbound HTTP/1.1 Upgrade.**

`Noise_XX` mutual authentication over an HTTP/1.1 Upgrade, a remote shell that survives client disconnects, an operator client that auto-reconnects, encrypted `scp`-style file transfer (`moecp`), and a zero-dependency outbound reverse TCP relay (`moesh_relay.py`) with explicit port and slot conflict detection.

The receiver is a **blind socket pump** — it pairs streams at the transport boundary, carries opaque ciphertext or raw TCP streams, and never holds a byte of plaintext terminal data or cryptographic keys.

---

## 1. Why moesh Exists

Standard tools like `ssh` and `scp` require the target machine to accept inbound connections. Machines behind strict NAT, firewalled cloud notebooks (Kaggle, Colab), or egress-only VMs cannot open listening ports. Meanwhile, traditional reverse proxies can silently interleave or drop connections when multiple agents dial the same route.

`moesh` inverts the connection direction and enforces strict slot ownership:

1. **Egress-Only Dialout:** The remote machine (**the agent**) dials *outbound* over standard TCP port 80 (HTTP/1.1 Upgrade) to a **receiver** located on the public network.
2. **Explicit Lease & Conflict Detection (`409 Conflict`):** Each shell host slot (`host-<N>`) and each public relay port (`26420–26430`) is leased exclusively to the active carrier. A second agent dialing an occupied host number, relay port, or relay label receives `HTTP/1.1 409 Conflict` with a list of free ports/active hosts and exits cleanly (exit code `3`) instead of hijacking or corrupting existing traffic.
3. **Control-Plane Status Probing (`/__moesh/status`):** Any agent can query `GET /__moesh/status` (or `--probe`) over HTTP port 80 to discover which `host-<N>` slots and relay ports (`26420–26430`) are open, free, in use, or unavailable without probing data ports.
4. **Single Master Key (`MOESH_TUNNEL_MASTER`):** A single 32-byte master key deterministically derives both the per-host static keys (`host-1`, `host-2`, ...) and the default operator static key via HKDF-SHA256. Any agent holding `MOESH_TUNNEL_MASTER` can expose or connect to any numbered host without manual public-key exchange.
5. **Survivable PTY Sessions:** Keystrokes, terminal sizes (`SIGWINCH`), and background processes attach to a persistent pseudo-terminal (PTY). Closing your laptop or dropping Wi-Fi leaves the remote processes running; reconnecting re-attaches immediately to the active session.

---

## 2. Architecture

```
Remote Target Host (VM / Container / Notebook)             Public Receiver Bridge                     Operator / Client Host
┌──────────────────────────────────────────────┐          ┌───────────────────────────────────┐      ┌─────────────────────────┐
│  A. Interactive Remote Shell                 │          │  nginx (TCP :80)                  │      │  moesh_shell.py / moecp │
│     moesh_tunnel.py                          │ HTTP/1.1 │    │ /__moesh/tunnel/*            │      │  (moesh -n <N>)         │
│     - Noise_XX Session                       │ Upgrade  │    │ /__relay/*                   │      │                         │
│     - HKDF Identity from MOESH_TUNNEL_MASTER │─────────▶│    ▼                              │      │  127.0.0.1:44441        │
│     - Exclusive lease per host-<N>           │Ciphertext│  moesh-bridge.py (Blind Pump)     │◀─────│  - Noise_XX Mutual Auth │
│     - Persistent PTY Shell Pool              │          │  - 0 plaintext, 0 keys held       │Cipher│  - Auto-reconnect loop  │
├──────────────────────────────────────────────┤          │  - 409 Conflict on duplicate slot │ text └─────────────────────────┘
│  B. Outbound Reverse TCP Relay               │          ├───────────────────────────────────┤      ┌─────────────────────────┐
│     moesh_relay.py (Python stdlib only)      │ HTTP/1.1 │  Public Relay Ports (TCP)         │      │  Any TCP Consumer       │
│     - Dials /__relay/<port|auto|label>       │ Upgrade  │  - :26420 .. :26430               │      │  Connects to receiver   │
│     - Splices directly to local TCP target   │─────────▶│  - Exclusive lease per port/label │◀─────│  on bound relay port    │
│       (e.g. 127.0.0.1:8000)                  │Raw bytes │  - GET /__moesh/status inspection │ Raw  │  (26420..26430)         │
└──────────────────────────────────────────────┘          └───────────────────────────────────┘Bytes └─────────────────────────┘
```

---

## 3. Core Capabilities

### A. Encrypted Remote Terminal (`moesh_tunnel` / `moesh_shell`)
- **End-to-End Encryption:** `Noise_XX_25519_ChaChaPoly_BLAKE2s` protects every keystroke and byte of output.
- **Zero-Ceremony Master Key Auth:** When `MOESH_TUNNEL_MASTER` is set, both the host's static key and the operator's static key are derived via HKDF-SHA256. `MOESH_TUNNEL_OPERATOR_PUB` and `~/.config/moesh/operator.key` remain supported alongside master-derived keys.
- **Survivable Sessions:** If transport drops, the agent buffers recent output in a 256 KiB ring buffer. When the operator re-attaches, state and history are restored.
- **Independent Concurrent Operators:** Configurable shell pool (`MOESH_TUNNEL_SESSIONS`, default 3) gives each connecting operator their own isolated PTY.

### B. Outbound TCP Port Relay (`moesh_relay`)
- **FRPC/FRPS Replacement:** Expose any local TCP service (`127.0.0.1:<port>`) onto a public receiver port (`26420–26430`) over outbound HTTP port 80.
- **Collision Proof:** Requesting an occupied port or service label returns `409 Conflict` with the list of free ports instead of stealing or interleaving traffic.
- **Keep-Alive Safe:** Active sessions are handed off to dedicated threads as soon as traffic arrives, immediately replenishing standby tunnels so HTTP keep-alive pools never starve the relay.
- **Zero External Dependencies:** Built entirely with the Python 3 standard library.

### C. Encrypted Remote File Copy (`moecp`)
- **Familiar `scp` Semantics:** Copy files and directory hierarchies to and from remote nodes (`moecp local.txt host-3:/tmp/`, `moecp -r -p ./data host-3:/opt/`).
- **Non-Disruptive Transfers:** Initiates a dedicated, fresh session (`fresh_session=True`) without disturbing active interactive shell sessions on the host.
- **End-to-End Cryptographic Verification:** Calculates and verifies SHA-256 digests on both endpoints before committing files to disk.

---

## 4. Quick Start

See [**docs/CONNECT.md**](docs/CONNECT.md) for the complete canonical guide.

### 1. Probe Open Relay Ports and Active Hosts
```bash
curl -s http://receiver.example.com/__moesh/status | python3 -m json.tool
# Or via the CLI:
python3 moesh_tunnel.py --probe --receiver receiver.example.com
python3 moesh_relay.py --probe --receiver receiver.example.com
```

### 2. Start a Remote Shell Agent (`moesh_tunnel.py`)
```bash
pip install -q noiseprotocol cryptography

export MOESH_TUNNEL_RECEIVER="receiver.example.com"
export MOESH_TUNNEL_MASTER="<64-hex-master-secret>"
export MOESH_TUNNEL_HOST="auto"   # or an explicit number e.g. "2"

python3 moesh_tunnel.py
```

### 3. Attach Interactive Shell (`moesh`) or Copy Files (`moecp`)
```bash
# Attach interactive shell to host-2:
moesh -n 2

# Copy files to/from host-2:
moecp ./config.yaml host-2:/tmp/config.yaml
moecp -r -p host-2:/var/log/app ./app-logs
```

### 4. Forward a Local TCP Port (`moesh_relay.py`)
```bash
# Forward a specific free port (e.g. 26425) to local 127.0.0.1:8000:
python3 moesh_relay.py --receiver receiver.example.com --remote-port 26425 --target 127.0.0.1:8000

# Or auto-select the lowest free port in 26420..26430:
python3 moesh_relay.py --receiver receiver.example.com --remote-port auto --target 127.0.0.1:8000
```

---

## 5. Complete Documentation

| Document | Purpose |
|---|---|
| [**docs/CONNECT.md**](docs/CONNECT.md) | **Canonical Connection Guide** — Probing, master-key auth, shell setup, `moecp`, and TCP port relays |
| [**docs/architecture.md**](docs/architecture.md) | Component architecture, RFC 4254 session model, and state transitions |
| [**docs/keys.md**](docs/keys.md) | Fleet master secrets, HKDF key derivation, pinning, and rotation procedures |
| [**docs/configuration.md**](docs/configuration.md) | Comprehensive catalog of CLI flags, environment variables, and defaults |
| [**docs/operations.md**](docs/operations.md) | Receiver management, systemd configuration, and log inspection |
| [**docs/security.md**](docs/security.md) | Cryptographic guarantees, threat model, and blind pump verification |
| [**PROTOCOL.md**](PROTOCOL.md) | Wire protocol specification, framing constants, and record definitions |
| [**SECURITY.md**](SECURITY.md) | Vulnerability disclosure policy and reporting process |

---

## 6. Testing & Quality Gate

```bash
# 1. Lint checks (Ruff standard rules)
ruff check .

# 2. Protocol core, deterministic host derivation, moecp & adversarial test suites
python3 -m pytest tests/test_protocol_core.py tests/test_named_hosts.py tests/test_moecp.py tests/test_moecp_adversarial.py -q

# 3. Full integration & operator outcome suite
python3 -m pytest tests -q
```

---

## License

`moesh` is licensed under the Apache License 2.0. See [`LICENSE`](LICENSE) for details.
