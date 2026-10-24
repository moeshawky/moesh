# moesh

**An SSH-like encrypted remote shell & blind reverse relay.**

Noise_XX mutual authentication over an HTTP/1.1 Upgrade, a remote shell that survives client disconnects, an operator client that auto-reconnects, and a zero-dependency outbound reverse relay for remote GPU/TPU accelerator services.

The receiver is a **blind socket pump** — it pairs streams at the transport boundary, carries opaque ciphertext or raw streams, and never holds a byte of plaintext terminal data or cryptographic keys.

---

## 1. Why moesh Exists

Standard tools like `ssh` require the target machine to accept inbound connections. Machines behind strict NAT, firewalled cloud notebooks (Kaggle, Colab), or egress-only VMs cannot open listening ports.

`moesh` inverts the connection direction:

1. **Egress-Only Dialout:** The remote machine (**the agent**) dials *outbound* over standard TCP port 80 (HTTP/1.1 Upgrade) to a **receiver** located on the public network.
2. **Blind Pairing:** The receiver buffers incoming agent tunnels in per-host queues without decrypting or inspecting payload bytes.
3. **End-to-End Cryptography:** When the operator client connects, the receiver splices the sockets. The operator and remote host perform a mutual `Noise_XX_25519_ChaChaPoly_BLAKE2s` handshake.
4. **Survivable PTY Sessions:** Keystrokes, terminal sizes (`SIGWINCH`), and background processes attach to a persistent pseudo-terminal (PTY). Closing your laptop or dropping Wi-Fi leaves the remote processes running; reconnecting re-attaches immediately to the active session.

---

## 2. Architecture

```
Remote Target Host (Kaggle / AWS / GCP / TPU)              Public Receiver Bridge                     Operator Terminal (Local)
┌──────────────────────────────────────────────┐          ┌───────────────────────────────────┐      ┌─────────────────────────┐
│  A. Interactive Remote Shell                 │          │  nginx (TCP :80)                  │      │  moesh_shell.py         │
│     moesh_tunnel.py                          │ HTTP/1.1 │    │ /__moesh/tunnel              │      │  (or moesh -n <1..10>)  │
│     - Noise_XX Session                       │ Upgrade  │    ▼                              │      │                         │
│     - Deterministic HKDF Identity            │─────────▶│  moesh-bridge.py (Blind Pump)     │◀─────│  127.0.0.1:44441        │
│     - Persistent PTY Shell Pool              │Ciphertext│  - 0 plaintext, 0 keys held       │Cipher│  - Noise_XX Mutual Auth │
│                                              │          │  - FIFO pairing per host/queue    │ text │  - Auto-reconnect loop  │
├──────────────────────────────────────────────┤          ├───────────────────────────────────┤      └─────────────────────────┘
│  B. Outbound Accelerator Relay               │          │  Public Relay Ports (TCP)         │      ┌─────────────────────────┐
│     moesh_relay.py (Zero dependencies)       │ HTTP/1.1 │  - :26430 (gpu)                   │      │  Local Consumer         │
│     - Dials outbound to /__relay/<service>   │ Upgrade  │  - :26429 (vllm)                  │      │  (OpenCode / Curl / SDK)│
│     - Splices directly to local service port │─────────▶│  - :26428 (embed)                 │◀─────│  Connects to localhost  │
│       (e.g. 127.0.0.1:8001 / 8000)           │Raw bytes │  - :26426 (lemonade)              │ Raw  │  on mapped relay port   │
│                                              │          │  - :26420 (qwen)                  │Bytes └─────────────────────────┘
└──────────────────────────────────────────────┘          └───────────────────────────────────┘
```

---

## 3. Core Capabilities

### A. Encrypted Remote Terminal (`moesh_tunnel` / `moesh_shell`)
- **End-to-End Encryption:** `Noise_XX_25519_ChaChaPoly_BLAKE2s` protects every keystroke and byte of output.
- **Mutual Pinning:** Both operator and remote agent pin public keys. Protocol handshakes abort before a shell is spawned if keys do not match.
- **Survivable Sessions:** If transport drops, the agent buffers recent output in a 256 KiB ring buffer. When the operator re-attaches, state and history are restored.
- **Independent Concurrent Operators:** Configurable shell pool (`MOESH_TUNNEL_SESSIONS`, default 3) gives each connecting operator their own isolated PTY.

### B. Outbound Accelerator Service Relay (`moesh_relay`)
- **FRP Alternative for Compute Nodes:** Expose services running on TPU VMs, GPU rigs, or Kaggle instances without running `frpc`/`frps` on the target machine.
- **Zero External Dependencies:** Built entirely with Python standard library (`socket`, `http.client`, `select`, `threading`).
- **Auto-Healing:** Automatically re-dials and reconnects if the receiver restarts or network hiccups occur.

### C. Unified Fleet Identity (Zero-Key-Exchange)
- **Deterministic Derivation:** A single 32-byte master secret (`MOESH_TUNNEL_MASTER`) provisions all numbered nodes (`host-1` through `host-10`) via HKDF-SHA256 (`info=b"moesh-agent-key-host-<n>"`).
- **Dual-Key Migration:** Operator verifies candidate keys simultaneously, supporting both new master-derived hosts and legacy pinned agent keys without dropping active sessions.

### D. Encrypted Remote File Copy (`moecp`)
- **Familiar `scp` Semantics:** Copy files and directory hierarchies to and from remote nodes (`moecp local.txt host-3:/tmp/`, `moecp -r -p ./weights host-3:/opt/`).
- **Non-Disruptive Transfers:** Initiates a dedicated, fresh session (`fresh_session=True`) allocating an isolated worker process without disturbing active interactive shell sessions on the host.
- **Pure In-Memory Bootstrap:** Remote worker is pushed as an ephemeral base64+zlib bootstrap payload directly into the fresh session; zero installation required on remote nodes.
- **End-to-End Cryptographic Verification:** Calculates and verifies SHA-256 digests on both endpoints before committing files to disk or preserving attributes (`-p`).
- **Real-Time Progress Meter:** Dynamic transfer percentage, byte counts, and throughput metrics with `-q` quiet mode for non-interactive scripts.

---

## 4. Port & Service Topology

The receiver operates as a blind socket pump with two classes of endpoints:

### Core Management & Terminal Endpoints

| Port | Protocol / Route | Purpose | Scope |
|---|---|---|---|
| **`80`** | HTTP/1.1 `/__moesh/tunnel`<br>HTTP/1.1 `/__relay/<service>` | Public ingress for outbound agent dials & reverse service relays | Public ingress (via Nginx / reverse proxy) |
| **`44441`** | Raw TCP (Noise_XX) | Local bridge listener for operator terminal clients (`moesh_shell.py`) | Local loopback only (`127.0.0.1`) |

### Configurable Reverse Service Relays

The receiver bridge exposes dedicated listening ports to pair incoming connections with outbound service agents over HTTP/1.1 Upgrade. Services and public listening ports are configured on the receiver via `MOESH_RELAYS`:

```bash
# Example receiver configuration (comma-separated <service>:<port>):
export MOESH_RELAYS="gpu:26430,vllm:26429,api:8080"
```

| Service Name | Default Bridge Port | Target Node Port | Typical Workload |
|---|---|---|---|
| `vllm` | `:26429` | `127.0.0.1:8001` | LLM inference server (e.g. OpenAI-compatible API) |
| `gpu` | `:26430` | `127.0.0.1:8001` | GPU worker / custom computation sidecar |
| `<custom>` | `:<port>` | `127.0.0.1:<port>` | Any arbitrary TCP service forwarded via `moesh_relay.py` |

---

## 5. Quick Start

### A. Terminal Shell Connection

#### 1. Remote Target Host (e.g. Host #2)
```bash
pip install -q noiseprotocol cryptography

export MOESH_TUNNEL_RECEIVER="receiver.example.com"
export MOESH_TUNNEL_RECEIVER_PORT="80"
export MOESH_TUNNEL_MASTER="<32-byte-hex-master-secret>"
export MOESH_TUNNEL_OPERATOR_PUB="<operator-public-key-hex>"
export MOESH_TUNNEL_HOST="2"

python3 moesh_tunnel.py
```

#### 2. Operator Machine
```bash
# Attach to host-2
python3 moesh_shell.py -n 2

# Or using the canonical alias:
moesh -n 2
```
*Disconnect at any time using `~.` or closing the window; reconnect with `-n 2` to resume exactly where you left off.*

---

### B. Accelerator Node Service Relay

On remote nodes running vLLM, TTS, or embedding engines:

```bash
# Expose local vLLM (127.0.0.1:8001) to receiver port 26429:
python3 moesh_relay.py --service vllm --target 127.0.0.1:8001 --receiver receiver.example.com

# Expose local GPU runner (127.0.0.1:8001) to receiver port 26430:
python3 moesh_relay.py --service gpu --target 127.0.0.1:8001 --receiver receiver.example.com

# Expose local Embedding model (127.0.0.1:8000) to receiver port 26428:
python3 moesh_relay.py --service embed --target 127.0.0.1:8000 --receiver receiver.example.com
```

---

### C. Secure Remote File Copy (`moecp`)

Mirroring the syntax and behavior of `scp` over the encrypted `moesh` transport:

```bash
# Upload a file to remote host-3:
moecp model.pt host-3:/opt/models/model.pt

# Upload using -n host shortcut:
moecp -n 3 model.pt remote:/opt/models/model.pt

# Recursively upload a directory preserving permissions and timestamps:
moecp -r -p ./checkpoints host-3:/opt/checkpoints

# Download a file from remote host-3:
moecp host-3:/var/log/train.log ./train.log

# Recursively download a remote directory:
moecp -r host-3:/opt/results ./results
```

---

## 6. Complete Documentation

Detailed guides and operational references:

| Document | Purpose |
|---|---|
| [**docs/CONNECT.md**](docs/CONNECT.md) | **Canonical Connection Guide** — Copy-paste runbooks for Kaggle, AWS, GCP, Colab, and TPU nodes |
| [**docs/architecture.md**](docs/architecture.md) | Component architecture, RFC 4254 session model, and state transitions |
| [**docs/keys.md**](docs/keys.md) | Fleet master secrets, HKDF key derivation, pinning, and rotation procedures |
| [**docs/configuration.md**](docs/configuration.md) | Comprehensive catalog of CLI flags, environment variables, and defaults |
| [**docs/operations.md**](docs/operations.md) | Receiver management, systemd configuration, and log inspection |
| [**docs/security.md**](docs/security.md) | Cryptographic guarantees, threat model, and blind pump verification |
| [**PROTOCOL.md**](PROTOCOL.md) | Wire protocol specification, framing constants, and record definitions |
| [**SECURITY.md**](SECURITY.md) | Vulnerability disclosure policy and reporting process |

---

## 7. Testing & Quality Gate

Verification suite runs self-contained without requiring live networks or mock keys:

```bash
# 1. Lint checks (Ruff standard rules)
ruff check .

# 2. Protocol core, deterministic host derivation & moecp test suite
python3 -m pytest tests/test_protocol_core.py tests/test_named_hosts.py tests/test_moecp.py -q

# 3. Full integration & operator outcome suite
python3 -m pytest tests -q
```

---

## License

`moesh` is licensed under the Apache License 2.0. See [`LICENSE`](LICENSE) for details.
