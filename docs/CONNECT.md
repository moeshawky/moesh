# CONNECT.md — moesh Canonical Connection Guide

*An SSH-like encrypted remote shell over HTTP/1.1 Upgrade with Noise_XX mutual authentication, survivable sessions, and automatic reconnect.*

---

## 1. Architecture

```
Target Host (Kaggle / AWS / GCP / Colab)             Receiver Bridge (Middle)            Operator Terminal (Local)
┌──────────────────────────────────────┐            ┌───────────────────────┐           ┌────────────────────────┐
│  moesh_tunnel.py (Agent)             │ HTTP/1.1   │ Nginx (:80)           │           │ moesh (Operator Client)│
│  - Dial outbound to receiver         │ Upgrade    │   │ /__moesh/tunnel   │ 127.0.0.1 │   moesh -n <1..10>     │
│  - Derive static key from MASTER + N │───────────▶│   ▼                   │   :44441  │                        │
│  - Spawn PTY bash session            │ Ciphertext │ moesh-bridge.py       │◀──────────│ Noise_XX Handshake     │
│  - Pin OPERATOR_PUB                  │            │ (Blind socket broker) │           │ - Pins MASTER key for N│
└──────────────────────────────────────┘            └───────────────────────┘           │ - Auto-reconnects      │
                                                                                        └────────────────────────┘
```

- **Transport:** Outbound HTTP/1.1 `Upgrade: moesh-tunnel-v2` on standard TCP/80 (works through restrictive outbound firewalls and corporate NATs; no incoming ports needed on the target host).
- **Encryption:** `Noise_XX_25519_ChaChaPoly_BLAKE2s` end-to-end between target host and operator.
- **Blind Bridge:** The receiver server ([`moesh-bridge.py`](/usr/local/bin/moesh-bridge.py)) holds **0 keys** and decrypts **0 bytes**; it is solely an opaque socket pump.
- **One Master Secret:** A single fleet secret (`MOESH_TUNNEL_MASTER`) provisions unlimited numbered hosts (`host-1`, `host-2`, ..., `host-N`) via HKDF-SHA256 derivation. You never need to manage or exchange individual host key pairs.

---

## 2. Canonical Parameters

| Parameter | Canonical Value | Description |
|---|---|---|
| **Receiver Host** | `receiver.example.com` | Receiver hostname dialed by target agents |
| **Receiver Port** | `80` | Standard HTTP port (proxied to bridge by Nginx) |
| **Fleet Master Secret** | `<fleet-master-secret-hex>` | 32-byte master secret (`MOESH_TUNNEL_MASTER`) |
| **Operator Public Key** | `<operator-public-key-hex>` | Operator static public key (`MOESH_TUNNEL_OPERATOR_PUB`) |
| **Host Identity Number** | `1`, `2`, `3`, ..., `10` | Unique number for this notebook/VM (`MOESH_TUNNEL_HOST`) |

---

## 3. Connecting from Target Environments

### A. Kaggle Notebooks

Add the following to a notebook cell:

```python
import os, subprocess, sys

# 1. Install prerequisites (standard python packages)
subprocess.run([sys.executable, "-m", "pip", "install", "-q", "noiseprotocol", "cryptography"], check=True)

# 2. Download moesh agent if not present
if not os.path.exists("moesh_tunnel.py"):
    subprocess.run(["curl", "-sSL", "-o", "moesh_tunnel.py", "https://raw.githubusercontent.com/moeshawky/moesh/master/moesh_tunnel.py"], check=True)
if not os.path.exists("moesh_proto.py"):
    subprocess.run(["curl", "-sSL", "-o", "moesh_proto.py", "https://raw.githubusercontent.com/moeshawky/moesh/master/moesh_proto.py"], check=True)
if not os.path.exists("moesh_wire.py"):
    subprocess.run(["curl", "-sSL", "-o", "moesh_wire.py", "https://raw.githubusercontent.com/moeshawky/moesh/master/moesh_wire.py"], check=True)

# 3. Environment configuration
# Set your notebook number (e.g. 1, 2, 3...)
NOTEBOOK_NUM = "1"

# From Kaggle User Secrets or direct string
from kaggle_secrets import UserSecretsClient
try:
    user_secrets = UserSecretsClient()
    master = user_secrets.get_secret("MOESH_TUNNEL_MASTER")
except Exception:
    master = "<32-byte-hex-master-secret>"

env = os.environ.copy()
env.update({
    "MOESH_TUNNEL_RECEIVER": "receiver.example.com",
    "MOESH_TUNNEL_RECEIVER_PORT": "80",
    "MOESH_TUNNEL_MASTER": master,
    "MOESH_TUNNEL_OPERATOR_PUB": "<operator-public-key-hex>",
    "MOESH_TUNNEL_HOST": NOTEBOOK_NUM,
    "MOESH_TUNNEL_SESSIONS": "3",
})

# 4. Launch tunnel agent daemon in background
proc = subprocess.Popen([sys.executable, "moesh_tunnel.py"], env=env)
print(f"moesh agent started (PID {proc.pid}) for host-{NOTEBOOK_NUM}")
```

---

### B. AWS / GCP / Cloud Linux Instances

#### One-Liner (Background Execution)

```bash
curl -sSL https://raw.githubusercontent.com/moeshawky/moesh/master/scripts/install-agent.sh | bash -s -- \
  --receiver receiver.example.com \
  --master <32-byte-hex-master-secret> \
  --operator-pub <operator-public-key-hex> \
  --host 1
```

#### Systemd Service (Persistent Daemon on VM)

Create `/etc/systemd/system/moesh-agent.service`:

```ini
[Unit]
Description=moesh remote terminal agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ubuntu
Environment="MOESH_TUNNEL_RECEIVER=receiver.example.com"
Environment="MOESH_TUNNEL_RECEIVER_PORT=80"
Environment="MOESH_TUNNEL_MASTER=<32-byte-hex-master-secret>"
Environment="MOESH_TUNNEL_OPERATOR_PUB=<operator-public-key-hex>"
Environment="MOESH_TUNNEL_HOST=1"
Environment="MOESH_TUNNEL_SESSIONS=3"
ExecStart=/usr/bin/python3 /opt/moesh/moesh_tunnel.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now moesh-agent
```

---

### C. Google Colab

```python
!pip install -q noiseprotocol cryptography
!git clone -q https://github.com/moeshawky/moesh.git /tmp/moesh

import os, subprocess, sys
from google.colab import userdata

try:
    master = userdata.get('MOESH_TUNNEL_MASTER')
except Exception:
    master = "<32-byte-hex-master-secret>"

env = os.environ.copy()
env.update({
    "MOESH_TUNNEL_RECEIVER": "receiver.example.com",
    "MOESH_TUNNEL_RECEIVER_PORT": "80",
    "MOESH_TUNNEL_MASTER": master,
    "MOESH_TUNNEL_OPERATOR_PUB": "<operator-public-key-hex>",
    "MOESH_TUNNEL_HOST": "4",
})

proc = subprocess.Popen([sys.executable, "/tmp/moesh/moesh_tunnel.py"], env=env)
print(f"moesh agent active on host-4 (PID {proc.pid})")
```

---

## 4. Attaching from the Operator Terminal

From your operator machine (where `~/.config/moesh/operator.key` and `~/.config/moesh/hosts.toml` live):

```bash
# Attach to host-1 (Kaggle notebook 1)
moesh -n 1
# (or from repo directory: python3 moesh_shell.py -n 1)

# Attach to host-2 (Kaggle notebook 2 / AWS VM)
moesh -n 2
# (or from repo directory: python3 moesh_shell.py -n 2)

# Attach to host-3
moesh -n 3
# (or from repo directory: python3 moesh_shell.py -n 3)
```

- When you press `Ctrl+D` or disconnect, the remote shell **survives** in the background.
- Running `moesh -n <N>` again **re-attaches** to the exact same shell and session history.
- Up to 3 operators can attach simultaneously to distinct PTYs.

---

## 5. Dual-Mode Deprecation & Migration

To allow smooth transition without killing active sessions:
1. `~/.config/moesh/hosts.toml` pins the fleet `master` and retains `legacy_agent_pub = "670d30..."`.
2. Existing instances running legacy agent keys authenticate via `legacy_agent_pub`.
3. New instances running `MOESH_TUNNEL_MASTER` authenticate via their HKDF-derived master key.
4. Once all target instances are configured with `MOESH_TUNNEL_MASTER`, delete `legacy_agent_pub` from `hosts.toml`.

---

## 6. Accelerator Service Outbound Relay (Without FRPC)

For accelerator machines (TPU VMs, Kaggle notebooks, GPU instances) running backend services (`vllm`, `runner.py`, `lemonade`, QMD embedding models) that must be exposed back to this server:

### Architecture: HTTP/1.1 Upgrade Reverse Pump
```
Accelerator Host (TPU/GPU/Kaggle)                    Receiver Bridge (Middle)               Local Consumer on Receiver
┌──────────────────────────────────────┐            ┌───────────────────────────────┐      ┌──────────────────────────┐
│  moesh_relay.py                      │ HTTP/1.1   │ Nginx (:80)                   │      │ e.g. OpenCode / Curl     │
│  - Dials outbound to /__relay/<svc>  │ Upgrade    │   │ /__relay/<service>        │      │ connects to localhost    │
│  - Splices to local target port      │───────────▶│   ▼                           │      │ on mapped port:          │
│    (e.g. 127.0.0.1:8001)             │ Raw bytes  │ moesh-bridge.py               │◀─────│ :26429 (vllm)            │
└──────────────────────────────────────┘            │ - Listens on public relay port│      │ :26430 (gpu)             │
                                                    │ - Pairs TCP connection FIFO   │      │ :26428 (embed)           │
                                                    └───────────────────────────────┘      └──────────────────────────┘
```

- **Zero dependencies:** Standard Python 3 stdlib only (`moesh_relay.py`).
- **No FRPC:** No tokens, no frpc binaries, no root required, no open inbound ports needed.
- **Firewall friendly:** All connections are outbound HTTP on port 80.

### Service Relay Port Allocation

The receiver bridge maps named services to listening ports (configured via `MOESH_RELAYS`):

| Port | Service Name | Target Local Port | Description |
|---|---|---|---|
| **`26430`** | `gpu` | `127.0.0.1:8001` | GPU runner / computation sidecar |
| **`26429`** | `vllm` | `127.0.0.1:8001` | vLLM OpenAI-compatible API server |
| **`26428`** | `embed` | `127.0.0.1:8000` | Embedding / Reranking generator |
| **`26426`** | `custom` | `127.0.0.1:8000` | Custom API service |

### Running on Accelerator Nodes

Download `moesh_relay.py` (or copy from repo) and run in the background:

#### A. vLLM Server
```bash
python3 moesh_relay.py --service vllm --target 127.0.0.1:8001 --receiver receiver.example.com
```
*On the receiver host, clients connect to `http://127.0.0.1:26429/v1`.*

#### B. GPU Runner / Worker
```bash
python3 moesh_relay.py --service gpu --target 127.0.0.1:8001 --receiver receiver.example.com
```
*On the receiver host, clients connect to `127.0.0.1:26430`.*

#### C. Embeddings Generator
```bash
python3 moesh_relay.py --service embed --target 127.0.0.1:8000 --receiver receiver.example.com
```
*On the receiver host, clients connect to `127.0.0.1:26428`.*
