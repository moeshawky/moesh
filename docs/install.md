# Installation Guide

`moesh` can be installed directly from PyPI or deployed from source.

Five core commands are provided:

| Command | Role | Machine | Dependencies |
|---|---|---|---|
| `moesh` | Operator terminal client | Your laptop / workstation | `noiseprotocol`, `cryptography` |
| `moecp` | Secure transactional file copy | Your laptop / workstation | `noiseprotocol`, `cryptography` |
| `moesh-tunnel` | Remote host agent daemon | Machine you want a shell on | `noiseprotocol`, `cryptography` |
| `moesh-relay` | Reverse TCP port relay | Machine running local services | Python stdlib only |
| `moesh-bridge` | Blind pairing broker | Public receiver server (nginx) | Python stdlib only |

---

## 1. Fast Installation (Recommended via PyPI)

### Standard User / Virtualenv Install
```bash
pip install moesh
```

### Isolated CLI Tool Install (uv / pipx)
For global system-wide CLI access without polluting system Python:
```bash
# Using uv (fastest):
uv tool install moesh

# Or using pipx:
pipx install moesh
```

Verify that the CLI commands are accessible in your PATH:
```bash
moesh --help
moecp --help
moesh-tunnel --help
moesh-relay --help
moesh-bridge --help
```

---

## 2. Remote Agent Setup (`moesh-tunnel`)

The agent host is the remote machine behind NAT, firewalls, or inside cloud environments (Colab, Kaggle, Lambda Labs, RunPod).

### 2.1 Ad-Hoc / Interactive Run
```bash
pip install moesh

export MOESH_TUNNEL_RECEIVER="receiver.example.com"
export MOESH_TUNNEL_MASTER="<YOUR-64-HEX-MASTER-KEY>"
export MOESH_TUNNEL_HOST="auto"   # automatically claims lowest free host-<N> slot

moesh-tunnel
```

#### Standalone File Deployment (Ephemeral Containers / Kaggle / Colab)
If running without `pip install moesh` by downloading raw source files from git, the agent requires 5 files in its working directory for full capabilities:
- `moesh_wire.py` & `moesh_proto.py` (framing and cryptography engine)
- `moesh_tunnel.py` (agent runner)
- `moecp.py` (imported by `moesh_tunnel.py:917` for native in-process file transfers)
- `moesh_shell.py` (imported for shared constants and resolution)

```bash
# Example standalone download:
BASE="https://raw.githubusercontent.com/moeshawky/moesh/master"
for f in moesh_wire.py moesh_proto.py moesh_tunnel.py moecp.py moesh_shell.py; do
  curl -fsSL "$BASE/$f" -o "$f"
done
python3 moesh_tunnel.py
```

### 2.2 Systemd Persistent Service
To keep the agent running across reboots on a VM:

1. Create a service environment file `/etc/moesh/agent.env`:
   ```bash
   sudo mkdir -p /etc/moesh
   sudo tee /etc/moesh/agent.env >/dev/null <<'EOF'
   MOESH_TUNNEL_RECEIVER=receiver.example.com
   MOESH_TUNNEL_RECEIVER_PORT=80
   MOESH_TUNNEL_MASTER=<YOUR-64-HEX-MASTER-KEY>
   MOESH_TUNNEL_HOST=auto
   MOESH_TUNNEL_SESSIONS=3
   EOF
   sudo chmod 0600 /etc/moesh/agent.env
   ```

2. Create `/etc/systemd/system/moesh-agent.service`:
   ```ini
   [Unit]
   Description=moesh remote terminal agent
   After=network-online.target
   Wants=network-online.target

   [Service]
   Type=simple
   User=ubuntu
   EnvironmentFile=/etc/moesh/agent.env
   ExecStart=/usr/local/bin/moesh-tunnel
   Restart=on-failure
   RestartPreventExitStatus=3
   RestartSec=3
   StandardOutput=append:/var/log/moesh-agent.log
   StandardError=append:/var/log/moesh-agent.log
   NoNewPrivileges=true
   ProtectSystem=full
   ProtectHome=false
   PrivateTmp=true

   [Install]
   WantedBy=multi-user.target
   ```
   *(Note `RestartPreventExitStatus=3`: if the host number is occupied, systemd stops cleanly rather than spinning on a taken slot.)*

3. Enable and start:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now moesh-agent
   sudo systemctl status moesh-agent
   ```

---

## 3. Operator Client Setup (`moesh` & `moecp`)

### 3.1 Key Management
You can generate a fresh fleet master secret directly:
```bash
moesh --new-master
```

### 3.2 Persistent Configuration (`hosts.toml`)
Create `~/.config/moesh/hosts.toml`:
```toml
prefix = "host"
master = "<YOUR-64-HEX-MASTER-KEY>"

# Optional default receiver operator port (default: 127.0.0.1:44441)
# addr = "receiver.example.com:44441"
```

### 3.3 Daily Usage
```bash
# Attach interactive terminal to host-1:
moesh -n 1

# Copy files to/from host-1:
moecp ./data.csv host-1:/opt/data.csv
moecp -r host-1:/var/log/app ./logs/
```

---

## 4. Outbound Reverse TCP Relay Setup (`moesh-relay`)

On compute nodes running inference servers (e.g. vLLM, Ollama, ComfyUI, FastAPI) that you want to expose to external clients:

```bash
# Expose local port 8000 onto the first free receiver port (26420..26430):
moesh-relay \
  --receiver receiver.example.com \
  --remote-port auto \
  --service vllm-api \
  --target 127.0.0.1:8000
```

External consumers can connect to `http://receiver.example.com:<PORT>`.

---

## 5. Receiver Server Setup (`moesh-bridge`)

The receiver server sits on the public internet behind an nginx reverse proxy. It requires **no cryptographic keys** and holds **zero plaintext data**.

### 5.1 nginx Reverse Proxy Configuration
Configure nginx on the receiver server to route outbound upgrades to `127.0.0.1:9447`:

```nginx
map $http_upgrade $moesh_connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 80;
    server_name receiver.example.com;

    # Agent shell tunnel dialouts
    location /__moesh/tunnel {
        proxy_pass http://127.0.0.1:9447;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $moesh_connection_upgrade;
        proxy_set_header Host $host;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    # Reverse TCP relays
    location ~ ^/__relay/ {
        proxy_pass http://127.0.0.1:9447;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $moesh_connection_upgrade;
        proxy_set_header Host $host;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    # Status inspection
    location /__moesh/status {
        proxy_pass http://127.0.0.1:9447;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
    }
}
```

Reload nginx:
```bash
sudo nginx -t && sudo systemctl reload nginx
```

### 5.2 systemd Service for `moesh-bridge`
Install `moesh` on the receiver server and configure `/etc/systemd/system/moesh-bridge.service`:

```ini
[Unit]
Description=moesh v2 receiver bridge
Documentation=https://github.com/moeshawky/moesh#readme
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/moesh-bridge
Restart=always
RestartSec=3
StandardOutput=append:/var/log/moesh-bridge.log
StandardError=append:/var/log/moesh-bridge.log
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now moesh-bridge
sudo systemctl status moesh-bridge
```

---

## 6. Advanced: Installing from Source Checkout

If you are developing `moesh` or deploying directly from git checkouts:

```bash
git clone https://github.com/moeshawky/moesh.git
cd moesh

# Install editable package with dev tools using uv:
uv sync

# Or standard pip editable install:
pip install -e .
```
All console scripts (`moesh`, `moecp`, `moesh-tunnel`, `moesh-relay`, `moesh-bridge`) will point to your local checkout.
