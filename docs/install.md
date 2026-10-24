# Installation

Target: Debian or Ubuntu. The receiver and the agent host are servers; the
operator's side is any Linux machine with a terminal.

Four core roles:

| role | machine | program | needs a dependency? |
|---|---|---|---|
| receiver | the public host nginx fronts | `moesh-bridge.py` | no — standard library only |
| agent | the machine you want a shell on | `moesh_tunnel.py` | yes — `noiseprotocol==0.3.1`, `cryptography` |
| operator | your terminal | `moesh_shell.py`, `moecp.py` | yes — `noiseprotocol==0.3.1`, `cryptography` |
| relay | accelerator nodes (GPU/TPU) | `moesh_relay.py` | no — standard library only |

All programs are self-contained Python scripts run as `python3 <file>.py`.
The agent, operator client, and `moecp` import `moesh_proto.py` and `moesh_wire.py`,
so they must sit in the same directory or on `PYTHONPATH`.

Replace `receiver.example.com` with the address of your receiver, and
`/opt/moesh` with wherever you keep the checkout.

---

## 1. The receiver

### 1.1 The bridge program

The bridge listens on `127.0.0.1:9447` (tunnels from agents) and on
`127.0.0.1:44441` (operators). Only nginx needs to reach it.

```sh
sudo install -m 0755 moesh-bridge.py /usr/local/bin/moesh-bridge.py
```

### 1.2 nginx

The agent's upgrade request arrives on `/__moesh/tunnel` (or
`/__moesh/tunnel/<name>`) and reverse relays arrive on `/__relay/<service>`.
Both must be proxied to the bridge. The `Upgrade` and `Connection` headers
have to survive the hop, or the bridge refuses the connection.

Create the site file:

```sh
sudo tee /etc/nginx/sites-available/moesh >/dev/null <<'EOF'
map $http_upgrade $moesh_connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 80;
    server_name receiver.example.com;

    location /__moesh/tunnel {
        proxy_pass http://127.0.0.1:9447;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $moesh_connection_upgrade;
        proxy_set_header Host $host;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    location ~ ^/__relay/ {
        proxy_pass http://127.0.0.1:9447;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $moesh_connection_upgrade;
        proxy_set_header Host $host;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
EOF
```

Enable it:

```sh
sudo ln -s /etc/nginx/sites-available/moesh /etc/nginx/sites-enabled/moesh
sudo nginx -t
sudo systemctl reload nginx
```

`nginx -t` must print `syntax is ok` and `test is successful` before the reload.

### 1.3 systemd

The repository ships `moesh-bridge.service`. It runs the bridge under
`/usr/bin/python3`, restarts it automatically, and writes its log to
`/var/log/moesh-bridge.log`.

```sh
sudo install -m 0644 moesh-bridge.service /etc/systemd/system/moesh-bridge.service
sudo systemctl daemon-reload
sudo systemctl enable --now moesh-bridge
```

### 1.4 Check the receiver

```sh
systemctl is-active moesh-bridge
ss -ltnp | grep -E '9447|44441'
tail -f /var/log/moesh-bridge.log
```

The log must show the listeners:

```
tunnel listening on 127.0.0.1:9447
operator-v2 listening on 127.0.0.1:44441
```

If reverse relays are enabled via `MOESH_RELAYS`, their listening ports (e.g. 26430, 26429) will also be reported.

### 1.5 The firewall

The agent dials the receiver on TCP 80. The operator port binds to `127.0.0.1:44441` by default, so it needs no public opening.

```sh
sudo ufw allow 80/tcp
```

---

## 2. The agent host

### 2.1 The code and dependencies

```sh
sudo install -d -m 0755 /opt/moesh
sudo install -m 0644 moesh_tunnel.py moesh_proto.py moesh_wire.py /opt/moesh/
sudo python3 -m venv /opt/moesh/.venv
sudo /opt/moesh/.venv/bin/pip install noiseprotocol==0.3.1 cryptography
```

### 2.2 Key setup: Master Secret vs Key Pair

You have two options for agent authentication:

#### Option A: Unified Fleet Master Secret (Recommended)
No key generation is required on the agent host. Provide the 32-byte master secret in the environment file:

```sh
sudo install -d -m 0750 -o moesh -g moesh /etc/moesh
sudo tee /etc/moesh/agent.env >/dev/null <<'EOF'
MOESH_TUNNEL_RECEIVER=receiver.example.com
MOESH_TUNNEL_RECEIVER_PORT=80
MOESH_TUNNEL_MASTER=<32-byte-hex-master-secret>
MOESH_TUNNEL_OPERATOR_PUB=<the operator's public half>
MOESH_TUNNEL_HOST=3
MOESH_TUNNEL_SESSIONS=3
EOF
sudo chmod 0600 /etc/moesh/agent.env
```

#### Option B: Individual Static Key Pair
Generate a local private/public key pair:

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin moesh
sudo install -d -m 0750 -o moesh -g moesh /etc/moesh
sudo /opt/moesh/.venv/bin/python /opt/moesh/moesh_tunnel.py \
    --generate-key --keyfile /etc/moesh/agent.key
sudo chown moesh:moesh /etc/moesh/agent.key /etc/moesh/agent.key.pub
sudo chmod 0600 /etc/moesh/agent.key
```

Then configure `/etc/moesh/agent.env` using `MOESH_TUNNEL_AGENT_KEYFILE=/etc/moesh/agent.key`.

### 2.3 The systemd unit

Create `/etc/systemd/system/moesh-agent.service`:

```ini
[Unit]
Description=moesh agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=moesh
Group=moesh
EnvironmentFile=/etc/moesh/agent.env
ExecStart=/opt/moesh/.venv/bin/python /opt/moesh/moesh_tunnel.py
Restart=always
RestartSec=3
StandardOutput=append:/var/log/moesh-agent.log
StandardError=append:/var/log/moesh-agent.log
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Enable and start:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now moesh-agent
```

### 2.4 Check the agent

```sh
systemctl is-active moesh-agent
tail -f /var/log/moesh-agent.log
```

The log must show the tunnel queued at the receiver:

```
agent static public key: <hex>
upgraded (HTTP/1.1 101 Switching Protocols, token moesh-tunnel-v2, host host-3)
queued at the receiver; waiting for an authenticated operator
tunnel established; waiting for an operator
```

---

## 3. The operator's machine

### 3.1 The code and dependencies

```sh
sudo install -d -m 0755 /opt/moesh
sudo install -m 0644 moesh_shell.py moecp.py moesh_proto.py moesh_wire.py /opt/moesh/
python3 -m venv /opt/moesh/.venv
/opt/moesh/.venv/bin/pip install noiseprotocol==0.3.1 cryptography
```

### 3.2 The key and pins file

Generate the operator keypair:

```sh
/opt/moesh/.venv/bin/python /opt/moesh/moesh_shell.py --generate-key
```

This creates `~/.config/moesh/operator.key` (mode `0600`) and `~/.config/moesh/operator.key.pub`.

Configure `~/.config/moesh/hosts.toml`:

```toml
prefix = "host"
master = "<fleet-master-secret-hex>"

[hosts.host-3]
# Optional host-specific overrides
```

### 3.3 Convenient PATH commands

Install wrapper scripts into `/usr/local/bin`:

```sh
# moesh (terminal shell client)
sudo tee /usr/local/bin/moesh >/dev/null <<'EOF'
#!/bin/sh
exec /opt/moesh/.venv/bin/python /opt/moesh/moesh_shell.py "$@"
EOF
sudo chmod 0755 /usr/local/bin/moesh

# moecp (secure file copy)
sudo tee /usr/local/bin/moecp >/dev/null <<'EOF'
#!/bin/sh
exec /opt/moesh/.venv/bin/python /opt/moesh/moecp.py "$@"
EOF
sudo chmod 0755 /usr/local/bin/moecp
```

### 3.4 Attach & Copy

```sh
# Open terminal on host-3
moesh -n 3

# Copy file to host-3
moecp model.pt host-3:/opt/models/model.pt
```

---

## 4. Accelerator Nodes (`moesh_relay.py`)

On compute nodes (GPU/TPU) running inference or sidecar services:

```sh
# Copy moesh_relay.py (no extra dependencies required)
install -m 0755 moesh_relay.py /usr/local/bin/moesh_relay.py

# Run in background or systemd unit
python3 /usr/local/bin/moesh_relay.py \
    --service vllm \
    --target 127.0.0.1:8001 \
    --receiver receiver.example.com
```

The service is now immediately reachable on the receiver host at port `26429`.
