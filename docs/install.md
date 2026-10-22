# Installation

Target: Debian or Ubuntu. The receiver and the agent host are servers; the
operator's side is any Linux machine with a terminal.

Three roles, three places:

| role | machine | program | needs a dependency? |
|---|---|---|---|
| receiver | the public host nginx fronts | `moesh-bridge.py` | no — standard library only |
| agent | the machine you want a shell on | `moesh_tunnel_v2.py` | yes — `noiseprotocol==0.3.1` |
| operator | your terminal | `moesh_shell_v2.py` | yes — `noiseprotocol==0.3.1` |

The three programs are plain scripts at the top of the checkout, run as
`python3 <file>.py`. The agent and the client import `moesh_proto_v2.py`,
so it must sit next to them.

Replace `receiver.example.com` with the address of your receiver, and
`/opt/moesh` with wherever you keep the checkout.

---

## 1. The receiver

### 1.1 The bridge program

The bridge listens on `127.0.0.1:9447` (tunnels from agents) and on
`127.0.0.1:44441` (operators). Only nginx needs to reach it.

```sh
sudo install -m 0644 moesh-bridge.py /usr/local/bin/moesh-bridge.py
```

### 1.2 nginx

The agent's upgrade request arrives on `/__moesh/tunnel` (or
`/__moesh/tunnel/<name>`) and must be proxied to the bridge. The `Upgrade`
and `Connection` headers have to survive the hop, or the bridge refuses the
connection.

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
}
EOF
```

The `map` block belongs to nginx's `http` context; on Debian and Ubuntu the
files in `sites-enabled` are included inside it, so it can live at the top of
the site file.

Enable it:

```sh
sudo ln -s /etc/nginx/sites-available/moesh /etc/nginx/sites-enabled/moesh
sudo nginx -t
sudo systemctl reload nginx
```

`nginx -t` must print `syntax is ok` and `test is successful` before the
reload.

### 1.3 systemd

The repository ships the unit. It runs the bridge under `/usr/bin/python3`,
restarts it, and writes its log to `/var/log/moesh-bridge.log`.

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

The log must show the two listeners:

```
tunnel listening on 127.0.0.1:9447
operator-v2 listening on 127.0.0.1:44441
```

If the log says `bind 127.0.0.1:9447 failed: ...`, something else already
holds that port.

### 1.5 The firewall

The agent dials the receiver on TCP 80. The operator port binds to
`127.0.0.1` by default, so it needs no public opening.

```sh
sudo ufw allow 80/tcp
```

---

## 2. The agent host

### 2.1 The code and the dependency

```sh
sudo install -d -m 0755 /opt/moesh
sudo install -m 0644 moesh_tunnel_v2.py moesh_proto_v2.py /opt/moesh/
sudo python3 -m venv /opt/moesh/.venv
sudo /opt/moesh/.venv/bin/pip install noiseprotocol==0.3.1
```

### 2.2 The key and the operator's pin

Create the service account first — it owns the key and the environment file:

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin moesh
sudo install -d -m 0750 -o moesh -g moesh /etc/moesh
sudo /opt/moesh/.venv/bin/python /opt/moesh/moesh_tunnel_v2.py \
    --generate-key --keyfile /etc/moesh/agent.key
sudo chown moesh:moesh /etc/moesh/agent.key /etc/moesh/agent.key.pub
sudo chmod 0600 /etc/moesh/agent.key
```

Copy `/etc/moesh/agent.key.pub` to the operator's machine — that public half
is what gets pinned there.

The operator's public half comes back the other way. The agent reads it
from the environment (see the next section), so keep a copy of it on the
agent host for your own records:

```sh
sudo install -m 0644 -o moesh -g moesh operator.pub /etc/moesh/operator.pub
```

The agent does not read that file itself: the value it pins is the one in
`MOESH_TUNNEL_V2_OPERATOR_PUB` below.

### 2.3 The environment file

```sh
sudo tee /etc/moesh/agent.env >/dev/null <<'EOF'
MOESH_TUNNEL_V2_RECEIVER=receiver.example.com
MOESH_TUNNEL_V2_RECEIVER_PORT=80
MOESH_TUNNEL_V2_HOST=3
MOESH_TUNNEL_V2_AGENT_KEYFILE=/etc/moesh/agent.key
MOESH_TUNNEL_V2_OPERATOR_PUB=<the operator's public half>
EOF
sudo chmod 0600 /etc/moesh/agent.env
```

`MOESH_TUNNEL_V2_HOST=3` gives the host the routing name `host-3`, which is
what the operator types as `-n 3`.

### 2.4 The unit

The repository ships no unit for the agent; this is an example to adapt.

```sh
sudo tee /etc/systemd/system/moesh-agent.service >/dev/null <<'EOF'
[Unit]
Description=moesh agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=moesh
Group=moesh
EnvironmentFile=/etc/moesh/agent.env
ExecStart=/opt/moesh/.venv/bin/python /opt/moesh/moesh_tunnel_v2.py
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
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now moesh-agent
```

The agent reads its key from `/etc/moesh/agent.key`, not from the home
directory, so `ProtectHome=true` is safe.

### 2.5 Check the agent

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

### 3.1 The code and the dependency

```sh
sudo install -d -m 0755 /opt/moesh
sudo install -m 0644 moesh_shell_v2.py moesh_proto_v2.py /opt/moesh/
python3 -m venv /opt/moesh/.venv
/opt/moesh/.venv/bin/pip install noiseprotocol==0.3.1
```

### 3.2 The key and the pins file

```sh
/opt/moesh/.venv/bin/python /opt/moesh/moesh_shell_v2.py --generate-key
```

That writes `~/.config/moesh/operator.key` (mode `0600`) and
`~/.config/moesh/operator.key.pub` (mode `0644`). Copy the `.pub` half to
the agent host.

Pin the agent's public half:

```sh
mkdir -p ~/.config/moesh
cat > ~/.config/moesh/hosts.toml <<'EOF'
prefix = "host"

[hosts.host-3]
agent_pub = "<the agent's public half>"
EOF
chmod 0600 ~/.config/moesh/hosts.toml
```

### 3.3 Reaching the operator port

The client connects to the receiver's operator port, `127.0.0.1:44441` by
default. Pick one of these:

**A — run the client on the receiver.** Nothing to configure; the default
address already points at the right place.

**B — forward the port over SSH.** The client's default address then works
unchanged, because the local end of the forward is the same port:

```sh
ssh -N -L 44441:127.0.0.1:44441 receiver.example.com
```

**C — bind the operator port to a private interface.** On the receiver:

```sh
MOESH_BRIDGE_OPERATOR_V2_LISTEN=10.0.0.5:44441
```

and on the operator's machine:

```sh
export MOESH_SHELL_V2_ADDR=10.0.0.5:44441
```

Restrict that port to the operator's address in the firewall.

### 3.4 A command on your PATH (optional)

The client is a script, so it is normally run as
`python3 /opt/moesh/moesh_shell_v2.py`. If you would rather have a command,
wrap it:

```sh
sudo tee /usr/local/bin/moesh-shell-v2 >/dev/null <<'EOF'
#!/bin/sh
exec /opt/moesh/.venv/bin/python /opt/moesh/moesh_shell_v2.py "$@"
EOF
sudo chmod 0755 /usr/local/bin/moesh-shell-v2
```

### 3.5 Attach

```sh
/opt/moesh/.venv/bin/python /opt/moesh/moesh_shell_v2.py -n 3
```

The client logs the routing name it asked for, then the authenticated
handshake:

```
waiting for host 'host-3' — the receiver is holding this connection while it attaches (it may be restarting)…
authenticated (agent static key matched the pin)
session active: 24x80 term=xterm-256color
```

A prompt means you are in.

---

## 4. What to check if something is missing

| symptom | look at | see |
|---|---|---|
| the agent cannot reach the receiver | the receiver's log and `systemctl is-active moesh-bridge` | [operations.md](operations.md) |
| nginx answers `502` | `sudo nginx -t` and the bridge's listener | [operations.md](operations.md) |
| the operator waits, then gives up | the agent's log line `tunnel established; waiting for an operator` | [operations.md](operations.md) |
| a key mismatch | the fingerprints in [keys.md](keys.md) | [keys.md](keys.md) |
