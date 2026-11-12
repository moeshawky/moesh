# Configuration

Everything configurable in `moesh`, with the default that applies when the
variable is not set. Each row names the source line it was read from.

---

## The operator client (`moesh_shell.py`)

### Environment

| variable | default | source |
|---|---|---|
| `MOESH_SHELL_ADDR` | `127.0.0.1:44441` | `moesh_shell.py:68` (`DEFAULT_ADDR`), used at `:1121` |
| `MOESH_SHELL_KEYFILE` | `~/.config/moesh/operator.key` | `moesh_shell.py:87` (`DEFAULT_KEYFILE`), used at `:1124` |
| `MOESH_SHELL_PEER_PUBFILE` | `~/.config/moesh/agent.pub` | `moesh_shell.py:89` (`DEFAULT_PEER_PUBFILE`), used at `:1128` |
| `MOESH_SHELL_HOSTS_FILE` | `~/.config/moesh/hosts.toml` | `moesh_shell.py:69-72` (`get_hosts_file`) |
| `MOESH_SHELL_HANDSHAKE_TIMEOUT` | `150` seconds | `moesh_shell.py:1313`, constant at `moesh_proto.py:137` |
| `MOESH_SHELL_PING_INTERVAL` | `15` seconds | `moesh_shell.py:1373` |
| `MOESH_SHELL_DEAD_AFTER` | `45` seconds | `moesh_shell.py:1376` |
| `MOESH_TUNNEL_HOST` | `default` — default for `-n` | `moesh_shell.py:1138`, constant at `moesh_wire.py:32` |
| `TERM` | `xterm-256color` | `moesh_shell.py:1244`, constant at `moesh_proto.py:167` |

Legacy aliases `MOESH_SHELL_V2_*` are supported for backward compatibility.

`MOESH_SHELL_DEAD_AFTER` is the client's silence limit: if nothing is received
within that duration, the session is treated as dead and reconnect begins.

### Flags

| flag | effect | source |
|---|---|---|
| `--addr HOST:PORT` | the receiver's operator endpoint | `moesh_shell.py:1120-1122` |
| `--keyfile PATH` | the operator's private key | `moesh_shell.py:1123-1125` |
| `--peer-pubfile PATH` | the agent's public key, for a single-host setup | `moesh_shell.py:1126-1129` |
| `--fresh` | ask for a new shell instead of re-attaching | `moesh_shell.py:1130-1134` |
| `--host`, `-n` | the host number or name to attach to | `moesh_shell.py:1135-1140` |
| `--new-master` | print a fresh master secret and the key it derives | `moesh_shell.py:1141-1145` |
| `--generate-key` | write a fresh operator key pair | `moesh_shell.py:1146-1150` |
| `--force` | overwrite an existing key file when generating | `moesh_shell.py:1151-1155` |
| `--no-reconnect` | exit on a lost connection instead of re-attaching | `moesh_shell.py:1156-1161` |
| `-q`, `--quiet` | suppress informational logging on stderr | `moesh_shell.py:1162-1167` |
| `-c`, `--command COMMAND` | command string to execute non-interactively on the remote host | `moesh_shell.py:1168-1174` |
| `command` (positional) | remote command arguments (e.g. `ls -la`) | `moesh_shell.py:1175-1179` |

The client requires a valid TTY when starting an interactive terminal session;
non-interactive execution (`-c` or positional command) runs headless without a local TTY.

---

## The agent (`moesh_tunnel.py`)

### Environment

| variable | default | source |
|---|---|---|
| `MOESH_TUNNEL_RECEIVER` | *none — the agent refuses to start without it* | `moesh_tunnel.py:1781` |
| `MOESH_TUNNEL_RECEIVER_PORT` | `80` | `moesh_tunnel.py:1793`, constant at `:89` |
| `MOESH_TUNNEL_PATH` | `/__moesh/tunnel` | `moesh_tunnel.py:1809`, constant at `moesh_wire.py:28` |
| `MOESH_TUNNEL_AGENT_KEY` | *none* — the agent's private key as hex | `moesh_tunnel.py:248` |
| `MOESH_TUNNEL_AGENT_KEYFILE` | *none* — a file holding that key | `moesh_tunnel.py:253` |
| `MOESH_TUNNEL_OPERATOR_PUB` | *none* — optional pinned operator public key (when unset, derived from `MOESH_TUNNEL_MASTER`) | `moesh_tunnel.py:295` |
| `MOESH_TUNNEL_HOST` | *none* — host number or `auto`; defaults to name below | `moesh_tunnel.py:352` |
| `MOESH_TUNNEL_PREFIX` | `host` | `moesh_tunnel.py:358`, constant at `moesh_proto.py:769` |
| `MOESH_TUNNEL_NAME` | `default` | `moesh_tunnel.py:365`, constant at `:99` |
| `MOESH_TUNNEL_MASTER` | *none* — fleet master secret for HKDF key derivation | `moesh_tunnel.py:312`, `:393` |
| `MOESH_TUNNEL_ID` | *none* — 16-hex carrier identifier (derived from machine-id when unset) | `moesh_tunnel.py:155-189` |
| `MOESH_TUNNEL_SESSIONS` | `3` concurrent operators | `moesh_tunnel.py:1820`, constant at `:91` |
| `MOESH_TUNNEL_PING_INTERVAL` | `15` seconds | `moesh_tunnel.py:1351` |
| `MOESH_TUNNEL_DEAD_AFTER` | `45` seconds | `moesh_tunnel.py:1352` |
| `MOESH_TUNNEL_CHILD_PIDFILE` | *none* — file that receives the active shell's PID | `moesh_tunnel.py:560`, `:602-613` |

Legacy aliases `MOESH_TUNNEL_V2_*` and `NB_TUNNEL_V2_*` are supported for backward compatibility.

`MOESH_TUNNEL_AGENT_KEY` is checked first; `MOESH_TUNNEL_AGENT_KEYFILE` is the fallback. If `MOESH_TUNNEL_MASTER` is provided, the static key is deterministically derived from `HKDF-SHA256(info=b"moesh-tunnel-v2/agent-static-key/v1/host-<n>")`.

### Flags

| flag | effect | source |
|---|---|---|
| `--generate-key` | write a fresh agent key pair and print the public half | `moesh_tunnel.py:1738-1742` |
| `--keyfile PATH` | where `--generate-key` writes the private key | `moesh_tunnel.py:1743-1747` |
| `--force` | overwrite an existing key file when generating | `moesh_tunnel.py:1748-1752` |
| `--probe` | query `/__moesh/status` for active hosts and relay ports and exit | `moesh_tunnel.py:1753-1757` |
| `--host`, `-n` | host number, name, or `auto` | `moesh_tunnel.py:1769-1774` |
| `--receiver RECEIVER` | receiver hostname or IP override | `moesh_tunnel.py:1758-1762` |
| `--port PORT` | receiver HTTP port override | `moesh_tunnel.py:1763-1768` |

### Back-off and Timings

| behaviour | value | source |
|---|---|---|
| wait after an authentication failure | 60 s | `moesh_tunnel.py:108` |
| network back-off, first step and ceiling | 2 s → 30 s | `moesh_tunnel.py:1005`, `:1028` |
| output kept while nobody is attached | 256 KiB | `moesh_tunnel.py:124`, `:502` |
| client silence deadline | 45 s | `moesh_tunnel.py:1226` |

---

## Secure File Copy (`moecp`)

### Environment

| variable | default | source |
|---|---|---|
| `MOESH_SHELL_ADDR` | `127.0.0.1:44441` | `moecp.py:2715` |
| `MOESH_SHELL_KEYFILE` | `~/.config/moesh/operator.key` | `moecp.py:2720` |
| `MOESH_SHELL_HOSTS_FILE` | `~/.config/moesh/hosts.toml` | `moesh_shell.py:69` |
| `MOECP_LOCK_DIR` | `~/.local/state/moesh/locks` | `moecp.py:306-321` |
| `MOECP_CLIENT_LEDGER_PATH` | `~/.local/state/moesh/ledger.db` | `moecp.py:1807-1812` |
| `MOECP_LEDGER_TTL_DAYS` | `7` days | `moecp.py:1816`, `:2287` |
| `MOECP_FRAME_TIMEOUT` | `30.0` s | `moecp.py:207` (`DEFAULT_FRAME_TIMEOUT`) |

### Flags

```
moecp [-h] [-r] [-p] [-q] [-v] [--retry RETRY] [--compression {auto,zlib,raw}] [-n HOST] [--addr ADDR] [--keyfile KEYFILE] paths [paths ...]
```

| flag | effect | source |
|---|---|---|
| `paths` | Source path(s) followed by destination target | `moecp.py:2723-2727` |
| `-r`, `--recursive` | Recursively copy entire directories | `moecp.py:2676-2680` |
| `-p`, `--preserve` | Preserves modification times, access times, and modes | `moecp.py:2681-2685` |
| `-q`, `--quiet` | Quiet mode: disables progress meter and non-fatal warnings | `moecp.py:2686-2690` |
| `-v`, `--verbose` | Verbose debug logging to stderr | `moecp.py:2691-2695` |
| `--retry RETRY` | Maximum retry attempts on connection interruption (default: 3) | `moecp.py:2696-2701` |
| `--compression` | Transfer compression strategy (`auto`=fast zlib-1 with pre-compressed bypass, `zlib`=force zlib-1, `raw`=uncompressed) | `moecp.py:2702-2707` |
| `-n`, `--host HOST` | Designated remote host number or name (e.g. `3` or `host-3`) | `moecp.py:2708-2712` |
| `--addr ADDR` | Receiver operator bridge address | `moecp.py:2713-2717` |
| `--keyfile KEYFILE` | Operator private key file path | `moecp.py:2718-2722` |

---

## Outbound TCP Reverse Relay (`moesh_relay.py`)

### Environment

| variable | default | source |
|---|---|---|
| `MOESH_RELAY_RECEIVER` | *none* — target receiver hostname/IP | `moesh_relay.py:42-44` |
| `MOESH_RELAY_PORT` | `80` (or `443` with TLS) | `moesh_relay.py:74-76` |
| `MOESH_RELAY_REMOTE_PORT` | `auto` (when `--name`/`--service` is unset) | `moesh_relay.py:946` |
| `MOESH_RELAY_NAME` | *none* — optional agent-defined port name (fallback: `MOESH_RELAY_SERVICE`) | `moesh_relay.py:955` |
| `MOESH_RELAY_SERVICE` | *none* — backward-compatible alias for `MOESH_RELAY_NAME` | `moesh_relay.py:956` |
| `MOESH_RELAY_TARGET` | `127.0.0.1:8000` | `moesh_relay.py:78` |
| `MOESH_RELAY_WORKERS` | `4` standby tunnel workers | `moesh_relay.py:80` |
| `MOESH_RELAY_ID` | *none* — persistent carrier identity | `moesh_relay.py:989` |
| `MOESH_RELAY_TOKEN` | *none* — shared authentication token | `moesh_relay.py:995` |
| `MOESH_RELAY_IDLE` | `900` seconds (standby tunnel refresh interval) | `moesh_relay.py:82` |
| `MOESH_RELAY_SESSION_IDLE` | `120` seconds (active paired session idle timeout; <=0 disables) | `moesh_relay.py:85` |
| `MOESH_RELAY_TLS` | `False` — use TLS for carrier connection | `moesh_relay.py:87` |
| `MOESH_RELAY_TLS_INSECURE` | `False` — disable TLS cert verification | `moesh_relay.py:88-90` |
| `MOESH_RELAY_TLS_CA_CERT` | *none* — custom CA cert path | `moesh_relay.py:91` |
| `MOESH_RELAY_TLS_PIN` | *none* — expected SHA-256 certificate fingerprint | `moesh_relay.py:92` |

### Flags

| flag | effect | source |
|---|---|---|
| `--remote-port`, `-R` | Public relay port on receiver (`26420..26430`) or `auto` | `moesh_relay.py:943-948` |
| `-n`, `--name`, `--service SERVICE` | Optional agent-defined name/label; returns `409 Conflict` if already held | `moesh_relay.py:949-959` |
| `--probe` | Query `/__moesh/status` for open/free/in-use/unavailable ports and exit | `moesh_relay.py:1023-1027` |
| `--receiver RECEIVER` | Receiver hostname or IP | `moesh_relay.py:960-964` |
| `--port PORT` | Receiver HTTP port (default 80, or 443 with TLS) | `moesh_relay.py:965-970` |
| `--url URL` | Full URL override (e.g. `https://receiver.example.com/__relay/26425`) | `moesh_relay.py:971-975` |
| `--target TARGET` | Local TCP target `host:port` to forward to (default `127.0.0.1:8000`) | `moesh_relay.py:976-980` |
| `--workers WORKERS` | Number of standby queued tunnels (default 4) | `moesh_relay.py:981-986` |
| `--id ID` | Carrier identity (default derived from host markers) | `moesh_relay.py:987-991` |
| `--token TOKEN` | Shared relay token for carrier authentication | `moesh_relay.py:992-1001` |
| `--claim-wait SECONDS` | Retry window when another carrier holds the port/label, then exit 3 (default 45.0) | `moesh_relay.py:1002-1007` |
| `--idle IDLE` | Standby tunnel refresh timeout in seconds (default 900) | `moesh_relay.py:1008-1013` |
| `--session-idle SECONDS` | Active session idle timeout in seconds (default 120; <=0 disables) | `moesh_relay.py:1014-1022` |
| `--tls` | Use TLS carrier connection (default port 443) | `moesh_relay.py:1028-1033` |
| `--tls-insecure` | Disable TLS certificate verification in dev/test | `moesh_relay.py:1034-1039` |
| `--insecure` | Alias for `--tls-insecure` | `moesh_relay.py:1040-1045` |
| `--tls-ca-cert PATH` | Path to custom CA certificate bundle | `moesh_relay.py:1046-1050` |
| `--tls-pin PIN` | Pin expected certificate SHA-256 fingerprint | `moesh_relay.py:1051-1055` |

### Relay Authentication Boundary & Secure Inference Deployment

#### Authentication Boundary
- **Carrier Authentication (`X-Moesh-Relay-Auth` / `--token`)**:
  When `MOESH_BRIDGE_RELAY_TOKEN` is configured on `moesh-bridge`, the carrier must provide `--token` matching the secret. This authenticates the **outbound agent dialout** to the receiver, preventing unauthorized workers from registering relays, occupying ports, or probing status.
- **Data-Plane Boundary**:
  The receiver bridge acts as a **blind TCP stream forwarder**. External clients connecting to the receiver's published relay port (e.g. `:26426`) connect directly to the upstream TCP target through the paired pipe. Relay carrier authentication does **not** authenticate external end users connecting to the public port.
- **Application-Level Security**:
  All services exposed via `moesh-relay` must configure their own authentication, authorization, and TLS termination at the application or reverse-proxy layer.

#### Secure LLM Inference Deployment (vLLM Example)
To expose a remote vLLM model inference engine securely:

```sh
# Step 1: Start vLLM locally with an API key and bind to localhost
python3 -m vllm.entrypoints.openai.api_server \
    --model meta-llama/Llama-3-8B-Instruct \
    --host 127.0.0.1 \
    --port 8000 \
    --api-key "<MODEL_API_KEY>"

# Step 2: Expose vLLM through the relay. --tls encrypts the carrier hop
# (agent -> bridge) only; the public relay port stays plaintext raw TCP.
# --session-idle 0 keeps long prefill/generation sessions open.
moesh-relay \
    --receiver receiver.example.com \
    --tls \
    --token "<RELAY_AUTH_TOKEN>" \
    --service vllm \
    --target 127.0.0.1:8000 \
    --session-idle 0

# Step 3: External clients query the model via the receiver's published port.
# Port 26426 is plaintext raw TCP (the bridge terminates TLS only on the tunnel
# listener, not on relay ports), so the client URL is http://:
curl http://receiver.example.com:26426/v1/chat/completions \
    -H "Authorization: Bearer <MODEL_API_KEY>" \
    -H "Content-Type: application/json" \
    -d '{
        "model": "meta-llama/Llama-3-8B-Instruct",
        "messages": [{"role": "user", "content": "Explain transactional durability in kernels"}]
    }'
```

**TLS boundaries:** `--tls` encrypts the agent→bridge carrier hop only
(moesh_relay.py:162-176); `--tls-cert/--tls-key` terminate TLS on the tunnel
listener only, not the public relay ports (moesh-bridge.py:2030-2062;
moesh-bridge.py:2072-2140 are plaintext); backend TLS terminates behind the
relay on the agent host (moesh-bridge.py:32-35). Because `:26426` is plaintext,
`curl https://receiver.example.com:26426` is unsupported as written — terminate
TLS at a front in front of the relay port for client-facing TLS.

---

## The receiver (`moesh-bridge.py`)

| variable | default | source |
|---|---|---|
| `MOESH_BRIDGE_TUNNEL_LISTEN` | `127.0.0.1:9447` — where nginx proxies the upgrade | `moesh-bridge.py:74` |
| `MOESH_BRIDGE_OPERATOR_V2_LISTEN` | `127.0.0.1:44441` — where the operator client connects | `moesh-bridge.py:76-78` |
| `MOESH_BRIDGE_OPERATOR_LISTEN` | `127.0.0.1:44440` — legacy v1 operator listener | `moesh-bridge.py:75` |
| `MOESH_BRIDGE_ALLOW_V1` | `1` — whether to allow legacy v1 connections; the V1 compatibility-path lifecycle is in PROTOCOL.md §9 (Receiver bridge). | `moesh-bridge.py:84` |
| `MOESH_RELAY_PORTS` | `26420-26430` — public TCP relay port pool (fallback: `MOESH_BRIDGE_GPU_PORTS`) | `moesh-bridge.py:2007-2015` |
| `MOESH_BRIDGE_LEASE_GRACE` | `1.5` — seconds a relay port stays held after its carrier's last live tunnel | `moesh-bridge.py:246` |
| `MOESH_BRIDGE_RELAY_TOKEN` | *unset* — when set, relay registration and `GET /__moesh/status` require `X-Moesh-Relay-Auth: <RELAY_AUTH_TOKEN>`; when unset the bridge logs that relay registration is open to anyone who can reach the tunnel listener | `moesh-bridge.py:258` |
| `MOESH_BRIDGE_HALFCLOSE_LINGER` | `60` — seconds the surviving direction of a half-closed pair is drained before both legs are closed (bounds CLOSE-WAIT accumulation) | `moesh-bridge.py:267` |
| `MOESH_BRIDGE_PAIR_SILENCE_TIMEOUT` | `30` — seconds a newly paired session has to move at least one byte in *each* direction; unestablished pairs are closed at the deadline (bounds the departed-worker carrier, HANDOFF.md §5); `0` disables; established sessions are never touched | `moesh-bridge.py:269-271` |
| `MOESH_BRIDGE_MAX_CONNECTIONS` | `0` — no ceiling; `N` caps simultaneously-active accepted connections across every listener; refusal happens at accept time and consumes zero queued tunnel slots (capacity is released on close/timeout/exception) | `moesh-bridge.py:326` |
| `MOESH_BRIDGE_TRUSTED_PROXIES` | `127.0.0.1,::1,::ffff:127.0.0.1` — comma-separated peer IPs trusted to provide forwarded client IP headers (`CF-Connecting-IP`, `X-Real-IP`, `X-Forwarded-For`) | `moesh-bridge.py:290-296` |
| `MOESH_BRIDGE_TLS_CERT` | *unset* — optional path to TLS certificate PEM for direct TLS termination on the tunnel listener without external nginx | `moesh-bridge.py:2032` |
| `MOESH_BRIDGE_TLS_KEY` | *unset* — optional path to TLS private key PEM for direct TLS termination on the tunnel listener | `moesh-bridge.py:2037` |

Two capacities are fixed constants rather than configuration, so that a
sustained flood of registrations cannot grow the process without bound:
`MAX_HOST_QUEUES = 256` routing labels and `MAX_RELAY_QUEUES = 128` relay
labels. Past the cap the bridge refuses the new label with `503 Service
Unavailable` instead of creating another queue. Each admitted host queue holds
at most 8 tunnels.

---

## `hosts.toml`

The client's pins file. One entry per host, each with the agent's public
key or a shared master secret.

```toml
prefix = "host"          # optional; the default prefix for a number
master = "<64 hex>"      # optional: fleet master secret for all numbered hosts
legacy_agent_pub = "<64 hex>" # optional: fallback candidate during migration

[hosts.default]
agent_pub = "<64 hex characters>"

[hosts.host-3]
agent_pub = "<64 hex characters>"
```

| key | meaning | source |
|---|---|---|
| `prefix` | how a number becomes a name: `-n 3` → `host-3` | `moesh_shell.py:167` |
| `master` (top level) | fleet master secret deriving static keys for all numbered hosts | `moesh_shell.py:269-278` |
| `legacy_agent_pub` | migration fallback key accepted alongside master derivation | `moesh_shell.py:233-235` |
| `[hosts.<name>].agent_pub` | explicitly pinned agent public key, as hex | `moesh_shell.py:258` |
| `[hosts.<name>].master` | host-specific master secret override | `moesh_shell.py:269-278` |

Rules the client applies:

* `agent_pub` takes priority for that specific host.
* If `master` is set, the derived HKDF key `proto.derive_static_key(master, host)` is added to candidates.
* If `legacy_agent_pub` is set, it is added to candidates, enabling multi-candidate matching during zero-downtime key rotation.
* A host with no valid candidates is refused (`moesh_shell.py:276-282`).

---

## Key paths

| purpose | default path | source |
|---|---|---|
| operator private key | `~/.config/moesh/operator.key` | `moesh_shell.py:87` (`DEFAULT_KEYFILE`) |
| operator public key | `~/.config/moesh/operator.key.pub` | `moesh_shell.py:186` |
| agent private key | `~/.config/moesh/agent.key` | `moesh_tunnel.py:107` (`DEFAULT_KEYFILE`) |
| agent public key | `~/.config/moesh/agent.key.pub` | `moesh_tunnel.py:1573` (`.pub` sibling in `generate_key`) |
| pins file | `~/.config/moesh/hosts.toml` | `moesh_shell.py:70` |

Private keys are written with mode `0600`, public keys with `0644`.

---

## Wire bounds

Set by the protocol core; not configurable, listed so you can recognise them
in a log:

| bound | value | source |
|---|---|---|
| upgrade token | `moesh-tunnel-v2` | `moesh_wire.py:16` |
| protocol version | `2` | `moesh_wire.py:12` |
| noise pattern | `Noise_XX_25519_ChaChaPoly_BLAKE2s` | `moesh_proto.py:121` (`NOISE_NAME`) |
| handshake deadline | 150 s | `moesh_proto.py:137` (`HANDSHAKE_TIMEOUT`) |
| negotiation deadline | 30 s | `moesh_proto.py:151` (`NEGOTIATION_TIMEOUT`) |
| terminal bytes in one record | 32768 | `moesh_wire.py:36` |
| control payload | 4096 | `moesh_wire.py:40` |
| ciphertext in one frame | 65535 | `moesh_proto.py:129` (`MAX_CIPHERTEXT`) |
| terminal rows / columns | 1–1000 | `moesh_proto.py:112-113` |
| default size | 24 × 80 | `moesh_proto.py:112-113` |
| moecp max frame header | 64 KiB | `moecp.py:82` (`MAX_FRAME_HDR`) |
| moecp max payload chunk | 10 MiB | `moecp.py:86` (`MAX_FRAME_PAYLOAD`) |
| moecp stream chunk size | 32 KiB | `moecp.py:78` (`CHUNK_SIZE`) |
