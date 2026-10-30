# Configuration

Everything configurable in `moesh`, with the default that applies when the
variable is not set. Each row names the source line it was read from.

---

## The operator client (`moesh_shell.py`)

### Environment

| variable | default | source |
|---|---|---|
| `MOESH_SHELL_ADDR` | `127.0.0.1:44441` | `moesh_shell.py:64`, used at `:812` |
| `MOESH_SHELL_KEYFILE` | `~/.config/moesh/operator.key` | `moesh_shell.py:66`, used at `:815` |
| `MOESH_SHELL_PEER_PUBFILE` | `~/.config/moesh/agent.pub` | `moesh_shell.py:67`, used at `:819` |
| `MOESH_SHELL_HOSTS_FILE` | `~/.config/moesh/hosts.toml` | `moesh_shell.py:68-71` |
| `MOESH_SHELL_HANDSHAKE_TIMEOUT` | `150` seconds | `moesh_shell.py:926`, constant at `moesh_proto.py:90` |
| `MOESH_SHELL_PING_INTERVAL` | `15` seconds | `moesh_shell.py:977` |
| `MOESH_SHELL_DEAD_AFTER` | `45` seconds | `moesh_shell.py:980` |
| `MOESH_TUNNEL_HOST` | `default` — default for `-n` | `moesh_shell.py:829`, constant at `moesh_wire.py:26` |
| `TERM` | `xterm-256color` | `moesh_shell.py:884`, constant at `moesh_proto.py:108` |

Legacy aliases `MOESH_SHELL_V2_*` are supported for backward compatibility.

`MOESH_SHELL_DEAD_AFTER` is the client's silence limit: if nothing is received
within that duration, the session is treated as dead and reconnect begins.

### Flags

| flag | effect | source |
|---|---|---|
| `--addr HOST:PORT` | the receiver's operator endpoint | `moesh_shell.py:811-813` |
| `--keyfile PATH` | the operator's private key | `moesh_shell.py:814-816` |
| `--peer-pubfile PATH` | the agent's public key, for a single-host setup | `moesh_shell.py:817-820` |
| `--fresh` | ask for a new shell instead of re-attaching | `moesh_shell.py:821-825` |
| `--host`, `-n` | the host number or name to attach to | `moesh_shell.py:826-831` |
| `--new-master` | print a fresh master secret and the key it derives | `moesh_shell.py:832-836` |
| `--generate-key` | write a fresh operator key pair | `moesh_shell.py:837-841` |
| `--force` | overwrite an existing key file when generating | `moesh_shell.py:842-846` |
| `--no-reconnect` | exit on a lost connection instead of re-attaching | `moesh_shell.py:847-852` |

The client requires a valid TTY when starting an interactive terminal session.

---

## The agent (`moesh_tunnel.py`)

### Environment

| variable | default | source |
|---|---|---|
| `MOESH_TUNNEL_RECEIVER` | *none — the agent refuses to start without it* | `moesh_tunnel.py:1168-1179` |
| `MOESH_TUNNEL_RECEIVER_PORT` | `80` | `moesh_tunnel.py:1180-1185`, constant at `:85` |
| `MOESH_TUNNEL_PATH` | `/__moesh/tunnel` | `moesh_tunnel.py:1186`, constant at `moesh_wire.py:23` |
| `MOESH_TUNNEL_AGENT_KEY` | *none* — the agent's private key as hex | `moesh_tunnel.py:151-155` |
| `MOESH_TUNNEL_AGENT_KEYFILE` | *none* — a file holding that key | `moesh_tunnel.py:156-160` |
| `MOESH_TUNNEL_OPERATOR_PUB` | *none* — optional pinned operator public key (when unset, derived from `MOESH_TUNNEL_MASTER`) | `moesh_tunnel.py:203-239` |
| `MOESH_TUNNEL_HOST` | *none* — host number or `auto`; defaults to name below | `moesh_tunnel.py:242-255` |
| `MOESH_TUNNEL_PREFIX` | `host` | `moesh_tunnel.py:234-236`, constant at `moesh_proto.py:730` |
| `MOESH_TUNNEL_NAME` | `default` | `moesh_tunnel.py:241`, constant at `:93` |
| `MOESH_TUNNEL_MASTER` | *none* — fleet master secret for HKDF key derivation | `moesh_tunnel.py:268-283` |
| `MOESH_TUNNEL_SESSIONS` | `3` concurrent operators | `moesh_tunnel.py:1193`, constant at `:86` |
| `MOESH_TUNNEL_PING_INTERVAL` | `15` seconds | `moesh_tunnel.py:871` |
| `MOESH_TUNNEL_DEAD_AFTER` | `45` seconds | `moesh_tunnel.py:872` |
| `MOESH_TUNNEL_CHILD_PIDFILE` | *none* — file that receives the active shell's PID | `moesh_tunnel.py:442`, `:453` |

Legacy aliases `MOESH_TUNNEL_V2_*` and `NB_TUNNEL_V2_*` are supported for backward compatibility.

`MOESH_TUNNEL_AGENT_KEY` is checked first; `MOESH_TUNNEL_AGENT_KEYFILE` is the fallback. If `MOESH_TUNNEL_MASTER` is provided, the static key is deterministically derived from `HKDF-SHA256(info=b"moesh-tunnel-v2/agent-static-key/v1/host-<n>")`.

### Flags

| flag | effect | source |
|---|---|---|
| `--generate-key` | write a fresh agent key pair and print the public half | `moesh_tunnel.py` |
| `--keyfile PATH` | where `--generate-key` writes the private key | `moesh_tunnel.py` |
| `--force` | overwrite an existing key file when generating | `moesh_tunnel.py` |
| `--probe` | query `/__moesh/status` for active hosts and relay ports and exit | `moesh_tunnel.py` |
| `--host`, `-n` | host number, name, or `auto` | `moesh_tunnel.py` |
| `--receiver` | receiver hostname or IP override | `moesh_tunnel.py` |
| `--receiver-port` | receiver HTTP port override | `moesh_tunnel.py` |

### Back-off and Timings

| behaviour | value | source |
|---|---|---|
| wait after an authentication failure | 60 s | `moesh_tunnel.py:108` |
| network back-off, first step and ceiling | 2 s → 30 s | `moesh_tunnel.py:1005`, `:1028` |
| output kept while nobody is attached | 256 KiB | `moesh_tunnel.py:114` |
| client silence deadline | 45 s | `moesh_tunnel.py:872-877` |

---

## Secure File Copy (`moecp`)

### Environment

| variable | default | source |
|---|---|---|
| `MOESH_SHELL_ADDR` | `127.0.0.1:44441` | `moecp.py:65` |
| `MOESH_SHELL_KEYFILE` | `~/.config/moesh/operator.key` | `moecp.py:66` |
| `MOESH_SHELL_HOSTS_FILE` | `~/.config/moesh/hosts.toml` | `moecp.py:67` |

### Flags

```
moecp [-h] [-r] [-p] [-q] [-v] [--retry RETRY] [--compression {auto,zlib,raw}] [-n HOST] [--addr ADDR] [--keyfile KEYFILE] paths [paths ...]
```

| flag | effect | source |
|---|---|---|
| `paths` | Source path(s) followed by destination target | `moecp.py:1653` |
| `-r`, `--recursive` | Recursively copy entire directories | `moecp.py:1675` |
| `-p`, `--preserve` | Preserves modification times, access times, and modes | `moecp.py:1680` |
| `-q`, `--quiet` | Quiet mode: disables progress meter and non-fatal warnings | `moecp.py:1684` |
| `-v`, `--verbose` | Verbose debug logging to stderr | `moecp.py:1689` |
| `--retry RETRY` | Maximum retry attempts on connection interruption (default: 3) | `moecp.py:1694` |
| `--compression` | Transfer compression strategy (`auto`=fast zlib-1 with pre-compressed bypass, `zlib`=force zlib-1, `raw`=uncompressed) | `moecp.py:1700` |
| `-n`, `--host HOST` | Designated remote host number or name (e.g. `3` or `host-3`) | `moecp.py:1706` |
| `--addr ADDR` | Receiver operator bridge address | `moecp.py:1711` |
| `--keyfile KEYFILE` | Operator private key file path | `moecp.py:1716` |

---

## Outbound TCP Reverse Relay (`moesh_relay.py`)

### Environment

| variable | default | source |
|---|---|---|
| `MOESH_RELAY_RECEIVER` | *none* — target receiver hostname/IP | `moesh_relay.py` |
| `MOESH_RELAY_PORT` | `80` | `moesh_relay.py` |
| `MOESH_RELAY_REMOTE_PORT` | `auto` (when `--service` is unset) | `moesh_relay.py` |
| `MOESH_RELAY_SERVICE` | *none* — optional label | `moesh_relay.py` |
| `MOESH_RELAY_TARGET` | `127.0.0.1:8000` | `moesh_relay.py` |
| `MOESH_RELAY_WORKERS` | `4` standby tunnel workers | `moesh_relay.py` |
| `MOESH_RELAY_IDLE` | `900` seconds (standby tunnel refresh interval) | `moesh_relay.py` |
| `MOESH_RELAY_SESSION_IDLE` | `120` seconds (active paired session idle timeout) | `moesh_relay.py` |

### Flags

| flag | effect | source |
|---|---|---|
| `--remote-port`, `-R` | Public relay port on receiver (`26420..26430`) or `auto` | `moesh_relay.py` |
| `--service SERVICE` | Optional service label; returns `409 Conflict` if already held | `moesh_relay.py` |
| `--probe` | Query `/__moesh/status` for open/free/in-use/unavailable ports and exit | `moesh_relay.py` |
| `--receiver RECEIVER` | Receiver hostname or IP | `moesh_relay.py` |
| `--port PORT` | Receiver HTTP port (default 80) | `moesh_relay.py` |
| `--url URL` | Full URL override (e.g. `http://receiver.example.com/__relay/26425`) | `moesh_relay.py` |
| `--target TARGET` | Local TCP target `host:port` to forward to (default `127.0.0.1:8000`) | `moesh_relay.py` |
| `--workers WORKERS` | Number of standby queued tunnels (default 4) | `moesh_relay.py` |
| `--id ID` | Carrier identity (default random per process; reuse across restarts to reclaim your own lease) | `moesh_relay.py` |
| `--claim-wait SECONDS` | Retry window when another carrier holds the port/label, then exit 3 (default 45) | `moesh_relay.py` |
| `--idle IDLE` | Standby tunnel refresh timeout in seconds (default 900) | `moesh_relay.py` |
| `--session-idle SECONDS` | Active session idle timeout in seconds (default 120) | `moesh_relay.py` |

---

## The receiver (`moesh-bridge.py`)

| variable | default | source |
|---|---|---|
| `MOESH_BRIDGE_TUNNEL_LISTEN` | `127.0.0.1:9447` — where nginx proxies the upgrade | `moesh-bridge.py` |
| `MOESH_BRIDGE_OPERATOR_V2_LISTEN` | `127.0.0.1:44441` — where the operator client connects | `moesh-bridge.py` |
| `MOESH_BRIDGE_OPERATOR_LISTEN` | `127.0.0.1:44440` — legacy v1 operator listener | `moesh-bridge.py` |
| `MOESH_BRIDGE_ALLOW_V1` | `1` — whether to allow legacy v1 connections | `moesh-bridge.py` |
| `MOESH_RELAY_PORTS` | `26420-26430` — public TCP relay port pool (fallback: `MOESH_BRIDGE_GPU_PORTS`) | `moesh-bridge.py` |
| `MOESH_RELAYS` | *none* — optional comma-separated `<label>:<port>` mappings | `moesh-bridge.py` |
| `MOESH_BRIDGE_LEASE_GRACE` | `1.5` — seconds a relay port stays held after its carrier's last live tunnel | `moesh-bridge.py` |
| `MOESH_BRIDGE_RELAY_TOKEN` | *unset* — when set, relay registration and `GET /__moesh/status` require `X-Moesh-Relay-Auth: <token>`; when unset the bridge logs that relay registration is open to anyone who can reach the tunnel listener | `moesh-bridge.py` |
| `MOESH_BRIDGE_HALFCLOSE_LINGER` | `60` — seconds the surviving direction of a half-closed pair is drained before both legs are closed (bounds CLOSE-WAIT accumulation) | `moesh-bridge.py` |

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
| `prefix` | how a number becomes a name: `-n 3` → `host-3` | `moesh_shell.py:117-120` |
| `master` (top level) | fleet master secret deriving static keys for all numbered hosts | `moesh_shell.py:244-259` |
| `legacy_agent_pub` | migration fallback key accepted alongside master derivation | `moesh_shell.py:261-269` |
| `[hosts.<name>].agent_pub` | explicitly pinned agent public key, as hex | `moesh_shell.py:232-242` |
| `[hosts.<name>].master` | host-specific master secret override | `moesh_shell.py:244-259` |

Rules the client applies:

* `agent_pub` takes priority for that specific host.
* If `master` is set, the derived HKDF key `proto.derive_static_key(master, host)` is added to candidates.
* If `legacy_agent_pub` is set, it is added to candidates, enabling multi-candidate matching during zero-downtime key rotation.
* A host with no valid candidates is refused (`moesh_shell.py:276-282`).

---

## Key paths

| purpose | default path | source |
|---|---|---|
| operator private key | `~/.config/moesh/operator.key` | `moesh_shell.py:66` |
| operator public key | `~/.config/moesh/operator.key.pub` | `moesh_shell.py:186` |
| agent private key | `~/.config/moesh/agent.key` | `moesh_tunnel.py:100` |
| agent public key | `~/.config/moesh/agent.key.pub` | `moesh_tunnel.py:968` |
| pins file | `~/.config/moesh/hosts.toml` | `moesh_shell.py:70` |

Private keys are written with mode `0600`, public keys with `0644`.

---

## Wire bounds

Set by the protocol core; not configurable, listed so you can recognise them
in a log:

| bound | value | source |
|---|---|---|
| upgrade token | `moesh-tunnel-v2` | `moesh_wire.py:14` |
| protocol version | `2` | `moesh_wire.py:11` |
| noise pattern | `Noise_XX_25519_ChaChaPoly_BLAKE2s` | `moesh_proto.py:81` |
| handshake deadline | 150 s | `moesh_proto.py:90` |
| negotiation deadline | 30 s | `moesh_proto.py:103` |
| terminal bytes in one record | 32768 | `moesh_wire.py:29` |
| control payload | 4096 | `moesh_wire.py:32` |
| ciphertext in one frame | 65535 | `moesh_proto.py:84` |
| terminal rows / columns | 1–1000 | `moesh_proto.py:112-113` |
| default size | 24 × 80 | `moesh_proto.py:112-113` |
| moecp max frame header | 64 KiB | `moecp.py:52` |
| moecp max payload chunk | 10 MiB | `moecp.py:53` |
| moecp stream chunk size | 1 MiB | `moecp.py:54` |
