# CLI Reference

Complete command-line interface reference for the five executables installed by `moesh`. Every flag, positional argument, default value, and exit code below is verified against the `argparse` definitions in running code.

**Last Verified:** 2026-10-30 UTC
**Verification Command:** `uv run pytest tests/test_doc_drift.py tests/test_cli_packaging.py -q`

---

## Summary of Entry Points

| Executable | Entry Point (`pyproject.toml:101-106`) | Role | Runtime Dependencies |
|---|---|---|---|
| `moesh` | `moesh_shell:main` | Interactive PTY client, non-interactive command runner, and stdin/stdout pipe client | `noiseprotocol==0.3.1`, `cryptography>=42.0.0` |
| `moecp` | `moecp:main` | Transactional encrypted file and directory transfer client (`scp` equivalent) | `noiseprotocol==0.3.1`, `cryptography>=42.0.0` |
| `moesh-tunnel` | `moesh_tunnel:main` | Outbound remote host daemon serving persistent PTY shells, `exec` commands, and native file transfers | `noiseprotocol==0.3.1`, `cryptography>=42.0.0` |
| `moesh-relay` | `moesh_relay:main` | Outbound reverse TCP port forwarder | Python standard library only |
| `moesh-bridge` | `moesh_bridge:main` | Blind HTTP/1.1 Upgrade pairing broker on the public receiver | Python standard library only |

---

## 1. `moesh` — Operator Shell & Remote Command Client

**Source:** `moesh_shell.py:1111-1292`

### Synopsis

```sh
# Interactive persistent PTY shell
moesh [-n HOST] [--addr HOST:PORT] [--keyfile PATH] [--peer-pubfile PATH] [--fresh] [--no-reconnect] [-q]

# Non-interactive command execution (-c string or positional argv)
moesh [-n HOST] [-q] -c COMMAND
moesh [-n HOST] [-q] [--] COMMAND [ARG ...]

# Key generation
moesh --new-master [-n HOST]
moesh --generate-key [--keyfile PATH] [--force]
```

### Arguments & Flags

| Option / Argument | Default | Source | Behavior |
|---|---|---|---|
| `command` (positional) | *none* | `moesh_shell.py:1175-1179` | Optional remote command tokens (`nargs=argparse.REMAINDER`). Leading `--` is stripped (`moesh_shell.py:1222-1223`), and multiple tokens are shell-quoted via `shlex.join` (`moesh_shell.py:1232`). |
| `-c`, `--command COMMAND` | *none* | `moesh_shell.py:1168-1173` | Execute `COMMAND` non-interactively via `session_type="exec"` (`moesh_shell.py:1240`) without allocating a remote PTY. |
| `-n`, `--host HOST` | `MOESH_TUNNEL_HOST` or `default` | `moesh_shell.py:1135-1140` | Target host number (`3` resolves to `host-3`) or explicit routing name (`host-3`). |
| `--addr ADDR` | `MOESH_SHELL_ADDR` or `127.0.0.1:44441` | `moesh_shell.py:1120-1122` | Receiver operator-v2 listener `host:port`. |
| `--keyfile PATH` | `MOESH_SHELL_KEYFILE` or `~/.config/moesh/operator.key` | `moesh_shell.py:1123-1125` | Explicit operator X25519 private key file (disables master-key fallback when passed explicitly; `moesh_shell.py:359-367`). |
| `--peer-pubfile PATH` | `MOESH_SHELL_PEER_PUBFILE` or `~/.config/moesh/agent.pub` | `moesh_shell.py:1126-1129` | Pinned agent public key file used only when attaching to `default` without a `[hosts.default]` entry (`moesh_shell.py:1212-1213`). |
| `--fresh` | `False` | `moesh_shell.py:1130-1134` | Request an unshared new PTY shell (`fresh_session=True`) instead of re-attaching to the detached running shell. |
| `--no-reconnect` | `False` | `moesh_shell.py:1156-1160` | Exit immediately when an interactive connection drops instead of entering the auto-reconnect loop. |
| `-q`, `--quiet` | `False` | `moesh_shell.py:1162-1166` | Suppress `[moesh HH:MM:SS]` informational log lines on `stderr`; keeps `stdout` clean for binary pipelines. |
| `--new-master` | `False` | `moesh_shell.py:1141-1145` | Generate and print a fresh 32-byte (64-hex) fleet master secret plus the derived public key for `-n HOST`, then exit. |
| `--generate-key` | `False` | `moesh_shell.py:1146-1150` | Generate a local operator static keypair (`0600` private key, `0644` `.pub` sibling), print public key + `SHA256:` fingerprint, and exit. |
| `--force` | `False` | `moesh_shell.py:1151-1155` | Overwrite an existing key file when combined with `--generate-key`. |

### Execution Modes

1. **Interactive PTY Mode** (no `-c` and no positional `command`):
   - Requires `stdin` and `stdout` to be a local TTY (`moesh_shell.py:1241-1243`; when stdin is not a TTY and no command is given, the client negotiates `session_type="exec"` instead of refusing, per `moesh_shell.py:1239`).
   - Negotiates `session_type="shell"`, switches the local terminal to raw mode without `ISIG`, forwards `SIGWINCH` window resizes, and detaches cleanly on `~.` at the start of a line.
2. **Non-Interactive Exec & Pipe Mode** (`-c COMMAND` or positional `COMMAND [ARG ...]`):
   - Works with or without a TTY and negotiates `session_type="exec"` (`moesh_shell.py:1240`).
   - Streams local `stdin` to the remote process in 32 KiB encrypted `DATA` records and writes remote output directly to `stdout`.
   - Preserves dashed flags on remote commands automatically (`moesh -n 3 ls -la /tmp` or `moesh -n 3 -- echo -n hello`).
   - Propagates the remote process exit code directly (`moesh_shell.py:1107-1108`).

### Verified Examples

```sh
# 1. Interactive shell on host-3
moesh -n 3

# 2. Run a remote command with dashed flags (no extra quoting needed)
moesh -n 3 ls -la /tmp

# 3. Run a shell pipeline string on host-3
moesh -n 3 -c "uname -a && df -h /"

# 4. Stream 5 MiB of binary data through remote cat and verify SHA-256
head -c 5242880 /dev/urandom | tee /tmp/in.bin | moesh -n 3 -q cat > /tmp/out.bin
cmp -s /tmp/in.bin /tmp/out.bin && echo "byte-identical"
```

### Exit Codes (`moesh`)

| Code | Condition | Source |
|---:|---|---|
| `0` | Remote shell or command exited with status `0`; a broken pipe on non-interactive exec closes cleanly | `run_exec_session` `return status` (`moesh_shell.py:1098`); BrokenPipeError → `0` (`moesh_shell.py:1264-1265`) |
| `<N>` | Remote command exit code propagated verbatim (`130` on `SIGINT`) | `def run_exec_session` (`moesh_shell.py:970`); `return status` (`moesh_shell.py:1098`) |
| `1` | `ProtocolError`, `TransportEOF`, or `AuthenticationError` (fatal protocol/identity failure); key-file overwrite refused without `--force` | `moesh_shell.py:1390-1392`; `generate_key` refusal (`moesh_shell.py:207`) |
| `2` | `argparse` argument/usage error only | `parser.parse_args` (`moesh_shell.py:1180`) |

---

## 2. `moecp` — Transactional Encrypted File Copy

**Source:** `moecp.py:2663-2825`

### Synopsis

```sh
moecp [-r] [-p] [-q] [-v] [--retry N] [--compression {auto,zlib,raw}] [-n HOST] [--addr HOST:PORT] [--keyfile PATH] SOURCE [SOURCE ...] DEST
```

### Path Specification Formats (`moecp.py:1015-1055`)

- `3:/remote/path` — shorthand for `host-3:/remote/path`
- `host-3:/remote/path` or `user@host-3:/remote/path` — explicit remote host routing name (`user@` prefix is stripped before label validation)
- `remote:/remote/path` — uses the host supplied via `-n HOST` (falls back to `host-1` if `-n` is unset)
- `./local/path` or `/local/path` — local filesystem path (note: local paths containing `:` after `/` such as `./a:b` are treated as local)

*(Remote-to-remote direct copy is rejected with exit code `1`; stage locally between hosts: `moecp.py:2751-2752`.)*

### Arguments & Flags

| Option / Argument | Default | Source | Behavior |
|---|---|---|---|
| `paths` (positional) | *required (≥2)* | `moecp.py:2723-2727` | One or more source paths followed by a single destination path. Multiple sources require the destination to be an existing directory (`moecp.py:1320-1389`, `:1780-1906`). |
| `-r`, `--recursive` | `False` | `moecp.py:2676-2680` | Recursively transfer directory trees (paginated manifests of 256 entries per frame above 32 KiB; `moecp.py:116-117`). |
| `-p`, `--preserve` | `False` | `moecp.py:2681-2685` | Preserve file modification times, access times, and POSIX permission modes. |
| `-q`, `--quiet` | `False` | `moecp.py:2686-2690`, `:2731-2734` | Disable progress meter, transfer summary, and `[moesh ...]` connection logs on `stderr`. |
| `-v`, `--verbose` | `False` | `moecp.py:2691-2695` | Print per-file debug diagnostics to `stderr`. |
| `--retry RETRY` | `3` | `moecp.py:2696-2701` | Maximum connection attempts on transient `TransportEOF`, `TimeoutError`, or `OSError` (`ProtocolError` aborts immediately without retrying; `moecp.py:2651-2654`). |
| `--compression {auto,zlib,raw}` | `auto` | `moecp.py:2702-2707` | `auto` compresses chunks with `zlib` level 1 while bypassing 29 pre-compressed extensions (`.safetensors`, `.gguf`, `.pt`, `.zst`, `.gz`, `.zip`, `.mp4`, etc.; `moecp.py:227-239`); `zlib` forces zlib-1; `raw` sends uncompressed 32 KiB chunks. |
| `-n`, `--host HOST` | `""` | `moecp.py:2708-2712` | Default remote host when using `remote:/path` target syntax. |
| `--addr ADDR` | `MOESH_SHELL_ADDR` or `127.0.0.1:44441` | `moecp.py:2713-2717` | Receiver operator-v2 listener `host:port`. |
| `--keyfile PATH` | `MOESH_SHELL_KEYFILE` or `~/.config/moesh/operator.key` | `moecp.py:2718-2722` | Explicit operator private key file path. |

### Verified Examples

```sh
# Upload a single file to host-3 using numeric shorthand
moecp AGENTS.md 3:/tmp/AGENTS.md

# Upload a directory recursively with mode/timestamp preservation in quiet mode
moecp -r -p -q ./checkpoints 3:/workspace/checkpoints

# Download logs from host-3 to local directory
moecp -r host-3:/var/log/app ./local-logs/
```

### Exit Codes (`moecp`)

| Code | Condition | Source |
|---:|---|---|
| `0` | All requested files transferred (or verified up-to-date via SHA-256 ledger) | `moecp.py:1586`, `:1906` |
| `1` | One or more files failed, destination locked (`TransferBusyError`), path escape rejected, remote module missing (`ProtocolError`), or both endpoints remote | `moecp.py:2656`, `:2752` |
| `2` | CLI argument validation failure (`argparse`) | `moecp.py:2737` |

---

## 3. `moesh-tunnel` — Remote Host Agent Daemon

**Source:** `moesh_tunnel.py:1609-1726`

### Synopsis

```sh
# Run agent daemon
moesh-tunnel [--receiver HOST] [--port PORT] [-n HOST|auto]

# Control-plane status probe (non-destructive)
moesh-tunnel --probe [--receiver HOST] [--port PORT]

# Generate static agent keypair
moesh-tunnel --generate-key [--keyfile PATH] [--force]
```

### Arguments & Flags

| Option | Default | Source | Behavior |
|---|---|---|---|
| `--receiver RECEIVER` | `MOESH_TUNNEL_RECEIVER` | `moesh_tunnel.py:1632-1636` | Receiver hostname or IP address to dial outbound. Required unless `--generate-key` is used. |
| `--port PORT` | `MOESH_TUNNEL_RECEIVER_PORT` or `80` | `moesh_tunnel.py:1637-1642` | Receiver HTTP port for `GET /__moesh/tunnel` and `GET /__moesh/status`. |
| `-n`, `--host HOST` | `MOESH_TUNNEL_HOST` or `default` | `moesh_tunnel.py:1643-1648` | Host slot number (`3` → `host-3`), explicit name, or `auto` to query `/__moesh/status` and claim the lowest unoccupied `host-<N>` (`moesh_tunnel.py:1518-1534`). |
| `--probe` | `False` | `moesh_tunnel.py:1627-1631` | Query `GET /__moesh/status` on the receiver, print active hosts and open/free relay ports, and exit `0`. |
| `--generate-key` | `False` | `moesh_tunnel.py:1612-1616` | Write a fresh X25519 agent keypair (`0600` private, `0644` `.pub`), print the public key + fingerprint, and exit. |
| `--keyfile PATH` | `~/.config/moesh/agent.key` | `moesh_tunnel.py:1617-1621` | Target path for `--generate-key`. |
| `--force` | `False` | `moesh_tunnel.py:1622-1626` | Overwrite an existing key file during `--generate-key`. |

*(Deployment note: When deploying `moesh_tunnel.py` as standalone `.py` files without `pip install moesh`, include `moesh_wire.py`, `moesh_proto.py`, `moesh_tunnel.py`, `moecp.py`, and `moesh_shell.py` in the same directory so in-process `moecp` transfers succeed.)*

### Exit Codes (`moesh-tunnel`)

| Code | Condition | Source |
|---:|---|---|
| `0` | Clean shutdown on `SIGINT`/`SIGTERM`, successful `--probe`, or successful `--generate-key` | `moesh_tunnel.py:1443`, `:1678`, `:1725` |
| `1` | Refused to overwrite existing key file without `--force`, or failed `--probe` HTTP query | `moesh_tunnel.py:1451`, `:1676` |
| `2` | Missing receiver address, missing/invalid cryptographic key configuration, or invalid port | `moesh_tunnel.py:1665`, `:1673`, `:1692` |
| `3` | Host slot already leased by another live carrier (`HTTP/1.1 409 Conflict` persisted past incident retry window; set `RestartPreventExitStatus=3` in systemd) | `HostConflictError` sets `_conflict_refused` (`moesh_tunnel.py:1700-1708`); `main` returns `3` (`moesh_tunnel.py:1849`) |

---

## 4. `moesh-relay` — Outbound Reverse TCP Port Relay

**Source:** `moesh_relay.py:926-1190`

### Synopsis

```sh
# Expose local TCP service onto a specific or auto-selected receiver port
moesh-relay --receiver HOST [-R PORT|auto] [-n NAME|--name NAME|--service LABEL] [--target HOST:PORT] [--workers N] [--id ID] [--token SECRET] [--claim-wait SEC] [--idle SEC] [--session-idle SEC] [--tls] [--tls-insecure] [--tls-ca-cert PATH] [--tls-pin PIN]

# Probe receiver relay ports and active hosts
moesh-relay --probe --receiver HOST [--port PORT] [--token SECRET] [--tls] [--tls-insecure] [--tls-ca-cert PATH] [--tls-pin PIN]
```

### Arguments & Flags

| Option | Default | Source | Behavior |
|---|---|---|---|
| `-R`, `--remote-port PORT` | `MOESH_RELAY_REMOTE_PORT` (empty/`""`, which the relay treats as `auto` to claim the lowest free port) | `moesh_relay.py:943-948` | Public TCP port on the receiver (`26420..26430`) or `auto` to claim the lowest free port. |
| `-n`, `--name`, `--service SERVICE` | `MOESH_RELAY_NAME` or `MOESH_RELAY_SERVICE` or `""` | `moesh_relay.py:949-959` | Optional agent-defined name/label for the leased relay port (default: port number or auto). |
| `--receiver RECEIVER` | `MOESH_RELAY_RECEIVER` or `MOESH_TUNNEL_RECEIVER` | `moesh_relay.py:960-964` | Receiver hostname or IP address. |
| `--port PORT` | `MOESH_RELAY_PORT` or `MOESH_TUNNEL_RECEIVER_PORT` or `80` (or `443` with TLS) | `moesh_relay.py:965-970` | Receiver HTTP/HTTPS port for Upgrade dialouts. |
| `--url URL` | `""` | `moesh_relay.py:971-975` | Full `http://` or `https://` override URL. Auto-activates TLS when scheme is `https://`. |
| `--target TARGET` | `MOESH_RELAY_TARGET` or `127.0.0.1:8000` | `moesh_relay.py:976-980` | Local `host:port` service to splice paired TCP streams into. |
| `--workers WORKERS` | `MOESH_RELAY_WORKERS` or `4` | `moesh_relay.py:981-986` | Number of standby queued connections maintained at the receiver. |
| `--id ID` | `MOESH_RELAY_ID` or `derive_carrier_id()` | `moesh_relay.py:987-991` | Carrier lease identity; derived from host markers so restarts reclaim the host's own lease immediately. |
| `--token TOKEN` | `MOESH_RELAY_TOKEN` or `MOESH_BRIDGE_RELAY_TOKEN` or `""` | `moesh_relay.py:992-1001` | Shared secret sent as `X-Moesh-Relay-Auth` when `MOESH_BRIDGE_RELAY_TOKEN` is set on the bridge. |
| `--claim-wait CLAIM_WAIT` | `45.0` seconds | `moesh_relay.py:1002-1007` | Retry window per `409 Conflict` incident before exiting with status `3`. |
| `--idle IDLE` | `MOESH_RELAY_IDLE` or `900` seconds | `moesh_relay.py:1008-1013` | Standby socket refresh interval before recycling an unpaired connection (staggered with make-before-break replacement). |
| `--session-idle SESSION_IDLE` | `MOESH_RELAY_SESSION_IDLE` or `120` seconds | `moesh_relay.py:1014-1022` | Idle timeout on active paired TCP sessions (set to 0 or negative to disable timeout for long-running inference). |
| `--probe` | `False` | `moesh_relay.py:1023-1027` | Query `GET /__moesh/status`, print open/free/in-use/unavailable relay ports and active shell hosts, and exit. |
| `--tls` | `MOESH_RELAY_TLS` or `False` | `moesh_relay.py:1028-1033` | Use TLS for carrier connection to receiver (default port 443). |
| `--tls-insecure` | `MOESH_RELAY_TLS_INSECURE` or `False` | `moesh_relay.py:1034-1039` | Disable TLS certificate verification for self-signed certificates in dev/test. |
| `--insecure` | `False` | `moesh_relay.py:1040-1045` | Alias for `--tls-insecure`. |
| `--tls-ca-cert PATH` | `MOESH_RELAY_TLS_CA_CERT` or `""` | `moesh_relay.py:1046-1050` | Path to custom CA certificate bundle for TLS verification. |
| `--tls-pin PIN` | `MOESH_RELAY_TLS_PIN` or `""` | `moesh_relay.py:1051-1055` | Expected SHA-256 fingerprint of the receiver TLS certificate (hex). |

### Exit Codes (`moesh-relay`)

| Code | Condition | Source |
|---:|---|---|
| `0` | Clean shutdown on `SIGINT` or successful `--probe` | `moesh_relay.py:367`, `:1187` |
| `1` | Failed `--probe` request (e.g. missing/wrong `--token` → `401`, or unreachable receiver) | `moesh_relay.py:365` |
| `2` | CLI argument validation error (e.g. missing `--receiver` or invalid `--target`) | `moesh_relay.py:1122` |
| `3` | Requested relay port or `--service` label remained held by another carrier past `--claim-wait` (`HTTP/1.1 409 Conflict`), or `401 Unauthorized` | `moesh_relay.py:1189` |

---

## 5. `moesh-bridge` — Blind Pairing Broker

**Source:** `moesh-bridge.py:2018-2151`

### Synopsis

```sh
# Start blind bridge with plaintext HTTP/1.1 Upgrade listener (default port 9447)
moesh-bridge

# Start blind bridge with direct TLS termination on the tunnel listener
moesh-bridge --tls-cert /path/to/cert.pem --tls-key /path/to/key.pem
```

### Arguments & Flags

| Option | Default | Source | Behavior |
|---|---|---|---|
| `--tls-cert PATH` | `MOESH_BRIDGE_TLS_CERT` or `""` | `moesh-bridge.py:2030-2034` | Path to TLS certificate PEM for direct TLS termination on the tunnel listener without an external reverse proxy. |
| `--tls-key PATH` | `MOESH_BRIDGE_TLS_KEY` or `""` | `moesh-bridge.py:2035-2039` | Path to TLS private key PEM for direct TLS termination on the tunnel listener. |

`moesh-bridge` accepts `-h`/`--help` for CLI discovery and `--tls-cert` / `--tls-key` for optional direct TLS termination on the tunnel listener without an external reverse proxy (`moesh-bridge.py:2022-2048`). All listener addresses, port pools, capacities, and optional relay tokens are configured via `MOESH_BRIDGE_*` and `MOESH_RELAY*` environment variables (`MOESH_BRIDGE_TLS_CERT` and `MOESH_BRIDGE_TLS_KEY` mirror the CLI flags). See [configuration.md](configuration.md#the-receiver-moesh-bridgepy) for every environment variable and capacity bound.

### Verified Examples

```sh
# Standard deployment behind local nginx:
moesh-bridge

# Direct HTTPS/WSS termination without nginx:
moesh-bridge \
    --tls-cert /etc/letsencrypt/live/receiver.example.com/fullchain.pem \
    --tls-key /etc/letsencrypt/live/receiver.example.com/privkey.pem
```

### Exit Codes (`moesh-bridge`)

| Code | Condition | Source |
|---:|---|---|
| `0` | Clean shutdown on `SIGINT` or `SIGTERM` | `moesh-bridge.py:2151` |
| `1` | Configuration error (e.g. providing `--tls-cert` without `--tls-key` or vice versa) | `moesh-bridge.py:2046-2048` |

---

## Verification

Run the CLI packaging and documentation drift suites locally:

```sh
uv run pytest tests/test_cli_packaging.py tests/test_doc_drift.py -v
```
