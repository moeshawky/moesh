# CLI Reference

Complete command-line interface reference for the five executables installed by `moesh`. Every flag, positional argument, default value, and exit code below is verified against the `argparse` definitions in running code.

**Last Verified:** 2026-10-30 UTC
**Verification Command:** `uv run pytest tests/test_doc_drift.py tests/test_cli_packaging.py -q`

---

## Summary of Entry Points

| Executable | Entry Point (`pyproject.toml:103-108`) | Role | Runtime Dependencies |
|---|---|---|---|
| `moesh` | `moesh_shell:main` | Interactive PTY client, non-interactive command runner, and stdin/stdout pipe client | `noiseprotocol==0.3.1`, `cryptography>=42.0.0` |
| `moecp` | `moecp:main` | Transactional encrypted file and directory transfer client (`scp` equivalent) | `noiseprotocol==0.3.1`, `cryptography>=42.0.0` |
| `moesh-tunnel` | `moesh_tunnel:main` | Outbound remote host daemon serving persistent PTY shells, `exec` commands, and native file transfers | `noiseprotocol==0.3.1`, `cryptography>=42.0.0` |
| `moesh-relay` | `moesh_relay:main` | Outbound reverse TCP port forwarder (`frpc` equivalent) | Python standard library only |
| `moesh-bridge` | `moesh_bridge:main` | Blind HTTP/1.1 Upgrade pairing broker on the public receiver (`frps` equivalent) | Python standard library only |

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
   - Requires `stdin` and `stdout` to be a local TTY (`moesh_shell.py:1241-1243`; exits with code `2` if not a TTY).
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
| `0` | Remote shell or command exited with status `0`, or local detached cleanly via `~.` | `moesh_shell.py:1264-1266` |
| `<N>` | Remote command exit code propagated verbatim (or `128 + signal` if killed by signal) | `moesh_shell.py:1104-1108` |
| `1` | Refused to overwrite existing key file without `--force`, or remote closed without `EXIT` status | `moesh_shell.py:206`, `:1108` |
| `2` | Configuration/key error, non-TTY `stdin` in interactive mode, authentication failure, or fatal protocol error | `moesh_shell.py:1220`, `:1243`, `:1279` |

---

## 2. `moecp` — Transactional Encrypted File Copy

**Source:** `moecp.py:2202-2353`

### Synopsis

```sh
moecp [-r] [-p] [-q] [-v] [--retry N] [--compression {auto,zlib,raw}] [-n HOST] [--addr HOST:PORT] [--keyfile PATH] SOURCE [SOURCE ...] DEST
```

### Path Specification Formats (`moecp.py:258-300`)

- `3:/remote/path` — shorthand for `host-3:/remote/path`
- `host-3:/remote/path` or `user@host-3:/remote/path` — explicit remote host routing name (`user@` prefix is stripped before label validation)
- `remote:/remote/path` — uses the host supplied via `-n HOST` (falls back to `host-1` if `-n` is unset)
- `./local/path` or `/local/path` — local filesystem path (note: local paths containing `:` after `/` such as `./a:b` are treated as local)

*(Remote-to-remote direct copy is rejected with exit code `1`; stage locally between hosts: `moecp.py:2288-2290`.)*

### Arguments & Flags

| Option / Argument | Default | Source | Behavior |
|---|---|---|---|
| `paths` (positional) | *required (≥2)* | `moecp.py:2261-2275` | One or more source paths followed by a single destination path. Multiple sources require the destination to be an existing directory (`moecp.py:1430-1435`, `:1725-1731`). |
| `-r`, `--recursive` | `False` | `moecp.py:2214-2218` | Recursively transfer directory trees (paginated manifests of 256 entries per frame above 32 KiB; `moecp.py:97-102`). |
| `-p`, `--preserve` | `False` | `moecp.py:2219-2223` | Preserve file modification times, access times, and POSIX permission modes. |
| `-q`, `--quiet` | `False` | `moecp.py:2224-2228`, `:2269-2272` | Disable progress meter, transfer summary, and `[moesh ...]` connection logs on `stderr`. |
| `-v`, `--verbose` | `False` | `moecp.py:2229-2233` | Print per-file debug diagnostics to `stderr`. |
| `--retry RETRY` | `3` | `moecp.py:2234-2239` | Maximum connection attempts on transient `TransportEOF`, `TimeoutError`, or `OSError` (`ProtocolError` aborts immediately without retrying; `moecp.py:2189-2190`). |
| `--compression {auto,zlib,raw}` | `auto` | `moecp.py:2240-2245` | `auto` compresses chunks with `zlib` level 1 while bypassing 29 pre-compressed extensions (`.safetensors`, `.gguf`, `.pt`, `.zst`, `.gz`, `.zip`, `.mp4`, etc.; `moecp.py:113-125`); `zlib` forces zlib-1; `raw` sends uncompressed 32 KiB chunks. |
| `-n`, `--host HOST` | `""` | `moecp.py:2246-2250` | Default remote host when using `remote:/path` target syntax. |
| `--addr ADDR` | `MOESH_SHELL_ADDR` or `127.0.0.1:44441` | `moecp.py:2251-2255` | Receiver operator-v2 listener `host:port`. |
| `--keyfile PATH` | `MOESH_SHELL_KEYFILE` or `~/.config/moesh/operator.key` | `moecp.py:2256-2260` | Explicit operator private key file path. |

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
| `0` | All requested files transferred (or verified up-to-date via SHA-256 ledger) | `moecp.py:2353` |
| `1` | One or more files failed, destination locked (`TransferBusyError`), path escape rejected, remote module missing (`ProtocolError`), or both endpoints remote | `moecp.py:2195`, `:2290`, `:2348` |
| `2` | CLI argument validation failure (`argparse`) | `moecp.py:2275` |

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
| `3` | Host slot already leased by another live carrier (`HTTP/1.1 409 Conflict` persisted past incident retry window; set `RestartPreventExitStatus=3` in systemd) | `moesh_tunnel.py:1574-1583`, `:1723-1724` |

---

## 4. `moesh-relay` — Outbound Reverse TCP Port Relay

**Source:** `moesh_relay.py:418-577`

### Synopsis

```sh
# Expose local TCP service onto a specific or auto-selected receiver port
moesh-relay --receiver HOST [-R PORT|auto] [--service LABEL] [--target HOST:PORT] [--workers N] [--id ID] [--token SECRET] [--claim-wait SEC] [--idle SEC] [--session-idle SEC]

# Probe receiver relay ports and active hosts
moesh-relay --probe --receiver HOST [--port PORT] [--token SECRET]
```

### Arguments & Flags

| Option | Default | Source | Behavior |
|---|---|---|---|
| `-R`, `--remote-port PORT` | `MOESH_RELAY_REMOTE_PORT` (`auto` if `--service` unset) | `moesh_relay.py:422-427`, `:542-546` | Public TCP port on the receiver (`26420..26430`) or `auto` to claim the lowest free port. |
| `--service SERVICE` | `MOESH_RELAY_SERVICE` or `""` | `moesh_relay.py:428-432` | Optional human-readable lease label (e.g. `vllm-api`). |
| `--receiver RECEIVER` | `MOESH_RELAY_RECEIVER` or `MOESH_TUNNEL_RECEIVER` | `moesh_relay.py:433-437` | Receiver hostname or IP address. |
| `--port PORT` | `MOESH_RELAY_PORT` or `MOESH_TUNNEL_RECEIVER_PORT` or `80` | `moesh_relay.py:438-443` | Receiver HTTP port for Upgrade dialouts. |
| `--url URL` | `""` | `moesh_relay.py:444-448` | Full `http://host:port/__relay/<target>` override URL. |
| `--target TARGET` | `MOESH_RELAY_TARGET` or `127.0.0.1:8000` | `moesh_relay.py:449-453` | Local `host:port` service to splice paired TCP streams into. |
| `--workers WORKERS` | `MOESH_RELAY_WORKERS` or `4` | `moesh_relay.py:454-459` | Number of standby queued connections maintained at the receiver. |
| `--id ID` | `MOESH_RELAY_ID` or `derive_carrier_id()` | `moesh_relay.py:460-464`, `:61-86` | Carrier lease identity; defaults to a deterministic 16-hex SHA-256 digest of `/etc/machine-id` so restarts reclaim the host's own lease immediately. |
| `--token TOKEN` | `MOESH_RELAY_TOKEN` or `""` | `moesh_relay.py:465-472` | Shared secret sent as `X-Moesh-Relay-Auth` when `MOESH_BRIDGE_RELAY_TOKEN` is set on the bridge. |
| `--claim-wait CLAIM_WAIT` | `45.0` seconds | `moesh_relay.py:473-478` | Retry window per `409 Conflict` incident before exiting with status `3`. |
| `--idle IDLE` | `MOESH_RELAY_IDLE` or `900` seconds | `moesh_relay.py:479-484` | Standby socket refresh interval before recycling an unpaired connection. |
| `--session-idle SESSION_IDLE` | `MOESH_RELAY_SESSION_IDLE` or `120` seconds | `moesh_relay.py:485-490` | Idle timeout on active paired TCP sessions. |
| `--probe` | `False` | `moesh_relay.py:491-495` | Query `GET /__moesh/status`, print open/free/in-use/unavailable relay ports and active shell hosts, and exit. |

### Exit Codes (`moesh-relay`)

| Code | Condition | Source |
|---:|---|---|
| `0` | Clean shutdown on `SIGINT` or successful `--probe` | `moesh_relay.py:534`, `:575` |
| `1` | Failed `--probe` request (e.g. missing/wrong `--token` → `401`, or unreachable receiver) | `moesh_relay.py:518-521` |
| `2` | CLI argument validation error (e.g. missing `--receiver` or invalid `--target`) | `moesh_relay.py:507`, `:538`, `:549` |
| `3` | Requested relay port or `--service` label remained held by another carrier past `--claim-wait` (`HTTP/1.1 409 Conflict`), or `401 Unauthorized` | `moesh_relay.py:573-574` |

---

## 5. `moesh-bridge` — Blind Pairing Broker

**Source:** `moesh-bridge.py:33-40` → `moesh-bridge.py:1505-1643`

### Synopsis

```sh
moesh-bridge [-h]
```

`moesh-bridge` accepts `-h`/`--help` for CLI discovery and packaging verification (`moesh-bridge.py:1507-1514`); all listener addresses, port pools, capacities, and optional relay tokens are configured via `MOESH_BRIDGE_*` and `MOESH_RELAY*` environment variables so systemd unit files hold the complete runtime configuration in one place. See [configuration.md](configuration.md#the-receiver-moesh-bridgepy) for every environment variable and capacity bound.

---

## Verification

Run the CLI packaging and documentation drift suites locally:

```sh
uv run pytest tests/test_cli_packaging.py tests/test_doc_drift.py -v
```
