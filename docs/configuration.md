# Configuration

Everything configurable in `moesh`, with the default that applies when the
variable is not set. Each row names the source line it was read from.

---

## The operator client (`moesh_shell_v2.py`)

### Environment

| variable | default | source |
|---|---|---|
| `MOESH_SHELL_V2_ADDR` | `127.0.0.1:44441` | `moesh_shell_v2.py:64`, used at `:663` |
| `MOESH_SHELL_V2_KEYFILE` | `~/.config/moesh/operator.key` | `moesh_shell_v2.py:73`, used at `:666` |
| `MOESH_SHELL_V2_PEER_PUBFILE` | `~/.config/moesh/agent.pub` | `moesh_shell_v2.py:74`, used at `:670` |
| `MOESH_SHELL_V2_HOSTS_FILE` | `~/.config/moesh/hosts.toml` | `moesh_shell_v2.py:68-71` |
| `MOESH_SHELL_V2_HANDSHAKE_TIMEOUT` | `150` seconds | `moesh_shell_v2.py:770`, constant at `moesh_proto_v2.py:81` |
| `MOESH_SHELL_V2_PING_INTERVAL` | `15` seconds | `moesh_shell_v2.py:821` |
| `MOESH_SHELL_V2_DEAD_AFTER` | `45` seconds | `moesh_shell_v2.py:824` |
| `MOESH_TUNNEL_V2_HOST` | `default` — the default for `-n` | `moesh_shell_v2.py:680`, constant at `:65` |
| `TERM` | `xterm-256color` | `moesh_shell_v2.py:733`, constant at `moesh_proto_v2.py:105` |

`MOESH_SHELL_V2_DEAD_AFTER` is the client's own silence limit: if nothing at
all comes back within that many seconds, the session is treated as dead. It
is deliberately shorter than the agent's, so the client gives up first and
re-attaches.

### Flags

| flag | effect | source |
|---|---|---|
| `--addr HOST:PORT` | the receiver's operator endpoint | `moesh_shell_v2.py:662-664` |
| `--keyfile PATH` | the operator's private key | `moesh_shell_v2.py:665-667` |
| `--peer-pubfile PATH` | the agent's public key, for a single-host setup | `moesh_shell_v2.py:668-671` |
| `--fresh` | ask for a new shell instead of re-attaching | `moesh_shell_v2.py:672-676` |
| `--host`, `-n` | the host number or name to attach to | `moesh_shell_v2.py:677-682` |
| `--new-master` | print a fresh master secret and the key it derives | `moesh_shell_v2.py:683-687` |
| `--generate-key` | write a fresh operator key pair | `moesh_shell_v2.py:688-692` |
| `--force` | overwrite an existing key file when generating | `moesh_shell_v2.py:693-697` |
| `--no-reconnect` | exit on a lost connection instead of re-attaching | `moesh_shell_v2.py:698-703` |

The client needs a real terminal: it refuses to start when standard input is
not a tty (`moesh_shell_v2.py:728-732`).

---

## The agent (`moesh_tunnel_v2.py`)

### Environment

| variable | default | source |
|---|---|---|
| `MOESH_TUNNEL_V2_RECEIVER` | *none — the agent refuses to start without it* | `moesh_tunnel_v2.py:960-966` |
| `MOESH_TUNNEL_V2_RECEIVER_PORT` | `80` | `moesh_tunnel_v2.py:967`, constant at `:84` |
| `MOESH_TUNNEL_V2_PATH` | `/__moesh/tunnel` | `moesh_tunnel_v2.py:968`, constant at `:85` |
| `MOESH_TUNNEL_V2_AGENT_KEY` | *none* — the agent's private key as hex | `moesh_tunnel_v2.py:149` |
| `MOESH_TUNNEL_V2_AGENT_KEYFILE` | *none* — a file holding that key | `moesh_tunnel_v2.py:150` |
| `MOESH_TUNNEL_V2_OPERATOR_PUB` | *none* — the pinned operator public key | `moesh_tunnel_v2.py:179` |
| `MOESH_TUNNEL_V2_HOST` | *none* — the host number; with none, the name below is used | `moesh_tunnel_v2.py:211` |
| `MOESH_TUNNEL_V2_PREFIX` | `host` | `moesh_tunnel_v2.py:212`, constant at `moesh_proto_v2.py:631` |
| `MOESH_TUNNEL_V2_NAME` | `default` | `moesh_tunnel_v2.py:216`, constant at `:93` |
| `MOESH_TUNNEL_V2_MASTER` | *none* — a master secret the static key is derived from | `moesh_tunnel_v2.py:243` |
| `MOESH_TUNNEL_V2_SESSIONS` | `3` concurrent operators | `moesh_tunnel_v2.py:975`, constant at `:86` |
| `MOESH_TUNNEL_V2_PING_INTERVAL` | `15` seconds | `moesh_tunnel_v2.py:720` |
| `MOESH_TUNNEL_V2_DEAD_AFTER` | `90` seconds | `moesh_tunnel_v2.py:721` |
| `MOESH_TUNNEL_V2_CHILD_PIDFILE` | *none* — a file that receives the shell's PID | `moesh_tunnel_v2.py:391` |

`MOESH_TUNNEL_V2_AGENT_KEY` is read first; `MOESH_TUNNEL_V2_AGENT_KEYFILE` is
the fallback (`moesh_tunnel_v2.py:149-156`). The agent needs one of them and
needs the operator's pin, or it refuses to start (`moesh_tunnel_v2.py:157-161`,
`:178-186`).

### Flags

| flag | effect | source |
|---|---|---|
| `--generate-key` | write a fresh agent key pair and print the public half | `moesh_tunnel_v2.py:941-945` |
| `--keyfile PATH` | where `--generate-key` writes the private key | `moesh_tunnel_v2.py:946-950` |
| `--force` | overwrite an existing key file when generating | `moesh_tunnel_v2.py:951-955` |

### The agent's back-off

| behaviour | value | source |
|---|---|---|
| wait after an authentication failure | 60 s | `moesh_tunnel_v2.py:108` |
| network back-off, first step and ceiling | 2 s → 30 s | `moesh_tunnel_v2.py:911`, `:934` |
| output kept while nobody is attached | 256 KiB | `moesh_tunnel_v2.py:114` |

---

## The receiver (`moesh-bridge.py`)

| variable | default | source |
|---|---|---|
| `MOESH_BRIDGE_TUNNEL_LISTEN` | `127.0.0.1:9447` — where nginx proxies the upgrade | `moesh-bridge.py:53` |
| `MOESH_BRIDGE_OPERATOR_V2_LISTEN` | `127.0.0.1:44441` — where the operator client connects | `moesh-bridge.py:55-57` |

---

## `hosts.toml`

The client's pins file. One entry per host, each with the agent's public
key.

```toml
prefix = "host"          # optional; the default prefix for a number

[hosts.default]
agent_pub = "<64 hex characters>"

[hosts.host-3]
agent_pub = "<64 hex characters>"
```

| key | meaning | source |
|---|---|---|
| `prefix` | how a number becomes a name: `-n 3` → `host-3` | `moesh_shell_v2.py:117-120` |
| `[hosts.<name>].agent_pub` | the pinned agent public key, as hex | `moesh_shell_v2.py:202-212` |
| `[hosts.<name>].master` | a master secret the host's key is derived from | `moesh_shell_v2.py:213-222` |
| `master` (top level) | one master secret for every host | `moesh_shell_v2.py:213` |

Rules the client applies:

* `agent_pub` wins over `master` for that host.
* A host with neither is refused, and the error lists the hosts that do have
  a pin (`moesh_shell_v2.py:223-229`).
* The file is only consulted when it has a `hosts` section. Without one, the
  client reads the agent's public key from `MOESH_SHELL_V2_PEER_PUBFILE`
  (`moesh_shell_v2.py:713-721`).

A routing name is at most 64 characters, and may hold letters, digits, dot,
dash and underscore (`moesh_tunnel_v2.py:217-224`, `moesh-bridge.py:95-99`).

---

## Key paths

| purpose | default path | source |
|---|---|---|
| operator private key | `~/.config/moesh/operator.key` | `moesh_shell_v2.py:73` |
| operator public key | `~/.config/moesh/operator.key.pub` | written next to the private key, `moesh_shell_v2.py:153` |
| agent private key | `~/.config/moesh/agent.key` | `moesh_tunnel_v2.py:100` |
| agent public key | `~/.config/moesh/agent.key.pub` | written next to the private key, `moesh_tunnel_v2.py:885` |
| pins file | `~/.config/moesh/hosts.toml` | `moesh_shell_v2.py:70` |

Private keys are written with mode `0600`, public keys with `0644`.

---

## Ports

| port | who listens | who connects |
|---|---|---|
| `9447` | the receiver's tunnel listener | nginx, which proxies `/__moesh/tunnel` to it |
| `44441` | the receiver's operator listener | the operator client |
| `80` | nginx on the receiver | the agent, by default (`MOESH_TUNNEL_V2_RECEIVER_PORT`) |

---

## Wire bounds

Set by the protocol core; not configurable, listed so you can recognise them
in a log.

| bound | value | source |
|---|---|---|
| upgrade token | `moesh-tunnel-v2` | `moesh_proto_v2.py:59` |
| protocol version | `2` | `moesh_proto_v2.py:56` |
| noise pattern | `Noise_XX_25519_ChaChaPoly_BLAKE2s` | `moesh_proto_v2.py:62` |
| handshake deadline | 150 s | `moesh_proto_v2.py:81` |
| negotiation deadline | 30 s | `moesh_proto_v2.py:94` |
| terminal bytes in one record | 32768 | `moesh_proto_v2.py:72` |
| control payload | 4096 | `moesh_proto_v2.py:75` |
| ciphertext in one frame | 65535 | `moesh_proto_v2.py:69` |
| terminal rows / columns | 1–1000 | `moesh_proto_v2.py:97`, `:100` |
| default size | 24 × 80 | `moesh_proto_v2.py:103-104` |

---

## Where the client reads its terminal size

The client measures the real window size of its own terminal
(`moesh_shell_v2.py:354`) and sends it in `HELLO`; a later resize is sent as a
`RESIZE` record (`moesh_shell_v2.py:387-389`). The agent applies it to the
PTY with `TIOCSWINSZ` (`moesh_tunnel_v2.py:309-311`), so the remote shell
sees the right size without reconnecting.
