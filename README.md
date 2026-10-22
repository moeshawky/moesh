# moesh

**An SSH-like encrypted remote shell.** Noise_XX over an HTTP/1.1 upgrade, a
shell that survives your disconnect, and a client that re-attaches by itself.
The receiver is a blind socket pump — it moves bytes between two peers and
never holds a byte of plaintext.

## Why it exists

`ssh host` needs the far machine to accept an inbound connection. A machine
behind NAT, a laptop on a locked-down network, or a host that is only allowed
to dial out cannot do that.

`moesh` inverts the direction. The far machine (**the agent**) dials out to a
**receiver** you run on the public network; the receiver pairs it with your
terminal (**the operator client**). Your keystrokes and the remote shell's
output travel over one encrypted session between your machine and the agent
host. The receiver copies bytes in both directions and reads none of them.

```
agent host (far side)                      receiver (the middle)
┌──────────────────────┐                  ┌────────────────────────────────┐
│  the agent           │  HTTP/1.1        │  nginx  /__moesh/tunnel        │
│  moesh_tunnel_v2.py  │  Upgrade  ────▶  │        │                       │
│  Noise_XX session    │  ciphertext      │  moesh-bridge.py (blind pump)  │
│  bash on a PTY       │───────────────▶  │        │                       │
└──────────────────────┘                  │  127.0.0.1:44441               │
                                          │        ▲                       │
                                          │        │  moesh_shell_v2.py    │
┌──────────────────────┐                  │        │  (the operator)       │
│  your terminal       │──────────────────│        │                       │
│  moesh_shell_v2.py   │  Noise_XX session└────────────────────────────────┘
│  -n 3                │
└──────────────────────┘
```

## Features

* **Encrypted end to end.** A `Noise_XX_25519_ChaChaPoly_BLAKE2s` session runs
  between your terminal and the agent host. The receiver carries ciphertext
  and never holds plaintext terminal data.
* **Pinned identities.** Each side pins the other's public key. A mismatch is
  refused before a shell exists.
* **The shell outlives the connection.** Detach and re-attach: the same
  directory, the same variables, the same background jobs.
* **Automatic re-attach.** A dropped transport is retried with a growing
  pause; the shell keeps running in the meantime.
* **One shell per operator.** Three concurrent operators by default, each on
  its own PTY, so two people never share a terminal.
* **No inbound port on the agent host.** It only dials out.
* **ssh-style key handling.** `--generate-key`, `0600` private / `0644` public,
  `SHA256:` fingerprints.

## Quick start

Three roles: the **agent host** you want a shell on, the **receiver** on the
public network, and your **terminal**. (Two machines are enough if you run
the client on the receiver.)

Requirements: Linux, Python 3.11 or newer, and `noiseprotocol==0.3.1`.

### 1. Install

```sh
cd /opt/moesh
python3 -m venv .venv
.venv/bin/pip install noiseprotocol==0.3.1
```

The three programs are plain scripts at the top of the tree:
`moesh_tunnel_v2.py` (agent), `moesh_shell_v2.py` (operator client) and
`moesh-bridge.py` (receiver). The receiver's nginx and systemd setup is in
[docs/install.md](docs/install.md).

### 2. Generate the keys, once per side

```sh
# on the agent host
.venv/bin/python moesh_tunnel_v2.py --generate-key
#   -> ~/.config/moesh/agent.key      (0600)
#   -> ~/.config/moesh/agent.key.pub  (0644)

# on your terminal
.venv/bin/python moesh_shell_v2.py --generate-key
#   -> ~/.config/moesh/operator.key      (0600)
#   -> ~/.config/moesh/operator.key.pub  (0644)
```

Both print the public half and a `SHA256:` fingerprint. The private half
never leaves the machine that generated it, and the repository ships no keys.

### 3. Exchange only the `.pub` halves

Copy `agent.key.pub` to your terminal and pin it:

```toml
# ~/.config/moesh/hosts.toml
prefix = "host"

[hosts.host-3]
agent_pub = "<the agent's public half>"
```

Copy `operator.key.pub` to the agent host and pin it there:

```sh
export MOESH_TUNNEL_V2_OPERATOR_PUB=<the operator's public half>
```

### 4. Start the agent

```sh
export MOESH_TUNNEL_V2_RECEIVER=receiver.example.com
export MOESH_TUNNEL_V2_HOST=3                  # -> the routing name "host-3"
export MOESH_TUNNEL_V2_AGENT_KEYFILE=$HOME/.config/moesh/agent.key
export MOESH_TUNNEL_V2_OPERATOR_PUB=<the operator's public half>
.venv/bin/python moesh_tunnel_v2.py
```

The agent logs `tunnel established; waiting for an operator` once the receiver
has queued its tunnel.

### 5. Attach

```sh
.venv/bin/python moesh_shell_v2.py -n 3
```

`-n 3` selects the routing name `host-3`; the client pins that host's public
key from `~/.config/moesh/hosts.toml` and refuses to run without it.

| flag | effect |
|---|---|
| `-n <number>` | attach to host `<number>` (`host-3` with the default prefix) |
| `--fresh` | start a new shell instead of re-attaching to the running one |
| `--no-reconnect` | exit on a lost connection instead of re-attaching |
| `--addr host:port` | the receiver's operator endpoint (default `127.0.0.1:44441`) |
| `--generate-key` | write a fresh key pair |
| `--force` | overwrite an existing key file when generating |

`~.` detaches and leaves the remote shell running.

The full key flow, including rotation, is in [docs/keys.md](docs/keys.md).

## How it works

1. The agent dials the receiver and asks for an HTTP/1.1 upgrade on
   `/__moesh/tunnel`. nginx forwards the request to the bridge.
2. The bridge answers `101 Switching Protocols` and puts the connection in a
   per-host queue. It copies bytes; it does not read them.
3. The operator's client connects to the receiver's operator port, names the
   host it wants, and the bridge pairs it with the oldest live tunnel for that
   host.
4. The client and the agent run a Noise_XX handshake across the paired
   sockets. Each side compares the static key it learned against the pin it
   was given; a mismatch aborts the session.
5. The session negotiates the terminal size and type, and the agent attaches
   the operator to a shell from its pool — the running one, or a new one when
   `--fresh` was given.

## Security model

* The receiver is **blind**: it holds no keys, decrypts nothing and logs no
  terminal bytes. What it sees is ciphertext, plus the host name in the clear
  (it is a routing label).
* Identities are **pinned**: the client pins the agent's public key per host,
  the agent pins the operator's public key, and both refuse to continue on a
  mismatch.
* The transport is **Noise_XX_25519_ChaChaPoly_BLAKE2s**, with a fresh
  handshake per connection and a fixed prologue that binds the protocol
  identity. There is no plaintext fallback in any code path.
* What it does **not** cover: a compromised endpoint, traffic analysis, and
  denial of service against the receiver.

The full threat model is in [docs/security.md](docs/security.md).

## Status

`moesh` is pre-1.0 and is not claimed to be production-ready. The gate is the
operator-outcome suite: the operator must reach a prompt with the shell state
intact. One intermittent failure is documented in the test protocol: on the
re-attach path the post-re-attach output was absent in 1 of 5 isolated
full-suite runs, while the prompt itself was present. If a session comes back
without the state you expect, reconnect with `--fresh`.

## Documentation

| document | what is in it |
|---|---|
| [docs/install.md](docs/install.md) | receiver (nginx + systemd), agent and client installation |
| [docs/keys.md](docs/keys.md) | key generation, pinning, fingerprints, rotation |
| [docs/configuration.md](docs/configuration.md) | every environment variable, flag, path and default |
| [docs/architecture.md](docs/architecture.md) | the components, the design lineage, the state machine |
| [docs/operations.md](docs/operations.md) | running it, reading the logs, common failures |
| [docs/security.md](docs/security.md) | the threat model and its limits |
| [PROTOCOL-v2.md](PROTOCOL-v2.md) | the wire contract: framing, record types, states |
| [SECURITY.md](SECURITY.md) | reporting a vulnerability |

## License

moesh is licensed under the Apache License 2.0. The full text is in the
[`LICENSE`](LICENSE) file in the repository root; the canonical text is at
<https://www.apache.org/licenses/LICENSE-2.0>.
