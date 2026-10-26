# Architecture

This page explains how the pieces fit together and where the design came
from. The wire contract — framing, record types, the session state machine —
is in [../PROTOCOL.md](../PROTOCOL.md).

---

## The components

| CLI command / file | role |
|---|---|
| `moesh_wire.py` | wire protocol constants and defaults: framing limits, payload bounds, upgrade tokens, route paths, version identifiers. Pure Python standard library with zero external dependencies. |
| `moesh_proto.py` | the wire protocol engine: framing serialization, the Noise_XX session state machine, deterministic HKDF key derivation, terminal size negotiation. |
| `moesh-tunnel` (`moesh_tunnel.py`) | **the agent daemon**: runs on the target host that offers the shell, holds the pool of tunnels and the pool of persistent PTY shells. |
| `moesh` (`moesh_shell.py`) | **the operator client**: attaches to the receiver's operator port, performs mutual Noise_XX authentication, handles raw terminal discipline and window resizes. |
| `moecp` (`moecp.py`) | **secure file copy**: scp-like utility over encrypted moesh transport, bootstrapping an ephemeral in-memory worker in a dedicated fresh PTY session with end-to-end SHA-256 verification and atomic staging. |
| `moesh-relay` (`moesh_relay.py`) | **accelerator reverse relay**: zero-dependency HTTP/1.1 Upgrade reverse pump connecting accelerator services (vLLM, GPU runners, embeddings) on remote nodes to receiver listening ports. |
| `moesh-bridge` (`moesh-bridge.py`) | **the receiver broker**: pairs an operator with an agent's tunnel and copies bytes. It is a blind socket pump holding 0 keys and decrypting 0 bytes. |
| `moesh-bridge.service` | the systemd unit for the receiver bridge. |
| `PROTOCOL.md` | the wire contract and framing specification. |
| `tests/` | the integration and verification suite: 149 tests covering protocol core, key generation, host identity, operator outcomes, moecp file transfers, and adversarial security boundaries. |

---

## The design lineage

### RFC 4254 — the SSH Connection Protocol

The question "how do you carry several interactive shells over one secure
transport?" has a canonical answer, and this project follows it rather than
inventing one.

**RFC 4254** (Standards Track, January 2006), §5 *Channel Mechanism*:

> All terminal sessions, forwarded connections, etc., are channels. Either
> side may open a channel. **Multiple channels are multiplexed into a
> single connection.**

§6 adds: *"Multiple sessions can be active simultaneously."* What `moesh`
uses of those pieces:

| RFC 4254 | moesh |
|---|---|
| transport + crypto layer | Noise_XX over the HTTP/1.1 upgrade |
| `SSH_MSG_CHANNEL_OPEN` / `_CONFIRMATION` / `_FAILURE` | one TCP tunnel per operator session |
| `SSH_MSG_CHANNEL_DATA` | length-prefixed encrypted records |
| `SSH_MSG_CHANNEL_EOF` / `_CLOSE` | the `EXIT` and `CLOSE` records |
| `SSH_MSG_CHANNEL_REQUEST` (`pty-req`, `window-change`) | the HELLO/ACCEPT/READY negotiation, `RESIZE` |
| `SSH_MSG_CHANNEL_WINDOW_ADJUST` | not implemented: the PTY applies its own back-pressure |
| `SSH_MSG_GLOBAL_REQUEST` | not implemented |

### tmux — a server that holds the shells

The other canonical shape is tmux: a server that holds the shells, and
clients that attach to it. **`moesh` is that shape, not the SSH one**, and
the reason is concrete:

> A blind bridge cannot demultiplex two encrypted sessions that share one
> socket — the framing is identical.

The agent host is therefore the tmux server: it holds the shells and the
pool of them, and every operator brings its own transport. One tunnel per
operator, one shell per operator, and two people never share a terminal.

---

## One tunnel per operator

```
agent host                                  receiver                    operator
┌───────────────────────────┐               ┌──────────────────┐        ┌──────────────┐
│ worker 1 ── tunnel ───────┼──► /__moesh/  │ host-3 queue     │◄──────┤ client       │
│ worker 2 ── tunnel ───────┼──► tunnel  ──►│ (FIFO, 8 slots)  │◄──────┤ client       │
│ worker 3 ── tunnel ───────┼──►            └──────────────────┘        └──────────────┘
│ shell pool: bash on a PTY │
└───────────────────────────┘
```

* The agent runs one worker thread per concurrent operator —
  `MOESH_TUNNEL_SESSIONS`, three by default (`moesh_tunnel.py:1193`).
  Each worker holds one connection to the receiver and serves whoever claims
  it (`moesh_tunnel.py:990-1030`).
* The receiver keeps one queue per host name (`moesh-bridge.py:85-92`) and
  pairs an operator with the oldest **live** tunnel in that queue
  (`moesh-bridge.py:298-324`). A tunnel that died while queued is discarded
  rather than paired.
* The agent's shell pool hands out one shell per session (`moesh_tunnel.py:530-580`).
  A detached shell is kept and given to the next operator; `--fresh` asks for a
  new one.

---

## The session state machine

```
CONNECTED → AUTHENTICATED → NEGOTIATING → READY → ACTIVE → CLOSING
```

* **CONNECTED** — the TCP connection is up.
* **AUTHENTICATED** — the Noise handshake finished and the peer's static
  key matched the pin. The client logs
  `authenticated (agent static key matched the pin)`.
* **NEGOTIATING** — `HELLO` carries the terminal type, encoding, size and
  capabilities; the agent answers `ACCEPT`. The agent picks the shell here:
  the running one, or a new one when `fresh_session` is set.
* **READY** — both sides have sent `READY`.
* **ACTIVE** — terminal bytes flow. No PTY is created and no byte is
  forwarded before this point.
* **CLOSING** — an authenticated `CLOSE` record ends the session.

Every transition is checked; an unlisted transition fails the session
closed. The record types and the exact field lists are in
[../PROTOCOL.md](../PROTOCOL.md).

---

## Secure File Copy Architecture (`moecp`)

`moecp` mirrors `scp` semantics across the encrypted `moesh` channel without requiring
pre-installed daemons or modifying remote files.

```
operator terminal (moecp)                      receiver (blind bridge)          target host (fresh session)
┌───────────────────────────┐                 ┌──────────────────────┐         ┌───────────────────────────┐
│ moecp client              │                 │ moesh-bridge.py      │         │ moesh_tunnel.py           │
│ - Connects to 127.0.0.1   │  Noise_XX       │ - Pairs FIFO         │ Noise_XX│ - Accepts fresh_session   │
│ - Sets fresh_session=True │────────────────▶│ - Opaque pump        │────────▶│ - Spawns clean bash PTY   │
│ - Injects bootstrap worker│  encrypted      │                      │encrypted│ - Executes worker in RAM  │
│ - Streams binary frames   │◀────────────────│                      │◀────────│ - Atomic staging & verify │
└───────────────────────────┘                 └──────────────────────┘         └───────────────────────────┘
```

1. **Session Isolation:** `moecp` initiates a Noise_XX session with `fresh_session=True`.
   The agent allocates a dedicated, unshared PTY process, completely insulating active
   interactive shell sessions from transfer traffic.
2. **In-Memory Bootstrap:** The client pushes a compressed (base64 + zlib) Python worker script
   directly into the PTY standard input. The worker executes strictly in memory without writing
   temporary scripts to the remote filesystem.
3. **Framed Streaming Protocol:** Communication switches to binary framing over the raw PTY:
   - Chunked streaming with 1 MiB transfer chunks and zlib compression.
   - Maximum frame header: 64 KiB; maximum payload: 10 MiB (defends against memory exhaustion).
4. **End-to-End Verification:** Source and destination compute streaming SHA-256 digests.
   If digests mismatch, the destination aborts without committing.
5. **Atomic Staging:** Inbound files are written to `.part.<pid>` temporary files in the target
   directory and moved via `os.replace` only after digest verification succeeds, preventing
   partial or corrupted files on disk.
6. **Path Traversal Sanitization:** All relative paths are scrubbed with `sanitize_relpath`,
   strictly rejecting directory traversal sequences (`..`), null bytes (`\0`), and absolute path
   roots (`/` and `\`).

---

## Accelerator Service Outbound Relay (`moesh_relay`)

For accelerator hosts (TPUs, GPUs, Kaggle instances) running backend services (such as vLLM,
TTS sidecars, or embeddings engines) that need to be accessed from the receiver or local network:

```
Accelerator Host                               Receiver Bridge                      Local Client on Receiver
┌───────────────────────────┐                 ┌──────────────────────┐             ┌─────────────────────────┐
│ moesh_relay.py            │ HTTP/1.1        │ moesh-bridge.py      │ TCP         │ OpenCode / cURL / SDK   │
│ - Dials /__relay/<svc>    │ Upgrade         │ - Listens on relay   │ Connection  │ - Connects to localhost │
│ - Splices to local port   │────────────────▶│   port (e.g. :26429) │◀────────────│   on mapped relay port  │
│   (e.g. 127.0.0.1:8001)   │ Raw bytes pump  │ - Pairs sockets FIFO │ Raw bytes   │   (e.g. 127.0.0.1:26429)│
└───────────────────────────┘                 └──────────────────────┘             └─────────────────────────┘
```

* **Zero Dependencies:** Written in standard-library Python; requires no external libraries or pip packages.
* **Firewall Friendly:** Dials outbound over HTTP/1.1 port 80 to `/__relay/<service>`. No incoming ports required.
* **Automatic Healing:** Maintains a worker pool (default 4 connections); immediately redials when connections are paired or dropped.

---

## Deterministic Fleet Identity (Zero-Key-Exchange)

Instead of managing separate key pairs for each remote host, fleets can derive identities deterministically
from a single 32-byte shared master secret (`MOESH_TUNNEL_MASTER`):

```
Master Secret (32 bytes) ──▶ HKDF-SHA256(info=b"moesh-agent-key-host-<n>") ──▶ Static Keypair for host-<n>
```

* **Agent Derivation:** When `MOESH_TUNNEL_MASTER` is present, `moesh_tunnel.py` derives its X25519 static
  key using HKDF-SHA256 with the info parameter bound to the host routing label (`host-<n>`).
* **Operator Verification:** In `~/.config/moesh/hosts.toml`, a top-level `master = "<hex>"` entry allows
  the operator client to derive and pin the expected public key for any host number automatically.
* **Dual-Key Migration:** Operator configurations can pin both `master` and `legacy_agent_pub`
  simultaneously, permitting seamless migration without dropping connectivity to legacy nodes.

---

## Where the shell lives

The agent owns the shells, and the shell outlives the operator's connection
but not the agent:

* the operator detaches → the shell keeps running, and its output is held
  in a bounded buffer (256 KiB) for the next operator
  (`moesh_tunnel.py:114`, `:430-436`);
* the operator re-attaches → the same shell, its directory, its variables
  and its jobs (`moesh_tunnel.py:641-696`);
* the agent stops → the shell is terminated with `SIGHUP` and reaped
  (`moesh_tunnel.py:487-501`).
