# Architecture

This page explains how the pieces fit together and where the design came
from. The wire contract — framing, record types, the session state machine —
is in [../PROTOCOL-v2.md](../PROTOCOL-v2.md).

---

## The components

| file | role |
|---|---|
| `moesh_proto_v2.py` | the wire protocol: framing, the Noise session, the state machine, key derivation. Every wire constant lives here. A few names are still re-declared in the endpoint modules — the receiver is standard-library only — and the test `INT-005` marks that as a known deviation. |
| `moesh_tunnel_v2.py` | **the agent**: runs on the host that offers the shell, holds the pool of tunnels and the pool of shells. |
| `moesh_shell_v2.py` | **the operator client**: attaches to the receiver's operator port and relays your terminal. |
| `moesh-bridge.py` | **the receiver**: pairs an operator with an agent's tunnel and copies bytes. It is blind. |
| `moesh-bridge.service` | the systemd unit for the receiver. |
| `PROTOCOL-v2.md` | the wire contract, in detail. |
| `tests/` | the integration suite: a real bridge, a real agent, a real client. |

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
| transport + crypto layer | Noise_XX over the HTTP upgrade |
| `SSH_MSG_CHANNEL_OPEN` / `_CONFIRMATION` / `_FAILURE` | one TCP tunnel per operator |
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

A future version could carry many channels inside one Noise session — the
framing and the record types are already there — but then the second
operator has to reach the first operator's client, the way `ssh -M` does.

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
  `MOESH_TUNNEL_V2_SESSIONS`, three by default (`moesh_tunnel_v2.py:977-987`).
  Each worker holds one connection to the receiver and serves whoever claims
  it (`moesh_tunnel_v2.py:898-935`).
* The receiver keeps one queue per host name (`moesh-bridge.py:85-92`) and
  pairs an operator with the oldest **live** tunnel in that queue
  (`moesh-bridge.py:298-324`). A tunnel that died while queued is discarded
  rather than paired.
* The agent's shell pool hands out one shell per session
  (`moesh_tunnel_v2.py:530-549`). A detached shell is kept and given to the
  next operator; `--fresh` asks for a new one.

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
[../PROTOCOL-v2.md](../PROTOCOL-v2.md).

---

## The two queues that matter

The receiver keeps the tunnels of each host name apart, so an operator can
never be paired with another host's tunnel:

| queue | filled by | drained by |
|---|---|---|
| `host-3` | the agent's upgrade request for `/__moesh/tunnel/host-3` | the operator who asks for `host-3` |

The routing name travels in the clear on both legs — as the path of the
upgrade request, and as a short label the client sends before the encrypted
session. It names a host; it carries no terminal data. See
[security.md](security.md).

---

## Where the shell lives

The agent owns the shells, and the shell outlives the operator's connection
but not the agent:

* the operator detaches → the shell keeps running, and its output is held
  in a bounded buffer (256 KiB) for the next operator
  (`moesh_tunnel_v2.py:114`, `:430-436`);
* the operator re-attaches → the same shell, its directory, its variables
  and its jobs (`moesh_tunnel_v2.py:641-696`);
* the agent stops → the shell is terminated with `SIGHUP` and reaped
  (`moesh_tunnel_v2.py:487-501`).

A `tmux` session inside the agent host would outlive the agent as well.
Nothing else would have to change.

---

## The client owns the local terminal

The client measures the real window size and advertises it
(`moesh_shell_v2.py:354`), keeps the local line discipline in raw mode
without `ISIG` so control characters reach the remote PTY untouched, forwards
`SIGWINCH` as an authenticated `RESIZE` record, and restores the original
terminal attributes on every exit path.

The remote PTY keeps its canonical line discipline with `ISIG` enabled, so
the destination generates `SIGINT`, `SIGTSTP` and EOF itself. No separate
remote signal protocol is invented.
