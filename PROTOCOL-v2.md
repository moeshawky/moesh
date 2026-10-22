# moesh v2 — protocol specification

Encrypted interactive PTY tunnel between an operator terminal and an agent
host, carried over the existing HTTP/1.1 Upgrade path.

Status: implemented. Every wire constant below lives in `moesh_proto_v2.py`.
The endpoints re-declare a few of them: the receiver bridge is
standard-library only and cannot import the module, and the agent and the
client still carry local copies of the host defaults. The test `INT-005`
in `tests/test_operator_outcome.py` checks this and is marked as a known
deviation, so the claim is measured rather than assumed.

---

## 1. Topology

```
operator terminal ──TCP 127.0.0.1:44441──▶ moesh-bridge.py ──TCP/80──▶ nginx
                                                  │                      │
                                                  │                      ▼
                                                  └────▶ agent host
                                                          (Noise responder,
                                                           PTY + bash)
```

* The agent host dials **out**; it never listens on a public interface, and
  there is no inbound terminal endpoint to attack anywhere in the design.
* The bridge is a **blind byte broker**: after the 101 it copies bytes in both
  directions and never interprets them.  It therefore never holds plaintext
  terminal data.
* nginx passes the `Upgrade` token through verbatim
  (`proxy_set_header Upgrade $http_upgrade`), which is why a custom token
  needs no nginx change.  The *route* does need one: an nginx fronting a
  deployment must proxy `/__moesh/tunnel` to the bridge's tunnel port; the
  legacy routes `/__tunnel/v1` and `/__relay/gpu` are kept beside it.
* The gpu relay (`/__relay/gpu`, ports 26420-26430) is untouched by this
  protocol: it keeps the `websocket` token and the v1 queue.

## 2. Upgrade handshake (not a WebSocket)

The agent sends:

```
GET /__moesh/tunnel HTTP/1.1
Host: <receiver>
Upgrade: moesh-tunnel-v2
Connection: Upgrade
X-Moesh-Tunnel-Version: 2
```

The receiver answers:

```
HTTP/1.1 101 Switching Protocols
Upgrade: moesh-tunnel-v2
Connection: Upgrade
X-Moesh-Tunnel-Version: 2
X-Moesh-Tunnel-Name: <host>
```

The token is custom on purpose.  The connection carries **no** RFC 6455
framing, so advertising `websocket` would be false.  The agent refuses a
response whose `Upgrade` token is not `moesh-tunnel-v2`; there is no fallback to
the v1 path.

## 3. Cryptography

| Property | Value |
|---|---|
| Protocol | `Noise_XX_25519_ChaChaPoly_BLAKE2s` |
| Roles | operator = **initiator**, agent = **responder** |
| Implementation | `noiseprotocol==0.3.1` (import name `noise`), `cryptography` backend |
| Prologue | `moesh-tunnel-v2/1/noise_xx_25519_chachapoly_blake2s` (fixed) |
| Key exchange | X25519, ephemeral per connection |
| Transport | ChaCha20-Poly1305, Noise transport messages (implicit nonces) |

* **Static pinning.**  Noise XX transmits the peer's static key encrypted.
  `noiseprotocol` overwrites any pre-set remote static with the value learned
  from the handshake (`noise/state.py:381`), so `set_remote_static_key` cannot
  enforce pinning in XX.  Pinning is therefore enforced in the application:
  the static key learned from the handshake is compared against the pin
  *before the first transport record is accepted*, on both sides
  (initiator after message 2, responder after message 3).  A mismatch aborts
  the session with `AuthenticationError`.
* **Fresh state per connection.**  A new handshake is performed for every
  transport connection; the handshake hash and the transport keys differ
  between sessions, so a record from another session does not decrypt.
* **No downgrade.**  The prologue binds the protocol identity and its major
  version to the handshake.  A peer using another prologue fails at message 2
  with `InvalidTag`.  A peer using another protocol version is refused in
  HELLO.  There is no plaintext fallback in any code path.
* **The broker is blind.**  The bridge sees only ciphertext; the tests assert
  that the captured wire bytes contain no terminal plaintext and that a third
  key pair cannot decrypt them.

## 4. Framing

Every byte on the wire belongs to exactly one frame:

```
uint32_be(ciphertext_length) || ciphertext
```

The same framing carries the three Noise handshake messages and every
transport record; the phases never interleave.

* `MAX_CIPHERTEXT = 65535` (Noise `MAX_MESSAGE_LEN`).
* A zero-length frame or a frame above the bound is refused immediately.
* A frame split across reads is reassembled; several frames in one read are
  all processed.

Transport record plaintext:

```
uint8(message_type) || payload
```

| Type | Name | Payload | Direction |
|---:|---|---|---|
| 1 | HELLO | JSON | operator → agent |
| 2 | ACCEPT | JSON | agent → operator |
| 3 | READY | JSON | both |
| 4 | DATA | raw terminal bytes | both |
| 5 | RESIZE | `uint16_be rows \|\| uint16_be cols` | operator → agent |
| 6 | EXIT | JSON `{"status": int, "signal": int\|null}` | agent → operator |
| 7 | PING | JSON `{"t": int}` | both |
| 8 | PONG | JSON `{"t": int}` | both |
| 9 | ERROR | JSON `{"code": str, "message": str}` | both |
| 10 | CLOSE | JSON `{"reason": str}` | both |

`DATA` payloads are binary-safe terminal bytes and are never reinterpreted.
Control payloads are compact JSON, at most 4096 bytes; a `DATA` payload is at
most 32768 bytes.

## 5. Negotiation

HELLO (operator):

```json
{"version": 2, "term": "xterm-256color", "encoding": "utf-8",
 "rows": 24, "cols": 80, "capabilities": ["resize", "ping"],
 "max_record": 32768, "handshake_hash": "<hex>"}
```

The agent validates every value (version, terminal type without control
characters, `utf-8` encoding, 1 ≤ rows ≤ 1000, 1 ≤ cols ≤ 1000,
`max_record` ≥ 256) and answers with ACCEPT carrying the accepted
configuration.  The operator's `handshake_hash` is compared with the agent's
own handshake hash, which binds the negotiation to the authenticated
transcript.

Two optional fields carry the session policy:

* `fresh_session` (HELLO, default `false`) — the operator asks for a **new**
  shell instead of re-attaching to the running one.
* `resumed` (ACCEPT, always present) — the agent answers `true` when it is
  re-attaching to the shell that survived the previous disconnect.

ACCEPT → READY (operator) → READY (agent) → the session is ACTIVE.

Terminal dimensions are authoritative for the remote PTY: the agent applies
them with `TIOCSWINSZ`, and the kernel raises the usual `SIGWINCH` in the
remote foreground process group.  A later RESIZE applies the same way,
without reconnecting.

## 6. States

```
CONNECTED → AUTHENTICATED → NEGOTIATING → READY → ACTIVE → CLOSING
```

Transitions are checked; an unlisted transition raises `StateError` and the
session fails closed.  No PTY is created and no terminal byte is forwarded
before the session is ACTIVE.

## 7. Signals and the line discipline

* The operator's local terminal is put in raw mode **without** `ISIG`, so
  Ctrl+C (`0x03`), Ctrl+Z (`0x1a`) and Ctrl+D (`0x04`) travel to the remote
  PTY as bytes.
* The remote PTY keeps its canonical line discipline with `ISIG` enabled, so
  the destination generates `SIGINT`, `SIGTSTP` and EOF itself.  No separate
  remote signal protocol exists.
* The operator's original terminal attributes are restored on every exit path
  (normal end, exception, `SIGINT`, `SIGTERM`, `SIGHUP`).

## 8. Lifecycle

* The **agent process** is long-lived: it redials after a transport loss
  (2 s, doubling to a 30 s ceiling).  An authentication failure is not a
  network loss: it logs `AUTHENTICATION FAILED` and waits 60 s instead of
  retrying in a loop.
* The **shell survives disconnects.**  When an operator detaches, the
  interactive Bash keeps running: its working directory, its variables and its
  background jobs are exactly as they were.  The next operator attaches to the
  same shell and receives the output produced while nobody was attached.  The
  agent sends a newline to the PTY on attach, so the shell draws a fresh
  prompt instead of leaving a blank screen.  An operator that wants a clean
  shell asks for one with `fresh_session` (`moesh-shell-v2 --fresh`).
* While no operator is attached the shell is still drained, into a bounded
  buffer of 256 KiB.  Older output is dropped when the buffer is full, and
  the drop is logged, so a chatty job cannot block the PTY and cannot grow
  memory without bound.
* An abrupt transport EOF is reported as an abrupt EOF; an authenticated
  CLOSE record is reported as a graceful close.  The two are distinguishable
  in the logs and in the exit path.
* `SIGTERM` and `SIGINT` stop the agent: the shell is terminated with
  `SIGHUP` and reaped, the socket is closed and the agent exits.  The signal
  handler raises, because a handler that only sets a flag would be ignored
  while the agent waits in a blocking read (PEP 475 restarts the syscall).

## 9. Receiver bridge

The bridge keeps three queues:

| Queue | Filled by | Drained by |
|---|---|---|
| `_shell` | `Upgrade: websocket` on `/__tunnel/v1` (v1) | operator port 44440 |
| `_shell_v2` | `Upgrade: moesh-tunnel-v2` on `/__moesh/tunnel` | operator port 44441 |
| `_gpu` | `Upgrade: websocket` on `/__relay/gpu` | public ports 26420-26430 |

Separate queues mean a v2 operator can never be paired with a v1 tunnel and
vice versa.  `MOESH_BRIDGE_ALLOW_V1=0` refuses the v1 **shell** path only; the
gpu relay is unaffected.

Environment knobs (all optional): `MOESH_BRIDGE_TUNNEL_LISTEN`,
`MOESH_BRIDGE_OPERATOR_LISTEN`, `MOESH_BRIDGE_OPERATOR_V2_LISTEN`,
`MOESH_BRIDGE_GPU_PORTS`, `MOESH_BRIDGE_ALLOW_V1`.

## 10. Agent-side entry contract

Whatever runs the agent on the agent host — a container, a VM, or a bare-metal
host, a systemd unit, a wrapper script — has this stop-and-rerun contract:

* Re-running the entry stops the previous agent **by PID** (the pid file, plus
  an exact `/proc` match on the agent's script path — never a command-line
  pattern that could match the entry itself), waits for it to exit, and only
  then starts the new one.  The old agent terminates its shell on the way
  out, so no orphan Bash survives and no stale tunnel can shadow the new one.
* Stopping or interrupting the entry leaves the agent running: it lives in its
  own session.  The tunnel stays up.  (A separate keepalive component, if the
  entry has one, can be stopped without touching the agent.)
* The postcondition is the log line `upgraded` in `moesh_tunnel_v2.log`, not a
  live process.

## 11. Known limits

* The bridge pairs FIFO and does not authenticate: an unauthenticated peer can
  consume one queued tunnel (it is then refused by the Noise handshake).  This
  is inherited from v1 and is unchanged by this work.
* The agent's static private key must reach the agent host through the
  operator's chosen secret channel.  The code reads it from the environment
  (`MOESH_TUNNEL_V2_AGENT_KEY`) or from a file
  (`MOESH_TUNNEL_V2_AGENT_KEYFILE`) and refuses to run without it.
* The operator's private key may live on the same host as the bridge.  The
  invariant that matters here — the *receiver* holds no plaintext — holds
  regardless; a compromised host loses both keys.
