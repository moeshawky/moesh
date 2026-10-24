# moesh — protocol specification

Encrypted interactive PTY tunnel between an operator terminal and an agent
host, carried over the existing HTTP/1.1 Upgrade path.

Status: implemented. Every wire constant below lives authoritatively in `moesh_wire.py`
and `moesh_proto.py`. The endpoints re-declare a few of them: the receiver bridge is
standard-library only and cannot import third-party modules, and the agent and client
carry local copies of host defaults. The test `INT-005` in `tests/test_operator_outcome.py`
checks this and is marked as a known deviation, so the claim is measured rather than assumed.

---

## 1. Topology

```
operator terminal ──TCP 127.0.0.1:44441──▶ moesh-bridge.py ──TCP/80──▶ nginx
(or moecp client)                                 │                      │
                                                  │                      ▼
                                                  └────▶ agent host
                                                          (Noise responder,
                                                           PTY + bash)
```

* The agent host dials **out**; it never listens on a public interface, and
  there is no inbound terminal endpoint to attack anywhere in the design.
* The bridge is a **blind byte broker**: after the 101 Switching Protocols response
  it copies bytes in both directions and never interprets them. It therefore never
  holds plaintext terminal or file data. The documented exception is the operator
  prelude: an operator sends a short plaintext routing label (`host: <name>\n` or
  `MOESH-TUNNEL-V2 <name>\n`) to select the host queue, which the bridge parses
  before switching to blind forwarding. This label carries no terminal data and
  never leaves the receiver host.
* nginx passes the `Upgrade` token through verbatim
  (`proxy_set_header Upgrade $http_upgrade`), which is why custom tokens need
  no nginx code changes. The *route* requires proxy configuration: an nginx
  fronting a deployment proxies `/__moesh/tunnel` to the bridge's tunnel port,
  and `/__relay/<service>` routes to the same bridge port.
* The reverse service relays (`/__relay/<service>`, configured via `MOESH_RELAYS`)
  allow remote compute sidecars (vLLM, GPU runners, embeddings) to expose TCP
  listeners on the receiver without inbound ports on the accelerator machine.

---

## 2. Upgrade handshake (not a WebSocket)

The agent sends:

```http
GET /__moesh/tunnel HTTP/1.1
Host: <receiver>
Upgrade: moesh-tunnel-v2
Connection: Upgrade
X-Moesh-Tunnel-Version: 2
```

The receiver answers:

```http
HTTP/1.1 101 Switching Protocols
Upgrade: moesh-tunnel-v2
Connection: Upgrade
X-Moesh-Tunnel-Version: 2
X-Moesh-Tunnel-Name: <host>
```

The token is custom on purpose. The connection carries **no** RFC 6455
framing, so advertising `websocket` would be false. The agent refuses a
response whose `Upgrade` token is not `moesh-tunnel-v2`; there is no fallback
to the legacy v1 path.

---

## 3. Cryptography

| Property | Value |
|---|---|
| Protocol | `Noise_XX_25519_ChaChaPoly_BLAKE2s` |
| Roles | operator = **initiator**, agent = **responder** |
| Implementation | `noiseprotocol==0.3.1` (import name `noise`), `cryptography` backend |
| Prologue | `moesh-tunnel-v2/2/noise_xx_25519_chachapoly_blake2s` (fixed) |
| Key exchange | X25519, ephemeral per connection |
| Transport | ChaCha20-Poly1305, Noise transport messages (implicit nonces) |

* **Static pinning.** Noise XX transmits the peer's static key encrypted.
  `noiseprotocol` overwrites any pre-set remote static with the value learned
  from the handshake (`noise/state.py:381`), so `set_remote_static_key` cannot
  enforce pinning in XX. Pinning is therefore enforced in application logic:
  the static key learned from the handshake is compared against the pin
  *before the first transport record is accepted*, on both sides
  (initiator after message 2, responder after message 3). A mismatch aborts
  the session with `AuthenticationError`.
* **Fresh state per connection.** A new handshake is performed for every
  transport connection; the handshake hash and the transport keys differ
  between sessions, so a record captured from another session does not decrypt.
* **No downgrade.** The prologue binds the protocol identity and its major
  version to the handshake. A peer using another prologue fails at message 2
  with `InvalidTag`. A peer using another protocol version is refused in
  HELLO. There is no plaintext fallback in any code path.
* **The broker is blind.** The bridge sees only ciphertext; tests verify that
  captured wire bytes contain no terminal plaintext and that a third key pair
  cannot decrypt them.

---

## 4. Framing

Every byte on the wire belongs to exactly one frame:

```
uint32_be(ciphertext_length) || ciphertext
```

The same framing carries the three Noise handshake messages and every
transport record; the phases never interleave.

* `MAX_CIPHERTEXT = 65535` (Noise `MAX_MESSAGE_LEN`).
* A zero-length frame or a frame above the bound is refused immediately.
* A frame split across reads is reassembled; multiple frames in one read
  buffer are sequentially processed.

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

`DATA` payloads are binary-safe terminal or file transfer bytes and are never
reinterpreted. Control payloads are compact JSON, at most 4096 bytes
(`MAX_CONTROL_PAYLOAD`); a `DATA` payload is at most 32768 bytes (`MAX_DATA_PAYLOAD`).

---

## 5. Negotiation

HELLO (operator):

```json
{
  "version": 2,
  "term": "xterm-256color",
  "encoding": "utf-8",
  "rows": 24,
  "cols": 80,
  "capabilities": ["resize", "ping"],
  "max_record": 32768,
  "handshake_hash": "<hex>"
}
```

The agent validates every value (version, terminal type without control
characters, `utf-8` encoding, 1 ≤ rows ≤ 1000, 1 ≤ cols ≤ 1000,
`max_record` ≥ 256) and answers with ACCEPT carrying the accepted
configuration. The operator's `handshake_hash` is compared with the agent's
own handshake hash, binding negotiation to the authenticated transcript.

Two optional fields carry the session policy:

* `fresh_session` (HELLO, default `false`) — when `true`, the agent allocates
  a **fresh** unshared shell process instead of re-attaching to a running one.
  This is used by `moesh-shell --fresh` and exclusively by `moecp` for isolated
  file transfers.
* `resumed` (ACCEPT, always present) — the agent answers `true` when it is
  re-attaching to the shell that survived a previous disconnect.

ACCEPT → READY (operator) → READY (agent) → the session is ACTIVE.

---

## 6. States

```
CONNECTED → AUTHENTICATED → NEGOTIATING → READY → ACTIVE → CLOSING
```

Transitions are checked; an unlisted transition raises `StateError` and the
session fails closed. No PTY is created and no terminal byte is forwarded
before the session is ACTIVE.

---

## 7. Signals and line discipline

* The operator's local terminal is put in raw mode **without** `ISIG`, so
  Ctrl+C (`0x03`), Ctrl+Z (`0x1a`) and Ctrl+D (`0x04`) travel to the remote
  PTY as bytes.
* The remote PTY keeps its canonical line discipline with `ISIG` enabled, so
  the destination generates `SIGINT`, `SIGTSTP` and EOF itself. No separate
  remote signal protocol exists.
* The operator's original terminal attributes are restored on every exit path
  (normal end, exception, `SIGINT`, `SIGTERM`, `SIGHUP`).

---

## 8. Lifecycle

* The **agent process** is long-lived: it redials after transport loss
  (2 s, doubling to a 30 s ceiling). An authentication failure is not a
  network loss: it logs `AUTHENTICATION FAILED` and waits 60 s instead of
  retrying in a loop.
* The **shell survives disconnects.** When an operator detaches, the
  interactive Bash keeps running: its working directory, variables, and
  background jobs are preserved. The next operator attaches to the same shell
  and receives buffered output. An operator or tool wanting an isolated shell
  requests one with `fresh_session`.
* While no operator is attached the shell is drained into a bounded ring buffer
  of 256 KiB. Older output is dropped when the buffer is full, preventing
  unbounded memory growth.
* An abrupt transport EOF is reported as an abrupt EOF; an authenticated
  CLOSE record is reported as a graceful close.
* `SIGTERM` and `SIGINT` stop the agent: active shells are terminated with
  `SIGHUP` and reaped, sockets are closed, and the agent exits.

---

## 9. Receiver bridge

The bridge keeps three distinct queue structures:

| Queue | Filled by | Drained by |
|---|---|---|
| `_shell` | `Upgrade: websocket` on `/__tunnel/v1` (legacy v1) | operator port 44440 |
| `_shell_v2` | `Upgrade: moesh-tunnel-v2` on `/__moesh/tunnel` | operator port 44441 (used by `moesh_shell` and `moecp`) |
| `_relays[service]` | `Upgrade: moesh-tunnel-v2` or `websocket` on `/__relay/<service>` | Dedicated TCP listening ports configured via `MOESH_RELAYS` |

Separate queues ensure an encrypted v2 operator cannot be paired with a v1 tunnel.
`MOESH_BRIDGE_ALLOW_V1=0` refuses the legacy v1 shell path while leaving v2 and reverse relays untouched.

Environment knobs: `MOESH_BRIDGE_TUNNEL_LISTEN`, `MOESH_BRIDGE_OPERATOR_LISTEN`,
`MOESH_BRIDGE_OPERATOR_V2_LISTEN`, `MOESH_RELAYS`, `MOESH_BRIDGE_GPU_PORTS`, `MOESH_BRIDGE_ALLOW_V1`.

---

## 10. Agent-side entry contract

Whatever runs the agent on the target host (systemd, container, or script) has this contract:

* Re-running the entry stops the previous agent **by PID** (from pid file or exact `/proc` match),
  waits for it to exit, and starts the new one. The old agent terminates its shell on exit, preventing
  orphan processes.
* Stopping or interrupting the entry leaves the agent running in its own session if detached.
* The postcondition is the log line `upgraded` in the agent log.

---

## 11. Known limits

* The bridge pairs FIFO and does not authenticate: an unauthenticated peer can
  consume one queued tunnel (it is immediately refused by the subsequent Noise handshake).
* The agent's static private key (or fleet master secret) must reach the agent host
  through a secure provisioning channel. The code reads it from environment or file.
* The operator's private key may live on the same host as the bridge. The invariant
  that matters — the *receiver* holds no plaintext — holds regardless.
