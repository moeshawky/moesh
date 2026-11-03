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

* `MAX_CIPHERTEXT = 65535` (Noise `MAX_MESSAGE_LEN`, defined at `moesh_proto.py:129`).
* A zero-length frame or a frame above the bound is refused immediately.
* A frame split across reads is reassembled; multiple frames in one read
  buffer are sequentially processed.

### Dead Tunnel Early Rejection Marker (`PAIR_DEAD_MARKER`)

When the bridge pairs an operator socket with a tunnel whose agent worker walked
away, the bridge writes `PAIR_DEAD_MARKER` (`b"\x01MOESH_DEAD_TUNNEL\n"`, defined
at `moesh_wire.py:63`) directly to the operator socket. Because a valid Noise
handshake frame begins with a 4-byte big-endian length whose first byte is `0x00`,
the non-zero leading byte `0x01` is unambiguous against ciphertext frames. The
client reads this marker after writing its first handshake message and retries
immediately (`moesh_proto.py:294-315`, `moesh_shell.py:532-557`).

Transport record plaintext:

```
uint8(message_type) || payload
```

| Type | Name | Payload | Direction |
|---:|---|---|---|
| 1 | HELLO | JSON | operator → agent |
| 2 | ACCEPT | JSON | agent → operator |
| 3 | READY | JSON | both |
| 4 | DATA | raw terminal or stdin/stdout stream bytes | both |
| 5 | RESIZE | `uint16_be rows \|\| uint16_be cols` | operator → agent |
| 6 | EXIT | JSON `{"status": int, "signal": int\|null}` | agent → operator |
| 7 | PING | JSON `{"t": int}` | both |
| 8 | PONG | JSON `{"t": int}` | both |
| 9 | ERROR | JSON `{"code": str, "message": str}` or `{"error": str}` | both |
| 10 | CLOSE | JSON `{"reason": str}` | both |

`DATA` payloads are binary-safe terminal or streaming bytes and are never
reinterpreted. Control payloads are compact JSON, at most 4096 bytes
(`MAX_CONTROL_PAYLOAD`, `moesh_wire.py:40`); a `DATA` payload is at most 32768 bytes (`MAX_DATA_PAYLOAD`, `moesh_wire.py:36`).

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
  "handshake_hash": "<hex>",
  "session_type": "shell",
  "fresh_session": false,
  "command": null
}
```

The agent validates every value (version `2`, terminal type without control
characters, `utf-8` encoding, 1 ≤ rows ≤ 1000, 1 ≤ cols ≤ 1000,
`max_record` ≥ 256; `moesh_proto.py:681-746`) and answers with ACCEPT carrying the accepted
configuration. The operator's `handshake_hash` is compared with the agent's
own handshake hash, binding negotiation to the authenticated transcript.

Session parameters:

* `session_type` (HELLO, default `"shell"`) — selects session dispatch:
  - `"shell"`: Interactive persistent PTY session.
  - `"exec"`: Non-interactive direct execution of `command` with bidirectional stdin/stdout streaming and process group cleanup.
  - `"transfer"`: Native in-process file transfer engine served by `moecp`.
* `command` (HELLO, optional string) — command string to execute when `session_type="exec"`.
* `fresh_session` (HELLO, default `false`) — when `true`, the agent allocates
  a **fresh** unshared shell process instead of re-attaching to a running one.
* `resumed` (ACCEPT, boolean) — the agent answers `true` when re-attaching
  to a shell that survived a previous disconnect.

ACCEPT → READY (operator) → READY (agent) → the session is ACTIVE.

### Native In-Process File Transfer Subprotocol (`session_type="transfer"`)

When `session_type="transfer"` is negotiated, the authenticated Noise `Msg.DATA`
channel carries framed streaming transfer records (`moecp.py:FramedStreamClient`):

```
uint32_be(header_length) || uint32_be(payload_length) || utf8_json(metadata) || raw_payload
```

* `MAX_FRAME_HDR = 65536` (64 KiB, `moecp.py:81`).
* `MAX_FRAME_PAYLOAD = 10485760` (10 MiB, `moecp.py:85`).
* Uncompressed chunk slice: `CHUNK_SIZE = 32768` (32 KiB, `moecp.py:77`).

#### Transfer Operations (`meta["op"]`)

* **Session Initialization:** `{"direction": "PUSH" | "PULL", "target": str, "is_dir": bool}` answered with `{"status": "OK"}`.
* **File Header:** `FILE_START` with relative path, size, mode, mtime, and expected SHA-256 digest. Answered with `READY` (carrying `transfer_id` and resume `offset`) or `COMMITTED` (skipping previously verified transfers).
* **Chunk Streaming:** `CHUNK` with encoding `"raw"` or `"zlib"` containing compressed chunk payloads bounded to `MAX_DECOMPRESSED_CHUNK` (32 KiB).
* **Completion & Manifests:** `FILE_END`, `DONE`, `LIST`, and `PULL_FILE`.
* **Transport Keepalive (`PING`):** `{"op": "PING"}` with zero payload (`moecp.py:920-922`). Emitted at rate-limited intervals (`HEARTBEAT_INTERVAL = 5.0` s, `moecp.py:109`) during long disk reads (e.g. SHA-256 computation over multi-gigabyte files). Receiving a `PING` frame resets the peer's per-frame deadline (`DEFAULT_FRAME_TIMEOUT = 30.0` s, configurable via `MOECP_FRAME_TIMEOUT`, `moecp.py:105`), preventing socket timeouts during heavy disk I/O.
* **Pre-Session Digest Caching:** Local upload sources are pre-hashed before the client establishes a transport connection or consumes a tunnel. Caching `(size, mtime_ns, sha256)` ensures `FILE_START` is transmitted in `<1ms` after `INIT_ACK`, avoiding idle wait against unpatched remote daemons and preventing redundant hashing on connection retries.

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
`MOESH_BRIDGE_OPERATOR_V2_LISTEN`, `MOESH_RELAYS`, `MOESH_BRIDGE_GPU_PORTS`, `MOESH_BRIDGE_ALLOW_V1`,
`MOESH_BRIDGE_TRUSTED_PROXIES`, `MOESH_BRIDGE_TLS_CERT`, `MOESH_BRIDGE_TLS_KEY`.

### 9.1 Carrier leases and generation counters

The receiver tracks active carrier ownership for hosts and relay services to prevent split-brain collisions:

* **Carrier Identity**: Each agent or relay daemon presents a stable carrier identifier via request headers (`X-Moesh-Carrier-Id`, `X-Moesh-Relay-Id`, `X-Moesh-Tunnel-Id`). When absent, the receiver derives identity from the verified client IP. When a carrier token is presented from a non-trusted IP, the bridge scopes the token as `<carrier>@<peer_ip>` to ensure distinct hosts sharing a cloned image or machine ID cannot collide.
* **Lease Acquisition & Retention**: A carrier acquires an exclusive lease on a service name or numeric port when dialing standby tunnels. An existing lease remains active while either queued tunnels or active pairings exist.
* **Generation Counters (`_lease_gens`)**: Every service or host maintains a strictly increasing monotonic generation counter. When ownership changes, the counter increments. Each queued tunnel carries the generation under which it was admitted (`entry.gen`). If a previous owner's stale socket remains in the queue when a new owner takes over, generation matching ensures the stale socket is discarded and never paired with traffic meant for the new carrier.
* **Queue Invariant**: On `queue.Full`, admission fails cleanly without corrupting existing leases or prematurely advancing generation counters. Dead sockets belonging to the same carrier are purged during refresh.

### 9.2 Proxy trust boundaries and 409 Conflict handling

* **Trust Boundaries (`TRUSTED_PROXIES`)**: Forwarded client IP headers (`CF-Connecting-IP`, `X-Real-IP`, `X-Forwarded-For`) are accepted exclusively when the immediate TCP peer address is present in `TRUSTED_PROXIES` (configured via `MOESH_BRIDGE_TRUSTED_PROXIES`, defaulting to loopback `127.0.0.1,::1,::ffff:127.0.0.1`). Untrusted direct connections attempting to send spoofed IP headers are evaluated using their raw socket peer address.
* **409 Conflict Responses**: When a carrier attempts to claim a service or port currently held by an active carrier with a different identity, the bridge refuses admission with HTTP `409 Conflict`. The response body includes diagnostic details (e.g. current lease holder, duration held, and a list of currently free relay ports).
* **Worker Backoff**: Competing workers receiving HTTP 409 do not abort immediately; they log the collision, respect the incident claim wait window, and back off (sleeping 1.5s between retries) without evicting the legitimate incumbent. If the incumbent exits, the standby queue empties, freeing the port lease for the waiting worker.

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
