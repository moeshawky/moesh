# Security

`moesh` protects terminal data, file transfers, and reverse service tunnels
across untrusted networks. This document describes the security guarantees,
threat model, and architectural boundaries.

---

## 1. The core design

The receiver is a **blind byte broker**. Following an HTTP/1.1 Upgrade, it
copies opaque bytes between TCP endpoints and never interprets them. It holds
**zero cryptographic keys**, decrypts **zero bytes**, and logs **zero terminal
or file data**. The cryptographic perimeter exists strictly between the operator's
client and the target agent host.

---

## 2. Cryptographic Guarantees

### End-to-end encryption

| property | specification |
|---|---|
| pattern | `Noise_XX_25519_ChaChaPoly_BLAKE2s` |
| roles | operator = initiator, agent = responder |
| key exchange | X25519 ephemeral Diffie-Hellman keys per connection |
| cipher | ChaCha20-Poly1305 AEAD |
| prologue | `moesh-tunnel-v2/2/noise_xx_25519_chachapoly_blake2s` |

- **Forward Secrecy:** Ephemeral keys (`e`) are freshly generated on each connection and erased upon completion. Passive recording of ciphertext cannot be decrypted if static keys are later compromised.
- **Transcript Binding:** Handshake hashes are compared during `HELLO`/`ACCEPT` negotiation, binding application parameters to the authenticated cryptographic exchange.
- **Downgrade Immunity:** Fixed prologue strings bind protocol version and cipher suite directly into the Noise handshake; peers speaking any other protocol or version fail at message 2 with an authentication error. There is no plaintext fallback.

### Mutual Identity Pinning

Both endpoints enforce strict static key pinning before transport data is accepted:

* **Operator Client:** Pins agent static keys per host in `~/.config/moesh/hosts.toml`, or derives them deterministically from `MOESH_TUNNEL_MASTER` via HKDF-SHA256 (`moesh_shell.py:228-285`).
* **Agent Host:** Pins the operator's static public key via `MOESH_TUNNEL_OPERATOR_PUB` or derives it deterministically from `MOESH_TUNNEL_MASTER` via HKDF-SHA256 (`moesh_tunnel.py:267-316`).

A key mismatch immediately terminates the connection with `AuthenticationError` before a shell or worker process is spawned.

---

## 3. Secure File Copy Hardening (`moecp`)

`moecp` implements an adversarial-grade transport layer designed to withstand
untrusted inputs and network tampering:

### Path Traversal Defenses
- **`sanitize_relpath` Enforcement:** Strips leading path separators and verifies that relative paths contain no parent directory traversals (`..`), embedded null bytes (`\0`), or Windows/POSIX drive and root indicators (`/` and `\`).
- **Filesystem Containment:** The destination root and the target are resolved
  through the real filesystem (`os.path.realpath`), the real target's parent
  must still be inside the real root, and the write is refused otherwise.  A
  lexical check alone is not sufficient: a symlinked directory component or a
  symlink at the final path name passes `abspath`/`commonpath` and then writes
  outside the root.  Staging files are created inside the resolved parent, so
  a parent-directory swap between the check and the write fails the write
  instead of redirecting it.

### Frame Length Bounds & DoS Prevention
- **Header Bounding:** Control headers are restricted to a maximum of 64 KiB (`MAX_FRAME_HDR`), preventing memory exhaustion during JSON payload decoding.
- **Payload Bounding:** Inbound transfer chunks are capped at 10 MiB (`MAX_FRAME_PAYLOAD`), defending against integer overflow and unconstrained buffer allocations.
- **Decompression Bounding:** A compressed frame is bounded *before* and
  *after* decompression, and the cumulative decoded byte count is capped by the
  file size the manifest declared.  A highly compressive payload or a
  malformed zlib stream therefore fails the transfer instead of expanding into
  unbounded memory or disk.

### Atomic Staging & Rollback
- **Staging Files:** Inbound files are written to `.part.<pid>` temporary files in the destination directory.
- **Digest Verification:** End-to-end SHA-256 digests are computed incrementally during streaming. If a digest mismatch, network drop, or corrupt zlib chunk occurs, the partial file is unlinked immediately.
- **Atomic Commit:** Files are committed using `os.replace` only after digest verification succeeds. At no point is a partial or corrupt file visible under its target filename.

### Session Isolation
- `moecp` negotiates `session_type=transfer`, which the agent serves **natively
  in-process**: no operator shell is borrowed and no child process is spawned,
  so transfer traffic cannot leak into an interactive session or its
  scrollback.  When an older agent does not offer a transfer session, `moecp`
  falls back to the compatibility path (a compressed worker pushed into a
  dedicated fresh PTY, executed in memory).  The native path is the one to
  expect against a current agent; the fallback exists so mixed fleets keep
  working.

---

## 4. Accelerator Service Reverse Relays (`moesh_relay.py`)

- **Outbound Egress Only:** Target accelerator nodes (GPUs/TPUs) make outbound TCP connections over HTTP port 80 to `/__relay/<service>`. No inbound listening ports are exposed on the compute nodes.
- **Blind Queue Splicing:** The receiver pairs reverse relays strictly by service name (e.g. `gpu`, `vllm`, `embed`) on dedicated listening ports configured via `MOESH_RELAYS`. Sockets are spliced as raw TCP streams without inspection or caching.
- **The relay is not encrypted by `moesh`, and the documentation says so:** the
  shell tunnel is Noise-encrypted end to end, but relayed traffic is the
  target service's own protocol, carried as raw TCP.  Whatever the exposed
  service protects with (TLS, application auth) is the only protection on that
  path.  Treat a relay port as a public port on the receiver: anyone who can
  reach it reaches the target service, and `moesh` adds no authentication of
  its own to the data plane.  Control-plane registration is what
  `MOESH_BRIDGE_RELAY_TOKEN` gates.

---

## 5. What the receiver and network can observe

The receiver and network observers see only:

1. **Host & Service Labels:** The routing label (e.g. `host-3`, `vllm`) transmitted during HTTP upgrade and operator prelude.
2. **Ciphertext & Lengths:** Framing lengths and encrypted payload chunks.
3. **Traffic Timing & Volume:** Transfer rates and timing patterns.

No terminal keystrokes, output text, file paths, file contents, or cryptographic private keys are visible to the receiver.

---

## 6. Threat Model & Boundaries

### What is not defended:
* **Compromised Endpoints:** If an attacker gains root or shell access on the operator machine or agent host, they possess the decrypted data and private keys on that machine. Run agents under dedicated, unprivileged accounts (`User=moesh`).
* **Traffic Analysis:** `moesh` does not pad packets to fixed sizes or inject chaff traffic. Packet timing and transfer volume are observable.
* **Denial of Service on Operator Port:** The receiver pairs operator connections FIFO without authentication (authentication happens in the Noise handshake). Anyone with network access to the operator port (`127.0.0.1:44441` by default) could consume a queued tunnel. Always keep the operator port bound to loopback or behind SSH port forwarding.
