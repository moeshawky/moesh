# Security

`moesh` protects one thing well: the contents of a terminal session between
your machine and the agent host. This page says what that means, and what it
does not mean.

---

## The design in one paragraph

The receiver is a **blind byte pump**. After the HTTP upgrade it copies bytes
in both directions and never interprets them. It holds no keys, decrypts
nothing, and logs no terminal bytes. The encryption lives in the session
between the operator's client and the agent host, so the receiver is not in
the trust path for your terminal data.

---

## What is protected

### The session is encrypted end to end

| property | value |
|---|---|
| pattern | `Noise_XX_25519_ChaChaPoly_BLAKE2s` |
| roles | the operator's client is the initiator, the agent is the responder |
| key exchange | X25519, ephemeral per connection |
| transport | ChaCha20-Poly1305 |

The handshake is fresh on every connection, so a record captured from one
session does not decrypt in another. The prologue is fixed and binds the
protocol identity and its major version to the handshake: a peer speaking
something else fails the handshake rather than being downgraded to a
plaintext path. There is no plaintext fallback anywhere in the code.

Both legs are covered. The client speaks Noise to the agent *through* the
bridge, so neither the bridge nor the network between them sees the
terminal.

### Identities are pinned

Each side pins the other's public key, and the pin is checked during the
handshake, before any terminal data is accepted:

* the operator's client pins the agent's key per host, in
  `~/.config/moesh/hosts.toml` (`moesh_shell_v2.py:177-229`);
* the agent pins the operator's key (`moesh_tunnel_v2.py:172-196`).

A mismatch aborts the session with an authentication error, before a shell
exists. Noise XX transmits the peer's static key encrypted, and the library
overwrites any pre-set remote static with the one learned from the
handshake, so the pin is enforced by the application rather than by the
library.

### Keys stay put

Private keys are written with mode `0600`, are never printed, and are never
passed on a command line. The repository ships no keys; every key is
generated locally. See [keys.md](keys.md).

---

## What the receiver can see

Being blind does not mean being blind to everything. The receiver, and
anyone watching the same network, can observe:

* **the host name, in the clear.** The operator's client names the host it
  wants before the encrypted session starts
  (`moesh_shell_v2.py:792`), and the agent puts the same name in the path of
  its upgrade request (`moesh_tunnel_v2.py:270`). Both are routing labels,
  not terminal content — but they are readable by the receiver.
* **the ciphertext**, its length, and its timing.
* **the volume of traffic**, which says something about how busy the session
  is.

The terminal's contents are none of these.

---

## What it does not protect against

### A compromised endpoint

The security of a session is the security of its two ends. If the operator's
machine or the agent host is compromised, the attacker has the shell — and,
on the agent host, the agent's private key. The receiver's blindness does
not help there: a compromised agent host can serve whatever it likes.

The shell runs as the account the agent runs as. Run the agent under a
dedicated account.

### Traffic analysis

As above: the host name is visible, and so is the shape of the traffic.
`moesh` does not pad, does not mix, and does not hide timing. It is not a
tool for concealing that a session exists.

### Denial of service against the receiver

The receiver pairs connections **first-in, first-out and without
authenticating them** (`moesh-bridge.py:298-324`). It cannot tell a real
operator from a probe, so:

* **Do not test the operator port with a plain connection.** The receiver
  pairs *any* connection with a queued tunnel, so a test connection consumes
  one and the real operator waits for the next one. Read the receiver's log
  instead — it reports every pairing.
* The queue holds eight tunnels per host (`moesh-bridge.py:90`); a ninth is
  refused.
* An operator connection waits up to 120 seconds for a host to appear
  (`moesh-bridge.py:390`) before it is dropped, and a tunnel waits the same
  for an operator (`moesh-bridge.py:202`).
* Anyone who can reach the operator port can stall an attach. The key pin
  still stops them from getting a shell.

Keep the operator port on a private interface or behind a forwarded port, and
let the firewall do the rest.

### A static key compromised later

Noise_XX provides forward secrecy against subsequent passive compromise of static keys:
ephemeral Diffie-Hellman keys (`e`) are generated freshly for each session and mixed into
the chaining key (`ee`), so recorded session ciphertext cannot be decrypted using static
keys alone if ephemeral secrets were erased. However, active adversary compromise of a static
key enables future session impersonation. Rotating a static key revokes trust for new sessions.

### Key distribution

`moesh` does not distribute keys for you. The public halves travel over
whatever channel you choose. Anyone who can substitute a `.pub` half can
impersonate that host, so pin keys over a channel you already trust and
compare the `SHA256:` fingerprint out of band.

---

## Practical advice

* Keep the operator port off the public internet.
* Pin both sides; never run with a pin you did not check.
* Check the fingerprint when a key changes.
* Run the agent as a dedicated, unprivileged account.
* Rotate keys when the machine they live on is rebuilt or handed over.
* Read the receiver's log to check liveness — never by connecting to the
  operator port.
