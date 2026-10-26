# Keys

`moesh` uses long-term static key pairs per side, following the standard SSH model:
the agent holds an **agent key pair**, the operator holds an **operator key pair**,
and each side pins the other's **public** half.

Alternatively, `moesh` supports **deterministic fleet identity**: a single shared
master secret derives unique per-host static keypairs via HKDF-SHA256 without
requiring individual key exchanges.

**The repository ships no keys.** Every key in this document is generated
locally, on the machine that will use it, and the private half never leaves
that machine.

---

## 1. Generate a key pair

Both programs generate keypairs using the same flags:

```sh
# On the agent host
moesh-tunnel --generate-key

# On the operator's terminal
moesh --generate-key
```

Or generate a single master key for your entire fleet:
```sh
moesh --new-master
```

Without `--keyfile`, the agent writes `~/.config/moesh/agent.key` and the
client writes `~/.config/moesh/operator.key`. Each private key gets a `.pub`
sibling:

| file | mode | content |
|---|---|---|
| `~/.config/moesh/agent.key` | `0600` | the agent's private key, as hex |
| `~/.config/moesh/agent.key.pub` | `0644` | the agent's public key, as hex |
| `~/.config/moesh/operator.key` | `0600` | the operator's private key, as hex |
| `~/.config/moesh/operator.key.pub` | `0644` | the operator's public key, as hex |

The agent logs:

```
agent static private key written to /home/you/.config/moesh/agent.key (mode 0600)
agent static public key written to /home/you/.config/moesh/agent.key.pub
agent static PUBLIC key (pin this on the operator): 96e43518ae3f781f0bcaf255be33d1383d2ac8ca722fc4eea7cdb336e83ebe7f
SHA256:rbA4PnNXQdNBisCjjd2Ksf3zdr9Hu7d/OL496Jobt7I
```

The client logs:

```
operator static private key written to /home/you/.config/moesh/operator.key (mode 0600)
operator static public key written to /home/you/.config/moesh/operator.key.pub
6d61bfaf17bda3e539ad5361013e1c09484bd28c91e95f5ef3b3d43efb62815a
SHA256:qcwOFs0GBikVBOCs3V9m+8+PDKFQtmHzQacl9M3qb0M
```

Neither program ever prints the private key.

---

## 2. Overwriting is refused by default

A stray invocation will not clobber a live key; both programs refuse to
write over an existing key file and exit with status `1`:

```
refusing to overwrite existing key: /home/you/.config/moesh/operator.key (use --force to replace)
```

Use `--force` to deliberately replace it:

```sh
moesh --generate-key --force
moesh-tunnel --generate-key --force
```

---

## 3. The fingerprint

The `SHA256:` line is an ssh-keygen-style fingerprint of the public key:
the base64-encoded SHA-256 digest without padding. It is a public checksum,
not a secret. To manually compute the fingerprint from a raw hex public key:

```sh
python3 - <<'EOF'
import base64, hashlib, pathlib
pub = pathlib.Path.home() / ".config/moesh/agent.key.pub"
raw = bytes.fromhex(pub.read_text().strip())
print("SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("="))
EOF
```

---

## 4. Deterministic Fleet Master Secret (Recommended)

Instead of generating and distributing separate key pairs for each remote host,
a fleet of hosts can be derived from a single 32-byte master secret:

```
Master Secret (32 bytes) ──▶ HKDF-SHA256(info=b"moesh-agent-key-host-<n>") ──▶ Static Key for host-<n>
```

### Deriving keys on the Operator Client

To inspect or generate a new fleet master secret and view derived keys:

```sh
python3 moesh_shell.py --new-master -n 3
```

This outputs:

```
master secret: 7f8a9b...
host host-3 public key: 4c3d2e...
SHA256:Uj8K...
```

### Configuring the Operator (`~/.config/moesh/hosts.toml`)

Set `master` at the top level of `~/.config/moesh/hosts.toml`:

```toml
prefix = "host"
master = "7f8a9b...<32-byte-hex-master-secret>"
```

The operator client now automatically derives and pins the expected static public
key for any host number specified on the command line (`-n 1` .. `-n 10`).

### Configuring the Agent Host

Provide `MOESH_TUNNEL_MASTER` in the agent's environment:

```sh
export MOESH_TUNNEL_MASTER="7f8a9b...<32-byte-hex-master-secret>"
export MOESH_TUNNEL_HOST="3"
export MOESH_TUNNEL_OPERATOR_PUB="<operator-public-key-hex>"
python3 moesh_tunnel.py
```

`moesh_tunnel.py` derives the static private key in memory using HKDF-SHA256
bound to `host-3`. No agent key file needs to be stored on disk.

---

## 5. Dual-Key Migration & Rotation

During migration from legacy pinned keys to master-derived keys, or when rotating
fleet keys, `hosts.toml` supports simultaneous candidate verification:

```toml
prefix = "host"
master = "<new-fleet-master-secret>"
legacy_agent_pub = "<previous-pinned-agent-public-key>"

[hosts.host-3]
agent_pub = "<host-specific-override-key>"
```

### Candidate Resolution Order:
1. `[hosts.<name>].agent_pub`: Exact match for that specific host.
2. `master`: HKDF-derived static public key for `<name>`.
3. `legacy_agent_pub`: Fallback public key accepted across all hosts.

If an incoming agent connects using either the new derived key or the legacy key,
the operator client authenticates successfully. Once all remote hosts have transitioned,
remove `legacy_agent_pub` from `hosts.toml`.

---

## 6. What never leaves the machine

| secret | where it lives | how it is protected |
|---|---|---|
| agent private key | `~/.config/moesh/agent.key` or `MOESH_TUNNEL_AGENT_KEY` | mode `0600`; read from file or environment |
| operator private key | `~/.config/moesh/operator.key` | mode `0600` |
| master secret | `MOESH_TUNNEL_MASTER` (agent) / `hosts.toml` (operator) | mode `0600` or environment only |

Public keys are meant to be shared. Pin them in `hosts.toml` or `MOESH_TUNNEL_OPERATOR_PUB`
and compare fingerprints out of band.
