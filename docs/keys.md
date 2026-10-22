# Keys

`moesh` uses one long-term static key pair per side, exactly like SSH's
host keys and user keys: the agent holds an **agent key pair**, the operator
holds an **operator key pair**, and each side pins the other's **public**
half.

**The repository ships no keys.** Every key in this document is generated
locally, on the machine that will use it, and the private half never leaves
that machine.

## Generate a key pair

Both programs generate a pair the same way.

```sh
# the agent host
python3 moesh_tunnel_v2.py --generate-key

# the operator's terminal
python3 moesh_shell_v2.py --generate-key
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

The agent prints:

```
agent static private key written to /home/you/.config/moesh/agent.key (mode 0600)
agent static public key written to /home/you/.config/moesh/agent.key.pub
agent static PUBLIC key (pin this on the receiver): 96e43518ae3f781f0bcaf255be33d1383d2ac8ca722fc4eea7cdb336e83ebe7f
SHA256:rbA4PnNXQdNBisCjjd2Ksf3zdr9Hu7d/OL496Jobt7I
```

The client prints the public half and the fingerprint:

```
6d61bfaf17bda3e539ad5361013e1c09484bd28c91e95f5ef3b3d43efb62815a
SHA256:qcwOFs0GBikVBOCs3V9m+8+PDKFQtmHzQacl9M3qb0M
```

Neither program prints the private key.

## Overwriting is refused by default

A stray invocation must not clobber a live key, so both programs refuse to
write over an existing key file (or its `.pub`) and exit with status `1`:

```
refusing to overwrite existing key: /home/you/.config/moesh/operator.key (use --force to replace)
```

`--force` replaces it:

```sh
python3 moesh_shell_v2.py --generate-key --force
python3 moesh_tunnel_v2.py --generate-key --force
```

Use a different location instead if you want to keep the old pair:

```sh
python3 moesh_shell_v2.py --generate-key --keyfile ~/.config/moesh/operator-2.key
```

## The fingerprint

The `SHA256:` line is the ssh-keygen-style fingerprint of the public key:
base64 of the SHA-256 digest, without padding. It is a checksum, not a
secret — compare it over a channel you already trust, to confirm that the
key you were given is the key you were sent.

The `.pub` file holds a bare hex key, not an OpenSSH key file, so
`ssh-keygen -l` cannot read it. To recompute the fingerprint from a file:

```sh
python3 - <<'EOF'
import base64, hashlib, pathlib
pub = pathlib.Path.home() / ".config/moesh/agent.key.pub"
raw = bytes.fromhex(pub.read_text().strip())
print("SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("="))
EOF
```

## Pin the agent's public half (on the operator's machine)

The client keeps one pin per host in `~/.config/moesh/hosts.toml`:

```toml
prefix = "host"

[hosts.host-3]
agent_pub = "<the agent's public half>"
```

`prefix` is optional and defaults to `host`; the number is what the operator
types (`-n 3` → `host-3`). The pin is the hex from `agent.key.pub`, with or
without a leading `0x`.

The client refuses to attach to a host that has no pin:

```
no pin for host 'host-3' in /home/you/.config/moesh/hosts.toml (known: default)
```

Set the pins file elsewhere with `MOESH_SHELL_V2_HOSTS_FILE`.

A single-host deployment does not need a pins file at all: with no
`[hosts]` section, the client reads the agent's public key from
`~/.config/moesh/agent.pub` (`MOESH_SHELL_V2_PEER_PUBFILE`).

## Provision the operator's public half (on the agent host)

The agent needs the operator's public key before it will start. Give it as
hex, in the environment:

```sh
export MOESH_TUNNEL_V2_OPERATOR_PUB=<the operator's public half>
python3 moesh_tunnel_v2.py
```

The agent's own private key is read from a file or from the environment:

```sh
export MOESH_TUNNEL_V2_AGENT_KEYFILE=$HOME/.config/moesh/agent.key
python3 moesh_tunnel_v2.py
```

The agent refuses to start without a key and without the operator's pin —
both are read before the first connection is made.

## Rotation

Rotating one side is two steps and one restart.

```sh
# 1. make the new pair
python3 moesh_tunnel_v2.py --generate-key --force

# 2. copy the new public half to the operator and put it in hosts.toml
#    (the agent's fingerprint changes with it)

# 3. restart the agent; it serves the new key on the next connection
systemctl restart moesh-agent
```

Rotating the operator is the mirror image: generate a new operator pair, put
the new public half into `MOESH_TUNNEL_V2_OPERATOR_PUB` on the agent host and
restart the agent.

The old private key is worthless once both sides have moved: the pin is
checked during the handshake, so a session with the old key is refused before
a shell exists.

## The master-secret alternative

Instead of a key pair per host, a host can be derived from a shared master
secret. The agent derives its static key from `MOESH_TUNNEL_V2_MASTER`, and
the client can be given the same secret:

```toml
[hosts.host-3]
master = "<64 hex characters>"
```

`python3 moesh_shell_v2.py --new-master -n 3` prints a fresh master secret
together with the public key it derives for that host. The master secret is
a private key in every sense: it must travel over a channel you trust, and
anyone holding it can impersonate that host.

Use the key-pair flow above unless you need one number to cover many hosts;
the pairs are easier to rotate one at a time.

## What never leaves the machine

| secret | where it lives | how it is protected |
|---|---|---|
| agent private key | `~/.config/moesh/agent.key` or `MOESH_TUNNEL_V2_AGENT_KEY` | mode `0600`; read from the environment or a file, never from a command line |
| operator private key | `~/.config/moesh/operator.key` | mode `0600` |
| master secret | `MOESH_TUNNEL_V2_MASTER` | environment only |

Public halves are meant to travel. Pin them over a channel you already
trust — the fingerprint is there so you can check what arrived.
