# Security Policy

## Reporting a vulnerability

Please report security problems **privately**, not in a public issue.

Use the repository's private vulnerability reporting form:

> https://github.com/moeshawky/moesh/security/advisories/new

If that form is not available to you, open an issue that says only that you
would like a private channel to discuss a security report, and leave the
details out of it. Do not put exploit details, keys or host names in a public
issue.

### What to include

* what you found, and what an attacker gains;
* how to reproduce it — the exact commands, the version or commit you tested;
* the impact you measured, not the impact you imagine.

### What to leave out

* **No private keys, ever.** Not yours, not anyone's.
* No real host names, addresses or customer data. `moesh` ships no keys and
  expects you to generate your own locally, so a reproduction only needs
  freshly generated pairs.

### Where to test

Only on machines you own or have permission to test. The receiver pairs
connections without authenticating them, so an unintended connection to an
operator port consumes a queued tunnel and disturbs whoever is using it.

## No keys are shipped

This repository contains **no keys**. Every key pair is generated locally, on
the machine that will use it:

```sh
moesh-tunnel --generate-key   # the agent
moesh --generate-key          # the operator
```

From a source checkout the same two commands are
`python3 moesh_tunnel.py --generate-key` and
`python3 moesh_shell.py --generate-key`.

Private keys are written with mode `0600`, are never printed, and never
leave the host that generated them. Only the public half is meant to travel,
and each side pins the other's public half by hand. See
[docs/keys.md](docs/keys.md).

If you find a private key committed in this repository, or in any history of
it, treat it as compromised: report it privately and rotate the key on every
host that used it.

## Supported versions

`moesh` is pre-1.0. There is no stable release series yet, so the only
supported version is the current tree:

| version | supported |
|---|---|
| the current tree | yes |
| anything older | no |

## Support statement

There is no support commitment, no response time and no service level for
this project while it is pre-1.0. Reports are read and acted on as time
allows, and behaviour may change without a deprecation period between minor
releases.

The security model — what `moesh` protects and what it does not — is written
down in [docs/security.md](docs/security.md). In short: the receiver is a
blind byte pump and never holds plaintext terminal data; the two ends pin
each other's static keys; and the tool does not defend against a compromised
endpoint, traffic analysis, or denial of service against the receiver.