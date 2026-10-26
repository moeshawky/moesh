# moesh — wire protocol constants and defaults
# Pure Python, standard library only, zero external dependencies.
"""Central wire protocol constants and shared configuration defaults.

Authoritative definitions for framing bounds, route paths, upgrade tokens,
and protocol versions across all moesh components (bridge, agent, shell).
"""

from __future__ import annotations

# Integer major protocol version for moesh v2; both peers must agree on this value during tunnel setup.
PROTOCOL_VERSION: int = 2
"""Major protocol version for moesh v2."""

# Custom HTTP/1.1 Upgrade header value requesting the encrypted v2 tunnel; it identifies the protocol, not a secret.
UPGRADE_TOKEN: str = "moesh-tunnel-v2"  # noqa: S105 - HTTP header upgrade token, not a secret
"""Custom HTTP/1.1 Upgrade header token for v2 encrypted tunnel."""

# Routing label prelude prefix sent by the operator to the receiver before the Noise session; includes the trailing space.
PRELUDE_PREFIX: bytes = b"MOESH-TUNNEL-V2 "
"""Routing label prelude prefix sent by operator to receiver before Noise session."""

# Canonical HTTP request path used for v2 tunnel upgrade requests.
TUNNEL_PATH: str = "/__moesh/tunnel"
"""HTTP request path for v2 tunnel upgrade."""

# Default HTTP request path used for tunnel connections when no override is supplied.
DEFAULT_PATH: str = "/__moesh/tunnel"
"""Default HTTP request path for tunnel connection."""

# Default host routing label used when no specific host name is specified.
DEFAULT_HOST: str = "default"
"""Default host routing label when no specific host name is specified."""

# Maximum plaintext payload in bytes for one DATA record; larger data must be split into multiple records.
MAX_DATA_PAYLOAD: int = 32768
"""Maximum plaintext payload in bytes for a DATA record."""

# Maximum plaintext payload in bytes for one control record.
MAX_CONTROL_PAYLOAD: int = 4096
"""Maximum plaintext payload in bytes for a control record."""
