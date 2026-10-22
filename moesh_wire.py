# moesh — wire protocol constants and defaults
# Pure Python, standard library only, zero external dependencies.
"""Central wire protocol constants and shared configuration defaults.

Authoritative definitions for framing bounds, route paths, upgrade tokens,
and protocol versions across all moesh components (bridge, agent, shell).
"""

from __future__ import annotations

PROTOCOL_VERSION: int = 2
"""Major protocol version for moesh v2."""

UPGRADE_TOKEN: str = "moesh-tunnel-v2"  # noqa: S105 - HTTP header upgrade token, not a secret
"""Custom HTTP/1.1 Upgrade header token for v2 encrypted tunnel."""

PRELUDE_PREFIX: bytes = b"MOESH-TUNNEL-V2 "
"""Routing label prelude prefix sent by operator to receiver before Noise session."""

TUNNEL_PATH: str = "/__moesh/tunnel"
"""HTTP request path for v2 tunnel upgrade."""

DEFAULT_PATH: str = "/__moesh/tunnel"
"""Default HTTP request path for tunnel connection."""

DEFAULT_HOST: str = "default"
"""Default host routing label when no specific host name is specified."""

MAX_DATA_PAYLOAD: int = 32768
"""Maximum plaintext payload in bytes for a DATA record."""

MAX_CONTROL_PAYLOAD: int = 4096
"""Maximum plaintext payload in bytes for a control record."""
