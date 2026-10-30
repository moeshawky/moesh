"""moesh — an SSH-like encrypted remote shell over HTTP/1.1 Upgrade with Noise_XX."""
from __future__ import annotations

import moecp as cp
import moesh_bridge as bridge
import moesh_proto as proto
import moesh_relay as relay
import moesh_shell as shell
import moesh_tunnel as tunnel
import moesh_wire as wire

__version__ = "0.2.0a4"

__all__ = [
    "__version__",
    "bridge",
    "cp",
    "proto",
    "relay",
    "shell",
    "tunnel",
    "wire",
]
