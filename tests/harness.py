#!/usr/bin/env python3
"""The test harness: the bridge, the agent and the operator client, in process.

Every test needs the same three things — a receiver bridge, a host agent and
an operator client — each on its own ports, with its own keys.  This module
holds them so the test files can be about behaviour instead of plumbing.

Two rules the harness keeps, because breaking them makes a failure
undiagnosable:

* **Every process gets its own evidence.**  The bridge writes to
  ``/tmp/opencode/bridge-test-<port>.log`` and each client writes to
  ``/tmp/opencode/test-client-<pid>.log`` with the *client's* pid.  Before
  this, every client in a run wrote to the same file — named after the
  pytest process — and each one truncated the last, so a failing test's
  client log was gone by the time anyone looked.
* **Ports are unique across the whole suite.**  One allocator serves every
  test file.  Two files once chose the same tunnel port: the second bridge
  could not bind it, and the two tests shared one log file, so the evidence
  of the first was overwritten by the second.
"""

from __future__ import annotations

import contextlib
import fcntl
import os
import pty
import select
import struct
import subprocess
import sys
import termios
import time
from typing import Any

import moesh_proto as proto

HERE = os.path.dirname(os.path.abspath(__file__))
TUNNEL_DIR = os.path.dirname(HERE)

#: Interpreter for every subprocess the harness launches; the default is the
#: running interpreter, so the suite is self-contained wherever it is
#: invoked.  Override with MOESH_TUNNEL_PYTHON.
AGENT_PYTHON = os.environ.get("MOESH_TUNNEL_PYTHON", sys.executable)
BRIDGE = os.path.join(TUNNEL_DIR, "moesh-bridge.py")
AGENT = os.path.join(TUNNEL_DIR, "moesh_tunnel.py")
CLIENT = os.path.join(TUNNEL_DIR, "moesh_shell.py")

#: Where the evidence of a run is written.  The operator reads these paths
#: when a test fails, so they are part of the contract with the operator.
EVIDENCE_DIR = "/tmp/opencode"  # noqa: S108 - the operator reads these paths

_PORT_BASE = [19470]
"""First tunnel port handed out.  The suite uses one allocator, so the
numbers never repeat inside a run and two test files cannot collide."""
_PORT_CEILING = 26400
"""Maximum port handed out to avoid colliding with live relay ports (26500-26700)."""


def _can_bind_triple(base: int) -> bool:
    """Verify that all three ports in the triple can be bound on 127.0.0.1."""
    import socket

    for port in (base, base + 1, base + 2):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def next_ports() -> tuple[int, int, int]:
    """Return a fresh (tunnel, operator, operator-v2) port triple."""
    seq_file = os.path.join(EVIDENCE_DIR, ".port_seq")
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    try:
        with open(seq_file, "a+", encoding="ascii") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.seek(0)
            content = f.read().strip()
            base = int(content) if content.isdigit() else _PORT_BASE[0]
            while True:
                if base >= _PORT_CEILING:
                    base = 19470
                if _can_bind_triple(base):
                    break
                base += 10
            _PORT_BASE[0] = base + 10
            f.seek(0)
            f.truncate()
            f.write(f"{_PORT_BASE[0]}\n")
            f.flush()
            fcntl.flock(f, fcntl.LOCK_UN)
            return base, base + 1, base + 2
    except OSError:
        base = _PORT_BASE[0]
        while True:
            if base >= _PORT_CEILING:
                base = 19470
            if _can_bind_triple(base):
                break
            base += 10
        _PORT_BASE[0] = base + 10
        return base, base + 1, base + 2


def set_winsize(fd: int, rows: int, cols: int) -> None:
    """Set the window size of a pty."""
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


class Bridge:
    """A bridge instance bound to private test ports."""

    def __init__(
        self,
        tunnel_port: int,
        operator_port: int,
        operator_v2_port: int,
        allow_v1: bool = True,
        env_extra: dict[str, str] | None = None,
    ) -> None:
        """Initialize and spawn a Bridge instance bound to private test ports."""
        os.makedirs("/tmp/opencode", exist_ok=True)  # noqa: S108
        env = dict(os.environ)
        env.update(
            {
                "MOESH_BRIDGE_TUNNEL_LISTEN": f"127.0.0.1:{tunnel_port}",
                "MOESH_BRIDGE_OPERATOR_LISTEN": f"127.0.0.1:{operator_port}",
                "MOESH_BRIDGE_OPERATOR_V2_LISTEN": f"127.0.0.1:{operator_v2_port}",
                "MOESH_BRIDGE_GPU_PORTS": "",
                "MOESH_BRIDGE_ALLOW_V1": "1" if allow_v1 else "0",
            }
        )
        if env_extra:
            env.update(env_extra)
        self.log_path = f"{EVIDENCE_DIR}/bridge-test-{tunnel_port}.log"
        # The bridge keeps writing to it for as long as it runs, so it
        # cannot be a context manager here.
        self.log = open(self.log_path, "wb")  # noqa: SIM115
        self.proc = subprocess.Popen(
            [sys.executable, BRIDGE], stdout=self.log, stderr=subprocess.STDOUT, env=env
        )
        # Wait for the log lines, never by connecting: a probe connection on an
        # operator port is paired with the agent's queued tunnel and consumes
        # it (the bridge pairs any operator connection with a tunnel).
        self._wait_for_line(f"tunnel listening on 127.0.0.1:{tunnel_port}")
        self._wait_for_line(f"operator listening on 127.0.0.1:{operator_port}")
        self._wait_for_line(f"operator-v2 listening on 127.0.0.1:{operator_v2_port}")

    def _wait_for_line(self, needle: str, timeout: float = 15.0) -> None:
        """Wait until the bridge logs ``needle``."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if needle in self.log_text():
                return
            time.sleep(0.1)
        raise RuntimeError(f"bridge did not report {needle!r}")

    def log_text(self) -> str:
        """Return the bridge log so far."""
        with open(self.log_path, errors="replace") as handle:
            return handle.read()

    def stop(self) -> None:
        """Stop the bridge instance."""
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.log.close()


class OperatorSession:
    """The operator client attached to a pty, driven like a real terminal."""

    def __init__(self, argv: list[str], env: dict[str, str], rows: int, cols: int):
        """Initialize an operator session attached to a pty."""
        os.makedirs("/tmp/opencode", exist_ok=True)  # noqa: S108
        self.master, slave = pty.openpty()
        set_winsize(self.master, rows, cols)
        self.buffer = b""
        self.cursor = 0

        def preexec() -> None:
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        # The client's own log goes to a file, not to /dev/null: when a test
        # fails, the reason is in there.  The file is named after the
        # client's pid, which is only known once the process exists, so it is
        # opened under a temporary name and renamed afterwards.  The child
        # keeps writing to the same inode either way.
        self.err_path = f"{EVIDENCE_DIR}/test-client-{os.getpid()}.log"
        # The client keeps writing to it for as long as it runs, so it
        # cannot be a context manager here.
        self.err = open(f"{EVIDENCE_DIR}/test-client-{os.getpid()}.tmp", "wb")  # noqa: SIM115
        self.proc = subprocess.Popen(
            argv,
            stdin=slave,
            stdout=slave,
            stderr=self.err,
            env=env,
            preexec_fn=preexec,
            close_fds=True,
        )
        os.close(slave)
        self.err_path = f"{EVIDENCE_DIR}/test-client-{self.proc.pid}.log"
        os.rename(f"{EVIDENCE_DIR}/test-client-{os.getpid()}.tmp", self.err_path)

    def read_until(self, needle: bytes, timeout: float = 25.0) -> bytes:
        """Read until ``needle`` appears; raise on timeout."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            idx = self.buffer.find(needle, self.cursor)
            if idx != -1:
                self.cursor = idx + len(needle)
                return self.buffer
            ready, _, _ = select.select([self.master], [], [], 0.5)
            if not ready:
                continue
            try:
                chunk = os.read(self.master, 65536)
            except OSError:
                break
            if not chunk:
                break
            self.buffer += chunk
        err_msg = ""
        if self.err_path and os.path.exists(self.err_path):
            with contextlib.suppress(OSError), open(self.err_path, "rb") as ef:
                err_data = ef.read()
                if err_data:
                    err_msg = f"; client stderr: {err_data[-1000:]!r}"
        raise AssertionError(
            f"timed out waiting for {needle!r}; saw {self.buffer[-800:]!r}{err_msg}"
        )

    def write(self, data: bytes) -> None:
        """Write bytes to the client's terminal."""
        os.write(self.master, data)

    def resize(self, rows: int, cols: int) -> None:
        """Resize the terminal; the kernel raises SIGWINCH in the client."""
        set_winsize(self.master, rows, cols)

    def close(self) -> None:
        """Terminate the client and release the pty."""
        try:
            self.proc.terminate()
            self.proc.wait(timeout=10)
        except Exception:
            self.proc.kill()
        with contextlib.suppress(OSError):
            os.close(self.master)


def make_keys(tmp_path: Any) -> tuple[str, str, bytes, bytes, bytes]:
    """Write the operator private key and the agent public key to ``tmp_path``.

    Returns the operator key file, the agent public key file, the agent
    private key, the agent public key and the operator public key, so the
    agent runs with exactly the key the operator pins.
    """
    operator_private, operator_public = proto.generate_static_keypair()
    agent_private, agent_public = proto.generate_static_keypair()
    operator_keyfile = os.path.join(str(tmp_path), "operator.key")
    with open(operator_keyfile, "w", encoding="ascii") as handle:
        handle.write(operator_private.hex() + "\n")
    os.chmod(operator_keyfile, 0o600)
    agent_pubfile = os.path.join(str(tmp_path), "agent.pub")
    with open(agent_pubfile, "w", encoding="ascii") as handle:
        handle.write(agent_public.hex() + "\n")
    return operator_keyfile, agent_pubfile, agent_private, agent_public, operator_public


def start_agent(
    tmp_path: Any, host: str, port: int, agent_private: bytes, operator_public: bytes
) -> subprocess.Popen[bytes]:
    """Start the host-side agent against a test bridge.

    Polls the agent log until the tunnel is established before returning the
    process, raising :class:`TimeoutError` if startup fails or times out.
    """
    env = dict(os.environ)
    env.update(
        {
            "MOESH_TUNNEL_RECEIVER": host,
            "MOESH_TUNNEL_RECEIVER_PORT": str(port),
            "MOESH_TUNNEL_AGENT_KEY": agent_private.hex(),
            "MOESH_TUNNEL_OPERATOR_PUB": operator_public.hex(),
            "MOESH_TUNNEL_CHILD_PIDFILE": os.path.join(str(tmp_path), "shell.pid"),
        }
    )
    # The agent keeps writing to it for as long as it runs.
    log_path = os.path.join(str(tmp_path), "agent.log")
    log = open(log_path, "ab")  # noqa: SIM115
    proc = subprocess.Popen(
        [AGENT_PYTHON, AGENT], stdout=log, stderr=subprocess.STDOUT, env=env
    )
    marker = f"\n--- agent start pid={proc.pid} ---\n".encode()
    log.write(marker)
    log.flush()

    deadline = time.time() + 20.0
    while time.time() < deadline:
        try:
            with open(log_path, "rb") as f:
                content = f.read()
                marker_idx = content.rfind(marker)
                if marker_idx != -1:
                    fresh = content[marker_idx + len(marker) :]
                    if (
                        b"tunnel established" in fresh
                        or b"waiting for an operator" in fresh
                    ):
                        return proc
        except OSError:
            pass
        if proc.poll() is not None:
            raise TimeoutError(
                f"Agent process {proc.pid} exited prematurely with code {proc.returncode}"
            )
        time.sleep(0.05)
    raise TimeoutError(f"Agent process {proc.pid} timed out waiting for tunnel establishment")
