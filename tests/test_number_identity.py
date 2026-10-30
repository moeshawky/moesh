#!/usr/bin/env python3
"""One number selects the host: name, key and queue.

The operator's SSH entries gave one number (the port) per host, and
changing it switched identity.  The tunnel does the same: the host's
``MOESH_TUNNEL_HOST = 3`` and the operator's ``moesh -n 3`` name the
same host, and the static key is derived from the master secret plus that
number — so the identity follows the number.
"""

from __future__ import annotations

import os
import subprocess
import time
from typing import TYPE_CHECKING, TypedDict

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

import pytest

import moesh_proto as proto
from tests.harness import AGENT_PYTHON, TUNNEL_DIR, Bridge, OperatorSession, next_ports

PREFIX = "host"


def _agent_env(
    tunnel_port: int, master: bytes, number: int, operator_pub: bytes
) -> dict[str, str]:
    env = dict(os.environ)
    env.update(
        {
            "MOESH_TUNNEL_RECEIVER": "127.0.0.1",
            "MOESH_TUNNEL_RECEIVER_PORT": str(tunnel_port),
            "MOESH_TUNNEL_MASTER": master.hex(),
            "MOESH_TUNNEL_HOST": str(number),
            # The agent authenticates the operator by pinning the
            # operator's static public key.
            "MOESH_TUNNEL_OPERATOR_PUB": operator_pub.hex(),
        }
    )
    return env


class Numbered(TypedDict):
    """What the numbered-host fixture hands to a test."""

    bridge: Bridge
    agents: dict[int, subprocess.Popen[bytes]]
    client_env: Callable[[], dict[str, str]]
    master: bytes
    pins: Path


@pytest.fixture()
def numbered(tmp_path: Path) -> Iterator[Numbered]:
    """One bridge, one master secret, two host numbers."""
    master = os.urandom(32)
    operator_private, operator_public = proto.generate_static_keypair()
    operator_keyfile = tmp_path / "operator.key"
    operator_keyfile.write_text(operator_private.hex() + "\n", encoding="ascii")
    operator_keyfile.chmod(0o600)
    tunnel_port, operator_port, operator_v2_port = next_ports()
    bridge = Bridge(
        tunnel_port=tunnel_port,
        operator_port=operator_port,
        operator_v2_port=operator_v2_port,
    )
    pins = tmp_path / "hosts.toml"
    pins.write_text(
        f'prefix = "{PREFIX}"\n\n[hosts.{PREFIX}-3]\nmaster = "{master.hex()}"\n\n[hosts.{PREFIX}-4]\nmaster = "{master.hex()}"\n',
        encoding="ascii",
    )
    agents = {}
    for number in (3, 4):
        # The agent keeps writing to it for as long as it runs.
        log = open(os.path.join(tmp_path, f"agent-{number}.log"), "wb")  # noqa: SIM115
        agents[number] = subprocess.Popen(
            [AGENT_PYTHON, os.path.join(TUNNEL_DIR, "moesh_tunnel.py")],
            stdout=log,
            stderr=subprocess.STDOUT,
            env=_agent_env(tunnel_port, master, number, operator_public),
        )
    for number in (3, 4):
        log_path = os.path.join(tmp_path, f"agent-{number}.log")
        deadline = time.time() + 25.0
        while time.time() < deadline:
            try:
                with open(log_path, "rb") as f:
                    content = f.read()
                    if b"tunnel established" in content or b"waiting for an operator" in content:
                        break
            except OSError:
                pass
            if agents[number].poll() is not None:
                raise TimeoutError(f"agent {number} died with {agents[number].returncode}")
            time.sleep(0.05)
        else:
            with open(log_path, "rb") as f:
                content = f.read()
            raise TimeoutError(
                f"agent {number} failed to establish tunnel within 25.0s; log: {content!r}"
            )

    def client_env() -> dict[str, str]:
        env = dict(os.environ)
        env.update(
            {
                "MOESH_SHELL_ADDR": f"127.0.0.1:{operator_v2_port}",
                "MOESH_SHELL_KEYFILE": str(operator_keyfile),
                "MOESH_SHELL_HOSTS_FILE": str(pins),
                "MOESH_SHELL_HANDSHAKE_TIMEOUT": "60",
                "TERM": "xterm-256color",
            }
        )
        return env

    yield {
        "bridge": bridge,
        "agents": agents,
        "client_env": client_env,
        "master": master,
        "pins": pins,
    }
    for agent in agents.values():
        agent.terminate()
        try:
            agent.wait(timeout=10)
        except subprocess.TimeoutExpired:
            agent.kill()
    bridge.stop()


def test_the_number_selects_the_host(numbered: Numbered) -> None:
    """`-n 3` reaches host 3, and its state is not host 4's."""
    three = OperatorSession(
        [AGENT_PYTHON, os.path.join(TUNNEL_DIR, "moesh_shell.py"), "-n", "3"],
        numbered["client_env"](),
        rows=24,
        cols=80,
    )
    try:
        assert three.read_until(b"$", timeout=40), "host 3 must answer"
        three.write(b"export OWNER=three\n")
        three.read_until(b"OWNER", timeout=20)
    finally:
        three.close()
    time.sleep(2)

    four = OperatorSession(
        [AGENT_PYTHON, os.path.join(TUNNEL_DIR, "moesh_shell.py"), "-n", "4"],
        numbered["client_env"](),
        rows=24,
        cols=80,
    )
    try:
        assert four.read_until(b"$", timeout=40), "host 4 must answer"
        four.write(b"echo OWNER=[$OWNER]\n")
        assert b"OWNER=[]" in four.read_until(b"OWNER=[]", timeout=25)
    finally:
        four.close()


def test_the_key_follows_the_number(numbered: Numbered) -> None:
    """The same master with a different number yields a different key."""
    three = proto.derive_static_key(numbered["master"], f"{PREFIX}-3")
    four = proto.derive_static_key(numbered["master"], f"{PREFIX}-4")
    assert three != four
    assert proto.public_key_bytes(three) != proto.public_key_bytes(four)


def test_the_bridge_keeps_one_queue_per_number(numbered: Numbered) -> None:
    """Each number lands in its own queue."""
    with open(numbered["bridge"].log_path, errors="replace") as handle:
        log = handle.read()
    assert f"host {PREFIX}-3" in log
    assert f"host {PREFIX}-4" in log
    assert f"host {PREFIX}-3" != f"host {PREFIX}-4"
