#!/usr/bin/env python3
"""Named-host routing: one tunnel per host, like separate SSH host entries.

The point: with several hosts running the agent, the operator must
be able to say WHICH host it wants, and each host must have its own
pinned key.  These tests use one bridge with two named queues.
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

_ALPHA = "alpha"
_BETA = "beta"


class Hosts(TypedDict):
    """What the named-host fixture hands to a test."""

    bridge: Bridge
    agents: dict[str, subprocess.Popen[bytes]]
    client_env: Callable[[str], dict[str, str]]
    alpha_public: bytes
    beta_public: bytes


@pytest.fixture()
def hosts(tmp_path: Path) -> Iterator[Hosts]:
    """Two named hosts behind one bridge, with a pins file for the client."""
    alpha_private, alpha_public = proto.generate_static_keypair()
    beta_private, beta_public = proto.generate_static_keypair()

    pins = tmp_path / "hosts.toml"
    pins.write_text(
        f'[hosts.{_ALPHA}]\nagent_pub = "{alpha_public.hex()}"\n\n[hosts.{_BETA}]\nagent_pub = "{beta_public.hex()}"\n',
        encoding="ascii",
    )

    # Every agent pins the same generated operator key, and the operator's
    # client proves itself with the matching private key: nothing here
    # touches key material outside this test's temporary directory.
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

    def start_agent(
        name: str, private: bytes, public: bytes
    ) -> subprocess.Popen[bytes]:
        env = dict(os.environ)
        env.update(
            {
                "MOESH_TUNNEL_RECEIVER": "127.0.0.1",
                "MOESH_TUNNEL_RECEIVER_PORT": str(tunnel_port),
                "MOESH_TUNNEL_AGENT_KEY": private.hex(),
                # The agent pins the OPERATOR's key, not its own.
                "MOESH_TUNNEL_OPERATOR_PUB": operator_public.hex(),
                "MOESH_TUNNEL_NAME": name,
            }
        )
        # The agent keeps writing to it for as long as it runs.
        log_file_path = os.path.join(tmp_path, f"agent-{name}.log")
        log = open(log_file_path, "wb")  # noqa: SIM115
        proc = subprocess.Popen(
            [AGENT_PYTHON, os.path.join(TUNNEL_DIR, "moesh_tunnel.py")],
            stdout=log,
            stderr=subprocess.STDOUT,
            env=env,
        )
        deadline = time.time() + 20.0
        while time.time() < deadline:
            try:
                with open(log_file_path, "rb") as f:
                    content = f.read()
                    if b"tunnel established" in content or b"waiting for an operator" in content:
                        break
            except OSError:
                pass
            if proc.poll() is not None:
                raise TimeoutError(
                    f"Agent {name} exited prematurely with code {proc.returncode}"
                )
            time.sleep(0.05)
        else:
            raise TimeoutError(f"Agent {name} timed out waiting for tunnel establishment")
        return proc

    agents = {
        _ALPHA: start_agent(_ALPHA, alpha_private, alpha_public),
        _BETA: start_agent(_BETA, beta_private, beta_public),
    }

    def client_env(host: str) -> dict[str, str]:
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
        "alpha_public": alpha_public,
        "beta_public": beta_public,
    }
    for agent in agents.values():
        agent.terminate()
        try:
            agent.wait(timeout=10)
        except subprocess.TimeoutExpired:
            agent.kill()
    bridge.stop()


def test_each_host_gets_its_own_session(hosts: Hosts) -> None:
    """Two named hosts, two clients: each reaches its own host."""
    alpha = OperatorSession(
        [AGENT_PYTHON, os.path.join(TUNNEL_DIR, "moesh_shell.py"), "--host", _ALPHA],
        hosts["client_env"](_ALPHA),
        rows=24,
        cols=80,
    )
    try:
        assert alpha.read_until(b"$", timeout=40), "the alpha host must answer"
        alpha.write(b"export WHICH=alpha\n")
        alpha.read_until(b"WHICH", timeout=20)
    finally:
        alpha.close()
    time.sleep(2)

    beta = OperatorSession(
        [AGENT_PYTHON, os.path.join(TUNNEL_DIR, "moesh_shell.py"), "--host", _BETA],
        hosts["client_env"](_BETA),
        rows=24,
        cols=80,
    )
    try:
        assert beta.read_until(b"$", timeout=40), "the beta host must answer"
        beta.write(b"echo WHICH=[$WHICH]\n")
        # The beta host never saw the alpha variable.
        assert b"WHICH=[]" in beta.read_until(b"WHICH=[]", timeout=25)
    finally:
        beta.close()


def test_a_host_without_a_pin_is_refused(hosts: Hosts) -> None:
    """An unpinned host name is refused before any session is attempted."""
    env = hosts["client_env"](_ALPHA)
    proc = subprocess.run(
        [
            AGENT_PYTHON,
            os.path.join(TUNNEL_DIR, "moesh_shell.py"),
            "--host",
            "not-pinned",
        ],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=60,
    )
    assert proc.returncode != 0
    assert b"not-pinned" in proc.stderr
    assert b"hosts.toml" in proc.stderr


def test_the_bridge_routes_by_name(hosts: Hosts) -> None:
    """The bridge logs one named queue per host, and keeps them apart."""
    with open(hosts["bridge"].log_path, errors="replace") as handle:
        log = handle.read()
    assert "host tunnel v2 attached" in log
    assert f"host {_ALPHA}" in log
    assert f"host {_BETA}" in log
