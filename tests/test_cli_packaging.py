"""Packaging & console scripts verification test suite.

Validates:
1. All advertised console scripts are present on PATH and answer --help with code 0.
2. Non-interactive command piping with moesh -n 3 -c against standard integration fixture.
3. Preserving argument quoting with moesh -n 3 python3 -c across the tunnel.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

import pytest

import moesh_proto as proto
from tests.harness import AGENT, AGENT_PYTHON, Bridge, next_ports


@pytest.fixture()
def integration_fixture(tmp_path: Path) -> Iterator[dict[str, Any]]:
    """Standard test integration fixture providing bridge, agent on host 3, and client configuration."""
    master = os.urandom(32)
    operator_private, operator_public = proto.generate_static_keypair()
    operator_keyfile = tmp_path / "operator.key"
    operator_keyfile.write_text(operator_private.hex() + "\n", encoding="ascii")
    operator_keyfile.chmod(0o600)

    pins = tmp_path / "hosts.toml"
    pins.write_text(
        f'prefix = "host"\n\n[hosts.host-3]\nmaster = "{master.hex()}"\n',
        encoding="ascii",
    )

    tunnel_port, operator_port, operator_v2_port = next_ports()
    bridge = Bridge(
        tunnel_port=tunnel_port,
        operator_port=operator_port,
        operator_v2_port=operator_v2_port,
    )

    agent_env = dict(os.environ)
    agent_env.update(
        {
            "MOESH_TUNNEL_RECEIVER": "127.0.0.1",
            "MOESH_TUNNEL_RECEIVER_PORT": str(tunnel_port),
            "MOESH_TUNNEL_MASTER": master.hex(),
            "MOESH_TUNNEL_HOST": "3",
            "MOESH_TUNNEL_OPERATOR_PUB": operator_public.hex(),
        }
    )
    log_path = tmp_path / "agent-3.log"
    log = open(log_path, "wb")  # noqa: SIM115
    agent = subprocess.Popen(
        [AGENT_PYTHON, AGENT],
        stdout=log,
        stderr=subprocess.STDOUT,
        env=agent_env,
    )

    # Barrier: wait up to 10s for tunnel establishment
    deadline = time.time() + 10.0
    while time.time() < deadline:
        if agent.poll() is not None:
            raise TimeoutError(
                f"Agent process {agent.pid} exited unexpectedly with code {agent.returncode}"
            )
        try:
            with open(log_path, "rb") as f:
                content = f.read()
                if b"tunnel established" in content or b"waiting for an operator" in content:
                    break
        except OSError:
            pass
        time.sleep(0.05)
    else:
        raise TimeoutError(f"Agent process {agent.pid} did not establish tunnel within 10.0s")

    client_env = dict(os.environ)
    client_env.update(
        {
            "MOESH_SHELL_ADDR": f"127.0.0.1:{operator_v2_port}",
            "MOESH_SHELL_KEYFILE": str(operator_keyfile),
            "MOESH_SHELL_HOSTS_FILE": str(pins),
            "MOESH_SHELL_HANDSHAKE_TIMEOUT": "10",
            "TERM": "xterm-256color",
        }
    )

    yield {
        "bridge": bridge,
        "agent": agent,
        "client_env": client_env,
        "operator_v2_port": operator_v2_port,
        "tunnel_port": tunnel_port,
    }

    agent.terminate()
    try:
        agent.wait(timeout=10)
    except subprocess.TimeoutExpired:
        agent.kill()
    log.close()
    bridge.stop()


@pytest.fixture()
def standard_integration_fixture(
    integration_fixture: dict[str, Any],
) -> dict[str, Any]:
    """Alias for integration_fixture to support either fixture name."""
    return integration_fixture


def test_all_console_scripts_on_path_help() -> None:
    """Verify all 5 advertised console scripts answer --help with code 0 on PATH."""
    scripts = ["moesh", "moecp", "moesh-tunnel", "moesh-relay", "moesh-bridge"]
    for script in scripts:
        path = shutil.which(script)
        assert path is not None, f"Console script {script!r} not found on PATH"
        res = subprocess.run(
            [path, "--help"],
            capture_output=True,
            text=True,
            check=True,
            timeout=15,
        )
        assert res.returncode == 0
        help_output = res.stdout.lower()
        assert "usage:" in help_output or "options:" in help_output, (
            f"Expected help banner in stdout for {script!r}, got: {res.stdout!r}"
        )


def test_moesh_c_flag_command_piping(
    integration_fixture: dict[str, Any],
) -> None:
    """Run `moesh -n 3 -c "echo 'hello world'"` asserting output and exit code 0."""
    moesh_bin = shutil.which("moesh")
    assert moesh_bin is not None, "moesh executable not found on PATH"

    env = integration_fixture["client_env"]
    res = subprocess.run(
        [moesh_bin, "-n", "3", "-c", "echo 'hello world'"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert res.returncode == 0, f"moesh failed with {res.returncode}: stdout={res.stdout!r}, stderr={res.stderr!r}"
    assert res.stdout == "hello world\n"


def test_moesh_c_flag_quoted_arguments(
    integration_fixture: dict[str, Any],
) -> None:
    """Run `moesh -n 3 python3 -c "import sys; sys.stdout.write('preserves quotes\\n')"` asserting quoting preservation."""
    moesh_bin = shutil.which("moesh")
    assert moesh_bin is not None, "moesh executable not found on PATH"

    env = integration_fixture["client_env"]
    res = subprocess.run(
        [
            moesh_bin,
            "-n",
            "3",
            "python3",
            "-c",
            "import sys; sys.stdout.write('preserves quotes\\n')",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert res.returncode == 0, f"moesh failed with {res.returncode}: stdout={res.stdout!r}, stderr={res.stderr!r}"
    assert res.stdout == "preserves quotes\n"
