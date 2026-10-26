#!/usr/bin/env python3
"""Tests for moecp (secure file copy utility over moesh).

Tests both pure unit behaviors (path parsing, worker script validity, CLI parsing,
local fallback copies) and end-to-end integration transfers (single file upload,
download, recursive directory synchronization, attribute preservation) over
the encrypted Noise_XX tunnel.
"""

from __future__ import annotations

import base64
import os
import stat
import subprocess
import time
import zlib
from typing import TYPE_CHECKING, Any, TypedDict

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

import pytest

import moecp
import moesh_proto as proto
from tests.harness import AGENT_PYTHON, TUNNEL_DIR, Bridge, next_ports

_ALPHA = "alpha"


class MoecpHosts(TypedDict):
    """Fixture payload for running moecp integration tests."""

    bridge: Bridge
    agent: subprocess.Popen[bytes]
    client_env: Callable[[str], dict[str, str]]
    operator_keyfile: Path
    pins_file: Path
    operator_port: int


@pytest.fixture()
def moecp_test_env(tmp_path: Path) -> Iterator[MoecpHosts]:
    """Launch a single agent behind a bridge with keys configured for moecp."""
    agent_private, agent_public = proto.generate_static_keypair()
    operator_private, operator_public = proto.generate_static_keypair()

    pins = tmp_path / "hosts.toml"
    pins.write_text(
        f'[hosts.{_ALPHA}]\nagent_pub = "{agent_public.hex()}"\n',
        encoding="ascii",
    )

    operator_keyfile = tmp_path / "operator.key"
    operator_keyfile.write_text(operator_private.hex() + "\n", encoding="ascii")
    operator_keyfile.chmod(0o600)

    tunnel_port, operator_port, operator_v2_port = next_ports()
    bridge = Bridge(
        tunnel_port=tunnel_port,
        operator_port=operator_port,
        operator_v2_port=operator_v2_port,
    )

    env = dict(os.environ)
    env.update(
        {
            "MOESH_TUNNEL_RECEIVER": "127.0.0.1",
            "MOESH_TUNNEL_RECEIVER_PORT": str(tunnel_port),
            "MOESH_TUNNEL_AGENT_KEY": agent_private.hex(),
            "MOESH_TUNNEL_OPERATOR_PUB": operator_public.hex(),
            "MOESH_TUNNEL_NAME": _ALPHA,
        }
    )
    log_file = open(tmp_path / f"agent-{_ALPHA}.log", "wb")  # noqa: SIM115
    agent = subprocess.Popen(
        [AGENT_PYTHON, os.path.join(TUNNEL_DIR, "moesh_tunnel.py")],
        stdout=log_file,
        stderr=subprocess.STDOUT,
        env=env,
    )
    time.sleep(2.0)

    def client_env(host: str) -> dict[str, str]:
        cenv = dict(os.environ)
        cenv.update(
            {
                "MOESH_SHELL_ADDR": f"127.0.0.1:{operator_v2_port}",
                "MOESH_SHELL_KEYFILE": str(operator_keyfile),
                "MOESH_SHELL_HOSTS_FILE": str(pins),
                "MOESH_SHELL_HANDSHAKE_TIMEOUT": "10",
            }
        )
        return cenv

    yield {
        "bridge": bridge,
        "agent": agent,
        "client_env": client_env,
        "operator_keyfile": operator_keyfile,
        "pins_file": pins,
        "operator_port": operator_v2_port,
    }

    agent.terminate()
    try:
        agent.wait(timeout=10)
    except subprocess.TimeoutExpired:
        agent.kill()
    log_file.close()
    bridge.stop()


# ─────────────────────────────────────────────────────────────────────────────
# Unit Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_parse_path_spec_remote_and_local() -> None:
    """PathSpec parsing distinguishes remote and local targets correctly."""
    # Remote with explicit named host
    p1 = moecp.parse_path_spec("alpha:/var/log/syslog")
    assert p1.is_remote is True
    assert p1.host == "alpha"
    assert p1.path == "/var/log/syslog"

    # Remote with number host shortcut (e.g. 3:/opt/foo -> host-3:/opt/foo)
    p2 = moecp.parse_path_spec("3:/opt/foo")
    assert p2.is_remote is True
    assert p2.host == "host-3"
    assert p2.path == "/opt/foo"

    # Remote keyword with default host
    p3 = moecp.parse_path_spec("remote:/opt/test", default_host="host-5")
    assert p3.is_remote is True
    assert p3.host == "host-5"
    assert p3.path == "/opt/test"

    # Remote keyword fallback without default host
    p4 = moecp.parse_path_spec("remote:/opt/data")
    assert p4.is_remote is True
    assert p4.host == "host-1"
    assert p4.path == "/opt/data"

    # Remote host with empty path defaults to "."
    p5 = moecp.parse_path_spec("alpha:")
    assert p5.is_remote is True
    assert p5.host == "alpha"
    assert p5.path == "."

    # Local paths
    p6 = moecp.parse_path_spec("./local.txt")
    assert p6.is_remote is False
    assert p6.path == "./local.txt"

    p7 = moecp.parse_path_spec("/etc/resolv.conf")
    assert p7.is_remote is False
    assert p7.path == "/etc/resolv.conf"


def test_worker_code_compiles_and_decompresses() -> None:
    """The in-memory remote bootstrap worker compiles and round-trips through zlib/b64."""
    # Verify the Python syntax of the worker code
    code_obj = compile(moecp._WORKER_CODE, "<remote_worker>", "exec")
    assert code_obj is not None

    # Verify the bootstrap command structure
    cmd = moecp.generate_bootstrap_cmd()
    assert cmd.startswith(b"exec python3 -u -c ")

    # Extract base64 payload and decompress to verify payload equality
    prefix = b"base64.b64decode('"
    start = cmd.find(prefix) + len(prefix)
    end = cmd.find(b"')", start)
    b64_str = cmd[start:end].decode("ascii")
    decompressed = zlib.decompress(base64.b64decode(b64_str)).decode("utf-8")
    assert decompressed.strip() == moecp._WORKER_CODE.strip()


def test_precompressed_extensions_parity() -> None:
    """Precompressed extension set in _WORKER_CODE matches moecp.PRECOMPRESSED_EXTS exactly."""
    # Check helper classification
    for ext in [".gz", ".tgz", ".zip", ".zst", ".safetensors", ".gguf", ".pt", ".bin", ".onnx", ".png", ".jpg", ".mp4"]:
        assert moecp.is_precompressed(f"model{ext}")
        assert moecp.is_precompressed(f"/path/to/archive{ext.upper()}")
    for ext in [".txt", ".py", ".json", ".csv", ".tar", ".log", ".md", ".toml"]:
        assert not moecp.is_precompressed(f"source{ext}")

    # Worker code parity
    ns: dict[str, Any] = {}
    exec(compile(moecp._WORKER_CODE, "<test>", "exec"), ns)  # noqa: S102
    worker_exts = set(ns["PRECOMPRESSED_EXTS"])
    assert worker_exts == set(moecp.PRECOMPRESSED_EXTS)


def test_local_to_local_file_copy(tmp_path: Path) -> None:
    """Local-to-local fallback mirrors scp behavior for local files."""
    src = tmp_path / "src.txt"
    src.write_text("hello local copy", encoding="utf-8")
    dst = tmp_path / "dst.txt"

    ret = moecp.main([str(src), str(dst)])
    assert ret == 0
    assert dst.read_text(encoding="utf-8") == "hello local copy"


def test_local_to_local_directory_copy(tmp_path: Path) -> None:
    """Local-to-local directory copy requires -r flag."""
    src_dir = tmp_path / "src_dir"
    src_dir.mkdir()
    (src_dir / "child.txt").write_text("child content", encoding="utf-8")
    dst_dir = tmp_path / "dst_dir"

    # Without -r should fail
    ret_fail = moecp.main([str(src_dir), str(dst_dir)])
    assert ret_fail == 1
    assert not dst_dir.exists()

    # With -r should succeed
    ret_ok = moecp.main(["-r", str(src_dir), str(dst_dir)])
    assert ret_ok == 0
    assert (dst_dir / "child.txt").read_text(encoding="utf-8") == "child content"


def test_remote_to_remote_disallowed() -> None:
    """Direct remote-to-remote transfers return error code 1."""
    ret = moecp.main(["alpha:/tmp/foo", "beta:/tmp/bar"])
    assert ret == 1


def test_insufficient_paths_error() -> None:
    """Providing fewer than two paths raises SystemExit from argparse."""
    with pytest.raises(SystemExit):
        moecp.main(["single_path"])


# ─────────────────────────────────────────────────────────────────────────────
# Integration Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_moecp_upload_single_file(moecp_test_env: MoecpHosts, tmp_path: Path) -> None:
    """moecp uploads a single local file to a remote destination path."""
    src_file = tmp_path / "test_upload.bin"
    test_data = b"MOECP_UPLOAD_PAYLOAD_TEST_" + os.urandom(4096)
    src_file.write_bytes(test_data)

    remote_dest = tmp_path / "remote_dest.bin"
    env = moecp_test_env["client_env"](_ALPHA)

    # Run moecp via subprocess to test realistic CLI invocation
    cmd = [
        AGENT_PYTHON,
        os.path.join(TUNNEL_DIR, "moecp.py"),
        "-q",
        str(src_file),
        f"{_ALPHA}:{remote_dest}",
    ]
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, f"moecp upload failed: stdout={proc.stdout} stderr={proc.stderr}"

    # Verify content arrived on the remote host filesystem
    assert remote_dest.exists(), f"destination {remote_dest} was not created"
    assert remote_dest.read_bytes() == test_data


def test_moecp_download_single_file(moecp_test_env: MoecpHosts, tmp_path: Path) -> None:
    """moecp downloads a single remote file to a local destination path."""
    remote_src = tmp_path / "remote_download_src.bin"
    test_data = b"MOECP_DOWNLOAD_PAYLOAD_TEST_" + os.urandom(8192)
    remote_src.write_bytes(test_data)

    local_dest = tmp_path / "downloaded.bin"
    env = moecp_test_env["client_env"](_ALPHA)

    cmd = [
        AGENT_PYTHON,
        os.path.join(TUNNEL_DIR, "moecp.py"),
        "-q",
        f"{_ALPHA}:{remote_src}",
        str(local_dest),
    ]
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, f"moecp download failed: stdout={proc.stdout} stderr={proc.stderr}"
    assert local_dest.read_bytes() == test_data


def test_moecp_recursive_upload_and_download(moecp_test_env: MoecpHosts, tmp_path: Path) -> None:
    """moecp recursively uploads and downloads nested directory structures."""
    upload_root = tmp_path / "tree_upload"
    upload_root.mkdir()
    (upload_root / "root.txt").write_text("root file content", encoding="utf-8")
    sub1 = upload_root / "subdir"
    sub1.mkdir()
    (sub1 / "nested.bin").write_bytes(b"nested binary payload " * 100)

    remote_dest_dir = tmp_path / "remote_tree"
    env = moecp_test_env["client_env"](_ALPHA)

    # 1. Recursive Upload
    upload_cmd = [
        AGENT_PYTHON,
        os.path.join(TUNNEL_DIR, "moecp.py"),
        "-r",
        "-q",
        str(upload_root),
        f"{_ALPHA}:{remote_dest_dir}",
    ]
    uproc = subprocess.run(upload_cmd, env=env, capture_output=True, text=True, timeout=30)
    assert uproc.returncode == 0, f"recursive upload failed: {uproc.stderr}"

    assert remote_dest_dir.is_dir()
    assert (remote_dest_dir / "root.txt").read_bytes() == b"root file content"
    assert (remote_dest_dir / "subdir" / "nested.bin").read_bytes() == b"nested binary payload " * 100

    # 2. Recursive Download
    download_root = tmp_path / "tree_download"
    download_root.mkdir()
    download_cmd = [
        AGENT_PYTHON,
        os.path.join(TUNNEL_DIR, "moecp.py"),
        "-r",
        "-q",
        f"{_ALPHA}:{remote_dest_dir}",
        str(download_root),
    ]
    dproc = subprocess.run(download_cmd, env=env, capture_output=True, text=True, timeout=30)
    assert dproc.returncode == 0, f"recursive download failed: {dproc.stderr}"

    assert (download_root / "root.txt").read_text(encoding="utf-8") == "root file content"
    assert (download_root / "subdir" / "nested.bin").read_bytes() == b"nested binary payload " * 100


def test_moecp_preserve_attributes(moecp_test_env: MoecpHosts, tmp_path: Path) -> None:
    """moecp preserves mode and timestamps when -p is specified."""
    src_file = tmp_path / "executable.sh"
    src_file.write_text("#!/bin/sh\necho preserved\n", encoding="utf-8")
    os.chmod(src_file, 0o755)  # noqa: S103 - testing mode preservation
    test_time = 1700000000.0
    os.utime(src_file, (test_time, test_time))

    remote_dest = tmp_path / "preserved.sh"
    env = moecp_test_env["client_env"](_ALPHA)

    cmd = [
        AGENT_PYTHON,
        os.path.join(TUNNEL_DIR, "moecp.py"),
        "-p",
        "-q",
        str(src_file),
        f"{_ALPHA}:{remote_dest}",
    ]
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, f"attribute upload failed: {proc.stderr}"

    st = os.stat(remote_dest)
    assert stat.S_IMODE(st.st_mode) == 0o755
    assert abs(st.st_mtime - test_time) <= 2.0
