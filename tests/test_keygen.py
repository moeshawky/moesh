"""Fast key-generation tests (no sockets, no bridge, no ports)."""

from __future__ import annotations

import stat
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pytest

import moesh_proto_v2 as proto
import moesh_shell_v2
import moesh_tunnel_v2


def test_client_generate_key_writes_private_0600_and_public_0644(tmp_path: Path) -> None:
    keyfile = tmp_path / "operator.key"
    assert moesh_shell_v2.generate_key(str(keyfile)) == 0
    pubfile = Path(str(keyfile) + ".pub")
    assert keyfile.is_file()
    assert pubfile.is_file()
    assert stat.S_IMODE(keyfile.stat().st_mode) == 0o600
    assert stat.S_IMODE(pubfile.stat().st_mode) == 0o644


def test_generate_key_prints_only_the_public_half(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    keyfile = tmp_path / "operator.key"
    rc = moesh_shell_v2.main(["--generate-key", "--keyfile", str(keyfile)])
    assert rc == 0
    captured = capsys.readouterr()
    out = captured.out
    pubfile = Path(str(keyfile) + ".pub")
    private_hex = keyfile.read_text(encoding="ascii").strip()
    public_hex = pubfile.read_text(encoding="ascii").strip()
    assert public_hex in out
    assert "SHA256:" in out
    assert private_hex not in out


def test_generate_key_refuses_to_overwrite_without_force(tmp_path: Path) -> None:
    # client
    ckey = tmp_path / "client.key"
    assert moesh_shell_v2.generate_key(str(ckey)) == 0
    cpub = Path(str(ckey) + ".pub")
    before_key = ckey.read_bytes()
    before_pub = cpub.read_bytes()
    assert moesh_shell_v2.generate_key(str(ckey)) == 1
    assert ckey.read_bytes() == before_key
    assert cpub.read_bytes() == before_pub
    assert moesh_shell_v2.generate_key(str(ckey), force=True) == 0

    # agent
    akey = tmp_path / "agent.key"
    assert moesh_tunnel_v2.generate_key(str(akey)) == 0
    apub = Path(str(akey) + ".pub")
    abefore_key = akey.read_bytes()
    abefore_pub = apub.read_bytes()
    assert moesh_tunnel_v2.generate_key(str(akey)) == 1
    assert akey.read_bytes() == abefore_key
    assert apub.read_bytes() == abefore_pub
    assert moesh_tunnel_v2.generate_key(str(akey), force=True) == 0

    # agent flag path
    fkey = tmp_path / "agent2.key"
    assert moesh_tunnel_v2.main(["--generate-key", "--keyfile", str(fkey)]) == 0
    fbefore = fkey.read_bytes()
    assert moesh_tunnel_v2.main(["--generate-key", "--keyfile", str(fkey)]) == 1
    assert fkey.read_bytes() == fbefore
    assert moesh_tunnel_v2.main(["--generate-key", "--keyfile", str(fkey), "--force"]) == 0


def test_generated_pair_matches_public_key_of(tmp_path: Path) -> None:
    keyfile = tmp_path / "k.key"
    assert moesh_shell_v2.generate_key(str(keyfile)) == 0
    private_hex = keyfile.read_text(encoding="ascii").strip()
    public_hex = Path(str(keyfile) + ".pub").read_text(encoding="ascii").strip()
    assert proto.public_key_of(bytes.fromhex(private_hex)) == public_hex

    akey = tmp_path / "a.key"
    assert moesh_tunnel_v2.generate_key(str(akey)) == 0
    aprivate_hex = akey.read_text(encoding="ascii").strip()
    apublic_hex = Path(str(akey) + ".pub").read_text(encoding="ascii").strip()
    assert proto.public_key_of(bytes.fromhex(aprivate_hex)) == apublic_hex
