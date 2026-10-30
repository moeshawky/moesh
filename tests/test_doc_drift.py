"""Mechanical documentation and packaging drift verification gate.

Under the documentarian skill, every claim, version number, option flag, wire
constant, and citation must be mechanically verified against running code.
"""

from __future__ import annotations

import argparse
import pathlib
import re
from typing import Any

import tomllib

import moecp
import moesh
import moesh_relay
import moesh_shell
import moesh_tunnel
import moesh_wire

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_version_parity() -> None:
    """pyproject.toml, moesh.__version__, and CHANGELOG.md must declare identical versions."""
    pyproject_path = REPO_ROOT / "pyproject.toml"
    with open(pyproject_path, "rb") as f:
        pyproject = tomllib.load(f)

    project_version = pyproject["project"]["version"]
    assert project_version == moesh.__version__, (
        f"pyproject.toml ({project_version}) != moesh.__version__ ({moesh.__version__})"
    )

    changelog_path = REPO_ROOT / "CHANGELOG.md"
    changelog_text = changelog_path.read_text(encoding="utf-8")
    m = re.search(r"^##\s+([0-9a-zA-Z\.\-]+)\s+—", changelog_text, re.MULTILINE)
    assert m is not None, "CHANGELOG.md missing release section heading"
    changelog_version = m.group(1).strip()
    assert changelog_version == project_version, (
        f"CHANGELOG.md latest version ({changelog_version}) != pyproject.toml ({project_version})"
    )


def test_sdist_excludes_operator_artifacts() -> None:
    """Operator-only artifacts (HANDOFF.md, TEST-PROTOCOL.md) must not be packaged in sdist."""
    pyproject_path = REPO_ROOT / "pyproject.toml"
    with open(pyproject_path, "rb") as f:
        pyproject = tomllib.load(f)

    sdist_cfg = pyproject.get("tool", {}).get("hatch", {}).get("build", {}).get("targets", {}).get("sdist", {})
    includes = sdist_cfg.get("include", [])
    assert "HANDOFF.md" not in includes, "HANDOFF.md must not be included in sdist"
    assert "TEST-PROTOCOL.md" not in includes, "TEST-PROTOCOL.md must not be included in sdist"

    gitignore_path = REPO_ROOT / ".gitignore"
    gitignore_text = gitignore_path.read_text(encoding="utf-8")
    assert "HANDOFF.md" in gitignore_text, ".gitignore must ignore HANDOFF.md"
    assert "TEST-PROTOCOL.md" in gitignore_text, ".gitignore must ignore TEST-PROTOCOL.md"


def test_readme_pypi_links_have_no_broken_relatives() -> None:
    """README.md links must not contain relative markdown targets that 404 on PyPI."""
    readme_path = REPO_ROOT / "README.md"
    readme_text = readme_path.read_text(encoding="utf-8")

    # Match markdown links [text](target)
    links = re.findall(r"\[([^\]]+)\]\(([^)]+)\)", readme_text)
    github_prefix = "https://github.com/moeshawky/moesh/blob/master/"

    for label, target in links:
        if target.startswith("#"):
            continue
        if target.startswith("http://") or target.startswith("https://"):
            if target.startswith(github_prefix):
                rel_path = target[len(github_prefix):]
                # Strip any anchor
                file_rel = rel_path.split("#")[0]
                local_file = REPO_ROOT / file_rel
                assert local_file.exists(), f"README link {target} points to non-existent local file {file_rel}"
            continue
        if target.startswith("mailto:"):
            continue
        # Any bare relative link to a file is rejected for PyPI README safety
        assert not target.endswith(".md"), (
            f"README.md contains relative markdown link [{label}]({target}); "
            f"convert to full GitHub URL to prevent 404s on PyPI."
        )


def test_wire_and_moecp_constants_parity() -> None:
    """Authoritative constants in moesh_wire.py and moecp.py must match documented values."""
    assert moesh_wire.UPGRADE_TOKEN == "moesh-tunnel-v2"  # noqa: S105
    assert moesh_wire.PROTOCOL_VERSION == 2
    assert moesh_wire.PAIR_DEAD_MARKER == b"\x01MOESH_DEAD_TUNNEL\n"
    assert moesh_wire.MAX_DATA_PAYLOAD == 32768
    assert moesh_wire.MAX_CONTROL_PAYLOAD == 4096

    assert moecp.CHUNK_SIZE == 32768
    assert moecp.MAX_FRAME_HDR == 65536
    assert moecp.MAX_FRAME_PAYLOAD == 10485760

    # Ensure docs/configuration.md documents the exact same wire bounds
    config_path = REPO_ROOT / "docs" / "configuration.md"
    config_text = config_path.read_text(encoding="utf-8")
    assert "moecp stream chunk size | 32 KiB" in config_text
    assert "moecp max frame header | 64 KiB" in config_text
    assert "moecp max payload chunk | 10 MiB" in config_text


def _extract_argparse_options(mod: Any) -> set[str]:
    """Helper to extract option strings (--foo, -f) from a module's main parser without executing."""
    captured: set[str] = set()
    orig_parse_args = argparse.ArgumentParser.parse_args

    def mock_parse_args(self: argparse.ArgumentParser, args: Any = None, namespace: Any = None) -> Any:
        for action in self._actions:
            captured.update(action.option_strings)
        raise SystemExit(0)

    argparse.ArgumentParser.parse_args = mock_parse_args  # type: ignore[method-assign]
    try:
        mod.main([])
    except SystemExit:
        pass
    finally:
        argparse.ArgumentParser.parse_args = orig_parse_args  # type: ignore[method-assign]

    return captured


def test_cli_options_parity() -> None:
    """All CLI options defined in argument parsers must be documented in docs/cli.md."""
    cli_doc_path = REPO_ROOT / "docs" / "cli.md"
    cli_doc = cli_doc_path.read_text(encoding="utf-8")

    modules_to_check = [
        (moesh_shell, "moesh"),
        (moecp, "moecp"),
        (moesh_tunnel, "moesh-tunnel"),
        (moesh_relay, "moesh-relay"),
    ]

    for mod, tool_name in modules_to_check:
        options = _extract_argparse_options(mod)
        assert options, f"Failed to extract options for {tool_name}"
        for opt in options:
            if opt in ("-h", "--help"):
                continue
            assert opt in cli_doc, f"Option {opt} of {tool_name} ({mod.__name__}) is missing from docs/cli.md"


def test_source_line_citations_exist() -> None:
    """All file.py:line citations across markdown documentation must reference existing lines."""
    docs_dir = REPO_ROOT / "docs"
    md_files = [
        *docs_dir.glob("*.md"),
        REPO_ROOT / "README.md",
        REPO_ROOT / "PROTOCOL.md",
        REPO_ROOT / "SECURITY.md",
    ]

    # Match patterns like moesh_tunnel.py:123 or path/to/file.py:20-30
    citation_pattern = re.compile(r"(?:([a-zA-Z0-9_\-\./]+)/)?([a-zA-Z0-9_\-]+\.py):([0-9]+)")

    for md_file in md_files:
        if not md_file.exists():
            continue
        text = md_file.read_text(encoding="utf-8")
        for match in citation_pattern.finditer(text):
            dir_prefix = match.group(1) or ""
            py_filename = match.group(2)
            line_num = int(match.group(3))

            # External package references (e.g. noise/state.py from noiseprotocol)
            if dir_prefix == "noise":
                continue

            local_py = REPO_ROOT / py_filename
            assert local_py.exists(), (
                f"In {md_file.name}: citation to {match.group(0)} references non-existent file {py_filename}"
            )

            total_lines = len(local_py.read_text(encoding="utf-8").splitlines())
            assert line_num <= total_lines, (
                f"In {md_file.name}: citation to {match.group(0)} exceeds file length ({total_lines} lines)"
            )
