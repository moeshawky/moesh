"""moesh_bridge — Importable bridge module and console_scripts entry point."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

# Exactly one location: the directory this module was imported from.  The
# wheel force-includes moesh-bridge.py beside this wrapper, and in a source
# checkout the two files sit together as well.  Searching the working
# directory or /usr/local/bin instead would let a stale copy elsewhere on the
# box answer for this install, which is undeclared filesystem state.
_script_path = Path(__file__).resolve().parent / "moesh-bridge.py"
if not _script_path.is_file():
    raise ImportError(
        f"Cannot locate 'moesh-bridge.py' next to {__file__}: {_script_path} "
        "does not exist.  Reinstall the package (the file must ship beside "
        "moesh_bridge.py) or run moesh-bridge.py from the source checkout."
    )

_spec = importlib.util.spec_from_file_location("moesh_bridge_impl", _script_path)
if _spec is None or _spec.loader is None:
    raise ImportError(f"Cannot load bridge module from {_script_path}")
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

# Re-export public attributes from moesh-bridge.py
for _k, _v in _mod.__dict__.items():
    if not _k.startswith("__"):
        globals()[_k] = _v


def main(argv: list[str] | None = None) -> int:
    """Console script entry point for moesh-bridge."""
    entry = getattr(_mod, "main", None)
    if entry is None:
        sys.stderr.write("moesh-bridge: entry point main() not found\n")
        return 1
    return int(entry(argv))


if __name__ == "__main__":
    sys.exit(main())
