#!/usr/bin/env bash
# Clean-wheel smoke test.
#
# Installs the built wheel into a throwaway virtual environment *outside the
# checkout* and requires every advertised console script to answer.  The
# working directory matters: the bridge wrapper locates ``moesh-bridge.py``
# next to itself, so a wheel that forgot to ship it must fail here rather than
# silently fall back to the source tree.
#
# Usage: scripts/smoke_wheel.sh [wheel-directory]   (default: dist)
set -euo pipefail

wheel_dir="${1:-dist}"
wheel="$(ls -1 "${wheel_dir}"/moesh-*.whl | head -n 1)"
if [ -z "${wheel}" ]; then
    echo "smoke_wheel: no wheel in ${wheel_dir}" >&2
    exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

python3 -m venv "${work}/venv"
"${work}/venv/bin/pip" install --quiet "${wheel}"

cd "${work}"

status=0
for ep in moesh moecp moesh-tunnel moesh-relay moesh-bridge; do
    printf '%-14s ' "${ep}"
    if timeout 60 "${work}/venv/bin/${ep}" --help >/dev/null 2>"${work}/${ep}.err"; then
        echo "ok"
    else
        echo "FAILED"
        tail -n 5 "${work}/${ep}.err" >&2
        status=1
    fi
done

"${work}/venv/bin/python" - <<'PY'
import moecp
import moesh
import moesh_bridge
import moesh_proto

print("import ok:", moesh.__version__, moesh.__file__)
print("bridge module:", moesh_bridge.__file__)
PY

exit "${status}"
