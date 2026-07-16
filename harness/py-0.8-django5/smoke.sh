#!/bin/sh
# Local smoke for this entry, no containers: build a throwaway venv with the
# entry's exact pins (valiss from the frozen v0.8.0 tag, Django and
# cryptography per pyproject.toml) and run smoke_test.py, which starts the
# server and drives every applicable scenario from scenarios.yaml over HTTP.
#
# The interpreter defaults to the series the entry's container image
# enforces; when it is absent locally the smoke falls back to python3 and
# says so — the Dockerfile still pins the real one. Override with PYTHON=.
set -eu

entry_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

python=${PYTHON:-python3.13}
if ! command -v "$python" >/dev/null 2>&1; then
    echo "smoke: $python not found; falling back to python3 (the container image enforces $python)" >&2
    python=python3
fi

workdir=$(mktemp -d "${TMPDIR:-/tmp}/valiss-smoke.XXXXXX")
trap 'rm -rf "$workdir"' EXIT

"$python" -m venv "$workdir/venv"
"$workdir/venv/bin/pip" install --quiet \
    "valiss @ git+https://github.com/valiss-dev/valiss-py@v0.8.0" \
    "$entry_dir" \
    pyyaml
exec "$workdir/venv/bin/python" "$entry_dir/smoke_test.py"
