#!/usr/bin/env sh
# apkdec first-run installer for macOS / Linux.
#
#   sh scripts/install.sh        (or: ./scripts/install.sh)
#
# - verifies Python 3.8+
# - installs the `apkdec` command (pipx if available, else pip --user / venv)
# - runs a health check
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

echo "==> apkdec installer (macOS / Linux)"

# Find a working Python 3.8+
PY=""
for c in python3 python; do
    if command -v "$c" >/dev/null 2>&1 && \
       "$c" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3, 8) else 1)' >/dev/null 2>&1; then
        PY="$c"
        break
    fi
done
if [ -z "$PY" ]; then
    echo "Error: Python 3.8+ not found." >&2
    echo "Install it from https://www.python.org/ (or 'brew install python') and re-run." >&2
    exit 1
fi
echo "    Python: $("$PY" --version 2>&1)  ($(command -v "$PY"))"

# Choose the best install method.
IN_VENV=$("$PY" -c 'import sys; print("1" if sys.prefix != sys.base_prefix else "")')
if [ -n "$IN_VENV" ]; then
    echo "    Detected active virtual environment; installing into it."
    "$PY" -m pip install --upgrade "$ROOT"
elif command -v pipx >/dev/null 2>&1; then
    echo "    Installing with pipx (isolated, auto-PATH)."
    pipx install --force "$ROOT"
else
    echo "    Installing with pip --user."
    "$PY" -m pip install --user --upgrade "$ROOT"
fi

# Decide how to invoke it for the health check / hints.
if command -v apkdec >/dev/null 2>&1; then
    RUN="apkdec"
else
    RUN="$PY -m apkdec"
    echo
    echo "Note: the 'apkdec' command is not on your PATH yet."
    echo "      Add your user scripts dir to PATH (pip prints its location),"
    echo "      or simply run:  $PY -m apkdec"
fi

echo
echo "==> Health check"
$RUN doctor || true

echo
echo "==> Done. Try:"
echo "      $RUN wizard            # interactive menu"
echo "      $RUN info  app.apk     # quick inspect"
echo "      $RUN scan  app.apk     # security review"
