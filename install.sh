#!/bin/sh
set -e
REPO="https://raw.githubusercontent.com/Abdess/retrobios/main"
SCRIPT=$(mktemp)
trap 'rm -f "$SCRIPT"' EXIT
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$REPO/install.py" -o "$SCRIPT"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$SCRIPT" "$REPO/install.py"
else
  echo "Error: curl or wget required" >&2; exit 1
fi
PYTHON=""
for cmd in python3 python; do
  if command -v "$cmd" >/dev/null 2>&1; then PYTHON="$cmd"; break; fi
done
if [ -z "$PYTHON" ]; then
  echo "Error: Python 3 required" >&2; exit 1
fi
"$PYTHON" "$SCRIPT" "$@"
