#!/bin/sh
set -eu

# One-line bootstrap and local wrapper. The downloaded installer is accepted
# only when it matches the SHA-256 embedded in this wrapper.
INSTALLER=""
# When sourced from stdin, $0 is the shell name and the working directory is
# not a trusted location for install.py. Reuse an adjacent installer only for
# an actual local install.sh invocation.
case "$0" in
  install.sh|*/install.sh)
    if [ -f "$0" ]; then
      SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
      INSTALLER="$SCRIPT_DIR/install.py"
    fi
    ;;
esac
TEMP_INSTALLER=""
TEMP_DIRECTORY=""
DEFAULT_INSTALL_URL="https://raw.githubusercontent.com/Abdess/retrobios/main/install.py"
DEFAULT_INSTALL_SHA256="3ea3a3e21012cc2dbf24c08a0ad314233ade04e62c0d2164b76146f1b361d714"
MAX_INSTALLER_BYTES=2097152

cleanup() {
  if [ -n "$TEMP_INSTALLER" ] && [ -f "$TEMP_INSTALLER" ]; then
    rm -f -- "$TEMP_INSTALLER"
  fi
  if [ -n "$TEMP_DIRECTORY" ] && [ -d "$TEMP_DIRECTORY" ]; then
    rmdir -- "$TEMP_DIRECTORY" 2>/dev/null || true
  fi
}
trap cleanup EXIT HUP INT TERM

if [ -z "$INSTALLER" ] || [ ! -f "$INSTALLER" ]; then
  install_url=${RETROBIOS_INSTALL_URL:-$DEFAULT_INSTALL_URL}
  expected=${RETROBIOS_INSTALL_SHA256:-$DEFAULT_INSTALL_SHA256}
  case "$install_url" in
    https://*) ;;
    *) echo "Error: installer URL must use HTTPS." >&2; exit 1 ;;
  esac
  case "$expected" in
    *[!0-9A-Fa-f]*)
      echo "Error: installer SHA-256 must contain exactly 64 hexadecimal characters." >&2
      exit 1
      ;;
  esac
  if [ "${#expected}" -ne 64 ]; then
    echo "Error: installer SHA-256 must contain exactly 64 hexadecimal characters." >&2
    exit 1
  fi
  TEMP_DIRECTORY=$(mktemp -d)
  TEMP_INSTALLER="$TEMP_DIRECTORY/install.py"
  if command -v curl >/dev/null 2>&1; then
    curl --fail --location --proto '=https' --tlsv1.2 \
      "$install_url" --output "$TEMP_INSTALLER"
  elif command -v wget >/dev/null 2>&1; then
    wget --https-only --output-document="$TEMP_INSTALLER" "$install_url"
  else
    echo "Error: curl or wget is required to download the installer." >&2
    echo "  On Debian or Ubuntu: sudo apt install curl" >&2
    exit 1
  fi
  actual_size=$(wc -c < "$TEMP_INSTALLER" | tr -d ' ')
  if [ "$actual_size" -gt "$MAX_INSTALLER_BYTES" ]; then
    echo "Error: downloaded installer exceeds the size limit." >&2
    exit 1
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$TEMP_INSTALLER" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "$TEMP_INSTALLER" | awk '{print $1}')
  else
    echo "Error: sha256sum or shasum is required." >&2
    exit 1
  fi
  expected=$(printf '%s' "$expected" | tr '[:upper:]' '[:lower:]')
  if [ "$actual" != "$expected" ]; then
    echo "Error: the downloaded installer does not match its expected fingerprint." >&2
    echo "  Nothing was run and nothing was written." >&2
    echo "  The download was most likely cut short. Try again, on another network if possible." >&2
    exit 1
  fi
  INSTALLER="$TEMP_INSTALLER"
fi

PYTHON=""
for command_name in python3 python; do
  if command -v "$command_name" >/dev/null 2>&1 \
    && "$command_name" -c 'import sys; raise SystemExit(sys.version_info < (3, 8))' 2>/dev/null; then
    PYTHON=$command_name
    break
  fi
done
if [ -z "$PYTHON" ]; then
  echo "Error: Python 3.8 or newer is required." >&2
  echo "  Install it, then run this command again. On Debian or Ubuntu: sudo apt install python3" >&2
  exit 1
fi

"$PYTHON" "$INSTALLER" "$@"
