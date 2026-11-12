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
# What a refused installer most likely means for this copy. The copy the
# site serves reads a commit's installer, which no cache serves stale, and
# curl or wget stop on a cut transfer before the hash is read: the site's
# build rewrites this line there (scripts/sitebootstrap.py).
MISMATCH_ADVICE="The download was most likely cut short: try again. Within minutes of an update of this project the two files can come from caches of different ages. Waiting five minutes settles that."
DEFAULT_INSTALL_SHA256="4b8e2e8e5343dbf75f6c9b089993cce3b7f64ad1e7a5a6c91993a07ec9674bc6"
# The pin above refuses any changed byte: this cap only stops a body that
# cannot be the installer (a sign-in portal's page) before it is hashed.
MAX_INSTALLER_BYTES=8388608

cleanup() {
  if [ -n "$TEMP_INSTALLER" ] && [ -f "$TEMP_INSTALLER" ]; then
    rm -f -- "$TEMP_INSTALLER"
  fi
  if [ -n "$TEMP_DIRECTORY" ] && [ -d "$TEMP_DIRECTORY" ]; then
    rmdir -- "$TEMP_DIRECTORY" 2>/dev/null || true
  fi
}
# A signal ends the run with the code a shell gives it, 130 for Ctrl+C:
# trapped by cleanup alone, the run went on, and Ctrl+C during the download
# was told as a network failure, with code 1.
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

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
  # Quiet but for the error line: a progress table followed by
  # "curl: (6) ..." and curl's own exit code told nobody what failed.
  if command -v curl >/dev/null 2>&1; then
    fetch() {
      curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
        --connect-timeout 30 --retry 2 "$install_url" --output "$TEMP_INSTALLER"
    }
  elif command -v wget >/dev/null 2>&1; then
    # BusyBox wget (Alpine, the RomM image) has no --https-only and refuses
    # the whole command over it (networking/wget.c wget_longopts). The URL
    # itself is checked to be https above, and the SHA-256 below decides.
    https_only=""
    if wget --help 2>&1 | grep -q -- '--https-only'; then
      https_only="--https-only"
    fi
    fetch() {
      wget --quiet ${https_only:+"$https_only"} --timeout=30 --tries=3 \
        --output-document="$TEMP_INSTALLER" "$install_url"
    }
  else
    echo "Error: curl or wget is required to download the installer." >&2
    echo "  On Debian or Ubuntu: sudo apt install curl" >&2
    exit 1
  fi
  if ! fetch_error=$(fetch 2>&1); then
    echo "Error: the installer could not be downloaded from $install_url" >&2
    echo "  $(printf '%s\n' "$fetch_error" | tail -n 1)" >&2
    echo "  Check the network connection, and HTTPS_PROXY if this network needs a proxy," >&2
    echo "  then run the same command again. Nothing was run and nothing was written." >&2
    exit 1
  fi
  actual_size=$(wc -c < "$TEMP_INSTALLER" | tr -d ' ')
  if [ "$actual_size" -gt "$MAX_INSTALLER_BYTES" ]; then
    # A page served in place of the file says the network answered, not this
    # project: the one cause a user can act on.
    echo "Error: the downloaded installer is $actual_size bytes, more than the $MAX_INSTALLER_BYTES this script accepts." >&2
    echo "  Nothing was run and nothing was written. A network that answers with a page of" >&2
    echo "  its own (a sign-in portal, a proxy) gives this: open any web page to sign in," >&2
    echo "  then run the same command again." >&2
    if [ -n "${RETROBIOS_INSTALL_URL:-}" ]; then
      echo "  RETROBIOS_INSTALL_URL is set in this environment and names another installer:" >&2
      echo "  unset it to use the installer this script names." >&2
    fi
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
    overrides=""
    [ -n "${RETROBIOS_INSTALL_URL:-}" ] && overrides="RETROBIOS_INSTALL_URL"
    if [ -n "${RETROBIOS_INSTALL_SHA256:-}" ]; then
      overrides="${overrides:+$overrides and }RETROBIOS_INSTALL_SHA256"
    fi
    if [ -n "$overrides" ]; then
      # A pin or a URL of the user's own refuses the installer: retrying,
      # as the advice below says, would never help.
      echo "  $overrides is set in this environment and decides which installer is" >&2
      echo "  accepted: unset it to use the installer this script names, or set it to match." >&2
      exit 1
    fi
    echo "  $MISMATCH_ADVICE" >&2
    exit 1
  fi
  INSTALLER="$TEMP_INSTALLER"
fi

# A Python can be built without ssl, unicodedata or zlib, and the installer
# needs all three: a python3 lacking ssl was chosen over a full python and
# every download then failed as if the network were down.
# A python3.X on PATH counts too, newest first: Buster and Ubuntu 18.04
# keep python3 at 3.7 or 3.6 beside the python3.8 the advice below has the
# user install, and the same advice looped.
versioned_pythons() {
  (
    IFS=:
    for dir in $PATH; do
      for path in "$dir"/python3.[0-9]*; do
        [ -x "$path" ] && basename -- "$path"
      done
    done
  ) | grep -E '^python3\.[0-9]+$' | sort -t . -k 2,2nr -u
}

find_python() {
  PYTHON=""
  PYTHON_LACKING=""
  PYTHON_OLD=""
  for command_name in python3 python $(versioned_pythons); do
    command -v "$command_name" >/dev/null 2>&1 || continue
    if ! "$command_name" -c 'import sys; raise SystemExit(sys.version_info < (3, 8))' \
        2>/dev/null; then
      found_version=$("$command_name" -c \
        'import sys; print("%d.%d.%d" % tuple(sys.version_info[:3]))' 2>/dev/null)
      if [ -n "$found_version" ]; then
        PYTHON_OLD=${PYTHON_OLD:-"$command_name here is $found_version"}
      fi
      continue
    fi
    if "$command_name" -c 'import ssl, unicodedata, zlib' 2>/dev/null; then
      PYTHON=$command_name
      return 0
    fi
    PYTHON_LACKING=${PYTHON_LACKING:-$command_name}
  done
  return 1
}

# The command that installs Python here, named for this system: Termux has
# no sudo and installs with pkg, macOS has no apt.
python_install_command() {
  case "${TERMUX_VERSION:-}:${PREFIX:-}" in
    ?*:*|*com.termux*) echo "pkg install python"; return ;;
  esac
  if [ "$(uname -s 2>/dev/null)" = "Darwin" ]; then
    echo "xcode-select --install"
    return
  fi
  os_ids=""
  if [ -r /etc/os-release ]; then
    os_ids=$(sed -n 's/^ID\(_LIKE\)\{0,1\}=//p' /etc/os-release | tr -d '"' | tr '\n' ' ')
  fi
  for os_id in $os_ids; do
    case "$os_id" in
      debian|ubuntu) echo "sudo apt install python3"; return ;;
      fedora|rhel|centos) echo "sudo dnf install python3"; return ;;
      arch) echo "sudo pacman -S python"; return ;;
      opensuse*|suse) echo "sudo zypper install python3"; return ;;
      alpine) echo "apk add python3"; return ;;
    esac
  done
  echo ""
}

if ! find_python; then
  install_command=$(python_install_command)
  # Termux installs without root: at a terminal, the bootstrap offers to run it.
  if [ "$install_command" = "pkg install python" ] && (: </dev/tty) 2>/dev/null; then
    printf 'Python 3.8 or newer is required. Install it now with "%s"? [Y/n] ' \
      "$install_command" >/dev/tty
    read -r answer </dev/tty || answer="n"
    case "$answer" in
      [Nn]*) ;;
      *) pkg install -y python </dev/tty && find_python || true ;;
    esac
  fi
fi
if [ -z "$PYTHON" ] && [ -n "$PYTHON_LACKING" ]; then
  echo "Error: $PYTHON_LACKING is built without a module the installer needs" >&2
  echo "  (ssl, unicodedata or zlib). Run it with a full Python 3.8 or newer." >&2
  exit 1
fi
if [ -z "$PYTHON" ] && [ -n "$PYTHON_OLD" ]; then
  # Debian Buster ships 3.7: apt answers that python3 is already the newest
  # version, and the same advice looped.
  echo "Error: Python 3.8 or newer is required, and $PYTHON_OLD." >&2
  echo "  Install a newer one: from this system's packages if they offer one, by" >&2
  echo "  updating the system, or from https://www.python.org/downloads/." >&2
  echo "  Then run this command again." >&2
  exit 1
fi
if [ -z "$PYTHON" ]; then
  echo "Error: Python 3.8 or newer is required." >&2
  if [ -n "$install_command" ]; then
    echo "  Install it with: $install_command" >&2
    echo "  Then run this command again." >&2
  else
    echo "  Install it with this system's package manager, then run this command again." >&2
  fi
  exit 1
fi

# Termux reaches shared storage, where RetroArch keeps its system folder,
# once termux-setup-storage has run: the installer told the user to run it
# and start again. At a terminal the bootstrap runs it here. It only asks
# the Termux app, which shows Android's permission dialog and creates
# ~/storage once allowed: the wait gives the user time to answer.
case "${TERMUX_VERSION:-}:${PREFIX:-}" in
  ?*:*|*com.termux*)
    if [ ! -d "$HOME/storage" ] && command -v termux-setup-storage >/dev/null 2>&1 \
      && (: </dev/tty) 2>/dev/null; then
      echo "Android asks for the storage permission: allow it, so that the files reach" >/dev/tty
      echo "the RetroArch folder." >/dev/tty
      termux-setup-storage </dev/tty >/dev/tty 2>&1 || true
      waited=0
      while [ ! -d "$HOME/storage" ] && [ "$waited" -lt 60 ]; do
        sleep 1
        waited=$((waited + 1))
      done
    fi
    ;;
esac

# Piped from curl, standard input is this script, not the terminal: the
# installer would skip every question it can ask. Hand it the terminal when
# there is one.
# A downloaded installer is a temporary copy the user cannot run again: its
# hints rebuild the one-line command instead.
if [ -n "$TEMP_INSTALLER" ]; then
  RETROBIOS_BOOTSTRAP=sh
  export RETROBIOS_BOOTSTRAP
fi
if [ ! -t 0 ] && (: </dev/tty) 2>/dev/null; then
  "$PYTHON" "$INSTALLER" "$@" </dev/tty
else
  "$PYTHON" "$INSTALLER" "$@"
fi
