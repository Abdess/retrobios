#!/usr/bin/env python3
"""Write the SHA-256 of install.py into the bootstraps that pin it.

install.sh and install.ps1 refuse an installer whose hash is not the one
they carry, so every change to install.py moves both pins in the same
commit. --check writes nothing and exits 1 naming each stale pin.

Usage:
    python scripts/pin_installer.py
    python scripts/pin_installer.py --check
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INSTALLER = "install.py"
# Each bootstrap and its one pin line, the value between the two groups.
PINS: dict[str, re.Pattern[str]] = {
    "install.sh": re.compile(r'^(DEFAULT_INSTALL_SHA256=")[0-9a-f]{64}(")', re.M),
    "install.ps1": re.compile(r'^(\s*\$defaultInstallSha256 = ")[0-9a-f]{64}(")', re.M),
}
COMMAND = "python scripts/pin_installer.py"


def installer_sha256(root: Path = ROOT) -> str:
    return hashlib.sha256((root / INSTALLER).read_bytes()).hexdigest()


def stale_pins(root: Path = ROOT) -> list[str]:
    """The bootstraps whose pin is not the SHA-256 of install.py."""
    digest = installer_sha256(root)
    stale = []
    for name, pin in PINS.items():
        found = pin.search((root / name).read_bytes().decode("utf-8"))
        if found is None:
            raise ValueError(f"{name}: no installer pin line")
        if found.group(0) != f"{found.group(1)}{digest}{found.group(2)}":
            stale.append(name)
    return stale


def write_pins(root: Path = ROOT) -> list[str]:
    """Rewrite each stale pin. Returns the bootstraps written."""
    digest = installer_sha256(root)
    written = []
    for name in stale_pins(root):
        path = root / name
        text = path.read_bytes().decode("utf-8")
        new, count = PINS[name].subn(rf"\g<1>{digest}\g<2>", text)
        if count != 1:
            raise ValueError(f"{name}: {count} installer pin lines, expected 1")
        path.write_bytes(new.encode("utf-8"))
        written.append(name)
    return written


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true",
                        help="write nothing, exit 1 if a pin is stale")
    args = parser.parse_args()
    if args.check:
        stale = stale_pins()
        for name in stale:
            print(f"{name}: pin is not the SHA-256 of {INSTALLER}, {COMMAND} writes it",
                  file=sys.stderr)
        return 1 if stale else 0
    for name in write_pins():
        print(f"{name}: pinned {installer_sha256()}")
    return 0


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
