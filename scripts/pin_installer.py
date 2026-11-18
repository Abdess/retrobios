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
import sys
from installer_build.pins import COMMAND, INSTALLER, installer_sha256, stale_pins, write_pins


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
    from core.cli import run_cli

    run_cli(main)
