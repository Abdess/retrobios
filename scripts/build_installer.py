#!/usr/bin/env python3
"""Build install.py from the installer/ package.

install.py ships as one file that needs nothing but the standard library:
the one-line bootstraps, install.sh and install.ps1 pin its SHA-256, and the
portable launchers and the PyPI package carry it as is. Its source is the
installer/ package, one module per concern, each importing from the others
what it uses, so ruff and mypy read every module on its own.

This script joins the modules into one namespace, in the order their imports
give: the package docstring, one block of standard library imports, then each
module body with its imports taken out. It refuses what one namespace cannot
hold: an import from outside the standard library, a name defined by two
modules, an import cycle, an import under another name, and a statement run
at import time that reads a name from a module placed after its own.

Usage:
    python scripts/build_installer.py          # write install.py
    python scripts/build_installer.py --check  # exit 1 if install.py differs
"""

from __future__ import annotations

import argparse
import sys

from core.artifacts import write_text_atomic
from installer_build.amalgamate import BuildError, COMMAND, OUTPUT, PACKAGE, ROOT, build


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Build install.py from the installer/ package.")
    parser.add_argument("--check", action="store_true",
                        help="write nothing, exit 1 if install.py differs from what the package builds")
    args = parser.parse_args(argv)
    try:
        text = build(ROOT / PACKAGE)
    except BuildError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    target = ROOT / OUTPUT
    current = target.read_text(encoding="utf-8") if target.exists() else ""
    if args.check:
        if current != text:
            print(f"{OUTPUT} differs from what {PACKAGE}/ builds: run {COMMAND}", file=sys.stderr)
            return 1
        print(f"{OUTPUT} is built from {PACKAGE}/")
        return 0
    if current == text:
        print(f"{OUTPUT} unchanged")
        return 0
    write_text_atomic(str(target), text)
    print(f"wrote {OUTPUT}")
    return 0


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
