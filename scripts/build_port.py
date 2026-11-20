#!/usr/bin/env python3
"""Build the handheld launchers in ports/ into their archives.

    RetroBIOS.zip            the PortMaster port (ports/RetroBIOS)
    RetroBIOS-batocera.zip   Batocera and Knulli, from Ports (ports/batocera)
    RetroBIOS.muxapp         muOS, from Applications (ports/muos)
    RetroBIOS-tools.zip      the Tools menu of ArkOS, dArkOS, ROCKNIX, JELOS
                             and AmberELEC (ports/tools)

Each carries ports/shared (tui.txt, which runs the full-screen interface,
rbevents.py and the controller mapping) beside its own launcher. The
PortMaster archive has the layout PortMaster's own release build gives a port
(PortMaster-New tools/build_release.py): the launch script at the top, and
one folder holding port.json, gameinfo.xml, the README as <name>.md, the
licenses and the port's files. A muOS application archive is extracted into
the applications folder, so its top folder is the application.

install.py is copied from the repository root, and only when it is the
installer the bootstraps pin, so every launcher runs the same bytes as the
one-line command of the same commit. The site builds them at each deploy
and serves them under get/handheld/ (scripts/sitegen/handheld.py): they are no
release files, and are written to tmp/handheld/ by default, away from the
packs of dist/. Members are written as the packs write
theirs: fixed timestamps, sorted names, the executable bit read from the
source, so the same tree gives the same archives.

Usage:
    python scripts/build_port.py
    python scripts/build_port.py --output-dir tmp/port   # default: tmp/handheld
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from core.hashing import file_digest
from core.artifacts import ArtifactLockBusy, artifact_lock
from core.paths import REPO_ROOT
from installer_build.port import ARCHIVES, build_archive


def main() -> int:
    parser = argparse.ArgumentParser(
        allow_abbrev=False, description="Build the RetroBIOS handheld launchers"
    )
    parser.add_argument("--output-dir", type=Path, default=REPO_ROOT / "tmp" / "handheld",
                        help="where the archives are written (default: tmp/handheld/)")
    args = parser.parse_args()
    try:
        with artifact_lock(str(args.output_dir)):
            paths = [build_archive(name, args.output_dir / name) for name in ARCHIVES]
    except (ArtifactLockBusy, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    for path in paths:
        digest = file_digest(path, "sha256")
        print(f"{path} ({path.stat().st_size} bytes, sha256 {digest})")
    return 0


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
