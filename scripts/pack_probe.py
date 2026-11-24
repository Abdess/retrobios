#!/usr/bin/env python3
"""Test a platform's pack the way a user installs it.

For one platform, the probe lays the platform's BIOS folder out in a scratch
root, in one or both of the ways a user gets it:

  pack       the pack generate_pack.py builds for the platform, extracted
  installer  install.py --dest on the scratch root, from that pack and the
             published manifest (install/<platform>.json), with no network

Then for each system a test game covers (campaign/content.yml and
campaign/pack_content.yml), it resolves the libretro cores the platform
runs for that system (platform config, target file, standalone and dual-mode
lists), and runs the game through core_probe.py with the system directory
taken from that layout.

core_probe copies what it stages, so the probe stages the files the core can
reach rather than the whole folder: the files the core's profile and the
platform's list declare, every file beside them in their directory, and for
a core that finds its BIOS by content, every root file of a size it accepts.
A file the core then looks for that the layout holds is staged and the run
repeated, until the core asks for nothing more the layout has.

Each run is a core_probe record in measurements/<emulator>.jsonl and one line
of measurements/pack-probes.jsonl naming the platform, the pack or manifest,
the verdict, every file the core opened mapped to the pack entry that put it
there, and the findings: a file the core looked for that the layout lacks,
or holds under another path.

Each core_probe run holds the host's probe lock (~/.local/state/retrobios/
probe.lock, RETROBIOS_PROBE_LOCK) and releases it before the next: other
probes run between ours. core_probe is told it is held
(RETROBIOS_PROBE_LOCK_HELD). Building and extracting the pack take no lock.

Usage:
    python scripts/pack_probe.py run --platform retroarch [--system sony-playstation]
    python scripts/pack_probe.py plan --platform batocera
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from model.cliargs import platform_arg, require_platform
from core.cli import run_cli
from core.paths import REPO_ROOT
from probes.packlayout import ProbeFailure
from probes.packprobe import EXIT_BUSY, TARGETS, run

WORK_DIR = REPO_ROOT / "tmp" / "pack_probe"
INSTALLS = ("pack", "installer")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mode", choices=("run", "plan"),
                        help="run: lay the folder out and start the games. plan: print the "
                             "systems, games and cores, run nothing")
    parser.add_argument("--platform", "-p", required=True, type=platform_arg,
                        help=f"the platform whose pack is tested: {', '.join(sorted(TARGETS))}")
    parser.add_argument("--system", dest="systems", action="append", default=[],
                        help="only this system (repeat)")
    parser.add_argument("--core", dest="cores", action="append", default=[],
                        help="only this core, by buildbot name or profile (repeat)")
    parser.add_argument("--install", action="append", choices=INSTALLS, default=[],
                        help="pack, installer or both (default both)")
    parser.add_argument("--pack", help="a pack already built for the platform, instead of building one")
    parser.add_argument("--fetch", action="store_true", help="fetch a missing game through romfetch")
    parser.add_argument("--refresh-cores", action="store_true", help="download the nightlies again")
    parser.add_argument("--keep", action="store_true", help="keep the extracted layouts")
    parser.add_argument("--work-dir", default=str(WORK_DIR),
                        help="where the pack is built and laid out (default tmp/pack_probe)")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    require_platform(args.platform, str(REPO_ROOT / "platforms"))
    if args.platform not in TARGETS:
        print(f"ERROR: pack_probe tests {', '.join(sorted(TARGETS))}, not {args.platform}",
              file=sys.stderr)
        return 2
    args.systems = set(args.systems) or None
    args.cores = set(args.cores) or None
    args.install = args.install or list(INSTALLS)
    try:
        return run(args)
    except ProbeFailure as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_BUSY if "busy host" in str(exc) else 1


if __name__ == "__main__":
    run_cli(main)
