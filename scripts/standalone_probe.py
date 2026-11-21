#!/usr/bin/env python3
"""Run a platform's standalone emulator on a game and record what it did.

The libretro counterpart is core_probe.py: this script records the same way,
in the same measurements/<emulator>.jsonl, for the release binaries the
platforms install beside RetroArch.

  resolve  the release asset a platform's installer picks, by its own rule
  fetch    download it into .cache/standalone/, by sha256
  run      one execution, printed as JSON
  check    the same execution under several variants of one BIOS file

The binary is the asset the platform downloads, unpacked from its AppImage
without running it. Each repetition starts a private Xvfb, runs the emulator
in core_probe's allowlist sandbox under strace, and samples the screen at a
fixed interval from the X server's framebuffer file. The BIOS files are
staged in a directory the emulator's settings name as its BIOS folder, the
way the platform configures it, and the files it opened there come from
strace.

The verdict of a repetition is one of boots, bios_error, crash, hang or
unknown, by the oracle's rules: a reference screen reached, an error string
of the emulator in its log, the process dying, a uniform screen to the end.
"""

from __future__ import annotations

import argparse
import http.client
import json
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import core_probe as cp
from core import upstream
from core.paths import REPO_ROOT
from probes.appimage import fetch, github_releases, select_asset
from probes.standaloneemulators import EMULATORS, Emulator
from probes.standalonerecord import DEFAULT_WORK_DIR, Busy, RunFailed, measure, validate


def probe(args: argparse.Namespace) -> int:
    emu = EMULATORS[args.emulator]
    problems = validate(args)
    if problems:
        for problem in problems:
            print(f"ERROR: {problem}", file=sys.stderr)
        return 2
    # One run on the host at a time, as core_probe: the lock is held for
    # this run, its load check included, and freed when it ends.
    with cp.host_probe_lock():
        return _probe(args, emu)


def _probe(args: argparse.Namespace, emu: Emulator) -> int:
    try:
        record = measure(args, emu)
    except RunFailed as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except Busy as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3
    if args.record:
        try:
            lines, record = cp.write_record(Path(args.record), record)
        except cp.ProbeError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        print(f"recorded {lines}", file=sys.stderr)
    print(json.dumps(record, indent=2))
    return 0


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="mode", required=True)
    for name, text in (("resolve", "print the asset the platform's installer picks"),
                       ("fetch", "download and unpack it into .cache/standalone/")):
        p = sub.add_parser(name, help=text)
        p.add_argument("emulator", choices=sorted(EMULATORS), help="the emulator, by its profile name")
    common = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    common.add_argument("emulator", choices=sorted(EMULATORS), help="the emulator, by its profile name")
    common.add_argument("--content", required=True, help="the game: a .cue, .iso or .chd")
    common.add_argument("--content-label", help="identity of the content, its Redump or No-Intro name")
    common.add_argument("--bios-file", action="append", default=[], metavar="DEST=SRC",
                        type=lambda t: cp.parse_assignment(t, "--bios-file"),
                        help="copy SRC into the staged BIOS folder as DEST")
    common.add_argument("--setting", action="append", default=[], metavar="SECTION.KEY=VALUE",
                        type=lambda t: cp.parse_assignment(t, "--setting"),
                        help="an emulator setting written before the run")
    common.add_argument("--sha256", help="the fetched asset to run (default: the newest fetched)")
    common.add_argument("--samples", type=int, default=60, help="screen samples per repetition")
    common.add_argument("--interval", type=float, default=1.0, help="seconds between two samples")
    common.add_argument("--oracle", metavar="FILE",
                        help="the boot oracle (default: tests/campaign/oracle.yml, as core_probe)")
    common.add_argument("--png-dir", help="write each distinct sampled screen of repetition 0 as PNG")
    common.add_argument("--record", metavar="DIR", nargs="?", const=str(REPO_ROOT),
                        help="append the record to measurements/<emulator>.jsonl in the checkout DIR")
    common.add_argument("--subject", help="slug naming what the record tests")
    common.add_argument("--supersedes", metavar="ID", help="id of an earlier record this one corrects")
    common.add_argument("--max-load", type=float, default=None,
                        help="refuse to record above this 1-minute load average (default: CPUs / 4)")
    common.add_argument("--work-dir", default=str(DEFAULT_WORK_DIR), help="scratch directory")
    common.add_argument("--no-trace", action="store_true", help="do not run under strace")
    common.add_argument("--require-sandbox", action="store_true",
                        help="refuse to run unless bubblewrap can isolate the emulator")
    sub.add_parser("run", parents=[common], help="one execution")
    check = sub.add_parser("check", parents=[common], help="compare variants of one BIOS file")
    check.add_argument("--vary", action="append", required=True, metavar="DEST=SRC",
                       type=lambda t: cp.parse_assignment(t, "--vary"),
                       help="one variant per occurrence; an empty SRC leaves DEST absent")
    check.add_argument("--observable", default="verdict", help="compared across variants")
    check.add_argument("--claim", required=True, help="the statement under test")
    check.add_argument("--method", required=True, help="how the run tests it")
    check.add_argument("--repeat", type=int, default=2, help="runs of each variant")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    emu = EMULATORS[args.emulator]
    if args.mode == "resolve":
        try:
            releases = github_releases(emu.repo)
        except cp.ProbeError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        asset = select_asset(releases, emu.asset_endswith, emu.asset_contains)
        print(json.dumps({"emulator": emu.name, "platform": emu.platform,
                          "installer_ref": emu.installer_ref, "asset": asset}, indent=2))
        return 0 if asset else 1
    if args.mode == "fetch":
        try:
            print(json.dumps(fetch(emu), indent=2))
        except (cp.ProbeError, upstream.UpstreamError, OSError, http.client.HTTPException,
                subprocess.CalledProcessError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        return 0
    return probe(args)


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
