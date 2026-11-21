"""The standalone_probe modes: resolve and fetch the asset, run or check it under the probe lock."""

from __future__ import annotations

import argparse
import http.client
import json
import subprocess
import sys
from pathlib import Path

import core_probe as cp
from core import upstream
from probes.appimage import fetch, github_releases, select_asset
from probes.standaloneemulators import EMULATORS, Emulator
from probes.standalonerecord import Busy, RunFailed, measure, validate


def run_mode(args: argparse.Namespace) -> int:
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
