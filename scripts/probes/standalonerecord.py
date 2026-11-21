"""The measurement record of a standalone run or check, and its options' checks."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import core_probe as cp
from core.paths import REPO_ROOT
from core.statefile import now_iso
from model.measurements import canonical, sha256_hex, slugify
from probes.appimage import installed
from probes.standaloneemulators import Emulator, emulator_settings
from probes.standalonerun import check_result, emulator_oracle, run_variant

DEFAULT_WORK_DIR = REPO_ROOT / "tmp" / "standalone_probe"
RECORD_VERSION = 4
OBSERVABLES = ("verdict", "screens", "frame_hashes", "uniform_frames")
SCRIPT = "scripts/standalone_probe.py"
SCRIPT_PATH = REPO_ROOT / SCRIPT
# The files that hold the code of a run: a record from a checkout where one
# of them differs from the commit says so.
CODE_FILES = (SCRIPT, "scripts/probes/standaloneemulators.py", "scripts/probes/appimage.py",
              "scripts/probes/xvfb.py", "scripts/probes/standalonerun.py",
              "scripts/probes/standalonerecord.py")


class RunFailed(Exception):
    """The emulator could not be run: no fetched asset, a sandbox or a
    staging failure."""


class Busy(Exception):
    """The host's load is past the threshold a recorded run accepts."""


def frontend_identity() -> dict:
    """core_probe's frontend identity of the command, modified when any file
    that holds the run's code differs from the commit."""
    identity = cp.frontend_identity(SCRIPT_PATH, SCRIPT)
    if identity["script_modified"] is False:
        try:
            status = subprocess.run(["git", "status", "--porcelain", "--", *CODE_FILES], cwd=REPO_ROOT,
                                    capture_output=True, text=True, check=True).stdout
        except (OSError, subprocess.CalledProcessError) as exc:
            print(f"WARNING: frontend state unknown, git failed: {exc}", file=sys.stderr)
            identity["script_modified"] = None
        else:
            identity["script_modified"] = bool(status.strip())
    return identity


def _variants(args: argparse.Namespace) -> list[cp.Variant]:
    if args.mode != "check":
        return [cp.Variant("default")]
    variants = []
    seen: set[str] = set()
    for dest, src in args.vary:
        label = Path(src).name if src else f"{dest}-absent"
        while label in seen:
            label += "+"
        seen.add(label)
        variants.append(cp.Variant(label, {dest: Path(src) if src else None}))
    return variants


def _run_variants(args: argparse.Namespace, emu: Emulator, tree: Path, oracle: dict,
                  repetitions: int) -> list[dict]:
    base = {dest: Path(src) for dest, src in args.bios_file}
    work = Path(tempfile.mkdtemp(prefix=f"{args.mode}-", dir=cp._ensure(Path(args.work_dir))))
    try:
        return [run_variant(args, emu, tree, oracle, base, variant, work / f"v{i}", repetitions)
                for i, variant in enumerate(_variants(args))]
    except (cp.ProbeError, OSError, subprocess.SubprocessError) as exc:
        raise RunFailed(exc) from exc
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _subject(args: argparse.Namespace, record: dict, sha256: str) -> str:
    if args.subject:
        return args.subject
    if args.mode == "check":
        digest = sha256_hex(canonical([args.claim, args.method, args.observable, args.vary[0][0]]))[:8]
        return f"{slugify(args.claim)}-{digest}"
    digest = sha256_hex(canonical([sha256, record["inputs"]["content"],
                                   record["inputs"]["options"], args.bios_file]))[:8]
    return f"run-{slugify(args.content_label or Path(args.content).name, 30)}-{digest}"


def measure(args: argparse.Namespace, emu: Emulator) -> dict:
    """Run the emulator on the content as the options ask and return the
    record, not yet written. Raises RunFailed or Busy."""
    try:
        meta, tree = installed(emu, args.sha256)
    except (cp.ProbeError, OSError, subprocess.SubprocessError) as exc:
        raise RunFailed(exc) from exc
    max_load = args.max_load if args.max_load is not None else (os.cpu_count() or 1) / 4
    load_before = cp.load_average()
    if args.record and load_before and load_before[0] > max_load:
        raise Busy(f"load average {load_before[0]} exceeds {max_load}: the machine is busy, "
                   f"nothing recorded")
    oracle = emulator_oracle(emu, Path(args.oracle) if args.oracle else cp.DEFAULT_ORACLE,
                             cp.file_digest(Path(args.content)))
    repetitions = 1 if args.mode == "run" else args.repeat
    variants = _run_variants(args, emu, tree, oracle, repetitions)
    load_after = cp.load_average()
    record: dict = {
        "record_version": RECORD_VERSION,
        "emulator": emu.name,
        "subject": None,
        "supersedes": args.supersedes,
        "kind": args.mode,
        "recorded_at": now_iso(),
        "core": {"file": meta["name"], "sha256": meta["sha256"], "repo": f"https://github.com/{meta['repo']}",
                 "commit": None, "build_command": None, "compiler": None, "library_name": emu.name,
                 "library_version": meta["tag"], "artifact": meta["url"]},
        "frontend": frontend_identity(),
        "host": {**cp.host_identity(), "load_before": load_before, "load_after": load_after,
                 "max_load": max_load},
        "inputs": {
            "content": cp.content_identity(Path(args.content), args.content_label),
            "options": {f"{s}.{k}": v for s, values in
                        emulator_settings(emu, Path("<bios>"), args.setting).items() for k, v in values.items()},
            "env": {},
            "frames": args.samples,
            "warmup": 0,
            "repetitions": repetitions,
            "presses": [],
            "observables": list(OBSERVABLES),
            "frame_hash_every": 1,
            "joypad_ports": 0,
            "oracle": oracle,
        },
        "variants": variants,
        "flags": [f"{v['label']}: {flag}" for v in variants for flag in v["flags"]],
    }
    if load_before and load_after and max(load_before[0], load_after[0]) > max_load:
        record["flags"].append(f"load average reached {max(load_before[0], load_after[0])} "
                               f"(threshold {max_load})")
    if args.mode == "check":
        record["check"] = {"claim": args.claim, "method": args.method, "observable": args.observable,
                           "variable": args.vary[0][0], "result": check_result(variants, args.observable)}
    record["subject"] = _subject(args, record, meta["sha256"])
    return record


def _check_mode_problems(args: argparse.Namespace) -> list[str]:
    problems = []
    if len({dest for dest, _ in args.vary}) != 1:
        problems.append("--vary must name the same DEST in every occurrence")
    problems.extend(f"--vary {dest}={src}: not a file"
                    for dest, src in args.vary if src and not Path(src).is_file())
    if args.observable not in OBSERVABLES:
        problems.append(f"--observable {args.observable}: not one of {', '.join(OBSERVABLES)}")
    return problems


def validate(args: argparse.Namespace) -> list[str]:
    problems = []
    if not Path(args.content).is_file():
        problems.append(f"--content {args.content}: not a file")
    problems.extend(f"--bios-file {dest}={src}: not a file"
                    for dest, src in args.bios_file if not Path(src).is_file())
    if args.oracle and not Path(args.oracle).is_file():
        problems.append(f"--oracle {args.oracle}: not a file")
    if args.samples < 2 or args.interval <= 0:
        problems.append("--samples must be >= 2 and --interval > 0")
    if args.require_sandbox:
        isolation = cp.sandbox_argv([])[1]
        if isolation != cp.SANDBOX:
            problems.append(f"--require-sandbox: {isolation}")
    if args.record:
        wrong = cp.not_a_checkout_root(Path(args.record))
        if wrong:
            problems.append(wrong)
    if args.subject and not re.fullmatch(r"[a-z0-9]+(?:[-_][a-z0-9]+)*", args.subject):
        problems.append(f"--subject {args.subject!r}: lowercase letters, digits, - and _ only")
    if args.mode == "check":
        problems += _check_mode_problems(args)
    return problems
