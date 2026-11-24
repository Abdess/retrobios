"""One standalone run under strace and Xvfb, its variants and their verdicts."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path

import core_probe as cp
from core.paths import REPO_ROOT
from probes.standaloneemulators import PATTERNS_FILE, PATTERNS_PATH, Emulator, emulator_settings, ini_text
from probes.xvfb import DISPLAY_NUMBER, read_lines, sample_screen, stop, wait_for_screen, with_display


def run_once(args: argparse.Namespace, emu: Emulator, tree: Path, system_dir: Path, scratch: Path,
             png_dir: Path | None) -> dict:
    home = scratch / "home"
    data = scratch / "data"
    for folder in (home, data):
        folder.mkdir(parents=True, exist_ok=True)
    settings = emulator_settings(emu, system_dir.resolve(), args.setting)
    settings_path = scratch / emu.settings_file
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(ini_text(settings), encoding="utf-8")
    content = Path(args.content).resolve()
    argv = [str(tree / emu.binary)] + [a.format(data=data.resolve()) for a in emu.args] + [str(content)]
    trace = scratch / "strace.txt"
    strace = shutil.which("strace") if not args.no_trace else None
    if strace:
        argv = [strace, "-f", "-qq", "-s", "4096", "-e", "trace=openat,open", "-o", str(trace)] + argv
    samples: list[tuple[float, str, bool]] = []
    logs: list[dict] = []
    if not shutil.which("Xvfb"):
        raise cp.ProbeError("Xvfb not found")
    fbdir = scratch / "fb"
    fbdir.mkdir(parents=True, exist_ok=True)
    screen_file = fbdir / "Xvfb_screen0"
    env = {"HOME": str(home.resolve()), "XDG_CONFIG_HOME": str(data.resolve()),
           "XDG_DATA_HOME": str(data.resolve()), "XDG_CACHE_HOME": str((home / ".cache").resolve()),
           "DISPLAY": f":{DISPLAY_NUMBER}", "QT_QPA_PLATFORM": "xcb", "LIBGL_ALWAYS_SOFTWARE": "1",
           "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    # The BIOS folder is writable, as the platform's is: PCSX2 creates its
    # NVRAM and MEC files there.
    prefix, isolation = cp.sandbox_argv([scratch, system_dir], [tree, content.parent])
    if args.require_sandbox and isolation != cp.SANDBOX:
        raise cp.ProbeError(f"refused to run the emulator outside a sandbox: {isolation}")
    proc = subprocess.Popen(prefix + with_display(argv, fbdir.resolve()), stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, env=env, start_new_session=True)
    reader = threading.Thread(target=read_lines, args=(proc.stdout, logs, samples), daemon=True)
    reader.start()
    try:
        wait_for_screen(proc, screen_file, logs)
        started = time.monotonic()
        ended = sample_screen(proc, screen_file, args, samples, png_dir, started)
        wall = time.monotonic() - started
    finally:
        stop(proc)
        reader.join(5)
    places = [(str(system_dir.resolve()), "<bios>"), (str(scratch.resolve()), "<scratch>"),
              (str(content.parent), "<content>"), (str(tree), "<emulator>"), (str(REPO_ROOT), "<repo>")]
    for line in logs:
        line["text"] = cp.host_paths_hidden(line["text"], places)
    rep: dict = {
        "loaded": ended is None,
        "library_name": emu.name,
        "frames": max(len(samples), 1),
        "wall_s": round(wall, 3),
        "sample_interval_s": args.interval,
        "sample_times_s": [t for t, _, _ in samples],
        # The shapes core_probe gives them: [sample, sha1] pairs, and the
        # digests of the samples that are one colour.
        "observables": {
            "frame_hashes": [[index, h] for index, (_, h, _) in enumerate(samples)],
            "uniform_frames": sorted({h for _, h, u in samples if u}),
            "screens": sorted({h for _, h, u in samples if not u}),
        },
        "logs": logs,
        "isolation": isolation,
    }
    if ended:
        rep["exit"] = ended
    if strace and trace.is_file():
        opened, probed = cp.files_under(cp.parse_strace(trace.read_text(encoding="utf-8", errors="replace")),
                                        system_dir)
        rep["files_opened"] = [{"path": rel, "sha1_after": cp.file_digest(system_dir / rel)}
                               for rel in opened if (system_dir / rel).is_file()]
        rep["files_probed_absent"] = probed
        rep["tracing"] = "strace"
    else:
        rep["files_opened"] = None
        rep["files_probed_absent"] = None
        rep["tracing"] = "disabled: --no-trace" if args.no_trace else "unavailable: strace not found"
    return rep


def run_variant(args: argparse.Namespace, emu: Emulator, tree: Path, oracle: dict,
                base: dict[str, Path], variant: cp.Variant, work: Path, repetitions: int) -> dict:
    reps: list[dict] = []
    flags: list[str] = []
    for index in range(repetitions):
        # A fresh BIOS folder each time: PCSX2 writes its NVRAM and MEC files
        # beside the BIOS, as on a user's folder, and a repetition must not
        # start from what the last one wrote.
        system_dir = work / f"bios{index}"
        staged = cp.stage_system_dir(base, variant, system_dir)
        png_dir = None
        if args.png_dir and index == 0:
            png_dir = Path(args.png_dir) / variant.label
            png_dir.mkdir(parents=True, exist_ok=True)
        rep = run_once(args, emu, tree, system_dir, work / f"rep{index}", png_dir)
        rep["verdict"], rep["verdict_evidence"] = cp.judge(rep, oracle)
        rep["observables"]["verdict"] = rep["verdict"]
        for entry in rep.get("files_opened") or []:
            expected = staged.get(entry["path"])
            entry["sha1_staged"] = expected
            if expected is not None and expected != entry["sha1_after"]:
                flags.append(f"repetition {index}: {entry['path']} sha1 changed during the run")
        reps.append(rep)
    verdict, evidence = cp.variant_verdict(reps)
    return {"label": variant.label, "system_files": dict(sorted(staged.items())), "repetitions": reps,
            "flags": flags, "verdict": verdict, "verdict_evidence": evidence}


def emulator_oracle(emu: Emulator, path: Path, content_sha1: str) -> dict:
    """The oracle core_probe reads (campaign/oracle.yml), looked up by
    the content's sha1 and the emulator's name, with the emulator's own
    error strings added as patterns. Without the file the oracle names the
    module that holds every pattern."""
    data, identity = cp.load_oracle(path)
    entries = cp.oracle_for(data, content_sha1, emu.name)
    own = [re.escape(text) for text in emu.error_patterns]
    entries["error_patterns"] = list(dict.fromkeys(entries["error_patterns"] + own))
    if identity is None:
        identity = {"file": PATTERNS_FILE, "sha256": cp.file_digest(PATTERNS_PATH, "sha256")}
    return {**identity, **entries}


def check_result(variants: list[dict], observable: str) -> dict:
    """core_probe's comparison, with each variant's verdict beside it."""
    return {**cp.check_result(variants, observable),
            "verdicts": {v["label"]: v["verdict"] for v in variants}}
