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
import contextlib
import hashlib
import http.client
import json
import os
import re
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO

sys.path.insert(0, str(Path(__file__).resolve().parent))

import core_probe as cp
from core import upstream
from core.statefile import now_iso

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / ".cache" / "standalone"
DEFAULT_WORK_DIR = ROOT / "tmp" / "standalone_probe"
RECORD_VERSION = 4
SCREEN = (1280, 720)
OBSERVABLES = ("verdict", "screens", "frame_hashes", "uniform_frames")
SCRIPT = "scripts/standalone_probe.py"


# --------------------------------------------------------------------------
# What each emulator is, how the platform installs it, how it is driven
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Emulator:
    """A standalone emulator as one platform installs it.

    `asset_*` reproduce the installer's choice: EmuDeck's getReleaseURLGH
    takes the first asset, over GitHub's release list in its own order
    (pre-releases included), whose name contains `asset_contains` and ends
    with `asset_endswith`.
    """

    name: str
    platform: str
    installer_ref: str
    repo: str
    asset_endswith: str
    asset_contains: str
    binary: str
    settings_file: str
    error_patterns: tuple[str, ...]
    settings: dict[str, dict[str, str]] = field(default_factory=dict)
    bios_setting: tuple[str, str] = ("", "")
    args: tuple[str, ...] = ()


EMULATORS: dict[str, Emulator] = {
    "duckstation": Emulator(
        name="duckstation",
        platform="emudeck",
        installer_ref="dragoonDorise/EmuDeck functions/EmuScripts/emuDeckDuckStation.sh "
                      "(getReleaseURLGH \"stenzek/duckstation\" \"AppImage\" \"x64.\")",
        repo="stenzek/duckstation",
        asset_endswith="AppImage",
        asset_contains="x64.",
        binary="usr/bin/duckstation-qt",
        # Core::SetDataRoot (src/core/core.cpp): $XDG_CONFIG_HOME/duckstation on Linux.
        settings_file="data/duckstation/settings.ini",
        bios_setting=("BIOS", "SearchDirectory"),
        settings={
            "Main": {"SetupWizardIncomplete": "false", "ConfirmPowerOff": "false",
                     "StartFullscreen": "true"},
            "AutoUpdater": {"CheckAtStartup": "false"},
            "GPU": {"Renderer": "Software"},
            # No sound device in the sandbox: the null backend, not an error dialog.
            "Audio": {"Backend": "Null"},
            "Logging": {"LogLevel": "Info", "LogToConsole": "true", "LogToFile": "false"},
            "Console": {"Region": "Auto"},
        },
        args=("-batch", "-nogui", "-fullscreen", "--"),
        # Strings of src/core/bios.cpp and src/core/system.cpp, as the
        # release binary carries them.
        error_patterns=("No BIOS image found for", "No BIOS images found",
                        "No BIOS images were found", "Failed to open BIOS"),
    ),
    "pcsx2": Emulator(
        name="pcsx2",
        platform="emudeck",
        installer_ref="dragoonDorise/EmuDeck functions/EmuScripts/emuDeckPCSX2QT.sh "
                      "(getReleaseURLGH \"PCSX2/pcsx2\" \"Qt.AppImage\" \"\")",
        repo="PCSX2/pcsx2",
        asset_endswith="Qt.AppImage",
        asset_contains="",
        binary="usr/bin/pcsx2-qt",
        # EmuFolders::SetDataDirectory (pcsx2/Pcsx2Config.cpp): $XDG_CONFIG_HOME/PCSX2 on Linux,
        # its settings in inis/.
        settings_file="data/PCSX2/inis/PCSX2.ini",
        bios_setting=("Folders", "Bios"),
        settings={
            # SETTINGS_VERSION of pcsx2/VMManager.cpp: another value resets every setting.
            "UI": {"SettingsVersion": "1", "SetupWizardIncomplete": "false", "ConfirmShutdown": "false",
                   "StartFullscreen": "true"},
            "AutoUpdater": {"CheckAtStartup": "false"},
            # GSRendererType::SW
            "EmuCore/GS": {"Renderer": "13"},
            # No sound device in the sandbox: the null backend, not an error dialog
            # over the screen.
            "SPU2/Output": {"Backend": "Null"},
            "Logging": {"EnableSystemConsole": "true", "EnableVerbose": "false"},
        },
        args=("-batch", "-nogui", "-fullscreen", "-earlyconsolelog", "--"),
        error_patterns=("requires a PlayStation 2 BIOS in order to run",
                        "Unable to auto locate a BIOS image", "BIOS image has not been selected",
                        "could not be read (permission denied?)"),
    ),
}


# --------------------------------------------------------------------------
# Pure helpers
# --------------------------------------------------------------------------

def select_asset(releases: Sequence[dict], endswith: str, contains: str) -> dict | None:
    """The asset EmuDeck's getReleaseURLGH returns: the first, over the
    releases in the API's order, whose name contains and ends as asked."""
    for release in releases:
        for asset in release.get("assets") or ():
            name = asset.get("name", "")
            if contains in name and name.endswith(endswith):
                return {"tag": release.get("tag_name"), "name": name,
                        "url": asset.get("browser_download_url"),
                        "prerelease": bool(release.get("prerelease"))}
    return None


def appimage_offset(head: bytes) -> int:
    """Where an AppImage's squashfs starts: the end of its ELF runtime,
    read from the section header table, as the runtime computes it."""
    if head[:4] != b"\x7fELF":
        raise cp.ProbeError("not an ELF file, not an AppImage")
    if head[4] == 2:
        shoff = struct.unpack_from("<Q", head, 0x28)[0]
        shentsize, shnum = struct.unpack_from("<HH", head, 0x3A)
    else:
        shoff = struct.unpack_from("<I", head, 0x20)[0]
        shentsize, shnum = struct.unpack_from("<HH", head, 0x2E)
    return shoff + shentsize * shnum


def ini_text(sections: dict[str, dict[str, str]]) -> str:
    out = []
    for section, values in sections.items():
        out.append(f"[{section}]")
        out.extend(f"{key} = {value}" for key, value in values.items())
        out.append("")
    return "\n".join(out)


def emulator_settings(emu: Emulator, bios_dir: Path, overrides: Sequence[tuple[str, str]]
                      ) -> dict[str, dict[str, str]]:
    """The settings written before a run: the emulator's own, the BIOS
    folder, then each SECTION.KEY=VALUE override."""
    sections = {name: dict(values) for name, values in emu.settings.items()}
    section, key = emu.bios_setting
    sections.setdefault(section, {})[key] = str(bios_dir)
    for name, value in overrides:
        sec, _, k = name.rpartition(".")
        if not sec or not k:
            raise cp.ProbeError(f"--setting {name}: SECTION.KEY expected")
        sections.setdefault(sec, {})[k] = value
    return sections


def parse_xwd(data: bytes) -> tuple[int, int, bytes]:
    """Width, height and RGB pixels of an XWD image, the file Xvfb keeps
    its screen in: 32 bits per pixel, least significant byte first."""
    if len(data) < 100:
        raise cp.ProbeError("framebuffer file shorter than an XWD header")
    fields = struct.unpack_from(">25I", data, 0)
    header_size, version = fields[0], fields[1]
    width, height = fields[4], fields[5]
    byte_order, bits_per_pixel, bytes_per_line, ncolors = fields[7], fields[11], fields[12], fields[19]
    if version != 7 or bits_per_pixel != 32 or byte_order != 0:
        raise cp.ProbeError(f"XWD version {version}, {bits_per_pixel} bpp, byte order "
                            f"{byte_order}: only version 7, 32 bpp, LSB first are read")
    start = header_size + ncolors * 12
    rows = [data[start + y * bytes_per_line:start + y * bytes_per_line + width * 4] for y in range(height)]
    packed = b"".join(rows)
    if len(packed) != width * height * 4:
        raise cp.ProbeError("framebuffer file shorter than its header says")
    return width, height, cp.to_rgb(1, width, height, packed)



# --------------------------------------------------------------------------
# Release binaries
# --------------------------------------------------------------------------

def github_releases(repo: str) -> list[dict]:
    from scraper.base_scraper import github_json

    return github_json(f"https://api.github.com/repos/{repo}/releases",
                       f"cannot list the releases of {repo}", timeout=60, error=cp.ProbeError)


def fetch(emu: Emulator, cache: Path = CACHE) -> dict:
    """Download the asset the platform picks, unpack it, and describe it."""
    asset = select_asset(github_releases(emu.repo), emu.asset_endswith, emu.asset_contains)
    if not asset:
        raise cp.ProbeError(f"{emu.repo}: no release asset matches the {emu.platform} rule")
    folder = cache / emu.name
    folder.mkdir(parents=True, exist_ok=True)
    partial = folder / f"{asset['name']}.part"
    # Whole or absent, retried on a cut stream (core.upstream.download).
    upstream.download(asset["url"], partial, timeout=600)
    sha256 = cp.file_digest(partial, "sha256")
    target = folder / sha256 / asset["name"]
    target.parent.mkdir(parents=True, exist_ok=True)
    partial.replace(target)
    unpack(target)
    meta = {**asset, "sha256": sha256, "repo": emu.repo, "platform": emu.platform,
            "installer_ref": emu.installer_ref, "fetched_at": now_iso()}
    (target.parent / "asset.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


def unpack(appimage: Path) -> Path:
    """The AppImage's tree, unpacked with unsquashfs: the runtime is never run."""
    tree = appimage.parent / "tree"
    if tree.is_dir():
        return tree
    unsquashfs = shutil.which("unsquashfs")
    if not unsquashfs:
        raise cp.ProbeError("unsquashfs not found (squashfs-tools)")
    with appimage.open("rb") as handle:
        offset = appimage_offset(handle.read(64))
    scratch = appimage.parent / "tree.part"
    shutil.rmtree(scratch, ignore_errors=True)
    subprocess.run([unsquashfs, "-q", "-n", "-o", str(offset), "-d", str(scratch), str(appimage)],
                   check=True, stdout=subprocess.DEVNULL)
    scratch.replace(tree)
    return tree


def installed(emu: Emulator, sha256: str | None, cache: Path = CACHE) -> tuple[dict, Path]:
    """The fetched asset to run: the one named by sha256, else the newest."""
    folder = cache / emu.name
    metas = sorted(folder.glob("*/asset.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    for path in metas:
        meta = json.loads(path.read_text(encoding="utf-8"))
        if sha256 in (None, meta["sha256"]):
            return meta, unpack(path.parent / meta["name"])
    raise cp.ProbeError(f"{emu.name}: no fetched asset{' ' + sha256 if sha256 else ''}, "
                        f"run `standalone_probe.py fetch {emu.name}`")


# --------------------------------------------------------------------------
# One repetition
# --------------------------------------------------------------------------

# The X server runs inside the sandbox, on the sandbox's own /tmp: the
# display is private to the run, and the host's /tmp/.X11-unix (read-only
# under WSLg) is never touched. Its fbdir option keeps the screen as an XWD
# file in the run's scratch folder, which the probe reads from outside.
DISPLAY_NUMBER = 1
XVFB_WRAPPER = (
    f'Xvfb ":{DISPLAY_NUMBER}" -screen 0 {SCREEN[0]}x{SCREEN[1]}x24 -nolisten tcp -fbdir "$1" '
    '-noreset >/dev/null 2>&1 &\n'
    'i=0\n'
    f'while [ ! -S /tmp/.X11-unix/X{DISPLAY_NUMBER} ]; do\n'
    '  i=$((i + 1)); [ "$i" -gt 400 ] && exit 97; sleep 0.05\n'
    'done\n'
    'shift\n'
    'exec "$@"\n'
)


def with_display(argv: list[str], fbdir: Path) -> list[str]:
    """The emulator's command, started once the sandbox's Xvfb listens."""
    return ["/bin/sh", "-c", XVFB_WRAPPER, "xvfb", str(fbdir), *argv]


def stop(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
    proc.wait()


ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def read_lines(stream: IO[bytes], out: list[dict], samples: list) -> None:
    """The emulator's console, line by line, each with the sample count
    reached when it was written, colour escapes removed."""
    for raw in iter(stream.readline, b""):
        text = ANSI.sub("", raw.decode("utf-8", errors="replace")).rstrip()
        if text:
            out.append({"frame": len(samples), "level": "info", "text": text})


def wait_for_screen(proc: subprocess.Popen, screen_file: Path, logs: list[dict]) -> None:
    deadline = time.monotonic() + 30
    while not screen_file.exists():
        if proc.poll() is not None or time.monotonic() > deadline:
            raise cp.ProbeError(f"Xvfb did not start in the sandbox (exit {proc.poll()}): "
                                f"{' / '.join(line['text'] for line in logs[-5:])}")
        time.sleep(0.05)


def sample_screen(proc: subprocess.Popen, screen_file: Path, args: argparse.Namespace,
                  samples: list[tuple[float, str, bool]], png_dir: Path | None, started: float) -> dict | None:
    """Hash the screen every interval. Returns how the emulator ended, None
    while it still runs."""
    for index in range(args.samples):
        target = started + (index + 1) * args.interval
        while time.monotonic() < target and proc.poll() is None:
            time.sleep(min(0.05, max(0.0, target - time.monotonic())))
        if proc.poll() is not None:
            code = proc.returncode
            return {"status": code if code >= 0 else None,
                    "signal": signal.Signals(-code).name if code < 0 else None}
        width, height, rgb = parse_xwd(screen_file.read_bytes())
        sha1 = hashlib.sha1(rgb).hexdigest()
        samples.append((round(time.monotonic() - started, 3), sha1, cp.uniform_frame(rgb, 3)))
        if png_dir and not any(p.name.endswith(f"{sha1[:12]}.png") for p in png_dir.iterdir()):
            (png_dir / f"{index:04d}-{sha1[:12]}.png").write_bytes(cp.png_bytes(width, height, rgb))
    return None


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
              (str(content.parent), "<content>"), (str(tree), "<emulator>"), (str(ROOT), "<repo>")]
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


# --------------------------------------------------------------------------
# Variants and the record
# --------------------------------------------------------------------------

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
    """The oracle core_probe reads (tests/campaign/oracle.yml), looked up by
    the content's sha1 and the emulator's name, with the emulator's own
    error strings of this script added as patterns. Without the file the
    oracle names this script, which then holds every pattern."""
    data, identity = cp.load_oracle(path)
    entries = cp.oracle_for(data, content_sha1, emu.name)
    own = [re.escape(text) for text in emu.error_patterns]
    entries["error_patterns"] = list(dict.fromkeys(entries["error_patterns"] + own))
    if identity is None:
        identity = {"file": SCRIPT, "sha256": cp.file_digest(Path(__file__).resolve(), "sha256")}
    return {**identity, **entries}


def check_result(variants: list[dict], observable: str) -> dict:
    """core_probe's comparison, with each variant's verdict beside it."""
    return {**cp.check_result(variants, observable),
            "verdicts": {v["label"]: v["verdict"] for v in variants}}


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
        meta, tree = installed(emu, args.sha256)
    except (cp.ProbeError, OSError, subprocess.SubprocessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    max_load = args.max_load if args.max_load is not None else (os.cpu_count() or 1) / 4
    load_before = cp.load_average()
    if args.record and load_before and load_before[0] > max_load:
        print(f"ERROR: load average {load_before[0]} exceeds {max_load}: the machine is busy, "
              f"nothing recorded", file=sys.stderr)
        return 3
    oracle = emulator_oracle(emu, Path(args.oracle) if args.oracle else cp.DEFAULT_ORACLE,
                             cp.file_digest(Path(args.content)))
    repetitions = 1 if args.mode == "run" else args.repeat
    base = {dest: Path(src) for dest, src in args.bios_file}
    if args.mode == "check":
        variants_in = []
        seen: set[str] = set()
        for dest, src in args.vary:
            label = Path(src).name if src else f"{dest}-absent"
            while label in seen:
                label += "+"
            seen.add(label)
            variants_in.append(cp.Variant(label, {dest: Path(src) if src else None}))
    else:
        variants_in = [cp.Variant("default")]
    work = Path(tempfile.mkdtemp(prefix=f"{args.mode}-", dir=cp._ensure(Path(args.work_dir))))
    try:
        variants = [run_variant(args, emu, tree, oracle, base, variant, work / f"v{i}", repetitions)
                    for i, variant in enumerate(variants_in)]
    except (cp.ProbeError, OSError, subprocess.SubprocessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        shutil.rmtree(work, ignore_errors=True)
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
        "frontend": cp.frontend_identity(Path(__file__).resolve(), SCRIPT),
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
    from model.measurements import canonical, sha256_hex, slugify

    if args.subject:
        record["subject"] = args.subject
    elif args.mode == "check":
        digest = sha256_hex(canonical([args.claim, args.method, args.observable, args.vary[0][0]]))[:8]
        record["subject"] = f"{slugify(args.claim)}-{digest}"
    else:
        digest = sha256_hex(canonical([meta["sha256"], record["inputs"]["content"],
                                       record["inputs"]["options"], args.bios_file]))[:8]
        record["subject"] = f"run-{slugify(args.content_label or Path(args.content).name, 30)}-{digest}"
    if args.record:
        try:
            lines, record = cp.write_record(Path(args.record), record)
        except cp.ProbeError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        print(f"recorded {lines}", file=sys.stderr)
    print(json.dumps(record, indent=2))
    return 0


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
    common.add_argument("--record", metavar="DIR", nargs="?", const=str(ROOT),
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
