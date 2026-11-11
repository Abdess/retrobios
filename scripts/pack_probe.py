#!/usr/bin/env python3
"""Test a platform's pack the way a user installs it.

For one platform, the probe lays the platform's BIOS folder out in a scratch
root, in one or both of the ways a user gets it:

  pack       the pack generate_pack.py builds for the platform, extracted
  installer  install.py --dest on the scratch root, from that pack and the
             published manifest (install/<platform>.json), with no network

Then for each system a test game covers (tests/campaign/content.yml and
tests/campaign/pack_content.yml), it resolves the libretro cores the platform
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
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import zipfile
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import autorun
import campaign
import measurement_records as mr
from common import (
    _norm_system_id,
    load_emulator_profiles,
    load_platform_config,
    load_target_config,
    platform_arg,
    require_platform,
    resolve_platform_cores,
    run_cli,
    runs_standalone,
)
from validation import filter_files_by_mode
from ziptools import safe_extract_zip

ROOT = Path(__file__).resolve().parent.parent
MAIN = autorun.main_checkout()
PACK_CONTENT_FILE = ROOT / "tests" / "campaign" / "pack_content.yml"
CONTENT_DIR = MAIN / ".cache" / "test-content"
CORE_CACHE = MAIN / ".cache" / "pack-probe" / "cores"
WORK_DIR = ROOT / "tmp" / "pack_probe"
BUILDBOT = campaign.BUILDBOT
PACK_PROBES = mr.PACK_PROBES
INSTALLS = ("pack", "installer")
VERDICTS = ("boots", "bios_error", "crash", "hang", "unknown")
MAX_ROUNDS = 6
PROBE_TIMEOUT = 900
IDLE_WAIT = 1800
PROBE_LOCK_ENV = "RETROBIOS_PROBE_LOCK"
PROBE_LOCK_HELD_ENV = "RETROBIOS_PROBE_LOCK_HELD"
PROBE_LOCK = Path(os.environ.get(PROBE_LOCK_ENV)
                  or Path.home() / ".local" / "state" / "retrobios" / "probe.lock")
EXIT_BUSY = 3

# The hardware target each platform is probed for: the one whose libretro
# cores are the buildbot's x86_64 Linux builds, or the platform's only one.
TARGETS = {"retroarch": "linux-x86_64", "batocera": "x86_64", "retrobat": "windows"}


class ProbeFailure(RuntimeError):
    """The probe cannot go on: no pack, no installer layout, a busy host."""


# --------------------------------------------------------------------------
# Layouts: the platform's BIOS folder as a user ends up with it
# --------------------------------------------------------------------------

@dataclass
class Layout:
    """A BIOS folder: every file by its path under the folder, and the pack
    or manifest entry that put it there (None for a file nothing declares)."""

    install: str
    root: Path
    files: dict[str, str | None]
    source: dict
    sizes: dict[str, int] = field(default_factory=dict)

    def size(self, rel: str) -> int:
        if rel not in self.sizes:
            self.sizes[rel] = (self.root / rel).stat().st_size
        return self.sizes[rel]


def walk(root: Path) -> list[str]:
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())


def file_sha(path: Path, algorithm: str = "sha1") -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def pack_layout(pack: Path, root: Path, identity: dict) -> Layout:
    """The pack extracted as a user does, at the root of the BIOS folder.
    Each file's entry is the archive member it came from."""
    if root.exists():
        shutil.rmtree(root)
    safe_extract_zip(str(pack), str(root))
    with zipfile.ZipFile(pack) as handle:
        members = {info.filename for info in handle.infolist() if not info.is_dir()}
    files = {rel: rel if rel in members else None for rel in walk(root)}
    return Layout("pack", root, files, {"pack": identity, "manifest": None})


def pack_identity(pack: Path) -> dict:
    with zipfile.ZipFile(pack) as handle:
        members = sum(1 for info in handle.infolist() if not info.is_dir())
    return {"file": pack.name, "sha256": file_sha(pack, "sha256"), "size": pack.stat().st_size,
            "members": members}


def manifest_entries(manifest: dict) -> dict[str, str]:
    """Destination -> the manifest entry that names it, as the installer
    places it under --dest: a file by its dest, a data directory member
    under its directory's dest."""
    out: dict[str, str] = {}
    for item in manifest.get("files") or ():
        out[item["dest"]] = f"files:{item['dest']}"
    for item in manifest.get("case_variants") or ():
        out.setdefault(item["dest"], f"case_variants:{item['dest']}")
    for directory in manifest.get("data_directories") or ():
        base = str(directory.get("dest") or "").strip("/")
        for member in directory.get("files") or {}:
            dest = f"{base}/{member}" if base else member
            out.setdefault(dest, f"data_directories:{directory['ref']}:{member}")
    return out


def installer_summary(stdout: str, system_dir: Path, save_dir: Path) -> str:
    """The end of the installer's output, as a record keeps it. The scratch
    folders are written as the options that named them: a record read
    elsewhere has no use for the path of the machine that ran the probe."""
    text = stdout.replace(str(system_dir), "<dest>").replace(str(save_dir), "<save-dir>")
    return " ".join(text.split())[-400:]


def installer_layout(platform: str, pack: Path, identity: dict, manifest_path: Path,
                     root: Path, narrow: Sequence[str] = ()) -> Layout:
    """install.py --dest on a scratch root, from the pack, offline. The
    manifest is the published one, the file a user's installer reads.
    ``narrow`` passes install.py options such as --system, for the tests."""
    system_dir, save_dir = root / "system", root / "saves"
    if root.exists():
        shutil.rmtree(root)
    argv = [sys.executable, str(ROOT / "install.py"), "--platform", platform, "--dest", str(system_dir),
            "--save-dir", str(save_dir), "--from-pack", str(pack), "--manifest", str(manifest_path),
            "--offline", "--yes", "--quiet", *narrow]
    proc = subprocess.run(argv, capture_output=True, text=True, check=False, cwd=ROOT)
    if proc.returncode != 0 or not system_dir.is_dir():
        raise ProbeFailure(f"install.py exited {proc.returncode}: {(proc.stderr or proc.stdout)[-1500:]}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entries = manifest_entries(manifest)
    files = {rel: entries.get(rel) for rel in walk(system_dir)}
    source = {
        "pack": identity,
        "manifest": {"path": manifest_path.relative_to(ROOT).as_posix() if manifest_path.is_relative_to(ROOT)
                     else manifest_path.name,
                     "sha256": file_sha(manifest_path, "sha256"),
                     "generated": manifest.get("generated"), "pack_files": manifest.get("pack_files")},
        "save_dir_files": len(walk(save_dir)) if save_dir.is_dir() else 0,
        "installer_summary": installer_summary(proc.stdout, system_dir, save_dir),
    }
    return Layout("installer", system_dir, files, source)


def build_pack(platform: str, out_dir: Path, narrow: Sequence[str] = ()) -> Path:
    """The platform's pack, built from this checkout as a release builds it.
    ``narrow`` passes generate_pack.py options such as --system, for the tests."""
    out_dir.mkdir(parents=True, exist_ok=True)
    for old in out_dir.glob("*_BIOS_Pack*.zip"):
        old.unlink()
    argv = [sys.executable, str(ROOT / "scripts" / "generate_pack.py"), "--platform", platform,
            "--offline", "--output-dir", str(out_dir), *narrow]
    proc = subprocess.run(argv, capture_output=True, text=True, check=False, cwd=ROOT)
    packs = sorted(p for p in out_dir.glob("*_BIOS_Pack*.zip") if ".part" not in p.name)
    if proc.returncode != 0 or len(packs) != 1:
        raise ProbeFailure(f"generate_pack.py exited {proc.returncode} with {len(packs)} packs: "
                           f"{proc.stderr[-1500:]}")
    return packs[0]


# --------------------------------------------------------------------------
# Which cores a platform runs for a system
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class CoreChoice:
    emulator: str
    so_name: str


def platform_system(config: dict, system: str) -> str | None:
    """The platform's own id of a system, compared on the normalised id."""
    wanted = _norm_system_id(system)
    matches = sorted(s for s in config.get("systems") or {} if _norm_system_id(s) == wanted)
    return matches[0] if matches else None


def libretro_build_runs(name: str, profile: dict, config: dict) -> bool:
    """The platform launches this profile's libretro build: it has one, and
    the platform does not run the emulator standalone only."""
    if "libretro" not in str(profile.get("type", "")) or profile.get("type") == "alias":
        return False
    standalone = {str(c) for c in config.get("standalone_cores") or ()}
    if not runs_standalone(name, profile, standalone):
        return True
    dual = {str(c) for c in config.get("dual_mode_cores") or ()}
    return bool(dual & ({name} | {str(c) for c in profile.get("cores") or ()}))


def so_names(name: str, profile: dict, buildbot: set[str], target: set[str] | None) -> list[str]:
    """The buildbot builds of a profile the platform runs. Every one the
    target names, else the build that carries the profile's key, else the
    first of its cores: that is on the buildbot."""
    names = [str(c) for c in profile.get("cores") or () if str(c) in buildbot]
    if target is not None:
        named = [n for n in names if n in target]
        if named:
            return sorted(named)
    if name in buildbot:
        return [name]
    return names[:1]


def choose_cores(config: dict, profiles: dict[str, dict], system: str, buildbot: set[str],
                 target: set[str] | None) -> list[CoreChoice]:
    wanted = _norm_system_id(system)
    out = []
    for name in sorted(resolve_platform_cores(config, profiles, target)):
        profile = profiles[name]
        if wanted not in {_norm_system_id(s) for s in profile.get("systems") or ()}:
            continue
        if not libretro_build_runs(name, profile, config):
            continue
        out.extend(CoreChoice(name, so) for so in so_names(name, profile, buildbot, target))
    return out


# --------------------------------------------------------------------------
# Staging: what the core can reach, grown to a fixed point
# --------------------------------------------------------------------------

def entry_paths(entry: dict) -> list[str]:
    """The paths a profile entry names under the system directory: its
    path or name, and its aliases beside it."""
    main = campaign.entry_dest(entry)
    folder = main.rsplit("/", 1)[0] + "/" if "/" in main else ""
    return [main] + [f"{folder}{alias}" for alias in entry.get("aliases") or ()]


def libretro_entries(profile: dict) -> list[dict]:
    return filter_files_by_mode(profile.get("files") or [], standalone=False)


def declared_sizes(profile: dict) -> set[int]:
    sizes: set[int] = set()
    for entry in libretro_entries(profile):
        value = entry.get("size")
        sizes.update(v for v in (value if isinstance(value, list) else [value]) if isinstance(v, int))
    return sizes


def with_folders(files: Iterable[str], staged: set[str]) -> set[str]:
    """Every file of every folder a staged file sits in, below the root: a
    core that lists its folder sees what the platform's folder holds."""
    folders = {rel.rsplit("/", 1)[0] + "/" for rel in staged if "/" in rel}
    return set(staged) | {rel for rel in files if any(rel.startswith(f) for f in folders)}


def initial_stage(layout: Layout, profile: dict, platform_dests: Iterable[str]) -> set[str]:
    files = set(layout.files)
    staged = {p for entry in libretro_entries(profile) for p in entry_paths(entry) if p in files}
    staged |= {d for d in platform_dests if d in files}
    if profile.get("found_by") == "content":
        sizes = declared_sizes(profile)
        staged |= {rel for rel in files if "/" not in rel and layout.size(rel) in sizes}
    return with_folders(files, staged)


def grow_stage(files: Iterable[str], staged: set[str], probed: Iterable[str]) -> set[str]:
    """The files the layout holds that the core looked for, as a file or as
    a folder, and their folders: empty once the staging is closed."""
    files = set(files)
    wanted = set()
    for path in probed:
        if path in files:
            wanted.add(path)
        else:
            wanted |= {rel for rel in files if rel.startswith(path.rstrip("/") + "/")}
    return with_folders(files, staged | wanted) - staged


# --------------------------------------------------------------------------
# Reading a run
# --------------------------------------------------------------------------

def run_verdict(record: dict | None) -> tuple[str, dict | None]:
    """The verdict of a run record: variants[0] from record version 4,
    unknown before the oracle or without a record."""
    if not record or not record.get("variants"):
        return "unknown", None
    variant = record["variants"][0]
    verdict = variant.get("verdict")
    if verdict not in VERDICTS:
        return "unknown", None
    return verdict, variant.get("verdict_evidence")


def first_repetition(record: dict) -> dict:
    return record["variants"][0]["repetitions"][0]


def declaring(profile: dict, path: str) -> list[str]:
    return sorted({entry["name"] for entry in libretro_entries(profile) if path in entry_paths(entry)})


def map_run(layout: Layout, staged: set[str], rep: dict, profile: dict) -> tuple[list[dict], list[dict]]:
    """The files the core opened, each with its pack entry, and the findings."""
    opened = []
    for item in rep.get("files_opened") or ():
        path = item["path"]
        opened.append({"path": path, "entry": layout.files.get(path) if path in staged else None,
                       "sha1": item.get("sha1_after"), "created": path not in staged})
    by_name: dict[str, list[str]] = {}
    for rel in layout.files:
        by_name.setdefault(rel.rsplit("/", 1)[-1].casefold(), []).append(rel)
    # An entry the core found under one of its names asks for nothing more:
    # BlastEm tries tmss.md, then reads bios_MD.bin, both names of one entry.
    read = {item["path"] for item in opened if not item["created"]}
    satisfied = {entry["name"] for entry in libretro_entries(profile) if read & set(entry_paths(entry))}
    findings = []
    for path in rep.get("files_probed_absent") or ():
        names = declaring(profile, path)
        if path in layout.files:
            findings.append({"kind": "not_staged", "path": path, "declared_by": names, "paths": [path]})
            continue
        if names and set(names) <= satisfied:
            continue
        elsewhere = sorted(p for p in by_name.get(path.rsplit("/", 1)[-1].casefold(), ()) if p != path)
        if elsewhere:
            kind = "elsewhere"
        else:
            kind = "missing_declared" if names else "missing_undeclared"
        findings.append({"kind": kind, "path": path, "declared_by": names, "paths": elsewhere})
    for item in opened:
        if item["path"] in staged and item["entry"] is None:
            findings.append({"kind": "unlisted", "path": item["path"], "declared_by": [], "paths": []})
    return opened, findings


# --------------------------------------------------------------------------
# Cores and content
# --------------------------------------------------------------------------

def buildbot_listing() -> set[str]:
    with urllib.request.urlopen(BUILDBOT, timeout=120) as response:
        page = response.read().decode("utf-8", "replace")
    return set(re.findall(r"([A-Za-z0-9_]+)_libretro\.so\.zip", page))


def fetch_core(name: str, refresh: bool = False) -> dict:
    """The buildbot nightly of a core, kept with where and when it came from."""
    folder = CORE_CACHE / name
    so, meta_path = folder / f"{name}_libretro.so", folder / "build.json"
    if so.is_file() and meta_path.is_file() and not refresh:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if meta.get("sha256") == file_sha(so, "sha256"):
            return {**meta, "path": str(so)}
    url = f"{BUILDBOT}{name}_libretro.so.zip"
    folder.mkdir(parents=True, exist_ok=True)
    archive = folder / f"{name}.zip.part"
    with urllib.request.urlopen(url, timeout=600) as response, archive.open("wb") as out:
        shutil.copyfileobj(response, out)
        modified = response.headers.get("Last-Modified")
    campaign.safe_extract_so(archive, f"{name}_libretro.so", so)
    archive.unlink()
    meta = {"name": name, "url": url, "last_modified": modified, "sha256": file_sha(so, "sha256"),
            "fetched_at": now_iso()}
    meta_path.write_text(json.dumps(meta, indent=1) + "\n", encoding="utf-8")
    return {**meta, "path": str(so)}


def load_contents(files: Sequence[Path]) -> dict[str, list[campaign.Content]]:
    out: dict[str, list[campaign.Content]] = {}
    for path in files:
        if path.is_file():
            for system, items in campaign.load_content(path).items():
                out.setdefault(system, []).extend(items)
    return out


def content_folder(content: campaign.Content, fetch: bool) -> Path:
    """The game's folder, fetched through romfetch when absent and asked to."""
    folder = CONTENT_DIR / content.romfetch_system / content.name
    if not (folder / "identity.json").is_file() and fetch:
        romfetch = shutil.which("romfetch")
        if not romfetch:
            raise campaign.Unavailable("romfetch not found")
        proc = subprocess.run([romfetch, "get", content.romfetch_system, content.name, "--json", "-q",
                               "--content-dir", str(CONTENT_DIR)], capture_output=True, text=True,
                              check=False, env=campaign.child_env(romfetch=True))
        if proc.returncode != 0:
            raise campaign.Unavailable(f"romfetch exit {proc.returncode} for {content.name!r}")
    campaign.verify_identity(folder)
    return folder


# --------------------------------------------------------------------------
# One probe: a core, a game, a layout
# --------------------------------------------------------------------------

def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def wait_idle(limit: float = IDLE_WAIT, poll: float = 30.0) -> None:
    """Wait for the load core_probe records under, a quarter of the CPUs.
    Extracting a pack loads the host itself for a minute or two."""
    threshold = (os.cpu_count() or 1) / 4
    waited = 0.0
    while os.getloadavg()[0] > threshold:
        if waited >= limit:
            raise ProbeFailure(f"busy host: load {os.getloadavg()[0]:.2f} above {threshold} "
                               f"for {int(waited)} s")
        time.sleep(poll)
        waited += poll


@contextlib.contextmanager
def probe_lock(path: Path | None = None) -> Iterator[None]:
    """The host's probe lock, for one run: one probe at a time on the host,
    released between runs so a pass never holds it for its whole length."""
    path = path or PROBE_LOCK
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def core_probe(argv: list[str], staged: set[str], layout: Layout, work: Path) -> tuple[int, dict | None, str]:
    """core_probe.py run under the probe lock, the system files passed in an
    argument file."""
    work.mkdir(parents=True, exist_ok=True)
    argfile = work / "system-files.args"
    argfile.write_text("".join(f"--system-file\n{rel}={layout.root / rel}\n" for rel in sorted(staged)),
                       encoding="utf-8")
    command = [sys.executable, str(ROOT / "scripts" / "core_probe.py"), *argv, f"@{argfile}"]
    with probe_lock():
        if "--record" in argv:
            wait_idle()
        # core_probe takes the same lock unless told its caller holds it.
        proc = subprocess.run(command, capture_output=True, text=True, check=False, cwd=ROOT,
                              timeout=PROBE_TIMEOUT * 2 + 120,
                              env={**os.environ, PROBE_LOCK_HELD_ENV: "1", PROBE_LOCK_ENV: str(PROBE_LOCK)})
    record = None
    if proc.returncode == 0:
        try:
            record = json.loads(proc.stdout)
        except ValueError:
            record = None
    # A traceback spells the checkout and the scratch folders: a record read
    # on another machine names them by role.
    places = [(str(work), "<work>"), (str(layout.root), "<dest>"), (str(ROOT), "<repo>")]
    error = proc.stderr.strip()
    for prefix, name in sorted(places, key=lambda place: -len(place[0])):
        error = error.replace(prefix, name)
    return proc.returncode, record, error[-1500:]


def probe_argv(core: dict, choice: CoreChoice, content: campaign.Content, load: Path,
               subject: str, record: bool, supersedes: str | None = None) -> list[str]:
    argv = ["run", "--core", core["path"], "--content", str(load), "--content-label", content.name,
            "--frames", str(content.frames), "--frame-hash-every", str(content.frame_hash_every),
            "--require-sandbox", "--timeout", str(PROBE_TIMEOUT),
            "--work-dir", str(ROOT / "tmp" / "core_probe"), "--core-artifact", core["url"]]
    if record:
        argv += ["--record", str(ROOT), "--emulator", choice.emulator, "--subject", subject]
        if supersedes:
            argv += ["--supersedes", supersedes]
    return argv


def subject_for(platform: str, install: str, system: str, so: str, content: str) -> str:
    subject = mr.slugify(f"{platform} {install} {system} {so} {content}", 85)
    return f"{mr.PACK_SUBJECT_PREFIX}{subject}"


def probe_one(layout: Layout, platform: str, config: dict, profile: dict, choice: CoreChoice,
              core: dict, system: str, content: campaign.Content, load: Path, work: Path) -> dict:
    """Run until the staging is closed. The first run is recorded, and when
    the staging grew, the closed one is recorded too and supersedes it."""
    native = platform_system(config, system)
    dests = [f.get("destination") or f.get("name")
             for f in ((config.get("systems") or {}).get(native) or {}).get("files") or ()]
    staged = initial_stage(layout, profile, dests)
    subject = subject_for(platform, layout.install, system, choice.so_name, content.name)
    code, record, error = core_probe(probe_argv(core, choice, content, load, subject, True),
                                     staged, layout, work)
    if code == EXIT_BUSY:
        raise ProbeFailure(f"core_probe refused on a busy host: {error}")
    rounds, first_id, records = 1, None, []
    if record:
        first_id = record["id"]
        records.append(first_id)
        added = grow_stage(layout.files, staged, first_repetition(record).get("files_probed_absent") or ())
        while added and rounds < MAX_ROUNDS:
            staged |= added
            rounds += 1
            code, record, error = core_probe(probe_argv(core, choice, content, load, subject, False),
                                             staged, layout, work)
            if not record:
                break
            added = grow_stage(layout.files, staged, first_repetition(record).get("files_probed_absent") or ())
        if rounds > 1 and record:
            code, record, error = core_probe(probe_argv(core, choice, content, load, subject, True, first_id),
                                             staged, layout, work)
            if code == EXIT_BUSY:
                raise ProbeFailure(f"core_probe refused on a busy host: {error}")
            if record:
                records.append(record["id"])
    verdict, evidence = run_verdict(record)
    opened, findings = map_run(layout, staged, first_repetition(record), profile) if record else ([], [])
    return {
        "schema_version": 1,
        "probed_at": now_iso(),
        "platform": platform,
        "platform_version": str(config.get("version") or ""),
        "target": TARGETS.get(platform),
        "install": layout.install,
        "source": {**layout.source, "repo_commit": git_head()},
        "system": system,
        "platform_system": native,
        "emulator": choice.emulator,
        "core": {"file": f"{choice.so_name}_libretro.so", "sha256": core["sha256"], "artifact": core["url"],
                 "last_modified": core.get("last_modified")},
        "content": {"label": content.name, "catalog": content.catalog, "region": content.region},
        "records": records,
        "rounds": rounds,
        "staged": len(staged),
        "verdict": verdict,
        "verdict_evidence": evidence,
        "files_opened": opened,
        "findings": findings,
        "error": None if record else (error or f"core_probe exited {code}"),
    }


def git_head() -> str | None:
    proc = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=False,
                          cwd=ROOT)
    return proc.stdout.strip() or None


def append_line(line: dict, root: Path = ROOT) -> dict:
    sealed = mr.seal_line(line, mr.CAMPAIGN_FILES[PACK_PROBES][0])
    path = root / mr.records_path(PACK_PROBES)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(mr.line_text(sealed) + "\n")
    return sealed


# --------------------------------------------------------------------------
# Plans and the command line
# --------------------------------------------------------------------------

@dataclass
class Unit:
    system: str
    content: campaign.Content
    cores: list[CoreChoice]


def plan(platform: str, systems: set[str] | None, cores: set[str] | None,
         buildbot: set[str]) -> tuple[dict, dict, list[Unit]]:
    config = load_platform_config(platform, str(ROOT / "platforms"))
    profiles = load_emulator_profiles(str(ROOT / "emulators"))
    target = load_target_config(platform, TARGETS[platform], str(ROOT / "platforms"))
    units = []
    for system, contents in sorted(load_contents([campaign.CONTENT_FILE, PACK_CONTENT_FILE]).items()):
        if systems and system not in systems:
            continue
        if not platform_system(config, system):
            continue
        choices = [c for c in choose_cores(config, profiles, system, buildbot, target)
                   if not cores or c.so_name in cores or c.emulator in cores]
        units.extend(Unit(system, content, choices) for content in contents)
    return config, profiles, units


def run(args: argparse.Namespace) -> int:
    buildbot = buildbot_listing()
    config, profiles, units = plan(args.platform, args.systems, args.cores, buildbot)
    if args.mode == "plan":
        for unit in units:
            print(f"{unit.system}: {unit.content.name}: "
                  f"{', '.join(f'{c.so_name} ({c.emulator})' for c in unit.cores) or 'no core'}")
        return 0
    if not units:
        print(f"ERROR: no test game for any system of {args.platform}", file=sys.stderr)
        return 2
    work = Path(args.work_dir) / args.platform
    pack = Path(args.pack) if args.pack else build_pack(args.platform, work / "dist")
    identity = pack_identity(pack)
    status = 0
    for install in args.install:
        if install == "pack":
            layout = pack_layout(pack, work / "pack", identity)
        else:
            layout = installer_layout(args.platform, pack, identity,
                                      ROOT / "install" / f"{args.platform}.json", work / "installer")
        try:
            for unit in units:
                try:
                    load = campaign.load_file(content_folder(unit.content, args.fetch), unit.content.load)
                except campaign.Unavailable as exc:
                    print(f"SKIP {unit.system}: {exc}", file=sys.stderr)
                    continue
                for choice in unit.cores:
                    core = fetch_core(choice.so_name, args.refresh_cores)
                    line = probe_one(layout, args.platform, config, profiles[choice.emulator], choice,
                                     core, unit.system, unit.content, load, work / "runs")
                    sealed = append_line(line)
                    print(f"{args.platform} {install} {unit.system} {choice.so_name}: {line['verdict']}, "
                          f"{len(line['files_opened'])} opened, {len(line['findings'])} findings, "
                          f"line {sealed['id']}")
                    if line["error"]:
                        status = 1
        finally:
            if not args.keep:
                shutil.rmtree(layout.root if install == "pack" else layout.root.parent, ignore_errors=True)
    return status


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
    require_platform(args.platform, str(ROOT / "platforms"))
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
