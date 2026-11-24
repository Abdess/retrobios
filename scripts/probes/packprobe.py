"""A pack probed the way a user runs it: cores chosen per system, files staged until the run settles, one line per probe."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from core_probe import (EXIT_BUSY, PROBE_LOCK_ENV, PROBE_LOCK_HELD_ENV, VERDICTS, head_commit,
                        host_probe_lock, probe_lock_path)
from core.paths import REPO_ROOT
from core.statefile import now_iso
from model import measurements as mr
from model.platforms import load_platform_config
from model.profiles import load_emulator_profiles
from model.systems import norm_system_id
from model.targets import load_target_config
from probes.content import Content, content_root, fetch_content, find_romfetch, load_content, load_file, ready_folder
from probes.cores import buildbot_listing, cached_nightly
from probes.entries import entry_dest
from probes.host import (CONTENT_FILE, PROBE_TIMEOUT, Host, StillBusy, Unavailable, main_cache, run_group,
                         run_when_idle, wait_for_load)
from probes.packlayout import (
    Layout,
    ProbeFailure,
    build_pack,
    installer_layout,
    pack_identity,
    pack_layout,
)
from resolve.cores import resolve_platform_cores
from resolve.standalone import platform_launches
from resolve.entryscope import filter_files_by_mode


PACK_CONTENT_FILE = REPO_ROOT / "tests" / "campaign" / "pack_content.yml"


MAX_ROUNDS = 6
IDLE_WAIT = 1800
IDLE_POLL = 30.0

# The hardware target each platform is probed for: the one whose libretro
# cores are the buildbot's x86_64 Linux builds, or the platform's only one.
TARGETS = {"retroarch": "linux-x86_64", "batocera": "x86_64", "retrobat": "windows"}


# --------------------------------------------------------------------------
# Which cores a platform runs for a system
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class CoreChoice:
    emulator: str
    so_name: str


def platform_system(config: dict, system: str) -> str | None:
    """The platform's own id of a system, compared on the normalised id."""
    wanted = norm_system_id(system)
    matches = sorted(s for s in config.get("systems") or {} if norm_system_id(s) == wanted)
    return matches[0] if matches else None


def libretro_build_runs(
    name: str, profile: dict, config: dict, profiles: dict[str, dict]
) -> bool:
    """The platform launches this profile's libretro build: it has one, and
    the platform does not run the emulator standalone only."""
    if "libretro" not in str(profile.get("type", "")) or profile.get("type") == "alias":
        return False
    standalone = platform_launches(config, profiles)
    if not standalone.runs_standalone(name, profile):
        return True
    return standalone.is_dual({name} | {str(c) for c in profile.get("cores") or ()})


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
    wanted = norm_system_id(system)
    out: list[CoreChoice] = []
    for name in sorted(resolve_platform_cores(config, profiles, target)):
        profile = profiles[name]
        if wanted not in {norm_system_id(s) for s in profile.get("systems") or ()}:
            continue
        if not libretro_build_runs(name, profile, config, profiles):
            continue
        out.extend(CoreChoice(name, so) for so in so_names(name, profile, buildbot, target))
    return out


# --------------------------------------------------------------------------
# Staging: what the core can reach, grown to a fixed point
# --------------------------------------------------------------------------

def entry_paths(entry: dict) -> list[str]:
    """The paths a profile entry names under the system directory: its
    path or name, and its aliases beside it."""
    main = entry_dest(entry)
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
    findings.extend({"kind": "unlisted", "path": item["path"], "declared_by": [], "paths": []}
                    for item in opened if item["path"] in staged and item["entry"] is None)
    return opened, findings


# --------------------------------------------------------------------------
# Cores and content
# --------------------------------------------------------------------------

def fetch_core(name: str, refresh: bool = False) -> dict:
    """The buildbot nightly of a core, kept with where and when it came from.
    refresh asks the buildbot whether a newer build replaced it."""
    return cached_nightly(name, main_cache() / "pack-probe" / "cores" / name, check=refresh)


def load_contents(files: Sequence[Path]) -> dict[str, list[Content]]:
    out: dict[str, list[Content]] = {}
    for path in files:
        if path.is_file():
            for system, items in load_content(path).items():
                out.setdefault(system, []).extend(items)
    return out


def content_folder(content: Content, fetch: bool) -> Path:
    """The game's folder, fetched through romfetch when absent and asked to."""
    root = content_root()

    def get(wanted: Content) -> None:
        romfetch = find_romfetch()
        if not romfetch:
            raise Unavailable("romfetch not found")
        fetch_content(wanted, root, romfetch)

    return ready_folder(content, root, get if fetch else None)[0]


# --------------------------------------------------------------------------
# One probe: a core, a game, a layout
# --------------------------------------------------------------------------

def wait_idle(host: Host, limit: float = IDLE_WAIT, poll: float = IDLE_POLL) -> None:
    """Wait for the load core_probe records under (core_probe.default_max_load).
    Extracting a pack loads the host itself for a minute or two."""
    try:
        wait_for_load(host, limit, poll)
    except StillBusy as exc:
        raise ProbeFailure(f"busy host: {exc}") from None


def core_probe(argv: list[str], staged: set[str], layout: Layout, work: Path) -> tuple[int, dict | None, str]:
    """core_probe.py run under the probe lock, the system files passed in an
    argument file."""
    work.mkdir(parents=True, exist_ok=True)
    argfile = work / "system-files.args"
    argfile.write_text("".join(f"--system-file\n{rel}={layout.root / rel}\n" for rel in sorted(staged)),
                       encoding="utf-8")
    command = [sys.executable, str(REPO_ROOT / "scripts" / "core_probe.py"), *argv, f"@{argfile}"]
    host = Host()
    with host_probe_lock():
        if "--record" in argv:
            wait_idle(host)
        # core_probe takes the same lock unless told its caller holds it.
        proc = run_when_idle(command, IDLE_WAIT, timeout=PROBE_TIMEOUT * 2 + 120, runner=run_group,
                             clock=host.clock, pause=host.sleep,
                             env={**os.environ, PROBE_LOCK_HELD_ENV: "1",
                                  PROBE_LOCK_ENV: str(probe_lock_path())})
    record = None
    if proc.returncode == 0:
        try:
            record = json.loads(proc.stdout)
        except ValueError:
            record = None
    # A traceback spells the checkout and the scratch folders: a record read
    # on another machine names them by role.
    places = [(str(work), "<work>"), (str(layout.root), "<dest>"), (str(REPO_ROOT), "<repo>")]
    error = proc.stderr.strip()
    for prefix, name in sorted(places, key=lambda place: -len(place[0])):
        error = error.replace(prefix, name)
    return proc.returncode, record, error[-1500:]


def probe_argv(core: dict, choice: CoreChoice, content: Content, load: Path,
               subject: str, record: bool, supersedes: str | None = None) -> list[str]:
    argv = ["run", "--core", core["path"], "--content", str(load), "--content-label", content.name,
            "--frames", str(content.frames), "--frame-hash-every", str(content.frame_hash_every),
            "--require-sandbox", "--timeout", str(PROBE_TIMEOUT),
            "--work-dir", str(REPO_ROOT / "tmp" / "core_probe"), "--core-artifact", core["url"]]
    if record:
        argv += ["--record", str(REPO_ROOT), "--emulator", choice.emulator, "--subject", subject]
        if supersedes:
            argv += ["--supersedes", supersedes]
    return argv


def subject_for(platform: str, install: str, system: str, so: str, content: str) -> str:
    subject = mr.slugify(f"{platform} {install} {system} {so} {content}", 85)
    return f"{mr.PACK_SUBJECT_PREFIX}{subject}"


@dataclass(frozen=True)
class ProbeTarget:
    """One core of one system, on the game loaded for it."""

    choice: CoreChoice
    core: dict
    system: str
    content: Content
    load: Path


def probe_one(layout: Layout, platform: str, config: dict, profile: dict, target: ProbeTarget,
              work: Path) -> dict:
    """Run until the staging is closed. The first run is recorded, and when
    the staging grew, the closed one is recorded too and supersedes it."""
    choice, core, system, content, load = target.choice, target.core, target.system, target.content, target.load
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
    """The revision the pack was built from, None when git cannot say."""
    try:
        return head_commit(REPO_ROOT) or None
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"WARNING: pack source commit unknown, git failed: {exc}", file=sys.stderr)
        return None


def append_line(line: dict, root: Path = REPO_ROOT) -> dict:
    sealed = mr.seal_line(line, mr.CAMPAIGN_FILES[mr.PACK_PROBES][0])
    path = root / mr.records_path(mr.PACK_PROBES)
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
    content: Content
    cores: list[CoreChoice]


def plan(platform: str, systems: set[str] | None, cores: set[str] | None,
         buildbot: set[str]) -> tuple[dict, dict, list[Unit]]:
    config = load_platform_config(platform, str(REPO_ROOT / "platforms"))
    profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
    target = load_target_config(platform, TARGETS[platform], str(REPO_ROOT / "platforms"))
    units: list[Unit] = []
    for system, contents in sorted(load_contents([CONTENT_FILE, PACK_CONTENT_FILE]).items()):
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
                                      REPO_ROOT / "install" / f"{args.platform}.json", work / "installer")
        try:
            for unit in units:
                try:
                    load = load_file(content_folder(unit.content, args.fetch), unit.content.load)
                except Unavailable as exc:
                    print(f"SKIP {unit.system}: {exc}", file=sys.stderr)
                    continue
                for choice in unit.cores:
                    core = fetch_core(choice.so_name, args.refresh_cores)
                    target = ProbeTarget(choice, core, unit.system, unit.content, load)
                    line = probe_one(layout, args.platform, config, profiles[choice.emulator], target,
                                     work / "runs")
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
