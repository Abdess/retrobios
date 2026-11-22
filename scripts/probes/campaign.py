"""One campaign pass: the checks of each emulator, the rule table, findings and commits."""

from __future__ import annotations

import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from unattended import jobs
from unattended import worktree
import core_probe
from core import hostguard
from core.hashing import file_digest
from core.paths import REPO_ROOT
from core.statefile import now_iso, save_state
from model import measurements as mr
from model.profiles import entry_system_ids
from probes import rules
from probes.profileedit import ProfileEditError, write_fields
from probes.content import Content, ContentStore, load_content, load_file
from probes.cores import Core, Cores
from probes.entries import (
    entry_dest,
    held_file,
    held_variants,
    is_bios,
    profile_digest,
    region_matches,
    regions_of,
)
from probes.findings import OPEN_STATUSES, latest_findings
from probes.gate import gate
from probes.host import (
    Host,
    Paths,
    Settings,
    StillBusy,
    Unavailable,
    child_env,
    run_when_idle,
    slug,
    wait_for_load,
)
from probes.state import DONE, FAILED, PENDING, load_state, should_run


CRASH_ATTEMPTS = 3


MAX_ALIAS_CANDIDATES = 6
MAX_REGION_DUMPS = 2


LOG_DAYS = 30


class Pause(RuntimeError):
    """The host cannot run measurements now: the pass stops and resumes later."""


# --------------------------------------------------------------------------
# Probe runs
# --------------------------------------------------------------------------

@dataclass
class ProbeResult:
    status: str
    record: dict | None = None
    reason: str = ""
    log: str = ""


@dataclass
class Unit:
    """One core of one emulator profile, with its systems' content."""

    emulator: str
    profile: dict
    core_name: str | None = None
    pending: str = ""
    # A game engine or utility profile: run when the buildbot has its core,
    # otherwise it is a standalone program.
    buildbot_only: bool = False


@dataclass(frozen=True)
class Trial:
    """One core on one content: what every check of that pairing shares."""

    unit: Unit
    core: Core
    content: Content
    load: Path
    frames: list[str]
    digest: str


@dataclass(frozen=True)
class Held:
    """A declared file the collection holds, at its place."""

    index: int
    entry: dict
    dest: str
    local: Path


@dataclass
class Pass:
    started: str
    records: list[str] = field(default_factory=list)
    findings: dict[str, int] = field(default_factory=dict)
    touched: set[str] = field(default_factory=set)
    result: str = "complete"
    detail: str = ""


class Campaign:
    def __init__(self, paths: Paths, settings: Settings | None = None, host: Host | None = None,
                 probe_script: Path | None = None, lock_path: Path | None = None) -> None:
        self.paths = paths
        self.settings = settings or Settings()
        self.host = host or Host()
        self.probe_script = probe_script or REPO_ROOT / "scripts" / "core_probe.py"
        self.lock_path = lock_path or Path(os.environ.get(hostguard.LOCK_ENV) or hostguard.DEFAULT_LOCK)
        self.state = load_state(paths.state)
        self.cores = Cores(self)
        self.store = ContentStore(self)
        self.content = load_content(paths.content_file)
        self.oracle_sha = file_digest(paths.oracle, "sha256") if paths.oracle.is_file() else ""
        self.oracle_data = core_probe.load_oracle(paths.oracle)[0]
        self.deadline = 0.0
        self.current: Pass | None = None
        self.dirty_at_start: set[str] = set()
        self._db: dict | None = None

    # -- logging ------------------------------------------------------------

    def log(self, text: str) -> None:
        line = f"{now_iso()} {text}"
        path = self.paths.logs / f"{dt.date.today().isoformat()}.log"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        if self.settings.echo:
            print(line, file=sys.stderr)

    # -- profiles and files -------------------------------------------------

    def profiles(self) -> dict[str, dict]:
        from model.profiles import emulator_profiles_cache, load_emulator_profiles

        # The campaign writes these profiles itself: each pass reads them again.
        folder = os.path.realpath(self.paths.emulators)
        for key in [key for key in emulator_profiles_cache if key[0] == folder]:
            del emulator_profiles_cache[key]
        profiles = load_emulator_profiles(folder, skip_aliases=False)
        return {name: profile for name, profile in profiles.items() if name != "00_example"}

    def digest_on_disk(self, emulator: str) -> str:
        """profile_digest of the profile as its file reads now. The campaign's
        own edits land between the two reads of a unit, so both go to disk."""
        path = self.paths.emulators / f"{emulator}.yml"
        return profile_digest(yaml.safe_load(path.read_text(encoding="utf-8")))

    @property
    def db(self) -> dict:
        if self._db is None:
            self._db = json.loads(self.paths.db.read_text(encoding="utf-8"))
        return self._db

    def local_file(self, entry: dict) -> Path | None:
        """The collection's copy of an entry, by its declared hashes or its name."""
        return held_file(entry, self.db, self.paths.root)

    def variant_files(self, entry: dict, primary: Path) -> list[Path]:
        """The .variants/ copies standing in for an entry's primary."""
        return held_variants(entry, self.db, self.paths.root, primary)

    # -- guards ---------------------------------------------------------------

    def guard(self) -> None:
        """Raise Pause when the pass must stop: budget spent, disk full, host busy."""
        if self.host.clock() >= self.deadline:
            raise Pause("budget")
        free = self.host.free_gb(self.paths.home if self.paths.home.exists() else self.paths.root)
        if free < self.settings.min_free_gb:
            raise Pause(f"disk: {free:.0f} GB free, the campaign stops under "
                        f"{self.settings.min_free_gb:.0f} GB")
        try:
            wait_for_load(self.host, self.settings.max_load_wait, self.host.poll)
        except StillBusy as exc:
            raise Pause(f"busy host: load stayed above {exc.threshold:.1f} for "
                        f"{int(exc.waited)} s") from None

    # -- one core_probe invocation -------------------------------------------

    def probe(self, argv: list[str], log_name: str) -> ProbeResult:
        """core_probe with retries for a crashing core. Never raises for the core's sake."""
        command = [sys.executable, str(self.probe_script), *argv]
        log = self.paths.logs / dt.date.today().isoformat() / f"{log_name}.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        repeats = argv.count("--vary") or 1
        reps = int(argv[argv.index("--repeat") + 1]) if "--repeat" in argv else 1
        budget = self.settings.probe_timeout * repeats * reps + 120
        attempt = 0
        while attempt < CRASH_ATTEMPTS:
            self.guard()
            try:
                # Refused on a busy host: run_when_idle runs it again until the wait runs out.
                proc = run_when_idle(command, self.settings.max_load_wait, timeout=budget,
                                     cwd=self.paths.root, env=child_env(), clock=self.host.clock,
                                     pause=self.host.sleep, runner=self.host.run)
            except subprocess.TimeoutExpired:
                with log.open("a", encoding="utf-8") as handle:
                    handle.write(f"$ {' '.join(command)}\nkilled after {budget} s\n")
                return ProbeResult(FAILED, reason="timeout", log=str(log))
            with log.open("a", encoding="utf-8") as handle:
                handle.write(f"$ {' '.join(command)}\n# exit {proc.returncode}\n"
                             f"{proc.stderr[-20000:]}\n")
            if proc.returncode == 0:
                try:
                    return ProbeResult(DONE, record=json.loads(proc.stdout), log=str(log))
                except ValueError:
                    return ProbeResult(FAILED, reason="core_probe printed no record", log=str(log))
            if proc.returncode == core_probe.EXIT_BUSY:
                raise Pause(f"busy host: core_probe refused to record for "
                            f"{int(self.settings.max_load_wait)} s")
            attempt += 1
            if proc.returncode == 2:
                return ProbeResult(FAILED, reason=f"core_probe refused the run: "
                                                  f"{proc.stderr.strip()[-300:]}", log=str(log))
            if "TimeoutExpired" in proc.stderr or "timed out after" in proc.stderr:
                return ProbeResult(FAILED, reason="timeout", log=str(log))
            self.log(f"{log_name}: attempt {attempt} exited {proc.returncode}")
        return ProbeResult(FAILED, reason=f"crashed {CRASH_ATTEMPTS} times", log=str(log))

    def probe_args(self, mode: str, core: Core, emulator: str, subject: str, content: Content | None,
                   load: Path | None) -> list[str]:
        argv = [mode, "--core", str(core.path), "--record", str(self.paths.root),
                "--emulator", emulator, "--subject", subject,
                "--max-load", str(self.host.max_load), "--timeout", str(self.settings.probe_timeout),
                "--work-dir", str(self.paths.root / "tmp" / "core_probe")]
        if self.paths.oracle.is_file():
            argv += ["--oracle", str(self.paths.oracle)]
        if not self.settings.allow_unsandboxed:
            argv.append("--require-sandbox")
        if core.artifact:
            argv += ["--core-artifact", core.artifact]
        if core.repo:
            argv += ["--core-repo", core.repo]
        if core.commit:
            argv += ["--core-commit", core.commit]
        if core.build_command:
            argv += ["--build-command", core.build_command]
        if content and load:
            argv += ["--content", str(load), "--content-label", content.name]
        return argv

    # -- the checks -------------------------------------------------------------

    def check_key(self, core: Core, content: Content, check: str) -> str:
        return f"{core.name}/{content.system}/{slug(content.name)}/{check}"

    def remember(self, emulator: str, key: str, result: ProbeResult, core: Core | None,
                 digest: str) -> None:
        judged = None
        if result.record and result.record["inputs"].get("content"):
            judged = [result.record["inputs"]["content"]["sha1"], result.record["core"]["library_name"]]
        entry = {"status": result.status, "at": now_iso(), "profile_digest": digest,
                 "core_sha256": core.sha256 if core else None,
                 "record_version": mr.RECORD_VERSION, "oracle_sha256": self.oracle_digest(judged)}
        if judged:
            entry["oracle_key"] = judged
        if result.reason:
            entry["reason"] = result.reason
        if result.log:
            entry["log"] = result.log
        if result.record:
            entry["record"] = result.record["id"]
            if self.current:
                self.current.records.append(result.record["id"])
                self.current.touched.add(mr.records_path(emulator))
        self.state["checks"].setdefault(emulator, {})[key] = entry

    def pending(self, emulator: str, key: str, reason: str, digest: str = "") -> None:
        self.state["checks"].setdefault(emulator, {})[key] = {
            "status": PENDING, "reason": reason, "at": now_iso(), "profile_digest": digest}

    def oracle_digest(self, key: list[str] | None) -> str:
        """What a check's verdicts depend on in the oracle: the entries of its
        content and core, else the whole file. Another core's references
        never make a check run again."""
        if not key:
            return self.oracle_sha
        return mr.value_sha1(core_probe.oracle_for(self.oracle_data, *key))

    def needed(self, emulator: str, key: str, core: Core, digest: str) -> bool:
        previous = self.state["checks"].get(emulator, {}).get(key)
        judged = (previous or {}).get("oracle_key")
        if previous and not judged and previous.get("record"):
            record = self.read_record(emulator, previous["record"]) or {}
            if (record.get("inputs") or {}).get("content"):
                judged = [record["inputs"]["content"]["sha1"], record["core"]["library_name"]]
                previous["oracle_key"] = judged
                # Judged against the entries the record kept, not the file it named.
                kept = {k: v for k, v in (record["inputs"].get("oracle") or {}).items()
                        if k not in ("file", "sha256")}
                previous["oracle_sha256"] = mr.value_sha1({"bios_patterns": [], **kept})
        return should_run(previous, core.sha256, digest, self.oracle_digest(judged))

    def check(self, emulator: str, key: str, core: Core, digest: str, argv: list[str],
              log_name: str) -> dict | None:
        """The record of a check: run now when needed, else the one kept."""
        if not self.needed(emulator, key, core, digest):
            previous = self.state["checks"].get(emulator, {}).get(key) or {}
            return self.read_record(emulator, previous.get("record"))
        result = self.probe(argv, log_name)
        self.remember(emulator, key, result, core, digest)
        return result.record

    def system_entries(self, profile: dict, system: str) -> list[tuple[int, dict]]:
        from resolve.validation import filter_files_by_mode

        libretro = filter_files_by_mode(profile.get("files") or [], standalone=False)
        keep = {id(e) for e in libretro}
        return [(i, e) for i, e in enumerate(profile.get("files") or [])
                if id(e) in keep and system in entry_system_ids(e, profile) and is_bios(e)]

    def boot_entry(self, entries: list[tuple[int, dict]], content: Content) -> tuple[int, dict] | None:
        held = [(i, e) for i, e in entries if region_matches(e, content.region) and self.local_file(e)]
        if content.boot_file:
            named = [(i, e) for i, e in held
                     if content.boot_file in (e["name"], *(e.get("aliases") or ()))]
            if named:
                return named[0]
        held.sort(key=lambda item: (item[1].get("priority", 1 << 30), item[0]))
        return held[0] if held else None

    @staticmethod
    def other_regions(entry: dict, staged: dict[str, tuple[int, dict, Path]], local: Path) -> list[Path]:
        """Held dumps of the same system for regions this entry does not
        serve, one per distinct file: the wrong-region variants."""
        mine = set(regions_of(entry))
        if not mine or "world" in mine:
            return []
        out: dict[str, Path] = {}
        for _, other, path in staged.values():
            theirs = set(regions_of(other))
            if theirs and "world" not in theirs and not theirs & mine and path.resolve() != local.resolve():
                out.setdefault(file_digest(path), path)
        return sorted(out.values(), key=lambda p: p.name)[:MAX_REGION_DUMPS]

    def run_unit_content(self, unit: Unit, core: Core, content: Content, digest: str) -> None:
        emulator, profile = unit.emulator, unit.profile
        entries = self.system_entries(profile, content.system)
        staged: dict[str, tuple[int, dict, Path]] = {}
        for index, entry in entries:
            local = self.local_file(entry)
            if local and entry_dest(entry) not in staged:
                staged[entry_dest(entry)] = (index, entry, local)
        tested = {dest: item for dest, item in staged.items() if region_matches(item[1], content.region)}
        keys = self.content_keys(core, content, tested)
        # The rules run on every pass, from the records kept when nothing
        # needs to run again: a change of the table applies without a run.
        try:
            folder = self.store.get(content)
            load = load_file(folder, content.load)
        except Unavailable as exc:
            for key in keys.values():
                if self.needed(emulator, key, core, digest):
                    self.pending(emulator, key, str(exc), digest)
            return
        frames = ["--frames", str(content.frames), "--frame-hash-every", str(content.frame_hash_every)]
        trial = Trial(unit, core, content, load, frames, digest)
        records = self.reference_runs(trial, keys, staged)
        if not records:
            return
        files_record, none_record = records
        full = rules.run_of(files_record, files_record["variants"][0]["label"])
        none = rules.run_of(none_record, none_record["variants"][0]["label"])
        self.log(f"{emulator}: {core.name} on {content.name}: full set {full.verdict}, "
                 f"no BIOS {none.verdict}")

        for dest, (index, entry, local) in sorted(tested.items()):
            self.test_entry(trial, keys[f"negative:{dest}"], Held(index, entry, dest, local), staged,
                            files_record, none)

        boot = self.boot_entry(entries, content)
        if boot and entry_dest(boot[1]) in tested:
            index, entry = boot
            self.follow_aliases(trial, index, entry, tested[entry_dest(entry)][2], none_record)

        if self.settings.bench and full.verdict == rules.BOOTS:
            self.bench(trial, keys["bench"], boot)

    def content_keys(self, core: Core, content: Content,
                     tested: dict[str, tuple[int, dict, Path]]) -> dict[str, str]:
        keys = {"files": self.check_key(core, content, "files"),
                "none": self.check_key(core, content, "none")}
        for dest in tested:
            keys[f"negative:{dest}"] = self.check_key(core, content, f"negative:{dest}")
        if self.settings.bench:
            keys["bench"] = self.check_key(core, content, "bench")
        return keys

    def reference_runs(self, trial: Trial, keys: dict[str, str],
                       staged: dict[str, tuple[int, dict, Path]]) -> tuple[dict, dict] | None:
        """The full set and no BIOS at all, or None while either is missing."""
        core, emulator, content, load = trial.core, trial.unit.emulator, trial.content, trial.load
        repeat = ["--repeat", str(self.settings.check_repeat)]
        stem = f"{core.name}-{slug(content.name)}"

        # files: every declared file the collection holds, at its place.
        argv = self.probe_args("run", core, emulator, slug(f"files-{stem}"), content, load) + trial.frames + repeat
        for dest, (_, _, local) in sorted(staged.items()):
            argv += ["--system-file", f"{dest}={local}"]
        files_record = self.check(emulator, keys["files"], core, trial.digest, argv, f"{emulator}-{stem}-files")
        # none: no BIOS at all.
        argv = self.probe_args("run", core, emulator, slug(f"none-{stem}"), content, load) + trial.frames + repeat
        none_record = self.check(emulator, keys["none"], core, trial.digest, argv, f"{emulator}-{stem}-none")
        if not files_record or not none_record:
            return None
        return files_record, none_record

    def test_entry(self, trial: Trial, key: str, held: Held, staged: dict[str, tuple[int, dict, Path]],
                   files_record: dict, none: rules.Run) -> None:
        """One declared file alone and replaced, then what its runs settle."""
        emulator, content, entry = trial.unit.emulator, trial.content, held.entry
        record = self.negative(trial, key, held, staged)
        if not record:
            return
        labels = [v["label"] for v in record["variants"]]
        present = rules.run_of(record, labels[0])
        zeros, half = (rules.run_of(record, label) for label in labels[1:3])
        for label in labels[3:]:
            self.log(f"{emulator}: {rules.rule_region(rules.run_of(record, label), present, entry, content.region)}")
        if held.dest in self.opened(files_record, 0) or held.dest in self.opened(record, 0):
            verdicts = rules.rule_need(none, present, entry, rules.read(none, present, zeros, half))
            validation = rules.rule_validation(zeros, half, none, present, entry)
            if validation:
                verdicts.append(validation)
            self.settle(emulator, content, trial.core, held.index, entry, verdicts)
            variants = self.variant_files(entry, held.local)
            if variants:
                self.run_variants(trial, held, variants)
        else:
            self.moved(trial, held, files_record, record)

    def bench(self, trial: Trial, key: str, boot: tuple[int, dict] | None) -> None:
        core, emulator, content = trial.core, trial.unit.emulator, trial.content
        stem = f"{core.name}-{slug(content.name)}"
        argv = self.probe_args("bench", core, emulator, slug(f"bench-{stem}"), content, trial.load)
        argv += ["--warmup", str(self.settings.bench_warmup), "--frames",
                 str(self.settings.bench_frames), "--repeat", str(self.settings.bench_repeat),
                 "--no-trace"]
        if boot:
            argv += ["--system-file", f"{entry_dest(boot[1])}={self.local_file(boot[1])}"]
        self.check(emulator, key, core, trial.digest, argv, f"{emulator}-{stem}-bench")

    def negative(self, trial: Trial, key: str, held: Held,
                 staged: dict[str, tuple[int, dict, Path]]) -> dict | None:
        """The file alone, then wrong files under its name: zeros of its
        size, its first half, and other regions' dumps."""
        core, content, entry, dest, local = trial.core, trial.content, held.entry, held.dest, held.local
        unit = trial.unit
        stem = f"{core.name}-{slug(content.name)}"
        size = local.stat().st_size
        others = self.other_regions(entry, staged, local)
        argv = self.probe_args("check", core, unit.emulator, slug(f"negative-{entry['name']}-{stem}"),
                               content, trial.load) + trial.frames
        argv += ["--vary", f"{dest}={local}", "--vary", f"{dest}=@zeros:{size}",
                 "--vary", f"{dest}=@head:{size // 2}:{local}"]
        for other in others:
            argv += ["--vary", f"{dest}={other}"]
        regions = f", then {', '.join(p.name for p in others)} staged under its name" if others else ""
        argv += ["--observable", "frame_hashes", "--repeat", str(self.settings.check_repeat),
                 "--claim", (f"{core.name} boots {content.name} with {entry['name']} alone and "
                             f"refuses a wrong file under its name"),
                 "--method", (f"{entry['name']} alone as {dest}, then {size} zero bytes and its "
                              f"first {size // 2} bytes{regions}, nothing else staged. Each run "
                              f"{self.settings.check_repeat} times from a fresh process for "
                              f"{content.frames} frames with no button pressed, every "
                              f"{content.frame_hash_every}th frame hashed. The boot oracle judges "
                              f"each variant against the reference frames of {content.name}.")]
        return self.check(unit.emulator, key, core, trial.digest, argv, f"{unit.emulator}-{stem}-negative")

    def moved(self, trial: Trial, held: Held, files_record: dict, alone: dict) -> None:
        """A file the core opened neither in the full set nor alone: where
        else it looked for a file of that name, else flagged."""
        unit, core, content = trial.unit, trial.core, trial.content
        index, entry, dest = held.index, held.entry, held.dest
        probed = [p for record in (files_record, alone) for r in record["variants"][0]["repetitions"]
                  for p in r.get("files_probed_absent") or ()]
        others = [p for p in dict.fromkeys(probed) if p != dest
                  and p.rsplit("/", 1)[-1].casefold() == dest.rsplit("/", 1)[-1].casefold()]
        for candidate in others[:MAX_ALIAS_CANDIDATES]:
            found = self.follow_up(trial, entry, held.local, candidate, f"path:{entry['name']}:{candidate}")
            if found and candidate in self.opened(found, 0):
                verdict = rules.rule_path(entry, dest, rules.Opened(candidate, found["id"]))
                if verdict:
                    self.settle(unit.emulator, content, core, index, entry, [verdict])
                    return
        verdict = rules.rule_never_opened(entry, [files_record["id"], alone["id"]], content.name)
        self.settle(unit.emulator, content, core, index, entry, [verdict])

    def read_record(self, emulator: str, rid: str | None) -> dict | None:
        return mr.read_record(self.paths.root, emulator, rid)

    @staticmethod
    def opened(record: dict, position: int) -> set[str]:
        out: set[str] = set()
        for rep in record["variants"][position]["repetitions"]:
            out |= {item["path"] for item in rep.get("files_opened") or ()}
        return out

    def follow_up(self, trial: Trial, entry: dict, local: Path, dest: str, check: str) -> dict | None:
        """The file staged at dest alone: does the core open it there."""
        unit, core, content = trial.unit, trial.core, trial.content
        stem = f"{core.name}-{slug(content.name)}"
        argv = self.probe_args("run", core, unit.emulator, slug(f"{check}-{stem}"), content, trial.load)
        argv += trial.frames + ["--system-file", f"{dest}={local}"]
        return self.check(unit.emulator, self.check_key(core, content, check), core, trial.digest, argv,
                          f"{unit.emulator}-{stem}-{slug(check)}")

    def follow_aliases(self, trial: Trial, index: int, entry: dict, local: Path, none_record: dict) -> None:
        """Names the core looked for, with no BIOS, that no entry declares."""
        unit, core, content = trial.unit, trial.core, trial.content
        declared = {e["name"] for e in unit.profile.get("files") or ()}
        declared |= {a for e in unit.profile.get("files") or () for a in e.get("aliases") or ()}
        suffix = Path(entry["name"]).suffix.casefold()
        dest = entry_dest(entry)
        folder = dest.rsplit("/", 1)[0] if "/" in dest else ""
        probed: list[str] = []
        for rep in none_record["variants"][0]["repetitions"]:
            for path in rep.get("files_probed_absent") or ():
                name = path.rsplit("/", 1)[-1]
                where = path.rsplit("/", 1)[0] if "/" in path else ""
                if (where == folder and name not in declared and Path(name).suffix.casefold() == suffix
                        and path not in probed):
                    probed.append(path)
        for candidate in probed[:MAX_ALIAS_CANDIDATES]:
            found = self.follow_up(trial, entry, local, candidate,
                                   f"alias:{entry['name']}:{candidate.rsplit('/', 1)[-1]}")
            if found and candidate in self.opened(found, 0):
                verdict = rules.rule_alias(self.reload_entry(unit, index), rules.Opened(candidate, found["id"]))
                if verdict:
                    self.settle(unit.emulator, content, core, index, self.reload_entry(unit, index), [verdict])

    def run_variants(self, trial: Trial, held: Held, variants: list[Path]) -> None:
        unit, core, content, digest = trial.unit, trial.core, trial.content, trial.digest
        index, entry, dest = held.index, held.entry, held.dest
        key = self.check_key(core, content, f"variants:{entry['name']}")
        if not self.needed(unit.emulator, key, core, digest):
            return
        stem = f"{core.name}-{slug(content.name)}"
        argv = self.probe_args("check", core, unit.emulator, slug(f"variants-{entry['name']}-{stem}"),
                               content, trial.load) + trial.frames
        for path in [held.local, *variants]:
            argv += ["--vary", f"{dest}={path}"]
        argv += ["--observable", "frame_hashes", "--repeat", str(self.settings.check_repeat),
                 "--claim", f"every copy of {entry['name']} boots {content.name} on {core.name}",
                 "--method", (f"Each copy the collection holds staged alone as {dest}, each run "
                              f"{self.settings.check_repeat} times for {content.frames} frames. The "
                              f"boot oracle judges each copy.")]
        record = self.check(unit.emulator, key, core, digest, argv, f"{unit.emulator}-{stem}-variants")
        if record:
            verdict = rules.rule_variants([rules.run_of(record, v["label"]) for v in record["variants"]],
                                          entry)
            if verdict:
                self.settle(unit.emulator, content, core, index, entry, [verdict])

    # -- verdicts -----------------------------------------------------------------

    def reload_entry(self, unit: Unit, index: int) -> dict:
        path = self.paths.emulators / f"{unit.emulator}.yml"
        unit.profile = yaml.safe_load(path.read_text(encoding="utf-8"))
        return unit.profile["files"][index]

    def settle(self, emulator: str, content: Content, core: Core, index: int, entry: dict,
               verdicts: Sequence[rules.Verdict]) -> None:
        """Apply what the table settles, queue the rest, resolve what now agrees."""
        path = self.paths.emulators / f"{emulator}.yml"
        for verdict in verdicts:
            fresh = (yaml.safe_load(path.read_text(encoding="utf-8")).get("files") or [])[index]
            if fresh.get("name") != entry.get("name"):
                self.log(f"{emulator}: files[{index}] is no longer {entry.get('name')}, nothing applied")
                return
            says = rules.current(fresh, verdict.field) if verdict.field in rules.SETTLED_FIELDS \
                else None
            agrees = verdict.field in rules.SETTLED_FIELDS and rules.agrees(fresh, verdict)
            if verdict.apply:
                updates: dict[str, object] = {}
                if not agrees or (verdict.field not in fresh and verdict.field != "validation"):
                    updates[verdict.field] = verdict.value
                evidence = rules.merge_evidence(fresh.get("evidence"), verdict,
                                                keep=lambda rid: mr.judged(self.paths.root, emulator, rid))
                if evidence != fresh.get("evidence"):
                    updates["evidence"] = evidence
                if updates:
                    try:
                        changed = write_fields(path, index, updates)
                    except ProfileEditError as exc:
                        self.finding(emulator, content, core, fresh, verdict, "open", says,
                                     extra=f". Not written: {exc}")
                        continue
                    if changed and self.current:
                        self.current.touched.add(path.relative_to(self.paths.root).as_posix())
                if agrees:
                    self.resolve(emulator, content, core, fresh, verdict, says)
                else:
                    self.finding(emulator, content, core, fresh, verdict, "applied", says)
                continue
            if verdict.rule == "never_opened":
                self.finding(emulator, content, core, fresh, verdict, "flagged", None)
            elif agrees:
                self.resolve(emulator, content, core, fresh, verdict, says)
            else:
                self.finding(emulator, content, core, fresh, verdict, "open", says)

    def finding_key(self, emulator: str, content: Content, entry: dict, verdict: rules.Verdict) -> str:
        return f"{emulator}/{content.system}/{entry['name']}/{verdict.field}"

    def finding(self, emulator: str, content: Content, core: Core, entry: dict,
                verdict: rules.Verdict, status: str, says: object, extra: str = "") -> None:
        key = self.finding_key(emulator, content, entry, verdict)
        previous = latest_findings(self.paths.root).get(key)
        if previous and previous["status"] == status and previous["rule"] == verdict.rule \
                and previous["run_shows"] == verdict.value and previous["profile_says"] == says \
                and previous["evidence"] == list(verdict.evidence):
            return
        # A review that read the code and kept the profile stands while the
        # runs keep showing the same thing.
        if previous and previous["status"] == "rejected" and status == "open" \
                and previous["rule"] == verdict.rule and previous["run_shows"] == verdict.value \
                and previous["profile_says"] == says:
            return
        line = mr.seal_line({
            "schema_version": 1, "found_at": now_iso(), "key": key, "emulator": emulator,
            "system": content.system, "file": entry["name"], "field": verdict.field,
            "status": status, "rule": verdict.rule, "profile_says": says, "run_shows": verdict.value,
            "statement": verdict.statement + extra, "evidence": list(verdict.evidence),
            "core": {"file": core.path.name, "sha256": core.sha256,
                     "library_version": self.library_version(emulator, verdict.evidence)},
            "content": content.name,
        }, "found_at")
        path = self.paths.root / mr.records_path(mr.FINDINGS)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(mr.line_text(line) + "\n")
        if self.current:
            self.current.findings[status] = self.current.findings.get(status, 0) + 1
            self.current.touched.add(mr.records_path(mr.FINDINGS))
        self.log(f"finding {status}: {key}: {verdict.statement}")

    def resolve(self, emulator: str, content: Content, core: Core, entry: dict,
                verdict: rules.Verdict, says: object) -> None:
        previous = latest_findings(self.paths.root).get(self.finding_key(emulator, content, entry, verdict))
        if previous and previous["status"] in OPEN_STATUSES:
            self.finding(emulator, content, core, entry, verdict, "resolved", says)

    def library_version(self, emulator: str, ids: Sequence[str]) -> str | None:
        for rid in ids:
            record = self.read_record(emulator, rid)
            if record:
                return record["core"].get("library_version")
        return None

    # -- reference frames -----------------------------------------------------------

    def references(self, only: set[str], system: str | None, png_dir: Path) -> list[dict]:
        """The full set run once per core and content, frames written as PNG,
        and the screens that stay on long enough to serve as references."""
        self.deadline = self.host.clock() + self.settings.budget
        listed = []
        for unit in self.units(only, system):
            contents = self.unit_contents(unit, system)
            if unit.pending or not contents:
                continue
            try:
                cores = self.unit_cores(unit.emulator, unit.profile, unit.buildbot_only)
            except Unavailable as exc:
                self.log(f"{unit.emulator}: {exc}")
                continue
            for core in cores:
                for content in contents:
                    self.guard()
                    self.store.hold(content, "references")
                    try:
                        load = load_file(self.store.get(content), content.load)
                    except Unavailable as exc:
                        self.log(f"{unit.emulator}: {exc}")
                        continue
                    stem = f"{core.name}-{slug(content.name)}"
                    target = png_dir / slug(core.name) / slug(content.name)
                    shutil.rmtree(target, ignore_errors=True)
                    argv = self.probe_args("run", core, unit.emulator, slug(f"references-{stem}"),
                                           content, load)
                    argv += ["--frames", str(content.frames), "--frame-hash-every",
                             str(content.frame_hash_every), "--repeat", str(self.settings.check_repeat),
                             "--png-dir", str(target)]
                    for _, entry in self.system_entries(unit.profile, content.system):
                        local = self.local_file(entry)
                        if local and f"{entry_dest(entry)}=" not in " ".join(argv):
                            argv += ["--system-file", f"{entry_dest(entry)}={local}"]
                    result = self.probe(argv, f"{unit.emulator}-{stem}-references")
                    self.store.release(content, "references")
                    if not result.record:
                        self.log(f"{unit.emulator}: references of {content.name}: {result.reason}")
                        continue
                    record = result.record
                    listed.append({
                        "emulator": unit.emulator, "core": core.name,
                        "library_name": record["core"]["library_name"], "content": content.name,
                        "content_sha1": record["inputs"]["content"]["sha1"], "record": record["id"],
                        "verdict": record["variants"][0]["verdict"],
                        "png_dir": str(target / record["variants"][0]["label"]),
                        "candidates": reference_candidates(record),
                    })
        save_state(self.paths.state, self.state)
        return listed

    # -- the pass -----------------------------------------------------------------

    def units(self, only: set[str], system: str | None) -> list[Unit]:
        out = []
        for emulator, profile in sorted(self.profiles().items()):
            cores = {str(c) for c in profile.get("cores") or ()}
            if only and emulator not in only and not (cores & only):
                continue
            systems = set(profile.get("systems") or ())
            if system and system not in systems:
                continue
            kind = str(profile.get("type") or "")
            if kind in ("alias", "launcher", "test"):
                continue
            if "libretro" in kind or kind in ("game", "utility"):
                out.append(Unit(emulator, profile, buildbot_only="libretro" not in kind))
                continue
            out.append(Unit(emulator, profile, pending="standalone"))
        return out

    def unit_contents(self, unit: Unit, system: str | None) -> list[Content]:
        systems = [s for s in unit.profile.get("systems") or () if not system or s == system]
        return [c for s in systems for c in self.content.get(s, ())]

    def run(self, only: set[str], system: str | None, commit_every: int = 0,
            commit: bool = False) -> Pass:
        self.deadline = self.host.clock() + self.settings.budget
        current = self.current = Pass(started=now_iso())
        units = self.units(only, system)
        isolation = core_probe.sandbox_argv([])[1]
        if isolation != core_probe.SANDBOX and not self.settings.allow_unsandboxed:
            # Fail closed: no core and no build runs outside the sandbox.
            current.result = "refused"
            current.detail = (f"no sandbox for third-party code ({isolation}). Install bubblewrap, "
                              f"or pass --allow-unsandboxed")
            self.log(f"pass refused: {current.detail}")
            self.write_run_line(current)
            save_state(self.paths.state, self.state)
            return current
        for unit in units:
            for content in self.unit_contents(unit, system):
                self.store.hold(content, unit.emulator)
        done_units = 0
        try:
            for unit in units:
                self.run_unit(unit, system)
                done_units += 1
                save_state(self.paths.state, self.state)
                if commit and commit_every and done_units % commit_every == 0:
                    self.commit_batch()
        except Pause as exc:
            current.result = "budget" if str(exc) == "budget" else "paused"
            current.detail = str(exc)
            self.log(f"pass paused: {exc}")
        except KeyboardInterrupt:
            current.result, current.detail = "stopped", "interrupted"
        finally:
            for unit in units:
                for content in self.unit_contents(unit, system):
                    self.store.release(content, unit.emulator)
            self.prune_logs()
            self.write_run_line(current)
            save_state(self.paths.state, self.state)
        if commit:
            self.commit_batch()
        return current

    def run_unit(self, unit: Unit, system: str | None) -> None:
        emulator, profile = unit.emulator, unit.profile
        digest = self.digest_on_disk(emulator)
        contents = self.unit_contents(unit, system)
        systems = [s for s in profile.get("systems") or () if not system or s == system]
        if unit.pending:
            for s in systems:
                self.pending(emulator, f"*/{s}/*", unit.pending, digest)
            return
        if not contents:
            for s in systems:
                self.pending(emulator, f"*/{s}/*", f"content: no test content listed for {s}", digest)
            return
        try:
            cores = self.unit_cores(emulator, profile, unit.buildbot_only)
        except Unavailable as exc:
            for s in systems:
                self.pending(emulator, f"*/{s}/*", str(exc), digest)
            self.log(f"{emulator}: {exc}")
            return
        for s in systems:
            self.state["checks"].setdefault(emulator, {}).pop(f"*/{s}/*", None)
        for core in cores:
            self.log(f"{emulator}: core {core.name} {core.sha256[:12]}")
            for content in contents:
                self.guard()
                self.run_unit_content(Unit(emulator, profile, core.name), core, content, digest)
        for content in contents:
            self.store.release(content, emulator)
        self.state["emulators"][emulator] = {"profile_digest": self.digest_on_disk(emulator),
                                             "at": now_iso()}
        # The campaign's own edits do not make its checks run again.
        new_digest = self.state["emulators"][emulator]["profile_digest"]
        for entry in self.state["checks"].get(emulator, {}).values():
            if entry.get("profile_digest") == digest:
                entry["profile_digest"] = new_digest

    def unit_cores(self, emulator: str, profile: dict, buildbot_only: bool = False) -> list[Core]:
        names = self.cores.names(profile)
        if names:
            return [self.cores.nightly(name, profile) for name in names]
        if buildbot_only:
            raise Unavailable("standalone: no libretro core on the buildbot")
        return [self.cores.build(emulator, profile)]

    def describe(self, only: set[str], system: str | None) -> list[str]:
        """One line per unit a pass would run: its cores and content, or why it waits."""
        lines = []
        for unit in self.units(only, system):
            contents = self.unit_contents(unit, system)
            if unit.pending:
                lines.append(f"{unit.emulator}: pending, {unit.pending}")
            elif not contents:
                lines.append(f"{unit.emulator}: pending, no test content for "
                             f"{', '.join(unit.profile.get('systems') or ())}")
            else:
                cores = sorted({str(c) for c in unit.profile.get("cores") or ()})
                lines.append(f"{unit.emulator}: cores {', '.join(cores)} on "
                             f"{', '.join(c.name for c in contents)}")
        return lines

    def counts(self) -> tuple[dict[str, int], dict[str, int], list[dict]]:
        counts = {DONE: 0, FAILED: 0, PENDING: 0}
        reasons: dict[str, int] = {}
        failed = []
        for emulator, checks in sorted(self.state["checks"].items()):
            for key, entry in sorted(checks.items()):
                status = entry.get("status", PENDING)
                counts[status] = counts.get(status, 0) + 1
                if status == PENDING:
                    reason = reason_class(entry.get("reason", ""))
                    reasons[reason] = reasons.get(reason, 0) + 1
                elif status == FAILED:
                    failed.append({"emulator": emulator, "check": key, "reason": entry.get("reason", "")})
        return counts, reasons, failed

    def write_run_line(self, current: Pass) -> None:
        counts, reasons, failed = self.counts()
        line = mr.seal_line({
            "schema_version": 1, "started_at": current.started, "ended_at": now_iso(),
            "result": current.result, "detail": current.detail, "counts": counts,
            "pending_reasons": reasons, "failed": failed, "records": current.records,
            "findings": dict(sorted(current.findings.items())),
        }, "started_at")
        path = self.paths.root / mr.records_path(mr.CAMPAIGN_RUNS)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(mr.line_text(line) + "\n")
        current.touched.add(mr.records_path(mr.CAMPAIGN_RUNS))
        self.state["last_run"] = {k: line[k] for k in ("id", "started_at", "ended_at", "result", "detail")}

    def prune_logs(self) -> None:
        limit = time.time() - LOG_DAYS * 86400
        for path in self.paths.logs.rglob("*.log") if self.paths.logs.is_dir() else ():
            if path.stat().st_mtime < limit:
                path.unlink()

    # -- commits (direct runs, autorun commits by its own rules) -------------------

    def plan_commits(self, dirty_at_start: set[str]) -> list[tuple[str, list[str]]]:
        """(subject, paths) of each commit: the records, then one per profile."""
        touched = sorted(self.current.touched if self.current else ())
        records = [p for p in touched if p.startswith(f"{mr.RECORDS_DIR}/") and p not in dirty_at_start]
        plan = []
        if records:
            plan.append(("chore: add campaign measurements", records))
        for path in touched:
            if path.startswith("emulators/") and path not in dirty_at_start:
                subject = f"chore: apply tested fields to {Path(path).stem}"
                if len(subject) > 50:
                    subject = "chore: apply tested profile fields"
                plan.append((subject, [path]))
        return plan

    def commit_batch(self) -> list[str]:
        plan = self.plan_commits(self.dirty_at_start)
        if not plan:
            return []
        if gate(self.paths.root, [Path(p).stem for _, ps in plan for p in ps if p.startswith("emulators/")],
                self.host) != 0:
            self.log("gate failed, nothing committed")
            return []
        made = []
        for subject, paths in plan:
            problems = jobs.check_subject(subject)
            if problems:
                raise ValueError(f"{subject!r}: {', '.join(problems)}")
            made.append(worktree.commit_paths(self.paths.root, paths, jobs.CommitRule(subject, tuple(paths))))
        if self.current:
            self.current.touched.clear()
        return made


def reference_candidates(record: dict, min_samples: int = 3) -> list[dict]:
    """Screens of a record's first variant that are not one colour and stay
    on for at least min_samples consecutive samples in every repetition:
    what a reviewer looks at to choose reference frames."""
    found: list[dict[str, tuple[int, int]]] = []
    for rep in record["variants"][0]["repetitions"]:
        observables = rep.get("observables") or {}
        uniform = set(observables.get("uniform_frames") or ())
        runs: dict[str, tuple[int, int]] = {}
        previous, start, length = None, 0, 0
        for frame, digest in [*(observables.get("frame_hashes") or ()), (None, None)]:
            if digest == previous:
                length += 1
                continue
            if previous and previous not in uniform and length >= min_samples:
                first, longest = runs.get(previous, (start, 0))
                runs[previous] = (min(first, start), max(longest, length))
            previous, start, length = digest, frame, 1
        found.append(runs)
    common = set(found[0]) if found else set()
    for runs in found[1:]:
        common &= set(runs)
    return sorted(({"sha1": digest, "first_frame": found[0][digest][0], "samples": found[0][digest][1]}
                   for digest in common), key=lambda item: item["first_frame"])


def reason_class(reason: str) -> str:
    """A pending reason without its detail, to count them."""
    head = reason.split(":", 1)[0].strip() if ":" in reason else reason
    return head or "unknown"
