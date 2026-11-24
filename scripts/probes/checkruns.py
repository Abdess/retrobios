"""What every check of a campaign shares: probe runs, the state each check is recorded in, and the findings they settle."""

from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

import yaml

import core_probe
from core import hostguard
from core.hashing import file_digest
from core.paths import REPO_ROOT
from core.statefile import now_iso
from model import measurements as mr
from probes import rules
from probes.content import Content, ContentStore, load_content
from probes.cores import Core, Cores
from probes.entries import held_file, held_variants, profile_digest
from probes.findings import OPEN_STATUSES, latest_findings
from probes.host import (
    Host,
    Paths,
    Settings,
    StillBusy,
    child_env,
    run_when_idle,
    slug,
    wait_for_load,
)
from probes.profileedit import ProfileEditError, write_fields
from probes.state import DONE, FAILED, PENDING, load_state, should_run


CRASH_ATTEMPTS = 3


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


@dataclass
class Pass:
    started: str
    records: list[str] = field(default_factory=list)
    findings: dict[str, int] = field(default_factory=dict)
    touched: set[str] = field(default_factory=set)
    result: str = "complete"
    detail: str = ""


class CheckRuns:
    """What every check of a campaign shares: settings and paths, probe runs, recorded state, findings."""

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

    def read_record(self, emulator: str, rid: str | None) -> dict | None:
        return mr.read_record(self.paths.root, emulator, rid)

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
