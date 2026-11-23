"""One job run: the host checks, the steps retried after a misread, the artifacts
computed twice, the commits, the state and the logs.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from core.artifacts import TIMESTAMP_KEYS
from core.hostguard import LockBusy, free_gb, global_lock, lock_busy
from core.paths import AUTORUN_DIR, AUTORUN_WORKTREE
from core.statefile import now_iso, save_state
from unattended.breaker import may_push, refresh_breaker
from unattended.jobs import AutorunError, BLOCKED, DEFERRED, FAILED, Job, OK, REFUSED, Step, job_env
from unattended.worktree import (
    changed_files,
    commit_paths,
    ensure_worktree,
    plan_commit,
    push_batch,
    seed_worktree,
    sync_worktree,
    unpushed,
)


ALERT_FREE_GB = 100
LOG_DAYS = 30
SEGFAULT_CODES = (139, -11)
HOST_MISREAD_MARKERS = ("SystemError", "unknown opcode")


@dataclass
class Outcome:
    returncode: int
    text: str = ""
    retried: bool = False


@dataclass
class Host:
    """What a run reads from the machine, replaced by fakes in the tests."""

    loadavg: Callable[[], tuple[float, float, float]] = os.getloadavg
    sleep: Callable[[float], None] = time.sleep
    clock: Callable[[], float] = time.monotonic
    cpu_count: int = os.cpu_count() or 1
    poll: float = 60.0

    @property
    def max_load(self) -> float:
        return self.cpu_count / 4


@dataclass
class Context:
    repo: Path
    jobs: dict[str, Job]
    lock_path: Path
    host: Host = field(default_factory=Host)
    gh: Callable[[list[str]], object] | None = None
    dry_run: bool = False
    push: bool = False

    @property
    def home(self) -> Path:
        return self.repo / AUTORUN_DIR

    @property
    def worktree(self) -> Path:
        return self.repo / AUTORUN_WORKTREE

    @property
    def state_path(self) -> Path:
        return self.home / "state.json"


# Host guards


def wait_for_load(host: Host, max_wait: float) -> bool:
    """True once the 1-minute load is at most a quarter of the CPUs."""
    deadline = host.clock() + max_wait
    while True:
        if host.loadavg()[0] <= host.max_load:
            return True
        left = deadline - host.clock()
        if left <= 0:
            return False
        host.sleep(min(host.poll, left))


def host_misread(returncode: int, text: str) -> bool:
    """A failure this host's CPU produces under load, worth one idle retry."""
    if returncode in SEGFAULT_CODES:
        return True
    return returncode != 0 and any(marker in text for marker in HOST_MISREAD_MARKERS)


# Running commands


def resolve_argv(argv: Sequence[str], out: str = "") -> list[str]:
    """`python` is the interpreter running autorun, {out} the scratch output."""
    resolved = [sys.executable if a == "python" else a for a in argv]
    return [a.replace("{out}", out) for a in resolved] if out else resolved


def execute(
    argv: Sequence[str],
    cwd: Path,
    log: Path,
    env: dict[str, str],
    timeout: float,
    stdout: Path | None = None,
) -> Outcome:
    """Run one command, its output appended to the job log."""
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a", encoding="utf-8") as handle:
        handle.write(f"$ {shlex.join(argv)}\n")
        start = handle.tell()
    try:
        with log.open("a", encoding="utf-8") as handle:
            if stdout is not None:
                stdout.parent.mkdir(parents=True, exist_ok=True)
                with stdout.open("w", encoding="utf-8") as out:
                    proc = subprocess.run(
                        list(argv), cwd=cwd, stdout=out, stderr=handle,
                        env=env, timeout=max(1, timeout), check=False,
                    )
            else:
                proc = subprocess.run(
                    list(argv), cwd=cwd, stdout=handle, stderr=subprocess.STDOUT,
                    env=env, timeout=max(1, timeout), check=False,
                )
        returncode = proc.returncode
    except subprocess.TimeoutExpired:
        returncode = 124
        with log.open("a", encoding="utf-8") as handle:
            handle.write(f"\nTIMEOUT after {int(timeout)}s\n")
    except OSError as exc:
        returncode = 127
        with log.open("a", encoding="utf-8") as handle:
            handle.write(f"\ncannot run: {exc}\n")
    with log.open("rb") as handle:
        handle.seek(start)
        text = handle.read().decode("utf-8", errors="replace")
    return Outcome(returncode, text)


def run_with_retry(
    run: Callable[[], Outcome],
    ok_codes: Sequence[int],
    wait_idle: Callable[[], object],
) -> Outcome:
    """Run once, and once more on an idle host when the failure is a misread."""
    first = run()
    if first.returncode in ok_codes or not host_misread(first.returncode, first.text):
        return first
    wait_idle()
    second = run()
    second.retried = True
    return second


# Double computation


def strip_volatile(value: object) -> object:
    if isinstance(value, dict):
        return {k: strip_volatile(v) for k, v in value.items() if k not in TIMESTAMP_KEYS}
    if isinstance(value, list):
        return [strip_volatile(v) for v in value]
    return value


def comparable(path: Path) -> object:
    if path.suffix == ".json":
        with contextlib.suppress(ValueError):
            return strip_volatile(json.loads(path.read_text(encoding="utf-8")))
    return path.read_bytes()


def _files(root: Path, glob: str) -> dict[str, Path]:
    if not root.is_dir():
        return {}
    found = root.glob(glob) if glob else root.rglob("*")
    return {p.relative_to(root).as_posix(): p for p in found if p.is_file()}


def differences(a: Path, b: Path, glob: str = "") -> list[str]:
    """Files that differ between two outputs, timestamps aside."""
    if a.is_dir() or b.is_dir():
        files_a, files_b = _files(a, glob), _files(b, glob)
        return sorted(
            name for name in set(files_a) | set(files_b)
            if name not in files_a or name not in files_b
            or comparable(files_a[name]) != comparable(files_b[name])
        )
    if not a.is_file() or not b.is_file():
        return [a.name]
    return [] if comparable(a) == comparable(b) else [a.name]


def twice(
    argv: Sequence[str],
    out_a: Path,
    out_b: Path,
    run: Callable[[list[str]], Outcome],
    glob: str = "",
) -> list[str]:
    """Compute one output twice and name what the two runs disagree on."""
    for out in (out_a, out_b):
        outcome = run(resolve_argv(argv, str(out)))
        if outcome.returncode != 0:
            raise AutorunError(FAILED, f"{shlex.join(argv)} exited {outcome.returncode}")
    return differences(out_a, out_b, glob)


# State and logs


def load_state(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except ValueError as exc:
        raise AutorunError(FAILED, f"{path} is unreadable: {exc}") from exc


def prune_logs(logs: Path, days: int = LOG_DAYS, now: float | None = None) -> int:
    limit = (now if now is not None else time.time()) - days * 86400
    removed = 0
    for path in logs.glob("*/*.log") if logs.is_dir() else ():
        if path.stat().st_mtime < limit:
            path.unlink()
            removed += 1
    return removed


def set_alert(state: dict, name: str, active: bool, detail: str, now: str) -> None:
    alerts = state.setdefault("alerts", {})
    if active:
        alerts.setdefault(name, {"since": now})["detail"] = detail
    else:
        alerts.pop(name, None)


def _remove_scratch(root: Path, rel: str) -> None:
    target = (root / rel).resolve()
    if root.resolve() not in target.parents:
        raise AutorunError(FAILED, f"scratch path {rel} leaves {root}")
    if target.is_dir():
        shutil.rmtree(target)
    elif target.exists():
        target.unlink()


def read_report(root: Path, rel: str) -> object:
    """The JSON report a job's step wrote, kept in the job's state."""
    if not rel:
        return None
    try:
        return json.loads((root / rel).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except ValueError as exc:
        return {"unreadable": str(exc)}


class Runner:
    """One job run: guards, steps, gate, double computation, commits, push."""

    def __init__(self, ctx: Context, job: Job, state: dict) -> None:
        self.ctx = ctx
        self.job = job
        self.state = state
        self.cwd = ctx.worktree if job.worktree else ctx.repo
        self.log = ctx.home / "logs" / job.name / f"{dt.date.today().isoformat()}.log"
        self.deadline = ctx.host.clock() + job.timeout
        self.commits: list[str] = []
        self.retried: list[str] = []
        self.report: object = None

    def note(self, text: str) -> None:
        self.log.parent.mkdir(parents=True, exist_ok=True)
        with self.log.open("a", encoding="utf-8") as handle:
            handle.write(f"# {now_iso()} {text}\n")

    def wait_idle(self) -> None:
        self.note("host misread suspected, retrying once on an idle host")
        wait_for_load(self.ctx.host, self.job.max_load_wait)

    def run_step(self, step: Step, argv: list[str] | None = None) -> Outcome:
        argv = argv if argv is not None else resolve_argv(step.argv)
        stdout = self.cwd / step.stdout if step.stdout else None

        def once() -> Outcome:
            left = self.deadline - self.ctx.host.clock()
            if left <= 0:
                return Outcome(124, "job timeout reached")
            return execute(argv, self.cwd, self.log, job_env(self.job, step), left, stdout)

        outcome = run_with_retry(once, step.ok_codes, self.wait_idle)
        if outcome.retried:
            self.retried.append(shlex.join(argv))
        return outcome

    def run_all(self, steps: Sequence[Step], what: str) -> None:
        for step in steps:
            outcome = self.run_step(step)
            if outcome.returncode not in step.ok_codes:
                raise AutorunError(
                    FAILED, f"{what}: {shlex.join(step.argv)} exited {outcome.returncode}"
                )

    def regate(self) -> bool:
        """The gate on the rebased batch. What it regenerates is computed
        twice and committed under the same rules before the push."""
        try:
            self.run_all(self.job.gate, "gate")
            self.check_twice()
            self.commit()
        except AutorunError as exc:
            self.note(f"gate on the rebased batch: {exc.detail}")
            return False
        return True

    def check_twice(self) -> None:
        """Each shipped artifact the gate wrote, computed again and compared."""
        scratch = self.cwd / "tmp" / "autorun" / "twice"
        for index, item in enumerate(self.job.twice):
            artifact = self.cwd / item.artifact
            for attempt in (1, 2):
                slot = scratch / f"{index}-{attempt}"
                if slot.exists():
                    _remove_scratch(self.cwd, slot.relative_to(self.cwd).as_posix())
                if item.glob or artifact.is_dir():
                    slot.parent.mkdir(parents=True, exist_ok=True)
                    out = slot
                else:
                    slot.mkdir(parents=True)
                    out = slot / artifact.name
                rel = out.relative_to(self.cwd).as_posix()
                outcome = self.run_step(Step(item.argv), resolve_argv(item.argv, rel))
                if outcome.returncode != 0:
                    raise AutorunError(FAILED, f"recomputing {item.artifact} exited "
                                               f"{outcome.returncode}")
                diff = differences(artifact, out, item.glob)
                if not diff:
                    break
                self.note(f"{item.artifact}: second computation differs on "
                          f"{', '.join(diff[:10])}")
                if attempt == 1:
                    wait_for_load(self.ctx.host, self.job.max_load_wait)
                    continue
                set_alert(self.state, "host-integrity", True,
                          f"{item.artifact} computed twice differs", now_iso())
                raise AutorunError(FAILED, f"{item.artifact}: two computations disagree "
                                           f"on {', '.join(diff[:5])}")
        set_alert(self.state, "host-integrity", False, "", now_iso())

    def commit(self) -> None:
        changed = changed_files(self.cwd)
        for rule in self.job.commits:
            files = plan_commit(changed, rule.paths)
            if not files:
                continue
            sha = commit_paths(self.cwd, files, rule)
            self.commits.append(sha)
            self.note(f"committed {sha[:12]} {rule.subject} ({len(files)} files)")
        leftovers = changed_files(self.cwd)
        if leftovers:
            raise AutorunError(
                FAILED, f"{len(leftovers)} paths changed outside every commit rule: "
                + ", ".join(leftovers[:5])
            )

    def execute(self) -> tuple[str, str]:
        ctx, job = self.ctx, self.job
        free = free_gb(ctx.repo)
        set_alert(self.state, "disk", free < ALERT_FREE_GB,
                  f"{free:.0f} GB free, under {ALERT_FREE_GB} GB", now_iso())
        if free < job.min_free_gb:
            return REFUSED, f"{free:.0f} GB free, {job.name} needs {job.min_free_gb:.0f} GB"
        if not wait_for_load(ctx.host, job.max_load_wait):
            return DEFERRED, f"load stayed above {ctx.host.max_load:.1f}"
        if job.commits and ctx.gh is not None:
            refresh_breaker(self.state, ctx.gh, now_iso())
        if job.commits and self.state.get("breaker", {}).get("open"):
            return BLOCKED, "circuit breaker open: a pushed automation commit failed CI"
        base = ""
        if job.worktree:
            ensure_worktree(ctx.repo, ctx.worktree)
            seeded = seed_worktree(ctx.repo, ctx.worktree)
            if seeded:
                self.note(f"hard-linked {', '.join(seeded[:5])}")
            base = sync_worktree(ctx.worktree)
        try:
            self.run_all(job.steps, "step")
            self.run_all(job.gate, "gate")
            self.check_twice()
            if job.commits:
                self.commit()
            if ctx.push and job.commits:
                reason = may_push(self.state)
                if reason:
                    return OK, f"{len(self.commits)} commits, push held: {reason}"
                pushed = push_batch(ctx.worktree, base, self.regate)
                if pushed:
                    self.state["push"] = {"sha": pushed, "at": now_iso(), "ci": "pending"}
                    return OK, f"pushed {pushed[:12]}"
        finally:
            self.report = read_report(self.cwd, job.report)
            for rel in job.scratch:
                _remove_scratch(self.cwd, rel)
        return OK, f"{len(self.commits)} commits"


def describe(job: Job, ctx: Context) -> list[str]:
    """What a run would do, for --dry-run."""
    lines = [f"job {job.name} in {ctx.worktree if job.worktree else ctx.repo}"]
    lines += [f"  step  {shlex.join(s.argv)}" for s in job.steps]
    lines += [f"  gate  {shlex.join(s.argv)}" for s in job.gate]
    lines += [f"  twice {t.artifact}: {shlex.join(t.argv)}" for t in job.twice]
    changed = changed_files(ctx.worktree) if (ctx.worktree / ".git").exists() else []
    for rule in job.commits:
        files = plan_commit(changed, rule.paths)
        lines.append(f"  commit {rule.subject!r} paths {', '.join(rule.paths)}")
        lines += [f"    would commit {f}" for f in files]
    lines += [f"  scratch {s}" for s in job.scratch]
    return lines


class UnknownJob(LookupError):
    """A job name that automation/jobs.yml does not declare."""


def find_job(ctx: Context, name: str) -> Job:
    """The job of that name, or UnknownJob naming the declared ones."""
    job = ctx.jobs.get(name)
    if job is None:
        raise UnknownJob(f"unknown job {name!r}: {', '.join(sorted(ctx.jobs))}")
    return job


def run_job(ctx: Context, name: str) -> tuple[str, str]:
    """Run one job and record it, returning (result, detail)."""
    job = find_job(ctx, name)
    if ctx.dry_run:
        return OK, "dry run"
    state = load_state(ctx.state_path)
    runner = Runner(ctx, job, state)
    started, clock = now_iso(), ctx.host.clock()
    lock = global_lock(ctx.lock_path) if job.lock else contextlib.nullcontext()
    interrupted: SystemExit | None = None
    try:
        with lock:
            runner.note(f"start {name}")
            try:
                result, detail = runner.execute()
            except AutorunError as exc:
                result, detail = exc.result, exc.detail
            except OSError as exc:
                result, detail = FAILED, f"{type(exc).__name__}: {exc}"
            except SystemExit as exc:
                # SIGTERM or SIGHUP (core.cli.run_cli): the run is recorded
                # as failed, then the process ends with the signal's status.
                interrupted = exc
                result, detail = FAILED, f"interrupted, exit status {exc.code}"
    except LockBusy as exc:
        result, detail = DEFERRED, str(exc)
    runner.note(f"end {name}: {result} {detail}")
    previous = state.setdefault("jobs", {}).get(name, {})
    record = {
        "last_start": started,
        "last_end": now_iso(),
        "duration_sec": round(ctx.host.clock() - clock, 1),
        "result": result,
        "detail": detail,
        "commits": runner.commits,
        "retried": runner.retried,
        "report": runner.report,
        "log": str(runner.log),
        "last_success": started if result == OK else previous.get("last_success"),
        "consecutive_failures": 0 if result in (OK, DEFERRED)
        else previous.get("consecutive_failures", 0) + 1,
    }
    state["jobs"][name] = record
    # A job's report can raise an alert of its own: campaign.py refusing to
    # run third-party code outside its sandbox.
    alert = runner.report.get("alert") if isinstance(runner.report, dict) else None
    if result != DEFERRED:
        set_alert(state, f"job:{name}", bool(alert), str(alert or ""), now_iso())
    prune_logs(ctx.home / "logs")
    save_state(ctx.state_path, state)
    if interrupted is not None:
        raise interrupted
    return result, detail


# Status


def status(ctx: Context) -> dict:
    state = load_state(ctx.state_path)
    return {
        "jobs": {
            name: {"schedule": job.schedule, **state.get("jobs", {}).get(name, {})}
            for name, job in sorted(ctx.jobs.items())
        },
        "breaker": state.get("breaker", {"open": False}),
        "push": state.get("push", {}),
        "alerts": state.get("alerts", {}),
        "lock": {"path": str(ctx.lock_path), "busy": lock_busy(ctx.lock_path)},
        "free_gb": round(free_gb(ctx.repo), 1),
        "worktree": {
            "path": str(ctx.worktree),
            "exists": (ctx.worktree / ".git").exists(),
            "unpushed": unpushed(ctx.worktree),
        },
    }


def render_status(report: dict) -> str:
    lines = []
    for name, job in report["jobs"].items():
        lines.append(
            f"{name:12} {job.get('result', 'never run'):9} {job.get('last_end', ''):25} "
            f"{job.get('detail', '')}"
        )
        counts = (job.get("report") or {}).get("counts") if isinstance(
            job.get("report"), dict) else None
        if counts:
            lines.append(f"{'':12} " + ", ".join(f"{n} {v}" for v, n in sorted(counts.items())))
    wt = report["worktree"]
    lines.append(f"worktree {wt['path']} ({'present' if wt['exists'] else 'absent'}, "
                 f"{wt['unpushed']} unpushed commits)")
    lines.append(f"lock {report['lock']['path']} ({'busy' if report['lock']['busy'] else 'free'})")
    lines.append(f"disk {report['free_gb']} GB free")
    breaker = report["breaker"]
    lines.append("breaker " + (f"OPEN since {breaker.get('opened_at')}: {breaker.get('reason')}"
                               if breaker.get("open") else "closed"))
    for name, alert in sorted(report["alerts"].items()):
        lines.append(f"ALERT {name}: {alert.get('detail', '')} (since {alert.get('since')})")
    return "\n".join(lines)
