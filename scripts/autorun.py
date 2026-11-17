#!/usr/bin/env python3
"""Run the repository's unattended jobs, one at a time, in their own worktree.

Jobs are declared in automation/jobs.yml: the commands, the gate they must
pass, the artifacts computed twice, the paths each commit may carry and the
schedule. A run takes one host-wide lock, waits for an idle host, refuses to
start on a full disk, and retries a step once on an idle host when it died
the way this host's CPU fails (exit 139, SystemError, "unknown opcode").

Jobs that commit run in .cache/autorun/worktree on the branch `autorun`,
never in the shared checkout and its index. The worktree is created on the
first run, fast-forwarded (or rebased) onto origin/main before each job, and
a job stops when it finds anything left uncommitted there. Commits name
their paths. Pushing is off unless --push is given: the batch is rebased on
origin/main, the gate runs again when origin/main moved, and the push never
forces. A red CI run on a pushed automation commit opens a circuit breaker
that stops every commit and push until a green run on main follows.

State, logs and the worktree live under .cache/autorun/ of the main
checkout. The lock is ~/.local/state/retrobios/auto.lock (RETROBIOS_AUTO_LOCK
overrides it), shared with any other heavy job on this host.

Usage:
    python scripts/autorun.py run nightly
    python scripts/autorun.py run nightly --dry-run
    python scripts/autorun.py run nightly --push
    python scripts/autorun.py status
    python scripts/autorun.py status --json
    python scripts/autorun.py install-timers
    python scripts/autorun.py install-timers --enable
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fnmatch
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
JOBS_FILE = REPO_ROOT / "automation" / "jobs.yml"
AUTORUN_DIR = Path(".cache") / "autorun"
DEFAULT_LOCK = Path.home() / ".local" / "state" / "retrobios" / "auto.lock"
LOCK_ENV = "RETROBIOS_AUTO_LOCK"
LOCK_HELD_ENV = "RETROBIOS_AUTO_LOCK_HELD"

BRANCH = "autorun"
REMOTE = "origin"
TARGET = "main"
REPO_SLUG = "Abdess/retrobios"

OK = "ok"
FAILED = "failed"
DEFERRED = "deferred"
REFUSED = "refused"
BLOCKED = "blocked"
EXIT_CODES = {OK: 0, DEFERRED: 75}

ALERT_FREE_GB = 100
LOG_DAYS = 30
SEGFAULT_CODES = (139, -11)
HOST_MISREAD_MARKERS = ("SystemError", "unknown opcode")
VOLATILE_KEYS = frozenset({"generated_at", "generated", "imported_at"})

CI_RED = frozenset({"failure", "timed_out", "startup_failure"})
CI_GREEN = frozenset({"success", "skipped", "neutral"})

JOB_KEYS = frozenset({
    "schedule", "steps", "gate", "twice", "commits", "worktree", "lock",
    "network", "min_free_gb", "max_load_wait", "timeout", "scratch", "report",
})


class AutorunError(RuntimeError):
    """A condition that ends a job with a named result."""

    def __init__(self, result: str, detail: str) -> None:
        super().__init__(detail)
        self.result = result
        self.detail = detail


class LockBusy(RuntimeError):
    """Another job holds the host-wide lock."""


@dataclass(frozen=True)
class Step:
    argv: tuple[str, ...]
    ok_codes: tuple[int, ...] = (0,)
    stdout: str = ""
    # Variables passed through beside the allowlist (romfetch's settings).
    env: tuple[str, ...] = ()
    # GITHUB_TOKEN for a first-party script that calls the GitHub API.
    github_token: bool = False


@dataclass(frozen=True)
class Twice:
    """An artifact the gate wrote, computed again into {out} and compared."""

    artifact: str
    argv: tuple[str, ...]
    glob: str = ""


@dataclass(frozen=True)
class CommitRule:
    subject: str
    paths: tuple[str, ...]
    body: str = ""


@dataclass(frozen=True)
class Job:
    name: str
    steps: tuple[Step, ...] = ()
    gate: tuple[Step, ...] = ()
    twice: tuple[Twice, ...] = ()
    commits: tuple[CommitRule, ...] = ()
    schedule: str = ""
    worktree: bool = True
    lock: bool = True
    network: bool = False
    min_free_gb: float = 30.0
    max_load_wait: int = 3600
    timeout: int = 21600
    scratch: tuple[str, ...] = ()
    report: str = ""


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
        return self.home / "worktree"

    @property
    def state_path(self) -> Path:
        return self.home / "state.json"


# Job registry


def check_subject(subject: str, body: str = "") -> list[str]:
    """What the repository's commit rules refuse in this message, checked
    when the job list loads instead of two hours into the job."""
    from commit_rules import problems

    return problems(f"{subject}\n\n{body}" if body else subject)


# The first-party scripts that call the GitHub API and may receive
# GITHUB_TOKEN: run as `python <script>` or `python -m <module>`, and tracked
# by git in this repository. Nothing else ever gets it, third-party code least.
TOKEN_SCRIPTS = ("scripts/check_freshness.py", "scripts/refresh_stale.py")
TOKEN_MODULE_PREFIX = "scripts.scraper."
NO_TOKEN_JOBS = frozenset({"campaign"})


def tracked(path: str, repo: Path = REPO_ROOT) -> bool:
    proc = subprocess.run(["git", "-C", str(repo), "ls-files", "--error-unmatch", "--", path],
                          capture_output=True, check=False)
    return proc.returncode == 0


def token_script(argv: Sequence[str], repo: Path = REPO_ROOT) -> str:
    """The tracked first-party script a step runs, or '' when it runs anything else."""
    if len(argv) < 2 or argv[0] != "python":
        return ""
    if argv[1] in TOKEN_SCRIPTS:
        path = argv[1]
    elif argv[1] == "-m" and len(argv) > 2 and argv[2].startswith(TOKEN_MODULE_PREFIX) \
            and re.fullmatch(r"[a-z0-9_.]+", argv[2]):
        path = argv[2].replace(".", "/") + ".py"
    else:
        return ""
    return path if tracked(path, repo) else ""


def _step(raw: object, where: str, job: str = "") -> Step:
    if isinstance(raw, list):
        return Step(argv=tuple(str(a) for a in raw))
    if isinstance(raw, dict) and isinstance(raw.get("run"), list):
        unknown = set(raw) - {"run", "ok_codes", "stdout", "env", "github_token"}
        if unknown:
            raise ValueError(f"{where}: unknown step key {sorted(unknown)}")
        names = tuple(str(n) for n in raw.get("env") or ())
        secret = [n for n in names if is_secret(n)]
        if secret:
            raise ValueError(f"{where}: a step never receives {', '.join(secret)}")
        argv = tuple(str(a) for a in raw["run"])
        token = raw.get("github_token", False)
        if token is not False:
            if token is not True:
                raise ValueError(f"{where}: github_token is true or absent")
            if job in NO_TOKEN_JOBS:
                raise ValueError(f"{where}: job {job} never receives GITHUB_TOKEN")
            if not token_script(argv):
                raise ValueError(f"{where}: github_token only goes to {', '.join(TOKEN_SCRIPTS)} "
                                 f"or python -m {TOKEN_MODULE_PREFIX}*, tracked in this repository")
        return Step(
            argv=argv,
            ok_codes=tuple(int(c) for c in raw.get("ok_codes", (0,))),
            stdout=str(raw.get("stdout") or ""),
            env=names,
            github_token=token is True,
        )
    raise ValueError(f"{where}: a step is a command list or a mapping with 'run'")


def parse_jobs(data: dict) -> dict[str, Job]:
    """Jobs from the registry mapping, refused whole on any unknown key."""
    defaults = data.get("defaults") or {}
    jobs: dict[str, Job] = {}
    for name, raw in (data.get("jobs") or {}).items():
        raw = {**defaults, **(raw or {})}
        unknown = set(raw) - JOB_KEYS
        if unknown:
            raise ValueError(f"job {name}: unknown key {sorted(unknown)}")
        twice = []
        for i, item in enumerate(raw.get("twice") or ()):
            argv = tuple(str(a) for a in item["run"])
            if "{out}" not in argv:
                raise ValueError(f"job {name}: twice[{i}] names no {{out}}")
            twice.append(Twice(str(item["artifact"]), argv, str(item.get("glob") or "")))
        commits = []
        for item in raw.get("commits") or ():
            rule = CommitRule(
                subject=str(item["subject"]),
                paths=tuple(str(p) for p in item["paths"]),
                body=str(item.get("body") or "").strip(),
            )
            problems = check_subject(rule.subject, rule.body)
            if problems:
                raise ValueError(f"job {name}: {rule.subject!r}: {', '.join(problems)}")
            commits.append(rule)
        if commits and raw.get("worktree") is False:
            raise ValueError(f"job {name}: a job that commits runs in the worktree")
        jobs[name] = Job(
            name=name,
            steps=tuple(_step(s, f"job {name}", name) for s in raw.get("steps") or ()),
            gate=tuple(_step(s, f"job {name} gate", name) for s in raw.get("gate") or ()),
            twice=tuple(twice),
            commits=tuple(commits),
            schedule=str(raw.get("schedule") or ""),
            worktree=bool(raw.get("worktree", True)),
            lock=bool(raw.get("lock", True)),
            network=bool(raw.get("network", False)),
            min_free_gb=float(raw.get("min_free_gb", 30)),
            max_load_wait=int(raw.get("max_load_wait", 3600)),
            timeout=int(raw.get("timeout", 21600)),
            scratch=tuple(str(p) for p in raw.get("scratch") or ()),
            report=str(raw.get("report") or ""),
        )
    return jobs


def load_jobs(path: Path = JOBS_FILE) -> dict[str, Job]:
    import yaml

    with path.open(encoding="utf-8") as handle:
        return parse_jobs(yaml.safe_load(handle) or {})


# Host guards


@contextlib.contextmanager
def global_lock(path: Path) -> Iterator[None]:
    """Hold the host-wide automation lock, or raise LockBusy at once."""
    import fcntl

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+", encoding="utf-8") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise LockBusy(f"{path} is held by another job") from exc
        handle.seek(0)
        handle.truncate()
        handle.write(f"{os.getpid()}\n")
        handle.flush()
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def lock_busy(path: Path) -> bool:
    try:
        with global_lock(path):
            return False
    except LockBusy:
        return True


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


def free_gb(path: Path) -> float:
    return shutil.disk_usage(path).free / 1024 ** 3


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
        return {k: strip_volatile(v) for k, v in value.items() if k not in VOLATILE_KEYS}
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


# Git


def git(cwd: Path, *args: str, check: bool = True,
        env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        ["git", "-C", str(cwd), *args], capture_output=True, text=True, check=False, env=env,
    )
    if check and proc.returncode != 0:
        raise AutorunError(
            FAILED, f"git {' '.join(args)}: {(proc.stderr or proc.stdout).strip()}"
        )
    return proc


def changed_files(worktree: Path) -> list[str]:
    """Every path git status reports, untracked included, ignored excluded."""
    out = git(worktree, "status", "--porcelain=v1", "-z", "--untracked-files=all").stdout
    entries = out.split("\0")
    paths: list[str] = []
    i = 0
    while i < len(entries):
        entry = entries[i]
        i += 1
        if len(entry) < 4:
            continue
        paths.append(entry[3:])
        if entry[0] in "RC":
            i += 1  # the rename source follows
    return sorted(set(paths))


def path_matches(pattern: str, path: str) -> bool:
    """A glob whose `*` stays inside one path segment."""
    parts, segments = pattern.split("/"), path.split("/")
    return len(parts) == len(segments) and all(
        fnmatch.fnmatchcase(s, p) for p, s in zip(parts, segments)
    )


def plan_commit(changed: Sequence[str], patterns: Sequence[str]) -> list[str]:
    return sorted(p for p in changed if any(path_matches(g, p) for g in patterns))


def commit_paths(worktree: Path, files: Sequence[str], rule: CommitRule) -> str:
    """Commit exactly these files, and return the new commit."""
    if not files:
        raise ValueError("no file to commit")
    git(worktree, "add", "--", *files)
    message = ["-m", rule.subject] + (["-m", rule.body] if rule.body else [])
    git(worktree, "commit", "--quiet", *message, "--", *files)
    return git(worktree, "rev-parse", "HEAD").stdout.strip()


def _hardlink_tree(src: Path, dst: Path) -> None:
    if src.is_dir():
        shutil.copytree(src, dst, copy_function=os.link, symlinks=True)
    else:
        dst.parent.mkdir(parents=True, exist_ok=True)
        os.link(src, dst)


def seed_worktree(repo: Path, worktree: Path) -> list[str]:
    """Hard-link what git does not carry: a tool deleting a file drops a link."""
    from largefiles import load_registered_paths

    seeded = []
    for rel in [".cache/large", "data", *load_registered_paths(repo / ".gitignore")]:
        src, dst = repo / rel, worktree / rel
        if src.exists() and not dst.exists():
            _hardlink_tree(src, dst)
            seeded.append(rel)
    return seeded


def ensure_worktree(repo: Path, worktree: Path) -> None:
    """Create the automation worktree on branch `autorun`, once."""
    if (worktree / ".git").exists():
        return
    git(repo, "fetch", "--quiet", REMOTE, TARGET)
    has_branch = git(
        repo, "rev-parse", "--verify", "--quiet", f"refs/heads/{BRANCH}", check=False
    ).returncode == 0
    worktree.parent.mkdir(parents=True, exist_ok=True)
    if has_branch:
        git(repo, "worktree", "add", str(worktree), BRANCH)
    else:
        git(repo, "worktree", "add", "-b", BRANCH, str(worktree), f"{REMOTE}/{TARGET}")


def sync_worktree(worktree: Path) -> str:
    """Bring the worktree onto origin/main, and return the base it now sits on."""
    leftovers = changed_files(worktree)
    if leftovers:
        raise AutorunError(
            BLOCKED, f"worktree holds {len(leftovers)} uncommitted paths: "
            + ", ".join(leftovers[:5])
        )
    git(worktree, "fetch", "--quiet", REMOTE, TARGET)
    upstream = f"{REMOTE}/{TARGET}"
    ahead = int(git(worktree, "rev-list", "--count", f"{upstream}..HEAD").stdout)
    if ahead == 0:
        git(worktree, "merge", "--ff-only", "--quiet", upstream)
    elif git(worktree, "merge-base", "--is-ancestor", upstream, "HEAD",
             check=False).returncode != 0:
        if git(worktree, "rebase", "--quiet", upstream, check=False).returncode != 0:
            git(worktree, "rebase", "--abort", check=False)
            raise AutorunError(BLOCKED, f"{ahead} automation commits conflict with {upstream}")
    return git(worktree, "rev-parse", upstream).stdout.strip()


def unpushed(worktree: Path) -> int:
    if not (worktree / ".git").exists():
        return 0
    proc = git(worktree, "rev-list", "--count", f"{REMOTE}/{TARGET}..HEAD", check=False)
    return int(proc.stdout.strip() or 0) if proc.returncode == 0 else 0


def push_batch(worktree: Path, gate_base: str, regate: Callable[[], bool]) -> str:
    """Rebase the night's commits on origin/main, gate again if it moved, push."""
    git(worktree, "fetch", "--quiet", REMOTE, TARGET)
    upstream = f"{REMOTE}/{TARGET}"
    if int(git(worktree, "rev-list", "--count", f"{upstream}..HEAD").stdout) == 0:
        return ""
    if git(worktree, "merge-base", "--is-ancestor", upstream, "HEAD",
           check=False).returncode != 0:
        if git(worktree, "rebase", "--quiet", upstream, check=False).returncode != 0:
            git(worktree, "rebase", "--abort", check=False)
            raise AutorunError(BLOCKED, f"rebase onto {upstream} conflicts, batch kept")
    if git(worktree, "rev-parse", upstream).stdout.strip() != gate_base and not regate():
        raise AutorunError(FAILED, f"gate failed on the batch rebased onto {upstream}")
    git(worktree, "push", "--quiet", REMOTE, f"HEAD:{TARGET}", env=token_env())
    return git(worktree, "rev-parse", "HEAD").stdout.strip()


# Circuit breaker


def gh_json(args: list[str]) -> object:
    """Parsed output of a gh command, or None when gh cannot answer."""
    try:
        proc = subprocess.run(
            ["gh", *args], capture_output=True, text=True, timeout=120, check=False,
            env=token_env(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        return json.loads(proc.stdout)
    except ValueError:
        return None


RUN_FIELDS = "workflowName,status,conclusion,headSha,createdAt"


def ci_verdict(runs: Sequence[dict]) -> str:
    """failure as soon as one run is red, success once all ended green."""
    if any(r.get("conclusion") in CI_RED for r in runs):
        return "failure"
    if not runs or any(r.get("status") != "completed" for r in runs):
        return "pending"
    if all(r.get("conclusion") in CI_GREEN for r in runs):
        return "success"
    return "pending"


def refresh_breaker(state: dict, gh: Callable[[list[str]], object], now: str) -> None:
    """Read CI for the last automation push, open or close the breaker."""
    push = state.setdefault("push", {})
    breaker = state.setdefault("breaker", {"open": False})
    sha = push.get("sha")
    if sha and push.get("ci") not in ("success", "failure"):
        runs = gh(["run", "list", "-R", REPO_SLUG, "--commit", sha, "--json", RUN_FIELDS])
        if isinstance(runs, list):
            verdict = ci_verdict(runs)
            push["ci"] = verdict
            if verdict == "failure":
                red = [r for r in runs if r.get("conclusion") in CI_RED]
                state["breaker"] = breaker = {
                    "open": True,
                    "sha": sha,
                    "opened_at": now,
                    "failed_run_at": max(str(r.get("createdAt") or "") for r in runs),
                    "reason": ", ".join(sorted({str(r.get("workflowName")) for r in red})),
                }
                state.setdefault("alerts", {})["ci"] = {
                    "since": now, "detail": f"red CI on {sha[:12]}: {breaker['reason']}",
                }
    if not breaker.get("open"):
        return
    runs = gh([
        "run", "list", "-R", REPO_SLUG, "--branch", TARGET, "--limit", "40",
        "--json", RUN_FIELDS,
    ])
    if not isinstance(runs, list):
        return
    after = [
        r for r in runs
        if str(r.get("createdAt") or "") > breaker.get("failed_run_at", "")
        and r.get("headSha") != breaker.get("sha")
    ]
    if not after:
        return
    newest = max(after, key=lambda r: str(r.get("createdAt") or ""))["headSha"]
    if ci_verdict([r for r in after if r.get("headSha") == newest]) == "success":
        state["breaker"] = {"open": False, "closed_at": now, "closed_by": newest}
        state.get("alerts", {}).pop("ci", None)


def may_push(state: dict) -> str:
    """Empty when a push may go out, else the reason it may not."""
    if state.get("breaker", {}).get("open"):
        return "circuit breaker open"
    push = state.get("push") or {}
    if push.get("sha") and push.get("ci") != "success":
        return f"CI of {push['sha'][:12]} has not ended green"
    return ""


# State and logs


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def load_state(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except ValueError as exc:
        raise AutorunError(FAILED, f"{path} is unreadable: {exc}") from exc


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    scratch = path.with_suffix(".tmp")
    scratch.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(scratch, path)


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


# Running a job


# What a job step inherits. A step can run third-party code (a buildbot
# core, a scraped page, a downloaded tool), so it gets the variables a
# program needs to run and nothing it could leak: no token, no password.
SAFE_ENV = frozenset({"PATH", "HOME", "LANG", "TZ", "TMPDIR"})
SECRET_NAMES = frozenset({"GITHUB_TOKEN", "GH_TOKEN", "ROMSTATION_USER", "ROMSTATION_PASS"})
SECRET_MARKERS = ("TOKEN", "SECRET", "PASS")


def is_secret(name: str) -> bool:
    upper = name.upper()
    return name in SECRET_NAMES or any(marker in upper for marker in SECRET_MARKERS)


def safe_env(names: Sequence[str] = (), add: dict[str, str] | None = None,
             source: dict[str, str] | None = None) -> dict[str, str]:
    """The allowlisted environment, plus the variables a step names
    explicitly. A secret is dropped even when named."""
    source = dict(os.environ) if source is None else source
    wanted = set(names)
    env = {key: value for key, value in source.items()
           if (key in SAFE_ENV or key.startswith("LC_") or key in wanted) and not is_secret(key)}
    env.update({key: value for key, value in (add or {}).items() if not is_secret(key)})
    return env


def token_env() -> dict[str, str]:
    """The environment of the phases that need GitHub: the push and gh."""
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    from common import github_token

    env = dict(os.environ)
    token = github_token()
    if token:
        env["GITHUB_TOKEN"] = token
    return env


def job_env(job: Job, step: Step | None = None) -> dict[str, str]:
    """A step's environment: the allowlist, the runner's own markers and the
    variables the step names. GITHUB_TOKEN only for a step that declares
    github_token, which the registry allows on first-party scripts alone."""
    add = {"RETROBIOS_AUTO": "1"}
    if job.lock:
        # A step that takes the host lock itself (campaign.py) runs under ours.
        add[LOCK_HELD_ENV] = "1"
    env = safe_env(step.env if step else (), add)
    if step is not None and step.github_token and job.name not in NO_TOKEN_JOBS:
        token = token_env().get("GITHUB_TOKEN")
        if token:
            env["GITHUB_TOKEN"] = token
    return env


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


def run_job(ctx: Context, name: str) -> tuple[str, str]:
    """Run one job and record it, returning (result, detail)."""
    job = ctx.jobs.get(name)
    if job is None:
        raise SystemExit(f"unknown job {name!r}: {', '.join(sorted(ctx.jobs))}")
    if ctx.dry_run:
        print("\n".join(describe(job, ctx)))
        return OK, "dry run"
    state = load_state(ctx.state_path)
    runner = Runner(ctx, job, state)
    started, clock = now_iso(), ctx.host.clock()
    lock = global_lock(ctx.lock_path) if job.lock else contextlib.nullcontext()
    try:
        with lock:
            runner.note(f"start {name}")
            try:
                result, detail = runner.execute()
            except AutorunError as exc:
                result, detail = exc.result, exc.detail
            except OSError as exc:
                result, detail = FAILED, f"{type(exc).__name__}: {exc}"
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


# Timers


def render_units(
    jobs: dict[str, Job], repo: Path, python: str, push: bool = False
) -> dict[str, str]:
    """systemd user units: one service template and a timer per scheduled job."""
    flags = " --push" if push else ""
    units = {
        "retrobios@.service": (
            "[Unit]\n"
            "Description=retrobios automation job %i\n"
            "\n"
            "[Service]\n"
            "Type=oneshot\n"
            f"WorkingDirectory={repo}\n"
            "Environment=RETROBIOS_AUTO=1\n"
            f"ExecStart={python} {repo / 'scripts' / 'autorun.py'} run %i{flags}\n"
            "TimeoutStartSec=6h\n"
            "Nice=10\n"
            "IOSchedulingClass=idle\n"
            "SuccessExitStatus=75\n"
        )
    }
    for name, job in sorted(jobs.items()):
        if not job.schedule:
            continue
        units[f"retrobios-{name}.timer"] = (
            "[Unit]\n"
            f"Description=retrobios automation: {name}\n"
            "\n"
            "[Timer]\n"
            f"OnCalendar={job.schedule}\n"
            "Persistent=true\n"
            f"Unit=retrobios@{name}.service\n"
            "\n"
            "[Install]\n"
            "WantedBy=timers.target\n"
        )
    return units


def install_timers(
    unit_dir: Path,
    units: dict[str, str],
    enable: bool,
    systemctl: Callable[[list[str]], int] | None = None,
) -> list[str]:
    """Write the units, and enable the timers only when asked."""
    unit_dir.mkdir(parents=True, exist_ok=True)
    for name, text in units.items():
        (unit_dir / name).write_text(text, encoding="utf-8")
    timers = sorted(n for n in units if n.endswith(".timer"))
    if enable:
        call = systemctl or (lambda args: subprocess.run(
            ["systemctl", "--user", *args], check=False).returncode)
        for args in (["daemon-reload"], ["enable", "--now", *timers]):
            if call(args) != 0:
                raise AutorunError(FAILED, f"systemctl --user {' '.join(args)} failed")
    return timers


# Command line


def main_checkout() -> Path:
    """The main checkout, also when this script runs from a linked worktree."""
    proc = git(REPO_ROOT, "rev-parse", "--path-format=absolute", "--git-common-dir",
               check=False)
    common = Path(proc.stdout.strip()) if proc.returncode == 0 else REPO_ROOT / ".git"
    return common.parent


def main() -> int:
    parser = argparse.ArgumentParser(
        allow_abbrev=False, description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)
    run_p = sub.add_parser("run", help="run one job from automation/jobs.yml")
    run_p.add_argument("job", help="a job name from automation/jobs.yml")
    run_p.add_argument("--dry-run", action="store_true",
                       help="print the commands and the files each commit would take")
    run_p.add_argument("--push", action="store_true",
                       help="push the committed batch to origin/main (off by default)")
    status_p = sub.add_parser("status", help="last result of every job, alerts, breaker")
    status_p.add_argument("--json", action="store_true", help="machine-readable status")
    timers_p = sub.add_parser("install-timers", help="write systemd user units")
    timers_p.add_argument("--enable", action="store_true",
                          help="also reload systemd and enable the timers")
    timers_p.add_argument("--unit-dir", type=Path,
                          default=Path.home() / ".config" / "systemd" / "user",
                          help="where the units go (default: %(default)s)")
    timers_p.add_argument("--with-push", action="store_true",
                          help="the units run jobs with --push")
    args = parser.parse_args()

    try:
        jobs = load_jobs()
    except (OSError, ValueError, KeyError) as exc:
        print(f"ERROR: automation/jobs.yml: {exc}", file=sys.stderr)
        return 2
    repo = main_checkout()
    ctx = Context(
        repo=repo,
        jobs=jobs,
        lock_path=Path(os.environ.get(LOCK_ENV) or DEFAULT_LOCK),
        gh=gh_json,
    )
    if args.command == "run":
        ctx.dry_run, ctx.push = args.dry_run, args.push
        result, detail = run_job(ctx, args.job)
        print(f"{args.job}: {result} ({detail})")
        return EXIT_CODES.get(result, 1)
    if args.command == "status":
        report = status(ctx)
        print(json.dumps(report, indent=2) if args.json else render_status(report))
        return 0
    units = render_units(jobs, repo, sys.executable, push=args.with_push)
    timers = install_timers(args.unit_dir, units, args.enable)
    print(f"wrote {len(units)} units to {args.unit_dir}")
    if not args.enable:
        print("enable with: python scripts/autorun.py install-timers --enable")
        print("  (systemctl --user daemon-reload && systemctl --user enable --now "
              + " ".join(timers) + ")")
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    from common import run_cli

    run_cli(main)
