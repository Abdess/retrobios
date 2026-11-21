"""The job registry: automation/jobs.yml read into jobs, the results a job ends
with, and the environment each step gets.
"""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from core.childenv import is_secret, safe_env
from core.hostguard import LOCK_HELD_ENV
from core.paths import REPO_ROOT
from model.sources import source_yaml_file


JOBS_FILE = REPO_ROOT / "automation" / "jobs.yml"


OK = "ok"
FAILED = "failed"
DEFERRED = "deferred"
REFUSED = "refused"
BLOCKED = "blocked"


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


# Job registry


def check_subject(subject: str, body: str = "") -> list[str]:
    """What the repository's commit rules refuse in this message, checked
    when the job list loads instead of two hours into the job."""
    from devtools.commitrules import problems

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
    return parse_jobs(source_yaml_file(path) or {})


# Running a job


def token_env() -> dict[str, str]:
    """The environment of the phases that need GitHub: the push and gh."""
    from core.github import github_token

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
