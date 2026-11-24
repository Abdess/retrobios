"""The checks validate.yml runs on a pull request, in its order."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field

from core.paths import REPO_ROOT


@dataclass(frozen=True)
class Step:
    command: str
    why: str
    needs: str = ""
    provider: str = ""
    env: dict[str, str] = field(default_factory=dict)
    # validate.yml marks the step continue-on-error: its failure is shown
    # and does not fail the run.
    may_fail: bool = False


# The full-screen tests, run again on the installer's Python floor: every
# module named test_tui_*.
TUI_MODULES = tuple(
    f"tests.{path.stem}" for path in sorted((REPO_ROOT / "tests").glob("test_tui_*.py"))
)


# The order of validate.yml: data fetched, site generated and built, then the
# suite, its 3.8 run and the built-site check.
STEPS: tuple[Step, ...] = (
    Step("python scripts/validate_pr.py --changed", "the BIOS files the branch adds"),
    Step("python scripts/validate_schemas.py --source-only", "profiles and platform files"),
    Step("mypy", "no type error in install.py, installer/ and scripts/", needs="mypy",
         provider='pip install -e ".[dev]"'),
    Step("ruff check .", "the lint rules of pyproject.toml", needs="ruff",
         provider='pip install -e ".[dev]"'),
    Step("python scripts/build_installer.py --check", "install.py is the one installer/ builds"),
    Step("python scripts/generate_readme.py --db database.json --platforms-dir platforms --check",
         "README.md and CONTRIBUTING.md are the generated ones", env={"RETROBIOS_OFFLINE": "1"}),
    Step("python scripts/profile_sync.py --added --strict", "each profile the branch adds"),
    Step("vermin --no-tips -t=3.8- --violations install.py installer", "the installer stays on Python 3.8",
         needs="vermin", provider="the pip line of CONTRIBUTING.md"),
    Step("shellcheck --version", "the launcher test runs shellcheck", needs="shellcheck",
         provider="the shellcheck package"),
    Step("python scripts/export_native.py --all --refresh-cache",
         "files the exporter tests compare with"),
    Step("python scripts/refresh_data_dirs.py", "data directories the pack-building tests read"),
    Step("python scripts/generate_site.py", "the pages the site tests read"),
    Step("npm ci --prefix website", "the site's packages, Node 24",
         needs="npm", provider="Node 24"),
    # Node's compile cache lands in /tmp, a 4 GB tmpfs here: one build
    # filled it and every later command failed with ENOSPC.
    Step("npm run build --prefix website", "the built site",
         needs="npm", provider="Node 24", env={"NODE_DISABLE_COMPILE_CACHE": "1"}),
    Step("python scripts/run_tests.py --jobs 4", "the suite, one process per module",
         env={"RETROBIOS_OFFLINE": "1"}),
    Step("python3.8 -m unittest " + " ".join(TUI_MODULES),
         "the full screen on the installer's floor",
         needs="python3.8", provider="a Python 3.8 with pyte",
         env={"RETROBIOS_OFFLINE": "1"}),
    Step("python scripts/validate_site.py --site-dir website/dist", "links and page budgets"),
)


def argv(command: str) -> list[str]:
    """The command, with `python` run by the interpreter running this script."""
    words = command.split()
    return [sys.executable, *words[1:]] if words[0] == "python" else words


def shown(step: Step) -> str:
    return step.command


def execute(step: Step) -> int:
    env = {**os.environ, **step.env}
    return subprocess.run(argv(step.command), cwd=REPO_ROOT, env=env, check=False).returncode


def run(steps: tuple[Step, ...] = STEPS) -> int:
    failed: list[str] = []
    allowed: list[str] = []
    not_run: list[str] = []
    for step in steps:
        print(f"\n== {shown(step)}", flush=True)
        if step.needs and shutil.which(step.needs) is None:
            print(f"not run: {step.needs} is not installed ({step.provider})")
            not_run.append(f"{shown(step)} ({step.needs}: {step.provider})")
            continue
        code = execute(step)
        if code:
            (allowed if step.may_fail else failed).append(f"{shown(step)} (exit {code})")
    print()
    for line in failed:
        print(f"FAILED   {line}")
    for line in allowed:
        print(f"FAILED   {line}, continue-on-error in CI as well")
    for line in not_run:
        print(f"NOT RUN  {line}")
    print(f"{len(steps) - len(failed) - len(allowed) - len(not_run)}/{len(steps)} checks passed")
    return 1 if failed else 0
