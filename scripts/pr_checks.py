#!/usr/bin/env python3
"""Run the checks validate.yml runs on a pull request, in its order.

Usage:
    python scripts/pr_checks.py
    python scripts/pr_checks.py --list

Each step runs even when an earlier one failed, as CI runs them, and the
summary names every step that failed or could not run. A step whose tool is
absent (npm, python3.8, vermin) is reported as not run, with what provides it.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Step:
    command: str
    why: str
    needs: str = ""
    provider: str = ""
    env: dict[str, str] = field(default_factory=dict)
    # A second command that reads the first one's output, as a shell pipe
    # would: mypy's report goes through mypy-baseline filter.
    then: str = ""
    # validate.yml marks the step continue-on-error: its failure is shown
    # and does not fail the run.
    may_fail: bool = False


# The order of validate.yml: data fetched, site generated and built, then the
# suite, its 3.8 run and the built-site check.
STEPS: tuple[Step, ...] = (
    Step("python scripts/validate_pr.py --changed", "the BIOS files the branch adds"),
    Step("python scripts/validate_schemas.py --source-only", "profiles and platform files"),
    Step("mypy", "no type error beyond mypy-baseline.txt", needs="mypy",
         provider="the pip line of CONTRIBUTING.md", then="mypy-baseline filter --no-colors"),
    Step("python scripts/profile_sync.py --added --strict", "each profile the branch adds"),
    Step("vermin --no-tips -t=3.8- --violations install.py", "install.py stays on Python 3.8",
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
    Step("python -m unittest discover -s tests -t .", "the suite",
         env={"RETROBIOS_OFFLINE": "1"}),
    Step("python3.8 -m unittest tests.test_install_tui", "the full screen on the installer's floor",
         needs="python3.8", provider="a Python 3.8 with pyte",
         env={"RETROBIOS_OFFLINE": "1"}),
    Step("python scripts/validate_site.py --site-dir website/dist", "links and page budgets"),
)


def argv(command: str) -> list[str]:
    """The command, with `python` run by the interpreter running this script."""
    words = command.split()
    return [sys.executable, *words[1:]] if words[0] == "python" else words


def shown(step: Step) -> str:
    return f"{step.command} | {step.then}" if step.then else step.command


def execute(step: Step) -> int:
    env = {**os.environ, **step.env}
    if not step.then:
        return subprocess.run(argv(step.command), cwd=ROOT, env=env).returncode
    first = subprocess.run(argv(step.command), cwd=ROOT, env=env, stdout=subprocess.PIPE)
    return subprocess.run(argv(step.then), cwd=ROOT, env=env, input=first.stdout).returncode


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


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.splitlines()[0])
    parser.add_argument("--list", action="store_true", help="print the steps and exit")
    args = parser.parse_args()
    if args.list:
        for step in STEPS:
            print(shown(step))
        return 0
    return run()


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
