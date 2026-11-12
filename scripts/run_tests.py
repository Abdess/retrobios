#!/usr/bin/env python3
"""Run the test suite as several processes, one test module each.

Usage:
    python scripts/run_tests.py                 # every module, a few at a time
    python scripts/run_tests.py --jobs 1        # one at a time, as discover runs
    python scripts/run_tests.py tests.test_install tests.test_e2e

unittest's discovery runs 8,500 tests in one process: about 40 minutes
here and 85 on the CI runner, and a module that left a variable or a flag
set changed the modules after it. Here each module gets a fresh process
and its own scratch folder (RETROBIOS_TEST_SCRATCH, read by tests/__init__),
the longest first so the last ones to start are short. Durations are kept in
tmp/test-durations.json, from the previous run, and a module never timed is
weighed by its size.

The host computes wrong and Python segfaults under load: a module killed by
a signal is run again alone at the end, and reported as passing only if that
run passes. Every module's output is kept in its own log, and the summary
counts the tests, the failures and the skips, a skip being no proof.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TESTS = ROOT / "tests"
WORK = ROOT / "tmp" / "test-runs"
DURATIONS = ROOT / "tmp" / "test-durations.json"
# The pty and site-build tests time themselves out under load: more than a
# third of the cores at once made them fail for no other reason.
DEFAULT_JOBS = max(1, min(6, (os.cpu_count() or 2) // 3))

# Lines of a failed module's tracebacks printed in the summary.
FAILURE_LINES = 200
_RAN = re.compile(r"^Ran (\d+) tests? in ([\d.]+)s$", re.M)
_COUNTS = re.compile(r"(failures|errors|skipped|expected failures|unexpected successes)=(\d+)")


@dataclass
class Result:
    module: str
    code: int
    seconds: float
    tests: int = 0
    failures: int = 0
    errors: int = 0
    skipped: int = 0
    log: Path | None = None
    crashed_then: int | None = None

    @property
    def passed(self) -> bool:
        return self.code == 0 if self.crashed_then is None else self.crashed_then == 0


def modules() -> list[str]:
    return sorted(f"tests.{path.stem}" for path in TESTS.glob("test_*.py"))


def load_durations() -> dict[str, float]:
    try:
        data = json.loads(DURATIONS.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        print(f"note: {DURATIONS} not read ({exc}), modules weighed by size", file=sys.stderr)
        return {}
    return {str(name): float(value) for name, value in data.items()
            if isinstance(value, (int, float))}


def weight(module: str, durations: dict[str, float]) -> float:
    """Seconds the module took last time, else its size as a stand-in."""
    if module in durations:
        return durations[module]
    path = TESTS / f"{module.split('.', 1)[1]}.py"
    return path.stat().st_size / 2000 if path.exists() else 0.0


def parse(result: Result, text: str) -> None:
    ran = _RAN.findall(text)
    if ran:
        result.tests = int(ran[-1][0])
    tail = text[text.rfind("\nRan "):] if "\nRan " in text else text
    for name, count in _COUNTS.findall(tail):
        if name == "failures":
            result.failures = int(count)
        elif name == "errors":
            result.errors = int(count)
        elif name == "skipped":
            result.skipped = int(count)


def run_module(module: str, env: dict[str, str], logs: Path) -> Result:
    scratch = WORK / "scratch" / module
    scratch.mkdir(parents=True, exist_ok=True)
    log = logs / f"{module}.log"
    started = time.monotonic()
    with log.open("w", encoding="utf-8") as out:
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", module], cwd=ROOT, stdout=out,
            stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            env={**env, "RETROBIOS_TEST_SCRATCH": str(scratch)}, check=False,
        )
    result = Result(module, proc.returncode, time.monotonic() - started, log=log)
    parse(result, log.read_text(encoding="utf-8", errors="replace"))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False,
                                     description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("modules", nargs="*", help="modules to run (tests.test_x), all by default")
    parser.add_argument("--jobs", "-j", type=int, default=DEFAULT_JOBS,
                        help=f"modules at once (default {DEFAULT_JOBS})")
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs takes a number from 1")
    known = modules()
    chosen = args.modules or known
    unknown = [name for name in chosen if name not in known]
    if unknown:
        parser.error(f"no such test module: {', '.join(unknown)}")
    durations = load_durations()
    order = sorted(chosen, key=lambda name: -weight(name, durations))
    logs = WORK / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "RETROBIOS_OFFLINE": os.environ.get("RETROBIOS_OFFLINE", "1")}
    started = time.monotonic()
    print(f"{len(order)} modules, {args.jobs} at a time, logs in {logs.relative_to(ROOT)}",
          flush=True)
    results: list[Result] = []
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        running = [pool.submit(run_module, name, env, logs) for name in order]
        for done in as_completed(running):
            result = done.result()
            results.append(result)
            if result.code != 0:
                why = f"signal {-result.code}" if result.code < 0 else "failed"
                print(f"  {why}: {result.module} ({result.seconds:.0f} s)", flush=True)
    # A module a signal killed is the host's doing until it fails alone.
    for result in results:
        if result.code < 0:
            print(f"  again, alone: {result.module}", flush=True)
            again = run_module(result.module, env, logs)
            result.crashed_then = again.code
            result.tests, result.failures, result.errors, result.skipped = (
                again.tests, again.failures, again.errors, again.skipped)
    timed = {**durations, **{r.module: round(r.seconds, 1) for r in results if r.code >= 0}}
    DURATIONS.write_text(json.dumps(timed, indent=1, sort_keys=True), encoding="utf-8")
    failed = [r for r in results if not r.passed]
    crashed = [r for r in results if r.crashed_then is not None]
    total = sum(r.tests for r in results)
    skipped = sum(r.skipped for r in results)
    print(f"\nRan {total} tests in {len(results)} modules in "
          f"{time.monotonic() - started:.0f} s, {skipped} skipped")
    for result in crashed:
        outcome = "passed" if result.crashed_then == 0 else "failed"
        print(f"  {result.module}: killed by signal {-result.code}, then {outcome} alone")
    for result in failed:
        print(f"FAILED {result.module}: {result.failures} failures, {result.errors} errors "
              f"(code {result.code if result.crashed_then is None else result.crashed_then}), "
              f"log {result.log.relative_to(ROOT) if result.log else '-'}")
        # A CI runner shows the output and keeps no file: what failed, and
        # why, is said here, the tracebacks unittest wrote, at most a page.
        if result.log is not None:
            text = result.log.read_text(encoding="utf-8", errors="replace")
            start = text.find("\n" + "=" * 70)
            shown = (text[start:] if start >= 0 else text).strip().splitlines()
            for line in shown[:FAILURE_LINES]:
                print(f"    {line}")
            if len(shown) > FAILURE_LINES:
                print(f"    ... {len(shown) - FAILURE_LINES} more lines in the log")
    print("OK" if not failed else f"FAILED ({len(failed)} modules)")
    return 1 if failed else 0


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
