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
a signal, or failing with an error sound hardware never raises (SystemError,
unknown opcode), is run again alone at the end, and reported as passing only
if that run passes. Every module's output is kept in its own log, and the summary
counts the tests, the failures and the skips, a skip being no proof.
"""

from __future__ import annotations

import argparse
import os
import time

from devtools.testrunner import (
    DEFAULT_JOBS,
    ROOT,
    WORK,
    failure_excerpt,
    load_durations,
    modules,
    rerun_crashed,
    run_all,
    save_durations,
    say,
    weight,
)


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
    say(f"{len(order)} modules, {args.jobs} at a time, logs in {logs.relative_to(ROOT)}")
    results = run_all(order, args.jobs, env, logs, say)
    rerun_crashed(results, env, logs, say)
    save_durations(durations, results)
    failed = [r for r in results if not r.passed]
    crashed = [r for r in results if r.crashed_then is not None]
    total = sum(r.tests for r in results)
    skipped = sum(r.skipped for r in results)
    print(f"\nRan {total} tests in {len(results)} modules in "
          f"{time.monotonic() - started:.0f} s, {skipped} skipped")
    for result in crashed:
        outcome = "passed" if result.crashed_then == 0 else "failed"
        why = (f"killed by signal {-result.code}" if result.code < 0
               else f"exit {result.code} on a host misread")
        print(f"  {result.module}: {why}, then {outcome} alone")
    for result in failed:
        print(f"FAILED {result.module}: {result.failures} failures, {result.errors} errors "
              f"(code {result.code if result.crashed_then is None else result.crashed_then}), "
              f"log {result.log.relative_to(ROOT) if result.log else '-'}")
        # A CI runner shows the output and keeps no file: what failed, and
        # why, is said here, the tracebacks unittest wrote, at most a page.
        if result.log is not None:
            for line in failure_excerpt(result.log):
                print(f"    {line}")
    print("OK" if not failed else f"FAILED ({len(failed)} modules)")
    return 1 if failed else 0


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
