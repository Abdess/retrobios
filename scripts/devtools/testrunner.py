"""The test suite run one module per process: the order, each run, the reruns and the timings kept."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from core.hostguard import host_misread
from core.paths import REPO_ROOT as ROOT

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


def run_all(order: Iterable[str], jobs: int, env: dict[str, str], logs: Path,
            say: Callable[[str], None]) -> list[Result]:
    """Every module, `jobs` at a time, each failure said as it ends."""
    results: list[Result] = []
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        running = [pool.submit(run_module, name, env, logs) for name in order]
        for done in as_completed(running):
            result = done.result()
            results.append(result)
            if result.code != 0:
                why = f"signal {-result.code}" if result.code < 0 else "failed"
                say(f"  {why}: {result.module} ({result.seconds:.0f} s)")
    return results


def rerun_crashed(results: Iterable[Result], env: dict[str, str], logs: Path,
                  say: Callable[[str], None]) -> None:
    """A module the host misread is the host's doing until it fails alone."""
    for result in results:
        if result.code != 0 and host_misread(result.code, _log_text(result)):
            say(f"  again, alone: {result.module}")
            again = run_module(result.module, env, logs)
            result.crashed_then = again.code
            result.tests, result.failures, result.errors, result.skipped = (
                again.tests, again.failures, again.errors, again.skipped)


def _log_text(result: Result) -> str:
    return result.log.read_text(encoding="utf-8", errors="replace") if result.log else ""


def save_durations(durations: dict[str, float], results: Iterable[Result]) -> None:
    """The timings of this run over the previous ones, a crashed run left out."""
    timed = {**durations, **{r.module: round(r.seconds, 1) for r in results
                             if r.crashed_then is None}}
    DURATIONS.write_text(json.dumps(timed, indent=1, sort_keys=True), encoding="utf-8")


def failure_excerpt(log: Path) -> list[str]:
    """The tracebacks unittest wrote in a module's log, at most a page."""
    text = log.read_text(encoding="utf-8", errors="replace")
    start = text.find("\n" + "=" * 70)
    shown = (text[start:] if start >= 0 else text).strip().splitlines()
    lines = shown[:FAILURE_LINES]
    if len(shown) > FAILURE_LINES:
        lines.append(f"... {len(shown) - FAILURE_LINES} more lines in the log")
    return lines


def say(line: str) -> None:
    print(line, flush=True)
