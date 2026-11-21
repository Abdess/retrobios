"""The outcome and duration of each step, and the summary table the run ends on."""

from __future__ import annotations

import time

from orchestrate.labels import step_number

# Steps that report without failing the run.
NON_BLOCKING = frozenset({"check_buildbot"})


class StepResults(dict):
    """The outcome of each step, and how long it took.

    A step's time runs from the previous step's outcome to its own, so the
    in-process steps (consistency, the truth diff) are timed like the ones
    run() launches. The summary prints it: finding the slow step in a
    twenty-minute run meant reading the whole log.
    """

    def __init__(self, start: float) -> None:
        super().__init__()
        self.seconds: dict[str, float] = {}
        self._mark = start

    def __setitem__(self, step: str, outcome: object) -> None:
        now = time.monotonic()
        self.seconds[step] = self.seconds.get(step, 0.0) + now - self._mark
        self._mark = now
        super().__setitem__(step, outcome)


class _Skipped:
    """A step that did not run. Truthy, so it never fails the pipeline, and
    distinct, so the summary does not report it as work that was done."""

    def __bool__(self) -> bool:
        return True

    def __repr__(self) -> str:
        return "SKIPPED"


SKIPPED = _Skipped()


def print_summary(results: StepResults, total_start: float, all_ok: bool) -> None:
    """The table of every step's outcome and duration, then the verdict."""
    total_elapsed = time.monotonic() - total_start
    print(f"\n{'=' * 60}")
    warned = []
    for step, outcome in results.items():
        # The number finds the step's lines in the log, the key is the
        # name a caller reading the results knows it by.
        number = step_number(step)
        if outcome is SKIPPED:
            print(f"  {number:<4} {step:.<40} SKIPPED")
            continue
        label = "OK" if outcome else "FAILED"
        if not outcome and step in NON_BLOCKING:
            # Printed FAILED right above "Pipeline COMPLETE", it read as a
            # contradiction: the step reports, it does not stop the run.
            label = "WARN"
            warned.append(step)
        print(f"  {number:<4} {step:.<40} {label:<7}{results.seconds[step]:>8.1f}s")
    print(f"  {'':<4} {'total':.<40} {'':<7}{total_elapsed:>8.1f}s")
    print(f"{'=' * 60}")
    print(f"  Pipeline {'COMPLETE' if all_ok else 'FINISHED WITH ERRORS'}")
    if warned:
        print(f"  {', '.join(warned)} reported a difference, which does not fail the run")
    print(f"{'=' * 60}")
