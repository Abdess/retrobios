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
import json
import os
import sys
from pathlib import Path

from core.hostguard import (
    DEFAULT_LOCK,
    LOCK_ENV,
)
from unattended.breaker import gh_json
from unattended.jobs import DEFERRED, OK, load_jobs
from unattended.runner import Context, UnknownJob, describe, find_job, render_status, run_job, status
from unattended.timers import install_timers, render_units
from unattended.worktree import main_checkout


EXIT_CODES = {OK: 0, DEFERRED: 75}


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
        try:
            if args.dry_run:
                print("\n".join(describe(find_job(ctx, args.job), ctx)))
            result, detail = run_job(ctx, args.job)
        except UnknownJob as exc:
            print(exc, file=sys.stderr)
            return 1
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
    from core.cli import run_cli

    run_cli(main)
