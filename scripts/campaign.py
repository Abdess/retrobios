#!/usr/bin/env python3
"""Run the real-condition campaign end to end: cores, content, checks, rules.

A maintainer starts each pass. For each emulator profile in scope, the
campaign takes the core (the libretro x86_64 Linux nightly, else a build of
the profile's pinned commit), the test content of each of its systems
(tests/campaign/content.yml, fetched through romfetch when it is not on
disk), and runs core_probe.py. The boot oracle of core_probe judges every
run: boots, bios_error, crash, hang or unknown, against the reference frames
and error patterns of tests/campaign/oracle.yml.

  files      every declared file the collection holds, staged: the full set,
             and which files the core opens
  none       no BIOS at all
  negative   per declared file of the content's region: the file alone, then
             zeros of its size, its first half and other regions' dumps
             staged under its name
  path       a declared file staged where the core looked for it
  alias      a declared file staged under a name the core looked for
  variants   each .variants/ copy of a file the core opened
  bench      with --bench only: the content timed, warm-up excluded

Every run is a record in measurements/<emulator>.jsonl. The fixed rule table
(probes/rules.py) reads the verdicts, never a comparison of frames. A
verdict the table settles is written into the profile with the record ids
as `evidence:`. Any other goes to measurements/findings.jsonl, where the
site lists it as open. Each pass adds one line to
measurements/campaign-runs.jsonl.

`review` closes an open finding once a maintainer has read the core's code:
`applied` writes the fields it names through the same profile editor, with
the finding's record ids as `evidence:`, and `rejected` keeps the profile.
The reason, with its file:line, goes on the finding's line, and a rejected
finding stays closed while the runs keep showing the same thing.

`references` runs the full set once per core and content with its frames
saved as PNG, and lists the screens that stay on for several samples: the
candidates a reviewer looks at before writing them into oracle.yml.

State is .cache/campaign/state.json of the main checkout: per check done,
failed or pending with the reason, and the core sha256, profile digest,
oracle sha256 and record version it ran against. A pass skips what is done
unless one of them changed. The campaign holds the host-wide automation
lock, waits for an idle host, stops cleanly on a busy host or a full disk,
and the next pass a maintainer starts resumes there.

Usage:
    python scripts/campaign.py run [--only CORE,...] [--system ID] [--budget 6h] [--bench]
    python scripts/campaign.py run --dry-run
    python scripts/campaign.py run --commit [--commit-every N]
    python scripts/campaign.py references --only CORE,... [--system ID]
    python scripts/campaign.py status [--json]
    python scripts/campaign.py findings [--all] [--json]
    python scripts/campaign.py review KEY --status applied|rejected --reason TEXT [--set FIELD=YAML]
    python scripts/campaign.py gate

A maintainer starts each pass for a question that names its profiles: no
job runs it on a schedule.
"""

from __future__ import annotations

import argparse
import json
import re
import signal
import sys
from collections.abc import Sequence
from pathlib import Path

# First: the floor, before anything else fails on an older interpreter.
if sys.version_info < (3, 9):
    sys.exit(
        f"{Path(sys.argv[0]).name} needs Python 3.9 or newer, "
        f"this is {sys.version.split()[0]}"
    )

sys.path.insert(0, str(Path(__file__).resolve().parent))

import yaml

from unattended import worktree
from core import hostguard
from probes.profileedit import ProfileEditError
from core.paths import REPO_ROOT
from probes.campaign import Campaign
from probes.content import ROMFETCH_ENV
from probes.gate import changed_profiles, gate
from probes.host import CONTENT_FILE, Paths, Settings, host_lock
from probes.reports import REVIEWED, open_findings, render_status, review_finding, status_report


EXIT_REFUSED = 3


def parse_budget(text: str) -> float:
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([smh]?)\s*", text or "")
    if not match:
        raise argparse.ArgumentTypeError(f"--budget {text!r}: a number with s, m or h")
    return float(match[1]) * {"": 1, "s": 1, "m": 60, "h": 3600}[match[2]]


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------

def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.split("\n\n")[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    scope = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    scope.add_argument("--only", default="", help="emulator profiles or core names, comma-separated")
    scope.add_argument("--system", help="one system id")
    scope.add_argument("--romfetch", default="",
                       help=f"romfetch command (default: ${ROMFETCH_ENV}, else romfetch on PATH)")
    scope.add_argument("--offline", action="store_true", help="no buildbot, no romfetch, no build")
    scope.add_argument("--content-file", default=str(CONTENT_FILE),
                       help="the test content list (default: tests/campaign/content.yml)")
    scope.add_argument("--allow-unsandboxed", action="store_true",
                       help="run cores and builds without bubblewrap when it is missing (refused by default)")
    run_p = sub.add_parser("run", parents=[scope], help="one pass: cores, content, checks, rules")
    run_p.add_argument("--budget", type=parse_budget, default=6 * 3600.0,
                       help="stop starting checks after this long (6h, 90m, 3600s)")
    run_p.add_argument("--max-load-wait", type=float, default=3600,
                       help="seconds to wait for an idle host before pausing the pass")
    run_p.add_argument("--min-free-gb", type=float, default=30, help="pause below this free space")
    run_p.add_argument("--cache-cap-gb", type=float, default=20,
                       help="content the campaign fetched is evicted past this size, oldest use first")
    run_p.add_argument("--bench", action="store_true",
                       help="also time each content that boots (benchmarks only choose between variants)")
    run_p.add_argument("--dry-run", action="store_true", help="print the plan, run nothing")
    run_p.add_argument("--commit", action="store_true",
                       help="commit records, findings and each changed profile behind the gate")
    run_p.add_argument("--commit-every", type=int, default=0, metavar="N",
                       help="with --commit, also commit after every N emulators")
    refs_p = sub.add_parser("references", parents=[scope],
                            help="run the full set with PNG frames and list reference candidates")
    refs_p.add_argument("--png-dir", default=str(REPO_ROOT / "tmp" / "campaign" / "references"),
                        help="where the frames are written, one folder per core and content")
    status_p = sub.add_parser("status", help="done, failed and pending checks, and why")
    status_p.add_argument("--json", action="store_true", help="the report as JSON")
    findings_p = sub.add_parser("findings", help="profile claims the runs contradict, open for review")
    findings_p.add_argument("--all", action="store_true", help="applied and resolved too")
    findings_p.add_argument("--json", action="store_true", help="the findings as JSON")
    review_p = sub.add_parser("review", help="close an open finding after reading the code")
    review_p.add_argument("key", help="emulator/system/file/field, as `findings` prints it")
    review_p.add_argument("--status", required=True, choices=REVIEWED,
                          help="applied: the profile now says what the code does, rejected: it already did")
    review_p.add_argument("--reason", required=True,
                          help="what the code does, with its file:line at the profile's pin")
    review_p.add_argument("--set", action="append", default=[], metavar="FIELD=YAML",
                          help="with --status applied, a field to write into the entry")
    review_p.add_argument("--index", type=int, help="the entry's position when several share its name")
    sub.add_parser("gate", help="tests, schemas, verify and pack of the changed profiles")
    return parser


def _review(parser: argparse.ArgumentParser, args: argparse.Namespace, paths: Paths) -> int:
    updates: dict[str, object] = {}
    for item in args.set:
        name, sep, value = item.partition("=")
        if not sep or not name:
            parser.error(f"--set {item!r}: FIELD=YAML")
        updates[name] = yaml.safe_load(value)
    try:
        line = review_finding(paths.root, args.key, args.status, args.reason, updates,
                              args.index)
    except (ValueError, ProfileEditError) as exc:
        print(f"campaign: {exc}", file=sys.stderr)
        return 1
    print(f"{line['status']} {line['key']} [{line['id']}]")
    return 0


def _findings(args: argparse.Namespace, paths: Paths) -> int:
    lines = open_findings(paths.root, args.all)
    if args.json:
        print(json.dumps(lines, indent=2))
    for line in [] if args.json else lines:
        print(f"{line['status']:8} {line['key']}: profile says {json.dumps(line['profile_says'])}, "
              f"run shows {json.dumps(line['run_shows'])}. {line['statement']} "
              f"[{', '.join(line['evidence'])}]")
    return 0


def _settings(args: argparse.Namespace) -> Settings:
    if args.command == "run":
        return Settings(budget=args.budget, max_load_wait=args.max_load_wait,
                        min_free_gb=args.min_free_gb, cache_cap_gb=args.cache_cap_gb,
                        romfetch=args.romfetch, network=not args.offline,
                        allow_unsandboxed=args.allow_unsandboxed, bench=args.bench)
    if args.command == "references":
        return Settings(romfetch=args.romfetch, network=not args.offline,
                        allow_unsandboxed=args.allow_unsandboxed)
    return Settings()


def _references(campaign: Campaign, args: argparse.Namespace, only: set[str]) -> int:
    try:
        with host_lock(campaign.lock_path):
            listed = campaign.references(only, args.system, Path(args.png_dir))
    except hostguard.LockBusy as exc:
        print(f"campaign: deferred, {exc}", file=sys.stderr)
        return 75
    print(json.dumps(listed, indent=2))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)

    paths = Paths.default()
    if args.command == "gate":
        return gate(paths.root, changed_profiles(paths.root))
    if args.command == "review":
        return _review(parser, args, paths)
    if args.command == "findings":
        return _findings(args, paths)
    settings = _settings(args)
    if args.command in ("run", "references"):
        paths.content_file = Path(args.content_file)
    campaign = Campaign(paths, settings)
    if args.command == "status":
        report = status_report(campaign)
        print(json.dumps(report, indent=2) if args.json else render_status(report))
        return 0
    only = {item.strip() for item in args.only.split(",") if item.strip()}
    if args.command == "references":
        return _references(campaign, args, only)
    if args.dry_run:
        campaign.run(only, args.system, dry_run=True)
        return 0
    return _run_pass(campaign, args, only, paths)


def _run_pass(campaign: Campaign, args: argparse.Namespace, only: set[str], paths: Paths) -> int:
    campaign.dirty_at_start = set(worktree.changed_files(paths.root)) if args.commit else set()

    def stop(signum: int, frame: object) -> None:
        # SIGTERM ends the pass like Ctrl-C: state saved, pass line written.
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    try:
        with host_lock(campaign.lock_path):
            current = campaign.run(only, args.system, commit_every=args.commit_every,
                                   commit=args.commit)
    except hostguard.LockBusy as exc:
        print(f"campaign: deferred, {exc}", file=sys.stderr)
        return 75
    counts, _, _ = campaign.counts()
    report = {"result": current.result, "detail": current.detail, "counts": counts,
              "records": len(current.records), "findings": current.findings}
    if current.result == "refused":
        # autorun raises an alert from this key of a job's report.
        report["alert"] = current.detail
    print(json.dumps(report))
    if current.result == "refused":
        return EXIT_REFUSED
    return 75 if current.result == "paused" else 0


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
