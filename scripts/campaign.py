#!/usr/bin/env python3
"""Run the real-condition campaign end to end: cores, content, checks, rules.

A maintainer starts each pass. For each emulator profile in scope, the
campaign takes the core (the libretro x86_64 Linux nightly, else a build of
the profile's pinned commit), the test content of each of its systems
(campaign/content.yml, fetched through romfetch when it is not on
disk), and runs core_probe.py. The boot oracle of core_probe judges every
run: boots, bios_error, crash, hang or unknown, against the reference frames
and error patterns of campaign/oracle.yml.

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

from core.paths import REPO_ROOT
from probes.campaignmodes import run_mode
from probes.content import ROMFETCH_ENV
from probes.host import CONTENT_FILE, parse_budget
from probes.reports import REVIEWED


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
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
                       help="the test content list (default: campaign/content.yml)")
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


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    return run_mode(parser, parser.parse_args(argv))


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
