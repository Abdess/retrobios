"""The flag combinations a profile pass refuses before any request."""

from __future__ import annotations

import argparse
import sys


def refuse_flag_combinations(args: argparse.Namespace) -> None:
    """Exit on a flag the chosen mode would not apply, before any request."""
    if args.verify_version or args.set_version:
        ignored = [
            flag for flag, on in (
                ("--verify-version", args.verify_version and args.set_version),
                ("--markdown", args.markdown),
                ("--fetch-plan", args.fetch_plan),
                ("--triage", args.triage),
                ("--strict", args.strict),
                ("--check-version", args.check_version),
                ("--detect-new-files", args.detect_new_files),
                ("--watch-hashes", args.watch_hashes),
                ("--full-diff", args.full_diff),
                ("--tree-diff", args.tree_diff),
                ("--backfill-commits", args.backfill_commits),
                ("--rebase-refs", args.rebase_refs),
                ("--attribute-refs", args.attribute_refs),
                ("--bump-commit", args.bump_commit),
                ("--realign-prose", args.realign_prose),
                ("--accept-changed", args.accept_changed),
                ("--dry-run", args.dry_run and not args.set_version),
            ) if on
        ]
        if ignored:
            mode = "--set-version" if args.set_version else "--verify-version"
            print(f"{mode} does not apply {', '.join(ignored)}", file=sys.stderr)
            raise SystemExit(1)
    if args.fresh and args.offline:
        print("--fresh asks the forges again, which --offline forbids.", file=sys.stderr)
        raise SystemExit(1)
    if args.accept_changed and not args.emulator:
        print(
            "--accept-changed applies to one profile at a time: its diff has "
            "to be read before its CHANGED refs can be recaled.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if args.attribute_refs and (
        args.rebase_refs or args.bump_commit or args.backfill_commits
        or args.realign_prose
    ):
        print(
            "--attribute-refs runs alone: it rewrites the refs the report was "
            "built from.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if args.realign_prose and (
        args.rebase_refs or args.bump_commit or args.backfill_commits
    ):
        print(
            "--realign-prose runs alone: the report has to be rebuilt on the "
            "realigned text before any other write.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if args.realign_prose:
        ignored = [
            flag for flag, on in (
                ("--json", args.as_json),
                ("--markdown", args.markdown),
                ("--fetch-plan", args.fetch_plan),
                ("--triage", args.triage),
                ("--changed-only", args.changed_only),
                ("--strict", args.strict),
                ("--check-version", args.check_version),
                ("--detect-new-files", args.detect_new_files),
                ("--watch-hashes", args.watch_hashes),
                ("--full-diff", args.full_diff),
                ("--tree-diff", args.tree_diff),
                ("--accept-changed", args.accept_changed),
            ) if on
        ]
        if ignored:
            # A mode applies a flag or refuses it, never swallows it.
            print(
                f"--realign-prose does not apply {', '.join(ignored)}",
                file=sys.stderr,
            )
            raise SystemExit(1)
    machine = [
        flag for flag, on in (
            ("--json", args.as_json),
            ("--markdown", args.markdown),
            ("--fetch-plan", args.fetch_plan),
            ("--triage", args.triage),
        ) if on
    ]
    # The version check and detection live on the report, so the outputs
    # built from the report (text, --json, --markdown) carry them. A URL
    # list and a ranking do not.
    lists_only = args.fetch_plan or args.triage
    extras = [
        flag for flag, on in (
            ("--check-version", args.check_version and lists_only),
            ("--detect-new-files", args.detect_new_files and lists_only),
            ("--watch-hashes", args.watch_hashes and lists_only),
            ("--full-diff", args.full_diff),
            ("--tree-diff", args.tree_diff),
        ) if on
    ]
    if machine and extras:
        # The extra sections only exist in the text report. The other outputs
        # returned before reaching them and printed as if never asked.
        print(
            f"{', '.join(machine)} does not carry {', '.join(extras)}",
            file=sys.stderr,
        )
        raise SystemExit(1)
