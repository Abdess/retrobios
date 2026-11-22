"""The campaign command's modes: gate, review, findings, status, references and a pass."""

from __future__ import annotations

import argparse
import json
import signal
import sys
from pathlib import Path

import yaml

from unattended import worktree
from core import hostguard
from probes.campaign import Campaign
from probes.gate import changed_profiles, gate
from probes.host import Paths, Settings, host_lock
from probes.profileedit import ProfileEditError
from probes.reports import open_findings, pass_report, render_status, review_finding, status_report

EXIT_REFUSED = 3


def run_mode(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
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
        for line in campaign.describe(only, args.system):
            print(line)
        return 0
    return _run_pass(campaign, args, only, paths)


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
    print(json.dumps(pass_report(campaign, current)))
    if current.result == "refused":
        return EXIT_REFUSED
    return 75 if current.result == "paused" else 0
