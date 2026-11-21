#!/usr/bin/env python3
"""Compare scraped platform YAMLs against ground-truth YAMLs.

Usage:
    python scripts/diff_truth.py --all
    python scripts/diff_truth.py --platform retroarch
    python scripts/diff_truth.py --platform retroarch --json
    python scripts/diff_truth.py --all --format markdown
"""

from __future__ import annotations

from core.paths import TRUTH_DIR
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from core.cli import add_repo_inputs
from model.cliargs import platform_arg, selected_platforms
from model.platforms import load_platform_config, native_layer
from model.safeparse import require_yaml, yaml_load
from model.targets import truth_target_dir
from resolve.truth import diff_platform_truth

yaml = require_yaml()


def _load_truth(truth_dir: str, platform: str) -> dict | None:
    path = os.path.join(truth_dir, f"{platform}.yml")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return yaml_load(f) or {}


def _where(entry: dict) -> str:
    """Where a diffed entry sits: one name can be declared at several paths."""
    return entry.get("destination") or entry["name"]


_TOTAL_LABELS = (
    ("total_missing", "missing"),
    ("total_extra_phantom", "unpaired"),
    ("total_extra_unprofiled", "unprofiled"),
    ("total_hash_mismatch", "hash"),
    ("total_required_mismatch", "required"),
)

_DIVERGENCE_LABELS = (
    ("missing", "MISSING"),
    ("extra_phantom", "UNPAIRED"),
    ("extra_unprofiled", "UNPROF"),
    ("hash_mismatch", "HASH"),
    ("required_mismatch", "REQ"),
)


def _terminal_divergence(sys_id: str, div: dict) -> list[str]:
    labels = [f"{label}:{len(div[key])}" for key, label in _DIVERGENCE_LABELS if div.get(key)]
    lines = [f"  {sys_id}: {' '.join(labels)}"]
    lines.extend(
        f"    + {_where(m)}  [{', '.join(m.get('cores', []))}]"
        for m in div.get("missing", [])
    )
    lines.extend(
        f"    ~ {_where(h)}  {h['hash_type']}: "
        f"{h['truth_' + h['hash_type']]} != {h['scraped_' + h['hash_type']]}"
        for h in div.get("hash_mismatch", [])
    )
    lines.extend(
        f"    - {_where(p)}  (no profile entry of this system matches it)"
        for p in div.get("extra_phantom", [])
    )
    lines.extend(
        f"    ? {_where(u)}  (unprofiled cores)"
        for u in div.get("extra_unprofiled", [])
    )
    lines.extend(
        f"    ! {_where(r)}  required: {r['truth_required']} != {r['scraped_required']}"
        for r in div.get("required_mismatch", [])
    )
    return lines


def _format_terminal(report: dict) -> str:
    lines: list[str] = []
    platform = report.get("platform", "unknown")
    s = report["summary"]

    lines.append(f"=== {platform} ===")
    lines.append(
        f"  {s['systems_compared']} systems compared: "
        f"{s['systems_fully_covered']} full, "
        f"{s['systems_partially_covered']} partial, "
        f"{s['systems_uncovered']} uncovered"
    )

    totals = [f"{s[key]} {label}" for key, label in _TOTAL_LABELS if s[key]]
    if totals:
        lines.append(f"  divergences: {', '.join(totals)}")
    else:
        lines.append("  no divergences")

    for sys_id, div in sorted(report.get("divergences", {}).items()):
        lines.extend(_terminal_divergence(sys_id, div))

    uncovered = report.get("uncovered_systems", [])
    if uncovered:
        lines.append(f"  uncovered ({len(uncovered)}): {', '.join(uncovered)}")

    return "\n".join(lines)


def _markdown_divergence(sys_id: str, div: dict) -> list[str]:
    lines = [f"## {sys_id}", ""]
    for m in div.get("missing", []):
        refs = ""
        if m.get("source_refs"):
            refs = " " + " ".join(f"`{r}`" for r in m["source_refs"])
        lines.append(f"- **Add** `{_where(m)}`{refs}")
    lines.extend(
        f"- **Fix hash** `{_where(h)}` {h['hash_type']}: "
        f"`{h['truth_' + h['hash_type']]}` != `{h['scraped_' + h['hash_type']]}`"
        for h in div.get("hash_mismatch", [])
    )
    # Evidence, not a request: an entry leaves a platform's file only on
    # proof (export_native's removal_candidates). A core can read a
    # file its profile does not pair with this declaration.
    lines.extend(
        f"- **Unpaired** `{_where(p)}`: no profile entry of this system matches it "
        "by path, name or hash"
        for p in div.get("extra_phantom", [])
    )
    lines.extend(
        f"- **Unpaired** `{_where(u)}`: some cores of this platform "
        "have no profile yet"
        for u in div.get("extra_unprofiled", [])
    )
    lines.extend(
        f"- **Fix required** `{_where(r)}`: truth={r['truth_required']}, scraped={r['scraped_required']}"
        for r in div.get("required_mismatch", [])
    )
    lines.append("")
    return lines


def _format_markdown(report: dict) -> str:
    lines: list[str] = []
    platform = report.get("platform", "unknown")
    s = report["summary"]

    lines.append(f"# {platform}")
    lines.append("")
    lines.append(
        f"**{s['systems_compared']}** systems compared | "
        f"**{s['systems_fully_covered']}** full | "
        f"**{s['systems_partially_covered']}** partial | "
        f"**{s['systems_uncovered']}** uncovered"
    )
    lines.append(
        f"**{s['total_missing']}** missing | "
        f"**{s['total_extra_phantom']}** unpaired | "
        f"**{s['total_extra_unprofiled']}** unprofiled | "
        f"**{s['total_hash_mismatch']}** hash | "
        f"**{s['total_required_mismatch']}** required"
    )
    lines.append("")

    for sys_id, div in sorted(report.get("divergences", {}).items()):
        lines.extend(_markdown_divergence(sys_id, div))

    uncovered = report.get("uncovered_systems", [])
    if uncovered:
        lines.append("## Uncovered systems")
        lines.append("")
        lines.extend(f"- {u}" for u in uncovered)
        lines.append("")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Compare scraped vs truth YAMLs")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--all", action="store_true", help="diff all registered platforms"
    )
    group.add_argument("--platform", "-p", type=platform_arg, help="diff a single platform")
    # One output form: --json beside --format markdown printed JSON and
    # dropped the markdown without a word.
    output = parser.add_mutually_exclusive_group()
    output.add_argument(
        "--json", action="store_true", dest="json_output", help="JSON output"
    )
    output.add_argument(
        "--format", choices=["terminal", "markdown"], default="terminal",
        help="report format (default: %(default)s)",
    )
    output.add_argument(
        "--markdown", action="store_const", const="markdown", dest="format",
        help="same as --format markdown, the spelling validate_pr uses",
    )
    parser.add_argument(
        "--truth-dir", default=TRUTH_DIR,
        help="directory of the truth models generate_truth writes (default: "
             "%(default)s)",
    )
    add_repo_inputs(parser, "platforms")
    parser.add_argument(
        "--target", "-t",
        help="read the models generate_truth --target wrote, each under the "
        "target as its platform files it",
    )
    args = parser.parse_args()

    platforms = selected_platforms(args)

    reports: list[dict] = []
    formatter = _format_markdown if args.format == "markdown" else _format_terminal
    compared = 0

    for platform in platforms:
        truth_dir = (
            truth_target_dir(args.truth_dir, [platform], args.target, args.platforms_dir)
            if args.target else args.truth_dir
        )
        truth = _load_truth(truth_dir, platform)
        if truth is None:
            print(f"skip {platform}: no truth YAML in {truth_dir}/", file=sys.stderr)
            continue

        try:
            # What the platform's own file declares: our shared groups,
            # mirrors and curated additions are not theirs to be credited.
            scraped = native_layer(load_platform_config(platform, args.platforms_dir))
        except FileNotFoundError:
            print(f"skip {platform}: no scraped config", file=sys.stderr)
            continue

        report = diff_platform_truth(truth, scraped)
        report["platform"] = platform
        compared += 1

        if args.json_output:
            reports.append(report)
        else:
            print(formatter(report))
            print()

    if args.json_output:
        json.dump(reports, sys.stdout, indent=2)
        print()

    # A named platform must be compared; --all must compare at least one.
    if compared < (len(platforms) if args.platform else 1):
        print(f"compared {compared} of {len(platforms)} platform(s)", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
