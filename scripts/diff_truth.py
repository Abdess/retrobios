#!/usr/bin/env python3
"""Compare scraped platform YAMLs against ground-truth YAMLs.

Usage:
    python scripts/diff_truth.py --all
    python scripts/diff_truth.py --platform retroarch
    python scripts/diff_truth.py --platform retroarch --json
    python scripts/diff_truth.py --all --format markdown
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from common import list_registered_platforms, load_platform_config, require_yaml, yaml_load
from truth import diff_platform_truth

yaml = require_yaml()


def _load_truth(truth_dir: str, platform: str) -> dict | None:
    path = os.path.join(truth_dir, f"{platform}.yml")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return yaml_load(f) or {}


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

    totals = []
    if s["total_missing"]:
        totals.append(f"{s['total_missing']} missing")
    if s["total_extra_phantom"]:
        totals.append(f"{s['total_extra_phantom']} phantom")
    if s["total_extra_unprofiled"]:
        totals.append(f"{s['total_extra_unprofiled']} unprofiled")
    if s["total_hash_mismatch"]:
        totals.append(f"{s['total_hash_mismatch']} hash")
    if s["total_required_mismatch"]:
        totals.append(f"{s['total_required_mismatch']} required")
    if totals:
        lines.append(f"  divergences: {', '.join(totals)}")
    else:
        lines.append("  no divergences")

    for sys_id, div in sorted(report.get("divergences", {}).items()):
        labels: list[str] = []
        if div.get("missing"):
            labels.append(f"MISSING:{len(div['missing'])}")
        if div.get("extra_phantom"):
            labels.append(f"PHANTOM:{len(div['extra_phantom'])}")
        if div.get("extra_unprofiled"):
            labels.append(f"UNPROF:{len(div['extra_unprofiled'])}")
        if div.get("hash_mismatch"):
            labels.append(f"HASH:{len(div['hash_mismatch'])}")
        if div.get("required_mismatch"):
            labels.append(f"REQ:{len(div['required_mismatch'])}")
        lines.append(f"  {sys_id}: {' '.join(labels)}")

        for m in div.get("missing", []):
            cores = ", ".join(m.get("cores", []))
            lines.append(f"    + {m['name']}  [{cores}]")
        for h in div.get("hash_mismatch", []):
            ht = h["hash_type"]
            lines.append(
                f"    ~ {h['name']}  {ht}: {h[f'truth_{ht}']} != {h[f'scraped_{ht}']}"
            )
        for p in div.get("extra_phantom", []):
            lines.append(f"    - {p['name']}  (phantom)")
        for u in div.get("extra_unprofiled", []):
            lines.append(f"    ? {u['name']}  (unprofiled)")
        for r in div.get("required_mismatch", []):
            lines.append(
                f"    ! {r['name']}  required: {r['truth_required']} != {r['scraped_required']}"
            )

    uncovered = report.get("uncovered_systems", [])
    if uncovered:
        lines.append(f"  uncovered ({len(uncovered)}): {', '.join(uncovered)}")

    return "\n".join(lines)


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
        f"**{s['total_extra_phantom']}** phantom | "
        f"**{s['total_extra_unprofiled']}** unprofiled | "
        f"**{s['total_hash_mismatch']}** hash | "
        f"**{s['total_required_mismatch']}** required"
    )
    lines.append("")

    for sys_id, div in sorted(report.get("divergences", {}).items()):
        lines.append(f"## {sys_id}")
        lines.append("")
        for m in div.get("missing", []):
            refs = ""
            if m.get("source_refs"):
                refs = " " + " ".join(f"`{r}`" for r in m["source_refs"])
            lines.append(f"- **Add** `{m['name']}`{refs}")
        for h in div.get("hash_mismatch", []):
            ht = h["hash_type"]
            lines.append(
                f"- **Fix hash** `{h['name']}` {ht}: `{h[f'truth_{ht}']}` != `{h[f'scraped_{ht}']}`"
            )
        for p in div.get("extra_phantom", []):
            lines.append(f"- **Remove** `{p['name']}` (phantom)")
        for u in div.get("extra_unprofiled", []):
            lines.append(f"- **Check** `{u['name']}` (unprofiled cores)")
        for r in div.get("required_mismatch", []):
            lines.append(
                f"- **Fix required** `{r['name']}`: truth={r['truth_required']}, scraped={r['scraped_required']}"
            )
        lines.append("")

    uncovered = report.get("uncovered_systems", [])
    if uncovered:
        lines.append("## Uncovered systems")
        lines.append("")
        for u in uncovered:
            lines.append(f"- {u}")
        lines.append("")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare scraped vs truth YAMLs")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--all", action="store_true", help="diff all registered platforms"
    )
    group.add_argument("--platform", help="diff a single platform")
    parser.add_argument(
        "--json", action="store_true", dest="json_output", help="JSON output"
    )
    parser.add_argument(
        "--format", choices=["terminal", "markdown"], default="terminal"
    )
    parser.add_argument("--truth-dir", default="dist/truth")
    parser.add_argument("--platforms-dir", default="platforms")
    args = parser.parse_args()

    if args.all:
        platforms = list_registered_platforms(
            args.platforms_dir, include_archived=True
        )
    else:
        platforms = [args.platform]

    reports: list[dict] = []
    formatter = _format_markdown if args.format == "markdown" else _format_terminal

    for platform in platforms:
        truth = _load_truth(args.truth_dir, platform)
        if truth is None:
            if not args.json_output:
                print(
                    f"skip {platform}: no truth YAML in {args.truth_dir}/",
                    file=sys.stderr,
                )
            continue

        try:
            scraped = load_platform_config(platform, args.platforms_dir)
        except FileNotFoundError:
            if not args.json_output:
                print(f"skip {platform}: no scraped config", file=sys.stderr)
            continue

        report = diff_platform_truth(truth, scraped)
        report["platform"] = platform

        if args.json_output:
            reports.append(report)
        else:
            print(formatter(report))
            print()

    if args.json_output:
        json.dump(reports, sys.stdout, indent=2)
        print()


if __name__ == "__main__":
    main()
