#!/usr/bin/env python3
"""Check that each MAME romset ref names the line declaring its own set.

profile_sync follows content: a ref that drifted still anchors wherever the
cited text went, which is what drift detection is for. It cannot say whether
the line a MAME ref points at declares the set the entry is named after, and
that is the only thing such a ref means. Asking the stronger question found
nineteen stale refs in one driver file where profile_sync had flagged five.

The set name is argument 1 of the machine macro, after the year. Matching the
name anywhere on the line would also match every clone that names this set as
its parent, which is most of a driver file. Comments are stripped first: a
declaration can sit behind one, as `/* Naomi */ GAME( 1998, naomi, ...)` does.

A set no machine macro declares is not an error. Device ROMs take the
shortname of their DEFINE_DEVICE_TYPE and some archives are bare ROM_START
blocks; a ref there cites something this check cannot judge, and says so.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(__file__))

import upstream
from safeparse import yaml_load
from scraper.mame_parser import _MACHINE_MACROS, strip_comments

DRIVER_REF = re.compile(r"^(src/[\w./+-]+):(\d+)$")


@dataclass(frozen=True)
class Finding:
    set_name: str
    path: str
    cited: int
    declared: int


def declares(line: str, set_name: str) -> bool:
    """Whether this line is the machine declaration of that set."""
    clean = strip_comments(line)
    match = _MACHINE_MACROS.search(clean)
    if not match:
        return False
    args = clean[match.end():].split(",")
    return len(args) > 1 and args[1].strip() == set_name


def audit(name: str, emulators_dir: str, cache_dir: str, offline: bool):
    """Findings, plus counts of refs that agree and of unjudgeable ones."""
    with open(os.path.join(emulators_dir, f"{name}.yml"), encoding="utf-8") as handle:
        document = yaml_load(handle) or {}
    repo = upstream.parse_repo(str(document.get("source") or ""))
    pin = str(document.get("source_commit") or "")
    if repo is None or not pin:
        return [], 0, 0
    sources: dict[str, list[str] | None] = {}
    findings: list[Finding] = []
    agreed = unjudged = 0
    for entry in document.get("files", []) or []:
        entry_name = str(entry.get("name", ""))
        match = DRIVER_REF.match(str(entry.get("source_ref") or ""))
        if not (entry_name.endswith(".zip") and match):
            continue
        path, cited = match.group(1), int(match.group(2))
        if path not in sources:
            sources[path] = upstream.fetch_file(repo, pin, path, cache_dir, offline)
        lines = sources[path]
        if lines is None:
            continue
        set_name = entry_name[:-4]
        if cited <= len(lines) and declares(lines[cited - 1], set_name):
            agreed += 1
            continue
        found = [i for i, line in enumerate(lines, 1) if declares(line, set_name)]
        if len(found) != 1:
            # None: a device set or a bare ROM_START. Several: the driver
            # declares the name twice and only a reader can choose.
            unjudged += 1
            continue
        findings.append(Finding(set_name, path, cited, found[0]))
    return findings, agreed, unjudged


def rewrite(name: str, emulators_dir: str, findings: list[Finding]) -> int:
    """Point each ref at the declaration, one entry at a time."""
    path = os.path.join(emulators_dir, f"{name}.yml")
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    written = 0
    for finding in findings:
        anchor = f"- name: {finding.set_name}.zip"
        old = f'source_ref: "{finding.path}:{finding.cited}"'
        start = text.find(anchor)
        if start < 0:
            continue
        at = text.find(old, start)
        if at < 0:
            continue
        new = f'source_ref: "{finding.path}:{finding.declared}"'
        text = text[:at] + new + text[at + len(old):]
        written += 1
    if written:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
    return written


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("emulators", nargs="+")
    parser.add_argument("--emulators-dir", default="emulators")
    parser.add_argument("--cache-dir", default=".cache")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()

    total = 0
    for name in args.emulators:
        findings, agreed, unjudged = audit(
            name, args.emulators_dir, args.cache_dir, args.offline
        )
        total += len(findings)
        print(
            f"{name}: {agreed} agree, {len(findings)} point elsewhere, "
            f"{unjudged} not judgeable"
        )
        for finding in findings:
            print(
                f"    {finding.set_name:16} {finding.path}"
                f":{finding.cited} -> {finding.declared}"
            )
        if args.write and findings:
            print(f"    written: {rewrite(name, args.emulators_dir, findings)}")
    raise SystemExit(1 if total and not args.write else 0)


if __name__ == "__main__":
    main()
