#!/usr/bin/env python3
"""Rehash every file database.json names and repair a confirmed bit flip.

git status never shows a flipped bit: the index compares size and mtime, and
a flip changes neither. Only reading the bytes again finds it. Every file
the database names is hashed and compared with its recorded SHA-1. A
mismatch is read a second time: two reads that disagree are a host misread
and nothing on disk changes.

A confirmed mismatch is handled by where the file comes from:

- committed and unmodified for git: restored from its blob in HEAD, once
  the blob's object id and its content SHA-1 both check out, then hashed
  again. Only with --apply.
- modified for git (git status lists it): a working change some session
  made, left alone and reported.
- gitignored (a large-files release asset) or untracked: flagged, never
  repaired.
- a blob in HEAD whose content is not the recorded SHA-1: the database and
  git disagree, flagged.

Run it on an idle host: a busy CPU here computes wrong hashes, which is the
fault this looks for. autorun.py's load guard holds the weekly job until the
host is idle.

Usage:
    python scripts/bios_integrity.py
    python scripts/bios_integrity.py --apply
    python scripts/bios_integrity.py --apply --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from largefiles import load_registered_paths

MISREAD = "misread"
RESTORED = "restored"
FLAGGED = "flagged"
SKIPPED = "skipped"


@dataclass(frozen=True)
class Finding:
    path: str
    verdict: str  # misread, restored, flagged, skipped
    reason: str
    expected: str
    found: str = ""


@dataclass
class Report:
    checked: int = 0
    findings: list[Finding] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.verdict] = counts.get(f.verdict, 0) + 1
        return counts

    def as_dict(self) -> dict:
        return {
            "checked": self.checked,
            "counts": self.counts(),
            "findings": [f.__dict__ for f in self.findings],
        }

    @property
    def clean(self) -> bool:
        return all(f.verdict in (MISREAD, RESTORED) for f in self.findings)


def sha1_of(path: Path) -> str:
    digest = hashlib.sha1()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


class GitFailed(RuntimeError):
    """A git command failed: its empty output says nothing about the file."""


def git(root: Path, *args: str) -> subprocess.CompletedProcess:
    """Run git in root. A failure raises: an unreadable index read as an empty
    status made a session's working change look unmodified, and --apply wrote
    HEAD's bytes over it."""
    done = subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=False)
    if done.returncode:
        message = done.stderr.decode(errors="replace").strip()
        raise GitFailed(f"git {' '.join(args)} exited {done.returncode}: {message}")
    return done


def head_blob(root: Path, path: str) -> str:
    """The blob HEAD records for path, empty when HEAD has none."""
    out = git(root, "ls-tree", "HEAD", "--", path).stdout.decode()
    parts = out.split()
    return parts[2] if len(parts) >= 3 and parts[1] == "blob" else ""


def modified_for_git(root: Path, path: str) -> bool:
    return bool(git(root, "status", "--porcelain", "--", path).stdout.strip())


def restore_from_blob(root: Path, path: str, blob: str, expected: str) -> str:
    """Write the blob's bytes over path, after checking them. Empty on success."""
    data = git(root, "cat-file", "blob", blob).stdout
    object_id = hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()
    if object_id != blob:
        return f"blob read back as {object_id[:12]}, not {blob[:12]}"
    if hashlib.sha1(data).hexdigest() != expected:
        return "HEAD holds other bytes than database.json records"
    target = root / path
    handle, scratch = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.")
    try:
        with os.fdopen(handle, "wb") as out:
            out.write(data)
        os.chmod(scratch, target.stat().st_mode & 0o777)
        os.replace(scratch, target)
    except OSError:
        if os.path.exists(scratch):
            os.unlink(scratch)
        raise
    return ""


def check(
    root: Path,
    db: dict,
    apply: bool,
    hasher: Callable[[Path], str] = sha1_of,
) -> Report:
    """Hash every database path, confirm each mismatch, repair what may be."""
    ignored = set(load_registered_paths(root / ".gitignore"))
    report = Report()
    for key, entry in sorted(db.get("files", {}).items(), key=lambda kv: kv[1]["path"]):
        path = entry["path"]
        expected = str(entry.get("sha1") or key).lower()
        local = root / path
        if not local.is_file():
            continue  # a release asset not fetched yet, verify reports it
        report.checked += 1
        first = hasher(local)
        if first == expected:
            continue
        second = hasher(local)
        if second != first:
            verdict = MISREAD if second == expected else FLAGGED
            report.findings.append(Finding(
                path, verdict, f"two reads disagree ({first[:12]}, {second[:12]})",
                expected, second))
            continue
        if path in ignored:
            report.findings.append(Finding(
                path, FLAGGED, "gitignored large file, never repaired here", expected, first))
            continue
        blob = head_blob(root, path)
        if not blob:
            report.findings.append(Finding(path, FLAGGED, "not in HEAD", expected, first))
            continue
        if modified_for_git(root, path):
            report.findings.append(Finding(
                path, SKIPPED, "modified for git: a working change, left alone",
                expected, first))
            continue
        if not apply:
            report.findings.append(Finding(
                path, FLAGGED, "bit flip, restorable from HEAD with --apply", expected, first))
            continue
        problem = restore_from_blob(root, path, blob, expected)
        if problem:
            report.findings.append(Finding(path, FLAGGED, problem, expected, first))
            continue
        after = hasher(local)
        if after == expected:
            report.findings.append(Finding(
                path, RESTORED, f"restored from blob {blob[:12]}", expected, first))
        else:
            report.findings.append(Finding(
                path, FLAGGED, f"restored but reads {after[:12]}", expected, after))
    return report


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.split("\n\n")[0])
    parser.add_argument("--apply", action="store_true",
                        help="restore confirmed flips of committed files from HEAD")
    parser.add_argument("--db", default="database.json",
                        help="database file to read (default: %(default)s)")
    parser.add_argument("--json", action="store_true", help="machine-readable report")
    args = parser.parse_args()

    from common import load_database

    root = Path.cwd()
    try:
        report = check(root, load_database(args.db), args.apply)
    except GitFailed as exc:
        print(f"ERROR: {exc}. Nothing was restored past this point.", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report.as_dict(), indent=2))
    else:
        for f in report.findings:
            print(f"{f.verdict.upper():9} {f.path}: {f.reason}")
        counts = ", ".join(f"{n} {v}" for v, n in sorted(report.counts().items()))
        print(f"{report.checked} files hashed" + (f", {counts}" if counts else ", all match"))
    return 0 if report.clean else 1


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
