"""Every file database.json names, hashed again, each confirmed bit flip repaired or flagged."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from collection.gitrestore import head_blob, modified_for_git, restore_from_blob
from core.hashing import file_digest
from model.largefiles import load_registered_paths

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


def check(
    root: Path,
    db: dict,
    apply: bool,
    hasher: Callable[[Path], str] = file_digest,
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
