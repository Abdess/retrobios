"""The recorded source trees and profile_sync's verdict on the emulator profiles."""

from __future__ import annotations

import json
import subprocess
import sys

from core.paths import REPO_ROOT
from freshness.findings import ERROR, OK, SKIPPED, STALE, UNKNOWN, Finding


def check_source_paths(profiles: dict) -> Finding:
    """The site links a cited path only where source-paths.json records it
    in the tree the profile pins. A recorded tree no profile pins any more,
    or a pinned tree the record lacks, means a pin moved or a profile was
    added and `sitesources.py --fetch` was not run after it. Every tree a run
    tries is recorded, read or not, so a lacking one was never tried."""
    from sitegen import sources as sitegen_sources

    pinned = {
        sitegen_sources.tree_key(repo, pin)
        for profile in profiles.values() if sitegen_sources.cited_paths(profile)
        for repo, pin in sitegen_sources.profile_trees(profile)
    } | {
        # The platform build files pin_build names, linked from a page too.
        sitegen_sources.tree_key(repo, pin)
        for profile in profiles.values()
        for repo, pin, _path in sitegen_sources.build_files(profile)
    }
    try:
        recorded = set(json.loads(sitegen_sources.SOURCE_PATHS.read_text(encoding="utf-8")))
    except (OSError, ValueError) as exc:
        return Finding("profiles", "source-paths.json", ERROR, detail=str(exc))
    orphaned = sorted(recorded - pinned)
    unrecorded = sorted(pinned - recorded)
    problems = [f"{len(found)} {words}" for found, words in (
        (orphaned, "recorded trees no profile pins"),
        (unrecorded, "pinned trees not recorded"),
    ) if found]
    return Finding(
        "profiles",
        "source-paths.json",
        STALE if problems else OK,
        local=f"{len(recorded)} trees",
        detail=(", ".join(problems) + ": run python scripts/sitesources.py --fetch") if problems
        else "every pinned tree is recorded, and only those",
    )


def check_profiles(run: bool, offline: bool) -> list[Finding]:
    if not run:
        return [
            Finding(
                "profiles",
                "profile_sync",
                SKIPPED,
                detail="pass --profiles, or run python scripts/profile_sync.py --all --triage",
            )
        ]
    cmd = [
        sys.executable,
        str(REPO_ROOT / "scripts" / "profile_sync.py"),
        "--all",
        "--json",
        "--check-version",
        "--detect-new-files",
        "--watch-hashes",
    ]
    if offline:
        cmd.append("--offline")
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, check=False)
    if proc.returncode not in (0, 1):
        tail = proc.stderr.strip().splitlines()[-1:]
        return [Finding("profiles", "profile_sync", ERROR, detail=tail[0] if tail else f"exit {proc.returncode}")]
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return [Finding("profiles", "profile_sync", ERROR, detail=f"unreadable report: {exc}")]
    return summarize_profile_sync(report)


_LEVELS = {"stale": STALE, "unknown": UNKNOWN}


def _verdict(row: dict) -> tuple[str | None, list[str]]:
    """The status profile_sync's attention reasons give a row, and their details.

    The reasons are decided once, on the report: a stale one makes the row
    stale, an unreadable one unknown, and a note says something without
    asking anything.
    """
    reasons = [r for r in row.get("attention") or () if isinstance(r, dict)]
    levels = {_LEVELS.get(str(r.get("level"))) for r in reasons}
    status = STALE if STALE in levels else UNKNOWN if UNKNOWN in levels else None
    asking = [str(r.get("detail") or "") for r in reasons if str(r.get("level")) in _LEVELS]
    notes = [str(r.get("detail") or "") for r in reasons if str(r.get("level")) not in _LEVELS]
    return status, asking or notes


def _skipped_finding(name: str, row: dict) -> Finding:
    """A profile profile_sync could not compare: its release page, or the skip.

    A skip profile_sync counts as a defect (no repository answers, no
    resolvable pin) is unknown. One that is the profile's nature (an upstream
    declared gone, a host no forge API serves, no source_ref) is never
    checkable and does not hold the exit code.
    """
    status, details = _verdict(row)
    reason = str(row["skipped"])
    declared = str(row.get("declared_version") or "")
    if row.get("page_version"):
        return Finding("profiles", name, status or OK, local=declared,
                       remote=str(row["page_version"]), detail=", ".join(details))
    if row.get("page_version_unread"):
        return Finding("profiles", name, status or UNKNOWN, local=declared,
                       detail=", ".join(details))
    if status is None:
        return Finding("profiles", name, SKIPPED, detail=reason)
    if reason not in details:
        details.insert(0, reason)
    return Finding("profiles", name, status, detail=", ".join(details))


def summarize_profile_sync(report: object) -> list[Finding]:
    """One row per profile with something to look at, from profile_sync's JSON.

    Each row carries the report's attention reasons: refs to review, a
    version behind its code, a file name or hash the cited code gained since
    the pin, a check the forge refused. A stale reason makes the profile
    stale, an unreadable one unknown, and one whose upstream moved while
    nothing asks for attention is counted as such without being stale.
    """
    if not isinstance(report, list):
        return [Finding("profiles", "profile_sync", ERROR, detail="report is not a list")]
    findings = []
    clean = moved = 0
    for row in report:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "?")
        if row.get("skipped"):
            findings.append(_skipped_finding(name, row))
            continue
        pin, head = str(row.get("pin") or ""), str(row.get("head") or "")
        status, details = _verdict(row)
        if status is not None:
            findings.append(
                Finding(
                    "profiles",
                    name,
                    status,
                    local=pin[:8],
                    remote=head[:8],
                    detail=", ".join(details),
                )
            )
        elif pin and head and pin != head:
            moved += 1
        else:
            clean += 1
    stale = sum(1 for f in findings if f.status == STALE)
    findings.insert(
        0,
        Finding(
            "profiles",
            "profile_sync",
            STALE if stale else OK,
            local=f"{clean} at tip, {moved} anchored past the tip",
            remote=f"{stale} to review",
        ),
    )
    return findings
