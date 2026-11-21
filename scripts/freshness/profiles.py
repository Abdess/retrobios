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


def summarize_profile_sync(report: object) -> list[Finding]:
    """One row per profile with something to look at, from profile_sync's JSON.

    The JSON carries the ref verdicts and the pin against the tip. A profile
    whose refs need review is stale, one the forge could not serve is unknown,
    and one whose upstream moved while every ref still anchors is reported as
    such without being counted as stale. A cited file that gained a file name
    since the pin, or a hash the profile does not declare, is stale too: the
    upstream may load a file the profile does not document.
    """
    if not isinstance(report, list):
        return [Finding("profiles", "profile_sync", ERROR, detail="report is not a list")]
    findings = []
    clean = moved = 0
    for row in report:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "?")
        if row.get("skipped") and row.get("page_version"):
            # Off any forge, the release page is the feed: a version there
            # beyond the declared one is a release the profile does not cover.
            declared, announced = str(row.get("declared_version") or ""), str(row["page_version"])
            if announced == declared:
                status, detail = OK, ""
            elif announced == str(row.get("no_genuine_copy") or ""):
                # Searched for and found only rebuilt: the profile covers the
                # newest build that can be read, until the page moves on.
                status, detail = OK, "no genuine copy of the announced release"
            else:
                status, detail = STALE, "a newer release is announced"
            findings.append(Finding("profiles", name, status, local=declared,
                                    remote=announced, detail=detail))
            continue
        if row.get("skipped") and row.get("page_version_unread"):
            # The release page is the only feed this profile has: unread, a
            # new release cannot be told from none, so the row is unknown.
            findings.append(Finding("profiles", name, UNKNOWN,
                                    local=str(row.get("declared_version") or ""),
                                    detail=f"version page unread: {row['page_version_unread']}"))
            continue
        if row.get("skipped"):
            # A skip profile_sync counts as a defect (no repository answers,
            # no resolvable pin) is unknown. One that is the profile's nature
            # (an upstream declared gone, a host no forge API serves, no
            # source_ref) is never checkable and does not hold the exit code.
            from profiling.reports import ProfileReport

            reason = str(row["skipped"])
            status = UNKNOWN if reason.startswith(ProfileReport.UNCHECKABLE) else SKIPPED
            findings.append(Finding("profiles", name, status, detail=reason))
            continue
        review = row.get("needs_review") or 0
        pin, head = str(row.get("pin") or ""), str(row.get("head") or "")
        added = sorted({
            str(item.get("name"))
            for item in row.get("new_files") or ()
            if isinstance(item, dict) and item.get("since_pin")
        })
        hashes = len(row.get("new_hashes") or ())
        reasons = [f"{review} refs to review"] if review else []
        if added:
            reasons.append(f"new file names since the pin: {', '.join(added)}")
        if hashes:
            reasons.append(f"{hashes} undeclared hashes added since the pin")
        if reasons:
            findings.append(
                Finding(
                    "profiles",
                    name,
                    STALE,
                    local=pin[:8],
                    remote=head[:8],
                    detail=", ".join(reasons),
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
