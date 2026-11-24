"""One profile's pass: the report the flags ask for, the writes it allows, and the output."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from datetime import date
from pathlib import Path

import yaml

from core import upstream
from profiling.bump import bump_commit, pins_changed
from profiling.detection import detect_upstream_changes, print_extras
from profiling.realign import realign_prose
from profiling.rebase import Recale, attribute_refs, rebase_refs
from profiling.reports import (
    ProfileReport,
    SkipKind,
    fetch_plan,
    format_markdown,
    format_report,
    report_to_dict,
)
from profiling.resolver import build_report
from profiling.sourcepaths import record_write
from profiling.triage import (
    PROGRESS_SECONDS, Progress, print_interrupted, print_triage, score_reports, scored_to_dict,
)
from profiling.versionbasis import VersionTag, version_tags
from profiling.versions import (
    VersionReport,
    check_version,
    latest_passed_release,
    newer_release,
    page_declared,
    page_version,
    version_warning,
)
from profiling.yamledit import YamlWriteError, backfill_commit


def _stale_prose_blocks(
    name: str, path: Path, args: argparse.Namespace,
    known: list[str] | None = None,
) -> bool:
    """Whether prose written under an older pin has to move first.

    Anchored from the current pin, a recale or a bump follows someone else's
    code (boom3 FileSystem.cpp:2125, written at b810234e, an unrelated
    OpenFileRead at 132dfddb). It moves first, from the pin it was written at.
    `known` is the answer the report already holds for the same text.
    """
    stale = (
        known if known is not None
        else realign_prose(path, args.cache_dir, args.offline, dry_run=True)
    )
    if stale:
        print(
            f"{name}: {len(stale)} prose citation(s) written under an older pin; "
            "run --realign-prose, or read them and set prose_written_at to the pin they match",
            file=sys.stderr,
        )
    return bool(stale)


def _read_stale_prose(
    name: str, path: Path, args: argparse.Namespace, failed: set[str]
) -> list[str]:
    """What --realign-prose would do or refuse on this profile, as a report.

    Read on every pass, not only before a write: prose that blocks the pin
    is review work whether or not this run tries to move it.
    """
    try:
        return realign_prose(path, args.cache_dir, args.offline, dry_run=True)
    except upstream.RateLimitError:
        raise
    except upstream.NotCachedError as exc:
        # Unread offline, as a report is: not clean, and not a failure.
        return [f"not read offline: {exc}"]
    except upstream.UpstreamError as exc:
        # Not read is not clean: the bump would refuse on the same error.
        print(f"{name}: prose not read, {exc}", file=sys.stderr)
        failed.add(name)
        return [f"not read: {exc}"]


def _backfill(
    args: argparse.Namespace, name: str, profile: dict, report: ProfileReport,
    path: Path,
) -> None:
    """Write the pin a profile without source_commit was written at."""
    if not report.pin or profile.get("source_commit"):
        return
    if args.dry_run:
        print(f"{name}: would write source_commit {report.pin[:7]}")
    elif backfill_commit(path, report.pin):
        print(f"{name}: source_commit {report.pin[:7]}")


def _write_attributions(
    args: argparse.Namespace, name: str, profile: dict, report: ProfileReport, path: Path
) -> None:
    if report.skipped:
        return
    with tempfile.TemporaryDirectory() as scratch:
        target = Path(scratch) / path.name
        target.write_bytes(path.read_bytes())
        verb = "would attribute " if args.dry_run else ""
        for line in attribute_refs(target, report, profile):
            print(f"{name}: {verb}{line}")
        if not args.dry_run:
            path.write_bytes(target.read_bytes())


def _promote(
    args: argparse.Namespace, name: str, path: Path, target: Path, moved: bool
) -> bool:
    """Write the edited copy over the profile, False when it was put back."""
    original = path.read_bytes()
    path.write_bytes(target.read_bytes())
    # The guard above read the prose under the pins the profile held.
    # A bump that moves upstream_commit can leave prose the report
    # judged in the fork under the new upstream pin (dolphin-mmjr2,
    # hatari, xenios): read it again on what was written. It reads
    # the profile's own history, so it runs on the real path, and a
    # read that fails (offline, rate limit) puts the profile back.
    try:
        left = realign_prose(path, args.cache_dir, args.offline, dry_run=True)
    except BaseException:
        path.write_bytes(original)
        raise
    if moved and left:
        path.write_bytes(original)
        print(
            f"{name}: the bump would leave {len(left)} prose citation(s) "
            "under an older pin, nothing was written. Read them first.",
            file=sys.stderr,
        )
        return False
    return True


def _apply_writes(
    args: argparse.Namespace, name: str, profile: dict, report: ProfileReport
) -> None:
    path = Path(args.emulators_dir) / f"{name}.yml"
    if not path.is_file():
        return
    if args.backfill_commits:
        _backfill(args, name, profile, report, path)
    if getattr(args, "attribute_refs", False):
        _write_attributions(args, name, profile, report, path)
        return
    # A backfill has just written a pin: the report's reading predates it.
    known = None if args.backfill_commits else report.stale_prose
    if not (args.rebase_refs or args.bump_commit) or _stale_prose_blocks(
        name, path, args, known
    ):
        return
    if _gained_since_pin(args, name, profile, report):
        return
    with tempfile.TemporaryDirectory() as scratch:
        # Always work on a copy. A dry run reports what it left there, a real
        # run promotes it. A recale rewrites the refs for HEAD, so the pin
        # has to follow or neither moves: a profile whose refs describe one
        # revision and whose pin names another is exactly what the
        # all-or-nothing rule exists to prevent. Recaling alone used to
        # leave that state behind, and a later bump then read the recaled
        # refs at the old pin and saw them shifted again.
        target = Path(scratch) / path.name
        target.write_bytes(path.read_bytes())
        recale, bumped = ("would recale ", "would set ") if args.dry_run else ("", "")
        outcome = Recale()
        if args.rebase_refs and not report.skipped:
            outcome = rebase_refs(target, report, args.accept_changed)
        for reason in outcome.refused:
            print(f"{name}: not recaled, cannot move {reason}", file=sys.stderr)
        applied = outcome.applied
        bump = bump_commit(target, report, args.accept_changed,
                           args.cache_dir, args.offline)
        moved = bump.moved
        if args.rebase_refs and applied and not moved:
            # A refusal bump_commit did not name is a ref the recale left
            # for a reader: the prose guard above has already passed.
            reason = bump.refusal or "the prose or an annotated ref has to move first"
            print(
                f"{name}: refs recaled but the pin will not follow, so nothing "
                f"was written: {reason}",
                file=sys.stderr,
            )
            return
        if bump.refusal and not outcome.refused:
            # A refused recale has named the citations that hold the pin.
            print(f"{name}: {bump.refusal}", file=sys.stderr)
        messages = [f"{name}: {recale}{line}" for line in applied]
        if moved:
            # Each pin the write changes, as written: a bump that only moved
            # upstream_commit announced the source_commit it already held.
            after = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
            before = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            messages += [
                f"{name}: {bumped}{pin} -> {str(after[pin])[:7]}"
                for pin in pins_changed(before, after)
            ]
        if (
            not args.dry_run and (applied or moved)
            and not _promote(args, name, path, target, moved)
        ):
            return
        for message in messages:
            print(message)


def _gained_since_pin(
    args: argparse.Namespace, name: str, profile: dict, report: ProfileReport
) -> bool:
    """Whether the cited files gained a file name or a hash literal since the pin.

    Refs that still anchor say nothing of what the code added around them:
    mame2003_plus gained two Taito G-NET BIOS sets in a zn.c whose cited
    lines only shifted. A bump past that would document a file set the code
    no longer has. --accept-changed says the additions were read.
    Decided per repository: an upstream that moved while the port sits on
    HEAD is read before a bump advances upstream_commit, and a repository
    held on its tag, which the bump leaves there, is not.
    """
    advancing = {s.path for s in report.cited_sources if s.advances()}
    if args.accept_changed or not advancing:
        return False
    if report.pinned_tag:
        # A held pin is not advanced at all: bump_commit says so itself.
        return False
    if report.new_files is None and report.new_hashes is None:
        _attach_detection(profile, report, args.cache_dir, args.offline, True, True)
    gained = sorted({
        item["name"] for item in report.new_files or ()
        if item.get("since_pin") and item["path"] in advancing
    })
    added = [item for item in report.new_hashes or () if item["path"] in advancing]
    if not (gained or added or report.detection_skipped):
        return False
    detail = ", ".join(gained[:5]) + (f", {len(added)} hash literal(s)" if added else "")
    if report.detection_skipped:
        detail = f"cited files unread ({report.detection_skipped})"
    print(
        f"{name}: the cited files changed beyond the refs since the pin ({detail.strip(', ')}), "
        "nothing was written. Read them, then rerun with --accept-changed.",
        file=sys.stderr,
    )
    return True


def _attach_detection(
    profile: dict, report: ProfileReport, cache_dir: str, offline: bool,
    files: bool, hashes: bool,
) -> None:
    """Record undeclared names and hashes of the cited files on the report.

    Kept on the report rather than printed, so --json carries them as the
    text report does. A forge that refuses is named on the report: the ref
    report already muted it, and one refusal must not end a pass over every
    profile. A quota signal still ends the profile.
    """
    if not report.head or not (files or hashes):
        return
    try:
        detect_upstream_changes(profile, report, cache_dir, offline, files, hashes)
    except upstream.RateLimitError:
        raise
    except upstream.UpstreamError as exc:
        report.detection_skipped = str(exc)


def _version_pin(report: ProfileReport, repo: upstream.Repo, field: str) -> str | None:
    """The pin of the repository core_version is read in: upstream_commit for
    a basis reading the upstream, the primary pin for the primary repository,
    None for a repository the report did not compare."""
    if field == "upstream":
        return report.upstream_pin
    if (repo.host, repo.slug) == (report.host, report.repo):
        return report.pin
    return None


def _version_of(
    args: argparse.Namespace, profile: dict, report: ProfileReport, named: VersionTag,
) -> tuple[VersionReport | None, str | None]:
    """One build's core_version against its repository: the report and the
    warning. A refused tag ancestry is named on version_unread."""
    repo = named.repo
    if repo is None:
        return None, None
    pin = _version_pin(report, repo, named.field)
    # A held upstream (yaps2 synced to PCSX2 342db515) is not one a newer
    # release of that project asks to profile again, as a held pin is not.
    frozen_by = "upstream_frozen" if named.field == "upstream" else "pin_frozen"
    version = check_version(named, args.cache_dir, args.offline)
    relation = None
    passed = None
    try:
        if version and version.tag_commit and pin and version.tag_commit != pin:
            relation = upstream.ancestry(
                repo, version.tag_commit, pin, args.cache_dir, args.offline
            )
        passed = latest_passed_release(repo, version, pin, args.cache_dir, args.offline)
        newer = None if passed or profile.get(frozen_by) else newer_release(
            repo, version, pin, args.cache_dir, args.offline
        )
    except upstream.RateLimitError:
        raise
    except upstream.UpstreamError as exc:
        report.version_unread = f"tag ancestry unread: {exc}"
        newer = None
    warning = version_warning(version, pin, relation, passed) or (
        f"{'release' if version.latest_release else 'tag'} {newer} is newer than core_version {version.declared} and the pin: "
        f"profile it, or hold the pin with {frozen_by} and the reason"
        if newer and version else None
    )
    return version, warning


def _attach_version(
    args: argparse.Namespace, profile: dict, report: ProfileReport
) -> None:
    """Record core_version against the forge's latest tag and release.

    Kept on the report rather than printed, so --json carries it as the text
    report does. A forge that refuses is named on the profile's own line
    (version_unread). Each build's tag is read in its own repository, and a
    warning names its build when the builds name different tags.
    """
    if not report.head:
        return
    named_tags = [named for named in version_tags(profile) if named.repo is not None]
    warnings: list[str] = []
    for named in named_tags:
        try:
            version, warning = _version_of(args, profile, report, named)
        except upstream.RateLimitError:
            raise
        except upstream.UpstreamError as exc:
            report.version_unread = f"version check skipped: {exc}"
            return
        if report.version is None:
            report.version = version
        if warning:
            warnings.append(f"{named.mode}: {warning}" if len(named_tags) > 1 else warning)
        report.version_warning = "; ".join(warnings) or None


def read_one_profile(
    args: argparse.Namespace,
    name: str,
    profile: dict,
    reports: list[ProfileReport],
    failed: set[str],
    writes: bool,
    written: set[str],
) -> None:
    """Build one profile's report into ``reports``, then apply the writes.

    A profile the writes changed is added to ``written``.
    """
    profile_path = Path(args.emulators_dir) / f"{name}.yml"
    try:
        report = _build_full_report(args, name, profile, profile_path, failed)
    except upstream.RateLimitError as exc:
        # A quota is one forge's: git.libretro.com answering 429 said
        # nothing about the 600 profiles on GitHub. upstream stops asking
        # that host, so the rest of the pass costs it nothing.
        print(f"{name}: {exc}", file=sys.stderr)
        report = _skipped(name, SkipKind.RATE_LIMITED, f"rate limited: {exc.host or exc}")
        writes = False
    reports.append(report)
    if report.unreached():
        failed.add(name)
    if writes:
        try:
            with record_write(profile_path, name, written):
                _apply_writes(args, name, profile, report)
        except YamlWriteError as exc:
            # The guard already left the file untouched, so keep going.
            print(f"{name}: write refused: {exc}", file=sys.stderr)
            failed.add(name)
        except upstream.UpstreamError as exc:
            # A prose read the writes need could not be made (offline with
            # a cold cache, a forge down): the profile was put back, and one
            # profile must not end the pass for the others.
            print(f"{name}: not written: {exc}", file=sys.stderr)
            failed.add(name)


def _skipped(name: str, kind: SkipKind, reason: str) -> ProfileReport:
    """The report of a profile no forge comparison could be made for."""
    report = ProfileReport(name=name, entries=[], counts={})
    report.skip(kind, reason)
    return report


def read_selected(
    args: argparse.Namespace, selected: dict, writes: bool
) -> tuple[list[ProfileReport], set[str], set[str], bool]:
    """Every selected profile's pass: the reports, the profiles that failed,
    the profiles it wrote, and whether the pass ran to its end."""
    # A profile that could not be compared or written is not a profile with
    # nothing to review: it stays in every output and fails the run.
    failed: set[str] = set()
    written: set[str] = set()
    reports: list[ProfileReport] = []
    quiet = args.offline or len(selected) < 2
    if not quiet:
        print(
            f"reading {len(selected)} profiles against their forges, a line every "
            f"{PROGRESS_SECONDS} s. --offline answers from the cache alone.",
            file=sys.stderr, flush=True,
        )
    progress = Progress(len(selected), "read", quiet)
    complete = True
    try:
        for name, profile in selected.items():
            progress.step(len(reports), name)
            read_one_profile(args, name, profile, reports, failed, writes, written)
    except KeyboardInterrupt:
        # What was read is still worth printing: a ranking of 200 profiles
        # beats none after 15 minutes.
        print_interrupted(len(reports), len(selected), "the output covers those read")
        complete = False
    return reports, failed, written, complete


def _build_full_report(
    args: argparse.Namespace,
    name: str,
    profile: dict,
    profile_path: Path,
    failed: set[str],
) -> ProfileReport:
    """The report of one profile, with every section the flags ask for.

    A rate limit propagates: the caller decides what one forge's quota
    means for the pass. Any other forge failure becomes a skip.
    """
    try:
        report = build_report(
            name, profile, args.cache_dir, args.offline,
            profile_path.read_text(encoding="utf-8")
            if profile_path.is_file() else None,
        )
    except upstream.RateLimitError:
        raise
    except upstream.NotCachedError as exc:
        # Offline with a cache that never stored this file: the profile
        # is unverified, not wrong. Reporting GONE sent readers after
        # files that exist.
        report = _skipped(name, SkipKind.OFFLINE, f"offline: {exc}")
    except upstream.GoneError as exc:
        # The forge is not coming back: a takedown, or a host that no
        # longer resolves. Saying so once in the summary beats repeating
        # it on stderr every pass, and it keeps the profile out of the
        # backlog, where nobody can act on it anyway.
        report = _skipped(name, SkipKind.GONE, f"upstream gone: {exc}")
    except upstream.UpstreamError as exc:
        # One unreachable forge must not abandon the other profiles.
        print(f"{name}: {exc}", file=sys.stderr)
        report = _skipped(name, SkipKind.UPSTREAM_ERROR, f"upstream error: {exc}")
    if not report.skipped and profile_path.is_file():
        report.stale_prose = _read_stale_prose(name, profile_path, args, failed)
    if args.check_version and profile.get("version_source"):
        report.page_version, report.page_version_unread = page_version(
            profile, args.cache_dir, args.offline
        )
        report.declared_version = page_declared(profile, report.page_version)
        report.no_genuine_copy = str(
            profile["version_source"].get("no_genuine_copy") or "") or None
    if args.check_version:
        _attach_version(args, profile, report)
    _attach_detection(
        profile, report, args.cache_dir, args.offline,
        args.detect_new_files, args.watch_hashes,
    )
    return report


def emit_reports(
    args: argparse.Namespace,
    selected: dict,
    reports: list[ProfileReport],
    shown: list[ProfileReport],
) -> bool | None:
    """Write the reports in the form the flags ask for. False when the
    triage was cut short."""
    if args.as_json and args.triage:
        # The ranking travels in the report: each row carries its score,
        # worst first, for a reader that cannot parse the table.
        scoring = score_reports(args, selected, shown)
        print(json.dumps([scored_to_dict(item) for item in scoring.ranked], indent=2))
        return scoring.complete
    if args.as_json:
        print(json.dumps([report_to_dict(r) for r in shown], indent=2))
        return None
    if args.markdown:
        target = Path(args.report_dir) / f"profile-sync-{date.today().isoformat()}.md"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(format_markdown(shown), encoding="utf-8")
        print(f"written: {target}")
        return None
    if args.fetch_plan:
        for report in shown:
            for url in fetch_plan(report):
                print(url)
        return None
    if args.triage:
        return print_triage(args, selected, shown)
    for report in shown:
        print(format_report(report, args.changed_only))
        print_extras(args, report)
        print()
    if args.changed_only:
        _print_elided(reports, len(shown), frozenset(report.name for report in shown))
    return None


def _print_elided(
    reports: list[ProfileReport], printed: int, listed: frozenset[str] = frozenset()
) -> None:
    """Account for what --changed-only left out, grouped by reason."""
    reasons: dict[str, int] = {}
    for report in reports:
        if report.needs_review() or report.name in listed:
            continue
        key = report.skipped or "nothing to review"
        reasons[key] = reasons.get(key, 0) + 1
    if not reasons:
        return
    total = sum(reasons.values())
    print(f"{printed} profils listes, {total} non listes:")
    for reason, count in sorted(reasons.items(), key=lambda item: -item[1]):
        print(f"  {count:4d}  {reason}")
