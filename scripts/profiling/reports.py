"""The report of one profile, and its text, markdown and JSON forms."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from core import upstream
from model.sourceref import ANNOTATION_RE, trim_prose
from profiling.anchoring import PartResult, REVIEW_STATUSES
from profiling.versions import VersionReport


@dataclass
class EntryReport:
    name: str
    source_ref: str
    status: str
    parts: list[PartResult]
    kind: str = "ref"
    field: str = ""


@dataclass(frozen=True)
class CitedSource:
    """A cited path in the repository the resolver settled it in, and the
    two revisions that repository is compared at."""

    path: str
    repo: upstream.Repo
    pin: str
    head: str
    # Read at its own revision: on HEAD, or held on the release tag the
    # profile documents. A bump does not move such a repository.
    own_revision: bool = False

    def advances(self) -> bool:
        """Whether a bump moves this repository's pin past what was cited."""
        return self.pin != self.head and not self.own_revision


@dataclass
class ProfileReport:
    name: str
    repo: str | None = None
    repos: list[str] = field(default_factory=list)
    pinned_tag: str | None = None
    # Set when pinned_tag carries a pin_frozen reason rather than a tag name.
    pin_frozen: bool = False
    host: str | None = None
    pin: str | None = None
    pin_origin: str | None = None
    head: str | None = None
    entries: list[EntryReport] = field(default_factory=list)
    skipped: str | None = None
    counts: dict[str, int] = field(default_factory=dict)
    # Declared repositories whose forge the tool cannot read. They are named
    # rather than dropped: a `source` on an unknown host used to fall back to
    # `upstream` in silence, and a divergence between the two went unseen.
    unread: list[str] = field(default_factory=list)
    # The upstream view when the profile declares one: its pin and HEAD. A
    # recale moves its parts onto upstream HEAD lines, so a bump advances
    # upstream_commit with source_commit, or the profile describes two
    # revisions at once (geolith jg.c drifted 213 -> 221 -> 229).
    upstream_pin: str | None = None
    upstream_head: str | None = None
    upstream_origin: str | None = None
    # The release tag the upstream view is pinned on, when it is one. That
    # view is read at its tag, and a bump leaves upstream_commit there.
    upstream_tag: str | None = None
    # Repositories whose pin is no ancestor of the branch the profile
    # tracks: history was rewritten, or the pin lies on another branch.
    orphaned: list[str] = field(default_factory=list)
    # Repositories the forge answers under another owner/name: renamed or
    # transferred. The redirect is followed in silence, so the move is named
    # and counted as review work, since a renamed project is re-profiled.
    moved_repos: list[str] = field(default_factory=list)
    # A profile off any forge names the page announcing its releases
    # (version_source): the version read there, beside the one declared.
    declared_version: str | None = None
    page_version: str | None = None
    # Why the page gave no version: not cached offline, absent, refused, or
    # the pattern no longer matches. A feed that moved is not a profile
    # without one, and check_freshness reads the difference here.
    page_version_unread: str | None = None
    # An announced version searched for and found only rebuilt or re-signed.
    no_genuine_copy: str | None = None
    # What realign_prose has to settle before a recale or a bump can run:
    # prose written under an older pin. None when not looked at. Counted to
    # review, or the triage read "0 to review" on a profile whose pin could
    # not move (blastem, xenia-edge, lindbergh-loader).
    stale_prose: list[str] | None = None
    # --check-version on a forge: core_version against the latest tag and
    # release, kept on the report so every output carries it.
    version: VersionReport | None = None
    version_warning: str | None = None
    # A forge that refused the version check or the tag ancestry read, kept
    # here so --json carries it as the text report does.
    version_unread: str | None = None
    # --detect-new-files and --watch-hashes, kept on the report so --json
    # carries them to check_freshness. None when not asked. A new file is
    # {path, line, name, since_pin}: since_pin when the pinned revision of
    # the same file does not carry the name. A new hash is {path, kind, value}.
    new_files: list[dict] | None = None
    new_files_elided: dict[str, int] = field(default_factory=dict)
    new_hashes: list[dict] | None = None
    detection_skipped: str | None = None
    # config_reads refs written for a build a platform ships, each read at
    # that build (pin_build) rather than at source_commit: {platform,
    # revision, ref, status, detail}. A status other than BUILD_OK is review
    # work.
    build_refs: list[dict] = field(default_factory=list)
    # Each cited path with the repository holding it, as the resolver
    # settled it: detection, the extras and the triage read the files
    # there. geolith cites jg.c in its GitLab upstream, which the port the
    # profile was read from does not carry. Not part of the JSON form.
    cited_sources: list[CitedSource] = field(default_factory=list)

    # Skips that say the profile cannot be checked as written: a repository
    # that no longer answers, no pin to read, a death the forge contradicts.
    # --strict passed them, and the CI job meant to stop an unchecked profile
    # let a mistyped repository through.
    UNCHECKABLE = (
        "no declared repository answers",
        "no source_commit and no resolvable profiled_date",
        "upstream_gone is declared but the forge answers",
        "upstream gone:",
    )

    def uncheckable(self) -> bool:
        """Whether the skip is a defect of the profile rather than its nature."""
        return bool(self.skipped and self.skipped.startswith(self.UNCHECKABLE))

    def needs_review(self) -> int:
        counts = self.counts or {}
        return (
            sum(counts.get(status, 0) for status in REVIEW_STATUSES)
            + len(self.orphaned)
            + len(self.stale_prose or ())
            + len(self.moved_repos)
            + sum(1 for ref in self.build_refs if ref["status"] != "BUILD_OK")
        )


def triage_state(report: ProfileReport) -> str:
    """One triage line: what to review, the pin to set again named first.

    A pin outside its branch's history or a repository answering under
    another name is fixed before any ref is read: pcem showed as "1 to
    review" for an upstream_commit off the dev branch.
    """
    if report.skipped:
        return report.skipped
    state = f"{report.needs_review()} to review"
    if report.orphaned:
        state += f", {len(report.orphaned)} orphaned pin"
    if report.moved_repos:
        state += f", {len(report.moved_repos)} repository moved"
    stale = len(report.stale_prose or ())
    if stale:
        state += f", {stale} prose under an older pin"
    unchecked = (report.counts or {}).get("UNCHECKED", 0)
    if unchecked:
        state += f", {unchecked} unchecked"
    return state


def _render_span(path: str, start: int | None, end: int | None) -> str:
    if start is None:
        return path
    if end and end != start:
        return f"{path}:{start}-{end}"
    return f"{path}:{start}"


def original_part(part: PartResult) -> str:
    """The part exactly as the profile writes it today."""
    return part.part.raw or _render_span(
        part.part.path, part.part.start, part.part.end
    )


def rendered_part(part: PartResult) -> str:
    """The part rewritten onto its new location, annotation preserved."""
    span = _render_span(part.new_path or part.part.path, part.start, part.end)
    raw = part.part.raw
    if not raw:
        return span
    located = trim_prose(ANNOTATION_RE.sub("", raw).strip())
    # `stella src/emucore/Cart.cxx:120` names the repository the lines are
    # in. The path was read without that word, and a recale wrote it back
    # without it: the attribution went with the old line numbers.
    word, _, rest = located.partition(" ")
    if rest.startswith(f"{part.part.path}:") and word and "/" not in word:
        span = f"{word} {span}"
    if located and located in raw:
        return raw.replace(located, span, 1)
    return span


def _part_line(part: PartResult) -> str:
    detail = part.status
    if part.new_path:
        detail += f" -> {part.new_path}"
    if part.start is not None and part.status != "ANCHORED":
        span = f"{part.start}"
        if part.end and part.end != part.start:
            span += f"-{part.end}"
        detail += f" -> {span}"
    if part.candidates:
        detail += f"  candidats: {', '.join(str(c) for c in part.candidates)}"
    if part.reason:
        detail += f"  ({part.reason})"
    if part.repo:
        detail += f"  [{part.repo}]"
    return f"      {original_part(part)}  {detail}"


def _report_header(report: ProfileReport) -> list[str]:
    """Repository, revisions and version lines heading one report."""
    slugs = " + ".join(report.repos) if report.repos else (report.repo or "")
    lines = [f"{report.name}  {slugs}".rstrip()]
    if report.pin and report.head:
        lines.append(
            f"  {report.pin[:7]} -> {report.head[:7]}   pin: {report.pin_origin}"
        )
    if report.pinned_tag:
        held = (
            f"pin held ({report.pinned_tag})" if report.pin_frozen
            else f"pinned to tag {report.pinned_tag}"
        )
        lines.append(f"  {held}: checked against its own revision, not against HEAD")
    elif report.pin and report.pin == report.head:
        lines.append("  pin is HEAD: checked for self-consistency")
    if report.upstream_tag and not report.pinned_tag:
        lines.append(
            f"  upstream pinned to tag {report.upstream_tag}: checked against "
            "its own revision, not against HEAD"
        )
    lines.extend(f"  not read (unsupported host): {url}" for url in report.unread or [])
    lines.extend(f"  orphaned pin: {line}" for line in report.orphaned)
    lines.extend(f"  moved repository: {line}" for line in report.moved_repos)
    if report.declared_version or report.page_version:
        lines.append(
            f"  version page: declared {report.declared_version or '-'}, "
            f"announced {report.page_version or 'unreadable'}"
            + (f" ({report.page_version_unread})" if report.page_version_unread else "")
            + (" (no genuine copy found)"
               if report.page_version and report.page_version == report.no_genuine_copy
               else "")
        )
    if report.version:
        version = report.version
        lines.append(
            f"  version: declared {version.declared}, "
            f"latest tag {version.latest_tag}, "
            f"latest release {version.latest_release} ({version.release_date})"
        )
    if report.version_unread:
        lines.append(f"  {report.version_unread}")
    if report.version_warning:
        lines.append(f"  {report.version_warning}")
    return lines


def _report_body(report: ProfileReport, changed_only: bool) -> list[str]:
    """Ref, prose and build lines of one report that was read."""
    lines = []
    for entry in report.entries:
        if changed_only and entry.status not in REVIEW_STATUSES:
            continue
        lines.append(f"  {entry.name}  {entry.source_ref}")
        lines.extend(_part_line(part) for part in entry.parts)
    summary = ", ".join(
        f"{count} {status.lower()}" for status, count in sorted(report.counts.items())
    )
    lines.append(f"  {len(report.entries)} refs: {summary}")
    lines.extend(f"  prose under an older pin: {line}" for line in report.stale_prose or ())
    for ref in report.build_refs:
        if changed_only and ref["status"] == "BUILD_OK":
            continue
        detail = f": {ref['detail']}" if ref["detail"] else ""
        lines.append(
            f"  {ref['status']} at {ref['platform']} build "
            f"{ref['revision'][:12] or '-'}  {ref['ref']}{detail}"
        )
    lines.append(f"  {report.needs_review()} to review")
    return lines


def _detection_lines(report: ProfileReport) -> list[str]:
    """--detect-new-files and --watch-hashes findings of one report."""
    lines = []
    if report.detection_skipped:
        lines.append(f"  extras skipped: {report.detection_skipped}")
    lines.extend(
        f"  new file: {item['path']}:{item['line']}  {item['name']}"
        for item in report.new_files or ()
    )
    lines.extend(
        f"  new file: {path}: {elided} further matches not shown"
        for path, elided in report.new_files_elided.items()
    )
    lines.extend(
        f"  new {item['kind']}: {item['path']}  {item['value']}"
        for item in report.new_hashes or ()
    )
    return lines


def format_report(report: ProfileReport, changed_only: bool = False) -> str:
    """Human-readable report for one profile."""
    lines = _report_header(report)
    if report.skipped:
        lines.append(f"  skipped: {report.skipped}")
    else:
        lines.extend(_report_body(report, changed_only))
    return "\n".join(lines + _detection_lines(report))


def report_to_dict(report: ProfileReport) -> dict:
    """Serialisable form of one report."""
    payload = asdict(report)
    del payload["cited_sources"]
    payload["needs_review"] = report.needs_review()
    return payload


def format_markdown(reports: list[ProfileReport]) -> str:
    """Report set as a markdown document."""
    lines = [
        "# profile-sync",
        "",
        "| profile | repository | refs | to review |",
        "|---|---|---|---|",
    ]
    for report in reports:
        if report.skipped:
            lines.append(
                f"| {report.name} | {report.repo or ''} | skipped | {report.skipped} |"
            )
            continue
        lines.append(
            f"| {report.name} | {report.repo} | {len(report.entries)} "
            f"| {report.needs_review()} |"
        )
    for report in reports:
        lines.extend(["", "```", format_report(report), "```"])
    return "\n".join(lines)


def fetch_plan(report: ProfileReport) -> list[str]:
    """Raw URLs at HEAD for the refs that need the code read again."""
    if report.skipped or not report.head or not report.host:
        return []
    owner, _, name = (report.repo or "").partition("/")
    fallback = upstream.make_repo(report.host, owner, name)
    urls = []
    for entry in report.entries:
        if entry.status not in REVIEW_STATUSES:
            continue
        for part in entry.parts:
            url = part.head_url
            if url is None:
                if fallback is None:
                    continue
                path = part.new_path or part.part.path
                url = upstream.raw_url(fallback, report.head, path)
            if part.part.start:
                url += f"#L{part.part.start}"
            urls.append(url)
    return urls
