"""Files and hashes upstream gained since the pin, and the diffs of cited paths."""

from __future__ import annotations

import argparse
import difflib
import os
import posixpath
import re
import sys

from core import upstream
from core.upstream import CompareResult
from profiling.citations import collect_tokens
from profiling.reports import CitedSource, ProfileReport


FILE_EXTENSIONS = (
    "bin", "rom", "zip", "dat", "bios", "img", "chd", "nvram", "sav",
    "ips", "pal", "fnt",
)

_FILE_RE = re.compile(
    r"[\w./+-]+\.(?:" + "|".join(FILE_EXTENSIONS) + r")\b", re.IGNORECASE
)
_SHA1_RE = re.compile(r"\b[0-9a-fA-F]{40}\b")
_MD5_RE = re.compile(r"\b[0-9a-fA-F]{32}\b")
_CRC_RE = re.compile(r"\b(?:0x)?([0-9a-fA-F]{8})\b")


def declared_names(profile: dict) -> set[str]:
    """Every filename the profile covers, aliases included."""
    names = set()
    for entry in profile.get("files") or []:
        if not isinstance(entry, dict):
            continue
        for value in [entry.get("name", "")] + list(entry.get("aliases") or []):
            if value:
                names.add(os.path.basename(str(value)).casefold())
    return names


def declared_hashes(profile: dict) -> set[str]:
    """Every hash the profile declares."""
    hashes = set()
    for entry in profile.get("files") or []:
        if isinstance(entry, dict):
            hashes.update(collect_tokens(entry))
    return hashes


# Sources where a filename is a string. Outside a literal or a comment,
# `EE.bios` is a config key and `psm_s.pal` a struct field (pcee2).
CODE_SUFFIXES = (
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inc", ".inl",
    ".m", ".mm", ".rs", ".java", ".kt", ".cs", ".swift",
)
_PRINTF_SPEC_RE = re.compile(
    r"[-+ #0]*(?:\d+|\*)?(?:\.\d+)?(?:hh|h|ll|l|z|j|t|L)?[diouxXsScpfFeEgGaA]"
)
_TITLE_WORD_RE = re.compile(r"[A-Z0-9][\w.()&'+-]*")


def _string_literal(line: str, index: int) -> tuple[int, int] | None:
    """Bounds of the double-quoted literal holding index, None outside one."""
    start = None
    position = 0
    while position < len(line):
        char = line[position]
        if char == "\\" and start is not None:
            position += 2
            continue
        if char == '"':
            if start is None:
                start = position + 1
            else:
                if start <= index < position:
                    return start, position
                start = None
        position += 1
    return None


def _in_comment(line: str, index: int) -> bool:
    before = line[:index]
    return "//" in before or "/*" in before or line.lstrip().startswith(("*", "#"))


def file_literal(line: str, start: int, end: int, code: bool) -> str | None:
    """The filename a match stands for, None when it names no file.

    A printf conversion glued to the name is not part of it: sdl2trs writes
    `"%slevel2.rom"` with ROM_PATH in front. A name with spaces is read
    whole: virtualjaguar opens `"Jaguar CD BIOS.rom"`, and the match alone
    was `BIOS.rom`. Such a name is written as a title, so `"Please insert
    bios.bin"` and `"Packing patches.zip"` still yield the file alone. In
    a code file a match outside any string or comment is an identifier and
    names nothing.
    """
    name = line[start:end]
    if start and line[start - 1] == "%":
        spec = _PRINTF_SPEC_RE.match(name)
        if spec:
            name = name[spec.end():]
    literal = _string_literal(line, start)
    if literal is None:
        if code and not _in_comment(line, start):
            return None
    elif literal[1] == end and line[start - 1:start] == " ":
        words = line[literal[0]:start].split() + [name]
        if all(_TITLE_WORD_RE.fullmatch(word) for word in words):
            return line[literal[0]:end]
    base = os.path.basename(name)
    # `".bin.hex.iii.rom"` (sdl2trs) lists extensions, it names no file.
    if base.startswith(".") or not _FILE_RE.fullmatch(base):
        return None
    return base


def detect_new_files(
    head_lines: list[str], known: set[str], cap: int = 25, path: str = ""
) -> tuple[list[tuple[int, str]], int]:
    """Filename literals at HEAD the profile does not declare."""
    found: list[tuple[int, str]] = []
    seen: set[str] = set()
    elided = 0
    code = path.lower().endswith(CODE_SUFFIXES)
    for number, line in enumerate(head_lines, start=1):
        for match in _FILE_RE.finditer(line):
            literal = file_literal(line, match.start(), match.end(), code)
            if literal is None:
                continue
            name = literal.casefold()
            if name in known or name in seen:
                continue
            seen.add(name)
            if len(found) >= cap:
                elided += 1
                continue
            found.append((number, literal))
    return found, elided


def watch_hashes(added_lines: list[str], known: set[str]) -> list[tuple[str, str]]:
    """Hash literals in added lines that no profile entry declares."""
    found: list[tuple[str, str]] = []
    for line in added_lines:
        strong = bool(_SHA1_RE.search(line) or _MD5_RE.search(line))
        for pattern, kind in ((_SHA1_RE, "sha1"), (_MD5_RE, "md5")):
            found.extend(
                (kind, value.lower()) for value in pattern.findall(line)
                if value.lower() not in known
            )
        if strong or not _FILE_RE.search(line):
            continue
        found.extend(
            ("crc32", value.lower()) for value in _CRC_RE.findall(line)
            if value.lower() not in known
        )
    return found


def unified_for_path(
    pin_lines: list[str], head_lines: list[str], path: str, context: int
) -> str:
    """Unified diff of one cited file between the two revisions."""
    diff = difflib.unified_diff(
        pin_lines,
        head_lines,
        fromfile=f"a/{path}",
        tofile=f"b/{path}",
        n=context,
        lineterm="",
    )
    return "\n".join(diff)


def tree_diff(result: CompareResult, ref_dirs: set[str]) -> list[str]:
    """Tree changes restricted to the directories the refs point at."""
    lines = []
    for change in result.files:
        directory = posixpath.dirname(change.path)
        if ref_dirs and not any(
            directory == d or directory.startswith(d + "/") for d in ref_dirs
        ):
            continue
        if change.status == "renamed" and change.previous_path:
            lines.append(f"renamed  {change.previous_path} -> {change.path}")
        else:
            lines.append(f"{change.status}  {change.path}")
    if result.truncated:
        lines.append("comparison truncated by the forge, list is partial")
    return lines


def _scan_source(
    source: CitedSource, names: set[str], known: set[str],
    cache_dir: str, offline: bool, files: bool, hashes: bool,
) -> tuple[list[dict], int, list[dict]] | None:
    """Undeclared names and added hash literals of one cited file, None when
    its repository does not carry it at HEAD."""
    path = source.path
    head_lines = upstream.fetch_file(source.repo, source.head, path, cache_dir, offline)
    if head_lines is None:
        return None
    pin_lines = upstream.fetch_file(source.repo, source.pin, path, cache_dir, offline) or []
    found_files: list[dict] = []
    elided = 0
    found_hashes: list[dict] = []
    if files:
        found, elided = detect_new_files(head_lines, names, path=path)
        at_pin = {
            name.casefold()
            for _, name in detect_new_files(
                pin_lines, names, cap=sys.maxsize, path=path
            )[0]
        }
        found_files = [
            {"path": path, "line": number, "name": name,
             "since_pin": name.casefold() not in at_pin}
            for number, name in found
        ]
    if hashes:
        added = [
            line
            for line in difflib.unified_diff(pin_lines, head_lines, n=0)
            if line.startswith("+") and not line.startswith("+++")
        ]
        found_hashes = [
            {"path": path, "kind": kind, "value": value}
            for kind, value in watch_hashes(added, known)
        ]
    return found_files, elided, found_hashes


def detect_upstream_changes(
    profile: dict, report: ProfileReport,
    cache_dir: str, offline: bool, files: bool, hashes: bool,
) -> None:
    """Record on the report the undeclared names (files) and the hash
    literals added since the pin (hashes) of the cited files at HEAD, each
    read in the repository the resolver settled it in."""
    names, known = declared_names(profile), declared_hashes(profile)
    found_files: list[dict] = []
    found_hashes: list[dict] = []
    # A path two repositories carry is read in both: a name or a hash the
    # first already listed for that path is not listed again.
    listed_files: set[tuple[str, str]] = set()
    listed_hashes: set[tuple[str, str, str]] = set()
    for source in report.cited_sources:
        scanned = _scan_source(source, names, known, cache_dir, offline, files, hashes)
        if scanned is None:
            continue
        new_files, elided, new_hashes = scanned
        found_files.extend(
            item for item in new_files
            if (item["path"], item["name"].casefold()) not in listed_files
        )
        found_hashes.extend(
            item for item in new_hashes
            if (item["path"], item["kind"], item["value"]) not in listed_hashes
        )
        listed_files.update((item["path"], item["name"].casefold()) for item in new_files)
        listed_hashes.update((item["path"], item["kind"], item["value"]) for item in new_hashes)
        if elided:
            report.new_files_elided.setdefault(source.path, elided)
    if files:
        report.new_files = found_files
    if hashes:
        report.new_hashes = found_hashes


def print_extras(
    args: argparse.Namespace, report: ProfileReport
) -> None:
    """--full-diff and --tree-diff, read from the forge after the ref report.

    The ref report mutes a forge that refuses, but the extras read the same
    forge again, so a refusal here is reported on the profile's own line
    instead of ending a pass over every profile. A quota signal still
    ends the profile.
    """
    if not (args.full_diff or args.tree_diff) or not report.cited_sources:
        return
    try:
        _print_extras_from(args, report)
    except upstream.RateLimitError:
        raise
    except upstream.UpstreamError as exc:
        print(f"  extras skipped: {exc}")


def _print_extras_from(args: argparse.Namespace, report: ProfileReport) -> None:
    if args.full_diff:
        for source in report.cited_sources:
            if args.ref and args.ref not in source.path:
                continue
            pin_lines = upstream.fetch_file(
                source.repo, source.pin, source.path, args.cache_dir, args.offline
            ) or []
            head_lines = upstream.fetch_file(
                source.repo, source.head, source.path, args.cache_dir, args.offline
            ) or []
            text = unified_for_path(pin_lines, head_lines, source.path, args.context)
            if text:
                print(text)
    if args.tree_diff:
        by_repo: dict[tuple[str, str], list[CitedSource]] = {}
        for source in report.cited_sources:
            by_repo.setdefault((source.repo.host, source.repo.slug), []).append(source)
        for sources in by_repo.values():
            first = sources[0]
            comparison = upstream.compare(
                first.repo, first.pin, first.head, args.cache_dir, args.offline
            )
            if len(by_repo) > 1:
                print(f"  {first.repo.slug}:")
            # The repository root is a directory like any other: dropping
            # the empty dirname would turn the filter off and list the
            # whole tree.
            ref_dirs = {posixpath.dirname(source.path) for source in sources}
            for line in tree_diff(comparison, ref_dirs):
                print(f"  {line}")
