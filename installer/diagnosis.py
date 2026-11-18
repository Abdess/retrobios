"""Why --check flags a file: where its bytes are, and which cores read it."""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

from installer.from_folders import (
    FOLDER_IN_PLACE,
    SHOWN_CORES,
    _ARCHIVE_SUFFIXES,
    FolderIndex,
    _ZippedLookup,
    _copy_reason,
    _counts_by_folder,
    _known_destinations,
    _place_reason,
)
from installer.host_fs import _is_file
from installer.manifest import GAME_DATA
from installer.paths import _entry_path, shown_path
from installer.platforms import entry_systems
from installer.regions import WORLD_REGION
from installer.text import _plural, shown_lines

if TYPE_CHECKING:
    from installer.from_folders import LocalCopy


def _copies(entry: dict) -> list[dict]:
    """Every copy the list knows for an entry: its own, other cores', the
    platform's declared one."""
    return [entry, *entry.get("alternatives", []), *entry.get("slot_choices", []),
            *entry.get("declared_choices", [])]


# id(manifest) -> (manifest, the cores its entries name), read once per list.
_LISTED_CORES: dict[int, tuple[dict, frozenset]] = {}


def _listed_cores(manifest: dict) -> frozenset:
    """Every core a copy of the list's entries names: the platform's own.

    system_cores reaches every profile, the target rule needing the cores off
    the platform too, and the "read by" line named Recalbox's mame0258 on
    Batocera and BizHawk on RetroArch.
    """
    cached = _LISTED_CORES.get(id(manifest))
    if cached is None or cached[0] is not manifest:
        cores = frozenset(
            core for entry in [*manifest.get("files", []), *manifest.get("omitted_files", [])]
            for copy in _copies(entry) for core in copy.get("cores") or [])
        cached = _LISTED_CORES[id(manifest)] = (manifest, cores)
    return cached[1]


def readers(entry: dict, manifest: dict) -> list[str]:
    """The cores that open an entry: as its copies name them, else the cores
    of its systems that the platform's own list names."""
    named = sorted({core for copy in _copies(entry) for core in copy.get("cores") or []})
    if named:
        return named
    system_cores = manifest.get("system_cores") or {}
    listed = _listed_cores(manifest)
    return sorted({core for system in entry_systems(entry)
                   for core in system_cores.get(system, []) if core in listed})


def opened_line(entry: dict, manifest: dict, bios_path: Path) -> str:
    """Where the emulators read an entry, and which ones: "read by mgba at
    ...", "expected at ..." where the list names none. "opened at" under
    "missing:" read as a file that was opened."""
    try:
        where = _entry_path(bios_path, entry)
    except ValueError:
        where = bios_path / str(entry.get("dest"))
    cores = readers(entry, manifest)
    if not cores:
        return f"expected at {where}"
    shown = ", ".join(cores[:SHOWN_CORES])
    if len(cores) > SHOWN_CORES:
        shown += f" and {len(cores) - SHOWN_CORES} more"
    return f"read by {shown} at {where}"


def _content_owners(files: list[dict]) -> dict[str, list[dict]]:
    """SHA-1 -> the entries one of whose copies holds it, in the list's order."""
    owners: dict[str, list[dict]] = {}
    for other in files:
        for sha1 in dict.fromkeys(held for c in _copies(other) if (held := c.get("sha1"))):
            owners.setdefault(sha1, []).append(other)
    return owners


def _content_owner(
    sha1: str, entry: dict, files: list[dict],
    owners: dict[str, list[dict]] | None = None,
) -> str:
    """Why a file holding sha1 is not the one entry wants, if the list knows."""
    for copy in entry.get("alternatives", []) + entry.get("slot_choices", []):
        if copy.get("sha1") == sha1 and copy.get("cores"):
            return (f"another revision: the copy {', '.join(copy['cores'])} "
                    "reads, not the one this list installs here")
    for copy in entry.get("declared_choices", []):
        if copy.get("sha1") == sha1:
            return ("another revision: the one the platform's own list declares, "
                    "not the one the cores read")
    if owners is None:
        owners = _content_owners(files)
    for other in owners.get(sha1, []):
        if other is entry or other.get("dest") == entry.get("dest"):
            continue
        regions = [r for r in other.get("regions") or [] if r != WORLD_REGION]
        if regions:
            return (f"another region: the contents of {other['dest']} "
                    f"({', '.join(regions)})")
        return f"another file: the contents of {other['dest']}"
    return ""


def _twin_in_place(entry: dict, files: list[dict], bios_path: Path) -> bool:
    """Whether the name a case variant shares with another entry, but for
    the case (bios.col and BIOS.col), is in place."""
    folded = str(entry.get("dest", "")).casefold()
    for twin in files:
        if twin is entry or twin.get("case_variant") or \
                str(twin.get("dest", "")).casefold() != folded:
            continue
        try:
            if _is_file(_entry_path(bios_path, twin)):
                return True
        except ValueError:
            continue
    return False


def _found_elsewhere(
    entry: dict, index: FolderIndex, bios_path: Path, files: list[dict],
    known: set[str], zipped: _ZippedLookup | None = None,
) -> tuple[str, str]:
    """(reason, folder too deep) for an entry missing at its place."""
    dest = str(entry.get("dest", ""))
    if entry.get("case_variant") and _twin_in_place(entry, files, bios_path):
        # A pack is read on Windows and macOS too, where two names that
        # differ only by case are one file: it carries one of the pair. Moving
        # the other copy here would take it from the core that opens it.
        # Only its twin in place says a pack was used: on an empty folder the
        # note named a pack never downloaded and pushed the BIOS files the
        # user looked for into "... and N more".
        return ("a second name the pack leaves out: Windows and macOS see it "
                "as the same file. Run the command without --check to add it"), ""
    name = dest.rsplit("/", 1)[-1]
    sizes = {size for copy in _copies(entry) if isinstance(size := copy.get("size"), int)}
    sha1s = {sha1 for copy in _copies(entry) if (sha1 := copy.get("sha1"))}
    try:
        expected = _entry_path(bios_path, entry)
    except ValueError:
        return "", ""
    same_name = [p for p in index.by_name.get(name.casefold(), []) if p != expected]
    matching = [p for p in same_name if index.size[p] in sizes and index.sha1(p) in sha1s]
    held = set(matching)
    for path in matching or same_name:
        contents = "" if path in held else ", with other contents"
        found = _place_reason(entry, path, index, expected, known, contents)
        if found[0]:
            return found
    above = index.root.parent / dest
    if index.root.parent != index.root and above.is_file():
        return f"one folder too high: it is at {above}", ""
    holder = index.first_holding(sizes, sha1s)
    if holder is not None:
        return _place_reason(entry, holder, index, expected, known)
    if name.casefold().endswith(_ARCHIVE_SUFFIXES):
        return "", ""
    if zipped is None:
        zipped = _ZippedLookup(index, known)
    reason = zipped.reason(name, {expected.parent, index.root})
    if reason:
        return reason, ""
    for path in index.apple_double.get(name.casefold(), []):
        if path.parent == expected.parent:
            return (f"only a Mac's ._ file: {path.name} holds Finder data, not the "
                    f"file itself. Copy {name} again"), ""
    return "", ""


def _wrong_contents(
    entry: dict, path: Path, index: FolderIndex, files: list[dict],
    owners: dict[str, list[dict]] | None = None,
) -> str:
    """Why the file at an entry's place is not the one the list installs."""
    try:
        if path.is_dir():
            return FOLDER_IN_PLACE
        size = path.stat().st_size
        with open(path, "rb") as handle:
            head = handle.read(4)
    except OSError as exc:
        return f"could not be read ({exc.strerror or exc}): its contents are unknown"
    sha1 = index.sha1(path)
    owner = _content_owner(sha1, entry, files, owners)
    if owner:
        return owner
    if head == b"PK\x03\x04" and not str(entry.get("dest", "")).casefold().endswith(".zip"):
        return "still zipped: this file is a ZIP archive, extract what it holds"
    expected = {listed for copy in _copies(entry)
                if isinstance(listed := copy.get("size"), int)}
    if size not in expected:
        want = " or ".join(f"{s:,}" for s in sorted(expected))
        return f"wrong size: {size:,} bytes, the list expects {want}"
    return "same size, other contents: another dump, or a damaged copy"


class Diagnosis(NamedTuple):
    reasons: dict[int, str]
    deep: dict[str, int]


def diagnose(
    missing: list[dict], mismatched: list[dict], files: list[dict], bios_path: Path,
    verified: list[dict] | None = None, index: FolderIndex | None = None,
) -> Diagnosis:
    """The reason --check gives for each file it flags, from what the folder
    holds and what the list records: id(entry) -> reason, and the folders
    holding files too deep with how many. The files the check verified are
    not read again: their SHA-1 is the one the list records."""
    reasons: dict[int, str] = {}
    deep: dict[str, int] = {}
    if not bios_path.is_dir() or not (missing or mismatched):
        return Diagnosis(reasons, deep)
    if index is None:
        index = bios_folder_index(bios_path, files, verified or [])
        if index is None:
            return Diagnosis(reasons, deep)
    known = _known_destinations(files)
    zipped = _ZippedLookup(index, known)
    for entry in missing:
        reason, extra = _found_elsewhere(entry, index, bios_path, files, known, zipped)
        if reason:
            reasons[id(entry)] = reason
        if extra:
            deep[extra] = deep.get(extra, 0) + 1
    owners = _content_owners(files) if mismatched else {}
    for entry in mismatched:
        try:
            path = _entry_path(bios_path, entry)
        except ValueError:
            continue
        reason = _wrong_contents(entry, path, index, files, owners)
        if reason:
            reasons[id(entry)] = reason
    return Diagnosis(reasons, deep)


class CheckHeld(NamedTuple):
    """What check_lines reads besides the list: the files verified, the BIOS
    folder's index and the copies found on this machine."""

    verified: list[dict] | None = None
    bios_index: FolderIndex | None = None
    copies: dict[int, LocalCopy] | None = None


def check_lines(
    missing: list[dict], mismatched: list[dict], files: list[dict], manifest: dict,
    bios_path: Path, every: bool, held: CheckHeld | None = None,
) -> list[str]:
    """The files --check flags, each with why and where its cores read it.

    "missing: scph5501.bin" left a user with the file one folder too deep,
    or still in its ZIP, to guess. A flagged file with a reason is always
    listed, and so is one a folder named with --from holds. Plain missing
    ones stop at ten unless every is set.
    """
    held = held or CheckHeld()
    index = held.bios_index
    found = diagnose(missing, mismatched, files, bios_path, held.verified, index)
    copies = held.copies or {}
    known = _known_destinations(files)
    lines = []
    for extra, count in sorted(found.deep.items(), key=lambda item: -item[1]):
        if count >= 3:
            lines.append(f"  {_plural(count, 'file')} sit too deep, in "
                         f"{bios_path / extra}: move what it holds up into {bios_path}.")
    lines += _check_copy_lines(missing + mismatched, copies, index)
    explained = [e for e in missing if id(e) in found.reasons or id(e) in copies]
    plain = [e for e in missing if id(e) not in found.reasons and id(e) not in copies]
    # A missing file with no more to say is a list: --verbose names each.
    shown = plain if every else []

    def block(label: str, entry: dict) -> list[str]:
        game = " (game data)" if entry.get("category") == GAME_DATA else ""
        rows = [f"    {label}: {entry['dest']}{game}"]
        if id(entry) in found.reasons:
            rows.append(f"      {found.reasons[id(entry)]}")
        copy = copies.get(id(entry))
        if copy is not None and copy.index is index and not copy.misplaced:
            rows.append(f"      a run without --check copies it from {copy.where()}")
        elif copy is not None and copy.index is index:
            where = _copy_reason(entry, copy, bios_path, known)
            if where and where != found.reasons.get(id(entry)):
                rows.append(f"      the right file: {where}")
            rows.append("      a run without --check copies it into place")
        elif copy is not None:
            rows.append(f"      in {shown_path(copy.index.label)}: {copy.where()}")
        rows.append(f"      {opened_line(entry, manifest, bios_path)}")
        return rows

    for entry in mismatched:
        lines += block("wrong copy", entry)
    for entry in explained:
        lines += block("missing", entry)
    for entry in shown:
        lines += block("missing", entry)
    if len(shown) < len(plain) and lines:
        lines.append(f"    ... and {len(plain) - len(shown)} more missing "
                     "(--verbose lists them all)")
    return shown_lines(lines)


def bios_folder_index(
    bios_path: Path, files: list[dict], verified: list[dict],
) -> FolderIndex | None:
    """The BIOS folder read for files misplaced in it. The files the check
    verified are not read again: their SHA-1 is the one the list records.
    An archive the list installs is not unpacked for its members: a MAME
    set holding a ROM a core also reads loose is that core's to open."""
    if not bios_path.is_dir():
        return None
    index = FolderIndex(bios_path)
    for entry in verified:
        if entry.get("sha1"):
            try:
                index.seed(_entry_path(bios_path, entry), entry["sha1"].lower())
            except ValueError:
                continue
    index.sealed = _known_destinations(files)
    index.listed = {str(f.get("dest", "")) for f in files}
    return index


def _check_copy_lines(
    entries: list[dict], copies: dict[int, LocalCopy], bios_index: FolderIndex | None,
) -> list[str]:
    """What --check says a run would copy instead of downloading."""
    fixed = sum(1 for e in entries if id(e) in copies and copies[id(e)].misplaced)
    lines = []
    if fixed:
        verb = "is" if fixed == 1 else "are"
        them = "it" if fixed == 1 else "them"
        lines.append(f"  {fixed} of these files {verb} in the BIOS folder in the wrong place: "
                     f"a run without --check copies {them} where the cores open {them}, and "
                     f"leaves the {'copy' if fixed == 1 else 'copies'} found as "
                     f"{'it is' if fixed == 1 else 'they are'}.")
    for label, count in _counts_by_folder(entries, copies, bios_index):
        them = "it" if count == 1 else "them"
        lines.append(f"  {label} holds {count} of these files: a run without --check "
                     f"copies {them}.")
    return shown_lines(lines)
