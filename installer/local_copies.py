"""The copies a run takes from --from folders: where each goes, why, and what could not be read."""

from __future__ import annotations

import os
from pathlib import Path

from installer.events import EVENTS
from installer.folder_index import FolderIndex, LocalCopy
from installer.paths import _entry_path, _safe_relative_path, shown_path
from installer.tally import _bytes
from installer.text import _plural, format_size, screen_text, shown_lines


def _known_destinations(files: list[dict]) -> set[str]:
    return {str(f.get("dest", "")).casefold() for f in files}


def _place_reason(
    entry: dict, path: Path, index: FolderIndex, expected: Path, known: set[str],
    contents: str = "",
) -> tuple[str, str]:
    """(reason, folder too deep) for an entry's file found at path in the
    BIOS folder, or ("", "") when that place says nothing. contents is
    ", with other contents" for a file of the right name and wrong bytes."""
    dest = str(entry.get("dest", ""))
    name = dest.rsplit("/", 1)[-1]
    rel = index.relative(path)
    # A dest below the save directory is not below this folder: a copy
    # here under the same tail is in the wrong place, not too deep.
    below = entry.get("root") != "save"
    if below and rel.endswith("/" + dest) and path.name == name:
        extra = rel[: -len(dest) - 1]
        top = index.root.name
        if extra.casefold() == top.casefold():
            return (f"nested folder: it is at {top}/{rel}{contents}, a "
                    f"{top} folder inside {top}"), extra
        depth = extra.count("/") + 1
        levels = "one folder" if depth == 1 else f"{depth} folders"
        return f"{levels} too deep: it is at {rel}{contents}", extra
    if path.name.casefold() == name.casefold():
        if path.parent == expected.parent and path.name != name:
            return (f"case of the name: the folder holds {path.name}{contents}, "
                    f"the cores open {name}"), ""
        return f"wrong folder: it is at {rel}{contents}", ""
    if contents:
        return "", ""
    if rel.casefold() in known:
        return f"its contents are at {rel}: copy that file to {dest}", ""
    return f"a name no core opens: its contents are at {rel}, rename it {name}", ""


def _copy_reason(entry: dict, copy: LocalCopy, bios_path: Path, known: set[str]) -> str:
    """Why a copy found in the BIOS folder is not at the entry's place."""
    if not copy.misplaced:
        # np2kai/2608_bd.wav and np2/2608_bd.wav hold the same bytes. Told
        # "wrong folder", a user moved np2's copy and broke that core.
        return f"the same file is at {copy.where()}, where the list installs it too"
    if copy.member:
        return f"still zipped: it is inside {copy.index.relative(copy.path)}"
    try:
        copy.path.relative_to(copy.index.root)
    except ValueError:
        return f"one folder too high: it is at {copy.path}"
    try:
        expected = _entry_path(bios_path, entry)
    except ValueError:
        return ""
    return _place_reason(entry, copy.path, copy.index, expected, known)[0]


def _above(entry: dict, index: FolderIndex) -> LocalCopy | None:
    """The entry's file at its place one folder above the BIOS folder."""
    if entry.get("root") == "save" or index.root.parent == index.root:
        return None
    try:
        above = index.root.parent / _safe_relative_path(entry.get("dest"), "dest")
        if above.stat().st_size != entry.get("size") or not above.is_file():
            return None
    except (OSError, ValueError):
        return None
    algorithm = "sha1" if entry.get("sha1") else "sha256"
    if index.digest(above, algorithm) != str(entry.get(algorithm, "")).lower():
        return None
    return LocalCopy(index, above)


def plan_local_copies(
    entries: list[dict], bios_path: Path, bios_index: FolderIndex | None,
    folders: list[FolderIndex],
) -> dict[int, LocalCopy]:
    """id(entry) -> where this machine already holds the entry's bytes: the
    BIOS folder itself first, a file misplaced in it, then each folder named
    with --from in turn. Every copy is found by size, then by hash."""
    if not entries or (bios_index is None and not folders):
        return {}
    # A file this run replaces is no source: its place is being written.
    written = set()
    for entry in entries:
        try:
            written.add(Path(os.path.realpath(_entry_path(bios_path, entry))))
        except ValueError:
            continue
    for index in ([bios_index] if bios_index is not None else []) + folders:
        index.writes(written)
    copies: dict[int, LocalCopy] = {}
    for entry in entries:
        copy = None
        if bios_index is not None:
            copy = bios_index.find(entry, written) or _above(entry, bios_index)
            if copy is not None:
                copy = LocalCopy(copy.index, copy.path, copy.member,
                                 _misplaced(entry, copy, bios_index))
        for index in folders:
            if copy is not None:
                break
            copy = index.find(entry, written)
        if copy is not None:
            copies[id(entry)] = copy
    return copies


def _misplaced(entry: dict, copy: LocalCopy, index: FolderIndex) -> bool:
    """Whether a copy in the BIOS folder sits where no other entry of the
    list goes: GBA_BIOS.BIN for gba_bios.bin is a mistake, np2/2608_bd.wav
    for np2kai/2608_bd.wav is the other core's file."""
    if copy.member:
        return True
    rel = index.relative(copy.path)
    if rel in index.listed:
        return False
    own = str(entry.get("dest", "")).casefold()
    return rel.casefold() not in index.sealed or rel.casefold() == own


def _counts_by_folder(
    entries: list[dict], copies: dict[int, LocalCopy], bios_index: FolderIndex | None,
) -> list[tuple[str, int]]:
    """(folder, files) for each --from folder that gives some of entries."""
    counts: dict[str, int] = {}
    for entry in entries:
        copy = copies.get(id(entry))
        if copy is not None and copy.index is not bios_index:
            counts[copy.index.label] = counts.get(copy.index.label, 0) + 1
    return list(counts.items())


def copy_plan_lines(
    entries: list[dict], copies: dict[int, LocalCopy], bios_index: FolderIndex | None,
    bios_path: Path, files: list[dict], every: bool, planned: bool,
) -> list[str]:
    """The files a run copies from this machine, by folder: the misplaced
    ones with the reason each was not where its cores open it."""
    known = _known_destinations(files)
    # By --from folder, "" for the misplaced files and "=" for the ones the
    # BIOS folder holds at another entry's place.
    groups: dict[str, list[dict]] = {}
    for entry in entries:
        copy = copies.get(id(entry))
        if copy is not None:
            key = (copy.index.label if copy.index is not bios_index
                   else "" if copy.misplaced else "=")
            groups.setdefault(key, []).append(entry)
    lines = []
    for key in sorted(groups, key=lambda k: (k != "", k != "=")):
        chosen = groups[key]
        sized = f"{_plural(len(chosen), 'file')} ({format_size(_bytes(chosen))})"
        if key == "":
            head = (f"Would fix {sized} misplaced in the BIOS folder, copied where the "
                    "cores open them:" if planned else
                    f"Fixing {sized} misplaced in the BIOS folder: copied where the cores "
                    "open them, the copies found left as they are.")
        elif key == "=":
            head = (f"Would copy {sized} the BIOS folder already holds at another "
                    "place of the list:" if planned else
                    f"{sized} the BIOS folder already holds at another place of the list:")
        else:
            head = (f"Would copy {sized} from {shown_path(key)}:" if planned else
                    f"{sized} found in {shown_path(key)}, each one checked by hash:")
        lines.append(f"\n  {head}" if planned else f"  {head}")
        for entry in chosen if every else chosen[:10]:
            copy = copies[id(entry)]
            why = (_copy_reason(entry, copy, bios_path, known) if key == ""
                   else f"from {copy.where()}" if key == "=" else copy.where())
            lines.append(f"    {entry['dest']}: {why}" if why else f"    {entry['dest']}")
        if len(chosen) > 10 and not every:
            lines.append(f"    ... and {len(chosen) - 10} more (--verbose lists them all)")
    return shown_lines(lines)


def emit_copies(
    plat: str, entries: list[dict], copies: dict[int, LocalCopy],
    bios_index: FolderIndex | None, bios_path: Path, files: list[dict],
) -> None:
    """One found event per file this machine holds, before it is copied."""
    known = _known_destinations(files)
    for entry in entries:
        copy = copies.get(id(entry))
        if copy is None:
            continue
        reason = (_copy_reason(entry, copy, bios_path, known)
                  if copy.index is bios_index else "")
        EVENTS.emit("found", platform=plat, dest=entry["dest"], folder=copy.index.label,
                    path=str(copy.path), member=copy.member, reason=reason)


class Unreadable:
    """A file, ZIP member or folder below a --from folder that could not be
    read, and may be a file the run still needs."""

    def __init__(self, index: FolderIndex, path: Path, member: str, why: str) -> None:
        self.index = index
        self.path = path
        self.member = member
        self.why = why

    def line(self) -> str:
        where = f"{self.member} inside {self.path}" if self.member else str(self.path)
        return screen_text(f"{where} could not be read: {self.why}")


def unreadable_copies(
    entries: list[dict], copies: dict[int, LocalCopy], folders: list[FolderIndex],
) -> list[Unreadable]:
    """What the --from folders hold that could not be read, of the size of
    a file no copy was found for, or of no known size: dropped silently,
    a file a user had read as one to download."""
    sizes = {e["size"] for e in entries
             if id(e) not in copies and isinstance(e.get("size"), int)}
    if not sizes:
        return []
    return [Unreadable(index, *held) for index in folders
            for held in index.unreadable_for(sizes)]


def unreadable_lines(found: list[Unreadable], every: bool) -> list[str]:
    lines = [f"  {item.line()}" for item in (found if every else found[:10])]
    if len(found) > len(lines):
        lines.append(f"  ... and {len(found) - len(lines)} more could not be read "
                     "(--verbose lists them all)")
    return shown_lines(lines)


def emit_unreadable(plat: str, found: list[Unreadable]) -> None:
    for item in found:
        EVENTS.emit("unreadable", platform=plat, folder=item.index.label,
                    path=str(item.path), member=item.member, reason=item.why)
