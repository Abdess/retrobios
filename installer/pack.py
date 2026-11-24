"""--pack: a pack written for a card a computer fills, from the choice to the parts on disk."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, NamedTuple

from installer.arguments import PACK_NAME_END
from installer.choices import recorded_axes
from installer.console import OUTPUT, detail
from installer.datadirs import install_data_directory
from installer.download import download_files
from installer.events import EVENTS
from installer.filesystems import fat32_drive
from installer.local_copies import plan_local_copies
from installer.host_fs import DRIVE_FULL, _drive_full, _is_dir, _stop
from installer.lists import ListFailure, held_targets, load_targets, targets_file_words
from installer.offline import LOCAL
from installer.pack_source import (
    pack_name_platforms,
    part_file_name,
)
from installer.paths import shown_path
from installer.plan_words import space_remedy
from installer.platforms import PLATFORM_NAMES, TARGET_PLATFORMS, display_name
from installer.space import space_shortfall
from installer.text import _plural, format_size, screen_text

if TYPE_CHECKING:
    from installer.terminal import Terminal
from installer.pack_parts import PackError, PackMember, pack_bound, plan_pack_parts, write_pack


# FAT32 holds no file of 4 GiB or more (its size field is 32 bits). A pack
# that would pass that on such a drive is written in parts of at most this
# many bytes, the margin keeping each well under.
FAT_FILE_LIMIT = 4 * 1024 ** 3 - 1
FAT_PART_BYTES = 4 * 1024 ** 3 - 64 * 1024 ** 2


def pack_default_name(plat: str, narrowed: bool) -> str:
    """<Platform>_BIOS_Pack.zip, with _Custom when the choice narrows the
    list, as generate_pack.py names a narrowed pack."""
    stem = PLATFORM_NAMES.get(plat, plat).replace(" ", "_")
    return f"{stem}{'_Custom' if narrowed else ''}{PACK_NAME_END}"


def pack_path(given: Path, plat: str, narrowed: bool) -> Path:
    """The pack --pack names: the file given, or the default name inside a
    folder given."""
    path = Path(os.path.expanduser(str(given)))
    if _is_dir(path) or str(given).endswith(("/", os.sep)):
        path = path / pack_default_name(plat, narrowed)
    return path.absolute()


def pack_layout(files: list[dict], data_dirs: list[dict]) -> tuple[
        dict[str, tuple[str, int]], list[dict], dict[str, dict]]:
    """Where each file of the choice goes in the pack: the members, by name,
    with their SHA-1 and size, the list manifest.json carries (path, sha1,
    size, systems) of the BIOS files, and the entry each member that no
    data tree holds is fetched as.

    A data tree's files take the path the reader looks under. A BIOS file
    is stored once by its SHA-1: at its dest, a file of another root (the
    save directory, an emulator's folder) under the root's name, and below
    by-sha1/ when another file already holds that name. A BIOS file whose
    bytes a tree holds is read from the tree's member."""
    members: dict[str, tuple[str, int]] = {}
    for entry in data_dirs:
        lead = f"{str(entry.get('dest') or '').rstrip('/')}/" if entry.get("dest") else ""
        for rel, meta in sorted((entry.get("files") or {}).items()):
            members.setdefault(f"{lead}{rel}", (str(meta["sha1"]), int(meta["size"])))
    by_sha1: dict[str, str] = {}
    for name, (sha1, _size) in sorted(members.items()):
        by_sha1.setdefault(sha1, name)
    systems: dict[str, set[str]] = {}
    listed: set[str] = set()
    sources: dict[str, dict] = {}
    for entry in sorted(files, key=lambda f: (str(f.get("root") or ""), str(f["dest"]))):
        sha1 = str(entry["sha1"]).lower()
        systems.setdefault(sha1, set()).update(entry.get("systems") or [])
        if sha1 not in by_sha1:
            root = str(entry.get("root") or "")
            name = f"{root}/{entry['dest']}" if root else str(entry["dest"])
            if name in members:
                name = f"by-sha1/{sha1}/{PurePosixPath(str(entry['dest'])).name}"
            members[name] = (sha1, int(entry["size"]))
            by_sha1[sha1] = name
            sources[name] = entry
        listed.add(by_sha1[sha1])
    rows = []
    for name in sorted(listed):
        sha1, size = members[name]
        row: dict = {"path": name, "sha1": sha1, "size": size}
        if systems.get(sha1):
            row["systems"] = sorted(systems[sha1])
        rows.append(row)
    return members, rows, sources


def pack_install_list(manifest: dict, files: list[dict], omitted: list[dict],
                      data_dirs: list[dict]) -> dict:
    """The platform's list narrowed to the choice, which the pack carries:
    --from-pack with no option installs what the choice kept, the same
    files at the same places."""
    narrowed = {key: value for key, value in manifest.items()
                if key not in ("files", "case_variants", "omitted_files",
                               "data_directories")}
    narrowed["files"] = [entry for entry in files if not entry.get("case_variant")]
    variants = [{key: value for key, value in entry.items() if key != "case_variant"}
                for entry in files if entry.get("case_variant")]
    if variants or "case_variants" in manifest:
        narrowed["case_variants"] = variants
    narrowed["omitted_files"] = list(omitted)
    if data_dirs or "data_directories" in manifest:
        narrowed["data_directories"] = list(data_dirs)
    return narrowed


def pack_manifest(plat: str, install_list: dict, rows: list[dict],
                  targets: dict | None) -> bytes:
    """manifest.json of a pack made here, as --from-pack reads it."""
    records = recorded_axes(install_list.get("files", []),
                            install_list.get("omitted_files", []))
    data: dict = {"platform": plat, "files": rows}
    for key in ("system_titles", "system_names"):
        if install_list.get(key):
            data[key] = install_list[key]
    data["list_records"] = sorted(records)
    if install_list.get("version"):
        data["list_version"] = install_list["version"]
    data["install_list"] = install_list
    if targets is not None:
        data["targets"] = targets
    return json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _pack_targets(plat: str) -> dict | None:
    """The cores per board the pack carries, as a pack built by the
    repository does: the list at hand offline, else the one fetched. None
    for a platform that publishes none, or a list the network did not
    bring. ListFailure for a list this run was given and cannot use."""
    if plat not in TARGET_PLATFORMS:
        return None
    if LOCAL.offline:
        return held_targets(plat)
    try:
        return load_targets(plat)
    except ListFailure as stopped:
        if stopped.problem.fatal:
            raise
        return None


def _pack_event(plat: str, path: Path, members: dict[str, tuple[str, int]],
                parts: list[Path], status: str, message: str, size: int = 0) -> None:
    EVENTS.emit("pack", platform=plat, path=str(path), files=len(members),
                bytes=sum(length for _sha1, length in members.values()), size=size,
                parts=[str(part) for part in parts], status=status, message=message)


def _pack_refused(plat: str, path: Path, words: str, code: int,
                  members: dict[str, tuple[str, int]] | None = None) -> int:
    """Say why no pack is made, the event saying it too: code."""
    print(f"Error: {screen_text(words)}. No pack was written.", file=sys.stderr)
    _pack_event(plat, path, members or {}, [], "failed", f"{words}.")
    return code


def _pack_space_refused(plat: str, path: Path, shortfall: tuple[int, int],
                        members: dict[str, tuple[str, int]]) -> int:
    """No pack for a drive that cannot hold it, refused as a run is for
    space (a no_space event and the shared remedy). The dry run checks too,
    so the plan never offers a pack the run then refuses to write."""
    needed, free = shortfall
    EVENTS.emit("no_space", platform=plat, folder=str(path.parent), bytes_needed=needed,
                bytes_free=free)
    code = _pack_refused(plat, path, f"the drive holding {shown_path(path.parent)} has "
                         f"{format_size(free)} free, and making the pack needs "
                         f"{format_size(needed)}", 2, members)
    remedy = space_remedy(needed - free, plat, None, commands=False)
    print("  " + "\n    ".join(remedy), file=sys.stderr)
    return code


def pack_parts_words(count: int, limit: int | None, fat: bool) -> str:
    """How the pack is written, in one line: whole, or in parts and why."""
    if count == 1:
        return "One ZIP."
    each = f"In {count} parts of at most {format_size(limit or 0)}"
    return f"{each}, as FAT32 holds no file of 4 GB." if fat else f"{each}."


def pack_space_bytes(files: int, bound: int, data_dirs: list[dict]) -> int:
    """What making a pack takes on its drive: the files fetched, the ZIP at
    its largest, and the largest source archive of a data tree, which is
    downloaded whole beside its tree until the tree is read. A pack read
    as the source fetches no archive."""
    archives = [int(entry.get("archive_size") or 0) for entry in data_dirs
                if entry.get("files") and isinstance(entry.get("archive_size"), int)]
    return files + bound + (max(archives, default=0) if LOCAL.pack is None else 0)


def run_pack(args: argparse.Namespace, plat: str, manifest: dict, files: list[dict],
             omitted: list[dict], data_dirs: list[dict], narrowed: bool,
             term: Terminal) -> int:
    """--pack: the choice downloaded into a pack instead of a folder, every
    member checked against its SHA-1 before the ZIP is closed. Returns the
    exit code: 0 once written (or listed with --dry-run), 1 when a file
    could not be had or the pack written, 2 when nothing was tried."""
    path = pack_path(args.pack, plat, narrowed)
    display = display_name(plat, manifest)
    if not path.name.endswith(PACK_NAME_END):
        return _pack_refused(plat, path, f"{path.name} does not end with {PACK_NAME_END}, "
                             "which --from-pack and the parts of a pack read", 2)
    if not _is_dir(path.parent):
        return _pack_refused(plat, path, f"the folder {shown_path(path.parent)} does not "
                             "exist", 2)
    spelled = pack_name_platforms(path.name)
    if spelled and plat not in spelled:
        return _pack_refused(plat, path, f"{path.name} names a pack for "
                             f"{' and '.join(display_name(name) for name in spelled)}, and "
                             f"this one is for {display_name(plat)}", 2)
    members, rows, sources = pack_layout(files, data_dirs)
    if not members:
        return _pack_refused(plat, path, "the choice keeps no file to put in a pack", 2)
    try:
        targets = _pack_targets(plat)
    except ListFailure as stopped:
        failure = stopped.problem
        words = (targets_file_words(failure) if failure.source == "file" else
                 f"the board list for {display} could not be read: {failure.words}")
        return _pack_refused(plat, path, words, failure.fatal, members)
    body = pack_manifest(plat, pack_install_list(manifest, files, omitted, data_dirs), rows,
                         targets)
    planned = [PackMember(name, sha1, size, Path())
               for name, (sha1, size) in sorted(members.items())]
    fat = fat32_drive(path.parent)
    limit = args.split
    if fat and (limit is None and pack_bound(len(body), planned) > FAT_FILE_LIMIT
                or limit is not None and limit > FAT_PART_BYTES):
        limit = FAT_PART_BYTES
    try:
        plan = plan_pack_parts(path.name, len(body), planned, limit)
    except PackError as exc:
        return _pack_refused(plat, path, str(exc), 2, members)
    count = len(plan)
    finals = ([path] if count == 1 else
              [path.with_name(part_file_name(path.name, index, count))
               for index in range(1, count + 1)])
    total = sum(size for _sha1, size in members.values())
    print(f"\nPack for {display}: {_plural(len(members), 'file')} ({format_size(total)}).")
    print(f"Pack: {shown_path(path)}")
    how = pack_parts_words(count, limit, fat and limit == FAT_PART_BYTES)
    if count > 1:
        print(f"  {how}")
    needed = pack_space_bytes(total, pack_bound(len(body), planned), data_dirs)
    shortfall = space_shortfall(path.parent, needed)
    if shortfall is not None:
        return _pack_space_refused(plat, path, shortfall, members)
    if args.dry_run:
        for name in sorted(members):
            detail(f"    {screen_text(name)} ({format_size(members[name][1])})")
        if not OUTPUT.verbose:
            print("  --verbose lists the files.")
        _pack_event(plat, path, members, finals, "planned", how)
        return 0
    staging = Path(tempfile.mkdtemp(prefix=f".{path.name}.", suffix=".staging",
                                    dir=str(path.parent)))
    try:
        return _fill_pack(args, _PackFill(plat, path, body, members, sources, data_dirs,
                                          limit), staging, term)
    except KeyboardInterrupt:
        _stop.set()
        print("\n  Stopped. No pack was written.", file=sys.stderr)
        _pack_event(plat, path, members, [], "failed", "Stopped before the pack was written.")
        return 130
    finally:
        shutil.rmtree(staging, ignore_errors=True)


class _PackFill(NamedTuple):
    """The pack _fill_pack writes: its path, manifest, members and their sources."""

    plat: str
    path: Path
    body: bytes
    members: dict[str, tuple[str, int]]
    sources: dict[str, dict]
    data_dirs: list[dict]
    limit: int | None


def _fill_pack(args: argparse.Namespace, pack: _PackFill, staging: Path,
               term: Terminal) -> int:
    """Fetch every member into staging, then write the pack from it."""
    plat, path, body, members, sources, data_dirs, limit = pack
    staged = [{**{key: value for key, value in entry.items()
                  if key not in ("root", "core_folder", "case_variant")}, "dest": name}
              for name, entry in sorted(sources.items())]
    copies = plan_local_copies(staged, staging, None, LOCAL.folders)
    fetched = sum(int(entry.get("size") or 0) for entry in staged)
    EVENTS.emit("download", platform=plat, files=len(staged), bytes=fetched)
    detail(f"\nDownloading {_plural(len(staged), 'file')} ({format_size(fetched)})...")
    failed, interrupted = download_files(staged, staging, jobs=args.jobs,
                                         verbose=args.verbose, term=term, copies=copies)
    if interrupted:
        raise KeyboardInterrupt
    owners: dict[str, Path] = {}
    trees_failed: list[tuple[str, str]] = []
    for index, entry in enumerate(data_dirs):
        lead = f"{str(entry.get('dest') or '').rstrip('/')}/" if entry.get("dest") else ""
        root = staging / ".trees" / str(index)
        names = [f"{lead}{rel}" for rel in sorted(entry.get("files") or {})]
        owned = [name for name in names if name in members and name not in sources
                 and name not in owners]
        if not owned:
            continue
        detail(f"  {entry.get('ref', 'data')}: {_plural(len(names), 'data file')}...")
        # The pack is rebuilt byte for byte: its tree is the listed one,
        # never what a rolling source serves since.
        counts = install_data_directory({**entry, "rolling": False}, root)
        problem = (str(counts["error"]) if counts["error"]
                   else f"{counts['changed']} changed in its source" if counts["changed"]
                   else f"{counts['absent']} not in its source" if counts["absent"]
                   else "")
        if problem:
            trees_failed.append((str(entry.get("ref", "data")), problem))
            continue
        for name in owned:
            owners[name] = root.joinpath(*PurePosixPath(name).parts)
    if failed or trees_failed:
        lines = [*failed, *trees_failed]
        print(f"\n  {_plural(len(lines), 'file')} could not be had: no pack was written.",
              file=sys.stderr)
        for dest, reason in lines[: None if args.verbose else 5]:
            print(f"    {screen_text(dest)}: {screen_text(str(reason))}", file=sys.stderr)
        if len(lines) > 5 and not args.verbose:
            print(f"    ... and {len(lines) - 5} more (--verbose lists them)", file=sys.stderr)
        _pack_event(plat, path, members, [], "failed",
                    f"{_plural(len(lines), 'file')} could not be had: no pack was written.")
        return 1
    ordered = [PackMember(name, sha1, size,
                          owners[name] if name in owners
                          else staging.joinpath(*PurePosixPath(name).parts))
               for name, (sha1, size) in sorted(members.items())]
    detail(f"\nWriting {path.name}...")
    try:
        result = write_pack(path, body, ordered, limit)
    except (OSError, PackError) as exc:
        words = (DRIVE_FULL if isinstance(exc, OSError) and _drive_full(exc)
                 else exc.strerror if isinstance(exc, OSError) and exc.strerror else str(exc))
        left = exc.left if isinstance(exc, PackError) else []
        after = ("Left behind, to delete: " + ", ".join(shown_path(f) for f in left) + "."
                 if left else "No pack was left behind.")
        print(f"\n  {path.name} could not be written: {screen_text(str(words))}. "
              f"{screen_text(after)}", file=sys.stderr)
        _pack_event(plat, path, members, [], "failed",
                    f"{path.name} could not be written: {words}. {after}")
        return 1
    written = result.files
    for old in result.removed:
        print(f"  Removed the earlier {shown_path(old)}.")
    for old, why in result.kept:
        print(f"  {shown_path(old)}: {why}.")
    size = sum(part.stat().st_size for part in written)
    print(f"\nPack made: {_plural(len(members), 'file')}, {format_size(size)}"
          + (f", in {len(written)} parts" if len(written) > 1 else "") + ".")
    for part in written if len(written) > 1 else []:
        print(f"  {shown_path(part)}")
    print("Install from it on the other device with --from-pack.")
    _pack_event(plat, path, members, written, "written",
                f"{path.name}: {_plural(len(members), 'file')}, every one checked.", size)
    return 0
