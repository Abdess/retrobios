#!/usr/bin/env python3
"""Cross-reference emulator profiles against platform configs.

Identifies BIOS files that emulators need but platforms don't declare,
providing gap analysis for extended coverage.

Usage:
    python scripts/cross_reference.py
    python scripts/cross_reference.py --emulator dolphin
    python scripts/cross_reference.py --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import zipfile
import zlib
from collections import Counter
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from alternatives import set_keys, set_requirements, settle_sets
from common import (
    OUTER_ROOTS,
    platform_arg,
    ProfileSelectionError,
    _foreign_tree,
    _norm_system_id,
    _owner_tokens,
    archive_entry,
    directory_members,
    expand_directory_entries,
    get_mame_clone_map,
    list_emulator_profiles,
    list_registered_platforms,
    merged_platform_declared_contents,
    load_data_dir_registry,
    load_database,
    load_emulator_profiles,
    load_platform_config,
    content_fits,
    name_match_size_ok,
    parse_md5_list,
    require_platform,
    require_yaml,
    resolve_local_file,
    platform_layouts,
    system_dir_path,
    standalone_set,
    select_emulator_profiles,
)
from hashing import parse_hash_list
from launchers import (
    LauncherLayer,
    bound_launchers,
    catalogued_model_files,
    declared_destinations,
    held_record,
    launcher_unproven,
    name_settings,
    set_by,
    setting_readers,
    suffixed_stem,
)
from launchers import _directories as launcher_directories
from launchers import _names as launcher_names
from validation import (
    case_folded_slots,
    declaration_settles,
    inner_rom_check,
    installed_with_emulator,
    outside_gap_scope,
    read_from_save_dir,
    unread_on,
    with_archive_members,
)

yaml = require_yaml()

DEFAULT_EMULATORS_DIR = "emulators"
DEFAULT_PLATFORMS_DIR = "platforms"
DEFAULT_DB = "database.json"


def load_platform_files(
    platforms_dir: str,
    platforms: list[str] | None = None,
) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Collect declared filenames + data_directories per system.

    Restricted to *platforms* when given, otherwise every registered platform.
    Keyed by the normalized system ID: a profile writes `sega-megacd` where
    RetroArch writes `sega-mega-cd`, and an exact match called 924 declared
    files undeclared.
    """
    declared = {}
    platform_data_dirs = {}
    for platform_name in platforms or list_registered_platforms(
        platforms_dir
    ):
        config = load_platform_config(platform_name, platforms_dir)
        for sys_id, system in config.get("systems", {}).items():
            for fe in system.get("files", []):
                name = fe.get("name", "")
                if name:
                    declared.setdefault(_norm_system_id(sys_id), set()).add(name)
            for dd in system.get("data_directories", []):
                ref = dd.get("ref", "")
                if ref:
                    platform_data_dirs.setdefault(_norm_system_id(sys_id), set()).add(ref)
    return declared, platform_data_dirs


def declared_names(
    platforms_dir: str, platforms: list[str] | None, db: dict
) -> dict[str, list[tuple[int | None, str]]]:
    """Every name the platforms declare, with each declaration's size and slot.

    The report judged "undeclared" per normalized system id, which does not
    bring bk and elektronika-bk, or nintendo-sgb and nintendo-super-game-boy,
    together: 646 entries whose exact name a platform declares were counted
    undeclared, while verify and the site read one flat index.
    """
    from common import merged_platform_declarations

    return merged_platform_declarations(
        [
            load_platform_config(platform_name, platforms_dir)
            for platform_name in platforms or list_registered_platforms(
                platforms_dir
            )
        ],
        db,
    )


def folded_declared_slots(
    platforms_dir: str, platforms: list[str] | None, db: dict
) -> frozenset[str]:
    """The slots platforms whose filesystem folds case fill, any spelling.

    RetroBat's 32X_G_BIOS.BIN is the file BlastEm opens as 32X_G_BIOS.bin,
    and the exact-case name test called it undeclared.
    """
    from common import platform_declarations

    slots: set[str] = set()
    for platform_name in platforms or list_registered_platforms(
        platforms_dir
    ):
        config = load_platform_config(platform_name, platforms_dir)
        slots |= case_folded_slots(config, platform_declarations(config, db))
    return frozenset(slots)


def _build_supplemental_index(
    data_root: str = "data", bios_root: str = "bios"
) -> set[str]:
    """Build a set of filenames and directory names in data/ and inside bios/ ZIPs.

    A directory is indexed only with its trailing slash: a bare name matched a
    file entry of the same name, and BasiliskII's required `ROM` read as held
    because cpcemu keeps a directory called ROM.
    """
    names: set[str] = set()
    root_path = Path(data_root)
    if root_path.is_dir():
        for fpath in root_path.rglob("*"):
            if fpath.name.startswith("."):
                continue
            if fpath.is_file():
                names.add(fpath.name)
                names.add(fpath.name.lower())
            else:
                names.add(fpath.name + "/")
                names.add(fpath.name.lower() + "/")
            if fpath.is_dir():
                # Also index relative path from data/subdir/ for directory entries
                parts = fpath.relative_to(root_path).parts
                if len(parts) > 1:
                    rel = "/".join(parts[1:])
                    names.add(rel + "/")
                    names.add(rel.lower() + "/")
    bios_path = Path(bios_root)
    if bios_path.is_dir():
        # Index directory names for directory-type entries (e.g., "nestopia/samples/moepro/")
        for dpath in bios_path.rglob("*"):
            if dpath.is_dir() and not dpath.name.startswith("."):
                names.add(dpath.name + "/")
                names.add(dpath.name.lower() + "/")
        names |= _zip_member_names(bios_path)
    return names


def _zip_member_names(bios_path: Path) -> set[str]:
    """Basenames of the files inside every ZIP under bios/, both cases."""
    import zipfile

    names: set[str] = set()
    for zpath in bios_path.rglob("*.zip"):
        try:
            with zipfile.ZipFile(zpath) as zf:
                members = [m for m in zf.namelist() if not m.endswith("/")]
        except (zipfile.BadZipFile, OSError) as exc:
            print(f"  WARNING: unreadable archive {zpath}: {exc}", file=sys.stderr)
            continue
        for member in members:
            basename = member.rsplit("/", 1)[-1]
            names.update((basename, basename.lower()))
    return names


def _resolve_source(
    fname: str,
    by_name: dict[str, list],
    by_name_lower: dict[str, str],
    data_names: set[str] | None = None,
    by_path_suffix: dict | None = None,
    file_entry: dict | None = None,
    db_files: dict | None = None,
    bios_dir: str | None = None,
) -> str | None:
    """Return the source category for a file, or None if not found.

    Returns ``"bios"`` (in database.json / bios/), ``"data"`` (in data/),
    or ``None`` (not available anywhere).

    A name hit whose size contradicts a size the emulator verifies is not the
    file, so it does not count as available. Nor is one whose bytes carry
    none of the hashes the entry declares: a name never wins over a declared
    hash, and zquestclassic's ending.mid read as held because Hydra Castle
    Labyrinth has another file of that name.

    Another casing of the name in another emulator's tree proves nothing, as
    in resolve_local_file's case-insensitive step: dosbox-x's et4000.bin read
    as held through pcem's et4000.BIN, which the pack and the installer
    refuse it.
    """
    declared = _declared_content(file_entry or {})
    owners = _owner_tokens(file_entry or {})

    def _can_be(sha1s: list | str) -> bool:
        if not file_entry or db_files is None:
            return True
        if not isinstance(sha1s, list):
            sha1s = [sha1s]
        return any(
            name_match_size_ok(file_entry, db_files.get(sha1, {}).get("size"))
            and content_fits(file_entry, db_files.get(sha1, {}).get("path", ""))
            and _record_carries(sha1, db_files.get(sha1, {}), declared)
            for sha1 in sha1s
        )

    def _name_hit(name: str) -> bool:
        """Whether the files indexed under *name* can be this entry."""
        return _can_be(by_name.get(name) or [])

    def _folded_hit(name: str) -> bool:
        """_name_hit for a name matched in another casing."""
        return _can_be([
            sha1 for sha1 in by_name.get(name) or []
            if db_files is None
            or not _foreign_tree(db_files.get(sha1, {}).get("path", ""), owners)
        ])

    # bios/ via database.json by_name
    if fname in by_name and _name_hit(fname):
        return "bios"
    stripped = fname.rstrip("/")
    basename = stripped.rsplit("/", 1)[-1] if "/" in stripped else None
    if basename and basename in by_name and _name_hit(basename):
        return "bios"
    key = fname.lower()
    if key in by_name_lower and _folded_hit(by_name_lower[key]):
        return "bios"
    if basename:
        if basename.lower() in by_name_lower and _folded_hit(
            by_name_lower[basename.lower()]
        ):
            return "bios"
    # bios/ via by_path_suffix (regional variants)
    if by_path_suffix and fname in by_path_suffix and _can_be(by_path_suffix[fname]):
        return "bios"
    # bios/ under the canonical MAME set name, as resolve_local_file does:
    # a renamed archive is held once, under the name the dedup kept.
    canonical = get_mame_clone_map(bios_dir).get(fname)
    if canonical and canonical != fname:
        if canonical in by_name and _name_hit(canonical):
            return "bios"
        if canonical.lower() in by_name_lower and _folded_hit(
            by_name_lower[canonical.lower()]
        ):
            return "bios"
    if data_names and _data_hit(fname, basename, file_entry, data_names):
        return "data"
    return None


def _data_hit(
    fname: str, basename: str | None, file_entry: dict | None, data_names: set[str]
) -> bool:
    """Whether data/ or a ZIP holds the name: a directory entry looks for a
    directory, a file entry for a file. A file entry that declares a hash is
    held only by a copy carrying it: touchhle's LiberationMono-Regular.ttf
    read as held because idtech4a++'s extras.zip has another font of that
    name."""
    looked_up = [fname, fname.lower()] + ([basename, basename.lower()] if basename else [])
    if fname.endswith("/") or (file_entry or {}).get("type") == "directory":
        looked_up = [name.rstrip("/") + "/" for name in looked_up]
        return any(name in data_names for name in looked_up)
    if not any(name in data_names for name in looked_up):
        return False
    declared = _declared_content(file_entry or {})
    if not declared:
        return True
    return any(
        _content_matches(location, declared)
        for location in _supplemental_locations().get((basename or fname).lower(), ())
    )


_HASH_FIELDS = ("sha1", "md5", "sha256", "crc32")


def _record_carries(sha1: str, record: dict, declared: dict[str, set[str]]) -> bool:
    """Whether a database record has one of the declared hashes, or none is declared."""
    if not declared:
        return True
    actual = {
        "sha1": sha1.lower(),
        **{field: str(record.get(field) or "").lower() for field in ("md5", "sha256", "crc32")},
    }
    return any(
        actual[field] and actual[field] in values
        for field, values in declared.items()
    )


def _declared_content(file_entry: dict) -> dict[str, set[str]]:
    """The hashes an entry declares, lowercased, by algorithm."""
    declared: dict[str, set[str]] = {}
    for field in _HASH_FIELDS:
        found = set(parse_hash_list(file_entry.get(field)))
        if found:
            declared[field] = found
    return declared


_locations_cache: dict[tuple[str, str], dict[str, list[tuple[str, str]]]] = {}


def _supplemental_locations(
    data_root: str = "data", bios_root: str = "bios"
) -> dict[str, list[tuple[str, str]]]:
    """Where each name of the supplemental index sits: a data/ file, or a
    member of a ZIP under bios/, keyed by lowercased basename."""
    key = (data_root, bios_root)
    if key in _locations_cache:
        return _locations_cache[key]
    found: dict[str, list[tuple[str, str]]] = {}
    root = Path(data_root)
    if root.is_dir():
        for path in root.rglob("*"):
            if path.is_file() and not path.name.startswith("."):
                found.setdefault(path.name.lower(), []).append((str(path), ""))
    for zpath in Path(bios_root).rglob("*.zip") if Path(bios_root).is_dir() else ():
        try:
            with zipfile.ZipFile(zpath) as zf:
                members = [m for m in zf.namelist() if not m.endswith("/")]
        except (zipfile.BadZipFile, OSError) as exc:
            print(f"  WARNING: unreadable archive {zpath}: {exc}", file=sys.stderr)
            continue
        for member in members:
            found.setdefault(member.rsplit("/", 1)[-1].lower(), []).append(
                (str(zpath), member)
            )
    _locations_cache[key] = found
    return found


def _content_matches(location: tuple[str, str], declared: dict[str, set[str]]) -> bool:
    """Whether the file or member at *location* carries a declared hash."""
    path, member = location
    try:
        if member:
            with zipfile.ZipFile(path) as zf:
                if set(declared) == {"crc32"}:
                    return f"{zf.getinfo(member).CRC:08x}" in declared["crc32"]
                data = zf.read(member)
        else:
            data = Path(path).read_bytes()
    except (zipfile.BadZipFile, KeyError, OSError) as exc:
        print(f"  WARNING: cannot read {path} {member}: {exc}", file=sys.stderr)
        return False
    actual = {
        "sha1": hashlib.sha1(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "crc32": f"{zlib.crc32(data) & 0xFFFFFFFF:08x}",
    }
    return any(actual[field] in values for field, values in declared.items())


_tree_cache: dict[tuple[str, str], list[str]] = {}


def _trees(data_root: str, bios_root: str) -> list[str]:
    """Every directory under data/ and bios/, as a path with a trailing slash."""
    key = (data_root, bios_root)
    if key not in _tree_cache:
        _tree_cache[key] = sorted(
            f"{path.as_posix()}/"
            for root in (data_root, bios_root) if Path(root).is_dir()
            for path in Path(root).rglob("*")
            if path.is_dir()
            and not any(p.startswith(".") for p in path.relative_to(root).parts)
        )
    return _tree_cache[key]


def held_copy(
    entry: dict, data_root: str = "data", bios_root: str = "bios"
) -> tuple[str, str] | None:
    """The data/ file, directory or bios/ ZIP member holding an entry.

    The database indexes the files under bios/, and an entry held otherwise
    (specmate.rom as a member of spectrum_opus.zip, Dolphin's fonts in its
    data directory) read as held with no word of where. Returns (path,
    member), the member empty for a file or a directory. A file entry that
    declares a hash is held only by a copy carrying it, as _data_hit judges.
    """
    names = [entry.get("name", ""), entry.get("path") or "", *(entry.get("aliases") or [])]
    names = [str(n) for n in names if n]
    if entry.get("type") == "directory" or any(n.endswith("/") for n in names[:1]):
        for name in names:
            tail = "/" + name.strip("/") + "/"
            for tree in _trees(data_root, bios_root):
                if tree.endswith(tail):
                    return tree, ""
        return None
    declared = _declared_content(entry)
    locations = _supplemental_locations(data_root, bios_root)
    for name in names:
        for location in locations.get(name.rsplit("/", 1)[-1].lower(), ()):
            if not declared or _content_matches(location, declared):
                return location
    return None


class FileConsumers:
    """Who reads each collected file, joined through the resolver.

    The site joined database files to emulators and platforms by bare name:
    each of the four pak0.pk3 of four games was attributed to every engine
    reading a pak0.pk3. A consumer here is an entry that resolves to the
    file by the evidence the pack uses, so a homonym is nobody's file.
    """

    def __init__(
        self, db: dict, zip_contents: dict | None = None,
        data_dir_registry: dict | None = None,
    ) -> None:
        self._db = db
        self._zip_contents = zip_contents
        # The builder resolves with the data trees: Dolphin's codehandler.bin
        # comes from data/dolphin-sys, and without them the name step gave it
        # Dolphin-MMJR's copy, which the site then said Dolphin reads.
        self._data_dir_registry = (
            data_dir_registry if data_dir_registry is not None
            else load_data_dir_registry(
                str(Path(__file__).resolve().parent.parent / DEFAULT_PLATFORMS_DIR)
            )
        )
        self._sha1_by_path = {
            path: sha1
            for sha1, entry in db.get("files", {}).items()
            for path in {entry.get("path", ""), *entry.get("paths", [])}
            if path
        }
        self.platforms: dict[str, set[str]] = {}
        # Under which of its systems each platform declares a file, so a
        # link can land on that section rather than the page top.
        self.platform_systems: dict[str, dict[str, set[str]]] = {}
        # Where each platform puts the file in its BIOS directory.
        self.platform_destinations: dict[str, dict[str, set[str]]] = {}
        self.emulators: dict[str, set[str]] = {}
        # The entry that reads each file, by its position in the profile's
        # files: a link lands on that entry's card, not the page top.
        self.emulator_entries: dict[str, dict[str, int]] = {}
        self.emulator_files: dict[str, list] = {}
        # Where each platform's pack installs the file, its cores' files
        # included: the platform's own list names a fraction of them.
        self.installed: dict[str, dict[str, set[str]]] = {}

    def sha1_of(self, entry: dict, dest: str = "", owner: str = "") -> str | None:
        """The collected file an entry resolves to, or None.

        A profile entry names its owner, as the builder does: without it the
        name step chose another tree's copy, and the page credited the file
        the pack does not ship.
        """
        if not entry.get("name"):
            return None
        if owner:
            entry = {**entry, "source_profile": owner}
        path, status = resolve_local_file(
            entry, self._db, self._zip_contents, dest_hint=dest,
            data_dir_registry=self._data_dir_registry,
        )
        if not path or status == "not_found":
            return None
        # Batocera pins naomi2.zip by the md5 of a ROM inside it: the resolver
        # hands back the archive as a mismatch, and the member settles it as
        # the builder does.
        if status == "hash_mismatch" and not (
            entry.get("zipped_file") and inner_rom_check(entry, path) == "ok"
        ):
            return None
        return self._sha1_by_path.get(path)

    def add_platforms(self, configs: dict[str, dict]) -> None:
        for name, config in configs.items():
            for system_id, system in config.get("systems", {}).items():
                for entry in system.get("files", []):
                    # No destination hint, as the builder, the manifest and
                    # verify resolve a declaration: with one, RetroBat's 63
                    # mame/hash lists credited another revision than the one
                    # its manifest installs.
                    sha1 = self.sha1_of(entry)
                    if sha1:
                        self.platforms.setdefault(sha1, set()).add(name)
                        self.platform_systems.setdefault(sha1, {}).setdefault(
                            name, set()
                        ).add(system_id)
                        where = str(entry.get("destination") or entry["name"])
                        # EmuDeck matches by md5 alone: its entries carry a
                        # system:md5 key, not a place in the folder.
                        if ":" not in where:
                            self.platform_destinations.setdefault(sha1, {}).setdefault(
                                name, set()
                            ).add(where)

    def add_manifests(self, install_dir: str | Path) -> None:
        """Read what each install manifest places, alternatives included."""
        for path in sorted(Path(install_dir).glob("*.json")):
            try:
                manifest = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                print(f"WARNING: {path}: {exc}", file=sys.stderr)
                continue
            platform = str(manifest.get("platform") or path.stem)
            for entry in manifest.get("files") or []:
                for sha1 in {entry.get("sha1"), *(
                    alt.get("sha1") for alt in entry.get("alternatives") or []
                )} - {None, ""}:
                    self.installed.setdefault(sha1, {}).setdefault(
                        platform, set()).add(str(entry.get("dest", "")))

    def sha1_at(self, path: str) -> str | None:
        """The file the database records at a collection path."""
        return self._sha1_by_path.get(path)

    def path_of(self, sha1: str) -> str:
        """The collection path the database records for a file."""
        return str(self._db.get("files", {}).get(sha1, {}).get("path", ""))

    def directory_members(self, entry: dict) -> dict[str, str]:
        """{destination: sha1} of the files a ``type: directory`` entry reads."""
        if entry.get("type") != "directory":
            return {}
        return {
            member["path"]: member["sha1"]
            for member in expand_directory_entries([entry], self._db)
            if member is not entry
        }

    def add_emulators(self, profiles: dict[str, dict]) -> None:
        """Each file a profile entry resolves to, a directory's members included.

        A directory entry was resolved by its own name and found nothing:
        11,976 files under alephone's Plugins/, cdogs' and thextech's trees
        named no emulator on their card.
        """
        for name, profile in profiles.items():
            if profile.get("type") == "alias":
                continue
            files = profile.get("files") or []
            self.emulator_files[name] = files
            # A file a profile names keeps its own entry over the directory
            # that also holds it.
            order = sorted(
                (i for i, entry in enumerate(files) if isinstance(entry, dict)),
                key=lambda i: files[i].get("type") == "directory",
            )
            for index in order:
                entry = files[index]
                members = self.directory_members(entry)
                if members:
                    found = [
                        self.sha1_of({**entry, "name": dest, "path": dest, "sha1": sha1},
                                     dest, owner=name)
                        for dest, sha1 in members.items()
                    ]
                else:
                    found = [self.sha1_of(*entry_target(entry, files), owner=name)]
                for sha1 in found:
                    if sha1:
                        self.emulators.setdefault(sha1, set()).add(name)
                        self.emulator_entries.setdefault(sha1, {}).setdefault(name, index)


def entry_target(entry: dict, files: list[dict]) -> tuple[dict, str]:
    """The entry a profile entry resolves through, and its destination.

    A ROM read inside an archive is the archive: FBNeo opens sm1.sm1 in
    neogeo.zip, and resolved by its crc32 it credited a loose copy FBNeo
    never opens, while no neogeo.zip card named FBNeo. The archive
    members the profile reads decide between same-named copies, as in
    the emulator pack and verify.
    """
    if entry.get("archive"):
        return archive_entry(entry["archive"], files), ""
    return with_archive_members(entry, files), entry.get("path") or ""


def entry_source(f: dict, index: dict) -> str | None:
    """Where the collection holds a profile entry, or None.

    By name, path and alias, then by any hash the entry declares. The gap
    report and the site pages read this one function, so a file is held or
    missing in the same way on both.
    """
    by_name, by_name_lower = index["by_name"], index["by_name_lower"]
    data_names, by_path_suffix = index.get("data_names"), index["by_path_suffix"]
    db_files = index["db_files"]
    fname = f.get("name", "")
    path_field = f.get("path") or ""
    # A directory is held when the collection holds files under it, the rule
    # the pack and verify --emulator expand it by: a bare-name lookup missed
    # cdogs' .wolf3d/, whose 695 files every pack carries.
    if f.get("type") == "directory" and directory_members(
        {"indexes": {"by_path_suffix": by_path_suffix}}, path_field or fname
    ):
        return "bios"
    found = None
    for candidate in [fname, *([path_field] if path_field != fname else []),
                      *(f.get("aliases") or [])]:
        if not candidate:
            continue
        source = _resolve_source(
            candidate, by_name, by_name_lower, data_names, by_path_suffix, f, db_files,
            index.get("bios_dir"),
        )
        if source == "bios":
            return source
        found = found or source

    def values(field: str) -> list[str]:
        return parse_hash_list(f.get(field))

    # The declared content anywhere in bios/ comes before a data/ copy, as in
    # the resolver: the hash steps run before the data directories.
    held = (
        any(index["by_md5"].get(v) for v in parse_md5_list(f.get("md5")))
        or any(v in db_files for v in values("sha1"))
        # rust_dos names its SC-55 ROMs by sha256 alone
        or any(v in index["by_sha256"] for v in values("sha256"))
        or any(index["by_crc32"].get(v) for v in values("crc32"))
    )
    return "bios" if held else found


def _resolve_archive_source(
    archive_name: str,
    by_name: dict[str, list],
    by_name_lower: dict[str, str],
    data_names: set[str] | None = None,
    by_path_suffix: dict | None = None,
) -> str:
    """Resolve source for an archive (ZIP) name, returning a source category string."""
    result = _resolve_source(
        archive_name, by_name, by_name_lower, data_names, by_path_suffix,
    )
    return result if result is not None else "missing"


def _first_hash(entry: dict) -> str:
    """The first hash an entry declares, strongest first, or ''."""
    for field in ("sha1", "sha256", "md5", "crc32"):
        value = entry.get(field)
        if isinstance(value, list):
            value = value[0] if value else ""
        if value:
            return f"{field}:{str(value).lower()}"
    return ""


def slot_key(f: dict, standalone: bool = False) -> tuple:
    """The slot a profile entry fills: its entries on one slot are the
    versions its code accepts there, and holding any of them fills it.

    The path is the one the running build reads: b2's standalone build
    reads MOS 3.20 and 3.50 from two directories, two slots, while the
    entries share a name and no `path:`."""
    fname = f.get("name", "")
    where = (f.get("standalone_path") if standalone else None) or f.get("path")
    return (
        fname,
        f.get("archive"),
        system_dir_path(f, where or fname),
        f.get("system"),
        f.get("selection_slot"),
        f.get("mode", "both"),
        read_from_save_dir(f, standalone),
    )


# Why an entry is left out of the comparison, in the order they are printed.
SET_ASIDE = {
    "other_versions": "other versions of a slot",
    "not_read": "not read on this platform",
    "outside_scope": "outside the pack",
    "launcher": "filled by the platform's launcher",
}


def profile_breakdown(data: dict) -> str:
    """Where each entry of a profile went, adding up to its file count.

    The heading said 261 files, 7 declared and 238 undeclared, and the 16
    others were nowhere: the versions a slot accepts, the entries the
    platform never opens and the ones no pack carries.
    """
    # A report built without the per-entry tally (a fixture, a saved --json
    # of an earlier run) falls back to its row counts.
    parts = [f"{data.get('declared_files', data['platform_covered'])} declared by platforms",
             f"{data.get('undeclared_files', data['gaps'])} undeclared"]
    unsourceable = data.get("unsourceable_files", len(data.get("unsourceable") or []))
    if unsourceable:
        parts.append(f"{unsourceable} unsourceable")
    aside = data.get("set_aside") or {}
    detail = [f"{aside[key]} {label}" for key, label in SET_ASIDE.items() if aside.get(key)]
    if detail:
        parts.append(f"{sum(aside.values())} set aside ({', '.join(detail)})")
    return ", ".join(parts)


def _cross_reference_profile(
    emu_name: str,
    profile: dict,
    declared: dict[str, set[str]],
    report: dict,
    index: dict,
    standalone_cores: set[str] | None = None,
    platform: str = "",
) -> None:
    """Compare one emulator profile against what the platforms declare.

    *platform* is the platform key under --platform, empty for the whole
    tree. It decides, through the functions verify reads, which entries the
    platform's launcher never opens and which ones its emulator package
    already installs.

    Split out of cross_reference, where it was a 200-line loop body that
    carried the whole function's branching: every file is resolved by name,
    by path, by hash and by archive membership before it can be called a
    gap. *index* carries the database lookups those steps share.
    """
    by_name = index["by_name"]
    by_name_lower = index["by_name_lower"]
    by_path_suffix = index["by_path_suffix"]
    data_names = index["data_names"]
    all_declared = index["all_declared"]
    emu_files = profile.get("files", [])
    systems = profile.get("systems", [])

    # Skip filename-agnostic profiles (BIOS detected without fixed names)
    if profile.get("bios_mode") == "agnostic":
        return

    if all_declared is not None:
        platform_names = all_declared
    else:
        platform_names = set()
        for sys_id in systems:
            platform_names.update(declared.get(_norm_system_id(sys_id), set()))

    # The build a platform runs decides which entries it reads, as in
    # find_undeclared_files: without a platform, the libretro build.
    layouts = platform_layouts(emu_name, profile, standalone_cores or set())
    # Each file under each layout the platform gives the emulator: both, for
    # one it launches as a libretro core and standalone.
    layout_files = [(f, standalone) for view, standalone in layouts for f in view.get("files", [])]
    gaps = []
    covered = []
    unsourceable_list: list[dict] = []
    archive_gaps: dict[tuple, dict] = {}
    seen_files: set[tuple] = set()

    # The entries of one profile on one slot are the versions its code
    # accepts there (raze's ten DUKE3D.GRP): holding any of them fills the
    # slot, as verify --emulator credits it.
    versions: dict[tuple, list[dict]] = {}
    for f, is_standalone in layout_files:
        versions.setdefault(slot_key(f, is_standalone), []).append(f)

    # What became of each entry, so the heading adds up: a file a platform
    # declares, one it does not, or one set aside and why. An entry read by
    # two builds keeps the first answer that compares it. Each layout lists
    # the profile's entries in their order, so a position names one entry.
    position = {id(f): i for view, _ in layouts for i, f in enumerate(view.get("files", []))}
    fates: dict[int, str] = {}
    # Grouped entries met, as (set keys, entry, fills, the list holding
    # its row, the row): settled once the profile is read.
    set_records: list[tuple[tuple, dict, bool, list | None, dict | None]] = []
    archive_rows: list[dict] = []

    def fate(f: dict, what: str) -> None:
        key = position[id(f)]
        current = fates.get(key)
        if current is None or (current in SET_ASIDE and what not in SET_ASIDE):
            fates[key] = what

    for f, is_standalone in layout_files:
        fname = f.get("name", "")
        # The destination the running build reads, as find_undeclared_files
        # takes it: Batocera's standalone Cemu reads keys.txt at
        # standalone_path, and the libretro Cemu/keys.txt reported here
        # settled the declaration on a slot the platform never fills.
        save_root = read_from_save_dir(f, is_standalone)
        if is_standalone:
            effective_path = f.get("standalone_path") or f.get("path") or fname
        elif save_root:
            effective_path = f.get("path") or fname
        else:
            effective_path = system_dir_path(f, f.get("path") or fname)
        slot = slot_key(f, is_standalone)
        seen_key = slot
        if len(layouts) > 1:
            # One file read at one path by both builds counts once.
            seen_key = (effective_path.casefold(), seen_key)
        if not fname:
            fate(f, "outside_scope")
            continue
        if seen_key in seen_files:
            fate(f, "other_versions")
            continue
        if unread_on(f, platform):
            fate(f, "not_read")
            continue

        # Collect unsourceable files separately (documented, not a gap)
        unsourceable_reason = f.get("unsourceable", "")
        keys = set_keys((emu_name, is_standalone), f)
        if unsourceable_reason:
            seen_files.add(seen_key)
            fate(f, "unsourceable")
            row = {
                "name": fname,
                "required": f.get("required", False),
                "reason": unsourceable_reason,
                "source_ref": f.get("source_ref", ""),
            }
            unsourceable_list.append(row)
            set_records.append((keys, f, False, unsourceable_list, row))
            continue

        if outside_gap_scope(f, is_standalone):
            fate(f, "outside_scope")
            continue

        archive = f.get("archive")

        # Check platform declaration: by name, by an alias the core answers
        # to (RetroArch lists amiberry's cd32.rom as kick40060.CD32), or by
        # archive.
        # A platform declares files of its BIOS tree: none answers for one
        # the core reads below the save directory.
        in_platform = not save_root and f.get("root") not in OUTER_ROOTS and declaration_settles(
            f, fname, platform_names, effective_path, index.get("folded_slots", frozenset()),
            index.get("declared_contents"),
        )

        if in_platform:
            seen_files.add(seen_key)
            fate(f, "declared")
            set_records.append((keys, f, True, None, None))
            covered.append({
                "name": fname,
                "path": effective_path,
                "required": f.get("required", False),
                "in_platform": True,
            })
            continue

        seen_files.add(seen_key)
        fate(f, "undeclared")

        if archive:
            archive_key = (
                archive,
                f.get("system"),
                f.get("selection_slot"),
                f.get("mode", "both"),
            )
            if archive_key not in archive_gaps:
                source = _resolve_archive_source(
                    archive, by_name, by_name_lower, data_names,
                    by_path_suffix,
                )
                archive_gaps[archive_key] = {
                    "name": archive,
                    "path": archive,
                    "required": False,
                    "note": "",
                    "source_ref": "",
                    "in_platform": False,
                    "in_repo": source != "missing",
                    "source": source,
                    "archive": archive,
                    "archive_file_count": 0,
                    "archive_required_count": 0,
                }
            entry = archive_gaps[archive_key]
            if entry["archive_file_count"] == 0:
                # The archive's own declaration names its sets: an archive
                # is a member like a loose file (Kronos' stvbios.zip).
                own = archive_entry(archive, emu_files)
                set_records.append((
                    set_keys((emu_name, is_standalone), own), own,
                    entry["in_repo"], archive_rows, entry,
                ))
                archive_rows.append(entry)
            entry["archive_file_count"] += 1
            if f.get("required", False):
                entry["archive_required_count"] += 1
                entry["required"] = True
            if not entry["source_ref"] and f.get("source_ref"):
                entry["source_ref"] = f["source_ref"]
            continue

        # --- resolve source provenance ---
        # A release asset is held when the database records it, as any other
        # file: storage says where the bytes are served from, not that the
        # collection has them (kenji-nx's user-picked firmware package).
        source = next(
            (
                found for version in versions[slot]
                if (found := entry_source(
                    {**version, "source_profile": emu_name}, index,
                )) is not None
            ),
            "missing",
        )
        if source != "missing" and f.get("storage", "") in ("release", "large_file"):
            source = "large_file"

        in_repo = source != "missing"

        entry = {
            "name": fname,
            "path": effective_path,
            "required": f.get("required", False),
            "bundled": installed_with_emulator(f, platform),
            "note": f.get("note", ""),
            "source_ref": f.get("source_ref", ""),
            "in_platform": False,
            "in_repo": in_repo,
            "source": source,
            # What tells this file from a homonym another emulator wants.
            "identity": _first_hash(f),
        }
        if save_root:
            entry["root"] = "save"
        elif f.get("unplaced"):
            entry["unplaced"] = f["unplaced"]
        elif f.get("root") in OUTER_ROOTS:
            entry["root"] = f["root"]
        elif index.get("launcher_candidates") is not None:
            # What verify hands the launcher layer for the same entry.
            probe = {
                **f,
                "profile": emu_name,
                "emulator": profile.get("emulator", emu_name),
                "path": effective_path,
                "in_repo": in_repo,
                "bundled": entry["bundled"],
            }
            index["launcher_candidates"].append(
                (emu_name, is_standalone, f, probe, entry)
            )
        gaps.append(entry)
        set_records.append((keys, f, in_repo, gaps, entry))

    # One need per set: a member another one fills is not a gap, and a set
    # nobody holds is one gap under its first member (alternatives.py), as
    # verify and the packs count it.
    # Archive units rank first among equals, as the builder orders them.
    grouped = sorted(
        (r for r in set_records if r[0]), key=lambda r: r[3] is not archive_rows
    )
    requirements = set_requirements(profile)
    excused, standing = settle_sets(
        [(keys, f, fills) for keys, f, fills, _l, _r in grouped],
        lambda key: requirements.get(key[1], True),
    )
    for at, (_keys, member, _fills, rows, set_row) in enumerate(grouped):
        if set_row is None or rows is None:
            continue
        if at in standing:
            set_row["alternatives"] = standing[at].others
            set_row["required"] = standing[at].required
        if at in excused:
            rows.remove(set_row)
            if id(member) in position:
                fates[position[id(member)]] = "other_versions"

    for ag in sorted(archive_gaps.values(), key=lambda e: e["name"]):
        if any(ag is row for row in archive_rows):
            gaps.append(ag)

    tally = Counter(fates.values())
    report[emu_name] = {
        "emulator": profile.get("emulator", emu_name),
        "systems": systems,
        "total_files": len(emu_files),
        "platform_covered": len(covered),
        **_gap_counts(gaps),
        "gap_details": gaps,
        "unsourceable": unsourceable_list,
        # Entries, not rows: an archive's members are one gap row.
        "declared_files": tally["declared"],
        "undeclared_files": tally["undeclared"],
        "unsourceable_files": tally["unsourceable"],
        "set_aside": {key: tally[key] for key in SET_ASIDE},
    }


def _gap_counts(gaps: list[dict]) -> dict[str, int]:
    """The per-source tallies of a profile's gap rows."""
    return {
        "gaps": len(gaps),
        "gap_in_repo": sum(1 for g in gaps if g["in_repo"]),
        "gap_missing": sum(1 for g in gaps if g["source"] == "missing"),
        "gap_bios": sum(1 for g in gaps if g["source"] == "bios"),
        "gap_data": sum(1 for g in gaps if g["source"] == "data"),
        "gap_large_file": sum(1 for g in gaps if g["source"] == "large_file"),
    }


def _settle_launcher_places(
    report: dict,
    candidates: list[tuple[str, bool, dict, dict, dict]],
    layer: LauncherLayer,
    db: dict,
) -> None:
    """Apply the platform's launcher places as find_undeclared_files does.

    Batocera's DuckStation generator fills the PAL slot with scph5502.bin,
    yet the report listed duckstation's scph1002a.bin as a file the pack
    carries, which neither the pack nor the manifest does.
    """
    added, settled = layer.settle(
        [(emu, standalone, f, probe) for emu, standalone, f, probe, _ in candidates],
        lambda probe: held_record(probe, db),
    )
    for emu, _standalone, _f, probe, gap in candidates:
        if id(probe) not in settled:
            continue
        data = report[emu]
        data["gap_details"] = [g for g in data["gap_details"] if g is not gap]
        data["undeclared_files"] -= 1
        data["set_aside"]["launcher"] += 1
    for entry in added:
        data = report[entry["profile"]]
        data["gap_details"].append({
            "name": entry["name"],
            "path": entry["path"],
            "required": entry.get("required", False),
            "bundled": False,
            "note": "",
            "source_ref": "",
            "in_platform": False,
            "in_repo": True,
            "source": "bios",
            "identity": entry.get("sha1") or "",
            "launcher": entry["launcher"],
            "launcher_of": entry["launcher_of"],
        })
    for data in report.values():
        data.update(_gap_counts(data["gap_details"]))


# The --json key of the launcher reads category, beside the emulator keys.
LAUNCHER_READS_KEY = "_launcher_reads_not_held"
# The --json key of the launcher records a config file does not prove.
LAUNCHER_UNPROVEN_KEY = "_launcher_unproven"

# A package record names no file: it records what a package builds.
_NAMELESS_KINDS = frozenset({"package"})

# The folder of the platform's own launcher, as its scraper spells it: a
# program the launcher runs from there (RetroBat's xbox-iso-vfs.exe) is part
# of the platform, never a file to collect.
PLATFORM_OWN_FOLDERS = frozenset({"<emulatorLauncher folder>"})


def launcher_file_names(record: dict) -> list[str]:
    """The concrete file names a launcher record reads, in code order.

    The names are read as the launcher layer reads them (`launchers._names`):
    a label after the name is dropped ("neocd_z.rom (CDZ)"), and a name with
    `<` or without an extension is not a file name (a folder the record
    links, an option value such as hatari2014's "default"). A name with a
    `{X}` placeholder is a template: Batocera's hatari tries tos{L}.img for
    every language and ROCKNIX links one memory card per slot and region,
    so its expansions say which variants the code accepts, not which file is
    owed. A wildcard is a pattern the emulator matches. `search_dir` is a
    folder and never a name, whatever the kind.
    """
    if record.get("kind") in _NAMELESS_KINDS:
        return []
    return [
        name for name in launcher_names({**record, "expands": {}}) if "*" not in name
    ]


def _profile_names(profiles: dict[str, dict]) -> tuple[dict[str, list[dict]], dict[str, list[dict]]]:
    """Profile entries by each name and alias they answer to, exact and folded."""
    exact: dict[str, list[dict]] = {}
    folded: dict[str, list[dict]] = {}
    for profile in profiles.values():
        if profile.get("type") in ("launcher", "alias"):
            continue
        for entry in profile.get("files") or []:
            names = {str(entry.get("name") or "")} | {str(a) for a in entry.get("aliases") or []}
            for name in names - {""}:
                base = name.rsplit("/", 1)[-1]
                exact.setdefault(base, []).append(entry)
                folded.setdefault(base.casefold(), []).append(entry)
    return exact, folded


class _NameHolder:
    """Whether the collection holds a file under a launcher name.

    A name is held when database.json carries a file under it or under an
    alias it indexes, when a profile entry that answers to the name (as its
    name or an alias) resolves, or when resolve_local_file finds it in a data
    directory. The database answers for files kept as release assets, absent
    from a checkout. A copy known only under another casing is returned
    apart: a launcher that matches names exactly does not open it.
    """

    def __init__(
        self, db: dict, profiles: dict[str, dict], data_dir_registry: dict | None
    ) -> None:
        self.db = db
        self.registry = data_dir_registry
        files = db.get("files", {})
        self.by_name = {
            name: sha1s
            for name, sha1s in db.get("indexes", {}).get("by_name", {}).items()
            if any(sha1 in files for sha1 in sha1s)
        }
        self.by_name_folded: dict[str, list[str]] = {}
        for name in self.by_name:
            self.by_name_folded.setdefault(name.casefold(), []).append(name)
        self.exact, self.folded = _profile_names(profiles)
        self._cache: dict[str, tuple[str, bool] | None] = {}

    def _entry_held(self, entry: dict) -> bool:
        names = [str(entry.get("name") or "")] + [str(a) for a in entry.get("aliases") or []]
        if any(n.rsplit("/", 1)[-1] in self.by_name for n in names if n):
            return True
        path, _status = resolve_local_file(entry, self.db, data_dir_registry=self.registry)
        return path is not None

    def held(self, name: str) -> tuple[str, bool] | None:
        """The name the collection holds *name* under, and whether its casing is exact."""
        if name in self._cache:
            return self._cache[name]
        base = name.rsplit("/", 1)[-1]
        found: tuple[str, bool] | None = None
        stem = suffixed_stem(base)
        if base in self.by_name or any(map(self._entry_held, self.exact.get(base, []))):
            found = (base, True)
        elif stem is not None and any(map(self._entry_held, self.exact.get(stem, []))):
            found = (base, True)
        else:
            path, _status = resolve_local_file(
                {"name": name}, self.db, data_dir_registry=self.registry
            )
            if path is not None:
                found = (Path(path).name, Path(path).name == base)
            elif base.casefold() in self.by_name_folded:
                found = (self.by_name_folded[base.casefold()][0], False)
            else:
                entry = next(
                    (e for e in self.folded.get(base.casefold(), []) if self._entry_held(e)),
                    None,
                )
                if entry is not None:
                    found = (str(entry.get("name") or ""), False)
        self._cache[name] = found
        return found


def launcher_reads_not_held(
    configs: dict[str, dict],
    db: dict,
    profiles: dict[str, dict],
    data_dir_registry: dict | None = None,
    emulator: str = "",
) -> list[dict]:
    """The file names a platform's launch code reads that the collection lacks.

    One row per platform and name, with every record that reads it. A
    launcher that matches case-insensitively, or runs on a filesystem that
    folds case, is satisfied by a copy under another casing. Elsewhere such
    a copy is reported with `held_as`, since the launcher does not open it
    under the name it asks for. *emulator* keeps the records whose emulator
    name designates that profile.

    Three records ask for nothing the collection lacks. A search keeps the
    first name it finds, so one held name fills it: RetroBat's Amiberry
    launcher returns the first of kick34005.A500, kick34005.A500.rom and
    amiga-os-130.rom that exists (Amiberry.Generator.cs:674-699). A copy
    whose source lies outside the BIOS directory brings a file the platform
    installs itself, from its own package or written by its own script
    (RetroPie's lr-vecx copies $md_inst/system.bin), and so does a program
    the launcher runs from its own folder. A file handed to the
    setting a reader's profile entry is read from is that entry's file,
    which the pack places under the launcher's name.
    """
    holder = _NameHolder(db, profiles, data_dir_registry)
    every_profile = set(profiles)
    rows: list[dict] = []
    for platform, config in configs.items():
        by_key: dict[str, dict] = {}
        # A record resting on a config file it cannot prove reads nothing
        # yet: it is reported apart (launcher_unproven).
        for record in bound_launchers(config, profiles):
            names = launcher_file_names(record)
            if not names:
                continue
            readers = sorted({
                key
                for part in str(record.get("emulator", "")).split(",")
                for key in LauncherLayer._profiles_named(part.strip(), profiles, every_profile)
            })
            if not readers:
                # RetroDECK names its frontend and the core option names the core.
                readers = setting_readers(
                    str(record.get("passes_to") or ""), profiles, every_profile
                )
            if emulator and emulator not in readers:
                continue
            folds = bool(record.get("case_insensitive") or config.get("case_insensitive_fs"))
            base = str(config.get("base_destination") or "bios")
            if record.get("kind") == "copies" and not launcher_directories(record, base):
                continue
            if str(record.get("search_dir") or "") in PLATFORM_OWN_FOLDERS:
                continue
            settings = name_settings(record, names)

            def by_setting(name: str) -> bool:
                """Whether the setting the name is written to reads a held file.

                A placeholder read from the setting takes the held dump the
                catalogues name after the model the launcher's name spells.
                """
                entries = [
                    entry
                    for key in readers
                    for entry in profiles[key].get("files") or []
                    if settings[name] and set_by(entry, settings[name])
                ]
                return any(holder._entry_held(entry) for entry in entries) or any(
                    "<" in str(entry.get("name", ""))
                    and any(
                        name_match_size_ok(entry, found.get("size"))
                        for found in catalogued_model_files(name, db)
                    )
                    for entry in entries
                )

            by_model = {name for name in names if by_setting(name)}
            if record.get("kind") == "names_searched" and any(
                (found := holder.held(name)) and (found[1] or folds) for name in names
            ):
                continue
            reader = {
                "emulator": str(record.get("emulator", "")),
                "build": str(record.get("build", "")),
                "kind": str(record.get("kind", "")),
                "source_ref": str(record.get("source_ref", "")),
                "profiles": readers,
            }
            # A name a reader's entry declares unsourceable is no gap: its
            # row carries the reason and is counted apart.
            unsourceable = {
                str(n).rsplit("/", 1)[-1]: str(entry["unsourceable"])
                for key in readers
                for entry in profiles[key].get("files") or []
                if entry.get("unsourceable")
                for n in (entry.get("name"), *(entry.get("aliases") or []))
                if n
            }
            for name in names:
                found = holder.held(name)
                if found and (found[1] or folds) or name in by_model:
                    continue
                key = name.casefold() if folds else name
                row = by_key.get(key)
                if row is None:
                    row = by_key[key] = {
                        "platform": platform,
                        "name": name,
                        "emulators": [],
                        "readers": [],
                    }
                    if found:
                        row["held_as"] = found[0]
                reason = unsourceable.get(name.rsplit("/", 1)[-1])
                if reason and "unsourceable" not in row:
                    row["unsourceable"] = reason
                if reader["emulator"] not in row["emulators"]:
                    row["emulators"].append(reader["emulator"])
                if reader not in row["readers"]:
                    row["readers"].append(reader)
        rows.extend(by_key[key] for key in sorted(by_key, key=str.casefold))
    return rows


def print_launcher_unproven(rows: list[dict]) -> None:
    """The launcher records resting on a config file the code does not prove.

    Neither a pack, a manifest nor a severity reads them: each is listed
    with the links it lacks.
    """
    if not rows:
        return
    platforms = sorted({r["platform"] for r in rows})
    noun = "platform" if len(platforms) == 1 else "platforms"
    print(f"\nLauncher records unproven: {len(rows)} across {len(platforms)} {noun}")
    for platform in platforms:
        print(f"\n{platform}")
        for row in (r for r in rows if r["platform"] == platform):
            print(f"    [{row['index']}] {row['emulator']} {row['kind']}: {row['passes_to']}")
            for link in row["missing"]:
                print(f"        missing {link}")


def print_launcher_reads(rows: list[dict]) -> None:
    """The launcher reads gap category, after the profile gaps.

    A name its reader declares unsourceable is listed apart, with the
    reason: it is no file left to find.
    """
    unsourceable = [r for r in rows if r.get("unsourceable")]
    rows = [r for r in rows if not r.get("unsourceable")]
    platforms = sorted({r["platform"] for r in rows})
    noun = "platform" if len(platforms) == 1 else "platforms"
    print(f"\nLauncher reads, not held: {len(rows)} names across {len(platforms)} {noun}")
    for platform in platforms:
        print(f"\n{platform}")
        for row in (r for r in rows if r["platform"] == platform):
            first = row["readers"][0]
            more = f" (+{len(row['readers']) - 1} records)" if len(row["readers"]) > 1 else ""
            casing = f", held as {row['held_as']}" if row.get("held_as") else ""
            print(
                f"    {row['name']} [{', '.join(row['emulators'])}, {first['kind']}, "
                f"{first['source_ref']}]{more}{casing}"
            )
    if not unsourceable:
        return
    platforms = sorted({r["platform"] for r in unsourceable})
    noun = "platform" if len(platforms) == 1 else "platforms"
    print(
        f"\nLauncher reads, unsourceable: {len(unsourceable)} names "
        f"across {len(platforms)} {noun}"
    )
    for row in unsourceable:
        print(
            f"    {row['platform']}: {row['name']} [{', '.join(row['emulators'])}, "
            f"{row['readers'][0]['source_ref']}]: {row['unsourceable']}"
        )


def cross_reference(
    profiles: dict[str, dict],
    declared: dict[str, set[str]],
    db: dict,
    platform_data_dirs: dict[str, set[str]] | None = None,
    data_names: set[str] | None = None,
    all_declared: dict[str, list[tuple[int | None, str]]] | None = None,
    standalone_cores: set[str] | None = None,
    folded_slots: frozenset[str] = frozenset(),
    platform: str = "",
    launcher_layer: LauncherLayer | None = None,
    declared_contents: dict[str, set[str]] | None = None,
) -> dict:
    """Compare emulator profiles against platform declarations.

    Returns a report with gaps (files emulators need but platforms don't list)
    and coverage stats.  Each gap entry carries a ``source`` field indicating
    where the file is available: ``"bios"`` (bios/ via database.json),
    ``"data"`` (data/ directory), ``"large_file"`` (GitHub release asset),
    or ``"missing"`` (not available anywhere).

    The boolean ``in_repo`` is derived: ``source != "missing"``.

    When *all_declared* is provided (every filename declared by any platform
    for any system, with its sizes and slots), it is used for the ``in_platform`` check
    instead of the per-system lookup.  This is appropriate for the global
    gap analysis page where "undeclared" means "no platform declares it at all".
    """
    platform_data_dirs = platform_data_dirs or {}
    by_name = db.get("indexes", {}).get("by_name", {})
    by_name_lower = {k.lower(): k for k in by_name}
    by_md5 = db.get("indexes", {}).get("by_md5", {})
    by_crc32 = db.get("indexes", {}).get("by_crc32", {})
    by_sha256 = db.get("indexes", {}).get("by_sha256", {})
    by_path_suffix = db.get("indexes", {}).get("by_path_suffix", {})
    db_files = db.get("files", {})
    report = {}

    index = {
        "by_name": by_name,
        "by_name_lower": by_name_lower,
        "by_md5": by_md5,
        "by_crc32": by_crc32,
        "by_sha256": by_sha256,
        "by_path_suffix": by_path_suffix,
        "db_files": db_files,
        "data_names": data_names,
        "all_declared": all_declared,
        "folded_slots": folded_slots,
        "declared_contents": declared_contents,
        "bios_dir": db.get("bios_dir"),
        "launcher_candidates": [] if launcher_layer else None,
    }
    for emu_name, profile in profiles.items():
        _cross_reference_profile(
            emu_name, profile, declared, report, index, standalone_cores,
            platform,
        )
    if launcher_layer:
        _settle_launcher_places(report, index["launcher_candidates"], launcher_layer, db)

    return report


def print_report(
    report: dict, scope: str = "all emulators", show_clean: bool = False
) -> None:
    """Print a human-readable gap analysis report.

    `scope` names what the totals cover: under --platform, the emulators
    that platform runs, not all of them. `show_clean` lists an emulator with
    nothing undeclared too: asked about by name, it was the whole answer and
    the report used to leave it out.
    """
    print("Emulator vs Platform Gap Analysis")
    print("=" * 60)
    print("* marks a file the emulator requires")

    total_gaps = 0
    totals: dict[str, int] = {"bios": 0, "data": 0, "large_file": 0, "missing": 0}
    # A runtime component bundled with its emulator is left out of the
    # collection by design, as verify and the gaps page say: not a file to find.
    bundled = 0

    for emu_name, data in sorted(report.items()):
        gaps = data["gaps"]
        if gaps == 0 and not show_clean:
            continue

        # Counted once, for the heading and the total alike: a file installed
        # with its emulator is neither one to source nor one the pack brings,
        # held or not (validation.deliverable leaves it out of every pack).
        bundled_gaps = [g for g in data["gap_details"] if g.get("bundled")]
        emulator_bundled = len(bundled_gaps)
        counts = {key: data.get(f"gap_{key}", 0) for key in totals}
        for g in bundled_gaps:
            counts[g.get("source", "missing")] -= 1
        counts["bundled"] = emulator_bundled
        parts = [f"{count} {key}" for key, count in counts.items() if count]
        status = ", ".join(parts) if parts else "OK"

        systems = ", ".join(data["systems"])
        print(f"\n{data['emulator']}" + (f" ({systems})" if systems else ""))
        print(f"  {data['total_files']} files in profile: {profile_breakdown(data)}")
        print(f"  Gaps: {status}")

        for g in data["gap_details"]:
            req = "*" if g["required"] else " "
            src = g.get("source", "missing").upper()
            if g.get("bundled"):
                src = "BUNDLED"
            # One line per file: a note spanning lines fell to column 0
            # between entries and read as an emulator heading.
            note = f": {' '.join(str(g['note']).split())}" if g["note"] else ""
            archive_info = ""
            if g.get("archive"):
                fc = g.get("archive_file_count", 0)
                rc = g.get("archive_required_count", 0)
                archive_info = f" ({fc} files, {rc} required)"
            if g.get("alternatives") and not g.get("in_repo"):
                archive_info += f" (or {', '.join(g['alternatives'])})"
            print(f"    {req} {g['name']} [{src}]{archive_info}{note}")

        total_gaps += gaps
        for key in totals:
            totals[key] += counts[key]
        bundled += emulator_bundled

    print(f"\n{'=' * 60}")
    print(f"Total: {total_gaps} undeclared files across {scope}")
    available = totals["bios"] + totals["data"] + totals["large_file"]
    print(f"  {available} available (bios: {totals['bios']}, data: {totals['data']}, "
          f"large_file: {totals['large_file']})")
    print(f"  {totals['missing']} missing (need to be sourced)")
    if bundled:
        print(f"  {bundled} bundled with their emulator, not packed")


def main() -> None:
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Emulator vs platform gap analysis")
    parser.add_argument(
        "--emulators-dir", default=DEFAULT_EMULATORS_DIR,
        help="emulator profile directory (default: %(default)s)",
    )
    parser.add_argument(
        "--platforms-dir", default=DEFAULT_PLATFORMS_DIR,
        help="platform YAML directory (default: %(default)s)",
    )
    parser.add_argument(
        "--db", default=DEFAULT_DB,
        help="database file to read (default: %(default)s)",
    )
    parser.add_argument("--emulator", "-e", help="Analyze single emulator")
    parser.add_argument(
        "--platform", "-p", type=platform_arg, help="Restrict analysis to one platform's cores"
    )
    parser.add_argument("--target", "-t", help="Hardware target (e.g., switch, rpi4)")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument(
        "--list-emulators", action="store_true", help="List available emulators"
    )
    args = parser.parse_args()
    from common import work_from_repo_root  # noqa: PLC0415

    work_from_repo_root(args, parser, ["emulators_dir", "platforms_dir", "db"])
    if args.list_emulators:
        ignored = [flag for flag, on in (
            ("--emulator", args.emulator), ("--platform", args.platform),
            ("--target", args.target), ("--json", args.json),
        ) if on]
        if ignored:
            parser.error(f"--list-emulators does not apply {', '.join(ignored)}")
        list_emulator_profiles(args.emulators_dir)
        return
    if args.platform:
        require_platform(args.platform, args.platforms_dir)

    import contextlib

    from refresh_data_dirs import hold_data_dirs

    # Files resolve against data/: the trees stay put until the process
    # ends, which releases the hold.
    held = contextlib.ExitStack()
    registry = load_data_dir_registry(args.platforms_dir)
    hold_data_dirs(held, registry)

    profiles = load_emulator_profiles(args.emulators_dir)
    # Every profile's names and aliases, whatever --emulator or --platform keeps.
    all_profiles = profiles
    emulator = args.emulator
    if emulator:
        # A typo answered "No emulator profiles found" with exit 0.
        try:
            ((emulator, _),) = select_emulator_profiles(
                [args.emulator],
                load_emulator_profiles(args.emulators_dir, skip_aliases=False),
            )
        except ProfileSelectionError as exc:
            raise SystemExit(f"ERROR: {exc}") from None
        profiles = {k: v for k, v in profiles.items() if k == emulator}

    if args.target and not args.platform:
        parser.error("--target requires --platform")

    standalone_cores: set[str] = set()
    if args.platform:
        from common import load_target_config, resolve_platform_cores

        try:
            target_cores = (
                load_target_config(args.platform, args.target, args.platforms_dir)
                if args.target
                else None
            )
        except (FileNotFoundError, ValueError) as exc:
            # A typo ended in a traceback where verify and slots name the
            # closest target.
            parser.error(str(exc))
        config = load_platform_config(args.platform, args.platforms_dir)
        relevant = resolve_platform_cores(config, profiles, target_cores=target_cores)
        run_anywhere = (
            set(resolve_platform_cores(config, profiles)) if args.target else relevant
        )
        profiles = {k: v for k, v in profiles.items() if k in relevant}
        standalone_cores = standalone_set(config)
    else:
        # The tree as every platform runs it: a profile some platform runs
        # standalone keeps its standalone entries. Laid out as libretro only,
        # eka2l1, dolphin and xenia-edge lost 133 files no platform declares.
        from common import list_registered_platforms, merged_standalone_set

        standalone_cores = merged_standalone_set(
            load_platform_config(name, args.platforms_dir)
            for name in list_registered_platforms(args.platforms_dir)
        )

    if not profiles:
        if emulator and args.target and emulator in run_anywhere:
            raise SystemExit(
                f"ERROR: {emulator} is not built for {args.platform}'s "
                f"{args.target} target; {args.platform} runs it elsewhere "
                f"(drop --target to see its files)"
            )
        if emulator:
            raise SystemExit(f"ERROR: {emulator} is not run by {args.platform}")
        print(f"{args.platform or 'The tree'} runs no profiled emulator.", file=sys.stderr)
        return

    selected = [args.platform] if args.platform else None
    declared, plat_data_dirs = load_platform_files(args.platforms_dir, selected)
    db = load_database(args.db)
    data_names = _build_supplemental_index()
    report = cross_reference(
        profiles, declared, db, plat_data_dirs, data_names,
        all_declared=declared_names(args.platforms_dir, selected, db),
        standalone_cores=standalone_cores,
        folded_slots=folded_declared_slots(args.platforms_dir, selected, db),
        declared_contents=merged_platform_declared_contents(
            [
                load_platform_config(name, args.platforms_dir)
                for name in selected or list_registered_platforms(args.platforms_dir)
            ],
            db,
        ),
        platform=config.get("_key", args.platform) if args.platform else "",
        # What the platform's launchers open, as verify and the builder read it.
        launcher_layer=LauncherLayer(
            config, profiles, relevant, db, declared_destinations(config)
        ) if args.platform else None,
    )

    # Counted apart from the profile gaps: a name only a launcher reads is
    # reported, not yet judged.
    launcher_reads = launcher_reads_not_held(
        {
            name: load_platform_config(name, args.platforms_dir)
            for name in (selected or list_registered_platforms(args.platforms_dir))
        },
        db, all_profiles, registry, emulator or "",
    )

    unproven = [
        row for row in launcher_unproven(
            {
                name: load_platform_config(name, args.platforms_dir)
                for name in (selected or list_registered_platforms(args.platforms_dir))
            },
            all_profiles,
        )
        if not emulator or any(
            emulator in LauncherLayer._profiles_named(part, all_profiles, set(all_profiles))
            for part in row["emulator"].split(", ")
        )
    ]

    if args.json:
        print(json.dumps(
            {**report, LAUNCHER_READS_KEY: launcher_reads, LAUNCHER_UNPROVEN_KEY: unproven},
            indent=2,
        ))
    else:
        if emulator:
            scope = emulator
        elif args.platform:
            scope = f"the emulators {args.platform} runs"
        else:
            scope = "all emulators"
        print_report(report, scope, show_clean=bool(args.emulator))
        print_launcher_reads(launcher_reads)
        print_launcher_unproven(unproven)


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
