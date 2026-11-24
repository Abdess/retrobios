"""Where a profile entry resolves in the collection: its copy, hash and slot."""

from __future__ import annotations

from model.database import get_mame_clone_map
from packs.supplemental import SupplementalIndex, data_hit, declared_content
from resolve.content import content_fits, name_match_size_ok
from resolve.directories import directory_members
from resolve.layout import system_dir_path
from resolve.localfile import held_record_for
from resolve.ownership import foreign_tree, owner_tokens
from resolve.validation import read_from_save_dir


def _resolve_source(
    fname: str,
    by_name: dict[str, list],
    by_name_lower: dict[str, str],
    data_names: SupplementalIndex | None = None,
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
    declared = declared_content(file_entry or {})
    owners = owner_tokens(file_entry or {})

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
            or not foreign_tree(db_files.get(sha1, {}).get("path", ""), owners)
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
    if basename and basename.lower() in by_name_lower and _folded_hit(
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
    if data_names and data_hit(fname, basename, file_entry, data_names):
        return "data"
    return None


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


def entry_index(db: dict, data_names: SupplementalIndex | None) -> dict:
    """The collection indexes entry_source reads, one build for every caller."""
    indexes = db.get("indexes", {})
    by_name = indexes.get("by_name", {})
    return {
        "by_name": by_name,
        "by_name_lower": {k.lower(): k for k in by_name},
        "by_md5": indexes.get("by_md5", {}),
        "by_crc32": indexes.get("by_crc32", {}),
        "by_sha256": indexes.get("by_sha256", {}),
        "by_path_suffix": indexes.get("by_path_suffix", {}),
        "db_files": db.get("files", {}),
        "data_names": data_names,
        "bios_dir": db.get("bios_dir"),
    }


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
    # the pack and verify --emulator expand it by, and by nothing else: a
    # bare-name lookup missed cdogs' .wolf3d/, whose 695 files every pack
    # carries, and called SuperTux's data/ held by MAME's plugins/data/.
    if f.get("type") == "directory" or fname.endswith("/"):
        members = directory_members(
            {"indexes": {"by_path_suffix": by_path_suffix}}, path_field or fname
        )
        return "bios" if members else None
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

    # The declared content anywhere in bios/ comes before a data/ copy, as in
    # the resolver: the hash steps run before the data directories, and the
    # held record is the one every declared hash agrees with.
    held = held_record_for(f, {
        "files": db_files,
        "indexes": {key: index[key] for key in ("by_md5", "by_sha256", "by_crc32")},
    })
    return "bios" if held is not None else found


def resolve_archive_source(
    archive_name: str,
    by_name: dict[str, list],
    by_name_lower: dict[str, str],
    data_names: SupplementalIndex | None = None,
    by_path_suffix: dict | None = None,
) -> str:
    """Resolve source for an archive (ZIP) name, returning a source category string."""
    result = _resolve_source(
        archive_name, by_name, by_name_lower, data_names, by_path_suffix,
    )
    return result if result is not None else "missing"


def first_hash(entry: dict) -> str:
    """The first hash an entry declares, strongest first, or ''."""
    for field in ("sha1", "sha256", "md5", "crc32"):
        value = entry.get(field)
        if isinstance(value, list):
            value = value[0] if value else ""
        if value:
            return f"{field}:{str(value).lower()}"
    return ""


def declared_as(f: dict, fname: str) -> dict[str, str]:
    """The category and path the profile gives the entry a row stands for.

    A row's own path is the destination the running build reads, so a
    reader that needs the profile's declaration takes it from here.
    """
    return {
        "category": str(f.get("category") or "bios"),
        "profile_path": str(f.get("path") or fname),
    }


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
