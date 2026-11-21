"""The secondary indexes of database.json: by hash, name, path tail, shadowed alias and proven name."""

from __future__ import annotations

import os

from collection.declared import hash_values


def _path_suffixes(rel_path: str) -> list[str]:
    """Every tail of a stored path that can answer a declared destination.

    A destination and the tree meet on a tail, and which tail is unknowable
    from here: one profile writes GC/USA/IPL.bin, another writes the whole
    nand/.../00000000.app.romfs. Indexing only the tail after
    bios/Manufacturer/Console answered the first and never the second, so
    every same-named file collapsed onto one entry.

    The bare filename is left out on purpose. by_name already holds it, and a
    name alone is the weakest evidence there is.

    bios/Nintendo/GameCube/GC/USA/IPL.bin -> GC/USA/IPL.bin, USA/IPL.bin
    """
    parts = [p for p in rel_path.replace("\\", "/").split("/") if p]
    if parts and parts[0] == "bios":
        parts = parts[1:]
    return ["/".join(parts[-depth:]) for depth in range(len(parts), 1, -1)]


def _index_suffixes(
    by_path_suffix: dict[str, list[str]], path: str, name: str, sha1: str
) -> None:
    """File a content under every tail of one of its paths but its bare name."""
    for suffix in _path_suffixes(path):
        if suffix == name:
            continue
        held = by_path_suffix.setdefault(suffix, [])
        if sha1 not in held:
            held.append(sha1)


def build_indexes(files: dict, aliases: dict) -> dict:
    """Build secondary indexes for fast lookup."""
    by_md5: dict[str, str] = {}
    by_name: dict[str, list[str]] = {}
    by_crc32: dict[str, str] = {}
    by_sha256: dict[str, str] = {}
    by_path_suffix: dict[str, list[str]] = {}

    for sha1, entry in files.items():
        by_md5[entry["md5"]] = sha1

        name = entry["name"]
        if name not in by_name:
            by_name[name] = []
        by_name[name].append(sha1)

        by_crc32[entry["crc32"]] = sha1
        by_sha256[entry["sha256"]] = sha1

        # Path suffix index for regional variant resolution
        _index_suffixes(by_path_suffix, entry["path"], name, sha1)

    # Add alias names to by_name index (aliases have different filenames for same SHA1)
    for sha1, alias_list in aliases.items():
        for alias in alias_list:
            name = alias["name"]
            if name not in by_name:
                by_name[name] = []
            if sha1 not in by_name[name]:
                by_name[name].append(sha1)
            # Also index alias paths in by_path_suffix
            _index_suffixes(by_path_suffix, alias["path"], name, sha1)

    return {
        "by_md5": by_md5,
        "by_name": by_name,
        "by_crc32": by_crc32,
        "by_sha256": by_sha256,
        "by_path_suffix": by_path_suffix,
    }


def shadowed_alias_index(
    shadowed: list[tuple[str, set[str], list[str]]], by_name: dict
) -> dict[str, list[str]]:
    """Profile aliases that a primary's name keeps out of by_name.

    QUASI88 reads DISK.ROM as n88sub.rom, but DISK.ROM is the MSX disk ROM's
    own name, so by_name never points it at the PC-88 file. The resolver reads
    this index only where the system names a maker and no copy filed under
    that maker answers the name. An entry with no hash designates the content
    its own name holds alone in by_name.
    """
    index: dict[str, set[str]] = {}
    for entry_name, matched, taken in shadowed:
        held = by_name.get(entry_name, [])
        designated = matched or (set(held) if len(held) == 1 else set())
        for alias in taken:
            fresh = designated - set(by_name.get(alias, []))
            if fresh:
                index.setdefault(alias, set()).update(fresh)
    return {alias: sorted(sha1s) for alias, sha1s in sorted(index.items())}


def proven_name_index(
    files: dict, indexes: dict, declarations: list[dict]
) -> dict[str, list[str]]:
    """Names whose held primary no declaration proves, mapped to the primaries
    of the same directory that declarations of that name prove by hash.

    A hashless entry takes a name's file by name alone. The collection files
    the DSi Panda devkit boot ROMs as dsi_bios7.bin and dsi_bios9.bin, with
    the eMMC key-Y zeroed, while every hash declared under those names
    designates a retail dump beside them: RetroBat and dsperate were served
    the devkit ROMs. Another revision kept in .variants/ is not a primary,
    and a dump filed elsewhere is another machine's file.
    """
    by_hash = {
        "sha1": {sha1: sha1 for sha1 in files},
        "md5": indexes.get("by_md5", {}),
        "crc32": indexes.get("by_crc32", {}),
        "sha256": indexes.get("by_sha256", {}),
    }
    proven: dict[str, set[str]] = {}
    for entry in declarations:
        # A zipped_file hash is the member's, not the file the name designates.
        if not isinstance(entry, dict) or entry.get("zipped_file"):
            continue
        name = str(entry.get("name") or "").rsplit("/", 1)[-1]
        if not name:
            continue
        for kind, index in by_hash.items():
            for value in hash_values(entry.get(kind)):
                held = index.get(value)
                if held in files:
                    proven.setdefault(name, set()).add(held)
    result: dict[str, list[str]] = {}
    for name, designated in sorted(proven.items()):
        primaries = {
            sha1 for sha1 in indexes.get("by_name", {}).get(name, [])
            if sha1 in files and "/.variants/" not in files[sha1]["path"]
        }
        if not primaries or primaries & designated:
            continue
        homes = {os.path.dirname(files[sha1]["path"]) for sha1 in primaries}
        beside = [
            sha1 for sha1 in designated
            if "/.variants/" not in files[sha1]["path"]
            and os.path.dirname(files[sha1]["path"]) in homes
        ]
        if beside:
            result[name] = sorted(beside, key=lambda sha1: files[sha1]["path"])
    return result


def database_indexes(
    files: dict,
    aliases: dict,
    shadowed: list[tuple[str, set[str], list[str]]],
    declarations: list[dict],
) -> dict:
    """Every index database.json publishes over the scanned files and their aliases."""
    indexes = build_indexes(files, aliases)
    indexes["by_shadowed_alias"] = shadowed_alias_index(shadowed, indexes["by_name"])
    indexes["by_proven_name"] = proven_name_index(files, indexes, declarations)
    return indexes
