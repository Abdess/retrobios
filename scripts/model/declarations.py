"""What a platform configuration declares: destinations, archive contents, names."""

from __future__ import annotations

from collections import Counter

from core.paths import sanitize_pack_path


def platform_declarations(
    config: dict, db: dict, *, enrich: bool = True
) -> dict[str, list[tuple[int | None, str]]]:
    """Every file name a platform declares, with each declaration's size and slot.

    A name alone does not say which file a declaration is: RetroArch declares
    galaksija/ROM1.BIN, a 4 KiB ROM, and DOSBox reads a 32 KiB SC-55 ROM1.BIN.
    The size, from the platform entry or else from the file its hash names,
    tells a declaration of the same file from a same-named one. None stands
    for a size nobody knows. The slot is the declared destination, sanitized
    and case-folded, relative to the directory core files go to: RetroDECK
    writes bios/ in front of every destination, the others put it in
    base_destination.

    With ``enrich``, a declaration also answers for the canonical name and
    the aliases the database knows its MD5 under. This handles a platform
    declaring a file under a different name than the emulator profile
    (e.g. Batocera ROM1 vs gsplus ROM).
    """
    prefix = declared_root(config).lower()
    declared: dict[str, list[tuple[int | None, str]]] = {}
    by_md5 = db.get("indexes", {}).get("by_md5", {})
    files_db = db.get("files", {})
    for system in config.get("systems", {}).values():
        for fe in system.get("files", []):
            name = fe.get("name", "")
            slot = sanitize_pack_path(fe.get("destination") or name).lower()
            if prefix and slot.startswith(prefix + "/"):
                slot = slot[len(prefix) + 1:]
            # A zipped_file entry pins a member of the archive it names: its
            # md5 and its size, when stated, are not the archive's.
            by_hash: dict = {}
            size = None
            if not fe.get("zipped_file"):
                md5 = (fe.get("md5") or "").lower()
                if md5 and "," not in md5:
                    by_hash = files_db.get(by_md5.get(md5, ""), {})
                size = fe.get("size")
                if size is None:
                    size = files_db.get(
                        (fe.get("sha1") or "").lower(), by_hash
                    ).get("size")
            if name:
                declared.setdefault(name, []).append((size, slot))
            if not enrich:
                continue
            for other in (by_hash.get("name", ""), *by_hash.get("aliases", [])):
                if other:
                    declared.setdefault(other, []).append((by_hash.get("size"), slot))
    return declared


def declared_root(config: dict) -> str:
    """The BIOS directory a platform writes into every destination, if any.

    Only a platform whose base_destination is explicitly empty does that
    (RetroDECK writes bios/ in front of each file), and core files go under
    the same directory. A config that does not state a base says nothing,
    and its common folder is a system's, not the BIOS root. A platform whose
    list also names folders beside the BIOS one states it as
    core_destination: EmuELEC's ports/ entries are a quarter of its list.
    """
    if config.get("base_destination") != "":
        return ""
    if config.get("core_destination"):
        return str(config["core_destination"])
    roots = [
        d.split("/", 1)[0]
        for system in config.get("systems", {}).values()
        for f in system.get("files", [])
        if "/" in (d := f.get("destination", "") or "")
    ]
    if not roots:
        return ""
    root, count = Counter(roots).most_common(1)[0]
    return root if count / len(roots) > 0.9 else ""


def platform_declared_contents(config: dict, db: dict) -> dict[str, set[str]]:
    """The folders each declared file's content sits in, keyed by its hashes.

    A core that scans a folder and identifies a ROM by its checksum reads a
    declared file whatever its name: RetroDECK lists atari800's Atari BASIC
    Rev A as ROM_BASIC_A, and the core takes it by CRC32. Keys are
    "md5:", "sha1:" and "crc32:" values of the database file the
    declaration resolves to, each with the declared slot's folder.
    """
    prefix = declared_root(config).lower()
    by_md5 = db.get("indexes", {}).get("by_md5", {})
    files_db = db.get("files", {})
    contents: dict[str, set[str]] = {}
    for system in config.get("systems", {}).values():
        for fe in system.get("files", []):
            if fe.get("zipped_file"):
                continue
            record = files_db.get((fe.get("sha1") or "").lower())
            md5 = (fe.get("md5") or "").lower()
            if record is None and md5 and "," not in md5:
                sha1 = by_md5.get(md5, "")
                record = files_db.get(sha1[0] if isinstance(sha1, list) else sha1)
            if not record:
                continue
            slot = sanitize_pack_path(fe.get("destination") or fe.get("name", "")).lower()
            if prefix and slot.startswith(prefix + "/"):
                slot = slot[len(prefix) + 1:]
            folder = slot.rpartition("/")[0]
            for field in ("md5", "sha1", "crc32"):
                value = str(record.get(field) or "").lower()
                if value:
                    contents.setdefault(f"{field}:{value}", set()).add(folder)
    return contents


def merged_platform_declared_contents(configs: list[dict], db: dict) -> dict[str, set[str]]:
    """`platform_declared_contents` of several platforms, one index."""
    merged: dict[str, set[str]] = {}
    for config in configs:
        for key, folders in platform_declared_contents(config, db).items():
            merged.setdefault(key, set()).update(folders)
    return merged


def merged_platform_declarations(
    configs: list[dict], db: dict
) -> dict[str, list[tuple[int | None, str]]]:
    """`platform_declarations` of several platforms, one index."""
    merged: dict[str, list[tuple[int | None, str]]] = {}
    for config in configs:
        for name, places in platform_declarations(config, db).items():
            merged.setdefault(name, []).extend(places)
    return merged


def expand_platform_declared_names(config: dict, db: dict) -> set[str]:
    """The names a platform declares, enriched as `platform_declarations`."""
    return set(platform_declarations(config, db))
