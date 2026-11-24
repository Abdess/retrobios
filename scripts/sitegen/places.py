"""Where the collection's folders place each system id: the run's set of system ids."""

from __future__ import annotations

from dataclasses import dataclass

from model.collection import copy_places
from model.manufacturers import manufacturer_slug
from model.systemnames import console_index, section_pairs_of, spelled_section
from resolve.localfile import resolution_is_hash_exact, resolve_local_file
from resolve.ownership import BUCKET_FOLDERS, names_manufacturer


def _copies_by_path(db: dict) -> dict[str, set[tuple[str, str, str]]]:
    """The copy places of each content, keyed by the path the database keeps."""
    files = db.get("files", {})
    return {
        str(files[sha1].get("path", "")): where
        for sha1, where in copy_places(db).items()
    }


def _system_folder(
    files: list[dict],
    db: dict,
    name_consoles: dict[str, set[tuple[str, str]]],
    sys_id: str = "",
    copies: dict[str, set[tuple[str, str, str]]] | None = None,
) -> tuple[str, str] | None:
    """The bios/<manufacturer>/<console> folder a system's files live in.

    A content votes for every folder holding a copy under the name the system
    declares, not only the one deduplication kept: disksys.rom is kept as
    Arcade/FBNeo/fdsbios.nes and filed again under Nintendo/Famicom Disk
    System. A copy filed under another name, outside the manufacturer the id
    names, is another machine's file and votes only when no copy carries the
    declared name. An id that names its manufacturer (nintendo-fds) keeps the
    votes cast inside that manufacturer when there are any, and a maker's
    folder outranks the folders that file copies by emulator.
    """
    if copies is None:
        copies = _copies_by_path(db)
    votes: dict[tuple[str, str], int] = {}
    for fe in files:
        local, status = resolve_local_file(fe, db)
        if not local or not resolution_is_hash_exact(status):
            continue
        held = copies.get(local, set())
        if not held:
            parts = local.split("/")
            if len(parts) >= 4 and parts[0] == "bios":
                held = {(parts[1], parts[2], parts[-1])}
        declared = str(fe.get("name", "")).casefold()
        named = {
            (m, c) for m, c, base in held
            if base.casefold() == declared or names_manufacturer(sys_id, m)
        }
        for place in named or {(m, c) for m, c, _ in held}:
            votes[place] = votes.get(place, 0) + 1
    if votes:
        own = [place for place in votes if names_manufacturer(sys_id, place[0])]
        makers = [place for place in votes if place[0] not in BUCKET_FOLDERS]
        candidates = own or makers or list(votes)
        return max(sorted(candidates), key=lambda place: votes[place])
    for fe in files:
        places = name_consoles.get(fe.get("name", ""), set())
        if len(places) == 1:
            return next(iter(places))
    return None


def _console_norm_index(manufacturers: dict) -> dict[str, tuple[str, str]]:
    """Normalized console name index for fuzzy matching."""
    console_norm: dict[str, tuple[str, str]] = {}
    for mfr, consoles in manufacturers.items():
        slug = manufacturer_slug(mfr)
        mfr_norm = slug
        for console in consoles:
            norm = console.lower().replace(" ", "-")
            entry = (slug, console)
            console_norm[norm] = entry
            console_norm[f"{mfr_norm}-{norm}"] = entry
            # Short aliases: strip common manufacturer prefix words
            for prefix in (
                f"{mfr_norm}-",
                "nintendo-",
                "sega-",
                "sony-",
                "snk-",
                "nec-",
            ):
                key = f"{prefix}{norm}"
                console_norm[key] = entry
    return console_norm


def _fuzzy_place(sys_id: str, console_norm: dict[str, tuple[str, str]]) -> tuple[str, str] | None:
    """Strategy 3: fuzzy match system_id against console directory names."""
    if sys_id in console_norm:
        return console_norm[sys_id]
    # Try partial match: "nintendo-wii" matches "Wii" under "Nintendo"
    parts = sys_id.split("-")
    for i in range(len(parts)):
        suffix = "-".join(parts[i:])
        if suffix in console_norm:
            return console_norm[suffix]
    return None


@dataclass(frozen=True)
class _FolderIndex:
    """What a system is placed in a console folder by."""

    db: dict
    name_consoles: dict[str, set[tuple[str, str]]]
    folders_by_name: dict[str, set[tuple[str, str]]]
    copies: dict[str, set[tuple[str, str, str]]]

    def place(self, sys_id: str, files: list) -> tuple[str, str] | None:
        """Strategy 1: the one console folder the id spells (nintendo-nes,
        NES). A copy of the disk system BIOS in the NES list does not
        move the NES to the folder that copy sits in.
        Strategy 2: the folder holding the files the system declares,
        found by content, and most votes win. A bare name stands in only
        where the collection files it in a single console."""
        place = spelled_section(sys_id, self.folders_by_name) or _system_folder(
            files, self.db, self.name_consoles, sys_id, self.copies
        )
        if place is None:
            return None
        mfr, console = place
        return (manufacturer_slug(mfr), console)


def _profile_system_pages(
    profiles: dict, pages: dict[str, tuple[str, str]], index: _FolderIndex,
    console_norm: dict[str, tuple[str, str]],
) -> None:
    """Systems only emulator profiles name (sega-naomi, commodore-pet): placed
    by the files the profile files under them, as a platform's are. A
    profile of one system files all of its entries there."""
    for profile in profiles.values():
        systems = [str(sid) for sid in profile.get("systems") or []]
        for sys_id in systems:
            if sys_id in pages:
                continue
            files = [
                entry for entry in profile.get("files") or []
                if isinstance(entry, dict)
                and (entry.get("system") == sys_id or len(systems) == 1)
            ]
            place = index.place(sys_id, files)
            if place is not None:
                pages[sys_id] = place
            elif sys_id in console_norm:
                pages[sys_id] = console_norm[sys_id]


def system_pages_from_data(
    manufacturers: dict,
    coverages: dict,
    db: dict,
    profiles: dict | None = None,
) -> dict[str, tuple[str, str]]:
    """The system_id -> (manufacturer_slug, console_name) table.

    Uses platform file paths to trace system_id -> bios directory -> manufacturer page.
    """
    # Every console folder a filename sits in. A name in one folder only can
    # place a system, while a name in several says nothing (MiSTer's boot.rom lives
    # under a dozen consoles, and the last one written used to win).
    name_consoles: dict[str, set[tuple[str, str]]] = {}
    for mfr, consoles in manufacturers.items():
        for console, entries in consoles.items():
            for entry in entries:
                name_consoles.setdefault(entry["name"], set()).add((mfr, console))

    console_norm = _console_norm_index(manufacturers)

    # Map system_id -> (manufacturer, console) via platform file entries
    index = _FolderIndex(
        db, name_consoles,
        console_index(section_pairs_of(manufacturers)),
        _copies_by_path(db),
    )
    pages: dict[str, tuple[str, str]] = {}
    for cov in coverages.values():
        config = cov["config"]
        for sys_id, system in config.get("systems", {}).items():
            if sys_id in pages:
                continue
            place = index.place(sys_id, system.get("files", [])) or _fuzzy_place(sys_id, console_norm)
            if place is not None:
                pages[sys_id] = place

    _profile_system_pages(profiles or {}, pages, index, console_norm)
    return pages
