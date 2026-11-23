"""Which arcade board each bios_zip archive of the collection is the BIOS of."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from core.memo import DerivedView
from model import siteinputs
from model.systemnames import (
    SYSTEM_PARENTS,
    ensure_console_sections,
    section_pairs,
    section_without_boards,
    system_name,
)

# A board is a system id that a profile entry with ``category: bios_zip``
# names, through its ``system:``/``systems:`` or the profile's single
# system, whose archive the collection holds, and that has no section under
# a machine's maker. The archive is found by its name and, where the entry
# lists ``contents:``, kept only when it holds one of those CRC32s:
# maclc3.zip names a MAME set and an unrelated 189 MB file. The folder a
# copy sits in decides nothing.


@dataclass(frozen=True)
class ArcadeBoards:
    """The boards elected from the profiles, for the sections installed."""

    # sha1 -> the board id the archive is the BIOS of.
    archive_boards: Mapping[str, str] = field(default_factory=dict)
    # Casefolded board name -> the board id that stands for it.
    board_names: Mapping[str, str] = field(default_factory=dict)
    # sha1 -> the (manufacturer, console) sections of the machines whose own
    # set the archive is: neogeo.zip for the Neo Geo, mz2000.zip for the MZ.
    archive_machines: Mapping[str, frozenset[tuple[str, str] | None]] = field(default_factory=dict)


def _owner_ids(entry: dict, systems: list[str]) -> set[str]:
    """The system ids a profile entry is declared for."""
    owners = {str(entry["system"])} if entry.get("system") else set()
    owners.update(str(sys_id) for sys_id in entry.get("systems") or [])
    if not owners and len(systems) == 1:
        owners = set(systems)
    return owners


# _board_role for an id whose archive is its machine's: a section under the
# machine's maker, or a reviewed parent outside Arcade.
_MACHINE = "\0machine"


def _board_role(sys_id: str) -> str | None:
    """A board's name, _MACHINE for an id that names a machine with a
    section of its own, None for an id that names neither (the generic
    arcade id, an id with no name)."""
    parent = SYSTEM_PARENTS.get(sys_id)
    if parent is not None:
        return None if parent[0] == "Arcade" else _MACHINE
    section = section_without_boards(sys_id)
    if section is not None and section[0] != "arcade":
        return _MACHINE
    try:
        return system_name(sys_id)
    except KeyError:
        return None


def _arcade_tails(by_path_suffix: dict) -> frozenset[str]:
    return frozenset(
        sha1s[0]
        for tail, sha1s in by_path_suffix.items()
        if tail.startswith("Arcade/") and len(sha1s) == 1
    )


_arcade_suffixes = DerivedView(_arcade_tails)


def in_arcade(sha1: str, db: dict) -> bool:
    """Whether a copy of the content sits under bios/Arcade/."""
    entry = db.get("files", {}).get(sha1) or {}
    if str(entry.get("path", "")).startswith("bios/Arcade/"):
        return True
    return sha1 in _arcade_suffixes(db.get("indexes", {}).get("by_path_suffix", {}))


def entry_archives(entry: dict, files: dict, by_name: dict) -> set[str]:
    """The archives of the collection a ``bios_zip`` entry names."""
    from core.ziptools import zip_member_crcs

    crcs = {
        str(member["crc32"]).lower()
        for member in entry.get("contents") or []
        if isinstance(member, dict) and member.get("crc32")
    }
    names = {str(entry.get("name", ""))}
    names.update(str(alias) for alias in entry.get("aliases") or [])
    archives: set[str] = set()
    for name in names:
        found = by_name.get(name.rsplit("/", 1)[-1]) or []
        for sha1 in [found] if isinstance(found, str) else found:
            if sha1 not in files:
                continue
            if crcs:
                held = zip_member_crcs(str(siteinputs.collection_path(files[sha1]["path"])))
                # An archive the build cannot read keeps its name.
                if held and not held & crcs:
                    continue
            archives.add(sha1)
    return archives


def _machine_section(sys_id: str) -> tuple[str, str] | None:
    """The (manufacturer, console) section SYSTEM_PARENTS files a machine
    id under, outside Arcade. Only a reviewed parent moves an archive out
    of the folder holding it: an id with a section of its own keeps its
    archives where the collection files them."""
    parent = SYSTEM_PARENTS.get(sys_id)
    if parent is None or parent[0] == "Arcade" or parent not in section_pairs:
        return None
    return parent


@dataclass
class _Ballots:
    """The votes the profiles cast, archive by archive."""

    # sha1 -> board name -> the profiles naming it. None: a machine's own.
    votes: dict[str, dict[str, set[str]] | None] = field(default_factory=dict)
    ids_by_name: dict[str, set[str]] = field(default_factory=dict)
    machines: dict[str, set[tuple[str, str] | None]] = field(default_factory=dict)

    def cast(self, key: str, entry: dict, owners: set[str], archives: set[str]) -> None:
        for owner in owners:
            role = _board_role(owner)
            if role == _MACHINE:
                # The profile's only system stands for an entry that names
                # none: MAME's printer and expansion sets in a Dragon
                # profile. Only an entry naming the machine moves its set,
                # and only when every machine it names has that section:
                # epson_fx80.zip, which sixteen machines load, has none.
                declared = entry.get("system") or entry.get("systems")
                places = {_machine_section(o) for o in owners
                          if _board_role(o) == _MACHINE} if declared else {None}
                section = next(iter(places)) if len(places) == 1 else None
                for sha1 in archives:
                    self.votes[sha1] = None
                    self.machines.setdefault(sha1, set()).add(section)
                continue
            if role is None:
                continue
            self.ids_by_name.setdefault(role.casefold(), set()).add(owner)
            for sha1 in archives:
                ballot = self.votes.setdefault(sha1, {})
                if ballot is not None:
                    ballot.setdefault(role.casefold(), set()).add(key)

    def elect(self, db: dict) -> ArcadeBoards:
        archive_boards: dict[str, str] = {}
        board_names: dict[str, str] = {}
        for sha1, ballot in self.votes.items():
            if not ballot:
                continue
            ranked = sorted(ballot.items(), key=lambda item: (-len(item[1]), item[0]))
            # Two boards named as often: a device ROM several boards share.
            if len(ranked) > 1 and len(ranked[0][1]) == len(ranked[1][1]):
                continue
            name = ranked[0][0]
            board = sorted(self.ids_by_name[name])[0]
            archive_boards[sha1] = board
            if in_arcade(sha1, db):
                board_names[name] = board
        # A board none of whose archives sits under Arcade has no section there.
        archive_boards = {sha1: board for sha1, board in archive_boards.items()
                          if system_name(board).casefold() in board_names}
        machines = {sha1: frozenset(places) for sha1, places in self.machines.items()}
        return ArcadeBoards(archive_boards, board_names, machines)


def elect_arcade_boards(profiles: dict[str, dict], db: dict) -> ArcadeBoards:
    """The board of each archive, elected from the profiles' ``bios_zip``
    entries against the console sections installed."""
    ensure_console_sections()
    files = db.get("files", {})
    by_name = db.get("indexes", {}).get("by_name", {})
    ballots = _Ballots()
    for key in sorted(profiles):
        profile = profiles[key]
        if profile.get("role") == "test":
            continue
        systems = [str(sys_id) for sys_id in profile.get("systems") or []]
        for entry in profile.get("files") or []:
            if not isinstance(entry, dict) or entry.get("category") != "bios_zip":
                continue
            owners = _owner_ids(entry, systems)
            if not owners:
                continue
            ballots.cast(key, entry, owners, entry_archives(entry, files, by_name))
    return ballots.elect(db)


def read_arcade_boards() -> ArcadeBoards:
    """The boards of the collection and profiles the site inputs name, none
    without a database."""
    from model.database import load_database
    from model.profiles import load_emulator_profiles

    inputs = siteinputs.current()
    if not inputs.db.exists():
        return ArcadeBoards()
    db = load_database(str(inputs.db))
    profiles = load_emulator_profiles(str(inputs.emulators), skip_aliases=False)
    return elect_arcade_boards(profiles, db)
