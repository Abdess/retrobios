"""Who decides what goes at a destination: the platform's claim against the emulator profile's."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from core.hashing import lists_hashes, parse_hash_list
from model.declarations import declared_slot
from model.profiles import entry_system_ids, lists_files
from packs.gaps import gap_destination
from resolve import nativemode
from resolve.archives import archive_entry, holds_required_members
from core.paths import comparable_destination
from resolve.collisions import accepted_by_all, content_sha1
from resolve.cores import resolve_platform_cores
from resolve.layout import system_dir_path
from resolve.localfile import resolution_is_hash_exact, resolve_local_file
from resolve.packfiles import preferred_entries
from resolve.launches import PlatformLaunches
from resolve.standalone import platform_layouts, platform_launches
from resolve.validation import (
    content_alternatives,
    outside_gap_scope,
    read_from_save_dir,
    with_archive_members,
)

if TYPE_CHECKING:
    from packs.extras import ExtraPlacement


# A profile entry can prove a slot without declaring a hash: Dolphin names no
# checksum for the GameCube boot ROM because its source names none, and the
# proof is then the path the repository stores the file at.
# A profile entry that names an exact size, for a file the code reads in
# full (no hash to declare), is proven by a held copy of that size: the
# platform's xmil/IPLROM.X1T pinned the 2 KiB X1 font where xmil reads a
# 32 KiB Turbo IPL, and a name-only claim could not contest it.
SIZE_EXACT = "size_exact"
PROVEN_STATUSES = frozenset({"path_exact", "members_held", SIZE_EXACT})


def _size_the_code_reads(entry: dict, local: str | None) -> bool:
    """Whether a name-resolved copy has the exact size the entry declares."""
    size = entry.get("size")
    if not local or not isinstance(size, int) or size <= 0:
        return False
    try:
        return os.path.getsize(local) == size
    except OSError:
        return False


# A core that reads ROMs inside an archive proves the archive by its members:
# FBNeo's neocdz.zip is any copy holding neocd.bin and 000-lo.lo by crc.
MEMBERS_HELD = "members_held"


@dataclass
class Claim:
    """One layer's answer to what belongs at a destination."""

    origin: str
    destination: str
    name: str
    emulator: str = ""
    entry: dict = field(default_factory=dict)
    local_path: str | None = None
    status: str = ""
    # A core that identifies its firmware by content reads no file by this
    # name: any dump it takes for the same system and region answers for it.
    accepts: tuple[dict, ...] = ()

    @property
    def is_proven(self) -> bool:
        """Whether the claim rests on evidence rather than on a bare name."""
        return resolution_is_hash_exact(self.status) or self.status in PROVEN_STATUSES


@dataclass
class Conflict:
    """Two proven claims on one destination that resolve to different files."""

    destination: str
    platform_claim: Claim
    profile_claims: list[Claim]

    @property
    def emulators(self) -> list[str]:
        return sorted({c.emulator for c in self.profile_claims if c.emulator})

    def files_read(self) -> list[tuple[str | None, list[str], str]]:
        """Each file the profiles want here, with the emulators reading it
        and the proof of the first claim on it.

        One file stood for every claim: Recalbox's neocdz.zip line gave
        geolith the archive fbneo reads, not the one geolith pins.
        """
        files: dict[str | None, tuple[list[str], str]] = {}
        for claim in self.profile_claims:
            emulators, status = files.setdefault(claim.local_path, ([], claim.status))
            if claim.emulator and claim.emulator not in emulators:
                emulators.append(claim.emulator)
        return [(path, sorted(emus), status) for path, (emus, status) in files.items()]


def platform_claims(
    config: dict,
    db: dict,
    base_dest: str = "",
    zip_contents: dict | None = None,
    data_dir_registry: dict | None = None,
) -> list[Claim]:
    """What the platform YAML says belongs at each of its destinations."""
    claims: list[Claim] = []
    for system in (config.get("systems") or {}).values():
        for entry in system.get("files") or []:
            if not isinstance(entry, dict):
                continue
            dest = declared_slot(entry)
            if not dest:
                continue
            full = f"{base_dest}/{dest}" if base_dest else dest
            local, status = resolve_local_file(
                entry,
                db,
                zip_contents,
                dest_hint=dest,
                data_dir_registry=data_dir_registry,
            )
            claims.append(
                Claim(
                    origin="platform",
                    destination=full,
                    name=entry.get("name", ""),
                    entry=entry,
                    local_path=local,
                    status=status,
                )
            )
    return claims


def profile_claims(
    profiles: dict,
    db: dict,
    base_dest: str = "",
    standalone_cores: PlatformLaunches | None = None,
    zip_contents: dict | None = None,
    data_dir_registry: dict | None = None,
    config: dict | None = None,
) -> list[Claim]:
    """What each emulator profile says belongs at each destination it names.

    With the platform's config, a claim sits where the pack puts the core's
    file (ExtraPlacement): under RetroDECK's bios/, under RomM's system
    folder. A file the platform cannot place claims nothing.

    A file can exist in one build of an emulator and not the other, and the
    two builds read from different directories. The mode is decided per
    emulator, not per pack: a platform runs some of its emulators as libretro
    cores and others standalone, naming the latter in ``standalone_cores``.
    An entry the standalone build alone loads does not address a platform
    running that emulator as a core, and where it does, the destination is
    ``standalone_path``. This is the gate verify already applies.
    """
    standalone_cores = standalone_cores or PlatformLaunches()
    placement = None
    if config is not None:
        from packs.extras import ExtraPlacement

        placement = ExtraPlacement(config, base_dest, profiles)
    claims: list[Claim] = []
    for emu_name, profile in sorted(profiles.items()):
        if not lists_files(profile):
            continue
        # The gap report skips a filename-agnostic profile whole: the builder
        # carries its scan candidates, never its named entries.
        if profile.get("bios_mode") == "agnostic":
            continue
        for layout, is_standalone in platform_layouts(emu_name, profile, standalone_cores):
            claims.extend(
                _archive_claims(
                    emu_name, layout, is_standalone, db, base_dest, placement,
                    zip_contents, data_dir_registry,
                )
            )
            for entry in layout.get("files") or []:
                if not isinstance(entry, dict):
                    continue
                # The same rule as the gap report and the builder: an entry the
                # pack never carries (a placeholder, a filename-agnostic scan)
                # arbitrates nothing. One read below the save directory sits
                # outside the BIOS tree, where no platform declares a file.
                if outside_gap_scope(entry, is_standalone) or read_from_save_dir(
                    entry, is_standalone
                ) or entry.get("unplaced"):
                    continue
                # A member of a romset is not a file at the BIOS root: the archive
                # holding it occupies the destination (_archive_claims). Claiming
                # the member put FBNeo's msx.zip contents loose at the root.
                if entry.get("archive"):
                    continue
                dest = gap_destination(entry, entry.get("name") or "", is_standalone, False)
                if not dest:
                    continue
                if placement is None:
                    full = f"{base_dest}/{dest}" if base_dest else dest
                else:
                    placed = placement.place(
                        {
                            "profile": emu_name,
                            "system": entry.get("system"),
                            "systems": entry_system_ids(entry, layout),
                        },
                        dest,
                    )
                    if placed is None:
                        continue
                    full = placed[1]
                # The owner's own copy is the one the builder ships.
                local, status = resolve_local_file(
                    {
                        **with_archive_members(entry, layout.get("files") or []),
                        "source_profile": emu_name,
                    },
                    db,
                    zip_contents,
                    dest_hint=dest,
                    data_dir_registry=data_dir_registry,
                )
                if status == "name_exact" and _size_the_code_reads(entry, local):
                    status = SIZE_EXACT
                accepts = tuple(content_alternatives(entry, layout))
                claims.append(
                    Claim(
                        origin="profile",
                        destination=full,
                        name=entry.get("name", ""),
                        emulator=emu_name,
                        entry=entry,
                        local_path=local,
                        status=status,
                        accepts=accepts,
                    )
                )
    return claims


def _archive_claims(
    emu_name: str,
    profile: dict,
    is_standalone: bool,
    db: dict,
    base_dest: str,
    placement: ExtraPlacement | None,
    zip_contents: dict | None,
    data_dir_registry: dict | None,
) -> list[Claim]:
    """The archives a core reads its ROMs from, where the builder places them.

    The archive sits at the root and, for a core that reads a directory of
    its own (archive_prefix), under it as well. The claim is proven when the
    copy holds every member the core requires.
    """
    files = [
        entry for entry in profile.get("files") or []
        if isinstance(entry, dict)
        and not outside_gap_scope(entry, is_standalone)
        and not read_from_save_dir(entry, is_standalone)
        and not entry.get("unplaced")
    ]
    prefix = profile.get("archive_prefix", "")
    claims: list[Claim] = []
    for archive in sorted({entry["archive"] for entry in files if entry.get("archive")}):
        entry = archive_entry(archive, files)
        members = entry.get("members")
        if not members:
            continue
        member = next(f for f in files if f.get("archive") == archive)
        system = member.get("system")
        if member.get("system_dir"):
            entry = {**entry, "system_dir": member["system_dir"]}
        root = system_dir_path(entry, archive)
        for dest in (root, f"{prefix}/{archive}") if prefix else (root,):
            if placement is None:
                full = f"{base_dest}/{dest}" if base_dest else dest
            else:
                placed = placement.place({"profile": emu_name, "system": system}, dest)
                if placed is None:
                    continue
                full = placed[1]
            local, status = resolve_local_file(
                {**entry, "source_profile": emu_name},
                db,
                zip_contents,
                dest_hint=dest,
                data_dir_registry=data_dir_registry,
            )
            if (
                local
                and not resolution_is_hash_exact(status)
                and holds_required_members(local, members)
            ):
                status = MEMBERS_HELD
            claims.append(
                Claim(
                    origin="profile",
                    destination=full,
                    name=archive,
                    emulator=emu_name,
                    entry=entry,
                    local_path=local,
                    status=status,
                )
            )
    return claims


def checked_by_path(mode: str, entry: dict, rule: str = "") -> bool:
    """Whether the frontend checks this declaration by its path alone.

    Whether a frontend reads the bytes is a property of the platform, but
    what it compares them with is the entry's: Batocera skips an empty md5
    (batocera-systems:1088), and EmuDeck declares neocdz.zip with no hash at
    all. Such an entry is a path, in an md5 platform as in an existence one.
    A member pinned inside an archive is content.
    """
    if not nativemode.reads_file_contents(mode):
        return True
    if entry.get("zipped_file"):
        return False
    if rule == nativemode.SIZE_AND_ANY_HASH:
        fields: tuple[str, ...] = ("md5", "sha1", "crc32")
    else:
        fields = (nativemode.digest_algorithm(mode) or "",)
    return not any(
        parse_hash_list(entry.get(name)) if name == "md5" else entry.get(name)
        for name in fields
    )


def _claim_rank(claim: Claim) -> int:
    """How strongly a platform claim speaks for what the pack ships."""
    if resolution_is_hash_exact(claim.status):
        return 2
    return 1 if claim.is_proven else 0


def _slot_claims(
    config: dict,
    profiles: dict,
    db: dict,
    base_dest: str,
    standalone_cores: PlatformLaunches | None,
    zip_contents: dict | None,
    data_dir_registry: dict | None,
) -> tuple[dict[str, Claim], dict[str, list[Claim]]]:
    """The platform claim and the proven profile claims at each destination."""
    fold = bool(config.get("case_insensitive_fs", False))
    # The builder's own choice among declarations sharing a destination,
    # read from the same function: the most accepting archive for zipped_file
    # members, then md5_exact. A rule of its own here compared profiles with
    # a file the pack does not ship (Batocera adam_fdc.zip).
    shipped = set(
        preferred_entries(
            config.get("systems") or {}, db, "bios", base_dest, False,
            zip_contents, True,
        ).values()
    )
    by_dest: dict[str, Claim] = {}
    for claim in platform_claims(
        config, db, base_dest, zip_contents, data_dir_registry
    ):
        key = comparable_destination(claim.destination, fold)
        held = by_dest.get(key)
        if held is not None and id(held.entry) in shipped:
            continue
        # A bare sibling met first must not stand for the destination: it
        # would hide the contradiction with the file actually shipped.
        if (
            held is None
            or id(claim.entry) in shipped
            or _claim_rank(claim) > _claim_rank(held)
        ):
            by_dest[key] = claim

    # Grouped before judging: a profile may declare several revisions that are
    # all acceptable at one destination, and the platform choosing one of them
    # is agreement, not contradiction. Only a destination where no profile
    # claim at all matches what ships is a disagreement.
    # A platform claim resting on a bare name, or on a pin no local file
    # matches, asserts nothing about content. Where the frontend never reads
    # the bytes, a proven profile claim then decides: RetroArch's neocdz.zip
    # pins an md5 nobody holds, and the primary shipped without the 000-lo.lo
    # geolith and FBNeo read inside it. Decided per entry: EmuDeck, an md5
    # platform, declares the same archive with no hash.
    mode = nativemode.platform_mode(config)
    rule = config.get("hash_rule", "")
    by_slot: dict[str, list[Claim]] = {}
    for claim in profile_claims(
        profiles, db, base_dest, standalone_cores, zip_contents, data_dir_registry,
        config=config,
    ):
        key = comparable_destination(claim.destination, fold)
        platform = by_dest.get(key)
        if platform is None or not claim.is_proven:
            continue
        if claim.status == SIZE_EXACT and (
            not platform.local_path
            or _size_the_code_reads(claim.entry, platform.local_path)
        ):
            # A size proves a claim only against a file of another size.
            continue
        if not platform.is_proven and not (
            platform.local_path and checked_by_path(mode, platform.entry, rule)
        ):
            continue
        by_slot.setdefault(key, []).append(claim)

    return by_dest, by_slot


def find_conflicts(
    config: dict,
    profiles: dict,
    db: dict,
    base_dest: str = "",
    standalone_cores: PlatformLaunches | None = None,
    zip_contents: dict | None = None,
    data_dir_registry: dict | None = None,
) -> list[Conflict]:
    """Destinations where a proven profile claim contradicts what ships.

    Only proven claims are compared. A claim resolved by filename alone
    asserts nothing about content and cannot contradict anything.
    """
    by_dest, by_slot = _slot_claims(
        config, profiles, db, base_dest, standalone_cores, zip_contents,
        data_dir_registry,
    )
    # A declaration that lists several accepted hashes is satisfied by any of
    # them: Recalbox names both scph1001.bin revisions, and mesence names
    # four BS-X dumps among which System.dat pins one. The resolver stops on
    # the first it finds, so the paths differ while both layers agree.
    disputed = {
        key: claims
        for key, claims in by_slot.items()
        if not any(_satisfies(c, by_dest[key], db) for c in claims)
    }

    return [
        Conflict(
            destination=by_dest[key].destination,
            platform_claim=by_dest[key],
            profile_claims=claims,
        )
        for key, claims in sorted(disputed.items())
    ]


# Why a decision went the way it did. Not the mode's own name: the mode is
# spelt in one place only, and nativemode answers whether it reads content.
SERVES_BOTH = "path_only_check"
ADDRESSEE = "addressee"
FRONTEND_CHECKS_CONTENT = "frontend_checks_content"


@dataclass
class Decision:
    """Which claim a pack should honour at a contested destination, and why."""

    conflict: Conflict
    winner: Claim
    reason: str

    @property
    def serves_both(self) -> bool:
        """Whether honouring the winner still satisfies the other layer."""
        return self.reason == SERVES_BOTH


def pack_overrides(
    config: dict,
    profiles: dict,
    db: dict,
    zip_contents: dict | None = None,
    data_dir_registry: dict | None = None,
    target_cores: set[str] | None = None,
    source: str = "full",
    choices: dict[str, list[tuple[str, str | None]]] | None = None,
) -> dict[str, str]:
    """Full pack destination -> the file a platform pack serves there instead.

    Where a source-verified profile contradicts the scraped baseline on one
    destination, the pack answers to the platform it is built for. In
    existence mode the frontend never reads the bytes, so serving the
    emulator's file satisfies both. The ZIP builder, the install manifest and
    verify all read this: two of them deciding alone gave the one-line
    installer different bytes than the ZIP. ``choices`` is slot_choices
    for the same arguments when the caller already holds it.
    """
    # A baseline-only pack serves what the platform declares, and a target's
    # pack answers to the cores that hardware builds: DuckStation does not
    # exist on any RetroArch target and still replaced its scph5000.bin.
    if not profiles or source == "platform":
        return {}
    cores = set(resolve_platform_cores(config, profiles, target_cores=target_cores))
    overrides: dict[str, str] = {}
    if choices is None:
        choices = slot_choices(config, profiles, db, zip_contents, data_dir_registry)
    for destination, ordered in choices.items():
        path = next((path for emulator, path in ordered if emulator in cores), None)
        if path:
            overrides[destination] = path
    return overrides


def slot_choices(
    config: dict,
    profiles: dict,
    db: dict,
    zip_contents: dict | None = None,
    data_dir_registry: dict | None = None,
) -> dict[str, list[tuple[str, str | None]]]:
    """Destination -> (core, the file it has served there) in decision order.

    A pack built for a set of cores serves the first choice whose core is in
    it, None standing for the platform's own answer. No core in it leaves
    the platform's answer too. The order is arbitrate's: a core agreeing with
    the platform settles the slot whatever else is present, then the
    strongest proof decides. Read for one core set by pack_overrides and
    recorded whole in the install manifest, so a target narrowed from the
    full manifest gets the bytes the target's own pack carries.
    """
    mode = nativemode.platform_mode(config)
    rule = config.get("hash_rule", "")
    platform_profiles = {
        name: profiles[name] for name in resolve_platform_cores(config, profiles)
    }
    by_dest, by_slot = _slot_claims(
        config,
        platform_profiles,
        db,
        config.get("base_destination", ""),
        platform_launches(config, profiles),
        zip_contents,
        data_dir_registry,
    )
    choices: dict[str, list[tuple[str, str | None]]] = {}
    for key, claims in sorted(by_slot.items()):
        platform = by_dest[key]
        # Where the frontend compares a hash, the platform's file stays.
        if not checked_by_path(mode, platform.entry, rule):
            continue
        agree = [_satisfies(c, platform, db) for c in claims]
        agreeing = [c for c, ok in zip(claims, agree) if ok]
        others = sorted(
            (c for c, ok in zip(claims, agree) if not ok),
            key=lambda claim: (-_claim_rank(claim), claims.index(claim)),
        )
        if not others:
            continue
        choices[platform.destination] = [
            *((c.emulator, None) for c in agreeing),
            *((c.emulator, c.local_path) for c in others),
        ]
    return choices


def _strongest(claims: list[Claim]) -> Claim:
    """The profile claim with the strongest proof, the first emulator breaking ties.

    yaps2 pins its GameIndex.yaml by sha1 while armsx2 and lrps2 only match a
    path: alphabetical order served armsx2's copy to all three.
    """
    return max(claims, key=lambda claim: (_claim_rank(claim), -claims.index(claim)))


def arbitrate(
    conflict: Conflict, mode: str, addressee: str = "platform", rule: str = "",
) -> Decision:
    """Decide a contested destination for the pack being built.

    A pack answers to whoever asked for it. A platform pack must leave the
    frontend's own check green, because a user reading red concludes the pack
    is broken. A pack built for one emulator answers to that emulator. The
    other layer is served as well whenever the destination allows it.

    In ``existence`` mode the frontend only looks for a path, so the emulator's
    file satisfies both sides at once and there is nothing to trade away. In a
    content-checking mode the two answers cannot share one path, and the pack's
    addressee decides. The loss is reported rather than absorbed: only the
    platform's own list can change what its frontend accepts there.
    """
    profile = _strongest(conflict.profile_claims)
    if addressee == "emulator":
        return Decision(conflict, profile, ADDRESSEE)
    if checked_by_path(mode, conflict.platform_claim.entry, rule):
        return Decision(conflict, profile, SERVES_BOTH)
    return Decision(conflict, conflict.platform_claim, FRONTEND_CHECKS_CONTENT)


def _satisfies(profile: Claim, platform: Claim, db: dict) -> bool:
    """Whether the two layers agree on what ships at this destination.

    They agree when they resolve to the same bytes, when the platform's own
    hash list accepts the profile's file, or when the profile's accepts the
    platform's. A contradiction needs both lists to reject the other side.
    A core found by content (found_by: content) reads no file by the
    destination's name, so any dump it takes for the same system and region
    settles the slot: DuckStation takes Batocera's scph1001.bin v2.0, which its profile
    labels scph1001_v20.bin.
    """
    if profile.local_path == platform.local_path:
        return True
    # Two paths can hold one content: AmberELEC's bluemsx declarations
    # resolve into the data/bluemsx cache, the profile's into bios/.
    if profile.local_path and platform.local_path:
        shipped = content_sha1(platform.local_path, db)
        if shipped is not None and shipped == content_sha1(profile.local_path, db):
            return True
    members = profile.entry.get("members")
    if members and platform.local_path:
        return holds_required_members(platform.local_path, members)
    if (
        profile.local_path
        and lists_hashes(platform.entry)
        and accepted_by_all(profile.local_path, [platform.entry], db)
    ):
        return True
    if platform.local_path and any(
        lists_hashes(label) and accepted_by_all(platform.local_path, [label], db)
        for label in profile.accepts
    ):
        return True
    return bool(
        platform.local_path
        and lists_hashes(profile.entry)
        and accepted_by_all(platform.local_path, [profile.entry], db)
    )
