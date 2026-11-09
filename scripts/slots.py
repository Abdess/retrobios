"""Who decides what goes at a destination.

A destination is a slot. Two layers can claim it: the platform YAML, scraped
from what the frontend declares, which can pin another file than the emulator
reads, and the emulator profile, read from the emulator's own source. Until this
module existed nothing compared the two: the builder resolves the platform
entry first and drops the profile entry on a bare filename match, so a profile
that names the right file for a slot could never win and never even be heard.

Claims are keyed by destination, folded to one case only where the platform's
filesystem folds it. Dolphin declares three IPL.bin separated only by their
path, and each is its own slot. A profile claim resting on a bare filename
proves nothing about content and contests no slot.

The pack builder, the install manifest and verify read slot_choices() through
pack_overrides(). arbitrate() states the same decision for one conflict and
feeds the report this module prints.
"""

from __future__ import annotations

import os
import zlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import nativemode
from common import (
    compute_hashes,
    platform_arg,
    archive_entry,
    build_zip_contents_index,
    check_inside_zip,
    entry_system_ids,
    holds_required_members,
    load_data_dir_registry,
    parse_md5_list,
    resolution_is_hash_exact,
    resolve_local_file,
    resolve_platform_cores,
    platform_layouts,
    standalone_set as platform_standalone_set,
    system_dir_path,
    variant_base_name,
)
from packresolve import preferred_entries
from validation import (
    content_alternatives,
    outside_gap_scope,
    read_from_save_dir,
    with_archive_members,
)

if TYPE_CHECKING:
    from packextras import ExtraPlacement

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


def _normalize(destination: str, fold: bool = True) -> str:
    """Comparable form of a destination, since layers write it differently.

    Case is folded only where the platform's filesystem folds it: on Linux
    RetroDECK ships bios/DISK.ROM and bios/disk.rom side by side.
    """
    cleaned = destination.strip().strip("/").replace("\\", "/")
    return cleaned.casefold() if fold else cleaned


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
            dest = entry.get("destination") or entry.get("name") or ""
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
    standalone_cores: set[str] | None = None,
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
    standalone_cores = standalone_cores or set()
    placement = None
    if config is not None:
        from packextras import ExtraPlacement  # noqa: PLC0415

        placement = ExtraPlacement(config, base_dest, profiles)
    claims: list[Claim] = []
    for emu_name, profile in sorted(profiles.items()):
        if profile.get("type") in ("launcher", "alias"):
            continue
        # The gap report skips a filename-agnostic profile whole: the builder
        # carries its scan candidates, never its named entries.
        if profile.get("bios_mode") == "agnostic":
            continue
        for profile, is_standalone in platform_layouts(emu_name, profile, standalone_cores):
            claims.extend(
                _archive_claims(
                    emu_name, profile, is_standalone, db, base_dest, placement,
                    zip_contents, data_dir_registry,
                )
            )
            for entry in profile.get("files") or []:
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
                dest = (
                    (entry.get("standalone_path") or entry.get("path"))
                    if is_standalone
                    else system_dir_path(entry, entry.get("path") or entry.get("name") or "")
                ) or entry.get("name") or ""
                if not dest:
                    continue
                if placement is None:
                    full = f"{base_dest}/{dest}" if base_dest else dest
                else:
                    placed = placement.place(
                        {
                            "profile": emu_name,
                            "system": entry.get("system"),
                            "systems": entry_system_ids(entry, profile),
                        },
                        dest,
                    )
                    if placed is None:
                        continue
                    full = placed[1]
                # The owner's own copy is the one the builder ships.
                local, status = resolve_local_file(
                    {
                        **with_archive_members(entry, profile.get("files") or []),
                        "source_profile": emu_name,
                    },
                    db,
                    zip_contents,
                    dest_hint=dest,
                    data_dir_registry=data_dir_registry,
                )
                if status == "name_exact" and _size_the_code_reads(entry, local):
                    status = SIZE_EXACT
                accepts = tuple(content_alternatives(entry, profile))
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
        parse_md5_list(entry.get(name)) if name == "md5" else entry.get(name)
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
    standalone_cores: set[str] | None,
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
        key = _normalize(claim.destination, fold)
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
    mode = config.get("verification_mode", "existence")
    rule = config.get("hash_rule", "")
    by_slot: dict[str, list[Claim]] = {}
    for claim in profile_claims(
        profiles, db, base_dest, standalone_cores, zip_contents, data_dir_registry,
        config=config,
    ):
        key = _normalize(claim.destination, fold)
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
    standalone_cores: set[str] | None = None,
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
    mode = config.get("verification_mode", "existence")
    rule = config.get("hash_rule", "")
    platform_profiles = {
        name: profiles[name] for name in resolve_platform_cores(config, profiles)
    }
    by_dest, by_slot = _slot_claims(
        config,
        platform_profiles,
        db,
        config.get("base_destination", ""),
        platform_standalone_set(config),
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


def _pinned_elsewhere(claims: list[Claim], winner: str | None) -> set[str]:
    """Emulators that pin content the served file does not carry."""
    return {
        c.emulator for c in claims
        if c.emulator and c.local_path != winner and resolution_is_hash_exact(c.status)
    }


def format_decision(decision: Decision) -> str:
    """One line naming the contested slot, the winner and the ground for it."""
    conflict = decision.conflict
    if decision.serves_both:
        winner = decision.winner.local_path
        # A claim that only matched a path is answered by whatever file sits
        # there. Only one that pins content can be left wanting.
        pinned_elsewhere = _pinned_elsewhere(conflict.profile_claims, winner)
        served = sorted({
            c.emulator for c in conflict.profile_claims if c.emulator
        } - pinned_elsewhere)
        others = sorted(pinned_elsewhere)
        line = (
            f"{conflict.destination}: serve {winner} "
            f"({', '.join(served) or 'profile'}): the frontend only "
            "checks the path, so both are satisfied"
        )
        if others:
            # One path holds one file: an emulator pinning another is not served.
            line += f"; {', '.join(others)} expected another file"
        return line
    if decision.reason == ADDRESSEE:
        return (
            f"{conflict.destination}: serve {decision.winner.local_path}, "
            "the pack answers to the emulator"
        )
    rejected = ", ".join(
        f"{path}, the file {', '.join(emulators) or 'the profile'} reads"
        for path, emulators, _status in conflict.files_read()
    )
    return (
        f"{conflict.destination}: keep {decision.winner.local_path}, the frontend "
        f"verifies content and would reject {rejected}"
    )


@dataclass
class Collision:
    """One destination a platform fills with two different files."""

    destination: str
    resolved: list[str]
    # Each declaration with the file it resolved to, in the platform's order.
    declarations: list[tuple[dict, str | None]] = field(default_factory=list)
    # The system of each declaration, in the same order.
    systems: list[str] = field(default_factory=list)
    # The file the pack ships at the destination, as the builder decides it.
    shipped: str | None = None


def _collision_json(collision: Collision) -> dict:
    return {
        "destination": collision.destination,
        "resolved": list(collision.resolved),
        "shipped": collision.shipped,
        "declarations": [
            {"system": system, "name": entry.get("name", ""), "file": local}
            for system, (entry, local) in zip(collision.systems, collision.declarations)
        ],
    }


def find_collisions(
    config: dict,
    db: dict,
    zip_contents: dict | None = None,
    data_dir_registry: dict | None = None,
) -> list[Collision]:
    """Destinations a platform declares twice and resolves two ways.

    One path holds one file, so whichever declaration the builder reaches
    first decides in silence. Declaring an archive several times to name its
    inner ROMs is the documented zipped_file pattern and resolves to one
    archive. Two declarations landing on two files name two files for one
    path. RetroDECK aims a PC-88 disk subsystem ROM and a
    CoCo disk ROM at one bios/disk.rom.
    """
    fold = bool(config.get("case_insensitive_fs", False))
    systems = config.get("systems") or {}
    # The builder lets a hash-constrained declaration that resolves by
    # content take the path, else the first it reaches walking the systems
    # sorted: the same choice says which file ships.
    preferred = set(
        preferred_entries(systems, db, "bios", "", False, zip_contents, True).values()
    )
    by_dest: dict[str, list[tuple[str, dict]]] = {}
    for sys_id, system in systems.items():
        for entry in system.get("files") or []:
            if not isinstance(entry, dict):
                continue
            dest = entry.get("destination") or entry.get("name") or ""
            if dest:
                by_dest.setdefault(_normalize(dest, fold), []).append((sys_id, entry))

    collisions = []
    for key, claims in sorted(by_dest.items()):
        if len(claims) < 2:
            continue
        entries = [entry for _sys_id, entry in claims]
        resolved = []
        declarations = []
        for entry in entries:
            local, _ = resolve_local_file(
                entry,
                db,
                zip_contents,
                dest_hint=entry.get("destination", ""),
                data_dir_registry=data_dir_registry,
            )
            declarations.append((entry, local))
            if local and local not in resolved:
                resolved.append(local)
        if len(resolved) > 1 and not _same_file_family(resolved):
            # A file every declaration accepts settles the path: RetroDECK
            # declares ATARIOSB.ROM twice, the second with an md5 list that
            # also names the first one's file.
            if any(_accepted_by_all(path, entries, db) for path in resolved):
                continue
            reached = sorted(
                (sys_id, local)
                for (sys_id, _entry), (_e, local) in zip(claims, declarations) if local
            )
            shipped = next(
                (local for entry, local in declarations if local and id(entry) in preferred),
                reached[0][1],
            )
            collisions.append(
                Collision(
                    destination=key,
                    resolved=resolved,
                    declarations=declarations,
                    systems=[sys_id for sys_id, _entry in claims],
                    shipped=shipped,
                )
            )
    return collisions


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
        shipped = _content_sha1(platform.local_path, db)
        if shipped is not None and shipped == _content_sha1(profile.local_path, db):
            return True
    members = profile.entry.get("members")
    if members and platform.local_path:
        return holds_required_members(platform.local_path, members)
    if (
        profile.local_path
        and _lists_hashes(platform.entry)
        and _accepted_by_all(profile.local_path, [platform.entry], db)
    ):
        return True
    if platform.local_path and any(
        _lists_hashes(label) and _accepted_by_all(platform.local_path, [label], db)
        for label in profile.accepts
    ):
        return True
    return bool(
        platform.local_path
        and _lists_hashes(profile.entry)
        and _accepted_by_all(platform.local_path, [profile.entry], db)
    )


def _lists_hashes(entry: dict) -> bool:
    """Whether a declaration says anything about content at all."""
    return any(
        _declared_hashes(entry, field_name)
        for field_name in ("md5", "sha1", "sha256", "crc32")
    )


def _declared_hashes(entry: dict, field_name: str) -> set[str]:
    """Hashes an entry accepts for one field, declared as a string or a list."""
    value = entry.get(field_name)
    values = value if isinstance(value, list) else [value]
    # Recalbox writes its md5 list comma separated, and profiles do the
    # same for sha256 (mesence names four BS-X dumps in one string).
    return {
        part.strip().lower()
        for v in values
        if v
        for part in str(v).split(",")
        if part.strip()
    }


def _record_at(path: str, db: dict) -> dict | None:
    """The database record stored at path, from an index built once per db.

    A scan of db['files'] on every call was O(calls x 19 000 files) on the
    path verify --all and slots.py both take.
    """
    files = db.get("files", {})
    cached = _PATH_INDEX.get(id(files))
    if cached is None or cached[0] is not files:
        cached = (files, {e.get("path"): e for e in files.values()})
        _PATH_INDEX[id(files)] = cached
    return cached[1].get(path)


_PATH_INDEX: dict[int, tuple[dict, dict[str, dict]]] = {}


def _content_sha1(path: str, db: dict) -> str | None:
    """The sha1 of the file at path, from the database or read from disk.

    A data directory cache is not in the database, so its files are hashed.
    """
    record = _record_at(path, db)
    if record is not None:
        return record.get("sha1")
    if not os.path.isfile(path):
        return None
    return compute_hashes(path, frozenset({"sha1"}))["sha1"]


def _accepted_by_all(path: str, entries: list[dict], db: dict) -> bool:
    """Whether every declaration's own hashes accept the file at path."""
    record = _record_at(path, db)
    if record is None:
        return False
    for entry in entries:
        if entry.get("zipped_file"):
            declared = parse_md5_list(entry.get("md5"))
            if declared and not any(
                check_inside_zip(path, entry["zipped_file"], m) == "ok" for m in declared
            ):
                return False
            continue
        for field_name in ("md5", "sha1", "sha256", "crc32"):
            declared = _declared_hashes(entry, field_name)
            if declared and str(record.get(field_name, "")).lower() not in declared:
                if field_name == "crc32" and _headerless_crc32(path, record, entry) in declared:
                    continue
                return False
    return True


COPIER_HEADER = 512


def _headerless_crc32(path: str, record: dict, entry: dict) -> str | None:
    """The crc32 of a file past its 512-byte copier header, when the entry
    declares both the file's size and the size without the header.

    Geargrafx drops the header when the file is 512 bytes over the expected
    size and computes the crc32 on the rest (src/media.cpp:754-773). The
    profile lists both sizes. EmuELEC's headered syscard3.pce (crc32
    64f78e3c) is the 6d9a73ef image the profile names.
    """
    sizes = entry.get("size")
    declared = sizes if isinstance(sizes, list) else [sizes]
    size = record.get("size")
    if not isinstance(size, int) or not {size, size - COPIER_HEADER} <= set(declared):
        return None
    try:
        with open(path, "rb") as f:
            f.seek(COPIER_HEADER)
            return f"{zlib.crc32(f.read()):08x}"
    except OSError:
        return None


def _same_file_family(paths: list[str]) -> bool:
    """Whether the paths are one file and its own pinned variants.

    A platform list built on an older romset pins bytes the primary no longer
    carries, which the repository keeps side by side under .variants. That is
    the documented multi-version case, not two machines fighting for a path.
    """
    canonical = set()
    for path in paths:
        if "/.variants/" in path:
            directory, _, name = path.rpartition("/")
            directory = directory[: -len("/.variants")]
            name = variant_base_name(name)
            path = f"{directory}/{name}"
        canonical.add(path.casefold())
    return len(canonical) == 1


def format_collision(collision: Collision) -> str:
    """One line naming the destination, which system declares which file,
    and the one the pack ships there."""
    owners: dict[str, list[str]] = {}
    for system, (_entry, local) in zip(collision.systems, collision.declarations):
        if local and system not in owners.setdefault(local, []):
            owners[local].append(system)
    parts = [
        f"{path} ({', '.join(owners[path])}) "
        + ("packed" if path == collision.shipped else "left out")
        for path in collision.resolved
    ]
    return f"{collision.destination}: " + ", ".join(parts)


def format_conflict(conflict: Conflict) -> str:
    """One line per conflict, naming both answers and who gave them."""
    emus = ", ".join(conflict.emulators) or "profile"
    return (
        f"{conflict.destination}: pack ships {conflict.platform_claim.local_path} "
        f"({conflict.platform_claim.status}), {emus} says "
        f"{conflict.profile_claims[0].local_path} "
        f"({conflict.profile_claims[0].status})"
    )


def scan_platform(
    platform: str, profiles: dict, db: dict, platforms_dir: str = "platforms",
    target_cores: set[str] | None = None,
) -> list[Conflict]:
    """Conflicts on one platform, using the cores that platform actually runs."""
    from common import load_platform_config, resolve_platform_cores

    config = load_platform_config(platform, platforms_dir)
    keys = resolve_platform_cores(config, profiles, target_cores=target_cores)
    relevant = {k: profiles[k] for k in keys if k in profiles}
    # The same evidence the builder and the verifier resolve with: without
    # the ZIP index and the data-directory registry the arbitration judged
    # with less than the tools that read its verdict.
    return find_conflicts(
        config,
        relevant,
        db,
        config.get("base_destination", ""),
        platform_standalone_set(config),
        build_zip_contents_index(db),
        load_data_dir_registry(platforms_dir),
    )


def main() -> int:
    import argparse
    import json

    from common import (
        build_target_cores_cache,
        list_registered_platforms,
        load_database,
        load_emulator_profiles,
        load_platform_config,
        require_platform,
    )

    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Report destinations where an emulator profile contradicts "
        "the file a platform baseline would ship.",
    )
    parser.add_argument(
        "--platform", "-p", type=platform_arg,
        help="one platform instead of all",
    )
    parser.add_argument(
        "--db", default="database.json",
        help="database file to read (default: %(default)s)",
    )
    parser.add_argument(
        "--platforms-dir", default="platforms",
        help="platform YAML directory (default: %(default)s)",
    )
    parser.add_argument(
        "--emulators-dir", default="emulators",
        help="emulator profile directory (default: %(default)s)",
    )
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument(
        "--target", "-t", help="judge only the cores a hardware target builds",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit 1 on any contested destination or destination declared twice; "
        "without it the run reports them and exits 0",
    )
    args = parser.parse_args()
    from common import work_from_repo_root  # noqa: PLC0415

    work_from_repo_root(args, parser, ["db", "platforms_dir", "emulators_dir"])

    import contextlib

    from common import load_data_dir_registry
    from refresh_data_dirs import hold_data_dirs

    # Claims resolve against data/: the trees stay put until the process
    # ends, which releases the hold.
    held = contextlib.ExitStack()
    hold_data_dirs(held, load_data_dir_registry(args.platforms_dir))

    db = load_database(args.db)
    profiles = load_emulator_profiles(args.emulators_dir)
    if args.platform:
        require_platform(args.platform, args.platforms_dir)
    names = (
        [args.platform]
        if args.platform
        else list_registered_platforms(args.platforms_dir)
    )
    target_cores: dict[str, set[str] | None] = {}
    if args.target:
        try:
            target_cores, names = build_target_cores_cache(
                names, args.target, args.platforms_dir, is_all=not args.platform
            )
        except (FileNotFoundError, ValueError) as exc:
            parser.error(str(exc))

    found: dict[str, list[Conflict]] = {}
    collided: dict[str, list[Collision]] = {}
    for name in names:
        conflicts = scan_platform(
            name, profiles, db, args.platforms_dir, target_cores.get(name)
        )
        if conflicts:
            found[name] = conflicts
        collisions = find_collisions(
            load_platform_config(name, args.platforms_dir),
            db,
            build_zip_contents_index(db),
            load_data_dir_registry(args.platforms_dir),
        )
        if collisions:
            collided[name] = collisions

    if args.json:
        # --strict gates on collisions too, so a document that carries only
        # conflicts hands a consumer an empty answer and a non-zero exit.
        payload = {
            "conflicts": {
                platform: [
                    {
                        "destination": c.destination,
                        "ships": c.platform_claim.local_path,
                        "ships_evidence": c.platform_claim.status,
                        "emulators": c.emulators,
                        "expected": [
                            {"file": path, "evidence": status, "emulators": emulators}
                            for path, emulators, status in c.files_read()
                        ],
                    }
                    for c in conflicts
                ]
                for platform, conflicts in found.items()
            },
            "collisions": {
                platform: [_collision_json(c) for c in platform_collisions]
                for platform, platform_collisions in collided.items()
            },
        }
        print(json.dumps(payload, indent=2))
    else:
        fixable = 0
        for platform, conflicts in found.items():
            config = load_platform_config(platform, args.platforms_dir)
            mode = config.get("verification_mode", "existence")
            print(f"{platform}: {len(conflicts)} contradicted [{mode}]")
            for conflict in conflicts:
                decision = arbitrate(conflict, mode, rule=config.get("hash_rule", ""))
                fixable += decision.serves_both
                print(f"  {format_decision(decision)}")
        total = sum(len(c) for c in found.values())
        for platform, collisions in collided.items():
            print(f"{platform}: {len(collisions)} destinations declared twice")
            for collision in collisions:
                print(f"  {format_collision(collision)}")
        # The totals close the run, collisions counted: printed before that
        # section, they were not the last word and left it out.
        doubled = sum(len(c) for c in collided.values())
        print(
            f"\n{total} contested destinations. {fixable} the pack settles on "
            f"its own, {total - fixable} follow the platform's list. "
            f"{doubled} destinations declared twice."
        )
        if not args.strict and (total or doubled):
            print(
                "Reported, not failed: the remainder changes when the platform's "
                "list does, which no build can do. Use --strict to gate on them."
            )

    return 1 if ((found or collided) and args.strict) else 0


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
