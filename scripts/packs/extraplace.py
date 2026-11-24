"""Where a core extra lands in a pack and which extra takes a destination."""

from __future__ import annotations

from core.paths import declared_destination, sanitize_pack_path
from model.declarations import OUTER_ROOTS, declared_root, outer_layout
from model.profiles import entry_system_ids, lists_files, profile_names
from packs.paths import libretro_systems, save_destination, save_layout
from resolve.archives import archive_members
from resolve.launches import PlatformLaunches
from resolve.layout import core_system_dirs, system_dir_path
from resolve.standalone import platform_layouts


def detect_extras_prefix(config: dict, base_dest: str) -> str:
    """The prefix core-extra destinations take (may be empty).

    When base_destination is empty (RetroDECK), it is the dominant root of
    the YAML-declared destinations.
    """
    return base_dest or declared_root(config)


def extra_full_destination(fe: dict, prefix: str) -> str:
    """Where a pack writes a core extra, from the pack root.

    A file the core reads below the frontend's save directory goes to the
    pack path its placement recorded (ExtraPlacement.place). Any other one
    goes below the platform's prefix, unless its destination carries it.
    The builder, the manifest and verify's replay all read this.
    """
    if fe.get("root") == "save":
        return str(fe.get("pack_path") or "")
    if fe.get("unprefixed"):
        # A path of the install tree outside the BIOS folder (AmberELEC's
        # pico-8/ beside bios/): no platform prefix in front.
        return declared_destination(fe)
    if fe.get("root") in OUTER_ROOTS:
        return outer_destination(
            fe["root"], declared_destination(fe)
        )
    return prefixed_destination(
        declared_destination(fe), prefix
    )


def outer_destination(root: str, dest: str) -> str:
    """The key of a destination below the roms or an emulator folder.

    Kept apart from the BIOS tree's paths and never written into a pack:
    the pack is extracted into the BIOS folder, and the installer places
    these files (``root: roms``, ``root: emulators``).
    """
    return f"{root}:{dest}"


def prefixed_destination(dest: str, prefix: str) -> str:
    """A core extra's destination from the pack root.

    The one rule the collector, the builder and the manifest place a file
    by. DuckStation's standalone `bios/<name>` on Recalbox lands in the
    `bios` folder itself: deduplicated at `bios/bios/<name>` but written at
    `bios/<name>`, it let PCSX2's scan claim the same path under another
    key, and `--region` withdrew one claim while the other kept the file.
    """
    if not dest or not prefix or dest.startswith(f"{prefix}/"):
        return dest
    return f"{prefix}/{dest}"


def extra_region_key(fe: dict, prefix: str) -> str:
    """The key a core extra is grouped, dropped and held under by --region.

    Its destination with the BIOS directory the platform writes in front of
    its own (declared_root): RetroDECK declares bios/scph5501.bin, and
    Beetle PSX's scph5501.bin grouped bare was looked up under another key,
    kept by the pack while the declaration of the same file was dropped,
    and the installer, which records the path once, dropped it.
    """
    return prefixed_destination(
        declared_destination(fe), prefix
    )


def save_entry_fields(fe: dict) -> dict:
    """What a manifest entry adds for a file read below the save directory.

    ``root: save`` puts its ``dest`` below the frontend's save directory,
    laid out as the pack lays it out. ``core_folder`` is the core's
    library_name when the platform's frontend inserts it as the first folder
    of ``dest`` (RetroArch's sort_savefiles_enable): the installer drops it
    where the frontend's own config turns sorting off.
    """
    fields = {"root": "save"}
    if fe.get("core_folder"):
        fields["core_folder"] = str(fe["core_folder"])
    return fields


def save_manifest_dest(fe: dict) -> str:
    """A manifest dest for a file read below the save directory.

    The pack path below the platform's save folder when the file is placed
    (``save_dest``), the system's folder first where the launcher keeps one
    per system, the core's own folder first where the frontend sorts saves
    by core.
    Without a save folder (an omission), the same shape: the core's folder,
    then the path the core reads, so two cores reading one name below their
    own folders stay two entries.
    """
    if fe.get("save_dest"):
        return str(fe["save_dest"])
    rel = sanitize_pack_path(fe.get("destination") or fe.get("path") or fe.get("name", ""))
    folder = fe.get("core_folder")
    return f"{folder}/{rel}" if folder else rel


def _detect_slug_structure(config: dict) -> tuple[bool, dict[str, str]]:
    """Detect whether a platform uses per-system slug destinations.

    Returns ``(is_slug_based, system_to_slug)`` where ``system_to_slug``
    maps system IDs to their destination slug prefix.  Slug-based means
    each system's files live under a per-system subfolder (e.g. RomM's
    ``bios/{platform_slug}/{file}``), with varying slugs across systems.

    Only returns True when nearly ALL destinations have a subfolder and
    nearly ALL systems map to a consistent slug, distinguishing true
    slug-based layouts (RomM) from platforms that happen to have some
    subfoldered files (RetroArch ``dc/``, ``neocd/``).
    """
    total_files = 0
    files_with_slash = 0
    sys_to_slug: dict[str, str] = {}
    total_systems_with_files = 0
    for sys_id, sys_data in config.get("systems", {}).items():
        files = sys_data.get("files", [])
        if not files:
            continue
        total_systems_with_files += 1
        slugs: set[str] = set()
        for f in files:
            d = f.get("destination", "")
            if d:
                total_files += 1
                if "/" in d:
                    files_with_slash += 1
                    slugs.add(d.split("/", 1)[0])
        if len(slugs) == 1:
            sys_to_slug[sys_id] = slugs.pop()

    if not sys_to_slug or total_files == 0:
        return False, {}
    # All conditions must hold for slug-based detection:
    # 1. Nearly all files have a subfolder
    # 2. Multiple distinct slugs (not a constant prefix)
    # 3. Nearly all systems with files map to a slug
    # 4. Files are exactly slug/filename (depth 2), not deeper
    unique_slugs = set(sys_to_slug.values())
    all_have_slash = files_with_slash / total_files > 0.95
    varying_slugs = len(unique_slugs) > 1
    high_coverage = len(sys_to_slug) / total_systems_with_files > 0.9
    # Count files deeper than slug/filename (e.g., amiga/bios/kick.rom)
    deep_files = 0
    for sys_data in config.get("systems", {}).values():
        for f in sys_data.get("files", []):
            d = f.get("destination", "")
            if d and d.count("/") > 1:
                deep_files += 1
    shallow = deep_files / total_files < 0.05 if total_files else True
    return (all_have_slash and varying_slugs and high_coverage and shallow), sys_to_slug

def _map_emulator_to_slug(
    profile: dict,
    platform_systems: set[str],
    norm_map: dict[str, str],
    sys_to_slug: dict[str, str],
) -> str:
    """Map an emulator to a destination slug for slug-based platforms."""
    from model.systems import norm_system_id

    emu_systems = set(profile.get("systems", []))
    # Direct match
    direct = emu_systems & platform_systems
    if direct:
        target = sorted(direct)[0]
        return sys_to_slug.get(target, "")
    # Normalized match
    for es in sorted(emu_systems):
        norm = norm_system_id(es)
        if norm in norm_map:
            target = norm_map[norm]
            return sys_to_slug.get(target, "")
    return ""

def _slug_for(
    u: dict, profiles: dict, platform_systems: set, norm_map: dict, sys_to_slug: dict,
    native_systems: set | None = None,
) -> str:
    """The platform slug a report entry files under, or empty.

    The entry's own system decides, and alone: picodrive's Mega CD BIOS
    belongs under segacd/, where RomM looks for a Mega CD game's firmware,
    and a file of a system the platform lacks has no folder there (MAME
    2003's ZN-1 BIOS once fell back on its Neo Geo systems). A file of no
    system takes the emulator's first system the platform declares for
    itself: a folder present only as a mirror of another slug's firmware
    (RomM's neogeoaes/) says nothing about the emulators that read it.
    """
    own = u.get("system")
    if own:
        return _map_emulator_to_slug(
            {"systems": [own]}, platform_systems, norm_map, sys_to_slug
        )
    emu_name = u.get("profile") or u.get("emulator", "")
    # The report carries the entry's own systems: (a MAME device set) or
    # its profile's, the same list either way when the entry names none.
    profile = {"systems": u["systems"]} if u.get("systems") else profiles.get(emu_name, {})
    if not profile:
        # The report names the display name where the key failed.
        profile = next(
            (pp for pp in profiles.values() if pp.get("emulator") == emu_name), {}
        )
    systems = platform_systems if native_systems is None else native_systems
    native_norm = {k: v for k, v in norm_map.items() if v in systems}
    return _map_emulator_to_slug(profile, systems, native_norm, sys_to_slug)


def native_slug_systems(config: dict) -> set[str]:
    """Systems the platform declares at least one file of its own for."""
    return {
        sid for sid, data in (config.get("systems") or {}).items()
        if any(not f.get("mirror_of") for f in data.get("files", []))
    }


def extra_dest(u: dict) -> str:
    """Where a report entry lands before any platform prefix.

    An archive entry goes by the archive's name, and a directory path takes
    the file's name after it ("cafeLibs/" + "snd_user.rpl"). A directory
    entry ("registered/") is that path itself.
    """
    archive = u.get("archive")
    # An archive goes at the root of the core's system directory, which a
    # platform handing each core its own folder writes in the path.
    raw = (u.get("path") or archive) if archive else (u.get("path") or u["name"])
    if not raw.endswith("/") or str(u["name"]).endswith("/"):
        return raw
    return f"{raw}{u['name']}"


def archive_prefix_extras(
    profiles: dict,
    relevant: set,
    covered_names: set,
    seen_dests: set,
    extras_prefix: str,
    by_name: dict,
    taken: dict[str, dict] | None = None,
    launches: PlatformLaunches | None = None,
) -> list[dict]:
    """A second copy of an archive under the subdirectory a core reads.

    Some cores look for their romset under a directory of their own
    (system/fbneo/neogeo.zip) while the platform declares it at the
    root. Both paths are carried so the core's own check finds it.
    """
    extras: list[dict] = []
    # Archive prefix pass: cores that store BIOS archives in a subdirectory
    # (e.g. system/fbneo/neogeo.zip).  When the archive is already covered at
    # the root, add a copy at the prefixed path so the core's .info firmware
    # check finds it.
    for emu_name, profile in sorted(profiles.items()):
        if not lists_files(profile):
            continue
        if emu_name not in relevant:
            continue
        # A platform that hands each core its own system directory moves the
        # subfolder with it, once per directory.
        views = [profile]
        if core_system_dirs(emu_name, profile, launches or PlatformLaunches()) is not None:
            views = [
                view for view, standalone
                in platform_layouts(emu_name, profile, launches or PlatformLaunches())
                if not standalone
            ]
        for view in views:
            extras.extend(_archive_prefix_copies(
                emu_name, view, covered_names, seen_dests, extras_prefix,
                by_name, taken,
            ))
    return extras


def _archive_prefix_copies(
    emu_name: str,
    profile: dict,
    covered_names: set,
    seen_dests: set,
    extras_prefix: str,
    by_name: dict,
    taken: dict[str, dict] | None,
) -> list[dict]:
    """The prefixed copies of one layout's archives."""
    extras: list[dict] = []
    prefix = profile.get("archive_prefix", "")
    if not prefix:
        return extras
    profile_archives: dict[str, dict] = {}
    for f in profile.get("files", []):
        archive = f.get("archive", "")
        if archive:
            profile_archives.setdefault(archive, f)
    for archive_name, archive_entry in sorted(profile_archives.items()):
        if archive_name not in covered_names:
            continue
        dest = f"{prefix}/{archive_name}"
        full_dest = prefixed_destination(dest, extras_prefix)
        if full_dest in seen_dests and (taken is None or full_dest not in taken):
            continue
        if not by_name.get(archive_name):
            continue
        extra = {
            "name": archive_name,
            "destination": dest,
            "required": True,
            "hle_fallback": False,
            "source_emulator": profile.get("emulator", emu_name),
            "source_profile": emu_name,
            # Keyed as the gap report keys an archive: name and path alike.
            "source_name": archive_name,
            "source_path": system_dir_path(archive_entry, archive_name),
            "category": archive_entry.get("category", "bios"),
            "source_system": archive_entry.get("system"),
            "source_systems": entry_system_ids(archive_entry, profile),
            "region": archive_entry.get("region"),
            "selection_slot": archive_entry.get("selection_slot"),
        }
        members = archive_members(archive_name, profile.get("files", []))
        if members:
            extra["members"] = members
        if archive_entry.get("system_dir"):
            extra["system_dir"] = archive_entry["system_dir"]
        extra["claim_order"] = (3, 0, emu_name)
        if take(extra, full_dest, seen_dests, taken):
            extras.append(extra)

    return extras


class ExtraPlacement:
    """Where a pack puts a core's file, decided once for every reader.

    The builder, and slots.py judging what a destination holds, both read
    this: placed apart, slot arbitration compared RetroDECK's bios/ claims
    with core claims at the root and never saw them meet.
    """

    def __init__(self, config: dict, base_dest: str, profiles: dict) -> None:
        from model.systems import norm_system_id

        self.prefix = detect_extras_prefix(config, base_dest)
        self.slug_based, self.sys_to_slug = _detect_slug_structure(config)
        self.platform_systems = set(config.get("systems", {}).keys())
        self.native_systems = native_slug_systems(config)
        self.flat = bool(config.get("firmware_folder_flat"))
        self.save = save_layout(config)
        # The roms root and emulator folders the platform's files describe,
        # for a file a launcher runs from them (ROCKNIX's roms/pico-8,
        # RetroBat's emulators/pico8).
        self.outer = {root for root in OUTER_ROOTS if outer_layout(config, root)}
        self.config = config
        self.norm_map = (
            {norm_system_id(sid): sid for sid in self.platform_systems}
            if self.slug_based
            else {}
        )
        self.profiles = profiles

    def place(self, entry: dict, dest: str) -> tuple[str, str] | None:
        """(pack-relative destination, full destination), or None.

        ``entry`` names its profile and may name its own system. A
        slug-based platform cannot place a file of a system it has no
        folder for. A file the core reads below the frontend's save
        directory (``root: save``) keeps its path relative to that
        directory and goes below the platform's save folder, which a
        platform keeping saves beside the content does not have.
        """
        if entry.get("unplaced"):
            return None
        if entry.get("unprefixed"):
            return dest, dest
        if entry.get("root") in OUTER_ROOTS:
            root = entry["root"]
            return (dest, outer_destination(root, dest)) if root in self.outer else None
        if entry.get("root") == "save":
            placed = self.save_places(entry, dest)
            return placed[0] if placed else None
        if self.slug_based:
            slug = _slug_for(
                entry, self.profiles, self.platform_systems, self.norm_map,
                self.sys_to_slug, self.native_systems,
            )
            if not slug or self.nested(dest):
                return None
            dest = f"{slug}/{dest}"
        return dest, prefixed_destination(dest, self.prefix)

    def places(self, entry: dict, dest: str) -> list[tuple[str, str]]:
        """Every (pack-relative, full) destination the pack gives an entry.

        One for most entries. A file read below the save directory of a
        platform that hands each system a save folder of its own goes once
        below each system that runs the core.
        """
        if entry.get("unplaced"):
            return []
        if entry.get("root") == "save":
            return self.save_places(entry, dest)
        placed = self.place(entry, dest)
        return [placed] if placed is not None else []

    def save_places(self, entry: dict, dest: str) -> list[tuple[str, str]]:
        """The destinations of a file read below the save directory."""
        if self.save is None:
            return []
        names = self.core_names(entry)
        sorted_by_core = self.save.sorts(names)
        systems = libretro_systems(self.config, names) if self.save.by_system else [""]
        placed = []
        for system in systems:
            full = save_destination(
                dest, entry.get("core_folder"), self.save, system, sorted_by_core
            )
            if full:
                placed.append((dest, full))
        return placed

    def core_names(self, entry: dict) -> set[str]:
        """The names a report entry's core goes by: its profile key and the
        upstream names its profile lists."""
        key = entry.get("profile") or entry.get("emulator", "")
        profile: dict = self.profiles.get(key) or next(
            (pp for pp in self.profiles.values() if pp.get("emulator") == key), {}
        )
        return set(profile_names(str(key), profile)) - {""}

    def nested(self, dest: str) -> bool:
        """True when the file would sit below a folder the frontend lists flat."""
        return self.slug_based and self.flat and "/" in dest

    def unplaced_reason(self, entry: dict, dest: str) -> str:
        """Why ``place`` returned None for this entry."""
        if entry.get("unplaced"):
            return str(entry["unplaced"])
        if entry.get("root") in OUTER_ROOTS:
            return f"no_{entry['root']}_directory"
        if entry.get("root") == "save":
            if self.save is None:
                return "no_save_directory"
            if self.save.by_system and not libretro_systems(
                self.config, self.core_names(entry)
            ):
                return "no_save_system"
            return "no_core_folder"
        return "below_platform_folder" if self.nested(dest) else "no_platform_slug"


def take(
    extra: dict, full_dest: str, seen_dests: set[str], taken: dict[str, dict] | None
) -> bool:
    """Whether an extra takes its destination. A taken one records the claim."""
    if full_dest in seen_dests:
        if taken is not None:
            another_claim(taken.get(full_dest), extra)
        return False
    seen_dests.add(full_dest)
    if taken is not None:
        taken[full_dest] = extra
    return True


def another_claim(extra: dict | None, claim: dict) -> None:
    """Record a core that reads a destination another core's extra took.

    The pack ships one file per destination, so the first claimant's extra
    stands. The others are kept on it so the manifest can name every core
    the file serves. A pack built for a target without the first core packs
    the next one's copy, and an installer narrowing by core must keep it.
    """
    if extra is None or claim.get("source_profile") == extra.get("source_profile"):
        return
    claims = extra.setdefault("other_claims", [])
    claims.append(claim)
    claims.sort(key=lambda c: c["claim_order"])
