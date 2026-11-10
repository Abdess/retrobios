"""What the cores need that the platform does not declare.

A pack is the platform's own list plus the files its cores load. The
second half is derived here, and the region pass reads the grouping
this module builds so the report and the pack withdraw the same files."""

from __future__ import annotations

from collections.abc import Iterable

from common import PROFILE_IDENTITY_FIELDS, _norm_system_id, entry_system_ids
from alternatives import core_file_spares, required_only_spares, set_fields
from common import archive_members, holds_required_members
from common import declared_root, expand_platform_declared_names, platform_declarations
from common import load_emulator_profiles
from common import resolution_is_hash_exact
from common import resolve_local_file
from common import resolve_platform_cores
from common import core_system_dirs, platform_layouts, system_dir_path
from common import standalone_set as platform_standalone_set
from common import OUTER_ROOTS, outer_layout, sanitize_pack_path
from common import size_fits
from validation import deliverable, read_from_save_dir, read_from_system_dir
from packpaths import libretro_systems, save_destination, save_layout
from region import FILE_GROUP


def _detect_extras_prefix(config: dict, base_dest: str) -> str:
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
        return sanitize_pack_path(fe.get("destination", fe.get("name", "")))
    if fe.get("root") in OUTER_ROOTS:
        return outer_destination(
            fe["root"], sanitize_pack_path(fe.get("destination", fe.get("name", "")))
        )
    return prefixed_destination(
        sanitize_pack_path(fe.get("destination", fe.get("name", ""))), prefix
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
        sanitize_pack_path(fe.get("destination", fe.get("name", ""))), prefix
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
    from common import _norm_system_id

    emu_systems = set(profile.get("systems", []))
    # Direct match
    direct = emu_systems & platform_systems
    if direct:
        target = sorted(direct)[0]
        return sys_to_slug.get(target, "")
    # Normalized match
    for es in sorted(emu_systems):
        norm = _norm_system_id(es)
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


def _file_sha1(path: str) -> str | None:
    """sha1 of a copy the database does not index, a data tree's file."""
    from hashing import compute_hashes

    try:
        return compute_hashes(path, frozenset({"sha1"}))["sha1"]
    except OSError:
        return None


class ExtraResolver:
    """How the builder finds the copy of a core's file it packs.

    The builder and verify's replay of its placement must look the file up
    the same way: by the storage-aware resolver with the archive index and
    the data directories, then through the core's own check. verify once
    looked up by name alone and compared other bytes than the pack's
    (blueMSX's MSX2P.rom from bios/ against the data tree's copy).
    """

    def __init__(
        self,
        db: dict,
        bios_dir: str,
        zip_contents: dict | None,
        data_registry: dict | None,
        validation_index: dict,
        validation_owners: dict | None,
        offline: bool | None = True,
        *,
        profiles: dict,
        pending_assets: bool = False,
    ) -> None:
        self.profiles = profiles
        self.db = db
        self.bios_dir = bios_dir
        self.zip_contents = zip_contents
        self.data_registry = data_registry
        self.validation_index = validation_index
        self.validation_owners = validation_owners
        self.offline = offline
        # verify's replay: never downloads, and counts the release asset an
        # online build fetches, as it does for a platform entry.
        self.pending_assets = pending_assets
        # Each profile's entries by slot, built on first use: every extra
        # scanned its whole profile, 33 million entries in one verify --all.
        self._slots: dict[str, dict[tuple[str, str], list[dict]]] = {}

    def alternatives(self, fe: dict) -> list[dict]:
        """The versions the extra's own profile accepts at its slot, as
        validation.extra_alternatives finds them."""
        from validation import slot_index

        key = fe.get("source_profile") or ""
        index = self._slots.get(key)
        if index is None:
            profile = (self.profiles or {}).get(key, {})
            index = self._slots[key] = slot_index(profile.get("files") or [])
        name = fe.get("source_name") or fe.get("name", "")
        return index.get((name, fe.get("source_path") or name), [])

    def resolve(self, fe: dict, dest: str) -> tuple[str | None, str, str]:
        """(local copy or None, resolver status, the core's disagreement)."""
        from packresolve import pending_release_asset, resolve_file, run_is_offline
        from validation import core_size_refusal, validated_choice

        local_path, status = resolve_file(
            fe, self.db, self.bios_dir, self.zip_contents,
            dest_hint=fe.get("destination", ""),
            data_dir_registry=self.data_registry, offline=self.offline,
        )
        if (
            self.pending_assets and status in ("not_found", "hash_mismatch")
            and not run_is_offline()
        ):
            # The asset the online builder fetches in resolve_file. Its record
            # answers the declaration, and there are no bytes on disk to check.
            asset = pending_release_asset(fe, self.db)
            if asset:
                return asset, "release_asset", ""
        if status in ("not_found", "external", "user_provided") or not local_path:
            return None, status, ""
        # The cores reading a moved layout's file are found under the
        # emulator's own path, not the folder the platform put it in.
        local_path, disagreement = validated_choice(
            fe, local_path, self.db, self.validation_index, self.bios_dir, None,
            fe.get("layout_path") or dest, self.validation_owners,
        )
        # The platform never reads the bytes, the core does: a copy it turns
        # away by its own size check is not its file, on any platform.
        if core_size_refusal(fe, local_path, self.alternatives(fe)):
            return None, "not_found", ""
        return local_path, status, disagreement


def hidden_extras(
    config: dict,
    emulators_dir: str,
    db: dict,
    profiles: dict,
    shipped: dict[str, str | None],
    target_cores: set[str] | None = None,
    region_drops: set[str] | None = None,
    placed: set[str] | None = None,
    report: list[dict] | None = None,
    resolver: ExtraResolver | None = None,
    placed_kind: dict[str, str] | None = None,
    placed_local: dict[str, str] | None = None,
    system_ids: list[str] | None = None,
    include_all: bool = False,
    required_only: bool = False,
) -> dict[tuple[str, str, str], str]:
    """Report entries the builder holds and still leaves out, with the reason.

    A destination the region pass withdraws never takes its path in the
    pack, so it blocks nothing here either.

    The builder walks the core extras after the platform's own files and
    skips a destination that a case-insensitive filesystem folds onto one
    already packed, or that a packed file blocks as a directory. RetroPie's
    openmsx fmpac.rom gave way to the platform's FMPAC.ROM, other bytes,
    while the report counted it in the pack. A twin carrying the same bytes
    serves the core on the filesystem that folds the names, so it is not a
    file left out. ``shipped`` maps the full destination of each platform
    file the pack carries to its local copy, or to None for a slot it keeps
    without one (user_provided, external). ``placed``, when given,
    receives the full destination of each held extra the pack carries, and
    ``placed_kind`` its category, carried by the extra itself: the second
    pass, the archive-prefix pass and the agnostic scan copy files no gap
    report entry names. ``placed_local`` receives the local copy the builder
    writes at each of those destinations, for the pack integrity check.
    ``system_ids`` replays a pack built with --system: the extras collected
    without the platform's paths, then those the systems own.
    ``resolver`` is the builder's lookup. An extra it cannot resolve is
    skipped and takes no path, as the builder skips it. ``include_all`` and
    ``required_only`` are the builder's for a --source truth or a
    --required-only pack: an optional extra is skipped before it takes a path.
    """
    from packpaths import _register_path, placement_block

    sha1_by_path = {
        entry.get("path"): sha1 for sha1, entry in db.get("files", {}).items()
    }
    base_dest = config.get("base_destination", "")
    case_insensitive = bool(config.get("case_insensitive_fs", False))
    seen: set[str] = set()
    parents: set[str] = set()
    content: dict[str, str | None] = {}
    for dest, local in shipped.items():
        _register_path(dest, seen, parents)
        content[dest.lower()] = sha1_by_path.get(local)
    lower = set(content) if case_insensitive else set()
    prefix = _detect_extras_prefix(config, base_dest)
    region_prefix = declared_root(config)
    hidden: dict[tuple[str, str, str], str] = {}
    packed_keys: set[tuple[str, str, str]] = set()
    extras = _collect_emulator_extras(
        config, emulators_dir, db, set() if system_ids else set(shipped),
        base_dest, profiles, target_cores=target_cores, include_all=include_all,
        undeclared=report,
    )
    if system_ids:
        extras = extras_for_systems(extras, system_ids)
    spares = core_file_spares(
        extras,
        lambda fe: extra_region_key(fe, region_prefix) in (region_drops or set()),
    ) if required_only else set()
    for fe in extras:
        if required_only and (fe.get("required") is False or id(fe) in spares):
            continue
        dest = sanitize_pack_path(fe.get("destination", fe.get("name", "")))
        if not dest or (region_drops and extra_region_key(fe, region_prefix) in region_drops):
            continue
        if fe.get("root") in OUTER_ROOTS:
            # As the builder does: the pack is extracted into the BIOS folder
            # and cannot reach the roms, emulator or configs folder, the
            # installer places these files.
            continue
        full = extra_full_destination(fe, prefix)
        if not full:
            continue
        reason = placement_block(full, seen, lower, parents, case_insensitive)
        if reason == "taken":
            # Another core's claim on the same path, settled by the claims
            # the collector records: not a file left out.
            continue
        if resolver is not None:
            local, _status, _disagreement = resolver.resolve(fe, dest)
            if not local:
                continue
        else:
            local, _status = resolve_local_file(
                fe, db, dest_hint=fe.get("destination", "")
            )
        held = (sha1_by_path.get(local) or _file_sha1(local)) if local else None
        if reason == "case_twin" and held and content.get(full.lower()) == held:
            continue
        key = (
            fe.get("source_emulator", ""), fe.get("source_name", ""),
            fe.get("source_path", ""),
        )
        if reason is not None:
            hidden.setdefault(key, reason)
            continue
        packed_keys.add(key)
        _register_path(full, seen, parents)
        content[full.lower()] = held
        if case_insensitive:
            lower.add(full.lower())
        if placed is not None and local:
            placed.add(full)
        if placed_kind is not None and local:
            placed_kind[full] = fe.get("category", "bios")
        if placed_local is not None and local:
            placed_local[full] = local
    # A file read below a save directory kept per system is packed once per
    # system: one copy left out does not leave the file out.
    return {key: reason for key, reason in hidden.items() if key not in packed_keys}


def _extra_dest(u: dict) -> str:
    """Where a report entry lands before any platform prefix.

    An archive entry goes by the archive's name, and a directory path takes
    the file's name after it ("cafeLibs/" + "snd_user.rpl").
    """
    archive = u.get("archive")
    # An archive goes at the root of the core's system directory, which a
    # platform handing each core its own folder writes in the path.
    raw = (u.get("path") or archive) if archive else (u.get("path") or u["name"])
    return f"{raw}{u['name']}" if raw.endswith("/") else raw


def unplaceable_extras(
    config: dict, undeclared: list[dict], profiles: dict
) -> dict[tuple[str, str, str], str]:
    """The report entries a slug-based platform cannot place, with the reason.

    RomM files every BIOS under the slug of its system and knows no slug
    for DOS or for the arcade sets MAME 2003 reads, and it lists each folder
    flat. The builder skipped those entries and the report counted them in
    the pack. The answer comes from the builder's own placement.
    """
    placement = ExtraPlacement(config, "", profiles)
    unplaced: dict[tuple[str, str, str], str] = {}
    for u in undeclared:
        if not u.get("in_repo") and not u.get("unplaced"):
            continue
        if (not placement.slug_based and u.get("root") not in ("save", *OUTER_ROOTS)
                and not u.get("unplaced")):
            continue
        dest = _extra_dest(u)
        if not placement.places(u, dest):
            key = (u.get("emulator", ""), u.get("name", ""), u.get("path") or "")
            unplaced[key] = placement.unplaced_reason(u, dest)
    return unplaced


def _agnostic_scan_extras(
    profiles: dict,
    relevant: set,
    db: dict,
    by_name: dict,
    seen_dests: set,
    extras_prefix: str,
    standalone_set: set[str] | None = None,
    taken: dict[str, dict] | None = None,
    all_profiles: dict | None = None,
) -> list[dict]:
    """Every interchangeable candidate a filename-agnostic core accepts.

    Such a core reads whatever sits in its BIOS directory, so the pack
    carries every dump of the right shape rather than one chosen name.
    The directory is the delicate part: anchoring it on a single
    filename walked into another emulator's tree, so the profile's own
    files have to agree before the scan follows an ambiguous name.
    ``all_profiles`` are the profiles a placeholder's directory is proven
    from, ``profiles`` when not given.
    """
    extras: list[dict] = []
    files_db = db.get("files", {})
    # Third pass: the agnostic scan. For filename-agnostic cores, include all
    # DB files matching the system path prefix and size criteria.
    for emu_name, profile in sorted(profiles.items()):
        if profile.get("type") in ("launcher", "alias"):
            continue
        if emu_name not in relevant:
            continue
        is_profile_agnostic = profile.get("bios_mode") == "agnostic"
        if not is_profile_agnostic:
            if not any(f.get("agnostic") for f in profile.get("files", [])):
                continue

        # Where each of this profile's files resolves.  A scan anchored on one
        # filename walks into whatever tree that name happens to hit: rom1.bin
        # is a PS2 ROM and a Roland SC-55 ROM, GameIndex.yaml belongs to four
        # PS2 profiles and to an Android package.  One match is not evidence
        # of a directory, two files of the same profile agreeing is.
        resolved_dirs: dict[int, str] = {}
        named_only: set[int] = set()
        agnostic_votes: dict[str, int] = {}
        for candidate in profile.get("files", []):
            if not isinstance(candidate, dict):
                continue
            local, status = resolve_local_file(
                {**candidate, "source_profile": emu_name},
                db,
                dest_hint=candidate.get("path", ""),
            )
            if not local or "/" not in local:
                continue
            directory = local.rsplit("/", 1)[0]
            if directory.endswith("/.variants"):
                directory = directory[: -len("/.variants")]
            resolved_dirs[id(candidate)] = directory + "/"
            if not (resolution_is_hash_exact(status) or status == "path_exact"):
                named_only.add(id(candidate))
            agnostic_votes[directory + "/"] = (
                agnostic_votes.get(directory + "/", 0) + 1
            )

        own = profile
        for profile, standalone in platform_layouts(emu_name, own, standalone_set or set()):
            # A layout copies each entry in order (a launcher's folder, a
            # system directory): its files are looked up as the profile's
            # own, or a bound layout scans nothing (KNULLI's bios/ps2).
            origin = {
                id(view): entry
                for view, entry in zip(profile.get("files", []), own.get("files", []))
            }
            for f in profile.get("files", []):
                if not is_profile_agnostic and not f.get("agnostic"):
                    continue
                fname = f.get("name", "")
                if not fname:
                    continue
                # A file of the build the platform does not run seeds nothing:
                # armsx2's proverb.zip is fetched by the Android app into its own
                # arcade/ folder, and the libretro packs carried it at system/.
                mode = f.get("mode")
                if (mode == "standalone" and not standalone) or (
                    mode == "libretro" and standalone
                ):
                    continue
                # The scan walks the BIOS tree: a file read below the save
                # directory is placed by the gap report's pass.
                if (read_from_save_dir(f, standalone) or f.get("unplaced")
                        or f.get("root") in OUTER_ROOTS or f.get("unprefixed")):
                    continue
                # An agnostic BIOS mode says the BIOS filename is free, not that
                # every file the emulator loads is.  A free filename still has a
                # known shape, and that shape is what identifies a candidate: an
                # entry declaring no size takes the whole directory, which is how
                # the flag icons of an Android package walked into a PS2 pack.
                if f.get("category", "bios") != "bios":
                    continue
                if not (f.get("size") or f.get("min_size") or f.get("max_size")):
                    continue
                # The free name is the BIOS directory's: a shader, a sound or a
                # font the emulator reads from its resources tree has a fixed
                # name and must not seed a scan (yaps2 flattened 189 of them to
                # the root of the RetroArch pack).
                bios_dir = profile.get("bios_directory")
                fpath = f.get("path") or ""
                if bios_dir and "/" in fpath and not fpath.startswith(bios_dir):
                    continue

                # A companion is read under its image's name with the
                # extension the code appends, in that case: only a file of
                # that extension is one, spelled as the code spells it. Its
                # size identifies nothing, PCSX2 reads min(size, filesize)
                # (BiosTools.cpp:234), and a 4 MB bound swept every smaller
                # file of the folder to the BIOS root. It sits beside its
                # image, so the scan looks where the image resolves: the
                # held ps2-0230a-20080220.rom1 is a DVD firmware dump filed
                # under DVD Firmware/.
                companion_ext, image = _companion_of(profile, fname)

                path_prefix = (
                    resolved_dirs.get(id(origin.get(id(image), image)), "") if image
                    else resolved_dirs.get(id(origin.get(id(f), f)), "")
                )
                # A placeholder (<bios>.bin) resolves to nothing and anchors no
                # directory. The folders where the system's other profiles
                # resolve hashed files of that shape do, those folders only:
                # LRPS2 and PCEE2 are made of placeholders, and on Batocera,
                # where no other libretro PS2 core anchors pcsx2/bios/, the
                # pack held nothing there. A companion (<bios>.nvm) looks
                # where its image is proven: RetroBat's pcsx2/bios/ had
                # scph39001.bin and its .nvm only at the BIOS root.
                exact_dirs: frozenset[str] = frozenset()
                anchor = image if image else f
                if not path_prefix and "<" in str(anchor.get("name", "")):
                    exact_dirs = placeholder_directories(
                        anchor, emu_name, profile, db, all_profiles or profiles
                    )
                if not path_prefix and not exact_dirs:
                    continue
                # A name matching one file identifies it. A name matching several
                # identifies nothing on its own, so the profile's other files have
                # to agree on the directory before the scan walks it.
                ambiguous = (
                    id(origin.get(id(f), f)) in named_only
                    and len(by_name.get(fname, [])) > 1
                )
                if ambiguous and agnostic_votes.get(path_prefix, 0) < 2:
                    continue

                # Scan DB for all files under this prefix matching size
                for sha1, entry in files_db.items():
                    path = entry.get("path", "")
                    if exact_dirs:
                        if ("/" not in path or path.rsplit("/", 1)[0] not in exact_dirs
                                or "/.variants/" in path):
                            continue
                    elif not path.startswith(path_prefix):
                        continue
                    if not companion_ext and not size_fits(f, entry.get("size", 0)):
                        continue
                    scan_name = entry.get("name", "")
                    if not scan_name:
                        continue
                    if companion_ext:
                        stem, _, ext = scan_name.rpartition(".")
                        if not stem or ext.lower() != companion_ext.lower():
                            continue
                        scan_name = f"{stem}.{companion_ext}"
                    # Into the directory the seed entry names, not the root:
                    # yaps2 reads its BIOS from pcsx2/bios/.
                    seed = f.get("path") or ""
                    if standalone:
                        seed = f.get("standalone_path") or seed
                    else:
                        seed = system_dir_path(f, seed or fname)
                    folder = seed.rsplit("/", 1)[0] if "/" in seed else ""
                    dest = f"{folder}/{scan_name}" if folder else scan_name
                    full_dest = prefixed_destination(dest, extras_prefix)
                    if full_dest in seen_dests and (taken is None or full_dest not in taken):
                        continue
                    extra = {
                        "name": scan_name,
                        "destination": dest,
                        # The scan already holds the entry it selected, so it
                        # names it by content.  Emitting the filename alone
                        # sent the packing step back to a by-name lookup, and
                        # three PS2 resources came back from another
                        # emulator's copy of the same filename.
                        "sha1": sha1,
                        "required": False,
                        "hle_fallback": False,
                        "source_emulator": profile.get("emulator", emu_name),
                        "source_profile": emu_name,
                        "source_name": fname,
                        "source_path": f.get("path") or "",
                        "category": f.get("category", "bios"),
                        "source_system": f.get("system"),
                        "source_systems": entry_system_ids(f, profile),
                        "region": f.get("region"),
                        "selection_slot": f.get("selection_slot"),
                        "agnostic_scan": True,
                    }
                    extra["claim_order"] = (4, 0, emu_name)
                    if _take(extra, full_dest, seen_dests, taken):
                        extras.append(extra)
                    else:
                        # The image another core's scan placed is this core's
                        # too, and so are the companions it reads beside it:
                        # Recalbox's libretro PCSX2 opens <bios>.erom next to
                        # the images LRPS2 placed, which LRPS2 never reads.
                        held = taken.get(full_dest) if taken is not None else None
                        if held is None or held.get("sha1") != sha1:
                            continue
                    extras.extend(_companion_extras(
                        _companions(path, scan_name, _companion_extensions(profile, fname), files_db),
                        folder, extras_prefix, seen_dests, profile, emu_name, f, taken,
                    ))
    return extras


def placeholder_directories(
    seed: dict, emu_name: str, profile: dict, db: dict, all_profiles: dict,
) -> frozenset[str]:
    """The folders that hold the dumps a placeholder entry accepts.

    Each folder where another profile of the same system resolves a hashed
    file of the seed's shape by content: PCSX2 proves bios/Sony/PlayStation 2/.
    Only that folder, not the ones below it (its DVD firmware).
    """
    systems = set(profile.get("systems", []))
    directories: set[str] = set()
    for other_name, other in all_profiles.items():
        if other_name == emu_name or not systems & set(other.get("systems", [])):
            continue
        for f in other.get("files", []):
            if not isinstance(f, dict) or not any(f.get(h) for h in ("sha1", "md5", "sha256", "crc32")):
                continue
            if f.get("size") and not size_fits(seed, f["size"]):
                continue
            local, status = resolve_local_file({**f, "source_profile": other_name}, db)
            if local and "/" in local and resolution_is_hash_exact(status):
                directories.add(local.rsplit("/", 1)[0])
    return frozenset(directories)


def _placeholder_scan(
    files: list[dict], emu_name: str, profile: dict, db: dict, standalone: bool,
    all_profiles: dict | None = None,
) -> list[dict]:
    """The dumps a profile made of placeholders accepts, found by evidence.

    `<bios>.bin` resolves to nothing, so it anchors no directory. The folder
    where other profiles of the same system resolve their hashed files of
    that shape is one: PCSX2 proves bios/Sony/PlayStation 2/ by content, and
    LRPS2 reads any 4-8 MB image. Only that folder, not the ones below it
    (its DVD firmware). Nothing proven, nothing scanned.
    """
    files_db = db.get("files", {})
    extras: list[dict] = []
    for seed in files:
        name = str(seed.get("name", ""))
        if "<" not in name or seed.get("category", "bios") != "bios":
            continue
        if not (seed.get("size") or seed.get("min_size") or seed.get("max_size")):
            continue
        directories = placeholder_directories(
            seed, emu_name, profile, db,
            all_profiles or load_emulator_profiles("emulators"),
        )
        layout = (seed.get("standalone_path") if standalone else None) or seed.get("path") or ""
        folder = layout.rsplit("/", 1)[0] if "/" in layout else ""
        for sha1, entry in sorted(files_db.items(), key=lambda kv: kv[1].get("path", "")):
            path = entry.get("path", "")
            if "/" not in path or path.rsplit("/", 1)[0] not in directories:
                continue
            if "/.variants/" in path or not size_fits(seed, entry.get("size", 0)):
                continue
            scan_name = entry.get("name", "")
            dest = f"{folder}/{scan_name}" if folder else scan_name
            extras.append({
                "name": scan_name,
                "destination": dest,
                "sha1": sha1,
                "source_system": seed.get("system"),
                "region": seed.get("region"),
            })
            extras.extend(_companion_extras(
                _companions(path, scan_name, _companion_extensions(profile, name), files_db),
                folder, "", set(), profile, emu_name, seed,
            ))
    return extras


def expand_agnostic_entries(
    files: list[dict], emu_name: str, profile: dict, db: dict, standalone: bool,
    all_profiles: dict | None = None,
) -> list[dict]:
    """A filename-agnostic profile's placeholders, as the files they accept.

    `<bios>.bin` names no file: the core takes any dump of the right shape
    in its BIOS folder, which is what the platform pack's scan carries. The
    emulator pack and verify --emulator looked the placeholder up by name,
    found nothing and shipped LRPS2 without a PS2 BIOS. The same scan
    replaces the placeholders here. With nothing found they stay, a gap.
    """
    if profile.get("bios_mode") != "agnostic" and not any(f.get("agnostic") for f in files):
        return files
    def folder(entry: dict) -> str:
        layout = (entry.get("standalone_path") if standalone else None) or entry.get("path") or ""
        return layout.rsplit("/", 1)[0] if "/" in layout else ""

    scanned = _agnostic_scan_extras(
        {emu_name: {**profile, "files": files}}, {emu_name}, db,
        db.get("indexes", {}).get("by_name", {}), set(), "",
        {emu_name} if standalone else set(),
    )
    # A placeholder is answered by files found in its own folder: PCEE2's
    # eeprom.dat, scanned at the root, said nothing about pcsx2/bios/.
    covered = {e["destination"].rsplit("/", 1)[0] if "/" in e["destination"] else "" for e in scanned}
    open_seeds = [
        f for f in files if "<" in str(f.get("name", "")) and folder(f) not in covered
    ]
    scanned += _placeholder_scan(
        open_seeds, emu_name, profile, db, standalone, all_profiles
    )
    covered = {e["destination"].rsplit("/", 1)[0] if "/" in e["destination"] else "" for e in scanned}
    if not scanned:
        return files
    concrete = [
        {
            "name": extra["name"],
            "path": extra["destination"],
            **({"standalone_path": extra["destination"]} if standalone else {}),
            "sha1": extra["sha1"],
            "required": False,
            **({"system": extra["source_system"]} if extra.get("source_system") else {}),
            **({"region": extra["region"]} if extra.get("region") else {}),
            "agnostic_scan": True,
        }
        for extra in scanned
    ]
    return [
        f for f in files
        if "<" not in str(f.get("name", "")) or folder(f) not in covered
    ] + concrete


def _companion_extras(
    companions: list[tuple[str, dict]],
    folder: str,
    extras_prefix: str,
    seen_dests: set[str],
    profile: dict,
    emu_name: str,
    seed: dict,
    taken: dict[str, dict] | None = None,
) -> list[dict]:
    """Extras for the companions of one scanned image, placed beside it."""
    extras: list[dict] = []
    for companion_sha1, companion in companions:
        companion_dest = f"{folder}/{companion['name']}" if folder else companion["name"]
        companion_full = prefixed_destination(companion_dest, extras_prefix)
        if companion_full in seen_dests and (taken is None or companion_full not in taken):
            continue
        extra = {
            "name": companion["name"],
            "destination": companion_dest,
            "sha1": companion_sha1,
            "required": False,
            "hle_fallback": False,
            "source_emulator": profile.get("emulator", emu_name),
            "source_profile": emu_name,
            "source_name": seed.get("name", ""),
            "source_path": seed.get("path") or "",
            "category": seed.get("category", "bios"),
            "source_system": seed.get("system"),
            "source_systems": entry_system_ids(seed, profile),
            "region": seed.get("region"),
            "selection_slot": seed.get("selection_slot"),
            "agnostic_scan": True,
        }
        extra["claim_order"] = (4, 0, emu_name)
        if _take(extra, companion_full, seen_dests, taken):
            extras.append(extra)
    return extras


def _companion_of(profile: dict, name: str) -> tuple[str, dict | None]:
    """The extension and the image of an entry named after a content-found image.

    ps2-0230a-20080220.rom1 beside ps2-0230a-20080220.bin (found_by:
    content) is the image's companion, read as <bios>.rom1. Empty for any
    other entry.
    """
    stem, _, ext = name.rpartition(".")
    if not stem:
        return "", None
    for entry in profile.get("files", []):
        other = str(entry.get("name", ""))
        if (
            other != name
            and entry.get("found_by") == "content"
            and other.rpartition(".")[0].lower() == stem.lower()
        ):
            return ext, entry
    return "", None


def _companion_extensions(profile: dict, seed_name: str) -> set[str]:
    """Extensions the profile declares beside a free-named BIOS entry.

    PCSX2 reads `<bios>.rom1` or the BIOS path with its extension replaced
    (`<stem>.rom1`), and likewise nvm and mec (BiosTools.cpp:214-229,
    CDVD.cpp:160-195). A profile states that by naming the companions after
    its BIOS entry: ps2-0230a-20080220.rom1 beside ps2-0230a-20080220.bin.
    """
    if _companion_of(profile, seed_name)[0]:
        return set()
    stem = seed_name.rsplit(".", 1)[0].lower()
    exts: set[str] = set()
    for entry in profile.get("files", []):
        other = str(entry.get("name", "")).lower()
        if other != seed_name.lower() and other.startswith(stem + "."):
            exts.add(other[len(stem) + 1:])
    return exts


def _companions(
    image_path: str, image_name: str, extensions: set[str], files_db: dict
) -> list[tuple[str, dict]]:
    """Files beside a scanned image that the core opens as its companions.

    Each is named as the core spells it: PCSX2 stats `<bios>.rom1`, then the
    BIOS path with its extension replaced by `rom1`, both case-sensitive on
    Linux (BiosTools.cpp:214-229). SCPH-70004.ROM1 as stored is never found
    beside SCPH-70004.BIN, SCPH-70004.rom1 is.
    """
    if not extensions:
        return []
    directory = image_path.rsplit("/", 1)[0] + "/"
    stem = image_name.rsplit(".", 1)[0]
    spelled = {f"{image_name}.{ext}".lower(): f"{image_name}.{ext}" for ext in extensions}
    spelled.update({f"{stem}.{ext}".lower(): f"{stem}.{ext}" for ext in extensions})
    return sorted(
        (sha1, {**entry, "name": spelled[str(entry.get("name", "")).lower()]})
        for sha1, entry in _files_by_directory(files_db).get(directory, ())
        if str(entry.get("name", "")).lower() in spelled
    )


# The database a directory index was built from, with the index: one walk
# per database instead of one per scanned image (1 023 walks of 19 041
# entries in verify --all).
_DIRECTORY_INDEX: tuple[dict, dict[str, list[tuple[str, dict]]]] | None = None


def _files_by_directory(files_db: dict) -> dict[str, list[tuple[str, dict]]]:
    global _DIRECTORY_INDEX
    if _DIRECTORY_INDEX is None or _DIRECTORY_INDEX[0] is not files_db:
        index: dict[str, list[tuple[str, dict]]] = {}
        for sha1, entry in files_db.items():
            directory = entry.get("path", "").rsplit("/", 1)[0] + "/"
            index.setdefault(directory, []).append((sha1, entry))
        _DIRECTORY_INDEX = (files_db, index)
    return _DIRECTORY_INDEX[1]


def _archive_prefix_extras(
    profiles: dict,
    relevant: set,
    covered_names: set,
    seen_dests: set,
    extras_prefix: str,
    by_name: dict,
    taken: dict[str, dict] | None = None,
    standalone_set: set[str] | None = None,
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
        if profile.get("type") in ("launcher", "alias"):
            continue
        if emu_name not in relevant:
            continue
        # A platform that hands each core its own system directory moves the
        # subfolder with it, once per directory.
        views = [profile]
        if core_system_dirs(emu_name, profile, standalone_set or set()) is not None:
            views = [
                view for view, standalone
                in platform_layouts(emu_name, profile, standalone_set or set())
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
        if _take(extra, full_dest, seen_dests, taken):
            extras.append(extra)

    return extras


class ExtraPlacement:
    """Where a pack puts a core's file, decided once for every reader.

    The builder, and slots.py judging what a destination holds, both read
    this: placed apart, slot arbitration compared RetroDECK's bios/ claims
    with core claims at the root and never saw them meet.
    """

    def __init__(self, config: dict, base_dest: str, profiles: dict) -> None:
        from common import _norm_system_id

        self.prefix = _detect_extras_prefix(config, base_dest)
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
            {_norm_system_id(sid): sid for sid in self.platform_systems}
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
        profile = self.profiles.get(key) or next(
            (pp for pp in self.profiles.values() if pp.get("emulator") == key), {}
        )
        return {str(key), *(str(c) for c in profile.get("cores") or [])} - {""}

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


def undeclared_report(
    config: dict,
    emulators_dir: str,
    db: dict,
    emu_profiles: dict | None,
    target_cores: set[str] | None = None,
    include_all: bool = False,
) -> list[dict]:
    """The gap report _collect_emulator_extras reads, for a caller that
    collects the extras more than once with these arguments: the region
    grouping and the pack or manifest phase 2 each computed it in full."""
    from verify import find_undeclared_files

    return find_undeclared_files(
        config, emulators_dir, db, emu_profiles, target_cores=target_cores,
        include_all=include_all,
        declared_names=platform_declarations(config, db, enrich=False),
    )


def _collect_emulator_extras(
    config: dict,
    emulators_dir: str,
    db: dict,
    seen: set,
    base_dest: str,
    emu_profiles: dict | None = None,
    target_cores: set[str] | None = None,
    include_all: bool = False,
    claimants: dict[tuple[str, str, str], str] | None = None,
    unplaceable: list[dict] | None = None,
    baseline_claims: dict[str, dict] | None = None,
    absent: list[dict] | None = None,
    undeclared: list[dict] | None = None,
) -> list[dict]:
    """Collect core requirement files from emulator profiles not in the platform pack.

    ``undeclared`` is the gap report when the caller already holds it,
    computed with the same arguments (verify's own pass).

    ``absent`` receives, placed like the others, the entries the collection
    does not hold: the region pass groups them as it groups the platform's
    own missing files, so the report withdraws the ones a request excludes.

    ``baseline_claims`` receives, for each destination in ``seen``, the core
    claims made on it: a pack built for a target that drops the platform's
    system frees the destination, and the first core claiming it fills it.

    ``claimants`` receives the destination of every report entry that
    asked for one, the ones a sibling already took included: the region
    report withdraws by that key, and an entry without one stayed listed
    after the builder had withdrawn its destination. ``unplaceable``
    receives the entries a slug-based platform cannot place, so the
    manifest and the report can say so instead of counting them packed.

    Uses the same system-overlap matching as verify.py cross-reference:
    - Matches emulators by shared system IDs with the platform
    - Filters mode: standalone, type: launcher, type: alias
    - Respects data_directories coverage
    - Only returns files that exist in the repo (packable)

    When the same file is needed at multiple destinations by different cores
    (e.g. cdimono1.zip at root for cdi2015 and at same_cdi/bios/ for same_cdi),
    all destinations are included so every core finds its files.

    Works for ANY platform (RetroArch, Batocera, Recalbox, etc.)
    """
    profiles = (
        emu_profiles
        if emu_profiles is not None
        else load_emulator_profiles(emulators_dir)
    )

    # Detect destination conventions for core extras
    placement = ExtraPlacement(config, base_dest, profiles)
    extras_prefix = placement.prefix
    is_slug_based = placement.slug_based

    # Use strict YAML names (no DB alias enrichment) so that files known
    # under an alias still get packed at the emulator's expected path.
    yaml_names = platform_declarations(config, db, enrich=False)

    if undeclared is None:
        undeclared = undeclared_report(
            config, emulators_dir, db, emu_profiles, target_cores, include_all
        )
    # A destination two cores claim goes to the strongest proof of what the
    # collection holds for it, then to the one that names its content:
    # hypseus-singe asks for gamecontrollerdb.txt by name alone and took the
    # BIOS root before Solarus, which pins its own by sha1, and fbalpha2012's
    # hashless hiscore.dat took RetroDECK's over mame2015's sha1. Profile
    # order decides only between claims of equal proof.
    undeclared = sorted(undeclared, key=lambda u: not _names_content(u))
    rank = _ClaimRanks(
        undeclared, placement, db, bool(config.get("case_insensitive_fs", False))
    )
    undeclared = rank.ordered(undeclared)
    extras = []
    seen_dests: set[str] = set(seen)
    # Destination -> the extra that took it, to record later claimants on.
    taken: dict[str, dict] = {}
    if baseline_claims is not None:
        for destination in seen:
            taken[destination] = baseline_claims.setdefault(destination, {})
    for u in undeclared:
        if u.get("bundled"):
            # Installed with the emulator for this build: already on the
            # user's machine. The mode a file is bundled for was settled
            # upstream, an entry scoped to another build never gets here.
            continue
        if u.get("unplaced"):
            # Read in a folder outside the BIOS tree: named, held or not,
            # never written where the emulator does not read it.
            if unplaceable is not None:
                unplaceable.append({**u, "unplaceable": u["unplaced"]})
            continue
        if not u["in_repo"] and absent is None:
            continue
        # For archive entries, use the archive name for resolution
        archive = u.get("archive")
        name = archive if archive else u["name"]
        dest = _extra_dest(u)

        # Slug-based platforms: prefix dest with system slug. A file read
        # below a save directory kept per system goes below each system.
        placements = placement.places(u, dest)
        save_root = u.get("root") == "save"
        if not u["in_repo"]:
            # Each core reading it is named on the omission: a list built
            # without the first reader still has to say the file is missing.
            for placed in placements:
                for claim in (u, *u.get("other_claims", [])):
                    missing = _report_extra(claim, name, placed[0])
                    if save_root:
                        _save_fields(missing, placed[1], placement)
                    absent.append(missing)
            continue
        if not placements:
            if unplaceable is not None:
                reason = placement.unplaced_reason(u, dest)
                unplaceable.append(
                    u if reason == "no_platform_slug" else {**u, "unplaceable": reason}
                )
            continue
        if claimants is not None:
            # Keyed as extra_region_key keys the extra that wins the path: a
            # losing claim kept the bare path, and on RetroDECK (declared
            # root bios/) verify --region listed Rustation's scph1002b.bin
            # as packed while the builder had withdrawn bios/scph1002b.bin.
            claimants[(u.get("emulator", ""), u.get("name", ""), u.get("path") or "")] = (
                prefixed_destination(
                    sanitize_pack_path(placements[0][0]), declared_root(config)
                )
            )
        for dest, full_dest in placements:
            candidates = [
                _report_extra(c, name, dest) for c in (u, *u.get("other_claims", []))
            ]
            if save_root:
                for item in candidates:
                    _save_fields(item, full_dest, placement)
            # Where the builder meets each claim: the strongest proof first, the
            # report's profile order between equals, archives after loose files.
            for item in candidates:
                item["claim_order"] = (
                    1, 1 if u.get("archive") else 0, -rank.of_extra(item, full_dest),
                    item["source_profile"],
                )
            candidates.sort(key=lambda item: item["claim_order"])
            extra, claims = candidates[0], candidates[1:]
            if not _take(extra, full_dest, seen_dests, taken):
                for claim in claims:
                    _another_claim(taken.get(full_dest), claim)
                continue
            for claim in claims:
                _another_claim(extra, claim)
            extras.append(extra)

    # Second pass: find alternative destinations for files already in the pack.
    # A file declared by the platform or emitted above may also be needed at a
    # different path by another core (e.g. neocd/ vs root, same_cdi/bios/ vs root).
    # Only adds a copy when the file is ALREADY covered at a different path -
    # never introduces a file that wasn't selected by the first pass.
    #
    # Skip for slug-based platforms (RomM): alternative paths don't map to
    # the required {platform_slug}/{file} structure.
    if is_slug_based:
        return extras

    relevant = resolve_platform_cores(config, profiles, target_cores=target_cores)
    standalone_set = platform_standalone_set(config)
    by_name = db.get("indexes", {}).get("by_name", {})
    by_path_suffix = db.get("indexes", {}).get("by_path_suffix", {})

    # Build set of filenames already covered (platform baseline + first pass extras)
    # Enriched with canonical names from DB via MD5 (handles platform renaming)
    platform_names = expand_platform_declared_names(config, db)
    covered_names = set(platform_names)
    for e in extras:
        covered_names.add(e["name"])

    for emu_name, profile in sorted(profiles.items()):
        if profile.get("type") in ("launcher", "alias"):
            continue
        if emu_name not in relevant:
            continue
        for profile, is_standalone in platform_layouts(emu_name, profile, standalone_set):
            for f in profile.get("files", []):
                fname = f.get("name", "")
                if not fname:
                    continue
                # Only duplicate files already covered at another destination.
                # An unsourceable entry is a file no collection holds: the name
                # covered elsewhere belongs to another program's file.
                # Nor is one placed outside the BIOS tree by the layout.
                if (fname not in covered_names or f.get("unsourceable") or f.get("unplaced")
                        or f.get("root") in OUTER_ROOTS or f.get("unprefixed")):
                    continue
                # Installed with the emulator or by the platform's package,
                # as the first pass already decided for the same entry.
                if not deliverable([f], is_standalone, config.get("_key", "")):
                    continue
                # A member of an archive is read inside it, never as a loose
                # file. The archive itself is placed by the passes above.
                if f.get("archive"):
                    continue
                # No path: the core reads it from nowhere a pack reaches
                # (Dolphin's codehandler.bin ships in its Sys tree).
                if "path" in f and f["path"] is None:
                    continue
                file_mode = f.get("mode")
                if file_mode == "standalone" and not is_standalone:
                    continue
                if file_mode == "libretro" and is_standalone:
                    continue
                if not read_from_system_dir(f, is_standalone):
                    continue
                if is_standalone:
                    raw = f.get("standalone_path") or f.get("path") or fname
                else:
                    raw = system_dir_path(f, f.get("path") or fname)
                dest = f"{raw}{fname}" if raw.endswith("/") else raw
                # A bare name is a destination too: the core reads it at the root
                # of the directory core files go to, which the platform may not
                # declare (Recalbox has its System Cards under pcenginecd/ only,
                # geargrafx reads them from the root).
                full_dest = prefixed_destination(dest, extras_prefix)
                if full_dest in seen_dests and full_dest not in taken:
                    continue
                if full_dest in taken and full_dest not in seen and fname not in platform_names:
                    # Another core's extra holds this path and only that
                    # extra covers the name: a pack without that core never
                    # reaches this copy, so this core claims nothing here.
                    # Batocera's launcher hands DuckStation one named BIOS;
                    # recorded on duckstation-legacy's scph100.bin, its claim
                    # kept the file for a target without legacy.
                    continue
                # Only files the database indexes: members of a data
                # directory are not in it and are not duplicated here.
                if not (
                    by_name.get(fname)
                    or by_name.get(dest.rsplit("/", 1)[-1])
                    or by_path_suffix.get(dest)
                ):
                    continue
                extra = {
                    "name": fname,
                    "destination": dest,
                    "required": f.get("required", False),
                    "hle_fallback": f.get("hle_fallback", False),
                    "source_emulator": profile.get("emulator", emu_name),
                    "source_profile": emu_name,
                    # The key the gap report gives the same entry.
                    "source_name": fname,
                    "source_path": raw,
                    "category": f.get("category", "bios"),
                    "source_system": f.get("system"),
                    "source_systems": entry_system_ids(f, profile),
                    "region": f.get("region"),
                    "selection_slot": f.get("selection_slot"),
                    **set_fields(f, profile),
                }
                # The same identity the first pass carries: without it the copy
                # resolves on its name alone and a same-named file of another
                # game fills the slot the profile marks as not held.
                for identity in PROFILE_IDENTITY_FIELDS:
                    if f.get(identity) not in (None, "", []):
                        extra[identity] = f[identity]
                if f.get("contents"):
                    extra["contents"] = f["contents"]
                if f.get("system_dir"):
                    extra["system_dir"] = f["system_dir"]
                extra["claim_order"] = (2, 0, emu_name)
                if _take(extra, full_dest, seen_dests, taken):
                    extras.append(extra)

    extras.extend(
        _archive_prefix_extras(
            profiles, relevant, covered_names, seen_dests, extras_prefix,
            by_name, taken, standalone_set,
        )
    )

    extras.extend(
        _agnostic_scan_extras(
            profiles, relevant, db, by_name, seen_dests, extras_prefix,
            standalone_set, taken,
        )
    )

    return extras

class _ClaimRanks:
    """How strongly each claim on a contested destination proves its file.

    2 a declared hash the collection holds, 1 a path or every member the
    core requires inside an archive, 0 a name, -1 a copy
    contradicting the hash the claim declares, -2 nothing held. Resolved only
    where two claims meet: a destination one core asks for has no contest.
    """

    def __init__(
        self, undeclared: list[dict], placement: ExtraPlacement, db: dict, fold: bool,
    ) -> None:
        self._db = db
        # Two spellings of one path are one file where the filesystem folds case.
        self._key = (lambda dest: dest.lower()) if fold else (lambda dest: dest)
        # An entry can take several destinations: one per system folder of a
        # save directory kept per system.
        self._placed: dict[int, list[tuple[str, str]]] = {}
        counts: dict[str, int] = {}
        for u in undeclared:
            placed = (
                placement.places(u, _extra_dest(u))
                if u.get("in_repo") and not u.get("bundled") else []
            )
            self._placed[id(u)] = placed
            for _dest, full in placed:
                key = self._key(full)
                counts[key] = counts.get(key, 0) + 1 + len(u.get("other_claims", []))
        self._contested = {dest for dest, n in counts.items() if n > 1}
        self._cache: dict[tuple, int] = {}

    def _contests(self, u: dict) -> list[tuple[str, str]]:
        """The entry's destinations another claim also asks for."""
        return [
            placed for placed in self._placed.get(id(u), [])
            if self._key(placed[1]) in self._contested
        ]

    def of_extra(self, extra: dict, full_dest: str) -> int:
        if self._key(full_dest) not in self._contested:
            return 0
        key = (extra.get("source_profile"), extra.get("source_name"),
               extra.get("source_path"), full_dest)
        if key not in self._cache:
            path, status = resolve_local_file(
                extra, self._db, dest_hint=extra.get("destination", "")
            )
            self._cache[key] = (
                -2 if not path
                else -1 if status == "hash_mismatch"
                else 2 if resolution_is_hash_exact(status)
                else 1 if status == "path_exact" or (
                    extra.get("members") and holds_required_members(path, extra["members"])
                )
                else 0
            )
        return self._cache[key]

    def ordered(self, undeclared: list[dict]) -> list[dict]:
        """The entries in their order, the claims on one contested path
        reordered among themselves by proof. Nothing else moves, so the
        pack and the manifest keep their order."""
        first: dict[str, int] = {}
        keys: list[tuple[int, int, int]] = []
        for position, u in enumerate(undeclared):
            contests = self._contests(u)
            if not contests:
                keys.append((position, 0, position))
                continue
            group = first.setdefault(self._key(contests[0][1]), position)
            keys.append((group, -self.of_entry(u), position))
        order = sorted(range(len(undeclared)), key=keys.__getitem__)
        return [undeclared[i] for i in order]

    def of_entry(self, u: dict) -> int:
        contests = self._contests(u)
        if not contests:
            return 0
        name = u.get("archive") or u["name"]
        return max(
            self.of_extra(_report_extra(c, name, dest), full)
            for dest, full in contests
            for c in (u, *u.get("other_claims", []))
        )


def _names_content(entry: dict) -> bool:
    """Whether a report entry declares the bytes it wants, not only a name.

    The claims folded onto the entry count: bsnes asks for SGB1.sfc by name
    and bsnes-hd pins its md5 under the same system, and the entry carrying
    both went after nSide's SGB1.sfc/ tree, which took the path from the file.
    """
    return any(
        claim.get(field)
        for claim in (entry, *entry.get("other_claims", []))
        for field in ("sha1", "md5", "sha256", "crc32")
    )


def _save_fields(extra: dict, pack_path: str, placement: ExtraPlacement) -> None:
    """Record where a file read below the save directory goes in the pack.

    ``core_folder`` stays only where the frontend sorts saves by core for
    every core, the one setting a frontend config can turn off and the
    installer then reads (RetroArch's sort_savefiles_enable). A launcher
    writing the save directory at each launch fixes the path the pack
    already spells out.
    """
    extra["pack_path"] = pack_path
    if placement.save is not None:
        # The path below the save directory, what the manifest writes.
        extra["save_dest"] = pack_path[len(placement.save.in_pack) + 1:]
        if not placement.save.by_core:
            extra.pop("core_folder", None)


def _report_extra(u: dict, name: str, dest: str) -> dict:
    """The extra a cross-reference entry asks for at its destination."""
    extra = {
        "name": name,
        "destination": dest,
        "required": u.get("required", False),
        "hle_fallback": u.get("hle_fallback", False),
        "source_emulator": u.get("emulator", ""),
        "source_profile": u.get("profile", ""),
        # Identity of the report entry this extra came from.  The name
        # alone does not identify it: Dolphin declares three IPL.bin that
        # differ only by path, and collapsing them onto one key withdraws
        # the wrong regional variant from the report.
        "source_name": u.get("name", ""),
        "source_path": u.get("path") or "",
        "category": u.get("category", "bios"),
        "source_system": u.get("system"),
        "source_systems": u.get("systems", []),
        "region": u.get("region"),
        "selection_slot": u.get("selection_slot"),
        **{k: u[k] for k in ("required_groups", "set_declared") if k in u},
    }
    if u.get("members"):
        extra["members"] = u["members"]
    if u.get("root") == "save":
        extra["root"] = "save"
        if u.get("core_folder") is not None:
            extra["core_folder"] = u["core_folder"]
    elif u.get("root") in OUTER_ROOTS:
        extra["root"] = u["root"]
    if u.get("system_dir"):
        extra["system_dir"] = u["system_dir"]
    if u.get("layout_path"):
        extra["layout_path"] = u["layout_path"]
    if u.get("unprefixed"):
        extra["unprefixed"] = True
    # The archive layout the core opens ranks same-named copies by what
    # they hold. Without it the first copy indexed won.
    if u.get("contents"):
        extra["contents"] = u["contents"]
    # Keep every reproducible identity constraint carried by the source
    # profile.  Some profiles expose CRC32/SHA-256 only through their
    # validation block, and dropping those fields here would let a same-named
    # but different payload enter a generated pack.
    expected = u.get("expected") or {}
    for identity in PROFILE_IDENTITY_FIELDS:
        declared = u.get(identity)
        if declared in (None, "", []):
            declared = expected.get(identity)
        if declared not in (None, "", []):
            extra[identity] = declared
    return extra


def _take(
    extra: dict, full_dest: str, seen_dests: set[str], taken: dict[str, dict] | None
) -> bool:
    """Whether an extra takes its destination. A taken one records the claim."""
    if full_dest in seen_dests:
        if taken is not None:
            _another_claim(taken.get(full_dest), extra)
        return False
    seen_dests.add(full_dest)
    if taken is not None:
        taken[full_dest] = extra
    return True


def _another_claim(extra: dict | None, claim: dict) -> None:
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


def _extra_system_ids(extra: dict) -> list[str]:
    """Return the narrowest system ownership preserved on a core extra."""
    explicit = extra.get("source_system")
    if explicit:
        return [str(explicit)]
    return [str(value) for value in extra.get("source_systems", []) if value]

def _serving_system_ids(extra: dict) -> list[str]:
    """Every system the extra's file serves: its own core's and those of the
    other cores whose claim rides on it. One file stands per destination, so
    narrowed to any of their systems the file is what that core reads.
    """
    ids = list(_extra_system_ids(extra))
    for claim in extra.get("other_claims", []):
        ids.extend(s for s in _extra_system_ids(claim) if s not in ids)
    return ids


def _kept(entries: list[dict], required_only: bool) -> list[dict]:
    """The entries a pack keeps: optional ones go under --required-only."""
    if not required_only:
        return entries
    return [e for e in entries if e.get("required") is not False]


def extras_for_systems(extras: list[dict], system_ids: list[str]) -> list[dict]:
    """Core extras owned by one of the given systems.

    Extras carry their profile/system identity directly. Display labels are
    presentation only and must never drive routing.
    """
    wanted = set(system_ids) | {_norm_system_id(s) for s in system_ids}
    return [
        fe for fe in extras
        if (
            set(_serving_system_ids(fe))
            | {_norm_system_id(s) for s in _serving_system_ids(fe)}
        ) & wanted
    ]


def report_owned_by_systems(report: list[dict], system_ids: list[str]) -> list[dict]:
    """Gap report entries whose extra a pack built with --system carries.

    The other cores whose claim rides on the entry count, as the builder
    counts them: MAME 2009's taitofx1.zip went into a --system
    panasonic-3do pack for MAME 2016 and was missing from the report.
    """
    def owner(entry: dict) -> dict:
        return {"source_system": entry.get("system"), "source_systems": entry.get("systems", [])}

    return [
        u for u in report
        if extras_for_systems(
            [{**owner(u), "other_claims": [owner(c) for c in u.get("other_claims", [])]}],
            system_ids,
        )
    ]


def _ships(
    config: dict,
    file_entry: dict,
    db: dict,
    zip_contents: dict | None,
    data_registry: dict | None,
    override: str | None,
) -> bool:
    """Whether the builder packs this declaration: resolved, and not refused
    by a hash frontend. A dump whose md5 Recalbox would reject is left out
    of the pack, so it cannot win a regional slot over a file that ships.

    Resolved with the builder's own inputs: without the data directories,
    AmberELEC's bluemsx config.ini read as missing while the pack held it.
    """
    from packresolve import resolve_declaration
    from validation import baseline_verdict

    path, status = resolve_declaration(
        file_entry, db, "bios", zip_contents, data_registry, override, offline=True,
    )
    if not path:
        return False
    return baseline_verdict(
        file_entry, path, status, config.get("verification_mode", "existence"),
        config.get("hash_rule", ""),
    )[1] is None


def platform_region_groups(
    config: dict,
    systems: dict,
    emulators_dir: str,
    db: dict | None,
    base_dest: str,
    emu_profiles: dict | None,
    *,
    target_cores: set[str] | None = None,
    include_extras: bool = True,
    include_all: bool = False,
    required_only: bool = False,
    extras_out: list[dict] | None = None,
    held_out: set[str] | None = None,
    undeclared: list[dict] | None = None,
    zip_contents: dict | None = None,
    data_registry: dict | None = None,
    slot_overrides: dict[str, str] | None = None,
) -> tuple[dict[str, list[tuple[str, str]]], dict[tuple[str, str, str], str]]:
    """Group a platform's pack candidates the way region filtering reads them.

    ``held_out`` receives the destinations whose file the collection holds:
    a missing file is grouped so the report can withdraw it, but it never
    takes the slot of a held one (resolve_region_drops).

    Returns the groups and, for every core extra, the destination it was
    grouped under, keyed by (emulator, name).  verify.py needs that mapping to
    withdraw from its report exactly what the builder withdraws from the pack:
    grouping the declared files here and the core extras there would let the
    two answer differently on the same request.  `extras_out` receives the
    core extras that were grouped, for the install manifest. ``undeclared``
    is the gap report when the caller holds it (undeclared_report, with the
    same target_cores and include_all). ``zip_contents``, ``data_registry``
    and ``slot_overrides`` (keyed by full pack destination) are the ones the
    builder resolves with, so a held declaration is the one the pack ships.
    """
    groups: dict[str, list[tuple[str, str]]] = {}
    for sys_id, system in systems.items():
        members = groups.setdefault(sys_id, [])
        # Decided over what the pack keeps: an optional winner removed
        # afterwards left its slot empty.
        for file_entry in _kept(system.get("files", []), required_only):
            dest = sanitize_pack_path(
                file_entry.get("destination", file_entry.get("name", ""))
            )
            if dest:
                members.append((dest, file_entry.get("name", "")))
                full_dest = f"{base_dest}/{dest}" if base_dest else dest
                if held_out is not None and db is not None and _ships(
                    config, file_entry, db, zip_contents, data_registry,
                    (slot_overrides or {}).get(full_dest),
                ):
                    held_out.add(dest)

    extra_dests: dict[tuple[str, str, str], str] = {}
    if not include_extras or db is None:
        return groups, extra_dests

    absent: list[dict] = []
    extras = _collect_emulator_extras(
        config,
        emulators_dir,
        db,
        set(),
        base_dest,
        emu_profiles,
        target_cores=target_cores,
        include_all=include_all,
        claimants=extra_dests,
        absent=absent,
        undeclared=undeclared,
    )
    held = {id(extra) for extra in extras}
    spellings = system_spellings(systems)
    region_prefix = declared_root(config)
    for extra in _kept(extras + absent, required_only):
        dest = extra_region_key(extra, region_prefix)
        if not dest:
            continue
        name = extra.get("name", "")
        extra_dests[
            (
                extra.get("source_emulator", ""),
                extra.get("source_name", ""),
                extra.get("source_path", ""),
            )
        ] = dest
        # A file a filename-agnostic scan accepts by shape competes only if
        # its seed names a region: PCSX2 picks no PS2 BIOS by territory, and
        # looked up by name its scph50006 took DuckStation's [japan], which
        # describes DuckStation's own PS1-on-PS2 choice.
        competes = not extra.get("agnostic_scan") or extra.get("region")
        for group_id in extra_region_groups(extra, spellings) if competes else ():
            groups.setdefault(group_id, []).append((dest, name))
        if extras_out is not None and id(extra) in held:
            extras_out.append(extra)
        if held_out is not None and id(extra) in held:
            held_out.add(dest)
    return groups, extra_dests


def system_spellings(systems: Iterable[str]) -> dict[str, str]:
    """A platform's own spelling of each system, keyed the way ids compare.

    RetroDECK files the Master System as sega-master-system, the profiles as
    sega-mastersystem. Grouped under both, the declared bios/bios_J.sms and
    the core's bios_J.sms were reduced apart and a --region us pack kept the
    Japanese BIOS.
    """
    spellings: dict[str, str] = {}
    for sys_id in sorted(systems):
        spellings.setdefault(_norm_system_id(sys_id), sys_id)
    return spellings


def extra_region_groups(
    extra: dict, spellings: dict[str, str] | None = None
) -> list[str]:
    """The region groups a core extra competes in.

    A group named after a system takes the platform's spelling of it, so the
    extra competes beside the files the platform declares for that system.
    """
    def system_group(sys_id: str) -> str:
        return (spellings or {}).get(_norm_system_id(sys_id), sys_id)

    emulator = extra.get("source_emulator", "")
    variant = extra.get("selection_slot")
    if variant:
        # A selection slot is one slot of one core, whatever system each
        # member is filed under: PicoDrive files its US Mega CD BIOS under
        # sega-segacd and the EU/JP ones under sega-megacd, and find_bios
        # picks one of the twelve. Keyed as emulator mode keys it.
        return [f"{emulator}:variant:{variant}"]
    explicit = extra.get("source_system")
    if explicit:
        return [system_group(str(explicit))]
    systems = [str(s) for s in extra.get("source_systems", []) if s]
    if len(systems) == 1:
        return [system_group(systems[0])]
    # No system names the machine this file is chosen for. Filed under every
    # system of a 30-system profile, CLK's American MSX ROM made the
    # Enterprise group drop its German ROM. Alone, it drops nothing and is
    # never dropped.
    destination = extra.get("destination", extra.get("name", ""))
    return [f"{emulator}{FILE_GROUP}{destination}"]

def emulator_region_drops(
    selected: list[tuple[str, dict]],
    standalone: bool,
    regions: list[str],
    required_only: bool = False,
    db: dict | None = None,
    zip_contents: dict | None = None,
    data_registry: dict | None = None,
) -> set[str]:
    """Destinations an emulator-mode `--region` withdraws.

    One group per system (or explicit selection_slot) inside each profile, so
    a multi-system core such as O2EM keeps a fallback BIOS for every system
    instead of letting one matching system empty another. The emulator pack
    and `verify --emulator` both read this, keyed by pack destination.

    With `db`, a requested-region file the collection lacks never displaces
    a held one, as in platform mode: a held scph5501.bin was withdrawn for a
    Japanese image nobody had collected, and the pack shipped no PlayStation
    BIOS at all. ``zip_contents`` and ``data_registry`` are the ones the
    emulator pack resolves with.
    """
    import region as region_mod
    from packpaths import _resolve_destination
    from validation import _build_validation_index, filter_files_by_mode

    region_index = region_mod.build_region_index(dict(selected))
    region_groups: dict[str, list[tuple[str, str]]] = {}
    held: set[str] | None = set() if db is not None else None
    validation_index = _build_validation_index(dict(selected)) if db is not None else {}
    for emu_name, profile in sorted(selected):
        # Decided over what the pack keeps, as on the platform side: an
        # optional winner removed afterwards left its slot empty.
        entries = filter_files_by_mode(profile.get("files", []), standalone)
        for fe in _kept(entries, required_only):
            dest = _resolve_destination(fe, standalone)
            if dest:
                group_id = _emulator_region_group(emu_name, profile, fe, dest)
                region_groups.setdefault(group_id, []).append(
                    (dest, fe.get("name", ""))
                )
                if held is not None and _emulator_ships(
                    fe, emu_name, profile, db, validation_index,
                    zip_contents, data_registry,
                ):
                    held.add(dest)
    return region_mod.resolve_region_drops(region_groups, region_index, regions, held)


def emulator_required_spares(
    emu_name: str,
    profile: dict,
    files: list[dict],
    standalone: bool,
    region_drops: set[str],
    db: dict,
    validation_index: dict,
    zip_contents: dict | None,
    data_registry: dict | None,
) -> set[str]:
    """The destinations an emulator --required-only pack leaves out: of each
    required set, one held member stays, the first the code loads among
    those the pack still carries after the region filter. An archive unit
    is a member like a loose file: Kronos reads kronos/stvbios.zip, else
    stvbios.zip. The pack and verify --emulator both read this."""
    from alternatives import groups_of, rank_in, required_groups
    from common import archive_entry
    from packpaths import _archive_destination, _resolve_destination

    candidates: list[dict] = []
    archives: list[str] = []
    for fe in files:
        archive = fe.get("archive")
        if archive and archive not in archives:
            archives.append(archive)
            own = archive_entry(archive, files)
            if groups_of(own):
                candidates.append({"dest": _archive_destination(
                    archive, profile.get("archive_prefix", ""),
                    profile.get("pack_structure"), standalone,
                ), "entry": own})
    for fe in files:
        if not fe.get("archive") and groups_of(fe):
            candidates.append({"dest": _resolve_destination(fe, standalone), "entry": fe})
    if not candidates:
        return set()
    spares = required_only_spares(
        candidates,
        owner=lambda _c: emu_name,
        held=lambda c: _emulator_ships(
            c["entry"], emu_name, profile, db, validation_index, zip_contents, data_registry,
        ),
        gone=lambda c: c["dest"] in region_drops,
        sets=lambda c: {g: rank_in(c["entry"], g) for g in required_groups(c["entry"], profile)},
    )
    return {c["dest"] for c in candidates if id(c) in spares}


def _emulator_ships(
    file_entry: dict, emu_name: str, profile: dict, db: dict,
    validation_index: dict, zip_contents: dict | None, data_registry: dict | None,
) -> bool:
    """Whether the emulator pack ships this entry: held, and not refused by
    the core's own check, the test _ships applies on the platform side.

    Resolved as generate_emulator_pack resolves: without the data
    directories, dolphin-mmjr2's nwc24msg.cfg read as missing while the pack
    held it.
    """
    from packresolve import resolve_file
    from validation import validated_choice, with_archive_members

    local, status = resolve_file(
        {**with_archive_members(file_entry, profile.get("files", [])),
         "source_profile": emu_name},
        db, "bios", zip_contents,
        dest_hint=file_entry.get("path", ""),
        data_dir_registry=data_registry,
        offline=True,
    )
    if status in ("not_found", "user_provided") or not local:
        return False
    _chosen, disagreement = validated_choice(
        file_entry, local, db, validation_index, "bios", None, emulators={emu_name},
    )
    return disagreement is None


def _emulator_region_group(
    emu_name: str, profile: dict, file_entry: dict, dest: str
) -> str:
    """Stable group ID for regional alternatives within an emulator profile.

    The rule extra_region_groups applies on the platform side: a file no
    system names, in a profile serving several, competes with nothing.
    Grouped together, geargrafx's LaserActive pac-n1.bin was dropped by
    --emulator --region us and kept by --platform --region us.
    """
    variant = file_entry.get("selection_slot")
    if variant:
        return f"{emu_name}:variant:{variant}"
    system = file_entry.get("system")
    profile_systems = list(profile.get("systems", []))
    if not system and len(profile_systems) == 1:
        system = profile_systems[0]
    if not system:
        return f"{emu_name}{FILE_GROUP}{dest}"
    return f"{emu_name}:system:{system}"
