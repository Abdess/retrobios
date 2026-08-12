"""What the cores need that the platform does not declare.

A pack is the platform's own list plus the files its cores load. The
second half is derived here, and the region pass reads the grouping
this module builds so the report and the pack withdraw the same files."""

from __future__ import annotations

from common import expand_platform_declared_names
from common import load_emulator_profiles
from common import resolution_is_hash_exact
from common import resolve_local_file
from common import sanitize_pack_path
def _emulator_systems_index(emu_profiles: dict | None) -> dict[str, list[str]]:
    """Map both the profile key and its display name to the profile's systems.

    find_undeclared_files reports the display name ("Beetle PSX (Mednafen
    PSX)"), while the profile dictionary is keyed by slug. A key-only lookup
    therefore missed almost every core, dropping its files into one shared
    bucket and losing the per-system grouping the narrowing passes rely on.
    """
    index: dict[str, list[str]] = {}
    for key, profile in (emu_profiles or {}).items():
        systems = list(profile.get("systems", []))
        index[key] = systems
        display = profile.get("emulator", "")
        if display:
            index.setdefault(display, systems)
    return index

def _detect_extras_prefix(config: dict, base_dest: str) -> str:
    """Detect the effective BIOS prefix for core extras.

    When base_destination is empty (RetroDECK), infer the prefix from
    the dominant root of YAML-declared destinations.  Returns the prefix
    to prepend to every core-extra destination (may be empty).
    """
    if base_dest:
        return base_dest
    dests: list[str] = []
    for sys_data in config.get("systems", {}).values():
        for f in sys_data.get("files", []):
            d = f.get("destination", "")
            if d and "/" in d:
                dests.append(d)
    if not dests:
        return ""
    from collections import Counter

    roots = Counter(d.split("/", 1)[0] for d in dests)
    most_common, count = roots.most_common(1)[0]
    if count / len(dests) > 0.9:
        return most_common
    return ""

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

def _agnostic_scan_extras(
    profiles: dict,
    relevant: set,
    db: dict,
    by_name: dict,
    seen_dests: set,
    extras_prefix: str,
) -> list[dict]:
    """Every interchangeable candidate a filename-agnostic core accepts.

    Such a core reads whatever sits in its BIOS directory, so the pack
    carries every dump of the right shape rather than one chosen name.
    The directory is the delicate part: anchoring it on a single
    filename walked into another emulator's tree, so the profile's own
    files have to agree before the scan follows an ambiguous name.
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
        # of a directory; two files of the same profile agreeing is.
        resolved_dirs: dict[int, str] = {}
        named_only: set[int] = set()
        agnostic_votes: dict[str, int] = {}
        for candidate in profile.get("files", []):
            if not isinstance(candidate, dict):
                continue
            local, status = resolve_local_file(
                candidate, db, dest_hint=candidate.get("path", "")
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

        for f in profile.get("files", []):
            if not is_profile_agnostic and not f.get("agnostic"):
                continue
            fname = f.get("name", "")
            if not fname:
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

            path_prefix = resolved_dirs.get(id(f), "")
            if not path_prefix:
                continue
            # A name matching one file identifies it. A name matching several
            # identifies nothing on its own, so the profile's other files have
            # to agree on the directory before the scan walks it.
            ambiguous = id(f) in named_only and len(by_name.get(fname, [])) > 1
            if ambiguous and agnostic_votes.get(path_prefix, 0) < 2:
                continue

            # Size criteria from the file entry
            min_size = f.get("min_size", 0)
            max_size = f.get("max_size", float("inf"))
            exact_size = f.get("size")
            if exact_size and not min_size:
                min_size = exact_size
                max_size = exact_size

            # Scan DB for all files under this prefix matching size
            for sha1, entry in files_db.items():
                path = entry.get("path", "")
                if not path.startswith(path_prefix):
                    continue
                size = entry.get("size", 0)
                if not (min_size <= size <= max_size):
                    continue
                scan_name = entry.get("name", "")
                if not scan_name:
                    continue
                dest = scan_name
                full_dest = f"{extras_prefix}/{dest}" if extras_prefix else dest
                if full_dest in seen_dests:
                    continue
                seen_dests.add(full_dest)
                extras.append(
                    {
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
                        "source_system": f.get("system"),
                        "source_systems": list(profile.get("systems", [])),
                        "region": f.get("region"),
                        "variant_group": f.get("variant_group"),
                        "agnostic_scan": True,
                    }
                )
    return extras


def _archive_prefix_extras(
    profiles: dict,
    relevant: set,
    covered_names: set,
    seen_dests: set,
    extras_prefix: str,
    by_name: dict,
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
        prefix = profile.get("archive_prefix", "")
        if not prefix:
            continue
        profile_archives: dict[str, dict] = {}
        for f in profile.get("files", []):
            archive = f.get("archive", "")
            if archive:
                profile_archives.setdefault(archive, f)
        for archive_name, archive_entry in sorted(profile_archives.items()):
            if archive_name not in covered_names:
                continue
            dest = f"{prefix}/{archive_name}"
            full_dest = f"{extras_prefix}/{dest}" if extras_prefix else dest
            if full_dest in seen_dests:
                continue
            if not by_name.get(archive_name):
                continue
            seen_dests.add(full_dest)
            extras.append(
                {
                    "name": archive_name,
                    "destination": dest,
                    "required": True,
                    "hle_fallback": False,
                    "source_emulator": profile.get("emulator", emu_name),
                    "source_profile": emu_name,
                    "source_system": archive_entry.get("system"),
                    "source_systems": list(profile.get("systems", [])),
                    "region": archive_entry.get("region"),
                    "variant_group": archive_entry.get("variant_group"),
                }
            )

    return extras


def _collect_emulator_extras(
    config: dict,
    emulators_dir: str,
    db: dict,
    seen: set,
    base_dest: str,
    emu_profiles: dict | None = None,
    target_cores: set[str] | None = None,
    include_all: bool = False,
) -> list[dict]:
    """Collect core requirement files from emulator profiles not in the platform pack.

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
    from common import _norm_system_id, resolve_platform_cores
    from verify import find_undeclared_files

    profiles = (
        emu_profiles
        if emu_profiles is not None
        else load_emulator_profiles(emulators_dir)
    )

    # Detect destination conventions for core extras
    extras_prefix = _detect_extras_prefix(config, base_dest)
    is_slug_based, sys_to_slug = _detect_slug_structure(config)
    platform_systems = set(config.get("systems", {}).keys())
    norm_map: dict[str, str] = {}
    if is_slug_based:
        for sid in platform_systems:
            norm_map[_norm_system_id(sid)] = sid

    # Use strict YAML names (no DB alias enrichment) so that files known
    # under an alias still get packed at the emulator's expected path.
    yaml_names: set[str] = set()
    for system in config.get("systems", {}).values():
        for fe in system.get("files", []):
            name = fe.get("name", "")
            if name:
                yaml_names.add(name)

    undeclared = find_undeclared_files(
        config, emulators_dir, db, emu_profiles, target_cores=target_cores,
        include_all=include_all, declared_names=yaml_names,
    )
    extras = []
    seen_dests: set[str] = set(seen)
    for u in undeclared:
        if not u["in_repo"]:
            continue
        # For archive entries, use the archive name for resolution
        archive = u.get("archive")
        name = archive if archive else u["name"]
        raw_dest = archive if archive else (u.get("path") or u["name"])
        # Directory path: append filename (e.g. "cafeLibs/" + "snd_user.rpl")
        dest = f"{raw_dest}{u['name']}" if raw_dest.endswith("/") else raw_dest

        # Slug-based platforms: prefix dest with system slug
        if is_slug_based:
            emu_name = u.get("profile") or u.get("emulator", "")
            profile = profiles.get(emu_name, {})
            # Try finding profile by display name if key lookup failed
            if not profile:
                for pn, pp in profiles.items():
                    if pp.get("emulator") == emu_name:
                        profile = pp
                        break
            slug = _map_emulator_to_slug(
                profile,
                platform_systems,
                norm_map,
                sys_to_slug,
            )
            if not slug:
                continue  # can't place without slug
            dest = f"{slug}/{dest}"

        full_dest = f"{extras_prefix}/{dest}" if extras_prefix else dest
        if full_dest in seen_dests:
            continue
        seen_dests.add(full_dest)
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
            "source_system": u.get("system"),
            "source_systems": u.get("systems", []),
            "region": u.get("region"),
            "variant_group": u.get("variant_group"),
        }
        # Keep every reproducible identity constraint carried by the source
        # profile.  Some profiles expose CRC32/SHA-256 only through their
        # validation block; dropping those fields here would let a same-named
        # but different payload enter a generated pack.
        expected = u.get("expected") or {}
        for identity in ("sha1", "md5", "sha256", "crc32", "size"):
            declared = u.get(identity)
            if declared in (None, "", []):
                declared = expected.get(identity)
            if declared not in (None, "", []):
                extra[identity] = declared
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
    standalone_set = {str(c) for c in config.get("standalone_cores", [])}
    by_name = db.get("indexes", {}).get("by_name", {})
    by_path_suffix = db.get("indexes", {}).get("by_path_suffix", {})

    # Build set of filenames already covered (platform baseline + first pass extras)
    # Enriched with canonical names from DB via MD5 (handles platform renaming)
    covered_names = expand_platform_declared_names(config, db)
    for e in extras:
        covered_names.add(e["name"])

    for emu_name, profile in sorted(profiles.items()):
        if profile.get("type") in ("launcher", "alias"):
            continue
        if emu_name not in relevant:
            continue
        is_standalone = emu_name in standalone_set or bool(
            standalone_set & {str(c) for c in profile.get("cores", [])}
        )
        for f in profile.get("files", []):
            fname = f.get("name", "")
            if not fname:
                continue
            # Only duplicate files already covered at another destination
            if fname not in covered_names:
                continue
            file_mode = f.get("mode")
            if file_mode == "standalone" and not is_standalone:
                continue
            if file_mode == "libretro" and is_standalone:
                continue
            # Skip files loaded from non-system directories (save_dir, content_dir)
            load_from = f.get("load_from", "")
            if load_from and load_from != "system_dir":
                continue
            if is_standalone:
                raw = f.get("standalone_path") or f.get("path") or fname
            else:
                raw = f.get("path") or fname
            dest = f"{raw}{fname}" if raw.endswith("/") else raw
            if dest == fname:
                continue  # no alternative destination
            full_dest = f"{extras_prefix}/{dest}" if extras_prefix else dest
            if full_dest in seen_dests:
                continue
            # Check file exists in repo or data dirs
            if not (
                by_name.get(fname)
                or by_name.get(dest.rsplit("/", 1)[-1])
                or by_path_suffix.get(dest)
            ):
                continue
            seen_dests.add(full_dest)
            extras.append(
                {
                    "name": fname,
                    "destination": dest,
                    "required": f.get("required", False),
                    "hle_fallback": f.get("hle_fallback", False),
                    "source_emulator": profile.get("emulator", emu_name),
                    "source_profile": emu_name,
                    "source_system": f.get("system"),
                    "source_systems": list(profile.get("systems", [])),
                    "region": f.get("region"),
                    "variant_group": f.get("variant_group"),
                }
            )

    extras.extend(
        _archive_prefix_extras(
            profiles, relevant, covered_names, seen_dests, extras_prefix,
            by_name,
        )
    )

    extras.extend(
        _agnostic_scan_extras(
            profiles, relevant, db, by_name, seen_dests, extras_prefix
        )
    )

    return extras

def _extra_system_ids(extra: dict) -> list[str]:
    """Return the narrowest system ownership preserved on a core extra."""
    explicit = extra.get("source_system")
    if explicit:
        return [str(explicit)]
    return [str(value) for value in extra.get("source_systems", []) if value]

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
) -> tuple[dict[str, list[tuple[str, str]]], dict[tuple[str, str, str], str]]:
    """Group a platform's pack candidates the way region filtering reads them.

    Returns the groups and, for every core extra, the destination it was
    grouped under, keyed by (emulator, name).  verify.py needs that mapping to
    withdraw from its report exactly what the builder withdraws from the pack:
    grouping the declared files here and the core extras there would let the
    two answer differently on the same request.
    """
    groups: dict[str, list[tuple[str, str]]] = {}
    for sys_id, system in systems.items():
        members = groups.setdefault(sys_id, [])
        for file_entry in system.get("files", []):
            dest = sanitize_pack_path(
                file_entry.get("destination", file_entry.get("name", ""))
            )
            if dest:
                members.append((dest, file_entry.get("name", "")))

    extra_dests: dict[tuple[str, str, str], str] = {}
    if not include_extras or db is None:
        return groups, extra_dests

    for extra in _collect_emulator_extras(
        config,
        emulators_dir,
        db,
        set(),
        base_dest,
        emu_profiles,
        target_cores=target_cores,
        include_all=include_all,
    ):
        dest = sanitize_pack_path(extra.get("destination", extra.get("name", "")))
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
        variant = extra.get("variant_group")
        for sys_id in _extra_system_ids(extra) or ["_extras"]:
            group_id = f"{sys_id}:variant:{variant}" if variant else sys_id
            groups.setdefault(group_id, []).append((dest, name))
    return groups, extra_dests

def _emulator_region_group(emu_name: str, profile: dict, file_entry: dict) -> str:
    """Stable group ID for regional alternatives within an emulator profile."""
    variant = file_entry.get("variant_group")
    if variant:
        return f"{emu_name}:variant:{variant}"
    system = file_entry.get("system")
    profile_systems = list(profile.get("systems", []))
    if not system and len(profile_systems) == 1:
        system = profile_systems[0]
    return f"{emu_name}:system:{system or '_profile'}"
