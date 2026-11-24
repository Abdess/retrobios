"""Files a core finds by scanning a directory, and the companions beside an image."""

from __future__ import annotations

from dataclasses import dataclass

from model.declarations import OUTER_ROOTS
from model.profiles import entry_system_ids, lists_files, load_emulator_profiles
from packs.extraplace import prefixed_destination, take
from resolve.content import declares_shape, shape_fits, size_fits
from resolve.launches import PlatformLaunches
from resolve.layout import system_dir_path
from resolve.localfile import resolution_is_hash_exact, resolve_local_file
from resolve.standalone import platform_layouts
from resolve.entryscope import read_by_build, read_from_save_dir


@dataclass(frozen=True)
class _ScanContext:
    """What every seed of one agnostic scan reads and fills."""

    db: dict
    files_db: dict
    by_name: dict
    seen_dests: set
    extras_prefix: str
    taken: dict[str, dict] | None
    profiles: dict


@dataclass(frozen=True)
class _ResolvedDirs:
    """Where a profile's own files resolve, the evidence a scan anchors on."""

    dirs: dict[int, str]
    named_only: set[int]
    votes: dict[str, int]


@dataclass(frozen=True)
class _ScanSeed:
    """One agnostic entry of one layout and the folder its scan walks."""

    emu_name: str
    layout: dict
    entry: dict
    name: str
    companion_ext: str
    image: dict | None
    path_prefix: str
    exact_dirs: frozenset[str]
    folder: str


def agnostic_scan_extras(
    profiles: dict,
    relevant: set,
    db: dict,
    by_name: dict,
    seen_dests: set,
    extras_prefix: str,
    launches: PlatformLaunches | None = None,
    taken: dict[str, dict] | None = None,
) -> list[dict]:
    """Every interchangeable candidate a filename-agnostic core accepts.

    Such a core reads whatever sits in its BIOS directory, so the pack
    carries every dump of the right shape rather than one chosen name.
    The directory is the delicate part: anchoring it on a single
    filename walked into another emulator's tree, so the profile's own
    files have to agree before the scan follows an ambiguous name.
    """
    extras: list[dict] = []
    context = _ScanContext(
        db, db.get("files", {}), by_name, seen_dests, extras_prefix, taken, profiles,
    )
    # Third pass: the agnostic scan. For filename-agnostic cores, include all
    # DB files matching the system path prefix and size criteria.
    for emu_name, profile in sorted(profiles.items()):
        if not lists_files(profile):
            continue
        if emu_name not in relevant:
            continue
        is_profile_agnostic = profile.get("bios_mode") == "agnostic"
        if not is_profile_agnostic and not any(
            f.get("agnostic") for f in profile.get("files", [])
        ):
            continue
        resolved = _resolved_dirs(emu_name, profile, db)
        for layout, standalone in platform_layouts(emu_name, profile, launches or PlatformLaunches()):
            # A layout copies each entry in order (a launcher's folder, a
            # system directory): its files are looked up as the profile's
            # own, or a bound layout scans nothing (KNULLI's bios/ps2).
            origin = {
                id(view): entry
                for view, entry in zip(layout.get("files", []), profile.get("files", []))
            }
            for f in layout.get("files", []):
                if not is_profile_agnostic and not f.get("agnostic"):
                    continue
                seed = _scan_seed(context, emu_name, layout, f, standalone, origin, resolved)
                if seed is not None:
                    extras.extend(_seed_extras(context, seed))
    return extras


def _resolved_dirs(emu_name: str, profile: dict, db: dict) -> _ResolvedDirs:
    """Where each of this profile's files resolves.

    A scan anchored on one filename walks into whatever tree that name
    happens to hit: rom1.bin is a PS2 ROM and a Roland SC-55 ROM,
    GameIndex.yaml belongs to four PS2 profiles and to an Android package.
    One match is not evidence of a directory, two files of the same profile
    agreeing is.
    """
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
    return _ResolvedDirs(resolved_dirs, named_only, agnostic_votes)


def _seeds_a_scan(f: dict, layout: dict, standalone: bool) -> bool:
    """Whether an agnostic entry may seed a scan of the BIOS directory."""
    # A file of the build the platform does not run seeds nothing:
    # armsx2's proverb.zip is fetched by the Android app into its own
    # arcade/ folder, and the libretro packs carried it at system/.
    if not read_by_build(f, standalone):
        return False
    # The scan walks the BIOS tree: a file read below the save
    # directory is placed by the gap report's pass.
    if (read_from_save_dir(f, standalone) or f.get("unplaced")
            or f.get("root") in OUTER_ROOTS or f.get("unprefixed")):
        return False
    # An agnostic BIOS mode says the BIOS filename is free, not that
    # every file the emulator loads is.  A free filename still has a
    # known shape, and that shape is what identifies a candidate: an
    # entry declaring no size takes the whole directory, which is how
    # the flag icons of an Android package walked into a PS2 pack.
    if f.get("category", "bios") != "bios":
        return False
    if not declares_shape(f):
        return False
    # The free name is the BIOS directory's: a shader, a sound or a
    # font the emulator reads from its resources tree has a fixed
    # name and must not seed a scan (yaps2 flattened 189 of them to
    # the root of the RetroArch pack).
    bios_dir = layout.get("bios_directory")
    fpath = f.get("path") or ""
    return not (bios_dir and "/" in fpath and not fpath.startswith(bios_dir))


def _scan_seed(
    context: _ScanContext,
    emu_name: str,
    layout: dict,
    f: dict,
    standalone: bool,
    origin: dict[int, dict],
    resolved: _ResolvedDirs,
) -> _ScanSeed | None:
    """The scan an agnostic entry seeds, None when it seeds none."""
    fname = f.get("name", "")
    if not fname or not _seeds_a_scan(f, layout, standalone):
        return None

    # A companion is read under its image's name with the
    # extension the code appends, in that case: only a file of
    # that extension is one, spelled as the code spells it. Its
    # size identifies nothing, PCSX2 reads min(size, filesize)
    # (BiosTools.cpp:234), and a 4 MB bound swept every smaller
    # file of the folder to the BIOS root. It sits beside its
    # image, so the scan looks where the image resolves: the
    # held ps2-0230a-20080220.rom1 is a DVD firmware dump filed
    # under DVD Firmware/.
    companion_ext, image = _companion_of(layout, fname)

    path_prefix = (
        resolved.dirs.get(id(origin.get(id(image), image)), "") if image
        else resolved.dirs.get(id(origin.get(id(f), f)), "")
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
            anchor, emu_name, layout, context.db, context.profiles
        )
    if not path_prefix and not exact_dirs:
        return None
    # A name matching one file identifies it. A name matching several
    # identifies nothing on its own, so the profile's other files have
    # to agree on the directory before the scan walks it.
    ambiguous = (
        id(origin.get(id(f), f)) in resolved.named_only
        and len(context.by_name.get(fname, [])) > 1
    )
    if ambiguous and resolved.votes.get(path_prefix, 0) < 2:
        return None

    # Into the directory the seed entry names, not the root:
    # yaps2 reads its BIOS from pcsx2/bios/.
    seed = f.get("path") or ""
    if standalone:
        seed = f.get("standalone_path") or seed
    else:
        seed = system_dir_path(f, seed or fname)
    folder = seed.rsplit("/", 1)[0] if "/" in seed else ""
    return _ScanSeed(
        emu_name, layout, f, fname, companion_ext, image, path_prefix, exact_dirs, folder,
    )


def _scanned_name(context: _ScanContext, seed: _ScanSeed, entry: dict) -> tuple[str, str] | None:
    """(path, name in the pack) of a database file the seed's scan accepts."""
    path = entry.get("path", "")
    if seed.exact_dirs:
        if ("/" not in path or path.rsplit("/", 1)[0] not in seed.exact_dirs
                or "/.variants/" in path):
            return None
    elif not path.startswith(seed.path_prefix):
        return None
    if not seed.companion_ext and not shape_fits(seed.entry, path, entry.get("size", 0)):
        return None
    scan_name = entry.get("name", "")
    if not scan_name:
        return None
    if seed.companion_ext:
        stem, _, ext = scan_name.rpartition(".")
        if not stem or ext.lower() != seed.companion_ext.lower():
            return None
        # Read only beside the image the core selected, so a
        # companion counts only next to an image the image's
        # own test accepts: Namco System 246 .nvm and .mec
        # dumps sit beside no PS2 BIOS.
        if not _image_beside(path, stem, seed.image, context.files_db):
            return None
        scan_name = f"{stem}.{seed.companion_ext}"
    return path, scan_name


def _scan_extra(seed: _ScanSeed, scan_name: str, dest: str, sha1: str) -> dict:
    """The extra a scan emits for one database file."""
    f, layout, emu_name = seed.entry, seed.layout, seed.emu_name
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
        "source_emulator": layout.get("emulator", emu_name),
        "source_profile": emu_name,
        "source_name": seed.name,
        "source_path": f.get("path") or "",
        "category": f.get("category", "bios"),
        "source_system": f.get("system"),
        "source_systems": entry_system_ids(f, layout),
        "region": f.get("region"),
        "selection_slot": f.get("selection_slot"),
        "agnostic_scan": True,
    }
    extra["claim_order"] = (4, 0, emu_name)
    return extra


def _seed_extras(context: _ScanContext, seed: _ScanSeed) -> list[dict]:
    """The extras one seed's scan places, companions included."""
    extras: list[dict] = []
    taken = context.taken
    # Scan DB for all files under this prefix matching size
    for sha1, entry in context.files_db.items():
        scanned = _scanned_name(context, seed, entry)
        if scanned is None:
            continue
        path, scan_name = scanned
        dest = f"{seed.folder}/{scan_name}" if seed.folder else scan_name
        full_dest = prefixed_destination(dest, context.extras_prefix)
        if full_dest in context.seen_dests and (taken is None or full_dest not in taken):
            continue
        extra = _scan_extra(seed, scan_name, dest, sha1)
        if take(extra, full_dest, context.seen_dests, taken):
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
            _companions(
                path, scan_name, _companion_extensions(seed.layout, seed.name),
                context.files_db,
            ),
            seed.folder, context.extras_prefix, context.seen_dests, seed.layout,
            seed.emu_name, seed.entry, taken,
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
            if (local and "/" in local and resolution_is_hash_exact(status)
                    and shape_fits(seed, local)):
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
        if not declares_shape(seed):
            continue
        # <bios>.nvm is read beside the image the core selected, never on
        # its own: its files come with each scanned image (_companions).
        if _companion_of(profile, name)[1] is not None:
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
            if "/.variants/" in path or not shape_fits(seed, path, entry.get("size", 0)):
                continue
            scan_name = entry.get("name", "")
            dest = f"{folder}/{scan_name}" if folder else scan_name
            extras.append({
                "name": scan_name,
                "destination": dest,
                "sha1": sha1,
                "source_name": name,
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

    scanned = agnostic_scan_extras(
        {emu_name: {**profile, "files": files}}, {emu_name}, db,
        db.get("indexes", {}).get("by_name", {}), set(), "",
        PlatformLaunches(standalone=frozenset({emu_name})) if standalone else PlatformLaunches(),
    )

    # A placeholder is answered by the files its own scan found in its own
    # folder: PCEE2's eeprom.dat, scanned at the root, said nothing about
    # pcsx2/bios/, and its COH-H images, scanned into pcsx2/bios/, say
    # nothing about the console <bios>.bin beside them.
    def answered(extras: list[dict]) -> set[tuple[str, str]]:
        return {
            (str(e.get("source_name", "")),
             e["destination"].rsplit("/", 1)[0] if "/" in e["destination"] else "")
            for e in extras
        }

    def is_answered(f: dict, covered: set[tuple[str, str]]) -> bool:
        # A companion placeholder (<bios>.rom1) is read beside its image, so
        # it is answered wherever the image placeholder is.
        _ext, image = _companion_of(profile, str(f.get("name", "")))
        names = {f.get("name", "")} | ({image.get("name", "")} if image else set())
        return any((n, folder(f)) in covered for n in names)

    covered = answered(scanned)
    open_seeds = [
        f for f in files
        if "<" in str(f.get("name", "")) and not is_answered(f, covered)
    ]
    scanned += _placeholder_scan(
        open_seeds, emu_name, profile, db, standalone, all_profiles
    )
    covered = answered(scanned)
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
        if "<" not in str(f.get("name", "")) or not is_answered(f, covered)
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
        if take(extra, companion_full, seen_dests, taken):
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


def _image_beside(
    companion_path: str, stem: str, image: dict | None, files_db: dict
) -> bool:
    """Whether the folder of a companion holds an image it is read beside.

    PCSX2 opens `<bios>.rom1`, then the BIOS path with its extension
    replaced (BiosTools.cpp LoadExtraRom, CDVD.cpp cdvdLoadNVRAM): the
    companion's stem is the image's name or the image's own stem. The
    image has to pass the image entry's test, its size and its ROM
    directory, as the scan that selected it does.
    """
    if image is None:
        return False
    directory = companion_path.rsplit("/", 1)[0] + "/"
    wanted = stem.lower()
    for _sha1, entry in _files_by_directory(files_db).get(directory, ()):
        name = str(entry.get("name", ""))
        if name.lower() != wanted and name.rpartition(".")[0].lower() != wanted:
            continue
        if name.lower() == companion_path.rsplit("/", 1)[-1].lower():
            continue
        if shape_fits(image, entry.get("path", ""), entry.get("size", 0)):
            return True
    return False


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
