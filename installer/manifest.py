"""The file list: the words its fields use, and the checks it passes before any of it is trusted."""
from __future__ import annotations

import re
import urllib.parse
from pathlib import PurePosixPath

from installer.events import _clean_mapping
from installer.paths import RELATIVE_ROOTS, _entry_key, _roms_relation, _safe_relative_path, _safe_target_dir
from installer.remote import MAX_DOWNLOAD_SIZE, MAX_MANIFEST_FILES, MAX_TOTAL_DOWNLOAD_SIZE, _LOOPBACK_HOSTS

# Why a manifest leaves a file out, as the installer words it. The manifest
# schema and the generator are held to this list by the tests.
OMISSION_REASONS = {
    "hash_mismatch": "hash mismatch",
    "not_found": "not found",
    "external": "external",
    "user_provided": "user provided",
    "no_platform_slug": "no platform folder",
    "below_platform_folder": "below the platform folder",
    "no_save_directory": "no save directory",
    "no_core_folder": "no core folder",
    "no_save_system": "no system runs the core",
    "outside_bios_folder": "read outside the BIOS folder",
    "no_roms_directory": "no roms folder",
    "no_configs_directory": "no configs folder",
    "no_emulators_directory": "no emulator folder",
}
# What a file is when it is not firmware, as the manifest's category field
# says, and as the installer words it. Firmware carries no category.
GAME_DATA = "game_data"
CATEGORY_LABELS = {GAME_DATA: "game data"}
# The manifest writes its digests in lowercase, as hashlib gives them, and
# every comparison reads them as written.
_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


# Marks a region group named after one file that no system names.
FILE_GROUP = ":file:"
MAX_SELECTION_TAGS = 1000
SELECTION_FIELDS = ("systems", "regions", "region_groups", "region_system_groups")
# The files cores load for systems the platform does not list (game engines,
# computers): no system of the platform owns them, and choosing systems
# leaves them out unless this name is chosen too.
OTHER_SYSTEMS = "other"


def _check_root(entry: dict, dest: str, omitted: bool = False) -> None:
    """root is absent or save, emulator only on a file left out (a path in
    the emulator's own folder, outside the BIOS tree), and core_folder one
    folder name of a save entry."""
    root = entry.get("root")
    if root not in (None, "save", "emulators", *RELATIVE_ROOTS) and not (
            omitted and root == "emulator"):
        raise ValueError(f"invalid root for {dest}")
    if root == "emulators" and len(PurePosixPath(dest).parts) < 2:
        raise ValueError(f"an emulators entry names its folder first: {dest}")
    folder = entry.get("core_folder")
    if folder is None:
        return
    if root != "save":
        raise ValueError(f"core_folder outside root: save for {dest}")
    if len(_safe_relative_path(folder, f"core_folder of {dest}").parts) != 1:
        raise ValueError(f"core_folder must be one folder name for {dest}")


def _check_relative_directories(data: dict) -> None:
    """The manifest's roms_directory and configs_directory, which every
    installable root: roms or root: configs entry needs."""
    installable = [
        entry for field in ("files", "case_variants")
        for entry in data.get(field) or [] if isinstance(entry, dict)
    ]
    for root in RELATIVE_ROOTS:
        field = f"{root}_directory"
        layout = data.get(field)
        if layout is None:
            if any(entry.get("root") == root for entry in installable):
                raise ValueError(f"entries below the {root} folder and no {field}")
            continue
        if (
            not isinstance(layout, dict)
            or set(layout) != {"bios_folder", "from_bios"}
            or len(_safe_relative_path(layout["bios_folder"], f"{field}.bios_folder").parts) != 1
        ):
            raise ValueError(f"invalid {field}")
        _roms_relation(layout["from_bios"], f"{field}.from_bios")


def _check_emulators_directory(data: dict) -> None:
    """The manifest's emulators_directory, which every installable root: emulators entry needs."""
    layout = data.get("emulators_directory")
    installable = [
        entry for field in ("files", "case_variants")
        for entry in data.get(field) or [] if isinstance(entry, dict)
    ]
    if layout is None:
        if any(entry.get("root") == "emulators" for entry in installable):
            raise ValueError("entries in emulator folders and no emulators_directory")
        return
    if not isinstance(layout, dict) or set(layout) != {"bios_folder", "searched", "default", "config"}:
        raise ValueError("invalid emulators_directory")
    searched = layout["searched"]
    if (
        not isinstance(searched, list) or not searched or layout["default"] not in searched
        or len(_safe_relative_path(layout["bios_folder"], "emulators_directory.bios_folder").parts) != 1
    ):
        raise ValueError("invalid emulators_directory")
    for template in searched:
        if not isinstance(template, str) or template.count("{key}") != 1:
            raise ValueError("invalid emulators_directory.searched")
        _safe_relative_path(
            template.replace("{key}", "key"), "emulators_directory.searched", colons=False
        )
    _safe_relative_path(layout["default"].replace("{key}", "key"), "emulators_directory.default",
                        colons=False)
    _safe_relative_path(layout["config"], "emulators_directory.config", colons=False)


def _check_save_directory(data: dict) -> None:
    """The manifest's save_directory, which every root: save entry needs."""
    layout = data.get("save_directory")
    entries = [
        entry for field in ("files", "case_variants", "omitted_files")
        for entry in data.get(field) or [] if isinstance(entry, dict)
    ]
    if layout is None:
        # An omission may name one: the list says the file exists and why
        # this platform cannot place it.
        installable = [
            entry for field in ("files", "case_variants")
            for entry in data.get(field) or [] if isinstance(entry, dict)
        ]
        if any(entry.get("root") == "save" for entry in installable):
            raise ValueError("entries below the save directory and no save_directory")
        return
    if (
        not isinstance(layout, dict)
        or set(layout) - {"by_system"} != {"folder", "by_core"}
        or not isinstance(layout["by_core"], bool)
        or layout.get("by_system", True) is not True
        or not _safe_relative_path(layout["folder"], "save_directory.folder").parts
    ):
        raise ValueError("invalid save_directory")
    if layout["by_core"]:
        # The core's folder heads each dest it names: dropped, never guessed,
        # where the frontend does not sort saves by core.
        for entry in entries:
            folder = entry.get("core_folder")
            dest = entry.get("dest")
            if folder and isinstance(dest, str) and dest.split("/", 1)[0] != folder:
                raise ValueError(f"{dest} does not start with its core_folder {folder}")


def _check_tags(entry: dict, field: str, where: str) -> None:
    """A selection field is absent or a short list of short strings."""
    value = entry.get(field)
    if value is None:
        return
    if (
        not isinstance(value, list)
        or len(value) > MAX_SELECTION_TAGS
        or not all(isinstance(tag, str) and 0 < len(tag) <= 256 for tag in value)
    ):
        raise ValueError(f"invalid {field} for {where}")


# What an alternative replaces on the entry it stands in for.
_COPY_FIELDS = (
    "sha1", "sha256", "size", "repo_path", "release_asset", "storage", "cores", "executable",
)


def _check_omission(entry: dict, dest: str) -> None:
    """The fields of a file left out: an omitted entry, or the claim of a core
    with nothing held at a destination another core's copy serves."""
    if not isinstance(entry.get("name"), str) or not entry["name"]:
        raise ValueError(f"invalid omitted file name for {dest}")
    if not isinstance(entry.get("system", ""), str):
        raise ValueError(f"invalid omitted system for {dest}")
    if not isinstance(entry.get("required"), bool):
        raise ValueError(f"invalid omitted required flag for {dest}")
    if entry.get("reason") not in OMISSION_REASONS:
        raise ValueError(f"invalid omission reason for {dest}")
    if "held" in entry and entry["held"] is not True:
        raise ValueError(f"invalid omitted held flag for {dest}")
    cores = entry.get("cores")
    if cores is not None and (
        not isinstance(cores, list)
        or not all(isinstance(core, str) for core in cores)
    ):
        raise ValueError(f"invalid omitted cores list for {dest}")
    for field in SELECTION_FIELDS:
        _check_tags(entry, field, dest)


def _check_download(entry: dict, where: str, dest: str) -> int:
    """The size, hashes, source and cores of one downloadable copy, and its size."""
    size = entry.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or not (0 <= size <= MAX_DOWNLOAD_SIZE):
        raise ValueError(f"invalid size for {dest}")

    sha1 = entry.get("sha1", "")
    sha256 = entry.get("sha256", "")
    if sha1 and (not isinstance(sha1, str) or not _SHA1_RE.fullmatch(sha1)):
        raise ValueError(f"invalid SHA1 for {dest}")
    if sha256 and (
        not isinstance(sha256, str) or not _SHA256_RE.fullmatch(sha256)
    ):
        raise ValueError(f"invalid SHA256 for {dest}")
    if not sha1 and not sha256:
        raise ValueError(f"missing content hash for {dest}")

    release_asset = entry.get("release_asset")
    repo_path = entry.get("repo_path")
    if release_asset:
        asset = _safe_relative_path(release_asset, f"{where}.release_asset")
        if len(asset.parts) != 1:
            raise ValueError(f"release asset must be a basename: {release_asset}")
    elif repo_path:
        source = _safe_relative_path(repo_path, f"{where}.repo_path")
        if source.parts[0] != "bios":
            raise ValueError(f"repo_path outside bios/: {repo_path}")
    else:
        raise ValueError(f"no download source for {dest}")

    cores = entry.get("cores")
    if cores is not None and (
        not isinstance(cores, list) or not all(isinstance(core, str) for core in cores)
    ):
        raise ValueError(f"invalid cores list for {dest}")
    if not isinstance(entry.get("executable", False), bool):
        raise ValueError(f"invalid executable flag for {dest}")
    return size


def _check_slot(entry: dict, where: str, dest: str) -> int:
    """The copies a platform file takes as cores and systems drop, and the largest size."""
    choices = entry.get("slot_choices", [])
    declared = entry.get("declared_choices")
    if declared is None and not choices:
        return 0
    if (
        entry.get("cores") is not None
        or not isinstance(choices, list)
        or not isinstance(declared, list)
        or not declared
        or len(choices) > MAX_SELECTION_TAGS
        or len(declared) > MAX_SELECTION_TAGS
    ):
        raise ValueError(f"invalid slot choices for {dest}")
    size = 0
    for index, choice in enumerate(declared):
        systems = choice.get("systems") if isinstance(choice, dict) else None
        if (
            not isinstance(systems, list)
            or not systems
            or not all(isinstance(s, str) for s in systems)
            or not set(choice) <= (set(_COPY_FIELDS) - {"cores"}) | {"systems"}
        ):
            raise ValueError(f"invalid declared choice for {dest}")
        size = max(size, _check_download(choice, f"{where}.declared_choices[{index}]", dest))
    for index, choice in enumerate(choices):
        if (
            not isinstance(choice, dict)
            or not choice.get("cores")
            or not set(choice) <= set(_COPY_FIELDS)
        ):
            raise ValueError(f"invalid slot choice for {dest}")
        # A choice naming only cores leaves the platform's own answer.
        if set(choice) != {"cores"}:
            size = max(size, _check_download(
                choice, f"{where}.slot_choices[{index}]", dest
            ))
    return size


def _check_entry(
    entry: object, where: str, seen_destinations: set[str]
) -> tuple[int, int]:
    """Check one file entry, return its size and the largest copy it may fetch."""
    if not isinstance(entry, dict):
        raise ValueError(f"{where} must be an object")
    # Below a roms or emulator folder a colon has no use: refused outright.
    dest = str(_safe_relative_path(
        entry.get("dest"), f"{where}.dest",
        colons=entry.get("root") not in ("emulators", *RELATIVE_ROOTS),
    ))
    key = _entry_key({**entry, "dest": dest})
    if key in seen_destinations:
        raise ValueError(f"duplicate manifest destination: {dest}")
    seen_destinations.add(key)
    _check_root(entry, dest)

    size = _check_download(entry, where, dest)
    largest = size
    alternatives = entry.get("alternatives", [])
    if not isinstance(alternatives, list) or len(alternatives) > MAX_SELECTION_TAGS:
        raise ValueError(f"invalid alternatives for {dest}")
    for alt_index, alternative in enumerate(alternatives):
        if (
            not isinstance(alternative, dict)
            or not alternative.get("cores")
            or not set(alternative) <= set(_COPY_FIELDS)
        ):
            raise ValueError(f"invalid alternative for {dest}")
        # Narrowing can swap in any copy: the cap holds for the largest.
        largest = max(largest, _check_download(
            alternative, f"{where}.alternatives[{alt_index}]", dest
        ))
    largest = max(largest, _check_slot(entry, where, dest))
    absent = entry.get("absent_claims", [])
    if not isinstance(absent, list) or len(absent) > MAX_SELECTION_TAGS:
        raise ValueError(f"invalid absent claims for {dest}")
    for claim in absent:
        if not isinstance(claim, dict):
            raise ValueError(f"invalid absent claim for {dest}")
        _check_omission(claim, dest)
    for field in (*SELECTION_FIELDS, "declared_in"):
        _check_tags(entry, field, dest)
    _check_expert_fields(entry, dest)
    return size, largest


def _check_expert_fields(entry: dict, dest: str) -> None:
    """`truth` and `slot`, what --source truth and --one-per-slot read."""
    if "truth" in entry and entry["truth"] is not False:
        raise ValueError(f"invalid truth flag for {dest}")
    slot = entry.get("slot")
    if slot is None:
        return
    if not isinstance(slot, dict) or not {"groups", "keys"} <= set(slot) <= {
            "groups", "keys", "also"}:
        raise ValueError(f"invalid slot for {dest}")
    also = slot.get("also", [])
    if not isinstance(also, list) or len(also) > MAX_SELECTION_TAGS:
        raise ValueError(f"invalid slot for {dest}")
    for chain in [slot, *also]:
        if not isinstance(chain, dict) or not {"groups", "keys"} <= set(chain) or (
                chain is not slot and set(chain) != {"groups", "keys"}):
            raise ValueError(f"invalid slot for {dest}")
        _check_slot_chain(chain, dest)


def _check_slot_chain(chain: dict, dest: str) -> None:
    """One name's groups and the claims at each key its lookup tries."""
    if not isinstance(chain.get("groups"), list):
        raise ValueError(f"invalid slot groups for {dest}")
    _check_tags(chain, "groups", dest)
    keys = chain["keys"]
    if not isinstance(keys, list) or len(keys) > MAX_SELECTION_TAGS:
        raise ValueError(f"invalid slot keys for {dest}")
    for claims in keys:
        if not isinstance(claims, dict) or not claims or len(claims) > MAX_SELECTION_TAGS:
            raise ValueError(f"invalid slot claims for {dest}")
        for name, claim in claims.items():
            if not isinstance(claim, dict):
                raise ValueError(f"invalid slot claim for {dest}")
            ranks = claim.get("ranks")
            if (not isinstance(name, str) or not 0 < len(name) <= 256
                    or not set(claim) <= {"ranks", "regions", "sets"}
                    or not isinstance(ranks, list) or not ranks
                    or len(ranks) > MAX_SELECTION_TAGS
                    or not all(rank is None or (isinstance(rank, int)
                                                and not isinstance(rank, bool))
                               for rank in ranks)):
                raise ValueError(f"invalid slot claim for {dest}")
            _check_tags(claim, "regions", dest)
            _check_tags(claim, "sets", dest)


def _check_omitted_entry(entry: dict, dest: str) -> None:
    """An omission's fields, its cores' claims and its expert fields, the
    same for omitted_files and truth_omitted."""
    _check_omission(entry, dest)
    _check_root(entry, dest, omitted=True)
    claims = entry.get("alternatives", [])
    if not isinstance(claims, list) or len(claims) > MAX_SELECTION_TAGS:
        raise ValueError(f"invalid omitted alternatives for {dest}")
    for claim in claims:
        claim_cores = claim.get("cores") if isinstance(claim, dict) else None
        if (
            not isinstance(claim, dict)
            or set(claim) != {"cores"}
            or not isinstance(claim_cores, list)
            or not claim_cores
            or not all(isinstance(core, str) for core in claim_cores)
        ):
            raise ValueError(f"invalid omitted alternative for {dest}")
    for field in (*SELECTION_FIELDS, "declared_in"):
        _check_tags(entry, field, dest)
    _check_expert_fields(entry, dest)


def _check_truth_lists(data: dict, seen_destinations: set[str]) -> int:
    """truth_files and truth_omitted, what --source truth adds to the list:
    each a valid entry, and the truth list it makes holds each destination
    once. Returns the largest size the truth files may fetch."""
    files = data.get("truth_files")
    if files is None:
        if "truth_omitted" in data:
            raise ValueError("truth_omitted without truth_files")
        return 0
    if not isinstance(files, list) or len(files) > MAX_MANIFEST_FILES:
        raise ValueError("invalid truth_files list")
    kept = {_entry_key(entry) for entry in data.get("files", [])
            if entry.get("truth", True)}
    seen: set[str] = set()
    largest = 0
    for index, entry in enumerate(files):
        _size, most = _check_entry(entry, f"truth_files[{index}]", seen)
        largest += most
    if seen & kept:
        raise ValueError("truth_files repeats a destination the truth list keeps")
    omitted = data.get("truth_omitted", [])
    if not isinstance(omitted, list) or len(omitted) > MAX_MANIFEST_FILES:
        raise ValueError("invalid truth_omitted list")
    for index, entry in enumerate(omitted):
        if not isinstance(entry, dict):
            raise ValueError(f"truth_omitted[{index}] must be an object")
        dest = str(_safe_relative_path(entry.get("dest"), f"truth_omitted[{index}].dest"))
        _check_omitted_entry(entry, dest)
    return largest


def _check_standalone_layouts(data: object, manifest: dict, plat: str) -> dict:
    """install/standalone/<platform>.json, checked as the list is: per
    emulator the list names, entries or [dest, sha1] pairs whose content
    the list carries. Returns the layouts."""
    if not isinstance(data, dict) or data.get("schema") != 1 or data.get("platform") != plat:
        raise ValueError(f"it is no standalone layout of {plat}")
    layouts = data.get("standalone_layouts")
    if not isinstance(layouts, dict) or len(layouts) > MAX_SELECTION_TAGS:
        raise ValueError("invalid standalone_layouts")
    if sorted(layouts) != sorted(manifest.get("standalone_builds") or []):
        raise ValueError("its builds are not the ones the file list names")
    sizes = {
        copy["sha1"]: copy.get("size", 0)
        for entry in [*manifest.get("files", []), *(manifest.get("truth_files") or [])]
        for copy in [entry, *entry.get("alternatives", []), *entry.get("slot_choices", [])]
        if isinstance(copy, dict) and copy.get("sha1")
        and (copy.get("repo_path") or copy.get("release_asset"))
    }
    for name, items in layouts.items():
        if (not isinstance(name, str) or not 0 < len(name) <= 256
                or not isinstance(items, list) or len(items) > MAX_MANIFEST_FILES):
            raise ValueError("invalid standalone_layouts entry")
        seen: set[str] = set()
        largest = 0
        for index, item in enumerate(items):
            where = f"standalone_layouts[{name!r}][{index}]"
            if isinstance(item, list):
                if (len(item) != 2 or not isinstance(item[1], str)
                        or item[1] not in sizes):
                    raise ValueError(f"invalid {where}")
                key = _entry_key({"dest": str(_safe_relative_path(item[0], where))})
                if key in seen:
                    raise ValueError(f"duplicate destination in {where}")
                seen.add(key)
                largest += int(sizes[item[1]] or 0)
            else:
                largest += _check_entry(item, where, seen)[1]
            if largest > MAX_TOTAL_DOWNLOAD_SIZE:
                raise ValueError("standalone build size exceeds safety limit")
    return layouts


def _check_data_directory_files(files: object, where: str) -> None:
    """A data directory's file list: relative paths, each with sha1 and size."""
    if not isinstance(files, dict) or not files or len(files) > MAX_MANIFEST_FILES:
        raise ValueError(f"{where}.files is invalid")
    for rel, meta in files.items():
        _safe_relative_path(rel, f"{where}.files")
        if (
            not isinstance(meta, dict)
            or not isinstance(meta.get("sha1"), str)
            or not _SHA1_RE.fullmatch(meta["sha1"])
            or not isinstance(meta.get("size"), int)
            or not 0 <= meta["size"] <= MAX_DOWNLOAD_SIZE
        ):
            raise ValueError(f"{where}.files[{rel!r}] is invalid")


def _check_data_directory(entry: object, where: str) -> None:
    """A data directory: its source archive, its mapping, its file list."""
    if not isinstance(entry, dict):
        raise ValueError(f"{where} must be an object")
    if not isinstance(entry.get("ref"), str) or not entry["ref"]:
        raise ValueError(f"{where}.ref is missing")
    if entry.get("dest", "") != "":
        _safe_relative_path(entry.get("dest"), f"{where}.dest")
    url = entry.get("url")
    parsed = urllib.parse.urlparse(url if isinstance(url, str) else "")
    if not (parsed.scheme == "https" or (
        parsed.scheme == "http" and (parsed.hostname or "") in _LOOPBACK_HOSTS
    )):
        raise ValueError(f"{where}.url must use HTTPS")
    kind = entry.get("type")
    if kind not in ("zip", "tarball"):
        raise ValueError(f"{where}.type must be zip or tarball")
    strip = entry.get("strip_components", 0)
    if not isinstance(strip, int) or isinstance(strip, bool) or not 0 <= strip <= 16:
        raise ValueError(f"{where}.strip_components is invalid")
    size = entry.get("archive_size", 1)
    if not isinstance(size, int) or isinstance(size, bool) or size < 1:
        raise ValueError(f"{where}.archive_size is invalid")
    if kind == "tarball" and (
        not isinstance(entry.get("source_path"), str) or not entry["source_path"]
    ):
        raise ValueError(f"{where}.source_path is missing")
    for field in ("exclude", "systems"):
        values = entry.get(field, [])
        if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            raise ValueError(f"{where}.{field} is invalid")
    if entry.get("optional", True) is not True:
        raise ValueError(f"{where}.optional is invalid")
    cores = entry.get("cores", ["-"])
    if not isinstance(cores, list) or not cores or not all(isinstance(c, str) and c for c in cores):
        raise ValueError(f"{where}.cores is invalid")
    _check_data_directory_files(entry.get("files"), where)


def _check_manifest_entries(data: dict, files: list) -> tuple[set[str], int, int]:
    """The files and case_variants lists: their destinations, the declared
    total and the largest total a download can reach."""
    seen_destinations: set[str] = set()
    total_size = 0
    largest_total = 0
    for index, entry in enumerate(files):
        size, largest = _check_entry(entry, f"files[{index}]", seen_destinations)
        total_size += size
        largest_total += largest
        if largest_total > MAX_TOTAL_DOWNLOAD_SIZE:
            raise ValueError("manifest total size exceeds safety limit")
    variants = data.get("case_variants", [])
    if not isinstance(variants, list) or len(variants) > MAX_MANIFEST_FILES:
        raise ValueError("invalid case_variants list")
    for index, entry in enumerate(variants):
        _size, largest = _check_entry(
            entry, f"case_variants[{index}]", seen_destinations
        )
        largest_total += largest
        if largest_total > MAX_TOTAL_DOWNLOAD_SIZE:
            raise ValueError("manifest total size exceeds safety limit")
    return seen_destinations, total_size, largest_total


def _check_manifest_directories(data: dict) -> None:
    """The data directories and the save, relative and emulators folders."""
    data_dirs = data.get("data_directories", [])
    if not isinstance(data_dirs, list) or len(data_dirs) > MAX_SELECTION_TAGS:
        raise ValueError("invalid data_directories list")
    for index, entry in enumerate(data_dirs):
        _check_data_directory(entry, f"data_directories[{index}]")
    _check_save_directory(data)
    _check_relative_directories(data)
    _check_emulators_directory(data)


def _check_omitted_list(omitted: list, seen_destinations: set[str]) -> None:
    """Each omitted file: an object at a destination no other entry holds."""
    seen_omitted: set[str] = set()
    for index, entry in enumerate(omitted):
        if not isinstance(entry, dict):
            raise ValueError(f"omitted_files[{index}] must be an object")
        dest = str(
            _safe_relative_path(
                entry.get("dest"), f"omitted_files[{index}].dest"
            )
        )
        key = _entry_key({**entry, "dest": dest})
        if key in seen_destinations or key in seen_omitted:
            raise ValueError(f"duplicate or conflicting omitted destination: {dest}")
        seen_omitted.add(key)
        _check_omitted_entry(entry, dest)


def _check_manifest_mappings(data: dict) -> None:
    """The core and system mappings, the offered boards and the system titles."""
    for field in ("core_names", "downloaded_cores", "system_cores", "system_names"):
        mapping = data.get(field)
        if mapping is None:
            continue
        if not isinstance(mapping, dict) or len(mapping) > MAX_MANIFEST_FILES:
            raise ValueError(f"invalid {field}")
        for key in mapping:
            if not isinstance(key, str) or not 0 < len(key) <= 256:
                raise ValueError(f"invalid {field} key")
            _check_tags(mapping, key, field)
            if mapping[key] is None:
                raise ValueError(f"invalid {field} for {key}")
    offered = data.get("offered_boards")
    if offered is not None:
        _check_offered_boards(offered)
    titles = data.get("system_titles")
    if titles is not None:
        _check_system_titles(titles)


def _check_offered_boards(offered: object) -> None:
    """offered_boards: per name, the folders and boards it is offered on."""
    if not isinstance(offered, dict) or len(offered) > MAX_MANIFEST_FILES:
        raise ValueError("invalid offered_boards")
    for key, places in offered.items():
        if not isinstance(key, str) or not 0 < len(key) <= 256:
            raise ValueError("invalid offered_boards key")
        if not isinstance(places, list) or not all(
            isinstance(p, dict) and isinstance(p.get("folder"), str)
            and p.get("root") in ("roms", "install")
            and isinstance(p.get("boards"), list)
            and all(isinstance(b, str) for b in p["boards"])
            for p in places
        ):
            raise ValueError(f"invalid offered_boards for {key}")


def _check_system_titles(titles: object) -> None:
    """system_titles: a short title per system."""
    if not isinstance(titles, dict) or len(titles) > MAX_MANIFEST_FILES:
        raise ValueError("invalid system_titles")
    for key, title in titles.items():
        if not isinstance(key, str) or not 0 < len(key) <= 256:
            raise ValueError("invalid system_titles key")
        if not isinstance(title, str) or not 0 < len(title) <= 256:
            raise ValueError(f"invalid system_titles for {key}")


def _check_copy_note(entry: dict, where: str) -> None:
    """A note of standalone_copies: its text and the detect lists."""
    detect = entry.get("detect", {})
    if not isinstance(entry["note"], str) or not isinstance(detect, dict):
        raise ValueError(f"invalid note entry at {where}")
    for values in detect.values():
        if not isinstance(values, list) or not all(
            isinstance(value, str) for value in values
        ):
            raise ValueError(f"invalid note entry at {where}")


def _check_copy_targets(entry: dict, index: int) -> None:
    """The target folders of a standalone copy."""
    targets = entry.get("targets", {})
    if targets and not isinstance(targets, dict):
        raise ValueError(f"invalid standalone copy targets at index {index}")
    for values in (targets or {}).values():
        if not isinstance(values, list) or len(values) > 100:
            raise ValueError(f"invalid standalone copy targets at index {index}")
        for value in values:
            _safe_target_dir(value, f"standalone_copies[{index}].targets")


def _check_standalone_copy(entry: object, index: int) -> None:
    """One entry of standalone_copies."""
    if not isinstance(entry, dict):
        raise ValueError(f"standalone_copies[{index}] must be an object")
    # The shape do_standalone_copies reads, checked here: a note with a
    # list for detect, a copy naming neither file nor pattern, or a list
    # for emulator passed and crashed the copy step after the download.
    where = f"standalone_copies[{index}]"
    if "note" in entry:
        _check_copy_note(entry, where)
        return
    if "file" not in entry and "pattern" not in entry:
        raise ValueError(f"{where} names neither a file nor a pattern")
    if not isinstance(entry.get("emulator", ""), str):
        raise ValueError(f"invalid emulator at {where}")
    if "file" in entry:
        _safe_relative_path(
            entry["file"], f"standalone_copies[{index}].file"
        )
    if "source" in entry:
        _safe_relative_path(
            entry["source"], f"standalone_copies[{index}].source"
        )
    if "as" in entry and (
        "file" not in entry or not isinstance(entry["as"], str)
        or PurePosixPath(_safe_relative_path(
            entry["as"], f"standalone_copies[{index}].as")).name != entry["as"]
    ):
        raise ValueError(f"invalid standalone copy name at {where}")
    if "pattern" in entry:
        pattern = entry["pattern"]
        if (
            not isinstance(pattern, str)
            or not pattern
            or len(pattern) > 256
            or "/" in pattern
            or "\\" in pattern
            or ".." in pattern
        ):
            raise ValueError(f"invalid standalone copy pattern: {pattern!r}")
    _check_copy_targets(entry, index)


def _validate_manifest(data: object, plat: str) -> dict:
    """Validate the untrusted install-manifest boundary using stdlib only."""
    if not isinstance(data, dict):
        raise ValueError("manifest root must be an object")
    if data.get("manifest_version") not in (1, 2):
        raise ValueError("unsupported manifest_version")
    if data.get("platform") != plat:
        raise ValueError("manifest platform does not match request")
    files = data.get("files")
    if not isinstance(files, list) or len(files) > MAX_MANIFEST_FILES:
        raise ValueError("invalid manifest files list")

    seen_destinations, total_size, largest_total = _check_manifest_entries(data, files)
    _check_manifest_directories(data)

    declared_total_files = data.get("total_files")
    if declared_total_files is not None and declared_total_files != len(files):
        raise ValueError("manifest total_files does not match files list")
    declared_total_size = data.get("total_size")
    if declared_total_size is not None and declared_total_size != total_size:
        raise ValueError("manifest total_size does not match file sizes")

    omitted = data.get("omitted_files", [])
    if not isinstance(omitted, list) or len(omitted) > MAX_MANIFEST_FILES:
        raise ValueError("invalid omitted_files list")
    _check_omitted_list(omitted, seen_destinations)
    if data.get("slot_fields", True) is not True:
        raise ValueError("invalid slot_fields")
    largest_total += _check_truth_lists(data, seen_destinations)
    if "standalone_builds" in data:
        _check_tags(data, "standalone_builds", "the file list")
    if largest_total > MAX_TOTAL_DOWNLOAD_SIZE:
        raise ValueError("manifest total size exceeds safety limit")
    declared_total_omitted = data.get("total_omitted")
    if (
        declared_total_omitted is not None
        and declared_total_omitted != len(omitted)
    ):
        raise ValueError("manifest total_omitted does not match omitted_files")

    _check_manifest_mappings(data)

    copies = data.get("standalone_copies", [])
    if not isinstance(copies, list) or len(copies) > 10_000:
        raise ValueError("invalid standalone_copies")
    for index, entry in enumerate(copies):
        _check_standalone_copy(entry, index)
    # Its paths checked above, every other string (a system's title, a
    # core's name) is shown as the terminal shows text.
    return _clean_mapping(data)


def _validate_targets(data: object) -> dict[str, dict]:
    """Validate and normalize legacy list-valued target manifests.

    A null core list means the target publishes no core inventory. That is a
    known target with no filter, not a broken manifest: rejecting it would
    discard every other target on the platform.
    """
    if not isinstance(data, dict) or len(data) > 10_000:
        raise ValueError("invalid targets manifest")
    normalized: dict[str, dict] = {}
    for target, value in data.items():
        if not isinstance(target, str) or not target or len(target) > 128:
            raise ValueError("invalid target name")
        if isinstance(value, dict):
            cores = value.get("cores")
        else:
            cores = value
        if cores is None:
            normalized[target] = {"cores": None}
            continue
        if not isinstance(cores, list) or len(cores) > 10_000 or not all(
            isinstance(core, str) and 0 < len(core) <= 256 for core in cores
        ):
            raise ValueError(f"invalid core list for target {target}")
        normalized[target] = {"cores": cores}
        images = value.get("images") if isinstance(value, dict) else None
        if images is None:
            continue
        if not isinstance(images, list) or len(images) > 10_000 or not all(
                isinstance(image, str) and 0 < len(image) <= 128 for image in images):
            raise ValueError(f"invalid image list for target {target}")
        normalized[target]["images"] = images
    return normalized
