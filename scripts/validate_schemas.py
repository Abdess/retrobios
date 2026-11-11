#!/usr/bin/env python3
"""Validate source and generated RetroBIOS data contracts."""

from __future__ import annotations

import argparse
import json
import re
import sys
import zipfile
from collections.abc import Callable
from pathlib import Path, PurePosixPath

import yaml

from common import source_yaml_paths, yaml_load

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ImportError:
    # Tests import this module and skip on the ImportError, the command
    # names the install pipeline.py names for the same step.
    if __name__ != "__main__":
        raise
    sys.exit('Error: jsonschema required (pip install "jsonschema[format-nongpl]")')

ROOT = Path(__file__).resolve().parent.parent
SCHEMAS = ROOT / "schemas"


def _load_json(path: Path) -> object:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _validator(name: str) -> Draft202012Validator:
    schema = _load_json(SCHEMAS / name)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _errors(validator: Draft202012Validator, data: object, label: str) -> list[str]:
    out: list[str] = []
    for error in sorted(validator.iter_errors(data), key=lambda item: list(item.path)):
        location = "/".join(str(part) for part in error.absolute_path) or "<root>"
        out.append(f"{label}:{location}: {error.message}")
    return out


_SOURCES: dict[tuple[Path, int, int], object] = {}


def _load_source(path: Path) -> object:
    """A source YAML, parsed once per run whichever check reads it: the
    schema pass, the data directory refs and the layout check each parsed
    all 649 profiles again. Keyed by size and mtime too, so a file written
    again in the same process is read again."""
    stat = path.stat()
    key = (path, stat.st_mtime_ns, stat.st_size)
    if key not in _SOURCES:
        with path.open(encoding="utf-8") as handle:
            _SOURCES[key] = yaml_load(handle)
    return _SOURCES[key]


def _validate_yaml_directory(
    directory: Path,
    schema_name: str,
    *,
    skip_private: bool = False,
) -> list[str]:
    validator = _validator(schema_name)
    out: list[str] = []
    for path in source_yaml_paths(directory):
        if skip_private and path.name.startswith("_"):
            continue
        try:
            data = _load_source(path)
        except (OSError, yaml.YAMLError) as exc:
            out.append(f"{path.relative_to(ROOT)}: {exc}")
            continue
        out.extend(_errors(validator, data, str(path.relative_to(ROOT))))
        out.extend(_unreachable_citations(path, data))
        if schema_name == "platform.schema.json":
            out.extend(_config_records_without_evidence(path, data))
        if schema_name == "emulator.schema.json":
            out.extend(_config_reads_without_build(path, data))
            out.extend(_checks_without_values(path, data))
            out.extend(_save_dir_without_library_name(path, data))
            out.extend(_systems_outside_profile(path, data))
            out.extend(_doubled_paths(path))
            out.extend(_group_requirement_split(path, data))
            out.extend(_data_only_source_refs(path, data))
    return out


_CHECK_FIELDS = {
    "crc32": ("crc32",),
    "md5": ("md5",),
    "sha1": ("sha1",),
    "sha256": ("sha256",),
    "size": ("size", "min_size", "max_size", "size_multiple"),
    "romdir": ("romdir",),
    "masked_sha1": ("masked_sha1",),
}


def _config_records_without_evidence(path: Path, document: object) -> list[str]:
    """A launcher record citing a config without the links its extractor reads.

    A config file is proof only when the code installing it and the code
    reading it are shown (launchers.config_evidence). The platform's half
    is the extractor's to write: a record citing a shipped config carries
    installs and overrides, and a feature or option file is never a
    record's source, only its choices_from.
    """
    if not isinstance(document, dict):
        return []
    from scraper.shell_launchers import config_ref, is_feature_ref  # noqa: PLC0415

    out: list[str] = []
    for index, record in enumerate(document.get("launchers") or []):
        if not isinstance(record, dict):
            continue
        cited = config_ref(str(record.get("source_ref") or ""))
        where = f"{path.relative_to(ROOT)}: launchers[{index}] ({record.get('emulator')})"
        features = [part for part in cited if is_feature_ref(part)]
        if features:
            out.append(f"{where} cites {features[0]} as source, choices_from holds it")
        if [part for part in cited if not is_feature_ref(part)] and not (
            record.get("installs") and "overrides" in record
        ):
            out.append(f"{where} cites a config without installs and overrides")
    return out


def _config_reads_without_build(path: Path, document: object) -> list[str]:
    """A config_reads entry naming a platform the profile gives no pin_build.

    Such an entry is read at the build that platform ships, and pin_build is
    where that build is named.
    """
    if not isinstance(document, dict):
        return []
    builds = {str(b.get("platform")) for b in document.get("pin_build") or []}
    out: list[str] = []
    for index, read in enumerate(document.get("config_reads") or []):
        if not isinstance(read, dict):
            continue
        if read.get("revision"):
            continue
        for platform in read.get("platforms") or []:
            if str(platform) not in builds:
                out.append(
                    f"{path.relative_to(ROOT)}: config_reads[{index}] ({read.get('file')}) "
                    f"names {platform}, which has no pin_build"
                )
    return out


def _systems_outside_profile(path: Path, document: object) -> list[str]:
    """An entry's system: or systems: naming a system its profile does not list.

    A --system pick selects the profile by its systems: and then the entry
    by its own, so a name the profile lacks is one no pick ever reaches.
    """
    if not isinstance(document, dict):
        return []
    listed = {str(s) for s in document.get("systems") or []}
    out: list[str] = []
    for index, entry in enumerate(document.get("files") or []):
        if not isinstance(entry, dict):
            continue
        named = [entry["system"]] if entry.get("system") else []
        named += list(entry.get("systems") or [])
        unknown = [str(s) for s in named if str(s) not in listed]
        if unknown:
            out.append(
                f"{path.relative_to(ROOT)}: files[{index}] ({entry.get('name')}) "
                f"system {', '.join(unknown)} not in the profile's systems"
            )
    return out


def _group_requirement_split(path: Path, document: object) -> list[str]:
    """A set named by a member and not declared, declared and never used,
    or a member that writes a required of its own.

    The requirement belongs to the set, in the profile's groups map, and a
    member's is derived from it. A value on the member is a second source
    that can contradict the first: a true on the first name only wrote the
    search order into required, and the other names read as optional.
    """
    from alternatives import groups_of

    if not isinstance(document, dict):
        return []
    label = path.relative_to(ROOT)
    declared = set((document.get("groups") or {}).keys())
    used: set[str] = set()
    out: list[str] = []
    for index, entry in enumerate(document.get("files") or []):
        if not isinstance(entry, dict):
            continue
        names = groups_of(entry)
        used.update(names)
        if names and "required" in entry:
            out.append(f"{label}: files[{index}] ({entry.get('name')}) is in a group "
                       "and writes required: the set's requirement is in groups")
    out.extend(f"{label}: group {g} has no entry in groups" for g in sorted(used - declared))
    out.extend(f"{label}: groups declares {g}, which no entry names" for g in sorted(declared - used))
    return out


_CODE_SUFFIXES = frozenset(
    "c cc cpp cxx c++ h hh hpp hxx inc inl ipp m mm mjs cjs js jsx ts tsx py cs java kt "
    "go rs lua pas pp asm s sh bash zsh ps1 bat cmd vbs swift d zig nim qml qc rb pl php "
    "scala ml hs dart vue ino z80 smali".split()
)
_CODE_FILE = re.compile(r"(?<=[\w+-])\.([A-Za-z0-9+]+)\b")
# A compiled image: a part that names one has to say where in it the file
# is read, an address, a decompiled function or an IL method.
# A name under a directory is a file of the tree it sits in, and a further
# extension (.dll.map) makes it another file.
_BINARY_FILE = re.compile(
    r"(?<![\w/+.-])[\w+.-]+\.(?:so|dll|exe|dylib|dex|elf|nro|xex)(?:\.\d+)*(?![\w.-]*\w)",
    re.IGNORECASE,
)
_BINARY_EVIDENCE = re.compile(
    r"\b0x[0-9a-fA-F]+\b"
    r"|\b(?:FUN|sub|thunk|LAB)_[0-9a-fA-F]+\b"
    r"|\bIL_[0-9a-fA-F]{4}\b"
    r"|::|\.\.c?ctor\b"
    r"|\b[A-Za-z_][\w.$]*\("
)

# Profiles whose files cite no published code. Each reason says why the
# check cannot apply yet.
DATA_ONLY_REF_EXCEPTIONS: dict[str, str] = {}


def _ref_cites_code(ref: str) -> bool:
    """A source_ref cites a source file or a place in a compiled image.

    A part naming a binary without an address, a decompiled function or an
    IL method says only that the binary exists: "import directory",
    "string table" and "readelf -d" are not the code that reads a file.
    """
    from sourceref import split_source_ref

    cited = False
    for part in split_source_ref(ref):
        located = bool(_BINARY_EVIDENCE.search(part.raw)) or any(
            suffix.lower() in _CODE_SUFFIXES for suffix in _CODE_FILE.findall(part.raw)
        )
        if _BINARY_FILE.search(part.raw) and not located:
            return False
        cited = cited or located
    return cited


def _data_only_source_refs(path: Path, document: object) -> list[str]:
    """A files[] source_ref that cites only data or build files.

    A data file is evidence that the emulator reads a file only once the
    code that ships and parses it is cited too: iwadinfo.txt names the
    IWADs, d_iwad.cpp is what reads it. 655 entries in 27 profiles cited
    the table alone, and six of them named a file no code opens.
    """
    if not isinstance(document, dict) or path.stem in DATA_ONLY_REF_EXCEPTIONS:
        return []
    out: list[str] = []
    for index, entry in enumerate(document.get("files") or []):
        if not isinstance(entry, dict) or not entry.get("source_ref"):
            continue
        refs = entry["source_ref"]
        for ref in refs.values() if isinstance(refs, dict) else [refs]:
            if ref and not _ref_cites_code(str(ref)):
                out.append(
                    f"{path.relative_to(ROOT)}: files[{index}] ({entry.get('name')}) "
                    f"source_ref cites no code that reads the file: {ref}"
                )
    return out


def _checks_without_values(path: Path, document: object) -> list[str]:
    """A check an entry declares with nothing to compare against.

    validation: [crc32] with no crc32 runs nothing: the file passes whatever
    it holds, and the report reads as checked. Fourteen profiles carried
    one, the code they describe either refusing or warning on a value the
    entry never wrote down.
    """
    out: list[str] = []
    files = document.get("files") if isinstance(document, dict) else None
    for index, entry in enumerate(files or []):
        if not isinstance(entry, dict):
            continue
        declared = entry.get("validation") or []
        if isinstance(declared, dict):
            declared = [check for checks in declared.values() for check in checks or []]
        for check in declared:
            fields = _CHECK_FIELDS.get(check)
            if fields and not any(entry.get(field) not in (None, "", []) for field in fields):
                out.append(
                    f"{path.relative_to(ROOT)}: files[{index}] ({entry.get('name')}) "
                    f"declares a {check} check with no {'/'.join(fields)} value"
                )
    return out


def _validate_json_files(
    paths: list[Path],
    schema_name: str,
    semantic_check: Callable[[Path, object], list[str]] | None = None,
) -> list[str]:
    validator = _validator(schema_name)
    out: list[str] = []
    for path in paths:
        try:
            data = _load_json(path)
        except (OSError, json.JSONDecodeError) as exc:
            out.append(f"{path.relative_to(ROOT)}: {exc}")
            continue
        validation_errors = _errors(validator, data, str(path.relative_to(ROOT)))
        out.extend(validation_errors)
        if not validation_errors and semantic_check is not None:
            out.extend(semantic_check(path, data))
    return out


def _validate_pack_manifests(dist: Path) -> list[str]:
    """Validate the integrity manifest each generated pack carries.

    generate_pack.py writes manifest.json inside the archive, not beside it,
    so a filesystem glob over dist/ matches nothing and silently validates
    zero documents.

    Reading a pack while a build is writing it reports "File is not a zip
    file" about an archive that is merely half-written, so this takes the same
    shared lock --verify-packs does. A build holding the exclusive lock means
    the packs on disk are mid-flight and there is nothing stable to validate.
    """
    if not dist.is_dir():
        return []

    sys.path.insert(0, str(ROOT / "scripts"))
    from common import ArtifactLockBusy, artifact_lock

    try:
        with artifact_lock(str(dist), exclusive=False):
            return _scan_pack_manifests(dist)
    except ArtifactLockBusy:
        print(
            f"note: {dist.name} is being written, skipping pack manifests",
            file=sys.stderr,
        )
        return []


def _scan_pack_manifests(dist: Path) -> list[str]:
    validator = _validator("pack-manifest.schema.json")
    # The lists a pack carries for the installer, each under its own
    # contract: the schemas name no other file, so they are checked here.
    carried = {
        "install_list": _validator("install-manifest.schema.json"),
        "targets": _validator("target-manifest.schema.json"),
    }

    def _label(path: Path) -> str:
        resolved = path.resolve()
        try:
            return str(resolved.relative_to(ROOT))
        except ValueError:
            return str(resolved)

    out: list[str] = []
    for archive in sorted(dist.glob("*.zip")):
        try:
            with zipfile.ZipFile(archive) as handle:
                members = [
                    name
                    for name in handle.namelist()
                    if PurePosixPath(name).name == "manifest.json"
                ]
                for member in members:
                    label = f"{_label(archive)}:{member}"
                    try:
                        document = json.loads(handle.read(member).decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                        out.append(f"{label}: {exc}")
                        continue
                    out.extend(_errors(validator, document, label))
                    for key, inner in carried.items():
                        if isinstance(document, dict) and key in document:
                            out.extend(_errors(inner, document[key], f"{label}:{key}"))
        except (OSError, zipfile.BadZipFile) as exc:
            out.append(f"{_label(archive)}: {exc}")
    return out


_UNREACHABLE_REF = re.compile(
    r"(?:^|[\s,;(])(?:tmp/|/|[A-Za-z]:[\\/]|\.{1,2}/)[\w.\\/+-]*[\w+-]:\d+(?:-\d+)?"
)


def _unreachable_citations(path: Path, document: object) -> list[str]:
    """Refs naming a place no repository can hold.

    A citation is read against a revision of a declared repository, so a
    scratch directory, an absolute path or one climbing out of the tree can
    never resolve and never will. kenji-nx carried tmp/es-de/ANDROID.md:470,
    a path from whoever profiled it, which profile_sync could only report
    missing forever.
    """
    out: list[str] = []
    stack: list[object] = [document]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
        elif isinstance(node, str):
            for match in _UNREACHABLE_REF.finditer(node):
                out.append(
                    f"{path.relative_to(ROOT)}: citation names a path outside "
                    f"any repository: {match.group().strip(' ,;(')}"
                )
    return out


_DOUBLED_PATH = re.compile(r"((?:[\w.-]+/){2,})\1")


def _doubled_paths(path: Path) -> list[str]:
    """A citation whose directory is written twice in a row.

    Read from the raw text, comments included: primehack's note on the
    Realtek loader cited Source/Core/Core/IOS/USB/Bluetooth/ twice over, a
    path no revision holds, in a comment the parsed document never shows.
    """
    out: list[str] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = _DOUBLED_PATH.search(line)
        if match:
            out.append(
                f"{path.relative_to(ROOT)}:{number}: citation repeats its "
                f"directory: {match.group(1)}"
            )
    return out


def _unknown_data_dir_refs() -> list[str]:
    """data_directories refs the registry does not define.

    A ref nobody registers is never fetched: yaps2 named yaps2-resources and
    every run printed "not cached" while refresh_data_dirs had nothing to
    refresh.
    """
    registry_path = ROOT / "platforms" / "_data_dirs.yml"
    with registry_path.open(encoding="utf-8") as handle:
        registered = set((yaml_load(handle) or {}).get("data_directories", {}))
    out: list[str] = []
    for directory in (ROOT / "emulators", ROOT / "platforms"):
        for path in source_yaml_paths(directory):
            if path.name.startswith("_"):
                continue
            document = _load_source(path) or {}
            systems = document.get("systems")
            holders = [document, *(systems.values() if isinstance(systems, dict) else [])]
            for holder in holders:
                if not isinstance(holder, dict):
                    continue
                for entry in holder.get("data_directories") or []:
                    ref = entry.get("ref") if isinstance(entry, dict) else None
                    if ref and ref not in registered:
                        out.append(
                            f"{path.relative_to(ROOT)}: data directory {ref!r} "
                            f"is not in platforms/_data_dirs.yml"
                        )
    return out


def _repository_layout_in_profiles() -> list[str]:
    """Profile destinations that name this repository's storage.

    `path:` is where the emulator's code reads the file, never where we keep
    it: a profile written from a clone filed its variants under
    `.variants/...`, and the pack then wrote them where no emulator looks.
    """
    out: list[str] = []
    for path in source_yaml_paths(ROOT / "emulators"):
        document = _load_source(path) or {}
        for entry in document.get("files") or []:
            if not isinstance(entry, dict):
                continue
            for key in ("path", "standalone_path"):
                value = str(entry.get(key) or "")
                if ".variants" in value.replace("\\", "/").split("/"):
                    out.append(
                        f"{path.relative_to(ROOT)}: {entry.get('name')} {key} "
                        f"names the repository's .variants/ storage: {value}"
                    )
    return out


def _semantic_envelope_checks(path: Path, document: dict) -> list[str]:
    if document.get("count") != len(document.get("items", [])):
        return [f"{path.relative_to(ROOT)}: count does not equal len(items)"]
    return []


def _semantic_database_checks(database: dict) -> list[str]:
    out: list[str] = []
    files = database.get("files", {})
    if database.get("total_files") != len(files):
        out.append("database.json: total_files does not equal len(files)")
    if database.get("total_size") != sum(entry.get("size", 0) for entry in files.values()):
        out.append("database.json: total_size does not equal the file-size sum")
    # One path holds one content. Two entries naming the same path means one
    # of them declares a hash the file at that path does not have.
    owners: dict[str, str] = {}
    for sha1, entry in files.items():
        if entry.get("sha1") != sha1:
            out.append(f"database.json: files/{sha1}: key and sha1 differ")
        path = entry.get("path", "")
        if not path:
            continue
        first = owners.setdefault(path, sha1)
        if first != sha1:
            out.append(
                f"database.json: {path} is claimed by {first} and {sha1}"
            )
    return out


def _save_dir_without_library_name(path: Path, document: object) -> list[str]:
    """A file the libretro build reads below the save directory, in a profile
    naming no library_name.

    RetroArch hands each core <save directory>/<library_name> by default
    (sort_savefiles_enable): without the name, packs and the installer
    cannot say where the file goes, and leave it out.
    """
    from validation import read_from_save_dir

    if not isinstance(document, dict):
        return []
    if "library_name" in document:
        return _save_folder_once_paths(path, document)
    return [
        f"{path.relative_to(ROOT)}: files[{index}] ({entry.get('name')}) is read "
        "below the save directory and the profile declares no library_name"
        for index, entry in enumerate(document.get("files") or [])
        if isinstance(entry, dict)
        and read_from_save_dir(entry)
        and not ("path" in entry and entry["path"] is None)
    ]


def _save_folder_once_paths(path: Path, document: dict) -> list[str]:
    """A core adding its own folder once: each save path starts with it.

    The pack places such a file at <save directory>/<path> whether the
    frontend sorts saves by core or not, which holds only when the path
    already names the folder the core reads below.
    """
    from validation import read_from_save_dir

    if not document.get("save_folder_once"):
        return []
    folder = f"{document.get('library_name') or ''}/"
    return [
        f"{path.relative_to(ROOT)}: files[{index}] ({entry.get('name')}) does not "
        f"start with {folder}, the folder save_folder_once says the core adds"
        for index, entry in enumerate(document.get("files") or [])
        if isinstance(entry, dict)
        and read_from_save_dir(entry)
        and entry.get("path")
        and not str(entry["path"]).startswith(folder)
    ]


def _registry_contract() -> list[str]:
    """The registry against its schema, and a release that still ships a pack.

    `release_pack` is the only list of the ZIPs a release publishes: a
    registry where no platform carries it would cut a release with no pack
    at all, and every download link would lead to the command.
    """
    registry_path = ROOT / "platforms" / "_registry.yml"
    if not registry_path.is_file():
        return []
    with registry_path.open(encoding="utf-8") as handle:
        registry = yaml_load(handle) or {}
    label = str(registry_path.relative_to(ROOT))
    out = _errors(_validator("registry.schema.json"), registry, label)
    platforms = registry.get("platforms") or {}
    if isinstance(platforms, dict) and not any(
        isinstance(entry, dict) and entry.get("release_pack") is True
        for entry in platforms.values()
    ):
        out.append(f"{label}: no platform has release_pack: true")
    return out


def _save_directory_blocks() -> list[str]:
    """Each registry save_directory is null or a folder and a by_core flag.

    The folder names the pack folder and the save directory's default place
    beside the BIOS directory: a relative path that never climbs. ``by_system`` (a save
    folder per launched system) needs the platform file's libretro_systems,
    and ``by_core_for`` names the cores a launcher sorts by core.
    """
    registry_path = ROOT / "platforms" / "_registry.yml"
    if not registry_path.is_file():
        return []
    with registry_path.open(encoding="utf-8") as handle:
        platforms = (yaml_load(handle) or {}).get("platforms") or {}
    out: list[str] = []
    for name, entry in sorted(platforms.items()):
        if not isinstance(entry, dict) or "save_directory" not in entry:
            continue
        block = entry["save_directory"]
        if block is None:
            continue
        folder = block.get("folder") if isinstance(block, dict) else None
        sorted_cores = block.get("by_core_for", []) if isinstance(block, dict) else None
        if (
            not isinstance(block, dict)
            or not {"folder", "by_core"} <= set(block) <= {
                "folder", "by_core", "by_system", "by_core_for", "pack_folder",
            }
            or not isinstance(block.get("pack_folder", "x"), str)
            or "/" in str(block.get("pack_folder", ""))
            or not isinstance(folder, str)
            or not folder
            or "\\" in folder
            or any(part in ("", ".", "..") for part in folder.split("/"))
            or not isinstance(block.get("by_core"), bool)
            or not isinstance(block.get("by_system", False), bool)
            or not isinstance(sorted_cores, list)
            or not all(isinstance(core, str) and core for core in sorted_cores)
        ):
            out.append(
                f"platforms/_registry.yml: {name}.save_directory must be null or "
                "{folder: <relative path>, by_core: <bool>, by_system: <bool>, "
                "by_core_for: [<core>]}"
            )
            continue
        if block.get("by_system") and not _libretro_systems(name):
            out.append(
                f"platforms/_registry.yml: {name}.save_directory.by_system and "
                f"platforms/{name}.yml lists no libretro_systems"
            )
        in_pack = block.get("pack_folder") or folder
        taken = _bios_tree_below(name, in_pack)
        if taken:
            out.append(
                f"platforms/_registry.yml: {name}.save_directory puts the save "
                f"files in {in_pack}/, which the BIOS tree uses ({taken}): "
                "name another pack_folder"
            )
    return out


def _bios_tree_below(platform: str, folder: str) -> str:
    """A destination the platform declares below ``folder``, or empty."""
    from common import load_platform_config

    try:
        config = load_platform_config(platform, str(ROOT / "platforms"))
    except FileNotFoundError:
        return ""
    prefix = f"{folder}/".lower()
    return next(
        (
            str(entry["destination"])
            for system in (config.get("systems") or {}).values()
            for entry in system.get("files") or []
            if str(entry.get("destination") or "").lower().startswith(prefix)
        ),
        "",
    )


def _libretro_systems(platform: str) -> dict:
    """The platform file's core -> systems table, inheritance included."""
    from common import load_platform_config

    try:
        config = load_platform_config(platform, str(ROOT / "platforms"))
    except FileNotFoundError:
        return {}
    return config.get("libretro_systems") or {}


def _semantic_install_checks(path: Path, manifest: dict) -> list[str]:
    out: list[str] = []
    files = manifest.get("files", [])
    if manifest.get("total_files") != len(files):
        out.append(f"{path.relative_to(ROOT)}: total_files does not equal len(files)")
    if manifest.get("total_size") != sum(entry.get("size", 0) for entry in files):
        out.append(f"{path.relative_to(ROOT)}: total_size does not equal the file-size sum")
    omitted = manifest.get("omitted_files", [])
    if manifest.get("total_omitted") != len(omitted):
        out.append(
            f"{path.relative_to(ROOT)}: total_omitted does not equal "
            "len(omitted_files)"
        )
    # One dest below the BIOS folder and one below the save directory are
    # two places.
    destinations = [(entry.get("root"), entry.get("dest")) for entry in files]
    if len(destinations) != len(set(destinations)):
        out.append(f"{path.relative_to(ROOT)}: duplicate destinations")
    omitted_destinations = [(entry.get("root"), entry.get("dest")) for entry in omitted]
    if len(omitted_destinations) != len(set(omitted_destinations)):
        out.append(f"{path.relative_to(ROOT)}: duplicate omitted destinations")
    overlap = set(destinations) & set(omitted_destinations)
    if overlap:
        out.append(
            f"{path.relative_to(ROOT)}: destinations are both downloadable and omitted"
        )
    saved = [
        entry for entry in [*files, *manifest.get("case_variants", [])]
        if entry.get("root") == "save"
    ]
    layout = manifest.get("save_directory")
    if saved and not layout:
        out.append(
            f"{path.relative_to(ROOT)}: entries read below the save directory "
            "and no save_directory"
        )
    stray = sorted(
        entry["dest"] for entry in [*files, *omitted]
        if entry.get("core_folder") and entry.get("root") != "save"
    )
    if stray:
        out.append(
            f"{path.relative_to(ROOT)}: core_folder outside root: save ({stray[0]})"
        )
    return out


def _event_schema_errors() -> list[str]:
    """install-events.schema.json is EVENT_KEYS written out, and a valid schema."""
    import generate_event_schema  # noqa: PLC0415

    path = ROOT / "schemas" / generate_event_schema.OUTPUT.name
    label = path.relative_to(ROOT).as_posix()
    if not path.is_file():
        return [f"{label}: missing, run python scripts/generate_event_schema.py"]
    if path.read_text(encoding="utf-8") != generate_event_schema.render(
        generate_event_schema.build_schema()
    ):
        return [f"{label}: differs from EVENT_KEYS in install.py, run "
                "python scripts/generate_event_schema.py"]
    Draft202012Validator.check_schema(_load_json(path))
    return []


def unchecked_formats() -> list[str]:
    """Formats the schemas declare that this jsonschema install cannot check.

    date-time and uri need the format extras. Without them the ten format
    constraints of the published schemas were accepted unread.
    """
    used = {
        match
        for path in SCHEMAS.glob("*.json")
        for match in re.findall(r'"format"\s*:\s*"([^"]+)"', path.read_text(encoding="utf-8"))
    }
    return sorted(used - set(FormatChecker().checkers))


def _format_errors() -> list[str]:
    """jsonschema skips a format it has no checker for: say so, and fail."""
    return [
        f"no checker for format {name}: install \"jsonschema[format-nongpl]\""
        for name in unchecked_formats()
    ]


def _measurement_errors(root: Path | None = None) -> list[str]:
    """Every record line under measurements/, against its schema and the
    rules measurement_records.read_records applies."""
    import measurement_records as mr  # noqa: PLC0415

    root = root or ROOT
    validator = _validator("core-probe-record.schema.json")
    out: list[str] = []
    campaign = {mr.records_path(name): _validator(schema)
                for name, (_, schema) in mr.CAMPAIGN_FILES.items()}
    for path, file in sorted(mr.tree_files(root).items()):
        if not path.endswith(".jsonl"):
            continue
        for number, line in enumerate(file.read_text(encoding="utf-8").splitlines(), 1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                out.append(f"{path}:{number}: {exc}")
                continue
            out.extend(_errors(campaign.get(path, validator), record, f"{path}:{number}"))
    if not out:
        try:
            mr.read_records(root)
            for name in mr.CAMPAIGN_FILES:
                mr.read_campaign(root, name)
        except mr.MeasurementsError as exc:
            out.append(str(exc))
    return out


def _defs_validator(name: str, definition: str) -> Draft202012Validator:
    """A validator for one $defs entry of a schema file."""
    schema = _load_json(SCHEMAS / name)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(
        {**schema, "$ref": f"#/$defs/{definition}"}, format_checker=FormatChecker()
    )


def _romfolder_errors() -> list[str]:
    """Every scraped setup against its schema, and every source_ref against
    the sources the file declares: a ref naming no declared repository can
    never be read back at a pin."""
    directory = ROOT / "platforms" / "romfolders"
    if not directory.is_dir():
        return []
    validator = _validator("romfolders.schema.json")
    out: list[str] = []
    for path in sorted(directory.glob("*.yml")):
        label = str(path.relative_to(ROOT))
        with path.open(encoding="utf-8") as handle:
            data = yaml_load(handle)
        errors = _errors(validator, data, label)
        out.extend(errors)
        if errors:
            continue
        declared = set(data["sources"])
        refs = [data["roms_root"]["source_ref"]]
        refs += [data["case_ref"]] if data.get("case_ref") else []
        refs += [r["source_ref"] for key in ("skip", "hidden", "media") for r in data.get(key, [])]
        for row in data["folders"]:
            refs.append(row["source_ref"])
            refs += [b["source_ref"] for b in (row.get("board_defaults") or {}).values()]
        for ref in refs:
            for part in ref.split("; "):
                key = part.split(" ", 1)[0]
                if key not in declared:
                    out.append(f"{label}: source_ref {part!r} names undeclared source {key!r}")
    return out


# Source data of the games-on-card mode: file pattern -> schema.
_GAMES_SOURCES = (
    ("games/catalogs/*/*.json", "game-catalog.schema.json"),
    ("games/arcade/*.json", "arcade-parents.schema.json"),
    ("games/headers.yml", "game-headers.schema.json"),
    ("games/regions.yml", "game-regions.schema.json"),
    ("games/extras.yml", "game-extras.schema.json"),
)


def _games_source_errors() -> list[str]:
    out: list[str] = []
    for pattern, schema in _GAMES_SOURCES:
        paths = sorted(ROOT.glob(pattern))
        if not paths:
            continue
        validator = _validator(schema)
        for path in paths:
            with path.open(encoding="utf-8") as handle:
                data = json.load(handle) if path.suffix == ".json" else yaml_load(handle)
            out.extend(_errors(validator, data, str(path.relative_to(ROOT))))
    return out


def _arcade_pin_errors() -> list[str]:
    """games/arcade/<profile>.json read at the revision and version its
    profile pins. A bump of the profile left the game-to-BIOS map of the old
    code in place, and the installer kept serving it."""
    out: list[str] = []
    for path in sorted((ROOT / "games" / "arcade").glob("*.json")):
        doc = _load_json(path)
        profile_path = ROOT / "emulators" / f"{doc.get('profile')}.yml"
        label = str(path.relative_to(ROOT))
        if not profile_path.is_file():
            out.append(f"{label}: no profile emulators/{profile_path.name}")
            continue
        profile = _load_source(profile_path) or {}
        pinned = profile.get("source_commit")
        pins = set(pinned.values()) if isinstance(pinned, dict) else {pinned}
        commit = (doc.get("source") or {}).get("commit")
        drifted = []
        if commit and commit not in pins:
            drifted.append(f"read at {commit[:12]}, the profile pins {pinned}")
        if doc.get("core_version") != profile.get("core_version"):
            drifted.append(f"core_version {doc.get('core_version')!r}, "
                           f"the profile says {profile.get('core_version')!r}")
        if drifted:
            out.append(f"{label}: {'; '.join(drifted)} "
                       f"(python -m scripts.scraper.arcade_parent_importer --profile {doc.get('profile')})")
    return out


def _games_index_errors() -> list[str]:
    """install/games/: each document against its kind, and the index
    against the files it lists (size and sha256)."""
    import hashlib

    base = ROOT / "install" / "games"
    index_path = base / "index.json"
    if not index_path.exists():
        return []
    out: list[str] = []
    index = _load_json(index_path)
    out.extend(_errors(_defs_validator("games-index.schema.json", "index"), index,
                       str(index_path.relative_to(ROOT))))
    kinds = {
        "setups": _defs_validator("games-index.schema.json", "setup"),
        "fallback": _defs_validator("games-index.schema.json", "fallback"),
        "systems": _defs_validator("games-index.schema.json", "system"),
        "arcade": _validator("arcade-parents.schema.json"),
    }
    listed: set[Path] = set()
    for kind, validator in kinds.items():
        for entry in (index.get(kind) or {}).values():
            path = base / entry["file"]
            listed.add(path)
            label = str(path.relative_to(ROOT))
            if not path.exists():
                out.append(f"{label}: listed in index.json, absent")
                continue
            data = path.read_bytes()
            if len(data) != entry["size"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
                out.append(f"{label}: size or sha256 differs from index.json")
            out.extend(_errors(validator, json.loads(data), label))
    for path in sorted(base.rglob("*.json")):
        if path != index_path and path not in listed:
            out.append(f"{path.relative_to(ROOT)}: not listed in index.json")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__)
    parser.add_argument(
        "--source-only",
        action="store_true",
        help="validate emulator/platform YAML only",
    )
    args = parser.parse_args()

    errors: list[str] = _format_errors()
    errors.extend(
        _validate_yaml_directory(ROOT / "emulators", "emulator.schema.json")
    )
    errors.extend(
        _validate_yaml_directory(
            ROOT / "platforms", "platform.schema.json", skip_private=True
        )
    )
    errors.extend(_unknown_data_dir_refs())
    errors.extend(_repository_layout_in_profiles())
    errors.extend(_save_directory_blocks())
    errors.extend(_registry_contract())
    errors.extend(_event_schema_errors())
    errors.extend(_measurement_errors())
    errors.extend(_romfolder_errors())
    errors.extend(_games_source_errors())
    errors.extend(_arcade_pin_errors())

    if not args.source_only:
        database_path = ROOT / "database.json"
        errors.extend(
            _validate_json_files(
                [database_path],
                "database.schema.json",
                lambda _path, database: _semantic_database_checks(database),
            )
        )

        install_paths = sorted((ROOT / "install").glob("*.json"))
        errors.extend(
            _validate_json_files(
                install_paths, "install-manifest.schema.json", _semantic_install_checks
            )
        )

        target_paths = sorted((ROOT / "install" / "targets").glob("*.json"))
        errors.extend(
            _validate_json_files(target_paths, "target-manifest.schema.json")
        )

        release_path = ROOT / "release.json"
        if release_path.exists():
            errors.extend(_validate_json_files([release_path], "release.schema.json"))

        stats_path = ROOT / "website" / "public" / "stats.json"
        if stats_path.exists():
            errors.extend(_validate_json_files([stats_path], "stats.schema.json"))

        api_dir = ROOT / "website" / "public" / "api" / "v1"
        api_database = api_dir / "database.json"
        if api_database.exists():
            errors.extend(
                _validate_json_files([api_database], "database.schema.json")
            )
        api_stats = api_dir / "stats.json"
        if api_stats.exists():
            errors.extend(_validate_json_files([api_stats], "stats.schema.json"))
        envelope_paths = [
            api_dir / name
            for name in ("catalog.json", "platforms.json", "emulators.json", "gaps.json")
            if (api_dir / name).exists()
        ] + sorted((api_dir / "platforms").glob("*.json")) + sorted(
            (api_dir / "systems").glob("*.json")
        ) + sorted((api_dir / "lookup").glob("*.json"))
        errors.extend(
            _validate_json_files(
                envelope_paths,
                "site-api-envelope.schema.json",
                _semantic_envelope_checks,
            )
        )

        errors.extend(_games_index_errors())
        errors.extend(_validate_pack_manifests(ROOT / "dist"))

    if errors:
        for error in errors:
            print(f"ERROR {error}")
        print(f"{len(errors)} schema or semantic error(s)")
        return 1
    print("All RetroBIOS schemas and semantic invariants are valid.")
    return 0


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
