"""Shared utilities for retrobios scripts.

Single source of truth for platform config loading, hash computation,
and file resolution - eliminates DRY violations across scripts.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from collections import Counter

import argparse
import filecmp
import hashlib
import functools
import json
import os
import re
import signal
import sys
import zipfile
from pathlib import Path
from typing import Any, TextIO

from alternatives import derive_member_requirements

# Every build script imports this module. verify.py, slots.py, validate_pr.py
# and cross_reference.py started under 3.8 and stopped halfway on a
# str.removeprefix AttributeError, which named no version.
if sys.version_info < (3, 9):
    sys.exit(
        f"{Path(sys.argv[0]).name} needs Python 3.9 or newer, "
        f"this is {sys.version.split()[0]}"
    )


try:
    import yaml
except ImportError:
    yaml = None








def require_directory(path: str, flag: str = "--bios-dir") -> None:
    """Stop on a folder that does not exist.

    identity --strict, dedup, auto_fetch, romset_recipes and generate_pack
    read a mistyped --bios-dir as an empty collection and passed: 0
    conflicts, 0 duplicates, a pack of nothing.
    """
    if not os.path.isdir(path):
        raise SystemExit(f"ERROR: {flag} {path} is not a directory")


class InputMissing(FileNotFoundError):
    """An input a command was pointed at does not exist. run_cli prints the
    message on one line instead of a stack trace."""


class DatabaseUnreadable(InputMissing):
    """The database a command was pointed at does not exist or is not JSON."""


class SourceUnreadable(ValueError):
    """A profile or platform file that is not valid YAML. Not an InputMissing:
    the callers that skip a platform whose file is absent must not skip one
    whose file is damaged. run_cli prints the message on one line."""


def source_yaml(stream: TextIO) -> Any:
    """Parse one of our YAML sources, naming the file a syntax error is in.

    Every profile is loaded whatever the command, so one misindented key in
    an unrelated profile stopped `verify.py --emulator handy` on a 37-line
    traceback, the faulty file named only near its end.
    """
    if yaml is None:
        return yaml_load(stream)
    try:
        return yaml_load(stream)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f"{stream.name}:{mark.line + 1}" if mark else stream.name
        problem = getattr(exc, "problem", None) or str(exc).splitlines()[0]
        raise SourceUnreadable(
            f"{where}: {problem}. Check it with: "
            "python scripts/validate_schemas.py --source-only"
        ) from None


def load_database(db_path: str) -> dict:
    """Load database.json and return parsed dict.

    A missing or damaged file raises DatabaseUnreadable, which run_cli turns
    into one line saying how to build it: `--db nosuch.json` ended at the
    bottom of a stack trace.
    """
    try:
        with open(db_path) as f:
            return json.load(f)
    except FileNotFoundError:
        # A mistyped --db beside the real database was told to rescan the
        # whole collection into a second file under the typo.
        import difflib  # noqa: PLC0415

        typed = Path(db_path)
        close = difflib.get_close_matches(
            typed.name, [p.name for p in typed.parent.glob("*.json")], n=1, cutoff=0.8
        )
        if close:
            raise DatabaseUnreadable(
                f"{db_path} not found. Close match: {typed.with_name(close[0])}"
            ) from None
        raise DatabaseUnreadable(
            f"{db_path} not found. Build it with: python scripts/generate_db.py "
            f"--force --bios-dir bios --output {db_path}"
        ) from None
    except json.JSONDecodeError as exc:
        raise DatabaseUnreadable(
            f"{db_path} is not valid JSON ({exc}). Rebuild it with: "
            f"python scripts/generate_db.py --force --bios-dir bios --output {db_path}"
        ) from None



# One slot: the dict it was built from, its size then, and the folded view.
# Keyed by id() alone, a database freed and replaced by another at the same
# address got the old index back, and the case-insensitive step answered from
# a collection that no longer existed.
_casefold_index_cache: list[tuple[dict, int, dict[str, list[str]]]] = []


def _casefold_name_index(by_name: dict) -> dict[str, list[str]]:
    """Build (and cache) a casefolded view of the by_name index."""
    if _casefold_index_cache:
        source, size, folded = _casefold_index_cache[0]
        if source is by_name and size == len(by_name):
            return folded
    folded: dict[str, list[str]] = {}
    for name, sha1s in by_name.items():
        folded.setdefault(name.casefold(), []).extend(sha1s)
    _casefold_index_cache[:] = [(by_name, len(by_name), folded)]
    return folded


# bios/Other/<emulator> and bios/Arcade/<emulator or board> file a copy by
# who loads it, not by machine.
BUCKET_FOLDERS = frozenset({"Other", "Arcade"})


def names_manufacturer(sys_id: str, manufacturer: str) -> bool:
    """Whether a system id names a maker folder: nec-pc-88 names NEC."""
    slug = manufacturer.lower().replace(" ", "-")
    return sys_id == slug or sys_id.startswith(f"{slug}-")


def _maker_folder(path: str, bios_dir: str) -> str | None:
    """The bios/<maker>/ folder a collection path is filed under."""
    prefix = f"{bios_dir.rstrip('/')}/"
    if not path.startswith(prefix):
        return None
    parts = path[len(prefix):].split("/")
    return parts[0] if len(parts) >= 2 else None


# One slot, keyed like the casefold view: the files dict, its size, the folders.
_maker_folders_cache: list[tuple[dict, int, frozenset[str]]] = []


def _maker_folders(db: dict) -> frozenset[str]:
    """Every maker folder the collection files a copy under."""
    files_db = db.get("files", {})
    if _maker_folders_cache:
        source, size, folders = _maker_folders_cache[0]
        if source is files_db and size == len(files_db):
            return folders
    bios_dir = str(db.get("bios_dir") or "bios")
    folders = frozenset(
        folder
        for entry in files_db.values()
        if (folder := _maker_folder(str(entry.get("path", "")), bios_dir))
        and folder not in BUCKET_FOLDERS
    )
    _maker_folders_cache[:] = [(files_db, len(files_db), folders)]
    return folders


def system_makers(file_entry: dict, db: dict) -> frozenset[str]:
    """The maker folders a platform entry's system names.

    Only a platform's own entry is asked: one that names an owning emulator
    is placed by that emulator's tree. Empty when the system names no maker
    (pc88, arcade), so nothing is narrowed there.
    """
    sys_id = str(file_entry.get("platform_system") or "")
    if not sys_id or _owner_tokens(file_entry):
        return frozenset()
    return frozenset(
        folder for folder in _maker_folders(db) if names_manufacturer(sys_id, folder)
    )


def other_maker(path: str, makers: frozenset[str], db: dict) -> bool:
    """Whether a path is filed under a maker the entry's system does not name."""
    if not makers:
        return False
    folder = _maker_folder(path, str(db.get("bios_dir") or "bios"))
    return folder is not None and folder not in BUCKET_FOLDERS and folder not in makers


def name_match_size_ok(file_entry: dict, candidate_size: int | None) -> bool:
    """Whether a candidate found by name may be the file the entry describes.

    Generic filenames collide across systems: rom1.bin is a Sony PlayStation 2
    firmware and a Roland SC-55mk2 program ROM. A name carries no evidence on
    its own, so a size the emulator verifies settles it. A size declared
    without ``validation: [size]`` is informative and rejects nothing.
    """
    validation = file_entry.get("validation")
    if isinstance(validation, dict):
        validation = validation.get("core", [])
    if "size" not in (validation or []) or candidate_size is None:
        return True
    return size_fits(file_entry, candidate_size)


def adler32_of(path: str, byteswap: bool = False) -> str:
    """The Adler-32 of a file, over its 16-bit words swapped when asked.

    Dolphin swaps every 16-bit word of its DSP ROMs before hashing them
    (Common::swap16 in DSPLLE.cpp:LoadDSPRom).
    """
    import struct  # noqa: PLC0415
    import zlib  # noqa: PLC0415

    with open(path, "rb") as f:
        data = f.read()
    if byteswap:
        if len(data) % 2:
            data += b"\x00"
        count = len(data) // 2
        data = struct.pack(f">{count}H", *struct.unpack(f"<{count}H", data))
    return format(zlib.adler32(data) & 0xFFFFFFFF, "08x")


def _adler32_value(value: object) -> str:
    return str(value).lower().removeprefix("0x")


def _held_adler32(name: str, db: dict, byteswap: bool) -> set[str]:
    """The Adler-32 of every copy of a name the collection holds."""
    files_db = db.get("files", {})
    held: set[str] = set()
    for sha1 in db.get("indexes", {}).get("by_name", {}).get(name, []):
        path = files_db.get(sha1, {}).get("path", "")
        try:
            held.add(adler32_of(path, byteswap))
        except OSError:
            continue
    return held


def held_adler32_pair(file_entry: dict, db: dict) -> str | None:
    """The entry's own value in the first pair its code accepts that is held.

    Dolphin hashes dsp_rom.bin and dsp_coef.bin together and warns on any
    combination outside its table: two files each accepted alone can still
    be a pair it refuses. ``adler32_pairs`` lists the accepted pairs, the
    entry's own value first, in the code's table order. Both members walk
    the same pairs over the same collection, so they settle on one pair.
    None when the entry declares no pair or none is held whole.
    """
    pairs = file_entry.get("adler32_pairs")
    partner = file_entry.get("adler32_pairs_with")
    if not pairs or not partner:
        return None
    byteswap = bool(file_entry.get("adler32_byteswap"))
    own = _held_adler32(file_entry.get("name", ""), db, byteswap)
    other = _held_adler32(partner, db, byteswap)
    for mine, theirs in pairs:
        if _adler32_value(mine) in own and _adler32_value(theirs) in other:
            return _adler32_value(mine)
    return None


def adler32_fits(file_entry: dict, path: str, db: dict | None = None) -> bool:
    """Whether a candidate carries an Adler-32 the entry's code accepts.

    Dolphin hashes its DSP ROMs and warns on every pair it does not take
    as current: the v0.3.1 free dsp_rom.bin is answered by its path, and
    shipped beside the official dsp_coef.bin it is a pair Dolphin rejects.
    A value declared without ``validation: [adler32]`` rejects nothing.
    With the collection at hand, a candidate outside the held pair the
    code accepts (``held_adler32_pair``) is refused too.
    """
    validation = file_entry.get("validation")
    if isinstance(validation, dict):
        validation = validation.get("core", [])
    declared = file_entry.get("known_hash_adler32")
    if "adler32" not in (validation or []) or not declared:
        return True
    values = declared if isinstance(declared, list) else [declared]
    accepted = {_adler32_value(v) for v in values}
    try:
        actual = adler32_of(path, bool(file_entry.get("adler32_byteswap")))
    except OSError:
        return False
    if actual not in accepted:
        return False
    chosen = held_adler32_pair(file_entry, db) if db is not None else None
    return chosen is None or actual == chosen


def size_fits(file_entry: dict, candidate_size: int) -> bool:
    """Whether a size is one the entry declares.

    ``size`` is an exact size or the list of sizes the code accepts, and it
    outranks a ``min_size``/``max_size`` range. Nothing declared fits all.
    """
    declared = file_entry.get("size")
    if declared is not None:
        allowed = declared if isinstance(declared, list) else [declared]
        return candidate_size in allowed
    low = file_entry.get("min_size")
    high = file_entry.get("max_size")
    if low is not None and candidate_size < low:
        return False
    return not (high is not None and candidate_size > high)




_shared_yml_cache: dict[str, dict] = {}
_platform_config_cache: dict[tuple[str, str], dict] = {}


def _inherited_yaml(platform_name: str, platforms_dir: str) -> tuple[dict, list[str]]:
    """The platform's YAML merged over its parents', and the chain of names.

    Built from fresh copies: merging over the parent's cached config shared
    its systems, so a child's overrides rewrote the parent for the rest of
    the run.
    """
    if yaml is None:
        raise ImportError("PyYAML required: pip install pyyaml")

    config_file = os.path.join(platforms_dir, f"{platform_name}.yml")
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Platform config not found: {config_file}")

    with open(config_file) as f:
        config = source_yaml(f) or {}
    if "inherits" not in config:
        return config, [platform_name]

    merged, chain = _inherited_yaml(config["inherits"], platforms_dir)
    # A version names one platform's release, never its parent's: Lakka
    # read as RetroArch v1.22.2 in its manifest, pack name and site page.
    # dat_version stays, it is the version of the inherited list itself.
    merged.pop("version", None)
    merged.update(
        {k: v for k, v in config.items() if k not in ("inherits", "overrides")}
    )
    if "overrides" in config and "systems" in config["overrides"]:
        merged.setdefault("systems", {})
        for sys_id, override in config["overrides"]["systems"].items():
            if sys_id in merged["systems"]:
                merged["systems"][sys_id] = {
                    **merged["systems"][sys_id],
                    **override,
                }
            else:
                merged["systems"][sys_id] = override
    return merged, [platform_name, *chain]


def load_platform_config(platform_name: str, platforms_dir: str = "platforms") -> dict:
    """Load a platform config with inheritance and shared group resolution.

    This is the SINGLE implementation used by generate_pack, generate_readme,
    verify, and auto_fetch. No other copy should exist.
    """
    cache_key = (platform_name, os.path.realpath(platforms_dir))
    if cache_key in _platform_config_cache:
        return _platform_config_cache[cache_key]

    config, chain = _inherited_yaml(platform_name, platforms_dir)

    shared_path = os.path.join(platforms_dir, "_shared.yml")
    # Merge metadata from _registry.yml. The registry is our curated source,
    # while the scraped YAML may be incomplete (missing cores, metadata fields).
    # Registry fields supplement (not replace) the scraped config.
    registry_path = os.path.join(platforms_dir, "_registry.yml")
    if os.path.exists(registry_path):
        reg_real = os.path.realpath(registry_path)
        if reg_real not in _shared_yml_cache:
            with open(registry_path) as f:
                _shared_yml_cache[reg_real] = source_yaml(f) or {}
        reg = _shared_yml_cache[reg_real]
        # The platform's own entry first, then its parents' for what it does
        # not say: RetroPie's status, scraper and install are its own, its
        # verification mode is RetroArch's.
        for depth, name in enumerate(chain):
            reg_entry = reg.get("platforms", {}).get(name, {})

            # Merge cores (union for lists, override for all_libretro), a
            # parent's only where the platform names none.
            reg_cores = reg_entry.get("cores")
            if reg_cores is not None and (depth == 0 or "cores" not in config):
                cfg_cores = config.get("cores")
                if reg_cores == "all_libretro":
                    config["cores"] = "all_libretro"
                elif isinstance(reg_cores, list) and isinstance(cfg_cores, list):
                    merged_set = {str(c) for c in cfg_cores} | {str(c) for c in reg_cores}
                    config["cores"] = sorted(merged_set)
                elif isinstance(reg_cores, list) and cfg_cores is None:
                    config["cores"] = reg_cores

            # Merge all registry fields absent from config (except cores,
            # handled above with union logic). No hardcoded list: any field
            # added to the registry is automatically available in the config.
            for key, val in reg_entry.items():
                if key != "cores" and key not in config:
                    config[key] = val

    # A shared group's file joins a system unless the platform already has
    # it there. Case only makes two names one where the filesystem folds it:
    # Lakka and RetroPie run on Linux, and np2kai opens 2608_bd.wav beside
    # System.dat's 2608_BD.WAV.
    def fold(destination: str) -> str:
        return destination.lower() if config.get("case_insensitive_fs") else destination

    if os.path.exists(shared_path):
        shared_real = os.path.realpath(shared_path)
        if shared_real not in _shared_yml_cache:
            with open(shared_path) as f:
                _shared_yml_cache[shared_real] = source_yaml(f) or {}
        shared = _shared_yml_cache[shared_real]
        shared_groups = shared.get("shared_groups", {})
        for system in config.get("systems", {}).values():
            for group_name in system.get("includes", []):
                if group_name in shared_groups:
                    existing = {
                        (f.get("name"), f.get("destination", f.get("name")))
                        for f in system.get("files", [])
                    }
                    existing_lower = {
                        fold(f.get("destination", f.get("name", "")))
                        for f in system.get("files", [])
                    }
                    for gf in shared_groups[group_name]:
                        key = (gf.get("name"), gf.get("destination", gf.get("name")))
                        dest_lower = fold(gf.get("destination", gf.get("name", "")))
                        if key not in existing and dest_lower not in existing_lower:
                            # Marked as ours: the platform's own file does not
                            # carry it, and an export must not count it kept.
                            system.setdefault("files", []).append(
                                {**gf, "shared_group": group_name}
                            )
                            existing.add(key)

    # Recalbox hashes a .zip by its members, so a plain md5 never answers one
    # of its archive declarations: the resolver reads the mark per entry.
    if config.get("zip_digest") == "composite":
        config["systems"] = {
            sys_id: {
                **system,
                "files": [
                    {**f, "zip_digest": "composite"}
                    if str(f.get("name", "")).lower().endswith(".zip")
                    else f
                    for f in system.get("files", [])
                ],
            }
            for sys_id, system in config.get("systems", {}).items()
        }

    # Each entry carries the system that declares it: a hashless name match is
    # narrowed to the maker folder that system names (resolve_local_file).
    # A system that names its own cores (EmuELEC, AmberELEC, KNULLI) also
    # passes them on, so another emulator's tree is foreign to its entries.
    # Fresh dicts, since a YAML anchor can share one entry between systems.
    config["systems"] = {
        sys_id: {
            **system,
            "files": [
                {
                    **f,
                    "platform_system": sys_id,
                    **(
                        {"platform_cores": list(system["cores"])}
                        if system.get("cores")
                        else {}
                    ),
                }
                for f in system["files"]
            ],
        }
        if isinstance(system, dict) and system.get("files")
        else system
        for sys_id, system in config.get("systems", {}).items()
    }

    # The registry key, which per-platform profile fields (installed_on,
    # not_bundled_on) name: the display name differs (MiSTer FPGA).
    config["_key"] = platform_name
    # Where the platform's games live, as its rom folders file records it
    # from the OS's own source (platforms/romfolders/<key>.yml, roms_root).
    romfolders = os.path.join(platforms_dir, "romfolders", f"{platform_name}.yml")
    if os.path.exists(romfolders):
        with open(romfolders) as f:
            roms_root = (source_yaml(f) or {}).get("roms_root")
        if isinstance(roms_root, dict):
            config["_roms_root"] = roms_root
    _platform_config_cache[cache_key] = config
    return config


def native_layer(config: dict | None) -> dict | None:
    """The platform config without what we add to it.

    A shared group's files join the config for the pack, but the platform's
    file does not carry them: counted kept, they were written into
    libretro's System.dat (N88EXT0-3.ROM) as if libretro declared them. What
    a core needs from a group reaches the export through the truth, as an
    addition the format's gates apply to. A scraper's mirror of an entry
    under another system (RomM's tg16 firmware under turbografx-cd), and a
    file our scraper adds from the cores' source (Dolphin's DSP ROMs in
    RetroArch's config), are not in the platform's file either.
    """
    if config is None:
        return None
    systems = {
        sys_id: {
            **system,
            "files": [
                f for f in system.get("files", [])
                if not ({"shared_group", "mirror_of", "curated"} & f.keys())
            ],
        }
        for sys_id, system in config.get("systems", {}).items()
    }
    return {**config, "systems": systems}


def load_data_dir_registry(platforms_dir: str = "platforms") -> dict:
    """Load the data directory registry from _data_dirs.yml."""
    registry_path = os.path.join(platforms_dir, "_data_dirs.yml")
    if not os.path.exists(registry_path):
        return {}
    with open(registry_path) as f:
        data = source_yaml(f) or {}
    return data.get("data_directories", {})


def load_platform_registry(platforms_dir: str = "platforms") -> dict:
    """Return the `platforms:` mapping from _registry.yml, empty if absent."""
    registry_path = os.path.join(platforms_dir, "_registry.yml")
    if not os.path.exists(registry_path):
        return {}
    with open(registry_path) as f:
        return (source_yaml(f) or {}).get("platforms", {})


def list_registered_platforms(platforms_dir: str = "platforms") -> list[str]:
    """List platforms registered in _registry.yml.

    Only registered platforms generate packs and appear in CI.
    Unregistered YAMLs (e.g., emulatorjs.yml) are base configs for inheritance.

    A missing registry, or a registered platform whose file is gone, raises:
    left out quietly, verify --all --strict and every --all build passed
    having checked none of it, and install.py kept serving its last manifest.
    """
    registry_path = os.path.join(platforms_dir, "_registry.yml")
    if not os.path.exists(registry_path):
        raise InputMissing(f"no platform registry at {registry_path}")
    with open(registry_path) as f:
        registry = source_yaml(f) or {}
    platforms = []
    for name, meta in sorted(registry.get("platforms", {}).items()):
        config_path = os.path.join(platforms_dir, meta.get("config", f"{name}.yml"))
        if not os.path.exists(config_path):
            raise FileNotFoundError(
                f"{name} is registered in {registry_path} but {config_path} does not exist"
            )
        platforms.append(name)
    return platforms


def list_release_pack_platforms(platforms_dir: str = "platforms") -> list[str]:
    """Registered platforms a release publishes a ZIP pack for.

    `release_pack: true` in _registry.yml is the whole list: the build of
    `--all`, the pack checks, the release record and every download table
    read it. The other platforms keep their install manifest and are served
    by the installer.
    """
    registry = load_platform_registry(platforms_dir)
    return [
        name
        for name in list_registered_platforms(platforms_dir)
        if registry.get(name, {}).get("release_pack") is True
    ]


# A list this short is printed whole rather than pointed at.
SHORT_LIST = 12


@functools.lru_cache(maxsize=1)
def _gh_cli_token() -> str:
    """What `gh auth token` prints, or "" when gh is absent or logged out."""
    import logging  # noqa: PLC0415
    import subprocess  # noqa: PLC0415

    log = logging.getLogger(__name__)
    try:
        proc = subprocess.run(
            ["gh", "auth", "token"], capture_output=True, text=True,
            timeout=10, check=False,
        )
    except FileNotFoundError:
        log.debug("gh is not installed, GitHub API calls go anonymous")
        return ""
    except (subprocess.TimeoutExpired, OSError) as exc:
        log.warning("gh auth token did not answer: %s", exc)
        return ""
    if proc.returncode != 0:
        log.debug("gh auth token: %s", (proc.stderr or "").strip())
        return ""
    return (proc.stdout or "").strip()


def github_token() -> str:
    """The token for api.github.com: GITHUB_TOKEN, GH_TOKEN, then gh's own.

    A maintainer logged in to gh had to export GITHUB_TOKEN by hand before
    profile_sync, the scrapers or an online pipeline, which refused the run
    or burnt the anonymous quota of 60 calls an hour. The token gh returns
    is put in the environment, so the subprocesses a run starts and the
    readers of os.environ get it too. RETROBIOS_OFFLINE runs make no API
    call and never ask gh.
    """
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
    if token or os.environ.get("RETROBIOS_OFFLINE"):
        return token
    token = _gh_cli_token()
    if token:
        os.environ["GITHUB_TOKEN"] = token
    return token


def suggest_names(
    typed: list[str],
    available: list[str],
    listing_flag: str,
    listed: int | None = None,
) -> str:
    """The closest known names to what was typed, and how to see them all.

    The hints showed the first ten or twenty names of the alphabet behind a
    "..." whatever was typed: sony-playstaton listed 3do to apple-iie.
    `listed` is how many entries the listing shows when `available` also
    holds aliases of them.
    """
    import difflib  # noqa: PLC0415

    total = len(available) if listed is None else listed
    close = sorted({m for name in typed
                    for m in difflib.get_close_matches(name, available, n=3, cutoff=0.6)})
    if close:
        return f"Close matches: {', '.join(close)}. {listing_flag} lists all {total}."
    if len(available) <= SHORT_LIST:
        return f"Known: {', '.join(available)}."
    return f"{listing_flag} lists all {total}."


def work_from_repo_root(
    args: argparse.Namespace, parser: argparse.ArgumentParser, path_flags: list[str]
) -> None:
    """Run from the repository root, whichever directory the command started in.

    database.json records every file from the root and the data registry
    names its caches the same way, so a run from scripts/ ended on a
    FileNotFoundError traceback. A path the caller typed is read from where
    they typed it, a default from the root.
    """
    root = Path(__file__).resolve().parent.parent
    if Path.cwd().resolve() == root:
        return
    for flag in path_flags:
        value = getattr(args, flag, None)
        if value and value != parser.get_default(flag):
            # A Path stays a Path for the code that joins onto it.
            setattr(args, flag, type(value)(os.path.abspath(value)))
    os.chdir(root)
    if getattr(args, "platform", None):
        # Read before the move, the registry was not there to map
        # "RetroArch" to its slug.
        args.platform = platform_arg(args.platform)


def platform_arg(value: str) -> str:
    """--platform as typed, mapped to the registry's slug when it names one.

    The site and the pack names say RetroArch and MiSTer FPGA, but verify and
    generate_pack refused both while install.py took them. Letters and
    digits decide, as for pack names. Anything else reaches require_platform
    unchanged and gets its suggestion.
    """
    key = re.sub(r"[^a-z0-9]", "", value.lower())
    if yaml is None or not os.path.isdir("platforms"):
        return value
    known = list_registered_platforms("platforms")
    for name in known:
        if re.sub(r"[^a-z0-9]", "", name.lower()) == key:
            return name
    return value


def require_platform(name: str, platforms_dir: str = "platforms") -> None:
    """Exit with a usable message when no platform answers to a name.

    A typo used to end in a traceback (verify, cross_reference) or in "no
    pack for batocra" after the whole build ran (generate_pack).
    """
    if "," in name:
        # generate_pack split the list to validate it, then used the whole
        # string as one name and ended in a traceback.
        raise SystemExit(
            f"ERROR: --platform takes one platform, not '{name}'. "
            "Run once per platform, or use --all."
        )
    if os.path.exists(os.path.join(platforms_dir, f"{name}.yml")):
        return
    import difflib  # noqa: PLC0415

    known = list_registered_platforms(platforms_dir)
    close = difflib.get_close_matches(name, known, n=1)
    hint = f" Close match: '{close[0]}'." if close else ""
    raise SystemExit(
        f"ERROR: unknown platform '{name}'.{hint}\nKnown platforms: {', '.join(known)}"
    )


def _target_overrides(platform_name: str, targets_dir: str) -> dict:
    overrides_file = os.path.join(targets_dir, "_overrides.yml")
    if not os.path.exists(overrides_file):
        return {}
    with open(overrides_file) as f:
        all_overrides = source_yaml(f) or {}
    return all_overrides.get(platform_name, {}).get("targets", {})


def _target_alias_index(targets: dict, overrides: dict) -> dict[str, str]:
    """Every name a target answers to, mapped to the name its file uses."""
    alias_index: dict[str, str] = {}
    for tname in targets:
        alias_index[tname] = tname
        for alias in overrides.get(tname, {}).get("aliases", []):
            alias_index[alias] = tname
    return alias_index


def platform_files_target(platform: str, target: str, platforms_dir: str = "platforms") -> bool:
    """Whether the platform's targets file knows this target, by any alias."""
    targets_dir = os.path.join(platforms_dir, "targets")
    target_file = os.path.join(targets_dir, f"{platform}.yml")
    if not os.path.exists(target_file):
        return False
    with open(target_file) as f:
        targets = (source_yaml(f) or {}).get("targets", {})
    return target in _target_alias_index(targets, _target_overrides(platform, targets_dir))


def canonical_target_name(
    platforms: list[str], target: str, platforms_dir: str = "platforms"
) -> str:
    """The name a target is filed under, whichever alias was typed.

    `switch`, `nx` and `nintendo-switch` named three packs of one target, and
    --verify-packs looked for a name no build had written. The typed name is
    kept when no platform knows it or when platforms file it differently.
    """
    targets_dir = os.path.join(platforms_dir, "targets")
    found: set[str] = set()
    for platform_name in platforms:
        target_file = os.path.join(targets_dir, f"{platform_name}.yml")
        if not os.path.exists(target_file):
            continue
        with open(target_file) as f:
            targets = (source_yaml(f) or {}).get("targets", {})
        canonical = _target_alias_index(
            targets, _target_overrides(platform_name, targets_dir)
        ).get(target)
        if canonical:
            found.add(canonical)
    return found.pop() if len(found) == 1 else target


def truth_target_dir(
    output_dir: str, platforms: list[str], target: str, platforms_dir: str = "platforms"
) -> str:
    """Where a target-narrowed truth model is written and read.

    Slugged from the name the target is filed under: `nx`, `switch` and
    `nintendo-switch` wrote three copies of one model, and a run under one
    alias left the others stale beside it. Called per platform, since two
    platforms can file one name differently (Lakka builds an image named
    switch). generate_truth writes here and diff_truth reads here.
    """
    named = canonical_target_name(platforms, target, platforms_dir)
    slug = re.sub(r"[^a-z0-9]+", "-", named.strip().lower()).strip("-")
    return os.path.join(output_dir, slug or "target")


def load_target_config(
    platform_name: str,
    target: str,
    platforms_dir: str = "platforms",
) -> set[str] | None:
    """Load target config and return the set of core names for the given target.

    Resolves aliases from _overrides.yml, applies add_cores/remove_cores.
    A target whose cores are null runs every core the platform declares and
    returns None, which filters nothing: the platforms with a single target
    (RetroBat on Windows, RetroDECK, RomM in the browser) kept a hand list
    that dropped 98 RetroBat cores and 300 RetroDECK ones.
    Raises ValueError if target is unknown (with list of available targets).
    Raises FileNotFoundError if no target file exists for the platform.
    """
    targets_dir = os.path.join(platforms_dir, "targets")
    target_file = os.path.join(targets_dir, f"{platform_name}.yml")
    if not os.path.exists(target_file):
        # The expected state for a platform that ships one build, said as
        # such: the file path read like a file missing from the repository.
        with_targets = sorted(
            Path(f).stem for f in os.listdir(targets_dir)
            if f.endswith(".yml") and not f.startswith("_")
        )
        raise FileNotFoundError(
            f"{platform_name} has no hardware targets: drop --target "
            f"(platforms with targets: {', '.join(with_targets)})"
        )
    with open(target_file) as f:
        data = source_yaml(f) or {}

    targets = data.get("targets", {})
    overrides = _target_overrides(platform_name, targets_dir)
    alias_index = _target_alias_index(targets, overrides)

    canonical = alias_index.get(target)
    if canonical is None:
        # A typo got the 30 targets and 18 aliases in two lines to read
        # through, where a platform or emulator name gets the closest ones.
        raise ValueError(
            f"Unknown target '{target}' for platform '{platform_name}'.\n"
            # Named as a full command: cross_reference.py and slots.py take
            # --target but have no --list-targets of their own.
            + suggest_names(
                [target], sorted(alias_index),
                f"python scripts/verify.py --platform {platform_name} --list-targets", len(targets),
            )
        )

    return _target_core_set(targets[canonical] or {}, overrides, canonical, platforms_dir)


def _target_core_set(
    entry: dict, overrides: dict, target: str, platforms_dir: str
) -> set[str] | None:
    """A target's cores: what the board builds, overrides applied, and the
    buildbot cores its RetroArch core downloader installs (`downloads`, a
    RetroArch targets entry), which a Batocera x86_64 or armv7 board can
    fetch from its menu."""
    declared = entry.get("cores")
    if declared is None:
        return None
    cores = apply_target_overrides({str(c) for c in declared}, overrides, target)
    downloads = entry.get("downloads")
    if downloads:
        cores |= load_target_config("retroarch", str(downloads), platforms_dir) or set()
    return cores


def apply_target_overrides(
    cores: set[str], overrides: dict, target: str
) -> set[str]:
    """Cores of one target once the platform's overrides are applied.

    ``_default`` applies to every target of the platform, then the target's
    own entry: a name the scraper reads as a core on every board (a machine
    variant, a launcher) is written once instead of once per board.
    """
    result = set(cores)
    for scope in ("_default", target):
        entry = overrides.get(scope) or {}
        result |= {str(c) for c in entry.get("add_cores") or []}
        result -= {str(c) for c in entry.get("remove_cores") or []}
    return result


def list_available_targets(
    platform_name: str,
    platforms_dir: str = "platforms",
) -> list[dict]:
    """List available targets for a platform with their aliases.

    Returns list of dicts with keys: name, architecture, core_count, aliases.
    Returns empty list if no target file exists.
    """
    targets_dir = os.path.join(platforms_dir, "targets")
    target_file = os.path.join(targets_dir, f"{platform_name}.yml")
    if not os.path.exists(target_file):
        return []
    with open(target_file) as f:
        data = source_yaml(f) or {}

    # The count --target filters on: overrides applied, as load_target_config
    # applies them. The scraped list counted Batocera's machine variants and
    # launchers, 198 cores shown for 187 used.
    overrides = _target_overrides(platform_name, targets_dir)

    result = []
    for tname, tdata in sorted(data.get("targets", {}).items()):
        aliases = (overrides.get(tname) or {}).get("aliases", [])
        # None: the target runs every core the platform declares.
        found = _target_core_set(tdata or {}, overrides, tname, platforms_dir)
        count = None if found is None else len(found)
        result.append(
            {
                "name": tname,
                "architecture": (tdata or {}).get("architecture", ""),
                "core_count": count,
                "aliases": aliases,
            }
        )
    return result


def target_listing_line(row: dict) -> str:
    """One --list-targets row, as verify and generate_pack print it."""
    aliases = f" (aliases: {', '.join(row['aliases'])})" if row["aliases"] else ""
    count = "all" if row["core_count"] is None else str(row["core_count"])
    return f"  {row['name']:30s} {row['architecture']:10s} {count:>4s} cores{aliases}"


HASH_EXACT_RESOLUTION_STATUSES = frozenset(
    {
        "sha1_exact",
        "sha256_exact",
        "crc32_exact",
        "md5_exact",
        "md5_composite_exact",
        "zip_exact",
        "data_dir_hash_exact",
    }
)


def resolution_is_hash_exact(status: str) -> bool:
    """Whether *status* proves content identity with a declared hash."""
    return status in HASH_EXACT_RESOLUTION_STATUSES


def declared_hash_verdict(
    candidate: str,
    *,
    has_strong_hash: bool,
    sha1_candidates: set,
    sha256_candidates: set,
    md5_list: list,
    crc_candidates: set,
    zipped_file: str | None,
    declared_size: int | list[int] | None,
    file_entry: dict | None = None,
    db: dict | None = None,
) -> str:
    """Judge a candidate found by name against everything the entry declares.

    A file reached through a directory walk was matched on its filename,
    which is the weakest evidence there is. Whatever the entry declares
    about its content is checked here before the walk may return it,
    including the size and Adler-32 the name steps over bios/ apply.
    """
    if not has_strong_hash:
        if file_entry is not None and not (
            name_match_size_ok(file_entry, os.path.getsize(candidate))
            and adler32_fits(file_entry, candidate, db)
        ):
            return "hash_mismatch"
        return "data_dir"
    algorithms: set[str] = set()
    if sha1_candidates:
        algorithms.add("sha1")
    if sha256_candidates:
        algorithms.add("sha256")
    if md5_list and not zipped_file:
        algorithms.add("md5")
    if crc_candidates:
        algorithms.add("crc32")
    actual = compute_hashes(candidate, frozenset(algorithms)) if algorithms else {}
    if sha1_candidates and actual.get("sha1", "").lower() not in sha1_candidates:
        return "hash_mismatch"
    if sha256_candidates and actual.get("sha256", "").lower() not in sha256_candidates:
        return "hash_mismatch"
    if md5_list and not zipped_file and not any(
        actual.get("md5", "").lower().startswith(expected) for expected in md5_list
    ):
        return "hash_mismatch"
    if crc_candidates and actual.get("crc32", "").lower() not in crc_candidates:
        return "hash_mismatch"
    if crc_candidates and declared_size is not None:
        allowed_sizes = declared_size if isinstance(declared_size, list) else [declared_size]
        if os.path.getsize(candidate) not in allowed_sizes:
            return "hash_mismatch"
    if zipped_file and md5_list and not any(
        check_inside_zip(candidate, zipped_file, expected) == "ok"
        for expected in md5_list
    ):
        return "hash_mismatch"
    return "data_dir_hash_exact"


def _resolve_in_data_dirs(
    names_to_try: list[str],
    data_dir_registry: dict,
    verdict: Callable[[str], str],
) -> tuple[tuple[str, str] | None, str | None]:
    """Look for one of these names in the cached data directories.

    Returns the first candidate whose content satisfies the entry, and
    separately the first that answered to the name but contradicted it: a
    name match alone never decides, so the caller reports the contradiction
    rather than shipping the file.
    """
    mismatch: str | None = None
    for _key, dd_entry in data_dir_registry.items():
        cache_dir = dd_entry.get("local_cache", "")
        if not cache_dir or not os.path.isdir(cache_dir):
            continue
        for try_name in names_to_try:
            candidate = os.path.join(cache_dir, try_name)
            if os.path.isfile(candidate):
                status = verdict(candidate)
                if status != "hash_mismatch":
                    return (candidate, status), mismatch
                mismatch = mismatch or candidate
        # The declared path may not be where the cache put it, so the tree
        # is searched for the bare filename, case-insensitively, in the order
        # a walk meets it.
        basename_targets = {
            (n.rsplit("/", 1)[-1] if "/" in n else n).casefold()
            for n in names_to_try
        }
        index = _data_dir_basenames(cache_dir)
        found = sorted(
            (order, path)
            for target in basename_targets
            for order, path in index.get(target, ())
        )
        for _order, candidate in found:
            status = verdict(candidate)
            if status != "hash_mismatch":
                return (candidate, status), mismatch
            mismatch = mismatch or candidate
    return None, mismatch


def _data_dir_tail(
    dest_hint: str, data_dir_registry: dict, file_entry: dict, db: dict
) -> str | None:
    """The cached data-directory file at the destination's own tail.

    The full destination first, then without its leading segment, never
    down to the bare name. A shortened tail two caches hold with different
    bytes proves nothing. The size and Adler-32 the code checks still bound
    the file, as on every name or path step without a hash.
    """
    parts = dest_hint.split("/")
    for start in range(min(2, len(parts) - 1)):
        tail = "/".join(parts[start:])
        hits = [
            os.path.join(cache_dir, tail)
            for cache_dir in (
                dd_entry.get("local_cache", "") for dd_entry in data_dir_registry.values()
            )
            if cache_dir and os.path.isfile(os.path.join(cache_dir, tail))
        ]
        if start and any(
            not filecmp.cmp(hits[0], other, shallow=False) for other in hits[1:]
        ):
            continue
        for candidate in hits:
            if name_match_size_ok(
                file_entry, os.path.getsize(candidate)
            ) and adler32_fits(file_entry, candidate, db):
                return candidate
    return None


# Basename index per data-directory cache. Walking the whole tree again for
# every unresolved name made resolution O(names x tree) on each pack build.
_data_dir_index: dict[str, dict[str, list[tuple[int, str]]]] = {}


def _data_dir_basenames(cache_dir: str) -> dict[str, list[tuple[int, str]]]:
    """Casefolded basename -> (walk order, path) of every file in a cache.

    Keyed by the tree's identity as well as its path: a refresh swaps in a
    new directory under the same name, and an index of the old one named
    files that were gone.
    """
    try:
        stat = os.stat(cache_dir)
    except OSError:
        return {}
    key = f"{os.path.realpath(cache_dir)}:{stat.st_dev}:{stat.st_ino}"
    if key not in _data_dir_index:
        index: dict[str, list[tuple[int, str]]] = {}
        order = 0
        for root, _dirs, fnames in os.walk(cache_dir):
            for fname in fnames:
                index.setdefault(fname.casefold(), []).append((order, os.path.join(root, fname)))
                order += 1
        _data_dir_index[key] = index
    return _data_dir_index[key]


def forget_data_dir_index() -> None:
    """Drop the basename indexes, after a data directory was refreshed."""
    _data_dir_index.clear()


def _resolve_agnostic(
    file_entry: dict, files_db: dict, has_strong_hash: bool
) -> tuple[str, str] | None:
    """Any file of the right shape under the declared prefix.

    Some cores accept whatever filename sits in their BIOS directory, so the
    shape (a size or a size range) is all that identifies a candidate. A
    declared hash outranks that, and stops this step being reached.
    """
    if not file_entry.get("agnostic") or has_strong_hash:
        return None
    prefix = file_entry.get("agnostic_path_prefix", "")
    if not prefix:
        return None
    for _sha1, entry in files_db.items():
        path = entry.get("path", "")
        if not path.startswith(prefix):
            continue
        if size_fits(file_entry, entry.get("size", 0)) and os.path.exists(path):
            return path, "agnostic_fallback"
    return None


_VARIANT_SUFFIX = re.compile(r"\.[0-9a-f]{8}$")


def variant_base_name(name: str) -> str:
    """The name a .variants/ copy stands in for: naomi2.zip.da79eca4 -> naomi2.zip.

    Only an eight-hex-digit suffix is a variant tag. A variant stored under
    its plain name (.variants/aes.zip) already is that name.
    """
    return _VARIANT_SUFFIX.sub("", name)


def _affinity_tokens(text: str) -> set[str]:
    return {
        token
        for token in (re.sub(r"[^0-9a-z]", "", part.casefold()) for part in text.split("/"))
        if token
    }


def _owner_tokens(file_entry: dict) -> set[str]:
    """Tokens naming the profile that asks for the file.

    A profile named after another with a suffix (cxbx-reloaded-2023,
    mame4droid-2024) is a release of that emulator, and the tree named by
    the shorter name is its own: cxbx-reloaded-2023 was served xemu's
    encrypted EEPROM because bios/Other/cxbx-reloaded/ read as foreign.
    Only whole leading words count, so dolphin-mmjr2 is not dolphin-mmjr.
    """
    tokens: set[str] = set()
    for owner in (file_entry.get("source_profile"), file_entry.get("source_emulator")):
        if owner:
            tokens |= _affinity_tokens(str(owner).replace(" ", ""))
    profile = str(file_entry.get("source_profile") or "").casefold()
    words = [word for word in re.split(r"[^0-9a-z]+", profile) if word]
    tokens |= {"".join(words[:end]) for end in range(1, len(words))}
    return tokens


def _foreign_tree(path: str, owners: set[str]) -> bool:
    """Whether a path lives in the tree of an emulator that is not the asker.

    bios/Other/<emulator>/ holds what one emulator ships. A same-named file
    found there answers that emulator's entry, not another's: EmuCoreX's
    unlock.wav was served from NetherSX2's tree, and upstream PCSX2's
    GameIndex.yaml from EmuCoreX's, while the system directory held a copy.
    """
    parts = path.split("/")
    if not owners or len(parts) < 4 or parts[0] != "bios" or parts[1] != "Other":
        return False
    return not (owners & _affinity_tokens(parts[2]))


def _engine_tree(path: str, owners: set[str]) -> bool:
    """Whether a path lives in another game's folder under bios/Game Engines/."""
    parts = path.split("/")
    if len(parts) < 4 or parts[0] != "bios" or parts[1] != "Game Engines":
        return False
    return not (owners & _affinity_tokens(parts[2]))


def _own_tree(path: str, owners: set[str]) -> bool:
    """Whether a path lives in the bios/Other/<emulator>/ tree of the asker."""
    parts = path.split("/")
    if not owners or len(parts) < 4 or parts[0] != "bios" or parts[1] != "Other":
        return False
    return bool(owners & _affinity_tokens(parts[2]))


def _rank_tail_candidates(
    candidates: list[str], start: int, tail: str, files_db: dict, owners: set[str],
    asker: frozenset[str] = frozenset(),
) -> list[str]:
    """Order the files a destination tail designates, the likeliest first.

    A tail found in another emulator's tree is that emulator's asset, not
    evidence about this entry, whatever its length. A full tail claimed
    twice goes to the file whose path carries the least on top of the
    destination, then to the owner's own copy (super3's Games.xml was served
    to Supermodel-Dojo by index order alone), then to any copy outside
    another emulator's tree (upstream PCSX2 took EmuCoreX's GameIndex.yaml
    over the system directory's).
    """
    def path_of(sha1: str) -> str:
        return files_db.get(sha1, {}).get("path", "")

    # Another emulator's tree answers that emulator's entry, at any tail
    # length when a profile asks: lrps2 names no hash for
    # pcsx2/resources/GameIndex.yaml, and the only full-tail copy was ARMSX2's,
    # which then counted as path proof and replaced the GameIndex RetroArch
    # pins on every desktop target. A platform's own declaration has no
    # asker, and the tree whose path is its destination still answers it.
    if start or asker:
        # The database keeps one path per content. When that path does not
        # end with the tail, the tail was indexed from an identical copy
        # elsewhere, and the recorded path says nothing about whose tree it
        # sits in: PCSX2x6's RedumpDatabase.yaml has EmuCoreX's bytes.
        candidates = [
            h for h in candidates
            if not path_of(h).endswith("/" + tail)
            or not _foreign_tree(path_of(h), owners if start else set(asker))
        ]
    if len(candidates) < 2:
        return candidates
    depth = len(tail.split("/"))
    return sorted(
        candidates,
        key=lambda h: (
            len(path_of(h).split("/")) - depth,
            not owners & _affinity_tokens(path_of(h).rsplit("/", 1)[0]),
            _foreign_tree(path_of(h), owners),
        ),
    )


# id(files) -> (files, len(files), {archive: entries with a crc32}). Callers
# ask once per entry of the same profile: scanning the list each time walked
# 38 million entries in one verify --all over mame.yml. The list is held so
# its id is not reused, a list that changed length is indexed again, and the
# members are read from the entries at each call. Short lists are scanned
# directly: a fresh default [] per call would only fill the cache.
_ARCHIVE_INDEX_MIN = 64
_archive_index: dict[int, tuple[list[dict], int, dict[str | None, list[dict]]]] = {}


def _member(f: dict) -> dict:
    member = {"crc32": str(f["crc32"]).lower(), "required": bool(f.get("required", True))}
    if f.get("group"):
        # One of the members sharing it is enough (alternatives.py).
        member["group"] = f["group"]
    return member


def _required_met(members: list[dict], held: Callable[[dict], bool]) -> tuple[int, bool]:
    """How many requirements an archive meets, and whether it meets all.

    A required member is one requirement, and so is a required set of
    alternatives, met when one of its members is held: Odin reads the
    first of three Hikaru boot ROMs it finds in hikaru.zip.
    """
    from alternatives import groups_of

    met = 0
    complete = True
    sets: dict[str, bool] = {}
    for m in members:
        if not m["required"]:
            continue
        names = groups_of(m)
        if names:
            for name in names:
                sets[name] = sets.get(name, False) or held(m)
            continue
        if held(m):
            met += 1
        else:
            complete = False
    met += sum(sets.values())
    return met, complete and all(sets.values())


def archive_members(archive: str, files: list[dict]) -> list[dict]:
    """The members a profile reads inside *archive*, with what it requires."""
    if len(files) < _ARCHIVE_INDEX_MIN:
        return [_member(f) for f in files if f.get("archive") == archive and f.get("crc32")]
    cached = _archive_index.get(id(files))
    if cached is None or cached[0] is not files or cached[1] != len(files):
        index: dict[str | None, list[dict]] = {}
        for f in files:
            if f.get("crc32"):
                index.setdefault(f.get("archive"), []).append(f)
        cached = _archive_index[id(files)] = (files, len(files), index)
    return [_member(f) for f in cached[2].get(archive, ())]


def archive_entry(archive: str, files: list[dict]) -> dict:
    """The entry a profile's archive resolves through.

    Its own declaration when it has one (it carries the container's hashes),
    and the members it reads inside, so a copy of the name that lacks a ROM
    the core requires is not taken for the archive.
    """
    own = next(
        (f for f in files if f.get("name") == archive and not f.get("archive")),
        {"name": archive},
    )
    members = archive_members(archive, files)
    return {**own, "members": members} if members else own


def archive_is_optional(entry: dict, archive: str, files: list[dict]) -> bool:
    """Optional as a whole: its own entry and every member it carries.

    A --required-only pack leaves it out, and the report of that pack too.
    geolith's _Required pack held neocd.zip and irrmaze.zip all the same.
    """
    return entry.get("required") is False and all(
        member.get("required") is False
        for member in files
        if member.get("archive") == archive
    )


def holds_required_members(path: str, members: list[dict]) -> bool:
    """Whether an archive holds every member a profile requires inside it."""
    crcs = zip_member_crcs(path)
    names = zip_member_names(path)
    return _required_met(members, lambda m: _member_held(m, crcs, names))[1]


def contents_members(file_entry: dict) -> list[dict]:
    """The members an archive entry's ``contents:`` lists, as ranking keys.

    A member is its crc32 where the profile declares one, its name where the
    code opens it by name alone: Flycast reads epr-21329.ic27 in
    hod2bios.zip by filename, and a copy without it has no Japan BIOS.
    A crc32 two members share also keeps the name: fpr23905.ic36 and
    fpr23905c.ic36 both have crc32 ffffffff in segadimm.zip, so the crc
    alone cannot tell a copy holding one from a copy holding both.
    """
    listed = [m for m in file_entry.get("contents") or [] if m.get("crc32") or m.get("name")]
    seen = Counter(str(m["crc32"]).lower() for m in listed if m.get("crc32"))
    members = []
    for m in listed:
        if not m.get("crc32"):
            members.append({"name": str(m["name"]), "required": True})
            continue
        crc = str(m["crc32"]).lower()
        member = {"crc32": crc, "required": True}
        if seen[crc] > 1 and m.get("name"):
            member["name"] = str(m["name"])
        members.append(member)
    return members


def _member_held(member: dict, crcs: frozenset[str], names: frozenset[str]) -> bool:
    named = member.get("name", "").rsplit("/", 1)[-1].casefold() in names
    if member.get("crc32"):
        return member["crc32"] in crcs and ("name" not in member or named)
    return named


def _holding_members(paths: list[str], members: list[dict]) -> list[str]:
    """The same-named archives holding the most required members, then the most members.

    FBNeo reads neocd.bin and 000-lo.lo inside neocdz.zip. The primary copy,
    a set without 000-lo.lo, won on the name while a variant held both.
    """
    def held(path: str) -> tuple[int, int]:
        crcs = zip_member_crcs(path)
        names = zip_member_names(path)
        found = {id(m) for m in members if _member_held(m, crcs, names)}
        return _required_met(members, lambda m: id(m) in found)[0], len(found)

    scores = {path: held(path) for path in paths}
    best = max(scores.values(), default=(0, 0))
    if best == (0, 0):
        # Not one declared member in any copy: the name is all that matches,
        # and galgames.zip holding only an assembler listing is not the set.
        return []
    return [path for path in paths if scores[path] == best]


def _covering_archives(paths: list[str]) -> list[str]:
    """Same-named archives, those holding every ROM each other copy holds.

    Without a declared layout, a primary that is a superset of the other
    primaries misses nothing any of them holds. Two copies that each hold a
    ROM the other lacks are different revisions, and nothing here can
    choose: the order is kept. Index order alone used to decide, and
    deleting an unrelated duplicate flipped which copy a core received.
    """
    # A variant is served only when no primary is, so the primaries are
    # the copies this choice is between. A copy in an emulator's own tree
    # (bios/Other/<emulator>/) is that emulator's file, not a revision of
    # the set: an entry no profile owns is not decided by it.
    pool = [
        path for path in paths
        if "/.variants/" not in path and not path.startswith("bios/Other/")
    ] or [path for path in paths if "/.variants/" not in path] or paths
    crcs = {path: zip_member_crcs(path) for path in pool}
    covering = [
        path for path in pool
        if crcs[path] and all(crcs[other] <= crcs[path] for other in pool)
    ]
    return covering + [path for path in paths if path not in covering]


def _by_affinity(paths: list[str], file_entry: dict, dest_hint: str) -> list[str]:
    """Same-named candidates, the likeliest first.

    A name step without a tie-break took whichever path sorted first: the
    TheXTech coin.ogg for Syobon Action, a Hurrican sound for ARMSX2, the
    1 MB CM-32L PCM ROM for ScummVM's 512 KB MT32_PCM.ROM. A size the entry
    declares orders the candidates first (ordering rejects nothing, so an
    unvalidated size keeps its informative status). Then the destination's
    directories and the profile that asks name where its own copy lives. The
    order is otherwise kept.
    """
    if len(paths) < 2:
        return paths
    hint = dest_hint or file_entry.get("path") or file_entry.get("destination") or ""
    wanted = _affinity_tokens(hint.rsplit("/", 1)[0] if "/" in hint else "")
    owners = _owner_tokens(file_entry)
    sized = any(file_entry.get(k) for k in ("size", "min_size", "max_size"))

    def score(path: str) -> tuple[int, bool, bool, bool, int]:
        fits = 0
        if sized and os.path.exists(path):
            fits = int(size_fits(file_entry, os.path.getsize(path)))
        tokens = _affinity_tokens(path.rsplit("/", 1)[0])
        # The owner's own copy ranks above any shared tree segment: NetherSX2's
        # shaders/common/ beat armsx2's own fxaa.fx on two directory tokens.
        # Another emulator's own tree ranks below everything else.
        # A game's folder under Game Engines/ holds that game's data: for a
        # name-only match, a neutral copy goes first. hypseus-singe,
        # flycast-dojo, lindbergh-loader and vvvvvv took C-Dogs' 98-line
        # gamecontrollerdb.txt by index order.
        return (
            fits, bool(owners & tokens), not _foreign_tree(path, owners | wanted),
            not _engine_tree(path, owners | wanted), len(wanted & tokens),
        )

    return sorted(paths, key=score, reverse=True)


_unreadable_archives: set[str] = set()


def _warn_unreadable_archive(path: str, exc: Exception) -> None:
    """Say once that an archive on disk cannot be read.

    Skipped in silence, a truncated ZIP came out as not_found or
    hash_mismatch, which reads as a missing dump instead of a broken one.
    """
    if path not in _unreadable_archives:
        _unreadable_archives.add(path)
        print(f"warning: unreadable archive {path}: {exc}", file=sys.stderr)


def resolve_local_file(
    file_entry: dict,
    db: dict,
    zip_contents: dict | None = None,
    dest_hint: str = "",
    _depth: int = 0,
    data_dir_registry: dict | None = None,
) -> tuple[str | None, str]:
    """Resolve a BIOS file to its local path using database.json.

    Single source of truth for file resolution, used by both verify.py
    and generate_pack.py. Does NOT handle storage tiers (external/user_provided)
    or release assets - callers handle those.

    dest_hint: optional destination path (e.g., "GC/USA/IPL.bin") used to
    disambiguate when multiple files share the same name. Matched against
    the by_path_suffix index built from the repo's directory structure.

    Returns ``(local_path, status)``.  Statuses describe the evidence used:
    ``sha1_exact``, ``sha256_exact``, ``crc32_exact``, ``md5_exact``,
    ``md5_composite_exact``, ``zip_exact``, ``path_exact``, ``name_exact``,
    ``hash_mismatch`` or ``not_found`` (plus documented fallback statuses).

    A path or filename is never allowed to override a declared strong hash.
    """
    sha1 = file_entry.get("sha1")
    name = file_entry.get("name", "")
    # A platform that hands each core a system directory of its own (MinUI's
    # Bios/<TAG>/) writes that folder in front of the core's path. The tail
    # the collection indexes is the core's path alone.
    system_dir = file_entry.get("system_dir")
    if system_dir and dest_hint.startswith(f"{system_dir}/"):
        dest_hint = dest_hint[len(system_dir) + 1:]
    # A launcher that moves the layout (EmuDeck links azahar's sysdata to
    # bios/azahar/keys) changes where the file goes, not the tail the
    # collection indexes it under. Both are asked, and the stronger proof
    # wins: a content or path match over a name, the destination on a tie.
    layout = file_entry.get("layout_path")
    if layout and layout != dest_hint:
        plain = {k: v for k, v in file_entry.items() if k != "layout_path"}
        answers = [
            resolve_local_file(
                plain, db, zip_contents, dest_hint=hint, _depth=_depth,
                data_dir_registry=data_dir_registry,
            )
            for hint in (dest_hint, str(layout))
        ]
        for found in answers:
            if found[0] is not None and (
                resolution_is_hash_exact(found[1]) or found[1] == "path_exact"
            ):
                return found
        for found in answers:
            if found[0] is not None and found[1] not in ("not_found", "hash_mismatch"):
                return found
        return next((found for found in answers if found[0] is not None), answers[0])
    # A name written with its directory is the destination when no path is
    # given: gam4980/E.BIN resolved by its basename took another model's OS
    # in verify --emulator and the emulator pack, while the platform pack,
    # which passes the destination, served the GAM4980's.
    if not dest_hint and "/" in name.strip("/"):
        dest_hint = name
    zipped_file = file_entry.get("zipped_file")
    aliases = file_entry.get("aliases", [])
    names_to_try = [name] + [a for a in aliases if a != name]

    # When name contains a path separator (e.g. "res/tilemap.bin"), also
    # try the basename since by_name indexes filenames without directories
    if "/" in name:
        name_base = name.rsplit("/", 1)[-1]
        if name_base and name_base not in names_to_try:
            names_to_try.append(name_base)

    # When dest_hint contains a path, also try its basename as a name
    # (handles emulator profiles where name: is descriptive and path: is
    # the actual filename, e.g. name: "MDA font ROM", path: "mda.rom")
    own_names = list(names_to_try)
    if dest_hint:
        hint_base = dest_hint.rsplit("/", 1)[-1] if "/" in dest_hint else dest_hint
        if hint_base and hint_base not in names_to_try:
            names_to_try.append(hint_base)

    md5_list = parse_md5_list(file_entry.get("md5"))
    files_db = db.get("files", {})
    by_md5 = db.get("indexes", {}).get("by_md5", {})
    # A value cut short stands for the one held md5 it starts, and only
    # then (cut_md5_owner): the dump it names is still name-guarded below.
    cut_owners = {
        cut: owner for cut in md5_list
        if len(cut) < 32 and (owner := cut_md5_owner(cut, by_md5))
    }
    md5_list = [cut_owners.get(value, value) for value in md5_list]
    sha1_candidates = [
        str(value).strip().lower()
        for value in (sha1 if isinstance(sha1, list) else [sha1] if sha1 else [])
        if str(value).strip()
    ]
    sha256_raw = file_entry.get("sha256")
    sha256_values = sha256_raw if isinstance(sha256_raw, list) else [sha256_raw]
    sha256_candidates = [
        candidate.strip().lower()
        for value in sha256_values
        if value
        for candidate in str(value).split(",")
        if len(candidate.strip()) == 64
    ]
    # One value, a list, or a comma-separated string, like the other hashes.
    crc_values = file_entry.get("crc32") or []
    # Kept in the order declared, which is the order a lookup tries them.
    crc_candidates = dict.fromkeys(
        candidate.strip().lower().removeprefix("0x")
        for value in (crc_values if isinstance(crc_values, list) else [crc_values])
        for candidate in str(value).split(",")
        if candidate.strip()
    )
    declared_size = file_entry.get("size")
    has_strong_hash = bool(
        sha1_candidates or sha256_candidates or md5_list or crc_candidates
    )
    by_name = db.get("indexes", {}).get("by_name", {})
    by_path_suffix = db.get("indexes", {}).get("by_path_suffix", {})

    def _record_match_status(match_sha1: str) -> str | None:
        """Return hash evidence when a DB record satisfies every declaration."""
        entry = files_db.get(match_sha1)
        if not entry:
            return None
        statuses: list[str] = []
        if sha1_candidates:
            if match_sha1.lower() not in sha1_candidates:
                return None
            statuses.append("sha1_exact")
        if sha256_candidates:
            if str(entry.get("sha256", "")).lower() not in sha256_candidates:
                return None
            statuses.append("sha256_exact")
        # With zipped_file the MD5 identifies the member, not the container.
        if md5_list and not zipped_file:
            actual_md5 = str(entry.get("md5", "")).lower()
            if actual_md5 not in md5_list:
                return None
            statuses.append("md5_exact")
        if crc_candidates:
            if str(entry.get("crc32", "")).lower() not in crc_candidates:
                return None
            if declared_size is not None:
                allowed_sizes = (
                    declared_size if isinstance(declared_size, list) else [declared_size]
                )
                if entry.get("size") not in allowed_sizes:
                    return None
            statuses.append("crc32_exact")
        return statuses[0] if statuses else None

    # 1. SHA1 exact match (accept list-valued sha1 from profiles)
    for cand in sha1_candidates:
        if cand in files_db:
            path = files_db[cand]["path"]
            status = _record_match_status(cand)
            if status and os.path.exists(path):
                return path, status

    # 1b. SHA256 exact match (profiles hashed from sources that publish
    # sha256, e.g. MesenCE). A full sha256 is a strong identifier.
    if sha256_candidates:
        by_sha256 = db.get("indexes", {}).get("by_sha256", {})
        for cand in sha256_candidates:
            match = by_sha256.get(cand)
            if match and match in files_db:
                path = files_db[match]["path"]
                status = _record_match_status(match)
                if status and os.path.exists(path):
                    return path, status

    # 1c. CRC32 lookup, only when no stronger hash is declared.  A declared
    # size confirms it when available. A handful of emulators validate CRC32
    # alone, so those entries retain the same (weaker) evidence as the core.
    if (
        crc_candidates
        and not zipped_file
        and not md5_list
        and not sha1_candidates
        and not sha256_candidates
    ):
        by_crc32 = db.get("indexes", {}).get("by_crc32", {})
        found: list[tuple[str, str]] = []
        for crc in crc_candidates:
            match = by_crc32.get(crc)
            if match and match in files_db:
                path = files_db[match]["path"]
                status = _record_match_status(match)
                if status and os.path.exists(path):
                    found.append((path, status))
        # A primary copy over a .variants/ one, as everywhere else.
        for path, status in found:
            if "/.variants/" not in path:
                return path, status
        if found:
            return found[0]

    # 2. MD5 direct lookup (skip for zipped_file: md5 is inner ROM, not container)
    # Guard: only accept if the found file's name matches the requested name
    # (or is a .variants/ derivative). Prevents cross-contamination when an
    # unrelated file happens to share the same MD5 in the index.
    _name_set = set(names_to_try)

    def _md5_name_ok(candidate_path: str) -> bool:
        bn = os.path.basename(candidate_path)
        if bn in _name_set:
            return True
        # .variants/ pattern: filename like "neogeo.zip.fc398ab4"
        return any(bn.startswith(n + ".") for n in _name_set)

    # A frontend that hashes an archive by its members (Recalbox) never reads
    # the container's own md5: neocd.bin's md5 is also the composite of a
    # one-member neocdz.zip, and the raw ROM shipped under the archive's name.
    composite_only = file_entry.get("zip_digest") == "composite"

    if md5_list and not zipped_file and not composite_only:
        for md5_candidate in md5_list:
            sha1_match = by_md5.get(md5_candidate)
            if sha1_match and sha1_match in files_db:
                path = files_db[sha1_match]["path"]
                # A full md5 as declared is a strong identifier: trusted
                # without name guard. One completed from a cut value still
                # needs the name check to avoid cross-contamination.
                status = _record_match_status(sha1_match)
                if status and os.path.exists(path):
                    if md5_candidate not in cut_owners.values() or _md5_name_ok(path):
                        return path, status

    # 2b. Path suffix lookup is useful for same-named regional files, but it
    # is identity evidence only when no content hash was declared.  A stale
    # or incorrect destination can therefore never mask a hash mismatch.
    own_file_absent = False
    if dest_hint and by_path_suffix:
        # A destination is written from the emulator's point of view
        # ("pcsx2/resources/GameIndex.yaml") and the index from the repo's
        # layout, so the two meet on a tail rather than on the whole string.
        # Longest tail first, and never down to the bare filename: that is the
        # weaker step below, and five files answer to GameIndex.yaml.
        # Two kinds of ambiguity appear once every tail is indexed. A
        # shortened tail can be claimed by several emulators shipping the same
        # asset tree, and it then proves nothing: skip it. The full tail can be
        # claimed twice as well, one storing it at the root of its own
        # directory and one nested deeper. There the file whose path carries
        # the least on top of the destination is the one that IS the
        # destination.
        # The descent drops at most one leading segment. A destination and the
        # tree differ by the wrapper directory at most. Beyond that the tail
        # stops describing this file and starts describing whichever emulator
        # happens to store the same asset tree.
        hint_parts = dest_hint.split("/")
        # The asking profile and the destination's own directories both name
        # whose tree a copy may come from.
        owners = _owner_tokens(file_entry) | _affinity_tokens("/".join(hint_parts[:-1]))
        for start in range(min(2, len(hint_parts) - 1)):
            tail = "/".join(hint_parts[start:])
            candidates = _rank_tail_candidates(
                by_path_suffix.get(tail, []), start, tail, files_db, owners,
                frozenset(_owner_tokens(file_entry)),
            )
            raw = by_path_suffix.get(tail, [])
            if start and len(raw) > 1:
                # Ambiguity is read before the foreign trees are set aside:
                # PCSX2x6's bin/resources/GameIndex.yaml met four copies
                # under resources/GameIndex.yaml, three in other emulators'
                # trees, and the fourth (PCSX2's console database, not
                # PCSX2x6's arcade one) passed for proof. Only the asker's own
                # tree still answers a tail several files share.
                candidates = [
                    h for h in candidates
                    if _own_tree(files_db.get(h, {}).get("path", ""), owners)
                ]
            if start and len(candidates) > 1:
                continue
            # The index names the file this destination designates. Not on
            # disk, it is a release asset the checkout does not hold, and no
            # other file of that name is it.
            if not start and candidates and not any(
                os.path.exists(files_db.get(h, {}).get("path", ""))
                for h in candidates
            ):
                own_file_absent = True
            for match_sha1 in candidates:
                if match_sha1 not in files_db:
                    continue
                path = files_db[match_sha1]["path"]
                if not os.path.exists(path):
                    continue
                if not has_strong_hash:
                    # A path names the file, the size the code checks still
                    # bounds it, as on the name step: ZEsarUX's 48 KB
                    # cpc6128.rom is not cap32's 32 KB one at the same tail.
                    if not name_match_size_ok(
                        file_entry, files_db[match_sha1].get("size")
                    ) or not adler32_fits(file_entry, path, db):
                        continue
                    return path, "path_exact"
                status = _record_match_status(match_sha1)
                if status:
                    return path, status

    # 2c. The same tail in a data directory. by_path_suffix indexes bios/
    # only, so AmberELEC's Machines/MSX - Arabic/config.ini fell through to
    # the name step and got msx-emu's ColecoVision config.ini, while
    # data/bluemsx held blueMSX's own at that very path. A platform
    # declaration is resolved without a hint, and its destination is that
    # path. The descent and the ambiguity rule are those of the bios/ tails.
    # A profile's entry is not asked here: it names its owner, the name step
    # sends it to its data directories when another emulator's copy answers,
    # and a dump it declares outranks the free one its tree bundles at the
    # same path (Dolphin's dsp_coef.bin over Sys/GC's).
    tail_hint = dest_hint or str(file_entry.get("destination") or "")
    if (
        tail_hint
        and data_dir_registry
        and not has_strong_hash
        and not _owner_tokens(file_entry)
    ):
        hit = _data_dir_tail(tail_hint, data_dir_registry, file_entry, db)
        if hit:
            return hit, "path_exact"

    # 3. No MD5 = any file with that name or alias (existence check)
    def _size_ok(match_sha1: str) -> bool:
        record = files_db.get(match_sha1, {})
        return name_match_size_ok(file_entry, record.get("size")) and adler32_fits(
            file_entry, record.get("path", ""), db
        )

    # An entry the profile documents as unsourceable is one the collection
    # cannot hold: a font that only exists inside a paid package, cheat codes
    # written per title. A file answering to its name is therefore a homonym
    # from another system, not a stale dump of the same file - kanji.rom names
    # an FPseNG font, an openMSX one and a 3DO ROM. Content still decides: the
    # hash and path steps above run first, so collecting the real bytes makes
    # the entry resolve.
    unsourceable = bool(file_entry.get("unsourceable")) or own_file_absent
    # A platform's own hashless entry whose system names a maker takes no copy
    # filed under another maker: AmberELEC's nec-pc-88 DISK.ROM, which QUASI88
    # reads as the 2 KB PC-88 disk ROM, got the 16 KB MSX one by name.
    makers = frozenset() if has_strong_hash else system_makers(file_entry, db)

    if not has_strong_hash and not unsourceable:
        candidates = []
        # The entry's own names first, the destination's basename only when
        # none of them answers. melonDS Nightly's dsi_nand.bin is read at
        # dsi/nand.bin: with the DSi image absent from the checkout, the
        # basename let the Wii nand.bin outrank the entry's own DSi variant.
        # A name whose held file no declaration proves, while declarations
        # of that name prove another dump beside it, means that dump: the
        # DSi devkit boot ROMs filed as dsi_bios7.bin went to RetroBat.
        by_proven_name = db.get("indexes", {}).get("by_proven_name", {})
        for tier in (own_names, names_to_try[len(own_names):]):
            for try_name in tier:
                for match_sha1 in (
                    by_proven_name.get(try_name) or by_name.get(try_name, [])
                ):
                    if match_sha1 in files_db and _size_ok(match_sha1):
                        path = files_db[match_sha1]["path"]
                        if os.path.exists(path) and path not in candidates:
                            candidates.append(path)
            if candidates:
                break
        if candidates and all("/.variants/" in p for p in candidates):
            # Only variants answer the exact casing, but the primary they
            # stand in for may be stored under another one: x1 asked for
            # IPLROM.X1 and got Recalbox's second md5 while iplrom.x1, the
            # dump every platform pins, sat in the same directory. A primary
            # counts here only in a variant's own directory and under its own
            # file name: an alias (iplrom.x1t names a font in System.dat) or
            # another machine's font.rom is not that file.
            homes = {p.split("/.variants/", 1)[0] for p in candidates}
            folded = _casefold_name_index(by_name)
            for try_name in names_to_try:
                wanted = try_name.rsplit("/", 1)[-1].casefold()
                for match_sha1 in folded.get(try_name.casefold(), []):
                    path = files_db.get(match_sha1, {}).get("path", "")
                    if (
                        "/.variants/" not in path
                        and os.path.dirname(path) in homes
                        and os.path.basename(path).casefold() == wanted
                        and _size_ok(match_sha1)
                        and os.path.exists(path)
                        and path not in candidates
                    ):
                        candidates.append(path)
        owners = _owner_tokens(file_entry)
        # Only another emulator's tree answers the exact casing: what it
        # holds there says nothing about this entry's file.
        exact_foreign = bool(candidates) and all(
            _foreign_tree(p, owners) for p in candidates
        )
        if not candidates or exact_foreign:
            # Case-insensitive fallback: upstream platforms disagree on
            # casing (VEC_MineStorm.vec vs VEC_Minestorm.vec). Two casings
            # can name two contents (FONT.ROM and font.rom), so this only
            # runs when no casing matches exactly, or when only another
            # emulator's tree does: xm6typeg got XM6 Utility's synthesized
            # SCSIINROM.DAT while the X68000 dump sat as scsiinrom.dat.
            # Another casing in another emulator's tree proves nothing:
            # reminiscence's music module reunion took skyline's
            # zoneinfo/Indian/Reunion.
            folded = _casefold_name_index(by_name)
            for try_name in names_to_try:
                for match_sha1 in folded.get(try_name.casefold(), []):
                    if match_sha1 in files_db and _size_ok(match_sha1):
                        path = files_db[match_sha1]["path"]
                        if _foreign_tree(path, owners):
                            continue
                        if os.path.exists(path) and path not in candidates:
                            candidates.append(path)
        # A platform entry names no profile, but a system that lists its
        # cores says whose files it asks for. A name only another emulator's
        # tree answers is no evidence, and the data directories hold those
        # emulators' trees too: EmuELEC's VVVVVV data.zip was served xrick's
        # archive of the same name, then xrick's data directory copy.
        core_owners = {
            token
            for core in file_entry.get("platform_cores") or ()
            for token in _affinity_tokens(str(core))
        }
        if (
            not owners
            and core_owners
            and candidates
            and all(_foreign_tree(p, core_owners) for p in candidates)
        ):
            candidates = []
            unsourceable = True
        if makers and candidates:
            candidates = [p for p in candidates if not other_maker(p, makers, db)]
            if not candidates:
                # The name belongs to another maker's file here. An emulator
                # of this system may still read it as an alias of one of its
                # own files, an alias by_name leaves out because a primary
                # already carries the name: QUASI88 reads DISK.ROM as
                # n88sub.rom.
                shadowed = db.get("indexes", {}).get("by_shadowed_alias", {})
                for try_name in own_names:
                    for match_sha1 in shadowed.get(try_name, []):
                        path = files_db.get(match_sha1, {}).get("path", "")
                        if (
                            _maker_folder(path, str(db.get("bios_dir") or "bios"))
                            in makers
                            and _size_ok(match_sha1)
                            and os.path.exists(path)
                            and path not in candidates
                        ):
                            candidates.append(path)
        if candidates:
            if zipped_file:
                candidates = [p for p in candidates if ".zip" in os.path.basename(p)]
            members = file_entry.get("members") or contents_members(file_entry)
            if members or (len(candidates) > 1 and name.casefold().endswith(".zip")):
                # Another emulator's own copy takes no part in the ranking:
                # Demul's naomi.zip holds more NAOMI BIOS rows than any MAME
                # set and broke the superset the MAME cores were served.
                candidates = [
                    p for p in candidates if not _foreign_tree(p, owners)
                ] or candidates
            if members:
                candidates = _holding_members(candidates, members)
            elif len(candidates) > 1 and name.casefold().endswith(".zip"):
                candidates = _covering_archives(candidates)
            candidates = _by_affinity(candidates, file_entry, dest_hint)
            best = candidates[0] if candidates else ""
            # A copy outside another emulator's tree comes first: the
            # affinity read pcsx2 in bios/Other/armsx2/pcsx2/ and served
            # upstream PCSX2 the patches.zip of ARMSX2.
            candidates = [
                p for p in candidates if not _foreign_tree(p, owners)
            ] or candidates
            primary = [p for p in candidates if "/.variants/" not in p]
            if primary or candidates:
                chosen = primary[0] if primary else candidates[0]
                # The best of them is another emulator's own copy, served or
                # set aside: the name says nothing about this profile's file,
                # and a data directory it reads may hold it. Dolphin got
                # Dolphin-MMJR's codehandler.bin while data/dolphin-sys held
                # its own, and blueMSX got the 16 KB RS232.ROM once msx-emu's
                # 8 KB copy was set aside, while data/bluemsx held its own,
                # and MSX2P.ROM of another dump once only msx-emu answered
                # the exact casing.
                if data_dir_registry and (exact_foreign or _foreign_tree(best, owners)):
                    hit, _mismatch = _resolve_in_data_dirs(
                        names_to_try, data_dir_registry,
                        functools.partial(
                            declared_hash_verdict,
                            has_strong_hash=False,
                            sha1_candidates=set(),
                            sha256_candidates=set(),
                            md5_list=[],
                            crc_candidates=set(),
                            zipped_file=zipped_file,
                            declared_size=declared_size,
                            file_entry=file_entry,
                            db=db,
                        ),
                    )
                    if hit:
                        return hit
                return chosen, "name_exact"

    # 4. Name + alias fallback with md5_composite + direct MD5 per candidate
    md5_set = set(md5_list)
    named: list[tuple[str, str, int | None]] = []
    seen_paths = set()
    for try_name in names_to_try:
        for match_sha1 in by_name.get(try_name, []):
            if match_sha1 in files_db:
                entry = files_db[match_sha1]
                path = entry["path"]
                if os.path.exists(path) and path not in seen_paths:
                    seen_paths.add(path)
                    named.append(
                        (path, entry.get("md5", ""), entry.get("size"))
                    )

    if zipped_file:
        named = [c for c in named if ".zip" in os.path.basename(c[0])]
    # Another maker's file is no mismatch of this one, it is another file.
    named = [c for c in named if not other_maker(c[0], makers, db)]
    # A size the emulator itself verifies settles a name collision, so a
    # candidate that fits is preferred over one that does not: "ROM" answers
    # both an Apple IIgs image and a Macintosh one. It ranks rather than
    # excludes, because a present file of the wrong size is reported as
    # present and untested, and dropping it would report it as absent.
    sized = [c for c in named if name_match_size_ok(file_entry, c[2])]
    if sized:
        named = sized

    if named:
        if md5_set and not (sha1_candidates or sha256_candidates or crc_candidates):
            if composite_only:
                named.sort(key=lambda c: "/.variants/" in c[0])
            for path, db_md5, _size in named:
                if ".zip" in os.path.basename(path):
                    try:
                        composite = md5_composite(path).lower()
                        # A zipped_file md5 is the member's: one member of
                        # another name has the same composite, and Batocera
                        # looks the member up by name.
                        if composite in md5_set and (
                            not zipped_file
                            or check_inside_zip(path, zipped_file, composite) == "ok"
                        ):
                            return path, "md5_composite_exact"
                    except (zipfile.BadZipFile, OSError) as exc:
                        _warn_unreadable_archive(path, exc)
                if db_md5.lower() in md5_set and not composite_only:
                    return path, "md5_exact"
        # When zipped_file is set, only accept candidates that contain it
        if zipped_file:
            valid = []
            for path, m, size in named:
                try:
                    with zipfile.ZipFile(path) as zf:
                        inner_names = {n.casefold() for n in zf.namelist()}
                        if zipped_file.casefold() in inner_names:
                            valid.append((path, m, size))
                except (zipfile.BadZipFile, OSError) as exc:
                    _warn_unreadable_archive(path, exc)
            # The archive whose member carries the declared md5 is the one:
            # neogeo.zip is held twice, each with its own sfix.sfix, and the
            # first by name was returned as a mismatch while the other matched.
            for path, _m, _size in sorted(valid, key=lambda c: "/.variants/" in c[0]):
                if any(check_inside_zip(path, zipped_file, md5) == "ok" for md5 in md5_list):
                    return path, "zip_exact"
            if valid:
                primary = [c[0] for c in valid if "/.variants/" not in c[0]]
                return (primary[0] if primary else valid[0][0]), "hash_mismatch"
            # No candidate contains the zipped_file: fall through to step 5
        elif not unsourceable:
            ordered = _by_affinity([c[0] for c in named], file_entry, dest_hint)
            primary = [c for c in ordered if "/.variants/" not in c]
            return (primary[0] if primary else ordered[0]), "hash_mismatch"

    # 5. zipped_file content match via pre-built index (last resort:
    # matches inner ROM MD5 across ALL ZIPs in the repo, so only use
    # when name-based resolution failed entirely)
    if (
        zipped_file
        and md5_list
        and zip_contents
        and not (sha1_candidates or sha256_candidates or crc_candidates)
    ):
        for md5_candidate in md5_list:
            if md5_candidate in zip_contents:
                zip_sha1 = zip_contents[md5_candidate]
                if zip_sha1 in files_db:
                    path = files_db[zip_sha1]["path"]
                    if os.path.exists(path):
                        return path, "zip_exact"

    # MAME clone fallback: if a file was deduped, resolve via canonical. The
    # clone name is a name step like the others: an unsourceable entry skips
    # it, and the size the code checks travels with it (dedup only merges
    # identical bytes, so the canonical copy has the clone's size).
    if _depth < 3 and not has_strong_hash and not unsourceable:
        clone_map = get_mame_clone_map(db.get("bios_dir"))
        canonical = clone_map.get(name)
        if canonical and canonical != name:
            canonical_entry = {
                field: file_entry[field]
                for field in ("size", "min_size", "max_size", "validation")
                if field in file_entry
            }
            canonical_entry["name"] = canonical
            result = resolve_local_file(
                canonical_entry,
                db,
                zip_contents,
                dest_hint,
                _depth=_depth + 1,
                data_dir_registry=data_dir_registry,
            )
            if result[0] and result[1] != "hash_mismatch":
                return result[0], "mame_clone"

    # Data directory fallback: scan data/ caches for matching filename

    data_dir_mismatch: str | None = None
    # Without a hash the cache walk matches on filename alone, which is the
    # step an unsourceable entry has to skip: hiscore.dat names one file per
    # driver set, so FBNeo's copy would answer for MAME's.
    if data_dir_registry and (has_strong_hash or not unsourceable):
        verdict = functools.partial(
            declared_hash_verdict,
            has_strong_hash=has_strong_hash,
            sha1_candidates=sha1_candidates,
            sha256_candidates=sha256_candidates,
            md5_list=md5_list,
            crc_candidates=set(crc_candidates),
            zipped_file=zipped_file,
            declared_size=declared_size,
            file_entry=file_entry,
            db=db,
        )
        hit, data_dir_mismatch = _resolve_in_data_dirs(
            names_to_try, data_dir_registry, verdict
        )
        if hit:
            return hit

    if data_dir_mismatch and not unsourceable:
        return data_dir_mismatch, "hash_mismatch"

    agnostic = _resolve_agnostic(file_entry, files_db, has_strong_hash)
    if agnostic:
        return agnostic

    return None, "not_found"


_mame_clone_map_cache: dict[str, dict[str, str]] = {}


def get_mame_clone_map(bios_dir: str | None = None) -> dict[str, str]:
    """The MAME clone map (clone_name -> canonical_name) of a scanned tree.

    dedup.py writes _mame_clones.json beside the tree it scanned, and the
    map of one tree says nothing about another: read from the repository
    root whatever ``--bios-dir`` said, an alternate tree's renamed clones
    fell out of its packs. Without a tree the repository's own is read.
    """
    if bios_dir is None:
        bios_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bios"
        )
    clone_path = os.path.join(os.path.dirname(os.path.abspath(bios_dir)), "_mame_clones.json")
    cached = _mame_clone_map_cache.get(clone_path)
    if cached is not None:
        return cached
    clone_map: dict[str, str] = {}
    if os.path.exists(clone_path):
        with open(clone_path) as f:
            data = json.load(f)
        for canonical, info in data.items():
            for clone in info.get("clones", []):
                clone_map[clone] = canonical
    _mame_clone_map_cache[clone_path] = clone_map
    return clone_map





_emulator_profiles_cache: dict[tuple[str, bool], dict[str, dict]] = {}


class ProfileSelectionError(ValueError):
    """A named profile cannot answer for itself."""


def profiles_for_systems(
    profiles: dict, system_ids: list[str], standalone: bool = False
) -> list[str]:
    """Profile keys that serve any of the systems, spelled either way.

    Compared on the normalized id: stella2014 writes atari_2600 where every
    other profile writes atari-2600, and an exact match built two different
    packs under one file name, the second replacing the first.
    """
    wanted = {_norm_system_id(sid) for sid in system_ids}
    matching = []
    for name, profile in sorted(profiles.items()):
        if profile.get("type") in ("launcher", "alias") or profile.get("role") == "test":
            continue
        if standalone and "standalone" not in profile.get("type", "libretro"):
            continue
        if wanted & {_norm_system_id(sid) for sid in profile.get("systems", [])}:
            matching.append(name)
    return matching


def entry_system_ids(entry: dict, profile: dict) -> list[str]:
    """Systems a profile entry serves.

    The entry's own `system:`, else its own `systems:` (a MAME device set
    the machines of several systems load), else every system of its
    profile.
    """
    own = entry.get("system")
    if own:
        return [str(own)]
    listed = entry.get("systems") or profile.get("systems") or []
    return [str(sid) for sid in listed]


def entry_serves_systems(entry: dict, profile: dict, system_ids: list[str]) -> bool:
    """Whether a profile entry belongs to one of the systems, spelled either way.

    The entry's own `system:` or `systems:` decides. One without either
    serves every system of its profile, the rule a platform pack applies to
    core extras.
    """
    wanted = {_norm_system_id(sid) for sid in system_ids}
    return bool(wanted & {_norm_system_id(sid) for sid in entry_system_ids(entry, profile)})


def select_emulator_profiles(
    profile_names: list[str],
    all_profiles: dict,
    standalone: bool = False,
) -> list[tuple[str, dict]]:
    """Resolve named profiles, refusing the ones that answer for no core.

    An alias is the same binary under another name, so naming one selects
    the profile it is an alias of, said on stderr. A launcher only starts an
    emulator and has no requirements of its own: naming one is a question
    about the wrong profile, and the error says so. Raising rather than exiting lets the verifier stop and the
    builder return empty-handed from one rule.
    """
    selected: list[tuple[str, dict]] = []
    for name in profile_names:
        if name not in all_profiles:
            # A buildbot name (pcfx, advmame) lives in a profile's cores:,
            # and the spelling hints sent pcfx to two PlayStation cores.
            claimants = sorted(
                key for key in upstream_profile_index(all_profiles).get(name, ())
                if all_profiles[key].get("type") != "launcher" and all_profiles[key].get("role") != "test"
            )
            if len(claimants) == 1:
                name = claimants[0]
            elif claimants:
                raise ProfileSelectionError(
                    f"{name} is a core name of {', '.join(claimants)}: "
                    f"use --emulator with one of them"
                )
        if name not in all_profiles:
            available = sorted(
                key
                for key, value in all_profiles.items()
                if value.get("type") != "alias" and value.get("role") != "test"
            )
            raise ProfileSelectionError(
                f"emulator '{name}' not found\n"
                + suggest_names([name], available, "--list-emulators")
            )
        profile = all_profiles[name]
        kind = profile.get("type", "libretro")
        if kind == "alias":
            # An alias without alias_of is found through the profile whose
            # cores: names it, as the buildbot reverse index does.
            target = profile.get("alias_of") or next(
                (
                    key for key, value in all_profiles.items()
                    if value.get("type") != "alias" and name in (value.get("cores") or [])
                ),
                None,
            )
            if not target or target not in all_profiles:
                raise ProfileSelectionError(
                    f"{name} is an alias with no profile of its own to name"
                )
            # The name a user reads in RetroArch or on the buildbot: the tool
            # knows the profile, so it says which and carries on.
            print(f"{name} is {target}: using its profile", file=sys.stderr)
            name, profile = target, all_profiles[target]
            kind = profile.get("type", "libretro")
            if any(key == name for key, _ in selected):
                continue
        if kind == "launcher":
            raise ProfileSelectionError(
                f"{name} is a launcher: use the emulator it launches"
            )
        if standalone and "standalone" not in kind:
            raise ProfileSelectionError(
                f"{name} ({kind}) does not support --standalone"
            )
        selected.append((name, profile))
    return selected


PROFILE_BACKUP_SUFFIX = ".old.yml"


def source_yaml_paths(directory: str | Path) -> list[Path]:
    """YAML sources in a directory, without the copies the hash merge keeps."""
    return [
        path
        for path in sorted(Path(directory).glob("*.yml"))
        if not path.name.endswith(PROFILE_BACKUP_SUFFIX)
    ]


def installed_data_refs(platform: str, emulators_dir: str = "") -> frozenset[str]:
    """Data directories a platform's own packages install beside the cores.

    The platform layer names trees for its systems (retroarch.yml carries
    dolphin-sys and ppsspp-assets, and Lakka inherits them), while Lakka's
    core packages put both into the system directory themselves. A profile
    records that with installed_on on its data directory reference.
    """
    emulators_dir = emulators_dir or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "emulators")
    return frozenset(
        str(tree.get("ref", ""))
        for profile in load_emulator_profiles(emulators_dir, skip_aliases=False).values()
        for tree in profile.get("data_directories") or []
        if isinstance(tree, dict) and platform in (tree.get("installed_on") or [])
    )


def load_emulator_profiles(
    emulators_dir: str,
    skip_aliases: bool = True,
) -> dict[str, dict]:
    """Load all emulator YAML profiles from a directory (cached)."""
    cache_key = (os.path.realpath(emulators_dir), skip_aliases)
    if cache_key in _emulator_profiles_cache:
        return _emulator_profiles_cache[cache_key]
    if skip_aliases:
        # A filter over the full set: parsed once, 534 YAML files cost 1.6 s
        # every time a process asked for both variants.
        profiles = {
            name: profile
            for name, profile in load_emulator_profiles(emulators_dir, False).items()
            if profile.get("type") != "alias"
        }
        _emulator_profiles_cache[cache_key] = profiles
        return profiles
    try:
        import yaml
    except ImportError:
        # Every consumer reads {} as "this repo documents no emulator", which
        # is what a broken install looks like from the outside: zero coverage,
        # no gap, nothing to fix.
        print(
            "warning: pyyaml is not installed, no emulator profile was loaded",
            file=sys.stderr,
        )
        return {}
    profiles = {}
    emu_path = Path(emulators_dir)
    if not emu_path.is_dir():
        # Read as "no emulator", a mistyped --emulators-dir built a pack
        # without any core file marked OK, and sitesources wrote {} over
        # source-paths.json, both exiting 0.
        raise InputMissing(f"no emulator profile directory at {emulators_dir}")
    for f in source_yaml_paths(emu_path):
        with open(f) as fh:
            profile = source_yaml(fh) or {}
        if "emulator" not in profile:
            continue
        _normalize_hash_fields(profile)
        derive_member_requirements(profile)
        profiles[f.stem] = profile
    _emulator_profiles_cache[cache_key] = profiles
    return profiles


_HASH_FIELDS = ("crc32", "md5", "sha1", "sha256")


def _normalize_hash_fields(node: object) -> None:
    """Coerce hash values to str in place.

    YAML types unquoted digit-only hashes (e.g. crc32: 70295038) as int,
    which breaks string comparisons and formatting downstream.
    """
    if isinstance(node, dict):
        for key, val in node.items():
            if key in _HASH_FIELDS:
                if isinstance(val, int):
                    node[key] = str(val)
                elif isinstance(val, list):
                    node[key] = [str(v) if isinstance(v, int) else v for v in val]
            else:
                _normalize_hash_fields(val)
    elif isinstance(node, list):
        for item in node:
            _normalize_hash_fields(item)


def unique_emulator_profiles(profiles: dict[str, dict]) -> dict[str, dict]:
    """Profiles counting as distinct emulators (aliases and tests excluded)."""
    return {
        k: v for k, v in profiles.items() if v.get("type") != "alias" and v.get("role") != "test"
    }


# Trees that hold game and engine data rather than the system files of a
# machine: the engine trees, and the publishers whose games an engine runs.
GAME_DATA_TOPS = (
    "RPG Maker",
    "ScummVM",
    "Game Engines",
    "sdlpal",
    "Dinothawr",
    "3D Realms",
    "Apogee",
    "Blizzard",
    "Bungie",
    "Crack dot Com",
    "Electronic Arts",
    "Epic MegaGames",
    "Id Software",
    "Interplay",
    "Monolith",
    "Softdisk",
    "Toys for Bob",
    "Valve",
)


def composition_tier(path: str) -> str:
    """Which composition bucket a repository path belongs to."""
    parts = path.split("/")
    top = parts[1] if len(parts) > 1 else ""
    if top == "Arcade":
        return "arcade"
    if top in GAME_DATA_TOPS:
        return "game_data"
    return "systems"


def compute_composition(db: dict) -> dict:
    """File and byte counts by tree area.

    Three buckets, each re-derivable from paths alone: arcade ROM sets
    (Arcade/), game and engine data (the trees of GAME_DATA_TOPS), and
    console or computer system files (everything else).
    """
    buckets = {
        "systems": {"files": 0, "size_bytes": 0},
        "arcade": {"files": 0, "size_bytes": 0},
        "game_data": {"files": 0, "size_bytes": 0},
    }
    for entry in db.get("files", {}).values():
        bucket = buckets[composition_tier(entry.get("path", ""))]
        bucket["files"] += 1
        bucket["size_bytes"] += entry.get("size", 0)
    return buckets


def count_catalog_matched(db: dict) -> int:
    """System files byte-identical to a dump-preservation catalog entry.

    Scoped to the systems bucket, the denominator every surface pairs it
    with: No-Intro, Redump and TOSEC index console and computer dumps, so
    arcade ROM sets and engine data sit on neither side of the ratio.
    """
    return sum(
        1
        for entry in db.get("files", {}).values()
        if entry.get("provenance")
        and composition_tier(entry.get("path", "")) == "systems"
    )


def group_identical_platforms(
    platforms: list[str],
    platforms_dir: str,
    target_cores_cache: dict[str, set[str] | None] | None = None,
) -> list[tuple[list[str], str]]:
    """Group platforms that produce identical packs.

    A pack is the platform's own files plus those of the emulators it runs,
    so two platforms share one only when both agree. base_destination does
    not separate them: destinations inside a pack are relative to it.

    Returns [(group_of_platform_names, representative), ...].
    The representative is the root platform (one that does not inherit).
    """
    fingerprints: dict[str, list[str]] = {}
    representatives: dict[str, str] = {}
    inherits: dict[str, bool] = {}

    for platform in platforms:
        try:
            raw_path = os.path.join(platforms_dir, f"{platform}.yml")
            with open(raw_path) as f:
                raw = source_yaml(f) or {}
            inherits[platform] = "inherits" in raw
            config = load_platform_config(platform, platforms_dir)
        except FileNotFoundError:
            fingerprints.setdefault(platform, []).append(platform)
            representatives.setdefault(platform, platform)
            inherits[platform] = False
            continue

        # Every field of every entry: the builder reads required, zipped_file,
        # size and crc32 too, so two lists that differ only there are two
        # packs. So is the way the frontend checks a file.
        entries = [
            json.dumps(fe, sort_keys=True, default=str)
            for _sys_id, system in sorted(config.get("systems", {}).items())
            for fe in system.get("files", [])
        ]
        entries.append(
            f"mode={config.get('verification_mode', '')}|rule={config.get('hash_rule', '')}"
        )

        fp = hashlib.sha1("|".join(sorted(entries)).encode()).hexdigest()
        cores = config.get("cores")
        emulators = [
            cores if isinstance(cores, str) else sorted(map(str, cores or [])),
            sorted(map(str, config.get("standalone_cores") or [])),
            sorted(map(str, config.get("dual_mode_cores") or [])),
            sorted(map(str, config.get("installable_cores") or [])),
            # One archive cannot serve a filesystem that folds case and one
            # that does not: Lakka keeps bios.col beside BIOS.col.
            bool(config.get("case_insensitive_fs")),
            # Where each core's files go: the same cores handed other
            # folders make another pack.
            sorted(
                tag for tag in standalone_set(config) if tag.startswith(CORE_DIR_PREFIX)
            ),
        ]
        fp = hashlib.sha1(f"{fp}|{emulators}".encode()).hexdigest()
        if target_cores_cache:
            tc = target_cores_cache.get(platform)
            if tc is not None:
                tc_str = "|".join(sorted(tc))
                fp = hashlib.sha1(f"{fp}|{tc_str}".encode()).hexdigest()
        fingerprints.setdefault(fp, []).append(platform)
        # Prefer the root platform (no inherits) as representative
        if fp not in representatives or (
            not inherits[platform] and inherits.get(representatives[fp], False)
        ):
            representatives[fp] = platform

    result = []
    for fp, group in fingerprints.items():
        rep = representatives[fp]
        ordered = [rep] + [p for p in group if p != rep]
        result.append((ordered, rep))
    return result


_directory_members_cache: dict[int, tuple[dict, dict[str, dict[str, str]]]] = {}


def directory_members(db: dict, directory: str) -> dict[str, str]:
    """Files the collection holds under a directory an emulator reads whole.

    Returns {destination: sha1}, each destination starting with the directory
    as the profile writes it. The collection and the destination meet on a
    tail, so the members are the indexed tails that begin with it.

    A generic directory name can sit in two unrelated trees (``voice/``,
    ``data/``). Members that do not share one parent, or a destination two
    contents claim, would merge them into one emulator's directory: nothing
    is returned and the entry stays a reported gap.
    """
    tail = directory.strip("/")
    if not tail:
        return {}
    by_path_suffix = db.get("indexes", {}).get("by_path_suffix", {})
    cached = _directory_members_cache.get(id(by_path_suffix))
    if cached is None or cached[0] is not by_path_suffix:
        cached = (by_path_suffix, {})
        _directory_members_cache[id(by_path_suffix)] = cached
    if tail in cached[1]:
        return cached[1][tail]

    prefix = f"{tail}/"
    infix = f"/{prefix}"
    held: dict[str, list[str]] = {}
    parent: dict[str, str] = {}
    for key, sha1s in by_path_suffix.items():
        if key.startswith(prefix):
            held[key] = sha1s
            continue
        at = key.find(infix)
        if at > 0:
            member = key[at + 1:]
            if len(key[:at]) > len(parent.get(member, "")):
                parent[member] = key[:at]
    held = {
        dest: sha1s for dest, sha1s in held.items() if "/.variants/" not in dest
    }
    one_tree = len({parent.get(dest, "") for dest in held}) <= 1
    one_content = all(len(sha1s) == 1 for sha1s in held.values())
    members = (
        {dest: held[dest][0] for dest in sorted(held)}
        if one_tree and one_content
        else {}
    )
    cached[1][tail] = members
    return members


def expand_directory_entries(
    files: list[dict], db: dict, standalone: bool = False
) -> list[dict]:
    """Replace each ``type: directory`` entry by the files held under it.

    A profile declares the directory its code walks, but what a pack can carry
    is the files. Each member keeps the entry's fields and is pinned to the
    content the collection holds at that destination. A directory nothing
    answers is kept as declared, one gap, and a member the profile also
    names as a file is left to that entry.
    """
    def destination(entry: dict) -> str:
        chosen = entry.get("standalone_path") if standalone else None
        return chosen or entry.get("path") or entry.get("name", "")

    if not any(entry.get("type") == "directory" for entry in files):
        return files
    named = {
        destination(entry) for entry in files if entry.get("type") != "directory"
    }
    expanded: list[dict] = []
    for entry in files:
        if entry.get("type") != "directory":
            expanded.append(entry)
            continue
        members = directory_members(db, destination(entry))
        if not members:
            expanded.append(entry)
            continue
        inherited = {
            key: value
            for key, value in entry.items()
            if key not in ("type", "standalone_path")
        }
        expanded.extend(
            {**inherited, "name": dest, "path": dest, "sha1": sha1}
            for dest, sha1 in members.items()
            if dest not in named
        )
    return expanded


def runs_standalone(
    emu_name: str, profile: dict, standalone_cores: set[str]
) -> bool:
    """Whether a platform lays this emulator's files out for its standalone build.

    A platform names the emulators it launches standalone in
    ``standalone_cores``, by profile key or by any name in ``cores:``. The
    name alone is not enough: Recalbox and Batocera call their standalone
    ScummVM ``scummvm``, which is also the key of the libretro core's
    profile, and that profile documents no standalone build. Laid out
    "standalone" it would lose every ``path:`` and drop its files at the
    root, so a profile whose ``type`` has no standalone build keeps its
    libretro layout whatever the platform calls it.
    """
    if not standalone_cores:
        return False
    if "standalone" not in str(profile.get("type", "")):
        return False
    names = {emu_name, *(str(c) for c in profile.get("cores", []))}
    # A name a build the platform compiles itself answers to means that
    # build there: RetroBat's standalone amiberry is 8.3.0, and the 8.5.0
    # profile, run there as the buildbot core, keeps its libretro layout.
    owners: dict[str, set[str]] = {}
    for tag in standalone_cores:
        if tag.startswith(OWN_BUILD_PREFIX):
            name, owner, source = json.loads(tag[len(OWN_BUILD_PREFIX):])
            if source == profile.get("source"):
                owners.setdefault(name, set()).add(owner)
    if any(emu_name not in owners[n] for n in names & owners.keys()):
        return False
    return emu_name in standalone_cores or bool(standalone_cores & names)


# Marks, in a platform's standalone set, an emulator it also launches as a
# libretro core. No core name starts with it.
DUAL_MODE_PREFIX = "dual:"
# Marks, in the same set, a whole directory the platform's launcher hands a
# standalone emulator (launchers.handed_directories), as JSON.
HANDED_PREFIX = "handed:"
# Marks, in the same set, a libretro core and the system directory the
# platform hands it (``core_system_dirs``), as JSON.
CORE_DIR_PREFIX = "coredir:"
# Marks, in the same set, a file the platform's launcher executes
# (launchers.executed_files), as JSON.
EXECUTED_PREFIX = "exec:"
# Marks, in the same set, a standalone name a build the platform compiles
# itself (built_by) answers to, as JSON [name, profile, source].
OWN_BUILD_PREFIX = "ownbuild:"
# Marks, in the same set, a file name the platform declares under one of the
# systems a launcher record is written for, as JSON [system, name]: it says
# which launch reads a profile entry of that name.
SYSTEM_FILE_PREFIX = "sysfile:"
# The key, in that index, of a machine a launcher record offers.
MACHINE_KEY = "machine:"


def core_system_dirs(
    emu_name: str, profile: dict, standalone_cores: Iterable[str]
) -> list[str] | None:
    """The system directories a platform hands this libretro core, or None.

    None when the platform declares no per-core directory: the core reads
    the one system directory every core shares. A platform that declares
    them (MinUI hands each launch tag its own Bios/<TAG>/) gives a core it
    lists no directory at all, so the list is then empty.
    """
    pairs = [
        json.loads(tag[len(CORE_DIR_PREFIX):])
        for tag in standalone_cores if tag.startswith(CORE_DIR_PREFIX)
    ]
    if not pairs:
        return None
    names = {emu_name, *(str(c) for c in profile.get("cores") or [])}
    return sorted({directory for core, directory in pairs if core in names})


def system_dir_view(profile: dict, directory: str) -> dict:
    """The profile as a core reads it from one handed system directory.

    Each file keeps its own path, relative to the system directory, and
    carries the directory: destinations put it in front, resolution takes
    it off again (resolve_local_file), so the collection is still searched
    by the core's own path. A core's archive subfolder moves with it.
    """
    view = {
        **profile,
        "files": [
            {**f, "system_dir": directory} if isinstance(f, dict) else f
            for f in profile.get("files") or []
        ],
    }
    if profile.get("archive_prefix"):
        view["archive_prefix"] = f"{directory}/{profile['archive_prefix']}"
    return view


def system_dir_path(entry: dict, path: str) -> str:
    """``path`` below the system directory the entry carries, if any."""
    directory = entry.get("system_dir")
    return f"{directory}/{path}" if directory else path


def own_build_tags(config: dict, standalone: set[str]) -> set[str]:
    """The standalone names the platform's own builds answer to, tagged.

    Read from the profiles of this repository, the ones every pack, manifest
    and report is built from.
    """
    platform = str(config.get("_key") or "")
    if not platform or not standalone:
        return set()
    profiles = load_emulator_profiles(str(Path(__file__).resolve().parent.parent / "emulators"))
    return {
        OWN_BUILD_PREFIX + json.dumps([n, key, p.get("source")])
        for key, p in profiles.items()
        if platform in (p.get("built_by") or []) and "standalone" in str(p.get("type", ""))
        for n in {key, *(str(c) for c in p.get("cores") or [])} & standalone
    }


def standalone_set(config: dict) -> set[str]:
    """The emulators a platform launches standalone, with its dual-mode ones.

    ``dual_mode_cores`` names those it offers both ways (Batocera lists
    libretro:dolphin and standalone dolphin for GameCube). They travel in the
    same set, tagged, so every reader of standalone_cores sees them.
    """
    names = {str(c) for c in config.get("standalone_cores") or []}
    names |= {DUAL_MODE_PREFIX + str(c) for c in config.get("dual_mode_cores") or []}
    # A buildbot core the platform's RetroArch installs under the name of an
    # emulator it runs standalone is that emulator's libretro build: run
    # both ways, as Batocera runs amiberry standalone and can fetch
    # amiberry_libretro.
    names |= {
        DUAL_MODE_PREFIX + str(c)
        for c in set(map(str, config.get("installable_cores") or []))
        & set(map(str, config.get("standalone_cores") or []))
    }
    names |= own_build_tags(config, names)
    # The system directory each core is handed travels the same way, so
    # platform_layouts places a core's files below it for every reader.
    names |= {
        CORE_DIR_PREFIX + json.dumps([str(core), directory])
        for directory, entry in (config.get("core_system_dirs") or {}).items()
        for core in entry.get("cores") or []
    }
    if names - {n for n in names if n.startswith(CORE_DIR_PREFIX)}:
        from launchers import executed_files, handed_directories  # noqa: PLC0415

        handed = handed_directories(config)
        # The record's position travels too: a search list is read in order.
        names |= {
            HANDED_PREFIX + json.dumps(
                [position, h.emulator, h.folder, h.directory, sorted(h.handles), h.source_ref,
                 h.roms_place, sorted(h.systems), h.holds_declared]
            )
            for position, h in enumerate(handed)
        }
        named = {system for h in handed for system in h.systems}
        names |= {
            SYSTEM_FILE_PREFIX + json.dumps([slug, str(f["name"]).lower()])
            for slug, system in (config.get("systems") or {}).items()
            if slug in named
            for f in system.get("files") or []
            if f.get("name")
        }
        # The machines a record offers under its systems, by normalized id.
        from launchers import native_systems  # noqa: PLC0415

        natives = native_systems(config)
        names |= {
            SYSTEM_FILE_PREFIX + json.dumps(
                [natives.get(str(native), str(native)), MACHINE_KEY + _norm_system_id(str(m))]
            )
            for record in config.get("launchers") or []
            for native in record.get("systems") or []
            for m in record.get("machines") or []
        }
        names |= {
            EXECUTED_PREFIX + json.dumps([run.emulator, run.name, run.place, run.source_ref])
            for run in executed_files(config)
        }
    return names


def merged_standalone_set(configs: Iterable[dict]) -> set[str]:
    """The standalone set of several platforms read as one tree.

    A per-core directory marker says which cores one platform hands a folder
    and that it hands the others none. Carried into the union, MinUI's 86
    markers left every core they do not list without a layout: the global
    gap report lost 238 profiles and 1201 files without a word.
    """
    return {
        tag
        for config in configs
        for tag in standalone_set(config)
        if not tag.startswith(CORE_DIR_PREFIX)
    }


def _handed(standalone_cores: Iterable[str]) -> list:
    """The directories a standalone set carries, as launchers built them."""
    from launchers import HandedDirectory  # noqa: PLC0415

    found = []
    for tag in standalone_cores:
        if not tag.startswith(HANDED_PREFIX):
            continue
        position, emulator, folder, directory, handles, ref, roms, systems, held = json.loads(
            tag[len(HANDED_PREFIX):]
        )
        found.append(((position, tag), HandedDirectory(
            emulator, folder, directory, frozenset(handles), ref,
            tuple(roms) if roms else None, frozenset(systems), held,
        )))
    return [h for _key, h in sorted(found, key=lambda pair: pair[0])]


def system_file_index(standalone_cores: Iterable[str]) -> dict[str, set[str]]:
    """File name, lower case -> the platform systems declaring it (SYSTEM_FILE_PREFIX)."""
    index: dict[str, set[str]] = {}
    for tag in standalone_cores:
        if tag.startswith(SYSTEM_FILE_PREFIX):
            slug, name = json.loads(tag[len(SYSTEM_FILE_PREFIX):])
            index.setdefault(name, set()).add(slug)
    return index


def entry_launch_systems(entry: dict, index: Mapping[str, set[str]]) -> frozenset[str]:
    """The platform systems, by our ids, that launch the emulator for an entry.

    The systems the entry names, and those under which the platform declares
    a file of one of its names (``index``, system_file_index): Recalbox lists
    XRoar's coco3.rom under trs80coco, which our coco is.
    """
    systems = {str(s) for s in entry.get("systems") or []}
    if entry.get("system"):
        systems.add(str(entry["system"]))
    for name in [entry.get("name"), *(entry.get("aliases") or [])]:
        if name:
            systems |= index.get(str(name).lower(), set())
    return frozenset(systems)


def _executed(standalone_cores: Iterable[str]) -> list:
    """The files a standalone set's launchers execute, as launchers read them."""
    from launchers import ExecutedFile  # noqa: PLC0415

    found = []
    for tag in standalone_cores:
        if tag.startswith(EXECUTED_PREFIX):
            emulator, name, place, ref = json.loads(tag[len(EXECUTED_PREFIX):])
            found.append(ExecutedFile(emulator, name, tuple(place) if place else None, ref))
    return found


# Why a standalone entry has no destination on a platform that relocates its
# layout: the manifest's omission reason, named as the installer words it.
OUTSIDE_BIOS_FOLDER = "outside_bios_folder"
# The entry root of a file read below the platform's roms directory, and of
# one read in an emulator's folder outside the BIOS tree that the registry
# describes. Each is located by the registry entry <root>_directory.
ROMS_ROOT = "roms"
EMULATORS_ROOT = "emulators"
CONFIGS_ROOT = "configs"
OUTER_ROOTS = (ROMS_ROOT, EMULATORS_ROOT, CONFIGS_ROOT)


def outer_layout(config: dict, root: str) -> dict | None:
    """Where a platform keeps the folder an outer root names, or None.

    roms: the roms root its rom folders file records (``path``, the OS's
    spelling, and ``from_bios``, relative to the BIOS folder), with the
    BIOS folder's own name, base_destination, that a run's folder must
    carry before ``from_bios`` is followed from it. emulators: the
    registry's ``emulators_directory``, the folders a launcher searches
    for an emulator by key, which no rom folders file describes.
    """
    if root == ROMS_ROOT:
        found = config.get("_roms_root") or {}
        base = str(config.get("base_destination") or "")
        path, relation = found.get("path"), found.get("from_bios")
        if not (path and relation) or "<" in str(path):
            return None
        if base:
            return {"path": str(path), "from_bios": str(relation), "bios_folder": base}
        # A list whose dests start above the BIOS folder (AmberELEC's
        # bios/...) installs into the folder holding it: a roms root there
        # or below is part of the install tree, written as a plain dest.
        declared = declared_root(config)
        if not declared:
            return None
        inside = os.path.normpath(f"{declared}/{relation}")
        if inside == ".." or inside.startswith("../"):
            return None
        return {"path": str(path), "install_prefix": "" if inside == "." else inside}
    if root == EMULATORS_ROOT:
        return config.get("emulators_directory") or None
    if root == CONFIGS_ROOT:
        # The frontend's configs folder, as its path code builds it
        # (configs_root, Batocera's batoceraPaths CONFIGS).
        found = config.get("configs_root") or {}
        base = str(config.get("base_destination") or "")
        if not (found.get("path") and found.get("from_bios") and base):
            return None
        return {"path": str(found["path"]), "from_bios": str(found["from_bios"]),
                "bios_folder": base}
    return None


def standalone_layout_path(entry: dict, profile: dict) -> str | None:
    """The path of an entry relative to the directories its standalone build declares.

    ``standalone_path`` when the entry has one. A profile with no libretro
    build has one layout, so its ``path`` is that layout: UAE4All2 reads
    kickstarts/kick13.rom below its working directory.
    """
    own = entry.get("standalone_path")
    if own:
        return own
    if "libretro" in str(profile.get("type", "")):
        return None
    return entry.get("path") or None


def standalone_destination(
    entry: dict, profile: dict, bindings: dict[str, tuple[str, str]]
) -> tuple[str, str] | None:
    """Where a platform puts a standalone entry: (tree, path).

    ``bindings`` are the places the platform's launchers give the layout
    (launchers.standalone_bindings): RetroPie and ROCKNIX give Flycast bios/dc,
    EmuDeck bios/flycast/bios, RetroPie gives UAE4All2's kickstarts/ bios/amiga,
    ROCKNIX runs PICO-8 from roms/pico-8. The tree is launchers.BIOS_TREE or
    launchers.ROMS_TREE. None when no binding covers the entry.
    """
    layout = standalone_layout_path(entry, profile)
    if layout is None or not bindings:
        return None
    from launchers import bound_path  # noqa: PLC0415

    return bound_path(layout, bindings)


def standalone_bindings_for(
    emu_name: str, profile: dict, standalone_cores: Iterable[str],
    systems: Iterable[str] = (),
) -> dict[str, tuple[str, str]]:
    """The places a platform gives this emulator's standalone layout, by subfolder.

    ``systems`` are those the entry is launched for (entry_launch_systems).
    """
    declared = profile.get("standalone_directories") or []
    pools = profile.get("standalone_pools") or {}
    if not declared and not pools:
        return {}
    from launchers import standalone_bindings  # noqa: PLC0415

    names = {emu_name, *(str(c) for c in profile.get("cores") or [])}
    layout = [
        path for f in profile.get("files") or []
        if isinstance(f, dict) and (path := standalone_layout_path(f, profile))
    ]
    return standalone_bindings(
        names, declared, _handed(standalone_cores), _executed(standalone_cores), layout,
        pools, systems,
    )


def platform_layouts(
    emu_name: str, profile: dict, standalone_cores: set[str]
) -> list[tuple[dict, bool]]:
    """The layouts a platform gives an emulator: (profile, standalone?) each.

    One, libretro or standalone, for most. Both for an emulator the platform
    launches either way: laid out standalone only, Batocera's libretro
    Dolphin found dolphin-emu/Sys/GC/ empty. Each layout keeps its own rules
    (what the build reads from the system directory, where it reads it).
    """
    if not runs_standalone(emu_name, profile, standalone_cores):
        directories = core_system_dirs(emu_name, profile, standalone_cores)
        if directories is None:
            return [(profile, False)]
        return [(system_dir_view(profile, d), False) for d in directories]
    standalone = profile
    # Bindings can depend on the system an entry is launched for, so each
    # set of launch systems gets its own.
    by_systems: dict[frozenset[str], dict[str, tuple[str, str]]] = {}
    names = {emu_name, *(str(c) for c in profile.get("cores") or [])}
    per_system = bool(
        profile.get("standalone_directories") or profile.get("standalone_pools")
    ) and any(h.systems and h.emulator in names for h in _handed(standalone_cores))
    index = system_file_index(standalone_cores) if per_system else {}
    # A profile system the platform launches under a system of its own, as
    # its list says for one entry, is launched there for every entry:
    # Recalbox lists mc10.rom under trs80coco, so alice.rom is read there.
    family: dict[str, set[str]] = {}
    for f in (profile.get("files") or []) if per_system else []:
        if isinstance(f, dict):
            own = entry_launch_systems(f, {})
            for system in own:
                family.setdefault(system, set()).update(entry_launch_systems(f, index) - own)

    def bindings_of(entry: dict) -> dict[str, tuple[str, str]]:
        systems = frozenset()
        if per_system:
            own = entry_launch_systems(entry, {})
            systems = entry_launch_systems(entry, index)
            if systems == own:
                systems = systems.union(*(family.get(s, set()) for s in own))
            if systems == own:
                # The platform's list names none of the entry's names: its
                # own system selects the launch that offers it as a machine
                # (RetroBat runs XRoar's coco3 under coco).
                systems = systems.union(*(
                    index.get(MACHINE_KEY + _norm_system_id(s), set()) for s in own
                ))
        if systems not in by_systems:
            by_systems[systems] = standalone_bindings_for(
                emu_name, profile, standalone_cores, systems
            )
        return by_systems[systems]

    layout_entries = [
        f for f in profile.get("files") or []
        if isinstance(f, dict) and standalone_layout_path(f, profile) is not None
    ]
    if any(bindings_of(f) for f in layout_entries):
        # The standalone view carries the platform's destination, so every
        # reader of standalone_path (builder, manifest, verify, slots) places
        # the file in the folder the platform hands the emulator.
        # An entry of the layout no binding covers is read in a folder the
        # platform keeps outside the BIOS tree: UAE4All2's kick.rom in
        # RetroPie's $md_inst. It is marked, never left at the BIOS root
        # where the emulator does not read it.
        files = []
        for f in profile.get("files") or []:
            if not isinstance(f, dict) or standalone_layout_path(f, profile) is None:
                files.append(f)
                continue
            placed = standalone_destination(f, profile, bindings_of(f))
            if placed is None or placed[0] == "outside":
                files.append({**f, "unplaced": OUTSIDE_BIOS_FOLDER})
                continue
            tree, path = placed
            moved = {**f, "standalone_path": path,
                     "layout_path": standalone_layout_path(f, profile)}
            if tree == "install":
                # Below the roms root inside the install tree (AmberELEC's
                # /storage/roms): a plain dest the platform prefix skips.
                files.append({**moved, "unprefixed": True})
                continue
            # A file the launcher runs from the roms directory (ROCKNIX's
            # roms/pico-8) or an emulator folder (RetroBat's emulators/pico8)
            # is relative to it, and says so.
            files.append({**moved, "root": tree} if tree else moved)
        standalone = {**profile, "files": files}
    dual = {c.removeprefix(DUAL_MODE_PREFIX) for c in standalone_cores
            if c.startswith(DUAL_MODE_PREFIX)}
    if "libretro" in str(profile.get("type", "")) and dual & {
        emu_name, *(str(c) for c in profile.get("cores", []))
    }:
        return [(profile, False), (standalone, True)]
    return [(standalone, True)]


# What identifies a profile entry's content, carried unchanged wherever the
# entry travels (cross-reference report, core extras, second-pass copies).
# Each copy once kept its own subset: np2kai's bios.rom lost min_size and
# validation on the way and resolved to an IBM PCjr ROM of the same name.
PROFILE_IDENTITY_FIELDS = (
    "sha1", "md5", "sha256", "crc32", "size", "min_size", "max_size",
    "validation", "aliases", "unsourceable",
)


def upstream_profile_index(
    profiles: dict[str, dict], include_aliases: bool = False
) -> dict[str, set[str]]:
    """Every name a core is known by upstream -> the profiles that claim it.

    A name can be claimed twice: the buildbot's `pcsx2` is the LRPS2 core,
    which lrps2.yml lists in `cores:`, and also the key of the standalone
    pcsx2 profile. A last-wins dict kept one of the two depending on file
    order, and a RetroArch target filter dropped LRPS2's files. Callers
    choose: a platform list prefers the exact key, a target filter keeps
    every claimant.
    """
    index: dict[str, set[str]] = {}
    for name, profile in profiles.items():
        if not include_aliases and profile.get("type") == "alias":
            continue
        index.setdefault(name, set()).add(name)
        for core in profile.get("cores") or []:
            index.setdefault(str(core), set()).add(name)
    return index


def preferred_profile(index: dict[str, set[str]], name: str) -> str | None:
    """The profile a name designates: its own key first, else the first claimant."""
    claimants = index.get(name)
    if not claimants:
        return None
    return name if name in claimants else sorted(claimants)[0]


def without_profile_blind(
    platforms: list[str],
    flags: list[str],
    platforms_dir: str,
    profiles: dict[str, dict],
    target_cores: dict[str, set[str] | None] | None,
    is_all: bool,
) -> list[str]:
    """The platforms a narrowing read from profiles can apply to.

    Regions, search order and game data are read from the profiles of the
    cores a platform runs. MiSTer and BizHawk declare `cores: []`: a
    --region, --one-per-slot or --no-game-data pack of theirs withdrew
    nothing while its name and README said it had. A named platform is
    refused (exit 1). Under --all it is left out with a notice. generate_pack
    and verify both read this.
    """
    if not flags:
        return platforms
    blind = [
        name for name in platforms
        if not resolve_platform_cores(
            load_platform_config(name, platforms_dir),
            profiles,
            target_cores=(target_cores or {}).get(name),
        )
    ]
    for name in blind:
        message = (
            f"{name} runs no core a profile describes, and {', '.join(flags)} "
            "reads the profiles"
        )
        if not is_all:
            print(f"ERROR: {message}: drop {', '.join(flags)}", file=sys.stderr)
            sys.exit(1)
        print(f"  {message}: left out")
    return [name for name in platforms if name not in blind]


def resolve_platform_cores(
    config: dict,
    profiles: dict[str, dict],
    target_cores: set[str] | None = None,
) -> set[str]:
    """Resolve which emulator profiles are relevant for a platform.

    Resolution strategies (by priority):
    1. cores: "all_libretro" -- all profiles with libretro in type
    2. cores: [list] -- profiles whose dict key matches a core name
    3. cores: absent, fallback to systems intersection

    Alias profiles are always excluded (they point to another profile).
    If target_cores is provided, result is intersected with it.
    """
    cores_config = config.get("cores")
    platform_key = str(config.get("_key") or "")
    downloaded_only: dict[str, str] = {}
    # The builds the platform compiles itself, by the names they answer to.
    # Such a name means that build there, and another revision of the same
    # project is not what the platform runs: ROCKNIX and RetroPie build only
    # standalone Amiberry, Recalbox its standalone and libretro Amiberry 8.2.2.
    # Only a platform listing the name both ways (dual_mode_cores) beside a
    # standalone-only build of its own runs the buildbot core too (RetroBat).
    # A core of another project under the name stays: RetroPie builds
    # minivmac37 standalone beside the minivmac core.
    own_builds = {
        name: p for name, p in profiles.items()
        if platform_key and platform_key in (p.get("built_by") or [])
    }

    def replaced_by_own(name: str, p: dict, libretro_only: bool = False) -> bool:
        if platform_key in (p.get("built_by") or []):
            return False
        names = {name, *(str(c) for c in p.get("cores") or [])}
        return any(
            (not libretro_only or "libretro" in str(q.get("type", "")))
            and q.get("source") == p.get("source")
            and names & {key, *(str(c) for c in q.get("cores") or [])}
            for key, q in own_builds.items()
        )

    def every_libretro() -> set[str]:
        # A build only some platforms compile (built_by) is absent from the
        # buildbot RetroArch installs from, so it is reached by name, or as one
        # of the libretro cores of a platform that compiles it: ROCKNIX ships
        # yabadabadoo with its RetroArch and names it nowhere else.
        return {
            name
            for name, p in profiles.items()
            if "libretro" in p.get("type", "") and p.get("type") != "alias"
            and (
                not p.get("built_by")
                or (platform_key and platform_key in p["built_by"])
            )
            and not replaced_by_own(name, p)
        }

    if cores_config == "all_libretro":
        result = every_libretro()
    elif isinstance(cores_config, list):
        # An emulator the platform launches standalone runs there even when
        # its own list names only the cores: Batocera's es_systems.yml files
        # lexaloffle and gsplus as standalone emulators and nowhere else. A
        # core its RetroArch installs from the buildbot is a libretro build
        # and designates libretro profiles only (below): Batocera downloads
        # the linuxloader core and runs no standalone Linux Loader.
        core_set = {str(c) for c in cores_config} | {
            str(c) for c in config.get("standalone_cores") or []
        }
        index = upstream_profile_index(profiles)
        platform = str(config.get("_key") or "")

        def designated(name: str) -> set[str]:
            # A build the platform compiles itself (built_by) is what its
            # name means there: Recalbox's uae4all is Chips-fr/uae4all-rpi,
            # RetroPie's the standalone uae4all2 under the same name. A
            # platform building one name in several revisions, one per board,
            # runs all of them: RetroPie's amiberry is 5.7.2 and 6.3.3 on x86.
            own = {
                p for p in index.get(name, ())
                if platform and platform in (profiles[p].get("built_by") or [])
            }
            if own:
                return own
            preferred = preferred_profile(index, name)
            return {preferred} if preferred is not None else set()

        result = {profile for c in core_set for profile in designated(c)}
        # A name the platform launches both ways designates its libretro
        # build too. Batocera, Recalbox and RetroBat run pcsx2 standalone and
        # as LRPS2, two profiles: the key match kept the standalone one and
        # LRPS2's files never reached their packs. A core its RetroArch
        # installs is a libretro build as well (amiberry's buildbot core
        # beside Batocera's standalone amiberry).
        def libretro_builds(name: object) -> set[str]:
            return {
                profile
                for profile in index.get(str(name), set())
                if "libretro" in str(profiles[profile].get("type", ""))
                and not profiles[profile].get("built_by")
                and not replaced_by_own(profile, profiles[profile], libretro_only=True)
            }

        dual = {p for c in config.get("dual_mode_cores") or [] for p in libretro_builds(c)}
        # A core reached only through the RetroArch downloader runs on the
        # boards whose downloader offers it: Batocera's x86_64 RetroArch
        # installs the amiberry core, its armv7 and aarch64 boards cannot.
        for c in config.get("installable_cores") or []:
            for profile in libretro_builds(c) - dual - result:
                downloaded_only.setdefault(profile, str(c))
        result |= dual | set(downloaded_only)
        # Support "all_libretro" as a list element: combines all libretro
        # profiles with explicitly listed standalone cores (e.g. RetroDECK
        # ships RetroArch + standalone emulators)
        if "all_libretro" in core_set or "retroarch" in core_set:
            result |= every_libretro()
    else:
        # Fallback: system ID intersection with normalization
        norm_plat_systems = {_norm_system_id(s) for s in config.get("systems", {})}
        result = {
            name
            for name, p in profiles.items()
            if {_norm_system_id(s) for s in p.get("systems", [])} & norm_plat_systems
            and p.get("type") != "alias"
            and not p.get("built_by")
        }

    if target_cores is not None:
        result = result & designated_profiles(profiles, target_cores)
        result -= {
            profile for profile, c in downloaded_only.items()
            if not downloadable_on(target_cores, c)
        }
    return result


@functools.lru_cache(maxsize=1)
def _retroarch_target_sets() -> tuple[frozenset[str], ...]:
    platforms = str(Path(__file__).resolve().parent.parent / "platforms")
    return tuple(
        frozenset(found)
        for t in list_available_targets("retroarch", platforms)
        if (found := load_target_config("retroarch", t["name"], platforms))
    )


def downloadable_on(target_cores: set[str], name: str) -> bool:
    """Whether a board's core set holds a RetroArch download list offering `name`.

    A board with a downloader carries a whole RetroArch targets entry in its
    set (load_target_config, `downloads`), a board without one only what it
    builds.
    """
    return any(name in found and found <= target_cores for found in _retroarch_target_sets())


def unresolved_platform_cores(config: dict, profiles: dict[str, dict]) -> set[str]:
    """The core names a platform lists that no profile answers to.

    resolve_platform_cores drops them without a word: ROCKNIX's `dolphin-sa`
    or Batocera's `wine` designate no profile, so nothing is known of the
    files they open. `retroarch` and `all_libretro` stand for every libretro
    profile and are never unresolved. A platform without a `cores:` list
    names no core.
    """
    cores_config = config.get("cores")
    if not isinstance(cores_config, list):
        return set()
    index = upstream_profile_index(profiles)
    return {
        name
        for name in (str(c) for c in cores_config)
        if name not in ("retroarch", "all_libretro") and not index.get(name)
    }


MANUFACTURER_PREFIXES = (
    "acorn-",
    "apple-",
    "microsoft-",
    "nintendo-",
    "sony-",
    "sega-",
    "snk-",
    "panasonic-",
    "nec-",
    "epoch-",
    "mattel-",
    "fairchild-",
    "hartung-",
    "tiger-",
    "magnavox-",
    "philips-",
    "bandai-",
    "casio-",
    "coleco-",
    "commodore-",
    "sharp-",
    "sinclair-",
    "atari-",
    "sammy-",
    "gce-",
    "interton-",
    "texas-instruments-",
    "videoton-",
    "wenquxing-",
    "aquaplus-",
)


def derive_manufacturer(system_id: str, system_data: dict) -> str:
    """Derive manufacturer name for a system.

    Priority: explicit manufacturer field > system ID prefix > 'Other'.
    """
    mfr = system_data.get("manufacturer", "")
    if mfr and mfr not in ("Various", "Other"):
        return mfr.split("|")[0].strip()
    s = system_id.lower().replace("_", "-")
    for prefix in MANUFACTURER_PREFIXES:
        if s.startswith(prefix):
            return prefix.rstrip("-").title()
    return "Other"


# Abbreviations that normalization alone cannot resolve.
# Maps platform-specific short names to canonical profile system IDs.
SYSTEM_ALIASES: dict[str, str] = {
    "gmaster": "hartung-game-master",
    "n64dd": "nintendo-64dd",
    "neogeo64": "hyper-neogeo64",
    "psvita": "sony-playstation-vita",
    # Platform IDs missing the manufacturer-prefix hyphen
    "atari5200": "atari-5200",
    "atari7800": "atari-7800",
    "atarist": "atari-st",
    "sega32x": "sega-32x",
    "segastv": "sega-stv",
    "ti994a": "ti99",
    # Other spellings of one machine: RomM files the Mega CD as sega-mega-cd
    # and the disk system as nintendo-fds, which normalize to the ids the
    # profiles use only through these.
    "sega-segacd": "sega-megacd",
    "nes-fds": "nintendo-fds",
    # One machine, two spellings across platform folders and profiles:
    # Recalbox's apple2gs, Batocera's astrocade, KNULLI and RetroBat's
    # astrocde, MiSTer's creativision, Batocera's gamepocketcomputer
    # folder, BizHawk's Super Game Boy, the FBA 2012 board names.
    "apple2gs": "apple-iigs",
    "astrocade": "bally-astrocade",
    "astrocde": "bally-astrocade",
    "creativision": "crvision",
    "gamepocketcomputer": "gamepock",
    "nintendo-super-game-boy": "nintendo-sgb",
    "cps1": "capcom-cps1",
    "cps2": "capcom-cps2",
    "cps3": "capcom-cps3",
    "pgm": "igs-pgm",
    # Rom folder names the setups of platforms/romfolders/ give a machine,
    # each proven by the source_ref of the folder row that names it: the
    # short tags of Onion, CrossMix-OS, Koriki and the MinUI family, the
    # number words of Koriki and plumOS, the region and hack folders of
    # ES-DE, the MSU-1 folders of the ES family, the arcade cores named as
    # folders.
    "a2600": "atari-2600",
    "atari2600": "atari-2600",
    "fiftytwohundred": "atari-5200",
    "seventyeighthundred": "atari-7800",
    "atarixegs": "xegs",
    "atarijaguarcd": "atari-jaguarcd",
    "fc": "nintendo-nes",
    "nesh": "nintendo-nes",
    "sfc": "nintendo-snes",
    "supa": "nintendo-snes",
    "snesh": "nintendo-snes",
    "snesna": "nintendo-snes",
    "snesmsu1": "nintendo-snes",
    "snes-msu1": "nintendo-snes",
    "msu1": "nintendo-snes",
    "vb": "nintendo-virtualboy",
    "gc": "nintendo-gamecube",
    "gbh": "nintendo-gb",
    "gb2players": "nintendo-gb",
    "gbch": "nintendo-gbc",
    "gbc2players": "nintendo-gbc",
    "gbah": "nintendo-gba",
    "mgba": "nintendo-gba",
    "poke": "nintendo-pokemon-mini",
    "pkm": "nintendo-pokemon-mini",
    "md": "sega-megadrive",
    "genh": "sega-megadrive",
    "megadriveh": "sega-megadrive",
    "megadrivejp": "sega-megadrive",
    "megadrive-japan": "sega-megadrive",
    "msumd": "sega-megadrive",
    "mdmsu": "sega-megadrive",
    "ms": "sega-mastersystem",
    "mark3": "sega-mastersystem",
    "gamegearh": "sega-gamegear",
    "megacdjp": "sega-megacd",
    "saturnjp": "sega-saturn",
    "sega32xjp": "sega-32x",
    "sega32xna": "sega-32x",
    "thirtytwox": "sega-32x",
    "segasgone": "sega-sg1000",
    "ps": "sony-playstation",
    "pce": "nec-pc-engine",
    "tg16cd": "nec-pc-engine-cd",
    "tg-cd": "nec-pc-engine-cd",
    "turbografxcd": "nec-pc-engine-cd",
    "neocd": "snk-neogeo-cd",
    "ngcd": "snk-neogeo-cd",
    "neogeocdjp": "snk-neogeo-cd",
    "supervision": "watara-supervision",
    "cplus4": "commodore-plus4",
    "cpet": "commodore-pet",
    "cpc": "amstrad-cpc",
    "to8": "thomson-to8",
    "tic": "tic80",
    "fba": "arcade",
    "hbmame": "arcade",
    "advmame": "arcade",
    "mame-advmame": "arcade",
    "mame2000": "arcade",
    "mame2003": "arcade",
    "mame2003plus": "arcade",
    "mame2010": "arcade",
    "mame-libretro": "arcade",
    "mame-mame4all": "arcade",
    "c20": "commodore-vic20",
    "segamodel3": "sega-model3",
    "pspminis": "sony-psp",
    "ndsiware": "nintendo-dsi",
    "wiiware": "nintendo-wii",
    "x16": "commanderx16",
    "zxnext": "sinclair-zx-spectrum-next",
    "vemulator": "sega-vmu",
    "ep64-128": "enterprise-64-128",
    "easyrpg": "rpgmaker",
    "ggh": "sega-gamegear",
    "gba2players": "nintendo-gba",
    "snesmsu": "nintendo-snes",
    "megadrivemsu": "sega-megadrive",
    "sgb-msu1": "nintendo-sgb",
}


@functools.lru_cache(maxsize=None)
def _norm_system_id(sid: str) -> str:
    """Normalize system ID for cross-platform matching.

    Resolves known aliases, then strips manufacturer prefixes and separators
    so that platform-specific IDs (e.g., "xbox", "nintendo-wiiu") match
    profile IDs (e.g., "microsoft-xbox", "nintendo-wii-u").

    A function of the string and two constant tables: a manifest run asks it
    1.7 million times for about 1,100 ids.
    """
    s = sid.lower().replace("_", "-")
    s = SYSTEM_ALIASES.get(s, s)
    for prefix in MANUFACTURER_PREFIXES:
        if s.startswith(prefix):
            s = s[len(prefix) :]
            break
    return s.replace("-", "")


def _name_key(name: str) -> str:
    """Letters and digits only, as the installer compares names."""
    return re.sub(r"[^a-z0-9]", "", name.lower())


def platform_system_names(config: dict, systems: list[str]) -> dict[str, list[str]]:
    """Per platform system, the names the platform's own file gives it.

    A Batocera user knows PlayStation as `psx`, the folder under roms/, and
    the platform YAML records that name as `native_system` on each file it
    transcribes. Only the platform's own entries count (`native_layer`), a
    name spelled like the system id adds nothing, and a name the platform
    gives to two systems, or that reads as another system's id, names
    neither. The install manifest's `system_names` and the `--system` of
    generate_pack and verify read this one mapping.
    """
    native = native_layer(config) or {}
    by_name: dict[str, set[str]] = {}
    for sys_id, system in native.get("systems", {}).items():
        if sys_id not in systems:
            continue
        for entry in system.get("files", []):
            name = entry.get("native_system")
            if isinstance(name, str) and name.strip():
                by_name.setdefault(name.strip(), set()).add(sys_id)
    ids = {_name_key(sys_id) for sys_id in systems}
    out: dict[str, list[str]] = {}
    for name, owners in by_name.items():
        if len(owners) != 1 or _name_key(name) in ids:
            continue
        out.setdefault(next(iter(owners)), []).append(name)
    return {sys_id: sorted(names) for sys_id, names in sorted(out.items())}


def select_systems(systems: dict, wanted: list[str]) -> dict:
    """The systems a --system list keeps, by id or normalized id."""
    norm = {_norm_system_id(s) for s in wanted}
    return {
        sid: data for sid, data in systems.items()
        if sid in wanted or _norm_system_id(sid) in norm
    }


def resolve_system_arg(
    value: str,
    systems: list[str],
    config: dict | None = None,
    listing: str = "--list-systems",
) -> list[str]:
    """The system ids a --system value names, or ValueError naming the rest.

    With a platform config, the platform's own names count as well (Batocera's
    `psx` is sony-playstation), the same mapping the install manifest carries
    as `system_names`. Without one, only our ids do. A whole value that is a
    name wins over splitting it on commas: Recalbox names one system
    `msx1,msx2`. An id wins over another system's native name, and a name
    nothing else matches falls back to the normalized id (`playstation`).
    An unknown name is refused, never ignored.
    """
    names = platform_system_names(config, systems) if config else {}
    exact: dict[str, list[str]] = {}
    by_key: dict[str, list[str]] = {}
    for sid in systems:
        exact.setdefault(sid.lower(), [sid])
        by_key.setdefault(_name_key(sid), []).append(sid)
    for sid, aliases in names.items():
        for alias in aliases:
            exact.setdefault(alias.lower(), [sid])
            if _name_key(alias) not in by_key:
                by_key[_name_key(alias)] = [sid]
    by_norm: dict[str, list[str]] = {}
    for sid in systems:
        by_norm.setdefault(_norm_system_id(sid), []).append(sid)

    value = value.strip()
    tokens = [value] if value.lower() in exact else value.split(",")
    chosen: list[str] = []
    unknown: list[str] = []
    for token in (t.strip() for t in tokens):
        if not token:
            continue
        keyed = by_key.get(_name_key(token), [])
        found = (
            exact.get(token.lower())
            or (keyed if len(keyed) == 1 else None)
            or by_norm.get(_norm_system_id(token))
        )
        if not found:
            unknown.append(token)
            continue
        chosen += [sid for sid in found if sid not in chosen]
    if unknown:
        known = sorted({*systems, *(a for v in names.values() for a in v)})
        hint = suggest_names(unknown, known, listing, listed=len(systems))
        raise ValueError(f"unknown system {', '.join(unknown)}. {hint}")
    if not chosen:
        raise ValueError("--system names no system")
    return chosen


def designated_profiles(profiles: dict[str, dict], names: set[str]) -> set[str]:
    """The profiles a list of upstream core names designates.

    The buildbot and es_systems name cores their own way (`mednafen_psx` for
    beetle_psx), and a profile's `cores:` lists those names. A name no profile
    claims stands for itself.
    """
    index = upstream_profile_index(profiles, include_aliases=True)
    return {profile for c in names for profile in index.get(c, {c})}


def system_core_reach(
    systems: dict[str, dict],
    profiles: dict[str, dict],
    platform_cores: set[str] | None,
) -> dict[str, set[str] | None]:
    """For each platform system, the cores whose presence keeps it.

    A system is reachable if at least one core that emulates it is available.
    Only cores relevant to the platform (platform_cores) can rule a system
    out: a system whose cores are all outside the platform's scope maps to
    None, kept whatever is available, there being no information to exclude
    it.
    """
    _norm_sid = _norm_system_id

    # Normalized system -> cores, from ALL profiles
    norm_system_cores: dict[str, set[str]] = {}
    for name, p in profiles.items():
        if p.get("type") == "alias":
            continue
        for sid in p.get("systems", []):
            norm_system_cores.setdefault(_norm_sid(sid), set()).add(name)

    # Platform-scoped mapping (for distinguishing "no info" from "known but off-target")
    norm_plat_system_cores: dict[str, set[str]] = {}
    if platform_cores is not None:
        for name in platform_cores:
            p = profiles.get(name, {})
            for sid in p.get("systems", []):
                norm_plat_system_cores.setdefault(_norm_sid(sid), set()).add(name)

    # A platform can file a system under an id no profile uses: Batocera's
    # enterprise-64-128 is ep128emu's enterprise-64 and enterprise-128, and
    # only CLK, off most targets, carries the joined id. The destinations a
    # system declares name the cores that read its files. A bare name proves
    # nothing (bios.bin belongs to many systems), so only a path counts.
    # The evidence only keeps: a path shared with an off-target core says
    # nothing of the other files, and Batocera's bbc runs on MAME, which no
    # profile ties to bbcb.zip, while CLK reads two of its ROMs.
    dest_cores: dict[str, set[str]] = {}
    for name, p in profiles.items():
        if p.get("type") == "alias":
            continue
        for f in p.get("files", []):
            for key in ("path", "standalone_path"):
                dest = f.get(key)
                if not isinstance(dest, str):
                    continue
                if dest.endswith("/"):
                    dest += f.get("name", "")
                dest = sanitize_pack_path(dest).lower()
                if "/" in dest:
                    dest_cores.setdefault(dest, set()).add(name)

    reach: dict[str, set[str] | None] = {}
    for sys_id, sys_data in systems.items():
        norm_key = _norm_sid(sys_id)
        if not norm_plat_system_cores.get(norm_key):
            reach[sys_id] = None
            continue
        file_cores = {
            core
            for fe in sys_data.get("files", [])
            for core in dest_cores.get(
                sanitize_pack_path(fe.get("destination") or fe.get("name", "")).lower(),
                (),
            )
        }
        reach[sys_id] = file_cores | norm_system_cores.get(norm_key, set())
    return reach


def filter_systems_by_target(
    systems: dict[str, dict],
    profiles: dict[str, dict],
    target_cores: set[str] | None,
    platform_cores: set[str] | None = None,
) -> dict[str, dict]:
    """Filter platform systems to only those reachable by target cores.

    Returns the filtered systems dict (or all if no target).
    """
    if target_cores is None:
        return systems
    available = designated_profiles(profiles, target_cores)
    reach = system_core_reach(systems, profiles, platform_cores)
    return {
        sys_id: sys_data
        for sys_id, sys_data in systems.items()
        if reach[sys_id] is None or reach[sys_id] & available
    }


def platform_scope_systems(
    config: dict,
    profiles: dict[str, dict],
    target_cores: set[str] | None,
    system_filter: list[str] | None = None,
) -> dict[str, dict]:
    """The systems a pack or a report of a platform covers.

    Those a core of the target runs, then the ones a --system list keeps.
    verify.py and generate_pack.py read this one function.
    """
    plat_cores = resolve_platform_cores(config, profiles) if target_cores else None
    systems = filter_systems_by_target(
        config.get("systems", {}), profiles, target_cores, platform_cores=plat_cores
    )
    return select_systems(systems, system_filter) if system_filter else systems


def system_scope_error(
    config: dict, platform_name: str, system_filter: list[str], target: str | None
) -> str:
    """Why a --system list leaves a platform no system.

    A system the platform declares but no core of the target runs was
    reported as a system the platform lacks, with a lookalike to try and a
    listing that refuses --target.
    """
    systems = config.get("systems", {})
    declared = select_systems(systems, system_filter)
    if declared and target:
        return (
            f"no core {platform_name} runs on target {target} emulates "
            f"{', '.join(sorted(declared))}"
        )
    hint = suggest_names(
        system_filter, sorted(systems), f"--platform {platform_name} --list-systems"
    )
    return f"{platform_name} has no system matching {', '.join(system_filter)}. {hint}"


def platform_declarations(
    config: dict, db: dict, *, enrich: bool = True
) -> dict[str, list[tuple[int | None, str]]]:
    """Every file name a platform declares, with each declaration's size and slot.

    A name alone does not say which file a declaration is: RetroArch declares
    galaksija/ROM1.BIN, a 4 KiB ROM, and DOSBox reads a 32 KiB SC-55 ROM1.BIN.
    The size, from the platform entry or else from the file its hash names,
    tells a declaration of the same file from a same-named one. None stands
    for a size nobody knows. The slot is the declared destination, sanitized
    and case-folded, relative to the directory core files go to: RetroDECK
    writes bios/ in front of every destination, the others put it in
    base_destination.

    With ``enrich``, a declaration also answers for the canonical name and
    the aliases the database knows its MD5 under. This handles a platform
    declaring a file under a different name than the emulator profile
    (e.g. Batocera ROM1 vs gsplus ROM).
    """
    prefix = declared_root(config).lower()
    declared: dict[str, list[tuple[int | None, str]]] = {}
    by_md5 = db.get("indexes", {}).get("by_md5", {})
    files_db = db.get("files", {})
    for system in config.get("systems", {}).values():
        for fe in system.get("files", []):
            name = fe.get("name", "")
            slot = sanitize_pack_path(fe.get("destination") or name).lower()
            if prefix and slot.startswith(prefix + "/"):
                slot = slot[len(prefix) + 1:]
            # A zipped_file entry pins a member of the archive it names: its
            # md5 and its size, when stated, are not the archive's.
            by_hash: dict = {}
            size = None
            if not fe.get("zipped_file"):
                md5 = (fe.get("md5") or "").lower()
                if md5 and "," not in md5:
                    by_hash = files_db.get(by_md5.get(md5, ""), {})
                size = fe.get("size")
                if size is None:
                    size = files_db.get(
                        (fe.get("sha1") or "").lower(), by_hash
                    ).get("size")
            if name:
                declared.setdefault(name, []).append((size, slot))
            if not enrich:
                continue
            for other in (by_hash.get("name", ""), *by_hash.get("aliases", [])):
                if other:
                    declared.setdefault(other, []).append((by_hash.get("size"), slot))
    return declared


def declared_root(config: dict) -> str:
    """The BIOS directory a platform writes into every destination, if any.

    Only a platform whose base_destination is explicitly empty does that
    (RetroDECK writes bios/ in front of each file), and core files go under
    the same directory. A config that does not state a base says nothing,
    and its common folder is a system's, not the BIOS root. A platform whose
    list also names folders beside the BIOS one states it as
    core_destination: EmuELEC's ports/ entries are a quarter of its list.
    """
    if config.get("base_destination", None) != "":
        return ""
    if config.get("core_destination"):
        return str(config["core_destination"])
    roots = [
        d.split("/", 1)[0]
        for system in config.get("systems", {}).values()
        for f in system.get("files", [])
        if "/" in (d := f.get("destination", "") or "")
    ]
    if not roots:
        return ""
    root, count = Counter(roots).most_common(1)[0]
    return root if count / len(roots) > 0.9 else ""


def platform_declared_contents(config: dict, db: dict) -> dict[str, set[str]]:
    """The folders each declared file's content sits in, keyed by its hashes.

    A core that scans a folder and identifies a ROM by its checksum reads a
    declared file whatever its name: RetroDECK lists atari800's Atari BASIC
    Rev A as ROM_BASIC_A, and the core takes it by CRC32. Keys are
    "md5:", "sha1:" and "crc32:" values of the database file the
    declaration resolves to, each with the declared slot's folder.
    """
    prefix = declared_root(config).lower()
    by_md5 = db.get("indexes", {}).get("by_md5", {})
    files_db = db.get("files", {})
    contents: dict[str, set[str]] = {}
    for system in config.get("systems", {}).values():
        for fe in system.get("files", []):
            if fe.get("zipped_file"):
                continue
            record = files_db.get((fe.get("sha1") or "").lower())
            md5 = (fe.get("md5") or "").lower()
            if record is None and md5 and "," not in md5:
                sha1 = by_md5.get(md5, "")
                record = files_db.get(sha1[0] if isinstance(sha1, list) else sha1)
            if not record:
                continue
            slot = sanitize_pack_path(fe.get("destination") or fe.get("name", "")).lower()
            if prefix and slot.startswith(prefix + "/"):
                slot = slot[len(prefix) + 1:]
            folder = slot.rpartition("/")[0]
            for field in ("md5", "sha1", "crc32"):
                value = str(record.get(field) or "").lower()
                if value:
                    contents.setdefault(f"{field}:{value}", set()).add(folder)
    return contents


def merged_platform_declared_contents(configs: list[dict], db: dict) -> dict[str, set[str]]:
    """`platform_declared_contents` of several platforms, one index."""
    merged: dict[str, set[str]] = {}
    for config in configs:
        for key, folders in platform_declared_contents(config, db).items():
            merged.setdefault(key, set()).update(folders)
    return merged


def merged_platform_declarations(
    configs: list[dict], db: dict
) -> dict[str, list[tuple[int | None, str]]]:
    """`platform_declarations` of several platforms, one index."""
    merged: dict[str, list[tuple[int | None, str]]] = {}
    for config in configs:
        for name, places in platform_declarations(config, db).items():
            merged.setdefault(name, []).extend(places)
    return merged


def expand_platform_declared_names(config: dict, db: dict) -> set[str]:
    """The names a platform declares, enriched as `platform_declarations`."""
    return set(platform_declarations(config, db))


import re




# Validation and mode filtering: extracted to validation.py for SoC.
# Re-exported below for backward compatibility.



def sanitize_pack_path(raw: str) -> str:
    """Strip traversal components from a relative destination.

    The builder and the coverage report key their region grouping on this
    value, so they have to derive it the same way: a destination normalized on
    one side only would be looked up under a key the other side never emits.
    """
    raw = raw.replace("\\", "/")
    return "/".join(p for p in raw.split("/") if p and p not in ("..", "."))




def list_emulator_profiles(emulators_dir: str, skip_aliases: bool = True) -> None:
    """Print available emulator profiles."""
    profiles = load_emulator_profiles(emulators_dir, skip_aliases=False)
    for name in sorted(profiles):
        p = profiles[name]
        if p.get("type") == "alias" or p.get("role") == "test":
            continue
        display = p.get("emulator", name)
        ptype = p.get("type", "libretro")
        systems = ", ".join(p.get("systems", [])[:3])
        more = "..." if len(p.get("systems", [])) > 3 else ""
        # The type is padded to its longest value, so the systems start in
        # one column whatever the type reads.
        kind = f"[{ptype}]"
        print(f"  {name:30s} {display:40s} {kind:24s}{systems}{more}".rstrip())


def system_index(profiles: dict) -> dict[str, tuple[str, set[str]]]:
    """Normalized system id -> (the first spelling met, the emulators).

    One system per normalized id, as --system selects: counted per spelling,
    nes and nintendo-nes were two systems and the README announced 550
    where --list-systems printed 513.
    """
    index: dict[str, tuple[str, set[str]]] = {}
    for name, p in sorted(profiles.items()):
        if p.get("type") in ("alias", "launcher") or p.get("role") == "test":
            continue
        for sys_id in p.get("systems", []):
            key = _norm_system_id(sys_id)
            index.setdefault(key, (sys_id, set()))[1].add(name)
    return index


def list_system_ids(emulators_dir: str) -> None:
    """Print available system IDs with emulator count."""
    index = system_index(load_emulator_profiles(emulators_dir))
    for _key, (spelling, emulators) in sorted(index.items(), key=lambda kv: kv[1][0]):
        count = len(emulators)
        print(f"  {spelling:35s} ({count} emulator{'s' if count > 1 else ''})")


def print_platform_listing(platforms_dir: str) -> None:
    """Every registered platform, one per line, marked when the installer
    alone serves it.

    Every platform takes --platform. --all covers every one, and the pack
    builder's --all the release packs. Printed by --list-platforms in
    verify.py and generate_pack.py, the name install.py gives it.
    """
    released = set(list_release_pack_platforms(platforms_dir))
    for name in list_registered_platforms(platforms_dir):
        print(name if name in released else f"{name} (installer only)")


def list_platform_system_ids(platform_name: str, platforms_dir: str) -> None:
    """Print system IDs from a platform's YAML config, with the platform's
    own names for them, which --system also accepts."""
    config = load_platform_config(platform_name, platforms_dir)
    systems = config.get("systems", {})
    names = platform_system_names(config, list(systems))
    for sys_id in sorted(systems):
        file_count = len(systems[sys_id].get("files", []))
        mfr = systems[sys_id].get("manufacturer", "")
        mfr_display = f"  [{mfr.split('|')[0]}]" if mfr else ""
        count = f"({file_count} file{'s' if file_count != 1 else ''})"
        also = f"  also: {', '.join(names[sys_id])}" if sys_id in names else ""
        print(f"  {sys_id:35s} {count:12s}{mfr_display}{also}".rstrip())


def build_target_cores_cache(
    platforms: list[str],
    target: str,
    platforms_dir: str,
    is_all: bool = False,
) -> tuple[dict[str, set[str] | None], list[str]]:
    """Build target cores cache for a list of platforms.

    Returns (cache dict, list of platforms to keep after skipping failures).
    A platform without a targets file cannot honour the target and is left
    out with the others, never run unfiltered, and a target no platform knows
    is refused: `--all --target swtich` checked BizHawk and MiSTer whole and
    exited 0, a green run that said nothing about the Switch.
    """
    cache: dict[str, set[str] | None] = {}
    skip: list[str] = []
    notes: list[str] = []
    for p in platforms:
        try:
            cache[p] = load_target_config(p, target, platforms_dir)
        except FileNotFoundError:
            if not is_all:
                raise
            notes.append(f"INFO: Skipping {p}: no hardware targets")
            skip.append(p)
        except SourceUnreadable:
            # A damaged targets file is not a platform without the target.
            raise
        except ValueError as e:
            if is_all:
                notes.append(f"INFO: Skipping {p}: {e}")
                skip.append(p)
            else:
                raise
    kept = [p for p in platforms if p not in skip]
    if is_all and platforms and not kept:
        # The seventeen per-platform lines buried the one suggestion that
        # mattered: the refusal names the closest target across them all.
        raise ValueError(_unknown_target_message(target, platforms, platforms_dir))
    for note in notes:
        print(note)
    return cache, kept


def _unknown_target_message(target: str, platforms: list[str], platforms_dir: str) -> str:
    """A target no platform has, with the closest names any of them knows."""
    import difflib  # noqa: PLC0415

    targets_dir = os.path.join(platforms_dir, "targets")
    owners: dict[str, list[str]] = {}
    for platform in platforms:
        target_file = os.path.join(targets_dir, f"{platform}.yml")
        if not os.path.exists(target_file):
            continue
        with open(target_file) as f:
            targets = (source_yaml(f) or {}).get("targets", {})
        overrides = _target_overrides(platform, targets_dir)
        for name in _target_alias_index(targets, overrides):
            owners.setdefault(name, []).append(platform)
    message = f"unknown target '{target}': no platform has it."
    close = difflib.get_close_matches(target, sorted(owners), n=3, cutoff=0.6)
    if close:
        named = ", ".join(f"{n} ({', '.join(sorted(owners[n]))})" for n in close)
        return f"{message} Close matches: {named}."
    return (f"{message} python scripts/verify.py --platform <name> --list-targets "
            "lists the targets of one platform.")


# Re-exported so the existing call sites keep working while the
# modules above become the place to import from.
from safeparse import (  # noqa: E402,F401
    parse_untrusted_xml,
    require_yaml,
    yaml_load,
    _pick_yaml_loader,
    _YAML_LOADER,
)
from hashing import (  # noqa: E402,F401
    compute_hashes,
    md5sum,
    md5_composite,
    parse_md5_list,
    cut_md5_owner,
    _ALL_ALGORITHMS,
    _md5_composite_cache,
)
from ziptools import (  # noqa: E402,F401
    check_inside_zip,
    build_zip_contents_index,
    MAX_ZIP_MEMBERS,
    MAX_ZIP_MEMBER_SIZE,
    MAX_ZIP_TOTAL_SIZE,
    MAX_ZIP_COMPRESSION_RATIO,
    safe_extract_zip,
    _zip_contents_cache,
    _BOUNDED_RATIO_METHODS,
    zip_member_crcs,
    zip_member_names,
)
from artifacts import (  # noqa: E402,F401
    write_if_changed,
    write_text_atomic,
    copy_file_atomic,
    plain_file_mode,
    set_plain_mode,
    ArtifactDirectoryMissing,
    ArtifactLockBusy,
    artifact_lock,
    hold_artifact_lock,
    hold_repository_outputs,
    publish_hold,
    repository_output_lock,
    _TIMESTAMP_PATTERNS,
    _strip_timestamps,
)
from largefiles import (  # noqa: E402,F401
    LARGE_FILES_RELEASE,
    LARGE_FILES_REPO,
    LARGE_FILES_CACHE,
    fetch_large_file,
)
from dumpcatalog import (  # noqa: E402,F401
    DEFAULT_PROVENANCE_DIR,
    load_provenance_snapshots,
    build_provenance_index,
    annotate_provenance,
    write_provenance_snapshot,
)


def _exit_on_signal(signum: int, _frame: object) -> None:
    sys.exit(128 + signum)


def run_cli(main: Callable[[], int | None]) -> None:
    """Run a command-line entry point to its exit status.

    A reader that stops early (`verify.py --all | head`) closed the pipe
    and the next write died on a BrokenPipeError traceback. Output nobody
    reads any more ends the run quietly, with the status a shell gives a
    writer whose reader left.

    SIGTERM (timeout, kill) and SIGHUP (a closed terminal) end the process
    without unwinding by default: a pack build left its multi-GB hidden
    .partial behind. Raised as SystemExit, they run the cleanup a failed
    write runs, and the status stays the one a shell gives the signal.
    """
    for name in ("SIGTERM", "SIGHUP"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), _exit_on_signal)
    # Redirected, stdout is block-buffered and stderr is not: the --strict
    # verdict landed on the first line of the log, before the report it
    # closes. Line buffering keeps the two in the order they were written.
    # A stream a caller swapped in (a test's StringIO) has nothing to set.
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is not None:
        reconfigure(line_buffering=True)
    try:
        code = main()
        sys.stdout.flush()
    except (InputMissing, SourceUnreadable, ArtifactLockBusy,
            ArtifactDirectoryMissing) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(141)
    sys.exit(code)
