"""Fetch MAME BIOS hashes from mamedev/mame source and merge into profiles.

Sparse clones the MAME repo, parses the source tree for BIOS root sets,
caches results to data/mame-hashes.json, and optionally merges into
emulator profiles that reference mamedev/mame upstream.
"""

from __future__ import annotations

import argparse
import json
import os
import logging
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from common import (
    github_token,
    list_registered_platforms,
    load_platform_config,
    source_yaml_paths,
    write_text_atomic,
    yaml_load,
)

import upstream

from ._hash_merge import (
    _build_contents,
    _build_source_ref,
    compute_diff,
    merge_mame_devices,
    merge_mame_profile,
    merge_mame_support,
    settled_required,
)
from .mame_devices import (
    attribute_softlists,
    attribute_systems,
    default_floppy_samples,
    device_systems,
    drive_form_factor,
    floppy_drives,
    floppy_sample_systems,
    locate_sources,
    open_listxml,
    platform_seeds,
    profile_seeds,
    scan_release,
    source_path,
)
from .mame_parser import parse_mame_source_tree

log = logging.getLogger(__name__)

_ROOT = Path(__file__).resolve().parents[2]
_CACHE_PATH = _ROOT / "data" / "mame-hashes.json"
# One clone per process: a fixed tmp/mame was removed and recloned at another
# release by a second run while the first was still parsing it.
_CLONE_DIR = _ROOT / "tmp" / f"mame-{os.getpid()}"
_EMULATORS_DIR = _ROOT / "emulators"
_PLATFORMS_DIR = _ROOT / "platforms"
_FLOPPY_SOURCE = "src/devices/imagedev/floppy.cpp"
# Where a device set goes when only machines no seed places load it: MAME
# starts such a machine from its set name, as an arcade folder passes one.
UNPLACED_SYSTEM = "arcade"
_REPO_URL = "https://github.com/mamedev/mame.git"
_STALE_HOURS = 24


# Cache


def _load_cache() -> dict[str, Any] | None:
    if not _CACHE_PATH.exists():
        return None
    try:
        with open(_CACHE_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _is_stale(cache: dict[str, Any] | None) -> bool:
    if cache is None or not cache.get("bios_sets"):
        return True
    fetched_at = cache.get("fetched_at")
    if not fetched_at:
        return True
    try:
        ts = datetime.fromisoformat(fetched_at)
        age = datetime.now(timezone.utc) - ts
        return age.total_seconds() > _STALE_HOURS * 3600
    except (ValueError, TypeError):
        return True


def _write_cache(data: dict[str, Any]) -> None:
    _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    write_text_atomic(
        str(_CACHE_PATH), json.dumps(data, indent=2, ensure_ascii=False)
    )
    log.info("cache written to %s", _CACHE_PATH)


# Git operations


def _run_git(
    args: list[str], cwd: Path | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )


def _sparse_clone(tag: str) -> None:
    """Clone the release the data will be labelled with, not master.

    The version comes from the latest release. Cloning master gave line
    numbers and hashes of a later revision under that release's label, and
    the profiles cited lines no declared revision holds.
    """
    if _CLONE_DIR.exists():
        shutil.rmtree(_CLONE_DIR)
    _CLONE_DIR.parent.mkdir(parents=True, exist_ok=True)

    log.info("sparse cloning mamedev/mame %s into %s", tag, _CLONE_DIR)
    _run_git(
        [
            "clone",
            "--depth",
            "1",
            "--branch",
            tag,
            "--filter=blob:none",
            "--sparse",
            _REPO_URL,
            str(_CLONE_DIR),
        ]
    )
    _run_git(
        ["sparse-checkout", "set", "src/mame", "src/devices"],
        cwd=_CLONE_DIR,
    )


def _get_version() -> str:
    """The latest MAME release version, such as 0.289."""
    return _parse_version_tag(_get_release_tag())


def _get_release_tag() -> str:
    """The latest MAME release tag, from the GitHub API.

    version.cpp is generated at build time, not in the repo. A failed lookup
    raises: "unknown" was cached for a day and written as core_version.
    """
    headers = {
        "User-Agent": "retrobios-scraper/1.0",
        "Accept": "application/vnd.github.v3+json",
    }
    token = github_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = "https://api.github.com/repos/mamedev/mame/releases/latest"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            tag = json.loads(resp.read()).get("tag_name", "")
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as exc:
        raise RuntimeError(f"cannot read the MAME release from {url}: {exc}") from exc
    if not tag:
        raise RuntimeError(f"no tag_name in {url}")
    return tag


def _parse_version_tag(tag: str) -> str:
    prefix = "mame"
    raw = tag.removeprefix(prefix) if tag.startswith(prefix) else tag
    if raw.isdigit() and len(raw) >= 4:
        return f"{raw[0]}.{raw[1:]}"
    return raw


def _get_commit() -> str:
    """The commit the clone holds, or an error: never an empty pin.

    Returned empty, it was cached for a day and the merge advanced
    core_version and the refs to the new release while upstream_commit
    stayed on the old one, a profile describing two revisions at once.
    """
    try:
        result = _run_git(["rev-parse", "HEAD"], cwd=_CLONE_DIR)
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"cannot read the commit of the MAME clone in {_CLONE_DIR}: {exc}"
        ) from exc
    commit = result.stdout.strip()
    if not commit:
        raise RuntimeError(f"the MAME clone in {_CLONE_DIR} names no commit")
    return commit


def _cleanup() -> None:
    if _CLONE_DIR.exists():
        log.info("cleaning up %s", _CLONE_DIR)
        shutil.rmtree(_CLONE_DIR)


# Profile discovery


_MAME_TREES = frozenset({
    "https://github.com/mamedev/mame",
    "https://github.com/libretro/mame",
})


def _find_mame_profiles() -> list[Path]:
    profiles: list[Path] = []
    for path in source_yaml_paths(_EMULATORS_DIR):
        try:
            with open(path, encoding="utf-8") as f:
                data = yaml_load(f)
            if not isinstance(data, dict):
                continue
            upstream = data.get("upstream", "")
            source = data.get("source", "")
            # Only match profiles tracking current MAME (not frozen snapshots
            # which have upstream like "mamedev/mame/tree/mame0139"), and only
            # those whose own tree is MAME's. GroovyMAME, A7800 and SAME CDi
            # declare mamedev/mame upstream but build from their own fork at
            # another release: refreshing their refs from current MAME moves
            # them onto paths their tree does not have, such as the 0.289 move
            # of neogeo.cpp from src/mame/neogeo/ to src/mame/snk/. A profile
            # that builds mamedev/mame itself at a pinned commit, as pSxMAME
            # does at 0.133, is a snapshot of that tree just the same.
            if (
                isinstance(upstream, str)
                and upstream.rstrip("/") == "https://github.com/mamedev/mame"
                and isinstance(source, str)
                and source.rstrip("/") in _MAME_TREES
                and not (
                    source.rstrip("/") == "https://github.com/mamedev/mame"
                    and data.get("source_commit")
                )
            ):
                profiles.append(path)
        except (yaml.YAMLError, OSError) as exc:
            # Skipped, a broken mame.yml left the list and the refresh
            # reported success without touching it.
            raise RuntimeError(f"cannot read {path}: {exc}") from exc
    return profiles


# Diff formatting


def _format_diff(
    profile_path: Path,
    diff: dict[str, Any],
    hashes: dict[str, Any],
    show_added: bool = True,
) -> list[str]:
    lines: list[str] = []
    name = profile_path.stem

    added = diff.get("added", [])
    updated = diff.get("updated", [])
    removed = diff.get("removed", [])
    unchanged = diff.get("unchanged", 0)

    if not added and not updated and not removed:
        lines.append(f"  {name}:")
        lines.append("    no changes")
        return lines

    lines.append(f"  {name}:")

    if show_added:
        bios_sets = hashes.get("bios_sets", {})
        for set_name in added:
            rom_count = len(bios_sets.get(set_name, {}).get("roms", []))
            source_file = bios_sets.get(set_name, {}).get("source_file", "")
            source_line = bios_sets.get(set_name, {}).get("source_line", "")
            ref = f"{source_file}:{source_line}" if source_file else ""
            lines.append(f"    + {set_name}.zip ({ref}, {rom_count} ROMs)")
    elif added:
        lines.append(f"    + {len(added)} new sets available (main profile only)")

    for set_name in updated:
        lines.append(f"    ~ {set_name}.zip (refreshed)")

    oos = diff.get("out_of_scope", 0)
    lines.append(f"    = {unchanged} unchanged")
    if oos:
        lines.append(f"    . {oos} out of scope (not BIOS root sets)")
    return lines


# Main


def _fetch_hashes(force: bool) -> dict[str, Any]:
    cache = _load_cache()
    if not force and not _is_stale(cache):
        log.info("using cached data from %s", cache.get("fetched_at", ""))
        return cache  # type: ignore[return-value]

    try:
        tag = _get_release_tag()
        _sparse_clone(tag)
        bios_sets = parse_mame_source_tree(str(_CLONE_DIR))
        version = _parse_version_tag(tag)
        commit = _get_commit()
        if not bios_sets or not commit:
            # An empty read was cached for a day and every profile entry
            # came out "out of scope", so nothing was refreshed and the
            # pipeline step reported OK.
            raise RuntimeError(f"no BIOS root set read at {tag}")

        data: dict[str, Any] = {
            "source": "mamedev/mame",
            "version": version,
            "commit": commit,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "bios_sets": bios_sets,
        }
        _write_cache(data)
        return data
    finally:
        _cleanup()


def _run(args: argparse.Namespace) -> None:
    hashes = _fetch_hashes(args.force)

    total_sets = len(hashes.get("bios_sets", {}))
    version = hashes.get("version", "unknown")
    commit = hashes.get("commit", "")[:12]

    if args.json:
        json.dump(hashes, sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
        return

    print(
        f"mame-hashes: {total_sets} BIOS root sets from mamedev/mame"
        f" @ {version} ({commit})"
    )
    print()

    profiles = _find_mame_profiles()
    if not profiles:
        print("  no profiles with mamedev/mame upstream found")
        return

    main_profile = _EMULATORS_DIR / "mame.yml"
    pinned_before = _pinned_version(main_profile)
    for profile_path in profiles:
        is_main = profile_path.name == "mame.yml"
        diff = compute_diff(str(profile_path), str(_CACHE_PATH), mode="mame")
        lines = _format_diff(profile_path, diff, hashes, show_added=is_main)
        for line in lines:
            print(line)

        if not args.dry_run:
            updated = diff.get("updated", [])
            added = diff.get("added", []) if is_main else []
            if added or updated:
                merge_mame_profile(
                    str(profile_path),
                    str(_CACHE_PATH),
                    write=True,
                    add_new=is_main,
                )
                log.info("merged into %s", profile_path.name)

    print()
    if args.dry_run:
        print("(dry run, no files modified)")
        return
    pinned_after = _pinned_version(main_profile)
    if pinned_after != pinned_before:
        # The device sets describe the release mame.yml is pinned on: left
        # behind, the profile names two releases at once.
        print(f"mame.yml moved from {pinned_before} to {pinned_after}: "
              "merging the device ROM sets of that release")
        _merge_devices(argparse.Namespace(
            listxml=fetch_release_listxml(pinned_after), dry_run=False,
        ))


def _pinned_version(profile_path: Path) -> str:
    profile = yaml_load(profile_path.read_text(encoding="utf-8")) if profile_path.is_file() else {}
    return str((profile or {}).get("core_version") or "")


def fetch_release_listxml(version: str) -> Path:
    """The -listxml MAME publishes for a release, in the DAT importer's cache.

    0.289 is the tag mame0289 and the asset mame0289lx.zip.
    """
    from .romset_dat_importer import MAME_LISTXML_URL, _download

    tag = "mame" + version.replace(".", "")
    return _download(
        MAME_LISTXML_URL.format(tag=tag), _ROOT / ".cache" / "dats" / f"{tag}lx.zip"
    )


def release_profile(
    release: str,
    bios_sets: dict[str, Any],
    upstream_commit: str,
    source_commit: str,
    cores: list[str],
    reference: dict[str, Any],
    built_by: list[str],
) -> dict[str, Any]:
    """A profile for one MAME release a platform builds, from its own source.

    Recalbox ships libretro/mame twice, built at 0.258 and at 0.278. The
    BIOS root sets and their ROMs change between releases, so the current
    MAME profile does not describe them. Each set keeps the system and the
    required flag the current profile gives it, while the contents and the line
    are the release's own, and so is a set the release runs without: recel is
    undumped at 0.258 and dumped later.
    """
    version = release.removeprefix("mame")
    version = f"{version[0]}.{version[1:]}" if version.isdigit() else version
    known = {
        str(f.get("name")): f for f in reference.get("files") or []
        if f.get("category") == "bios_zip"
    }
    files = []
    for set_name, data in sorted(bios_sets.items()):
        name = f"{set_name}.zip"
        entry: dict[str, Any] = {
            "name": name,
            # The libretro build searches the content folder, then
            # <system>/mame/bios and <system>/mame/roms (retro_init.cpp,
            # Set_Path_Option): the system folder itself is not read.
            "path": f"mame/bios/{name}",
            "required": settled_required(known.get(name, {}), data),
            "category": "bios_zip",
        }
        if known.get(name, {}).get("system"):
            entry["system"] = known[name]["system"]
        entry["source_ref"] = _build_source_ref(data, "upstream ")
        entry["contents"] = _build_contents(data.get("roms", []))
        files.append(entry)
    return {
        "emulator": f"MAME {version}",
        "type": "libretro",
        "core_classification": "frozen_snapshot",
        "source": "https://github.com/libretro/mame",
        "upstream": f"https://github.com/mamedev/mame/tree/{release}",
        "profiled_date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "source_commit": source_commit,
        "upstream_commit": upstream_commit,
        "core_version": version,
        # Where profile_sync reads it again: the makefile of the libretro/mame
        # tree the platform builds, at source_commit.
        "version_basis": {
            "kind": "file",
            "path": "makefile",
            "pattern": '#define BARE_BUILD_VERSION "([^"]+)"',
        },
        "display_name": f"Arcade (MAME {version})",
        "cores": cores,
        "built_by": built_by,
        # The pin is the commit the platform builds, so the profile is judged
        # against its own revision: libretro/mame HEAD is a later release.
        "pin_frozen": (
            f"{', '.join(built_by)} build{'s' if len(built_by) == 1 else ''} "
            f"libretro/mame at this revision for the {version} release. "
            "Later commits are not part of that build."
        ),
        "systems": list(reference.get("systems") or []),
        "notes": (
            f"libretro/mame built at the {version} release. BIOS root sets "
            f"read from mamedev/mame at {release}: the sets and their ROMs "
            "are that release's, not the current one's."
        ),
        "files": files,
    }


_QUOTE_REF = re.compile(r'^(\s*source_ref: )([^"\'\n].*)$', re.MULTILINE)


def _write_release(args: argparse.Namespace) -> None:
    """Write the profile of one MAME release, read from its own tag."""
    try:
        _sparse_clone(args.release)
        bios_sets = parse_mame_source_tree(str(_CLONE_DIR))
        commit = _get_commit()
    finally:
        _cleanup()
    if not bios_sets or not commit:
        raise RuntimeError(f"no BIOS root set read at {args.release}")
    reference = yaml_load((_EMULATORS_DIR / "mame.yml").read_text(encoding="utf-8"))
    profile = release_profile(
        args.release, bios_sets, commit, args.source_commit, args.core, reference,
        args.built_by,
    )
    # A reason a reader wrote, citing the platform's own build file, outlives
    # a regeneration: the derived one says less.
    if Path(args.profile).is_file():
        previous = yaml_load(Path(args.profile).read_text(encoding="utf-8")) or {}
        if str(previous.get("pin_frozen") or "").strip():
            profile["pin_frozen"] = previous["pin_frozen"]
    text = yaml.safe_dump(profile, sort_keys=False, allow_unicode=True, width=100)
    # Citations are written double-quoted in every profile: left bare, each
    # regeneration rewrote all of them.
    text = _QUOTE_REF.sub(r'\g<1>"\g<2>"', text)
    write_text_atomic(str(args.profile), text)
    print(f"{args.profile}: {len(profile['files'])} BIOS root sets at {args.release}")


def _platform_archives() -> list[tuple[str, str]]:
    """(file name, system) for every file a registered platform declares."""
    stated: list[tuple[str, str]] = []
    for name in list_registered_platforms(str(_PLATFORMS_DIR)):
        config = load_platform_config(name, str(_PLATFORMS_DIR))
        for system, data in (config.get("systems") or {}).items():
            for entry in (data or {}).get("files") or []:
                stated.append((str(entry.get("name") or ""), str(system)))
    return stated


def _merge_devices(args: argparse.Namespace) -> None:
    """Document the device ROM sets of the release mame.yml is pinned on.

    The listxml must be that release's: the lines are read at its tag and
    have to be the lines of the profile's upstream_commit.
    """
    profile_path = _EMULATORS_DIR / "mame.yml"
    text = profile_path.read_text(encoding="utf-8")
    profile = yaml_load(text) or {}
    with open_listxml(args.listxml) as stream:
        tag, devices, machines = scan_release(stream)
    version = _parse_version_tag(tag)
    if str(profile.get("core_version")) != version:
        raise RuntimeError(
            f"{args.listxml} is MAME {version}, mame.yml is pinned on "
            f"{profile.get('core_version')}: refresh the BIOS root sets first"
        )
    repo = upstream.parse_repo(_REPO_URL)
    commit = upstream.tag_commit(repo, tag, upstream.CACHE_DIR)
    if not commit or commit != profile.get("upstream_commit"):
        raise RuntimeError(
            f"{tag} is {commit}, mame.yml upstream_commit is "
            f"{profile.get('upstream_commit')}"
        )

    def fetch(path: str) -> list[str] | None:
        return upstream.fetch_file(repo, commit, path, upstream.CACHE_DIR)

    unplaced = locate_sources(devices, fetch)
    written = profile_seeds(text)
    stated, conflicts = platform_seeds(
        _platform_archives(), machines, profile.get("systems") or [], written
    )
    seeds = {**stated, **written}
    systems = attribute_systems(machines, seeds)
    listed = profile.get("systems") or []
    filed = device_systems(
        machines, seeds, UNPLACED_SYSTEM if UNPLACED_SYSTEM in listed else ""
    )
    for set_name, device in devices.items():
        device["systems"] = filed.get(set_name, [])
    report = merge_mame_devices(str(profile_path), devices, write=not args.dry_run)

    shipped = upstream.list_directory(repo, commit, "hash", upstream.CACHE_DIR)
    if shipped is None:
        raise RuntimeError(f"hash/ of {repo.slug} at {commit} could not be listed")
    present = {name[:-4] for name in shipped if name.endswith(".xml")}
    declared = attribute_softlists(machines, systems)
    lists = {name: found for name, found in declared.items() if name in present}
    floppy = fetch(_FLOPPY_SOURCE)
    if floppy is None:
        raise RuntimeError(f"{_FLOPPY_SOURCE} is absent at {commit}")
    samples = default_floppy_samples("\n".join(floppy))
    form_factors: dict[str, str] = {}
    for drive in floppy_drives(machines):
        lines = fetch(source_path(machines[drive].sourcefile))
        form_factors[drive] = drive_form_factor("\n".join(lines or []), drive)
    sample_systems = floppy_sample_systems(machines, systems, samples, form_factors)
    support = merge_mame_support(
        str(profile_path), lists, sample_systems, write=not args.dry_run
    )

    print(f"mame-devices: {len(devices)} device ROM sets in the {tag} listxml")
    print(f"  {profile_path.name}:")
    print(f"    + {len(report['added'])} added")
    print(f"    ~ {len(report['updated'])} updated")
    print(f"    = {len(report['unchanged'])} unchanged")
    for set_name in report["conflict"]:
        print(f"    ! {set_name}.zip is listed under another category, left as written")
    by_count = Counter(len(device["systems"]) for device in devices.values())
    fallen = sum(1 for device in devices.values() if UNPLACED_SYSTEM in device["systems"])
    print(
        f"  systems: {by_count[1]} sets under one system, "
        f"{sum(n for k, n in by_count.items() if k > 1)} under several, "
        f"{fallen} of them under {UNPLACED_SYSTEM} (loaded by machines no entry places), "
        f"{by_count[0]} instantiated by no machine of the release "
        "(they serve every system of the profile)"
    )
    print(
        f"  seeds: {len(written)} written in {profile_path.name}, "
        f"{len(stated)} from platform files"
    )
    for set_name, found in sorted(conflicts.items()):
        print(f"    {set_name}.zip stated under {', '.join(found)}, left unseeded")
    print(
        f"  software lists: {len(lists)} filed under their systems, "
        f"{len(present) - len(lists)} declared by no placed machine stay with hash/, "
        f"{len(set(declared) - present)} placed lists absent from hash/"
    )
    unread = sorted(drive for drive, found in form_factors.items() if not found)
    print(
        f"  floppy samples: {len(sample_systems)} of {len(samples)} filed, "
        f"{len(support['samples'])} entries rewritten"
    )
    for drive in unread:
        print(f"    {drive}: no form factor read, taken to load every list")
    if unplaced:
        print(f"  {len(unplaced)} without source lines:")
        for set_name, reason in sorted(unplaced.items()):
            print(f"    {set_name} ({devices[set_name]['source_file']}, {reason})")
    if args.dry_run:
        print("(dry run, no files modified)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        prog="mame_hash_scraper",
        description="Fetch MAME BIOS hashes from source and merge into profiles.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="show diff only, do not modify profiles",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="output raw JSON to stdout",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="re-fetch even if cache is fresh",
    )
    devices = parser.add_argument_group(
        "device ROM sets",
        "document every device set with dumped ROMs from the release's "
        "-listxml (e.g. --devices --listxml .cache/dats/mame0289lx.zip)",
    )
    devices.add_argument(
        "--devices", action="store_true",
        help="merge device ROM sets into mame.yml instead of BIOS root sets",
    )
    devices.add_argument(
        "--listxml", type=Path,
        help="MAME -listxml, plain or as the release's mameNNNNlx.zip",
    )
    release = parser.add_argument_group(
        "release profile",
        "write the profile of one MAME release a platform builds "
        "(e.g. --release mame0278 --profile emulators/mame0278.yml "
        "--source-commit <libretro/mame sha> --core mame0278 --built-by recalbox)",
    )
    release.add_argument("--release", help="mamedev/mame tag, such as mame0278")
    release.add_argument("--profile", type=Path, help="profile file to write")
    release.add_argument("--source-commit", help="libretro/mame commit the platform builds")
    release.add_argument("--core", action="append", default=[], help="core name, repeatable")
    release.add_argument(
        "--built-by", action="append", default=[],
        help="platform that compiles this build, repeatable",
    )
    return parser


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s: %(message)s",
    )
    parser = build_parser()
    args = parser.parse_args()
    if args.devices or args.listxml:
        if not (args.devices and args.listxml):
            parser.error("--devices and --listxml go together")
        if args.release or args.profile or args.json or args.force:
            parser.error("--devices takes only --listxml and --dry-run")
        _merge_devices(args)
        return
    if args.release or args.profile:
        missing = [
            flag for flag, value in (
                ("--release", args.release), ("--profile", args.profile),
                ("--source-commit", args.source_commit), ("--core", args.core),
                ("--built-by", args.built_by),
            ) if not value
        ]
        if missing:
            parser.error(f"a release profile needs {', '.join(missing)}")
        if args.dry_run or args.json:
            parser.error("--release writes a profile; --dry-run and --json do not apply")
        _write_release(args)
        return
    _run(args)


if __name__ == "__main__":
    main()
