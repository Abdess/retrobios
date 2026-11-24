"""The install manifest of a platform."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, TypedDict

from core.options import reject_unknown
from core.paths import REPO_ROOT, declared_destination
from model.platforms import load_platform_config
from model.profiles import load_emulator_profiles
from model.registry import load_data_dir_registry, platform_registry_at
from packs import slots
from packs.archive import CASE_FOLDING_OS
from packs.declsettle import DeclarationJudge
from packs.extras import (
    undeclared_report,
)
from packs.manifestcores import (
    manifest_selection,
)
from packs.naming import manifest_suffix
from packs.standalone import standalone_layouts
from resolve.contentlayout import TARGET_KEY
from resolve.cores import platform_scope_systems, resolve_platform_cores as _platform_cores
from resolve.gamedata import platform_game_data, without_game_data
from resolve.acceptance import destination_owners
from resolve.validation import build_validation_index

if TYPE_CHECKING:
    from typing_extensions import Unpack
from packs.manifestbuild import ManifestBuild, ManifestSettings


class InstallListOptions(TypedDict, total=False):
    """The keyword options of generate_install_list, which it hands to
    generate_manifest."""

    emulators_dir: str
    zip_contents: dict | None
    emu_profiles: dict | None
    target_cores: set[str] | None
    source: str
    regions: list[str] | None
    target_name: str | None
    offline: bool | None
    required_only: bool
    data_registry: dict | None
    fold_case: bool | None
    no_game_data: bool
    one_per_slot: bool
    uncached_out: dict[str, str] | None


class ManifestOptions(InstallListOptions, total=False):
    """The keyword options of generate_manifest."""

    known_slot_choices: dict | None
    build_out: dict | None


def _start_manifest(
    platform_name: str,
    platforms_dir: str,
    db: dict,
    bios_dir: str,
    registry_path: str,
    opts: ManifestSettings,
) -> tuple[ManifestBuild, dict]:
    """The manifest's configuration and scope, and the profiles before the
    game data cut."""
    config = load_platform_config(platform_name, platforms_dir)
    if opts.fold_case is not None:
        config = {**config, "case_insensitive_fs": opts.fold_case}
    if opts.target_name:
        config = {**config, TARGET_KEY: opts.target_name}
    zip_contents = {} if opts.zip_contents is None else opts.zip_contents
    emu_profiles = opts.emu_profiles
    if emu_profiles is None:
        emu_profiles = load_emulator_profiles(opts.emulators_dir)
    data_registry = opts.data_registry
    if data_registry is None:
        data_registry = load_data_dir_registry(platforms_dir)
    full_profiles = emu_profiles
    game_entries: set[int] = set()
    if opts.no_game_data:
        cut = without_game_data(config, emu_profiles, data_registry, opts.target_cores)
        config, emu_profiles = cut.config, cut.profiles
    else:
        game_entries = platform_game_data(config, emu_profiles, data_registry)

    # Load registry for install metadata
    plat_registry = platform_registry_at(registry_path).get(platform_name) or {}

    pack_systems = platform_scope_systems(config, emu_profiles, opts.target_cores)
    build = ManifestBuild(
        platform_name, platforms_dir, db, bios_dir, opts, config, emu_profiles,
        zip_contents, data_registry, game_entries, plat_registry.get("install", {}),
        str(REPO_ROOT), pack_systems,
    )
    build.manifest_profiles = {
        name: emu_profiles[name]
        for name in _platform_cores(config, emu_profiles)
    }
    build.manifest_validation = build_validation_index(build.manifest_profiles)
    build.manifest_owners = destination_owners(build.manifest_profiles)
    _settle_manifest_scope(build)
    return build, full_profiles


def _settle_manifest_scope(build: ManifestBuild) -> None:
    """Game data destinations, slot choices and the region selection."""
    opts, config, emu_profiles = build.opts, build.config, build.emu_profiles
    # A destination is game data when every declaration of it is: a firmware
    # declaration of the same path keeps it in a pack built without game data.
    declared_kinds: dict[str, set[bool]] = {}
    for system in build.pack_systems.values():
        for fe in system.get("files", []):
            bare = declared_destination(fe)
            if bare:
                declared_kinds.setdefault(bare, set()).add(id(fe) in build.game_entries)
    build.game_destinations = {d for d, kinds in declared_kinds.items() if kinds == {True}}

    # The full manifest records every core's answer at a contested slot, so a
    # target narrowed from it gets what that target's own pack serves.
    whole = opts.target_cores is None and opts.source != "platform" and bool(emu_profiles)
    # The truth list read inside this run takes the choices already made.
    build.slot_choices = (
        opts.known_slot_choices if opts.known_slot_choices is not None and whole
        else slots.slot_choices(config, emu_profiles, build.db, build.zip_contents,
                                build.data_registry)
        if whole else {}
    )
    # Derived from the same choices: computed twice, it was 8% of a run.
    build.slot_overrides = slots.pack_overrides(
        config, emu_profiles, build.db, build.zip_contents, build.data_registry,
        target_cores=opts.target_cores, source=opts.source,
        choices=build.slot_choices if whole else None,
    )

    # Read by the region grouping and by phase 2 with the same arguments.
    build.undeclared = (
        undeclared_report(
            config, opts.emulators_dir, build.db, emu_profiles, opts.target_cores,
            include_all=(opts.source == "truth"),
        )
        if opts.source != "platform"
        else None
    )
    build.region_drops, build.selection, build.builder_held = manifest_selection(
        config, build.pack_systems, opts.emulators_dir, build.db, build.base_dest,
        emu_profiles, opts.target_cores, opts.source,
        required_only=opts.required_only, regions=opts.regions,
        undeclared=build.undeclared, zip_contents=build.zip_contents,
        data_registry=build.data_registry, slot_overrides=build.slot_overrides,
        one_per_slot=opts.one_per_slot,
    )


def generate_manifest(
    platform_name: str,
    platforms_dir: str,
    db: dict,
    bios_dir: str,
    registry_path: str,
    **options: Unpack[ManifestOptions],
) -> dict:
    """Generate a JSON manifest for a platform (same resolution as generate_pack).

    Returns a dict ready for JSON serialization with file inventory,
    install hints, and download metadata. ``fold_case`` overrides the
    platform's ``case_insensitive_fs``, for the case variants below.

    A file that is a game's data, not firmware, carries ``"category":
    "game_data"``, so the installer can leave it out as the builder does
    under ``no_game_data``. Firmware carries no category.
    One build: generate_install_list adds what --source truth and
    --standalone read. `build_out` receives the slot choices and the
    profiles this build read, which that second build takes over.
    `uncached_out` maps each data directory the list carries and the cache
    does not hold to its cache folder: the caller reports it.
    """
    reject_unknown("generate_manifest", options, ManifestOptions.__optional_keys__)
    opts = ManifestSettings(**options)
    build, full_profiles = _start_manifest(
        platform_name, platforms_dir, db, bios_dir, registry_path, opts
    )
    config, verification_mode = build.config, build.verification_mode

    declarations = DeclarationJudge(
        db, bios_dir, build.zip_contents, build.data_registry, opts.offline,
        verification_mode, config.get("hash_rule", ""), build.manifest_profiles,
        build.manifest_validation, build.manifest_owners,
    )

    def settle(
        file_entry: dict, sys_id: str, dest: str, override: str | None
    ) -> tuple[str | None, str]:
        """The file served once the slot is settled, or None and why not."""
        settled = declarations.settle(file_entry, sys_id, dest, override)
        renamed = os.path.basename(settled.resolved or "") != file_entry.get("name", "")
        if settled.agnostic_dir and renamed:
            # The pack explains the rename in a note of its own.
            build.rename_notes.add(file_entry.get("name", ""))
        if not settled.ships:
            return None, "hash_mismatch" if settled.refusal else settled.status
        # The variant the pack ships when an emulator rejects the
        # resolved file: the installer must place the same bytes.
        return settled.path, settled.status

    if opts.source != "truth":
        build.list_baseline(settle)
    build.list_core_files()
    result = build.result(build.list_data_directories())
    detect = build.install_section.get("detect", [])
    if build.case_insensitive and opts.fold_case is None and any(
        d.get("os") not in CASE_FOLDING_OS for d in detect
    ):
        # RetroArch also runs where case is kept: there Mesen-CE opens
        # bios.col and np2kai np2kai/2608_bd.wav, which the folded list
        # serves only as BIOS.col and 2608_BD.WAV. The installer adds these
        # where the directory keeps case, while the pack, extracted on Windows
        # or macOS too, stays folded.
        kept = generate_manifest(
            platform_name, platforms_dir, db, bios_dir, registry_path,
            emulators_dir=opts.emulators_dir, zip_contents=build.zip_contents,
            emu_profiles=full_profiles, target_cores=opts.target_cores, source=opts.source,
            regions=opts.regions, target_name=opts.target_name, offline=opts.offline,
            required_only=opts.required_only, data_registry=build.data_registry,
            fold_case=False, no_game_data=opts.no_game_data,
        )
        folded = {entry["dest"] for entry in build.manifest_files}
        folded_lower = {dest.lower() for dest in folded}
        variants = [
            entry for entry in kept["files"]
            if entry["dest"] not in folded and entry["dest"].lower() in folded_lower
        ]
        if variants:
            result["case_variants"] = variants
    if opts.build_out is not None:
        opts.build_out.update(slot_choices=build.slot_choices, profiles=build.manifest_profiles)
    return result


def generate_install_list(
    platform_name: str,
    platforms_dir: str,
    db: dict,
    bios_dir: str,
    registry_path: str,
    standalone_out: dict | None = None,
    **options: Unpack[InstallListOptions],
) -> dict:
    """The list install.py reads: the full manifest, the files and omissions
    the --source truth build holds apart from it, and the emulators with a
    standalone build. `standalone_out` receives, per such emulator, what
    `--emulator X --standalone` packs, written apart from the list
    (install/standalone/<platform>.json) and fetched only by a run given
    --standalone.

    A manifest whose name carries a narrowing tag (manifest_suffix), or
    built under a case fold override, is no list install.py reads by default
    and gets neither.
    """
    settings = ManifestSettings(**options)
    built: dict = {}
    result = generate_manifest(platform_name, platforms_dir, db, bios_dir, registry_path,
                               build_out=built, **options)
    narrowed = manifest_suffix(
        settings.source, settings.regions, settings.target_name, settings.required_only,
        one_per_slot=settings.one_per_slot, no_game_data=settings.no_game_data,
    )
    if narrowed or settings.target_cores is not None or settings.fold_case is not None:
        return result
    truth_options: InstallListOptions = {**options, "source": "truth"}
    truth = generate_manifest(
        platform_name, platforms_dir, db, bios_dir, registry_path,
        **truth_options, known_slot_choices=built["slot_choices"],
    )
    _mark_truth(result, truth)
    layouts = standalone_layouts(
        built["profiles"], settings.emulators_dir, db, bios_dir,
        settings.zip_contents or {}, settings.offline, platforms_dir, result,
    )
    if layouts:
        result["standalone_builds"] = sorted(layouts)
        if standalone_out is not None:
            standalone_out.update(layouts)
    return result


def _truth_key(entry: dict) -> tuple:
    """What tells one entry from another, as the installer's _entry_key."""
    root = entry.get("root")
    cores = tuple(entry.get("cores") or []) if root == "emulator" else ()
    return (str(entry.get("dest")), root, cores)


def _mark_truth(result: dict, truth: dict) -> None:
    """What `--source truth` installs, carried in the full list.

    The truth list holds what the emulator profiles prove is read. A file of
    the full list it does not hold, by destination and content, is marked
    `"truth": false`, and what only the truth list holds is `truth_files`.
    Omissions compare by destination. The installer then rebuilds the
    truth list from the full one, and a list without `truth_files` is one
    published before, on which `--source truth` is refused.
    """
    held = {(_truth_key(entry), entry.get("sha1")) for entry in truth["files"]}
    full = {(_truth_key(entry), entry.get("sha1")) for entry in result["files"]}
    for entry in result["files"]:
        if (_truth_key(entry), entry.get("sha1")) not in held:
            entry["truth"] = False
    result["truth_files"] = [
        entry for entry in truth["files"]
        if (_truth_key(entry), entry.get("sha1")) not in full
    ]
    absent = {_truth_key(entry) for entry in truth["omitted_files"]}
    listed = {_truth_key(entry) for entry in result["omitted_files"]}
    for entry in result["omitted_files"]:
        if _truth_key(entry) not in absent:
            entry["truth"] = False
    result["truth_omitted"] = [
        entry for entry in truth["omitted_files"] if _truth_key(entry) not in listed
    ]
