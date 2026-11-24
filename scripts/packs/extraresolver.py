"""The copy the builder packs for a core extra, and the extras it holds yet leaves out."""

from __future__ import annotations

from typing import TYPE_CHECKING, TypedDict

from core.options import reject_unknown
from core.paths import declared_destination
from model.alternatives import core_file_spares
from model.database import sha1_at
from model.declarations import OUTER_ROOTS, declared_root
from packs.extraplace import (
    ExtraPlacement,
    detect_extras_prefix,
    extra_dest,
    extra_full_destination,
    extra_region_key,
)
from packs.extraregions import extras_for_systems
from packs.extras import collect_emulator_extras
from resolve.localfile import resolve_local_file

if TYPE_CHECKING:
    from typing_extensions import Unpack


def _file_sha1(path: str) -> str | None:
    """sha1 of a copy the database does not index, a data tree's file."""
    from core.hashing import compute_hashes

    try:
        return compute_hashes(path, frozenset({"sha1"}))["sha1"]
    except OSError:
        return None


class ResolverOptions(TypedDict, total=False):
    pending_assets: bool


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
        **options: Unpack[ResolverOptions],
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
        reject_unknown("ExtraResolver", options, ResolverOptions.__optional_keys__)
        self.pending_assets = options.get("pending_assets", False)
        # Each profile's entries by slot, built on first use: every extra
        # scanned its whole profile, 33 million entries in one verify --all.
        self._slots: dict[str, dict[tuple[str, str], list[dict]]] = {}

    def alternatives(self, fe: dict) -> list[dict]:
        """The versions the extra's own profile accepts at its slot, as
        acceptance.extra_alternatives finds them."""
        from resolve.acceptance import slot_index

        key = fe.get("source_profile") or ""
        index = self._slots.get(key)
        if index is None:
            profile = (self.profiles or {}).get(key, {})
            index = self._slots[key] = slot_index(profile.get("files") or [])
        name = fe.get("source_name") or fe.get("name", "")
        return index.get((name, fe.get("source_path") or name), [])

    def resolve(self, fe: dict, dest: str) -> tuple[str | None, str, str]:
        """(local copy or None, resolver status, the core's disagreement)."""
        from resolve.packfiles import release_asset_paths, resolve_file, run_is_offline
        from resolve.acceptance import core_size_refusal, validated_choice

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
            assets = release_asset_paths(fe, self.db)
            if assets:
                return assets[0], "release_asset", ""
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


class HiddenOptions(TypedDict, total=False):
    """How hidden_extras replays the builder, and what else it fills."""

    report: list[dict] | None
    resolver: ExtraResolver | None
    placed_kind: dict[str, str] | None
    placed_local: dict[str, str] | None
    system_ids: list[str] | None
    include_all: bool
    required_only: bool


def hidden_extras(
    config: dict,
    emulators_dir: str,
    db: dict,
    profiles: dict,
    shipped: dict[str, str | None],
    target_cores: set[str] | None = None,
    region_drops: set[str] | None = None,
    placed: set[str] | None = None,
    **options: Unpack[HiddenOptions],
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
    from packs.archive import Placed

    reject_unknown("hidden_extras", options, HiddenOptions.__optional_keys__)
    report = options.get("report")
    resolver = options.get("resolver")
    placed_kind = options.get("placed_kind")
    placed_local = options.get("placed_local")
    system_ids = options.get("system_ids")
    include_all = options.get("include_all", False)
    required_only = options.get("required_only", False)
    base_dest = config.get("base_destination", "")
    taken = Placed(bool(config.get("case_insensitive_fs", False)), content={})
    for dest, local in shipped.items():
        taken.take(dest, sha1_at(db, local))
    prefix = detect_extras_prefix(config, base_dest)
    region_prefix = declared_root(config)
    hidden: dict[tuple[str, str, str], str] = {}
    packed_keys: set[tuple[str, str, str]] = set()
    extras = collect_emulator_extras(
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
        dest = _packable_dest(fe, region_drops, region_prefix)
        if not dest:
            continue
        full = extra_full_destination(fe, prefix)
        if not full:
            continue
        reason = taken.block(full)
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
        held = (sha1_at(db, local) or _file_sha1(local)) if local else None
        if reason == "case_twin" and held and taken.content_at(full) == held:
            continue
        key = (
            fe.get("source_emulator", ""), fe.get("source_name", ""),
            fe.get("source_path", ""),
        )
        if reason is not None:
            hidden.setdefault(key, reason)
            continue
        packed_keys.add(key)
        taken.take(full, held)
        if local:
            _record_placed(full, local, fe, placed, placed_kind, placed_local)
    # A file read below a save directory kept per system is packed once per
    # system: one copy left out does not leave the file out.
    return {key: reason for key, reason in hidden.items() if key not in packed_keys}


def _packable_dest(fe: dict, region_drops: set[str] | None, region_prefix: str) -> str:
    """The extra's destination, empty when the builder never places it."""
    dest = declared_destination(fe)
    if not dest or (region_drops and extra_region_key(fe, region_prefix) in region_drops):
        return ""
    if fe.get("root") in OUTER_ROOTS:
        # As the builder does: the pack is extracted into the BIOS folder
        # and cannot reach the roms, emulator or configs folder, the
        # installer places these files.
        return ""
    return dest


def _record_placed(
    full: str,
    local: str,
    fe: dict,
    placed: set[str] | None,
    placed_kind: dict[str, str] | None,
    placed_local: dict[str, str] | None,
) -> None:
    """Note a held extra the pack carries in each record the caller asked for."""
    if placed is not None:
        placed.add(full)
    if placed_kind is not None:
        placed_kind[full] = fe.get("category", "bios")
    if placed_local is not None:
        placed_local[full] = local


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
        dest = extra_dest(u)
        if not placement.places(u, dest):
            key = (u.get("emulator", ""), u.get("name", ""), u.get("path") or "")
            unplaced[key] = placement.unplaced_reason(u, dest)
    return unplaced
