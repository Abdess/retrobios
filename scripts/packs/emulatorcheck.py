"""Coverage of one emulator or one system, as the emulator reads its files."""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, field

from core.hashing import compute_hashes
from core.paths import BIOS_DIR, REPO_ROOT
from core.ziptools import build_zip_contents_index
from model.alternatives import set_requirements, settle_sets, slot_set_keys
from model.database import sha1_at
from model.profiles import (
    load_emulator_profiles,
    no_profile_for_systems,
    profiles_for_systems,
    select_emulator_profiles,
)
from model.registry import load_data_dir_registry
from packs.archive import Placed
from packs.datatrees import carried_trees, claimed_tree_files
from packs.emulatorentries import EmulatorPackEntries, EmulatorSelection, emulator_pack_entries
from packs.verdicts import (
    RELEASE_ASSET_PENDING,
    Severity,
    Status,
    SEVERITY_ORDER,
    STATUS_ORDER,
    emulator_severity,
    storage_verdict,
)
from resolve.validation import (
    build_validation_index,
    build_ground_truth,
    validated_choice,
    with_archive_members,
)


# The repository's platforms wherever the script runs from, for library calls
# that pass no directory.
_REPO_PLATFORMS = str(REPO_ROOT / "platforms")


class NoSystemProfileError(ValueError):
    """No profile serves the systems asked for."""


# Emulator/system mode verification


def _effective_validation_label(details: list[dict], validation_index: dict) -> str:
    """Determine the bracket label for the report.

    Returns the union of all check types used, e.g. [crc32+existence+size].
    """
    all_checks: set[str] = set()
    has_files = False
    for d in details:
        fname = d.get("name", "")
        if d.get("note"):
            continue  # skip informational entries (empty profiles)
        has_files = True
        entry = validation_index.get(fname)
        if entry:
            all_checks.update(entry["checks"])
        else:
            all_checks.add("existence")
    if not has_files:
        return "existence"
    return "+".join(sorted(all_checks))


_HASH_CONTRADICTED = "declared hash contradicted by the local file"

# Reduced in the order generate_emulator_pack chooses, so the
# destination's status is the one the pack reports: a slot it
# fills with a contradicted copy, or counts as refused by the
# core, is not missing because another alternative is absent.
_SLOT_PREFERENCE: tuple[Callable[[tuple], bool], ...] = (
    lambda a: a[0]["status"] == Status.OK,
    lambda a: a[0]["status"] == Status.UNTESTED
    and a[0].get("reason") == _HASH_CONTRADICTED,
    lambda a: a[0]["status"] != Status.MISSING,
)


def _archive_result(
    archive: str, required: bool, local_path: str | None, resolve_status: str,
) -> dict:
    """The verdict on an archive unit, from its resolution."""
    if local_path and resolve_status == "hash_mismatch":
        # Same policy as the loose-file branch below: the name
        # matched while the bytes contradict the hash the profile
        # declares on the container. Reporting it covered says the
        # collection holds an archive it does not.
        return {
            "name": archive,
            "status": Status.UNTESTED,
            "required": required,
            "path": local_path,
            "reason": "declared hash contradicted by the local file",
        }
    if local_path:
        result = {
            "name": archive,
            "status": Status.OK,
            "required": required,
            "path": local_path,
        }
        if resolve_status == RELEASE_ASSET_PENDING:
            result["release_asset"] = local_path
        return result
    return {
        "name": archive,
        "status": Status.MISSING,
        "required": required,
    }


PlacedResult = tuple[str, dict, bool, bool, list[dict]]


@dataclass
class _EmulatorPack:
    """The emulator pack as verify_emulator retraces it, and its report."""

    db: dict
    standalone: bool
    required_only: bool
    validation_index: dict
    zip_contents: dict
    data_registry: dict | None
    details: list[dict] = field(default_factory=list)
    # Members of a set another member fills, or that the set's first member
    # stands for: not missing, and out of every count.
    set_members: list[dict] = field(default_factory=list)
    file_status: dict[str, str] = field(default_factory=dict)
    file_severity: dict[str, str] = field(default_factory=dict)
    dest_to_name: dict[str, str] = field(default_factory=dict)
    data_dir_notices: list[str] = field(default_factory=list)
    # The paths the emulator pack writes a profile file to. A copy whose hash
    # the profile contradicts is written too (UNTESTED here, a DISCREPANCY in
    # the pack), so the status alone does not say what the pack holds.
    packed_dests: set[str] = field(default_factory=set)
    # The emulator pack walks profiles in name order and keeps the first
    # file at a path, folding case: a later profile's different file there
    # (zesarux pentagon.rom after speccy's PENTAGON.ROM) is not in the pack.
    # Destination -> (file packed there, its profile, the path as written).
    # Archives and data trees take paths too, before and after the loose
    # files of their profile, as the pack writes them.
    placed: dict[str, tuple[str | None, str, str]] = field(default_factory=dict)
    taken: Placed = field(default_factory=lambda: Placed(True))
    content_ids: dict[str, str | None] = field(default_factory=dict)

    def pending(self, entry: dict, local_path: str | None, status: str) -> tuple[str | None, str]:
        from resolve.packfiles import pending_release_asset, run_is_offline

        # Read from disk and the cache, as _resolve_for_platform does: a
        # release asset the cache lacks is fetched by an online build
        # (generate_emulator_pack resolves with offline=offline).
        if status in ("not_found", "hash_mismatch") and not run_is_offline():
            asset = pending_release_asset(entry, self.db)
            if asset:
                return asset, RELEASE_ASSET_PENDING
        return local_path, status

    def content_id(self, path: str | None) -> str | None:
        if not path:
            return None
        if path not in self.content_ids:
            self.content_ids[path] = sha1_at(self.db, path) or (
                compute_hashes(path)["sha1"] if os.path.isfile(path) else None
            )
        return self.content_ids[path]

    def block(self, dest: str) -> str | None:
        return self.taken.block(dest)

    def occupy(self, dest: str, path: str | None, owner: str) -> None:
        if self.block(dest):
            return
        self.placed[dest.lower()] = (path, owner, dest)
        self.taken.take(dest)

    def carry_trees(self, emu_name: str, profile: dict) -> None:
        """The profile's data trees follow its files in the pack, which
        writes them even when the system filter leaves it no file:
        bluemsx's Machines/ tree holds msx-emu's coleco.rom path in a
        --system colecovision pack. A tree the cache lacks is noticed."""
        for ref, cache, dd_dest in carried_trees(
            profile, self.standalone, self.required_only, self.data_registry,
        ):
            if cache is None:
                self.data_dir_notices.append(ref)
                continue
            for src, full in claimed_tree_files(cache, dd_dest, self.taken):
                self.placed[full.lower()] = (src, emu_name, full)

    def verify_profile(
        self, emu_name: str, profile: dict, carried: EmulatorPackEntries,
    ) -> None:
        """Verify one profile's entries and add them to the report."""
        if not carried.carries_entries:
            self.details.append(
                {
                    "name": f"({emu_name})",
                    "status": Status.OK,
                    "required": False,
                    "system": "",
                    "note": f"No files needed for {profile.get('emulator', emu_name)}",
                    "ground_truth": [],
                }
            )
            self.carry_trees(emu_name, profile)
            return

        # Each destination's outcome, settled by set once the profile is
        # read: an archive unit is a member like a loose file (Kronos reads
        # kronos/stvbios.zip, else stvbios.zip).
        placed_results = self._archive_results(emu_name, carried)
        self._place_loose(emu_name, self._loose_results(emu_name, carried), placed_results)
        self._settle(emu_name, profile, placed_results)
        self.carry_trees(emu_name, profile)

    def _archive_results(self, emu_name: str, carried: EmulatorPackEntries) -> list[PlacedResult]:
        # Verify archives as units (e.g., neogeo.zip, aes.zip)
        from resolve.packfiles import resolve_file

        placed_results: list[PlacedResult] = []
        for archive, own_entry, dest in carried.archives:
            local_path, resolve_status = self.pending(own_entry, *resolve_file(
                own_entry,
                self.db,
                BIOS_DIR,
                self.zip_contents,
                data_dir_registry=self.data_registry,
                offline=True,
            ))
            members = [f for f in carried.entries if f.get("archive") == archive]
            required = any(f.get("required", True) for f in members)
            result = _archive_result(archive, required, local_path, resolve_status)
            result["system"] = members[0].get("system", "")
            result["hle_fallback"] = False
            result["ground_truth"] = build_ground_truth(archive, self.validation_index)
            result["destination"] = dest
            block = self.block(dest)
            if block and local_path and result["status"] != Status.MISSING:
                other_path, owner, other_dest = self.placed.get(dest.lower(), (None, "", ""))
                if block == "path_conflict" or self.content_id(local_path) != self.content_id(other_path):
                    # The pack serves the other profile's file here: this
                    # archive is not in it, whatever this profile resolves.
                    result["status"] = Status.MISSING
                    result["reason"] = (
                        "a packed file occupies its directory" if block == "path_conflict"
                        else f"the pack holds {owner}'s {other_dest} at this path"
                    )
            elif local_path:
                self.occupy(dest, local_path, emu_name)
                self.packed_dests.add(dest)
            placed_results.append((dest, result, required, False, [own_entry]))
        return placed_results

    def _loose_results(
        self, emu_name: str, carried: EmulatorPackEntries,
    ) -> dict[str, list[tuple[dict, bool, bool, dict]]]:
        from resolve.packfiles import resolve_file

        # Results of this emulator, by destination. Several entries of one
        # profile on one destination are the releases the code accepts
        # there (a shareware and a retail HOG, each GRP in a size table):
        # holding one of them fills the slot, and the others are not gaps.
        emu_results: dict[str, list[tuple[dict, bool, bool, dict]]] = {}

        for dest, alternatives in carried.slots.items():
            for file_entry in alternatives:
                # The emulator pack's resolution, release assets included.
                local_path, resolve_status = self.pending(file_entry, *resolve_file(
                    {**with_archive_members(file_entry, carried.entries), "source_profile": emu_name},
                    self.db,
                    BIOS_DIR,
                    self.zip_contents,
                    dest_hint=file_entry.get("path", ""),
                    data_dir_registry=self.data_registry,
                    offline=True,
                ))
                if resolve_status in ("not_found", "user_provided", "external"):
                    local_path = None
                name = file_entry.get("name", "")
                required = file_entry.get("required", True)
                hle = file_entry.get("hle_fallback", False)

                result = self._loose_result(
                    file_entry, name, required, local_path, resolve_status, emu_name,
                )
                result["system"] = file_entry.get("system", "")
                result["hle_fallback"] = hle
                result["ground_truth"] = build_ground_truth(name, self.validation_index)
                emu_results.setdefault(dest, []).append((result, required, hle, file_entry))
        return emu_results

    def _loose_result(
        self, file_entry: dict, name: str, required: bool, local_path: str | None,
        resolve_status: str, emu_name: str,
    ) -> dict:
        """The verdict on a loose profile entry, from its resolution."""
        stored = storage_verdict(file_entry, emulator_pack=True)
        if stored is not None:
            return stored
        if resolve_status == RELEASE_ASSET_PENDING:
            return {
                "name": name,
                "status": Status.OK,
                "required": required,
                "path": local_path,
                "release_asset": local_path,
                "reason": "release asset, fetched when the pack is built",
            }
        if not local_path:
            result = {"name": name, "status": Status.MISSING, "required": required}
            # An entry the profile documents as unsourceable is absent by
            # design: a per-user key, a slot the user fills, a dump nobody
            # has made. Counting it beside a file somebody could still
            # find invites the wrong repair: dropping the flag, or
            # chasing a vendor's whole install tree.
            unsourceable = file_entry.get("unsourceable")
            if unsourceable:
                result["unsourceable"] = (
                    unsourceable if isinstance(unsourceable, str) else ""
                )
            return result
        # Apply emulator validation
        # Judged by this emulator's own entries, as it runs its check,
        # through the selection the emulator pack makes.
        chosen, disagreement = validated_choice(
            file_entry, local_path, self.db, self.validation_index, BIOS_DIR,
            None, emulators={emu_name},
        )
        if disagreement:
            return {
                "name": name,
                "status": Status.UNTESTED,
                "required": required,
                "path": local_path,
                "reason": disagreement.split(" says ", 1)[-1],
            }
        if chosen != local_path:
            return {
                "name": name,
                "status": Status.OK,
                "required": required,
                "path": chosen,
            }
        if resolve_status == "hash_mismatch":
            # Nothing in validation: caught it, but the name matched
            # while the bytes contradict the hash the profile
            # declares. That is a different file wearing the right
            # name (config.ini and ROM collide across systems), so
            # calling it covered reports the collection as holding
            # something it does not. Validation runs first because it
            # names the specific field that disagrees.
            return {
                "name": name,
                "status": Status.UNTESTED,
                "required": required,
                "path": local_path,
                "reason": "declared hash contradicted by the local file",
            }
        return {
            "name": name,
            "status": Status.OK,
            "required": required,
            "path": local_path,
        }

    def _place_loose(
        self, emu_name: str,
        emu_results: dict[str, list[tuple[dict, bool, bool, dict]]],
        placed_results: list[PlacedResult],
    ) -> None:
        for dest, alternatives in emu_results.items():
            # What the emulator pack places here: an accepted file, else a
            # file whose hash the profile contradicts. A refused copy is held
            # but never packed.
            slot_entries = [a[3] for a in alternatives]
            kept = _preferred_alternatives(alternatives)
            packed = next(
                (a[0].get("path") for a in kept
                 if a[0]["status"] == Status.OK and a[0].get("path")),
                None,
            ) or next(
                (a[0].get("path") for a in kept
                 if a[0]["status"] == Status.UNTESTED
                 and a[0].get("reason") == _HASH_CONTRADICTED and a[0].get("path")),
                None,
            )
            held = packed or next(
                (a[0].get("path") for a in kept
                 if a[0]["status"] != Status.MISSING and a[0].get("path")),
                None,
            )
            block = self.block(dest)
            block_reason = ""
            if block and held is not None:
                block_reason = self._block_reason(dest, block, held)
            elif not block and packed is not None:
                self.occupy(dest, packed, emu_name)
                self.packed_dests.add(dest)
            for result, required, hle, _file_entry in kept:
                if block_reason and result["status"] != Status.MISSING:
                    result["status"] = Status.MISSING
                    result["reason"] = block_reason
                result["destination"] = dest
                placed_results.append((dest, result, required, hle, slot_entries))

    def _block_reason(self, dest: str, block: str, held: str) -> str:
        other_path, owner, other_dest = self.placed.get(dest.lower(), (None, "", ""))
        same = self.content_id(held) is not None and self.content_id(held) == self.content_id(
            other_path
        )
        if block == "path_conflict":
            return "a packed file occupies its directory"
        if block == "case_twin":
            return (
                f"packed only as {other_dest}, from {owner}"
                if same
                else f"the pack holds {owner}'s {other_dest} at this path"
            )
        if not same:
            return f"the pack holds {owner}'s {other_dest} at this path"
        return ""

    def _settle(self, emu_name: str, profile: dict, placed_results: list[PlacedResult]) -> None:
        # A set the code takes one member of is one need: once a member is
        # in the pack the others are not missing, and a set nobody holds is
        # one gap under its first member. Settled per profile, before the
        # destinations of several profiles are merged.
        excused, standing = settle_sets([
            (
                slot_set_keys(emu_name, entries),
                entries[0],
                result["status"] == Status.OK
                or (result["status"] == Status.UNTESTED
                    and result.get("reason") == _HASH_CONTRADICTED),
            )
            for _dest, result, _required, _hle, entries in placed_results
        ], lambda key: set_requirements(profile).get(key[1], True))
        for position, (dest, result, required, hle, _fe) in enumerate(placed_results):
            if position in excused and result["status"] == Status.MISSING:
                self.set_members.append(result)
                continue
            if position in standing:
                result["alternatives"] = standing[position].others
                result["required"] = required = standing[position].required
            self.details.append(result)

            # Aggregate by destination (path if available, else name)
            self.dest_to_name[dest] = result["name"]
            cur = result["status"]
            prev = self.file_status.get(dest)
            if prev is None or STATUS_ORDER.get(cur, 0) > STATUS_ORDER.get(
                prev, 0
            ):
                self.file_status[dest] = cur
            sev = emulator_severity(cur, required, hle)
            prev_sev = self.file_severity.get(dest)
            if prev_sev is None or SEVERITY_ORDER.get(
                sev, 0
            ) > SEVERITY_ORDER.get(prev_sev, 0):
                self.file_severity[dest] = sev


def _preferred_alternatives(
    alternatives: list[tuple[dict, bool, bool, dict]],
) -> list[tuple[dict, bool, bool, dict]]:
    """The one alternative the emulator pack places at a destination."""
    if len(alternatives) > 1:
        for keep in _SLOT_PREFERENCE:
            chosen = [a for a in alternatives if keep(a)]
            if chosen:
                return chosen[:1]
    return alternatives


def verify_emulator(
    profile_names: list[str],
    emulators_dir: str,
    db: dict,
    standalone: bool = False,
    regions: list[str] | None = None,
    platforms_dir: str = _REPO_PLATFORMS,
    system_ids: list[str] | None = None,
    required_only: bool = False,
) -> dict:
    """Verify files for specific emulator profiles.

    A region priority list narrows the report the same way a pack built with the
    same list would be narrowed, through the emulator pack's own drop set.
    `system_ids` keeps the entries of those systems, as the system pack does.
    `required_only` reports on the pack built with --required-only: a loose
    file or tree marked ``required: false`` is left out, and an archive when
    it and every member it carries are optional, as the builder leaves them.
    A name no profile answers for raises ProfileSelectionError.
    """
    # Also load aliases for redirect messages
    all_profiles = load_emulator_profiles(emulators_dir, skip_aliases=False)

    selected = select_emulator_profiles(profile_names, all_profiles, standalone)
    # The member index only answers a zipped_file entry, and decompressing
    # every archive took 23 of the 24 seconds of a run that had none.
    zip_contents = (
        build_zip_contents_index(db)
        if any(f.get("zipped_file") for _name, profile in selected
               for f in profile.get("files") or [])
        else {}
    )

    # Build validation index from selected profiles only
    selected_profiles = dict(selected)
    validation_index = build_validation_index(selected_profiles)
    data_registry = load_data_dir_registry(platforms_dir)

    pack = _EmulatorPack(
        db, standalone, required_only, validation_index, zip_contents, data_registry,
    )

    # The emulator pack withdraws these, and the report withdraws the same.
    region_drops: set[str] = set()
    if regions:
        from packs.extras import emulator_region_drops

        region_drops = emulator_region_drops(
            selected, standalone, regions, required_only, db=db,
            zip_contents=zip_contents, data_registry=data_registry,
        )

    selection = EmulatorSelection(
        db, standalone, all_profiles, validation_index, zip_contents, data_registry,
        system_ids=system_ids, required_only=required_only, region_drops=region_drops,
    )
    for emu_name, profile in sorted(selected):
        pack.verify_profile(emu_name, profile, emulator_pack_entries(emu_name, profile, selection))

    counts = {
        Severity.OK: 0,
        Severity.INFO: 0,
        Severity.WARNING: 0,
        Severity.CRITICAL: 0,
    }
    for s in pack.file_severity.values():
        counts[s] = counts.get(s, 0) + 1
    status_counts: dict[str, int] = {}
    for s in pack.file_status.values():
        status_counts[s] = status_counts.get(s, 0) + 1

    label = _effective_validation_label(pack.details, validation_index)

    gt_filenames = set(validation_index)
    total = len(pack.file_status)
    with_validation = sum(
        1 for dest in pack.file_status if pack.dest_to_name.get(dest, "") in gt_filenames
    )

    return {
        "emulators": [n for n, _ in selected],
        "verification_mode": label,
        "total_files": total,
        # The paths the emulator pack fills with the profile's files, for the
        # pipeline's comparison with the pack built in memory.
        "pack_destinations": sorted(pack.packed_dests),
        "severity_counts": counts,
        "status_counts": status_counts,
        "details": pack.details,
        "set_members": pack.set_members,
        "data_dir_notices": sorted(set(pack.data_dir_notices)),
        "ground_truth_coverage": {
            "with_validation": with_validation,
            "platform_only": total - with_validation,
            "total": total,
        },
    }


def verify_system(
    system_ids: list[str],
    emulators_dir: str,
    db: dict,
    standalone: bool = False,
    regions: list[str] | None = None,
    platforms_dir: str = _REPO_PLATFORMS,
    required_only: bool = False,
) -> dict:
    """Verify files for all emulators supporting given system IDs.

    Raises NoSystemProfileError when no profile serves them, and
    ProfileSelectionError as verify_emulator does.
    """
    profiles = load_emulator_profiles(emulators_dir)
    matching = profiles_for_systems(profiles, system_ids, standalone)

    if not matching:
        raise NoSystemProfileError(no_profile_for_systems(profiles, system_ids, standalone))

    return verify_emulator(
        matching, emulators_dir, db, standalone, regions=regions,
        platforms_dir=platforms_dir, system_ids=system_ids, required_only=required_only,
    )
