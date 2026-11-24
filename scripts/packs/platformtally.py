"""Each declaration of a platform resolved and tallied by verify."""

from __future__ import annotations

from dataclasses import dataclass, field

from core.paths import BIOS_DIR, declared_destination
from model.declarations import declared_components
from packs.verdicts import (
    RELEASE_ASSET_PENDING,
    SEVERITY_ORDER,
    STATUS_ORDER,
    Severity,
    Status,
    compute_severity,
    storage_verdict,
    verify_entry_existence,
    verify_entry_md5,
    verify_entry_sha1,
)
from resolve.categories import BIOS, EntryCategories
from resolve.nativemode import digest_algorithm, reads_file_contents
from resolve.validation import accepted_hashes, build_ground_truth
from resolve.acceptance import agnostic_substitute, baseline_verdict, validated_choice


def dest_key(file_entry: dict, sys_id: str) -> str:
    """The path a declaration occupies, as the builder keys its pack."""
    dest = declared_destination(file_entry)
    return dest or f"{sys_id}/{file_entry.get('name', '')}"


def twin_index(
    verify_systems: dict, db: dict, base_dest: str, zip_contents: dict,
) -> tuple[dict[str, int], dict[int, tuple[str, dict]]]:
    """Which declaration the pack ships at each destination, and every declaration by id."""
    # From the module that defines the rule, not the builder's CLI: importing
    # generate_pack made every verify depend on its argparse and manifest code.
    from resolve.packfiles import preferred_entries as _preferred_entries

    preferred_entries = _preferred_entries(
        verify_systems, db, BIOS_DIR, base_dest, False,
        zip_contents, True,
    )
    winners = {
        id(fe): (sid, fe)
        for sid, system in verify_systems.items()
        for fe in system.get("files", [])
    }
    return preferred_entries, winners


@dataclass(frozen=True)
class DeclarationResolver:
    """How a platform run resolves its declarations, as the builder does."""

    db: dict
    zip_contents: dict
    data_dir_registry: dict | None
    slot_overrides: dict[str, str]
    mode: str
    platform_profiles: dict
    # Which declaration the pack ships at each destination, and every
    # declaration by id (twin_index).
    preferred_entries: dict[str, int]
    winners: dict[int, tuple[str, dict]]
    base_dest: str


def _resolve_declaration(
    file_entry: dict, sys_id: str, resolver: DeclarationResolver,
) -> tuple[str | None, str, str | None, dict]:
    """Resolve a declaration to the file the pack ships at its destination.

    When another declaration holds the destination, that one's file is
    returned and the evidence reset: the winner's hash match is not this
    declaration's, which is hashed against the shipped file. The
    declaration that holds the path comes last.
    """
    base_dest = resolver.base_dest
    bare = declared_destination(file_entry)
    preferred = resolver.preferred_entries.get(f"{base_dest}/{bare}" if base_dest else bare)
    held_by, winner = (None, file_entry)
    if preferred is not None and preferred != id(file_entry):
        held_by, winner = resolver.winners[preferred]
    local_path, resolve_status = _resolve_for_platform(
        winner, held_by or sys_id, resolver.db, resolver.zip_contents,
        resolver.data_dir_registry, resolver.slot_overrides, resolver.mode,
        resolver.platform_profiles,
    )
    return local_path, "" if held_by else resolve_status, held_by, winner


def _expects(entry: dict) -> str:
    """The first hash a declaration names, as the message quotes it."""
    return next(
        (f" ({h} {str(entry[h]).split(',')[0]})"
         for h in ("sha1", "md5", "crc32") if entry.get(h)),
        "",
    )


def _side(sys_id: str, entry: dict) -> str:
    """One declaration named by the platform's own system, or its component."""
    native = entry.get("native_system") or ", ".join(
        declared_components(entry.get("component"))
    )
    return f"{sys_id} ({native})" if native else sys_id


def _twin_unmet(
    result: dict,
    held_by: str | None,
    file_entry: dict | None = None,
    sys_id: str = "",
    destination: str = "",
    holder: dict | None = None,
) -> bool:
    """Mark a declaration unmet at a path another declaration holds.

    The path is answered by the winner's file, which the pack counts once.
    This declaration's failure is reported, never folded into the
    destination's status. The message names the path, both systems and
    what this declaration expects: "is not met at the path coco holds"
    named neither the path nor the file wanted there. Two declarations of
    one system are told apart by the platform's own system (RetroDECK
    declares decocass.zip for MAME and for FBNeo, both arcade here), and by
    the hash the holder names when that is the same too (its three
    64DD_IPL.bin revisions).
    """
    if held_by is None or result["status"] == Status.OK:
        return False
    entry = file_entry or {}
    expects = _expects(entry)
    owner, other, held = sys_id or "this", held_by, ""
    if owner == other and holder is not None:
        owner, other = _side(owner, entry), _side(other, holder)
        if owner == other:
            held = _expects(holder)
    result["discrepancy"] = (
        f"{destination or result.get('name', '')} is declared for {owner}"
        f" and for {other}. The {owner} declaration{expects} is not met at"
        f" the path, which holds the {other} file{held}"
    )
    # Read by reports that list entries: the destination itself is held, and
    # a count by destination does not include this one.
    result["settled_by"] = held_by
    return True


def _resolve_for_platform(
    file_entry: dict,
    sys_id: str,
    db: dict,
    zip_contents: dict,
    data_dir_registry: dict | None,
    slot_overrides: dict[str, str],
    mode: str,
    platform_profiles: dict,
) -> tuple[str | None, str]:
    """Resolve one platform entry the way the pack builder does.

    The builder's own resolution (packresolve.resolve_declaration), read from
    disk and the large-file cache: verify never downloads. A frontend that
    never reads the bytes takes the filename-free core's own image.
    """
    from resolve.packfiles import release_asset_paths, resolve_declaration, run_is_offline

    override = slot_overrides.get(
        declared_destination(file_entry)
    )
    local_path, status = resolve_declaration(
        file_entry, db, BIOS_DIR, zip_contents, data_dir_registry,
        override, offline=True,
    )
    if status in ("not_found", "hash_mismatch") and not run_is_offline():
        # Not in the cache, and the release holds a copy that answers the
        # declaration: an online build fetches and packs it (resolve_file).
        assets = release_asset_paths(file_entry, db)
        if assets:
            return assets[0], RELEASE_ASSET_PENDING
    if status == "not_found" and not reads_file_contents(mode):
        found = agnostic_substitute(file_entry, sys_id, db, platform_profiles)
        if found:
            return found[0], "agnostic_fallback"
    return local_path, status


@dataclass(frozen=True)
class PlatformRun:
    """The inputs of one verify_platform run, read by each of its stages."""

    config: dict
    db: dict
    emulators_dir: str
    emu_profiles: dict | None
    profiles: dict
    target_cores: set[str] | None
    data_dir_registry: dict | None
    zip_contents: dict
    system_filter: list[str] | None
    required_only: bool
    mode: str
    base_dest: str

    def full(self, destination: str) -> str:
        return f"{self.base_dest}/{destination}" if self.base_dest else destination


@dataclass
class PlatformTally:
    """Each declaration's verdict, and the verdicts aggregated by destination."""

    run: PlatformRun
    platform: str
    resolver: DeclarationResolver
    region_drops: set[str]
    validation_index: dict
    validation_owners: dict[str, list[tuple[str, str]]]
    hle_index: dict[str, bool]
    categories: EntryCategories
    details: list[dict] = field(default_factory=list)
    file_status: dict[str, str] = field(default_factory=dict)
    file_required: dict[str, bool] = field(default_factory=dict)
    file_severity: dict[str, str] = field(default_factory=dict)
    # What each entry is: firmware, a game's data, or a name no core the
    # platform runs opens. Only firmware gaps carry a severity.
    file_category: dict[str, str] = field(default_factory=dict)
    # (system, full destination, local copy) of each declaration the builder
    # writes, and None for one whose slot it keeps without a file from the
    # collection (user_provided, external). Placed below in the builder's order.
    packed_order: list[tuple[str, str, str | None]] = field(default_factory=list)
    shipped_keys: set[str] = field(default_factory=set)
    results_at: dict[str, list[dict]] = field(default_factory=dict)

    def judge(self, sys_id: str, file_entry: dict) -> None:
        """Verify one declaration and add it to its destination's tally."""
        destination = declared_destination(file_entry)
        if self.region_drops and destination in self.region_drops:
            return
        local_path, resolve_status, held_by, holder = _resolve_declaration(
            file_entry, sys_id, self.resolver,
        )
        result, local_path = self._verdict(
            file_entry, sys_id, local_path, resolve_status, destination,
        )
        result["system"] = sys_id
        result["hle_fallback"] = self.hle_index.get(file_entry.get("name", ""), False)
        result["ground_truth"] = build_ground_truth(
            file_entry.get("name", ""),
            self.validation_index,
        )
        self.details.append(result)
        config = self.run.config
        mode = self.run.mode
        # Occupied only where the builder ships the declaration: a hash
        # the frontend refuses is left out, and the destination stays free
        # for a core's file the pack does carry.
        if (
            local_path
            and result["status"] != Status.MISSING
            and baseline_verdict(
                file_entry, local_path, resolve_status, mode, config.get("hash_rule", "")
            )[1] is None
        ):
            self.packed_order.append((sys_id, self.run.full(destination), local_path))
            self.shipped_keys.add(dest_key(file_entry, sys_id))
        if _twin_unmet(
            result, held_by, file_entry, sys_id, self.run.full(destination), holder,
        ):
            return
        self._aggregate(sys_id, file_entry, destination, result)

    def _verdict(
        self, file_entry: dict, sys_id: str, local_path: str | None,
        resolve_status: str, destination: str,
    ) -> tuple[dict, str | None]:
        """The declaration's result, and the local copy the pack writes for it."""
        config = self.run.config
        mode = self.run.mode
        stored = storage_verdict(file_entry, emulator_pack=False)
        if resolve_status == RELEASE_ASSET_PENDING:
            # Counted as an online build counts it, which fetches the
            # asset. Under --offline the builder cannot, and neither
            # does this report (_resolve_for_platform).
            result = {
                "name": file_entry.get("name", ""),
                "required": file_entry.get("required", True),
                "status": Status.OK,
                "release_asset": local_path,
                "reason": "release asset, fetched when the pack is built",
            }
            # Written at its path like any held file: keyed to None, it
            # stayed out of pack_destinations and step 5 read the pack's
            # copy as a file only the pack holds.
            self.packed_order.append((sys_id, self.run.full(destination), local_path))
            self.shipped_keys.add(dest_key(file_entry, sys_id))
            return result, None
        if stored is not None:
            # The builder keeps the slot: instructions for a user_provided
            # file, the download for an external one, whether it arrives
            # or not. No core file goes there.
            self.packed_order.append((sys_id, self.run.full(destination), None))
            return stored, None
        if not reads_file_contents(mode):
            return verify_entry_existence(
                file_entry,
                local_path,
                self.validation_index,
                self.run.db,
                destination,
                self.validation_owners,
                resolve_status,
                config.get("platform", ""),
            ), local_path
        if digest_algorithm(mode) == "sha1":
            return verify_entry_sha1(file_entry, local_path), local_path
        result = verify_entry_md5(
            file_entry, local_path, resolve_status, config.get("hash_rule", "")
        )
        # Emulator-level validation: informational for platform packs.
        # Platform verification (MD5) is the authority. Emulator
        # mismatches are reported as discrepancies, not failures.
        if result["status"] == Status.OK:
            _chosen, disagreement = validated_choice(
                file_entry, local_path, self.run.db, self.validation_index, "bios",
                digest_algorithm(mode), destination, self.validation_owners,
            )
            if disagreement:
                result["discrepancy"] = f"{self.platform} says OK but {disagreement}"
                if accepted := accepted_hashes(disagreement):
                    result["accepted"] = accepted
        return result, local_path

    def _aggregate(
        self, sys_id: str, file_entry: dict, destination: str, result: dict,
    ) -> None:
        # Aggregate by destination, keyed as the builder keys its pack.
        # A declaration that finds nothing leaves the path to one that
        # holds a file: the builder packs that file there, whatever the
        # order the two are read in.
        dest = dest_key(file_entry, sys_id)
        self.results_at.setdefault(dest, []).append(result)
        required = file_entry.get("required", True)
        cur = result["status"]
        prev = self.file_status.get(dest)
        hle = self.hle_index.get(file_entry.get("name", ""), False)
        sev = compute_severity(cur, required, self.run.mode, hle)
        explained = self.categories.explain(file_entry, destination, sys_id)
        category = explained.pop("category")
        result["category"] = category
        result["category_evidence"] = explained
        if cur != Status.MISSING:
            # A held entry is firmware for the counts: its category only
            # documents it.
            category = BIOS
        if self.file_category.get(dest, category) == BIOS:
            category = BIOS
        self.file_category[dest] = category
        if prev is not None and (cur == Status.MISSING) != (prev == Status.MISSING):
            if cur == Status.MISSING:
                return
            del self.file_status[dest], self.file_severity[dest]
            prev = None
        if prev is None or STATUS_ORDER.get(cur, 0) > STATUS_ORDER.get(prev, 0):
            self.file_status[dest] = cur
            self.file_required[dest] = required
        prev_sev = self.file_severity.get(dest)
        if prev_sev is None or SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(
            prev_sev, 0
        ):
            self.file_severity[dest] = sev

    def settle_groups(self) -> None:
        """RetroBat's group: one file of it held is enough, and the others are
        reported OPTIONAL (batocera-systems/Program.cs). None held, each stays
        required."""
        members: dict[tuple[str, str], list[str]] = {}
        for sys_id, system in self.run.config.get("systems", {}).items():
            for file_entry in system.get("files", []):
                if file_entry.get("group"):
                    dest = dest_key(file_entry, sys_id)
                    if dest in self.file_status:
                        members.setdefault((sys_id, file_entry["group"]), []).append(dest)
        for dests in members.values():
            if not any(self.file_status[d] == Status.OK for d in dests):
                continue
            for dest in dests:
                if self.file_status[dest] == Status.MISSING:
                    self.file_required[dest] = False
                    self.file_severity[dest] = compute_severity(
                        Status.MISSING, False, self.run.mode
                    )
                    for result in self.results_at.get(dest, []):
                        result["required"] = False

    def credit_placed(self, placed: set[str]) -> None:
        """An existence frontend is satisfied by any file at the path, and the
        builder fills a free platform destination with a core's file."""
        for dest, status in self.file_status.items():
            if status == Status.MISSING and self.run.full(dest) in placed:
                self.file_status[dest] = Status.OK
                self.file_severity[dest] = Severity.OK
                for result in self.results_at.get(dest, []):
                    result["status"] = Status.OK

    def severity_counts(self) -> tuple[dict[str, int], dict[str, list[str]]]:
        """Destinations by severity, and the missing ones that are not firmware."""
        counts = {
            Severity.OK: 0,
            Severity.INFO: 0,
            Severity.WARNING: 0,
            Severity.CRITICAL: 0,
        }
        not_firmware: dict[str, list[str]] = {}
        for dest, s in self.file_severity.items():
            category = self.file_category.get(dest, BIOS)
            if category != BIOS and self.file_status.get(dest) == Status.MISSING:
                not_firmware.setdefault(category, []).append(dest)
                continue
            counts[s] = counts.get(s, 0) + 1
        return counts, not_firmware
