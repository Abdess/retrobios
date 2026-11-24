"""The rows of the bulk data exports: platform entries, emulator files, gaps, cross-references and wanted dumps."""

from __future__ import annotations

import functools
import json
import sys
from collections.abc import Callable

from core.artifacts import json_text as _json_text
from core.paths import REPO_ROOT
from model.database import sha1_at
from model.platforms import ENTRY_TAGS, registry_fields
from model.profiles import is_emulator
from sitegen.config import build_commit
from sitegen.install import release_pack_platforms
from sitegen.lookup import HASH_ALGORITHMS, hash_pairs
from sitegen.provenance import WantedDumps


def accepted_hash_rows(platform_files: list[dict], emulator_items: list[dict]) -> list[dict]:
    """One row per accepted hash value, for both layers, lookup-ready."""
    rows: list[dict] = []
    for row in platform_files:
        # A table row keeps the field as declared under <algorithm>_raw.
        declared = {algo: row.get(f"{algo}_raw", row.get(algo)) for algo in HASH_ALGORITHMS}
        rows.extend({
            "layer": "platform", "owner": row["platform_id"],
            "system": row["system"], "name": row["name"],
            "path": row["destination"], "algorithm": algorithm, "value": value,
        } for algorithm, value in hash_pairs(declared))
    for item in emulator_items:
        for entry in item["profile"].get("files", []) or []:
            if not isinstance(entry, dict):
                continue
            rows.extend({
                "layer": "emulator", "owner": item["id"],
                "system": _json_text(entry.get("system")),
                "name": entry.get("name", ""), "path": entry.get("path", "") or "",
                "algorithm": algorithm, "value": value,
            } for algorithm, value in hash_pairs(entry))
            # Members of an archive: MAME and FBNeo hash the ROMs inside the
            # set, never the set. Left out, a loose nmk004.bin (crc32
            # 83b6f611) found no row while the site search found it.
            archive = entry.get("name", "")
            for member in entry.get("contents") or []:
                if not isinstance(member, dict) or not member.get("name"):
                    continue
                rows.extend({
                    "layer": "emulator", "owner": item["id"],
                    "system": _json_text(entry.get("system")),
                    "name": str(member["name"]), "path": f"{archive}/{member['name']}",
                    "algorithm": algorithm, "value": value,
                } for algorithm, value in hash_pairs(member))
    rows.sort(key=lambda r: (r["layer"], r["owner"], r["name"], r["algorithm"], r["value"]))
    return rows


def _verify_outcomes(
    coverage: dict, db: dict
) -> Callable[[str, str], dict]:
    """For each declared entry, in declaration order: what verify found.

    Returns a function of (system, name) giving the next outcome for that
    pair: status, category, the collection path that answers the entry and
    that file's sha1. The CSV gave the declaration and nothing about it.
    """
    details: dict[tuple[str, str], list[dict]] = {}
    for detail in coverage.get("details") or []:
        details.setdefault((detail.get("system", ""), detail.get("name", "")), []).append(detail)
    taken: dict[tuple[str, str], int] = {}

    def outcome(system: str, name: str) -> dict:
        found = details.get((system, name)) or [{}]
        nth = taken.get((system, name), 0)
        taken[(system, name)] = nth + 1
        detail = found[min(nth, len(found) - 1)]
        path = str(detail.get("path") or "") if detail.get("status") != "missing" else ""
        return {
            "status": detail.get("status", ""),
            "category": detail.get("category", ""),
            "collection_path": path,
            "resolved_sha1": sha1_at(db, path) or "",
        }
    return outcome


@functools.lru_cache(maxsize=1)
def _contract_keys() -> frozenset[str]:
    """The top-level keys platform.schema.json allows in a platform's list."""
    schema = json.loads((REPO_ROOT / "schemas" / "platform.schema.json").read_text(encoding="utf-8"))
    return frozenset(schema.get("properties") or {})


def _split_contract(config: dict) -> tuple[dict, dict]:
    """The list, valid against platform.schema.json, and the registry entry.

    load_platform_config merges the registry into the list: `install`,
    `logo`, `scraper` and `_key` made all 18 contracts fail the published
    schema. They stay published, beside the contract.
    """
    allowed = _contract_keys()
    contract = {key: value for key, value in config.items() if key in allowed}
    if isinstance(contract.get("systems"), dict):
        contract["systems"] = {
            sys_id: {
                **system,
                "files": [
                    {
                        k: v
                        for k, v in f.items()
                        if k not in ENTRY_TAGS
                    }
                    for f in system["files"]
                ],
            }
            if isinstance(system, dict) and system.get("files")
            else system
            for sys_id, system in contract["systems"].items()
        }
    registry = {key: value for key, value in registry_fields(config).items()
                if key not in allowed}
    # The merged config gives a child its parent's release_pack: Lakka and
    # RetroPie said true in the API while every page said they had no ZIP.
    # The registry's own entry decides, as it does for the pages.
    released = config.get("_key") in release_pack_platforms()
    if released or "release_pack" in registry:
        registry["release_pack"] = released
    return contract, registry


# Per-entry fields a folder check needs beyond the hashes: an md5 is a ZIP
# member's when zipped_file is set, and a CSV without it judged 106 good
# Batocera files wrong.
ENTRY_EXPORT_FIELDS = (
    "zipped_file", "hash_match_mandatory", "mandatory_declared", "curated",
    "shared_group", "mirror_of", "zip_digest",
)


def platform_export_rows(
    coverages: dict, db: dict | None = None,
) -> tuple[list[dict], list[dict]]:
    """Normalized platform summaries and one row per declared file."""
    items: list[dict] = []
    file_rows: list[dict] = []
    for key, coverage in sorted(coverages.items()):
        config = coverage["config"]
        outcome = _verify_outcomes(coverage, db or {})
        contract, registry = _split_contract(config)
        items.append({
            "id": key,
            "name": coverage["platform"],
            "coverage": {
                field: coverage.get(field, 0)
                for field in (
                    "total", "present", "verified", "untested", "missing",
                    "core_present", "core_missing", "core_unplaced", "core_unsourceable",
                )
            },
            "contract": contract,
            "registry": registry,
        })
        for system_id, system in sorted(config.get("systems", {}).items()):
            file_rows.extend({
                "platform_id": key,
                "platform": coverage["platform"],
                "system": system_id,
                "name": entry.get("name", ""),
                "destination": entry.get(
                    "destination", entry.get("dest", entry.get("name", ""))
                ),
                "required": bool(entry.get("required", True)),
                "region": _json_text(entry.get("region")),
                "selection_slot": _json_text(entry.get("selection_slot")),
                "size": entry.get("size"),
                "sha1": _json_text(entry.get("sha1")),
                "sha256": _json_text(entry.get("sha256")),
                "md5": _json_text(entry.get("md5")),
                "crc32": _json_text(entry.get("crc32")),
                **{field: _export_flag(entry.get(field)) for field in ENTRY_EXPORT_FIELDS},
                **outcome(system_id, entry.get("name", "")),
            } for entry in system.get("files", []) or [])
    return items, file_rows


def _export_flag(value: object) -> object:
    """A per-entry field as CSV and SQLite hold it: booleans stay booleans,
    an absent field is empty."""
    if value is None:
        return ""
    return value if isinstance(value, bool) else str(value)


def emulator_export_items(profiles: dict) -> list[dict]:
    return [
        {"id": key, "profile": profile}
        for key, profile in sorted(profiles.items())
    ]


def gap_export_rows(
    coverages: dict, gap_report: dict | None = None, db: dict | None = None,
) -> list[dict]:
    """Every gap the site reports, both layers, in one table.

    ``platform`` rows are anomalies against a platform's own BIOS list.
    ``emulator`` rows are files a profiled core loads that no platform
    declares, which is the larger number the gap analysis page leads with.
    A `layer` column keeps the two apart instead of publishing only one.
    """
    rows: list[dict] = []
    db = db or {}
    for key, coverage in sorted(coverages.items()):
        for detail in coverage.get("details", []):
            if detail.get("status") == "ok" and not detail.get("discrepancy"):
                continue
            path = str(detail.get("path") or "") if detail.get("status") != "missing" else ""
            rows.append({
                "category": detail.get("category", "bios"),
                "collection_path": path,
                "resolved_sha1": sha1_at(db, path) or "",
                "layer": "platform",
                "platform_id": key,
                "platform": coverage["platform"],
                "emulator": "",
                "system": detail.get("system", ""),
                "name": detail.get("name", ""),
                "status": detail.get("status", ""),
                "required": bool(detail.get("required", True)),
                "in_repo": "",
                "reason": detail.get("reason", ""),
                "discrepancy": detail.get("discrepancy", ""),
                "destination": detail.get("destination", ""),
                "expected": "",
            })
    for emu_key, data in sorted((gap_report or {}).items()):
        systems = ";".join(str(s) for s in data.get("systems", []) or [])
        # The category travels on the row: its path is the destination the
        # running build reads, not the profile's, and a join on it left 940
        # rows without one.
        rows.extend({
            "category": gap.get("category", ""),
            "collection_path": "",
            "resolved_sha1": "",
            "layer": "emulator",
            "platform_id": "",
            "platform": "",
            "emulator": data.get("emulator", emu_key),
            "system": systems,
            "name": gap.get("name", ""),
            # A file the emulator's own package installs is not one to
            # find: its own status, as unsourceable has.
            "status": (
                "bundled" if gap.get("bundled") and gap.get("source") == "missing"
                else gap.get("source", "")
            ),
            "required": bool(gap.get("required", False)),
            "in_repo": bool(gap.get("in_repo", False)),
            "reason": gap.get("note", ""),
            "discrepancy": "",
            # What a contributor needs to supply the right revision and
            # put it in the right place: the gaps table gave neither.
            "destination": gap.get("path") or gap.get("name", ""),
            "expected": gap.get("identity", ""),
        } for gap in data.get("gap_details", []) or [])
        rows.extend({
            "category": entry.get("category", ""),
            "collection_path": "",
            "resolved_sha1": "",
            "layer": "emulator",
            "platform_id": "",
            "platform": "",
            "emulator": data.get("emulator", emu_key),
            "system": systems,
            "name": entry.get("name", ""),
            "status": "unsourceable",
            "required": bool(entry.get("required", False)),
            "in_repo": False,
            "reason": entry.get("reason", ""),
            "discrepancy": "",
            "destination": entry.get("path") or entry.get("name", ""),
            "expected": "",
        } for entry in data.get("unsourceable", []) or [])
    # Two declarations that differ only in what the row does not carry are
    # one row: AmberELEC's hardwareconfig.xml was printed twice.
    unique: dict[tuple, dict] = {}
    for row in rows:
        unique.setdefault(tuple(sorted((k, str(v)) for k, v in row.items())), row)
    return list(unique.values())


def cross_reference_export_rows(coverages: dict, profiles: dict) -> list[dict]:
    from resolve.cores import resolve_platform_cores

    unique = {
        key: value
        for key, value in profiles.items()
        if is_emulator(value)
    }
    rows: list[dict] = []
    for platform_id, coverage in sorted(coverages.items()):
        for profile_id in sorted(resolve_platform_cores(coverage["config"], unique)):
            profile = unique[profile_id]
            cores = profile.get("cores") or [profile_id]
            systems = profile.get("systems") or [""]
            for core in cores:
                rows.extend({
                    "platform_id": platform_id,
                    "platform": coverage["platform"],
                    "profile_id": profile_id,
                    "emulator": profile.get("emulator", profile_id),
                    "core": core,
                    "system": system,
                    "classification": profile.get("core_classification", ""),
                    "type": profile.get("type", ""),
                    "source": _json_text(profile.get("source")),
                    "upstream": _json_text(profile.get("upstream")),
                    "profiled_commit": _json_text(profile.get("source_commit", "")),
                    "file_count": len(profile.get("files", []) or []),
                } for system in systems)
    return rows


@functools.lru_cache(maxsize=1)
def source_commit() -> str:
    """build_commit, empty outside a checkout: the exports then name no commit."""
    import subprocess

    try:
        return build_commit()
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        print(f"  no commit recorded in the exports: {error}", file=sys.stderr)
        return ""


# One row per dump a catalog describes and the collection lacks: the list
# the provenance page publishes under "Wanted".
WANTED_FIELDS = ("catalog", "dat", "name", "description", "size", "crc32", "md5", "sha1")


def provenance_wanted_rows(dumps: WantedDumps | None) -> list[dict]:
    """The Wanted list of the provenance page, as rows."""
    rows: list[dict] = []
    for catalog, data in (dumps.wanted if dumps else {}).items():
        for entry in data["missing"]:
            rows.extend({
                "catalog": catalog, "dat": dat,
                **{f: _json_text(entry.get(f)) for f in WANTED_FIELDS[2:]},
            } for dat in entry.get("dats") or [entry.get("dat", "")])
    rows.sort(key=lambda r: (r["catalog"], r["dat"], r["name"], r["sha1"]))
    return rows
