"""The bulk data exports: CSV, JSON and SQLite of the collection, platforms and gaps."""

from __future__ import annotations

import csv
import functools
import io
import json
import os
import shutil
import sqlite3
import sys
from collections.abc import Callable
from pathlib import Path

from core.artifacts import build_timestamp
from core.artifacts import json_text as _json_text
from core.hashing import file_digest
from model import retired as model_retired
from model.database import sha1_at
from model.dumpcatalog import load_provenance_snapshots
from model.profiles import is_emulator
from packs.crossref import FileConsumers, SupplementalIndex
from acquire.provenance import build_report
from sitegen.apiitems import core_index_items, system_index_items
from sitegen.config import DATA_LICENSE, REPO_URL, build_commit
from core.paths import REPO_ROOT
from sitegen.install import release_pack_platforms
from sitegen.lookup import (
    HASH_ALGORITHMS,
    hash_pairs,
    data_directory_members,
    file_location_items,
    file_lookup_records,
    write_lookup_shards,
)
from sitegen.provenance import load_derivable
from sitegen.publish import publish_manifests
from sitegen.structured import write_platform_dats, collection_dat
from sitegen.write import record_written, write_if_changed


def generate_stats(stats: dict) -> str:
    return json.dumps(stats, indent=2) + "\n"


def _accepted_hash_rows(platform_files: list[dict], emulator_items: list[dict]) -> list[dict]:
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


def _csv_document(fieldnames: list[str], rows: list[dict]) -> str:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(
        stream, fieldnames=fieldnames, extrasaction="ignore", lineterminator="\n"
    )
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue()


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
    # platform_system and platform_cores are the resolver's copies of the key
    # each entry sits under and of that system's cores.
    if isinstance(contract.get("systems"), dict):
        contract["systems"] = {
            sys_id: {
                **system,
                "files": [
                    {
                        k: v
                        for k, v in f.items()
                        if k not in ("platform_system", "platform_cores")
                    }
                    for f in system["files"]
                ],
            }
            if isinstance(system, dict) and system.get("files")
            else system
            for sys_id, system in contract["systems"].items()
        }
    registry = {key: value for key, value in config.items()
                if key not in allowed and key != "_key"}
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


def _platform_export_rows(
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
                    "core_present", "core_missing", "core_unsourceable",
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


def _emulator_export_items(profiles: dict) -> list[dict]:
    return [
        {"id": key, "profile": profile}
        for key, profile in sorted(profiles.items())
    ]


def build_emulator_gap_report(
    profiles: dict,
    coverages: dict,
    db: dict,
    data_names: SupplementalIndex | None = None,
) -> dict:
    """Files a core loads that no platform declares, per emulator profile.

    The gap analysis page and the published gaps export must not compute this
    twice and drift. Both read this one report.
    """
    from packs.crossref import cross_reference as run_cross_reference, global_report_scope

    declared, scope = global_report_scope(
        [cov["config"] for cov in coverages.values()], db)
    unique_profiles = {
        k: v
        for k, v in profiles.items()
        if is_emulator(v)
    }
    return run_cross_reference(unique_profiles, declared, db, data_names=data_names, **scope)


def _gap_export_rows(
    coverages: dict, gap_report: dict | None = None, db: dict | None = None,
    profiles: dict | None = None,
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
        categories = _profile_categories((profiles or {}).get(emu_key) or {})
        rows.extend({
            "category": categories.get(
                (gap.get("name", ""), gap.get("path") or gap.get("name", "")), ""),
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
            "category": categories.get(
                (entry.get("name", ""), entry.get("path") or entry.get("name", "")), ""),
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


def _profile_categories(profile: dict) -> dict[tuple[str, str], str]:
    """(name, path) -> the category a profile gives the entry, bios by default."""
    found: dict[tuple[str, str], str] = {}
    for entry in profile.get("files") or []:
        if isinstance(entry, dict) and entry.get("name"):
            name = str(entry["name"])
            found.setdefault((name, str(entry.get("path") or name)),
                             str(entry.get("category") or "bios"))
    return found


def _cross_reference_export_rows(coverages: dict, profiles: dict) -> list[dict]:
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


def _write_sqlite_export(
    destination: Path,
    db: dict,
    platform_items: list[dict],
    platform_files: list[dict],
    emulator_items: list[dict],
    gap_rows: list[dict],
) -> None:
    """Build a queryable, deterministic snapshot without embedding binaries."""
    temp_dir = Path("tmp") / "site"
    temp_dir.mkdir(parents=True, exist_ok=True)
    temp_path = temp_dir / f"retrobios-{os.getpid()}.sqlite"
    temp_path.unlink(missing_ok=True)
    destination.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(temp_path)
    try:
        connection.executescript("""
            PRAGMA journal_mode = OFF;
            PRAGMA synchronous = OFF;
            CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE files (
                sha1 TEXT PRIMARY KEY, path TEXT NOT NULL, name TEXT NOT NULL,
                size INTEGER NOT NULL, md5 TEXT NOT NULL, sha256 TEXT NOT NULL,
                crc32 TEXT NOT NULL, adler32 TEXT NOT NULL
            );
            CREATE TABLE file_provenance (
                sha1 TEXT NOT NULL, catalog TEXT NOT NULL, details_json TEXT NOT NULL,
                PRIMARY KEY (sha1, catalog),
                FOREIGN KEY (sha1) REFERENCES files(sha1)
            );
            CREATE TABLE platforms (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, total INTEGER NOT NULL,
                present INTEGER NOT NULL, verified INTEGER NOT NULL,
                missing INTEGER NOT NULL, contract_json TEXT NOT NULL
            );
            CREATE TABLE platform_files (
                platform_id TEXT NOT NULL, system TEXT NOT NULL, name TEXT NOT NULL,
                destination TEXT NOT NULL, required INTEGER NOT NULL,
                region TEXT, selection_slot TEXT, size INTEGER,
                sha1 TEXT, sha256 TEXT, md5 TEXT, crc32 TEXT,
                status TEXT, category TEXT, collection_path TEXT, resolved_sha1 TEXT,
                zipped_file TEXT, hash_match_mandatory INTEGER, mandatory_declared INTEGER,
                curated INTEGER, shared_group TEXT, mirror_of TEXT, zip_digest TEXT
            );
            CREATE TABLE emulators (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, type TEXT,
                classification TEXT, source TEXT, upstream TEXT,
                source_commit TEXT, profile_json TEXT NOT NULL
            );
            CREATE TABLE emulator_systems (
                emulator_id TEXT NOT NULL, system TEXT NOT NULL,
                PRIMARY KEY (emulator_id, system)
            );
            CREATE TABLE emulator_files (
                emulator_id TEXT NOT NULL, system TEXT, name TEXT NOT NULL,
                path TEXT, required INTEGER NOT NULL, mode TEXT, region TEXT,
                size TEXT, sha1 TEXT, sha256 TEXT, md5 TEXT, crc32 TEXT,
                source_ref TEXT
            );
            CREATE TABLE gaps (
                layer TEXT NOT NULL, platform_id TEXT, platform TEXT,
                emulator TEXT, system TEXT, name TEXT NOT NULL,
                status TEXT NOT NULL, required INTEGER NOT NULL,
                in_repo TEXT, reason TEXT, discrepancy TEXT,
                destination TEXT, expected TEXT, category TEXT,
                collection_path TEXT, resolved_sha1 TEXT
            );
            CREATE TABLE accepted_hashes (
                layer TEXT NOT NULL, owner TEXT NOT NULL, system TEXT,
                name TEXT NOT NULL, path TEXT, algorithm TEXT NOT NULL,
                value TEXT NOT NULL
            );
            CREATE INDEX accepted_hashes_value_idx ON accepted_hashes(algorithm, value);
            CREATE INDEX files_name_idx ON files(name);
            CREATE INDEX files_md5_idx ON files(md5);
            CREATE INDEX files_sha256_idx ON files(sha256);
            CREATE INDEX platform_files_name_idx ON platform_files(name);
            CREATE INDEX emulator_files_name_idx ON emulator_files(name);
            CREATE INDEX gaps_status_idx ON gaps(layer, status);
        """)
        commit = source_commit()
        metadata = {
            "schema_version": "1",
            "generated_at": build_timestamp(db),
            **({"commit": commit} if commit else {}),
            "source": REPO_URL,
            "scope": "metadata only, no BIOS or firmware payload bytes",
            "license": DATA_LICENSE,
        }
        connection.executemany(
            "INSERT INTO metadata(key, value) VALUES (?, ?)",
            sorted(metadata.items()),
        )
        for sha1, entry in sorted(db.get("files", {}).items()):
            connection.execute(
                "INSERT INTO files VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    sha1, entry.get("path", ""), entry.get("name", ""),
                    entry.get("size", 0), entry.get("md5", ""),
                    entry.get("sha256", ""), entry.get("crc32", ""),
                    entry.get("adler32", ""),
                ),
            )
            for catalog, details in sorted((entry.get("provenance") or {}).items()):
                connection.execute(
                    "INSERT INTO file_provenance VALUES (?, ?, ?)",
                    (sha1, catalog, _json_text(details)),
                )
        for item in platform_items:
            coverage = item["coverage"]
            connection.execute(
                "INSERT INTO platforms VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    item["id"], item["name"], coverage.get("total", 0),
                    coverage.get("present", 0), coverage.get("verified", 0),
                    coverage.get("missing", 0), _json_text(item["contract"]),
                ),
            )
        connection.executemany(
            "INSERT INTO platform_files VALUES "
            "(:platform_id, :system, :name, :destination, :required, :region, "
            ":selection_slot, :size, :sha1, :sha256, :md5, :crc32, :status, :category, "
            ":collection_path, :resolved_sha1, :zipped_file, :hash_match_mandatory, "
            ":mandatory_declared, :curated, :shared_group, :mirror_of, :zip_digest)",
            platform_files,
        )
        for item in emulator_items:
            profile = item["profile"]
            connection.execute(
                "INSERT INTO emulators VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    item["id"], profile.get("emulator", item["id"]),
                    profile.get("type", ""),
                    profile.get("core_classification", ""),
                    _json_text(profile.get("source")),
                    _json_text(profile.get("upstream")),
                    # source_commit is a string or, when the builds live in
                    # separate repositories, an object keyed by build mode.
                    # SQLite cannot bind the object form.
                    _json_text(profile.get("source_commit", "")),
                    _json_text(profile),
                ),
            )
            for system in sorted(set(profile.get("systems", []) or [])):
                connection.execute(
                    "INSERT INTO emulator_systems VALUES (?, ?)",
                    (item["id"], system),
                )
            for entry in profile.get("files", []) or []:
                connection.execute(
                    "INSERT INTO emulator_files VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        item["id"], _json_text(entry.get("system")),
                        entry.get("name", ""), entry.get("path", ""),
                        int(bool(entry.get("required", False))),
                        entry.get("mode", ""), _json_text(entry.get("region")),
                        _json_text(entry.get("size")), _json_text(entry.get("sha1")),
                        _json_text(entry.get("sha256")), _json_text(entry.get("md5")),
                        _json_text(entry.get("crc32")),
                        _json_text(entry.get("source_ref")),
                    ),
                )
        connection.executemany(
            "INSERT INTO accepted_hashes VALUES "
            "(:layer, :owner, :system, :name, :path, :algorithm, :value)",
            _accepted_hash_rows(platform_files, emulator_items),
        )
        connection.executemany(
            "INSERT INTO gaps VALUES "
            "(:layer, :platform_id, :platform, :emulator, :system, :name, "
            ":status, :required, :in_repo, :reason, :discrepancy, :destination, :expected, "
            ":category, :collection_path, :resolved_sha1)",
            gap_rows,
        )
        connection.commit()
        connection.execute("VACUUM")
    finally:
        connection.close()
    os.replace(temp_path, destination)


def write_single_item(
    path: Path, kind: str, item: dict, generated_at: str, commit: str = "",
) -> None:
    """One item in the envelope of its collection, for a page to link."""
    path.parent.mkdir(parents=True, exist_ok=True)
    write_if_changed(
        str(path),
        json.dumps(
            {"schema_version": 1, "generated_at": generated_at,
             **({"commit": commit} if commit else {}), "kind": kind,
             "count": 1, "items": [item]},
            indent=2, sort_keys=True, ensure_ascii=False, default=str,
        ) + "\n",
    )


def system_export_item(slug: str, manufacturer: str, consoles: dict[str, list]) -> dict:
    """A system page's files by console, with the hashes its cards show."""
    fields = ("name", "path", "size", "sha1", "md5", "sha256", "crc32")
    return {
        "id": slug,
        "name": manufacturer,
        "consoles": {
            console: [
                {field: entry[field] for field in fields if entry.get(field) is not None}
                for entry in sorted(entries, key=lambda e: (e.get("name", ""), e.get("sha1", "")))
            ]
            for console, entries in sorted(consoles.items())
        },
    }


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


def _provenance_wanted_rows(db: dict) -> list[dict]:
    """The Wanted list of the provenance page, as rows. A dump the
    collection already produces (derivable.json) is not wanted."""
    derivable = load_derivable()
    rows: list[dict] = []
    for catalog, data in build_report(db, load_provenance_snapshots()).items():
        for entry in data["missing"]:
            if (entry.get("sha1") or "").lower() in derivable:
                continue
            rows.extend({
                "catalog": catalog, "dat": dat,
                **{f: _json_text(entry.get(f)) for f in WANTED_FIELDS[2:]},
            } for dat in entry.get("dats") or [entry.get("dat", "")])
    rows.sort(key=lambda r: (r["catalog"], r["dat"], r["name"], r["sha1"]))
    return rows


def generate_data_exports(
    docs: Path,
    db: dict,
    coverages: dict,
    profiles: dict,
    stats: dict,
    gap_report: dict | None = None,
    consumers: FileConsumers | None = None,
) -> list[dict]:
    """Create versioned static API, CSV and SQLite metadata snapshots."""
    api = docs / "api" / "v1"
    downloads = docs / "downloads"
    schemas_dest = api / "schemas"
    for directory in (api, downloads, schemas_dest):
        directory.mkdir(parents=True, exist_ok=True)

    generated_at = build_timestamp(db)
    # The revision the data was read at: a tool comparing two downloads
    # could not tell which commit each came from.
    commit = source_commit()
    stamp = {"commit": commit} if commit else {}
    platform_items, platform_files = _platform_export_rows(coverages, db)
    emulator_items = _emulator_export_items(profiles)
    gap_rows = _gap_export_rows(coverages, gap_report, db, profiles)
    cross_rows = _cross_reference_export_rows(coverages, profiles)

    members = data_directory_members()
    locations = file_location_items(db, profiles, members)
    wanted = _provenance_wanted_rows(db)
    envelopes = {
        "platforms.json": ("platforms", platform_items),
        "emulators.json": ("emulators", emulator_items),
        "gaps.json": ("verification-and-coverage-gaps", gap_rows),
        "file-locations.json": ("file-locations", locations),
    }
    write_lookup_shards(
        api, file_lookup_records(db, coverages, profiles, locations, members, consumers,
                                 model_retired.load(REPO_ROOT / "retired.json"), wanted),
        generated_at, commit,
    )
    for filename, (kind, items) in envelopes.items():
        document = {
            "schema_version": 1,
            "generated_at": generated_at,
            **stamp,
            "kind": kind,
            "count": len(items),
            "items": items,
        }
        write_if_changed(
            str(api / filename),
            json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        )
    # One platform without the others, as api/v1/emulators/<id>.json is one
    # profile: platforms.json is 2.8 MB for twelve platforms.
    for item in platform_items:
        write_single_item(api / "platforms" / f"{item['id']}.json",
                          "platforms", item, generated_at, commit)
    write_if_changed(str(api / "stats.json"), generate_stats(stats))
    write_if_changed(
        str(api / "database.json"),
        json.dumps(db, ensure_ascii=False, indent=2) + "\n",
    )

    # Every schema the published files are written against, the manifests'
    # too: an integrator had the platform's list and not what the pack writes.
    for schema_path in sorted((REPO_ROOT / "schemas").glob("*.schema.json")):
        shutil.copy2(schema_path, schemas_dest / schema_path.name)
        record_written(schemas_dest / schema_path.name)

    manifest_assets = publish_manifests(api)
    for filename, (kind, items) in {
        "systems.json": ("system-index", system_index_items(db, coverages, profiles)),
        "cores.json": ("core-index", core_index_items(profiles)),
    }.items():
        write_if_changed(str(api / filename), json.dumps({
            "schema_version": 1, "generated_at": generated_at, **stamp,
            "kind": kind, "count": len(items), "items": items,
        }, ensure_ascii=False, indent=2, sort_keys=True) + "\n")

    file_rows = []
    for sha1, entry in sorted(db.get("files", {}).items()):
        file_rows.append({
            "sha1": sha1,
            "path": entry.get("path", ""),
            "name": entry.get("name", ""),
            "size": entry.get("size", 0),
            "md5": entry.get("md5", ""),
            "sha256": entry.get("sha256", ""),
            "crc32": entry.get("crc32", ""),
            "adler32": entry.get("adler32", ""),
            "provenance_catalogs": ";".join(
                sorted((entry.get("provenance") or {}).keys())
            ),
        })
    write_if_changed(str(downloads / "retrobios.dat"), collection_dat(db, generated_at))
    platform_dats = write_platform_dats(downloads / "dat", db, members, generated_at)
    write_if_changed(
        str(downloads / "files.csv"),
        _csv_document(
            [
                "sha1", "path", "name", "size", "md5", "sha256",
                "crc32", "adler32", "provenance_catalogs",
            ],
            file_rows,
        ),
    )
    write_if_changed(
        str(downloads / "platform-files.csv"),
        _csv_document(
            [
                "platform_id", "platform", "system", "name", "destination",
                "required", "region", "selection_slot", "size", "sha1",
                "sha256", "md5", "crc32", "status", "category",
                "collection_path", "resolved_sha1", *ENTRY_EXPORT_FIELDS,
            ],
            platform_files,
        ),
    )
    write_if_changed(
        str(downloads / "cross-reference.csv"),
        _csv_document(
            [
                "platform_id", "platform", "profile_id", "emulator", "core",
                "system", "classification", "type", "source", "upstream",
                "profiled_commit", "file_count",
            ],
            cross_rows,
        ),
    )
    write_if_changed(
        str(downloads / "gaps.csv"),
        _csv_document(
            [
                "layer", "platform_id", "platform", "emulator", "system",
                "name", "status", "required", "in_repo", "reason",
                "discrepancy", "destination", "expected", "category",
                "collection_path", "resolved_sha1",
            ],
            gap_rows,
        ),
    )
    write_if_changed(
        str(downloads / "accepted-hashes.csv"),
        _csv_document(
            ["layer", "owner", "system", "name", "path", "algorithm", "value"],
            _accepted_hash_rows(platform_files, emulator_items),
        ),
    )
    _write_sqlite_export(
        downloads / "retrobios.sqlite", db, platform_items, platform_files,
        emulator_items, gap_rows,
    )
    record_written(downloads / "retrobios.sqlite")
    write_if_changed(
        str(downloads / "provenance-wanted.csv"),
        _csv_document(list(WANTED_FIELDS), wanted),
    )

    assets = [
        (api / "database.json", "Content database", "application/json", "schemas/database.schema.json"),
        (api / "platforms.json", "Platform contracts", "application/json", "schemas/site-api-envelope.schema.json"),
        (api / "emulators.json", "Emulator profiles", "application/json", "schemas/site-api-envelope.schema.json"),
        (api / "gaps.json", "Verification and coverage gaps", "application/json", "schemas/site-api-envelope.schema.json"),
        (api / "file-locations.json", "Where each file's card is, by SHA1", "application/json", "schemas/site-api-envelope.schema.json"),
        (api / "stats.json", "Project statistics", "application/json", "schemas/stats.schema.json"),
        (api / "systems.json", "System ids, their names and sections", "application/json",
         "schemas/site-api-envelope.schema.json"),
        (api / "cores.json", "Core names and the profile each one is", "application/json",
         "schemas/site-api-envelope.schema.json"),
        *manifest_assets,
        (downloads / "files.csv", "File hashes CSV", "text/csv", None),
        (downloads / "retrobios.dat", "Collection DAT (Logiqx XML, for clrmamepro and RomVault)",
         "application/xml", None),
        *((path, f"Setup DAT: {path.stem}", "application/xml", None) for path in platform_dats),
        (downloads / "platform-files.csv", "Platform declarations CSV", "text/csv", None),
        (downloads / "cross-reference.csv", "Cross-reference CSV", "text/csv", None),
        (downloads / "gaps.csv", "Verification and coverage gaps CSV", "text/csv", None),
        (downloads / "accepted-hashes.csv", "Accepted hashes, one row per value", "text/csv", None),
        (downloads / "provenance-wanted.csv", "Catalogued dumps the collection lacks", "text/csv", None),
        (downloads / "retrobios.sqlite", "SQLite snapshot", "application/vnd.sqlite3", None),
        *([(downloads / "measurements.sqlite", "Core probe measurements (SQLite)",
            "application/vnd.sqlite3", None)]
          if (downloads / "measurements.sqlite").is_file() else []),
    ]
    catalog_items: list[dict] = []
    published: list[dict] = []
    for path, title, media_type, schema in assets:
        relative = path.relative_to(docs).as_posix()
        item = {
            "title": title,
            "url": relative,
            "media_type": media_type,
            "bytes": path.stat().st_size,
            "sha256": file_digest(path, "sha256"),
        }
        if schema:
            item["schema"] = schema
        catalog_items.append(item)
        # In the catalog both references resolve against the catalog's own
        # URL, as RFC 3986 clients do: `url` was relative to the site root
        # and `schema` to api/v1/, so no single base resolved both.
        published.append({
            **item,
            "url": os.path.relpath(path, api).replace(os.sep, "/"),
        })
    catalog = {
        "schema_version": 1,
        "generated_at": generated_at,
        **stamp,
        "kind": "catalog",
        "license": DATA_LICENSE,
        "count": len(published),
        "items": published,
    }
    write_if_changed(
        str(api / "catalog.json"),
        json.dumps(catalog, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )
    # api/v1/ itself is a folder GitHub Pages answers with the 404 page: the
    # entry point is a document of its own, naming where to start.
    entry_points = [
        {"title": "Catalog", "url": "catalog.json",
         "description": "Each dataset, manifest, export and download with its size, "
                        "SHA256 and schema. The one-item documents of emulators/, "
                        "platforms/, systems/ and lookup/ are not listed."},
        {"title": "System ids", "url": "systems.json",
         "description": "Each system id with its name and the section holding its files."},
        {"title": "Core names", "url": "cores.json",
         "description": "Each core name and alias with the profile it designates."},
        {"title": "Schemas", "url": "schemas/site-api-envelope.schema.json",
         "description": "The envelope every JSON document of api/v1 shares."},
    ]
    write_if_changed(str(api / "index.json"), json.dumps({
        "schema_version": 1, "generated_at": generated_at, **stamp,
        "kind": "index", "license": DATA_LICENSE,
        "count": len(entry_points), "items": entry_points,
    }, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    return catalog_items
