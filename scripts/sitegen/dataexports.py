"""The bulk data exports: CSV, JSON and SQLite of the collection, platforms and gaps."""

from __future__ import annotations

import csv
import io
import json
import os
import shutil
import sqlite3
from pathlib import Path

from core.artifacts import build_timestamp
from core.artifacts import json_text as _json_text
from core.hashing import file_digest
from model import retired as model_retired
from packs.consumers import FileConsumers
from sitegen.apiitems import core_index_items, system_index_items
from sitegen.config import DATA_LICENSE, REPO_URL
from core.paths import REPO_ROOT
from sitegen.lookup import (
    data_directory_members,
    file_location_items,
    file_lookup_records,
    write_lookup_shards,
)
from sitegen.provenance import WantedDumps
from sitegen.publish import publish_manifests
from sitegen.structured import write_platform_dats, collection_dat
from sitegen.write import record_written, write_if_changed
from sitegen.exportrows import (
    ENTRY_EXPORT_FIELDS,
    WANTED_FIELDS,
    accepted_hash_rows,
    cross_reference_export_rows,
    emulator_export_items,
    gap_export_rows,
    platform_export_rows,
    provenance_wanted_rows,
    source_commit,
)


def generate_stats(stats: dict) -> str:
    return json.dumps(stats, indent=2) + "\n"


def _csv_document(fieldnames: list[str], rows: list[dict]) -> str:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(
        stream, fieldnames=fieldnames, extrasaction="ignore", lineterminator="\n"
    )
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue()


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
            accepted_hash_rows(platform_files, emulator_items),
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


def generate_data_exports(
    docs: Path,
    db: dict,
    coverages: dict,
    profiles: dict,
    stats: dict,
    gap_report: dict | None = None,
    consumers: FileConsumers | None = None,
    dumps: WantedDumps | None = None,
) -> list[dict]:
    """Create versioned static API, CSV and SQLite metadata snapshots.

    ``dumps`` is the provenance page's own wanted list, so its CSV holds
    the rows the page shows."""
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
    platform_items, platform_files = platform_export_rows(coverages, db)
    emulator_items = emulator_export_items(profiles)
    gap_rows = gap_export_rows(coverages, gap_report, db)
    cross_rows = cross_reference_export_rows(coverages, profiles)

    members = data_directory_members()
    locations = file_location_items(db, profiles, members)
    wanted = provenance_wanted_rows(dumps)
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
            accepted_hash_rows(platform_files, emulator_items),
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
