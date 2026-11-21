"""The published system documents: game identification, header readers, region rules and extra files."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from games.inputs import FORMAT_VERSION, load_json, load_optional_yaml
from games.profileindex import Profiles
from model.romfolders import SystemResolver


def _catalogs(directory: Path) -> Iterable[dict]:
    if directory.is_dir():
        for path in sorted(directory.glob("*/*.json")):
            yield load_json(path)


def _add_catalog(doc: dict, catalog: dict) -> None:
    regions_table = catalog["regions"]
    fields = catalog["fields"]
    col = {name: i for i, name in enumerate(fields)}
    ident = doc.setdefault("identify", {"sources": [], "regions": [], "games": [], "serials": {}})
    region_index: dict[tuple[str, ...], int] = {
        tuple(r): i for i, r in enumerate(ident["regions"])
    }

    def reindex(i: int) -> int:
        value = tuple(regions_table[i]) if i is not None and i >= 0 else ()
        if value not in region_index:
            region_index[value] = len(ident["regions"])
            ident["regions"].append(list(value))
        return region_index[value]

    ident["sources"].append({
        k: catalog[k] for k in ("source", "dat", "version", "fetched_from", "licence", "serial_note") if k in catalog
    })
    for row in catalog["games"]:
        region = reindex(row[col["region"]])
        ident["games"].append([row[col["crc32"]], row[col["size"]], region, row[col["title"]]])
        for serial in row[col["serials"]] if "serials" in col else []:
            ident["serials"].setdefault(serial, set()).add(region)


def build_systems(
    resolver: SystemResolver,
    profiles: Profiles,
    used: dict[str, set[str]],
    games: Path,
) -> tuple[dict[str, dict], dict]:
    """Published system documents and per-system coverage.

    `used` holds, per system, the profiles some setup starts for it: their
    region files are published even without a rule of their own.
    """
    headers = load_optional_yaml(games / "headers.yml").get("systems", {})
    extras: dict[str, list[dict]] = {}
    for entry in load_optional_yaml(games / "extras.yml").get("extras", []):
        extras.setdefault(entry["system"], []).append(entry)
    rule_file = load_optional_yaml(games / "regions.yml")
    cases = rule_file.get("cases", {})
    docs: dict[str, dict] = {}

    def doc_for(system: str) -> dict:
        key = resolver.canonical(system)
        return docs.setdefault(key, {"format_version": FORMAT_VERSION, "system": key})

    for catalog in _catalogs(games / "catalogs"):
        _add_catalog(doc_for(catalog["system"]), catalog)
    for doc in docs.values():
        ident = doc.get("identify")
        if ident:
            ident["games"].sort()
            ident["serials"] = {s: sorted(r) for s, r in sorted(ident["serials"].items())}
    for system, spec in headers.items():
        doc_for(system)["headers"] = spec
    for system, entries in extras.items():
        doc_for(system).setdefault("extras", []).extend(entries)
    rule_profiles: dict[str, set[str]] = {}
    for system, spec in rule_file.get("systems", {}).items():
        doc = doc_for(system)
        rules = doc.setdefault("region_rules", {})
        rules.update(spec)
        named = {
            case["case"] for core in spec.values()
            for case in (core.get("keep_all_regions") or []) if isinstance(case, dict)
        }
        if named:
            doc.setdefault("cases", {}).update({c: cases[c] for c in sorted(named) if c in cases})
        rule_profiles.setdefault(doc["system"], set()).update(spec if isinstance(spec, dict) else ())
    for system, names in used.items():
        rule_profiles.setdefault(resolver.canonical(system), set()).update(names)
    for system, names in rule_profiles.items():
        files = {
            name: tagged for name in sorted(names)
            if name in profiles.profiles
            and (tagged := profiles.region_files(name, system))
            and set(tagged) - {"any"}
        }
        if files:
            doc_for(system)["region_files"] = files
    coverage = {
        system: {
            "games": len(doc.get("identify", {}).get("games", [])),
            "serials": len(doc.get("identify", {}).get("serials", {})),
            "header_readers": len((doc.get("headers") or {}).get("readers", {}) or []),
            "region_profiles": len(doc.get("region_files", {})),
            "extras": bool(doc.get("extras")),
        }
        for system, doc in sorted(docs.items())
    }
    return docs, coverage
