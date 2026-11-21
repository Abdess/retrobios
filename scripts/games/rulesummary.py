"""What games/regions.yml and games/extras.yml hold, counted for a report."""

from __future__ import annotations


def summary(regions: dict, extras: dict) -> dict:
    keeps = [
        {"case": keep["case"], "system": system, "profile": name, "condition": keep["condition"]}
        for system, cores in sorted((regions.get("systems") or {}).items())
        for name, rule in sorted(cores.items())
        for keep in rule.get("keep_all_regions") or []
    ]
    systems = regions.get("systems") or {}
    return {
        "region_systems": len(systems),
        "region_cores": sum(len(c) for c in systems.values()),
        "cases": sorted(regions.get("cases") or {}),
        "case_entries": keeps,
        "extras": len(extras.get("extras") or []),
        "extra_systems": sorted({e["system"] for e in extras.get("extras") or []}),
    }
