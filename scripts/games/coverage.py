"""The coverage of the games index: the floors it may not fall below and its printed table."""

from __future__ import annotations

import gzip
from pathlib import Path

# Coverage the published data may not fall below. A rescrape or a DAT import
# that loses rows fails the step instead of shipping a thinner index.
FLOORS = {
    "folders_resolved_share": 0.84,
    "catalog_systems": 30,
    "arcade_profiles": 6,
}


def floor_failures(coverage: dict) -> list[str]:
    total = sum(c["folders"] for c in coverage["setups"].values())
    resolved = sum(c["resolved"] for c in coverage["setups"].values())
    out = []
    share = resolved / total if total else 0.0
    if share < FLOORS["folders_resolved_share"]:
        out.append(f"folders resolved {resolved}/{total} ({share:.1%}) under {FLOORS['folders_resolved_share']:.0%}")
    catalogs = sum(1 for c in coverage["systems"].values() if c["games"])
    if catalogs < FLOORS["catalog_systems"]:
        out.append(f"systems with a game catalog {catalogs} under {FLOORS['catalog_systems']}")
    if len(coverage["arcade"]) < FLOORS["arcade_profiles"]:
        out.append(f"arcade profiles {len(coverage['arcade'])} under {FLOORS['arcade_profiles']}")
    return out


def print_coverage(coverage: dict, files: dict[Path, str]) -> None:
    print("Setups (folders / resolved to a system / default core profiled / with a fallback set):")
    for setup, c in coverage["setups"].items():
        print(f"  {setup:16} {c['folders']:4} {c['resolved']:4} {c['profile']:4} {c['fallback']:4}")
    print("Systems (games by hash / serials / header readers / profiles with region files / extras):")
    for system, c in coverage["systems"].items():
        print(f"  {system:28} {c['games']:6} {c['serials']:6} {c['header_readers']:3} "
              f"{c['region_profiles']:3} {'yes' if c['extras'] else '-'}")
    print(f"Arcade indexes: {', '.join(coverage['arcade']) or 'none'}")
    raw = sum(len(t.encode()) for t in files.values())
    packed = sum(len(gzip.compress(t.encode(), 9, mtime=0)) for t in files.values())
    print(f"{len(files)} files, {raw:,} bytes, {packed:,} bytes gzip")
