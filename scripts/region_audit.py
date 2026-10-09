"""Cross-check profile region: values against dump-catalog provenance.

Advisory only. The emulator source decides what a region: value should be; this
reports where an independent catalogue disagrees, so a hand-written value gets a
second opinion before it is trusted.

Read the limits printed in the header before acting on anything here.
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import region
from common import load_database, load_emulator_profiles, resolve_local_file

# No-Intro filename tokens: full English territory names.
NOINTRO = {
    "World": "world",
    "USA": "north-america",
    "Canada": "canada",
    "Europe": "europe",
    "Japan": "japan",
    "Asia": "asia",
    "Korea": "south-korea",
    "Brazil": "brazil",
    "Taiwan": "taiwan",
    "China": "china",
    "Hong Kong": "hong-kong",
    "France": "france",
    "Germany": "germany",
    "Spain": "spain",
    "Italy": "italy",
    "Netherlands": "netherlands",
    "Sweden": "sweden",
    "Norway": "norway",
    "Denmark": "denmark",
    "Finland": "finland",
    "Australia": "australia",
    "New Zealand": "new-zealand",
    "Russia": "russia",
    "UK": "uk",
    "Portugal": "portugal",
    "Greece": "greece",
    "Poland": "poland",
    "India": "india",
    "Mexico": "mexico",
    "Argentina": "argentina",
    "Latin America": "latin-america",
}

_PAREN = re.compile(r"\(([^)]+)\)")

LIMITS = """Limits, read before trusting any line below.

  TOSEC's country field is the country of ORIGIN, not the regional variant
  (TOSEC Naming Convention v4, p.12). A Korean MSX ROM published by Microsoft
  US is tagged (US). TOSEC names are therefore NOT read here.

  Redump DATs carry no region at all: it exists in the redump.org database but
  is never exported, so a Redump entry contributes nothing.

  Only No-Intro filename tokens are usable, and only for the fraction of repo
  files that carry one. Everything else is silent, not clean.

  The emulator source decides. A disagreement is a prompt to reread the code,
  never a correction to apply on its own.
"""


def tokens_from_name(name: str) -> set[str]:
    """Extract geography slugs from a No-Intro style DAT entry name."""
    found: set[str] = set()
    for group in _PAREN.findall(name):
        for part in (p.strip() for p in group.split(",")):
            slug = NOINTRO.get(part)
            if slug:
                found.add(slug)
    return found


def catalog_regions(db: dict) -> dict[str, tuple[set[str], str]]:
    """Map SHA1 to (geography slugs, source label) from No-Intro provenance."""
    out: dict[str, tuple[set[str], str]] = {}
    for sha1, record in db["files"].items():
        entry = (record.get("provenance") or {}).get("no-intro")
        if not entry:
            continue
        name = entry.get("name", "")
        found = tokens_from_name(name)
        if found:
            out[sha1] = (found, name)
    return out


def resolve_sha1(file_entry: dict, db: dict, by_path: dict | None = None) -> str | None:
    """The repo SHA1 a profile entry resolves to, by the pack's own resolver.

    A private resolver read sha1, then md5, then a lone name: entries that
    identify their file by path (Dolphin's three IPL.bin), by crc32
    (geargrafx) or by sha256 (mednafen) were never checked at all.
    """
    if by_path is None:
        by_path = {entry.get("path", ""): sha1 for sha1, entry in db["files"].items()}
    path, status = resolve_local_file(
        file_entry, db, dest_hint=file_entry.get("path") or ""
    )
    if not path or status in ("not_found", "hash_mismatch"):
        return None
    return by_path.get(path)


def build_report(profiles: dict, db: dict) -> dict:
    """Compare every declared region: against the No-Intro catalogue."""
    catalog = catalog_regions(db)
    agree = 0
    unchecked = 0
    conflicts: list[dict] = []
    vocabulary: collections.Counter = collections.Counter()
    for slugs, _name in catalog.values():
        vocabulary.update(slugs)

    by_path = {entry.get("path", ""): sha1 for sha1, entry in db["files"].items()}
    for emu_name, profile in sorted(profiles.items()):
        if profile.get("type") in ("launcher", "alias"):
            continue
        for f in profile.get("files") or []:
            if not isinstance(f, dict) or not f.get("region"):
                continue
            declared = region.normalize_declared(f["region"])
            sha1 = resolve_sha1(dict(f, source_profile=emu_name), db, by_path)
            if not sha1 or sha1 not in catalog:
                unchecked += 1
                continue
            found, name = catalog[sha1]
            if region.WORLD in declared or any(
                region.comparable(d, c) for d in declared for c in found
            ):
                agree += 1
                continue
            conflicts.append(
                {
                    "emulator": emu_name,
                    "file": f.get("name", ""),
                    "profile": sorted(declared),
                    "catalog": sorted(found),
                    "dat_name": name,
                }
            )
    return {
        "agree": agree,
        "disagree": len(conflicts),
        "unchecked": unchecked,
        "catalog_files": len(catalog),
        "repo_files": len(db["files"]),
        "vocabulary": dict(vocabulary.most_common()),
        "conflicts": conflicts,
    }


def print_report(report: dict) -> None:
    print(LIMITS)
    print(
        f"repo files: {report['repo_files']}   "
        f"with a usable No-Intro region token: {report['catalog_files']}"
    )
    print(
        f"declared region: values -> agree {report['agree']}, "
        f"disagree {report['disagree']}, no catalogue entry {report['unchecked']}"
    )
    if report["vocabulary"]:
        print("\ncatalogue vocabulary present in this collection:")
        for slug, count in report["vocabulary"].items():
            print(f"  {count:5d}  {slug}")
    if not report["conflicts"]:
        print("\nNo disagreement.")
        return
    print("\nDISAGREEMENTS (reread the emulator source, do not apply blindly):\n")
    for c in report["conflicts"]:
        print(f"  {c['emulator']}: {c['file']}")
        print(f"    profile:   {c['profile']}")
        print(f"    catalogue: {c['catalog']}  ({c['dat_name']})")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Cross-check profile region: values against No-Intro provenance"
    )
    parser.add_argument("--db", default="database.json", help="Path to database.json")
    parser.add_argument("--emulators-dir", default="emulators")
    parser.add_argument("--json", action="store_true", help="Machine-readable output")
    args = parser.parse_args()

    db = load_database(args.db)
    profiles = load_emulator_profiles(args.emulators_dir)
    report = build_report(profiles, db)

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
