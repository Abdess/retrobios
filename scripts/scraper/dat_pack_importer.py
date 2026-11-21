"""Import BIOS entries from a No-Intro or TOSEC DAT pack.

Dat-o-Matic blocks automated downloads and TOSEC ships yearly packs,
so both are imported from a locally downloaded archive:

    python -m scripts.scraper.dat_pack_importer --source no-intro --pack lovepack.zip
    python -m scripts.scraper.dat_pack_importer --source tosec --pack TOSEC-v2025-03-13.zip

No-Intro marks BIOS dumps with a "[BIOS]" game name prefix inside the
system DATs. TOSEC groups firmware into dedicated DATs whose name
contains "Firmware" or "BIOS". Only those entries are imported.
"""

from __future__ import annotations

import argparse
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from model.dumpcatalog import write_provenance_snapshot
from .listxml import iter_dat_documents
from .logiqx_parser import LogiqxDat, parse_logiqx

SOURCES = ("no-intro", "tosec")


def _bios_entries(source: str, dat: LogiqxDat) -> list[dict]:
    """Filter a parsed DAT down to its BIOS/firmware entries."""
    if source == "no-intro":
        roms = [r for r in dat.roms if r.game.startswith("[BIOS]")]
    else:
        dat_name = dat.name.casefold()
        if "firmware" not in dat_name and "bios" not in dat_name:
            return []
        roms = dat.roms
    return dat.provenance_entries(roms)


def import_pack(source: str, pack: Path) -> tuple[dict, list[dict], int]:
    """Import BIOS entries from a pack. Returns (dats, entries, skipped)."""
    dats = {}
    entries = []
    skipped = 0
    for _member, content in iter_dat_documents(pack):
        try:
            dat = parse_logiqx(content)
        except (ValueError, SyntaxError):
            skipped += 1
            continue
        dat_entries = _bios_entries(source, dat)
        if dat_entries:
            dats[dat.name] = dat.version
            entries.extend(dat_entries)
    return dats, entries, skipped


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Import BIOS provenance from a DAT pack")
    parser.add_argument(
        "--source", required=True, choices=SOURCES,
        help="catalog the pack comes from",
    )
    parser.add_argument("--pack", required=True, help="DAT pack (ZIP or directory)")
    parser.add_argument("--output", "-o", help="Snapshot output path")
    parser.add_argument("--dry-run", action="store_true", help="Show imported entries")
    args = parser.parse_args()

    pack = Path(args.pack)
    if not pack.exists():
        print(f"Error: pack '{pack}' not found", file=sys.stderr)
        return 1

    try:
        dats, entries, skipped = import_pack(args.source, pack)
    except zipfile.BadZipFile as e:
        print(f"Error: {pack} is not a valid ZIP archive: {e}", file=sys.stderr)
        return 1

    if not entries:
        print(f"Error: no BIOS entries found in {pack}", file=sys.stderr)
        return 1

    if skipped:
        print(f"  Skipped {skipped} non-Logiqx members")

    if args.dry_run:
        for dat in sorted(dats):
            count = sum(1 for e in entries if e["dat"] == dat)
            print(f"  {dat} ({dats[dat]}): {count} entries")
        print(f"\nTotal: {len(entries)} entries across {len(dats)} DATs")
        return 0

    output = args.output or f"provenance/{args.source}.json"
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    imported_at = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    written = write_provenance_snapshot(output, args.source, imported_at, dats, entries)
    status = "Written" if written else "Unchanged"
    print(f"{status} {output}: {len(entries)} entries from {len(dats)} DATs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
