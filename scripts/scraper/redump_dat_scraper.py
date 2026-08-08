"""Fetch Redump BIOS DAT files and write a provenance snapshot.

Redump serves BIOS DATs as static clrmamepro files linked from
https://redump.info/downloads under /static/bios/. The downloads page
is scanned for those links, so new BIOS DATs are picked up without
code changes.

Run manually, then commit the snapshot:
    python -m scripts.scraper.redump_dat_scraper --dry-run
    python -m scripts.scraper.redump_dat_scraper --output provenance/redump.json
"""

from __future__ import annotations

import argparse
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from ..common import write_provenance_snapshot
from .base_scraper import _read_limited
from .logiqx_parser import parse_logiqx, validate_logiqx_format

BASE_URL = "https://redump.info"
DOWNLOADS_URL = f"{BASE_URL}/downloads"


def _fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "retrobios-scraper/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return _read_limited(resp).decode("utf-8", "replace")
    except urllib.error.URLError as e:
        raise ConnectionError(f"Failed to fetch {url}: {e}") from e


def discover_bios_datfiles(downloads_html: str) -> list[str]:
    """Extract BIOS DAT paths from the downloads page."""
    paths = set(re.findall(r'href="(/static/bios/[^"]+\.dat)"', downloads_html))
    return sorted(paths)


def parse_redump_dat(content: str) -> tuple[str, str, list[dict]]:
    """Parse a Redump Logiqx BIOS DAT into provenance entries.

    The machine description carries the useful context (hardware
    model, kernel or firmware version), so it is kept per entry.
    """
    dat = parse_logiqx(content)
    entries = [
        {
            "dat": dat.name,
            "name": rom.name,
            "description": rom.description,
            "size": rom.size,
            "crc32": rom.crc32,
            "md5": rom.md5,
            "sha1": rom.sha1,
        }
        for rom in dat.roms
    ]
    return dat.name, dat.version, entries


def fetch_snapshot() -> tuple[dict, list[dict]]:
    """Fetch all Redump BIOS DATs. Returns (dats metadata, entries)."""
    paths = discover_bios_datfiles(_fetch(DOWNLOADS_URL))
    if not paths:
        raise ValueError("No BIOS datfile links found on downloads page")
    dats = {}
    entries = []
    for path in paths:
        content = _fetch(f"{BASE_URL}{path}")
        if not validate_logiqx_format(content):
            raise ValueError(f"Unexpected DAT format for {path}")
        name, version, dat_entries = parse_redump_dat(content)
        dats[name] = version
        entries.extend(dat_entries)
    return dats, entries


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch Redump BIOS DAT provenance")
    parser.add_argument("--dry-run", action="store_true", help="Show fetched entries")
    parser.add_argument(
        "--output", "-o", default="provenance/redump.json", help="Snapshot output path"
    )
    args = parser.parse_args()

    try:
        dats, entries = fetch_snapshot()
    except (ConnectionError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if args.dry_run:
        for dat in sorted(dats):
            count = sum(1 for e in entries if e["dat"] == dat)
            print(f"  {dat} ({dats[dat]}): {count} entries")
        print(f"\nTotal: {len(entries)} entries across {len(dats)} DATs")
        return 0

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    imported_at = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    written = write_provenance_snapshot(args.output, "redump", imported_at, dats, entries)
    status = "Written" if written else "Unchanged"
    print(f"{status} {args.output}: {len(entries)} entries from {len(dats)} DATs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
