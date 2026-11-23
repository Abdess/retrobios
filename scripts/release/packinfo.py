"""What download.py prints about one platform's pack, or about its absence from a release."""

from __future__ import annotations

import sys
from typing import NoReturn

from core.sizes import size_text
from core.text import count_text
from release.packgroups import find_pack, list_platforms

# A release publishes packs for the setups most people download. The others
# are served file by file by the installer.
NO_PACK_HINT = (
    "A setup without a pack is served by the installer:\n"
    "  curl -fsSL https://abdess.github.io/retrobios/i | sh -s -- --platform <name>"
)


def exit_without_pack(platform: str, release: dict) -> NoReturn:
    """Name the packs the release holds and point to the installer, exit 1."""
    print(f"Platform '{platform}' not found in release.")
    print("Available:", ", ".join(list_platforms(release)))
    print(NO_PACK_HINT)
    sys.exit(1)


def show_info(platform: str, release: dict, record: dict) -> None:
    """Show pack information for a platform, the record naming its pack."""
    pack = find_pack(release, platform, record)
    if not pack:
        exit_without_pack(platform, release)

    print(f"  Platform: {pack.platform}")
    print(f"  File: {pack.name}")
    print(f"  Parts: {count_text(len(pack.parts), 'part')}")
    print(f"  Size: {pack.size:,} bytes ({size_text(pack.size)})")
    for part in pack.parts:
        print(f"    {part['name']} ({part.get('size', 0):,} bytes)")
