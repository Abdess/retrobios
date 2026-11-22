"""The platform logos and system icons the site shows, copied once into docs_assets/."""

from __future__ import annotations

import json
import re
import urllib.parse
from collections.abc import Iterator
from pathlib import Path

from core.paths import DB_FILE, PLATFORMS_DIR, REPO_ROOT
from model.collection import group_by_manufacturer
from model.database import load_database
from model.guides import group_tiles, platform_guides
from model.registry import load_platform_registry
from scraper.base_scraper import FetchError, fetch_bytes
from sitegen.imagenormalize import (
    ICON_SIZE,
    LOGO_SIZE,
    is_svg,
    minify_svg,
    safe_svg,
    shrink_embedded,
    square_image,
)
from sitegen.render import SYSTEM_ICON_BASE, console_icon_name

LOGO_DIR = REPO_ROOT / "docs_assets" / "logos"
ICON_DIR = REPO_ROOT / "docs_assets" / "system-icons"
AVATAR_HOST = "avatars.githubusercontent.com"
USER_AGENT = "retrobios-site-images"


def fetch(url: str) -> bytes:
    """A GET retried on a rate limit or a dropped connection: one 429
    midway left icons rewritten under a sources.json of the previous run."""
    return fetch_bytes(url, {"User-Agent": USER_AGENT}, timeout=60)


def write_manifest(directory: Path, note: str, entries: list[dict]) -> None:
    entries.sort(key=lambda entry: entry["file"])
    document = {"note": note, "images": entries}
    (directory / "sources.json").write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def fetch_logos() -> Iterator[tuple[str, str]]:
    """Each logo as it is written, (file name, source URL). sources.json is
    written after the last one."""
    platforms = load_platform_registry(REPO_ROOT / PLATFORMS_DIR, required=True)
    LOGO_DIR.mkdir(parents=True, exist_ok=True)
    entries = []
    # The tiles of a kind of device (Android handhelds) beside the setups
    # carry a logo too, named after the tile.
    sources = [(name, entry.get("logo"), entry, platform_guides().get(name))
               for name, entry in sorted(platforms.items())]
    sources += [(re.sub(r"[^a-z0-9]+", "-", tile.name.lower()).strip("-"), tile.logo, {}, tile)
                for tiles in group_tiles().values() for tile in tiles]
    for name, url, entry, guide in sources:
        if not url:
            # No logo of its own: the tile shows initials, and an old copy
            # would still be served.
            for stale in LOGO_DIR.glob(f"{name}.*"):
                stale.unlink()
            continue
        download = f"{url}?s={LOGO_SIZE * 2}" if AVATAR_HOST in url else url
        data = fetch(download)
        if is_svg(data):
            file_name, payload = f"{name}.svg", minify_svg(shrink_embedded(safe_svg(data, url)))
        else:
            file_name, payload = f"{name}.webp", square_image(
                data, LOGO_SIZE, "WEBP", flip=bool(entry.get("logo_flip")),
                trim=bool(entry.get("logo_trim")))
        for stale in LOGO_DIR.glob(f"{name}.*"):
            if stale.name != file_name:
                stale.unlink()
        (LOGO_DIR / file_name).write_bytes(payload)
        # Who owns each mark: logo_owner and logo_licence in the guides.
        owner = (guide and guide.logo_owner) or name
        licence = (guide and guide.logo_licence) or "ownership not recorded"
        entries.append({
            "file": file_name, "platform": name, "source": url,
            "owner": owner, "licence": licence,
        })
        yield file_name, url
    write_manifest(
        LOGO_DIR,
        "Each platform's own logo, owned by its project and shown only to name that "
        "platform. Copied once by scripts/fetch_site_images.py.",
        entries,
    )


def fetch_icons() -> Iterator[str]:
    """Each icon's file name as it is written, the systems libretro draws no
    icon for skipped. sources.json is written after the last one."""
    db = load_database(str(REPO_ROOT / DB_FILE))
    names = sorted({
        console_icon_name(manufacturer, console)
        for manufacturer, consoles in group_by_manufacturer(db).items()
        for console in consoles
    })
    ICON_DIR.mkdir(parents=True, exist_ok=True)
    entries = []
    for name in names:
        url = f"{SYSTEM_ICON_BASE}/{urllib.parse.quote(name)}.png"
        try:
            data = fetch(url)
        except FetchError as exc:
            if exc.status == 404:
                continue
            raise
        file_name = f"{name}.png"
        (ICON_DIR / file_name).write_bytes(square_image(data, ICON_SIZE))
        entries.append({"file": file_name, "source": url})
        yield file_name
    write_manifest(
        ICON_DIR,
        "System icons from libretro/retroarch-assets (xmb/systematic), "
        "licensed CC-BY-4.0 by the libretro team. Resized to 48 px.",
        entries,
    )
