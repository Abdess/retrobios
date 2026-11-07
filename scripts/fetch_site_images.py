#!/usr/bin/env python3
"""Download the platform logos and system icons the site shows, once.

The site served these from other hosts: GitHub avatars and files on the
``master`` branch of upstream repositories. A rename upstream broke an image
in silence, and every page view hit third-party hosts. This tool copies them
into ``docs_assets/logos/`` and ``docs_assets/system-icons/``, which are
committed, and records where each came from in a ``sources.json`` beside
them. The site build only reads those copies (``sitediagrams.localize_images``).

Raster logos are normalised to an 80 px square WebP, twice the 40 px they
are shown at, and system icons to a 48 px PNG, so every tile has the same
weight. SVG is minified by svgo, and a raster an SVG embeds is cut to the
tile size.
Normalising needs Pillow. This is a maintenance tool run by hand when a
logo changes, not a build step: the build stays on the standard library
and PyYAML.

    python scripts/fetch_site_images.py              # logos and icons
    python scripts/fetch_site_images.py --only logos
"""

from __future__ import annotations

import argparse
import base64
import io
import json
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

LOGO_DIR = ROOT / "docs_assets" / "logos"
ICON_DIR = ROOT / "docs_assets" / "system-icons"
LOGO_SIZE = 80
ICON_SIZE = 48
AVATAR_HOST = "avatars.githubusercontent.com"
USER_AGENT = "retrobios-site-images"

def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def square_image(data: bytes, size: int, kind: str = "PNG") -> bytes:
    try:
        from PIL import Image
    except ImportError as exc:
        raise SystemExit("Pillow is needed to normalise raster images: pip install Pillow") from exc
    image = Image.open(io.BytesIO(data)).convert("RGBA")
    image.thumbnail((size, size), Image.LANCZOS)
    tile = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    tile.paste(image, ((size - image.width) // 2, (size - image.height) // 2), image)
    out = io.BytesIO()
    if kind == "WEBP":
        # Quality 90: half the bytes of lossless, edges still clean at 40 px.
        tile.save(out, "WEBP", quality=90, method=6)
    else:
        tile.save(out, "PNG", optimize=True)
    return out.getvalue()


def is_svg(data: bytes) -> bool:
    head = data[:512].lstrip().lower()
    return head.startswith(b"<?xml") or head.startswith(b"<svg")


def safe_svg(data: bytes, url: str) -> bytes:
    lowered = data.lower()
    for token in (b"<script", b"javascript:", b"onload=", b"<foreignobject"):
        if token in lowered:
            raise SystemExit(f"{url}: SVG carries {token.decode()}, not copied")
    return data


# A raster inside an SVG logo: RetroDECK's icon carried a 441 x 334 PNG,
# 9 KiB of a mark drawn 40 px wide. It never needs more pixels than the
# whole tile.
EMBEDDED_RASTER = re.compile(rb'data:image/(?:png|jpeg|webp);base64,([A-Za-z0-9+/=\s]+)')


def shrink_embedded(data: bytes) -> bytes:
    """Each raster an SVG embeds, at most LOGO_SIZE pixels on its longest side."""

    def shrink(match: re.Match[bytes]) -> bytes:
        try:
            from PIL import Image
        except ImportError as exc:
            raise SystemExit("Pillow is needed to normalise raster images: pip install Pillow") from exc
        image = Image.open(io.BytesIO(base64.b64decode(re.sub(rb"\s", b"", match.group(1))))).convert("RGBA")
        if max(image.size) <= LOGO_SIZE:
            return match.group(0)
        image.thumbnail((LOGO_SIZE, LOGO_SIZE), Image.LANCZOS)
        out = io.BytesIO()
        image.save(out, "PNG", optimize=True)
        return b"data:image/png;base64," + base64.b64encode(out.getvalue())

    return EMBEDDED_RASTER.sub(shrink, data)


# Editor markup (Inkscape's namedview, sodipodi attributes, metadata) was
# most of the bytes of two logos. svgo comes with the site's packages.
SVGO = ROOT / "website" / "node_modules" / ".bin" / "svgo"


def minify_svg(data: bytes) -> bytes:
    if not SVGO.is_file():
        raise SystemExit("svgo is needed to minify SVG logos: npm ci --prefix website")
    result = subprocess.run([str(SVGO), "--multipass", "-i", "-", "-o", "-"],
                            input=data, capture_output=True, check=True)
    return result.stdout


def write_manifest(directory: Path, note: str, entries: list[dict]) -> None:
    entries.sort(key=lambda entry: entry["file"])
    document = {"note": note, "images": entries}
    (directory / "sources.json").write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def fetch_logos() -> None:
    from siteguides import GUIDES

    with open(ROOT / "platforms" / "_registry.yml", encoding="utf-8") as handle:
        platforms = yaml.safe_load(handle)["platforms"]
    LOGO_DIR.mkdir(parents=True, exist_ok=True)
    entries = []
    for name, entry in sorted(platforms.items()):
        url = entry.get("logo")
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
            file_name, payload = f"{name}.webp", square_image(data, LOGO_SIZE, "WEBP")
        for stale in LOGO_DIR.glob(f"{name}.*"):
            if stale.name != file_name:
                stale.unlink()
        (LOGO_DIR / file_name).write_bytes(payload)
        # Who owns each mark: logo_owner and logo_licence in the guides.
        guide = GUIDES.get(name)
        owner = (guide and guide.logo_owner) or name
        licence = (guide and guide.logo_licence) or "ownership not recorded"
        entries.append({
            "file": file_name, "platform": name, "source": url,
            "owner": owner, "licence": licence,
        })
        print(f"  {file_name} from {url}")
    write_manifest(
        LOGO_DIR,
        "Each platform's own logo, owned by its project and shown only to name that "
        "platform. Copied once by scripts/fetch_site_images.py.",
        entries,
    )


def fetch_icons() -> None:
    from common import load_database
    from sitecollection import _group_by_manufacturer
    from siterender import SYSTEM_ICON_BASE, _icon_name

    db = load_database(str(ROOT / "database.json"))
    names = sorted({
        _icon_name(manufacturer, console)
        for manufacturer, consoles in _group_by_manufacturer(db).items()
        for console in consoles
    })
    ICON_DIR.mkdir(parents=True, exist_ok=True)
    entries = []
    for name in names:
        url = f"{SYSTEM_ICON_BASE}/{urllib.parse.quote(name)}.png"
        try:
            data = fetch(url)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                continue
            raise
        file_name = f"{name}.png"
        (ICON_DIR / file_name).write_bytes(square_image(data, ICON_SIZE))
        entries.append({"file": file_name, "source": url})
        print(f"  {file_name}")
    write_manifest(
        ICON_DIR,
        "System icons from libretro/retroarch-assets (xmb/systematic), "
        "licensed CC-BY-4.0 by the libretro team. Resized to 48 px.",
        entries,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], allow_abbrev=False)
    parser.add_argument("--only", choices=("logos", "icons"), help="fetch one kind only")
    args = parser.parse_args()
    if args.only in (None, "logos"):
        print("Platform logos:")
        fetch_logos()
    if args.only in (None, "icons"):
        print("System icons:")
        fetch_icons()


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
