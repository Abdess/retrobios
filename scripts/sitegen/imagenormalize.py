"""Logos and icons brought to one tile size: rasters squared, SVG checked and minified."""

from __future__ import annotations

import base64
import io
import re
import subprocess
from typing import Any

from core.paths import REPO_ROOT

LOGO_SIZE = 80
ICON_SIZE = 48


def _pillow() -> Any:
    """Pillow's Image and ImageChops, or an exit naming what to install."""
    try:
        from PIL import Image, ImageChops
    except ImportError as exc:
        raise SystemExit("Pillow is needed to normalise raster images: pip install Pillow") from exc
    return Image, ImageChops


def square_image(data: bytes, size: int, kind: str = "PNG", flip: bool = False,
                 trim: bool = False) -> bytes:
    """*flip* mirrors the image top to bottom, for a boot logo stored in the
    row order a device's screen reads (MinUI's). *trim* cuts the plain
    background around the mark, the corner pixel's colour, and keeps that
    colour around it: a 640 x 480 boot screen became a dot."""
    Image, ImageChops = _pillow()
    image = Image.open(io.BytesIO(data)).convert("RGBA")
    if flip:
        image = image.transpose(Image.Transpose.FLIP_TOP_BOTTOM)
    background = (0, 0, 0, 0)
    if trim:
        background = image.getpixel((0, 0))
        # Faint noise in the background is no part of the mark.
        box = (ImageChops.difference(image, Image.new("RGBA", image.size, background))
               .convert("L").point(lambda value: 255 if value > 48 else 0).getbbox())
        if box:
            image = image.crop(box)
        side = round(max(image.size) * 1.2)
        framed = Image.new("RGBA", (side, side), background)
        framed.paste(image, ((side - image.width) // 2, (side - image.height) // 2))
        image = framed
    image.thumbnail((size, size), Image.LANCZOS)
    tile = Image.new("RGBA", (size, size), background)
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
    return head.startswith((b"<?xml", b"<svg"))


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
        Image, _ = _pillow()
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
SVGO = REPO_ROOT / "website" / "node_modules" / ".bin" / "svgo"


def minify_svg(data: bytes) -> bytes:
    if not SVGO.is_file():
        raise SystemExit("svgo is needed to minify SVG logos: npm ci --prefix website")
    result = subprocess.run([str(SVGO), "--multipass", "-i", "-", "-o", "-"],
                            input=data, capture_output=True, check=True)
    return result.stdout
