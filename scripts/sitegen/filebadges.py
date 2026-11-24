"""The chips beside an emulator file's name: need, holding, build, category and region."""

from __future__ import annotations

import html

from core.text import series
from sitegen.install import comes_with_app


# Region slugs whose words are not the slug title-cased, beyond region.LABELS.
_REGION_WORDS = {"world": "every region"}


def region_words(value: object, most: int = 0) -> str:
    """A region: value in words. ``most`` caps the regions named, the rest
    counted: one Saturn BIOS serves seven."""
    raw = value if isinstance(value, list) else [value] if value else []
    from model.region import label

    words = [_REGION_WORDS.get(str(r)) or label(str(r)) for r in raw]
    if most and len(words) > most:
        words = words[:most] + [f"{len(words) - most} more"]
    return series(words)


_CATEGORY_WORDS = {"bios": "BIOS", "game_data": "game data", "bios_zip": "BIOS ZIP"}


def _status_badges(f: dict, in_repo: bool, for_system: str, shipped: bool) -> list[str]:
    """The chips saying whether a file is needed and whether it is held."""
    required = f.get("required", False)
    badges = []
    if shipped:
        # NetherSX2's three interface fonts sat beside the BIOS as
        # "required" and "missing": the app ships them, nobody fetches them.
        # Narrowed to one build, the build is named.
        build = f.get("mode") if f.get("mode") in ("standalone", "libretro") else ""
        label = f"installed with the {build} emulator" if build else "comes with the app"
        badges.append(f'<span class="rb-badge rb-badge-info">{label}</span>')
    elif required:
        needed = f"required for {html.escape(for_system)}" if for_system else "required"
        badges.append(
            f'<span class="rb-badge rb-badge-danger">{needed}</span>'
        )
    else:
        badges.append(
            '<span class="rb-badge rb-badge-muted">optional</span>'
        )
    # Whether the collection holds a file the app ships says nothing to
    # the reader: no status chip.
    if shipped:
        status = ""
    elif in_repo:
        status = '<span class="rb-badge rb-badge-success">in repo</span>'
    elif f.get("unsourceable"):
        status = '<span class="rb-badge rb-badge-muted">unsourceable</span>'
    else:
        status = '<span class="rb-badge rb-badge-warning">missing</span>'
    if status:
        badges.append(status)
    return badges


def file_badges(f: dict, in_repo: bool, for_system: str = "") -> list[str]:
    """The status chips shown beside a file name.

    Fourteen independent optional fields, each contributing at most one
    chip. Kept apart from the rest of the row so the field-by-field
    rendering stays readable. ``for_system`` names the system a required
    file serves, on a profile that runs more than one.
    """
    hle = f.get("hle_fallback", False)
    mode = f.get("mode", "")
    category = f.get("category", "")
    region = f.get("region", "")
    storage = f.get("storage", "")
    embedded = f.get("embedded", False)
    has_builtin = f.get("has_builtin", False)
    archive = f.get("archive", "")
    ftype = f.get("type", "")
    shipped = comes_with_app(f)
    badges = _status_badges(f, in_repo, for_system, shipped)
    if hle:
        badges.append(
            '<span class="rb-badge rb-badge-info">HLE fallback</span>'
        )
    if mode and not (shipped and mode in ("standalone", "libretro")):
        badges.append(
            f'<span class="rb-badge rb-badge-muted">{mode}</span>'
        )
    if category and category != "bios":
        badges.append(
            f'<span class="rb-badge rb-badge-info">{_CATEGORY_WORDS.get(category, category)}</span>'
        )
    if region:
        # Labelled: "optional in repo japan" read as one run-on phrase.
        badges.append(
            f'<span class="rb-badge rb-badge-muted">Region: {region_words(region)}</span>'
        )
    if storage and storage != "embedded":
        badges.append(
            f'<span class="rb-badge rb-badge-muted">{storage}</span>'
        )
    if embedded:
        badges.append(
            '<span class="rb-badge rb-badge-muted">embedded</span>'
        )
    if has_builtin:
        badges.append(
            '<span class="rb-badge rb-badge-info">built-in fallback</span>'
        )
    if archive:
        badges.append(
            f'<span class="rb-badge rb-badge-muted rb-badge-archive">in {archive}</span>'
        )
    if ftype and ftype != "bios":
        badges.append(
            f'<span class="rb-badge rb-badge-muted">{ftype}</span>'
        )

    return badges
