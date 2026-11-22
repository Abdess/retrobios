"""Diagrams for the site, written as SVG from the repository's own data."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from xml.sax.saxutils import escape

from model.registry import load_platform_registry
from model.sources import source_yaml_file
from core.text import count_text
from model import siteinputs
from sitegen import markup
from orchestrate.labels import STEP_LABELS


FONT = "system-ui, -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif"
# The stylesheet sets the page font on every <text>, so a path takes the
# mono font from an inline style, which outranks it.
MONO_STYLE = "font-family: var(--sl-font-mono, ui-monospace, SFMono-Regular, Menlo, monospace)"
WIDE = 720
NARROW = 340
# The wide drawing is scaled to a column about 700 px wide: these sizes read
# at 14 px of body text there, the size of the prose around the figure.
COLUMN = 700
TEXT_SIZE = round(14 * WIDE / COLUMN, 1)
TITLE_SIZE = round(15 * WIDE / COLUMN, 1)
LINE = 20
PAD = 12
# A box holds a title and at most this many lines: the rest is the caption's.
MAX_BOX_LINES = 3

# Default colours for an SVG read outside the page. The stylesheet replaces
# them on the site through the rb-d-* classes.
INK = "#1f2233"
FILL = "#f5f6fa"
STROKE = "#8c92ac"
ACCENT = "#3b3f7a"
MUTED = "#546e7a"


class Mono(str):
    """A path or a name typed as is: drawn in the mono font on a line of its
    own, never broken."""


def _width(text: str, size: float, bold: bool = False) -> float:
    """Rough advance of a string: 0.56 em a character, 0.6 bold or mono."""
    return len(text) * size * (0.6 if bold or isinstance(text, Mono) else 0.56)


def wrap(text: str, width: float, size: float, bold: bool = False) -> list[str]:
    """Greedy word wrap against the estimated advance. A Mono line stays whole."""
    if isinstance(text, Mono):
        return [text]
    lines: list[str] = []
    current = ""
    for word in text.split():
        candidate = f"{current} {word}".strip()
        if current and _width(candidate, size, bold) > width:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    return lines


def svg_number(value: float) -> str:
    text = f"{value:.1f}"
    return text[:-2] if text.endswith(".0") else text


@dataclass
class Box:
    title: str
    lines: list[str] = field(default_factory=list)
    accent: bool = False
    number: str = ""


@dataclass
class Figure:
    """One diagram: what it shows, said twice (alt and caption), and drawn twice."""

    image_id: str
    title: str
    desc: str
    caption: str
    wide: Callable[[], tuple[float, float, list[str]]]
    narrow: Callable[[], tuple[float, float, list[str]]]


# Drawing primitives


def svg_text(x: float, y: float, value: str, size: float = TEXT_SIZE,
          bold: bool = False, anchor: str = "start", cls: str = "") -> str:
    weight = ' font-weight="600"' if bold else ""
    klass = f' class="{cls}"' if cls else ""
    style = f' style="{MONO_STYLE}"' if isinstance(value, Mono) else ""
    fill = MUTED if cls == "rb-d-muted" else ("#ffffff" if cls == "rb-d-numtext" else INK)
    return (
        f'<text x="{svg_number(x)}" y="{svg_number(y)}" font-size="{svg_number(size)}"{weight} '
        f'text-anchor="{anchor}" fill="{fill}"{klass}{style}>{escape(value)}</text>'
    )


def svg_rect(x: float, y: float, w: float, h: float, accent: bool = False) -> str:
    cls = "rb-d-box rb-d-accent" if accent else "rb-d-box"
    stroke = ACCENT if accent else STROKE
    width = 2 if accent else 1
    return (
        f'<rect x="{svg_number(x)}" y="{svg_number(y)}" width="{svg_number(w)}" height="{svg_number(h)}" rx="4" '
        f'fill="{FILL}" stroke="{stroke}" stroke-width="{width}" class="{cls}"/>'
    )


def badge_side(number: str) -> float:
    return max(20.0, _width(number, 11, True) + 10)


def badge(x: float, y: float, number: str) -> list[str]:
    side = badge_side(number)
    return [
        f'<rect x="{svg_number(x)}" y="{svg_number(y)}" width="{svg_number(side)}" height="20" rx="3" '
        f'fill="{ACCENT}" class="rb-d-num"/>',
        svg_text(x + side / 2, y + 14, number, 11, True, "middle", "rb-d-numtext"),
    ]


def svg_connector(points: list[tuple[float, float]], head: bool = True) -> list[str]:
    """A connector through *points*, with a drawn arrowhead at the end.

    The head is a small triangle, never a text glyph.
    """
    path = " ".join(
        f"{'M' if index == 0 else 'L'}{svg_number(x)} {svg_number(y)}" for index, (x, y) in enumerate(points)
    )
    out = [
        f'<path d="{path}" fill="none" stroke="{STROKE}" stroke-width="1.5" class="rb-d-line"/>'
    ]
    if head and len(points) >= 2:
        (x1, y1), (x2, y2) = points[-2], points[-1]
        if x1 == x2:
            sign = 1 if y2 > y1 else -1
            tri = [(x2, y2), (x2 - 5, y2 - 8 * sign), (x2 + 5, y2 - 8 * sign)]
        else:
            sign = 1 if x2 > x1 else -1
            tri = [(x2, y2), (x2 - 8 * sign, y2 - 5), (x2 - 8 * sign, y2 + 5)]
        out.append(
            '<path d="M' + " L".join(f"{svg_number(x)} {svg_number(y)}" for x, y in tri)
            + f' Z" fill="{STROKE}" class="rb-d-head"/>'
        )
    return out


def box_lines(box: Box, width: float) -> tuple[list[str], list[str]]:
    """The title and body lines of *box* drawn *width* wide, as wrapped."""
    inner = width - 2 * PAD
    title_lines = wrap(box.title, inner - (badge_side(box.number) + 8 if box.number else 0),
                       TITLE_SIZE, True)
    body: list[str] = []
    for line in box.lines:
        body.extend(wrap(line, inner, TEXT_SIZE))
    return title_lines, body


def _box_height(box: Box, width: float) -> tuple[list[str], list[str], float]:
    title_lines, body = box_lines(box, width)
    height = PAD + len(title_lines) * LINE + (6 if body else 0) + len(body) * LINE + PAD
    if box.number:
        height = max(height, PAD * 2 + 20)
    return title_lines, body, height + 2


def _draw_box(box: Box, x: float, y: float, width: float, height: float,
              title_lines: list[str], body: list[str]) -> list[str]:
    out = [svg_rect(x, y, width, height, box.accent)]
    tx = x + PAD
    if box.number:
        out.extend(badge(x + PAD, y + PAD, box.number))
        tx += badge_side(box.number) + 8
    cy = y + PAD + 15
    for line in title_lines:
        out.append(svg_text(tx, cy, line, TITLE_SIZE, True))
        cy += LINE
    cy += 6
    for line in body:
        out.append(svg_text(x + PAD, cy, line, TEXT_SIZE, cls="rb-d-muted"))
        cy += LINE
    return out


def flow(boxes: list[Box], vertical: bool, total: float) -> tuple[float, float, list[str]]:
    """Boxes joined in order: a row on a wide screen, a column on a narrow one."""
    out: list[str] = []
    if vertical:
        width = total
        y = 1.0
        measured = [_box_height(box, width - 2) for box in boxes]
        height = max(m[2] for m in measured)
        for index, (box, (title_lines, body, _)) in enumerate(zip(boxes, measured)):
            out.extend(_draw_box(box, 1, y, width - 2, height, title_lines, body))
            y += height
            if index < len(boxes) - 1:
                out.extend(svg_connector([(width / 2, y), (width / 2, y + 22)]))
                y += 24
        return width, y + 1, out
    gap = 26.0
    width = (total - gap * (len(boxes) - 1) - 2) / len(boxes)
    measured = [_box_height(box, width) for box in boxes]
    height = max(m[2] for m in measured)
    for index, (box, (title_lines, body, _)) in enumerate(zip(boxes, measured)):
        x = 1 + index * (width + gap)
        # One height for the row: boxes as tall as their own lines made four
        # sizes side by side.
        out.extend(_draw_box(box, x, 1, width, height, title_lines, body))
        if index < len(boxes) - 1:
            mid = 1 + height / 2
            out.extend(svg_connector([(x + width, mid), (x + width + gap - 1, mid)]))
    return total, height + 2, out


def columns(boxes: list[Box], vertical: bool, total: float) -> tuple[float, float, list[str]]:
    """Side-by-side boxes with no order between them."""
    out: list[str] = []
    if vertical:
        y = 1.0
        measured = [_box_height(box, total - 2) for box in boxes]
        height = max(m[2] for m in measured)
        for box, (title_lines, body, _) in zip(boxes, measured):
            out.extend(_draw_box(box, 1, y, total - 2, height, title_lines, body))
            y += height + 12
        return total, y - 11, out
    gap = 16.0
    width = (total - gap * (len(boxes) - 1) - 2) / len(boxes)
    measured = [_box_height(box, width) for box in boxes]
    height = max(m[2] for m in measured)
    for index, (box, (title_lines, body, _)) in enumerate(zip(boxes, measured)):
        out.extend(_draw_box(box, 1 + index * (width + gap), 1, width, height, title_lines, body))
    return total, height + 2, out


def grid(boxes: list[Box], per_row: int, total: float) -> tuple[float, float, list[str]]:
    """Ordered boxes in rows, each row joined to the next by an elbow line."""
    out: list[str] = []
    gap_x, gap_y = 18.0, 30.0
    width = (total - gap_x * (per_row - 1) - 2) / per_row
    rows = [boxes[i:i + per_row] for i in range(0, len(boxes), per_row)]
    y = 1.0
    previous_end: tuple[float, float] | None = None
    for row in rows:
        measured = [_box_height(box, width) for box in row]
        height = max(m[2] for m in measured)
        for index, (box, (title_lines, body, _)) in enumerate(zip(row, measured)):
            x = 1 + index * (width + gap_x)
            if previous_end is not None and index == 0:
                px, py = previous_end
                out.extend(svg_connector([(px, py), (px, py + gap_y / 2), (x + width / 2, py + gap_y / 2),
                                  (x + width / 2, y)]))
            out.extend(_draw_box(box, x, y, width, height, title_lines, body))
            if index < len(row) - 1:
                out.extend(svg_connector([(x + width, y + height / 2), (x + width + gap_x - 1, y + height / 2)]))
            previous_end = (x + width / 2, y + height)
        y += height + gap_y
    return total, y - gap_y + 1, out


def svg_document(width: float, height: float, title: str, desc: str, body: list[str],
                 base: str) -> str:
    """A drawing as a standalone, accessible SVG element."""
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {svg_number(width)} {svg_number(height)}" '
        f'width="{svg_number(width)}" height="{svg_number(height)}" role="img" '
        f'aria-labelledby="{base}-t {base}-d" font-family="{FONT}">'
        f'<title id="{base}-t">{escape(title)}</title>'
        f'<desc id="{base}-d">{escape(desc)}</desc>'
        + "".join(body)
        + "</svg>"
    )


def svg(figure: Figure, layout: str, suffix: str = "") -> str:
    """One layout of *figure* as a standalone, accessible SVG element."""
    width, height, body = (figure.wide if layout == "wide" else figure.narrow)()
    return svg_document(width, height, figure.title, figure.desc, body,
                        f"rb-fig-{figure.image_id}{suffix}-{layout}")


# The colours retrobios.css gives a diagram, per theme: --rb-diagram-* and
# --rb-text-secondary, then the text and background Starlight resolves
# --sl-color-text and --sl-color-bg to (props.css: gray-2 and black, whose
# values swap with the theme). An SVG shown through <img> reads none of them.
THEMES: dict[str, dict[str, str]] = {
    "dark": {"text": "#c1c3c8", "bg": "#17181c", "fill": "#252838", "stroke": "#7c82a3",
             "accent": "#aebcff", "muted": "#a6adc8"},
    "light": {"text": "#353841", "bg": "#ffffff", "fill": "#f5f6fa", "stroke": "#8c92ac",
              "accent": "#3b3f7a", "muted": "#546e7a"},
}
# Where the files are served, under the site's public folder.
DIAGRAM_DIR = "assets/diagrams"
# retrobios.css shows the narrow layout below this width.
NARROW_MEDIA = "(max-width: 37.5em)"


def themed(document: str, theme: str) -> str:
    """*document* with the theme's colours, the rules retrobios.css gives
    the .rb-diagram classes on the page."""
    c = THEMES[theme]
    style = (
        f"<style>svg{{color:{c['text']}}}text{{font-family:{FONT};fill:currentColor}}"
        f".rb-d-box{{fill:{c['fill']};stroke:{c['stroke']}}}.rb-d-accent{{stroke:{c['accent']}}}"
        f".rb-d-line{{stroke:{c['stroke']}}}.rb-d-head{{fill:{c['stroke']}}}"
        f".rb-d-num{{fill:{c['accent']}}}.rb-d-numtext{{fill:{c['bg']}}}"
        f".rb-d-muted{{fill:{c['muted']}}}</style>"
    )
    head = document.index(">") + 1
    return document[:head] + style + document[head:]


def _size(document: str) -> tuple[str, str]:
    match = re.match(r'<svg [^>]*?width="([\d.]+)" height="([\d.]+)"', document)
    if not match:
        raise ValueError("an SVG document without its size")
    return match.group(1), match.group(2)


def diagram_files(stem: str, layouts: dict[str, str]) -> dict[str, str]:
    """The files of one drawing: *layouts* maps wide and narrow to its SVG,
    each written once per theme."""
    return {f"{stem}-{layout}-{theme}.svg": themed(document, theme) + "\n"
            for layout, document in layouts.items() for theme in THEMES}


def pictures(stem: str, layouts: dict[str, str]) -> str:
    """The drawing on the page: one <picture> per theme, the narrow layout
    under NARROW_MEDIA. Each image is alt="", the figure says the words."""
    (wide_w, wide_h), (narrow_w, narrow_h) = _size(layouts["wide"]), _size(layouts["narrow"])
    out = []
    for theme in THEMES:
        url = markup.site_href(f"{DIAGRAM_DIR}/{stem}")
        out.append(
            f'<picture class="rb-diagram rb-diagram-{theme}">'
            f'<source media="{NARROW_MEDIA}" srcset="{url}-narrow-{theme}.svg" '
            f'width="{narrow_w}" height="{narrow_h}" />'
            f'<img src="{url}-wide-{theme}.svg" width="{wide_w}" height="{wide_h}" alt="" '
            'loading="lazy" decoding="async" /></picture>'
        )
    return "".join(out)


def _layouts(figure: Figure) -> dict[str, str]:
    return {layout: svg(figure, layout) for layout in ("wide", "narrow")}


def figure_files() -> dict[str, str]:
    """Every figure's files, by name under DIAGRAM_DIR."""
    return {name: text for image_id in IMAGE_IDS
            for name, text in diagram_files(image_id, _layouts(figures()[image_id])).items()}


def write_diagram_files(directory: Path, files: dict[str, str]) -> None:
    """*files* under *directory*, and no other SVG: a drawing renamed or
    dropped leaves no file behind."""
    directory.mkdir(parents=True, exist_ok=True)
    for stale in directory.glob("*.svg"):
        if stale.name not in files:
            stale.unlink()
    for name, text in sorted(files.items()):
        path = directory / name
        if not path.is_file() or path.read_text(encoding="utf-8") != text:
            path.write_text(text, encoding="utf-8")


# Data


def registry() -> dict:
    return _registry_in(str(siteinputs.current().platforms))


@cache
def _registry_in(platforms_dir: str) -> dict:
    return load_platform_registry(platforms_dir, required=True)


def setups() -> tuple[str, ...]:
    """The registered setups: each has its own page, pack and file list, so
    every count of setups on the site is this one."""
    return _setups_in(str(siteinputs.current().platforms))


@cache
def _setups_in(platforms_dir: str) -> tuple[str, ...]:
    from model.registry import list_registered_platforms

    return tuple(sorted(list_registered_platforms(platforms_dir)))


def setups_named(named: list[str]) -> str:
    """*named*, then how many other setups there are: "A, B and 15 more"."""
    from model.guides import setup_count

    others = setup_count() - len(named)
    return ", ".join(named) + (f" and {others} more" if others else "")


def platform_modes() -> dict[str, tuple[str, str, str | None]]:
    """name -> (display name, verification mode, hash rule) for every platform."""
    return _platform_modes_in(str(siteinputs.current().platforms))


@cache
def _platform_modes_in(platforms_dir: str) -> dict[str, tuple[str, str, str | None]]:
    from model.platforms import load_platform_config
    from sitegen.install import display_name

    out: dict[str, tuple[str, str, str | None]] = {}
    for name in _setups_in(platforms_dir):
        config = load_platform_config(name, platforms_dir)
        rule = _registry_in(platforms_dir).get(name, {}).get("hash_rule") or config.get("hash_rule")
        out[name] = (display_name(config, name), config.get("verification_mode", ""), rule)
    return out


def _display(name: str) -> str:
    return platform_modes()[name][0]


def _folder(name: str) -> str:
    return str(registry()[name].get("extract_to", "")).strip()


# Frontends and emulators shown in the explainer, each pair one a user meets
# together. Tests check that the platform runs that emulator.
CHAIN_EXAMPLES = (("batocera", "duckstation"), ("emudeck", "pcsx2"), ("retroarch", "beetle_psx"))


def emulator_names() -> dict[str, str]:
    return _emulator_names_in(str(siteinputs.current().emulators))


@cache
def _emulator_names_in(emulators_dir: str) -> dict[str, str]:
    names: dict[str, str] = {}
    for _, emulator in CHAIN_EXAMPLES:
        profile = source_yaml_file(Path(emulators_dir) / f"{emulator}.yml") or {}
        label = str(profile.get("emulator", emulator))
        names[emulator] = re.sub(r"\s*\(.*\)$", "", label)
    return names


def _bios_chain_boxes() -> list[Box]:
    platform, _emulator = CHAIN_EXAMPLES[0]
    return [
        Box("The device", ["A PC, a Steam Deck, a handheld or a TV box"], number="1"),
        Box("Setup", ["The menu that picks a game"], number="2"),
        Box("Emulator", ["Starts the game and reads its BIOS"], number="3"),
        Box("BIOS folder", [f"{_display(platform)} reads", Mono(_folder(platform))],
            accent=True, number="4"),
    ]


def _bios_chain_caption() -> str:
    """The examples the boxes leave out, read from the registry and profiles."""
    named = setups_named([_display(platform) for platform, _ in CHAIN_EXAMPLES])
    pairs = ", ".join(
        f"{_display(platform)} starts {emulator_names()[emulator]}"
        for platform, emulator in CHAIN_EXAMPLES
    )
    folders = ", ".join(f"{_display(platform)} {_folder(platform)}" for platform, _ in CHAIN_EXAMPLES)
    return (
        f"Setups: {named}. Examples: {pairs}. "
        f"BIOS folders: {folders}. The ZIP or the command fills that folder."
    )


def _install_boxes() -> list[Box]:
    return [
        Box("Finds the setup", ["And the folder it reads"], number="1"),
        Box("Looks at the files", ["The ones already in the folder"], number="2"),
        Box("Downloads the rest", ["Only what is missing or different"], number="3"),
        Box("Checks each file", ["Before saving it"], accent=True, number="4"),
    ]


MODE_TEXT = {
    "existence": ("Name only", "Only the name and place count."),
    "md5": ("MD5 fingerprint", "The content must match an MD5 the platform lists."),
    "sha1": ("SHA-1 fingerprint", "The content must match a SHA-1 the platform lists."),
}


def _modes() -> dict[str, list[str]]:
    """Mode -> the platforms checking that way, RomM's size rule named."""
    by_mode: dict[str, list[str]] = {mode: [] for mode in MODE_TEXT}
    for display, mode, rule in platform_modes().values():
        label = f"{display} (size, then any hash)" if rule == "size_and_any_hash" else display
        by_mode.setdefault(mode, []).append(label)
    return {mode: sorted(names, key=str.casefold) for mode, names in by_mode.items()}


def _mode_boxes() -> list[Box]:
    """Each way of checking and how many platforms use it. The names are in
    the caption: eleven of them do not fit in three lines of a box."""
    boxes = []
    for mode, (title, text) in MODE_TEXT.items():
        count = len(_modes().get(mode, []))
        boxes.append(Box(title, [text, count_text(count, "platform")]))
    return boxes


def _mode_summary() -> str:
    return " ".join(
        f"{title}: {', '.join(_modes().get(mode, []))}."
        for mode, (title, _) in MODE_TEXT.items()
    )


# MinUI names a BIOS folder after the tag in parentheses of the ROM folder.
# These are three of the tags its launch scripts read.
MINUI_EXAMPLES = (("Sony PlayStation", "PS"), ("Game Boy Advance", "GBA"), ("Sega Genesis", "MD"))


def minui_files() -> dict[str, list[str]]:
    return _minui_files_in(str(siteinputs.manifests_dir()))


@cache
def _minui_files_in(manifests_dir: str) -> dict[str, list[str]]:
    manifest = json.loads((Path(manifests_dir) / "minui.json").read_text(encoding="utf-8"))
    by_tag: dict[str, list[str]] = {}
    for entry in manifest.get("files", []):
        parts = str(entry.get("dest", "")).split("/")
        if len(parts) == 3 and parts[0] == "Bios":
            by_tag.setdefault(parts[1], []).append(parts[2])
    return {tag: sorted(names, key=str.casefold) for tag, names in by_tag.items()}


def _minui_wide() -> tuple[float, float, list[str]]:
    out: list[str] = []
    left_x, right_x, row = 1.0, 430.0, 22.0
    out.append(svg_text(left_x, 16, "Roms/", TITLE_SIZE, True))
    out.append(svg_text(right_x, 16, "Bios/", TITLE_SIZE, True))
    y = 30.0
    for name, tag in MINUI_EXAMPLES:
        files = minui_files().get(tag, [])
        shown = files[:2] + ([f"and {len(files) - 2} more"] if len(files) > 2 else [])
        height = max(row + 8, 14 + row * (1 + len(shown)))
        label = f"{name} ({tag})/"
        out.append(svg_rect(left_x + 14, y, 250, row + 8))
        out.append(svg_text(left_x + 24, y + 19, label, TEXT_SIZE, True))
        out.append(svg_rect(right_x + 14, y, 250, height))
        out.append(svg_text(right_x + 24, y + 19, f"{tag}/", TEXT_SIZE, True))
        for index, file_name in enumerate(shown):
            out.append(svg_text(right_x + 40, y + 19 + row * (index + 1), file_name, TEXT_SIZE,
                             cls="rb-d-muted"))
        out.extend(svg_connector([(left_x + 264, y + (row + 8) / 2), (right_x + 13, y + (row + 8) / 2)]))
        out.append(svg_text((left_x + 264 + right_x + 14) / 2, y + (row + 8) / 2 - 6,
                         f"tag {tag}", 11, anchor="middle", cls="rb-d-muted"))
        y += height + 14
    return WIDE, y - 12, out


def _minui_narrow() -> tuple[float, float, list[str]]:
    out: list[str] = []
    y = 1.0
    for name, tag in MINUI_EXAMPLES:
        files = minui_files().get(tag, [])
        out.append(svg_rect(1, y, NARROW - 2, 30))
        out.append(svg_text(11, y + 20, f"Roms/{name} ({tag})/", TEXT_SIZE, True))
        out.extend(svg_connector([(NARROW / 2, y + 30), (NARROW / 2, y + 52)]))
        out.append(svg_text(NARROW / 2 + 10, y + 45, f"tag {tag}", 11, cls="rb-d-muted"))
        y += 54
        detail = ""
        if len(files) == 1:
            detail = files[0]
        elif files:
            detail = f"{len(files)} files, such as {files[0]}"
        height = 30 + (LINE if detail else 0)
        out.append(svg_rect(1, y, NARROW - 2, height, accent=True))
        out.append(svg_text(11, y + 20, f"Bios/{tag}/", TEXT_SIZE, True))
        if detail:
            out.append(svg_text(11, y + 20 + LINE, detail, TEXT_SIZE, cls="rb-d-muted"))
        y += height + 18
    return NARROW, y - 17, out


def _pipeline_boxes() -> list[Box]:
    """The steps pipeline.py runs, numbered as the run prints them."""
    labels = STEP_LABELS
    boxes = []
    for label in labels.values():
        number, title = label.split(" ", 1)
        title = title.replace("mame", "MAME").replace("fbneo", "FBNeo")
        boxes.append(Box(title[0].upper() + title[1:], number=number))
    return boxes


def _layers(vertical: bool) -> tuple[float, float, list[str]]:
    shared = Box("_shared.yml", ["Curated groups shared between platforms"])
    platform = Box("Platform files", ["Scraped from each platform"])
    profiles = Box("Emulator profiles", ["Read from emulator source code"])
    pack = Box("Pack generation", ["Platform baseline plus what its cores load"], accent=True)
    zip_box = Box("One ZIP pack per platform")
    out: list[str] = []

    def place(box: Box, x: float, y: float, w: float) -> tuple[float, float, float, float]:
        title_lines, body, h = _box_height(box, w)
        out.extend(_draw_box(box, x, y, w, h, title_lines, body))
        return x, y, w, h

    if not vertical:
        px, py, pw, ph = place(platform, 1, 1, 200)
        sx, sy, sw, sh = place(shared, 1, py + ph + 26, 200)
        ex, ey, ew, eh = place(profiles, 1, sy + sh + 26, 200)
        out.extend(svg_connector([(sx + sw / 2, sy), (px + pw / 2, py + ph)]))
        out.extend(svg_connector([(sx + sw / 2, sy + sh), (ex + ew / 2, ey)]))
        _, _, pack_h = _box_height(pack, 200)
        gx, gy, gw, gh = place(pack, 270, sy + (sh - pack_h) / 2, 200)
        out.extend(svg_connector([(px + pw, py + ph / 2), (240, py + ph / 2), (240, gy + 20), (gx - 1, gy + 20)]))
        out.extend(svg_connector([(ex + ew, ey + eh / 2), (240, ey + eh / 2), (240, gy + gh - 20),
                          (gx - 1, gy + gh - 20)]))
        zx, zy, zw, zh = place(zip_box, 518, gy + (gh - 42) / 2, 200)
        out.extend(svg_connector([(gx + gw, gy + gh / 2), (zx - 1, gy + gh / 2)]))
        return WIDE, max(ey + eh, gy + gh) + 2, out

    w = NARROW - 2
    half = (w - 14) / 2
    sx, sy, sw, sh = place(shared, 1, 1, w)
    px, py, pw, ph = place(platform, 1, sy + sh + 26, half)
    ex, ey, ew, eh = place(profiles, 15 + half, py, half)
    out.extend(svg_connector([(px + pw / 2, sy + sh), (px + pw / 2, py)]))
    out.extend(svg_connector([(ex + ew / 2, sy + sh), (ex + ew / 2, ey)]))
    bottom = max(py + ph, ey + eh)
    gx, gy, gw, gh = place(pack, 1, bottom + 26, w)
    out.extend(svg_connector([(px + pw / 2, py + ph), (px + pw / 2, gy)]))
    out.extend(svg_connector([(ex + ew / 2, ey + eh), (ex + ew / 2, gy)]))
    zx, zy, zw, zh = place(zip_box, 1, gy + gh + 26, w)
    out.extend(svg_connector([(NARROW / 2, gy + gh), (NARROW / 2, zy)]))
    return NARROW, zy + zh + 2, out


def _figures() -> dict[str, Figure]:
    chain = _bios_chain_boxes
    install = _install_boxes
    return {
        "bios-chain": Figure(
            "bios-chain",
            "How a BIOS file is used",
            "A device runs a setup, the setup starts an emulator, and the emulator "
            "reads BIOS files from one folder. The ZIP or the command fills that folder.",
            _bios_chain_caption(),
            lambda: flow(chain(), False, WIDE),
            lambda: flow(chain(), True, NARROW),
        ),
        "install-flow": Figure(
            "install-flow",
            "What the command does",
            "The command finds the setup and its BIOS folder, looks at the files already "
            "there, downloads what is missing or different, then checks each file before "
            "saving it.",
            "Running the command again repeats the same steps and downloads only what changed.",
            lambda: grid(install(), 2, WIDE),
            lambda: flow(install(), True, NARROW),
        ),
        "verification-modes": Figure(
            "verification-modes",
            "How each platform checks a file",
            "Three ways platforms check a BIOS file. " + _mode_summary(),
            "Each platform's own check, read from its source code. A file that passes on one "
            "platform can be refused on another. " + _mode_summary(),
            lambda: columns(_mode_boxes(), False, WIDE),
            lambda: columns(_mode_boxes(), True, NARROW),
        ),
        "minui-card": Figure(
            "minui-card",
            "MinUI card layout",
            "SD card folders: the tag in parentheses of each Roms folder, such as PS, names "
            "the matching folder under Bios.",
            "The folder under Bios takes the tag in parentheses of the ROM folder, not its "
            "full name. Files listed are the ones the MinUI pack puts there.",
            _minui_wide,
            _minui_narrow,
        ),
        "pipeline": Figure(
            "pipeline",
            "Pipeline steps",
            "The pipeline runs its steps in order: "
            + ", ".join(f"{b.number} {b.title}" for b in _pipeline_boxes()) + ".",
            "Read from the step list in scripts/orchestrate/labels.py, numbered as the run prints them.",
            lambda: grid(_pipeline_boxes(), 4, WIDE),
            lambda: grid(_pipeline_boxes(), 2, NARROW),
        ),
        "data-layers": Figure(
            "data-layers",
            "Three layers of data",
            "Platform files and emulator profiles both feed pack generation, _shared.yml "
            "adds curated groups to both, and pack generation writes one ZIP per platform.",
            "The platform's list is the baseline, the profiles add what the cores load.",
            lambda: _layers(False),
            lambda: _layers(True),
        ),
    }


@cache
def figures() -> dict[str, Figure]:
    return _figures()


IMAGE_IDS = ("bios-chain", "install-flow", "verification-modes", "minui-card", "pipeline", "data-layers")

# Entities for the characters Markdown reads as syntax, for a figure that
# lands indented (in a list, a tab or an admonition), where it is parsed as
# inline text rather than kept as a raw HTML block.
_INLINE_ESCAPES = str.maketrans({"_": "&#95;", "*": "&#42;", "`": "&#96;", "[": "&#91;", "]": "&#93;"})


def figure_html(image_id: str, occurrence: int = 1, inline: bool = False) -> str:
    figure = figures()[image_id]
    suffix = "" if occurrence == 1 else f"-{occurrence}"
    drawings = pictures(image_id, _layouts(figure))
    said = f'<span class="sr-only">{escape(figure.desc)}</span>'
    caption = escape(figure.caption)
    anchor = f"rb-fig-{image_id}{suffix}"
    if inline:
        html = (
            f'<span class="rb-figure rb-figure-inline" id="{anchor}" {markup.search_exclude()}>'
            f'{drawings} {said} <span class="rb-figure-caption">{caption}</span></span>'
        )
        return html.translate(_INLINE_ESCAPES)
    return (
        f'<figure class="rb-figure" id="{anchor}" {markup.search_exclude()}>\n'
        f"{drawings}\n"
        f"{said}\n"
        f"<figcaption>{caption}</figcaption>\n"
        "</figure>"
    )


def write_svgs(directory: Path) -> list[Path]:
    """Each diagram's wide layout as a file, for reading outside the site."""
    directory.mkdir(parents=True, exist_ok=True)
    written = []
    for image_id in IMAGE_IDS:
        path = directory / f"{image_id}.svg"
        path.write_text(svg(figures()[image_id], "wide", "") + "\n", encoding="utf-8")
        written.append(path)
    return written
