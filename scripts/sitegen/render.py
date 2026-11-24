"""Small renderings shared by every page."""

from __future__ import annotations

import re
from collections.abc import Callable

from core.text import count_text as count_text
from model.collection import manufacturer_slug
from sitegen import runsections
from sitegen.runsections import system_name


WIKI_SRC_DIR = "wiki"  # manually maintained wiki sources
SYSTEM_ICON_BASE = "https://raw.githubusercontent.com/libretro/retroarch-assets/master/xmb/systematic/png"

_CODE_SPAN = re.compile(r"(`+).+?\1", re.S)


def code_span(value: object) -> str:
    """A value as an inline code span it cannot leave.

    Markdown shows HTML inside a code span as text, so the one way out is a
    backtick in the value closing the span early. Data from a profile, a
    platform file or a file name is not ours to trust that far.
    """
    return "`" + str(value).replace("`", "'") + "`"


# A hash shown short, in a card, a platform row or an emulator table: as long
# as the card's own address (sha1-<12 hex>), one length across the site.
SHORT_HASH = 12
# A file card's permanent id: published, linked from outside, and read back
# by the site's lookup (model/retired.py keeps a retired one answering).
CARD_ANCHOR = re.compile(rf"sha1-[0-9a-f]{{{SHORT_HASH}}}")


def card_anchor(sha1: str) -> str:
    """The id of the card a file's sha1 heads: sha1-<first 12 hex>."""
    return f"sha1-{sha1[:SHORT_HASH]}"


def escape_tags(text: str) -> str:
    """Show a placeholder such as ``<system_dir>`` as it was written.

    Profile prose names paths with angle brackets. Passed through as HTML
    they are unknown tags and vanish from the page, and ``<title id>`` opens
    a title element that swallows everything after it. Code spans keep their
    brackets, and an autolink stays a link.
    """
    def outside(chunk: str) -> str:
        return re.sub(r"<(?!https?://|mailto:)", "&lt;", chunk)

    out: list[str] = []
    position = 0
    for match in _CODE_SPAN.finditer(text):
        out.append(outside(text[position:match.start()]))
        out.append(match.group(0))
        position = match.end()
    out.append(outside(text[position:]))
    return "".join(out)


def admonition_body(text: str) -> str:
    """Indent prose without turning source tokens such as ``#if`` into H1s."""
    escaped = re.sub(r"(?m)^(\s*)#", r"\1\\#", escape_tags(text))
    return escaped.replace("\n", "\n    ")

def console_icon_name(manufacturer: str, console_name: str) -> str:
    return f"{manufacturer} - {console_name}".replace("/", " ")

def slugify_anchor(text: str) -> str:
    """Slugify text for MkDocs anchor compatibility."""
    slug = text.lower()
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = re.sub(r"[\s]+", "-", slug)
    slug = slug.strip("-")
    return slug

def console_anchor(manufacturer: str, console: str) -> str:
    """The id of a console's heading on its manufacturer's page, from the
    same sections that name the systems."""
    from core.anchors import toc_slug

    key = (manufacturer_slug(manufacturer), console)
    return runsections.current().anchors.get(key) or toc_slug(console)


def board_slug(sys_id: str) -> str:
    """The slug of a board's section: its page is systems/arcade-<slug>/
    and its heading's id is <slug>. Read from the board's display name,
    so every id of one board gives one slug."""
    from core.anchors import toc_slug

    return toc_slug(system_name(str(sys_id)))


def scalar_text(key: object, value: object) -> str:
    """A scalar of a structured block. A source reference reads as code."""
    if isinstance(value, bool):
        text = "yes" if value else "no"
    elif value is None:
        text = "none"
    else:
        # One line: a folded note's second line started at column 0 and
        # left the admonition it was written in. Never cut: 34 notes lost
        # their end, and a cut citation links to another line.
        text = " ".join(str(value).split())
    return f"`{text}`" if key == "source_ref" else text


def _field_label(key: object) -> str:
    """A YAML key as the page shows it: words, not an identifier."""
    return str(key).replace("_", " ")


FieldText = Callable[[object, object], str]


def render_yaml_value(
    lines: list[str], val: object, indent: int = 4,
    field_text: FieldText = scalar_text,
) -> None:
    """Render any YAML value as a nested markdown list.

    Every level is a list item and its children a sublist four spaces in.
    A key written as a paragraph with its children indented below it read as
    an indented code block: the clownmdemu page showed the raw asterisks.
    ``field_text`` renders each scalar, so a page can link a source_ref.
    """
    pad = " " * indent
    if isinstance(val, dict):
        for k, v in val.items():
            if isinstance(v, (dict, list)) and v:
                lines.append(f"{pad}- **{_field_label(k)}:**")
                lines.append("")
                render_yaml_value(lines, v, indent + 4, field_text)
            else:
                lines.append(f"{pad}- **{_field_label(k)}:** {field_text(k, v)}")
        lines.append("")
    elif isinstance(val, list):
        for item in val:
            if isinstance(item, dict):
                # Scalars on the item's line, lists and maps as its children:
                # cemu's firmware titles lost the files each title carries.
                scalars = {ik: iv for ik, iv in item.items()
                           if not (isinstance(iv, (dict, list)) and iv)}
                nested = {ik: iv for ik, iv in item.items() if ik not in scalars}
                parts = [f"{_field_label(ik)}: {field_text(ik, iv)}"
                         for ik, iv in scalars.items()]
                lines.append(f"{pad}- {', '.join(parts)}".rstrip())
                if nested:
                    lines.append("")
                    render_yaml_value(lines, nested, indent + 4, field_text)
            else:
                lines.append(f"{pad}- {field_text(None, item)}")
        lines.append("")
    elif isinstance(val, str) and "\n" in val:
        lines.extend(f"{pad}{line}" for line in val.split("\n"))
    else:
        lines.append(f"{pad}{field_text(None, val)}")


def _platform_link(name: str, display: str, prefix: str = "") -> str:
    """Generate a markdown link to a platform page."""
    return f"[{display}]({prefix}platforms/{name}.md)"

def emulator_link(name: str, prefix: str = "") -> str:
    """Generate a markdown link to an emulator page."""
    return f"[{name}]({prefix}emulators/{name}.md)"

def percent_text(n: int, total: int) -> str:
    if total == 0:
        return "0%"
    return f"{n / total * 100:.1f}%"

def by_mode(value: str | dict, mode: str) -> str:
    """Read a profile field that may be keyed by build mode."""
    if isinstance(value, dict):
        return str(value.get(mode) or "") if mode else ""
    return str(value or "")


def system_ids(profiles: dict[str, dict], platforms: list[dict]) -> set[str]:
    """Every system id a page can name: the platforms' and the profiles'."""
    ids = {str(sys_id) for config in platforms for sys_id in config.get("systems", {})}
    for profile in profiles.values():
        ids.update(str(sys_id) for sys_id in profile.get("systems") or [])
        for entry in profile.get("files") or []:
            if not isinstance(entry, dict):
                continue
            if entry.get("system"):
                ids.add(str(entry["system"]))
            ids.update(str(sys_id) for sys_id in entry.get("systems") or [])
    return ids
