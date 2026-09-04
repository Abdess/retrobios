"""Small renderings shared by every page."""

from __future__ import annotations

import re

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import json
import urllib.request
WIKI_SRC_DIR = "wiki"  # manually maintained wiki sources
SYSTEM_ICON_BASE = "https://raw.githubusercontent.com/libretro/retroarch-assets/master/xmb/systematic/png"
ICON_CACHE_PATH = Path(".cache") / "system_icons.json"

# Icon names confirmed to exist upstream. A name absent from this map has not
# been checked yet; a name mapped to False has no icon and gets none rendered,
# because a heading with a broken image reads worse than a heading without one.
_icon_available: dict[str, bool] = {}

def _admonition_body(text: str) -> str:
    """Indent prose without turning source tokens such as ``#if`` into H1s."""
    escaped = re.sub(r"(?m)^(\s*)#", r"\1\\#", text)
    return escaped.replace("\n", "\n    ")

def _icon_name(manufacturer: str, console_name: str) -> str:
    return f"{manufacturer} - {console_name}".replace("/", " ")

def _icon_url(icon_name: str) -> str:
    return f"{SYSTEM_ICON_BASE}/{urllib.parse.quote(icon_name)}.png"

def prime_system_icons(names: set[str]) -> None:
    """Record which system icons upstream actually serves.

    Results persist in ``.cache`` so later runs skip the network. Names that
    cannot be checked stay unavailable: the site never links an image it has
    not seen answer.
    """
    cached: dict[str, bool] = {}
    if ICON_CACHE_PATH.exists():
        try:
            with open(ICON_CACHE_PATH) as f:
                cached = json.load(f)
        except (json.JSONDecodeError, OSError):
            cached = {}

    unknown = sorted(n for n in names if n not in cached)
    if unknown:
        def check(name: str) -> tuple[str, bool | None]:
            """True when served, False when upstream says it is gone.

            None on a transient failure, so a flaky run never records an
            icon as absent for every later build.
            """
            req = urllib.request.Request(_icon_url(name), method="HEAD")
            try:
                with urllib.request.urlopen(req, timeout=15) as resp:
                    return name, resp.status == 200
            except urllib.error.HTTPError as exc:
                return name, False if exc.code == 404 else None
            except (urllib.error.URLError, OSError):
                return name, None

        print(f"Checking {len(unknown)} system icons...")
        with ThreadPoolExecutor(max_workers=8) as pool:
            for name, ok in pool.map(check, unknown):
                if ok is not None:
                    cached[name] = ok
        ICON_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(ICON_CACHE_PATH, "w") as f:
            json.dump(cached, f, indent=2, sort_keys=True)

    _icon_available.update(cached)
    missing = sum(1 for n in names if not cached.get(n))
    if missing:
        print(f"  {missing} systems have no upstream icon")

def system_icon_markdown(manufacturer: str, console_name: str) -> str:
    """Icon image for a system heading, empty when upstream serves none."""
    name = _icon_name(manufacturer, console_name)
    if not _icon_available.get(name):
        return ""
    return f"![{console_name}]({_icon_url(name)}){{ width=24 }} "

# Global index: maps system_id -> (manufacturer_slug, console_name) for cross-linking
_system_page_map: dict[str, tuple[str, str]] = {}

def _slugify_anchor(text: str) -> str:
    """Slugify text for MkDocs anchor compatibility."""
    import re

    slug = text.lower()
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = re.sub(r"[\s]+", "-", slug)
    slug = slug.strip("-")
    return slug

def _system_link(sys_id: str, prefix: str = "") -> str:
    """Generate a markdown link to a system page with anchor."""
    if sys_id in _system_page_map:
        slug, console = _system_page_map[sys_id]
        anchor = _slugify_anchor(console)
        return f"[{sys_id}]({prefix}systems/{slug}.md#{anchor})"
    return sys_id

def _render_yaml_value(lines: list[str], val, indent: int = 4) -> None:
    """Render any YAML value as indented markdown."""
    pad = " " * indent
    if isinstance(val, dict):
        for k, v in val.items():
            if isinstance(v, dict):
                lines.append(f"{pad}**{k}:**")
                lines.append("")
                _render_yaml_value(lines, v, indent + 4)
            elif isinstance(v, list):
                lines.append(f"{pad}**{k}:**")
                lines.append("")
                for item in v:
                    if isinstance(item, dict):
                        parts = [
                            f"{ik}: {iv}"
                            for ik, iv in item.items()
                            if not isinstance(iv, (dict, list))
                        ]
                        lines.append(f"{pad}- {', '.join(parts)}")
                    else:
                        lines.append(f"{pad}- {item}")
                lines.append("")
            else:
                # Truncate very long strings in tables
                sv = str(v)
                if len(sv) > 200:
                    sv = sv[:200] + "..."
                lines.append(f"{pad}- **{k}:** {sv}")
    elif isinstance(val, list):
        for item in val:
            if isinstance(item, dict):
                parts = [
                    f"{ik}: {iv}"
                    for ik, iv in item.items()
                    if not isinstance(iv, (dict, list))
                ]
                lines.append(f"{pad}- {', '.join(parts)}")
            else:
                lines.append(f"{pad}- {item}")
    elif isinstance(val, str) and "\n" in val:
        for line in val.split("\n"):
            lines.append(f"{pad}{line}")
    else:
        lines.append(f"{pad}{val}")

def _platform_link(name: str, display: str, prefix: str = "") -> str:
    """Generate a markdown link to a platform page."""
    return f"[{display}]({prefix}platforms/{name}.md)"

def _emulator_link(name: str, prefix: str = "") -> str:
    """Generate a markdown link to an emulator page."""
    return f"[{name}]({prefix}emulators/{name}.md)"

def _fmt_size(size: int) -> str:
    if size >= 1024 * 1024 * 1024:
        return f"{size / (1024**3):.1f} GB"
    if size >= 1024 * 1024:
        return f"{size / (1024**2):.1f} MB"
    if size >= 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size} B"

def _pct(n: int, total: int) -> str:
    if total == 0:
        return "0%"
    return f"{n / total * 100:.1f}%"

def _by_mode(value, mode: str) -> str:
    """Read a profile field that may be keyed by build mode."""
    if isinstance(value, dict):
        return str(value.get(mode) or "") if mode else ""
    return str(value or "")
