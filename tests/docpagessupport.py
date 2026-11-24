"""Page readers shared by the doc page test modules."""

from __future__ import annotations

import tests
from tests import mdsections

import functools
import io
import json
import re
import tokenize
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent

WIKI = ROOT / "wiki"

PUBLISHED = sorted(WIKI.glob("*.md")) + [ROOT / "README.md", ROOT / "CONTRIBUTING.md"]

# The marketing vocabulary the project refuses in published text.
MARKETING_WORDS = re.compile(
    r"\b(comprehensive|robust|seamless(ly)?|leverag\w*|streamlin\w*|delv(e|ing))\b",
    re.IGNORECASE,
)


def _page(name: str) -> str:
    return (WIKI / name).read_text(encoding="utf-8")


# A section runs to the next heading of any level.
_section = functools.partial(mdsections.section, stop=6)


def _table_rows(text: str) -> list[list[str]]:
    rows: list[list[str]] = []
    rows.extend(
        [cell.strip() for cell in line.strip().strip("|").split(" | ")]
        for line in text.splitlines()
        if line.startswith("|") and not re.match(r"\|\s*-", line)
    )
    return rows[1:]


def _schema(name: str) -> dict:
    return json.loads((ROOT / "schemas" / f"{name}.schema.json").read_text(encoding="utf-8"))


def _registry() -> dict:
    import yaml

    return yaml.safe_load((ROOT / "platforms" / "_registry.yml").read_text(encoding="utf-8"))["platforms"]


def _python_prose(source: str) -> str:
    """Comments and docstrings of a module, one per line."""
    parts: list[str] = []
    previous = tokenize.INDENT
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type == tokenize.COMMENT or token.type == tokenize.STRING and previous in (
            tokenize.INDENT, tokenize.NEWLINE, tokenize.NL, tokenize.DEDENT,
        ):
            parts.append(token.string)
        if token.type not in (tokenize.COMMENT, tokenize.NL):
            previous = token.type
    return "\n".join(parts)


# Words a heading keeps capitalized: names of platforms, systems and programs.
_HEADING_KEEP = set(["Batocera", "Recalbox", "Lakka", "Dolphin", "Redump", "Linux", "Windows", "Android", "Python", "Steam", "Deck", "macOS", "Termux", "Flatpak", "Switch", "Raspberry", "Pi", "Mega", "Drive", "Genesis", "Saturn", "Dreamcast", "Amiga", "Atari", "Sega", "Nintendo", "Sony", "Neo", "Geo", "Lynx", "Jaguar", "Commodore", "Apple", "Mac", "Spectrum", "Sinclair", "Amstrad", "MSX", "GameCube", "Wii", "Game", "Boy", "Advance", "Famicom", "Disk", "System", "Super", "Master", "PlayStation", "Vita", "Xbox", "Arcade", "English", "French", "Spanish", "I", "Lua", "Unity", "Qt", "Kodi", "Discord", "Pages", "Actions", "Docker", "Windows", "Mac", "Ubuntu", "Debian", "Arch", "SteamOS", "Chihiro", "NAOMI", "Triforce", "Lindbergh", "Model", "PinMAME", "ScummVM", "Dinothawr", "Cemu", "Citra", "Yuzu", "Ryujinx", "Mednafen", "Beetle", "Stella", "Hatari", "Caprice", "Vice", "Fuse", "Daphne", "Hypseus", "Singe", "Supermodel", "Flycast", "Redream", "DuckStation", "SwanStation", "Opera", "Gearsystem", "Picodrive", "Snes9x", "Nestopia", "Mesen", "Gambatte", "SameBoy", "mGBA", "melonDS", "DeSmuME", "Azahar", "Eden", "Sudachi", "Torzu", "Xemu", "Cxbx", "PCSX2", "AetherSX2", "NetherSX2", "ARMSX2", "RPCS3", "Vita3K", "Zinc", "Raine", "FBNeo", "FinalBurn", "Neo", "MAME", "Clrmamepro", "RomVault"])


def _sentence_case(title: str) -> str:
    words = title.split(" ")
    out = []
    starts = True
    for w in words:
        core = w.strip("()[],:.")
        if starts:
            # The first word of a heading or of a clause after ":", "." or " - ".
            head, sep, tail = core.partition("-")
            if sep and re.fullmatch(r"[A-Z][a-z]+", tail) and tail not in _HEADING_KEEP:
                w = w.replace(core, f"{head}-{tail.lower()}", 1)
        elif re.fullmatch(r"[A-Z][a-z]+(-[A-Z]?[a-z]+)*", core) and core not in _HEADING_KEEP:
            w = w.replace(core, core.lower(), 1)
        out.append(w)
        starts = w.endswith((":", ".")) or w == "-" or re.fullmatch(r"\d+[a-z]?\.?", w) is not None
    return " ".join(out)
