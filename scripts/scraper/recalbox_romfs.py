"""How Recalbox's romfs2 reads a system.ini and a board defconfig to build a board's systems."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

# romfs2 systemholder.py reads core.0 to core.19.
CORE_SLOTS = 20
# romfs2 configin.py: the board is the lowercased rest of the first key
# carrying this prefix, the suffix a system.ini key or section takes.
TARGET_PREFIX = "BR2_PACKAGE_RECALBOX_TARGET_"
# romfs2 inisettings.py loadFile: a key line is tried first, then a section.
_INI_KEY = re.compile(r'^([^#;].*?)\s?=\s?"?(.*?)"?$')
_INI_SECTION = re.compile(r"^\[(.*)\]")
_CORE_SECTION = re.compile(r"core\.(\d+)(?:\.[\w-]+)?")
# romfs2 keyvaluesettings.py loadFile, the reader configin.py uses.
_CONFIG_KEY = re.compile(r"^([^#;].*?)\s?=\s?(.+)$")


@dataclass(frozen=True)
class SystemIni:
    """The sections of one system.ini, and the line of each `<section>/<key>`."""

    sections: dict[str, dict[str, str]]
    lines: dict[str, int]

    def core_sections(self) -> Iterator[dict[str, str]]:
        """Every `[core.N]` and `[core.N.<board>]` section some board builds."""
        for name, values in self.sections.items():
            slot = _CORE_SECTION.fullmatch(name)
            if slot and int(slot.group(1)) < CORE_SLOTS:
                yield values

    def slots(self, board: str) -> Iterator[str]:
        """The `core.N` sections a board builds: `[core.N]` or `[core.N.<board>]` alone."""
        for slot in range(CORE_SLOTS):
            section = f"core.{slot}"
            if section in self.sections or f"{section}.{board}" in self.sections:
                yield section

    def get(self, section: str, key: str, board: str) -> tuple[str | None, int | None]:
        """systemholder.py __get: the board's section, then the board's key,
        then the plain key."""
        for where, name in ((f"{section}.{board}", key), (section, f"{key}.{board}"), (section, key)):
            if name in self.sections.get(where, {}):
                return self.sections[where][name], self.lines.get(f"{where}/{name}")
        return None, None


def read_system_ini(text: str) -> SystemIni:
    """One system.ini as romfs2 reads it, the last value of a key kept."""
    sections: dict[str, dict[str, str]] = {}
    lines: dict[str, int] = {}
    section = "default"
    for number, line in enumerate(text.splitlines(), 1):
        if key := _INI_KEY.match(line):
            name = key.group(1).strip()
            sections.setdefault(section, {})[name] = key.group(2).strip()
            lines[f"{section}/{name}"] = number
        elif header := _INI_SECTION.match(line):
            section = header.group(1).strip()
            sections.setdefault(section, {})
    return SystemIni(sections, lines)


@dataclass(frozen=True)
class Defconfig:
    """The board a defconfig builds, and the line of each symbol it sets to y."""

    board: str | None
    enabled: dict[str, int]


def read_defconfig(text: str) -> Defconfig:
    """One Buildroot defconfig as romfs2 configin.py reads it."""
    values: dict[str, tuple[str, int]] = {}
    for number, line in enumerate(text.splitlines(), 1):
        if key := _CONFIG_KEY.match(line):
            values[key.group(1).strip()] = (key.group(2).strip(), number)
    board = next((name[len(TARGET_PREFIX):].lower() for name in values if name.startswith(TARGET_PREFIX)), None)
    return Defconfig(board, {name: number for name, (value, number) in values.items() if value == "y"})


def defconfig_boards(defconfigs: Iterable[tuple[str, str]]) -> dict[str, tuple[str, Defconfig]]:
    """Each board and the (path, defconfig) that builds it, from (path, text)
    pairs. A defconfig that names no Recalbox target builds no board."""
    found: dict[str, tuple[str, Defconfig]] = {}
    for path, text in defconfigs:
        config = read_defconfig(text)
        if config.board:
            found[config.board] = (path, config)
    return found
