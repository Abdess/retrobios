"""Leaving a game's own data out of a pack, a manifest or a report.

A platform list can name the files a game reads beside the firmware its
emulator needs, and a core profile marks the data files of the games it runs
`category: game_data`. `--no-game-data` keeps the firmware: the platform's
entries categorized as game data and the profiles' game data entries are left
out, and each one is named with the reason.

Every caller cuts from the full platform config and the full profiles. The
category of a platform entry is read from the profiles' game data entries, so
cutting twice would find no evidence the second time.
"""

from __future__ import annotations

from dataclasses import dataclass

from resolve.cores import resolve_platform_cores
from resolve.categories import GAME_DATA, EntryCategories


@dataclass(frozen=True)
class LeftOut:
    """One game data file left out, and who reads it as game data."""

    layer: str  # "platform" (the platform's list) or "core" (a core profile)
    system: str
    name: str
    readers: tuple[str, ...]

    def describe(self) -> str:
        where = f"{self.system}/{self.name}" if self.system else self.name
        if not self.readers:
            return where
        return f"{where} (game data of {', '.join(self.readers)})"


@dataclass
class GameDataCut:
    """The config and profiles without game data, and what was left out."""

    config: dict
    profiles: dict[str, dict]
    left_out: list[LeftOut]

    def report_lines(self) -> list[str]:
        """What the cut left out, named, one line per layer.

        The platform layer names each entry and the cores that read it as
        game data. The core layer names each core with the files its profile
        declares `category: game_data`, held by the collection or not.
        """
        lines = []
        platform = [item.describe() for item in self.left_out if item.layer == "platform"]
        if platform:
            lines.append(
                f"Left out as game data, {len(platform)} entries of the platform's "
                f"list: {', '.join(platform)}"
            )
        by_core: dict[str, list[str]] = {}
        for item in self.left_out:
            if item.layer == "core":
                names = by_core.setdefault(item.readers[0], [])
                if item.name not in names:
                    names.append(item.name)
        if by_core:
            count = sum(len(names) for names in by_core.values())
            named = "; ".join(
                f"{core}: {', '.join(names)}" for core, names in sorted(by_core.items())
            )
            lines.append(
                f"Left out as game data, {count} files the cores declare "
                f"category: game_data ({named})"
            )
        return lines


def is_game_data(entry: dict) -> bool:
    return entry.get("category") == GAME_DATA


def _entry_names(entry: dict) -> set[str]:
    names = {str(entry.get("name") or "")}
    names.update(str(a) for a in entry.get("aliases") or [])
    path = str(entry.get("path") or "")
    if path:
        names.add(path.rstrip("/").rsplit("/", 1)[-1])
    return {n.casefold() for n in names if n}


def platform_game_data(
    config: dict, profiles: dict[str, dict], data_registry: dict | None
) -> set[int]:
    """The `id()` of every platform entry categorized as game data."""
    categories = EntryCategories(config, profiles, data_registry)
    return {
        id(fe)
        for sys_id, system in (config.get("systems") or {}).items()
        for fe in system.get("files") or []
        if isinstance(fe, dict)
        and categories.category(
            fe, str(fe.get("destination", fe.get("name", ""))), sys_id
        ) == GAME_DATA
    }


def without_game_data(
    config: dict,
    profiles: dict[str, dict],
    data_registry: dict | None = None,
    target_cores: set[str] | None = None,
) -> GameDataCut:
    """The platform config and the profiles with every game data entry removed.

    The profiles lose their `category: game_data` files, so no core extra
    of that category reaches the pack, the manifest or the report. The
    platform keeps every entry that is not categorized game data.
    """
    dropped = platform_game_data(config, profiles, data_registry)
    examined = sorted(resolve_platform_cores(config, profiles, target_cores=target_cores))
    readers_by_name: dict[str, set[str]] = {}
    for key in examined:
        for fe in profiles[key].get("files") or []:
            if isinstance(fe, dict) and is_game_data(fe):
                for name in _entry_names(fe):
                    readers_by_name.setdefault(name, set()).add(key)

    left_out: list[LeftOut] = []
    systems: dict[str, dict] = {}
    for sys_id, system in (config.get("systems") or {}).items():
        files = system.get("files") or []
        kept = [fe for fe in files if id(fe) not in dropped]
        for fe in files:
            if id(fe) in dropped:
                name = str(fe.get("name") or "")
                left_out.append(LeftOut(
                    "platform", sys_id, name,
                    tuple(sorted(readers_by_name.get(name.casefold(), ()))),
                ))
        systems[sys_id] = {**system, "files": kept} if len(kept) != len(files) else system

    left_out.extend(
        LeftOut("core", "", str(fe.get("name") or ""), (key,))
        for key in examined
        for fe in profiles[key].get("files") or []
        if isinstance(fe, dict) and is_game_data(fe)
    )

    stripped = {
        key: (
            {**profile, "files": [
                fe for fe in profile.get("files") or []
                if not (isinstance(fe, dict) and is_game_data(fe))
            ]}
            if any(isinstance(fe, dict) and is_game_data(fe)
                   for fe in profile.get("files") or [])
            else profile
        )
        for key, profile in profiles.items()
    }
    return GameDataCut({**config, "systems": systems}, stripped, left_out)
