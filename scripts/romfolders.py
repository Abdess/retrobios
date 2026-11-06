"""Rom folders of each setup: where its games live and what each folder holds.

`platforms/romfolders/<setup>.yml` records what a frontend's own source says
about its game folders, read at a pinned revision: the roms root relative to
the BIOS folder, each folder with the system name the OS gives it, the
extensions it lists and the core it starts by default. Those files hold the
OS's facts only. Which repository system a folder is, and which profile its
core is, is decided here, through the one alias table in common.py
(`SYSTEM_ALIASES`, `_norm_system_id`) and the profiles' `cores:` lists, so a
change to either reaches every setup without a rescrape.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from common import (
    _norm_system_id,
    list_registered_platforms,
    load_emulator_profiles,
    load_platform_config,
    native_layer,
    preferred_profile,
    upstream_profile_index,
)
from safeparse import yaml_load

ROMFOLDERS_DIR = Path("platforms") / "romfolders"
SOURCES_DIR = ROMFOLDERS_DIR / "_sources"

# "<source key> <path>:<line>[-<line>]", several joined by "; ".
_REF_PART = re.compile(r"^(?P<key>[a-z0-9][a-z0-9-]*) (?P<path>\S+?)(?::(?P<lines>\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*))?$")


def split_refs(source_ref: str) -> list[tuple[str, str, str | None]]:
    """Each (source key, path, lines) a source_ref names, or ValueError."""
    parts: list[tuple[str, str, str | None]] = []
    for raw in source_ref.split("; "):
        match = _REF_PART.match(raw.strip())
        if not match:
            raise ValueError(f"source_ref part {raw!r} is not '<source> <path>:<line>'")
        parts.append((match["key"], match["path"], match["lines"]))
    return parts


def setup_paths(directory: Path = ROMFOLDERS_DIR) -> list[Path]:
    """The setup files of a directory, without the sources file."""
    return sorted(p for p in Path(directory).glob("*.yml") if not p.name.startswith("_"))


def load_setup(path: Path) -> dict:
    with Path(path).open(encoding="utf-8") as handle:
        return yaml_load(handle)


def load_setups(directory: Path = ROMFOLDERS_DIR) -> dict[str, dict]:
    """Every setup document of a directory, keyed by its `setup:` id."""
    return {doc["setup"]: doc for doc in (load_setup(p) for p in setup_paths(directory))}


@dataclass
class Resolution:
    """What a folder resolved to, and how."""

    systems: list[str]
    basis: str


@dataclass
class SystemResolver:
    """Folder and system names to repository system ids.

    The universe is every system a profile or a platform file names. A name
    resolves, in this order, as one of those ids, as a name a platform's own
    file gives a system (`native_system`, the folder Batocera calls `psx`),
    or through `_norm_system_id`, which applies SYSTEM_ALIASES then drops the
    maker prefix and separators. A name nothing matches stays unresolved:
    a new abbreviation goes into SYSTEM_ALIASES, never into a table here.

    Ids that normalize alike are one machine spelled several ways
    (`sega-megadrive`, `sega-mega-drive`, `mega-drive`). Each class answers
    with one canonical id, the spelling most profiles use, and
    `equivalents()` gives the whole class back to whoever matches a
    profile's `systems:` or a manifest's `systems`.
    """

    ids: set[str]
    profile_use: dict[str, int]
    native: dict[str, dict[str, set[str]]]
    by_norm: dict[str, set[str]] = field(default_factory=dict)
    canonical_of: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for sid in self.ids:
            self.by_norm.setdefault(_norm_system_id(sid), set()).add(sid)
        for members in self.by_norm.values():
            best = min(members, key=lambda s: (-self.profile_use.get(s, 0), -len(s), s))
            for sid in members:
                self.canonical_of[sid] = best

    @classmethod
    def from_repo(
        cls, emulators_dir: str = "emulators", platforms_dir: str = "platforms"
    ) -> SystemResolver:
        profiles = load_emulator_profiles(emulators_dir)
        use: dict[str, int] = {}
        for profile in profiles.values():
            for sid in profile.get("systems") or []:
                use[str(sid)] = use.get(str(sid), 0) + 1
        ids = set(use)
        native: dict[str, dict[str, set[str]]] = {}
        for platform in list_registered_platforms(platforms_dir):
            config = load_platform_config(platform, platforms_dir)
            ids.update(config.get("systems", {}))
            names: dict[str, set[str]] = {}
            for sys_id, system in (native_layer(config) or {}).get("systems", {}).items():
                for entry in system.get("files", []):
                    name = entry.get("native_system")
                    if isinstance(name, str) and name.strip():
                        names.setdefault(name.strip().lower(), set()).add(sys_id)
            native[platform] = names
        return cls(ids=ids, profile_use=use, native=native)

    def canonical(self, sid: str) -> str:
        return self.canonical_of.get(sid, sid)

    def equivalents(self, sid: str) -> set[str]:
        """Every id spelling the same machine as sid, sid included."""
        return set(self.by_norm.get(_norm_system_id(sid), ())) | {sid}

    def _answer(self, found: set[str], basis: str) -> Resolution:
        return Resolution(sorted({self.canonical(s) for s in found}), basis)

    def resolve(self, names: list[str], platform: str = "") -> Resolution:
        """The systems the first name that resolves designates."""
        for name in names:
            if not name:
                continue
            lowered = name.strip().lower()
            if lowered in self.ids:
                return self._answer({lowered}, "id")
            own = self.native.get(platform, {}).get(lowered)
            if own and len(own) == 1:
                return self._answer(own, f"native name of {platform}")
            norm = self.by_norm.get(_norm_system_id(lowered))
            if norm:
                return self._answer(norm, "normalized id")
            claimed = [
                (plat, owners) for plat, table in sorted(self.native.items())
                if (owners := table.get(lowered)) and len(owners) == 1
            ]
            if claimed:
                plat, owners = claimed[0]
                return self._answer(owners, f"native name of {plat}")
        return Resolution([], "unresolved")


@dataclass
class ProfileResolver:
    """An OS's core name to the repository profile that documents it."""

    index: dict[str, set[str]]

    @classmethod
    def from_repo(cls, emulators_dir: str = "emulators") -> ProfileResolver:
        return cls(upstream_profile_index(load_emulator_profiles(emulators_dir)))

    def resolve(self, core: str | None) -> str | None:
        if not core:
            return None
        # RetroPie names a libretro package lr-<core> (scriptmodules/libretrocores).
        bare = core.removeprefix("lr-")
        spellings = (core, core.lower(), bare, bare.replace("-", "_"), bare.lower().replace("-", "_"))
        for name in dict.fromkeys(spellings):
            found = preferred_profile(self.index, name)
            if found:
                return found
        return None


_TAG = re.compile(r"\(([^()]+)\)\s*$")


def folder_names(row: dict) -> list[str]:
    """The names a folder row is known by, the OS's system name first.

    A folder named for people and tagged for the frontend, `Sony PlayStation
    (PS)` on CrossMix-OS, is also known by its tag.
    """
    names = [row.get("name") or "", row["folder"], *(row.get("aliases") or [])]
    names += [m.group(1).strip() for n in list(names) if (m := _TAG.search(n))]
    return [n for n in dict.fromkeys(names) if n]
