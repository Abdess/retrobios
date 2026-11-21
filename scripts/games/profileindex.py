"""What a profile declares, looked up for the game rules and the games index."""

from __future__ import annotations

from pathlib import Path

from model.profiles import entry_system_ids
from model.region import normalize_declared
from model.romfolders import SystemResolver


def profile_pins(profile: dict) -> set[str]:
    """Every commit a profile is pinned to, a build-mode dict included."""
    pins: set[str] = set()
    for key in ("source_commit", "upstream_commit"):
        value = profile.get(key)
        values = value.values() if isinstance(value, dict) else [value]
        pins.update(str(v) for v in values if v)
    return pins


def declared_names(profile: dict) -> set[str]:
    """The names and aliases a profile's files answer to."""
    names: set[str] = set()
    for entry in profile.get("files") or []:
        if isinstance(entry, dict) and entry.get("name"):
            names.add(str(entry["name"]))
            names.update(str(a) for a in entry.get("aliases") or [])
    return names


def tagged_regions(profile: dict, name: str) -> set[str]:
    """The regions a profile tags a file with, over all its declarations."""
    out: set[str] = set()
    for entry in profile.get("files") or []:
        if isinstance(entry, dict) and (
            entry.get("name") == name or name in (entry.get("aliases") or [])
        ):
            out |= normalize_declared(entry.get("region"))
    return out


def every_tag(profile: dict) -> set[str]:
    return {
        region
        for entry in profile.get("files") or []
        if isinstance(entry, dict)
        for region in normalize_declared(entry.get("region"))
    }


def _entry_names(entry: dict) -> set[str]:
    names = {str(entry.get("name") or "")}
    names |= {str(a) for a in entry.get("aliases") or []}
    for key in ("path", "standalone_path", "destination"):
        if entry.get(key):
            names.add(Path(str(entry[key])).name)
    return {n.lower() for n in names if n}


class Profiles:
    """Profile lookups the fallback and region sections share."""

    def __init__(self, profiles: dict[str, dict], resolver: SystemResolver) -> None:
        self.profiles = profiles
        self.resolver = resolver
        self._by_name: dict[str, dict[str, list[dict]]] = {}

    def entries_named(self, profile: str, name: str) -> list[dict]:
        table = self._by_name.get(profile)
        if table is None:
            table = {}
            for entry in self.profiles.get(profile, {}).get("files") or []:
                if isinstance(entry, dict):
                    for n in _entry_names(entry):
                        table.setdefault(n, []).append(entry)
            self._by_name[profile] = table
        return table.get(name.lower(), [])

    def serves(self, profile: str, entry: dict, system: str) -> bool:
        wanted = self.resolver.equivalents(system)
        return bool(set(entry_system_ids(entry, self.profiles.get(profile, {}))) & wanted)

    def region_files(self, profile: str, system: str) -> dict[str, list[str]]:
        """Region slug -> file names the profile tags for it, for one system.

        `any` holds the files declared with no region: those are installed
        whatever the game's region.
        """
        out: dict[str, set[str]] = {}
        data = self.profiles.get(profile, {})
        for entry in data.get("files") or []:
            if not isinstance(entry, dict) or not self.serves(profile, entry, system):
                continue
            if entry.get("category") == "game_data":
                continue
            regions = normalize_declared(entry.get("region")) or {"any"}
            for region in regions:
                out.setdefault(region, set()).add(str(entry["name"]))
        return {k: sorted(v) for k, v in sorted(out.items())}
