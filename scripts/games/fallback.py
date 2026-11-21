"""The fallback sets: per system and default core, the install-list files an unrecognised game keeps."""

from __future__ import annotations

import posixpath
from dataclasses import dataclass, field
from pathlib import Path

from games.inputs import FORMAT_VERSION
from games.profileindex import Profiles
from model.platforms import load_platform_config, native_layer

import install


def platform_required(platform: str, platforms_dir: str) -> dict[tuple[str, str], bool]:
    """(system, file name) -> required, as the platform's own list declares it."""
    config = load_platform_config(platform, platforms_dir)
    out: dict[tuple[str, str], bool] = {}
    for sys_id, system in (native_layer(config) or config).get("systems", {}).items():
        for entry in system.get("files", []):
            for name in {entry.get("name"), Path(str(entry.get("destination") or "")).name} - {None, ""}:
                out[(sys_id, str(name).lower())] = entry.get("required") is not False
    return out


def narrowed(manifest: dict, cores: list[str], cache: dict) -> list[tuple[dict, str]]:
    """The install list under some cores, each file with its lowercased
    base name. The answer depends on the cores alone, and a platform asks
    it once per system they run."""
    key = (id(manifest), tuple(cores))
    if key not in cache:
        files, _omitted = install.narrow(
            manifest["files"], manifest.get("omitted_files", []), [], cores, [])
        cache[key] = [(entry, posixpath.basename(entry["dest"]).lower()) for entry in files]
    return cache[key]


def fallback_set(
    manifest: dict,
    platform_required: dict[tuple[str, str], bool],
    profiles: Profiles,
    system: str,
    profile: str | None,
    narrowed_cache: dict | None = None,
) -> dict:
    """The files an unrecognised game of one system keeps on one platform.

    The platform's own files for the system, plus what the default core's
    profile reads for it. The core step is the installer's own narrowing
    (`install.narrow` with the designated cores). A core file the list does
    not attribute to a platform system is kept when the profile entry that
    declares it serves the system.
    """
    wanted = profiles.resolver.equivalents(system)
    cores = sorted(install.designated_cores(manifest, [profile])) if profile else []
    rows: list[list] = []
    for entry, base in narrowed(manifest, cores, {} if narrowed_cache is None else narrowed_cache):
        systems = set(entry.get("systems") or [])
        dest = entry["dest"]
        if entry.get("cores") is None:
            if not systems & wanted:
                continue
            required = any(
                platform_required.get((s, base), True) for s in systems & wanted
            )
        else:
            if systems and not systems & wanted:
                continue
            declared = profiles.entries_named(profile or "", base)
            if not systems and not any(profiles.serves(profile or "", e, system) for e in declared):
                continue
            required = any(e.get("required") is not False for e in declared) if declared else True
        rows.append([dest, int(entry["size"]), required, entry.get("category") or "bios"])
    rows.sort()
    return {
        "files": rows,
        "bytes": sum(r[1] for r in rows),
        "required_bytes": sum(r[1] for r in rows if r[2]),
    }


def shared_table(platform: str, sets: dict[str, dict]) -> dict:
    """One row per install-list file, and each set as indices into it.

    The sets of the MAME-run systems hold the same thousand files: written
    out per set, Batocera's table weighed half a megabyte compressed.
    """
    rows = sorted({(r[0], r[1], r[3]) for body in sets.values() for r in body["files"]})
    position = {row: i for i, row in enumerate(rows)}
    published = {}
    for key, body in sorted(sets.items()):
        published[key] = {
            "files": [position[(r[0], r[1], r[3])] for r in body["files"]],
            "optional": [position[(r[0], r[1], r[3])] for r in body["files"] if not r[2]],
            "bytes": body["bytes"],
            "required_bytes": body["required_bytes"],
        }
    return {
        "format_version": FORMAT_VERSION,
        "platform": platform,
        "files": [list(r) for r in rows],
        "sets": published,
    }


@dataclass
class FallbackTables:
    """The fallback sets of a folder's systems under one core, computed
    once per platform."""

    profiles: Profiles
    tables: dict[str, dict[str, dict]] = field(default_factory=dict)
    narrowed: dict = field(default_factory=dict)

    def keys(self, platform: str, manifest: dict, required: dict[tuple[str, str], bool],
             systems: list[str], chosen: str | None) -> list[str]:
        keys = []
        table = self.tables.setdefault(platform, {})
        for system in systems:
            key = f"{system}|{chosen or ''}"
            if key not in table:
                table[key] = fallback_set(manifest, required, self.profiles, system, chosen, self.narrowed)
            keys.append(key)
        return keys
