"""The launcher rows of a gap report: names read and not held, records left unproven."""

from __future__ import annotations

from pathlib import Path

from model.platforms import load_platform_config
from model.launcherrecords import record_emulators
from model.profiles import lists_files
from model.registry import list_registered_platforms
from resolve.content import name_match_size_ok
from resolve.launcherlayer import LauncherLayer
from resolve.launcherconfig import bound_launchers, launcher_unproven
from resolve.launcherplaces import (
    catalogued_model_files,
    name_settings,
    record_directories as launcher_directories,
    record_names as launcher_names,
    set_by,
    setting_readers,
    suffixed_stem,
)
from resolve.localfile import resolve_local_file

# The --json key of the launcher reads category, beside the emulator keys.
LAUNCHER_READS_KEY = "_launcher_reads_not_held"
# The --json key of the launcher records a config file does not prove.
LAUNCHER_UNPROVEN_KEY = "_launcher_unproven"


# A package record names no file: it records what a package builds.
_NAMELESS_KINDS = frozenset({"package"})

# The folder of the platform's own launcher, as its scraper spells it: a
# program the launcher runs from there (RetroBat's xbox-iso-vfs.exe) is part
# of the platform, never a file to collect.
PLATFORM_OWN_FOLDERS = frozenset({"<emulatorLauncher folder>"})


def launcher_file_names(record: dict) -> list[str]:
    """The concrete file names a launcher record reads, in code order.

    The names are read as the launcher layer reads them (`launchers.record_names`):
    a label after the name is dropped ("neocd_z.rom (CDZ)"), and a name with
    `<` or without an extension is not a file name (a folder the record
    links, an option value such as hatari2014's "default"). A name with a
    `{X}` placeholder is a template: Batocera's hatari tries tos{L}.img for
    every language and ROCKNIX links one memory card per slot and region,
    so its expansions say which variants the code accepts, not which file is
    owed. A wildcard is a pattern the emulator matches. `search_dir` is a
    folder and never a name, whatever the kind.
    """
    if record.get("kind") in _NAMELESS_KINDS:
        return []
    return [
        name for name in launcher_names({**record, "expands": {}}) if "*" not in name
    ]


def _profile_names(profiles: dict[str, dict]) -> tuple[dict[str, list[dict]], dict[str, list[dict]]]:
    """Profile entries by each name and alias they answer to, exact and folded."""
    exact: dict[str, list[dict]] = {}
    folded: dict[str, list[dict]] = {}
    for profile in profiles.values():
        if not lists_files(profile):
            continue
        for entry in profile.get("files") or []:
            names = {str(entry.get("name") or "")} | {str(a) for a in entry.get("aliases") or []}
            for name in names - {""}:
                base = name.rsplit("/", 1)[-1]
                exact.setdefault(base, []).append(entry)
                folded.setdefault(base.casefold(), []).append(entry)
    return exact, folded


class _NameHolder:
    """Whether the collection holds a file under a launcher name.

    A name is held when database.json carries a file under it or under an
    alias it indexes, when a profile entry that answers to the name (as its
    name or an alias) resolves, or when resolve_local_file finds it in a data
    directory. The database answers for files kept as release assets, absent
    from a checkout. A copy known only under another casing is returned
    apart: a launcher that matches names exactly does not open it.
    """

    def __init__(
        self, db: dict, profiles: dict[str, dict], data_dir_registry: dict | None
    ) -> None:
        self.db = db
        self.registry = data_dir_registry
        files = db.get("files", {})
        self.by_name = {
            name: sha1s
            for name, sha1s in db.get("indexes", {}).get("by_name", {}).items()
            if any(sha1 in files for sha1 in sha1s)
        }
        self.by_name_folded: dict[str, list[str]] = {}
        for name in self.by_name:
            self.by_name_folded.setdefault(name.casefold(), []).append(name)
        self.exact, self.folded = _profile_names(profiles)
        self._cache: dict[str, tuple[str, bool] | None] = {}

    def _entry_held(self, entry: dict) -> bool:
        names = [str(entry.get("name") or "")] + [str(a) for a in entry.get("aliases") or []]
        if any(n.rsplit("/", 1)[-1] in self.by_name for n in names if n):
            return True
        path, _status = resolve_local_file(entry, self.db, data_dir_registry=self.registry)
        return path is not None

    def held(self, name: str) -> tuple[str, bool] | None:
        """The name the collection holds *name* under, and whether its casing is exact."""
        if name in self._cache:
            return self._cache[name]
        base = name.rsplit("/", 1)[-1]
        found: tuple[str, bool] | None = None
        stem = suffixed_stem(base)
        if base in self.by_name or any(map(self._entry_held, self.exact.get(base, []))) or stem is not None and any(map(self._entry_held, self.exact.get(stem, []))):
            found = (base, True)
        else:
            path, _status = resolve_local_file(
                {"name": name}, self.db, data_dir_registry=self.registry
            )
            if path is not None:
                found = (Path(path).name, Path(path).name == base)
            elif base.casefold() in self.by_name_folded:
                found = (self.by_name_folded[base.casefold()][0], False)
            else:
                entry = next(
                    (e for e in self.folded.get(base.casefold(), []) if self._entry_held(e)),
                    None,
                )
                if entry is not None:
                    found = (str(entry.get("name") or ""), False)
        self._cache[name] = found
        return found


def _held_by_setting(
    name: str,
    settings: dict,
    readers: list[str],
    profiles: dict[str, dict],
    holder: _NameHolder,
    db: dict,
) -> bool:
    """Whether the setting the name is written to reads a held file.

    A placeholder read from the setting takes the held dump the
    catalogues name after the model the launcher's name spells.
    """
    entries = [
        entry
        for key in readers
        for entry in profiles[key].get("files") or []
        if settings[name] and set_by(entry, settings[name])
    ]
    return any(holder._entry_held(entry) for entry in entries) or any(
        "<" in str(entry.get("name", ""))
        and any(
            name_match_size_ok(entry, found.get("size"))
            for found in catalogued_model_files(name, db)
        )
        for entry in entries
    )


def _unsourceable_names(readers: list[str], profiles: dict[str, dict]) -> dict[str, str]:
    return {
        str(n).rsplit("/", 1)[-1]: str(entry["unsourceable"])
        for key in readers
        for entry in profiles[key].get("files") or []
        if entry.get("unsourceable")
        for n in (entry.get("name"), *(entry.get("aliases") or []))
        if n
    }


def _add_name_row(
    by_key: dict[str, dict],
    platform: str,
    name: str,
    found: tuple[str, bool] | None,
    folds: bool,
    reader: dict,
    unsourceable: dict[str, str],
) -> None:
    """Add a launcher record to the row of a name the collection lacks."""
    key = name.casefold() if folds else name
    row = by_key.get(key)
    if row is None:
        row = by_key[key] = {
            "platform": platform,
            "name": name,
            "emulators": [],
            "readers": [],
        }
        if found:
            row["held_as"] = found[0]
    reason = unsourceable.get(name.rsplit("/", 1)[-1])
    if reason and "unsourceable" not in row:
        row["unsourceable"] = reason
    if reader["emulator"] not in row["emulators"]:
        row["emulators"].append(reader["emulator"])
    if reader not in row["readers"]:
        row["readers"].append(reader)


def launcher_reads_not_held(
    configs: dict[str, dict],
    db: dict,
    profiles: dict[str, dict],
    data_dir_registry: dict | None = None,
    emulator: str = "",
) -> list[dict]:
    """The file names a platform's launch code reads that the collection lacks.

    One row per platform and name, with every record that reads it. A
    launcher that matches case-insensitively, or runs on a filesystem that
    folds case, is satisfied by a copy under another casing. Elsewhere such
    a copy is reported with `held_as`, since the launcher does not open it
    under the name it asks for. *emulator* keeps the records whose emulator
    name designates that profile.

    Three records ask for nothing the collection lacks. A search keeps the
    first name it finds, so one held name fills it: RetroBat's Amiberry
    launcher returns the first of kick34005.A500, kick34005.A500.rom and
    amiga-os-130.rom that exists (Amiberry.Generator.cs:674-699). A copy
    whose source lies outside the BIOS directory brings a file the platform
    installs itself, from its own package or written by its own script
    (RetroPie's lr-vecx copies $md_inst/system.bin), and so does a program
    the launcher runs from its own folder. A file handed to the
    setting a reader's profile entry is read from is that entry's file,
    which the pack places under the launcher's name.
    """
    holder = _NameHolder(db, profiles, data_dir_registry)
    every_profile = set(profiles)
    rows: list[dict] = []
    for platform, config in configs.items():
        by_key: dict[str, dict] = {}
        # A record resting on a config file it cannot prove reads nothing
        # yet: it is reported apart (launcher_unproven).
        for record in bound_launchers(config, profiles):
            names = launcher_file_names(record)
            if not names:
                continue
            readers = sorted({
                key
                for part in record_emulators(record)
                for key in LauncherLayer._profiles_named(part, profiles, every_profile)
            })
            if not readers:
                # RetroDECK names its frontend and the core option names the core.
                readers = setting_readers(
                    str(record.get("passes_to") or ""), profiles, every_profile
                )
            if emulator and emulator not in readers:
                continue
            folds = bool(record.get("case_insensitive") or config.get("case_insensitive_fs"))
            base = str(config.get("base_destination") or "bios")
            if record.get("kind") == "copies" and not launcher_directories(record, base):
                continue
            if str(record.get("search_dir") or "") in PLATFORM_OWN_FOLDERS:
                continue
            settings = name_settings(record, names)
            by_model = {
                name for name in names
                if _held_by_setting(name, settings, readers, profiles, holder, db)
            }
            if record.get("kind") == "names_searched" and any(
                (found := holder.held(name)) and (found[1] or folds) for name in names
            ):
                continue
            reader = {
                "emulator": str(record.get("emulator", "")),
                "build": str(record.get("build", "")),
                "kind": str(record.get("kind", "")),
                "source_ref": str(record.get("source_ref", "")),
                "profiles": readers,
            }
            # A name a reader's entry declares unsourceable is no gap: its
            # row carries the reason and is counted apart.
            unsourceable = _unsourceable_names(readers, profiles)
            for name in names:
                found = holder.held(name)
                if found and (found[1] or folds) or name in by_model:
                    continue
                _add_name_row(by_key, platform, name, found, folds, reader, unsourceable)
        rows.extend(by_key[key] for key in sorted(by_key, key=str.casefold))
    return rows


def launcher_rows(
    selected: list[str] | None,
    platforms_dir: str,
    db: dict,
    all_profiles: dict[str, dict],
    registry: dict,
    emulator: str | None,
) -> tuple[list[dict], list[dict]]:
    """The names a launcher reads that the collection lacks, and the
    launcher records nothing proves."""
    configs = {
        name: load_platform_config(name, platforms_dir)
        for name in (selected or list_registered_platforms(platforms_dir))
    }
    # Counted apart from the profile gaps: a name only a launcher reads is
    # reported, not yet judged.
    launcher_reads = launcher_reads_not_held(
        configs, db, all_profiles, registry, emulator or "",
    )

    unproven = [
        row for row in launcher_unproven(configs, all_profiles)
        if not emulator or any(
            emulator in LauncherLayer._profiles_named(part, all_profiles, set(all_profiles))
            for part in record_emulators(row)
        )
    ]
    return launcher_reads, unproven
