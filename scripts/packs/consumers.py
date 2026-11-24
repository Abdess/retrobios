"""Who reads each collected file, joined through the resolver as the pack resolves it."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from core.paths import BIOS_DIR, PLATFORMS_DIR, REPO_ROOT
from model.database import sha1_at
from model.registry import load_data_dir_registry
from packs.supplemental import content_matches, declared_content, supplemental_locations
from resolve.archives import archive_entry
from resolve.directories import expand_directory_entries
from resolve.localfile import resolve_local_file
from resolve.acceptance import inner_rom_check
from resolve.entryscope import with_archive_members


def held_copy(
    entry: dict, data_root: str = "data", bios_root: str = BIOS_DIR
) -> tuple[str, str] | None:
    """The data/ file or bios/ ZIP member holding a file entry.

    The database indexes the files under bios/, and an entry held otherwise
    (specmate.rom as a member of spectrum_opus.zip, Dolphin's fonts in its
    data directory) read as held with no word of where. Returns (path,
    member), the member empty for a file. A file entry that declares a hash
    is held only by a copy carrying it, as data_hit judges. A directory
    entry is never answered here: its copies are the files
    FileConsumers.directory_members finds, the ones verify and the pack
    read, and a folder of the same name elsewhere held another emulator's
    tree (SuperTux's data/ named MAME's plugins/data/).
    """
    names = [entry.get("name", ""), entry.get("path") or "", *(entry.get("aliases") or [])]
    names = [str(n) for n in names if n]
    if entry.get("type") == "directory" or any(n.endswith("/") for n in names[:1]):
        return None
    declared = declared_content(entry)
    locations = supplemental_locations(data_root, bios_root)
    for name in names:
        for location in locations.get(name.rsplit("/", 1)[-1].lower(), ()):
            if not declared or content_matches(location, declared):
                return location
    return None


class FileConsumers:
    """Who reads each collected file, joined through the resolver.

    The site joined database files to emulators and platforms by bare name:
    each of the four pak0.pk3 of four games was attributed to every engine
    reading a pak0.pk3. A consumer here is an entry that resolves to the
    file by the evidence the pack uses, so a homonym is nobody's file.
    """

    def __init__(
        self, db: dict, zip_contents: dict | None = None,
        data_dir_registry: dict | None = None,
    ) -> None:
        self._db = db
        self._zip_contents = zip_contents
        # The builder resolves with the data trees: Dolphin's codehandler.bin
        # comes from data/dolphin-sys, and without them the name step gave it
        # Dolphin-MMJR's copy, which the site then said Dolphin reads.
        self._data_dir_registry = (
            data_dir_registry if data_dir_registry is not None
            else load_data_dir_registry(
                str(REPO_ROOT / PLATFORMS_DIR)
            )
        )
        self.platforms: dict[str, set[str]] = {}
        # Under which of its systems each platform declares a file, so a
        # link can land on that section rather than the page top.
        self.platform_systems: dict[str, dict[str, set[str]]] = {}
        # Where each platform puts the file in its BIOS directory.
        self.platform_destinations: dict[str, dict[str, set[str]]] = {}
        self.emulators: dict[str, set[str]] = {}
        # The entry that reads each file, by its position in the profile's
        # files: a link lands on that entry's card, not the page top.
        self.emulator_entries: dict[str, dict[str, int]] = {}
        self.emulator_files: dict[str, list] = {}
        # Where each platform's pack installs the file, its cores' files
        # included: the platform's own list names a fraction of them.
        self.installed: dict[str, dict[str, set[str]]] = {}

    def sha1_of(self, entry: dict, dest: str = "", owner: str = "") -> str | None:
        """The collected file an entry resolves to, or None.

        A profile entry names its owner, as the builder does: without it the
        name step chose another tree's copy, and the page credited the file
        the pack does not ship.
        """
        if not entry.get("name"):
            return None
        if owner:
            entry = {**entry, "source_profile": owner}
        path, status = resolve_local_file(
            entry, self._db, self._zip_contents, dest_hint=dest,
            data_dir_registry=self._data_dir_registry,
        )
        if not path or status == "not_found":
            return None
        # Batocera pins naomi2.zip by the md5 of a ROM inside it: the resolver
        # hands back the archive as a mismatch, and the member settles it as
        # the builder does.
        if status == "hash_mismatch" and not (
            entry.get("zipped_file") and inner_rom_check(entry, path) == "ok"
        ):
            return None
        return sha1_at(self._db, path)

    def add_platforms(self, configs: dict[str, dict]) -> None:
        for name, config in configs.items():
            for system_id, system in config.get("systems", {}).items():
                for entry in system.get("files", []):
                    # No destination hint, as the builder, the manifest and
                    # verify resolve a declaration: with one, RetroBat's 63
                    # mame/hash lists credited another revision than the one
                    # its manifest installs.
                    sha1 = self.sha1_of(entry)
                    if sha1:
                        self.platforms.setdefault(sha1, set()).add(name)
                        self.platform_systems.setdefault(sha1, {}).setdefault(
                            name, set()
                        ).add(system_id)
                        where = str(entry.get("destination") or entry["name"])
                        # EmuDeck matches by md5 alone: its entries carry a
                        # system:md5 key, not a place in the folder.
                        if ":" not in where:
                            self.platform_destinations.setdefault(sha1, {}).setdefault(
                                name, set()
                            ).add(where)

    def add_manifests(self, install_dir: str | Path) -> None:
        """Read what each install manifest places, alternatives included."""
        for path in sorted(Path(install_dir).glob("*.json")):
            try:
                manifest = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                print(f"WARNING: {path}: {exc}", file=sys.stderr)
                continue
            platform = str(manifest.get("platform") or path.stem)
            for entry in manifest.get("files") or []:
                for sha1 in {entry.get("sha1"), *(
                    alt.get("sha1") for alt in entry.get("alternatives") or []
                )} - {None, ""}:
                    self.installed.setdefault(sha1, {}).setdefault(
                        platform, set()).add(str(entry.get("dest", "")))

    def sha1_at(self, path: str) -> str | None:
        """The file the database records at a collection path."""
        return sha1_at(self._db, path)

    def path_of(self, sha1: str) -> str:
        """The collection path the database records for a file."""
        return str(self._db.get("files", {}).get(sha1, {}).get("path", ""))

    def directory_members(self, entry: dict) -> dict[str, str]:
        """{destination: sha1} of the files a ``type: directory`` entry reads."""
        if entry.get("type") != "directory":
            return {}
        return {
            member["path"]: member["sha1"]
            for member in expand_directory_entries([entry], self._db)
            if member is not entry
        }

    def add_emulators(self, profiles: dict[str, dict]) -> None:
        """Each file a profile entry resolves to, a directory's members included.

        A directory entry was resolved by its own name and found nothing:
        11,976 files under alephone's Plugins/, cdogs' and thextech's trees
        named no emulator on their card.
        """
        for name, profile in profiles.items():
            if profile.get("type") == "alias":
                continue
            files = profile.get("files") or []
            self.emulator_files[name] = files
            # A file a profile names keeps its own entry over the directory
            # that also holds it.
            order = sorted(
                (i for i, entry in enumerate(files) if isinstance(entry, dict)),
                key=lambda i: files[i].get("type") == "directory",
            )
            for index in order:
                entry = files[index]
                members = self.directory_members(entry)
                if members:
                    found = [
                        self.sha1_of({**entry, "name": dest, "path": dest, "sha1": sha1},
                                     dest, owner=name)
                        for dest, sha1 in members.items()
                    ]
                else:
                    found = [self.sha1_of(*entry_target(entry, files), owner=name)]
                for sha1 in found:
                    if sha1:
                        self.emulators.setdefault(sha1, set()).add(name)
                        self.emulator_entries.setdefault(sha1, {}).setdefault(name, index)


def entry_target(entry: dict, files: list[dict]) -> tuple[dict, str]:
    """The entry a profile entry resolves through, and its destination.

    A ROM read inside an archive is the archive: FBNeo opens sm1.sm1 in
    neogeo.zip, and resolved by its crc32 it credited a loose copy FBNeo
    never opens, while no neogeo.zip card named FBNeo. The archive
    members the profile reads decide between same-named copies, as in
    the emulator pack and verify.
    """
    if entry.get("archive"):
        return archive_entry(entry["archive"], files), ""
    return with_archive_members(entry, files), entry.get("path") or ""
