"""The platform's launcher layer, read by verify and by the pack builder.

A platform's own launch code often decides which name a file is read under.
Batocera's DuckStation generator tries 22 names per region and keeps the
first it finds, RetroBat's ares launcher writes the LaserActive image it
finds into ares's settings. The platform scraper records that code under
``launchers:`` and this module turns the records into places: a set of
destinations, relative to the directory core files go to, any one of which
the launcher reads for one purpose.

Two consequences follow, both computed here once for every reader. A core
file the launcher would not read because another name of the same place is
held is not missing on that platform. A place nothing fills yet receives,
under the launcher's name, a file the core accepts by content.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from common import declared_root, name_match_size_ok, resolve_local_file, sanitize_pack_path

# The kinds whose names say which file the launcher opens. A link of a named
# file is one too: ROCKNIX links /storage/roms/bios/nds_bios_arm9.bin into
# DraStic's system folder, so that is the path the emulator reads. The others
# hand over a directory, copy a file the platform already names, or let the
# emulator choose.
PLACE_KINDS = ("names_searched", "fixed_name", "core_option", "links")

# How each launcher extractor spells the BIOS directory in search_dir, as the
# platform's own scripts name it: RetroPie's scriptmodules ($biosdir,
# retropie_launchers.BIOSDIR), EmuDeck's EmuScripts (${biosPath},
# emudeck_launchers.BIOS) and RetroDECK's framework ($bios_path,
# retrodeck_launchers.BIOS).
BIOS_ROOT_TOKENS = ("$biosdir", "${biosdir}", "${biosPath}", "$bios_path", "${bios_path}")

# A path spelled from a home or filesystem root names the BIOS directory by
# its base name: /userdata/bios, ~/roms/bios, $HOME/RetroPie/BIOS.
_ROOTED = ("/", "~/", "$HOME/", "$home/", "${HOME}/")

_LABELLED = re.compile(r"^([^\s()]+\.[A-Za-z0-9]+) \([^()]*\)$")
_PLACEHOLDER = re.compile(r"\{(\w+)\}")
_HASH_FIELDS = ("sha1", "md5", "crc32", "sha256")


@dataclass(frozen=True)
class LauncherPlace:
    """One file a launcher opens, under any of ``paths``.

    ``paths`` are in the order the launcher tries them, relative to the
    directory core files go to. An unanchored place has no directory of its
    own: the core resolves the name the launcher passes in the directory it
    reads the entry from. ``alternatives`` is true when the launcher keeps
    the first name it finds, false when each path is the one it passes.
    """

    emulator: str
    build: str
    kind: str
    slot: str
    paths: tuple[str, ...]
    case_insensitive: bool
    anchored: bool
    conditional: bool
    source_ref: str
    passes_to: str = ""

    def fold(self, name: str) -> str:
        return name.lower() if self.case_insensitive else name

    def basenames(self) -> set[str]:
        return {self.fold(p.rsplit("/", 1)[-1]) for p in self.paths}

    @property
    def stands_for_default(self) -> bool:
        """Whether filling the place means the core's default is never read.

        A launcher that always passes the file it found replaces the name
        the core would open by itself. A record that applies only under an
        option or a system leaves that default in use elsewhere, and a core
        option offers a file the user may choose without ever choosing it.
        """
        return (
            self.kind in ("names_searched", "fixed_name", "links")
            and not self.conditional
        )


def setting_tokens(passes_to: str) -> set[str]:
    """The words of a record's ``passes_to``, as an emulator setting is spelled.

    "command line -romfile4p" hands the file to sdltrs's romfile4p option,
    "settings.bml NeoGeoPocket/Firmware/BIOS.World" to an ares setting.
    """
    return {
        word.strip("()\"',;").lstrip("-")
        for word in passes_to.split()
    } - {""}


def suffixed_stem(name: str) -> str | None:
    """The file name a launcher name carries before an extension it appended.

    ROCKNIX's Amiberry config passes kick34005.A500.rom, the name Amiberry
    gives Kickstart 1.3 (amiberry_whdbooter.cpp:370) followed by ".rom". A
    stem that is no file name itself (scph1001 of scph1001.bin) is none.
    """
    base = name.rsplit("/", 1)[-1]
    stem = base.rsplit(".", 1)[0]
    return stem if "." in stem else None


_MODEL = re.compile(r"\b([A-Z]{2,5})-?(\d{3,6}[A-Z]?)\b")


def catalogued_model_files(name: str, db: dict) -> list[dict]:
    """Held files a dump catalogue describes as the model a launcher name spells.

    RetroDECK sets LRPS2's pcsx2_bios option to scph10000.bin, a name no code
    hashes: the SCPH-10000 is the model whose BIOS it means. Redump and TOSEC
    describe two revisions for it. Primaries come before .variants copies,
    then the Redump name, which carries the version (ps2-0100j before
    ps2-0101j), then the No-Intro and TOSEC names.
    """
    stem = name.rsplit("/", 1)[-1].rsplit(".", 1)[0].casefold()
    if not re.fullmatch(r"[a-z]{2,5}\d{3,6}[a-z]?", stem):
        return []
    found = []
    for record in db.get("files", {}).values():
        catalogues = record.get("provenance") or {}
        models = {
            (a + b).casefold()
            for entry in catalogues.values()
            for a, b in _MODEL.findall(str(entry.get("description") or ""))
        }
        if stem in models:
            names = [
                str((catalogues.get(source) or {}).get("name") or "")
                for source in ("redump", "no-intro", "tosec")
            ]
            found.append(("/.variants/" in str(record.get("path", "")), names, record))
    # The core accepts every revision of the model, and neither priority nor
    # region separates two primaries. The pick must still be the same on
    # every run, so it goes to the original revision: the Redump name carries
    # the version, and ps2-0100j sorts before ps2-0101j.
    return [record for *_key, record in sorted(found, key=lambda f: (f[0], f[1]))]


def name_settings(record: dict, names: list[str]) -> dict[str, str]:
    """The setting each name of a record is written to.

    A record naming several files of one config spells passes_to as
    describe_keys does (shell_launchers.py), "atari800.cfg ROM_OS_A_PAL,
    ROM_5200_A, ...", one key per name and in the order of the names. When
    the counts differ, each name keeps the whole description.
    """
    passes_to = str(record.get("passes_to") or "")
    head, _, rest = passes_to.partition(" ")
    keys = [
        key.strip()
        for key in re.sub(r"\[[^\]]*\]", ",", rest).split(",")
        if key.strip()
    ]
    if len(names) > 1 and len(keys) == len(names) and all(" " not in k for k in keys):
        return {name: f"{head} {key}" for name, key in zip(names, keys)}
    return {name: passes_to for name in names}


def setting_readers(passes_to: str, profiles: dict, keys: Iterable[str]) -> list[str]:
    """The profiles with an entry read from the setting a launcher writes."""
    if not passes_to:
        return []
    return sorted(
        key for key in keys
        if (profile := profiles.get(key)) is not None
        and any(set_by(entry, passes_to) for entry in profile.get("files") or [])
    )


def set_by(entry: dict, passes_to: str) -> bool:
    """Whether a launcher hands its file to the setting a profile entry is read from."""
    key = str(entry.get("config_key") or "")
    return bool(key) and key in setting_tokens(passes_to)


def _bios_relative(directory: str, base: str) -> str | None:
    """A launcher directory relative to the BIOS root, None when it is not one."""
    directory = directory.strip().rstrip("/")
    roots = {base, "<system_directory>", *BIOS_ROOT_TOKENS}
    head, _, rest = directory.partition("/")
    if directory in roots:
        return ""
    if head in roots:
        relative = rest
    elif directory.startswith(_ROOTED) and base and f"/{base}/" in f"{directory}/":
        relative = f"{directory}/".split(f"/{base}/", 1)[1].rstrip("/")
    else:
        return None
    return None if re.search(r"[\s<>]", relative) else relative


def _directories(record: dict, base: str) -> list[str] | None:
    """The directories a record reads, in order. None when the code says none.

    ``search_dir`` transcribes the code, conditions included: "bios/chihiro,
    then bios", "bios/pcsx2/bios if any listed name is there, else bios".
    A directory the record describes rather than names ("directory of the
    Chihiro BIOS found") cannot be placed.
    """
    raw = record.get("search_dir")
    if raw is None:
        return None
    text = re.sub(r"\([^()]*\)", "", str(raw))
    text = re.sub(r"\s+if\s+[^,]*", "", text)
    found: list[str] = []
    for part in re.split(r",|\bthen\b|\belse\b", text):
        if not part.strip():
            continue
        relative = _bios_relative(part, base)
        if relative is None:
            return []
        if relative not in found:
            found.append(relative)
    return found


def _names(record: dict) -> list[str]:
    """The file names a record tries, placeholders expanded in code order."""
    expands = record.get("expands") or {}
    names: list[str] = []
    for raw in record.get("names") or []:
        name = str(raw).strip()
        labelled = _LABELLED.match(name)
        if labelled:
            name = labelled.group(1)
        expanded = [name]
        for key in _PLACEHOLDER.findall(name):
            values = expands.get(key)
            if values is None:
                expanded = []
                break
            expanded = [
                candidate.replace("{" + key + "}", str(value))
                for candidate in expanded
                for value in values
            ]
        for candidate in expanded:
            if "<" in candidate or "." not in candidate.rsplit("/", 1)[-1]:
                continue
            if candidate not in names:
                names.append(candidate)
    return names


def launcher_places(config: dict) -> list[LauncherPlace]:
    """Every place a platform's launchers open a named file from."""
    base = str(config.get("base_destination") or "bios")
    places: list[LauncherPlace] = []
    for record in config.get("launchers") or []:
        kind = record.get("kind")
        if kind not in PLACE_KINDS:
            continue
        names = _names(record)
        directories = _directories(record, base)
        if not names or directories == []:
            continue
        anchored = directories is not None

        def paths_of(name: str) -> tuple[str, ...]:
            if not anchored:
                return (name,)
            return tuple(
                sanitize_pack_path(f"{d}/{name}" if d else name) for d in directories
            )

        common = {
            "emulator": str(record.get("emulator", "")),
            "build": str(record.get("build", "")),
            "kind": kind,
            "slot": str(record.get("slot") or ""),
            # A filesystem that folds case folds it for the launcher too.
            "case_insensitive": bool(
                record.get("case_insensitive") or config.get("case_insensitive_fs")
            ),
            "anchored": anchored,
            "conditional": bool(record.get("depends_on_option")),
            "source_ref": str(record.get("source_ref", "")),
        }
        settings = name_settings(record, names)
        if kind == "names_searched":
            # Each directory in turn, every name in it.
            depth = len(directories) if anchored else 1
            ordered = tuple(paths_of(name)[i] for i in range(depth) for name in names)
            places.append(LauncherPlace(
                paths=ordered, passes_to=str(record.get("passes_to") or ""), **common
            ))
            continue
        # A fixed name is the one file passed, and a core option offers
        # each value as the file the user picks: one place per name.
        places.extend(
            LauncherPlace(paths=paths_of(name), passes_to=settings[name], **common)
            for name in names
        )
    return places


# The names a platform's launch code gives its BIOS root, besides the
# base_destination _bios_relative reads: RetroPie's scriptmodules set
# biosdir="$home/RetroPie/BIOS", EmuDeck's scripts ${biosPath}, RetroDECK's
# component scripts $bios_path.
BIOS_ROOT_VARIABLES = ("$biosdir", "$home/RetroPie/BIOS", "${biosPath}", "$bios_path")

# The kinds that hand an emulator a whole directory.
HANDED_KINDS = ("links", "passes_path")

_HOME = re.compile(r"^(?:\$\{HOME\}|\$HOME|\$home|~)(?=/|$)")
# Flatpak sets XDG_DATA_HOME to ~/.var/app/<id>/data inside the sandbox.
_FLATPAK_DATA = re.compile(r"^~/\.var/app/[^/]+/data(?=/|$)")


def normalize_handle(token: str) -> str:
    """One spelling for a path, setting or function a launcher record names.

    ``$home``, ``$HOME``, ``${HOME}`` and ``~`` are one directory, and a
    Flatpak's data directory is its ``$XDG_DATA_HOME``.
    """
    token = token.strip().strip("\"'").rstrip(",;").rstrip("/")
    token = token.removesuffix("()")
    token = _HOME.sub("~", token)
    return _FLATPAK_DATA.sub("$XDG_DATA_HOME", token)


def _folder_in_bios(directory: str, base: str) -> str | None:
    """A directory relative to the BIOS root, None when it lies outside."""
    relative = _bios_relative(directory, base)
    if relative is not None:
        return relative
    directory = directory.strip().rstrip("/")
    for variable in BIOS_ROOT_VARIABLES:
        if directory == variable:
            return ""
        if directory.startswith(variable + "/"):
            rest = directory[len(variable) + 1:]
            return None if re.search(r"[\s<>$:;]", rest) else rest
    return None


@dataclass(frozen=True)
class HandedDirectory:
    """A whole directory a platform hands a standalone emulator.

    ``folder`` is the directory relative to the BIOS root, None when it lies
    outside it. ``handles`` are the paths, settings and functions the record
    names on the emulator's side: the link's other end, the config key, the
    function a patch rewrites.
    """

    emulator: str
    folder: str | None
    directory: str
    handles: frozenset[str]
    source_ref: str


def handed_directories(config: dict) -> list[HandedDirectory]:
    """Every whole directory a platform links or passes to a standalone build.

    A record naming files (gpsp's gba_bios.bin) or one slot of a directory
    (RetroDECK's GC/EUR) hands over no whole directory, and a search_dir
    holding several directories names no single one.
    """
    base = str(config.get("base_destination") or "bios")
    found: list[HandedDirectory] = []
    for record in config.get("launchers") or []:
        if record.get("build") != "standalone" or record.get("kind") not in HANDED_KINDS:
            continue
        if record.get("names") or record.get("slot"):
            continue
        raw = str(record.get("search_dir") or "").strip()
        if not raw or re.search(r"[\s,:;]", raw):
            continue
        directory = normalize_handle(raw)
        handles = frozenset(
            handle
            for token in str(record.get("passes_to") or "").split()
            if (handle := normalize_handle(token)) and handle != directory
        )
        for emulator in (e.strip() for e in str(record.get("emulator", "")).split(",")):
            found.append(HandedDirectory(
                emulator=emulator,
                folder=_folder_in_bios(raw, base),
                directory=directory,
                handles=handles,
                source_ref=str(record.get("source_ref", "")),
            ))
    return found


def standalone_root(
    names: Iterable[str], declared: Iterable[str], handed: Iterable[HandedDirectory]
) -> str | None:
    """The folder of the BIOS tree a platform gives a standalone build's layout.

    ``declared`` are the directories the build resolves ``standalone_path``
    against, as its profile names them (``standalone_directories``). A
    record handing a folder of the BIOS tree under one of them gives it
    directly: RetroPie points Flycast's ~/.local/share/flycast at bios/dc. A
    record handing a directory outside the tree under one of them is
    followed through a link to the tree: ROCKNIX's patched Flycast uses
    /storage/roms/dreamcast/data, which its start script links to bios/dc.

    None when nothing gives a folder, or when two records give two: the
    layout is then the profile's, relative to the BIOS root.
    """
    names = set(names)
    wanted = {normalize_handle(d) for d in declared}
    if not wanted:
        return None
    records = [h for h in handed if h.emulator in names]
    folders: set[str] = set()
    for record in records:
        if not record.handles & wanted:
            continue
        if record.folder is not None:
            folders.add(record.folder)
            continue
        folders.update(
            link.folder
            for link in records
            if link.folder is not None and record.directory in link.handles
        )
    return next(iter(folders)) if len(folders) == 1 else None


def held_record(report: dict, db: dict) -> dict | None:
    """The database record of the file the collection holds for a report entry."""
    local, status = resolve_local_file(report, db, dest_hint=report.get("path") or "")
    if local is None or status in ("not_found", "hash_mismatch"):
        return None
    for record in db.get("files", {}).values():
        if record.get("path") == local:
            return record
    return None


def declared_destinations(config: dict) -> set[str]:
    """Each destination the platform declares, relative to the core file directory.

    Case is kept: a launcher that matches names exactly is not served by a
    declaration of another case.
    """
    prefix = declared_root(config)
    found: set[str] = set()
    for system in config.get("systems", {}).values():
        for entry in system.get("files", []):
            slot = sanitize_pack_path(entry.get("destination") or entry.get("name", ""))
            if prefix and slot.lower().startswith(prefix.lower() + "/"):
                slot = slot[len(prefix) + 1:]
            if slot:
                found.add(slot)
    return found


def _hashes(entry: dict) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for field in _HASH_FIELDS:
        value = entry.get(field) or (entry.get("expected") or {}).get(field)
        if not value:
            continue
        values = value if isinstance(value, list) else str(value).split(",")
        found[field] = {str(v).strip().lower() for v in values if str(v).strip()}
    return found


def accepts(entry: dict, record: dict) -> bool:
    """Whether a core entry takes the database file ``record`` by its content."""
    hashes = _hashes(entry)
    if not hashes:
        return False
    return any(
        str(record.get(field, "")).lower() in values
        for field, values in hashes.items()
    )


@dataclass
class _Candidate:
    """A core entry one launcher place stands for, and how it was matched."""

    entry: dict
    names: set[str]
    by_content: bool
    # Matched by the size the code checks, the entry naming no hash.
    by_shape: bool = False
    # Matched through the setting the launcher writes or the name it extends.
    by_setting_or_stem: bool = False


class LauncherLayer:
    """The launcher places of one platform matched to the cores it runs.

    ``declared`` holds each destination the platform declares, relative to
    the directory core files go to, case kept.
    """

    def __init__(
        self,
        config: dict,
        profiles: dict,
        relevant: Iterable[str],
        db: dict,
        declared: Iterable[str],
    ) -> None:
        self.places = launcher_places(config)
        self.declared = set(declared)
        self.declared_folded = {d.lower() for d in self.declared}
        self.declared_names = {d.rsplit("/", 1)[-1] for d in self.declared}
        self.declared_names_folded = {n.lower() for n in self.declared_names}
        by_name = db.get("indexes", {}).get("by_name", {})
        self._by_name = by_name
        self._by_name_folded: dict[str, list[str]] = {}
        for name, sha1s in by_name.items():
            self._by_name_folded.setdefault(name.lower(), []).extend(sha1s)
        self._files = db.get("files", {})
        self._owners: dict[tuple[str, bool], list[LauncherPlace]] = {}
        self._unoffered: dict[tuple[str, bool], list[tuple[dict, dict]]] = {}
        relevant = set(relevant)
        for place in self.places:
            standalone = place.build == "standalone"
            owners = {
                key
                for emulator in (e.strip() for e in place.emulator.split(","))
                for key in self._profiles_named(emulator, profiles, relevant)
            }
            # RetroDECK names its frontend, retroarch, and the core option it
            # writes, pcsx2_bios, names the core.
            if not owners:
                owners = set(setting_readers(place.passes_to, profiles, relevant))
            for key in sorted(owners):
                self._owners.setdefault((key, standalone), []).append(place)
                # The report never offers a placeholder, which stands for every
                # file a scan finds, nor an entry the platform's list settles
                # (AmberELEC declares kick34005.A500): the launcher still reads
                # its file under its own name.
                self._unoffered.setdefault((key, standalone), [
                    (entry, _placeholder_report(key, profiles[key], entry))
                    for entry in profiles[key].get("files") or []
                ])
        self._db = db

    @staticmethod
    def _profiles_named(name: str, profiles: dict, relevant: set[str]) -> list[str]:
        """The profiles a platform's emulator name designates, among those it runs."""
        return sorted(
            key for key in relevant
            if (profile := profiles.get(key)) is not None
            and profile.get("type") not in ("alias", "launcher")
            and (key == name or name in {str(c) for c in profile.get("cores") or []})
        )

    def __bool__(self) -> bool:
        return bool(self._owners)

    def places_for(self, emulator: str, standalone: bool) -> list[LauncherPlace]:
        return self._owners.get((emulator, standalone), [])

    def files_named(self, place: LauncherPlace, name: str) -> list[dict]:
        """The database files carrying a name, in the place's case rule."""
        if place.case_insensitive:
            sha1s = self._by_name_folded.get(name.lower(), [])
        else:
            sha1s = self._by_name.get(name, [])
        return [self._files[s] for s in dict.fromkeys(sha1s) if s in self._files]

    def match(self, place: LauncherPlace, entry: dict) -> _Candidate | None:
        """How a core entry belongs to a place: by a name it is read under, or by content."""
        basenames = place.basenames()
        own = {
            place.fold(str(n).rsplit("/", 1)[-1])
            for n in (entry.get("name", ""), *(entry.get("aliases") or []))
            if n
        }
        names = own & basenames
        if names:
            return _Candidate(entry, names, False)
        # RetroPie runs sdl2trs with -romfile4p $biosdir/level4p.rom: the
        # file under that name is the one the romfile4p slot reads.
        if set_by(entry, place.passes_to):
            return _Candidate(entry, basenames, False, by_setting_or_stem=True)
        if place.kind == "fixed_name":
            stems = {
                base for base in basenames
                if (stem := suffixed_stem(base)) is not None and place.fold(stem) in own
            }
            if stems:
                return _Candidate(entry, stems, False, by_setting_or_stem=True)
        content = {
            place.fold(path.rsplit("/", 1)[-1])
            for path in place.paths
            if any(
                accepts(entry, record)
                for record in self.files_named(place, path.rsplit("/", 1)[-1])
            )
        }
        if content:
            return _Candidate(entry, content, True)
        # A hashless entry the code checks by size: EmuDeck passes
        # Complex_4627v1.03.bin as xemu's flash ROM, and xemu's entry
        # Complex_4627.bin states only the sizes it maps.
        checks = entry.get("validation") or []
        sized = any(entry.get(k) for k in ("size", "min_size", "max_size"))
        if not _hashes(entry) and sized and "size" in checks:
            shaped = {
                place.fold(path.rsplit("/", 1)[-1])
                for path in place.paths
                if any(
                    name_match_size_ok(entry, record.get("size"))
                    for record in self.files_named(place, path.rsplit("/", 1)[-1])
                )
            }
            if shaped:
                return _Candidate(entry, shaped, False, by_shape=True)
        return None

    def platform_holds(self, place: LauncherPlace) -> bool:
        """Whether the platform's own list declares a file the place reads."""
        if place.anchored:
            pool = self.declared_folded if place.case_insensitive else self.declared
            return any(place.fold(path) in pool for path in place.paths)
        pool = self.declared_names_folded if place.case_insensitive else self.declared_names
        return bool(place.basenames() & pool)

    def settle(
        self,
        candidates: list[tuple[str, bool, dict, dict]],
        resolve_held: Callable[[dict], dict | None],
    ) -> tuple[list[dict], set[int]]:
        """What the launcher layer adds to the report and what it settles.

        ``candidates`` holds (profile, standalone, profile entry, report
        entry) for every core entry the report considered. ``resolve_held``
        returns the database record of the file the collection holds for a
        report entry, None when it holds none.

        Returns the report entries to add, one per place nothing filled that
        a held file the core accepts can fill under the launcher's name, and
        the ids of the report entries the filled places settle.
        """
        added: list[dict] = []
        settled: set[int] = set()
        # Destinations the report already fills with a held file, whichever
        # core asked for it: the pack puts a file there either way.
        reported_at: dict[str, dict] = {}
        for _emulator, _standalone, _entry, report in candidates:
            if report.get("in_repo"):
                destination = sanitize_pack_path(report.get("path") or report.get("name", ""))
                reported_at.setdefault(destination, report)
        by_layout: dict[tuple[str, bool], list[tuple[dict, dict]]] = {}
        for emulator, standalone, entry, report in candidates:
            by_layout.setdefault((emulator, standalone), []).append((entry, report))
        offered = {id(entry) for _e, _s, entry, _r in candidates}
        for layout, members in self._unoffered.items():
            for entry, report in members:
                if id(entry) in offered:
                    continue
                if "<" not in str(entry.get("name", "")):
                    report["in_repo"] = resolve_held(report) is not None
                report["unoffered"] = True
                by_layout.setdefault(layout, []).append((entry, report))
        placed: set[str] = set()
        for (emulator, standalone), members in sorted(by_layout.items()):
            for place in self.places_for(emulator, standalone):
                # An entry the report left out answers only through the
                # setting or the extended name: by its own name it was left
                # out for a reason (a region variant, a settled duplicate).
                matched = [
                    (candidate, report)
                    for entry, report in members
                    if (candidate := self.match(place, entry)) is not None
                    and (candidate.by_setting_or_stem or not report.get("unoffered"))
                ]
                # A size names one entry only when no other of the core's
                # entries takes that size too.
                if sum(c.by_shape for c, _ in matched) > 1:
                    matched = [(c, r) for c, r in matched if not c.by_shape]
                if not matched:
                    continue
                filled = self._fill(place, matched, reported_at, resolve_held, placed)
                if filled is None:
                    continue
                if isinstance(filled, dict):
                    added.append(filled)
                if place.stands_for_default:
                    # The emulator opens the launcher's file instead of its
                    # own name, so a copy under that name is read by nobody:
                    # EmuDeck passes Complex_4627v1.03.bin to xemu, which then
                    # never opens Complex_4627.bin. A held file sitting on one
                    # of the place's own paths is what fills it.
                    own = {place.fold(p) for p in place.paths}
                    settled.update(
                        id(report) for _candidate, report in matched
                        if not report.get("in_repo")
                        or place.fold(sanitize_pack_path(
                            report.get("path") or report.get("name", "")
                        )) not in own
                    )
        return added, settled

    def _fill(
        self,
        place: LauncherPlace,
        matched: list[tuple[_Candidate, dict]],
        reported_at: dict[str, dict],
        resolve_held: Callable[[dict], dict | None],
        placed: set[str],
    ) -> dict | bool | None:
        """True when the place is filled already, a new report entry when one fills it."""
        if self.platform_holds(place):
            return True
        folded_reported = {place.fold(dest): r for dest, r in reported_at.items()}
        for path in place.paths:
            name = path.rsplit("/", 1)[-1]
            key = place.fold(name)
            if place.anchored:
                if place.fold(path) in folded_reported:
                    return True
            elif any(
                key == place.fold(r.get("name", "")) or key == place.fold(dest.rsplit("/", 1)[-1])
                for dest, r in folded_reported.items()
            ):
                return True
            if not place.anchored:
                # A setting holds a name the core resolves in the directory
                # of the entry read from it: LRPS2 joins pcsx2_bios under
                # pcsx2/bios.
                setting = [
                    (candidate, report) for candidate, report in matched
                    if set_by(candidate.entry, place.passes_to)
                ]
                directory = next(
                    (
                        str(c.entry.get("path") or "").rpartition("/")[0]
                        for c, _report in setting
                        if "/" in str(c.entry.get("path") or "")
                    ),
                    None,
                )
                if directory is None:
                    continue
                path = f"{directory}/{name}"
                if place.fold(path) in folded_reported:
                    return True
                source = self._content_for(place, name, key, setting, resolve_held)
                if source is None or place.fold(path) in placed:
                    continue
                placed.add(place.fold(path))
                return _launcher_entry(source[0], name, path, source[1], place)
            # The emulator as this platform installs it brings the file: the
            # place is filled, nothing is packed (ROCKNIX's xemu hdd image).
            if any(key in candidate.names and report.get("bundled")
                   for candidate, report in matched):
                return True
            source = self._content_for(place, name, key, matched, resolve_held)
            if source is None:
                continue
            report, record = source
            if place.fold(path) in placed:
                return True
            placed.add(place.fold(path))
            return _launcher_entry(report, name, path, record, place)
        return None

    def _content_for(
        self,
        place: LauncherPlace,
        name: str,
        key: str,
        matched: list[tuple[_Candidate, dict]],
        resolve_held: Callable[[dict], dict | None],
    ) -> tuple[dict, dict] | None:
        """A held file the core accepts for one launcher name, and its entry.

        The file the database knows under that name comes first when the
        core accepts it: by content when the entry pins one, by name and
        size when the entry reads it under that name. Otherwise the file the
        collection holds for an entry read under that name.
        """
        for candidate, report in matched:
            if key not in candidate.names:
                continue
            for record in self.files_named(place, name):
                if accepts(candidate.entry, record) or (
                    not candidate.by_content
                    and not _hashes(candidate.entry)
                    and name_match_size_ok(candidate.entry, record.get("size"))
                ):
                    return report, record
        for candidate, report in matched:
            if key not in candidate.names or candidate.by_content:
                continue
            if not report.get("in_repo"):
                continue
            record = resolve_held(report)
            if record is not None:
                return report, record
        for candidate, report in matched:
            if key not in candidate.names or not set_by(candidate.entry, place.passes_to):
                continue
            for record in catalogued_model_files(name, self._db):
                if name_match_size_ok(candidate.entry, record.get("size")):
                    return report, record
        return None


def _placeholder_report(key: str, profile: dict, entry: dict) -> dict:
    """The report entry of an entry the gap report never builds."""
    identity = {
        field: entry[field]
        for field in ("aliases", "md5", "sha1", "sha256", "crc32", "size", "min_size", "max_size")
        if entry.get(field) is not None
    }
    return {
        **identity,
        "profile": key,
        "emulator": profile.get("emulator", key),
        "name": entry.get("name", ""),
        "path": entry.get("path") or entry.get("name", ""),
        "system": entry.get("system"),
        "systems": profile.get("systems"),
        "required": entry.get("required", False),
        "category": entry.get("category"),
        "in_repo": False,
    }


def _launcher_entry(
    report: dict, name: str, path: str, record: dict, place: LauncherPlace
) -> dict:
    """The report entry asking for a file under the name a launcher opens."""
    entry = {
        key: report.get(key)
        for key in (
            "profile", "emulator", "systems", "system", "region", "variant_group",
            "required", "hle_fallback", "category",
        )
    }
    entry.update(
        name=name,
        path=path,
        bundled=False,
        in_repo=True,
        note="",
        checks=[],
        source_ref=None,
        expected={},
        sha1=record.get("sha1"),
        md5=record.get("md5"),
        launcher=place.source_ref,
        launcher_of=report.get("name", ""),
    )
    return entry
