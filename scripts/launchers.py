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
        if kind == "names_searched":
            # Each directory in turn, every name in it.
            depth = len(directories) if anchored else 1
            ordered = tuple(paths_of(name)[i] for i in range(depth) for name in names)
            places.append(LauncherPlace(paths=ordered, **common))
            continue
        # A fixed name is the one file passed, and a core option offers
        # each value as the file the user picks: one place per name.
        places.extend(LauncherPlace(paths=paths_of(name), **common) for name in names)
    return places


# The names a platform's launch code gives its BIOS root, besides the
# base_destination _bios_relative reads: RetroPie's scriptmodules set
# biosdir="$home/RetroPie/BIOS", EmuDeck's scripts ${biosPath}, RetroDECK's
# component scripts $bios_path.
BIOS_ROOT_VARIABLES = ("$biosdir", "$home/RetroPie/BIOS", "${biosPath}", "$bios_path")

# The kinds that hand an emulator a whole directory.
HANDED_KINDS = ("links", "passes_path")

# How a launcher record says the platform starts the emulator in a directory
# (retropie_launchers._working_directory), and the handle a profile gives
# that directory in standalone_directories: the call its code reads it with.
WORKING_DIRECTORY_PASSED = "working directory of "
WORKING_DIRECTORY = "getcwd"
# The handle a profile declares when its program reads its files beside its
# own executable: a launcher record executing one of the profile's files
# places the folder holding that file where the launcher runs it from.
EXECUTABLE_DIRECTORY = "executable directory"

# The trees a placed folder belongs to: the BIOS tree every destination is
# relative to, and the roms directory of a platform whose registry names it.
BIOS_TREE = ""
ROMS_TREE = "roms"
# A folder of neither tree, which no pack and no installer can fill.
OUTSIDE_TREE = "outside"
Place = tuple[str, str]

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
    roms_folder: str | None = None

    def place(self) -> Place | None:
        """The folder as a place, None when it lies outside both roots."""
        if self.folder is not None:
            return (BIOS_TREE, self.folder)
        if self.roms_folder is not None:
            return (ROMS_TREE, self.roms_folder)
        return None


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
        passes_to = str(record.get("passes_to") or "")
        if passes_to.startswith(WORKING_DIRECTORY_PASSED):
            # The program runs from the directory: what its code reads
            # through getcwd(), or relative to it, is below it.
            handles = frozenset({WORKING_DIRECTORY})
        else:
            handles = frozenset(
                handle
                for token in passes_to.split()
                if (handle := normalize_handle(token)) and handle != directory
            )
        folder = _folder_in_bios(raw, base)
        for emulator in (e.strip() for e in str(record.get("emulator", "")).split(",")):
            found.append(HandedDirectory(
                emulator=emulator,
                folder=folder,
                directory=directory,
                handles=handles,
                source_ref=str(record.get("source_ref", "")),
                roms_folder=None if folder is not None else folder_in_roms(raw, config),
            ))
    return found


def folder_in_roms(directory: str, config: dict) -> str | None:
    """A directory relative to the platform's roms directory, None outside it.

    Only a platform whose registry names the roms directory has one
    (``roms_directory.path``): ROCKNIX's /storage/roms, which holds its BIOS
    folder and the folders its launchers run programs from.
    """
    roms = str((config.get("roms_directory") or {}).get("path") or "").rstrip("/")
    directory = directory.strip().rstrip("/")
    if not roms or not directory.startswith(roms + "/"):
        return None
    rest = directory[len(roms) + 1:]
    return None if re.search(r"[\s<>$:;]", rest) else rest


@dataclass(frozen=True)
class ExecutedFile:
    """A file a platform's launcher executes, and where it lies.

    ``place`` is (root, path): the BIOS tree or the roms directory, None
    when the file lies outside both (RetroBat's emulator folders).
    """

    emulator: str
    name: str
    place: Place | None
    source_ref: str


def executed_files(config: dict) -> list[ExecutedFile]:
    """Every file a platform's launchers execute, from records passing it to exec."""
    base = str(config.get("base_destination") or "bios")
    found: list[ExecutedFile] = []
    for record in config.get("launchers") or []:
        if record.get("kind") not in ("fixed_name", "names_searched"):
            continue
        if str(record.get("passes_to") or "").strip() != "exec":
            continue
        raw = str(record.get("search_dir") or "").strip()
        directories = _directories(record, base)
        roms = folder_in_roms(raw, config) if raw and not directories else None
        # A program file needs no extension (pico8, vox): the names are
        # taken as written, placeholders left out.
        for name in (str(n).strip() for n in record.get("names") or []):
            if not name or re.search(r"[<>{}]", name):
                continue
            if directories:
                place: Place | None = (BIOS_TREE, sanitize_pack_path(
                    f"{directories[0]}/{name}" if directories[0] else name
                ))
            elif roms is not None:
                place = (ROMS_TREE, sanitize_pack_path(f"{roms}/{name}" if roms else name))
            else:
                place = None
            for emulator in (e.strip() for e in str(record.get("emulator", "")).split(",")):
                found.append(ExecutedFile(
                    emulator, name.rsplit("/", 1)[-1], place, str(record.get("source_ref", ""))
                ))
    return found


def standalone_bindings(
    names: Iterable[str],
    declared: Iterable[str],
    handed: Iterable[HandedDirectory],
    executed: Iterable[ExecutedFile] = (),
    layout: Iterable[str] = (),
) -> dict[str, Place]:
    """The folders a platform gives a standalone build's layout.

    ``declared`` are the directories the build resolves its paths against,
    as its profile names them (``standalone_directories``). The result maps
    a subfolder of that layout ("" for the whole of it) to the place, a
    folder of the BIOS tree or of the roms directory, the emulator reads it
    from.

    A record handing a folder under a declared directory gives it directly:
    RetroPie points Flycast's ~/.local/share/flycast at bios/dc. A record
    handing a directory outside the trees is followed through the links that
    put a folder at it or below it: ROCKNIX's patched Flycast uses
    /storage/roms/dreamcast/data, which its start script links to bios/dc,
    and RetroPie starts UAE4All2 in $md_inst, whose kickstarts folder it
    links to bios/amiga.

    A profile whose program reads its files beside its executable declares
    EXECUTABLE_DIRECTORY, and ``layout`` holds its paths: a launcher that
    executes one of them gives the folder holding it. Batocera runs
    pico-8/pico8 from its BIOS folder, ROCKNIX pico8_64 from
    /storage/roms/pico-8.

    A subfolder two records give two places is left out.
    """
    names = set(names)
    wanted = {normalize_handle(d) for d in declared}
    if not wanted:
        return {}
    records = [h for h in handed if h.emulator in names]

    def below(handle: str, directory: str) -> str | None:
        if handle == directory:
            return ""
        if handle.startswith(directory + "/"):
            return handle[len(directory) + 1:]
        return None

    found: dict[str, set[Place]] = {}
    for record in records:
        subs = {
            sub for handle in record.handles for directory in wanted
            if (sub := below(handle, directory)) is not None
        }
        for sub in subs:
            if record.folder is not None:
                found.setdefault(sub, set()).add((BIOS_TREE, record.folder))
                continue
            # A link into the BIOS tree comes first: the pack fills that.
            linked = False
            for link in records:
                target = link.place()
                if target is None:
                    continue
                for handle in link.handles:
                    rest = below(handle, record.directory)
                    if rest is not None:
                        key = "/".join(p for p in (sub, rest) if p)
                        found.setdefault(key, set()).add(target)
                        linked = True
            if not linked and record.roms_folder is not None:
                found.setdefault(sub, set()).add((ROMS_TREE, record.roms_folder))
    if EXECUTABLE_DIRECTORY in wanted:
        paths = list(layout)
        for run in executed:
            if run.emulator not in names:
                continue
            # A program run from a folder outside both trees (RetroBat's
            # emulators/pico8) binds its folder to no place a pack fills.
            root, path = run.place or (OUTSIDE_TREE, run.name)
            folder = path.rsplit("/", 1)[0] if "/" in path else ""
            for entry_path in paths:
                if entry_path.rsplit("/", 1)[-1] != run.name:
                    continue
                sub = entry_path.rsplit("/", 1)[0] if "/" in entry_path else ""
                found.setdefault(sub, set()).add((root, folder))
    return {sub: next(iter(places)) for sub, places in found.items() if len(places) == 1}


def bound_path(path: str, bindings: dict[str, Place]) -> Place | None:
    """Where a platform holds a layout path, None when no binding covers it.

    The longest subfolder that contains the path wins: a link of
    kickstarts/ places kickstarts/kick13.rom even when the whole layout is
    bound elsewhere.
    """
    for sub in sorted(bindings, key=len, reverse=True):
        if sub and not path.startswith(sub + "/"):
            continue
        rest = path[len(sub) + 1:] if sub else path
        root, folder = bindings[sub]
        return (root, f"{folder}/{rest}" if folder else rest)
    return None


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
        relevant = set(relevant)
        for place in self.places:
            standalone = place.build == "standalone"
            for emulator in (e.strip() for e in place.emulator.split(",")):
                for key in self._profiles_named(emulator, profiles, relevant):
                    self._owners.setdefault((key, standalone), []).append(place)

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
        placed: set[str] = set()
        for (emulator, standalone), members in sorted(by_layout.items()):
            for place in self.places_for(emulator, standalone):
                matched = [
                    (candidate, report)
                    for entry, report in members
                    if (candidate := self.match(place, entry)) is not None
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
                continue
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
        return None


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
