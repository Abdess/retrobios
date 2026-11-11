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
from collections.abc import Callable, Iterable, Mapping
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


# How a record's passes_to names what carries the file when it names no
# config file: an option on the command line, or a libretro core option.
COMMAND_LINE = "command line"
CORE_OPTIONS = "core options"
_TAIL_WORDS = re.compile(r"\s+(?:unset|left empty)$")
_KEY_TOKEN = re.compile(r"^-{0,2}[\w.$()/\\]+$")


def config_target(record: dict) -> tuple[str, list[str]]:
    """The config a record writes its file to, and the keys it names there.

    passes_to spells them as describe_keys does: "settings.ini [BIOS]
    SearchDirectory, [BIOS] PathNTSCU, PathNTSCJ unset", "command line
    -hard", "core option pcsx2_bios", "hatarib_tos = hatarib/<value>". A
    part that reads as prose ("only if the file exists") names no key. When
    passes_to names no file ("romlist coco"), the file is the one the record
    installs and the whole of passes_to is the key.
    """
    # A parenthesis says how the file is passed, unless a config variable
    # opens it: $(FILE_PATH) is amiberry's.
    text = re.sub(r"(?<!\$)\([^()]*\)", "", str(record.get("passes_to") or "")).strip()
    head, _, rest = text.partition(" ")
    if text.startswith(COMMAND_LINE + " "):
        flag = text[len(COMMAND_LINE):].split()[0]
        return COMMAND_LINE, [flag]
    if text.startswith("core option "):
        return CORE_OPTIONS, [text[len("core option "):].split()[0]]
    if "." not in head or head.startswith("<"):
        # The file is the one the record installs, named by its path or,
        # when a variable spells the path, by the config file it cites.
        from scraper.shell_launchers import config_ref, is_feature_ref, ref_path  # noqa: PLC0415

        installed = str((record.get("installs") or {}).get("path") or "").rsplit("/", 1)[-1]
        cited = [
            ref_path(part).rsplit("/", 1)[-1]
            for part in config_ref(str(record.get("source_ref") or ""))
            if not is_feature_ref(part)
        ]
        if "." in installed or (installed and not cited):
            return installed, [text]
        if installed and cited:
            return cited[0], [text]
        if record.get("build") == "libretro" and record.get("kind") == "core_option":
            return CORE_OPTIONS, [head]
        return "", []
    keys: list[str] = []
    section = ""
    for piece in re.split(r",\s*", rest):
        piece = _TAIL_WORDS.sub("", piece.strip())
        # A section opens anywhere in a piece: "BIOS9Path [DSi] FirmwarePath".
        for chunk in re.split(r"(\[[^\]]+\])", piece):
            chunk = chunk.strip()
            if not chunk:
                continue
            if chunk.startswith("[") and chunk.endswith("]"):
                section = chunk
                continue
            # "A = B = <value>" sets every key before the value.
            names = [p.strip() for p in re.split(r"\s*=\s*", chunk)]
            if len(names) > 1:
                names = names[:-1]
            for name in names:
                if not _KEY_TOKEN.match(name):
                    continue
                key = f"{section} {name}" if section else name
                if key not in keys:
                    keys.append(key)
    return head, keys


def _read_keys(read: dict) -> dict[str, str]:
    """Each key a config_reads entry says the build reads, to its source_ref."""
    found: dict[str, str] = {}
    for entry in read.get("keys") or []:
        spelled = entry.get("key")
        for key in spelled if isinstance(spelled, list) else [spelled]:
            if key:
                found[str(key)] = str(entry.get("source_ref") or "")
    return found


def _handle_refs(profile: dict) -> dict[str, str]:
    """The handles a profile names with the code that reads them."""
    found: dict[str, str] = {}
    for item in profile.get("standalone_directories") or []:
        if isinstance(item, dict) and item.get("source_ref"):
            handle = str(item.get("handle") or "").partition(" = ")[0]
            found[handle] = str(item["source_ref"])
    for handle, value in (profile.get("standalone_pools") or {}).items():
        if isinstance(value, dict) and value.get("source_ref"):
            found[str(handle)] = str(value["source_ref"])
    return found


def directory_handles(profile: dict) -> list[str]:
    """standalone_directories as handle strings, a {handle, source_ref} item
    by its handle."""
    return [
        str(item.get("handle") or "") if isinstance(item, dict) else str(item)
        for item in profile.get("standalone_directories") or []
    ]


def pool_folders(profile: dict) -> dict[str, str]:
    """standalone_pools as handle to subfolder, a {folder, source_ref} value
    by its folder."""
    return {
        str(handle): str(value.get("folder") or "") if isinstance(value, dict) else str(value)
        for handle, value in (profile.get("standalone_pools") or {}).items()
    }


def _reads_apply(read: dict, profile: dict, platform: str) -> bool:
    """Whether a config_reads entry describes the build ``platform`` ships.

    An entry naming platforms is read at their pin_build revision or its
    revision. One that names none is read at the profile's pin, the build
    of every platform no entry names and with no pin_build of its own or
    one pinning the same commit.
    """
    named = [str(p) for p in read.get("platforms") or []]
    if named:
        return platform in named
    # A platform an entry names has its build read there, not at the pin.
    if any(platform in (r.get("platforms") or []) for r in profile.get("config_reads") or []):
        return False
    pin = str(profile.get("source_commit") or "")
    builds = [b for b in profile.get("pin_build") or [] if b.get("platform") == platform]
    return all(pin and str(b.get("value") or "").startswith(pin[:12]) for b in builds)


def _file_matches(read_file: str, file: str, record: dict) -> bool:
    """Whether a config_reads file is the one a record writes.

    The entry names the file as the build finds it: a name, a glob ("*.uae",
    any file the launcher passes), a path, or the flag the launcher passes
    it with (amiberry's -f).
    """
    from fnmatch import fnmatch  # noqa: PLC0415

    spelled = read_file.rsplit("/", 1)[-1].casefold()
    if file and fnmatch(file.casefold(), spelled):
        return True
    installed = str((record.get("installs") or {}).get("path") or "").rsplit("/", 1)[-1]
    if installed and fnmatch(installed.casefold(), spelled):
        return True
    return read_file.startswith("-") and read_file in str(record.get("passes_to") or "").split()


@dataclass(frozen=True)
class ConfigEvidence:
    """Whether a launcher record that rests on a config holds, and why not.

    ``config`` holds the parts of its source_ref that cite a config, option
    or feature file. A record citing none, and choosing among no listed
    option values, rests on code alone and holds.
    """

    config: tuple[str, ...]
    missing: tuple[str, ...]
    readers: tuple[str, ...] = ()

    @property
    def proven(self) -> bool:
        return not self.missing


def _named_profiles(record: dict, profiles: Mapping[str, dict], platform: str) -> list[str]:
    """The profiles a record's emulator names, a platform's own build first."""
    found = []
    for part in (e.strip() for e in str(record.get("emulator", "")).split(",")):
        named = [
            key for key, profile in profiles.items()
            if profile.get("type") not in ("alias", "launcher")
            and (key == part or part in {str(c) for c in profile.get("cores") or []})
        ]
        own = [k for k in named if platform in (profiles[k].get("built_by") or [])]
        found.extend(own or [k for k in named if not profiles[k].get("built_by")])
    return sorted(set(found))


def config_evidence(
    record: dict, profiles: Mapping[str, dict], platform: str = ""
) -> ConfigEvidence:
    """What a record citing a config file proves, link by link.

    A config file is proof only when the code that installs it and the code
    that reads it are shown: (a) the platform installs the file at a path
    (``installs``), (b) its launch code was read for what replaces the file
    or the key (``overrides``), (c) the emulator loads that file and (d)
    reads each key and opens the value (``config_reads`` of its profile, at
    the build the platform ships). A feature or option file only lists the
    values a menu offers: it goes in ``choices_from``, beside the code that
    writes the choice, and such a record needs (c) and (d) too.
    """
    from scraper.shell_launchers import config_ref, is_feature_ref  # noqa: PLC0415

    cited = config_ref(str(record.get("source_ref") or ""))
    choices = str(record.get("choices_from") or "")
    if not cited and not choices:
        return ConfigEvidence((), ())
    missing: list[str] = []
    features = [part for part in cited if is_feature_ref(part)]
    if features:
        missing.append("an option list cited as source, not as choices_from")
    shipped = [part for part in cited if not is_feature_ref(part)]
    if shipped:
        installs = record.get("installs") or {}
        if not (installs.get("path") and installs.get("source_ref")):
            missing.append("installs: the code that puts the config in place")
        if "overrides" not in record:
            missing.append("overrides: the launch code read for what replaces it")
    file, keys = config_target(record)
    if not keys:
        missing.append("a key the config hands the file to")
    readers: list[str] = []
    uncovered = list(keys)
    loaded = False
    named = _named_profiles(record, profiles, platform)
    if file == CORE_OPTIONS:
        # A core option is read by the core RetroArch runs, not by the
        # frontend a record names (RetroDECK's retroarch component).
        named = [k for k in named if "libretro" in str(profiles[k].get("type") or "")]
    for key in named or sorted(profiles):
        profile = profiles[key]
        handles = _handle_refs(profile)
        for read in profile.get("config_reads") or []:
            if not _reads_apply(read, profile, platform):
                continue
            if not _file_matches(str(read.get("file") or ""), file, record):
                continue
            loaded = True
            known = _read_keys(read)
            before = len(uncovered)
            uncovered = [k for k in uncovered if not (known.get(k) or handles.get(k))]
            if len(uncovered) < before and key not in readers:
                readers.append(key)
    if not loaded:
        missing.append(f"config_reads: an emulator that loads {file or 'the config'}")
    elif uncovered:
        missing.append("config_reads: no read of " + ", ".join(uncovered))
    return ConfigEvidence(tuple(cited or [choices]), tuple(missing), tuple(readers))


_DEFAULT_PROFILES: dict[str, dict] | None = None


def _profiles_or_repo(profiles: Mapping[str, dict] | None) -> Mapping[str, dict]:
    """The profiles given, else this repository's, read once."""
    global _DEFAULT_PROFILES  # noqa: PLW0603
    if profiles is not None:
        return profiles
    if _DEFAULT_PROFILES is None:
        from pathlib import Path  # noqa: PLC0415

        from common import load_emulator_profiles  # noqa: PLC0415

        _DEFAULT_PROFILES = load_emulator_profiles(
            str(Path(__file__).resolve().parent.parent / "emulators")
        )
    return _DEFAULT_PROFILES


def _cites_config(record: dict) -> bool:
    from scraper.shell_launchers import config_ref  # noqa: PLC0415

    return bool(record.get("choices_from")) or bool(config_ref(str(record.get("source_ref") or "")))


def bound_launchers(config: dict, profiles: Mapping[str, dict] | None = None) -> list[dict]:
    """The launcher records a platform's packs, manifests and reports consume.

    A record resting on a config file binds only when config_evidence holds
    for it. The repository's profiles are read only when a record cites one.
    """
    records = [r for r in config.get("launchers") or [] if isinstance(r, dict)]
    if not any(_cites_config(r) for r in records):
        return records
    known = _profiles_or_repo(profiles)
    platform = str(config.get("_key") or "")
    return [r for r in records if config_evidence(r, known, platform).proven]


def launcher_unproven(
    configs: Mapping[str, dict], profiles: Mapping[str, dict] | None = None
) -> list[dict]:
    """The records resting on a config file whose evidence does not hold.

    One row per record, with the config parts it cites and each missing
    link. Reported apart: no severity, count or exit code reads it.
    """
    rows: list[dict] = []
    for platform, config in configs.items():
        records = [r for r in config.get("launchers") or [] if isinstance(r, dict)]
        if not any(_cites_config(r) for r in records):
            continue
        known = _profiles_or_repo(profiles)
        for index, record in enumerate(records):
            evidence = config_evidence(record, known, str(config.get("_key") or platform))
            if evidence.proven:
                continue
            rows.append({
                "platform": platform,
                "index": index,
                "emulator": str(record.get("emulator", "")),
                "kind": str(record.get("kind", "")),
                "passes_to": str(record.get("passes_to") or ""),
                "source_ref": str(record.get("source_ref", "")),
                "config": list(evidence.config),
                "missing": list(evidence.missing),
            })
    return rows


def launcher_places(
    config: dict, profiles: Mapping[str, dict] | None = None
) -> list[LauncherPlace]:
    """Every place a platform's launchers open a named file from."""
    base = str(config.get("base_destination") or "bios")
    places: list[LauncherPlace] = []
    for record in bound_launchers(config, profiles):
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

# The name a platform's launch code gives its roms root: RetroDECK's
# component scripts write $roms_path (retrodeck_launchers), the setting whose
# default is the roms root (config/retrodeck/retrodeck.json:5), RetroPie's
# scriptmodules $romdir (retropie_packages.sh:47-49).
ROMS_ROOT_VARIABLES = ("$roms_path", "${roms_path}", "$romdir", "${romdir}")

# The kinds that hand an emulator a whole directory. A scans_dir record sets
# the directory the emulator picks its file from: ROCKNIX writes ARMSX2's
# [Folders] Bios, EmuDeck PCSX2's.
HANDED_KINDS = ("links", "passes_path", "scans_dir")

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
# The emulator folders of a platform whose registry describes them.
EMULATORS_TREE = "emulators"
# The frontend's configs folder of a platform whose file records it.
CONFIGS_TREE = "configs"
# The tree a platform's list installs into when it starts above the BIOS
# folder: a plain dest, with no prefix.
INSTALL_TREE = "install"
# A folder of neither tree, which no pack and no installer can fill.
OUTSIDE_TREE = "outside"
Place = tuple[str, str]
# The binding key of a search list standing for the whole layout: the
# directories hold the layout's files themselves (XRoar's ROMs, MAME's sets),
# never its subfolders.
SEARCHED_FILES = "*"

_HOME = re.compile(r"^(?:\$\{HOME\}|\$HOME|\$home|~)(?=/|$)")
# Flatpak sets XDG_DATA_HOME to ~/.var/app/<id>/data inside the sandbox.
_FLATPAK_DATA = re.compile(r"^~/\.var/app/[^/]+/data(?=/|$)")


def normalize_handle(token: str, home: str = "") -> str:
    """One spelling for a path, setting or function a launcher record names.

    ``$home``, ``$HOME``, ``${HOME}`` and ``~`` are one directory, and a
    Flatpak's data directory is its ``$XDG_DATA_HOME``. ``home`` is the
    platform's home directory spelled out (``home_directory``): EmuELEC
    links /storage/.local/share/flycast, Flycast's ~/.local/share/flycast.
    """
    token = token.strip().strip("\"'").rstrip(",;").rstrip("/")
    token = token.removesuffix("()")
    home = home.rstrip("/")
    if home and _below(token, home) is not None:
        token = "~" + token[len(home):]
    token = _HOME.sub("~", token)
    return _FLATPAK_DATA.sub("$XDG_DATA_HOME", token)


_INI_KEY = re.compile(r"(\[[^\]\s]+\])\s+([^\s,;=()]+)")


def ini_keys(passes_to: str) -> frozenset[str]:
    """The INI keys a record's ``passes_to`` writes, as "[Section] Key".

    A key alone is ambiguous: PCSX2 reads its BIOS folder from [Folders]
    Bios and the image name from [Filenames] BIOS. A profile declares the
    key it resolves a folder from in that spelling ("[Folders] Bios = bios").
    """
    return frozenset(f"{section} {key}" for section, key in _INI_KEY.findall(passes_to))


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
    roms_place: Place | None = None
    # The platform systems, by our ids, the record applies to. Empty when
    # the launcher hands the directory whatever the system.
    systems: frozenset[str] = frozenset()
    # Whether the platform's own list declares files in the folder.
    holds_declared: bool = False

    def place(self) -> Place | None:
        """The folder as a place, None when it lies outside both roots."""
        if self.folder is not None:
            return (BIOS_TREE, self.folder)
        return self.roms_place


# The placeholder a launcher record writes for the system it is launched
# for, as Recalbox's extractor spells it: Recalbox passes XRoar `-rompath`
# `os.path.join(BIOS, args.system)`.
SYSTEM_PLACEHOLDER = "<system>"


def native_systems(config: dict) -> dict[str, str]:
    """The platform's own system names, each to our id for it.

    A system states its name (native_id) or its files do (native_system).
    Without either, our id is the platform's name.
    """
    found: dict[str, str] = {}
    for slug, system in (config.get("systems") or {}).items():
        names = {str(system["native_id"])} if system.get("native_id") else {
            str(f["native_system"]) for f in system.get("files") or [] if f.get("native_system")
        }
        for name in names or {slug}:
            found.setdefault(name, slug)
    return found


# How the launcher extractors spell the folder holding the launched game:
# RetroBat's Path.GetDirectoryName(rom) (retrobat_launchers._KNOWN), KNULLI's
# os.path.dirname(rom) and its software list folder (mameGenerator.py:113-116).
GAME_FOLDERS = ("<rom directory>", "<romDirname>", "<softDir>")


def _listed_directories(raw: str) -> list[str] | None:
    """The directories of a search path, None for one directory.

    XRoar's rompath is a colon-separated list (RetroDECK writes four
    directories), each entry a path or a variable spelling one. A Windows
    drive letter or a backslash means a single path. MAME splits its search
    paths on semicolons whatever the system (src/emu/fileio.cpp:53-58):
    RetroBat passes `-rp bios;<rom directory>`, KNULLI `-rompath
    <romDirname>;/userdata/bios/mame;/userdata/bios`. The game's own folder
    is no folder a pack fills, so it gives no directory.
    """
    if ";" in raw:
        parts = [p.strip() for p in raw.split(";") if p.strip()]
        kept = [p for p in parts if p not in GAME_FOLDERS]
        if kept and all(not re.search(r"[\s,<>]", p) for p in kept):
            return kept
        return None
    if ":" not in raw or "\\" in raw or re.match(r"^[A-Za-z]:", raw):
        return None
    parts = [p.strip() for p in raw.split(":")]
    if all(p and p[0] in "/$~" and not re.search(r"[\s,;]", p) for p in parts):
        return parts
    return None


def handed_directories(
    config: dict, profiles: Mapping[str, dict] | None = None
) -> list[HandedDirectory]:
    """Every whole directory a platform links or passes to a standalone build.

    A record naming files (gpsp's gba_bios.bin) or one slot of a directory
    (RetroDECK's GC/EUR) hands over no whole directory, and a search_dir
    describing several directories in prose names no single one. A search
    path (XRoar's rompath) gives each of its directories, in order. A record
    naming systems applies to those systems only, and one whose search_dir
    holds <system> gives one directory per system the platform declares.
    """
    base = str(config.get("base_destination") or "bios")
    home = str(config.get("home_directory") or "")
    natives = native_systems(config)
    declared = {d.lower() for d in declared_destinations(config)}
    found: list[HandedDirectory] = []
    for record in bound_launchers(config, profiles):
        if record.get("build") != "standalone" or record.get("kind") not in HANDED_KINDS:
            continue
        if record.get("names") or record.get("slot"):
            continue
        raw = str(record.get("search_dir") or "").strip()
        if not raw:
            continue
        named = frozenset(natives.get(str(s), str(s)) for s in record.get("systems") or [])
        if SYSTEM_PLACEHOLDER in raw:
            variants = [
                (raw.replace(SYSTEM_PLACEHOLDER, native), frozenset({slug}))
                for native, slug in sorted(natives.items())
                if not named or slug in named
            ]
        else:
            variants = [(raw, named)]
        passes_to = str(record.get("passes_to") or "")
        for spelled, systems in variants:
            parts = _listed_directories(spelled) or [spelled]
            if any(re.search(r"[\s,:;]", part) for part in parts):
                continue
            for part in parts:
                directory = normalize_handle(part, home)
                if passes_to.startswith(WORKING_DIRECTORY_PASSED):
                    # The program runs from the directory: what its code
                    # reads through getcwd(), or relative to it, is below it.
                    handles = frozenset({WORKING_DIRECTORY})
                else:
                    handles = frozenset(
                        handle
                        for token in passes_to.split()
                        if (handle := normalize_handle(token, home)) and handle != directory
                    ) | ini_keys(passes_to)
                folder = _folder_in_bios(part, base)
                for emulator in (e.strip() for e in str(record.get("emulator", "")).split(",")):
                    found.append(HandedDirectory(
                        emulator=emulator,
                        folder=folder,
                        directory=directory,
                        handles=handles,
                        source_ref=str(record.get("source_ref", "")),
                        roms_place=None if folder is not None else (
                            _roms_place(config, folder_in_roms(part, config))
                            or _configs_place(folder_in_configs(part, config))
                            or _emulators_place(folder_in_emulators(part, config))
                        ),
                        systems=systems,
                        holds_declared=bool(folder) and any(
                            d.startswith(f"{(folder or '').lower()}/") for d in declared
                        ),
                    ))
    return found


def _configs_place(path: str | None) -> Place | None:
    """A folder below the configs root, as a place of the configs tree."""
    return None if path is None else (CONFIGS_TREE, path)


def _emulators_place(path: str | None) -> Place | None:
    """A folder an emulator key names, as a place of the emulators tree."""
    return None if path is None else (EMULATORS_TREE, path)


def _roms_place(config: dict, path: str | None) -> Place | None:
    """A path below the roms root as a place: in the install tree when the
    platform installs above its BIOS folder (AmberELEC), else the roms tree."""
    if path is None:
        return None
    from common import ROMS_ROOT, outer_layout  # noqa: PLC0415

    layout = outer_layout(config, ROMS_ROOT) or {}
    if "install_prefix" in layout:
        prefix = layout["install_prefix"]
        return (INSTALL_TREE, sanitize_pack_path(f"{prefix}/{path}" if prefix else path))
    return (ROMS_TREE, path)


def folder_in_configs(directory: str, config: dict) -> str | None:
    """A directory relative to the frontend's configs folder, None outside it.

    Only a platform whose file records its configs root has one
    (``configs_root.path``): Batocera's /userdata/system/configs, where its
    generators start shadPS4 from configs/shadps4.
    """
    from common import CONFIGS_ROOT  # noqa: PLC0415

    return folder_in_root(directory, config, CONFIGS_ROOT)


def folder_in_roms(directory: str, config: dict) -> str | None:
    """A directory relative to the platform's roms directory, None outside it.

    Only a platform whose rom folders file records its roms root has one
    (``roms_root.path``): ROCKNIX's /storage/roms, which holds its BIOS
    folder and the folders its launchers run programs from.
    """
    from common import ROMS_ROOT, outer_layout  # noqa: PLC0415

    spelled = directory.strip().rstrip("/")
    for variable in ROMS_ROOT_VARIABLES:
        if outer_layout(config, ROMS_ROOT) and (
            spelled == variable or spelled.startswith(variable + "/")
        ):
            rest = spelled[len(variable) + 1:]
            return None if re.search(r"[\s<>$:;]", rest) else rest
    return folder_in_root(directory, config, ROMS_ROOT)


def folder_in_root(directory: str, config: dict, root: str) -> str | None:
    """A directory relative to an outer root's path, None outside it."""
    from common import outer_layout  # noqa: PLC0415

    roms = str((outer_layout(config, root) or {}).get("path") or "").rstrip("/")
    directory = directory.strip().rstrip("/")
    if not roms or not directory.startswith(roms + "/"):
        return None
    rest = directory[len(roms) + 1:]
    return None if re.search(r"[\s<>$:;]", rest) else rest


def folder_in_emulators(directory: str, config: dict) -> str | None:
    """The emulator folder a launcher names by its key, None for any other.

    Only a platform whose registry describes its emulator folders has one
    (``emulators_directory.launcher_spelling``): RetroBat's generators take
    each from AppConfig.GetFullPath("<key>"), a folder of the RetroBat
    install named after the key.
    """
    spelling = str((config.get("emulators_directory") or {}).get("launcher_spelling") or "")
    if "{key}" not in spelling:
        return None
    # The key, then any folder below it: Citron's generator creates
    # <folder>/user, its portable data folder.
    pattern = re.escape(spelling).replace(re.escape("{key}"), r"([\w.-]+)") + r"((?:/[\w.-]+)*)"
    found = re.fullmatch(pattern, directory.strip())
    return found.group(1) + found.group(2) if found else None


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
        emulator_folder = folder_in_emulators(raw, config) if raw and not directories else None
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
                place = _roms_place(config, sanitize_pack_path(f"{roms}/{name}" if roms else name))
            elif emulator_folder is not None:
                place = (EMULATORS_TREE, sanitize_pack_path(f"{emulator_folder}/{name}"))
            else:
                place = None
            for emulator in (e.strip() for e in str(record.get("emulator", "")).split(",")):
                found.append(ExecutedFile(
                    emulator, name.rsplit("/", 1)[-1], place, str(record.get("source_ref", ""))
                ))
    return found


def _below(handle: str, directory: str) -> str | None:
    """``handle`` relative to ``directory``, None when it is not inside it."""
    if handle == directory:
        return ""
    if handle.startswith(directory + "/"):
        return handle[len(directory) + 1:]
    return None


def _join(*parts: str) -> str:
    return "/".join(p for p in parts if p)


def _record_places(
    record: HandedDirectory, inner: str, records: list[HandedDirectory]
) -> list[tuple[str, Place]]:
    """(subfolder, place) for the directory ``inner`` below what a record hands.

    A record handing a folder of a tree gives it directly. One handing a
    directory outside the trees is followed through the links that put a
    folder at that directory, below it or above it.
    """
    if record.folder is not None:
        return [("", (BIOS_TREE, _join(record.folder, inner)))]
    base = _join(record.directory, inner)
    found: list[tuple[str, Place]] = []
    for link in records:
        target = link.place()
        if target is None:
            continue
        for handle in link.handles:
            rest = _below(handle, base)
            if rest is not None:
                found.append((rest, target))
                continue
            up = _below(base, handle) if inner else None
            if up:
                found.append(("", (target[0], _join(target[1], up))))
    if not found and record.roms_place is not None:
        root, folder = record.roms_place
        found.append(("", (root, _join(folder, inner))))
    return found


def _bind(
    records: list[HandedDirectory],
    links: list[HandedDirectory],
    wanted: set[str],
    named: Mapping[str, str],
    pools: Mapping[str, str],
) -> dict[str, set[Place]]:
    """The places each subfolder of the layout is given by ``records``.

    A record whose handle is a declared directory, or lies below one, gives
    that subfolder, and a handle ``named`` gives the one folder it stands
    for. One whose handle lies above a declared directory, or is the
    environment variable the declared directory is spelled from
    ($XDG_DATA_HOME/suyu), gives the declared directory where it lands:
    RetroPie configures XRoar with --prefix=$md_inst, so
    ${prefix}/share/xroar/roms is $md_inst/share/xroar/roms. When it lands
    in no folder a pack fills, the layout is read outside the trees.
    ``links`` are the records followed from a directory outside the trees.

    A handle in ``pools`` names a list of directories the program searches
    one after the other: openMSX's filepool, XRoar's rompath. A file in any
    of them is read, so the pool gives one: the directory the platform's own
    list already fills (Batocera's bios/openmsx beside bios/Machines), else
    the first of the BIOS tree, else the first a pack can fill. A list that
    already holds the folder the layout's files take without the launcher
    keeps them there: KNULLI starts MAME with `-rompath`
    <romDirname>;/userdata/bios/mame;/userdata/bios, and the sets at the BIOS
    root stay. A pool standing for the whole layout holds its files
    directly, not its folders (SEARCHED_FILES): MAME reads hash/ and
    samples/ through other settings.
    """
    found: dict[str, set[Place]] = {}
    pooled: dict[str, list[tuple[bool, Place]]] = {}
    for record in records:
        for handle in record.handles:
            if handle in pools:
                for rest, place in _record_places(record, "", links):
                    pooled.setdefault(_join(pools[handle], rest), []).append(
                        (record.holds_declared, place)
                    )
                continue
            if handle in named:
                for rest, place in _record_places(record, "", links):
                    found.setdefault(_join(named[handle], rest), set()).add(place)
            for directory in wanted:
                sub = _below(handle, directory)
                if sub is not None:
                    for rest, place in _record_places(record, "", links):
                        found.setdefault(_join(sub, rest), set()).add(place)
                    continue
                if handle == directory:
                    continue
                inner = next(
                    (up for spelled in (f"${handle}", handle)
                     if (up := _below(directory, spelled)) is not None),
                    None,
                )
                if inner is None:
                    continue
                places = _record_places(record, inner, links)
                for rest, place in places or [("", (OUTSIDE_TREE, ""))]:
                    found.setdefault(rest, set()).add(place)
    for sub, entries in pooled.items():
        # The folder the files already take, else the directory the
        # platform's own list fills, else the first of the BIOS tree, else
        # the first a pack fills.
        unmoved = [p for _held, p in entries if p == (BIOS_TREE, sub)]
        filled = [p for held, p in entries if held]
        in_bios = [p for _held, p in entries if p[0] == BIOS_TREE]
        chosen = (unmoved or filled or in_bios or [p for _h, p in entries])[0]
        found.setdefault(sub or SEARCHED_FILES, set()).add(chosen)
    return found


def standalone_bindings(
    names: Iterable[str],
    declared: Iterable[str],
    handed: Iterable[HandedDirectory],
    executed: Iterable[ExecutedFile] = (),
    layout: Iterable[str] = (),
    pools: Mapping[str, str] | None = None,
    systems: Iterable[str] = (),
) -> dict[str, Place]:
    """The folders a platform gives a standalone build's layout.

    ``declared`` are the directories the build resolves its paths against,
    as its profile names them (``standalone_directories``), and ``pools``
    the settings it reads as search lists, each to the subfolder of the
    layout its directories stand for (``standalone_pools``). The result maps
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

    ``systems`` are the platform systems, by our ids, an entry is launched
    for. A record naming systems replaces, for those systems, what the
    records naming none give: RetroBat passes XRoar `-rompath bios/coco` for
    coco and bios/dragon for every other system.

    A profile whose program reads its files beside its executable declares
    EXECUTABLE_DIRECTORY, and ``layout`` holds its paths: a launcher that
    executes one of them gives the folder holding it. Batocera runs
    pico-8/pico8 from its BIOS folder, ROCKNIX pico8_64 from
    /storage/roms/pico-8.

    A subfolder two records give two places is left out.
    """
    names = set(names)
    pools = {normalize_handle(k): str(v).strip("/") for k, v in (pools or {}).items()}
    # "<handle> = <subfolder>" names the code's handle for one folder of the
    # layout: Citron's CitronPath::KeysDir is its keys/ folder, and a patch
    # that rewrites the handle moves that folder alone.
    named: dict[str, str] = {}
    wanted: set[str] = set()
    for raw in declared:
        handle, sep, sub = str(raw).partition(" = ")
        if sep:
            named[normalize_handle(handle)] = sanitize_pack_path(sub.strip())
        else:
            wanted.add(normalize_handle(handle))
    wanted -= set(pools)
    if not wanted and not named and not pools:
        return {}
    systems = set(systems)
    records = [h for h in handed if h.emulator in names]
    generic = [h for h in records if not h.systems]
    specific = [h for h in records if h.systems & systems]

    found = _bind(generic, generic, wanted, named, pools)
    # A link is followed whatever system it was written for.
    found.update(_bind(specific, specific + generic, wanted, named, pools))
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
    bound elsewhere. SEARCHED_FILES covers the files at the root of the
    layout alone.
    """
    for sub in sorted(bindings, key=len, reverse=True):
        if sub == SEARCHED_FILES:
            if "/" in path:
                continue
            root, folder = bindings[sub]
            return (root, f"{folder}/{path}" if folder else path)
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
        self.places = launcher_places(config, profiles)
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
            # writes, pcsx2_bios, names the core: a libretro core option
            # belongs to a libretro core.
            if place.build == "libretro" and place.kind == "core_option":
                owners = {k for k in owners if "libretro" in str(profiles[k].get("type") or "")}
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
        self._declared_elsewhere: set[tuple[str, bool, str, str]] = set()

    def declared_elsewhere(self, emulator: str, standalone: bool, entry: dict) -> None:
        """Record a core entry the platform's list settles under another
        name. A launcher opening the entry's own name finds nothing there:
        RetroPie lists KS 1.3 as kick34005.A500, and its fs-uae launcher
        passes $biosdir/kick13.rom. A name the list holds somewhere is
        copied to the launcher's place from that declaration."""
        name = str(entry.get("name", ""))
        if name.rsplit("/", 1)[-1].lower() in self.declared_names_folded:
            return
        self._declared_elsewhere.add((emulator, standalone, name, str(entry.get("path") or "")))

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
        # RetroPie runs sdl2trs with `-romfile4p $biosdir/level4p.rom`: the
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
            # A file the layout reads outside the BIOS tree fills no
            # destination of it.
            if report.get("in_repo") and not report.get("unplaced"):
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
                if (*layout, str(entry.get("name", "")),
                        str(entry.get("path") or "")) in self._declared_elsewhere:
                    report["declared_elsewhere"] = True
                by_layout.setdefault(layout, []).append((entry, report))
        placed: set[str] = set()
        for (emulator, standalone), members in sorted(by_layout.items()):
            for place in self.places_for(emulator, standalone):
                # An entry the report left out answers only through the
                # setting or the extended name: by its own name it was left
                # out for a reason (a region variant, a settled duplicate).
                # One the platform settles under another name still answers
                # by its own: the place reads a name the list does not hold.
                matched = [
                    (candidate, report)
                    for entry, report in members
                    if (candidate := self.match(place, entry)) is not None
                    and (candidate.by_setting_or_stem or not report.get("unoffered")
                         or report.get("declared_elsewhere"))
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
                # The launcher hands the emulator that file from the BIOS
                # tree: read outside it no more.
                settled.update(id(report) for _c, report in matched if report.get("unplaced"))
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
            "profile", "emulator", "systems", "system", "region", "selection_slot",
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
