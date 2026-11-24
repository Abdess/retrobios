"""A launcher record's names and directories, turned into the places the launcher reads a file from."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from core.paths import comparable_destination, sanitize_pack_path
from resolve.launcherconfig import bound_launchers


# The kinds whose names say which file the launcher opens. A link of a named
# file is one too: ROCKNIX links /storage/roms/bios/nds_bios_arm9.bin into
# DraStic's system folder, so that is the path the emulator reads. The others
# hand over a directory, copy a file the platform already names, or let the
# emulator choose.
PLACE_KINDS = ("names_searched", "fixed_name", "core_option", "links")

# How each launcher extractor spells the BIOS directory in search_dir, as the
# platform's own scripts name it: RetroPie's scriptmodules ($biosdir,
# retropie_reader.BIOSDIR), EmuDeck's EmuScripts (${biosPath},
# emudeck_launchers.BIOS) and RetroDECK's framework ($bios_path,
# retrodeck_launchers.BIOS).
BIOS_ROOT_TOKENS = ("$biosdir", "${biosdir}", "${biosPath}", "$bios_path", "${bios_path}")

# A path spelled from a home or filesystem root names the BIOS directory by
# its base name: /userdata/bios, ~/roms/bios, $HOME/RetroPie/BIOS.
_ROOTED = ("/", "~/", "$HOME/", "$home/", "${HOME}/")

_LABELLED = re.compile(r"^([^\s()]+\.[A-Za-z0-9]+) \([^()]*\)$")
_PLACEHOLDER = re.compile(r"\{(\w+)\}")


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
        return comparable_destination(name, self.case_insensitive)

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


def record_directories(record: dict, base: str) -> list[str] | None:
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


def record_names(record: dict) -> list[str]:
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


def _place_paths(name: str, directories: list[str] | None) -> tuple[str, ...]:
    """The paths a name is opened at: under each directory, or bare when the
    record anchors it nowhere."""
    if directories is None:
        return (name,)
    return tuple(
        sanitize_pack_path(f"{d}/{name}" if d else name) for d in directories
    )


def launcher_places(
    config: dict, profiles: Mapping[str, dict]
) -> list[LauncherPlace]:
    """Every place a platform's launchers open a named file from."""
    base = str(config.get("base_destination") or "bios")
    places: list[LauncherPlace] = []
    for record in bound_launchers(config, profiles):
        kind = record.get("kind")
        if kind not in PLACE_KINDS:
            continue
        names = record_names(record)
        directories = record_directories(record, base)
        if not names or directories == []:
            continue
        anchored = directories is not None
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
            depth = len(directories) if directories is not None else 1
            ordered = tuple(
                _place_paths(name, directories)[i] for i in range(depth) for name in names
            )
            places.append(LauncherPlace(
                paths=ordered, passes_to=str(record.get("passes_to") or ""), **common
            ))
            continue
        # A fixed name is the one file passed, and a core option offers
        # each value as the file the user picks: one place per name.
        places.extend(
            LauncherPlace(
                paths=_place_paths(name, directories), passes_to=settings[name], **common
            )
            for name in names
        )
    return places
