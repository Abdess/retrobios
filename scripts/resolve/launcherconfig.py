"""Whether a launcher record's config file binds: the evidence that the emulator reads what the platform writes."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

from model.launcherrecords import record_emulators
from model.profiles import lists_files, platform_builds, profile_names


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
        from resolve.launcherrefs import config_ref, is_feature_ref, ref_path

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
    from fnmatch import fnmatch

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
    for part in record_emulators(record):
        named = [
            key for key, profile in profiles.items()
            if lists_files(profile) and part in profile_names(key, profile)
        ]
        found.extend(platform_builds(named, profiles, platform))
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
    from resolve.launcherrefs import config_ref, is_feature_ref

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


def _cites_config(record: dict) -> bool:
    from resolve.launcherrefs import config_ref

    return bool(record.get("choices_from")) or bool(config_ref(str(record.get("source_ref") or "")))


def bound_launchers(config: dict, profiles: Mapping[str, dict]) -> list[dict]:
    """The launcher records a platform's packs, manifests and reports consume.

    A record resting on a config file binds only when config_evidence holds
    for it against the run's profiles.
    """
    records = [r for r in config.get("launchers") or [] if isinstance(r, dict)]
    if not any(_cites_config(r) for r in records):
        return records
    platform = str(config.get("_key") or "")
    return [r for r in records if config_evidence(r, profiles, platform).proven]


def launcher_unproven(
    configs: Mapping[str, dict], profiles: Mapping[str, dict]
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
        for index, record in enumerate(records):
            evidence = config_evidence(record, profiles, str(config.get("_key") or platform))
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
