"""EmuDeck's launcher layer, read from its EmuScripts at the pinned commit.

Each functions/EmuScripts/emuDeck<Name>.sh sets an emulator up once, at
install or update: it writes BIOS paths into the emulator's config with
changeLine, iniFieldUpdate or RetroArch_setConfigOverride, rewrites the
paths of a config it ships with sed, or links a directory of bios/ to the
emulator's own. Nothing runs between that setup and a launch, so these are
the names and directories the emulator is left with.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Callable

try:
    from .configgen_launchers import Launcher
    from .shell_launchers import (
        LauncherPatternMissing,
        RepoTree,
        Script,
        describe_keys,
        settings,
        source_ref,
        words,
    )
except ImportError:
    from configgen_launchers import Launcher
    from shell_launchers import (
        LauncherPatternMissing,
        RepoTree,
        Script,
        describe_keys,
        settings,
        source_ref,
        words,
    )

EMUSCRIPTS = "functions/EmuScripts"
CONFIGS = "configs"
BIOS = "${biosPath}"
# EmuDeck's settings put the BIOS directory under the Emulation folder.
EMULATION_BIOS = "${emulationPath}/bios"
STORAGE = "${storagePath}"
FLATPAK_DATA = "${HOME}/.var/app/"
# The function every EmuScript installs its Flatpak config with.
CONFIG_EMU_FP = "functions/configEmuFP.sh"

# EmuScripts file names that differ from the emulator profile they set up.
# The platform and target scrapers both read them here.
SCRIPT_EMULATORS = {
    "pcsx2qt": "pcsx2",
    "rpcs3legacy": "rpcs3",
    "cemuproton": "cemu",
    "rmg": "mupen64plus_next",
}
# The main RetroArch config script installs no emulator, and emudeck-we's
# emuDeckTemplate.ps1 is the skeleton new installers are copied from.
NOT_EMULATORS = {"retroarch_maincfg", "template"}
# EmuDeck's SteamOS installers are shell scripts, emudeck-we's PowerShell.
SCRIPT_SUFFIXES = (".sh", ".ps1")

# What the emulator does with a directory written into each key.
DIRECTORY_KINDS = {
    "SearchDirectory": "scans_dir",
    "Bios": "scans_dir",
    "rompath": "scans_dir",
    "system_directory": "passes_path",
}


def emulator_of_script(file_name: str) -> str | None:
    """The emulator an EmuScripts file sets up, None for a helper script."""
    stem, dot, suffix = file_name.rpartition(".")
    if not dot or f".{suffix}" not in SCRIPT_SUFFIXES:
        return None
    key = re.sub(r"^emuDeck", "", stem, flags=re.IGNORECASE).lower()
    if not key or key in NOT_EMULATORS:
        return None
    return SCRIPT_EMULATORS.get(key, key)


def _script(tree: RepoTree, name: str) -> Script:
    path = f"{EMUSCRIPTS}/{name}"
    return Script(path, tree.read(path))


def _emulator(name: str) -> str:
    emulator = emulator_of_script(name)
    if emulator is None:
        raise LauncherPatternMissing(f"{EMUSCRIPTS}/{name}", "emulator script")
    return emulator


def _is_bios(value: str) -> bool:
    return any(value == root or value.startswith(root + "/") for root in (BIOS, EMULATION_BIOS))


def with_evidence(tree: RepoTree, script: Script, record: Launcher, config: str) -> Launcher:
    """A record citing a shipped config, with the steps that install it.

    configEmuFP rsyncs the repository's configs/<app> over the Flatpak's:
    the _init call overwrites (keeping a .bak), every other call passes
    --ignore-existing and leaves the user's file in place.
    """
    fp = Script(CONFIG_EMU_FP, tree.read(CONFIG_EMU_FP))
    rsync_line, _ = fp.find(r"^\s*rsync .*\$emudeckBackend/configs/", "rsync of the configs")
    keep_line, _ = fp.find(r'overwrite="--ignore-existing"', "--ignore-existing")
    calls = {n for n, line in script.code() if re.match(r"\s*configEmuFP\s", line)}
    if not calls:
        raise script.missing("configEmuFP call")
    variable = script.assignment_ending("/" + config)
    if variable is None:
        raise script.missing(f"config variable for {config}")
    record.installs = {
        "path": script.expand(variable.value, variable.line, set()),
        "source_ref": source_ref([(script.path, calls), (fp.path, {keep_line, rsync_line})]),
    }
    record.kept_if_present = True
    record.overrides = []
    return record


def _repo_config(script: Script, path: str) -> str:
    """The repository copy of a Flatpak config EmuDeck installs."""
    if not path.startswith(FLATPAK_DATA):
        raise script.missing(f"repository copy of {path}")
    return f"{CONFIGS}/{path[len(FLATPAK_DATA):]}"


def setters(script: Script) -> list[tuple[str, str, str, str, set[int]]]:
    """(config file, section, key, value, lines) for each path setter call.

    Reads changeLine "$KEY" "$KEY$VALUE" "$FILE", iniFieldUpdate "$FILE"
    "Section" "Key" "Value" and RetroArch_setConfigOverride 'key' "value" "$FILE".
    """
    found = []
    for number, line in script.code():
        command = words(line)
        if not command:
            continue
        used = {number}
        args = [script.expand(w.text, number, used) for w in command[1:]]
        name = command[0].raw
        if name == "changeLine" and len(args) == 3:
            key, value, file = args
            if not value.startswith(key):
                if BIOS in value:
                    raise script.missing(f"changeLine value starting with its key at line {number}")
                continue
            value = value[len(key) :].strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            found.append((file, "", key.strip().rstrip("=").strip(), value, used))
        elif name == "iniFieldUpdate" and len(args) == 4:
            file, section, key, value = args
            found.append((file, section, key, value, used))
        elif name == "RetroArch_setConfigOverride" and len(args) == 3:
            key, value, file = args
            found.append((file, "", key, value.strip('"'), used))
    return found


def setter_records(tree: RepoTree, name: str, option_key: str | None = None) -> list[Launcher]:
    """Records for the paths a script's setters write under the BIOS or storage directory.

    A file named under bios/ or storage/ is a fixed name, grouped by config
    and directory. A bios directory is handed to the emulator, which picks.
    """
    script = _script(tree, name)
    emulator = _emulator(name)
    records: list[Launcher] = []
    groups: dict[tuple[str, str], tuple[list[tuple[str, str]], list[str], set[int]]] = {}
    for file, section, key, value, lines in setters(script):
        config = posixpath.basename(file)
        paths = value.split(";")
        if not any(_is_bios(p) for p in paths) and not value.startswith(STORAGE + "/"):
            continue
        is_file = len(paths) == 1 and re.search(r"\.[A-Za-z0-9]+$", posixpath.basename(value))
        if is_file:
            folder = posixpath.dirname(value)
            keys, names, refs = groups.setdefault((config, folder), ([], [], set()))
            keys.append((section, key))
            names.append(posixpath.basename(value))
            refs |= lines
            continue
        if not any(_is_bios(p) for p in paths):
            continue
        if key not in DIRECTORY_KINDS:
            raise script.missing(f"known directory key, got {key}")
        records.append(
            Launcher(
                emulator=emulator,
                build="libretro" if emulator == "retroarch" else "standalone",
                kind=DIRECTORY_KINDS[key],
                names=[],
                source_ref=source_ref([(script.path, lines)]),
                search_dir=value,
                passes_to=describe_keys(config, ((section, key),)),
            )
        )
    for (config, folder), (keys, names, refs) in groups.items():
        records.append(
            Launcher(
                emulator=emulator,
                build="standalone",
                kind="fixed_name",
                names=names,
                source_ref=source_ref([(script.path, refs)]),
                search_dir=folder,
                passes_to=describe_keys(config, tuple(keys)),
            )
        )
    if not records:
        raise script.missing(f"setter writing a path under {BIOS}")
    if option_key:
        for record in records:
            _add_option(tree, script, record, option_key)
    return records


def _add_option(tree: RepoTree, script: Script, record: Launcher, option_key: str) -> None:
    """depends_on_option from the value the shipped config gives option_key."""
    config = record.passes_to.split(" ", 1)[0]
    file_var = script.assignment_ending("/" + config)
    if file_var is None:
        raise script.missing(f"config variable for {config}")
    path = _repo_config(script, script.expand(file_var.value, file_var.line, set()))
    option = next((s for s in settings(tree.read(path)) if s.key == option_key), None)
    if option is None:
        raise LauncherPatternMissing(path, option_key)
    record.depends_on_option = f"{option_key} = {option.value} in the shipped {config}"
    record.source_ref += f", {source_ref([(path, {option.line})])}"


def sed_rewrites(script: Script, function: str) -> list[tuple[str, str, str, set[int]]]:
    """(config path, old prefix, new prefix, lines) for sed -i "s|old|new|g" "$file" in a function."""
    start, _ = script.find(rf"^\s*{re.escape(function)}\s*\(\)\s*\{{", f"function {function}")
    end = next(
        (n for n, line in script.code() if n > start and re.match(r"^\}", line)), len(script.lines)
    )
    found = []
    for number, line in script.code():
        if not start < number < end:
            continue
        command = words(line)
        if len(command) == 4 and command[0].raw == "sed" and command[1].raw == "-i":
            pattern = re.fullmatch(r"s\|([^|]*)\|([^|]*)\|g", command[2].text)
            if pattern is None:
                continue
            used: set[int] = {number}
            old, new, file = (
                script.expand(text, number, used).replace("\\/", "/")
                for text in (pattern.group(1), pattern.group(2), command[3].text)
            )
            found.append((file, old, new, used))
    return found


def _rewritten(value: str, old: str, new: str) -> str | None:
    if not value.startswith(old):
        return None
    rest = value[len(old) :]
    return new.rstrip("/") + "/" + rest.lstrip("/")


def ares(tree: RepoTree) -> list[Launcher]:
    """settings.bml Firmware keys, their /home/deck/Emulation/bios/ prefix rewritten."""
    name = "emuDeckares.sh"
    script = _script(tree, name)
    rewrites = [
        r for r in sed_rewrites(script, "ares_setEmulationFolder") if _is_bios(r[2].rstrip("/"))
    ]
    if not rewrites:
        raise script.missing("sed rewrite of the BIOS path")
    file, old, new, script_lines = rewrites[0]
    path = _repo_config(script, file)
    records = []
    system, in_firmware = "", False
    entries: dict[str, list[tuple[str, str, int]]] = {}
    for number, line in enumerate(tree.read(path).splitlines(), 1):
        indent = len(line) - len(line.lstrip(" "))
        text = line.strip()
        if indent == 0 and text:
            system, in_firmware = text, False
        elif indent == 2:
            in_firmware = text == "Firmware"
        elif indent == 4 and in_firmware and ":" in text:
            key, value = (part.strip() for part in text.split(":", 1))
            target = _rewritten(value, old, new)
            if target is not None:
                entries.setdefault(system, []).append((key, target, number))
    if not entries:
        raise LauncherPatternMissing(path, f"Firmware path under {old}")
    for system, found in entries.items():
        folder = posixpath.commonpath([posixpath.dirname(t) for _, t, _ in found])
        records.append(with_evidence(
            tree, script,
            Launcher(
                emulator="ares",
                build="standalone",
                kind="fixed_name",
                names=[posixpath.relpath(t, folder) for _, t, _ in found],
                source_ref=source_ref(
                    [(path, {n for _, _, n in found}), (script.path, script_lines)]
                ),
                slot=system,
                search_dir=folder,
                passes_to="settings.bml "
                + ", ".join(f"{system}/Firmware/{k}" for k, _, _ in found),
            ),
            posixpath.basename(path),
        ))
    return records


def melonds(tree: RepoTree) -> list[Launcher]:
    """melonDS.ini paths set by changeLine, melonDS.toml paths shipped and rewritten by sed."""
    name = "emuDeckMelonDS.sh"
    script = _script(tree, name)
    records = [
        with_evidence(tree, script, record, str(record.passes_to or "").split(" ", 1)[0])
        for record in setter_records(tree, name, option_key="ExternalBIOSEnable")
    ]
    # A config whose BIOS keys the setters write again keeps their values.
    set_by_setters = {file for file, _, _, value, _ in setters(script) if _is_bios(value)}
    for file, old, new, sed_lines in sed_rewrites(script, "melonDS_init"):
        if file in set_by_setters:
            continue
        path = _repo_config(script, file)
        found = []
        for setting in settings(tree.read(path)):
            target = _rewritten(setting.value, old, new)
            if target is not None and _is_bios(posixpath.dirname(target)):
                found.append((setting, target))
        if not found:
            continue
        folder = posixpath.commonpath([posixpath.dirname(t) for _, t in found])
        config = posixpath.basename(path)
        shipped = {s.key: s for s in settings(tree.read(path))}
        if "ExternalBIOSEnable" not in shipped or "ConsoleType" not in shipped:
            raise LauncherPatternMissing(path, "ExternalBIOSEnable and ConsoleType")
        option, console = shipped["ExternalBIOSEnable"], shipped["ConsoleType"]
        # The DS keys are read under ExternalBIOSEnable, the DSi keys only
        # when the console is a DSi (ConsoleType 1).
        record = Launcher(
            emulator="melonds",
            build="standalone",
            kind="fixed_name",
            names=[posixpath.relpath(t, folder) for _, t in found],
            source_ref=source_ref([
                (path, {option.line, console.line, *(s.line for s, _ in found)}),
                (script.path, sed_lines),
            ]),
            search_dir=folder,
            passes_to=describe_keys(config, tuple((s.section, s.key) for s, _ in found)),
            depends_on_option=(
                f"[DS] keys: ExternalBIOSEnable = true, {option.value} in the shipped {config}; "
                f"[DSi] keys: ConsoleType = 1, {console.value} in the shipped {config}"
            ),
        )
        records.append(with_evidence(tree, script, record, config))
    if len(records) < 2:
        raise script.missing("melonDS.toml BIOS paths rewritten by sed")
    return records


# Scripts whose setters write a BIOS path or directory into the emulator config.
SETTER_SCRIPTS = (
    "emuDeckRMG.sh",
    "emuDeckXemu.sh",
    "emuDeckDuckStation.sh",
    "emuDeckPCSX2QT.sh",
    "emuDeckARMSX2.sh",
    "emuDeckMAME.sh",
    "emuDeckRetroArch.sh",
)

# Scripts that link a directory of bios/ to one the emulator reads.
LINK_SCRIPTS = (
    "emuDeckFlycast.sh",
    "emuDeckAzahar.sh",
    "emuDeckCitron.sh",
    "emuDeckEden.sh",
    "emuDeckSuyu.sh",
    "emuDeckYuzu.sh",
    "emuDeckRyujinx.sh",
    "emuDeckShadPS4.sh",
)


def configured(tree: RepoTree) -> list[Launcher]:
    return [record for name in SETTER_SCRIPTS for record in setter_records(tree, name)]


def links(tree: RepoTree) -> list[Launcher]:
    records = []
    for name in LINK_SCRIPTS:
        script = _script(tree, name)
        found = script.links(BIOS)
        if not found:
            raise script.missing(f"ln -s of a path under {BIOS}")
        records.extend(
            Launcher(
                emulator=_emulator(name),
                build="standalone",
                kind="links",
                names=list(link.names),
                source_ref=source_ref([(script.path, link.lines)]),
                expands=link.expands or None,
                search_dir=link.bios_side,
                passes_to=f"symlink {link.link} -> {link.target}",
            )
            for link in found
        )
    return records


EXTRACTORS: tuple[Callable[[RepoTree], list[Launcher]], ...] = (
    ares,
    melonds,
    configured,
    links,
)

SOURCE_SCRIPTS = ("emuDeckares.sh", "emuDeckMelonDS.sh", *SETTER_SCRIPTS, *LINK_SCRIPTS)


def extract_launchers(tree: RepoTree) -> list[dict]:
    """Every launcher record the extractors find, in extractor order."""
    return [record.entry() for extractor in EXTRACTORS for record in extractor(tree)]
