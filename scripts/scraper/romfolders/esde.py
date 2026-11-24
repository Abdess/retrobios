"""ES-DE: es_systems.xml with the alternative emulators and the commands an installer writes over it."""

from __future__ import annotations

import re
import shlex
from collections.abc import Iterator

from model.romfolders import format_ref
from model.safeparse import parse_untrusted_xml

from . import Fetcher, SourceError, register
from .es import extension_list, first_lines, lenient_xml, folder_offers, strip_prefix


# ---------------------------------------------------------------------------
# ES-DE (EmuDeck, RetroDECK)


_RA_CORE = re.compile(r"%CORE_RETROARCH%[/\\]([\w.+-]+?)_libretro")
_EMULATOR = re.compile(r"%EMULATOR_([A-Za-z0-9_-]+)%")


def command_core(command: str) -> tuple[str | None, str | None]:
    match = _RA_CORE.search(command)
    if match:
        return "retroarch", match.group(1)
    match = _EMULATOR.search(command)
    if match:
        name = match.group(1).lower()
        return name, name
    return None, None


def esde_systems(text: str, path: str) -> Iterator[tuple[str, str, list[str], list[tuple[str, str]]]]:
    root = parse_untrusted_xml(lenient_xml(text), path)
    for system in root.iter("system"):
        name = (system.findtext("name") or "").strip()
        rom_path = (system.findtext("path") or "").strip()
        commands = [((c.get("label") or "").strip(), (c.text or "").strip())
                    for c in system.findall("command")]
        yield name, rom_path, extension_list(system.findtext("extension")), commands


def _alternative_emulators(text: str, function: str) -> dict[str, tuple[str, int]]:
    """`ESDE_setEmu '<label>' <system>` calls inside one function."""
    out: dict[str, tuple[str, int]] = {}
    inside = False
    for number, line in enumerate(text.splitlines(), 1):
        if re.search(rf"\b{re.escape(function)}\b\s*\(\)|function\s+{re.escape(function)}\b", line):
            inside = True
            continue
        if not inside:
            continue
        if line.rstrip() == "}":
            break
        match = re.search(r"ESDE_setEmu\s+['\"]([^'\"]+)['\"]\s+([\w.-]+)", line)
        if match:
            out[match.group(2)] = (match.group(1), number)
    return out


_ROMPATH_OPTIONS = ("-rompath", "-rp")


def _core_words(command: str) -> tuple[str, list[str]] | None:
    """The core and the words of the content RetroArch hands it.

    ES-DE starts the libretro MAME core with a quoted command line as its
    content (`-L .../mame_libretro.so "apple2e -rompath \\"...\\" ..."`): popen
    runs it through the shell (es-core/src/utils/PlatformUtil.cpp:231, 257),
    and the core splits the content on spaces and quotes when it is no file
    (retro_init.cpp parse_cmdline, mmain2).
    """
    core = _RA_CORE.search(command)
    if core is None:
        return None
    try:
        args = shlex.split(command)
        at = args.index("-L")
        content = shlex.split(args[at + 2]) if at + 2 < len(args) else []
    except ValueError:
        return None
    return core.group(1), content


def _searched_by(commands: list[tuple[str, str, int | None]], key: str, path: str) -> list[dict]:
    """The ROM folders each emulator's commands pass it, by emulator and core.

    ES-DE starts standalone MAME with `-rompath %GAMEDIR%\\;%ROMPATH%/<system>`
    and a machine, or %BASENAME% where the game is the machine. The command
    line outranks mame.ini. The libretro MAME core gets the same option in
    the command line it is handed as content, after the machine. %GAMEDIR%
    is the game's own folder, no folder a pack fills.
    """
    found: dict[tuple[str, str], dict] = {}
    for _label, command, line in commands:
        libretro = _core_words(command)
        if libretro is not None:
            core, words = libretro
            if words[:1] == [core]:
                # A first word naming the core is dropped (mmain2).
                words = words[1:]
            name = "retroarch"
            at = next((i for i, w in enumerate(words) if w in _ROMPATH_OPTIONS), None)
            machine = words[0] if words and at else ""
        else:
            emulator = _EMULATOR.search(command)
            if emulator is None:
                continue
            core, name = "", emulator.group(1).lower()
            words = command.replace("\\;", ";").split()
            at = next((i for i, w in enumerate(words) if w in _ROMPATH_OPTIONS), None)
            machine = words[at + 2] if at is not None and at + 2 < len(words) else ""
        if at is None or at + 1 >= len(words):
            continue
        reads = [
            folder for part in words[at + 1].split(";")
            if (folder := strip_prefix(part, ["%ROMPATH%/", "%ROMPATH%\\"]))
        ]
        if not reads:
            continue
        record = found.setdefault((name, core), {"emulator": name, "core": core, "reads": [],
                                                 "machines": [], "any_machine": False,
                                                 "lines": []})
        record["reads"] += [r for r in reads if r not in record["reads"]]
        if not machine or machine.startswith("%"):
            record["any_machine"] = True
        elif machine not in record["machines"]:
            record["machines"].append(machine)
        record["lines"].append(line)
    rows = []
    for record in found.values():
        row = {"emulator": record["emulator"]}
        if record["core"]:
            row["core"] = record["core"]
        row["reads"] = record["reads"]
        if record["machines"]:
            row["machines"] = record["machines"]
        if record["any_machine"]:
            row["any_machine"] = True
        row["source_ref"] = format_ref(key, path, *record["lines"])
        rows.append(row)
    return rows


def _command_lines(text: str) -> dict[str, list[int]]:
    """Command text -> the lines it is written on, in file order."""
    out: dict[str, list[int]] = {}
    for number, line in enumerate(text.splitlines(), 1):
        match = re.search(r"<command\b[^>]*>([^<]*)</command>", line)
        if match:
            out.setdefault(match.group(1).strip(), []).append(number)
    return out


@register("esde")
def esde(spec: dict, fetcher: Fetcher) -> list[dict]:
    """Each system of ES-DE's list whose path is %ROMPATH%/<folder>.

    The default emulator is the first <command> (FileData.cpp), unless an
    alternativeEmulator label is written for the system: an installer that
    sets one names a command of that system by its label. A custom system
    file replaces the bundled definition of the same name.
    """
    params = spec["params"]
    systems: dict[str, dict] = {}
    for item in [params["systems"], *params.get("custom", [])]:
        key, path = item["source"], item["path"]
        text = lenient_xml(fetcher.text(key, path))
        lines = first_lines(text, r"<name>([^<]+)</name>")
        command_lines = _command_lines(text)
        for name, rom_path, extensions, commands in esde_systems(text, path):
            folder = strip_prefix(rom_path, ["%ROMPATH%/", "%ROMPATH%\\"])
            if not name or not folder:
                continue
            start = lines.get(name) or 0
            placed = [
                (label, command, next(
                    (n for n in command_lines.get(command, []) if n >= start), None))
                for label, command in commands
            ]
            systems[name] = {
                "folder": folder, "extensions": extensions, "commands": commands,
                "ref": format_ref(key, path, lines.get(name)),
                "searched_by": _searched_by(placed, key, path),
                "placed": [(*c, key, path) for c in placed],
            }
    alternatives: dict[str, tuple[str, int]] = {}
    alt = params.get("alternatives")
    if alt:
        alternatives = _alternative_emulators(fetcher.text(alt["source"], alt["path"]), alt["function"])
        if not alternatives:
            raise SourceError(f"{alt['path']}: no ESDE_setEmu call in {alt['function']}")
    rows: list[dict] = []
    for name, system in systems.items():
        commands = system["commands"]
        refs = [system["ref"]]
        chosen = commands[0] if commands else ("", "")
        note = None
        if name in alternatives:
            label, line = alternatives[name]
            match = next((c for c in commands if c[0] == label), None)
            refs.append(format_ref(alt["source"], alt["path"], line))
            if match:
                chosen = match
            else:
                note = f"alternative emulator '{label}' names no command of this system"
        emulator, core = command_core(chosen[1])
        offers = folder_offers([
            {"emulator": e, "core": c, "source_ref": format_ref(key_, path_, line)}
            for _label, command, line, key_, path_ in system["placed"]
            for e, c in [command_core(command)] if e
        ], core, emulator)
        extensions = system["extensions"]
        if "." in extensions:
            # ES-DE's "." is a file without an extension (SystemData.cpp
            # getExtension), not a suffix the schema can hold.
            extensions = [e for e in extensions if e != "."]
            note = "; ".join(filter(None, [note, "files without an extension are games too ('.' in the list)"]))
        rows.append({
            "folder": system["folder"],
            "name": name,
            "extensions": extensions,
            "core": core,
            "emulator": emulator,
            "source_ref": "; ".join(refs),
            "note": note,
            "offers": offers,
            "searched_by": system["searched_by"] or None,
        })
    return rows
