"""EmulationStation family: the system lists each OS builds its menu from.

Every parser returns one row per folder under the roms root, with the
extensions the list accepts, the core the OS starts by default and the
line of the list that says so. Systems the list keeps outside the roms root
(an absolute path elsewhere) or marks as no game system are left out: the
installer never scans them.

Formats, by the shape of the source:

- `batocera-es`: es_systems.yml plus configgen-defaults.yml and its per-board
  files (Batocera, KNULLI).
- `es-xml`: a static es_systems.cfg (AmberELEC, CHAos, PAN4ELEC, ArkOS,
  dArkOS, RetroBat).
- `es-json`: EmuELEC's es_systems.json, turned into the XML at build time.
- `elec-conf`: config/emulators/<system>.conf plus the add_emu_core and
  add_es_system calls of the emulators package (ROCKNIX, JELOS, KOLOS,
  UnofficialOS, ArchR).
- `esde`: ES-DE's es_systems.xml, with the alternative emulators and custom
  systems an installer writes over it (EmuDeck, RetroDECK).
- `recalbox`: one system.ini per system (Recalbox).
- `retropie`: platforms.cfg and the addEmulator calls of the scriptmodules.
"""

from __future__ import annotations

import html
import json
import re
import shlex
from collections import Counter
from collections.abc import Iterator

from safeparse import parse_untrusted_xml, yaml_load_upstream

from . import Fetcher, SourceError, register


def _ref(key: str, path: str, *lines: int | str | None) -> str:
    kept = [str(n) for n in lines if n not in (None, "")]
    return f"{key} {path}:{','.join(kept)}" if kept else f"{key} {path}"


def _board(core: str | None, emulator: str | None, source_ref: str) -> dict:
    out = {"core": core or emulator, "emulator": emulator, "source_ref": source_ref}
    return {k: str(v) for k, v in out.items() if v}


def _top_key_lines(text: str) -> dict[str, int]:
    """First line of each top-level YAML key."""
    out: dict[str, int] = {}
    for number, line in enumerate(text.splitlines(), 1):
        match = re.match(r"^([A-Za-z0-9_+.\-]+):", line)
        if match:
            out.setdefault(match.group(1), number)
    return out


def _strip_prefix(path: str, prefixes: list[str]) -> str | None:
    """The folder under the roms root, or None for a path outside it."""
    for prefix in prefixes:
        if path.startswith(prefix):
            rest = path[len(prefix):].strip("/\\")
            return rest.replace("\\", "/") or None
    return None


def _extensions(raw: str | list | None) -> list[str]:
    words = raw.split() if isinstance(raw, str) else [str(w) for w in raw or []]
    return [w if w.startswith(".") else f".{w}" for w in words if w]


# ---------------------------------------------------------------------------
# Batocera and KNULLI


def _yaml_or_link(fetcher: Fetcher, key: str, directory: str, name: str) -> tuple[dict, str, str]:
    """A configgen file, following a git symlink the raw route serves as text."""
    path = f"{directory}/{name}"
    text = fetcher.text(key, path)
    data = yaml_load_upstream(text)
    if isinstance(data, str) and data.strip().endswith(".yml"):
        path = f"{directory}/{data.strip()}"
        text = fetcher.text(key, path)
        data = yaml_load_upstream(text)
    if not isinstance(data, dict):
        raise SourceError(f"{path} is not a mapping")
    return data, text, path


@register("batocera-es")
def batocera_es(spec: dict, fetcher: Fetcher) -> list[dict]:
    """es_systems.yml read the way batocera-es-system writes the XML.

    A system with no emulator and no `force` is never written
    (es_systems.py `_system_dict_to_xml`), `path` defaults to the key and an
    absolute path leaves the roms root. The default core is configgen's:
    the board file first, then configgen-defaults.yml (shared.py
    ConfiggenDefaults.get).
    """
    params = spec["params"]
    key = params.get("source", "os")
    es_path = params["es_systems"]
    es_text = fetcher.text(key, es_path)
    systems = yaml_load_upstream(es_text)
    if not isinstance(systems, dict):
        raise SourceError(f"{es_path} is not a mapping")
    es_lines = _top_key_lines(es_text)
    directory = params["configgen_dir"]
    defaults, def_text, def_path = _yaml_or_link(fetcher, key, directory, "configgen-defaults.yml")
    def_lines = _top_key_lines(def_text)
    boards: dict[str, tuple[dict, dict[str, int], str]] = {}
    for path in fetcher.tree(key, f"{directory}/configgen-defaults-"):
        name = path.rsplit("/", 1)[-1]
        if not name.endswith(".yml"):
            continue
        data, text, real = _yaml_or_link(fetcher, key, directory, name)
        boards[name[len("configgen-defaults-"):-len(".yml")]] = (data, _top_key_lines(text), real)
    rows: list[dict] = []
    for name, system in systems.items():
        if not isinstance(system, dict):
            continue
        if not system.get("emulators") and not system.get("force"):
            continue
        path = system.get("path", name)
        if not path or str(path).startswith("/"):
            continue
        base = defaults.get(name) or {}
        emulator, core = base.get("emulator"), base.get("core")
        board_defaults: dict[str, dict] = {}
        for board, (data, lines, real) in sorted(boards.items()):
            override = data.get(name) or {}
            b_emu, b_core = override.get("emulator", emulator), override.get("core", core)
            if (b_emu, b_core) != (emulator, core) and b_core:
                board_defaults[board] = _board(b_core, b_emu, _ref(key, real, lines.get(name)))
        refs = [_ref(key, es_path, es_lines.get(name))]
        if name in def_lines:
            refs.append(_ref(key, def_path, def_lines[name]))
        rows.append({
            "folder": str(path),
            "name": name,
            "extensions": _extensions(system.get("extensions")),
            "core": str(core) if core else None,
            "emulator": str(emulator) if emulator else None,
            "source_ref": "; ".join(refs),
            "board_defaults": board_defaults,
            "arcade": system.get("hardware") == "arcade" or None,
        })
    return rows


# ---------------------------------------------------------------------------
# Static es_systems.cfg (XML) and EmuELEC's es_systems.json


def _first_lines(text: str, pattern: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for number, line in enumerate(text.splitlines(), 1):
        match = re.search(pattern, line)
        if match:
            out.setdefault(match.group(1).strip(), number)
    return out


def _all_lines(text: str, pattern: str) -> dict[str, list[int]]:
    """Every line each name is declared on, in file order."""
    out: dict[str, list[int]] = {}
    for number, line in enumerate(text.splitlines(), 1):
        match = re.search(pattern, line)
        if match:
            out.setdefault(html.unescape(match.group(1)).strip(), []).append(number)
    return out


def _name_once(row: dict, lines: dict[str, list[int]], seen: dict[str, int]) -> dict:
    """A system name the list gives twice designates neither: the row keeps
    its folder and the line of its own occurrence."""
    name = row["name"]
    index = seen.get(name, 0)
    seen[name] = index + 1
    found = lines.get(name, [])
    row["line"] = found[index] if index < len(found) else None
    if len(found) > 1:
        row["note"] = "; ".join(filter(None, [row.get("note"), f"the list names {len(found)} systems {name}"]))
        row["name"] = None
    return row


def _pick_default(emulators: list[tuple[str, list[tuple[str, bool]]]], rule: str) -> tuple[str | None, str | None]:
    """The emulator and core the frontend starts when the user chose none.

    `flagged`: the core marked default, else the first emulator's first
    core. `first`: the first emulator's first core, whatever is flagged.
    """
    if rule == "flagged":
        for emulator, cores in emulators:
            for core, default in cores:
                if default:
                    return emulator, core
    for emulator, cores in emulators:
        if cores:
            return emulator, cores[0][0]
        return emulator, None
    return None, None


_LIBRETRO_SO = re.compile(r"-L\s+\S*?[/\\]([\w.+-]+?)_libretro\.(?:so|dll|dylib)")


def _libretro_in_command(command: str) -> tuple[str | None, str | None]:
    match = _LIBRETRO_SO.search(command)
    return ("retroarch", match.group(1)) if match else (None, None)


def _is_arcade(hardware: str | None, platform: str | None) -> bool | None:
    words = set(re.split(r"[\s,]+", (platform or "").lower()))
    return (hardware or "").lower() == "arcade" or "arcade" in words or None


@register("es-xml")
def es_xml(spec: dict, fetcher: Fetcher) -> list[dict]:
    """A static es_systems.cfg. `boards` names the file another build
    installs instead (dArkOS copies es_systems.cfg.<chipset>): a system whose
    default differs there gets that board's default."""
    params = spec["params"]
    key = params.get("source", "os")
    rows = _xml_rows(fetcher.text(key, params["file"]), key, params["file"], params)
    for board, path in sorted((params.get("boards") or {}).items()):
        other = {r["name"]: r for r in _xml_rows(fetcher.text(key, path), key, path, params)}
        for row in rows:
            alt = other.get(row["name"])
            if alt and alt["core"] and (alt["core"], alt["emulator"]) != (row["core"], row["emulator"]):
                row.setdefault("board_defaults", {})[board] = _board(
                    alt["core"], alt["emulator"], alt["source_ref"])
    return rows


_BARE_AMPERSAND = re.compile(r"&(?!(?:[A-Za-z]+|#\d+|#x[0-9A-Fa-f]+);)")
_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)


def _lenient_xml(text: str) -> str:
    """The list as EmulationStation's pugixml reads it, lines kept in place.

    pugixml keeps a bare `&` as text (ArkOS ships `2>&1` in a command) and
    accepts `--` inside a comment (EmuDeck comments out a command holding
    `--no-gui`). A comment is blanked to its newlines, so a system left in
    a comment neither parses nor lends its line to a citation.
    """
    text = _COMMENT.sub(lambda m: "\n" * m.group(0).count("\n"), text)
    return _BARE_AMPERSAND.sub("&amp;", text)


def _xml_rows(text: str, key: str, path: str, params: dict) -> list[dict]:
    text = _lenient_xml(text)
    root = parse_untrusted_xml(text, path)
    lines = _all_lines(text, r"<name>([^<]+)</name>")
    seen: dict[str, int] = {}
    rule = params.get("default", "flagged")
    rows: list[dict] = []
    for system in root.iter("system"):
        name = (system.findtext("name") or "").strip()
        command = (system.findtext("command") or "").strip()
        platform = (system.findtext("platform") or "").strip()
        row = _name_once({"name": name}, lines, seen)
        if not name or "ignore" in (command, platform):
            continue
        folder = _strip_prefix((system.findtext("path") or "").strip(), params["path_prefixes"])
        if not folder:
            continue
        emulators = [
            (emulator.get("name") or "",
             [((core.text or "").strip(), core.get("default") == "true")
              for core in emulator.iter("core") if (core.text or "").strip()])
            for emulator in system.iter("emulator")
        ]
        emulator, core = _pick_default(emulators, rule)
        if not emulators:
            # No <emulators>: the command starts the core itself (ArkOS
            # `retroarch -L .../mess_libretro.so %ROM%`).
            emulator, core = _libretro_in_command(command)
        rows.append({
            "folder": folder,
            "name": row["name"],
            "extensions": _extensions(system.findtext("extension")),
            "core": core or emulator,
            "emulator": emulator,
            "source_ref": _ref(key, path, row["line"]),
            "arcade": _is_arcade(system.findtext("hardware"), platform),
            "note": row.get("note"),
        })
    return rows


@register("es-json")
def es_json(spec: dict, fetcher: Fetcher) -> list[dict]:
    params = spec["params"]
    key = params.get("source", "os")
    path = params["file"]
    text = fetcher.text(key, path)
    lines = _all_lines(text, r'^\s{4,6}"name":\s*"([^"]+)"')
    seen: dict[str, int] = {}
    rows: list[dict] = []
    for system in json.loads(text).get("systems", []):
        name = system.get("name") or ""
        row = _name_once({"name": name}, lines, seen)
        if "ignore" in (system.get("command"), system.get("platform")):
            continue
        folder = _strip_prefix(system.get("path") or "", params["path_prefixes"])
        if not name or not folder:
            continue
        emulators = [
            (emulator.get("name") or "",
             [(c.get("name") or "", bool(c.get("default"))) for c in emulator.get("cores") or []])
            for emulator in system.get("emulators") or []
        ]
        emulator, core = _pick_default(emulators, params.get("default", "flagged"))
        rows.append({
            "folder": folder,
            "name": row["name"],
            "extensions": _extensions(system.get("extensions")),
            "core": core or emulator,
            "emulator": emulator,
            "source_ref": _ref(key, path, row["line"]),
            "arcade": _is_arcade(system.get("hardware"), system.get("platform")),
            "note": row.get("note"),
        })
    return rows


# ---------------------------------------------------------------------------
# ROCKNIX family: config/emulators/<system>.conf and the emulators package


def _conf_values(text: str) -> tuple[dict[str, str], dict[str, int]]:
    values: dict[str, str] = {}
    lines: dict[str, int] = {}
    for number, line in enumerate(text.splitlines(), 1):
        match = re.match(r"^\s*(SYSTEM_[A-Z_]+)=(.*)$", line)
        if not match:
            continue
        raw = match.group(2).strip()
        try:
            value = " ".join(shlex.split(raw))
        except ValueError:
            value = raw.strip('"')
        values[match.group(1)] = value
        lines[match.group(1)] = number
    return values, lines


def _package_calls(text: str) -> tuple[list[dict], dict[str, list[int]]]:
    """add_emu_core and add_es_system calls of makeinstall_target, each
    with the `case` branches it sits under as (variable, pattern) pairs.
    An `if` block nests a condition whose truth the build decides: its
    calls carry it as a branch the default choice does not count as
    unconditional."""
    cores: list[dict] = []
    systems: dict[str, list[int]] = {}
    stack: list[list[str]] = []
    inside = False
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if raw.startswith("makeinstall_target()"):
            inside = True
            continue
        if not inside or not line:
            continue
        if raw.startswith("}"):
            break
        match = re.match(r'case\s+"?\$\{?(\w+)\}?"?\s+in', line)
        if match:
            stack.append(["case", match.group(1), ""])
            continue
        if line == "esac":
            stack.pop()
            continue
        if line.startswith("if ") or line.startswith("[") and "&&" not in line and line.endswith("then"):
            stack.append(["if", line, ""])
            continue
        if line in ("fi",):
            if stack and stack[-1][0] == "if":
                stack.pop()
            continue
        if line in ("then", "else") or line.startswith("elif "):
            continue
        ends = line.endswith(";;")
        if ends:
            line = line[:-2].strip()
        if stack and stack[-1][0] == "case":
            match = re.match(r"^([^()\s][^()]*)\)\s*(.*)$", line)
            if match and not line.startswith(("add_", "[", "sed", "cp", "mkdir")):
                stack[-1][2] = match.group(1).strip()
                line = match.group(2).strip()
        words = line.split()
        branches = [(s[1], s[2]) for s in stack]
        if words[:1] == ["add_emu_core"] and len(words) >= 4:
            cores.append({
                "system": words[1], "emulator": words[2], "core": words[3],
                "default": len(words) > 4 and words[4] == "true",
                "branches": branches, "line": number,
            })
        elif words[:1] == ["add_es_system"] and len(words) >= 2:
            systems.setdefault(words[1], []).append(number)
        if ends and stack and stack[-1][0] == "case":
            stack[-1][2] = ""
    return cores, systems


def _board_key(branches: list[tuple[str, str]]) -> str | None:
    """A default chosen under one `case` on the device names that device."""
    if len(branches) == 1 and branches[0][1] and branches[0][1] != "*":
        variable, pattern = branches[0]
        if not variable.startswith("["):
            return f"{variable}={pattern}"
    return None


@register("elec-conf")
def elec_conf(spec: dict, fetcher: Fetcher) -> list[dict]:
    """A system ES lists is one add_es_system writes from its conf file
    (SYSTEM_PATH, SYSTEM_EXTENSION). The default is the core whose
    add_emu_core says true: unconditional, else the `*)` branch of a
    device case, the branches for named devices going to board_defaults."""
    params = spec["params"]
    key = params.get("source", "os")
    package = params["package"]
    cores, systems = _package_calls(fetcher.text(key, package))
    if not systems:
        raise SourceError(f"{package}: no add_es_system call")
    conf_dir = params["conf_dir"]
    rows: list[dict] = []
    for name, lines in systems.items():
        conf_path = f"{conf_dir}/{name}.conf"
        conf_text = fetcher.optional_text(key, conf_path)
        if conf_text is None:
            continue
        values, value_lines = _conf_values(conf_text)
        folder = _strip_prefix(values.get("SYSTEM_PATH", ""), params["path_prefixes"])
        if not folder:
            continue
        mine = [c for c in cores if c["system"] == name]
        flagged = [c for c in mine if c["default"]]
        plain = [c for c in flagged if not c["branches"]]
        star = [c for c in flagged if c["branches"] and c["branches"][-1][1] == "*"]
        pick = (plain or star or flagged or [None])[0]
        if pick is None:
            pick = next((c for c in mine if not c["branches"]), mine[0] if mine else None)
        board_defaults = {}
        for c in flagged:
            board = _board_key(c["branches"])
            if c is not pick and board and (c["emulator"], c["core"]) != (
                    pick and pick["emulator"], pick and pick["core"]):
                board_defaults[board] = _board(c["core"], c["emulator"], _ref(key, package, c["line"]))
        refs = [
            _ref(key, conf_path, value_lines.get("SYSTEM_PATH"), value_lines.get("SYSTEM_EXTENSION")),
            _ref(key, package, *lines),
        ]
        if pick:
            refs.append(_ref(key, package, pick["line"]))
        note = None
        if pick and pick["branches"] and not _board_key(pick["branches"]) and pick["branches"][-1][1] != "*":
            note = "default core chosen under a build condition: " + ", ".join(
                f"{v} {p}".strip() for v, p in pick["branches"])
        rows.append({
            "folder": folder,
            "name": name,
            "extensions": _extensions(values.get("SYSTEM_EXTENSION")),
            "core": pick["core"] if pick else None,
            "emulator": pick["emulator"] if pick else None,
            "source_ref": "; ".join(refs),
            "board_defaults": board_defaults,
            "arcade": values.get("SYSTEM_HARDWARE") == "arcade" or None,
            "note": note,
        })
    return rows


# ---------------------------------------------------------------------------
# ES-DE (EmuDeck, RetroDECK)


_RA_CORE = re.compile(r"%CORE_RETROARCH%[/\\]([\w.+-]+?)_libretro")
_EMULATOR = re.compile(r"%EMULATOR_([A-Za-z0-9_-]+)%")


def _command_core(command: str) -> tuple[str | None, str | None]:
    match = _RA_CORE.search(command)
    if match:
        return "retroarch", match.group(1)
    match = _EMULATOR.search(command)
    if match:
        name = match.group(1).lower()
        return name, name
    return None, None


def _esde_systems(text: str, path: str) -> Iterator[tuple[str, str, list[str], list[tuple[str, str]]]]:
    root = parse_untrusted_xml(_lenient_xml(text), path)
    for system in root.iter("system"):
        name = (system.findtext("name") or "").strip()
        rom_path = (system.findtext("path") or "").strip()
        commands = [((c.get("label") or "").strip(), (c.text or "").strip())
                    for c in system.findall("command")]
        yield name, rom_path, _extensions(system.findtext("extension")), commands


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


def _searched_by(commands: list[tuple[str, str, int | None]], key: str, path: str) -> list[dict]:
    """The ROM folders each standalone emulator's commands pass it, by emulator.

    ES-DE starts standalone MAME with `-rompath %GAMEDIR%\\;%ROMPATH%/<system>`
    and a machine, or %BASENAME% where the game is the machine. The command
    line outranks mame.ini. %GAMEDIR% is the game's own folder, no folder a
    pack fills.
    """
    found: dict[str, dict] = {}
    for _label, command, line in commands:
        emulator = _EMULATOR.search(command)
        if emulator is None or _RA_CORE.search(command):
            continue
        words = command.replace("\\;", ";").split()
        at = next((i for i, w in enumerate(words) if w in _ROMPATH_OPTIONS), None)
        if at is None or at + 1 >= len(words):
            continue
        reads = [
            folder for part in words[at + 1].split(";")
            if (folder := _strip_prefix(part, ["%ROMPATH%/", "%ROMPATH%\\"]))
        ]
        if not reads:
            continue
        name = emulator.group(1).lower()
        record = found.setdefault(name, {"emulator": name, "reads": [], "machines": [],
                                         "any_machine": False, "lines": []})
        record["reads"] += [r for r in reads if r not in record["reads"]]
        machine = words[at + 2] if at + 2 < len(words) else ""
        if not machine or machine.startswith("%"):
            record["any_machine"] = True
        elif machine not in record["machines"]:
            record["machines"].append(machine)
        record["lines"].append(line)
    rows = []
    for record in found.values():
        row = {"emulator": record["emulator"], "reads": record["reads"]}
        if record["machines"]:
            row["machines"] = record["machines"]
        if record["any_machine"]:
            row["any_machine"] = True
        row["source_ref"] = _ref(key, path, *record["lines"])
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
        text = _lenient_xml(fetcher.text(key, path))
        lines = _first_lines(text, r"<name>([^<]+)</name>")
        command_lines = _command_lines(text)
        for name, rom_path, extensions, commands in _esde_systems(text, path):
            folder = _strip_prefix(rom_path, ["%ROMPATH%/", "%ROMPATH%\\"])
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
                "ref": _ref(key, path, lines.get(name)),
                "searched_by": _searched_by(placed, key, path),
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
            refs.append(_ref(alt["source"], alt["path"], line))
            if match:
                chosen = match
            else:
                note = f"alternative emulator '{label}' names no command of this system"
        emulator, core = _command_core(chosen[1])
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
            "searched_by": system["searched_by"] or None,
        })
    return rows


# ---------------------------------------------------------------------------
# Recalbox


def _ini_sections(text: str) -> tuple[dict[str, dict[str, str]], dict[str, int]]:
    sections: dict[str, dict[str, str]] = {}
    lines: dict[str, int] = {}
    current: dict[str, str] | None = None
    name = ""
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith((";", "#")):
            continue
        if line.startswith("[") and line.endswith("]"):
            name = line[1:-1]
            current = sections.setdefault(name, {})
            lines.setdefault(name, number)
        elif current is not None and "=" in line:
            k, v = line.split("=", 1)
            current[k.strip()] = v.strip().strip('"')
            lines.setdefault(f"{name}/{k.strip()}", number)
    return sections, lines


# romfs2 systemholder.py reads core.0 to core.19.
_RECALBOX_CORE_SLOTS = 20
_RECALBOX_TARGET = "BR2_PACKAGE_RECALBOX_TARGET_"
_ENABLED = re.compile(r"^(BR2_\w+)=y\s*$")
# FolderData.cpp IsMatching: a list opening with files: holds whole file
# names, each bounded by a space or an end of the list.
_FILES_PREFIX = "files:"


def _recalbox_names(listed: str) -> list[str]:
    """The whole names of a files: list. A name may hold spaces
    ("prince of persia (1990).zip"): a list with a word that has no dot
    is one name, not several."""
    words = listed.split()
    if words and all("." in word for word in words):
        return words
    return [listed.strip()] if listed.strip() else []


def _recalbox_boards(fetcher: Fetcher, key: str, configs_dir: str) -> dict[str, tuple[str, dict[str, int]]]:
    """Each board's tag and the packages its defconfig enables, with their
    lines. The tag is the lowercased BR2_PACKAGE_RECALBOX_TARGET_<tag>
    (romfs2 configin.py), the suffix a system.ini key or section takes."""
    fetcher.cache_directory(key, configs_dir)
    boards: dict[str, tuple[str, dict[str, int]]] = {}
    for path in fetcher.entries(key, configs_dir):
        if not path.endswith("_defconfig"):
            continue
        enabled: dict[str, int] = {}
        for number, line in enumerate(fetcher.text(key, path).splitlines(), 1):
            found = _ENABLED.match(line.strip())
            if found:
                enabled.setdefault(found.group(1), number)
        tags = [name[len(_RECALBOX_TARGET):].lower() for name in enabled if name.startswith(_RECALBOX_TARGET)]
        if tags:
            boards[tags[0]] = (path, enabled)
    if not boards:
        raise SourceError(f"{configs_dir}: no defconfig names a Recalbox target")
    return boards


def _recalbox_get(
    sections: dict[str, dict[str, str]], lines: dict[str, int], section: str, key: str, board: str
) -> tuple[str | None, int | None]:
    """systemholder.py __get: the board's section, then the board's key,
    then the plain key."""
    for where, name in ((f"{section}.{board}", key), (section, f"{key}.{board}"), (section, key)):
        if name in sections.get(where, {}):
            return sections[where][name], lines.get(f"{where}/{name}")
    return None, None


@register("recalbox")
def recalbox(spec: dict, fetcher: Fetcher) -> list[dict]:
    """One system.ini per system, built once per board. A core is kept on
    a board whose defconfig enables its `package`, and a system left with
    none is not built there (romfs2). The default core is the lowest
    `priority` (EmulatorManager), the last listed on a tie. The row names the
    default most boards share, and `board_defaults` every board that differs.
    A `.ext!` extension is an archive the frontend hands over unopened, and
    a `files:` list names whole files instead of extensions."""
    params = spec["params"]
    key = params.get("source", "os")
    boards = _recalbox_boards(fetcher, key, params["configs_dir"])
    rows: list[dict] = []
    fetcher.cache_directory(key, params["systems_dir"])
    for entry in fetcher.entries(key, params["systems_dir"]):
        path = f"{entry}/system.ini"
        text = fetcher.optional_text(key, path)
        if text is None:
            continue
        sections, lines = _ini_sections(text)
        system = sections.get("system", {})
        folder = _strip_prefix(system.get("roms.folder", ""), ["%ROOT%/"])
        if not folder:
            continue
        picks: dict[str, dict] = {}
        extensions: set[str] = set()
        names: set[str] = set()
        for board, (config_path, enabled) in sorted(boards.items()):
            cores = []
            for slot in range(_RECALBOX_CORE_SLOTS):
                section = f"core.{slot}"
                if section not in sections and f"{section}.{board}" not in sections:
                    continue
                package, _ = _recalbox_get(sections, lines, section, "package", board)
                if package not in enabled:
                    continue
                priority, priority_line = _recalbox_get(sections, lines, section, "priority", board)
                core, core_line = _recalbox_get(sections, lines, section, "core", board)
                emulator, _ = _recalbox_get(sections, lines, section, "emulator", board)
                exts, _ = _recalbox_get(sections, lines, section, "extensions", board)
                if (exts or "").startswith(_FILES_PREFIX):
                    names.update(_recalbox_names(exts[len(_FILES_PREFIX):]))
                else:
                    extensions.update((exts or "").split())
                cores.append({
                    "core": core, "emulator": emulator, "priority": int(priority or "255"),
                    "source_ref": "; ".join([
                        _ref(key, path, priority_line, core_line),
                        _ref(key, config_path, enabled[package]),
                    ]),
                })
            if cores:
                picks[board] = min(reversed(cores), key=lambda c: c["priority"])
        if not picks:
            continue
        shared = Counter((pick["core"], pick["emulator"]) for pick in picks.values())
        core, emulator = max(shared, key=lambda pair: shared[pair])
        first = next(pick for pick in picks.values() if (pick["core"], pick["emulator"]) == (core, emulator))
        board_defaults = {
            board: _board(pick["core"], pick["emulator"], pick["source_ref"])
            for board, pick in picks.items() if (pick["core"], pick["emulator"]) != (core, emulator)
        }
        archive = any(e.endswith("!") for e in extensions)
        rows.append({
            "folder": folder,
            "name": system.get("name"),
            "extensions": sorted({e.rstrip("!") for e in extensions}),
            "files": sorted(names),
            "core": core,
            "emulator": emulator,
            "source_ref": "; ".join([_ref(key, path, lines.get("system/roms.folder")), first["source_ref"]]),
            "board_defaults": board_defaults,
            "arcade": sections.get("properties", {}).get("type") == "arcade" or None,
            "note": "an extension ending in ! is an archive the frontend does not open" if archive else None,
        })
    return rows


# ---------------------------------------------------------------------------
# RetroPie


_MODULE_FIELD = re.compile(r'^rp_module_(id|section|flags)="([^"]*)"', re.MULTILINE)
_ADD_EMULATOR = re.compile(r'^\s*addEmulator\s+(\S+)\s+("[^"]*"|\S+)\s+("[^"]*"|\S+)')
_LIST = re.compile(r'(?:local\s+)?(\w+)=\(([^)]*)\)')
_LOOP = re.compile(r'for (\w+) in (.+?); do')


def _module_valid(flags: list[str], platform: set[str]) -> bool:
    """packages.sh rp_registerModule: flags read in order, `!all` drops
    the module, a platform flag keeps it, `!<platform flag>` drops it."""
    valid = True
    for flag in flags:
        if flag == "!all":
            valid = False
        elif flag in platform:
            valid = True
        elif flag.startswith("!") and flag[1:] in platform:
            valid = False
    return valid


def _emulator_calls(text: str) -> Iterator[tuple[int, str, str, list[str]]]:
    """(line, default flag, emulator id, systems) of each addEmulator call,
    a system variable expanded through the loop or array that sets it."""
    lines = text.splitlines()
    arrays = {m.group(1): m.group(2).replace('"', "").split() for m in _LIST.finditer(text)}
    loops: list[tuple[int, str, list[str]]] = []
    for index, line in enumerate(lines):
        match = _LOOP.search(line)
        if match:
            items = match.group(2).strip()
            array = re.fullmatch(r'"?\$\{(\w+)\[@\]\}"?', items)
            loops.append((index, match.group(1),
                          arrays.get(array.group(1), []) if array else items.replace('"', "").split()))
    for index, line in enumerate(lines):
        match = _ADD_EMULATOR.match(line)
        if not match or "function addEmulator" in line:
            continue
        flag, emu, system = match.group(1), match.group(2).strip('"'), match.group(3).strip('"')
        systems = [system]
        var = re.fullmatch(r"\$\{?(\w+)\}?", system)
        if var:
            found = [items for i, name, items in loops if i < index and name == var.group(1)]
            if found:
                systems = found[-1]
            elif var.group(1) in arrays:
                systems = arrays[var.group(1)]
            else:
                continue
        yield index + 1, flag, emu, systems


@register("retropie")
def retropie(spec: dict, fetcher: Fetcher) -> list[dict]:
    """Folders are `<system>` under the roms root (helpers.sh addSystem),
    with `<system>_exts` from platforms.cfg. The default is set once, by
    the first installed module whose addEmulator passes 1: a basic install
    installs the core then the main section in registration order
    (setup.sh basic_install_setup, packages.sh rp_registerAllModules). A
    system no basic-install module serves gets its folder from an optional
    module, so the first opt, then exp, module stands as its default."""
    params = spec["params"]
    key = params.get("source", "os")
    cfg_path = params["platforms_cfg"]
    cfg = fetcher.text(key, cfg_path)
    exts: dict[str, tuple[str, int]] = {}
    for number, line in enumerate(cfg.splitlines(), 1):
        match = re.match(r'^([\w-]+)_exts="([^"]*)"', line)
        if match:
            exts[match.group(1)] = (match.group(2), number)
    platform = set(params["platform_flags"])
    modules: list[dict] = []
    for kind in params["module_dirs"]:
        for path in fetcher.tree(key, f"scriptmodules/{kind}/"):
            if not path.endswith(".sh") or path.count("/") != 2:
                continue
            text = fetcher.text(key, path)
            fields = dict(_MODULE_FIELD.findall(text))
            if not _module_valid(fields.get("flags", "").split(), platform):
                continue
            modules.append({"path": path, "id": fields.get("id", ""),
                            "section": fields.get("section", ""), "text": text})
    order = [m for section in params["install_sections"] for m in modules if m["section"] == section]
    defaults: dict[str, tuple[str, str, int]] = {}
    for module in order:
        for line, flag, emu, systems in _emulator_calls(module["text"]):
            if flag != "1":
                continue
            emu = emu.replace("${md_id}", module["id"]).replace("$md_id", module["id"])
            for system in systems:
                defaults.setdefault(system, (emu, module["path"], line))
    rows: list[dict] = []
    for system, (raw, line) in sorted(exts.items()):
        refs = [_ref(key, cfg_path, line)]
        core = None
        if system in defaults:
            core, path, call = defaults[system]
            refs.append(_ref(key, path, call))
        emulator = "retroarch" if core and core.startswith("lr-") else core
        rows.append({
            "folder": system,
            "extensions": _extensions(raw),
            "core": core,
            "emulator": emulator,
            "source_ref": "; ".join(refs),
        })
    return rows
