"""Folder lists built from package scripts: elec-conf emulator packages, Recalbox system.ini, RetroPie scriptmodules."""

from __future__ import annotations

import re
import shlex
from collections import Counter
from collections.abc import Iterator

from model.romfolders import DEFAULT_ROW_SOURCE, format_ref

from ..recalbox_romfs import Defconfig, defconfig_boards, read_system_ini
from ..retropie_modules import PLATFORM_FLAGS, module_enabled, module_fields
from . import Fetcher, SourceError, register
from .es import _board, _extensions, _offers, _strip_prefix


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


def _nesting(line: str, stack: list[list[str]]) -> bool:
    """Follow case and if nesting. True when the line is consumed."""
    match = re.match(r'case\s+"?\$\{?(\w+)\}?"?\s+in', line)
    if match:
        stack.append(["case", match.group(1), ""])
        return True
    if line == "esac":
        stack.pop()
        return True
    if line.startswith("if ") or line.startswith("[") and "&&" not in line and line.endswith("then"):
        stack.append(["if", line, ""])
        return True
    if line in ("fi",):
        if stack and stack[-1][0] == "if":
            stack.pop()
        return True
    return line in ("then", "else") or line.startswith("elif ")


def _record_call(
    words: list[str], number: int, stack: list[list[str]],
    cores: list[dict], systems: dict[str, list[int]],
) -> None:
    branches = [(s[1], s[2]) for s in stack]
    if words[:1] == ["add_emu_core"] and len(words) >= 4:
        cores.append({
            "system": words[1], "emulator": words[2], "core": words[3],
            "default": len(words) > 4 and words[4] == "true",
            "branches": branches, "line": number,
        })
    elif words[:1] == ["add_es_system"] and len(words) >= 2:
        systems.setdefault(words[1], []).append(number)


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
        if _nesting(line, stack):
            continue
        ends = line.endswith(";;")
        if ends:
            line = line[:-2].strip()
        if stack and stack[-1][0] == "case":
            match = re.match(r"^([^()\s][^()]*)\)\s*(.*)$", line)
            if match and not line.startswith(("add_", "[", "sed", "cp", "mkdir")):
                stack[-1][2] = match.group(1).strip()
                line = match.group(2).strip()
        _record_call(line.split(), number, stack, cores, systems)
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
    key = params.get("source", DEFAULT_ROW_SOURCE)
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
        candidates = plain or star or flagged
        pick: dict | None = candidates[0] if candidates else None
        if pick is None:
            pick = next((c for c in mine if not c["branches"]), mine[0] if mine else None)
        board_defaults = {}
        for c in flagged:
            board = _board_key(c["branches"])
            if c is not pick and board and (c["emulator"], c["core"]) != (
                    pick and pick["emulator"], pick and pick["core"]):
                board_defaults[board] = _board(c["core"], c["emulator"], format_ref(key, package, c["line"]))
        refs = [
            format_ref(key, conf_path, value_lines.get("SYSTEM_PATH"), value_lines.get("SYSTEM_EXTENSION")),
            format_ref(key, package, *lines),
        ]
        if pick:
            refs.append(format_ref(key, package, pick["line"]))
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
            "offers": _offers([
                {"emulator": c["emulator"], "core": c["core"],
                 "when": ", ".join(f"{v} {p}".strip() for v, p in c["branches"]),
                 "source_ref": format_ref(key, package, c["line"])}
                for c in mine
            ], pick["core"] if pick else None, pick["emulator"] if pick else None),
            "arcade": values.get("SYSTEM_HARDWARE") == "arcade" or None,
            "note": note,
        })
    return rows


# ---------------------------------------------------------------------------
# Recalbox


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


def _recalbox_boards(fetcher: Fetcher, key: str, configs_dir: str) -> dict[str, tuple[str, Defconfig]]:
    """Each board and the defconfig that builds it, with the lines of the
    packages it enables."""
    fetcher.cache_directory(key, configs_dir)
    found = defconfig_boards(
        (path, fetcher.text(key, path))
        for path in fetcher.entries(key, configs_dir) if path.endswith("_defconfig")
    )
    if not found:
        raise SourceError(f"{configs_dir}: no defconfig names a Recalbox target")
    return found


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
    key = params.get("source", DEFAULT_ROW_SOURCE)
    boards = _recalbox_boards(fetcher, key, params["configs_dir"])
    rows: list[dict] = []
    fetcher.cache_directory(key, params["systems_dir"])
    for entry in fetcher.entries(key, params["systems_dir"]):
        path = f"{entry}/system.ini"
        text = fetcher.optional_text(key, path)
        if text is None:
            continue
        ini = read_system_ini(text)
        sections, lines = ini.sections, ini.lines
        system = sections.get("system", {})
        folder = _strip_prefix(system.get("roms.folder", ""), ["%ROOT%/"])
        if not folder:
            continue
        picks: dict[str, dict] = {}
        extensions: set[str] = set()
        names: set[str] = set()
        for board, (config_path, config) in sorted(boards.items()):
            enabled = config.enabled
            cores = []
            for section in ini.slots(board):
                package, _ = ini.get(section, "package", board)
                if package not in enabled:
                    continue
                priority, priority_line = ini.get(section, "priority", board)
                core, core_line = ini.get(section, "core", board)
                emulator, _ = ini.get(section, "emulator", board)
                exts, _ = ini.get(section, "extensions", board)
                listed = exts or ""
                if listed.startswith(_FILES_PREFIX):
                    names.update(_recalbox_names(listed[len(_FILES_PREFIX):]))
                else:
                    extensions.update(listed.split())
                cores.append({
                    "core": core, "emulator": emulator, "priority": int(priority or "255"),
                    "source_ref": "; ".join([
                        format_ref(key, path, priority_line, core_line),
                        format_ref(key, config_path, enabled[package]),
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
            "source_ref": "; ".join([format_ref(key, path, lines.get("system/roms.folder")), first["source_ref"]]),
            "board_defaults": board_defaults,
            "arcade": sections.get("properties", {}).get("type") == "arcade" or None,
            "note": "an extension ending in ! is an archive the frontend does not open" if archive else None,
        })
    return rows


# ---------------------------------------------------------------------------
# RetroPie


_ADD_EMULATOR = re.compile(r'^\s*addEmulator\s+(\S+)\s+("[^"]*"|\S+)\s+("[^"]*"|\S+)')
_LIST = re.compile(r'(?:local\s+)?(\w+)=\(([^)]*)\)')
_LOOP = re.compile(r'for (\w+) in (.+?); do')


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
    key = params.get("source", DEFAULT_ROW_SOURCE)
    cfg_path = params["platforms_cfg"]
    cfg = fetcher.text(key, cfg_path)
    exts: dict[str, tuple[str, int]] = {}
    for number, cfg_line in enumerate(cfg.splitlines(), 1):
        match = re.match(r'^([\w-]+)_exts="([^"]*)"', cfg_line)
        if match:
            exts[match.group(1)] = (match.group(2), number)
    platform = PLATFORM_FLAGS[params["platform"]]
    modules: list[dict] = []
    for kind in params["module_dirs"]:
        for path in fetcher.tree(key, f"scriptmodules/{kind}/"):
            if not path.endswith(".sh") or path.count("/") != 2:
                continue
            text = fetcher.text(key, path)
            fields = module_fields(text)
            if not module_enabled(fields.get("flags", "").split(), platform):
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
        refs = [format_ref(key, cfg_path, line)]
        core = None
        if system in defaults:
            core, path, call = defaults[system]
            refs.append(format_ref(key, path, call))
        emulator = "retroarch" if core and core.startswith("lr-") else core
        rows.append({
            "folder": system,
            "extensions": _extensions(raw),
            "core": core,
            "emulator": emulator,
            "source_ref": "; ".join(refs),
        })
    return rows
