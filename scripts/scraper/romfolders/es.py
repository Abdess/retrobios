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

from model.romfolders import DEFAULT_ROW_SOURCE, format_ref
from model.safeparse import parse_untrusted_xml, yaml_load_upstream

from . import Fetcher, SourceError, register


def board_entry(core: str | None, emulator: str | None, source_ref: str) -> dict:
    out = {"core": core or emulator, "emulator": emulator, "source_ref": source_ref}
    return {k: str(v) for k, v in out.items() if v}


def folder_offers(choices: list[dict], core: str | None, emulator: str | None) -> list[dict]:
    """Every (emulator, core) a folder can start, in the list's order, or
    none when the default is the only one.

    A core written under several branches of a device case keeps the
    conditions it is written under, and none once a branch is the `*)` one
    beside another or no branch at all: every build then offers it.
    """
    found: dict[tuple[str, str], dict] = {}
    whens: dict[tuple[str, str], set[str]] = {}
    lines: dict[tuple[str, str], list[str]] = {}
    for choice in choices:
        pair = (str(choice.get("emulator") or ""), str(choice.get("core") or choice.get("emulator") or ""))
        if not pair[1]:
            continue
        whens.setdefault(pair, set()).add(str(choice.get("when") or ""))
        ref = str(choice.get("source_ref") or "")
        if ref and pair in found and found[pair].get("source_ref", "").split(":")[0] == ref.split(":")[0]:
            lines[pair].append(ref.rsplit(":", 1)[-1])
        if pair not in found:
            found[pair] = {k: str(v) for k, v in {**choice, "core": pair[1]}.items()
                           if v and k != "when"}
            lines[pair] = []
    out = []
    for pair, offer in found.items():
        if lines[pair] and offer.get("source_ref"):
            offer["source_ref"] = ",".join([offer["source_ref"], *lines[pair]])
        conditions = whens[pair]
        if "" not in conditions and not (
                len(conditions) > 1 and any(w.endswith(" *") for w in conditions)):
            offer = {**offer, "when": "; ".join(sorted(conditions))}
            offer = {k: offer[k] for k in ("emulator", "core", "when", "source_ref") if k in offer}
        out.append(offer)
    if [(o.get("emulator", ""), o["core"]) for o in out] == [(emulator or "", core or emulator or "")]:
        return []
    return out


def _top_key_lines(text: str) -> dict[str, int]:
    """First line of each top-level YAML key."""
    out: dict[str, int] = {}
    for number, line in enumerate(text.splitlines(), 1):
        match = re.match(r"^([A-Za-z0-9_+.\-]+):", line)
        if match:
            out.setdefault(match.group(1), number)
    return out


def strip_prefix(path: str, prefixes: list[str]) -> str | None:
    """The folder under the roms root, or None for a path outside it."""
    for prefix in prefixes:
        if path.startswith(prefix):
            rest = path[len(prefix):].strip("/\\")
            return rest.replace("\\", "/") or None
    return None


def extension_list(raw: str | list | None) -> list[str]:
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
    key = params.get("source", DEFAULT_ROW_SOURCE)
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
        folder = system.get("path", name)
        if not folder or str(folder).startswith("/"):
            continue
        base = defaults.get(name) or {}
        emulator, core = base.get("emulator"), base.get("core")
        board_defaults: dict[str, dict] = {}
        for board, (data, lines, real) in sorted(boards.items()):
            override = data.get(name) or {}
            b_emu, b_core = override.get("emulator", emulator), override.get("core", core)
            if (b_emu, b_core) != (emulator, core) and b_core:
                board_defaults[board] = board_entry(b_core, b_emu, format_ref(key, real, lines.get(name)))
        refs = [format_ref(key, es_path, es_lines.get(name))]
        if name in def_lines:
            refs.append(format_ref(key, def_path, def_lines[name]))
        rows.append({
            "folder": str(folder),
            "name": name,
            "extensions": extension_list(system.get("extensions")),
            "core": str(core) if core else None,
            "emulator": str(emulator) if emulator else None,
            "source_ref": "; ".join(refs),
            "board_defaults": board_defaults,
            "arcade": system.get("hardware") == "arcade" or None,
        })
    return rows


# ---------------------------------------------------------------------------
# Static es_systems.cfg (XML) and EmuELEC's es_systems.json


def first_lines(text: str, pattern: str) -> dict[str, int]:
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
    key = params.get("source", DEFAULT_ROW_SOURCE)
    rows = _xml_rows(fetcher.text(key, params["file"]), key, params["file"], params)
    for board, path in sorted((params.get("boards") or {}).items()):
        other = {r["name"]: r for r in _xml_rows(fetcher.text(key, path), key, path, params)}
        for row in rows:
            alt = other.get(row["name"])
            if alt and alt["core"] and (alt["core"], alt["emulator"]) != (row["core"], row["emulator"]):
                row.setdefault("board_defaults", {})[board] = board_entry(
                    alt["core"], alt["emulator"], alt["source_ref"])
    return rows


_BARE_AMPERSAND = re.compile(r"&(?!(?:[A-Za-z]+|#\d+|#x[0-9A-Fa-f]+);)")
_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)


def lenient_xml(text: str) -> str:
    """The list as EmulationStation's pugixml reads it, lines kept in place.

    pugixml keeps a bare `&` as text (ArkOS ships `2>&1` in a command) and
    accepts `--` inside a comment (EmuDeck comments out a command holding
    `--no-gui`). A comment is blanked to its newlines, so a system left in
    a comment neither parses nor lends its line to a citation.
    """
    text = _COMMENT.sub(lambda m: "\n" * m.group(0).count("\n"), text)
    return _BARE_AMPERSAND.sub("&amp;", text)


def _xml_rows(text: str, key: str, path: str, params: dict) -> list[dict]:
    text = lenient_xml(text)
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
        folder = strip_prefix((system.findtext("path") or "").strip(), params["path_prefixes"])
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
            "extensions": extension_list(system.findtext("extension")),
            "core": core or emulator,
            "emulator": emulator,
            "source_ref": format_ref(key, path, row["line"]),
            "offers": folder_offers(
                [{"emulator": e, "core": c} for e, cores in emulators for c, _d in cores or [(e, False)]],
                core, emulator),
            "arcade": _is_arcade(system.findtext("hardware"), platform),
            "note": row.get("note"),
        })
    return rows


@register("es-json")
def es_json(spec: dict, fetcher: Fetcher) -> list[dict]:
    params = spec["params"]
    key = params.get("source", DEFAULT_ROW_SOURCE)
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
        folder = strip_prefix(system.get("path") or "", params["path_prefixes"])
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
            "extensions": extension_list(system.get("extensions")),
            "core": core or emulator,
            "emulator": emulator,
            "source_ref": format_ref(key, path, row["line"]),
            "offers": folder_offers(
                [{"emulator": e, "core": c} for e, cores in emulators for c, _d in cores or [(e, False)]],
                core, emulator),
            "arcade": _is_arcade(system.get("hardware"), system.get("platform")),
            "note": row.get("note"),
        })
    return rows
