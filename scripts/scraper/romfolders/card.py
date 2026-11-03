"""Rom folder parsers for handheld card OSes and the frontends without a menu.

Each parser reads the system list the OS ships at the pinned commit and
returns one row per folder, in the OS's own spelling:

- `onion`: Onion's optional packages, `Emu/<SYS>/config.json` and the
  `launch.sh` beside it. RetroArch-section packages (`RApp/`) add cores on the
  same folder, the stock menu starts the `Emu/` one.
- `spruce`: spruceOS `Emu/<SYS>/config.json`, `default_emulator`.
- `crossmix`: CrossMix-OS `Emus/<SYS>/config.json`, first `launchlist` entry
  with a script, as `load_launcher.sh` picks it.
- `koriki`: SimpleMenu section groups, first launcher of `execs`.
- `allium`: Allium `consoles.toml`, first entry of `cores`.
- `minui`: MinUI, MyMinUI and NextUI paks. A Roms folder starts the pak named
  by the text in its last parentheses (`getEmuName`), so the folder of a row
  is the one the skeleton ships, else the tag alone.
- `plumos`: plumOS `systems.json`, `directory_aliases` by priority.
- `muos`: muOS `core.json`, every `friendly` name of a system.
- `gmenu2x`: MiyooCFW, the folders its image ships and the gmenu2x links
  whose text a repository holds.
- `mister`: MiSTer, one `games/<core>/` folder per core the distribution ships.
- `romm`: RomM, one library folder per platform slug it plays or keeps BIOS for.
- `bizhawk`: BizHawk's per-system base folders.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from configparser import ConfigParser
from pathlib import PurePosixPath

from . import Fetcher, SourceError, register

_LIBRETRO = re.compile(r"([A-Za-z0-9_+.\-${}]+?)_libretro\.so")
_EMU_EXE = re.compile(r"^\s*EMU_EXE=[\"']?([A-Za-z0-9_+.\-]+)", re.M)


def line_of(text: str, needle: str, start: int = 0) -> int:
    """1-based line of the first needle at or after start, 0 when absent."""
    idx = text.find(needle, start)
    return text.count("\n", 0, idx) + 1 if idx >= 0 else 0


def ref(key: str, path: str, line: int | str | None = None) -> str:
    """A source_ref part. A space in a path is written %20, as in a URL:
    the ref grammar ends a path at the first space."""
    path = path.replace("%", "%25").replace(" ", "%20")
    return f"{key} {path}:{line}" if line else f"{key} {path}"


def extensions(raw: str | Iterable[str] | None) -> list[str]:
    """Lowercased extensions with the dot, from a list or a `|`/`,` string."""
    items = re.split(r"[|,]", raw) if isinstance(raw, str) else list(raw or [])
    out: list[str] = []
    for item in items:
        ext = str(item).strip().lower().lstrip(".")
        if ext and f".{ext}" not in out:
            out.append(f".{ext}")
    return out


def _shell_value(script: str, name: str) -> str | None:
    match = re.search(rf"^\s*{re.escape(name)}=[\"']?([A-Za-z0-9_+.\-]+)", script, re.M)
    return match.group(1) if match else None


def libretro_core(script: str) -> str | None:
    """The core a launch script names: `<core>_libretro.so`, a shell variable
    assigned in the same script, or `EMU_EXE=`."""
    for match in _LIBRETRO.finditer(script):
        name = match.group(1).split("/")[-1]
        if "$" not in name:
            return name
        var = re.fullmatch(r"\$\{?(\w+)\}?", name)
        if var:
            value = _shell_value(script, var.group(1))
            if value:
                return value
    exe = _EMU_EXE.search(script)
    return exe.group(1) if exe else None


def _json(fetcher: Fetcher, key: str, path: str) -> tuple[dict, str]:
    text = fetcher.text(key, path)
    try:
        return json.loads(text), text
    except ValueError as exc:
        raise SourceError(f"{path}: {exc}") from exc


def _rompath_folder(rompath: str) -> str:
    """The folder under Roms/ a stock-menu config.json points at."""
    path = rompath.strip().replace("\\", "/")
    for prefix in ("../../Roms/", "/mnt/SDCARD/Roms/"):
        if path.startswith(prefix):
            return path[len(prefix):].strip("/")
    raise SourceError(f"rompath {rompath!r} is not under Roms/")


# Onion

@register("onion")
def parse_onion(spec: dict, fetcher: Fetcher) -> list[dict]:
    params = spec["params"]
    key = params["source"]
    pattern = re.compile(r"^static/packages/(Emu|RApp)/([^/]+)/\1/([^/]+)/config\.json$")
    packages: dict[str, list[dict]] = {}
    for path in fetcher.tree(key, "static/packages/"):
        match = pattern.match(path)
        if not match:
            continue
        layer, package = match.group(1), match.group(2)
        config, text = _json(fetcher, key, path)
        script_path = f"{path.rsplit('/', 1)[0]}/{config.get('launch', 'launch.sh')}"
        script = fetcher.optional_text(key, script_path) or ""
        packages.setdefault(_rompath_folder(config.get("rompath", "")), []).append({
            "layer": layer, "package": package, "config": config,
            "core": libretro_core(script), "ref": ref(key, path, line_of(text, '"rompath"')),
            "script": script_path,
        })
    rows = []
    for folder, found in packages.items():
        found.sort(key=lambda p: (p["layer"] != "Emu", p["package"]))
        emu = [p for p in found if p["layer"] == "Emu"]
        first = emu[0] if emu else found[0]
        others = [p["package"] for p in found if p is not first]
        row = {
            "folder": folder,
            "extensions": extensions(first["config"].get("extlist")),
            "source_ref": first["ref"],
        }
        if emu:
            row["core"] = first["core"]
            row["emulator"] = "retroarch" if first["core"] else "standalone"
            note = f"package '{first['package']}' (Emu/, the stock menu entry)"
            if not first["core"]:
                note += f", launches {first['script']}"
        else:
            note = "only RetroArch-section packages (RApp/), the user picks the core"
        if others:
            note += f". Other packages on this folder: {', '.join(others)}"
        row["note"] = note
        rows.append(row)
    return rows


# spruceOS

@register("spruce")
def parse_spruce(spec: dict, fetcher: Fetcher) -> list[dict]:
    params = spec["params"]
    key = params["source"]
    skip = set(params.get("skip", []))
    rows = []
    for path in fetcher.tree(key, "Emu/"):
        parts = path.split("/")
        if len(parts) != 3 or parts[2] != "config.json" or parts[1] in skip:
            continue
        config, text = _json(fetcher, key, path)
        notes = []
        if config.get("devices"):
            notes.append(f"only on devices {', '.join(map(str, config['devices']))}")
        if config.get("ignoreList"):
            notes.append(f"ignoreList {', '.join(map(str, config['ignoreList']))}")
        rows.append({
            "folder": parts[1],
            "aliases": [str(a) for a in config.get("alternativeFolderNames") or []],
            "extensions": extensions(config.get("extlist")),
            "core": config.get("default_emulator"),
            "source_ref": ref(key, path, line_of(text, '"default_emulator"') or 1),
            "note": ". ".join(notes),
        })
    return rows


# CrossMix-OS

@register("crossmix")
def parse_crossmix(spec: dict, fetcher: Fetcher) -> list[dict]:
    params = spec["params"]
    key = params["source"]
    rows = []
    for path in fetcher.tree(key, "Emus/"):
        parts = path.split("/")
        if len(parts) != 3 or parts[2] != "config.json" or parts[1].startswith("_"):
            continue
        config, text = _json(fetcher, key, path)
        launchers = [e for e in config.get("launchlist") or [] if e.get("launch")]
        script_name = launchers[0]["launch"] if launchers else config.get("launch", "launch.sh")
        script_path = f"Emus/{parts[1]}/{script_name}"
        script = fetcher.optional_text(key, script_path) or ""
        core = libretro_core(script)
        note = f"default launcher {launchers[0].get('name') if launchers else script_name} ({script_path})"
        folder = _rompath_folder(config.get("rompath", ""))
        rows.append({
            "folder": folder,
            "name": parts[1] if parts[1] != folder else None,
            "extensions": extensions(config.get("extlist")),
            "core": core,
            "emulator": "retroarch" if core else "standalone",
            "source_ref": ref(key, path, line_of(text, '"rompath"') or 1),
            "note": note if core else f"{note}, names no libretro core",
        })
    return rows


# Koriki

@register("koriki")
def parse_koriki(spec: dict, fetcher: Fetcher) -> list[dict]:
    params = spec["params"]
    key = params["source"]
    path = params["sections"]
    text = fetcher.text(key, path)
    parser = ConfigParser(interpolation=None, strict=False)
    parser.optionxform = str  # type: ignore[assignment]
    parser.read_string(text)
    skip = set(params.get("skip", []))
    rows = []
    for section in parser.sections():
        if section in skip:
            continue
        body = parser[section]
        dirs = [d.strip() for d in body.get("romDirs", "").split(",") if d.strip()]
        if not dirs:
            continue
        rel = [d.replace(params["roms_prefix"], "").strip("/") for d in dirs]
        execs = [PurePosixPath(e.strip()).name for e in body.get("execs", "").split(",") if e.strip()]
        core = None
        if execs:
            launcher = fetcher.optional_text(key, f"{params['launchers']}/{execs[0]}")
            core = libretro_core(launcher or "")
        note = f"launchers {', '.join(execs)}"
        if len(rel) > 1 or "/" in rel[0]:
            note += f". romDirs {', '.join(rel)}"
        rows.append({
            "folder": rel[0].split("/")[0],
            "name": section,
            "extensions": extensions(body.get("romExts")),
            "core": core or (execs[0] if execs else None),
            "emulator": "retroarch" if core else "standalone",
            "source_ref": ref(key, path, line_of(text, f"[{section}]")),
            "note": note,
        })
    return rows


# Allium

_TOML_KEY = r'(?:"[^"]*"|[A-Za-z0-9_\-]+)'


def _toml_value(raw: str) -> object:
    raw = raw.strip()
    if raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    if raw.startswith("["):
        return re.findall(r'"([^"]*)"', raw)
    if raw in ("true", "false"):
        return raw == "true"
    if re.fullmatch(r"-?\d+", raw):
        return int(raw)
    raise SourceError(f"TOML value {raw!r} is outside the subset Allium's files use")


def parse_toml_subset(text: str) -> dict:
    """The TOML Allium writes: `[[array]]`, `[a.b]` tables, string, integer,
    boolean and string-array values, arrays that may span lines. Anything
    else is refused rather than guessed. Each table records the line it
    starts on under `__line__`."""
    root: dict = {}
    current: dict = root
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].split("#", 1)[0].strip() if '"' not in lines[i] else lines[i].strip()
        i += 1
        if not line or line.startswith("#"):
            continue
        if line.startswith("[["):
            name = line.strip("[]").strip()
            current = {"__line__": i}
            root.setdefault(name, []).append(current)
            continue
        if line.startswith("["):
            current = root
            for part in re.findall(_TOML_KEY, line.strip("[]")):
                current = current.setdefault(part.strip('"'), {})
            current["__line__"] = i
            continue
        match = re.match(rf"({_TOML_KEY})\s*=\s*(.*)$", line)
        if not match:
            raise SourceError(f"TOML line {i}: {line!r} is outside the subset Allium's files use")
        value = match.group(2)
        while value.count("[") > value.count("]") and i < len(lines):
            value += lines[i].strip()
            i += 1
        current[match.group(1).strip('"')] = _toml_value(value)
    return root


@register("allium")
def parse_allium(spec: dict, fetcher: Fetcher) -> list[dict]:
    params = spec["params"]
    key = params["source"]
    consoles = parse_toml_subset(fetcher.text(key, params["consoles"]))["consoles"]
    cores = parse_toml_subset(fetcher.text(key, params["cores"])).get("cores", {})
    rows = []
    for console in consoles:
        patterns = [str(p) for p in console.get("patterns") or []]
        if not patterns:
            continue
        first = (console.get("cores") or [None])[0]
        core_def = cores.get(first, {}) if first else {}
        core = core_def.get("retroarch") if isinstance(core_def, dict) else None
        rows.append({
            "folder": patterns[0],
            "name": console["name"],
            "aliases": patterns[1:],
            "extensions": extensions(console.get("extensions")),
            "core": core or first,
            "emulator": "retroarch" if core else "standalone",
            "source_ref": ref(key, params["consoles"], console["__line__"]),
            "note": "a folder named any pattern, or ending in '(<pattern>)', is this console. A file's own extension wins over its folder",
        })
    return rows


# MinUI, MyMinUI, NextUI

_PAK = re.compile(r"^skeleton/(?:[^/]+/)+(?:Emus|paks/Emus)/(?:[^/]+/)?([^/]+)\.pak/launch\.sh$")


def _pak_device(path: str) -> str:
    """The device directory a pak sits under (`Emus/<device>/X.pak`,
    `SYSTEM/<device>/paks/Emus/X.pak`)."""
    parts = path.split("/")
    if "paks" in parts:
        return parts[parts.index("paks") - 1]
    idx = parts.index("Emus")
    return parts[idx + 1] if not parts[idx + 1].endswith(".pak") else parts[1]


@register("minui")
def parse_minui(spec: dict, fetcher: Fetcher) -> list[dict]:
    params = spec["params"]
    key = params["source"]
    tree = fetcher.tree(key, "skeleton/")
    shipped: dict[str, str] = {}
    for path in tree:
        match = re.match(r"^skeleton/[^/]+/Roms/([^/]+)/", path)
        if match:
            name = match.group(1)
            tag = re.search(r"\(([^()]*)\)\s*$", name)
            shipped.setdefault(tag.group(1) if tag else name, name)
    paks: dict[str, dict[str, tuple[str, str]]] = {}
    for path in tree:
        match = _PAK.match(path)
        if not match:
            continue
        script = fetcher.text(key, path)
        core = libretro_core(script)
        line = line_of(script, "EMU_EXE=") or line_of(script, "_libretro.so") or 1
        paks.setdefault(match.group(1), {})[_pak_device(path)] = (core or "", ref(key, path, line))
    rows = []
    for tag, devices in sorted(paks.items()):
        counts: dict[str, int] = {}
        for core, _ in devices.values():
            counts[core] = counts.get(core, 0) + 1
        core = min(counts, key=lambda c: (-counts[c], c == "", c))
        default_ref = next(r for c, r in sorted(devices.values()) if c == core)
        boards = {
            device: {"core": c, "source_ref": r}
            for device, (c, r) in sorted(devices.items()) if c != core and c
        }
        folder = shipped.get(tag, tag)
        rows.append({
            "folder": folder,
            "name": tag,
            "aliases": [tag] if folder != tag else [],
            "core": core or None,
            "emulator": "minarch" if core else "standalone",
            "source_ref": default_ref,
            "board_defaults": boards,
            "note": (f"any folder named {tag} or ending in '({tag})' starts {tag}.pak. "
                     f"Devices: {', '.join(sorted(devices))}"),
        })
    return rows


# plumOS

@register("plumos")
def parse_plumos(spec: dict, fetcher: Fetcher) -> list[dict]:
    params = spec["params"]
    key = params["source"]
    text = fetcher.text(key, params["path"])
    systems = json.loads(text)["systems"]
    taken: dict[str, str] = {}
    rows = []
    pos = 0
    for system in systems:
        needle = f'"id": "{system["id"]}"'
        line = line_of(text, needle, pos)
        pos = max(pos, text.find(needle, pos) + 1)
        aliases = [a["name"] for a in sorted(system.get("directory_aliases") or [],
                                             key=lambda a: a.get("priority", 0))]
        free = [a for a in aliases if a not in taken]
        if not free:
            continue
        folder = free[0]
        taken[folder] = system["id"]
        kind, _, core = (system.get("default_launch_profile") or "").partition(":")
        notes = [] if system.get("enabled") else ["disabled by default"]
        shared = [f"{a} (also {taken[a]})" for a in aliases if a in taken and taken[a] != system["id"]]
        if shared:
            notes.append(f"shares {', '.join(shared)}, the extension decides")
        rows.append({
            "folder": folder,
            "name": system["id"],
            "aliases": [a for a in aliases if a != folder],
            "extensions": extensions(system.get("extensions")),
            "core": core or None,
            "emulator": kind or None,
            "source_ref": ref(key, params["path"], line),
            "note": ". ".join(notes),
        })
    return rows


# muOS

def _muos_norm(name: str) -> str:
    """The key muOS looks a folder up by (common.c: lowercase, drop ' -_+')."""
    return re.sub(r"[ \-_+]", "", name.lower())


@register("muos")
def parse_muos(spec: dict, fetcher: Fetcher) -> list[dict]:
    params = spec["params"]
    key = params["source"]
    text = fetcher.text(key, params["path"])
    data = json.loads(text)
    rows = []
    for system, entry in data.items():
        friendly = [str(f) for f in entry.get("friendly") or []]
        if not friendly:
            continue
        want = _muos_norm(entry.get("catalogue") or system)
        folder = next((f for f in friendly if f == want), friendly[0])
        default = entry.get("default")
        libretro = entry.get("libretro") or {}
        so = (libretro.get(default) or {}).get("core") if default in libretro else None
        core = so[: -len("_libretro.so")] if so and so.endswith("_libretro.so") else default
        rows.append({
            "folder": folder,
            "name": system,
            "aliases": friendly,
            "core": core,
            "emulator": "retroarch" if so else "external",
            "source_ref": ref(key, params["path"], line_of(text, json.dumps(system) + ":")),
            "note": "a folder matches when its name, lowercased without ' -_+', is one of the friendly names",
        })
    return rows


# MiyooCFW

@register("gmenu2x")
def parse_gmenu2x(spec: dict, fetcher: Fetcher) -> list[dict]:
    params = spec["params"]
    rows: dict[str, dict] = {}
    for link in params.get("links", []):
        text = fetcher.text(link["source"], link["path"])
        fields = dict(
            line.split("=", 1) for line in text.splitlines() if "=" in line
        )
        selector = fields.get("selectordir", "").rstrip("/")
        prefix = params["link_roms_prefix"]
        if not selector.startswith(prefix):
            raise SourceError(f"{link['path']}: selectordir {selector!r} is not under {prefix}")
        folder = selector[len(prefix):].strip("/")
        rows[folder] = {
            "folder": folder,
            "extensions": extensions(fields.get("selectorfilter")),
            "core": link["core"],
            "emulator": "standalone",
            "source_ref": ref(link["source"], link["path"], line_of(text, "selectordir=")),
            "note": f"gmenu2x link of the {link['core']} package",
        }
    key = params["source"]
    for path in fetcher.tree(key, params["shipped_roms"] + "/"):
        folder = path[len(params["shipped_roms"]) + 1:].split("/")
        if len(folder) < 2 or folder[0] in rows:
            continue
        rows[folder[0]] = {
            "folder": folder[0],
            "source_ref": ref(key, f"{params['shipped_roms']}/{folder[0]}"),
            "note": "folder the image ships. Its emulator link lives in a release package no repository holds",
        }
    return list(rows.values())


# MiSTer

@register("mister")
def parse_mister(spec: dict, fetcher: Fetcher) -> list[dict]:
    params = spec["params"]
    key = params["source"]
    arcade = set(params.get("arcade", []))
    folders = sorted({p.split("/")[1] for p in fetcher.tree(key, "games/") if p.count("/") >= 2})
    return [
        {
            "folder": folder,
            "emulator": "mister-core",
            "source_ref": ref(key, f"games/{folder}/"),
            "arcade": folder in arcade or None,
            "note": params["arcade_note"] if folder in arcade else None,
        }
        for folder in folders
        if folder not in params.get("skip", [])
    ]


# RomM

@register("romm")
def parse_romm(spec: dict, fetcher: Fetcher) -> list[dict]:
    params = spec["params"]
    key = params["source"]
    text = fetcher.text(key, params["cores_map"])
    lines = text.splitlines()
    maps: dict[str, dict[str, tuple[list[str], int]]] = {}
    block = None
    entry = None
    for number, line in enumerate(lines, 1):
        start = re.match(r"const (_EJS_(?:NIGHTLY_)?CORES_MAP)\b", line)
        if start:
            block = start.group(1)
            continue
        if block and line.startswith("}"):
            block = None
            continue
        if not block:
            continue
        head = re.match(r'\s+"?([\w-]+)"?:\s*\[(.*)$', line)
        if head:
            entry = (head.group(1), number)
            maps.setdefault(block, {})[entry[0]] = (re.findall(r'"([\w-]+)"', head.group(2)), number)
            if "]" in head.group(2):
                entry = None
        elif entry:
            maps[block][entry[0]][0].extend(re.findall(r'"([\w-]+)"', line))
            if "]" in line:
                entry = None
    stable = maps.get("_EJS_CORES_MAP", {})
    nightly = maps.get("_EJS_NIGHTLY_CORES_MAP", {})
    if not stable:
        raise SourceError(f"{params['cores_map']}: _EJS_CORES_MAP not found")
    bios = json.loads(fetcher.text(key, params["bios_fixture"]))
    bios_slugs = {name.split(":", 1)[0] for name in bios}
    rows = []
    for slug in sorted(set(stable) | set(nightly) | bios_slugs):
        found = stable.get(slug) or nightly.get(slug)
        if found:
            note = None if slug in stable else "core only with EmulatorJS nightly cores"
            rows.append({"folder": slug, "core": found[0][0], "emulator": "emulatorjs",
                         "source_ref": ref(key, params["cores_map"], found[1]), "note": note})
        else:
            rows.append({"folder": slug, "source_ref": ref(key, params["bios_fixture"]),
                         "note": "no EmulatorJS core, RomM keeps BIOS for it"})
    return rows


# BizHawk

@register("bizhawk")
def parse_bizhawk(spec: dict, fetcher: Fetcher) -> list[dict]:
    params = spec["params"]
    key = params["source"]
    entries = fetcher.text(key, params["paths"])
    loader = fetcher.text(key, params["rom_loader"])
    config = fetcher.text(key, params["config"])
    combined = {
        m.group(1): re.findall(r"VSystemID\.Raw\.(\w+)", m.group(2))
        for m in re.finditer(r"string (COMBINED_SYSIDS_\w+) = string\.Join\(\"_\", ([^)]*)\)", entries)
    }
    ext_fields: dict[str, tuple[list[str], int]] = {}
    for number, line in enumerate(loader.splitlines(), 1):
        clean = re.sub(r"/\*.*?\*/", "", line)
        match = re.search(r"IReadOnlyCollection<string> (\w+) = new\[\] \{ (.*?) \}", clean)
        if match:
            ext_fields[match.group(1)] = (re.findall(r'"([^"]+)"', match.group(2)), number)
    preferred: dict[str, str] = {}
    picker = config[config.find("CorePickerUIData"):]
    for match in re.finditer(r"\(\[([^\]]+)\],\s*\[\s*CoreNames\.(\w+)", picker):
        for sid in re.findall(r"VSystemID\.Raw\.(\w+)", match.group(1)):
            preferred.setdefault(sid, match.group(2))
    rows = []
    for number, line in enumerate(entries.splitlines(), 1):
        match = re.search(
            r"CommonEntriesFor\((?:VSystemID\.Raw\.(\w+)|(COMBINED_SYSIDS_\w+)), "
            r"basePath: Path\.Combine\(\"\.\", \"([^\"]+)\"\)", line)
        if not match:
            continue
        sids = [match.group(1)] if match.group(1) else combined.get(match.group(2), [])
        exts: list[str] = []
        refs = [ref(key, params["paths"], number)]
        for sid in sids:
            if sid in ext_fields:
                exts.extend(ext_fields[sid][0])
                refs.append(ref(key, params["rom_loader"], ext_fields[sid][1]))
        cores = [preferred[s] for s in sids if s in preferred]
        note = "the open dialog starts here, nothing is scanned"
        if cores:
            note += f". Default core {cores[0]} (CorePickerUIData, CoreNames[0])"
        rows.append({
            "folder": match.group(3),
            "name": sids[0] if sids else None,
            "aliases": sids[1:],
            "extensions": extensions(exts),
            "emulator": "EmuHawk",
            "source_ref": "; ".join(refs),
            "note": note,
        })
    return rows
