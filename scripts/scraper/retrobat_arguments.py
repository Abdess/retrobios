"""RetroBat generators that hand a BIOS path on the command line or a folder beside the binary."""

from __future__ import annotations

import re

from .csharp_source import (
    LauncherPatternMissing,
    Record,
    STRING,
    Source,
    _call_args,
    _code,
    _method_of,
    _statement_start,
    _unescape,
    source_ref,
)
from .retrobat_generators import FEATURES, GENERATORS, launcher_record, system_feature_choices
from .retrobat_render import covered_records, path_parts, render, when


def _argument_paths(src: Source, emulator: str, build: str) -> list[tuple[Record, list[str]]]:
    """commandArray.Add(<path under bios>) after its flag, with its conditions."""
    code = _code(src)
    found = []
    for add in re.finditer(r"commandArray\.Add\(", code):
        expr = _call_args(src, add.end() - 1)
        end = add.end() + len(expr) + 1
        if re.fullmatch(STRING, expr.strip()):
            continue
        method = _method_of(src, add.start())
        rendered = render(src, expr, method[0], add.start())
        if rendered is None or not rendered[0].startswith("bios"):
            continue
        flags = list(re.finditer(r'"(-[\w-]+)"', code[method[0] : add.start()]))
        if not flags:
            raise LauncherPatternMissing(src.path, f"flag before line {src.line(add.start())}")
        flag_at = method[0] + flags[-1].start()
        conditions, returns = when(src, add.start())
        found.append(
            (
                launcher_record(
                    emulator,
                    build,
                    "passes_path",
                    [],
                    path_parts(
                        src,
                        *returns,
                        *rendered[1],
                        src.lines(flag_at, flag_at + 1),
                        src.lines(_statement_start(src, add.start()), end),
                    ),
                    search_dir=rendered[0],
                    passes_to=f"command line {flags[-1].group(1)} {rendered[0]}",
                    fails_when_missing=False,
                ),
                conditions,
            )
        )
    return found


def _with_conditions(record: Record, conditions: list[str]) -> Record:
    out = {key: value for key, value in record.items() if key != "source_ref"}
    if conditions:
        out["depends_on_option"] = ", ".join(conditions)
    out["source_ref"] = record["source_ref"]
    return out


_BIOS_GUARD = r'string\.IsNullOrEmpty\(AppConfig\["bios"\]\)'


def mame(sources: dict[str, Source]) -> list[Record]:
    """MAME folders: the standalone build's own, and those of the MESS systems
    that the standalone build and the libretro core share."""
    own = sources[f"{GENERATORS}/Mame64.Generator.cs"]
    found = _argument_paths(own, "mame64", "standalone")
    if not found:
        raise LauncherPatternMissing(own.path, "MAME folder arguments")
    records = covered_records(
        own,
        [
            split
            for record, conditions in found
            for split in _per_emulator(own, _with_conditions(record, conditions))
        ],
        # The bezel artwork folder is read by the launcher, not passed.
        skip=(_BIOS_GUARD, r"ConfigureBezels\("),
    )
    mess = sources[f"{GENERATORS}/MessSystem.cs"]
    found = _argument_paths(mess, "mame64", "standalone")
    if not found:
        raise LauncherPatternMissing(mess.path, "MESS folder arguments")
    shared = []
    for record, conditions in found:
        if "standalone" in conditions:
            shared.append(_with_conditions(record, [c for c in conditions if c != "standalone"]))
            continue
        shared.append(_with_conditions(record, conditions))
        libretro = dict(record, emulator="mame", build="libretro", names=[])
        shared.append(_with_conditions(libretro, conditions))
    return records + covered_records(
        mess,
        shared,
        # The softlist file and the Lua autoboot script are named after the game.
        skip=(
            _BIOS_GUARD,
            r'"hash", (?:SystemConfig\["force_softlist"\]|romMedia) \+ "\.xml"',
            r'"autoboot_scripts"',
        ),
    )


def psxmame(sources: dict[str, Source]) -> list[Record]:
    src = sources[f"{GENERATORS}/PSXMame.Generator.cs"]
    found = _argument_paths(src, "psxmame", "standalone")
    if not found:
        raise LauncherPatternMissing(src.path, "rompath argument")
    return covered_records(src, [_with_conditions(record, conditions) for record, conditions in found])


def xroar(sources: dict[str, Source]) -> list[Record]:
    src = sources[f"{GENERATORS}/Xroar.Generator.cs"]
    found = _argument_paths(src, "xroar", "standalone")
    if not found:
        raise LauncherPatternMissing(src.path, "rompath argument")
    records = [
        split
        for record, conditions in found
        for split in _per_system(src, _with_conditions(record, conditions))
    ]
    # The machines ES offers under a system the folder is chosen for: XRoar
    # runs a CoCo 3 for coco, so its ROMs are read from that system's folder.
    features = sources[FEATURES]
    for record in records:
        systems = record.get("systems")
        if not isinstance(systems, list) or not systems:
            continue
        machines: list[str] = []
        lines = []
        for system in systems:
            choices, span = system_feature_choices(features, "xroar", "xroar_machine", system)
            machines += [m for m in choices if m not in machines]
            lines.append(span)
        record["machines"] = machines
        ref = record.pop("source_ref")
        record["source_ref"] = f"{ref}, {source_ref((features.path, lines))}"
    line = src.find(r'string (\w+) = ("rompath (?:[^"\\\n]|\\.)*");', "config rompath line")
    written = _unescape(line.group(2)[1:-1])
    relative = re.fullmatch(r'rompath "(.*)"', written)
    method = _method_of(src, line.start())
    setup = src.find(r'string setupPath = Path\.Combine\(path, "([^"]+)"\);', "xroar config file")
    use = src.find(rf"lines\[i\] = {line.group(1)};", "rompath replacement", line.end(), method[1])
    parts = [p for p in re.split(r"\\+", relative.group(1) if relative else "") if p]
    if "bios" not in parts:
        raise LauncherPatternMissing(src.path, "bios in the config rompath")
    records.append(
        launcher_record(
            "xroar",
            "standalone",
            "passes_path",
            [],
            path_parts(
                src, src.lines(line.start(), line.end()), src.lines(use.start(), use.end())
            ),
            search_dir="/".join(parts[parts.index("bios") :]),
            passes_to=f"{setup.group(1)} {written}",
            fails_when_missing=False,
        )
    )
    return covered_records(src, records)


_EMULATOR_BRANCH = re.compile(r"([^\s;<>]+) when (\w+), else ([^\s;<>]+)")


def _per_emulator(src: Source, record: Record) -> list[Record]:
    """A directory chosen by the emulator the generator runs, one record each.

    Mame64.Generator.cs sets `bool hbmame = emulator == "hbmame";` and passes
    `-sp bios/hbmame/samples` for it, bios/mame/samples for mame64. A choice
    on any other condition is left as it reads.
    """
    rendered = str(record.get("search_dir", ""))
    branch = _EMULATOR_BRANCH.fullmatch(rendered)
    if branch is None:
        return [record]
    chosen, flag, default = branch.groups()
    declared = re.search(rf'bool {flag} = emulator == "([\w.-]+)";', _code(src))
    if declared is None:
        return [record]
    ref = str(record["source_ref"])
    if not ref.startswith(src.path + ":"):
        raise LauncherPatternMissing(src.path, f"source of the directory choice {rendered!r}")
    spans = [
        (int(first), int(last or first))
        for first, _, last in (s.partition("-") for s in ref[len(src.path) + 1:].split(", "))
    ]
    spans.append(src.lines(declared.start(), declared.end()))
    prefix = str(record["passes_to"]).removesuffix(rendered).strip()
    out = []
    for emulator, directory in ((declared.group(1), chosen), (record["emulator"], default)):
        split = {k: v for k, v in record.items() if k != "source_ref"}
        split.update(emulator=emulator, search_dir=directory, passes_to=f"{prefix} {directory}")
        split["source_ref"] = path_parts(src, *spans)
        out.append(split)
    return out


_SYSTEM_BRANCH = re.compile(r'(\S+), or (\S+) when system == "([\w.-]+)"')


def _per_system(src: Source, record: Record) -> list[Record]:
    """A directory chosen by the system, one record per choice.

    `romPath = <a>; if (system == "coco") romPath = <b>;` renders as "<a>, or
    <b> when system == "coco"": <b> is passed for that system, <a> for every
    other one.
    """
    rendered = str(record.get("search_dir", ""))
    branch = _SYSTEM_BRANCH.fullmatch(rendered)
    if branch is None:
        if " or " in rendered:
            raise LauncherPatternMissing(src.path, f"directory choice {rendered!r}")
        return [record]
    default, chosen, system = branch.groups()
    flag = str(record["passes_to"]).removesuffix(rendered).strip()
    names = record["names"]
    if not isinstance(names, list):
        raise LauncherPatternMissing(src.path, "names of a directory choice")
    out = []
    for directory, systems in ((default, None), (chosen, [system])):
        split = {k: v for k, v in record.items() if k != "source_ref"}
        split.update(
            names=list(names), search_dir=directory, passes_to=f"{flag} {directory}"
        )
        if systems:
            split["systems"] = systems
        split["source_ref"] = record["source_ref"]
        out.append(split)
    return out


# Generators that start an emulator with a portable data folder beside its
# binary: (generator, emulator key, binary, the code's name for the folder).
PORTABLE_USERS = (
    ("Citron.Generator.cs", "citron", "citron.exe", "PORTABLE_DIR"),
    ("Eden.Generator.cs", "eden", "eden.exe", "PORTABLE_DIR"),
    ("Ryujinx.Generator.cs", "ryujinx", "Ryujinx.exe", "DefaultPortableDir"),
    ("ShadPS4.Generator.cs", "shadps4", "shadPS4.exe", "PORTABLE_DIR"),
    ("Sudachi.Generator.cs", "sudachi", "sudachi.exe", "PORTABLE_DIR"),
    ("Yuzu.Generator.cs", "yuzu", "yuzu.exe", "PORTABLE_DIR"),
)
_EMULATOR_FOLDER = (
    r"GetEmulatorPathAndExe\(emulator, out string path, out string exe, \"[^\"]+\"\)"
    r"|string path = AppConfig\.GetFullPath\((?:emulator(?:\.Replace\(\"-\", \" \"\))?"
    r"|\"\w+\")\);"
)
_PORTABLE_FOLDER = r'string (userFolder|setupPath) = Path\.Combine\(path, "(\w+)"\);'
# Ryujinx's generator hands --root-data-dir saves/switch/ryujinx/portable
# instead when that folder exists.
_ALTERNATE_ROOT = (
    r'string portablePath = Path\.Combine\(AppConfig\.GetFullPath\("saves"\), "switch", '
    r'"ryujinx", "portable"\);'
)


def portable_users(sources: dict[str, Source]) -> list[Record]:
    """The portable data folder a generator gives an emulator beside its binary.

    The emulator folder comes from AppConfig.GetFullPath, and the generator
    creates or configures <folder>/user (<folder>/portable for Ryujinx)
    before launching: the emulator then keeps its data there (keys/,
    sys_modules/, system/) in place of %APPDATA%.
    """
    records = []
    for name, emulator, binary, handle in PORTABLE_USERS:
        src = sources[f"{GENERATORS}/{name}"]
        found = src.find(_EMULATOR_FOLDER, f"{emulator} folder")
        folder = src.find(_PORTABLE_FOLDER, "portable folder")
        spans = [src.lines(found.start(), found.end()), src.lines(folder.start(), folder.end())]
        if folder.group(1) == "userFolder":
            create = src.find(
                r"Directory\.CreateDirectory\(userFolder\)", "user folder creation", folder.end()
            )
            spans[-1] = src.lines(folder.start(), create.end())
        depends = None
        alternate = re.search(_ALTERNATE_ROOT, src.text)
        if alternate:
            spans.append(src.lines(alternate.start(), alternate.end()))
            depends = "unless saves/switch/ryujinx/portable exists, passed with -r"
        records.append(launcher_record(
            emulator,
            "standalone",
            "passes_path",
            [],
            source_ref((src.path, spans)),
            search_dir=f'<AppConfig.GetFullPath("{emulator}")>/{folder.group(2)}',
            passes_to=f"{handle}, the portable folder beside {binary}",
            fails_when_missing=False,
            depends_on_option=depends,
        ))
    return records


def pico8(sources: dict[str, Source]) -> list[Record]:
    """The PICO-8 binary the generator runs, from an emulator folder.

    AppConfig.GetFullPath names a folder of the RetroBat install
    (emulatorLauncher.cfg, else emulators/<key>): the binary is never
    looked up in the BIOS tree.
    """
    src = sources[f"{GENERATORS}/Pico8.Generator.cs"]
    folder = src.find(r'string path = AppConfig\.GetFullPath\("(\w+)"\);', "pico8 folder")
    exe = src.find(
        r'string exe = Path\.Combine\(path, "([^"]+)"\);', "binary path", folder.end()
    )
    check = src.find(r"if \(!File\.Exists\(exe\)\)\s*return null;", "binary check", exe.end())
    run = src.find(r"FileName = exe,\s*WorkingDirectory = path,", "binary run", check.end())
    return [
        launcher_record(
            "pico8",
            "standalone",
            "fixed_name",
            [exe.group(1)],
            source_ref(
                (
                    src.path,
                    [
                        src.lines(folder.start(), folder.end()),
                        src.lines(exe.start(), check.end()),
                        src.lines(run.start(), run.end()),
                    ],
                )
            ),
            case_insensitive=True,
            search_dir=f"<AppConfig.GetFullPath(\"{folder.group(1)}\")>",
            passes_to="exec",
            fails_when_missing="returns no process when the binary is absent",
        )
    ]
