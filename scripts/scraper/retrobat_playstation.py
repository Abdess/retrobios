"""RetroBat launcher records of PCSX2, the PS1 BIOS cascades and DuckStation."""

from __future__ import annotations

import re

from .csharp_source import (
    LauncherPatternMissing,
    Record,
    Source,
    _array_at,
    _code_chars,
    _strings,
    _throw_message,
    _unique,
    source_ref,
)
from .retrobat_generators import BIOS, FEATURES, GENERATORS, _record, feature_choices


def pcsx2(sources: dict[str, Source]) -> list[Record]:
    src = sources[f"{GENERATORS}/Pcsx2.Generator.cs"]
    records = []

    qt = src.find(r"private void SetupConfigurationQT\(", "SetupConfigurationQT")
    qt_body = src.block_at(qt.end())
    folder = src.find(
        rf'string biosPath = Path\.Combine\({BIOS}, ((?:"[^"]+"(?:, )?)+)\);',
        "Qt BIOS folder",
        qt_body[0],
        qt_body[1],
    )
    src.find(
        r"Directory\.GetFiles\(biosPath\)\.Length == 0\)[^\n]*\n\s*biosPath = " + BIOS,
        "empty folder fallback",
        folder.end(),
        qt_body[1],
    )
    write = src.find(
        r'ini\.WriteValue\("Filenames", "BIOS", biosFile\);',
        "Qt BIOS write",
        folder.end(),
        qt_body[1],
    )
    message, _ = _throw_message(src, folder.end(), write.start())
    src.find(r'SystemConfig\["pcsx2_forcebios"\]', "pcsx2_forcebios", folder.end(), write.start())
    sub = "/".join(_strings(folder.group(1)))
    for var in ("biosList", "arcadeBiosList"):
        decl = src.find(rf"var {var} = new string\[\] \{{", f"Qt {var}", qt_body[0], qt_body[1])
        names, lines = _array_at(src, decl.end() - 1)
        records.append(
            _record(
                "pcsx2",
                "standalone",
                "names_searched",
                names,
                source_ref(
                    (
                        src.path,
                        [
                            (src.line(decl.start()), lines[1]),
                            src.lines(folder.start(), write.end()),
                        ],
                    )
                ),
                case_insensitive=True,
                search_dir=f"bios/{sub} (bios when bios/{sub} holds no file)",
                passes_to="inis/PCSX2.ini [Folders] Bios, [Filenames] BIOS",
                fails_when_missing=message,
                depends_on_option="pcsx2_forcebios",
            )
        )

    legacy = src.find(r"private void SetupPaths\(", "SetupPaths")
    legacy_body = src.block_at(legacy.end())
    decl = src.find(
        r"var biosList = new string\[\] \{", "1.6 biosList", legacy_body[0], legacy_body[1]
    )
    names, lines = _array_at(src, decl.end() - 1)
    case = src.find(r'case "BIOS":', "1.6 BIOS case", legacy_body[0], legacy_body[1])
    default = src.find(
        r'value = "([^"]+)";\s*break;', "1.6 default BIOS", case.end(), legacy_body[1]
    )
    folder = src.find(
        r'File\.Exists\(Path\.Combine\(biosPath, ((?:"[^"]+", )+)b\)\)',
        "1.6 BIOS folder",
        legacy_body[0],
        legacy_body[1],
    )
    sub = "/".join(_strings(folder.group(1)))
    records.append(
        _record(
            "pcsx2",
            "standalone",
            "names_searched",
            names,
            source_ref(
                (
                    src.path,
                    [(src.line(decl.start()), lines[1]), src.lines(case.start(), default.end())],
                )
            ),
            case_insensitive=True,
            search_dir=f"bios/{sub} if any listed name is there, else bios",
            passes_to="inis/PCSX2_ui.ini [Folders] Bios, [Filenames] BIOS",
            fails_when_missing=f"no error: BIOS name defaults to {default.group(1)}",
            depends_on_option="pcsx2_forcebios",
        )
    )
    return records


def pcsx2_libretro(sources: dict[str, Source]) -> list[Record]:
    src = sources[f"{GENERATORS}/LibRetro.CoreOptions.cs"]
    features = sources[FEATURES]
    guard = src.find(r'if \(core != "pcsx2"\)', "pcsx2 guard")
    method = src.enclosing(guard.start())
    folder = src.find(
        r'string ps2BiosFolder = Path\.Combine\(biosRoot, ((?:"[^"]+"(?:, )?)+)\);',
        "LRPS2 folder",
        method[0],
        method[1],
    )
    option = src.find(r'isOptSet\("(lrps2_bios)"\)', "lrps2_bios", folder.end(), method[1])
    write = src.find(
        r'coreSettings\["(pcsx2_bios)"\] = \w+;', "pcsx2_bios write", option.end(), method[1]
    )
    message, _ = _throw_message(src, option.end(), write.start())
    choices, choice_lines = feature_choices(features, "libretro", option.group(1), core="pcsx2")
    sub = "/".join(_strings(folder.group(1)))
    records = [
        _record(
            "pcsx2",
            "libretro",
            "core_option",
            choices,
            source_ref(
                (src.path, [src.lines(folder.start(), write.end())]),
                (features.path, [choice_lines]),
            ),
            case_insensitive=True,
            search_dir=f"<system_directory>/{sub}",
            passes_to=f"{write.group(1)} = <value>",
            fails_when_missing=message,
            depends_on_option=option.group(1),
        )
    ]

    scan = src.find(
        r"private static string GetFirstPS2Bios\(string biosFolder\)", "GetFirstPS2Bios"
    )
    scan_body = src.block_at(scan.end())
    preferred = src.find(
        r'n\.Equals\("([^"]+)", StringComparison\.OrdinalIgnoreCase\)',
        "preferred PS2 BIOS",
        scan_body[0],
        scan_body[1],
    )
    sizes = src.find(
        r"MIN_BIOS_SIZE = (\d+) \* 1024 \* 1024;\s*const long MAX_BIOS_SIZE = (\d+) \* 1024 \* 1024;",
        "BIOS size bounds",
        scan_body[0],
        scan_body[1],
    )
    auto = src.find(
        r"string autoBios = GetFirstPS2Bios\(ps2BiosFolder\);",
        "GetFirstPS2Bios call",
        write.end(),
        method[1],
    )
    auto_write = src.find(
        r'coreSettings\["pcsx2_bios"\] = autoBios;', "autoBios write", auto.end(), method[1]
    )
    auto_message, _ = _throw_message(src, auto.end(), auto_write.start())
    records.append(
        _record(
            "pcsx2",
            "libretro",
            "scans_dir",
            [
                preferred.group(1),
                f"<first file {sizes.group(1)}-{sizes.group(2)} MiB, ordinal-ignore-case>",
            ],
            source_ref(
                (
                    src.path,
                    [
                        (src.line(scan.start()), src.lines(*scan_body)[1]),
                        src.lines(auto.start(), auto_write.end()),
                    ],
                )
            ),
            case_insensitive=True,
            search_dir=f"<system_directory>/{sub}",
            passes_to="pcsx2_bios = <chosen name>",
            fails_when_missing=auto_message,
            depends_on_option=f"{option.group(1)} unset",
        )
    )
    return records


PSX_CASCADES = {
    f"{GENERATORS}/Bizhawk.Generator.cs": ("bizhawk", "standalone"),
    f"{GENERATORS}/Mednafen.Generator.cs": ("mednafen", "standalone"),
    f"{GENERATORS}/LibRetro.CoreOptions.cs": (None, "libretro"),
}


def _top_level_else(src: Source, block: tuple[int, int]) -> int | None:
    """Offset of the last else of an if chain at the top of a block, not an else if."""
    depth, last = 0, None
    for offset, char in _code_chars(src.text[block[0] + 1 : block[1] - 1]):
        absolute = block[0] + 1 + offset
        if char in "{(":
            depth += 1
        elif char in "})":
            depth -= 1
        elif (
            depth == 0
            and src.text.startswith("else", absolute)
            and not re.match(r"else\s+if\b", src.text[absolute:])
        ):
            last = absolute
    return last


def psx_cascades(sources: dict[str, Source]) -> list[Record]:
    """psxonpsp660.bin, then ps1_rom.bin, then one file per region."""
    records = []
    for path, (fixed_emulator, build) in PSX_CASCADES.items():
        src = sources[path]
        for cascade in src.find_all(
            r'if \(!SystemConfig\.getOptBoolean\("(\w+_original_bios)"\)\)', "PSX BIOS cascade"
        ):
            emulator = fixed_emulator
            if emulator is None:
                guards = re.findall(r'if \(core != "([^"]+)"\)', src.text[: cascade.start()])
                if not guards:
                    raise LauncherPatternMissing(path, "core guard before the PSX cascade")
                emulator = guards[-1]
            branch = src.block_at(cascade.end())
            after = re.compile(r"\s*else\s*(\{|[^;]*;)").match(src.text, branch[1])
            if after is None:
                raise LauncherPatternMissing(
                    path, f"else after the PSX cascade at line {src.line(cascade.start())}"
                )
            original_end = src.block_at(after.start(1))[1] if after.group(1) == "{" else after.end()
            final_else = _top_level_else(src, branch)
            if final_else is None:
                raise LauncherPatternMissing(
                    path, f"final else of the PSX cascade at line {src.line(cascade.start())}"
                )
            searched = _unique(
                re.findall(rf'Path\.Combine\({BIOS}, "([^"]+)"\)', src.text[branch[0] : final_else])
            )
            if not searched:
                raise LauncherPatternMissing(path, "searched PSX BIOS names")
            keys = _unique(re.findall(r'\w+\["([^"]+)"\]\s*=', src.text[branch[0] : branch[1]]))
            ref = source_ref((path, [src.lines(cascade.start(), original_end)]))
            records.append(
                _record(
                    emulator,
                    build,
                    "names_searched",
                    searched,
                    ref,
                    case_insensitive=True,
                    search_dir="bios",
                    passes_to=", ".join(keys),
                    fails_when_missing=False,
                    depends_on_option=f"{cascade.group(1)} off",
                )
            )
            fallback_text = src.text[final_else : branch[1]]
            fallback = _unique([n for n in _strings(fallback_text) if n.lower().endswith(".bin")])
            if fallback:
                checked = "File.Exists" in fallback_text
                records.append(
                    _record(
                        emulator,
                        build,
                        "fixed_name",
                        fallback,
                        ref,
                        case_insensitive=True,
                        search_dir="bios",
                        passes_to=", ".join(keys),
                        fails_when_missing=(
                            False if checked else "names written without an existence check"
                        ),
                    )
                )
    return records


def duckstation(sources: dict[str, Source]) -> list[Record]:
    src = sources[f"{GENERATORS}/Duckstation.Generator.cs"]
    features = sources[FEATURES]
    search = src.find(
        r'ini\.WriteValue\("BIOS", "SearchDirectory", biosPath\);', "SearchDirectory write"
    )
    option = src.find(r'isOptSet\("(duck_bios)"\)', "duck_bios", search.end())
    block = src.block_at(option.end())
    keys = re.findall(
        r'ini\.WriteValue\("BIOS", "(\w+)", SystemConfig\["duck_bios"\]\);',
        src.text[block[0] : block[1]],
    )
    if not keys:
        raise LauncherPatternMissing(src.path, "duck_bios writes")
    cleared = src.block_at(block[1])
    choices, choice_lines = feature_choices(features, "duckstation", option.group(1))
    return [
        _record(
            "duckstation",
            "standalone",
            "passes_path",
            [],
            source_ref((src.path, [src.lines(search.start(), search.end()), src.lines(*cleared)])),
            search_dir="bios",
            passes_to="settings.ini [BIOS] SearchDirectory = bios",
            fails_when_missing=False,
            depends_on_option=f"{option.group(1)} unset",
        ),
        _record(
            "duckstation",
            "standalone",
            "core_option",
            choices,
            source_ref(
                (src.path, [src.lines(option.start(), block[1])]), (features.path, [choice_lines])
            ),
            search_dir="bios",
            passes_to="settings.ini [BIOS] " + " = ".join(keys) + " = <value>",
            fails_when_missing="not checked by the launcher",
            depends_on_option=option.group(1),
        ),
    ]
