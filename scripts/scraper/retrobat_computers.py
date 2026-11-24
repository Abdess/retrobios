"""RetroBat launcher records of Hatari, Amiberry, WinUAE and openMSX."""

from __future__ import annotations

import re

from .csharp_source import (
    LauncherPatternMissing,
    Record,
    Source,
    _array_at,
    _strings,
    _throw_message,
    source_ref,
)
from .retrobat_generators import (
    BIOS,
    FEATURES,
    GENERATORS,
    TARGET_ABSENT,
    _joined,
    _record,
    feature_choices,
)


def hatari(sources: dict[str, Source]) -> list[Record]:
    """tos.img in bios, a TOS chosen in bios/hatari/tos, and EmuTOS from there
    for a hard disk image, for a missing tos.img, or after a TOS too old for
    autostart or GEMDOS."""
    src = sources[f"{GENERATORS}/Hatari.Generator.cs"]
    features = sources[FEATURES]
    folder = src.find(
        rf'string (\w+) = Path\.Combine\({BIOS}, ((?:"[^"]+"(?:, )?)+)\);', "TOS folder"
    )
    tos_dir, folders = folder.group(1), _strings(folder.group(2))
    default = src.find(
        rf'string (\w+) = Path\.Combine\({BIOS}, "([^"]+)"\);', "default TOS path", folder.end()
    )
    var, name = default.group(1), default.group(2)
    emutos = src.find(
        rf'string (\w+) = Path\.Combine\({tos_dir}, "([^"]+)"\);', "EmuTOS path", default.end()
    )
    override = src.find(
        rf'isOptSet\("(\w+)"\)[^\n]*\n\s*{var} = Path\.Combine\({tos_dir}, SystemConfig\["\1"\]\);',
        "TOS option override",
        emutos.end(),
    )
    option = override.group(1)
    disk = src.find(
        rf"else if \(media\.HasHardDiskImage && File\.Exists\({emutos.group(1)}\)\)",
        "EmuTOS for a hard disk image",
        override.end(),
    )
    absent = src.find(
        rf"if \(!File\.Exists\({var}\) && File\.Exists\({emutos.group(1)}\)\)\s*{var} = {emutos.group(1)};",
        "EmuTOS without tos.img",
        disk.end(),
    )
    newer = src.find(
        r"new string\[\] \{ ((?:\"[^\"]+\"(?:, )?)+) \}\s*"
        rf"\.Select\(t => Path\.Combine\({tos_dir}, t\)\)\s*\.FirstOrDefault\(t => File\.Exists\(t\)\);",
        "TOS for autostart and GEMDOS",
        absent.end(),
    )
    write = src.find(
        rf'ini\.WriteValue\("(\w+)", "(\w+)", {var}\);', "TOS ini write", newer.end()
    )
    message, _ = _throw_message(src, newer.end(), write.start())
    passes = f"hatari.cfg [{write.group(1)}] {write.group(2)}"
    tos_folder = "/".join(["bios", *folders])
    choices, choice_lines = feature_choices(features, "hatari", option)
    head = src.lines(folder.start(), emutos.end())
    tail = src.lines(write.start(), write.end())
    return [
        _record(
            "hatari",
            "standalone",
            "fixed_name",
            [name],
            source_ref((src.path, [head, src.lines(absent.start(), absent.end()), tail])),
            case_insensitive=True,
            search_dir="bios",
            passes_to=f"{passes}=<bios>/{name}",
            fails_when_missing=f"{tos_folder}/{emutos.group(2)} instead, else {message}",
            depends_on_option=f"{option} unset, no hard disk image",
        ),
        _record(
            "hatari",
            "standalone",
            "core_option",
            choices,
            source_ref(
                (src.path, [head, src.lines(override.start(), override.end()), tail]),
                (features.path, [choice_lines]),
            ),
            case_insensitive=True,
            search_dir=tos_folder,
            passes_to=f"{passes}=<bios>/{'/'.join(folders)}/<value>",
            fails_when_missing=message,
            depends_on_option=option,
        ),
        _record(
            "hatari",
            "standalone",
            "fixed_name",
            [emutos.group(2)],
            source_ref((src.path, [head, src.lines(disk.start(), absent.end()), tail])),
            case_insensitive=True,
            search_dir=tos_folder,
            passes_to=f"{passes}=<bios>/{'/'.join(folders)}/{emutos.group(2)}",
            fails_when_missing=f"{name} is used, as without a hard disk image",
            depends_on_option=f"{option} unset, a hard disk image mounted or no {name}",
        ),
        _record(
            "hatari",
            "standalone",
            "names_searched",
            _strings(newer.group(1)),
            source_ref((src.path, [head, src.lines(newer.start(), newer.end()), tail])),
            case_insensitive=True,
            search_dir=tos_folder,
            passes_to=f"{passes}=<first found>",
            fails_when_missing="the TOS older than 1.04 is kept",
            depends_on_option=f"{option} unset, autostart or GEMDOS folder, TOS older than 1.04",
        ),
    ]


def hatari_libretro(sources: dict[str, Source]) -> list[Record]:
    src = sources[f"{GENERATORS}/LibRetro.CoreOptions.cs"]
    features = sources[FEATURES]
    records = []

    tosimage = src.find(
        r'string (\w+) = SystemConfig\["(\w+)"\];\s*'
        rf'if \(!string\.IsNullOrEmpty\(\1\) && \1 != "(\w+)" && File\.Exists\(Path\.Combine\({BIOS}, '
        r'((?:"[^"]+", )+)\1\)\)\)\s*coreSettings\["(hatari_tosimage)"\] = \1;'
        r'\s*else\s*coreSettings\["\5"\] = "\3";',
        "hatari_tosimage",
    )
    guard = src.find(r'if \(core != "(hatari2014)"\)', "hatari2014 guard")
    folders = _strings(tosimage.group(4).rstrip(", "))
    choices, choice_lines = feature_choices(
        features, "libretro", tosimage.group(2), core=guard.group(1)
    )
    records.append(
        _record(
            guard.group(1),
            "libretro",
            "core_option",
            choices,
            source_ref(
                (src.path, [src.lines(guard.start(), tosimage.end())]),
                (features.path, [choice_lines]),
            ),
            search_dir="/".join(["bios", *folders]),
            passes_to=f"{tosimage.group(5)} = <value>, if the file is there | {tosimage.group(3)}",
            fails_when_missing=f"{tosimage.group(5)} = {tosimage.group(3)}",
            depends_on_option=tosimage.group(2),
        )
    )

    guard = src.find(r'if \(core != "hatarib"\)', "hatarib guard")
    method = src.enclosing(guard.start())
    tos_img = src.find(
        r'string (\w+) = Path\.Combine\((\w+), "([^"]+)"\);', "hatarib tos.img path",
        method[0], method[1],
    )
    own = src.find(
        rf'string (\w+) = Path\.Combine\({tos_img.group(2)}, "([^"]+)"\);', "hatarib folder",
        tos_img.end(), method[1],
    )
    option = src.find(
        r'string (\w+) = SystemConfig\["(hatarib_tos)"\];', "hatarib option", own.end(), method[1]
    )
    tos_var, key = option.group(1), option.group(2)
    named = src.find(
        rf'if \({tos_var} == "(\w+)"\)\s*\{{\s*if \(File\.Exists\({tos_img.group(1)}\)\)\s*'
        r'(\w+) = "([^"]+)";',
        "tos.img choice", option.end(), method[1],
    )
    builtin = src.find(
        rf'else if \({tos_var}\.StartsWith\("(\w+)"\)\)', "EmuTOS choices", named.end(), method[1]
    )
    shared = src.find(
        rf'string (\w+) = Path\.Combine\({own.group(1)}, {tos_var}\);\s*'
        rf'string (\w+) = Path\.Combine\({tos_img.group(2)}, ((?:"[^"]+", )+){tos_var}\);',
        "shared TOS folder", builtin.end(), method[1],
    )
    copy = src.find(
        rf"if \(!File\.Exists\({shared.group(1)}\) && File\.Exists\({shared.group(2)}\)\)",
        "copy from the shared folder", shared.end(), method[1],
    )
    chosen = src.find(
        rf'if \(File\.Exists\({shared.group(1)}\)\)\s*{named.group(2)} = "([^"/]+)/" \+ {tos_var};',
        "chosen TOS write", copy.end(), method[1],
    )
    fallback = src.find(
        rf'if \({named.group(2)} == null\)\s*\{{\s*{named.group(2)} = "([^"]+)";\s*'
        rf'if \(File\.Exists\({tos_img.group(1)}\)\)\s*\{{\s*{named.group(2)} = "([^"]+)";',
        "default TOS", chosen.end(), method[1],
    )
    emutos = src.find(
        rf'{named.group(2)} = "{re.escape(fallback.group(1))}";', "EmuTOS for a disk", fallback.end(),
        method[1],
    )
    folders = _strings(shared.group(3).rstrip(", "))
    choices, choice_lines = feature_choices(features, "libretro", key, core="hatarib")
    files = [c for c in choices if c != named.group(1) and not c.startswith(builtin.group(1))]
    head = src.lines(tos_img.start(), own.end())
    records.append(
        _record(
            "hatarib",
            "libretro",
            "fixed_name",
            [tos_img.group(3)],
            source_ref((src.path, [head, src.lines(named.start(), named.end()),
                                   src.lines(fallback.start(), emutos.end())])),
            case_insensitive=True,
            search_dir="bios",
            passes_to=f"{key} = {fallback.group(2)}",
            fails_when_missing=f"falls back to {key} = {fallback.group(1)}",
            depends_on_option=(
                f"{key} unset or {named.group(1)}; {fallback.group(1)} instead for a hard disk image "
                "under a TOS other than EmuTOS, or for autostart or GEMDOS under TOS older than 1.04"
            ),
        )
    )
    records.append(
        _record(
            "hatarib",
            "libretro",
            "core_option",
            files,
            source_ref(
                (src.path, [head, src.lines(shared.start(), chosen.end())]),
                (features.path, [choice_lines]),
            ),
            case_insensitive=True,
            search_dir=f"bios/{own.group(2)}",
            passes_to=f"{key} = {chosen.group(1)}/<value>",
            fails_when_missing=f"{key} = {fallback.group(1)}, or {fallback.group(2)} when bios holds it",
            depends_on_option=key,
        )
    )
    records.append(
        _record(
            "hatarib",
            "libretro",
            "copies",
            files,
            source_ref((src.path, [head, src.lines(shared.start(), copy.end())])),
            case_insensitive=True,
            search_dir="/".join(["bios", *folders]),
            passes_to=f"bios/{own.group(2)}/<value>",
            fails_when_missing=False,
            depends_on_option=_joined(key, TARGET_ABSENT),
        )
    )
    return records


def _kickstart_table(
    src: Source,
    entry: str,
    find_method: str,
) -> tuple[list[tuple[str, list[str], list[tuple[int, int]]]], str, tuple[int, int]]:
    """Kickstart candidate lists of an Amiga model table, identical lists merged."""
    lists: dict[tuple[str, tuple[str, ...]], list[tuple[int, int]]] = {}
    for model in src.find_all(rf'\{{\s*"[\w+]+",\s*new {entry}\s*\{{', f"{entry} table"):
        block = src.block_at(model.start())
        for field in re.finditer(
            r"\b(Kickstart|KickstartExt)\s*=\s*new\s*(?:string)?\[\]\s*\{",
            src.text[block[0] : block[1]],
        ):
            names, (_, last) = _array_at(src, block[0] + field.end() - 1)
            lists.setdefault((field.group(1), tuple(names)), []).append(
                (src.line(model.start()), last)
            )
    method = src.find(find_method, "Kickstart lookup method")
    body = src.block_at(method.end())
    dirs = src.find(
        r'new\s*(?:List<string>\s*)?(?:\[\])?\s*\{\s*biosPath((?:, Path\.Combine\(biosPath, "[^"]+"\))+)\s*\}',
        "Kickstart search directories",
        body[0],
        body[1],
    )
    search = ", ".join(["bios", *(f"bios/{d}" for d in _strings(dirs.group(1)))])
    method_span = (src.line(method.start()), src.lines(*body)[1])
    return (
        [(field, list(names), spans) for (field, names), spans in lists.items()],
        search,
        method_span,
    )


AMIBERRY_KEY = "amiberry"


def amiberry(sources: dict[str, Source]) -> list[Record]:
    """Kickstarts searched in bios and copied into the folders the generator
    writes to amiberry.conf, both below the amiberry emulator folder."""
    src = sources[f"{GENERATORS}/Amiberry.Generator.cs"]
    lists, search, method_span = _kickstart_table(
        src, "AmigaModel", r"private string FindBios\(string\[\] candidates\)"
    )
    warnings = {
        "Kickstart": src.find(
            r'Warning\("\[Amiberry\] No Kickstart ROM found', "Kickstart warning"
        ),
        "KickstartExt": src.find(
            r'Warning\("\[Amiberry\] No extended ROM found', "extended ROM warning"
        ),
    }
    keys = {"Kickstart": "kickstart_rom_file", "KickstartExt": "kickstart_ext_rom_file"}
    records = []
    for field, names, spans in lists:
        stage = src.find(rf"StageKickstart\(_model\.{field}\)", f"StageKickstart({field})")
        records.append(
            _record(
                "amiberry",
                "standalone",
                "names_searched",
                names,
                source_ref(
                    (
                        src.path,
                        [*spans, src.lines(stage.start(), warnings[field].end()), method_span],
                    )
                ),
                case_insensitive=True,
                search_dir=search,
                passes_to=f"copied to <amiberry roms>/{names[0]}, {keys[field]}",
                fails_when_missing=f"warning, {keys[field]} not written",
            )
        )
    folder = src.find(
        r'GetEmulatorPathAndExe\(emulator, out string path, out string exe(?:, "[^"]+")+\)',
        "amiberry folder",
    )
    home = f'<AppConfig.GetFullPath("{AMIBERRY_KEY}")>'
    roms = src.find(
        r'(\w+) = Path\.Combine\(path, "(\w+)"\);\s*'
        r'FileTools\.TryCreateDirectory\(\1\);\s*overrides\["rom_path"\] = \1;',
        "rom_path folder",
    )
    whdboot = src.find(
        r'overrides\["whdboot_path"\] = Path\.Combine\(path, "(\w+)"\);', "whdboot_path folder"
    )
    write = src.find(r"MergeConfLines\(confFile, overrides\);", "amiberry.conf write")
    head = src.lines(folder.start(), folder.end())
    written = src.lines(write.start(), write.end())
    for directory, match, key in ((roms.group(2), roms, "rom_path"),
                                  (whdboot.group(1), whdboot, "whdboot_path")):
        records.append(
            _record(
                "amiberry",
                "standalone",
                "passes_path",
                [],
                source_ref((src.path, [head, src.lines(match.start(), match.end()), written])),
                search_dir=f"{home}/{directory}",
                passes_to=f"written: {key} in amiberry.conf",
                fails_when_missing=False,
            )
        )
    stage = src.find(r"private string StageKickstart\(string\[\] candidates\)", "StageKickstart")
    stage_body = src.block_at(stage.end())
    stage_text = src.text[stage_body[0]:stage_body[1]]
    if not re.search(r"Path\.Combine\(_amiberryRomsPath, candidates\[0\]\)", stage_text) or not re.search(
        r"!dst\.Exists \|\| dst\.Length != src\.Length \|\| dst\.LastWriteTimeUtc < src\.LastWriteTimeUtc",
        stage_text,
    ):
        raise LauncherPatternMissing(src.path, "StageKickstart copy to candidates[0] when stale")
    stage_span = (src.line(stage.start()), src.lines(*stage_body)[1])
    for field, names, spans in lists:
        call = src.find(rf"StageKickstart\(_model\.{field}\)", f"StageKickstart({field})")
        records.append(
            _record(
                "amiberry",
                "standalone",
                "copies",
                names,
                source_ref((src.path, [*spans, head, src.lines(roms.start(), roms.end()),
                                       src.lines(call.start(), call.end()),
                                       stage_span, method_span])),
                case_insensitive=True,
                search_dir=search,
                passes_to=f"{home}/{roms.group(2)}/{names[0]}",
                fails_when_missing=False,
                depends_on_option="first name found, the target is absent, smaller or older",
            )
        )
    stage_key = src.find(r"private void StageRomKey\(\)", "StageRomKey")
    key_body = src.block_at(stage_key.end())
    key_text = src.text[key_body[0]:key_body[1]]
    named = re.search(r'FindBios\(new\[\] \{ "([^"]+)" \}\)', key_text)
    if not named or not re.search(
        r"!File\.Exists\(dest\) \|\| new FileInfo\(dest\)\.Length != new FileInfo\(source\)\.Length",
        key_text,
    ):
        raise LauncherPatternMissing(src.path, "StageRomKey copy when absent or resized")
    records.append(
        _record(
            "amiberry",
            "standalone",
            "copies",
            [named.group(1)],
            source_ref((src.path, [head, src.lines(roms.start(), roms.end()),
                                   (src.line(stage_key.start()), src.lines(*key_body)[1]), method_span])),
            case_insensitive=True,
            search_dir=search,
            passes_to=f"{home}/{roms.group(2)}/{named.group(1)}",
            fails_when_missing=False,
            depends_on_option="the target is absent or its size differs",
        )
    )
    return records


def winuae(sources: dict[str, Source]) -> list[Record]:
    src = sources[f"{GENERATORS}/Uae.Generator.cs"]
    lists, search, method_span = _kickstart_table(
        src, "Candidate", r"public static string Find\(string\[\] candidates\)"
    )
    writer = src.find(r"private void WriteKickstartRom\(", "WriteKickstartRom")
    body = src.block_at(writer.end())
    keys = {"Kickstart": "kickstart_rom_file", "KickstartExt": "kickstart_ext_rom_file"}
    records = []
    for field, names, spans in lists:
        lookup = src.find(
            rf"AmigaBios\.Find\(candidate\.{field}\)", f"Find({field})", body[0], body[1]
        )
        message, throw_line = _throw_message(src, lookup.end(), body[1])
        records.append(
            _record(
                "winuae",
                "standalone",
                "names_searched",
                names,
                source_ref(
                    (src.path, [*spans, (src.line(lookup.start()), throw_line + 1), method_span])
                ),
                case_insensitive=True,
                search_dir=search,
                passes_to=f"game .uae {keys[field]}=<found path>",
                fails_when_missing=message,
            )
        )
    table = src.find(
        r"WhdBootKickstartEntry\[\] _whdBootKickstarts = new\[\]", "WHDBoot Kickstart table"
    )
    table_block = src.block_at(table.end())
    targets = re.findall(
        r'new WhdBootKickstartEntry\("([^"]+)", AmigaBios\.BySystem\["[^"]+"\]\.Kickstart\)',
        src.text[table_block[0] : table_block[1]],
    )
    loop = src.find(r"foreach \(var entry in _whdBootKickstarts\)", "WHDBoot copy loop")
    loop_block = src.block_at(loop.end())
    folder = src.find(
        r'Path\.Combine\(whdBoot, ((?:"[^"]+"(?:, )?)+)\)',
        "WHDBoot Kickstarts folder",
        0,
        loop.start(),
    )
    records.append(
        _record(
            "winuae",
            "standalone",
            "copies",
            targets,
            source_ref(
                (
                    src.path,
                    [
                        (src.line(loop.start()), src.lines(*loop_block)[1]),
                        (src.line(table.start()), src.lines(*table_block)[1]),
                    ],
                )
            ),
            case_insensitive=True,
            search_dir=search,
            passes_to=f"<WHDBoot>/{'/'.join(_strings(folder.group(1)))}/<name>",
            fails_when_missing=False,
            depends_on_option="the system's Kickstart candidates",
        )
    )
    return records


def openmsx(sources: dict[str, Source]) -> list[Record]:
    src = sources[f"{GENERATORS}/OpenMSX.Generator.cs"]
    table = src.find(
        r"Dictionary<string, string\[\]> biosFiles = new Dictionary<string, string\[\]>\(\)\s*\{",
        "biosFiles table",
    )
    block = src.block_at(table.end() - 1)
    check = src.find(r"foreach \(var c in biosFileRequired\)", "per-file BIOS check")
    message, throw_line = _throw_message(src, check.end(), len(src.text))
    folder = re.search(r"in '([^']+)' folder", message)
    if folder is None:
        raise LauncherPatternMissing(src.path, "systemroms folder in the BIOS message")
    records = []
    for entry in re.finditer(
        r'\{ "([^"]+)", new string\[\] \{([^}]*)\} \}', src.text[block[0] : block[1]]
    ):
        start = block[0] + entry.start()
        records.append(
            _record(
                "openmsx",
                "standalone",
                "fixed_name",
                _strings(entry.group(2)),
                source_ref(
                    (
                        src.path,
                        [
                            src.lines(start, block[0] + entry.end()),
                            (src.line(check.start()), throw_line),
                        ],
                    )
                ),
                case_insensitive=False,
                search_dir=folder.group(1).replace("\\", "/"),
                passes_to=f"-machine {entry.group(1)}",
                fails_when_missing=message,
            )
        )
    if not records:
        raise LauncherPatternMissing(src.path, "biosFiles entries")
    # OPENMSX_HOME is the user directory: openMSX reads share/systemroms below it.
    home = src.find(
        rf'string (\w+) = Path\.Combine\({BIOS}, "([^"]+)"\);', "OPENMSX_HOME folder"
    )
    handed = src.find(
        rf'ret\.EnvironmentVariables\["(OPENMSX_HOME)"\] = {home.group(1)};',
        "OPENMSX_HOME environment", home.end(),
    )
    records.append(
        _record(
            "openmsx",
            "standalone",
            "passes_path",
            [],
            source_ref(
                (src.path, [src.lines(home.start(), home.end()),
                            src.lines(handed.start(), handed.end())])
            ),
            search_dir=f"bios/{home.group(2)}",
            passes_to=f"environment {handed.group(1)}",
            fails_when_missing=False,
        )
    )
    return records
