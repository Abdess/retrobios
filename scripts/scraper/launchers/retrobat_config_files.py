"""RetroBat generators that write a BIOS file into the emulator's configuration."""

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
    _split_top,
    _statement_start,
    _strings,
    _throw_message,
    _unescape,
    source_ref,
)
from .retrobat_generators import (
    BIOS,
    FEATURES,
    GENERATORS,
    TARGET_ABSENT,
    BIOS_ROOT,
    joined,
    launcher_record,
    feature_choices,
)
from .retrobat_render import config_label, covered_records, path_parts, render, when


# Each extractor takes the sources by path and returns its records.


def ares(sources: dict[str, Source]) -> list[Record]:
    """Fallback chains: x = Path.Combine(dir, a), then if (!File.Exists(x)) x = b."""
    src = sources[f"{GENERATORS}/Ares.Generator.cs"]
    records = []
    head = r'string (\w+) = Path\.Combine\((\w+), "([^"]+)"\);'
    for found in src.find_all(head, "Path.Combine fallback chain"):
        var, folder = found.group(1), found.group(2)
        names, end = [found.group(3)], found.end()
        step = re.compile(
            rf'\s*if \(!File\.Exists\({var}\)\)\s*{var} = Path\.Combine\({folder}, "([^"]+)"\);'
        )
        while more := step.match(src.text, end):
            names.append(more.group(1))
            end = more.end()
        if len(names) == 1:
            continue
        block = src.enclosing(found.start())
        target = src.find(
            rf'firmware\["([^"]+)"\] = {var}\.', f"firmware key for {var}", end, block[1]
        )
        container = list(
            re.compile(r'GetOrCreateContainer\("(\w+)"\)').finditer(
                src.text, block[0], found.start()
            )
        )
        folder_decl = src.find(
            rf'string {folder} = Path\.Combine\({BIOS}, "([^"]+)"\);',
            f"folder {folder}",
            block[0],
            found.start(),
        )
        sections = "/".join(m.group(1) for m in container)
        records.append(
            launcher_record(
                "ares",
                "standalone",
                "names_searched",
                names,
                source_ref((src.path, [(src.line(found.start()), src.line(target.end()))])),
                case_insensitive=True,
                search_dir=f"bios/{folder_decl.group(1)}",
                passes_to=f"settings.bml {sections}/{target.group(1)} (first found)",
                fails_when_missing=False,
            )
        )
    if not records:
        raise LauncherPatternMissing(src.path, "File.Exists fallback chain")
    return records


def mesen(sources: dict[str, Source]) -> list[Record]:
    """Files copied from bios into Mesen's Firmware folder, renamed on the way."""
    src = sources[f"{GENERATORS}/Mesen.Generator.cs"]
    records = []
    for folder in src.find_all(
        r'string targetFirmwarePath = Path\.Combine\(\w+, "Firmware"\);', "Firmware folder"
    ):
        block = src.enclosing(folder.start())
        body = src.text[block[0] : block[1]]
        targets = dict(
            re.findall(
                r'string (targetFirmware\d+) = Path\.Combine\(targetFirmwarePath, "([^"]+)"\);',
                body,
            )
        )
        pairs = re.findall(
            rf'string (sourceFirmware\d+) = Path\.Combine\({BIOS}, "([^"]+)"\);', body
        )
        copies = re.findall(
            r"!File\.Exists\((targetFirmware\d+)\)[^\n]*\n\s*File\.Copy\((sourceFirmware\d+), \1\);",
            body,
        )
        if not pairs or len(copies) != len(pairs):
            raise LauncherPatternMissing(
                src.path, f"guarded File.Copy at line {src.line(folder.start())}"
            )
        by_source = {source: target for target, source in copies}
        names = [name for _, name in pairs]
        destinations = [targets[by_source[var]] for var, _ in pairs]
        try:
            fails: str | bool = _throw_message(src, folder.start(), block[1])[0]
        except LauncherPatternMissing:
            fails = False
        records.append(
            launcher_record(
                "mesen",
                "standalone",
                "copies",
                names,
                source_ref((src.path, [src.statement_span(block)])),
                case_insensitive=True,
                search_dir="bios",
                passes_to=", ".join(f"<mesen>/Firmware/{d}" for d in destinations),
                fails_when_missing=fails,
                depends_on_option=TARGET_ABSENT,
            )
        )
    return records


def _name_of(src: Source, var: str, offset: int) -> tuple[str, str, list[tuple[int, int]]]:
    """A variable holding bios/<folders>/<name>, as (folder, name, lines)."""
    method = _method_of(src, offset)
    rendered = render(src, var, method[0], offset)
    if rendered is None or not rendered[0].startswith("bios/") or ", " in rendered[0]:
        raise LauncherPatternMissing(
            src.path, f"bios path held by {var} at line {src.line(offset)}"
        )
    folder, _, name = rendered[0].rpartition("/")
    return folder, name, rendered[1]


def desmume(sources: dict[str, Source]) -> list[Record]:
    src = sources[f"{GENERATORS}/Desmume.Generator.cs"]
    code = _code(src)
    pair = src.find(
        r"if \(File\.Exists\((\w+)\) && File\.Exists\((\w+)\)\)\s*\{", "BIOS pair check"
    )
    block = src.block_at(pair.end() - 1)
    keys = {
        value: key
        for key, value in re.findall(
            r'\w+\.WriteValue\("\w+", "(\w+)", (\w+)\);', code[block[0] : block[1]]
        )
    }
    flag = re.search(r'\w+\.WriteValue\("(\w+)", "(\w+)", "1"\);', code[block[0] : block[1]])
    if flag is None or any(var not in keys for var in pair.groups()):
        raise LauncherPatternMissing(src.path, "BIOS pair writes")
    names, spans = [], []
    for var in pair.groups():
        folder, name, lines = _name_of(src, var, pair.start())
        names.append(name)
        spans += lines
    conditions, returns = when(src, pair.start())
    config = config_label(src, pair.start(), "ini")
    records = [
        launcher_record(
            "desmume",
            "standalone",
            "fixed_name",
            names,
            path_parts(src, *returns, *spans, src.lines(pair.start(), block[1])),
            case_insensitive=True,
            search_dir=folder,
            passes_to=f"{config} [{flag.group(1)}] "
            + ", ".join(keys[var] for var in pair.groups())
            + ", only if every listed file exists",
            fails_when_missing=f"{flag.group(2)} left at 0",
            depends_on_option=", ".join(conditions) or None,
        )
    ]
    firmware = src.find(
        rf'string (\w+) = Path\.Combine\({BIOS_ROOT}, "([^"]+)"\);\s*'
        r'if \(SystemConfig\.isOptSet\("(\w+)"\)[^\n]*\)\s*\{\s*'
        r'string (\w+) = SystemConfig\["\3"\];\s*if \(File\.Exists\(\4\)\)\s*\1 = \4;\s*\}\s*'
        r"if \(File\.Exists\(\1\)\)\s*\{",
        "firmware default and user file",
    )
    fw_block = src.block_at(firmware.end() - 1)
    fw_write = src.find(
        rf'\w+\.WriteValue\("(\w+)", "(\w+)", {firmware.group(1)}\);',
        "firmware write",
        fw_block[0],
        fw_block[1],
    )
    fw_flag = src.find(
        rf'\w+\.WriteValue\("{fw_write.group(1)}", "(\w+)", "1"\);',
        "firmware flag",
        fw_block[0],
        fw_block[1],
    )
    conditions, returns = when(src, firmware.start())
    records.append(
        launcher_record(
            "desmume",
            "standalone",
            "fixed_name",
            [firmware.group(2)],
            path_parts(src, *returns, src.lines(firmware.start(), fw_flag.end())),
            case_insensitive=True,
            search_dir="bios",
            passes_to=f"{config} [{fw_write.group(1)}] {fw_write.group(2)}, only if the file exists",
            fails_when_missing=f"{fw_flag.group(1)} left at 0",
            depends_on_option=", ".join(
                [*conditions, f"{firmware.group(3)} unset or not an existing file"]
            ),
        )
    )
    return covered_records(src, records)


def melonds_dsi(sources: dict[str, Source]) -> list[Record]:
    src = sources[f"{GENERATORS}/MelonDS.Generator.cs"]
    features = sources[FEATURES]
    code = _code(src)
    check = src.find(
        r"if \(((?:!File\.Exists\(\w+\)(?: \|\| )?)+)\)\s*throw new ApplicationException",
        "DSi files check",
    )
    message, throw_line = _throw_message(src, check.start(), len(src.text))
    method = _method_of(src, check.start())
    variables = re.findall(r"!File\.Exists\((\w+)\)", check.group(1))
    writes = {
        var: key
        for section, key, var in re.findall(
            r'\w+\.WriteValue\("(\w+)", "(\w+)", "\\"" \+ (\w+)\.Replace',
            code[check.end() : method[1]],
        )
        if section == "DSi"
    }
    if set(variables) - set(writes):
        raise LauncherPatternMissing(src.path, "DSi path writes")
    names, spans = [], []
    folders = set()
    for var in variables:
        decl = src.find(
            rf'string {var} = Path\.Combine\((\w+), "([^"]+)"\);',
            f"{var} declaration",
            method[0],
            check.start(),
        )
        root = render(src, decl.group(1), method[0], decl.start())
        if root is None or not root[0].startswith("bios"):
            raise LauncherPatternMissing(src.path, f"bios folder of {var}")
        folders.add(root[0])
        names.append(decl.group(2))
        spans += [*root[1], src.lines(decl.start(), decl.end())]
    if len(folders) != 1:
        raise LauncherPatternMissing(src.path, "one folder for the DSi files")
    folder = folders.pop()
    last_write = (
        max(
            m.end()
            for m in re.finditer(
                r'\w+\.WriteValue\("DSi", "\w+", [^;]+;', code[check.end() : method[1]]
            )
        )
        + check.end()
    )
    dsi = src.find(
        r'bool (\w+) = SystemConfig\.isOptSet\("(\w+)"\) && SystemConfig\["\2"\] == "(\w+)";',
        "DSi console option",
        method[0],
        check.start(),
    )
    boot = src.find(
        r'bool (\w+) = Path\.GetExtension\(rom\)\.ToLowerInvariant\(\) == "([^"]+)";',
        "DSi NAND boot extension",
    )
    forced = src.find(
        rf"if \({boot.group(1)}\)\s*{dsi.group(1)} = true;", "NAND boot forces DSi", dsi.end()
    )
    mode = f'{dsi.group(2)} == "{dsi.group(3)}" || rom extension "{boot.group(2)}"'
    region = src.find(
        r'if \(SystemConfig\.isOptSet\("(\w+)"\)[^\n]*\)\s*\{\s*string (\w+) = SystemConfig\["\1"\];\s*'
        r'string (\w+) = Directory\.GetFiles\((\w+), "([^"]+)"\)\s*'
        r"\.FirstOrDefault\(f => Path\.GetFileNameWithoutExtension\(f\)\s*"
        r"\.IndexOf\(\2, StringComparison\.OrdinalIgnoreCase\) >= 0\);\s*"
        r"if \(\3 != null\)\s*(\w+) = \3;",
        "DSi NAND region match",
        method[0],
        check.start(),
    )
    region_block = src.block_at(region.start())
    choices, choice_lines = feature_choices(features, "melonds", region.group(1))
    stem, _, extension = region.group(5).rpartition(".")
    nand_name = names[variables.index(region.group(6))]
    config = config_label(src, check.start(), "ini")
    records = [
        launcher_record(
            "melonds",
            "standalone",
            "fixed_name",
            names,
            path_parts(
                src,
                src.lines(boot.start(), boot.end()),
                src.lines(dsi.start(), forced.end()),
                *spans,
                (src.line(check.start()), throw_line),
                src.lines(check.end(), last_write),
            ),
            case_insensitive=True,
            search_dir=folder,
            passes_to=f"{config} [DSi] " + ", ".join(writes[v] for v in variables),
            fails_when_missing=message,
            depends_on_option=mode,
        ),
        launcher_record(
            "melonds",
            "standalone",
            "scans_dir",
            [f"{stem}{{region}}*.{extension}"],
            source_ref(
                (src.path, [src.statement_span(region_block)]),
                (features.path, [choice_lines]),
            ),
            expands={"region": choices},
            case_insensitive=True,
            search_dir=folder,
            passes_to=f"{config} [DSi] {writes[region.group(6)]}, first file whose name holds the region",
            fails_when_missing=f"falls back to {nand_name}",
            depends_on_option=(
                f'{dsi.group(2)} == "{dsi.group(3)}", {region.group(1)} set,'
                f' rom extension not "{boot.group(2)}"'
            ),
        ),
    ]
    return records


def jzintv(sources: dict[str, Source]) -> list[Record]:
    src = sources[f"{GENERATORS}/Jzintv.Generator.cs"]
    check = src.find(
        r"if \(!File\.Exists\((\w+)\) \|\| !File\.Exists\((\w+)\)\)\s*throw new ApplicationException",
        "exec and grom check",
    )
    message, throw_line = _throw_message(src, check.start(), len(src.text))
    passed = []
    for var in check.groups():
        add = src.find(
            rf'commandArray\.Add\("(-\w+)"\);\s*commandArray\.Add\("\\"" \+ {var} \+ "\\""\);',
            f"flag passing {var}",
            check.end(),
        )
        folder, name, lines = _name_of(src, var, check.start())
        passed.append((add.start(), add.group(1), name, lines, add.end()))
    passed.sort()
    records = [
        launcher_record(
            "jzintv",
            "standalone",
            "fixed_name",
            [name for _, _, name, _, _ in passed],
            path_parts(
                src,
                *[span for p in passed for span in p[3]],
                (src.line(check.start()), throw_line),
                src.lines(passed[0][0], passed[-1][4]),
            ),
            case_insensitive=True,
            search_dir=folder,
            passes_to="command line "
            + " ".join(f"{flag} <bios>/{name}" for _, flag, name, _, _ in passed),
            fails_when_missing=message,
        )
    ]
    ecs = src.find(
        rf'string (\w+) = Path\.Combine\({BIOS_ROOT}, "([^"]+)"\);\s*if \(File\.Exists\(\1\)\)\s*\{{\s*'
        r'commandArray\.Add\("(-\w+)"\);',
        "ECS ROM",
    )
    warning = src.find(
        r'Warning\("([^"]+)"\);\s*commandArray\.Add\("(-\w+)"\);', "ECS warning", ecs.end()
    )
    option = src.find(
        r'if \(SystemConfig\.getOptBoolean\("(\w+)"\)\)\s*\{', "ECS option", 0, ecs.start()
    )
    commands = src.find(
        r'string commandFile = rom\.Replace\(Path\.GetExtension\(rom\), "([^"]+)"\);\s*'
        r'if \(!File\.Exists\(commandFile\)\)\s*commandFile = Path\.Combine\(AppConfig\.GetFullPath\("(\w+)"\),\s*"([^"]+)", "([^"]+)"\);\s*'
        r"if \(File\.Exists\(commandFile\)\)",
        "command file lookup",
    )
    records.append(
        launcher_record(
            "jzintv",
            "standalone",
            "fixed_name",
            [ecs.group(2)],
            path_parts(
                src,
                src.lines(commands.start(), commands.end()),
                src.lines(option.start(), warning.end()),
            ),
            case_insensitive=True,
            search_dir="bios",
            passes_to=f"command line {ecs.group(3)} <bios>/{ecs.group(2)}, only if the file exists",
            fails_when_missing=f"warning '{warning.group(1)}', {warning.group(2)} passed",
            depends_on_option=(
                f"{option.group(1)} on, no <rom>{commands.group(1)} and no "
                f"{commands.group(2)}/{commands.group(3)}/{commands.group(4)}"
            ),
        )
    )
    return covered_records(src, records)


def blastem(sources: dict[str, Source]) -> list[Record]:
    src = sources[f"{GENERATORS}/Blastem.Generator.cs"]
    helper = src.find(
        r"private static void SetBiosPath\(\w+ (\w+), string (\w+), string (\w+), string (\w+)\)",
        "SetBiosPath",
    )
    body = src.block_at(helper.end())
    node, key, folder, name = helper.groups()
    src.find(
        rf"string (\w+) = Path\.Combine\({folder}, {name}\);\s*if \(File\.Exists\(\1\)\)\s*{node}\[{key}\] = \1;",
        "SetBiosPath guarded write",
        body[0],
        body[1],
    )
    section = src.find(r'var (\w+) = cfg\.GetOrCreateSection\("(system)"\);', "system section")
    config = src.find(
        r'string targetCfg = Path\.Combine\(path, "([^"]+)"\);', "BlastEm config file"
    )
    records = []
    for call in src.find_all(
        r'SetBiosPath\((\w+), "(\w+)", (\w+), "([^"]+)"\);', "SetBiosPath call"
    ):
        root = render(src, call.group(3), _method_of(src, call.start())[0], call.start())
        if root is None or root[0] != "bios":
            raise LauncherPatternMissing(
                src.path, f"bios folder passed at line {src.line(call.start())}"
            )
        records.append(
            launcher_record(
                "blastem",
                "standalone",
                "fixed_name",
                [call.group(4)],
                path_parts(
                    src,
                    *root[1],
                    src.lines(call.start(), call.end()),
                    (src.line(helper.start()), src.lines(*body)[1]),
                ),
                case_insensitive=True,
                search_dir="bios",
                passes_to=f"{config.group(1)} {section.group(2)}.{call.group(2)}, only if the file exists",
                fails_when_missing=f"info log, {call.group(2)} left as it is",
            )
        )
    return covered_records(src, records)


def value_writes(
    src: Source, emulator: str, build: str, start: int = 0, end: int | None = None
) -> list[Record]:
    """Configuration values that resolve under the bios folder.

    A directory becomes passes_path, a file fixed_name, guarded or not by a
    File.Exists on the variable it writes.
    """
    code = _code(src)
    records = []
    for write in re.compile(r"(\w+)\.WriteValue\(").finditer(
        code, start, len(code) if end is None else end
    ):
        args = _split_top(_call_args(src, write.end() - 1), ",")
        if len(args) != 3 or not re.fullmatch(rf"@?{STRING}|null", args[0]):
            continue
        key_literal = re.fullmatch(STRING, args[1])
        if key_literal is None:
            continue
        writer, section, value = write.group(1), args[0].lstrip("@"), args[2]
        key = _unescape(key_literal.group(1))
        method = _method_of(src, write.start())
        rendered = render(src, value, method[0], write.start())
        if rendered is None or not rendered[0].startswith("bios"):
            continue
        conditions, returns = when(src, write.start())
        section = _unescape(section[1:-1]) if section != "null" else ""
        target = f"{config_label(src, write.start(), writer)} " + (
            f"[{section}] {key}" if section else key
        )
        span = src.lines(
            _statement_start(src, write.start()),
            write.end() + len(_call_args(src, write.end() - 1)),
        )
        ref = path_parts(src, *returns, *rendered[1], span)
        depends = ", ".join(conditions) or None
        folder, _, name = rendered[0].rpartition("/")
        if "." not in name or ", " in rendered[0]:
            records.append(
                launcher_record(
                    emulator,
                    build,
                    "passes_path",
                    [],
                    ref,
                    search_dir=rendered[0],
                    passes_to=f"{target} = {rendered[0]}",
                    fails_when_missing=False,
                    depends_on_option=depends,
                )
            )
            continue
        variable = value.strip()
        guarded = any(c == f"File.Exists({variable})" for c in conditions)
        if guarded:
            depends = ", ".join(c for c in conditions if c != f"File.Exists({variable})") or None
        records.append(
            launcher_record(
                emulator,
                build,
                "fixed_name",
                [name],
                ref,
                case_insensitive=True,
                search_dir=folder,
                passes_to=target
                + (
                    ", only if the file exists"
                    if guarded
                    else ", written without an existence check"
                ),
                fails_when_missing=f"{key} not written"
                if guarded
                else "path written without an existence check",
                depends_on_option=depends,
            )
        )
    return records


def dolphin(sources: dict[str, Source]) -> list[Record]:
    src = sources[f"{GENERATORS}/Dolphin.Generator.cs"]
    records = value_writes(src, "dolphin", "standalone")
    if not records:
        raise LauncherPatternMissing(src.path, "GBA BIOS write")
    method = src.find(r"private void CopySegaBoot\(string path\)", "CopySegaBoot")
    body = src.block_at(method.end())
    target = src.find(
        r"string target = (Path\.Combine\(path, [^;]+\));", "segaboot target", body[0], body[1]
    )
    array = src.find(
        r"string\[\] candidates = new string\[\]\s*\{", "segaboot candidates", body[0], body[1]
    )
    block = src.block_at(array.end() - 1)
    names = []
    for item in _split_top(src.text[block[0] + 1 : block[1] - 1].strip(), ","):
        rendered = render(src, item, body[0], block[0])
        if rendered is None or not rendered[0].startswith("bios/"):
            raise LauncherPatternMissing(src.path, f"segaboot candidate {item}")
        names.append(rendered[0][len("bios/") :])
    src.find(
        r"candidates\.FirstOrDefault\(f => File\.Exists\(f\)\)",
        "first existing candidate",
        block[1],
        body[1],
    )
    warning = src.find(r'Warning\("([^"]+)"\);', "segaboot warning", block[1], body[1])
    src.find(
        r"if \(dst\.Exists && dst\.Length == src\.Length && dst\.LastWriteTimeUtc >= src\.LastWriteTimeUtc\)",
        "up-to-date check",
        block[1],
        body[1],
    )
    call = src.find(r"CopySegaBoot\(path\);", "CopySegaBoot call")
    conditions, returns = when(src, call.start())
    destination = render(src, target.group(1), body[0], target.start())
    records.append(
        launcher_record(
            "dolphin",
            "standalone",
            "copies",
            names,
            path_parts(
                src,
                *returns,
                src.lines(_statement_start(src, call.start()), call.end()),
                src.lines(method.start(), body[1]),
            ),
            case_insensitive=True,
            search_dir="bios",
            passes_to=destination[0] if destination else target.group(1),
            fails_when_missing=f"warning '{_unescape(warning.group(1))}' when the target is absent too",
            depends_on_option=joined(
                *conditions, "first name found",
                "the target is absent, smaller or older",
            ),
        )
    )
    return covered_records(src, records, skip=(r"DolphinTool\.exe",))


def raine(sources: dict[str, Source]) -> list[Record]:
    src = sources[f"{GENERATORS}/Raine.Generator.cs"]
    records = value_writes(src, "raine", "standalone")
    if not any(r["kind"] == "fixed_name" for r in records):
        raise LauncherPatternMissing(src.path, "neocd_bios write")
    return covered_records(src, records)


def gsplus(sources: dict[str, Source]) -> list[Record]:
    """The first of the names GSplus accepts that the bios folder holds, written
    as its ROM path. Without one the key is left alone and GSplus searches
    beside its executable."""
    src = sources[f"{GENERATORS}/GsPlus.Generator.cs"]
    listed = src.find(
        r"static readonly string\[\] (\w+) = new string\[\] \{ ((?:\"[^\"]+\"(?:, )?)+) \};",
        "ROM names",
    )
    root = src.find(r"string (\w+) = AppConfig\.GetFullPath\(\"bios\"\);", "bios folder")
    first = src.find(
        rf"string (\w+) = {listed.group(1)}\s*\.Select\(n => Path\.Combine\({root.group(1)}, n\)\)"
        r"\s*\.FirstOrDefault\(File\.Exists\);",
        "first name present",
    )
    write = src.find(
        rf'(\w+)\.WriteValue\(null, "(\w+)", {first.group(1)}\);', "ROM path write"
    )
    conditions, returns = when(src, write.start())
    # The test on the name found is the selection itself, not a condition.
    conditions = [c for c in conditions if first.group(1) not in c]
    target = f"{config_label(src, write.start(), write.group(1))} {write.group(2)}"
    record = launcher_record(
        "gsplus",
        "standalone",
        "names_searched",
        _strings(listed.group(2)),
        path_parts(
            src,
            *returns,
            src.lines(listed.start(), listed.end()),
            src.lines(root.start(), root.end()),
            src.lines(first.start(), write.end()),
        ),
        case_insensitive=True,
        search_dir="bios",
        passes_to=f"{target} = <first found>",
        fails_when_missing=False,
        depends_on_option=", ".join(conditions) or None,
    )
    return covered_records(src, [record])


def rpcs3(sources: dict[str, Source]) -> list[Record]:
    src = sources[f"{GENERATORS}/Rpcs3.Generator.cs"]
    marker = src.find(
        rf"string (\w+) = (Path\.Combine\(path, [^;]+\));\s*string \w+ = {BIOS_ROOT};",
        "installed firmware marker",
    )
    pup = src.find(
        rf'string (\w+) = {BIOS_ROOT};\s*string (\w+) = Path\.Combine\(\1, "([^"]+)"\);',
        "PS3 update file",
        marker.start(),
    )
    method = _method_of(src, pup.start())
    check = src.find(
        rf"if \(!File\.Exists\({marker.group(1)}\) && !File\.Exists\({pup.group(2)}\)\)\s*throw",
        "firmware check",
        pup.end(),
    )
    message, _ = _throw_message(src, check.start(), method[1])
    install = src.find(
        rf'"(--\w+)",\s*StringExtensions\.QuoteString\({pup.group(2)}\)',
        "firmware install argument",
        check.end(),
    )
    returned = src.find(r"return new ProcessStartInfo\(\)", "install launch", install.end())
    installed = render(src, marker.group(2), method[0], marker.start())
    record = launcher_record(
        "rpcs3",
        "standalone",
        "fixed_name",
        [pup.group(3)],
        path_parts(src, src.lines(marker.start(), src.block_at(returned.end())[1])),
        case_insensitive=True,
        search_dir="bios",
        passes_to=(
            f"command line {install.group(1)} <bios>/{pup.group(3)}, launched instead of the game"
        ),
        fails_when_missing=message,
        depends_on_option=f"{installed[0] if installed else marker.group(2)} absent",
    )
    return covered_records(src, [record])


def bizhawk_gb(sources: dict[str, Source]) -> list[Record]:
    """Game Boy BIOS switches: the core reads the file only when the launcher saw it."""
    src = sources[f"{GENERATORS}/Bizhawk.CoreOptions.cs"]
    config = sources[f"{GENERATORS}/Bizhawk.Generator.cs"].find(
        r'string configFile = Path\.Combine\(path, "([^"]+)"\);', "BizHawk config file"
    )
    code = _code(src)
    records = []
    for flag in src.find_all(
        r'if \(File\.Exists\((\w+)\) && SystemConfig\.getOptBoolean\("(\w+)"\)\)\s*'
        r'(\w+)\["(\w+)"\] = "(\w+)";\s*else\s*\3\["\4"\] = "(\w+)";',
        "GB BIOS switch",
    ):
        var, option, node, key, on, off = flag.groups()
        method = _method_of(src, flag.start())
        core = src.find(r'if \(core != "(\w+)"\)\s*return;', "core guard", method[0], flag.start())
        container = src.find(
            rf'var {node} = \w+\.GetOrCreateContainer\("([^"]+)"\);',
            "sync settings container",
            method[0],
            flag.start(),
        )
        default = src.find(
            rf'string {var} = Path\.Combine\({BIOS_ROOT}, "([^"]+)"\);',
            "default GB BIOS",
            method[0],
            flag.start(),
        )
        chosen = list(
            re.compile(
                rf'(?:else )?if \(system == "(\w+)"\)\s*'
                rf'{var} = Path\.Combine\({BIOS_ROOT}, "([^"]+)"\);'
            ).finditer(code, default.end(), flag.start())
        )
        if code[default.end() : flag.start()].count(f"{var} =") != len(chosen):
            raise LauncherPatternMissing(
                src.path, f"{var} choice at line {src.line(default.start())}"
            )
        ref = path_parts(
            src, src.lines(core.start(), core.end()), src.lines(default.start(), flag.end())
        )
        others = " && ".join(f'system != "{m.group(1)}"' for m in chosen)
        slots = [("other systems", default.group(1), others)]
        slots += [(m.group(1), m.group(2), f'system == "{m.group(1)}"') for m in chosen]
        for slot, name, system in slots:
            records.append(
                launcher_record(
                    "bizhawk",
                    "standalone",
                    "fixed_name",
                    [name],
                    ref,
                    slot=slot,
                    case_insensitive=True,
                    search_dir="bios",
                    passes_to=(
                        f"{config.group(1)} {container.group(1)} {key} = {on},"
                        " only if the file exists, the path itself is not written"
                    ),
                    fails_when_missing=f"{key} = {off}",
                    depends_on_option=", ".join(
                        c for c in (f'core == "{core.group(1)}"', f"{option} on", system) if c
                    ),
                )
            )
    return covered_records(
        src,
        records,
        # A DSi NAND boot copies the game itself to bios/dsi_nand.bin.
        skip=(r'string biosPath = AppConfig\.GetFullPath\("bios"\);',),
    )
