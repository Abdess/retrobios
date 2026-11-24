"""RetroBat generators that copy BIOS files or write a folder under bios into a configuration."""

from __future__ import annotations

import re

from .csharp_source import (
    LauncherPatternMissing,
    Record,
    Source,
    _array_at,
    _code,
    _method_of,
    _split_top,
    _strings,
    _throw_message,
    source_ref,
)
from .retrobat_config_files import value_writes
from .retrobat_generators import GENERATORS, TARGET_ABSENT, BIOS_ROOT, joined, launcher_record
from .retrobat_render import config_label, covered_records, path_parts, render, when
from model.launcherrecords import join_emulators


def _copies_if_absent(
    src: Source, emulator: str, build: str, within: tuple[int, int] | None = None
) -> list[Record]:
    """File.Copy(source, target) when the target is absent and the source exists,
    one record per method and target folder."""
    code = _code(src)
    start, end = within or (0, len(code))
    groups: dict[
        tuple[tuple[int, int], str], list[tuple[int, str, str, list[tuple[int, int]]]]
    ] = {}
    for copy in re.compile(
        r"if \(!File\.Exists\((\w+)\) && File\.Exists\((\w+)\)\)\s*(?:\{\s*)?try \{ File\.Copy\(\2, \1\); \}"
    ).finditer(code, start, end):
        target_var, source_var = copy.groups()
        method = _method_of(src, copy.start())
        source = render(src, source_var, method[0], copy.start())
        target = render(src, target_var, method[0], copy.start())
        if source is None or target is None or not source[0].startswith("bios/"):
            raise LauncherPatternMissing(src.path, f"copy at line {src.line(copy.start())}")
        folder, _, name = source[0].rpartition("/")
        destination = target[0].rpartition("/")[0]
        spans = [*source[1], *target[1], src.lines(copy.start(), copy.end())]
        groups.setdefault((method, destination), []).append((copy.start(), folder, name, spans))
    records = []
    for (_, destination), copies in groups.items():
        folders = {folder for _, folder, _, _ in copies}
        if len(folders) != 1:
            raise LauncherPatternMissing(src.path, f"one source folder for {destination}")
        conditions, returns = when(src, copies[0][0])
        records.append(
            launcher_record(
                emulator,
                build,
                "copies",
                [name for _, _, name, _ in copies],
                path_parts(src, *returns, *[s for c in copies for s in c[3]]),
                case_insensitive=True,
                search_dir=folders.pop(),
                passes_to=f"{destination}/<name>",
                fails_when_missing=False,
                depends_on_option=joined(*conditions, TARGET_ABSENT),
            )
        )
    if not records:
        raise LauncherPatternMissing(src.path, "copy when the target is absent")
    return records


def dosbox_copies(sources: dict[str, Source]) -> list[Record]:
    """MT-32 ROMs and SoundFonts copied from bios/scummvm/extra."""
    return [
        record
        for path, emulator in (
            (f"{GENERATORS}/DosBoxPure.Generator.cs", "dosbox-pure"),
            (f"{GENERATORS}/DosBoxStaging.Generator.cs", "dosbox-staging"),
        )
        for record in covered_records(
            sources[path], _copies_if_absent(sources[path], emulator, "standalone")
        )
    ]


def capsimg(sources: dict[str, Source]) -> list[Record]:
    """capsimg.dll copied next to RetroArch for the cores that read .ipf images."""
    src = sources[f"{GENERATORS}/LibRetro.Generator.cs"]
    cores = src.find(
        r"static readonly List<string> (capsimgCore) = new List<string>\(\) \{", "capsimg core list"
    )
    names, core_lines = _array_at(src, cores.end() - 1)
    gate = src.find(
        rf"if \(core != null && rom != null && {cores.group(1)}\.Contains\(core\) && "
        r'Path\.GetExtension\(rom\)\.ToLowerInvariant\(\) == "([^"]+)"\)',
        "capsimg gate",
    )
    block = src.block_at(gate.end())
    [record] = _copies_if_absent(src, join_emulators(names), "libretro", block)
    record["source_ref"] = source_ref(
        (src.path, [(src.line(cores.start()), core_lines[1]), src.statement_span(block)])
    )
    record["depends_on_option"] = joined(
        f'core in {cores.group(1)}, rom extension "{gate.group(1)}"', TARGET_ABSENT
    )
    return [record]


def tsugaru(sources: dict[str, Source]) -> list[Record]:
    """The FM Towns ROM folder, chosen by where FMT_SYS.ROM is."""
    src = sources[f"{GENERATORS}/Tsugaru.Generator.cs"]
    code = _code(src)
    first = src.find(
        rf'if \(Directory\.Exists\((Path\.Combine\({BIOS_ROOT}, "[^"]+"\))\)\)\s*(\w+) = \1;',
        "first FM Towns folder",
    )
    var = first.group(2)
    method = _method_of(src, first.start())
    unset = src.find(rf"string {var} = null;", f"{var} declaration", method[0], first.start())
    folders = [render(src, first.group(1), method[0], first.start())]
    names, end = set(), first.end()
    step = re.compile(
        rf'\s*if \(!File\.Exists\(Path\.Combine\({var}, "([^"]+)"\)\)\)\s*{var} = ([^;]+);'
    )
    while more := step.match(code, end):
        names.add(more.group(1))
        folders.append(render(src, more.group(2), method[0], more.start()))
        end = more.end()
    final = re.compile(
        rf'\s*if \(!File\.Exists\(Path\.Combine\({var}, "([^"]+)"\)\)\)\s*\{{'
    ).match(code, end)
    if final is None or any(folder is None for folder in folders):
        raise LauncherPatternMissing(src.path, "FMT_SYS.ROM folder chain")
    names.add(final.group(1))
    block = src.block_at(final.end() - 1)
    info = re.search(r'Info\("([^"]+)"\);\s*return null;', code[block[0] : block[1]])
    cmos = src.find(
        rf'commandArray\.Add\({var}\);\s*commandArray\.Add\("(-\w+)"\);\s*'
        rf'commandArray\.Add\(Path\.Combine\({var}, "([^"]+)"\)\);',
        "folder and CMOS arguments",
        block[1],
        method[1],
    )
    if info is None or len(names) != 1:
        raise LauncherPatternMissing(src.path, "FMT_SYS.ROM missing branch")
    record = launcher_record(
        "tsugaru",
        "standalone",
        "passes_path",
        sorted(names),
        path_parts(
            src, src.lines(unset.start(), unset.end()), src.lines(first.start(), cmos.end())
        ),
        case_insensitive=True,
        search_dir=", then ".join(folder[0] for folder in folders if folder),
        passes_to=(
            "command line: first argument <folder found>,"
            f" {cmos.group(1)} <folder found>/{cmos.group(2)}"
        ),
        fails_when_missing=f"info '{info.group(1)}', no launch",
        depends_on_option=(
            f"{folders[0][0] if folders[0] else ''} is a directory"
            f" ({var} stays null otherwise when {final.group(1)} is checked)"
        ),
    )
    return covered_records(src, [record])


def _indexer_writes(src: Source, emulator: str, writer: str) -> list[Record]:
    """writer["key"] = value, for each value that resolves to a folder under bios."""
    code = _code(src)
    records = []
    for write in re.compile(rf'\b{writer}\["([^"]+)"\] = ([^;]+);').finditer(code):
        method = _method_of(src, write.start())
        rendered = render(src, src.text[write.start(2) : write.end(2)], method[0], write.start())
        if rendered is None or not rendered[0].startswith("bios"):
            continue
        conditions, returns = when(src, write.start())
        records.append(
            launcher_record(
                emulator,
                "standalone",
                "passes_path",
                [],
                path_parts(src, *returns, *rendered[1], src.lines(write.start(), write.end())),
                search_dir=rendered[0],
                passes_to=(
                    f"{config_label(src, write.start(), writer)} {write.group(1)} = {rendered[0]}"
                ),
                fails_when_missing=False,
                depends_on_option=", ".join(conditions) or None,
            )
        )
    if not records:
        raise LauncherPatternMissing(src.path, f"{writer}[...] write of a bios folder")
    return records


def eka2l1(sources: dict[str, Source]) -> list[Record]:
    src = sources[f"{GENERATORS}/Eka2l1.Generator.cs"]
    return covered_records(src, _indexer_writes(src, "eka2l1", "yml"))


def fbneo(sources: dict[str, Source]) -> list[Record]:
    src = sources[f"{GENERATORS}/Fbneo.Generator.cs"]
    return covered_records(src, _indexer_writes(src, "fbneo", "cfg"))


def snes9x(sources: dict[str, Source]) -> list[Record]:
    src = sources[f"{GENERATORS}/Snes9x.Generator.cs"]
    entry = src.find(rf'\{{ "([^"]+)", (Path\.Combine\({BIOS_ROOT}\)) \}}', "bios folder entry")
    loop = src.find(
        r"foreach \(KeyValuePair<string, string> pair in (\w+)\)", "path loop", entry.end()
    )
    body = src.block_at(loop.end())
    write = src.find(
        r'(\w+)\.WriteValue\(@?"([^"]+)", pair\.Key, pair\.Value\);',
        "path write",
        body[0],
        body[1],
    )
    config = config_label(src, write.start(), write.group(1))
    record = launcher_record(
        "snes9x",
        "standalone",
        "passes_path",
        [],
        path_parts(src, src.lines(entry.start(), entry.end()), src.lines(loop.start(), body[1])),
        search_dir="bios",
        passes_to=f"{config} [{write.group(2)}] {entry.group(1)} = bios",
        fails_when_missing=False,
    )
    return covered_records(src, [record])


def value_folders(sources: dict[str, Source]) -> list[Record]:
    """Configuration keys given a folder under bios."""
    records = []
    for path, emulator, skip in (
        # VMU saves are synchronised with the libretro core's bios/dc.
        (f"{GENERATORS}/Flycast.Generator.cs", "flycast", (r"string libretroPath = ",)),
        (f"{GENERATORS}/ScummVm.Generator.cs", "scummvm", ()),
    ):
        found = value_writes(sources[path], emulator, "standalone")
        if not found:
            raise LauncherPatternMissing(path, "bios folder write")
        records += covered_records(sources[path], found, skip=skip)
    return records


def demul(sources: dict[str, Source]) -> list[Record]:
    src = sources[f"{GENERATORS}/Demul.Generator.cs"]
    listing = src.find(r"var (\w+) = new List<string>\s*\{", "rom paths list")
    block = src.block_at(listing.end() - 1)
    loop = src.find(
        rf"for \(int i = 0; i < {listing.group(1)}\.Count; i\+\+\)\s*"
        rf'(\w+)\.WriteValue\("(\w+)", "(\w+)" \+ i, {listing.group(1)}\[i\]\);',
        "rom paths write",
        block[1],
    )
    method = _method_of(src, listing.start())
    config = config_label(src, loop.start(), loop.group(1))
    records = []
    for index, item in enumerate(_split_top(src.text[block[0] + 1 : block[1] - 1].strip(), ",")):
        rendered = render(src, item, method[0], listing.start())
        if rendered is None:
            raise LauncherPatternMissing(src.path, f"rom path {item}")
        if not rendered[0].startswith("bios"):
            continue
        records.append(
            launcher_record(
                "demul",
                "standalone",
                "passes_path",
                [],
                path_parts(
                    src,
                    *rendered[1],
                    src.lines(listing.start(), block[1]),
                    src.lines(loop.start(), loop.end()),
                ),
                search_dir=rendered[0],
                passes_to=f"{config} [{loop.group(2)}] {loop.group(3)}{index} = {rendered[0]}",
                fails_when_missing=False,
            )
        )
    return covered_records(src, records)


def bsyndrome(sources: dict[str, Source]) -> list[Record]:
    src = sources[f"{GENERATORS}/PortsLauncher.Configuration.cs"]
    records = []
    for arg in src.find_all(
        r'string (\w+) = "(--\w+)=\\"" \+ (\w+) \+ "\\"";\s*commandArray\.Add\(\1\);',
        "path argument",
    ):
        method = _method_of(src, arg.start())
        rendered = render(src, arg.group(3), method[0], arg.start())
        if rendered is None or not rendered[0].startswith("bios"):
            continue
        conditions, returns = when(src, arg.start())
        records.append(
            launcher_record(
                "bsyndrome",
                "standalone",
                "passes_path",
                [],
                path_parts(src, *returns, *rendered[1], src.lines(arg.start(), arg.end())),
                search_dir=rendered[0],
                passes_to=f"command line {arg.group(2)}={rendered[0]}",
                fails_when_missing=False,
                depends_on_option=", ".join(conditions) or None,
            )
        )
    if not records:
        raise LauncherPatternMissing(src.path, "bios folder argument")
    return covered_records(src, records)


def xm6pro(sources: dict[str, Source]) -> list[Record]:
    src = sources[f"{GENERATORS}/Xm6pro.Generator.cs"]
    method = src.find(r"private void CopyBiosFiles\(string (\w+)\)", "CopyBiosFiles")
    body = src.block_at(method.end())
    loop = src.find(r"foreach \(string (\w+) in (\w+)\)", "copy loop", body[0], body[1])
    table = src.find(
        rf"static readonly string\[\] {loop.group(2)} = new string\[\] \{{", "X68000 BIOS list"
    )
    names, lines = _array_at(src, table.end() - 1)
    copy = src.find(
        rf"string (\w+) = Path\.Combine\((\w+), {loop.group(1)}\);\s*"
        rf"string (\w+) = Path\.Combine\({method.group(1)}, {loop.group(1)}\);\s*"
        r"if \(File\.Exists\(\1\) && !File\.Exists\(\3\)\)",
        "copy when the target is absent",
        loop.end(),
        body[1],
    )
    folder = render(src, copy.group(2), body[0], copy.start())
    if folder is None or not folder[0].startswith("bios/"):
        raise LauncherPatternMissing(src.path, "keropi folder")
    conditions, _ = when(src, loop.start())
    record = launcher_record(
        "xm6pro",
        "standalone",
        "copies",
        names,
        path_parts(src, (src.line(table.start()), lines[1]), src.lines(method.start(), body[1])),
        case_insensitive=True,
        search_dir=folder[0],
        passes_to="<emulator>/<name>",
        fails_when_missing=False,
        depends_on_option=joined(*conditions, TARGET_ABSENT),
    )
    return covered_records(src, [record])


def arcadeduck(sources: dict[str, Source]) -> list[Record]:
    """The BIOS archive ArcadeDuck's own database names for the game's system."""
    src = sources[f"{GENERATORS}/ArcadeDuck.Generator.cs"]
    db = sources[f"{GENERATORS}/ArcadeDuck.Database.cs"]
    database = db.find(
        r'string dbFile = Path\.Combine\(emulatorPath, ((?:"[^"]+"(?:, )?)+)\);', "database file"
    )
    lookup = db.find(r"public string GetBiosArchive\(string systemId\)", "GetBiosArchive")
    lookup_body = db.block_at(lookup.end())
    fixed = db.find(
        r'if \(systemId == "(\w+)"\)\s*return "([^"]+)";',
        "built-in archive",
        lookup_body[0],
        lookup_body[1],
    )
    method = src.find(
        r"private string GetBiosPath\(string rom, string biosRoot, bool isChd\)", "GetBiosPath"
    )
    body = src.block_at(method.end())
    src.find(
        r"string romDir = Path\.GetDirectoryName\(Path\.GetFullPath\(rom\)\);\s*"
        r"var candidates = new List<string> \{ romDir \};",
        "game folder first",
        body[0],
        body[1],
    )
    src.find(
        r"if \(isChd && Directory\.GetParent\(romDir\) != null\)\s*"
        r"candidates\.Add\(Directory\.GetParent\(romDir\)\.FullName\);",
        "folder above a CHD-only set second",
        body[0],
        body[1],
    )
    src.find(r"candidates\.Add\(biosRoot\);", "bios folder last", body[0], body[1])
    message, _ = _throw_message(src, body[0], body[1])
    root = src.find(rf"string biosPath = {BIOS_ROOT};", "bios root")
    write = src.find(r'ini\.WriteValue\("(\w+)", "(\w+)", biosPath\);', "SearchDirectory write")
    config = config_label(src, write.start(), "ini")
    target = f"{config} [{write.group(1)}] {write.group(2)}"
    database_file = "/".join(_strings(database.group(1)))
    ref = source_ref(
        (
            src.path,
            [
                src.lines(root.start(), root.end()),
                src.lines(method.start(), body[1]),
                src.lines(write.start(), write.end()),
            ],
        ),
        (
            db.path,
            [db.lines(database.start(), database.end()), db.lines(fixed.start(), fixed.end())],
        ),
    )
    records = [
        launcher_record(
            "arcadeduck",
            "standalone",
            "names_searched",
            [f"<bios archive of the game's system in {database_file}>"],
            ref,
            case_insensitive=False,
            search_dir="<rom directory>, then the folder above it for a CHD-only set, then bios",
            passes_to=f"{target} = <folder found>",
            fails_when_missing=message,
        ),
        launcher_record(
            "arcadeduck",
            "standalone",
            "names_searched",
            [fixed.group(2)],
            ref,
            slot=fixed.group(1),
            case_insensitive=False,
            search_dir="<rom directory>, then the folder above it for a CHD-only set, then bios",
            passes_to=f"{target} = <folder found>",
            fails_when_missing=message,
            depends_on_option=f"{database_file} names no archive for {fixed.group(1)}",
        ),
        launcher_record(
            "arcadeduck",
            "standalone",
            "passes_path",
            [],
            ref,
            search_dir="bios",
            passes_to=f"{target} = bios",
            fails_when_missing=False,
            depends_on_option="no bios archive known for the game's system",
        ),
    ]
    return covered_records(src, records)
