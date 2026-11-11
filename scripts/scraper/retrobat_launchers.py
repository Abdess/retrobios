"""RetroBat's launcher layer, read from emulatorLauncher's C# generators.

emulatorLauncher decides, per emulator, which file names it looks for in the
BIOS directory, in what order, and what it writes into the emulator's
configuration. The C# is read as text, never compiled: each extractor targets
one construct the generators use and raises LauncherPatternMissing when that
construct is gone, so an upstream rewrite stops the scrape instead of
publishing an empty list.
"""

from __future__ import annotations

import bisect
import re
from collections.abc import Callable, Iterator

try:
    from .shell_launchers import is_feature_ref, split_ref
except ImportError:
    from shell_launchers import is_feature_ref, split_ref  # type: ignore[no-redef]

GENERATORS = "emulatorLauncher/Generators"
FEATURES = ".emulationstation/es_features.cfg"

SOURCE_FILES = (
    f"{GENERATORS}/Amiberry.Generator.cs",
    f"{GENERATORS}/ArcadeDuck.Database.cs",
    f"{GENERATORS}/ArcadeDuck.Generator.cs",
    f"{GENERATORS}/Ares.Generator.cs",
    f"{GENERATORS}/Bizhawk.CoreOptions.cs",
    f"{GENERATORS}/Bizhawk.Generator.cs",
    f"{GENERATORS}/Blastem.Generator.cs",
    f"{GENERATORS}/Citron.Generator.cs",
    f"{GENERATORS}/Cxbx.Generator.cs",
    f"{GENERATORS}/Demul.Generator.cs",
    f"{GENERATORS}/Desmume.Generator.cs",
    f"{GENERATORS}/Dolphin.Generator.cs",
    f"{GENERATORS}/DosBoxPure.Generator.cs",
    f"{GENERATORS}/DosBoxStaging.Generator.cs",
    f"{GENERATORS}/Duckstation.Generator.cs",
    f"{GENERATORS}/Eden.Generator.cs",
    f"{GENERATORS}/Eka2l1.Generator.cs",
    f"{GENERATORS}/Fbneo.Generator.cs",
    f"{GENERATORS}/Flycast.Generator.cs",
    f"{GENERATORS}/GsPlus.Generator.cs",
    f"{GENERATORS}/Hatari.Generator.cs",
    f"{GENERATORS}/Jgenesis.Generator.cs",
    f"{GENERATORS}/Jzintv.Generator.cs",
    f"{GENERATORS}/KegaFusion.Generator.cs",
    f"{GENERATORS}/Kronos.Generator.cs",
    f"{GENERATORS}/LibRetro.CoreOptions.cs",
    f"{GENERATORS}/LibRetro.Generator.cs",
    f"{GENERATORS}/Mame64.Generator.cs",
    f"{GENERATORS}/Mednafen.Generator.cs",
    f"{GENERATORS}/MelonDS.Generator.cs",
    f"{GENERATORS}/Mesen.Generator.cs",
    f"{GENERATORS}/MessSystem.cs",
    f"{GENERATORS}/Mupen64.Generator.cs",
    f"{GENERATORS}/OpenMSX.Generator.cs",
    f"{GENERATORS}/PSXMame.Generator.cs",
    f"{GENERATORS}/Pcsx2.Generator.cs",
    f"{GENERATORS}/Pico8.Generator.cs",
    f"{GENERATORS}/PortsLauncher.Configuration.cs",
    f"{GENERATORS}/Project64.Generator.cs",
    f"{GENERATORS}/Raine.Generator.cs",
    f"{GENERATORS}/Rpcs3.Generator.cs",
    f"{GENERATORS}/Ryujinx.Generator.cs",
    f"{GENERATORS}/SSF.Generator.cs",
    f"{GENERATORS}/ScummVm.Generator.cs",
    f"{GENERATORS}/ShadPS4.Generator.cs",
    f"{GENERATORS}/Snes9x.Generator.cs",
    f"{GENERATORS}/Sudachi.Generator.cs",
    f"{GENERATORS}/Tsugaru.Generator.cs",
    f"{GENERATORS}/Uae.Generator.cs",
    f"{GENERATORS}/Xemu.Generator.cs",
    f"{GENERATORS}/Xm6pro.Generator.cs",
    f"{GENERATORS}/Xroar.Generator.cs",
    f"{GENERATORS}/Yabasanshiro.Generator.cs",
    f"{GENERATORS}/Ymir.Generator.cs",
    f"{GENERATORS}/Yuzu.Generator.cs",
    f"{GENERATORS}/mGBA.Generator.cs",
    FEATURES,
)

BIOS = r'AppConfig\.GetFullPath\("bios"\)'
STRING = r'"((?:[^"\\\n]|\\.)*)"'

Record = dict[str, object]


class LauncherPatternMissing(ValueError):
    """A construct an extractor reads is absent from the launcher source."""

    def __init__(self, path: str, what: str) -> None:
        super().__init__(f"{path}: {what} not found")


class Source:
    """One source file with line lookup and C#-aware brace matching."""

    def __init__(self, path: str, text: str) -> None:
        self.path = path
        self.text = text
        self._starts = [0] + [m.end() for m in re.finditer(r"\n", text)]
        self._blocks: list[tuple[int, int]] | None = None
        self._ends: list[int] | None = None
        self.code: str | None = None
        self.bare: str | None = None

    def line(self, offset: int) -> int:
        return bisect.bisect_right(self._starts, offset)

    def lines(self, start: int, end: int) -> tuple[int, int]:
        return self.line(start), self.line(max(start, end - 1))

    def find(
        self, pattern: str, what: str, start: int = 0, end: int | None = None, flags: int = 0
    ) -> re.Match[str]:
        found = re.compile(pattern, flags).search(
            self.text, start, len(self.text) if end is None else end
        )
        if found is None:
            raise LauncherPatternMissing(self.path, what)
        return found

    def find_all(
        self, pattern: str, what: str, start: int = 0, end: int | None = None
    ) -> list[re.Match[str]]:
        found = list(
            re.compile(pattern).finditer(self.text, start, len(self.text) if end is None else end)
        )
        if not found:
            raise LauncherPatternMissing(self.path, what)
        return found

    def blocks(self) -> list[tuple[int, int]]:
        """Every brace pair, as (offset of "{", offset after "}")."""
        if self._blocks is None:
            self._blocks = []
            stack: list[int] = []
            for offset, char in _code_chars(self.text):
                if char == "{":
                    stack.append(offset)
                elif char == "}" and stack:
                    self._blocks.append((stack.pop(), offset + 1))
        return self._blocks

    def block_at(self, open_offset: int) -> tuple[int, int]:
        """The block opened by the first "{" at or after open_offset."""
        candidates = [b for b in self.blocks() if b[0] >= open_offset]
        if not candidates:
            raise LauncherPatternMissing(self.path, f"block after line {self.line(open_offset)}")
        return min(candidates)

    def enclosing(self, offset: int) -> tuple[int, int]:
        """The innermost block holding offset."""
        holding = [b for b in self.blocks() if b[0] < offset < b[1]]
        if not holding:
            raise LauncherPatternMissing(self.path, f"block around line {self.line(offset)}")
        return max(holding)

    def header(self, block: tuple[int, int]) -> str:
        """The statement that owns a block's opening brace, comments and
        preprocessor lines (#region, #if) removed."""
        if self._ends is None:
            self._ends = [o for o, c in _code_chars(self.text) if c in ";{}"]
        previous = bisect.bisect_left(self._ends, block[0]) - 1
        start = self._ends[previous] + 1 if previous >= 0 else 0
        text = re.sub(r"//[^\n]*|/\*.*?\*/|^[ \t]*#[^\n]*", "", self.text[start : block[0]],
                      flags=re.S | re.M)
        return " ".join(text.split())

    def statement_span(self, block: tuple[int, int]) -> tuple[int, int]:
        """Lines of a block, from the statement that owns its opening brace."""
        first, last = self.lines(*block)
        line_text = self.text[self._starts[first - 1] : block[0]].strip()
        return (first - 1 if not line_text and first > 1 else first), last


def _code_chars(text: str) -> Iterator[tuple[int, str]]:
    """Characters of C# code outside string, char literals and comments."""
    i, n = 0, len(text)
    while i < n:
        char = text[i]
        if text.startswith("//", i):
            i = text.find("\n", i)
            i = n if i < 0 else i
            continue
        if text.startswith("/*", i):
            close = text.find("*/", i + 2)
            i = n if close < 0 else close + 2
            continue
        if text.startswith('@"', i):
            i += 2
            while i < n and not (text[i] == '"' and not text.startswith('""', i)):
                i += 2 if text.startswith('""', i) else 1
            i += 1
            continue
        if char in "\"'":
            i += 1
            while i < n and text[i] != char and text[i] != "\n":
                i += 2 if text[i] == "\\" else 1
            i += 1
            continue
        yield i, char
        i += 1


def _unescape(literal: str) -> str:
    return re.sub(r"\\(.)", lambda m: {"n": "\n", "t": "\t"}.get(m.group(1), m.group(1)), literal)


def _strings(text: str) -> list[str]:
    return [_unescape(m.group(1)) for m in re.finditer(STRING, text)]


def _unique(names: list[str]) -> list[str]:
    return list(dict.fromkeys(names))


def _span(first: int, last: int) -> str:
    return str(first) if first == last else f"{first}-{last}"


def _merge(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Spans sorted, joined when only one line separates them."""
    merged: list[tuple[int, int]] = []
    for first, last in sorted(spans):
        if merged and first <= merged[-1][1] + 2:
            merged[-1] = (merged[-1][0], max(last, merged[-1][1]))
        else:
            merged.append((first, last))
    return merged


def source_ref(*parts: tuple[str, list[tuple[int, int]]]) -> str:
    """path:a-b, c-d for each file, a later range of one file left bare."""
    refs = []
    for path, spans in parts:
        ranges = [_span(*s) for s in _merge(spans)]
        refs.append(f"{path}:{', '.join(ranges)}")
    return ", ".join(refs)


def _array_at(src: Source, offset: int) -> tuple[list[str], tuple[int, int]]:
    """String literals of the array initializer opened at offset."""
    block = src.block_at(offset)
    return _strings(src.text[block[0] : block[1]]), src.lines(*block)


def _call_args(src: Source, open_paren: int) -> str:
    depth = 0
    for offset, char in _code_chars(src.text[open_paren:]):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return src.text[open_paren + 1 : open_paren + offset]
    raise LauncherPatternMissing(src.path, f"closing parenthesis after line {src.line(open_paren)}")


def render_concat(expression: str) -> str:
    """A C# string concatenation as text, each non-literal operand as <operand>."""
    parts, depth, current, in_string = [], 0, "", False
    i = 0
    while i < len(expression):
        char = expression[i]
        if in_string:
            current += char
            if char == "\\":
                current += expression[i + 1]
                i += 1
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
            current += char
        elif char in "([":
            depth += 1
            current += char
        elif char in ")]":
            depth -= 1
            current += char
        elif char == "+" and depth == 0:
            parts.append(current.strip())
            current = ""
        else:
            current += char
        i += 1
    parts.append(current.strip())
    rendered = []
    for part in parts:
        literal = re.fullmatch(STRING, part)
        rendered.append(_unescape(literal.group(1)) if literal else f"<{part}>")
    return "".join(rendered)


def _throw_message(src: Source, start: int, end: int) -> tuple[str, int]:
    found = src.find(r"throw new ApplicationException\(", "ApplicationException", start, end)
    message = render_concat(_call_args(src, found.end() - 1))
    return f"ApplicationException '{message}'", src.line(found.start())


def system_feature_choices(
    src: Source, emulator: str, option: str, system: str
) -> tuple[list[str], tuple[int, int]]:
    """Values es_features.cfg offers for an option of an emulator under one system."""
    text = src.text
    for found in re.finditer(r'<emulator name="([^"]*)"', text):
        if emulator in [name.strip() for name in found.group(1).split(",")]:
            start, end = found.start(), text.find("</emulator>", found.start())
            break
    else:
        raise LauncherPatternMissing(src.path, f"emulator {emulator}")
    for block in re.finditer(r'<system name="([^"]*)">', text[start:end]):
        if system not in [name.strip() for name in block.group(1).split(",")]:
            continue
        scope = start + block.start()
        close = text.find("</system>", scope)
        feature = src.find(
            rf'<feature [^>]*value="{re.escape(option)}"', f"{option} of {system}", scope, close
        )
        stop = text.find("</feature>", feature.end())
        values = re.findall(r'<choice [^>]*value="([^"]*)"', text[feature.end():stop])
        if not values:
            raise LauncherPatternMissing(src.path, f"choices of {option} for {system}")
        return values, src.lines(feature.start(), stop + len("</feature>"))
    raise LauncherPatternMissing(src.path, f"system {system} of {emulator}")


def feature_choices(
    src: Source, emulator: str, option: str, core: str | None = None
) -> tuple[list[str], tuple[int, int]]:
    """Values es_features.cfg offers for an option of one emulator or core."""
    text = src.text
    scope_start, scope_end = 0, len(text)
    for found in re.finditer(r'<emulator name="([^"]*)"', text):
        if emulator in [name.strip() for name in found.group(1).split(",")]:
            scope_start = found.start()
            scope_end = text.find("</emulator>", scope_start)
            break
    else:
        raise LauncherPatternMissing(src.path, f"emulator {emulator}")
    if core is not None:
        found = src.find(
            rf'<core name="{re.escape(core)}"', f"core {core} of {emulator}", scope_start, scope_end
        )
        scope_start, scope_end = found.start(), text.find("</core>", found.start())
    feature = src.find(
        rf'<feature [^>]*value="{re.escape(option)}"',
        f"feature {option} of {emulator}",
        scope_start,
        scope_end,
    )
    close = text.find("</feature>", feature.end())
    values = re.findall(r'<choice [^>]*value="([^"]*)"', text[feature.end() : close])
    if not values:
        raise LauncherPatternMissing(src.path, f"choices of {option}")
    return values, src.lines(feature.start(), close + len("</feature>"))


# A copy record reads `names` from `search_dir` and hands them to the path in
# `passes_to`. When the copy is skipped is a condition of the record.
TARGET_ABSENT = "the target does not exist"


def _joined(*parts: str | None) -> str | None:
    """Conditions of a record, joined, None when there are none."""
    return ", ".join(part for part in parts if part) or None


def _record(
    emulator: str, build: str, kind: str, names: list[str], ref: str, **fields: object
) -> Record:
    record: Record = {"emulator": emulator, "build": build, "kind": kind, "names": names}
    record.update({key: value for key, value in fields.items() if value is not None})
    record["source_ref"] = ref
    return record


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
            _record(
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
        rf'string (\w+) = Path\.Combine\((\w+), "([^"]+)"\);', "hatarib tos.img path",
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
            _record(
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


def xemu(sources: dict[str, Source]) -> list[Record]:
    src = sources[f"{GENERATORS}/Xemu.Generator.cs"]
    features = sources[FEATURES]
    records = []

    mcpx = src.find(
        rf'if \(File\.Exists\(Path\.Combine\({BIOS}, "([^"]+)"\)\)\)\s*(\w+) = Path\.Combine',
        "MCPX boot ROM",
    )
    bootrom = src.find(
        rf'ini\.WriteValue\("([\w.]+)", "(bootrom_path)", "\'" \+ {mcpx.group(2)}',
        "bootrom_path write",
    )
    records.append(
        _record(
            "xemu",
            "standalone",
            "fixed_name",
            [mcpx.group(1)],
            source_ref(
                (
                    src.path,
                    [
                        src.lines(mcpx.start(), mcpx.end()),
                        src.lines(bootrom.start(), bootrom.end()),
                    ],
                )
            ),
            case_insensitive=True,
            search_dir="bios",
            passes_to=f"xemu.toml [{bootrom.group(1)}] {bootrom.group(2)}, only if the file exists",
            fails_when_missing=f"{bootrom.group(2)} not written",
        )
    )

    flash = src.find(r'isOptSet\("(xemu_flashrom)"\)', "xemu_flashrom")
    # The flashrom is written outside a Chihiro launch only.
    chihiro_set = src.find(r"(_chihiro) = \(([^;]+)\);", "Chihiro test")
    chihiro_guard = src.find_all(
        rf"if \(!{chihiro_set.group(1)}\)", "flashrom guard", end=flash.start()
    )[-1]
    flash_default = src.find(
        r'ini\.WriteValue\("([\w.]+)", "(flashrom_path)", "\'" \+ Path\.Combine\(flashromPath, "([^"]+)"\)',
        "flashrom default",
        flash.end(),
    )
    choices, choice_lines = feature_choices(features, "xemu", flash.group(1))
    records.append(
        _record(
            "xemu",
            "standalone",
            "core_option",
            _unique([flash_default.group(3), *choices]),
            source_ref(
                (src.path, [
                    src.lines(chihiro_set.start(), chihiro_set.end()),
                    src.lines(chihiro_guard.start(), flash_default.end()),
                ]),
                (features.path, [choice_lines]),
            ),
            case_insensitive=True,
            search_dir="bios",
            passes_to=(
                f"xemu.toml [{flash_default.group(1)}] {flash_default.group(2)}=<bios>/<value>,"
                f" default {flash_default.group(3)}"
            ),
            fails_when_missing="path written without an existence check",
            depends_on_option=f"{flash.group(1)}, not ({chihiro_set.group(2)})",
        )
    )

    setup = src.find(r"private void SetupChihiroConfiguration\(", "SetupChihiroConfiguration")
    body = src.block_at(setup.end())
    chain = src.find(
        r'string (\w+) = Path\.Combine\(biosPath, ((?:"[^"]+", )*)"([^"]+)"\);\s*'
        r'if \(!File\.Exists\(\1\)\)\s*\1 = Path\.Combine\(biosPath, ((?:"[^"]+", )*)"([^"]+)"\);',
        "Chihiro BIOS chain",
        body[0],
        body[1],
    )
    dirs = [
        "/".join(["bios", *_strings(chain.group(2))]),
        "/".join(["bios", *_strings(chain.group(4))]),
    ]
    bios_write = src.find(
        r'ini\.WriteValue\("([\w.]+)", "(bios_path)"', "Chihiro bios_path", chain.end(), body[1]
    )
    warning = src.find(
        r'else\s*SimpleLogger\.Instance\.Warning\("([^"]+)"\);',
        "Chihiro missing warning",
        bios_write.end(),
        body[1],
    )
    records.append(
        _record(
            "xemu",
            "standalone",
            "names_searched",
            _unique([chain.group(3), chain.group(5)]),
            source_ref((src.path, [src.lines(chain.start(), warning.end())])),
            case_insensitive=True,
            search_dir=", then ".join(dirs),
            passes_to=f"xemu.toml [{bios_write.group(1)}] {bios_write.group(2)}",
            fails_when_missing=f"warning '{warning.group(1)}', {bios_write.group(2)} not written",
        )
    )

    companions = src.find(
        r"foreach \(var f in new\[\] \{", "Chihiro companion files", chain.end(), body[1]
    )
    names, _ = _array_at(src, companions.end() - 1)
    loop = src.block_at(src.block_at(companions.end() - 1)[1])
    records.append(
        _record(
            "xemu",
            "standalone",
            "fixed_name",
            names,
            source_ref((src.path, [(src.line(companions.start()), src.lines(*loop)[1])])),
            case_insensitive=True,
            search_dir="directory of the Chihiro BIOS found",
            passes_to="nothing passed: existence checked only",
            fails_when_missing="warning per missing file",
        )
    )

    board = src.find(
        r'if \((!File\.Exists\(Path\.Combine\(biosDir, "[^"]+"\)\)(?:\s*&&\s*)?)+\)\s*'
        r'SimpleLogger\.Instance\.Warning\("([^"]+)"\);',
        "media board flash names",
        companions.end(),
        body[1],
    )
    records.append(
        _record(
            "xemu",
            "standalone",
            "names_searched",
            re.findall(r'Path\.Combine\(biosDir, "([^"]+)"\)', board.group(0)),
            source_ref((src.path, [src.lines(board.start(), board.end())])),
            case_insensitive=True,
            search_dir="directory of the Chihiro BIOS found",
            passes_to="nothing passed: warning if none exists",
            fails_when_missing=f"warning '{board.group(2)}'",
        )
    )
    return records


def xemu_saves(sources: dict[str, Source]) -> list[Record]:
    """The files the xemu generator keeps below the saves folder.

    An Xbox gets eeprom.bin and xbox_hdd.qcow2 in saves/<system>, written
    from the launcher's own resources when absent, and their paths in
    xemu.toml. A Chihiro keeps chihiro_eeprom.bin there, copied into the
    emulator folder before the run and back after it, and its snapshot
    store.
    """
    src = sources[f"{GENERATORS}/Xemu.Generator.cs"]
    chihiro = src.find(r'(_chihiro) = \(emulator == "([\w-]+)" \|\| system == "(\w+)"\);', "Chihiro switch")
    chihiro_when = f'emulator == "{chihiro.group(2)}" or system == "{chihiro.group(3)}"'
    saves = src.find(
        r'if \(!string\.IsNullOrEmpty\(AppConfig\["saves"\]\) && Directory\.Exists\(AppConfig\.GetFullPath\("saves"\)\)\)'
        r'\s*\{\s*string savePath = Path\.Combine\(AppConfig\.GetFullPath\("saves"\), system\);',
        "Xbox save folder",
    )
    eeprom = src.find(
        r'if \(!File\.Exists\(Path\.Combine\(savePath, "([^"]+)"\)\)\)\s*\{[^{}]*?'
        r'File\.WriteAllBytes\(Path\.Combine\(savePath, "\1"\), Properties\.Resources\.(\w+)\);\s*\}',
        "EEPROM written from resources",
        saves.end(),
    )
    hdd = src.find(
        r'if \(!File\.Exists\(Path\.Combine\(savePath, "([^"]+)"\)\)\)\s*\{[^{}]*?'
        r'File\.WriteAllBytes\(zipFile, Properties\.Resources\.(\w+)\);[^{}]*?Zip\.Extract\(zipFile, savePath\);[^{}]*?\}',
        "hard disk image written from resources",
        eeprom.end(),
    )
    eeprom_key = src.find(
        r'ini\.WriteValue\("([\w.]+)", "(eeprom_path)", "\'" \+ eepromPath', "eeprom_path write"
    )
    hdd_key = src.find(r'ini\.WriteValue\("([\w.]+)", "(hdd_path)", "\'" \+ hddPath', "hdd_path write")
    records = [
        _record(
            "xemu",
            "standalone",
            "fixed_name",
            [eeprom.group(1), hdd.group(1)],
            source_ref(
                (
                    src.path,
                    [
                        src.lines(chihiro.start(), chihiro.end()),
                        src.lines(saves.start(), hdd.end()),
                        src.lines(eeprom_key.start(), eeprom_key.end()),
                        src.lines(hdd_key.start(), hdd_key.end()),
                    ],
                )
            ),
            case_insensitive=True,
            search_dir="saves/<system>",
            passes_to=(
                f"xemu.toml [{eeprom_key.group(1)}] {eeprom_key.group(2)}, {hdd_key.group(2)};"
                f" written from the launcher's {eeprom.group(2)} and {hdd.group(2)} resources"
                " when absent, the disk image unzipped"
            ),
            fails_when_missing="never missing: the launcher writes both",
            depends_on_option=_joined("the saves folder is set and exists", f"not ({chihiro_when})"),
        )
    ]

    setup = src.find(r"private void SetupChihiroEeprom\(string path\)", "SetupChihiroEeprom")
    body = src.block_at(setup.end())
    folder = src.find(
        r'string savePath = Path\.Combine\(AppConfig\.GetFullPath\("saves"\), "(\w+)"\);',
        "Chihiro save folder",
        body[0],
        body[1],
    )
    pair = src.find(
        r'_chihiroEeprom = Path\.Combine\(path, "([^"]+)"\);\s*'
        r'_chihiroEepromSave = Path\.Combine\(savePath, "\1"\);',
        "Chihiro EEPROM pair",
        folder.end(),
        body[1],
    )
    save = src.find(r"private void SaveChihiroEeprom\(\)", "SaveChihiroEeprom")
    save_body = src.block_at(save.end())
    records.append(
        _record(
            "xemu, xemu-chihiro",
            "standalone",
            "copies",
            [pair.group(1)],
            source_ref(
                (
                    src.path,
                    [
                        src.lines(chihiro.start(), chihiro.end()),
                        src.statement_span(body),
                        src.statement_span(save_body),
                    ],
                )
            ),
            case_insensitive=True,
            search_dir=f"saves/{folder.group(1)}",
            passes_to=(
                f"<emulator>/{pair.group(1)}, restored when the saved copy is newer or the"
                " emulator folder holds none, copied back after the run"
            ),
            fails_when_missing=False,
            depends_on_option=chihiro_when,
        )
    )

    store = src.find(
        r'string savePath = Path\.Combine\(AppConfig\.GetFullPath\("saves"\), "(\w+)"\);\s*'
        r'if \(!Directory\.Exists\(savePath\)\) try \{ Directory\.CreateDirectory\(savePath\); \} catch \{ \}\s*'
        r'if \(Directory\.Exists\(savePath\)\)\s*'
        r'ini\.WriteValue\("([\w.]+)", "(\w+)", "\'" \+ Path\.Combine\(savePath, "([^"]+)"\)',
        "Chihiro snapshot store",
    )
    records.append(
        _record(
            "xemu, xemu-chihiro",
            "standalone",
            "fixed_name",
            [store.group(4)],
            source_ref((src.path, [src.lines(chihiro.start(), chihiro.end()),
                                   src.lines(store.start(), store.end())])),
            case_insensitive=True,
            search_dir=f"saves/{store.group(1)}",
            passes_to=f"xemu.toml [{store.group(2)}] {store.group(3)}, created by the emulator",
            fails_when_missing=False,
            depends_on_option=chihiro_when,
        )
    )
    return records


# What the Cxbx generator hands each build: the data folder is the one its
# settings.ini sits in (Cxbx-Reloaded Settings::FindSettingsLocation), which
# the launcher writes beside the binary.
CXBX_DATA_FOLDER = "Settings::GetDataLocation"


def cxbx(sources: dict[str, Source]) -> list[Record]:
    """The folder each Cxbx build runs from, and the EEPROM written there.

    The generator picks the emulator folder by core or emulator name, opens
    settings.ini in it, and for an Xbox writes EEPROM.bin into the
    cxbx-reloaded folder from its own resource when absent.
    """
    src = sources[f"{GENERATORS}/Cxbx.Generator.cs"]
    named = src.find_all(
        r'(?:else )?if \(\(core != null && core == "([\w-]+)"\) \|\| '
        r'\(emulator != null && emulator == "\1"\)\)\s*\{\s*path = AppConfig\.GetFullPath\("([\w-]+)"\);',
        "emulator folder by name",
    )
    fallbacks = src.find_all(
        r'if \(string\.IsNullOrEmpty\(path\)\)\s*path = AppConfig\.GetFullPath\("([\w-]+)"\);',
        "default emulator folder",
    )
    settings = src.find(
        r'IniFile\.FromFile\(Path\.Combine\(path, "(settings\.ini)"\)', "settings.ini beside the binary"
    )
    settings_span = src.lines(settings.start(), settings.end())
    passes_to = (
        f"{CXBX_DATA_FOLDER}, the folder holding {settings.group(1)},"
        " which the launcher writes beside the binary"
    )
    records = []
    for match in named:
        records.append(
            _record(
                match.group(1),
                "standalone",
                "passes_path",
                [],
                source_ref((src.path, [src.lines(match.start(), match.end()), settings_span])),
                search_dir=f'<AppConfig.GetFullPath("{match.group(2)}")>',
                passes_to=passes_to,
                fails_when_missing=False,
            )
        )
    first, *rest = fallbacks
    others = "neither core nor emulator is " + " or ".join(f'"{m.group(1)}"' for m in named)
    records.append(
        _record(
            first.group(1),
            "standalone",
            "passes_path",
            [],
            source_ref(
                (
                    src.path,
                    [src.lines(first.start(), first.end()),
                     *(src.lines(m.start(), m.end()) for m in rest), settings_span],
                )
            ),
            search_dir=f'<AppConfig.GetFullPath("{first.group(1)}")>',
            passes_to=passes_to,
            fails_when_missing=False,
            depends_on_option=_joined(
                others,
                *(f'<AppConfig.GetFullPath("{m.group(1)}")> when "{first.group(1)}" is not set'
                  for m in rest),
            ),
        )
    )
    records.extend(_cxbx_mount(src, [*(m.group(1) for m in named), first.group(1)]))
    eeprom = src.find(
        r'if \(system == "(\w+)"\)\s*\{\s*string (\w+) = Path\.Combine\(AppConfig\.GetFullPath\("([\w-]+)"\), "([^"]+)"\);'
        r'\s*if \(!File\.Exists\(\2\)\)\s*File\.WriteAllBytes\(\2, Properties\.Resources\.(\w+)\);'
        r'\s*WriteXboxEEPROM\(\2\);\s*\}',
        "EEPROM written from resources",
    )
    records.append(
        _record(
            eeprom.group(3),
            "standalone",
            "fixed_name",
            [eeprom.group(4)],
            source_ref((src.path, [src.lines(eeprom.start(), eeprom.end())])),
            case_insensitive=True,
            search_dir=f'<AppConfig.GetFullPath("{eeprom.group(3)}")>',
            passes_to=(
                f"written from the launcher's {eeprom.group(5)} resource when absent,"
                " then its language set: the emulator reads it from its data folder"
            ),
            fails_when_missing="never missing: the launcher writes it",
            depends_on_option=f'system == "{eeprom.group(1)}"',
        )
    )
    return records


def _cxbx_mount(src: Source, emulators: list[str]) -> list[Record]:
    """What the generator needs to mount an .iso before Cxbx opens it: its
    own xbox-iso-vfs.exe, run from the launcher's folder, and the Dokan 2
    runtime installed on the system."""
    iso = src.find(
        r'if \(Path\.GetExtension\(rom\)\.ToLowerInvariant\(\) != "(\.\w+)"\)\s*return rom;',
        "mount for disc images only",
    )
    vfs = src.find(
        r'string (\w+) = Path\.Combine\(Path\.GetDirectoryName\(typeof\(\w+\)\.Assembly\.Location\), "([^"]+)"\);'
        r'\s*if \(!File\.Exists\(\1\)\)\s*throw new ApplicationException\("([^"]+)"\);',
        "mount tool beside the launcher",
        iso.end(),
    )
    dokan = src.find(
        r'string (\w+) = Environment\.GetEnvironmentVariable\("(\w+)"\);.*?'
        r'\1 = Path\.Combine\(\1, "([^"]+)"\);\s*if \(!File\.Exists\(\1\)\)\s*\{[^{}]*?'
        r'throw new ApplicationException\("([^"]+)"\);\s*\}',
        "Dokan runtime check",
        vfs.end(),
        flags=re.S,
    )
    iso_span = src.lines(iso.start(), iso.end())
    when = f'rom extension "{iso.group(1)}"'
    emulator = ", ".join(emulators)
    return [
        _record(
            emulator,
            "standalone",
            "fixed_name",
            [vfs.group(2)],
            source_ref((src.path, [iso_span, src.lines(vfs.start(), vfs.end())])),
            case_insensitive=True,
            search_dir="<emulatorLauncher folder>",
            passes_to="exec",
            fails_when_missing=vfs.group(3),
            depends_on_option=when,
        ),
        _record(
            emulator,
            "standalone",
            "fixed_name",
            [dokan.group(3)],
            source_ref((src.path, [iso_span, src.lines(dokan.start(), dokan.end())])),
            case_insensitive=True,
            search_dir=f"%{dokan.group(2)}%",
            passes_to=f"nothing passed: checked before {vfs.group(2)} mounts the image",
            fails_when_missing=dokan.group(4),
            depends_on_option=when,
        ),
    ]


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


# Generators that write each BIOS path into the emulator's configuration
# only when the file exists: string x = Path.Combine(bios, ..., "name");
# if (File.Exists(x)) ini.WriteValue("section", "key", x).
GUARDED_WRITES = {
    f"{GENERATORS}/Jgenesis.Generator.cs": "jgenesis",
    f"{GENERATORS}/KegaFusion.Generator.cs": "kega-fusion",
    f"{GENERATORS}/MelonDS.Generator.cs": "melonds",
    f"{GENERATORS}/Mupen64.Generator.cs": "mupen64",
    f"{GENERATORS}/Project64.Generator.cs": "project64",
    f"{GENERATORS}/mGBA.Generator.cs": "mgba",
}

_METHOD = re.compile(
    r"(?:(?:public|private|protected|internal|static|override|virtual)\s+)+[\w<>\[\],. ]+\s\w+\s*\("
)
_TRANSPARENT = re.compile(r"(?:using\s*\(.*\)|try)")
_IF = re.compile(r"(?:else\s+)?if\s*\((.*)\)")
_GUARD = re.compile(
    r'if \(File\.Exists\((\w+)\)\)\s*(\w+)\.WriteValue\("([^"]*)", "([^"]+)", ([^;\n]+)\);'
)
_BIOS_ROOT = r'(?:Program\.)?AppConfig\.GetFullPath\("bios"\)'


def _negate(condition: str) -> str:
    """The condition under which an early return is not taken.

    A conjunction of inequalities becomes the disjunction of equalities,
    anything else is wrapped in not (...).
    """
    tests = condition.split(" && ")
    compared = [re.fullmatch(rf"(\w+) != ({STRING})", t) for t in tests]
    if all(compared):
        return " || ".join(f"{m.group(1)} == {m.group(2)}" for m in compared)
    return f"not ({condition})"


Reach = tuple[tuple[int, int], list[str], list[tuple[int, int]]]


def _conditions(src: Source, offset: int) -> Reach | None:
    """The method holding offset, the conditions under which it is reached,
    and the lines of the early returns among them.

    Each enclosing if adds its condition, and an early return at the top of
    the method adds the condition that does not return. None when a block in
    between is not an if, a using or a try: a loop or an else would need its
    own reading.
    """
    enclosing: list[str] = []
    for block in sorted((b for b in src.blocks() if b[0] < offset < b[1]), reverse=True):
        header = src.header(block)
        if _METHOD.match(header):
            returns, spans = [], []
            for found in re.finditer(r"\bif \(", src.text[block[0] : offset]):
                paren = block[0] + found.end() - 1
                if src.enclosing(paren) != block:
                    continue
                cond = _call_args(src, paren)
                tail = re.compile(r"\s*return\b[^;]*;").match(src.text, paren + len(cond) + 2)
                if tail:
                    returns.append(_negate(" ".join(cond.split())))
                    spans.append(src.lines(block[0] + found.start(), tail.end()))
            return block, returns + enclosing[::-1], spans
        condition = _IF.fullmatch(header)
        if condition:
            text = " ".join(condition.group(1).split())
            switch = re.fullmatch(
                r'SystemConfig\.isOptSet\("(\w+)"\) && SystemConfig\.getOptBoolean\("\1"\)', text
            )
            enclosing.append(f"{switch.group(1)} on" if switch else text)
        elif not _TRANSPARENT.fullmatch(header):
            return None
    return None


def _config_name(src: Source, method: tuple[int, int], writer: str) -> str:
    """The file the writer variable opens, read in its method or else in the file."""
    opener = r"(\w+)\s*=\s*(?:\w+\.FromFile|new \w+)\((\w+)"
    declared = {
        m.group(1): "/".join(_strings(m.group(2)))
        for m in re.finditer(
            r'string (\w+) = Path\.Combine\(path, ((?:"[^"]+"(?:, )?)+)\);', src.text
        )
    }
    local = [
        m.group(2)
        for m in re.finditer(opener, src.text[method[0] : method[1]])
        if m.group(1) == writer and m.group(2) in declared
    ]
    if local:
        return declared[local[0]]
    files = {declared[m.group(2)] for m in re.finditer(opener, src.text) if m.group(2) in declared}
    if len(files) != 1:
        raise LauncherPatternMissing(src.path, f"configuration file opened as {writer}")
    return files.pop()


def _root_writes(src: Source, emulator: str) -> list[Record]:
    """Configuration keys that receive the bios folder itself."""
    records = []
    for root in re.finditer(rf"string (\w+) = {_BIOS_ROOT};", src.text):
        root_reach = _conditions(src, root.start())
        if root_reach is None:
            continue
        method = root_reach[0]
        # A folder below the root, `string x = Path.Combine(root, "cdb")`
        # that the method creates or tests as a directory. A file below it
        # is a guarded write's, read by _guarded_write.
        folders = {root.group(1): ("bios", root)}
        for sub in re.compile(
            rf"string (\w+) = Path\.Combine\({root.group(1)}, ((?:{STRING}, )*{STRING})\);"
        ).finditer(src.text, root.end(), method[1]):
            if re.search(
                rf"\b(?:\w*CreateDirectory|Directory\.Exists)\({sub.group(1)}\)",
                src.text[sub.end() : method[1]],
            ):
                folders[sub.group(1)] = ("/".join(["bios", *_strings(sub.group(2))]), sub)
        names = "|".join(map(re.escape, folders))
        for write in re.compile(
            rf'(\w+)\.WriteValue\("([^"]*)", "([^"]+)", (?:"\'" \+ )?({names})(?: \+ "\'")?\);'
        ).finditer(src.text, root.end(), method[1]):
            reached = _conditions(src, write.start())
            if reached is None:
                continue
            writer, section, key, held = write.groups()
            folder, declared = folders[held]
            target = f"[{section}] {key}" if section else key
            records.append(
                _record(
                    emulator,
                    "standalone",
                    "passes_path",
                    [],
                    source_ref(
                        (
                            src.path,
                            [
                                *reached[2],
                                src.lines(root.start(), root.end()),
                                *([src.lines(declared.start(), declared.end())]
                                  if declared is not root else []),
                                src.lines(write.start(), write.end()),
                            ],
                        )
                    ),
                    search_dir=folder,
                    passes_to=f"{_config_name(src, method, writer)} {target} = {folder}",
                    fails_when_missing=False,
                    depends_on_option=", ".join(reached[1]) or None,
                )
            )
    return records


def _guarded_write(src: Source, emulator: str, guard: re.Match[str]) -> Record | None:
    """The record of one guarded write, None when its shape is another one.

    The written value must be the checked path itself (quoted or with its
    separators replaced), the path a literal under the bios folder that
    nothing reassigns before the check, and every block around the write an
    if, a using or a try.
    """
    var, writer, section, key, value = guard.groups()
    if not re.fullmatch(
        rf"(?:{STRING} \+ )?{var}(?:\.Replace\({STRING}, {STRING}\))?(?: \+ {STRING})?",
        value.strip(),
    ):
        return None
    reached = _conditions(src, guard.start())
    if reached is None:
        return None
    method, conditions, returns = reached
    decls = list(
        re.compile(
            rf"string {var} = Path\.Combine\((\w+|{_BIOS_ROOT}), ((?:{STRING}, )*{STRING})\);"
        ).finditer(src.text, method[0], guard.start())
    )
    if not decls or re.search(rf"\b{var}\s*=[^=]", src.text[decls[-1].end() : guard.start()]):
        return None
    decl = decls[-1]
    root = decl.group(1)
    if not re.fullmatch(_BIOS_ROOT, root) and not re.search(
        rf"string {root} = {_BIOS_ROOT};", src.text[method[0] : decl.start()]
    ):
        return None
    *folders, name = _strings(decl.group(2))
    target = f"[{section}] {key}" if section else key
    return _record(
        emulator,
        "standalone",
        "fixed_name",
        [name],
        source_ref(
            (
                src.path,
                [
                    *returns,
                    src.lines(decl.start(), decl.end()),
                    src.lines(guard.start(), guard.end()),
                ],
            )
        ),
        case_insensitive=True,
        search_dir="/".join(["bios", *folders]),
        passes_to=f"{_config_name(src, method, writer)} {target}, only if the file exists",
        fails_when_missing=f"{key} not written",
        depends_on_option=", ".join(conditions) or None,
    )


def guarded_writes_in(src: Source, emulator: str) -> list[Record]:
    """Every guarded write of one generator, then the keys given the bios folder."""
    found = [_guarded_write(src, emulator, guard) for guard in _GUARD.finditer(src.text)]
    records = [record for record in found if record is not None]
    if not records:
        raise LauncherPatternMissing(src.path, "File.Exists guarded WriteValue")
    return records + _root_writes(src, emulator)


def guarded_writes(sources: dict[str, Source]) -> list[Record]:
    """One fixed name per configuration key, written only when the file exists."""
    return [
        record
        for path, emulator in GUARDED_WRITES.items()
        for record in guarded_writes_in(sources[path], emulator)
    ]


# Expression rendering for the generators below: a path expression becomes
# bios/<folders>/<name>, <x> for AppConfig.GetFullPath("x"), <emulator> for
# the emulator's own folder, and None when it is built from anything else.

_PATH_PARAMS = {"path": "<emulator>", "emulatorPath": "<emulator>", "_path": "<emulator>"}
_KNOWN = {
    "Path.GetDirectoryName(rom)": "<rom directory>",
    "Path.GetDirectoryName(Path.GetFullPath(rom))": "<rom directory>",
    "rom": "<rom>",
}
_WRAPPERS = ("EnsureDirectoryExists",)

Rendered = tuple[str, list[tuple[int, int]]]


def _comment_spans(text: str) -> Iterator[tuple[int, int]]:
    """Offsets of the comments of C# code, string and char literals skipped."""
    i, n = 0, len(text)
    while i < n:
        if text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end < 0 else end
            yield i, end
            i = end
        elif text.startswith("/*", i):
            close = text.find("*/", i + 2)
            end = n if close < 0 else close + 2
            yield i, end
            i = end
        elif text.startswith('@"', i):
            i += 2
            while i < n and not (text[i] == '"' and not text.startswith('""', i)):
                i += 2 if text.startswith('""', i) else 1
            i += 1
        elif text[i] in "\"'":
            quote = text[i]
            i += 1
            while i < n and text[i] != quote and text[i] != "\n":
                i += 2 if text[i] == "\\" else 1
            i += 1
        else:
            i += 1


def _code(src: Source) -> str:
    """The text with comments blanked, offsets and lines unchanged."""
    if src.code is None:
        chars = list(src.text)
        for start, end in _comment_spans(src.text):
            for i in range(start, end):
                if chars[i] != "\n":
                    chars[i] = " "
        src.code = "".join(chars)
    return src.code


def _split_top(text: str, separator: str) -> list[str]:
    """text split on separator outside strings, parentheses and braces."""
    code = {offset for offset, _ in _code_chars(text)}
    parts, depth, start = [], 0, 0
    for i, char in enumerate(text):
        if i not in code:
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif depth == 0 and text.startswith(separator, i):
            parts.append(text[start:i].strip())
            start = i + len(separator)
    parts.append(text[start:].strip())
    return parts


def _wrapped(expr: str, opener: str) -> str | None:
    """The inside of opener(...) when the parentheses span the whole expression."""
    if not expr.startswith(opener + "(") or not expr.endswith(")"):
        return None
    inner = expr[len(opener) + 1 : -1]
    depth = 0
    for offset, char in _code_chars(inner):
        depth += {"(": 1, ")": -1}.get(char, 0)
        if depth < 0:
            return None
    return inner


def _method_of(src: Source, offset: int) -> tuple[int, int]:
    for block in sorted((b for b in src.blocks() if b[0] < offset < b[1]), reverse=True):
        if _METHOD.match(src.header(block)):
            return block
    raise LauncherPatternMissing(src.path, f"method around line {src.line(offset)}")


def _bare(src: Source) -> str:
    """The code with comments and the inside of literals blanked."""
    if src.bare is None:
        chars = [" " if c != "\n" else c for c in src.text]
        for offset, char in _code_chars(src.text):
            chars[offset] = char
        src.bare = "".join(chars)
    return src.bare


def _statement_start(src: Source, offset: int) -> int:
    code = _bare(src)
    found = max(code.rfind(";", 0, offset), code.rfind("{", 0, offset), code.rfind("}", 0, offset))
    start = found + 1
    while start < offset and code[start].isspace():
        start += 1
    return start


def _statement_end(src: Source, offset: int) -> int:
    """Offset of the semicolon that ends the statement running at offset."""
    depth = 0
    for position, char in _code_chars(src.text[offset:]):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == ";" and depth == 0:
            return offset + position
    raise LauncherPatternMissing(src.path, f"end of the statement at line {src.line(offset)}")


_ATOM = r"!?[\w.]+(?:\((?:[^()]|\([^()]*\))*\))?"


def _negated(condition: str) -> str:
    """not condition, written as a C# reader would."""
    if re.fullmatch(_ATOM, condition):
        return condition[1:] if condition.startswith("!") else f"!{condition}"
    return _negate(condition)


def _owner_condition(src: Source, start: int) -> str | None:
    """Condition of the if whose statement or block ends just before start."""
    code = _code(src)
    before = code[:start].rstrip()
    if before.endswith("}"):
        block = max(b for b in src.blocks() if b[1] == len(before))
        owner = _IF.fullmatch(src.header(block))
        return owner.group(1) if owner else None
    if not before.endswith(";"):
        return None
    owner_start = _statement_start(src, len(before) - 1)
    head = re.match(r"(?:else\s+)?if\s*\(", code[owner_start:])
    if head is None:
        return None
    return " ".join(_call_args(src, owner_start + head.end() - 1).split())


def _braceless_if(src: Source, offset: int) -> str | None:
    """Condition of an if or else without braces that owns the statement at offset."""
    code = _code(src)
    start = _statement_start(src, offset)
    if re.fullmatch(r"else\s*", code[start:offset]):
        owner = _owner_condition(src, start)
        return _negated(owner) if owner else None
    head = re.search(r"(?:else\s+)?if\s*\(", code[start:offset])
    if head is None or head.start() != 0:
        return None
    paren = start + head.end() - 1
    condition = _call_args(src, paren)
    rest = code[paren + len(condition) + 2 : offset]
    if rest.strip():
        return None
    return " ".join(condition.split())


def _render(src: Source, expr: str, scope: int, before: int) -> Rendered | None:
    """A path expression as text, with the lines of the declarations it read."""
    expr = " ".join(expr.split())
    if re.fullmatch(_BIOS_ROOT, expr):
        return "bios", []
    changed = re.fullmatch(r'Path\.ChangeExtension\(exe, "(\.\w+)"\)', expr)
    if changed:
        return f"<exe>{changed.group(1)}", []
    named = re.fullmatch(r'(?:Program\.)?AppConfig\.GetFullPath\("([\w.-]+)"\)', expr)
    if named:
        return f"<{named.group(1)}>", []
    if expr in _KNOWN:
        return _KNOWN[expr], []
    replaced = re.fullmatch(rf"(.+)\.Replace\({STRING}, {STRING}\)", expr)
    if replaced:
        return _render(src, replaced.group(1), scope, before)
    for wrapper in _WRAPPERS:
        inner = _wrapped(expr, wrapper)
        if inner is not None:
            return _render(src, inner, scope, before)
    ternary = _split_top(expr, "?")
    if len(ternary) == 2:
        branches = _split_top(ternary[1], ":")
        if len(branches) == 2:
            first = _render(src, branches[0], scope, before)
            second = _render(src, branches[1], scope, before)
            if first is None or second is None:
                return None
            return f"{first[0]} when {ternary[0]}, else {second[0]}", first[1] + second[1]
    terms = _split_top(expr, " + ")
    if len(terms) > 1:
        while terms and terms[0] == '"\\""':
            terms = terms[1:]
        while terms and terms[-1] in ('"\\""', '"\\\\"'):
            terms = terms[:-1]
        pieces, spans = [], []
        for term in terms:
            if term == '";"':
                pieces.append(";")
                continue
            done = _render(src, term, scope, before)
            if done is None:
                return None
            pieces.append(done[0])
            spans += done[1]
        return "".join(pieces), spans
    combine = _wrapped(expr, "Path.Combine")
    if combine is not None:
        base, *rest = _split_top(combine, ",")
        root = _render(src, base, scope, before)
        literals = [re.fullmatch(STRING, part) for part in rest]
        if root is None or not all(literals):
            return None
        return "/".join([root[0], *(_unescape(m.group(1)) for m in literals if m)]), root[1]
    if expr in _PATH_PARAMS:
        return _PATH_PARAMS[expr], []
    if re.fullmatch(r"\w+", expr):
        code = _code(src)
        decls = list(re.compile(rf"(?:string|var)\s+{expr}\s*=\s*").finditer(code, scope, before))
        if not decls:
            return (_PATH_PARAMS[expr], []) if expr in _PATH_PARAMS else None
        decl = decls[-1]
        decl_end = _statement_end(src, decl.end())
        base = _render(src, src.text[decl.end() : decl_end], scope, decl.start())
        if base is None:
            return None
        text, spans = base[0], [*base[1], src.lines(decl.start(), decl_end)]
        for again in re.compile(rf"(?<![\w.]){expr}\s*=(?!=)\s*").finditer(code, decl_end, before):
            again_end = _statement_end(src, again.end())
            value = _render(src, src.text[again.end() : again_end], scope, again.start())
            if value is None:
                return None
            condition = _braceless_if(src, again.start())
            text += f", or {value[0]}" + (f" when {_readable(condition)}" if condition else "")
            spans += [*value[1], src.lines(_statement_start(src, again.start()), again_end)]
        return text, spans
    return None


_OPTION_FORMS = (
    (r'SystemConfig\.isOptSet\("(\w+)"\) && SystemConfig\.getOptBoolean\("\1"\)', r"\1 on"),
    (
        r'SystemConfig\.isOptSet\("(\w+)"\) && !string\.IsNullOrEmpty\(SystemConfig\["\1"\]\)',
        r"\1 set",
    ),
    (r'SystemConfig\.getOptBoolean\("(\w+)"\)', r"\1 on"),
    (r'SystemConfig\["(\w+)"\]', r"\1"),
)


def _readable(condition: str) -> str:
    text = " ".join(condition.split())
    for pattern, replacement in _OPTION_FORMS:
        text = re.sub(pattern, replacement, text)
    return text


# Early returns taken when the emulator itself is not installed.
_EMULATOR_MISSING = (
    r"!File\.Exists\(exe\)|!Directory\.Exists\(path\)|string\.IsNullOrEmpty\((?:path|exe)\)"
)


def _when(src: Source, offset: int) -> tuple[list[str], list[tuple[int, int]]]:
    """Conditions under which the statement at offset runs, outermost first,
    with the lines of the early returns among them.

    A braceless if, every enclosing if, else and loop up to the method, and
    the early returns at the top of the method.
    """
    found: list[str] = []
    own = _braceless_if(src, offset)
    if own:
        found.append(_readable(own))
    for block in sorted((b for b in src.blocks() if b[0] < offset < b[1]), reverse=True):
        header = src.header(block)
        if _METHOD.match(header):
            returns, spans = [], []
            code = _code(src)
            for early in re.finditer(r"\bif \(", code[block[0] : offset]):
                paren = block[0] + early.end() - 1
                if src.enclosing(paren) != block:
                    continue
                cond = _call_args(src, paren)
                tail = re.compile(r"\s*return\b[^;]*;").match(code, paren + len(cond) + 2)
                cond = " ".join(cond.split())
                if tail and not re.fullmatch(_EMULATOR_MISSING, cond):
                    returns.append(_readable(_negated(cond)))
                    spans.append(src.lines(block[0] + early.start(), tail.end()))
            return returns + found[::-1], spans
        condition = _IF.fullmatch(header)
        if condition:
            found.append(_readable(condition.group(1)))
        elif header == "else":
            previous = max(b for b in src.blocks() if b[1] <= block[0])
            owner = _IF.fullmatch(src.header(previous))
            found.append(f"not ({_readable(owner.group(1))})" if owner else "else")
        elif not _TRANSPARENT.fullmatch(header) and not header.startswith(("catch", "lock")):
            found.append(header)
    raise LauncherPatternMissing(src.path, f"method around line {src.line(offset)}")


def _argument_of(src: Source, method: tuple[int, int], parameter: str) -> Rendered | None:
    """A parameter of method, rendered from the argument its one caller passes."""
    header = src.header(method)
    signature = re.search(r"(\w+)\s*\((.*)\)\s*$", header)
    if signature is None:
        return None
    names = [part.split("=")[0].split()[-1] for part in _split_top(signature.group(2), ",")]
    if parameter not in names:
        return None
    code = _code(src)
    calls = [
        call
        for call in re.finditer(rf"(?<![\w.]){signature.group(1)}\(", code)
        if not _statement_start(src, method[0]) <= call.start() < method[1]
    ]
    if len(calls) != 1:
        return None
    arguments = _split_top(_call_args(src, calls[0].end() - 1), ",")
    caller = _method_of(src, calls[0].start())
    return _render(src, arguments[names.index(parameter)], caller[0], calls[0].start())


def _config_label(src: Source, offset: int, writer: str) -> str:
    """The file the writer variable opens, as a path under the emulator folder."""
    method = _method_of(src, offset)
    code = _code(src)
    for scope in (method, (0, len(code))):
        for opened in re.finditer(
            rf"\b{writer}\s*=\s*(?:\w+\.FromFile|\w+\.Load|new \w+)\(", code[scope[0] : scope[1]]
        ):
            paren = scope[0] + opened.end() - 1
            target = _split_top(_call_args(src, paren), ",")[0]
            rendered = _render(src, target, _method_of(src, paren)[0], paren)
            if rendered is None:
                rendered = _argument_of(src, _method_of(src, paren), target)
            if rendered is not None:
                return rendered[0].replace("<emulator>/", "")
    raise LauncherPatternMissing(src.path, f"configuration file opened as {writer}")


def _bios_lines(src: Source) -> list[int]:
    code = _code(src)
    return sorted(
        {
            src.line(m.start())
            for m in re.finditer(r'AppConfig\.GetFullPath\("bios"\)|AppConfig\["bios"\]', code)
        }
    )


def _covered(src: Source, records: list[Record], skip: tuple[str, ...] = ()) -> list[Record]:
    """records, once every line of src that names the bios folder is in one.

    A line no record cites and no skip pattern describes is a construct the
    extractors do not read, and stops the scrape.
    """
    covered: set[int] = set()
    for record in records:
        for part in str(record["source_ref"]).split(", "):
            path, _, span = part.rpartition(":") if ":" in part else (src.path, "", part)
            if path and path != src.path:
                continue
            first, _, last = span.partition("-")
            covered.update(range(int(first), int(last or first) + 1))
    lines = src.text.split("\n")
    for line in _bios_lines(src):
        if line in covered or any(re.search(p, lines[line - 1]) for p in skip):
            continue
        raise LauncherPatternMissing(src.path, f"reader for the bios reference at line {line}")
    return records


def _path_parts(src: Source, *spans: tuple[int, int]) -> str:
    return source_ref((src.path, list(spans)))


def _option_path_in(src: Source, features: Source, emulator: str) -> list[Record]:
    """A default name under bios that an option replaces before it is written."""
    code = _code(src)
    override = src.find(
        rf"(?:string )?(\w+) = Path\.Combine\({_BIOS_ROOT}, SystemConfig\[\"(\w+)\"\]\);",
        "path taken from an option",
    )
    var, option = override.groups()
    method = _method_of(src, override.start())
    gate = src.find(
        rf'if \(SystemConfig\.isOptSet\("{option}"\)', f"{option} gate", method[0], override.start()
    )
    gate_block = _gate_span(src, gate, override)
    write = re.compile(
        rf'(\w+)\.WriteValue\("([^"]*)", "([^"]+)", ([^;\n]*\b{var}\b[^;\n]*)\);'
    ).search(code, override.end(), method[1])
    if write is None:
        raise LauncherPatternMissing(src.path, f"write of {var}")
    writer, section, key = write.group(1), _unescape(write.group(2)), _unescape(write.group(3))
    guarded = re.compile(rf"if \(File\.Exists\({var}\)[^\n]*\)\s*$").search(
        code, method[0], write.start()
    )
    flag = None if guarded else _flag_guard(code, var, method[0], write.start())
    guarded = guarded or flag
    skipped = re.findall(
        rf'SystemConfig\["{option}"\] != "(\w+)"', code[gate.start() : write.end()]
    )
    config = _config_label(src, write.start(), writer)
    target = f"{config} [{section}] {key}" if section else f"{config} {key}"
    suffix = ", only if the file exists" if guarded else ", written without an existence check"
    fails = f"{key} not written" if guarded else "path written without an existence check"
    write_span = src.lines(
        flag.start() if flag else _statement_start(src, write.start()), write.end()
    )
    choices, choice_lines = feature_choices(features, emulator, option)
    fallback = _fallback_names(src, var, gate_block[1], write.start())
    if fallback is not None:
        fails = f"{', then '.join(fallback[0])}, instead, else {fails}"
    records = []
    default = list(
        re.compile(rf'string {var} = Path\.Combine\({_BIOS_ROOT}, "([^"]+)"\);').finditer(
            code, method[0], gate.start()
        )
    )
    if default:
        records.append(
            _record(
                emulator,
                "standalone",
                "fixed_name",
                [default[-1].group(1)],
                _path_parts(src, src.lines(default[-1].start(), default[-1].end()), write_span),
                case_insensitive=True,
                search_dir="bios",
                passes_to=target + suffix,
                fails_when_missing=fails,
                depends_on_option=f"{option} unset",
            )
        )
    records.append(
        _record(
            emulator,
            "standalone",
            "core_option",
            [c for c in choices if c not in skipped],
            source_ref(
                (src.path, [src.lines(gate.start(), gate_block[1]), write_span]),
                (features.path, [choice_lines]),
            ),
            case_insensitive=True,
            search_dir="bios",
            passes_to=f"{target} = <bios>/<value>{suffix}",
            fails_when_missing=fails,
            depends_on_option=option,
        )
    )
    if fallback is not None:
        names, span = fallback
        unset = f"{default[-1].group(1)} absent with {option} unset" if default else None
        chosen = f"the {option} file absent" + (
            f", {option} not {' or '.join(skipped)}" if skipped else ""
        )
        records.append(
            _record(
                emulator,
                "standalone",
                "names_searched",
                names,
                _path_parts(src, span, write_span),
                case_insensitive=True,
                search_dir="bios",
                passes_to=f"{target} = <first found>{suffix}",
                fails_when_missing=f"{key} not written" if guarded else fails,
                depends_on_option=" or ".join(c for c in (unset, chosen) if c),
            )
        )
    return records + _root_writes(src, emulator)


def _gate_span(src: Source, gate: re.Match[str], override: re.Match[str]) -> tuple[int, int]:
    """The span an option gate governs: its block, or the one statement a
    braceless if runs, which must be the override."""
    paren = gate.start() + len("if ")
    after = paren + len(_call_args(src, paren)) + 2
    if re.match(r"\s*\{", src.text[after:]):
        block = src.block_at(after)
    else:
        block = (after, _statement_end(src, after))
    if not block[0] < override.start() < block[1]:
        raise LauncherPatternMissing(
            src.path, f"option block around line {src.line(override.start())}"
        )
    return block


def _flag_guard(code: str, var: str, start: int, end: int) -> re.Match[str] | None:
    """A write under `if (flag)` where flag holds File.Exists of the path."""
    flag = re.compile(rf"bool (\w+) = [^;\n]*\bFile\.Exists\({var}\)[^;\n]*;").search(
        code, start, end
    )
    if flag is None or not re.compile(rf"if \({flag.group(1)}\)\s*$", re.M).search(
        code, flag.end(), end
    ):
        return None
    return flag


def _fallback_names(
    src: Source, var: str, start: int, end: int
) -> tuple[list[str], tuple[int, int]] | None:
    """Names tried in bios, first existing one kept, when the chosen file is absent."""
    found = re.compile(
        rf"if \(([^\n]*!File\.Exists\({var}\)[^\n]*)\)\s*"
        rf"{var} = new\[\] \{{ (?P<names>(?:{STRING}(?:, )?)+) \}}\.Select\((?P<arg>\w+) => "
        rf"Path\.Combine\({_BIOS_ROOT}, (?P=arg)\)\)\.FirstOrDefault\(File\.Exists\) \?\? {var};"
    ).search(_code(src), start, end)
    if found is None:
        return None
    return _strings(found.group("names")), src.lines(found.start(), found.end())


OPTION_PATHS = {
    f"{GENERATORS}/Kronos.Generator.cs": "kronos",
    f"{GENERATORS}/SSF.Generator.cs": "ssf",
    f"{GENERATORS}/Yabasanshiro.Generator.cs": "yabasanshiro",
    f"{GENERATORS}/Ymir.Generator.cs": "ymir",
}


def option_paths(sources: dict[str, Source]) -> list[Record]:
    """Saturn emulators: a default BIOS name an option replaces before the write."""
    return [
        record
        for path, emulator in OPTION_PATHS.items()
        for record in _covered(
            sources[path], _option_path_in(sources[path], sources[FEATURES], emulator)
        )
    ]


def _name_of(src: Source, var: str, offset: int) -> tuple[str, str, list[tuple[int, int]]]:
    """A variable holding bios/<folders>/<name>, as (folder, name, lines)."""
    method = _method_of(src, offset)
    rendered = _render(src, var, method[0], offset)
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
    conditions, returns = _when(src, pair.start())
    config = _config_label(src, pair.start(), "ini")
    records = [
        _record(
            "desmume",
            "standalone",
            "fixed_name",
            names,
            _path_parts(src, *returns, *spans, src.lines(pair.start(), block[1])),
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
        rf'string (\w+) = Path\.Combine\({_BIOS_ROOT}, "([^"]+)"\);\s*'
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
    conditions, returns = _when(src, firmware.start())
    records.append(
        _record(
            "desmume",
            "standalone",
            "fixed_name",
            [firmware.group(2)],
            _path_parts(src, *returns, src.lines(firmware.start(), fw_flag.end())),
            case_insensitive=True,
            search_dir="bios",
            passes_to=f"{config} [{fw_write.group(1)}] {fw_write.group(2)}, only if the file exists",
            fails_when_missing=f"{fw_flag.group(1)} left at 0",
            depends_on_option=", ".join(
                [*conditions, f"{firmware.group(3)} unset or not an existing file"]
            ),
        )
    )
    return _covered(src, records)


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
        root = _render(src, decl.group(1), method[0], decl.start())
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
    config = _config_label(src, check.start(), "ini")
    records = [
        _record(
            "melonds",
            "standalone",
            "fixed_name",
            names,
            _path_parts(
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
        _record(
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
        _record(
            "jzintv",
            "standalone",
            "fixed_name",
            [name for _, _, name, _, _ in passed],
            _path_parts(
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
        rf'string (\w+) = Path\.Combine\({_BIOS_ROOT}, "([^"]+)"\);\s*if \(File\.Exists\(\1\)\)\s*\{{\s*'
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
        _record(
            "jzintv",
            "standalone",
            "fixed_name",
            [ecs.group(2)],
            _path_parts(
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
    return _covered(src, records)


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
        root = _render(src, call.group(3), _method_of(src, call.start())[0], call.start())
        if root is None or root[0] != "bios":
            raise LauncherPatternMissing(
                src.path, f"bios folder passed at line {src.line(call.start())}"
            )
        records.append(
            _record(
                "blastem",
                "standalone",
                "fixed_name",
                [call.group(4)],
                _path_parts(
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
    return _covered(src, records)


def _value_writes(
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
        rendered = _render(src, value, method[0], write.start())
        if rendered is None or not rendered[0].startswith("bios"):
            continue
        conditions, returns = _when(src, write.start())
        section = _unescape(section[1:-1]) if section != "null" else ""
        target = f"{_config_label(src, write.start(), writer)} " + (
            f"[{section}] {key}" if section else key
        )
        span = src.lines(
            _statement_start(src, write.start()),
            write.end() + len(_call_args(src, write.end() - 1)),
        )
        ref = _path_parts(src, *returns, *rendered[1], span)
        depends = ", ".join(conditions) or None
        folder, _, name = rendered[0].rpartition("/")
        if "." not in name or ", " in rendered[0]:
            records.append(
                _record(
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
            _record(
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
    records = _value_writes(src, "dolphin", "standalone")
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
        rendered = _render(src, item, body[0], block[0])
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
    conditions, returns = _when(src, call.start())
    destination = _render(src, target.group(1), body[0], target.start())
    records.append(
        _record(
            "dolphin",
            "standalone",
            "copies",
            names,
            _path_parts(
                src,
                *returns,
                src.lines(_statement_start(src, call.start()), call.end()),
                src.lines(method.start(), body[1]),
            ),
            case_insensitive=True,
            search_dir="bios",
            passes_to=destination[0] if destination else target.group(1),
            fails_when_missing=f"warning '{_unescape(warning.group(1))}' when the target is absent too",
            depends_on_option=_joined(
                *conditions, "first name found",
                "the target is absent, smaller or older",
            ),
        )
    )
    return _covered(src, records, skip=(r"DolphinTool\.exe",))


def raine(sources: dict[str, Source]) -> list[Record]:
    src = sources[f"{GENERATORS}/Raine.Generator.cs"]
    records = _value_writes(src, "raine", "standalone")
    if not any(r["kind"] == "fixed_name" for r in records):
        raise LauncherPatternMissing(src.path, "neocd_bios write")
    return _covered(src, records)


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
    conditions, returns = _when(src, write.start())
    # The test on the name found is the selection itself, not a condition.
    conditions = [c for c in conditions if first.group(1) not in c]
    target = f"{_config_label(src, write.start(), write.group(1))} {write.group(2)}"
    record = _record(
        "gsplus",
        "standalone",
        "names_searched",
        _strings(listed.group(2)),
        _path_parts(
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
    return _covered(src, [record])


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
        source = _render(src, source_var, method[0], copy.start())
        target = _render(src, target_var, method[0], copy.start())
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
        conditions, returns = _when(src, copies[0][0])
        records.append(
            _record(
                emulator,
                build,
                "copies",
                [name for _, _, name, _ in copies],
                _path_parts(src, *returns, *[s for c in copies for s in c[3]]),
                case_insensitive=True,
                search_dir=folders.pop(),
                passes_to=f"{destination}/<name>",
                fails_when_missing=False,
                depends_on_option=_joined(*conditions, TARGET_ABSENT),
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
        for record in _covered(
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
    [record] = _copies_if_absent(src, ", ".join(names), "libretro", block)
    record["source_ref"] = source_ref(
        (src.path, [(src.line(cores.start()), core_lines[1]), src.statement_span(block)])
    )
    record["depends_on_option"] = _joined(
        f'core in {cores.group(1)}, rom extension "{gate.group(1)}"', TARGET_ABSENT
    )
    return [record]


def tsugaru(sources: dict[str, Source]) -> list[Record]:
    """The FM Towns ROM folder, chosen by where FMT_SYS.ROM is."""
    src = sources[f"{GENERATORS}/Tsugaru.Generator.cs"]
    code = _code(src)
    first = src.find(
        rf'if \(Directory\.Exists\((Path\.Combine\({_BIOS_ROOT}, "[^"]+"\))\)\)\s*(\w+) = \1;',
        "first FM Towns folder",
    )
    var = first.group(2)
    method = _method_of(src, first.start())
    unset = src.find(rf"string {var} = null;", f"{var} declaration", method[0], first.start())
    folders = [_render(src, first.group(1), method[0], first.start())]
    names, end = set(), first.end()
    step = re.compile(
        rf'\s*if \(!File\.Exists\(Path\.Combine\({var}, "([^"]+)"\)\)\)\s*{var} = ([^;]+);'
    )
    while more := step.match(code, end):
        names.add(more.group(1))
        folders.append(_render(src, more.group(2), method[0], more.start()))
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
    record = _record(
        "tsugaru",
        "standalone",
        "passes_path",
        sorted(names),
        _path_parts(
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
    return _covered(src, [record])


def rpcs3(sources: dict[str, Source]) -> list[Record]:
    src = sources[f"{GENERATORS}/Rpcs3.Generator.cs"]
    marker = src.find(
        rf"string (\w+) = (Path\.Combine\(path, [^;]+\));\s*string \w+ = {_BIOS_ROOT};",
        "installed firmware marker",
    )
    pup = src.find(
        rf'string (\w+) = {_BIOS_ROOT};\s*string (\w+) = Path\.Combine\(\1, "([^"]+)"\);',
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
    installed = _render(src, marker.group(2), method[0], marker.start())
    record = _record(
        "rpcs3",
        "standalone",
        "fixed_name",
        [pup.group(3)],
        _path_parts(src, src.lines(marker.start(), src.block_at(returned.end())[1])),
        case_insensitive=True,
        search_dir="bios",
        passes_to=(
            f"command line {install.group(1)} <bios>/{pup.group(3)}, launched instead of the game"
        ),
        fails_when_missing=message,
        depends_on_option=f"{installed[0] if installed else marker.group(2)} absent",
    )
    return _covered(src, [record])


def _indexer_writes(src: Source, emulator: str, writer: str) -> list[Record]:
    """writer["key"] = value, for each value that resolves to a folder under bios."""
    code = _code(src)
    records = []
    for write in re.compile(rf'\b{writer}\["([^"]+)"\] = ([^;]+);').finditer(code):
        method = _method_of(src, write.start())
        rendered = _render(src, src.text[write.start(2) : write.end(2)], method[0], write.start())
        if rendered is None or not rendered[0].startswith("bios"):
            continue
        conditions, returns = _when(src, write.start())
        records.append(
            _record(
                emulator,
                "standalone",
                "passes_path",
                [],
                _path_parts(src, *returns, *rendered[1], src.lines(write.start(), write.end())),
                search_dir=rendered[0],
                passes_to=(
                    f"{_config_label(src, write.start(), writer)} {write.group(1)} = {rendered[0]}"
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
    return _covered(src, _indexer_writes(src, "eka2l1", "yml"))


def fbneo(sources: dict[str, Source]) -> list[Record]:
    src = sources[f"{GENERATORS}/Fbneo.Generator.cs"]
    return _covered(src, _indexer_writes(src, "fbneo", "cfg"))


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
            rf'string {var} = Path\.Combine\({_BIOS_ROOT}, "([^"]+)"\);',
            "default GB BIOS",
            method[0],
            flag.start(),
        )
        chosen = list(
            re.compile(
                rf'(?:else )?if \(system == "(\w+)"\)\s*'
                rf'{var} = Path\.Combine\({_BIOS_ROOT}, "([^"]+)"\);'
            ).finditer(code, default.end(), flag.start())
        )
        if code[default.end() : flag.start()].count(f"{var} =") != len(chosen):
            raise LauncherPatternMissing(
                src.path, f"{var} choice at line {src.line(default.start())}"
            )
        ref = _path_parts(
            src, src.lines(core.start(), core.end()), src.lines(default.start(), flag.end())
        )
        others = " && ".join(f'system != "{m.group(1)}"' for m in chosen)
        slots = [("other systems", default.group(1), others)]
        slots += [(m.group(1), m.group(2), f'system == "{m.group(1)}"') for m in chosen]
        for slot, name, system in slots:
            records.append(
                _record(
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
    return _covered(
        src,
        records,
        # A DSi NAND boot copies the game itself to bios/dsi_nand.bin.
        skip=(r'string biosPath = AppConfig\.GetFullPath\("bios"\);',),
    )


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
        rendered = _render(src, expr, method[0], add.start())
        if rendered is None or not rendered[0].startswith("bios"):
            continue
        flags = list(re.finditer(r'"(-[\w-]+)"', code[method[0] : add.start()]))
        if not flags:
            raise LauncherPatternMissing(src.path, f"flag before line {src.line(add.start())}")
        flag_at = method[0] + flags[-1].start()
        conditions, returns = _when(src, add.start())
        found.append(
            (
                _record(
                    emulator,
                    build,
                    "passes_path",
                    [],
                    _path_parts(
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
    records = _covered(
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
    return records + _covered(
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
    return _covered(src, [_with_conditions(record, conditions) for record, conditions in found])


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
        _record(
            "xroar",
            "standalone",
            "passes_path",
            [],
            _path_parts(
                src, src.lines(line.start(), line.end()), src.lines(use.start(), use.end())
            ),
            search_dir="/".join(parts[parts.index("bios") :]),
            passes_to=f"{setup.group(1)} {written}",
            fails_when_missing=False,
        )
    )
    return _covered(src, records)


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
        split["source_ref"] = _path_parts(src, *spans)
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
        records.append(_record(
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
        _record(
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


def snes9x(sources: dict[str, Source]) -> list[Record]:
    src = sources[f"{GENERATORS}/Snes9x.Generator.cs"]
    entry = src.find(rf'\{{ "([^"]+)", (Path\.Combine\({_BIOS_ROOT}\)) \}}', "bios folder entry")
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
    config = _config_label(src, write.start(), write.group(1))
    record = _record(
        "snes9x",
        "standalone",
        "passes_path",
        [],
        _path_parts(src, src.lines(entry.start(), entry.end()), src.lines(loop.start(), body[1])),
        search_dir="bios",
        passes_to=f"{config} [{write.group(2)}] {entry.group(1)} = bios",
        fails_when_missing=False,
    )
    return _covered(src, [record])


def value_folders(sources: dict[str, Source]) -> list[Record]:
    """Configuration keys given a folder under bios."""
    records = []
    for path, emulator, skip in (
        # VMU saves are synchronised with the libretro core's bios/dc.
        (f"{GENERATORS}/Flycast.Generator.cs", "flycast", (r"string libretroPath = ",)),
        (f"{GENERATORS}/ScummVm.Generator.cs", "scummvm", ()),
    ):
        found = _value_writes(sources[path], emulator, "standalone")
        if not found:
            raise LauncherPatternMissing(path, "bios folder write")
        records += _covered(sources[path], found, skip=skip)
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
    config = _config_label(src, loop.start(), loop.group(1))
    records = []
    for index, item in enumerate(_split_top(src.text[block[0] + 1 : block[1] - 1].strip(), ",")):
        rendered = _render(src, item, method[0], listing.start())
        if rendered is None:
            raise LauncherPatternMissing(src.path, f"rom path {item}")
        if not rendered[0].startswith("bios"):
            continue
        records.append(
            _record(
                "demul",
                "standalone",
                "passes_path",
                [],
                _path_parts(
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
    return _covered(src, records)


def bsyndrome(sources: dict[str, Source]) -> list[Record]:
    src = sources[f"{GENERATORS}/PortsLauncher.Configuration.cs"]
    records = []
    for arg in src.find_all(
        r'string (\w+) = "(--\w+)=\\"" \+ (\w+) \+ "\\"";\s*commandArray\.Add\(\1\);',
        "path argument",
    ):
        method = _method_of(src, arg.start())
        rendered = _render(src, arg.group(3), method[0], arg.start())
        if rendered is None or not rendered[0].startswith("bios"):
            continue
        conditions, returns = _when(src, arg.start())
        records.append(
            _record(
                "bsyndrome",
                "standalone",
                "passes_path",
                [],
                _path_parts(src, *returns, *rendered[1], src.lines(arg.start(), arg.end())),
                search_dir=rendered[0],
                passes_to=f"command line {arg.group(2)}={rendered[0]}",
                fails_when_missing=False,
                depends_on_option=", ".join(conditions) or None,
            )
        )
    if not records:
        raise LauncherPatternMissing(src.path, "bios folder argument")
    return _covered(src, records)


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
    folder = _render(src, copy.group(2), body[0], copy.start())
    if folder is None or not folder[0].startswith("bios/"):
        raise LauncherPatternMissing(src.path, "keropi folder")
    conditions, _ = _when(src, loop.start())
    record = _record(
        "xm6pro",
        "standalone",
        "copies",
        names,
        _path_parts(src, (src.line(table.start()), lines[1]), src.lines(method.start(), body[1])),
        case_insensitive=True,
        search_dir=folder[0],
        passes_to="<emulator>/<name>",
        fails_when_missing=False,
        depends_on_option=_joined(*conditions, TARGET_ABSENT),
    )
    return _covered(src, [record])


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
    root = src.find(rf"string biosPath = {_BIOS_ROOT};", "bios root")
    write = src.find(r'ini\.WriteValue\("(\w+)", "(\w+)", biosPath\);', "SearchDirectory write")
    config = _config_label(src, write.start(), "ini")
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
        _record(
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
        _record(
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
        _record(
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
    return _covered(src, records)


EXTRACTORS: tuple[Callable[[dict[str, Source]], list[Record]], ...] = (
    amiberry,
    arcadeduck,
    ares,
    bizhawk_gb,
    blastem,
    bsyndrome,
    capsimg,
    cxbx,
    demul,
    desmume,
    dolphin,
    dosbox_copies,
    duckstation,
    eka2l1,
    fbneo,
    gsplus,
    guarded_writes,
    hatari,
    hatari_libretro,
    jzintv,
    mame,
    melonds_dsi,
    mesen,
    openmsx,
    option_paths,
    pcsx2,
    pcsx2_libretro,
    pico8,
    portable_users,
    psx_cascades,
    psxmame,
    raine,
    rpcs3,
    snes9x,
    tsugaru,
    value_folders,
    winuae,
    xemu,
    xemu_saves,
    xm6pro,
    xroar,
)


def extract_launchers(texts: dict[str, str]) -> list[Record]:
    """Every launcher record the extractors find, in extractor order."""
    missing = [path for path in SOURCE_FILES if path not in texts]
    if missing:
        raise LauncherPatternMissing(missing[0], "source file")
    sources = {path: Source(path, text) for path, text in texts.items()}
    return [
        _choices_apart(record) for extractor in EXTRACTORS for record in extractor(sources)
    ]


def _choices_apart(record: Record) -> Record:
    """The es_features.cfg part of a record's source_ref, moved to choices_from.

    The feature file lists the values a menu option offers. The generator
    writing the choice is the record's evidence, never the list.
    """
    parts = split_ref(str(record["source_ref"]))
    listed = [p for p in parts if is_feature_ref(p)]
    if not listed:
        return record
    code = [p for p in parts if not is_feature_ref(p)]
    if not code:
        raise LauncherPatternMissing(listed[0], "generator code beside the option list")
    moved = {k: v for k, v in record.items() if k != "source_ref"}
    return {**moved, "choices_from": ", ".join(listed), "source_ref": ", ".join(code)}
