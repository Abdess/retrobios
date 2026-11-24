"""RetroBat generator paths, es_features.cfg choices, the record shape and the guarded BIOS writes."""

from __future__ import annotations

import re

from .csharp_source import (
    LauncherPatternMissing,
    Record,
    STRING,
    Source,
    _METHOD,
    _call_args,
    _strings,
    source_ref,
)


GENERATORS = "emulatorLauncher/Generators"
FEATURES = ".emulationstation/es_features.cfg"


BIOS = r'AppConfig\.GetFullPath\("bios"\)'


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
    compared = [m for t in tests if (m := re.fullmatch(rf"(\w+) != ({STRING})", t))]
    if len(compared) == len(tests):
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
