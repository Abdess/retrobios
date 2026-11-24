"""RetroBat C# path expressions rendered as text, with the conditions a write runs under."""

from __future__ import annotations

import re

from .csharp_source import (
    LauncherPatternMissing,
    Record,
    STRING,
    Source,
    _METHOD,
    _call_args,
    _code,
    _method_of,
    _split_top,
    _statement_end,
    _statement_start,
    _strings,
    _unescape,
    _wrapped,
    source_ref,
)
from .retrobat_generators import (
    FEATURES,
    GENERATORS,
    BIOS_ROOT,
    IF,
    TRANSPARENT,
    negate,
    launcher_record,
    root_writes,
    feature_choices,
)


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


_ATOM = r"!?[\w.]+(?:\((?:[^()]|\([^()]*\))*\))?"


def _negated(condition: str) -> str:
    """not condition, written as a C# reader would."""
    if re.fullmatch(_ATOM, condition):
        return condition[1:] if condition.startswith("!") else f"!{condition}"
    return negate(condition)


def _owner_condition(src: Source, start: int) -> str | None:
    """Condition of the if whose statement or block ends just before start."""
    code = _code(src)
    before = code[:start].rstrip()
    if before.endswith("}"):
        block = max(b for b in src.blocks() if b[1] == len(before))
        owner = IF.fullmatch(src.header(block))
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


def render(src: Source, expr: str, scope: int, before: int) -> Rendered | None:
    """A path expression as text, with the lines of the declarations it read."""
    expr = " ".join(expr.split())
    fixed = _render_fixed(expr)
    if fixed is not None:
        return fixed
    replaced = re.fullmatch(rf"(.+)\.Replace\({STRING}, {STRING}\)", expr)
    if replaced:
        return render(src, replaced.group(1), scope, before)
    for wrapper in _WRAPPERS:
        inner = _wrapped(expr, wrapper)
        if inner is not None:
            return render(src, inner, scope, before)
    ternary = _split_top(expr, "?")
    if len(ternary) == 2:
        branches = _split_top(ternary[1], ":")
        if len(branches) == 2:
            return _render_choice(src, ternary[0], branches, scope, before)
    terms = _split_top(expr, " + ")
    if len(terms) > 1:
        return _render_terms(src, terms, scope, before)
    combine = _wrapped(expr, "Path.Combine")
    if combine is not None:
        base, *rest = _split_top(combine, ",")
        root = render(src, base, scope, before)
        literals = [re.fullmatch(STRING, part) for part in rest]
        if root is None or not all(literals):
            return None
        return "/".join([root[0], *(_unescape(m.group(1)) for m in literals if m)]), root[1]
    if expr in _PATH_PARAMS:
        return _PATH_PARAMS[expr], []
    if re.fullmatch(r"\w+", expr):
        return _render_variable(src, expr, scope, before)
    return None


def _render_fixed(expr: str) -> Rendered | None:
    """The expressions that name one known folder or file."""
    if re.fullmatch(BIOS_ROOT, expr):
        return "bios", []
    changed = re.fullmatch(r'Path\.ChangeExtension\(exe, "(\.\w+)"\)', expr)
    if changed:
        return f"<exe>{changed.group(1)}", []
    named = re.fullmatch(r'(?:Program\.)?AppConfig\.GetFullPath\("([\w.-]+)"\)', expr)
    if named:
        return f"<{named.group(1)}>", []
    if expr in _KNOWN:
        return _KNOWN[expr], []
    return None


def _render_choice(
    src: Source, condition: str, branches: list[str], scope: int, before: int
) -> Rendered | None:
    """A `condition ? a : b` expression."""
    first = render(src, branches[0], scope, before)
    second = render(src, branches[1], scope, before)
    if first is None or second is None:
        return None
    return f"{first[0]} when {condition}, else {second[0]}", first[1] + second[1]


def _render_terms(src: Source, terms: list[str], scope: int, before: int) -> Rendered | None:
    """A concatenation, the quotes wrapped around it dropped."""
    while terms and terms[0] == '"\\""':
        terms = terms[1:]
    while terms and terms[-1] in ('"\\""', '"\\\\"'):
        terms = terms[:-1]
    pieces, spans = [], []
    for term in terms:
        if term == '";"':
            pieces.append(";")
            continue
        done = render(src, term, scope, before)
        if done is None:
            return None
        pieces.append(done[0])
        spans += done[1]
    return "".join(pieces), spans


def _render_variable(src: Source, expr: str, scope: int, before: int) -> Rendered | None:
    """A local variable, from its declaration and every later assignment before use."""
    code = _code(src)
    decls = list(re.compile(rf"(?:string|var)\s+{expr}\s*=\s*").finditer(code, scope, before))
    if not decls:
        return (_PATH_PARAMS[expr], []) if expr in _PATH_PARAMS else None
    decl = decls[-1]
    decl_end = _statement_end(src, decl.end())
    declared = render(src, src.text[decl.end() : decl_end], scope, decl.start())
    if declared is None:
        return None
    text, spans = declared[0], [*declared[1], src.lines(decl.start(), decl_end)]
    for again in re.compile(rf"(?<![\w.]){expr}\s*=(?!=)\s*").finditer(code, decl_end, before):
        again_end = _statement_end(src, again.end())
        value = render(src, src.text[again.end() : again_end], scope, again.start())
        if value is None:
            return None
        condition = _braceless_if(src, again.start())
        text += f", or {value[0]}" + (f" when {_readable(condition)}" if condition else "")
        spans += [*value[1], src.lines(_statement_start(src, again.start()), again_end)]
    return text, spans


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


def when(src: Source, offset: int) -> tuple[list[str], list[tuple[int, int]]]:
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
        condition = IF.fullmatch(header)
        if condition:
            found.append(_readable(condition.group(1)))
        elif header == "else":
            previous = max(b for b in src.blocks() if b[1] <= block[0])
            owner = IF.fullmatch(src.header(previous))
            found.append(f"not ({_readable(owner.group(1))})" if owner else "else")
        elif not TRANSPARENT.fullmatch(header) and not header.startswith(("catch", "lock")):
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
    return render(src, arguments[names.index(parameter)], caller[0], calls[0].start())


def config_label(src: Source, offset: int, writer: str) -> str:
    """The file the writer variable opens, as a path under the emulator folder."""
    method = _method_of(src, offset)
    code = _code(src)
    for scope in (method, (0, len(code))):
        for opened in re.finditer(
            rf"\b{writer}\s*=\s*(?:\w+\.FromFile|\w+\.Load|new \w+)\(", code[scope[0] : scope[1]]
        ):
            paren = scope[0] + opened.end() - 1
            target = _split_top(_call_args(src, paren), ",")[0]
            rendered = render(src, target, _method_of(src, paren)[0], paren)
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


def covered_records(src: Source, records: list[Record], skip: tuple[str, ...] = ()) -> list[Record]:
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


def path_parts(src: Source, *spans: tuple[int, int]) -> str:
    return source_ref((src.path, list(spans)))


def _option_path_in(src: Source, features: Source, emulator: str) -> list[Record]:
    """A default name under bios that an option replaces before it is written."""
    code = _code(src)
    override = src.find(
        rf"(?:string )?(\w+) = Path\.Combine\({BIOS_ROOT}, SystemConfig\[\"(\w+)\"\]\);",
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
    config = config_label(src, write.start(), writer)
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
        re.compile(rf'string {var} = Path\.Combine\({BIOS_ROOT}, "([^"]+)"\);').finditer(
            code, method[0], gate.start()
        )
    )
    if default:
        records.append(
            launcher_record(
                emulator,
                "standalone",
                "fixed_name",
                [default[-1].group(1)],
                path_parts(src, src.lines(default[-1].start(), default[-1].end()), write_span),
                case_insensitive=True,
                search_dir="bios",
                passes_to=target + suffix,
                fails_when_missing=fails,
                depends_on_option=f"{option} unset",
            )
        )
    records.append(
        launcher_record(
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
            launcher_record(
                emulator,
                "standalone",
                "names_searched",
                names,
                path_parts(src, span, write_span),
                case_insensitive=True,
                search_dir="bios",
                passes_to=f"{target} = <first found>{suffix}",
                fails_when_missing=f"{key} not written" if guarded else fails,
                depends_on_option=" or ".join(c for c in (unset, chosen) if c),
            )
        )
    return records + root_writes(src, emulator)


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
        rf"Path\.Combine\({BIOS_ROOT}, (?P=arg)\)\)\.FirstOrDefault\(File\.Exists\) \?\? {var};"
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
        for record in covered_records(
            sources[path], _option_path_in(sources[path], sources[FEATURES], emulator)
        )
    ]
