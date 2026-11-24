"""RetroPie's scriptmodules loaded as one shell, and the launcher record read from them."""

from __future__ import annotations

import re
import shlex
from collections.abc import Iterator
from dataclasses import dataclass, field
from functools import partial
from itertools import product
from pathlib import PurePosixPath
from typing import Any, ClassVar

from .configgen_launchers import Launcher as ConfiggenLauncher
from .retropie_modules import module_field_lines


SCRIPTMODULES = "scriptmodules"
SECTIONS = ("emulators", "libretrocores", "ports")


# The package whose config every lr- core runs under.
LIBRETRO_FRONTEND = "retroarch"


_FUNCTION = re.compile(r"^function\s+([\w.+-]+)\s*\(\)\s*\{\s*$")
_ASSIGN = re.compile(r"^(?:local\s+)?([A-Za-z_]\w*)=(.*)$")
_DECLARE = re.compile(r"^local\s+([A-Za-z_]\w*(?:\s+[A-Za-z_]\w*)*)\s*$")
_FOR = re.compile(r"^for\s+([A-Za-z_]\w*)\s+in\s+(.*?)\s*(?:;\s*do)?\s*$")
_HEREDOC = re.compile(r"(?<!<)<<-?(?!<)\s*['\"]?(\w+)['\"]?")
_VAR = re.compile(r"\$\{([A-Za-z_]\w*)(\[@\])?\}|\$([A-Za-z_]\w*|\d)")
_SUBST = re.compile(r"\$\(([\w.+-]+(?:\$\{md_id\}|\$md_id)?)\)")
_MD_ID_TEST = re.compile(r'^!?\s*\[\[\s*"\$md_id"\s*(==|!=)\s*"?([\w.+-]+)"?\s*\]\]$')


class LauncherPatternMissing(ValueError):
    """A construct an extractor reads is absent from the scriptmodules."""

    def __init__(self, path: str, what: str) -> None:
        super().__init__(f"{path}: {what}")


@dataclass
class Launcher(ConfiggenLauncher):
    """One thing a package hands an emulator, or the package itself."""

    # Unset when the package script checks nothing, where configgen writes False.
    fails_when_missing: bool | str | None = None
    package: str | None = None
    repo: str | None = None
    lines: list[tuple[str, int]] = field(default_factory=list, repr=False)

    ENTRY_ORDER: ClassVar[tuple[str, ...]] = (
        "emulator", "package", "repo", "systems", "build", "kind", "slot",
        "names", "case_insensitive", "search_dir", "passes_to",
        "fails_when_missing", "depends_on_option", "installs", "kept_if_present",
        "overrides", "source_ref",
    )


@dataclass
class Module:
    """One package script: its id, section, lines and functions."""

    path: str
    section: str
    lines: list[str]
    id: str
    id_line: int
    repo: str | None
    repo_line: int | None
    functions: dict[str, tuple[int, int]] = field(default_factory=dict)

    @property
    def build(self) -> str:
        libretro = self.section == "libretrocores" or self.id == LIBRETRO_FRONTEND
        return "libretro" if libretro else "standalone"


@dataclass
class Event:
    """A statement reached while walking a package's functions."""

    path: str
    line: int
    words: list[list[str]]
    raw: str
    conditions: list[str]
    heredoc: bool
    opener: list[list[str]] = field(default_factory=list)


def _logical_lines(
    lines: list[str], start: int, end: int
) -> Iterator[tuple[int, str, str | None]]:
    """(line number, text, heredoc opener or None) for lines start..end, continuations joined."""
    tag: str | None = None
    opener = ""
    number = start
    while number <= end:
        text = lines[number - 1]
        first = number
        if tag is not None:
            if text.strip() == tag:
                tag = None
            else:
                yield first, text, opener
            number += 1
            continue
        while text.rstrip().endswith("\\") and number < end:
            number += 1
            text = text.rstrip()[:-1] + " " + lines[number - 1].strip()
        opened = _HEREDOC.search(text)
        if opened is not None:
            tag = opened.group(1)
            opener = text.strip()
        yield first, text, None
        number += 1


def _brace(word: str) -> list[str]:
    """Bash brace expansion of comma lists, outside variable references."""
    found = re.search(r"(?<!\$)\{([^{}$]*,[^{}$]*)\}", word)
    if found is None:
        return [word]
    head, tail = word[: found.start()], word[found.end():]
    return [
        expanded
        for option in found.group(1).split(",")
        for expanded in _brace(head + option + tail)
    ]


def _split(text: str) -> list[str]:
    """Shell words with quotes removed, a line bash itself would accept."""
    try:
        return shlex.split(text, comments=True)
    except ValueError:
        return text.split()


class Scripts:
    """Every package script, with the functions RetroPie loads into one shell."""

    def __init__(self, files: dict[str, str]) -> None:
        self.files = files
        self.modules: dict[str, Module] = {}
        self.owner: dict[str, Module] = {}
        self._walked: dict[str, list[Event]] = {}
        for path in sorted(files):
            parts = PurePosixPath(path).parts
            is_package = (
                len(parts) == 3
                and parts[0] == SCRIPTMODULES
                and parts[1] in SECTIONS
                and parts[2].endswith(".sh")
            )
            if is_package:
                module = self._parse(path, parts[1], files[path])
                if module is not None:
                    self.modules[module.id] = module
        if not self.modules:
            raise LauncherPatternMissing(SCRIPTMODULES, "no package script declares rp_module_id")
        for module in self.modules.values():
            for name in module.functions:
                self.owner[name] = module

    @staticmethod
    def _parse(path: str, section: str, text: str) -> Module | None:
        lines = text.splitlines()
        fields = module_field_lines(text)
        if "id" not in fields:
            return None
        repo = fields.get("repo")
        module = Module(
            path=path, section=section, lines=lines,
            id=fields["id"][0], id_line=fields["id"][1],
            repo=repo[0] if repo else None, repo_line=repo[1] if repo else None,
        )
        opened: tuple[str, int] | None = None
        tag: str | None = None
        for number, line in enumerate(lines, 1):
            # A generated script may define functions of its own.
            if tag is not None:
                if line.strip() == tag:
                    tag = None
                continue
            heredoc = _HEREDOC.search(line)
            if heredoc is not None:
                tag = heredoc.group(1)
            header = _FUNCTION.match(line)
            if header is not None:
                opened = (header.group(1), number)
            elif opened is not None and line.rstrip() == "}":
                module.functions[opened[0]] = (opened[1], number)
                opened = None
        if opened is not None:
            raise LauncherPatternMissing(path, f"function {opened[0]} has no closing brace")
        return module

    def echo_value(self, name: str) -> str | None:
        """What a function whose whole body is one `echo "X"` prints."""
        module = self.owner.get(name)
        if module is None:
            return None
        start, end = module.functions[name]
        body = [line.strip() for line in module.lines[start:end - 1] if line.strip()]
        if len(body) == 1:
            words = _split(body[0])
            if len(words) == 2 and words[0] == "echo":
                return words[1]
        return None

    def walk(self, package: Module) -> list[Event]:
        """Every statement of a package's functions, as RetroPie runs them for it."""
        if package.id not in self._walked:
            events: dict[tuple[str, int], Event] = {}
            for name in package.functions:
                self._walk(package, name, {}, [], set(), events)
            self._walked[package.id] = sorted(
                events.values(), key=lambda e: (e.path != package.path, e.path, e.line)
            )
        return self._walked[package.id]

    def _walk(
        self,
        package: Module,
        name: str,
        args: dict[str, list[str]],
        conditions: list[str],
        stack: set[str],
        events: dict[tuple[str, int], Event],
    ) -> None:
        if name in stack:
            return
        module = self.owner[name]
        start, end = module.functions[name]
        env: dict[str, list[str]] = dict(args)
        loops: list[tuple[str | None, list[str] | None]] = []
        branches: list[tuple[str, bool | None]] = []
        array: tuple[str, list[str]] | None = None
        for number, text, opener in _logical_lines(module.lines, start + 1, end - 1):
            stripped = text.strip()
            if array is not None:
                if self._array_line(array, stripped, package, env):
                    array = None
                continue
            if opener is not None:
                if self._live(branches):
                    events.setdefault((module.path, number), Event(
                        module.path, number, self._expand_all(stripped.split(), package, env),
                        stripped, conditions + self._shown(branches, package, env), True,
                        self._expand_all(_split(opener), package, env),
                    ))
                continue
            if not stripped or stripped.startswith("#"):
                continue
            if self._branch(stripped, package, env, branches):
                continue
            if not self._live(branches):
                continue
            if self._loop(stripped, package, env, loops):
                continue
            if stripped in ("do", "then", "else", "fi", "esac", "{", "}"):
                continue
            guarded = self._guard(
                stripped, package, env, conditions + self._shown(branches, package, env)
            )
            if guarded is None:
                continue
            stripped, shown = guarded
            opens = re.match(r"^(?:local\s+)?([A-Za-z_]\w*)=\(([^)]*)$", stripped)
            if opens is not None:
                array = (opens.group(1), [opens.group(2)])
                continue
            if self._bind(stripped, package, env):
                continue
            words = [self.expand(w, package, env) for w in _split(stripped)]
            # The first walk to reach a line is the one with its caller's arguments.
            events.setdefault(
                (module.path, number), Event(module.path, number, words, stripped, shown, False)
            )
            self._descend(package, name, words, shown, stack, events)

    def _descend(
        self,
        package: Module,
        name: str,
        words: list[list[str]],
        shown: list[str],
        stack: set[str],
        events: dict[tuple[str, int], Event],
    ) -> None:
        """Walk the function a statement calls, with the words it passes."""
        callee = words[0][0] if words and words[0] else None
        if callee in self.owner and callee != name:
            call_args = {str(i): w for i, w in enumerate(words[1:], 1)}
            self._walk(package, callee, call_args, shown, stack | {name}, events)

    def _expand_all(
        self, words: list[str], package: Module, env: dict[str, list[str]]
    ) -> list[list[str]]:
        return [self.expand(w, package, env) for w in words]

    def _array_line(
        self, array: tuple[str, list[str]], stripped: str, package: Module,
        env: dict[str, list[str]],
    ) -> bool:
        """Add one line to a multi-line array, and say whether it closed it."""
        body = re.sub(r"\s+#.*$", "", stripped)
        closed = body.endswith(")")
        array[1].append(body[:-1] if closed else body)
        if closed:
            words = _split(" ".join(array[1]))
            env[array[0]] = [v for w in words for v in self.expand(w, package, env)]
        return closed

    def _loop(
        self, stripped: str, package: Module, env: dict[str, list[str]],
        loops: list[tuple[str | None, list[str] | None]],
    ) -> bool:
        """Track for/while/until/done, and say whether the line was one of them."""
        loop = _FOR.match(stripped)
        if loop is not None:
            values = [v for w in _split(loop.group(2)) for v in self.expand(w, package, env)]
            loops.append((loop.group(1), env.get(loop.group(1))))
            env[loop.group(1)] = values
            return True
        if re.match(r"^(while|until)\b|^for\s*\(\(", stripped):
            loops.append((None, None))
            return True
        if stripped == "done" or stripped.startswith(("done ", "done;")):
            if loops:
                var, previous = loops.pop()
                if var is not None:
                    if previous is None:
                        env.pop(var, None)
                    else:
                        env[var] = previous
            return True
        return False

    def _guard(
        self, stripped: str, package: Module, env: dict[str, list[str]], shown: list[str]
    ) -> tuple[str, list[str]] | None:
        """The statement a `[[ test ]] && statement` runs and its conditions, None if never."""
        guard = re.match(r"^\[\[\s*(.*?)\s*\]\]\s*&&\s*(.*)$", stripped)
        if guard is None:
            return stripped, shown
        verdict = self._md_id_test(f"[[ {guard.group(1)} ]]", package)
        if verdict is False or "$md_mode" in guard.group(1) or "$mode" in guard.group(1):
            return None
        if verdict is None:
            shown = shown + [self._render(guard.group(1), package, env)]
        return guard.group(2), shown

    def _branch(
        self, stripped: str, package: Module, env: dict[str, list[str]],
        branches: list[tuple[str, bool | None]],
    ) -> bool:
        """Track if/elif/else/fi, and say whether the line was one of them."""
        opened = re.match(r"^(if|elif)\s+(.*?)\s*(?:;\s*then)?\s*$", stripped)
        if opened is not None:
            condition = opened.group(2)
            verdict = self._md_id_test(condition, package)
            if "$md_mode" in condition or "$mode" in condition:
                verdict = True if "install" in condition else None
            if opened.group(1) == "if":
                branches.append((condition, verdict))
            elif branches:
                previous, previous_verdict = branches[-1]
                if previous_verdict is True:
                    verdict = False
                branches[-1] = (condition, verdict)
            return True
        if stripped == "else" and branches:
            condition, verdict = branches[-1]
            branches[-1] = (f"not ({condition})", None if verdict is None else not verdict)
            return True
        if stripped == "fi" or stripped.startswith("fi "):
            if branches:
                branches.pop()
            return True
        return False

    @staticmethod
    def _live(branches: list[tuple[str, bool | None]]) -> bool:
        return all(verdict is not False for _c, verdict in branches)

    def _shown(
        self, branches: list[tuple[str, bool | None]], package: Module, env: dict[str, list[str]]
    ) -> list[str]:
        return [
            self._render(condition, package, env)
            for condition, verdict in branches if verdict is None
        ]

    def _render(self, condition: str, package: Module, env: dict[str, list[str]]) -> str:
        """A condition with its variables filled in when each takes one value."""
        values = self.expand(condition, package, env)
        return values[0] if len(values) == 1 else condition

    @staticmethod
    def _md_id_test(condition: str, package: Module) -> bool | None:
        test = _MD_ID_TEST.match(condition.strip())
        if test is None:
            return None
        equal = package.id == test.group(2)
        return equal if test.group(1) == "==" else not equal

    def _bind(self, stripped: str, package: Module, env: dict[str, list[str]]) -> bool:
        """Record a variable assignment, and say whether the line was one."""
        if _DECLARE.match(stripped):
            return True
        assign = _ASSIGN.match(stripped)
        if assign is None:
            return False
        name, value = assign.group(1), assign.group(2).strip()
        if value.startswith("("):
            closing = value.rfind(")")
            inner = value[1:closing] if closing > 0 else value[1:]
            env[name] = [v for w in _split(inner) for v in self.expand(w, package, env)]
            return True
        words = _split(value) or [""]
        if "$(" in words[0] and _SUBST.fullmatch(words[0]) is None:
            # A command's output: the variable stays a reference.
            env.pop(name, None)
            return True
        expanded = self.expand(words[0], package, env)
        if any("$(" in v for v in expanded):
            env.pop(name, None)
        else:
            env[name] = expanded
        return True

    def expand(self, word: str, package: Module, env: dict[str, list[str]]) -> list[str]:
        """Every value a word takes: braces, $md_id, bound variables, $(echo functions)."""
        word = re.sub(r"\$\{md_id\}|\$md_id\b", package.id, word)

        def substitute(found: re.Match[str]) -> str:
            printed = self.echo_value(found.group(1))
            return printed if printed is not None else found.group(0)

        word = _SUBST.sub(substitute, word)
        results: list[str] = []
        for braced in _brace(word):
            names = [m.group(1) or m.group(3) for m in _VAR.finditer(braced)]
            bound = [n for n in names if n in env]
            if not bound:
                results.append(braced)
                continue
            results.extend(
                _VAR.sub(partial(_bound_value, dict(zip(bound, values))), braced)
                for values in product(*(env[n] for n in bound))
            )
        return results


def _bound_value(chosen: dict[str, str], found: re.Match[str]) -> str:
    key = found.group(1) or found.group(3)
    return chosen.get(key, found.group(0))


def merge_records(records: list[Launcher]) -> list[Launcher]:
    """Records equal but for their lines become one, citing every line."""
    merged: dict[tuple[Any, ...], Launcher] = {}
    for record in records:
        entry = record.entry()
        entry.pop("source_ref")
        key = tuple((k, repr(v)) for k, v in entry.items())
        if key in merged:
            kept = merged[key]
            kept.lines += record.lines
            kept.source_ref = source_ref(kept.lines)
        else:
            merged[key] = record
    return list(merged.values())


def source_ref(lines: list[tuple[str, int]]) -> str:
    """`path:a-b, c` per file, in first-seen file order, adjacent lines joined."""
    # Not shell_launchers.merge_lines: joining across a one-line gap would turn
    # the committed lr-prboom.sh:86, 88 of four retropie.yml records into 86-88.
    by_path: dict[str, list[int]] = {}
    for path, number in lines:
        by_path.setdefault(path, []).append(number)
    parts = []
    for path, numbers in by_path.items():
        ranges: list[list[int]] = []
        for number in sorted(set(numbers)):
            if ranges and number == ranges[-1][1] + 1:
                ranges[-1][1] = number
            else:
                ranges.append([number, number])
        spans = ", ".join(str(a) if a == b else f"{a}-{b}" for a, b in ranges)
        parts.append(f"{path}:{spans}")
    return ", ".join(parts)
