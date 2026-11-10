"""RetroPie's launcher layer, read from the scriptmodules.

RetroPie publishes no BIOS list, but its package scripts decide where a file
dropped in ~/RetroPie/BIOS ends up: px68k links five names into ~/.keropi,
redream links dc_boot.bin under another name, sdltrs passes one ROM per
machine on its command line, the fs-uae launch script refuses to start
without kick13.rom. Each package also says which project it builds
(`rp_module_repo`) and which systems it registers (`addSystem`), which is
what ties a package to the emulator profile describing that build.

The bash is read as text, never run. A small evaluator follows what the
scripts do between a function's braces: local assignments, arrays, `for`
loops, brace expansion, `$md_id` and calls into other packages' functions,
the way RetroPie runs them in one shell. Every line of a package function
that names the BIOS directory must match a known construct, else the scrape
stops with LauncherPatternMissing: a use nobody classified would otherwise
drop out of the platform file without a word.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Iterator
from dataclasses import dataclass, field
from itertools import product
from pathlib import PurePosixPath
from typing import Any

SCRIPTMODULES = "scriptmodules"
SECTIONS = ("emulators", "libretrocores", "ports")
PACKAGES_SCRIPT = "retropie_packages.sh"

BIOSDIR = "$biosdir"
# The package whose config every lr- core runs under.
LIBRETRO_FRONTEND = "retroarch"
# The launch scripts copied next to an emulator spell the directory out.
BIOS_SPELLED = "RetroPie/BIOS"

# Commands whose $biosdir argument creates, owns or deletes a path and hands
# nothing to an emulator.
HOUSEKEEPING = frozenset({"mkUserDir", "chown", "chmod", "rm", "mkdir", "iniConfig"})

# Arguments that name a BIOS file or directory outside $biosdir, per package,
# as the emulator documents the flag. Each must still be in the scriptmodule.
OUTSIDE_BIOS: dict[str, tuple[str, ...]] = {
    "basilisk": ("--rom",),  # BasiliskII --rom <ROM file>
    "gngeopi": ("-B",),  # gngeo -B/--biospath <directory of neogeo.zip>
}

# Packages whose emulator reads its system files below the working directory
# the generated launch script enters with pushd: DraStic opens system/<name>
# under it, UAE4All2 kickstarts/<name> (its launchDir is getcwd()). Each must
# still pushd.
WORKING_DIRECTORY: tuple[str, ...] = ("drastic", "uae4all")

_FUNCTION = re.compile(r"^function\s+([\w.+-]+)\s*\(\)\s*\{\s*$")
_ASSIGN = re.compile(r"^(?:local\s+)?([A-Za-z_]\w*)=(.*)$")
_DECLARE = re.compile(r"^local\s+([A-Za-z_]\w*(?:\s+[A-Za-z_]\w*)*)\s*$")
_FOR = re.compile(r"^for\s+([A-Za-z_]\w*)\s+in\s+(.*?)\s*(?:;\s*do)?\s*$")
_HEREDOC = re.compile(r"(?<!<)<<-?(?!<)\s*['\"]?(\w+)['\"]?")
_VAR = re.compile(r"\$\{([A-Za-z_]\w*)(\[@\])?\}|\$([A-Za-z_]\w*|\d)")
_SUBST = re.compile(r"\$\(([\w.+-]+(?:\$\{md_id\}|\$md_id)?)\)")
_MD_ID_TEST = re.compile(r'^!?\s*\[\[\s*"\$md_id"\s*(==|!=)\s*"?([\w.+-]+)"?\s*\]\]$')
_MODULE_FIELD = re.compile(r'^rp_module_(id|repo)="([^"]*)"', re.MULTILINE)
_EXTENSION = re.compile(r"\.[A-Za-z0-9]{1,5}$")


class LauncherPatternMissing(ValueError):
    """A construct an extractor reads is absent from the scriptmodules."""

    def __init__(self, path: str, what: str) -> None:
        super().__init__(f"{path}: {what}")


@dataclass
class Launcher:
    """One thing a package hands an emulator, or the package itself."""

    emulator: str
    build: str
    kind: str
    names: list[str]
    source_ref: str
    package: str | None = None
    repo: str | None = None
    systems: list[str] | None = None
    slot: str | None = None
    case_insensitive: bool | None = None
    search_dir: str | None = None
    passes_to: str | None = None
    fails_when_missing: bool | str | None = None
    depends_on_option: str | None = None
    lines: list[tuple[str, int]] = field(default_factory=list, repr=False)

    def entry(self) -> dict[str, Any]:
        """The platform YAML form, in a fixed key order, unset keys left out."""
        order = (
            "emulator", "package", "repo", "systems", "build", "kind", "slot",
            "names", "case_insensitive", "search_dir", "passes_to",
            "fails_when_missing", "depends_on_option", "source_ref",
        )
        return {key: getattr(self, key) for key in order if getattr(self, key) is not None}


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
        fields: dict[str, tuple[str, int]] = {}
        for found in _MODULE_FIELD.finditer(text):
            line = text.count("\n", 0, found.start()) + 1
            fields.setdefault(found.group(1), (found.group(2), line))
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
                body = re.sub(r"\s+#.*$", "", stripped)
                closed = body.endswith(")")
                array[1].append(body[:-1] if closed else body)
                if closed:
                    words = _split(" ".join(array[1]))
                    env[array[0]] = [v for w in words for v in self.expand(w, package, env)]
                    array = None
                continue
            if opener is not None:
                if self._live(branches):
                    words = [self.expand(w, package, env) for w in stripped.split()]
                    events.setdefault((module.path, number), Event(
                        module.path, number, words, stripped,
                        conditions + self._shown(branches, package, env), True,
                        [self.expand(w, package, env) for w in _split(opener)],
                    ))
                continue
            if not stripped or stripped.startswith("#"):
                continue
            if self._branch(stripped, package, env, branches):
                continue
            if not self._live(branches):
                continue
            loop = _FOR.match(stripped)
            if loop is not None:
                values = [v for w in _split(loop.group(2)) for v in self.expand(w, package, env)]
                loops.append((loop.group(1), env.get(loop.group(1))))
                env[loop.group(1)] = values
                continue
            if re.match(r"^(while|until)\b|^for\s*\(\(", stripped):
                loops.append((None, None))
                continue
            if stripped == "done" or stripped.startswith("done ") or stripped.startswith("done;"):
                if loops:
                    var, previous = loops.pop()
                    if var is not None:
                        if previous is None:
                            env.pop(var, None)
                        else:
                            env[var] = previous
                continue
            if stripped in ("do", "then", "else", "fi", "esac", "{", "}"):
                continue
            guard = re.match(r"^\[\[\s*(.*?)\s*\]\]\s*&&\s*(.*)$", stripped)
            shown = conditions + self._shown(branches, package, env)
            if guard is not None:
                verdict = self._md_id_test(f"[[ {guard.group(1)} ]]", package)
                if verdict is False or "$md_mode" in guard.group(1) or "$mode" in guard.group(1):
                    continue
                if verdict is None:
                    shown = shown + [self._render(guard.group(1), package, env)]
                stripped = guard.group(2)
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
            callee = words[0][0] if words and words[0] else None
            if callee in self.owner and callee != name:
                call_args = {str(i): w for i, w in enumerate(words[1:], 1)}
                self._walk(package, callee, call_args, shown, stack | {name}, events)

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
            for values in product(*(env[n] for n in bound)):
                chosen = dict(zip(bound, values))

                def replace(found: re.Match[str]) -> str:
                    key = found.group(1) or found.group(3)
                    return chosen.get(key, found.group(0))

                results.append(_VAR.sub(replace, braced))
        return results


def _mentions_bios(text: str) -> bool:
    return BIOSDIR in text or "${biosdir}" in text or BIOS_SPELLED in text


def _is_file(path: str) -> bool:
    return bool(_EXTENSION.search(PurePosixPath(path).name)) and "*" not in path


def _split_path(path: str) -> tuple[str, str]:
    pure = PurePosixPath(path.rstrip("/"))
    return str(pure.parent), pure.name


class PackageReader:
    """Launcher records of one package, from the statements its functions run."""

    def __init__(self, scripts: Scripts, package: Module) -> None:
        self.scripts = scripts
        self.package = package
        self.records: list[Launcher] = []
        self.installed_as: dict[str, str] = {}

    def record(
        self, kind: str, names: list[str], lines: list[tuple[str, int]], **fields: Any
    ) -> None:
        self.records.append(Launcher(
            emulator=fields.pop("emulator", self.package.id),
            package=self.package.id,
            build=self.package.build,
            kind=kind,
            names=names,
            source_ref=source_ref(lines),
            lines=list(lines),
            **fields,
        ))

    def final(self, path: str) -> str:
        """The file a scratch config ends up as, from the copyDefaultConfig that installs it."""
        return self.installed_as.get(path, path)

    def read(self) -> list[Launcher]:
        events = self.scripts.walk(self.package)
        for event in events:
            if not event.heredoc and event.words and event.words[0] == ["copyDefaultConfig"]:
                if len(event.words) >= 3 and len(event.words[1]) == 1 and len(event.words[2]) == 1:
                    self.installed_as.setdefault(event.words[1][0], event.words[2][0])
        links: list[Event] = []
        for event in events:
            if not event.words or not event.words[0]:
                continue
            if links and not self._same_link_run(links[-1], event):
                self._links(links)
                links = []
            if self._is_bios_link(event):
                links.append(event)
                continue
            self._classify(event)
        if links:
            self._links(links)
        self._outside_bios(events)
        self._working_directory(events)
        self._reaching_links(events)
        return self.records

    @staticmethod
    def _depends(event: Event) -> str | None:
        return "; ".join(event.conditions) if event.conditions else None

    def _classify(self, event: Event) -> None:
        command = event.words[0][0]
        if event.heredoc:
            if _mentions_bios(event.raw):
                self._heredoc_setting(event)
            return
        if command == "addEmulator":
            self._add_emulator(event)
            return
        if not _mentions_bios(event.raw):
            return
        if command in HOUSEKEEPING:
            return
        handlers = {
            "cp": self._copy,
            "runCmd": self._run_cmd,
            "unzip": self._unzip,
            "mv": self._move,
            "moveConfigFile": self._move,
            "moveConfigDir": self._move_dir,
            "iniSet": self._ini_set,
            "copyDefaultConfig": self._written,
            "cat": self._written,
            "echo": self._written,
            "cmake": self._build_flag,
        }
        handler = handlers.get(command)
        if handler is None:
            raise LauncherPatternMissing(
                f"{event.path}:{event.line}", f"unrecognised use of the BIOS directory: {event.raw}"
            )
        handler(event)

    def _is_bios_link(self, event: Event) -> bool:
        words = event.words
        if words[0][0] != "ln" or not _mentions_bios(event.raw):
            return False
        paths = [w for w in words[1:] if not w[0].startswith("-")]
        if len(paths) != 2 or not all(_mentions_bios(v) for v in paths[0]):
            raise LauncherPatternMissing(
                f"{event.path}:{event.line}", f"link without a BIOS source: {event.raw}"
            )
        return True

    @staticmethod
    def _same_link_run(previous: Event, event: Event) -> bool:
        return (
            event.words[0][0] == "ln"
            and previous.path == event.path
            and event.line - previous.line <= 2
        )

    def _links(self, events: list[Event]) -> None:
        sources: list[str] = []
        targets: list[str] = []
        for event in events:
            paths = [w for w in event.words[1:] if not w[0].startswith("-")]
            source, target = paths
            if len(target) == 1 and len(source) > 1:
                target = [f"{target[0].rstrip('/')}/{_split_path(s)[1]}" for s in source]
            sources += source
            targets += target
        folders = {_split_path(s)[0] for s in sources}
        whole_dir = all(
            not _is_file(s) and "/" not in s.replace(BIOSDIR, "", 1).strip("/") for s in sources
        )
        if whole_dir:
            names: list[str] = []
            search_dir = sources[0]
            passes_to = f"{targets[0]} is a symlink to it"
        else:
            if len(folders) != 1:
                raise LauncherPatternMissing(
                    f"{events[0].path}:{events[0].line}",
                    "links from several BIOS folders in one run",
                )
            search_dir = folders.pop()
            names = [_split_path(s)[1] for s in sources]
            passes_to = _render_targets(names, targets)
        self.record(
            "links", names, [(e.path, e.line) for e in events],
            case_insensitive=False, search_dir=search_dir, passes_to=passes_to,
            fails_when_missing=False, depends_on_option=self._depends(events[0]),
        )

    def _copy(self, event: Event) -> None:
        paths = [v for w in event.words[1:] if not w[0].startswith("-") for v in w]
        *sources, target = paths
        if not _mentions_bios(target):
            raise LauncherPatternMissing(
                f"{event.path}:{event.line}", f"copy out of the BIOS directory: {event.raw}"
            )
        folders = {_split_path(s)[0] for s in sources}
        if len(folders) != 1:
            raise LauncherPatternMissing(f"{event.path}:{event.line}", "copy from several folders")
        self.record(
            "copies", [_split_path(s)[1] for s in sources], [(event.path, event.line)],
            search_dir=folders.pop(), passes_to=target.rstrip("/"),
            fails_when_missing=False, depends_on_option=self._depends(event),
        )

    def _run_cmd(self, event: Event) -> None:
        inner = Event(event.path, event.line, event.words[1:], event.raw, event.conditions, False)
        if not inner.words or inner.words[0][0] != "unzip":
            raise LauncherPatternMissing(f"{event.path}:{event.line}", f"runCmd of {event.raw}")
        self._unzip(inner)

    def _unzip(self, event: Event) -> None:
        values = [v for w in event.words[1:] for v in w]
        if "-d" not in values:
            raise LauncherPatternMissing(f"{event.path}:{event.line}", "unzip without -d")
        target = values[values.index("-d") + 1]
        archives = [v for v in values if v.endswith(".zip")]
        if len(archives) != 1 or not _mentions_bios(target):
            raise LauncherPatternMissing(f"{event.path}:{event.line}", f"unzip of {event.raw}")
        self.record(
            "copies", [], [(event.path, event.line)],
            search_dir=archives[0], passes_to=target,
            fails_when_missing=False, depends_on_option=self._depends(event),
        )

    def _move(self, event: Event) -> None:
        source, target = (w for w in event.words[1:] if not w[0].startswith("-"))
        if not all(_mentions_bios(v) for v in source + target):
            raise LauncherPatternMissing(
                f"{event.path}:{event.line}", f"move across folders: {event.raw}"
            )
        folders = {_split_path(s)[0] for s in source}
        destinations = {_split_path(t)[0] for t in target}
        if len(folders) != 1 or len(destinations) != 1:
            raise LauncherPatternMissing(
                f"{event.path}:{event.line}", "move between several folders"
            )
        self.record(
            "moves", [_split_path(s)[1] for s in source], [(event.path, event.line)],
            case_insensitive=False, search_dir=folders.pop(), passes_to=destinations.pop(),
            fails_when_missing=False, depends_on_option=self._depends(event),
        )

    def _move_dir(self, event: Event) -> None:
        link, real = (w[0] for w in event.words[1:3])
        if not _mentions_bios(real) or _mentions_bios(link):
            raise LauncherPatternMissing(
                f"{event.path}:{event.line}", f"moveConfigDir into a non-BIOS folder: {event.raw}"
            )
        self.record(
            "links", [], [(event.path, event.line)],
            search_dir=real, passes_to=f"{link} is a symlink to it",
            fails_when_missing=False, depends_on_option=self._depends(event),
        )

    def _ini_set(self, event: Event) -> None:
        key, value = event.words[1][0], event.words[2][0]
        target = self._ini_file(event)
        passes_to = f"{key} in {self.final(target)}" if target else key
        if _is_file(value) and ";" not in value:
            folder, name = _split_path(value)
            self.record(
                "fixed_name", [name], [(event.path, event.line)],
                case_insensitive=False, search_dir=folder, passes_to=passes_to,
                fails_when_missing=False, depends_on_option=self._depends(event),
            )
            return
        self.record(
            "passes_path", [], [(event.path, event.line)],
            search_dir=value, passes_to=passes_to,
            fails_when_missing=False, depends_on_option=self._depends(event),
        )

    def _ini_file(self, event: Event) -> str | None:
        """The file the closest iniConfig above this iniSet points at."""
        if len(event.words) > 3:
            return event.words[3][0]
        lines = self.scripts.files[event.path].splitlines()
        for number in range(event.line - 1, 0, -1):
            words = _split(lines[number - 1].strip())
            if words and words[0] == "iniConfig" and len(words) >= 4:
                return words[3]
            if _FUNCTION.match(lines[number - 1]):
                break
        return None

    def _written(self, event: Event) -> None:
        """A file the package writes into the BIOS directory itself."""
        target = next(
            (v for w in reversed(event.words[1:]) for v in w if _mentions_bios(v)), None
        )
        if target is None or not _is_file(target):
            raise LauncherPatternMissing(f"{event.path}:{event.line}", f"write of {event.raw}")
        folder, name = _split_path(target)
        self.record(
            "copies", [name], [(event.path, event.line)],
            search_dir=None, passes_to=folder,
            fails_when_missing=False, depends_on_option=self._depends(event),
        )

    def _build_flag(self, event: Event) -> None:
        flags = [
            v for w in event.words[1:] for v in w
            if v.startswith("-D") and "=" in v and _mentions_bios(v)
        ]
        if not flags:
            raise LauncherPatternMissing(f"{event.path}:{event.line}", f"cmake of {event.raw}")
        for flag in flags:
            option, value = flag.split("=", 1)
            self.record(
                "passes_path", [], [(event.path, event.line)],
                search_dir=value, passes_to=f"build option {option}",
                fails_when_missing=False, depends_on_option=self._depends(event),
            )

    def _heredoc_setting(self, event: Event) -> None:
        """A `KEY = $biosdir/...` or `--flag="$biosdir"` line of a generated file."""
        text = event.raw
        setting = re.match(r'^([\w.-]+)\s*=\s*"?([^"]*)"?$', text)
        flag = re.match(r'^(--?[\w-]+)(?:=|\s+)"?([^"]*)"?$', text)
        found = flag or setting
        if found is None:
            raise LauncherPatternMissing(
                f"{event.path}:{event.line}", f"generated line names the BIOS directory: {text}"
            )
        key, value = found.group(1), found.group(2)
        kind, names, folder = "passes_path", [], value
        if _is_file(value):
            folder, name = _split_path(value)
            kind, names = "fixed_name", [name]
        written = _redirect_target(event.opener)
        if written is None:
            raise LauncherPatternMissing(
                f"{event.path}:{event.line}", "generated file with no > or >> target"
            )
        self.record(
            kind, names, [(event.path, event.line)],
            case_insensitive=False if kind == "fixed_name" else None,
            search_dir=folder, passes_to=f"{key} in {self.final(written)}",
            fails_when_missing=False, depends_on_option=self._depends(event),
        )

    def _add_emulator(self, event: Event) -> None:
        if len(event.words) < 5:
            return
        command = event.words[4][0]
        if not _mentions_bios(command):
            return
        names = event.words[2]
        tokens = _split(command)
        found = [
            (flag, value) for flag, value in zip(tokens, tokens[1:])
            if flag.startswith("-") and _mentions_bios(value)
        ]
        found += [
            tuple(token.split("=", 1)) for token in tokens
            if token.startswith("-") and "=" in token and _mentions_bios(token.split("=", 1)[1])
        ]
        if not found:
            raise LauncherPatternMissing(
                f"{event.path}:{event.line}",
                f"addEmulator names the BIOS directory without a flag: {command}",
            )
        for emulator in names:
            for flag, value in found:
                self._command_line(event, emulator, flag, value)

    def _command_line(self, event: Event, emulator: str, flag: str, value: str) -> None:
        folder, name = _split_path(value)
        if _is_file(value):
            kind, names, search = "fixed_name", [name], folder
        else:
            kind, names, search = "passes_path", [], value
        self.record(
            kind, names, [(event.path, event.line)], emulator=emulator,
            case_insensitive=False if kind == "fixed_name" else None,
            search_dir=search, passes_to=f"command line {flag}",
            fails_when_missing=False, depends_on_option=self._depends(event),
        )

    def _outside_bios(self, events: list[Event]) -> None:
        flags = OUTSIDE_BIOS.get(self.package.id)
        if not flags:
            return
        seen: set[str] = set()
        for event in events:
            if event.words[0][0] != "addEmulator" or len(event.words) < 5:
                continue
            tokens = _split(event.words[4][0])
            for flag, value in zip(tokens, tokens[1:]):
                if flag in flags:
                    seen.add(flag)
                    for emulator in event.words[2]:
                        self._command_line(event, emulator, flag, value)
        missing = sorted(set(flags) - seen)
        if missing:
            raise LauncherPatternMissing(
                self.package.path, f"addEmulator no longer passes {missing}"
            )


    def _reaching_links(self, events: list[Event]) -> None:
        """The directories outside the BIOS one that a whole-directory link lies in.

        openmsx's moveConfigDir "$home/.openMSX" "$configdir/msx/openmsx"
        puts the emulator's directory where the systemroms link to BIOS/openmsx
        lies, and xroar's ./configure --prefix="$md_inst" builds the program
        whose share/xroar/roms links to $biosdir. Neither line names the BIOS
        directory, and each says where the link is read from.
        """
        suffix = " is a symlink to it"
        linked = [
            (record.passes_to or "").removesuffix(suffix).rstrip("/")
            for record in self.records
            if record.kind == "links" and not record.names
            and (record.passes_to or "").endswith(suffix)
        ]
        if not linked:
            return

        def holds(directory: str) -> bool:
            directory = directory.strip("\"'").rstrip("/")
            return bool(directory) and any(
                path == directory or path.startswith(directory + "/") for path in linked
            )

        for event in events:
            if event.heredoc or not event.words or _mentions_bios(event.raw):
                continue
            command = event.words[0][0]
            if command == "moveConfigDir" and len(event.words) >= 3:
                link, real = event.words[1][0], event.words[2][0]
                if holds(real):
                    self.record(
                        "links", [], [(event.path, event.line)],
                        search_dir=real, passes_to=f"{link}{suffix}",
                        fails_when_missing=False, depends_on_option=self._depends(event),
                    )
            elif command.endswith("configure"):
                for word in event.words[1:]:
                    prefix = word[0].strip("\"'")
                    if prefix.startswith("--prefix=") and holds(prefix[len("--prefix="):]):
                        self.record(
                            "passes_path", [], [(event.path, event.line)],
                            search_dir=prefix[len("--prefix="):].strip("\"'"),
                            passes_to="${prefix} of configure --prefix",
                            fails_when_missing=False, depends_on_option=self._depends(event),
                        )

    def _working_directory(self, events: list[Event]) -> None:
        """The folder a generated launch script enters before it runs the emulator."""
        if self.package.id not in WORKING_DIRECTORY:
            return
        found = False
        for event in events:
            if not event.heredoc or not event.words or event.words[0] != ["pushd"]:
                continue
            script = _redirect_target(event.opener)
            if script is None or len(event.words) != 2 or len(event.words[1]) != 1:
                raise LauncherPatternMissing(
                    f"{event.path}:{event.line}", f"pushd outside a launch script: {event.raw}"
                )
            found = True
            self.record(
                "passes_path", [], [(event.path, event.line)],
                search_dir=event.words[1][0].strip("\"'"),
                passes_to=f"working directory of {script}",
                fails_when_missing=False, depends_on_option=self._depends(event),
            )
        if not found:
            raise LauncherPatternMissing(
                self.package.path, "the launch script no longer enters a working directory"
            )


def _redirect_target(words: list[list[str]]) -> str | None:
    """The file a `cat > FILE << EOF` or `cat << EOF >> FILE` line writes."""
    flat = [w[0] for w in words if w]
    for index, word in enumerate(flat[:-1]):
        if word in (">", ">>"):
            return flat[index + 1]
    return None


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


def _render_targets(names: list[str], targets: list[str]) -> str:
    """Where linked names land: one folder when the names are kept, each path when renamed."""
    folders = {_split_path(t)[0] for t in targets}
    kept = [_split_path(t)[1] for t in targets] == names
    if kept and len(folders) == 1:
        return f"{folders.pop()}/<name>"
    return ", ".join(targets)


def source_ref(lines: list[tuple[str, int]]) -> str:
    """`path:a-b, c` per file, in first-seen file order, adjacent lines joined."""
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


def package_record(scripts: Scripts, package: Module) -> Launcher:
    """What the package builds and the systems it registers."""
    systems: list[str] = []
    lines: list[tuple[str, int]] = [(package.path, package.id_line)]
    if package.repo_line is not None:
        lines.append((package.path, package.repo_line))
    for event in scripts.walk(package):
        if event.heredoc or not event.words or not event.words[0]:
            continue
        command = event.words[0][0]
        if command == "addSystem":
            values = event.words[1] if len(event.words) > 1 else []
        elif command == "addPort":
            values = ["ports"]
        else:
            continue
        if not values:
            raise LauncherPatternMissing(f"{event.path}:{event.line}", f"{command} takes no value")
        for value in values:
            if "$" in value or not value:
                raise LauncherPatternMissing(
                    f"{event.path}:{event.line}", f"system name {value!r} not resolved"
                )
            if value not in systems:
                systems.append(value)
        lines.append((event.path, event.line))
    return Launcher(
        emulator=package.id, package=package.id, repo=package.repo,
        systems=systems or None, build=package.build, kind="package", names=[],
        source_ref=source_ref(lines),
    )


def launch_script_records(scripts: Scripts) -> list[Launcher]:
    """The launch scripts installed next to an emulator that refuse to start without a file."""
    records = []
    for path, text in sorted(scripts.files.items()):
        parts = PurePosixPath(path).parts
        is_script = (
            len(parts) == 4 and parts[0] == SCRIPTMODULES and parts[1] in SECTIONS
            and path.endswith(".sh")
        )
        if not is_script or not _mentions_bios(text):
            continue
        package = scripts.modules.get(parts[2])
        if package is None:
            raise LauncherPatternMissing(path, f"launch script of no package {parts[2]}")
        records += _launch_script(path, text.splitlines(), package)
    return records


def _launch_script(path: str, lines: list[str], package: Module) -> list[Launcher]:
    env: dict[str, str] = {"HOME": "$HOME"}
    records = []
    checks = 0
    number = 0
    while number < len(lines):
        number += 1
        stripped = lines[number - 1].strip()
        if not stripped or stripped.startswith("#"):
            continue
        assign = re.match(r'^([A-Za-z_]\w*)="([^"]*)"$', stripped)
        if assign is not None:
            env[assign.group(1)] = _VAR.sub(
                lambda m: env.get(m.group(1) or m.group(3), m.group(0)), assign.group(2)
            )
            continue
        check = re.match(r'^if \[\[ ! -f "([^"]+)" \]\]; then$', stripped)
        if check is None:
            continue
        tested = check.group(1)
        resolved = _VAR.sub(lambda m: env.get(m.group(1) or m.group(3), m.group(0)), tested)
        if not _mentions_bios(resolved):
            continue
        block_start = number
        message: str | None = None
        exits = False
        while number < len(lines) and lines[number].strip() != "fi":
            number += 1
            body = lines[number - 1].strip()
            exits = exits or body == "exit 1"
            pause = re.search(r'--pause "([^"]*)"', body)
            if pause is not None:
                message = pause.group(1)
        number += 1
        if not exits:
            continue
        checks += 1
        variable = re.fullmatch(r"\$\{?(\w+)\}?", tested)
        passes_to = None
        cited = list(range(block_start, number + 1))
        if variable is not None:
            for later, line in enumerate(lines[number:], number + 1):
                flag = re.search(r'(--?[\w-]+)="\$' + variable.group(1) + r'"', line)
                if flag is not None:
                    passes_to = f"command line {flag.group(1)}"
                    cited.append(later)
                    break
        folder, name = _split_path(resolved)
        records.append(Launcher(
            emulator=package.id, package=package.id, build=package.build,
            kind="fixed_name", names=[name], case_insensitive=False,
            search_dir=folder, passes_to=passes_to,
            fails_when_missing=message if message is not None else True,
            source_ref=source_ref([(path, n) for n in cited]),
        ))
    if not checks:
        raise LauncherPatternMissing(path, "names the BIOS directory but checks no file")
    return records


def extract_launchers(files: dict[str, str]) -> list[dict[str, Any]]:
    """Every launcher record, from the scriptmodules keyed by repo-relative path."""
    scripts = Scripts(files)
    records: list[Launcher] = []
    for package in sorted(scripts.modules.values(), key=lambda m: m.path):
        records.append(package_record(scripts, package))
        records += merge_records(PackageReader(scripts, package).read())
    records += launch_script_records(scripts)
    return [record.entry() for record in records]
