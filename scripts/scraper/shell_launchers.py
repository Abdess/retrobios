"""Readers for launchers written as shell scripts and key=value configs.

ROCKNIX and EmuDeck launch emulators from bash: a start script links or
writes a BIOS path, a config shipped with the package names the file. These
helpers read that text without running it. Each one targets a construct
(an assignment, a for loop, an ln command, a key of a config) and the
extractors built on them raise LauncherPatternMissing when the construct is
gone, so a rewrite upstream stops the scrape instead of publishing nothing.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

try:
    from .base_scraper import fetch_bytes, github_headers
    from .configgen_launchers import LauncherShapeError
except ImportError:
    from base_scraper import fetch_bytes, github_headers
    from configgen_launchers import LauncherShapeError

NAME = r"[A-Za-z_][A-Za-z0-9_]*"
# A single-quoted "$" is literal: it is carried as this mark through expansion.
LITERAL_DOLLAR = "\x00"
# A loop variable expands to this mark around its name, so the caller can
# tell which part of a path the loop supplies.
LOOP_MARK = "\x01"


class LauncherPatternMissing(LauncherShapeError):
    """A construct an extractor reads is absent from the launcher source."""

    def __init__(self, path: str, what: str) -> None:
        super().__init__(f"{path}: {what} not found")


def span(first: int, last: int) -> str:
    return str(first) if first == last else f"{first}-{last}"


def merge_lines(lines: Iterable[int]) -> list[tuple[int, int]]:
    """Line numbers as sorted spans, a gap of one line joined."""
    spans: list[tuple[int, int]] = []
    for line in sorted(set(lines)):
        if spans and line <= spans[-1][1] + 2:
            spans[-1] = (spans[-1][0], line)
        else:
            spans.append((line, line))
    return spans


def source_ref(parts: Iterable[tuple[str, Iterable[int]]]) -> str:
    """path:a-b, c for each file, files in the order given."""
    merged: dict[str, set[int]] = {}
    for path, lines in parts:
        merged.setdefault(path, set()).update(lines)
    return ", ".join(
        f"{path}:{', '.join(span(*s) for s in merge_lines(lines))}"
        for path, lines in merged.items()
    )


# The files a platform ships as configuration: an emulator reads them, the
# platform's code never runs them. Batocera's .yml lists and an EmuELEC .opt
# only offer the values a menu option takes.
_CONFIG_FILE = re.compile(
    r"\.(?:ini|cfg|conf|rc|rc_\w+|opt|bml|toml|uae|template|yml|yaml)$", re.IGNORECASE
)
_FEATURE_FILE = re.compile(r"(?:^|/)es_features[^/]*$|\.opt$", re.IGNORECASE)


def split_ref(ref: str) -> list[str]:
    """The parts of a source_ref, each "path:lines", a bare line span
    continuing the path before it."""
    parts: list[str] = []
    for part in (p.strip() for p in ref.split(", ")):
        if not part:
            continue
        if re.fullmatch(r"\d+(?:-\d+)?", part) and parts:
            parts[-1] += f", {part}"
        else:
            parts.append(part)
    return parts


def ref_path(part: str) -> str:
    return part.rsplit(":", 1)[0] if re.search(r":\d", part) else part


def config_ref(ref: str) -> list[str]:
    """The parts of a source_ref that cite a config, option or feature file.

    Such a part proves what the file says, never that an emulator reads it:
    melonDS.ini keys are written on ROCKNIX for a build that reads them only
    when another key is set.
    """
    return [part for part in split_ref(ref) if _CONFIG_FILE.search(ref_path(part))]


def is_feature_ref(part: str) -> bool:
    """Whether a source_ref part cites a file that lists a menu option's values."""
    return bool(_FEATURE_FILE.search(ref_path(part)))


@dataclass
class Word:
    """A shell word: as written, and with quotes removed."""

    raw: str
    text: str


def words(line: str) -> list[Word]:
    """The words of one command line, quotes removed, comments dropped.

    Variables are left unexpanded, each written ${NAME} so the quoting that
    ended a name ("$a""b") still ends it. A "$" inside single quotes is kept
    as LITERAL_DOLLAR so a later expansion leaves it alone.
    """
    result: list[Word] = []
    raw, text, quote, started, segment = "", "", "", False, 0

    def close_segment() -> None:
        nonlocal text, segment
        text = text[:segment] + re.sub(rf"\$({NAME})", r"${\1}", text[segment:])
        segment = len(text)

    i = 0
    while i < len(line):
        char = line[i]
        if quote == "'":
            raw += char
            if char == "'":
                quote = ""
                segment = len(text)
            else:
                text += LITERAL_DOLLAR if char == "$" else char
        elif quote == '"':
            raw += char
            if char == "\\" and i + 1 < len(line) and line[i + 1] in '"\\$`':
                raw += line[i + 1]
                text += LITERAL_DOLLAR if line[i + 1] == "$" else line[i + 1]
                i += 1
            elif char == '"':
                quote = ""
                close_segment()
            else:
                text += char
        elif char in "'\"":
            close_segment()
            quote, started = char, True
            raw += char
        elif char == "\\" and i + 1 < len(line):
            raw += char + line[i + 1]
            text += line[i + 1]
            started = True
            i += 1
        elif char == "#" and not started:
            break
        elif char.isspace() or char == ";":
            if started:
                close_segment()
                result.append(Word(raw, text))
            raw, text, started, segment = "", "", False, 0
            if char == ";":
                result.append(Word(";", ";"))
        else:
            raw += char
            text += char
            started = True
        i += 1
    if started:
        close_segment()
        result.append(Word(raw, text))
    return result


@dataclass
class Assignment:
    line: int
    value: str


@dataclass
class Loop:
    """A for loop: its variable, its items and the lines they come from."""

    var: str
    items: list[str]
    start: int
    end: int
    lines: set[int] = field(default_factory=set)


@dataclass
class Link:
    """An ln -s whose link or target lies under the BIOS root."""

    target: str
    link: str
    bios_side: str
    names: list[str]
    lines: set[int]
    bios_is_target: bool = True
    expands: dict[str, list[str]] = field(default_factory=dict)


def _placeholders(text: str, marks: dict[str, Loop]) -> str:
    """Loop marks written as {VAR}, the placeholder `expands` resolves."""
    for mark, loop in marks.items():
        text = text.replace(mark, "{" + loop.var + "}")
    return text


class Script:
    """One shell script or makefile, read line by line."""

    def __init__(self, path: str, text: str) -> None:
        self.path = path
        self.text = text
        self.lines = text.splitlines()
        self._assignments: dict[str, list[Assignment]] = {}
        self._arrays: dict[str, tuple[int, list[str]]] = {}
        for number, line in enumerate(self.lines, 1):
            found = re.match(rf"\s*(?:local\s+|export\s+)?({NAME})=(.*)$", line)
            if found is None:
                continue
            array = re.fullmatch(r"\((.*)\)\s*", found.group(2))
            if array:
                self._arrays[found.group(1)] = (number, [w.text for w in words(array.group(1))])
                continue
            value = words(found.group(2))
            if value and value[0].raw:
                self._assignments.setdefault(found.group(1), []).append(
                    Assignment(number, value[0].text)
                )

    def missing(self, what: str) -> LauncherPatternMissing:
        return LauncherPatternMissing(self.path, what)

    def code(self) -> Iterable[tuple[int, str]]:
        """Lines that are not comments."""
        for number, line in enumerate(self.lines, 1):
            if not line.lstrip().startswith("#"):
                yield number, line

    def find(
        self, pattern: str, what: str, start: int = 1, end: int | None = None
    ) -> tuple[int, re.Match[str]]:
        """The first code line from start to end matching pattern."""
        for number, line in self.code():
            if number < start or (end is not None and number > end):
                continue
            found = re.search(pattern, line)
            if found:
                return number, found
        raise self.missing(what)

    def assignment_ending(self, suffix: str) -> Assignment | None:
        """The first assignment whose value ends with suffix."""
        return next(
            (a for found in self._assignments.values() for a in found if a.value.endswith(suffix)),
            None,
        )

    def value(self, name: str, before: int) -> Assignment | None:
        """The last assignment of name above a line, else the first below it."""
        assignments = self._assignments.get(name, [])
        above = [a for a in assignments if a.line < before]
        if above:
            return above[-1]
        return assignments[0] if assignments else None

    def expand(
        self, text: str, line: int, used: set[int], fixed: dict[str, str] | None = None
    ) -> str:
        """Variables replaced by their assigned value, unknown ones as ${NAME}."""
        fixed = fixed or {}

        def replace(found: re.Match[str], depth: int) -> str:
            name = found.group(1) or found.group(2)
            if name in fixed:
                return fixed[name]
            assignment = self.value(name, line)
            if assignment is None or depth > 8:
                return "${" + name + "}"
            used.add(assignment.line)
            return expand_once(assignment.value, assignment.line, depth + 1)

        def expand_once(value: str, at: int, depth: int) -> str:
            nonlocal line
            saved, line = line, at
            try:
                return re.sub(rf"\$\{{({NAME})\}}|\$({NAME})", lambda m: replace(m, depth), value)
            finally:
                line = saved

        return expand_once(text, line, 0).replace(LITERAL_DOLLAR, "$")

    def loops(self) -> list[Loop]:
        """Every for loop, items from a word list or from "${ARRAY[@]}"."""
        found_loops = []
        for number, line in self.code():
            head = re.match(rf"\s*for ({NAME}) in (.*?)\s*(?:;\s*do)?\s*$", line)
            if head is None:
                continue
            items = [w.text for w in words(head.group(2)) if w.text != ";"]
            lines = {number}
            if len(items) == 1 and (array := re.fullmatch(rf"\$\{{({NAME})\[@\]\}}", items[0])):
                if array.group(1) not in self._arrays:
                    raise self.missing(f"array {array.group(1)}")
                array_line, items = self._arrays[array.group(1)]
                lines.add(array_line)
            found_loops.append(Loop(head.group(1), items, number, self._loop_end(number), lines))
        return found_loops

    def _loop_end(self, start: int) -> int:
        depth = 0
        for number, line in self.code():
            if number < start:
                continue
            if re.match(r"\s*(for|while|until)\b", line):
                depth += 1
            if re.match(r"\s*done\b", line) or re.search(r";\s*done\s*$", line):
                depth -= 1
                if depth == 0:
                    return number
        raise self.missing(f"done of the loop at line {start}")

    def links(self, bios_root: str, fixed: dict[str, str] | None = None) -> list[Link]:
        """ln -s commands with the link or its target under bios_root.

        Links in one loop, or written one by one as P/n linked to Q/n, are
        one Link listing each n.
        """
        loops = self.loops()
        found: list[Link] = []
        for number, line in self.code():
            command = words(line)
            heads = [
                i
                for i, w in enumerate(command)
                if w.raw == "ln"
                and (i == 0 or command[i - 1].raw in {";", "then", "do", "&&", "||"})
            ]
            for head in heads:
                args = []
                for word in command[head + 1 :]:
                    if word.raw in {";", "&&", "||"}:
                        break
                    args.append(word)
                options = [w.text for w in args if w.text.startswith("-")]
                operands = [w.text for w in args if not w.text.startswith("-")]
                if not any("s" in o for o in options) or len(operands) != 2:
                    continue
                enclosing = [lp for lp in loops if lp.start < number <= lp.end]
                env = dict(fixed or {})
                marks = {f"{LOOP_MARK}{lp.var}{LOOP_MARK}": lp for lp in enclosing}
                env.update({lp.var: mark for mark, lp in marks.items()})
                used = {number}
                target, link = (self.expand(op, number, used, env) for op in operands)
                if not (_under(target, bios_root) or _under(link, bios_root)):
                    continue
                bios_is_target = _under(target, bios_root)
                bios_side = (target if bios_is_target else link).rstrip("/")
                folder, _, last = bios_side.rpartition("/")
                present = [m for m in marks if m in target or m in link]
                if any(m in folder for m in present):
                    raise self.missing(
                        f"loop variable only in the last segment of the ln at line {number}"
                    )
                names: list[str] = []
                expands: dict[str, list[str]] = {}
                if present:
                    bios_side = folder
                    if last in marks:
                        names = list(marks[last].items)
                    else:
                        names = [_placeholders(last, marks)]
                        expands = {lp.var: list(lp.items) for m, lp in marks.items() if m in last}
                    if bios_is_target and last not in link:
                        link = f"{link.rstrip('/')}/{last}"
                    for mark in present:
                        used |= marks[mark].lines
                    template = _placeholders(last, marks) if expands else "<name>"
                    target, link = (
                        p.replace(last, template) if last in p else _placeholders(p, marks)
                        for p in (target, link)
                    )
                duplicate = next((f for f in found if (f.target, f.link) == (target, link)), None)
                if duplicate is not None:
                    duplicate.lines |= used
                    continue
                found.append(Link(target, link, bios_side, names, used, bios_is_target, expands))
        return _merge_links(found)


def _under(path: str, root: str) -> bool:
    return path.rstrip("/") == root.rstrip("/") or path.startswith(root.rstrip("/") + "/")


def _merge_links(links: list[Link]) -> list[Link]:
    """Single links P/n -> Q/n sharing P and Q folded into one, names in order."""
    merged: list[Link] = []
    folds: dict[tuple[str, str, bool], tuple[Link, list[Link]]] = {}
    for link in links:
        bios = link.bios_side.rstrip("/")
        bios_is_target = link.bios_is_target
        other = (link.link if bios_is_target else link.target).rstrip("/")
        name = bios.rsplit("/", 1)[-1]
        if link.names or other.rsplit("/", 1)[-1] != name:
            merged.append(link)
            continue
        key = (bios.rsplit("/", 1)[0], other.rsplit("/", 1)[0], bios_is_target)
        if key in folds:
            folds[key][1].append(link)
        else:
            folds[key] = (link, [link])
            merged.append(link)
    folded: set[int] = set()
    for (parent, other_parent, bios_is_target), (first, members) in folds.items():
        if len(members) == 1:
            continue
        first.names = [m.bios_side.rstrip("/").rsplit("/", 1)[-1] for m in members]
        first.bios_side = parent
        bios_end, other_end = f"{parent}/<name>", f"{other_parent}/<name>"
        first.target, first.link = (
            (bios_end, other_end) if bios_is_target else (other_end, bios_end)
        )
        for member in members[1:]:
            first.lines |= member.lines
            folded.add(id(member))
    return [link for link in merged if id(link) not in folded]


_COPY = re.compile(r"(?:^|[\s;&|(])(cp|rsync|install|mv)\s")
_GUARD = re.compile(r"\[\[?\s*!\s+-[fde]\s+(\S+)\s*\]")


@dataclass
class ConfigPlacement:
    """How a start script puts a config where the emulator reads it.

    ``install`` are the lines copying it there, ``kept_if_present`` whether
    every such copy runs only when the file (or its folder) is absent, and
    ``overrides`` the sed lines rewriting one of the record's keys in it.
    """

    script: str
    path: str
    install: set[int]
    kept_if_present: bool
    overrides: set[int]


def _bare_key(key: str) -> str:
    return key.rsplit("] ", 1)[-1].rsplit("/", 1)[-1].strip()


def _guarded(script: Script, number: int, target: str) -> bool:
    """Whether a line runs only when target, or a folder above it, is absent."""

    def covers(found: re.Match[str], at: int) -> bool:
        guarded = script.expand(words(found.group(1))[0].text, at, set()).rstrip("/")
        return target == guarded or target.startswith(guarded + "/")

    line = script.lines[number - 1]
    if any(covers(m, number) for m in _GUARD.finditer(line)):
        return True
    depth = 0
    for at in range(number - 1, 0, -1):
        text = script.lines[at - 1].strip()
        if re.match(r"fi\b", text):
            depth += 1
        elif re.match(r"if\b", text):
            if depth:
                depth -= 1
                continue
            return any(covers(m, at) for m in _GUARD.finditer(text))
    return False


def config_placement(
    script: Script,
    target: str,
    keys: Iterable[str] = (),
    writers: Iterable[str] = (),
    source_name: str = "",
    required: bool = True,
    sources: tuple[str, ...] = (),
) -> ConfigPlacement:
    """The lines of a start script that install ``target`` and rewrite its keys.

    A copy installs the target when its destination is the file or a folder
    above it. ``writers`` are other commands that write the file (ROCKNIX
    generates mednafen.cfg with mednafen_gen_config.sh). A copy guarded by
    `[ ! -f X ]` or `[ ! -d X ]` on the target or a folder above it, or made
    with cp -n or rsync --ignore-existing, leaves a file already there.
    """
    install: set[int] = set()
    kept = True
    overrides: set[int] = set()
    bare = {_bare_key(k) for k in keys} - {""}
    writer = re.compile("|".join(re.escape(w) for w in writers)) if writers else None
    for number, line in script.code():
        if (copy := _COPY.search(line)) or (writer and writer.search(line)):
            if copy:
                args = []
                for word in words(line[copy.start(1):])[1:]:
                    # The command ends at a separator or a redirection.
                    if word.raw in {";", "&&", "||", "|"} or re.match(r"\d*>", word.raw):
                        break
                    args.append(word.text)
                operands = [a for a in args if not a.startswith("-")]
                if not operands:
                    continue
                destination = script.expand(operands[-1], number, set()).rstrip("/")
                source = script.expand(operands[0], number, set()).rstrip("/")
                hits = target == destination or target.startswith(destination + "/") or (
                    target.startswith(f"{destination}/{source.rsplit('/', 1)[-1]}")
                )
                # A copy of another file into the same place is another
                # record's: amiberry copies the A500 or the A1200 setup.
                named = source.rsplit("/", 1)[-1]
                if not hits or (source_name and "." in named and named != source_name):
                    continue
                # A named file copied into a folder above the target is
                # another file of that folder (ARMSX2's secrets.ini).
                if (
                    not source_name and "." in named and "*" not in named
                    and destination != target and named != target.rsplit("/", 1)[-1]
                ):
                    continue
                if sources and not source.startswith(sources):
                    continue
                skip = "-n" in args or "--ignore-existing" in args
            else:
                skip = False
            install.add(number)
            if not (skip or _guarded(script, number, target)):
                kept = False
        elif re.search(r"\bsed\b.*\s-i\b|\bsed -i", line) and bare:
            expanded = script.expand(line, number, set())
            if target in expanded or target.rsplit("/", 1)[-1] in expanded:
                if any(re.search(rf"\b{re.escape(k)}\b", expanded) for k in bare):
                    overrides.add(number)
    if not install and required:
        raise script.missing(f"install of {target}")
    return ConfigPlacement(script.path, target, install, kept, overrides)


def evidence_fields(
    placements: Iterable[ConfigPlacement],
    installed: Iterable[tuple[str, Iterable[int]]] = (),
) -> dict:
    """The installs, kept_if_present and overrides fields of a config record.

    ``placements`` are the steps that put the file in place, in the order
    they run (a first-boot copy, then the start script). ``installed`` are
    the build steps that put it where they copy it from (a package.mk copy
    into /usr/config).
    """
    placements = list(placements)
    steps = [p for p in placements if p.install]
    if not steps:
        raise LauncherPatternMissing(placements[0].path if placements else "", "install")
    return {
        "installs": {
            "path": steps[-1].path,
            "source_ref": source_ref([*installed, *((p.script, p.install) for p in steps)]),
        },
        "kept_if_present": all(p.kept_if_present for p in steps),
        "overrides": [
            source_ref([(p.script, {line})]) for p in placements for line in sorted(p.overrides)
        ],
    }


@dataclass
class Setting:
    section: str
    key: str
    value: str
    line: int


def settings(text: str, separator: str = "=") -> list[Setting]:
    """key = value lines under their [section], quotes around the value removed.

    separator " " reads mednafen's "key value" form.
    """
    found, section = [], ""
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped[0] in "#;":
            continue
        header = re.fullmatch(r"\[([^\]]+)\]", stripped)
        if header:
            section = header.group(1)
            continue
        if separator == " ":
            pair = re.fullmatch(r"(\S+)(?:\s+(.*))?", stripped)
        else:
            pair = re.fullmatch(r"([^=\s]+)\s*=\s*(.*)", stripped)
        if pair is None:
            continue
        value = (pair.group(2) or "").strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        found.append(Setting(section, pair.group(1), value, number))
    return found


def describe_keys(file: str, keys: tuple[tuple[str, str], ...]) -> str:
    """file [section] key, key [other] key, sections named where they change."""
    described, section = file, None
    for index, (key_section, key) in enumerate(keys):
        if key_section and key_section != section:
            described += f" [{key_section}] {key}"
            section = key_section
        else:
            described += (" " if index == 0 else ", ") + key
    return described


@dataclass
class Entry:
    """A directory entry: kind is "dir", "file" or "link"."""

    kind: str
    target: str = ""


class RepoTree:
    """Files of one repository revision, read on demand and kept."""

    def __init__(
        self,
        read: Callable[[str], str],
        listdir: Callable[[str], dict[str, Entry]],
    ) -> None:
        self._read = read
        self._listdir = listdir
        self._texts: dict[str, str] = {}
        self._dirs: dict[str, dict[str, Entry]] = {}

    def read(self, path: str) -> str:
        if path not in self._texts:
            self._texts[path] = self._read(path)
        return self._texts[path]

    def listdir(self, path: str) -> dict[str, Entry]:
        if path not in self._dirs:
            self._dirs[path] = self._listdir(path)
        return self._dirs[path]

    def has(self, path: str) -> bool:
        parent, _, name = path.rpartition("/")
        try:
            return name in self.listdir(parent)
        except LauncherPatternMissing:
            return False

    @classmethod
    def from_files(cls, files: dict[str, str], links: dict[str, str] | None = None) -> RepoTree:
        """A tree held in memory: file texts by path, symlink targets by path."""
        links = links or {}

        def read(path: str) -> str:
            if path not in files:
                raise LauncherPatternMissing(path, "file")
            return files[path]

        def listdir(path: str) -> dict[str, Entry]:
            prefix = path.rstrip("/") + "/"
            entries: dict[str, Entry] = {}
            for name, target in links.items():
                if name.startswith(prefix) and "/" not in name[len(prefix) :]:
                    entries[name[len(prefix) :]] = Entry("link", target)
            for name in files:
                if name.startswith(prefix):
                    rest = name[len(prefix) :]
                    head, _, tail = rest.partition("/")
                    entries.setdefault(head, Entry("dir" if tail else "file"))
            if not entries:
                raise LauncherPatternMissing(path, "directory")
            return entries

        return cls(read, listdir)

    @classmethod
    def github(cls, repo: str, rev: str) -> RepoTree:
        """A GitHub repository at one revision: raw files and the trees API."""

        def read(path: str) -> str:
            url = f"https://raw.githubusercontent.com/{repo}/{rev}/{path}"
            return fetch_bytes(url).decode("utf-8-sig")

        def listdir(path: str) -> dict[str, Entry]:
            url = f"https://api.github.com/repos/{repo}/git/trees/{rev}:{path}"
            try:
                listing = json.loads(fetch_bytes(url, headers=github_headers()))
            except ConnectionError as e:
                raise LauncherPatternMissing(path, f"directory ({e})") from e
            entries = {}
            for item in listing.get("tree", []):
                if item["mode"] == "120000":
                    entries[item["path"]] = Entry("link", read(f"{path}/{item['path']}").strip())
                else:
                    entries[item["path"]] = Entry("dir" if item["type"] == "tree" else "file")
            return entries

        return cls(read, listdir)
