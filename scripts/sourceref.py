"""The grammar of a profile's source_ref: where a reference points.

Read by the site to link citations and by profile_sync to check them. Kept
apart so that building the site does not depend on the comparison tool.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Iterator

_REF_RE = re.compile(r"^(?P<path>[^:]+?)(?::(?P<start>\d+)(?:-(?P<end>\d+))?)?$")
_BARE_RANGE_RE = re.compile(r"^:?(\d+(?:-\d+)?)$")
_SPLIT_RE = re.compile(r"[,;]")
_ANNOTATION_RE = re.compile(r"\s*\([^)]*\)?")
_LOCATED_RE = re.compile(r"^[^\s:]+:\d+(?:-\d+)?$")


# A part opening with one of these words says which declared repository its
# lines are in: `upstream src/bios.c:40` is the original emulator,
# `source libretro.c:120` the repository the profile names as its source,
# usually the libretro port. A reader could not tell which code asked for
# the file when a profile declares both.
REPO_ROLES = ("source", "upstream")


_BINARY_SUFFIXES = (
    ".dll", ".exe", ".so", ".dylib", ".apk", ".elf", ".o", ".a", ".jar", ".dex",
)
_HEX_ADDRESS_RE = re.compile(r"\b0x[0-9a-fA-F]{2,}")


def is_binary_citation(path: str) -> bool:
    """True when a ref locates code inside a shipped binary, not a source file.

    `BAM.dll 1.5-408 .text:0x100c3960-0x100c3a97`, `libmain.so LoadNES
    0x3bb49` and `.rdata dialog filter` were read by disassembly. No revision
    of any repository holds those bytes, so the ref can neither anchor nor
    break: 77 parts of `future-pinball-fploader` alone were reported GONE.
    """
    if _HEX_ADDRESS_RE.search(path):
        return True
    if " " not in path:
        # A bare `DesktopKinect.dll` names a shipped library, never a source
        # file: no directory, no line, only its import table to read.
        return "/" not in path and path.lower().endswith(_BINARY_SUFFIXES)
    head = path.split(" ", 1)[0]
    if head.lower().endswith(_BINARY_SUFFIXES):
        return True
    return head.startswith(".") and "/" not in head


def ref_role(path: str) -> tuple[str, str]:
    """The role word a cited path opens with, and the path without it."""
    word, _, rest = path.partition(" ")
    if word in REPO_ROLES and rest.strip():
        return word, rest.strip()
    return "", path


@dataclass(frozen=True)
class RefPart:
    path: str
    start: int | None
    end: int | None
    raw: str = ""
    # The repository the part names (`upstream src/a.c:5`), empty when it
    # names none. Carried per part: one profile cites the same path in both
    # repositories, hypseus-singe's lair.cpp under `source` and `upstream`.
    role: str = ""

    @property
    def last(self) -> int | None:
        """Last cited line: the end of a range, or the single line."""
        return self.end or self.start


def parse_source_ref(ref: str) -> tuple[str, int | None, int | None]:
    """Split 'path/file.cpp:123-129' into (path, start, end)."""
    m = _REF_RE.match(ref.strip())
    if not m:
        return ref.strip(), None, None
    start = int(m.group("start")) if m.group("start") else None
    end = int(m.group("end")) if m.group("end") else start
    return m.group("path"), start, end


def source_ref_values(value: str | dict | None) -> list[tuple[str, str]]:
    """Flatten a source_ref into (label, refs) pairs.

    Most entries hold a plain string. `ymir` keys its refs by mode instead,
    since its standalone and libretro builds read different files.
    """
    if isinstance(value, dict):
        return [(str(k), str(v)) for k, v in value.items() if v]
    return [("", str(value))] if value else []


def split_source_ref(ref: str) -> list[RefPart]:
    """A source_ref may carry several references.

    Separators are the comma and the semicolon. A part reduced to a line or a
    line range continues the previous part's file: `geo.c:234-243, 273-285`
    cites two ranges of the same file, a form used by 430 parts across 69
    profiles. Parenthetical annotations are prose and are dropped: 285 entries
    across 50 profiles carry them.
    """
    parts: list[RefPart] = []
    for raw in split_outside_parentheses(str(ref or "")):
        chunk = _trim_prose(_ANNOTATION_RE.sub("", raw).strip())
        if not chunk:
            continue
        bare = _BARE_RANGE_RE.match(chunk)
        if bare and parts:
            start, _, end = bare.group(1).partition("-")
            parts.append(
                RefPart(parts[-1].path, int(start), int(end or start), raw)
            )
            continue
        path, start_line, end_line = parse_source_ref(chunk)
        parts.append(RefPart(path, start_line, end_line, raw))
    return parts


def ref_prose_text(ref: str) -> str:
    """The text of a source_ref its parts do not read, positions kept.

    split_source_ref keeps the located head of each chunk and drops the
    rest: annotations, and prose after the head. A citation written there
    (`(MACHINE_IS_SPECTRUM_128_P2 covers Pentagon, src/cpu.h:545)`, or the
    second half of `pce.cpp:477-483 + huc.cpp:284-304`) was never anchored.
    Every character a part reads is blanked, so the prose scanner finds
    the rest at the offsets it has in the scalar.
    """
    masked = list(ref)
    depth = 0
    outside: list[int] = []

    def settle() -> None:
        text = "".join(ref[i] for i in outside)
        head = text.strip().split(" ", 1)[0] if text.strip() else ""
        located = bool(head) and bool(
            _LOCATED_RE.match(head) or _BARE_RANGE_RE.match(head)
        )
        blank = outside
        if located:
            first = next(k for k, i in enumerate(outside) if not ref[i].isspace())
            blank = outside[first:first + len(head)]
        for i in blank:
            masked[i] = " "
        outside.clear()

    for index, char in enumerate(ref):
        if char == "(":
            depth += 1
        if depth == 0:
            if char in ",;":
                settle()
            else:
                outside.append(index)
        if char == ")":
            depth = max(0, depth - 1)
    settle()
    return "".join(masked)


def split_outside_parentheses(text: str) -> list[str]:
    """Split on commas and semicolons, ignoring those inside an annotation.

    Each chunk keeps its annotation, so a rewrite can put the prose back.
    """
    chunks: list[str] = []
    current: list[str] = []
    depth = 0
    for char in text:
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        if char in ",;" and depth == 0:
            chunks.append("".join(current))
            current = []
        else:
            current.append(char)
    chunks.append("".join(current))
    return [c for c in (chunk.strip() for chunk in chunks) if c]


def _trim_prose(chunk: str) -> str:
    """Drop a trailing comment written without parentheses.

    `libretro.cpp:1520-1521 candidates_a1200` cites a location followed by a
    note. The leading token is kept only when it already reads as a reference,
    so `munt ROMInfo.cpp`, which names an external project, stays intact and
    is reported rather than silently truncated to `munt`.
    """
    if " " not in chunk:
        return chunk
    head = chunk.split(" ", 1)[0]
    if _LOCATED_RE.match(head) or _BARE_RANGE_RE.match(head):
        return head
    return chunk


# Files a repository carries without an extension and that prose cites by
# name. Widening the pattern to any dotless word instead would swallow the
# hex addresses and the constants profiles write the same way: ALTERNATEROMS,
# F000, C000 all read as `name:number`.
PROSE_EXTENSIONLESS = (
    "Makefile",
    "makefile",
    "GNUmakefile",
    "CMakeLists",
    "Kconfig",
    "Dockerfile",
    "configure",
    "README",
    "LICENSE",
    "COPYING",
    "CHANGELOG",
)
# Any other dotless file is cited with its directory, which a constant or a
# hex address never carries: lightspark's tools/errorgen:20.
_PROSE_PATH = (
    r"(?P<path>[A-Za-z0-9_][\w./+-]*\.[A-Za-z]\w*"
    r"|(?:[\w./+-]*/)?(?:" + "|".join(PROSE_EXTENSIONLESS) + r")"
    r"|(?:[\w.+-]+/)+[A-Za-z_][\w+-]*)"
)
PROSE_CITE_RE = re.compile(_PROSE_PATH + r":(?P<range>\d+(?:-\d+)?)")
# A file named before its locations, `Source/engine/assets.cpp:` then a
# list, and a location that leaves the file out, `(:507)`, which reads in
# the file named last: devilutionx, corsixth and starship cite their load
# order this way. Neither was collected, so no bump or guard followed them.
_PROSE_FILE_NAMED_RE = re.compile(_PROSE_PATH + r":(?=\s|$)")
_PROSE_ABBREVIATED_RE = re.compile(
    r"(?:(?<=[(\s])|^):(?P<range>\d+(?:-\d+)?)(?![\w:-])(?!\.\d)"
)
PROSE_LIST_ITEM_RE = re.compile(r"\d+[.)](?:\s|$)")
PROSE_WRAPPED_RANGE_RE = re.compile(r":\d+(?:-\d+)?(?:[,)\s]|$)")
PROSE_CONT_RE = re.compile(r",(?P<range>\d+(?:-\d+)?)(?![\w-])(?!\.\d)")
# A spaced continuation is accepted only for a range: `x.c:55-71, 80-147`
# follows the source_ref convention, while `x.c:100, 200 files` is prose.
PROSE_CONT_SPACED_RE = re.compile(r", +(?P<range>\d+-\d+)(?![\w-])(?!\.\d)")
# A spaced single line joins the run only inside a list that closes the
# citation: `bgmusic.c:29, 321)` and `.gitlab-ci.yml:110, 116, 139, 400`
# end on a bracket, a semicolon, a sentence end or the line end, while in
# `x.c:100, 200 files` a word follows and the number is prose.
PROSE_CONT_LIST_RE = re.compile(
    r"(?:, +\d+(?:-\d+)?(?![\w-])(?!\.\d))+(?=[)\];]|\.(?!\w)|\s*$)"
)
_PROSE_LIST_RANGE_RE = re.compile(r"\d+(?:-\d+)?")
# Words that read as prose before a filename. Anything else in project
# position marks the citation external, the way `munt ROMInfo.cpp` does in
# a source_ref: the profile does not declare that repository.
PROSE_LINKING_WORDS = frozenset((
    "a", "an", "and", "are", "as", "at", "before", "both", "but", "by",
    "each", "for", "from", "in", "into", "is", "it", "its", "no", "not",
    "of", "on", "only", "or", "over", "per", "see", "so", "than", "that",
    "the", "their", "then", "these", "this", "those", "to", "under",
    "upstream", "uses", "via", "was", "when", "where", "while", "with",
))
_PROJECT_WORD_RE = re.compile(r"[A-Za-z0-9][\w-]*")


# What separates one citation from the next in prose. lynx-emu writes
# `...:112; mednafen src/lynx/system.cpp:86-93`: without the semicolon the
# project word read as prose and the citation was charged to the fork. A
# sentence end separates them the same way.
_PROSE_LIST_DELIMITERS = ",;:(."


def _prose_external(
    line: str, path_start: int, known: frozenset[str] | set[str] = frozenset()
) -> bool:
    """True when the word before the path names an undeclared project.

    `munt ROMInfo.cpp:206-213` in prose follows the source_ref convention:
    the leading word is the project, and no declared repository can confirm
    the reference. The word counts as a project only when a list delimiter
    or the line start precedes it, it reads as an identifier, it is not a
    linking word, and it does not name a declared repository: in
    `boot, in libretro.cpp:12` the candidate is prose, and in
    `mednafen src/lynx/rom.cpp:55` it is the declared upstream itself.
    """
    before = line[:path_start].rstrip()
    if not before or before[-1] in _PROSE_LIST_DELIMITERS:
        return False
    word_start = max(before.rfind(" "), before.rfind("\t"), before.rfind("(")) + 1
    word = before[word_start:]
    if not _PROJECT_WORD_RE.fullmatch(word):
        return False
    if word.lower() in PROSE_LINKING_WORDS or word.lower() in known:
        return False
    lead = before[:word_start].rstrip()
    return not lead or lead[-1] in _PROSE_LIST_DELIMITERS


def _prose_role(line: str, path_start: int) -> str:
    """The role word written right before a prose path, empty when none.

    Prose follows the source_ref convention: `(upstream retro_host.c:196)`
    names the original emulator, `ref: source src/devices/floppy.cpp:1656`
    the repository declared as source. Read as a linking word or a project
    name, the word was dropped or made the citation external.
    """
    before = line[:path_start].rstrip()
    word = before[max(before.rfind(" "), before.rfind("\t"), before.rfind("(")) + 1:]
    return word if word in REPO_ROLES else ""


def resolve_project_word(path: str, trees: Iterable[list[str] | None]) -> str | None:
    """Path of `project file` inside a declared tree, None when out of reach.

    m64plus-fz cites `rice Config.cpp` and `mupen64plus-core
    device/pif/bootrom_hle.c`: plugins vendored in the declared repository
    under mupen64plus-video-rice/ and mupen64plus-core/. A citation is in
    reach when exactly one file ends with the path below a directory naming
    the project. The first tree that answers decides.
    """
    word, _, rest = path.partition(" ")
    rest = rest.strip().lstrip("/")
    if not rest:
        return None
    word = word.lower()
    suffix = "/" + rest
    for tree in trees:
        matches = [
            p for p in tree or []
            if p.endswith(suffix)
            and any(word in seg.lower() for seg in p[: -len(suffix)].split("/"))
        ]
        if len(matches) == 1:
            return matches[0]
        if matches:
            return None
    return None


def _prose_runs(
    text: str, known: frozenset[str] | set[str] = frozenset()
) -> Iterator[tuple[
    int, tuple[int, int], tuple[tuple[int, int], ...], tuple[RefPart, ...], str, int
]]:
    """Citation runs inside one prose scalar.

    A run is a path:range with its attached continuation ranges, written
    without a space after the comma the way the corpus writes them:
    `main.c:112,1624-1633` cites two ranges of one file, while `x.c:100, 200`
    is a citation followed by prose. A token carrying :// is a URL, whose
    host:port shape would otherwise pass for a citation.

    The last item is 0 for a run held by one line. A run wrapped onto the
    next line gives the offset where that line's text starts in the
    joined line, so a writer can put each span back on its own line.
    """
    lines = text.splitlines()
    # The file an abbreviated location reads in, and the role it was named
    # under, carried from line to line within the scalar.
    named: tuple[str, str] | None = None
    # Where the run wrapped from the line before ends in this one: its
    # ranges are that run's, not abbreviated locations of their own.
    carried = 0
    for number, own in enumerate(lines):
        # A literal block keeps its line breaks, so a citation wrapped after
        # `file:` or after a range's comma lost the ranges on the next line
        # (gearcoleco `libretro.cpp:` then four ranges). The next line is
        # read as the run's continuation, and a run reaching into it is wrapped.
        line = own.rstrip()
        boundary = len(line)
        joined_at = 0
        following = lines[number + 1].lstrip() if number + 1 < len(lines) else ""
        if PROSE_WRAPPED_RANGE_RE.match(following) and line[-1:].isalnum():
            # The break can fall before the colon too: jgenesis wraps
            # `.../src/config.rs` then `:76-78,95-99` on the next line.
            joined_at = len(line)
            line += following
            following = ""
        # A numbered list after a colon (abuse: `setup.cpp:` then `1. -datadir`)
        # is not a range.
        if not following[:1].isdigit() or PROSE_LIST_ITEM_RE.match(following):
            following = ""
        if following and line.endswith(":"):
            joined_at = len(line)
            line += following
        elif following and line.endswith(","):
            joined_at = len(line) + 1
            line += " " + following
        consumed, carried = carried, 0
        events = sorted(
            [(m.start(), 0, m) for m in PROSE_CITE_RE.finditer(line)]
            + [(m.start(), 1, m) for m in _PROSE_FILE_NAMED_RE.finditer(line)]
            + [(m.start(), 2, m) for m in _PROSE_ABBREVIATED_RE.finditer(line)],
            key=lambda event: (event[0], event[1]),
        )
        for _start, kind, match in events:
            if match.start() >= boundary:
                break
            if match.start() < consumed:
                continue
            if kind == 1:
                if "://" not in line[max(0, match.start() - 3):match.end()]:
                    named = (match.group("path"), "")
                continue
            if kind == 2:
                if named is None:
                    continue
                path, role = named
                path_start = match.start()
                path_span = (path_start, path_start)
            else:
                path, role, path_start, path_span = _prose_path(
                    line, lines, number, match, known
                )
                if path is None:
                    continue
                named = (path, role)
            spans = [(match.start("range"), match.end("range"))]
            end = match.end()
            while True:
                cont = PROSE_CONT_RE.match(line, end)
                if cont is None and (listed := PROSE_CONT_LIST_RE.match(line, end)):
                    spans.extend(
                        (item.start(), item.end())
                        for item in _PROSE_LIST_RANGE_RE.finditer(
                            line, end, listed.end()
                        )
                    )
                    end = listed.end()
                    break
                if cont is None:
                    cont = PROSE_CONT_SPACED_RE.match(line, end)
                if cont is None:
                    break
                spans.append((cont.start("range"), cont.end("range")))
                end = cont.end()
            consumed = end
            if end > boundary:
                indent = len(lines[number + 1]) - len(lines[number + 1].lstrip())
                carried = indent + end - joined_at
            parts = []
            for lo, hi in spans:
                rng = line[lo:hi]
                a, _, b = rng.partition("-")
                parts.append(RefPart(path, int(a), int(b or a), rng, role))
            yield (
                number, path_span, tuple(spans), tuple(parts),
                line[path_start:end], joined_at if end > boundary else 0,
            )


def _prose_path(
    line: str, lines: list[str], number: int, match: re.Match,
    known: frozenset[str] | set[str],
) -> tuple[str | None, str, int, tuple[int, int]]:
    """(path, role, start, span) of one written citation, None for a URL."""
    token_start = max(line.rfind(" ", 0, match.start()),
                      line.rfind("\t", 0, match.start())) + 1
    token = line[token_start:].split()[0] if line[token_start:] else ""
    if "://" in token:
        return None, "", 0, (0, 0)
    path = match.group("path")
    path_start = match.start("path")
    # A dotfile citation opens its token with the dot: `.gitlab-ci.yml`
    # after a delimiter is the filename, while the dot of `boot.cfg`
    # inside a word belongs to the word before it.
    if (
        path_start > 0
        and line[path_start - 1] == "."
        and (path_start == 1 or line[path_start - 2] in " \t(")
    ):
        path_start -= 1
        path = "." + path
    # A path opening its line reads its role or project word at the
    # end of the line before: genesis_plus_gx_expanded wrapped
    # `(Batocera` and `package/batocera/...mk:7` one line apart.
    lead = line[:path_start]
    if number and not lead.strip():
        lead = lines[number - 1].rstrip() + " "
    role = _prose_role(lead, len(lead))
    if not role and _prose_external(lead, len(lead), known):
        # Kept with its project word, the source_ref convention: the
        # report looks for the project inside the declared trees
        # (mupen64plus-ae vendors `rice Config.cpp`) and calls the
        # citation EXTERNAL only when none carries it.
        before = lead.rstrip()
        word = before[max(before.rfind(" "), before.rfind("\t"),
                          before.rfind("(")) + 1:]
        path = f"{word} {path}"
    return path, role, path_start, (path_start, match.end("path"))
