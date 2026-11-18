"""C# source read as text, never compiled: comments and strings told apart from
code, string literals, call arguments, statements, and the lines a construct
spans. A construct that is gone raises LauncherPatternMissing."""

from __future__ import annotations

import bisect
import re
from collections.abc import Iterator

from model.sourceref import span

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
        ranges = [span(*s) for s in _merge(spans)]
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


_METHOD = re.compile(
    r"(?:(?:public|private|protected|internal|static|override|virtual)\s+)+[\w<>\[\],. ]+\s\w+\s*\("
)


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
    for _offset, char in _code_chars(inner):
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
