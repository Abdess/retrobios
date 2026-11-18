"""Counts, sizes and words wrapped to the width of a line or a cell."""
from __future__ import annotations

import re
import unicodedata

from installer.invocation import _INVOCATION


def _plural(count: int, word: str) -> str:
    """Count and noun, so a run of one file does not read as machine output:
    1 file, 2 files, 1 wrong copy, 2 wrong copies."""
    if count == 1:
        return f"{count} {word}"
    if word.endswith("y") and word[-2:-1] not in tuple("aeiou"):
        return f"{count} {word[:-1]}ies"
    return f"{count} {word}s"


def agree(count: int, one: str, many: str) -> str:
    """The verb a count takes: "1 needs", "2 need". Each count said with a
    verb reads it here: "1 need the internet" stood on the plan."""
    return f"{count} {one if count == 1 else many}"


def format_size(n: int) -> str:
    """Human-readable file size."""
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    if n < 1024 * 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB"
    return f"{n / (1024 * 1024 * 1024):.1f} GB"


# C0 and C1 controls, DEL and lone surrogates: a file, folder or core name
# holding ESC would drive the terminal (clear it, or set the clipboard with
# OSC 52) instead of being shown.
_CONTROLS = re.compile("[\x00-\x1f\x7f-\x9f\ud800-\udfff]")


def screen_text(text: str) -> str:
    """Text as a terminal shows it, every control character a "?"."""
    return _CONTROLS.sub("?", text)


def _char_width(char: str) -> int:
    if unicodedata.combining(char) or unicodedata.category(char) in ("Mn", "Me", "Cf"):
        return 0
    return 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1


def cell_width(text: str) -> int:
    """Terminal cells the text takes: a CJK character two, an accent none."""
    return sum(_char_width(char) for char in text)


def fit(text: str, width: int) -> str:
    """The text cut to width cells, never through a character."""
    text = screen_text(text)
    kept: list[str] = []
    used = 0
    for char in text:
        size = _char_width(char)
        if used + size > width:
            break
        kept.append(char)
        used += size
    return "".join(kept)


def _split_word(word: str, room: int) -> list[str]:
    """A word longer than room, cut after a slash where it can be: a path
    read /home/us and er/bios when cut anywhere."""
    pieces = []
    while cell_width(word) > room:
        head = fit(word, max(room, 1))
        # After the last separator that fits, a Windows one too: cut where
        # a third of the room was left, a folder broke inside its name
        # ("Game Bo" / "y Advance").
        cut = max(head.rfind("/"), head.rfind("\\")) + 1
        if cut <= 1:
            cut = len(head)
        pieces.append(word[:cut])
        word = word[cut:]
    return pieces + [word] if word else pieces


def _is_path_word(word: str) -> bool:
    """A word that is a path: it breaks after a separator, never inside a name."""
    return ("/" in word or "\\" in word) and not word.startswith(("http:", "https:"))


_UNIT = re.compile(r"(B|KB|MB|GB)\b")


def _glued_words(text: str) -> list[str]:
    """The words of text, a size kept with its unit: "5.1" / "KB" was
    broken across two lines of a 40-column headline."""
    words: list[str] = []
    for word in text.split():
        if words and _UNIT.match(word) and re.fullmatch(r"\(?\d+(\.\d+)?", words[-1]):
            words[-1] += f" {word}"
        else:
            words.append(word)
    return words


# A shell word: quoted parts kept with what they quote.
_SHELL_WORD = re.compile(r"""(?:'[^']*'|"[^"]*"|[^\s'"]+|['"])+""")


def _path_tail(text: str, width: int) -> str:
    """A path cut to its last folders that fit after ".../", as a person
    reads it on a narrow screen (".../retroarch/system"). Its last name is
    kept whole however long: cut in its middle, RetroArch_BIOS_Pack.zip
    read "Pack.zip"."""
    if cell_width(text) <= width:
        return text
    separator = "\\" if "\\" in text and "/" not in text else "/"
    parts = text.rstrip(separator).split(separator)
    tail = parts[-1]
    for part in reversed(parts[:-1]):
        longer = f"{part}{separator}{tail}"
        if cell_width(f"...{separator}{longer}") > width:
            break
        tail = longer
    return f"...{separator}{tail}"


def _command_groups(text: str) -> list[str]:
    """A command's shell words as they stay together on a line: a long
    option with its value. "--platform" ended a line, its value on the next."""
    groups: list[str] = []
    for word in _SHELL_WORD.findall(text):
        last = groups[-1] if groups else ""
        if (last.startswith("--") and len(last) > 2 and " " not in last and "=" not in last
                and not word.startswith("-") and word != "|"):
            groups[-1] = f"{last} {word}"
        else:
            groups.append(word)
    return groups


def _continuation(powershell: bool | None = None) -> str:
    """The character that ends a line of a command the shell reads on: a
    backtick in PowerShell, a backslash in sh. Asked as the command's words
    ask it: with RETROBIOS_OS=windows elsewhere one command had
    PowerShell's quotes and sh's line ends."""
    return "`" if (_INVOCATION.powershell() if powershell is None else powershell) else "\\"


def _command_wrap(text: str, width: int, indent: str = "  ",
                  powershell: bool | None = None) -> list[str]:
    """A command too wide for width, broken between its shell words, each
    line but the last ending with the continuation the shell accepts, so a
    copy of the lines runs as the command does. A line one group wide that
    fits only without the indent loses it. A path still wider keeps its
    last folders (_path_tail), said by TUI_SHORTENED: folded by the
    terminal, it read as broken inside a word. A web
    address is never cut."""
    lead = text[:len(text) - len(text.lstrip(" "))]
    tail = " " + _continuation(powershell)
    groups = _command_groups(text)
    lines: list[str] = []
    line = ""

    def close(done: str, last: bool) -> str:
        end = "" if last else tail
        prefix = lead + indent if lines else lead
        for fewer in (lead, ""):
            if cell_width(prefix + done + end) > width >= cell_width(fewer + done + end):
                prefix = fewer
        return prefix + done + end

    fitted: list[str] = []
    for number, group in enumerate(groups):
        end = 0 if number == len(groups) - 1 else len(tail)
        room = width - cell_width(lead + indent) - end
        # A group is an option and its value: split at the first space, a
        # quoted value keeping its own.
        option, _space, value = (group.partition(" ") if group.startswith("--") and " " in group
                                 else ("", "", group))
        if cell_width(group) > room and "://" not in value and _is_path_word(value.strip("'\"")):
            keep = cell_width(option) + 1 if option else 0
            quote = value[0] if value[:1] in "'\"" and value[-1:] == value[:1] else ""
            bare = value[1:-1] if quote else value
            short = quote + _path_tail(bare, max(8, room - keep - 2 * len(quote))) + quote
            if option and cell_width(short) > room - keep:
                # The option and the name do not fit together: the value
                # on a line of its own, its name whole.
                fitted += [option, quote + _path_tail(bare, max(8, room - 2 * len(quote)))
                           + quote]
                continue
            group = (f"{option} " if option else "") + short
        fitted.append(group)
    for number, group in enumerate(fitted):
        end = 0 if number == len(fitted) - 1 else len(tail)
        prefix = lead + indent if lines else lead
        longer = f"{line} {group}" if line else group
        if not line or cell_width(prefix + longer + (tail if end else "")) <= width:
            line = longer
            continue
        lines.append(close(line, False))
        line = group
    lines.append(close(line, True))
    return lines


def _wrap(text: str, width: int, indent: str = "  ", whole: str = "",
          powershell: bool | None = None) -> list[str]:
    """Lines of at most width cells, the ones after the first indented.

    whole keeps every word whole, a longer one alone on a line wider than
    width, which the terminal folds and a copy keeps in one piece: "text"
    for prose and paths, "command" for a command, whose words are shell
    words. A restore command was drawn split inside its URL and its folder,
    and a backup folder's dated name fell on a line of its own."""
    if cell_width(text) <= width:
        return [text]
    if whole == "command":
        return _command_wrap(text, width, indent, powershell)
    lead = text[:len(text) - len(text.lstrip(" "))]
    lines: list[str] = []
    line = ""
    words = _glued_words(text)
    if len(words) == 1 and _is_path_word(text.strip()):
        # A folder on a line of its own goes on at its own indent: the
        # rest of a save folder sat two cells under its start, the BIOS
        # folder's at its label's.
        indent = ""

    def close(done: str) -> str:
        # A line one word wide that fits without the indent loses it: one
        # cell too wide, a folder was folded by the terminal inside a word
        # ("syste" / "m"). The line's own lead too: a
        # pack path of 75 cells was folded at 80 columns under an indent
        # of 6.
        prefix = lead + indent if lines else lead
        if cell_width(prefix + done) > width >= cell_width(lead + done):
            prefix = lead
        elif cell_width(prefix + done) > width >= cell_width(done) and " " not in done:
            prefix = ""
        return prefix + done

    for word in words:
        # Kept whole, a path is still broken after a separator where it is
        # wider than the screen: the terminal folded it inside a name. A
        # command's words stay whole, copied as one.
        room = width - len(lead + indent)
        # A word that fits on a line of its own stays whole there (close).
        # A path only where it fits at the indent its line has: dropped to
        # fit, a folder stood at one indent and its neighbour at another.
        alone = lead + indent if (lines or line) and _is_path_word(word) else lead
        pieces = ([word] if whole == "command" or (whole and not _is_path_word(word))
                  or cell_width(alone + word) <= width else _split_word(word, room))
        if len(pieces) > 1 and _is_path_word(word):
            # The path starts on the line it follows, broken at a separator
            # that fits there: "BIOS folder:" stood alone above its folder.
            prefix = lead + indent if lines else lead
            left = width - cell_width(prefix + line) - (1 if line else 0)
            head = _split_word(word, left)[0] if left >= 8 else ""
            if head.endswith(("/", "\\")) and head != word:
                pieces = [head, *_split_word(word[len(head):], room)]
        for index, piece in enumerate(pieces):
            prefix = lead + indent if lines else lead
            # The rest of a word broken at a slash joins it without a space:
            # a path was drawn "retroarch/ system", and copied wrong.
            longer = f"{line}{'' if index else ' '}{piece}" if line else piece
            # A path's pieces keep the indent, which they are cut to fit:
            # joined past it, the last piece of a folder lost its indent.
            if not line or cell_width(prefix + longer) <= width or (
                    lines and " " not in longer and cell_width(lead + longer) <= width
                    and not _is_path_word(word)):
                line = longer
            else:
                lines.append(close(line))
                line = piece
    lines.append(close(line))
    return lines
