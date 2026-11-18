"""Keys read from the terminal and the lines painted back."""
from __future__ import annotations

import codecs
import os
import re
import unicodedata
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import NamedTuple

from installer.embedded import shown_path
from installer.invocation import Invocation
from installer.line_ui import _pad
from installer.run import _COLOUR_BASES, _FOLDER_LABEL, _KEY_NUMBER, _PASTE_END, _PROGRESS_BAR, _STYLES
from installer.terminal import COLOUR_ROLES, _apart, painted, status_spans
from installer.text import _char_width, cell_width, fit, screen_text
from installer.tui_state import TUI_ROUTES


class TuiKey(NamedTuple):
    """One key press: a name ("up", "enter"), or "char" or "paste" and the text."""

    name: str
    text: str = ""


class TuiMouse(NamedTuple):
    """One mouse report: the button (0 left, 1 middle, 2 right, 3 a legacy
    release, 64 and 65 the wheel, plus 4, 8 and 16 for Shift, Meta and
    Ctrl), the cell counted from 1, and whether the button went up."""

    button: int
    col: int
    row: int
    release: bool = False
    name: str = "mouse"
    text: str = ""


def _sgr_mouse(params: str, final: str) -> TuiMouse | None:
    """An SGR report: ESC [ < button ; column ; row, M pressed, m released."""
    parts = params[1:].split(";")
    if len(parts) != 3 or not all(part.isdigit() for part in parts):
        return None
    button, col, row = (int(part) for part in parts)
    return TuiMouse(button, col, row, final == "m")


def _x10_mouse(data: str) -> TuiMouse | None:
    """A legacy report: three characters, each 32 plus its value, read from
    the bytes before UTF-8 decoding (TerminalInput): a position byte past
    127 is no character of its own."""
    codes = [ord(char) - 32 for char in data]
    if any(not 0 <= code <= 223 for code in codes):
        return None
    button, col, row = codes
    if col < 1 or row < 1:
        return None
    return TuiMouse(button, col, row, button & 3 == 3 and not button & 64)


_CSI_KEYS = {"A": "up", "B": "down", "C": "right", "D": "left", "H": "home", "F": "end",
             "Z": "shift-tab"}
_TILDE_KEYS = {"1": "home", "7": "home", "4": "end", "8": "end", "5": "pgup", "6": "pgdn",
               "3": "delete", "11": "f1"}
_SS3_KEYS = {"A": "up", "B": "down", "C": "right", "D": "left", "H": "home", "F": "end",
             "P": "f1", "M": "enter"}
# msvcrt.getwch gives these after a \x00 or \xe0 prefix.
_WINDOWS_KEYS = {"H": "up", "P": "down", "K": "left", "M": "right", "I": "pgup",
                 "Q": "pgdn", "G": "home", "O": "end", "S": "delete", ";": "f1"}


def _plain_key(char: str) -> TuiKey | None:
    """The key one character stands for, None for a control nobody bound."""
    named = {"\r": "enter", "\n": "enter", "\x7f": "backspace", "\x08": "backspace",
             "\t": "tab", "\x1b": "esc", "\x03": "ctrl-c", "\x04": "ctrl-d",
             "\x15": "ctrl-u", "\x1a": "ctrl-z"}.get(char)
    if named:
        return TuiKey(named)
    if char < " " or unicodedata.category(char) in ("Cc", "Cs"):
        return None
    return TuiKey("char", char)


def _csi_key(params: str, final: str) -> TuiKey | TuiMouse | None:
    if params.startswith("<"):
        return _sgr_mouse(params, final) if final in "Mm" else None
    if final == "~":
        if params == "200":
            return TuiKey("paste-start")
        name = _TILDE_KEYS.get(params.split(";")[0])
        return TuiKey(name) if name else None
    name = _CSI_KEYS.get(final)
    if name is None:
        return None
    if params in ("", "1"):
        return TuiKey(name)
    if params == "1;2" and name in ("up", "down"):
        return TuiKey(f"shift-{name}")
    return None


def _escape(buffer: str) -> tuple[int, TuiKey | TuiMouse | None]:
    """The sequence at the start of buffer: the characters it takes and its
    key (None for one nobody bound), or 0 while more are needed to tell."""
    if len(buffer) < 2:
        return 0, None
    if buffer[1] == "[":
        if buffer[2:3] == "M":
            # A legacy mouse report: three bytes of button and position
            # follow, read as a report and never as keys.
            return (6, _x10_mouse(buffer[3:6])) if len(buffer) >= 6 else (0, None)
        for end in range(2, len(buffer)):
            code = ord(buffer[end])
            if 0x40 <= code <= 0x7E:
                return end + 1, _csi_key(buffer[2:end], buffer[end])
            if not 0x20 <= code <= 0x3F:
                return 1, TuiKey("esc")
        return 0, None
    if buffer[1] == "O":
        if len(buffer) < 3:
            return 0, None
        name = _SS3_KEYS.get(buffer[2])
        return 3, TuiKey(name) if name else None
    return 1, TuiKey("esc")


class KeyDecoder:
    """Keys from what a terminal sends, however the reads split it.

    Unknown sequences (F13) are dropped, never taken as text. A mouse
    report, SGR or legacy, comes out as a TuiMouse.
    """

    def __init__(self) -> None:
        self.buffer = ""
        self.paste: str | None = None

    def feed(self, text: str) -> list[TuiKey | TuiMouse]:
        self.buffer += text
        return self._drain(final=False)

    def flush(self) -> list[TuiKey | TuiMouse]:
        """What is left once the wait for the rest of a sequence is over.

        An open paste stays open: over SSH its end arrives later than 40 ms.
        """
        return self._drain(final=True)

    def close_paste(self) -> list[TuiKey | TuiMouse]:
        """The paste so far, its end never seen, without its newlines."""
        text = "".join(char for char in self.paste or "" if char >= " " and char != "\x7f")
        self.paste = None
        return [TuiKey("paste", text)] if text else []

    @property
    def waiting(self) -> bool:
        return bool(self.buffer) or self.paste is not None

    def _drain(self, final: bool) -> list[TuiKey | TuiMouse]:
        keys: list[TuiKey | TuiMouse] = []
        while self.buffer:
            if self.paste is not None:
                end = self.buffer.find(_PASTE_END)
                if end < 0:
                    # The end marker may be cut between two reads.
                    keep = next((n for n in range(len(_PASTE_END) - 1, 0, -1)
                                 if self.buffer.endswith(_PASTE_END[:n])), 0)
                    cut = len(self.buffer) - keep
                    self.paste += self.buffer[:cut]
                    self.buffer = self.buffer[cut:]
                    break
                self.paste += self.buffer[:end]
                self.buffer = self.buffer[end + len(_PASTE_END):]
                keys += self.close_paste()
                continue
            if self.buffer[0] == "\x1b":
                taken, key = _escape(self.buffer)
                if not taken:
                    if final:
                        if self.buffer == "\x1b":
                            keys.append(TuiKey("esc"))
                        self.buffer = ""
                    break
                self.buffer = self.buffer[taken:]
                if key is not None and key.name == "paste-start":
                    self.paste = ""
                elif key is not None:
                    keys.append(key)
                continue
            key = _plain_key(self.buffer[0])
            self.buffer = self.buffer[1:]
            if key is not None:
                keys.append(key)
        return keys


_X10_START = b"\x1b[M"


class TerminalInput:
    """The text the keys are read from, out of the bytes a terminal sends.

    A legacy mouse report is three raw bytes after ESC [ M: a column from
    162 and a row from 96 made two of them one UTF-8 character, so the
    report came one character short and took the next key as its row. Its
    three bytes go to the key decoder one character each, whatever UTF-8
    makes of them, and the rest is decoded as text."""

    def __init__(self, encoding: str = "utf-8") -> None:
        self.text = codecs.getincrementaldecoder(encoding)(errors="replace")
        # The report bytes still to come from the next read, and the last
        # two bytes read, where a report's ESC [ may have started.
        self.need = 0
        self.tail = b""

    def decode(self, data: bytes) -> str:
        out: list[str] = []
        if self.need:
            raw, data = data[:self.need], data[self.need:]
            self.need -= len(raw)
            out.append(raw.decode("latin-1"))
        joined = self.tail + data
        shift = len(self.tail)
        start = shift
        search = 0
        while True:
            at = joined.find(_X10_START, search)
            if at < 0:
                break
            report = at + len(_X10_START)
            if report <= shift:
                # Read whole before: decoded then.
                search = at + 1
                continue
            out.append(self.text.decode(joined[start:report]))
            raw = joined[report:report + 3]
            out.append(raw.decode("latin-1"))
            self.need = 3 - len(raw)
            start = search = report + len(raw)
        out.append(self.text.decode(joined[start:]))
        self.tail = joined[-2:]
        return "".join(out)

    def flush(self) -> None:
        """The wait for the rest of a report is over: none is owed."""
        self.need = 0


def decode_windows_key(first: str, read_next: Callable[[], str]) -> TuiKey | None:
    """A key from msvcrt.getwch: arrows and pages come as a prefix, then a code."""
    if first in ("\x00", "\xe0"):
        name = _WINDOWS_KEYS.get(read_next())
        return TuiKey(name) if name else None
    return _plain_key(first)


def ascii_text(text: str) -> str:
    """The text in ASCII, accents dropped (Edition) and any other character
    as one ? per cell it took, so the columns stay where they were."""
    if text.isascii():
        return text
    plain = "".join(char for char in unicodedata.normalize("NFKD", text)
                    if not unicodedata.combining(char))
    return "".join(char if char.isascii() else "?" * _char_width(char) for char in plain)


def middle(text: str, width: int) -> str:
    """A long path cut in its middle, its start and its last folders kept."""
    if cell_width(text) <= width:
        return text
    if width <= 3:
        return fit(text, width)
    room = width - 3
    tail = fit(text[::-1], room // 2)[::-1]
    return fit(text, room - cell_width(tail)) + "..." + tail


def _columns(left: str, right: str, width: int) -> str:
    """left, and right against the edge when both fit, else left alone."""
    room = width - cell_width(right) - 2
    if not right or room < 8:
        return fit(left, width)
    return _pad(fit(left, room), room) + "  " + right


# Said under a command a path of which was cut to fit (_command_wrap).
TUI_SHORTENED = "Shortened to fit this window."


class TuiLine(str):
    """A screen line and how it is drawn: "head" (the screen's title),
    "title", "focus", "dim", "hint" (the bar), "refusal" or plain.

    mark is what a click on the line reaches (tui_hits): ("row", index,
    (action, value)) for a row of the list, ("scroll", kind, rows) for the
    line saying which lines are in view, ("bar",) for the bar."""

    style = ""
    mark: tuple | None = None
    # A line of a command, however it was wrapped: the mouse is left to the
    # terminal on a frame showing one (tui_wants_mouse).
    command = False
    # Whether the command it holds is typed into PowerShell, from the
    # Invocation that made it: its line ends follow its words.
    powershell: bool | None = None
    # Shown on the Details screen, not on the screen it explains.
    detail = False
    # A count standing for Details lines: left out where they are shown.
    brief = False


def _styled(text: str, style: str = "") -> TuiLine:
    line = TuiLine(screen_text(text))
    line.style = style
    return line


def _detail(text: str, style: str = "") -> TuiLine:
    """A line of the Details screen: an explanation, a list, a reason."""
    line = _styled(text, style)
    line.detail = True
    return line


def _details(lines: Iterable[str]) -> list[TuiLine]:
    """lines as Details lines, each keeping how it is drawn."""
    marked = []
    for line in lines:
        copy = TuiLine(str(line))
        for name in ("style", "mark", "command", "powershell"):
            if hasattr(line, name):
                setattr(copy, name, getattr(line, name))
        copy.detail = True
        marked.append(copy)
    return marked


def _is_detail(line: object) -> bool:
    return bool(getattr(line, "detail", False))


def _command_line(text: str, hint: Invocation) -> TuiLine:
    """A line holding a command hint made, wrapped with hint's shell."""
    line = _styled(text, "command")
    line.powershell = hint.powershell()
    return line


def _bar_keys() -> set[str]:
    """Every name a key or a button takes on the bar, on every route."""
    keys = {"Enter", "Esc", "Space", "Start", "Select", "Ctrl-C", "?", "/", "X/Space/tap",
            "Space/tap"}
    for route in TUI_ROUTES.values():
        keys.update(route.bar)
        keys.update(name for name in route.bar.values() if name)
    keys.update(name.strip() for pair in _SHORT_KEYS for name in pair)
    keys.update(f"{route.help['page'] or 'PgUp/PgDn'}".split(", ")[0]
                for route in TUI_ROUTES.values())
    return keys


def _bar_spans(text: str, first: str) -> list[tuple[int, int, str]]:
    """The bar's key names faint, the first in first, its actions plain:
    drawn faint, Back and Quit were the hardest words to find on a
    handheld, B being its way back."""
    spans = []
    for number, entry in enumerate(re.finditer(r"\S+(?: \S+)*", text)):
        key = entry.group().split(" ", 1)[0]
        if entry.group().endswith(TUI_ARMED_SHORT):
            # Armed by a first tap: the whole entry stands out, a plain
            # ": tap again" looked like no change at all.
            spans.append((entry.start(), entry.end(), first))
        elif key in _bar_keys() and " " in entry.group():
            spans.append((entry.start(), entry.start() + len(key),
                          first if number == 0 else "muted"))
    return spans


def tui_paint(text: str, style: str, colour: bool) -> str:
    """A drawn line as the terminal gets it: its style, and with colour the
    roles of its words (COLOUR_ROLES). The characters are those of text.

    The title names RetroBIOS in the accent, a headline its counts and
    sizes, the bar the key it names first, a line its status words, the
    plan and the result the BIOS folder in bold.
    """
    if not colour:
        if style == "hint":
            return painted(text, _bar_spans(text, "strong"))
        return _STYLES.get(style, "") + text
    base = _COLOUR_BASES.get(style, "")
    if style == "folder":
        # The rest of a BIOS folder wrapped onto its own line, as bold as
        # its start.
        start = len(text) - len(text.lstrip(" "))
        return painted(text, [(start, len(text.rstrip(" ")), "strong")], base)
    if style not in ("", "head", "title", "hint", "refusal"):
        return painted(text, [], base)
    spans: list[tuple[int, int, str]] = []
    if style == "hint":
        return painted(text, _bar_spans(text, "accent"))
    if style == "head":
        at = text.find("RetroBIOS")
        if at >= 0:
            spans.append((at, at + len("RetroBIOS"), "accent"))
    if style == "title":
        spans += [(match.start(), match.end(), "accent")
                  for match in _KEY_NUMBER.finditer(text)]
    lead = text.lstrip(" ")
    if lead.startswith(_FOLDER_LABEL):
        start = len(text) - len(lead) + len(_FOLDER_LABEL)
        # The folder alone: on Options the bold ran on into --dest.
        end = text.find("  ", start)
        spans.append((start, len(text.rstrip(" ")) if end < 0 else end, "strong"))
    bar = _PROGRESS_BAR.match(text)
    if bar:
        spans += [(bar.start(1), bar.end(1), "accent"), (bar.start(2), bar.end(2), "muted")]
    # On a bold line a status word stays bold.
    spans += [(start, end, f"strong+{role}" if base == "strong"
               and not COLOUR_ROLES[role].startswith("1;") else role)
              for start, end, role in status_spans(text)]
    return painted(text, _apart(spans), base)


def _short_path(path: Path | None, home: Path) -> str:
    if path is None:
        return ""
    text = str(path)
    home_text = str(home)
    if home_text not in ("", "/", ".") and (text == home_text
                                           or text.startswith(home_text + os.sep)):
        return "~" + text[len(home_text):]
    return shown_path(text)


# What a check run tells the screen, kept whole when Choose systems widens a
# --system plan: Back with the same ticks gives that plan back.
_CHECK_FIELDS = ("check", "files", "systems", "choices", "set_aside", "found", "scanned",
                 "unreadable", "saves", "check_summary", "checked_flags", "cli_systems",
                 "facts", "ticked", "version", "board", "checked_dests", "games",
                 "games_unavailable")

TUI_ARMED_SHORT = "tap again"

# Shorter key names for a narrow bar: at 40 columns "X/Space Tick" was cut,
# and nothing said how to tick with a controller.
_SHORT_KEYS = (("A/Enter/tap ", "A/tap "), ("A/Enter ", "A "), ("B/Esc ", "B "),
               ("X/Space/tap ", "X/tap "),
               ("X/Space ", "X "), ("Y/o ", "Y "), ("Left/Right ", "<> "), ("Up/Down ", "^v "))
