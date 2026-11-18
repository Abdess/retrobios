"""Keys and mouse reports decoded from what the terminal sends."""
from __future__ import annotations

import codecs
import unicodedata
from collections.abc import Callable
from typing import NamedTuple

_PASTE_START = "\x1b[200~"
_PASTE_END = "\x1b[201~"


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
