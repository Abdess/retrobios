"""The line questions: an answer typed, a quit, a folder typed."""
from __future__ import annotations

import os
import sys
from pathlib import Path

from installer.probe import _host_path
from installer.text import _glued_words, cell_width


def _names_and(names: list[str]) -> str:
    """Names in a sentence: A, A and B, A, B and C."""
    return " and ".join(names) if len(names) < 3 else f"{', '.join(names[:-1])} and {names[-1]}"


def _typed_folder(raw: str) -> Path:
    """A folder typed at a question, read as a shell reads an argument.

    Explorer's "Copy as path" puts quotes around it, and users quote a path
    with spaces: kept, they sent the files into a folder named `"` under
    the current directory, and the run said Done.
    """
    text = raw.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        text = text[1:-1].strip()
    # Under WSL, D: and D:\ are the Windows drive the screen calls D:.
    return _host_path(os.path.expandvars(os.path.expanduser(text)))


def _ask(prompt: str) -> str:
    """An answer, or a stop: Ctrl+D at a question is Ctrl+C.

    Both used to leave with 0, so `install.sh && retroarch` went on with no
    BIOS. They now end where Ctrl+C ends everywhere else, on 130.
    """
    try:
        return input(prompt).strip()
    except EOFError:
        print()
        raise KeyboardInterrupt from None


# A quit chosen at a question or on the screen: nothing was installed, as
# gh ends a prompt cancelled. 130 is 128 plus SIGINT, which shells read as a
# run killed by Ctrl-C, and 0 let `install.sh && retroarch` start RetroArch
# on no BIOS. Ctrl-C and Ctrl-D keep 130.
QUIT_CODE = 2


def _quit() -> None:
    """q at a question ends the run on QUIT_CODE."""
    sys.exit(QUIT_CODE)


def _no_widow(lines: list[str], room: int) -> list[str]:
    """Wrapped lines whose last one is not a word alone: "shared" stood on a
    line of its own under its size at 40 columns. The
    word before it goes down with it where both fit."""
    if len(lines) < 2 or len(_glued_words(lines[-1])) > 1:
        return lines
    # A size goes down with its unit: "1.4" / "MB shared" split it.
    words = _glued_words(lines[-2])
    lead = lines[-2][:len(lines[-2]) - len(lines[-2].lstrip(" "))]
    moved = f"{words[-1]} {lines[-1].strip()}"
    if len(words) < 2 or cell_width(moved) > room:
        return lines
    return [*lines[:-2], lead + " ".join(words[:-1]), moved]
