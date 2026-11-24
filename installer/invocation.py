"""How the installer was started, and the command it gives back to run it again."""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import shlex
import sys
from pathlib import Path

from installer.remote import BOOTSTRAP_URL

# Downloads at once when --jobs is not given.
DEFAULT_JOBS = 8

# Options that take a value, as a hint gives them back.
_VALUED_OPTIONS = (
    "--system", "--core", "--emulator", "--region", "--target", "--cores-dir", "--save-dir",
    "--from-pack", "--from", "--manifest",
)


# The options a choice at the questions sets, which replace the command's.
_CHOICE_OPTIONS = ("--system", "--core", "--region", "--for-games", "--required-only")

# The order every command given back writes its options in: the list, what
# narrows it, where files are copied from, then how the run goes. The screen
# wrote --manifest before --from and line mode after it, for one choice
# An option not named here comes after them.
_COMMAND_ORDER = (
    "--manifest", "--from-pack", "--system", "--core", "--emulator", "--standalone",
    "--region", "--one-per-slot", "--source", "--find", "--for-games", "--required-only",
    "--all-files", "--target", "--no-game-data", "--installed-cores", "--cores-dir",
    "--every-board",
    "--declared-only", "--standalone-copies", "--save-dir", "--jobs", "--from",
    "--add-app", "--offline", "--check", "--dry-run",
)


# The options that print a list and install nothing, in the order a run
# names them.
LISTING_FLAGS = (("--list-platforms", "list_platforms"), ("--list-targets", "list_targets"),
                 ("--list-systems", "list_systems"), ("--list-cores", "list_cores"),
                 ("--list-emulators", "list_emulators"))


def listings_given(args: argparse.Namespace) -> list[str]:
    """The listing options of a run, as typed."""
    return [flag for flag, attr in LISTING_FLAGS if getattr(args, attr)]


def _command_rank(option: tuple[str, str | None]) -> int:
    flag = option[0]
    return _COMMAND_ORDER.index(flag) if flag in _COMMAND_ORDER else len(_COMMAND_ORDER)


def package_command(prefix: str) -> str:
    """The command that ran the retrobios package, read from the environment
    it runs in. uvx runs it from uv's cache (~/.cache/uv/archive-v0/<id>
    with uv 0.12.9) and pipx run from pipx's (~/.cache/pipx/<id> with
    pipx 1.4.3), and neither leaves a retrobios command behind. pip, pipx
    install (pipx's venvs/) and uv tool install do."""
    parts = re.split(r"[\\/]", prefix)
    if "archive-v0" in parts:
        return "uvx retrobios"
    if any(part in ("pipx", ".pipx") for part in parts) and "venvs" not in parts:
        return "pipx run retrobios"
    return "retrobios"


class Invocation:
    """How this run was started, so that a hint gives the command back whole.

    A one-liner user has no install.py to run: install.sh and install.ps1 run
    a temporary copy and say so in RETROBIOS_BOOTSTRAP. And a hint that
    dropped --system turned a retry of 2 files into one of 8069.
    """

    def __init__(self) -> None:
        self.os_type = ""
        self.options: list[tuple[str, str | None]] = []
        # Per platform, what was chosen at the questions.
        self.chosen: dict[str, list[tuple[str, str | None]]] = {}

    def record(self, args: argparse.Namespace) -> None:
        """Keep every option that decides what a run installs or reports."""
        options: list[tuple[str, str | None]] = []
        for flag in _VALUED_OPTIONS:
            value = getattr(args, flag[2:].replace("-", "_"), None)
            values = value if isinstance(value, list) else [value] if value else []
            options += [(flag, str(v)) for v in values]
        games = getattr(args, "for_games", None)
        if games is not None:
            options.append(("--for-games", None if games is True else str(games)))
        if getattr(args, "source", "full") != "full":
            options.append(("--source", args.source))
        if getattr(args, "find", None):
            options.append(("--find", args.find))
        for flag, on in (
            ("--required-only", getattr(args, "required_only", False)),
            ("--all-files", getattr(args, "all_files", False)),
            ("--every-board", args.every_board),
            ("--installed-cores", args.installed_cores and not args.cores_dir),
            ("--no-game-data", args.no_game_data),
            ("--declared-only", args.declared_only),
            ("--one-per-slot", getattr(args, "one_per_slot", False)),
            ("--standalone", getattr(args, "standalone", False)),
            ("--standalone-copies", args.standalone_copies),
            ("--offline", offline_option(getattr(args, "offline", False))),
            ("--check", args.check),
            ("--dry-run", args.dry_run),
        ):
            if on:
                options.append((flag, None))
        self.options = options

    def powershell(self) -> bool:
        """Whether the command is typed into PowerShell: its words and its
        line ends both read this (_continuation). The bootstrap names its
        shell, the system decides without one."""
        bootstrap = os.environ.get("RETROBIOS_BOOTSTRAP")
        if bootstrap in ("ps1", "sh"):
            return bootstrap == "ps1"
        return (self.os_type or ("windows" if os.name == "nt" else "")) == "windows"

    def launcher(self, elevated: bool = False) -> str:
        """The command without its options, as the user typed it."""
        bootstrap = os.environ.get("RETROBIOS_BOOTSTRAP", "")
        if bootstrap == "ps1":
            return f"&([scriptblock]::Create((irm {BOOTSTRAP_URL}.ps1)))"
        if bootstrap == "sh":
            return f"curl -fsSL {BOOTSTRAP_URL} | {'sudo ' if elevated else ''}sh -s --"
        if bootstrap == "pypi":
            return f"{'sudo ' if elevated else ''}{package_command(sys.prefix)}"
        python = "python" if self.os_type == "windows" else "python3"
        return f"{'sudo ' if elevated else ''}{python} install.py"

    def word(self, value: str) -> str:
        if self.powershell():
            # A comma makes an array and @ a splat in PowerShell arguments.
            if re.fullmatch(r"[A-Za-z0-9_./:\\-]+", value):
                return value
            return "'" + value.replace("'", "''") + "'"
        return shlex.quote(value)

    def command(
        self, plat: str, dest: Path | str | None, elevated: bool = False,
        without: tuple[str, ...] = (),
    ) -> str:
        """The full command for plat and dest, a str dest being a placeholder."""
        words = [self.launcher(elevated)]
        if plat:
            words += ["--platform", plat]
        if isinstance(dest, Path):
            words += ["--dest", self.word(str(dest.absolute()))]
        elif dest:
            words += ["--dest", dest]
        for flag, value in self.flags(plat):
            if flag in without:
                continue
            words += [flag] if value is None else [flag, self.word(value)]
        return " ".join(words)

    def flags(self, plat: str) -> list[tuple[str, str | None]]:
        """The options of the run for plat, in the command's order."""
        options = self.options
        if plat in self.chosen:
            # A choice made at the questions replaces the narrowing the
            # command line gave: both were printed, and --system named
            # the systems of the first run and of the second.
            replaced = {*_CHOICE_OPTIONS, *(flag for flag, _value in self.chosen[plat])}
            options = [option for option in options if option[0] not in replaced]
        return sorted([*options, *self.chosen.get(plat, [])], key=_command_rank)


_INVOCATION = Invocation()


def installer_id() -> str:
    """The first twelve hex digits of this file's SHA-256, as the bootstraps pin it."""
    try:
        return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()[:12]
    except (OSError, NameError):
        return "unknown"


# --offline, or this variable set to anything but 0, which every run the
# full-screen interface starts inherits. RETROBIOS_OFFLINE stays the build
# scripts' own: CI and the test suite set it for every process they start.
OFFLINE_VARIABLE = "RETROBIOS_INSTALL_OFFLINE"


def offline_option(given: bool) -> bool:
    """Whether a command given back to the user carries --offline: given,
    or RETROBIOS_INSTALL_OFFLINE set. sudo does not pass the variable on,
    and the command it was told to run fetched what the run had left out.
    Line mode and the screen build their commands with this one rule."""
    return given or offline_requested()


def offline_requested() -> bool:
    return os.environ.get(OFFLINE_VARIABLE, "") not in ("", "0")
