#!/usr/bin/env python3
"""Rewrite the marked tables of wiki/installer.md from install.py.

    python scripts/generate_installer_doc.py           rewrite the tables
    python scripts/generate_installer_doc.py --check   exit 1 when one is stale

Each table sits between `<!-- generated: NAME -->` and
`<!-- /generated: NAME -->`. What install.py knows is written from it: the
options and their arguments from its parser, the event kinds and their keys
from EVENT_KEYS, the exit codes from its sys.exit calls, the RETROBIOS_PAD
values and each route's keys from TUI_ROUTES, the handheld launchers from
sitehandheld.LAUNCHERS. The prose cells (what an option
does, when an event comes) are kept as written, matched by their row. A row
install.py gains has no prose yet: the generator names it and writes nothing,
and the row is added by hand inside the markers, its first cell holding the
option, kind, code or value alone.

The run samples (a dry run, a first install, a later check, the reasons a
file is refused, a run copying from an old card) are printed by install.py
itself, run in its own process against the committed install/<platform>.json
served on the loopback, from a home and a card made under tmp/ and shown as
/home/me and /userdata. The reasons and the copy are read from a four-file
list laid out in that home (SMALL_LIST), whose files are written there. Only
the transport and the machine are stood in for, see _child. Each is dated by
the `generated` field of its list, so a rendering is the same from one day
to the next.
"""

from __future__ import annotations

import argparse
import ast
import contextlib
import http.server
import importlib.util
import json
import os
import re
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import zipfile
from pathlib import Path, PurePosixPath
from typing import Callable

import sitehandheld
from artifacts import write_text_atomic

ROOT = Path(__file__).resolve().parent.parent
PAGE = ROOT / "wiki" / "installer.md"
INSTALLER = ROOT / "install.py"

_spec = importlib.util.spec_from_file_location("install", INSTALLER)
_install = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_install)

BLOCK = re.compile(
    r"(?P<open><!-- generated: (?P<name>[a-z-]+) -->\n)(?P<body>.*?)"
    r"(?P<close><!-- /generated: (?P=name) -->)", re.S)
_CELL = re.compile(r"(?<!\\)\|")

# The help screen's actions, as the page names them.
ACTIONS = {
    "move": "Move",
    "page": "Page",
    "ok": "Continue, open, choose",
    "tick": "Tick, untick",
    "options": "Change",
    "back": "Back, and quit on the first screen",
    "stop": "Stop an install",
    "kill": "Quit at once",
    "enter": "Use the folder typed",
    "esc": "Clear a filter, leave the folder typed",
}
# The two routes no launcher names, as the page heads their columns.
ROUTE_HEADINGS = {"keys": "Computer (`keys`)", "both": "Unknown (`both`)"}


class MissingProse(Exception):
    """Rows install.py has that the page does not describe yet."""


def _cells(line: str) -> list[str]:
    return [cell.strip() for cell in _CELL.split(line.strip().strip("|"))]


def _rows(body: str) -> list[list[str]]:
    lines = [line for line in body.splitlines() if line.startswith("|")]
    return [_cells(line) for line in lines[2:]]


def _prose(body: str, key: re.Pattern[str], width: int) -> dict[str, list[str]]:
    """The prose cells of each row, by the key its first cell holds."""
    kept = {}
    for cells in _rows(body):
        found = key.search(cells[0])
        if found:
            kept[found.group(1)] = (cells[1:] + [""] * width)[:width]
    return kept


def _table(heading: list[str], rows: list[list[str]]) -> str:
    lines = ["| " + " | ".join(heading) + " |",
             "|" + "|".join("-" * (len(cell) + 2) for cell in heading) + "|"]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join(lines) + "\n"


def _with_prose(name: str, facts: list[tuple[str, str]], body: str, key: str,
                width: int) -> list[list[str]]:
    """Each row's first cell from install.py, the rest from the page, whose
    last cell must be written."""
    prose = _prose(body, re.compile(key), width)
    missing = [fact for fact, _cell in facts if not prose.get(fact, [""])[-1]]
    if missing:
        raise MissingProse(f"{name}: no text for {', '.join(missing)}")
    return [[cell, *prose[fact]] for fact, cell in facts]


def option_rows(body: str) -> list[list[str]]:
    facts = []
    # argparse's own --help last, after the options of the run.
    for action in sorted(_install.build_parser()._actions,
                         key=lambda action: isinstance(action, argparse._HelpAction)):
        flags = sorted(action.option_strings, key=lambda flag: not flag.startswith("--"))
        metavar = "" if action.nargs == 0 else (action.metavar or action.dest.upper())
        shown = ", ".join(f"`{flag} {metavar}`" if metavar else f"`{flag}`" for flag in flags)
        facts.append((flags[0], f'<span id="option-{flags[0][2:]}"></span>{shown}'))
    return _with_prose("options", facts, body, r"`(--[a-z-]+)", 1)


def exit_codes() -> list[int]:
    """The codes install.py exits with: its sys.exit calls, 0 for a run
    that returns, 2 for an option argparse refuses."""
    codes = {0, 2}
    for node in ast.walk(ast.parse(INSTALLER.read_text(encoding="utf-8"))):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "exit" and getattr(node.func.value, "id", "") == "sys"
                and node.args):
            continue
        given = node.args[0]
        for value in ((given.body, given.orelse) if isinstance(given, ast.IfExp) else (given,)):
            if isinstance(value, ast.Constant) and isinstance(value.value, int):
                codes.add(value.value)
    return sorted(codes)


def exit_rows(body: str) -> list[list[str]]:
    facts = [(str(code), f"`{code}`") for code in exit_codes()]
    return _with_prose("exit-codes", facts, body, r"`(\d+)`", 1)


def event_rows(body: str) -> list[list[str]]:
    facts = [(kind, f"`{kind}`") for kind in _install.EVENT_KEYS]
    rows = _with_prose("events", facts, body, r"`([a-z_]+)`", 2)
    for row, keys in zip(rows, _install.EVENT_KEYS.values()):
        row[1] = ", ".join(f"`{key}`" for key in keys)
    return rows


def pad_rows(body: str) -> list[list[str]]:
    facts = [(route, f"`{route}`") for route in _install.TUI_PAD_ROUTES]
    return _with_prose("pad-routes", facts, body, r"`([a-z_]+)`", 2)


def route_keys() -> str:
    routes = _install.TUI_ROUTES
    actions = list(next(iter(routes.values())).help)
    unnamed = [action for action in actions if action not in ACTIONS]
    if unnamed or any(list(route.help) != actions for route in routes.values()):
        raise MissingProse(f"route-keys: TUI_ROUTES actions {unnamed or 'differ by route'} "
                           "need a name in ACTIONS")
    heading = ["Action", *(ROUTE_HEADINGS.get(name, f"`{name}`") for name in routes)]
    rows = [[ACTIONS[action], *(route.help[action] or "none" for route in routes.values())]
            for action in actions]
    return _table(heading, rows)


# Card markers that are files with no extension: the MiSTer binary.
_BARE_FILES = frozenset({"MiSTer"})


def _marker(rule: _install._OsRule) -> str:
    """A card rule's evidence in words: the file or folder, and the line it
    holds for a rule that reads one."""
    if rule.method == "file_matches":
        path, pattern = rule.values
        line = re.sub(r"\\s\*\$$", "", re.sub(r"^(\^|\\A)", "", pattern)).replace("\\", "")
        return f"`{path}` holding the line `{line}`"
    named = ", ".join(f"`{value}`" if PurePosixPath(value).suffix or value in _BARE_FILES
                      else f"`{value}/`" for value in rule.values)
    if rule.method == "games_part":
        # Told on the games part beside its bios folder, on a drive the
        # system does not call fixed (install.games_part).
        return f"{named} beside `bios/`, on a drive that is not a fixed disk"
    return named


def _list_words(plat: str) -> str:
    name = _install.display_name(plat)
    return f"{name}'{'' if name.endswith('s') else 's'} list"


def card_marker_rows() -> list[list[str]]:
    """The files that name a card or a SHARE drive, in the order they are
    read: install.py's card rules, then its SHARE drive files."""
    rows = [[_marker(rule), rule.name,
             f"`{rule.bios or 'bios'}`, {_list_words(rule.manifest)}"]
            for rule in _install._card_rules()]
    hostname = "system.hostname=BATOCERA"
    for plat, marker in _install._SHARE_DRIVES:
        name = _install.display_name(plat)
        evidence = (f"`{marker}` holding `{hostname}` or no hostname line, and no KNULLI file "
                    "above" if plat == "batocera" else f"`{marker}`")
        rows.append([evidence, f"{name} SHARE drive", f"`bios`, {_list_words(plat)}"])
    rows.append([f"`{_install._SHARE_DRIVES[0][1]}` with any other hostname, and no KNULLI "
                 "file above, or the files of two SHARE drives",
                 "named by neither: the run says which systems it could be",
                 "the folder of the system named with `--platform`"])
    return rows


# The folder the line menu example names: a home that is no one's.
MENU_FOLDER = "/home/me/.config/retroarch/system"


def line_menu() -> str:
    """The line menu of a RetroArch run, g then Enter pressed, as install.py
    prints it for the RetroArch list (install/retroarch.json): the very
    function line mode runs, its questions answered here. The page carried
    a copy typed by hand, whose keys and counts drifted from the installer."""
    import io  # noqa: PLC0415
    from unittest import mock  # noqa: PLC0415

    manifest = json.loads((ROOT / "install" / "retroarch.json").read_text(encoding="utf-8"))
    files = [*manifest["files"], *(manifest.get("case_variants") or [])]
    folder = Path(MENU_FOLDER)
    out = io.StringIO()
    answers = iter(["g", ""])

    def answer(prompt: str) -> str:
        given = next(answers)
        print(f"{prompt}{given}".rstrip())
        return given

    invocation = _install.Invocation()
    invocation.os_type = "linux"
    environment = {key: value for key, value in os.environ.items()
                   if key not in (_install.OFFLINE_VARIABLE, "RETROBIOS_BOOTSTRAP")}
    with mock.patch.dict(os.environ, environment, clear=True), \
            mock.patch.object(_install, "_INVOCATION", invocation), \
            mock.patch.object(_install, "_ask", answer), \
            mock.patch.object(_install, "folder_warnings", return_value=[]), \
            contextlib.redirect_stdout(out):
        cut = [False]

        def command(choice: object) -> str:
            invocation.chosen["retroarch"] = (
                (_install.chosen_flags(choice) if choice is not None else [])
                + ([("--no-game-data", None)] if cut[0] else []))
            return invocation.command("retroarch", folder)

        _install._prompt_custom_selection(
            "retroarch", files, manifest.get("omitted_files") or [], None, "RetroArch",
            False, manifest.get("data_directories") or [], folder,
            _install.records_selection(files), None, manifest, False, command, cut)
    return "```\n" + out.getvalue().strip("\n") + "\n```"


# The home and the card the run samples show, in place of the sandbox's.
SHOWN_HOME = "/home/me"
SHOWN_CARD = ""
RETROARCH_CFG = ('system_directory = "~/.config/retroarch/system"\n'
                 'savefile_directory = "~/.config/retroarch/saves"\n')


class _ListHandler(http.server.SimpleHTTPRequestHandler):
    """Serves the committed file lists, install/<platform>.json, and nothing
    else: a sample that asks for a file is a sample that downloads."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def do_GET(self) -> None:  # noqa: N802
        if not re.fullmatch(r"/install/[a-z0-9_-]+\.json", self.path):
            self.send_error(404)
            return
        super().do_GET()

    def log_message(self, *_args: object) -> None:
        return


class _LoopbackServer(http.server.ThreadingHTTPServer):
    """The list server, named by its number: HTTPServer.server_bind looks
    127.0.0.1 up with socket.getfqdn, a DNS query wherever /etc/hosts does
    not name it."""

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name, self.server_port = host, port


# The list the reasons and the copy are shown with: four files, each with
# the contents its name says, read as RetroArch's.
SMALL_LIST = {
    "scph5500.bin": (b"J" * 64, ["sony-playstation"], ["japan"], None),
    "scph5501.bin": (b"U" * 64, ["sony-playstation"], ["north-america"],
                     ["beetle_psx", "pcsx_rearmed"]),
    "gba_bios.bin": (b"G" * 32, ["nintendo-gba"], None, ["mgba"]),
    "pcsx/extra.bin": (b"E" * 8, ["sony-playstation"], None, ["pcsx_rearmed"]),
}


def write_small_list(path: Path) -> None:
    import hashlib  # noqa: PLC0415

    files = []
    for dest, (data, systems, regions, cores) in SMALL_LIST.items():
        files.append({"dest": dest, "size": len(data), "sha1": hashlib.sha1(data).hexdigest(),
                      "sha256": hashlib.sha256(data).hexdigest(),
                      "md5": hashlib.md5(data).hexdigest(), "systems": systems,
                      "cores": cores, "repo_path": f"bios/{dest}",
                      **({"regions": regions} if regions else {})})
    path.write_text(json.dumps({
        "manifest_version": 2, "platform": "retroarch", "display_name": "RetroArch",
        "base_destination": "system", "files": files, "total_files": len(files),
        "total_size": sum(entry["size"] for entry in files)}), encoding="utf-8")


def _child(spec: dict) -> int:
    """install.main() as the sample runs it, in its own process. Only the
    transport and the machine are stood in for: no connection leaves the
    loopback, detection finds the card folder the spec names, a file or a
    data tree of a landed run reports its bytes written without fetching
    them, and a held run finds every file and tree in place. The counts,
    sizes and words are the installer's own."""
    import concurrent.futures  # noqa: PLC0415
    import socket  # noqa: PLC0415
    from unittest import mock  # noqa: PLC0415

    real_connect = socket.create_connection

    def loopback_only(address: tuple, *args: object, **kwargs: object) -> socket.socket:
        if address[0] not in ("127.0.0.1", "localhost"):
            raise OSError(f"the sample makes no request to {address[0]}")
        return real_connect(address, *args, **kwargs)

    real_download = _install._download_one

    def landed(f: dict, bios: Path, verbose: bool = False, progress: object = None,
               copy: object = None) -> tuple[str, bool, str]:
        if copy is not None:
            # A copy from this machine is made for real: it is local.
            return real_download(f, bios, verbose, progress, copy)
        if progress is not None:
            progress.add(f["size"])
        return f["dest"], True, ""

    def held(files: list[dict], _bios: Path, **_kwargs: object) -> tuple:
        return [], list(files), []

    def tree_landed(entry: dict, _bios: Path, state: object = None,
                    _progress: object = None) -> dict:
        return {"present": 0, "installed": len(entry["files"]), "changed": 0,
                "absent": 0, "error": "", "not_kept": []}

    def tree_held(entry: dict, bios: Path, remember: bool = False) -> tuple:
        return bios / entry.get("dest", ""), {}, len(entry["files"])

    patches = [
        mock.patch.object(socket, "create_connection", loopback_only),
        # One worker and the submission order: the progress lines of a log.
        mock.patch.object(concurrent.futures, "as_completed", list),
        mock.patch.object(sys, "argv", ["install.py", *spec["argv"]]),
    ]
    if spec.get("card"):
        patches += [
            mock.patch.object(_install, "detect_platforms",
                              lambda _os: [(spec["platform"], Path(spec["card"]))]),
            mock.patch.object(_install, "_mounted_cards", lambda: []),
        ]
    if spec.get("landed"):
        patches.append(mock.patch.object(_install, "_download_one", landed))
        patches.append(mock.patch.object(_install, "install_data_directory", tree_landed))
    if spec.get("held"):
        patches.append(mock.patch.object(_install, "check_local", held))
        patches.append(mock.patch.object(_install, "data_directory_state", tree_held))
    with contextlib.ExitStack() as stack:
        for patch in patches:
            stack.enter_context(patch)
        try:
            _install.main()
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else 1
    return 0


# What the process of a run sample executes, the spec as its one argument.
CHILD = ("import json, sys; sys.path.insert(0, 'scripts'); import generate_installer_doc; "
         "sys.exit(generate_installer_doc._child(json.loads(sys.argv[1])))")


class Sandbox:
    """A home with a RetroArch config and a card folder, under tmp/, and the
    committed file lists served on the loopback. Every run sample of the page
    is printed here."""

    def __enter__(self) -> Sandbox:
        (ROOT / "tmp").mkdir(exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix="installer-doc-", dir=ROOT / "tmp"))
        self.home = self.root / "home"
        self.card = self.root / "card"
        config = self.home / ".config" / "retroarch" / "retroarch.cfg"
        config.parent.mkdir(parents=True)
        config.write_text(RETROARCH_CFG, encoding="utf-8")
        self.server = _LoopbackServer(("127.0.0.1", 0), _ListHandler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.root)

    def small(self, kind: str) -> str:
        """A run over SMALL_LIST in a home of its own: "refused", a --check
        of a folder holding a copy of each kind a check names, or "from", a
        run copying from an old card what it holds and downloading the rest."""
        home = self.root / kind
        system = home / ".config" / "retroarch" / "system"
        system.mkdir(parents=True)
        (system.parent / "retroarch.cfg").write_text(RETROARCH_CFG, encoding="utf-8")
        listed = home / "list.json"
        write_small_list(listed)
        data = {dest: entry[0] for dest, entry in SMALL_LIST.items()}
        if kind == "refused":
            (system / "scph5500.bin").write_bytes(data["scph5500.bin"])
            (system / "scph5501.bin").write_bytes(data["scph5500.bin"])
            (system / "system").mkdir()
            (system / "system" / "gba_bios.bin").write_bytes(data["gba_bios.bin"])
            with zipfile.ZipFile(system / "PSX BIOS.zip", "w") as archive:
                archive.writestr("extra.bin", data["pcsx/extra.bin"])
            # A check that flags a file ends on 3, as documented.
            return self.run("retroarch", "--check", "--verbose", "--manifest", str(listed),
                            home=home, codes=(3,))
        old = home / "old"
        old.mkdir()
        for dest in ("scph5500.bin", "scph5501.bin"):
            (old / dest).write_bytes(data[dest])
        return self.run("retroarch", "--yes", "--verbose", "--manifest", str(listed),
                        "--from", str(old), home=home, landed=True)

    def run(self, platform: str, *argv: str, landed: bool = False,
            held: bool = False, home: Path | None = None, codes: tuple = (0,)) -> str:
        """What install.py prints for the run, the sandbox read as a user's
        home and card."""
        home = home or self.home
        card = self.card / "userdata" / "bios" if platform != "retroarch" else None
        if card is not None:
            card.mkdir(parents=True, exist_ok=True)
        spec = {"platform": platform, "argv": ["--plain", "--platform", platform, *argv],
                "card": str(card) if card else None, "landed": landed, "held": held}
        env = {"PATH": os.environ.get("PATH", ""), "HOME": str(home),
               "RETROBIOS_OS": "linux", "LANG": "C.UTF-8",
               "RETROBIOS_BASE_URL": f"http://127.0.0.1:{self.server.server_address[1]}"}
        done = subprocess.run(
            [sys.executable, "-s", "-c", CHILD, json.dumps(spec)],
            cwd=ROOT, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True,
            check=False)
        if done.returncode not in codes:
            raise SampleFailed(f"install.py {' '.join(spec['argv'])} exited "
                               f"{done.returncode}: {done.stderr.strip()[-2000:]}")
        return done.stdout.replace(str(home), SHOWN_HOME).replace(str(self.card), SHOWN_CARD)


# The runs printed in this process, by what they read: the page is rendered
# more than once by --check and by the tests, from the same installer and lists.
_RUNS: dict[tuple, str] = {}


def _stamp(platform: str) -> tuple[int, int]:
    return tuple(hash(path.read_bytes()) for path in
                 (INSTALLER, ROOT / "install" / f"{platform}.json"))


class _LazySandbox:
    """A Sandbox opened at the first run a rendering asks for, and only then."""

    def __init__(self, stack: contextlib.ExitStack) -> None:
        self.stack = stack
        self.box: Sandbox | None = None

    def run(self, platform: str, *argv: str, **kinds: bool) -> str:
        key = (platform, argv, kinds.get("landed", False), kinds.get("held", False),
               _stamp(platform))
        if key in _RUNS:
            return _RUNS[key]
        if self.box is None:
            self.box = self.stack.enter_context(Sandbox())
        _RUNS[key] = self.box.run(platform, *argv, **kinds)
        return _RUNS[key]

    def small(self, kind: str) -> str:
        key = ("small", kind, _stamp("retroarch"))
        if key not in _RUNS:
            if self.box is None:
                self.box = self.stack.enter_context(Sandbox())
            _RUNS[key] = self.box.small(kind)
        return _RUNS[key]


class SampleFailed(Exception):
    """A run sample install.py could not print."""


def _lines_from(text: str, first: str, last: str | None = None, count: int | None = None
                ) -> list[str]:
    """The lines of a run from the one starting with first, through the one
    starting with last or for count lines."""
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if line.startswith(first)), None)
    if start is None:
        raise SampleFailed(f"the run printed no line starting {first!r}")
    if count is not None:
        return lines[start:start + count]
    end = next((i for i in range(start, len(lines)) if lines[i].startswith(last)), None)
    if end is None:
        raise SampleFailed(f"the run printed no line starting {last!r} after {first!r}")
    return lines[start:end + 1]


def _fenced(lines: list[str]) -> str:
    return "```\n" + "\n".join(lines) + "\n```"


def list_date(platform: str) -> str:
    """The day the committed list was generated, which dates its samples."""
    manifest = json.loads((ROOT / "install" / f"{platform}.json").read_text(encoding="utf-8"))
    return manifest["generated"][:10]


# The platform of the run walked through under Reading a run.
WALKTHROUGH = "batocera"
# A system of the RetroArch list one core pulls most of: the sample of the
# line naming it. A list where it no longer does fails the rendering, and
# another system is named here.
BULK_SYSTEM = "sony-playstation"


def _bulk_line(box: Sandbox | _LazySandbox) -> str:
    run = box.run("retroarch", "--dry-run", "--verbose", "--system", BULK_SYSTEM)
    found = [line for line in run.splitlines() if re.match(r"  \S+ pulls ", line)]
    if len(found) != 1:
        raise SampleFailed(f"a RetroArch run with --system {BULK_SYSTEM} names no core "
                           "pulling most of its download: name another BULK_SYSTEM")
    return found[0]


def sample_writers(box: Sandbox) -> dict[str, Callable[[str], str]]:
    """The run samples, each from the run that prints it: the walk through a
    run reads its --verbose lines, the default sample the lines it hides them
    from."""
    default_run = lambda: box.run(WALKTHROUGH, "--yes", "--jobs", "1", landed=True)  # noqa: E731
    install_run = lambda: box.run(WALKTHROUGH, "--yes", "--jobs", "1", "--verbose",  # noqa: E731
                                  landed=True)
    check_run = lambda: box.run(WALKTHROUGH, "--check", "--verbose", held=True)  # noqa: E731
    dry_run = lambda: box.run("retroarch", "--dry-run", "--verbose")  # noqa: E731
    return {
        "run-default": lambda _body: _fenced(
            _lines_from(default_run(), "Installing ", "Next: ")),
        "dry-run": lambda _body: (
            f"A RetroArch dry run into an empty folder, with the list of "
            f"{list_date('retroarch')}, printed this:\n\n"
            + _fenced(_lines_from(dry_run(), "Fetching file index", "  0 in place"))),
        "run-date": lambda _body: (
            f"Each line a first install prints, and what it means. The run below is a\n"
            f"{_install.display_name(WALKTHROUGH)} install into an empty folder, from the "
            f"list of {list_date(WALKTHROUGH)}.\nThe figures change with each release."),
        "run-first-lines": lambda _body: _fenced(
            _lines_from(install_run(), "Looking for setups", "  Found")),
        "run-index": lambda _body: _fenced(
            _lines_from(install_run(), "Fetching file index", "  0 in place")),
        "run-download": lambda _body: _fenced(
            _lines_from(install_run(), "Downloading ", count=4)),
        "run-end": lambda _body: _fenced(
            _lines_from(install_run(), "Done.", "To check this later")),
        "bulk-hint": lambda _body: (
            f"RetroArch with `--system {BULK_SYSTEM}`, from the list of "
            f"{list_date('retroarch')}:\n\n"
            + _fenced([_bulk_line(box)])),
        "run-check": lambda _body: _fenced(
            _lines_from(check_run(), "Checking existing files",
                        "  Every file on the list is in place")),
        "check-refused": lambda _body: _fenced(_refused_lines(box.small("refused"))),
        "from-run": lambda _body: _fenced(
            _lines_from(box.small("from"), "Done.", count=2)),
    }


def _refused_lines(text: str) -> list[str]:
    """The files a check flags, each with its reason and where its cores read it."""
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines)
                  if re.fullmatch(r"  \d+ files? [a-z ]+\.", line)), None)
    if start is None:
        raise SampleFailed("the check printed no files not in place")
    end = max(i for i, line in enumerate(lines) if line.lstrip().startswith("read by "))
    return lines[start:end + 1]


def render(page: str) -> str:
    """The page with each marked table and run sample written from install.py."""
    writers = {
        "options": lambda body: _table(["Option", "Effect"], option_rows(body)),
        "exit-codes": lambda body: _table(["Code", "Meaning"], exit_rows(body)),
        "events": lambda body: _table(["Kind", "Keys", "When"], event_rows(body)),
        "pad-routes": lambda body: _table(["Value", "Input", "Set by"], pad_rows(body)),
        "route-keys": lambda _body: route_keys(),
        "card-markers": lambda _body: _table(["On the card", "System", "Files go to"],
                                             card_marker_rows()),
        "line-menu": lambda _body: line_menu(),
        # Where each handheld launcher goes, written from the site's own
        # description of it (sitehandheld.LAUNCHERS).
        "handheld": lambda _body: "\n".join(sitehandheld.table_rows()),
        "handheld-downloads": lambda _body: "\n".join(sitehandheld.download_rows()),
    }
    seen = []
    with contextlib.ExitStack() as stack:
        box = _LazySandbox(stack)
        writers.update(sample_writers(box))

        def write(match: re.Match[str]) -> str:
            name = match.group("name")
            if name not in writers:
                raise MissingProse(f"no table is written for the marker {name!r}")
            seen.append(name)
            table = writers[name](match.group("body"))
            return f"{match.group('open')}\n{table}\n{match.group('close')}"

        text = BLOCK.sub(write, page)
    absent = sorted(set(writers) - set(seen))
    if absent:
        raise MissingProse(f"markers missing from the page: {', '.join(absent)}")
    return text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true",
                        help="exit 1 when a table differs from install.py, writing nothing")
    parser.add_argument("--page", type=Path, default=PAGE, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    current = args.page.read_text(encoding="utf-8")
    try:
        text = render(current)
    except MissingProse as exc:
        print(f"{args.page}: {exc}. Add the row inside its markers, then run "
              "python scripts/generate_installer_doc.py", file=sys.stderr)
        return 1
    except SampleFailed as exc:
        print(f"{args.page}: {exc}", file=sys.stderr)
        return 1
    if text == current:
        return 0
    if args.check:
        print(f"{args.page} differs from install.py and install/*.json: run "
              "python scripts/generate_installer_doc.py", file=sys.stderr)
        return 1
    write_text_atomic(str(args.page), text)
    print(f"Wrote {args.page}")
    return 0


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
