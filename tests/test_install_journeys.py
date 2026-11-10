"""The five journeys of the full screen, keys counted from launch.

Measured on 2026-11-09: a first install with RetroArch found, a muOS card
in a reader holding a game, an update after a release, an install narrowed
to one system then run again, a look at what is missing, and a folder for
another device. Each test drives the real install.py --tui on a
pseudo-terminal against a loopback repository, every key counted, typed
letters included. A journey that takes another number of keys than
JOURNEY_KEYS fails: a change that shortens one lowers its count here, and
one that lengthens it has to say so here too.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import functools
import hashlib
import http.server
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import install  # noqa: E402
import test_install_games as games  # noqa: E402
from test_install_tui import DOWN, UP, Pty, pty, pyte  # noqa: E402

END = "\x1b[F"
ESC = "\x1b"

# (keys to start the install or reach the answer, keys in all). One system
# is reached through None and the filter, the other device's folder typed
# as ~/bios.
JOURNEY_KEYS = {
    "first_install": (2, 3),
    "card_with_games": (2, 3),
    "update": (2, 3),
    "one_system": (14, 15),
    "one_system_again": (2, 3),
    "what_is_missing": (5, 6),
    "another_device": (19, 20),
}

# Words each journey's screens show by default, summed over the screens it
# stops on, and the most one screen of the default path may show (owner,
# 2026-11-09: a beginner lost the important line in text). A path is no
# word: its length is the machine's. The counts from before the Details
# screen took the plan's and the result's notes are in claudedocs/
# user_research/installer_ux/phase1_measure.md. A change that adds words
# raises a number here and says why.
JOURNEY_WORDS = {
    "first_install": 63,
    "card_with_games": 106,
    "update": 79,
    "one_system": 193,
    "one_system_again": 68,
    "what_is_missing": 223,
    "another_device": 230,
}
# Which setup? names every setup, Preview every file: lists, not prose.
SCREEN_CEILING = 90
# The same journeys in line mode, run without questions: (lines, words) of
# what happens, where, the result and the next step.
LINE_TEXT = {
    "first_install": (4, 18),
    "card_with_games": (4, 29),
    "update": (5, 36),
    "one_system": (4, 18),
    "what_is_missing": (3, 15),
    "another_device": (4, 18),
}


def words(text: str) -> int:
    """Words a reader reads, a path left out."""
    return sum(1 for token in text.split() if re.search(r"[A-Za-z0-9]", token)
               and "/" not in token)


def lines(text: str) -> int:
    return sum(1 for line in text.splitlines() if line.strip())


# Runs install.py with the mounted drives a reader would show, none or the
# card named: the drives of the machine running the tests (WSL's /mnt/d)
# changed the screens. Only the screen's own process looks for cards: the
# runs it starts are given --platform and --dest.
_WITH_CARDS = (
    "import os, sys\n"
    "from pathlib import Path\n"
    "sys.argv[0] = {script!r}\n"
    "sys.path.insert(0, os.path.dirname(sys.argv[0]))\n"
    "import install\n"
    "card = os.environ.get('JOURNEY_CARD')\n"
    "install._mounted_cards = lambda: [Path(card)] if card else []\n"
    "install._line_buffered_stdout()\n"
    "install.main()\n"
)


class _Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        return


class Repository:
    """The games fixture of test_install_games served on loopback: a
    RetroArch list, the same list for Batocera, the games index with a
    muOS setup, and every payload."""

    def __init__(self, test: unittest.TestCase) -> None:
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        self.root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        test.addCleanup(shutil.rmtree, self.root, True)
        self.site = self.root / "site"
        (self.site / "install" / "games").mkdir(parents=True)
        (self.site / "bios").mkdir()
        self.listed = games.manifest()
        self.write_list()
        muos = dict(games.SETUP, setup="muos", name="muOS",
                    roms_root={"path": "/mnt/mmc/ROMS", "from_bios": "../../ROMS"})
        retroarch = dict(games.SETUP, roms_root={"path": None, "from_bios": None})
        games.write_index(self.site / "install" / "games", setup=retroarch,
                          more_setups={"muos": muos})
        handler = functools.partial(_Quiet, directory=str(self.site))
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        test.addCleanup(server.server_close)
        test.addCleanup(server.shutdown)
        self.home = self.root / "home"
        self.home.mkdir()
        self.env = {**os.environ, "TERM": "xterm", "HOME": str(self.home),
                    "RETROBIOS_OS": "linux", "XDG_CONFIG_HOME": str(self.home / ".config"),
                    "RETROBIOS_BASE_URL": f"http://127.0.0.1:{server.server_address[1]}",
                    "RETROBIOS_CACHE": str(self.root / "cache")}
        for name in ("DISPLAY", "WAYLAND_DISPLAY", "SSH_CONNECTION", "SSH_TTY", "NO_COLOR",
                     install.TUI_PAD_ENV, install.OFFLINE_VARIABLE, *install._STEAM_MARKERS):
            self.env.pop(name, None)

    def write_list(self) -> None:
        for entry in self.listed["files"]:
            payload = entry["dest"].encode().ljust(entry["size"], b".")[:entry["size"]]
            entry["sha1"] = hashlib.sha1(payload).hexdigest()
            entry["sha256"] = hashlib.sha256(payload).hexdigest()
            (self.site / entry["repo_path"]).write_bytes(payload)
        for plat in ("retroarch", "batocera"):
            (self.site / "install" / f"{plat}.json").write_text(
                json.dumps({**self.listed, "platform": plat}))

    def retroarch_here(self) -> Path:
        """A RetroArch whose configuration names its system folder."""
        dest = self.root / "retroarch" / "system"
        dest.mkdir(parents=True)
        config = self.home / ".config" / "retroarch"
        config.mkdir(parents=True)
        (config / "retroarch.cfg").write_text(f'system_directory = "{dest}"\n')
        return dest


def written(folder: Path) -> list[str]:
    return sorted(p.relative_to(folder).as_posix() for p in folder.rglob("*") if p.is_file())


@unittest.skipUnless(pyte and pty, "the journeys need pyte and a pty")
class Journeys(unittest.TestCase):
    def start(self, repo: Repository, *args: str, env: dict | None = None) -> Pty:
        program = [sys.executable, "-c",
                   _WITH_CARDS.format(script=str(REPO_ROOT / "install.py"))]
        term = Pty(list(args), {**repo.env, **(env or {})}, 80, 24, program=program)
        self.addCleanup(lambda: term.status is None and os.kill(term.pid, 9))
        self.keys = 0
        self.screens: list[str] = []
        waiting = term.wait

        def wait(needle: str, timeout: float = 20.0) -> str:
            # Each screen the journey stops on, read once drawn whole.
            waiting(needle, timeout)
            screen = term.settle(0.3)
            self.screens.append(screen)
            return screen

        term.wait = wait  # type: ignore[method-assign]
        return term

    def press(self, term: Pty, *keys: str) -> None:
        """Each key sent, a typed word counted letter by letter."""
        for key in keys:
            if len(key) > 1 and not key.startswith(ESC):
                for letter in key:
                    term.send(letter)
                    self.keys += 1
            else:
                term.send(key)
                self.keys += 1

    def counted(self, journey: str, started: int, total: int) -> None:
        self.assertEqual((started, total), JOURNEY_KEYS[journey],
                         f"{journey} takes {(started, total)} keys now: longer is a step "
                         "back, shorter lowers JOURNEY_KEYS")
        said = [words(screen) for screen in self.screens]
        self.assertLessEqual(sum(said), JOURNEY_WORDS[journey],
                             f"{journey} shows {said} words: more is a step back")
        self.assertLessEqual(max(said), SCREEN_CEILING, said)
        self.screens = []

    def finish(self, term: Pty) -> int:
        term.wait("A/Enter Exit", timeout=60)
        self.press(term, "\r")
        return term.close()

    def test_first_install_with_retroarch_found(self):
        repo = Repository(self)
        dest = repo.retroarch_here()
        term = self.start(repo)
        screen = term.wait("Where to install?", timeout=40)
        self.assertIn("> RetroArch", screen)
        self.press(term, "\r")
        term.wait("files to download", timeout=40)
        self.press(term, "\r")
        started = self.keys
        self.assertEqual(self.finish(term), 0)
        self.counted("first_install", started, self.keys)
        self.assertEqual(written(dest), sorted(e["dest"] for e in repo.listed["files"]))

    def test_a_muos_card_holding_a_game(self):
        """The screen passes --platform=retroarch to its runs: the card's
        games were not read, and the plan offered the whole list."""
        repo = Repository(self)
        card = repo.root / "MUOS"
        bios = card / "MUOS" / "bios"
        bios.mkdir(parents=True)
        (card / "ROMS" / "GBA").mkdir(parents=True)
        (card / "ROMS" / "GBA" / "unknown.gba").write_bytes(b"not in any catalog")
        term = self.start(repo, env={"JOURNEY_CARD": str(card)})
        term.wait("Where to install?", timeout=40)
        self.press(term, "\r")
        screen = term.wait("For the games on this card: yes", timeout=60)
        self.assertIn("For the 1 game on this card.", screen)
        self.press(term, "\r")
        started = self.keys
        self.assertEqual(self.finish(term), 0)
        self.counted("card_with_games", started, self.keys)
        self.assertEqual(written(bios), ["gba_bios.bin"])

    def test_an_update_after_a_release(self):
        repo = Repository(self)
        dest = repo.retroarch_here()
        first = subprocess.run(
            [sys.executable, str(REPO_ROOT / "install.py"), "--platform", "retroarch",
             "--dest", str(dest), "--all-files", "--yes"],
            env=repo.env, capture_output=True, text=True, timeout=120, check=False,
            stdin=subprocess.DEVNULL)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        # The release changes one file.
        changed = next(e for e in repo.listed["files"] if e["dest"] == "md_eu.bin")
        changed["size"] += 1
        repo.write_list()
        term = self.start(repo)
        term.wait("Where to install?", timeout=40)
        self.press(term, "\r")
        term.wait("1 file to download", timeout=40)
        self.press(term, "\r")
        started = self.keys
        self.assertEqual(self.finish(term), 0)
        self.counted("update", started, self.keys)
        self.assertEqual((dest / "md_eu.bin").stat().st_size, changed["size"])

    def test_one_system_then_the_same_again(self):
        repo = Repository(self)
        dest = repo.retroarch_here()
        term = self.start(repo)
        term.wait("Where to install?", timeout=40)
        self.press(term, "\r")
        term.wait("files to download", timeout=40)
        for _step in range(12):
            if "> Choose systems" in term.settle():
                break
            self.press(term, DOWN)
        self.press(term, "\r")
        term.wait("RetroBIOS: Choose systems")
        # None, the filter, the system ticked, Esc clearing the filter,
        # Esc for Done.
        self.press(term, "n", "/", "gba", "\r", "\r", ESC, ESC)
        term.wait("for 1 of", timeout=20)
        self.press(term, "\r")
        term.wait("Counted again for these choices", timeout=40)
        self.press(term, "\r")
        started = self.keys
        self.assertEqual(self.finish(term), 0)
        self.counted("one_system", started, self.keys)
        self.assertEqual(written(dest), ["gba_bios.bin"])
        # The next release: the earlier choice is not kept, and two keys
        # install the whole list.
        term = self.start(repo)
        term.wait("Where to install?", timeout=40)
        self.press(term, "\r")
        term.wait("files to download", timeout=40)
        self.press(term, "\r")
        started = self.keys
        self.assertEqual(self.finish(term), 0)
        self.counted("one_system_again", started, self.keys)
        self.assertEqual(written(dest), sorted(e["dest"] for e in repo.listed["files"]))

    def test_what_is_missing(self):
        repo = Repository(self)
        repo.retroarch_here()
        term = self.start(repo)
        term.wait("Where to install?", timeout=40)
        self.press(term, "\r")
        term.wait("files to download", timeout=40)
        self.press(term, "o")
        term.wait("Each row is an option")
        self.press(term, END, UP)
        term.wait("> Preview the file list")
        self.press(term, "\r")
        term.wait("md_eu.bin", timeout=40)
        started = self.keys
        self.press(term, "q")
        self.assertEqual(term.close(), 2)
        self.counted("what_is_missing", started, self.keys)

    def test_a_folder_for_another_device(self):
        repo = Repository(self)
        repo.retroarch_here()
        term = self.start(repo)
        term.wait("Where to install?", timeout=40)
        for _step in range(12):
            if "> Another setup or folder" in term.settle():
                break
            self.press(term, DOWN)
        self.press(term, "\r")
        term.wait("Which setup?")
        # The filter's Enter takes the one setup it leaves.
        self.press(term, "/", "bato", "\r")
        term.wait("Which folder?", timeout=40)
        self.press(term, DOWN, "\r")
        term.wait("RetroBIOS: Type a path")
        self.press(term, "~/bios", "\r")
        term.wait("Create the folder?")
        self.press(term, "\r")
        screen = term.wait("files to download", timeout=40)
        self.assertIn("RetroBIOS: Batocera", screen)
        self.press(term, "\r")
        started = self.keys
        self.assertEqual(self.finish(term), 0)
        self.counted("another_device", started, self.keys)
        self.assertEqual(written(repo.home / "bios"),
                         sorted(e["dest"] for e in repo.listed["files"]))


@unittest.skipUnless(pty, "the journeys need a pty")
class LineModeJourneys(unittest.TestCase):
    """The journeys in line mode without questions: what happens, where, the
    result and the next step by default, every hidden line given back by
    --verbose, and nothing waiting for an answer."""

    def run_line(self, repo: Repository, *args: str, card: Path | None = None
                 ) -> subprocess.CompletedProcess:
        program = [sys.executable, "-c",
                   _WITH_CARDS.format(script=str(REPO_ROOT / "install.py"))]
        env = {**repo.env, **({"JOURNEY_CARD": str(card)} if card else {})}
        return subprocess.run([*program, *args], env=env, capture_output=True, text=True,
                              timeout=120, check=False, stdin=subprocess.DEVNULL)

    def budget(self, journey: str, proc: subprocess.CompletedProcess) -> None:
        text = proc.stdout + proc.stderr
        most_lines, most_words = LINE_TEXT[journey]
        self.assertLessEqual(lines(text), most_lines, text)
        self.assertLessEqual(words(text), most_words, text)

    def test_each_journey_says_what_where_result_and_next(self):
        repo = Repository(self)
        dest = repo.retroarch_here()
        # No --yes and no terminal: nothing is asked, nothing waits.
        proc = self.run_line(repo)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.budget("first_install", proc)
        said = [line for line in proc.stdout.splitlines() if line.strip()]
        self.assertEqual([line.split(" ", 1)[0] for line in said],
                         ["Installing", "BIOS", "Done.", "Next:"])
        changed = next(e for e in repo.listed["files"] if e["dest"] == "md_eu.bin")
        changed["size"] += 1
        repo.write_list()
        proc = self.run_line(repo, "--yes")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.budget("update", proc)
        shutil.rmtree(dest)
        dest.mkdir()
        proc = self.run_line(repo, "--system", "nintendo-gba", "--yes")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.budget("one_system", proc)
        shutil.rmtree(dest)
        dest.mkdir()
        proc = self.run_line(repo, "--check")
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        self.budget("what_is_missing", proc)
        proc = self.run_line(repo, "--platform", "batocera", "--dest", str(repo.home / "bios"),
                             "--yes")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.budget("another_device", proc)

    def test_a_card_with_games(self):
        repo = Repository(self)
        card = repo.root / "MUOS"
        (card / "MUOS" / "bios").mkdir(parents=True)
        (card / "ROMS" / "GBA").mkdir(parents=True)
        (card / "ROMS" / "GBA" / "unknown.gba").write_bytes(b"not in any catalog")
        proc = self.run_line(repo, "--yes", card=card)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.budget("card_with_games", proc)
        self.assertIn("what the games need", proc.stdout)

    def test_verbose_gives_back_every_line(self):
        """Each line a run prints by default, --verbose prints too, with
        more: the same runs into two folders, read as one."""
        repo = Repository(self)
        folders = {name: repo.root / name for name in ("default", "verbose")}
        runs: dict[str, list] = {}
        for name, folder in folders.items():
            extra = ["--verbose"] if name == "verbose" else []
            base = ["--platform", "retroarch", "--dest", str(folder)]
            runs[name] = [self.run_line(repo, *base, "--yes", *extra)]
            # A later run replaces a changed file and keeps the old one.
            (folder / "md_eu.bin").write_bytes(b"changed")
            runs[name].append(self.run_line(repo, *base, "--yes", *extra))
            (folder / "md_eu.bin").write_bytes(b"changed")
            runs[name].append(self.run_line(repo, *base, "--check", *extra))

        def read(text: str, folder: Path) -> set:
            # The backup folder is named for the second it was made in.
            text = re.sub(r"retrobios-backup\S*", "retrobios-backup", text)
            return {line.strip().replace(str(folder), "<folder>")
                    for line in text.splitlines() if line.strip()}

        for index in range(3):
            with self.subTest(run=index):
                quiet, full = runs["default"][index], runs["verbose"][index]
                self.assertEqual(quiet.returncode, full.returncode, quiet.stdout + full.stdout)
                shown = read(quiet.stdout + quiet.stderr, folders["default"])
                said = read(full.stdout + full.stderr, folders["verbose"])
                self.assertLessEqual(shown, said, sorted(shown - said))
                self.assertGreater(len(said), len(shown))


if __name__ == "__main__":
    unittest.main()
