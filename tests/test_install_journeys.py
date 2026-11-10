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
# as ~/bios. With one setup found the screen opens on its plan: one key
# fewer, and one more for another device, whose Esc goes back to the
# setups. The second run of one system takes its install record's choice.
JOURNEY_KEYS = {
    "first_install": (1, 2),
    "card_with_games": (1, 2),
    "update": (1, 2),
    "one_system": (13, 14),
    "one_system_again": (1, 2),
    "what_is_missing": (4, 5),
    "another_device": (20, 21),
}

# Words each journey's screens show by default, summed over the screens it
# stops on, and the most one screen of the default path may show (owner,
# 2026-11-09: a beginner lost the important line in text). A path is no
# word: its length is the machine's. A change that adds words raises a
# number here and says why.
JOURNEY_WORDS = {
    "first_install": 47,
    "card_with_games": 87,
    "update": 70,
    "one_system": 179,
    "one_system_again": 67,
    "what_is_missing": 207,
    # The plan of the setup found comes first now (33 words), the setups
    # one Esc away, and the last plan names Change where (2 words).
    "another_device": 265,
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
    # After one system installed, the check counts the install record's
    # choice: one line says so, and how to count every file.
    "what_is_missing": (4, 25),
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
        # The one setup found: its plan first.
        screen = term.wait("files to download", timeout=40)
        self.assertIn("Change where", screen)
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
        # The next release changes its file: the plan opens on the same
        # choice, read from the install record, and one key installs it.
        changed = next(e for e in repo.listed["files"] if e["dest"] == "gba_bios.bin")
        changed["size"] += 1
        repo.write_list()
        term = self.start(repo)
        screen = term.wait("1 file to download", timeout=40)
        self.assertRegex(screen, r"Same choice as on \d+ [A-Z][a-z]{2}: yes")
        self.press(term, "\r")
        started = self.keys
        self.assertEqual(self.finish(term), 0)
        self.counted("one_system_again", started, self.keys)
        self.assertEqual(written(dest), ["gba_bios.bin"])
        self.assertEqual((dest / "gba_bios.bin").stat().st_size, changed["size"])

    def test_what_is_missing(self):
        repo = Repository(self)
        repo.retroarch_here()
        term = self.start(repo)
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
        # The plan of the one setup found first: Esc goes back to the setups.
        term.wait("files to download", timeout=40)
        self.press(term, ESC)
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

    def test_what_to_act_on_is_said_by_default(self):
        """A file an emulator needs that the collection lacks, a wrong copy
        and what becomes of it: said without --verbose (review of
        2026-11-10). The plain missing files wait on --verbose."""
        repo = Repository(self)
        repo.listed["omitted_files"] = [{"dest": "lost.bin", "name": "lost.bin",
                                         "system": "nintendo-gba", "systems": ["nintendo-gba"],
                                         "required": True, "reason": "not_found"}]
        repo.write_list()
        folder = repo.root / "dest"
        base = ["--platform", "retroarch", "--dest", str(folder)]
        needs = "1 file an emulator needs is not available here (--verbose names it)."
        proc = self.run_line(repo, *base, "--yes")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(needs, proc.stdout)
        (folder / "md_eu.bin").write_bytes(b"changed")
        (folder / "gba_bios.bin").unlink()
        proc = self.run_line(repo, *base, "--check")
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        self.assertIn("wrong copy: md_eu.bin", proc.stdout)
        self.assertIn("A wrong copy is replaced, and the one in place kept in "
                      "retrobios-backup", proc.stdout)
        self.assertIn(needs, proc.stdout)
        self.assertNotIn("missing: gba_bios.bin", proc.stdout)
        self.assertIn("missing: gba_bios.bin",
                      self.run_line(repo, *base, "--check", "--verbose").stdout)


def events(proc: subprocess.CompletedProcess, kind: str | None = None) -> list[dict]:
    said = [json.loads(line) for line in proc.stdout.splitlines() if line.startswith("{")]
    return [event for event in said if kind is None or event["event"] == kind]


class InstallRecord(unittest.TestCase):
    """What an install placed, recorded beside the BIOS folder, and its
    choice taken by the next run when nothing on the command line chose."""

    def setUp(self):
        self.repo = Repository(self)
        self.dest = self.repo.root / "retroarch" / "system"
        self.record = self.dest.parent / install.BACKUP_DIR / "system.install.json"

    def run_line(self, *args: str, dest: Path | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(REPO_ROOT / "install.py"), "--platform", "retroarch",
             "--dest", str(dest or self.dest), *args],
            env=self.repo.env, capture_output=True, text=True, timeout=120, check=False,
            stdin=subprocess.DEVNULL)

    def dests(self, proc: subprocess.CompletedProcess) -> list[str]:
        return sorted(event["dest"] for event in events(proc, "file"))

    def everything(self) -> list[str]:
        return sorted(entry["dest"] for entry in self.repo.listed["files"])

    def test_the_record_holds_each_file_written_and_its_hash(self):
        proc = self.run_line("--system", "nintendo-gba", "--yes", "--events")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        said = events(proc, "record")
        self.assertEqual([event["status"] for event in said], ["written"])
        self.assertEqual(said[0]["choice"], ["--system", "nintendo-gba"])
        self.assertEqual((said[0]["path"], said[0]["files"]), (str(self.record), 1))
        # Before the summary, its keys those of EVENT_KEYS.
        kinds = [event["event"] for event in events(proc)]
        self.assertEqual(kinds.index("record") + 1, kinds.index("summary"))
        self.assertEqual(list(said[0])[1:], list(install.EVENT_KEYS["record"]))
        kept = json.loads(self.record.read_text(encoding="utf-8"))
        files = kept["setups"]["retroarch"]["files"]
        self.assertEqual([item["dest"] for item in files], ["gba_bios.bin"])
        self.assertEqual(files[0]["sha1"], hashlib.sha1(
            (self.dest / "gba_bios.bin").read_bytes()).hexdigest())
        self.assertEqual((files[0]["from"], files[0]["root"]), ("download", ""))
        self.assertEqual(kept["folder"], str(self.dest))
        # Nothing of it in the BIOS folder, which some cores read whole.
        self.assertEqual(written(self.dest), ["gba_bios.bin"])

    def test_the_next_run_takes_the_recorded_choice(self):
        self.run_line("--system", "nintendo-gba", "--yes")
        (self.dest / "gba_bios.bin").unlink()
        proc = self.run_line("--yes", "--events")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        kinds = [event["event"] for event in events(proc)]
        self.assertLess(kinds.index("record"), kinds.index("choices"))
        applied = events(proc, "record")[0]
        self.assertEqual((applied["status"], applied["choice"]),
                         ("applied", ["--system", "nintendo-gba"]))
        self.assertEqual(self.dests(proc), ["gba_bios.bin"])
        self.assertEqual(written(self.dest), ["gba_bios.bin"])
        (self.dest / "gba_bios.bin").unlink()
        proc = self.run_line("--yes")
        self.assertRegex(proc.stdout, r"Installing 1 file \(.*\) for RetroArch, same choice "
                                      r"as on \d+ [A-Z][a-z]{2}\.")

    def test_the_command_line_replaces_the_record(self):
        self.run_line("--system", "nintendo-gba", "--yes")
        self.assertEqual(self.dests(self.run_line("--system", "sega-megadrive", "--check",
                                                  "--events")),
                         sorted(e["dest"] for e in self.repo.listed["files"]
                                if "sega-megadrive" in e.get("systems", [])))
        whole = self.run_line("--all-files", "--check", "--events")
        self.assertEqual(self.dests(whole), self.everything())
        self.assertEqual(events(whole, "record"), [])

    def test_a_record_that_cannot_be_read_is_said_once_and_ignored(self):
        self.dest.mkdir(parents=True)
        self.record.parent.mkdir()
        self.record.write_text("{not json", encoding="utf-8")
        proc = self.run_line("--yes", "--events")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        said = events(proc, "record")
        self.assertEqual([event["status"] for event in said], ["unreadable", "written"])
        self.assertIn("is damaged, so it is ignored.", said[0]["message"])
        # Said once to a person (standard error under --events), once as an event.
        self.assertEqual(proc.stderr.count("so it is ignored"), 1)
        self.assertEqual(self.dests(proc), self.everything())
        # Replaced by a record that reads.
        self.assertEqual(json.loads(self.record.read_text())["schema"], install.RECORD_SCHEMA)
        for text in ('{"schema": 99, "setups": {}}', '{"schema": 1, "setups": {"retroarch": 3}}',
                     "\xff\xfe"):
            with self.subTest(record=text):
                self.record.write_bytes(text.encode("latin-1"))
                proc = self.run_line("--check", "--events")
                self.assertEqual(events(proc, "record")[0]["status"], "unreadable")
                self.assertEqual(self.dests(proc), self.everything())

    def test_a_record_for_another_folder_is_not_applied(self):
        self.run_line("--system", "nintendo-gba", "--yes")
        # A sibling folder shares the holder, never the record.
        other = self.dest.parent / "bios"
        proc = self.run_line("--check", "--events", dest=other)
        self.assertEqual(events(proc, "record"), [])
        self.assertEqual(self.dests(proc), self.everything())
        # The record copied under the sibling's name still names the first.
        shutil.copy(self.record, self.record.with_name("bios.install.json"))
        proc = self.run_line("--check", "--events", dest=other)
        self.assertEqual(events(proc, "record"), [])
        self.assertEqual(self.dests(proc), self.everything())
        # The record of another setup in the same folder is not this one's.
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "install.py"), "--platform", "batocera",
             "--dest", str(self.dest), "--check", "--events"],
            env=self.repo.env, capture_output=True, text=True, timeout=120, check=False,
            stdin=subprocess.DEVNULL)
        self.assertEqual(events(proc, "record"), [])
        self.assertEqual(self.dests(proc), self.everything())

    def test_line_mode_chooses_what_the_screen_chooses(self):
        """The plan's choice from the record is the same set of files on the
        screen and in line mode: the screen's options, given to a run, and a
        run given none."""
        self.run_line("--system", "nintendo-gba", "--yes")
        (self.dest / "gba_bios.bin").unlink()
        state = install.TuiState()
        state.platform, state.dest = "retroarch", self.dest
        install._tui_record_load(state)
        self.assertTrue(install.tui_record_kept(state))
        flags = [flag if value is None else f"{flag}={value}"
                 for flag, value in install.tui_flags(state)]
        screen = self.run_line(*flags, "--dry-run", "--events")
        line = self.run_line("--dry-run", "--events")
        self.assertEqual(self.dests(screen), ["gba_bios.bin"])
        self.assertEqual(self.dests(line), self.dests(screen))
        self.assertEqual(events(line, "check")[0]["bytes_needed"],
                         events(screen, "check")[0]["bytes_needed"])


if __name__ == "__main__":
    unittest.main()
