"""The real install.py --tui on a pseudo-terminal, read back with pyte, against a
loopback copy of the repository. Skips when pyte is not installed (CI installs it)."""

from __future__ import annotations

import tests
from tests import loopback

import functools
import hashlib
import http.server
import json
import os
import re
import select
import shlex
import sys
import termios
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import install
from tests.test_install_selection import FakeRepository
from tests.netguard import module_guard
from tests.tuisupport import (
    DOWN, fresh_state, HOME, Pty, pty, pyte, REPO_ROOT, RIGHT, SaveDirectoryRepository, sgr,
    _terminfo_folder, UP, x10,
)


# No connection off the loopback and no card of the host reaches a test,
# in this process or one it starts: the module fails at its end when one is tried.
setUpModule, tearDownModule = module_guard("test_tui_pty")


# --- End to end, on a pseudo-terminal -------------------------------------


def on_setups(term: Pty) -> str:
    """The setups found, one Back from the plan the screen opens on when it
    found one setup: the first screen as it was before."""
    term.wait("> Install")
    term.send("\x1b")
    return term.wait("Where to install?")


class _SlowHandler(loopback.Quiet):
    """Serves each file after a pause, so a test can stop a download midway."""

    def do_GET(self) -> None:
        if self.path.startswith("/bios/"):
            time.sleep(0.6)
        super().do_GET()


class GameDataRepository(FakeRepository):
    """The fake repository with a categorized list and one slow file per file."""

    def __init__(self, slow: bool = False) -> None:
        super().__init__()
        self.slow = slow

    def __enter__(self) -> GameDataRepository:
        super().__enter__()
        path = self.root / "install" / "retroarch.json"
        manifest = json.loads(path.read_text())
        manifest["categorized"] = True
        payload = b"a game's data"
        (self.root / "bios" / "game.dat").write_bytes(payload)
        manifest["files"].append({
            "dest": "game.dat", "sha1": hashlib.sha1(payload).hexdigest(),
            "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload),
            "repo_path": "bios/game.dat", "cores": None, "systems": ["nintendo-gba"],
            "category": "game_data"})
        path.write_text(json.dumps(manifest))
        if self.slow:
            self.httpd.shutdown()
            self.httpd.server_close()
            handler = functools.partial(_SlowHandler, directory=str(self.root))
            self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
            threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return self


@unittest.skipUnless(pyte and pty and hasattr(pty, "fork"),
                     "screen tests need pyte (pip install pyte==0.8.2) and a pty")
class EndToEnd(unittest.TestCase):
    """The real install.py --tui, keys in and screens out."""

    def repo(self, cls=FakeRepository, **options) -> FakeRepository:
        repo = cls(**options)
        repo.__enter__()
        self.addCleanup(repo.__exit__, None, None, None)
        home = repo.root / "home"
        cfg = home / ".config" / "retroarch"
        cfg.mkdir(parents=True)
        repo.dest.mkdir()
        (cfg / "retroarch.cfg").write_text(f'system_directory = "{repo.dest}"\n')
        self.env = {**repo.env(), "HOME": str(home), "TERM": "xterm",
                    "RETROBIOS_OS": "linux", "XDG_CONFIG_HOME": str(home / ".config")}
        self.env.pop("NO_COLOR", None)
        # Whatever the shell running the tests has, the input is not known:
        # the bar names both the button and the key. Each test names its own.
        for name in ("DISPLAY", "WAYLAND_DISPLAY", "SSH_CONNECTION", "SSH_TTY",
                     install.TUI_PAD_ENV, *install._STEAM_MARKERS):
            self.env.pop(name, None)
        return repo

    def start(self, *args: str, cols: int = 80, rows: int = 24) -> Pty:
        term = Pty(list(args), self.env, cols, rows)
        self.addCleanup(lambda: term.status is None and os.kill(term.pid, 9))
        return term


    def card_repo(self, system: str) -> tuple[Path, Path]:
        from tests.test_install_app import AppRepository, make_card

        repo = self.repo(AppRepository)
        root = repo.root / "card"
        return root, make_card(root, system)

    def assertAppOnCard(self, root: Path, system: str) -> None:
        index = json.loads((REPO_ROOT / "install" / "launchers" / "index.json").read_text())
        targets = install.app_targets(index, install.APP_PLACES[system])
        for target in targets:
            data = (root / target["dest"]).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), target["sha256"],
                             target["dest"])

    def test_put_the_app_on_a_muos_card_from_the_result(self):
        root, bios = self.card_repo("muOS")
        term = self.start("--platform", "retroarch", "--dest", str(root))
        term.wait("files to download")
        term.send("\r")
        screen = term.wait(install.APP_OFFER)
        self.assertIn("> Exit", screen)
        term.send(DOWN, "\r")
        screen = term.wait("RetroBIOS is on the muOS card")
        self.assertIn("Archive Manager", screen)
        term.send("\r")
        self.assertEqual(term.close(), 0)
        self.assertAppOnCard(root, "muOS")
        self.assertEqual(len(list(bios.iterdir())), 5)
        self.assertIn("RetroBIOS is on the muOS card", term.after())

    def test_put_the_app_on_a_knulli_card_from_the_options(self):
        root, _bios = self.card_repo("KNULLI")
        term = self.start("--platform", "knulli", "--dest", str(root))
        term.wait("files to download")
        term.send("o")
        term.wait("RetroBIOS: Change")
        for _step in range(20):
            if "> Put RetroBIOS on this card: no" in term.settle():
                break
            term.send(DOWN)
        term.send("\r")
        term.wait("> Put RetroBIOS on this card: yes")
        term.send("\x1b")
        term.wait("files to download")
        term.send("\r")
        screen = term.wait("RetroBIOS is on the KNULLI card")
        self.assertIn("start RetroBIOS from Ports", screen)
        self.assertNotIn(install.APP_OFFER, screen)
        # The command, a Details line, is said after Exit once they were opened.
        term.send("d")
        term.wait("RetroBIOS: Details")
        term.send("\x1b")
        term.wait("RetroBIOS is on the KNULLI card")
        term.send("\r")
        self.assertEqual(term.close(), 0)
        self.assertAppOnCard(root, "KNULLI")
        self.assertIn("--add-app", term.after())

    def test_two_presses_install_everything(self):
        repo = self.repo()
        term = self.start()
        # The one setup found here: its plan first.
        screen = term.wait("files to download")
        self.assertIn("5 files to download, 30 B", screen)
        self.assertIn("Change where", screen)
        self.assertIn("> Install", screen)
        term.send("\r")
        term.wait("5 files installed.")
        term.send("\r")
        self.assertEqual(term.close(), 0)
        self.assertEqual(len(repo.installed()), 5)
        after = term.after()
        self.assertIn("RetroBIOS: Done", after)
        self.assertIn("5 files installed.", after)
        # The command is a Details line: said after Exit once they were opened.
        self.assertIn("Next: start RetroArch and play.", after)
        self.assertNotIn("--platform retroarch --dest", after)
        # The cursor and the main screen come back before the result is printed.
        self.assertIn(b"\x1b[?25h\x1b[?1049l", term.raw)

    def test_the_save_directory_is_the_one_line_mode_finds(self):
        """The interface named the BIOS folder with --dest, so its runs never
        read retroarch.cfg: keys.txt went to a guessed RetroArch/saves, or
        was dropped without a word, where line mode writes it to the
        savefile_directory RetroArch reads."""
        import subprocess

        def written(repo, saves: Path) -> list[str]:
            return sorted([*repo.installed(), *(
                "saves/" + p.relative_to(saves).as_posix()
                for p in saves.rglob("*") if p.is_file())])

        results = []
        for mode in ("line", "interface"):
            with self.subTest(mode=mode):
                repo = self.repo(SaveDirectoryRepository)
                home = Path(self.env["HOME"])
                saves = home / "MySaves"
                saves.mkdir()
                cfg = home / ".config" / "retroarch" / "retroarch.cfg"
                cfg.write_text(f'system_directory = "{repo.dest}"\n'
                               f'savefile_directory = "{saves}"\n')
                if mode == "line":
                    proc = subprocess.run(
                        [sys.executable, str(REPO_ROOT / "install.py"), "--platform",
                         "retroarch", "--yes"], env=self.env, capture_output=True,
                        text=True, timeout=60, check=False, stdin=subprocess.DEVNULL)
                    self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                    self.assertIn("6 files installed", proc.stdout)
                else:
                    term = self.start()
                    screen = term.wait("files to download")
                    self.assertIn("6 files to download", screen)
                    # The second folder the run writes to, named on the
                    # plan's Details before anything is written, and on the
                    # result's.
                    term.send("d")
                    screen = term.wait("RetroBIOS: Details")
                    self.assertIn("1 file read from RetroArch's save directory goes to a "
                                  "folder per core under:\n   ~/MySaves", screen)
                    term.send("\x1b")
                    term.wait("files to download")
                    term.send("\r")
                    term.wait("6 files installed.")
                    term.send("d")
                    screen = term.wait("RetroBIOS: Details")
                    # Spelled in full on the result, as its other folders.
                    joined = "".join(line.strip() for line in screen.splitlines())
                    self.assertIn("folder per core under:" + str(saves), joined)
                    term.send("\x1b")
                    term.wait("6 files installed.")
                    term.send("\r")
                    self.assertEqual(term.close(), 0)
                results.append(written(repo, saves))
                self.assertIn("saves/Azahar/Azahar/sysdata/keys.txt", results[-1])
        self.assertEqual(results[0], results[1])

    def test_one_system_from_the_checklist(self):
        repo = self.repo()
        term = self.start("--platform", "retroarch", "--dest", str(repo.dest), cols=40, rows=15)
        term.wait("> Install")
        term.send(DOWN, "\r")
        term.wait("Choose systems")
        # D-pad and A only: the list opens on its first system, A unticks
        # it, B goes back to the plan.
        term.send("\r")
        screen = term.wait("1 of 2 systems")
        self.assertIn("> [ ] nintendo-gba", screen)
        self.assertIn("[x] sony-playstation", screen)
        term.send("\x1b")
        term.wait("About 3 files")
        # Install counts the choice on Confirm first.
        term.send("\r")
        screen = term.wait("files to download")
        self.assertIn("3 files to download", screen)
        term.send("\r")
        term.wait("3 files installed.")
        term.send("d")
        term.wait("RetroBIOS: Details")
        term.send("\x1b")
        term.wait("3 files installed.")
        term.send("\r")
        self.assertEqual(term.close(), 0)
        self.assertEqual(repo.installed(), ["pcsx/extra.bin", "scph5500.bin", "scph5501.bin"])
        self.assertIn("--system sony-playstation", term.after().replace("\n", " "))

    def test_options_region_and_game_data(self):
        repo = self.repo(GameDataRepository)
        term = self.start("--platform", "retroarch", "--dest", str(repo.dest))
        term.wait("6 files to download")
        term.send("o")
        screen = term.wait("RetroBIOS: Change")
        self.assertIn("--no-game-data", screen)
        term.send("\r")
        term.wait("Preferred regions")
        term.send(DOWN, "\r", "\x1b")
        screen = term.wait("Preferred regions: North America")
        for _step in range(8):
            if "> Game data: kept" in term.settle():
                break
            term.send(DOWN)
        term.send(RIGHT, "\x1b")
        # Back on the plan, the check runs again under the new options.
        screen = term.wait("4 files to download")
        self.assertIn("> Install", screen)
        term.send("\r")
        term.wait("installed.")
        term.send("o")
        screen = term.wait("RetroBIOS: Details")
        self.assertIn("1 game data file left out.", screen)
        term.send("\r")
        term.wait("installed.")
        term.send("\r")
        self.assertEqual(term.close(), 0)
        self.assertEqual(repo.installed(), ["gba_bios.bin", "mgba/extra.bin",
                                            "pcsx/extra.bin", "scph5501.bin"])

    def test_preview_writes_nothing(self):
        repo = self.repo()
        term = self.start("--platform", "retroarch", "--dest", str(repo.dest))
        term.wait("> Install")
        term.send("o", "G", UP, "\r")
        screen = term.wait("Nothing is written.")
        self.assertIn("missing", screen)
        self.assertIn("scph5501.bin", screen)
        term.send("\x1b", "\x1b", "q")
        self.assertEqual(term.close(), install.QUIT_CODE)
        self.assertEqual(repo.installed(), [])
        self.assertIn("Nothing was installed.", term.after())

    def test_ctrl_c_during_the_download(self):
        repo = self.repo(GameDataRepository, slow=True)
        term = self.start("--platform", "retroarch", "--dest", str(repo.dest), "--jobs", "1")
        term.wait("> Install")
        term.send("\r")
        term.wait("1 of 6 files")
        term.send("\x03")
        screen = term.wait("Stopped:")
        term.send("\r")
        self.assertEqual(term.close(), 130)
        # The count said is the count on disk: "6 of 6" after a stop at 1
        # passed a regex and was false.
        on_disk = len(repo.installed())
        self.assertLess(on_disk, 6)
        self.assertIn(f"Stopped: {on_disk} of 6 installed, run again to finish.", screen)
        self.assertIn(f"Stopped: {on_disk} of 6 installed", term.after())

    def test_sigterm_during_the_download_is_a_stop(self):
        """Start+Select on a handheld is gptokeyb's pkill: SIGTERM, SIGKILL 3 s on."""
        import signal

        repo = self.repo(GameDataRepository, slow=True)
        term = self.start("--platform", "retroarch", "--dest", str(repo.dest), "--jobs", "1")
        term.wait("> Install")
        term.send("\r")
        term.wait("1 of 6 files")
        started = time.monotonic()
        os.kill(term.pid, signal.SIGTERM)
        code = term.close()
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual(code, 130)
        on_disk = len(repo.installed())
        self.assertGreaterEqual(on_disk, 1)
        after = term.after()
        self.assertIn(f"Stopped: {on_disk} of 6 installed, run again to finish.", after)
        self.assertNotIn("Nothing was installed", after)
        # The plain outcome only: the log's last lines are for a run that died.
        self.assertIsNone(re.search(r"\[\d+/6\]", after), after)
        self.assertNotIn("Stopping.", after)
        time.sleep(1)
        self.assertEqual(len(repo.installed()), on_disk)

    def test_copy_from_an_old_card(self):
        repo = self.repo()
        old = Path(self.env["HOME"]) / "oldcard"
        (old / "bios").mkdir(parents=True)
        for name in ("scph5500.bin", "scph5501.bin", "gba_bios.bin"):
            payload = FakeRepository.PAYLOADS[name][0]
            (old / "bios" / name).write_bytes(payload)
        term = self.start("--platform", "retroarch", "--dest", str(repo.dest))
        term.wait("5 files to download")
        term.send(DOWN, DOWN, "\r")
        term.wait("Choose the old card")
        for _ in range(12):
            if "> oldcard/" in term.settle():
                break
            term.send(DOWN)
        self.assertIn("> oldcard/", term.settle())
        term.send("\r")
        term.wait("> Use this folder")
        term.send("\r")
        screen = term.wait("found in")
        # The folder wraps at a slash: compared without the spaces.
        self.assertIn("3 found in oldcard, 2 to download (8 B)", screen)
        # Checked again, the plan opens on Install.
        term.send("\r")
        screen = term.wait("files installed.")
        # Where each came from, as the line mode says it.
        self.assertIn("5 files installed.", screen)
        self.assertIn("3 files copied from", screen)
        self.assertIn("2 downloaded.", screen)
        term.send("o")
        term.wait("RetroBIOS: Details")
        term.send("\r")
        term.wait("files installed.")
        term.send("\r")
        self.assertEqual(term.close(), 0)
        self.assertEqual(len(repo.installed()), 5)
        self.assertIn(f"--from {old}", term.after().replace("\n", " "))

    def test_ctrl_c_on_the_first_screen(self):
        self.repo()
        term = self.start()
        term.wait("> Install")
        term.send("\x03")
        self.assertEqual(term.close(), 130)
        self.assertIn(b"\x1b[?2004l\x1b[0m\x1b[?25h\x1b[?1049l", term.raw)

    def test_a_stop_from_outside_gives_the_terminal_back(self):
        import signal

        self.repo()
        term = self.start()
        term.wait("> Install")
        mark = len(term.raw)
        os.kill(term.pid, signal.SIGTSTP)
        end = time.monotonic() + 10
        stopped = False
        while time.monotonic() < end and not stopped:
            term._pump(0.05)
            pid, status = os.waitpid(term.pid, os.WNOHANG | os.WUNTRACED)
            stopped = bool(pid) and os.WIFSTOPPED(status)
        self.assertTrue(stopped)
        self.assertIn(b"\x1b[?25h\x1b[?1049l", term.raw[mark:])
        mark = len(term.raw)
        os.kill(term.pid, signal.SIGCONT)
        term.wait("A/Enter Install")
        end = time.monotonic() + 5
        while b"\x1b[?1049h" not in term.raw[mark:] and time.monotonic() < end:
            term._pump(0.05)
        self.assertIn(b"\x1b[?1049h", term.raw[mark:])
        term.send("q")
        self.assertEqual(term.close(), install.QUIT_CODE)

    def test_closing_the_window_ends_with_its_signal(self):
        """The terminal gone, the farewell has nowhere to go: the code is
        129 (SIGHUP), not 120 from the flush failing at exit."""
        self.repo()
        for screen_name, keys_first in (("files to download", ()),
                                        ("Where to install?", ("\x1b",))):
            with self.subTest(screen=screen_name):
                term = self.start()
                term.wait("files to download")
                term.send(*keys_first)
                term.wait(screen_name)
                os.close(term.fd)
                end = time.monotonic() + 20
                status = None
                while time.monotonic() < end:
                    pid, status = os.waitpid(term.pid, os.WNOHANG)
                    if pid:
                        break
                    time.sleep(0.05)
                else:
                    os.kill(term.pid, 9)
                    self.fail("still running once its window closed")
                term.status = os.WEXITSTATUS(status)
                self.assertTrue(os.WIFEXITED(status))
                self.assertEqual(term.status, 129)

    def test_closing_the_window_while_it_installs(self):
        """The changing screen fails to draw on the closed window: that is
        the window's signal, not a crash with a log kept."""
        repo = self.repo(GameDataRepository, slow=True)
        scratch = repo.root / "scratch"
        scratch.mkdir()
        self.env["TMPDIR"] = str(scratch)
        term = self.start("--platform", "retroarch", "--dest", str(repo.dest), "--jobs", "1")
        term.wait("> Install")
        term.send("\r")
        term.wait("1 of 6 files")
        os.close(term.fd)
        end = time.monotonic() + 20
        while time.monotonic() < end:
            pid, status = os.waitpid(term.pid, os.WNOHANG)
            if pid:
                break
            time.sleep(0.05)
        else:
            os.kill(term.pid, 9)
            self.fail("still running once its window closed")
        term.status = os.WEXITSTATUS(status)
        self.assertEqual(term.status, 129)
        self.assertEqual(list(scratch.glob("retrobios-tui-*/error.log")), [])

    def test_no_key_on_the_first_screen_closes_it(self):
        """A mapper that never opens the pad left the first screen up for
        good: a handheld then has no way out but the power button."""
        self.repo()
        self.env[install.TUI_IDLE_ENV] = "1"
        term = self.start()
        term.wait("> Install")
        self.assertEqual(term.close(), install.QUIT_CODE)
        self.assertIn("No button pressed, closing.", term.after())
        # A key pressed, the screen stays: the person is there.
        term = self.start()
        term.wait("> Install")
        term.send(DOWN)
        end = time.monotonic() + 2.5
        while time.monotonic() < end:
            term._pump(0.05)
        self.assertEqual(os.waitpid(term.pid, os.WNOHANG), (0, 0))
        term.send("q")
        self.assertEqual(term.close(), install.QUIT_CODE)

    def test_no_key_on_a_screen_reached_by_itself_closes_it(self):
        """Given --platform, as the offline launcher route is, the check
        runs at once and the plan follows without a key: the close counted
        only on the first screen, and never came."""
        repo = self.repo()
        self.env[install.TUI_IDLE_ENV] = "1"
        term = self.start("--platform", "retroarch", "--dest", str(repo.dest))
        term.wait("> Install")
        self.assertEqual(term.close(), install.QUIT_CODE)
        self.assertIn("No button pressed, closing.", term.after())
        self.assertEqual(repo.installed(), [])

    def test_a_desktop_names_its_keys_and_a_pad_its_buttons(self):
        self.repo()
        for env, bar in (({"DISPLAY": ":0"}, "Enter Continue  Esc Quit  ? Help"),
                         ({"RETROBIOS_PAD": "gptokeyb", "DISPLAY": ":0"},
                          "A Continue  B Quit"),
                         ({"RETROBIOS_PAD": "muxterm"}, "Start Continue  B Quit")):
            with self.subTest(env=env):
                self.env.update(env)
                term = self.start(cols=40, rows=12)
                on_setups(term)
                screen = term.wait(bar)
                self.assertEqual(screen.splitlines()[-1].strip(), bar)
                term.send("q")
                self.assertEqual(term.close(), install.QUIT_CODE)
                for name in env:
                    self.env.pop(name)

    def test_resize_redraws(self):
        self.repo()
        term = self.start(cols=40, rows=15)
        on_setups(term)
        term.resize(100, 30)
        term.send(DOWN)
        screen = term.wait("> Another setup or folder")
        self.assertIn("B/Esc Quit", screen.splitlines()[29])
        term.resize(30, 10)
        term.wait("40x12 or more, now 30x10")
        term.resize(40, 12)
        term.wait("Where to install?")
        term.send("q")
        self.assertEqual(term.close(), install.QUIT_CODE)

    def test_plain_mode_keeps_the_line_questions(self):
        self.repo()
        for env in ({"RETROBIOS_PLAIN": "1"}, {"ACCESSIBLE": "1"}):
            with self.subTest(env=env):
                self.env.update(env)
                term = self.start()
                # The setup found is asked as the screen asks it.
                term.wait("Enter for RetroArch")
                term.send("\r")
                term.wait("Enter) install everything")
                term.send("q\r")
                term.close()
                self.assertNotIn(b"\x1b[?1049h", term.raw)
                for name in env:
                    self.env.pop(name)

    def test_dumb_terminal_writes_no_escape(self):
        """TERM unset printed the banner bold and dim, and redrew the
        progress with CSI, where the screen itself read it as dumb."""
        self.repo()
        for value in ("dumb", None):
            with self.subTest(term=value):
                if value is None:
                    self.env.pop("TERM", None)
                else:
                    self.env["TERM"] = value
                term = self.start()
                term.wait("Enter for RetroArch")
                term.send("\r")
                if value is None:
                    # In place since the first run: no menu, nothing asked.
                    term.wait("every one in place: nothing to install")
                else:
                    term.wait("Enter) install everything")
                    term.send("\r")
                term.wait("Done.")
                term.close()
                self.assertNotIn(b"\x1b", term.raw)

    def test_a_terminal_that_cannot_draw_the_screen_gets_the_questions(self):
        """TERM=vt52 moves the cursor with ESC Y: the screen opened and drew
        CSI sequences it printed as text."""
        self.repo()
        self.env["TERMINFO"] = str(_terminfo_folder(self))
        for name in ("rbtest-glass", "rbtest-vt52"):
            with self.subTest(term=name):
                self.env["TERM"] = name
                term = self.start()
                term.wait("Enter for RetroArch")
                term.send("\r")
                term.wait("Enter) install everything")
                term.send("q\r")
                term.close()
                self.assertNotIn(b"\x1b[?1049h", term.raw)
                term = self.start("--tui")
                self.assertEqual(term.close(), 2)
                said = term.raw.decode()
                self.assertIn(f"--tui cannot open the full-screen interface here: TERM={name}",
                              said)
                self.assertNotIn("\x1b", said)

    def test_no_color_draws_no_colour(self):
        """The screen marks the row in focus with > as well as reverse video,
        so NO_COLOR, or a terminal of fewer than 8 colours, takes the colour
        away and leaves the same screen."""
        self.repo()
        screens = {}
        for name, env in (("colour", {}), ("no_color", {"NO_COLOR": "1"}),
                          ("mono", {"TERM": "rbtest-mono",
                                    "TERMINFO": str(_terminfo_folder(self))})):
            with self.subTest(env=name):
                self.env.pop("NO_COLOR", None)
                self.env.update({"TERM": "xterm", **env})
                term = self.start()
                screen = on_setups(term)
                self.assertIn("> RetroArch", screen)
                screens[name] = screen
                # pyte reads the colours drawn: RetroBIOS in the accent.
                title = term.screen.buffer[0]
                at = screen.splitlines()[0].index("RetroBIOS")
                self.assertEqual(title[at].fg, "magenta" if name == "colour" else "default")
                term.send("q")
                self.assertEqual(term.close(), install.QUIT_CODE)
                colours = set()
                for params in re.findall(rb"\x1b\[([0-9;]*)m", term.raw):
                    colours |= {int(code) for code in params.split(b";") if code} & {
                        *range(30, 50), *range(90, 108)}
                self.assertEqual(bool(colours), name == "colour", colours)
        self.assertEqual(screens["colour"], screens["no_color"])
        self.assertEqual(screens["colour"], screens["mono"])


@unittest.skipUnless(pyte and pty and hasattr(pty, "fork"),
                     "screen tests need pyte (pip install pyte==0.8.2) and a pty")
class TheTerminalComesBack(unittest.TestCase):
    """However the screen ends or pauses, the terminal is handed back as it
    was lent: the cursor shown, the main screen, echo, lines and signals."""

    repo = EndToEnd.repo
    start = EndToEnd.start

    # What a new pseudo-terminal has, which the child started on.
    @staticmethod
    def fresh_modes() -> list:
        master, slave = os.openpty()
        try:
            return termios.tcgetattr(slave)
        finally:
            os.close(master)
            os.close(slave)

    def assertGivenBack(self, term: Pty, since: int = 0) -> None:
        raw = term.raw[since:]
        self.assertGreater(raw.rfind(b"\x1b[?1049l"), raw.rfind(b"\x1b[?1049h"), raw[-200:])
        self.assertGreater(raw.rfind(b"\x1b[?25h"), raw.rfind(b"\x1b[?25l"), raw[-200:])
        # Clicks are given back too: a shell left with them on reads each
        # one as a line of escape bytes.
        for mode in (b"1000", b"1006"):
            self.assertGreater(raw.rfind(b"\x1b[?" + mode + b"l"),
                               raw.rfind(b"\x1b[?" + mode + b"h"), raw[-200:])
        self.assertNotIn(b"\x1b[?1003h", raw)

    def assertModesBack(self, modes: list) -> None:
        fresh = self.fresh_modes()
        for index, flag in ((3, termios.ECHO), (3, termios.ICANON), (3, termios.ISIG),
                            (3, termios.IEXTEN), (0, termios.ICRNL), (0, termios.IXON)):
            self.assertEqual(modes[index] & flag, fresh[index] & flag, (index, flag))
        self.assertEqual(modes, fresh)

    def ended(self, how) -> Pty:
        self.repo()
        term = self.start()
        term.wait("> Install")
        # Every way out below starts with the clicks asked for, written
        # right after the frame.
        term.settle()
        self.assertIn(install._MOUSE_ON.encode(), term.raw)
        how(term)
        return term

    def test_ctrl_c(self):
        term = self.ended(lambda term: term.send("\x03"))
        self.assertEqual(term.close(), 130)
        self.assertGivenBack(term)
        self.assertModesBack(term.modes)

    def test_eof_on_stdin(self):
        """Ctrl-D, the terminal's end of input, typed at the screen."""
        term = self.ended(lambda term: term.send("\x04"))
        self.assertEqual(term.close(), 130)
        self.assertGivenBack(term)
        self.assertModesBack(term.modes)

    def test_sigterm(self):
        import signal

        term = self.ended(lambda term: os.kill(term.pid, signal.SIGTERM))
        self.assertEqual(term.close(), 128 + signal.SIGTERM)
        self.assertGivenBack(term)
        self.assertModesBack(term.modes)

    def test_sighup(self):
        """The hangup without the window gone (kill -HUP, an ssh session
        dropped while its pty lingers)."""
        import signal

        term = self.ended(lambda term: os.kill(term.pid, signal.SIGHUP))
        self.assertEqual(term.close(), 128 + signal.SIGHUP)
        self.assertGivenBack(term)
        self.assertModesBack(term.modes)

    def shell(self) -> Pty:
        """An interactive bash on a pseudo-terminal, a shell with job control
        as a person's terminal runs one."""
        self.repo()
        env = {**self.env, "PS1": "PROMPT$ ",
               "PATH": f"{Path(sys.executable).parent}{os.pathsep}{self.env.get('PATH', '')}"}
        term = Pty(["--norc", "--noprofile", "-i"], env, program=["/bin/bash"])
        self.addCleanup(lambda: term.status is None and os.killpg(term.pid, 9))
        term.wait("PROMPT$")
        return term

    def typed(self, term: Pty, line: str) -> None:
        os.write(term.fd, line.encode() + b"\r")

    @unittest.skipUnless(Path("/bin/bash").exists(), "a shell with job control")
    def test_ctrl_z_then_fg(self):
        """ISIG is off on the screen, so Ctrl-Z reached it as a byte and did
        nothing: the shell never got its terminal back. From a shell with
        job control it stops, and fg brings the screen back."""
        term = self.shell()
        self.typed(term, f"{shlex.quote(sys.executable)} {REPO_ROOT / 'install.py'} --tui")
        term.wait("> Install")
        mark = len(term.raw)
        term.send("\x1a")
        end = time.monotonic() + 10
        while b"PROMPT$" not in term.raw[mark:] and time.monotonic() < end:
            term._pump(0.05)
        self.assertIn(b"Stopped", term.raw[mark:], term.raw[mark:][-300:])
        self.assertGivenBack(term, mark)
        # fg: the shell's SIGCONT, and the screen is back, raw again.
        mark = len(term.raw)
        self.typed(term, "fg")
        end = time.monotonic() + 5
        while b"\x1b[?1049h" not in term.raw[mark:] and time.monotonic() < end:
            term._pump(0.05)
        self.assertIn(b"\x1b[?1049h", term.raw[mark:])
        term.wait("> Install")
        self.assertFalse(termios.tcgetattr(term.fd)[3] & termios.ECHO)
        # The clicks come back with the screen.
        term.settle()
        self.assertIn(install._MOUSE_ON.encode(), term.raw[mark:])
        term.send("q")
        term.wait("PROMPT$")
        self.typed(term, "exit")
        self.assertEqual(term.close(), install.QUIT_CODE)
        self.assertGivenBack(term)

    def test_ctrl_z_with_no_shell_to_resume_it_is_ignored(self):
        """Started straight on a terminal (a terminal
        app's -e, a desktop entry) or under a launcher's sh -c, nothing ever
        resumed the screen a Ctrl-Z stopped. It now goes on, and says why."""
        self.repo()
        for program in (None, ["/bin/sh", "-c", f"{shlex.quote(sys.executable)} "
                                                f"{REPO_ROOT / 'install.py'} \"$@\"", "sh"]):
            with self.subTest(program=program):
                term = Pty(["--tui"], self.env, program=program)
                self.addCleanup(lambda term=term: term.status is None
                                and os.killpg(term.pid, 9))
                term.wait("> Install")
                term.send("\x1a")
                screen = term.wait("Ctrl-Z is ignored")
                self.assertIn("no shell started this installer", " ".join(screen.split()))
                pid, status = os.waitpid(term.pid, os.WNOHANG | os.WUNTRACED)
                self.assertEqual(pid, 0, "stopped")
                term.send("q")
                self.assertEqual(term.close(), install.QUIT_CODE)
                self.assertGivenBack(term)

    def test_ctrl_z_needs_a_shell_that_can_resume(self):
        state = install.TuiState(os_type="linux", home=HOME)
        with mock.patch.object(install.os, "getpgrp", return_value=10), \
                mock.patch.object(install.os, "getsid", return_value=10):
            self.assertFalse(install.tui_ctrl_z(state))
        self.assertEqual(state.status, install.CTRL_Z_NO_SHELL)
        state.status = ""
        with mock.patch.object(install.os, "getpgrp", return_value=12), \
                mock.patch.object(install.os, "getsid", return_value=10):
            self.assertTrue(install.tui_ctrl_z(state))
        self.assertEqual(state.status, "")

    @staticmethod
    def proc_state(pid: int) -> str:
        """The state letter Linux gives a process (T is stopped)."""
        text = Path(f"/proc/{pid}/stat").read_text()
        return text[text.rindex(")") + 2]

    @staticmethod
    def children(pid: int) -> list[int]:
        found = []
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                text = (entry / "stat").read_text()
            except OSError:
                continue
            if int(text[text.rindex(")") + 2:].split()[1]) == pid:
                found.append(int(entry.name))
        return found

    @unittest.skipUnless(Path("/proc/self/stat").exists(), "reads process states in /proc")
    def test_ctrl_z_through_install_sh_stops_the_wrapper_and_the_install(self):
        """Ctrl-Z stopped the installer alone. install.sh,
        which runs it as a child, kept waiting, the shell never got its prompt
        back, and the install run behind the screen kept writing."""
        repo = self.repo(GameDataRepository, slow=True)
        env = {**self.env, "PS1": "PROMPT$ ",
               "PATH": f"{Path(sys.executable).parent}{os.pathsep}{self.env['PATH']}"}
        # Typed at an interactive bash, as a person runs it: install.sh is a
        # job of a shell that can resume it.
        term = Pty(["--norc", "--noprofile", "-i"], env, program=["/bin/bash"])
        self.addCleanup(lambda: term.status is None and os.killpg(term.pid, 9))
        term.wait("PROMPT$")
        self.typed(term, f"sh {REPO_ROOT / 'install.sh'} --jobs 1")
        term.wait("to download")
        term.send("\r")
        term.wait("Installing")
        time.sleep(0.8)
        wrapper = self.children(term.pid)
        self.assertEqual(len(wrapper), 1, wrapper)
        installer = self.children(wrapper[0])
        self.assertEqual(len(installer), 1, installer)
        runs = self.children(installer[0])
        self.assertTrue(runs, "no install run")
        mark = len(term.raw)
        term.send("\x1a")
        end = time.monotonic() + 10
        while b"PROMPT$" not in term.raw[mark:] and time.monotonic() < end:
            term._pump(0.05)
        # The wrapper is stopped: the shell reports its job stopped.
        self.assertIn(b"Stopped", term.raw[mark:], term.raw[mark:][-300:])
        self.assertEqual(self.proc_state(wrapper[0]), "T")
        self.assertEqual(self.proc_state(installer[0]), "T")
        self.assertEqual([self.proc_state(run) for run in runs], ["T"] * len(runs))
        written = sorted(repo.dest.rglob("*"))
        time.sleep(2)
        self.assertEqual(sorted(repo.dest.rglob("*")), written)
        # fg continues the job's group: the screen comes back and the install
        # carries on to its end.
        mark = len(term.raw)
        self.typed(term, "fg")
        end = time.monotonic() + 5
        while b"\x1b[?1049h" not in term.raw[mark:] and time.monotonic() < end:
            term._pump(0.05)
        self.assertIn(b"\x1b[?1049h", term.raw[mark:])
        term.wait("files installed", timeout=30)
        term.send("\r")
        term.wait("PROMPT$")
        self.typed(term, "exit")
        self.assertEqual(term.close(), 0)


@unittest.skipUnless(pyte and pty and hasattr(pty, "fork"),
                     "screen tests need pyte (pip install pyte==0.8.2) and a pty")
class MouseOnAPty(unittest.TestCase):
    """The real install.py --tui, clicked through a pseudo-terminal."""

    repo = EndToEnd.repo
    start = EndToEnd.start

    @staticmethod
    def line_of(term: Pty, needle: str) -> int:
        return next(index for index, line in enumerate(term.screen.display) if needle in line)

    def click(self, term: Pty, col: int, row: int) -> None:
        # A deliberate tap, after the screen settled: a press sooner is the
        # second of a double tap on the screen before.
        time.sleep(install.TUI_TAP_SETTLE)
        term.send(sgr(col + 1, row + 1), sgr(col + 1, row + 1, release=True))

    def test_taps_choose_a_row_and_press_the_bar(self):
        self.repo()
        term = self.start()
        on_setups(term)
        term.settle()
        self.assertIn(install._MOUSE_ON.encode(), term.raw)
        row = self.line_of(term, "Another setup")
        self.click(term, 60, row)
        term.settle()
        self.assertTrue(term.screen.buffer[row][3].reverse, term.text())
        self.assertIn("Where to install?", term.text())
        self.click(term, 60, row)
        term.wait("Which setup?")
        # The bar's ? Help, pressed by a click.
        bar = term.screen.display[-1]
        self.click(term, bar.index("? Help") + 1, len(term.screen.display) - 1)
        term.wait("Any key or a tap closes this help")
        self.click(term, 10, 5)
        term.wait("Which setup?")
        # Legacy reports move the focus the same way.
        row = self.line_of(term, " > ") + 2
        time.sleep(install.TUI_TAP_SETTLE)
        term.send(x10(20, row + 1), x10(20, row + 1, 3))
        term.settle()
        self.assertTrue(term.screen.buffer[row][3].reverse, term.text())
        term.send("q")
        self.assertEqual(term.close(), install.QUIT_CODE)
        raw = term.raw
        self.assertGreater(raw.rfind(b"\x1b[?1000l"), raw.rfind(b"\x1b[?1000h"))

    def test_no_clicks_asked_when_turned_off(self):
        for name, value in ((install.TUI_MOUSE_ENV, "1"), (install.TUI_PAD_ENV, "gptokeyb")):
            with self.subTest(env=name):
                self.repo()
                self.env[name] = value
                term = self.start()
                term.wait("RetroBIOS")
                term.settle()
                term.send("\x03")
                term.close()
                self.assertNotIn(b"\x1b[?1000h", term.raw)

    def test_line_mode_asks_for_no_clicks(self):
        self.repo()
        term = self.start("--plain")
        term.settle(quiet=1.0)
        term.send("\x03")
        term.close()
        self.assertNotIn(b"\x1b[?1000h", term.raw)
        self.assertNotIn(b"\x1b[?1006h", term.raw)

    def test_a_crash_gives_the_clicks_back(self):
        """The crash path ends in _tui_cleanup, as every other way out."""
        master, slave = os.openpty()
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        with open(slave, encoding="utf-8", closefd=False) as given, \
                open(slave, "w", encoding="utf-8", closefd=False) as shown:
            terminal = install._TuiTerminal(given, shown)
            terminal.mouse_allowed = True
            terminal.enter()
            terminal.set_mouse(True)
            problems = install._tui_cleanup(terminal, [], {}, fresh_state())
            self.assertEqual(problems, [])
            raw = b""
            while select.select([master], [], [], 0.2)[0]:
                raw += os.read(master, 65536)
            for mode in (b"1000", b"1006"):
                self.assertGreater(raw.rfind(b"\x1b[?" + mode + b"l"),
                                   raw.rfind(b"\x1b[?" + mode + b"h"))


@unittest.skipUnless(pyte and pty and hasattr(pty, "fork"),
                     "the pty runs need pyte and a pty")
class TapsOnAPty(unittest.TestCase):
    """Taps on the real install.py --tui."""

    repo = EndToEnd.repo
    start = EndToEnd.start
    line_of = staticmethod(MouseOnAPty.line_of)
    click = MouseOnAPty.click

    def test_taps_on_systems_tick_and_write_nothing(self):
        repo = self.repo()
        term = self.start()
        term.wait("> Install")
        row = self.line_of(term, "Choose systems")
        self.click(term, 20, row)
        term.settle()
        self.click(term, 20, row)
        term.wait("RetroBIOS: Choose systems")
        bar = term.settle().splitlines()[-1]
        self.assertIn("A/Enter/tap Tick", bar)
        row = self.line_of(term, "sony-playstation")
        self.click(term, 20, row)
        self.assertIn("[ ] sony-playstation", term.settle())
        self.click(term, 20, row)
        self.assertIn("[x] sony-playstation", term.settle())
        self.click(term, 20, self.line_of(term, "nintendo-gba"))
        screen = term.settle()
        self.assertIn("[ ] nintendo-gba", screen)
        self.assertIn("RetroBIOS: Choose systems", screen)
        self.assertEqual(repo.installed(), [])
        term.send("q")
        self.assertEqual(term.close(), install.QUIT_CODE)
        self.assertEqual(repo.installed(), [])

    def test_the_result_is_left_by_a_tap_on_exit(self):
        self.repo()
        term = self.start()
        term.wait("files to download")
        row = self.line_of(term, "> Install")
        self.click(term, 20, row)
        term.settle()
        self.click(term, 20, row)
        term.wait("files installed.")
        term.settle()
        mark = term.raw.rfind(b"files installed")
        self.assertGreater(term.raw.rfind(b"\x1b[?1000h"), term.raw.rfind(b"\x1b[?1000l"))
        bar = term.screen.display[-1]
        self.click(term, bar.index("Exit"), len(term.screen.display) - 1)
        self.assertEqual(term.close(), 0)
        self.assertIn("Next: start RetroArch and play.", term.after())
        self.assertGreater(term.raw.rfind(b"\x1b[?1000l"), mark)


@unittest.skipUnless(pyte and pty and hasattr(pty, "fork"),
                     "screen tests need pyte (pip install pyte==0.8.2) and a pty")
class TapsOnAPtySeeFirst(unittest.TestCase):
    """Taps that never commit a row not yet seen, on the real install.py
    --tui."""

    repo = EndToEnd.repo
    start = EndToEnd.start
    line_of = staticmethod(MouseOnAPty.line_of)
    click = MouseOnAPty.click

    def bar_entry(self, term: Pty, word: str) -> tuple[int, int]:
        line = len(term.screen.display) - 1
        return term.screen.display[line].index(word), line

    def test_one_tap_on_the_bar_install_installs_nothing(self):
        repo = self.repo()
        term = self.start()
        term.wait("> Install")
        term.settle()
        self.click(term, *self.bar_entry(term, "Install"))
        self.assertIn(install.TUI_ARMED, term.settle().splitlines()[-1])
        self.assertEqual(repo.installed(), [])
        self.click(term, *self.bar_entry(term, "Install"))
        term.wait("files installed")
        term.send("q")
        term.close()

    def test_a_double_tap_on_continue_neither_quits_nor_installs(self):
        repo = self.repo()
        term = self.start()
        on_setups(term)
        term.settle()
        col, line = self.bar_entry(term, "Continue")
        report = sgr(col + 1, line + 1) + sgr(col + 1, line + 1, release=True)
        term.send(report + report)
        term.settle()
        term.send(report)
        term.settle(0.6)
        self.assertIsNone(os.waitpid(term.pid, os.WNOHANG)[0] or None)
        self.assertEqual(repo.installed(), [])
        term.send("q")
        if "Quit?" in term.settle():
            term.send("\r")
        self.assertIn(term.close(), (install.QUIT_CODE, 0))

    def test_a_double_tap_on_continue_stays_on_what_it_opened(self):
        # at 0, 80, 150 and 250 ms the second tap pressed
        # B/Esc Back on the Checking screen, back to the first screen.
        for gap in (0.0, 0.08, 0.15, 0.25):
            with self.subTest(gap=gap):
                repo = self.repo()
                term = self.start()
                on_setups(term)
                term.settle()
                time.sleep(install.TUI_TAP_SETTLE)
                col, line = self.bar_entry(term, "Continue")
                press = sgr(col + 1, line + 1)
                release = sgr(col + 1, line + 1, release=True)
                os.write(term.fd, (press + release).encode())
                time.sleep(gap)
                os.write(term.fd, (press + release).encode())
                screen = term.settle(0.8)
                self.assertNotIn("Where to install?", screen)
                self.assertNotIn("Quit?", screen)
                term.wait("> Install")
                self.assertEqual(repo.installed(), [])
                term.send("q")
                term.close()

    def test_continue_then_install_in_one_cell_stops_on_confirm(self):
        repo = self.repo()
        term = self.start()
        term.wait("> Install")
        row = self.line_of(term, "Choose systems")
        self.click(term, 20, row)
        term.settle()
        self.click(term, 20, row)
        term.wait("RetroBIOS: Choose systems")
        row = self.line_of(term, "sony-playstation")
        self.click(term, 20, row)
        term.settle()
        col, line = self.bar_entry(term, "Done")
        report = sgr(col + 1, line + 1) + sgr(col + 1, line + 1, release=True)
        # A double tap: the first goes back to the plan, the second lands on
        # its Back inside the settle time and does nothing.
        time.sleep(install.TUI_TAP_SETTLE)
        term.send(report + report)
        screen = term.wait("for 1 of 2 systems")
        screen = term.settle(0.6)
        self.assertIn("RetroBIOS: RetroArch", screen)
        self.assertEqual(repo.installed(), [])
        # Install on the plan counts the choice on Confirm, which waits.
        col, line = self.bar_entry(term, "Install")
        report = sgr(col + 1, line + 1) + sgr(col + 1, line + 1, release=True)
        time.sleep(install.TUI_TAP_SETTLE)
        term.send(report + report)
        term.wait("Counted again for these choices")
        screen = term.settle(0.6)
        self.assertIn("RetroBIOS: Confirm", screen)
        self.assertEqual(repo.installed(), [])
        # A tap made later installs: Confirm is the look before the install.
        time.sleep(install.TUI_TAP_SETTLE)
        term.send(report)
        term.wait("files installed")
        self.assertNotEqual(repo.installed(), [])
        term.send("q")
        term.close()

    def test_the_game_data_row_keeps_the_ticks_to_the_install(self):
        from tests.test_tui_pty import GameDataRepository

        repo = self.repo(GameDataRepository)
        term = self.start()
        term.wait("> Install")
        for _step in range(8):
            if "> Choose systems" in term.settle():
                break
            term.send("\x1b[B")
        term.send("\r")
        term.wait("RetroBIOS: Choose systems")
        term.send("n")
        for _step in range(8):
            if "> [ ] nintendo-gba" in term.settle():
                break
            term.send("\x1b[B")
        term.send(" ")
        term.settle()
        term.send("\x1b")
        term.wait("> Install")
        for _step in range(8):
            if "> Game data: kept" in term.settle():
                break
            term.send("\x1b[B")
        term.send("\r")
        term.wait("Game data: left out")
        for _step in range(8):
            if "> Install" in term.settle():
                break
            term.send("\x1b[A")
        term.send("\r")
        # The changed choices are counted again on Confirm, which has no
        # Install row until its dry run ends: Enter sent on the title alone
        # fell on "Counting the files" and did nothing on a slow runner.
        term.wait("Counted again for these choices")
        term.settle()
        term.send("\r")
        term.wait("files installed")
        self.assertEqual(repo.installed(), ["gba_bios.bin", "mgba/extra.bin"])
        term.send("q")
        term.close()

    def test_two_taps_on_a_region_untick_it_where_it_was(self):
        self.repo()
        term = self.start()
        term.wait("> Install")
        term.send("o")
        term.wait("Preferred regions")
        term.send("\r")
        term.wait("RetroBIOS: Preferred regions")
        row = self.line_of(term, "North America")
        self.click(term, 20, row)
        screen = term.settle()
        self.assertIn("[1] North America", screen.splitlines()[row])
        self.click(term, 20, row)
        screen = term.settle()
        self.assertIn("[ ] North America", screen.splitlines()[row])
        self.assertNotIn("[1]", screen)
        term.send("q")
        term.close()


# install.py whose tui_view takes SLOW seconds on the first frame of each
# screen, as a slower device takes to lay one out.
SLOW_VIEW = """
import os, sys, time
sys.argv[0] = {install!r}
sys.path.insert(0, {repo!r})
import install
slow = float(os.environ["SLOW"])
real, seen = install.tui_view, [None]
def view(state, cols, rows):
    key = (state.screen, len(state.stack))
    if key != seen[0]:
        seen[0] = key
        time.sleep(slow)
    return real(state, cols, rows)
install.tui_view = view
sys.exit(install.main())
"""


@unittest.skipUnless(pyte and pty and hasattr(pty, "fork"),
                     "screen tests need pyte (pip install pyte==0.8.2) and a pty")
class TheSettleRunsFromTheFrameShown(unittest.TestCase):
    """The settle was stamped before the layout, so on
    a slow one the second click of a double click on Options' Back reached
    the plan's Quit."""

    repo = EndToEnd.repo
    bar_entry = TapsOnAPtySeeFirst.bar_entry

    def test_a_double_click_on_back_stays_on_the_plan_after_a_slow_layout(self):
        repo = self.repo()
        wrapper = repo.root / "slowview.py"
        wrapper.write_text(SLOW_VIEW.format(install=str(REPO_ROOT / "install.py"),
                                            repo=str(REPO_ROOT)))
        env = {**self.env, "SLOW": "0.5"}
        term = Pty([], env, 80, 24, program=[sys.executable, str(wrapper)])
        self.addCleanup(lambda: term.status is None and os.kill(term.pid, 9))
        term.wait("> Install")
        term.settle()
        term.send("o")
        term.wait("RetroBIOS: Change")
        term.settle()
        time.sleep(1.0)
        col, line = self.bar_entry(term, "Back")
        report = sgr(col + 1, line + 1) + sgr(col + 1, line + 1, release=True)
        os.write(term.fd, report.encode())
        time.sleep(0.2)
        os.write(term.fd, report.encode())
        time.sleep(1.0)
        screen = term.settle(0.6)
        self.assertNotIn("Quit?", screen)
        self.assertIn("RetroBIOS: RetroArch", screen.splitlines()[0])
        self.assertEqual(repo.installed(), [])
        term.send("q")
        if "Quit?" in term.settle():
            term.send("\r")
        term.close()


if __name__ == "__main__":
    unittest.main()
