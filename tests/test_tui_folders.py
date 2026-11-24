"""Folders on the full screen: the work folders, copying from an old card, the
save folder, card folders and folders this user cannot open."""

from __future__ import annotations

import tests

import contextlib
import errno
import io
import os
import shutil
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

import install
from tests.installsupport import make_card
from tests.netguard import module_guard
from tests.tuisupport import (
    _args, CHECK, checked_state, FILES, found, fresh_state, HOME, in_full, install_run,
    _installed_state, Key, MANIFEST, option_focus, PLAN, plan_event, planned, press, REPO_ROOT,
    reported, screen_text, SYSTEM_DIR, SYSTEMS, urllib_error, WindowsOs,
)


# No connection off the loopback and no card of the host reaches a test,
# in this process or one it starts: the module fails at its end when one is tried.
setUpModule, tearDownModule = module_guard("test_tui_folders")


class TicksBarAndPaths(unittest.TestCase):
    """Ticks, the key bar, the network clock and typed paths."""

    def systems(self) -> install.TuiState:
        state = checked_state()
        press(state, "down", "enter")
        self.assertEqual(state.screen, "systems")
        return state

    def focused(self, state: install.TuiState) -> install.TuiRow:
        rows = install.tui_rows(state)
        return rows[state.focus[state.screen]]

    def test_install_says_the_size_the_headline_says(self):
        """One system ticked: the headline said About 3479 files, 82.2 MB
        and the row Install 6.6 GB, the whole list's size."""
        big = 6 * 1024 ** 3
        state = checked_state()
        state.files[0] = {**state.files[0], "size": big}
        state.check = planned({**state.check, "bytes_needed": state.check["bytes_needed"] + big})
        self.assertEqual(install.tui_rows(state)[0].label, "Install 6.0 GB")
        for system, label, head in (("nintendo-gba", "Install", "About 1 file, 16.0 KB"),
                                    ("sony-playstation", "Install 6.0 GB",
                                     "About 3 files, 6.0 GB")):
            with self.subTest(system=system):
                state.ticked = {system}
                self.assertTrue(install._tui_estimating(state))
                self.assertEqual(install.tui_rows(state)[0].label, label)
                self.assertIn(head, "\n".join(install.tui_view(state, 80, 24)))

    def test_the_filter_never_changes_the_ticks(self):
        state = self.systems()
        press(state, "n")
        state.focus["systems"] = next(i for i, row in enumerate(install.tui_rows(state))
                                      if row.value == "nintendo-gba")
        press(state, "right")
        self.assertEqual(state.ticked, {"nintendo-gba"})
        press(state, "/", "p", "l", "a", "y")
        self.assertEqual(self.focused(state).action, "filter")
        press(state, "enter")
        # Enter lands on the first match, never on All or None.
        self.assertEqual(self.focused(state).value, "sony-playstation")
        press(state, " ")
        self.assertEqual(state.ticked, {"nintendo-gba", "sony-playstation"})
        press(state, " ")
        press(state, "esc")
        # The filter is cleared, the row in focus stays in focus, and A there
        # continues instead of ticking everything.
        self.assertEqual(state.filters["systems"], "")
        self.assertEqual(self.focused(state).value, "sony-playstation")
        self.assertEqual(state.ticked, {"nintendo-gba"})
        self.assertIn("A/Enter Tick", install.tui_view(state, 80, 24)[-1])
        state.focus["systems"] = 0
        press(state, " ")
        self.assertEqual(state.editing, "")
        self.assertEqual(state.ticked, {"nintendo-gba"})

    def test_the_bar_names_what_a_does_on_the_focused_row(self):
        state = checked_state()
        self.assertTrue(install.tui_view(state, 80, 24)[-1].strip().startswith("A/Enter Install"))
        press(state, "down")
        self.assertTrue(install.tui_view(state, 80, 24)[-1].strip().startswith("A/Enter Open"))
        state = self.systems()
        state.focus["systems"] = next(i for i, row in enumerate(install.tui_rows(state))
                                      if row.action == "all")
        self.assertIn("A/Enter Tick all", install.tui_view(state, 80, 24)[-1])

    def test_esc_and_q_stop_an_install(self):
        for key in ("esc", "backspace", "q"):
            with self.subTest(key=key):
                state = checked_state()
                press(state, "enter")
                self.assertEqual(press(state, key), [("stop",)])
                self.assertTrue(state.stopping)
                self.assertEqual(press(state, key), [("kill",)])

    def test_options_read_the_plan_again(self):
        state = self.systems()
        press(state, "n")
        state.focus["systems"] = 1
        press(state, "right")
        ticked = set(state.ticked)
        press(state, "esc", "o")
        self.assertEqual(state.screen, "options")
        option_focus(state, "game_data")
        press(state, "enter")
        self.assertTrue(state.no_game_data)
        effects = press(state, "esc")
        self.assertEqual(effects, [("run", "check")])
        self.assertIn("--no-game-data", [f for f, _v in state.checked_flags])
        self.assertNotIn("--system", [f for f, _v in state.checked_flags])
        for event in [*FILES, *SYSTEMS, {**CHECK, "missing": 2, "bytes_needed": 600}]:
            install.tui_receive(state, ("event", state.run_id, event))
        with mock.patch.object(install, "_tui_folder_facts", return_value={}):
            install.tui_receive(state, ("ended", state.run_id, 1, []))
        self.assertEqual(state.screen, "plan")
        self.assertEqual(state.ticked, ticked)
        for cols, rows in ((80, 24), (40, 15)):
            text = "\n".join(install.tui_view(state, cols, rows))
            # the headline counts the ticked systems.
            self.assertIn("About 1 file, 16.0 KB, for 1 of 3 systems", " ".join(text.split()))
            self.assertNotIn("3 files to download", text)

    def test_no_network_is_said_at_once(self):
        import socket

        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        inbox = __import__("queue").Queue()
        started = time.monotonic()
        with mock.patch.object(install, "active_remote", return_value=install.Remote(
                install.DEFAULT_RELEASE_REF, f"http://127.0.0.1:{port}", False)):
            install._tui_fetch("retroarch", inbox)
        self.assertLess(time.monotonic() - started, 5)
        kind, plat, title, lines, code = inbox.get_nowait()
        self.assertEqual((kind, title, code), ("manifest_failed", "No connection", 1))
        self.assertIn("could not be downloaded: the server refused the connection", lines[0])
        # The pack is the one option named: the way of a handheld with no
        # Wi-Fi.
        self.assertIn("Or copy a pack to the card and run the installer with --from-pack",
                      " ".join(lines))
        self.assertNotIn("--", " ".join(lines).replace("--from-pack", ""))
        state = fresh_state()
        with mock.patch.object(install.Path, "exists", return_value=True):
            press(state, "enter")
        install.tui_receive(state, (kind, plat, title, lines, code))
        self.assertEqual([row.action for row in install.tui_rows(state)],
                         ["retry", "elsewhere", "quit"])

    def test_a_missing_list_names_the_revision_asked_for(self):
        # Line mode named RETROBIOS_REF, the screen said only "at this address".
        inbox = __import__("queue").Queue()
        missing = install.urllib.error.HTTPError("u", 404, "Not Found", {}, None)
        with mock.patch.object(install, "_fetch_json", side_effect=missing), \
                mock.patch.dict(os.environ, {"RETROBIOS_REF": "v2020.01.01",
                                             "RETROBIOS_BASE_URL": ""}):
            install._tui_fetch("batocera", inbox)
        _kind, _plat, title, lines, _code = inbox.get_nowait()
        self.assertEqual(title, "No file list")
        self.assertIn("RETROBIOS_REF=v2020.01.01 has no list for batocera", lines[1])

    def test_the_clock_says_so(self):
        import ssl

        inbox = __import__("queue").Queue()
        error = urllib_error(ssl.SSLCertVerificationError("certificate is not yet valid"))
        words = install.network_words(error, today=install.datetime.date(1980, 1, 1))
        with mock.patch.object(install, "_fetch_json", side_effect=error), \
                mock.patch.object(install, "network_words", return_value=words):
            install._tui_fetch("retroarch", inbox)
        _kind, _plat, title, lines, _code = inbox.get_nowait()
        self.assertEqual(title, "The clock is wrong")
        self.assertIn("The clock reads 1980-01-01", lines[0])

    def test_one_line_per_cause(self):
        state = checked_state()
        state.stack.append("result")
        state.code = 2
        state.summary = {"installed": 0, "up_to_date": 0, "failed": [
            {"dest": f"f{n}.bin", "reason": "folder not writable"} for n in range(50)]}
        _title, lines = install.tui_outcome(state)
        self.assertEqual([line for line in lines if "failed" in line],
                         ["Nothing was installed: 50 files failed.",
                          "  failed: 50 files (folder not writable), first f0.bin"])

    def test_failures_read_alike_in_both_modes(self):
        """The screen grouped a reason past three files and capped at 20
        lines, line mode grouped one shared reason and capped at 10."""
        failed = ([{"dest": f"ro{n}.bin", "reason": "folder not writable"} for n in range(5)]
                  + [{"dest": "a.bin", "reason": "HTTP 404"}]
                  + [{"dest": f"cut{n}.bin", "reason": f"timed out {n}"} for n in range(12)])
        state = checked_state()
        state.stack.append("result")
        state.code = 1
        state.summary = {"installed": 1, "up_to_date": 0, "failed": failed}
        _title, lines = install.tui_outcome(state)
        screen = [line for line in lines if line.startswith(("  failed:", "  ..."))]
        said: list[str] = []
        records = install.event_records(failed)
        with mock.patch.object(install, "SAID_FAILED", set()):
            install._say_failures(said.append, records)
        self.assertEqual(screen, said)
        self.assertEqual(said[0], "  failed: 5 files (folder not writable), first ro0.bin")
        self.assertEqual(said[1], "  failed: a.bin (HTTP 404)")
        self.assertEqual(len(said), install.FAILED_LINES_CAP + 1)
        self.assertEqual(said[-1], "  ... and 4 more")

    def test_folder_inside_a_card_offers_its_root(self):
        card = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, card, True)
        (card / ".system").mkdir()
        (card / ".system" / "version.txt").write_text("MinUI-20250101\n")
        (card / "Bios").mkdir()
        state = fresh_state()
        state.stack = ["folder"]
        self.assertEqual(install._choose(state, "minui", card / "Bios"), [])
        self.assertEqual(state.screen, "cardroot")
        text = screen_text(install.tui_view(state, 120, 40))
        self.assertIn(f"under the card's root: {card}", text)
        self.assertEqual(press(state, "enter"), [("fetch", "minui")])
        self.assertEqual(state.dest, card)

    def test_the_banner_is_not_an_error_line(self):
        state = fresh_state()
        state.platform, state.dest = "retroarch", SYSTEM_DIR
        state.manifest, state.manifest_for = MANIFEST, "retroarch"
        install._start_check(state)
        install.tui_receive(state, ("ended", state.run_id, 1,
                                    ["RetroBIOS 532f0b8d96e0", "Error: refused."]))
        self.assertEqual(state.error, ["Error: refused."])
        self.assertNotIn("retry", [row.action for row in install.tui_rows(state)])

    def test_typed_path_replaces_the_one_offered(self):
        state = fresh_state()
        state.platform, state.stack = "retroarch", ["folder"]
        state.folder_default = SYSTEM_DIR
        state.focus["folder"] = 2
        press(state, "enter")
        self.assertEqual((state.screen, state.path_selected), ("path", True))
        install.tui_update(state, Key("paste", '"/media/sd card/bios"'))
        self.assertEqual(state.path_text, '"/media/sd card/bios"')
        install.tui_update(state, Key("ctrl-u"))
        self.assertEqual(state.path_text, "")
        install.tui_update(state, Key("paste", '/media/x"'))
        self.assertEqual(install.typed_path(state.path_text), Path("/media/x"))

    def test_path_from_the_root_is_not_created_on_a(self):
        state = fresh_state()
        state.stack = ["folder"]
        install._choose(state, "retroarch", Path("/no/such/deep/folder"))
        self.assertEqual(state.screen, "create")
        self.assertEqual(self.focused(state).action, "other")
        self.assertIn("Every folder of this path would be made",
                      " ".join(install.tui_view(state, 120, 40)))
        near = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, near, True)
        # Line mode's rule: two missing levels are asked with no in focus,
        # one is made and said on the plan.
        state.stack = ["folder"]
        with contextlib.redirect_stdout(io.StringIO()):
            install._choose(state, "retroarch", near / "a" / "b")
        self.assertEqual((state.screen, self.focused(state).action), ("create", "other"))
        self.assertFalse(state.facts["risky"])
        state.stack = ["folder"]
        with contextlib.redirect_stdout(io.StringIO()):
            install._choose(state, "retroarch", near / "bios")
        self.assertEqual(state.screen, "checking")
        self.assertIn("bios is created in", state.card_note)

    def test_two_setups_of_one_name(self):
        flatpak = HOME / ".var/app/org.libretro.RetroArch/config/retroarch/system"
        setups = install.tell_apart([("retroarch", flatpak, "RetroArch"),
                                     ("retroarch", SYSTEM_DIR, "RetroArch"),
                                     ("emudeck", HOME / "Emulation/bios", "EmuDeck")])
        self.assertEqual([label for _p, _f, label in setups],
                         ["RetroArch (Flatpak)", "RetroArch (installed)", "EmuDeck"])
        # Two that no package names keep the end of their folder.
        twice = install.tell_apart([("retroarch", SYSTEM_DIR, "RetroArch"),
                                    ("retroarch", HOME / "ra2/system", "RetroArch")])
        self.assertEqual([label for _p, _f, label in twice],
                         ["RetroArch (retroarch/system)", "RetroArch (ra2/system)"])
        state = fresh_state()
        state.setups = setups
        state.setup_folders = install.setup_folders(setups)
        self.assertIn("RetroArch (Flatpak)", "\n".join(install.tui_view(state, 40, 15)))
        # A Flatpak whose config names a system folder outside its sandbox.
        elsewhere = HOME / "bios"
        config = HOME / ".var/app/org.libretro.RetroArch/config/retroarch/retroarch.cfg"
        with mock.patch.dict(install._RETROARCH_CONFIGS, {elsewhere: (config, config.parent)}):
            setups = install.tell_apart([("retroarch", elsewhere, "RetroArch"),
                                         ("retroarch", SYSTEM_DIR, "RetroArch")])
        self.assertEqual(setups[0][2], "RetroArch (Flatpak)")

    def test_the_check_counts_while_it_reads(self):
        state = fresh_state()
        state.platform, state.dest = "retroarch", SYSTEM_DIR
        state.manifest, state.manifest_for = MANIFEST, "retroarch"
        install._start_check(state)
        install.tui_receive(state, ("event", state.run_id,
                                    {"event": "checking", "files_done": 120, "files_total": 400}))
        self.assertIn("Reading the files already in the folder: 120 of 400",
                      "\n".join(install.tui_view(state, 80, 24)))

    def test_narrow_bar_keeps_the_keys_to_finish(self):
        state = self.systems()
        self.assertEqual(install.tui_view(state, 40, 15)[-1].strip(),
                         "A Tick  B Done  ? Help")

    def test_device_name_finds_its_setup(self):
        state = fresh_state()
        state.stack = ["platforms"]
        press(state, "/", "m", "u", "o", "s")
        self.assertEqual([row.value for row in install.tui_rows(state)][1:],
                         [("retroarch", "muOS")])

    def test_long_preview_wraps_only_what_is_in_view(self):
        state = checked_state()
        state.stack += ["options", "preview"]
        state.dry = dict(CHECK)
        state.dry_files = [{**FILES[0], "dest": f"file{n:05d}.bin"} for n in range(8000)]
        state.cols, state.rows = 40, 15
        real = install._text_lines
        calls = []

        def counted(items, width, whole=False):
            calls.append(len(items))
            return real(items, width, whole)

        with mock.patch.object(install, "_text_lines", counted):
            press(state, "end")
            lines = install.tui_view(state, 40, 15)
        self.assertLess(sum(calls), 40)
        self.assertIn("file07999.bin", "\n".join(lines))

    def test_titles_and_regions(self):
        state = checked_state()
        state.manifest = {**MANIFEST, "system_titles": {"nintendo-gba": "Game Boy Advance"}}
        state.stack.append("systems")
        text = "\n".join(install.tui_view(state, 40, 15))
        self.assertIn("[x] Game Boy Advance", text)
        self.assertEqual(install.region_title("asia-ntsc"), "Asia (NTSC)")
        self.assertEqual(install.region_title("north-america"), "North America")

    def test_jobs_stop_at_the_ends_and_q_keeps_the_error_code(self):
        state = checked_state()
        state.jobs = 1
        install._option(state, "jobs", -1)
        self.assertEqual(state.jobs, 1)
        state.jobs = 32
        install._option(state, "jobs", 1)
        self.assertEqual(state.jobs, 32)
        state = fresh_state()
        state.stack, state.error_code = ["setup", "error"], 2
        press(state, "q")
        self.assertEqual(state.exit_code, 2)

    def test_ascii_keeps_the_columns(self):
        self.assertEqual(install.ascii_text("Édition ファミ"), "Edition ??????")

    def test_refused_tui_says_why_without_the_usage(self):
        proc = install_run("--tui")
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stderr.strip().splitlines(),
                         ["install.py: error: --tui cannot open the full-screen interface "
                          "here: the input is not a terminal"])


class WorkFolders(unittest.TestCase):
    """Every run's folder of logs goes, but the one a failure names."""

    class Terminal:
        state_to = None

        def __init__(self, *_streams) -> None:
            self.frame = []

        def enter(self) -> None:
            pass

        def leave(self) -> None:
            pass

        def size(self) -> tuple:
            return 80, 24

        def draw(self, lines, cols) -> None:
            pass

        def set_mouse(self, on: bool) -> None:
            pass

        def keys(self, timeout):
            WorkFolders.Terminal.state_to(self)
            return [Key("enter")]

    def run_to(self, code: int) -> tuple:
        work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work, True)
        state = checked_state()
        state.stack.append("result")
        state.code = code
        state.log = str(work / "install.log")
        state.summary = {"installed": 1, "failed": [] if code == 0 else [
            {"dest": "a.bin", "reason": "HTTP 404"}]}
        WorkFolders.Terminal.state_to = lambda _t: None
        out = io.StringIO()
        with mock.patch.object(install, "_TuiTerminal", self.Terminal), \
                mock.patch.object(install, "tui_start", return_value=(state, [])), \
                mock.patch.object(install, "open_list_and_pack"), \
                mock.patch.object(install, "detect_os", return_value="linux"), \
                mock.patch.object(install.tempfile, "mkdtemp", return_value=str(work)), \
                mock.patch.object(sys, "stdout", out), mock.patch.object(sys, "stderr", out):
            self.assertEqual(install.run_tui(_args()), code)
        return work, out.getvalue()

    def test_a_success_leaves_nothing(self):
        work, out = self.run_to(0)
        self.assertFalse(work.exists())
        self.assertNotIn("Details:", out)

    def test_a_failure_keeps_the_log_it_names(self):
        work, out = self.run_to(1)
        self.assertTrue(work.exists())
        self.assertIn(f"Log: {work / 'install.log'}", out)

    def test_a_stop_leaves_nothing(self):
        work, out = self.run_to(130)
        self.assertFalse(work.exists())

    def test_a_full_temp_disk_or_a_failing_pruner_still_opens(self):
        real_write = Path.write_text

        def full(path, *args, **kwargs):
            if path.name == install.TUI_OWNER:
                raise OSError(errno.ENOSPC, "No space left on device")
            return real_write(path, *args, **kwargs)

        with mock.patch.object(Path, "write_text", full):
            work, out = self.run_to(0)
        self.assertFalse(work.exists())
        with mock.patch.object(install, "_prune_work_folders",
                               side_effect=OSError(errno.EACCES, "denied")):
            work, out = self.run_to(0)
        self.assertFalse(work.exists())
        err = io.StringIO()
        with mock.patch.object(install.tempfile, "mkdtemp",
                               side_effect=OSError(errno.ENOSPC, "No space left")), \
                mock.patch.object(install, "tui_start", return_value=(fresh_state(), [])), \
                mock.patch.object(install, "open_list_and_pack"), \
                mock.patch.object(install, "detect_os", return_value="linux"), \
                mock.patch.object(sys, "stderr", err):
            self.assertEqual(install.run_tui(_args()), 1)
        self.assertIn("no work folder could be made", err.getvalue())

    def test_a_stop_while_it_starts_ends_on_the_farewell(self):
        """Start+Select during the detection: the signal is the interface's,
        never the default action that ended Python without a word."""
        import signal

        for number in (signal.SIGTERM, signal.SIGHUP):
            with self.subTest(signal=number):
                heard = []

                def recorder(signum, _frame, heard=heard):
                    heard.append(signum)

                previous = signal.signal(number, recorder)
                self.addCleanup(signal.signal, number, previous)
                interrupt = signal.getsignal(signal.SIGINT)

                def starting(*_args, number=number, **_kwargs):
                    os.kill(os.getpid(), number)
                    return fresh_state(), [("fetch", "retroarch")]

                entered = []
                WorkFolders.Terminal.state_to = lambda _t: None
                out = io.StringIO()
                work = Path(tempfile.mkdtemp())
                self.addCleanup(shutil.rmtree, work, True)
                with mock.patch.object(install, "_TuiTerminal", self.Terminal), \
                        mock.patch.object(install.tempfile, "mkdtemp", return_value=str(work)), \
                        mock.patch.object(self.Terminal, "enter",
                                          lambda _t, entered=entered: entered.append(True)), \
                        mock.patch.object(install, "tui_start", side_effect=starting), \
                        mock.patch.object(install, "open_list_and_pack"), \
                        mock.patch.object(install, "_tui_fetch") as fetch, \
                        mock.patch.object(install, "detect_os", return_value="linux"), \
                        mock.patch.object(sys, "stdout", out), \
                        mock.patch.object(sys, "stderr", out):
                    code = install.run_tui(_args())
                self.assertEqual(code, 128 + number)
                self.assertEqual(heard, [])
                self.assertEqual(entered, [])
                fetch.assert_not_called()
                self.assertEqual(out.getvalue(), "RetroBIOS: stopped. Nothing was installed.\n")
                self.assertIs(signal.getsignal(number), recorder)
                self.assertIs(signal.getsignal(signal.SIGINT), interrupt)


class CopyFromAnOldCard(unittest.TestCase):
    """--from in the interface: a row on the plan, the browser, the counts."""

    def recheck(self, state: install.TuiState, events: list) -> None:
        plan = plan_event(CHECK, [event["dest"] for event in events if event["event"] == "found"
                                  and event["dest"] in {file["dest"] for file in FILES}])
        for event in [*FILES, *SYSTEMS, *events, CHECK, plan]:
            install.tui_receive(state, ("event", state.run_id, event))
        with mock.patch.object(install, "_tui_folder_facts", return_value={
                "free": 50 * 1024 ** 3, "writable": True, "cores": []}):
            install.tui_receive(state, ("ended", state.run_id, 1, []))

    def test_the_plan_offers_it_and_the_browser_adds_the_folder(self):
        old = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, old, True)
        (old / "bios").mkdir()
        (old / "backup.zip").write_bytes(b"PK")
        state = checked_state()
        row = next(i for i, r in enumerate(install.tui_rows(state)) if r.action == "fromcard")
        self.assertEqual(install.tui_rows(state)[row].label,
                         "Copy the BIOS files from an old card or a folder")
        state.focus["plan"] = row
        state.home = old
        with mock.patch.object(install, "_mounted_cards", return_value=[]):
            press(state, "enter")
            self.assertEqual((state.screen, state.browse_for), ("browse", "from"))
            labels = [r.label for r in install.tui_rows(state)]
            self.assertEqual(labels, ["Use this folder", "..", "bios/", "backup.zip"])
            self.assertIn("Choose the old card", "\n".join(install.tui_view(state, 80, 24)))
            effects = press(state, "enter")
        self.assertEqual(effects, [("run", "check")])
        self.assertEqual(state.from_folders, [old])
        self.assertIn(f"--from={old}", install.tui_argv(state, "check", "py", "i.py"))
        self.recheck(state, [found("scph5500.bin", str(old)), found("gba_bios.bin", str(old))])
        self.assertEqual(state.screen, "plan")
        text = "".join("".join(install.tui_view(state, 120, 40)).split())
        # The folder by its name: the whole path pushed the BIOS folder off.
        self.assertIn("".join(f"2 found in {old.name}, 2 to download (512.0 KB)".split()), text)
        # A second folder from the options: --from twice.
        press(state, "o")
        state.focus["options"] = next(i for i, r in enumerate(install.tui_rows(state))
                                      if r.action == "from")
        self.assertEqual(install.tui_rows(state)[state.focus["options"]].right, "--from")
        with mock.patch.object(install, "_mounted_cards", return_value=[]):
            press(state, "enter")
            # It opens beside the first folder: the second card sits next to it.
            self.assertEqual(state.browse_dir, old.parent)
            install._browse_to(state, old)
            state.focus["browse"] = 3
            self.assertEqual(press(state, "enter"), [("run", "check")])
        self.assertEqual(state.from_folders, [old, old / "backup.zip"])
        self.assertEqual([flag for flag in install.tui_argv(state, "check", "py", "i.py")
                          if flag.startswith("--from=")],
                         [f"--from={old}", f"--from={old / 'backup.zip'}"])

    def test_left_takes_the_last_folder_back(self):
        state = checked_state()
        state.from_folders = [Path("/media/old")]
        state.checked_flags = install.tui_flags(state)
        state.stack.append("options")
        state.focus["options"] = next(i for i, r in enumerate(install.tui_rows(state))
                                      if r.action == "from")
        # Said, and the screen stays: Back to the plan counts again.
        self.assertEqual(press(state, "left"), [])
        self.assertEqual((state.screen, state.from_folders), ("options", []))
        self.assertIn("No longer copying from old.", "\n".join(install.tui_view(state, 80, 24)))
        self.assertEqual(press(state, "esc"), [("run", "check")])

    def test_the_command_line_folders_are_kept(self):
        with mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]), \
                mock.patch.object(install, "_mounted_cards", return_value=[]):
            args = _args(platform="retroarch", dest=SYSTEM_DIR)
            setattr(args, "from", [Path("/media/old")])
            state, _effects = install.tui_start(args, "linux")
        self.assertEqual(state.from_folders, [Path("/media/old")])
        self.assertIn(("--from", "/media/old"), install.tui_flags(state))

    @in_full
    def test_files_in_the_wrong_place_are_said_and_listed(self):
        state = checked_state()
        state.platform, state.dest = "retroarch", SYSTEM_DIR
        install._start_check(state)
        self.recheck(state, [found("scph5500.bin", str(SYSTEM_DIR),
                                   "nested folder: bios/scph5500.bin")])
        text = " ".join(line.strip() for line in install.tui_view(state, 120, 40))
        # a fix copies, and the screen says the user's
        # copy stays.
        self.assertIn("1 file is in the wrong place, it will be copied where the emulators "
                      "read it, the copy left as it is.", text)
        row = next(i for i, r in enumerate(install.tui_rows(state)) if r.action == "misplaced")
        state.focus["plan"] = row
        press(state, "enter")
        self.assertEqual(state.screen, "misplaced")
        self.assertIn("scph5500.bin: nested folder: bios/scph5500.bin",
                      "\n".join(install.tui_view(state, 80, 24)))
        press(state, "esc")
        self.assertEqual(state.screen, "plan")

    def test_the_result_says_the_misplaced_copies_stay(self):
        state = checked_state()
        state.stack.append("result")
        state.code = 0
        state.summary = {"event": "summary", "mode": "install", "installed": 2,
                         "up_to_date": 0, "pending": 0, "failed": [], "skipped": [],
                         "left_out": [], "kept": [], "interrupted": False}
        state.local_dests = {"scph5500.bin": (str(SYSTEM_DIR), "nested folder: bios/a")}
        state.finished = [("scph5500.bin", True, ""), ("gba_bios.bin", True, "")]
        text = " ".join(" ".join(install.tui_outcome(state)[1]).split())
        self.assertIn("1 file copied from the wrong place in the BIOS folder, 1 downloaded. "
                      "The copies in the wrong place were left as they are.", text)

    def test_a_local_copy_is_no_download_speed(self):
        state = checked_state()
        press(state, "enter")
        mega = 1024 * 1024
        events = [(9.0, {"event": "found", **found("big.bin", "/media/old")}),
                  (9.0, {"event": "download", "platform": "retroarch", "files": 2,
                         "bytes": 300 * mega}),
                  (10.0, {"event": "downloaded", "dest": "big.bin", "ok": True, "reason": "",
                          "size": 200 * mega, "files_done": 1, "files_total": 2,
                          "bytes_done": 200 * mega, "bytes_total": 300 * mega}),
                  # The engine says which bytes came from this machine.
                  (10.0, {"event": "transfer", "bytes_local": 200 * mega,
                          "bytes_network": 0}),
                  (11.0, {"event": "progress", "files_done": 1, "files_total": 2,
                          "bytes_done": 201 * mega, "bytes_total": 300 * mega}),
                  (11.0, {"event": "transfer", "bytes_local": 200 * mega,
                          "bytes_network": mega}),
                  (12.0, {"event": "progress", "files_done": 1, "files_total": 2,
                          "bytes_done": 202 * mega, "bytes_total": 300 * mega}),
                  (12.0, {"event": "transfer", "bytes_local": 200 * mega,
                          "bytes_network": 2 * mega})]
        for when, event in events:
            state.now = when
            install.tui_receive(state, ("event", state.run_id, event))
        text = "\n".join(install.tui_view(state, 80, 24))
        self.assertIn("1.0 MB/s, 1:38 left", text)


class SaveDirectoryLeftOut(unittest.TestCase):
    """Files left out of the save directory are said."""

    UNPLACED = {"reason": "no_save_directory", "label": "no save directory", "files": 2,
                "required": 0}

    def _ended(self, manifest: dict) -> tuple:
        state = fresh_state()
        state.stack = ["setup"]
        with mock.patch.object(install.Path, "exists", return_value=True):
            install.tui_update(state, Key("enter"))
        install.tui_receive(state, ("manifest", "retroarch", manifest))
        summary = {"event": "summary", "mode": "check", "installed": 0, "up_to_date": 0,
                   "pending": 5, "failed": [], "skipped": [self.UNPLACED], "left_out": [],
                   "kept": [], "interrupted": False}
        for event in [*FILES, *SYSTEMS, CHECK, PLAN, summary]:
            install.tui_receive(state, ("event", state.run_id, event))
        with mock.patch.object(install, "_tui_folder_facts", return_value={
                "free": 50 * 1024 ** 3, "writable": True, "cores": []}):
            install.tui_receive(state, ("ended", state.run_id, 1, []))
        return state, summary

    @in_full
    def test_a_list_that_holds_none_of_them_offers_no_folder(self):
        """RetroPie's list leaves its save files out with no hash or address:
        --save-dir installs none of them, and was advised again each run."""
        state, summary = self._ended(MANIFEST)
        # The count on the screen, why on Details.
        lines = ["2 files read from RetroArch's save directory left out.",
                 "RetroArch keeps it in no fixed place, and its file list holds none of them."]
        plan = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
        self.assertIn(" ".join(lines), plan)
        self.assertNotIn("--save-dir", plan)
        state.stack.append("result")
        state.code = 0
        state.summary = {**summary, "mode": "install", "installed": 5}
        outcome = install.tui_outcome(state)[1]
        self.assertEqual([text for text in outcome if "save" in text or "place" in text],
                         lines)
        self.assertTrue(install._is_detail(outcome[outcome.index(lines[1])]))

    @in_full
    def test_files_left_out_of_the_save_directory_are_said(self):
        state = fresh_state()
        state.stack = ["setup"]
        with mock.patch.object(install.Path, "exists", return_value=True):
            install.tui_update(state, Key("enter"))
        install.tui_receive(state, ("manifest", "retroarch", {
            **MANIFEST, "save_directory": {"folder": "saves", "by_core": True}}))
        summary = {"event": "summary", "mode": "check", "installed": 0, "up_to_date": 0,
                   "pending": 5, "failed": [], "skipped": [self.UNPLACED], "left_out": [],
                   "kept": [], "interrupted": False}
        for event in [*FILES, *SYSTEMS, CHECK, PLAN, summary]:
            install.tui_receive(state, ("event", state.run_id, event))
        with mock.patch.object(install, "_tui_folder_facts", return_value={
                "free": 50 * 1024 ** 3, "writable": True, "cores": []}):
            install.tui_receive(state, ("ended", state.run_id, 1, []))
        line = "2 files read from RetroArch's save directory left out. "
        plan = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
        # The plan names the row that sets it, the result the option a
        # command carries.
        self.assertIn(line + "Choose it in Change, Save folder (--save-dir). Its place is "
                      "not known.", plan)
        state.stack.append("result")
        state.code = 0
        state.summary = {**summary, "mode": "install", "installed": 5}
        self.assertIn(line + "Choose it in Change, Save folder (--save-dir), next time.",
                      install.tui_outcome(state)[1])


class TheSaveFolderHasARow(unittest.TestCase):
    """A card on a PC left the save-directory files out and named
    --save-dir, which Options had no row for: the interface user had to
    leave it and type a command."""

    def state(self) -> install.TuiState:
        state = checked_state()
        state.manifest = {**MANIFEST, "save_directory": {"folder": "saves", "by_core": True}}
        return state

    def test_options_list_it_and_the_browser_sets_it(self):
        state = self.state()
        rows = install._option_rows(state)
        [row] = [row for row in rows if row.action == "savedir"]
        # Named as line mode names it, from the same rules.
        place = install.save_directory_for(state.dest, state.manifest, None)
        self.assertEqual((row.label, row.right),
                         (f"Save folder: {install._short_path(place.directory, HOME)}",
                          "--save-dir"))
        saves = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, saves, True)
        state.stack = ["setup", "plan", "options"]
        install._option(state, "savedir", 0)
        self.assertEqual(state.screen, "browse")
        self.assertIn("save directory", " ".join(" ".join(install.tui_view(state, 120, 40))
                                                 .split()))
        install._browse_to(state, saves)
        effects = install._activate(state, install.TuiRow("use", "Use this folder"))
        self.assertIn(("--save-dir", str(saves)), install.tui_flags(state))
        self.assertTrue(any(effect[0] == "run" for effect in effects), effects)
        self.assertEqual(install._save_folder_words(state), str(saves))

    def test_a_list_without_a_save_directory_has_no_row(self):
        self.assertNotIn("savedir", [row.action for row in install._option_rows(checked_state())])


class TheSaveFolderLineFollowsTheChoice(unittest.TestCase):
    """The save-folder line was the check's: with the system owning the
    save file unticked, the result named a folder nothing was written to,
    and kept, the Confirm screen did not name it."""

    SAVES = {"event": "saves", "platform": "retroarch", "files": 1,
             "folder": "/home/user/MySaves/<core>"}
    LINE = ("1 file read from RetroArch's save directory goes to a folder per core under: "
            "~/MySaves")
    # The result spells every folder in full.
    RESULT = ("1 file read from RetroArch's save directory goes to a folder per core under: "
              "/home/user/MySaves")

    def said(self, lines) -> str:
        return " ".join(" ".join(lines).split())

    def run_to_result(self, confirm_saves: bool, install_saves: bool) -> install.TuiState:
        state = checked_state()
        state.saves = dict(self.SAVES)
        state.must_confirm = True
        state.stack.append("confirm")
        install._start_run(state, "confirm")
        dry = {**CHECK, "files": 3, "missing": 3, "wrong_hash": 0}
        for event in [*([self.SAVES] if confirm_saves else []), dry]:
            install.tui_receive(state, ("event", state.run_id, event))
        install.tui_receive(state, ("ended", state.run_id, 1, []))
        self.confirm = self.said(install.tui_view(state, 200, 40))
        install._start_run(state, "install")
        summary = {"event": "summary", "mode": "install", "installed": 3, "up_to_date": 0,
                   "pending": 0, "failed": [], "skipped": [], "left_out": [], "kept": [],
                   "interrupted": False}
        for event in [*([self.SAVES] if install_saves else []), summary]:
            install.tui_receive(state, ("event", state.run_id, event))
        install.tui_receive(state, ("ended", state.run_id, 0, []))
        return state

    def test_unticked_it_is_named_nowhere(self):
        state = self.run_to_result(confirm_saves=False, install_saves=False)
        self.assertNotIn("save directory", self.confirm)
        self.assertEqual(state.screen, "result")
        self.assertNotIn("save directory", self.said(install.tui_outcome(state)[1]))

    @in_full
    def test_kept_the_confirm_screen_and_the_result_name_it(self):
        state = self.run_to_result(confirm_saves=True, install_saves=True)
        self.assertIn(self.LINE, self.confirm)
        self.assertIn(self.RESULT, self.said(install.tui_outcome(state)[1]))


@unittest.skipIf(os.name == "nt" or os.geteuid() == 0,
                 "a folder without search permission is POSIX")
class AFolderThisUserCannotOpen(unittest.TestCase):
    """A BIOS folder under a folder this user cannot enter: given with
    --dest the interface ended on a traceback before its first screen, and
    typed on the folder screen it ended on a crash log."""

    def setUp(self):
        base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, base, True)
        self.lock = base / "lock"
        self.lock.mkdir()
        os.chmod(self.lock, 0o000)
        self.addCleanup(os.chmod, self.lock, 0o755)
        self.dest = self.lock / "system"

    def said(self, state: install.TuiState) -> str:
        return screen_text(install.tui_view(state, 200, 40))

    def test_typed_it_stays_on_the_path_screen(self):
        state = fresh_state()
        state.platform = "retroarch"
        state.stack = ["setup", "folder", "path"]
        state.path_text = str(self.dest)
        self.assertEqual(install.tui_update(state, Key("enter")), [])
        self.assertEqual(state.screen, "path")
        self.assertEqual(state.path_text, str(self.dest))
        self.assertIn(f"This user cannot open {install._short_path(self.lock, state.home)} "
                      "(Permission denied)", self.said(state))

    def test_given_with_dest_opens_the_folder_screen(self):
        args = _args(platform="retroarch", dest=str(self.dest))
        with mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "_mounted_cards", return_value=[]):
            state, effects = install.tui_start(args, "linux")
        self.assertEqual(effects, [])
        self.assertEqual(state.screen, "folder")
        self.assertIn(f"This user cannot open {install._short_path(self.lock, state.home)} "
                      "(Permission denied)", self.said(state))
        self.assertIn("choose another folder", self.said(state))

    def test_chosen_from_the_setups(self):
        state = fresh_state()
        state.setups = [("retroarch", self.dest, "RetroArch")]
        state.setup_folders = install.setup_folders(state.setups)
        state.stack = ["setup"]
        self.assertEqual(install.tui_update(state, Key("enter")), [])
        self.assertEqual(state.screen, "folder")
        # The folder found is the one RetroArch reads: its built-in default
        # is not, and was offered with Enter on "Use this folder".
        self.assertIsNone(state.folder_default)
        self.assertNotIn("reads its BIOS files from", self.said(state))
        self.assertIn(f"This user cannot open {install._short_path(self.lock, state.home)} "
                      "(Permission denied)", self.said(state))

    def test_a_home_it_cannot_open_is_said_on_the_first_screen(self):
        """HOME kept across su without -: detection raised PermissionError
        before the first screen."""
        home = self.lock.parent / "home"
        home.mkdir()
        os.chmod(home, 0o000)
        self.addCleanup(os.chmod, home, 0o755)
        install._DETECTION_REFUSED.clear()
        self.addCleanup(install._DETECTION_REFUSED.clear)
        with mock.patch.dict(os.environ, {"HOME": str(home)}), \
                mock.patch.object(install, "_mounted_cards", return_value=[]):
            state, _effects = install.tui_start(_args(), "linux")
        self.assertIn("Could not look for setups: this user cannot open", self.said(state))

    def test_the_nearest_folder_stops_above_it(self):
        self.assertEqual(install._nearest_folder(self.dest / "deeper"), self.lock)

    def test_a_closed_folder_under_home_hides_nothing_else(self):
        """~/.config/EmuDeck at 000 made detection return nothing, and the
        folder screen offered ~/.config/retroarch/system, which this
        RetroArch does not read: its retroarch.cfg names another."""
        home = self.lock.parent / "home"
        closed = home / ".config" / "EmuDeck"
        closed.mkdir(parents=True)
        cfg = home / ".config" / "retroarch" / "retroarch.cfg"
        cfg.parent.mkdir()
        system = self.lock.parent / "elsewhere" / "system"
        system.mkdir(parents=True)
        cfg.write_text(f'system_directory = "{system}"\n')
        os.chmod(closed, 0o000)
        self.addCleanup(os.chmod, closed, 0o755)
        install._DETECTION_REFUSED.clear()
        self.addCleanup(install._DETECTION_REFUSED.clear)
        with mock.patch.dict(os.environ, {"HOME": str(home)}), \
                mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "_RETROARCH_CONFIGS", {}):
            state, _effects = install.tui_start(_args(), "linux")
        self.assertEqual([setup[:2] for setup in state.setups], [("retroarch", system)])
        screen = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertEqual(screen.count("Could not look for setups: this user cannot open "
                                      "~/.config/EmuDeck (Permission denied)"), 1, screen)

    def test_the_refusal_is_drawn_above_a_full_list(self):
        """With a closed HOME the first screen is the 18 setups: the line,
        drawn under them, was dropped at 80x24 and at 40x15."""
        home = self.lock.parent / "home"
        home.mkdir()
        os.chmod(home, 0o000)
        self.addCleanup(os.chmod, home, 0o755)
        install._DETECTION_REFUSED.clear()
        self.addCleanup(install._DETECTION_REFUSED.clear)
        with mock.patch.dict(os.environ, {"HOME": str(home)}), \
                mock.patch.object(install, "_mounted_cards", return_value=[]):
            state, _effects = install.tui_start(_args(), "linux")
        self.assertEqual(state.screen, "platforms")
        for cols, rows in ((80, 24), (40, 15)):
            with self.subTest(size=f"{cols}x{rows}"):
                lines = install.tui_view(state, cols, rows)
                self.assertEqual(len(lines), rows)
                screen = " ".join(" ".join(lines).split())
                self.assertIn("Could not look for setups", screen)
                self.assertIn("name the BIOS folder with --dest.", screen)
                # The list keeps its focused row in view.
                self.assertIn("RetroArch", screen)

    def test_detection_lines_are_read_not_captured(self):
        """The screen read detection's lines by capturing stdout and stderr,
        and dropped a refusal by comparing its printed text: a folder whose
        name the terminal text escapes was then said twice."""
        closed = self.lock.parent / "esc\x1bape"
        closed.mkdir()
        os.chmod(closed, 0o000)
        self.addCleanup(os.chmod, closed, 0o755)
        install._DETECTION_REFUSED.clear()
        self.addCleanup(install._DETECTION_REFUSED.clear)

        def detect(_os_type: str) -> list:
            install._SETUP_SEARCH.active = True
            try:
                install._is_dir(closed / "bios")
                install.note_detection("Batocera found here, but no folder.")
            finally:
                install._SETUP_SEARCH.active = False
            return []

        with mock.patch.object(install, "detect_platforms", side_effect=detect), \
                mock.patch.object(install, "detect_frontends", return_value=[]), \
                mock.patch.object(install, "_mounted_cards", return_value=[]), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()) as err:
            state, _effects = install.tui_start(_args(), "linux")
        self.assertEqual((out.getvalue(), err.getvalue()), ("", ""))
        self.assertEqual(install._DETECTION_REFUSED, [(closed, "Permission denied")])
        self.assertEqual(len(state.refused), 1)
        self.assertEqual(state.notes, ["Batocera found here, but no folder."])


class AGoesIntoASubfolder(unittest.TestCase):
    """At HOME or a drive root A went into the first "dir" row: a mounted
    card or drive listed first (/mnt/d, the Windows D: drive, then took
    the BIOS files at its root) or .cache."""

    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.home, True)
        self.card = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.card, True)
        self.state = install.TuiState(os_type="linux", home=self.home)
        self.state.platform = "retroarch"
        self.state.stack = ["folder", "browse"]

    def focused(self) -> install.TuiRow:
        return self.state.browse_rows[self.state.focus["browse"]]

    def test_a_card_and_cache_are_passed_over(self):
        (self.home / ".cache").mkdir()
        (self.home / "Games").mkdir()
        with mock.patch.object(install, "_mounted_cards", return_value=[self.card]):
            install._browse_to(self.state, self.home)
        self.assertEqual(self.state.browse_rows[2].value, self.card)
        self.assertEqual(self.focused().label, "Games/")
        self.assertEqual(self.state.status, "")

    def test_with_no_visible_subfolder_a_folder_below_takes_the_focus(self):
        """The focus stayed on Use this folder under the
        sentence that warns against it, and A, A, A installed BizHawk into
        the home folder."""
        (self.home / ".cache").mkdir()
        (self.home / ".config").mkdir()
        with mock.patch.object(install, "_mounted_cards", return_value=[self.card]):
            install._browse_to(self.state, self.home)
        self.assertEqual(self.focused().label, ".cache/")
        self.assertIn("No setup reads BIOS files in the home folder", self.state.status)
        screen = " ".join(" ".join(install.tui_view(self.state, 80, 24)).split())
        self.assertIn("No setup reads BIOS files in the home folder.", screen)

    def test_on_windows_the_other_drives_are_passed_over(self):
        """The card rows are drive roots there (E:\\): at D:\\ the first
        was E:\\, and at E:\\ it was D:\\."""
        (self.home / "Games").mkdir()
        drives = [Path("D:\\"), Path("E:\\")]
        windows = WindowsOs()
        windows.path = types.SimpleNamespace(
            **{name: getattr(os.path, name) for name in dir(os.path)
               if not name.startswith("_")})
        windows.path.exists = lambda path: str(path) in ("C:\\", "D:\\", "E:\\")
        with mock.patch.object(install, "os", windows), \
                mock.patch.object(install, "_mounted_cards", return_value=drives):
            install._browse_to(self.state, self.home)
            self.assertEqual(self.focused().label, "Games/")
            # The drives list keeps its first drive focused.
            install._browse_to(self.state, None)
            self.assertEqual([row.label for row in self.state.browse_rows],
                             ["C:\\", "D:\\", "E:\\"])
            self.assertEqual(self.state.focus["browse"], 0)


class TheFolderScreenSaysWhatItOffers(unittest.TestCase):
    """The folder screen said "usually reads its BIOS files from" for any
    folder it offered: the folder named with --dest, reached by Change
    folder, and the built-in default while the retroarch.cfg found here
    names another. A closed folder found here opened on "No usual
    RetroArch folder here" under the setup that listed it."""

    def said(self, state: install.TuiState) -> str:
        return " ".join(" ".join(install.tui_view(state, 200, 40)).split())

    def test_change_folder_names_the_chosen_folder(self):
        state = checked_state()
        state.stack = ["setup", "plan"]
        mine = Path("/home/user/typed/mybios")
        state.dest = mine
        install._activate(state, install.TuiRow("folder", "Change folder"))
        self.assertEqual(state.screen, "folder")
        screen = self.said(state)
        self.assertNotIn("usually reads", screen)
        self.assertIn(f"The BIOS folder chosen for RetroArch: {mine}", screen)

    def test_another_setup_offers_the_folder_found_here(self):
        state = fresh_state()
        found = Path("/home/user/Games/bios")
        state.setups = [("retroarch", found, "RetroArch")]
        state.setup_folders = install.setup_folders(state.setups)
        state.stack = ["setup", "platforms"]
        install._activate(state, install.TuiRow("platform", "RetroArch", value="retroarch"))
        self.assertEqual(state.folder_default, found)
        self.assertIn(f"RetroArch reads its BIOS files from: {found}", self.said(state))

    def test_with_none_found_the_usual_folder_is_offered(self):
        state = fresh_state()
        state.setups = []
        state.stack = ["setup", "platforms"]
        install._activate(state, install.TuiRow("platform", "RetroArch", value="retroarch"))
        self.assertIn("RetroArch usually reads its BIOS files from:", self.said(state))

    def test_a_closed_folder_found_here_asks_for_another(self):
        state = fresh_state()
        state.stack = ["setup"]
        with mock.patch.object(install, "closed_folder",
                               return_value=(Path("/home/user/lock"), "Permission denied")):
            install.tui_update(state, Key("enter"))
        self.assertEqual(state.screen, "folder")
        screen = self.said(state)
        self.assertNotIn("No usual RetroArch folder here", screen)
        self.assertIn("Choose another folder for RetroArch", screen)

    def test_a_refused_folder_puts_browse_under_a(self):
        for facts in ({"free": 10, "writable": True, "cores": []},
                      {"free": 50 * 1024 ** 3, "writable": False, "cores": []}):
            with self.subTest(facts=facts):
                state = checked_state(facts)
                self.assertEqual(install.tui_rows(state)[0].action, "folder")
                install.tui_update(state, Key("enter"))
                self.assertEqual(state.screen, "folder")
                rows = install.tui_rows(state)
                self.assertEqual(rows[state.focus["folder"]].action, "browse")


class CopyFromStartsInDownloads(unittest.TestCase):
    """A ZIP in Downloads took 18 presses from the first screen: the copy
    browser opened at HOME, under every mounted drive."""

    def test_a_zip_in_downloads_opens_there(self):
        home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, home, True)
        (home / "Downloads").mkdir()
        state = checked_state()
        state.home = home
        with mock.patch.object(install, "_mounted_cards", return_value=[]):
            install._open_from_browser(state)
            self.assertEqual(state.browse_dir, home)
            state.stack.pop()
            (home / "Downloads" / "PSX BIOS.zip").write_bytes(b"")
            install._open_from_browser(state)
        self.assertEqual(state.browse_dir, home / "Downloads")


class NothingFoundIsSaid(unittest.TestCase):
    """With nothing detected the first screen was the list of 18 setups,
    with no line at 40x15 saying nothing was found, which the beginner's
    page names."""

    def test_at_every_size(self):
        with mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]), \
                mock.patch.object(install, "_mounted_cards", return_value=[]):
            state, _effects = install.tui_start(_args(), "linux")
        self.assertEqual(state.screen, "platforms")
        for cols, rows in ((40, 12), (40, 15), (80, 24)):
            with self.subTest(size=f"{cols}x{rows}"):
                screen = " ".join(" ".join(install.tui_view(state, cols, rows)).split())
                self.assertIn("Nothing was found here", screen)
        page = (REPO_ROOT / "wiki" / "first-install.md").read_text(encoding="utf-8")
        self.assertIn("Nothing was found here", page)


class AFocusesNoSystemFolder(unittest.TestCase):
    """At / A went into bin/, and at a drive root holding $RECYCLE.BIN into
    the recycle bin, which Use this folder then took as the BIOS folder."""

    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.home, True)
        self.state = install.TuiState(os_type="linux", home=self.home)
        self.state.platform = "retroarch"
        self.state.stack = ["folder", "browse"]

    def focused(self) -> install.TuiRow:
        return self.state.browse_rows[self.state.focus["browse"]]

    def test_the_recycle_bin_and_restore_points_are_passed_over(self):
        for name in ("$RECYCLE.BIN", "System Volume Information", "Games"):
            (self.home / name).mkdir()
        with mock.patch.object(install, "_mounted_cards", return_value=[]):
            install._browse_to(self.state, self.home)
        self.assertEqual(self.focused().label, "Games/")

    def test_explorer_hidden_folders_are_passed_over(self):
        for name in ("Boot", "Games"):
            (self.home / name).mkdir()
        real_stat = os.stat

        def stat(path, *args, **kwargs):
            result = real_stat(path, *args, **kwargs)
            hidden = 0x2 | 0x4 if Path(path).name == "Boot" else 0
            return types.SimpleNamespace(st_file_attributes=hidden, st_mode=result.st_mode)

        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install.os, "stat", stat):
            install._browse_to(self.state, self.home)
        self.assertEqual(self.focused().label, "Games/")

    def test_at_the_root_no_system_folder_is_focused(self):
        with mock.patch.object(install, "_mounted_cards", return_value=[]):
            install._browse_to(self.state, Path("/"))
        row = self.focused()
        if row.action == "dir":
            self.assertNotIn(row.value.name, install._POSIX_ROOT_SYSTEM)
        names = {r.value.name for r in self.state.browse_rows if r.action == "dir"}
        if "bin" in names and names - install._POSIX_ROOT_SYSTEM - {""}:
            self.assertEqual(row.action, "dir")


class CardFoldersAndNarrowBars(unittest.TestCase):
    """Card folders, refusals and bars at 40 columns, as the screens show
    them."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        patcher = mock.patch.dict(install._DETECTED_OS, {})
        patcher.start()
        self.addCleanup(patcher.stop)

    def start(self, mounts=(), found=(), **given) -> tuple:
        with mock.patch.object(install, "_mounted_cards", return_value=list(mounts)), \
                mock.patch.object(install, "detect_platforms", return_value=list(found)), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            return install.tui_start(_args(**given), "linux")

    def test_a_card_found_by_its_files_gets_its_folder_without_a_question(self):
        """Create the folder? for the Onion card's own
        BIOS, which line mode created."""
        onion = self.root / "ONIONB"
        make_card(onion, "Onion")
        shutil.rmtree(onion / "BIOS")
        state, effects = self.start([onion], platform="onion")
        self.assertEqual(effects, [("fetch", "retroarch")])
        self.assertEqual(state.dest, onion / "BIOS")
        self.assertIn("BIOS is created on ONIONB", state.card_note)

    def test_a_refused_dest_says_the_remedy_that_works(self):
        rocknix = self.root / "ROCKNIX"
        make_card(rocknix, "ROCKNIX")
        stick = self.root / "STICK"
        (stick / "photos").mkdir(parents=True)
        for named, plat, dest, words, never in (
                ("knulli", "knulli", rocknix / "roms" / "bios", "--platform rocknix", "<card>"),
                ("onion", "retroarch", stick, "Name the top folder of the Onion card",
                 "<card>/BIOS")):
            with self.subTest(named=named):
                with contextlib.redirect_stderr(io.StringIO()) as err, \
                        self.assertRaises(SystemExit):
                    reported(install.card_dest, named, plat, dest)
                self.assertIn(words, err.getvalue())
                self.assertNotIn(never, err.getvalue())
        minui = self.root / "MINUI"
        make_card(minui, "MinUI")
        (minui / "Bios").mkdir()
        state = install.TuiState()
        install._card_status(state, install.card_choice("minui", "minui", minui / "Bios"),
                             given=True)
        self.assertIn(f"Run it again with --dest {minui}.", state.status)

    def test_wsl_names_drives_in_line_mode_messages(self):
        """/mnt/f in a refusal where D:\\ was typed."""
        mnt = self.root / "mnt"
        make_card(mnt / "f", "muOS")
        (mnt / "g" / "photos").mkdir(parents=True)
        with mock.patch.dict(install._WSL, {"active": True, "root": str(mnt)}), \
                mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()):
            with contextlib.redirect_stderr(io.StringIO()) as err, \
                    self.assertRaises(SystemExit):
                reported(install.card_dest, "onion", "retroarch", mnt / "f")
            self.assertIn("F:\\ is a muOS card", err.getvalue())
            note = install.card_choice("knulli", "knulli", mnt / "g").note
            self.assertIn("G:\\bios", note)
            self.assertNotIn(str(mnt), note)
            self.assertEqual(install._last_name(str(mnt / "g" / "old")), "old")

    def test_choose_the_card_below_only_when_one_is_mounted(self):
        muos = self.root / "MUOS"
        make_card(muos, "muOS")
        stick = self.root / "USBSTICK"
        (stick / "photos").mkdir(parents=True)
        with mock.patch.object(install, "_mounted_cards", return_value=[muos, stick]):
            state, _effects = self.start([muos, stick], platform="onion")
            rows = install.tui_rows(state)
            state.focus["folder"] = next(index for index, row in enumerate(rows)
                                         if row.action == "browse")
            install.tui_update(state, Key("enter"))
            self.assertEqual(state.screen, "browse")
            self.assertIn("No Onion card is mounted", state.status)
            focused = install.tui_rows(state)[state.focus["browse"]]
            self.assertEqual(focused.value, stick)

    def test_type_a_path_says_f1_and_f1_says_more(self):
        muos = self.root / "MUOS"
        make_card(muos, "muOS")
        with mock.patch.object(install, "_mounted_cards", return_value=[]):
            state, _effects = self.start(platform="onion")
        stick = self.root / "STICK"
        stick.mkdir()
        state.stack.append("path")
        install._card_status(state, install.card_choice("Onion", "retroarch", stick))
        text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertIn("F1 says more.", text)
        self.assertNotIn("? says more", text)
        install.tui_update(state, Key("f1"))
        self.assertTrue(state.help)
        help_text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertIn("Onion keeps .tmp_update at the root of its card", help_text)

    def test_batocera_on_a_computer_offers_its_share(self):
        stick = self.root / "SHARE"
        stick.mkdir()
        state, _effects = self.start([stick])
        state.stack = ["platforms"]
        state.focus["platforms"] = install._platform_focus(state, "batocera")
        with mock.patch.object(install, "_mounted_cards", return_value=[stick]):
            install.tui_update(state, Key("enter"))
            rows = install.tui_rows(state)
            text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertEqual(state.screen, "folder")
        self.assertNotIn("/userdata/bios", text)
        self.assertIn("SHARE drive", text)
        self.assertEqual([row.action for row in rows], ["share", "browse", "type"])
        self.assertEqual(rows[0].value, stick / "bios")

    def test_the_first_screen_bar_says_quit(self):
        state, _effects = self.start()
        self.assertEqual(state.stack, ["platforms"])
        self.assertIn("B/Esc Quit", install._TUI_VIEWS["platforms"](state, 80, 24)[2])
        state.stack = ["setup", "platforms"]
        self.assertIn("B/Esc Back", install._TUI_VIEWS["platforms"](state, 80, 24)[2])

    def test_a_pad_result_prints_no_command(self):
        """A shell command on a controller-only screen."""
        state = _installed_state(self.root / "bios")
        state.summary["kept"] = [{"folder": str(self.root / "kept"), "files": 1}]
        state.pad = "muxterm"
        _title, lines = install.tui_outcome(state)
        text = " ".join(lines)
        self.assertNotIn("install.py", text)
        self.assertIn("kept in", text)
        state.pad = "keys"
        self.assertIn("Same choice without questions:", install.tui_outcome(state)[1])

    def test_the_checking_screen_is_titled_as_the_plan(self):
        state = install.TuiState()
        state.platform, state.dest = "retroarch", self.root / "bios"
        install._DETECTED_OS[("retroarch", state.dest)] = "ArkOS"
        state.stack = ["checking"]
        text = " ".join(install.tui_view(state, 80, 24))
        self.assertIn("ArkOS (RetroArch files):", text)

    def test_the_backup_line_survives_forty_columns(self):
        """Under the pack and copy split it was cut."""
        state = checked_state()
        state.found = [found("gba_bios.bin", "/media/old")]
        state.check = planned(CHECK, ["gba_bios.bin"])
        lines = [str(line) for line in install._plan_lines(state.check, state.dest, state)]
        self.assertTrue(any("copied from this machine" in line for line in lines), lines)
        counts = next(index for index, line in enumerate(lines) if " in place, " in line)
        self.assertTrue(lines[counts + 1].startswith("The 1 wrong copy is replaced"), lines)

    def test_an_empty_folder_is_said_once(self):
        old = self.root / "USBSTICK"
        old.mkdir()
        state = checked_state()
        state.offline = True
        state.from_folders = [old]
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: install.OFFLINE_FLAG_VALUE}):
            lines = [str(line) for line in install._plan_lines(state.check, state.dest,
                                                              state)]
        said = [line for line in lines if "USBSTICK" in line]
        self.assertEqual(said, ["USBSTICK holds none of these files: run the installer again "
                                "with a pack (--from-pack) or without --offline."])

    def test_amberelec_keeps_its_files_on_the_games_part(self):
        self.assertEqual(install.card_where("AmberELEC", ""),
                         "on the games part of its SD card")
        files = [{"dest": "bios/a.bin"}, {"dest": "bios/Machines/b.xml"}]
        self.assertEqual(install.shown_bios_folder(self.root, files), self.root / "bios")
        self.assertEqual(install.shown_bios_folder(self.root, [{"dest": "a.bin"}]),
                         self.root)

    def test_a_save_directory_left_out_has_one_wording(self):
        files = [{"dest": "keys.txt", "root": "save", "sha1": "0" * 40, "size": 1}]
        kept, left = install.place_save_entries(files, self.root / "BIOS",
                                                {"platform": "retroarch", "save_directory": {
                                                    "folder": "saves", "by_core": False},
                                                 "base_destination": "system"},
                                                None, "RetroArch")
        self.assertIn("left out: its place is not known. Name it with --save-dir.",
                      "\n".join(install.save_lines(kept, left, self.root / "BIOS",
                                                   "RetroArch")))


if __name__ == "__main__":
    unittest.main()
