"""Packs, cores and games on the full screen, and the words the docs share with it."""

from __future__ import annotations

import tests
from tests import loopback
from tests.sources import script_paths, script_source

import contextlib
import hashlib
import io
import json
import os
import queue
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import install
from tests.test_install_app import make_card
from tests.test_install_selection import FakeRepository
from tests.netguard import module_guard
from tests.tuisupport import (
    _args, BUILDER_FLOOR, CHECK, checked_state, DriveRuns, engine_events, FILES, fresh_state,
    games_part, games_state, HOME, in_full, install_run, Key, LineModeRuns, MANIFEST, PLAN, press,
    ProvenRuns, Pty, pty, pyte, REPO_ROOT, reported, SIZES, SYSTEM_DIR, SYSTEMS,
)


# No connection off the loopback and no card of the host reaches a test,
# in this process or one it starts: the module fails at its end when one is tried.
setUpModule, tearDownModule = module_guard("test_tui_packs")


class PacksWordingAndDocs(unittest.TestCase):
    """What the screen, the packs, the
    wording and the docs answer, line mode's parity being in
    LineModeAndScreenDecideAlike."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        install.LOCAL.reset()
        self.addCleanup(install.LOCAL.reset)

    @unittest.skipUnless(pyte and pty and hasattr(pty, "fork") and shutil.which("script"),
                         "the line mode run needs a pty")
    def test_the_printed_command_makes_the_same_choice(self):
        """"Same choice without
        questions" left out the folder chosen at a question and the file
        list, and installed elsewhere or was refused. Run as printed, it
        finds every file of the choice in place and nothing else."""
        with FakeRepository() as repo:
            home = repo.root / "home"
            home.mkdir()
            listing = repo.root / "install" / "retroarch.json"
            env = {**repo.env(), "HOME": str(home), "RETROBIOS_OS": "linux", "TERM": "xterm",
                   "XDG_CONFIG_HOME": str(home / ".config")}
            env.pop("RETROBIOS_BOOTSTRAP", None)
            command = " ".join(shlex.quote(part) for part in [
                sys.executable, str(REPO_ROOT / "install.py"), "--plain",
                "--manifest", str(listing)])
            proc = subprocess.run(
                ["script", "-qec", command, "/dev/null"],
                # Enter on RetroArch, first of the setups that read its list
                #, then its folder.
                input=f"\n{repo.dest}\nc\n2\n2\n\n", env=env, capture_output=True,
                text=True, timeout=120, check=False)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            installed = repo.installed()
            self.assertEqual(installed, ["pcsx/extra.bin", "scph5501.bin"])
            printed = re.search(r"Same choice without questions: (.+)", proc.stdout)[1]
            words = shlex.split(printed.strip())
            self.assertEqual(words[:2], ["python3", "install.py"])
            for option in ("--dest", "--manifest", "--system"):
                self.assertIn(option, words)
            again = subprocess.run(
                [sys.executable, str(REPO_ROOT / "install.py"), *words[2:], "--dry-run",
                 "--events"], env=env, capture_output=True, text=True, timeout=120,
                check=False, stdin=subprocess.DEVNULL)
            files = [json.loads(line) for line in again.stdout.splitlines()
                     if '"event": "file"' in line]
            self.assertEqual(sorted(event["dest"] for event in files), installed)
            self.assertTrue(all(event["state"] == "present" for event in files))

    # a pack's own list records its systems.

    @unittest.skipIf(sys.version_info < BUILDER_FLOOR,
                     "generate_pack.py's context managers need Python 3.9")
    def test_a_pack_records_the_systems_of_its_files(self):
        from packs import scope

        install_list = {"files": [{"dest": "a.bin", "systems": ["3do"]},
                                  {"dest": "b/c.bin", "systems": []}],
                        "system_titles": {"3do": "3DO Interactive Multiplayer"},
                        "system_names": {"3do": ["3do"]}}
        manifest = {"files": [{"path": "a.bin"}, {"path": "b/c.bin"}, {"path": "README.md"}]}
        scope.annotate_pack_systems(manifest, scope.pack_systems(install_list))
        self.assertEqual([entry.get("systems") for entry in manifest["files"]],
                         [["3do"], [], None])
        self.assertEqual(manifest["system_titles"], {"3do": "3DO Interactive Multiplayer"})
        source = script_source("generate_pack.py")
        self.assertIn("pack_systems_by_name=systems_for", source)
        schema = json.loads((REPO_ROOT / "schemas" / "pack-manifest.schema.json").read_text())
        self.assertIn("systems", schema["properties"]["files"]["items"]["properties"])

    def pack(self, systems: bool) -> Path:
        from tests.test_install_offline import GBA, US

        members = {"scph5501.bin": US, "gba_bios.bin": GBA}
        listed = [{"path": path, "sha1": hashlib.sha1(data).hexdigest(),
                   "md5": hashlib.md5(data).hexdigest(), "size": len(data),
                   "status": "verified", "name": path,
                   **({"systems": ["sony-playstation" if "scph" in path else "nintendo-gba"]}
                      if systems else {})} for path, data in members.items()]
        folder = self.root / ("new" if systems else "old")
        folder.mkdir()
        path = folder / "RetroArch_v1_BIOS_Pack.zip"
        with zipfile.ZipFile(path, "w") as archive:
            for member, data in members.items():
                archive.writestr(member, data)
            archive.writestr("manifest.json", json.dumps({
                "files": listed, **({"system_titles": {"nintendo-gba": "Game Boy Advance"}}
                                    if systems else {})}))
        return path

    def test_system_works_with_a_pack_alone(self):
        dest = self.root / "system"
        dest.mkdir()
        new = self.pack(True)
        events, _text = engine_events(_args(from_pack=[new], dest=dest, platform="retroarch",
                                            system=["nintendo-gba"], check=True, events=True,
                                            no_input=True, declared_only=False))
        files = [event["dest"] for event in events if event["event"] == "file"]
        self.assertEqual(files, ["gba_bios.bin"])
        # The screen offers Choose systems with that pack, titled from it.
        install.LOCAL.pack = install.PackSource([new])
        manifest = install.LOCAL.pack.manifest("retroarch")
        self.assertEqual(manifest["system_titles"], {"nintendo-gba": "Game Boy Advance"})
        state = checked_state()
        state.manifest = manifest
        self.assertIn("systems", [row.action for row in install.tui_rows(state)])
        # An older pack names the remedy that works.
        old = self.pack(False)
        install.LOCAL.reset()
        err = io.StringIO()
        install.LOCAL.pack = install.PackSource([old])
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit):
            reported(install._requested_narrowing, _args(system=["nintendo-gba"]), "retroarch",
                     install.LOCAL.pack.manifest("retroarch")["files"], [])
        self.assertIn("Add --manifest FILE, a copy of install/retroarch.json", err.getvalue())
        self.assertNotIn("older release", err.getvalue())

    def test_a_pack_cannot_write_escapes_through_its_system_names(self):
        """The titles and ids a pack
        records reached print() raw in the systems list."""
        from tests.test_install_offline import GBA, US

        members = {"scph5501.bin": US, "gba_bios.bin": GBA}
        listed = [{"path": path, "sha1": hashlib.sha1(data).hexdigest(), "size": len(data),
                   "systems": ["bad\nid" if "scph" in path else "nintendo-gba"]}
                  for path, data in members.items()]
        path = self.root / "RetroArch_v1_BIOS_Pack.zip"
        with zipfile.ZipFile(path, "w") as archive:
            for member, data in members.items():
                archive.writestr(member, data)
            archive.writestr("manifest.json", json.dumps({
                "files": listed,
                "system_titles": {"nintendo-gba": "\x1b]0;x\x07GBA", "bad\nid": "Bad"},
                "system_names": {"nintendo-gba": ["\x1b[2J"]}}))
        pack = install.PackSource([path])
        self.addCleanup(pack.close)
        manifest = pack.manifest("retroarch")
        self.assertEqual(manifest.get("system_titles", {}), {})
        self.assertEqual(manifest.get("system_names", {}), {})
        self.assertNotIn("systems", next(f for f in manifest["files"]
                                         if f["dest"] == "scph5501.bin"))
        # What _pick prints and the command line go through screen_text.
        with contextlib.redirect_stdout(io.StringIO()) as out, \
                mock.patch.object(install, "_ask", side_effect=["1"]):
            install._pick("Systems:", [("x", [])], labels={"x": "\x1b]0;x\x07GBA"})
        self.assertNotIn("\x1b", out.getvalue())
        self.assertIn("?]0;x?GBA", out.getvalue())
        with contextlib.redirect_stdout(io.StringIO()) as out, \
                mock.patch.object(install, "_ask", side_effect=["c", "1", "q"]), \
                contextlib.suppress(SystemExit):
            install._prompt_custom_selection(install.MenuContext("retroarch",
                                                                 [{"dest": "a", "size": 1, "systems": ["x"], "cores": None}],
                                                                 []),
                                             command=lambda _choice: "python3 install.py --dest '\x1b[2J'")
        self.assertNotIn("\x1b", out.getvalue())

    def test_the_home_folder_is_said_on_the_plan(self):
        """The plan named ~ and said nothing more."""
        state = checked_state()
        state.dest = state.home
        lines = " ".join(str(line) for line in install._plan_lines(state.check, state.dest,
                                                                     state))
        self.assertIn("No setup reads BIOS files in the home folder.", lines)

    def test_systems_seen_and_left_unchanged_keep_the_exact_plan(self):
        """Opening Choose systems on a --system plan and
        going back turned the exact plan into an estimate."""
        state = checked_state()
        state.cli_systems = ["nintendo-gba"]
        state.systems = [row for row in state.systems if row["system"] == "nintendo-gba"]
        state.ticked = {"nintendo-gba"}
        state.checked_flags = install.tui_flags(state)
        exact = install.tui_view(state, 80, 24)
        rows = install.tui_rows(state)
        state.focus["plan"] = next(i for i, row in enumerate(rows) if row.action == "systems")
        press(state, "enter")
        self.assertEqual(state.screen, "checking")
        # The check of every system comes back, the ticks kept.
        for event in [*FILES, *SYSTEMS, CHECK, PLAN]:
            install.tui_receive(state, ("event", state.run_id, event))
        with mock.patch.object(install, "_tui_folder_facts", return_value={
                "free": 50 * 1024 ** 3, "writable": True, "cores": []}):
            install.tui_receive(state, ("ended", state.run_id, 0, []))
        self.assertEqual((state.screen, state.ticked), ("systems", {"nintendo-gba"}))
        press(state, "esc")
        self.assertEqual(state.screen, "plan")
        self.assertEqual(install.tui_view(state, 80, 24), exact)
        # Ticks changed: an estimate, without the whole list's counts.
        state.focus["plan"] = next(i for i, row in enumerate(install.tui_rows(state))
                                   if row.action == "systems")
        press(state, "enter")
        for event in [*FILES, *SYSTEMS, CHECK, PLAN]:
            install.tui_receive(state, ("event", state.run_id, event))
        with mock.patch.object(install, "_tui_folder_facts", return_value={
                "free": 50 * 1024 ** 3, "writable": True, "cores": []}):
            install.tui_receive(state, ("ended", state.run_id, 0, []))
        state.ticked = {"sony-playstation"}
        press(state, "esc")
        text = " ".join(install.tui_view(state, 120, 40))
        self.assertIn("About", text)
        self.assertNotIn(f"{CHECK['present']} in place,", text)

    def test_the_copy_browser_leaves_the_card_being_installed_to(self):
        """The card installed to was focused and taken,
        and WSL rows read /mnt/d where every other screen writes D:."""
        dest_card, old = self.root / "d", self.root / "e"
        make_card(dest_card, "Onion")
        old.mkdir()
        state = install.TuiState(os_type="wsl", home=self.root / "home")
        (self.root / "home").mkdir()
        state.platform, state.dest = "retroarch", dest_card / "BIOS"
        with mock.patch.object(install, "_mounted_cards", return_value=[dest_card, old]), \
                mock.patch.dict(install._WSL, {"active": True, "root": str(self.root)}):
            install._open_from_browser(state)
            rows = install.tui_rows(state)
            self.assertEqual(rows[state.focus["browse"]].value, old)
            # Not offered at all, as line mode's Copy from leaves it out.
            self.assertNotIn("D: (Onion card)", [row.label for row in rows])
            self.assertIn("E: (card or drive)", [row.label for row in rows])
            # Reached through its folders all the same, it is refused.
            install._browse_to(state, dest_card)
            state.focus["browse"] = 0
            press(state, "enter")
        self.assertEqual(state.screen, "browse")
        self.assertIn("That is the card being installed to", state.status)
        self.assertEqual(state.from_folders, [])

    def test_typing_a_filter_names_the_keys_that_end_it(self):
        """While typing, the bar named Tick and Help,
        the focus stayed on None, F1 ended the typing, and a filter that
        matched nothing said nothing."""
        state = checked_state()
        press(state, "down", "enter")
        self.assertEqual(state.screen, "systems")
        press(state, "/")
        rows = install.tui_rows(state)
        self.assertEqual(rows[state.focus["systems"]].action, "filter")
        bar = install.tui_view(state, 80, 24)[-1]
        self.assertEqual(bar.strip(), "Enter Done  Esc Clear")
        press(state, "s", "e", "g", "a", " ", "?")
        self.assertEqual(state.filters["systems"], "sega ?")
        self.assertIn("No system matches 'sega ?'.", " ".join(install.tui_view(state, 80, 24)))
        press(state, "f1")
        self.assertTrue(state.help)
        press(state, "x")
        self.assertEqual((state.help, state.editing), (False, "systems"))

    def test_a_computer_finds_its_own_setups(self):
        """Windows and mac matched nothing, RetroBat
        came 27th on Windows, and a Batocera SHARE drive was not found."""
        names = {install._row_name(row) for row in install.setup_list([], set(), "windows",
                                                                      "windows")}
        self.assertEqual(names, {"retroarch", "retrobat", "emudeck", "bizhawk"})
        self.assertEqual({install._row_name(row) for row in install.setup_list(
            [], set(), "mac", "darwin")}, {"retroarch"})
        for os_type in ("windows", "wsl"):
            rows = [install._row_name(row) for row in install.setup_list([], set(), "", os_type)]
            self.assertEqual(rows[:3], ["retroarch", "retrobat", "emudeck"], os_type)
        share = self.root / "SHARE"
        (share / "system").mkdir(parents=True)
        (share / "system" / "batocera.conf").write_text("system.hostname=BATOCERA\n")
        with mock.patch.object(install, "_mounted_cards", return_value=[share]), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.dict(install._DETECTED_OS, {}):
            setups, mounted = install.found_setups("linux")
        self.assertEqual(setups, [("batocera", share / "bios", "Batocera SHARE drive (SHARE)")])
        self.assertEqual(mounted, {("batocera", share / "bios")})

    def test_a_pack_preview_installs_from_the_pack(self):
        """"23 files to download" on a --from-pack run."""
        state = checked_state()
        state.stack.append("preview")
        state.dry = dict(CHECK)
        install.LOCAL.pack = mock.Mock(name="pack")
        self.assertIn("to install from the pack", install._pager_items(state)[0])

    @in_full
    def test_scroll_is_named_only_where_the_text_scrolls(self):
        """"Up/Down Scroll" over nine lines that fit."""
        state = checked_state()
        state.stack = ["result"]
        state.summary = {"installed": 1, "up_to_date": 0, "pending": 0, "failed": [],
                         "kept": [], "skipped": [], "left_out": [], "interrupted": False}
        state.code = 0
        self.assertNotIn("Scroll", install.tui_view(state, 80, 40)[-1])
        state.summary["failed"] = [{"dest": f"f{n}.bin", "reason": f"r{n}"} for n in range(20)]
        self.assertIn("Scroll", install.tui_view(state, 80, 12)[-1])

    def test_gptokeyb_names_select_then_start(self):
        """"Start+Select" on the bars, "Select, then
        Start" in the help and the docs."""
        state = checked_state()
        state.pad = "gptokeyb"
        state.stack.append("checking")
        self.assertIn("Select+Start Quit", install.tui_view(state, 80, 24)[-1])
        self.assertEqual(install.TUI_ROUTES["gptokeyb"].stop[1], "B or Select+Start")

    def test_nothing_to_confirm_is_titled_so(self):
        """Confirm over nothing to confirm, offline."""
        state = checked_state()
        state.stack.append("confirm")
        state.dry = dict(CHECK)
        state.offline = True
        self.assertIn("Nothing to install", install.tui_view(state, 80, 24)[0])

    def test_another_folder_for_a_card_setup_asks_for_its_card(self):
        """A full Onion card offered another folder for
        RetroArch, and the result said to choose another folder."""
        onion = self.root / "ONION"
        make_card(onion, "Onion")
        state = checked_state({"free": 1024, "writable": True, "cores": []})
        state.dest = onion / "BIOS"
        with mock.patch.object(install, "_mounted_cards", return_value=[onion]), \
                mock.patch.dict(install._DETECTED_OS, {("retroarch", onion / "BIOS"): "Onion"}):
            state.facts = {**install._tui_folder_facts(state), "free": 1024}
            plan = " ".join(install.tui_view(state, 120, 40))
            self.assertIn("Free some space on the card first.", plan)
            rows = install.tui_rows(state)
            state.focus["plan"] = next(i for i, row in enumerate(rows) if row.action == "folder")
            press(state, "enter")
            view = " ".join(install.tui_view(state, 120, 40))
            state.stack = ["result"]
            state.no_space = (90010, 36 * 1024)
            state.full_drive = install.full_drive_words(state)
            _title, lines = install.tui_outcome(state)
        self.assertEqual(state.card_bound, ("Onion", "BIOS"))
        self.assertIn("The BIOS folder chosen for Onion:", view)
        self.assertIn("Free some space on the card, then run again.", lines)

    def test_the_dest_example_is_this_systems(self):
        """/media/$USER/SHARE/bios on macOS and Windows."""
        self.assertEqual(install.drive_example("darwin", "SHARE", "bios"), "/Volumes/SHARE/bios")
        self.assertEqual(install.drive_example("wsl", "SHARE", "bios"), "/mnt/e/bios")
        self.assertEqual(install.drive_example("windows", "SHARE", "bios", "batocera"),
                         "\\\\BATOCERA\\share\\bios")
        self.assertEqual(install.drive_example("windows", "<card>"), "E:\\")
        self.assertEqual(install.drive_example("linux", "<card>"), "/media/$USER/<card>")

    def test_the_copy_browser_opens_on_a_path_without_dot_dot(self):
        """--from t/../packx opened the browser on t/.."""
        packx = self.root / "packx"
        packx.mkdir()
        state, _effects = install.tui_start(
            _args(**{"from": [str(self.root / "t" / ".." / "packx")]}), "linux", detect=False)
        self.assertEqual(state.from_folders, [packx])

    def test_no_clause_semicolon_in_what_the_installer_prints(self):
        self.assertNotIn("; ", " ".join(install.build_parser().format_help().split()))
        source = Path(install.__file__).read_text(encoding="utf-8")
        for said in ("to fetch them; a file", "every board; --target", "with the system; ",
                     "no core list; ", "{retrodeck_json}; assuming", "REGION_ALIASES)}; ",
                     "extracted; ~/.config", "read-only; 1 once"):
            self.assertNotIn(said, source)

    def test_the_docs_say_what_the_installer_does(self):
        page = (REPO_ROOT / "wiki" / "installer.md").read_text(encoding="utf-8")
        menu = page[re.search(r"RetroArch: \d+ files, [\d.]+ [KMG]B[.,]", page).start():]
        menu = menu[:menu.index("```")]
        self.assertIn("BIOS folder:", menu)
        self.assertIn("f) copy from a folder or an old card", menu)
        # The owner's request of 2026-10-27: game data counted apart, g.
        # test_doc_pages_installer checks that the figures add up.
        self.assertRegex(menu, r"\d+ BIOS files \([\d.]+ [KMG]B\)(,| and) \d+ game data files")
        self.assertRegex(menu, r"g\) Game data: kept \(\d+ files")
        env = page[page.index("## Environment overrides"):]
        self.assertIn("`TERMINFO`", env)
        self.assertIn("`TERMINFO_DIRS`", env)
        for path in script_paths("generate_installer_doc.py"):
            script = path.read_text(encoding="utf-8")
            self.assertEqual(
                [n for n, line in enumerate(script.splitlines(), 1) if len(line) > 100], [])


class OnePowerShellRule(unittest.TestCase):
    """The words of a command asked RETROBIOS_BOOTSTRAP
    or the detected system, its line ends RETROBIOS_BOOTSTRAP or os.name:
    with RETROBIOS_OS=windows on Linux one command had PowerShell's quotes
    and sh's line ends, and pasted into either shell it broke."""

    def test_the_words_and_the_line_ends_read_one_rule(self):
        cases = ((None, "windows", True), ("sh", "windows", False), ("ps1", "linux", True),
                 (None, "linux", False), ("sh", "linux", False))
        for bootstrap, os_type, powershell in cases:
            with self.subTest(bootstrap=bootstrap, os_type=os_type):
                hint = install.Invocation()
                hint.os_type, hint.options = os_type, [("--system", "it's")]
                env = {key: value for key, value in os.environ.items()
                       if key != "RETROBIOS_BOOTSTRAP"}
                if bootstrap:
                    env["RETROBIOS_BOOTSTRAP"] = bootstrap
                with mock.patch.dict(os.environ, env, clear=True):
                    self.assertEqual(hint.powershell(), powershell)
                    text = hint.command("retroarch", Path("/home/me/My Games/bios"))
                    # Line mode's wrap reads the run's Invocation, the
                    # screen's the one that made its command.
                    with mock.patch.object(install, "_INVOCATION", hint):
                        wrapped = install._command_wrap(text, 40)
                    drawn = [str(line) for line in install._text_lines(
                        [install._command_line(text, hint)], 40)]
                for lines in (wrapped, drawn):
                    lines = [line for line in lines if line.strip()]
                    ends = {line.rstrip()[-1] for line in lines[:-1]}
                    self.assertEqual(ends, {"`" if powershell else "\\"})
                    words = " ".join(lines)
                    self.assertIn("'it''s'" if powershell else shlex.quote("it's"), words)


class EachDataTreeReadOnce(unittest.TestCase):
    """The count line, the check, the events and the
    install each read and hashed every data tree in place, twice per run
    on an SD card through a reader."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.dest = self.root / "bios"
        bios = b"bios bytes"
        (self.dest / "gba_bios.bin").parent.mkdir(parents=True)
        (self.dest / "gba_bios.bin").write_bytes(bios)
        trees = []
        for ref, files, held in (("dolphin-sys", {"Sys/a.bin": b"a", "Sys/b.bin": b"bb"}, 2),
                                 ("ppsspp", {"assets/c.bin": b"ccc", "assets/d.bin": b"d"}, 1)):
            for rel, data in list(files.items())[:held]:
                (self.dest / ref / rel).parent.mkdir(parents=True, exist_ok=True)
                (self.dest / ref / rel).write_bytes(data)
            trees.append({"ref": ref, "dest": ref, "type": "zip",
                          "url": f"https://example.invalid/{ref}.zip",
                          "systems": ["nintendo-gba"],
                          "files": {rel: {"sha1": hashlib.sha1(data).hexdigest(),
                                          "size": len(data)} for rel, data in files.items()}})
        self.list = self.root / "retroarch.json"
        self.list.write_text(json.dumps({
            "manifest_version": 2, "platform": "retroarch", "data_directories": trees,
            "files": [{"dest": "gba_bios.bin", "sha1": hashlib.sha1(bios).hexdigest(),
                       "size": len(bios), "repo_path": "bios/gba_bios.bin", "cores": None,
                       "systems": ["nintendo-gba"]}]}))

    def test_each_tree_is_hashed_once_per_run(self):
        real = install.data_directory_state
        for mode in ("check", "events", "dry_run", "yes"):
            with self.subTest(mode=mode):
                calls = []

                def counted(entry, bios_path, calls=calls):
                    calls.append(entry["ref"])
                    return real(entry, bios_path)

                given = {"events": True, "check": True} if mode == "events" else {mode: True}
                stream = io.StringIO() if mode == "events" else None
                with mock.patch.object(install, "data_directory_state", counted), \
                        mock.patch.object(install.EVENTS, "stream", stream), \
                        mock.patch.object(install, "detect_os", return_value="linux"), \
                        mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}), \
                        contextlib.redirect_stdout(io.StringIO()), \
                        contextlib.redirect_stderr(io.StringIO()), \
                        contextlib.suppress(SystemExit):
                    try:
                        install._install(_args(platform="retroarch", dest=self.dest,
                                               manifest=self.list, no_input=True,
                                               declared_only=False, **given), io.StringIO())
                    finally:
                        install.LOCAL.reset()
                self.assertEqual(sorted(calls), ["dolphin-sys", "ppsspp"])


def core_list(path: Path, files: list) -> Path:
    path.write_text(json.dumps({"manifest_version": 2, "platform": "retroarch",
                                "categorized": True, "base_destination": "system",
                                "save_directory": {"folder": "saves", "by_core": True},
                                "files": files}), encoding="utf-8")
    return path


class CoresListAndFolderFailures(unittest.TestCase):
    """The cores the run accepts, one tick
    list, a folder failure said as it happened, every proven card named,
    reads that show, and tests that leave the host alone."""

    setUp = LineModeRuns.setUp
    line_run = LineModeRuns.line_run
    entry = staticmethod(LineModeRuns.entry)
    drive = DriveRuns.drive
    first_screen = DriveRuns.first_screen
    line_from = ProvenRuns.line_from

    # Root cause 1: the cores a choice is made among are the run's.

    def files(self) -> list:
        entry = self.entry
        return [
            entry("scph5501.bin", b"S" * 8, ["sony-playstation"]),
            entry("pcsx/extra.bin", b"P" * 4, ["sony-playstation"], cores=["pcsx_rearmed"]),
            entry("fc/disksys.rom", b"F" * 8, ["nintendo-famicom-disk"], cores=["mesen"]),
            # Read from the save directory alone: set aside where it is not known.
            entry("3ds/aes_keys.txt", b"K" * 4, ["nintendo-3ds"], cores=["azahar"],
                  root="save"),
            # Game data alone: --no-game-data leaves its core no file.
            entry("quake/pak0.pak", b"Q" * 4, ["other"], cores=["tyrquake"],
                  category="game_data"),
        ]

    def check_events(self, *extra: str) -> list:
        listing = core_list(self.root / "cores.json", self.files())
        dest = self.root / "dest"
        dest.mkdir(exist_ok=True)
        done = install_run("--platform", "retroarch", "--dest", str(dest), "--manifest",
                           str(listing), "--check", "--events", *extra,
                           env={"HOME": str(self.root / "home"),
                                "RETROBIOS_INSTALL_OFFLINE": "1"})
        return [json.loads(line) for line in done.stdout.splitlines() if line.startswith("{")]

    def cores_state(self, events: list, no_game_data: bool = False) -> install.TuiState:
        state = checked_state()
        state.manifest = {"manifest_version": 2, "platform": "retroarch", "categorized": True,
                          "files": self.files()}
        state.set_aside = set(next(event for event in events
                                   if event["event"] == "set_aside")["dests"])
        state.no_game_data = no_game_data
        return state

    def test_cores_lists_what_the_run_accepts_and_an_untick_runs(self):
        """Cores listed 189 cores where --core accepted 181,
        and an untick sent the 8 save-folder-only cores: "unknown core"."""
        events = self.check_events()
        self.assertEqual(next(e for e in events if e["event"] == "set_aside")["dests"],
                         ["3ds/aes_keys.txt"])
        state = self.cores_state(events)
        self.assertNotIn("azahar", install.tui_choices(state)["cores"])
        state.stack = ["setup", "plan", "options", "cores"]
        row = next(r for r in install.tui_rows(state) if r.value == "mesen")
        install._tick(state, row, False)
        cores = [value for flag, value in install.tui_flags(state) if flag == "--core"]
        self.assertEqual(sorted(cores), ["pcsx_rearmed", "tyrquake"])
        listing = self.root / "cores.json"
        done = install_run("--platform", "retroarch", "--dest", str(self.root / "dest"),
                           "--manifest", str(listing), "--dry-run",
                           *[f"--core={core}" for core in cores],
                           env={"HOME": str(self.root / "home"),
                                "RETROBIOS_INSTALL_OFFLINE": "1"})
        self.assertNotIn("unknown core", done.stdout + done.stderr)

    def test_both_modes_count_out_of_the_cores_the_run_keeps(self):
        """Line mode said "1 of 181 cores", the screen
        "1 of 189", and 22 more under --no-game-data."""
        for no_game_data in (False, True):
            with self.subTest(no_game_data=no_game_data):
                extra = ("--no-game-data",) if no_game_data else ()
                state = self.cores_state(self.check_events(*extra), no_game_data)
                expected = ["mesen", "pcsx_rearmed"] + ([] if no_game_data else ["tyrquake"])
                self.assertEqual(install.tui_choices(state)["cores"], expected)
                listing = core_list(self.root / "line.json", self.files())
                # A folder not named system: the save directory is not known.
                text, _asked = self.line_run(
                    _args(manifest=listing, dest=self.root / "dest", declared_only=False,
                          dry_run=True, no_game_data=no_game_data), ["c", "", "1"])
                head = text.rsplit("Counted again for these choices", 1)[1]
                self.assertIn(f"1 of {len(expected)} cores", head)
                state.cores = ["mesen"]
                self.assertIn(f"1 of {len(expected)}",
                              next(r.label for r in install.tui_rows(
                                  self.options(state)) if r.action == "cores"))

    @staticmethod
    def text(state: install.TuiState, cols: int, rows: int) -> str:
        """The frame drawn, its folded lines joined into one text."""
        return " ".join(" ".join(str(line).split()) for line in
                        install.tui_view(state, cols, rows))

    @staticmethod
    def options(state: install.TuiState) -> install.TuiState:
        state.stack = ["setup", "plan", "options"]
        return state

    def test_an_untick_keeps_the_other_systems_cores(self):
        """With --system sony-playstation, one untick on
        pcsx_rearmed cleared mesen, drawn ticked under the other systems."""
        state = checked_state()
        state.ticked = {"sony-playstation"}
        state.stack = ["setup", "plan", "options", "cores"]
        state.cores_all = True
        boxes = {r.value: r.label[:3] for r in install.tui_rows(state) if r.action == "core"}
        self.assertEqual(boxes, {"mesen": "[x]", "pcsx_rearmed": "[x]"})
        row = next(r for r in install.tui_rows(state) if r.value == "pcsx_rearmed")
        install._tick(state, row, None)
        boxes = {r.value: r.label[:3] for r in install.tui_rows(state) if r.action == "core"}
        self.assertEqual(boxes, {"mesen": "[x]", "pcsx_rearmed": "[ ]"})
        # The --core given is the cores ticked, exactly.
        self.assertEqual([v for f, v in install.tui_flags(state) if f == "--core"], ["mesen"])

    def test_a_core_of_another_system_is_not_all_cores(self):
        """Mesen ticked alone with the PlayStation chosen
        read "Cores: all", the run keeping none of pcsx_rearmed's files."""
        state = checked_state()
        state.ticked = {"sony-playstation"}
        state.cores = ["mesen"]
        options = self.options(state)
        self.assertIn("Cores: 0 of 1", [r.label for r in install.tui_rows(options)])
        state.stack = ["setup", "plan"]
        self.assertIn("0 of 1 cores", self.text(state, 100, 30))
        self.assertEqual(install.core_count_words(["mesen"], ["pcsx_rearmed"]), "0 of 1 cores")

    def test_none_then_done_says_why_on_a_long_list(self):
        """On 189 cores the status and the sentence were
        dropped, Done with nothing ticked did nothing visible."""
        state = checked_state()
        state.manifest = {**MANIFEST, "files": [
            *MANIFEST["files"],
            *({"dest": f"x/{n}.bin", "size": 1, "systems": ["sony-playstation"],
               "cores": [f"core{n:03}"]} for n in range(60))]}
        state.stack = ["setup", "plan", "options", "cores"]
        state.focus["cores"] = install._first_item(state)
        press(state, "n")
        done = next(i for i, r in enumerate(install.tui_rows(state)) if r.action == "done")
        state.focus["cores"] = done
        press(state, "enter")
        self.assertEqual(state.screen, "cores")
        for cols, rows in ((80, 24), (40, 12)):
            text = self.text(state, cols, rows)
            self.assertIn("No core is ticked", text)
            self.assertIn("Untick the cores", text)
        press(state, "esc")
        self.assertEqual(state.screen, "cores")

    def test_core_rows_say_what_each_core_adds(self):
        """Line mode counted each core's files, the
        screen named the cores alone."""
        state = checked_state()
        state.stack = ["setup", "plan", "options", "cores"]
        rows = {r.value: r.right for r in install.tui_rows(state) if r.action == "core"}
        self.assertEqual(rows["pcsx_rearmed"], "1 file, 4 B")
        state.cores_all = True
        rows = {r.value: r.right for r in install.tui_rows(state) if r.action == "core"}
        self.assertEqual(rows["mesen"], "1 file, 8.0 KB")

    def test_one_core_has_no_cores_row(self):
        """A list with one core offered Cores, where line
        mode asks nothing."""
        state = checked_state()
        state.manifest = {**MANIFEST, "files": [
            entry for entry in MANIFEST["files"] if entry["dest"] != "fc/disksys.rom"]}
        self.assertNotIn("cores", [r.action for r in install.tui_rows(self.options(state))])

    # Root cause 2: one tick list.

    def test_the_three_lists_open_and_answer_alike(self):
        """Choose systems opened on None, A unticking
        every system, Cores closed on A, regions ticked on A."""
        for route in ("both", "gptokeyb", "muxterm", "miyoo"):
            for screen, opener in (("systems", ("plan", "systems")),
                                   ("cores", ("options", "cores")),
                                   ("regions", ("options", "regions"))):
                with self.subTest(route=route, screen=screen):
                    state = checked_state()
                    state.pad = route
                    if opener[0] == "options":
                        press(state, "o")
                    state.focus[state.screen] = next(
                        i for i, r in enumerate(install.tui_rows(state))
                        if r.action == opener[1])
                    press(state, "enter")
                    self.assertEqual(state.screen, screen)
                    rows = install.tui_rows(state)
                    focused = rows[state.focus[screen]]
                    self.assertIn(focused.action, install.TUI_TICK_ROWS)
                    self.assertEqual([r.action for r in rows[-2:]], ["none", "done"])
                    hint = install._TUI_VIEWS[screen](state, 78, 21)[2]
                    self.assertEqual(hint[:2], ("A/Enter Tick", "B/Esc Done"))
                    before = install.tui_flags(state)
                    press(state, "enter")
                    self.assertEqual(state.screen, screen)
                    self.assertNotEqual(install.tui_flags(state), before)

    # Root cause 3: a folder failure as it happened.

    def test_a_folder_that_cannot_be_created_ends_on_its_reason(self):
        """The result said "22 files not fetched
        (RETROBIOS_INSTALL_OFFLINE=1)" and sent the user for a pack."""
        for os_type in ("linux", "android"):
            with self.subTest(os_type=os_type):
                state = checked_state()
                state.os_type = os_type
                install.tui_update(state, Key("enter"))
                for event in ({"event": "error", "stage": "dest", "reason": "not_writable",
                               "platform": "retroarch",
                               "message": f"{SYSTEM_DIR} cannot be created: Permission denied"},
                              {"event": "summary", "mode": "install", "installed": 0,
                               "up_to_date": 0, "pending": 4, "failed": [], "skipped": [],
                               "left_out": [], "kept": [], "interrupted": False}):
                    install.tui_receive(state, ("event", state.run_id, event))
                install.tui_receive(state, ("ended", state.run_id, 2, []))
                title, lines = install.tui_outcome(state)
                text = " ".join(map(str, lines))
                self.assertEqual(title, "Nothing installed")
                self.assertIn("cannot be created (permission denied)", text)
                self.assertNotIn("not fetched", text)
                self.assertNotIn("not in", text.split("cannot be created")[0])
                self.assertEqual("termux-setup-storage" in text, os_type == "android")
                self.assertNotIn("sudo", text if os_type == "android" else "")

    def test_android_never_offers_sudo_and_a_phone_plan_says_why(self):
        """Termux was offered sudo, and at 40x12 the plan
        offered Install anyway with no word of why."""
        hint = install.Invocation()
        hint.os_type = "android"
        remedy = install.write_remedy(Path("/storage/emulated/0/RetroArch/system"),
                                      "retroarch", hint)
        self.assertEqual(remedy, [install.TERMUX_STORAGE_WORDS])
        state = checked_state({"free": 50 * 1024 ** 3, "writable": False, "cores": []})
        state.os_type = "android"
        for cols, rows in ((40, 12), (80, 24)):
            text = self.text(state, cols, rows)
            self.assertIn("This folder cannot be written to", text)
            self.assertNotIn("sudo", text)

    # Root cause 4: every proven card named, the real marker said.

    def test_an_arkos_card_is_found_beside_an_amberelec_card(self):
        """An ArkOS card its bgmusic
        or launchimages prove was named nowhere, and its route said it
        could not tell it."""
        games = games_part(self.root / "media" / "GAMES")
        for marker in ("bgmusic", "launchimages"):
            with self.subTest(marker=marker):
                ark = self.drive(f"ARK_{marker}", ("bios", "nes", marker))
                self.assertEqual(install.card_system(ark), ("retroarch", ark / "bios", "ArkOS"))
                for name in ("ArkOS", "dArkOS"):
                    setup = install.card_setup(name, "retroarch")
                    self.assertEqual(install._card_is(setup, ark)[0], "own", name)
                state = self.first_screen([games, ark])
                text = self.text(state, 80, 24)
                self.assertIn(f"ArkOS SD card (ARK_{marker})", text)
                self.assertIn("AmberELEC SD card (GAMES)", text)

    def test_the_emuelec_refusal_names_its_file(self):
        """The refusal named bezels, which AmberELEC's
        card holds too."""
        games = games_part(self.root / "media" / "GAMES")
        (games / "bezels").mkdir()
        setup = install.card_setup("EmuELEC", "emuelec")
        choice = install._not_the_card(setup, games, games, "AmberELEC")
        self.assertIn("bezels/default.cfg", choice.detail)

    # Root cause 5: the reads before the menu show.

    def test_the_reads_before_the_menu_show_a_count(self):
        """A rerun read every file before the menu, one at
        a time and with nothing on screen."""
        payload = b"R" * 16
        (self.here / "a.bin").write_bytes(payload)
        listing = core_list(self.root / "read.json",
                            [self.entry("a.bin", payload, ["sony-playstation"])])
        with mock.patch.object(install, "_live_stdout", return_value=True):
            text, _asked = self.line_run(_args(manifest=listing, dest=self.here,
                                               declared_only=False), [])
        self.assertIn("\r  read 1/1", text)
        self.assertLess(text.index("read 1/1"), text.index("every one in place"))

    # Root cause 6: every other item.

    @in_full
    def test_offline_the_plan_promises_no_replacement_it_cannot_make(self):
        """Offline, the plan said a wrong copy no folder
        holds "is replaced"."""
        state = checked_state()
        state.offline = True
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            text = self.text(state, 100, 30)
        self.assertIn("1 wrong copy", text)
        self.assertNotIn("wrong copy is replaced", text)

    def test_options_name_the_plans_bios_folder(self):
        """AmberELEC's Options read the games part, its
        plan the bios folder below it."""
        state = checked_state()
        state.manifest = {**MANIFEST, "files": [
            {**entry, "dest": f"bios/{entry['dest']}"} for entry in MANIFEST["files"]]}
        state.dest = Path("/media/me/GAMES")
        row = next(r for r in install.tui_rows(self.options(state)) if r.action == "folder")
        self.assertEqual(row.label, "BIOS folder: /media/me/GAMES/bios")

    def test_finished_with_errors_says_a_rerun_retries(self):
        """The screen never said a rerun retries the files
        that failed, and line mode named each failure twice."""
        state = checked_state()
        install.tui_update(state, Key("enter"))
        install.tui_receive(state, ("event", state.run_id, {
            "event": "summary", "mode": "install", "installed": 3, "up_to_date": 0,
            "pending": 1, "failed": [{"dest": "gba_bios.bin", "reason": "timed out"}],
            "skipped": [], "left_out": [], "kept": [], "interrupted": False}))
        install.tui_receive(state, ("ended", state.run_id, 1, []))
        title, lines = install.tui_outcome(state)
        self.assertEqual(title, "Finished with errors")
        self.assertIn("Run it again to retry only those.", lines)
        # Line mode: the FAILED line of the progress names it, the end not again.
        install.SAID_FAILED.clear()
        install.SAID_FAILED.add("gba_bios.bin")
        self.addCleanup(install.SAID_FAILED.clear)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out), \
                contextlib.suppress(SystemExit):
            install._report_outcome([Path("/b")], 3, 0, 1, 0, False,
                                    details=install.OutcomeDetails(failures=[("gba_bios.bin", "timed out")]))
        self.assertNotIn("gba_bios.bin", out.getvalue())
        self.assertIn("Run the same command again to retry only those.", out.getvalue())

    def test_below_40_columns_no_word_is_broken(self):
        """The reason line, Found and Install for were
        left to the terminal, which broke "/media/moi/" and "ONION/BIOS"."""
        with mock.patch.object(install, "terminal_size", return_value=(39, 11)), \
                mock.patch.object(install, "_is_terminal", return_value=True):
            for text in ("  Found Onion at /media/moi/ONION/BIOS (RetroArch files)",
                         "The window is 39x11: questions come line by line "
                         "(40x12 for the full screen)."):
                lines = install.fold_line(text).split("\n")
                self.assertTrue(all(len(line) <= 38 for line in lines), lines)
                self.assertEqual(" ".join(" ".join(lines).split()), " ".join(text.split()))

    def test_the_narrowing_line_is_a_sentence(self):
        """The plan read "--region." on a line alone."""
        state = checked_state()
        state.regions = ["japan"]
        text = self.text(state, 100, 30)
        self.assertIn("For this choice: regions ranked.", text)
        self.assertNotIn(" --region.", text)

    def test_offline_choice_of_systems_is_never_about_0_files(self):
        """"About 0 files, 0 B, for 10 of 11 systems"."""
        state = checked_state()
        state.offline = True
        state.ticked = {"sony-playstation"}
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            text = self.text(state, 100, 30)
        self.assertNotIn("About 0 files", text)
        self.assertIn("need the internet", text)

    def test_a_phone_bar_after_a_tap_keeps_quit_and_one_wording(self):
        """At 40 columns on Android the armed bar dropped
        Esc Quit and said "click", the row "tap again"."""
        state = fresh_state()
        state.os_type = "android"
        state.mouse = True
        state.stack = ["setup"]
        install.tui_view(state, 40, 12)
        state.tapped = install._tapped_row(state)
        frame = install.tui_view(state, 40, 12)
        text = "\n".join(map(str, frame))
        self.assertNotIn("click", text)
        self.assertIn("tap again", text)
        self.assertIn("Esc Quit", str(frame[-1]))

    def test_the_offline_screen_names_the_setups_list(self):
        """The offline screen said install/<platform>.json
        for AmberELEC, chosen one screen before."""
        inbox: queue.Queue = queue.Queue()
        install.LOCAL.reset()
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            install._tui_fetch("amberelec", inbox)
        message = inbox.get_nowait()
        self.assertIn("install/amberelec.json", " ".join(message[3]))

    # Root cause 7: the tests leave the host alone.

    def test_no_connection_leaves_the_loopback_nor_a_card_comes_in(self):
        """261 connections to GitHub left this module,
        and tests failed with an AmberELEC card in the reader."""
        import socket

        log = Path(os.environ["RETROBIOS_TEST_NETLOG"])
        before = log.read_text(encoding="utf-8")
        self.addCleanup(log.write_text, before, encoding="utf-8")
        with self.assertRaisesRegex(OSError, "makes no request"):
            socket.create_connection(("192.0.2.1", 80), timeout=1)
        child = subprocess.run(
            [sys.executable, "-c", "import os, socket\n"
             "print(os.path.ismount('/media/x'), os.path.ismount('/mnt/d'))\n"
             "socket.create_connection(('192.0.2.1', 80), 1)"],
            capture_output=True, text=True, check=False, timeout=60)
        self.assertEqual(child.stdout.strip(), "False False")
        self.assertIn("makes no request", child.stderr)
        self.assertEqual(len(log.read_text(encoding="utf-8").splitlines()),
                         len(before.splitlines()) + 2)
        self.assertFalse(os.path.ismount("/media/x"))


class GamesOnTheCard(unittest.TestCase):
    """For the games on this card: the first choice where the card holds
    games, the whole list one press away (--for-games)."""

    @in_full
    def test_a_card_with_games_opens_on_them(self):
        state = games_state()
        self.assertTrue(state.for_games)
        self.assertEqual(state.games_choice, "probe")
        argv = install.tui_argv(state, "check", "py", "i.py")
        self.assertEqual(argv[4:], ["--for-games", "--check", "--events"])
        rows = install.tui_rows(state)
        self.assertEqual([row.action for row in rows[:4]],
                         ["install", "games", "startonly", "gameslist"])
        self.assertEqual(rows[1].label, "For the games on this card: yes")
        self.assertEqual(rows[1].right, "412 games")
        text = "\n".join(install.tui_view(state, 80, 24))
        self.assertIn("For the 412 games on this card.", text)
        self.assertIn("2 games get every BIOS of their system: Show the games.", text)

    def test_a_card_without_games_keeps_the_whole_list(self):
        state = fresh_state()
        with mock.patch.object(install.Path, "exists", return_value=True):
            install.tui_update(state, Key("enter"))
        install.tui_receive(state, ("games_here", "retroarch", SYSTEM_DIR, 0))
        install.tui_receive(state, ("manifest", "retroarch", MANIFEST))
        self.assertFalse(state.for_games)
        self.assertNotIn("--for-games", install.tui_argv(state, "check", "py", "i.py"))
        self.assertNotIn("games", [row.action for row in install.tui_rows(checked_state())])

    def test_a_look_at_another_folder_is_ignored(self):
        state = fresh_state()
        with mock.patch.object(install.Path, "exists", return_value=True):
            install.tui_update(state, Key("enter"))
        install.tui_receive(state, ("games_here", "retroarch", HOME / "other", 5))
        self.assertIsNone(state.for_games)

    def test_everything_is_one_press_away(self):
        state = games_state()
        state.focus["plan"] = 1
        self.assertEqual(press(state, "enter"), [("run", "check")])
        self.assertFalse(state.for_games)
        self.assertEqual(state.games_choice, "user")
        self.assertNotIn("--for-games", install.tui_argv(state, "check", "py", "i.py"))
        self.assertEqual(state.refocus, "games")

    def test_only_what_starts_adds_its_flag(self):
        state = games_state()
        state.focus["plan"] = 2
        self.assertEqual(press(state, "enter"), [("run", "check")])
        self.assertIn("--required-only", install.tui_argv(state, "check", "py", "i.py"))
        self.assertEqual(install.tui_command(state).split()[-2:],
                         ["--for-games", "--required-only"])

    def test_show_the_games_names_those_that_fell_back(self):
        state = games_state()
        state.focus["plan"] = 3
        press(state, "enter")
        self.assertEqual(state.screen, "games")
        items = install._pager_items(state)
        self.assertTrue(any(line.endswith("(GBA): 12 games, 8 recognised, Europe only")
                            for line in items), items)
        self.assertIn("GBA/demo.gba: not recognised", items)
        press(state, "enter")
        self.assertEqual(state.screen, "plan")

    def test_the_result_names_them_too(self):
        state = games_state()
        state.stack.append("result")
        state.code = 0
        state.download = {"event": "download", "files": 4, "bytes": 1064964}
        state.summary = {"event": "summary", "mode": "install", "installed": 4,
                         "up_to_date": 1, "pending": 0, "failed": [], "skipped": [],
                         "left_out": [], "kept": [], "interrupted": False}
        lines = install.tui_outcome(state)[1]
        self.assertIn("Not recognised, every BIOS of their system kept: GBA/demo.gba, "
                      "GBA/hack.gba.", lines)

    def test_the_command_line_decides_and_names_a_folder(self):
        args = _args()
        args.for_games, args.required_only = Path("games"), True
        with mock.patch.object(install, "_mounted_cards", return_value=[]):
            state, _effects = install.tui_start(args, "linux", detect=False)
        self.assertEqual(state.games_choice, "cli")
        flags = install.tui_flags(state)
        self.assertIn(("--for-games", str(Path("games").absolute())), flags)
        self.assertIn(("--required-only", None), flags)
        state.platform, state.dest = "retroarch", SYSTEM_DIR
        install.tui_receive(state, ("games_here", "retroarch", SYSTEM_DIR, 0))
        self.assertTrue(state.for_games)

    def test_another_folder_is_looked_at_from_what_was_read(self):
        state = games_state()
        state.dest = HOME / "card" / "BIOS"
        with mock.patch.object(install, "games_probe", return_value=0) as probe:
            self.assertEqual(install._start_check(state), [("run", "check")])
        probe.assert_called_once_with("retroarch", HOME / "card" / "BIOS", network=False,
                                      os_type="linux")
        self.assertFalse(state.for_games)
        self.assertEqual(state.games_probed, ("retroarch", HOME / "card" / "BIOS"))

    def test_the_fetch_looks_at_the_card_before_the_list_arrives(self):
        inbox: queue.Queue = queue.Queue()

        def fetched(plat, held):
            held.put(("manifest", plat, MANIFEST))

        with mock.patch.object(install, "_tui_fetch", side_effect=fetched), \
                mock.patch.object(install, "games_probe", return_value=3) as probe:
            install._tui_fetch_games("retroarch", inbox, SYSTEM_DIR, True)
        probe.assert_called_once_with("retroarch", SYSTEM_DIR, attempts=1)
        self.assertEqual(inbox.get()[0], "games_here")
        self.assertEqual(inbox.get()[0], "manifest")

    def test_reading_the_games_is_counted_while_the_check_runs(self):
        state = fresh_state()
        state.platform, state.dest, state.stack = "retroarch", SYSTEM_DIR, ["checking"]
        state.manifest, state.run, state.running = MANIFEST, "check", True
        install.tui_receive(state, ("event", state.run_id, {
            "event": "games_reading", "files_done": 40, "files_total": 412}))
        self.assertIn("Reading the games: 40 of 412",
                      "\n".join(install.tui_view(state, 80, 24)))

    def test_what_the_games_need_not_known_is_said(self):
        state = games_state()
        state.games = None
        state.games_unavailable = {"event": "games_unavailable", "platform": "retroarch",
                                   "reason": "offline", "message": "the games index is "
                                   "not on this machine"}
        self.assertIn("What the games need is not known: the games index is not on this "
                      "machine. Every file is kept.", install.games_plan_words(state))

    def test_every_size_draws_the_rows(self):
        state = games_state()
        for cols, rows in SIZES:
            with self.subTest(size=f"{cols}x{rows}"):
                state.cols, state.rows = cols, rows
                lines = install.tui_view(state, cols, rows)
                self.assertTrue(any("For the games" in line for line in lines), lines)


@unittest.skipUnless(pyte and pty, "the end-to-end screens need pyte and a pty")
class GamesEndToEnd(unittest.TestCase):
    """The real --tui on a card with games, against a loopback repository."""

    def test_the_plan_opens_on_the_games_and_installs_only_them(self):
        from tests import test_install_games as games

        card = games.Card()
        self.addCleanup(card.close)
        card.game("SEGACD", "sonic.iso", games.mcd_iso(100))
        root = card.root / "repo"
        (root / "install").mkdir(parents=True)
        shutil.copytree(card.lists / "games", root / "install" / "games")
        listed = games.manifest()
        (root / "bios").mkdir()
        for entry in listed["files"]:
            payload = entry["dest"].encode().ljust(entry["size"], b".")[:entry["size"]]
            (root / entry["repo_path"]).write_bytes(payload)
        (root / "install" / "retroarch.json").write_text(json.dumps(listed))
        base = loopback.serve(self, root)
        env = {**os.environ, "TERM": "xterm", "HOME": str(card.root), "RETROBIOS_OS": "linux",
               "RETROBIOS_BASE_URL": base,
               "RETROBIOS_CACHE": str(card.cache)}
        for name in ("DISPLAY", "WAYLAND_DISPLAY", "SSH_CONNECTION", "SSH_TTY", "NO_COLOR",
                     install.TUI_PAD_ENV, install.OFFLINE_VARIABLE, *install._STEAM_MARKERS):
            env.pop(name, None)
        term = Pty(["--platform", "retroarch", "--dest", str(card.bios)], env)
        self.addCleanup(lambda: term.status is None and os.kill(term.pid, 9))
        screen = term.wait("For the games on this card: yes", timeout=40)
        self.assertIn("For the 1 game on this card.", screen)
        term.send("\r")
        term.wait("A/Enter Exit", timeout=40)
        term.send("\r")
        self.assertEqual(term.close(), 0)
        written = sorted(p.name for p in card.bios.rglob("*") if p.is_file())
        self.assertEqual(written, ["bios_CD_E.bin", "cd_extra.bin"])


if __name__ == "__main__":
    unittest.main()
