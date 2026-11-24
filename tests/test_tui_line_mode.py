"""Line mode and the full screen decide alike on the same findings."""

from __future__ import annotations

import tests

import argparse
import contextlib
import io
import json
import os
import re
import shutil
import sys
import unittest
from pathlib import Path
from unittest import mock

import install
from tests.test_install_app import make_card
from tests.netguard import module_guard
from tests.tuisupport import (
    _args, BUILDER_FLOOR, _CardFixtures, checked_state, _Decided, engine_events, fresh_state, HOME,
    in_full, _installed_state, Key, line_decision, LineModeRuns, _OutsideTextFindings, planned,
    press, REPO_ROOT, reported, screen_decision, screen_keys, SYSTEM_DIR,
)


# No connection off the loopback and no card of the host reaches a test,
# in this process or one it starts: the module fails at its end when one is tried.
setUpModule, tearDownModule = module_guard("test_tui_line_mode")


def screen_plan(args: argparse.Namespace, manifest: dict, events: list[dict],
                facts: dict | None = None) -> tuple[install.TuiState, str]:
    """The plan screen fed the events of a check run, as the screen reads
    its child: (state, text at 120x40)."""
    state, _effects = install.tui_start(args, "linux", detect=False)
    state.manifest, state.manifest_for = manifest, state.platform
    state.stack = ["checking"]
    install._start_run(state, "check")
    for event in events:
        install.tui_receive(state, ("event", state.run_id, event))
    with mock.patch.object(install, "_tui_folder_facts", return_value=facts or {
            "free": 50 * 1024 ** 3, "writable": True, "cores": []}):
        install.tui_receive(state, ("ended", state.run_id, 0, []))
    return state, " ".join(" ".join(install.tui_view(state, 120, 40)).split())


class _LineModeFindings(_CardFixtures):
    """The line-mode cases of the card fixtures, run by
    LineModeAndScreenDecideAlike."""

    def test_a_drive_two_systems_fit_is_taken_as_named_and_said(self):
        """--platform knulli is never refused on a
        drive whose only evidence is a batocera.conf, --platform batocera
        takes its bios folder, and the doubt is said. Recalbox refuses it
        with words for a SHARE drive."""
        drives = self.renamed()
        for name in ("renamed, no about.info", "Batocera as shipped"):
            drive = drives[name]
            with self.subTest(drive=name):
                choice = install.card_choice("knulli", "knulli", drive)
                self.assertEqual((choice.plat, choice.folder, choice.refused),
                                 ("knulli", drive / "bios", ""))
                self.assertIn("Taken as KNULLI's, as named", choice.note)
        drive = drives["renamed, no about.info"]
        choice = install.card_choice("batocera", "batocera", drive)
        self.assertEqual((choice.plat, choice.folder), ("batocera", drive / "bios"))
        self.assertIn("names the host RG40XXH", choice.note)
        refused = install.card_choice("recalbox", "recalbox", drive)
        self.assertIn("could be a KNULLI card or a Batocera SHARE drive", refused.refused)
        words = install._dest_refusal_words(refused, None)
        self.assertIn("Connect the Recalbox SHARE drive", words)
        self.assertNotIn("Insert", words)
        other = install.card_choice("recalbox", "recalbox", drives["Batocera as shipped"])
        words = install._dest_refusal_words(other, None)
        self.assertIn("Connect the Recalbox SHARE drive, or name that drive's own system: "
                      "--platform batocera", words)

    def test_the_first_screen_and_line_mode_say_the_doubt(self):
        """The screen's first row was "Batocera SHARE
        drive (KNULLI2)". A renamed card with about.info is KNULLI's, one
        without is listed by neither and said."""
        drives = self.renamed()
        knulli, doubt = drives["KNULLI renamed"], drives["renamed, no about.info"]
        with mock.patch.object(install, "_mounted_cards", return_value=[knulli, doubt]), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            setups, _mounted = install.found_setups("linux")
        self.assertEqual([(plat, path) for plat, path, _label in setups],
                         [("knulli", knulli / "bios")])
        self.assertIn("KNULLI SD card", setups[0][2])
        text = out.getvalue()
        self.assertIn(f"{doubt} could be a KNULLI card or a Batocera SHARE drive", text)
        self.assertIn(f"--platform knulli --dest {doubt} or --platform batocera --dest {doubt}",
                      text)
        with mock.patch.object(install, "_mounted_cards", return_value=[knulli, doubt]), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]), \
                contextlib.redirect_stdout(io.StringIO()):
            state, _effects = install.tui_start(_args(), "linux")
        self.assertTrue(any("could be a KNULLI card" in note for note in state.notes))
        self.assertEqual([setup[0] for setup in state.setups], ["knulli"])

    def test_a_list_without_systems_narrows_by_what_it_records(self):
        """Install/minui.json records cores and regions,
        no system, and all three options were refused with a remedy that
        fetched the same list."""
        listing, _pack, _listed = self.minui()
        code, text, kept = self.narrowed("minui", manifest=listing, core=["mgba"])
        self.assertEqual(code, 0, text)
        self.assertEqual(kept, ["Bios/MGBA/gba_bios.bin"])
        code, text, kept = self.narrowed("minui", manifest=listing, region=["us"])
        self.assertEqual(code, 0, text)
        self.assertNotIn("Bios/PS/scph5500.bin", kept)
        code, text, _kept = self.narrowed("minui", manifest=listing,
                                          system=["nintendo-gba"])
        self.assertEqual(code, 1)
        self.assertIn("records no systems, so --system cannot narrow it", text)
        self.assertIn("Run it without --system, or narrow with --core and --region", text)
        self.assertNotIn("one-line installer", text)
        # The remedy followed: what it names works.
        code, text, _kept = self.narrowed("minui", manifest=listing, core=["mgba"],
                                          region=["us"])
        self.assertEqual(code, 0, text)

    @unittest.skipIf(sys.version_info < BUILDER_FLOOR,
                     "generate_pack.py's context managers need Python 3.9")
    def test_a_pack_names_its_list_only_when_that_list_records_it(self):
        """A MinUI pack sent --core to install/minui.json,
        refused the same way, and a MiSTer pack to install/misterfpga.json,
        which records no core. The pack now records what its list narrows
        by, and each remedy changes the outcome."""
        listing, pack, listed = self.minui()
        self.assertEqual(listed["list_records"], ["cores", "regions"])
        # The pack carries its install list since 2026-11: --core narrows it
        # alone, as with the list named beside it.
        code, text, kept = self.narrowed("minui", from_pack=[pack], core=["mgba"])
        self.assertEqual((code, kept), (0, ["Bios/MGBA/gba_bios.bin"]), text)
        code, text, kept = self.narrowed("minui", from_pack=[pack], manifest=listing,
                                         core=["mgba"])
        self.assertEqual((code, kept), (0, ["Bios/MGBA/gba_bios.bin"]), text)
        mister_list, mister, listed = self.minui("misterfpga", systems=True, cores=False,
                                                 regions=False)
        self.assertEqual(listed["list_records"], ["regions", "systems"])
        code, text, _kept = self.narrowed("misterfpga", from_pack=[mister], core=["x"])
        self.assertEqual(code, 1)
        # Its own list, which the pack carries, refuses it as --manifest would.
        self.assertIn("the misterfpga file list records no cores, so --core cannot narrow it",
                      text)
        self.assertNotIn("--manifest", text)
        code, text, kept = self.narrowed("misterfpga", from_pack=[mister],
                                         system=["nintendo-gba"])
        self.assertEqual((code, kept), (0, ["Bios/MGBA/gba_bios.bin"]), text)
        self.assertTrue(mister_list.exists())

    def test_line_mode_offers_what_can_be_chosen(self):
        """"c) choose systems, cores and regions" with a
        pack that records systems only, and "Cores: 1) azahar" asked with
        one answer."""
        mister, _pack, _listed = self.minui("misterfpga", systems=True, cores=False,
                                            regions=False)
        files = json.loads(mister.read_text())["files"]
        self.assertEqual(install.narrowing_words(files, []), "systems")
        listing, _pack, _listed = self.minui()
        minui = json.loads(listing.read_text())["files"]
        self.assertEqual(install.narrowing_words(minui, []), "cores and regions")
        one_core = [{**entry, "systems": ["nintendo-3ds"], "cores": ["azahar"]}
                    for entry in minui[:1]]
        with mock.patch.object(install, "_ask", side_effect=["", ""]) as asked, \
                contextlib.redirect_stdout(io.StringIO()) as out:
            install._choose_narrowing(one_core, [], {}, None)
        self.assertNotIn("Cores:", out.getvalue())
        self.assertEqual(asked.call_count, 0)

    # the remedies of a card.

    def test_a_full_card_is_freed_never_left_for_another_drive(self):
        with mock.patch.object(install.shutil, "disk_usage",
                               return_value=mock.Mock(free=10)), \
                contextlib.redirect_stderr(io.StringIO()) as err, \
                self.assertRaises(SystemExit):
            reported(install._check_free_space, self.root, 1000, "retroarch", card=True)
        said = err.getvalue()
        self.assertIn("on the card, then run it again", said)
        self.assertNotIn("--platform", said)
        self.assertNotIn("another drive", said)

    def test_line_mode_names_the_way_to_another_folder(self):
        hint = install.Invocation()
        with mock.patch.object(install, "_folder_writable", return_value=False), \
                mock.patch.object(install, "_on_read_only_mount", return_value=False):
            lines = install.folder_warnings("retroarch", self.root, [], hint, True, False)
        self.assertIn("This folder cannot be written to: run it again with another --dest.",
                      lines)
        self.assertNotIn("choose another one", " ".join(lines))
        with mock.patch.object(install, "_folder_writable", return_value=False), \
                mock.patch.object(install, "_on_read_only_mount", return_value=True):
            lines = install.folder_warnings("retroarch", self.root, [], hint, True, True)
        self.assertEqual(lines, [install.read_only_words(self.root)])

    def test_line_mode_names_the_way_to_another_drive(self):
        """The line plan said "choose another folder", a choice the line menu
        does not have, and the refusal after Enter named --dest: both name
        the same command now."""
        hint = install.Invocation()
        with mock.patch.object(install, "_space_short", return_value=(5000, 1000)), \
                mock.patch.object(install, "_folder_writable", return_value=True):
            lines = install.folder_warnings("batocera", self.root, [], hint, True, False)
        command = hint.command("batocera", "<folder on another drive>")
        self.assertEqual(lines, ["Not enough free space: 4.9 KB needed. Free up 3.9 KB, "
                                 "or install to another drive:", command])
        with mock.patch.object(install.shutil, "disk_usage",
                               return_value=mock.Mock(free=1000)), \
                contextlib.redirect_stderr(io.StringIO()) as err, \
                self.assertRaises(SystemExit):
            reported(install._check_free_space, self.root, 5000, "batocera")
        self.assertIn("  Free up 3.9 KB, or install to another drive:\n    " + command,
                      err.getvalue())

    def test_the_plan_warns_on_the_space_the_run_refuses_on(self):
        """The screen held the files missing or wrong against the free space,
        the run those and the data trees: a plan without a warning stopped
        for space right after Install."""
        state = fresh_state()
        state.facts["free"] = 1000
        check = {"bytes_needed": 500}
        self.assertFalse(install._short_of_space(state, check))
        check["space_bytes"] = 5000
        self.assertTrue(install._short_of_space(state, check))
        self.assertEqual(install.space_needed(check), 5000)


class LineModeAndScreenDecideAlike(_LineModeFindings, _OutsideTextFindings,
                                   unittest.TestCase):
    """Line mode looked at
    this machine alone, took this computer's default folder with a card in
    the reader or nothing found, and the screen put RetroArch under A for a
    KNULLI card named with --dest. The same inputs now give the same
    platform and folder on both, A or Enter taking what each offers first."""

    setUp = LineModeRuns.setUp

    def card(self, name: str, system: str) -> Path:
        root = self.root / "media" / name
        make_card(root, system)
        return root

    both = LineModeRuns.both

    def test_the_same_scenarios_give_the_same_platform_and_folder(self):
        onion = self.card("ONION", "Onion")
        muos = self.card("MUOS", "muOS")
        knulli = self.card("KNULLI", "KNULLI")
        bare = self.card("ONIONB", "Onion")
        shutil.rmtree(bare / "BIOS")
        default = install._default_dest("linux", "retroarch")
        pc = [("retroarch", self.here)]
        share = self.root / "media" / "SHARE"
        (share / "roms").mkdir(parents=True)
        batocera = self.root / "batocera.json"
        batocera.write_text(json.dumps({"manifest_version": 2, "platform": "batocera",
                                        "files": []}))
        blank = self.root / "blank"
        blank.mkdir()
        scenarios = {
            # the drive's root in
            # line mode, another system's card first on the screen.
            "a Batocera list, its SHARE drive": (
                [share], [], {"manifest": batocera}, ("batocera", share / "bios")),
            "a Batocera list, a muOS card and its SHARE drive": (
                [muos, share], [], {"manifest": batocera}, ("batocera", share / "bios")),
            # the setups found asked as the screen
            # asks, Enter on the first.
            "nothing named, RetroArch here": ([], pc, {}, ("retroarch", self.here)),
            "a list, RetroArch here and an Onion card": (
                [onion], pc, {"manifest": self.list}, ("retroarch", self.here)),
            # --dest with a setup found.
            "--dest a blank folder, RetroArch here": (
                [onion], pc, {"dest": blank}, ("retroarch", blank)),
            "a list, an Onion card in the reader": (
                [onion], [], {"manifest": self.list}, ("retroarch", onion / "BIOS")),
            "a list, an Onion card without its BIOS folder": (
                [bare], [], {"manifest": self.list}, ("retroarch", bare / "BIOS")),
            "a list, a KNULLI card in the reader": (
                [knulli], [], {"manifest": self.list}, ("retroarch", default)),
            "a list, nothing here": ([], [], {"manifest": self.list}, ("retroarch", default)),
            "nothing named, two cards": (
                [muos, onion], [], {}, ("retroarch", muos / "MUOS" / "bios")),
            "nothing named, nothing here": ([], [], {}, ("retroarch", default)),
            "--dest a KNULLI card, RetroArch here": (
                [knulli], pc, {"dest": knulli}, ("knulli", knulli / "bios")),
            "--platform onion, its card": (
                [onion, muos], pc, {"platform": "onion"}, ("retroarch", onion / "BIOS")),
        }
        for name, (mounts, found, given, expected) in scenarios.items():
            with self.subTest(scenario=name):
                line, screen, text = self.both(mounts, found, **given)
                self.assertEqual(tuple(line), expected, text)
                self.assertEqual(screen, expected)
                self.assertNotIn("using default path", text)

    def unasked(self, mounts: list, found: list, **given) -> tuple:
        """(platforms or exit code, text, events) of a run without
        questions: --no-input, or --yes, which implies it."""
        def stop(_args, platforms):
            raise _Decided(platforms)

        install.LOCAL.reset()
        self.addCleanup(install.LOCAL.reset)
        args = _args(declared_only=False, offline=False, no_input=True, **given)
        events = []
        with mock.patch.object(install, "_mounted_cards", return_value=mounts), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "detect_platforms", return_value=found), \
                mock.patch.object(install, "detect_frontends", return_value=[]), \
                mock.patch.object(install, "app_refusal", side_effect=stop), \
                mock.patch.object(install, "detect_os", return_value="linux"), \
                mock.patch.object(install.EVENTS, "emit",
                                  side_effect=lambda kind, **keys: events.append((kind, keys))), \
                mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()) as err:
            try:
                install._install(args, io.StringIO())
            except _Decided as decided:
                return [tuple(each) for each in decided.args[0]], out.getvalue(), events
            except SystemExit as exit_:
                return exit_.code, out.getvalue() + err.getvalue(), events
        raise AssertionError(out.getvalue())

    def test_a_run_without_questions_sees_the_cards_the_screen_sees(self):
        """--yes and --no-input looked at this machine
        alone, beside the Onion card the screen and line mode open on: the
        files went to the home folder, or the run said nothing is here."""
        onion = self.card("ONION", "Onion")
        default = install._default_dest("linux", "retroarch")
        for flag in ({"yes": True}, {}):
            for name, (mounts, given) in {
                "an Onion card, a list": ([onion], {"manifest": self.list}),
                "an Onion card, nothing named": ([onion], {}),
            }.items():
                with self.subTest(flag=flag, scenario=name):
                    chosen, text, _events = self.unasked(mounts, [], **flag, **given)
                    self.assertEqual(chosen, [("retroarch", onion / "BIOS")], text)
                    self.assertNotIn(str(default), text)
                    install._DETECTED_OS.clear()
                    with mock.patch.object(install, "_mounted_cards", return_value=mounts), \
                            mock.patch.object(install, "_mount_points",
                                              return_value=frozenset()), \
                            mock.patch.object(install, "detect_platforms", return_value=[]), \
                            mock.patch.object(install, "detect_frontends", return_value=[]):
                        screen = screen_decision(_args(declared_only=False, **given))
                    self.assertEqual(chosen, [screen])

    def test_a_run_without_questions_stops_on_two_setups(self):
        """--yes beside two setups
        installed for both, where its help says it stops on what to name.
        It now stops with an error event naming each and its --dest."""
        onion, muos = self.card("ONION", "Onion"), self.card("MUOS", "muOS")
        pc = [("retroarch", self.here)]
        for flag in ({"yes": True}, {}):
            for name, (mounts, found, given) in {
                "two cards": ([onion, muos], [], {}),
                "a card and RetroArch here, a list": ([onion], pc, {"manifest": self.list}),
                "two setups here": ([], [("retroarch", self.here),
                                         ("emudeck", self.root / "Emulation" / "bios")], {}),
            }.items():
                with self.subTest(flag=flag, scenario=name):
                    code, text, events = self.unasked(mounts, found, **flag, **given)
                    self.assertEqual(code, 1, text)
                    errors = [keys for kind, keys in events if kind == "error"]
                    self.assertEqual([(e["stage"], e["reason"]) for e in errors],
                                     [("detect", "conflict")])
                    self.assertIn("a run without questions installs for one", text)
                    self.assertRegex(text, r"--platform \w+ --dest ")

    def share(self, name: str = "SHARE") -> Path:
        share = self.root / "media" / name
        (share / "system").mkdir(parents=True)
        (share / "roms").mkdir()
        (share / "system" / "batocera.conf").write_text("system.hostname=BATOCERA\n")
        return share

    def test_a_drive_is_offered_by_the_folder_its_system_reads(self):
        """RetroArch's folder question
        numbered a Batocera SHARE drive and a KNULLI card, and one press put
        RetroArch's list at their root, beside roms/ and system/. A drive
        nothing names went to its root too. Now another system's drive is
        left out and said, in both modes, and a drive is its bios folder."""
        share, knulli = self.share(), self.card("KNULLI", "KNULLI")
        stick = self.root / "media" / "EASYROMS"
        (stick / "bios").mkdir(parents=True)
        onion = self.card("ONION", "Onion")
        mounts = [share, knulli, stick, onion]
        with mock.patch.object(install, "_mounted_cards", return_value=mounts), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                mock.patch.object(install, "_ask", side_effect=["q"]), \
                self.assertRaises(SystemExit):
            install.ask_platform_folder("linux", "retroarch")
        text = out.getvalue()
        # One parenthesis a row.
        self.assertIn(f"1) EASYROMS: bios (drive, {stick / 'bios'})", text)
        self.assertIn(f"2) ONION: BIOS (Onion SD card, {onion / 'BIOS'})", text)
        self.assertNotIn("3)", text)
        self.assertIn("Not offered here, each reads its own system's files: SHARE (Batocera "
                      f"SHARE drive: --platform batocera --dest {share}), KNULLI (KNULLI SD "
                      f"card: --platform knulli --dest {knulli}).", text)
        state = install.TuiState(os_type="linux", home=HOME)
        state.platform, state.stack = "retroarch", ["folder"]
        state.folder_default, state.folder_kind = SYSTEM_DIR, "usual"
        with mock.patch.object(install, "_mounted_cards", return_value=mounts), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()):
            state.folder_scan = install.scan_folder(state)
            rows = install.tui_rows(state)
            screen = " ".join(install.tui_view(state, 120, 40))
            state.focus["folder"] = next(index for index, row in enumerate(rows)
                                         if row.action == "drive")
            install.tui_update(state, Key("enter"))
        self.assertEqual([row.value for row in rows if row.action == "drive"],
                         [stick / "bios", onion / "BIOS"])
        self.assertIn("Not offered here", screen)
        self.assertEqual(state.dest, stick / "bios")

    def test_a_list_card_setups_read_offers_them_first(self):
        """With a RetroArch pack or list and nothing found,
        the first screen was RetroArch's folder question: ArkOS, muOS and
        JELOS, which read the same list, were out of reach. Both modes now
        open on the setups that read it, RetroArch first."""
        stick = self.root / "media" / "EASYROMS"
        (stick / "bios").mkdir(parents=True)
        args = dict(manifest=self.list, declared_only=False, offline=False)
        text, asked = self.line_run(_args(**args), [], mounts=[stick])
        self.assertIn("Which setup is the RetroArch list for?", text)
        self.assertIn("ArkOS", text)
        self.assertNotIn("Batocera", text)
        self.assertIn("[Enter for RetroArch]", asked[0])
        with mock.patch.object(install, "_mounted_cards", return_value=[stick]), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            install._DETECTED_OS.clear()
            state = screen_keys(_args(**args), [])
            with contextlib.redirect_stdout(io.StringIO()):
                install._open_local_sources(_args(**args))
            rows = install.tui_rows(state)
            labels = [row.label for row in rows]
            focused = rows[state.focus["platforms"]]
            install._DETECTED_OS.clear()
            ark = screen_keys(_args(**args), ["end", Key("char", "/"), *[
                Key("char", c) for c in "arkos"], "enter", "enter"])
        self.assertEqual(state.screen, "platforms")
        self.assertEqual(focused.value, "retroarch")
        self.assertTrue(any(label.startswith("ArkOS") for label in labels), labels)
        self.assertFalse(any(label.startswith("Batocera") for label in labels), labels)
        self.assertEqual(ark.screen, "folder")
        self.assertEqual(install._tui_card_bound(ark)[0], "ArkOS")

    # The owner's request of 2026-10-27: BIOS files and game data counted
    # apart, the game data choice on the plan itself and in the menu.

    def game_list(self) -> tuple[Path, list]:
        files = [self.entry("gba_bios.bin", b"gba", ["nintendo-gba"]),
                 self.entry("doom/doom1.wad", b"wad" * 10, ["doom"], category="game_data")]
        return self.listing("retroarch", files, categorized=True), files

    def test_line_mode_counts_game_data_apart_and_g_leaves_it_out(self):
        listing, _files = self.game_list()
        args = dict(manifest=listing, dest=self.here, declared_only=False, dry_run=True)
        text, asked = self.line_run(_args(**args), ["g", ""])
        self.assertIn("1 BIOS file (3 B) and 1 game data file (30 B).", text)
        self.assertIn("g) Game data: kept (1 file, 30 B): leave it out", text)
        self.assertIn("Game data: files a game or a game engine reads, of no use to the "
                      "other cores.", text)
        after = text[text.index("Counted again"):]
        self.assertIn("RetroArch: 1 file, 3 B.", after)
        self.assertIn("g) Game data: left out (1 file, 30 B): keep it", after)
        self.assertIn("--no-game-data", after)
        self.assertIn("1 game data file left out (--no-game-data)", after)
        self.assertNotIn("doom1.wad would", after)

    @in_full
    def test_the_plan_counts_game_data_apart_and_one_press_leaves_it_out(self):
        state = checked_state()
        manifest = json.loads(json.dumps(state.manifest))
        for entry in manifest["files"]:
            if entry["dest"] == "pcsx/extra.bin":
                entry["category"] = "game_data"
        state.manifest = manifest
        text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertIn("3 BIOS files (1.0 MB) and 1 game data file (4 B).", text)
        self.assertIn("Game data: files a game or a game engine reads, of no use to the "
                      "other cores.", text)
        rows = install.tui_rows(state)
        row = next(row for row in rows if row.action == "gamedata")
        self.assertEqual(row.label, "Game data: kept")
        state.focus["plan"] = rows.index(row)
        effects = install.tui_update(state, Key("enter"))
        self.assertTrue(state.no_game_data)
        self.assertEqual(effects, [("run", "check")])
        self.assertIn(("--no-game-data", None), install.tui_flags(state))

    def test_the_result_counts_game_data_apart_in_both_modes(self):
        state = _installed_state(Path("/x/system"))
        state.manifest = {**state.manifest, "files": [
            *state.manifest["files"],
            {"dest": "doom/doom1.wad", "size": 30, "category": "game_data", "cores": None}]}
        state.finished = [("scph5500.bin", True, ""), ("doom/doom1.wad", True, "")]
        state.summary = {**state.summary, "installed": 2}
        _title, lines = install.tui_outcome(state)
        self.assertIn("Installed: 1 BIOS file and 1 game data file.", lines)
        # The data tree files are installed without a file event: the parts
        # still add up to the head's count.
        state.summary = {**state.summary, "installed": 5}
        _title, lines = install.tui_outcome(state)
        self.assertIn("5 files installed.", lines[0])
        self.assertIn("Installed: 1 BIOS file, 1 game data file and 3 data files.", lines)
        listing, _files = self.game_list()
        backup = self.root / "old"
        (backup / "doom").mkdir(parents=True)
        (backup / "gba_bios.bin").write_bytes(b"gba")
        (backup / "doom" / "doom1.wad").write_bytes(b"wad" * 10)
        args = _args(manifest=listing, dest=self.here, offline=True, declared_only=False,
                     no_input=True, verbose=True)
        setattr(args, "from", [backup])
        real = io.StringIO()
        install.LOCAL.reset()
        self.addCleanup(install.LOCAL.reset)
        with mock.patch.object(install, "detect_os", return_value="linux"), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            install._install(args, real)
        # Every file from one folder: one count, as the screen's result.
        self.assertIn(f"Done. 2 files copied from {backup}.", real.getvalue())
        self.assertIn("Installed: 1 BIOS file and 1 game data file.", real.getvalue())

    # 2026-10-27, CI run 40541886959: the run said 8069 files, the menu
    # 8348 and 3259 BIOS files and 5089 game data files, the real dry run
    # 8358. Every count of a run is one tally of one list.

    def counted_list(self) -> Path:
        files = [self.entry("gba_bios.bin", b"gba", ["nintendo-gba"]),
                 self.entry("doom/doom1.wad", b"wad" * 10, ["doom"], category="game_data"),
                 self.entry("doom/doom2.wad", b"two" * 20, ["doom"], category="game_data")]
        variant = {**self.entry("DOOM/DOOM1.WAD", b"WAD" * 10, ["doom"]),
                   "category": "game_data"}
        omitted = [{"dest": "doom/doom3.wad", "name": "doom3.wad", "system": "doom",
                    "systems": ["doom"], "required": False, "reason": "not_found",
                    "category": "game_data"}]
        return self.listing("retroarch", files, categorized=True, case_variants=[variant],
                            omitted_files=omitted)

    def test_every_count_of_a_line_run_is_one_list(self):
        args = dict(manifest=self.counted_list(), dest=self.here, declared_only=False,
                    dry_run=True)
        text, _asked = self.line_run(_args(**args), [""])
        # The second spelling a folder keeping case installs is counted
        # everywhere or nowhere: here, everywhere.
        self.assertIn("RetroArch: 4 files, 123 B.\n  1 BIOS file (3 B) and 3 game data files "
                      "(120 B).", text)
        self.assertIn("g) Game data: kept (3 files, 120 B): leave it out", text)
        # Said once, by the menu: the run head repeated it right under it.
        after = text[text.index("q) quit"):text.index("Checking existing files")]
        self.assertNotIn("4 files (123 B)", after)
        self.assertIn("0 in place, 4 missing, 0 wrong copies", text)
        self.assertIn("4 files (123 B)", text[text.index("Checking existing files"):])

    def test_g_counts_the_systems_chosen_and_leaves_out_what_it_said(self):
        args = dict(manifest=self.counted_list(), dest=self.here, declared_only=False,
                    dry_run=True)
        text, _asked = self.line_run(_args(**args), ["c", "2", ""])
        after = text[text.index("Counted again"):]
        self.assertIn("RetroArch: 1 file, 3 B, for 1 of 2 systems.", after)
        # No game data among the systems chosen: nothing for g to leave out.
        self.assertNotIn("g) Game data", after)
        text, _asked = self.line_run(_args(**args), ["c", "1", "g", "", "g", ""])
        after = text[text.index("Counted again"):]
        self.assertIn("g) Game data: kept (3 files, 120 B): leave it out", after)
        # doom holds only game data: Enter is refused, as the screen offers
        # no Install for it, and g puts it back.
        self.assertIn("g) Game data: left out (3 files, 120 B): keep it", after)
        self.assertIn("doom holds only game data: nothing is left to install.", after)
        self.assertNotIn("All files up to date", text)
        self.assertIn("RetroArch: 3 files, 120 B, for 1 of 2 systems.",
                      after[after.rindex("Counted again"):])
        text, _asked = self.line_run(_args(**args), ["g", ""])
        self.assertIn("4 game data files left out (--no-game-data), 1 of them not "
                      "installable", text)

    def test_the_parts_add_up_on_every_committed_list(self):
        for path in sorted((REPO_ROOT / "install").glob("*.json")):
            manifest = json.loads(path.read_text(encoding="utf-8"))
            if not manifest.get("categorized"):
                continue
            with self.subTest(path.name):
                for files in (manifest.get("files", []),
                              manifest.get("files", []) + manifest.get("case_variants", [])):
                    counts = install.tally(files)
                    self.assertEqual(counts.bios + counts.games, counts.files)
                    self.assertEqual(counts.files, len(files))
                    self.assertEqual(counts.bios_size + counts.game_size, counts.size)
                    self.assertEqual(counts.size, sum(e.get("size") or 0 for e in files))
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    install._print_menu_head(install.MenuContext(manifest["platform"],
                                                                 manifest["files"], [],
                                                                 manifest=manifest),
                                             current=None, given=None)
                head = re.search(r"(\d+) files?, ", out.getvalue())
                split = re.search(r"(\d+) BIOS files? \(.*?\) and (\d+) game data files?",
                                  out.getvalue())
                if split:
                    self.assertEqual(int(split[1]) + int(split[2]), int(head[1]))

    @in_full
    def test_the_screen_divides_the_count_it_shows(self):
        state = checked_state()
        manifest = json.loads(json.dumps(state.manifest))
        manifest["case_variants"] = [{"dest": "PCSX/EXTRA.BIN", "size": 4,
                                      "category": "game_data", "cores": ["pcsx_rearmed"],
                                      "systems": ["sony-playstation"]}]
        for entry in manifest["files"]:
            if entry["dest"] == "pcsx/extra.bin":
                entry["category"] = "game_data"
        state.manifest = manifest
        state.files = [*state.files, {
            "event": "file", "platform": "retroarch", "dest": "PCSX/EXTRA.BIN",
            "systems": ["sony-playstation"], "size": 4, "state": "missing"}]
        state.checked_dests.add("PCSX/EXTRA.BIN")
        state.check = planned({**state.check, "missing": state.check["missing"] + 1,
                               "files": state.check["files"] + 1,
                               "bytes_needed": state.check["bytes_needed"] + 4})
        text = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
        self.assertIn("5 files to download", text)
        self.assertIn("3 BIOS files (1.0 MB) and 2 game data files (8 B).", text)
        row = next(row for row in install.tui_rows(state) if row.action == "gamedata")
        self.assertEqual((row.label, row.right), ("Game data: kept", "2 files, 8 B"))

    # line mode wording.

    def test_one_row_says_type_1(self):
        with mock.patch.object(install, "_ask", side_effect=["2", "q"]), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                self.assertRaises(SystemExit):
            install._prompt_platform_choice([("retroarch", self.here)], other=list)
        self.assertIn("Type 1, o for another setup or folder, or q to quit.", out.getvalue())
        self.assertNotIn("1 to 1", out.getvalue())

    def test_a_number_out_of_range_at_copy_from_is_said_as_one(self):
        stick = self.root / "media" / "STICK"
        stick.mkdir(parents=True)
        with mock.patch.object(install, "_mounted_cards", return_value=[stick]), \
                mock.patch.object(install, "_ask", side_effect=["2", ""]), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            install._ask_from_folder([], self.here)
        self.assertIn("Type 1, a folder, or Enter.", out.getvalue())
        self.assertNotIn("does not exist", out.getvalue())

    def test_a_number_with_no_drive_listed_is_said_as_one(self):
        # With no drive listed, "2" was read as the folder ./2.
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "_ask", side_effect=["2", ""]), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            install._ask_from_folder([], self.here)
        self.assertIn("Type a folder, or Enter.", out.getvalue())
        self.assertNotIn("does not exist", out.getvalue())

    def test_the_copy_line_names_the_folder_it_copies_from(self):
        payload = b"gba"
        files = [self.entry("gba_bios.bin", payload, ["nintendo-gba"])]
        listing = self.listing("retroarch", files)
        old = self.root / "OLD"
        old.mkdir()
        (old / "gba_bios.bin").write_bytes(payload)
        args = _args(manifest=listing, dest=self.here, declared_only=False, offline=True)
        setattr(args, "from", [old])
        text, _asked = self.line_run(args, [""])
        self.assertIn(f"Copying 1 file (3 B) from {old}...", text)
        self.assertNotIn("copied from", text[text.index("\nCopying "):])
        self.assertNotIn("found on this machine (", text)

    def test_the_save_lines_name_the_frontend_both_times(self):
        onion = self.card("ONION", "Onion")
        files = [self.entry("gba_bios.bin", b"g", ["nintendo-gba"]),
                 self.entry("x/keys.txt", b"k", ["nintendo-3ds"], root="save")]
        listing = self.listing("retroarch", files, base_destination="RetroArch",
                               save_directory={"folder": "saves", "by_core": False})
        text, _asked = self.line_run(_args(manifest=listing, declared_only=False,
                                           offline=False), [""], mounts=[onion])
        self.assertIn("Install for:", text)
        self.assertIn("save directory left out", text)
        self.assertNotIn("Onion's save directory", text)
        self.assertIn("RetroArch's save directory", text)

    def test_line_mode_repeats_the_command_after_enter(self):
        payload = b"gba"
        files = [self.entry("gba_bios.bin", payload, ["nintendo-gba"])]
        listing = self.listing("retroarch", files)
        old = self.root / "OLD"
        old.mkdir()
        (old / "gba_bios.bin").write_bytes(payload)
        args = _args(manifest=listing, declared_only=False, offline=True, verbose=True)
        setattr(args, "from", [old])
        real = io.StringIO()
        install.LOCAL.reset()
        self.addCleanup(install.LOCAL.reset)
        invocation = install.Invocation()
        invocation.os_type = "linux"
        invocation.record(args)
        with mock.patch.object(install, "_INVOCATION", invocation), \
                mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "detect_platforms",
                                  return_value=[("retroarch", self.here)]), \
                mock.patch.object(install, "detect_frontends", return_value=[]), \
                mock.patch.object(install, "detect_os", return_value="linux"), \
                mock.patch.object(install.sys.stdin, "isatty", return_value=True), \
                mock.patch.object(install, "_is_terminal", return_value=True), \
                mock.patch.object(install, "_ask", return_value=""), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            install._install(args, real)
        said = real.getvalue()
        self.assertIn("Same choice without questions: python3 install.py --platform retroarch "
                      f"--dest {self.here}", said)
        self.assertIn("To check this later, run that command with --check.", said)

    def test_line_mode_says_the_card_it_found_and_names_its_folder(self):
        onion = self.card("ONION", "Onion")
        with mock.patch.object(install, "_mounted_cards", return_value=[onion]), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            _platforms, text = line_decision(_args(manifest=self.list, declared_only=False),
                                             lambda prompt: "")
        self.assertIn(f"Found Onion at {onion / 'BIOS'} (RetroArch files)", text)
        self.assertNotIn("No supported platform detected", text)

    def test_a_pack_gets_the_menu_and_its_folder_named(self):
        """No menu and no folder before the copy, the pack's list
        recording no system."""
        from tests.test_install_offline import _pack, PAYLOAD

        downloads = self.root / "downloads"
        downloads.mkdir()
        pack = _pack(downloads, "RetroArch_v1_BIOS_Pack.zip", PAYLOAD)
        install.LOCAL.reset()
        self.addCleanup(install.LOCAL.reset)
        menus = []
        real = install._prompt_custom_selection

        def menu(*given, **named):
            with mock.patch.object(install, "_ask", return_value="q"):
                try:
                    real(*given, **named)
                except SystemExit as stop:
                    menus.append(stop.code)
                    raise

        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]), \
                mock.patch.object(install, "detect_os", return_value="linux"), \
                mock.patch.object(install.sys.stdin, "isatty", return_value=True), \
                mock.patch.object(install, "_is_terminal", return_value=True), \
                mock.patch.object(install, "_ask", side_effect=lambda prompt: (
                    "" if prompt.startswith(">") else str(self.here))), \
                mock.patch.object(install, "_prompt_custom_selection", menu), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                self.assertRaises(SystemExit):
            install._install(_args(from_pack=[pack], declared_only=False), io.StringIO())
        text = out.getvalue()
        self.assertEqual(menus, [install.QUIT_CODE])
        self.assertIn("RetroArch was not found here.", text)
        self.assertIn(f"BIOS folder: {self.here}", text)
        self.assertIn("Enter) install everything", text)
        self.assertNotIn("c) choose systems", text)
        self.assertNotIn("Copying", text)

    # every line-mode finding, each answered
    # by line mode and the screen from one decision.

    line_run = LineModeRuns.line_run

    listing = LineModeRuns.listing

    entry = staticmethod(LineModeRuns.entry)

    def test_o_then_the_setup_found_offers_the_folder_it_reads(self):
        """O then RetroArch offered
        its built-in folder, and Enter filled it, where the screen keeps the
        folder retroarch.cfg names."""
        pc = [("retroarch", self.here)]
        args = dict(manifest=self.list, declared_only=False, offline=False)
        text, asked = self.line_run(_args(**args), ["o", "", ""], found=pc)
        self.assertIn(f"RetroArch reads its BIOS files from: {self.here}.", text)
        self.assertIn("(Enter for the folder RetroArch reads)", asked[2])
        self.assertNotIn("default BIOS folder", text)
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "detect_platforms", return_value=pc), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            install._DETECTED_OS.clear()
            given = iter(["o", "", ""])
            line, _text = line_decision(_args(**args), lambda _prompt: next(given))
            install._DETECTED_OS.clear()
            state = screen_keys(_args(**args), ["end", "enter", "enter", "enter"])
        self.assertEqual(tuple(line[0]), ("retroarch", self.here))
        self.assertEqual((state.platform, state.dest), ("retroarch", self.here))

    def test_a_share_drive_typed_is_read_as_its_bios_folder(self):
        """The SHARE drive's root,
        typed for Batocera or Recalbox, was the BIOS folder, beside roms/
        and system/. Another system's drive is refused, in both modes."""
        shares = {}
        for plat, marker in (("batocera", "system/batocera.conf"),
                             ("recalbox", "system/recalbox.conf")):
            share = self.root / "media" / f"SHARE-{plat}"
            (share / "system").mkdir(parents=True)
            (share / "roms").mkdir()
            # Batocera's own hostname: another would fit KNULLI renamed too.
            (share / marker).write_text("system.hostname=BATOCERA\n")
            shares[plat] = share
        for plat, share in shares.items():
            other = shares["recalbox" if plat == "batocera" else "batocera"]
            listing = self.listing(plat, [])
            with self.subTest(platform=plat):
                text, _asked = self.line_run(_args(manifest=listing, declared_only=False),
                                             [str(other), str(share)])
                self.assertIn(f"{other} is a {install.display_name(install.share_drive(other))}"
                              " SHARE drive", text)
                self.assertIn(f"SHARE drive: its BIOS folder is {share / 'bios'}", text)
                with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                        mock.patch.object(install, "detect_platforms", return_value=[]), \
                        mock.patch.object(install, "detect_frontends", return_value=[]):
                    line, _text = line_decision(_args(manifest=listing, declared_only=False),
                                                lambda _prompt, typed=str(share): typed)
                    refused = screen_keys(_args(manifest=listing), [
                        "end", "enter", Key("paste", str(other)), "enter"])
                    state = screen_keys(_args(manifest=listing), [
                        "end", "enter", Key("paste", str(share)), "enter"])
                self.assertEqual(tuple(line[0]), (plat, share / "bios"))
                self.assertEqual((state.platform, state.dest), (plat, share / "bios"))
                self.assertIn("SHARE drive", refused.status)
                self.assertEqual(refused.screen, "path")

    def test_the_setups_found_are_labelled_alike(self):
        """"Onion SD card
        (ONION) (/media/me/ONION/BIOS)", two pairs of brackets, and a MinUI
        card named by its root where its BIOS folder is Bios."""
        onion, minui = self.card("ONION", "Onion"), self.card("MINUI", "MinUI")
        mounts, pc = [onion, minui], [("retroarch", self.here)]
        text, _asked = self.line_run(_args(declared_only=False), [], mounts, pc)
        self.assertNotIn(") (", text)
        self.assertIn(f"Found MinUI at {minui / 'Bios'}", text)
        with mock.patch.object(install, "_mounted_cards", return_value=mounts), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "detect_platforms", return_value=pc), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            install._DETECTED_OS.clear()
            setups, _mounted = install.found_setups("linux")
            state = install.TuiState(os_type="linux", home=HOME)
            state.setups = setups
            state.setup_folders = install.setup_folders(setups)
            for index, (plat, path, label) in enumerate(setups):
                state.focus["setup"] = index
                screen = " ".join(install.tui_view(state, 120, 40))
                folder = install.setup_bios_folder(plat, path)
                with self.subTest(setup=label):
                    self.assertIn(f"{index + 1}) {label}: {folder}", text)
                    self.assertIn(f"BIOSfolder:{folder}", screen.replace(" ", ""))

    def test_both_count_the_systems_out_of_the_same_list(self):
        """The plan said 1 of 12 systems where Choose
        systems and line mode listed 11, a system whose only file is read
        from an unknown save directory counted."""
        payload = b"gba"
        files = [self.entry("gba_bios.bin", payload, ["nintendo-gba"]),
                 self.entry("ds.bin", b"ds", ["nintendo-ds"]),
                 self.entry("Azahar/keys.txt", b"keys", ["nintendo-3ds"], root="save")]
        # No retroarch.cfg, and a BIOS folder not named as the list's: the
        # save directory is not known, and keys.txt is left out.
        manifest = {"base_destination": "RetroArch",
                    "save_directory": {"folder": "saves", "by_core": False}}
        listing = self.listing("retroarch", files, **manifest)
        args = dict(manifest=listing, dest=self.here, declared_only=False,
                    system=["nintendo-gba"])
        text, _asked = self.line_run(_args(**args), [])
        self.assertIn("for 1 of 2 systems (--system).", text)
        events, _out = engine_events(_args(**args, check=True, events=True, no_input=True))
        choices = next(event for event in events if event["event"] == "choices")
        self.assertEqual(choices["systems"], ["nintendo-ds", "nintendo-gba"])
        manifest = json.loads(listing.read_text())
        state, screen = screen_plan(_args(**args), manifest, events)
        self.assertIn("For 1 of 2 systems (--system).", screen)
        # Choose systems, opened from that plan, lists the same two.
        self.assertEqual(len(install.tui_systems(state)), 2)

    def test_after_o_the_list_offers_the_setups_its_file_list_serves(self):
        """Batocera was offered for a RetroArch list,
        and refused once its folder had been asked."""
        install.LOCAL.reset()
        self.addCleanup(install.LOCAL.reset)
        install.LOCAL.manifest = self.list
        line = [name for name, _label in install._line_setups([], set(), "linux")]
        state = install.TuiState(os_type="linux", home=HOME)
        state.stack = ["platforms"]
        screen = [install._row_name(row) for row in install.tui_rows(state)
                  if row.action != "filter"]
        self.assertEqual(line, screen)
        self.assertIn("retroarch", line)
        self.assertIn("Onion", line)
        self.assertNotIn("batocera", line)
        self.assertNotIn("knulli", line)

    def test_a_choice_of_systems_is_confirmed_before_anything_is_written(self):
        """C installed as soon as the
        last list was answered, and its command left out --dest and
        --manifest. The menu comes back counted, as the screen's Confirm."""
        files = [self.entry("gba_bios.bin", b"gba", ["nintendo-gba"]),
                 self.entry("scph5501.bin", b"psx", ["sony-playstation"])]
        listing = self.listing("retroarch", files)
        args = _args(manifest=listing, dest=self.here, declared_only=False)
        text, asked = self.line_run(args, ["c", "1"])
        self.assertIn("Counted again for these choices. Nothing is written before Enter.", text)
        self.assertIn("RetroArch: 1 file, 3 B, for 1 of 2 systems.", text)
        self.assertIn("Enter) install these", text)
        self.assertEqual(asked[-1], "> ")
        command = next(line for line in text.splitlines()
                       if "Same choice without questions:" in line)
        for option in (f"--dest {self.here}", f"--manifest {listing}",
                       "--system nintendo-gba"):
            self.assertIn(option, command)
        self.assertNotIn("Copying", text)
        self.assertEqual(list(self.here.iterdir()), [])
        # The screen: Choose systems, A ticks, B back to the plan, whose
        # Install counts the choice on Confirm first.
        state = checked_state()
        press(state, "down", "enter")
        self.assertEqual(state.screen, "systems")
        press(state, "enter", "esc")
        effects = press(state, "enter")
        self.assertEqual((state.screen, effects), ("confirm", [("run", "confirm")]))

    def tree(self, ref: str, systems: list, count: int) -> dict:
        return {"ref": ref, "url": "https://example.org/tree.zip", "type": "zip",
                "systems": systems, "dest": ref,
                "files": {f"f{n}.dat": {"sha1": "a" * 40, "size": 10} for n in range(count)}}

    def test_both_count_the_data_files_of_the_systems_kept(self):
        """Line mode counted 2636 data files of other
        systems for every --system tried, where the screen counts none."""
        files = [self.entry("gba_bios.bin", b"gba", ["nintendo-gba"]),
                 self.entry("scph5501.bin", b"psx", ["sony-playstation"])]
        trees = [self.tree("gba-tree", ["nintendo-gba"], 2),
                 self.tree("psx-tree", ["sony-playstation"], 5)]
        listing = self.listing("retroarch", files, data_directories=trees)
        args = dict(manifest=listing, dest=self.here, declared_only=False)
        for system, count in (("nintendo-gba", 2), ("sony-playstation", 5)):
            with self.subTest(system=system):
                text, _asked = self.line_run(_args(**args, system=[system]), [])
                self.assertIn(f"and {count} data files (", text)
                events, _out = engine_events(_args(**args, system=[system], check=True,
                                                   events=True, no_input=True))
                data = next(event for event in events if event["event"] == "data")
                self.assertEqual(data["files"], count)
        text, _asked = self.line_run(_args(**args), [])
        self.assertIn("and 7 data files (", text)

    @unittest.skipUnless(hasattr(os, "statvfs"), "statvfs reads mount flags")
    def test_a_read_only_card_gets_one_remedy_and_no_sudo(self):
        """The plan offered sudo for a read-only mount,
        with a command that dropped --from-pack and --manifest, and the
        result offered nothing. One advice, line mode before its menu, the
        plan and the result."""
        listing = self.listing("retroarch", [self.entry("a.bin", b"a", ["x"])])
        args = _args(manifest=listing, dest=self.here, declared_only=False)
        words = install.read_only_words(self.here)
        with mock.patch.object(install, "_on_read_only_mount", return_value=True), \
                mock.patch.object(install, "_folder_writable", return_value=False):
            text, _asked = self.line_run(args, [])
            state = checked_state({"free": 10 ** 9, "writable": False, "cores": []})
            plan = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
            state.summary = {"installed": 0, "up_to_date": 0, "pending": 1, "kept": [],
                             "failed": [{"dest": "a.bin", "reason": install.NOT_WRITABLE}],
                             "skipped": [], "left_out": [], "interrupted": False}
            state.code = 2
            _title, result = install.tui_outcome(state)
        menu = text[:text.index("Enter)")]
        for said in (menu, plan, " ".join(result)):
            self.assertIn(words, said)
            self.assertNotIn("sudo", said)

    def test_the_sudo_command_keeps_every_option_of_the_run(self):
        """The plan's sudo line dropped --from-pack and
        --manifest, and with --offline stopped at the file list."""
        state = checked_state({"free": 10 ** 9, "writable": False, "cores": []})
        state.manifest_path, state.manifest_given = Path("/l/retroarch.json"), True
        state.passthrough = [("--from-pack", "/p/RetroArch_BIOS_Pack.zip")]
        with mock.patch.object(install, "_on_read_only_mount", return_value=False):
            plan = " ".join(str(line) for line in install._plan_lines(state.check, state.dest,
                                                                       state))
        line = plan[plan.index("Or run it as root"):]
        for option in ("--manifest /l/retroarch.json", "--from-pack /p/RetroArch_BIOS_Pack.zip",
                       f"--dest {SYSTEM_DIR}"):
            self.assertIn(option, line)

    def test_the_save_files_are_counted_after_the_choice(self):
        """--system sony-playstation said 106 files went
        to the save directory, none of them PlayStation's."""
        here = self.root / "pc" / "system"
        files = [self.entry("gba_bios.bin", b"gba", ["nintendo-gba"]),
                 self.entry("Azahar/keys.txt", b"keys", ["nintendo-3ds"], root="save")]
        listing = self.listing("retroarch", files, base_destination="system",
                               save_directory={"folder": "saves", "by_core": False})
        for system, count in ((["nintendo-gba"], 0), (["nintendo-3ds"], 1), (None, 1)):
            args = dict(manifest=listing, dest=here, declared_only=False, system=system)
            with self.subTest(system=system):
                text, _asked = self.line_run(_args(**args), [])
                events, _out = engine_events(_args(**args, check=True, events=True,
                                                   no_input=True))
                saves = [event for event in events if event["event"] == "saves"]
                if count:
                    self.assertIn("1 file read from RetroArch's save directory goes to", text)
                    self.assertEqual([event["files"] for event in saves], [1])
                else:
                    self.assertNotIn("save directory", text)
                    self.assertEqual(saves, [])

    def test_a_list_that_leaves_out_save_files_says_so_before_the_menu(self):
        """ROCKNIX's 44 files left out were said after
        the install only, as the frontend's, where the plan says them."""
        omitted = [{"dest": f"saves/{n}.key", "name": f"{n}.key", "system": "",
                    "systems": [], "required": False, "reason": "no_save_directory",
                    "cores": None} for n in range(3)]
        listing = self.listing("rocknix", [self.entry("a.bin", b"a", ["x"])],
                               omitted_files=omitted)
        card = self.card("ROCKNIX", "ROCKNIX")
        args = _args(manifest=listing, dest=card, declared_only=False)
        text, _asked = self.line_run(args, [])
        said = "3 files read from ROCKNIX's save directory left out"
        self.assertLess(text.index(said), text.index("Enter)"))
        state = checked_state()
        state.platform = "rocknix"
        summary = {"skipped": [{"reason": "no_save_directory", "files": 3}]}
        self.assertIn(said, " ".join(install._unplaced_lines(summary, state)))
        # And the end of the run names it as the plan does.
        seen = [{**entry, "frontend": "ROCKNIX"} for entry in omitted]
        with contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.suppress(SystemExit):
            install._report_outcome([self.here], 1, 0, 0, 3, False,
                                    details=install.OutcomeDetails(omitted_entries=seen))
        self.assertIn(said, out.getvalue())

    def test_the_drives_mounted_here_are_offered_in_both(self):
        """The copy question listed no drive and took q
        as a folder, and the screen's Which folder? listed none where line
        mode numbered them."""
        stick, onion = self.root / "media" / "USBSTICK", self.card("ONION", "Onion")
        stick.mkdir(parents=True)
        mounts = [stick]
        with mock.patch.object(install, "_mounted_cards", return_value=mounts), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                mock.patch.object(install, "_ask", side_effect=["q"]), \
                self.assertRaises(SystemExit) as stop:
            install._ask_from_folder([], onion / "BIOS")
        self.assertEqual(stop.exception.code, install.QUIT_CODE)
        self.assertIn(f"1) {install.card_line(stick)}", out.getvalue())
        with mock.patch.object(install, "_mounted_cards", return_value=[stick, onion]), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                mock.patch.object(install, "_ask", side_effect=["2", ""]):
            install._ask_from_folder([], onion / "BIOS")
        # The card installed to is not offered to copy from.
        self.assertNotIn(str(onion), out.getvalue())
        with mock.patch.object(install, "_mounted_cards", return_value=mounts), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                mock.patch.object(install, "_ask", side_effect=["1"]), \
                mock.patch.object(install, "_missing_dest", return_value=True):
            folder = install.ask_platform_folder("linux", "retroarch")
        # a drive is offered by its bios folder, never its
        # root, which no setup reads.
        self.assertEqual(folder, stick / "bios")
        state = install.TuiState(os_type="linux", home=HOME)
        state.platform, state.stack = "retroarch", ["folder"]
        state.folder_default, state.folder_kind = SYSTEM_DIR, "usual"
        with mock.patch.object(install, "_mounted_cards", return_value=mounts):
            state.folder_scan = install.scan_folder(state)
        rows = install.tui_rows(state)
        self.assertEqual([row.value for row in rows if row.action == "drive"],
                         [stick / "bios"])

    def test_the_systems_are_listed_by_title_in_the_screen_order(self):
        """Line mode listed ids, nintendo-3ds before
        nintendo-ds, where the screen lists titles."""
        titles = {"nintendo-ds": "Nintendo DS", "nintendo-gba": "Nintendo Game Boy Advance"}
        files = [self.entry("ds.bin", b"ds", ["nintendo-ds"]),
                 self.entry("gba.bin", b"gba", ["nintendo-gba"]),
                 self.entry("3ds.bin", b"3ds", ["nintendo-3ds"])]
        manifest = {"system_titles": titles}
        listing = self.listing("retroarch", files, **manifest)
        text, _asked = self.line_run(_args(manifest=listing, dest=self.here,
                                           declared_only=False), ["c"])
        listed = text[text.index("Systems:"):]
        places = [listed.index(label) for label in (
            "1) Nintendo DS  nintendo-ds", "2) Nintendo Game Boy Advance  nintendo-gba",
            "3) nintendo-3ds")]
        self.assertEqual(places, sorted(places))
        state = install.TuiState(os_type="linux", home=HOME)
        state.manifest = {"files": files, **manifest}
        state.systems = [{"system": system, "name": system, "missing": 1, "wrong_hash": 0,
                          "bytes_needed": 2} for system in ("nintendo-3ds", "nintendo-ds",
                                                            "nintendo-gba")]
        order = [row["system"] for row in install._sorted_systems(state)]
        self.assertEqual(order, ["nintendo-ds", "nintendo-gba", "nintendo-3ds"])

    def test_the_card_question_looks_again_and_lists_blank_drives(self):
        """Enter at Card root never looked again, a
        blank stick was listed for KNULLI on the screen alone, and the two
        modes differed on creating its bios."""
        onion = self.card("ONION", "Onion")
        seen: list = []
        answers = iter(["", "1"])

        def answer(_prompt: str) -> str:
            value = next(answers)
            if not value:
                # The card goes in while the question waits.
                seen.append(onion)
            return value

        with mock.patch.object(install, "_mounted_cards", side_effect=lambda: list(seen)), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "_ask", side_effect=answer), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            dest = install.card_install_dest("onion", "retroarch", True)
        self.assertEqual(dest, onion / "BIOS")
        self.assertIn(f"1) {install.card_line(onion)}", out.getvalue())
        # KNULLI fills its card when it first starts: a blank drive is
        # listed in both, after Look again on the screen, and its bios is
        # created without a question in both.
        stick = self.root / "media" / "USBSTICK"
        stick.mkdir(parents=True)
        with mock.patch.object(install, "_mounted_cards", return_value=[stick]), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]), \
                mock.patch.object(install, "_ask", side_effect=["1"]), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            dest = install.card_install_dest("knulli", "knulli", True)
            state = screen_keys(_args(platform="knulli"), [])
            rows = install.tui_rows(state)
            self.assertEqual([row.action for row in rows][:2], ["rescan", "card"])
            self.assertEqual(rows[state.focus["folder"]].action, "rescan")
            press(state, "down", "enter")
        self.assertEqual(dest, stick / "bios")
        self.assertIn(f"1) {install.card_line(stick)}", out.getvalue())
        self.assertEqual((state.dest, state.screen), (stick / "bios", "checking"))

    def test_a_full_or_read_only_folder_is_said_before_enter(self):
        """Line mode showed Enter) install
        everything over a full card and refused after it. On a card setup
        both say to free space on the card."""
        onion = self.card("ONION", "Onion")
        listing = self.listing("retroarch", [self.entry("a.bin", b"a" * 4096, ["x"])])
        usage = mock.Mock(free=1024)
        with mock.patch.object(install.shutil, "disk_usage", return_value=usage), \
                mock.patch.object(install, "dest_drive", return_value=onion):
            install._DETECTED_OS[("retroarch", onion / "BIOS")] = "Onion"
            text, _asked = self.line_run(_args(manifest=listing, dest=onion / "BIOS",
                                               platform="retroarch", declared_only=False),
                                         [], [onion])
            state = checked_state({"free": 1024, "writable": True, "cores": []})
            state.dest = onion / "BIOS"
            install._DETECTED_OS[("retroarch", state.dest)] = "Onion"
            state.facts = install._tui_folder_facts(state)
            plan = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
        menu = text[:text.index("Enter)")]
        self.assertIn("Not enough free space: 4.0 KB needed, 1.0 KB free. Free some space "
                      "on the card first.", menu)
        self.assertIn("Free some space on the card first.", plan)

    def test_a_device_typed_is_named_first(self):
        """"miyoo mini" listed MinUI with RG28XX, RG34XX
        and RG34XX SP, where the screen's row names the Miyoo Mini."""
        install.LOCAL.reset()
        choices = install._line_setups([], set(), "linux")
        found = install._line_matches(choices, "miyoo mini", [], set(), "linux")
        rows = {install._row_name(row): row
                for row in install.setup_list([], set(), "miyoo mini", "linux")}
        self.assertTrue(found)
        for index, label in found:
            name = choices[index][0]
            with self.subTest(setup=name):
                self.assertIn("Miyoo Mini", label.split("(", 1)[1])
                first = rows[name].right.split(", ")[0]
                self.assertTrue(label.split("(", 1)[1].startswith(first), (label, first))

    def test_line_mode_says_setup_where_the_screen_does(self):
        """"Detecting platform..." and "No supported
        platform found here", where the screen says setup and "Nothing was
        found here.\""""
        # The standalone emulators' lists come from the network: none here
        #, and none found.
        with mock.patch.object(install, "_install_standalone_folders", return_value=False):
            text, _asked = self.line_run(_args(declared_only=False), [])
        self.assertIn("Looking for setups here...", text)
        # Said once, the question alone after it.
        self.assertEqual(text.count("Nothing was found here."), 1)
        self.assertIn("\nWhich setup?\n", text)
        self.assertNotIn("Detecting platform", text)
        self.assertNotIn("No supported platform", text)
        state = install.TuiState(os_type="linux", home=HOME)
        state.stack = ["platforms"]
        self.assertIn("Nothing was found here.", " ".join(install.tui_view(state, 80, 24)))

    def test_yes_at_a_terminal_asks_nothing(self):
        """--yes waited at Install for: and at the menu."""
        seen = []
        with mock.patch.object(sys, "argv", ["install.py", "--yes", "--plain"]), \
                mock.patch.object(install, "_run", side_effect=seen.append):
            install.main()
        self.assertTrue(seen[0].no_input)
        self.assertIn("implies --no-input",
                      " ".join(install.build_parser().format_help().split()))
        # Asked nothing, with two setups found where the screen offers both.
        pc = [("retroarch", self.here), ("retroarch", self.root / "other")]
        seen[0].manifest = self.list
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            _text, asked = self.line_run(seen[0], [], found=pc)
        self.assertEqual(asked, [])

    # line mode, and the screen beside it.

    def copy_folder(self) -> tuple[Path, Path]:
        listing, _files = self.game_list()
        old = self.root / "OLD"
        (old / "doom").mkdir(parents=True)
        (old / "gba_bios.bin").write_bytes(b"gba")
        (old / "doom" / "doom1.wad").write_bytes(b"wad" * 10)
        return listing, old

    def test_the_copy_line_says_copying_once(self):
        """"Copying 22 files copied
        from ...", its size read as the folder's."""
        listing, old = self.copy_folder()
        args = _args(manifest=listing, dest=self.here, declared_only=False, no_input=True,
                     offline=True)
        setattr(args, "from", [old])
        text, _asked = self.line_run(args, [])
        self.assertIn(f"Copying 2 files (33 B) from {old}...", text)
        self.assertNotIn("files copied from", text[text.index("\nCopying "):])

    def test_narrowed_is_said_only_when_the_list_shrank(self):
        """Enter for every system said "Narrowed 4 to 4"."""
        args = dict(manifest=self.counted_list(), dest=self.here, declared_only=False,
                    dry_run=True)
        text, _asked = self.line_run(_args(**args), ["c", "", ""])
        self.assertNotRegex(text, r"Narrowed (\d+) to \1 files")
        text, _asked = self.line_run(_args(**args), ["c", "1", ""])
        # The menu counted the choice again before Enter: said once.
        self.assertIn("Counted again for these choices", text)
        self.assertNotIn("Narrowed", text)
        args = _args(manifest=self.counted_list(), dest=self.here, declared_only=False,
                     dry_run=True, no_input=True, system=["doom"])
        text, _asked = self.line_run(args, [])
        self.assertRegex(text, r"Narrowed 4 to \d files")

    def test_the_dry_run_names_systems_by_their_titles(self):
        """--dry-run listed microsoft-msx where the list
        and the screen say Microsoft MSX."""
        files = [self.entry("msx/msx.rom", b"msx", ["microsoft-msx"]),
                 self.entry("gba_bios.bin", b"gba", ["nintendo-gba"])]
        listing = self.listing("retroarch", files, system_titles={
            "microsoft-msx": "Microsoft MSX", "nintendo-gba": "Nintendo Game Boy Advance"})
        args = _args(manifest=listing, dest=self.here, declared_only=False, dry_run=True,
                     no_input=True)
        text, _asked = self.line_run(args, [])
        self.assertIn("  Microsoft MSX  1 file, 3 B", text)
        self.assertNotIn("  microsoft-msx  1 file", text)
        manifest = json.loads(listing.read_text(encoding="utf-8"))
        state = install.TuiState(os_type="linux", home=HOME)
        state.manifest = manifest
        self.assertEqual(install._tui_system_label({"system": "microsoft-msx"},
                                                   install._system_titles(state)),
                         "Microsoft MSX")

    def test_the_largest_systems_tail_counts_groups(self):
        """"... and 78 more systems" under a plan of 65."""
        files = [{"dest": f"{n}.bin", "size": n + 1, "systems": [f"s{n}"]} for n in range(12)]
        files.append({"dest": "shared.bin", "size": 1, "systems": ["s0", "s1"]})
        out = io.StringIO()
        with mock.patch.object(install.shutil, "get_terminal_size",
                               return_value=os.terminal_size((80, 10))), \
                contextlib.redirect_stdout(out):
            install._print_plan(files, Path("dest"), install.Terminal(io.StringIO()))
        self.assertIn("12 systems in 13 groups, the largest first", out.getvalue())
        self.assertIn("... and 3 more groups:", out.getvalue())
        # The same tail under --check, for the files the collection lacks.
        absent = [{"dest": f"{n}.bin", "systems": [f"s{n}", "shared"]} for n in range(10)]
        lines = install._needed_lines(absent, "Absent")
        self.assertIn("    ... and 2 more groups (--check --verbose lists them all)", lines)

    def test_a_command_given_back_keeps_offline_in_both_modes(self):
        """With the variable alone,
        line mode's Same choice ended with --offline and the screen's not."""
        args = dict(manifest=self.counted_list(), dest=self.here, declared_only=False,
                    dry_run=True)
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            text, _asked = self.line_run(_args(**args), ["c", "1", ""])
            line = next(line for line in text.splitlines() if "Same choice" in line)
            self.assertIn(" --offline", line)
            state = checked_state()
            self.assertIn(" --offline", install.tui_command(state))

    def test_q_quits_on_the_quit_code_in_both_modes(self):
        args = dict(manifest=self.counted_list(), dest=self.here, declared_only=False)
        install.LOCAL.reset()
        with mock.patch.object(install, "_ask", return_value="q"), \
                contextlib.redirect_stdout(io.StringIO()), \
                self.assertRaises(SystemExit) as stop:
            install._prompt_custom_selection(install.MenuContext("retroarch", [], []))
        self.assertEqual(stop.exception.code, 2)
        self.assertEqual(install.QUIT_CODE, 2)
        state = checked_state()
        install.tui_update(state, Key("char", "q"))
        self.assertEqual(state.exit_code, 2)
        del args

    def test_a_card_in_the_reader_is_offered_not_asked_for(self):
        """Line mode numbered the card and said to mount
        it, the screen said none was mounted."""
        card = self.root / "media" / "KNULLI2"
        (card / "system").mkdir(parents=True)
        (card / "system" / "batocera.conf").write_text("system.hostname=RG40XXH\n")
        with mock.patch.object(install, "_mounted_cards", return_value=[card]), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "_ask", side_effect=["q"]), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                self.assertRaises(SystemExit):
            install.card_install_dest("knulli", "knulli", interactive=True)
        text = out.getvalue()
        self.assertIn("Type 1 if it is the KNULLI card, or type its top folder.", text)
        self.assertNotIn("Mount the card", text)
        self.assertIn(f"1) {card.name} (card or drive, {card})", text)
        state = install.TuiState(os_type="linux", home=HOME)
        state.platform = "knulli"
        state.card_bound = install.card_bound("knulli", "knulli")
        with mock.patch.object(install, "_mounted_cards", return_value=[card]), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()):
            install._open_folder_screen(state, None)
            rows = install.tui_rows(state)
            text = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
        self.assertEqual(rows[state.focus["folder"]].value, card)
        self.assertNotIn("is mounted", text)

    def test_a_list_and_nothing_found_stops_a_run_without_questions(self):
        """--yes with a list filled this computer's
        default folder, where the page says a run that needs an answer stops."""
        for flag in ({"yes": True}, {}):
            with self.subTest(flag=flag):
                code, text, events = self.unasked([], [], manifest=self.list, **flag)
                self.assertEqual(code, 1, text)
                self.assertNotIn("using default path", text)
                self.assertIn("Name its folder with --dest", text)
                self.assertEqual([(keys["stage"], keys["reason"]) for kind, keys in events
                                  if kind == "error"], [("detect", "not_found")])
        chosen, text, _events = self.unasked([], [], platform="retroarch", yes=True)
        self.assertEqual(chosen, [("retroarch", install._default_dest("linux", "retroarch"))])

    def test_a_terminal_the_screen_cannot_use_is_named(self):
        """TERM unset or dumb gave line questions without
        a word, where a small window said why."""
        reason = install.line_mode_reason
        tty = mock.Mock(isatty=lambda: True)

        def said(env: dict, size: tuple[int, int] = (80, 24), drawing: str = "",
                 **given) -> str:
            with mock.patch.object(install, "_terminal_size", return_value=size), \
                    mock.patch.object(install, "terminal_without_ansi", return_value=drawing), \
                    mock.patch.object(install, "_tui_keys_blocker", return_value=""), \
                    mock.patch.object(install.os, "name", "posix"):
                return reason(install.tui_obstacle(_args(**given), tty, tty, env))

        self.assertEqual(said({}), "TERM is not set: questions come line by line.")
        self.assertEqual(said({"TERM": "dumb"}), "TERM=dumb: questions come line by line.")
        self.assertEqual(said({"TERM": "vt52"}, drawing="TERM=vt52 cannot move the cursor"),
                         "TERM=vt52 cannot move the cursor: questions come line by line.")
        self.assertEqual(said({"TERM": "xterm"}, (39, 12)),
                         "The window is 39x12: questions come line by line (40x12 for the "
                         "full screen).")
        self.assertEqual(said({"TERM": "xterm"}, (0, 0)), "")
        self.assertEqual(said({"TERM": "xterm"}, check=True), "")
        self.assertEqual(reason(install.tui_obstacle(_args(), io.StringIO(), tty, {})), "")
        self.assertEqual(said({"TERM": "xterm"}), "")

    def test_game_data_has_one_wording_and_one_decision(self):
        """Five wordings, "No game data" read as a
        list holding none, and --no-game-data given offered it back on the
        screen alone."""
        listing, _files = self.game_list()
        args = dict(manifest=listing, dest=self.here, declared_only=False, dry_run=True)
        text, _asked = self.line_run(_args(**args), ["g", ""])
        self.assertIn("g) Game data: kept (1 file, 30 B): leave it out", text)
        after = text[text.index("Counted again"):]
        self.assertIn("1 BIOS file (3 B). 1 game data file left out.", after)
        self.assertIn("1 game data file left out (--no-game-data)", after)
        text, _asked = self.line_run(_args(no_game_data=True, **args), [""])
        self.assertNotIn("g) ", text)
        state = checked_state()
        state.manifest = {**state.manifest, "files": [
            *state.manifest["files"], {"dest": "doom/doom1.wad", "size": 30,
                                       "category": "game_data", "systems": ["doom"]}]}
        state.no_game_data = state.cli_no_game_data = True
        self.assertFalse(any(row.action == "gamedata" for row in install.tui_rows(state)))

    def test_three_kinds_are_named_in_both_modes(self):
        """"data files" beside game data files, never
        said what they were."""
        listing, _files = self.game_list()
        manifest = json.loads(listing.read_text(encoding="utf-8"))
        manifest["data_directories"] = [{"ref": "dolphin-sys", "systems": ["nintendo-gba"],
                                         "files": {"a": {"size": 5}, "b": {"size": 5}}}]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            install._print_menu_head(install.MenuContext("retroarch", manifest["files"], [],
                                                         data_trees=manifest["data_directories"],
                                                         manifest=manifest),
                                     current=None, given=None)
        self.assertIn("1 BIOS file (3 B), 1 game data file (30 B) and 2 data files (10 B).",
                      out.getvalue())
        self.assertIn("Data files: the files an emulator reads from a data folder of its own",
                      out.getvalue())

    def test_the_wsl_folder_question_offers_both_sides(self):
        """Line mode's half."""
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "_ask", side_effect=["q"]), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                self.assertRaises(SystemExit):
            install.ask_platform_folder("wsl", "retroarch")
        label, folder = install.other_side("wsl", "retroarch")[0]
        self.assertIn(f"1) {label}", out.getvalue())
        self.assertEqual(out.getvalue().count(install.shown_path(folder)), 1)


if __name__ == "__main__":
    unittest.main()
