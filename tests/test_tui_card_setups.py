"""Card setups: each one reaches its card, a drive is a card by its files, one
reading per card."""

from __future__ import annotations

import tests

import contextlib
import io
import json
import re
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path, PurePosixPath, PureWindowsPath
from unittest import mock

import install
from tests.test_install_app import make_card
from tests.test_install_selection import FakeRepository
from tests.netguard import module_guard
from tests.tuisupport import (
    _args, checked_state, ChoiceRuns, ChoiceScreens, DriveRuns, fresh_state, games_part, HOME,
    install_run, Key, LineModeRuns, press, REPO_ROOT, reported, screen_text, SYSTEM_DIR,
)


# No connection off the loopback and no card of the host reaches a test,
# in this process or one it starts: the module fails at its end when one is tried.
setUpModule, tearDownModule = module_guard("test_tui_card_setups")


class ACardSystemNamedOnAComputer(unittest.TestCase):
    """`--platform onion` on a PC wrote RetroArch's files into the PC's own
    ~/.config/retroarch/system, which Onion never reads: the system's list
    is RetroArch's, and so was the folder detection found for it."""

    ONION = {".tmp_update/onionVersion/version.txt": "4.3.1\n"}

    def card(self, files: dict) -> Path:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        for name, text in files.items():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text(text, encoding="utf-8")
        return root

    def test_the_systems_that_run_from_a_card(self):
        self.assertEqual(install.card_bound("onion", "retroarch"), ("Onion", "BIOS"))
        self.assertEqual(install.card_bound("muOS", "retroarch"), ("muOS", "MUOS/bios"))
        self.assertEqual(install.card_bound("spruceos", "retroarch"), ("spruceOS", "BIOS"))
        self.assertEqual(install.card_bound("knulli", "knulli"), ("KNULLI", "bios"))
        self.assertEqual(install.card_bound("nextui", "nextui"), ("NextUI", ""))
        self.assertIsNone(install.card_bound("retroarch", "retroarch"))
        self.assertIsNone(install.card_bound("batocera", "batocera"))

    def test_without_questions_the_run_names_the_card_and_writes_nothing(self):
        home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, home, True)
        system = home / ".config" / "retroarch" / "system"
        system.mkdir(parents=True)
        (home / ".config" / "retroarch" / "retroarch.cfg").write_text(
            f'system_directory = "{system}"\n', encoding="utf-8")
        with FakeRepository() as repo:
            proc = install_run("--platform", "onion", "--yes",
                               env={**repo.env(), "HOME": str(home), "RETROBIOS_OS": "linux"})
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("Onion keeps its BIOS files on its SD card, not on this machine.",
                      proc.stderr)
        self.assertIn("--platform onion --dest /media/$USER/<card>", proc.stderr)
        self.assertEqual(list(system.iterdir()), [])

    def test_one_mounted_card_of_that_system_is_taken(self):
        onion, other = self.card(self.ONION), self.card({"roms/a": ""})
        with mock.patch.object(install, "_mounted_cards", return_value=[other, onion]), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            dest = install.card_install_dest("onion", "retroarch", interactive=False)
        self.assertEqual(dest, onion / "BIOS")
        self.assertIn(f"Onion card found at {onion.name}, BIOS folder {onion / 'BIOS'}",
                      out.getvalue())

    def test_at_a_terminal_the_card_root_is_asked(self):
        onion = self.card(self.ONION)
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "_ask", return_value=str(onion)) as ask, \
                contextlib.redirect_stdout(io.StringIO()) as out:
            dest = install.card_install_dest("onion", "retroarch", interactive=True)
        self.assertEqual(dest, onion / "BIOS")
        self.assertIn("Mount the card, then type its top folder.", out.getvalue())
        ask.assert_called_once()
        knulli = self.card({"roms/a": ""})
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "_ask", return_value=str(knulli)), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(install.card_install_dest("knulli", "knulli", True),
                             knulli / "bios")

    def ask(self, *answers: str):
        """_ask answering in turn, and the prompts it was asked."""
        given = iter(answers)
        asked: list = []

        def answer(prompt: str) -> str:
            asked.append(prompt)
            return next(given)
        return mock.patch.object(install, "_ask", side_effect=answer), asked

    def test_a_typed_root_that_does_not_exist_is_asked_again(self):
        """A typo four folders deep was created and
        filled, and a menu answer (8) became the card."""
        onion = self.card(self.ONION)
        typo = REPO_ROOT / "tmp" / "no-such" / "media" / "NEXT"
        patcher, asked = self.ask("8", str(typo), str(onion))
        with mock.patch.object(install, "_mounted_cards", return_value=[]), patcher, \
                contextlib.redirect_stdout(io.StringIO()) as out:
            dest = install.card_install_dest("onion", "retroarch", interactive=True)
        self.assertEqual(dest, onion / "BIOS")
        self.assertEqual(len(asked), 3)
        # No card is listed: 8 is no number of the list, and no folder.
        self.assertIn("Type the card's top folder, Enter to look again, or q to quit.",
                      out.getvalue())
        self.assertIn("NEXT does not exist, or is not a folder. Type the top folder of the "
                      "Onion card.", out.getvalue())
        self.assertFalse((REPO_ROOT / "tmp" / "no-such").exists())

    def test_a_typed_root_that_is_no_card_of_that_system_is_asked_again(self):
        """A folder that was no Onion card ended the run."""
        blank, onion = self.card({"roms/a": ""}), self.card(self.ONION)
        patcher, asked = self.ask(str(blank), str(onion))
        with mock.patch.object(install, "_mounted_cards", return_value=[]), patcher, \
                contextlib.redirect_stdout(io.StringIO()) as out:
            dest = install.card_install_dest("onion", "retroarch", interactive=True)
        self.assertEqual((dest, len(asked)), (onion / "BIOS", 2))
        self.assertIn(f"{blank} is not an Onion SD card: no Onion files on it. Onion keeps "
                      ".tmp_update at the root of its card.", out.getvalue())

    def test_a_minui_root_is_a_minui_card(self):
        blank = self.card({"roms/a": ""})
        minui = self.card({".system/version.txt": "NextUI-20250101\n", "Bios/x": ""})
        patcher, asked = self.ask(str(minui / "Bios"), str(blank), str(minui))
        with mock.patch.object(install, "_mounted_cards", return_value=[]), patcher, \
                contextlib.redirect_stdout(io.StringIO()) as out:
            dest = install.card_install_dest("nextui", "nextui", interactive=True)
        self.assertEqual((dest, len(asked)), (minui, 3))
        self.assertIn(f"is inside a NextUI card, whose root is {minui}", out.getvalue())
        self.assertIn("is not a NextUI SD card: no NextUI files on it. NextUI keeps "
                      ".system/version.txt at the root of its card.", out.getvalue())

    def test_the_mounted_drives_are_listed_and_taken_by_number(self):
        """The screen lists the mounted cards, the
        prompt did not: it listed
        every drive, a muOS card beside Onion's question, and the muOS card
        taken by number made the run a muOS install."""
        muos, blank = self.card({"MUOS/bios/x": ""}), self.card({"roms/a": ""})
        first, second = (self.card({"system/batocera.conf": "system.hostname=KNULLI\n"})
                         for _card in range(2))
        patcher, asked = self.ask("4", "2")
        with mock.patch.object(install, "_mounted_cards",
                               return_value=[muos, first, blank, second]), \
                patcher, contextlib.redirect_stdout(io.StringIO()) as out:
            dest = install.card_install_dest("knulli", "knulli", interactive=True)
        self.assertEqual((dest, len(asked)), (second / "bios", 2))
        self.assertIn(f"1) {first.name} (KNULLI card, {first})", out.getvalue())
        self.assertIn(f"2) {second.name} (KNULLI card, {second})", out.getvalue())
        self.assertNotIn(str(muos), out.getvalue())
        # KNULLI fills its card when it first starts, and
        # a blank drive is listed after its own cards, as on the screen.
        self.assertIn(f"3) {blank.name} (card or drive, {blank})", out.getvalue())
        self.assertIn("Type a number from 1 to 3, a folder, Enter to look again, or q to "
                      "quit.", out.getvalue())

    def test_creating_several_folders_on_the_card_is_asked(self):
        """N to the question ended the whole run where it
        meant "not that card"."""
        root = self.card({"roms/a.txt": ""})
        rocknix = root / "R"
        rocknix.mkdir()
        card = self.card({"roms/a": ""})
        make_card(card, "ROCKNIX")
        patcher, asked = self.ask(str(rocknix), "n", str(card))
        with mock.patch.object(install, "_mounted_cards", return_value=[]), patcher, \
                contextlib.redirect_stdout(io.StringIO()) as out:
            dest = install.card_install_dest("rocknix", "rocknix", interactive=True)
        self.assertEqual(dest, card / "roms" / "bios")
        self.assertIn("[y/N]", asked[1])
        self.assertEqual(asked[2], "Card root, Enter to look again, q to quit: ")
        self.assertIn("Not created.", out.getvalue())
        self.assertFalse((rocknix / "roms").exists())

    def test_the_menu_asks_a_card_system_for_its_card(self):
        """ROCKNIX picked from the menu on a PC was
        offered /storage/roms/bios."""
        card = self.card({"roms/a": ""})
        make_card(card, "ROCKNIX")
        patcher, asked = self.ask(str(card))
        with mock.patch.object(install, "_choose_platform", return_value="rocknix"), \
                mock.patch.object(install, "_mounted_cards", return_value=[]), patcher, \
                contextlib.redirect_stdout(io.StringIO()):
            chosen = install._prompt_manual_platform("linux")
        self.assertEqual(chosen, [("rocknix", card / "roms" / "bios")])
        self.assertEqual(asked, ["Card root, Enter to look again, q to quit: "])

    def test_a_card_of_another_system_is_not_offered(self):
        """A on the first mount wrote Onion's BIOS/ on a
        muOS card, which reads MUOS/bios."""
        muos, blank = self.card({"MUOS/bios/x": ""}), self.card({"roms/a": ""})
        found = [("retroarch", SYSTEM_DIR)]
        with mock.patch.object(install, "_mounted_cards", return_value=[muos, blank]), \
                mock.patch.object(install, "detect_platforms", return_value=found), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            state, effects = install.tui_start(_args(platform="onion"), "linux")
            self.assertEqual((state.screen, effects), ("folder", []))
            rows = install.tui_rows(state)
            text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertEqual([row.action for row in rows], ["browse", "type", "rescan"])
        self.assertEqual(state.focus["folder"], 0)
        self.assertIn("Where is the SD card?", text)
        self.assertIn("No Onion card is mounted. Insert it, then choose Look again.", text)

    def test_only_the_cards_of_that_system_are_listed(self):
        first, second = self.card(self.ONION), self.card(self.ONION)
        muos = self.card({"MUOS/bios/x": ""})
        state = fresh_state()
        state.stack = ["setup", "platforms"]
        state.filters["platforms"] = "onion"
        state.focus["platforms"] = 1
        with mock.patch.object(install, "_mounted_cards", return_value=[muos, first, second]):
            press(state, "enter")
            self.assertEqual(state.screen, "folder")
            rows = install.tui_rows(state)
            install.tui_update(state, Key("enter"))
        self.assertEqual([(row.action, row.value) for row in rows][:2],
                         [("card", first), ("card", second)])
        self.assertNotIn("rescan", [row.action for row in rows])
        self.assertEqual(state.dest, first / "BIOS")
        # Titled as the card found by itself.
        self.assertEqual(install.detected_os("retroarch", first / "BIOS"), "Onion")

    def test_look_again_finds_the_card_inserted(self):
        onion = self.card(self.ONION)
        mounts: list = []
        with mock.patch.object(install, "_mounted_cards", side_effect=lambda: list(mounts)), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            state, _effects = install.tui_start(_args(platform="onion"), "linux")
            press(state, "down", "down", "enter")
            self.assertEqual(state.status, "Still no Onion card is mounted.")
            mounts.append(onion)
            press(state, "enter")
            rows = install.tui_rows(state)
        self.assertEqual(rows[state.focus["folder"]].action, "card")
        self.assertEqual(state.status, "")

    def test_a_folder_that_is_no_card_of_that_system_is_refused(self):
        blank = self.card({"roms/a": ""})
        muos = self.card({"MUOS/bios/x": ""})
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            state, _effects = install.tui_start(_args(platform="onion"), "linux")
            press(state, "enter")
            self.assertEqual(state.screen, "browse")
            install._browse_to(state, blank)
            effects = press(state, "enter")
            self.assertEqual((effects, state.screen), ([], "browse"))
            self.assertIn("Not an Onion SD card: no Onion files on it.", state.status)
            self.assertIn(f"{blank} is not an Onion SD card", state.status_more)
            self.assertIsNone(state.dest)
            # a muOS card made the run a muOS install
            # without a word.
            install._browse_to(state, muos)
            press(state, "enter")
            # it is a card's top folder, of another card.
            self.assertEqual(state.status, "That is a muOS card. Insert the Onion card, or "
                             "go back and choose muOS.")
        self.assertIsNone(state.dest)

    def test_a_typed_card_root_is_checked_on_the_path_screen(self):
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            state, _effects = install.tui_start(_args(platform="rocknix"), "linux")
            press(state, "down", "enter")
            self.assertEqual(state.screen, "path")
            state.path_text = str(REPO_ROOT / "tmp" / "no-such-card")
            effects = press(state, "enter")
        self.assertEqual((effects, state.screen), ([], "path"))
        self.assertEqual("That folder does not exist. Choose the card's top folder.",
                         state.status)

    def test_a_dest_that_is_no_card_of_that_system_is_refused(self):
        blank = self.card({"roms/a": ""})
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            state, effects = install.tui_start(_args(platform="onion", dest=str(blank)),
                                               "linux")
        self.assertEqual((effects, state.screen), ([], "folder"))
        self.assertIn("Not an Onion SD card", state.status)

    def test_change_folder_names_the_folder_it_reuses(self):
        """Use this folder on the card screen named
        nothing."""
        onion = self.card(self.ONION)
        state = checked_state()
        state.platform, state.card_bound = "retroarch", ("Onion", "BIOS")
        state.dest = onion / "BIOS"
        press(state, "o")
        rows = install.tui_rows(state)
        state.focus["options"] = [row.action for row in rows].index("folder")
        press(state, "enter")
        with mock.patch.object(install, "_mounted_cards", return_value=[]):
            text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertEqual(state.screen, "folder")
        self.assertIn("Where is the SD card?", text)
        self.assertIn("The BIOS folder chosen for Onion:", text)
        self.assertEqual(state.folder_default, onion / "BIOS")

    def test_the_interface_takes_the_one_onion_card_mounted(self):
        onion = self.card(self.ONION)
        (onion / "BIOS").mkdir()
        found = [("retroarch", SYSTEM_DIR)]
        with mock.patch.object(install, "_mounted_cards", return_value=[onion]), \
                mock.patch.object(install, "detect_platforms", return_value=found), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            state, effects = install.tui_start(_args(platform="onion"), "linux")
        self.assertEqual(effects, [("fetch", "retroarch")])
        self.assertEqual(state.dest, onion / "BIOS")

    def test_on_the_device_its_own_folder_is_used(self):
        device = Path("/mnt/SDCARD/BIOS")
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "detect_platforms",
                                  return_value=[("retroarch", device)]), \
                mock.patch.object(install, "detect_frontends", return_value=[]), \
                mock.patch.dict(install._DETECTED_OS, {("retroarch", device): "Onion"}), \
                mock.patch.object(install.Path, "exists", return_value=True):
            state, effects = install.tui_start(_args(platform="onion"), "linux")
        self.assertEqual(effects, [("fetch", "retroarch")])
        self.assertEqual(state.dest, device)

    def test_a_stick_inserted_moves_no_row_until_look_again(self):
        """A blank stick mounted while the folder screen was open moved the
        rows on the next frame, and Enter on Look again opened the browser."""
        stick = self.card({"README.txt": ""})
        state = install.TuiState(os_type="linux", home=HOME)
        state.platform, state.card_bound = "knulli", ("KNULLI", "bios")
        with mock.patch.object(install, "_mounted_cards", return_value=[]):
            install._open_folder_screen(state, None)
        before = [row.label for row in install.tui_rows(state)]
        state.focus["folder"] = before.index("Look again")
        with mock.patch.object(install, "_mounted_cards", return_value=[stick]) as scan:
            install.tui_view(state, 80, 24)
            self.assertEqual([row.label for row in install.tui_rows(state)], before)
            self.assertEqual(scan.call_count, 0)
            install.tui_update(state, Key("enter"))
        self.assertEqual(state.screen, "folder")
        self.assertIn(stick, [row.value for row in install.tui_rows(state)])


class ACardSetupIsOneDesign(unittest.TestCase):
    """A setup that runs from
    its SD card, chosen on a computer, always asks for that card."""

    def platforms(self, needle: str = "") -> install.TuiState:
        state = fresh_state()
        state.stack = ["setup", "platforms"]
        state.filters["platforms"] = needle
        state.focus["platforms"] = 1
        return state

    def test_a_handheld_typed_in_the_filter_asks_for_its_card(self):
        for needle in ("onion", "miyoo mini", "rg35xx", "r36s", "arkos", "anbernic"):
            with self.subTest(needle=needle):
                state = self.platforms(needle)
                with mock.patch.object(install, "_mounted_cards", return_value=[]):
                    row = install.tui_rows(state)[1]
                    effects = press(state, "enter")
                    text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
                plat, name = row.value if row.action == "cardsystem" else (row.value,) * 2
                self.assertEqual((effects, state.screen), ([], "folder"))
                self.assertIsNotNone(state.card_bound)
                self.assertEqual(state.card_bound, install.card_bound(name, plat))
                self.assertIn("Where is the SD card?", text)
                self.assertNotIn("default", [r.action for r in install.tui_rows(state)])
                self.assertNotIn(str(SYSTEM_DIR), text)

    def test_retroarch_typed_is_still_this_computer(self):
        state = self.platforms("retroarch")
        press(state, "enter")
        self.assertIsNone(state.card_bound)
        self.assertEqual(state.folder_default, SYSTEM_DIR)

    def test_a_card_backed_out_of_is_forgotten(self):
        state = fresh_state()
        state.stack = ["setup"]
        state.focus["setup"] = 2
        press(state, "enter")
        state.focus["platforms"] = install._platform_focus(state, "rocknix")
        with mock.patch.object(install, "_mounted_cards", return_value=[]):
            press(state, "enter")
            self.assertEqual(state.card_bound, ("ROCKNIX", "roms/bios"))
            press(state, "esc", "esc")
            self.assertEqual(state.screen, "setup")
            state.focus["setup"] = 0
            with mock.patch.object(install.Path, "exists", return_value=True):
                press(state, "enter")
        self.assertIsNone(state.card_bound)
        self.assertEqual((state.platform, state.dest), ("retroarch", SYSTEM_DIR))
        install._open_folder_screen(state, state.dest, "chosen")
        title = install.tui_view(state, 80, 24)[0]
        self.assertIn("Which folder?", title)
        self.assertNotIn("card", [row.action for row in install.tui_rows(state)])

    def test_on_the_device_its_own_folder_is_offered(self):
        share = Path("/userdata/bios")
        state = fresh_state()
        state.setups = [("knulli", share, "KNULLI")]
        state.setup_folders = install.setup_folders(state.setups)
        state.stack = ["setup", "platforms"]
        state.focus["platforms"] = install._platform_focus(state, "knulli")
        with mock.patch.dict(install._DETECTED_OS, {("knulli", share): "KNULLI"}), \
                mock.patch.object(install, "_mounted_cards", return_value=[]):
            press(state, "enter")
            rows = [row.action for row in install.tui_rows(state)]
            text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertEqual(rows, ["default", "browse", "type"])
        self.assertEqual((state.folder_default, state.folder_kind), (share, "found"))
        self.assertIn("Which folder? KNULLI reads its BIOS files from: /userdata/bios", text)
        self.assertNotIn("No KNULLI card is mounted", text)


def _card_from_rules(root: Path, setup: install.CardSetup) -> Path:
    """A card as setup's system leaves it, written from the rules that
    tell it: a test that names each marker by hand misses the next one."""
    root.mkdir(parents=True, exist_ok=True)
    if setup.plat in install.CARD_PLATFORMS:
        (root / ".system").mkdir(exist_ok=True)
        prefix = next(prefix for name, _marker, prefix in install._CARD_RULES
                      if name == setup.plat)
        (root / install.CARD_MARKER).write_text(f"{prefix}20250101\n", encoding="utf-8")
    for rule in setup.rules[:1]:
        if rule.method == "file_matches":
            path, pattern = rule.values
            text = re.sub(r"\\(.)", r"\1", pattern.strip("^$").replace(r"\s*", ""))
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            (root / path).write_text(text + "\n", encoding="utf-8")
            continue
        if rule.method == "games_part":
            # What the system writes beside its bios folder on that part.
            (root / "bios").mkdir(exist_ok=True)
        for value in rule.values:
            (root / value).parent.mkdir(parents=True, exist_ok=True)
            # A marker the BIOS folder sits under is a folder on the card
            # (muOS's MUOS/bios): written as a file, no folder fits below it.
            if (rule.method == "games_part" and "." not in PurePosixPath(value).name
                    or str(setup.below).startswith(f"{value}/")):
                (root / value).mkdir(exist_ok=True)
            else:
                (root / value).write_text("", encoding="utf-8")
    return root


def _card_row(setup: install.CardSetup) -> str:
    """The setup list's row of a card system: MiSTer's board sits on a desk
    and keeps its plain row among the platforms."""
    return setup.name if setup.plat in install._DESK_CARDS else f"{setup.name}, SD card"


def _setup_folder(setup: install.CardSetup, card: Path) -> Path:
    return card / setup.below if setup.below else card


class EveryCardSetupGoesToItsCard(unittest.TestCase):
    """The card setups were fixed one
    by one, and UnofficialOS, ArchR, ArkOS, MiyooCFW and the Anbernic
    firmware stayed on the RetroArch row, which listed them and opened this
    computer's folder. Each system that runs from its SD card, from every
    way in, goes to its card."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.setups = install.card_setups()

    def test_one_list_holds_every_card_system(self):
        names = {setup.name for setup in self.setups}
        self.assertLessEqual({rule.name for rule in install._card_rules()}, names)
        self.assertLessEqual(set(install._systems_reading()["retroarch"]), names)
        self.assertLessEqual({install.display_name(plat) for plat in install.CARD_PLATFORMS},
                             names)
        self.assertLessEqual({"Onion", "spruceOS", "muOS", "JELOS", "ROCKNIX", "KNULLI",
                              "ArkOS", "dArkOS", "UnofficialOS", "ArchR", "MiyooCFW",
                              "Anbernic stock firmware", "Allium", "Koriki", "CrossMix-OS",
                              "MinUI", "NextUI", "MyMinUI"}, names)
        self.assertEqual(len(names), len(self.setups))
        # A system the guide writes is one of them.
        try:
            import yaml
        except ImportError:
            return
        guides = yaml.safe_load((REPO_ROOT / "platforms" / "_guides.yml").read_text())
        for system in guides["handheld_guide"]["systems"]:
            with self.subTest(system=system["name"]):
                self.assertIn(system["name"], names)

    def test_its_folder_is_the_one_the_guide_names(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("pyyaml is not installed")
        guides = yaml.safe_load((REPO_ROOT / "platforms" / "_guides.yml").read_text())
        below = {setup.name: setup.below for setup in self.setups}
        for system in guides["handheld_guide"]["systems"]:
            folder = re.search(r"`([^`]+)`", system.get("folder", ""))
            if folder:
                with self.subTest(system=system["name"]):
                    self.assertTrue(folder.group(1).endswith(below[system["name"]]),
                                    (folder.group(1), below[system["name"]]))

    def platforms(self, needle: str = "") -> install.TuiState:
        state = fresh_state()
        state.stack = ["setup", "platforms"]
        state.filters["platforms"] = needle
        return state

    def test_the_setup_list_has_a_row_for_each_without_the_filter(self):
        state = self.platforms()
        rows = install.tui_rows(state)
        self.assertEqual({row.value: row for row in rows if row.action == "platform"}[
            "retroarch"].right, "")
        for setup in self.setups:
            with self.subTest(system=setup.name):
                state = self.platforms()
                rows = install.tui_rows(state)
                index = next(i for i, row in enumerate(rows)
                             if row.label == _card_row(setup))
                state.focus["platforms"] = index
                with mock.patch.object(install, "_mounted_cards", return_value=[]):
                    effects = press(state, "enter")
                    text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
                self.assertEqual((effects, state.screen), ([], "folder"))
                self.assertEqual(state.card_bound, (setup.name, setup.below))
                self.assertIsNone(state.folder_default)
                self.assertIn("Where is the SD card?", text)
                self.assertNotIn(str(SYSTEM_DIR), text)

    def test_its_name_in_the_filter_finds_its_row(self):
        for setup in self.setups:
            with self.subTest(system=setup.name):
                rows = install.tui_rows(self.platforms(setup.name))
                self.assertIn(_card_row(setup), [row.label for row in rows])

    def test_platform_named_on_a_computer_asks_for_the_card(self):
        for setup in self.setups:
            with self.subTest(system=setup.name):
                plat = install.normalize_platform(setup.name, say=False)
                self.assertEqual(plat, setup.plat)
                self.assertEqual(install.card_bound(setup.name, plat),
                                 (setup.name, setup.below))
                with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                        contextlib.redirect_stderr(io.StringIO()) as err, \
                        self.assertRaises(SystemExit) as stop:
                    reported(install.card_install_dest, setup.name, plat, interactive=False)
                self.assertEqual(stop.exception.code, 1)
                self.assertIn(f"{setup.name} keeps its BIOS files on its SD card",
                              err.getvalue())
                with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                        mock.patch.object(install, "detect_platforms", return_value=[
                            ("retroarch", SYSTEM_DIR)]), \
                        mock.patch.object(install, "detect_frontends", return_value=[]):
                    state, effects = install.tui_start(_args(platform=setup.name), "linux")
                self.assertEqual((effects, state.screen), ([], "folder"))
                self.assertEqual(state.card_bound, (setup.name, setup.below))
                self.assertIsNone(state.folder_default)

    def test_the_line_menu_offers_it_and_asks_for_its_card(self):
        offered = [name for name, _label in install._line_setups()]
        for setup in self.setups:
            with self.subTest(system=setup.name):
                key = setup.plat if setup.name == install.display_name(setup.plat) \
                    else setup.name
                self.assertIn(key, offered)
                card = _card_from_rules(self.root / f"menu{offered.index(key)}", setup)
                with mock.patch.object(install, "_choose_platform", return_value=key), \
                        mock.patch.object(install, "_mounted_cards", return_value=[]), \
                        mock.patch.object(install, "_ask", return_value=str(card)), \
                        contextlib.redirect_stdout(io.StringIO()):
                    chosen = install._prompt_manual_platform("linux", ask=False)
                self.assertEqual(chosen, [(setup.plat, _setup_folder(setup, card))])

    def test_its_card_gives_one_folder_whichever_way_it_is_named(self):
        for index, setup in enumerate(self.setups):
            with self.subTest(system=setup.name):
                card = _card_from_rules(self.root / f"card{index}", setup)
                # a card no file names gets its folder
                # below the root with --dest too, as typed.
                want = _setup_folder(setup, card)
                with contextlib.redirect_stdout(io.StringIO()):
                    by_dest = install.card_dest(setup.name, setup.plat, card)
                self.assertEqual(by_dest, (setup.plat, want))
                with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                        mock.patch.object(install, "detect_platforms", return_value=[]), \
                        mock.patch.object(install, "detect_frontends", return_value=[]):
                    state, _effects = install.tui_start(
                        _args(platform=setup.name, dest=str(card)), "linux")
                    self.assertEqual(state.dest, want)
                    # --dest alone, then the setup's row: the folder of the
                    # same --dest.
                    state, _effects = install.tui_start(_args(dest=str(card)), "linux")
                    if state.screen == "platforms":
                        rows = install.tui_rows(state)
                        label = (f"{setup.name}, SD card")
                        state.focus["platforms"] = [row.label for row in rows].index(label)
                        press(state, "enter")
                    self.assertEqual(state.dest, want)
                # Its card chosen as a card's root: its BIOS folder below it.
                if setup.known():
                    choice = install.card_choice(setup.name, setup.plat, card)
                    self.assertEqual((choice.refused, choice.folder),
                                     ("", _setup_folder(setup, card)))

    def test_another_systems_card_is_refused_for_each(self):
        """KNULLI and ROCKNIX took a
        muOS or an Onion card, and wrote their layout into it."""
        cards = {}
        for name in ("muOS", "Onion", "MinUI"):
            setup = next(item for item in self.setups if item.name == name)
            cards[name] = _card_from_rules(self.root / name, setup)
        for setup in self.setups:
            for name, card in cards.items():
                if name == setup.name or (name == "MinUI"
                                          and setup.plat in install.CARD_PLATFORMS):
                    continue
                with self.subTest(system=setup.name, card=name):
                    choice = install.card_choice(setup.name, setup.plat, card)
                    self.assertIn(f"is {install._a(name)} card, not "
                                  f"{install._a(setup.name)} card", choice.refused)
                    self.assertTrue(install.card_choice(setup.name, setup.plat,
                                                        card).refused)
                    with mock.patch.object(install, "_mounted_cards",
                                           return_value=list(cards.values())):
                        self.assertNotIn(card, install.mounted_cards_of(setup.name,
                                                                        setup.plat))

    def test_a_games_part_named_by_its_bios_folder_is_its_card(self):
        """AmberELEC and EmuELEC write bios/ below their games part, as
        RetroDECK below its folder. Their BIOS folder named got bios/bios
        on a card not started once, and was refused on one started."""
        for setup in self.setups:
            if setup.name not in install._GAMES_PART_CARDS:
                continue
            started = _card_from_rules(self.root / setup.name / "started", setup)
            blank = self.root / setup.name / "blank"
            (blank / "bios").mkdir(parents=True)
            for card in (started, blank):
                with self.subTest(system=setup.name, card=card.name):
                    choice = install.card_choice(setup.name, setup.plat, card / "bios")
                    self.assertEqual((choice.refused, choice.folder), ("", card))
            # A folder named bios holding bios/ is a card's root, as named.
            nested = self.root / setup.name / "bios"
            (nested / "bios").mkdir(parents=True)
            self.assertEqual(install.card_choice(setup.name, setup.plat, nested).folder,
                             nested)

    def test_a_mister_card_gets_its_files_below_games(self):
        """A MiSTer card mounted on a computer got RetroArch's list, and
        with --platform misterfpga its files at the root, where MiSTer
        reads none: it reads games/<core>/ below /media/fat."""
        card = self.root / "MiSTer"
        (card / "games").mkdir(parents=True)
        (card / "_Computer").mkdir()
        for name in ("MiSTer", "menu.rbf", "MiSTer.ini"):
            (card / name).write_text("", encoding="utf-8")
        self.assertEqual(install.card_system(card),
                         ("misterfpga", card / "games", "MiSTer FPGA"))
        for named in (card, card / "games"):
            with self.subTest(named=named.name):
                choice = install.card_choice("misterfpga", "misterfpga", named)
                self.assertEqual((choice.refused, choice.folder), ("", card / "games"))
        # A folder holding a games folder and nothing of MiSTer's is no card.
        other = self.root / "stick"
        (other / "games").mkdir(parents=True)
        self.assertIsNone(install.card_system(other))

    def test_a_blank_drive_is_refused_where_the_card_always_names_its_system(self):
        blank = self.root / "BLANK"
        blank.mkdir()
        for setup in self.setups:
            with self.subTest(system=setup.name):
                choice = install.card_choice(setup.name, setup.plat, blank)
                if setup.known() and not setup.fresh:
                    self.assertIn(f"is not {install._a(setup.name)} SD card", choice.refused)
                else:
                    self.assertEqual((choice.refused, choice.folder),
                                     ("", _setup_folder(setup, blank)))
                    self.assertTrue(choice.note)


class OneCardReading(unittest.TestCase):
    """One reading
    of a card's root, said the same on the screen and in line mode."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        patcher = mock.patch.dict(install._DETECTED_OS, {})
        patcher.start()
        self.addCleanup(patcher.stop)

    def blank(self, name: str = "USBSTICK") -> Path:
        stick = self.root / name
        (stick / "photos").mkdir(parents=True)
        return stick

    def start(self, **given) -> install.TuiState:
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            state, _effects = install.tui_start(_args(**given), "linux")
        return state

    def test_a_blank_card_gets_one_folder_and_one_note_everywhere(self):
        """--dest kept the stick's
        root, typed it got bios below it, and the screen said nothing."""
        stick = self.blank()
        for named, plat, below in (("knulli", "knulli", "bios"),
                                   ("rocknix", "rocknix", "roms/bios"),
                                   ("ArkOS", "retroarch", "bios")):
            with self.subTest(system=named):
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    by_dest = install.card_dest(named, plat, stick)
                self.assertEqual(by_dest, (plat, stick / below))
                note = install.card_choice(named, plat, stick).note
                self.assertTrue(note)
                self.assertIn(note, out.getvalue())
                state = self.start(platform=named, dest=str(stick))
                self.assertEqual(state.dest, stick / below)
                self.assertEqual(state.card_note, note)
                # one rule with line mode, whose question
                # creates one missing level and says it. Two are asked, and
                # the note is kept on Create the folder? and on the plan.
                one = (stick / below).parent.is_dir()
                self.assertEqual(state.screen, "checking" if one else "create")
                if not one:
                    self.assertIn(note.split(":")[0],
                                  screen_text(install.tui_view(state, 120, 40)))
                    install.tui_update(state, Key("enter"))
                self.assertEqual(state.card_note, note)

    def test_the_minui_family_refuses_a_blank_dest(self):
        """Taken with --dest, refused typed."""
        stick = self.blank()
        for plat in ("minui", "nextui", "myminui"):
            with self.subTest(platform=plat):
                choice = install.card_choice(plat, plat, stick)
                self.assertIn("SD card", choice.refused)
                with self.assertRaises(SystemExit), \
                        contextlib.redirect_stderr(io.StringIO()):
                    install.card_dest(plat, plat, stick)

    def test_a_card_mounted_as_its_bios_folder_is_the_card(self):
        """An Onion card mounted as BIOS was refused,
        ROCKNIX's roms/bios was taken for KNULLI, a muOS card's folder
        too."""
        onion = self.root / "BIOS"
        make_card(onion, "Onion")
        choice = install.card_choice("Onion", "retroarch", onion)
        self.assertEqual((choice.refused, choice.folder), ("", onion / "BIOS"))
        knulli = self.root / "k" / "bios"
        make_card(knulli, "KNULLI")
        self.assertEqual(install.card_choice("knulli", "knulli", knulli).folder,
                         knulli / "bios")
        rocknix = self.root / "ROCKNIX"
        make_card(rocknix, "ROCKNIX")
        refused = install.card_choice("knulli", "knulli", rocknix / "roms" / "bios")
        self.assertIn("is a ROCKNIX card, not a KNULLI card", refused.refused)
        muos = self.root / "MUOS"
        make_card(muos, "muOS")
        refused = install.card_choice("knulli", "knulli", muos / "MUOS" / "bios")
        self.assertIn("is a muOS card", refused.refused)

    def test_no_folder_above_a_mounted_drive_is_its_card(self):
        """A card mounted as MUOS beside a stick: /media/me, which holds
        it, is no muOS card for the stick."""
        stick = self.blank()
        (self.root / "MUOS" / "bios").mkdir(parents=True)
        with mock.patch.object(install, "_mounted_cards",
                               return_value=[stick, self.root / "MUOS"]):
            choice = install.card_choice("knulli", "knulli", stick)
            self.assertEqual((choice.refused, choice.folder), ("", stick / "bios"))
            bios = self.root / "mnt" / "bios"
            (bios / "x").mkdir(parents=True)
        with mock.patch.object(install, "_mounted_cards", return_value=[bios]):
            # A drive mounted at a folder named bios is the card itself.
            self.assertEqual(install._card_and_below(
                install.card_setup("knulli", "knulli"), bios), (bios, False))

    def test_a_refused_dest_says_why_in_the_events(self):
        """Code 1 and no reason in the stream."""
        stick = self.blank()
        proc = install_run("--events", "--platform", "onion", "--dest", str(stick),
                           "--manifest", str(REPO_ROOT / "install" / "retroarch.json"),
                           "--dry-run", env={install.OFFLINE_VARIABLE: "1"})
        self.assertEqual(proc.returncode, 1, proc.stderr)
        events = [json.loads(line) for line in proc.stdout.splitlines()]
        error = next(event for event in events if event["event"] == "error")
        self.assertEqual((error["stage"], error["reason"]), ("detect", "not_found"))
        self.assertIn("is not an Onion SD card", error["message"])
        self.assertEqual(events[-1], {"event": "end", "code": 1})
        table = (REPO_ROOT / "wiki" / "installer.md").read_text(encoding="utf-8")
        self.assertIn("not the card of the system named", table)

    def test_a_card_no_file_names_is_titled_by_its_system(self):
        """An ArkOS card chosen read as RetroArch."""
        stick = self.blank()
        state = self.start(platform="ArkOS", dest=str(stick))
        self.assertEqual(install.detected_os("retroarch", state.dest), "ArkOS")

    def test_a_list_named_for_another_systems_card_says_so(self):
        """--platform batocera on an Onion card."""
        onion = self.root / "ONION"
        make_card(onion, "Onion")
        choice = install.card_choice("batocera", "batocera", onion)
        self.assertEqual((choice.refused, choice.folder), ("", onion))
        self.assertIn("is an Onion card", choice.note)
        self.assertIn("--platform onion", choice.note)
        state = self.start(platform="batocera", dest=str(onion))
        self.assertEqual(state.card_note, choice.note)

    def test_amberelec_and_emuelec_are_asked_for_their_card(self):
        """"Use this folder" on /storage/roms of a PC."""
        for plat, name in (("amberelec", "AmberELEC"), ("emuelec", "EmuELEC")):
            with self.subTest(system=name):
                setup = install.card_setup(plat, plat)
                self.assertEqual((setup.name, setup.below), (name, ""))
                state = self.start(platform=plat)
                self.assertEqual(state.screen, "folder")
                self.assertIsNone(state.folder_default)
                self.assertIn("Where is the SD card?",
                              " ".join(install.tui_view(state, 80, 24)))
                stick = self.blank(f"{name}STICK")
                choice = install.card_choice(plat, plat, stick)
                self.assertEqual(choice.folder, stick)
                # Its card is told by what it writes at every boot: a stick
                # holding none of it is one not started yet, never "cannot
                # tell".
                self.assertIn(f"says it is {install._a(name)} card yet", choice.note)
                self.assertNotIn("cannot tell", choice.note)

    def test_install_py_has_two_blank_lines_around_each_definition(self):
        """E305 after _card_mount, and the same slip
        before _Interrupted, TuiRow and _setup_label (pycodestyle E302,
        E303, E305 at top level)."""
        import ast

        lines = (REPO_ROOT / "install.py").read_text(encoding="utf-8").splitlines()
        body = ast.parse("\n".join(lines)).body

        def blank_before(node: ast.stmt) -> int:
            # The longest run of blank lines between the code above and the
            # statement, its decorators and comments in between, as
            # pycodestyle counts them.
            index = min([node.lineno] + [item.lineno for item in
                                         getattr(node, "decorator_list", [])]) - 2
            runs, run = [], 0
            while index >= 0 and (not lines[index].strip() or lines[index].startswith("#")):
                if lines[index].strip():
                    runs.append(run)
                    run = 0
                else:
                    run += 1
                index -= 1
            return max(runs + [run])

        definitions = (ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)
        for before, after in zip(body, body[1:]):
            count = blank_before(after)
            with self.subTest(line=after.lineno):
                if isinstance(after, definitions) or isinstance(before, definitions):
                    self.assertEqual(count, 2)

    def test_a_refusal_is_said_once_and_another_card_names_its_remedy(self):
        """Said twice, and "Choose the card's top folder"
        for the top folder of another card."""
        stick = self.blank()
        state = self.start(platform="onion")
        state.pad = "keys"
        install._card_status(state, install.card_choice("Onion", "retroarch", stick))
        after = install._status_after(state)
        self.assertEqual(len(after), 1)
        self.assertTrue(after[0].endswith("? says more."))
        state.help = True
        self.assertIn("Onion keeps .tmp_update",
                      " ".join(" ".join(install.tui_view(state, 80, 24)).split()))
        state.help = False
        muos = self.root / "MUOS"
        make_card(muos, "muOS")
        install._card_status(state, install.card_choice("Onion", "retroarch", muos))
        self.assertEqual(state.status, "That is a muOS card. Insert the Onion card, or go "
                         "back and choose muOS.")
        with mock.patch.object(install, "_ask", side_effect=[str(muos), str(stick),
                                                              KeyboardInterrupt]), \
                mock.patch.object(install, "_mounted_cards", return_value=[]), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                self.assertRaises(KeyboardInterrupt):
            install.card_install_dest("Onion", "retroarch", True)
        self.assertIn("Insert the Onion card, or choose muOS for that one.", out.getvalue())

    def test_line_mode_names_the_card_picked_and_its_folder(self):
        """No echo of the card picked, "Mount the
        card" under two mounted, /mnt/d where the list says D:."""
        cards = [self.root / "ONION", self.root / "ONION2"]
        for card in cards:
            make_card(card, "Onion")
        with mock.patch.object(install, "_ask", return_value="2"), \
                mock.patch.object(install, "_mounted_cards", return_value=cards), \
                mock.patch.object(install, "_missing_dest", return_value=True), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()):
            dest = install.card_install_dest("Onion", "retroarch", True)
        self.assertEqual(dest, cards[1] / "BIOS")
        text = out.getvalue()
        self.assertIn("Type its number or its top folder:", text)
        self.assertNotIn("Mount the card", text)
        self.assertIn(f"Onion card ONION2, BIOS folder {cards[1] / 'BIOS'}", text)
        self.assertEqual(install.detected_os("retroarch", dest), "Onion")
        with mock.patch.object(install, "_ask", return_value=""), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            install._prompt_custom_selection(install.MenuContext("retroarch", [], [], name="Onion",
                                                                 bios_path=dest))
        self.assertIn("Onion: 0 files", out.getvalue())
        self.assertIn(f"BIOS folder: {dest}", out.getvalue())
        proc = install_run("--platform", "onion", "--dest", str(cards[0]), "--dry-run",
                           "--manifest", str(REPO_ROOT / "install" / "retroarch.json"),
                           env={install.OFFLINE_VARIABLE: "1"})
        self.assertNotIn("gets the RetroArch file list", proc.stdout)

    def test_wsl_names_the_folder_by_its_drive_letter(self):
        with mock.patch.dict(install._WSL, {"active": True, "root": "/mnt"}):
            self.assertEqual(install._short_path(Path("/mnt/d/BIOS"), HOME), "D:\\BIOS")
            self.assertEqual(install.shown_path(Path("/mnt/d")), "D:\\")
            args = _args(dest=Path("D:\\"), save_dir=Path("F:\\saves"))
            setattr(args, "from", [Path("E:\\")])
            args.from_pack = [Path("E:\\pack.zip")]
            install._wsl_dest(args)
            self.assertEqual((args.dest, getattr(args, "from"), args.from_pack, args.save_dir),
                             (Path("/mnt/d"), [Path("/mnt/e")], [Path("/mnt/e/pack.zip")],
                              Path("/mnt/f/saves")))
        with mock.patch.dict(install._WSL, {"active": False}):
            self.assertEqual(install._short_path(Path("/mnt/d/BIOS"), HOME), "/mnt/d/BIOS")

    def test_a_multi_word_system_example_can_be_pasted(self):
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                contextlib.redirect_stderr(io.StringIO()) as err, \
                self.assertRaises(SystemExit):
            reported(install.card_install_dest, "Anbernic stock firmware", "retroarch", False)
        self.assertIn("--platform anbernicstockfirmware --dest", err.getvalue())


class DriveIsACardByItsFiles(unittest.TestCase):
    """A drive is a handheld's card only by
    the files its system writes, one settle from the frame shown, one
    vocabulary and one count per run, and the focus after an action."""

    setUp = LineModeRuns.setUp
    line_run = LineModeRuns.line_run
    listing = LineModeRuns.listing
    entry = staticmethod(LineModeRuns.entry)
    receive = staticmethod(ChoiceRuns.receive)
    game_manifest = ChoiceRuns.game_manifest
    game_events = ChoiceRuns.game_events
    game_plan = ChoiceRuns.game_plan
    game_listing = ChoiceScreens.game_listing
    screen = staticmethod(ChoiceScreens.screen)

    drive = DriveRuns.drive

    first_screen = DriveRuns.first_screen

    folder_screen = DriveRuns.folder_screen

    def test_a_data_drive_or_a_stick_is_no_card(self):
        """A data drive holding bios/, snes/ and Music/
        was "a card in the reader", and three presses of Enter put the list
        on it. A stick with bios/ alone is no card either: both are listed,
        never under Enter, and a plain line says why."""
        data = self.drive("DATA", ("bios", "snes", "Music"))
        stick = self.drive("STICK", ("bios",))
        mounts = [data, stick]
        with mock.patch.object(install, "_mounted_cards", return_value=mounts), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()):
            self.assertEqual(install.unproven_drives(), [data, stick])
        state = self.first_screen(mounts)
        self.assertEqual(state.setups, [])
        self.assertIn("Nothing was found here", self.screen(state))
        state, text, rows = self.folder_screen(mounts)
        self.assertNotIn(rows[0].value, (data / "bios", stick / "bios"))
        self.assertIn(self.UNPROVEN_TWO, text)
        self.assertIn(data / "bios", [row.value for row in rows])
        text, asked = self.line_run(_args(manifest=self.game_listing(), dry_run=True,
                                          declared_only=False), ["1", ""], mounts=mounts)
        self.assertNotIn("in the reader", text)
        self.assertIn(self.UNPROVEN_TWO, text)
        self.assertIn("Enter for the default above", asked[-2])
        self.assertNotIn(f"BIOS folder: {data / 'bios'}", text)

    # The note on drives with a bios folder and no handheld's folder.
    UNPROVEN_TWO = ("DATA and STICK have a bios folder but no folder a handheld system "
                    "writes. Pick one below if the BIOS files go there.")
    UNPROVEN_ONE = ("DATA has a bios folder but no folder a handheld system writes. Pick "
                    "it below if the BIOS files go there.")

    def test_the_layouts_handhelds_write_are_cards(self):
        """ArkOS's EASYROMS, AmberELEC's GAMES and EmuELEC's EEROMS, each
        with the folders its own image writes there. ArkOS's reads
        RetroArch's list, the two others are their systems' own cards."""
        arkos = games_part(self.root / "media" / "EASYROMS")
        amber = games_part(self.root / "media" / "GAMES")
        emuelec = self.drive("EEROMS", ("bios", "nes", "bezels"))
        (emuelec / "bezels" / "default.cfg").write_text("")
        mounts = [arkos, amber, emuelec]
        with mock.patch.object(install, "_mounted_cards", return_value=mounts), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()):
            self.assertEqual([install.games_part(mount).name for mount in mounts],
                             ["ArkOS", "AmberELEC", "EmuELEC"])
            # The three are their systems' own cards.
            self.assertEqual([install.card_system(mount) for mount in mounts],
                             [("retroarch", arkos / "bios", "ArkOS"),
                              ("amberelec", amber, "AmberELEC"),
                              ("emuelec", emuelec, "EmuELEC")])
            # One of these the system calls fixed is a disk, not a card.
            with mock.patch.object(install, "_drive_not_removable", return_value=True):
                self.assertEqual([install.card_system(mount) for mount in mounts],
                                 [None, None, None])

    def test_a_dest_on_a_games_part_reads_its_rom_folders(self):
        """--dest EASYROMS/bios --for-games from a computer: detection never
        ran on the card, the generic RetroArch folders were tried, and the
        run kept every file of the list."""
        arkos = games_part(self.root / "media" / "EASYROMS")
        index = {"setups": {"arkos": {}, "retroarch": {}}}
        with mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "_drive_not_removable", return_value=False):
            self.assertEqual(install.games_setups(index, "retroarch", arkos / "bios"), ["arkos"])
            self.assertEqual(install.games_setups(index, "retroarch", self.root / "bios"),
                             ["retroarch"])
            # Its games are offered without --for-games: EASYROMS keeps no
            # roms folder, its console folders sit beside bios.
            self.assertTrue(install._may_hold_games(arkos / "bios"))

    def test_a_card_beside_a_data_drive_comes_first(self):
        """The ArkOS card and the data drive mounted,
        the data drive sorted first and took Enter. The card comes first in
        both modes, the drive listed after it with its note."""
        data = self.drive("DATA", ("bios", "snes", "Music"))
        card = games_part(self.root / "media" / "EASYROMS")
        mounts = [data, card]
        state = self.first_screen(mounts)
        # The card is the setup found, under Enter.
        text = self.screen(state)
        self.assertIn("> dArkOS or ArkOS SD card (EASYROMS", text)
        with mock.patch.object(install, "_mounted_cards", return_value=mounts), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()):
            install.tui_update(state, Key("enter"))
        self.assertEqual(state.dest, card / "bios")
        text, asked = self.line_run(_args(manifest=self.game_listing(), dry_run=True,
                                          declared_only=False), [""], mounts=mounts)
        self.assertIn("Enter for dArkOS or ArkOS SD card (EASYROMS)", asked[0])
        self.assertIn(f"BIOS folder: {card / 'bios'}", text)

    def test_two_cards_are_spoken_of_in_the_plural(self):
        """"Cards are in the reader (DATA, EASYROMS):
        choose its system", then "The card in the reader" of one of two."""
        arkos = games_part(self.root / "media" / "EASYROMS")
        second = games_part(self.root / "media" / "ROMS2")
        mounts = [arkos, second]
        state = self.first_screen(mounts)
        # Each card its folders prove is a setup found, by its own name.
        text = self.screen(state)
        self.assertIn("ArkOS SD card (EASYROMS", text)
        self.assertIn("ArkOS SD card (ROMS2", text)
        text, asked = self.line_run(_args(manifest=self.game_listing(), dry_run=True,
                                          declared_only=False), [], mounts=mounts)
        self.assertIn("1) dArkOS or ArkOS SD card (EASYROMS", text)
        self.assertIn("2) dArkOS or ArkOS SD card (ROMS2", text)
        self.assertNotIn("in the reader", text)

    def test_a_fixed_partition_is_told_from_a_card(self):
        """Every mount under /media and /mnt, and on
        Windows every drive letter, was a card. A whole partition of a disk
        sysfs calls fixed is not, a USB or MMC one is, a folder bound in
        place says nothing, and Windows answers by GetDriveTypeW."""
        sys_root = self.root / "sys"
        devices = sys_root / "devices"
        for disk, part, removable in (("pci0/nvme0n1", "nvme0n1p2", "0"),
                                      ("pci0/usb2/2-1/sdb", "sdb1", "0"),
                                      ("mmc0/mmcblk0", "mmcblk0p1", "0"),
                                      ("pci0/sdc", "sdc1", "1")):
            (devices / disk / part).mkdir(parents=True)
            (devices / disk / part / "partition").write_text("1\n")
            (devices / disk / "removable").write_text(f"{removable}\n")
        block = sys_root / "dev" / "block"
        block.mkdir(parents=True)
        for number, target in (("259:2", "pci0/nvme0n1/nvme0n1p2"),
                               ("8:17", "pci0/usb2/2-1/sdb/sdb1"),
                               ("179:1", "mmc0/mmcblk0/mmcblk0p1"),
                               ("8:33", "pci0/sdc/sdc1")):
            (block / number).symlink_to(devices / target)
        mountinfo = "\n".join([
            "40 1 259:2 / /media/me/DATA rw - ext4 /dev/nvme0n1p2 rw",
            "41 1 8:17 / /media/me/EASYROMS rw - vfat /dev/sdb1 rw",
            "42 1 179:1 / /media/me/GAMES rw - exfat /dev/mmcblk0p1 rw",
            "43 1 8:33 / /media/me/STICK rw - vfat /dev/sdc1 rw",
            "44 1 259:2 /home/me/cards/X /media/me/BOUND rw - ext4 /dev/nvme0n1p2 rw",
            "45 1 0:74 / /mnt/d rw - 9p D:\\134 rw"])
        told = {name: install._fixed_partition(Path(point), mountinfo, sys_root)
                for name, point in (("DATA", "/media/me/DATA"), ("USB", "/media/me/EASYROMS"),
                                    ("MMC", "/media/me/GAMES"), ("STICK", "/media/me/STICK"),
                                    ("BOUND", "/media/me/BOUND"), ("WSL", "/mnt/d"),
                                    ("unmounted", "/media/me/NONE"))}
        self.assertEqual(told, {"DATA": True, "USB": False, "MMC": False, "STICK": False,
                                "BOUND": False, "WSL": False, "unmounted": False})
        for kind, fixed in ((2, False), (3, True), (4, True)):
            kernel = types.SimpleNamespace(GetDriveTypeW=lambda root, kind=kind: kind)
            fake = types.SimpleNamespace(windll=types.SimpleNamespace(kernel32=kernel))
            with mock.patch.object(install.os, "name", "nt"), \
                    mock.patch.dict(sys.modules, {"ctypes": fake}):
                self.assertEqual(install._drive_not_removable(PureWindowsPath("D:\\")), fixed)


if __name__ == "__main__":
    unittest.main()
