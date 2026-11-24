"""The handheld launchers' scripts, controller mappings, archives and the pages that describe them."""
from __future__ import annotations

import tests
from tests import scratch_dir

import hashlib
import json
import os
import re
import shutil
import subprocess
import unittest
import zipfile

import yaml

from installer_build import pins, port
from tests.handheldsupport import (
    REPO_ROOT,
    PORTS,
    install,
    read_gptk,
    sdl_vidpid,
    sdl_vidpid_list,
    assert_muxterm_hides_every_pad,
)


SCRIPTS = [
    PORTS / "shared" / "tui.txt",
    PORTS / "RetroBIOS" / "RetroBIOS.sh",
    PORTS / "RetroBIOS" / "retrobios" / "screens.txt",
    PORTS / "batocera" / "RetroBIOS.sh",
    PORTS / "muos" / "mux_launch.sh",
    PORTS / "tools" / "RetroBIOS.sh",
]


# What each button does in the interface (wiki/installer.md, the full-screen
# interface): the convergent menu mapping of handheld_runtime.md.
ROLES = {
    "a": "enter", "start": "enter", "b": "esc", "back": "esc", "x": "space",
    "y": "tab", "l1": "pageup", "r1": "pagedown",
    "up": "up", "down": "down", "left": "left", "right": "right",
}


# What a Linux console or a terminal sends for each key gptokeyb and evmapy
# emit, and the key the interface reads from it.
SEQUENCES = {
    "enter": "\r", "esc": "\x1b", "space": " ", "tab": "\t",
    "pageup": "\x1b[5~", "pagedown": "\x1b[6~",
    "up": "\x1b[A", "down": "\x1b[B", "left": "\x1b[D", "right": "\x1b[C",
}


INTERFACE_KEYS = {
    "enter": "enter", "esc": "esc", "space": "char", "tab": "tab",
    "pageup": "pgup", "pagedown": "pgdn",
    "up": "up", "down": "down", "left": "left", "right": "right",
}


# gptokeyb's char_to_keycode (PortsMaster/gptokeyb src/util.cpp) names.
GPTOKEYB_NAMES = set(SEQUENCES) | {"backspace", '\\"'}


class EveryScriptParses(unittest.TestCase):
    def test_bash_n(self):
        for script in SCRIPTS:
            with self.subTest(script=str(script.relative_to(REPO_ROOT))):
                proc = subprocess.run(["bash", "-n", str(script)], capture_output=True,
                                      text=True, check=False)
                self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_shellcheck(self):
        """CI provides shellcheck (validate.yml checks it), so there it may
        not skip."""
        if shutil.which("shellcheck") is None:
            if os.environ.get("CI"):
                self.fail("CI must provide shellcheck for the handheld launchers")
            self.skipTest("shellcheck is not installed")
        proc = subprocess.run(
            ["shellcheck", "--shell=bash", "--severity=style", "--external-sources",
             "--source-path=SCRIPTDIR", *map(str, SCRIPTS)],
            capture_output=True, text=True, check=False)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_launchers_are_executable(self):
        for script in (PORTS / "RetroBIOS" / "RetroBIOS.sh", PORTS / "batocera" / "RetroBIOS.sh",
                       PORTS / "muos" / "mux_launch.sh", PORTS / "tools" / "RetroBIOS.sh"):
            with self.subTest(script=str(script.relative_to(REPO_ROOT))):
                self.assertTrue(script.stat().st_mode & 0o111)
                self.assertTrue(script.read_text().startswith("#!/bin/bash\n"))

    def test_muos_headers(self):
        """muOS's frontend reads the HELP, ICON and GRID lines of an app
        (MustardOS internal share/application/*/mux_launch.sh)."""
        head = (PORTS / "muos" / "mux_launch.sh").read_text().splitlines()[1:4]
        self.assertEqual([line.split(":")[0] for line in head], ["# HELP", "# ICON", "# GRID"])
        self.assertTrue(all(line.split(":", 1)[1].strip() for line in head))


class ControllerMappings(unittest.TestCase):
    def _decodes(self, key: str) -> str:
        decoder = install.KeyDecoder()
        keys = decoder.feed(SEQUENCES[key]) + decoder.flush()
        self.assertEqual(len(keys), 1, key)
        return keys[0].name

    def test_gptk_maps_every_button_the_interface_reads(self):
        mapping = read_gptk(PORTS / "shared" / "retrobios.gptk")
        for button, key in ROLES.items():
            with self.subTest(button=button):
                self.assertEqual(mapping[button][0], key)
                self.assertEqual(self._decodes(key), INTERFACE_KEYS[key])
        for values in mapping.values():
            self.assertIn(values[0], GPTOKEYB_NAMES | {"repeat"})
            self.assertTrue(set(values[1:]) <= {"repeat"})
        self.assertEqual(mapping["up"], ["up", "repeat"])
        self.assertEqual(mapping["down"], ["down", "repeat"])
        self.assertEqual(mapping["guide"], ['\\"'])

    def test_evmapy_keys_map_the_same_buttons(self):
        """Batocera's evmapy names L1 and R1 pageup and pagedown, and Select
        select (batocera-pygame evmapy.keys)."""
        data = json.loads((PORTS / "batocera" / "RetroBIOS.sh.keys").read_text())
        actions = {a["trigger"]: a for a in data["actions_player1"]}
        triggers = {"a": "a", "start": "start", "b": "b", "back": "select", "x": "x",
                    "y": "y", "l1": "pageup", "r1": "pagedown", "up": "up",
                    "down": "down", "left": "left", "right": "right"}
        for button, trigger in triggers.items():
            with self.subTest(button=button):
                action = actions[trigger]
                self.assertEqual(action["type"], "key")
                self.assertEqual(action["target"], [f"KEY_{ROLES[button].upper()}"])
        for stick in ("up", "down", "left", "right"):
            self.assertEqual(actions[f"joystick1{stick}"]["target"], [f"KEY_{stick.upper()}"])
        self.assertEqual(len(actions), len(data["actions_player1"]))

    def test_x_ticks_and_y_opens_the_options_on_every_route(self):
        """The interface reads Space as Tick and Tab as Options: a mapping
        that sends Y as Space activates the focused row instead."""
        self.assertEqual(self._decodes("space"), "char")
        self.assertEqual(self._decodes("tab"), "tab")
        gptk = read_gptk(PORTS / "shared" / "retrobios.gptk")
        self.assertEqual((gptk["x"], gptk["y"]), (["space"], ["tab"]))
        keys = json.loads((PORTS / "batocera" / "RetroBIOS.sh.keys").read_text())
        targets = {a["trigger"]: a["target"] for a in keys["actions_player1"]}
        self.assertEqual((targets["x"], targets["y"]), (["KEY_SPACE"], ["KEY_TAB"]))
        # muxterm sends Y as Space on its own (MustardOS/terminal input.c):
        # where gptokeyb runs beside it, muxterm is told to leave the pad
        # (assert_muxterm_hides_every_pad).
        for launcher in (PORTS / "muos" / "mux_launch.sh", PORTS / "RetroBIOS" / "RetroBIOS.sh"):
            self.assertIn("rb_muxterm ", launcher.read_text())
        self.assertFalse((PORTS / "muos" / "muxterm.gptk").exists())


class TheSdlModel(unittest.TestCase):
    def test_it_reads_the_ids_as_sdl_does(self):
        self.assertEqual(sdl_vidpid(0x19, 1, 1, 0x100, "Deeplay-keys"), (1, 1))
        self.assertEqual(sdl_vidpid(0x05, 0, 0x2009, 1, "pad"), (0, 0))
        self.assertEqual(sdl_vidpid(0x05, 0, 0x2009, 1, "ab"), (0x6261, 0))
        self.assertEqual(sdl_vidpid_list("0x0001/0x0001, 0x045e/0x028e"),
                         [0x00010001, 0x045e028e])

    def test_the_first_hint_allowed_the_h700_pad(self):
        with self.assertRaises(AssertionError):
            assert_muxterm_hides_every_pad(unittest.TestCase(), "0x0001/0x0001")


class TheArchives(unittest.TestCase):
    LAYOUT = {
        port.PORT_ZIP: ("RetroBIOS.sh", "retrobios"),
        port.BATOCERA_ZIP: ("RetroBIOS.sh", "retrobios"),
        port.MUOS_APP: (None, "RetroBIOS"),
        port.TOOLS_ZIP: ("RetroBIOS.sh", "retrobios"),
    }

    def setUp(self):
        self.out = scratch_dir(self)

    def test_every_release_archive_is_built(self):
        self.assertEqual(set(port.ARCHIVES), set(self.LAYOUT))

    def test_layout(self):
        for name, (script, folder) in self.LAYOUT.items():
            with self.subTest(archive=name):
                with zipfile.ZipFile(port.build_archive(name, self.out / name)) as zf:
                    names = zf.namelist()
                    modes = {n: zf.getinfo(n).external_attr >> 16 for n in names}
                self.assertEqual(names, sorted(names))
                top = [n for n in names if "/" not in n]
                self.assertEqual({n.split("/")[0] for n in names if "/" in n}, {folder})
                for member in ("install.py", "tui.txt", "rbevents.py",
                               "licenses/LICENSE-retrobios.txt"):
                    self.assertIn(f"{folder}/{member}", names)
                launcher = script or f"{folder}/mux_launch.sh"
                self.assertTrue(modes[launcher] & 0o111, launcher)
                if name == port.BATOCERA_ZIP:
                    self.assertEqual(top, ["RetroBIOS.sh", "RetroBIOS.sh.keys"])
                    self.assertNotIn("retrobios/retrobios.gptk", names)
                elif script:
                    self.assertEqual(top, [script])
                    self.assertIn(f"{folder}/retrobios.gptk", names)
                else:
                    self.assertEqual(top, [])
                    self.assertIn("RetroBIOS/retrobios.gptk", names)

    def test_the_port_describes_itself_to_portmaster(self):
        """port.json and the files harbourmaster's captain.check_port and the
        PortMaster listing read, beside the launch script."""
        name = port.PORT_ZIP
        with zipfile.ZipFile(port.build_archive(name, self.out / name)) as zf:
            names = zf.namelist()
            described = json.loads(zf.read("retrobios/port.json"))
        for member in ("retrobios/screens.txt", "retrobios/gameinfo.xml", "retrobios/retrobios.md"):
            self.assertIn(member, names)
        self.assertEqual(described["version"], 4)
        self.assertEqual(described["name"], "retrobios.zip")
        self.assertEqual(described["items"], ["RetroBIOS.sh", "retrobios"])
        self.assertEqual(described["attr"]["genres"], ["other"])

    def test_the_muos_icon_is_the_glyph_its_header_names(self):
        """muOS reads glyph/<ICON>.png in the application's folder, and the
        muxapp named an icon it did not carry."""
        header = (REPO_ROOT / "ports" / "muos" / "mux_launch.sh").read_text()
        icon = re.search(r"^# ICON: (\S+)$", header, re.MULTILINE).group(1)
        name = port.MUOS_APP
        with zipfile.ZipFile(port.build_archive(name, self.out / name)) as zf:
            data = zf.read(f"RetroBIOS/glyph/{icon}.png")
        self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")

    def test_no_tools_support_file_is_a_menu_entry(self):
        """EmulationStation lists a folder only when it holds a file of the
        system's extension (.sh for Tools and Ports): batocera-emulationstation
        and EmulationStation-fcamod SystemData.cpp drop a folder with none.
        The support folders must keep none, or each shows up in the menu."""
        for name in (port.TOOLS_ZIP, port.PORT_ZIP, port.BATOCERA_ZIP):
            with self.subTest(archive=name):
                with zipfile.ZipFile(port.build_archive(name, self.out / name)) as zf:
                    inside = [n for n in zf.namelist()
                              if "/" in n and n.lower().endswith(".sh")]
                self.assertEqual(inside, [])

    def test_each_carries_the_pinned_installer(self):
        pinned = pins.pinned_sha256("install.sh")
        for name, (_script, folder) in self.LAYOUT.items():
            with self.subTest(archive=name):
                with zipfile.ZipFile(port.build_archive(name, self.out / name)) as zf:
                    bundled = hashlib.sha256(zf.read(f"{folder}/install.py")).hexdigest()
                self.assertEqual(bundled, pinned)

    def test_reproducible(self):
        for name in port.ARCHIVES:
            with self.subTest(archive=name):
                first = port.build_archive(name, self.out / f"a-{name}").read_bytes()
                second = port.build_archive(name, self.out / f"b-{name}").read_bytes()
                self.assertEqual(first, second)

    def test_each_names_the_release_packs(self):
        """packs.txt names the platforms a release publishes a pack for, as
        the registry marks them, and the pack's name for each."""
        registry = yaml.safe_load((REPO_ROOT / "platforms" / "_registry.yml").read_text())
        released = {name for name, entry in registry["platforms"].items()
                    if entry.get("release_pack") is True}
        labels = port.release_pack_labels()
        self.assertEqual(set(labels), released)
        self.assertEqual(labels["retroarch"], "RetroArch")
        expected = "".join(f"{p}\t{label}\n" for p, label in sorted(labels.items()))
        for name, (_script, folder) in self.LAYOUT.items():
            with self.subTest(archive=name), \
                    zipfile.ZipFile(port.build_archive(name, self.out / name)) as zf:
                self.assertEqual(zf.read(f"{folder}/packs.txt").decode(), expected)

    def test_an_unpinned_installer_is_refused(self):
        root = scratch_dir(self)
        for name in ("install.py", "install.sh", "LICENSE", "NOTICE"):
            shutil.copy(REPO_ROOT / name, root / name)
        shutil.copytree(PORTS, root / "ports")
        with (root / "install.py").open("a") as fh:
            fh.write("\n")
        for name in port.ARCHIVES:
            with self.subTest(archive=name), self.assertRaises(ValueError):
                port.build_archive(name, self.out / name, root)

    def test_the_site_serves_each_and_the_release_none(self):
        """Each archive carries install.py: the site serves it from its own
        commit (sitegen/handheld.py), and the release steps never build one."""
        text = (REPO_ROOT / "wiki" / "release-process.md").read_text(encoding="utf-8")
        self.assertNotIn("scripts/build_port.py", text)
        installer = (REPO_ROOT / "wiki" / "installer.md").read_text(encoding="utf-8")
        for name in port.ARCHIVES:
            with self.subTest(archive=name):
                self.assertNotIn(name, text)
                self.assertIn(f"](../get/handheld/{name})", installer)


class TheDocs(unittest.TestCase):
    def test_the_offline_packs_named_are_the_ones_that_serve(self):
        """The wiki names the pack each firmware takes offline: the release
        pack of the platform install.py detects it as, or none."""
        labels = port.release_pack_labels()
        served = {}
        for rule in install._EMBEDDED_RULES:
            served.setdefault(rule.name, labels.get(rule.manifest))
        for name in ("muOS", "ArkOS", "dArkOS", "JELOS"):
            self.assertEqual(served[name], "RetroArch", name)
        self.assertEqual(served["Batocera"], "Batocera")
        for name in ("ROCKNIX", "KNULLI", "AmberELEC"):
            self.assertIsNone(served[name], name)
        text = (REPO_ROOT / "wiki" / "installer.md").read_text(encoding="utf-8")
        self.assertIn("The releases carry no pack for ROCKNIX,\nKnulli or AmberELEC", text)

    def test_every_pad_value_is_documented(self):
        """RETROBIOS_PAD is a contract the interface reads: each value tui.txt
        names has its row in the handheld section."""
        text = (REPO_ROOT / "wiki" / "installer.md").read_text(encoding="utf-8")
        tui = (PORTS / "shared" / "tui.txt").read_text()
        for value in ("gptokeyb", "muxterm", "evmapy", "miyoo"):
            self.assertIn(f"| `{value}` |", text)
            self.assertIn(value, tui)

    def handheld(self) -> str:
        text = (REPO_ROOT / "wiki" / "installer.md").read_text(encoding="utf-8")
        start = text.index("## On a handheld")
        end = text.find("\n## ", start + 1)
        return text[start:end if end != -1 else len(text)]

    def test_the_idle_limit_is_documented(self):
        """Every launcher sets RETROBIOS_IDLE_EXIT for the interface: a
        mapper that runs but never opens the pad leaves no button to quit."""
        self.assertIn("`RETROBIOS_IDLE_EXIT`", self.handheld())
        self.assertIn("RETROBIOS_IDLE_EXIT", (PORTS / "shared" / "tui.txt").read_text())

    def test_no_page_buttons_are_promised_in_muxterm(self):
        """muxterm keeps PgUp and PgDn for its scrollback (T/input.c:352-360)."""
        readme = " ".join((PORTS / "muos" / "README.md").read_text().split())
        self.assertNotIn("L1 and R1 to page", readme)
        self.assertIn("L1 and R1 do nothing in muxterm", readme)
        rows = [line for line in self.handheld().splitlines() if line.startswith("| L1, R1 |")]
        self.assertEqual(len(rows), 1)
        self.assertIn("not in muxterm", rows[0])

    def test_muos_paths_are_the_card_muos_mounts(self):
        """muOS mounts the first card at /mnt/mmc (MustardOS internal
        mux_launch.sh, GET_VAR storage/rom/mount)."""
        text = (REPO_ROOT / "wiki" / "installer.md").read_text(encoding="utf-8")
        start = text.index("## On a handheld")
        end = text.find("\n## ", start + 1)
        section = text[start:end if end != -1 else len(text)]
        self.assertNotIn("/mmc/MUOS", section.replace("/mnt/mmc", ""))
        self.assertIn("`MUOS/PortMaster/autoinstall/`", section)


if __name__ == "__main__":
    unittest.main()
