"""The handheld launchers: their scripts, controller mappings and archives,
and what each one does on a simulated device.

A device is simulated with a pseudo-terminal standing for its console, a
fake install.py that records how it was started, and fakes for what the
firmware provides (gptokeyb, setfont, chvt, curl, foot, xterm, muxterm,
PortMaster's control.txt and muOS's retro.sh), all on PATH or in a folder
the launcher reads. What only a device shows (the text reaching the screen,
the pad reaching the console, a compositor covering it) is not exercised.
"""
from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import hashlib
import importlib.util
import json
import os
import pty
import re
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time
import unittest
import zipfile
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
PORTS = REPO_ROOT / "ports"
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import build_port  # noqa: E402

_spec = importlib.util.spec_from_file_location("install", REPO_ROOT / "install.py")
install = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(install)

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


def _tempdir(test: unittest.TestCase) -> Path:
    scratch = REPO_ROOT / "tmp"
    scratch.mkdir(exist_ok=True)
    path = Path(tempfile.mkdtemp(dir=str(scratch)))
    test.addCleanup(shutil.rmtree, path, True)
    return path


def read_gptk(path: Path) -> dict[str, list[str]]:
    """key -> values, as gptokeyb's parseConfigFile reads `key = value`."""
    mapping: dict[str, list[str]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("["):
            continue
        key, sep, value = line.partition(" = ")
        assert sep, line
        mapping.setdefault(key, []).append(value.split("#")[0].strip())
    return mapping


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


def sdl_vidpid(bus: int, vendor: int, product: int, version: int, name: str) -> tuple[int, int]:
    """The vendor and product SDL 2 reads back from the GUID it builds for
    a device: SDL_CreateJoystickGUID, then SDL_GetJoystickGUIDInfo
    (libsdl-org/SDL release-2.30.x src/joystick/SDL_joystick.c). A vendor of
    0 makes the GUID carry the name instead of the ids."""
    data = bytearray(16)
    struct.pack_into("<HH", data, 0, bus, 0x5a5a)
    if vendor:
        struct.pack_into("<HHHHH", data, 4, vendor, 0, product, 0, version)
    else:
        raw = name.encode()[:11]
        data[4:4 + len(raw)] = raw
    words = struct.unpack("<8H", bytes(data))
    if (words[0] < 0x20 or words[0] == 0xFF) and words[3] == 0 and words[5] == 0:
        return words[2], words[4]
    return 0, 0


def sdl_vidpid_list(hint: str) -> list[int]:
    """SDL_LoadVIDPIDListFromHint: every pair of 0x numbers."""
    entries = []
    for vendor, product in re.findall(r"0x([0-9a-fA-F]+)[^x]*?0x([0-9a-fA-F]+)", hint):
        entries.append((int(vendor, 16) & 0xFFFF) << 16 | (int(product, 16) & 0xFFFF))
    return entries


# Input devices a muOS device lists in /proc/bus/input/devices: the H700
# pad before 2026-08-28 (gpio-keys, 0001:0001, MustardOS internal
# f6a14e3121 device/rg35xx-plus/control/gamecontrollerdb/modern.txt), the
# muinput pad after it (0x756d), a USB and a Bluetooth pad, gptokeyb2's
# uinput keyboard, and pads whose vendor is 0.
PADS = [
    (0x19, 0x0001, 0x0001, 0x0100, "Deeplay-keys"),
    (0x19, 0x0001, 0x0001, 0x0100, "muOS-Keys"),
    (0x06, 0x756d, 0x6b6d, 0x0001, "muOS-Keys"),
    (0x03, 0x045e, 0x028e, 0x0114, "Microsoft X-Box 360 pad"),
    (0x05, 0x057e, 0x2009, 0x8111, "Pro Controller"),
    (0x06, 0x0000, 0x0000, 0x0000, "Fake Keyboard"),
]
PADS += [(bus, 0, product, 1, "pad"[:length] + "x" * max(0, length - 3))
         for bus in (0x03, 0x05, 0x06, 0x19, 0xFF) for product in (0, 1, 0x2009)
         for length in range(13)]
PADS += [(bus, vendor, product, 1, "pad")
         for bus in (0x03, 0x05, 0x19) for vendor in (1, 0x0079, 0xFFFF)
         for product in (0, 1, 0xFFFF)]


def assert_muxterm_hides_every_pad(test: unittest.TestCase, hint: str) -> None:
    """muxterm reads the pad itself (T/input.c:303-317) while gptokeyb2
    sends its keys, so every button would act twice. The launchers set
    SDL_GAMECONTROLLER_IGNORE_DEVICES_EXCEPT, which hides from SDL every
    device it does not name (SDL_gamecontroller.c:2145-2150, applied to the
    joystick layer by SDL_ShouldIgnoreJoystick, SDL_joystick.c:3006)."""
    allowed = sdl_vidpid_list(hint)
    # An empty list allows every device.
    test.assertTrue(allowed, hint)
    for pad in PADS:
        vendor, product = sdl_vidpid(*pad)
        with test.subTest(pad=pad):
            test.assertNotIn(vendor << 16 | product, allowed)


def assert_muxterm_mapping(test: unittest.TestCase, args: list[str], shared: Path) -> None:
    """muxterm keeps PgUp and PgDn for its scrollback and never writes them
    to the terminal (T/input.c:352-360): in muxterm, L1 and R1 send nothing,
    so they cannot scroll the interface away. Every other button is
    retrobios.gptk's."""
    test.assertEqual(args[-2], "-c")
    mapping = read_gptk(Path(args[-1]))
    expected = read_gptk(shared)
    expected["l1"] = expected["r1"] = ['\\"']
    test.assertEqual(mapping, expected)


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
        build_port.PORT_ZIP: ("RetroBIOS.sh", "retrobios"),
        build_port.BATOCERA_ZIP: ("RetroBIOS.sh", "retrobios"),
        build_port.MUOS_APP: (None, "RetroBIOS"),
        build_port.TOOLS_ZIP: ("RetroBIOS.sh", "retrobios"),
    }

    def setUp(self):
        self.out = _tempdir(self)

    def test_every_release_archive_is_built(self):
        self.assertEqual(set(build_port.ARCHIVES), set(self.LAYOUT))

    def test_layout(self):
        for name, (script, folder) in self.LAYOUT.items():
            with self.subTest(archive=name):
                with zipfile.ZipFile(build_port.build_archive(name, self.out / name)) as zf:
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
                if name == build_port.BATOCERA_ZIP:
                    self.assertEqual(top, ["RetroBIOS.sh", "RetroBIOS.sh.keys"])
                    self.assertNotIn("retrobios/retrobios.gptk", names)
                elif script:
                    self.assertEqual(top, [script])
                    self.assertIn(f"{folder}/retrobios.gptk", names)
                else:
                    self.assertEqual(top, [])
                    self.assertIn("RetroBIOS/retrobios.gptk", names)

    def test_the_muos_icon_is_the_glyph_its_header_names(self):
        """muOS reads glyph/<ICON>.png in the application's folder, and the
        muxapp named an icon it did not carry."""
        header = (REPO_ROOT / "ports" / "muos" / "mux_launch.sh").read_text()
        icon = re.search(r"^# ICON: (\S+)$", header, re.MULTILINE).group(1)
        name = build_port.MUOS_APP
        with zipfile.ZipFile(build_port.build_archive(name, self.out / name)) as zf:
            data = zf.read(f"RetroBIOS/glyph/{icon}.png")
        self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")

    def test_no_tools_support_file_is_a_menu_entry(self):
        """EmulationStation lists a folder only when it holds a file of the
        system's extension (.sh for Tools and Ports): batocera-emulationstation
        and EmulationStation-fcamod SystemData.cpp drop a folder with none.
        The support folders must keep none, or each shows up in the menu."""
        for name in (build_port.TOOLS_ZIP, build_port.PORT_ZIP, build_port.BATOCERA_ZIP):
            with self.subTest(archive=name):
                with zipfile.ZipFile(build_port.build_archive(name, self.out / name)) as zf:
                    inside = [n for n in zf.namelist()
                              if "/" in n and n.lower().endswith(".sh")]
                self.assertEqual(inside, [])

    def test_each_carries_the_pinned_installer(self):
        pinned = build_port.pinned_installer_sha256()
        for name, (_script, folder) in self.LAYOUT.items():
            with self.subTest(archive=name):
                with zipfile.ZipFile(build_port.build_archive(name, self.out / name)) as zf:
                    bundled = hashlib.sha256(zf.read(f"{folder}/install.py")).hexdigest()
                self.assertEqual(bundled, pinned)

    def test_reproducible(self):
        for name in build_port.ARCHIVES:
            with self.subTest(archive=name):
                first = build_port.build_archive(name, self.out / f"a-{name}").read_bytes()
                second = build_port.build_archive(name, self.out / f"b-{name}").read_bytes()
                self.assertEqual(first, second)

    def test_each_names_the_release_packs(self):
        """packs.txt names the platforms a release publishes a pack for, as
        the registry marks them, and the pack's name for each."""
        registry = yaml.safe_load((REPO_ROOT / "platforms" / "_registry.yml").read_text())
        released = {name for name, entry in registry["platforms"].items()
                    if entry.get("release_pack") is True}
        labels = build_port.release_pack_labels()
        self.assertEqual(set(labels), released)
        self.assertEqual(labels["retroarch"], "RetroArch")
        expected = "".join(f"{p}\t{label}\n" for p, label in sorted(labels.items()))
        for name, (_script, folder) in self.LAYOUT.items():
            with self.subTest(archive=name):
                with zipfile.ZipFile(build_port.build_archive(name, self.out / name)) as zf:
                    self.assertEqual(zf.read(f"{folder}/packs.txt").decode(), expected)

    def test_an_unpinned_installer_is_refused(self):
        root = _tempdir(self)
        for name in ("install.py", "install.sh", "LICENSE", "NOTICE"):
            shutil.copy(REPO_ROOT / name, root / name)
        shutil.copytree(PORTS, root / "ports")
        with (root / "install.py").open("a") as fh:
            fh.write("\n")
        for name in build_port.ARCHIVES:
            with self.subTest(archive=name), self.assertRaises(ValueError):
                build_port.build_archive(name, self.out / name, root)

    def test_the_site_serves_each_and_the_release_none(self):
        """Each archive carries install.py: the site serves it from its own
        commit (sitehandheld.py), and the release steps never build one."""
        text = (REPO_ROOT / "wiki" / "release-process.md").read_text(encoding="utf-8")
        self.assertNotIn("scripts/build_port.py", text)
        installer = (REPO_ROOT / "wiki" / "installer.md").read_text(encoding="utf-8")
        for name in build_port.ARCHIVES:
            with self.subTest(archive=name):
                self.assertNotIn(name, text)
                self.assertIn(f"](../get/handheld/{name})", installer)


FAKE_INSTALL = r'''
import json, os, signal, subprocess, sys, time
calls = os.environ["FAKE_CALLS"]
state = os.environ["FAKE_STATE"]


def tty(fd):
    try:
        return os.ttyname(fd)
    except OSError:
        return ""


def note(name, text=""):
    with open(os.path.join(state, name), "a") as fh:
        fh.write(text + "\n")


if "--engine" in sys.argv:
    # The engine the interface starts in its own session: it writes its
    # summary on SIGINT, as install.py does, and records any other signal.
    def summary(signum, _frame):
        note("engine.log", "summary after SIGINT")
        sys.exit(130)

    def other(signum, _frame):
        note("engine.log", f"signal {signum}")
        sys.exit(128 + signum)

    signal.signal(signal.SIGINT, summary)
    signal.signal(signal.SIGTERM, other)
    with open(os.path.join(state, "engine.pid"), "w") as fh:
        fh.write(str(os.getpid()))
    note("engine.ready")
    time.sleep(60)
    sys.exit(0)

with open(calls, "a") as fh:
    fh.write(json.dumps({"argv0": sys.argv[0], "args": sys.argv[1:], "stdin": tty(0),
                         "stdout": tty(1), "term": os.environ.get("TERM", ""),
                         "pythonhome": os.environ.get("PYTHONHOME", ""),
                         "base_url": os.environ.get("RETROBIOS_BASE_URL", ""),
                         "offline": os.environ.get("RETROBIOS_INSTALL_OFFLINE", ""),
                         "idle_exit": os.environ.get("RETROBIOS_IDLE_EXIT"),
                         "pad": os.environ.get("RETROBIOS_PAD")}) + "\n")
if "--check" in sys.argv:
    # install.py --check --events: detection is local, then the file list.
    # With RETROBIOS_INSTALL_OFFLINE the file list stops the run at once
    # with reason offline. Otherwise it is downloaded: a closed loopback
    # port refuses at once, any other address is three tries of 30 s on a
    # device without a network (FAKE_CURL, the probe that found it so).
    offline = os.environ.get("RETROBIOS_INSTALL_OFFLINE", "") not in ("", "0")
    base_url = os.environ.get("RETROBIOS_BASE_URL", "")
    no_network = os.environ.get("FAKE_CURL", "0") in ("5", "6", "7", "28")
    if os.environ.get("FAKE_DETECT_HANG"):
        time.sleep(60)
    print(json.dumps({"event": "start", "mode": "check"}), flush=True)
    print(json.dumps({"event": "detect", "os": "linux", "os_name": "Fake OS",
                      "platforms": [{"platform": os.environ.get("FAKE_PLATFORM", "retroarch"),
                                     "name": os.environ.get("FAKE_PLATFORM_NAME", "RetroArch"),
                                     "bios_dir": "/roms/bios"}]}), flush=True)
    if no_network and not offline and not base_url.startswith("http://127.0.0.1"):
        time.sleep(90)
    print(json.dumps({"event": "error", "stage": "manifest",
                      "reason": "offline" if offline else "network",
                      "platform": os.environ.get("FAKE_PLATFORM", "retroarch"),
                      "message": "this run makes no network request (--offline)" if offline
                      else "unreachable"}))
    print(json.dumps({"event": "end", "code": 1}))
    sys.exit(1)
if os.environ.get("FAKE_REFUSE"):
    print("install.py: error: --tui cannot open the full-screen interface here: "
          "the terminal is 30x10, smaller than 40x12", file=sys.stderr)
    sys.exit(2)
if os.environ.get("FAKE_RAW") and os.isatty(0):
    import tty as _tty
    _tty.setraw(0)
if os.environ.get("FAKE_DRAIN") and os.isatty(0):
    # What the console still holds when the interface starts: bytes a
    # question left behind are read as the interface's first keys.
    # TCSANOW, as install.py sets its mode: TCSAFLUSH would discard them.
    import select as _select
    import termios as _termios
    import tty as _tty
    _tty.setraw(0, _termios.TCSANOW)
    left = b""
    while _select.select([0], [], [], 0.3)[0]:
        chunk = os.read(0, 64)
        if not chunk:
            break
        left += chunk
    note("ui.input", left.hex())
if os.environ.get("FAKE_HOLD"):
    # The interface up and waiting for a key until a signal ends it. With
    # FAKE_ENGINE an install runs, and SIGTERM gives it 2 s to say what it
    # wrote, as install.py's run_tui does. FAKE_NO_HANDLER is a signal that
    # comes before run_tui installs its handlers.
    engine = None
    if os.environ.get("FAKE_ENGINE"):
        engine = subprocess.Popen([sys.executable, sys.argv[0], "--events", "--engine"],
                                  start_new_session=True)
        while not os.path.exists(os.path.join(state, "engine.ready")):
            time.sleep(0.05)

    def stop(signum, _frame):
        note("ui.log", f"signal {signum}")
        if engine is not None:
            engine.send_signal(signal.SIGINT)
            try:
                engine.wait(2)
            except subprocess.TimeoutExpired:
                engine.kill()
            print("RetroBIOS: the install was stopped, 2 files written.")
        if os.environ.get("FAKE_TERM_ERROR"):
            print("Error: " + os.environ["FAKE_TERM_ERROR"], file=sys.stderr)
        sys.exit(128 + signum)

    if os.environ.get("FAKE_IGNORE_TERM"):
        # An interface stuck where its signal handler never runs.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    elif not os.environ.get("FAKE_NO_HANDLER"):
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGHUP, stop)
    with open(os.path.join(state, "ui.pid"), "w") as fh:
        fh.write(str(os.getpid()))
    note("ui.ready")
    time.sleep(60)
    sys.exit(0)
if os.environ.get("FAKE_IDLE_ERROR"):
    # RETROBIOS_IDLE_EXIT on an error screen: the idle line, then the error.
    print("RetroBIOS: No button pressed, closing.", file=sys.stderr)
    print("Error: " + os.environ["FAKE_IDLE_ERROR"], file=sys.stderr)
if os.environ.get("FAKE_QUIT"):
    # q or Quit on the screen: the farewell on stderr, code 2.
    print("RetroBIOS: quit. Nothing was installed.", file=sys.stderr)
if os.environ.get("FAKE_ERROR"):
    print("Error: " + os.environ["FAKE_ERROR"], file=sys.stderr)
sys.exit(int(os.environ.get("FAKE_CODE", "0")))
'''

# The real pgrep and pkill: Device puts a pgrep on PATH that answers for the
# compositor check.
PGREP = shutil.which("pgrep", path="/usr/bin:/bin") or "pgrep"
PKILL = shutil.which("pkill", path="/usr/bin:/bin") or "pkill"

# gptokeyb as PortsMaster/gptokeyb runs it: kill mode takes the argument
# after the flag (`-1`, `-k` or `-sudokill`) as its target. Start + Select
# (FAKE_PRESS, once FAKE_PRESS_AT exists, by default once the interface is
# up) is doKillMode in src/util.cpp: pkill -f on the target, which also
# matches gptokeyb's own command line (SDL turns that SIGTERM into an event
# it does not read there), 3 s, then pkill -9 -f and exit. `-sudokill` runs
# both through sudo. Stopped otherwise by a SIGTERM, which it records.
# FAKE_MAPPER_DIES is a mapper that cannot start (no /dev/uinput).
FAKE_MAPPER = f'''#!/bin/bash
printf '%s\\n' "$@" > "$FAKE_STATE/mapper.args"
echo $$ > "$FAKE_STATE/mapper.pid"
printf '%s\\n' "${{SDL_GAMECONTROLLERCONFIG_FILE:-}}" > "$FAKE_STATE/mapper.db"
if [ -n "${{FAKE_MAPPER_DIES:-}}" ]; then
  echo "gptokeyb: cannot open /dev/uinput" >&2
  exit 1
fi
name="" sudo=""
while [ $# -gt 0 ]; do
  case "$1" in
    -1|-k) name="$2"; shift 2 ;;
    -sudokill) name="$2" sudo="sudo"; shift 2 ;;
    -c) shift 2 ;;
    *) shift ;;
  esac
done
killing=""
trap '[ -n "$killing" ] || {{ echo stopped > "$FAKE_STATE/mapper.stopped"; exit 0; }}' TERM
until [ -n "${{FAKE_PRESS:-}}" ] && [ -e "$FAKE_STATE/${{FAKE_PRESS_AT:-ui.ready}}" ]; do sleep 0.1; done
killing=1
echo "kill $name" >> "$FAKE_STATE/mapper.log"
$sudo {PKILL} -f "$name"
sleep 3
if {PGREP} -f "$name" > /dev/null; then $sudo {PKILL} -9 -f "$name"; fi
exit 0
'''

# gptokeyb2 as PortsMaster/gptokeyb2 src/util.c kills: SIGKILL only, by
# process name (pkill -9 NAME) unless -X, then pgrep -f and kill -9 on every
# match but its own ancestry and children. It quits after a kill, and keeps
# running when it has no process name. FAKE_MAPPER_STAYS is gptokeyb2
# before 2026-10-05, which keeps running after a -X kill (an inner
# `int status` shadows the result, 23581b62ec src/util.c:486-519).
FAKE_GPTOKEYB2 = f'''#!/bin/bash
printf '%s\\n' "$@" > "$FAKE_STATE/mapper.args"
echo $$ > "$FAKE_STATE/mapper.pid"
if [ -n "${{FAKE_MAPPER_DIES:-}}" ]; then
  echo "gptokeyb2: cannot open /dev/uinput" >&2
  exit 1
fi
want_kill="" name=""
while [ $# -gt 0 ]; do
  case "$1" in
    -X) want_kill=1; shift ;;
    -c) shift 2 ;;
    -*) shift ;;
    *) [ -z "$name" ] && name="$1"; shift ;;
  esac
done
trap 'echo stopped > "$FAKE_STATE/mapper.stopped"; exit 0' TERM
until [ -n "${{FAKE_PRESS:-}}" ] && [ -e "$FAKE_STATE/${{FAKE_PRESS_AT:-ui.ready}}" ]; do sleep 0.1; done
echo "kill $name" >> "$FAKE_STATE/mapper.log"
if [ -z "$name" ]; then
  while :; do sleep 0.1; done
fi
if [ -n "$want_kill" ]; then
  ours=" $$ "
  p=$$
  while [ "$p" -gt 1 ]; do
    p=$(awk '{{print $4}}' "/proc/$p/stat" 2>/dev/null)
    [ -n "$p" ] || break
    ours="$ours$p "
  done
  for pid in $({PGREP} -f "$name"); do
    case "$ours" in *" $pid "*) continue ;; esac
    [ "$(awk '{{print $4}}' "/proc/$pid/stat" 2>/dev/null)" = "$$" ] && continue
    kill -9 "$pid" 2>/dev/null
  done
else
  {PKILL} -9 "$name"
fi
if [ -n "${{FAKE_MAPPER_STAYS:-}}" ]; then
  while :; do sleep 0.1; done
fi
exit 0
'''

# ROCKNIX's /usr/bin/sudo: a stub that runs nothing (ROCKNIX distribution
# packages/sysutils/busybox/scripts/sudo).
ROCKNIX_SUDO = """#!/bin/sh
printf '%s\\n' "sudo $*" >> "$FAKE_STATE/tools.log"
echo " You are 'root' so 'sudo' is not required or supported"
exit 1
"""

FAKE_RECORDER = """#!/bin/sh
printf '%s\\n' "$(basename "$0") $*" >> "$FAKE_STATE/tools.log"
"""

# chvt brings the console to the front, so RB_VT_ACTIVE then names it. A
# compositor that keeps the display (FAKE_CHVT_REFUSED) leaves chvt waiting
# in VT_WAITACTIVE and the console in front unchanged.
FAKE_CHVT = """#!/bin/sh
# A loaded machine starts the process late (FAKE_CHVT_DELAY seconds).
[ -n "$FAKE_CHVT_DELAY" ] && sleep "$FAKE_CHVT_DELAY"
printf '%s\\n' "chvt $*" >> "$FAKE_STATE/tools.log"
[ -n "$FAKE_CHVT_REFUSED" ] && exec sleep 30
[ -n "$RB_VT_ACTIVE" ] && printf 'tty%s\\n' "$1" > "$RB_VT_ACTIVE"
exit 0
"""

FAKE_SETFONT = """#!/bin/sh
printf '%s\\n' "setfont $*" >> "$FAKE_STATE/tools.log"
while [ $# -gt 0 ]; do
  [ "$1" = "-O" ] && { [ -n "$FAKE_NO_SAVE" ] && exit 1; printf 'font' > "$2"; }
  shift
done
"""

# A terminal app: records how it was started and the SDL hint it was given,
# then runs its command. FAKE_TERM_FAILS is one that cannot open its window.
FAKE_TERMAPP = """#!/bin/sh
printf '%s\\n' "$(basename "$0") $*" >> "$FAKE_STATE/tools.log"
printf '%s\\n' "${SDL_GAMECONTROLLER_IGNORE_DEVICES_EXCEPT:-}" > "$FAKE_STATE/termapp.sdl"
printf '%s\\n' "${SDL_GAMECONTROLLER_IGNORE_DEVICES:-}" > "$FAKE_STATE/termapp.sdl_ignore"
echo $$ > "$FAKE_STATE/termapp.pid"
if [ -n "$FAKE_TERM_FAILS" ]; then
  echo "$(basename "$0"): Can't open display" >&2
  exit 1
fi
while [ $# -gt 0 ]; do
  case "$1" in
    --|-e) shift; break ;;
    *) shift ;;
  esac
done
exec "$@"
"""

# sudo with env_reset: the environment is dropped but for the variables
# --preserve-env names.
FAKE_SUDO = """#!/bin/bash
printf '%s\\n' "sudo $*" >> "$FAKE_STATE/tools.log"
keep=""
while [ $# -gt 0 ]; do
  case "$1" in
    --preserve-env=*) keep="${1#--preserve-env=}"; shift ;;
    -*) shift ;;
    *) break ;;
  esac
done
case ",$keep," in
  *,SDL_GAMECONTROLLERCONFIG_FILE,*) ;;
  *) unset SDL_GAMECONTROLLERCONFIG_FILE ;;
esac
exec "$@"
"""


class Device:
    """A simulated handheld: fake tools on PATH and a pty as its console."""

    def __init__(self, test: unittest.TestCase, **env: str):
        self.test = test
        self.root = _tempdir(test)
        self.state = self.root / "state"
        self.state.mkdir()
        # Registered before every other cleanup, so it runs after them.
        test.addCleanup(self._sweep)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        master, slave = pty.openpty()
        test.addCleanup(os.close, master)
        test.addCleanup(os.close, slave)
        termios.tcsetattr(slave, termios.TCSANOW, termios.tcgetattr(slave))
        import fcntl  # noqa: PLC0415
        # Wide enough that no path in a message is folded.
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 250, 0, 0))
        self.master, self.slave = master, slave
        self.console = os.ttyname(slave)
        self.before = termios.tcgetattr(slave)
        (self.bin / "python3").symlink_to(shutil.which("python3.8") or sys.executable)
        self.tool("gptokeyb", FAKE_MAPPER)
        self.tool("setfont", FAKE_SETFONT)
        self.tool("chvt", FAKE_CHVT)
        # A probe that cannot connect is offline (curl exit 7).
        self.tool("curl", '#!/bin/sh\nexit "${FAKE_CURL:-0}"\n')
        self.tool("pgrep", '#!/bin/sh\nexit "${FAKE_PGREP:-1}"\n')
        # A runner's real sudo needs no password: the Tools entry then ran
        # the fake mapper as root, with a reset environment, and recorded
        # nothing. A device has no sudo unless a test gives it one.
        self.tool("sudo", "#!/bin/sh\nexit 1\n")
        fonts = self.root / "fonts"
        fonts.mkdir()
        for name in ("Lat7-TerminusBold32x16", "Lat7-TerminusBold22x11",
                     "Lat7-TerminusBold20x10", "Lat7-Terminus16"):
            (fonts / f"{name}.psf.gz").write_bytes(b"")
        (self.root / "fb").write_text("640,480\n")
        environ = {k: v for k, v in os.environ.items()
                   if k not in ("DISPLAY", "WAYLAND_DISPLAY", "RETROBIOS_BASE_URL",
                                "RETROBIOS_INSTALL_OFFLINE", "RETROBIOS_IDLE_EXIT",
                                "RETROBIOS_PAD", "XAUTHORITY", "XDG_RUNTIME_DIR")}
        self.env = {
            **environ,
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "HOME": str(self.root),
            "XDG_RUNTIME_DIR": str(self.root / "runtime"),
            "FAKE_STATE": str(self.state),
            "FAKE_CALLS": str(self.state / "calls.jsonl"),
            "RB_FONTS": str(fonts),
            "RB_FB": str(self.root / "fb"),
            "RB_MESSAGE_WAIT": "1",
            "TERM": "dumb",
            # The ArkOS marker is a plymouth theme the host may carry too
            # (GitHub's Ubuntu 24.04 runner does): no ArkOS unless a test says so.
            "RB_ARK_MARKER": str(self.root / "no-ark-marker"),
            **env,
        }
        test.addCleanup(self._reap)

    def tool(self, name: str, text: str) -> Path:
        path = self.bin / name
        # python3 starts as a link to the real interpreter: never write through it.
        if path.is_symlink() or path.exists():
            path.unlink()
        path.write_text(text)
        path.chmod(0o755)
        return path

    def unpack(self, archive: str, into: Path) -> Path:
        """The launcher archive extracted where the firmware keeps it, with
        the fake installer in place of install.py."""
        into.mkdir(parents=True, exist_ok=True)
        built = build_port.build_archive(archive, self.root / "dist" / archive)
        with zipfile.ZipFile(built) as zf:
            zf.extractall(into)
            for info in zf.infolist():
                mode = info.external_attr >> 16
                if mode:
                    (into / info.filename).chmod(mode & 0o777)
        for found in into.rglob("install.py"):
            found.write_text(FAKE_INSTALL)
        return into

    def run(self, argv: list[str], stdio_tty: bool = False, keys: str = "", **env: str):
        """Run a launcher with *keys* waiting on the console as buttons
        pressed. Its console output is read from the pty."""
        if keys:
            os.write(self.master, keys.encode())
        stdin = self.slave if stdio_tty else subprocess.DEVNULL
        stdout = self.slave if stdio_tty else subprocess.PIPE
        start = time.monotonic()
        proc = subprocess.run(argv, env={**self.env, **env}, stdin=stdin, stdout=stdout,
                              stderr=subprocess.PIPE, timeout=120, check=False)
        self.elapsed = time.monotonic() - start
        self.screen = self._drain()
        return proc

    def spawn(self, argv: list[str], **env: str) -> subprocess.Popen:
        proc = subprocess.Popen(argv, env={**self.env, **env}, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.test.addCleanup(lambda: proc.poll() is None and proc.kill())
        return proc

    def wait_for(self, name: str, timeout: float = 20) -> None:
        end = time.monotonic() + timeout
        while not (self.state / name).exists():
            self.test.assertLess(time.monotonic(), end, f"{name} never appeared")
            time.sleep(0.05)

    def _drain(self) -> str:
        chunks = []
        os.set_blocking(self.master, False)
        while True:
            try:
                chunk = os.read(self.master, 65536)
            except (BlockingIOError, OSError):
                break
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks).decode("utf-8", "replace")

    def _reap(self) -> None:
        """A fake the launcher failed to stop must not outlive the test."""
        for name in ("mapper.pid", "ui.pid", "engine.pid"):
            path = self.state / name
            if path.exists():
                try:
                    os.kill(int(path.read_text()), signal.SIGKILL)
                except (ProcessLookupError, ValueError):
                    pass

    def _left(self) -> list[int]:
        """The processes a run on this device started that still run: each
        carries the device's FAKE_STATE in its environment."""
        marker = f"FAKE_STATE={self.state}".encode()
        found = []
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit() or int(entry.name) == os.getpid():
                continue
            try:
                environ = (entry / "environ").read_bytes()
            except OSError:
                continue
            if marker in environ.split(b"\0"):
                found.append(int(entry.name))
        return found

    def _sweep(self) -> None:
        """No process outlives its test. A launcher's stop sentinel polls
        every 5 s, so what is still running 6 s on was left behind: it is
        killed, and the test fails naming it, instead of the leak running
        into the tests after it."""
        end = time.monotonic() + 6
        while (left := self._left()) and time.monotonic() < end:
            time.sleep(0.1)
        named = []
        for pid in left:
            try:
                argv = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ")
                os.kill(pid, signal.SIGKILL)
            except (ProcessLookupError, FileNotFoundError):
                continue
            named.append(f"{pid} {argv.decode('utf-8', 'replace').strip()}")
        self.test.assertEqual(named, [], "processes left running after the test")

    def calls(self) -> list[dict]:
        path = self.state / "calls.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines()]

    def tui_calls(self) -> list[dict]:
        return [c for c in self.calls() if "--tui" in c["args"]]

    def lines(self, name: str) -> list[str]:
        path = self.state / name
        return path.read_text().splitlines() if path.exists() else []

    def tools(self) -> list[str]:
        return self.lines("tools.log")

    def mapper_args(self) -> list[str]:
        return self.lines("mapper.args")

    def assert_mapper_stopped(self) -> None:
        """The launcher stopped gptokeyb itself, before it exited."""
        pid = int((self.state / "mapper.pid").read_text())
        stopped = (self.state / "mapper.stopped").exists()
        if not stopped:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.test.assertTrue(stopped, "gptokeyb was left running")

    def assert_mapper_gone(self) -> None:
        """gptokeyb ended, by its own kill mode or by the launcher."""
        pid = int((self.state / "mapper.pid").read_text())
        end = time.monotonic() + 5
        while Path(f"/proc/{pid}").exists() and time.monotonic() < end:
            time.sleep(0.05)
        self.test.assertFalse(Path(f"/proc/{pid}").exists(), "gptokeyb was left running")

    def assert_console_restored(self) -> None:
        self.test.assertEqual(termios.tcgetattr(self.slave), self.before)


def sentinels(token: str) -> list[int]:
    """The Start + Select sentinels of a run: `bash -c SCRIPT TOKEN`, where
    the mapper carries the token after its own path."""
    found = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            argv = (entry / "cmdline").read_bytes().split(b"\0")
        except OSError:
            continue
        if len(argv) > 3 and argv[1] == b"-c" and argv[3] == token.encode():
            found.append(int(entry.name))
    return found


def wait_until(test: unittest.TestCase, check, timeout: float, what: str) -> None:
    end = time.monotonic() + timeout
    while not check():
        test.assertLess(time.monotonic(), end, what)
        time.sleep(0.1)


CONTROL_TXT = '''
directory="{roms}"
ESUDO=""
ESUDOKILL="-1"
CUR_TTY="{console}"
GPTOKEYB="$controlfolder/gptokeyb $ESUDOKILL"
get_controls() {{ sdl_controllerconfig="fake"; }}
'''

DIALOG_TXT = '''
PM_PID=""
PM_DONE="$FAKE_STATE/pm_done"
trace() { printf '%s\\n' "$*" >> "$FAKE_STATE/dialog.log"; }
PortMasterIPCheck() { echo 192.168.0.1; }
PortMasterDialogInit() { trace "INIT $*"; }
PortMasterDialogExit() { trace EXIT; }
PortMasterDialog() { trace "CMD $*"; }
PortMasterDialogResult() { trace "ASK $*"; echo quit; }
pm_finish() { trace FINISH; }
'''


class ThePortMasterPort(unittest.TestCase):
    """RetroBIOS.sh from the PortMaster archive, on a fake PortMaster."""

    def device(self, console: str | None = None, **env: str) -> Device:
        device = Device(self, **env)
        roms = device.root / "roms"
        self.gamedir = device.unpack(build_port.PORT_ZIP, roms / "ports") / "retrobios"
        control = device.root / "xdg" / "PortMaster"
        control.mkdir(parents=True)
        self.control = control
        (control / "control.txt").write_text(
            CONTROL_TXT.format(roms=str(roms).lstrip("/"), console=console or device.console))
        (control / "PortMasterDialog.txt").write_text(DIALOG_TXT)
        shutil.copy(device.bin / "gptokeyb", control / "gptokeyb")
        device.env["XDG_DATA_HOME"] = str(device.root / "xdg")
        # No muxterm on this device unless a test puts one there.
        device.env["RB_MUXTERM"] = str(device.root / "no-muxterm")
        self.script = str(roms / "ports" / "RetroBIOS.sh")
        return device

    def dialog(self, device: Device) -> list[str]:
        return device.lines("dialog.log")

    def test_online_on_the_console(self):
        device = self.device()
        proc = device.run(["bash", self.script], FAKE_RAW="1", FAKE_CODE="0")
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        [call] = device.tui_calls()
        self.assertEqual(call["args"], ["--tui"])
        self.assertEqual((call["stdin"], call["stdout"]), (device.console, device.console))
        self.assertEqual(call["term"], "linux")
        installer = str(self.gamedir / "install.py")
        self.assertEqual(call["argv0"], installer)
        self.assertEqual(call["pad"], "gptokeyb")
        self.assertEqual(call["idle_exit"], "300")
        # Kill mode on the Start + Select sentinel, never on the installer's
        # path, which the engine's command line carries too.
        args = device.mapper_args()
        self.assertEqual(args[0], "-1")
        self.assertRegex(args[1], r"^retrobios-stop-\d+x$")
        self.assertEqual(args[2:], ["-c", str(self.gamedir / "retrobios.gptk")])
        device.assert_mapper_stopped()
        self.assertEqual(sentinels(args[1]), [])
        device.assert_console_restored()
        # Reset when the console is taken and again when it is handed back.
        self.assertEqual(device.screen.count("\x1bc"), 2)
        self.assertLess(device.screen.index("Checking the connection"),
                        device.screen.rindex("\x1bc"))
        saved = str(self.gamedir / "run" / "font.psf")
        fonts = device.env["RB_FONTS"]
        self.assertEqual(device.tools(), [
            f"setfont -C {device.console} -O {saved} {fonts}/Lat7-TerminusBold22x11.psf.gz",
            f"setfont -C {device.console} {saved}",
        ])
        # PortMaster's own end of a port, after the interface, no screens.
        self.assertEqual(self.dialog(device), ["FINISH"])

    def test_the_interface_status_is_the_port_status(self):
        device = self.device()
        proc = device.run(["bash", self.script], FAKE_CODE="3", FAKE_ERROR="the folder is read-only")
        self.assertEqual(proc.returncode, 3)
        self.assertIn("Error: the folder is read-only", device.screen)
        self.assertIn("log.txt", device.screen)

    def test_a_quit_chosen_shows_no_message(self):
        """A quit chosen exits 2, below 128, and the
        first line of tui.err went into a message box waiting for A."""
        device = self.device()
        proc = device.run(["bash", self.script], FAKE_QUIT="1", FAKE_CODE="2",
                          RB_MESSAGE_WAIT="300")
        self.assertEqual(proc.returncode, 2)
        self.assertLess(device.elapsed, 15)
        self.assertNotIn("Nothing was installed", device.screen)
        self.assertNotIn("Press A", device.screen)
        device.assert_console_restored()

    def test_the_quit_line_is_the_one_install_py_writes(self):
        state = install.TuiState(os_type="linux", home=Path.home())
        state.quit_asked, state.exit_code = True, install.QUIT_CODE
        self.assertTrue(install.tui_quit_chosen(state))
        line = install.tui_farewell(state)[0]
        tui = (REPO_ROOT / "ports" / "shared" / "tui.txt").read_text(encoding="utf-8")
        self.assertIn(f'= "{line}" ]', tui)
        self.assertIn(f'print("{line}", file=sys.stderr)', FAKE_INSTALL)

    def test_offline_installs_from_a_pack_on_the_card(self):
        device = self.device(FAKE_CURL="7")
        roms = device.root / "roms"
        (roms / "Batocera_43.1_BIOS_Pack.zip").write_bytes(b"")
        pack = self.gamedir / "RetroArch_Lakka_v1.22.2_BIOS_Pack.zip"
        pack.write_bytes(b"")
        proc = device.run(["bash", self.script])
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        [call] = device.tui_calls()
        self.assertEqual(call["args"], ["--tui", "--from-pack", str(pack),
                                        "--platform", "retroarch"])

    def test_offline_prefers_the_pack_of_this_system(self):
        device = self.device(FAKE_CURL="6")
        (self.gamedir / "Batocera_43.1_BIOS_Pack.zip").write_bytes(b"")
        pack = device.root / "roms" / "RetroArch_Lakka_v1.22.2_BIOS_Pack.part1of2.zip"
        pack.write_bytes(b"")
        device.run(["bash", self.script])
        [call] = device.tui_calls()
        self.assertEqual(call["args"][1:3], ["--from-pack", str(pack)])

    def test_offline_without_a_pack_says_where_to_put_one(self):
        device = self.device(FAKE_CURL="7")
        proc = device.run(["bash", self.script])
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(device.tui_calls(), [])
        screen = " ".join(device.screen.split())
        self.assertIn("No network connection", screen)
        self.assertIn("RetroArch", screen)
        self.assertIn(str(self.gamedir), screen)
        self.assertIn("github.com/Abdess/retrobios/releases/latest", screen)
        device.assert_mapper_stopped()
        device.assert_console_restored()

    def test_offline_says_so_at_once_and_bounds_the_detection(self):
        """A detection run that hangs is stopped after RB_DETECT_LIMIT, with
        a line on the console from the start."""
        device = self.device(FAKE_CURL="28")
        pack = self.gamedir / "RetroArch_Lakka_v1.22.2_BIOS_Pack.zip"
        pack.write_bytes(b"")
        proc = device.run(["bash", self.script], FAKE_DETECT_HANG="1", RB_DETECT_LIMIT="2")
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        self.assertLess(device.elapsed, 15)
        screen = device.screen
        self.assertIn("Checking the connection", screen)
        self.assertIn("No connection. Looking for the BIOS folder", screen)
        [call] = device.tui_calls()
        # The detection was stopped: no platform, the first pack.
        self.assertEqual(call["args"], ["--tui", "--from-pack", str(pack)])
        log = (self.gamedir / "log.txt").read_text()
        self.assertIn("the detection run took over 2 s and was stopped", log)

    def test_the_detection_is_told_to_make_no_request(self):
        """RETROBIOS_INSTALL_OFFLINE: install.py detects, then stops where
        the file list would download, at once and with reason offline
        (install.py _network_allowed). The interface run does not inherit
        it, and no address is borrowed for the detection."""
        device = self.device(FAKE_CURL="7")
        pack = self.gamedir / "RetroArch_Lakka_v1.22.2_BIOS_Pack.zip"
        pack.write_bytes(b"")
        proc = device.run(["bash", self.script])
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        self.assertLess(device.elapsed, 15)
        [check] = [c for c in device.calls() if "--check" in c["args"]]
        self.assertEqual(check["args"], ["--check", "--events"])
        self.assertEqual((check["offline"], check["base_url"]), ("1", ""))
        detected = (self.gamedir / "run" / "detect.jsonl").read_text().splitlines()
        self.assertEqual([json.loads(line)["event"] for line in detected],
                         ["start", "detect", "error", "end"])
        self.assertEqual(json.loads(detected[2])["reason"], "offline")
        [call] = device.tui_calls()
        self.assertEqual(call["args"], ["--tui", "--from-pack", str(pack),
                                        "--platform", "retroarch"])
        self.assertEqual((call["offline"], call["base_url"]), ("", ""))
        self.assertNotIn("took over", (self.gamedir / "log.txt").read_text())

    def test_a_certificate_failure_is_not_offline(self):
        # curl 60: the network answered, install.py reports the certificate.
        device = self.device(FAKE_CURL="60")
        device.run(["bash", self.script])
        [call] = device.tui_calls()
        self.assertEqual(call["args"], ["--tui"])

    def test_an_old_python_is_told_on_the_console(self):
        device = self.device()
        device.tool("python3", '#!/bin/sh\n[ "$1" = "--version" ] && echo "Python 3.7.3"\nexit 1\n')
        device.tool("uname", "#!/bin/sh\necho armv7l\n")
        proc = device.run(["bash", self.script])
        self.assertEqual(proc.returncode, 1)
        screen = " ".join(device.screen.split())
        self.assertIn("Python 3.8 or newer is needed", screen)
        self.assertIn("3.7.3", screen)
        self.assertIn("--dest", screen)
        self.assertEqual(device.calls(), [])

    def _python_without_ssl(self, device) -> None:
        """A python3 3.8 or newer whose ssl import fails, as on a CFW image
        built without OpenSSL."""
        real = shutil.which("python3.8") or sys.executable
        shadow = device.root / "no-ssl"
        shadow.mkdir()
        (shadow / "ssl.py").write_text('raise ImportError("built without ssl")\n')
        device.tool("python3", f'#!/bin/sh\nPYTHONPATH="{shadow}" exec {real} "$@"\n')

    def test_a_python_without_ssl_is_told_on_the_console(self):
        """Only the version was probed: a python3 without ssl was chosen and
        every download failed as if the network were down."""
        device = self.device()
        self._python_without_ssl(device)
        device.tool("uname", "#!/bin/sh\necho armv7l\n")
        proc = device.run(["bash", self.script])
        self.assertEqual(proc.returncode, 1)
        screen = " ".join(device.screen.split())
        self.assertIn("built without a module install.py needs", screen)
        self.assertEqual(device.calls(), [])

    def test_a_python_without_ssl_gives_way_to_the_runtime(self):
        device = self.device()
        self._python_without_ssl(device)
        real = shutil.which("python3.8") or sys.executable
        device.tool("uname", "#!/bin/sh\necho aarch64\n")
        device.tool("mount", '#!/bin/sh\nprintf "mount %s\\n" "$*" >> "$FAKE_STATE/tools.log"\n'
                    'mkdir -p "$2/bin"\n'
                    f'printf \'#!/bin/sh\\nunset PYTHONHOME\\nexec {real} "$@"\\n\' > "$2/bin/python3"\n'
                    'chmod +x "$2/bin/python3"\n')
        device.tool("umount", FAKE_RECORDER)
        (self.control / "libs").mkdir()
        (self.control / "libs" / "python_3.11.squashfs").write_bytes(b"")
        proc = device.run(["bash", self.script])
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        [call] = device.tui_calls()
        self.assertTrue(any(t.startswith("mount") for t in device.tools()))

    def test_the_runtime_is_mounted_then_unmounted(self):
        """ArkOS's Python 3.7: PortMaster's python_3.11 runtime, mounted for
        the run and unmounted after it."""
        device = self.device()
        real = shutil.which("python3.8") or sys.executable
        device.tool("python3", '#!/bin/sh\n[ "$1" = "--version" ] && echo "Python 3.7.3"\nexit 1\n')
        device.tool("uname", "#!/bin/sh\necho aarch64\n")
        # The runtime's python, a stand-in that ignores the PYTHONHOME the
        # launcher sets for the real one.
        device.tool("mount", '#!/bin/sh\nprintf "mount %s\\n" "$*" >> "$FAKE_STATE/tools.log"\n'
                    'mkdir -p "$2/bin"\n'
                    f'printf \'#!/bin/sh\\nunset PYTHONHOME\\nexec {real} "$@"\\n\' > "$2/bin/python3"\n'
                    'chmod +x "$2/bin/python3"\n')
        device.tool("umount", FAKE_RECORDER)
        (self.control / "libs").mkdir()
        squashfs = self.control / "libs" / "python_3.11.squashfs"
        squashfs.write_bytes(b"")
        proc = device.run(["bash", self.script])
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        self.assertEqual(len(device.tui_calls()), 1)
        runtime = str(device.root / "python_3.11")
        mounts = [t for t in device.tools() if t.startswith(("mount", "umount"))]
        self.assertEqual(mounts, [f"umount {runtime}", f"mount {squashfs} {runtime}",
                                  f"umount {runtime}"])

    def test_a_refused_console_falls_back_to_portmaster_screens(self):
        device = self.device()
        device.run(["bash", self.script], FAKE_REFUSE="1")
        self.assertEqual(len(device.tui_calls()), 1)
        dialog = self.dialog(device)
        self.assertEqual(dialog[0], "INIT no-check")
        self.assertIn("ASK selection_list --register=notice --want-description --want-cancel",
                      dialog)
        device.assert_mapper_stopped()
        device.assert_console_restored()

    def test_a_console_this_user_cannot_open_is_opened_up(self):
        """PortMaster's control.txt chmods the consoles only under sudo: the
        launcher does it for the one it draws on."""
        device = self.device()
        os.chmod(device.console, 0o000)
        self.addCleanup(os.chmod, device.console, 0o620)
        proc = device.run(["bash", self.script])
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        [call] = device.tui_calls()
        self.assertEqual(call["stdin"], device.console)
        self.assertEqual(os.stat(device.console).st_mode & 0o777, 0o666)

    def test_under_a_compositor_without_a_terminal_app_the_screens_open(self):
        device = self.device(FAKE_PGREP="0")
        device.run(["bash", self.script])
        self.assertEqual(device.tui_calls(), [])
        self.assertEqual(self.dialog(device)[0], "INIT no-check")
        self.assertEqual(device.mapper_args(), [])

    def test_arkos_offers_the_card_portmaster_does_not_run_from(self):
        device = self.device(FAKE_CURL="7")
        marker = device.root / "text.plymouth"
        marker.write_text("")
        roms = device.root / "roms" / "bios"
        other = device.root / "roms2" / "bios"
        roms.mkdir(parents=True)
        other.mkdir(parents=True)
        (roms / "a.bin").write_bytes(b"x")
        (other / "b.bin").write_bytes(b"y")
        pack = self.gamedir / "RetroArch_Lakka_v1.22.2_BIOS_Pack.zip"
        pack.write_bytes(b"")
        device.run(["bash", self.script], keys="\r", RB_ARK_MARKER=str(marker),
                   RB_OTHER_CARDS=f"{roms}:{other}",
                   RB_RETROARCH_CFG=str(device.root / "none.cfg"))
        [call] = device.tui_calls()
        # The port's games card is roms here: its bios is the destination.
        self.assertEqual(call["args"][:3], ["--tui", "--from", str(other)])

    def test_arkos_destination_is_the_folder_retroarch_reads(self):
        """control.txt names roms2 as the port's card whenever a second card
        is mounted: RetroArch's system_directory decides."""
        device = self.device(FAKE_CURL="7")
        marker = device.root / "text.plymouth"
        marker.write_text("")
        roms = device.root / "roms" / "bios"
        other = device.root / "roms2" / "bios"
        roms.mkdir(parents=True)
        other.mkdir(parents=True)
        (roms / "a.bin").write_bytes(b"x")
        (other / "b.bin").write_bytes(b"y")
        cfg = device.root / "retroarch.cfg"
        cfg.write_text(f'system_directory = "{other}"\n')
        (self.gamedir / "RetroArch_Lakka_v1.22.2_BIOS_Pack.zip").write_bytes(b"")
        device.run(["bash", self.script], keys="\r", RB_ARK_MARKER=str(marker),
                   RB_OTHER_CARDS=f"{roms}:{other}", RB_RETROARCH_CFG=str(cfg))
        [call] = device.tui_calls()
        self.assertEqual(call["args"][:3], ["--tui", "--from", str(roms)])

    def test_under_a_compositor_foot_shows_the_interface(self):
        device = self.device(WAYLAND_DISPLAY="wayland-1")
        device.tool("foot", FAKE_TERMAPP)
        proc = device.run(["bash", self.script], FAKE_CODE="4")
        self.assertEqual(proc.returncode, 4)
        [call] = device.tui_calls()
        self.assertEqual(call["args"], ["--tui"])
        self.assertEqual(device.tools(), [f"foot -F -- bash {self.gamedir}/tui.txt here"])
        self.assertRegex(device.mapper_args()[1], r"^retrobios-stop-\d+x$")
        device.assert_mapper_stopped()

    def test_a_terminal_app_that_cannot_open_hands_over(self):
        """foot refused the display: the interface never ran, and the port
        opens PortMaster's screens instead of ending on a status of 1."""
        device = self.device(WAYLAND_DISPLAY="wayland-1")
        device.tool("foot", FAKE_TERMAPP)
        proc = device.run(["bash", self.script], FAKE_TERM_FAILS="1")
        self.assertEqual(device.tui_calls(), [])
        self.assertEqual(self.dialog(device)[0], "INIT no-check", proc.stderr.decode())
        log = (self.gamedir / "log.txt").read_text()
        self.assertIn("foot ended with status 1 before the interface ran", log)
        device.assert_mapper_stopped()

    def test_on_muos_the_interface_opens_in_muxterm(self):
        """mod_muOS.txt sets CUR_TTY to /dev/null: muxterm shows the
        interface, told to leave the pad to gptokeyb."""
        device = self.device(console="/dev/null")
        muxterm = device.tool("muxterm", FAKE_TERMAPP)
        proc = device.run(["bash", self.script], RB_MUXTERM=str(muxterm))
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        [call] = device.tui_calls()
        self.assertEqual(call["args"], ["--tui"])
        self.assertEqual(device.tools(), [f"muxterm --gl -- bash {self.gamedir}/tui.txt here"])
        [hint] = device.lines("termapp.sdl")
        assert_muxterm_hides_every_pad(self, hint)
        assert_muxterm_mapping(self, device.mapper_args(), self.gamedir / "retrobios.gptk")
        self.assertEqual(call["pad"], "gptokeyb_muxterm")
        self.assertEqual(call["idle_exit"], "300")
        self.assertEqual(self.dialog(device), ["FINISH"])

    def test_on_muos_without_muxterm_the_log_says_why_the_screens_open(self):
        device = self.device(console="/dev/null")
        device.run(["bash", self.script])
        self.assertEqual(device.tui_calls(), [])
        self.assertEqual(self.dialog(device)[0], "INIT no-check")
        log = (self.gamedir / "log.txt").read_text()
        self.assertIn("/dev/null is not a console", log)

    def test_start_select_lets_the_install_say_what_it_wrote(self):
        """gptokeyb's kill reaches the sentinel only: the interface is asked
        to stop, gives the running install its SIGINT and 2 s, and writes
        its result. The engine never sees gptokeyb's SIGTERM or SIGKILL."""
        device = self.device()
        proc = device.run(["bash", self.script], FAKE_HOLD="1", FAKE_ENGINE="1",
                          FAKE_PRESS="1", RB_MESSAGE_WAIT="300")
        self.assertEqual(proc.returncode, 143, proc.stderr.decode())
        self.assertLess(device.elapsed, 15)
        self.assertEqual(device.lines("ui.log"), ["signal 15"])
        self.assertEqual(device.lines("engine.log"), ["summary after SIGINT"])
        self.assertIn("RetroBIOS: the install was stopped, 2 files written.", device.screen)
        self.assertNotIn("Press A", device.screen)
        device.assert_mapper_gone()
        device.assert_console_restored()
        self.assertEqual(self.dialog(device), ["FINISH"])

    def test_start_select_on_an_error_screen_returns_at_once(self):
        """The interface leaves an error screen with its farewell on stderr,
        and gptokeyb is gone: no message may wait for a button."""
        device = self.device()
        proc = device.run(["bash", self.script], FAKE_HOLD="1", FAKE_PRESS="1",
                          FAKE_TERM_ERROR="could not reach the file list",
                          RB_MESSAGE_WAIT="300")
        self.assertEqual(proc.returncode, 143)
        self.assertLess(device.elapsed, 10)
        self.assertNotIn("Press A", device.screen)
        device.assert_mapper_gone()
        device.assert_console_restored()

    def test_an_idle_close_on_an_error_names_the_error_at_once(self):
        """The interface closed for want of a button: the mapper never
        opened the pad, so no A can close a message. The error it closed is
        named, for RB_DEAD_WAIT seconds, not the idle line for 300."""
        device = self.device()
        proc = device.run(["bash", self.script], FAKE_IDLE_ERROR="could not reach the file list",
                          FAKE_CODE="1", RB_MESSAGE_WAIT="300", RB_DEAD_WAIT="1")
        self.assertEqual(proc.returncode, 1)
        self.assertLess(device.elapsed, 10)
        self.assertIn("could not reach the file list", device.screen)
        self.assertNotIn("No button pressed", device.screen)
        device.assert_console_restored()

    def test_the_idle_line_is_the_one_install_py_writes(self):
        """The launcher keyed on the words without install.py's prefix, and
        its fake printed them the same way: the test passed, the device
        still waited 300 s."""
        state = install.TuiState(os_type="linux", home=Path.home())
        state.idle_closed = True
        line = install._farewell_lines(state)[0]
        tui = (REPO_ROOT / "ports" / "shared" / "tui.txt").read_text(encoding="utf-8")
        self.assertIn(f'= "{line}" ]', tui)
        self.assertIn(f'print("{line}", file=sys.stderr)', FAKE_INSTALL)

    def test_start_select_before_the_interface_handles_signals(self):
        """A SIGTERM before run_tui installs its handlers ends Python on the
        default action, status 143."""
        device = self.device()
        proc = device.run(["bash", self.script], FAKE_HOLD="1", FAKE_PRESS="1",
                          FAKE_NO_HANDLER="1", RB_MESSAGE_WAIT="300")
        self.assertEqual(proc.returncode, 143)
        self.assertLess(device.elapsed, 10)
        self.assertNotIn("Press A", device.screen)
        device.assert_console_restored()

    def test_a_mapper_that_dies_at_once_starts_no_interface(self):
        device = self.device()
        proc = device.run(["bash", self.script], FAKE_MAPPER_DIES="1", RB_MESSAGE_WAIT="300",
                          RB_DEAD_WAIT="1")
        self.assertEqual(proc.returncode, 1)
        self.assertLess(device.elapsed, 10)
        self.assertEqual(device.tui_calls(), [])
        screen = " ".join(device.screen.split())
        self.assertIn("The controller cannot be read", screen)
        self.assertIn("log.txt", screen)
        log = (self.gamedir / "log.txt").read_text()
        self.assertIn("cannot open /dev/uinput", log)
        device.assert_console_restored()

    def test_a_mapper_that_dies_later_ends_the_interface(self):
        """Nothing moves the interface once gptokeyb is gone: it is asked to
        stop instead of waiting for a key forever."""
        device = self.device()
        proc = device.spawn(["bash", self.script], FAKE_HOLD="1", RB_DEAD_WAIT="1",
                            RB_MESSAGE_WAIT="300")
        device.wait_for("ui.ready")
        os.kill(int((device.state / "mapper.pid").read_text()), signal.SIGKILL)
        self.assertEqual(proc.wait(timeout=20), 143)
        self.assertEqual(device.lines("ui.log"), ["signal 15"])
        # The interface disappears: the console says why, for RB_DEAD_WAIT.
        screen = " ".join(device._drain().split())
        self.assertIn("gptokeyb, which turns the buttons into keys, stopped during the run",
                      screen)
        device.assert_console_restored()

    def test_start_select_with_an_interface_that_ignores_sigterm(self):
        """An interface that does not stop within RB_STOP_GRACE is killed,
        and the engine it started in its own session with it."""
        device = self.device()
        proc = device.run(["bash", self.script], FAKE_HOLD="1", FAKE_ENGINE="1",
                          FAKE_IGNORE_TERM="1", FAKE_PRESS="1", RB_STOP_GRACE="1",
                          RB_MESSAGE_WAIT="300")
        self.assertEqual(proc.returncode, 137, proc.stderr.decode())
        self.assertLess(device.elapsed, 15)
        engine = int((device.state / "engine.pid").read_text())
        wait_until(self, lambda: not Path(f"/proc/{engine}").exists(), 5,
                   "the engine outlived the interface")
        log = (self.gamedir / "log.txt").read_text()
        self.assertIn("the interface did not stop within 1 s", log)
        device.assert_console_restored()

    def test_an_interface_that_ignores_sigterm_without_pkill(self):
        """With no working pkill, the engines cannot be found: the interface
        itself is still killed after RB_STOP_GRACE."""
        device = self.device()
        device.tool("pkill", "#!/bin/sh\necho 'pkill: applet not found' >&2\nexit 127\n")
        proc = device.run(["bash", self.script], FAKE_HOLD="1", FAKE_IGNORE_TERM="1",
                          FAKE_PRESS="1", RB_STOP_GRACE="1", RB_MESSAGE_WAIT="300")
        self.assertEqual(proc.returncode, 137, proc.stderr.decode())
        self.assertLess(device.elapsed, 15)
        ui = int((device.state / "ui.pid").read_text())
        self.assertFalse(Path(f"/proc/{ui}").exists())

    def test_the_sentinel_ends_when_the_launcher_is_killed(self):
        """SIGKILL leaves the launcher no trap: the sentinel ends by itself
        once the launcher is gone."""
        device = self.device()
        proc = device.spawn(["bash", self.script], FAKE_HOLD="1")
        device.wait_for("ui.ready")
        token = device.mapper_args()[1]
        self.assertEqual(len(sentinels(token)), 1)
        proc.kill()
        proc.wait(timeout=5)
        wait_until(self, lambda: not sentinels(token), 10, "the sentinel outlived the launcher")

    def test_a_closed_terminal_ends_the_run(self):
        """The terminal app closed (muxterm's Menu, foot's window): the run
        inside it stops the interface and ends the run, and no other route
        or screen opens after it."""
        device = self.device(WAYLAND_DISPLAY="wayland-1")
        device.tool("foot", FAKE_TERMAPP)
        proc = device.spawn(["bash", self.script], FAKE_HOLD="1")
        device.wait_for("ui.ready")
        # FAKE_TERMAPP execs its command: its pid is the run inside it.
        os.kill(int((device.state / "termapp.pid").read_text()), signal.SIGHUP)
        self.assertEqual(proc.wait(timeout=20), 143)
        self.assertEqual(device.lines("ui.log"), ["signal 15"])
        self.assertEqual(self.dialog(device), ["FINISH"])
        device.assert_mapper_stopped()

    def test_sigterm_to_the_launcher_stops_the_interface_and_restores(self):
        """A firmware that signals the launcher alone: the trap stops the
        interface, the mapper and puts the console back."""
        device = self.device()
        proc = device.spawn(["bash", self.script], FAKE_HOLD="1", FAKE_RAW="1")
        device.wait_for("ui.ready")
        proc.send_signal(signal.SIGTERM)
        self.assertEqual(proc.wait(timeout=20), 143)
        self.assertEqual(device.lines("ui.log"), ["signal 15"])
        device.assert_mapper_stopped()
        device.assert_console_restored()

    def test_the_font_is_put_back_without_setfont_o(self):
        """busybox setfont has no -O: on ArkOS the font is changed only when
        the Lat7-Terminus20x10 its tools restore exists, and that one is put
        back."""
        device = self.device(FAKE_NO_SAVE="1")
        fonts = device.env["RB_FONTS"]
        (Path(fonts) / "Lat7-Terminus20x10.psf.gz").write_bytes(b"")
        marker = device.root / "text.plymouth"
        marker.write_text("")
        device.run(["bash", self.script], RB_ARK_MARKER=str(marker))
        chosen = f"{fonts}/Lat7-TerminusBold22x11.psf.gz"
        saved = str(self.gamedir / "run" / "font.psf")
        self.assertEqual(device.tools(), [
            f"setfont -C {device.console} -O {saved} {chosen}",
            f"setfont -C {device.console} {chosen}",
            f"setfont -C {device.console} {fonts}/Lat7-Terminus20x10.psf.gz",
        ])

    def test_elsewhere_a_font_that_cannot_be_saved_is_left(self):
        """Lat7-Terminus20x10 is ArkOS's font: put back on another device,
        it left the console in a font it never had."""
        device = self.device(FAKE_NO_SAVE="1")
        (Path(device.env["RB_FONTS"]) / "Lat7-Terminus20x10.psf.gz").write_bytes(b"")
        device.run(["bash", self.script])
        self.assertEqual(len([t for t in device.tools() if t.startswith("setfont")]), 1)

    def test_without_the_fallback_font_the_font_is_left(self):
        device = self.device(FAKE_NO_SAVE="1")
        device.run(["bash", self.script])
        self.assertEqual(len([t for t in device.tools() if t.startswith("setfont")]), 1)

    def test_a_read_only_card_runs_from_the_runtime_folder(self):
        device = self.device()
        self.gamedir.chmod(0o555)
        self.addCleanup(self.gamedir.chmod, 0o755)
        proc = device.run(["bash", self.script])
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        self.assertEqual(len(device.tui_calls()), 1)
        spare = device.root / "runtime" / "retrobios"
        log = (spare / "log.txt").read_text()
        self.assertIn(f"{self.gamedir} cannot be written", log)
        self.assertTrue((spare / "run" / "status").exists())

    def test_nothing_writable_is_said_on_the_console(self):
        device = self.device()
        self.gamedir.chmod(0o555)
        self.addCleanup(self.gamedir.chmod, 0o755)
        runtime = device.root / "runtime"
        runtime.mkdir(mode=0o555)
        self.addCleanup(runtime.chmod, 0o755)
        proc = device.run(["bash", self.script], RB_DEAD_WAIT="2")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(device.calls(), [])
        self.assertIn("the SD card may be read-only or full", " ".join(device.screen.split()))
        # Left on the console long enough to read before the menu redraws.
        self.assertGreaterEqual(device.elapsed, 2)

    def test_the_previous_log_is_kept(self):
        device = self.device()
        (self.gamedir / "log.txt").write_text("the failure\n")
        device.run(["bash", self.script])
        self.assertEqual((self.gamedir / "log.prev.txt").read_text(), "the failure\n")
        self.assertNotIn("the failure", (self.gamedir / "log.txt").read_text())


class TheBatoceraPort(unittest.TestCase):
    def device(self, **env: str) -> tuple[Device, Path]:
        device = Device(self, **env)
        ports = device.unpack(build_port.BATOCERA_ZIP, device.root / "userdata" / "roms" / "ports")
        return device, ports

    def console_switch(self, device: Device) -> dict[str, str]:
        number = re.fullmatch(r"/dev/pts/(\d+)", device.console)
        self.assertIsNotNone(number)
        self.number = number.group(1)
        # The console in front before the switch: never the pty the test
        # was given, which was /dev/pts/2 on a busy machine, so the launcher
        # found itself already in front and switched nowhere.
        self.home = "3" if self.number == "2" else "2"
        (device.root / "active").write_text(f"tty{self.home}\n")
        return {"RB_VT_ACTIVE": str(device.root / "active"), "RB_VT_PREFIX": "/dev/pts/",
                "RB_VT_SWITCH": self.number}

    def test_xterm_in_the_x11_session(self):
        device, ports = self.device(DISPLAY=":0")
        device.tool("xterm", FAKE_TERMAPP)
        proc = device.run(["/bin/bash", str(ports / "RetroBIOS.sh")])
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        [call] = device.tui_calls()
        self.assertEqual(call["args"], ["--tui"])
        self.assertEqual(device.tools(),
                         [f"xterm -fullscreen -e bash {ports}/retrobios/tui.txt here"])
        # evmapy reads RetroBIOS.sh.keys: no gptokeyb is started.
        self.assertEqual(device.mapper_args(), [])
        self.assertEqual(call["pad"], "evmapy")
        self.assertEqual(call["idle_exit"], "300")

    def test_the_x_cookie_goes_with_the_display(self):
        """S31emulationstation starts X with XAUTHORITY=/var/lib/.Xauthority:
        without it xterm is refused the display."""
        device, ports = self.device()
        device.tool("xterm", FAKE_TERMAPP + "")
        socket_dir = device.root / "x11"
        socket_dir.mkdir()
        import socket as _socket  # noqa: PLC0415
        sock = _socket.socket(_socket.AF_UNIX)
        sock.bind(str(socket_dir / "X0"))
        self.addCleanup(sock.close)
        cookie = device.root / "Xauthority"
        cookie.write_text("")
        device.tool("xterm", '#!/bin/sh\nprintf "%s %s\\n" "$DISPLAY" "$XAUTHORITY" '
                    '> "$FAKE_STATE/x.env"\n' + FAKE_TERMAPP.split("\n", 1)[1])
        proc = device.run(["/bin/bash", str(ports / "RetroBIOS.sh")],
                          RB_X_SOCKET=str(socket_dir / "X0"), RB_XAUTH=str(cookie))
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        self.assertEqual(device.lines("x.env"), [f":0 {cookie}"])

    def test_console_switch_when_no_terminal_app(self):
        device, ports = self.device(FAKE_PGREP="0")
        proc = device.run(["/bin/bash", str(ports / "RetroBIOS.sh")], **self.console_switch(device))
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        [call] = device.tui_calls()
        self.assertEqual(call["stdin"], device.console)
        chvt = [line for line in device.tools() if line.startswith("chvt")]
        self.assertEqual(chvt, [f"chvt {self.number}", f"chvt {self.home}"])
        device.assert_console_restored()

    def test_a_refused_console_switch_shows_nothing_on_an_unseen_console(self, **slow):
        """The compositor keeps the display: chvt waits and the console in
        front stays the same. The launcher switches back and stops, instead
        of an interface no key reaches."""
        device, ports = self.device(FAKE_PGREP="0")
        proc = device.run(["/bin/bash", str(ports / "RetroBIOS.sh")], FAKE_CHVT_REFUSED="1",
                          **self.console_switch(device), **slow)
        self.assertEqual(proc.returncode, 125)
        self.assertLess(device.elapsed, 20)
        self.assertEqual(device.tui_calls(), [])
        chvt = [line for line in device.tools() if line.startswith("chvt")]
        self.assertEqual(chvt, [f"chvt {self.number}", f"chvt {self.home}"])
        self.assertEqual((device.root / "active").read_text(), f"tty{self.home}\n")
        log = (ports / "retrobios" / "log.txt").read_text()
        self.assertIn(f"console {self.number} did not come to the front", log)
        self.assertNotIn("\x1bc", device.screen)

    def test_the_switch_back_is_waited_for_on_a_slow_machine(self):
        """The console to go back to was already in front, so rb_chvt
        returned before its chvt had even started, and the launcher ended
        with the switch back still pending: under load the log missed
        "chvt 2". A chvt that starts 1.2 s late made it fail every time."""
        self.test_a_refused_console_switch_shows_nothing_on_an_unseen_console(
            FAKE_CHVT_DELAY="1.2")

    def test_a_slow_console_switch_still_comes_back(self):
        device, ports = self.device(FAKE_PGREP="0")
        proc = device.run(["/bin/bash", str(ports / "RetroBIOS.sh")], FAKE_CHVT_DELAY="1.2",
                          **self.console_switch(device))
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        chvt = [line for line in device.tools() if line.startswith("chvt")]
        self.assertEqual(chvt, [f"chvt {self.number}", f"chvt {self.home}"])
        self.assertEqual((device.root / "active").read_text(), f"tty{self.home}\n")

    def test_xterm_that_cannot_open_hands_over_to_the_console(self):
        device, ports = self.device(DISPLAY=":0", FAKE_PGREP="0")
        device.tool("xterm", FAKE_TERMAPP)
        proc = device.run(["/bin/bash", str(ports / "RetroBIOS.sh")], FAKE_TERM_FAILS="1",
                          **self.console_switch(device))
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        [call] = device.tui_calls()
        self.assertEqual(call["stdin"], device.console)
        self.assertTrue(device.tools()[0].startswith("xterm -fullscreen -e bash"))


class TheMuosApp(unittest.TestCase):
    def device(self, muxterm: bool, gptokeyb2: bool = True) -> tuple[Device, Path]:
        device = Device(self)
        apps = device.unpack(build_port.MUOS_APP, device.root / "mmc" / "MUOS" / "application")
        muos = device.root / "opt-muos"
        (muos / "script" / "var").mkdir(parents=True)
        (muos / "script" / "var" / "retro.sh").write_text(
            'SETUP_APP() { printf "SETUP_APP %s\\n" "$1" >> "$FAKE_STATE/tools.log"; }\n'
            'GET_VAR() { case "$2" in\n'
            f'  storage/rom/mount) echo "{device.root / "mmc"}" ;;\n'
            f'  storage/sdcard/mount) echo "{device.root / "sdcard"}" ;;\n'
            '  *) echo "" ;;\nesac; }\n')
        if muxterm:
            (muos / "frontend").mkdir()
            shutil.copy(device.tool("muxterm", FAKE_TERMAPP), muos / "frontend" / "muxterm")
        pm = device.root / "mmc" / "MUOS" / "PortMaster"
        pm.mkdir(parents=True)
        if gptokeyb2:
            (pm / "gptokeyb2").write_text(FAKE_GPTOKEYB2)
            (pm / "gptokeyb2").chmod(0o755)
        device.env["RB_MUOS"] = str(muos)
        return device, apps / "RetroBIOS"

    def test_in_muxterm(self):
        device, app = self.device(muxterm=True)
        # muOS starts an app as <app>/mux_launch.sh <app>.
        proc = device.run([str(app / "mux_launch.sh"), str(app)])
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        [call] = device.tui_calls()
        self.assertEqual(call["args"], ["--tui"])
        self.assertEqual(device.tools(), ["SETUP_APP retrobios",
                                          f"muxterm --gl -- bash {app}/tui.txt here"])
        # muxterm leaves the pad to gptokeyb2, which sends each button once
        # with the interface's mapping: Y is Tab (Options), not muxterm's Space.
        [hint] = device.lines("termapp.sdl")
        assert_muxterm_hides_every_pad(self, hint)
        args = device.mapper_args()
        self.assertEqual(args[0], "-X")
        self.assertRegex(args[1], r"^retrobios-stop-\d+x$")
        assert_muxterm_mapping(self, args, app / "retrobios.gptk")
        self.assertEqual(read_gptk(Path(args[-1]))["y"], ["tab"])
        self.assertEqual(call["pad"], "gptokeyb_muxterm")
        self.assertEqual(call["idle_exit"], "300")
        device.assert_mapper_stopped()

    def test_muxterm_alone_without_gptokeyb2(self):
        device, app = self.device(muxterm=True, gptokeyb2=False)
        proc = device.run([str(app / "mux_launch.sh"), str(app)])
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        [call] = device.tui_calls()
        self.assertEqual(call["pad"], "muxterm")
        self.assertEqual(call["idle_exit"], "300")
        # muxterm then reads the pad itself.
        self.assertEqual(device.lines("termapp.sdl"), [""])
        self.assertEqual(device.mapper_args(), [])

    def test_start_select_ends_the_run_in_muxterm(self):
        """gptokeyb2 kills with SIGKILL: -X reaches the sentinel, and the
        interface is asked to stop as on the other routes."""
        device, app = self.device(muxterm=True)
        proc = device.run([str(app / "mux_launch.sh"), str(app)], FAKE_HOLD="1",
                          FAKE_PRESS="1", RB_MESSAGE_WAIT="300")
        self.assertEqual(proc.returncode, 143, proc.stderr.decode())
        self.assertLess(device.elapsed, 10)
        self.assertEqual(device.lines("ui.log"), ["signal 15"])
        device.assert_mapper_gone()

    def test_start_select_ends_the_run_on_the_console(self):
        device, app = self.device(muxterm=False)
        proc = device.run([str(app / "mux_launch.sh"), str(app)], FAKE_HOLD="1",
                          FAKE_PRESS="1", RB_CONSOLE=device.console, RB_MESSAGE_WAIT="300")
        self.assertEqual(proc.returncode, 143, proc.stderr.decode())
        self.assertLess(device.elapsed, 10)
        self.assertEqual(device.lines("ui.log"), ["signal 15"])
        device.assert_console_restored()

    def test_start_select_with_a_gptokeyb2_that_keeps_running(self):
        """gptokeyb2 before 2026-10-05 keeps running after its -X kill: only
        the sentinel's end says Start + Select was pressed."""
        device, app = self.device(muxterm=True)
        proc = device.run([str(app / "mux_launch.sh"), str(app)], FAKE_HOLD="1",
                          FAKE_PRESS="1", FAKE_MAPPER_STAYS="1", RB_MESSAGE_WAIT="300")
        self.assertEqual(proc.returncode, 143, proc.stderr.decode())
        self.assertLess(device.elapsed, 10)
        self.assertEqual(device.lines("ui.log"), ["signal 15"])
        self.assertIn("Start + Select", (app / "log.txt").read_text())
        device.assert_mapper_stopped()

    def test_a_gptokeyb2_that_cannot_start_is_named(self):
        device, app = self.device(muxterm=False)
        proc = device.run([str(app / "mux_launch.sh"), str(app)], FAKE_MAPPER_DIES="1",
                          RB_CONSOLE=device.console, RB_DEAD_WAIT="1")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(device.tui_calls(), [])
        screen = " ".join(device.screen.split())
        self.assertIn("gptokeyb2, which turns the buttons into keys, stopped as soon as it "
                      "started", screen)

    def test_an_arrow_at_the_question_leaves_nothing_behind(self):
        """An arrow is three bytes: the first answers the question, the rest
        must not reach the interface as two more keys."""
        device, app = self.device(muxterm=False)
        _sd1, sd2, _pack = self.two_cards(device)
        proc = device.run([str(app / "mux_launch.sh"), str(app)], keys="\x1b[B",
                          FAKE_CURL="7", FAKE_DRAIN="1", RB_CONSOLE=device.console,
                          RB_BIOS_DEST=str(sd2))
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        [call] = device.tui_calls()
        self.assertNotIn("--from", call["args"])
        self.assertEqual(device.lines("ui.input"), [""])

    def test_start_select_at_the_question_starts_no_interface(self):
        device, app = self.device(muxterm=False)
        _sd1, sd2, _pack = self.two_cards(device)
        proc = device.run([str(app / "mux_launch.sh"), str(app)], FAKE_CURL="7",
                          FAKE_PRESS="1", FAKE_PRESS_AT="calls.jsonl", RB_MESSAGE_WAIT="300",
                          RB_CONSOLE=device.console, RB_BIOS_DEST=str(sd2))
        self.assertEqual(proc.returncode, 143, proc.stderr.decode())
        self.assertLess(device.elapsed, 10)
        self.assertEqual(device.tui_calls(), [])
        # Never started: an interface started then stopped at once would
        # end the same way, before Python records anything.
        self.assertFalse((app / "run" / "tui.err").exists())

    def test_on_the_console_without_muxterm(self):
        device, app = self.device(muxterm=False)
        proc = device.run([str(app / "mux_launch.sh"), str(app)], RB_CONSOLE=device.console)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        [call] = device.tui_calls()
        self.assertEqual(call["stdin"], device.console)
        self.assertEqual(device.mapper_args()[3], str(app / "retrobios.gptk"))
        device.assert_console_restored()

    def test_offline_reads_a_pack_at_the_card_root(self):
        device, app = self.device(muxterm=True)
        pack = device.root / "mmc" / "RetroArch_Lakka_v1.22.2_BIOS_Pack.zip"
        pack.write_bytes(b"")
        device.run([str(app / "mux_launch.sh"), str(app)], FAKE_CURL="7")
        [call] = device.tui_calls()
        self.assertEqual(call["args"][:3], ["--tui", "--from-pack", str(pack)])

    def test_offline_names_the_pack_that_serves_muos(self):
        """muOS runs RetroArch, and install.py reads it as retroarch: the
        RetroArch pack serves it."""
        device, app = self.device(muxterm=True)
        proc = device.run([str(app / "mux_launch.sh"), str(app)], FAKE_CURL="7")
        self.assertEqual(proc.returncode, 1)
        # muxterm draws what its child writes: here the launcher's stdout.
        screen = " ".join(proc.stdout.decode().split())
        self.assertIn("download the RetroArch BIOS pack (a file whose name starts with "
                      "RetroArch_ and ends in _BIOS_Pack.zip)", screen)

    def test_offline_takes_no_pack_named_for_another_system(self):
        device, app = self.device(muxterm=True)
        (device.root / "mmc" / "Batocera_43.1_BIOS_Pack.zip").write_bytes(b"")
        proc = device.run([str(app / "mux_launch.sh"), str(app)], FAKE_CURL="7")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(device.tui_calls(), [])

    def test_offline_reads_a_pack_on_the_second_card(self):
        device, app = self.device(muxterm=True)
        (device.root / "sdcard").mkdir()
        pack = device.root / "sdcard" / "RetroArch_Lakka_v1.22.2_BIOS_Pack.zip"
        pack.write_bytes(b"")
        device.run([str(app / "mux_launch.sh"), str(app)], FAKE_CURL="7")
        [call] = device.tui_calls()
        self.assertEqual(call["args"][:3], ["--tui", "--from-pack", str(pack)])

    def two_cards(self, device: Device) -> tuple[Path, Path, Path]:
        """SD1 and SD2 both hold MUOS/bios, SD2's is the one muOS binds."""
        sd1 = device.root / "mmc" / "MUOS" / "bios"
        sd2 = device.root / "sdcard" / "MUOS" / "bios"
        sd1.mkdir(parents=True)
        sd2.mkdir(parents=True)
        (sd1 / "scph5501.bin").write_bytes(b"x")
        (sd2 / "gba_bios.bin").write_bytes(b"y")
        pack = device.root / "mmc" / "RetroArch_Lakka_v1.22.2_BIOS_Pack.zip"
        pack.write_bytes(b"")
        return sd1, sd2, pack

    def test_offline_offers_the_other_card(self):
        device, app = self.device(muxterm=False)
        sd1, sd2, pack = self.two_cards(device)
        proc = device.run([str(app / "mux_launch.sh"), str(app)], keys="\r", FAKE_CURL="7",
                          RB_CONSOLE=device.console, RB_BIOS_DEST=str(sd2))
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        self.assertIn("Copy the BIOS files from the other card?", device.screen)
        self.assertIn(str(sd1), device.screen)
        [call] = device.tui_calls()
        self.assertEqual(call["args"], ["--tui", "--from", str(sd1), "--from-pack", str(pack),
                                        "--platform", "retroarch"])

    def test_b_declines_the_other_card(self):
        device, app = self.device(muxterm=False)
        _sd1, sd2, pack = self.two_cards(device)
        device.run([str(app / "mux_launch.sh"), str(app)], keys="\x1b", FAKE_CURL="7",
                   RB_CONSOLE=device.console, RB_BIOS_DEST=str(sd2))
        [call] = device.tui_calls()
        self.assertEqual(call["args"], ["--tui", "--from-pack", str(pack),
                                        "--platform", "retroarch"])

    def test_the_card_the_system_reads_is_never_offered(self):
        device, app = self.device(muxterm=False)
        sd1, _sd2, _pack = self.two_cards(device)
        shutil.rmtree(device.root / "sdcard")
        device.run([str(app / "mux_launch.sh"), str(app)], FAKE_CURL="7",
                   RB_CONSOLE=device.console, RB_BIOS_DEST=str(sd1))
        self.assertNotIn("other card", device.screen)
        [call] = device.tui_calls()
        self.assertNotIn("--from", call["args"])

    def test_online_asks_nothing(self):
        device, app = self.device(muxterm=False)
        _sd1, sd2, _pack = self.two_cards(device)
        device.run([str(app / "mux_launch.sh"), str(app)],
                   RB_CONSOLE=device.console, RB_BIOS_DEST=str(sd2))
        self.assertNotIn("other card", device.screen)
        [call] = device.tui_calls()
        self.assertEqual(call["args"], ["--tui"])


class TheToolsEntry(unittest.TestCase):
    def device(self, **env: str) -> tuple[Device, Path]:
        device = Device(self, **env)
        tools = device.unpack(build_port.TOOLS_ZIP, device.root / "tools")
        device.env["RB_ROOT"] = str(device.root / "fs")
        return device, tools

    def arkos(self, device: Device) -> Path:
        fs = device.root / "fs"
        (fs / "opt" / "system").mkdir(parents=True)
        (fs / "opt" / "inttools").mkdir(parents=True)
        shutil.copy(device.bin / "gptokeyb", fs / "opt" / "inttools" / "gptokeyb")
        return fs

    def test_arkos_console_one(self):
        device, tools = self.device()
        self.arkos(device)
        proc = device.run(["bash", str(tools / "RetroBIOS.sh")], RB_CONSOLE=device.console)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        [call] = device.tui_calls()
        self.assertEqual((call["stdin"], call["term"]), (device.console, "linux"))
        self.assertEqual(call["pad"], "gptokeyb")
        self.assertEqual(call["idle_exit"], "300")
        args = device.mapper_args()
        self.assertEqual(args[0], "-1")
        self.assertRegex(args[1], r"^retrobios-stop-\d+x$")
        self.assertEqual(args[2:], ["-c", str(tools / "retrobios" / "retrobios.gptk")])
        device.assert_mapper_stopped()
        device.assert_console_restored()

    def test_the_previous_log_is_kept(self):
        device, tools = self.device()
        self.arkos(device)
        log = tools / "retrobios" / "log.txt"
        log.write_text("the failure\n")
        device.run(["bash", str(tools / "RetroBIOS.sh")], RB_CONSOLE=device.console)
        self.assertEqual((tools / "retrobios" / "log.prev.txt").read_text(), "the failure\n")
        self.assertNotIn("the failure", log.read_text())

    def test_arkos_sudo_keeps_the_controller_list(self):
        """sudo's env_reset would drop SDL_GAMECONTROLLERCONFIG_FILE, and a
        pad SDL does not know sends nothing."""
        device, tools = self.device()
        fs = self.arkos(device)
        db = fs / "opt" / "inttools" / "gamecontrollerdb.txt"
        db.write_text("")
        device.tool("sudo", FAKE_SUDO)
        proc = device.run(["bash", str(tools / "RetroBIOS.sh")], RB_CONSOLE=device.console)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        self.assertEqual(device.lines("mapper.db"), [str(db)])
        started = [t for t in device.tools() if "gptokeyb" in t]
        self.assertTrue(started[0].startswith(
            "sudo --preserve-env=SDL_GAMECONTROLLERCONFIG_FILE "), started)

    def test_start_select_on_the_console(self):
        device, tools = self.device()
        self.arkos(device)
        proc = device.run(["bash", str(tools / "RetroBIOS.sh")], RB_CONSOLE=device.console,
                          FAKE_HOLD="1", FAKE_PRESS="1", RB_MESSAGE_WAIT="300")
        self.assertEqual(proc.returncode, 143, proc.stderr.decode())
        self.assertLess(device.elapsed, 10)
        self.assertEqual(device.lines("ui.log"), ["signal 15"])
        self.assertNotIn("Press A", device.screen)
        device.assert_mapper_gone()
        device.assert_console_restored()

    def test_arkos_other_card_without_a_pack_needs_one(self):
        """--from needs the list of files, which an offline run takes from a
        pack: the message says so."""
        device, tools = self.device(FAKE_CURL="7")
        fs = self.arkos(device)
        roms, roms2 = device.root / "roms" / "bios", device.root / "roms2" / "bios"
        roms.mkdir(parents=True)
        roms2.mkdir(parents=True)
        (roms / "bios.bin").write_bytes(b"x")
        cfg = fs / "home" / "ark" / ".config" / "retroarch"
        cfg.mkdir(parents=True)
        (cfg / "retroarch.cfg").write_text(f'system_directory = "{roms2}"\n')
        proc = device.run(["bash", str(tools / "RetroBIOS.sh")], keys="\r",
                          RB_CONSOLE=device.console, RB_OTHER_CARDS=f"{roms}:{roms2}")
        self.assertEqual(proc.returncode, 1)
        screen = " ".join(device.screen.split())
        self.assertIn(f"Copy the BIOS files from the other card? {roms} holds files", screen)
        self.assertIn("with it, the files on the other card are copied too", screen)
        self.assertEqual(device.tui_calls(), [])

    def test_amberelec_console(self):
        device, tools = self.device()
        etc = device.root / "fs" / "etc"
        etc.mkdir(parents=True)
        (etc / "os-release").write_text('NAME="AmberELEC"\n')
        proc = device.run(["bash", str(tools / "RetroBIOS.sh")], RB_CONSOLE=device.console)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        [call] = device.tui_calls()
        self.assertEqual(call["stdin"], device.console)
        self.assertEqual(device.mapper_args()[0], "-1")

    def rocknix(self, device: Device) -> None:
        etc = device.root / "fs" / "etc"
        etc.mkdir(parents=True)
        (etc / "os-release").write_text('NAME="ROCKNIX"\n')
        device.tool("sudo", ROCKNIX_SUDO)

    def control_ini(self, device: Device) -> None:
        """control-gen_init.sh writes control.ini as control-gen.cpp:31
        does: `ESUDOKILL="-sudokill"`, and GPTOKEYB with it."""
        folder = device.root / "fs" / "storage" / ".config" / "gptokeyb"
        shutil.copy(device.bin / "gptokeyb", device.root / "gptokeyb-rocknix")
        device.tool("control-gen_init.sh", f'''#!/bin/sh
mkdir -p "{folder}"
cat > "{folder}/control.ini" <<'INI'
controlfolder="{device.root}"
ESUDO="sudo"
ESUDOKILL="-sudokill"
export SDL_GAMECONTROLLERCONFIG_FILE="$controlfolder/gamecontrollerdb.txt"
get_controls() {{
DEVICE="03000000"
param_device="fake pad"
}}
GPTOKEYB="$controlfolder/gptokeyb-rocknix $ESUDOKILL"
INI
''')

    def test_rocknix_runs_in_the_terminal_tools_opens(self):
        device, tools = self.device()
        self.rocknix(device)
        proc = device.run(["bash", str(tools / "RetroBIOS.sh")], stdio_tty=True, TERM="xterm")
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        [call] = device.tui_calls()
        self.assertEqual((call["stdin"], call["stdout"]), (device.console, device.console))
        self.assertEqual(call["term"], "xterm")
        self.assertEqual(call["pad"], "gptokeyb")
        self.assertEqual(call["idle_exit"], "300")
        # The terminal app owns its window: no console reset, no font.
        self.assertNotIn("\x1bc", device.screen)
        self.assertEqual([t for t in device.tools() if t.startswith("setfont")], [])

    def test_rocknix_loads_the_controller_list_its_own_tools_load(self):
        """control-gen_init.sh writes control.ini, which names the pad's
        controller list and the GPTOKEYB to start (ROCKNIX fex-emu's Start
        FEXConfig.sh). Its ESUDO is not this launcher's."""
        device, tools = self.device()
        self.rocknix(device)
        self.control_ini(device)
        proc = device.run(["bash", str(tools / "RetroBIOS.sh")], stdio_tty=True, TERM="xterm")
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        self.assertEqual(device.lines("mapper.args")[0], "-1")
        self.assertRegex(device.mapper_args()[1], r"^retrobios-stop-\d+x$")
        self.assertEqual(device.lines("mapper.db"), [f"{device.root}/gamecontrollerdb.txt"])
        started = [t for t in device.tools() if t.startswith("sudo")]
        self.assertEqual(started, [])
        # Stopped without the sudo control.ini names.
        device.assert_mapper_stopped()

    def test_rocknix_start_select_with_its_controller_setup(self):
        """control.ini's `-sudokill` runs the kill through sudo, which on
        ROCKNIX runs nothing: the mapper is started with -1, and Start +
        Select ends the run at once instead of 3 s later through the
        liveness watch."""
        device, tools = self.device()
        self.rocknix(device)
        self.control_ini(device)
        proc = device.run(["bash", str(tools / "RetroBIOS.sh")], stdio_tty=True, TERM="xterm",
                          FAKE_HOLD="1", FAKE_PRESS="1", RB_MESSAGE_WAIT="300")
        self.assertEqual(proc.returncode, 143, proc.stderr.decode())
        self.assertLess(device.elapsed, 10)
        self.assertEqual(device.lines("ui.log"), ["signal 15"])
        log = (tools / "retrobios" / "log.txt").read_text()
        self.assertIn("Start + Select: the interface is asked to stop", log)
        self.assertNotIn("the controller mapper stopped", log)
        self.assertNotIn("You are 'root'", log)
        device.assert_mapper_gone()

    def test_rocknix_offline_names_no_pack_the_releases_lack(self):
        """No release pack spells ROCKNIX, and install.py refuses one named
        for another system: the RetroArch pack on the card is not offered,
        and the message gives the computer route."""
        device, tools = self.device(FAKE_CURL="7")
        self.rocknix(device)
        (tools / "retrobios" / "RetroArch_v1.22.2_BIOS_Pack.zip").write_bytes(b"")
        proc = device.run(["bash", str(tools / "RetroBIOS.sh")], stdio_tty=True, TERM="xterm",
                          FAKE_PLATFORM="rocknix", FAKE_PLATFORM_NAME="ROCKNIX")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(device.tui_calls(), [])
        screen = " ".join(device.screen.split())
        self.assertIn("the releases carry no BIOS pack for ROCKNIX", screen)
        self.assertIn("--dest", screen)
        self.assertNotIn("download", screen)

    def test_rocknix_start_select_in_foot(self):
        device, tools = self.device()
        self.rocknix(device)
        proc = device.run(["bash", str(tools / "RetroBIOS.sh")], stdio_tty=True, TERM="xterm",
                          FAKE_HOLD="1", FAKE_PRESS="1", FAKE_TERM_ERROR="unreachable",
                          RB_MESSAGE_WAIT="300")
        self.assertEqual(proc.returncode, 143, proc.stderr.decode())
        self.assertLess(device.elapsed, 10)
        self.assertNotIn("Press A", device.screen)
        device.assert_mapper_gone()


class TheSweep(unittest.TestCase):
    def test_a_process_left_running_fails_its_test(self):
        started = []

        class Leaky(unittest.TestCase):
            def runTest(inner):
                device = Device(inner)
                started.append(subprocess.Popen(["sleep", "60"], env=device.env,
                                                stdin=subprocess.DEVNULL))

        result = unittest.TestResult()
        Leaky().run(result)
        [proc] = started
        self.assertEqual(proc.wait(timeout=5), -signal.SIGKILL)
        [(_, report)] = result.failures
        self.assertIn(f"{proc.pid} sleep 60", report)


class TheLiveness(unittest.TestCase):
    def test_a_zombie_is_not_running(self):
        """A process that exited and that its parent has not reaped still
        has /proc/PID: rb_alive reads its state."""
        pid = os.fork()
        if pid == 0:
            os._exit(0)
        self.addCleanup(os.waitpid, pid, 0)
        wait_until(self, lambda: Path(f"/proc/{pid}/stat").read_text().split(") ")[1][0] == "Z",
                   5, "no zombie")
        proc = subprocess.run(
            ["bash", "-c", 'source "$1"; rb_alive "$2" && echo alive || echo gone', "bash",
             str(PORTS / "shared" / "tui.txt"), str(pid)],
            capture_output=True, text=True, check=False)
        self.assertEqual(proc.stdout.strip(), "gone", proc.stderr)
        proc = subprocess.run(
            ["bash", "-c", 'source "$1"; rb_alive "$$" && echo alive || echo gone', "bash",
             str(PORTS / "shared" / "tui.txt")],
            capture_output=True, text=True, check=False)
        self.assertEqual(proc.stdout.strip(), "alive", proc.stderr)


class TheDocs(unittest.TestCase):
    def test_the_offline_packs_named_are_the_ones_that_serve(self):
        """The wiki names the pack each firmware takes offline: the release
        pack of the platform install.py detects it as, or none."""
        labels = build_port.release_pack_labels()
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
