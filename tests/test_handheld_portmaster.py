"""RetroBIOS.sh from the PortMaster archive, run on a simulated device with a fake PortMaster."""
from __future__ import annotations

import tests

import json
import os
import shutil
import signal
import sys
import unittest
from pathlib import Path

from installer_build import port
from tests.handheldsupport import (
    REPO_ROOT,
    install,
    assert_muxterm_hides_every_pad,
    assert_muxterm_mapping,
    FAKE_INSTALL,
    FAKE_TERMAPP,
    Device,
    wait_until,
)


FAKE_RECORDER = """#!/bin/sh
printf '%s\\n' "$(basename "$0") $*" >> "$FAKE_STATE/tools.log"
"""


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
        self.gamedir = device.unpack(port.PORT_ZIP, roms / "ports") / "retrobios"
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


if __name__ == "__main__":
    unittest.main()
