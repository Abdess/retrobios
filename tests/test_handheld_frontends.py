"""The Batocera port, the muOS app and the tools entry, run on a simulated device, and the device's own checks."""
from __future__ import annotations

import tests

import contextlib
import os
import re
import shutil
import signal
import subprocess
import unittest
from pathlib import Path

from installer_build import port
from tests.handheldsupport import (
    PORTS,
    read_gptk,
    assert_muxterm_hides_every_pad,
    assert_muxterm_mapping,
    PGREP,
    PKILL,
    FAKE_TERMAPP,
    Device,
    wait_until,
)


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


class TheBatoceraPort(unittest.TestCase):
    def device(self, **env: str) -> tuple[Device, Path]:
        device = Device(self, **env)
        ports = device.unpack(port.BATOCERA_ZIP, device.root / "userdata" / "roms" / "ports")
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
        import socket as _socket
        sock = _socket.socket(_socket.AF_UNIX)
        # A socket address holds 108 bytes, fewer than a scratch folder can.
        with contextlib.chdir(socket_dir):
            sock.bind("X0")
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
        apps = device.unpack(port.MUOS_APP, device.root / "mmc" / "MUOS" / "application")
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
        tools = device.unpack(port.TOOLS_ZIP, device.root / "tools")
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


if __name__ == "__main__":
    unittest.main()
