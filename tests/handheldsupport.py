"""What the handheld launcher tests share: a simulated device, its fake firmware tools and the pad models.

A device is simulated with a pseudo-terminal standing for its console, a
fake install.py that records how it was started, and fakes for what the
firmware provides (gptokeyb, setfont, chvt, curl, foot, xterm, muxterm,
PortMaster's control.txt and muOS's retro.sh), all on PATH or in a folder
the launcher reads. What only a device shows (the text reaching the screen,
the pad reaching the console, a compositor covering it) is not exercised.
"""
from __future__ import annotations

import tests
from tests import scratch_dir

import contextlib
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
import termios
import time
import unittest
import zipfile
from pathlib import Path

from installer_build import port

REPO_ROOT = Path(__file__).resolve().parent.parent
PORTS = REPO_ROOT / "ports"

_spec = importlib.util.spec_from_file_location("install", REPO_ROOT / "install.py")
install = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(install)


def read_gptk(path: Path) -> dict[str, list[str]]:
    """key -> values, as gptokeyb's parseConfigFile reads `key = value`."""
    mapping: dict[str, list[str]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "[")):
            continue
        key, sep, value = line.partition(" = ")
        assert sep, line
        mapping.setdefault(key, []).append(value.split("#")[0].strip())
    return mapping


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


class Device:
    """A simulated handheld: fake tools on PATH and a pty as its console."""

    def __init__(self, test: unittest.TestCase, **env: str):
        self.test = test
        self.root = scratch_dir(test)
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
        import fcntl
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
        built = port.build_archive(archive, self.root / "dist" / archive)
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
                with contextlib.suppress(ProcessLookupError, ValueError):
                    os.kill(int(path.read_text()), signal.SIGKILL)

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
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)
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


def wait_until(test: unittest.TestCase, check, timeout: float, what: str) -> None:
    end = time.monotonic() + timeout
    while not check():
        test.assertLess(time.monotonic(), end, what)
        time.sleep(0.1)
