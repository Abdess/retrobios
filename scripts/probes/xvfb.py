"""The private X server of a standalone run and the screen samples read from it."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import os
import re
import signal
import struct
import subprocess
import time
from pathlib import Path
from typing import IO

import core_probe as cp

SCREEN = (1280, 720)

# The X server runs inside the sandbox, on the sandbox's own /tmp: the
# display is private to the run, and the host's /tmp/.X11-unix (read-only
# under WSLg) is never touched. Its fbdir option keeps the screen as an XWD
# file in the run's scratch folder, which the probe reads from outside.
DISPLAY_NUMBER = 1
XVFB_WRAPPER = (
    f'Xvfb ":{DISPLAY_NUMBER}" -screen 0 {SCREEN[0]}x{SCREEN[1]}x24 -nolisten tcp -fbdir "$1" '
    '-noreset >/dev/null 2>&1 &\n'
    'i=0\n'
    f'while [ ! -S /tmp/.X11-unix/X{DISPLAY_NUMBER} ]; do\n'
    '  i=$((i + 1)); [ "$i" -gt 400 ] && exit 97; sleep 0.05\n'
    'done\n'
    'shift\n'
    'exec "$@"\n'
)

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def parse_xwd(data: bytes) -> tuple[int, int, bytes]:
    """Width, height and RGB pixels of an XWD image, the file Xvfb keeps
    its screen in: 32 bits per pixel, least significant byte first."""
    if len(data) < 100:
        raise cp.ProbeError("framebuffer file shorter than an XWD header")
    fields = struct.unpack_from(">25I", data, 0)
    header_size, version = fields[0], fields[1]
    width, height = fields[4], fields[5]
    byte_order, bits_per_pixel, bytes_per_line, ncolors = fields[7], fields[11], fields[12], fields[19]
    if version != 7 or bits_per_pixel != 32 or byte_order != 0:
        raise cp.ProbeError(f"XWD version {version}, {bits_per_pixel} bpp, byte order "
                            f"{byte_order}: only version 7, 32 bpp, LSB first are read")
    start = header_size + ncolors * 12
    rows = [data[start + y * bytes_per_line:start + y * bytes_per_line + width * 4] for y in range(height)]
    packed = b"".join(rows)
    if len(packed) != width * height * 4:
        raise cp.ProbeError("framebuffer file shorter than its header says")
    return width, height, cp.to_rgb(1, width, height, packed)


def with_display(argv: list[str], fbdir: Path) -> list[str]:
    """The emulator's command, started once the sandbox's Xvfb listens."""
    return ["/bin/sh", "-c", XVFB_WRAPPER, "xvfb", str(fbdir), *argv]


def stop(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
    proc.wait()


def read_lines(stream: IO[bytes], out: list[dict], samples: list) -> None:
    """The emulator's console, line by line, each with the sample count
    reached when it was written, colour escapes removed."""
    for raw in iter(stream.readline, b""):
        text = ANSI.sub("", raw.decode("utf-8", errors="replace")).rstrip()
        if text:
            out.append({"frame": len(samples), "level": "info", "text": text})


def wait_for_screen(proc: subprocess.Popen, screen_file: Path, logs: list[dict]) -> None:
    deadline = time.monotonic() + 30
    while not screen_file.exists():
        if proc.poll() is not None or time.monotonic() > deadline:
            raise cp.ProbeError(f"Xvfb did not start in the sandbox (exit {proc.poll()}): "
                                f"{' / '.join(line['text'] for line in logs[-5:])}")
        time.sleep(0.05)


def sample_screen(proc: subprocess.Popen, screen_file: Path, args: argparse.Namespace,
                  samples: list[tuple[float, str, bool]], png_dir: Path | None, started: float) -> dict | None:
    """Hash the screen every interval. Returns how the emulator ended, None
    while it still runs."""
    for index in range(args.samples):
        target = started + (index + 1) * args.interval
        while time.monotonic() < target and proc.poll() is None:
            time.sleep(min(0.05, max(0.0, target - time.monotonic())))
        if proc.poll() is not None:
            code = proc.returncode
            return {"status": code if code >= 0 else None,
                    "signal": signal.Signals(-code).name if code < 0 else None}
        width, height, rgb = parse_xwd(screen_file.read_bytes())
        sha1 = hashlib.sha1(rgb).hexdigest()
        samples.append((round(time.monotonic() - started, 3), sha1, cp.uniform_frame(rgb, 3)))
        if png_dir and not any(p.name.endswith(f"{sha1[:12]}.png") for p in png_dir.iterdir()):
            (png_dir / f"{index:04d}-{sha1[:12]}.png").write_bytes(cp.png_bytes(width, height, rgb))
    return None
