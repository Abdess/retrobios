#!/usr/bin/env python3
"""Run a libretro core headless and record what it did.

Three modes share one runner:

  run    one execution, printed as JSON
  bench  warm-up then timed repetitions, with timing statistics
  check  the same execution under several variants of one system file,
         compared on a named observable

Each repetition runs in its own process, under strace when it is installed,
so the files a core opened are read from the kernel rather than guessed.
`--record` appends one record per invocation, as one line of
measurements/<emulator>.jsonl in this repository, carrying what is needed to
reproduce it (core build, frontend commit, host, inputs by hash).
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import datetime as dt
import fcntl
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import statistics
import struct
import subprocess
import sys
import tempfile
import time
import zlib
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path

# The probe tools do not import common.py, which states the 3.9 floor for the
# other scripts. Under 3.8 they stopped on a str.removesuffix AttributeError.
if sys.version_info < (3, 9):
    sys.exit(
        f"{Path(sys.argv[0]).name} needs Python 3.9 or newer, "
        f"this is {sys.version.split()[0]}"
    )

ROOT = Path(__file__).resolve().parent.parent
MIN_BENCH_REPETITIONS = 5
DEFAULT_WORK_DIR = ROOT / "tmp" / "core_probe"
BASE_OBSERVABLES = ("frame_sha1", "video_sha1", "audio_sha1", "state_sha1")

# libretro.h environment commands the probe answers.
ENV_GET_CAN_DUPE = 3
ENV_GET_SYSTEM_DIRECTORY = 9
ENV_SET_PIXEL_FORMAT = 10
ENV_GET_VARIABLE = 15
ENV_SET_VARIABLES = 16
ENV_GET_VARIABLE_UPDATE = 17
ENV_SET_SUPPORT_NO_GAME = 18
ENV_GET_LOG_INTERFACE = 27
ENV_GET_SAVE_DIRECTORY = 31
ENV_GET_CORE_OPTIONS_VERSION = 52
ENV_EXPERIMENTAL = 0x10000

PIXEL_BYTES = {0: 2, 1: 4, 2: 2}
LOG_LEVELS = ("debug", "info", "warn", "error")
JOYPAD_BUTTONS = {
    "b": 0, "y": 1, "select": 2, "start": 3, "up": 4, "down": 5, "left": 6,
    "right": 7, "a": 8, "x": 9, "l": 10, "r": 11, "l2": 12, "r2": 13,
    "l3": 14, "r3": 15,
}
STRACE_LINE = re.compile(
    r'^(?:\[pid\s+)?(?P<pid>\d+)\]?\s+(?P<call>openat|open)\('
    r'(?:[^,]+,\s*)?"(?P<path>(?:[^"\\]|\\.)*)"(?:\.\.\.)?,\s*(?P<flags>[^,)]+)'
    r'.*\)\s*=\s*(?P<ret>-?\d+)(?:\s+(?P<errno>[A-Z]+))?'
)
PRINTF_SPEC = re.compile(r"%(?P<flags>[-+ #0]*)(?P<width>\*|\d+)?(?:\.(?P<prec>\*|\d+))?"
                         r"(?P<len>hh|h|ll|l|j|z|t|L)?(?P<conv>[diouxXeEfFgGaAcspn%])")


# One measurement at a time on the host: each core_probe execution takes this
# lock itself, its load check included, and releases it when it ends. A pass
# of many runs never holds it between them, so two passes interleave.
PROBE_LOCK_ENV = "RETROBIOS_PROBE_LOCK"
PROBE_LOCK_HELD_ENV = "RETROBIOS_PROBE_LOCK_HELD"
DEFAULT_PROBE_LOCK = Path.home() / ".local" / "state" / "retrobios" / "probe.lock"


def probe_lock_path() -> Path:
    return Path(os.environ.get(PROBE_LOCK_ENV) or DEFAULT_PROBE_LOCK)


@contextlib.contextmanager
def host_probe_lock() -> Iterator[None]:
    """The host's probe lock for one execution. A caller that already holds
    it for this run says so with RETROBIOS_PROBE_LOCK_HELD."""
    if os.environ.get(PROBE_LOCK_HELD_ENV):
        yield
        return
    path = probe_lock_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(f"waiting for {path}: another measurement is running", file=sys.stderr)
            fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


class ProbeError(RuntimeError):
    """A run that cannot produce a trustworthy result."""


# --------------------------------------------------------------------------
# Hashing and small helpers
# --------------------------------------------------------------------------

def file_digest(path: Path, algorithm: str = "sha1") -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cue_tracks(cue: Path) -> list[Path]:
    """Files a .cue sheet references, in order."""
    tracks: list[Path] = []
    for line in cue.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.match(r'\s*FILE\s+"([^"]+)"', line) or re.match(r"\s*FILE\s+(\S+)", line)
        if match:
            tracks.append(cue.parent / match.group(1))
    return tracks


def content_identity(path: Path, label: str | None) -> dict:
    tracks = [
        {"file": track.name, "sha1": file_digest(track), "size": track.stat().st_size}
        for track in (cue_tracks(path) if path.suffix.lower() == ".cue" else [])
    ]
    return {
        "label": label,
        "sha1": file_digest(path),
        "size": path.stat().st_size,
        "tracks": tracks,
    }


def describe_env_value(value: str) -> str:
    """An environment value as a record keeps it: a file by name and sha256.

    The path is a detail of the host that ran the probe, the bytes are what
    the run depended on.
    """
    path = Path(value)
    if path.is_absolute() and path.is_file():
        return f"{path.name} sha256:{file_digest(path, 'sha256')}"
    return value


def parse_assignment(text: str, flag: str) -> tuple[str, str]:
    key, sep, value = text.partition("=")
    if not sep or not key:
        raise argparse.ArgumentTypeError(f"{flag} expects KEY=VALUE, got {text!r}")
    return key, value


def parse_press(text: str) -> tuple[int, int, int]:
    """FRAME:BUTTON[:LENGTH] on joypad port 0."""
    parts = text.split(":")
    if len(parts) not in (2, 3) or parts[1].lower() not in JOYPAD_BUTTONS:
        raise argparse.ArgumentTypeError(
            f"--press expects FRAME:BUTTON[:LENGTH] with BUTTON in "
            f"{', '.join(JOYPAD_BUTTONS)}, got {text!r}"
        )
    try:
        frame = int(parts[0])
        length = int(parts[2]) if len(parts) == 3 else 1
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"--press {text!r}: {exc}") from exc
    if frame < 0 or length < 1:
        raise argparse.ArgumentTypeError(f"--press {text!r}: frame >= 0, length >= 1")
    return frame, JOYPAD_BUTTONS[parts[1].lower()], length


def parse_strace(text: str) -> list[dict]:
    """open/openat calls from `strace -f -e trace=openat,open` output."""
    calls: list[dict] = []
    for line in text.splitlines():
        match = STRACE_LINE.match(line.strip())
        if not match:
            continue
        ret = int(match.group("ret"))
        calls.append({
            "path": bytes(match.group("path"), "utf-8").decode("unicode_escape"),
            "flags": match.group("flags").strip(),
            "ok": ret >= 0,
            "errno": match.group("errno"),
        })
    return calls


def files_under(calls: Iterable[dict], directory: Path) -> tuple[list[str], list[str]]:
    """Relative paths opened, and probed but absent, under a directory."""
    base = os.path.realpath(directory)
    opened: dict[str, None] = {}
    missing: dict[str, None] = {}
    for call in calls:
        path = os.path.realpath(call["path"])
        if path != base and not path.startswith(base + os.sep):
            continue
        if os.path.isdir(path):
            continue
        rel = os.path.relpath(path, base)
        (opened if call["ok"] else missing)[rel] = None
    return list(opened), [rel for rel in missing if rel not in opened]


def elf_comment(path: Path) -> list[str]:
    """Strings of the ELF .comment section: the compilers that built the file."""
    data = path.read_bytes()
    if data[:4] != b"\x7fELF" or data[4] != 2:
        return []
    endian = "<" if data[5] == 1 else ">"
    shoff = struct.unpack_from(endian + "Q", data, 0x28)[0]
    shentsize, shnum, shstrndx = struct.unpack_from(endian + "HHH", data, 0x3A)
    sections = [struct.unpack_from(endian + "IIQQQQIIQQ", data, shoff + i * shentsize)
                for i in range(shnum)]
    if shstrndx >= len(sections):
        return []
    names_off = sections[shstrndx][4]
    for section in sections:
        name_end = data.index(b"\0", names_off + section[0])
        if data[names_off + section[0]:name_end] == b".comment":
            raw = data[section[4]:section[4] + section[5]]
            return sorted({item.decode("utf-8", "replace") for item in raw.split(b"\0") if item})
    return []


def mednafen_state_vars(state: bytes) -> dict[str, str]:
    """SECTION.VAR -> hex value from a Mednafen MDFNSVST save state."""
    start = state.find(b"MDFNSVST")
    if start < 0:
        return {}
    pos = start + 32
    out: dict[str, str] = {}
    while pos + 36 <= len(state):
        section = state[pos:pos + 32].split(b"\0", 1)[0].decode("ascii", "replace")
        size = struct.unpack_from("<I", state, pos + 32)[0]
        body = state[pos + 36:pos + 36 + size]
        pos += 36 + size
        cursor = 0
        while cursor < len(body):
            name_len = body[cursor]
            name = body[cursor + 1:cursor + 1 + name_len].decode("ascii", "replace")
            cursor += 1 + name_len
            if cursor + 4 > len(body):
                break
            value_len = struct.unpack_from("<I", body, cursor)[0] & 0x7FFFFFFF
            cursor += 4
            out[f"{section}.{name}"] = body[cursor:cursor + value_len].hex()
            cursor += value_len
    return out


def render_printf(fmt: bytes, args: Sequence[int]) -> str:
    """Render a C format string with the integer-class arguments captured.

    Floating-point arguments travel in vector registers, which a ctypes
    callback cannot see: they are shown as <double>.
    """
    text = fmt.decode("utf-8", "replace")
    queue = list(args)
    out: list[str] = []
    last = 0
    for match in PRINTF_SPEC.finditer(text):
        out.append(text[last:match.start()])
        last = match.end()
        conv = match.group("conv")
        if conv == "%":
            out.append("%")
            continue
        for star in (match.group("width"), match.group("prec")):
            if star == "*" and queue:
                queue.pop(0)
        if conv in "eEfFgGaA":
            out.append("<double>")
            continue
        value = queue.pop(0) if queue else 0
        if conv == "s":
            out.append(ctypes.string_at(value).decode("utf-8", "replace") if value else "(null)")
        elif conv == "c":
            out.append(chr(value & 0xFF))
        elif conv == "p":
            out.append(hex(value))
        elif conv in "di":
            bits = 64 if match.group("len") in ("l", "ll", "j", "z", "t") else 32
            value &= (1 << bits) - 1
            out.append(str(value - (1 << bits) if value >> (bits - 1) else value))
        else:
            bits = 64 if match.group("len") in ("l", "ll", "j", "z", "t") else 32
            value &= (1 << bits) - 1
            out.append({"o": f"{value:o}", "x": f"{value:x}", "X": f"{value:X}"}.get(conv, str(value)))
    out.append(text[last:])
    return "".join(out).rstrip("\n")


def uniform_frame(frame: bytes, pixel_bytes: int) -> bool:
    """True for a frame of one colour, an empty one included: a screen that
    shows nothing of the game."""
    if len(frame) <= pixel_bytes:
        return True
    return frame == frame[:pixel_bytes] * (len(frame) // pixel_bytes)


def png_bytes(width: int, height: int, rgb: bytes) -> bytes:
    def chunk(tag: bytes, body: bytes) -> bytes:
        return struct.pack(">I", len(body)) + tag + body + struct.pack(">I", zlib.crc32(tag + body))
    rows = b"".join(b"\0" + rgb[y * width * 3:(y + 1) * width * 3] for y in range(height))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows, 6)) + chunk(b"IEND", b""))


def to_rgb(fmt: int, width: int, height: int, packed: bytes) -> bytes:
    out = bytearray(width * height * 3)
    if fmt == 1:
        out[0::3], out[1::3], out[2::3] = packed[2::4], packed[1::4], packed[0::4]
        return bytes(out)
    for i, (pixel,) in enumerate(struct.iter_unpack("<H", packed)):
        if fmt == 2:
            r, g, b = (pixel >> 11) & 31, (pixel >> 5) & 63, pixel & 31
            out[i * 3:i * 3 + 3] = bytes((r << 3, g << 2, b << 3))
        else:
            r, g, b = (pixel >> 10) & 31, (pixel >> 5) & 31, pixel & 31
            out[i * 3:i * 3 + 3] = bytes((r << 3, g << 3, b << 3))
    return bytes(out)


# --------------------------------------------------------------------------
# libretro bindings (worker side)
# --------------------------------------------------------------------------

class RetroSystemInfo(ctypes.Structure):
    _fields_ = [("library_name", ctypes.c_char_p), ("library_version", ctypes.c_char_p),
                ("valid_extensions", ctypes.c_char_p), ("need_fullpath", ctypes.c_bool),
                ("block_extract", ctypes.c_bool)]


class RetroGameGeometry(ctypes.Structure):
    _fields_ = [("base_width", ctypes.c_uint), ("base_height", ctypes.c_uint),
                ("max_width", ctypes.c_uint), ("max_height", ctypes.c_uint),
                ("aspect_ratio", ctypes.c_float)]


class RetroSystemTiming(ctypes.Structure):
    _fields_ = [("fps", ctypes.c_double), ("sample_rate", ctypes.c_double)]


class RetroSystemAvInfo(ctypes.Structure):
    _fields_ = [("geometry", RetroGameGeometry), ("timing", RetroSystemTiming)]


class RetroGameInfo(ctypes.Structure):
    _fields_ = [("path", ctypes.c_char_p), ("data", ctypes.c_void_p),
                ("size", ctypes.c_size_t), ("meta", ctypes.c_char_p)]


class RetroVariable(ctypes.Structure):
    _fields_ = [("key", ctypes.c_char_p), ("value", ctypes.c_char_p)]


LOG_ARGS = 16
LogFn = ctypes.CFUNCTYPE(None, ctypes.c_int, ctypes.c_char_p, *([ctypes.c_size_t] * LOG_ARGS))


class RetroLogCallback(ctypes.Structure):
    _fields_ = [("log", LogFn)]


EnvFn = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_uint, ctypes.c_void_p)
VideoFn = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint, ctypes.c_size_t)
AudioFn = ctypes.CFUNCTYPE(None, ctypes.c_int16, ctypes.c_int16)
AudioBatchFn = ctypes.CFUNCTYPE(ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t)
PollFn = ctypes.CFUNCTYPE(None)
InputFn = ctypes.CFUNCTYPE(ctypes.c_int16, ctypes.c_uint, ctypes.c_uint, ctypes.c_uint, ctypes.c_uint)


class Frontend:
    """The libretro callbacks for one run."""

    def __init__(self, spec: dict) -> None:
        self.spec = spec
        self.system_dir = spec["system_dir"].encode()
        self.save_dir = spec["save_dir"].encode()
        self.options: dict[bytes, bytes] = {k.encode(): v.encode() for k, v in spec["options"].items()}
        self.defaults: dict[bytes, bytes] = {}
        self.declared: dict[str, list[str]] = {}
        self.option_buffers: list[ctypes.Array] = []
        self.pixel_format = 0
        self.frame = 0
        self.last_frame = b""
        self.last_size = (0, 0)
        self.video = hashlib.sha1()
        self.audio = hashlib.sha1()
        self.frame_hashes: list[list] = []
        self.uniform: set[str] = set()
        self.logs: list[dict] = []
        self.presses: list[tuple[int, int, int]] = [tuple(p) for p in spec["presses"]]
        self.unanswered: dict[int, int] = {}
        self.input_queries = 0
        self.input_pressed = 0
        # What a run showed so far, one JSON line per event, flushed at once:
        # a core that kills the worker leaves its logs and frames behind.
        events = spec.get("events")
        self.events = open(events, "a", encoding="utf-8", buffering=1) if events else None  # noqa: SIM115
        self.callbacks = (
            EnvFn(self.environment), VideoFn(self.video_refresh), AudioFn(self.audio_sample),
            AudioBatchFn(self.audio_batch), PollFn(lambda: None), InputFn(self.input_state),
        )
        self.log_callback = RetroLogCallback(LogFn(self.log))

    def event(self, kind: str, **values: object) -> None:
        if self.events:
            self.events.write(json.dumps({"event": kind, **values}) + "\n")

    def log(self, level: int, fmt: bytes, *args: int) -> None:
        name = LOG_LEVELS[level] if 0 <= level < len(LOG_LEVELS) else str(level)
        line = {"frame": self.frame, "level": name, "text": render_printf(fmt or b"", args)}
        self.logs.append(line)
        self.event("log", **line)

    def environment(self, cmd: int, data: int) -> bool:
        cmd &= ~ENV_EXPERIMENTAL
        if cmd == ENV_GET_CAN_DUPE:
            ctypes.cast(data, ctypes.POINTER(ctypes.c_bool))[0] = True
            return True
        if cmd in (ENV_GET_SYSTEM_DIRECTORY, ENV_GET_SAVE_DIRECTORY):
            value = self.system_dir if cmd == ENV_GET_SYSTEM_DIRECTORY else self.save_dir
            buffer = ctypes.create_string_buffer(value)
            self.option_buffers.append(buffer)
            ctypes.cast(data, ctypes.POINTER(ctypes.c_char_p))[0] = ctypes.cast(buffer, ctypes.c_char_p)
            return True
        if cmd == ENV_SET_PIXEL_FORMAT:
            fmt = ctypes.cast(data, ctypes.POINTER(ctypes.c_int))[0]
            if fmt not in PIXEL_BYTES:
                return False
            self.pixel_format = fmt
            return True
        if cmd == ENV_SET_VARIABLES:
            array = ctypes.cast(data, ctypes.POINTER(RetroVariable))
            index = 0
            while array[index].key:
                key, desc = array[index].key, (array[index].value or b"").decode("utf-8", "replace")
                values = desc.split(";", 1)[-1].strip().split("|")
                self.declared[key.decode()] = values
                self.defaults[key] = values[0].encode()
                index += 1
            return True
        if cmd == ENV_GET_VARIABLE:
            var = ctypes.cast(data, ctypes.POINTER(RetroVariable))[0]
            value = self.options.get(var.key, self.defaults.get(var.key))
            if value is None:
                return False
            buffer = ctypes.create_string_buffer(value)
            self.option_buffers.append(buffer)
            ctypes.cast(data, ctypes.POINTER(RetroVariable))[0].value = ctypes.cast(buffer, ctypes.c_char_p)
            return True
        if cmd == ENV_GET_VARIABLE_UPDATE:
            ctypes.cast(data, ctypes.POINTER(ctypes.c_bool))[0] = False
            return True
        if cmd == ENV_SET_SUPPORT_NO_GAME:
            return True
        if cmd == ENV_GET_LOG_INTERFACE:
            ctypes.cast(data, ctypes.POINTER(RetroLogCallback))[0] = self.log_callback
            return True
        if cmd == ENV_GET_CORE_OPTIONS_VERSION:
            ctypes.cast(data, ctypes.POINTER(ctypes.c_uint))[0] = 0
            return True
        self.unanswered[cmd] = self.unanswered.get(cmd, 0) + 1
        return False

    def video_refresh(self, data: int, width: int, height: int, pitch: int) -> None:
        if data and data != ctypes.c_void_p(-1).value:
            row = width * PIXEL_BYTES[self.pixel_format]
            raw = ctypes.string_at(data, pitch * (height - 1) + row) if height else b""
            self.last_frame = b"".join(raw[y * pitch:y * pitch + row] for y in range(height))
            self.last_size = (width, height)
        self.video.update(struct.pack("<II", *self.last_size) + hashlib.sha1(self.last_frame).digest())
        every = self.spec["frame_hash_every"]
        if every and self.frame % every == 0:
            digest = hashlib.sha1(self.last_frame).hexdigest()
            self.frame_hashes.append([self.frame, digest])
            flat = digest in self.uniform or uniform_frame(self.last_frame, PIXEL_BYTES[self.pixel_format])
            if flat:
                self.uniform.add(digest)
            self.event("frame", frame=self.frame, sha1=digest, uniform=flat)
            png_dir = self.spec.get("png_dir")
            if png_dir and self.last_frame:
                rgb = to_rgb(self.pixel_format, *self.last_size, self.last_frame)
                Path(png_dir, f"frame{self.frame:07d}.png").write_bytes(png_bytes(*self.last_size, rgb))

    def audio_sample(self, left: int, right: int) -> None:
        self.audio.update(struct.pack("<hh", left, right))

    def audio_batch(self, data: int, frames: int) -> int:
        self.audio.update(ctypes.string_at(data, frames * 4))
        return frames

    def input_state(self, port: int, device: int, index: int, button: int) -> int:
        self.input_queries += 1
        if port or device != 1 or index:
            return 0
        held = int(any(start <= self.frame < start + length and button == pressed
                       for start, pressed, length in self.presses))
        self.input_pressed += held
        return held


def run_worker(spec: dict) -> dict:
    """Load the core in this process and run it. Returns the measured result."""
    # Nothing of the host's environment reaches the core: only what --env gave.
    os.environ.clear()
    os.environ.update(spec["env"])
    core = ctypes.CDLL(spec["core"])
    front = Frontend(spec)
    for name, fn in zip(("retro_set_environment", "retro_set_video_refresh", "retro_set_audio_sample",
                         "retro_set_audio_sample_batch", "retro_set_input_poll", "retro_set_input_state"),
                        front.callbacks):
        getattr(core, name)(fn)
    info = RetroSystemInfo()
    core.retro_get_system_info(ctypes.byref(info))
    front.event("info", library_name=info.library_name.decode(), library_version=info.library_version.decode())
    core.retro_init()
    game = None
    if spec.get("content"):
        path = spec["content"].encode()
        game = RetroGameInfo(path, None, 0, None)
        if not info.need_fullpath:
            blob = Path(spec["content"]).read_bytes()
            holder = ctypes.create_string_buffer(blob, len(blob))
            front.option_buffers.append(holder)
            game.data, game.size = ctypes.cast(holder, ctypes.c_void_p), len(blob)
    core.retro_load_game.restype = ctypes.c_bool
    loaded = bool(core.retro_load_game(ctypes.byref(game) if game else None))
    front.event("loaded", value=loaded)
    if not loaded:
        return {"loaded": False, "logs": front.logs, "library_name": info.library_name.decode()}
    # A frontend plugs a joypad into each port after loading, as RetroArch does.
    for port in range(spec["joypad_ports"]):
        core.retro_set_controller_port_device(ctypes.c_uint(port), ctypes.c_uint(1))
    av = RetroSystemAvInfo()
    core.retro_get_system_av_info(ctypes.byref(av))
    warmup, frames = spec["warmup"], spec["frames"]
    for _ in range(warmup):
        core.retro_run()
        front.frame += 1
    started = time.perf_counter()
    for _ in range(frames):
        core.retro_run()
        front.frame += 1
    wall = time.perf_counter() - started
    core.retro_serialize_size.restype = ctypes.c_size_t
    size = core.retro_serialize_size()
    state = b""
    if size:
        buffer = ctypes.create_string_buffer(size)
        core.retro_serialize.restype = ctypes.c_bool
        if core.retro_serialize(buffer, ctypes.c_size_t(size)):
            state = buffer.raw
    if spec.get("state_out"):
        Path(spec["state_out"]).write_bytes(state)
    state_vars = mednafen_state_vars(state)
    observables = {
        "frame_sha1": hashlib.sha1(front.last_frame).hexdigest(),
        "video_sha1": front.video.hexdigest(),
        "audio_sha1": front.audio.hexdigest(),
        "state_sha1": hashlib.sha1(state).hexdigest() if state else None,
    }
    for name in spec["state_vars"]:
        observables[f"state:{name}"] = state_vars.get(name)
    if spec["frame_hash_every"]:
        observables["frame_hashes"] = front.frame_hashes
        observables["uniform_frames"] = sorted(front.uniform)
    core.retro_unload_game()
    core.retro_deinit()
    return {
        "loaded": True,
        "library_name": info.library_name.decode(),
        "library_version": info.library_version.decode(),
        "fps_nominal": av.timing.fps,
        "frames": frames,
        "warmup": warmup,
        "wall_s": wall,
        "observables": observables,
        "logs": front.logs,
        "options_declared": front.declared,
        "env_unanswered": {str(k): v for k, v in sorted(front.unanswered.items())},
        "last_frame_size": list(front.last_size),
        "input_queries": front.input_queries,
        "input_pressed": front.input_pressed,
    }


# --------------------------------------------------------------------------
# Host, core and frontend identity (parent side)
# --------------------------------------------------------------------------

def load_average() -> list[float] | None:
    try:
        return [round(value, 2) for value in os.getloadavg()]
    except OSError:
        return None


def cpu_model() -> str | None:
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        return platform.processor() or None
    return platform.processor() or None


def host_identity() -> dict:
    return {
        "cpu_model": cpu_model(),
        "cpu_count": os.cpu_count(),
        "os": platform.platform(),
        "kernel": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
    }


def frontend_identity() -> dict:
    script = Path(__file__).resolve()
    commit: str | None = None
    dirty: bool | None = None
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                                text=True, check=True).stdout.strip()
        status = subprocess.run(["git", "status", "--porcelain", "--", str(script)], cwd=ROOT,
                                capture_output=True, text=True, check=True).stdout
        dirty = bool(status.strip())
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"WARNING: frontend commit unknown, git failed: {exc}", file=sys.stderr)
    return {"script": "scripts/core_probe.py", "commit": commit, "script_modified": dirty,
            "script_sha256": file_digest(script, "sha256")}


def core_identity(args: argparse.Namespace) -> dict:
    core = Path(args.core)
    identity = {
        "file": core.name,
        "sha256": file_digest(core, "sha256"),
        "repo": args.core_repo,
        "commit": args.core_commit,
        "build_command": args.build_command,
        "compiler": elf_comment(core) or None,
    }
    if args.core_artifact:
        identity["artifact"] = args.core_artifact
    return identity


# --------------------------------------------------------------------------
# Runs (parent side)
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Synthetic:
    """A wrong file made for a negative test: `@zeros:SIZE` is SIZE zero
    bytes, `@head:SIZE:PATH` the first SIZE bytes of PATH."""

    kind: str
    size: int
    source: Path | None = None

    @classmethod
    def parse(cls, text: str) -> Synthetic:
        kind, _, rest = text[1:].partition(":")
        size_text, _, source = rest.partition(":")
        if kind not in ("zeros", "head") or not size_text.isdigit() or (kind == "head") != bool(source):
            raise argparse.ArgumentTypeError(
                f"{text!r}: a made file is @zeros:SIZE or @head:SIZE:PATH")
        return cls(kind, int(size_text), Path(source) if source else None)

    def label(self, dest: str) -> str:
        if self.kind == "zeros":
            return f"{dest}-zeros-{self.size}"
        return f"{dest}-head-{self.size}-of-{self.source.name}"

    def write(self, out: Path) -> None:
        if self.kind == "zeros":
            out.write_bytes(bytes(self.size))
            return
        with self.source.open("rb") as handle:
            out.write_bytes(handle.read(self.size))


@dataclass
class Variant:
    label: str
    files: dict[str, Path | Synthetic | None] = field(default_factory=dict)


def stage_system_dir(base: dict[str, Path], variant: Variant, target: Path) -> dict[str, str | None]:
    """Copy the system files of one variant. Returns dest -> sha1 (None = absent)."""
    target.mkdir(parents=True, exist_ok=True)
    staged: dict[str, str | None] = {}
    for dest, src in {**base, **variant.files}.items():
        out = target / dest
        if src is None:
            out.unlink(missing_ok=True)
            staged[dest] = None
            continue
        out.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(src, Synthetic):
            src.write(out)
        else:
            shutil.copyfile(src, out)
        staged[dest] = file_digest(out)
    return staged


def host_paths_hidden(text: str, places: Sequence[tuple[str, str]]) -> str:
    """A core log line with the probe's own directories named, not spelled.

    Cores print the paths they open. Those paths belong to the host that ran
    the probe and would make two identical runs on two machines differ.
    """
    for prefix, name in places:
        text = text.replace(prefix, name)
    return text


_BWRAP_WORKS: dict[str, bool] = {}


SANDBOX = "bwrap"
# What a core or a build sees of the host, read-only: the system's programs
# and libraries, and the parts of /etc the dynamic loader, fonts, TLS, the
# clock and user lookups read. Nothing else of the tree exists inside.
SANDBOX_SYSTEM = ("/usr", "/lib", "/lib32", "/lib64", "/libx32", "/bin", "/sbin")
SANDBOX_ETC = ("/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/fonts",
               "/etc/ssl", "/etc/ca-certificates", "/etc/localtime", "/etc/nsswitch.conf",
               "/etc/passwd", "/etc/group", "/etc/alternatives")


def _bwrap_base(bwrap: str, network: bool) -> list[str]:
    argv = [bwrap, "--unshare-all", "--die-with-parent", "--new-session"]
    if network:
        argv.append("--share-net")
    for path in SANDBOX_SYSTEM:
        if os.path.islink(path):
            # usrmerge: /lib -> usr/lib is a link, made again inside.
            argv += ["--symlink", os.readlink(path), path]
        elif os.path.isdir(path):
            argv += ["--ro-bind", path, path]
    for path in SANDBOX_ETC:
        argv += ["--ro-bind-try", path, path]
    argv += ["--ro-bind-try", "/sys/devices/system/cpu", "/sys/devices/system/cpu",
             "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/dev/shm", "--tmpfs", "/tmp",
             "--tmpfs", "/mnt", "--tmpfs", str(Path.home())]
    return argv


def _python_prefix(path: Path) -> bool:
    """A Python installation or a venv, and nothing wider: it holds
    lib/pythonX.Y or a pyvenv.cfg, and it is neither / nor the home folder
    nor a folder above it."""
    home = Path.home().resolve()
    resolved = path.resolve()
    if resolved == Path("/") or resolved == home or resolved in home.parents:
        return False
    version = f"python{sys.version_info.major}.{sys.version_info.minor}"
    return (path / "pyvenv.cfg").is_file() or (path / "lib" / version).is_dir()


def interpreter_paths() -> list[Path]:
    """What the worker's Python needs inside the sandbox when the system
    binds do not hold it: CI's setup-python under /opt/hostedtoolcache, a
    venv, pyenv or uv. Without it the worker could not start, and every run
    crashed.

    Only Python installation prefixes are bound whole (sys.prefix,
    sys.base_prefix and the prefix of each link's target, each proven by
    lib/pythonX.Y or pyvenv.cfg). Every link on the way to the interpreter
    is bound as itself, a single file, so ~/.local/bin/python3 never exposes
    ~/.local."""
    system = ("/usr/", "/bin/", "/lib")
    found: list[Path] = []

    def add(path: Path) -> None:
        path = Path(os.path.abspath(path))
        # Inside a tree already bound, a path is there already: bwrap cannot
        # mount over a link in a read-only tree, and the run would not start.
        if any(path == bound or bound in path.parents for bound in found):
            return
        if not str(path).startswith(system) and path.exists():
            found.append(path)

    for prefix in (Path(sys.prefix), Path(sys.base_prefix)):
        if _python_prefix(prefix):
            add(prefix)
    hop = Path(sys.executable)
    for _ in range(16):
        if _python_prefix(hop.parent.parent):
            add(hop.parent.parent)
        if not hop.is_symlink():
            break
        add(hop)
        target = Path(os.readlink(hop))
        hop = target if target.is_absolute() else hop.parent / target
    return found


def sandbox_argv(writable: Sequence[Path], readonly: Sequence[Path] = (),
                 network: bool = False) -> tuple[list[str], str]:
    """The bubblewrap prefix a third-party program runs under, and its name.

    An allowlist: the system's programs and libraries and a few files of
    /etc read-only, an empty home, empty /tmp and /mnt, the `readonly` paths
    (the core, the content, the staged system directory) read-only, and only
    `writable` writable. Every namespace is unshared, the network too unless
    `network` asks for it. Without a working bwrap the returned prefix is
    empty and the name says why, so the caller can refuse to run.
    """
    bwrap = shutil.which("bwrap")
    if not bwrap:
        return [], "environment only: bwrap not found"
    if bwrap not in _BWRAP_WORKS:
        probe_run = subprocess.run(_bwrap_base(bwrap, False) + ["/bin/true"], capture_output=True,
                                   check=False, env={})
        _BWRAP_WORKS[bwrap] = probe_run.returncode == 0
    if not _BWRAP_WORKS[bwrap]:
        return [], "environment only: bwrap cannot create a sandbox here"
    argv = _bwrap_base(bwrap, network)
    for path in readonly:
        # Mounted at the path as the caller names it: a link's own path stays
        # usable inside, its target's bytes behind it.
        resolved, named = Path(path).resolve(), Path(os.path.abspath(path))
        argv += ["--ro-bind", str(resolved), str(named)]
    for path in writable:
        resolved = Path(path).resolve()
        resolved.mkdir(parents=True, exist_ok=True)
        argv += ["--bind", str(resolved), str(resolved)]
    return argv, SANDBOX


def run_group(command: list[str], timeout: float, env: dict[str, str]) -> subprocess.CompletedProcess:
    """Run the worker in a process group of its own and kill the whole group
    when it outlives the timeout. Killing strace alone left a hung core
    spinning, detached from anything that would ever stop it."""
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                          env=env, start_new_session=True) as proc:
        try:
            out, err = proc.communicate(timeout=timeout)
        except BaseException:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate()
            raise
    return subprocess.CompletedProcess(command, proc.returncode, out, err)


WORKER_TRACEBACK = "Traceback (most recent call last)"


def exit_description(returncode: int) -> dict:
    """The status of a worker that died. A signal reaches the probe as a
    negative code, or as 128 + its number through bubblewrap's init."""
    number = -returncode if returncode < 0 else returncode - 128 if 128 < returncode < 160 else 0
    name = None
    if number:
        with contextlib.suppress(ValueError):
            name = signal.Signals(number).name
    return {"status": returncode, "signal": name}


def partial_result(events: Path, spec: dict) -> dict:
    """A repetition rebuilt from the events a worker wrote before it died."""
    lines = []
    if events.is_file():
        for line in events.read_text(encoding="utf-8", errors="replace").splitlines():
            with contextlib.suppress(ValueError):
                lines.append(json.loads(line))
    info = next((e for e in lines if e.get("event") == "info"), {})
    loaded = next((e["value"] for e in lines if e.get("event") == "loaded"), False)
    frames = [e for e in lines if e.get("event") == "frame"]
    result: dict = {
        "loaded": bool(loaded),
        "library_name": info.get("library_name", ""),
        "logs": [{k: e[k] for k in ("frame", "level", "text")} for e in lines if e.get("event") == "log"],
    }
    if info.get("library_version"):
        result["library_version"] = info["library_version"]
    if spec["frame_hash_every"]:
        result["observables"] = {
            "frame_hashes": [[e["frame"], e["sha1"]] for e in frames],
            "uniform_frames": sorted({e["sha1"] for e in frames if e.get("uniform")}),
        }
    return result


def run_once(args: argparse.Namespace, system_dir: Path, scratch: Path, state_out: Path | None,
             png_dir: Path | None) -> dict:
    save_dir = scratch / "save"
    save_dir.mkdir(parents=True, exist_ok=True)
    spec = {
        "core": str(Path(args.core).resolve()),
        "content": str(Path(args.content).resolve()) if args.content else None,
        "system_dir": str(system_dir.resolve()),
        "save_dir": str(save_dir.resolve()),
        "options": dict(args.option),
        "frames": args.frames,
        "warmup": args.warmup,
        "presses": [list(p) for p in args.press],
        "state_vars": args.state_var,
        "frame_hash_every": args.frame_hash_every,
        "joypad_ports": args.joypad_ports,
        "png_dir": str(png_dir) if png_dir else None,
        "state_out": str(state_out) if state_out else None,
        "env": dict(args.env),
        "events": str((scratch / "events.jsonl").resolve()),
    }
    spec_path, out_path, trace_path = scratch / "spec.json", scratch / "result.json", scratch / "strace.txt"
    spec_path.write_text(json.dumps(spec), encoding="utf-8")
    command = [sys.executable, "-I", str(Path(__file__).resolve()), "_worker", str(spec_path), str(out_path)]
    strace = shutil.which("strace") if not args.no_trace else None
    if strace:
        command = [strace, "-f", "-qq", "-s", "4096", "-e", "trace=openat,open", "-o", str(trace_path)] + command
    writable = [scratch] + [p for p in (png_dir, state_out.parent if state_out else None) if p]
    readonly = [Path(__file__), Path(args.core), system_dir, *interpreter_paths()]
    if args.content:
        readonly.append(Path(args.content).resolve().parent)
    readonly += [Path(part) for _, value in args.env for part in value.replace(":", " ").split()
                 if Path(part).is_absolute() and Path(part).exists()]
    prefix, isolation = sandbox_argv(writable, readonly)
    if args.require_sandbox and isolation != SANDBOX:
        raise ProbeError(f"refused to run the core outside a sandbox: {isolation}")
    # The core sees the variables it was given and nothing of the host's.
    try:
        proc = run_group(prefix + command, args.timeout, dict(args.env))
    except subprocess.TimeoutExpired:
        result = partial_result(scratch / "events.jsonl", spec)
        result["exit"] = {"status": None, "signal": "SIGKILL", "timeout_s": args.timeout}
    else:
        if proc.returncode == 0 and out_path.exists():
            result = json.loads(out_path.read_text(encoding="utf-8"))
        elif WORKER_TRACEBACK in proc.stderr:
            # The probe's own code failed: no verdict on the core is drawn.
            raise ProbeError(f"worker exited {proc.returncode}: {proc.stderr.strip()[-2000:]}")
        else:
            result = partial_result(scratch / "events.jsonl", spec)
            result["exit"] = exit_description(proc.returncode)
    places = [(str(system_dir.resolve()), "<system>"), (str(save_dir.resolve()), "<save>")]
    if args.content:
        folder = Path(args.content).resolve().parent
        # MAME prints the folder above the content's too ("Parent path").
        places.append((str(folder), "<content>"))
        if folder.parent != folder.parent.parent:
            places.append((str(folder.parent), "<content>/.."))
    places.append((str(ROOT), "<repo>"))
    for line in result.get("logs", []):
        line["text"] = host_paths_hidden(line["text"], places)
    if strace:
        opened, probed = files_under(parse_strace(trace_path.read_text(encoding="utf-8", errors="replace")),
                                     system_dir)
        result["files_opened"] = [{"path": rel, "sha1_after": file_digest(system_dir / rel)}
                                  for rel in opened if (system_dir / rel).is_file()]
        result["files_probed_absent"] = probed
        result["tracing"] = "strace"
    else:
        result["files_opened"] = None
        result["files_probed_absent"] = None
        result["tracing"] = "unavailable: strace not found" if not args.no_trace else "disabled: --no-trace"
    if result.get("wall_s") and result.get("frames"):
        result["ms_per_frame"] = result["wall_s"] * 1000 / result["frames"]
        result["fps"] = result["frames"] / result["wall_s"]
    result["isolation"] = isolation
    return result


def timing_stats(values: Sequence[float]) -> dict:
    return {
        "median": statistics.median(values),
        "mean": statistics.fmean(values),
        "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
        "min": min(values),
        "max": max(values),
        "raw": list(values),
    }


def run_variant(args: argparse.Namespace, base: dict[str, Path], variant: Variant,
                work: Path, repetitions: int) -> dict:
    system_dir = work / "system"
    staged = stage_system_dir(base, variant, system_dir)
    reps: list[dict] = []
    flags: list[str] = []
    for index in range(repetitions):
        scratch = work / f"rep{index}"
        scratch.mkdir(parents=True, exist_ok=True)
        png_dir = None
        if args.png_dir and index == 0:
            png_dir = Path(args.png_dir) / variant.label
            png_dir.mkdir(parents=True, exist_ok=True)
        state_out = Path(args.state_dir) / f"{variant.label}.state" if args.state_dir and index == 0 else None
        if state_out:
            state_out.parent.mkdir(parents=True, exist_ok=True)
        rep = run_once(args, system_dir, scratch, state_out, png_dir)
        oracle = oracle_for(args.oracle_data, args.content_sha1, rep.get("library_name"))
        judge_repetition(rep, oracle)
        if rep.get("exit"):
            flags.append(f"repetition {index}: {rep['verdict_evidence']['detail']}")
        if not rep.get("loaded"):
            flags.append(f"repetition {index}: retro_load_game returned false")
        for entry in rep.get("files_opened") or []:
            expected = staged.get(entry["path"])
            entry["sha1_staged"] = expected
            if expected is not None and expected != entry["sha1_after"]:
                flags.append(f"repetition {index}: {entry['path']} sha1 changed during the run")
        reps.append(rep)
    reference = reps[0].get("observables")
    for index, rep in enumerate(reps[1:], 1):
        if rep.get("observables") != reference:
            differing = sorted(k for k in (reference or {}) if (rep.get("observables") or {}).get(k) != reference[k])
            flags.append(f"repetition {index} disagrees with repetition 0 on {', '.join(differing)}")
    out = {
        "label": variant.label,
        "system_files": {dest: sha for dest, sha in sorted(staged.items())},
        "repetitions": reps,
        "flags": flags,
    }
    judge_variant(out)
    return out


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     fromfile_prefix_chars="@")
    sub = parser.add_subparsers(dest="mode", required=True)
    common = argparse.ArgumentParser(add_help=False, allow_abbrev=False, fromfile_prefix_chars="@")
    common.add_argument("--core", required=True, help="libretro .so to load")
    common.add_argument("--content", help="content to load (a .cue is identified with its tracks)")
    common.add_argument("--content-label", help="identity of the content, e.g. its Redump name")
    common.add_argument("--system-file", action="append", default=[], metavar="DEST=SRC",
                        type=lambda t: parse_assignment(t, "--system-file"),
                        help="copy SRC into the staged system dir as DEST")
    common.add_argument("--option", action="append", default=[], metavar="KEY=VALUE",
                        type=lambda t: parse_assignment(t, "--option"), help="core option")
    common.add_argument("--env", action="append", default=[], metavar="KEY=VALUE",
                        type=lambda t: parse_assignment(t, "--env"),
                        help="environment variable for the core process, e.g. LD_PRELOAD of a fixed clock")
    common.add_argument("--frames", type=int, default=600, help="frames timed after warm-up")
    common.add_argument("--warmup", type=int, default=0, help="frames run before timing starts")
    common.add_argument("--press", action="append", default=[], type=parse_press,
                        metavar="FRAME:BUTTON[:LEN]", help="hold a joypad button on port 0")
    common.add_argument("--joypad-ports", type=int, default=2, metavar="N",
                        help="ports given a joypad after loading (default 2)")
    common.add_argument("--state-var", action="append", default=[], metavar="SECTION.VAR",
                        help="report a Mednafen save-state variable as an observable")
    common.add_argument("--frame-hash-every", type=int, default=0, metavar="K",
                        help="record the sha1 of every K-th frame")
    common.add_argument("--png-dir", help="write the frames sampled by --frame-hash-every as PNG")
    common.add_argument("--state-dir", help="write the save state at the end of the first repetition")
    common.add_argument("--core-repo", help="source repository URL of the core build")
    common.add_argument("--core-commit", help="commit the core was built from")
    common.add_argument("--build-command", help="command and flags that built the core")
    common.add_argument("--core-artifact", metavar="URL",
                        help="where the .so was downloaded from, such as a buildbot nightly")
    common.add_argument("--record", metavar="DIR", nargs="?", const=str(ROOT),
                        help="append the record as one line of measurements/<emulator>.jsonl "
                             "in the checkout DIR (default: this one)")
    common.add_argument("--emulator", help="profile the record is filed under (default: the "
                                           "profile whose cores: names the .so, else the "
                                           "core's library name)")
    common.add_argument("--subject", help="slug naming what the record tests, shared by its "
                                          "reruns (default: derived from the claim and method, "
                                          "or from the inputs of a run or bench)")
    common.add_argument("--supersedes", metavar="ID",
                        help="id of an earlier record of the same emulator this one corrects")
    common.add_argument("--max-load", type=float, default=None,
                        help="refuse to record when the 1-minute load average exceeds this "
                             "(default: a quarter of the CPU count)")
    common.add_argument("--work-dir", default=str(DEFAULT_WORK_DIR), help="scratch directory")
    common.add_argument("--timeout", type=int, default=1800,
                        help="seconds per repetition, after which the run is killed and judged a hang")
    common.add_argument("--oracle", default=None, metavar="FILE",
                        help="reference frames and error patterns the verdicts are judged against "
                             "(default: tests/campaign/oracle.yml)")
    common.add_argument("--no-trace", action="store_true", help="do not run the worker under strace")
    common.add_argument("--require-sandbox", action="store_true",
                        help="refuse to run the core unless bubblewrap can isolate it")

    run = sub.add_parser("run", parents=[common], help="one execution")
    run.add_argument("--repeat", type=int, default=1,
                     help="runs, each in a fresh process: the verdict is the one they all agree on")
    bench = sub.add_parser("bench", parents=[common], help="timed repetitions")
    bench.add_argument("--repeat", type=int, default=MIN_BENCH_REPETITIONS,
                       help=f"timed repetitions, each in a fresh process (at least {MIN_BENCH_REPETITIONS} to record)")
    check = sub.add_parser("check", parents=[common], help="compare variants of a system file")
    check.add_argument("--vary", action="append", required=True, metavar="DEST=SRC",
                       type=lambda t: parse_assignment(t, "--vary"),
                       help="one variant per occurrence; an empty SRC leaves DEST absent")
    check.add_argument("--observable", required=True,
                       help="the observable compared across variants")
    check.add_argument("--claim", required=True, help="the statement under test")
    check.add_argument("--method", required=True, help="how the run tests it")
    check.add_argument("--repeat", type=int, default=2, help="runs of each variant, each in a fresh process")
    rejudge = sub.add_parser("rejudge", help="judge recorded runs again against the current oracle, "
                                               "offline: no core runs")
    rejudge.add_argument("--record", metavar="DIR", default=str(ROOT),
                         help="the checkout whose measurements/ are judged again (default: this one)")
    rejudge.add_argument("--emulator", action="append", default=[],
                         help="only these emulators' records (default: every one)")
    rejudge.add_argument("--oracle", default=None, metavar="FILE",
                         help="the oracle to judge against (default: tests/campaign/oracle.yml)")
    rejudge.add_argument("--dry-run", action="store_true",
                         help="print what would be appended, write nothing")
    worker = sub.add_parser("_worker", help="internal: one run in this process, started by the others")
    worker.add_argument("spec", help="JSON file describing the run")
    worker.add_argument("out", help="JSON file the result is written to")
    return parser


def not_a_checkout_root(directory: Path) -> str | None:
    """Why --record DIR is refused, or None. DIR is the checkout, never its
    measurements/ folder: that wrote measurements/measurements/<emulator>.jsonl."""
    form = "--record names the root of a git checkout (the folder holding measurements/), e.g. --record ."
    if not (directory / ".git").exists():
        return f"--record {directory}: not a git checkout root. {form}"
    proc = subprocess.run(["git", "-C", str(directory), "rev-parse", "--show-toplevel"],
                          capture_output=True, text=True, check=False)
    top = proc.stdout.strip()
    if proc.returncode != 0 or not top or Path(top).resolve() != directory.resolve():
        return f"--record {directory}: not a git checkout root (its root is {top or 'unknown'}). {form}"
    return None


def validate_args(args: argparse.Namespace) -> list[str]:
    problems: list[str] = []
    if not Path(args.core).is_file():
        problems.append(f"--core {args.core}: not a file")
    if args.content and not Path(args.content).is_file():
        problems.append(f"--content {args.content}: not a file")
    for dest, src in args.system_file:
        if not Path(src).is_file():
            problems.append(f"--system-file {dest}={src}: not a file")
    if args.repeat < 1:
        problems.append("--repeat must be >= 1")
    if args.frames < 1 or args.warmup < 0:
        problems.append("--frames must be >= 1 and --warmup >= 0")
    if args.require_sandbox:
        isolation = sandbox_argv([])[1]
        if isolation != SANDBOX:
            problems.append(f"--require-sandbox: {isolation}")
    for key, value in args.env:
        if key != "LD_PRELOAD":
            continue
        # A library the loader cannot find is skipped without a word, and
        # the run would record a fixed clock it never had. Only a file that
        # exists is bound into the sandbox and recorded by sha256.
        for library in value.replace(":", " ").split():
            if not (Path(library).is_absolute() and Path(library).is_file()):
                problems.append(f"--env LD_PRELOAD: {library} is not an absolute path to a file")
    if args.oracle and not Path(args.oracle).is_file():
        problems.append(f"--oracle {args.oracle}: not a file")
    if args.png_dir and not args.frame_hash_every:
        problems.append("--png-dir needs --frame-hash-every")
    if args.record:
        wrong = not_a_checkout_root(Path(args.record))
        if wrong:
            problems.append(wrong)
        if not args.emulator and Path(args.core).is_file():
            try:
                default_emulator(Path(args.core), None)
            except ProbeError as exc:
                problems.append(str(exc))
    if (args.subject or args.supersedes or args.emulator) and not args.record:
        problems.append("--emulator, --subject and --supersedes need --record")
    for flag, value in (("--subject", args.subject), ("--emulator", args.emulator)):
        if value and not re.fullmatch(r"[a-z0-9]+(?:[-_][a-z0-9]+)*", value):
            problems.append(f"{flag} {value!r}: lowercase letters, digits, - and _ only")
    if args.mode == "bench" and args.record and args.repeat < MIN_BENCH_REPETITIONS:
        problems.append(f"a recorded benchmark needs --repeat >= {MIN_BENCH_REPETITIONS}")
    if args.mode == "check":
        dests = {dest for dest, _ in args.vary}
        if len(dests) != 1:
            problems.append("--vary must name the same DEST in every occurrence")
        for dest, src in args.vary:
            if src.startswith("@"):
                try:
                    made = Synthetic.parse(src)
                except argparse.ArgumentTypeError as exc:
                    problems.append(f"--vary {dest}: {exc}")
                    continue
                if made.source and not made.source.is_file():
                    problems.append(f"--vary {dest}={src}: {made.source} is not a file")
            elif src and not Path(src).is_file():
                problems.append(f"--vary {dest}={src}: not a file")
        names = set(BASE_OBSERVABLES) | {f"state:{v}" for v in args.state_var}
        if args.frame_hash_every:
            names.update(("frame_hashes", "uniform_frames"))
        if args.observable not in names:
            problems.append(f"--observable {args.observable}: not one of {', '.join(sorted(names))}")
    return problems


def variants_for(args: argparse.Namespace) -> list[Variant]:
    if args.mode != "check":
        return [Variant("default")]
    out: list[Variant] = []
    seen: set[str] = set()
    for dest, src in args.vary:
        made = Synthetic.parse(src) if src.startswith("@") else None
        label = made.label(dest) if made else Path(src).name if src else f"{dest}-absent"
        while label in seen:
            label += "+"
        seen.add(label)
        out.append(Variant(label, {dest: made or (Path(src) if src else None)}))
    return out


def unsettled(variant: dict, observable: str) -> bool:
    """True when a variant cannot vouch for one value of the observable.

    A repetition that did not load, a file changed during the run, or two
    repetitions that disagree on this observable. A disagreement on another
    observable stays in the variant's flags without voiding this one.
    """
    reps = variant["repetitions"]
    if any(not rep.get("loaded") for rep in reps):
        return True
    if any("changed during the run" in flag for flag in variant["flags"]):
        return True
    values = {json.dumps((rep.get("observables") or {}).get(observable), sort_keys=True) for rep in reps}
    return len(values) > 1


def check_result(variants: list[dict], observable: str) -> dict:
    groups: dict[str, list[str]] = {}
    failed = [v["label"] for v in variants if unsettled(v, observable)]
    for variant in variants:
        value = (variant["repetitions"][0].get("observables") or {}).get(observable)
        groups.setdefault(json.dumps(value, sort_keys=True), []).append(variant["label"])
    if failed:
        status = "inconclusive"
        statement = (f"{observable} is not settled in {len(failed)} of {len(variants)} variants "
                     f"({', '.join(failed)}): no comparison is drawn")
    elif len(groups) == 1:
        status = "same"
        statement = f"{observable} is identical across all {len(variants)} variants"
    else:
        status = "differs"
        statement = f"{observable} takes {len(groups)} distinct values across {len(variants)} variants"
    other = sorted({v["label"] for v in variants if v["flags"]} - set(failed))
    if other:
        statement += f". Other flags, in {len(other)} variants, are listed with them"
    return {
        "status": status,
        "statement": statement,
        "groups": [{"value": json.loads(key), "variants": labels} for key, labels in groups.items()],
    }


# --------------------------------------------------------------------------
# Boot oracle: what a run reached, from positive evidence
# --------------------------------------------------------------------------

BOOTS, BIOS_ERROR, CRASH, HANG, UNKNOWN = "boots", "bios_error", "crash", "hang", "unknown"
VERDICTS = (BOOTS, BIOS_ERROR, CRASH, HANG, UNKNOWN)
DEFAULT_ORACLE = ROOT / "tests" / "campaign" / "oracle.yml"


def oracle_for(data: dict, content_sha1: str | None, library_name: str | None) -> dict:
    """The oracle entries that judge one content on one core: its reference
    frames, the error patterns every core shares and the core's own, the
    core's known error screens, and the log lines by which it says it loaded
    the console's own BIOS."""
    core = (data.get("cores") or {}).get(library_name or "") or {}
    references: list[dict] = []
    for item in data.get("content") or ():
        if content_sha1 and item.get("sha1") == content_sha1:
            block = (item.get("references") or {}).get(library_name or "") or {}
            references = [{"sha1": f["sha1"], "stage": f["stage"], "shows": f["shows"]}
                          for f in block.get("frames") or ()]
    patterns = [p["pattern"] for p in (data.get("error_patterns") or ())]
    patterns += [p["pattern"] for p in core.get("error_patterns") or ()]
    screens = [{"sha1": s["sha1"], "shows": s["shows"]} for s in core.get("error_screens") or ()]
    loaded = [p["pattern"] for p in core.get("bios_patterns") or ()]
    return {"references": references, "error_patterns": patterns, "error_screens": screens,
            "bios_patterns": loaded,
            "fallback_patterns": [p["pattern"] for p in core.get("fallback_patterns") or ()],
            "load_patterns": [p["pattern"] for p in core.get("load_patterns") or ()]}


def sampled(rep: dict) -> list[tuple[int, str]]:
    observables = rep.get("observables") or {}
    return [(int(frame), digest) for frame, digest in observables.get("frame_hashes") or ()]


def judge(rep: dict, oracle: dict) -> tuple[str, dict]:
    """The verdict of one repetition and the evidence that decided it.

    In order: a worker killed after the timeout is a hang and one that died
    a crash, from the process status. A reference frame of the game reached
    is a boot: the console's own screens alone are not. Without one, an error pattern of the core log or a known error screen
    is a BIOS error. Every sampled frame of the second half one colour is a
    hang. Anything else is unknown: a run is never called a boot because
    its frames differ from another run's.
    """
    ended = rep.get("exit")
    if ended and ended.get("timeout_s") is not None:
        return HANG, {"rule": "timeout", "detail": f"killed after {ended['timeout_s']} s",
                      "exit_status": ended.get("status"), "signal": ended.get("signal")}
    if ended:
        how = f"signal {ended['signal']}" if ended.get("signal") else f"exit status {ended.get('status')}"
        return CRASH, {"rule": "exit_status", "detail": f"the worker died: {how}",
                       "exit_status": ended.get("status"), "signal": ended.get("signal")}
    frames = sampled(rep)
    final = (rep.get("observables") or {}).get("frame_sha1")
    if final:
        frames.append((int(rep.get("frames", 0)) + int(rep.get("warmup", 0)), final))
    references = {r["sha1"]: r for r in oracle.get("references") or ()}
    reached = [(frame, digest) for frame, digest in frames if digest in references]
    stages = list(dict.fromkeys(references[d]["stage"] for _, d in reached))
    # A core that hides the BIOS screens by default still says it loaded one.
    if "bios" not in stages and any(re.search(pattern, line["text"])
                                    for pattern in oracle.get("bios_patterns") or ()
                                    for line in rep.get("logs") or ()):
        stages.insert(0, "bios")
    game = [(frame, digest) for frame, digest in reached if references[digest]["stage"] == "game"]
    if game:
        frame, digest = game[0]
        return BOOTS, {"rule": "reference_frame",
                       "detail": f"frame {frame} shows {references[digest]['shows']}",
                       "frame": frame, "sha1": digest, "stages": stages}
    verdict, evidence = _without_the_game(rep, oracle, frames)
    if stages:
        # The console's own screens without one of the game: never a boot.
        evidence["stages"] = stages
        evidence["detail"] += ", after the BIOS screens and no screen of the game"
    return verdict, evidence


def _without_the_game(rep: dict, oracle: dict, frames: list[tuple[int, str]]) -> tuple[str, dict]:
    """The verdict of a run that reached no screen of the game."""
    for pattern in oracle.get("error_patterns") or ():
        for line in rep.get("logs") or ():
            if re.search(pattern, line["text"]):
                return BIOS_ERROR, {"rule": "error_pattern",
                                    "detail": f"the core logged an error at frame {line['frame']}",
                                    "pattern": pattern, "log": line["text"], "frame": line["frame"]}
    screens = {s["sha1"]: s for s in oracle.get("error_screens") or ()}
    for frame, digest in frames:
        if digest in screens:
            return BIOS_ERROR, {"rule": "error_screen",
                                "detail": f"frame {frame} shows {screens[digest]['shows']}",
                                "frame": frame, "sha1": digest}
    if not rep.get("loaded"):
        return UNKNOWN, {"rule": "no_evidence",
                         "detail": "retro_load_game returned false and no error pattern matched"}
    uniform = set((rep.get("observables") or {}).get("uniform_frames") or ())
    tail = [digest for frame, digest in sampled(rep)][len(sampled(rep)) // 2:]
    if tail and all(digest in uniform for digest in tail):
        return HANG, {"rule": "uniform_tail",
                      "detail": f"the last {len(tail)} sampled frames are one colour each"}
    if not oracle.get("references"):
        return UNKNOWN, {"rule": "no_evidence", "detail": "no reference frame is known for this "
                                                          "content on this core"}
    return UNKNOWN, {"rule": "no_evidence", "detail": "no reference frame reached, no error pattern "
                                                      "and no error screen"}


BUILTIN = "builtin"
SYSTEM_PLACE = "<system>/"


def bios_used(rep: dict, oracle: dict) -> tuple[str, str | None]:
    """Which BIOS the core ran, from its log, and the line that says so.

    `staged:<dest>` when a load pattern names the file under the system
    directory, `builtin` when a fallback pattern says the core went to its
    own BIOS (OpenBIOS, HLE), `unknown` otherwise. The last such line wins:
    a core that tries a file and then falls back logs both, in that order.
    A file the core opened is no proof: Beetle PSX hashes every file of the
    folder before it decides.
    """
    found: tuple[str, str | None] = ("unknown", None)
    for line in rep.get("logs") or ():
        text = line["text"]
        if any(re.search(pattern, text) for pattern in oracle.get("fallback_patterns") or ()):
            found = (BUILTIN, text)
        for pattern in oracle.get("load_patterns") or ():
            match = re.search(pattern, text)
            path = match.groupdict().get("path") if match else None
            if path:
                found = (f"staged:{path.removeprefix(SYSTEM_PLACE)}", text)
    return found


def judge_repetition(rep: dict, oracle: dict) -> None:
    """The verdict, its evidence and the BIOS used, written into the repetition."""
    verdict, evidence = judge(rep, oracle)
    used, line = bios_used(rep, oracle)
    if line:
        evidence["bios_log"] = line
    if verdict == BOOTS and used == BUILTIN:
        evidence["detail"] += ", on the core's built-in BIOS"
    rep["verdict"], rep["verdict_evidence"], rep["bios_used"] = verdict, evidence, used


def judge_variant(variant: dict) -> None:
    """The variant's verdict and BIOS: what every repetition agrees on."""
    reps = variant["repetitions"]
    variant["verdict"], variant["verdict_evidence"] = variant_verdict(reps)
    used = {rep.get("bios_used", "unknown") for rep in reps}
    variant["bios_used"] = used.pop() if len(used) == 1 else "unknown"


def variant_verdict(reps: Sequence[dict]) -> tuple[str, dict]:
    """The verdict all repetitions agree on, else unknown."""
    verdicts = [rep["verdict"] for rep in reps]
    if len(set(verdicts)) == 1:
        first = reps[0]["verdict_evidence"]
        evidence = {"rule": "repetitions_agree",
                    "detail": f"{len(reps)} of {len(reps)} repetitions: {first['detail']}",
                    "repetitions": verdicts}
        for key in ("frame", "sha1", "stages", "pattern", "log", "exit_status", "signal", "bios_log"):
            if key in first:
                evidence[key] = first[key]
        return verdicts[0], evidence
    return UNKNOWN, {"rule": "repetitions_disagree",
                     "detail": f"the repetitions disagree: {', '.join(verdicts)}",
                     "repetitions": verdicts}


def load_oracle(path: Path | None) -> tuple[dict, dict | None]:
    """The oracle file's data and its identity, or nothing without a file."""
    if path is None or not path.is_file():
        return {}, None
    import yaml  # noqa: PLC0415

    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    try:
        shown = path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        shown = path.name
    return data, {"file": shown, "sha256": file_digest(path, "sha256")}


def default_emulator(core_file: Path, library_name: str | None) -> str:
    """The profile whose cores: names the .so, else the library name as a slug."""
    stem = core_file.name.split(".")[0].removesuffix("_libretro")
    sys.path.insert(0, str(ROOT / "scripts"))
    from common import load_emulator_profiles  # noqa: PLC0415

    owners = sorted(key for key, profile in load_emulator_profiles(str(ROOT / "emulators")).items()
                    if stem == key or stem in (profile.get("cores") or []))
    if len(owners) == 1:
        return owners[0]
    if len(owners) > 1:
        raise ProbeError(f"{core_file.name}: profiles {', '.join(owners)} all name core "
                         f"{stem}, pass --emulator")
    slug = re.sub(r"[^a-z0-9]+", "_", (library_name or stem).lower()).strip("_")
    return slug or "core"


def default_subject(record: dict) -> str:
    """A slug shared by the reruns of one test: a check by its claim and
    method, a run or bench by its inputs."""
    from measurement_records import canonical, sha256_hex, slugify  # noqa: PLC0415

    check = record.get("check")
    if check:
        digest = sha256_hex(canonical([check["claim"], check["method"], check["observable"],
                                       check["variable"]]))[:8]
        return f"{slugify(check['claim'])}-{digest}"
    inputs = {k: v for k, v in record["inputs"].items() if k != "repetitions"}
    content = (record["inputs"].get("content") or {}).get("label") or "no content"
    digest = sha256_hex(canonical([record["core"]["sha256"], inputs]))[:8]
    return f"{record['kind']}-{slugify(content, 30)}-{digest}"


def write_record(directory: Path, full: dict) -> tuple[Path, dict]:
    """Append the record, with its id, to its emulator's .jsonl. Returns the
    file and the record as written."""
    from measurement_records import line_text, parse_lines, records_path, seal  # noqa: PLC0415

    sealed = seal(full)
    lines = directory / records_path(sealed["emulator"])
    existing = parse_lines(lines.read_text(encoding="utf-8"), str(lines)) if lines.is_file() else []
    if sealed["supersedes"] and sealed["supersedes"] not in {r["id"] for r in existing}:
        raise ProbeError(f"--supersedes {sealed['supersedes']}: no such record in {lines}")
    lines.parent.mkdir(parents=True, exist_ok=True)
    with lines.open("a", encoding="utf-8") as handle:
        handle.write(line_text(sealed) + "\n")
    return lines, sealed


def probe(args: argparse.Namespace) -> int:
    problems = validate_args(args)
    if problems:
        for problem in problems:
            print(f"ERROR: {problem}", file=sys.stderr)
        return 2
    with host_probe_lock():
        return _probe(args)


def _probe(args: argparse.Namespace) -> int:
    max_load = args.max_load if args.max_load is not None else (os.cpu_count() or 1) / 4
    load_before = load_average()
    if args.record and load_before and load_before[0] > max_load:
        print(f"ERROR: load average {load_before[0]} exceeds {max_load}: the machine is busy, "
              f"nothing recorded (raise --max-load to override)", file=sys.stderr)
        return 3
    repetitions = args.repeat
    base = {dest: Path(src) for dest, src in args.system_file}
    args.oracle_data, oracle_identity = load_oracle(Path(args.oracle) if args.oracle else DEFAULT_ORACLE)
    args.content_sha1 = file_digest(Path(args.content)) if args.content else None
    work = Path(tempfile.mkdtemp(prefix=f"{args.mode}-", dir=_ensure(Path(args.work_dir))))
    try:
        variants = [run_variant(args, base, variant, work / f"v{i}", repetitions)
                    for i, variant in enumerate(variants_for(args))]
    except (ProbeError, subprocess.TimeoutExpired) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        shutil.rmtree(work, ignore_errors=True)
    load_after = load_average()
    first = variants[0]["repetitions"][0]
    from measurement_records import RECORD_VERSION  # noqa: PLC0415

    record: dict = {
        "record_version": RECORD_VERSION,
        "emulator": None,
        "subject": None,
        "supersedes": args.supersedes,
        "kind": args.mode,
        "recorded_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "core": {**core_identity(args), "library_name": first.get("library_name"),
                 "library_version": first.get("library_version")},
        "frontend": frontend_identity(),
        "host": {**host_identity(), "load_before": load_before, "load_after": load_after,
                 "max_load": max_load},
        "inputs": {
            "content": content_identity(Path(args.content), args.content_label) if args.content else None,
            "options": dict(args.option),
            "env": {key: describe_env_value(value) for key, value in args.env},
            "frames": args.frames,
            "warmup": args.warmup,
            "repetitions": repetitions,
            "presses": [{"frame": f, "button": b, "length": n} for f, b, n in args.press],
            "observables": list(BASE_OBSERVABLES) + [f"state:{v}" for v in args.state_var]
                           + (["frame_hashes", "uniform_frames"] if args.frame_hash_every else []),
            "frame_hash_every": args.frame_hash_every,
            "joypad_ports": args.joypad_ports,
            "oracle": ({**oracle_identity, **oracle_for(args.oracle_data, args.content_sha1,
                                                          first.get("library_name"))}
                       if oracle_identity else None),
        },
        "variants": variants,
        "flags": [f"{v['label']}: {flag}" for v in variants for flag in v["flags"]],
    }
    if load_before and load_after and max(load_before[0], load_after[0]) > max_load:
        record["flags"].append(f"load average reached {max(load_before[0], load_after[0])} "
                               f"(threshold {max_load})")
    if args.mode == "bench":
        reps = variants[0]["repetitions"]
        record["timing"] = {"ms_per_frame": timing_stats([r["ms_per_frame"] for r in reps if "ms_per_frame" in r]),
                            "fps": timing_stats([r["fps"] for r in reps if "fps" in r])}
    if args.mode == "check":
        record["check"] = {"claim": args.claim, "method": args.method, "observable": args.observable,
                           "variable": args.vary[0][0],
                           "result": {**check_result(variants, args.observable),
                                      "verdicts": {v["label"]: v["verdict"] for v in variants}}}
    try:
        record["emulator"] = args.emulator or default_emulator(Path(args.core), first.get("library_name"))
    except ProbeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    record["subject"] = args.subject or default_subject(record)
    if args.record:
        try:
            lines, record = write_record(Path(args.record), record)
        except ProbeError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        print(f"recorded {lines} (line {sum(1 for _ in lines.open(encoding='utf-8'))})",
              file=sys.stderr)
    print(json.dumps(record, indent=2, sort_keys=False))
    return 0


def _ensure(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def rejudged(record: dict, data: dict, identity: dict | None, now: str) -> dict | None:
    """The record judged again from its own runs, superseding it, or None
    when the judgement it carries is the one the oracle gives now.

    Nothing of the runs changes: logs, frames, files and timings are the
    record's. The verdicts, their evidence, bios_used and inputs.oracle are
    computed again, and judged_at and judged_by say when and by what.
    """
    import copy  # noqa: PLC0415

    # Another probe (standalone_probe, pack_probe) judges with its own rules.
    if record.get("record_version", 0) < 4 or record["frontend"].get("script") != "scripts/core_probe.py":
        return None
    out = copy.deepcopy(record)
    content_sha1 = ((out["inputs"].get("content") or {}).get("sha1"))
    for variant in out["variants"]:
        for rep in variant["repetitions"]:
            judge_repetition(rep, oracle_for(data, content_sha1, rep.get("library_name")))
        judge_variant(variant)
    first = out["variants"][0]["repetitions"][0]
    out["inputs"]["oracle"] = ({**identity, **oracle_for(data, content_sha1, first.get("library_name"))}
                               if identity else None)
    if out.get("check"):
        out["check"]["result"]["verdicts"] = {v["label"]: v["verdict"] for v in out["variants"]}

    def judgement(item: dict) -> list:
        return [[v.get("verdict"), v.get("verdict_evidence"), v.get("bios_used"),
                 [[r.get("verdict"), r.get("verdict_evidence"), r.get("bios_used")] for r in v["repetitions"]]]
                for v in item["variants"]]
    if record.get("record_version") == RECORD_VERSION_NOW() and judgement(out) == judgement(record):
        return None
    for key in ("id", "migrated_from_version"):
        out.pop(key, None)
    out["record_version"] = RECORD_VERSION_NOW()
    out["supersedes"] = record["id"]
    out["judged_at"] = now
    ident = frontend_identity()
    out["judged_by"] = {"script": ident["script"], "commit": ident["commit"],
                        "script_sha256": ident["script_sha256"]}
    return out


def RECORD_VERSION_NOW() -> int:  # noqa: N802
    from measurement_records import RECORD_VERSION  # noqa: PLC0415

    return RECORD_VERSION


def rejudge_records(args: argparse.Namespace) -> int:
    """Append, for each live record whose judgement the oracle now gives
    otherwise, the record judged again, superseding it."""
    from measurement_records import line_text, live, read_records, records_path, seal  # noqa: PLC0415

    root = Path(args.record)
    data, identity = load_oracle(Path(args.oracle) if args.oracle else DEFAULT_ORACLE)
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    stored = read_records(root)
    alive = {r["id"] for r in live(s.record for s in stored)}
    written = 0
    for entry in stored:
        if entry.record["id"] not in alive or (args.emulator and entry.emulator not in args.emulator):
            continue
        new = rejudged(entry.record, data, identity, now)
        if new is None:
            continue
        sealed = seal(new)
        before = {v["label"]: v.get("verdict") for v in entry.record["variants"]}
        after = {v["label"]: f"{v['verdict']} ({v['bios_used']})" for v in sealed["variants"]}
        print(json.dumps({"emulator": entry.emulator, "supersedes": entry.record["id"], "id": sealed["id"],
                          "before": before, "after": after}))
        written += 1
        if not args.dry_run:
            with (root / records_path(entry.emulator)).open("a", encoding="utf-8") as handle:
                handle.write(line_text(sealed) + "\n")
    print(f"{written} records judged again" + (" (dry run, nothing written)" if args.dry_run else ""),
          file=sys.stderr)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.mode == "rejudge":
        return rejudge_records(args)
    if args.mode == "_worker":
        spec = json.loads(Path(args.spec).read_text(encoding="utf-8"))
        Path(args.out).write_text(json.dumps(run_worker(spec)), encoding="utf-8")
        return 0
    return probe(args)


if __name__ == "__main__":
    if sys.argv[1:2] == ["_worker"]:
        # The worker runs in the sandbox, where this file is all of the
        # repository there is: it imports nothing beside the standard library.
        sys.exit(main())
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from common import run_cli

    run_cli(main)
