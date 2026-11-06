#!/usr/bin/env python3
"""Record the installer demo shown in the README and on the site, once.

The recording is the full-screen installer run from the one-line command on
an ArkOS SD card that holds six games: it finds the card, plans only the BIOS
files those games need, installs them and shows the summary. Everything it
reads is local and the same on every machine:

- The card is built under tmp/demo/ (bios/, the folders ArkOS writes on its
  games partition, one game per console) and mounted at /media/EASYROMS in a
  mount namespace of this user (unshare), on a tmpfs of a card's size. /media
  and /mnt are emptied there, so no drive of this machine is shown.
- The repository is served on 127.0.0.1 and named with RETROBIOS_BASE_URL:
  the file lists, install/games/ and the BIOS files are this checkout's.
- The one-line command runs this checkout's install.sh and install.py. The
  shell of the recording answers `curl -fsSL <site>/i` with a line that
  starts the local install.sh, which skips the download of the installer and
  its SHA-256 check and runs the rest of the bootstrap as the site's copy does.
- HOME is an empty folder and the prompt is "$ ".

docs_assets/demo/install.tape drives VHS (github.com/charmbracelet/vhs, with
ttyd, ffmpeg and a Chromium on PATH). This script encodes what it records:

    docs_assets/demo/install.gif    the README
    docs_assets/demo/install.webm   the site, with install.mp4 as fallback
    docs_assets/demo/install.png    the first frame shown, the video's poster
    docs_assets/demo/demo.json      what the recording shows, for the alt text

The site build copies the video files and never runs this script. Run it
again when a screen of the installer or the file list of its games changes:

    python scripts/make_demo.py
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import http.server
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs_assets" / "demo"
TAPE = OUT / "install.tape"
WORK = ROOT / "tmp" / "demo"
# What the tape writes, read back here (paths relative to ROOT, the tape's
# working directory).
RECORDED = WORK / "recorded.mp4"
POSTER_SHOT = WORK / "poster.png"
MOUNT = "/media/EASYROMS"
CARD_SIZE = "29g"
SETUP = "ArkOS"

# The card: the folders ArkOS's default tree writes on EASYROMS (install.py
# _GAMES_PART_RULES reads launchimages/), and one game per console folder,
# named as the folder's extensions in install/games/setups/arkos.json allow.
CARD_FOLDERS = ("bios", "bgmusic", "launchimages", "themes/es-theme-nes-box")
GAMES = {
    "psx": "Sky Courier (USA).iso",
    "segacd": "Night Shift (USA).iso",
    "megadrive": "Old Harbour (World).md",
    "mastersystem": "Tide Runner (Europe).sms",
    "gamegear": "Pocket Quest (World).gg",
    "pcengine": "Star Lancer (Japan).pce",
}
GAME_BYTES = 256 * 1024
# A PlayStation disc carries Sony's licence text in sector 4, the text the
# cores read the region from (install/games/systems/sony-playstation.json).
PSX_LICENCE = b"          Licensed  by          Sony Computer Entertainment Amer  ica "

# Size targets of the outputs, in bytes: the README and two site pages.
LIMITS = {"install.gif": 1_500_000, "install.webm": 1_000_000,
          "install.mp4": 1_000_000, "install.png": 150_000}
GIF_FPS = 10
VIDEO_FPS = 25


def game_bytes(name: str) -> bytes:
    """Bytes of a game no catalog names, the same on every run."""
    seed = hashlib.sha256(name.encode("utf-8")).digest()
    blocks, counter = [], 0
    while len(blocks) * 32 < GAME_BYTES:
        blocks.append(hashlib.sha256(seed + counter.to_bytes(4, "big")).digest())
        counter += 1
    return b"".join(blocks)[:GAME_BYTES]


def build_card(card: Path) -> None:
    if card.exists():
        shutil.rmtree(card)
    for folder in CARD_FOLDERS:
        (card / folder).mkdir(parents=True)
    (card / "launchimages" / "loading.jpg").write_bytes(b"\xff\xd8\xff\xe0" + bytes(60) + b"\xff\xd9")
    (card / "themes" / "es-theme-nes-box" / "theme.xml").write_text(
        "<theme>\n</theme>\n", encoding="utf-8")
    for folder, name in GAMES.items():
        data = bytearray(game_bytes(name))
        if folder == "psx":
            data[4 * 2048:4 * 2048 + len(PSX_LICENCE)] = PSX_LICENCE
        (card / folder).mkdir()
        (card / folder / name).write_bytes(bytes(data))


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass


@contextmanager
def served_repository() -> Iterator[str]:
    """The repository on a loopback port, the base URL install.py accepts
    without HTTPS."""
    handler = functools.partial(QuietHandler, directory=str(ROOT))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def write_session(work: Path, names: list[str]) -> Path:
    """The program the recording's shell becomes: the card mounted in a
    namespace of its own, then a clean interactive bash, or the command
    given as arguments, with only the variables names lists."""
    rc = work / "bashrc"
    rc.write_text(
        "PS1='$ '\n"
        "unset HISTFILE PROMPT_COMMAND\n"
        "curl() {\n"
        '  if [ "$*" = "-fsSL https://abdess.github.io/retrobios/i" ]; then\n'
        '    printf \'exec %s "$@"\\n\' "$RETROBIOS_DEMO_BOOTSTRAP"\n'
        "  else\n"
        '    command curl "$@"\n'
        "  fi\n"
        "}\n"
        "clear\n",
        encoding="utf-8",
    )
    session = work / "session.sh"
    session.write_text(
        "#!/bin/sh\n"
        "# Written by scripts/make_demo.py.\n"
        "set -eu\n"
        "inner='set -eu\n"
        "mount -t tmpfs -o mode=0755 demo /media\n"
        "mount -t tmpfs -o mode=0755 demo /mnt\n"
        f"mkdir {MOUNT}\n"
        f"mount -t tmpfs -o size={CARD_SIZE},mode=0755 EASYROMS {MOUNT}\n"
        f'cp -a "$RETROBIOS_DEMO_CARD/." {MOUNT}/\n'
        'cd "$HOME"\n'
        'exec unshare --user --map-user="$RETROBIOS_DEMO_UID" '
        '--map-group="$RETROBIOS_DEMO_GID" env -i '
        + " ".join(f'{name}="${name}"' for name in names) + ' "$@"\'\n'
        'if [ "$#" -eq 0 ]; then\n'
        f'  set -- bash --noprofile --rcfile "{rc}" -i\n'
        "fi\n"
        'exec unshare --user --mount --map-root-user /bin/sh -c "$inner" sh "$@"\n',
        encoding="utf-8",
    )
    session.chmod(0o755)
    return session


def session_env(base_url: str, work: Path, card: Path) -> dict[str, str]:
    home = work / "home"
    home.mkdir(parents=True, exist_ok=True)
    return {
        "HOME": str(home),
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "TERM": "xterm-256color",
        "TMPDIR": str(work / "scratch"),
        "RETROBIOS_OS": "linux",
        "RETROBIOS_BASE_URL": base_url,
        # What the downloaded bootstrap sets: commands given back are the
        # one-line command, not a path to a temporary copy.
        "RETROBIOS_BOOTSTRAP": "sh",
        "RETROBIOS_DEMO_BOOTSTRAP": str(ROOT / "install.sh"),
        "RETROBIOS_DEMO_CARD": str(card),
        "RETROBIOS_DEMO_UID": str(os.getuid()),
        "RETROBIOS_DEMO_GID": str(os.getgid()),
    }


def format_size(size: int) -> str:
    """The size as the installer writes it."""
    spec = importlib.util.spec_from_file_location("retrobios_install", ROOT / "install.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("install.py cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return str(module.format_size(size))


def measure(session: Path, env: dict[str, str]) -> dict:
    """What the recording shows, read from the same run without the screen:
    the games read on the card and the files planned for them."""
    command = [str(session), sys.executable, str(ROOT / "install.py"), "--platform", "retroarch",
               "--dest", f"{MOUNT}/bios", "--for-games", "--dry-run", "--events"]
    result = subprocess.run(command, env=env, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"the dry run failed ({result.returncode}):\n{result.stderr}")
    events = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    games = next(e for e in events if e["event"] == "games")
    check = next(e for e in events if e["event"] == "check")
    size = {key.lower(): int(value) for key, value in
            re.findall(r"^Set (Width|Height) (\d+)$", TAPE.read_text(encoding="utf-8"), re.M)}
    return {
        "width": size["width"],
        "height": size["height"],
        "setup": SETUP,
        "games": games["games"],
        "systems": len(games["found"]),
        "files": check["missing"],
        "size": format_size(check["bytes_needed"]),
    }


def ffmpeg(*args: str) -> None:
    subprocess.run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", *args], check=True)


def encode(recorded: Path, poster: Path, out: Path, scratch: Path) -> None:
    palette = scratch / "palette.png"
    ffmpeg("-i", str(recorded), "-vf", f"fps={GIF_FPS},palettegen=max_colors=48:stats_mode=full",
           str(palette))
    ffmpeg("-i", str(recorded), "-i", str(palette), "-lavfi",
           f"fps={GIF_FPS}[v];[v][1:v]paletteuse=dither=none:diff_mode=rectangle",
           "-loop", "0", str(out / "install.gif"))
    ffmpeg("-i", str(recorded), "-an", "-r", str(VIDEO_FPS), "-c:v", "libvpx-vp9",
           "-b:v", "0", "-crf", "42", "-row-mt", "1", "-deadline", "good",
           "-pix_fmt", "yuv420p", str(out / "install.webm"))
    ffmpeg("-i", str(recorded), "-an", "-r", str(VIDEO_FPS), "-c:v", "libx264",
           "-preset", "veryslow", "-crf", "30", "-tune", "animation", "-pix_fmt", "yuv420p",
           "-movflags", "+faststart", str(out / "install.mp4"))
    ffmpeg("-i", str(poster), "-pred", "mixed", "-compression_level", "100",
           str(out / "install.png"))


def check_sizes(out: Path) -> list[str]:
    return [f"{name}: {(out / name).stat().st_size:,} bytes, over {limit:,}"
            for name, limit in LIMITS.items() if (out / name).stat().st_size > limit]


def main() -> None:
    parser = argparse.ArgumentParser(allow_abbrev=False,
                                     description="Record the installer demo (VHS).")
    parser.parse_args()
    missing = [tool for tool in ("vhs", "ttyd", "ffmpeg", "unshare") if shutil.which(tool) is None]
    if missing:
        sys.exit(f"Missing on PATH: {', '.join(missing)} (VHS: github.com/charmbracelet/vhs)")
    if WORK.exists():
        shutil.rmtree(WORK)
    (WORK / "scratch").mkdir(parents=True)
    try:
        card = WORK / "card"
        build_card(card)
        with served_repository() as base_url:
            env = session_env(base_url, WORK, card)
            session = write_session(WORK, sorted(env))
            facts = measure(session, env)
            vhs_env = {**os.environ, **env, "PATH": os.environ.get("PATH", ""),
                       "HOME": os.environ.get("HOME", ""),
                       "RETROBIOS_DEMO_SESSION": str(session)}
            subprocess.run(["vhs", str(TAPE.relative_to(ROOT))], cwd=ROOT, env=vhs_env,
                           check=True)
        encode(RECORDED, POSTER_SHOT, OUT, WORK / "scratch")
        (OUT / "demo.json").write_text(json.dumps(facts, indent=2) + "\n", encoding="utf-8")
        for name in (*LIMITS, "demo.json"):
            print(f"{(OUT / name).relative_to(ROOT)}  {(OUT / name).stat().st_size:,} bytes")
        over = check_sizes(OUT)
        if over:
            sys.exit("Over the size targets:\n  " + "\n  ".join(over))
    finally:
        shutil.rmtree(WORK, ignore_errors=True)


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
