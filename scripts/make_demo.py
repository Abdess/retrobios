#!/usr/bin/env python3
"""Record the installer demos shown in the README and on the site, once.

Each recording is the installer on a dArkOS SD card that holds six games: it
finds the card, plans only the BIOS files those games need, installs them
and shows the summary. Two variants, by where the install box says the
command runs:

- default: the one-line command in a terminal on a Linux computer, the card
  mounted at /media/EASYROMS. The README and every tab but one show it.
- handheld: the full-screen interface on dArkOS itself, at the 640x480
  screen of an RG351MP, as the Tools menu launcher starts it (ports/shared/
  tui.txt: install.py --tui, RETROBIOS_PAD=gptokeyb, RETROBIOS_IDLE_EXIT).
  The keys typed are the ones gptokeyb sends for the buttons
  (ports/shared/retrobios.gptk: A is Enter), and the bottom line names the
  buttons. The "On the device" tab shows it.

No Windows variant: pwsh on Linux runs install.ps1's whole flow, but the
installer reads drive E: there only through its WSL layout, and its summary
gives the command back with --dest /mnt/e/bios, a path no Windows user sees.

Everything a recording reads is local and the same on every machine:

- The card is built under tmp/demo/ (bios/, the folders dArkOS writes on its
  games partition, one game per console) on a tmpfs of a card's size, in a
  mount namespace of this user (unshare, or bwrap for the handheld, whose
  root holds dArkOS's /home/ark, /opt/system, /roms and its boot splash). /media and /mnt are
  emptied, so no drive of this machine is shown.
- The repository is served on 127.0.0.1 and named with RETROBIOS_BASE_URL:
  the file lists, install/games/ and the BIOS files are this checkout's.
- The one-line command runs this checkout's install.sh: the shell answers
  `curl -fsSL <site>/i` with a line that starts the local install.sh, which
  skips the download of the installer and its SHA-256 check and runs the
  rest of the bootstrap as the site's copy does.
- HOME is an empty folder and the prompt is "$ ".

docs_assets/demo/<stem>.tape drives VHS (github.com/charmbracelet/vhs, with
ttyd, ffmpeg and a Chromium on PATH, and bwrap for the handheld). This
script encodes what it records:

    docs_assets/demo/install.gif     the README (the default variant only)
    docs_assets/demo/<stem>.webm     the site, with <stem>.mp4 as fallback
    docs_assets/demo/<stem>.png      the first frame shown, the video's poster
    docs_assets/demo/demo.json       per variant, what it shows and its alt text

The site build copies the video files and never runs this script. Run it
again when a screen of the installer or the file list of its games changes:

    python scripts/make_demo.py                      # both variants
    python scripts/make_demo.py --variant handheld   # one, the others kept
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
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs_assets" / "demo"
WORK = ROOT / "tmp" / "demo"
FACTS = OUT / "demo.json"
CARD_SIZE = "29g"
# The system on the device: dArkOS, which replaced ArkOS on 30 December
# 2025 (christianhaitian/arkos wiki). A computer reading its card cannot
# tell the two apart (install.py card_title), and says both.
SETUP = "dArkOS"
CARD_SETUP = "dArkOS or ArkOS"
# The boot splash title dArkOS is recognised by on the device
# (finishing_touches.sh:359-361, install.py _PLYMOUTH_TITLE), dated as its
# latest release, v08272026.
SPLASH = "/usr/share/plymouth/themes/text.plymouth"
SPLASH_TEXT = "[Plymouth Theme]\ntitle=dArkOS (08272026)\n"


@dataclass(frozen=True)
class Variant:
    """One recording. *place* is "computer" (the card in a reader, the
    one-line command typed) or "device" (the interface on the card's own
    system). *os_type* is RETROBIOS_OS for the run."""

    name: str
    stem: str
    mount: str
    os_type: str
    place: str
    gif: bool = False

    @property
    def tape(self) -> Path:
        return OUT / f"{self.stem}.tape"

    @property
    def suffix(self) -> str:
        return "" if self.name == "default" else f"-{self.name}"

    @property
    def recorded(self) -> Path:
        """What the tape writes, read back here (relative to ROOT, the
        tape's working directory)."""
        return WORK / f"recorded{self.suffix}.mp4"

    @property
    def poster_shot(self) -> Path:
        return WORK / f"poster{self.suffix}.png"

    @property
    def outputs(self) -> tuple[str, ...]:
        names = (f"{self.stem}.webm", f"{self.stem}.mp4", f"{self.stem}.png")
        return ((f"{self.stem}.gif",) if self.gif else ()) + names


VARIANTS: dict[str, Variant] = {
    "default": Variant("default", "install", "/media/EASYROMS", "linux", "computer",
                       gif=True),
    "handheld": Variant("handheld", "install-handheld", "/roms", "linux", "device"),
}
# The default variant's paths, as the tests and the README name them.
TAPE = VARIANTS["default"].tape
RECORDED = VARIANTS["default"].recorded
POSTER_SHOT = VARIANTS["default"].poster_shot
MOUNT = VARIANTS["default"].mount

# Where ArkOS keeps what the handheld recording needs: the Tools menu folder
# the launcher sits in (ports/tools/RetroBIOS.sh, RB_DIR), the user, and
# EASYROMS at /roms (install.py _OS_RULES, ArkOS).
ARK_HOME = "/home/ark"
ARK_TOOLS = "/opt/system/Tools"
ARK_INSTALLER = f"{ARK_TOOLS}/retrobios/install.py"

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

# Size targets of the outputs, in bytes, by extension: the README and the
# site's pages.
LIMITS = {".gif": 1_500_000, ".webm": 1_000_000, ".mp4": 1_000_000, ".png": 150_000}
GIF_FPS = 10
VIDEO_FPS = 25


def limits(variant: Variant) -> dict[str, int]:
    """Each output of a variant and its size target."""
    return {name: LIMITS[Path(name).suffix] for name in variant.outputs}


def game_bytes(name: str) -> bytes:
    """Bytes of a game no catalog names, the same on every run."""
    seed = hashlib.sha256(name.encode("utf-8")).digest()
    blocks: list[bytes] = []
    counter = 0
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


def _write_rc(work: Path) -> Path:
    """The startup file of the shell the recording types into: the prompt,
    no history, and the site's address answered with the local bootstrap."""
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
    return rc


def _computer_session(variant: Variant, work: Path, names: list[str]) -> str:
    rc = _write_rc(work)
    interactive = f'bash --noprofile --rcfile "{rc}" -i'
    mount = variant.mount
    return (
        "inner='set -eu\n"
        "mount -t tmpfs -o mode=0755 demo /media\n"
        "mount -t tmpfs -o mode=0755 demo /mnt\n"
        f"mkdir {mount}\n"
        f"mount -t tmpfs -o size={CARD_SIZE},mode=0755 EASYROMS {mount}\n"
        f'cp -a "$RETROBIOS_DEMO_CARD/." {mount}/\n'
        'cd "$HOME"\n'
        'exec unshare --user --map-user="$RETROBIOS_DEMO_UID" '
        '--map-group="$RETROBIOS_DEMO_GID" env -i '
        + " ".join(f'{name}="${name}"' for name in names) + ' "$@"\'\n'
        'if [ "$#" -eq 0 ]; then\n'
        f"  set -- {interactive}\n"
        "fi\n"
        'exec unshare --user --mount --map-root-user /bin/sh -c "$inner" sh "$@"\n'
    )


def _usr_binds() -> str:
    """This machine's /usr, entry by entry over a tmpfs, /usr/share too: a
    bind of the whole of /usr is read-only, and dArkOS's splash file goes in
    /usr/share/plymouth, which this machine does not have."""
    def bind(source: Path) -> str:
        return (f"--symlink {os.readlink(source)} {source}" if source.is_symlink()
                else f"--ro-bind {source} {source}")
    usr = Path("/usr")
    share = usr / "share"
    words = ["--tmpfs /usr"]
    words += [bind(entry) for entry in sorted(usr.iterdir()) if entry != share]
    words += [bind(entry) for entry in sorted(share.iterdir()) if entry.name != "plymouth"]
    words.append(f'--ro-bind "$RETROBIOS_DEMO_SPLASH" {SPLASH}')
    return " ".join(words)


def _device_session(names: list[str]) -> str:
    """dArkOS's own root, made of this machine's /usr and /etc: the user and
    the Tools menu folder ArkOS's line keeps, the boot splash title dArkOS
    is recognised by, EASYROMS at /roms, and the installer where the Tools
    menu launcher keeps it."""
    binds = " ".join(
        f"--symlink usr/{name} /{name}" for name in ("bin", "lib", "lib64", "sbin"))
    return (
        'if [ "$#" -eq 0 ]; then\n'
        f'  set -- python3 {ARK_INSTALLER} --tui\n'
        "fi\n"
        "exec bwrap --unshare-user --unshare-pid --unshare-ipc --unshare-uts --hostname darkos "
        '--uid "$RETROBIOS_DEMO_UID" --gid "$RETROBIOS_DEMO_GID" '
        f"{_usr_binds()} {binds} --ro-bind /etc /etc --proc /proc --dev /dev "
        f"--tmpfs /tmp --dir {ARK_HOME} --dir /opt/inttools --dir {ARK_TOOLS} "
        f'--ro-bind "$RETROBIOS_DEMO_INSTALLER" {ARK_INSTALLER} '
        f'--ro-bind "$RETROBIOS_DEMO_CARD" /card --size 31138512896 --tmpfs /roms '
        f"--chdir {ARK_HOME} "
        "/bin/sh -c 'cp -a /card/. /roms/ && exec env -i \"$@\"' sh "
        + " ".join(f'{name}="${name}"' for name in names) + ' "$@"\n'
    )


def write_session(work: Path, names: list[str], variant: Variant = VARIANTS["default"]) -> Path:
    """The program the recording's shell becomes: the card mounted in a
    namespace of its own, then a clean interactive shell (or, on the
    device, the interface), or the command given as arguments, with only
    the variables names lists."""
    body = (_device_session(names) if variant.place == "device"
            else _computer_session(variant, work, names))
    session = work / f"session{variant.suffix}.sh"
    session.write_text("#!/bin/sh\n# Written by scripts/make_demo.py.\nset -eu\n" + body,
                       encoding="utf-8")
    session.chmod(0o755)
    return session


def _splash(work: Path) -> Path:
    """dArkOS's boot splash theme, bound at SPLASH on the device."""
    path = work / "text.plymouth"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(SPLASH_TEXT, encoding="utf-8")
    return path


def session_env(base_url: str, work: Path, card: Path,
                variant: Variant = VARIANTS["default"]) -> dict[str, str]:
    """The variables of the run, and of nothing else: the namespace starts
    from an empty environment."""
    own = {
        "RETROBIOS_DEMO_CARD": str(card),
        "RETROBIOS_DEMO_UID": str(os.getuid()),
        "RETROBIOS_DEMO_GID": str(os.getgid()),
    }
    if variant.place == "device":
        return {
            **own,
            "HOME": ARK_HOME,
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "LANG": "C.UTF-8",
            # ArkOS's console (ports/tools/RetroBIOS.sh: console 1).
            "TERM": "linux",
            "RETROBIOS_OS": variant.os_type,
            "RETROBIOS_BASE_URL": base_url,
            # What ports/shared/tui.txt exports before the interface starts.
            "RETROBIOS_PAD": "gptokeyb",
            "RETROBIOS_IDLE_EXIT": "300",
            "RETROBIOS_DEMO_INSTALLER": str(ROOT / "install.py"),
            "RETROBIOS_DEMO_SPLASH": str(_splash(work)),
        }
    home = work / "home"
    home.mkdir(parents=True, exist_ok=True)
    return {
        **own,
        "HOME": str(home),
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "TERM": "xterm-256color",
        "TMPDIR": str(work / "scratch"),
        "RETROBIOS_OS": variant.os_type,
        "RETROBIOS_BASE_URL": base_url,
        # What the downloaded bootstrap sets: commands given back are
        # the one-line command, not a path to a temporary copy.
        "RETROBIOS_BOOTSTRAP": "sh",
        "RETROBIOS_DEMO_BOOTSTRAP": str(ROOT / "install.sh"),
    }


def _installer() -> object:
    spec = importlib.util.spec_from_file_location("retrobios_install", ROOT / "install.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("install.py cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def format_size(size: int) -> str:
    """The size as the installer writes it."""
    return str(_installer().format_size(size))  # type: ignore[attr-defined]


def describe(variant: str, facts: dict) -> str:
    """A recording in words, for a reader who cannot see it: its alt text."""
    plan = (f"plans {facts['files']} BIOS files ({facts['size']}) for them, installs them "
            "and shows the summary.")
    if variant == "handheld":
        return (f"Recording of the full-screen installer on the {facts['width']} by "
                f"{facts['height']} screen of a handheld, started from the Tools menu of "
                f"{facts['setup']}, on a demonstration card. It finds the {facts['games']} games "
                f"on the card, {plan} The A button chooses, and the bottom line names the buttons.")
    return (f"Recording of the one-line command in a terminal, on a demonstration card. The "
            f"installer finds {_article(facts['setup'])} {facts['setup']} SD card with "
            f"{facts['games']} games, {plan}")


def _article(name: str) -> str:
    return "an" if name[:1].lower() in "aeiou" else "a"


def measure(session: Path, env: dict[str, str], variant: Variant = VARIANTS["default"]) -> dict:
    """What the recording shows, read from the same run without the screen:
    the games read on the card and the files planned for them."""
    installer = ARK_INSTALLER if variant.place == "device" else str(ROOT / "install.py")
    options = ([] if variant.place == "device" else
               ["--platform", "retroarch", "--dest", f"{variant.mount}/bios", "--for-games"])
    command = [str(session), "python3" if variant.place == "device" else sys.executable,
               installer, *options, "--dry-run", "--events", "--no-input"]
    result = subprocess.run(command, env=env, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"the dry run failed ({result.returncode}):\n{result.stderr}")
    events = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    games = next(e for e in events if e["event"] == "games")
    check = next(e for e in events if e["event"] == "check")
    size = {key.lower(): int(value) for key, value in
            re.findall(r"^Set (Width|Height) (\d+)$", variant.tape.read_text(encoding="utf-8"),
                       re.M)}
    facts = {
        "width": size["width"],
        "height": size["height"],
        "setup": SETUP if variant.place == "device" else CARD_SETUP,
        "games": games["games"],
        "systems": len(games["found"]),
        "files": check["missing"],
        "size": format_size(check["bytes_needed"]),
    }
    if variant.name == "handheld":
        facts["pad"] = env["RETROBIOS_PAD"]
    facts["alt"] = describe(variant.name, facts)
    return facts


def ffmpeg(*args: str) -> None:
    subprocess.run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", *args], check=True)


def encode(variant: Variant, out: Path, scratch: Path) -> None:
    recorded, stem = str(variant.recorded), variant.stem
    if variant.gif:
        palette = scratch / "palette.png"
        ffmpeg("-i", recorded, "-vf", f"fps={GIF_FPS},palettegen=max_colors=48:stats_mode=full",
               str(palette))
        ffmpeg("-i", recorded, "-i", str(palette), "-lavfi",
               f"fps={GIF_FPS}[v];[v][1:v]paletteuse=dither=none:diff_mode=rectangle",
               "-loop", "0", str(out / f"{stem}.gif"))
    ffmpeg("-i", recorded, "-an", "-r", str(VIDEO_FPS), "-c:v", "libvpx-vp9",
           "-b:v", "0", "-crf", "42", "-row-mt", "1", "-deadline", "good",
           "-pix_fmt", "yuv420p", str(out / f"{stem}.webm"))
    ffmpeg("-i", recorded, "-an", "-r", str(VIDEO_FPS), "-c:v", "libx264",
           "-preset", "veryslow", "-crf", "30", "-tune", "animation", "-pix_fmt", "yuv420p",
           "-movflags", "+faststart", str(out / f"{stem}.mp4"))
    ffmpeg("-i", str(variant.poster_shot), "-pred", "mixed", "-compression_level", "100",
           str(out / f"{stem}.png"))


def check_sizes(out: Path, variant: Variant = VARIANTS["default"]) -> list[str]:
    return [f"{name}: {(out / name).stat().st_size:,} bytes, over {limit:,}"
            for name, limit in limits(variant).items() if (out / name).stat().st_size > limit]


def load_facts() -> dict:
    """demo.json, an empty mapping before the first recording."""
    if not FACTS.is_file():
        return {}
    return json.loads(FACTS.read_text(encoding="utf-8"))


def record(variant: Variant) -> dict:
    """Record one variant into OUT and return what it shows."""
    card = WORK / "card"
    build_card(card)
    with served_repository() as base_url:
        env = session_env(base_url, WORK, card, variant)
        session = write_session(WORK, sorted(env), variant)
        facts = measure(session, env, variant)
        vhs_env = {**os.environ, **env, "PATH": os.environ.get("PATH", ""),
                   "HOME": os.environ.get("HOME", ""),
                   "RETROBIOS_DEMO_SESSION": str(session)}
        subprocess.run(["vhs", str(variant.tape.relative_to(ROOT))], cwd=ROOT, env=vhs_env,
                       check=True)
    encode(variant, OUT, WORK / "scratch")
    return facts


def needed_tools(variant: Variant) -> list[str]:
    tools = ["vhs", "ttyd", "ffmpeg"]
    return [*tools, "bwrap" if variant.place == "device" else "unshare"]


def main() -> None:
    parser = argparse.ArgumentParser(allow_abbrev=False,
                                     description="Record the installer demos (VHS).")
    parser.add_argument("--variant", action="append", choices=sorted(VARIANTS),
                        help="record this variant only (repeatable); every variant by default")
    args = parser.parse_args()
    chosen = [VARIANTS[name] for name in (args.variant or VARIANTS)]
    missing = sorted({tool for variant in chosen for tool in needed_tools(variant)
                      if shutil.which(tool) is None})
    if missing:
        sys.exit(f"Missing on PATH: {', '.join(missing)} (VHS: github.com/charmbracelet/vhs)")
    facts = load_facts()
    over: list[str] = []
    try:
        for variant in chosen:
            if WORK.exists():
                shutil.rmtree(WORK)
            (WORK / "scratch").mkdir(parents=True)
            facts[variant.name] = record(variant)
            for name in variant.outputs:
                print(f"{(OUT / name).relative_to(ROOT)}  {(OUT / name).stat().st_size:,} bytes")
            over += check_sizes(OUT, variant)
        ordered = {name: facts[name] for name in VARIANTS if name in facts}
        FACTS.write_text(json.dumps(ordered, indent=2) + "\n", encoding="utf-8")
        if over:
            sys.exit("Over the size targets:\n  " + "\n  ".join(over))
    finally:
        shutil.rmtree(WORK, ignore_errors=True)


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
