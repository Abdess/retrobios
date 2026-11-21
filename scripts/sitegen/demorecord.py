"""Recording one installer demo: what it shows, the VHS run and the encoded outputs."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path

from core.paths import REPO_ROOT
from installer_build.module import installer_module
from sitegen.democard import build_card
from sitegen.demosession import ARK_INSTALLER, served_repository, session_env, write_session
from sitegen.demovariants import OUT, VARIANTS, WORK, Variant, describe

# The system on the device: dArkOS, which replaced ArkOS on 30 December
# 2025 (christianhaitian/arkos wiki). A computer reading its card cannot
# tell the two apart (install.py card_title), and says both.
SETUP = "dArkOS"
CARD_SETUP = "dArkOS or ArkOS"

GIF_FPS = 10
VIDEO_FPS = 25


def format_size(size: int) -> str:
    """The size as the installer writes it."""
    return str(installer_module().format_size(size))


def measure(session: Path, env: dict[str, str], variant: Variant = VARIANTS["default"]) -> dict:
    """What the recording shows, read from the same run without the screen:
    the games read on the card and the files planned for them."""
    installer = ARK_INSTALLER if variant.place == "device" else str(REPO_ROOT / "install.py")
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
        subprocess.run(["vhs", str(variant.tape.relative_to(REPO_ROOT))], cwd=REPO_ROOT,
                       env=vhs_env, check=True)
    encode(variant, OUT, WORK / "scratch")
    return facts


def needed_tools(variant: Variant) -> list[str]:
    tools = ["vhs", "ttyd", "ffmpeg"]
    return [*tools, "bwrap" if variant.place == "device" else "unshare"]


def missing_tools(variants: Iterable[Variant]) -> list[str]:
    """The tools the variants need that are not on PATH, sorted."""
    return sorted({tool for variant in variants for tool in needed_tools(variant)
                   if shutil.which(tool) is None})


def fresh_work() -> None:
    """An empty WORK with its scratch folder, before each recording."""
    if WORK.exists():
        shutil.rmtree(WORK)
    (WORK / "scratch").mkdir(parents=True)


def remove_work() -> None:
    shutil.rmtree(WORK, ignore_errors=True)
