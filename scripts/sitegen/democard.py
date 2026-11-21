"""The demonstration SD card the installer demos read: its folders and six games."""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

CARD_SIZE = "29g"

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
