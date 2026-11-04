#!/usr/bin/env python3
"""The search gate: queries a visitor types, and the pages that answer them.

Runs measure.mjs against a served build, through the site's own search box,
and checks each query's expected pages against the rank it must reach: the
first result, or the first three. Exits 1 when a query misses.

    python website/tools/search_gate.py --site-dir website/dist
    python website/tools/search_gate.py http://127.0.0.1:4321/retrobios/

With --site-dir the build is served by serve.mjs (as GitHub Pages serves it)
on a free port for the run. The browser driver is playwright-core in
website/node_modules (npm install --no-save --prefix website playwright-core)
and Chrome at /usr/bin/google-chrome, or CHROME_PATH.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
BASE = "/retrobios/"
# What the home page transfers on a phone, everything it loads before a
# visitor does anything (gzip, as GitHub Pages serves it).
HOME_BUDGET_KB = 80

# Query: (pages that answer it, as path prefixes under the site, and the rank one
# of them must reach). An emulator name must find the emulator itself first,
# not its launcher or a frozen copy.
QUERIES: dict[str, tuple[tuple[str, ...], int]] = {
    "batocera folder": (("platforms/batocera/",), 1),
    "missing bios": (("wiki/troubleshooting/", "wiki/what-are-bios-files/", "wiki/faq/"), 1),
    "neogeo.zip": (("emulators/fbneo", "emulators/mame", "systems/snk/", "systems/arcade"), 1),
    "retroarch system folder": (("platforms/retroarch/",), 1),
    "installer": (("wiki/installer/", "wiki/first-install/"), 1),
    # The file's card on its system page, where it is downloaded. "systems/sony"
    # holds the manufacturer page and the console's own (systems/sony-playstation/).
    "scph5501": (("systems/sony",), 3),
    # How a setup checks a hash, or the page that checks one.
    "md5": (("wiki/verification-modes/", "files/"), 1),
    "where do bios files go": (("which-pack/", "wiki/first-install/"), 1),
    "dolphin": (("emulators/dolphin/",), 1),
    "duckstation": (("emulators/duckstation/",), 1),
    # A console and "bios": the console's own page first, before any setup's
    # list for it or a part of its manufacturer's page.
    "playstation bios": (("systems/sony-playstation/",), 1),
    "dreamcast bios": (("systems/sega",), 3),
    "neo geo bios": (("systems/snk",), 3),
    "wonderswan color": (("systems/bandai",), 3),
    # The platforms' own names for a console (psx, dc, gba), a search field
    # of its page. Flycast's page names dc_boot.bin and where it goes.
    "psx bios": (("systems/sony",), 3),
    "dc bios missing": (("systems/sega", "emulators/flycast/"), 3),
    "gba bios": (("systems/nintendo",), 3),
    # A console whose page answers "No file needed" says BIOS only where the
    # search does not read: its `terms` field carries "<name> BIOS".
    "snes bios": (("systems/nintendo-snes/",), 1),
    "nes bios": (("systems/nintendo-nes/",), 1),
    "gamecube bios": (("systems/nintendo-gamecube/",), 1),
    "game boy bios": (("systems/nintendo-game-boy/",), 1),
    "3ds bios": (("systems/nintendo-3ds/",), 1),
    # A console another one's name begins with, both ways: the longer name's
    # page holds every word of the shorter query. GBA and GBC are sections
    # of their maker's page. Saturn.emu is an emulator named after its
    # console.
    "playstation 2 bios": (("systems/sony-playstation-2/",), 1),
    # Every Sony console has a page of its own (CONSOLE_PAGES). The search
    # weighs words, not their order, and "3" is on too many pages to weigh:
    # the PlayStation page, which names BIOS v3.0 and leads "playstation
    # bios", stays just above. "ps3 bios" finds the page first.
    "playstation 3 bios": (("systems/sony-playstation-3/",), 2),
    "ps3 bios": (("systems/sony-playstation-3/",), 1),
    "game boy advance bios": (("systems/nintendo/",), 1),
    "game boy color bios": (("systems/nintendo/",), 1),
    "nintendo ds bios": (("systems/nintendo-nintendo-ds/",), 1),
    "nintendo dsi bios": (("systems/nintendo-nintendo-dsi/",), 1),
    "wii bios": (("systems/nintendo/",), 1),
    "wii u bios": (("systems/nintendo-wii-u/",), 1),
    "saturn bios": (("systems/sega-saturn/",), 1),
    # The words an emulator prints, and the page that answers them.
    "bios not found": (("wiki/troubleshooting/",), 3),
    "please insert playstation cd-rom": (("wiki/troubleshooting/",), 3),
    "offline install": (("wiki/installer/",), 3),
    # The table of versions, or the FAQ answer headed with the question,
    # which links it.
    # The version table before any MAME part, whose card titles name MAME files.
    "which mame version": (("wiki/technical-faq/", "wiki/faq/"), 1),
    # Checking a dump is what the Find a file page does.
    "check my dump": (("files/",), 1),
    "md5 check": (("files/",), 1),
    "is my bios correct": (("files/",), 3),
    # A folder is checked by the setup's command, which troubleshooting runs.
    "check my bios folder": (("wiki/troubleshooting/",), 3),
    # A tool author's words: the data reference or the installer's.
    "manifest": (("data/", "wiki/installer/"), 3),
    "events": (("data/", "wiki/installer/"), 3),
    "exit code": (("data/", "wiki/installer/"), 3),
    "rate limit": (("data/", "wiki/installer/"), 3),
    "schema": (("data/",), 3),
    "json schema": (("data/",), 3),
    "license": (("data/", "wiki/legal/"), 3),
    "check bios folder script": (("data/",), 3),
    # The iPhone and iPad answer: copy the files to the app, no terminal.
    "ios": (("which-pack/", "wiki/faq/"), 3),
    # A device name: the guide of the handhelds that run it.
    "r36s": (("platforms/", "which-pack/"), 3),
    "steam deck": (("platforms/emudeck/", "platforms/retrodeck/", "which-pack/"), 1),
    "knulli": (("platforms/knulli/",), 1),
    # A card folded in a table row, on the last part of MAME's cards.
    "bbc_flop_torch.xml": (("emulators/mame-files-",), 3),
    # FinalBurn Neo has no pgm.zip entry: the archive is named by the badge
    # of each member it reads there, in the Status column of its table.
    "pgm.zip": (("emulators/fbneo/",), 3),
    # A dump name in a wanted list folded under its filter box.
    "speeddos": (("provenance-tosec/",), 1),
    # A pasted hash of any kind finds the file's card, its hashes now in a
    # closed fold: the MD5, CRC32 and SHA256 of scph5501.bin. The search box
    # offers "Look up this hash", and the lookup opens the card.
    "490f666e1afb15b7362b406ed1cea246": (("systems/sony-playstation/",), 1),
    "8d8cb7e4": (("systems/sony-playstation/",), 1),
    "11052b6499e466bbf0a709b1f9cb6834a9418e66680387912451e971cf8a1fef": (("systems/sony-playstation/",), 1),
}


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


# Node's compile cache fills /tmp (a 4 GB tmpfs under WSL): every node this
# gate starts runs without it.
NODE_ENV = {**os.environ, "NODE_DISABLE_COMPILE_CACHE": "1"}


@contextmanager
def served(site_dir: Path) -> Iterator[str]:
    """The build served by serve.mjs on a free port, for the run."""
    port = _free_port()
    server = subprocess.Popen(["node", str(TOOLS / "serve.mjs"), str(site_dir), str(port)], env=NODE_ENV)
    url = f"http://127.0.0.1:{port}{BASE}"
    try:
        for _ in range(100):
            try:
                with urllib.request.urlopen(url, timeout=2):
                    break
            except (urllib.error.URLError, ConnectionError):
                if server.poll() is not None:
                    raise RuntimeError(f"serve.mjs exited with {server.returncode}") from None
                time.sleep(0.1)
        else:
            raise RuntimeError(f"serve.mjs did not answer on {url}")
        yield url
    finally:
        server.terminate()
        server.wait(timeout=10)


def run_gate(base: str) -> int:
    root = "/" + base.split("/", 3)[3]
    run = subprocess.run(
        ["node", str(TOOLS / "measure.mjs"), "search", base, "starlight-ui", *QUERIES],
        capture_output=True, text=True, check=False, env=NODE_ENV,
    )
    if run.returncode:
        print(run.stderr.strip() or f"measure.mjs exited with {run.returncode}", file=sys.stderr)
        return 1
    answered = 0
    for line in run.stdout.splitlines():
        result = json.loads(line)
        if "query" not in result:
            print(f"first search: {result['first_search_kb']} KB in {result['first_search_requests']} requests")
            continue
        pages, rank = QUERIES[result["query"]]
        top = [entry.split(" | ") for entry in result["top"][:3]]
        hit = any(href[len(root):].startswith(pages) for _title, href in top[:rank])
        answered += hit
        shown = "; ".join(f"{title} ({href[len(root):] or '/'})" for title, href in top)
        print(f"{'ok  ' if hit else 'MISS'} {result['query']!r} (top {rank}): {shown}")
    print(f"{answered}/{len(QUERIES)} queries answered")
    home = home_weight(base)
    print(f"{'ok  ' if home <= HOME_BUDGET_KB else 'OVER'} home: {home:.1f} KB "
          f"transferred at 390 px (budget {HOME_BUDGET_KB} KB)")
    return 0 if answered == len(QUERIES) and home <= HOME_BUDGET_KB else 1


def home_weight(base: str) -> float:
    """The home page's transfer at 390 px, once the network is idle."""
    run = subprocess.run(
        ["node", str(TOOLS / "measure.mjs"), "weight", base, ""],
        capture_output=True, text=True, check=True, env=NODE_ENV,
    )
    return float(json.loads(run.stdout.splitlines()[0])["total_kb"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("url", nargs="?", default="http://127.0.0.1:4321/retrobios/",
                        help="a served build, under /retrobios/ (default: %(default)s)")
    parser.add_argument("--site-dir", type=Path,
                        help="serve this build for the run instead of reading URL")
    args = parser.parse_args()
    if args.site_dir is None:
        return run_gate(args.url)
    if not (args.site_dir / "pagefind").is_dir():
        print(f"{args.site_dir}: no built site with a search index", file=sys.stderr)
        return 1
    with served(args.site_dir) as url:
        return run_gate(url)


if __name__ == "__main__":
    sys.exit(main())
