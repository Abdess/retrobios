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
import sys

from core.paths import REPO_ROOT
from sitegen.demorecord import fresh_work, missing_tools, record, remove_work
from sitegen.demovariants import OUT, VARIANTS, check_sizes, load_facts, write_facts


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(allow_abbrev=False,
                                     description="Record the installer demos (VHS).")
    parser.add_argument("--variant", action="append", choices=sorted(VARIANTS),
                        help="record this variant only (repeatable); every variant by default")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    chosen = [VARIANTS[name] for name in (args.variant or VARIANTS)]
    missing = missing_tools(chosen)
    if missing:
        sys.exit(f"Missing on PATH: {', '.join(missing)} (VHS: github.com/charmbracelet/vhs)")
    facts = load_facts()
    over: list[str] = []
    try:
        for variant in chosen:
            fresh_work()
            facts[variant.name] = record(variant)
            for name in variant.outputs:
                print(f"{(OUT / name).relative_to(REPO_ROOT)}  {(OUT / name).stat().st_size:,} bytes")
            over += check_sizes(OUT, variant)
        write_facts(facts)
        if over:
            sys.exit("Over the size targets:\n  " + "\n  ".join(over))
    finally:
        remove_work()


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
