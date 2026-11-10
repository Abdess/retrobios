#!/usr/bin/env python3
"""Write the notes of a release from its record.

The notes carried the pack table, typed by hand from figures release.json
already held: a copied cell or an old collection total at the top is how
issue 81 happened. Install commands, the parts sentence and the table come
from the record and the registry. Each row links the files of this release,
which sit right below the notes, and the setups the registry does not mark
release_pack are named with the command. The text is a beginner's page: one
idea per line, plain words (owner, 2026-11-10). The maintainer writes
what changed, and that text is appended as given once it holds none of the
REFUSED phrases.

Usage:
    python scripts/release_notes.py --whats-new tmp/whats-new.md --output notes.md
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import release_record
from common import (
    list_registered_platforms,
    list_release_pack_platforms,
    load_platform_config,
    load_platform_registry,
    require_directory,
    write_text_atomic,
)
from siteguides import install_command

REPO = "Abdess/retrobios"
SITE = "https://abdess.github.io/retrobios/"


def _size(count: int) -> str:
    if count >= 1024**3:
        return f"{count / 1024**3:.1f} GB"
    return f"{count / 1024**2:.0f} MB"


def _display(pack: str) -> str:
    """RetroArch_Lakka_v1.22.2_BIOS_Pack.zip reads as RetroArch Lakka v1.22.2."""
    return pack.split("_BIOS_Pack", 1)[0].replace("_", " ")


def _owner(name: str, pack: dict) -> str:
    """The platform a pack is named after: RetroArch_Lakka is RetroArch's."""
    key = _match_key(name)
    return sorted(
        pack.get("platforms", ()), key=lambda p: key.find(_match_key(p)) % (len(key) + 1)
    )[0]


def _extract_folders(record: dict, platforms_dir: str) -> dict[str, str]:
    """Pack name to the folder the registry says it extracts into."""
    registry = load_platform_registry(platforms_dir)
    folders: dict[str, str] = {}
    for name, pack in sorted(record.get("packs", {}).items()):
        folder = registry.get(_owner(name, pack), {}).get("extract_to")
        if folder:
            folders[name] = folder
    return folders


def without_pack(platforms_dir: str) -> list[str]:
    """Display names of the registered setups no release publishes a ZIP for."""
    released = set(list_release_pack_platforms(platforms_dir))
    names = [
        str(load_platform_config(key, platforms_dir).get("platform", key))
        for key in list_registered_platforms(platforms_dir)
        if key not in released
    ]
    return sorted(names, key=str.casefold)


def no_pack_paragraph(platforms_dir: str) -> list[str]:
    """One paragraph naming the setups served by the command alone."""
    names = without_pack(platforms_dir)
    if not names:
        return []
    listed = ", ".join(names[:-1]) + f" and {names[-1]}" if len(names) > 1 else names[0]
    return [
        (f"No ZIP for {listed}. The command above installs them."
         " Add `--dry-run` to see what it would do."),
        "",
    ]


def _match_key(value: str) -> str:
    """Letters and digits only: the platform is `misterfpga`, the pack MiSTer_FPGA."""
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _link(pack: dict, tag: str) -> str:
    """The pack's files on this release, one link per part."""
    base = f"https://github.com/{REPO}/releases/download/{tag}"
    assets = pack["assets"]
    if len(assets) == 1:
        return f"[Download]({base}/{assets[0]})"
    return ", ".join(f"[part {i}]({base}/{name})" for i, name in enumerate(assets, 1))


# Words the published notes of v2026.10.10 carried by hand: "never from a
# forum list" judged lists other people keep, and "a game never stops on a
# missing file" was a claim the gap analysis contradicts. Text about other
# projects says what changed, not who erred (wiki/release-process.md).
REFUSED = ("their file", "theirs", "of ours", "corrected", "wrong", "drift",
           "left out", "never seen", "forum", "never stops", "never fails")


def refused_words(text: str) -> list[str]:
    """The refused phrases the text holds, case ignored."""
    lowered = text.lower()
    return [phrase for phrase in REFUSED if phrase in lowered]


def render(record: dict, platforms_dir: str, whats_new: str) -> str:
    packs = record.get("packs", {})
    folders = _extract_folders(record, platforms_dir)
    tag = str(record.get("tag", ""))
    lines = [
        "### Install in one command",
        "",
        "It finds the setup and its BIOS folder, then downloads only what is missing.",
        "",
        "**Linux, macOS, Steam Deck**",
        "```sh",
        install_command("sh"),
        "```",
        "",
        "**Windows (PowerShell)**",
        "```powershell",
        install_command("powershell"),
        "```",
        "",
        (f"**On a handheld**: copy the `RetroBIOS` file for the system to the card"
         f" ([which one]({SITE}wiki/installer/#on-a-handheld-the-retrobios-port))."),
        "",
        "### Or download a pack",
        "",
        "Extract it into the BIOS folder.",
        "",
    ]
    if any(len(pack["assets"]) > 1 for pack in packs.values()):
        lines += [
            ("A pack in parts: each part is an ordinary ZIP. Extract every part into"
             " the same folder. Nothing needs joining."),
            "",
        ]
    lines += [
        "| Platform | Download | Size | Files | Extract to |",
        "|----------|----------|-----:|------:|-----------|",
    ]
    for name, pack in sorted(packs.items(), key=lambda item: -item[1]["extracted_size"]):
        folder = folders.get(name)
        lines.append(
            f"| {_display(name)} | {_link(pack, tag)} |"
            f" {_size(pack['extracted_size'])} | {pack['files']:,} |"
            f" {f'`{folder}`' if folder else '-'} |"
        )
    lines += [
        "",
        f"Files no pack holds yet: [gap analysis]({SITE}gaps/).",
        "",
        *no_pack_paragraph(platforms_dir),
        whats_new.strip(),
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Write a release's notes")
    parser.add_argument("--record", default=release_record.RECORD, type=Path,
                        help="release record (default: %(default)s)")
    parser.add_argument("--whats-new", required=True, type=Path,
                        help="what changed since the previous release, written by hand")
    parser.add_argument("--platforms-dir", default="platforms",
                        help="registry read for each pack's extract folder (default: %(default)s)")
    parser.add_argument("--output", required=True, type=Path,
                        help="notes file to write, passed to gh release create --notes-file")
    args = parser.parse_args()
    require_directory(args.platforms_dir, "--platforms-dir")

    record = release_record.load_record(args.record)
    if not record.get("packs"):
        print(f"Error: {args.record} records no pack", file=sys.stderr)
        return 1
    whats_new = args.whats_new.read_text(encoding="utf-8")
    if not whats_new.strip():
        print(f"Error: {args.whats_new} is empty", file=sys.stderr)
        return 1
    refused = refused_words(whats_new)
    if refused:
        print(f"Error: {args.whats_new} says {', '.join(repr(w) for w in refused)}. State what"
              " changed and how it was checked, not a verdict on other projects or a"
              " promise the gap analysis contradicts", file=sys.stderr)
        return 1
    write_text_atomic(str(args.output), render(record, args.platforms_dir, whats_new))
    print(f"Wrote {args.output} for {record['tag']}, {len(record['packs'])} packs")
    return 0


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
