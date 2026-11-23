"""The download pages of each setup, and their index."""

from __future__ import annotations

import json
import re

from model import releaserecord
from model import siteinputs
from sitegen.guidedata import device_groups, group_tiles, platform_guides, handheld_guide
from model.platforms import load_platform_config
from model.registry import load_platform_registry
from installer_build.handhelds import GROUP_PAGE
from sitegen import handheld as sitehandheld, markup
from sitegen.config import RELEASE_URL, REPO_URL
from core.paths import REPO_ROOT
from core.sizes import size_text
from sitegen.guidepage import (
    NO_ZIP_FAQ,
    folder_words,
    setup_relative,
    setup_routes,
    get_page_title,
    no_zip_line,
)
from sitegen.home import next_block
from sitegen.install import display_name, has_release_pack, platform_display
from sitegen.parts import parent_front_matter
from sitegen.releasepacks import asset_links
from sitegen.versions import release_line, version_line


def _unzip_into(platform_name: str, display: str, extract_to: str | None, parts: int) -> list[str]:
    """Where the ZIP is unzipped, on the get/ page. A folder the registry
    writes relative to the setup's own (`system/`, `bios/`) is named as the
    setup's, with the way to find it."""
    what = "them all" if parts > 1 else "it"
    if not setup_relative(extract_to):
        return [f"- Unzip {what} into {folder_words(display, extract_to)}.", ""]
    guide = platform_guides().get(platform_name)
    lead = guide.lead if guide else ""
    return [
        f"- Unzip {what} into {folder_words(display, extract_to)}. "
        f"[Where is it?](../platforms/{platform_name}.md#where-the-files-go)",
        "",
        *([lead, ""] if lead else []),
    ]


def _pack_lines(platform_name: str, display: str, record: dict, pack: dict) -> list[str]:
    """The ZIP of a release and the command, on its get/ page. A pack in
    parts puts the command first: 3,236 people took part 1 of the RetroArch
    pack and 2,404 part 3, and the command has no part to miss. A pack in
    one file keeps its ZIP first, the command after it."""
    parts = len(pack["assets"])
    release = release_line(platform_name, record)
    extract_to = (load_platform_registry(str(siteinputs.current().platforms)).get(platform_name) or {}).get("extract_to")
    command = setup_routes(platform_name, display)
    download = [
        "This address stays the same. It always gives the latest ZIP.",
        "",
        asset_links(platform_name, record, REPO_URL, f"Download {display} Pack",
                    button=lambda text, url: markup.button(text, url, primary=True)),
        "",
        f"- {size_text(pack['download_size'])} to download, "
        f"{size_text(pack['extracted_size'])} once unzipped.",
        *(["- Both parts are needed." if parts == 2 else f"- All {parts} parts are needed."]
          if parts > 1 else []),
        *_unzip_into(platform_name, display, extract_to, parts),
        *(line for text in release for line in (text, "")),
        version_line(platform_name, record, named=len(release) > 1),
        "",
    ]
    if parts == 1:
        return [*download, *command]
    return [
        f"The ZIP comes in {parts} parts, all needed. The command needs no ZIP. "
        "It installs every file and checks it.",
        "",
        *command,
        f"## Or download the {parts} parts {{ #download }}",
        "",
        *download,
    ]


def get_page_data(platform_name: str) -> dict:
    """The structured data of get/<platform>/: the page changes with the
    release it lists, so its tag is its date, the one the sitemap gives
    (vYYYY.MM.DD). Empty when no release publishes the platform's pack."""
    record = releaserecord.load_advertised()
    tag_date = re.fullmatch(r"v(\d{4})\.(\d{2})\.(\d{2})", str(record.get("tag", "")))
    if has_release_pack(platform_name) and releaserecord.pack_for(platform_name, record) and tag_date:
        return {"dateModified": "-".join(tag_date.groups())}
    return {}


def generate_get_page(platform_name: str) -> str:
    """get/<platform>/: the address a link outside the site can keep.

    Every release deletes the previous tag, and with it each asset URL: six
    of the eight links a wiki had to our packs went dead. This page lists
    the files of the pack the current release holds, read from release.json,
    or the command when no release publishes one. The release process
    never touches it: committing release.json rebuilds it."""
    config = load_platform_config(platform_name, str(siteinputs.current().platforms))
    display = display_name(config, platform_name)
    record = releaserecord.load_advertised()
    pack = releaserecord.pack_for(platform_name, record)
    released = has_release_pack(platform_name)
    title = get_page_title(platform_name, display)
    if released and pack and pack.get("assets"):
        description = (f"The BIOS pack for {display}: {size_text(pack['download_size'])} to "
                       "download. The address stays the same and always gives the latest ZIP.")
    else:
        description = f"The BIOS files for {display}: one command installs and checks them."
    lines = [
        "---", "search: exclude", f"description: {json.dumps(description)}",
        *parent_front_matter((display, f"/platforms/{platform_name}/")), "---", "",
        f"# {title}", "",
    ]
    if released and pack and pack.get("assets"):
        lines += _pack_lines(platform_name, display, record, pack)
    elif released and record.get("tag"):
        lines += [
            f"No {display} ZIP yet. The next release has one. "
            "The command installs every file and checks it.",
            "",
            *setup_routes(platform_name, display),
        ]
    elif released:
        lines += [
            "This address stays the same. It always gives the latest ZIP.",
            "",
            markup.button(f"Download {display} Pack", RELEASE_URL, primary=True),
            "",
        ]
    else:
        lines += [
            no_zip_line(display),
            "",
            *setup_routes(platform_name, display),
            f"[Why no ZIP?](../{NO_ZIP_FAQ})",
            "",
        ]
    lines += sitehandheld.platform_block(platform_name, REPO_ROOT)
    lines += next_block([
        f"[{display}](../platforms/{platform_name}.md#install): the folder, "
        "and how to run the command on the device",
        "[All installer options](../wiki/installer.md)",
    ])
    return "\n".join(lines)


def generate_get_index() -> str:
    """get/: the permanent page of every setup, grouped as the home tiles
    are. A link trimmed to /get/ answered 404."""
    registry = load_platform_registry(str(siteinputs.current().platforms))
    lines = [
        "---", "search: exclude",
        'description: "The BIOS files of every setup, one page each. Each address stays the same."',
        "---", "",
        "# BIOS files by setup", "",
        "One page per setup. Its address stays the same, so it is the one to share.", "",
    ]
    handhelds = handheld_guide()
    for group, (label, _description) in device_groups().items():
        names = [name for name, entry in registry.items() if entry.get("device_group") == group]
        if not names:
            continue
        lines += [f"## {label}", ""]
        for name in names:
            display = platform_display(name)
            lines.append(f"- [{get_page_title(name, display)}]({name}.md)")
        # The handheld app sits with the group whose tile leads to the
        # handheld guide.
        if any(handhelds and tile.link == handhelds.path
               for tile in group_tiles().get(group, ())):
            lines.append(f"- [{sitehandheld.GROUP_TITLE}]({GROUP_PAGE}.md)")
        lines.append("")
    return "\n".join(lines)
