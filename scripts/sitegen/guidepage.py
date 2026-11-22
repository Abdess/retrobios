"""The setup guide atop each platform page: download, install and the handheld guide."""

from __future__ import annotations

import html
import json

from core.text import series
from model import releaserecord
from model import siteinputs
from model.collection import profiles_on_disk
from model.guides import (
    GUIDES,
    Guide,
    HandheldGuide,
    HandheldSystem,
    TERMINALS,
    detected_systems as _detected_systems,
)
from model.registry import load_platform_registry
from resolve.nativemode import digest_algorithm
from installer_build.handhelds import GROUP_PAGE
from sitegen import handheld as sitehandheld, markup
from core.sizes import size_text
from sitegen.guides import platform_args, terminal_tabs
from sitegen.home import next_block
from sitegen.install import installer_module, has_release_pack, platform_display
from sitegen.extraction import extract_notes
from sitegen.releasepacks import download_links
from sitegen.versions import release_line, setup_version, version_line


# Why a setup has no ZIP, answered once on the FAQ.
NO_ZIP_FAQ = "wiki/faq.md#why-is-there-no-zip-for-my-setup"


def no_zip_line(display: str) -> str:
    """The one line a setup without a release pack shows where the ZIP would be."""
    return f"No ZIP for {display}. The command installs every file and checks it."


def get_page_link(platform_name: str, prefix: str = "") -> str:
    """The platform's permanent download page, as a site link."""
    return f"{prefix}{releaserecord.GET_DIR}/{platform_name}.md"


def get_page_title(platform_name: str, display: str) -> str:
    """What a get/ page holds, by its name: the ZIP of a setup a release
    publishes one for, the files of any other. "Download KNULLI" read as
    the system's own download. A setup that is also an emulator (BizHawk)
    names it last: "BizHawk BIOS files" is the title of its emulator page.
    A profile listing no file (the RetroArch frontend) titles its page
    "... emulator", which no setup title repeats."""
    kind = "BIOS pack" if has_release_pack(platform_name) else "BIOS files"
    if (profiles_on_disk().get(platform_name) or {}).get("files"):
        return f"{kind} for {display}"
    return f"{display} {kind}"


def setup_relative(extract_to: str | None) -> bool:
    """Whether the registry writes the folder relative to the setup's own
    (`system/`, `Firmware/`), not as a path the device reads."""
    if not extract_to:
        return False
    return not extract_to.startswith(("/", "~", "<"))


def folder_words(display: str, extract_to: str | None) -> str:
    """The folder a pack or a copy goes into, in words: the device's path,
    or a folder of the setup named as the setup's."""
    if not extract_to:
        return "the BIOS folder"
    if setup_relative(extract_to):
        return f"{display}'s `{extract_to.rstrip('/')}` folder"
    return f"`{extract_to}`"


def pack_buttons(platform_name: str, label: str = "Pack", prefix: str = "../",
                  display: str | None = None) -> str:
    """The way to the platform's ZIP from its setup page: a button to its
    get/ page, the release it comes from, and the setup version its list
    was read at. "Does this pack fit my version?" is the first question a
    frontend user asks. A setup with no release pack gets the line that
    says so, and why."""
    if not has_release_pack(platform_name):
        display = display or platform_display(platform_name)
        return f"{no_zip_line(display)} [Why no ZIP?]({prefix}{NO_ZIP_FAQ})"
    record = releaserecord.load_advertised()
    buttons = download_links(
        platform_name,
        record,
        label,
        button=lambda text, url: markup.button(text, url, primary=True),
        page=get_page_link(platform_name, prefix),
    )
    released = release_line(platform_name, record)
    return "\n\n".join([buttons, *released,
                        version_line(platform_name, record, named=len(released) > 1,
                                     prefix=prefix)])


def _check_sentence(display: str, mode: str, config: dict, no_list: bool) -> str:
    """What the frontend itself checks, from the mode its code uses."""
    if no_list:
        return (f"{display} has no BIOS list, so it checks nothing itself. Each "
                "emulator looks for its own files when a game starts.")
    if config.get("hash_rule") == "size_and_any_hash":
        return f"{display} also checks each file's size and contents."
    if digest_algorithm(mode):
        return f"{display} also checks each file's contents."
    return f"{display} checks names only. `--check` also checks contents."


def _folder_rows(rows: tuple[tuple[str, str], ...], indent: str = "") -> list[str]:
    return [
        f"{indent}| Where | BIOS folder |",
        f"{indent}|-------|-------------|",
        *(f"{indent}| {label} | {path} |" for label, path in rows),
    ]


# The second most asked question about BIOS files (14 % of the community
# sample): the file is there and the setup still reports it missing.
# `--check` lists every file whose hash is wrong by name (install.py, the
# "wrong hash" lines of check_lines).
MISSING_IN_PLACE = "Reported missing anyway? `--check` names a wrong file."

# Under every command of a setup page: the safety list is the one the home
# page shows in full, so the setup page links it.
SAFE_LINK = "[Is it safe?](../index.md#is-it-safe)"

def first_screen_words() -> list[str]:
    """What a beginner sees when the command runs, the screen's own words
    read from install.py: the one-liner opens the full screen, and the page
    showed a line menu (Enter, i, c, q) nobody saw, whose keys had changed
    since."""
    installer = installer_module()
    # The screen it opens first: the setup found, or the list when none
    # is. Install comes on the next one, Choose systems beside it and named
    # above on the page.
    # Nothing found, the folder comes before Install: which-pack left it
    # out.
    return [f"It asks **{installer.TUI_FOUND_TITLE}** (or **{installer.TUI_CHOOSE_TITLE}** "
            f"and **{installer.TUI_FOLDER_TITLE}**), then offers **{installer.TUI_INSTALL_ROW}**."]


# The demo files the site serves (docs_assets/demo/, scripts/make_demo.py):
# the GIF is the README's, the tape and demo.json are inputs.
DEMO_ASSETS = tuple(f"{stem}.{ext}" for stem in ("install", "install-handheld")
                    for ext in ("webm", "mp4", "png"))


def check_pass_line() -> str:
    """The pass line of "How to check": the words `--check` prints only when
    no file is missing or wrong (install.py EVERYTHING_IN_PLACE), read from
    the installer. Typed here, it kept "All files up to date." after the
    installer said "Everything is in place."."""
    return f"Good result: `{installer_module().EVERYTHING_IN_PLACE}`"

# Under "From your computer": a device with no network installs from the ZIP
# (`--from-pack`). The id is the one wiki/installer.md gives its section.
OFFLINE_LINE = ("No internet on the device? "
                "[Install from the ZIP](../wiki/installer.md#without-a-network-offline-install).")


def _network_share(name: str, guide: Guide) -> str:
    """The network folder a computer fills, for a setup that runs on its own
    device and has no ZIP: the command runs on the computer and writes
    there. Empty when the page cites no such folder."""
    if guide.run != ("device",) or _computer_first(name, guide):
        return ""
    for label, path in guide.folders:
        if label.startswith("From Windows") and path.startswith("`\\\\"):
            return path.strip("`").rstrip("\\")
    return ""


def _share_tabs(name: str, share: str) -> tuple[dict[str, str], dict[str, str]]:
    """The command per computer for a network folder (\\\\RECALBOX\\share\\bios),
    and how a Mac or a Linux desktop opens that folder first. Only Windows
    had a line: a Mac user fell back to SSH or to taking the card out.

    macOS mounts smb://recalbox/share at /Volumes/share. A Linux desktop
    mounts it where its file manager chooses, so that tab names the folder.
    """
    host, _, rest = share.lstrip("\\").partition("\\")
    volume, _, below = rest.partition("\\")
    url = f"smb://{host.lower()}/{volume}"
    tail = "/" + below.replace("\\", "/") if below else ""
    args = {
        "windows": f"--platform {name} --dest {share}",
        "macos": f"--platform {name} --dest /Volumes/{volume}{tail}",
        "linux": f"--platform {name} --dest /path/to/{volume}{tail}",
    }
    how = {
        "macos": (f"In Finder, Go > Connect to Server: `{url}`. Then paste the line in "
                  "**Terminal**."),
        "linux": (f"Open `{url}` in the file manager. Paste the line in a terminal, "
                  f"with the folder it opened for `/path/to/{volume}`."),
    }
    return args, how


def _offline_line(name: str) -> list[str]:
    """The offline line, on a setup whose ZIP a release publishes: the
    installer reads that ZIP with no network (`--from-pack`)."""
    pack = releaserecord.pack_for(name, releaserecord.load_advertised())
    return [OFFLINE_LINE, ""] if pack and pack.get("assets") else []


# The route of a setup with no ZIP when the device has no network: the
# command writes to any folder named after --dest (wiki/installer.md), so a
# computer fills the device's card. The FAQ answers it with an example.
CARD_ROUTE_FAQ = "wiki/faq.md#fill-an-sd-card-from-a-computer"


def _card_route(name: str, display: str, guide: Guide) -> list[str]:
    """The route with no network on the device, for a setup whose ZIP no
    release publishes: the command run on a computer, into the card. A
    setup with a ZIP has the offline line, a card setup's command already
    runs on the computer. The folder named after --dest is the one the
    command fills on the device (the registry's extract_to): AmberELEC's is
    `/storage/roms/`, which holds `bios/` and `neogeo/`. How a computer
    sees it is the reader's to name: no guide cites it."""
    if guide.on_card or _offline_line(name):
        return []
    extract_to = (load_platform_registry(str(siteinputs.current().platforms)).get(name) or {}).get("extract_to")
    leaf = (extract_to or "bios").rstrip("/").rsplit("/", 1)[-1].lstrip("~") or "bios"
    tabs = guide.card_run or ("windows", "macos", "linux")
    args = {key: f"--platform {name} --dest "
                 + (f"E:\\path\\to\\{leaf}" if key == "windows" else f"/path/to/{leaf}")
            for key in tabs}
    if guide.run != ("device",):
        lead = ("No network here? Run the command on a computer that has one, with a USB "
                f"drive's folder after `--dest`. Then copy it into {folder_words(display, extract_to)}.")
        return [lead, "", *terminal_tabs(tabs, args, steps=False)]
    # A folder on the card's Linux partition: Windows and macOS show the
    # small boot partition alone, and no folder there fits --dest.
    put = ("Put the device's card in a computer." if "windows" in tabs
           else "Only a Linux computer opens the card.")
    lead = (f"No network? {put} After `--dest`, "
            f"name the folder the device calls `{extract_to}`.")
    return [lead, "", *terminal_tabs(tabs, args, steps=False),
            f"[More on SD cards](../{CARD_ROUTE_FAQ})", ""]


def _get_page_line(name: str, display: str) -> list[str]:
    """The setup's get/ page, under the command of a setup with no ZIP: the
    address a guide writer keeps. A setup with a ZIP links it by its button."""
    if has_release_pack(name):
        return []
    return [f"Link to share: [{get_page_title(name, display)}](../{get_page_link(name)})", ""]


def setup_routes(name: str, display: str, page_link: bool = False) -> list[str]:
    """The ways to run the command for a setup no ZIP serves first, written
    once for its setup page and its get/ page: the network folder from a
    computer, the card from a computer when the device has no network, and
    the device's own terminal. *page_link* adds the get/ page, on the setup
    page only."""
    guide = GUIDES[name]
    share = _network_share(name, guide)
    card = _card_route(name, display, guide)
    shared = _get_page_line(name, display) if page_link else []
    if share or (card and guide.run == ("device",)):
        computer = ["## From a computer { #from-your-computer }", ""]
        if share:
            args, how = _share_tabs(name, share)
            # The setup page stays in its word budget: its Mac and Linux
            # lines are on the get/ page, the one the command is shared from.
            tabs = ("windows",) if page_link else ("windows", "macos", "linux")
            computer += [
                "Needs the device on the same network.",
                "",
                *terminal_tabs(tabs, args, how=how),
                *([f"[Mac or Linux](../{get_page_link(name)}#from-your-computer)", ""]
                  if page_link else []),
                SAFE_LINK,
                "",
            ]
        return [*computer, *card,
                *_guide_install(name, guide, "## On the device { #install }"), *shared]
    return [*_guide_install(name, guide, "## Install"), *shared, *card]


# Shown in the "On the device" tab of a guide that has no `terminal:` of its own.
DEVICE_TERMINAL_FALLBACK = "Or fill the folder from a computer, with the ZIP."


def _computer_first(name: str, guide: Guide) -> bool:
    """A system that runs only on its own device, with a ZIP to download: a
    beginner fills its folder from a computer more easily than from a
    terminal on the TV. Without a ZIP the command is the only route."""
    pack = releaserecord.pack_for(name, releaserecord.load_advertised())
    return guide.run == ("device",) and bool(pack and pack.get("assets"))


def _ships_neogeo(name: str) -> bool:
    """Whether the setup's files hold `neogeo.zip`, the archive a reader most
    often unzips by mistake: arcade BIOS sets are read zipped."""
    manifest = siteinputs.manifests_dir() / f"{name}.json"
    if not manifest.is_file():
        return False
    files = json.loads(manifest.read_text(encoding="utf-8")).get("files", [])
    return any(f.get("dest", "").rsplit("/", 1)[-1] == "neogeo.zip" for f in files)


def _guide_download(name: str, display: str, guide: Guide, extract_to: str | None,
                    heading: str) -> list[str]:
    """The pack: its buttons, its size, and where it is unzipped."""
    lines = [heading, ""]
    record = releaserecord.load_advertised()
    pack = releaserecord.pack_for(name, record)
    network = any(label.startswith("From ") for label, _path in guide.folders)
    if pack and pack.get("assets"):
        parts = len(pack["assets"])
        bullets = [
            f"{size_text(pack['download_size'])} to download, "
            f"{size_text(pack['extracted_size'])} once unzipped."
        ]
        if parts > 1:
            bullets.append("Both parts are needed." if parts == 2 else f"All {parts} parts are needed.")
        if _computer_first(name, guide) and network:
            target = "the network folder above"
        else:
            target = f"`{extract_to}`" if extract_to else "the BIOS folder"
        bullets.append(f"Unzip {'them all' if parts > 1 else 'it'} into {target}."
                       + (" Files like `neogeo.zip` stay zipped." if _ships_neogeo(name) else ""))
        if guide.download_hint and not _computer_first(name, guide):
            bullets.append(guide.download_hint)
        lines += [
            pack_buttons(name, f"Download {display} Pack"),
            "",
            *(f"- {b}" for b in bullets),
            "",
        ]
    elif not has_release_pack(name):
        lines += [pack_buttons(name, display=display), ""]
    elif record.get("tag"):
        made_from = setup_version(name)
        lines += [
            f"No {display} ZIP yet. The command installs the same files"
            + (f", made for {made_from}." if made_from else "."),
            "",
        ]
    else:
        lines += [pack_buttons(name, f"Download {display} Pack"), ""]
    return [*lines, *only_some_consoles(name, "../")]


def only_some_consoles(name: str, prefix: str = "") -> list[str]:
    """The way to a smaller download, in the words Get the files uses."""
    return [
        f"Only some consoles? [Pick them]({prefix}which-pack.md?platform={name}"
        f"#only-some-consoles), or the command's **{installer_module().TUI_SYSTEMS_ROW}**.",
        "",
    ]


def _guide_install(name: str, guide: Guide, heading: str) -> list[str]:
    """The command, in a tab per place it runs, and whether it is safe."""
    lines = [
        heading,
        "",
        "It finds the folder and checks each file.",
        "",
    ]
    if guide.on_card:
        lines += [
            "Put the SD card in a computer. On Windows, note its letter, like "
            "**E:**. Put the card's path after `--dest`.",
            "",
        ]
    device = guide.terminal or f"{TERMINALS['device'][1]} {DEVICE_TERMINAL_FALLBACK}"
    return [
        *lines,
        *terminal_tabs(guide.run, platform_args(name, guide), how={"device": device}),
        SAFE_LINK,
        "",
    ]


def devices_meta(devices: tuple[str, ...]) -> str:
    """The device names a reader types, as the `devices` search field of the
    page: an attribute on an empty element, commas out (the search engine
    splits its keys on commas), so no excerpt shows them."""
    names = " ".join(name.replace(",", " ") for name in devices)
    return f'<span data-pagefind-meta="devices:{html.escape(names, quote=True)}"></span>'


# Devices named in a row of the handheld guide. The rest stay in the
# page's search field and on the list the row links.
HANDHELD_ROW_DEVICES = 6


# Where a handheld row with no cited folder sends the reader: the setting
# that shows RetroArch's BIOS folder, the words of the RetroArch page.
RETROARCH_FOLDER_SETTING = ("In RetroArch, open **Settings > Directory > System/BIOS**. "
                            "It shows the folder.")
# After a folder on a part of the card only Linux reads.
LINUX_ONLY_HINT = ("Copy from a Linux computer, or check the folder in RetroArch's "
                   "**Settings > Directory > System/BIOS**.")


def _handheld_row(system: HandheldSystem) -> str:
    shown = ", ".join(system.devices[:HANDHELD_ROW_DEVICES])
    more = len(system.devices) - HANDHELD_ROW_DEVICES
    devices = (f"{shown}{f' and {more} more' if more > 0 else ''} "
               f"([list]({system.devices_source}))" if system.devices else "")
    if not system.folder:
        folder = RETROARCH_FOLDER_SETTING
    else:
        folder = f"{system.folder} ([source]({system.folder_source}))"
        if system.linux_only:
            folder += f". {LINUX_ONLY_HINT}"
    return f"| {handheld_name(system)} | {devices} | {folder} |"


def handheld_name(system: HandheldSystem) -> str:
    """A system's cell: its name, and for one that stopped, that it did and
    what replaced it, with the project's own page saying so."""
    return (f"{system.name}, {system.ended} ([source]({system.ended_source}))"
            if system.ended else system.name)


def generate_handheld_guide(guide: HandheldGuide) -> str:
    """The guide for the handheld systems that run a setup (ArkOS, muOS,
    Onion... run RetroArch): one row per system the installer detects, the
    folder seen on the card from a computer and the devices, each cited from
    the system's own pages, then that setup's ZIP and the command for a card.

    A handheld owner starts from the device name. The systems were named
    only in a closed note, with a path seen from inside the device."""
    uses = GUIDES[guide.uses]
    display = platform_display(guide.uses)
    args = {"windows": f"--platform {guide.uses} --dest E:\\BIOS",
            "macos": f"--platform {guide.uses} --dest /path/to/card/BIOS",
            "linux": f"--platform {guide.uses} --dest /path/to/card/BIOS"}
    return "\n".join([
        f"# {guide.title}",
        "",
        guide.summary,
        "",
        devices_meta(guide.devices),
        "",
        "[Download](#download)",
        "",
        "## Where the files go { #where-the-files-go }",
        "",
        "Put the SD card in a computer. Find the system below.",
        "",
        "| System | Devices | BIOS folder on the card |",
        "|--------|---------|-------------------------|",
        *(_handheld_row(system) for system in guide.systems),
        "",
        *_guide_download(guide.uses, display, uses, None, "## Download { #download }"),
        *_offline_line(guide.uses),
        f"On {series(sitehandheld.group_systems(), 'or')}: "
        f"[{sitehandheld.GROUP_TITLE}]"
        f"(../get/{GROUP_PAGE}.md).",
        "",
        "## Fill the card from a computer { #install }",
        "",
        "On Windows, note the card's letter, like **E:**. Put its BIOS folder after "
        "`--dest`, written as in the table.",
        "",
        *terminal_tabs(("windows", "macos", "linux"), args),
        SAFE_LINK,
        "",
        *next_block([
            f"[{display}]({guide.uses}.md): every folder and every file",
            "[When a game does not start](../wiki/troubleshooting.md)",
        ]),
    ]) + "\n"


def platform_guide(name: str, display: str, cov: dict, registry: dict, no_list: bool) -> list[str]:
    """The guide part of a platform page: folder, command, pack, check, next.

    A system that runs only on its own device puts the computer route
    (download, unzip into the network folder) before the command."""
    guide = GUIDES[name]
    entry = registry.get(name, {})
    extract_to = entry.get("extract_to")
    # An app's page opens on the command: one line to paste is the shortest
    # way to a working setup, and the folder table is what a manual copy needs.
    lines = ["## Where the files go", ""]
    if guide.lead:
        lines += [guide.lead, ""]
    lines += _folder_rows(guide.folders)
    if extract_to and has_release_pack(name):
        lines.append(f"| Unzip the pack into | `{extract_to}` |")
    lines.append("")
    for note in guide.notes:
        lines += [note, ""]
    lines += [line for note in extract_notes(str(siteinputs.current().platforms), released_only=True)
              if f"The {display} pack " in note
              for line in (note, "")]
    if guide.more_folders:
        detected = _detected_systems(registry, name) if guide.more_folders_detected else []
        lines += markup.details("note", guide.more_folders_title, [
            *_folder_rows(guide.more_folders),
            *(f"| {system} | `{folder}` |" for system, folder in detected),
            "",
            *([guide.more_folders_note, ""] if guide.more_folders_note else []),
        ])
    if guide.on_card:
        lines += ["<!-- image: minui-card -->", ""]
    if _computer_first(name, guide):
        # The ZIP copied over the network needs the folder table above it.
        lines += [
            *_guide_download(name, display, guide, extract_to,
                             "## From a computer { #download }"),
            *_offline_line(name),
            *_guide_install(name, guide, "## On the device { #install }"),
        ]
    else:
        where = lines
        lines = [
            *setup_routes(name, display, page_link=True),
            *_guide_download(name, display, guide, extract_to, "## Download"),
            *_offline_line(name),
            *where,
        ]
    check_args = {key: f"{args} --check" for key, args in platform_args(name, guide).items()}
    lines += [
        "## How to check",
        "",
        "Add `--check` to the command. It changes nothing.",
        "",
        *terminal_tabs(guide.run, check_args, steps=False),
        check_pass_line(),
        "",
        _check_sentence(display, cov["mode"], cov["config"], no_list),
        "",
        MISSING_IN_PLACE,
        "",
        *([guide.finish, ""] if guide.finish else []),
        *next_block([
            "[First install, step by step](../wiki/first-install.md)",
            "[When a game does not start](../wiki/troubleshooting.md)",
        ]),
    ]
    return lines
