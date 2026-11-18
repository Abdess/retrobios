"""The which-pack page: the folder each setup reads."""

from __future__ import annotations

import release_record
from core.paths import REPO_ROOT
from core.ziptools import build_zip_contents_index
from model import siteinputs
from model.guides import (
    ALSO_RUNS,
    DEVICE_GROUPS,
    GROUP_ANCHORS,
    GUIDES,
    Guide,
    PACKAGE_COMMAND,
    TERMINALS,
    install_command,
)
from model.platforms import load_platform_config
from model.registry import load_platform_registry
from packs.crossref import FileConsumers
from sitegen import markup, steps as sitesteps
from sitegen.config import RELEASE_URL
from sitegen.guidepage import NO_ZIP_FAQ, devices_meta, first_screen_words, get_page_link
from sitegen.guides import fence, terminal_tabs, trust_box
from sitegen.home import _group_keys, _next_block, _runs_on, setup_picker
from sitegen.install import _installer, has_release_pack
from sitegen.readme import NO_PACK, download_links
from sitegen.render import _fmt_size


# Build cross-reference indexes


def _build_file_consumers(db: dict, coverages: dict, profiles: dict) -> FileConsumers:
    """Which platforms and emulators read each collected file."""
    consumers = FileConsumers(db, build_zip_contents_index(db))
    consumers.add_platforms({name: cov["config"] for name, cov in coverages.items()})
    consumers.add_emulators(profiles)
    consumers.add_manifests(REPO_ROOT / "install")
    return consumers


def _build_emulator_file_index(profiles: dict) -> dict[str, dict]:
    """Map emulator_name -> {systems, norm}, for the platform pages.

    norm holds the systems as _norm_system_id reads them: a platform files
    the Mega Drive as sega-mega-drive and genesis_plus_gx as sega-megadrive,
    and an exact match left the RetroArch page with no emulator for it.
    """
    from model.systems import _norm_system_id

    return {
        name: {
            "systems": set(profile.get("systems", [])),
            "norm": {_norm_system_id(str(s)) for s in profile.get("systems", [])},
            # Archive members are read inside their archive, never by name.
            "names": {
                str(entry["name"]).lower()
                for entry in profile.get("files") or []
                if isinstance(entry, dict) and entry.get("name")
                and not entry.get("archive")
            },
        }
        for name, profile in profiles.items()
        if profile.get("type") != "alias"
    }


def _folder_cell(name: str, guide: Guide, prefix: str = "") -> str:
    """The BIOS folder in a table cell, or a link where it depends on the system."""
    if len(guide.folders) > 3:
        return f"Depends on the system: [listed on its page]({prefix}platforms/{name}.md#where-the-files-go)"
    return "<br>".join(f"{label}: {path}" for label, path in guide.folders)


def _pack_cell(name: str, record: dict, prefix: str = "") -> str:
    """The pack's parts and size, or the command where the release has none."""
    if not has_release_pack(name):
        return f"No ZIP. [{NO_PACK}]({prefix}platforms/{name}.md#install)."
    pack = release_record.pack_for(name, record)
    if record.get("tag") and not (pack and pack.get("assets")):
        return f"No ZIP yet. [{NO_PACK}]({prefix}platforms/{name}.md#install)."
    # One small button to the setup's get/ page, which lists every part, and
    # the size after it.
    link = download_links(name, record, "ZIP", page=get_page_link(name, prefix),
                          button=lambda text, url: markup.button(text, url))
    size = pack.get("download_size") if pack else None
    return f"{link} ({_fmt_size(size)})" if size else link


def _own_root_folders(registry: dict) -> dict[str, str]:
    """Platforms whose pack holds its own top folder, with where it unzips.

    The same rule as extract_notes: a list written from an empty base
    destination carries its root in every path."""
    folders = {}
    for key, entry in registry.items():
        config = load_platform_config(key, str(siteinputs.current().platforms))
        if config.get("base_destination") == "" and entry.get("extract_to"):
            folders[key] = entry["extract_to"]
    return folders


def _folder_row(key: str, display: dict[str, str], registry: dict, record: dict,
                own_root: dict[str, str]) -> str:
    """One setup's row: where it runs, its BIOS folder and its ZIP. A setup
    whose ZIP holds its own top folder says where to unzip it, and the
    BIOS folder itself when it has no ZIP to unzip."""
    guide = GUIDES[key]
    pack = release_record.pack_for(key, record)
    zipped = bool(pack and pack.get("assets"))
    folder = (f"Unzip into `{own_root[key]}`" if key in own_root and zipped
              else _folder_cell(key, guide))
    return (f"| [{display[key]}](platforms/{key}.md) | "
            f"{guide.runs_on or _runs_on(registry[key], guide)} | {folder} | "
            f"{_pack_cell(key, record)} |")


def _folder_tables(registry: dict, record: dict, display: dict[str, str]) -> list[str]:
    """Every setup's folder and ZIP, one table per device group, the groups
    of one setup together under "Other setups" as on the tiles. A row for
    each setup that runs another (LaunchBox, Android) under its group."""
    own_root = _own_root_folders(registry)
    header = ["| Setup | Runs on | BIOS folder | ZIP |", "|-------|---------|-------------|-----|"]
    lines: list[str] = []
    alone: list[str] = []
    for group, (label, _description) in DEVICE_GROUPS.items():
        members = _group_keys(registry, group, display)
        if len(members) == 1 and not ALSO_RUNS.get(group):
            alone += members
            continue
        if not members:
            continue
        lines += [f'<span id="{GROUP_ANCHORS[group]}"></span>**{label}**', "", *header]
        lines += [_folder_row(key, display, registry, record, own_root) for key in members]
        lines += [
            f"| {setup} | {runs_on} | {folder}, same as "
            f"[{display[uses]}](platforms/{uses}.md) | {_pack_cell(uses, record)} |"
            for setup, _summary, uses, runs_on, folder in ALSO_RUNS.get(group, ())
        ]
        lines.append("")
    if alone:
        anchors = "".join(f'<span id="{GROUP_ANCHORS[registry[key]["device_group"]]}"></span>'
                          for key in alone)
        lines += [f"{anchors}**Other setups**", "", *header,
                  *(_folder_row(key, display, registry, record, own_root) for key in alone), ""]
    return lines


# iPhone and iPad: no terminal, so each app is filled its own way. Every
# step is the app's own: RetroArch's iOS guide (Files app, On My iPhone >
# RetroArch) and platform_darwin.m (system under Documents/RetroArch), the
# DS BIOS rows of Delta's Settings.storyboard, Provenance's import guide.
IOS_SOURCES = {
    "retroarch_docs": "https://github.com/libretro/docs/blob/"
                      "cfa4c1a17e586c01d3a48e9eda12b6c989f8954f/docs/guides/install-ios.md?plain=1#L94",
    "retroarch_code": "https://github.com/libretro/RetroArch/blob/"
                      "5333a7c5a59e268470834a96f86047d3cb6139a9/frontend/drivers/platform_darwin.m#L438-L459",
    "delta": "https://github.com/rileytestut/Delta/blob/"
             "c1d3d068e019e6493eed45654569db3cc5beb86a/Delta/Base.lproj/Settings.storyboard#L2448-L2500",
    "provenance": "https://wiki.provenance-emu.com/using-provenance/importing-roms",
}
IOS_DEVICES = ("iPhone", "iPad", "iOS", "Delta", "Provenance")
# The same names as which-pack's search terms, the section's meta field
# alone leaving "ios" unanswered.
IOS_TERMS = tuple(name.lower() for name in IOS_DEVICES)


def ios_section() -> list[str]:
    """The section the iPhone and iPad tile opens: the consoles picked on a
    computer, then each app's own way in."""
    return [
        "## iPhone and iPad { #iphone-and-ipad }",
        "",
        devices_meta(IOS_DEVICES),
        "",
        "[Pick the consoles](which-pack.md?platform=retroarch#only-some-consoles) "
        "on a computer. Copy them to the app.",
        "",
        "- **RetroArch**: Files app, **On My iPhone > RetroArch**, then "
        f"`RetroArch/system/` ([docs]({IOS_SOURCES['retroarch_docs']}), "
        f"[code]({IOS_SOURCES['retroarch_code']})).",
        "- **Delta**, for DS games: import `bios7.bin`, `bios9.bin` and `firmware.bin` "
        f"in **Settings**, under **Nintendo DS** ([code]({IOS_SOURCES['delta']})).",
        "- **Provenance**: share the file, then **Copy to Provenance** "
        f"([docs]({IOS_SOURCES['provenance']})).",
        "",
    ]


def generate_which_pack() -> str:
    """The device picker: every registered platform as a tile under the
    device it runs on, the ZIP advice with every folder and ZIP in one closed
    table, the console picker, and the command for a setup not listed.

    The tiles are the choice. Open tables under them listed every setup a
    second time and made the page 11,800 px tall on a phone."""
    registry = load_platform_registry(str(siteinputs.current().platforms))
    record = release_record.load_advertised()
    display = {key: load_platform_config(key, str(siteinputs.current().platforms)).get("platform", key)
               for key in registry}
    all_tabs = ("windows", "macos", "linux", "steamdeck", "android")
    # The quick install box also runs on a game system: its tab shows the
    # handheld recording (sitesteps).
    box_tabs = (*all_tabs, "device")
    box_steps, box_demos = sitesteps.install_box(box_tabs)
    # Python is on most Linux and macOS machines: the package runs the same
    # installer there without the bootstrap.
    for tab in ("macos", "linux"):
        box_demos[tab] = [*box_demos[tab],
                          f"With Python 3.8 or newer, `{PACKAGE_COMMAND}` does the same.", ""]
    lines = [
        "---",
        f"terms: {', '.join(IOS_TERMS)}",
        "---",
        "",
        "# Get the files",
        "",
        "Pick the setup. Its page gives the folder and the command.",
        "",
        "## Pick the setup { #pick-your-setup }",
        "",
        *setup_picker(registry, display),
        "## Folders and ZIP files { #manual-download }",
        "",
        "- A big ZIP comes in parts, like `Pack.part1of2.zip`. Download every part.",
        "- Unzip them into the BIOS folder. Put the files straight in it, "
        "not in a new folder.",
        "- Leave the ZIPs inside, like `neogeo.zip`, as they are.",
        "- A few ZIPs hold their own top folder. Their setup's page says where "
        "to unzip them.",
        "",
        *markup.details("note", "Every folder and ZIP in one table",
                        _folder_tables(registry, record, display)),
    ]
    pending = any(has_release_pack(key) and not (pack and pack.get("assets"))
                  for key, pack in ((key, release_record.pack_for(key, record)) for key in registry))
    if record.get("tag") and pending:
        lines += ["Setups added after the last release have no ZIP until the next one.", ""]
    lines += ["No ZIP on a row: the command serves that setup. ZIPs are made for the "
              f"setups most people download. [Why?]({NO_ZIP_FAQ})", ""]
    lines += [
        f"The ZIPs come from the [latest release]({RELEASE_URL}). The command may "
        "install newer files.",
        "",
        "## Only some consoles?",
        "",
        "Pick them here, and get the files and the command. Or use the command's "
        f"**{_installer().TUI_SYSTEMS_ROW}**.",
        "",
        "<FilePicker />",
        "",
        *ios_section(),
        "## Not in the list? One command finds it { #quick-install }",
        "",
        "A **terminal** is a window for typing commands.",
        "",
        *terminal_tabs(box_tabs, {}, under_steps=box_steps, under_command=box_demos),
        "On Batocera, Recalbox and other game systems, run it on the device. "
        "The setup's page shows how.",
        "",
        *first_screen_words(),
        "",
        *trust_box(""),
        "**Check the folder later.** Add `--check`. It changes nothing.",
        "",
        *terminal_tabs(all_tabs, dict.fromkeys(TERMINALS, "--check"), steps=False),
        *markup.details("note", "Fill an SD card from a computer", [
            "Name the setup and the BIOS folder on the card. For RetroArch on a "
            "Nintendo Switch:",
            "",
            "Linux, macOS:",
            "",
            *fence("sh", install_command(
                "sh", "--platform retroarch --dest /path/to/sdcard/retroarch/cores/system")),
            "",
            "Windows (PowerShell, E: being the card):",
            "",
            *fence("powershell", install_command(
                "powershell", "--platform retroarch --dest E:\\retroarch\\cores\\system")),
        ]),
        *markup.details("note", "Copy the BIOS files from an old card", [
            "Plug the old card in and add `--from` with its folder. The BIOS files "
            "found there are copied, and the rest downloaded. The old card is only read.",
            "",
            "Linux, macOS:",
            "",
            *fence("sh", install_command("sh", "--from /media/me/OLDCARD")),
            "",
            "Windows (PowerShell, E: being the old card):",
            "",
            *fence("powershell", install_command("powershell", "--from E:\\")),
        ]),
        "Details: [All installer options](wiki/installer.md).",
        "",
        *_next_block([
            "[First install, step by step](wiki/first-install.md)",
            "[When a game does not start](wiki/troubleshooting.md)",
        ]),
    ]
    return "\n".join(lines) + "\n"
