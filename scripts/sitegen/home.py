"""The home and explore pages: the setup picker and the collection in figures."""

from __future__ import annotations

import html

from core.paths import PLATFORMS_DIR
from model.composition import compute_composition
from model.guides import DEVICE_GROUPS, GROUP_TILES, GUIDES, Guide, TRUST_ITEMS, setup_count
from model.platforms import load_platform_config
from model.profiles import unique_emulator_profiles
from model.registry import load_platform_registry
from sitegen import markup
from sitegen.readme import demo_description, demo_facts
from sitegen.render import fmt_size


# Home page


def stat_block(value: str, label: str) -> list[str]:
    return [
        markup.block_open("div", 'class="rb-stat"'),
        # One line, a space between: the page text read "168/168Coverage".
        f'<span class="rb-stat-value">{value}</span> <span class="rb-stat-label">{label}</span>',
        "</div>",
        "",
    ]


def group_members(coverages: dict, registry: dict, group: str) -> list[str]:
    """Registered platforms of a device group, by display name."""
    return sorted(
        (name for name in coverages if registry.get(name, {}).get("device_group") == group),
        key=lambda name: coverages[name]["platform"].casefold(),
    )


def next_block(links: list[str]) -> list[str]:
    """Where to go from here, at the end of a page: a plain heading and a
    list. A tinted callout with a side stripe said the same as the pager."""
    return ["## Next steps", "", *(f"- {link}" for link in links), ""]


def _tiles(registry: dict, members: list[str], display: dict[str, str], prefix: str = "",
           group: str = "", eager: int = 0) -> list[str]:
    """The setup tiles of one device group: logo, name and the hardware it
    runs on, then the group's other tiles: a kind of device that runs one of
    the setups (Android handhelds, Linux handhelds)."""
    return markup.platform_tiles([
        *((display[name], f"{prefix}platforms/{name}.md",
           str(registry.get(name, {}).get("logo") or ""),
           GUIDES[name].runs_on or runs_on_text(registry.get(name, {}), GUIDES[name]))
          for name in members),
        *((tile.name, f"{prefix}{tile.link}", tile.logo, tile.text)
          for tile in GROUP_TILES.get(group, ())),
    ], eager=eager)


def setup_picker(registry: dict, display: dict[str, str], prefix: str = "") -> list[str]:
    """Every setup as a tile, under the device group it belongs to. The
    setups alone in their group share one row: "MiSTer FPGA" above
    "MiSTer FPGA" said nothing. Only the first row of logos loads with the
    page: the 19 logos were most of the bytes of the home page."""
    lines: list[str] = []
    alone: list[str] = []
    for group, (label, _description) in DEVICE_GROUPS.items():
        members = group_keys(registry, group, display)
        if len(members) == 1 and not GROUP_TILES.get(group):
            alone += members
        elif members:
            eager = 0 if lines else markup.FIRST_ROW_TILES
            lines += [f"**{label}**", "",
                      *_tiles(registry, members, display, prefix, group, eager)]
    if alone:
        eager = 0 if lines else markup.FIRST_ROW_TILES
        lines += ["**Other setups**", "", *_tiles(registry, alone, display, prefix, eager=eager)]
    return lines


def generate_home(
    db: dict,
    coverages: dict,
    profiles: dict,
    registry: dict | None = None,
    platforms_dir: str = PLATFORMS_DIR,
) -> str:
    """The page someone lands on knowing nothing: what a BIOS file is,
    whether they need one, and the three steps to get the right ones.

    The figures about the collection, the cards to the deeper pages and the
    call for help sat below the steps and doubled the page: they are on the
    Explore index, one tab further. No date and no "next" box: the hero
    buttons say where to go."""
    registry = registry or load_platform_registry(platforms_dir)
    display = {key: load_platform_config(key, platforms_dir).get("platform", key)
               for key in registry}
    named = [n for n in ("RetroArch", "Batocera", "EmuDeck") if n in display.values()]
    others = setup_count() - len(named)
    works_with = ", ".join(named) + (f" and {others} more" if others else "")

    lines = [
        "# BIOS files for emulators",
        "",
        "Some consoles need a small program to start their games. It is called "
        "the **BIOS**. The emulator needs a copy of it. RetroBIOS puts the right copy "
        "in the right folder.",
        "",
        markup.button("Get the files", "which-pack.md", primary=True) + " "
        + markup.button("What is a BIOS?", "wiki/what-are-bios-files.md"),
        "",
        f"Free. No account. Works with {works_with}.",
        "",
        "- BIOS missing, even with the file there? "
        "[When a game does not start](wiki/troubleshooting.md)",
        "- Have a file? [Check it](files/index.md)",
        "",
        "## Is it needed? { #do-i-need-it }",
        "",
        "- **Yes**, if the emulator says a BIOS is missing.",
        "- **Yes** for PlayStation 2 and Neo Geo.",
        "- **Better with it** for Dreamcast: some games need it.",
        "- **Usually not** for NES, Super Nintendo, Mega Drive and Game Boy.",
        "",
        "Details: [Every console, one by one](systems/index.md)",
        "",
        "## Three steps",
        "",
        *markup.steps([
            "**Pick the device.** Its page gives one line to copy.",
            "**Paste it, press Enter.** Some setups have a ZIP.",
            "**Start a game.**",
        ]),
        *install_demo(),
        "## Pick the device { #pick-your-device }",
        "",
        *setup_picker(registry, display),
        "## Is it safe?",
        "",
        *(f"- {item}" for item in TRUST_ITEMS),
        "",
        "[How the command is checked](wiki/faq.md#is-piping-the-installer-into-a-shell-safe). "
        "Details: [Is it legal?](wiki/legal.md)",
        "",
    ]
    return "\n".join(lines) + "\n"


def generate_explore_index(db: dict, coverages: dict, profiles: dict) -> str:
    """The Explore tab opens here: where to look for one console, one
    emulator or one installer option, and the figures of the collection."""
    total_files = db.get("total_files", 0)
    total_size = db.get("total_size", 0)
    emulator_count = len(unique_emulator_profiles(profiles))
    lines = [
        "# Explore",
        "",
        "One console, one emulator, or one installer option: each has its page, "
        "with the files it needs and the code that reads them.",
        "",
        *markup.card_grid([
            ("Systems", ["What each console and computer needs, file by file.", "",
                         "[Browse the systems](systems/index.md)"]),
            ("Emulators", ["What each emulator reads, with the source code that reads it.", "",
                           "[Browse the emulators](emulators/index.md)"]),
            ("Installer options", [
                "Fewer files, one region, another folder, a check without download.", "",
                "[All installer options](wiki/installer.md)"]),
            ("How files are checked", [
                "Each setup checks its files its own way: by name, by MD5 or by SHA1.", "",
                "[How each platform checks files](wiki/verification-modes.md)"]),
            ("Data and API", ["Every file and hash as JSON, CSV and SQLite.", "",
                              "[Data and API](data.md)"]),
        ]),
        "## The collection",
        "",
        markup.block_open("div", 'class="rb-stats"'),
        "",
        *stat_block(f"{total_files:,}", COLLECTION_FILES_LABEL),
        *stat_block(str(setup_count()), "Setups supported"),
        *stat_block(str(emulator_count), "Emulators documented"),
        *stat_block(fmt_size(total_size), "Size of the collection"),
        "</div>",
        "",
        composition_sentence(db),
        "",
        "## Help the project",
        "",
        "A file sent in, an emulator profile or a correction fills a gap for "
        "every setup at once. For contributors: [How to contribute](contributing.md).",
        "",
    ]
    return "\n".join(lines) + "\n"


# The home tile counts the whole collection. Labelled "Files" above a table
# of pack buttons, it read as what one pack contains.
COLLECTION_FILES_LABEL = "Files collected"


def composition_sentence(db: dict) -> str:
    comp = compute_composition(db)
    return (
        f"The collection holds {comp['systems']['files']:,} console and "
        f"computer system files, {comp['arcade']['files']:,} arcade ROM sets "
        f"(`Arcade/`), and {comp['game_data']['files']:,} game and engine "
        "data files (`Game Engines/`, `RPG Maker/`, `ScummVM/` and the game "
        "publishers' trees). No pack holds "
        "them all: each carries what its platform's emulators load."
    )


def install_demo(variant: str = "default", name: str = "") -> list[str]:
    """An installer demo (default, or handheld): a video that loads once it
    is on screen, its description for screen readers. *name* tells two
    demos of one page apart (the tab each sits in)."""
    facts = demo_facts(variant)
    text = html.escape(demo_description(facts), quote=True)
    own = f' variant="{variant}" name="{name}"' if name else ""
    return [f'<InstallDemo description="{text}" width="{facts["width"]}" '
            f'height="{facts["height"]}"{own} />', ""]


# Navigation


_OS_NAMES = {"windows": "Windows", "darwin": "macOS", "linux": "Linux"}


def runs_on_text(entry: dict, guide: Guide) -> str:
    """Where a setup runs, read from the systems the installer detects it on."""
    if guide.on_card:
        return "SD card, filled from a computer"
    if "server" in guide.run:
        return "A server"
    if "device" in guide.run:
        return "Its own system"
    systems = {rule.get("os") for rule in (entry.get("install") or {}).get("detect") or []}
    names = [label for key, label in _OS_NAMES.items() if key in systems]
    if "steamdeck" in guide.run:
        names.append("Steam Deck")
    if "android" in guide.run:
        names.append("Android")
    return ", ".join(names)


def group_keys(registry: dict, group: str, display: dict[str, str]) -> list[str]:
    return sorted(
        (k for k in registry if registry[k].get("device_group") == group),
        key=lambda k: display[k].casefold(),
    )
