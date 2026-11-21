"""The platforms and systems a file list names, and the names people type for them."""
from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import NoReturn

from installer.embedded import _EMBEDDED_RULES, _NO_FOLDER
from installer.manifest import OTHER_SYSTEMS
from installer.refusal import Refusal

# The platforms that publish a core list per board, install/targets/ in the
# repository: a test holds the two equal. Offline, a platform outside it
# has no hardware targets, where the run sent the user after a list that
# exists nowhere.
TARGET_PLATFORMS = frozenset({
    "amberelec", "batocera", "emudeck", "emuelec", "knulli", "lakka", "recalbox", "retroarch",
    "retrobat", "retrodeck", "retropie", "rocknix", "romm",
})


# Platforms with a manifest in install/. Manifest URLs are case sensitive,
# so user input is normalized against this list before any fetch.
AVAILABLE_PLATFORMS = (
    "retroarch", "batocera", "recalbox", "retrobat", "emudeck",
    "lakka", "retrodeck", "rocknix", "romm", "bizhawk", "misterfpga",
    "retropie", "amberelec", "emuelec", "knulli",
    "minui", "nextui", "myminui",
)

# The names the frontends give themselves, as each manifest's display_name
# spells them (a test holds the two equal). Detection and the platform menu
# come before any manifest is fetched, and str.capitalize() wrote Retroarch,
# Retrodeck and Misterfpga.
PLATFORM_NAMES = {
    "retroarch": "RetroArch", "batocera": "Batocera", "recalbox": "Recalbox",
    "retrobat": "RetroBat", "emudeck": "EmuDeck", "lakka": "Lakka",
    "retrodeck": "RetroDECK", "rocknix": "ROCKNIX", "romm": "RomM",
    "bizhawk": "BizHawk", "misterfpga": "MiSTer FPGA", "retropie": "RetroPie",
    "amberelec": "AmberELEC", "emuelec": "EmuELEC", "knulli": "KNULLI",
    "minui": "MinUI", "nextui": "NextUI", "myminui": "MyMinUI",
}


# Fallback BIOS destination per platform when --platform is forced
# but auto-detection finds nothing on the machine.
DEFAULT_DESTS = {
    "batocera": Path("/userdata/bios"),
    "recalbox": Path("/recalbox/share/bios"),
    "lakka": Path("/storage/system"),
    "retrodeck": Path.home() / "retrodeck",
    "emudeck": Path.home() / "Emulation" / "bios",
    "rocknix": Path("/storage/roms/bios"),
    # Their BIOS lists name files under /storage/roms beside bios/.
    "amberelec": Path("/storage/roms"),
    "emuelec": Path("/storage/roms"),
    "knulli": Path("/userdata/bios"),
    "misterfpga": Path("/media/fat/games"),
    "retropie": Path.home() / "RetroPie" / "BIOS",
    "romm": Path("/romm/library/bios"),
}


def display_name(plat: str, manifest: dict | None = None) -> str:
    """A platform's name as the frontend writes it, the manifest's when it has one."""
    named = (manifest or {}).get("display_name")
    if isinstance(named, str) and named.strip().isprintable() and 0 < len(named.strip()) <= 40:
        return named.strip()
    return PLATFORM_NAMES.get(plat, plat)


def _name_key(name: str) -> str:
    """Letters and digits only: MiSTer FPGA, misterfpga and Mister-FPGA are one name."""
    return re.sub(r"[^a-z0-9]", "", name.lower())


# A list this short is printed whole rather than pointed at.
SHORT_LIST = 12


# Names people type for a system, each with its id. Only ever suggested:
# --system gba, psx and ps1 were refused with no hint on RetroArch, whose
# list names no system that way, and taking one in silence could install
# another console than the one meant.
SYSTEM_SHORT_NAMES = {
    **dict.fromkeys(("psx", "ps1", "ps", "playstation1"), "sony-playstation"),
    "ps2": "sony-playstation-2", "ps3": "sony-playstation-3", "psp": "sony-psp",
    **dict.fromkeys(("vita", "psvita"), "sony-playstation-vita"),
    "gb": "nintendo-gb", "gbc": "nintendo-gbc", "gba": "nintendo-gba",
    **dict.fromkeys(("nes", "famicom", "fc"), "nintendo-nes"), "fds": "nintendo-fds",
    **dict.fromkeys(("snes", "sfc", "superfamicom"), "nintendo-snes"),
    "n64": "nintendo-64", "n64dd": "nintendo-64dd", "sgb": "nintendo-sgb",
    **dict.fromkeys(("nds", "ds"), "nintendo-ds"), "dsi": "nintendo-dsi",
    "3ds": "nintendo-3ds", "wiiu": "nintendo-wii-u", "switch": "nintendo-switch",
    **dict.fromkeys(("gc", "ngc", "gcn", "gamecube"), "nintendo-gamecube"),
    "pokemini": "nintendo-pokemon-mini",
    **dict.fromkeys(("md", "gen", "genesis", "megadrive"), "sega-mega-drive"),
    **dict.fromkeys(("scd", "segacd", "megacd"), "sega-mega-cd"),
    "32x": "sega-32x", **dict.fromkeys(("sms", "mastersystem"), "sega-master-system"),
    **dict.fromkeys(("gg", "gamegear"), "sega-game-gear"),
    **dict.fromkeys(("ss", "saturn"), "sega-saturn"),
    **dict.fromkeys(("dc", "dreamcast"), "sega-dreamcast"),
    **dict.fromkeys(("naomi", "atomiswave"), "sega-dreamcast-arcade"),
    **dict.fromkeys(("pce", "tg16", "turbografx", "turbografx16", "pcengine",
                     "supergrafx"), "nec-pc-engine"),
    **dict.fromkeys(("pcecd", "tgcd", "turbografxcd"), "nec-pc-engine-cd"),
    "pcfx": "nec-pc-fx",
    **dict.fromkeys(("neogeo", "mvs", "aes"), "snk-neogeo"),
    **dict.fromkeys(("neocd", "neogeocd"), "snk-neogeo-cd"),
    **dict.fromkeys(("msx", "msx2"), "microsoft-msx"),
    "c64": "commodore-c64", "c128": "commodore-c128",
    **dict.fromkeys(("amiga", "cd32"), "commodore-amiga"),
    "x68k": "sharp-x68000", **dict.fromkeys(("jag", "jaguar"), "atari-jaguar"),
    **dict.fromkeys(("st", "atarist"), "atari-st"), "a800": "atari-400-800",
    **dict.fromkeys(("coleco", "colecovision"), "coleco-colecovision"),
    **dict.fromkeys(("intv", "intellivision"), "mattel-intellivision"),
    "o2": "magnavox-odyssey2", "channelf": "fairchild-channel-f",
    **dict.fromkeys(("zx", "spectrum", "zxspectrum"), "sinclair-zx-spectrum"),
    "cpc": "amstrad-cpc", "bbc": "acorn-bbc-micro", "apple2": "apple-ii",
}

# A system some lists file under another id, by the file that stands for it.
# The Neo Geo card offers --system snk-neogeo, and RetroArch's list keeps
# neogeo.zip under arcade: the run suggests arcade, never takes it.
SYSTEM_KEY_FILES = {"snk-neogeo": "neogeo.zip"}


def key_file_holders(files: list[dict], omitted: list[dict]) -> dict[str, list[str]]:
    """The systems a list files each SYSTEM_KEY_FILES file under, for the
    systems the list does not name itself."""
    entries = files + omitted
    known = {system for entry in entries for system in entry_systems(entry)}
    holders: dict[str, list[str]] = {}
    for system, name in SYSTEM_KEY_FILES.items():
        if system in known:
            continue
        held = sorted({
            holder for entry in entries
            if PurePosixPath(str(entry.get("dest", ""))).name.lower() == name
            for holder in entry_systems(entry)
        })
        if held:
            holders[system] = held
    return holders


def did_you_mean(
    typed: list[str], known: list[str], listing: str,
    aliases: dict[str, str] | None = None, inside_from: int = 4,
    meant: dict[str, list[str]] | None = None,
) -> str:
    """The closest known names to what was typed, and the option listing them all.

    A typo was answered with every name the platform has, up to 400 on one
    line, with no hint that playstation is sony-playstation. An alias close
    to what was typed suggests the name it stands for. A name holding what
    was typed, inside_from letters or more, is suggested too. meant gives,
    by the letters and digits of a typed name, the names it stands for
    here, suggested instead of the close ones.
    """
    import difflib

    by_key: dict[str, str] = {}
    for name in known:
        by_key.setdefault(_name_key(name), name)
    for alias, name in (aliases or {}).items():
        by_key.setdefault(_name_key(alias), name)
    close: list[str] = []
    for word in typed:
        key = _name_key(word)
        if not key:
            continue
        if meant and key in meant:
            close += [name for name in meant[key] if name not in close]
            continue
        matches = difflib.get_close_matches(key, list(by_key), n=3, cutoff=0.6)
        if len(key) >= inside_from:
            matches += sorted(k for k in by_key if key in k and k not in matches)
        for k in matches:
            # Two aliases of one system (psx, ps1) name it once.
            if by_key[k] not in close:
                close.append(by_key[k])
    if close:
        return f"Close matches: {', '.join(close[:3])}. {listing} lists all {len(known)}."
    if len(known) <= SHORT_LIST:
        return f"Known: {', '.join(known)}."
    return f"{listing} lists all {len(known)}."


def refuse_name(platform: str, *lines: str) -> NoReturn:
    """End the run on a name it cannot use (a platform, target, system, core
    or emulator), refused before any download.

    The reason went to stderr only: a reader of --events got start, then
    end with code 1, and could not tell a typo from a failed download. Code
    2, as for an option argparse refuses: 1 also means --check found files
    to fetch, and a script reading it reran the install on a typo forever.
    """
    raise Refusal("option", "unknown", platform, *lines, code=2)


# Frontends and systems that keep no BIOS folder of their own: each
# emulator they start reads its own, which a run without --platform finds.
# --platform es-de was "Unknown platform", the answer left unsaid.
_NO_BIOS_FOLDER = ("ES-DE", "LaunchBox", "Android")


def normalize_platform(name: str, say: bool = True) -> str:
    """Return the canonical platform id for user-supplied input.

    The site writes MiSTer FPGA and RetroArch: letters and digits decide,
    as they do for verify.py and generate_pack.py. say is False where the
    name is read again later, which says it once.
    """
    key = _name_key(name)
    for plat in AVAILABLE_PLATFORMS:
        if key and key in (_name_key(plat), _name_key(display_name(plat))):
            return plat
    # --list-platforms prints `muOS: retroarch`, and --platform muos was
    # refused: a system named there stands for the list it gets.
    for rule in _EMBEDDED_RULES:
        if key and rule.manifest and key == _name_key(rule.name):
            if say:
                print(f"  {rule.name} gets the {display_name(rule.manifest)} file list: "
                      f"--platform {rule.manifest}.")
            return rule.manifest
    for frontend in _NO_BIOS_FOLDER:
        if key and key == _name_key(frontend):
            refuse_name(name.strip(), f"{frontend} has no BIOS folder of its own: run again "
                        "without --platform, and the installer fills the folder of each "
                        "emulator it finds here.")
    # --list-platforms prints TrimUI with why it gets no folder, and naming
    # it answered "Unknown platform".
    for rule in _EMBEDDED_RULES:
        if key and not rule.manifest and key == _name_key(rule.name):
            refuse_name(name.strip(), f"{rule.name} is not installed to: "
                        f"{_NO_FOLDER.get(rule.name, 'no source names its BIOS folder')}.",
                        "  Name that folder: --platform retroarch "
                        "--dest FOLDER")
    # Every name --list-platforms prints, so that spruce suggests spruceOS
    # and the count is the one the listing shows.
    known = list(AVAILABLE_PLATFORMS) + list(dict.fromkeys(
        rule.name for rule in _EMBEDDED_RULES
        if _name_key(rule.name) not in {_name_key(plat) for plat in AVAILABLE_PLATFORMS}
    )) + list(_NO_BIOS_FOLDER)
    refuse_name(name.strip(), f"Unknown platform '{name.strip()}'. "
                + did_you_mean([name], known, "--list-platforms"))


def entry_systems(entry: dict) -> list[str]:
    """The platform systems a file or an omission belongs to.

    An omission's `system` is spelled the way its profile spells it. Only
    `systems` names the platform's own, the ones --system accepts.
    """
    return list(entry.get("systems") or [])


def system_title(system: str, manifest: dict | None) -> str:
    """A system as the screen's Choose systems names it (_tui_system_label)."""
    names = ((manifest or {}).get("system_names") or {}).get(system)
    titles = (manifest or {}).get("system_titles")
    return _tui_system_label({"system": system, "name": ", ".join(names or [system])},
                             titles if isinstance(titles, dict) else {})


def _tui_system_label(row: dict, titles: dict | None = None) -> str:
    """The name a person reads: the file list's title when it has one, the
    platform's own name when it is one (Sony - PlayStation), the id with the
    platform's short name otherwise (psx)."""
    title = (titles or {}).get(row["system"])
    if isinstance(title, str) and title.strip():
        return title.strip()
    if row["system"] == OTHER_SYSTEMS:
        return OTHER_TITLE
    name = row.get("name") or row["system"]
    if name == row["system"]:
        return name
    if " " in name or any(char.isupper() for char in name):
        return name
    return f"{row['system']} ({name})"


# What the "other" row of the systems holds, in words (OTHER_SYSTEMS).
OTHER_TITLE = "Other systems and game engines"
