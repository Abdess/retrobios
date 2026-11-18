"""System ids: manufacturers, aliases, normalization and the names platforms give them."""

from __future__ import annotations

import functools
import re

from core.cli import suggest_names
from model.platforms import native_layer


MANUFACTURER_PREFIXES = (
    "acorn-",
    "apple-",
    "microsoft-",
    "nintendo-",
    "sony-",
    "sega-",
    "snk-",
    "panasonic-",
    "nec-",
    "epoch-",
    "mattel-",
    "fairchild-",
    "hartung-",
    "tiger-",
    "magnavox-",
    "philips-",
    "bandai-",
    "casio-",
    "coleco-",
    "commodore-",
    "sharp-",
    "sinclair-",
    "atari-",
    "sammy-",
    "gce-",
    "interton-",
    "texas-instruments-",
    "videoton-",
    "wenquxing-",
    "aquaplus-",
)


def derive_manufacturer(system_id: str, system_data: dict) -> str:
    """Derive manufacturer name for a system.

    Priority: explicit manufacturer field > system ID prefix > 'Other'.
    """
    mfr = system_data.get("manufacturer", "")
    if mfr and mfr not in ("Various", "Other"):
        return mfr.split("|")[0].strip()
    s = system_id.lower().replace("_", "-")
    for prefix in MANUFACTURER_PREFIXES:
        if s.startswith(prefix):
            return prefix.rstrip("-").title()
    return "Other"


# Abbreviations that normalization alone cannot resolve.
# Maps platform-specific short names to canonical profile system IDs.
SYSTEM_ALIASES: dict[str, str] = {
    "gmaster": "hartung-game-master",
    "n64dd": "nintendo-64dd",
    "neogeo64": "hyper-neogeo64",
    "psvita": "sony-playstation-vita",
    # Platform IDs missing the manufacturer-prefix hyphen
    "atari5200": "atari-5200",
    "atari7800": "atari-7800",
    "atarist": "atari-st",
    "sega32x": "sega-32x",
    "segastv": "sega-stv",
    "ti994a": "ti99",
    # Other spellings of one machine: RomM files the Mega CD as sega-mega-cd
    # and the disk system as nintendo-fds, which normalize to the ids the
    # profiles use only through these.
    "sega-segacd": "sega-megacd",
    "nes-fds": "nintendo-fds",
    # One machine, two spellings across platform folders and profiles:
    # Recalbox's apple2gs, Batocera's astrocade, KNULLI and RetroBat's
    # astrocde, MiSTer's creativision, Batocera's gamepocketcomputer
    # folder, BizHawk's Super Game Boy, the FBA 2012 board names.
    "apple2gs": "apple-iigs",
    "astrocade": "bally-astrocade",
    "astrocde": "bally-astrocade",
    "creativision": "crvision",
    "gamepocketcomputer": "gamepock",
    "nintendo-super-game-boy": "nintendo-sgb",
    "cps1": "capcom-cps1",
    "cps2": "capcom-cps2",
    "cps3": "capcom-cps3",
    "pgm": "igs-pgm",
    # Rom folder names the setups of platforms/romfolders/ give a machine,
    # each proven by the source_ref of the folder row that names it: the
    # short tags of Onion, CrossMix-OS, Koriki and the MinUI family, the
    # number words of Koriki and plumOS, the region and hack folders of
    # ES-DE, the MSU-1 folders of the ES family, the arcade cores named as
    # folders.
    "a2600": "atari-2600",
    "atari2600": "atari-2600",
    "fiftytwohundred": "atari-5200",
    "seventyeighthundred": "atari-7800",
    "atarixegs": "xegs",
    "atarijaguarcd": "atari-jaguarcd",
    "fc": "nintendo-nes",
    "nesh": "nintendo-nes",
    "sfc": "nintendo-snes",
    "supa": "nintendo-snes",
    "snesh": "nintendo-snes",
    "snesna": "nintendo-snes",
    "snesmsu1": "nintendo-snes",
    "snes-msu1": "nintendo-snes",
    "msu1": "nintendo-snes",
    "vb": "nintendo-virtualboy",
    "gc": "nintendo-gamecube",
    "gbh": "nintendo-gb",
    "gb2players": "nintendo-gb",
    "gbch": "nintendo-gbc",
    "gbc2players": "nintendo-gbc",
    "gbah": "nintendo-gba",
    "mgba": "nintendo-gba",
    "poke": "nintendo-pokemon-mini",
    "pkm": "nintendo-pokemon-mini",
    "md": "sega-megadrive",
    "genh": "sega-megadrive",
    "megadriveh": "sega-megadrive",
    "megadrivejp": "sega-megadrive",
    "megadrive-japan": "sega-megadrive",
    "msumd": "sega-megadrive",
    "mdmsu": "sega-megadrive",
    "ms": "sega-mastersystem",
    "mark3": "sega-mastersystem",
    "gamegearh": "sega-gamegear",
    "megacdjp": "sega-megacd",
    "saturnjp": "sega-saturn",
    "sega32xjp": "sega-32x",
    "sega32xna": "sega-32x",
    "thirtytwox": "sega-32x",
    "segasgone": "sega-sg1000",
    "ps": "sony-playstation",
    "pce": "nec-pc-engine",
    "tg16cd": "nec-pc-engine-cd",
    "tg-cd": "nec-pc-engine-cd",
    "turbografxcd": "nec-pc-engine-cd",
    "neocd": "snk-neogeo-cd",
    "ngcd": "snk-neogeo-cd",
    "neogeocdjp": "snk-neogeo-cd",
    "supervision": "watara-supervision",
    "cplus4": "commodore-plus4",
    "cpet": "commodore-pet",
    "cpc": "amstrad-cpc",
    "to8": "thomson-to8",
    "tic": "tic80",
    "fba": "arcade",
    "hbmame": "arcade",
    "advmame": "arcade",
    "mame-advmame": "arcade",
    "mame2000": "arcade",
    "mame2003": "arcade",
    "mame2003plus": "arcade",
    "mame2010": "arcade",
    "mame-libretro": "arcade",
    "mame-mame4all": "arcade",
    "c20": "commodore-vic20",
    "segamodel3": "sega-model3",
    "pspminis": "sony-psp",
    "ndsiware": "nintendo-dsi",
    "wiiware": "nintendo-wii",
    "x16": "commanderx16",
    "zxnext": "sinclair-zx-spectrum-next",
    "vemulator": "sega-vmu",
    "ep64-128": "enterprise-64-128",
    "easyrpg": "rpgmaker",
    "ggh": "sega-gamegear",
    "gba2players": "nintendo-gba",
    "snesmsu": "nintendo-snes",
    "megadrivemsu": "sega-megadrive",
    "sgb-msu1": "nintendo-sgb",
    # Spellings profiles gave a machine the others call by another id:
    # ares's own system names, dgen and picodrive's sega-genesis beside
    # sega-megadrive, fbneo's sinclair-spectrum and snk-neogeo-pocket,
    # emux_sms's sms. muOS names its GBA folder gameboyadvance first, the
    # folder resolved to ares's game-boy-advance, and an unrecognised GBA
    # game got no file of the nintendo-gba list.
    "famicom": "nintendo-nes",
    "famicom-disk-system": "nintendo-fds",
    "super-famicom": "nintendo-snes",
    "game-boy-advance": "nintendo-gba",
    "neo-geo-pocket": "snk-ngp",
    "snk-neogeo-pocket": "snk-ngp",
    "neo-geo-pocket-color": "snk-ngpc",
    "wonderswan": "bandai-wswan",
    "wonderswan-color": "bandai-wswanc",
    "sega-genesis": "sega-megadrive",
    "genesis": "sega-megadrive",
    "sinclair-spectrum": "sinclair-zx-spectrum",
    "sms": "sega-mastersystem",
    # The platforms' one Neo Geo system: the profiles file the MVS sets,
    # which every Neo Geo core reads, under snk-neogeo-mvs.
    "snk-neogeo": "snk-neogeo-mvs",
    "neogeo": "snk-neogeo-mvs",
}


@functools.cache
def _norm_system_id(sid: str) -> str:
    """Normalize system ID for cross-platform matching.

    Resolves known aliases, then strips manufacturer prefixes and separators
    so that platform-specific IDs (e.g., "xbox", "nintendo-wiiu") match
    profile IDs (e.g., "microsoft-xbox", "nintendo-wii-u").

    A function of the string and two constant tables: a manifest run asks it
    1.7 million times for about 1,100 ids.
    """
    s = sid.lower().replace("_", "-")
    s = SYSTEM_ALIASES.get(s, s)
    for prefix in MANUFACTURER_PREFIXES:
        if s.startswith(prefix):
            s = s[len(prefix) :]
            break
    return s.replace("-", "")


def _name_key(name: str) -> str:
    """Letters and digits only, as the installer compares names."""
    return re.sub(r"[^a-z0-9]", "", name.lower())


def platform_system_names(config: dict, systems: list[str]) -> dict[str, list[str]]:
    """Per platform system, the names the platform's own file gives it.

    A Batocera user knows PlayStation as `psx`, the folder under roms/, and
    the platform YAML records that name as `native_system` on each file it
    transcribes. Only the platform's own entries count (`native_layer`), a
    name spelled like the system id adds nothing, and a name the platform
    gives to two systems, or that reads as another system's id, names
    neither. The install manifest's `system_names` and the `--system` of
    generate_pack and verify read this one mapping.
    """
    native = native_layer(config) or {}
    by_name: dict[str, set[str]] = {}
    for sys_id, system in native.get("systems", {}).items():
        if sys_id not in systems:
            continue
        for entry in system.get("files", []):
            name = entry.get("native_system")
            if isinstance(name, str) and name.strip():
                by_name.setdefault(name.strip(), set()).add(sys_id)
    ids = {_name_key(sys_id) for sys_id in systems}
    out: dict[str, list[str]] = {}
    for name, owners in by_name.items():
        if len(owners) != 1 or _name_key(name) in ids:
            continue
        out.setdefault(next(iter(owners)), []).append(name)
    return {sys_id: sorted(names) for sys_id, names in sorted(out.items())}


def select_systems(systems: dict, wanted: list[str]) -> dict:
    """The systems a --system list keeps, by id or normalized id."""
    norm = {_norm_system_id(s) for s in wanted}
    return {
        sid: data for sid, data in systems.items()
        if sid in wanted or _norm_system_id(sid) in norm
    }


def resolve_system_arg(
    value: str,
    systems: list[str],
    config: dict | None = None,
    listing: str = "--list-systems",
) -> list[str]:
    """The system ids a --system value names, or ValueError naming the rest.

    With a platform config, the platform's own names count as well (Batocera's
    `psx` is sony-playstation), the same mapping the install manifest carries
    as `system_names`. Without one, only our ids do. A whole value that is a
    name wins over splitting it on commas: Recalbox names one system
    `msx1,msx2`. An id wins over another system's native name, and a name
    nothing else matches falls back to the normalized id (`playstation`).
    An unknown name is refused, never ignored.
    """
    names = platform_system_names(config, systems) if config else {}
    exact: dict[str, list[str]] = {}
    by_key: dict[str, list[str]] = {}
    for sid in systems:
        exact.setdefault(sid.lower(), [sid])
        by_key.setdefault(_name_key(sid), []).append(sid)
    for sid, aliases in names.items():
        for alias in aliases:
            exact.setdefault(alias.lower(), [sid])
            if _name_key(alias) not in by_key:
                by_key[_name_key(alias)] = [sid]
    by_norm: dict[str, list[str]] = {}
    for sid in systems:
        by_norm.setdefault(_norm_system_id(sid), []).append(sid)

    value = value.strip()
    tokens = [value] if value.lower() in exact else value.split(",")
    chosen: list[str] = []
    unknown: list[str] = []
    for token in (t.strip() for t in tokens):
        if not token:
            continue
        keyed = by_key.get(_name_key(token), [])
        found = (
            exact.get(token.lower())
            or (keyed if len(keyed) == 1 else None)
            or by_norm.get(_norm_system_id(token))
        )
        if not found:
            unknown.append(token)
            continue
        chosen += [sid for sid in found if sid not in chosen]
    if unknown:
        known = sorted({*systems, *(a for v in names.values() for a in v)})
        hint = suggest_names(unknown, known, listing, listed=len(systems))
        raise ValueError(f"unknown system {', '.join(unknown)}. {hint}")
    if not chosen:
        raise ValueError("--system names no system")
    return chosen


def system_index(profiles: dict) -> dict[str, tuple[str, set[str]]]:
    """Normalized system id -> (the first spelling met, the emulators).

    One system per normalized id, as --system selects: counted per spelling,
    nes and nintendo-nes were two systems and the README announced 550
    where --list-systems printed 513.
    """
    index: dict[str, tuple[str, set[str]]] = {}
    for name, p in sorted(profiles.items()):
        if p.get("type") in ("alias", "launcher") or p.get("role") == "test":
            continue
        for sys_id in p.get("systems", []):
            key = _norm_system_id(sys_id)
            index.setdefault(key, (sys_id, set()))[1].add(name)
    return index
