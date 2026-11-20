"""The name a person reads for each system, and the console sections that give it."""

from __future__ import annotations

from model import siteinputs
from model.collection import SECTION_LABELS, PROGRAM_TOPS, manufacturer_slug


# (manufacturer slug, console) -> the id of the console's heading. Two
# folders spelled alike (Sega's "Mega CD" and "Mega-CD") share a slug, and
# the second heading took "mega-cd_1" while every link said "mega-cd".
console_anchors: dict[tuple[str, str], str] = {}


boards_built = [False]


# Every (manufacturer, console) section the system pages carry.
section_pairs: set[tuple[str, str]] = set()
# Normalized id -> the console sections spelled that way.
_console_sections: dict[str, set[tuple[str, str]]] = {}
# A console section by the name its heading reads (Bandai WonderSwan).
sections_by_name: dict[str, set[tuple[str, str]]] = {}
# Emulator and engine names. A heading spelled like one (Game Engines >
# Solarus, ZC > ZC210) files that program's copies and names no system.
known_program_names: set[str] = set()


def program_names(profiles: dict[str, dict]) -> set[str]:
    """Every name an emulator profile goes by: its key, its emulator and
    display names."""
    names = {str(key) for key in profiles}
    for profile in profiles.values():
        names.update(
            str(profile[field]) for field in ("emulator", "display_name")
            if profile.get(field)
        )
    return names


def set_console_sections(
    sections: dict[str, dict] | set[tuple[str, str]],
    programs: set[str] | frozenset[str] = frozenset(),
) -> None:
    """Install the console sections the system pages carry.

    ``sections`` maps each manufacturer to its consoles, as the system pages
    group them, or is a set of (manufacturer, console) pairs. ``programs``
    are the emulator names, which never name a system.
    """
    from model.systems import norm_system_id

    pairs = (
        {(mfr, console) for mfr, consoles in sections.items() for console in consoles}
        if isinstance(sections, dict) else set(sections)
    )
    # A reviewed parent under a maker the pages carry is a section even with
    # no folder of its own: the Atom's sets sit under bios/Arcade, and the
    # system pages file them under Acorn (sitegen.systempages.arcade_board_sections).
    makers = {mfr for mfr, _console in pairs}
    pairs |= {parent for parent in SYSTEM_PARENTS.values()
              if parent[0] in makers and parent[0] not in PROGRAM_TOPS}
    from core.anchors import unique_anchor, toc_slug

    _console_sections.clear()
    sections_by_name.clear()
    console_anchors.clear()
    section_pairs.clear()
    section_pairs.update(pairs)
    by_maker: dict[str, list[str]] = {}
    for mfr, console in pairs:
        by_maker.setdefault(mfr, []).append(console)
        for name in {heading_name(mfr, console).casefold(), console.casefold()}:
            sections_by_name.setdefault(name, set()).add((mfr, console))
    # In the order the page lists them, after the page title's own id.
    for mfr, consoles in by_maker.items():
        used = {toc_slug(mfr)}
        for console in sorted(consoles):
            console_anchors[(manufacturer_slug(mfr), console)] = unique_anchor(toc_slug(console), used)
    for mfr, console in pairs:
        spelled = console.lower().replace(" ", "-")
        slug = mfr.lower().replace(" ", "-")
        for key in {norm_system_id(f"{slug}-{spelled}"), norm_system_id(spelled)}:
            _console_sections.setdefault(key, set()).add((mfr, console))
    known_program_names.clear()
    known_program_names.update(name.casefold() for name in programs)
    _sections_installed[0] = True
    # Which ids are boards depends on which have a section elsewhere.
    boards_built[0] = False


_sections_installed = [False]


def ensure_console_sections() -> None:
    """Read the sections from the repository when no generator installed
    them, so a page rendered on its own names systems as the site does."""
    if _sections_installed[0]:
        return
    from model.collection import group_by_manufacturer
    from model.database import load_database
    from model.profiles import load_emulator_profiles

    inputs = siteinputs.current()
    db = load_database(str(inputs.db))
    profiles = load_emulator_profiles(str(inputs.emulators), skip_aliases=False)
    set_console_sections(group_by_manufacturer(db), program_names(profiles))


def own_section(sys_id: str) -> tuple[str, str] | None:
    """The console section that is this id's own, or None.

    Of two sections spelled alike (Atari and Camputers both file a Lynx),
    the one under the maker the id names is kept. Two left is no answer,
    and neither is a section that files a program's copies.
    """
    from model.systems import norm_system_id

    ensure_console_sections()
    places = _console_sections.get(norm_system_id(sys_id), set())
    if len(places) > 1:
        places = {
            (mfr, console) for mfr, console in places
            if sys_id.lower().startswith(mfr.lower().replace(" ", "-") + "-")
        }
    if len(places) != 1:
        return None
    mfr, console = next(iter(places))
    # A folder under a program's top, named like its own page (Dinothawr) or
    # like an emulator holds a program's files, not a system's.
    if (
        mfr in PROGRAM_TOPS
        or console.casefold() == mfr.casefold()
        or heading_name(mfr, console).casefold() in known_program_names
    ):
        return None
    return mfr, console


def heading_name(mfr: str, console: str) -> str:
    """A console heading read out of its page: the maker in front, unless
    the heading already starts with it or the page is a game publisher's."""
    from model.composition import GAME_DATA_TOPS

    if mfr in GAME_DATA_TOPS:
        return SECTION_LABELS.get((mfr, console), console)
    if console.casefold().startswith(mfr.split()[0].casefold()):
        return console
    return f"{mfr} {console}"


def system_name(sys_id: str) -> str:
    """The display name of a system id, the only one a page prints."""
    sys_id = str(sys_id)
    section = own_section(sys_id)
    if section is not None:
        return heading_name(*section)
    name = SYSTEM_NAMES.get(sys_id)
    if name is None:
        raise KeyError(
            f"system {sys_id!r} has no console section of its own and no "
            "entry in model.systemnames.SYSTEM_NAMES"
        )
    return name


# Systems without a console section of their own.
SYSTEM_NAMES: dict[str, str] = {
    "2ship": "The Legend of Zelda: Majora's Mask",
    "aarch64": "ARM 64-bit (AArch64)",
    "acclaim-zn1": "Acclaim ZN-1",
    "adrift": "ADRIFT",
    "advsys": "AdvSys",
    "ags": "Adventure Game Studio games",
    "agt": "Adventure Game Toolkit",
    "alan": "Alan",
    "alg-laserdisc": "American Laser Games laserdisc",
    "allied-leisure-pinball": "Allied Leisure pinball",
    "alpha": "DEC Alpha",
    "andamiro-pumpitup": "Andamiro Pump It Up",
    "apf-m1000": "APF M-1000",
    "apfm1000": "APF M-1000",
    "apple-iie": "Apple IIe",
    "apple-ios": "Apple iOS",
    "apple2": "Apple II",
    "arcade": "Arcade games",
    "arcade-laserdisc": "Laserdisc arcade games",
    "arcadia-systems": "Arcadia Systems Multi Select",
    "arduboy": "Arduboy",
    "aristocrat-mk5": "Aristocrat MK5",
    "aristocrat-mk6": "Aristocrat MK6",
    "aristocrat-mk7": "Aristocrat MK7",
    "arm": "ARM",
    "atari-falcon": "Atari Falcon",
    "atari-jaguarcd": "Atari Jaguar CD",
    "atari-ste": "Atari STE",
    "atari-system1": "Atari System 1",
    "atari-tt": "Atari TT",
    "atari-zn1": "Atari ZN-1",
    "atlus-zn1": "Atlus ZN-1",
    "bandai-playdia": "Bandai Playdia",
    "bandai-wswanc": "Bandai WonderSwan Color",
    "barcrest-mpu4": "Barcrest MPU4",
    "bbc-master-128": "Acorn BBC Master 128",
    "bbc-master-compact": "Acorn BBC Master Compact",
    "bbc-master-et": "Acorn BBC Master ET",
    "bbc-micro-b": "Acorn BBC Micro Model B",
    "bbc-micro-bplus": "Acorn BBC Micro Model B+",
    "bbk-longman-4980": "BBK Longman A4980",
    "bbk-longman-4988": "BBK Longman A4988",
    "bennugd": "BennuGD games",
    "bermuda-syndrome": "Bermuda Syndrome game",
    "brezzasoft-crystal": "BrezzaSoft Crystal System",
    "bshift": "Half-Life: Blue Shift",
    "caesar3": "Caesar III",
    "cambridge-z88": "Cambridge Computer Z88",
    "camplynx": "Camputers Lynx",
    "capcom-cps1": "Capcom CPS-1",
    "capcom-cps2": "Capcom CPS-2",
    "capcom-cps3": "Capcom CPS-3",
    "capcom-zn1": "Capcom ZN-1",
    "capcom-zn2": "Capcom ZN-2",
    "casio-pv1000": "Casio PV-1000",
    "catacomb-3d": "Catacomb 3-D",
    "catacomb-adventure": "Catacomb Adventure Series",
    "cave-cv1000": "Cave CV1000",
    "cave-story": "Cave Story",
    "cavestory": "Cave Story",
    "celeste-classic": "Celeste Classic",
    "century-cvs": "Century CVS",
    "ces-galaxy-games": "CES Galaxy Games",
    "cgenie": "EACA Colour Genie",
    "chex": "Chex Quest",
    "chip8": "CHIP-8",
    "coco3": "Tandy Color Computer 3",
    "commanderx16": "Commander X16",
    "commodore-c64-supercpu": "Commodore 64 with SuperCPU",
    "commodore-cd32": "Commodore Amiga CD32",
    "commodore-cdtv": "Commodore CDTV",
    "commodore-cubo": "CD Express Cubo CD32",
    "coolbar": "Coolbar feature phones",
    "cstrike": "Counter-Strike",
    "ctf": "Quake II: Capture the Flag",
    "czero": "Counter-Strike: Condition Zero",
    "czeror": "Counter-Strike: Condition Zero Deleted Scenes",
    "dark-forces": "Star Wars: Dark Forces",
    "dark-forces-ii": "Star Wars Jedi Knight: Dark Forces II",
    "deco-cassette": "Data East DECO Cassette System",
    "descent2": "Descent II",
    "dingoo-a320": "Dingoo A320",
    "dinothawr": "Dinothawr game",
    "discrete-arcade": "Discrete logic arcade games",
    "dmc": "Deathmatch Classic",
    "doom3-bfg": "Doom 3: BFG Edition",
    "dos": "MS-DOS",
    "dragon32": "Dragon 32",
    "dragon64": "Dragon 64",
    "droidworks": "Star Wars: DroidWorks",
    "duke-nukem-2": "Duke Nukem II",
    "duke3d": "Duke Nukem 3D",
    "dusklight": "The Legend of Zelda: Twilight Princess",
    "efo-cedar-magnet": "EFO Cedar Magnet System",
    "eighting-zn1": "Eighting ZN-1",
    "elektor-tv-games-computer": "Elektor TV Games Computer",
    "emerson-arcadia-2001": "Emerson Arcadia 2001",
    "enemy-territory-quake-wars": "Enemy Territory: Quake Wars",
    "enemyterritory": "Wolfenstein: Enemy Territory",
    "enterprise-128": "Enterprise 128",
    "enterprise-64": "Enterprise 64",
    "entex-advision": "Entex Adventure Vision",
    "epoch-scv": "Epoch Super Cassette Vision",
    "epochcv": "Epoch Cassette Vision",
    "eternal-computer": "Eternal Software Initiative computer",
    "exelvision-exl100": "Exelvision EXL 100",
    "exhumed": "PowerSlave",
    "exidy-maxaflex": "Exidy Max-A-Flex",
    "fallout": "Fallout",
    "flash": "Adobe Flash",
    "flashback": "Flashback",
    "fm77av": "Fujitsu FM77AV",
    "fpinball": "Future Pinball tables",
    "fruitmachine": "Fruit machines",
    "fury": "Ion Fury game",
    "gaelco-powervr": "Gaelco PowerVR boards",
    "galaksija": "Galaksija computer",
    "game": "Picross puzzle (libretro sample)",
    "gamecom": "Tiger Game.com",
    "gamemaker": "GameMaker games",
    "gameplan-mpu1": "Game Plan MPU-1",
    "gamepock": "Epoch Game Pocket Computer",
    "gametank": "GameTank console",
    "gearbox": "Half-Life: Opposing Force",
    "ghostship": "Super Mario 64",
    "glulx": "Glulx",
    "gottlieb-system1": "Gottlieb System 1",
    "half-life-2": "Half-Life 2",
    "handheld-electronic": "Nintendo Game & Watch",
    "heart-of-darkness": "Heart of Darkness",
    "heretic": "Heretic",
    "heroes-of-might-and-magic-2": "Heroes of Might and Magic II",
    "hexen": "Hexen",
    "hexen2": "Hexen II",
    "hugo": "Hugo",
    "hyper-neogeo64": "SNK Hyper Neo Geo 64",
    "ibm-at": "IBM PC/AT",
    "ibm-pcjr": "IBM PCjr",
    "ibm-ps1": "IBM PS/1",
    "ibm-xt": "IBM PC XT",
    "icarus-starship-command-simulator": "Icarus Starship Command Simulator",
    "igs-pgm": "IGS PolyGame Master",
    "imax-macs": "I'Max MACS",
    "interact": "Interact Home Computer",
    "interton-vc4000": "Interton VC 4000",
    "itech-eagle": "Incredible Technologies Eagle",
    "jacl": "JACL",
    "jedi-academy": "Star Wars Jedi Knight: Jedi Academy",
    "jedi-outcast": "Star Wars Jedi Knight II: Jedi Outcast",
    "jediacademy": "Star Wars Jedi Knight: Jedi Academy",
    "jediknight2": "Star Wars Jedi Knight II: Jedi Outcast",
    "jupiter-ace": "Jupiter Cantab Jupiter Ace",
    "konami-bubble-system": "Konami Bubble System",
    "konami-bubblesystem": "Konami Bubble System",
    "konami-bubsys": "Konami Bubble System",
    "konami-endeavour": "Konami Endeavour",
    "konami-gq": "Konami GQ",
    "konami-gv": "Konami GV",
    "konami-gx": "Konami GX",
    "konami-python": "Konami Python",
    "konami-python2": "Konami Python 2",
    "konami-twinkle": "Konami Twinkle",
    "konami-viper": "Konami Viper",
    "lambda-8300": "Lambda 8300",
    "laserdisc-arcade": "Laserdisc arcade games",
    "level9": "Level 9",
    "lowresnx": "LowRes NX programs",
    "lynx": "Atari Lynx",
    "m68k": "Motorola 68000",
    "magnetic-scrolls": "Magnetic Scrolls",
    "marty": "Fujitsu FM Towns Marty",
    "mega-cd-32x": "Sega Mega-CD 32X",
    "mega-duck": "Welback Mega Duck",
    "mega-ld": "Sega Mega LD",
    "microdigital-tk85": "Microdigital TK85",
    "microsoft-msx2": "MSX2",
    "midway-mcr": "Midway MCR",
    "mips": "MIPS",
    "mips64": "MIPS64",
    "miuchiz": "Miuchiz",
    "mohaa": "Medal of Honor: Allied Assault",
    "mohaa-breakthrough": "Medal of Honor: Allied Assault Breakthrough",
    "mohaa-spearhead": "Medal of Honor: Allied Assault Spearhead",
    "msx1": "MSX",
    "msx2": "MSX2",
    "msx2+": "MSX2+",
    "msx2plus": "MSX2+",
    "msxturboR": "MSX turbo R",
    "msxturbor": "MSX turbo R",
    "mysteries-of-the-sith": "Star Wars Jedi Knight: Mysteries of the Sith",
    "myvision": "Nichibutsu My Vision",
    "mz2000": "Sharp MZ-2000",
    "mz2500": "Sharp MZ-2500",
    "mz700": "Sharp MZ-700",
    "mz800": "Sharp MZ-800",
    "mz80k": "Sharp MZ-80K",
    "nam": "NAM",
    "namco-na1": "Namco NA-1",
    "namco-nb1": "Namco NB-1",
    "namco-system11": "Namco System 11",
    "namco-system246": "Namco System 246",
    "namco-system256": "Namco System 256",
    "namco-system357": "Namco System 357",
    "namco-system573": "Konami System 573",
    "naomi2": "Sega NAOMI 2",
    "napalm": "NAPALM",
    "nec-pc-80": "NEC PC-8001",
    "nec-supergrafx": "NEC SuperGrafx",
    "neogeo64": "SNK Hyper Neo Geo 64",
    "ngpc": "SNK Neo Geo Pocket Color",
    "nichibutsu-hrdvd": "Nichibutsu High Rate DVD",
    "nintendo-aleck64": "Nintendo Aleck64",
    "nintendo-gb": "Nintendo Game Boy",
    "nintendo-gbc": "Nintendo Game Boy Color",
    "nintendo-nss": "Nintendo Super System",
    "nintendo-playch10": "Nintendo PlayChoice-10",
    "nintendo-sfcbox": "Nintendo Super Famicom Box",
    "nintendo-virtualboy": "Nintendo Virtual Boy",
    "nintendo-wii-arcade": "Nintendo Wii arcade boards",
    "nmk16": "NMK16",
    "oberon": "Project Oberon",
    "olivetti-pc128": "Olivetti Prodest PC 128",
    "omicron": "Omicron cartridges",
    "onscripter": "ONScripter visual novels",
    "openbor": "OpenBOR games",
    "opengoal": "Jak and Daxter",
    "oricatmos": "Oric Atmos",
    "outlaws": "Outlaws",
    "palm-os": "Palm OS",
    "pc-engine-ld": "NEC PC Engine LD-ROM2",
    "pc60": "NEC PC-6001",
    "pc80": "NEC PC-8001",
    "pce-tourvision": "TourVision",
    "pdark": "Perfect Dark",
    "pegasus": "Aamber Pegasus",
    "philips-p2000t": "Philips P2000T",
    "philips-vg5k": "Philips VG 5000",
    "picocomputer-6502": "Picocomputer 6502 programs",
    "pocket-challenge-v2": "Benesse Pocket Challenge V2",
    "powerslave": "PowerSlave",
    "ppc": "PowerPC",
    "ppc64": "PowerPC 64-bit",
    "prey": "Prey",
    "prince-of-persia": "Prince of Persia",
    "ps4": "Sony PlayStation 4",
    "pv1000": "Casio PV-1000",
    "quadrilateral-cowboy": "Quadrilateral Cowboy",
    "quake2": "Quake II",
    "quake3": "Quake III Arena",
    "quake4": "Quake 4",
    "realrtcw": "Return to Castle Wolfenstein (RealRTCW)",
    "recel-system3": "Recel System III",
    "redneck": "Redneck Rampage",
    "ricochet": "Ricochet",
    "ringo-r470": "Ringo R470",
    "riscv": "RISC-V",
    "riscv32": "RISC-V 32-bit",
    "riscv64": "RISC-V 64-bit",
    "rogue": "Quake II: Ground Zero",
    "rott": "Rise of the Triad",
    "rpgmaker": "RPG Maker games",
    "s390x": "IBM z/Architecture (s390x)",
    "sam-coupe": "MGT SAM Coupe",
    "sammy-atomiswave": "Sammy Atomiswave",
    "sammy-medal": "Sammy medal games",
    "science-of-cambridge-mk14": "Science of Cambridge MK14",
    "scott-adams": "Scott Adams adventures",
    "scott-adams-plus": "Scott Adams Plus adventures",
    "scummvm": "ScummVM games",
    "scv": "Epoch Super Cassette Vision",
    "sdlpal": "The Legend of Sword and Fairy",
    "sega-atomiswave": "Sammy Atomiswave",
    "sega-dreamcast-arcade": "Sega Dreamcast-based arcade boards",
    "sega-isgsm": "Sega ISG Selection Master",
    "sega-megaplay": "Sega Mega Play",
    "sega-megatech": "Sega Mega-Tech",
    "sega-model1": "Sega Model 1",
    "sega-naomi": "Sega NAOMI",
    "sega-naomi2": "Sega NAOMI 2",
    "sega-naomigd": "Sega NAOMI GD-ROM",
    "sega-outrun": "OutRun",
    "sega-pico": "Sega Pico",
    "sega-sg1000": "Sega SG-1000",
    "sega-shootingzone": "Sega Shooting Zone",
    "sega-system-sp": "Sega System SP",
    "sega-system16b": "Sega System 16B",
    "sega-systemsp": "Sega System SP",
    "sega-vmu": "Sega Dreamcast VMU",
    "serious-sam": "Serious Sam",
    "sg-1000": "Sega SG-1000",
    "sielectronics-y2": "SiElectronics System Y2",
    "sinclair-ql": "Sinclair QL",
    "sinclair-zx-spectrum-next": "ZX Spectrum Next",
    "sinclair-zx80-81": "Sinclair ZX80 and ZX81",
    "skin-deep": "Skin Deep",
    "smbx": "Super Mario Bros. X",
    "snk-neogeo-aes": "SNK Neo Geo AES",
    "snk-neogeo-mvs": "SNK Neo Geo MVS",
    "snk-neogeo": "SNK Neo Geo",
    "neogeo": "SNK Neo Geo",
    "snk-ngpc": "SNK Neo Geo Pocket Color",
    "soh": "The Legend of Zelda: Ocarina of Time",
    "sonic-1-2013": "Sonic the Hedgehog (2013)",
    "sonic-2-2013": "Sonic the Hedgehog 2 (2013)",
    "sonic-mania": "Sonic Mania",
    "soniccd": "Sonic CD",
    "sony-psp": "Sony PlayStation Portable",
    "sparc": "SPARC",
    "sparc64": "SPARC64",
    "spectravideo": "Spectravideo",
    "star-control-2": "Star Control II",
    "starship": "Star Fox 64",
    "strife": "Strife",
    "sunplus-native32": "Sunplus Native32",
    "sunplus-spmp8000": "Sunplus SPMP8000",
    "super-kaneko-nova": "Kaneko Super Nova System",
    "super-mario-war": "Super Mario War game",
    "superacan": "Funtech Super A'Can",
    "supergrafx": "NEC SuperGrafx",
    "supergrafx-cd": "NEC SuperGrafx CD",
    "solarus": "Solarus games",
    "supertux": "SuperTux game",
    "supertuxkart": "SuperTuxKart game",
    "supracan": "Funtech Super A'Can",
    "symbian": "Symbian OS",
    "tab-silverball": "TAB Austria Silverball",
    "tads": "TADS",
    "taito-cchip": "Taito C-Chip",
    "taito-fx1": "Taito FX-1",
    "taito-gnet": "Taito G-NET",
    "taito-type-x": "Taito Type X",
    "taito-typezero": "Taito Type Zero",
    "tamagotchi-p1": "Bandai Tamagotchi P1",
    "tandy-1000": "Tandy 1000",
    "taylormade": "TaylorMade",
    "teamarena": "Quake III: Team Arena",
    "tecmo-tps": "Tecmo TPS",
    "tfc": "Team Fortress Classic",
    "the-dark-mod": "The Dark Mod",
    "thomson-mo6": "Thomson MO6",
    "thomson-to7": "Thomson TO7",
    "thomson-to770": "Thomson TO7/70",
    "thomson-to8": "Thomson TO8",
    "thomson-to8d": "Thomson TO8D",
    "thomson-to9": "Thomson TO9",
    "thomson-to9plus": "Thomson TO9+",
    "tic80": "TIC-80 cartridges",
    "tiger-game-com": "Tiger Game.com",
    "timex-tc2048": "Timex Computer 2048",
    "timex-ts1500": "Timex Sinclair 1500",
    "timex-ts2068": "Timex Sinclair 2068",
    "tomb-raider": "Tomb Raider",
    "tomb-raider-1": "Tomb Raider",
    "tomb-raider-2": "Tomb Raider II",
    "transport-tycoon-deluxe": "Transport Tycoon Deluxe",
    "tvgames": "Plug-and-play TV games",
    "tyrian": "Tyrian",
    "ur-quan-masters": "Star Control II",
    "urban-terror": "Urban Terror",
    "uzebox": "Uzebox",
    "vaporspec": "VaporSpec cartridges",
    "vc4000": "Interton VC 4000",
    "vg5k": "Philips VG 5000",
    "vgmplay": "Video game music files",
    "videobrain": "Umtech VideoBrain",
    "videosystem-zn1": "Video System ZN-1",
    "vircon32": "Vircon32 cartridges",
    "virtuality-su2000": "Virtuality SU2000",
    "vm-labs-nuon": "VM Labs Nuon",
    "vpinball": "Visual Pinball tables",
    "vtech-vsmile": "VTech V.Smile",
    "vvvvvv": "VVVVVV game",
    "watara-supervision": "Watara Supervision",
    "wonderswan-color": "Bandai WonderSwan Color",
    "ww2gi": "World War II GI",
    "x86": "x86 PC",
    "x86-64": "x86-64 PC",
    "xatrix": "Quake II: The Reckoning",
    "xrick": "Rick Dangerous",
    "ym2608": "Yamaha YM2608",
    "zc210": "Zelda Classic",
    "zeldaclassic": "Zelda Classic",
    "zn1-acclaim": "Acclaim ZN-1",
    "zn1-atlus": "Atlus ZN-1",
    "zn1-capcom": "Capcom ZN-1",
    # mame2003 files taitofx1.zip and tps.zip under these ids, its notes
    # name the boards: the Taito FX-1 and the Tecmo TPS, both ZN-1 based.
    "zn1-taito": "Taito FX-1",
    "zn1-tecmo": "Tecmo TPS",
    "zn1-video-system": "Video System ZN-1",
    "zn2-capcom": "Capcom ZN-2",
    "zx-spectrum-128": "Sinclair ZX Spectrum 128",
}


# A system id with no section of its own -> the (manufacturer, console)
# section holding its files: a model, a regional name or an add-on of the
# machine that section covers, or a game whose data that section files.
# Reviewed entry by entry against the files the profiles and platforms
# declare for the id, never decided by a vote of the folders those files
# sit in. A section that is not the machine stays out of this table even
# when it holds a copy: NAOMI's naomi2.zip filed with the Dreamcast, the
# PET's ROMs in VICE's tree under the C128, the Arcadia's under the Saturn.
SYSTEM_PARENTS: dict[str, tuple[str, str]] = {
    # Nintendo. The twin folders (DS and Nintendo DS, 64DD and Nintendo
    # 64DD) gave each name two headings and no link.
    "64dd": ("Nintendo", "Nintendo 64DD"),
    "nintendo-64dd": ("Nintendo", "Nintendo 64DD"),
    "nintendo-ds": ("Nintendo", "Nintendo DS"),
    "nintendo-dsi": ("Nintendo", "Nintendo DS"),
    "famicom": ("Nintendo", "NES"),
    "super-famicom": ("Nintendo", "SNES"),
    # Bandai: the Color boot ROMs, and those of Benesse's WonderSwan-based
    # Pocket Challenge V2, sit with the WonderSwan.
    "wonderswan-color": ("Bandai", "WonderSwan"),
    "bandai-wswanc": ("Bandai", "WonderSwan"),
    "pocket-challenge-v2": ("Bandai", "WonderSwan"),
    # SNK
    "ngpc": ("SNK", "Neo Geo Pocket"),
    "snk-ngpc": ("SNK", "Neo Geo Pocket"),
    "snk-neogeo-aes": ("SNK", "Neo Geo"),
    "snk-neogeo-mvs": ("SNK", "Neo Geo"),
    # The platforms' one Neo Geo system, as Batocera and RetroDECK spell it.
    "snk-neogeo": ("SNK", "Neo Geo"),
    "neogeo": ("SNK", "Neo Geo"),
    # Sega. The VMU is the Dreamcast's memory card, its images sit there.
    # Sega's arcade section holds the OutRun board ROMs Cannonball reads.
    "sega-genesis": ("Sega", "Mega Drive"),
    "mega-cd-32x": ("Sega", "Mega CD"),
    "sega-vmu": ("Sega", "Dreamcast"),
    "sega-outrun": ("Sega", "Arcade"),
    # NEC and Pioneer: both LaserActive packs (LD-ROM2 and Mega LD) file
    # their BIOS under the LaserActive.
    "nec-supergrafx": ("NEC", "PC Engine"),
    "supergrafx": ("NEC", "PC Engine"),
    "supergrafx-cd": ("NEC", "PC Engine CD"),
    "pc-engine-ld": ("Pioneer", "LaserActive"),
    "mega-ld": ("Pioneer", "LaserActive"),
    # Microsoft MSX generations
    "microsoft-msx2": ("Microsoft", "MSX"),
    "msx2": ("Microsoft", "MSX"),
    "msx2plus": ("Microsoft", "MSX"),
    "msx2+": ("Microsoft", "MSX"),
    "msxturboR": ("Microsoft", "MSX"),
    "msxturbor": ("Microsoft", "MSX"),
    # Sinclair: 128-0.rom and 128-1.rom, and Timex's tc2048.rom.
    "zx-spectrum-128": ("Sinclair", "ZX Spectrum"),
    "timex-tc2048": ("Sinclair", "ZX Spectrum"),
    # Acorn: os12.rom and basic2.rom for the Model B and B+, and the
    # Master Compact's bbcmc.zip.
    "bbc-micro-b": ("Acorn", "BBC Micro"),
    "bbc-micro-bplus": ("Acorn", "BBC Micro"),
    "bbc-master-compact": ("Acorn", "BBC Micro"),
    # Atari: falcon.img, ste.img and tt.img sit with the ST TOS images.
    "atari-ste": ("Atari", "ST"),
    "atari-tt": ("Atari", "ST"),
    "atari-falcon": ("Atari", "ST"),
    # Home computers filed under their family
    "apple-iie": ("Apple", "Apple II"),
    "apf-m1000": ("APF", "Imagination Machine"),
    "apfm1000": ("APF", "Imagination Machine"),
    "bbk-longman-4980": ("BBK", "A4980"),
    "bbk-longman-4988": ("BBK", "A4988"),
    "coco3": ("Tandy", "CoCo"),
    "commodore-cdtv": ("Commodore", "Amiga"),
    "dragon32": ("Dragon", "Dragon"),
    "dragon64": ("Dragon", "Dragon"),
    "enterprise-64": ("Enterprise", "64-128"),
    "enterprise-128": ("Enterprise", "64-128"),
    "fm77av": ("Fujitsu", "FM-7"),
    "gamepock": ("Epoch", "Game Pocket"),
    "ibm-pcjr": ("IBM", "PC"),
    "ibm-xt": ("IBM", "PC"),
    "marty": ("Fujitsu", "FM Towns"),
    "mz700": ("Sharp", "MZ"),
    "mz80k": ("Sharp", "MZ"),
    "mz800": ("Sharp", "MZ"),
    "oricatmos": ("Tangerine", "Oric"),
    "palm-os": ("Palm", "Palm"),
    "philips-vg5k": ("Philips", "VG5000"),
    "vg5k": ("Philips", "VG5000"),
    "videobrain": ("VideoBrain", "Family Computer"),
    # Computers whose sets sit under bios/Arcade with MAME's: the Atom has
    # no folder of its own, its section holds those sets. The MZ-2000 and
    # MZ-2500 sets join the MZ ones.
    "atom": ("Acorn", "Atom"),
    "mz2000": ("Sharp", "MZ"),
    "mz2500": ("Sharp", "MZ"),
    # Files kept at the maker's root, so each file is a heading of its own
    # on a page that is the machine's: the first one leads there.
    "galaksija": ("Galaksija", "Galaksija"),
    "vircon32": ("Vircon", "Vircon32"),
    # Games, filed with the game whose folder holds their data
    "dinothawr": ("Dinothawr", "Dinothawr"),
    "doom": ("Id Software", "Doom"),
    # The other games of the Doom engines keep their IWADs in its folder.
    "heretic": ("Id Software", "Doom"),
    "hexen": ("Id Software", "Doom"),
    "strife": ("Id Software", "Doom"),
    "chex": ("Id Software", "Doom"),
    "ctf": ("Id Software", "Quake II"),
    "teamarena": ("Id Software", "Quake III Arena"),
    "enemyterritory": ("Id Software", "Wolfenstein Enemy Territory"),
    "gearbox": ("Valve", "Half-Life"),
    "dmc": ("Valve", "Half-Life"),
    "ricochet": ("Valve", "Half-Life"),
    "tfc": ("Valve", "Half-Life"),
    "mohaa": ("Electronic Arts", "Medal of Honor Allied Assault"),
    "mohaa-breakthrough": ("Electronic Arts", "Medal of Honor Allied Assault"),
    "mohaa-spearhead": ("Electronic Arts", "Medal of Honor Allied Assault"),
    "ur-quan-masters": ("Toys for Bob", "The Ur-Quan Masters"),
    "star-control-2": ("Toys for Bob", "The Ur-Quan Masters"),
    # Systems whose files sit in the folder of the program that reads them,
    # the only section listing them. DOS and ScummVM also read the Roland
    # MT-32 ROMs, which their own sections do not hold.
    "bbc-master-128": ("Other", "beebem"),
    "bbc-master-et": ("Other", "beebem"),
    "cave-story": ("Other", "NXEngine"),
    "dos": ("DOS", "DOSBox"),
    "scummvm": ("ScummVM", "ScummVM"),
    "sinclair-zx-spectrum-next": ("Other", "cspect"),
    "solarus": ("Game Engines", "Solarus"),
    "sunplus-spmp8000": ("Other", "spmp8000emu"),
    "tomb-raider-1": ("Game Engines", "TRX"),
    "tyrian": ("Other", "opentyrian"),
    "vm-labs-nuon": ("Other", "nuance"),
    "xrick": ("Other", "xrick"),
    "zc210": ("ZC", "ZC210"),
    # The collection's general arcade section, where naomi.zip, neogeo.zip
    # and the other board sets sit. A sound chip's set and a toy's stay in
    # the Arcade folders holding them: neither is an arcade board.
    "arcade": ("Arcade", "Arcade"),
    "miuchiz": ("Arcade", "MAME"),
    "ym2608": ("Arcade", "Arcade"),
}
