#!/usr/bin/env python3
"""Scraper for Batocera batocera-systems.

Source: https://github.com/batocera-linux/batocera.linux/.../batocera-systems
Format: Python dict with systems -> biosFiles
Hash: MD5 primary
"""

from __future__ import annotations

import ast
import re
import sys
from collections.abc import Callable, Iterator


from model.database import load_database
from core.paths import DB_FILE, PLATFORMS_DIR, REPO_ROOT
from model.targets import load_target_config, target_overrides
from core.hashing import cut_md5_owner
from model.safeparse import yaml_load_upstream

from typing import ClassVar

from .base_scraper import (
    BaseScraper,
    BiosRequirement,
    fetch_text,
    github_json,
    md5_field,
    optional_core_lists,
    systems_from_requirements,
)
from .batocera_configgen import Configgen, configs_root
from .batocera_launchers import extract_launchers
from .targets.batocera_targets_scraper import BuildSelection
from .targets.batocera_targets_scraper import Scraper as BoardTargets

PLATFORM_NAME = "batocera"

_RAW_BASE = "https://raw.githubusercontent.com/batocera-linux/batocera.linux"


def pick_stable_tag(names: list[str]) -> str | None:
    """Pick the highest batocera-N(.M) tag from a list of tag names."""
    import re

    stable = []
    for name in names:
        m = re.fullmatch(r"batocera-(\d+(?:\.\d+)?)", name)
        if m:
            stable.append((tuple(int(x) for x in m.group(1).split(".")), name))
    return max(stable)[1] if stable else None


def fetch_stable_tag() -> str:
    """Return the newest stable batocera-N(.M) tag name.

    Raises rather than falling back to master: the YAML records the tag
    it was read from, and the exporter patches that revision.
    """
    url = "https://api.github.com/repos/batocera-linux/batocera.linux/tags?per_page=100"
    tags = github_json(url, "cannot list batocera tags")
    tag = pick_stable_tag([tag["name"] for tag in tags])
    if not tag:
        raise RuntimeError("no stable batocera tag among the latest 100")
    return tag


SOURCE_URL = (
    _RAW_BASE + "/{tag}"
    "/package/batocera/core/batocera-scripts/scripts/batocera-systems"
)

CONFIGGEN_DEFAULTS_URL = (
    _RAW_BASE + "/{tag}"
    "/package/batocera/core/batocera-configgen/configs/"
    "configgen-defaults.yml"
)

ES_SYSTEMS_URL = (
    _RAW_BASE + "/{tag}"
    "/package/batocera/emulationstation/batocera-es-system/es_systems.yml"
)

# Names es_systems.yml files under an emulator that are not emulators:
# machine selectors, video plugins, launchers. Read from the overrides the
# target scraper applies, so one list says what is not a core.
TARGETS_DIR = REPO_ROOT / PLATFORMS_DIR / "targets"


def _not_cores(platform: str = "batocera") -> set[str]:
    default = target_overrides(platform, TARGETS_DIR).get("_default") or {}
    return {str(name) for name in default.get("remove_cores") or []}


def _es_systems_data(text: str) -> dict:
    data = yaml_load_upstream(text)
    if not isinstance(data, dict):
        raise ValueError("es_systems.yml is not a mapping")
    return data


def _system_entries(spec: object) -> Iterator[tuple[str, str | None, dict | None]]:
    """(emulator, core, core spec) for each core one es_systems.yml system offers.

    A system lists each emulator a user may pick and the cores under it.
    Keys whose value is not a mapping (archs_include) describe the entry,
    not a core. An emulator that lists no core is yielded once with None.
    """
    emulators = spec.get("emulators") if isinstance(spec, dict) else None
    if not isinstance(emulators, dict):
        return
    for emulator, entries in emulators.items():
        if not isinstance(entries, dict):
            continue
        offered = [(str(core), item) for core, item in entries.items() if isinstance(item, dict)]
        if not offered:
            yield str(emulator), None, None
        for core, item in offered:
            yield str(emulator), core, item


def es_systems_entries(text: str) -> Iterator[tuple[str, str, str | None, dict | None]]:
    """(system, emulator, core, core spec) for every core es_systems.yml offers.

    `emulator` is `libretro` for a libretro core. Any other emulator is its
    own core, and what it lists under it are machines or builds. Raises
    ValueError when the file is not a mapping.
    """
    for system, spec in _es_systems_data(text).items():
        for emulator, core, item in _system_entries(spec):
            yield str(system), emulator, core, item


def es_systems_emulators(text: str) -> tuple[set[str], set[str]]:
    """Every core es_systems.yml offers, and those that run standalone.

    configgen-defaults.yml only names the one picked by default, so
    reading it alone left DOSBox Staging, melonDS DS and nine other built
    cores outside the pack. The non-cores a standalone emulator lists are
    named in the overrides.
    """
    cores: set[str] = set()
    standalone: set[str] = set()
    for _system, emulator, core, _spec in es_systems_entries(text):
        names = {core} if core else set()
        if emulator != "libretro":
            names.add(emulator)
            standalone |= names
        cores |= names
    return cores, standalone


def es_systems_libretro(text: str) -> set[str]:
    """The cores es_systems.yml offers under `libretro:` for some system."""
    return {
        core for _system, emulator, core, _spec in es_systems_entries(text)
        if emulator == "libretro" and core
    }


def es_systems_libretro_systems(text: str, dropped: set[str]) -> dict[str, list[str]]:
    """libretro core -> the systems es_systems.yml offers it under `libretro:`.

    configgen hands a libretro core /userdata/saves/<system> at each launch
    (libretroConfig.py: savefile_directory = SAVES / system.name), so a file
    a core reads below its save directory sits once in each of these
    system folders.
    """
    found: dict[str, set[str]] = {}
    for system, emulator, core, _spec in es_systems_entries(text):
        if emulator == "libretro" and core and core not in dropped:
            found.setdefault(core, set()).add(system)
    return {core: sorted(systems) for core, systems in sorted(found.items())}


def es_systems_by_system(
    es_systems_text: str, defaults_text: str, dropped: set[str],
    built: Callable[[str], bool] | None = None,
) -> dict[str, list[str]]:
    """system -> the cores es_systems.yml offers it, in the file's order.

    Read as configgen_cores reads the whole list: a core under `libretro:`
    is a libretro core, any other emulator is its own core and so is each
    build it lists. The core configgen-defaults.yml starts by default comes
    last when es_systems.yml does not offer it.
    """
    data = _es_systems_data(es_systems_text)
    defaults = yaml_load_upstream(defaults_text)
    if not isinstance(defaults, dict):
        raise ValueError("configgen-defaults.yml is not a mapping")
    result: dict[str, list[str]] = {}
    for system, spec in data.items():
        names: list[str] = []
        for offered, core, _item in _system_entries(spec):
            if offered != "libretro":
                names.append(offered)
            if core:
                names.append(core)
        default = defaults.get(system)
        if isinstance(default, dict):
            emulator, core = default.get("emulator"), default.get("core")
            if (built is not None and emulator and emulator != "libretro"
                    and str(emulator) not in names and not built(str(emulator))):
                # A default the build lacks (configgen_cores).
                emulator = core = None
            if emulator and emulator != "libretro":
                names.append(str(emulator))
            if core:
                names.append(str(core))
        names = [n for n in dict.fromkeys(names) if n not in dropped]
        if names:
            result[str(system)] = names
    return result


SYSTEM_SLUG_MAP = {
    "advision": "entex-advision",
    "amiga500": "commodore-amiga",
    "bbc": "acorn-bbc-micro",
    "bk": "elektronika-bk",
    "gp32": "gamepark-gp32",
    # MSU-MD runs on the Mega Drive cores and loads the Mega-CD BIOS.
    "megadrive-msu": "sega-mega-cd",
    "segaai": "sega-ai",
    "socrates": "vtech-socrates",
    "sufami": "nintendo-sufami-turbo",
    "videopacplus": "philips-videopac",
    "vsmile": "vtech-vsmile",
    "atari800": "atari-400-800",
    "atari5200": "atari-5200",
    "atarist": "atari-st",
    "lynx": "atari-lynx",
    "3do": "3do",
    "amiga": "commodore-amiga",
    "amiga600": "commodore-amiga",
    "amiga1200": "commodore-amiga",
    "amigacd32": "commodore-amiga",
    "amigacdtv": "commodore-amiga",
    "c128": "commodore-c128",
    "colecovision": "coleco-colecovision",
    "dreamcast": "sega-dreamcast",
    "naomi": "sega-dreamcast-arcade",
    "naomi2": "sega-dreamcast-arcade",
    "atomiswave": "sega-dreamcast-arcade",
    "fds": "nintendo-fds",
    "gamecube": "nintendo-gamecube",
    "gb": "nintendo-gb",
    "gba": "nintendo-gba",
    "gbc": "nintendo-gbc",
    "nds": "nintendo-ds",
    "n64dd": "nintendo-64dd",
    "satellaview": "nintendo-satellaview",
    "sgb": "nintendo-sgb",
    "snes": "nintendo-snes",
    "channelf": "fairchild-channel-f",
    "intellivision": "mattel-intellivision",
    "msx": "microsoft-msx",
    "msx1": "microsoft-msx",
    "msx2": "microsoft-msx",
    "msxturbor": "microsoft-msx",
    "neogeo": "snk-neogeo",
    "neogeocd": "snk-neogeo-cd",
    "odyssey2": "magnavox-odyssey2",
    "pcengine": "nec-pc-engine",
    "pcenginecd": "nec-pc-engine",
    "supergrafx": "nec-pc-engine",
    "pc88": "nec-pc-88",
    "pc98": "nec-pc-98",
    "pcfx": "nec-pc-fx",
    "psx": "sony-playstation",
    "ps2": "sony-playstation-2",
    "psp": "sony-psp",
    "saturn": "sega-saturn",
    "segacd": "sega-mega-cd",
    "mastersystem": "sega-master-system",
    "megadrive": "sega-mega-drive",
    "gamegear": "sega-game-gear",
    "x1": "sharp-x1",
    "x68000": "sharp-x68000",
    "zxspectrum": "sinclair-zx-spectrum",
    "scummvm": "scummvm",
    "doom": "doom",
    "macintosh": "apple-macintosh-ii",
    "dos": "dos",
    "videopac": "philips-videopac",
    "pokemini": "nintendo-pokemon-mini",
    "gsplus": "apple-iigs",
    "apple2": "apple-ii",
    "apple2gs": "apple-iigs",
    "ps3": "sony-playstation-3",
    "psvita": "sony-playstation-vita",
    "coco": "coco",
    "dragon32": "dragon32",
    "dragon64": "dragon64",
    "mc10": "mc10",
    "msx2+": "microsoft-msx",
    "spectravideo": "spectravideo",
    "tvc": "videoton-tvc",
    "enterprise": "enterprise-64-128",
    "vis": "tandy-vis",
    "supracan": "supracan",
    "jaguar": "atari-jaguar",
    "jaguarcd": "atari-jaguar",
    "switch": "nintendo-switch",
    "wii": "nintendo-wii",
    "xbox360": "microsoft-xbox-360",
}


_MD5_RE = re.compile(r"^[a-fA-F0-9]+$")


def _load_md5_index() -> dict[str, str]:
    """Load by_md5 index from database.json for prefix resolution."""
    db_path = REPO_ROOT / DB_FILE
    if not db_path.exists():
        return {}
    return load_database(str(db_path)).get("indexes", {}).get("by_md5", {})


def _resolve_truncated_md5(md5: str, md5_index: dict[str, str]) -> str:
    """Resolve a truncated MD5 to its full 32-char version (cut_md5_owner)."""
    if not md5 or len(md5) == 32:
        return md5
    if not _MD5_RE.match(md5):
        return md5
    owner = cut_md5_owner(md5, md5_index)
    if owner:
        print(f"  fixed truncated md5: {md5} -> {owner}", file=sys.stderr)
        return owner
    return md5


# `systems = {`, or `systems = OrderedDict({` as older forks write it.
_SYSTEMS_START = re.compile(r"^systems\s*=\s*(?:OrderedDict\(\s*)?\{", re.MULTILINE)


def comment_start(line: str) -> int | None:
    """Index of the # opening a comment on `line`, strings of either quote read whole."""
    quote = None
    j = 0
    while j < len(line):
        ch = line[j]
        if ch == "\\":
            j += 2
            continue
        if quote:
            if ch == quote:
                quote = None
        elif ch in ('"', "'"):
            quote = ch
        elif ch == "#":
            return j
        j += 1
    return None


def _strip_comment(line: str) -> str:
    """The line without a trailing # comment, strings kept whole."""
    cut = comment_start(line)
    return line if cut is None else line[:cut]


def _closing_brace(raw: str, start: int) -> int:
    """Index of the brace closing the one at `start`, past strings and comments."""
    depth = 0
    i = start
    quote = None
    while i < len(raw):
        ch = raw[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in ('"', "'"):
            quote = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        elif ch == "#":
            i = raw.find("\n", i)
            if i == -1:
                break
        i += 1
    raise ValueError("the systems dict is not closed")


def systems_span(raw: str) -> tuple[int, int]:
    """Offsets of the opening and closing brace of the `systems` dict of a
    batocera-systems script.

    Found by reading strings and comments, never by running the script.
    Raises ValueError when the script assigns no such dict or never closes it.
    """
    match = _SYSTEMS_START.search(raw)
    if not match:
        raise ValueError("no 'systems = {' in the script")
    start = match.end() - 1
    return start, _closing_brace(raw, start)


def extract_systems_dict(raw: str) -> dict:
    """The `systems` dict of a batocera-systems style script.

    Read with ast.literal_eval, never executed: the text is the platform's
    code. A key written twice keeps its later value, as it does when Python
    runs the script.
    """
    start, end = systems_span(raw)
    clean_dict_str = "\n".join(_strip_comment(line) for line in raw[start : end + 1].split("\n"))

    # OrderedDict({...}) -> just the inner dict literal
    clean_dict_str = re.sub(r"OrderedDict\(\s*\{", "{", clean_dict_str)
    clean_dict_str = re.sub(r"\}\s*\)", "}", clean_dict_str)

    try:
        return ast.literal_eval(clean_dict_str)
    except (SyntaxError, ValueError) as e:
        raise ValueError(f"Failed to parse systems dict: {e}") from e


def is_checkbios_script(raw_data: str) -> bool:
    """A batocera-systems script as its forks ship it: the `systems` dict of
    biosFiles and the checkBios that reads it."""
    has_dict = _SYSTEMS_START.search(raw_data) is not None
    return has_dict and "def checkBios" in raw_data and '"biosFiles"' in raw_data


def requirements_from_systems(
    systems: dict, slug_map: dict[str, str], strip: str = "bios/"
) -> list[BiosRequirement]:
    """One requirement per biosFiles item, filed under our system slug.

    `strip` is the part of each declared path that the platform's
    base_destination already stands for: `bios/` where the pack is extracted
    into the BIOS folder, nothing where it is extracted into the folder the
    script's prefix names (AmberELEC and EmuELEC declare `neogeo/neogeo.zip`
    and `ports/...` beside `bios/`).
    """
    requirements = []
    md5_index = _load_md5_index()
    for sys_key, sys_data in systems.items():
        system_slug = slug_map.get(sys_key, sys_key)
        for bios in sys_data.get("biosFiles", []):
            declared_path = bios.get("file", "")
            file_path = declared_path
            values, as_list = md5_field(bios.get("md5"))
            md5 = ",".join(
                _resolve_truncated_md5(value, md5_index) for value in values
            )
            zipped_file = bios.get("zippedFile", "")
            if strip and file_path.startswith(strip):
                file_path = file_path[len(strip):]
            native: dict[str, object] = {"native_name": sys_data.get("name", "")}
            if as_list:
                native["md5_list"] = True
            requirements.append(
                BiosRequirement(
                    name=file_path.split("/")[-1],
                    system=system_slug,
                    md5=md5 or None,
                    # checkBios tries altmd5 when the zipped member's md5 differs.
                    alt_md5=bios.get("altmd5") or None,
                    destination=file_path,
                    native_path=declared_path,
                    required=True,
                    zipped_file=zipped_file or None,
                    native_id=sys_key,
                    native=native,
                )
            )
    return requirements


def platform_systems(
    requirements: list[BiosRequirement], source_dict: dict, slug_map: dict[str, str]
) -> dict:
    """The `systems:` section of a platform YAML, in the script's order."""
    display_names: dict[str, str] = {}
    for sys_key, sys_data in source_dict.items():
        dname = sys_data.get("name", "")
        if dname:
            display_names[slug_map.get(sys_key, sys_key)] = dname

    def system_fields(req: BiosRequirement) -> dict:
        fields = {"native_id": req.native_id, "name": display_names.get(req.system)}
        return {key: value for key, value in fields.items() if value}

    systems = systems_from_requirements(requirements, system_fields)
    return systems


def configgen_cores(
    defaults_text: str, es_systems_text: str, dropped: set[str],
    built: Callable[[str], bool] | None = None,
) -> tuple[list[str], list[str], list[str]]:
    """Core names, standalone cores and dual-mode cores of a configgen build.

    Standalone cores are those with emulator != "libretro" in
    configgen-defaults.yml or listed outside `libretro:` in es_systems.yml,
    dual-mode ones those es_systems.yml also offers under libretro (dolphin
    for GameCube). `dropped` names what es_systems.yml files under an
    emulator without being one.

    `built` says whether some board builds a name (boards_build). What it
    answers no for is not run: KNULLI's es_systems lists citron and shadps4,
    which no KNULLI board selects, and its defaults pick suyu, which no
    package builds. A default's core follows a standalone emulator the
    build runs (vox_official is lexaloffle's Voxatron build).
    """
    data = yaml_load_upstream(defaults_text)
    cores, standalone = es_systems_emulators(es_systems_text)
    libretro = es_systems_libretro(es_systems_text)
    if not cores:
        raise RuntimeError("es_systems.yml names no emulator")
    if built is not None:
        cores = {name for name in cores if built(name)}
        standalone &= cores
    for system, cfg in data.items():
        if system == "default" or not isinstance(cfg, dict):
            continue
        emulator = cfg.get("emulator", "")
        core = cfg.get("core", "")
        if emulator and emulator != "libretro":
            if built is not None and not built(emulator):
                continue
            standalone.add(emulator)
            if core and core != emulator:
                standalone.add(core)
        elif built is not None and core and not built(core):
            continue
        if core:
            cores.add(core)
    dual = (standalone & libretro) - dropped
    return sorted(cores - dropped), sorted(standalone - dropped), sorted(dual)


def boards_build(selection: BuildSelection, launchers: list[dict]) -> Callable[[str], bool]:
    """Whether some board of a build runs an emulator.

    es_systems.yml ties each name to the packages that build it
    (requireAnyOf), and a name it lists is built when a board selects one of
    them: KNULLI lists citron and shadps4, and its Config.in selects them
    only on x86_64 boards, which it has none of. A name only
    configgen-defaults.yml gives is built when a board selects the package
    of that name: the symbol its Config.in defines, else the one Buildroot
    derives from the folder (BR2_PACKAGE_<NAME>, package/pkg-generic.mk). A
    program the launcher runs from the BIOS folder (lexaloffle,
    /userdata/bios/pico-8/pico8) needs no package.
    """
    supplied = {
        name.strip()
        for record in launchers
        if record.get("passes_to") == "exec"
        and str(record.get("search_dir") or "").startswith("/userdata/bios")
        for name in str(record.get("emulator", "")).split(",")
    }

    def built(name: str) -> bool:
        if name in selection.emulators or name in supplied:
            return True
        if name in selection.listed:
            return False
        symbol = selection.packages.get(name) or (
            "BR2_PACKAGE_" + name.upper().replace("-", "_"))
        return symbol in selection.symbols

    return built


def installable_cores(
    selection: BuildSelection, cores: list[str], standalone: list[str], dual: list[str],
) -> list[str]:
    """Buildbot cores a board's RetroArch core downloader installs, beyond
    the libretro cores the image builds.

    The targets scraper names, per board, the RetroArch targets entry its
    downloader reads (`downloads`): a Batocera x86_64 board installs any
    core of linux-x86_64, an armv7 one any of linux-armhf. A name compares
    within its build mode: amiberry built standalone is another program
    than amiberry_libretro, which the buildbot serves.
    """
    found: set[str] = set()
    for entry in selection.targets.values():
        if entry.get("downloads"):
            found |= load_target_config("retroarch", entry["downloads"]) or set()
    built_libretro = (set(cores) - set(standalone)) | set(dual)
    return sorted(found - built_libretro)


def records_run(launchers: list[dict], built: Callable[[str], bool]) -> list[dict]:
    """The launcher records of emulators the build runs.

    configgen keeps the generators of emulators a build does not select
    (KNULLI's citron, pcsx2, shadps4): what they read is never read on the
    device, so the records do not describe the platform.
    """
    return [r for r in launchers if any(built(n) for n in str(r["emulator"]).split(", "))]


class CheckBiosScraper(BaseScraper):
    """A batocera-systems list as Batocera and its forks ship it."""

    # Our slug for each system key of the list.
    slug_map: ClassVar[dict[str, str]] = SYSTEM_SLUG_MAP
    # The list's file name, for the format refusal.
    list_name: ClassVar[str] = "batocera-systems"
    # What base_destination already stands for in each declared path
    # (requirements_from_systems).
    strip: ClassVar[str] = "bios/"

    def validate_format(self, raw_data: str) -> bool:
        return is_checkbios_script(raw_data)

    def fetch_requirements(self) -> list[BiosRequirement]:
        """Parse the list and return BIOS requirements."""
        raw = self._fetch_raw()
        if not self.validate_format(raw):
            raise ValueError(f"{self.list_name} format validation failed")
        return requirements_from_systems(extract_systems_dict(raw), self.slug_map, strip=self.strip)

    def platform_systems(self) -> dict:
        """The `systems:` section of the platform YAML, in the script's order."""
        return platform_systems(
            self.fetch_requirements(), extract_systems_dict(self._fetch_raw()), self.slug_map
        )


class Scraper(CheckBiosScraper):
    """Scraper for batocera-systems Python dict."""

    def __init__(self) -> None:
        self.tag = fetch_stable_tag()
        super().__init__(url=SOURCE_URL.format(tag=self.tag))

    def _fetch_cores(
        self, built: Callable[[str], bool] | None = None
    ) -> tuple[list[str], list[str], list[str]]:
        """Core names, standalone cores and dual-mode cores at the pinned tag.

        With `built` (boards_build), a name counts when some board builds
        it or its launcher runs a program from the BIOS folder.
        """
        return configgen_cores(
            fetch_text(CONFIGGEN_DEFAULTS_URL.format(tag=self.tag)),
            fetch_text(ES_SYSTEMS_URL.format(tag=self.tag)),
            _not_cores(),
            built,
        )

    def validate_format(self, raw_data: str) -> bool:
        """Validate batocera-systems format."""
        has_systems = "systems" in raw_data and "biosFiles" in raw_data
        has_dict = _SYSTEMS_START.search(raw_data) is not None
        has_md5 = '"md5"' in raw_data
        has_file = '"file"' in raw_data
        return has_systems and has_dict and has_md5 and has_file

    def generate_platform_yaml(self) -> dict:
        """Generate a platform YAML config dict from scraped data."""
        systems = self.platform_systems()

        launchers = extract_launchers(
            lambda path: fetch_text(f"{_RAW_BASE}/{self.tag}/{path}")
        )
        selection = BoardTargets().build_selection(self.tag)
        built = boards_build(selection, launchers)
        launchers = records_run(launchers, built)
        cores, standalone, dual = self._fetch_cores(built)
        installable = installable_cores(selection, cores, standalone, dual)
        libretro_systems = es_systems_libretro_systems(
            fetch_text(ES_SYSTEMS_URL.format(tag=self.tag)), _not_cores()
        )
        result = {
            "platform": "Batocera",
            "version": self.tag.removeprefix("batocera-"),
            "homepage": "https://batocera.org",
            "source": self.url,
            "base_destination": "bios",
            "hash_type": "md5",
            "verification_mode": "md5",
            "cores": cores,
            "systems": systems,
        }
        result.update(optional_core_lists(standalone, dual, installable))
        # The systems each libretro core runs for: its save folders.
        result["libretro_systems"] = libretro_systems
        result["launchers"] = launchers
        result["configs_root"] = configs_root(
            Configgen(lambda path: fetch_text(f"{_RAW_BASE}/{self.tag}/{path}"))
        )
        return result


def main() -> None:
    from scripts.scraper.base_scraper import scraper_cli

    scraper_cli(Scraper, "Scrape batocera BIOS requirements")


if __name__ == "__main__":
    main()
