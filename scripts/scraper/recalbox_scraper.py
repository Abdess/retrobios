#!/usr/bin/env python3
"""Scraper for Recalbox BIOS requirements.

Source: https://gitlab.com/recalbox/recalbox/-/raw/master/board/recalbox/fsoverlay/recalbox/share_init/system/.emulationstation/es_bios.xml
Format: XML (es_bios.xml)
Hash: MD5 (multiple valid hashes per entry, comma-separated)

Recalbox verification logic:
- Checks MD5 of file on disk against list of valid hashes
- Multiple MD5s accepted per BIOS (different ROM revisions)
- Alternate file paths (pipe-separated)
- hashMatchMandatory flag: if false, wrong hash = warning (YELLOW) not error (RED)
- ZIP files get composite MD5 calculation
"""

from __future__ import annotations

from common import parse_untrusted_xml

from .base_scraper import BaseScraper, BiosRequirement, fetch_bytes, requirement_entry
from .recalbox_launchers import SOURCE_FILES as LAUNCHER_FILES
from .recalbox_launchers import LauncherShapeError, extract_launchers

PLATFORM_NAME = "recalbox"

def _fetch_gitlab_stable_tag() -> str:
    """Fetch the latest stable x.y.z tag from the Recalbox GitLab."""
    import json
    import re

    url = "https://gitlab.com/api/v4/projects/recalbox%2Frecalbox/repository/tags?per_page=50"
    try:
        tags = json.loads(fetch_bytes(url))
    except (ConnectionError, json.JSONDecodeError) as e:
        raise RuntimeError(f"cannot list Recalbox tags: {e}") from e
    stable = [t["name"] for t in tags if re.fullmatch(r"[0-9]+\.[0-9]+(\.[0-9]+)?", t["name"])]
    if not stable:
        raise RuntimeError("no stable Recalbox tag among the latest 50")
    return stable[0]


SOURCE_URL = (
    "https://gitlab.com/recalbox/recalbox/-/raw/{tag}/"
    "board/recalbox/fsoverlay/recalbox/share_init/system/"
    ".emulationstation/es_bios.xml"
)

SYSTEM_SLUG_MAP = {
    "3do": "3do",
    "bk": "elektronika-bk",
    "dragon": "dragon64",
    "palm": "palm-os",
    "pokemini": "nintendo-pokemon-mini",
    "sufami": "nintendo-sufami-turbo",
    "videopacplus": "philips-videopac",
    "trs80coco": "coco",
    "amiga600": "commodore-amiga",
    "amiga1200": "commodore-amiga",
    "amigacd32": "commodore-amiga",
    "amigacdtv": "commodore-amiga",
    "amstradcpc": "amstrad-cpc",
    "atari800": "atari-400-800",
    "atari5200": "atari-5200",
    "atari7800": "atari-7800",
    "atarilynx": "atari-lynx",
    "atarist": "atari-st",
    "c64": "commodore-c64",
    "channelf": "fairchild-channel-f",
    "colecovision": "coleco-colecovision",
    "dreamcast": "sega-dreamcast",
    "fds": "nintendo-fds",
    "gamecube": "nintendo-gamecube",
    "gamegear": "sega-game-gear",
    "gb": "nintendo-gb",
    "gba": "nintendo-gba",
    "gbc": "nintendo-gbc",
    "intellivision": "mattel-intellivision",
    "jaguar": "atari-jaguar",
    "mastersystem": "sega-master-system",
    "megadrive": "sega-mega-drive",
    "msx": "microsoft-msx",
    "msx1": "microsoft-msx",
    "msx2": "microsoft-msx",
    "n64": "nintendo-64",
    "naomi": "sega-dreamcast-arcade",
    "naomigd": "sega-dreamcast-arcade",
    "atomiswave": "sega-dreamcast-arcade",
    "nds": "nintendo-ds",
    "neogeo": "snk-neogeo",
    "neogeocd": "snk-neogeo-cd",
    "o2em": "magnavox-odyssey2",
    "pcengine": "nec-pc-engine",
    "pcenginecd": "nec-pc-engine",
    "pcfx": "nec-pc-fx",
    "ps2": "sony-playstation-2",
    "psx": "sony-playstation",
    "saturn": "sega-saturn",
    "scummvm": "scummvm",
    "segacd": "sega-mega-cd",
    "snes": "nintendo-snes",
    "supergrafx": "nec-pc-engine",
    "x68000": "sharp-x68000",
    "zxspectrum": "sinclair-zx-spectrum",
}


SYSTEMS_TREE_URL = (
    "https://gitlab.com/api/v4/projects/recalbox%2Frecalbox/repository/tree"
    "?path=package/recalbox-romfs2/systems&ref={tag}&per_page=100&page={page}"
)
SYSTEMS_DIR = "package/recalbox-romfs2/systems"
# One raw read per system.ini made about 150 requests and GitLab throttled
# the scrape past half an hour. GraphQL returns a batch of blobs at once.
GRAPHQL_URL = "https://gitlab.com/api/graphql"
BLOBS_QUERY = (
    "query($paths: [String!]!, $ref: String!) { project(fullPath: \"recalbox/recalbox\") "
    "{ repository { blobs(paths: $paths, ref: $ref) { nodes { path rawBlob } } } } }"
)
BLOBS_PER_QUERY = 50


def _ini_sections(text: str) -> dict[str, dict[str, str]]:
    """Sections and their key = value lines of one Recalbox system.ini.

    Recalbox's .ini files are not strict INI (a value can run on a bare
    line), so only sections and key = value lines are read.
    """
    import re

    sections: dict[str, dict[str, str]] = {}
    current: dict[str, str] | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith((";", "#")):
            continue
        header = re.fullmatch(r"\[([^\]]+)\]", line)
        if header:
            current = sections.setdefault(header.group(1).strip(), {})
            continue
        if current is not None and "=" in line:
            key, value = line.split("=", 1)
            current[key.strip()] = value.strip().strip('"')
    return sections


def _core_names(values: dict[str, str]) -> tuple[set[str], set[str]]:
    """(cores, standalone) one [core.N] section names."""
    emulator = values.get("emulator", "")
    core = values.get("core", "")
    if emulator == "libretro":
        return ({core} if core else set()), set()
    if not emulator:
        return set(), set()
    names = {emulator} | ({core} if core and core != emulator else set())
    return names, set(names)


def system_ini_libretro(text: str) -> set[str]:
    """The libretro cores one Recalbox system.ini offers."""
    import re

    return {
        values.get("core", "")
        for section, values in _ini_sections(text).items()
        if re.fullmatch(r"core\.\d+(\.[\w-]+)?", section)
        and values.get("emulator") == "libretro" and values.get("core")
    }


def system_ini_name(text: str, folder: str) -> str:
    """The system name a system.ini gives, the one ES passes configgen.

    configgen hands a libretro core /recalbox/share/saves/<that name>
    (projects/configgen/configgen/generators/libretro/libretroRetroarch.py
    savesFolder). The folder name stands in where the file names none.
    """
    return _ini_sections(text).get("system", {}).get("name") or folder


def libretro_systems(inis: dict[str, str]) -> dict[str, list[str]]:
    """libretro core -> the systems whose system.ini offers it.

    ``inis`` maps each system folder to its system.ini.
    """
    found: dict[str, set[str]] = {}
    for folder, text in inis.items():
        name = system_ini_name(text, folder)
        for core in system_ini_libretro(text):
            found.setdefault(core, set()).add(name)
    return {core: sorted(systems) for core, systems in sorted(found.items())}


def system_ini_cores(text: str) -> tuple[set[str], set[str]]:
    """The cores one Recalbox system.ini offers, and those run standalone.

    Each ``[core.N]`` section (or its board override ``[core.N.<board>]``)
    names an ``emulator`` and a ``core``: ``libretro`` with the core's name,
    or a standalone emulator. es_bios.xml only names the cores that need a
    BIOS, so read alone it left most of Recalbox's cores outside the pack.
    """
    import re

    cores: set[str] = set()
    standalone: set[str] = set()
    for section, values in _ini_sections(text).items():
        if not re.fullmatch(r"core\.\d+(\.[\w-]+)?", section):
            continue
        found, alone = _core_names(values)
        cores |= found
        standalone |= alone
    return cores, standalone


# romfs2 systemholder.py reads core.0 to core.19.
CORE_SLOTS = 20


def board_cores(text: str, board: str, enabled: set[str]) -> set[str]:
    """The cores of one system.ini a board's image builds.

    romfs2 builds each board's list as systemholder.py does: a slot exists
    as ``[core.N]`` or as ``[core.N.<board>]`` alone (gb's bsnes on x86_64),
    each key is read from the board's section, then as ``<key>.<board>``,
    then plain, and a core is kept when the Buildroot package it names is
    enabled in the board's defconfig.
    """
    sections = _ini_sections(text)
    cores: set[str] = set()
    for slot in range(CORE_SLOTS):
        plain, own = f"core.{slot}", f"core.{slot}.{board}"
        if plain not in sections and own not in sections:
            continue

        def read(key: str, plain: str = plain, own: str = own) -> str:
            for where, name in ((own, key), (plain, f"{key}.{board}"), (plain, key)):
                if name in sections.get(where, {}):
                    return sections[where][name]
            return ""

        if read("package") in enabled:
            cores |= _core_names({"emulator": read("emulator"), "core": read("core")})[0]
    return cores


class Scraper(BaseScraper):
    """Scraper for Recalbox es_bios.xml."""

    def __init__(self, tag: str | None = None) -> None:
        # A target scraper passes the tag platforms/recalbox.yml pins.
        self.tag = tag or _fetch_gitlab_stable_tag()
        super().__init__(url=SOURCE_URL.format(tag=self.tag))

    def _system_inis(self, systems: list[str]) -> list[str]:
        """Every system's system.ini at the tag, read in batches."""
        paths = [f"{SYSTEMS_DIR}/{system}/system.ini" for system in systems]
        texts = self._blobs(paths)
        return [texts[path] for path in paths]

    def _blobs(self, paths: list[str]) -> dict[str, str]:
        """The files at `paths` at the tag, read in batches."""
        import json

        texts: dict[str, str] = {}
        for start in range(0, len(paths), BLOBS_PER_QUERY):
            batch = paths[start:start + BLOBS_PER_QUERY]
            body = json.dumps({"query": BLOBS_QUERY,
                               "variables": {"paths": batch, "ref": self.tag}}).encode()
            answer = json.loads(fetch_bytes(
                GRAPHQL_URL, data=body, headers={"Content-Type": "application/json"},
            ))
            try:
                nodes = answer["data"]["project"]["repository"]["blobs"]["nodes"]
            except (KeyError, TypeError) as exc:
                raise RuntimeError(f"GitLab returned no blobs: {answer.get('errors')}") from exc
            texts.update({n["path"]: n["rawBlob"] for n in nodes if n.get("rawBlob")})
        missing = [path for path in paths if path not in texts]
        if missing:
            raise RuntimeError(f"nothing at {self.tag} for {', '.join(missing[:5])}")
        return texts

    def _fetch_launchers(self) -> list[dict]:
        """Launcher records read from configgen at the scraped tag."""
        texts = self._blobs(list(LAUNCHER_FILES))

        def read(path: str) -> str:
            if path not in texts:
                raise LauncherShapeError(f"{path} is read but not in SOURCE_FILES")
            return texts[path]

        return extract_launchers(read)

    def _fetch_cores(self) -> tuple[list[str], list[str], list[str]]:
        """Every core Recalbox's systems offer, those it runs standalone, and
        those it offers both as a libretro core and standalone.

        Read from each system.ini of recalbox-romfs2 at the scraped tag: the
        systems ES lists and the cores a user can pick for each.
        """
        import json

        systems: list[str] = []
        page = 1
        while True:
            listing = json.loads(fetch_bytes(SYSTEMS_TREE_URL.format(tag=self.tag, page=page)))
            systems += [
                item["name"] for item in listing
                if item.get("type") == "tree" and not item["name"].startswith(".")
            ]
            if len(listing) < 100:
                break
            page += 1
        if not systems:
            raise RuntimeError(f"no Recalbox system found at {self.tag}")
        cores: set[str] = set()
        standalone: set[str] = set()
        libretro: set[str] = set()
        texts = self._system_inis(systems)
        # The systems each libretro core runs for: its save folders.
        self.libretro_systems = libretro_systems(dict(zip(systems, texts)))
        for text in texts:
            found, alone = system_ini_cores(text)
            cores |= found
            standalone |= alone
            libretro |= system_ini_libretro(text)
        if not cores:
            raise RuntimeError(f"no core in Recalbox's system.ini files at {self.tag}")
        return sorted(cores), sorted(standalone), sorted(libretro & standalone)

    def fetch_requirements(self) -> list[BiosRequirement]:
        """Parse es_bios.xml and return BIOS requirements."""
        raw = self._fetch_raw()

        if not self.validate_format(raw):
            raise ValueError("es_bios.xml format validation failed")

        root = parse_untrusted_xml(raw, "es_bios.xml")
        requirements = []
        seen = set()

        for system_elem in root.findall(".//system"):
            platform = system_elem.get("platform", "")
            # One <system> can serve several platforms ("msx1,msx2", "gb,gbc"):
            # it is filed under the first, which names the machine family.
            first = platform.split(",")[0].strip()
            system_slug = SYSTEM_SLUG_MAP.get(first, first)
            fullname = system_elem.get("fullname", "")

            for bios_elem in system_elem.findall("bios"):
                paths_str = bios_elem.get("path", "")
                md5_str = bios_elem.get("md5", "")
                mandatory = bios_elem.get("mandatory", "true") != "false"

                paths = [p.strip() for p in paths_str.split("|") if p.strip()]
                if not paths:
                    continue

                primary_path = paths[0]
                name = (
                    primary_path.split("/")[-1] if "/" in primary_path else primary_path
                )

                md5_list = [m.strip() for m in md5_str.split(",") if m.strip()]
                all_md5 = ",".join(md5_list) if md5_list else None

                dedup_key = (platform, primary_path)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                native: dict[str, object] = {}
                if fullname:
                    native["native_name"] = fullname
                core = bios_elem.get("core", "").strip()
                if core:
                    native["core"] = core
                note = bios_elem.get("note", "").strip()
                if note:
                    native["note"] = note
                # Recalbox reads a missing attribute as true for both flags,
                # so only the explicit value carries information.
                hash_match = bios_elem.get("hashMatchMandatory")
                if hash_match is not None:
                    native["hash_match_mandatory"] = hash_match != "false"
                if bios_elem.get("mandatory") is not None:
                    native["mandatory_declared"] = mandatory
                if len(paths) > 1:
                    native["alt_paths"] = paths[1:]

                requirements.append(
                    BiosRequirement(
                        name=name,
                        system=system_slug,
                        md5=all_md5,
                        destination=primary_path,
                        required=mandatory,
                        native_id=platform,
                        native=native,
                    )
                )

        return requirements

    def validate_format(self, raw_data: str) -> bool:
        """Validate es_bios.xml format."""
        return "<biosList" in raw_data and "<system" in raw_data and "<bios" in raw_data

    def generate_platform_yaml(self) -> dict:
        """Generate a platform YAML config dict from scraped data."""
        requirements = self.fetch_requirements()

        systems: dict[str, dict] = {}
        for req in requirements:
            if req.system not in systems:
                sys_entry: dict = {"files": []}
                if req.native_id:
                    sys_entry["native_id"] = req.native_id
                systems[req.system] = sys_entry

            systems[req.system]["files"].append(requirement_entry(req))

        cores, standalone, dual = self._fetch_cores()
        return {
            "platform": "Recalbox",
            "version": self.tag,
            "homepage": "https://www.recalbox.com",
            "source": self.url,
            "base_destination": "bios",
            "hash_type": "md5",
            "verification_mode": "md5",
            "cores": cores,
            "standalone_cores": standalone,
            # Launched both ways: each layout gets its files.
            **({"dual_mode_cores": dual} if dual else {}),
            "systems": systems,
            "libretro_systems": self.libretro_systems,
            "launchers": self._fetch_launchers(),
        }


def main() -> None:
    """CLI entry point."""
    from .base_scraper import scraper_cli

    scraper_cli(Scraper, "Scrape Recalbox es_bios.xml")


if __name__ == "__main__":
    main()
