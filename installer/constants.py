"""Where the file lists and files come from, their limits, and the vocabulary every part shares."""
from __future__ import annotations

import os
import re
import sys
import threading
import urllib.parse
from pathlib import Path

# File lists are read from main, the newest ones, whichever commit the
# installer came from. RETROBIOS_REF pins them to a tag or a commit when
# reproducibility matters.
DEFAULT_RELEASE_REF = "main"
RELEASE_REF = os.environ.get("RETROBIOS_REF", DEFAULT_RELEASE_REF)
DEFAULT_BASE_URL = (
    "https://raw.githubusercontent.com/Abdess/retrobios/"
    + urllib.parse.quote(RELEASE_REF, safe="")
)


_LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "::1")


def _checked_base_url(value: str) -> str:
    """Refuse a base URL that is neither HTTPS nor loopback.

    This base serves the manifest and the files it declares, so whoever
    controls it controls the expected hashes too and verification stops
    proving anything. install.sh and install.ps1 make the same check on the
    URL they fetch the installer from.

    Plain HTTP to loopback stays allowed: nothing sits between the two ends
    to intercept it, and it is how the installer is exercised end to end.
    """
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme == "https":
        return value
    host = (parsed.hostname or "").lower()
    if parsed.scheme == "http" and host in _LOOPBACK_HOSTS:
        return value
    print(
        f"Error: RETROBIOS_BASE_URL must use HTTPS, got {value!r}",
        file=sys.stderr,
    )
    sys.exit(1)


BASE_URL = _checked_base_url(os.environ.get("RETROBIOS_BASE_URL", DEFAULT_BASE_URL))
MANIFEST_URL = f"{BASE_URL}/install/{{platform}}.json"
TARGETS_URL = f"{BASE_URL}/install/targets/{{platform}}.json"
# What --standalone reads, apart from the list every run downloads.
STANDALONE_DIR = "standalone"
STANDALONE_URL = f"{BASE_URL}/install/standalone/{{platform}}.json"
# The platforms that publish a core list per board, install/targets/ in the
# repository: a test holds the two equal. Offline, a platform outside it
# has no hardware targets, where the run sent the user after a list that
# exists nowhere.
TARGET_PLATFORMS = frozenset({
    "amberelec", "batocera", "emudeck", "emuelec", "knulli", "lakka", "recalbox", "retroarch",
    "retrobat", "retrodeck", "retropie", "rocknix", "romm",
})
RAW_FILE_URL = f"{BASE_URL}/{{path}}"
RELEASE_URL = (
    "https://github.com/Abdess/retrobios/releases/download/large-files/{asset}"
)
MAX_RETRIES = 3
# Seconds a connection has to open. A dropped network cost three tries of a
# 30-second timeout, 93 s, before the error: a connection that does not open
# now fails in this time, and once open a read waits as long as before, so
# a slow line is not cut.
CONNECT_TIMEOUT = 4.0
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_TARGETS_BYTES = 4 * 1024 * 1024
MAX_STANDALONE_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_FILES = 100_000
MAX_DOWNLOAD_SIZE = 1024 * 1024 * 1024
# A data directory's source archive: PCSX2's source tarball is the largest.
MAX_DATA_ARCHIVE_SIZE = 4 * 1024 * 1024 * 1024
MAX_TOTAL_DOWNLOAD_SIZE = 64 * 1024 * 1024 * 1024
# Why a manifest leaves a file out, as the installer words it. The manifest
# schema and the generator are held to this list by the tests.
OMISSION_REASONS = {
    "hash_mismatch": "hash mismatch",
    "not_found": "not found",
    "external": "external",
    "user_provided": "user provided",
    "no_platform_slug": "no platform folder",
    "below_platform_folder": "below the platform folder",
    "no_save_directory": "no save directory",
    "no_core_folder": "no core folder",
    "no_save_system": "no system runs the core",
    "outside_bios_folder": "read outside the BIOS folder",
    "no_roms_directory": "no roms folder",
    "no_configs_directory": "no configs folder",
    "no_emulators_directory": "no emulator folder",
}
# What a file is when it is not firmware, as the manifest's category field
# says, and as the installer words it. Firmware carries no category.
GAME_DATA = "game_data"
CATEGORY_LABELS = {GAME_DATA: "game data"}
# The manifest writes its digests in lowercase, as hashlib gives them, and
# every comparison reads them as written.
_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

# The region vocabulary of scripts/region.py, which this file cannot import.
# A test holds the two copies equal.
WORLD_REGION = "world"
REGION_TREE: dict[str, frozenset] = {
    "north-america": frozenset({"canada"}),
    "latin-america": frozenset({"brazil", "mexico", "argentina"}),
    "europe": frozenset({
        "uk", "france", "germany", "italy", "spain", "netherlands", "portugal",
        "greece", "poland", "russia", "sweden", "norway", "denmark", "finland",
    }),
    "asia": frozenset({
        "japan", "south-korea", "china", "taiwan", "hong-kong", "singapore",
        "india", "asia-ntsc", "asia-pal",
    }),
    "oceania": frozenset({"australia", "new-zealand"}),
}
REGION_ALIASES: dict[str, str] = {
    "jp": "japan",
    "ntsc-j": "japan",
    "us": "north-america",
    "usa": "north-america",
    "na": "north-america",
    "ntsc-u": "north-america",
    "eu": "europe",
    "pal": "europe",
    "kr": "south-korea",
    "korea": "south-korea",
    "auto": WORLD_REGION,
    "gb": "uk",
    "ca": "canada",
    "br": "brazil",
    "mx": "mexico",
    "ar": "argentina",
    "fr": "france",
    "de": "germany",
    "it": "italy",
    "es": "spain",
    "nl": "netherlands",
    "pt": "portugal",
    "gr": "greece",
    "pl": "poland",
    "ru": "russia",
    "se": "sweden",
    "no": "norway",
    "dk": "denmark",
    "fi": "finland",
    "cn": "china",
    "tw": "taiwan",
    "hk": "hong-kong",
    "sg": "singapore",
    "in": "india",
    "au": "australia",
    "nz": "new-zealand",
}
AREA_TERRITORIES: dict[str, frozenset] = {
    "asia-ntsc": frozenset({"taiwan"}),
    "asia-pal": frozenset({"china"}),
}
_REGION_PARENT = {
    member: parent for parent, members in REGION_TREE.items() for member in members
}
REGIONS = frozenset({WORLD_REGION} | set(REGION_TREE) | set(_REGION_PARENT))
# Marks a region group named after one file that no system names.
FILE_GROUP = ":file:"
MAX_SELECTION_TAGS = 1000
SELECTION_FIELDS = ("systems", "regions", "region_groups", "region_system_groups")
# The files cores load for systems the platform does not list (game engines,
# computers): no system of the platform owns them, and choosing systems
# leaves them out unless this name is chosen too.
OTHER_SYSTEMS = "other"

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

# Frontends whose BIOS live on their SD card, installed from a computer the
# card is mounted on. Each release unpacks as .system/ at the card root and
# writes its release name as the first line of .system/version.txt (MinUI
# makefile:22-24 and 152-157, NextUI makefile:33-35 and 249, MyMinUI
# makefile:16-19 and 124). The registry publishes the same rules as each
# manifest's `detect` (card_marker), and a test holds the two equal.
CARD_MARKER = ".system/version.txt"
_CARD_RULES: tuple[tuple[str, str, str], ...] = (
    ("minui", CARD_MARKER, "MinUI-"),
    ("nextui", CARD_MARKER, "NextUI-"),
    ("myminui", CARD_MARKER, "MyMinUI-"),
)
CARD_PLATFORMS = frozenset(name for name, _file, _prefix in _CARD_RULES)

SITE_URL = "https://abdess.github.io/retrobios/"
INSTALLER_PAGE = f"{SITE_URL}wiki/installer/"
TROUBLESHOOTING_PAGE = f"{SITE_URL}wiki/troubleshooting/"
# The one-line bootstraps the site serves: BOOTSTRAP_URL for sh, .ps1 after it
# for PowerShell (scripts/sitebootstrap.py).
BOOTSTRAP_URL = f"{SITE_URL}i"

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

# Set when the run is interrupted, so queued downloads end instead of draining
# the pool: every future is submitted before the first one completes.
_stop = threading.Event()
# Set once a run starts writing: Ctrl+C before that has nothing to carry on.
_writing = threading.Event()


class _Interrupted(Exception):
    """Raised inside a worker once the run has been stopped."""


# A file this size or larger keeps its partial download when a transfer
# stops, and the next run asks the server for the rest: the release assets
# run to hundreds of megabytes. Smaller files simply start over.
RESUME_FROM_SIZE = 16 * 1024 * 1024
# Read once, before any download thread runs: reading the umask sets it.
_UMASK = os.umask(0)
os.umask(_UMASK)
