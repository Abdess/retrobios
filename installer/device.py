"""The device this runs on: the board it was built for and the system version it runs."""
from __future__ import annotations

import platform
import re
from collections.abc import Callable
from pathlib import Path
from typing import NamedTuple

from installer.cards import _mounted_cards
from installer.detect_os import _on_device, _parse_os_release
from installer.host_fs import _is_dir, _is_file
from installer.platforms import display_name
from installer.text import _CONTROLS

# Where an embedded system names the board it was built for, in the words
# of our target lists: batocera-system.mk writes BATOCERA_SYSTEM_ARCH,
# recalbox-system.mk RECALBOX_SYSTEM_PLATFORM, ROCKNIX's scripts/image puts
# HW_DEVICE in os-release (RK3326, our rk3326). Lakka's scripts/image writes
# LIBREELEC_DEVICE when the image is built for a device (RPi4) and always
# LIBREELEC_PROJECT (Generic): the first one set is the board. KNULLI moves
# /usr/share/batocera to /usr/share/knulli (knulli-linux 57afa662,
# board/scripts/post-build-script.sh:264-278) and writes KNULLI_SYSTEM_ARCH
# to knulli.arch (package/system/knulli-system/knulli-system.mk:98-99).
# AmberELEC's scripts/image writes COREELEC_DEVICE (a21975bf, line 168), the
# DEVICE its Makefile builds (RG351P). EmuELEC's writes the same line (v4.8,
# line 189), the DEVICE of the release image (OdroidGoAdvance).
_BOARD_SOURCES: dict[str, tuple[str, str]] = {
    "amberelec": ("os_release", "COREELEC_DEVICE"),
    "emuelec": ("os_release", "COREELEC_DEVICE"),
    "batocera": ("file", "/usr/share/batocera/batocera.arch"),
    "recalbox": ("file", "/recalbox/recalbox.arch"),
    "rocknix": ("os_release", "HW_DEVICE"),
    "lakka": ("os_release", "LIBREELEC_DEVICE|LIBREELEC_PROJECT"),
    "knulli": ("file", "/usr/share/knulli/knulli.arch"),
    "retropie": ("retropie", ""),
}

# The board a system's own name stands for, where the two differ: the
# target lists are named for the board files (configs/knulli-rk3566.board),
# and the arch file for the TARGET flag the board sets. knulli-rk3566.board
# sets BR2_PACKAGE_BATOCERA_TARGET_RK3568, which knulli-system.mk:22-23
# (20260511) writes as rk3568. batocera-zen3.board sets TARGET_ZEN3, which
# batocera-system.mk:56-57 (batocera-43.1) writes as x86-64-v3.
_BOARD_NAMES: dict[str, dict[str, str]] = {
    "batocera": {"x86-64-v3": "zen3"},
    "knulli": {"rk3568": "rk3566"},
}


# The board a card names on a partition a computer reads. Batocera writes
# its image's board to boot/batocera.board on the BATOCERA boot partition,
# the FAT one beside SHARE (batocera-43.1, board/batocera/scripts/
# post-image-script.sh:60), and reads it there itself (package/batocera/
# core/batocera-scripts/scripts/batocera-info). batocera.arch is inside the
# image, out of a computer's reach. KNULLI writes boot/knulli.board the same
# way (knulli-linux 20260511, board/scripts/post-image-script.sh:66). Both
# write the image's name, which the target list maps to its board.
_CARD_BOARD_FILES: dict[str, str] = {"batocera": "boot/batocera.board",
                                     "knulli": "boot/knulli.board"}


def card_board(platform: str) -> str | None:
    """The board the card mounted here names, None where no card or two
    cards of different boards do: a card is most often prepared on a
    computer, where the system's own board file does not exist."""
    where = _CARD_BOARD_FILES.get(platform)
    if where is None:
        return None
    boards: set[str] = set()
    for mount in _mounted_cards():
        try:
            value = (mount / where).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if value.strip() and not _CONTROLS.search(value.strip()):
            boards.add(value.strip().lower())
    return boards.pop() if len(boards) == 1 else None


def detect_board(platform: str) -> str | None:
    """The board this system was built for, or None where it names none."""
    kind, where = _BOARD_SOURCES.get(platform, ("", ""))
    if kind == "file":
        try:
            value = Path(where).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
    elif kind == "os_release":
        release = _parse_os_release()
        value = next((release[key] for key in where.split("|") if release.get(key)), "")
    elif kind == "retropie":
        value = _retropie_board() or ""
    else:
        return None
    board = value.strip().lower()
    # A board no TARGET line names is written "unknown" (KNULLI's r16).
    if board == "unknown":
        return None
    return _BOARD_NAMES.get(platform, {}).get(board, board) or None


# RetroPie names its board as get_platform does (RetroPie-Setup f5ebfba6,
# scriptmodules/system.sh:396-424 and 425-513): a Pi by the BCM Hardware
# line of /proc/cpuinfo or raspberrypi in its device tree, its model by the
# CPU field (bits 12-15) of a revision code with bit 23 set, rpi1 without
# it. With neither a Hardware line nor a device tree, the machine: x86_64.
# Read only where RetroPie is installed (rootdir /opt/retropie,
# retropie_packages.sh:17): a computer preparing a Pi's card is no Pi.
_RPI_MODELS = {0: "rpi1", 1: "rpi2", 2: "rpi3", 3: "rpi4", 4: "rpi5"}


def _retropie_board() -> str | None:
    """The target RetroPie's own reading of this machine names, or None."""
    if not _is_dir(_on_device("/opt/retropie")):
        return None
    try:
        cpuinfo = _on_device("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace")
    except OSError:
        cpuinfo = ""
    fields = {key.strip(): value.strip() for key, sep, value in
              (line.partition(":") for line in cpuinfo.splitlines()) if sep}
    tree = _on_device("/proc/device-tree/compatible")
    try:
        compatible = tree.read_bytes().decode("ascii", errors="replace")
    except OSError:
        compatible = None
    hardware = fields.get("Hardware", "")
    if hardware.startswith("BCM") or (not hardware and compatible is not None
                                      and "raspberrypi" in compatible):
        try:
            revision = int(fields.get("Revision", ""), 16)
        except ValueError:
            return None
        if not (revision >> 23) & 1:
            return "rpi1"
        return _RPI_MODELS.get((revision >> 12) & 15)
    if hardware or compatible is not None:
        return None
    return "x86_64" if platform.machine() == "x86_64" else None


# A version as a list or a system writes it: v1.22.2, 43.1, 8.3.1.1.
_VERSION_TEXT = re.compile(r"[0-9A-Za-z][0-9A-Za-z._+-]{0,39}")
# What generate_pack.py wrote as every list's version until it recorded the
# platform's own: not a version, so a list holding it names none.
_NO_LIST_VERSION = "1.0"
# What the platform's own check does, not a verdict on it: it compares the
# files with the list of its own version, and no run proved them working.
_MD5_CHECK = ("{name}'s own BIOS check reads the list of the version it runs, and "
              "may show some files as not matching it.")


def _version_line(path: Path) -> str:
    """The first line of a small version file, "" when it cannot be read."""
    if not _is_file(path):
        return ""
    try:
        with path.open("rb") as fh:
            head = fh.read(4096)
    except OSError:
        return ""
    lines = head.decode("utf-8", errors="replace").strip().splitlines()
    return lines[0].strip() if lines else ""


def _batocera_version(_bios_path: Path) -> str:
    # batocera-system.mk:9,100-102 (batocera-43.1): the version, then the
    # date and time of the build.
    words = _version_line(_on_device("/usr/share/batocera/batocera.version")).split()
    return words[0] if words else ""


def _recalbox_version(_bios_path: Path) -> str:
    # Dockerfile:31 (recalbox 10.1.1) writes RECALBOX_VERSION, which
    # .gitlab-ci.yml:723 sets to the release tag, or for a build of a branch
    # to its date and name. A build from a working tree says "development"
    # (projects/configgen/configgen/challenge/RuleScript.py:64). Only a
    # release is a version a list is built for.
    text = _version_line(_on_device("/recalbox/recalbox.version"))
    return text if re.fullmatch(r"\d+(?:\.\d+)+", text) else ""


def _retrobat_version(bios_path: Path) -> str:
    # <RetroBat>/system/version.info, which es-update writes and es-checkversion
    # reads (emulatorlauncher 48cdc616, es-update/RetrobatVersion.cs:66-92).
    # The 8.3.1 installer holds "8.3.1.1-stable-win64".
    text = _version_line(bios_path.parent / "system" / "version.info")
    head = text.split("-", 1)[0]
    return head if re.fullmatch(r"\d+(?:\.\d+)+", head) else ""


def _os_release_version(key: str, value: str) -> Callable[[Path], str]:
    """VERSION_ID from os-release, on the system that names itself so."""
    def read(_bios_path: Path) -> str:
        release = _parse_os_release()
        if release.get(key, "").lower() != value:
            return ""
        return release.get("VERSION_ID", "")
    return read


def _same_release(installed: str, listed: str) -> bool:
    return installed == listed


def _retrobat_release(installed: str, listed: str) -> bool:
    # The release tagged 8.3.1 ships 8.3.1.1: a fourth number is a build of
    # the tagged version.
    return installed == listed or installed.startswith(listed + ".")


class _VersionSource(NamedTuple):
    """Where a system states the version it runs, and what a different one means."""

    read: Callable[[Path], str]
    meaning: str
    same: Callable[[str, str], bool] = _same_release
    # Written by the list (v6.1) and not by the system (6.1).
    prefix: str = ""


# The systems whose version a file states, read without running anything.
# RetroArch writes its version in no file: its lists come from core info
# files the online updater replaces, so its version is not compared. KNULLI
# writes its codename (knulli-system.mk:9,100-102, "scarab") and ROCKNIX the
# date of the build (scripts/image:82), not the release their lists name.
# AmberELEC's list names a prerelease tag, and how that tag maps to the
# VERSION its image writes is not established.
_VERSION_SOURCES: dict[str, _VersionSource] = {
    "batocera": _VersionSource(_batocera_version, _MD5_CHECK),
    "recalbox": _VersionSource(_recalbox_version, _MD5_CHECK),
    "retrobat": _VersionSource(_retrobat_version, _MD5_CHECK, _retrobat_release),
    # scripts/image:159-164 (Lakka-LibreELEC v6.1) writes VERSION_ID from
    # OS_VERSION, "6.1" in distributions/Lakka/version, and ID=lakka.
    "lakka": _VersionSource(
        _os_release_version("ID", "lakka"),
        "Lakka checks only that a file is there, so this matters only where a core "
        "of the version it runs reads a file this list does not name.", prefix="v"),
    # scripts/image:172-177 (EmuELEC v4.8): VERSION_ID from OS_VERSION, 4.8 in
    # distributions/EmuELEC/version, and NAME=EmuELEC.
    "emuelec": _VersionSource(_os_release_version("NAME", "emuelec"), _MD5_CHECK),
}


def version_note(plat: str, bios_path: Path, manifest: dict) -> tuple[str, str, str] | None:
    """(list version, installed version, sentence) when the system here runs
    another version than the one the list was built for, else None: an
    unknown version on either side says nothing."""
    source = _VERSION_SOURCES.get(plat)
    listed = manifest.get("version")
    if (source is None or not isinstance(listed, str) or listed == _NO_LIST_VERSION
            or not _VERSION_TEXT.fullmatch(listed)):
        return None
    installed = source.read(bios_path)
    if not _VERSION_TEXT.fullmatch(installed):
        return None
    compared = listed[len(source.prefix):] if listed.startswith(source.prefix) else listed
    if source.same(installed, compared):
        return None
    name = display_name(plat, manifest)
    return listed, installed, (
        f"This list was built for {name} {listed}, this machine runs {installed}. "
        + source.meaning.format(name=name))
