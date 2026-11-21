"""The setups found here, how each is named and told apart, and the line question picking one."""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from installer.cards import (
    _SHARE_FOLDERS,
    _mount_name,
    _mounted_cards,
    _systems_reading,
    card_bound,
    card_setup,
    card_setups,
    card_system,
    doubt_words,
    drive_kind,
)
from installer.console import _ask, _quit
from installer.detection_notes import note_detection
from installer.detect_frontends import _UNNAMEABLE, _android_storage_root, detect_platforms
from installer.detect_os import (
    _DETECTED_OS,
    _FROM_CARD,
    _os_default_dests,
    card_title,
    detect_os,
    detected_os,
    detected_shown,
)
from installer.frontend_folders import _retroarch_config_at
from installer.host_fs import _DETECTION_REFUSED, _is_dir, _is_file
from installer.offline import LOCAL
from installer.platforms import AVAILABLE_PLATFORMS, DEFAULT_DESTS, _name_key, display_name
from installer.terminal import terminal_size
from installer.text import _no_widow, _plural, _wrap
from installer.tui_state import TuiRow, _folded, _matches

if TYPE_CHECKING:
    from installer.tui_state import TuiState


def _card_word(system: tuple[str, Path, str]) -> str:
    """A mounted drive's kind as the first screen writes it: SD card, or
    SHARE drive."""
    return "SD card" if drive_kind(system) == "card" else drive_kind(system)


# Platforms with no install location of their own: the BIOS folder sits
# beside the executable, wherever the archive was extracted.
PORTABLE_ONLY = {
    "bizhawk": "BizHawk reads the Firmware folder beside EmuHawk, and none was found.",
}


def _default_dest(os_type: str, platform_name: str) -> Path | None:
    """Fall back path for a platform named on the command line but not found,
    or None where no folder on this OS is one the platform reads.

    A home directory is meaningless for RetroArch on Android, where Termux
    owns the home and the frontend reads from shared storage. ~/bios is read
    by no platform, RetroBat lives on Windows only, and a Batocera or Recalbox
    path on Windows resolved to the root of the current drive: 8.7 GB under
    C:\\userdata\\bios, reported done.
    """
    default = _built_in_dest(os_type, platform_name)
    if default is not None and (_refused_near(default) or platform_name in _UNNAMEABLE):
        # The Flatpak's own folder at 000 hid the retroarch.cfg naming
        # ~/Games/bios, and 6.6 GB were offered to a folder it does not read.
        return None
    return default


def _built_in_dest(os_type: str, platform_name: str) -> Path | None:
    """The platform's usual folder on this OS, whatever detection met."""
    if os_type == "android" and platform_name == "retroarch":
        return _android_storage_root() / "RetroArch" / "system"
    if platform_name in PORTABLE_ONLY or (os_type == "windows" and platform_name
                                          not in _os_default_dests(os_type)):
        return None
    return (_os_default_dests(os_type).get(platform_name)
            or (None if platform_name == "retrobat" else DEFAULT_DESTS.get(platform_name)))


def _refused_near(default: Path) -> bool:
    """Whether detection met a closed folder under HOME, where configs that
    could name another folder live, or above the default itself."""
    home = Path.home()
    place = default.absolute()
    return any(home in (folder, *folder.parents) or folder in (place, *place.parents)
               for folder, _why in _DETECTION_REFUSED)


# Every device the setup lists name, once, as its maker or its store spells
# the model, with the maker: a system list writes the model, and the filter
# also finds it by its maker's name. Two lists spelled one device two ways
# (Powkiddy RK2023 and RK2023, RGCUBEXX and RG CubeXX, Flip2 and Flip 2), and
# a device typed as one list wrote it found that system alone. A test holds
# every list to these names and each name to one spelling.
_DEVICES: dict[str, str] = {
    **{model: "Anbernic" for model in (
        "RG28XX", "RG34XX", "RG34XX SP", "RG35XX", "RG35XX 2024", "RG35XX H",
        "RG35XX Plus", "RG35XX Pro", "RG35XX SP", "RG40XX H", "RG40XX V", "RG CubeXX",
        "RG ARC", "RG ARC-S", "RG 55G1", "RG351", "RG351M", "RG351MP", "RG351P", "RG351V",
        "RG353", "RG353M", "RG353P", "RG353PS", "RG353V", "RG353VS", "RG503", "RG552")},
    **{model: "Powkiddy" for model in (
        "RGB10", "RGB10X", "RGB10 Max", "RGB10 Max 2", "RGB10 Max 3", "RGB10 Max 3 Pro",
        "RGB20 Pro", "RGB20S", "RGB20SX", "RGB30", "RK2023", "X35H", "X35S", "X55", "V10",
        "PowKiddy Q20 Mini", "PowKiddy Q90", "PowKiddy V90")},
    **{model: "Miyoo" for model in (
        "Miyoo A30", "Miyoo Flip", "Miyoo Mini", "Miyoo Mini Flip", "Miyoo Mini Plus")},
    **{model: "TrimUI" for model in ("TrimUI Brick", "TrimUI Smart", "TrimUI Smart Pro")},
    **{model: "Retroid" for model in (
        "Retroid Pocket", "Retroid Pocket 5", "Retroid Pocket 6", "Retroid Pocket Flip 2",
        "Retroid Pocket Mini", "Retroid Pocket Nova")},
    **{model: "AYN" for model in (
        "AYN Odin", "AYN Odin 2", "AYN Odin 3", "AYN Thor", "AYN Loki Max",
        "AYN Loki Mini Pro", "AYN Loki Zero")},
    **{model: "AYANEO" for model in (
        "AYANEO Pocket", "AYANEO Air", "AYANEO Air Plus", "AYANEO Air Pro", "AYANEO 2",
        "AYANEO 2S", "AYANEO 2021", "AYANEO Geek", "AYANEO Next")},
    **{model: "Hardkernel" for model in (
        "Odroid Go", "Odroid Go Advance", "Odroid Go Super", "Odroid Go Ultra")},
    **{model: "MagicX" for model in (
        "MagicX XU10", "MagicX XU Mini M", "MagicX XU20 V32", "MagicX Mini Zero 28")},
    **{model: "GameForce" for model in ("GameForce Ace", "GameForce Chi")},
    **{model: "SJGAM" for model in ("SJGAM M21", "SJGAM M22 Pro")},
    **{model: "" for model in (
        "R33S", "R35S", "R36H", "R36S", "R36S Plus", "R36S Soysauce", "R40XX Pro Max",
        "XF40H", "K36", "M17", "BittBoy", "Pocket Go", "Sup M3", "XYC Q8", "Android",
        # dArkOS names these two by model alone (v08272026 release notes).
        "A10 Mini", "Miniloong Pocket 1")},
    "G350": "BattleXP",
    "GKD Pixel": "GKD",
    "GKD Pixel 2": "GKD",
    "Mangmi Air X": "Mangmi",
    "Orange Pi Zero 2w": "Orange Pi",
    "Steam Deck": "Valve",
    "ROG Ally": "ASUS",
}

# The devices whose own system is Android. On a computer RetroArch's row is
# that computer's RetroArch, and a Retroid Pocket owner found it in one press
# and got the computer's folder. Listed only where RetroBIOS runs on Android.
_ANDROID_DEVICES = ("Android", "Retroid Pocket", "Retroid Pocket 5", "AYN Odin", "AYN Odin 3")


def _device_key(text: str) -> str:
    """A device name compared without case, spaces or punctuation, + read as
    Plus: RG CubeXX, RGCUBEXX and rg-cubexx are one device, Mini+ is Mini Plus."""
    return _name_key(re.sub(r"\s*\+", " plus", _folded(text)))


# The devices people type in the setup filter instead of the setup they run,
# beside the setups a first-party page says each one runs, spelled as
# _DEVICES spells them. Keys are platform ids or the system names of
# _EMBEDDED_RULES, and a device that runs several setups is under each. The
# handheld systems' lists are those of platforms/_guides.yml (handheld_guide,
# each with its devices_source), and a test holds the two equal.
_SETUP_DEVICES: dict[str, tuple[str, ...]] = {
    "ArkOS": ("RG353M", "RG353V", "RG503", "RGB30", "RK2023", "RG351MP", "RG351V", "R35S",
              "RGB10"),
    "muOS": ("RG35XX H", "RG35XX Plus", "RG35XX SP", "RG35XX 2024", "RG34XX", "RG40XX H",
             "RG40XX V", "RG28XX", "RG CubeXX", "TrimUI Brick", "TrimUI Smart Pro"),
    "Onion": ("Miyoo Mini", "Miyoo Mini Plus"),
    "spruceOS": ("Miyoo A30", "Miyoo Flip", "Miyoo Mini", "Miyoo Mini Plus",
                 "Miyoo Mini Flip", "TrimUI Smart Pro", "TrimUI Brick",
                 "RG35XX Plus", "RG40XX H", "RGB30"),
    "Allium": ("Miyoo Mini", "Miyoo Mini Plus", "Miyoo Mini Flip"),
    # The stock Linux these devices ship with runs /mnt/vendor/bin/dmenu.bin:
    # GarlicOS/bootloader_anbernic_rg35xxplus 45b489b4, README.md:4.
    "Anbernic stock firmware": ("RG35XX Plus", "RG35XX H", "RG35XX SP", "RG28XX"),
    "ArchR": ("R36S", "R33S", "R36S Soysauce", "Odroid Go Advance", "Odroid Go Super",
              "RG351V", "RG351M", "GameForce Chi", "MagicX XU10", "RGB10", "RGB10X", "K36"),
    "CrossMix-OS": ("TrimUI Smart Pro",),
    "dArkOS": ("RG353M", "RG353V", "RG503", "RGB30", "RGB20 Pro", "RK2023", "RG351MP", "RGB10",
               "G350", "Odroid Go Advance", "A10 Mini", "Miniloong Pocket 1"),
    # JELOS 7b2e116c, packages/hardware/quirks/devices: one folder per device
    # it was built for, the handhelds here.
    "JELOS": ("RG351M", "RG351V", "RG353M", "RG353P", "RG353V", "RG353VS", "RG503", "RG552",
              "R33S", "R36S", "GameForce Ace", "GameForce Chi", "Odroid Go Advance",
              "Odroid Go Super", "Odroid Go Ultra", "MagicX XU10", "RGB10", "RGB10 Max 3",
              "RGB10 Max 3 Pro", "RGB20S", "RGB30", "RK2023", "X55", "AYANEO Air",
              "AYANEO Air Plus", "AYANEO Air Pro", "AYANEO 2", "AYANEO 2S", "AYANEO 2021",
              "AYANEO Geek", "AYANEO Next", "AYN Loki Max", "AYN Loki Mini Pro",
              "AYN Loki Zero"),
    "KOLOS": ("RG353P", "RG353M", "RG353V", "RG353VS", "RG503", "RK2023", "RGB30",
              "RGB10 Max 3"),
    "Koriki": ("Miyoo Mini",),
    "MiyooCFW": ("BittBoy", "Pocket Go", "PowKiddy Q90", "PowKiddy V90", "PowKiddy Q20 Mini",
                 "Sup M3", "XYC Q8"),
    "plumOS": ("MagicX XU20 V32",),
    "RetroOZ": ("Odroid Go Super", "Odroid Go Advance", "RGB10 Max", "RGB10 Max 2"),
    "UnofficialOS": ("R35S", "R36S", "RG351M", "RG351P", "RG351V", "RG353M", "RG353P",
                     "RG353V", "RG503", "RG552", "RGB30", "RGB20 Pro", "Odroid Go Advance",
                     "Odroid Go Super"),
    # The Android tile of the handheld group (_guides.yml): goretroid.com
    # "OS: Android 13" for the Retroid Pocket 5, ayntec.com "Android 15" for
    # the AYN Odin 3. The guide runs RetroArch on Steam Deck (run: steamdeck)
    # and on Windows, which the ROG Ally runs (rog.asus.com spec,
    # "Windows 11 Home").
    "retroarch": ("Steam Deck", "ROG Ally", "Android", "Retroid Pocket", "Retroid Pocket 5",
                  "AYN Odin", "AYN Odin 3"),
    "emudeck": ("Steam Deck", "ROG Ally"),
    "retrodeck": ("Steam Deck",),
    "retrobat": ("ROG Ally",),
    "bizhawk": ("ROG Ally",),
    # _guides.yml runs_on, each cited there.
    "batocera": ("Steam Deck",),
    "amberelec": ("RG351", "RG552"),
    "emuelec": ("Odroid Go",),
    # shauninman/MinUI dbf89435, README.md:65-90, Supported Devices.
    "minui": ("RG28XX", "RG34XX", "RG34XX SP", "RG35XX", "RG35XX Plus", "RG35XX H",
              "RG35XX SP", "RG40XX H", "RG40XX V", "RG CubeXX", "GKD Pixel", "M17",
              "MagicX XU Mini M", "MagicX Mini Zero 28", "Miyoo A30", "Miyoo Flip",
              "Miyoo Mini", "Miyoo Mini Flip", "Miyoo Mini Plus", "RGB30", "TrimUI Brick",
              "TrimUI Smart", "TrimUI Smart Pro"),
    "nextui": ("TrimUI Brick", "TrimUI Smart Pro"),
    # Turro75/MyMinUI 72ed4f3d, README.md:11-35, List of working devices.
    "myminui": ("RG35XX", "Miyoo Mini", "Miyoo Mini Flip", "Miyoo Mini Plus", "Miyoo A30",
                "SJGAM M21", "SJGAM M22 Pro", "R36S", "R36H", "R36S Plus", "R40XX Pro Max",
                "XF40H", "RG351P", "RG353V", "RG353VS", "RG353P", "RG353PS", "RG353M", "V10",
                "RGB30", "RG35XX SP"),
    # rocknix.org/devices, read 2026-10-26.
    "rocknix": ("RG351", "RG353", "RG503", "RG552", "RG 55G1", "RG ARC", "RG35XX 2024",
                "RG35XX Plus", "RG35XX Pro", "RG35XX H", "RG35XX SP", "RG28XX", "RG40XX V",
                "RG40XX H", "RG CubeXX", "RG34XX", "AYANEO Pocket", "AYN Odin 2",
                "AYN Odin 3", "AYN Thor", "GameForce Ace", "Odroid Go Advance",
                "Odroid Go Super", "Odroid Go Ultra", "MagicX XU Mini M", "Mangmi Air X",
                "RGB10", "RGB10X", "RK2023", "RGB20SX", "RGB20 Pro", "RGB30", "X35S", "X35H",
                "X55", "MagicX XU10", "Retroid Pocket 5", "Retroid Pocket 6",
                "Retroid Pocket Flip 2", "Retroid Pocket Mini", "Retroid Pocket Nova", "R33S",
                "R35S", "R36S", "K36"),
    # knulli.org, read 2026-10-26.
    "knulli": ("RG ARC-S", "RG28XX", "RG34XX", "RG35XX", "RG35XX Plus", "RG35XX H",
               "RG35XX 2024", "RG35XX SP", "RG40XX H", "RG40XX V", "RG CubeXX",
               "Retroid Pocket 5", "Retroid Pocket Flip 2", "Retroid Pocket Mini",
               "Miyoo Flip", "Orange Pi Zero 2w", "RGB30", "X55", "TrimUI Brick",
               "TrimUI Smart Pro", "G350", "GKD Pixel 2"),
}


def _setup_devices(name: str, os_type: str = "") -> tuple[str, ...]:
    """The devices a setup row names: an Android device only where this
    installer runs on Android, RetroArch's row being this machine's."""
    devices = _SETUP_DEVICES.get(name, ())
    if name == "retroarch" and os_type != "android":
        devices = tuple(device for device in devices if device not in _ANDROID_DEVICES)
    return devices


def android_hint(needle: str, os_type: str) -> str:
    """What a filter that names an Android device and finds nothing says:
    RetroArch is the Android setup, and its row on a computer is that
    computer's (_setup_devices). "android" matched nothing, with no word."""
    if os_type == "android" or not any(_device_found(device, needle)
                                       for device in _ANDROID_DEVICES):
        return ""
    return "On Android, choose RetroArch: run RetroBIOS on the device itself."


def _device_needle(needle: str) -> str:
    """The filter text with a model's short form spelled out: owners write
    RP5 for the Retroid Pocket 5, as the store names it."""
    short = re.fullmatch(r"\s*rp\s*(\d+)\s*", needle, re.IGNORECASE)
    if short:
        return f"Retroid Pocket {short.group(1)}"
    return needle


# A list that names a family stands for each of its models: ROCKNIX lists
# RG351 and RG353, and the RG353V typed from the box found every system but
# it. AmberELEC's RG351 is the series it was made for (amberelec.org).
_DEVICE_FAMILIES: dict[str, tuple[str, ...]] = {
    "RG351": ("RG351P", "RG351M", "RG351V", "RG351MP"),
    "RG353": ("RG353P", "RG353M", "RG353V", "RG353VS", "RG353PS"),
}


def _device_found(device: str, needle: str) -> bool:
    """Whether typed text names device, by its model, with or without its
    maker: Powkiddy RK2023 and RK2023 are one device. A family is found by
    the name of any of its models."""
    key = _device_key(_device_needle(needle))
    if not key:
        return False
    maker = _device_key(_DEVICES.get(device, ""))
    return any(key in _device_key(model) or key in maker + _device_key(model)
               for model in (device, *_DEVICE_FAMILIES.get(device, ())))


def _setup_matches(plat: str, systems: list[str], needle: str,
                   os_type: str = "") -> list[str] | None:
    """What the filter names for plat: its devices and systems that match,
    [] when plat's own name does, None when nothing does. A device counts
    for each setup it runs."""
    if not needle or _name_found(f"{plat} {display_name(plat)}", needle):
        return []
    devices = [device for device in _setup_devices(plat, os_type)
               if _device_found(device, needle)]
    named = [system for system in systems if _name_found(system, needle) or any(
        _device_found(device, needle) for device in _SETUP_DEVICES.get(system, ()))]
    return _computer_named(plat, needle) + devices + named or None


def _system_matches(name: str, needle: str) -> list[str] | None:
    """What the filter names for a card system: [] when its name does, the
    devices that run it that match, None when nothing does."""
    if not needle or _name_found(name, needle):
        return []
    return [device for device in _SETUP_DEVICES.get(name, ())
            if _device_found(device, needle)] or None


def _name_found(name: str, needle: str) -> bool:
    """Whether typed text names a setup, compared as a device is: spruce os,
    unofficial os and cross mix found nothing on the screen, and line mode
    took Unofficial OS."""
    key = _device_key(needle)
    return _matches(name, needle) or bool(key) and key in _device_key(name)


def _comma_forms(names: list[str]) -> tuple:
    """Shorter forms of a list for a narrow screen, each cut at a comma:
    "Miyoo Mini, +2" where "Miyoo ...s" said nothing."""
    return tuple(", ".join(names[:keep]) + f", +{len(names) - keep}"
                 for keep in range(len(names) - 1, 0, -1))


def _device_forms(names: list[str]) -> tuple:
    """A setup row's devices cut for a narrow screen, the setup's name kept
    whole: at 40 columns KNULLI and ROCKNIX lost every device, and
    "CrossMix-OS, SD ca" was cut mid-word. The last form counts them, and a
    row naming no device can leave its right column empty."""
    if not names:
        return ("",)
    if len(names) == 1:
        # A count of one names nothing: the name is cut instead (TuiRow.cut).
        return ()
    return (*_comma_forms(names), _plural(len(names), "device"))


def _device_setup(state: TuiState, plat: str, system: str) -> Path | None:
    """The folder detection found for system on this machine itself, never
    a card mounted in a reader: on a computer a card is looked for."""
    return _found_device(state.setups, state.mounted_setups, plat, system)


def _found_device(setups: list, mounted: set, plat: str, system: str) -> Path | None:
    return next((path for name, path, _label in setups if name == plat
                 and (name, path) not in mounted
                 and detected_os(name, path) == system), None)


def setup_folder(os_type: str, setups: list, mounted: set, plat: str,
                 system: str) -> tuple[Path | None, str]:
    """(folder, kind) offered for a setup taken from the setup list, on the
    screen's Which folder? and at line mode's folder question. kind is
    "found" (detected here), "share" (a system a computer reaches on its
    SHARE drive, no folder of its own here) or "usual" (its built-in one).

    The folder detected here comes before the built-in one: line mode, by
    o then RetroArch, offered ~/.config/retroarch/system and filled it,
    when the retroarch.cfg found here names another folder. A card in a
    reader is its own system's, never this computer's RetroArch, and a
    system that runs from its card is found on the device itself only."""
    bound = card_bound(system, plat)
    if bound:
        found = _found_device(setups, mounted, plat, bound[0])
        return found, "found" if found else "usual"
    found = next((path for name, path, _label in setups if name == plat
                  and (name, path) not in mounted), None)
    if found is not None:
        return found, "found"
    if plat in _SHARE_FOLDERS:
        # /userdata/bios exists on the Batocera machine alone: a computer
        # sees its share drive or its network share.
        return None, "share"
    return _default_dest(os_type, plat), "usual"


def setup_list(setups: list, mounted: set, needle: str = "",
               os_type: str = "", serves: frozenset = frozenset()) -> list[TuiRow]:
    """The setup list, the screen's and the numbered one of line mode: each
    platform, then each system that runs from its SD card, with what the
    filter named. setups and mounted are what detection found here, as
    TuiState holds them.

    Every card system is a row of its own that asks for its card, with or
    without the filter, from card_setups(): RetroArch's row listed muOS,
    JELOS and fourteen more, and A on it led an R36S owner to this
    computer's RetroArch folder. RetroArch's row is this computer's. A card
    row names the devices that run it, the name a handheld's owner knows:
    "Onion, SD card" beside "RetroArch files" said nothing to a Miyoo Mini
    owner. With nothing found here the card rows come right after RetroArch
    (_cards_first). Line mode listed them in another order, and its 8 was
    the screen's 19. serves, when not empty, keeps the setups that read
    the file list given (LocalSources.serves).
    """
    every_card = card_setups()
    cards = {setup.name for setup in every_card}
    cards_setups = [setup for setup in every_card if not serves or setup.plat in serves]
    systems = _systems_reading()
    desktop: list[TuiRow] = []
    handheld: list[tuple[str, TuiRow]] = []
    for plat in AVAILABLE_PLATFORMS:
        if serves and plat not in serves:
            continue
        others = [name for name in systems.get(plat, []) if name not in cards]
        named = _setup_matches(plat, others, needle, os_type)
        if named is None:
            continue
        setup = card_setup(plat, plat)
        label = display_name(plat)
        if (setup and plat not in _DESK_CARDS
                and _found_device(setups, mounted, plat, setup.name) is None):
            label += ", SD card"
        # The systems and devices the filter named, else a card's devices.
        shown = named or (list(_setup_devices(plat, os_type)) if setup else [])
        row = TuiRow("platform", label, ", ".join(shown), plat, narrow=_device_forms(shown),
                     cut=shown[0] if shown else "")
        if setup and plat not in _DESK_CARDS:
            handheld.append((label, row))
        else:
            desktop.append(row)
    for setup in cards_setups:
        if setup.name == display_name(setup.plat):
            continue
        named = _system_matches(setup.name, needle)
        if named is None:
            continue
        label = setup.name
        if _found_device(setups, mounted, setup.plat, setup.name) is None:
            label += ", SD card"
        shown = named or list(_SETUP_DEVICES.get(setup.name, ()))
        handheld.append((label, TuiRow("cardsystem", label, ", ".join(shown)
                                       or f"{display_name(setup.plat)} files",
                                       (setup.plat, setup.name),
                                       narrow=_device_forms(shown),
                                       cut=shown[0] if shown else "")))
    handheld.sort(key=lambda item: item[0].casefold())
    cards_rows = [row for _label, row in handheld]
    if _cards_first(setups):
        # The setups this computer runs lead, before the cards: RetroBat
        # was row 27 of 34 on Windows, after 23 SD card rows.
        here = _DESKTOP_LEAD.get(os_type, ("retroarch",))
        lead = sorted((row for row in desktop if row.value in here),
                      key=lambda row: here.index(row.value))
        rest = [row for row in desktop if row.value not in here]
        return [*lead, *cards_rows, *rest]
    return [*desktop, *cards_rows]


# The systems that run from an SD card on a board kept on a desk, not in
# the hand: their row stays among the platforms, and the handhelds' block,
# which leads when nothing is found here, keeps Onion four presses away.
_DESK_CARDS = frozenset({"misterfpga", "lakka"})

# The setups a computer runs, by its system, first in the setup list when
# nothing was found here. RetroBat runs on Windows alone (retrobat.org), and
# under WSL its folder is the Windows side's (_os_default_dests). EmuDeck has
# a Windows edition (emudeck-we).
_DESKTOP_LEAD: dict[str, tuple[str, ...]] = {
    "windows": ("retroarch", "retrobat", "emudeck"),
    "wsl": ("retroarch", "retrobat", "emudeck"),
}

# The computer systems people type in the setup filter, with the setups each
# one runs: "windows" and "mac" matched nothing. RetroArch runs on the three
# (retroarch.com), RetroBat on Windows only, EmuDeck has a Windows edition
# and a Linux one (SteamOS), RetroDECK is a Linux Flatpak, BizHawk publishes
# Windows and Linux builds, RetroPie runs on Debian and Ubuntu.
_COMPUTER_SYSTEMS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "Windows": (("windows", "pc"), ("retroarch", "retrobat", "emudeck", "bizhawk")),
    "macOS": (("macos", "mac", "osx", "macbook"), ("retroarch",)),
    "Linux": (("linux", "ubuntu", "debian", "steamos"),
              ("retroarch", "emudeck", "retrodeck", "bizhawk", "retropie")),
}


def _computer_named(plat: str, needle: str) -> list[str]:
    """The computer systems the filter names that run plat."""
    key = _device_key(needle)
    # Two letters are a word on their way: "wi" said "No setup matches"
    # between "w" and "win". "pc" is one of the words.
    if len(key) < 2:
        return []
    return [name for name, (words, plats) in _COMPUTER_SYSTEMS.items()
            if plat in plats and any(word.startswith(key) for word in words)]


def _cards_first(setups: list) -> bool:
    """Whether the card rows follow RetroArch: nothing was found here, so
    this is a computer a handheld's card is prepared on, or a console the
    detection does not know. A pad cannot type in the filter, and Onion was
    row 30 of 34: 29 presses of Down. Right after RetroArch it is row 19,
    in view after five presses of L1/R1 at 40x12, which page by the rows
    drawn (_page_step). A row that opened a list of the
    cards cost one more press than the list it opened."""
    return not setups


def _setup_label(plat: str, path: Path | None) -> str:
    system = detected_shown(plat, path) if path is not None else ""
    name = display_name(plat)
    return f"{system} ({name} files)" if system and system != name else name


def _install_kind(path: Path) -> str:
    """What sets one install of a frontend apart from another of the same."""
    # The config detection read it from says how it was installed: the
    # Flatpak's system directory can be anywhere its config names.
    found = _retroarch_config_at(path)
    text = path.as_posix() + (" " + Path(found[0]).as_posix() if found else "")
    for marker, word in (("/.var/app/", "Flatpak"), ("/steamapps/", "Steam"),
                         ("/snap/", "Snap")):
        if marker in text:
            return word
    if _is_file(path.parent / "retroarch.cfg"):
        return "portable"
    return ""


def tell_apart(setups: list[tuple]) -> list[tuple]:
    """Two setups that read alike get the word that separates them: the
    Flatpak and the native RetroArch were both "RetroArch" at 40 columns.
    The one no package names is "installed", and two of those keep the
    end of their folder, the only thing that tells them apart."""
    labels = [label for _plat, _path, label in setups]
    kinds = [_install_kind(path) or "installed" for _plat, path, _label in setups]
    named = list(zip(labels, kinds))
    return [(plat, path, label if labels.count(label) == 1
             else f"{label} ({kind})" if named.count((label, kind)) == 1
             else f"{label} ({'/'.join(path.parts[-2:])})")
            for (plat, path, label), kind in zip(setups, kinds)]


def found_setups(os_type: str) -> tuple[list[tuple[str, Path, str]], set]:
    """(setups, mounted): what detection finds here, each with its label,
    then each card mounted in a reader whose own files name its system, and
    the (platform, folder) of those cards. The screen's "Found on this
    machine" and line mode's "Found" read this one list: line mode looked
    at this machine alone, and a mounted Onion card was never offered."""
    found = detect_platforms(os_type)
    cards = [(card_system(mount), mount) for mount in _mounted_cards()]
    setups = [(name, path, _setup_label(name, path)) for name, path in found]
    mounted: set = set()
    # On the device itself its own card is the system found, by its own
    # path (muOS reads /run/muos/storage/bios, a bind of MUOS/bios).
    here = {detected_os(name, path) for name, path in found}
    taken = []
    for card, mount in cards:
        if card is None:
            # A drive whose files fit two systems is said, never guessed.
            words = doubt_words(mount)
            if words:
                note_detection(f"  {words}", sys.stdout)
            continue
        if (card[0], card[1]) not in found and card[2] not in here:
            _DETECTED_OS.setdefault((card[0], card[1]), card[2])
            _FROM_CARD.add((card[0], card[1]))
            mounted.add((card[0], card[1]))
            taken.append((card, mount))
    systems = [card[2] for card, _mount in taken]
    counts = {mount: _bios_count(card[1]) for card, mount in taken
              if systems.count(card[2]) > 1}
    # Two cards of one system read alike: each says what its BIOS folder
    # holds, and the one with fewer files, the card being set up rather
    # than the old one, comes first.
    taken.sort(key=lambda item: (systems.index(item[0][2]), counts.get(item[1], -1)))
    for card, mount in taken:
        kind = _card_word(card)
        held = counts.get(mount)
        what = ("" if held is None else ", no BIOS folder" if held < 0
                else f", {_plural(held, 'BIOS file')}")
        setups.append((card[0], card[1],
                       f"{card_title(card[2])} {kind} ({_mount_name(mount)}{what})"))
    return tell_apart(setups), mounted


def _bios_count(folder: Path, cap: int = 99999) -> int:
    """How many files a card's BIOS folder holds, -1 when it has none."""
    if not _is_dir(folder):
        return -1
    count = 0
    for _top, _dirs, files in os.walk(folder):
        count += len(files)
        if count >= cap:
            break
    return count


def _row_name(row: TuiRow) -> str:
    """The name a setup row is typed back with: a platform id, or the name
    of a system that runs from its SD card."""
    value = row.value
    if row.action == "cardsystem" and isinstance(value, tuple):
        return str(value[1])
    return str(value)


def _row_platform(row: TuiRow) -> str:
    """The platform of the system a cardsystem row stands for."""
    value = row.value
    return str(value[0]) if isinstance(value, tuple) else ""


def _line_setups(setups: list | None = None, mounted: set | None = None,
                 os_type: str = "") -> list[tuple[str, str]]:
    """(name typed back, label) of each choice of the line menus, the
    screen's setup list (setup_list) in its order, numbered: Onion was
    reachable only as RetroArch, whose folder on a computer is the
    computer's, and the numbers followed another order than the rows."""
    def devices(names: list[str]) -> str:
        # The devices that run it, three at most: the name its owner knows.
        more = f", +{len(names) - 3}" if len(names) > 3 else ""
        return ", ".join(names[:3]) + more

    choices = []
    for row in setup_list(setups or [], mounted or set(), "", os_type or detect_os(),
                          LOCAL.serves()):
        name = _row_name(row)
        if row.action == "cardsystem":
            listed = list(_SETUP_DEVICES.get(name, ()))
            shown = devices(listed) or f"{display_name(_row_platform(row))} files"
            choices.append((name, f"{row.label} ({shown})"))
        else:
            listed = list(_setup_devices(name, os_type or detect_os())) \
                if card_setup(name, name) else []
            choices.append((name, row.label + (f" ({devices(listed)})" if listed else "")))
    return choices


def _line_matches(choices: list[tuple[str, str]], typed: str, setups: list | None = None,
                  mounted: set | None = None, os_type: str = "") -> list[tuple[int, str]]:
    """(index, label) of the choices a typed device or system name finds,
    with the screen filter's own matcher: "miyoo" was refused, the line
    menu knowing only setup names. The label names what was matched first,
    as the screen's row does on its right: "miyoo mini" listed MinUI with
    RG28XX, RG34XX and RG34XX SP."""
    found = {_row_name(row): row for row in setup_list(
        setups or [], mounted or set(), typed, os_type or detect_os(), LOCAL.serves())}
    matched = []
    for index, (name, label) in enumerate(choices):
        row = found.get(name)
        if row is None:
            continue
        named = row.right.split(", ") if row.right else []
        more = f", +{len(named) - 3}" if len(named) > 3 else ""
        matched.append((index, f"{row.label} ({', '.join(named[:3])}{more})" if named
                        else label))
    return matched


def _choose_platform(title: str, default: str = "", setups: list | None = None,
                     mounted: set | None = None) -> str:
    """One setup from the numbered list, Enter taking the default: a
    platform id, or the name of a system that runs from its SD card, which
    normalize_platform turns into its list.

    A device several systems run lists them all, and Enter after that list
    takes none of them: it took RetroArch, which none of them was. A number
    out of range is said as one, never read as a device name.
    """
    os_type = detect_os()
    choices = _line_setups(setups, mounted, os_type)
    if default and default not in {name for name, _label in choices}:
        # A file list for another setup: Enter takes the first row, where
        # the screen's focus falls (_platform_focus).
        default = choices[0][0] if choices else ""
    print(f"\n{title}")
    # Wrapped at the width between words, its devices under its name: left
    # to the terminal, "Miyoo Flip" was folded inside "Miy" and "oo" below
    # 40 columns.
    cols = terminal_size()[0] - 1
    width = len(str(len(choices)))
    for i, (_name, label) in enumerate(choices, 1):
        number = f"  {i:>{width}}) "
        pieces = _no_widow(_wrap(label, max(cols - len(number), 8), ""),
                           max(cols - len(number), 8))
        print(number + pieces[0])
        for piece in pieces[1:]:
            print(" " * len(number) + piece)
    print("  q) quit")
    print("Type a number, a setup's name, or the device's name (Miyoo Mini, R36S).")
    usage = (f"  Type a number from 1 to {len(choices)}, a setup name or the "
             "device's name, or q to quit.")
    while True:
        prompt = f"> [Enter for {display_name(default)}] " if default else "> "
        choice = _ask(prompt)
        if not choice:
            if default:
                return default
            print(usage)
            continue
        if choice.lower() == "q":
            _quit()
        if choice.isdigit():
            if 1 <= int(choice) <= len(choices):
                return choices[int(choice) - 1][0]
            print(usage)
            continue
        key = _name_key(choice)
        for name, _label in choices:
            if key and key in (_name_key(name), _name_key(display_name(name))):
                return name
        found = _line_matches(choices, choice, setups, mounted, os_type) if key else []
        if len(found) == 1:
            print(f"  {found[0][1]}")
            return choices[found[0][0]][0]
        if found:
            print(f"  {len(found)} setups run on '{choice.strip()}':")
            for index, label in found:
                print(f"  {index + 1}) {label}")
            print("  Type the number of the right one.")
            default = ""
            continue
        hint = android_hint(choice, os_type)
        print(f"  {hint}" if hint else usage)


def drive_example(os_type: str, label: str, below: str = "", plat: str = "") -> str:
    """Where a drive mounted here is, as this system writes it, for the
    example a refusal gives: macOS mounts it at /Volumes/<label>, WSL at
    /mnt/<letter>, Windows names a letter. A Linux path with $USER was
    given on every system, which PowerShell does not expand. plat, a
    system reached over the network, names its network share on Windows."""
    if os_type == "windows":
        if plat in _SHARE_FOLDERS:
            return _SHARE_FOLDERS[plat]
        return "E:\\" + below.replace("/", "\\")
    root = {"darwin": f"/Volumes/{label}", "wsl": "/mnt/e",
            "android": f"/storage/{label}"}.get(os_type, f"/media/$USER/{label}")
    return f"{root}/{below}" if below else root
