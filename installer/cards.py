"""Cards and drives mounted here: where each is mounted, how it is named and the system it belongs to."""
from __future__ import annotations

import os
import re
from pathlib import Path, PurePosixPath
from typing import NamedTuple

from installer.embedded import CARD_PLATFORMS, _CARD_RULES, _EMBEDDED_RULES, _STANDIN_MANIFESTS, _OsRule, _a, _built_on
from installer.host_fs import _WSL, _exists, _is_dir, _is_file, _probed
from installer.paths import shown_path
from installer.platforms import AVAILABLE_PLATFORMS, _name_key, display_name
from installer.terminal import _kernel32
from installer.text import screen_text

# Systems a computer reaches over the network or on their SHARE drive: their
# own folder (/userdata/bios) exists only on the machine that runs them, and
# was offered on a computer as where they read. _guides.yml, folders.
_SHARE_FOLDERS = {
    "batocera": "\\\\BATOCERA\\share\\bios",
    "recalbox": "\\\\RECALBOX\\share\\bios",
}

# What a handheld system writes on the games part a computer mounts, beside
# its bios folder: a drive holding these is that card, and a data drive or
# a stick with an emulation library holds none of them.
# Each rule's values must all be there, with bios/, on a drive the system
# does not call fixed (games_part). One system may have several rules: any
# one of them is its proof.
_GAMES_PART_RULES = (
    # ArkOS and dArkOS mount EASYROMS as /roms. Every default tree ArkOS
    # ships for it holds bgmusic/, from the first one (christianhaitian/arkos
    # 9664c869, 2020-11-30, defaultromsfolderstructure.tar) through the
    # per-device trees of c14afbe5 (rg351p, rgb10, rk2020) to f41b9485, and
    # an RG351P card older than them gets it from the 11232020 update
    # (Update-RG351P.sh:238-242). launchimages/ is in every tree from
    # 495eb210 (2020-12-16) on. dArkOS daecf488 creates both
    # (game_systems.txt:23,54, finishing_touches.sh:288-290,420-430).
    # themes/ is no proof: the 12262020 update left it on the system part of
    # a card with under 1 GB free (Update-RGB10.sh:59-69), and 2020's trees
    # hold none.
    # Its list is RetroArch's, written in the bios folder of that part.
    _OsRule("retroarch", "ArkOS", "games_part", ("bgmusic",), "bios"),
    _OsRule("retroarch", "ArkOS", "games_part", ("launchimages",), "bios"),
    # AmberELEC 5a3882cb fills GAMES at every boot: homebrew/ from its ports
    # with gamelist.xml (packages/amberelec/sources/autostart.sh:93-94,
    # 110-113) and gamedata/ for RetroArch, PPSSPP, DOSBox and Hatari
    # (autostart.sh:123-145). Its list is written below that part's root.
    _OsRule(_STANDIN_MANIFESTS["AmberELEC"], "AmberELEC", "games_part",
            ("gamedata", "homebrew"), ""),
    # EmuELEC d4c7b2f1 copies its default bezels to EEROMS at every boot
    # (packages/sx05re/emuelec/bin/emuelec_autostart.sh:78-81).
    _OsRule(_STANDIN_MANIFESTS["EmuELEC"], "EmuELEC", "games_part",
            ("bezels/default.cfg",), ""),
)

# GetDriveTypeW: DRIVE_FIXED, DRIVE_REMOTE, DRIVE_CDROM and DRIVE_RAMDISK,
# none of them a card in a reader.
_NOT_REMOVABLE_TYPES = (3, 4, 5, 6)


def _drive_not_removable(mount: Path) -> bool:
    """Whether the system says mount is a drive no card sits in: a fixed
    disk, a network drive or a disc on Windows (GetDriveTypeW), a whole
    partition of a disk the kernel calls fixed elsewhere (_fixed_partition).
    False where it says nothing."""
    if os.name == "nt":
        try:
            kind = _kernel32().GetDriveTypeW(str(mount))
        except (AttributeError, OSError):
            return False
        return kind in _NOT_REMOVABLE_TYPES
    try:
        text = Path("/proc/self/mountinfo").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return _fixed_partition(mount, text, Path("/sys"))


def _fixed_partition(mount: Path, mountinfo: str, sys_root: Path) -> bool:
    """Whether mountinfo mounts a whole partition at mount whose disk sysfs
    calls fixed: removable at 0, neither on USB nor an MMC card. False for
    a folder bound in place, which is no whole drive, and for WSL's
    /mnt/d, a Windows drive Linux cannot classify."""
    for line in mountinfo.splitlines():
        fields = line.split(" ")
        if len(fields) < 5:
            continue
        point = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), fields[4])
        if point != str(mount):
            continue
        # Field 4 is the folder of the filesystem mounted there: "/" for a
        # whole partition, a folder for a bind mount (proc(5)).
        device = sys_root / "dev" / "block" / fields[2]
        if fields[3] != "/" or not _exists(device):
            return False
        try:
            real = device.resolve()
            disk = real.parent if _exists(real / "partition") else real
            if "/usb" in real.as_posix() or disk.name.startswith("mmcblk"):
                return False
            return (disk / "removable").read_text(encoding="ascii").strip() == "0"
        except OSError:
            return False
    return False


def _games_part_matches(rule: _OsRule, root: Path) -> bool:
    """Whether root is the games part rule's system writes: its bios folder
    and every value of the rule on root's own drive, on a drive the system
    does not call fixed."""
    return (_is_dir(root / "bios")
            and all(_exists(root / value) and _on_the_drive(root, value)
                    for value in rule.values)
            and not _drive_not_removable(root))


def games_part(root: Path) -> _OsRule | None:
    """The rule naming the handheld system whose games part root is, by the
    files that system writes there, None for none (_GAMES_PART_RULES). The
    one reading of a games part, for the three systems alike: each is its
    system's own card everywhere (card_system, the first screen, the card
    routes, line mode). ArkOS's was a card "of a system that reads
    RetroArch's list", named nowhere and called a card RetroBIOS cannot
    tell on the ArkOS route."""
    return next((rule for rule in _GAMES_PART_RULES if _games_part_matches(rule, root)), None)


def card_platform(root: Path) -> str | None:
    """The frontend whose card ``root`` is, from the release name it wrote."""
    for name, marker, prefix in _CARD_RULES:
        try:
            with open(root / marker, encoding="utf-8", errors="replace") as handle:
                first = handle.readline().strip()
        except OSError:
            continue
        if first.startswith(prefix):
            return name
    return None


# A system that runs from its SD card names the card by where the device
# mounts the part of it that holds the BIOS folder: on a computer that
# part's root stands in for the mount point, and its device rule then reads
# the same below the root. The specific mounts come before /mnt/, where
# MiyooCFW mounts its MAIN part. The folders below them are the ones
# _guides.yml handheld_guide gives each system, and a test holds the two
# equal.
_CARD_MOUNTS = ("/mnt/SDCARD/", "/mnt/plumos-user/", "/mnt/mmc/", "/storage/", "/roms/",
                "/mnt/")


def _card_mount(path: str) -> str:
    """The card mount a device path lies under, "" for none."""
    return next((mount for mount in _CARD_MOUNTS if path.startswith(mount)), "")


# Systems whose card a computer sees as their data partition, by the file
# their own build writes there, paths below that partition. KNULLI's is
# /userdata, which S12populateshare fills from datainit (knulli-cfw
# distribution ab3a6809, board/batocera/fsoverlay/etc/init.d/
# S12populateshare:93). The first rule is system/configs/emulationstation/
# about.info, which every board's datainit holds with the one line KNULLI
# (board/batocera/*/fsoverlay/usr/share/batocera/datainit/system/configs/
# emulationstation/about.info), and which S12populateshare copies back at
# each start when it is missing or older. EmulationStation reads it as the
# system's name (knulli-cfw/batocera-emulationstation f7c5ae10,
# es-app/src/ApiSystem.cpp:190-208) and no menu writes it. The second is
# system.hostname=KNULLI in system/batocera.conf, which datainit sets
# (datainit/system/batocera.conf:485) and the HOSTNAME row of the menu
# rewrites (es-app/src/guis/GuiMenu.cpp:4092): a card renamed there was
# read as a Batocera SHARE drive. ROCKNIX's is /storage: userconfig-setup:12
# copies /usr/config into /storage/.config, and its system.cfg sets
# root.password=rocknix (ROCKNIX distribution 8b70f693, projects/ROCKNIX/
# packages/rocknix/config/system/configs/system.cfg:153). Nothing else there
# names ROCKNIX: a password changed with setrootpass
# (packages/rocknix/sources/scripts/setrootpass:25) leaves the card named
# by nothing, never by another system.
_SHARE_RULES: tuple[_OsRule, ...] = (
    _OsRule(_STANDIN_MANIFESTS["KNULLI"], "KNULLI", "file_matches",
            ("system/configs/emulationstation/about.info", r"\AKNULLI\s*$"), "bios"),
    _OsRule(_STANDIN_MANIFESTS["KNULLI"], "KNULLI", "file_matches",
            ("system/batocera.conf", r"^system\.hostname=KNULLI\s*$"), "bios"),
    _OsRule("rocknix", "ROCKNIX", "file_matches",
            (".config/system/configs/system.cfg", r"^root\.password=rocknix\s*$"),
            "roms/bios"),
    # Lakka's is /storage, its STORAGE partition (Lakka-LibreELEC v6.1,
    # packages/sysutils/busybox/scripts/fs-resize:31). RetroArch reads its
    # BIOS through /tmp/system, an overlay whose upper folder is
    # /storage/system (packages/lakka/retroarch_base/retroarch/system.d/
    # tmp-system.mount:12). With HOME=/storage (config/retroarch-env.conf:1)
    # RetroArch writes .config/retroarch/retroarch.cfg from the /etc
    # skeleton at its first start (RetroArch 69a4f0ea, configuration.c:
    # 3650-3676), whose system_directory is that overlay (config/
    # retroarch.cfg:3217): no other system we install for reads /tmp/system.
    _OsRule("lakka", "Lakka", "file_matches",
            (".config/retroarch/retroarch.cfg",
             r'^system_directory = "/tmp/system"\s*$'), "system"),
    # MiSTer's is its exFAT partition, /media/fat (Main_MiSTer e0a234f9,
    # file_io.cpp:1177), whose root holds the MiSTer binary and menu.rbf
    # (Distribution_MiSTer ce602319) and which reads each core's files
    # below games/ (GAMES_DIR, file_io.h:171). A card prepared on a
    # computer got RetroArch's list, or MiSTer's at its root.
    _OsRule("misterfpga", "MiSTer FPGA", "file_exists", ("MiSTer", "menu.rbf"), "games"),
)


def _card_rules() -> list[_OsRule]:
    """The device rules that name a card, their paths below its root."""
    rules = list(_SHARE_RULES)
    for rule in _EMBEDDED_RULES:
        if rule.method != "file_exists" or not rule.manifest or not rule.bios:
            continue
        # Only a file on the part its BIOS folder is on names the card: one
        # on its system part (/etc/main, /mnt/vendor) is not on it.
        mount = _card_mount(rule.bios)
        if mount and all(value.startswith(mount) for value in rule.values):
            rules.append(rule._replace(
                values=tuple(value[len(mount):] for value in rule.values),
                bios=rule.bios[len(mount):], configs=()))
    # The games part of a handheld system: the files it writes there name
    # the card as surely as Onion's .tmp_update (games_part), ArkOS's as
    # AmberELEC's.
    rules += list(_GAMES_PART_RULES)
    return rules


def _card_rule_matches(rule: _OsRule, root: Path) -> bool:
    if rule.method == "games_part":
        return _games_part_matches(rule, root)
    if rule.method == "file_matches":
        path, pattern = rule.values
        try:
            text = (root / path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
        return (re.search(pattern, text, re.MULTILINE) is not None
                and _on_the_drive(root, path))
    return (all(_exists(root / value) for value in rule.values)
            and all(_on_the_drive(root, value) for value in rule.values))


def _on_the_drive(root: Path, relative: str) -> bool:
    """Whether a marker below root is on root's own drive: /media/me holds
    the folder a card is mounted at as MUOS, and was read as a muOS card
    whose BIOS folder was the other card's MUOS/bios. A folder on the way
    that is a mount point is another drive (_card_boundary)."""
    points = _mount_points()
    folder = root
    for part in PurePosixPath(relative).parts:
        folder = folder / part
        if _card_boundary(folder, points):
            return False
    return True


def card_system(root: Path) -> tuple[str, Path, str] | None:
    """(file list, BIOS folder, system name) of the card mounted at root.

    None when nothing on it names a system, or when two systems that would
    write to different folders both match: the card is then the user's to
    name, never a guess.
    """
    plat = card_platform(root)
    if plat:
        return plat, root, display_name(plat)
    matched = _card_matches(root)
    if not matched:
        share = share_drive(root)
        return (share, root / "bios", display_name(share)) if share else None
    if len({(rule.manifest, rule.bios) for rule in matched}) != 1:
        return None
    rule = matched[0]
    return rule.manifest, root / (rule.bios or ""), rule.name


# The SHARE drive of a system a computer reaches over the network, by the
# file the system keeps on it, and both read bios/ beside it. Batocera's data
# part (/userdata) holds system/batocera.conf, which S12populateshare copies
# there (batocera.linux d1966272, board/batocera/fsoverlay/etc/init.d/
# S12populateshare:104) and which sets system.hostname=BATOCERA
# (package/batocera/core/batocera-system/batocera.conf:103). Recalbox's
# (/recalbox/share) holds system/recalbox.conf (recalbox 64b0fd40,
# board/recalbox/fsoverlay/etc/init.d/S12populateshare:93), a name no menu
# changes. KNULLI, built on Batocera, writes the same batocera.conf: its
# rules (_SHARE_RULES) are read first, and a batocera.conf whose hostname
# is neither system's own, on a drive no about.info names, is one of the
# two renamed in its menu. That drive is said to be either (share_doubt),
# never taken for one: a renamed KNULLI card was filled with Batocera's
# list. Typed at the folder question, a drive was taken as the BIOS folder
# and filled beside roms/ and system/, where neither reads.
_SHARE_DRIVES: tuple[tuple[str, str], ...] = (
    ("batocera", "system/batocera.conf"),
    ("recalbox", "system/recalbox.conf"),
)
_HOSTNAME_LINE = re.compile(r"^system\.hostname=(.*?)\s*$", re.MULTILINE)


def _share_markers(root: Path) -> list[str]:
    """The platforms whose SHARE drive file is on root's own drive."""
    return [plat for plat, marker in _SHARE_DRIVES
            if _is_file(root / marker) and _on_the_drive(root, marker)]


def _share_hostname(root: Path) -> str | None:
    """The hostname system/batocera.conf on root sets, "" when it sets none,
    None when the file cannot be read."""
    try:
        text = (root / "system" / "batocera.conf").read_text(encoding="utf-8",
                                                             errors="replace")
    except OSError:
        return None
    found = _HOSTNAME_LINE.findall(text)
    return found[-1] if found else ""


def share_drive(root: Path) -> str | None:
    """The platform whose SHARE drive root is, by its own files, or None:
    for none, and for files that name two systems (share_doubt)."""
    markers = _share_markers(root)
    if len(markers) != 1:
        return None
    if markers == ["batocera"] and _share_hostname(root) not in ("", "BATOCERA"):
        return None
    return markers[0]


def share_doubt(root: Path) -> tuple[tuple[str, ...], str]:
    """(platforms, why) for a drive whose files fit more than one system,
    ((), "") for any other: a batocera.conf renamed in its menu, with no
    file KNULLI alone writes, or the files of Batocera and Recalbox both."""
    if card_platform(root) or _card_matches(root):
        return (), ""
    markers = _share_markers(root)
    if len(markers) > 1:
        return tuple(markers), "it holds system/batocera.conf and system/recalbox.conf"
    if markers == ["batocera"]:
        hostname = _share_hostname(root)
        if hostname not in ("", "BATOCERA"):
            return ((_STANDIN_MANIFESTS["KNULLI"], "batocera"),
                    f"its system/batocera.conf names the host {screen_text(hostname or '?')}, "
                    "which the menus of KNULLI and Batocera both set")
    return (), ""


def _doubt_kinds(plats: tuple[str, ...]) -> str:
    """The systems a drive could be, in words: a KNULLI card or a Batocera
    SHARE drive."""
    return " or ".join(f"{_a(display_name(plat))} "
                       f"{'SHARE drive' if plat in _SHARE_FOLDERS else 'card'}"
                       for plat in plats)


def doubt_words(root: Path) -> str:
    """What is said of a mounted drive share_doubt cannot name, and how to
    name it: the same words on the first screen and in line mode."""
    plats, why = share_doubt(root)
    if not plats:
        return ""
    shown = shown_path(root)
    kinds = _doubt_kinds(plats)
    names = " or ".join(f"--platform {plat} --dest {shown}" for plat in plats)
    return f"{shown} could be {kinds}: {why}. Name it: {names}."


def drive_kind(system: tuple[str, Path, str]) -> str:
    """What a drive card_system read is, in words: an Onion card, a
    Batocera SHARE drive."""
    return "SHARE drive" if system[0] in _SHARE_FOLDERS else "card"


def _card_matches(root: Path, above: bool = False) -> list[_OsRule]:
    """The card rules root matches, a system another one is built on left
    out for it. above is for a folder above the one named: a rule that is
    one bare folder name (muOS's MUOS) then needs the system's BIOS folder
    too, a folder of backups holding a MUOS copy being no muOS card."""
    matched = [rule for rule in _card_rules() if _card_rule_matches(rule, root)
               and not (above and _bare_marker(rule) and not _is_dir(root / (rule.bios or "")))]
    bases = {rule.base for rule in matched if rule.base}
    return [rule for rule in matched if rule.name not in bases]


def _bare_marker(rule: _OsRule) -> bool:
    """Whether a card rule is only folder names any folder can hold."""
    return rule.method == "file_exists" and all(
        "/" not in value and not value.startswith(".") for value in rule.values)


class CardSetup(NamedTuple):
    """A system that runs from its SD card, as a computer sees that card."""

    name: str
    plat: str
    # Its BIOS folder below the card's root, "" for the root itself.
    below: str
    # The rules that tell its card by the files on it: none when every file
    # that names the system is on another part of the card (/etc, /usr).
    rules: tuple = ()
    # A card its rules do not match may still be its card: a share the
    # system fills when it first starts.
    fresh: bool = False

    def known(self) -> bool:
        """Whether the files on a card can say it is this system's."""
        return self.plat in CARD_PLATFORMS or bool(self.rules)


def card_setups() -> list[CardSetup]:
    """Every system that runs from its SD card, with the folder its device
    reads below the card's root.

    The MinUI family is told by its card's version.txt, KNULLI and ROCKNIX
    by the share they fill, and each system that gets RetroArch's list by
    its device rule, whose BIOS folder lies on one of _CARD_MOUNTS. The
    setup list, its filter, --platform, the line questions and every check
    of a card read this list: a second one kept by hand left UnofficialOS,
    ArkOS and MiyooCFW on this computer's RetroArch folder.
    """
    rules = _card_rules()
    setups = [CardSetup(display_name(plat), plat, "") for plat in AVAILABLE_PLATFORMS
              if plat in CARD_PLATFORMS]
    # KNULLI is named by two files: one setup holding both rules.
    shares = {rule.name: tuple(each for each in _SHARE_RULES if each.name == rule.name)
              for rule in _SHARE_RULES}
    setups += [CardSetup(name, rules[0].manifest, rules[0].bios or "", rules, True)
               for name, rules in shares.items()]
    # AmberELEC and EmuELEC mount their card's games part as /storage/roms,
    # the folder their list is written below: AmberELEC 5a3882cb fs-resize
    # formats it exFAT as GAMES (packages/sysutils/busybox/scripts/
    # fs-resize:64), autostart.sh:93 fills it as "the GAMES volume". EmuELEC
    # d4c7b2f1 makes EEROMS (fs-resize:127-140), mount_romfs.sh:10-14 mounts
    # it there. A computer sees that part's root, told by what each writes
    # there at every boot (_GAMES_PART_RULES): a card not started once
    # holds none of it yet, as a KNULLI card before its first start.
    setups += [CardSetup(name, plat, "", tuple(rule for rule in rules if rule.name == name),
                         True)
               for name, plat in _STANDIN_MANIFESTS.items() if name in _GAMES_PART_CARDS]
    for name in _systems_reading().get("retroarch", []):
        below = next((rule.bios[len(_card_mount(rule.bios)):] for rule in _EMBEDDED_RULES
                      if rule.name == name and rule.bios and _card_mount(rule.bios)), "")
        if below:
            own = tuple(rule for rule in rules if rule.name in (name, _built_on(name)))
            # Told by the games part alone, as AmberELEC's: a card that holds
            # none of it yet is taken as named, said so.
            setups.append(CardSetup(name, "retroarch", below, own,
                                    bool(own) and all(rule.method == "games_part"
                                                      for rule in own)))
    return setups


# The systems whose list is written below their card's games part, which a
# computer sees as a drive of its own beside the system part (card_setups).
_GAMES_PART_CARDS = ("AmberELEC", "EmuELEC")


def setup_bios_folder(plat: str, path: Path) -> Path:
    """The BIOS folder a setup found is announced with, before its list is
    read: a MinUI card's Bios below its root, the folder found else. The
    first screen and line mode's Found named /media/me/MINUI, the plan
    then /media/me/MINUI/Bios. An AmberELEC or EmuELEC games part, whose
    list writes bios/ below its root (shown_bios_folder), is announced by
    that bios folder."""
    if plat in CARD_PLATFORMS:
        return path / "Bios"
    rule = games_part(path) if plat in _STANDIN_MANIFESTS.values() else None
    return path / "bios" if rule is not None and rule.manifest == plat else path


def card_setup(named: str, plat: str) -> CardSetup | None:
    """The card setup a name stands for with plat's list: a system by its
    own name, or a list that is one (MinUI). RetroArch names a list, not a
    card."""
    key = _name_key(named)
    return next((setup for setup in card_setups() if setup.plat == plat and (
        plat in CARD_PLATFORMS or (key and key == _name_key(setup.name)))), None)


def _mount_points() -> frozenset:
    """Every mount point this process sees, from /proc/self/mountinfo where
    it exists: os.path.ismount compares devices, and misses a bind mount
    from the same filesystem (a stick bound inside a muOS card's mount)."""
    try:
        text = Path("/proc/self/mountinfo").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return frozenset()
    # Field 5 is the mount point, with space, tab, newline and backslash
    # written as octal escapes (proc(5)).
    return frozenset(re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), fields[4])
                     for fields in (line.split(" ") for line in text.splitlines())
                     if len(fields) > 4)


def _is_mount(folder: Path, points: frozenset | None = None) -> bool:
    """Whether a drive is mounted at folder, probed as detection probes."""
    if str(folder) in (_mount_points() if points is None else points):
        return True
    return _probed(lambda: os.path.ismount(folder), folder)


def _card_boundary(folder: Path, points: frozenset | None = None) -> bool:
    """Whether folder is where a drive is mounted: no folder above it is on
    the same card. /media/me holds a card mounted as MUOS, and is no muOS
    card for it."""
    return _is_mount(folder, points) or folder in _mounted_cards()


def card_bound(named: str, plat: str) -> tuple[str, str] | None:
    """(system name, BIOS folder below the card root) when what --platform
    named runs from an SD card, else None.

    `--platform onion` gets RetroArch's list, and on a computer that list's
    default folder is the computer's own RetroArch: the files went there,
    which Onion never reads. --platform retroarch names a list, not a card.
    """
    setup = card_setup(named, plat)
    return (setup.name, setup.below) if setup else None


def _mount_name(mount: Path) -> str:
    """How a person names a mounted card: E:\\ on Windows, its label elsewhere.
    Under WSL /mnt/d is the Windows D: drive, which "d" did not say."""
    if (_WSL["active"] and mount.parent == Path(_WSL["root"]) and len(mount.name) == 1
            and mount.name.isalpha()):
        return f"{mount.name.upper()}:"
    # The label is whoever formatted the card's: shown, never obeyed.
    return screen_text(mount.name or str(mount))


def _mounted_cards() -> list[Path]:
    """Mount points of removable media, where a card or a share appears.

    A handheld's card is most often prepared on a PC with a card reader: on
    Windows every drive but the system one may be that card.
    """
    if os.name == "nt":
        system = os.environ.get("SYSTEMDRIVE", "C:").upper()
        return [Path(f"{letter}:\\") for letter in "DEFGHIJKLMNOPQRSTUVWXYZ"
                if f"{letter}:" != system and os.path.exists(f"{letter}:\\")]
    found: list[Path] = []
    for root in (Path("/media"), Path("/run/media"), Path("/mnt"), Path("/Volumes")):
        try:
            children = sorted(root.iterdir())
        except OSError:
            continue
        for child in children:
            # WSL's own mounts, and the Windows system drive, hold no card.
            if child.name in ("wsl", "wslg") or (root.name == "mnt" and child.name == "c"):
                continue
            if os.path.ismount(child):
                found.append(child)
            elif root.name in ("media", "run") or root == Path("/run/media"):
                # /media/<user>/<label> and /run/media/<user>/<label>.
                try:
                    found += [g for g in sorted(child.iterdir()) if os.path.ismount(g)]
                except OSError:
                    continue
    return found


def _systems_reading() -> dict[str, list[str]]:
    """The device systems that get each platform's files, as detection knows
    them: someone on muOS or ArkOS looks for that name, not RetroArch."""
    names: dict[str, list[str]] = {}
    for rule in _EMBEDDED_RULES:
        if (rule.manifest and rule.name != display_name(rule.manifest)
                and rule.name not in names.setdefault(rule.manifest, [])):
            names[rule.manifest].append(rule.name)
    return names
