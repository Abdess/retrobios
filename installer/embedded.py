"""Embedded systems named by the files their builds write."""
from __future__ import annotations

from typing import NamedTuple

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


class _OsRule(NamedTuple):
    """One piece of evidence that names an embedded system.

    manifest is the platform whose files it gets, "" for a system the
    installer does not lay out. name is the system's own name. values are the
    KEY=value pairs of os_release (any one), the files of file_exists (all),
    or the file and the pattern of file_matches. bios is the folder used when
    none of configs (retroarch.cfg files, read in order, `*` allowed) names a
    system_directory. home is what `~` means to that system's RetroArch.
    base is the system this one is built on: both match, this one is meant.
    """

    manifest: str
    name: str
    method: str
    values: tuple[str, ...]
    bios: str | None
    configs: tuple[str, ...] = ()
    home: str = ""
    base: str = ""


# The platform whose files each of these systems gets. They publish their own
# BIOS list, and these platforms transcribe it.
_STANDIN_MANIFESTS = {
    "AmberELEC": "amberelec",
    "EmuELEC": "emuelec",
    "KNULLI": "knulli",
}

# Where the ELEC family keeps RetroArch: the config runemu writes and copies
# back on every launch, and HOME=/storage for the services that start it.
_ELEC_CONFIGS = ("/storage/.config/retroarch/retroarch.cfg",)
# ArkOS and dArkOS: the 64-bit and the 32-bit RetroArch. "Switch to SD2 for
# Roms" rewrites /roms/ to /roms2/ in both (darkos daecf488,
# scripts/Switch to SD2 for Roms.sh:91-92), so a second card is read here.
_ARK_CONFIGS = ("/home/ark/.config/retroarch/retroarch.cfg",
                "/home/ark/.config/retroarch32/retroarch.cfg")
_PLYMOUTH_TITLE = "/usr/share/plymouth/themes/text.plymouth"

# muOS runs RetroArch on the config it copies from its default on first launch
# (internal f41f4a89, script/control/retroarch.sh:8-20). The default names
# /run/muos/storage/bios, a bind mount of MUOS/bios on the second card when
# that card holds one, else on the first (script/device/bind.sh:4,116-150),
# and loads cores from /opt/muos/share/core (retroarch.default.cfg:2806,3151).
MUOS_RETROARCH_CONFIGS = (
    "/opt/muos/share/info/config/retroarch.cfg",
    "/opt/muos/share/emulator/retroarch/retroarch.default.cfg",
)

# Embedded systems, by what their own builds write. The registry publishes the
# same rules as each manifest's `detect`, and a test holds the two equal.
# MiSTer is a path rule below.
_EMBEDDED_RULES: tuple[_OsRule, ...] = (
    # ROCKNIX writes OS_NAME and no ID since 2025 (scripts/image). Older
    # images wrote ID=rocknix.
    _OsRule("rocknix", "ROCKNIX", "os_release", ("OS_NAME=rocknix", "ID=rocknix"),
            "/storage/roms/bios"),
    # Knulli (knulli-linux 57afa662): OS_NAME in os-release
    # (board/scripts/post-build-script.sh:233-236) and knulli.version
    # (package/system/knulli-system/knulli-system.mk:98-102).
    _OsRule(_STANDIN_MANIFESTS["KNULLI"], "KNULLI", "os_release", ("OS_NAME=knulli",),
            "/userdata/bios", base="Batocera"),
    _OsRule(_STANDIN_MANIFESTS["KNULLI"], "KNULLI", "file_exists",
            ("/usr/share/knulli/knulli.version",), "/userdata/bios", base="Batocera"),
    _OsRule("lakka", "Lakka", "os_release", ("ID=lakka",), "/storage/system"),
    # batocera.linux 38845725, batocera-system.mk:21-22 (the same lines in
    # batocera-30): batocera.arch and batocera.version.
    _OsRule("batocera", "Batocera", "file_exists", ("/usr/share/batocera/batocera.version",),
            "/userdata/bios"),
    _OsRule("recalbox", "Recalbox", "file_exists", ("/recalbox/recalbox.version",),
            "/recalbox/share/bios"),
    _OsRule("recalbox", "Recalbox", "file_exists", ("/usr/bin/recalbox-settings",),
            "/recalbox/share/bios"),
    _OsRule("retroarch", "muOS", "file_exists", ("/opt/muos",), "/run/muos/storage/bios",
            configs=MUOS_RETROARCH_CONFIGS),
    _OsRule("retroarch", "muOS", "file_exists", ("/mnt/mmc/MUOS",), "/mnt/mmc/MUOS/bios"),
    # AmberELEC 5a3882cb: scripts/image:150-152 writes NAME="${DISTRONAME}",
    # AmberELEC in distributions/AmberELEC/options:17. CHAos (tech4bot/AmberELEC
    # c0a4b0c6) is built from the same tree and writes the same name
    # (distributions/AmberELEC/options:14). runemu.py:22 launches with
    # /storage/.config/retroarch/retroarch.cfg, whose default is "~/roms/bios"
    # (packages/games/tools/retroarch/sources/retroarch.cfg:611), and
    # emustation.service:6 sets HOME=/storage.
    _OsRule(_STANDIN_MANIFESTS["AmberELEC"], "AmberELEC", "os_release", ("NAME=AmberELEC",),
            "/storage/roms"),
    # PAN4ELEC (Kegg1701/P4ELEC 9c19bfb2), an overlay on an AmberELEC image:
    # AmberELEC/usr/bin/batocera-info:101 prints its name.
    _OsRule(_STANDIN_MANIFESTS["AmberELEC"], "PAN4ELEC", "file_matches",
            ("/usr/bin/batocera-info", r"OPERATING SYSTEM: PAN4ELEC"),
            "/storage/roms", base="AmberELEC"),
    # EmuELEC d4c7b2f1: scripts/image:172-176 NAME and ID from DISTRONAME,
    # EmuELEC in distributions/EmuELEC/options:4. setsettings.sh:22 names the
    # config, and libretro_base/retroarch/package.mk:117 sets its
    # system_directory to /storage/roms/bios.
    _OsRule(_STANDIN_MANIFESTS["EmuELEC"], "EmuELEC", "os_release", ("NAME=EmuELEC",),
            "/storage/roms"),
    # JELOS 7b2e116c: scripts/image:118-120 OS_NAME="${DISTRONAME}", JELOS in
    # distributions/JELOS/options:17. runemu.sh:37 names the config, whose
    # default is "~/roms/bios" (retroarch/sources/RK3566/retroarch.cfg:716),
    # and emustation.service:8 sets HOME=/storage.
    _OsRule("retroarch", "JELOS", "os_release", ("OS_NAME=JELOS",),
            "/storage/roms/bios", _ELEC_CONFIGS, "/storage"),
    # KOLOS (AnonLinuxOS/KOLOS 7daf5950) keeps OS_NAME=JELOS
    # (distributions/JELOS/options:17) and adds jelos-ready.service
    # ("KOLOS system ready script"), installed by scripts/install:100-102.
    _OsRule("retroarch", "KOLOS", "file_exists",
            ("/usr/lib/systemd/system/jelos-ready.service",),
            "/storage/roms/bios", _ELEC_CONFIGS, "/storage", base="JELOS"),
    # UnofficialOS 22635796: scripts/image:119-120 OS_NAME, UnofficialOS in
    # distributions/UnofficialOS/options:17, config at
    # packages/unofficialos/sources/scripts/runemu.sh:37.
    _OsRule("retroarch", "UnofficialOS", "os_release", ("OS_NAME=UnofficialOS",),
            "/storage/roms/bios", _ELEC_CONFIGS, "/storage"),
    # Arch R (archr-linux/Arch-R dbd45d45): scripts/image:164-177 NAME and
    # OS_NAME, ArchR in distributions/ArchR/options:17. factoryreset:9-10
    # names the config, whose default is "~/roms/bios"
    # (retroarch/sources/RK3326/retroarch.cfg:718).
    _OsRule("retroarch", "ArchR", "os_release", ("OS_NAME=ArchR",),
            "/storage/roms/bios", _ELEC_CONFIGS, "/storage"),
    # ArkOS: the user and the menu folder, and the boot splash title its
    # updates write (christianhaitian/arkos dedf4278, Update-RGB10.sh:76).
    _OsRule("retroarch", "ArkOS", "file_exists", ("/home/ark", "/opt/system"), "/roms/bios",
            _ARK_CONFIGS),
    _OsRule("retroarch", "ArkOS", "file_matches", (_PLYMOUTH_TITLE, r"^title=\s*ArkOS\b"),
            "/roms/bios", _ARK_CONFIGS),
    # dArkOS daecf488: finishing_touches.sh:359-361 writes "title=dArkOS
    # (<date>)", kept by the dArkOSRE, dArkOSen and ArkOS4Clone overlays.
    # Default system_directory "/roms/bios" (retroarch.cfg.rgb10:3043).
    _OsRule("retroarch", "dArkOS", "file_matches", (_PLYMOUTH_TITLE, r"^title=\s*dArkOS"),
            "/roms/bios", _ARK_CONFIGS, base="ArkOS"),
    # RetroOZ 0.60 image (no build source is published): title=RetroOZ in
    # the splash theme, /opt/.retrooz/version, and /etc/retrooz_version, the
    # file PortMaster reads (device_info.txt:95). RetroArch is started with
    # --config /home/odroid/.config/retroarch/retroarch.cfg (es_systems.cfg),
    # system_directory "/roms/bios" (retroarch32/retroarch.cfg:3046).
    _OsRule("retroarch", "RetroOZ", "file_matches", (_PLYMOUTH_TITLE, r"^title=\s*RetroOZ"),
            "/roms/bios", ("/home/odroid/.config/retroarch/retroarch.cfg",
                           "/home/odroid/.config/retroarch32/retroarch.cfg")),
    _OsRule("retroarch", "RetroOZ", "file_exists", ("/opt/.retrooz",),
            "/roms/bios", ("/home/odroid/.config/retroarch/retroarch.cfg",
                           "/home/odroid/.config/retroarch32/retroarch.cfg")),
    _OsRule("retroarch", "RetroOZ", "file_exists", ("/etc/retrooz_version",),
            "/roms/bios", ("/home/odroid/.config/retroarch/retroarch.cfg",
                           "/home/odroid/.config/retroarch32/retroarch.cfg")),
    # TheRA is left undetected: no image or source of its Odroid Go builds is
    # published, so neither its markers nor its folder could be read.
    # spruceOS 824b1aae: the spruce folder at the card root. RetroArch reads
    # Saves/ra-configs/retroarch-<platform>.cfg (spruce/scripts/
    # helperFunctions.sh:157-165), seeded with system_directory
    # "/mnt/SDCARD/BIOS" (RetroArch/platform/retroarch-Brick.cfg.bak:3279).
    _OsRule("retroarch", "spruceOS", "file_exists", ("/mnt/SDCARD/spruce",),
            "/mnt/SDCARD/BIOS", ("/mnt/SDCARD/Saves/ra-configs/retroarch-*.cfg",),
            base="TrimUI"),
    # CrossMix-OS 206d612f: crossmix-version.txt (System/usr/trimui/scripts/
    # update_common.sh:20), RetroArch/retroarch.cfg:3202 (patch_ra_cfg.sh:5).
    _OsRule("retroarch", "CrossMix-OS", "file_exists",
            ("/mnt/SDCARD/System/usr/trimui/crossmix-version.txt",),
            "/mnt/SDCARD/BIOS", ("/mnt/SDCARD/RetroArch/retroarch.cfg",), base="TrimUI"),
    # Onion 07505ea5: Makefile:75-76 writes onionVersion/version.txt, and
    # static/build/.tmp_update/script/patch_ra_cfg.sh:6 names the config
    # (system_directory at static/configs/RetroArch/.retroarch/retroarch.cfg:3009).
    _OsRule("retroarch", "Onion", "file_exists",
            ("/mnt/SDCARD/.tmp_update/onionVersion/version.txt",),
            "/mnt/SDCARD/BIOS", ("/mnt/SDCARD/RetroArch/.retroarch/retroarch.cfg",)),
    # Allium ee0dda97: its base folder /mnt/SDCARD/.allium
    # (crates/common/src/constants.rs:19-34). RetroArch runs with
    # HOME=/mnt/SDCARD/RetroArch on .retroarch/retroarch.cfg
    # (static/.allium/cores/retroarch/launch_without_savestate_auto_load.sh:2-7),
    # and Allium's RetroArch patch makes $ROOT/BIOS the default system folder.
    _OsRule("retroarch", "Allium", "file_exists", ("/mnt/SDCARD/.allium",),
            "/mnt/SDCARD/BIOS", ("/mnt/SDCARD/RetroArch/.retroarch/retroarch.cfg",)),
    # Koriki 8513071c: src/systemInfo/main.c:106 reads Koriki/version.txt,
    # .tmp_update/runtime.sh:271 installs RetroArch/.retroarch/retroarch.cfg
    # (system_directory at base/RetroArch/.retroarch/retroarch.cfg:3191).
    _OsRule("retroarch", "Koriki", "file_exists", ("/mnt/SDCARD/Koriki/version.txt",),
            "/mnt/SDCARD/BIOS", ("/mnt/SDCARD/RetroArch/.retroarch/retroarch.cfg",)),
    # MiyooCFW (buildroot d5912eeb): board/miyoo/rootfs/etc/main sets HOME=/mnt
    # (line 4), package/miyoo/miyoo-ctl/miyoo-ctl.mk:12 installs miyooctl.
    # RetroArch is a DINGUX build: $HOME/.retroarch/retroarch.cfg, and
    # $HOME/.retroarch/system when no config names a folder.
    _OsRule("retroarch", "MiyooCFW", "file_exists", ("/etc/main", "/usr/bin/miyooctl"),
            "/mnt/.retroarch/system", ("/mnt/.retroarch/retroarch.cfg",), "/mnt"),
    # plumOS: os-release ID=plumos (game-de-it/plumOS-pixel2_v2 dec872c0,
    # rootfs/pixel2/etc/os-release:2, PortMaster device_info.txt:101). Each
    # device build appends its own system_directory at launch: the Pixel 2
    # build /mnt/plumos-user/bios (package/app-layer-pixel2/bin/
    # plumos-retroarch-launch:342, mount point made by rootfs/pixel2/sbin/
    # init:29), the MF build <card>/BIOS (plumOS-MF 0095017c,
    # plumos-retroarch-launch:15). Only the first is told apart by a file.
    _OsRule("retroarch", "plumOS", "file_exists", ("/mnt/plumos-user",),
            "/mnt/plumos-user/bios"),
    _OsRule("retroarch", "plumOS", "os_release", ("ID=plumos",), None),
    # TrimUI's stock firmware publishes no source naming its RetroArch BIOS
    # folder. PortMaster finds its libraries in /usr/trimui
    # (trimui/launch_hooks.txt:37). Named so that what runs on top of it is
    # told apart, never installed to by a guess.
    _OsRule("", "TrimUI", "file_exists", ("/usr/trimui",), None),
    # MinUI, MyMinUI and NextUI keep their system in .system at the card root
    # (MinUI dbf89435, workspace/all/common/defines.h:14-16) and give each core
    # Bios/<tag>/ (workspace/all/minarch/minarch.c:2942). Their file lists
    # write that layout below the card root, and the card's version.txt
    # says which of the three it is (card_platform).
    _OsRule("", "MinUI", "file_exists", ("/mnt/SDCARD/.system/res",), None, base="TrimUI"),
    _OsRule("", "MinUI", "file_exists", ("/mnt/sdcard/.system/res",), None, base="TrimUI"),
    _OsRule("retroarch", "Anbernic stock firmware", "file_exists",
            ("/mnt/vendor/bin/dmenu.bin",), "/mnt/mmc/bios"),
)


def _a(name: str) -> str:
    """A name with its article: an Onion, a muOS."""
    return f"{'an' if name[:1].lower() in 'aeiou' else 'a'} {name}"


def _built_on(name: str) -> str:
    """The system name is built on (dArkOS on ArkOS), "" for none."""
    return next((rule.base for rule in _EMBEDDED_RULES if rule.name == name and rule.base), "")


# Why a system found here gets no folder: said once per run.
_NO_FOLDER = {
    "TrimUI": "its firmware publishes no source naming the folder its RetroArch reads",
    "MinUI": f"its card names no release in {CARD_MARKER}, which tells MinUI, NextUI "
             "and MyMinUI apart. Name the card's root and the one it runs: "
             "--platform minui (or nextui, myminui) --dest /mnt/SDCARD",
}
