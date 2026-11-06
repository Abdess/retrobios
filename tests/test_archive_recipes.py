"""A held romset archive carries the members of its own set and nothing else.

The MAME device sets added in March 2026 each held the ROMs of every slot
option reachable from the device: sys68k_cpu30.zip carried 33 members of the
H19 terminal and other cards next to its five CPU-30 ROMs, slvrball.zip 371
members of ISA cards and other slot devices. MAME reads a slot card from the card's own archive, so
those members were never read there, and the archive matched no recipe.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import hashlib
import sys
import unittest
import zipfile
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

# Sets whose archive also carries the ROMs of devices the machine references
# (listxml device_ref). A device looks for its ROMs under its own name, then
# under the system's (device_t::searchpath, src/emu/device.cpp:140-152), so
# MAME finds them in the machine's own archive too. A device set is not a
# system: the devices it holds are never looked for in its archive.
DEVICE_ROMS = {
    # NAOMI boards: the JVS I/O board and the Maple interface
    "airlbios.zip": ("jvs13551.zip", "mie.zip"),
    "f355bios.zip": ("jvs13551.zip", "mie.zip"),
    "f355dlx.zip": ("jvs13551.zip", "mie.zip"),
    "hod2bios.zip": ("jvs13551.zip", "mie.zip"),
    "naomi.zip": ("jvs13551.zip", "mie.zip"),
    "naomi2.zip": ("jvs13551.zip", "mie.zip"),
    "naomigd.zip": ("jvs13551.zip", "mie.zip"),
    # Teletext character ROM: SAA5050 in bbcmet (acorn/bbcm.cpp:701), which
    # bbcm builds on (line 764)
    "bbcm.zip": ("saa5050.zip",),
    # DragonDOS, the default cartridge (trs/dragon.cpp:544, 562)
    "dragon32.zip": ("dragon_fdc.zip",),
    "dragon64.zip": ("dragon_fdc.zip",),
    # PC-80S31 disk unit (nec/pc6001.cpp:1644 through pc6601_fdc_config,
    # nec/pc8001.cpp:1257)
    "pc6001mk2sr.zip": ("pc80s31.zip",),
    "pc8001mk2sr.zip": ("pc80s31.zip",),
}

# Archives that share a set name without being that set.
NOT_ROMSETS = {"samples", "artwork"}

MIN_EXTRA = 1

# Kept as they are: rewriting them would drop bytes the collection holds
# nowhere else, or they are another emulator's archive under a MAME set name.
KEPT = {
    "bios/Acorn/BBC Micro/.variants/bbcb.zip": (
        "MAME 0.150's bbcb loads its DFS ROMs from the machine archive "
        "(src/mess/drivers/bbc.c ROM_START(bbcb)), older than every imported "
        "listxml; zdfs-0.90.rom is held only here"
    ),
    "bios/Arcade/Arcade/.variants/cvs.zip.3c69f366": (
        "the 2001 mame.dk distribution of cvs.zip; its cvs.txt is held only here"
    ),
    "bios/Mattel/Aquarius/.variants/aquarius_ar.zip.73026a45": (
        "a platform pack copy; its TMCTV.png is held only here"
    ),
    # Each carries slot ROMs beside its own set. Its own members, TorrentZipped,
    # are byte for byte the archive under the newer MAME name in Arcade/MAME,
    # so trimming it makes a duplicate: whether the old name stays is the
    # owner's storage decision (2026-11-06).
    "bios/Arcade/Arcade/fccpu20.zip": "MAME 0.196 to 0.258 fccpu20, now sys68k_cpu20.zip",
    "bios/Arcade/Arcade/fcisio1.zip": "MAME 0.196 to 0.258 fcisio1, now sys68k_isio1.zip",
    "bios/Arcade/Arcade/interpod.zip": "MAME 0.177 to 0.215 interpod, now cbm_interpod.zip",
    "bios/Sega/Dreamcast/dc.zip": (
        "RetroBat's dc/dc.zip holds dc_boot.bin and dc_flash.bin, the names the "
        "Dreamcast BIOS goes by outside MAME, not MAME's dc set"
    ),
}


def _hashes(values: object) -> set[str]:
    raw = values if isinstance(values, list) else str(values or "").split(",")
    return {str(value).strip().lower() for value in raw if str(value).strip()}


class HeldArchivesMatchTheirRecipes(unittest.TestCase):
    def test_no_member_outside_every_recipe_of_the_name(self):
        bios = REPO_ROOT / "bios"
        if not bios.is_dir() or not (REPO_ROOT / "recipes").is_dir():
            self.skipTest("bios/ or recipes/ is not present")
        from common import (  # noqa: PLC0415
            list_registered_platforms,
            load_emulator_profiles,
            load_platform_config,
            variant_base_name,
        )
        from hashing import md5_composite_of  # noqa: PLC0415
        from romset_recipes import load_dat_recipes  # noqa: PLC0415

        allowed: dict[str, set[str]] = defaultdict(set)
        for archive, per_label in load_dat_recipes(REPO_ROOT / "recipes").items():
            for recipe in per_label.values():
                allowed[archive.lower()] |= {crc for _name, crc in recipe}
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"), skip_aliases=False)
        for profile in profiles.values():
            for entry in profile.get("files", []) or []:
                crcs = {
                    str(member.get("crc32") or "").lower()
                    for member in entry.get("contents") or []
                }
                crcs.discard("")
                if not crcs:
                    continue
                for name in [entry.get("name", "")] + list(entry.get("aliases") or []):
                    if name:
                        allowed[str(name).lower()] |= crcs
        for name, devices in DEVICE_ROMS.items():
            for device in devices:
                allowed[name] |= allowed.get(device, set())

        pinned: set[str] = set()
        zipped: dict[str, set[tuple[str, str]]] = defaultdict(set)
        platforms_dir = str(REPO_ROOT / "platforms")
        for platform in list_registered_platforms(platforms_dir):
            config = load_platform_config(platform, platforms_dir)
            for system in config.get("systems", {}).values():
                for entry in system.get("files", []) or []:
                    if entry.get("zipped_file"):
                        for md5 in _hashes(entry.get("md5")):
                            zipped[str(entry.get("name", "")).lower()].add(
                                (str(entry["zipped_file"]).casefold(), md5)
                            )
                        continue
                    for key in ("md5", "sha1", "alt_md5"):
                        pinned |= _hashes(entry.get(key))

        offenders = []
        for path in sorted(bios.rglob("*")):
            name = variant_base_name(path.name).lower()
            if not path.is_file() or name not in allowed or not name.endswith(".zip"):
                continue
            if path.parent.name in NOT_ROMSETS:
                continue
            stem = name[:-4]
            try:
                with zipfile.ZipFile(path) as archive:
                    extra = [
                        info for info in archive.infolist()
                        if not info.is_dir()
                        and f"{info.CRC:08x}" not in allowed[name]
                        # a merged set keeps each clone in a folder of its name
                        and not ("/" in info.filename and info.filename.split("/")[0] != stem)
                    ]
                    extra = [
                        info for info in extra
                        if (info.filename.casefold(),
                            hashlib.md5(archive.read(info)).hexdigest()) not in zipped[name]
                    ]
            except zipfile.BadZipFile:
                continue
            if len(extra) < MIN_EXTRA or str(path.relative_to(REPO_ROOT)) in KEPT:
                continue
            blob = path.read_bytes()
            container = {hashlib.md5(blob).hexdigest(), hashlib.sha1(blob).hexdigest(),
                         md5_composite_of(path)}
            if container & pinned:
                continue
            offenders.append(
                f"{path.relative_to(REPO_ROOT)}: {len(extra)} members outside every "
                f"{name} recipe ({', '.join(info.filename for info in extra[:4])})"
            )
        self.assertEqual(offenders, [], "\n".join(offenders))


if __name__ == "__main__":
    unittest.main()
