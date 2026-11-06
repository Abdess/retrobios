"""A profile's checks are the ones the emulator's code runs.

Each case reads a profile from emulators/ and offers its entry files of
chosen sizes or contents, then compares the verdict with what the code at
the profile's pin does with the same file. The cases come from reading that
code: a check the code does not run rejects a file the emulator loads, and a
check left out lets through a file the emulator refuses.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import re
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from validation import _build_validation_index, check_file_validation  # noqa: E402


def _profile(name: str) -> dict:
    with open(REPO_ROOT / "emulators" / f"{name}.yml", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


class _Probe(unittest.TestCase):
    """Offer a profile entry a file and read the verdict."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def accepts(self, emulator: str, name: str, data: bytes, strict: bool = False) -> bool:
        """strict counts a check the code only warns about."""
        index = _build_validation_index({emulator: _profile(emulator)})
        path = Path(self._tmp.name) / name
        path.write_bytes(data)
        return check_file_validation(
            str(path), name, index, emulators={emulator}, strict=strict
        ) is None


class BeebEmTeletextFont(_Probe):
    """BuildMode7Font reads 96 characters of 18 two-byte rows, 3456 bytes,
    and returns false at the first EOF, which stops BeebEm at startup;
    bytes past them are never read (Src/Video.cpp:167-215 at a982ba6)."""

    def test_short_is_refused_and_longer_is_read(self):
        self.assertFalse(self.accepts("beebem", "Teletext.fnt", b"\0" * 100))
        self.assertTrue(self.accepts("beebem", "Teletext.fnt", b"\0" * 3456))
        self.assertTrue(self.accepts("beebem", "Teletext.fnt", b"\0" * 4000))


class BeebEmSystemRoms(_Probe):
    """The OS, Tube, Z80 and Master 512 ROMs are read with one fread of the
    slot's size. A short read reports an error and BeebEm runs with what it
    read. Bytes past the slot are never read (Src/BeebMem.cpp:1291-1308,
    Src/Tube.cpp:1540-1553, Src/Z80Support.cpp:247-261,
    Src/Master512CoPro.cpp:3777-3790 at a982ba6)."""

    CASES = (("OS12.rom", 16384), ("B+MOS.rom", 16384), ("MOS.rom", 16384),
             ("MOS400.rom", 16384), ("6502Tube.rom", 2048), ("Z80.rom", 4096),
             ("BIOS.rom", 16384))

    def test_longer_is_read_and_shorter_only_warns(self):
        for name, size in self.CASES:
            with self.subTest(name=name):
                self.assertTrue(self.accepts("beebem", name, b"\0" * (size * 2)))
                self.assertTrue(self.accepts("beebem", name, b"\0" * (size // 2)))
                self.assertFalse(
                    self.accepts("beebem", name, b"\0" * (size // 2), strict=True)
                )


class BeebEmSidewaysRoms(_Probe):
    """ReadRom loads any file up to MAX_PALROM_SIZE (131072) into a bank and
    refuses a larger one, leaving the bank empty (Src/BeebMem.cpp:1207-1262,
    Src/PALRom.h:52 at a982ba6)."""

    def test_up_to_128k_is_read_and_larger_refused(self):
        for size in (8192, 16384, 32768, 131072):
            with self.subTest(size=size):
                self.assertTrue(self.accepts("beebem", "BASIC2.rom", b"\0" * size))
        self.assertFalse(self.accepts("beebem", "BASIC2.rom", b"\0" * 200000))


class BeetleLynxBootRom(_Probe):
    """CRom drops a boot ROM under 512 bytes and keeps the 0x88 fill, so no
    game boots, and a longer one is read for its first 512 bytes
    (mednafen/lynx/rom.cpp:61-75 at fcdefcf)."""

    def test_short_is_refused_and_longer_is_read(self):
        self.assertFalse(self.accepts("beetle_lynx", "lynxboot.img", b"\0" * 256))
        self.assertTrue(self.accepts("beetle_lynx", "lynxboot.img", b"\0" * 512))
        self.assertTrue(self.accepts("beetle_lynx", "lynxboot.img", b"\0" * 1024))


class BeetleGbaBios(_Probe):
    """CPUInit copies the BIOS only when it is exactly 0x4000 bytes and
    otherwise falls back to HLE (mednafen/gba/GBA.cpp:2639-2673 at
    b158166)."""

    def test_only_16k_is_used(self):
        self.assertTrue(self.accepts("beetle_gba", "gba_bios.bin", b"\0" * 16384))
        for size in (1000, 32768):
            with self.subTest(size=size):
                self.assertFalse(self.accepts("beetle_gba", "gba_bios.bin", b"\0" * size))


class Atari800SystemRoms(_Probe):
    """SYSROM_FindInDir takes a file of an allowed length whose CRC32 is in
    SYSROM_roms, else, by its lowercased name, any file of that length as a
    custom ROM (atari800/src/sysrom.c:88-112, 281-315, 387-416 at 4e7fbc7).
    BB01R4_OS.ROM and XEGAME.ROM are on no name list: only their CRC32 makes
    them that ROM."""

    def test_named_roms_need_only_the_length(self):
        for name, size in (("ATARIOSA.ROM", 10240), ("ATARIOSB.ROM", 10240),
                           ("ATARIXL.ROM", 16384), ("5200.rom", 2048),
                           ("ATARIBAS.ROM", 8192)):
            with self.subTest(name=name):
                self.assertTrue(self.accepts("atari800", name, b"\1" * size))
                self.assertFalse(self.accepts("atari800", name, b"\1" * (size + 1)))

    def test_unlisted_names_need_their_crc(self):
        for name, size in (("BB01R4_OS.ROM", 16384), ("XEGAME.ROM", 8192)):
            with self.subTest(name=name):
                self.assertFalse(self.accepts("atari800", name, b"\1" * size))


class AresAtari5200Bios(unittest.TestCase):
    """ares registers an Atari 5200 firmware by sha256 and refuses to load a
    game without it (desktop-ui/emulator/atari-5200.cpp:12-16, 82-88 at
    4cb8d92). The profile left the system out, so no pack carried the BIOS."""

    def test_the_profile_declares_it(self):
        profile = _profile("ares")
        self.assertIn("atari-5200", profile["systems"])
        entry = next(f for f in profile["files"] if f.get("system") == "atari-5200")
        self.assertTrue(entry["required"])
        self.assertEqual(
            entry["sha256"],
            "06b250f18983d058c0f156ce7ee88ae48b6eaf11e6f10f21dccf6ac7ffb6a6af",
        )


class A5200Bios(_Probe):
    """The core reads 0x800 bytes and falls back to the Altirra OS on a short
    read. Bytes past them are never read (libretro/libretro.c:456-468 at
    40c6f2f)."""

    def test_short_falls_back_and_longer_is_read(self):
        self.assertFalse(self.accepts("a5200", "5200.rom", b"\0" * 1024))
        self.assertTrue(self.accepts("a5200", "5200.rom", b"\0" * 2048))
        self.assertTrue(self.accepts("a5200", "5200.rom", b"\0" * 4096))


class BeetlePceSystemCards(_Probe):
    """PCE_LoadCD hands the file to HuC_Load, which skips a 512-byte copier
    header and checks no hash (mednafen/pce/pce.cpp:441-457,
    mednafen/pce/huc.cpp:185-202 at b96c11e). The profile carried md5 and
    sha1 values no code holds, and a headered card the core boots was
    reported as a hash discrepancy."""

    def test_a_headered_card_is_not_judged(self):
        self.assertTrue(self.accepts("beetle_pce", "syscard3.pce", b"\0" * 262656))

    def test_no_hash_the_code_does_not_hold(self):
        for entry in _profile("beetle_pce")["files"]:
            with self.subTest(name=entry["name"]):
                self.assertFalse({"md5", "sha1", "crc32", "sha256"} & set(entry))


class EightyOneRoms(_Probe):
    """memory_load reads the ROM and CRC32Block's value only picks the tape
    patches in rompatch.c: a ROM the table does not know loads without them
    (81/zx81/zx81.c:102-103, 81/Ace/ace.c:77-78, 81/zx81/rompatch.c at
    fa70949). The profile declared a crc32 check with no value."""

    def test_an_unknown_rom_is_not_refused(self):
        for name, size in (("zx81.edition3.rom", 8192), ("zx80.rom", 4096),
                           ("jupiterace.rom", 8192)):
            with self.subTest(name=name):
                self.assertTrue(self.accepts("81", name, b"\1" * size))
                entry = next(f for f in _profile("81")["files"] if f["name"] == name)
                self.assertNotIn("crc32", entry.get("validation") or [])


class AdvanceMameArchives(_Probe):
    """verify_length_and_hash checks each member and only adds a warning. The
    archive itself has no size or hash anyone checks (src/romload.c:327-363
    at 21f8f6f). The 26 BIOS archives declared archive-level checks with no
    archive values."""

    def test_no_archive_level_check(self):
        # a7800's MAME warns the same way (src/emu/romload.cpp:427-452 at 7a2afdc).
        for emulator in ("advancemame", "a7800"):
            for entry in _profile(emulator)["files"]:
                if entry.get("category") != "bios_zip":
                    continue
                with self.subTest(emulator=emulator, name=entry["name"]):
                    self.assertFalse(entry.get("validation"))
                    self.assertTrue(entry.get("contents"))


class MameMemberChecksOnlyWarn(unittest.TestCase):
    """libretro MAME and mame2015 warn on a member's wrong length or checksums
    and run (src/emu/romload.cpp:602-625 at 9069f39, src/emu/romload.c:501-519
    at 7adbf44). An archive-level check with no archive value ran nothing."""

    def test_no_valueless_archive_check(self):
        for emulator, names in (
            ("mame", ("vsmile.zip", "qsound.zip", "ym2413.zip", "ym2608.zip")),
            ("cdi2015", ("cdimono1.zip",)),
        ):
            entries = {f["name"]: f for f in _profile(emulator)["files"]}
            for name in names:
                with self.subTest(emulator=emulator, name=name):
                    self.assertFalse(entries[name].get("validation"))


class HypseusArchives(unittest.TestCase):
    """Hypseus checks each member's size and CRC32, never the archive
    (game.cpp:636-906 at cda8796). Its 71 archives declared archive-level
    checks with no archive value."""

    def test_no_archive_level_check(self):
        for entry in _profile("hypseus-singe")["files"]:
            if entry.get("category") == "bios_zip":
                with self.subTest(name=entry["name"]):
                    self.assertFalse(entry.get("validation"))


class DolphinForksIplDumps(_Probe):
    """Load_BS2 compares the IPL's CRC32 with six Redump dumps and only
    raises "The IPL file is not a known good dump" before booting it
    (Source/Core/Core/Boot/Boot.cpp:296-337 at Dolphin-MMJR 1b095b6,
    408-449 at Dolphin-MMJR2 4d0fdb8). The profiles declared the check with
    no value, so nothing told a known dump from any other."""

    def test_an_unknown_ipl_only_warns(self):
        for emulator in ("dolphin-mmjr", "dolphin-mmjr2"):
            with self.subTest(emulator=emulator):
                data = b"\0" * 2097152
                self.assertTrue(self.accepts(emulator, "IPL.bin", data))
                self.assertFalse(self.accepts(emulator, "IPL.bin", data, strict=True))


class GambatteBootRoms(_Probe):
    """get_bootloader_from_file reads 0x100 or 0x900 bytes and gives up on a
    short read, and never reads past them (libgambatte/libretro/libretro.cpp
    1426-1486 at d9d6cd0). The upstream crc32 check the profile claimed has
    no code behind it: sinamas/gambatte was reset to a README in 2021."""

    def test_short_is_refused_and_longer_is_read(self):
        for name, size in (("gb_bios.bin", 256), ("gbc_bios.bin", 2304)):
            with self.subTest(name=name):
                self.assertFalse(self.accepts("gambatte", name, b"\0" * (size - 1)))
                self.assertTrue(self.accepts("gambatte", name, b"\0" * (size + 512)))


class GeargrafxCards(_Probe):
    """LoadBiosData strips a 512-byte header and refuses any other size. The
    CRC32 only names the card in the log, and an unknown LaserActive CRC32
    is logged and loaded (src/media.cpp:570-632, 662-705, 1028-1063 at
    d0307bf). The profiles declared crc32 checks with no value."""

    def test_size_decides_and_an_unknown_card_loads(self):
        for name, size in (("syscard3.pce", 262144), ("gexpress.pce", 32768),
                           ("pac-n10.bin", 524288)):
            with self.subTest(name=name):
                self.assertTrue(self.accepts("geargrafx", name, b"\1" * size, strict=True))
                self.assertTrue(self.accepts("geargrafx", name, b"\1" * (size + 512)))
                self.assertFalse(self.accepts("geargrafx", name, b"\1" * (size - 1)))


class MgbaGameBoyBootRoms(_Probe):
    """The libretro port hands the boot ROM to the core and GBReset drops one
    whose CRC32 GBIsCompatibleBIOS does not list for the model
    (src/gb/gb.c:50-63, 605-628, 661-665 at 7a12d6d). The profile declared
    the crc32 check with no value."""

    def test_an_unknown_boot_rom_is_dropped(self):
        for name, size in (("gb_bios.bin", 256), ("sgb_bios.bin", 256),
                           ("gbc_bios.bin", 2304)):
            with self.subTest(name=name):
                self.assertFalse(self.accepts("mgba", name, b"\0" * size))


class NestopiaFdsBios(_Probe):
    """Fds::Bios logs "warning, unknown BIOS ROM!" for a CRC32 other than the
    Famicom and Twin Famicom ones and uses the ROM (source/core/NstFds.cpp
    57-127 at b9fdc9c). The profile declared the check with no value."""

    def test_an_unknown_bios_only_warns(self):
        self.assertTrue(self.accepts("nestopia", "disksys.rom", b"\0" * 8192))
        self.assertFalse(self.accepts("nestopia", "disksys.rom", b"\0" * 8192, strict=True))


class AppleIIgsRomSizes(_Probe):
    """GSplus and KEGS read a 32, 128 or 256 KB ROM and refuse any other size
    ("The ROM size should be 128K or 256K", gsplus/src/config.c:1297-1316 at
    41e7103). The profiles declared the size check with no size."""

    def test_three_sizes_and_nothing_else(self):
        for emulator in ("gsplus", "kegs"):
            for size in (32768, 131072, 262144):
                with self.subTest(emulator=emulator, size=size):
                    self.assertTrue(self.accepts(emulator, "ROM", b"\0" * size))
            with self.subTest(emulator=emulator, size=65536):
                self.assertFalse(self.accepts(emulator, "ROM", b"\0" * 65536))


class AltirraHappy810(_Probe):
    """ATFirmwareDetection recognises the pre-v7 Happy 810 ROM by its size
    (3K, 4K or a doubled overdump) and a CRC32 that skips the hidden 1K and
    the serial. The whole-file CRC32 the profile checked is never computed,
    so a dump with another serial was refused (firmwaredetect.cpp:186-231 in
    the 4.40 source)."""

    def test_any_serial_passes_and_size_only_warns(self):
        self.assertTrue(self.accepts("altirra", "happy-810-prev7-4k.rom", b"\5" * 4096, strict=True))
        self.assertTrue(self.accepts("altirra", "happy-810-prev7-3k.rom", b"\5" * 3072, strict=True))
        self.assertFalse(self.accepts("altirra", "happy-810-prev7-4k.rom", b"\5" * 5000, strict=True))
        self.assertTrue(self.accepts("altirra", "happy-810-prev7-4k.rom", b"\5" * 5000))


class AzaharConsoleUniqueData(_Probe):
    """LoadSecureInfoA, LoadLocalFriendCodeSeedB and LoadMovable refuse a
    file of the wrong size, and only log a failed signature: the data is
    loaded and used (src/core/hw/unique_data.cpp:43-123, 165-202,
    src/core/hle/service/cfg/cfg.cpp:405-410 at 9dd12da)."""

    def test_size_refuses_and_signature_only_warns(self):
        for name, size in (("SecureInfo_A", 273), ("LocalFriendCodeSeed_B", 272),
                           ("movable.sed", 288)):
            with self.subTest(name=name):
                self.assertTrue(self.accepts("azahar", name, b"\0" * size))
                self.assertFalse(self.accepts("azahar", name, b"\0" * size, strict=True))
                self.assertFalse(self.accepts("azahar", name, b"\0" * (size + 7)))


class ClkMasterSystemBios(unittest.TestCase):
    """CLK loads the western Master System BIOS for every region but Japan,
    Brazil included (Machines/MasterSystem/MasterSystem.cpp:137-140,
    Analyser/Static/Sega/Target.hpp:24-29 at 53a1ee7). Tagged north-america
    and europe only, a Brazilian pack dropped it for the Japanese one."""

    def test_brazil_keeps_the_western_bios(self):
        import region

        index = region.build_region_index({"clk": _profile("clk")})
        group = {"sms": [("MasterSystem/bios.sms", "bios.sms"),
                         ("MasterSystem/japanese-bios.sms", "japanese-bios.sms")]}
        drops = region.resolve_region_drops(group, index, ["brazil"])
        self.assertEqual(drops, {"MasterSystem/japanese-bios.sms"})


class FbAlpha2012HiscoreFromSaveDir(unittest.TestCase):
    """HiscoreInit opens <g_save_dir>/hiscore.dat in the libretro build
    (svn-current/trunk/src/burn/hiscore.cpp:411 at 0ce31536, and :116 of the
    CPS-3 core at 57f8015c). Read as a system file, the entry took the
    bios/hiscore.dat slot that MAME cores read on RetroDECK and RetroBat."""

    def test_hiscore_is_not_a_system_file(self):
        from validation import read_from_system_dir

        for emulator in ("fbalpha2012", "fbalpha2012_cps3"):
            with self.subTest(emulator=emulator):
                entry = next(
                    f for f in _profile(emulator)["files"] if f["name"] == "hiscore.dat"
                )
                self.assertFalse(read_from_system_dir(entry))


_LAUNCHER_CODE = re.compile(
    r"Generator\.(py|cs)|configgen|emulatorlauncher|libretroCores\.py|LibRetro\.CoreOptions",
    re.IGNORECASE,
)


def _prose(node: object) -> list[str]:
    if isinstance(node, dict):
        return [
            text
            for key, value in node.items()
            for text in ([value] if key in ("note", "notes") and isinstance(value, str)
                         else _prose(value))
        ]
    if isinstance(node, list):
        return [text for item in node for text in _prose(item)]
    return []


class HatariTosNamesLiveWithTheLaunchers(unittest.TestCase):
    """The TOS names Batocera, Recalbox and RetroBat pass to Hatari are
    recorded under each platform's launchers: since 8dc485dc. The tos.img
    notes kept describing those generators and an aliases field the entry
    no longer had."""

    def test_no_launcher_in_the_profiles(self):
        for emulator in ("hatari", "hatarib"):
            with self.subTest(emulator=emulator):
                profile = _profile(emulator)
                tos = next(f for f in profile["files"] if f["name"] == "tos.img")
                self.assertNotIn("aliases", tos)
                cited = [t for t in _prose(profile) if _LAUNCHER_CODE.search(t)]
                self.assertEqual(cited, [])


def _launcher_citations(profile: dict) -> list[str]:
    refs = [str(f.get("source_ref") or "") for f in profile.get("files") or []]
    return [t for t in _prose(profile) + refs if _LAUNCHER_CODE.search(t)]


class BizHawkFindsFirmwareByHash(unittest.TestCase):
    """DoScanAndResolve hashes every file of a known firmware size under
    the firmware folder and binds each slot to the best present option. A
    user specification names any file (FirmwareManager.cs:143-222 at
    bdddf4a5). No file name is opened by the code, so every entry is a
    label. 38 entries carried the names RetroBat's Bizhawk.Generator.cs
    writes, and the export added 59 of them to RetroBat's native file."""

    def test_entries_are_labels_named_by_the_firmware_database(self):
        from validation import opens_by_name

        profile = _profile("bizhawk")
        named = [f["name"] for f in profile["files"] if opens_by_name(f, profile, True)]
        self.assertEqual(named, [])
        self.assertEqual([f["name"] for f in profile["files"] if f.get("aliases")], [])
        self.assertEqual(_launcher_citations(profile), [])


class AmiberryNamesComeFromItsCode(unittest.TestCase):
    """The standalone ROM scan names every Kickstart by the ROM database
    whatever the file is called (src/osdep/amiberry_gui.cpp:217-240,
    src/rommgr.cpp:3172-3241 at 648aeeab), so amiga-os-310.rom is a label.
    kick02019.AROS and kick02019.AROS.ext are names only Recalbox's configgen
    writes, and the code has its own AROS (':AROS', src/memory.cpp:2156)."""

    def test_scan_label_and_no_launcher_names(self):
        from validation import opens_by_name

        profile = _profile("amiberry")
        entry = next(f for f in profile["files"] if f["name"] == "amiga-os-310.rom")
        self.assertFalse(opens_by_name(entry, profile, True))
        names = {f["name"] for f in profile["files"]}
        self.assertFalse({"kick02019.AROS", "kick02019.AROS.ext"} & names)
        self.assertEqual(_launcher_citations(profile), [])


class WinUaeNamesComeFromItsCode(unittest.TestCase):
    """get_kickstart_filehandle opens kickstart_rom_file, then kick.rom under
    the data path, then a scanned ROM of the configured name
    (memory.cpp:2038-2071 at 7ee16ec5). The scan identifies Kickstarts by
    content. Every entry carried the names and aliases RetroBat's
    Uae.Generator.cs searches, and kick.rom was missing."""

    def test_kick_rom_is_read_by_name_and_kickstarts_are_labels(self):
        from validation import opens_by_name, read_from_system_dir

        profile = _profile("winuae")
        kick = next(f for f in profile["files"] if f["name"] == "kick.rom")
        self.assertTrue(opens_by_name(kick, profile, True))
        self.assertFalse(read_from_system_dir(kick, True))
        labels = [f for f in profile["files"] if f.get("sha1") and f["name"] != "rom.key"]
        self.assertTrue(labels)
        self.assertFalse(any(opens_by_name(f, profile, True) for f in labels))
        self.assertEqual([f["name"] for f in profile["files"] if f.get("aliases")], [])
        self.assertEqual(_launcher_citations(profile), [])


if __name__ == "__main__":
    unittest.main()
