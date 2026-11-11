"""Content tests a profile declares, run the way the emulator runs them.

The PCSX2 family lists every file of its BIOS folder whose ROM directory
holds RESET and ROMVER, whatever its name and, in most forks, its size. A
4 to 8 MB bound stood in for that test on Recalbox's libretro PCSX2: it
dropped the 2 MB System 246 image the core lists and let the scan carry
.nvm and .mec files that sit beside no image. Amiberry names a flash image
by the SHA-1 of its bytes with the board configuration cleared, xemu maps
any flash image whose size is a whole number of 64 KiB.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import common  # noqa: E402
import generate_pack as builder  # noqa: E402
import packextras  # noqa: E402
from romdir import romdir_accepts, walk  # noqa: E402
from validation import _build_validation_index, check_file_validation  # noqa: E402

# How each fork reads the table, as the profiles declare it.
WX = {"reset_compare": 5, "missing_reset": "rejects", "terminated_names": False,
      "extinfo": False, "unreadable_romver": "rejects", "truncated_walk": "rejects",
      "offset_width": 32}
AETHER = {"reset_compare": 5, "missing_reset": "ends_walk", "terminated_names": False,
          "extinfo": False, "unreadable_romver": "ignored", "truncated_walk": "ends_walk"}
CLASSIC = {"reset_compare": 10, "missing_reset": "ends_walk", "terminated_names": True,
           "extinfo": False, "unreadable_romver": "ends_walk", "truncated_walk": "ends_walk"}
MODERN = {"reset_compare": 10, "missing_reset": "ends_walk", "terminated_names": True,
          "extinfo": True, "unreadable_romver": "ends_walk", "truncated_walk": "ends_walk"}
FORKS = {"wx": WX, "aether": AETHER, "classic": CLASSIC, "modern": MODERN}

ROMDIR_AT = 0x2700  # where retail images keep the table, inside RESET


def entry(name: bytes, size: int) -> bytes:
    return name.ljust(10, b"\x00")[:10] + struct.pack("<HI", 0, size)


def image(
    entries: list[tuple[bytes, int]] | None = None,
    romver: bytes = b"0230AC20080220",
    serial: bytes = b"20080220-000000",
    terminator: bool = True,
    tail: int = 0x100,
) -> bytes:
    """A BIOS laid out as a retail one: the table at 0x2700 inside RESET,
    then ROMDIR, EXTINFO and ROMVER, each file at the sum of the sizes
    before it rounded to 16 bytes."""
    if entries is None:
        entries = [(b"RESET", ROMDIR_AT), (b"ROMDIR", 0x50), (b"EXTINFO", 0x30), (b"ROMVER", 0x10)]
    table = b"".join(entry(n, s) for n, s in entries) + (entry(b"", 0) if terminator else b"")
    offsets, offset = {}, 0
    for name, size in entries:
        offsets[name] = offset
        offset += size if size % 16 == 0 else (size + 16) & 0xFFFFFFF0
    end = max(ROMDIR_AT + len(table), min(offset, 1 << 20)) + tail
    data = bytearray(end)
    data[ROMDIR_AT:ROMDIR_AT + len(table)] = table
    for name, payload, skip in ((b"EXTINFO", serial, 0x10), (b"ROMVER", romver, 0)):
        at = offsets.get(name, 1 << 40) + skip
        if at + len(payload) <= len(data):
            data[at:at + len(payload)] = payload
    return bytes(data)


class RomdirWalk(unittest.TestCase):
    def test_a_retail_layout_passes_every_fork(self):
        data = image()
        for fork, spec in FORKS.items():
            with self.subTest(fork=fork):
                found = walk(data, spec)
                self.assertIsNotNone(found)
                self.assertEqual(found.romver, b"0230AC20080220")
        self.assertEqual(walk(data, MODERN).serial, "20080220-000000")

    def test_a_file_without_romver_fails_every_fork(self):
        data = image([(b"RESET", ROMDIR_AT), (b"ROMDIR", 0x40), (b"EXTINFO", 0x30)])
        for fork, spec in FORKS.items():
            with self.subTest(fork=fork):
                self.assertFalse(romdir_accepts(data, spec))
        self.assertFalse(romdir_accepts(b"\x00" * 0x4000, MODERN))
        self.assertFalse(romdir_accepts(b"", MODERN))

    def test_reset_compare_is_the_strncmp_length(self):
        """strncmp(name, "RESET", 5) in the wxWidgets and AetherSX2 code takes
        RESETX, sizeof(fileName) wants RESET and a NUL."""
        data = image([(b"RESETX", ROMDIR_AT), (b"ROMDIR", 0x40), (b"ROMVER", 0x10)])
        self.assertTrue(romdir_accepts(data, WX))
        self.assertTrue(romdir_accepts(data, AETHER))
        self.assertFalse(romdir_accepts(data, MODERN))

    def test_a_name_without_nul_ends_the_later_walk(self):
        data = image([(b"RESET", ROMDIR_AT), (b"ABCDEFGHIJ", 0x100), (b"ROMVER", 0x10)])
        self.assertTrue(romdir_accepts(data, WX))
        self.assertTrue(romdir_accepts(data, AETHER))
        self.assertFalse(romdir_accepts(data, CLASSIC))
        self.assertFalse(romdir_accepts(data, MODERN))

    def test_romver_past_the_end_of_the_file(self):
        """AetherSX2 zero-fills the 14 bytes and counts ROMVER found, the
        wxWidgets stream throws, the later code ends the walk."""
        data = image([(b"RESET", ROMDIR_AT), (b"ROMDIR", 0x200000), (b"ROMVER", 0x10)])
        self.assertTrue(romdir_accepts(data, AETHER))
        self.assertFalse(romdir_accepts(data, WX))
        self.assertFalse(romdir_accepts(data, CLASSIC))

    def test_an_unreadable_extinfo_ends_the_walk_before_romver(self):
        data = image([(b"RESET", ROMDIR_AT), (b"ROMDIR", 0x200000), (b"EXTINFO", 0x30),
                      (b"ROMVER", 0x10)])
        self.assertFalse(romdir_accepts(data, MODERN))
        self.assertTrue(romdir_accepts(data, AETHER))

    def test_a_table_that_runs_off_the_file(self):
        """Without the zero entry the next read fails: the wxWidgets stream
        throws, the later code keeps the ROMVER it met."""
        data = image([(b"RESET", 0x10), (b"ROMVER", 0x10)], terminator=False, tail=0)
        self.assertEqual(len(data), ROMDIR_AT + 2 * 16)
        self.assertTrue(romdir_accepts(data, MODERN))
        self.assertFalse(romdir_accepts(data, WX))

    def test_the_wx_offset_is_a_32_bit_uint(self):
        wrap = (1 << 32) - ROMDIR_AT - 0x50
        data = image([(b"RESET", ROMDIR_AT), (b"ROMDIR", 0x50), (b"PAD", wrap), (b"ROMVER", 0x10)])
        romver_at = 0
        data = bytearray(data)
        data[romver_at:romver_at + 14] = b"0230AC20080220"
        self.assertTrue(romdir_accepts(bytes(data), WX))
        self.assertFalse(romdir_accepts(bytes(data), {**WX, "offset_width": 64}))

    def test_512_ki_entries_without_reset(self):
        """The later loop just ends and walks on from the last entry it read,
        the wxWidgets code throws."""
        data = bytearray(512 * 1024 * 16)
        data[-16:] = entry(b"ROMVER", 0x10)
        data[0:14] = b"0230AC20080220"
        self.assertTrue(romdir_accepts(bytes(data), MODERN))
        self.assertFalse(romdir_accepts(bytes(data), WX))

    def test_serial_and_zone_tests(self):
        coh = image(romver=b"0100TZ20000306", serial=b"20040519-145634")
        stamp = image(serial=b"20111012-094243")
        self.assertTrue(romdir_accepts(coh, {**MODERN, "zones": ["TZ"]}))
        self.assertFalse(romdir_accepts(image(), {**MODERN, "zones": ["TZ"]}))
        self.assertFalse(romdir_accepts(coh, {**MODERN, "refused_zones": ["TZ"]}))
        self.assertTrue(romdir_accepts(image(romver=b"0100TC20000306"),
                                       {**MODERN, "refused_zones": ["TZ"]}))
        self.assertFalse(romdir_accepts(stamp, {**MODERN, "refused_serials": ["20111012-094243"]}))

    def test_every_pcsx2_profile_declares_its_walk(self):
        """A content-found PS2 image without its walk would be judged by the
        defaults, not by what its fork does."""
        import yaml
        for path in sorted((REPO_ROOT / "emulators").glob("*.yml")):
            profile = yaml.safe_load(path.read_text())
            if "sony-playstation-2" not in (profile.get("systems") or []):
                continue
            for f in profile.get("files") or []:
                if "romdir" in (f.get("validation") or []):
                    with self.subTest(profile=path.stem, name=f.get("name")):
                        self.assertTrue(set(f["romdir"]) >= {
                            "reset_compare", "missing_reset", "terminated_names", "extinfo",
                            "unreadable_romver", "truncated_walk"})


class OtherContentTests(unittest.TestCase):
    def test_masked_sha1_clears_the_config_bytes(self):
        payload = bytearray(range(256)) * 512  # 131072 bytes
        cleared = bytearray(payload)
        cleared[0x10:0x30] = bytes(0x20)
        spec = {"zeroed": [16, 48], "reads": [{"size": 131072, "lengths": [0x1C000]}],
                "sha1": hashlib.sha1(cleared[:0x1C000]).hexdigest()}
        entry_ = {"validation": ["masked_sha1"], "masked_sha1": spec}
        with tempfile.TemporaryDirectory() as tmp:
            good = Path(tmp, "flash.rom")
            good.write_bytes(bytes(payload))
            other = Path(tmp, "other.rom")
            other.write_bytes(bytes(payload[:-1]) + b"\x01")
            short = Path(tmp, "short.rom")
            short.write_bytes(bytes(payload[:65536]))
            config = bytearray(payload)
            config[0x20] ^= 0xFF
            reconfigured = Path(tmp, "reconfigured.rom")
            reconfigured.write_bytes(bytes(config))
            self.assertTrue(common.content_fits(entry_, str(good)))
            self.assertTrue(common.content_fits(entry_, str(reconfigured)))
            self.assertTrue(common.content_fits(entry_, str(other)))  # past 0x1c000
            self.assertFalse(common.content_fits(entry_, str(short)))
            payload[0x100] ^= 1
            good.write_bytes(bytes(payload))
            common._masked_sha1_verdict.cache_clear()
            self.assertFalse(common.content_fits(entry_, str(good)))

    def test_size_multiple(self):
        flash = {"min_size": 65536, "size_multiple": 65536, "validation": ["size"]}
        self.assertTrue(common.size_fits(flash, 262144))
        self.assertTrue(common.size_fits(flash, 65536 * 3))
        self.assertFalse(common.size_fits(flash, 65536 + 1))
        self.assertFalse(common.size_fits(flash, 0))


class ScannerVerifyManifestAgree(unittest.TestCase):
    """The pack and manifest scan, the emulator pack and verify --emulator
    expansion, the name step of the resolver and verify's validation judge
    one folder the same way."""

    IMAGES = {
        "SCPH-70004.BIN": image(),
        "246C.bin": image(romver=b"0100TZ20000306", serial=b"20021119-163841"),
        "GameIndex.yaml": b"GameIndex: not a BIOS\n" * 300,
        "ps2-dvd-311.bin": b"\x00" * 0x4000,
    }
    COMPANIONS = {"SCPH-70004.nvm": b"N" * 1024, "246C.mec": b"\x03\x06\x02\x00",
                  "loose.nvm": b"L" * 1024}

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "emulators").mkdir()
        files, by_name = {}, {}
        for name, payload in {**self.IMAGES, **self.COMPANIONS}.items():
            path = self.root / "bios" / "PS2" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            sha1 = hashlib.sha1(payload).hexdigest()
            files[sha1] = {"path": str(path), "name": name, "size": len(payload), "sha1": sha1,
                           "md5": hashlib.md5(payload).hexdigest()}
            by_name.setdefault(name, []).append(sha1)
        self.sha1 = {r["name"]: s for s, r in files.items()}
        self.db = {"files": files, "indexes": {
            "by_name": by_name, "by_md5": {r["md5"]: s for s, r in files.items()},
            "by_sha256": {}, "by_crc32": {}, "by_path_suffix": {}}}
        spec = "\n".join(f"      {k}: {str(v).lower() if isinstance(v, bool) else v}"
                         for k, v in MODERN.items())
        # The anchor proves bios/PS2 holds this system's BIOS by content.
        (self.root / "emulators" / "anchor.yml").write_text(
            "emulator: anchor\ntype: libretro\nsystems: [sony-playstation-2]\ncores: [anchor]\n"
            "files:\n  - name: SCPH-70004.BIN\n"
            f"    sha1: {self.sha1['SCPH-70004.BIN']}\n"
        )
        (self.root / "emulators" / "demo.yml").write_text(
            "emulator: demo\ntype: libretro\nbios_mode: agnostic\n"
            "systems: [sony-playstation-2]\ncores: [demo]\nfiles:\n"
            "  - name: \"<bios>.bin\"\n    found_by: content\n    path: \"ps2/<bios>.bin\"\n"
            "    required: true\n    validation: [romdir]\n    romdir:\n" + spec + "\n"
            "  - name: \"<bios>.nvm\"\n    path: \"ps2/<bios>.nvm\"\n    size: 1024\n"
            "  - name: \"<bios>.mec\"\n    path: \"ps2/<bios>.mec\"\n    size: 4\n"
        )
        common._emulator_profiles_cache.clear()
        self.profiles = common.load_emulator_profiles(str(self.root / "emulators"))
        self.config = {"platform": "Demo", "verification_mode": "existence",
                       "cores": ["demo", "anchor"], "base_destination": "", "systems": {}}

    def tearDown(self):
        common._emulator_profiles_cache.clear()
        self._tmp.cleanup()

    def accepted(self) -> set[str]:
        """What the core lists: each image its walk accepts, each companion
        beside an accepted image of its stem."""
        seed = self.profiles["demo"]["files"][0]
        images = {n for n in self.IMAGES
                  if common.content_fits(seed, str(self.root / "bios" / "PS2" / n))}
        stems = {n.rsplit(".", 1)[0] for n in images}
        return images | {n for n in self.COMPANIONS if n.rsplit(".", 1)[0] in stems}

    def test_the_walk_settles_the_folder(self):
        self.assertEqual(self.accepted(), {"SCPH-70004.BIN", "246C.bin",
                                           "SCPH-70004.nvm", "246C.mec"})

    def test_platform_pack_and_manifest_scan(self):
        extras = builder._collect_emulator_extras(
            self.config, str(self.root / "emulators"), self.db, set(), "", self.profiles,
        )
        placed = {e["name"] for e in extras if e.get("source_profile") == "demo"}
        self.assertEqual(placed, self.accepted())
        self.assertTrue(all(e["destination"].startswith("ps2/") for e in extras
                            if e.get("source_profile") == "demo"))

    def test_emulator_pack_and_verify_expansion(self):
        demo = self.profiles["demo"]
        expanded = packextras.expand_agnostic_entries(
            demo["files"], "demo", demo, self.db, False, self.profiles,
        )
        names = {f["name"] for f in expanded if f.get("agnostic_scan")}
        self.assertEqual(names, self.accepted())

    def test_resolver_name_step_and_validation_agree(self):
        index = _build_validation_index(self.profiles_with_labels())
        for name in self.IMAGES:
            path = str(self.root / "bios" / "PS2" / name)
            entry_ = {"name": name, "found_by": "content", "validation": ["romdir"],
                      "romdir": MODERN, "source_profile": "labels"}
            resolved, status = common.resolve_local_file(entry_, self.db)
            failure = check_file_validation(path, name, index)
            with self.subTest(name=name):
                accepted = name in self.accepted()
                # A name the walk refuses is a mismatch, never a name match.
                self.assertEqual(resolved, path)
                self.assertEqual(status, "name_exact" if accepted else "hash_mismatch")
                self.assertEqual(failure is None, accepted)

    def profiles_with_labels(self) -> dict:
        return {"labels": {"emulator": "labels", "files": [
            {"name": name, "found_by": "content", "validation": ["romdir"], "romdir": MODERN}
            for name in self.IMAGES
        ]}}


if __name__ == "__main__":
    unittest.main()
