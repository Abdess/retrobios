"""An archive declared once per member ships as the copy holding them all.

Batocera checks adam_fdc.zip through eight zipped_file declarations. The
first hash-exact answer was a one-member MAME set, so the pack shipped it and
seven of the eight members Batocera checks were missing.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))


class PreferredArchive(unittest.TestCase):
    def test_the_archive_most_declarations_accept_wins(self):
        import generate_pack

        roms = {f"r{i}.bin": bytes([i]) * 32 for i in range(3)}
        with tempfile.TemporaryDirectory() as tmp:
            previous = os.getcwd()
            os.chdir(tmp)
            self.addCleanup(os.chdir, previous)
            Path("bios/a").mkdir(parents=True)
            Path("bios/b").mkdir(parents=True)
            with zipfile.ZipFile("bios/a/set.zip", "w") as zf:
                zf.writestr("r0.bin", roms["r0.bin"])
            with zipfile.ZipFile("bios/b/set.zip", "w") as zf:
                for name, data in roms.items():
                    zf.writestr(name, data)
            files, by_md5, by_name = {}, {}, {}
            for path in ("bios/a/set.zip", "bios/b/set.zip"):
                data = Path(path).read_bytes()
                sha1, md5 = hashlib.sha1(data).hexdigest(), hashlib.md5(data).hexdigest()
                files[sha1] = {"path": path, "name": "set.zip", "sha1": sha1, "md5": md5,
                               "size": len(data)}
                by_md5[md5] = sha1
                by_name.setdefault("set.zip", []).append(sha1)
            db = {"files": files, "indexes": {"by_name": by_name, "by_md5": by_md5,
                                              "by_path_suffix": {}, "by_crc32": {}}}
            member_md5 = {n: hashlib.md5(d).hexdigest() for n, d in roms.items()}
            one_member = files[by_name["set.zip"][0]]["md5"]
            declarations = [{"name": "set.zip", "destination": "set.zip", "md5": one_member}]
            declarations += [
                {"name": "set.zip", "destination": "set.zip", "zipped_file": name, "md5": md5}
                for name, md5 in member_md5.items()
            ]
            systems = {"s": {"files": declarations}}
            preferred = generate_pack._preferred_entries(
                systems, db, "bios", "", False, {}, True)
            chosen = next(fe for fe in declarations if id(fe) == preferred["set.zip"])
            path, _status = generate_pack.resolve_file(chosen, db, "bios", {}, offline=True)
            self.assertEqual(path, "bios/b/set.zip")


class OneWinnerRuleForEveryReader(unittest.TestCase):
    """verify passed the data-directory registry to the winner rule, the pack
    and the manifest passed none: a declaration only a data/ cache satisfies
    won in the report and lost in the pack. The rule takes no registry."""

    def test_the_rule_reads_no_data_directory(self):
        import inspect  # noqa: PLC0415

        import generate_pack  # noqa: PLC0415

        parameters = inspect.signature(generate_pack._preferred_entries).parameters
        self.assertFalse([name for name in parameters if "registry" in name])


class IntegrityChecksEveryMember(unittest.TestCase):
    """A pack holding one ROM of an archive declared per ROM fails its check.

    The check accepted the destination as soon as one declaration passed,
    so a Batocera pack missing seven of adam_fdc.zip's eight ROMs verified.
    """

    def test_a_missing_member_is_an_error_when_the_repository_holds_it(self):
        import yaml

        import packverify

        roms = {f"r{i}.bin": bytes([i]) * 32 for i in range(3)}
        with tempfile.TemporaryDirectory() as tmp:
            previous = os.getcwd()
            os.chdir(tmp)
            self.addCleanup(os.chdir, previous)
            Path("bios/b").mkdir(parents=True)
            with zipfile.ZipFile("bios/b/set.zip", "w") as zf:
                for name, data in roms.items():
                    zf.writestr(name, data)
            data = Path("bios/b/set.zip").read_bytes()
            sha1 = hashlib.sha1(data).hexdigest()
            db = {"files": {sha1: {"path": "bios/b/set.zip", "name": "set.zip", "sha1": sha1,
                                   "md5": hashlib.md5(data).hexdigest(), "size": len(data)}},
                  "indexes": {"by_name": {"set.zip": [sha1]}, "by_md5": {},
                              "by_path_suffix": {}, "by_crc32": {}}}
            Path("platforms").mkdir()
            config = {"platform": "P", "verification_mode": "md5", "base_destination": "bios",
                      "cores": [], "systems": {"s": {"files": [
                          {"name": "set.zip", "destination": "set.zip", "zipped_file": n,
                           "md5": hashlib.md5(d).hexdigest()} for n, d in roms.items()]}}}
            Path("platforms/p.yml").write_text(yaml.safe_dump(config), encoding="utf-8")
            Path("emulators").mkdir()
            import io

            inner = io.BytesIO()
            with zipfile.ZipFile(inner, "w") as zf:
                zf.writestr("r0.bin", roms["r0.bin"])
            with zipfile.ZipFile("pack.zip", "w") as zf:
                zf.writestr("bios/set.zip", inner.getvalue())
            ok, *_rest, = packverify.verify_pack_against_platform(
                "pack.zip", "p", "platforms", db, emulators_dir="emulators", emu_profiles={})
            errors = _rest[2]
            self.assertFalse(ok)
            self.assertEqual(sorted(e.split(": ")[1] for e in errors),
                             ["r1.bin not found inside ZIP", "r2.bin not found inside ZIP"])


class TheArchiveHoldingTheCoreMembers(unittest.TestCase):
    """FBNeo reads neocd.bin and 000-lo.lo inside neocdz.zip. The primary
    copy has no 000-lo.lo, and a variant holds both. Resolved by name, every
    pack shipped the primary at fbneo/neocdz.zip and the core could not
    start a Neo Geo CD game."""

    def setUp(self):
        directory = tempfile.mkdtemp(dir=REPO_ROOT / "tmp")
        self.addCleanup(shutil.rmtree, directory, True)
        root = Path(directory)
        self.roms = {"neocd.bin": b"bios" * 8, "000-lo.lo": b"zoom" * 8}
        files, by_name = {}, {}
        for path, members in (
            (root / "bios/neocdz.zip", ["neocd.bin"]),
            (root / "bios/.variants/neocdz.zip.ba20a7be", ["neocd.bin", "000-lo.lo"]),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(path, "w") as zf:
                for member in members:
                    zf.writestr(member, self.roms[member])
            sha1 = hashlib.sha1(path.read_bytes()).hexdigest()
            files[sha1] = {"path": str(path), "name": "neocdz.zip", "sha1": sha1}
            by_name.setdefault("neocdz.zip", []).append(sha1)
        self.db = {"files": files, "indexes": {"by_name": by_name, "by_md5": {},
                                               "by_path_suffix": {}, "by_crc32": {}}}
        self.profile_files = [
            {"name": name, "archive": "neocdz.zip", "required": True,
             "crc32": format(zlib.crc32(data), "08x")}
            for name, data in self.roms.items()
        ]

    def test_the_copy_with_every_required_member_wins(self):
        from common import archive_entry, resolve_local_file

        path, status = resolve_local_file(
            archive_entry("neocdz.zip", self.profile_files), self.db
        )
        self.assertTrue(path.endswith(".variants/neocdz.zip.ba20a7be"))
        self.assertEqual(status, "name_exact")

    def test_without_members_the_primary_stays(self):
        from common import resolve_local_file

        path, _status = resolve_local_file({"name": "neocdz.zip"}, self.db)
        self.assertTrue(path.endswith("bios/neocdz.zip"))

    def test_the_extras_carry_the_members(self):
        from packextras import _report_extra

        members = [{"crc32": "5a86cff2", "required": True}]
        extra = _report_extra(
            {"name": "neocdz.zip", "archive": "neocdz.zip", "members": members},
            "neocdz.zip", "fbneo/neocdz.zip",
        )
        self.assertEqual(extra["members"], members)

    def test_the_collection_holds_each_archive_a_core_requires(self):
        """FBNeo's nmk004.zip wants nmk004.bin crc 8ae61a09, but both copies held
        MAME's 83b6f611 dump while the FBNeo dump sat loose in bios/."""
        import json

        from common import archive_members, load_emulator_profiles, zip_member_crcs

        database = REPO_ROOT / "database.json"
        if not database.exists():
            self.skipTest("database.json is not generated")
        db = json.loads(database.read_text())
        by_name = db["indexes"]["by_name"]
        short = []
        for emu, profile in load_emulator_profiles(str(REPO_ROOT / "emulators")).items():
            entries = [f for f in profile.get("files") or [] if not f.get("unsourceable")]
            for archive in sorted({f["archive"] for f in entries if f.get("archive")}):
                required = {
                    m["crc32"] for m in archive_members(archive, entries) if m["required"]
                }
                copies = [
                    REPO_ROOT / db["files"][sha1]["path"]
                    for sha1 in by_name.get(archive, []) if sha1 in db["files"]
                ]
                if required and copies and not any(
                    required <= zip_member_crcs(str(path)) for path in copies
                ):
                    short.append(f"{emu}: {archive}")
        self.assertEqual(short, [])

    def test_verify_and_the_pack_read_one_entry(self):
        for module in ("verify.py", "generate_pack.py"):
            source = (REPO_ROOT / "scripts" / module).read_text()
            with self.subTest(module=module):
                self.assertIn("archive_entry(", source)
                self.assertNotIn('{"name": archive', source)


class EveryDeclaredLayoutIsHeld(unittest.TestCase):
    """mame4droid reads awbios.zip as MAME 0.139 laid it out, bios.ic23_l
    alone, and every copy held the later bios0/bios1.ic23 split: the core
    found no BIOS in the archive the pack shipped under its name. A
    ``contents:`` list names one version of a set, and the collection must
    hold that version, served to the profile that declares it."""

    def setUp(self):
        import json

        from common import get_mame_clone_map

        database = REPO_ROOT / "database.json"
        if not (REPO_ROOT / "bios").is_dir() or not database.exists():
            self.skipTest("bios/ or database.json is absent")
        self.db = json.loads(database.read_text())
        self.clones = get_mame_clone_map(str(REPO_ROOT / "bios"))
        previous = os.getcwd()
        os.chdir(REPO_ROOT)
        self.addCleanup(os.chdir, previous)

    def _declared_archives(self):
        from common import load_emulator_profiles

        for emu, profile in load_emulator_profiles("emulators").items():
            for entry in profile.get("files") or []:
                if entry.get("category") == "bios_zip" and not entry.get("unsourceable"):
                    yield emu, entry

    def _copies(self, entry) -> list[str]:
        """Paths the database holds under the archive's names. dedup.py keeps
        one of several byte-identical MAME archives and maps the others to it,
        so a clone name is held by its canonical copy."""
        by_name = self.db["indexes"]["by_name"]
        names = [entry["name"], *(entry.get("aliases") or [])]
        names += [self.clones[name] for name in names if name in self.clones]
        return [
            self.db["files"][sha1]["path"] for name in names
            for sha1 in by_name.get(name, []) if sha1 in self.db["files"]
        ]

    def test_every_declared_archive_has_a_copy(self):
        """The layout check below skips an archive with no copy at all.
        Looking up names alone, it skipped 23 MAME device sets held only
        through the clone map, and Supermodel's pro1000.zip, which the
        collection did not hold. A set with no copy is an acquisition
        target, marked ``unsourceable:`` only when a homonym would otherwise
        stand in."""
        absent = sorted({
            f"{emu}: {entry['name']}"
            for emu, entry in self._declared_archives() if not self._copies(entry)
        })
        self.assertEqual(absent, [])

    def test_a_copy_holds_each_declared_layout_and_is_served(self):
        from common import resolve_local_file, zip_member_crcs

        short, unserved = [], []
        for emu, entry in self._declared_archives():
            crcs = {str(m["crc32"]).lower() for m in entry.get("contents") or []
                    if m.get("crc32")}
            copies = [path for path in self._copies(entry) if Path(path).exists()]
            if not crcs or not copies:
                continue
            if not any(crcs <= zip_member_crcs(path) for path in copies):
                short.append(f"{emu}: {entry['name']}")
                continue
            path, _status = resolve_local_file(entry, self.db)
            if not path or not crcs <= zip_member_crcs(path):
                unserved.append(f"{emu}: {entry['name']} -> {path}")
        self.assertEqual(short, [])
        self.assertEqual(unserved, [])


class AnArchiveHashedByItsMembers(unittest.TestCase):
    """Recalbox hashes a .zip with Zip::Md5Composite (Bios.cpp:64-68). Its
    neocdz.zip pin is neocd.bin's md5, which is also the composite of a
    one-member archive, and the md5 step served the raw ROM under the
    archive's name: Recalbox cannot open it and reports the BIOS red."""

    def setUp(self):
        directory = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, directory, True)
        rom = b"bios" * 8
        raw = directory / "bios/neocd.bin"
        archive = directory / "bios/.variants/neocdz.zip.4f28af31"
        archive.parent.mkdir(parents=True)
        raw.write_bytes(rom)
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("neocd.bin", rom)
        files, by_md5, by_name = {}, {}, {}
        for path, name in ((raw, "neocd.bin"), (archive, "neocdz.zip")):
            data = path.read_bytes()
            sha1, md5 = hashlib.sha1(data).hexdigest(), hashlib.md5(data).hexdigest()
            files[sha1] = {"path": str(path), "name": name, "sha1": sha1, "md5": md5}
            by_md5[md5] = sha1
            by_name.setdefault(name, []).append(sha1)
        self.db = {"files": files, "indexes": {"by_name": by_name, "by_md5": by_md5,
                                               "by_path_suffix": {}, "by_crc32": {}}}
        self.entry = {"name": "neocdz.zip", "md5": hashlib.md5(rom).hexdigest()}
        self.archive = str(archive)

    def test_the_archive_answers_a_composite_frontend(self):
        from common import resolve_local_file

        path, status = resolve_local_file({**self.entry, "zip_digest": "composite"}, self.db)
        self.assertEqual((path, status), (self.archive, "md5_composite_exact"))

    def test_a_plain_digest_still_takes_the_md5_match(self):
        from common import resolve_local_file

        path, _status = resolve_local_file(self.entry, self.db)
        self.assertTrue(path.endswith("neocd.bin"))

    def test_the_registry_marks_recalbox_archives(self):
        from common import load_platform_config

        config = load_platform_config("recalbox", str(REPO_ROOT / "platforms"))
        marks = {
            (f["name"].lower().endswith(".zip"), f.get("zip_digest"))
            for system in config["systems"].values() for f in system["files"]
        }
        self.assertEqual(marks, {(True, "composite"), (False, None)})


class AnArchiveRankedByWhatItHolds(unittest.TestCase):
    """Two primaries answered hod2bios.zip and the first one indexed won:
    Flycast received a set without epr-21329.ic27, its Japan BIOS, once an
    unrelated duplicate was deleted and the index order flipped."""

    def setUp(self):
        directory = tempfile.mkdtemp(dir=REPO_ROOT / "tmp")
        self.addCleanup(shutil.rmtree, directory, True)
        self.root = Path(directory)
        self.roms = {f"epr-213{n}.ic27": bytes([n]) * 16 for n in (29, 30, 31, 32)}

    def _db(self, copies: list[tuple[str, list[str]]]) -> dict:
        files, by_name = {}, {}
        for relative, members in copies:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(path, "w") as zf:
                for member in members:
                    zf.writestr(member, self.roms.get(member, member.encode()))
            sha1 = hashlib.sha1(path.read_bytes()).hexdigest()
            files[sha1] = {"path": str(path), "name": "hod2bios.zip", "sha1": sha1}
            by_name.setdefault("hod2bios.zip", []).append(sha1)
        return {"files": files, "indexes": {"by_name": by_name, "by_md5": {},
                                            "by_path_suffix": {}, "by_crc32": {}}}

    def _resolve(self, entry: dict, db: dict) -> str:
        from common import resolve_local_file

        path, _status = resolve_local_file(entry, db)
        return str(Path(path).relative_to(self.root))

    def test_member_names_the_code_opens_choose_the_copy(self):
        db = self._db([("bios/Arcade/hod2bios.zip", ["epr-21330.ic27", "epr-21331.ic27"]),
                       ("bios/MAME/hod2bios.zip", list(self.roms))])
        entry = {"name": "hod2bios.zip", "contents": [
            {"name": name, "size": 16} for name in ("epr-21331.ic27", "epr-21330.ic27",
                                                     "epr-21329.ic27")]}
        self.assertEqual(self._resolve(entry, db), "bios/MAME/hod2bios.zip")

    def test_member_crcs_choose_the_copy(self):
        db = self._db([("bios/Arcade/hod2bios.zip", ["epr-21330.ic27", "renamed.ic27"]),
                       ("bios/MAME/hod2bios.zip", ["epr-21330.ic27", "epr-21332.ic27"])])
        entry = {"name": "hod2bios.zip", "contents": [
            {"name": "other-name.ic27", "crc32": format(zlib.crc32(self.roms[name]), "08x")}
            for name in ("epr-21330.ic27", "epr-21332.ic27")]}
        self.assertEqual(self._resolve(entry, db), "bios/MAME/hod2bios.zip")

    def test_a_shared_crc_keeps_the_member_name(self):
        """segadimm.zip holds fpr23905.ic36 and fpr23905c.ic36, both crc32
        ffffffff. Ranked by crc alone, a copy without fpr23905c.ic36 tied with
        the full set and came first in the index."""
        self.roms["fpr23905.ic36"] = self.roms["fpr23905c.ic36"] = b"\xff" * 16
        db = self._db([("bios/Arcade/hod2bios.zip", ["epr-21330.ic27", "fpr23905.ic36"]),
                       ("bios/MAME/hod2bios.zip",
                        ["epr-21330.ic27", "fpr23905.ic36", "fpr23905c.ic36"])])
        crc = format(zlib.crc32(b"\xff" * 16), "08x")
        first = format(zlib.crc32(self.roms["epr-21330.ic27"]), "08x")
        entry = {"name": "hod2bios.zip", "contents": [
            {"name": "epr-21330.ic27", "crc32": first},
            {"name": "fpr23905.ic36", "crc32": crc},
            {"name": "fpr23905c.ic36", "crc32": crc}]}
        self.assertEqual(self._resolve(entry, db), "bios/MAME/hod2bios.zip")

    def test_a_copy_holding_no_declared_member_is_not_the_archive(self):
        """galgames.zip held only an assembler listing and none of the six
        ROMs MAME declares: the name step served it as the BIOS set."""
        from common import resolve_local_file

        db = self._db([("bios/MAME/hod2bios.zip", ["listing.lst"])])
        entry = {"name": "hod2bios.zip", "contents": [
            {"name": name, "crc32": format(zlib.crc32(self.roms[name]), "08x")}
            for name in ("epr-21330.ic27", "epr-21332.ic27")]}
        path, status = resolve_local_file(entry, db)
        self.assertEqual(status, "hash_mismatch")
        self.assertEqual(Path(path).relative_to(self.root).as_posix(),
                         "bios/MAME/hod2bios.zip")

    def test_without_a_layout_a_superset_primary_wins(self):
        db = self._db([("bios/Arcade/hod2bios.zip", ["epr-21330.ic27"]),
                       ("bios/MAME/hod2bios.zip", list(self.roms))])
        self.assertEqual(self._resolve({"name": "hod2bios.zip"}, db),
                         "bios/MAME/hod2bios.zip")

    def test_two_revisions_keep_the_index_order(self):
        db = self._db([("bios/Arcade/hod2bios.zip", ["epr-21330.ic27", "epr-21331.ic27"]),
                       ("bios/MAME/hod2bios.zip", ["epr-21330.ic27", "epr-21332.ic27"])])
        self.assertEqual(self._resolve({"name": "hod2bios.zip"}, db),
                         "bios/Arcade/hod2bios.zip")

    def test_a_variant_does_not_stop_a_primary_from_covering(self):
        db = self._db([("bios/Arcade/hod2bios.zip", ["epr-21330.ic27"]),
                       ("bios/MAME/hod2bios.zip", list(self.roms)),
                       ("bios/Arcade/.variants/hod2bios.zip", ["proto.ic27"])])
        self.assertEqual(self._resolve({"name": "hod2bios.zip"}, db),
                         "bios/MAME/hod2bios.zip")

    def test_every_claim_path_carries_the_layout(self):
        from packextras import _report_extra

        contents = [{"name": "epr-21329.ic27", "size": 16}]
        extra = _report_extra({"name": "hod2bios.zip", "contents": contents},
                              "hod2bios.zip", "dc/hod2bios.zip")
        self.assertEqual(extra["contents"], contents)
        # The second pass builds its extra from the profile entry itself.
        source = (REPO_ROOT / "scripts" / "packextras.py").read_text()
        self.assertEqual(source.count('extra["contents"] = '), 2)
        report = (REPO_ROOT / "scripts" / "verify.py").read_text()
        self.assertIn('entry["contents"] = f["contents"]', report)


class ALooseEntryNamingItsArchive(unittest.TestCase):
    """gngeopi declares neogeo.zip loose and, apart, the ROMs it opens inside.
    The archive pass took the copy holding them, the loose entry resolved by
    name alone to another copy, and the profile blocked its own archive:
    verify said missing, the pack said missing, and the ZIP held it."""

    def test_verify_and_the_pack_ship_the_archive_once(self):
        import io
        from contextlib import redirect_stdout

        import yaml

        from common import _emulator_profiles_cache
        from generate_pack import generate_emulator_pack
        from verify import verify_emulator

        _emulator_profiles_cache.clear()
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, root, True)
        previous = os.getcwd()
        os.chdir(root)
        self.addCleanup(os.chdir, previous)
        roms = {"bios.rom": b"B" * 32, "lo.lo": b"L" * 32, "rev.rom": b"R" * 32}
        files, by_name = {}, {}
        # Two revisions, neither holding the other: index order picks A.
        for path, members in (("bios/A/set.zip", ["bios.rom", "rev.rom"]),
                              ("bios/B/set.zip", ["bios.rom", "lo.lo"])):
            Path(path).parent.mkdir(parents=True)
            with zipfile.ZipFile(path, "w") as zf:
                for member in members:
                    zf.writestr(member, roms[member])
            sha1 = hashlib.sha1(Path(path).read_bytes()).hexdigest()
            files[sha1] = {"path": path, "name": "set.zip", "sha1": sha1, "size": 1}
            by_name.setdefault("set.zip", []).append(sha1)
        db = {"files": files, "indexes": {"by_name": by_name, "by_md5": {},
                                          "by_path_suffix": {}, "by_crc32": {}}}
        Path("emulators").mkdir()
        Path("emulators/neo.yml").write_text(yaml.safe_dump({
            "emulator": "Neo", "type": "libretro", "systems": ["snk-neogeo-mvs"],
            "files": [{"name": "set.zip", "required": True, "category": "bios_zip"}] + [
                {"name": name, "archive": "set.zip", "required": True,
                 "crc32": format(zlib.crc32(data), "08x")}
                for name, data in roms.items() if name != "rev.rom"
            ],
        }))
        report = verify_emulator(["neo"], "emulators", db, platforms_dir="platforms")
        with redirect_stdout(io.StringIO()) as out:
            zip_path = generate_emulator_pack(
                ["neo"], "emulators", db, "bios", "out", offline=True,
                platforms_dir="platforms",
            )
        with zipfile.ZipFile(zip_path) as zf, zf.open("set.zip") as inner:
            held = zipfile.ZipFile(io.BytesIO(inner.read())).namelist()
        self.assertEqual(sorted(held), ["bios.rom", "lo.lo"])
        self.assertNotIn("missing", out.getvalue())
        self.assertEqual({d["status"] for d in report["details"]}, {"ok"})
        self.assertEqual(report["total_files"], 1)


class AnotherEmulatorsOwnSet(unittest.TestCase):
    """Demul's naomi.zip in bios/Other/demul/ holds more NAOMI BIOS rows than
    any MAME set. Ranked with the others it won the member count for Flycast
    and broke the superset rule for the MAME cores, which then got a smaller
    copy."""

    def setUp(self):
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, root, True)
        previous = os.getcwd()
        os.chdir(root)
        self.addCleanup(os.chdir, previous)
        self.roms = {f"r{n}.ic27": bytes([n]) * 16 for n in range(5)}
        layout = {"bios/Arcade/naomi.zip": ["r0.ic27", "r1.ic27"],
                  "bios/MAME/naomi.zip": ["r0.ic27", "r1.ic27", "r2.ic27"],
                  "bios/Other/demul/naomi.zip": list(self.roms)}
        files, by_name = {}, {}
        for relative, members in layout.items():
            Path(relative).parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(relative, "w") as zf:
                for member in members:
                    zf.writestr(member, self.roms[member])
            sha1 = hashlib.sha1(Path(relative).read_bytes()).hexdigest()
            files[sha1] = {"path": relative, "name": "naomi.zip", "sha1": sha1}
            by_name.setdefault("naomi.zip", []).append(sha1)
        self.db = {"files": files, "indexes": {"by_name": by_name, "by_md5": {},
                                               "by_path_suffix": {}, "by_crc32": {}}}

    def _contents(self, names: list[str]) -> list[dict]:
        return [{"name": n, "crc32": format(zlib.crc32(self.roms[n]), "08x")} for n in names]

    def test_its_member_count_does_not_rank_for_another_emulator(self):
        from common import resolve_local_file

        entry = {"name": "naomi.zip", "source_profile": "flycast",
                 "contents": self._contents(list(self.roms))}
        path, _status = resolve_local_file(entry, self.db)
        self.assertEqual(path, "bios/MAME/naomi.zip")

    def test_it_does_not_break_the_superset_of_an_unowned_entry(self):
        from common import resolve_local_file

        path, _status = resolve_local_file({"name": "naomi.zip"}, self.db)
        self.assertEqual(path, "bios/MAME/naomi.zip")

    def test_its_owner_still_gets_it(self):
        from common import resolve_local_file

        entry = {"name": "naomi.zip", "source_profile": "demul",
                 "contents": self._contents(list(self.roms))}
        path, _status = resolve_local_file(entry, self.db)
        self.assertEqual(path, "bios/Other/demul/naomi.zip")


class ArchiveMembersIndexOnce(unittest.TestCase):
    """with_archive_members asks once per entry of a profile: scanning the
    whole list for each walked 38 million entries in one verify --all."""

    class CountingList(list):
        walks = 0

        def __iter__(self):
            type(self).walks += 1
            return super().__iter__()

    def entries(self) -> list[dict]:
        files = self.CountingList()
        self.CountingList.walks = 0
        for n in range(300):
            files.append({"name": f"m{n}.rom", "archive": f"set{n % 30}.zip",
                          "crc32": f"{n:08X}", "required": n % 3 != 0})
        files.append({"name": "loose.bin", "crc32": "deadbeef"})
        files.append({"name": "nocrc.rom", "archive": "set0.zip"})
        return files

    @staticmethod
    def scanned(archive, files) -> list[dict]:
        return [{"crc32": str(f["crc32"]).lower(), "required": bool(f.get("required", True))}
                for f in list.__iter__(files) if f.get("archive") == archive and f.get("crc32")]

    def test_a_profile_list_is_walked_once_and_answers_as_a_scan(self):
        from common import archive_members

        files = self.entries()
        for archive in [f"set{n}.zip" for n in range(30)] + ["absent.zip", "", None]:
            with self.subTest(archive=archive):
                self.assertEqual(archive_members(archive, files), self.scanned(archive, files))
        self.assertEqual(self.CountingList.walks, 1)

    def test_a_list_that_grew_is_indexed_again(self):
        from common import archive_members

        files = self.entries()
        archive_members("set1.zip", files)
        files.append({"name": "late.rom", "archive": "set1.zip", "crc32": "ABCDEF01"})
        self.assertEqual(archive_members("set1.zip", files), self.scanned("set1.zip", files))
        self.assertIn({"crc32": "abcdef01", "required": True}, archive_members("set1.zip", files))


if __name__ == "__main__":
    unittest.main()
