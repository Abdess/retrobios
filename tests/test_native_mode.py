#!/usr/bin/env python3
"""The native-mode policy verify.py and generate_pack.py must share.

verify.py and generate_pack.py must reach the same verdict on the same file:
a pack and a coverage report that disagree describe different collections.
The rule used to rest on both files spelling out `mode == "existence"` in
their own words. Routing both through scripts/nativemode.py single-sources
it, and these tests make the agreement checkable instead of reviewable.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import nativemode  # noqa: E402


class ModeVocabulary(unittest.TestCase):
    def test_modes_match_the_platform_schema(self):
        """A mode added to one side and not the other is the bug this catches."""
        schema = json.loads(
            (REPO_ROOT / "schemas" / "platform.schema.json").read_text()
        )
        enum = schema["properties"]["verification_mode"]["enum"]
        self.assertEqual(sorted(nativemode.MODES), sorted(enum))

    def test_schema_default_matches_the_module_default(self):
        schema = json.loads(
            (REPO_ROOT / "schemas" / "platform.schema.json").read_text()
        )
        self.assertEqual(
            schema["properties"]["verification_mode"]["default"],
            nativemode.DEFAULT_MODE,
        )

    def test_unknown_or_missing_mode_falls_back_to_the_default(self):
        for value in (None, "", "sha256", "MD5"):
            self.assertEqual(nativemode.normalize(value), nativemode.DEFAULT_MODE)

    def test_every_declared_platform_mode_is_known(self):
        import yaml

        for path in sorted((REPO_ROOT / "platforms").glob("*.yml")):
            if path.name.startswith("_"):
                continue
            data = yaml.safe_load(path.read_text()) or {}
            mode = data.get("verification_mode")
            if mode is None:
                continue
            self.assertIn(mode, nativemode.MODES, f"{path.name} declares {mode!r}")


class ContentReadingPolicy(unittest.TestCase):
    def test_existence_reads_nothing(self):
        self.assertFalse(nativemode.reads_file_contents("existence"))
        self.assertIsNone(nativemode.digest_algorithm("existence"))

    def test_digest_modes_read_their_digest(self):
        self.assertEqual(nativemode.digest_algorithm("md5"), "md5")
        self.assertEqual(nativemode.digest_algorithm("sha1"), "sha1")
        self.assertTrue(nativemode.reads_file_contents("md5"))
        self.assertTrue(nativemode.reads_file_contents("sha1"))

    def test_exclusion_follows_content_reading_for_every_mode(self):
        """The builder omits exactly what the frontend would reject."""
        for mode in nativemode.MODES:
            self.assertEqual(
                nativemode.hash_mismatch_excludes_file(mode),
                nativemode.reads_file_contents(mode),
                f"mode {mode} disagrees with itself",
            )


class BothConsumersAgree(unittest.TestCase):
    """verify.py and generate_pack.py must answer the same for every mode."""

    def test_builder_and_verifier_share_one_predicate(self):
        from generate_pack import _intentional_hash_exclusion
        from verify import compute_severity  # noqa: F401  (import proves wiring)

        for mode in nativemode.MODES:
            # No entries is never an exclusion, whatever the mode.
            self.assertFalse(_intentional_hash_exclusion([], {}, verification_mode=mode))

        # The builder must refuse to exclude under existence even when asked.
        self.assertFalse(
            _intentional_hash_exclusion(
                [{"name": "x.bin"}], {}, verification_mode="existence"
            )
        )

    def test_severity_uses_the_shared_predicate(self):
        from verify import Severity, Status, compute_severity

        # Existence mode: a missing required file is a warning, not critical.
        self.assertEqual(
            compute_severity(Status.MISSING, True, "existence"),
            Severity.WARNING,
        )
        # Digest mode: the same absence is critical.
        self.assertEqual(
            compute_severity(Status.MISSING, True, "md5"),
            Severity.CRITICAL,
        )
        # An unknown mode must fall back to existence, not to the strictest
        # reading: a typo in a platform YAML should not invent CRITICALs.
        self.assertEqual(
            compute_severity(Status.MISSING, True, "sha256"),
            Severity.WARNING,
        )


class ThePolicyIsSpeltInOnePlace(unittest.TestCase):
    """Consumers ask the module; they do not re-spell the rule.

    Four sites still compared the mode to a literal after this module existed,
    and one of them dispatched an unknown mode to MD5 verification while
    compute_severity was scoring it as existence.
    """

    LITERALS = ('!= "existence"', '== "existence"', 'in ("md5", "sha1")')

    def test_no_consumer_compares_the_mode_to_a_literal(self):
        scripts = Path(__file__).resolve().parent.parent / "scripts"
        offenders = []
        for path in sorted(scripts.glob("*.py")):
            if path.name == "nativemode.py":
                continue
            for number, line in enumerate(path.read_text().splitlines(), 1):
                if any(literal in line for literal in self.LITERALS):
                    offenders.append(f"{path.name}:{number}: {line.strip()}")
        self.assertEqual(
            offenders, [],
            "route these through nativemode: " + "; ".join(offenders),
        )

    def test_an_unknown_mode_verifies_the_way_it_is_scored(self):
        """A typo in a platform YAML must not verify one way and score another."""
        import verify

        self.assertFalse(nativemode.reads_file_contents("sha256"))
        self.assertEqual(
            verify.compute_severity(verify.Status.MISSING, True, "sha256"),
            verify.Severity.WARNING,
        )
        config = {
            "platform": "Typo",
            "verification_mode": "shaa1",
            "systems": {},
            "cores": [],
        }
        result = verify.verify_platform(
            config, {"files": {}, "indexes": {}}, emu_profiles={},
            supplemental_names=set(),
        )
        self.assertEqual(result["verification_mode"], nativemode.DEFAULT_MODE)


class GapAnalysisAgreesWithTheBuilder(unittest.TestCase):
    """"Available" must mean the pack will carry it.

    find_undeclared_files answered from the name index, so a core extra whose
    local copy contradicts its declared hash counted as held. Under a digest
    mode the builder drops exactly that file, so the coverage report described
    a pack that would not contain it: seven such files across three platforms.
    """

    def _fixture(self):
        import hashlib
        import tempfile

        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        (root / "emulators").mkdir()
        rom = root / "collide.rom"
        rom.write_bytes(b"THE BYTES THE COLLECTION HOLDS")
        sha1 = hashlib.sha1(rom.read_bytes()).hexdigest()
        db = {
            "files": {
                sha1: {
                    "path": str(rom),
                    "name": "collide.rom",
                    "size": rom.stat().st_size,
                    "sha1": sha1,
                    "md5": hashlib.md5(rom.read_bytes()).hexdigest(),
                    "sha256": hashlib.sha256(rom.read_bytes()).hexdigest(),
                    "crc32": "00000000",
                }
            },
            "indexes": {
                "by_name": {"collide.rom": [sha1]},
                "by_md5": {hashlib.md5(rom.read_bytes()).hexdigest(): sha1},
                "by_sha256": {},
                "by_crc32": {},
                "by_path_suffix": {},
            },
        }
        (root / "emulators" / "demo.yml").write_text(
            "emulator: demo\n"
            "type: libretro\n"
            "display_name: Demo\n"
            "systems: [demo-system]\n"
            "cores: [demo]\n"
            "files:\n"
            "  - name: collide.rom\n"
            "    system: demo-system\n"
            "    required: true\n"
            "    md5: \"" + "f" * 32 + "\"\n"
        )
        return tmp, root, db

    def _in_repo(self, mode: str) -> bool:
        import common
        from verify import find_undeclared_files

        tmp, root, db = self._fixture()
        try:
            common._emulator_profiles_cache.clear()
            profiles = common.load_emulator_profiles(str(root / "emulators"))
            config = {
                "platform": "Demo",
                "verification_mode": mode,
                "cores": ["demo"],
                "systems": {},
            }
            found = find_undeclared_files(
                config, str(root / "emulators"), db, emu_profiles=profiles
            )
            entry = next(e for e in found if e["name"] == "collide.rom")
            return bool(entry["in_repo"])
        finally:
            common._emulator_profiles_cache.clear()
            tmp.cleanup()

    def test_a_digest_mode_does_not_call_a_contradicted_copy_available(self):
        self.assertFalse(
            self._in_repo("md5"),
            "the builder drops this file, so the report must not count it",
        )

    def test_existence_mode_still_counts_it(self):
        """The frontend never opens the file, so the pack carries it."""
        self.assertTrue(self._in_repo("existence"))

    def test_the_two_modes_answer_the_way_the_shared_predicate_says(self):
        for mode in nativemode.MODES:
            with self.subTest(mode=mode):
                self.assertEqual(
                    self._in_repo(mode),
                    not nativemode.hash_mismatch_excludes_file(mode),
                )


if __name__ == "__main__":
    unittest.main()
