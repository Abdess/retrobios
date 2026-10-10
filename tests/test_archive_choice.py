"""An archive declared once per member ships as the copy holding them all.

Batocera checks adam_fdc.zip through eight zipped_file declarations. The
first hash-exact answer was a one-member MAME set, so the pack shipped it and
seven of the eight members Batocera checks were missing.
"""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import unittest
import zipfile
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


if __name__ == "__main__":
    unittest.main()
