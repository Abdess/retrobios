"""The pack and the install manifest place the same bytes at a destination.

The builder replaced a file an emulator rejects by a held variant both
accept; the manifest kept the first resolution. install.py then placed the
PS2 ROM2.BIN at galaksija/ROM2.BIN where the pack carried the Galaksija ROM,
across 14 destinations on six platforms.
"""

from __future__ import annotations

import ast
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from validation import (  # noqa: E402
    _build_validation_index,
    destination_owners,
    validated_choice,
)


class ValidatedChoice(unittest.TestCase):
    def test_a_rejected_file_gives_way_to_an_accepted_variant(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            wrong = Path(tmp) / "ps2" / "ROM2.BIN"
            right = Path(tmp) / "galaksija" / "ROM2.BIN"
            wrong.parent.mkdir()
            right.parent.mkdir()
            wrong.write_bytes(b"p" * 64)
            right.write_bytes(b"g" * 4096)
            db = {
                "files": {
                    hashlib.sha1(p.read_bytes()).hexdigest(): {
                        "path": str(p),
                        "name": "ROM2.BIN",
                        "size": p.stat().st_size,
                        "md5": hashlib.md5(p.read_bytes()).hexdigest(),
                    }
                    for p in (wrong, right)
                },
                "indexes": {"by_name": {}, "by_md5": {}},
            }
            db["indexes"]["by_name"]["ROM2.BIN"] = list(db["files"])
            index = _build_validation_index({
                "galaksija": {
                    "emulator": "galaksija",
                    "files": [{"name": "ROM2.BIN", "size": 4096, "validation": ["size"]}],
                }
            })
            chosen, disagreement = validated_choice(
                {"name": "ROM2.BIN"}, str(wrong), db, index, tmp, None
            )
            self.assertEqual(chosen, str(right))
            self.assertIsNone(disagreement)

    def test_a_destination_another_emulator_owns_is_not_judged(self):
        """ZEsarUX's 48 KB cpc6128.rom check gave ep128emu the composite image."""
        profiles = {
            "zesarux": {"files": [
                {"name": "cpc6128.rom", "size": 49152, "validation": ["size"]},
            ]},
            "ep128emu": {"files": [
                {"name": "cpc6128.rom", "path": "ep128emu/roms/cpc6128.rom"},
            ]},
        }
        index = _build_validation_index(profiles)
        owners = destination_owners(profiles)
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            rom = Path(tmp) / "cpc6128.rom"
            rom.write_bytes(b"c" * 32768)
            db = {"files": {}, "indexes": {"by_name": {}, "by_md5": {}}}
            for destination, judged in (
                ("ep128emu/roms/cpc6128.rom", False),
                ("cpc6128.rom", True),
            ):
                with self.subTest(destination=destination):
                    _chosen, disagreement = validated_choice(
                        {"name": "cpc6128.rom"}, str(rom), db, index, tmp, None,
                        destination, owners,
                    )
                    self.assertEqual(disagreement is not None, judged)

    def test_pack_and_manifest_both_read_it(self):
        tree = ast.parse((REPO_ROOT / "scripts" / "generate_pack.py").read_text(encoding="utf-8"))
        callers = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
            and any(
                isinstance(call, ast.Call) and getattr(call.func, "id", None) == "validated_choice"
                for call in ast.walk(node)
            )
        }
        self.assertLessEqual({"generate_pack", "generate_manifest"}, callers)


if __name__ == "__main__":
    unittest.main()
