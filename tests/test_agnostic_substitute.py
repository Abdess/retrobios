"""Pack, verify and manifest answer the same way for a filename-agnostic core.

The pack alone renamed any PS2 image into a missing slot, even on an md5
platform whose frontend then rejects it, and counted it OK; verify called
the slot missing and the manifest omitted it.
"""

from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from validation import agnostic_substitute  # noqa: E402


class AgnosticSubstitute(unittest.TestCase):
    def test_only_the_platform_cores_answer(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            held = Path(tmp) / "ps2" / "scph39001.bin"
            held.parent.mkdir()
            held.write_bytes(b"x" * 16)
            db = {
                "files": {"a": {"path": str(held), "name": "scph39001.bin", "size": 16}},
                "indexes": {"by_name": {"scph39001.bin": ["a"]}},
            }
            agnostic = {
                "bios_mode": "agnostic",
                "systems": ["sony-playstation-2"],
                "files": [{"name": "scph39001.bin", "min_size": 8}],
            }
            self.assertEqual(
                agnostic_substitute({}, "sony-playstation-2", db, {"pcsx2": agnostic}),
                (str(held), f"{held.parent}/"),
            )
            self.assertIsNone(agnostic_substitute({}, "sony-playstation-2", db, {}))
            self.assertIsNone(agnostic_substitute({}, "nintendo-nes", db, {"pcsx2": agnostic}))
            self.assertIsNone(
                agnostic_substitute({"md5": "0" * 32}, "sony-playstation-2", db, {"pcsx2": agnostic})
            )

    def test_every_reader_calls_it_behind_the_existence_gate(self):
        builder = (REPO_ROOT / "scripts" / "generate_pack.py").read_text(encoding="utf-8")
        verify = (REPO_ROOT / "scripts" / "verify.py").read_text(encoding="utf-8")
        self.assertEqual(builder.count("agnostic_substitute(file_entry, sys_id"), 2)
        self.assertEqual(verify.count("agnostic_substitute(file_entry, sys_id"), 1)
        for source in (builder, verify):
            for call in re.finditer(r"agnostic_substitute\(file_entry, sys_id", source):
                window = source[max(0, call.start() - 300):call.start()]
                self.assertIn("reads_file_contents", window)
        self.assertNotIn('_emu_prof.get("bios_mode")', builder)


if __name__ == "__main__":
    unittest.main()
