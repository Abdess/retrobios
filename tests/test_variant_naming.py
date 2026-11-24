"""A .variants/ copy is named <name>.<first 8 hex digits of its md5>.

Four forms had grown side by side: the md5 prefix the docs named, the sha1
prefix validate_pr wrote, a crc32, no suffix at all, and hiscore_<sha1>.dat.
A name cut from another digest cannot be checked against the bytes, and a
copy with no suffix collides with the next revision of the same name.
Reads the repository: skips outside a git checkout.
"""

from __future__ import annotations

import tests

import hashlib
import re
import subprocess
import unittest
from pathlib import Path

from resolve.lookup import variant_base_name

REPO_ROOT = Path(__file__).resolve().parents[1]
TAG = re.compile(r"\.([0-9a-f]{8})$")


def misnamed(path: Path, data: bytes) -> str | None:
    """Why *path*, a .variants/ copy holding *data*, breaks the rule, or None."""
    tag = TAG.search(path.name)
    if tag is None:
        return "no md5 suffix"
    if tag.group(1) != hashlib.md5(data).hexdigest()[:8]:
        return f"suffix {tag.group(1)} is not the md5 prefix"
    if not variant_base_name(path.name):
        return "no name before the suffix"
    return None


class VariantNameRule(unittest.TestCase):
    def test_the_rule(self):
        data = b"revision"
        good = f"rom.bin.{hashlib.md5(data).hexdigest()[:8]}"
        self.assertIsNone(misnamed(Path(good), data))
        self.assertEqual(misnamed(Path("rom.bin"), data), "no md5 suffix")
        sha1_tag = f"rom.bin.{hashlib.sha1(data).hexdigest()[:8]}"
        self.assertIn("not the md5 prefix", misnamed(Path(sha1_tag), data))
        self.assertEqual(misnamed(Path("hiscore_2be55274.dat"), data), "no md5 suffix")


class TrackedVariantsFollowTheRule(unittest.TestCase):
    def test_every_tracked_variant(self):
        if not (REPO_ROOT / ".git").exists():
            self.skipTest("not a git checkout")
        out = subprocess.run(
            ["git", "ls-files", "-z", "bios"], cwd=REPO_ROOT,
            capture_output=True, check=True,
        ).stdout.decode()
        variants = [p for p in out.split("\0") if "/.variants/" in p]
        if not variants:
            self.skipTest("bios/ not present")
        wrong = {}
        for rel in variants:
            path = REPO_ROOT / rel
            if not path.is_file():
                continue
            reason = misnamed(path, path.read_bytes())
            if reason:
                wrong[rel] = reason
        self.assertEqual(wrong, {})


if __name__ == "__main__":
    unittest.main()
