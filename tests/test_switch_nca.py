from __future__ import annotations

import tests

import hashlib
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
BIOS_ROOT = REPO_ROOT / "bios"


def misnamed_ncas(root: Path) -> list[str]:
    """NCAs whose name is not the first 16 bytes of their SHA-256.

    A Switch content archive is named after its own digest, and the
    yuzu-family firmware install compares the two before copying
    (src/frontend_common/content_manager.h:262-331 in Eden). A dump that
    fails it is refused there, so the collection holds none.
    """
    bad: list[str] = []
    for path in sorted(root.rglob("registered/*.nca")):
        digest = hashlib.sha256()
        with path.open("rb") as f:
            for block in iter(lambda: f.read(1 << 20), b""):
                digest.update(block)
        if digest.hexdigest()[:32] != path.name.split(".", 1)[0].lower():
            bad.append(str(path.relative_to(root)))
    return bad


class SwitchNcaNames(unittest.TestCase):
    def test_a_renamed_nca_is_named(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            folder = Path(scratch) / "registered"
            folder.mkdir()
            good = hashlib.sha256(b"nca").hexdigest()[:32]
            (folder / f"{good}.cnmt.nca").write_bytes(b"nca")
            (folder / f"{'0' * 32}.nca").write_bytes(b"nca")
            self.assertEqual(misnamed_ncas(Path(scratch)), [f"registered/{'0' * 32}.nca"])

    def test_every_held_nca_carries_its_digest(self) -> None:
        if not any(BIOS_ROOT.rglob("registered/*.nca")):
            self.skipTest("no NCA in bios/")
        self.assertEqual(misnamed_ncas(BIOS_ROOT), [])


if __name__ == "__main__":
    unittest.main()
