"""Every data_directories ref names a registered data directory.

yaps2 referenced yaps2-resources, absent from _data_dirs.yml: the pack and
verify only said "not cached" and refresh_data_dirs had nothing to fetch.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))


class DataDirRefsAreRegistered(unittest.TestCase):
    def test_no_unknown_ref(self):
        try:
            import validate_schemas
        except ImportError as exc:
            self.skipTest(f"validate_schemas needs jsonschema: {exc}")
        self.assertEqual(validate_schemas._unknown_data_dir_refs(), [])



class EachSourceIsParsedOnce(unittest.TestCase):
    """The schema pass, the data directory refs and the layout check each
    parsed every profile again: 2,038 parses for about 690 files."""

    def test_three_checks_one_parse(self):
        import tempfile
        from unittest import mock

        try:
            import validate_schemas
        except ImportError as exc:
            self.skipTest(f"validate_schemas needs jsonschema: {exc}")
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            root = Path(tmp)
            (root / "emulators").mkdir()
            (root / "platforms").mkdir()
            (root / "platforms" / "_data_dirs.yml").write_text("data_directories: {}\n")
            (root / "emulators" / "core.yml").write_text(
                "emulator: Core\nfiles:\n- name: a.bin\n  path: .variants/a.bin\n")
            loaded = []
            real = validate_schemas.yaml_load
            with mock.patch.object(validate_schemas, "ROOT", root), \
                    mock.patch.object(validate_schemas, "yaml_load",
                                      side_effect=lambda h: loaded.append(h.name) or real(h)):
                validate_schemas._validate_yaml_directory(root / "emulators", "emulator.schema.json")
                validate_schemas._unknown_data_dir_refs()
                layout = validate_schemas._repository_layout_in_profiles()
        self.assertEqual(sorted(Path(n).name for n in loaded), ["_data_dirs.yml", "core.yml"])
        self.assertEqual(len(layout), 1)

if __name__ == "__main__":
    unittest.main()
