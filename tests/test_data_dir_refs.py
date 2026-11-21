"""Every data_directories ref names a registered data directory.

yaps2 referenced yaps2-resources, absent from _data_dirs.yml: the pack and
verify only said "not cached" and refresh_data_dirs had nothing to fetch.
"""

from __future__ import annotations

import tests

import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


class DataDirRefsAreRegistered(unittest.TestCase):
    def test_no_unknown_ref(self):
        try:
            from schemas import sourcetree
        except ImportError as exc:
            self.skipTest(f"validate_schemas needs jsonschema: {exc}")
        self.assertEqual(sourcetree.unknown_data_dir_refs(), [])



class EachSourceIsParsedOnce(unittest.TestCase):
    """The schema pass, the data directory refs and the layout check each
    parsed every profile again: 2,038 parses for about 690 files."""

    def test_three_checks_one_parse(self):
        import tempfile
        from unittest import mock

        try:
            from schemas import sources, sourcetree
        except ImportError as exc:
            self.skipTest(f"validate_schemas needs jsonschema: {exc}")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "emulators").mkdir()
            (root / "platforms").mkdir()
            (root / "platforms" / "_data_dirs.yml").write_text("data_directories: {}\n")
            (root / "emulators" / "core.yml").write_text(
                "emulator: Core\nfiles:\n- name: a.bin\n  path: .variants/a.bin\n")
            loaded = []
            real = sources.yaml_load
            with mock.patch("core.paths.REPO_ROOT", root), \
                    mock.patch.object(sources, "yaml_load",
                                      side_effect=lambda h: loaded.append(h.name) or real(h)):
                sourcetree.validate_yaml_directory(root / "emulators", "emulator.schema.json")
                sourcetree.unknown_data_dir_refs()
                layout = sourcetree.repository_layout_in_profiles()
        # _data_dirs.yml is read by model.registry.load_data_dir_registry, so
        # only the profile passes through the schema checks' own loader.
        self.assertEqual(sorted(Path(n).name for n in loaded), ["core.yml"])
        self.assertEqual(len(layout), 1)

if __name__ == "__main__":
    unittest.main()
