"""Schema-invalid synthetic manifests must not crash semantic validation."""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

try:
    import validate_schemas
except ImportError as exc:
    validate_schemas = None
    IMPORT_ERROR = str(exc)
else:
    IMPORT_ERROR = ""


@unittest.skipIf(validate_schemas is None, f"validate_schemas unavailable: {IMPORT_ERROR}")
class SemanticManifestValidation(unittest.TestCase):
    def test_invalid_synthetic_manifest_reports_schema_errors_without_crashing(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as directory:
            root = Path(directory)
            (root / "emulators").mkdir()
            platforms = root / "platforms"
            platforms.mkdir()
            (platforms / "_data_dirs.yml").write_text(
                "data_directories: {}\n", encoding="utf-8"
            )
            (root / "database.json").write_text(
                json.dumps({"files": None}), encoding="utf-8"
            )
            install = root / "install"
            install.mkdir()
            (install / "synthetic.json").write_text(
                json.dumps({"files": None}), encoding="utf-8"
            )
            api = root / "docs" / "api" / "v1"
            api.mkdir(parents=True)
            (api / "catalog.json").write_text(
                json.dumps({"count": 1, "items": None}), encoding="utf-8"
            )

            output = io.StringIO()
            with mock.patch.object(validate_schemas, "ROOT", root), mock.patch.object(
                sys, "argv", ["validate_schemas.py"]
            ), redirect_stdout(output):
                result = validate_schemas.main()

        self.assertEqual(result, 1)
        text = output.getvalue().replace("\\", "/")
        self.assertIn("database.json", text)
        self.assertIn("install/synthetic.json", text)
        self.assertIn("docs/api/v1/catalog.json", text)
        self.assertIn("files", text)
        self.assertIn("items", text)
        self.assertNotIn("Traceback", text)

    def test_valid_synthetic_manifest_still_runs_semantic_checks(self):
        manifest = {
            "manifest_version": 2,
            "source": "full",
            "regions": [],
            "platform": "synthetic",
            "display_name": "Synthetic",
            "version": "test",
            "generated": "2026-10-21T00:00:00Z",
            "base_destination": "",
            "detect": [],
            "standalone_copies": [],
            "total_files": 1,
            "total_size": 0,
            "total_omitted": 0,
            "omitted_files": [],
            "files": [],
        }
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as directory:
            path = Path(directory) / "synthetic.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            errors = validate_schemas._validate_json_files(
                [path],
                "install-manifest.schema.json",
                validate_schemas._semantic_install_checks,
            )

        self.assertEqual(len(errors), 1)
        self.assertIn("total_files does not equal len(files)", errors[0])


if __name__ == "__main__":
    unittest.main()
