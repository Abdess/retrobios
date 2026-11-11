"""Schema-invalid synthetic manifests must not crash semantic validation."""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

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
            api = root / "website" / "public" / "api" / "v1"
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
        self.assertIn("website/public/api/v1/catalog.json", text)
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

    def test_an_emulator_folder_omission_is_keyed_by_its_cores(self):
        """mame2015 and mame2016 read 3dobios.zip each in its own folder:
        two omissions, two places. The same core twice is one place."""
        path = REPO_ROOT / "install" / "synthetic.json"

        def omission(core: str) -> dict:
            return {"dest": "3dobios.zip", "root": "emulator", "cores": [core]}

        def errors(omitted: list[dict]) -> list[str]:
            manifest = {"files": [], "total_files": 0, "total_size": 0,
                        "omitted_files": omitted, "total_omitted": len(omitted)}
            return [e for e in validate_schemas._semantic_install_checks(path, manifest)
                    if "omitted destinations" in e]

        self.assertEqual(errors([omission("mame2015"), omission("mame2016")]), [])
        self.assertEqual(len(errors([omission("mame2015"), omission("mame2015")])), 1)
        self.assertEqual(len(errors([{"dest": "a.bin"}, {"dest": "a.bin"}])), 1)


try:
    import jsonschema
except ImportError:
    jsonschema = None


@unittest.skipIf(jsonschema is None, "jsonschema unavailable")
class DataRootIsKeyedBySystem(unittest.TestCase):
    """AetherSX2 gave Android/data/xyz.aethersx2.android only in its notes:
    the site could not print the folder, nor which OS tabs apply."""

    def _errors(self, value):
        schema = json.loads((REPO_ROOT / "schemas/emulator.schema.json").read_text(encoding="utf-8"))
        validator = jsonschema.Draft202012Validator(schema["properties"]["data_root"])
        return list(validator.iter_errors(value))

    def test_a_system_with_its_path_and_reference(self):
        self.assertEqual(self._errors({"android": {
            "path": "Android/data/xyz.aethersx2.android/files", "source_ref": "a.kt:1"}}), [])

    def test_an_unknown_system_or_a_path_without_reference(self):
        self.assertTrue(self._errors({"amiga": {"path": "x", "source_ref": "y"}}))
        self.assertTrue(self._errors({"windows": {"path": "%APPDATA%/X"}}))
        self.assertTrue(self._errors({}))


class WithoutJsonschema(unittest.TestCase):
    """The documented command stopped on a bare ImportError traceback that
    named neither the install nor the format-nongpl extra."""

    def test_the_command_names_the_install(self):
        import os
        import subprocess

        scratch = REPO_ROOT / "tmp" / "tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            stub = Path(directory) / "jsonschema"
            stub.mkdir()
            (stub / "__init__.py").write_text(
                'raise ImportError("No module named jsonschema")\n', encoding="utf-8"
            )
            env = {**os.environ, "PYTHONPATH": directory}
            proc = subprocess.run(
                [sys.executable, "scripts/validate_schemas.py", "--source-only"],
                capture_output=True, text=True, check=False, cwd=REPO_ROOT, env=env,
            )
        self.assertEqual(proc.returncode, 1)
        self.assertNotIn("Traceback", proc.stderr)
        self.assertIn('pip install "jsonschema[format-nongpl]"', proc.stderr)


if __name__ == "__main__":
    unittest.main()
