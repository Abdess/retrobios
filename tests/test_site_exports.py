"""Regression tests for the public website data and citation contracts."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from generate_site import (  # noqa: E402
    _admonition_body,
    _browser_title,
    _forge_sources,
    _source_ref_markdown,
    decorate_markdown_pages,
    generate_data_exports,
)


class SiteReferenceContracts(unittest.TestCase):
    def setUp(self) -> None:
        scratch = ROOT / "tmp" / "tests"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.docs = Path(self.temp.name) / "docs"
        self.docs.mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def _fixtures() -> tuple[dict, dict, dict, dict]:
        payload = b"firmware"
        sha1 = hashlib.sha1(payload).hexdigest()
        md5 = hashlib.md5(payload).hexdigest()
        sha256 = hashlib.sha256(payload).hexdigest()
        db = {
            "schema_version": 1,
            "generated_at": "2026-08-09T00:00:00Z",
            "total_files": 1,
            "total_size": len(payload),
            "files": {
                sha1: {
                    "path": "bios/Test/fw.bin",
                    "name": "fw.bin",
                    "size": len(payload),
                    "sha1": sha1,
                    "md5": md5,
                    "sha256": sha256,
                    "crc32": "0f00ba11",
                    "adler32": "0f00ba11",
                }
            },
            "indexes": {
                "by_md5": {md5: sha1},
                "by_name": {"fw.bin": [sha1]},
                "by_crc32": {"0f00ba11": sha1},
                "by_sha256": {sha256: sha1},
                "by_path_suffix": {"fw.bin": [sha1]},
            },
        }
        coverages = {
            "test": {
                "platform": "Test Platform",
                "config": {
                    "platform": "Test Platform",
                    "cores": ["testemu"],
                    "systems": {
                        "test-system": {
                            "files": [
                                {
                                    "name": "fw.bin",
                                    "destination": "fw.bin",
                                    "required": True,
                                    "sha1": sha1,
                                    "size": len(payload),
                                }
                            ]
                        }
                    },
                },
                "total": 1,
                "present": 1,
                "verified": 1,
                "untested": 0,
                "missing": 0,
                "core_present": 1,
                "core_missing": 0,
                "core_unsourceable": 0,
                "details": [],
            }
        }
        profiles = {
            "testemu": {
                "emulator": "Test Emulator",
                "type": "libretro",
                "source": "https://github.com/example/emulator",
                "source_commit": "a" * 40,
                "cores": ["testemu"],
                "systems": ["test-system"],
                "files": [
                    {
                        "name": "fw.bin",
                        "system": "test-system",
                        "required": True,
                        "source_ref": "src/firmware.cpp:10-12",
                    }
                ],
            }
        }
        stats = {
            "schema_version": 1,
            "generated_at": "2026-08-09T00:00:00Z",
            "files": 1,
            "size_bytes": len(payload),
            "platforms": 1,
            "emulators": 1,
            "systems": 1,
            "catalog_matched": 0,
            "source": "https://github.com/Abdess/retrobios",
            "downloads": "https://github.com/Abdess/retrobios/releases/tag/v2026.08.06",
            "composition": {
                "systems": {"files": 1, "size_bytes": len(payload)},
                "arcade": {"files": 0, "size_bytes": 0},
                "game_data": {"files": 0, "size_bytes": 0},
            },
        }
        return db, coverages, profiles, stats

    def test_source_references_are_revision_pinned_links(self):
        _, _, profiles, _ = self._fixtures()
        rendered = _source_ref_markdown(
            profiles["testemu"], "src/firmware.cpp:10-12"
        )
        self.assertIn("/blob/" + "a" * 40 + "/src/firmware.cpp#L10-L12", rendered)

    def test_ambiguous_two_repository_path_is_never_linked(self):
        """A path that could live in either declared repository stays plain.

        The libretro port and the original emulator are two different trees.
        Linking an unattributable path to whichever came first publishes a
        citation that resolves to nothing.
        """
        profile = {
            "source": "https://github.com/libretro/example-libretro",
            "source_commit": "a" * 40,
            "upstream": "https://gitlab.com/vendor/example",
            "upstream_commit": "b" * 40,
        }
        rendered = _source_ref_markdown(profile, "jg.c:213-214")
        self.assertEqual(rendered, "`jg.c:213-214`")
        self.assertNotIn("http", rendered)

        # A repository-name prefix removes the ambiguity, so it links again.
        prefixed = _source_ref_markdown(profile, "example/jg.c:213-214")
        self.assertIn("gitlab.com/vendor/example/-/blob/" + "b" * 40 + "/jg.c", prefixed)

    def test_preprocessor_tokens_cannot_become_page_headings(self):
        rendered = _admonition_body("First paragraph.\n\n#if FEATURE\nEnabled")
        self.assertIn("\\#if FEATURE", rendered)
        self.assertNotIn("\n    #if FEATURE", rendered)

    def test_browser_titles_distinguish_emulators_from_system_pages(self):
        self.assertEqual(
            _browser_title(Path("emulators/qemu.md"), "QEMU"),
            "QEMU emulator firmware",
        )
        self.assertEqual(
            _browser_title(Path("systems/qemu.md"), "QEMU"),
            "QEMU systems",
        )

    def test_exports_have_catalog_hashes_and_queryable_sqlite(self):
        db, coverages, profiles, stats = self._fixtures()
        exports = generate_data_exports(
            self.docs, db, coverages, profiles, stats
        )
        catalog = json.loads((self.docs / "api/v1/catalog.json").read_text())
        self.assertEqual(catalog["count"], len(exports))
        for item in catalog["items"]:
            path = self.docs / item["url"]
            self.assertTrue(path.is_file())
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), item["sha256"])

        with sqlite3.connect(self.docs / "downloads/retrobios.sqlite") as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM files").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT count(*) FROM platforms").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT count(*) FROM emulators").fetchone()[0], 1)

    def test_page_metadata_is_specific_and_idempotent(self):
        page = self.docs / "gaps.md"
        page.write_text("# Gap Analysis - RetroBIOS\n\nCurrent unresolved entries.\n")
        decorate_markdown_pages(self.docs)
        decorate_markdown_pages(self.docs)
        content = page.read_text()
        self.assertEqual(content.count('type="application/ld+json"'), 1)
        self.assertIn("Current RetroBIOS verification gaps", content)
        self.assertIn('"@type":"TechArticle"', content)


class PerModeSourcePins(unittest.TestCase):
    """A profile whose builds live in separate repositories.

    `source`, `upstream` and `source_commit` may each be keyed by build mode.
    Reading the URL from one mode and the revision from another produces a
    permalink into a tree that never held that line, and binding the object
    form straight into SQLite fails outright.
    """

    PROFILE = {
        "emulator": "twobuilds",
        "source": {
            "standalone": "https://github.com/vendor/emu",
            "libretro": "https://github.com/porter/emu-libretro",
        },
        "upstream": "https://github.com/vendor/emu",
        "source_commit": {"standalone": "a" * 40, "libretro": "b" * 40},
    }

    def test_each_repository_keeps_its_own_revision(self):
        pairs = {
            (repo.slug, pin) for repo, pin in _forge_sources(self.PROFILE)
        }
        self.assertIn(("vendor/emu", "a" * 40), pairs)
        self.assertIn(("porter/emu-libretro", "b" * 40), pairs)
        # The libretro fork must never be pinned to the standalone revision.
        self.assertNotIn(("porter/emu-libretro", "a" * 40), pairs)
        self.assertNotIn(("vendor/emu", "b" * 40), pairs)

    def test_a_build_mode_label_is_resolved_first(self):
        repo, pin = _forge_sources(self.PROFILE, "libretro")[0]
        self.assertEqual((repo.slug, pin), ("porter/emu-libretro", "b" * 40))

    def test_the_plain_string_form_is_unchanged(self):
        profile = {
            "source": "https://github.com/vendor/emu",
            "source_commit": "c" * 40,
        }
        self.assertEqual(
            [(repo.slug, pin) for repo, pin in _forge_sources(profile)],
            [("vendor/emu", "c" * 40)],
        )

    def test_sqlite_export_accepts_a_per_mode_commit(self):
        from generate_site import _json_text

        self.assertEqual(
            _json_text(self.PROFILE["source_commit"]),
            '{"libretro": "' + "b" * 40 + '", "standalone": "' + "a" * 40 + '"}',
        )
        self.assertEqual(_json_text("c" * 40), "c" * 40)


if __name__ == "__main__":
    unittest.main()
