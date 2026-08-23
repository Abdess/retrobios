#!/usr/bin/env python3
"""What ships must satisfy the declaration that put it there.

A file reaches a pack because something asked for it: a platform's own list,
or a profile describing what a core loads. Whichever it was, the bytes shipped
have to satisfy that declaration. Two files in the collection did not, and
both were distributed for months before anyone compared them: a C128 kernal
that was two ROMs concatenated, and a Cave Story build the core would not
accept.

This is checked against the published manifests rather than the built packs,
because the manifest is what install.py fetches and it names the repository
path each entry comes from.
"""

from __future__ import annotations

import hashlib
import json
import sys
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import common  # noqa: E402
from nativemode import reads_file_contents  # noqa: E402


def _declared_digests(entry: dict) -> dict[str, set[str]]:
    """Every content value a declaration commits to, lowercased."""
    out: dict[str, set[str]] = {}
    for algo in ("md5", "sha1"):
        raw = entry.get(algo)
        values = raw if isinstance(raw, list) else [raw]
        cleaned = set()
        for value in values:
            if isinstance(value, str) and value.strip():
                # Recalbox publishes several acceptable hashes per entry.
                cleaned.update(v.strip().lower() for v in value.split(",") if v.strip())
        if cleaned:
            out[algo] = cleaned
    return out


class ShippedFilesSatisfyTheirDeclaration(unittest.TestCase):
    def setUp(self):
        self.install = ROOT / "install"
        if not self.install.is_dir() or not list(self.install.glob("*.json")):
            self.skipTest("no published manifests in install/")

    def test_every_manifest_entry_matches_its_platform_declaration(self):
        """A pinned hash and the shipped bytes must be the same file.

        Only on platforms whose frontend reads the bytes. Under an existence
        mode the code never opens the file, so an upstream hash contradicted
        by the local dump is reported and the file still ships: withholding
        it would deny the frontend something it would have loaded.

        Only entries the platform pins by hash are checkable here. An entry
        with no declared hash commits to nothing, and one whose bytes come
        from a release asset is not in the working tree to hash.
        """
        violations = []
        checked = 0
        for manifest_path in sorted(self.install.glob("*.json")):
            platform = manifest_path.stem
            try:
                config = common.load_platform_config(platform, str(ROOT / "platforms"))
            except (FileNotFoundError, KeyError):
                continue
            if not reads_file_contents(config.get("verification_mode")):
                continue
            # A destination may be declared by more than one system, bare in
            # one and hash-constrained in another; the builder lets whichever
            # resolves claim it, so any of them satisfying the bytes is enough.
            declared: dict[str, list[dict]] = {}
            for system in config.get("systems", {}).values():
                for entry in system.get("files", []):
                    dest = entry.get("destination") or entry.get("name", "")
                    if dest:
                        declared.setdefault(
                            common.sanitize_pack_path(dest), []
                        ).append(entry)

            manifest = json.loads(manifest_path.read_text())
            for shipped in manifest.get("files", []):
                entries = declared.get(
                    common.sanitize_pack_path(shipped.get("dest", "")), []
                )
                entries = [e for e in entries if not e.get("zipped_file")]
                candidates = [(e, _declared_digests(e)) for e in entries]
                candidates = [(e, w) for e, w in candidates if w]
                if not candidates:
                    continue
                repo_path = shipped.get("repo_path", "")
                if not repo_path:
                    continue
                blob_path = ROOT / repo_path
                if not blob_path.is_file():
                    continue
                blob = blob_path.read_bytes()
                checked += 1
                digests = {
                    algo: [hashlib.new(algo, blob).hexdigest()]
                    for algo in ("md5", "sha1")
                }
                # Recalbox pins some arcade archives by the MD5 of their
                # members rather than of the container, which is what
                # md5_composite computes and what the resolver matches on.
                # A variant carries its hash after the extension
                # (cdimono1.zip.e6714b3d), so the name is not the test.
                try:
                    digests["md5"].append(common.md5_composite(str(blob_path)))
                except (zipfile.BadZipFile, OSError):
                    pass
                # Batocera publishes 29-character prefixes, so compare by prefix.
                satisfied = any(
                    all(
                        any(
                            got.startswith(a)
                            for got in digests[algo]
                            for a in accepted
                        )
                        for algo, accepted in wanted.items()
                    )
                    for _e, wanted in candidates
                )
                if not satisfied:
                    first = candidates[0][1]
                    algo = sorted(first)[0]
                    violations.append(
                        f"{platform}: {shipped['dest']} ships {repo_path} "
                        f"with {algo} {digests[algo][0]}, declared "
                        f"{sorted(first[algo])[0]}"
                    )
        self.assertEqual(
            violations, [],
            f"{len(violations)} of {checked} pinned entries ship contradicted "
            "bytes:\n  " + "\n  ".join(violations[:12]),
        )
        self.assertGreater(checked, 200, "the check reached almost nothing")


class ProfileContradictionsAreKnown(unittest.TestCase):
    """A profile's hash and the file answering to it may legitimately differ.

    Emulators ship their own build of a shared data file: four hiscore.dat
    versions are held, and ti99sim converts its cartridges differently from
    the release Recalbox pinned. What must not happen is such a file reaching
    a pack, because there the platform's own declaration governs and is
    checked above. This test records how many profile declarations no held
    file satisfies, so the number cannot grow unnoticed.
    """

    def test_the_count_of_unsatisfied_profile_hashes_is_known(self):
        database = ROOT / "database.json"
        if not database.is_file():
            self.skipTest("database.json not built")
        db = common.load_database(str(database))
        profiles = common.load_emulator_profiles(str(ROOT / "emulators"))
        unsatisfied = []
        for name, profile in sorted(profiles.items()):
            if profile.get("type") in ("alias", "launcher"):
                continue
            for entry in profile.get("files", []):
                if not isinstance(entry, dict) or entry.get("unsourceable"):
                    continue
                if not _declared_digests(entry):
                    continue
                path, status = common.resolve_local_file(
                    entry, db, dest_hint=entry.get("path", "")
                )
                if path and status == "hash_mismatch":
                    unsatisfied.append(f"{name}/{entry.get('name','')}")
        self.assertLessEqual(
            len(unsatisfied), 20,
            "profile declarations no held file satisfies grew past the known "
            f"set ({len(unsatisfied)}):\n  " + "\n  ".join(sorted(unsatisfied)),
        )


if __name__ == "__main__":
    unittest.main()
