"""Generated artifacts are written whole or not at all.

write_if_changed got the scratch-and-rename treatment, but the install
manifests, the target manifests and release.json were still truncated at
their final name, and restore_large_files copied an asset straight to its
path in bios/: a scan running beside the copy hashed the truncated file.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import artifacts  # noqa: E402


class WholeOrNothing(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_an_interrupted_write_keeps_the_previous_file(self):
        target = self.dir / "manifest.json"
        target.write_text("{}")
        with mock.patch("os.replace", side_effect=OSError("cut")), self.assertRaises(OSError):
            artifacts.write_text_atomic(str(target), "{\"files\": []}")
        self.assertEqual(target.read_text(), "{}")
        self.assertEqual(os.listdir(self.dir), ["manifest.json"])

    def test_an_interrupted_copy_leaves_no_file(self):
        source = self.dir / "asset.bin"
        source.write_bytes(b"x" * 1000)
        target = self.dir / "bios" / "asset.bin"
        target.parent.mkdir()
        with mock.patch("shutil.copy2", side_effect=OSError("cut")), self.assertRaises(OSError):
            artifacts.copy_file_atomic(str(source), str(target))
        self.assertEqual(os.listdir(target.parent), [])


class EveryWriterGoesThroughIt(unittest.TestCase):
    def test_manifests_record_and_restore_use_the_atomic_helpers(self):
        scripts = REPO_ROOT / "scripts"
        for name, helper in (
            ("generate_pack.py", "write_text_atomic("),
            ("release_record.py", "write_text_atomic("),
            ("restore_large_files.py", "copy_file_atomic("),
        ):
            source = (scripts / name).read_text(encoding="utf-8")
            with self.subTest(script=name):
                self.assertIn(helper, source)
        pack = (scripts / "generate_pack.py").read_text(encoding="utf-8")
        self.assertNotIn('with open(path, "w") as f:\n        f.write(new_json)', pack)
        self.assertNotIn("json.dump(result, f", pack)
        self.assertNotIn("args.output.write_text(", (scripts / "release_record.py").read_text())
        self.assertNotIn("shutil.copy2(source, path)", (scripts / "restore_large_files.py").read_text())


    def test_scrapers_write_whole_files(self):
        """A streamed yaml.dump into platforms/<x>.yml let a concurrent reader
        parse a valid platform holding a fraction of its systems."""
        import re

        streamed = re.compile(
            r"open\([^)]*['\"](?:w|wb|a)['\"]|\.write_text\(|\.write_bytes\("
        )
        offenders = [
            f"{path.relative_to(REPO_ROOT)}:{number}"
            for path in sorted((REPO_ROOT / "scripts" / "scraper").rglob("*.py"))
            for number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), 1
            )
            if streamed.search(line)
        ]
        self.assertEqual(offenders, [])

    def test_generators_publish_whole_files(self):
        """install/games/ (12 MB, read by install.py --for-games), the event
        schema, the launcher index and wiki/installer.md were truncated at
        their final name: an interrupted run left a committed-looking file
        holding part of a JSON document. The installer doc's sandbox writes
        throwaway fixtures under tmp/ and is not published."""
        import ast

        sandbox = {"write_small_list", "Sandbox"}
        offenders = []
        for path in sorted((REPO_ROOT / "scripts").glob("generate_*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for top in tree.body:
                if path.name == "generate_installer_doc.py" and getattr(top, "name", "") in sandbox:
                    continue
                for node in ast.walk(top):
                    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                            and node.func.attr in ("write_text", "write_bytes")):
                        offenders.append(f"{path.name}:{node.lineno}")
        self.assertEqual(offenders, [])

    def test_the_text_is_utf8_whatever_the_locale(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "out.yml"
            artifacts.write_text_atomic(str(target), "name: \u00e9mulateur \u2014 \u30d5\n")
            self.assertEqual(
                target.read_bytes().decode("utf-8"), "name: \u00e9mulateur \u2014 \u30d5\n"
            )


class TheNativeIndexKeepsEveryPlatform(unittest.TestCase):
    """Native originals refresh platform by platform, in parallel. Each run
    rewrote the whole URL index it had read before downloading, and the last
    writer erased the others' entries."""

    def test_an_entry_recorded_during_a_download_survives(self):
        import io
        import json

        import export_native

        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as directory:
            root = Path(directory)
            index = root / export_native.SOURCES_INDEX

            class Response(io.BytesIO):
                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

            def other_run_records_meanwhile(request, timeout):
                index.write_text(json.dumps({"retrobat/file.json": "https://b"}))
                return Response(b"payload")

            with mock.patch.object(
                export_native.urllib.request, "urlopen", other_run_records_meanwhile
            ):
                export_native.fetch("https://a", root / "batocera" / "file", index)
            recorded = json.loads(index.read_text())
            self.assertEqual(recorded.get("retrobat/file.json"), "https://b")
            self.assertEqual(recorded.get("batocera/file"), "https://a")
            self.assertEqual((root / "batocera" / "file").read_bytes(), b"payload")

class ScratchFilesGetThePlainMode(unittest.TestCase):
    """mkstemp makes its file 0600 and the rename kept it: database.json,
    the manifests and the packs came out readable by their owner only."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        previous = os.umask(0o022)
        self.addCleanup(os.umask, previous)

    def _mode(self, path: Path) -> int:
        return path.stat().st_mode & 0o777

    def test_text_and_bytes_writers(self):
        artifacts.write_text_atomic(str(self.dir / "a.json"), "{}")
        artifacts.write_bytes_atomic(str(self.dir / "b.bin"), b"x")
        self.assertEqual(self._mode(self.dir / "a.json"), 0o644)
        self.assertEqual(self._mode(self.dir / "b.bin"), 0o644)

    def test_the_umask_decides(self):
        os.umask(0o002)
        artifacts.write_text_atomic(str(self.dir / "a.json"), "{}")
        self.assertEqual(self._mode(self.dir / "a.json"), 0o664)

    def test_threads_reading_the_mode_leave_the_umask_alone(self):
        """mame_devices fetches on eight threads and every cache write reads
        the umask: unguarded, two readers interleaved and left it at 0."""
        import threading  # noqa: PLC0415

        interval = sys.getswitchinterval()
        sys.setswitchinterval(1e-6)
        self.addCleanup(sys.setswitchinterval, interval)
        modes: set[int] = set()

        def read() -> None:
            seen = {artifacts.plain_file_mode() for _ in range(20000)}
            modes.update(seen)

        threads = [threading.Thread(target=read) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        current = os.umask(0o022)
        self.assertEqual(current, 0o022)
        self.assertEqual(modes, {0o644})

    def test_no_script_reads_the_umask_unguarded(self):
        offenders = [
            f"{path.name}:{number}"
            for path in sorted((REPO_ROOT / "scripts").rglob("*.py"))
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
            if "os.umask(" in line and path.name != "artifacts.py"
        ]
        self.assertEqual(offenders, [])

    def test_packs_and_their_manifest(self):
        import zipfile  # noqa: PLC0415

        import generate_pack  # noqa: PLC0415

        pack = self.dir / "Pack.zip"
        with generate_pack._writing_pack(str(pack)) as zf:
            zf.writestr("a.bin", b"x")
        self.assertEqual(self._mode(pack), 0o644)
        os.chmod(pack, 0o600)
        generate_pack.inject_manifest(str(pack), {"files": []})
        self.assertEqual(self._mode(pack), 0o644)
        with zipfile.ZipFile(pack) as zf:
            self.assertIn("manifest.json", zf.namelist())

    def test_every_renamed_scratch_gets_the_mode(self):
        """A function that renames a mkstemp file into place sets its mode.

        copy_file_atomic is the one exception: copy2 gives the scratch the
        source file's own mode.
        """
        import ast  # noqa: PLC0415

        def name_of(node: ast.AST) -> str | None:
            return node.id if isinstance(node, ast.Name) else None

        def callee(call: ast.Call) -> str:
            func = call.func
            return func.attr if isinstance(func, ast.Attribute) else name_of(func) or ""

        unset = []
        for path in sorted((REPO_ROOT / "scripts").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for func in ast.walk(tree):
                if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if func.name == "copy_file_atomic":
                    continue
                scratches: set[str] = set()
                for node in ast.walk(func):
                    if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
                            and callee(node.value) == "mkstemp"
                            and isinstance(node.targets[0], ast.Tuple)):
                        scratch = name_of(node.targets[0].elts[1])
                        if scratch:
                            scratches.add(scratch)
                calls = [n for n in ast.walk(func) if isinstance(n, ast.Call)]
                moded = {
                    name_of(c.args[0]) for c in calls
                    if callee(c) in ("set_plain_mode", "chmod") and c.args
                }
                for call in calls:
                    if callee(call) != "replace" or not call.args:
                        continue
                    first = name_of(call.args[0])
                    if first in scratches and first not in moded:
                        unset.append(f"{path.name}:{call.lineno} {func.name}")
        self.assertEqual(unset, [])



class RestoreSkipsDownloadsInProgress(unittest.TestCase):
    """A scratch file another run is still writing is neither hashed nor read."""

    def test_a_scratch_promoted_mid_scan_does_not_stop_the_restore(self) -> None:
        import restore_large_files

        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp)
            (cache / "done.bin").write_bytes(b"whole")
            scratch = cache / "big.bin.ab12.tmp"
            scratch.write_bytes(b"part")
            real_isfile = os.path.isfile

            def check_then_promote(path: str) -> bool:
                found = real_isfile(path)
                # The concurrent fetch renames its scratch file right after
                # the check, before the open.
                if path == str(scratch) and found:
                    os.replace(scratch, cache / "big.bin")
                return found

            with mock.patch.object(restore_large_files.os.path, "isfile",
                                   side_effect=check_then_promote):
                index = restore_large_files.index_cache(str(cache))
            self.assertNotIn(str(scratch), index.values())
            self.assertIn(str(cache / "done.bin"), index.values())


class ATerminatedBuildLeavesNoScratch(unittest.TestCase):
    """`timeout 120 generate_pack.py --platform RetroArch` left a 3.4 GB
    hidden .partial in dist/: SIGTERM ended the process without running the
    cleanup a failed write runs."""

    CHILD = (
        "import sys, time\n"
        "sys.path.insert(0, 'scripts')\n"
        "from common import run_cli\n"
        "from generate_pack import _writing_pack\n"
        "def main():\n"
        "    with _writing_pack(sys.argv[1]) as zf:\n"
        "        zf.writestr('a.bin', b'x')\n"
        "        print('writing', flush=True)\n"
        "        time.sleep(60)\n"
        "run_cli(main)\n"
    )

    def test_sigterm_removes_the_partial_pack(self):
        import signal  # noqa: PLC0415
        import subprocess  # noqa: PLC0415

        if not hasattr(signal, "SIGTERM") or os.name != "posix":
            self.skipTest("POSIX signals")
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            pack = Path(tmp) / "Demo_BIOS_Pack.zip"
            child = subprocess.Popen(
                [sys.executable, "-c", self.CHILD, str(pack)], cwd=REPO_ROOT,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            self.assertEqual(child.stdout.readline().strip(), "writing")
            self.assertTrue(list(Path(tmp).glob(".*.partial")))
            child.send_signal(signal.SIGTERM)
            child.communicate(timeout=60)
            self.assertEqual(child.returncode, 128 + signal.SIGTERM)
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
