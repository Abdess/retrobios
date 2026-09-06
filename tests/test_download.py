"""Tests for the release pack downloaders.

Packs over 2 GB are published as numbered volumes (`.zip.001`, `.zip.002`),
so a downloader that expects one asset per platform finds nothing for most
of them. These tests pin the grouping, the join and the staging location.
"""
from __future__ import annotations

import functools
import hashlib
import http.server
import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "download", REPO_ROOT / "scripts" / "download.py"
)
download = importlib.util.module_from_spec(_spec)
# Registered before execution: a dataclass resolves its annotations through
# sys.modules and cannot be built from a module that is not there yet.
sys.modules["download"] = download
_spec.loader.exec_module(download)

SHELL = REPO_ROOT / "scripts" / "download.sh"

# A slice of a real release: two whole packs, three split, and the checksums.
RELEASE_ASSETS = [
    "Batocera_43.1_BIOS_Pack.zip.001",
    "Batocera_43.1_BIOS_Pack.zip.002",
    "BizHawk_2.11.1_BIOS_Pack.zip",
    "EmuDeck_2.3.8_BIOS_Pack.zip",
    "RetroArch_Lakka_v1.22.2_BIOS_Pack.zip.001",
    "RetroArch_Lakka_v1.22.2_BIOS_Pack.zip.002",
    "RetroDECK_0.10.9b_BIOS_Pack.zip.001",
    "RetroDECK_0.10.9b_BIOS_Pack.zip.002",
    "RetroDECK_0.10.9b_BIOS_Pack.zip.003",
    "SHA256SUMS.txt",
]


def _closed_port() -> int:
    """A loopback port nothing listens on, so connecting is refused at once."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):  # keep the test output pristine
        pass


def _release(names, base="https://example.invalid", size=10):
    return {
        "assets": [
            {
                "name": name,
                "size": size,
                "browser_download_url": f"{base}/assets/{name}",
            }
            for name in names
        ]
    }


class TestPackGrouping(unittest.TestCase):
    def test_whole_pack_has_one_part(self):
        packs = download.group_packs(_release(["EmuDeck_2.3.8_BIOS_Pack.zip"]))
        self.assertEqual([p.name for p in packs], ["EmuDeck_2.3.8_BIOS_Pack.zip"])
        self.assertEqual(len(packs[0].parts), 1)

    def test_volumes_group_into_one_pack(self):
        packs = download.group_packs(
            _release(
                [
                    "Batocera_43.1_BIOS_Pack.zip.001",
                    "Batocera_43.1_BIOS_Pack.zip.002",
                ]
            )
        )
        self.assertEqual([p.name for p in packs], ["Batocera_43.1_BIOS_Pack.zip"])
        self.assertEqual(
            [part["name"] for part in packs[0].parts],
            [
                "Batocera_43.1_BIOS_Pack.zip.001",
                "Batocera_43.1_BIOS_Pack.zip.002",
            ],
        )

    def test_pack_size_is_the_sum_of_its_volumes(self):
        packs = download.group_packs(
            _release(
                [
                    "Batocera_43.1_BIOS_Pack.zip.001",
                    "Batocera_43.1_BIOS_Pack.zip.002",
                ],
                size=7,
            )
        )
        self.assertEqual(packs[0].size, 14)

    def test_volumes_order_numerically_not_lexically(self):
        packs = download.group_packs(
            _release(
                [
                    "Big_BIOS_Pack.zip.010",
                    "Big_BIOS_Pack.zip.009",
                    "Big_BIOS_Pack.zip.001",
                ]
            )
        )
        self.assertEqual(
            [part["name"] for part in packs[0].parts],
            ["Big_BIOS_Pack.zip.001", "Big_BIOS_Pack.zip.009", "Big_BIOS_Pack.zip.010"],
        )

    def test_other_assets_are_not_packs(self):
        packs = download.group_packs(_release(["SHA256SUMS.txt", "database.json"]))
        self.assertEqual(packs, [])

    def test_list_platforms_names_split_packs(self):
        names = download.list_platforms(_release(RELEASE_ASSETS))
        self.assertIn("Batocera 43.1", names)
        self.assertIn("RetroDECK 0.10.9b", names)
        self.assertEqual(len(names), 5)

    def test_find_pack_resolves_a_split_platform(self):
        pack = download.find_pack(_release(RELEASE_ASSETS), "batocera")
        self.assertIsNotNone(pack)
        self.assertEqual(pack.name, "Batocera_43.1_BIOS_Pack.zip")
        self.assertEqual(len(pack.parts), 2)

    def test_find_pack_maps_retroarch_to_the_lakka_asset(self):
        pack = download.find_pack(_release(RELEASE_ASSETS), "retroarch")
        self.assertEqual(pack.name, "RetroArch_Lakka_v1.22.2_BIOS_Pack.zip")

    def test_find_pack_returns_none_for_an_unknown_platform(self):
        self.assertIsNone(download.find_pack(_release(RELEASE_ASSETS), "nintendo"))

    def test_find_pack_resolves_a_platform_id_that_drops_separators(self):
        # The platform is `misterfpga` everywhere else; the asset is MiSTer_FPGA.
        pack = download.find_pack(
            _release(RELEASE_ASSETS + ["MiSTer_FPGA_2026-08-29_BIOS_Pack.zip"]),
            "misterfpga",
        )
        self.assertIsNotNone(pack)
        self.assertEqual(pack.name, "MiSTer_FPGA_2026-08-29_BIOS_Pack.zip")


class TestJoinVolumes(unittest.TestCase):
    def test_joined_volumes_reproduce_the_archive(self):
        tmp = Path(tempfile.mkdtemp())
        archive = tmp / "pack.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("bios/scph5501.bin", b"\x01\x02" * 5000)
            zf.writestr("bios/dc_boot.bin", b"\x03\x04" * 5000)
        raw = archive.read_bytes()
        cut = len(raw) // 3
        parts = []
        for index, start in enumerate(range(0, len(raw), cut), start=1):
            part = tmp / f"pack.zip.{index:03d}"
            part.write_bytes(raw[start : start + cut])
            parts.append(part)
        self.assertGreater(len(parts), 1)

        joined = tmp / "joined.zip"
        download.join_volumes(parts, joined)

        self.assertEqual(joined.read_bytes(), raw)
        with zipfile.ZipFile(joined) as zf:
            self.assertEqual(zf.testzip(), None)


class TestStagingIsolation(unittest.TestCase):
    """Two downloads into one BIOS folder must not share a staging directory."""

    def setUp(self):
        self.dest = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dest, True)

    def test_two_runs_stage_in_separate_directories(self):
        first = download.make_staging(self.dest)
        second = download.make_staging(self.dest)
        self.assertNotEqual(first, second)
        for staging in (first, second):
            self.assertEqual(staging.parent, self.dest)
            self.assertTrue(staging.name.startswith(download.STAGING_PREFIX))

    def test_one_run_cleaning_up_leaves_the_other_transfer_alone(self):
        finished = download.make_staging(self.dest)
        in_flight = download.make_staging(self.dest)
        (in_flight / "Batocera_BIOS_Pack.zip").write_bytes(b"still downloading")

        # What main() does in its finally clause once a pack is extracted.
        shutil.rmtree(finished, ignore_errors=True)

        self.assertTrue(
            (in_flight / "Batocera_BIOS_Pack.zip").is_file(),
            "a finished download removed an archive another run was still writing",
        )


class ReleaseServer:
    """Serves a release index and its assets over loopback."""

    def __init__(self, pack_name: str, payload: dict[str, bytes], volumes: int):
        self.root = Path(tempfile.mkdtemp())
        (self.root / "assets").mkdir()
        archive = self.root / "assets" / pack_name
        with zipfile.ZipFile(archive, "w") as zf:
            for name, data in payload.items():
                zf.writestr(name, data)
        raw = archive.read_bytes()
        self.digest = hashlib.sha256(raw).hexdigest()
        archive.unlink()

        self.names: list[str] = []
        if volumes == 1:
            (self.root / "assets" / pack_name).write_bytes(raw)
            self.names.append(pack_name)
        else:
            cut = len(raw) // volumes + 1
            for index, start in enumerate(range(0, len(raw), cut), start=1):
                name = f"{pack_name}.{index:03d}"
                (self.root / "assets" / name).write_bytes(raw[start : start + cut])
                self.names.append(name)

        (self.root / "assets" / "SHA256SUMS.txt").write_text(
            f"{self.digest}  {pack_name}\n"
        )

        handler = functools.partial(_QuietHandler, directory=str(self.root))
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

        index = self.root / "repos" / "Abdess" / "retrobios" / "releases"
        index.mkdir(parents=True)
        assets = [
            {
                "name": name,
                "size": (self.root / "assets" / name).stat().st_size,
                "browser_download_url": f"{self.base}/assets/{name}",
            }
            for name in self.names + ["SHA256SUMS.txt"]
        ]
        (index / "latest").write_text(json.dumps({"assets": assets}))
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def corrupt_last_volume(self) -> None:
        target = self.root / "assets" / self.names[-1]
        target.write_bytes(target.read_bytes()[:-16] + b"0" * 16)

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


class DownloaderCase(unittest.TestCase):
    """Common fixture: a two-volume pack served over loopback."""

    volumes = 2
    payload = {
        "bios/scph5501.bin": b"\x10\x20" * 4096,
        "bios/dc/dc_boot.bin": b"\x30\x40" * 4096,
    }

    pack_name = "Batocera_43.1_BIOS_Pack.zip"
    platform = "batocera"
    platform_label = "Batocera 43.1"

    def setUp(self):
        self.server = ReleaseServer(self.pack_name, self.payload, self.volumes)
        self.addCleanup(self.server.close)
        self.dest = Path(tempfile.mkdtemp()) / "bios"
        # A pack is gigabytes: staging it in the system temp directory fills
        # the RAM disk that /tmp is on the appliances these packs target.
        self.tmpdir = Path(tempfile.mkdtemp())

    def env(self) -> dict[str, str]:
        env = dict(os.environ)
        env.update(
            RETROBIOS_API=self.base_api(),
            TMPDIR=str(self.tmpdir),
            TMP=str(self.tmpdir),
            TEMP=str(self.tmpdir),
        )
        return env

    def base_api(self) -> str:
        return self.server.base

    def assert_extracted(self):
        for name, data in self.payload.items():
            extracted = self.dest / name
            self.assertTrue(extracted.is_file(), f"{name} not extracted")
            self.assertEqual(extracted.read_bytes(), data)

    def assert_listed(self, out: str):
        names = [
            line.strip().lstrip("- ").strip()
            for line in out.splitlines()
            if "BIOS" not in line and line.strip()
        ]
        self.assertIn(self.platform_label, names)
        self.assertNotIn(".001", out)

    def assert_refused(self, proc):
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("checksum", (proc.stdout + proc.stderr).lower())
        self.assertFalse((self.dest / "bios/scph5501.bin").exists())

    def assert_no_leftovers(self):
        self.assertEqual(
            sorted(p.name for p in self.tmpdir.iterdir()),
            [],
            "pack staged in the system temp directory",
        )
        searched = list(self.dest.parent.iterdir()) + list(self.dest.rglob("*"))
        leftovers = sorted(
            p.name for p in searched if "_BIOS_Pack" in p.name or p.name.startswith(".")
        )
        self.assertEqual(leftovers, [], "download staging left behind")


class WholePackCase(DownloaderCase):
    """A pack published whole, under a name the platform id does not spell."""

    volumes = 1
    pack_name = "MiSTer_FPGA_2026-08-29_BIOS_Pack.zip"
    platform = "misterfpga"
    platform_label = "MiSTer FPGA 2026-08-29"


class TestDownloadPython(DownloaderCase):
    def run_cli(self, *args, expect_success=True):
        proc = subprocess.run(
            ["python3", str(REPO_ROOT / "scripts" / "download.py"), *args],
            env=self.env(),
            capture_output=True,
            text=True,
            timeout=120,
        )
        if expect_success:
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return proc

    def test_list_names_the_pack(self):
        proc = self.run_cli("--list")
        self.assert_listed(proc.stdout)

    def test_pack_downloads_and_extracts(self):
        self.run_cli(self.platform, str(self.dest))
        self.assert_extracted()

    def test_volumes_are_not_staged_in_the_system_temp_directory(self):
        self.run_cli(self.platform, str(self.dest))
        self.assert_no_leftovers()

    def test_a_corrupt_volume_is_refused(self):
        self.server.corrupt_last_volume()
        proc = self.run_cli(self.platform, str(self.dest), expect_success=False)
        self.assert_refused(proc)

    def test_info_reports_every_volume(self):
        proc = self.run_cli("--info", self.platform)
        self.assertIn("2 parts", proc.stdout)

    def test_an_unreachable_release_endpoint_fails(self):
        env = self.env()
        env["RETROBIOS_API"] = f"http://127.0.0.1:{_closed_port()}"
        proc = subprocess.run(
            ["python3", str(REPO_ROOT / "scripts" / "download.py"), "--list"],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_a_non_loopback_http_api_is_refused(self):
        env = self.env()
        env["RETROBIOS_API"] = "http://api.example.com"
        proc = subprocess.run(
            ["python3", str(REPO_ROOT / "scripts" / "download.py"), "--list"],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("RETROBIOS_API", proc.stderr)


@unittest.skipUnless(
    shutil.which("curl") and shutil.which("unzip"), "curl and unzip required"
)
class TestDownloadShell(DownloaderCase):
    def run_cli(self, *args, expect_success=True):
        proc = subprocess.run(
            ["bash", str(SHELL), *args],
            env=self.env(),
            capture_output=True,
            text=True,
            timeout=120,
        )
        if expect_success:
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return proc

    def test_list_names_the_pack(self):
        proc = self.run_cli("--list")
        self.assert_listed(proc.stdout)

    def test_pack_downloads_and_extracts(self):
        self.run_cli(self.platform, str(self.dest))
        self.assert_extracted()

    def test_volumes_are_not_staged_in_the_system_temp_directory(self):
        self.run_cli(self.platform, str(self.dest))
        self.assert_no_leftovers()

    def test_a_corrupt_volume_is_refused(self):
        self.server.corrupt_last_volume()
        proc = self.run_cli(self.platform, str(self.dest), expect_success=False)
        self.assert_refused(proc)

    def test_an_unknown_platform_lists_what_exists(self):
        proc = self.run_cli("nintendo", str(self.dest), expect_success=False)
        self.assertIn(self.platform_label, proc.stdout + proc.stderr)


class TestWholePackPython(WholePackCase, TestDownloadPython):
    def test_info_reports_every_volume(self):
        proc = self.run_cli("--info", self.platform)
        self.assertIn("1 part", proc.stdout)


class TestWholePackShell(WholePackCase, TestDownloadShell):
    pass


if __name__ == "__main__":
    unittest.main()
