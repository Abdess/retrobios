"""standalone_probe: the platform's asset choice, the AppImage offset, the
framebuffer reader, the settings it writes and the oracle it judges with."""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import core_probe as cp  # noqa: E402
import standalone_probe as sp  # noqa: E402


def xwd(width: int, height: int, pixels: bytes, ncolors: int = 0, pad: int = 0) -> bytes:
    """An XWD file as Xvfb keeps its screen: version 7, 32 bpp, LSB first."""
    name = b"Xvfb main window\0"
    header_size = 100 + len(name)
    bytes_per_line = width * 4 + pad
    fields = [header_size, 7, 2, 24, width, height, 0, 0, 32, 0, 32, 32, bytes_per_line, 4,
              0xFF0000, 0xFF00, 0xFF, 8, 256, ncolors, ncolors, width, height, 0, 0]
    rows = b"".join(pixels[y * width * 4:(y + 1) * width * 4] + b"\0" * pad for y in range(height))
    return struct.pack(">25I", *fields) + name + b"\0" * (12 * ncolors) + rows


class AssetChoice(unittest.TestCase):
    RELEASES = [
        {"tag_name": "preview", "prerelease": True, "assets": [
            {"name": "DuckStation-x64-SSE2.AppImage", "browser_download_url": "u1"},
            {"name": "DuckStation-x64.AppImage", "browser_download_url": "u2"}]},
        {"tag_name": "latest", "prerelease": False, "assets": [
            {"name": "DuckStation-x64.AppImage", "browser_download_url": "u3"}]},
    ]

    def test_first_match_in_api_order_like_getreleaseurlgh(self) -> None:
        asset = sp.select_asset(self.RELEASES, "AppImage", "x64.")
        self.assertEqual((asset["tag"], asset["name"], asset["url"]),
                         ("preview", "DuckStation-x64.AppImage", "u2"))
        self.assertTrue(asset["prerelease"])

    def test_no_match(self) -> None:
        self.assertIsNone(sp.select_asset(self.RELEASES, "Qt.AppImage", ""))

    def test_every_emulator_names_its_installer_and_profile(self) -> None:
        profiles = {p.stem for p in (ROOT / "emulators").glob("*.yml")}
        for name, emu in sp.EMULATORS.items():
            self.assertEqual(name, emu.name)
            self.assertIn(name, profiles)
            self.assertIn("EmuDeck", emu.installer_ref)
            self.assertTrue(emu.error_patterns)


class AppImage(unittest.TestCase):
    def test_offset_is_the_end_of_the_section_headers(self) -> None:
        head = bytearray(64)
        head[:5] = b"\x7fELF\x02"
        struct.pack_into("<Q", head, 0x28, 1000)
        struct.pack_into("<HH", head, 0x3A, 64, 30)
        self.assertEqual(sp.appimage_offset(bytes(head)), 1000 + 64 * 30)

    def test_not_elf(self) -> None:
        with self.assertRaises(cp.ProbeError):
            sp.appimage_offset(b"hsqs" + bytes(60))


class Framebuffer(unittest.TestCase):
    def test_reads_rgb_and_skips_colormap_and_padding(self) -> None:
        # Two pixels, BGRX: red then blue.
        pixels = bytes((0, 0, 255, 0, 255, 0, 0, 0))
        width, height, rgb = sp.parse_xwd(xwd(2, 1, pixels, ncolors=3, pad=8))
        self.assertEqual((width, height), (2, 1))
        self.assertEqual(rgb, bytes((255, 0, 0, 0, 0, 255)))

    def test_refuses_other_layouts(self) -> None:
        data = bytearray(xwd(1, 1, bytes(4)))
        struct.pack_into(">I", data, 44, 16)
        with self.assertRaises(cp.ProbeError):
            sp.parse_xwd(bytes(data))

    def test_truncated(self) -> None:
        with self.assertRaises(cp.ProbeError):
            sp.parse_xwd(xwd(4, 4, bytes(64))[:-10])


class Settings(unittest.TestCase):
    def test_bios_folder_and_overrides(self) -> None:
        emu = sp.EMULATORS["duckstation"]
        sections = sp.emulator_settings(emu, Path("/b"), [("GPU.Renderer", "Vulkan"), ("New.Key", "1")])
        self.assertEqual(sections["BIOS"]["SearchDirectory"], "/b")
        self.assertEqual(sections["GPU"]["Renderer"], "Vulkan")
        self.assertEqual(sections["New"]["Key"], "1")
        self.assertEqual(emu.settings["GPU"]["Renderer"], "Software")
        text = sp.ini_text(sections)
        self.assertIn("[BIOS]\nSearchDirectory = /b\n", text)

    def test_override_needs_a_section(self) -> None:
        with self.assertRaises(cp.ProbeError):
            sp.emulator_settings(sp.EMULATORS["pcsx2"], Path("/b"), [("Renderer", "13")])

    def test_display_wrapper_passes_the_command_through(self) -> None:
        argv = sp.with_display(["/emu", "--", "game.cue"], Path("/fb"))
        self.assertEqual(argv[:2], ["/bin/sh", "-c"])
        self.assertEqual(argv[3:], ["xvfb", "/fb", "/emu", "--", "game.cue"])
        self.assertIn(f'Xvfb ":{sp.DISPLAY_NUMBER}"', argv[2])


class Oracle(unittest.TestCase):
    def test_emulator_patterns_join_the_oracle_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "oracle.yml"
            path.write_text("error_patterns:\n  - {pattern: 'shared', source_ref: x}\n"
                            "cores:\n  duckstation:\n    error_screens:\n"
                            "      - {sha1: '" + "a" * 40 + "', shows: 'no BIOS'}\n"
                            "content:\n  - sha1: '" + "b" * 40 + "'\n    references:\n"
                            "      duckstation:\n        frames:\n"
                            "          - {sha1: '" + "c" * 40 + "', stage: bios, shows: 'logo'}\n",
                            encoding="utf-8")
            oracle = sp.emulator_oracle(sp.EMULATORS["duckstation"], path, "b" * 40)
        self.assertEqual(oracle["references"][0]["sha1"], "c" * 40)
        self.assertEqual(oracle["error_screens"][0]["shows"], "no BIOS")
        self.assertEqual(oracle["error_patterns"][0], "shared")
        self.assertIn(r"No\ BIOS\ image\ found\ for", oracle["error_patterns"])
        self.assertEqual(len(oracle["sha256"]), 64)

    def test_without_the_file_the_oracle_names_the_script(self) -> None:
        oracle = sp.emulator_oracle(sp.EMULATORS["pcsx2"], Path("/nonexistent/oracle.yml"), "0" * 40)
        self.assertEqual(oracle["file"], sp.SCRIPT)
        self.assertEqual(oracle["references"], [])

    def test_a_log_line_gives_bios_error_through_core_probe_judge(self) -> None:
        oracle = sp.emulator_oracle(sp.EMULATORS["duckstation"], Path("/nonexistent"), "0" * 40)
        rep = {"loaded": True, "observables": {"frame_hashes": [[0, "d" * 40]], "uniform_frames": []},
               "logs": [{"frame": 3, "level": "info", "text": "E: No BIOS image found for NTSC-J region."}]}
        verdict, evidence = cp.judge(rep, oracle)
        self.assertEqual((verdict, evidence["rule"]), ("bios_error", "error_pattern"))

    def test_an_early_exit_is_a_crash_and_a_black_tail_a_hang(self) -> None:
        oracle = {"references": [], "error_patterns": [], "error_screens": []}
        rep = {"loaded": False, "exit": {"status": 1, "signal": None}, "observables": {}, "logs": []}
        self.assertEqual(cp.judge(rep, oracle)[0], "crash")
        black = "e" * 40
        rep = {"loaded": True, "logs": [], "observables": {
            "frame_hashes": [[0, "f" * 40], [1, black], [2, black]], "uniform_frames": [black]}}
        self.assertEqual(cp.judge(rep, oracle)[0], "hang")

    def test_check_result_carries_the_verdicts(self) -> None:
        def variant(label: str, verdict: str) -> dict:
            return {"label": label, "flags": [], "verdict": verdict, "repetitions": [
                {"loaded": True, "observables": {"verdict": verdict}}]}
        result = sp.check_result([variant("absent", "bios_error"), variant("scph5501.bin", "boots")],
                                 "verdict")
        self.assertEqual(result["status"], "differs")
        self.assertEqual(result["verdicts"], {"absent": "bios_error", "scph5501.bin": "boots"})


class HostLock(unittest.TestCase):
    def test_a_run_holds_the_probe_lock_for_itself(self) -> None:
        import contextlib
        from unittest import mock

        events = []

        @contextlib.contextmanager
        def lock():
            events.append("take")
            yield
            events.append("free")

        def body(_args, _emu):
            events.append("run")
            return 0

        with tempfile.NamedTemporaryFile(suffix=".cue") as content, \
                mock.patch.object(sp.cp, "host_probe_lock", lock), mock.patch.object(sp, "_probe", body):
            args = sp.build_parser().parse_args(["run", "duckstation", "--content", content.name])
            self.assertEqual(sp.probe(args), 0)
        self.assertEqual(events, ["take", "run", "free"])


class CommandLine(unittest.TestCase):
    def test_check_refuses_two_destinations(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".cue") as content:
            args = sp.build_parser().parse_args(
                ["check", "duckstation", "--content", content.name, "--vary", "a.bin=", "--vary", "b.bin=",
                 "--claim", "c", "--method", "m"])
            self.assertIn("--vary must name the same DEST in every occurrence", sp.validate(args))

    def test_unknown_observable(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".cue") as content:
            args = sp.build_parser().parse_args(
                ["check", "pcsx2", "--content", content.name, "--vary", "a.bin=", "--observable", "fps",
                 "--claim", "c", "--method", "m"])
            self.assertTrue(any("--observable fps" in p for p in sp.validate(args)))


if __name__ == "__main__":
    unittest.main()
