"""core_probe runs a libretro core headless and records what it measured.

The parsers are checked on fixed inputs. One test builds a ten-line
libretro core with the C compiler, when there is one, and runs the whole
probe on it: staging, the worker process, strace, the record and its schema.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import argparse
import contextlib
import hashlib
import io
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path
from typing import ClassVar

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import core_probe
import measurement_records

STRACE_SAMPLE = """\
4242  openat(AT_FDCWD, "/sys/bios/card.bin", O_RDONLY) = 5
4242  openat(AT_FDCWD, "/sys/bios/missing.bin", O_RDONLY) = -1 ENOENT (No such file or directory)
[pid  4243] open("/sys/bios/sub/x.rom", O_RDONLY|O_CLOEXEC) = 7
4242  openat(AT_FDCWD, "/elsewhere/game.cue", O_RDONLY) = 3
4242  read(3, "...", 10) = 10
"""

FAKE_CORE = r"""
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
struct retro_system_info { const char *n, *v, *e; bool full, block; };
struct retro_game_geometry { unsigned bw, bh, mw, mh; float a; };
struct retro_system_timing { double fps, rate; };
struct retro_system_av_info { struct retro_game_geometry g; struct retro_system_timing t; };
struct retro_log_callback { void (*log)(int, const char *, ...); };
typedef bool (*env_t)(unsigned, void *);
typedef void (*video_t)(const void *, unsigned, unsigned, size_t);
typedef size_t (*batch_t)(const int16_t *, size_t);
typedef int16_t (*input_t)(unsigned, unsigned, unsigned, unsigned);
static env_t env; static video_t video; static batch_t batch; static input_t input;
static unsigned ports, frames; static struct retro_log_callback logger;
static uint16_t pixels[4 * 2]; static unsigned char card;
void retro_set_environment(env_t e) { bool t = true; env = e; env(18, &t); }
void retro_set_video_refresh(video_t v) { video = v; }
void retro_set_audio_sample(void *f) { (void)f; }
void retro_set_audio_sample_batch(batch_t b) { batch = b; }
void retro_set_input_poll(void *f) { (void)f; }
void retro_set_input_state(input_t f) { input = f; }
void retro_set_controller_port_device(unsigned port, unsigned device) { (void)port; if (device == 1) ports++; }
void retro_get_system_info(struct retro_system_info *i) {
  i->n = "Fake"; i->v = "1"; i->e = ""; i->full = true; i->block = false; }
void retro_get_system_av_info(struct retro_system_av_info *i) {
  memset(i, 0, sizeof *i); i->t.fps = 60.0; i->t.rate = 44100.0; }
void retro_init(void) {}
void retro_deinit(void) {}
bool retro_load_game(const void *g) {
  const char *dir = NULL; char path[4096]; struct retro_log_callback cb;
  const char *tag = getenv("CORE_PROBE_TEST_TAG");
  (void)g; env(9, &dir);
  snprintf(path, sizeof path, "%s/card.bin", dir);
  FILE *f = fopen(path, "rb");
  card = 0;
  if (f) { int c = fgetc(f); card = c < 0 ? 0 : (unsigned char)c; fclose(f); }
  if (env(27, &cb)) {
    logger = cb;
    cb.log(1, "card %s byte %d\n", f ? "present" : "absent", (int)card);
    cb.log(1, "tag %s\n", tag ? tag : "unset");
    if (card == 0xEE) cb.log(3, "BIOS not found: card.bin\n"); }
  return true; }
void retro_unload_game(void) {}
void retro_run(void) {
  int16_t s[4] = {1, 2, 3, 4};
  const char *end = getenv("CORE_PROBE_TEST_END");
  if (end && frames == 1 && !strcmp(end, "crash")) { if (logger.log) logger.log(3, "about to fall\n"); raise(SIGSEGV); }
  if (end && frames == 1 && !strcmp(end, "hang")) for (;;) {}
  if (frames++ == 0 && logger.log) logger.log(1, "ports %u\n", ports);
  input(0, 1, 0, 8);
  for (int i = 0; i < 8; i++) pixels[i] = card;
  video(pixels, 4, 2, 8); batch(s, 2); }
size_t retro_serialize_size(void) { return 1; }
bool retro_serialize(void *d, size_t n) { (void)n; *(unsigned char *)d = card; return true; }
"""


def mednafen_state(sections: dict[str, dict[str, bytes]]) -> bytes:
    body = b""
    for section, entries in sections.items():
        chunk = b"".join(bytes([len(name)]) + name.encode() + struct.pack("<I", len(value)) + value
                         for name, value in entries.items())
        body += section.encode().ljust(32, b"\0") + struct.pack("<I", len(chunk)) + chunk
    return b"MDFNSVST".ljust(32, b"\0") + body


def checkout(path: Path) -> Path:
    """A folder made the root of a git checkout, as --record requires."""
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    return path


class ParsingTests(unittest.TestCase):
    def test_assignment(self) -> None:
        self.assertEqual(core_probe.parse_assignment("a=b=c", "--option"), ("a", "b=c"))
        self.assertEqual(core_probe.parse_assignment("dest=", "--vary"), ("dest", ""))
        for bad in ("novalue", "=x"):
            with self.assertRaises(argparse.ArgumentTypeError):
                core_probe.parse_assignment(bad, "--option")

    def test_press(self) -> None:
        self.assertEqual(core_probe.parse_press("120:start"), (120, 3, 1))
        self.assertEqual(core_probe.parse_press("5:A:10"), (5, 8, 10))
        for bad in ("x:a", "1:turbo", "1:a:0", "-1:a", "1"):
            with self.assertRaises(argparse.ArgumentTypeError):
                core_probe.parse_press(bad)

    def test_strace(self) -> None:
        calls = core_probe.parse_strace(STRACE_SAMPLE)
        self.assertEqual([c["path"] for c in calls],
                         ["/sys/bios/card.bin", "/sys/bios/missing.bin", "/sys/bios/sub/x.rom",
                          "/elsewhere/game.cue"])
        self.assertEqual([c["ok"] for c in calls], [True, False, True, True])
        self.assertEqual(calls[1]["errno"], "ENOENT")
        opened, absent = core_probe.files_under(calls, Path("/sys/bios"))
        self.assertEqual(opened, ["card.bin", "sub/x.rom"])
        self.assertEqual(absent, ["missing.bin"])

    def test_printf(self) -> None:
        name = core_probe.ctypes.create_string_buffer(b"mpeg_card.bin")
        address = core_probe.ctypes.addressof(name)
        self.assertEqual(core_probe.render_printf(b"open %s: %d%% %x\n", [address, 50, 255]),
                         "open mpeg_card.bin: 50% ff")
        self.assertEqual(core_probe.render_printf(b"%d", [0xFFFFFFFF]), "-1")
        self.assertEqual(core_probe.render_printf(b"%.2f fps %u", [7]), "<double> fps 7")
        self.assertEqual(core_probe.render_printf(b"%s", [0]), "(null)")

    def test_mednafen_state(self) -> None:
        state = b"\x00" * 7 + mednafen_state({"MPEG": {"Present": b"\x01", "AuthState": b"\x02"},
                                              "CDB": {"Word": b"\x34\x12"}})
        self.assertEqual(core_probe.mednafen_state_vars(state),
                         {"MPEG.Present": "01", "MPEG.AuthState": "02", "CDB.Word": "3412"})
        self.assertEqual(core_probe.mednafen_state_vars(b"no state"), {})

    def test_elf_comment(self) -> None:
        self.assertIsInstance(core_probe.elf_comment(Path(sys.executable).resolve()), list)
        with tempfile.NamedTemporaryFile(dir=REPO_ROOT / "tmp" / "tests") as handle:
            handle.write(b"not an elf")
            handle.flush()
            self.assertEqual(core_probe.elf_comment(Path(handle.name)), [])

    def test_env_file_recorded_by_name_and_hash(self) -> None:
        library = Path(sys.executable).resolve()
        described = core_probe.describe_env_value(str(library))
        self.assertEqual(described, f"{library.name} sha256:{core_probe.file_digest(library, 'sha256')}")
        self.assertEqual(core_probe.describe_env_value("2000-01-01 00:00:00"), "2000-01-01 00:00:00")

    def test_uniform_frame(self) -> None:
        self.assertTrue(core_probe.uniform_frame(b"", 2))
        self.assertTrue(core_probe.uniform_frame(b"\x01\x02" * 8, 2))
        self.assertFalse(core_probe.uniform_frame(b"\x01\x02" * 7 + b"\x01\x03", 2))
        self.assertFalse(core_probe.uniform_frame(b"\x00\x00\x00\x00\x00\x00\x00\x01", 4))

    def test_cue_tracks(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp" / "tests") as tmp:
            cue = Path(tmp, "d.cue")
            cue.write_text('FILE "a b.bin" BINARY\n  TRACK 01 MODE2/2352\nFILE c.bin BINARY\n',
                           encoding="utf-8")
            self.assertEqual([p.name for p in core_probe.cue_tracks(cue)], ["a b.bin", "c.bin"])


def frames(*pairs: tuple[int, str]) -> list[list]:
    return [[frame, digest] for frame, digest in pairs]


class OracleTests(unittest.TestCase):
    """judge() turns a repetition into a verdict from positive evidence only."""

    TITLE, LOGO, ERROR, BLACK, OTHER = ("1" * 40, "2" * 40, "3" * 40, "4" * 40, "5" * 40)
    ORACLE: ClassVar[dict] = {"references": [{"sha1": "2" * 40, "stage": "bios", "shows": "the console logo"},
                             {"sha1": "1" * 40, "stage": "game", "shows": "the title"}],
              "error_patterns": [r"BIOS not found"],
              "error_screens": [{"sha1": "3" * 40, "shows": "the core's missing-BIOS message"}]}

    def rep(self, hashes: list, logs: list[str] = (), uniform: list[str] = (), loaded: bool = True,
            **extra: object) -> dict:
        return {"loaded": loaded, "library_name": "Fake", "frames": 100, "warmup": 0,
                "logs": [{"frame": 0, "level": "error", "text": text} for text in logs],
                "observables": {"frame_hashes": hashes, "uniform_frames": list(uniform)}, **extra}

    def test_a_reference_frame_is_a_boot_with_its_stages(self) -> None:
        verdict, evidence = core_probe.judge(
            self.rep(frames((0, self.BLACK), (10, self.LOGO), (20, self.TITLE)),
                     logs=["BIOS not found"]), self.ORACLE)
        self.assertEqual(verdict, "boots")
        self.assertEqual((evidence["rule"], evidence["frame"], evidence["stages"]),
                         ("reference_frame", 20, ["bios", "game"]))

    def test_a_bios_load_line_stands_for_hidden_bios_screens(self) -> None:
        oracle = {**self.ORACLE, "bios_patterns": [r"^found US BIOS file"]}
        verdict, evidence = core_probe.judge(
            self.rep(frames((0, self.TITLE)), logs=["found US BIOS file, crc32 1: x"]), oracle)
        self.assertEqual((verdict, evidence["stages"]), ("boots", ["bios", "game"]))
        self.assertEqual(core_probe.judge(self.rep(frames((0, self.TITLE))), oracle)[1]["stages"], ["game"])

    def test_the_bios_used_comes_from_the_log(self) -> None:
        oracle = {**self.ORACLE, "fallback_patterns": [r"^Firmware is missing: "],
                  "load_patterns": [r"^Firmware found: (?P<path>.+)$"]}
        cases = [
            (["Searching for firmware checksum: 0555", "Firmware is missing: scph5501.bin"], "builtin"),
            (["Firmware found: <system>/scph5501.bin", "Firmware SHA1: 0555"], "staged:scph5501.bin"),
            # A file tried, then the fallback: the last line decides.
            (["Firmware found: <system>/a.bin", "Firmware is missing: b.bin"], "builtin"),
            (["nothing about the BIOS"], "unknown"),
        ]
        for logs, expected in cases:
            self.assertEqual(core_probe.bios_used(self.rep([], logs=logs), oracle)[0], expected, logs)
        rep = self.rep(frames((10, self.TITLE)), logs=["Firmware is missing: scph5501.bin"])
        core_probe.judge_repetition(rep, oracle)
        self.assertEqual((rep["verdict"], rep["bios_used"]), ("boots", "builtin"))
        self.assertTrue(rep["verdict_evidence"]["detail"].endswith("on the core's built-in BIOS"))
        self.assertEqual(rep["verdict_evidence"]["bios_log"], "Firmware is missing: scph5501.bin")
        variant = {"repetitions": [rep, {**rep, "bios_used": "staged:a.bin"}]}
        core_probe.judge_variant(variant)
        self.assertEqual(variant["bios_used"], "unknown")

    def test_the_bios_screens_alone_are_not_a_boot(self) -> None:
        # A console that shows its logo and then refuses the disc never reached the game.
        verdict, evidence = core_probe.judge(
            self.rep(frames((0, self.LOGO), (10, self.BLACK), (20, self.BLACK)), uniform=[self.BLACK]),
            self.ORACLE)
        self.assertEqual((verdict, evidence["rule"], evidence["stages"]), ("hang", "uniform_tail", ["bios"]))
        self.assertIn("no screen of the game", evidence["detail"])

    def test_an_error_pattern_or_screen_without_a_reference_is_a_bios_error(self) -> None:
        verdict, evidence = core_probe.judge(
            self.rep(frames((0, self.OTHER)), logs=["x", "BIOS not found: scph5501.bin"]), self.ORACLE)
        self.assertEqual((verdict, evidence["rule"], evidence["log"]),
                         ("bios_error", "error_pattern", "BIOS not found: scph5501.bin"))
        verdict, evidence = core_probe.judge(self.rep(frames((0, self.ERROR))), self.ORACLE)
        self.assertEqual((verdict, evidence["rule"], evidence["frame"]), ("bios_error", "error_screen", 0))
        self.assertEqual(core_probe.judge(self.rep([], logs=["BIOS not found"], loaded=False),
                                          self.ORACLE)[0], "bios_error")

    def test_process_status_decides_crash_and_hang_first(self) -> None:
        crashed = self.rep(frames((0, self.TITLE)), exit={"status": -11, "signal": "SIGSEGV"})
        self.assertEqual(core_probe.judge(crashed, self.ORACLE)[0], "crash")
        killed = self.rep([], exit={"status": None, "signal": "SIGKILL", "timeout_s": 5})
        self.assertEqual(core_probe.judge(killed, self.ORACLE), (
            "hang", {"rule": "timeout", "detail": "killed after 5 s", "exit_status": None,
                     "signal": "SIGKILL"}))

    def test_a_one_colour_second_half_is_a_hang(self) -> None:
        run = self.rep(frames((0, self.OTHER), (10, self.OTHER), (20, self.BLACK), (30, self.BLACK)),
                       uniform=[self.BLACK])
        self.assertEqual(core_probe.judge(run, self.ORACLE)[1]["rule"], "uniform_tail")
        lit = self.rep(frames((0, self.BLACK), (10, self.BLACK), (20, self.OTHER), (30, self.BLACK)),
                       uniform=[self.BLACK])
        self.assertEqual(core_probe.judge(lit, self.ORACLE)[0], "unknown")

    def test_frames_that_differ_are_never_a_boot(self) -> None:
        verdict, evidence = core_probe.judge(self.rep(frames((0, self.OTHER), (10, "6" * 40))),
                                             self.ORACLE)
        self.assertEqual((verdict, evidence["rule"]), ("unknown", "no_evidence"))
        verdict, evidence = core_probe.judge(self.rep(frames((0, self.TITLE))),
                                             {**self.ORACLE, "references": []})
        self.assertEqual(verdict, "unknown")
        self.assertIn("no reference frame is known", evidence["detail"])
        self.assertEqual(core_probe.judge(self.rep([], loaded=False), self.ORACLE)[0], "unknown")

    def test_a_variant_needs_every_repetition_to_agree(self) -> None:
        boot = {"verdict": "boots", "verdict_evidence": {"rule": "reference_frame", "detail": "d",
                                                         "frame": 3, "stages": ["game"]}}
        verdict, evidence = core_probe.variant_verdict([boot, boot])
        self.assertEqual((verdict, evidence["rule"], evidence["stages"]),
                         ("boots", "repetitions_agree", ["game"]))
        hang = {"verdict": "hang", "verdict_evidence": {"rule": "uniform_tail", "detail": "d"}}
        verdict, evidence = core_probe.variant_verdict([boot, hang])
        self.assertEqual((verdict, evidence["repetitions"]), ("unknown", ["boots", "hang"]))

    def test_oracle_entries_are_picked_by_content_and_core(self) -> None:
        data = {"error_patterns": [{"pattern": "shared"}],
                "cores": {"Fake": {"error_patterns": [{"pattern": "own"}],
                                   "error_screens": [{"sha1": self.ERROR, "shows": "s"}]}},
                "content": [{"name": "disc", "sha1": "a" * 40, "references": {
                    "Fake": {"frames": [{"sha1": self.TITLE, "stage": "game", "shows": "t"}]},
                    "Other": {"frames": [{"sha1": self.LOGO, "stage": "bios", "shows": "l"}]}}}]}
        picked = core_probe.oracle_for(data, "a" * 40, "Fake")
        self.assertEqual(picked["references"], [{"sha1": self.TITLE, "stage": "game", "shows": "t"}])
        self.assertEqual(picked["error_patterns"], ["shared", "own"])
        self.assertEqual(picked["bios_patterns"], [])
        self.assertEqual(core_probe.oracle_for(data, "b" * 40, "Fake")["references"], [])
        self.assertEqual(core_probe.oracle_for(data, "a" * 40, "Nobody")["error_patterns"], ["shared"])

    def test_every_reference_judges_its_own_record_a_boot(self) -> None:
        """Each reference block names the run it was taken from: judged
        again with the oracle as it stands, every repetition of that run
        boots, so a frame copied wrong or a stage mislabelled fails here."""
        data, _ = core_probe.load_oracle(core_probe.DEFAULT_ORACLE)
        records = {s.record["id"]: s.record for s in measurement_records.read_records(REPO_ROOT)}
        checked = 0
        for item in data.get("content") or ():
            for library, block in item["references"].items():
                record = records.get(block["recorded_from"])
                self.assertIsNotNone(record, f"{item['name']} on {library}: {block['recorded_from']}")
                self.assertEqual(record["inputs"]["content"]["sha1"], item["sha1"], item["name"])
                # A check names the variant that ran the full set, a run has one.
                label = block.get("variant")
                chosen = next(v for v in record["variants"] if v["label"] == label) if label \
                    else record["variants"][0]
                for rep in chosen["repetitions"]:
                    oracle = core_probe.oracle_for(data, item["sha1"], rep["library_name"])
                    verdict, evidence = core_probe.judge(rep, oracle)
                    self.assertEqual(verdict, "boots", f"{item['name']} on {library}: {evidence}")
                    checked += 1
        self.assertGreaterEqual(checked, 2 * 14)

    def test_the_repository_names_the_bios_each_core_ran(self) -> None:
        data, _ = core_probe.load_oracle(core_probe.DEFAULT_ORACLE)
        cases = {
            "Beetle PSX": [("Firmware is missing: scph5501.bin", "builtin"),
                           ("Firmware found: <system>/scph5501.bin", "staged:scph5501.bin"),
                           ("Firmware found but has invalid SHA1: <system>/scph5501.bin", "staged:scph5501.bin")],
            "Beetle PSX HW": [("Firmware is missing: scph5500.bin", "builtin")],
            "SwanStation": [("[HostInterface] No BIOS image found for NTSC-U/C (US, Canada) region", "builtin"),
                            ("[HostInterface] Using BIOS 'scph5501.bin': SCPH-5501", "staged:scph5501.bin"),
                            ("[HostInterface] Falling back to possibly-incompatible image "
                             "'<system>/scph5500.bin': SCPH-5500", "staged:scph5500.bin")],
            "PCSX-ReARMed": [('Loaded BIOS "<system>/scph5500.bin".', "staged:scph5500.bin"),
                             ("No BIOS files found.", "builtin"), ("Using HLE BIOS.", "builtin")],
            "Flycast": [("[BOOT]: Did not load BIOS, using reios", "builtin"),
                        ("Loaded <system>/dc/dc_boot.bin as bootrom", "staged:dc/dc_boot.bin")],
            "PCSX1": [("anything", "unknown")],
        }
        for library, lines in cases.items():
            oracle = core_probe.oracle_for(data, None, library)
            for text, expected in lines:
                rep = {"logs": [{"frame": 0, "level": "info", "text": text}]}
                self.assertEqual(core_probe.bios_used(rep, oracle)[0], expected, (library, text))

    def test_the_repository_error_patterns_and_screens(self) -> None:
        data, _ = core_probe.load_oracle(core_probe.DEFAULT_ORACLE)
        saturn = core_probe.oracle_for(data, None, "Beetle Saturn")
        for line in ('Cannot open BIOS file "/system/sega_101.bin".',
                     'BIOS file "/system/sega_101.bin" is of an incorrect size.',
                     'BIOS file "/system/sega_101.bin" could not be fully read (short or failed read).'):
            rep = {"loaded": False, "logs": [{"frame": 0, "level": "error", "text": line}]}
            self.assertEqual(core_probe.judge(rep, saturn)[0], "bios_error", line)
        menu = {"Beetle PSX": "dfbfc299250c0983f86bbf951efd187441306d92",
                "Beetle PSX HW": "dfbfc299250c0983f86bbf951efd187441306d92",
                "SwanStation": "167fb7b6527e295b12dca5806a29856f5f31d401",
                "pcsx2": "46329c633ea7d0b63349261e4aab169e4f44d3f6"}
        for library, sha1 in menu.items():
            rep = {"loaded": True, "logs": [], "frames": 100, "warmup": 0,
                   "observables": {"frame_hashes": [[90, sha1]], "uniform_frames": []}}
            verdict, evidence = core_probe.judge(rep, core_probe.oracle_for(data, None, library))
            self.assertEqual((verdict, evidence["rule"]), ("bios_error", "error_screen"), library)
        # The PlayStation cores fall back to a built-in BIOS: nothing they log is an error.
        for library in ("Beetle PSX", "SwanStation", "PCSX-ReARMed", "PCSX1"):
            self.assertEqual(core_probe.oracle_for(data, None, library)["error_patterns"], [])

    def test_the_repository_oracle_is_well_formed(self) -> None:
        import yaml
        data = yaml.safe_load(core_probe.DEFAULT_ORACLE.read_text(encoding="utf-8"))
        patterns = list(data.get("error_patterns") or ())
        for core in (data.get("cores") or {}).values():
            patterns += [p for key in ("error_patterns", "bios_patterns", "fallback_patterns", "load_patterns")
                         for p in core.get(key) or []]
            for screen in core.get("error_screens") or ():
                self.assertRegex(screen["sha1"], r"^[0-9a-f]{40}$")
        for pattern in patterns:
            self.assertTrue(pattern.get("source_ref") or pattern.get("reason"), pattern)
            core_probe.re.compile(pattern["pattern"])
        for item in data.get("content") or ():
            self.assertRegex(item["sha1"], r"^[0-9a-f]{40}$")
            for block in item["references"].values():
                self.assertRegex(block["recorded_from"], r"^\d{4}-\d{2}-\d{2}-[0-9a-f]{12}$")
                stages = {frame["stage"] for frame in block["frames"]}
                self.assertIn("game", stages, item["name"])
                for frame in block["frames"]:
                    self.assertRegex(frame["sha1"], r"^[0-9a-f]{40}$")
                    self.assertIn(frame["stage"], ("bios", "game"))
                    self.assertTrue(frame["shows"])

    def test_made_files(self) -> None:
        zeros = core_probe.Synthetic.parse("@zeros:16")
        self.assertEqual((zeros.label("bios.bin"), zeros.source), ("bios.bin-zeros-16", None))
        head = core_probe.Synthetic.parse("@head:8:/x/scph5501.bin")
        self.assertEqual(head.label("bios.bin"), "bios.bin-head-8-of-scph5501.bin")
        for bad in ("@zeros:", "@zeros:8:/x", "@head:8", "@ones:8", "@head:x:/y"):
            with self.assertRaises(argparse.ArgumentTypeError):
                core_probe.Synthetic.parse(bad)
        self.assertEqual(core_probe.exit_description(-11), {"status": -11, "signal": "SIGSEGV"})
        self.assertEqual(core_probe.exit_description(139), {"status": 139, "signal": "SIGSEGV"})
        self.assertEqual(core_probe.exit_description(1), {"status": 1, "signal": None})


class ResultTests(unittest.TestCase):
    @staticmethod
    def variant(label: str, value: str, loaded: bool = True) -> dict:
        return {"label": label, "flags": [],
                "repetitions": [{"loaded": loaded, "observables": {"video_sha1": value}}]}

    def test_same_differs_inconclusive(self) -> None:
        same = core_probe.check_result([self.variant("a", "1"), self.variant("b", "1")], "video_sha1")
        self.assertEqual(same["status"], "same")
        differs = core_probe.check_result([self.variant("a", "1"), self.variant("b", "2")], "video_sha1")
        self.assertEqual(differs["status"], "differs")
        self.assertEqual(len(differs["groups"]), 2)
        flagged = core_probe.check_result([self.variant("a", "1", loaded=False), self.variant("b", "1")],
                                          "video_sha1")
        self.assertEqual(flagged["status"], "inconclusive")

    def test_other_observable_does_not_void_the_check(self) -> None:
        variant = {"label": "a", "flags": ["repetition 1 disagrees with repetition 0 on state_sha1"],
                   "repetitions": [{"loaded": True, "observables": {"video_sha1": "1", "state_sha1": "x"}},
                                   {"loaded": True, "observables": {"video_sha1": "1", "state_sha1": "y"}}]}
        result = core_probe.check_result([variant], "video_sha1")
        self.assertEqual(result["status"], "same")
        self.assertIn("Other flags", result["statement"])
        self.assertEqual(core_probe.check_result([variant], "state_sha1")["status"], "inconclusive")

    def test_host_paths_hidden(self) -> None:
        places = [("/tmp/x/system", "<system>"), ("/tmp/x", "<repo>")]
        self.assertEqual(core_probe.host_paths_hidden("/tmp/x/system/bios.bin NOT FOUND", places),
                         "<system>/bios.bin NOT FOUND")

    def test_timing_stats(self) -> None:
        stats = core_probe.timing_stats([1.0, 2.0, 3.0, 4.0, 10.0])
        self.assertEqual((stats["median"], stats["mean"], stats["min"], stats["max"]), (3.0, 4.0, 1.0, 10.0))
        self.assertEqual(stats["raw"], [1.0, 2.0, 3.0, 4.0, 10.0])

    def test_refusals(self) -> None:
        parser = core_probe.build_parser()
        core = sys.executable
        bench = parser.parse_args(["bench", "--core", core, "--record", "x", "--repeat", "3"])
        self.assertIn("a recorded benchmark needs --repeat >= 5", core_probe.validate_args(bench))
        check = parser.parse_args(["check", "--core", core, "--vary", "a=", "--vary", "b=",
                                   "--observable", "video_sha1", "--claim", "c", "--method", "m"])
        self.assertTrue(any("same DEST" in p for p in core_probe.validate_args(check)))
        unknown = parser.parse_args(["check", "--core", core, "--vary", "a=", "--observable", "nope",
                                     "--claim", "c", "--method", "m"])
        self.assertTrue(any("--observable nope" in p for p in core_probe.validate_args(unknown)))

    def test_a_preload_the_loader_cannot_find_is_refused(self) -> None:
        # libfaketime.so.1 by bare name, with libfaketime not installed, was
        # skipped by the loader: every run recorded a fixed clock it never had.
        parser = core_probe.build_parser()
        core = sys.executable
        for value in ("libfaketime.so.1", "/nonexistent/libfaketime.so.1", f"{core}:libfaketime.so.1"):
            args = parser.parse_args(["run", "--core", core, "--env", f"LD_PRELOAD={value}"])
            with self.subTest(value=value):
                self.assertTrue(any("LD_PRELOAD" in p for p in core_probe.validate_args(args)))
        found = parser.parse_args(["run", "--core", core, "--env", f"LD_PRELOAD={core}"])
        self.assertFalse([p for p in core_probe.validate_args(found) if "LD_PRELOAD" in p])


@unittest.skipUnless(shutil.which("cc"), "no C compiler")
class FakeCoreTests(unittest.TestCase):
    """The whole probe against a core compiled from FAKE_CORE."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp" / "tests"))
        source = cls.tmp / "fake.c"
        source.write_text(FAKE_CORE, encoding="utf-8")
        cls.core = cls.tmp / "fake_libretro.so"
        subprocess.run(["cc", "-shared", "-fPIC", "-o", str(cls.core), str(source)], check=True)
        cls.cards = []
        for byte in (b"\x01", b"\x01", b"\x02"):
            path = cls.tmp / f"card{len(cls.cards)}.bin"
            path.write_bytes(byte)
            cls.cards.append(path)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def probe(self, argv: list[str]) -> tuple[int, dict | None]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = core_probe.main(argv + ["--work-dir", str(self.tmp / "work")])
        return code, json.loads(out.getvalue()) if code == 0 else None

    def test_run_record(self) -> None:
        record_dir = checkout(self.tmp / "records")
        code, record = self.probe(["check", "--core", str(self.core), "--frames", "3",
                                   "--vary", f"card.bin={self.cards[0]}", "--vary", f"card.bin={self.cards[1]}",
                                   "--vary", f"card.bin={self.cards[2]}", "--vary", "card.bin=",
                                   "--observable", "frame_sha1", "--claim", "c", "--method", "m",
                                   "--record", str(record_dir), "--max-load", "1000",
                                   "--env", "CORE_PROBE_TEST_TAG=set-by-test", "--press", "0:a:2"])
        self.assertEqual(code, 0)
        result = record["check"]["result"]
        self.assertEqual(result["status"], "differs")
        self.assertEqual(sorted(len(g["variants"]) for g in result["groups"]), [1, 1, 2])
        first = record["variants"][0]["repetitions"][0]
        self.assertEqual(first["logs"][0]["text"], "card present byte 1")
        self.assertEqual(first["logs"][1]["text"], "tag set-by-test")
        self.assertEqual(first["logs"][2]["text"], "ports 2")
        self.assertEqual((first["input_queries"], first["input_pressed"]), (3, 2))
        self.assertEqual(record["inputs"]["env"], {"CORE_PROBE_TEST_TAG": "set-by-test"})
        self.assertEqual(record["variants"][3]["repetitions"][0]["logs"][0]["text"], "card absent byte 0")
        if first["tracing"] == "strace":
            self.assertEqual([f["path"] for f in first["files_opened"]], ["card.bin"])
            self.assertEqual(record["variants"][3]["repetitions"][0]["files_probed_absent"], ["card.bin"])
        self.assertEqual(first["frames"], 3)
        self.assertEqual(record["emulator"], "fake")
        self.assertEqual([p.relative_to(record_dir).as_posix()
                          for p in record_dir.rglob("*") if p.is_file() and ".git" not in p.parts],
                         ["measurements/fake.jsonl"])
        line = json.loads((record_dir / "measurements" / "fake.jsonl").read_text())
        self.assertEqual(measurement_records.check_line(line), [])
        # The line is the record the run printed, id included.
        self.assertEqual(line, record)
        try:
            from jsonschema import Draft202012Validator
        except ImportError:
            return
        schema = json.loads((REPO_ROOT / "schemas" / "core-probe-record.schema.json").read_text())
        self.assertEqual(list(Draft202012Validator(schema).iter_errors(line)), [])

    def oracle_file(self) -> Path:
        title = hashlib.sha1(struct.pack("<8H", *[1] * 8)).hexdigest()
        content = self.tmp / "game.bin"
        content.write_bytes(b"game")
        path = self.tmp / "oracle.yml"
        path.write_text(
            "error_patterns:\n  - pattern: 'BIOS not found'\n    reason: test\n"
            "cores:\n  Fake:\n    error_patterns: []\n    error_screens: []\n"
            f"content:\n  - name: game\n    sha1: {core_probe.file_digest(content)}\n"
            "    references:\n      Fake:\n        recorded_from: 2026-10-27-000000000000\n"
            f"        frames:\n          - sha1: {title}\n            stage: game\n"
            "            shows: card one\n", encoding="utf-8")
        return path

    def test_verdicts_of_a_negative_check(self) -> None:
        oracle = self.oracle_file()
        error = self.tmp / "error.bin"
        error.write_bytes(b"\xee")
        code, record = self.probe(["check", "--core", str(self.core), "--frames", "4",
                                   "--frame-hash-every", "1", "--content", str(self.tmp / "game.bin"),
                                   "--oracle", str(oracle), "--vary", "card.bin=",
                                   "--vary", f"card.bin={self.cards[0]}", "--vary", f"card.bin={error}",
                                   "--vary", "card.bin=@zeros:1",
                                   "--vary", f"card.bin=@head:0:{self.cards[0]}",
                                   "--observable", "frame_hashes", "--claim", "c", "--method", "m",
                                   "--no-trace", "--repeat", "2"])
        self.assertEqual(code, 0)
        verdicts = record["check"]["result"]["verdicts"]
        self.assertEqual(verdicts, {"card.bin-absent": "hang", "card0.bin": "boots",
                                    "error.bin": "bios_error", "card.bin-zeros-1": "hang",
                                    "card.bin-head-0-of-card0.bin": "hang"})
        boot = record["variants"][1]
        self.assertEqual((boot["verdict_evidence"]["rule"], boot["verdict_evidence"]["stages"]),
                         ("repetitions_agree", ["game"]))
        self.assertEqual(boot["repetitions"][0]["verdict_evidence"]["rule"], "reference_frame")
        self.assertEqual(record["variants"][3]["system_files"],
                         {"card.bin": hashlib.sha1(b"\x00").hexdigest()})
        self.assertEqual(record["inputs"]["oracle"]["error_patterns"], ["BIOS not found"])
        self.assertEqual(record["record_version"], 5)
        self.assertEqual({v["bios_used"] for v in record["variants"]}, {"unknown"})
        self.assert_schema(record)

    def test_recorded_runs_are_judged_again_offline(self) -> None:
        oracle = self.oracle_file()
        record_dir = checkout(self.tmp / "rejudge")
        code, first = self.probe(["run", "--core", str(self.core), "--frames", "4", "--frame-hash-every", "1",
                                  "--content", str(self.tmp / "game.bin"), "--oracle", str(oracle),
                                  "--no-trace", "--record", str(record_dir), "--max-load", "1000"])
        self.assertEqual((code, first["variants"][0]["bios_used"]), (0, "unknown"))
        # The core's fallback line becomes known: the same runs now name the BIOS.
        oracle.write_text(oracle.read_text().replace(
            "    error_patterns: []\n", "    error_patterns: []\n    fallback_patterns:\n"
            "      - pattern: '^card absent'\n        reason: test\n", 1), encoding="utf-8")
        argv = ["rejudge", "--record", str(record_dir), "--oracle", str(oracle)]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(core_probe.main(argv), 0)
        lines = [json.loads(line) for line in (record_dir / "measurements" / "fake.jsonl").read_text().splitlines()]
        self.assertEqual(len(lines), 2)
        again = lines[1]
        self.assertEqual((again["supersedes"], again["record_version"]), (first["id"], 5))
        self.assertEqual(again["variants"][0]["bios_used"], "builtin")
        self.assertEqual(again["variants"][0]["repetitions"][0]["logs"], first["variants"][0]["repetitions"][0]["logs"])
        self.assertEqual(again["recorded_at"], first["recorded_at"])
        self.assertIn("judged_at", again)
        self.assertEqual(measurement_records.check_line(again), [])
        self.assert_schema(again)
        # Judged once: a second pass has nothing to add.
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            core_probe.main(argv)
        self.assertEqual(len((record_dir / "measurements" / "fake.jsonl").read_text().splitlines()), 2)

    def test_a_crash_and_a_hang_are_verdicts(self) -> None:
        oracle = self.oracle_file()
        code, record = self.probe(["run", "--core", str(self.core), "--frames", "4",
                                   "--frame-hash-every", "1", "--oracle", str(oracle),
                                   "--env", "CORE_PROBE_TEST_END=crash"])
        self.assertEqual(code, 0)
        crashed = record["variants"][0]
        self.assertEqual((crashed["verdict"], crashed["repetitions"][0]["exit"]["signal"]),
                         ("crash", "SIGSEGV"))
        self.assertEqual(crashed["repetitions"][0]["logs"][-1]["text"], "about to fall")
        self.assertEqual(crashed["repetitions"][0]["observables"]["frame_hashes"][0][0], 0)
        self.assert_schema(record)
        code, record = self.probe(["run", "--core", str(self.core), "--frames", "4",
                                   "--frame-hash-every", "1", "--oracle", str(oracle), "--timeout", "3",
                                   "--env", "CORE_PROBE_TEST_END=hang", "--no-trace"])
        self.assertEqual(code, 0)
        self.assertEqual((record["variants"][0]["verdict"],
                          record["variants"][0]["repetitions"][0]["verdict_evidence"]["rule"]),
                         ("hang", "timeout"))

    def assert_schema(self, record: dict) -> None:
        try:
            from jsonschema import Draft202012Validator
        except ImportError:
            return
        schema = json.loads((REPO_ROOT / "schemas" / "core-probe-record.schema.json").read_text())
        sealed = measurement_records.seal({**record, "emulator": "fake", "subject": "s"})
        self.assertEqual([e.message for e in Draft202012Validator(schema).iter_errors(sealed)], [])

    def test_a_run_waits_for_the_host_lock_and_frees_it(self) -> None:
        import fcntl
        import time

        lock = self.tmp / "host.lock"
        argv = [sys.executable, str(REPO_ROOT / "scripts" / "core_probe.py"), "run", "--core",
                str(self.core), "--frames", "1", "--no-trace", "--work-dir", str(self.tmp / "work")]
        env = {**os.environ, "RETROBIOS_PROBE_LOCK": str(lock)}
        with lock.open("a") as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            waiting = subprocess.Popen(argv, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                       text=True)
            time.sleep(1.5)
            self.assertIsNone(waiting.poll(), "the run went ahead while another held the lock")
            # A caller that holds the lock for this run says so.
            held_run = subprocess.run(argv, env={**env, "RETROBIOS_PROBE_LOCK_HELD": "1"},
                                      capture_output=True, text=True, timeout=60, check=False)
            self.assertEqual(held_run.returncode, 0, held_run.stderr)
            fcntl.flock(held, fcntl.LOCK_UN)
        _, err = waiting.communicate(timeout=60)
        self.assertEqual(waiting.returncode, 0, err)
        self.assertIn("another measurement is running", err)
        # Released at the end of the run: the lock is free again.
        with lock.open("a") as again:
            fcntl.flock(again, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_second_run_is_appended_beside_the_first(self) -> None:
        record_dir = checkout(self.tmp / "appended")
        argv = ["run", "--core", str(self.core), "--frames", "1", "--no-trace", "--max-load", "1000",
                "--record", str(record_dir), "--subject", "smoke"]
        self.assertEqual(self.probe(argv)[0], 0)
        lines = record_dir / "measurements" / "fake.jsonl"
        first = lines.read_text()
        code, record = self.probe(argv)
        self.assertEqual(code, 0)
        self.assertTrue(lines.read_text().startswith(first))
        ids = [json.loads(line)["id"] for line in lines.read_text().splitlines()]
        self.assertEqual(len(ids), 2)
        code, corrected = self.probe(argv + ["--supersedes", ids[0]])
        self.assertEqual((code, corrected["supersedes"]), (0, ids[0]))
        code, _ = self.probe(argv + ["--supersedes", "2000-01-01-000000000000"])
        self.assertEqual(code, 2)
        self.assertEqual(len(lines.read_text().splitlines()), 3)

    def test_record_defaults_to_this_checkout(self) -> None:
        parser = core_probe.build_parser()
        args = parser.parse_args(["run", "--core", sys.executable, "--record", "--frames", "1"])
        self.assertEqual(Path(args.record), REPO_ROOT)
        self.assertIsNone(parser.parse_args(["run", "--core", sys.executable]).record)

    def test_bench_stats(self) -> None:
        code, record = self.probe(["bench", "--core", str(self.core), "--frames", "2", "--warmup", "1",
                                   "--repeat", "5", "--no-trace", "--max-load", "1000"])
        self.assertEqual(code, 0)
        self.assertEqual(len(record["timing"]["ms_per_frame"]["raw"]), 5)
        self.assertEqual(record["variants"][0]["repetitions"][0]["tracing"], "disabled: --no-trace")
        self.assertEqual(record["flags"], [])

    def test_busy_machine_refused(self) -> None:
        refused = checkout(self.tmp / "refused")
        code, _ = self.probe(["run", "--core", str(self.core), "--frames", "1", "--record",
                              str(refused), "--max-load", "-1"])
        self.assertEqual(code, 3)
        self.assertFalse((refused / "measurements").exists())

    def test_record_names_a_checkout_root(self) -> None:
        # --record measurements wrote measurements/measurements/<emulator>.jsonl.
        root = checkout(self.tmp / "rooted")
        (root / "measurements").mkdir()
        for wrong in (root / "measurements", self.tmp / "plain"):
            wrong.mkdir(exist_ok=True)
            err = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                code = core_probe.main(["run", "--core", str(self.core), "--frames", "1", "--no-trace",
                                        "--record", str(wrong), "--work-dir", str(self.tmp / "work")])
            self.assertEqual(code, 2)
            self.assertIn("not a git checkout root", err.getvalue())
            self.assertIn("--record .", err.getvalue())
            self.assertFalse((wrong / "measurements" / "fake.jsonl").exists())
        self.assertIsNone(core_probe.not_a_checkout_root(root))
        self.assertIsNone(core_probe.not_a_checkout_root(REPO_ROOT))

    def test_the_core_sees_only_the_env_it_was_given(self) -> None:
        os.environ["CORE_PROBE_TEST_TAG"] = "from-the-host"
        os.environ["GITHUB_TOKEN"] = "secret"
        try:
            code, record = self.probe(["run", "--core", str(self.core), "--frames", "1",
                                       "--no-trace"])
        finally:
            del os.environ["CORE_PROBE_TEST_TAG"]
            del os.environ["GITHUB_TOKEN"]
        self.assertEqual(code, 0)
        rep = record["variants"][0]["repetitions"][0]
        self.assertEqual(rep["logs"][1]["text"], "tag unset")
        self.assertTrue(rep["isolation"] == "bwrap" or rep["isolation"].startswith("environment only"))


class Sandbox(unittest.TestCase):
    """What a core run under bubblewrap can reach: an allowlist."""

    def setUp(self) -> None:
        if not core_probe.sandbox_argv([])[0]:
            self.skipTest("no working bwrap on this host")
        self.tmp = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp" / "tests"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.out = self.tmp / "out"
        self.inputs = self.tmp / "inputs"
        self.inputs.mkdir()
        (self.inputs / "bios.bin").write_text("BIOS")
        self.elsewhere = self.tmp / "elsewhere"
        self.elsewhere.mkdir()

    def inside(self, script: str, **kwargs: object) -> subprocess.CompletedProcess:
        prefix, isolation = core_probe.sandbox_argv([self.out], [self.inputs], **kwargs)
        self.assertEqual(isolation, core_probe.SANDBOX)
        return subprocess.run(prefix + ["/bin/sh", "-c", script], capture_output=True, text=True,
                              check=False, env={"PATH": "/usr/bin:/bin"})

    def test_nothing_of_the_user_or_the_checkout_is_reachable(self) -> None:
        home = Path.home()
        hidden = [home / ".config", home / ".ssh", home / ".git-credentials", home / ".netrc",
                  home / ".gitconfig", REPO_ROOT / ".git", REPO_ROOT / "scripts", REPO_ROOT / "bios",
                  REPO_ROOT / "emulators", self.elsewhere,
                  Path("/mnt/c"), Path("/root"), Path("/var"), Path("/etc/shadow"), Path("/opt")]
        script = "; ".join(f'test -e "{path}" && echo "LEAK {path}"' for path in hidden)
        # The checkout exists only as the path down to the bound folders.
        script += f'; ls -A /mnt /tmp; ls -A ~ 2>/dev/null; ls -A "{REPO_ROOT}"; echo end'
        proc = self.inside(script)
        self.assertNotIn("LEAK", proc.stdout)
        self.assertEqual(proc.stdout.split(), ["/mnt:", "/tmp:", "tmp", "end"])

    def test_inputs_read_only_work_dir_writable(self) -> None:
        proc = self.inside(f'cat "{self.inputs}/bios.bin"; echo; echo x > "{self.inputs}/bios.bin" 2>/dev/null '
                           f'|| echo refused; echo ok > "{self.out}/w"; echo no > "{self.elsewhere}/w" '
                           f'2>/dev/null || echo gone')
        self.assertEqual(proc.stdout.split(), ["BIOS", "refused", "gone"])
        self.assertEqual((self.inputs / "bios.bin").read_text(), "BIOS")
        self.assertEqual((self.out / "w").read_text(), "ok\n")
        self.assertFalse((self.elsewhere / "w").exists())

    def test_no_network_unless_asked(self) -> None:
        devices = "tail -n +3 /proc/net/dev | cut -d: -f1"
        self.assertEqual(self.inside(devices).stdout.split(), ["lo"])
        self.assertNotEqual(self.inside(devices, network=True).stdout.split(), ["lo"])

    def test_a_probe_can_require_the_sandbox(self) -> None:
        args = core_probe.build_parser().parse_args(
            ["run", "--core", sys.executable, "--require-sandbox"])
        self.assertEqual([p for p in core_probe.validate_args(args) if "sandbox" in p], [])
        with unittest.mock.patch.object(core_probe.shutil, "which", return_value=None):
            problems = core_probe.validate_args(args)
        self.assertIn("--require-sandbox: environment only: bwrap not found", problems)



class TheInterpreterIsInTheSandbox(unittest.TestCase):
    """CI's setup-python, a venv and uv put Python outside /usr. The sandbox
    bound only the system trees, so the worker could not start and every run
    crashed on the runner."""

    def test_each_link_to_the_interpreter_is_bound(self):
        from unittest import mock  # noqa: PLC0415

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "uv" / "cpython-3.13.12" / "bin"
            real.mkdir(parents=True)
            (real / "python3.13").write_text("")
            version = f"python{sys.version_info.major}.{sys.version_info.minor}"
            (root / "uv" / "cpython-3.13.12" / "lib" / version).mkdir(parents=True)
            alias = root / "uv" / "cpython-3.13"
            alias.symlink_to(root / "uv" / "cpython-3.13.12")
            venv = root / "venv" / "bin"
            venv.mkdir(parents=True)
            (root / "venv" / "pyvenv.cfg").write_text("home = x\n")
            (venv / "python").symlink_to(alias / "bin" / "python3.13")
            with mock.patch.object(core_probe.sys, "executable", str(venv / "python")), \
                    mock.patch.object(core_probe.sys, "prefix", str(root / "venv")), \
                    mock.patch.object(core_probe.sys, "base_prefix", str(root / "uv" / "cpython-3.13.12")):
                paths = core_probe.interpreter_paths()
        self.assertIn(root / "venv", paths)
        self.assertIn(alias, paths)
        self.assertIn(root / "uv" / "cpython-3.13.12", paths)
        # The venv's own link sits in the venv, bound already.
        self.assertNotIn(venv / "python", paths)

    def test_a_link_in_a_shared_folder_binds_only_itself(self):
        """~/.local/bin/python3 must not expose ~/.local: only the link file
        and the proven Python prefix behind it are bound."""
        from unittest import mock  # noqa: PLC0415

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            prefix = root / "share" / "cpython"
            (prefix / "bin").mkdir(parents=True)
            (prefix / "bin" / "python3").write_text("")
            version = f"python{sys.version_info.major}.{sys.version_info.minor}"
            (prefix / "lib" / version).mkdir(parents=True)
            local = root / "dotlocal"
            (local / "bin").mkdir(parents=True)
            (local / "secrets.txt").write_text("x")
            (local / "bin" / "python3").symlink_to(prefix / "bin" / "python3")
            with mock.patch.object(core_probe.sys, "executable", str(local / "bin" / "python3")), \
                    mock.patch.object(core_probe.sys, "prefix", str(prefix)), \
                    mock.patch.object(core_probe.sys, "base_prefix", str(prefix)):
                paths = core_probe.interpreter_paths()
        self.assertNotIn(local, paths)
        self.assertIn(local / "bin" / "python3", paths)
        self.assertIn(prefix, paths)

    def test_home_and_root_are_never_a_prefix(self):
        self.assertFalse(core_probe._python_prefix(Path("/")))
        self.assertFalse(core_probe._python_prefix(Path.home()))

    def test_a_link_is_mounted_at_its_own_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "real"
            target.mkdir()
            link = Path(tmp) / "link"
            link.symlink_to(target)
            prefix, isolation = core_probe.sandbox_argv([], [link])
        if isolation != core_probe.SANDBOX:
            self.skipTest(f"no sandbox here ({isolation})")
        self.assertIn(["--ro-bind", str(target.resolve()), str(link)],
                      [prefix[i:i + 3] for i in range(len(prefix) - 2)])


if __name__ == "__main__":
    unittest.main()
