"""campaign.py runs the real-condition campaign: state, guards, content, rules.

No network and no real core. The rules and the profile editor are checked on
synthetic records and profiles, the guards and the probe retries on a fake
host, the content store on folders made in the test. One class builds a
libretro core from C, when a compiler is there, and runs whole passes on a
synthetic checkout: records, rules applied with their evidence, findings,
resume and rerun on a changed core.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

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
from types import MappingProxyType

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import campaign
import campaign_profiles
import campaign_rules as rules
import measurement_records as mr

TMP = REPO_ROOT / "tmp" / "tests"

PROFILE = """\
emulator: Fake
type: libretro
cores: [fake]
systems: [fake-system]
notes: >
  A profile for the tests.

files:
  # -- the BIOS --

  - name: "bios.bin"
    description: "The BIOS"
    required: true
    size: 4
    validation: [size]
    aliases:
      - "Bios.bin"

  - name: "other.bin"
    required: false
"""

FAKE_CORE = r"""
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct retro_system_info { const char *n, *v, *e; bool full, block; };
struct retro_game_geometry { unsigned bw, bh, mw, mh; float a; };
struct retro_system_timing { double fps, rate; };
struct retro_system_av_info { struct retro_game_geometry g; struct retro_system_timing t; };
typedef bool (*env_t)(unsigned, void *);
typedef void (*video_t)(const void *, unsigned, unsigned, size_t);
typedef size_t (*batch_t)(const int16_t *, size_t);
typedef int16_t (*input_t)(unsigned, unsigned, unsigned, unsigned);
static env_t env; static video_t video; static batch_t batch;
static uint16_t pixels[4 * 2]; static int booted; static unsigned frame;
void retro_set_environment(env_t e) { bool t = true; env = e; env(18, &t); }
void retro_set_video_refresh(video_t v) { video = v; }
void retro_set_audio_sample(void *f) { (void)f; }
void retro_set_audio_sample_batch(batch_t b) { batch = b; }
void retro_set_input_poll(void *f) { (void)f; }
void retro_set_input_state(input_t f) { (void)f; }
void retro_set_controller_port_device(unsigned port, unsigned device) { (void)port; (void)device; }
void retro_get_system_info(struct retro_system_info *i) {
  i->n = "Fake"; i->v = "1"; i->e = ""; i->full = true; i->block = false; }
void retro_get_system_av_info(struct retro_system_av_info *i) {
  memset(i, 0, sizeof *i); i->t.fps = 60.0; i->t.rate = 44100.0; }
void retro_init(void) {}
void retro_deinit(void) {}
static FILE *try_open(const char *dir, const char *name) {
  char path[4096]; snprintf(path, sizeof path, "%s/%s", dir, name); return fopen(path, "rb"); }
/* booted: 0 a black screen to the end, 1 the BIOS logo then the title,
   2 the title alone (the built-in stand-in of FAKE_HLE). */
bool retro_load_game(const void *g) {
  const char *dir = NULL; FILE *f; unsigned char buf[8]; size_t n = 0; (void)g; env(9, &dir);
  f = try_open(dir, "bios.bin");
  if (!f) f = try_open(dir, "BIOS.BIN");
  if (f) { n = fread(buf, 1, sizeof buf, f); fclose(f); }
  int valid = f && n == 4 && buf[0] == 'B';
#ifdef FAKE_HLE
  /* Checks the size only: a file of the wrong size is refused for the
     stand-in, one of the right size is run, whatever it holds. */
  booted = valid ? 1 : (f && n == 4) ? 0 : 2;
#else
  booted = valid ? 1 : 0;
#endif
  return true; }
void retro_unload_game(void) {}
void retro_run(void) {
  int16_t s[4] = {1, 2, 3, 4};
#ifdef FAKE_HANG
  for (;;) {}
#endif
  int shown = frame < 4 ? 0 : booted == 1 && frame < 8 ? 1 : booted ? 2 : 0;
  for (int i = 0; i < 8; i++) pixels[i] = shown == 0 ? 0 : (uint16_t)((shown == 1 ? 1 : 20) + i);
  frame++;
  video(pixels, 4, 2, 8); batch(s, 2); }
size_t retro_serialize_size(void) { return 0; }
bool retro_serialize(void *d, size_t n) { (void)d; (void)n; return false; }
"""


def run(verdict: str, label: str = "v", stages: tuple[str, ...] = (),
        rid: str = "2026-10-27-aaaaaaaaaaaa") -> rules.Run:
    return rules.Run(verdict, rid, label, stages)


NONE_BOOTS = run(rules.BOOTS, "none", ("game",), "2026-10-27-000000000001")
NONE_HANGS = run(rules.HANG, "none", (), "2026-10-27-000000000001")
PRESENT = run(rules.BOOTS, "bios.bin", ("bios", "game"), "2026-10-27-000000000002")


class RuleTable(unittest.TestCase):
    ENTRY = MappingProxyType({"name": "bios.bin", "required": True, "aliases": ["Bios.bin"]})
    RID = "2026-10-27-bbbbbbbbbbbb"

    def test_a_verdict_is_read_from_the_record(self) -> None:
        record = {"id": self.RID, "variants": [
            {"label": "a", "verdict": "boots", "verdict_evidence": {"rule": "repetitions_agree",
                                                                    "detail": "d", "stages": ["bios"]}},
            {"label": "old"}]}
        self.assertEqual(rules.run_of(record, "a"), rules.Run("boots", self.RID, "a", ("bios",)))
        # A record from before the oracle proves nothing.
        self.assertEqual(rules.run_of(record, "old").verdict, rules.UNKNOWN)

    def test_boots_with_no_bios_settles_hle_and_queues_required(self) -> None:
        verdicts = rules.rule_need(NONE_BOOTS, PRESENT, self.ENTRY)
        self.assertEqual([(v.field, v.value, v.apply) for v in verdicts],
                         [("hle_fallback", True, True), ("required", False, False)])
        self.assertEqual(verdicts[0].evidence, (NONE_BOOTS.record_id,))
        optional = rules.rule_need(NONE_BOOTS, PRESENT, {"name": "a", "required": False})
        self.assertEqual([v.field for v in optional], ["hle_fallback"])

    def test_a_file_the_content_never_uses_settles_nothing(self) -> None:
        unused = run(rules.BOOTS, "bios.bin", ("game",))
        self.assertFalse(rules.read(NONE_BOOTS, unused, unused, unused))
        self.assertEqual(rules.rule_need(NONE_BOOTS, unused, self.ENTRY, used=False), [])
        # A wrong file that hangs where no file boots: the core reads it.
        self.assertTrue(rules.read(NONE_BOOTS, unused, run(rules.HANG), unused))
        self.assertTrue(rules.read(NONE_BOOTS, PRESENT, None, None))

    def test_fails_without_and_boots_alone_settles_required(self) -> None:
        for failure in rules.FAILS:
            verdicts = rules.rule_need(run(failure, "none"), PRESENT, self.ENTRY)
            self.assertEqual([(v.field, v.value, v.apply) for v in verdicts],
                             [("required", True, True), ("hle_fallback", False, True)])

    def test_unknown_or_no_boot_alone_settles_nothing(self) -> None:
        for none, present in ((run(rules.UNKNOWN), PRESENT), (NONE_HANGS, run(rules.HANG)),
                              (NONE_HANGS, run(rules.UNKNOWN))):
            (verdict,) = rules.rule_need(none, present, self.ENTRY)
            self.assertFalse(verdict.apply)
            self.assertEqual(verdict.rule, "unsettled")

    def test_file_use(self) -> None:
        self.assertEqual(rules.file_use(run(rules.BIOS_ERROR), NONE_HANGS, PRESENT), rules.REFUSED)
        # It boots without the BIOS screens the right file shows: a fallback.
        self.assertEqual(rules.file_use(run(rules.BOOTS, stages=("game",)), NONE_BOOTS, PRESENT),
                         rules.REFUSED)
        self.assertEqual(rules.file_use(run(rules.BOOTS, stages=("bios", "game")), NONE_BOOTS, PRESENT),
                         rules.USED)
        self.assertEqual(rules.file_use(run(rules.HANG), NONE_BOOTS, PRESENT), rules.USED)
        self.assertEqual(rules.file_use(run(rules.CRASH), NONE_BOOTS, PRESENT), rules.USED)
        # A hang the run with no file shows too says nothing about the file.
        self.assertIsNone(rules.file_use(run(rules.HANG), NONE_HANGS, PRESENT))
        self.assertIsNone(rules.file_use(run(rules.UNKNOWN), NONE_BOOTS, PRESENT))
        self.assertIsNone(rules.file_use(run(rules.BIOS_ERROR), NONE_BOOTS, run(rules.HANG)))
        no_logo = run(rules.BOOTS, stages=("game",))
        self.assertIsNone(rules.file_use(run(rules.BOOTS, stages=("game",)), NONE_BOOTS, no_logo))

    def test_the_bios_the_log_names_settles_the_file_use(self) -> None:
        present = run(rules.BOOTS, stages=("game",))  # no BIOS screen to compare with
        fallback = rules.Run(rules.BOOTS, "r", "zeros", ("game",), "builtin")
        loaded = rules.Run(rules.BOOTS, "r", "other", ("game",), "staged:bios.bin")
        self.assertEqual(rules.file_use(fallback, NONE_BOOTS, present), rules.REFUSED)
        self.assertEqual(rules.file_use(loaded, NONE_BOOTS, present), rules.USED)
        self.assertIsNone(rules.file_use(run(rules.BOOTS, stages=("game",)), NONE_BOOTS, present))
        record = {"id": "x", "variants": [{"label": "a", "verdict": "boots", "bios_used": "builtin",
                                           "verdict_evidence": {"rule": "r", "detail": "d"}}]}
        self.assertEqual(rules.run_of(record, "a").bios_used, "builtin")
        builtin_none = rules.Run(rules.BOOTS, "n", "none", ("game",), "builtin")
        (hle,) = rules.rule_need(builtin_none, PRESENT, {"name": "a"})
        self.assertIn("on its built-in BIOS", hle.statement)

    def test_validation_agrees_or_adds_size(self) -> None:
        refused = run(rules.BOOTS, stages=("game",))
        used = run(rules.HANG)
        entry = {"name": "bios.bin", "validation": ["size", "md5"]}
        verdict = rules.rule_validation(refused, refused, NONE_BOOTS, PRESENT, entry)
        self.assertEqual((verdict.rule, verdict.apply), ("validation_agrees", True))
        self.assertTrue(rules.agrees(entry, verdict))
        added = rules.rule_validation(used, refused, NONE_BOOTS, PRESENT, {"name": "bios.bin"})
        self.assertEqual((added.rule, added.value, added.apply), ("validation_size_added", ["size"], True))
        self.assertFalse(rules.agrees({"name": "bios.bin"}, added))
        self.assertEqual(rules.rule_validation(used, used, NONE_BOOTS, PRESENT, {"name": "b"}).rule,
                         "validation_agrees")

    def test_validation_contradicted_is_queued(self) -> None:
        refused = run(rules.BIOS_ERROR)
        used = run(rules.HANG)
        cases = [
            (refused, None, {"name": "b", "validation": ["size"]}),        # content check undeclared
            (used, None, {"name": "b", "validation": ["md5"]}),            # declared, not done
            (None, used, {"name": "b", "validation": ["size"]}),           # half of it runs
            (used, refused, {"name": "b", "validation": {"core": ["md5"]}}),  # per-build form
        ]
        for zeros, half, entry in cases:
            verdict = rules.rule_validation(zeros, half, NONE_BOOTS, PRESENT, entry)
            self.assertEqual((verdict.rule, verdict.apply), ("validation_contradicted", False), entry)
            self.assertEqual(set(verdict.value), {"content", "size"})
            self.assertFalse(rules.agrees(entry, verdict))
        self.assertIsNone(rules.rule_validation(run(rules.UNKNOWN), None, NONE_BOOTS, PRESENT,
                                                {"name": "b"}))

    def test_a_warned_check_lets_a_wrong_file_run(self) -> None:
        """Beetle PSX logs a wrong SHA1 and boots the file (libretro.c:853-860),
        PCSX ReARMed refuses an image without the kernel's first instruction
        or "PS compatible" (frontend/libretro.c:3646-3651)."""
        refused = run(rules.BIOS_ERROR)
        used = run(rules.HANG)
        warned = {"name": "b", "validation": ["sha1"], "on_mismatch": "warn"}
        self.assertEqual(rules.rule_validation(used, used, NONE_BOOTS, PRESENT, warned).rule,
                         "validation_agrees")
        by_check = {"name": "b", "validation": ["size", "md5"], "on_mismatch": {"md5": "warn"}}
        self.assertEqual(rules.rule_validation(used, refused, NONE_BOOTS, PRESENT, by_check).rule,
                         "validation_agrees")
        self.assertEqual(rules.rule_validation(used, None, NONE_BOOTS, PRESENT,
                                               {"name": "b", "validation": ["sha1"]}).rule,
                         "validation_contradicted")
        signature = {"name": "b", "validation": ["size", "signature"]}
        self.assertEqual(rules.rule_validation(refused, None, NONE_BOOTS, PRESENT, signature).rule,
                         "validation_agrees")

    def test_path_and_alias(self) -> None:
        self.assertIsNone(rules.rule_path(self.ENTRY, "bios.bin", rules.Opened("bios.bin", self.RID)))
        moved = rules.rule_path(self.ENTRY, "bios.bin", rules.Opened("sys/bios.bin", self.RID))
        self.assertEqual((moved.field, moved.value, moved.apply), ("path", "sys/bios.bin", True))
        self.assertIsNone(rules.rule_alias(self.ENTRY, rules.Opened("Bios.bin", self.RID)))
        alias = rules.rule_alias(self.ENTRY, rules.Opened("BIOS.BIN", self.RID))
        self.assertEqual((alias.field, alias.value), ("aliases", ["Bios.bin", "BIOS.BIN"]))

    def test_never_opened_is_flagged_not_applied(self) -> None:
        verdict = rules.rule_never_opened(self.ENTRY, [self.RID], "Game (USA)")
        self.assertFalse(verdict.apply)
        self.assertEqual(verdict.rule, "never_opened")

    def test_variants(self) -> None:
        self.assertIsNone(rules.rule_variants([run(rules.BOOTS, "a"), run(rules.BOOTS, "b")], self.ENTRY))
        verdict = rules.rule_variants([run(rules.BOOTS, "b"), run(rules.HANG, "a")], self.ENTRY)
        self.assertEqual((verdict.value, verdict.apply), (["a", "b"], False))

    def test_every_settled_field_can_carry_evidence(self) -> None:
        schema = json.loads((REPO_ROOT / "schemas" / "emulator.schema.json").read_text())
        evidence = schema["properties"]["files"]["items"]["properties"]["evidence"]["properties"]
        self.assertEqual(set(rules.SETTLED_FIELDS), set(evidence))

    def test_agreement_and_evidence(self) -> None:
        self.assertTrue(rules.agrees({"name": "a"}, rules.Verdict("r", "hle_fallback", False, "", ())))
        self.assertFalse(rules.agrees({"name": "a"}, rules.Verdict("r", "hle_fallback", True, "", ())))
        self.assertTrue(rules.agrees(self.ENTRY, rules.Verdict("r", "aliases", ["Bios.bin"], "", ())))
        merged = rules.merge_evidence({"required": ["x"]}, rules.Verdict("r", "required", True, "", ("y", "x")))
        self.assertEqual(merged, {"required": ["x", "y"]})
        # An id a frame comparison wrote no longer proves the field.
        merged = rules.merge_evidence({"required": ["old"], "path": ["p"]},
                                      rules.Verdict("r", "required", True, "", ("new",)),
                                      keep=lambda rid: rid != "old")
        self.assertEqual(merged, {"path": ["p"], "required": ["new"]})

    def test_reference_candidates(self) -> None:
        def rep(hashes: list[str]) -> dict:
            return {"observables": {"frame_hashes": [[i * 10, h] for i, h in enumerate(hashes)],
                                    "uniform_frames": ["black"]}}
        record = {"variants": [{"repetitions": [
            rep(["black"] * 4 + ["logo"] * 3 + ["flash"] + ["title"] * 5),
            rep(["black"] * 5 + ["logo"] * 3 + ["title"] * 3)]}]}
        self.assertEqual(campaign.reference_candidates(record),
                         [{"sha1": "logo", "first_frame": 40, "samples": 3},
                          {"sha1": "title", "first_frame": 80, "samples": 5}])


class ProfileEditor(unittest.TestCase):
    def test_replace_insert_and_keep_the_rest(self) -> None:
        out = campaign_profiles.set_fields(PROFILE, 0, {
            "required": False, "hle_fallback": True,
            "aliases": ["Bios.bin", "BIOS.BIN"], "evidence": {"hle_fallback": ["2026-10-27-cccccccccccc"]}})
        parsed = yaml.safe_load(out)
        self.assertEqual(parsed["files"][0]["hle_fallback"], True)
        self.assertEqual(parsed["files"][0]["aliases"], ["Bios.bin", "BIOS.BIN"])
        self.assertEqual(parsed["files"][1], {"name": "other.bin", "required": False})
        self.assertIn("  # -- the BIOS --", out)
        self.assertIn('    required: false\n    hle_fallback: true\n', out)
        self.assertIn('      - "BIOS.BIN"\n', out)
        lines = out.splitlines()
        self.assertEqual(lines[lines.index('    evidence:') + 1], '      hle_fallback: ["2026-10-27-cccccccccccc"]')

    def test_the_last_entry_and_a_no_op(self) -> None:
        out = campaign_profiles.set_fields(PROFILE, 1, {"path": "sub/other.bin"})
        self.assertEqual(yaml.safe_load(out)["files"][1]["path"], "sub/other.bin")
        self.assertEqual(campaign_profiles.set_fields(PROFILE, 1, {"required": False}), PROFILE)

    def test_refusals(self) -> None:
        with self.assertRaises(campaign_profiles.ProfileEditError):
            campaign_profiles.set_fields(PROFILE, 2, {"required": False})
        with self.assertRaises(campaign_profiles.ProfileEditError):
            campaign_profiles.set_fields("emulator: X\n", 0, {"required": False})
        with self.assertRaises(campaign_profiles.ProfileEditError):
            campaign_profiles.set_fields(PROFILE, 0, {"name": "x.bin"})

    def test_every_profile_reads_as_its_entries(self) -> None:
        # The text layout the editor reads holds in every profile it may edit.
        for path in sorted((REPO_ROOT / "emulators").glob("*.yml")):
            text = path.read_text(encoding="utf-8")
            entries = (yaml.safe_load(text) or {}).get("files") or []
            if not entries or "\nfiles:\n" not in text:
                continue
            with self.subTest(profile=path.name):
                self.assertEqual(len(campaign_profiles.item_spans(text.splitlines())), len(entries))


class FakeHost(campaign.Host):
    def __init__(self, loads: list[float] | None = None, free: float = 500.0) -> None:
        super().__init__()
        self.loads = list(loads or [0.0])
        self.now = 0.0
        self.slept: list[float] = []
        self.free = free
        self.calls: list[list[str]] = []
        self.results: list[object] = []
        self.loadavg = self._load
        self.sleep = self._sleep
        self.clock = lambda: self.now
        self.free_gb = lambda path: self.free
        self.cpu_count = 4
        self.run = self._run

    def _load(self) -> tuple[float, float, float]:
        value = self.loads.pop(0) if len(self.loads) > 1 else self.loads[0]
        return (value, value, value)

    def _sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds

    def _run(self, argv, **kwargs):
        self.calls.append(list(argv))
        result = self.results.pop(0) if len(self.results) > 1 else self.results[0]
        if isinstance(result, BaseException):
            raise result
        return result


def screen(base: int) -> str:
    """The sha1 of a frame of FAKE_CORE: eight 16-bit pixels from base up."""
    return hashlib.sha1(struct.pack("<8H", *range(base, base + 8))).hexdigest()


class Workspace(unittest.TestCase):
    def setUp(self) -> None:
        TMP.mkdir(parents=True, exist_ok=True)
        self.tmp = Path(tempfile.mkdtemp(dir=TMP))
        self.root = self.tmp / "repo"
        (self.root / "emulators").mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        (self.root / "emulators" / "fake.yml").write_text(PROFILE, encoding="utf-8")
        bios = self.root / "bios" / "Fake" / "bios.bin"
        bios.parent.mkdir(parents=True)
        bios.write_bytes(b"BIOS")
        sha1 = hashlib.sha1(b"BIOS").hexdigest()
        db = {"files": {sha1: {"path": "bios/Fake/bios.bin", "name": "bios.bin", "size": 4,
                               "sha1": sha1, "md5": hashlib.md5(b"BIOS").hexdigest()}},
              "indexes": {"by_name": {"bios.bin": [sha1]}, "by_md5": {}, "by_crc32": {},
                          "by_sha256": {}, "by_path_suffix": {}}}
        (self.root / "database.json").write_text(json.dumps(db), encoding="utf-8")
        self.content_file = self.tmp / "content.yml"
        self.content_file.write_text(yaml.safe_dump({"systems": {"fake-system": {
            "romfetch": "fakesys", "content": [{
                "name": "Fake Game (World)", "catalog": "no-intro", "reason": "a test",
                "frames": 12, "frame_hash_every": 2}]}}}), encoding="utf-8")
        self.game = self.tmp / "content" / "fakesys" / "Fake Game (World)"
        self.oracle = self.tmp / "oracle.yml"
        self.oracle.write_text(yaml.safe_dump({
            "error_patterns": [], "cores": {}, "content": [{
                "name": "Fake Game (World)", "sha1": hashlib.sha1(b"GAME").hexdigest(),
                "references": {"Fake": {"recorded_from": "2026-10-27-000000000000", "frames": [
                    {"sha1": screen(1), "stage": "bios", "shows": "the fake logo"},
                    {"sha1": screen(20), "stage": "game", "shows": "the fake title"}]}}}]}),
            encoding="utf-8")
        self.paths = campaign.Paths(root=self.root, home=self.tmp / "home",
                                    content=self.tmp / "content", db=self.root / "database.json",
                                    content_file=self.content_file, oracle=self.oracle)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def put_game(self, folder: Path | None = None, payload: bytes = b"GAME") -> Path:
        folder = folder or self.game
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "game.bin").write_bytes(payload)
        (folder / "identity.json").write_text(json.dumps({"status": "verified", "files": [
            {"name": "game.bin", "size": len(payload), "sha1": hashlib.sha1(payload).hexdigest()}]}))
        return folder

    def make(self, host: campaign.Host | None = None, **settings: object) -> campaign.Campaign:
        values = {"delays": (1, 2), "echo": False, **settings}
        return campaign.Campaign(self.paths, campaign.Settings(**values), host or FakeHost(),
                                 lock_path=self.tmp / "auto.lock")


class StateAndResume(Workspace):
    def test_should_run(self) -> None:
        self.assertTrue(campaign.should_run(None, "a", "d"))
        done = {"status": "done", "core_sha256": "a", "profile_digest": "d",
                "record_version": mr.RECORD_VERSION, "oracle_sha256": ""}
        self.assertFalse(campaign.should_run(done, "a", "d"))
        # A record from before the verdicts, or judged against another oracle, runs again.
        self.assertTrue(campaign.should_run({**done, "record_version": 3}, "a", "d"))
        self.assertTrue(campaign.should_run(done, "a", "d", "f" * 64))
        self.assertTrue(campaign.should_run(done, "b", "d"))
        self.assertTrue(campaign.should_run(done, "a", "e"))
        self.assertTrue(campaign.should_run({**done, "status": "pending"}, "a", "d"))
        self.assertFalse(campaign.should_run({**done, "status": "failed"}, "a", "d"))

    def test_a_record_judged_again_is_read_in_its_place(self) -> None:
        lines = self.root / mr.records_path("fake")
        lines.parent.mkdir(parents=True, exist_ok=True)
        old = {"id": "2026-10-27-aaaaaaaaaaaa", "supersedes": None, "verdict": "old"}
        new = {"id": "2026-10-28-bbbbbbbbbbbb", "supersedes": old["id"], "verdict": "new"}
        lines.write_text("\n".join(json.dumps(r) for r in (old, new)) + "\n", encoding="utf-8")
        self.assertEqual(self.make().read_record("fake", old["id"])["verdict"], "new")
        self.assertIsNone(self.make().read_record("fake", "2026-10-27-cccccccccccc"))

    def test_only_its_own_oracle_entries_make_a_check_run_again(self) -> None:
        key = [hashlib.sha1(b"GAME").hexdigest(), "Fake"]
        before = self.make().oracle_digest(key)
        data = yaml.safe_load(self.oracle.read_text())
        data["content"][0]["references"]["Other"] = {"recorded_from": "2026-10-27-000000000000",
                                                     "frames": [{"sha1": "a" * 40, "stage": "game",
                                                                 "shows": "x"}]}
        self.oracle.write_text(yaml.safe_dump(data), encoding="utf-8")
        self.assertEqual(self.make().oracle_digest(key), before)
        data["cores"] = {"Fake": {"error_patterns": [{"pattern": "BIOS", "reason": "r"}]}}
        self.oracle.write_text(yaml.safe_dump(data), encoding="utf-8")
        self.assertNotEqual(self.make().oracle_digest(key), before)

    def test_evidence_does_not_change_the_digest(self) -> None:
        profile = yaml.safe_load(PROFILE)
        before = campaign.profile_digest(profile)
        profile["files"][0]["evidence"] = {"required": ["2026-10-27-dddddddddddd"]}
        self.assertEqual(campaign.profile_digest(profile), before)
        profile["files"][0]["required"] = False
        self.assertNotEqual(campaign.profile_digest(profile), before)

    def test_state_survives_a_reload(self) -> None:
        c = self.make()
        c.pending("fake", "fake/fake-system/x/files", "content: romfetch not found")
        campaign.save_state(self.paths.state, c.state)
        again = self.make()
        self.assertEqual(again.state["checks"]["fake"]["fake/fake-system/x/files"]["status"], "pending")

    def test_budget(self) -> None:
        self.assertEqual(campaign.parse_budget("6h"), 21600)
        self.assertEqual(campaign.parse_budget("90m"), 5400)
        self.assertEqual(campaign.parse_budget("30"), 30)


class Guards(Workspace):
    def test_busy_host_waits_then_runs(self) -> None:
        host = FakeHost(loads=[5.0, 5.0, 0.5])
        c = self.make(host, max_load_wait=600)
        c.deadline = 10_000
        c.guard()
        self.assertEqual(host.slept, [60.0, 60.0])

    def test_busy_host_pauses(self) -> None:
        host = FakeHost(loads=[5.0])
        c = self.make(host, max_load_wait=120)
        c.deadline = 10_000
        with self.assertRaisesRegex(campaign.Pause, "busy host"):
            c.guard()

    def test_full_disk_pauses(self) -> None:
        c = self.make(FakeHost(free=10.0), min_free_gb=30)
        c.deadline = 10_000
        with self.assertRaisesRegex(campaign.Pause, "disk"):
            c.guard()

    def test_budget_pauses(self) -> None:
        c = self.make()
        c.deadline = 0
        with self.assertRaisesRegex(campaign.Pause, "budget"):
            c.guard()

    def test_the_lock_is_skipped_under_autorun(self) -> None:
        lock = self.tmp / "held.lock"
        with campaign.autorun.global_lock(lock):
            with self.assertRaises(campaign.autorun.LockBusy), campaign.host_lock(lock):
                pass
            os.environ[campaign.LOCK_HELD_ENV] = "1"
            try:
                with campaign.host_lock(lock):
                    pass
            finally:
                del os.environ[campaign.LOCK_HELD_ENV]


class ChildEnvironment(unittest.TestCase):
    def test_probes_builds_and_romfetch_get_no_secret(self) -> None:
        host = {"GITHUB_TOKEN": "t", "GH_TOKEN": "t", "ROMSTATION_USER": "u", "ROMSTATION_PASS": "p",
                "ROMFETCH_CONTENT_DIR": "/c", "SSH_AUTH_SOCK": "/s", "PATH": "/usr/bin"}
        with unittest.mock.patch.dict(os.environ, host):
            probe, fetch = campaign.child_env(), campaign.child_env(romfetch=True)
        for env in (probe, fetch):
            self.assertFalse({"GITHUB_TOKEN", "GH_TOKEN", "ROMSTATION_USER", "ROMSTATION_PASS",
                              "SSH_AUTH_SOCK"} & set(env))
            self.assertEqual(env["PATH"], "/usr/bin")
        self.assertNotIn("ROMFETCH_CONTENT_DIR", probe)
        self.assertEqual(fetch["ROMFETCH_CONTENT_DIR"], "/c")

    def test_the_probe_is_started_with_that_environment(self) -> None:
        seen: list[dict] = []
        host = FakeHost()
        host.run = lambda argv, **kw: (seen.append(kw.get("env")),
                                       subprocess.CompletedProcess([], 0, '{"id": "x"}', ""))[1]
        with tempfile.TemporaryDirectory(dir=TMP) as tmp:
            paths = campaign.Paths(root=Path(tmp), home=Path(tmp) / "h", content=Path(tmp) / "c",
                                   db=Path(tmp) / "db.json", content_file=campaign.CONTENT_FILE)
            c = campaign.Campaign(paths, campaign.Settings(echo=False), host, lock_path=Path(tmp) / "l")
            c.deadline = 10_000
            with unittest.mock.patch.dict(os.environ, {"GITHUB_TOKEN": "t"}):
                c.probe(["run"], "x")
        self.assertNotIn("GITHUB_TOKEN", seen[0])


class FailClosed(Workspace):
    """No core and no build runs outside the sandbox unless asked."""

    def test_a_pass_without_a_sandbox_is_refused(self) -> None:
        host = FakeHost()
        host.results = [subprocess.CompletedProcess([], 0, "{}", "")]
        c = self.make(host)
        with unittest.mock.patch.object(campaign.core_probe.shutil, "which", return_value=None):
            current = c.run(set(), None)
        self.assertEqual(current.result, "refused")
        self.assertIn("bwrap not found", current.detail)
        self.assertEqual(host.calls, [])
        self.assertEqual(mr.read_campaign(self.root, mr.CAMPAIGN_RUNS)[-1]["result"], "refused")

    def test_the_override_lets_it_run(self) -> None:
        c = self.make(allow_unsandboxed=True)
        c.unit_cores = lambda *a, **k: []
        with unittest.mock.patch.object(campaign.core_probe.shutil, "which", return_value=None):
            self.assertEqual(c.run(set(), None).result, "complete")

    def test_every_probe_requires_the_sandbox(self) -> None:
        core = campaign.Core("fake", self.tmp / "x.so", "a" * 64)
        self.assertIn("--require-sandbox", self.make().probe_args("run", core, "fake", "s", None, None))
        self.assertNotIn("--require-sandbox", self.make(allow_unsandboxed=True).probe_args(
            "run", core, "fake", "s", None, None))

    def test_a_build_without_a_sandbox_is_refused(self) -> None:
        c = self.make()
        src = c.paths.home / "src" / campaign.slug("https://example.invalid/x")
        (src / ".git").mkdir(parents=True)
        (src / "Makefile").write_text("all:\n")
        host = c.host
        host.results = [subprocess.CompletedProcess([], 0, "", "")]
        with unittest.mock.patch.object(campaign.core_probe.shutil, "which", return_value=None), \
                self.assertRaisesRegex(campaign.Unavailable, "refused: no sandbox"):
            c.cores.compile("https://example.invalid/x", "a" * 40, self.tmp / "out")
        self.assertFalse(any(call[0] == "make" for call in host.calls))


@unittest.skipUnless(shutil.which("git") and shutil.which("make"), "no git or make")
class BuildIsolation(unittest.TestCase):
    """Builds run on an archive exported from bare mirrors that only host git
    touches: a build cannot reach the mirror, and host git runs nothing a
    repository's config or attributes name."""

    MAIN = "https://example.invalid/team/main.git"
    SUB = "https://example.invalid/team/sub.git"

    def setUp(self) -> None:
        TMP.mkdir(parents=True, exist_ok=True)
        self.tmp = Path(tempfile.mkdtemp(dir=TMP))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.pwned = self.tmp / "PWNED"
        sub = self.repo("sub", {"sub.c": "int x;\n"})
        self.sub_sha = self.git(sub, "rev-parse", "HEAD").strip()
        self.mirrors = {self.SUB: self.bare(sub, "sub")}
        main_mirror = self.tmp / "mirrors" / "main.git"
        # A Makefile that tries to plant a hook and a config line in the mirror.
        makefile = (
            "all:\n"
            f"\t-mkdir -p {main_mirror}/hooks\n"
            f"\t-echo 'touch {self.pwned}' > {main_mirror}/hooks/post-checkout\n"
            f"\t-printf '[core]\\n\\tfsmonitor = touch {self.pwned}\\n' >> {main_mirror}/config\n"
            "\ttouch fake_libretro.so\n")
        main = self.repo("main", {"Makefile": makefile, ".gitmodules":
                                  '[submodule "lib"]\n\tpath = lib\n\turl = ../sub.git\n'})
        self.git(main, "update-index", "--add", "--cacheinfo", f"160000,{self.sub_sha},lib")
        self.git(main, "commit", "-q", "-m", "submodule")
        self.commit = self.git(main, "rev-parse", "HEAD").strip()
        self.mirrors[self.MAIN] = self.bare(main, "main")
        self.config = (main_mirror / "config").read_text()

    def git(self, repo: Path, *args: str) -> str:
        return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-C", str(repo), *args],
                              check=True, capture_output=True, text=True).stdout

    def repo(self, name: str, files: dict[str, str]) -> Path:
        path = self.tmp / "work" / name
        subprocess.run(["git", "init", "-q", str(path)], check=True)
        for rel, text in files.items():
            (path / rel).write_text(text)
        self.git(path, "add", *files)
        self.git(path, "commit", "-q", "-m", "one")
        return path

    def bare(self, work: Path, name: str) -> Path:
        path = self.tmp / "mirrors" / f"{name}.git"
        subprocess.run(["git", "clone", "-q", "--bare", str(work), str(path)], check=True)
        return path

    def test_the_export_holds_the_tree_and_its_submodule_and_no_git(self) -> None:
        tree = self.tmp / "tree"
        campaign.export_commit(self.mirrors.__getitem__, self.MAIN, self.commit, tree)
        self.assertEqual((tree / "lib" / "sub.c").read_text(), "int x;\n")
        self.assertTrue((tree / "Makefile").is_file())
        self.assertEqual([p for p in tree.rglob(".git")], [])

    def test_a_build_cannot_reach_the_mirror(self) -> None:
        tree = self.tmp / "tree"
        prefix, isolation = campaign.core_probe.sandbox_argv([tree])
        if isolation != campaign.core_probe.SANDBOX:
            self.skipTest("no working bwrap on this host")
        campaign.export_commit(self.mirrors.__getitem__, self.MAIN, self.commit, tree)
        proc = subprocess.run(prefix + ["make"], cwd=tree, capture_output=True, text=True,
                              check=False, env=campaign.child_env())
        self.assertEqual(proc.returncode, 0, proc.stderr)
        mirror = self.mirrors[self.MAIN]
        self.assertFalse((mirror / "hooks" / "post-checkout").exists())
        self.assertEqual((mirror / "config").read_text(), self.config)
        campaign.export_commit(self.mirrors.__getitem__, self.MAIN, self.commit, self.tmp / "again")
        self.assertFalse(self.pwned.exists())

    def test_host_git_runs_nothing_a_repository_config_names(self) -> None:
        mirror = self.mirrors[self.MAIN]
        hook = mirror / "hooks" / "reference-transaction"
        hook.write_text(f"#!/bin/sh\ntouch {self.pwned}\n")
        hook.chmod(0o755)
        with (mirror / "config").open("a") as handle:
            handle.write(f"[core]\n\tfsmonitor = touch {self.pwned}\n\tsshCommand = touch {self.pwned}\n"
                         f'[filter "x"]\n\tsmudge = touch {self.pwned}\n')
        (mirror / "info").mkdir(exist_ok=True)
        (mirror / "info" / "attributes").write_text("* filter=x\n")
        campaign.export_commit(self.mirrors.__getitem__, self.MAIN, self.commit, self.tmp / "tree")
        campaign.git_out("-C", str(mirror), "update-ref", "refs/x", self.commit)
        self.assertFalse(self.pwned.exists())
        # Plain git on the same mirror runs the planted hook: the test plants a live one.
        subprocess.run(["git", "-C", str(mirror), "update-ref", "refs/y", self.commit], check=True)
        self.assertTrue(self.pwned.exists())

    def test_only_https_mirrors(self) -> None:
        c = campaign.Campaign(campaign.Paths(root=self.tmp, home=self.tmp / "home", content=self.tmp,
                                             db=self.tmp / "db.json", content_file=campaign.CONTENT_FILE),
                              campaign.Settings(echo=False), FakeHost(), lock_path=self.tmp / "l")
        for url in ("file:///etc", "/home/x/repo", "ext::sh -c touch", "ssh://h/r", "git@h:r"):
            with self.subTest(url=url), self.assertRaises(campaign.Unavailable):
                c.cores.mirror(url)
        self.assertEqual(campaign.submodule_url(self.MAIN, "../sub.git"), self.SUB)
        self.assertEqual(campaign.git_env()["GIT_ALLOW_PROTOCOL"], "https")

    def test_a_whole_build_wipes_old_clones_and_copies_a_regular_file(self) -> None:
        if campaign.core_probe.sandbox_argv([])[1] != campaign.core_probe.SANDBOX:
            self.skipTest("no working bwrap on this host")
        home = self.tmp / "home"
        (home / "src" / "old" / ".git").mkdir(parents=True)
        c = campaign.Campaign(campaign.Paths(root=self.tmp, home=home, content=self.tmp,
                                             db=self.tmp / "db.json", content_file=campaign.CONTENT_FILE),
                              campaign.Settings(echo=False), campaign.Host(), lock_path=self.tmp / "l")
        c.cores.mirror = self.mirrors.__getitem__
        so, command = c.cores.compile(self.MAIN, self.commit, self.tmp / "out")
        self.assertEqual(so, self.tmp / "out" / "fake_libretro.so")
        self.assertIn("isolation: bwrap", command)
        self.assertFalse((home / "src").exists())


class BuiltCore(unittest.TestCase):
    def setUp(self) -> None:
        TMP.mkdir(parents=True, exist_ok=True)
        self.tree = Path(tempfile.mkdtemp(dir=TMP))
        self.addCleanup(shutil.rmtree, self.tree, True)
        self.secret = self.tree.parent / f"{self.tree.name}-host-file"
        self.secret.write_text("host secret")
        self.addCleanup(self.secret.unlink)

    def test_a_link_is_never_taken_for_the_core(self) -> None:
        (self.tree / "a_libretro.so").symlink_to(self.secret)
        with self.assertRaises(campaign.Unavailable):
            campaign.built_core(self.tree)
        (self.tree / "sub").mkdir()
        (self.tree / "sub" / "b_libretro.so").write_bytes(b"\x7fELF")
        self.assertEqual(campaign.built_core(self.tree), self.tree / "sub" / "b_libretro.so")

    def test_copy_refuses_a_link(self) -> None:
        link = self.tree / "c_libretro.so"
        link.symlink_to(self.secret)
        with self.assertRaises(OSError):
            campaign.copy_regular(link, self.tree / "out.so")
        self.assertFalse((self.tree / "out.so").exists())


class ProbeRuns(Workspace):
    def completed(self, code: int, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess([], code, stdout, stderr)

    def probe(self, *results: object) -> tuple[campaign.ProbeResult, FakeHost]:
        host = FakeHost()
        host.results = list(results)
        c = self.make(host)
        c.deadline = 10_000
        return c.probe(["run", "--core", "x.so"], "fake-run"), host

    def test_timeout_is_failed_and_not_retried(self) -> None:
        result, host = self.probe(subprocess.TimeoutExpired(["x"], 1))
        self.assertEqual((result.status, result.reason), ("failed", "timeout"))
        self.assertEqual(len(host.calls), 1)
        self.assertIn("killed after", Path(result.log).read_text())
        result, host = self.probe(self.completed(1, stderr="subprocess.TimeoutExpired: timed out after 900 seconds"))
        self.assertEqual((result.reason, len(host.calls)), ("timeout", 1))

    def test_a_crashing_core_is_tried_three_times(self) -> None:
        result, host = self.probe(self.completed(1, stderr="worker exited -11"))
        self.assertEqual((result.status, result.reason), ("failed", "crashed 3 times"))
        self.assertEqual(len(host.calls), 3)

    def test_a_crash_then_a_record(self) -> None:
        record = {"id": "2026-10-27-eeeeeeeeeeee"}
        result, host = self.probe(self.completed(1, stderr="worker exited -11"),
                                  self.completed(0, stdout=json.dumps(record)))
        self.assertEqual((result.status, result.record, len(host.calls)), ("done", record, 2))

    def test_refusal_on_a_busy_host_pauses(self) -> None:
        with self.assertRaisesRegex(campaign.Pause, "busy host"):
            self.probe(self.completed(3, stderr="load average"))


class Content(Workspace):
    def content(self, name: str = "Fake Game (World)", pinned: bool = False) -> campaign.Content:
        return campaign.Content("fake-system", "fakesys", name, "no-intro", "r", None, "", 12, 2,
                                pinned, None)

    def test_local_content_is_verified_by_its_identity(self) -> None:
        self.put_game()
        c = self.make()
        self.assertEqual(c.store.get(self.content()), self.game)
        (self.game / "game.bin").write_bytes(b"EDIT")
        with self.assertRaisesRegex(campaign.Unavailable, "does not match"):
            self.make().store.get(self.content())

    def test_without_romfetch_the_check_waits_for_content(self) -> None:
        c = self.make(romfetch=str(self.tmp / "absent-romfetch"))
        with self.assertRaisesRegex(campaign.Unavailable, "romfetch not found"):
            c.store.get(self.content())

    def test_romfetch_is_retried_on_a_source_error(self) -> None:
        fetcher = self.tmp / "romfetch"
        fetcher.write_text("#!/bin/sh\n")
        fetcher.chmod(0o755)
        host = FakeHost()
        error = json.dumps({"error": {"code": "network", "message": "m", "hint": "h"}})
        game = self.game

        def fetched(*args, **kwargs):
            self.put_game(game)
            return subprocess.CompletedProcess([], 0, '{"status": "verified"}', "")
        host.results = [subprocess.CompletedProcess([], 3, error, ""), None]
        host.run = lambda argv, **kw: (host.calls.append(argv), fetched() if len(host.calls) == 2
                                        else host.results[0])[1]
        c = self.make(host, romfetch=str(fetcher))
        self.assertEqual(c.store.get(self.content()), self.game)
        self.assertEqual(host.slept, [1])
        self.assertEqual(host.calls[0][1:4], ["get", "fakesys", "Fake Game (World)"])
        self.assertTrue(c.state["content"]["fakesys/Fake Game (World)"]["fetched_by_campaign"])

    def test_romfetch_not_found_names_its_code(self) -> None:
        fetcher = self.tmp / "romfetch"
        fetcher.write_text("#!/bin/sh\n")
        host = FakeHost()
        host.results = [subprocess.CompletedProcess(
            [], 1, json.dumps({"error": {"code": "no_entry", "message": "m", "hint": "h"}}), "")]
        c = self.make(host, romfetch=str(fetcher))
        with self.assertRaisesRegex(campaign.Unavailable, r"exit 1 \(no_entry\)"):
            c.store.get(self.content())
        self.assertEqual(len(host.calls), 1)

    def test_shared_content_stays_until_its_last_user(self) -> None:
        c = self.make()
        self.put_game()
        content = self.content()
        c.state["content"][content.key] = {"fetched_by_campaign": True, "pinned": False, "size": 4}
        c.store.hold(content, "alpha")
        c.store.hold(content, "beta")
        c.store.release(content, "alpha")
        self.assertTrue(self.game.is_dir())
        c.store.release(content, "beta")
        self.assertFalse(self.game.exists())

    def test_pinned_or_foreign_content_is_never_deleted(self) -> None:
        c = self.make()
        self.put_game()
        content = self.content(pinned=True)
        c.state["content"][content.key] = {"fetched_by_campaign": True, "pinned": True}
        c.store.hold(content, "alpha")
        c.store.release(content, "alpha")
        self.assertTrue(self.game.is_dir())
        c.state["content"][content.key] = {"fetched_by_campaign": False, "pinned": False}
        c.store.hold(content, "alpha")
        c.store.release(content, "alpha")
        self.assertTrue(self.game.is_dir())

    def test_least_recently_used_goes_first_past_the_cap(self) -> None:
        c = self.make(cache_cap_gb=5e-9)
        for name, used in (("Old", "2026-01-01"), ("New", "2026-06-01"), ("Kept", "2025-01-01")):
            self.put_game(self.tmp / "content" / "fakesys" / name)
            c.state["content"][f"fakesys/{name}"] = {"fetched_by_campaign": True, "pinned": name == "Kept",
                                                     "size": 4, "last_used": used}
        self.assertEqual(c.store.evict(keep=set()), ["fakesys/Old"])
        self.assertTrue((self.tmp / "content" / "fakesys" / "New").is_dir())
        self.assertTrue((self.tmp / "content" / "fakesys" / "Kept").is_dir())

    def test_load_file(self) -> None:
        self.put_game()
        self.assertEqual(campaign.load_file(self.game, ""), self.game / "game.bin")
        with self.assertRaises(campaign.Unavailable):
            campaign.load_file(self.game, "cue")


class Findings(Workspace):
    RID = "2026-10-27-ffffffffffff"

    def setUp(self) -> None:
        super().setUp()
        self.c = self.make()
        self.c.current = campaign.Pass(started=campaign.now_iso())
        self.content = campaign.Content("fake-system", "fakesys", "Fake Game (World)", "no-intro",
                                        "r", None, "", 12, 2, False, None)
        self.core = campaign.Core("fake", self.tmp / "fake_libretro.so", "a" * 64)
        self.profile = self.root / "emulators" / "fake.yml"

    def lines(self) -> list[dict]:
        return mr.read_campaign(self.root, mr.FINDINGS)

    def entry(self, index: int = 0) -> dict:
        return yaml.safe_load(self.profile.read_text())["files"][index]

    def none(self, verdict: str) -> rules.Run:
        return rules.Run(verdict, self.RID, "none")

    def present(self) -> rules.Run:
        return rules.Run(rules.BOOTS, self.RID, "bios.bin", ("game",))

    def test_a_settled_field_is_written_with_its_evidence(self) -> None:
        verdicts = rules.rule_need(self.none(rules.BOOTS), self.present(), self.entry())
        self.c.settle("fake", self.content, self.core, 0, self.entry(), verdicts)
        entry = self.entry()
        self.assertEqual(entry["hle_fallback"], True)
        self.assertEqual(entry["evidence"], {"hle_fallback": [self.RID]})
        self.assertEqual(entry["required"], True)
        self.assertEqual([(line["field"], line["status"]) for line in self.lines()],
                         [("hle_fallback", "applied"), ("required", "open")])
        self.assertIn("emulators/fake.yml", self.c.current.touched)
        # The same outcome a second time adds nothing.
        self.c.settle("fake", self.content, self.core, 0, self.entry(), verdicts)
        self.assertEqual(len(self.lines()), 2)

    def test_an_agreeing_run_adds_evidence_only(self) -> None:
        verdicts = rules.rule_need(self.none(rules.HANG), self.present(), self.entry())
        self.c.settle("fake", self.content, self.core, 0, self.entry(), verdicts)
        entry = self.entry()
        self.assertEqual((entry["required"], entry["hle_fallback"]), (True, False))
        self.assertEqual(entry["evidence"], {"hle_fallback": [self.RID], "required": [self.RID]})
        self.assertEqual(self.lines(), [])

    def test_a_later_agreement_resolves_the_open_finding(self) -> None:
        (verdict,) = rules.rule_need(self.none(rules.UNKNOWN), self.present(), self.entry())
        self.c.settle("fake", self.content, self.core, 0, self.entry(), [verdict])
        self.assertEqual(self.lines()[-1]["status"], "open")
        later = rules.Verdict("inconclusive", "hle_fallback", False, "agrees now", ("2026-10-28-000000000000",))
        self.c.settle("fake", self.content, self.core, 0, self.entry(), [later])
        self.assertEqual([line["status"] for line in self.lines()], ["open", "resolved"])

    def test_new_evidence_writes_the_finding_again(self) -> None:
        verdict = rules.Verdict("unsettled", "hle_fallback", None, "x", (self.RID,))
        self.c.settle("fake", self.content, self.core, 0, self.entry(), [verdict])
        self.c.settle("fake", self.content, self.core, 0, self.entry(), [verdict])
        later = rules.Verdict("unsettled", "hle_fallback", None, "x", ("2026-10-28-000000000000",))
        self.c.settle("fake", self.content, self.core, 0, self.entry(), [later])
        self.assertEqual([line["evidence"] for line in self.lines()],
                         [[self.RID], ["2026-10-28-000000000000"]])

    def test_never_opened_is_flagged(self) -> None:
        verdict = rules.rule_never_opened(self.entry(1), [self.RID], "Fake Game (World)")
        self.c.settle("fake", self.content, self.core, 1, self.entry(1), [verdict])
        self.assertEqual(self.lines()[0]["status"], "flagged")
        self.assertNotIn("evidence", self.entry(1))

    def test_finding_lines_validate(self) -> None:
        verdicts = rules.rule_need(self.none(rules.BOOTS), self.present(), self.entry())
        self.c.settle("fake", self.content, self.core, 0, self.entry(), verdicts)
        self.c.write_run_line(self.c.current)
        try:
            from jsonschema import Draft202012Validator
        except ImportError:
            self.skipTest("jsonschema is a tooling dependency")
        for name, (_, schema_name) in mr.CAMPAIGN_FILES.items():
            schema = json.loads((REPO_ROOT / "schemas" / schema_name).read_text())
            for line in mr.read_campaign(self.root, name):
                self.assertEqual(list(Draft202012Validator(schema).iter_errors(line)), [], name)

    def contradicted(self) -> rules.Verdict:
        return rules.rule_validation(rules.Run(rules.HANG, self.RID, "zeros"), None,
                                     self.none(rules.BOOTS), self.present(),
                                     {**self.entry(), "validation": ["md5"]})

    def test_a_review_applies_through_the_profile_editor(self) -> None:
        self.c.settle("fake", self.content, self.core, 0, self.entry(), [self.contradicted()])
        key = self.lines()[-1]["key"]
        with self.assertRaises(ValueError):
            campaign.review_finding(self.root, key, "applied", " ")
        line = campaign.review_finding(self.root, key, "applied", "the core logs the md5 (x.c:1)",
                                       {"on_mismatch": "warn"})
        self.assertEqual((line["status"], line["reason"]), ("applied", "the core logs the md5 (x.c:1)"))
        entry = self.entry()
        self.assertEqual(entry["on_mismatch"], "warn")
        self.assertEqual(entry["evidence"], {"validation": [self.RID]})
        text = self.profile.read_text()
        self.assertLess(text.index("validation: [size]"), text.index("on_mismatch"))
        self.assertEqual(campaign.open_findings(self.root), [])
        with self.assertRaises(ValueError):
            campaign.review_finding(self.root, key, "rejected", "again")
        try:
            from jsonschema import Draft202012Validator
        except ImportError:
            self.skipTest("jsonschema is a tooling dependency")
        schema = json.loads((REPO_ROOT / "schemas" / "campaign-finding.schema.json").read_text())
        for found in self.lines():
            self.assertEqual(list(Draft202012Validator(schema).iter_errors(found)), [])

    def test_a_rejected_finding_stays_closed_on_the_same_run(self) -> None:
        verdict = self.contradicted()
        self.c.settle("fake", self.content, self.core, 0, self.entry(), [verdict])
        key = self.lines()[-1]["key"]
        with self.assertRaises(ValueError):
            campaign.review_finding(self.root, key, "rejected", "kept", {"required": False})
        out = io.StringIO()
        with contextlib.redirect_stdout(out), unittest.mock.patch.object(campaign.Paths, "default",
                                                                return_value=self.paths):
            self.assertEqual(campaign.main(["review", key, "--status", "rejected",
                                            "--reason", "the md5 is checked (x.c:2)"]), 0)
        before = self.profile.read_text()
        later = rules.Verdict(verdict.rule, verdict.field, verdict.value, verdict.statement,
                              ("2026-10-28-000000000000",))
        self.c.settle("fake", self.content, self.core, 0, self.entry(), [later])
        self.assertEqual([line["status"] for line in self.lines()], ["open", "rejected"])
        self.assertEqual(self.profile.read_text(), before)

    def test_the_batch_commit_plan(self) -> None:
        verdicts = rules.rule_need(self.none(rules.BOOTS), self.present(), self.entry())
        self.c.settle("fake", self.content, self.core, 0, self.entry(), verdicts)
        self.c.current.touched.add(mr.records_path("fake"))
        plan = self.c.plan_commits(set())
        self.assertEqual(plan, [
            ("chore: add campaign measurements", ["measurements/fake.jsonl", "measurements/findings.jsonl"]),
            ("chore: apply tested fields to fake", ["emulators/fake.yml"])])
        for subject, _ in plan:
            self.assertEqual(campaign.autorun.check_subject(subject), [], subject)
        # A file someone had changed before the pass is left to them.
        self.assertEqual(self.c.plan_commits({"emulators/fake.yml"})[1:], [])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(self.c.commit_batch(dry_run=True), [])
        self.assertIn("would commit 'chore: add campaign measurements'", out.getvalue())


class ContentFile(Workspace):
    def test_a_content_list_can_be_named(self) -> None:
        other = self.tmp / "other.yml"
        other.write_text(yaml.safe_dump({"systems": {"fake-system": {
            "romfetch": "fakesys", "content": [{"name": "Other Game (Japan)", "catalog": "redump",
                                                "reason": "r"}]}}}), encoding="utf-8")
        out = io.StringIO()
        with unittest.mock.patch.object(campaign.Paths, "default", return_value=self.paths), \
                contextlib.redirect_stdout(out):
            self.assertEqual(campaign.main(["run", "--dry-run", "--content-file", str(other)]), 0)
        self.assertIn("Other Game (Japan)", out.getvalue())


class Registry(unittest.TestCase):
    def test_no_profile_takes_a_campaign_file_name(self) -> None:
        stems = {p.stem for p in (REPO_ROOT / "emulators").glob("*.yml")}
        self.assertEqual(stems & set(mr.CAMPAIGN_FILES), set())

    def test_content_list(self) -> None:
        content = campaign.load_content(campaign.CONTENT_FILE)
        systems = {s for p in (REPO_ROOT / "emulators").glob("*.yml")
                   for s in (yaml.safe_load(p.read_text()) or {}).get("systems") or ()}
        self.assertTrue(content)
        for system, items in content.items():
            self.assertIn(system, systems)
            for item in items:
                self.assertIn(item.catalog, ("redump", "no-intro"))
                self.assertGreater(len(item.reason), 40)
                self.assertGreater(item.frames, item.frame_hash_every)

    def test_no_job_runs_a_standing_campaign(self) -> None:
        """A daily pass over every profile contradicted the rule that probes
        run on demand, for a question that names its profiles."""
        for name, job in campaign.autorun.load_jobs().items():
            for step in [*job.steps, *job.gate]:
                with self.subTest(job=name):
                    self.assertNotIn("scripts/campaign.py", step.argv)


@unittest.skipUnless(shutil.which("cc") and shutil.which("strace"), "no C compiler or no strace")
class FakeCorePasses(Workspace):
    """Whole passes against a core compiled from FAKE_CORE."""

    @classmethod
    def setUpClass(cls) -> None:
        # These passes prove the cores run sandboxed. Without a working bwrap
        # the campaign refuses, and the cause is named here instead of a KeyError.
        _prefix, isolation = campaign.core_probe.sandbox_argv([Path(tempfile.gettempdir())])
        if isolation != campaign.core_probe.SANDBOX:
            raise unittest.SkipTest(f"no sandbox here ({isolation}): install bubblewrap")
        TMP.mkdir(parents=True, exist_ok=True)
        cls.build = Path(tempfile.mkdtemp(dir=TMP))
        source = cls.build / "fake.c"
        source.write_text(FAKE_CORE, encoding="utf-8")
        # The core sees no variable of the host, so its behaviour is compiled in.
        cls.cores = {}
        for kind, flags in (("plain", []), ("hle", ["-DFAKE_HLE"]), ("hang", ["-DFAKE_HANG"])):
            cls.cores[kind] = cls.build / f"fake_{kind}_libretro.so"
            subprocess.run(["cc", "-shared", "-fPIC", *flags, "-o", str(cls.cores[kind]), str(source)],
                           check=True)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.build, ignore_errors=True)

    def passing(self, kind: str = "plain", core: Path | None = None,
                **settings: object) -> campaign.Campaign:
        self.put_game()
        # The core_probe threshold follows the host: a test never waits on the real load.
        host = campaign.Host(loadavg=lambda: (0.0, 0.0, 0.0), free_gb=lambda path: 500.0,
                             cpu_count=1_000_000)
        values = {"bench_warmup": 2, "bench_frames": 4, "check_repeat": 2, "probe_timeout": 30,
                  "delays": (1,), "echo": False, **settings}
        c = campaign.Campaign(self.paths, campaign.Settings(**values), host,
                              lock_path=self.tmp / "auto.lock")
        so = core or self.cores[kind]
        c.unit_cores = lambda *a, **k: [campaign.Core("fake", so, campaign.file_sha256(so))]
        return c

    def test_a_stand_in_is_proven_and_written(self) -> None:
        c = self.passing("hle")
        current = c.run(set(), None)
        self.assertEqual(current.result, "complete")
        records = [s.record for s in mr.read_records(self.root)]
        isolations = {rep["isolation"] for r in records for v in r["variants"] for rep in v["repetitions"]}
        self.assertEqual(isolations, {campaign.core_probe.SANDBOX})
        kinds = sorted(r["subject"].split("-")[0] for r in records)
        self.assertEqual(kinds, ["alias", "files", "negative", "none"])
        by_kind = {r["subject"].split("-")[0]: r for r in records}
        self.assertEqual(by_kind["files"]["variants"][0]["verdict"], "boots")
        self.assertEqual(by_kind["none"]["variants"][0]["verdict_evidence"]["stages"], ["game"])
        self.assertEqual(by_kind["negative"]["check"]["result"]["verdicts"],
                         {"bios.bin": "boots", "bios.bin-zeros-4": "hang",
                          "bios.bin-head-2-of-bios.bin": "boots"})
        entry = yaml.safe_load((self.root / "emulators" / "fake.yml").read_text())["files"][0]
        self.assertEqual(entry["hle_fallback"], True)
        self.assertEqual(entry["validation"], ["size"])
        self.assertEqual(entry["evidence"], {
            "aliases": [by_kind["alias"]["id"]], "hle_fallback": [by_kind["none"]["id"]],
            "validation": [by_kind["none"]["id"], by_kind["negative"]["id"]]})
        statuses = {(f["field"], f["status"]) for f in mr.read_campaign(self.root, mr.FINDINGS)}
        self.assertEqual(statuses, {("hle_fallback", "applied"), ("required", "open"),
                                    ("aliases", "applied")})
        runs = mr.read_campaign(self.root, mr.CAMPAIGN_RUNS)
        self.assertEqual(runs[-1]["counts"]["done"], 4)
        # The game is pinned by nobody but was not fetched by the campaign: kept.
        self.assertTrue(self.game.is_dir())

        # A second pass on the same core and profile runs nothing.
        again = self.passing("hle")
        self.assertEqual(again.run(set(), None).records, [])

        # A new build of the core runs everything again.
        rebuilt = self.build / "fake2_libretro.so"
        shutil.copy2(self.cores["hle"], rebuilt)
        with rebuilt.open("ab") as handle:
            handle.write(b"\0")
        third = self.passing("hle", core=rebuilt)
        # BIOS.BIN is declared now, so no alias run follows.
        self.assertEqual(len(third.run(set(), None).records), 3)

    def test_a_size_check_the_profile_lacks_is_written(self) -> None:
        profile = self.root / "emulators" / "fake.yml"
        profile.write_text(PROFILE.replace("    validation: [size]\n", ""), encoding="utf-8")
        self.passing("hle").run(set(), None)
        entry = yaml.safe_load(profile.read_text())["files"][0]
        self.assertEqual(entry["validation"], ["size"])
        applied = {f["field"] for f in mr.read_campaign(self.root, mr.FINDINGS) if f["status"] == "applied"}
        self.assertIn("validation", applied)

    def test_bench_runs_only_when_asked(self) -> None:
        self.passing("plain", bench=True).run(set(), None)
        subjects = [s.record["subject"] for s in mr.read_records(self.root)]
        self.assertEqual(sum(s.startswith("bench") for s in subjects), 1)

    def test_no_stand_in_settles_required_and_finds_an_alias(self) -> None:
        c = self.passing()
        c.run(set(), None)
        entry = yaml.safe_load((self.root / "emulators" / "fake.yml").read_text())["files"][0]
        self.assertEqual((entry["required"], entry["hle_fallback"]), (True, False))
        self.assertIn("BIOS.BIN", entry["aliases"])
        self.assertEqual(sorted(entry["evidence"]), ["aliases", "hle_fallback", "required"])
        alias = [f for f in mr.read_campaign(self.root, mr.FINDINGS) if f["field"] == "aliases"]
        self.assertEqual(alias[0]["status"], "applied")

    def test_a_hung_core_is_killed_and_the_pass_moves_on(self) -> None:
        c = self.passing("hang", probe_timeout=2)
        c.run(set(), None)
        # The whole process group went with the run: no worker spins on.
        left = subprocess.run(["pgrep", "-f", str(self.cores["hang"])], capture_output=True, check=False)
        self.assertEqual(left.stdout, b"")
        checks = c.state["checks"]["fake"]
        self.assertTrue(checks)
        # A run killed after its timeout is a record whose verdict is a hang.
        self.assertEqual({entry["status"] for entry in checks.values()}, {"done"})
        records = [s.record for s in mr.read_records(self.root)]
        self.assertTrue(records)
        self.assertEqual({v["verdict"] for r in records for v in r["variants"]}, {"hang"})
        self.assertEqual({rep["verdict_evidence"]["rule"] for r in records for v in r["variants"]
                          for rep in v["repetitions"]}, {"timeout"})

    def test_two_passes_interleave_their_runs(self) -> None:
        """Each core_probe takes the host lock for its own run: a pass never
        holds it between runs, so a second pass runs between them."""
        import threading
        import time

        spans: dict[str, list[tuple[float, float]]] = {"a": [], "b": []}
        other = Workspace(methodName="setUp")
        other.setUp()
        self.addCleanup(other.tearDown)
        passes = []
        for name, workspace in (("a", self), ("b", other)):
            c = FakeCorePasses.passing(workspace, "hle") if workspace is self else self.passing_in(workspace)
            real = c.host.run

            def timed(argv: list[str], *args: object, _name: str = name, _real=real, **kwargs: object):
                start = time.monotonic()
                try:
                    return _real(argv, *args, **kwargs)
                finally:
                    spans[_name].append((start, time.monotonic()))
            c.host.run = timed
            passes.append(c)
        threads = [threading.Thread(target=c.run, args=(set(), None)) for c in passes]
        cwd = Path.cwd()
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        # Each pass moved into its own root and back: the process ends where it began.
        self.assertEqual(Path.cwd(), cwd)
        ends = {name: sorted(end for _, end in runs) for name, runs in spans.items()}
        self.assertGreater(len(ends["a"]), 2)
        self.assertGreater(len(ends["b"]), 2)
        # Neither pass finished all its runs before the other started finishing its own.
        self.assertLess(ends["b"][0], ends["a"][-1])
        self.assertLess(ends["a"][0], ends["b"][-1])

    def passing_in(self, workspace: Workspace) -> campaign.Campaign:
        workspace.put_game()
        host = campaign.Host(loadavg=lambda: (0.0, 0.0, 0.0), free_gb=lambda path: 500.0,
                             cpu_count=1_000_000)
        c = campaign.Campaign(workspace.paths, campaign.Settings(
            check_repeat=2, probe_timeout=30, delays=(1,), echo=False), host,
            lock_path=workspace.tmp / "auto.lock")
        so = self.cores["hle"]
        c.unit_cores = lambda *a, **k: [campaign.Core("fake", so, campaign.file_sha256(so))]
        return c

    def test_missing_content_leaves_the_checks_pending(self) -> None:
        c = self.passing(romfetch=str(self.tmp / "no-romfetch"))
        shutil.rmtree(self.game)
        c.run(set(), None)
        reasons = {entry["reason"] for entry in c.state["checks"]["fake"].values()}
        self.assertEqual(len(reasons), 1)
        self.assertIn("romfetch not found", reasons.pop())


if __name__ == "__main__":
    unittest.main()
