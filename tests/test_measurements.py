"""Core probe records under measurements/, and what the site makes of them.

Synthetic record trees are built under tmp/tests: one full record per line,
read from the tree, compiled into the index and the SQLite files. The append-only rule is checked against a commit, two branches that
each add a line merge, and the records this repository holds are checked
against HEAD.
"""

from __future__ import annotations

import copy
import html
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import measurement_records as mr  # noqa: E402
import sitemeasurements as sm  # noqa: E402

REPO_URL = "https://github.com/Abdess/retrobios"
COMMIT = "e" * 40
SHA1 = "a" * 40
SHA256 = "b" * 64


def repetition(value: str, frames: int = 3) -> dict:
    return {
        "loaded": True, "library_name": "Fake", "library_version": "1", "fps_nominal": 60.0,
        "frames": frames, "warmup": 0, "wall_s": 0.5, "ms_per_frame": 2.5, "fps": 400.0,
        "observables": {"frame_sha1": value, "video_sha1": value, "audio_sha1": SHA1,
                        "state_sha1": None, "frame_hashes": [[0, value], [150, value]]},
        "logs": [{"frame": 0, "level": "info", "text": "card present " * 20}],
        "options_declared": {"fake_option": ["a", "b"]}, "env_unanswered": {"65": 1},
        "last_frame_size": [4, 2], "tracing": "strace", "input_queries": 3, "input_pressed": 1,
        "files_opened": [{"path": "card.bin", "sha1_after": SHA1, "sha1_staged": SHA1}],
        "files_probed_absent": [],
        "verdict": "boots",
        "verdict_evidence": {"rule": "reference_frame", "detail": "reached the title", "frame": 150,
                             "sha1": value, "stages": ["game"]},
    }


def full_record(emulator: str, subject: str, when: str, kind: str = "check",
                values: tuple[str, ...] = ("1" * 40, "2" * 40), observable: str = "video_sha1") -> dict:
    variants = [{"label": f"v{i}", "system_files": {"card.bin": SHA1},
                 "repetitions": [repetition(v), repetition(v)], "flags": [], "verdict": "boots",
                 "verdict_evidence": {"rule": "repetitions_agree", "detail": "both boot",
                                      "repetitions": ["boots", "boots"]}}
                for i, v in enumerate(values)]
    record = {
        "record_version": 4, "emulator": emulator, "subject": subject,
        "supersedes": None, "kind": kind, "recorded_at": when,
        "core": {"file": "fake_libretro.so", "sha256": SHA256, "repo": "https://example.org/fake",
                 "commit": "c" * 40, "build_command": "make", "compiler": ["GCC 13"],
                 "library_name": "Fake", "library_version": "1"},
        "frontend": {"script": "scripts/core_probe.py", "commit": "d" * 40, "script_modified": False,
                     "script_sha256": SHA256},
        "host": {"cpu_model": "Test CPU", "cpu_count": 8, "os": "Linux-6.1-x86_64-with-glibc2.39",
                 "kernel": "6.1", "machine": "x86_64", "python": "3.12.3",
                 "load_before": [0.5, 0.5, 0.5], "load_after": [0.6, 0.5, 0.5], "max_load": 2.0},
        "inputs": {"content": {"label": "test disc", "sha1": SHA1, "size": 10,
                               "tracks": [{"file": "t.bin", "sha1": SHA1, "size": 9}]},
                   "options": {"fake_option": "a"}, "env": {}, "frames": 3, "warmup": 0,
                   "repetitions": 2 if kind == "check" else 5, "presses": [],
                   "observables": ["frame_sha1", "video_sha1", "audio_sha1", "state_sha1", "frame_hashes"],
                   "frame_hash_every": 150, "joypad_ports": 2,
                   "oracle": {"file": "tests/campaign/oracle.yml", "sha256": SHA256,
                              "references": [{"sha1": values[0], "stage": "game", "shows": "title"}],
                              "error_patterns": ["BIOS not found"], "error_screens": []}},
        "variants": variants,
        "flags": [],
    }
    if kind == "check":
        groups: dict[str, list[str]] = {}
        for variant, value in zip(variants, values):
            key = json.dumps(variant["repetitions"][0]["observables"][observable], sort_keys=True)
            groups.setdefault(key, []).append(variant["label"])
        record["check"] = {
            "claim": f"The card decides what {emulator} shows.", "method": "Each card, twice.",
            "observable": observable, "variable": "card.bin",
            "result": {"status": "differs" if len(groups) > 1 else "same",
                       "statement": f"{observable} takes {len(groups)} values",
                       "groups": [{"value": json.loads(k), "variants": v} for k, v in groups.items()],
                       "verdicts": {v["label"]: v["verdict"] for v in variants}},
        }
    else:
        record["variants"] = record["variants"][:1]
        record["variants"][0]["repetitions"] = [repetition(values[0]) for _ in range(5)]
        raw = [2.0, 2.5, 3.0, 2.2, 2.4]
        stats = {"median": 2.4, "mean": 2.42, "stdev": 0.37, "min": 2.0, "max": 3.0, "raw": raw}
        record["timing"] = {"ms_per_frame": stats,
                            "fps": {**stats, "median": 416.7, "raw": [1000 / v for v in raw]}}
    return record




def git(cwd: Path, *args: str) -> str:
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@t", "GIT_CEILING_DIRECTORIES": str(cwd.parent)}
    return subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True,
                          check=True).stdout.strip()


def add_record(tree: Path, full: dict) -> dict:
    sealed = mr.seal(full)
    lines = tree / mr.records_path(sealed["emulator"])
    lines.parent.mkdir(parents=True, exist_ok=True)
    with lines.open("a", encoding="utf-8") as handle:
        handle.write(mr.line_text(sealed) + "\n")
    return sealed


def commit_all(tree: Path, message: str) -> str:
    git(tree, "add", "--all", ".")
    git(tree, "commit", "-q", "-m", message)
    return git(tree, "rev-parse", "HEAD")


class Workspace(unittest.TestCase):
    """A tree with three records under measurements/ and one profile."""

    def setUp(self) -> None:
        (REPO_ROOT / "tmp" / "tests").mkdir(parents=True, exist_ok=True)
        self.tmp = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp" / "tests"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.tree = self.tmp / "tree"
        self.tree.mkdir()
        self.first = add_record(self.tree, full_record("alpha", "card", "2026-10-01T10:00:00+00:00"))
        self.bench = add_record(self.tree, full_record("alpha", "speed", "2026-10-01T11:00:00+00:00",
                                                       kind="bench"))
        self.beta = add_record(self.tree, full_record("beta", "card", "2026-10-02T10:00:00+00:00",
                                                      values=("1" * 40, "1" * 40)))
        self.emulators = self.tmp / "emulators"
        self.emulators.mkdir()
        (self.emulators / "alpha.yml").write_text(
            'emulator: "Alpha"\ntype: libretro\nsystems:\n  - sega-saturn\nfiles: []\n')

    def built(self, public: Path) -> sm.Built:
        return sm.build(public, self.tree, self.emulators, scratch=self.tmp / "scratch",
                        system_names={"sega-saturn": "Sega Saturn"}, repo=REPO_URL, commit=COMMIT)

    def repository(self) -> str:
        """Make the tree a git repository, its records committed on main."""
        git(self.tree, "init", "-q", "-b", "main")
        (self.tree / ".gitattributes").write_text("measurements/*.jsonl merge=union\n")
        return commit_all(self.tree, "feat: first records")


class RecordLine(unittest.TestCase):
    def test_a_line_holds_the_whole_record(self) -> None:
        for kind in ("check", "bench"):
            full = full_record("alpha", "card", "2026-10-01T10:00:00+00:00", kind=kind)
            sealed = mr.seal(full)
            with self.subTest(kind=kind):
                self.assertEqual({k: v for k, v in sealed.items() if k != "id"}, full)
                self.assertEqual(json.loads(mr.line_text(sealed)), sealed)
                self.assertEqual(mr.check_line(sealed), [])
                self.assertIn("frame_hashes", mr.line_text(sealed))
                self.assertIn("card present", mr.line_text(sealed))
                self.assertNotIn("\n", mr.line_text(sealed))

    def test_id_is_reproducible(self) -> None:
        full = full_record("alpha", "card", "2026-10-01T10:00:00+00:00")
        self.assertEqual(mr.seal(full), mr.seal(copy.deepcopy(full)))
        self.assertRegex(mr.seal(full)["id"], r"^2026-10-01-[0-9a-f]{12}$")

    def test_tampering_is_named(self) -> None:
        sealed = mr.seal(full_record("alpha", "card", "2026-10-01T10:00:00+00:00"))
        for changed in ({**sealed, "subject": "other"},
                        {**sealed, "variants": sealed["variants"][:1]}):
            self.assertTrue(any("does not hash" in p for p in mr.check_line(changed)))

    def test_first_layout_record_keeps_its_id(self) -> None:
        old = mr.first_layout(full_record("alpha", "card", "2026-10-01T10:00:00+00:00"))
        rid = f"2026-10-01-{mr.sha256_hex(mr.canonical(old))[:12]}"
        line = {**old, "record_version": mr.RECORD_VERSION, "emulator": "alpha", "subject": "card",
                "supersedes": None, "migrated_from_version": 1, "id": rid}
        self.assertEqual(mr.check_line(line), [])
        self.assertEqual(mr.first_layout(line), old)
        self.assertTrue(mr.check_line({**line, "id": "2026-10-01-000000000000"}))
        changed = copy.deepcopy(line)
        changed["variants"][0]["repetitions"][0]["logs"] = []
        self.assertTrue(any("first-layout" in p for p in mr.check_line(changed)))


class ReadAndIndex(Workspace):
    def test_records_are_read_from_the_tree(self) -> None:
        records = mr.read_records(self.tree)
        self.assertEqual([(s.emulator, s.line) for s in records], [("alpha", 1), ("alpha", 2), ("beta", 1)])
        self.assertEqual(mr.read_records(self.tmp / "empty"), [])

    def test_a_broken_tree_is_named(self) -> None:
        stray = self.tree / mr.RECORDS_DIR / "data" / "beta" / "2026-10-02-000000000000.json.gz"
        stray.parent.mkdir(parents=True)
        stray.write_bytes(b"x")
        lines = self.tree / mr.records_path("beta")
        lines.write_text(lines.read_text() * 2)
        with self.assertRaises(mr.MeasurementsError) as caught:
            mr.read_records(self.tree)
        message = str(caught.exception)
        self.assertIn(f"{mr.RECORDS_DIR}/data/beta/2026-10-02-000000000000.json.gz: "
                      f"{mr.RECORDS_DIR}/ holds <emulator>.jsonl files only", message)
        self.assertIn(f"measurements/beta.jsonl:2: id {self.beta['id']} appears twice", message)

    def test_index_shape(self) -> None:
        index = self.built(self.tmp / "public").index
        self.assertEqual({k: index[k] for k in ("schema_version", "kind", "repo", "commit", "records", "count")},
                         {"schema_version": 1, "kind": "measurements", "repo": REPO_URL,
                          "commit": COMMIT, "records": 3, "count": 2})
        keys = {"emulator", "emulator_name", "profiled", "systems", "system_names", "subject", "kind",
                "claim", "method", "observable", "variable", "status", "statement", "content",
                "variants", "repetitions", "flags", "date", "host", "core", "frontend_commit", "id",
                "runs", "record_url", "sqlite", "verdicts", "proves", "records"}
        for item in index["items"]:
            self.assertEqual(set(item), keys)
        alpha = {i["subject"]: i for i in index["items"] if i["emulator"] == "alpha"}
        self.assertEqual(alpha["card"]["status"], "differs")
        self.assertEqual(alpha["card"]["system_names"], ["Sega Saturn"])
        self.assertEqual(alpha["card"]["record_url"],
                         f"{REPO_URL}/blob/{COMMIT}/measurements/alpha.jsonl#L1")
        # A benchmark stays in the records and the SQLite files, never in the index.
        self.assertNotIn("speed", alpha)
        self.assertNotIn("ms per frame", json.dumps(index))
        written = json.loads((self.tmp / "public" / sm.INDEX_PATH).read_text())
        self.assertEqual(written, index)

    def test_a_frame_check_shows_its_verdicts_never_frames_that_differ(self) -> None:
        record = full_record("alpha", "boot", "2026-10-06T10:00:00+00:00", observable="frame_hashes")
        record["variants"][1]["verdict"] = "hang"
        self.assertEqual(sm.result_of(record), ("mixed", "v0: boots. v1: hang"))
        self.assertEqual([v["verdict"] for v in sm.verdicts_of(record)], ["boots", "hang"])
        old = {**record, "record_version": 3,
               "variants": [{k: v for k, v in variant.items() if not k.startswith("verdict")}
                            for variant in record["variants"]]}
        status, statement = sm.result_of(old)
        self.assertEqual(status, "no verdict")
        self.assertNotIn("differ", statement)
        # A check on another observable keeps its comparison.
        self.assertEqual(sm.result_of(full_record("alpha", "c", "2026-10-06T10:00:00+00:00"))[0], "differs")

    def test_a_boot_on_the_built_in_bios_is_named_so(self) -> None:
        import core_probe  # noqa: PLC0415

        record = full_record("alpha", "region-x-game-others", "2026-10-28T10:00:00+00:00",
                             kind="run", observable="frame_hashes")
        oracle = {"references": [{"sha1": "1" * 40, "stage": "game", "shows": "the title"}],
                  "error_patterns": [], "error_screens": [], "bios_patterns": [],
                  "fallback_patterns": [r"^Firmware is missing: "], "load_patterns": []}
        for variant in record["variants"]:
            for rep in variant["repetitions"]:
                rep["logs"] = [{"frame": 0, "level": "info", "text": "Firmware is missing: scph5501.bin"}]
                core_probe.judge_repetition(rep, oracle)
            core_probe.judge_variant(variant)
        self.assertEqual(record["variants"][0]["bios_used"], "builtin")
        status, statement = sm.result_of(record)
        self.assertEqual(status, sm.BOOTS_BUILTIN)
        self.assertIn("built-in BIOS", statement)
        # The proof line a profile field rests on names the BIOS the core ran.
        record["variants"][0]["system_files"] = {}
        line = sm.proof_line("required of scph5501.bin", [(sm.shown_of(record), ["../r.jsonl#L1"])])
        self.assertEqual(html.unescape(line), "- required of scph5501.bin: with no BIOS, it boots on the "
                                              "core's built-in BIOS ([record](../r.jsonl#L1)).")
        self.assertNotIn("other region", line)

    def test_links_name_the_last_commit_that_touched_the_records(self) -> None:
        first = self.repository()
        (self.tree / "other.txt").write_text("x")
        commit_all(self.tree, "chore: unrelated")
        self.assertEqual(mr.last_commit(self.tree), first)
        index = sm.build(self.tmp / "public", self.tree, self.emulators, scratch=self.tmp / "scratch").index
        self.assertEqual(index["commit"], first)
        self.assertTrue(all(f"/blob/{first}/measurements/" in i["record_url"] for i in index["items"]))

    def test_latest_record_of_a_subject_wins_and_a_superseded_one_is_dropped(self) -> None:
        later = full_record("alpha", "card", "2026-10-05T10:00:00+00:00", values=("3" * 40, "3" * 40))
        later["supersedes"] = self.first["id"]
        add_record(self.tree, later)
        card = next(i for i in self.built(self.tmp / "public").index["items"]
                    if i["emulator"] == "alpha" and i["subject"] == "card")
        self.assertEqual((card["status"], card["runs"]), ("same", 1))
        self.assertTrue(card["record_url"].endswith("#L3"))

    def test_sqlite_tables_and_row_counts_match_the_records(self) -> None:
        public = self.tmp / "public"
        self.built(public)
        connection = sqlite3.connect(public / sm.SQLITE_PATH)
        tables = [row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY rowid")]
        self.assertEqual(tuple(tables), sm.TABLES)
        count = lambda table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # noqa: E731
        records = [s.record for s in mr.read_records(self.tree)]
        self.assertEqual(count("runs"), len(records))
        self.assertEqual(count("checks"), sum(1 for r in records if r.get("check")))
        self.assertEqual(count("benchmarks"), 2 * sum(1 for r in records if r.get("timing")))
        self.assertEqual(count("variants"), sum(len(r["variants"]) for r in records))
        self.assertEqual(count("check_groups"),
                         sum(len(r["check"]["result"]["groups"]) for r in records if r.get("check")))
        self.assertEqual(count("hosts"), 1)
        self.assertEqual(count("cores"), 1)
        meta = dict(connection.execute("SELECT key, value FROM meta"))
        self.assertEqual((meta["measurements_repo"], meta["measurements_commit"]), (REPO_URL, COMMIT))
        self.assertEqual(connection.execute("SELECT system FROM emulator_systems").fetchall(),
                         [("sega-saturn",)])
        self.assertEqual(connection.execute("SELECT record_url FROM runs WHERE line = 1 AND emulator = 'beta'")
                         .fetchone()[0], f"{REPO_URL}/blob/{COMMIT}/measurements/beta.jsonl#L1")
        indexes = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}
        self.assertTrue({"runs_emulator_idx", "emulator_systems_system_idx", "checks_claim_idx"} <= indexes)
        connection.close()
        for emulator, expected in (("alpha", 2), ("beta", 1)):
            per = sqlite3.connect(public / sm.PER_EMULATOR_DIR / f"{emulator}.sqlite")
            self.assertEqual(per.execute("SELECT COUNT(*), MIN(emulator), MAX(emulator) FROM runs").fetchone(),
                             (expected, emulator, emulator))
            per.close()

    def test_two_builds_are_byte_identical(self) -> None:
        one, two = self.tmp / "one", self.tmp / "two"
        first, second = self.built(one), self.built(two)
        self.assertEqual([p.relative_to(one) for p in first.paths], [p.relative_to(two) for p in second.paths])
        for path in first.paths:
            self.assertEqual(path.read_bytes(), (two / path.relative_to(one)).read_bytes(), path.name)

    def test_no_records_writes_an_empty_index(self) -> None:
        shutil.rmtree(self.tree / mr.RECORDS_DIR)
        built = self.built(self.tmp / "public")
        self.assertEqual((built.index["records"], built.index["count"]), (0, 0))
        self.assertEqual(len(built.paths), 2)

    def test_every_line_validates_against_the_schema(self) -> None:
        try:
            from jsonschema import Draft202012Validator
        except ImportError:
            self.skipTest("jsonschema is not installed")
        import validate_schemas  # noqa: PLC0415

        self.assertEqual(validate_schemas._measurement_errors(self.tree), [])
        lines = self.tree / mr.records_path("beta")
        record = json.loads(lines.read_text())
        record["kind"] = "guess"
        lines.write_text(mr.line_text(record) + "\n")
        errors = validate_schemas._measurement_errors(self.tree)
        self.assertTrue(any("measurements/beta.jsonl:1" in e and "kind" in e for e in errors), errors)
        self.assertIsNotNone(Draft202012Validator)

    def test_a_version_5_record_names_the_bios_it_ran(self) -> None:
        try:
            from jsonschema import Draft202012Validator
        except ImportError:
            self.skipTest("jsonschema is not installed")
        schema = json.loads((REPO_ROOT / "schemas" / "core-probe-record.schema.json").read_text())
        record = mr.seal({**full_record("alpha", "card", "2026-10-28T10:00:00+00:00"), "record_version": 5})
        errors = [e.message for e in Draft202012Validator(schema).iter_errors(record)]
        self.assertIn("'bios_used' is a required property", errors)
        for variant in record["variants"]:
            variant["bios_used"] = "builtin"
            for rep in variant["repetitions"]:
                rep["bios_used"] = "staged:card.bin"
        self.assertEqual([e.message for e in Draft202012Validator(schema).iter_errors(record)
                          if "bios_used" in e.message], [])
        record["variants"][0]["bios_used"] = "the other region's"
        self.assertTrue(list(Draft202012Validator(schema).iter_errors(record)))

    def test_a_version_4_record_needs_its_verdicts(self) -> None:
        try:
            from jsonschema import Draft202012Validator  # noqa: F401
        except ImportError:
            self.skipTest("jsonschema is not installed")
        import validate_schemas  # noqa: PLC0415

        lines = self.tree / mr.records_path("beta")
        record = json.loads(lines.read_text())
        del record["variants"][0]["verdict"]
        del record["variants"][0]["repetitions"][0]["verdict_evidence"]
        lines.write_text(mr.line_text(record) + "\n")
        errors = validate_schemas._measurement_errors(self.tree)
        self.assertTrue(any("'verdict' is a required property" in e for e in errors), errors)
        self.assertTrue(any("'verdict_evidence' is a required property" in e for e in errors), errors)
        old = {**record, "record_version": 3}
        lines.write_text(mr.line_text(old) + "\n")
        self.assertFalse(any("required property" in e
                             for e in validate_schemas._measurement_errors(self.tree)))


class AppendOnly(Workspace):
    def setUp(self) -> None:
        super().setUp()
        self.commit = self.repository()

    def test_an_appended_line_and_a_new_file_pass(self) -> None:
        add_record(self.tree, full_record("alpha", "card", "2026-10-04T10:00:00+00:00"))
        add_record(self.tree, full_record("gamma", "card", "2026-10-04T10:00:00+00:00"))
        self.assertEqual(mr.append_only_problems(self.tree, "HEAD"), [])

    def test_a_changed_line_is_named(self) -> None:
        lines = self.tree / mr.records_path("alpha")
        text = lines.read_text().splitlines()
        text[0] = text[0].replace('"Each card, twice."', '"Each card, once."')
        lines.write_text("\n".join(text) + "\n")
        self.assertEqual(mr.append_only_problems(self.tree, "HEAD"),
                         ["measurements/alpha.jsonl: line 1 changed"])

    def test_a_removed_line_or_file_is_named(self) -> None:
        lines = self.tree / mr.records_path("alpha")
        lines.write_text(lines.read_text().splitlines()[0] + "\n")
        (self.tree / mr.records_path("beta")).unlink()
        self.assertEqual(mr.append_only_problems(self.tree, "HEAD"),
                         ["measurements/alpha.jsonl: line 2 removed", "measurements/beta.jsonl: removed"])

    def test_two_branches_adding_a_line_merge_cleanly(self) -> None:
        git(self.tree, "checkout", "-q", "-b", "left")
        add_record(self.tree, full_record("alpha", "card", "2026-10-06T10:00:00+00:00"))
        commit_all(self.tree, "left")
        git(self.tree, "checkout", "-q", "main")
        git(self.tree, "checkout", "-q", "-b", "right")
        add_record(self.tree, full_record("alpha", "speed", "2026-10-06T11:00:00+00:00", kind="bench",
                                          values=("4" * 40,)))
        commit_all(self.tree, "right")
        git(self.tree, "merge", "-q", "--no-edit", "left")
        self.assertEqual(mr.append_only_problems(self.tree, self.commit), [])
        records = mr.read_records(self.tree)
        self.assertEqual(sum(1 for s in records if s.emulator == "alpha"), 4)


class CommittedRecords(unittest.TestCase):
    """The records this repository holds."""

    def test_no_line_changed_or_vanished_since_head(self) -> None:
        if subprocess.run(["git", "-C", str(REPO_ROOT), "rev-parse", "--verify", "-q", "HEAD"],
                          capture_output=True, check=False).returncode != 0:
            self.skipTest("not a git checkout")
        self.assertEqual(mr.append_only_problems(REPO_ROOT, "HEAD"), [])

    def test_every_record_reads_and_joins_its_data(self) -> None:
        records = mr.read_records(REPO_ROOT)
        self.assertGreaterEqual(len(records), 7)

    def test_jsonl_files_merge_by_union(self) -> None:
        rules = (REPO_ROOT / ".gitattributes").read_text().splitlines()
        rule = next(line for line in rules if line.startswith(f"{mr.RECORDS_DIR}/*.jsonl "))
        self.assertIn("merge=union", rule.split())


class SitePages(unittest.TestCase):
    ITEM = {
        "emulator": "beetle_saturn", "emulator_name": "Beetle Saturn", "profiled": True,
        "systems": ["sega-saturn"], "system_names": ["Sega Saturn"], "subject": "mpeg-card",
        "kind": "check", "claim": "The card <image> decides it.", "method": "Twice per card; every input fixed.",
        "observable": "video_sha1", "variable": "mpeg_card.bin", "status": "same",
        "statement": "video_sha1 is identical across all 11 variants", "content": "disc",
        "variants": 11, "repetitions": 2, "flags": 1, "date": "2026-10-27T05:14:32+00:00",
        "host": "Test CPU, 12 CPUs", "core": {"library": "Beetle Saturn v1.32.1", "commit": "2ce77e2" * 5 + "abcde",
                                             "file": "x.so", "sha256": SHA256, "repo": None, "build": "make"},
        "frontend_commit": None, "id": "2026-10-27-43527b763ace", "runs": 2,
        "record_url": f"{REPO_URL}/blob/{'e' * 40}/measurements/beetle_saturn.jsonl#L4",
        "sqlite": "downloads/measurements/beetle_saturn.sqlite", "records": [],
    }

    def item(self, **values: object) -> dict:
        return {**self.ITEM, **values}

    def test_the_data_page_claims_no_link_an_emulator_page_lacks(self) -> None:
        """The Data page said each per-emulator database is "linked from its
        page". An emulator page shows the proof lines, which link the record
        lines and never the database."""
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as scratch:
            path = Path(scratch) / "m.sqlite"
            connection = sqlite3.connect(path)
            connection.execute("CREATE TABLE meta (key TEXT)")
            connection.commit()
            connection.close()
            text = "\n".join(sm.data_page_section(path))
        proofs = "\n".join(sm.proof_section([self.item()]))
        self.assertNotIn("downloads/measurements/", proofs)
        self.assertNotIn("linked from its page", text)
        self.assertIn("downloads/measurements/<emulator>.sqlite", text)

    URL = f"{REPO_URL}/blob/{'e' * 40}/measurements/beetle_psx.jsonl"

    def record(self, line: int, proves=(), shown=None, observed=None) -> dict:
        return {"url": f"{self.URL}#L{line}", "proves": list(proves), "shown": shown, "observed": observed}

    def lines(self, *items: dict) -> list[str]:
        return [html.unescape(line) for line in sm.proof_section(list(items)) if line.startswith("- ")]

    def test_one_line_per_claim(self) -> None:
        """Records that back the same claim collapse into one line: every
        name strace saw opened in one list, each result once."""
        alias = "aliases of scph5501.bin"
        builtin = ["text", sm.proof_result([{"variant": "default", "verdict": sm.BOOTS_BUILTIN,
                                             "bios_used": "builtin", "detail": "", "staged": []}])]
        lines = self.lines(
            self.item(subject="alias-b", records=[self.record(5, [alias], ["opened", "SCPH5501.BIN"])]),
            self.item(subject="alias-a", records=[self.record(3, [alias], ["opened", "SCPH-5501.BIN"])]),
            self.item(subject="none", records=[self.record(9, ["hle_fallback of scph5501.bin"], builtin),
                                               self.record(7, ["hle_fallback of scph5501.bin"], builtin)]))
        self.assertEqual(lines, [
            f"- aliases of scph5501.bin: the core opened SCPH-5501.BIN, SCPH5501.BIN "
            f"(records [1]({self.URL}#L3), [2]({self.URL}#L5)).",
            f"- hle_fallback of scph5501.bin: with no BIOS, it boots on the core's built-in BIOS "
            f"(records [1]({self.URL}#L7), [2]({self.URL}#L9)).",
        ])
        many = self.lines(self.item(subject="s", records=[
            self.record(n, ["required of a.bin"], ["text", "with no BIOS, it hangs"]) for n in range(1, 11)]))
        self.assertEqual(many, [f"- required of a.bin: with no BIOS, it hangs ([10 records]({self.URL}))."])
        # Two results for one claim stay on its one line, each with its records.
        mixed = self.lines(self.item(subject="s", records=[
            self.record(1, ["validation of a.bin"], ["text", "a.bin: boots. zeros: hangs"]),
            self.record(2, ["validation of a.bin"], ["text", "with no BIOS, it boots"])]))
        self.assertEqual(mixed, [f"- validation of a.bin: a.bin: boots. zeros: hangs ([record]({self.URL}#L1)). "
                                 f"With no BIOS, it boots ([record]({self.URL}#L2))."])

    def test_a_line_says_what_was_observed_or_is_left_out(self) -> None:
        said = {"issue": "85", "said": "the Lunar opening movie plays with sound"}
        lines = self.lines(
            # A pre-oracle record with no opened file and no observation: nothing to state.
            self.item(subject="alias-x", records=[self.record(1, ["aliases of a.bin"], None)]),
            self.item(subject="issue85-vcd-player-boot", records=[self.record(2)]),
            self.item(subject="issue85-lunar-opening-movie",
                      records=[self.record(3, observed=said), self.record(4)]))
        self.assertEqual(lines, [f"- issue 85: the Lunar opening movie plays with sound ([record]({self.URL}#L3))."])
        self.assertEqual(sm.proof_section([self.item(records=[self.record(1)])]), [])

    def test_no_page_says_before_the_boot_oracle(self) -> None:
        stored = mr.read_records(REPO_ROOT)
        index = sm.build_index(stored, {"repo": REPO_URL, "commit": "e" * 40}, sm.load_profiles(REPO_ROOT / "emulators"),
                               None, sm.load_observations(REPO_ROOT / sm.OBSERVATIONS))
        for emulator, items in sm.by_emulator(index).items():
            text = "\n".join(sm.proof_section(items))
            self.assertNotIn("boot oracle", text, emulator)
            # One line per profile field: its records never spread over two lines.
            fields = [line.split(":")[0] for line in text.splitlines()
                      if line.startswith("- ") and not line.startswith("- issue ")]
            self.assertEqual(len(fields), len(set(fields)), emulator)
        lines = [html.unescape(line) for line in sm.proof_section(sm.by_emulator(index).get("beetle_psx", []))
                 if line.startswith("- aliases of")]
        self.assertEqual(len(lines), 1)
        self.assertIn("the core opened ", lines[0])

    def test_every_observation_names_records_that_exist(self) -> None:
        observations = sm.load_observations(REPO_ROOT / sm.OBSERVATIONS)
        stored = mr.read_records(REPO_ROOT)
        known = {s.record["id"] for s in stored} | {s.record["subject"] for s in stored}
        self.assertTrue(observations)
        self.assertLessEqual(set(observations), known, set(observations) - known)

    def test_the_issue_85_comparison_holds_in_the_records(self) -> None:
        """Video and audio equal on each disc across every core commit run,
        card off and on: the sentence the Proof line gives. The base and the
        patched build are both there, and reruns on a later upstream base may
        add commits without changing the claim."""
        said = sm.load_observations(REPO_ROOT / sm.OBSERVATIONS)["issue85-regression-card-on"]["said"]
        self.assertIn("20 discs", said)
        runs: dict[str, list[dict]] = {}
        for entry in mr.read_records(REPO_ROOT):
            if entry.record["subject"] in ("issue85-regression-card-off", "issue85-regression-card-on"):
                runs.setdefault(entry.record["inputs"]["content"]["label"], []).append(entry.record)
        if not runs:
            self.skipTest("no issue 85 record")
        self.assertEqual(len(runs), 20)
        for disc, records in runs.items():
            with self.subTest(disc=disc):
                commits = {r["core"]["commit"][:7] for r in records}
                self.assertLessEqual({"2ce77e2", "41d7596"}, commits)
                self.assertEqual({r["subject"] for r in records},
                                 {"issue85-regression-card-off", "issue85-regression-card-on"})
                seen = {(rep["observables"]["video_sha1"], rep["observables"]["audio_sha1"])
                        for r in records for v in r["variants"] for rep in v["repetitions"]}
                self.assertEqual(len(seen), 1)

    def test_the_removed_blocks_are_gone(self) -> None:
        for name in ("tested_section", "region_section", "core_region_line", "campaign_section",
                     "coverage_section", "packs_section", "pack_tested_section", "bench_statement"):
            self.assertFalse(hasattr(sm, name), name)
        docs = REPO_ROOT / "website" / "src" / "content" / "docs"
        pages = [*docs.glob("emulators/*.md*"), *docs.glob("systems/*.md*"),
                 *docs.glob("platforms/*.md*"), *docs.glob("measurements*.md*")]
        if not pages:
            self.skipTest("the site has not been generated")
        for page in pages:
            text = page.read_text(encoding="utf-8")
            for removed in ("rb-tested", "rb-region-runs", "## Tested", "## Region check",
                            "ms per frame", "## Campaign", "## Coverage", "## Packs"):
                self.assertNotIn(removed, text, f"{page.name}: {removed}")

    def test_run_output_is_text_never_markup(self) -> None:
        nasty = "`code` {expr} <script>alert(1)</script> [x](javascript:alert(1)) \"q\" 'q' **b**"
        verdicts = [{"variant": nasty, "verdict": nasty, "bios_used": f"staged:{nasty}", "detail": nasty},
                    {"variant": nasty, "verdict": "boots", "bios_used": "builtin", "detail": nasty}]
        line = sm.proof_line(nasty, [(["text", sm.proof_result(verdicts)], ["javascript:alert(1)"]),
                                     (["opened", nasty], ["javascript:alert(1)"])])
        self.assertNotIn("<script", line)
        self.assertNotIn("(javascript:", line)
        self.assertNotRegex(line, r"[{}`*]")
        self.assertNotRegex(line, r"\[")
        self.assertNotIn("](", line)
        self.assertIn("&lt;script&gt;", line)

    def test_hosts_table_on_the_method_page(self) -> None:
        page = sm.with_hosts(f"x\n\n{sm.HOSTS_MARKER}\n",
                                           {"items": [self.ITEM, {**self.ITEM, "host": "Test CPU, 12 CPUs, load 1 before, 2 after"}]})
        self.assertIn("| Test CPU, 12 CPUs | 2 |", page)
        self.assertNotIn(sm.HOSTS_MARKER, page)

    def test_the_explorer_reads_the_index(self) -> None:
        source = (REPO_ROOT / "website" / "src" / "components" / "MeasurementsExplorer.astro").read_text()
        self.assertIn("data/measurements/index.json", source)
        self.assertEqual(sm.INDEX_PATH.as_posix(), "data/measurements/index.json")
        read = set(re.findall(r"\b(?:item|i)\.([a-z_]+)", source)) - {"length"}
        self.assertTrue(read)
        self.assertLessEqual(read, set(self.ITEM), read - set(self.ITEM))
        page = sm.generate_explorer_page({"records": 7, "count": 7, "commit": "e" * 40,
                                                        "repo": REPO_URL})
        self.assertIn("<MeasurementsExplorer />", page)
        self.assertIn("downloads/measurements.sqlite", page)
        self.assertIn(f"({REPO_URL}/tree/{'e' * 40}/measurements)", page)


    def test_the_builds_read_the_records_in_this_repository(self) -> None:
        for name in ("deploy-site.yml", "validate.yml"):
            workflow = (REPO_ROOT / ".github" / "workflows" / name).read_text()
            with self.subTest(workflow=name):
                self.assertIn('- "measurements/**"', workflow)
                self.assertNotIn("measurements-pin", workflow)
                self.assertNotIn(".cache/measurements", workflow)
                self.assertNotIn("--require-measurements", workflow)
        self.assertFalse((REPO_ROOT / "measurements-pin.json").exists())
        self.assertFalse((REPO_ROOT / "scripts" / "sync_measurements.py").exists())

    def test_nothing_links_the_former_measurements_repository(self) -> None:
        former = "retrobios-" + "measurements"
        roots = ["wiki", "schemas", "scripts", "website/src", ".github", "tests", "measurements"]
        suffixes = {".md", ".py", ".json", ".jsonl", ".yml", ".astro", ".ts", ".mjs"}
        stray = [path.relative_to(REPO_ROOT).as_posix()
                 for root in roots for path in sorted((REPO_ROOT / root).rglob("*"))
                 if path.is_file() and path.suffix in suffixes
                 and former in path.read_text(encoding="utf-8", errors="replace")]
        stray += [name for name in ("README.md", "CONTRIBUTING.md")
                  if former in (REPO_ROOT / name).read_text(encoding="utf-8")]
        self.assertEqual(stray, [])


class Freshness(unittest.TestCase):
    def test_no_measurements_area(self) -> None:
        import check_freshness  # noqa: PLC0415
        import refresh_stale  # noqa: PLC0415

        self.assertNotIn("measurements", check_freshness.AREAS)
        self.assertNotIn("measurements", refresh_stale.AUTO_AREAS)


if __name__ == "__main__":
    unittest.main()
