"""The --events stream, its schema and the installer page written from the code."""
from __future__ import annotations

import tests
from tests import scratch_dir

import argparse
import contextlib
import io
import json
import socket
import subprocess
import unittest
import unittest.mock
from pathlib import Path

from tests.netguard import module_guard
from tests.installsupport import REPO_ROOT, install, _install_run, _SyntheticTree, _events


# No connection off the loopback and no card of the host reaches a test:
# the module fails at its end otherwise.
setUpModule, tearDownModule = module_guard("test_install_events")


class SystemEventsFollowTheChoice(unittest.TestCase):
    """--system nintendo-gba wrote `system` events for nintendo-ds, gb and
    gbc: SkyEmu's files carry four systems, and each was described by the
    few of its files the choice kept."""

    def test_only_the_chosen_systems_are_described(self):
        files = [{"dest": "gba_bios.bin", "size": 1, "systems": ["nintendo-gba"]},
                 {"dest": "SkyEmu/dmg.bin", "size": 1,
                  "systems": ["nintendo-gb", "nintendo-gba"]}]
        stream = io.StringIO()
        install.EVENTS.open(stream)
        self.addCleanup(setattr, install.EVENTS, "stream", None)
        install._emit_check("retroarch", {}, Path("/b"), install.CheckTally(files, [], []),
                            chosen=["nintendo-gba"])
        systems = [json.loads(line)["system"] for line in stream.getvalue().splitlines()
                   if json.loads(line)["event"] == "system"]
        self.assertEqual(systems, ["nintendo-gba"])
        stream.seek(0)
        stream.truncate()
        install._emit_check("retroarch", {}, Path("/b"), install.CheckTally(files, [], []))
        systems = [json.loads(line)["system"] for line in stream.getvalue().splitlines()
                   if json.loads(line)["event"] == "system"]
        self.assertEqual(systems, ["nintendo-gb", "nintendo-gba"])


class EventsDescribeTheRun(unittest.TestCase, _SyntheticTree):
    """--events: the handheld port reads the run as JSON lines on stdout and
    never parses the text, which goes to stderr."""

    def setUp(self):
        self.env = self.serve_tree(self)

    def _run(self, *argv: str) -> tuple[subprocess.CompletedProcess, list[dict]]:
        proc = _install_run(self.env, "--platform", "retroarch", "--dest", str(self.bios),
                            "--events", "--jobs", "1", *argv)
        self.assertNotIn("Traceback", proc.stderr)
        return proc, _events(proc)

    def _head(self, mode: str, installer: str) -> list[dict]:
        return [
            {"event": "start", "schema": install.EVENT_SCHEMA, "installer": installer,
             "mode": mode},
            {"event": "detect", "os": "linux", "os_name": install._os_name(),
             "platforms": [{"platform": "retroarch", "name": "RetroArch",
                            "bios_dir": str(self.bios)}]},
            # The systems Choose systems lists, before the files are read.
            {"event": "choices", "platform": "retroarch",
             "systems": ["sys-a", "sys-b", "other"]},
            # Nothing set aside before the choice.
            {"event": "set_aside", "platform": "retroarch", "dests": []},
            # a.bin and b.bin are in place: the first read and the last.
            {"event": "checking", "files_done": 1, "files_total": 2},
            {"event": "checking", "files_done": 2, "files_total": 2},
            {"event": "file", "platform": "retroarch", "dest": "a.bin",
             "systems": ["sys-a"], "size": 100, "state": "present"},
            {"event": "file", "platform": "retroarch", "dest": "b.bin",
             "systems": ["sys-a"], "size": 150, "state": "wrong_hash"},
            {"event": "file", "platform": "retroarch", "dest": "c.bin",
             "systems": ["sys-b"], "size": 70, "state": "missing"},
            {"event": "file", "platform": "retroarch", "dest": "d.bin",
             "systems": [], "size": 25, "state": "missing"},
            {"event": "system", "platform": "retroarch", "system": "other", "name": "other",
             "files": 1, "present": 0, "missing": 1, "wrong_hash": 0, "bytes_needed": 25},
            {"event": "system", "platform": "retroarch", "system": "sys-a", "name": "alpha",
             "files": 2, "present": 1, "missing": 0, "wrong_hash": 1, "bytes_needed": 150},
            {"event": "system", "platform": "retroarch", "system": "sys-b", "name": "sys-b",
             "files": 1, "present": 0, "missing": 1, "wrong_hash": 0, "bytes_needed": 70},
            {"event": "check", "platform": "retroarch", "name": "RetroArch",
             "bios_dir": str(self.bios), "files": 4, "present": 1, "missing": 2,
             "wrong_hash": 1, "bytes_needed": 245, "data_missing": 0,
             "not_installable": 1},
            # Every file of this list is the platform's own (cores: null).
            {"event": "declared", "platform": "retroarch", "files": 4, "present": 1,
             "missing": 2, "wrong_hash": 1, "bytes_needed": 245,
             "dests": ["a.bin", "b.bin", "c.bin", "d.bin"]},
            # No data tree in this list.
            {"event": "data", "platform": "retroarch", "files": 0, "bytes": 0},
            # The missing and the wrong copy, written: what the run holds
            # against the free space.
            {"event": "space", "platform": "retroarch", "bytes": 245},
            # Each file not in place comes from the network: no copy here,
            # no pack.
            {"event": "fetch_plan", "platform": "retroarch", "files": 3, "bytes": 245,
             "copied": [], "lacking": [], "data_files": 0, "data_bytes": 0},
        ]

    SKIPPED = [{"reason": "not_found", "label": "not found", "files": 1, "required": 1}]

    def test_a_check_run(self):
        proc, events = self._run("--check", "--verbose")
        self.assertEqual(proc.returncode, 3)
        installer = events[0]["installer"]
        self.assertEqual(events, self._head("check", installer) + [
            {"event": "summary", "mode": "check", "installed": 0, "up_to_date": 1,
             "pending": 3, "failed": [], "skipped": self.SKIPPED, "left_out": [], "kept": [],
             "interrupted": False},
            {"event": "end", "code": 3},
        ])
        self.assertIn("1 in place, 2 missing, 1 wrong copy", proc.stderr)
        self.assertFalse((self.bios / "c.bin").exists())

    def test_an_install_run(self):
        proc, events = self._run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        installer = events[0]["installer"]
        kept = events[-2]["kept"]
        self.assertEqual(len(kept), 1, kept)
        self.assertEqual(Path(kept[0]["folder"]).parent, self.home / install.BACKUP_DIR)
        progress = [event for event in events if event["event"] == "progress"]
        for event in progress:
            self.assertEqual(list(event), ["event", *install.EVENT_KEYS["progress"]])
        done = [{"event": "downloaded", "dest": dest, "ok": True, "reason": "",
                 "size": size, "files_done": n, "files_total": 3, "bytes_done": total,
                 "bytes_total": 245}
                for n, (dest, size, total) in enumerate(
                    (("c.bin", 70, 70), ("d.bin", 25, 95), ("b.bin", 150, 245)), 1)]
        # bytes_done counts every byte arrived, as the progress events do:
        # the worker may be into the next file before a finished one is
        # reported, so it never runs back and covers at least the files done.
        downloaded = [e for e in events if e["event"] == "downloaded"]
        arrived = [e["bytes_done"] for e in downloaded]
        self.assertEqual(arrived, sorted(arrived))
        for event, expected in zip(downloaded, done):
            self.assertGreaterEqual(event["bytes_done"], expected["bytes_done"])
            self.assertLessEqual(event["bytes_done"], 245)
            event["bytes_done"] = expected["bytes_done"]
        # The last transfer: every byte came over the network.
        self.assertEqual([e for e in events if e["event"] == "transfer"][-1],
                         {"event": "transfer", "bytes_local": 0, "bytes_network": 245})
        record = next(e for e in events if e["event"] == "record")
        # What the run placed, and its choice, the whole list: written
        # right before the summary.
        self.assertEqual({key: record[key] for key in ("folder", "status", "choice", "files")},
                         {"folder": str(self.bios), "status": "written",
                          "choice": ["--all-files"], "files": 3})
        self.assertEqual(record["path"], str(self.home / install.BACKUP_DIR
                                             / f"{self.bios.name}.install.json"))
        self.assertEqual([e for e in events if e["event"] not in ("progress", "transfer")],
                         self._head("install", installer) + [
            {"event": "download", "platform": "retroarch", "files": 3, "bytes": 245},
            *done,
            record,
            {"event": "summary", "mode": "install", "installed": 3, "up_to_date": 1,
             "pending": 0, "failed": [], "skipped": self.SKIPPED, "left_out": [],
             "kept": [{"folder": kept[0]["folder"], "files": 1, "bytes": 11}],
             "interrupted": False},
            {"event": "end", "code": 0},
        ])
        self.assertEqual((self.bios / "b.bin").read_bytes(), self.FILES["bios/A/b.bin"])
        self.assertIn("Done. 3 files installed", proc.stderr)

    def test_every_event_has_its_schema_keys(self):
        _proc, events = self._run()
        for event in events:
            self.assertEqual(list(event), ["event", *install.EVENT_KEYS[event["event"]]])

    def test_a_file_list_out_of_reach_is_a_network_error(self):
        # A port nothing listens on: the connection is refused at once.
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            closed = probe.getsockname()[1]
        env = {**self.env, "RETROBIOS_BASE_URL": f"http://127.0.0.1:{closed}"}
        proc = _install_run(env, "--platform", "retroarch", "--dest", str(self.bios),
                            "--events", "--check")
        events = _events(proc)
        self.assertEqual([e["event"] for e in events], ["start", "detect", "error", "end"])
        self.assertEqual(events[2]["reason"], "network")
        self.assertEqual(events[2]["stage"], "manifest")
        self.assertEqual(events[3], {"event": "end", "code": 1})

    def test_nothing_detected_is_an_empty_platform_list(self):
        proc = _install_run(self.env, "--events", "--check")
        events = _events(proc)
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(events[1]["platforms"], [])
        self.assertEqual(events[-1], {"event": "end", "code": 1})

    def test_the_schema_is_documented(self):
        page = (REPO_ROOT / "wiki" / "installer.md").read_text(encoding="utf-8")
        for kind, keys in install.EVENT_KEYS.items():
            row = next((line for line in page.splitlines()
                        if line.startswith(f"| `{kind}` |")), None)
            self.assertIsNotNone(row, kind)
            for key in keys:
                self.assertIn(f"`{key}`", row, f"{kind}.{key}")

    def test_a_run_is_valid_against_the_published_schema(self):
        try:
            from jsonschema import Draft202012Validator
        except ImportError:
            self.skipTest("jsonschema is not installed")
        schema = json.loads(EVENT_SCHEMA_PATH.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        for argv in (("--check",), ()):
            _proc, events = self._run(*argv)
            for event in events:
                errors = [error.message for error in validator.iter_errors(event)]
                self.assertEqual(errors, [], event)
        self.assertTrue(list(validator.iter_errors({"event": "file", "platform": "x"})))
        self.assertTrue(list(validator.iter_errors(
            {"event": "end", "code": 0, "extra": 1})))


EVENT_SCHEMA_PATH = REPO_ROOT / "schemas" / "install-events.schema.json"


class TheEventSchemaFileIsEventKeys(unittest.TestCase):
    """The table in the wiki was the only description of --events a reader
    outside Python could check a stream against."""

    def _generator(self):
        from installer_build import eventschema

        return eventschema

    def test_the_committed_file_is_the_generated_one(self):
        generator = self._generator()
        self.assertEqual(EVENT_SCHEMA_PATH.read_text(encoding="utf-8"),
                         generator.render(generator.build_schema()),
                         "run python scripts/generate_event_schema.py")

    def test_each_kind_has_exactly_its_keys(self):
        schema = json.loads(EVENT_SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual(schema["properties"]["event"]["enum"], list(install.EVENT_KEYS))
        for kind, keys in install.EVENT_KEYS.items():
            shape = schema["$defs"][kind]
            self.assertEqual(shape["required"], ["event", *keys], kind)
            self.assertEqual(list(shape["properties"]), ["event", *keys], kind)
            self.assertIs(shape["additionalProperties"], False, kind)
        start = schema["$defs"]["start"]["properties"]["schema"]
        self.assertEqual(start, {"const": install.EVENT_SCHEMA})

    def test_a_key_without_a_type_stops_the_generator(self):
        generator = self._generator()
        with unittest.mock.patch.dict(install.EVENT_KEYS, {"new": ("untyped_key",)}), \
                unittest.mock.patch.object(generator, "EVENT_KEYS", install.EVENT_KEYS), \
                self.assertRaises(KeyError):
            generator.build_schema()

    def test_the_check_command_fails_on_a_stale_file(self):
        import generate_event_schema as command

        scratch = scratch_dir(self) / "events.schema.json"
        scratch.write_text("{}\n", encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(command.main(["--check", "--output", str(scratch)]), 1)
            self.assertEqual(command.main(["--output", str(scratch)]), 0)
            self.assertEqual(command.main(["--check", "--output", str(scratch)]), 0)


class TheInstallerPageIsWrittenFromTheCode(unittest.TestCase):
    """The options, events, exit codes and keys of wiki/installer.md were
    written by hand beside the code that defines them, and every audit
    found one of them behind it."""

    PAGE = REPO_ROOT / "wiki" / "installer.md"

    def setUp(self):
        import generate_installer_doc
        from installer_build import installerdoc

        self.generator = generate_installer_doc
        self.doc = installerdoc
        self.scratch = scratch_dir(self) / "installer.md"
        self.scratch.write_text(self.PAGE.read_text(encoding="utf-8"), encoding="utf-8")

    def run_generator(self, *argv: str) -> tuple[int, str]:
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = self.generator.main([*argv, "--page", str(self.scratch)])
        return code, err.getvalue()

    def test_the_committed_page_is_the_generated_one(self):
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(self.generator.main(["--check"]), 0,
                             err.getvalue() + "run python scripts/generate_installer_doc.py")

    def test_a_hand_edit_of_a_fact_fails_the_check(self):
        page = self.scratch.read_text(encoding="utf-8")
        for old, new in (("`--jobs N`", "`--jobs JOBS`"),
                         ("| `end` | `code` |", "| `end` | `code`, `reason` |"),
                         ("| Quit at once | none |", "| Quit at once | q |"),
                         # A code install.py never exits with.
                         ("| `141` |", "| `142` | stopped twice |\n| `141` |")):
            with self.subTest(edit=new):
                self.assertIn(old, page)
                self.scratch.write_text(page.replace(old, new, 1), encoding="utf-8")
                self.assertEqual(self.run_generator("--check")[0], 1)
                self.assertEqual(self.run_generator()[0], 0)
                self.assertEqual(self.scratch.read_text(encoding="utf-8"), page)

    def test_the_prose_is_kept(self):
        page = self.scratch.read_text(encoding="utf-8")
        old = "| Parallel downloads, 1 to 32, default 8 |"
        self.assertIn(old, page)
        edited = page.replace(old, "| Parallel downloads, from 1 to 32 |")
        self.scratch.write_text(edited, encoding="utf-8")
        self.assertEqual(self.run_generator("--check")[0], 0)

    def test_what_the_code_gains_stops_it_until_the_page_says_it(self):
        real = self.doc._install.build_parser

        def gained() -> argparse.ArgumentParser:
            parser = real()
            parser.add_argument("--brand-new", action="store_true", help="new")
            return parser

        page = self.scratch.read_text(encoding="utf-8")
        events = {**self.doc._install.EVENT_KEYS, "brand_new": ("thing",)}
        for name, patch in (
                ("--brand-new", unittest.mock.patch.object(
                    self.doc._install, "build_parser", gained)),
                ("brand_new", unittest.mock.patch.object(
                    self.doc._install, "EVENT_KEYS", events))):
            with self.subTest(gained=name), patch:
                code, said = self.run_generator()
                self.assertEqual(code, 1)
                self.assertIn(name, said)
                self.assertEqual(self.scratch.read_text(encoding="utf-8"), page)
                self.assertEqual(self.run_generator("--check")[0], 1)
        # The row added by hand, its first cell alone: the generator fills it.
        close = "\n\n<!-- /generated: options -->"
        self.scratch.write_text(
            page.replace(close, "\n| `--brand-new` | Something new |" + close, 1),
            encoding="utf-8")
        with unittest.mock.patch.object(self.doc._install, "build_parser", gained):
            self.assertEqual(self.run_generator()[0], 0)
        self.assertIn('| <span id="option-brand-new"></span>`--brand-new` | Something new |',
                      self.scratch.read_text(encoding="utf-8"))

    def test_the_exit_codes_are_the_ones_install_py_exits_with(self):
        self.assertEqual(self.doc.exit_codes(), [0, 1, 2, 3, 4, 130, 141])

    def test_a_missing_marker_stops_it(self):
        page = self.scratch.read_text(encoding="utf-8")
        self.scratch.write_text(page.replace("<!-- generated: route-keys -->\n", ""),
                                encoding="utf-8")
        code, said = self.run_generator("--check")
        self.assertEqual(code, 1)
        self.assertIn("route-keys", said)


if __name__ == "__main__":
    unittest.main()
