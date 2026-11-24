"""Tests for prose citations in profile_sync: collection, recale, realign (no network)."""

from __future__ import annotations

import tests

import contextlib
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

import profile_sync
from profiling import anchoring
from profiling import citations as profiling_citations
from profiling import proseedit
from profiling import realign
from profiling import rebase
from profiling import repos as profiling_repos
from model import sourceref
from profiling.reports import (
    EntryReport,
    ProfileReport,
)
from profiling.anchoring import PartResult, worst_status
from profiling.bump import bump_commit
from profiling.citations import collect_citations
from profiling.rebase import rebase_refs
from model.sourceref import RefPart
from core import upstream
from core import upstreamtree
from tests.profilesyncsupport import PROSE_SAMPLE
from tests.profilesyncsupport import setUpModule as setUpModule
from tests.profilesyncsupport import tearDownModule as tearDownModule


class TestCollectCitations(unittest.TestCase):
    def test_files_refs_in_document_order(self):
        document = {
            "files": [
                {"name": "a.bin", "source_ref": "a.c:1"},
                {"name": "b.bin"},
                {"name": "c.bin", "source_ref": "c.c:3"},
            ],
        }
        refs = [c for c in collect_citations(document) if c.kind == "ref"]
        self.assertEqual([c.ref for c in refs], ["a.c:1", "c.c:3"])
        self.assertEqual(refs[0].field, "files[a.bin].source_ref")
        self.assertIs(refs[0].entry, document["files"][0])

    def test_data_directories_refs_are_citations_too(self):
        document = {
            "data_directories": [
                {"key": "sys", "source_ref": "loader.cpp:44"},
            ],
        }
        refs = collect_citations(document)
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0].kind, "ref")
        self.assertEqual(refs[0].ref, "loader.cpp:44")

    def test_mode_keyed_ref_keeps_its_label(self):
        document = {
            "files": [
                {
                    "name": "a.bin",
                    "source_ref": {"standalone": "a.c:1", "libretro": "b.c:2"},
                },
            ],
        }
        refs = collect_citations(document)
        self.assertEqual(
            [(c.label, c.ref) for c in refs],
            [("standalone", "a.c:1"), ("libretro", "b.c:2")],
        )

    def test_notes_citation_with_continuation_run(self):
        document = {
            "notes": "The reset path (main.c:112,1624-1633) runs first.\n",
        }
        prose = collect_citations(document)
        self.assertEqual(len(prose), 1)
        self.assertEqual(prose[0].kind, "prose")
        self.assertEqual(prose[0].field, "notes")
        self.assertEqual(prose[0].ref, "main.c:112,1624-1633")
        self.assertEqual(
            [(p.path, p.start, p.end) for p in prose[0].parts],
            [("main.c", 112, 112), ("main.c", 1624, 1633)],
        )

    def test_a_semicolon_separates_citations_like_a_comma(self):
        # lynx-emu: `...:112; mednafen src/lynx/system.cpp:86-93` cites the
        # mednafen upstream, not the fork the profile was read from.
        for line in (
            "see Lynx.emu/src/lynx/system.cpp:112; mednafen src/lynx/system.cpp:86-93",
            "see Lynx.emu/src/lynx/system.cpp:112, mednafen src/lynx/system.cpp:86-93",
            "see Lynx.emu/src/lynx/system.cpp:112. mednafen src/lynx/system.cpp:86-93",
        ):
            with self.subTest(line=line):
                start = line.index("src/lynx/system.cpp:86")
                self.assertTrue(sourceref._prose_external(line, start))
        line = "boot; then src/lynx/system.cpp:86"
        self.assertFalse(sourceref._prose_external(line, line.index("src/")))

    def test_spans_locate_the_tokens_on_the_line(self):
        document = {"notes": "See main.c:112,1624-1633 for the boot path.\n"}
        citation = collect_citations(document)[0]
        line = document["notes"].splitlines()[citation.line]
        self.assertEqual(line[slice(*citation.path_span)], "main.c")
        self.assertEqual(
            [line[lo:hi] for lo, hi in citation.spans], ["112", "1624-1633"]
        )

    def test_comma_space_is_prose_not_a_continuation(self):
        document = {"notes": "x.c:100, 200 files are read.\n"}
        citation = collect_citations(document)[0]
        self.assertEqual(citation.ref, "x.c:100")

    def test_a_url_port_is_not_a_citation(self):
        document = {"notes": "Served from https://example.com:8080/path.\n"}
        self.assertEqual(collect_citations(document), [])

    def test_version_and_ratio_text_is_not_a_citation(self):
        document = {"notes": "Since v1.6.0:123 the ratio 16:9 applies.\n"}
        self.assertEqual(collect_citations(document), [])

    def test_nested_note_and_exclusion_note_are_scanned(self):
        document = {
            "exclusion_note": "Loaded by hook.c:655 at boot.",
            "files": [
                {"name": "a.bin", "note": "Table at data.rs:12-20."},
            ],
        }
        fields = {c.field for c in collect_citations(document)}
        self.assertEqual(fields, {"exclusion_note", "files[a.bin].note"})

    def test_string_inside_a_list_is_scanned(self):
        document = {
            "analysis": {"entries": ["checked in geo.c:234-243"]},
        }
        citation = collect_citations(document)[0]
        self.assertEqual(citation.field, "analysis.entries[0]")
        self.assertEqual(citation.ref, "geo.c:234-243")

    def test_whole_value_pseudo_ref_is_a_prose_citation(self):
        document = {"analysis": {"upstream_ref": "src/a.c:12-20"}}
        citation = collect_citations(document)[0]
        self.assertEqual(citation.kind, "prose")
        self.assertEqual(citation.ref, "src/a.c:12-20")

    def test_two_runs_on_one_line_stay_separate(self):
        document = {"notes": "hook.c:655-709 and hook.c:874-928 serve it.\n"}
        refs = [c.ref for c in collect_citations(document)]
        self.assertEqual(refs, ["hook.c:655-709", "hook.c:874-928"])

    def test_trailing_comma_stays_prose(self):
        document = {"notes": "boot (pif.c:252-260,\nthen the response).\n"}
        citation = collect_citations(document)[0]
        self.assertEqual(citation.ref, "pif.c:252-260")

    def test_continuation_ending_a_sentence_is_kept(self):
        document = {"notes": "It reads b.c:2,8-9. Then it boots.\n"}
        citation = collect_citations(document)[0]
        self.assertEqual(citation.ref, "b.c:2,8-9")

    def test_decimal_number_is_not_a_continuation(self):
        document = {"notes": "Set at x.c:1,2.5 percent of the frame.\n"}
        citation = collect_citations(document)[0]
        self.assertEqual(citation.ref, "x.c:1")

    def test_dotfile_keeps_its_leading_dot(self):
        document = {"notes": "Built by CI (.gitlab-ci.yml:306) nightly.\n"}
        citation = collect_citations(document)[0]
        self.assertEqual(citation.ref, ".gitlab-ci.yml:306")
        self.assertEqual(citation.parts[0].path, ".gitlab-ci.yml")
        line = document["notes"].splitlines()[0]
        self.assertEqual(line[slice(*citation.path_span)], ".gitlab-ci.yml")

    def test_sentence_dot_is_not_a_dotfile(self):
        document = {"notes": "It runs on boot.data.c:12 is the table.\n"}
        citation = collect_citations(document)[0]
        self.assertEqual(citation.parts[0].path, "boot.data.c")

    def test_external_project_prefix_keeps_its_word(self):
        """The project word travels with the path, the source_ref convention.

        Dropping the run left m64plus-fz's `rice Config.cpp` unchecked
        although its declared repository vendors the plugin.
        """
        document = {
            "notes": "ref: mt32_model.cpp:36-97, munt ROMInfo.cpp:206-213\n"
        }
        citations = collect_citations(document)
        self.assertEqual(
            [c.ref for c in citations],
            ["mt32_model.cpp:36-97", "ROMInfo.cpp:206-213"],
        )
        self.assertEqual(citations[1].parts[0].path, "munt ROMInfo.cpp")
        self.assertTrue(profiling_citations.is_external_citation("munt ROMInfo.cpp"))

    def test_project_word_ending_the_line_before_marks_the_path_external(self):
        # genesis_plus_gx_expanded wrapped `(Batocera` and
        # `package/batocera/...mk:7` one line apart in its notes, and the
        # path was read against the declared repository: 1 to review.
        document = {
            "notes": "Batocera builds it at a0b5a033\n(Batocera\n"
            "package/batocera/emulators/gpgx.mk:7), the same tree.\n"
        }
        citation = collect_citations(document)[0]
        self.assertEqual(
            citation.parts[0].path, "Batocera package/batocera/emulators/gpgx.mk"
        )
        self.assertTrue(profiling_citations.is_external_citation(citation.parts[0].path))
        sentence = {"notes": "It is read by the file\nsrc/gpgx.c:7 at boot.\n"}
        self.assertEqual(collect_citations(sentence)[0].parts[0].path, "src/gpgx.c")

    def test_project_word_resolves_inside_a_declared_tree(self):
        tree = [
            "mupen64plus-video-rice/upstream/src/Config.cpp",
            "mupen64plus-video-gln64/src/Config.cpp",
            "mupen64plus-core/upstream/src/device/pif/bootrom_hle.c",
        ]
        resolve = sourceref.resolve_project_word
        self.assertEqual(
            resolve("rice Config.cpp", [tree]),
            "mupen64plus-video-rice/upstream/src/Config.cpp",
        )
        self.assertEqual(
            resolve("mupen64plus-core device/pif/bootrom_hle.c", [tree]),
            "mupen64plus-core/upstream/src/device/pif/bootrom_hle.c",
        )
        self.assertIsNone(resolve("munt ROMInfo.cpp", [tree]))
        self.assertIsNone(resolve("mupen64plus Config.cpp", [tree]))

    def test_project_word_resolves_inside_a_submodule(self):
        """idtech4a++ and starship cite files of a submodule. The declared
        tree holds only the gitlink, so the parts stayed external and moved
        unchecked with every bump."""
        links = ["Q3E/src/main/jni/xash3d/xash3d-fwgs", "tools/Torch", "libs/zlib"]
        resolve = profiling_repos.resolve_through_gitlinks
        self.assertEqual(
            resolve("xash3d-fwgs filesystem/filesystem.c", [links]),
            "Q3E/src/main/jni/xash3d/xash3d-fwgs/filesystem/filesystem.c",
        )
        self.assertEqual(
            resolve("Torch src/Companion.cpp", [links]), "tools/Torch/src/Companion.cpp"
        )
        self.assertIsNone(resolve("munt ROMInfo.cpp", [links]))
        self.assertIsNone(resolve("lib x.c", [["a/lib1", "b/lib2"]]))

    def test_a_submodule_file_is_read_at_its_pinned_commit(self):
        port = upstream.make_repo("github.com", "glKarin", "com.n0n3m4.diii4a")
        files = {
            (port.slug, "p1", ".gitmodules"): [
                '[submodule "Q3E/src/main/jni/xash3d/xash3d-fwgs"]',
                "\tpath = Q3E/src/main/jni/xash3d/xash3d-fwgs",
                "\turl = ../xash3d-fwgs.git",
            ],
            ("glKarin/xash3d-fwgs", "s1", "filesystem/filesystem.c"): ["getenv(x)"],
        }

        def fetch(repo, sha, path, *_):
            return files.get((repo.slug, sha, path))

        with mock.patch.object(upstream, "fetch_file", side_effect=fetch), \
                mock.patch.object(
                    upstreamtree, "list_gitlinks",
                    return_value={"Q3E/src/main/jni/xash3d/xash3d-fwgs": "s1"},
                ):
            target = upstreamtree.through_gitlink(
                port, "p1",
                "Q3E/src/main/jni/xash3d/xash3d-fwgs/filesystem/filesystem.c", "c",
            )
        self.assertEqual(
            (target[0].slug, target[1], target[2]),
            ("glKarin/xash3d-fwgs", "s1", "filesystem/filesystem.c"),
        )

    def test_run_is_rendered_with_its_written_path(self):
        parts = [RefPart("mupen64plus-video-rice/upstream/src/Config.cpp", 38, 38, "38")]
        self.assertEqual(
            proseedit.run_after_moves(parts, {0: (40, 40, None)}, "Config.cpp:38"),
            "Config.cpp:40",
        )

    def test_linking_word_is_not_a_project(self):
        document = {"notes": "It boots, in libretro.cpp:12 as shown.\n"}
        refs = [c.ref for c in collect_citations(document)]
        self.assertEqual(refs, ["libretro.cpp:12"])

    def test_spaced_range_continuation_is_part_of_the_run(self):
        document = {
            "notes": "ref: soundcanvas.cpp:55-71, 80-147, Ext plugin.cpp:23\n"
        }
        citations = collect_citations(document)
        self.assertEqual(len(citations), 2)
        self.assertEqual(citations[1].parts[0].path, "Ext plugin.cpp")
        self.assertEqual(citations[0].ref, "soundcanvas.cpp:55-71, 80-147")
        self.assertEqual(
            [(p.start, p.end) for p in citations[0].parts],
            [(55, 71), (80, 147)],
        )

    def test_spaced_lone_number_stays_prose(self):
        document = {"notes": "It reads x.c:100, 200 files at boot.\n"}
        citation = collect_citations(document)[0]
        self.assertEqual(citation.ref, "x.c:100")

    def test_spaced_lone_number_closing_the_citation_joins_the_run(self):
        # vkquake wrote `(Quake/bgmusic.c:29, 321).` and cemu a list of ten
        # lines of .gitlab-ci.yml: only the first number was ever compared.
        cases = {
            "music (Quake/bgmusic.c:29, 321).\n": [(29, 29), (321, 321)],
            "(ref: a/b.cpp:1586-1633, 2646).\n": [(1586, 1633), (2646, 2646)],
            "jobs in .gitlab-ci.yml:110, 116, 139-140\n": [
                (110, 110), (116, 116), (139, 140)
            ],
            "read at x.c:5, 6; then y\n": [(5, 5), (6, 6)],
        }
        for text, spans in cases.items():
            citation = collect_citations({"notes": text})[0]
            self.assertEqual(
                [(p.start, p.end) for p in citation.parts], spans, text
            )
            line = text.splitlines()[0]
            self.assertEqual(
                [line[lo:hi] for lo, hi in citation.spans],
                [p.raw for p in citation.parts],
            )

    def test_spaced_number_list_followed_by_a_word_stays_prose(self):
        for text in (
            "It reads x.c:5, 6, 7 players at once.\n",
            "It reads x.c:5, 6 and 7 at once.\n",
            "Lines 3, 4 and 5, version 2, 3 players.\n",
        ):
            refs = [c.ref for c in collect_citations({"notes": text})]
            self.assertEqual(refs, ["x.c:5"] if "x.c" in text else [], text)

    def test_declared_repository_name_is_not_external(self):
        document = {
            "upstream": "https://github.com/o/mednafen",
            "notes": "ref: geo.c:1-2, mednafen src/lynx/rom.cpp:55-74\n",
        }
        refs = [c.ref for c in collect_citations(document)]
        self.assertEqual(refs, ["geo.c:1-2", "src/lynx/rom.cpp:55-74"])

    def test_punctuation_before_the_path_is_not_a_project(self):
        document = {"notes": "loads it (-framefile); singe_utils.cpp:35-42\n"}
        refs = [c.ref for c in collect_citations(document)]
        self.assertEqual(refs, ["singe_utils.cpp:35-42"])

    def test_the_word_upstream_is_prose(self):
        document = {"notes": "same shape (upstream retro_host.c:196-198).\n"}
        refs = [c.ref for c in collect_citations(document)]
        self.assertEqual(refs, ["retro_host.c:196-198"])


class TestCitationSurfaceGuard(unittest.TestCase):
    def test_no_consumer_rederives_source_ref(self):
        """collect_citations is the only reader of source_ref values.

        A consumer keying on the field name reopens the gap this closes:
        citations outside its list rot while the pin advances. The walker
        matches the key once, in the model walk the site shares. Everything
        else goes through the collector. Every profiling module is read, the
        audits beside profile_sync included: mamerefs takes its driver refs
        from the collector too.
        """
        cli = Path(profile_sync.__file__)
        source = "".join(
            path.read_text(encoding="utf-8")
            for path in [cli, cli.parent / "model" / "citations.py",
                         *sorted((cli.parent / "profiling").glob("*.py"))]
        )
        self.assertNotIn('.get("source_ref")', source)
        self.assertEqual(source.count('== "source_ref"'), 1)


# One run written twice in a folded scalar: no physical line carries the
# folded sentence, and the run alone is not unique.
FOLDED_TWICE = PROSE_SAMPLE.replace(
    "files:",
    "twice: >\n  Read at (q.c:7) first\n  and again at (q.c:7) later.\nfiles:",
)


class TestRebaseProse(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "p.yml"
        self.path.write_text(PROSE_SAMPLE, encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def _report(self, entries, counts=None):
        return ProfileReport(
            name="p", repo="o/n", pin="pin", head="head",
            entries=entries, counts=counts or {},
        )

    def _prose_entry(self, ref, parts, field="notes"):
        status = worst_status([p.status for p in parts])
        return EntryReport(field, ref, status, parts, "prose", field)

    def test_shifted_prose_run_moves_and_the_sentence_stays(self):
        part = PartResult(RefPart("a.c", 10, 10, "10"), "SHIFTED", None, 14, 14, [])
        applied = rebase_refs(
            self.path, self._report([self._prose_entry("a.c:10", [part])])
        ).applied
        self.assertEqual(applied, ["notes: a.c:10 -> a.c:14"])
        text = self.path.read_text()
        self.assertIn("system directory (a.c:14) and reads", text)
        self.assertEqual(
            yaml.safe_load(text)["notes"].count("a.c:14"), 1
        )

    def test_continuation_ranges_move_together(self):
        parts = [
            PartResult(RefPart("b.c", 2, 2, "2"), "SHIFTED", None, 5, 5, []),
            PartResult(RefPart("b.c", 8, 9, "8-9"), "SHIFTED", None, 11, 12, []),
        ]
        applied = rebase_refs(
            self.path, self._report([self._prose_entry("b.c:2,8-9", parts)])
        ).applied
        self.assertEqual(applied, ["notes: b.c:2,8-9 -> b.c:5,11-12"])
        self.assertIn("both ranges (b.c:5,11-12) on boot", self.path.read_text())

    def test_prose_and_structured_move_in_one_pass(self):
        prose = PartResult(RefPart("a.c", 10, 10, "10"), "SHIFTED", None, 14, 14, [])
        structured = PartResult(RefPart("a.c", 10, 12), "SHIFTED", None, 14, 16, [])
        applied = rebase_refs(
            self.path,
            self._report([
                self._prose_entry("a.c:10", [prose]),
                EntryReport("a.bin", "a.c:10-12", "SHIFTED", [structured]),
            ]),
        ).applied
        self.assertEqual(len(applied), 2)
        text = self.path.read_text()
        self.assertIn('source_ref: "a.c:14-16"', text)
        self.assertIn("(a.c:14)", text)

    def test_review_status_blocks_prose_too(self):
        part = PartResult(RefPart("a.c", 10, 10, "10"), "SHIFTED", None, 14, 14, [])
        report = self._report(
            [self._prose_entry("a.c:10", [part])], counts={"GONE": 1}
        )
        self.assertEqual(rebase_refs(self.path, report).applied, [])
        self.assertIn("(a.c:10)", self.path.read_text())

    def test_ambiguous_sentence_location_is_left_alone(self):
        self.path.write_text(FOLDED_TWICE, encoding="utf-8")
        part = PartResult(RefPart("q.c", 7, 7, "7"), "SHIFTED", None, 9, 9, [])
        applied = rebase_refs(
            self.path, self._report([self._prose_entry("q.c:7", [part], "twice")])
        ).applied
        self.assertEqual(applied, [])
        self.assertEqual(self.path.read_text(), FOLDED_TWICE)

    def test_one_sentence_in_two_fields_moves_in_both(self):
        # emucorex cites CMakeLists.txt:706 in notes and in exclusion_note on
        # identical lines: neither was unique in the file, one was left, and
        # the pin refused to follow.
        text = PROSE_SAMPLE.replace(
            "files:",
            'quirks: |\n  The loader appends dc/ to the system directory '
            '(a.c:10) and reads\n  nothing else.\nfiles:',
        )
        self.path.write_text(text, encoding="utf-8")
        part = PartResult(RefPart("a.c", 10, 10, "10"), "SHIFTED", None, 14, 14, [])
        report = self._report([
            self._prose_entry("a.c:10", [part]),
            self._prose_entry("a.c:10", [part], "quirks"),
        ])
        self.assertEqual(
            rebase_refs(self.path, report).applied,
            ["notes: a.c:10 -> a.c:14", "quirks: a.c:10 -> a.c:14"],
        )
        written = self.path.read_text()
        self.assertEqual(written, text.replace("(a.c:10)", "(a.c:14)"))
        self.assertEqual(rebase.pending_recale(report, text=written), 0)
        self.assertTrue(bump_commit(self.path, report).moved)

    def test_a_refused_recale_names_the_citation_and_writes_nothing(self):
        # The structured ref could move, the prose could not: the run
        # printed nothing, wrote nothing, and the pin stayed.
        self.path.write_text(FOLDED_TWICE, encoding="utf-8")
        prose = PartResult(RefPart("q.c", 7, 7, "7"), "SHIFTED", None, 9, 9, [])
        structured = PartResult(RefPart("a.c", 10, 12), "SHIFTED", None, 14, 16, [])
        report = self._report([
            self._prose_entry("q.c:7", [prose], "twice"),
            EntryReport("a.bin", "a.c:10-12", "SHIFTED", [structured]),
        ])
        recale = rebase_refs(self.path, report)
        self.assertEqual(recale.applied, [])
        self.assertIn("twice: q.c:7 (0 lines carry its sentence)", recale.refused)
        self.assertEqual(self.path.read_text(), FOLDED_TWICE)

    def test_folded_scalar_moves_through_its_run_token(self):
        text = PROSE_SAMPLE.replace(
            "files:",
            "quirk_note: >\n  Loaded beside the card\n  (q.c:7). Checked"
            " later.\nfiles:",
        )
        self.path.write_text(text, encoding="utf-8")
        part = PartResult(RefPart("q.c", 7, 7, "7"), "SHIFTED", None, 9, 9, [])
        applied = rebase_refs(
            self.path,
            self._report([self._prose_entry("q.c:7", [part], "quirk_note")]),
        ).applied
        self.assertEqual(applied, ["quirk_note: q.c:7 -> q.c:9"])
        content = self.path.read_text()
        self.assertIn("(q.c:9). Checked", content)
        self.assertIn(
            "(q.c:9).", yaml.safe_load(content)["quirk_note"]
        )

    def test_folded_rename_keeps_the_separator_as_written(self):
        # boom3 cites libretro.cpp:1635-1643, 2384-2405 in a folded note.
        # The rename rewrote the run as one token without the space, and
        # the written document no longer matched the intended one.
        text = PROSE_SAMPLE.replace(
            "files:",
            "quirk_note: >\n  Passes fs_game\n  (q.c:10-12, 30-40). Checked"
            " later.\nfiles:",
        )
        self.path.write_text(text, encoding="utf-8")
        parts = [
            PartResult(RefPart("q.c", 10, 12, "10-12"), "RENAMED", "src/q.c", 20, 22, []),
            PartResult(RefPart("q.c", 30, 40, "30-40"), "RENAMED", "src/q.c", 50, 60, []),
        ]
        applied = rebase_refs(
            self.path,
            self._report([self._prose_entry("q.c:10-12, 30-40", parts, "quirk_note")]),
        ).applied
        self.assertEqual(
            applied, ["quirk_note: q.c:10-12, 30-40 -> src/q.c:20-22, 50-60"]
        )
        self.assertIn(
            "(src/q.c:20-22, 50-60).",
            yaml.safe_load(self.path.read_text())["quirk_note"],
        )

    def test_parts_disagreeing_on_the_new_file_do_not_move(self):
        parts = [
            PartResult(RefPart("b.c", 2, 2, "2"), "RENAMED", "src/b.c", 5, 5, []),
            PartResult(RefPart("b.c", 8, 9, "8-9"), "RENAMED", "old/b.c", 11, 12, []),
        ]
        applied = rebase_refs(
            self.path, self._report([self._prose_entry("b.c:2,8-9", parts)])
        ).applied
        self.assertEqual(applied, [])

    def test_renamed_prose_path_is_rewritten(self):
        part = PartResult(
            RefPart("a.c", 10, 10, "10"), "RENAMED", "src/a.c", 14, 14, []
        )
        applied = rebase_refs(
            self.path, self._report([self._prose_entry("a.c:10", [part])])
        ).applied
        self.assertEqual(applied, ["notes: a.c:10 -> src/a.c:14"])
        self.assertIn("(src/a.c:14)", self.path.read_text())


class TestPendingProse(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "p.yml"
        self.path.write_text(PROSE_SAMPLE, encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def _report(self, parts):
        status = worst_status([p.status for p in parts])
        entry = EntryReport("notes", "a.c:10", status, parts, "prose", "notes")
        return ProfileReport(
            name="p", repo="o/n", pin="pin", head="newhead",
            entries=[entry], counts={status: 1},
        )

    def test_moved_prose_still_in_the_file_blocks_the_pin(self):
        part = PartResult(RefPart("a.c", 10, 10, "10"), "SHIFTED", None, 14, 14, [])
        report = self._report([part])
        text = self.path.read_text()
        self.assertEqual(rebase.pending_recale(report, text=text), 1)
        self.assertFalse(bump_commit(self.path, report).moved)
        self.assertEqual(
            yaml.safe_load(self.path.read_text())["source_commit"], "pin"
        )

    def test_recaled_prose_lets_the_pin_advance(self):
        part = PartResult(RefPart("a.c", 10, 10, "10"), "SHIFTED", None, 14, 14, [])
        report = self._report([part])
        rebase_refs(self.path, report)
        self.assertTrue(bump_commit(self.path, report).moved)
        self.assertEqual(
            yaml.safe_load(self.path.read_text())["source_commit"], "newhead"
        )

    def test_anchored_prose_never_blocks(self):
        part = PartResult(RefPart("a.c", 10, 10, "10"), "ANCHORED", None, None, None, [])
        report = self._report([part])
        self.assertEqual(
            rebase.pending_recale(report, text=self.path.read_text()), 0
        )
        self.assertTrue(bump_commit(self.path, report).moved)

    def test_unwritable_prose_blocks_the_pin(self):
        self.path.write_text(FOLDED_TWICE, encoding="utf-8")
        part = PartResult(RefPart("q.c", 7, 7, "7"), "SHIFTED", None, 9, 9, [])
        report = self._report([part])
        report.entries[0] = EntryReport(
            "twice", "q.c:7", "SHIFTED", [part], "prose", "twice"
        )
        self.assertEqual(rebase_refs(self.path, report).applied, [])
        self.assertFalse(bump_commit(self.path, report).moved)


class TestWrappedProse(unittest.TestCase):
    """A literal block keeps its breaks: gearcoleco wrote `(libretro.cpp:`
    and put its four ranges on the next line, which the scan never read."""

    TEXT = PROSE_SAMPLE.replace(
        "files:",
        "adam: |\n  Loaded by the ADAM entry points (libretro.cpp:\n"
        "  2372-2373, 2429-2433) and by c.c:5-6,\n  40-41 at boot.\n"
        "  The data root is set in s.cpp:\n    1. -datadir\nfiles:",
    )

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "p.yml"
        self.path.write_text(self.TEXT, encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_both_wraps_are_read_whole(self):
        runs = {
            c.ref: c.wrapped
            for c in profiling_citations.collect_citations(yaml.safe_load(self.TEXT))
            if c.field == "adam"
        }
        self.assertEqual(
            runs,
            {"libretro.cpp:2372-2373, 2429-2433": True, "c.c:5-6, 40-41": True},
        )

    def test_a_break_before_the_colon_is_read_whole(self):
        # jgenesis wrote `(frontend/.../config.rs` then `:76-78,95-99)` on the
        # next line, and the citation was never collected.
        text = PROSE_SAMPLE.replace(
            "files:",
            "cfg: |\n  Read from the config (src/config.rs\n  :76-78,95-99) at start.\nfiles:",
        )
        runs = {
            c.ref: c.wrapped
            for c in profiling_citations.collect_citations(yaml.safe_load(text))
            if c.field == "cfg"
        }
        self.assertEqual(runs, {"src/config.rs:76-78,95-99": True})

    def _report(self, ref, parts):
        return ProfileReport(
            name="p", repo="o/n", pin="pin", head="newhead",
            entries=[EntryReport("adam", ref, "SHIFTED", parts, "prose", "adam")],
            counts={"SHIFTED": 1},
        )

    def test_a_wrapped_run_moves_on_both_lines_and_the_pin_follows(self):
        # gearcoleco put its four ranges on the line after `libretro.cpp:`,
        # and the run held the pin with nothing written and nothing said.
        parts = [
            PartResult(RefPart("libretro.cpp", 2372, 2373, "2372-2373"),
                       "SHIFTED", None, 2381, 2382, []),
            PartResult(RefPart("libretro.cpp", 2429, 2433, "2429-2433"),
                       "SHIFTED", None, 2438, 2442, []),
        ]
        report = self._report("libretro.cpp:2372-2373, 2429-2433", parts)
        self.assertEqual(len(rebase_refs(self.path, report).applied), 1)
        text = self.path.read_text()
        self.assertIn("(libretro.cpp:\n  2381-2382, 2438-2442) and by", text)
        self.assertTrue(bump_commit(self.path, report).moved)

    def test_a_break_before_the_colon_moves_the_next_line(self):
        # playdiaemu wrote `.../src/content.rs` and `:111-199` one line apart.
        text = PROSE_SAMPLE.replace(
            "files:",
            "adam: |\n  ZIP archives from the game path (src/content.rs\n"
            "  :111-199). No other file is opened.\nfiles:",
        )
        self.path.write_text(text, encoding="utf-8")
        part = PartResult(RefPart("src/content.rs", 111, 199, "111-199"),
                          "CHANGED", None, 111, 204, [])
        report = self._report("src/content.rs:111-199", [part])
        report.counts = {"CHANGED": 1}
        self.assertEqual(
            rebase_refs(self.path, report, accept_changed=True).applied,
            ["adam: src/content.rs:111-199 -> src/content.rs:111-204"],
        )
        self.assertIn("(src/content.rs\n  :111-204). No", self.path.read_text())
        self.assertTrue(bump_commit(self.path, report, accept_changed=True).moved)


class TestOpcodeCache(unittest.TestCase):
    """The diff cache was keyed by id() of lists anchor_block builds and frees
    on return: a later pair at the same addresses read another file's
    opcodes, and a CHANGED ref could be mapped onto the wrong line."""

    def test_each_pair_gets_its_own_diff(self):
        import difflib

        for n in range(200):
            pin = [f"line {n} {i}" for i in range(n % 7 + 2)]
            head = [f"line {n} {i}" for i in range(n % 5 + 1)] + [f"new {n}"]
            expected = difflib.SequenceMatcher(
                None, pin, head, autojunk=False
            ).get_opcodes()
            self.assertEqual(anchoring._opcodes(list(pin), list(head)), expected)


class TestCommentCitations(unittest.TestCase):
    """The loader drops comments: zesarux's `# rom_load switch,
    src/cpu.c:3212-3451` stayed on the old lines under a new pin."""

    TEXT = PROSE_SAMPLE.replace(
        "files:",
        "# rom_load switch, src/cpu.c:3212-3451\n"
        "quirk: |\n  # not a comment x.c:5 inside a block\n"
        "label: \"quoted # y.c:7\"\n"
        "files:",
    ).replace('source_ref: "a.c:10-12"', 'source_ref: "a.c:10-12"  # see z.c:9')

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "p.yml"
        self.path.write_text(self.TEXT, encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_comments_only(self):
        found = [c.ref for c in profiling_citations.comment_citations(self.TEXT)]
        self.assertEqual(found, ["src/cpu.c:3212-3451", "z.c:9"])
        document = yaml.safe_load(self.TEXT)
        self.assertNotIn(
            "src/cpu.c:3212-3451",
            [c.ref for c in profiling_citations.collect_citations(document)],
        )
        self.assertIn(
            "src/cpu.c:3212-3451",
            [c.ref for c in profiling_citations.collect_citations(document, self.TEXT)],
        )

    def _report(self, index, part):
        field = profiling_citations.comment_citations(self.TEXT)[index].field
        return ProfileReport(
            name="p", repo="o/n", pin="pin", head="newhead",
            entries=[EntryReport("comment", f"{part.part.path}:{part.part.raw}",
                                 part.status, [part], "prose", field)],
            counts={part.status: 1},
        )

    def test_a_comment_run_moves_and_the_pin_follows(self):
        # amiarcadia `# da.h:3-5` and mame2003_plus `core_options.c:223-236`
        # held the pin, and --rebase-refs wrote nothing and said nothing.
        part = PartResult(RefPart("src/cpu.c", 3212, 3451, "3212-3451"),
                          "SHIFTED", None, 3268, 3507, [])
        report = self._report(0, part)
        self.assertEqual(
            rebase_refs(self.path, report).applied,
            ["comment line 10: src/cpu.c:3212-3451 -> src/cpu.c:3268-3507"],
        )
        self.assertEqual(
            self.path.read_text(),
            self.TEXT.replace("src/cpu.c:3212-3451", "src/cpu.c:3268-3507"),
        )
        self.assertTrue(bump_commit(self.path, report).moved)

    def test_a_renamed_comment_path_is_rewritten(self):
        # bennugd `libretro.c:887-910` in a comment: RENAMED to
        # libretro/libretro.c, same lines, and nothing moved.
        part = PartResult(RefPart("z.c", 9, 9, "9"), "RENAMED", "src/z.c", 9, 9, [])
        report = self._report(1, part)
        self.assertEqual(
            rebase_refs(self.path, report).applied, ["comment line 16: z.c:9 -> src/z.c:9"]
        )
        self.assertIn('"a.c:10-12"  # see src/z.c:9', self.path.read_text())
        self.assertTrue(bump_commit(self.path, report).moved)


class TestRealignProse(unittest.TestCase):
    """A prose scalar written under an older pin realigns from that pin."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.path = self.dir / "p.yml"
        self.files: dict[tuple[str, str], list[str]] = {}
        self._orig = (
            upstream.fetch_file,
            upstreamtree.list_tree,
        )
        upstream.fetch_file = (
            lambda repo, sha, path, cache_dir, offline=False: self.files.get(
                (sha, path)
            )
        )
        upstreamtree.list_tree = (
            lambda repo, sha, cache_dir, offline=False: (
                sorted({p for _, p in self.files}), False
            )
        )

    def tearDown(self):
        (
            upstream.fetch_file,
            upstreamtree.list_tree,
        ) = self._orig
        self.tmp.cleanup()

    def _git(self, *argv):
        subprocess.run(
            ["git", "-c", "commit.gpgsign=false", *argv],
            cwd=self.dir, capture_output=True, check=True,
        )

    def _commit(self, text, message):
        self.path.write_text(text, encoding="utf-8")
        self._git("add", "p.yml")
        self._git("commit", "-m", message)

    def _repo_with_advanced_pin(self):
        self._git("init", "-q")
        self._git("config", "user.email", "t@t")
        self._git("config", "user.name", "t")
        written = PROSE_SAMPLE.replace('"pin"', '"oldpin"')
        self._commit(written, "profile")
        # The pin advances in the working tree, the text stays committed.
        self.path.write_text(PROSE_SAMPLE, encoding="utf-8")

    def test_run_realigns_from_the_writing_pin(self):
        self._repo_with_advanced_pin()
        # At the writing pin line 10 is the subject. At the current pin the
        # same content sits on line 14. Anchoring from the current pin would
        # track whatever occupies line 10 there instead.
        self.files[("oldpin", "a.c")] = ["x"] * 9 + ["subject"]
        self.files[("pin", "a.c")] = ["x"] * 13 + ["subject"]
        self.files[("oldpin", "b.c")] = ["p", "two", "q", "r", "s", "t", "u", "eight", "nine"]
        self.files[("pin", "b.c")] = ["p", "two", "q", "r", "s", "t", "u", "eight", "nine"]
        messages = realign.realign_prose(self.path, self.tmp.name)
        self.assertIn("notes: a.c:10 -> a.c:14", messages)
        text = self.path.read_text()
        self.assertIn("(a.c:14)", text)
        self.assertIn("(b.c:2,8-9)", text)
        self.assertEqual(
            yaml.safe_load(text)["source_commit"], "pin",
        )

    def test_two_entries_sharing_a_name_keep_their_own_history(self):
        # supermodel declares Games.xml once per build mode. Both notes
        # answered to files[Games.xml].note, and the history of the libretro
        # note decided where the standalone note was written.
        sample = (
            'emulator: Test\n'
            'source: "https://github.com/o/n"\n'
            'source_commit: "oldpin"\n'
            'files:\n'
            '  - name: "Games.xml"\n'
            '    mode: standalone\n'
            '    note: "Parsed at startup (a.c:10)."\n'
            '  - name: "Games.xml"\n'
            '    mode: libretro\n'
            '    note: "Read through the VFS (b.c:2)."\n'
        )
        self._git("init", "-q")
        self._git("config", "user.email", "t@t")
        self._git("config", "user.name", "t")
        self._commit(sample, "profile")
        # The pin advances and the libretro note is rewritten, uncommitted.
        self.path.write_text(
            sample.replace('"oldpin"', '"pin"').replace("(b.c:2)", "(b.c:5)"),
            encoding="utf-8",
        )
        self.files[("oldpin", "a.c")] = ["x"] * 9 + ["subject"]
        self.files[("pin", "a.c")] = ["x"] * 13 + ["subject"]
        self.files[("pin", "b.c")] = ["p"] * 4 + ["read"]
        messages = realign.realign_prose(self.path, self.tmp.name, dry_run=True)
        self.assertEqual(
            messages,
            ["would recale files[Games.xml@standalone].note: a.c:10 -> a.c:14"],
        )

    def test_pin_moved_under_committed_text_is_not_guessed(self):
        """A committed pin change under the same text may be a correction.

        vitaquake2 kept its notes while 38fc9331 re-pinned it onto the
        revision those notes described. Realigning from the first pin moved
        correct citations onto unrelated code.
        """
        self._repo_with_advanced_pin()
        self._commit(PROSE_SAMPLE, "put the pin on the revision the refs describe")
        self.files[("oldpin", "a.c")] = ["x"] * 9 + ["subject"]
        self.files[("pin", "a.c")] = ["x"] * 13 + ["subject"]
        self.files[("oldpin", "b.c")] = list("pqrstuvwx")
        self.files[("pin", "b.c")] = list("pqrstuvwx")
        before = self.path.read_text()
        messages = realign.realign_prose(self.path, self.tmp.name)
        self.assertTrue(
            any("pin moved under this text" in m for m in messages), messages
        )
        self.assertEqual(self.path.read_text(), before)

    def test_rewording_around_citations_keeps_the_writing_pin(self):
        """Punctuation edited in a note after a bump is not a new writing.

        Keyed on the whole text, the rewording commit became the writing
        revision, its pin was current, and the bump that had left the
        citations behind was no longer reported.
        """
        self._repo_with_advanced_pin()
        self._commit(PROSE_SAMPLE, "advance the pin")
        self._commit(
            PROSE_SAMPLE.replace("on boot.", "at boot."), "reword the note"
        )
        self.files[("oldpin", "a.c")] = ["x"] * 9 + ["subject"]
        self.files[("pin", "a.c")] = ["x"] * 13 + ["subject"]
        self.files[("oldpin", "b.c")] = list("pqrstuvwx")
        self.files[("pin", "b.c")] = list("pqrstuvwx")
        messages = realign.realign_prose(self.path, self.tmp.name, dry_run=True)
        self.assertTrue(
            any("pin moved under this text" in m for m in messages), messages
        )

    def test_a_citation_corrected_beside_another_dates_only_itself(self):
        """idtech4a++ advanced its pin in the commit that corrected two
        citations of its notes by hand. Dated per field, the untouched
        Game.java:69-72 took that commit's current pin and was never
        offered again, though its lines had moved."""
        self._repo_with_advanced_pin()
        self._commit(
            PROSE_SAMPLE.replace("(b.c:2,8-9)", "(b.c:3,9-10)"),
            "advance the pin, b.c corrected by hand",
        )
        self.files[("oldpin", "a.c")] = ["x"] * 9 + ["subject"]
        self.files[("pin", "a.c")] = ["x"] * 13 + ["subject"]
        self.files[("pin", "b.c")] = list("pqrstuvwxyz")
        messages = realign.realign_prose(self.path, self.tmp.name, dry_run=True)
        flagged = [m for m in messages if "a.c:10" in m]
        self.assertTrue(flagged, messages)
        self.assertFalse([m for m in messages if "b.c:" in m], messages)

    def test_a_source_declared_gone_is_read_through_its_mirror(self):
        """teknogods/TeknoParrotUI answers 404. Read there, every citation
        written under the old pin was absent and blocked the profile."""
        self._repo_with_advanced_pin()
        self._commit(
            PROSE_SAMPLE.replace(
                'source_commit: "pin"\n',
                'source_commit: "pin"\n'
                'upstream_gone: "o/n answers 404."\n'
                'source_mirror: "https://github.com/m/n"\n',
            ),
            "advance the pin, declare the forge gone",
        )
        self.files[("oldpin", "a.c")] = ["x"] * 9 + ["subject"]
        self.files[("pin", "a.c")] = ["x"] * 13 + ["subject"]
        self.files[("oldpin", "b.c")] = list("pqrstuvwx")
        self.files[("pin", "b.c")] = list("pqrstuvwx")
        served = upstream.fetch_file
        upstream.fetch_file = (
            lambda repo, sha, path, cache_dir, offline=False: (
                served(repo, sha, path, cache_dir, offline)
                if repo.slug == "m/n" else None
            )
        )
        messages = realign.realign_prose(self.path, self.tmp.name, dry_run=True)
        # b.c did not move between the two pins: nothing to read again.
        self.assertFalse([m for m in messages if "b.c:" in m], messages)

    def test_a_citation_in_an_unmoved_upstream_needs_no_reading(self):
        """nethersx2 cites AetherSX2 files that only its upstream carries,
        at an upstream pin that never moved. The port's pin did move under
        the text, and the reading through the port called each file absent
        while the other said nothing: thirteen disagreements on every run."""
        sample = (
            'emulator: Test\n'
            'source: "https://github.com/o/port"\n'
            'upstream: "https://github.com/o/up"\n'
            'source_commit: "oldpin"\n'
            'upstream_commit: "uppin"\n'
            'notes: |\n'
            '  The BIOS check lives upstream (up.c:5).\n'
        )
        self._git("init", "-q")
        self._git("config", "user.email", "t@t")
        self._git("config", "user.name", "t")
        self._commit(sample, "profile")
        self._commit(sample.replace('"oldpin"', '"pin"'), "advance the port")
        self.files[("uppin", "up.c")] = ["a", "b", "c", "d", "check bios"]
        before = self.path.read_text()
        messages = realign.realign_prose(self.path, self.tmp.name, dry_run=True)
        self.assertFalse(
            any("readings disagree" in m for m in messages), messages
        )
        self.assertEqual(self.path.read_text(), before)

    def test_dry_run_writes_nothing(self):
        self._repo_with_advanced_pin()
        self.files[("oldpin", "a.c")] = ["x"] * 9 + ["subject"]
        self.files[("pin", "a.c")] = ["x"] * 13 + ["subject"]
        self.files[("oldpin", "b.c")] = list("pqrstuvwx")
        self.files[("pin", "b.c")] = list("pqrstuvwx")
        messages = realign.realign_prose(
            self.path, self.tmp.name, dry_run=True
        )
        self.assertTrue(any("would recale" in m for m in messages))
        self.assertIn("(a.c:10)", self.path.read_text())

    def test_an_unreadable_history_blocks_rather_than_passes(self):
        """git failing (no repository, dubious ownership) read as "nothing
        written under an older pin" and let a bump through."""
        self.path.write_text(PROSE_SAMPLE, encoding="utf-8")
        messages = realign.realign_prose(self.path, self.tmp.name, dry_run=True)
        self.assertEqual(messages, ["read again: p.yml: git history unreadable"])

    def test_an_unreadable_revision_stops_the_move(self):
        self._repo_with_advanced_pin()
        self.files[("oldpin", "a.c")] = ["x"] * 9 + ["subject"]
        self.files[("pin", "a.c")] = ["x"] * 13 + ["subject"]
        with mock.patch.object(realign, "_git_file_at", return_value=None):
            messages = realign.realign_prose(self.path, self.tmp.name)
        self.assertTrue(messages)
        self.assertTrue(all(m.startswith("read again: notes:") for m in messages))
        self.assertIn("(a.c:10)", self.path.read_text())

    def _repo_with_a_broken_revision(self, broken_pin: str):
        self._git("init", "-q")
        self._git("config", "user.email", "t@t")
        self._git("config", "user.name", "t")
        written = PROSE_SAMPLE.replace('"pin"', '"oldpin"')
        self._commit(written, "profile")
        broken = PROSE_SAMPLE.replace('"pin"', f'"{broken_pin}"')
        self._commit(broken + "files: [\n", "invalid yaml")
        self._commit(written, "repair")
        self.path.write_text(PROSE_SAMPLE, encoding="utf-8")
        self.files[("oldpin", "a.c")] = ["x"] * 9 + ["subject"]
        self.files[("pin", "a.c")] = ["x"] * 13 + ["subject"]
        self.files[("oldpin", "b.c")] = list("pqrstuvwx")
        self.files[("pin", "b.c")] = list("pqrstuvwx")

    def test_a_revision_that_does_not_parse_is_passed_over(self):
        """lindbergh-loader committed invalid YAML once, repaired the same
        day under the same pin. Every older note was reported unreadable
        and the recale stayed refused for good."""
        self._repo_with_a_broken_revision("oldpin")
        messages = realign.realign_prose(self.path, self.tmp.name, dry_run=True)
        self.assertFalse(any("unreadable" in m for m in messages), messages)
        self.assertTrue(any("would recale" in m for m in messages), messages)

    def test_a_revision_that_does_not_parse_still_blocks_when_it_can_matter(self):
        """The pins differ across the gap and the note's citations changed:
        the text may have come in there under either pin."""
        self._git("init", "-q")
        self._git("config", "user.email", "t@t")
        self._git("config", "user.name", "t")
        self._commit(
            PROSE_SAMPLE.replace('"pin"', '"older"').replace("a.c:10", "a.c:3"),
            "profile",
        )
        self._commit(PROSE_SAMPLE + "files: [\n", "invalid yaml")
        self._commit(PROSE_SAMPLE.replace('"pin"', '"oldpin"'), "repair")
        self.path.write_text(PROSE_SAMPLE, encoding="utf-8")
        messages = realign.realign_prose(self.path, self.tmp.name, dry_run=True)
        self.assertTrue(any("unreadable" in m for m in messages), messages)

    def test_a_deleted_namesake_is_not_the_profiles_history(self):
        """mupen64plus.yml was renamed away in March, and a new standalone
        profile took the name in October. The deletion commit holds no file,
        so the older revisions were read as a gap and every note reported
        unreadable."""
        self._git("init", "-q")
        self._git("config", "user.email", "t@t")
        self._git("config", "user.name", "t")
        self._commit(
            PROSE_SAMPLE.replace('"pin"', '"older"').replace("a.c:10", "a.c:3"),
            "old profile",
        )
        self._git("rm", "-q", "p.yml")
        self._git("commit", "-m", "rename away")
        self._commit(PROSE_SAMPLE, "new profile")
        self.files[("pin", "a.c")] = ["x"] * 9 + ["subject"]
        self.assertEqual(
            realign.realign_prose(self.path, self.tmp.name, dry_run=True), []
        )

    def test_scalar_written_at_the_current_pin_is_left_alone(self):
        self._git("init", "-q")
        self._git("config", "user.email", "t@t")
        self._git("config", "user.name", "t")
        self._commit(PROSE_SAMPLE, "profile")
        self.files[("pin", "a.c")] = ["x"] * 9 + ["subject"]
        self.assertEqual(
            realign.realign_prose(self.path, self.tmp.name), []
        )

    def test_range_lost_between_the_pins_is_reported_not_moved(self):
        self._repo_with_advanced_pin()
        self.files[("oldpin", "a.c")] = ["x"] * 9 + ["subject"]
        self.files[("pin", "a.c")] = ["y"] * 20
        self.files[("oldpin", "b.c")] = list("pqrstuvwx")
        self.files[("pin", "b.c")] = list("pqrstuvwx")
        messages = realign.realign_prose(self.path, self.tmp.name)
        self.assertTrue(any("read again" in m for m in messages))
        self.assertIn("(a.c:10)", self.path.read_text())

    def test_unreadable_tree_is_not_an_absence(self):
        self._git("init", "-q")
        self._git("config", "user.email", "t@t")
        self._git("config", "user.name", "t")
        base = PROSE_SAMPLE.replace("(a.c:10)", "(deep.c:10)")
        self._commit(base.replace('"pin"', '"oldpin"'), "profile")
        self.path.write_text(base, encoding="utf-8")
        upstreamtree.list_tree = (
            lambda repo, sha, cache_dir, offline=False: ([], True)
        )
        self.files[("oldpin", "b.c")] = list("pqrstuvwx")
        self.files[("pin", "b.c")] = list("pqrstuvwx")
        messages = realign.realign_prose(self.path, self.tmp.name)
        self.assertTrue(
            any("tree unreadable" in m for m in messages), messages
        )
        self.assertFalse(any("absent at the writing" in m for m in messages))

    def test_several_paths_carrying_the_name_stay_unclear(self):
        self._git("init", "-q")
        self._git("config", "user.email", "t@t")
        self._git("config", "user.name", "t")
        base = PROSE_SAMPLE.replace("(a.c:10)", "(deep.c:10)")
        self._commit(base.replace('"pin"', '"oldpin"'), "profile")
        self.path.write_text(base, encoding="utf-8")
        self.files[("oldpin", "src/deep.c")] = ["x"]
        self.files[("oldpin", "contrib/deep.c")] = ["y"]
        self.files[("oldpin", "b.c")] = list("pqrstuvwx")
        self.files[("pin", "b.c")] = list("pqrstuvwx")
        messages = realign.realign_prose(self.path, self.tmp.name)
        self.assertTrue(
            any("2 paths carry the name" in m for m in messages), messages
        )

    def test_bare_filename_resolves_through_the_tree(self):
        self._git("init", "-q")
        self._git("config", "user.email", "t@t")
        self._git("config", "user.name", "t")
        base = PROSE_SAMPLE.replace("(a.c:10)", "(deep.c:10)")
        self._commit(base.replace('"pin"', '"oldpin"'), "profile")
        self.path.write_text(base, encoding="utf-8")
        self.files[("oldpin", "src/deep.c")] = ["x"] * 9 + ["subject"]
        self.files[("pin", "src/deep.c")] = ["x"] * 13 + ["subject"]
        self.files[("oldpin", "b.c")] = list("pqrstuvwx")
        self.files[("pin", "b.c")] = list("pqrstuvwx")
        messages = realign.realign_prose(self.path, self.tmp.name)
        self.assertIn("notes: deep.c:10 -> deep.c:14", messages)
        self.assertIn("(deep.c:14)", self.path.read_text())


class TestRealignFlagMatrix(unittest.TestCase):
    """--realign-prose applies a flag or refuses it, never swallows it."""

    def _run(self, *extra):
        argv = ["profile_sync.py", "--emulator", "x", "--realign-prose", *extra]
        stderr = io.StringIO()
        saved = sys.argv
        try:
            sys.argv = argv
            with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as caught:
                profile_sync.main()
        finally:
            sys.argv = saved
        return caught.exception.code, stderr.getvalue()

    def test_output_flags_are_refused(self):
        for flag in (
            "--json", "--markdown", "--fetch-plan", "--triage",
            "--changed-only", "--strict", "--check-version", "--detect-new-files",
            "--watch-hashes", "--full-diff", "--tree-diff",
            "--accept-changed",
        ):
            code, err = self._run(flag)
            self.assertEqual(code, 1, flag)
            self.assertIn("does not apply", err, flag)

    def test_write_flags_are_refused(self):
        for flag in ("--rebase-refs", "--bump-commit", "--backfill-commits"):
            code, err = self._run(flag)
            self.assertEqual(code, 1, flag)
            self.assertIn("runs alone", err, flag)


if __name__ == "__main__":
    unittest.main()
