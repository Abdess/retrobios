"""The readings of scripts/site_insights.py, on synthetic figures."""
from __future__ import annotations

import tests

import datetime as dt
import email.message
import io
import json
import tempfile
import unittest
import urllib.error
import urllib.parse
import zipfile
from pathlib import Path
from unittest import mock

from sitegen import insights

PAGE = "https://abdess.github.io/retrobios/emulators/mgba/"


class FileNamesInSearches(unittest.TestCase):
    def test_each_name_carries_what_the_project_knows(self) -> None:
        queries = [insights.Query("gba_bios.bin download", PAGE, 1, 300, 8.0),
                   insights.Query("where to put GBA_BIOS.BIN", PAGE, 0, 50, 9.0),
                   insights.Query("dsp1b.rom snes", PAGE, 0, 40, 9.0),
                   insights.Query("mystery.pup", PAGE, 0, 10, 30.0),
                   insights.Query("gba bios", PAGE, 5, 900, 7.0)]
        rows = insights.searched_files(queries, held={"gba_bios.bin"}, declared={"gba_bios.bin", "dsp1b.rom"})
        self.assertEqual(rows, [("gba_bios.bin", 350, "held"), ("dsp1b.rom", 40, "declared, not held"),
                                ("mystery.pup", 10, "unknown")])


class SearchGaps(unittest.TestCase):
    def test_first_page_rarely_clicked_against_its_position(self) -> None:
        low = insights.Query("swanstation", PAGE, 3, 540, 5.6)
        fine = insights.Query("nethersx2 bios", PAGE, 54, 484, 4.6)
        far = insights.Query("xbox bios", PAGE, 0, 900, 10.7)
        expected = {5: 0.08, 6: 0.05, 11: 0.02}
        self.assertEqual(insights.missed_clicks([low, fine, far], expected), [low])
        self.assertEqual(insights.near_first_page([low, fine, far]), [far])

    def test_a_low_rate_is_normal_low_on_the_page(self) -> None:
        ninth = insights.Query("ps2 bios", PAGE, 9, 600, 8.8)
        third = insights.Query("ps1 bios", PAGE, 9, 600, 3.2)
        expected = {3: 0.20, 9: 0.013}
        self.assertEqual(insights.missed_clicks([ninth, third], expected), [third])

    def test_the_least_impressions_floor_holds(self) -> None:
        rare = insights.Query("dsp1b.rom", PAGE, 0, 99, 2.0)
        self.assertEqual(insights.missed_clicks([rare], {2: 0.3}), [])

    def test_most_clicks_lost_comes_first(self) -> None:
        small = insights.Query("a", PAGE, 0, 200, 1.0)
        large = insights.Query("b", PAGE, 0, 400, 2.0)
        self.assertEqual(insights.missed_clicks([small, large], {1: 0.3, 2: 0.2}), [large, small])


class ExpectedRate(unittest.TestCase):
    def test_each_bucket_pools_its_searches(self) -> None:
        queries = [insights.Query("a", PAGE, 30, 100, 1.2), insights.Query("b", PAGE, 10, 400, 0.9),
                   insights.Query("c", PAGE, 50, 1000, 8.6)]
        with mock.patch.object(insights, "BUCKET_FLOOR", 100):
            expected = insights.expected_ctr(queries)
        self.assertAlmostEqual(expected[1], 40 / 500)
        self.assertAlmostEqual(expected[9], 50 / 1000)

    def test_a_thin_bucket_borrows_its_neighbours(self) -> None:
        queries = [insights.Query("a", PAGE, 40, 400, 4.0), insights.Query("b", PAGE, 2, 10, 5.0),
                   insights.Query("c", PAGE, 20, 400, 6.0)]
        with mock.patch.object(insights, "BUCKET_FLOOR", 300):
            expected = insights.expected_ctr(queries)
        self.assertAlmostEqual(expected[4], 0.1)
        self.assertAlmostEqual(expected[5], 62 / 810)

    def test_positions_past_twenty_share_a_bucket(self) -> None:
        queries = [insights.Query("a", PAGE, 1, 300, 24.0), insights.Query("b", PAGE, 2, 300, 57.0)]
        with mock.patch.object(insights, "BUCKET_FLOOR", 500):
            expected = insights.expected_ctr(queries)
        self.assertAlmostEqual(expected[insights.LAST_BUCKET], 3 / 600)


class Fragments(unittest.TestCase):
    def test_anchors_of_one_page_merge(self) -> None:
        rows = [insights.Query("pcsx bios", PAGE + "#optional", 2, 100, 4.0),
                insights.Query("pcsx bios", PAGE + "#proof", 1, 300, 8.0),
                insights.Query("pcsx bios", PAGE, 0, 0, 9.0),
                insights.Query("other", PAGE + "#proof", 5, 50, 3.0)]
        merged = sorted(insights.merge_fragments(rows), key=lambda q: q.text)
        self.assertEqual(merged[0], insights.Query("other", PAGE, 5, 50, 3.0))
        self.assertEqual((merged[1].page, merged[1].clicks, merged[1].impressions), (PAGE, 3, 400))
        self.assertAlmostEqual(merged[1].position, (4.0 * 100 + 8.0 * 300) / 400)


class ByPage(unittest.TestCase):
    OTHER = "https://abdess.github.io/retrobios/emulators/duckstation/"

    def test_pages_sum_their_searches_and_lose_most_first(self) -> None:
        queries = [insights.Query("mgba bios", PAGE, 10, 100, 1.0), insights.Query("gba bios", PAGE, 0, 300, 3.0),
                   insights.Query("gba bios download", PAGE, 1, 50, 3.0), insights.Query("x", PAGE, 0, 10, 3.0),
                   insights.Query("duckstation bios", self.OTHER, 30, 100, 1.0)]
        pages = insights.by_page(queries, {1: 0.2, 3: 0.1})
        self.assertEqual([p.page for p in pages], [PAGE, self.OTHER])
        mgba = pages[0]
        self.assertEqual((mgba.clicks, mgba.impressions), (11, 460))
        self.assertAlmostEqual(mgba.position, (100 * 1.0 + 360 * 3.0) / 460)
        self.assertAlmostEqual(mgba.lost, 20 + 36 - 11)
        self.assertEqual(mgba.top, ("gba bios", "mgba bios", "gba bios download"))
        self.assertAlmostEqual(pages[1].lost, -10)

    def test_the_table_shows_changes_against_the_period_before(self) -> None:
        now = [insights.Query("mgba bios", PAGE, 10, 100, 2.0),
               insights.Query("duckstation bios", self.OTHER, 3, 50, 4.0)]
        before = [insights.Query("mgba bios", PAGE, 4, 80, 2.5)]
        text = insights.report(readings(queries=now, previous=before))
        self.assertIn("| /emulators/mgba/ |", text)
        self.assertIn("| 10 (+6) | 100 (+20) | 10.0% | 2.0 (-0.5) | mgba bios |", text)
        self.assertIn("| 3 (new) | 50 (new) |", text)
        self.assertIn("Against 2026-09-03 to 2026-09-30 (28 days): +9 clicks, +70 impressions.", text)

    def test_an_empty_period_before_is_said_and_adds_no_change(self) -> None:
        text = insights.report(readings(queries=[insights.Query("mgba bios", PAGE, 10, 100, 2.0)], previous=[]))
        self.assertIn("Search Console holds nothing for the period before, 2026-09-03 to 2026-09-30", text)
        self.assertIn("| 10 | 100 | 10.0% | 2.0 | mgba bios |", text)


class FileNamesTable(unittest.TestCase):
    def test_only_names_not_held_are_listed(self) -> None:
        queries = [insights.Query("gba_bios.bin", PAGE, 1, 300, 8.0), insights.Query("dsp1b.rom", PAGE, 0, 40, 9.0)]
        text = insights.report(readings(queries=queries, held={"gba_bios.bin"}, declared={"dsp1b.rom"}))
        self.assertIn("1 of 2 searched file names are held. Not held (1):", text)
        self.assertIn("| `dsp1b.rom` | 40 | declared, not held |", text)
        self.assertNotIn("| `gba_bios.bin` |", text)

    def test_all_held_is_one_line(self) -> None:
        text = insights.report(readings(queries=[insights.Query("gba_bios.bin", PAGE, 1, 300, 8.0)],
                                        held={"gba_bios.bin"}))
        self.assertIn("All 1 searched file names are held.", text)
        self.assertNotIn("| File |", text)


def github(downloads: list[tuple[str, str, int]]) -> dict:
    return {"views": {"count": 5, "uniques": 2, "views": [{"timestamp": "2026-11-05T00:00:00Z"},
                                                           {"timestamp": "2026-11-18T00:00:00Z"}]},
            "clones": {"count": 1}, "referrers": [], "paths": [], "downloads": downloads}


class Downloads(unittest.TestCase):
    DOWNLOADS = [("v1", "A.zip", 120), ("v1", "B.zip", 40), ("v2", "C.zip", 7)]

    def test_without_snapshot_the_totals_are_labelled_all_time(self) -> None:
        text = insights.report(readings(github=github(self.DOWNLOADS)))
        self.assertIn("No earlier snapshot", text)
        self.assertIn("| Release | File | Downloads, all time |", text)
        self.assertIn("| v1 | A.zip | 120 |", text)
        self.assertIn("14 days (2026-11-05 to 2026-11-18)", text)

    def test_with_snapshot_the_change_comes_first(self) -> None:
        snapshot = {"taken": "2026-11-12 08:00 UTC", "counts": {"v1/A.zip": 118, "v1/B.zip": 30}}
        text = insights.report(readings(github=github(self.DOWNLOADS), snapshot=snapshot))
        self.assertIn("| Release | File | Since 2026-11-12 08:00 UTC | All time |", text)
        table = text[text.index("| Release |"):]
        self.assertLess(table.index("B.zip"), table.index("C.zip"))
        self.assertIn("| v1 | B.zip | +10 | 40 |", text)
        self.assertIn("| v2 | C.zip | +7 (new) | 7 |", text)
        self.assertIn("| v1 | A.zip | +2 | 120 |", text)

    def test_the_snapshot_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "insights" / "downloads.json"
            self.assertIsNone(insights.load_snapshot(path))
            taken = dt.datetime(2026, 11, 19, 10, 30, tzinfo=dt.timezone.utc)
            insights.save_snapshot(path, insights.downloads_snapshot(self.DOWNLOADS, taken))
            snapshot = insights.load_snapshot(path)
            self.assertEqual(snapshot, {"taken": "2026-11-19 10:30 UTC",
                                        "counts": {"v1/A.zip": 120, "v1/B.zip": 40, "v2/C.zip": 7}})
            path.write_text("{", encoding="utf-8")
            with self.assertRaisesRegex(SystemExit, "not a download snapshot"):
                insights.load_snapshot(path)


class SiteActions(unittest.TestCase):
    def test_events_are_grouped_by_kind_and_pages_apart(self) -> None:
        hits = [("/emulators/mgba/", 40), ("search-none/kenji nx", 3), ("search-none/dsp1b.rom", 7),
                ("helpful/no", 2), ("/old/link/ [404]", 5), ("download/Batocera_43.1_BIOS_Pack.zip", 9)]
        actions = insights.site_actions(hits)
        self.assertEqual(actions["search-none"], [("dsp1b.rom", 7), ("kenji nx", 3)])
        self.assertEqual(actions["404"], [("/old/link/", 5)])
        self.assertEqual(actions["pages"], [("/emulators/mgba/", 40)])
        self.assertEqual(actions["helpful"], [("no", 2)])


def readings(**fields: object) -> insights.Readings:
    base: dict = {"start": dt.date(2026, 10, 1), "end": dt.date(2026, 10, 28),
                  "now": dt.datetime(2026, 11, 19, 12, 0, tzinfo=dt.timezone.utc),
                  "held": set(), "declared": set()}
    return insights.Readings(**{**base, **fields})


class TheReport(unittest.TestCase):
    def test_a_skipped_source_leaves_no_section(self) -> None:
        text = insights.report(readings(queries=[insights.Query("gba_bios.bin", PAGE, 1, 300, 8.0)],
                                        held={"gba_bios.bin"}))
        self.assertIn("## Google searches", text)
        self.assertIn("2026-10-01 to 2026-10-28 (28 days): 1 clicks", text)
        self.assertNotIn("## On the site", text)
        self.assertNotIn("## GitHub", text)

    def test_the_site_section_states_its_period(self) -> None:
        goat = {"hits": [("/emulators/mgba/", 4)], "referrers": [], "visits": 4, "actions": 0}
        text = insights.report(readings(goat=goat, goat_end=dt.date(2026, 11, 19)))
        self.assertIn("2026-10-01 to 2026-11-19 (50 days), UTC days: 4 page views", text)

    def test_the_site_period_starts_on_the_first_day_counted(self) -> None:
        goat = {"hits": [], "referrers": [], "visits": 4, "actions": 0, "first_day": dt.date(2026, 11, 6)}
        text = insights.report(readings(goat=goat, goat_end=dt.date(2026, 11, 19)))
        self.assertIn("2026-11-06 to 2026-11-19 (14 days), UTC days", text)

    def test_names_come_from_profiles_and_the_collection(self) -> None:
        db = {"indexes": {"by_name": {"SCPH5501.BIN": ["x"]}}}
        profiles = {"p": {"files": [{"name": "bios/dsp1b.rom", "aliases": ["DSP1B.bin"]}, "str"]}}
        held, declared = insights.collection_names(db, profiles)
        self.assertEqual(held, {"scph5501.bin"})
        self.assertEqual(declared, {"dsp1b.rom", "dsp1b.bin"})


def goat_export(hourly: list[tuple[str, str, str, int]]) -> bytes:
    """A GoatCounter JSON export holding (hour, path, referrer, count) rows."""
    paths = {path: n for n, path in enumerate(sorted({row[1] for row in hourly}), 100)}
    refs = {ref: n for n, ref in enumerate(sorted({row[2] for row in hourly}), 1)}
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        folder = "goatcounter-export-site-20261120T000000Z/"
        archive.writestr(folder + "info.json", "{}")
        archive.writestr(folder + "paths.jsonl", "\n".join(json.dumps(
            {"id": n, "path": path.removesuffix(" [404]"), "title": "404" if path.endswith(" [404]") else ""})
            for path, n in paths.items()))
        archive.writestr(folder + "refs.jsonl", "\n".join(json.dumps({"id": n, "ref": ref}) for ref, n in refs.items()))
        archive.writestr(folder + "hit_stats.jsonl", "\n".join(json.dumps(
            {"hour": hour, "path_id": paths[path], "ref_id": refs[ref], "count": count})
            for hour, path, ref, count in hourly))
    return buffer.getvalue()


class GoatCounterExport(unittest.TestCase):
    FIRST = dt.datetime(2026, 10, 20, tzinfo=dt.timezone.utc)
    AFTER = dt.datetime(2026, 11, 17, tzinfo=dt.timezone.utc)

    def test_counts_inside_the_span_add_up_by_path_and_referrer(self) -> None:
        raw = goat_export([("2026-10-19T23:00:00Z", "/", "", 50),
                           ("2026-10-20T00:00:00Z", "/", "", 3),
                           ("2026-10-25T10:00:00Z", "/", "Google", 4),
                           ("2026-10-25T10:00:00Z", "/gone/ [404]", "github.com", 2),
                           ("2026-11-16T23:00:00Z", "search-none/kenji", "", 5),
                           ("2026-11-17T00:00:00Z", "/", "Google", 70)])
        got = insights.read_export(raw, self.FIRST, self.AFTER)
        self.assertEqual(dict(got["hits"]), {"/": 7, "/gone/ [404]": 2, "search-none/kenji": 5})
        self.assertEqual(got["referrers"], [("Google", 4), ("(direct)", 3), ("github.com", 2)])
        self.assertEqual((got["visits"], got["actions"]), (9, 5))
        self.assertEqual(got["first_day"], dt.date(2026, 10, 20))
        self.assertEqual(insights.site_actions(got["hits"])["404"], [("/gone/", 2)])

    def test_the_export_is_asked_for_once_and_read_when_ready(self) -> None:
        raw = goat_export([("2026-10-21T08:00:00Z", "/", "", 1)])
        calls: list[tuple[str, dict | None]] = []

        def fetch(url: str, headers: dict[str, str] | None = None, body: dict | None = None) -> tuple[int, bytes]:
            calls.append((url, body))
            if url.endswith("/export"):
                return 202, json.dumps({"id": 7}).encode()
            return (202, b"") if len(calls) < 4 else (200, raw)

        with mock.patch.object(insights, "_fetch", fetch), mock.patch.object(insights.time, "sleep"):
            self.assertEqual(insights._goat_export(self.FIRST, {}), raw)
        self.assertEqual(calls[0], (f"{insights.GOATCOUNTER}/export",
                                    {"format": "json", "start_from_day": "2026-10-20T00:00:00Z"}))
        self.assertEqual([url for url, _ in calls[1:]], [f"{insights.GOATCOUNTER}/export/7/download"] * 3)

    def test_an_export_never_ready_ends_the_run(self) -> None:
        def fetch(url: str, headers: dict[str, str] | None = None, body: dict | None = None) -> tuple[int, bytes]:
            return 202, json.dumps({"id": 7}).encode()

        with mock.patch.object(insights, "_fetch", fetch), mock.patch.object(insights.time, "sleep"), \
                self.assertRaisesRegex(SystemExit, "export 7 not ready"):
            insights._goat_export(self.FIRST, {})

    def test_a_long_rate_limit_ends_the_run_instead_of_sleeping(self) -> None:
        headers = email.message.Message()
        headers["X-Rate-Limit-Reset"] = "2355"
        refusal = urllib.error.HTTPError("https://retrobios.goatcounter.com/api/v0/stats/hits", 429,
                                         "Too Many Requests", headers, io.BytesIO(b""))
        with mock.patch.object(insights.urllib.request, "urlopen", side_effect=refusal), \
                mock.patch.object(insights.upstream, "_sleep") as sleep, \
                mock.patch.object(insights.upstream, "_exhausted_hosts", set()), \
                self.assertRaisesRegex(SystemExit, "2356 s"):
            insights._get_json("https://retrobios.goatcounter.com/api/v0/stats/hits")
        sleep.assert_not_called()

    def test_a_short_rate_limit_is_waited(self) -> None:
        headers = email.message.Message()
        headers["X-Rate-Limit-Reset"] = "1"
        refusal = urllib.error.HTTPError("https://x/api", 429, "Too Many Requests", headers, io.BytesIO(b""))
        answer = mock.MagicMock()
        answer.__enter__.return_value.status = 200
        answer.__enter__.return_value.read.return_value = json.dumps({"ok": 1}).encode()
        with mock.patch.object(insights.urllib.request, "urlopen", side_effect=[refusal, answer]), \
                mock.patch.object(insights.upstream, "_sleep") as sleep:
            self.assertEqual(insights._get_json("https://x/api"), {"ok": 1})
        sleep.assert_called_once_with(2)

    def test_a_server_error_is_asked_again(self) -> None:
        """A 502 from GoatCounter ended the run on the first try."""
        refusal = urllib.error.HTTPError("https://x/api", 502, "Bad Gateway", email.message.Message(),
                                         io.BytesIO(b""))
        answer = mock.MagicMock()
        answer.__enter__.return_value.status = 200
        answer.__enter__.return_value.read.return_value = json.dumps({"ok": 1}).encode()
        with mock.patch.object(insights.urllib.request, "urlopen", side_effect=[refusal, answer]), \
                mock.patch.object(insights.upstream, "_sleep"):
            self.assertEqual(insights._get_json("https://x/api"), {"ok": 1})

    def test_github_headers_come_from_the_forge_helper(self) -> None:
        seen: list[dict[str, str]] = []

        def get_json(url: str, headers: dict[str, str] | None = None, body: dict | None = None):
            seen.append(dict(headers or {}))
            return [] if "releases" in url else {}

        with mock.patch.object(insights, "github_token", return_value="SECRET"), \
                mock.patch("core.github.github_token", return_value="SECRET"), \
                mock.patch.object(insights, "_get_json", get_json):
            insights.fetch_github()
        self.assertTrue(seen)
        for headers in seen:
            self.assertEqual(headers["Authorization"], "Bearer SECRET")
            self.assertEqual(headers["Accept"], "application/vnd.github+json")
            self.assertEqual(headers["User-Agent"], insights.USER_AGENT)


if __name__ == "__main__":
    unittest.main()
