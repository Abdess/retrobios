"""The readings of scripts/site_insights.py, on synthetic figures."""
from __future__ import annotations

import tests

import datetime as dt
import email.message
import io
import json
import unittest
import urllib.error
import urllib.parse
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
    def test_first_page_rarely_clicked(self) -> None:
        low = insights.Query("swanstation", PAGE, 3, 540, 5.6)
        fine = insights.Query("nethersx2 bios", PAGE, 54, 484, 4.6)
        far = insights.Query("xbox bios", PAGE, 0, 900, 10.7)
        self.assertEqual(insights.missed_clicks([low, fine, far]), [low])
        self.assertEqual(insights.near_first_page([low, fine, far]), [far])


class SiteActions(unittest.TestCase):
    def test_events_are_grouped_by_kind_and_pages_apart(self) -> None:
        hits = [("/emulators/mgba/", 40), ("search-none/kenji nx", 3), ("search-none/dsp1b.rom", 7),
                ("helpful/no", 2), ("/old/link/ [404]", 5), ("download/Batocera_43.1_BIOS_Pack.zip", 9)]
        actions = insights.site_actions(hits)
        self.assertEqual(actions["search-none"], [("dsp1b.rom", 7), ("kenji nx", 3)])
        self.assertEqual(actions["404"], [("/old/link/", 5)])
        self.assertEqual(actions["pages"], [("/emulators/mgba/", 40)])
        self.assertEqual(actions["helpful"], [("no", 2)])


class TheReport(unittest.TestCase):
    def test_a_skipped_source_leaves_no_section(self) -> None:
        text = insights.report(dt.date(2026, 10, 1), dt.date(2026, 10, 28),
                         [insights.Query("gba_bios.bin", PAGE, 1, 300, 8.0)], None, None,
                         held={"gba_bios.bin"}, declared=set())
        self.assertIn("## Google searches", text)
        self.assertIn("| gba_bios.bin | /emulators/mgba/ | 300 | 0.3% | 8.0 |", text)
        self.assertNotIn("## On the site", text)
        self.assertNotIn("## GitHub", text)

    def test_names_come_from_profiles_and_the_collection(self) -> None:
        db = {"indexes": {"by_name": {"SCPH5501.BIN": ["x"]}}}
        profiles = {"p": {"files": [{"name": "bios/dsp1b.rom", "aliases": ["DSP1B.bin"]}, "str"]}}
        held, declared = insights.collection_names(db, profiles)
        self.assertEqual(held, {"scph5501.bin"})
        self.assertEqual(declared, {"dsp1b.rom", "dsp1b.bin"})


class FakeGoatCounter:
    """Hourly counts by path, paged the way /stats/hits pages: by count,
    a hundred at most, past the ids in exclude_paths."""

    def __init__(self, hourly: dict[tuple[str, dt.datetime], int]) -> None:
        self.hourly = hourly
        self.ids = {path: n for n, path in enumerate(sorted({path for path, _ in hourly}), 1)}
        self.calls = 0

    def __call__(self, url: str, headers: dict[str, str] | None = None) -> dict:
        self.calls += 1
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        start = dt.datetime.strptime(query["start"][0], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
        end = dt.datetime.strptime(query["end"][0], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
        excluded = {int(i) for i in query.get("exclude_paths", [""])[0].split(",") if i}
        counts: dict[str, int] = {}
        for (path, hour), count in self.hourly.items():
            if start <= hour <= end and self.ids[path] not in excluded:
                counts[path] = counts.get(path, 0) + count
        ranked = sorted(counts.items(), key=lambda row: (-row[1], row[0]))
        limit = int(query["limit"][0])
        return {"hits": [{"path": path, "path_id": self.ids[path], "count": count,
                          "title": "404" if path.startswith("/gone") else ""} for path, count in ranked[:limit]],
                "more": len(ranked) > limit}


class GoatCounterPaging(unittest.TestCase):
    START = dt.datetime(2026, 10, 20, tzinfo=dt.timezone.utc)
    END = dt.datetime(2026, 11, 17, tzinfo=dt.timezone.utc)

    def hits(self, server: FakeGoatCounter) -> dict[str, int]:
        with mock.patch.object(insights, "_get_json", server):
            return dict(insights._goat_hits(self.START, self.END, {}))

    def test_windows_add_up_without_counting_an_hour_twice(self) -> None:
        # One visit at the last hour of each day, the hour a window boundary falls on.
        hourly = {(f"/page{day}", self.START + dt.timedelta(days=day, hours=23)): 1 for day in range(28)}
        hourly[("/gone/link/", self.START + dt.timedelta(days=7))] = 3
        hourly[("search-none/kenji", self.END - dt.timedelta(hours=1))] = 2
        hourly[("/late", self.END)] = 9
        got = self.hits(FakeGoatCounter(hourly))
        self.assertEqual(sum(got.values()), 28 + 3 + 2)
        self.assertEqual(got["/gone/link/ [404]"], 3)
        self.assertEqual(got["search-none/kenji"], 2)
        self.assertNotIn("/late", got)

    def test_a_window_with_too_many_paths_is_read_in_halves(self) -> None:
        hourly = {(f"/p{n}", self.START + dt.timedelta(hours=n % 300)): n + 1 for n in range(250)}
        server = FakeGoatCounter(hourly)
        with mock.patch.object(insights, "GOAT_MAX_EXCLUDED", 100):
            got = self.hits(server)
        self.assertEqual(got, {f"/p{n}": n + 1 for n in range(250)})
        self.assertGreater(server.calls, 4)

    def test_a_long_rate_limit_ends_the_run_instead_of_sleeping(self) -> None:
        headers = email.message.Message()
        headers["X-Rate-Limit-Reset"] = "2355"
        refusal = urllib.error.HTTPError("https://retrobios.goatcounter.com/api/v0/stats/hits", 429,
                                         "Too Many Requests", headers, io.BytesIO(b""))
        with mock.patch.object(insights.urllib.request, "urlopen", side_effect=refusal), \
                mock.patch.object(insights.time, "sleep") as sleep, \
                self.assertRaisesRegex(SystemExit, "2356 s"):
            insights._get_json("https://retrobios.goatcounter.com/api/v0/stats/hits")
        sleep.assert_not_called()

    def test_a_short_rate_limit_is_waited(self) -> None:
        headers = email.message.Message()
        headers["X-Rate-Limit-Reset"] = "1"
        refusal = urllib.error.HTTPError("https://x/api", 429, "Too Many Requests", headers, io.BytesIO(b""))
        answer = mock.MagicMock()
        answer.__enter__.return_value = io.BytesIO(json.dumps({"ok": 1}).encode())
        with mock.patch.object(insights.urllib.request, "urlopen", side_effect=[refusal, answer]), \
                mock.patch.object(insights.time, "sleep") as sleep:
            self.assertEqual(insights._get_json("https://x/api"), {"ok": 1})
        sleep.assert_called_once_with(2)


if __name__ == "__main__":
    unittest.main()
