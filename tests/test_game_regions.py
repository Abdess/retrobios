"""games/regions.yml and games/extras.yml: the rules the games-on-card mode reads.

Every rule names a profile and files that profile declares, cites the code
at the profile's own pin, and speaks the region vocabulary of region.py.
The checker is run on small fixtures, once clean and once per way a rule
can lose its backing, then on the repository's own files.
"""

from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import game_rules  # noqa: E402
from common import load_emulator_profiles  # noqa: E402

FIXTURES = REPO_ROOT / "tests" / "fixtures" / "game_rules"

# The cases the research names where a proven game region does not settle
# the file (games_on_card_research.md section 2).
EXPECTED_CASES = {
    "user-region-option", "psx-override-bios", "duckstation-custom-region",
    "cross-region-fallback", "first-disc-region", "multi-area-disc",
    "saturn-kr-ipl", "saturn-disc-database", "sms-crc-list",
    "megacd-region-list", "gamecube-unknown-region", "naomi-one-archive",
    "nds-header-decides", "optional-pif",
}


def _schema_validator(name: str):
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:
        raise unittest.SkipTest(f"schema check needs jsonschema: {exc}") from exc
    schema = json.loads((REPO_ROOT / "schemas" / name).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


class FixtureChecks(unittest.TestCase):
    def setUp(self) -> None:
        self.profiles = load_emulator_profiles(str(FIXTURES / "emulators"))
        self.regions = game_rules.load_yaml(FIXTURES / "regions.yml")
        self.extras = game_rules.load_yaml(FIXTURES / "extras.yml")

    def errors(self, regions=None, extras=None) -> list[str]:
        return game_rules.check(
            regions if regions is not None else self.regions,
            extras if extras is not None else self.extras,
            self.profiles,
        )

    def psx(self, regions: dict) -> dict:
        return regions["systems"]["sony-playstation"]["psxcore"]

    def test_clean_fixture_passes(self) -> None:
        self.assertEqual(self.errors(), [])

    def test_unknown_profile(self) -> None:
        extras = copy.deepcopy(self.extras)
        extras["extras"][0]["profile"] = "nocore"
        self.assertTrue(any("no profile nocore" in e for e in self.errors(extras=extras)))

    def test_system_the_profile_does_not_run(self) -> None:
        extras = copy.deepcopy(self.extras)
        extras["extras"][0]["system"] = "sega-saturn"
        self.assertTrue(any("does not declare system" in e for e in self.errors(extras=extras)))

    def test_undeclared_file(self) -> None:
        extras = copy.deepcopy(self.extras)
        extras["extras"][0]["files"] = ["FdsBios.bin"]
        self.assertTrue(any("declares no file FdsBios.bin" in e for e in self.errors(extras=extras)))

    def test_alias_counts_as_declared(self) -> None:
        regions = copy.deepcopy(self.regions)
        self.psx(regions)["keep_all_regions"][0]["files"] = ["scph7003.bin"]
        self.assertFalse(any("declares no file" in e for e in self.errors(regions=regions)))

    def test_unknown_region(self) -> None:
        regions = copy.deepcopy(self.regions)
        self.psx(regions)["default_region"] = "usa-canada"
        self.assertTrue(any("unknown region usa-canada" in e for e in self.errors(regions=regions)))

    def test_route_to_a_region_no_file_carries(self) -> None:
        regions = copy.deepcopy(self.regions)
        self.psx(regions)["routes"] = {"south-korea": "oceania"}
        self.assertTrue(any("no file is tagged oceania" in e for e in self.errors(regions=regions)))

    def test_citation_at_another_revision(self) -> None:
        regions = copy.deepcopy(self.regions)
        self.psx(regions)["source_ref"] = "example/psxcore@deadbeef core.c:10"
        self.assertTrue(any("not a pin of the profile" in e for e in self.errors(regions=regions)))

    def test_missing_citation(self) -> None:
        regions = copy.deepcopy(self.regions)
        del self.psx(regions)["keep_all_regions"][0]["source_ref"]
        self.assertTrue(any("no source_ref" in e for e in self.errors(regions=regions)))

    def test_case_without_description(self) -> None:
        regions = copy.deepcopy(self.regions)
        self.psx(regions)["keep_all_regions"][0]["case"] = "made-up"
        self.assertTrue(any("not described" in e for e in self.errors(regions=regions)))

    def test_region_free_file_tagged_with_a_region(self) -> None:
        regions = copy.deepcopy(self.regions)
        self.psx(regions)["region_free"] = ["scph5500.bin"]
        self.assertTrue(any("tagged ['japan']" in e for e in self.errors(regions=regions)))

    def header_errors(self, header: dict) -> list[str]:
        extras = copy.deepcopy(self.extras)
        extras["extras"][0]["trigger"] = {"header": header}
        headers = game_rules.load_yaml(FIXTURES / "headers.yml")
        return game_rules.check(self.regions, extras, self.profiles, headers)

    def test_header_trigger_takes_a_label_the_reader_returns(self) -> None:
        self.assertEqual(self.header_errors({"reader": "fds-image", "values": ["fds"]}), [])

    def test_header_trigger_with_free_text(self) -> None:
        errors = self.header_errors({"reader": "fds-image", "values": ["FDS header at 0"]})
        self.assertTrue(any("never returns 'FDS header at 0'" in e for e in errors))

    def test_header_trigger_naming_no_reader(self) -> None:
        errors = self.header_errors({"reader": "fds-magic", "values": ["fds"]})
        self.assertTrue(any("no reader fds-magic" in e for e in errors))

    def test_serial_reader_takes_any_value(self) -> None:
        self.assertEqual(self.header_errors({"reader": "dc-product-id", "values": ["T7001D  50"]}), [])

    def test_header_field_value(self) -> None:
        self.assertEqual(
            self.header_errors({"reader": "dc-product-id", "field": "disk_type", "values": ["MIL CD"]}), [])
        errors = self.header_errors({"reader": "dc-product-id", "field": "area", "values": ["J"]})
        self.assertTrue(any("has no field area" in e for e in errors))

    def test_summary_is_stable(self) -> None:
        first = game_rules.summary(self.regions, self.extras)
        second = game_rules.summary(copy.deepcopy(self.regions), copy.deepcopy(self.extras))
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))
        self.assertEqual(first["case_entries"][0]["case"], "psx-override-bios")


class FixtureSchemas(unittest.TestCase):
    def test_fixtures_match_the_schemas(self) -> None:
        for name, schema in (("regions.yml", "game-regions.schema.json"),
                             ("extras.yml", "game-extras.schema.json")):
            errors = list(_schema_validator(schema).iter_errors(
                game_rules.load_yaml(FIXTURES / name)))
            self.assertEqual(errors, [], name)

    def test_schema_refuses_an_option_case_without_its_option(self) -> None:
        regions = game_rules.load_yaml(FIXTURES / "regions.yml")
        keep = regions["systems"]["sony-playstation"]["psxcore"]["keep_all_regions"][0]
        del keep["option"]
        self.assertTrue(list(_schema_validator("game-regions.schema.json").iter_errors(regions)))

    def test_schema_refuses_two_triggers(self) -> None:
        extras = game_rules.load_yaml(FIXTURES / "extras.yml")
        extras["extras"][0]["trigger"]["every_game"] = True
        self.assertTrue(list(_schema_validator("game-extras.schema.json").iter_errors(extras)))


class RepositoryRules(unittest.TestCase):
    """The committed files, against the committed profiles."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.regions = game_rules.load_yaml(REPO_ROOT / game_rules.REGIONS_FILE)
        cls.extras = game_rules.load_yaml(REPO_ROOT / game_rules.EXTRAS_FILE)

    def test_every_rule_is_backed_by_its_profile(self) -> None:
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        headers = game_rules.load_yaml(REPO_ROOT / game_rules.HEADERS_FILE)
        self.assertEqual(game_rules.check(self.regions, self.extras, profiles, headers), [])

    def test_files_match_the_schemas(self) -> None:
        self.assertEqual(list(_schema_validator("game-regions.schema.json").iter_errors(self.regions)), [])
        self.assertEqual(list(_schema_validator("game-extras.schema.json").iter_errors(self.extras)), [])

    def test_the_fourteen_cases_are_encoded_and_used(self) -> None:
        self.assertEqual(set(self.regions["cases"]), EXPECTED_CASES)
        used = {row["case"] for row in game_rules.summary(self.regions, self.extras)["case_entries"]}
        self.assertEqual(used, EXPECTED_CASES)

    def test_region_free_files_never_carry_a_region(self) -> None:
        # The installer keeps them for every region: a profile tag would let
        # a region filter drop what the code opens for every game.
        for system, cores in self.regions["systems"].items():
            for core, rule in cores.items():
                for keep in rule.get("keep_all_regions") or []:
                    if keep["keeps"] == "region-free-files":
                        self.assertTrue(set(keep["files"]) <= set(rule.get("region_free") or []),
                                        f"{system}/{core}")


if __name__ == "__main__":
    unittest.main()
