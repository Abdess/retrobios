"""Header readers: schema, references between readers and cores, pinned citations."""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import json
import re
import sys
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from common import load_emulator_profiles  # noqa: E402
from region import REGIONS  # noqa: E402

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover - CI installs it
    Draft202012Validator = None

HEADERS = ROOT / "games" / "headers.yml"
_CITATION = re.compile(r"^([\w.-]+/[\w.-]+)@([0-9a-f]{8,40}) ")
# Tools the containers cite that are not emulators: no profile pins them.
TOOL_REPOS = {"python/cpython", "ip7z/7zip"}


def load() -> dict:
    return yaml.safe_load(HEADERS.read_text(encoding="utf-8"))


def pins(profile: dict) -> set[str]:
    out: set[str] = set()
    for key in ("source_commit", "upstream_commit"):
        value = profile.get(key)
        if isinstance(value, dict):
            out.update(str(v) for v in value.values() if v)
        elif value:
            out.add(str(value))
    return out


def outcomes(node: object) -> list[list[str]]:
    """Every region list anywhere below a node."""
    found: list[list[str]] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "regions" and isinstance(value, list):
                found.append(value)
            else:
                found += outcomes(value)
    elif isinstance(node, list):
        if node and all(isinstance(v, str) and v in REGIONS for v in node):
            found.append(node)
        for value in node:
            found += outcomes(value)
    return found


def decode(reader: dict, raw: object) -> object:
    """A reference decoder for the kinds whose rule is a plain lookup."""
    rule = reader["decode"]
    kind = rule["kind"]
    for entry in rule["values"]:
        value = entry["value"]
        hit = (
            (kind == "exact-prefix" and str(raw).startswith(value))
            or (kind == "prefix-nocase" and str(raw).lower().startswith(value))
            or (kind == "integer" and raw == value)
            or (kind == "char-at" and len(str(raw)) > rule["index"]
                and str(raw)[rule["index"]] == value)
        )
        if hit:
            return entry.get("regions") or entry.get("standard") or entry.get("label")
    return rule["otherwise"]


def check(cond: dict, data: bytes) -> bool:
    """A reference evaluator for the byte, text and size tests of a predicate."""
    if "all" in cond:
        return all(check(c, data) for c in cond["all"])
    if "any" in cond:
        return any(check(c, data) for c in cond["any"])
    if "file_size" in cond:
        bounds = cond["file_size"]
        return bounds.get("min", 0) <= len(data) <= bounds.get("max", len(data))
    offset = cond["offset"]
    if "text" in cond or "not_text" in cond:
        want = cond.get("text", cond.get("not_text"))
        hit = data[offset:offset + len(want)] == want.encode("latin-1")
        return hit if "text" in cond else not hit
    value = data[offset] & cond.get("mask", 0xFF)
    if "equals" in cond:
        return value == cond["equals"]
    if "not_equals" in cond:
        return value != cond["not_equals"]
    return value in cond["in"]


class HeaderReaders(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.doc = load()
        cls.profiles = load_emulator_profiles(str(ROOT / "emulators"))

    @unittest.skipIf(Draft202012Validator is None, "jsonschema not installed")
    def test_schema(self) -> None:
        schema = json.loads((ROOT / "schemas" / "game-headers.schema.json").read_text())
        errors = [f"{list(e.path)}: {e.message}" for e in Draft202012Validator(schema).iter_errors(self.doc)]
        self.assertEqual(errors, [])

    def test_core_order_names_readers_of_its_system(self) -> None:
        for system, block in self.doc["systems"].items():
            for core, spec in block["cores"].items():
                missing = [r for r in spec["order"] if r not in block["readers"]]
                self.assertEqual(missing, [], f"{system}/{core}")

    def test_every_core_is_a_profile(self) -> None:
        for system, block in self.doc["systems"].items():
            for core in block["cores"]:
                self.assertIn(core, self.profiles, system)

    def test_every_system_is_a_repository_system(self) -> None:
        from romfolders import SystemResolver

        ids = SystemResolver.from_repo().ids
        self.assertEqual([s for s in self.doc["systems"] if s not in ids], [])

    def test_regions_are_vocabulary(self) -> None:
        for regions in outcomes(self.doc["systems"]):
            self.assertLessEqual(set(regions), set(REGIONS), regions)

    def test_core_citations_name_the_profile_pin(self) -> None:
        for system, block in self.doc["systems"].items():
            for core, spec in block["cores"].items():
                match = _CITATION.match(spec["source_ref"])
                self.assertIsNotNone(match, f"{system}/{core}")
                sha = match.group(2)
                self.assertTrue(any(p.startswith(sha) for p in pins(self.profiles[core])),
                                f"{system}/{core}: {sha} is not a pin of the profile")

    def test_reader_citations_name_a_profile_pin(self) -> None:
        every_pin = {p for profile in self.profiles.values() for p in pins(profile)}
        refs = [(f"{s}/{r}", spec["source_ref"]) for s, block in self.doc["systems"].items()
                for r, spec in block["readers"].items()]
        refs += [(f"containers/{c}", spec["source_ref"]) for c, spec in self.doc["containers"].items()]
        for label, ref in refs:
            match = _CITATION.match(ref)
            self.assertIsNotNone(match, label)
            if match.group(1) in TOOL_REPOS:
                continue
            self.assertTrue(any(p.startswith(match.group(2)) for p in every_pin),
                            f"{label}: {match.group(2)} pins no profile")

    def test_reference_decodes(self) -> None:
        psx = self.doc["systems"]["sony-playstation"]["readers"]
        self.assertEqual(decode(psx["psx-serial-prefix"], "SLUS_012.34"), ["north-america"])
        self.assertEqual(decode(psx["psx-serial-prefix"], "SCES_000.01"), ["europe"])
        self.assertEqual(decode(psx["psx-serial-prefix"], "XXXX_000.01"), "unknown")
        self.assertEqual(decode(psx["psx-serial-letter"], "SLPS_012.04"), ["japan"])
        self.assertEqual(decode(psx["psx-licence-offset60"], "Euro pe   "), ["europe"])
        mcd = self.doc["systems"]["sega-megacd"]["readers"]["mcd-security-code"]
        self.assertEqual(decode(mcd, 0x64), ["europe"])
        self.assertEqual(decode(mcd, 0x7A), ["north-america"])
        gc = self.doc["systems"]["nintendo-gamecube"]["readers"]["gc-region"]
        self.assertEqual(decode(gc, 3), "unknown")
        n64 = self.doc["systems"]["nintendo-64"]["readers"]["n64-country"]
        self.assertEqual(decode(n64, 0x45), {"standard": "ntsc"})
        self.assertEqual(decode(n64, 0x50), "pal")

    def test_reader_ids_are_unique(self) -> None:
        ids = [r for block in self.doc["systems"].values() for r in block["readers"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_reader_extras_names_exists(self) -> None:
        extras = yaml.safe_load((ROOT / "games" / "extras.yml").read_text(encoding="utf-8"))
        defined = {r for block in self.doc["systems"].values() for r in block["readers"]}
        named = {
            entry["trigger"]["header"]["reader"]
            for entry in extras["extras"]
            if "header" in entry.get("trigger", {})
        }
        self.assertTrue(named)
        self.assertEqual(sorted(named - defined), [])

    def test_predicate_readers_decode_reference_bytes(self) -> None:
        systems = self.doc["systems"]
        sgb = systems["nintendo-sgb"]["readers"]["gb-sgb-flag"]["decode"]
        header = bytearray(0x150)
        header[0x146], header[0x14B] = 0x03, 0x33
        self.assertTrue(all(check(c, bytes(header)) for c in sgb["all"]))
        header[0x143] = 0x80
        self.assertFalse(all(check(c, bytes(header)) for c in sgb["all"]))
        sufami = systems["nintendo-sufami-turbo"]["readers"]["sufami-magic"]["decode"]
        cart = bytearray(0x80000)
        cart[0:14] = b"BANDAI SFC-ADX"
        self.assertTrue(all(check(c, bytes(cart)) for c in sufami["all"]))
        cart[0x10:0x1E] = b"SFC-ADX BACKUP"
        self.assertFalse(all(check(c, bytes(cart)) for c in sufami["all"]))

    def test_cores_that_pick_no_bios_read_nothing_for_it(self) -> None:
        for system, block in self.doc["systems"].items():
            for core, spec in block["cores"].items():
                if spec.get("selects_bios") is False:
                    self.assertNotIn("preference", spec, f"{system}/{core}")


if __name__ == "__main__":
    unittest.main()
