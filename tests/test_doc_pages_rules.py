"""What the wiki states about the data model holds against the code.

A page that quotes a resolution order, a field list or a rule drifts when
the code moves, and nothing else notices.
"""

from __future__ import annotations

import tests
from tests.mdsections import FENCED

import hashlib
import inspect
import io
import json
import re
import unittest
import zipfile

from tests.docpagessupport import PUBLISHED, ROOT, WIKI, _page, _registry, _schema, _section, _table_rows


class OneResolutionChain(unittest.TestCase):
    """architecture.md drew path_suffix as the first step, before SHA1, while
    the code and verification-modes.md try it after every hash."""

    ORDER = ("SHA1", "SHA256", "CRC32", "MD5", "Path suffix")

    def test_the_table_follows_the_code(self):
        from resolve.localfile import resolve_local_file

        source = inspect.getsource(resolve_local_file)
        steps = re.findall(r"# \d+[a-z]?\. (SHA1|SHA256|CRC32|MD5|Path suffix)", source)
        self.assertEqual(tuple(dict.fromkeys(steps)), self.ORDER)
        table = _table_rows(_section(_page("verification-modes.md"), "File resolution chain"))
        methods = [row[1] for row in table[: len(self.ORDER)]]
        self.assertEqual(
            [next(m for m in self.ORDER if method.startswith(m)) for method in methods],
            list(self.ORDER),
        )

    def test_architecture_links_instead_of_drawing_a_second_one(self):
        section = _section(_page("architecture.md"), "File resolution chain")
        self.assertNotIn("```mermaid", section)
        self.assertIn("verification-modes.md#file-resolution-chain", section)


class RequirementFieldsTable(unittest.TestCase):
    """The table stopped at native_id: native_path, mirror_of, alt_md5 and
    the native dict, the fields that make a platform YAML reversible, were
    named nowhere a scraper author reads first."""

    def test_every_field_and_native_key_is_listed(self) -> None:
        from dataclasses import fields

        from scraper.base_scraper import BiosRequirement

        section = _section(_page("adding-a-platform.md"), "BiosRequirement fields")
        listed = {row[0].strip("`") for row in _table_rows(section)}
        self.assertEqual(listed, {f.name for f in fields(BiosRequirement)})
        native_row = next(row for row in _table_rows(section) if row[0] == "`native`")[2]
        keys: set[str] = set()
        for path in (ROOT / "scripts" / "scraper").glob("*_scraper.py"):
            source = path.read_text(encoding="utf-8")
            keys |= set(re.findall(r'native\["(\w+)"\]', source))
            keys |= set(re.findall(r'native(?:: dict\[str, object\])?\s*=\s*\{"(\w+)"', source))
        self.assertTrue(keys)
        for key in keys:
            self.assertIn(f"`{key}`", native_row)


class RecalboxSeverity(unittest.TestCase):
    """The table gave verify.py a mapping from hashMatchMandatory that the
    code never reads, and called a missing optional file GREEN."""

    def test_the_verify_column_is_what_compute_severity_returns(self):
        from packs.verdicts import Status, compute_severity

        section = _section(_page("verification-modes.md"), "Mandatory levels (Recalbox)")
        rows = _table_rows(section)
        self.assertTrue(rows)
        status = {"hash matches": Status.OK, "missing": Status.MISSING, "hash differs": Status.UNTESTED}
        for state, mandatory, _hash_match, _colour, expected in rows:
            for required in ((True, False) if mandatory == "(any)" else (mandatory == "true",)):
                self.assertEqual(
                    compute_severity(status[state], required, "md5").upper(), expected,
                    f"{state} mandatory={mandatory}",
                )
        self.assertNotIn("severity levels", _page("tools.md"))


class Md5CompositeDefinition(unittest.TestCase):
    """The page described the MD5 of the members' MD5s, the code hashes the
    members' contents in name order."""

    def test_page_and_code_agree(self):
        from core.hashing import md5_composite_of

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            zf.writestr("b.rom", b"BBBB")
            zf.writestr("a.rom", b"AAAA")
        buffer.seek(0)
        self.assertEqual(md5_composite_of(buffer), hashlib.md5(b"AAAABBBB").hexdigest())
        section = _section(_page("verification-modes.md"), "md5_composite (Recalbox ZIP verification)")
        self.assertIn("contents of every member", section)
        self.assertNotIn("inner file MD5s", section)

    def test_composite_only_is_read_by_both_checks(self):
        """The page said the direct MD5 is tried before the composite, which
        Recalbox never does for a .zip, and the pack check did the same."""
        from resolve.localfile import resolve_local_file
        from resolve.acceptance import digest_verdict

        section = _section(_page("verification-modes.md"), "md5_composite (Recalbox ZIP verification)")
        self.assertIn("zip_digest: composite", section)
        self.assertNotIn("is tried before reporting a mismatch", section)
        for function in (resolve_local_file, digest_verdict):
            self.assertIn('get("zip_digest") == "composite"', inspect.getsource(function))


class ValidationIndexScope(unittest.TestCase):
    """The page said the index reads every profile. verify and the builder
    pass it only the profiles the platform resolves."""

    def test_page_names_the_scope_the_code_uses(self):
        from packs import coverage

        source = inspect.getsource(coverage.verify_platform)
        self.assertRegex(source, r"plat_cores = resolve_platform_cores\(config, profiles\)")
        self.assertIn("build_validation_index(platform_profiles)", source)
        section = _section(_page("verification-modes.md"), "Validation index")
        self.assertIn("resolve_platform_cores", section)
        self.assertNotIn("reads all emulator profiles", section)


class CoreResolutionWrittenOnce(unittest.TestCase):
    """architecture.md and adding-a-platform.md each stated the core
    resolution rule, and only one knew that a list naming retroarch takes
    every libretro profile. Neither said built_by profiles stay out."""

    def test_one_statement_matching_the_platforms_and_the_code(self):
        import yaml

        from resolve.cores import resolve_platform_cores, _platform_profiles

        self.assertNotIn("cores: [list]", _page("architecture.md"))
        # resolve_platform_cores narrows by target, _platform_profiles holds
        # the strategies.
        source = inspect.getsource(_platform_profiles)
        self.assertIn('not p.get("built_by")', source)
        self.assertIn('"retroarch" in core_set', source)
        self.assertIn('config.get("installable_cores")', source)
        self.assertIn("downloadable_on", inspect.getsource(resolve_platform_cores))
        naming = set()
        for path in (ROOT / "platforms").glob("*.yml"):
            config = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            cores = config.get("cores")
            if isinstance(cores, list) and "retroarch" in map(str, cores):
                naming.add(str(config.get("platform") or path.stem).lower())
        section = _section(_page("adding-a-platform.md"), "Required fields")
        bullet = next(p for p in section.split("\n- ") if p.startswith("**Explicit list**"))
        used_by = re.search(r"Used by ([^.]+)\.", bullet.replace("\n", " ")).group(1)
        names = [n.strip().lower() for n in used_by.split(",")]
        words = {2: "two", 3: "three", 4: "four", 5: "five"}
        counted = re.search(r"\(the last\s+(\w+)\)", bullet).group(1)
        self.assertEqual(counted, words[len(naming)])
        self.assertEqual(set(names[-len(naming):]), naming)
        libretro = next(p for p in section.split("\n- ") if p.startswith("**all_libretro**"))
        self.assertIn("built_by", libretro)
        for name in ("installable_cores", "downloadable_on", "downloaded_cores"):
            self.assertIn(f"`{name}`", bullet)


class ProfileFieldsRequired(unittest.TestCase):
    """The table marked source, profiled_date, core_version and systems as
    required and called the schema authoritative, which requires none."""

    def test_yes_matches_the_schema(self):
        schema = json.loads((ROOT / "schemas" / "emulator.schema.json").read_text(encoding="utf-8"))
        required = set(schema["required"])
        for rule in schema.get("allOf", []):
            for branch in ("then", "else"):
                required |= set(rule.get(branch, {}).get("required", []))
        section = _section(_page("profiling.md"), "Profile fields")
        marked = {
            row[0].strip("`") for row in _table_rows(section)
            if row[1].startswith(("yes", "for `type", "with `"))
        }
        self.assertEqual(marked, required)


class ShortMd5Handling(unittest.TestCase):
    """Three pages said some Batocera entries carry 29-character MD5s and show
    as untested. No platform YAML holds one, since the Batocera scraper
    completes them, and adding-a-scraper.md said to store them as-is."""

    def test_no_page_claims_short_md5_entries(self):
        offenders = [
            page.name for page in PUBLISHED
            if re.search(r"(?i)29[- ]char|truncated md5 hashes in some entries|store the hash as-is",
                         page.read_text(encoding="utf-8"))
        ]
        self.assertEqual(offenders, [])

    def test_the_page_names_what_the_code_does(self):
        from resolve.localfile import resolve_local_file
        from scraper import batocera_scraper

        scraper = inspect.getsource(batocera_scraper)
        self.assertIn("_resolve_truncated_md5(value, md5_index) for value in values", scraper)
        resolver = inspect.getsource(resolve_local_file)
        self.assertIn("cut_md5_owner(cut, by_md5)", resolver)
        self.assertIn("_md5_name_ok(path)", resolver)
        section = _section(_page("verification-modes.md"), "MD5 shorter than 32 characters (Batocera)")
        self.assertIn("_resolve_truncated_md5", section)
        self.assertIn("cut_md5_owner", section)


class RegistryKeysDocumented(unittest.TestCase):
    """zip_digest, firmware_folder_flat and extract_to were read from the
    registry by the resolver, the pack and the README, and the page that
    adds a platform named none of them while saying runtime behaviour lives
    in the platform YAML only."""

    def test_every_registry_key_is_on_the_page(self):
        import yaml

        registry = yaml.safe_load((ROOT / "platforms" / "_registry.yml").read_text(encoding="utf-8"))
        keys = {key for entry in registry["platforms"].values() for key in entry}
        page = _page("adding-a-platform.md")
        self.assertEqual(sorted(k for k in keys if not re.search(rf"\b{k}\b", page)), [])

    def test_the_page_says_the_registry_reaches_the_config(self):
        from model import platforms

        source = inspect.getsource(platforms.load_platform_config)
        self.assertIn("config[key] = val", source)
        section = _section(_page("adding-a-platform.md"), "Step 2: Register the platform")
        self.assertIn("copies every registry key", section)
        self.assertNotIn("belongs to the platform\nYAML", section)


class ResolutionSkipsNamesForUnheldFiles(unittest.TestCase):
    """The resolution table promised name_exact to any entry without a hash,
    while an unsourceable entry, or one whose indexed path is absent from
    disk, skips every step that answers by name and returns not_found."""

    def test_the_page_names_both_cases_the_code_guards(self):
        from resolve.localfile import resolve_local_file

        source = inspect.getsource(resolve_local_file)
        self.assertIn('unsourceable = bool(file_entry.get("unsourceable")) or own_file_absent', source)
        for guard in (
            "if not has_strong_hash and not unsourceable:",
            "elif not unsourceable:",
            "if _depth < 3 and not has_strong_hash and not unsourceable:",
            "if data_dir_registry and (has_strong_hash or not unsourceable):",
        ):
            self.assertIn(guard, source)
        section = _section(_page("verification-modes.md"), "File resolution chain")
        self.assertIn("`unsourceable:`", section)
        self.assertIn("restore_large_files.py", section)


def _table_fields(section: str) -> set[str]:
    fields = set()
    for line in section.splitlines():
        cell = re.match(r"^\| ((?:`[a-z_0-9]+`(?:, )?)+) \|", line)
        if cell:
            fields |= set(re.findall(r"`([a-z_0-9]+)`", cell.group(1)))
    return fields


class ProfileFieldTables(unittest.TestCase):
    """Seven profile-level fields (pin_frozen, data_root, version_source and
    four more) sat in the file entry table, where a reader wrote them on a
    file and the schema refused it."""

    def test_each_table_holds_its_level_of_the_schema(self):
        schema = _schema("emulator")
        top = set(schema["properties"])
        entry = set(schema["properties"]["files"]["items"]["properties"])
        page = _page("profiling.md")
        profile_section = page.split("### Profile fields")[1].split("\n### ")[0]
        described = _table_fields(profile_section)
        described |= set(re.findall(r"`([a-z_0-9]+)`", profile_section.split("Descriptive fields")[1]))
        self.assertEqual(sorted(described ^ top), [])
        file_section = page.split("### File entry fields")[1].split("\n## ")[0]
        self.assertEqual(sorted(_table_fields(file_section) ^ entry), [])
        self.assertIn("pin_frozen", _table_fields("| `pin_frozen` | why |") - entry)


class PlatformListsFollowTheRegistry(unittest.TestCase):
    """The mode lists and the list of platforms naming their cores were
    written by hand: KNULLI, AmberELEC, EmuELEC and the MinUI family were
    missing from the core list."""

    def _names(self) -> dict[str, str]:
        import yaml

        names = {}
        for key, entry in _registry().items():
            config = yaml.safe_load((ROOT / "platforms" / entry["config"]).read_text(encoding="utf-8"))
            names[str(config.get("platform") or key)] = key
        return names

    def _modes(self) -> dict[str, str]:
        from model import platforms

        return {key: platforms.load_platform_config(key, str(ROOT / "platforms")).get("verification_mode")
                for key in _registry()}

    def _split(self, text: str) -> set[str]:
        names = self._names()
        listed = {n.strip() for n in re.split(r",|\band\b", text) if n.strip()}
        unknown = listed - set(names)
        self.assertEqual(unknown, set(), "not in platforms/_registry.yml")
        return {names[n] for n in listed}

    def test_verification_mode_sections(self):
        page = _page("verification-modes.md")
        modes = self._modes()
        seen = set()
        for mode, heading in (("existence", "Existence mode"), ("md5", "MD5 mode"), ("sha1", "SHA1 mode")):
            line = re.search(r"\*\*Platforms\*\*: (.+)", _section(page, heading)).group(1)
            keys = self._split(line)
            self.assertEqual({k for k in keys if modes[k] != mode}, set(), mode)
            seen |= keys
        self.assertEqual(seen, set(_registry()))

    def test_adding_a_platform_mode_table(self):
        section = _section(_page("adding-a-platform.md"), "Step 4: Add verification logic")
        modes = self._modes()
        seen = set()
        for row in _table_rows(section):
            keys = self._split(row[2])
            self.assertEqual({k for k in keys if modes[k] != row[0].strip("`")}, set(), row[0])
            seen |= keys
        self.assertEqual(seen, set(_registry()))

    def test_the_explicit_core_lists(self):
        import yaml

        section = _section(_page("adding-a-platform.md"), "Required fields")
        bullet = next(p for p in section.split("\n- ") if p.startswith("**Explicit list**"))
        used_by = re.search(r"Used by ([^.]+)\.", bullet.replace("\n", " ")).group(1)
        listing = set()
        for key, entry in _registry().items():
            config = yaml.safe_load((ROOT / "platforms" / entry["config"]).read_text(encoding="utf-8"))
            cores = entry.get("cores", config.get("cores"))
            if isinstance(cores, list) and cores:
                listing.add(key)
        self.assertEqual(self._split(used_by), listing)

    def test_the_check_refuses_an_unknown_platform(self):
        with self.assertRaises(AssertionError):
            self._split("RetroArch, Lakka, Batocera Plus")


class ListsFollowTheCode(unittest.TestCase):
    """The detection table named three of the eight methods the registry
    uses, the pipeline list stopped at eleven of its steps and the target
    scraper table at four of seven scrapers."""

    def test_install_detection_methods(self):
        used = {rule["method"] for entry in _registry().values()
                for rule in (entry.get("install") or {}).get("detect") or []}
        section = _section(_page("adding-a-platform.md"), "Step 7: Add install detection (optional)")
        self.assertEqual({row[0].strip("`") for row in _table_rows(section)}, used)

    def test_pipeline_steps(self):
        from orchestrate.labels import STEP_LABELS

        section = _section(_page("adding-a-platform.md"), "Step 8: Validate the full pipeline")
        listed = re.findall(r"^- (\d\w*) ", section, re.M)
        self.assertEqual(listed, [label.split(" ", 1)[0] for label in STEP_LABELS.values()])

    def test_target_scrapers(self):
        modules = {p.stem.removesuffix("_scraper") for p in (ROOT / "scripts/scraper/targets").glob("*_targets_scraper.py")}
        section = _section(_page("adding-a-scraper.md"), "Existing target scrapers")
        self.assertEqual({row[0].strip("`") for row in _table_rows(section)}, modules)
        for path in (ROOT / "scripts/scraper/targets").glob("*_targets_scraper.py"):
            name = re.search(r'^PLATFORM_NAME = "(\w+)"', path.read_text(encoding="utf-8"), re.M).group(1)
            self.assertIn(name, _registry())
        for page in ("adding-a-platform.md", "adding-a-scraper.md"):
            self.assertNotIn('PLATFORM_NAME = "myplatform_targets"', _page(page))

    def test_exporter_contract(self):
        from exporter.base_exporter import BaseExporter

        section = _page("adding-a-platform.md").split("## Step 5: Create an exporter")[1].split("### Round-trip")[0]
        for method in set(re.findall(r"def (\w+)\(", section)) | set(re.findall(r"`(\w+)\(\)`", section)):
            self.assertTrue(hasattr(BaseExporter, method), method)
        self.assertTrue(BaseExporter.__abstractmethods__ <= set(re.findall(r"def (\w+)\(", section)))


class ExamplesComeFromTheData(unittest.TestCase):
    """The Dolphin example carried a source_ref, an Adler-32 and a region
    the profile never had, the launcher paragraph said 22 names per region
    for 22 in all, and two pages cited Beetle PSX as a required HLE file
    after the profile made it optional."""

    def _profile(self, name: str) -> dict:
        import yaml

        return yaml.safe_load((ROOT / "emulators" / f"{name}.yml").read_text(encoding="utf-8"))

    def _yaml_blocks(self, page: str) -> list[str]:
        return [b.split("\n", 1)[1].rsplit("```", 1)[0] for b in FENCED.findall(_page(page)) if b.startswith("```yaml")]

    def _subset(self, shown: dict, actual: dict) -> None:
        for key, value in shown.items():
            self.assertEqual(value, actual.get(key), key)

    def test_profile_excerpts(self):
        import yaml

        blocks = self._yaml_blocks("profiling.md")
        duck = yaml.safe_load(blocks[0])[0]
        entry = next(f for f in self._profile("duckstation")["files"] if f["name"] == duck["name"])
        self._subset(duck, entry)
        dolphin = yaml.safe_load(next(b for b in blocks if b.startswith("emulator: Dolphin")))
        profile = self._profile("dolphin")
        self._subset({k: v for k, v in dolphin.items() if k != "files"}, profile)
        for shown in dolphin["files"]:
            actual = next(f for f in profile["files"] if f.get("path") == shown["path"])
            self._subset(shown, actual)

    def test_launcher_excerpt(self):
        import yaml

        shown = yaml.safe_load(next(b for b in self._yaml_blocks("adding-a-platform.md")
                                    if b.startswith("launchers:")))["launchers"][0]
        config = yaml.safe_load((ROOT / "platforms/batocera.yml").read_text(encoding="utf-8"))
        record = next(r for r in config["launchers"]
                      if r["emulator"] == shown["emulator"] and r.get("slot") == shown["slot"])
        self._subset({k: v for k, v in shown.items() if k != "source_ref"}, record)
        self.assertTrue(record["source_ref"].endswith(shown["source_ref"].split("...")[-1]))

    def test_required_hle_examples(self):
        for page in ("profiling.md", "reference-terms.md"):
            text = _page(page).replace("\n", " ")
            match = re.search(r"among them (\w+)'s +`([^`]+)`", text)
            entry = next(f for f in self._profile(match.group(1).lower())["files"]
                         if f["name"] == match.group(2))
            self.assertTrue(entry.get("required") and entry.get("hle_fallback"), page)

    def test_reference_terms_source_ref(self):
        text = _section(_page("reference-terms.md"), "Terms of the reference pages").replace("\n", " ")
        cited = re.search(r"lists `scph5501.bin` at\s+`([^`]+)`", text).group(1)
        entry = next(f for f in self._profile("duckstation")["files"] if f["name"] == "scph5501.bin")
        self.assertEqual(cited, entry["source_ref"])


class ArchitectureStatesTheArbitration(unittest.TestCase):
    """architecture.md said the profile takes precedence for pack generation,
    while slots.arbitrate() keeps the platform's file where its frontend
    checks the content: RetroBat's ATARIOSB.ROM."""

    def test_the_page_says_what_arbitrate_decides(self):
        from packs import slots

        page = (WIKI / "architecture.md").read_text(encoding="utf-8")
        self.assertNotIn("the profile takes precedence for pack generation", page)
        section = page[page.index("### When both layers claim one destination"):]
        section = section[:section.index("\n## ")]
        self.assertIn("`slots.arbitrate()`", section)
        # The pack, the manifest and verify decide through slot_choices, and
        # a test in test_slots forbids them to call arbitrate: the page names
        # the function they read, not only the one the report prints.
        self.assertIn("`slots.slot_choices()`", section)
        self.assertIn("`slots.pack_overrides()`", section)
        self.assertNotIn("both decide through `slots.arbitrate()`", section)
        source = inspect.getsource(slots.arbitrate)
        # The three outcomes the section describes.
        for outcome in ("ADDRESSEE", "SERVES_BOTH", "FRONTEND_CHECKS_CONTENT"):
            self.assertIn(outcome, source)
        for said in ("--emulator", "`existence`", "the platform's file stays"):
            self.assertIn(said, section)


class VersionBasisReferenceIsTheSchema(unittest.TestCase):
    """profiling.md listed five kinds of version_basis: `unverified`, its
    `why` and the `url`, `commit` and `match` keys 18 profiles use were in
    the schema alone."""

    def test_the_row_names_every_kind_reason_and_key(self):
        schema = json.loads((ROOT / "schemas" / "emulator.schema.json").read_text(encoding="utf-8"))
        basis = schema["$defs"]["version_basis"]["properties"]
        page = (WIKI / "profiling.md").read_text(encoding="utf-8")
        row = next(line for line in page.splitlines() if line.startswith("| `version_basis` |"))
        for word in [*basis["kind"]["enum"], *basis["why"]["enum"], *basis]:
            with self.subTest(word=word):
                self.assertIn(f"`{word}`", row)
        tools = (WIKI / "tools.md").read_text(encoding="utf-8")
        self.assertIn("`unverified`", tools)


class ProfilingStatesTheHashRuleOnce(unittest.TestCase):
    """profiling.md let an .info MD5 in ('source confirmation makes it more
    reliable') and a file the code never loads stay ('can be left out'),
    beside the strict rule of the same paragraph."""

    def test_no_permissive_form_remains(self):
        page = (WIKI / "profiling.md").read_text(encoding="utf-8")
        self.assertNotIn("source confirmation makes it more reliable", page)
        self.assertNotIn("it can be left out of the profile", page)
        self.assertIn("An MD5 the .info or\n  the docs alone give is not written", page)


class ClaimRuleNamesTheSizeProof(unittest.TestCase):
    """architecture.md said a file found by its name claims nothing, while
    slots.py has counted a name-found copy at the declared size against a
    platform file of another size since 2b535525e."""

    def test_the_page_states_what_slots_counts(self):
        from packs import slots

        self.assertIn(slots.SIZE_EXACT, slots.PROVEN_STATUSES)
        page = " ".join((ROOT / "wiki" / "architecture.md").read_text(encoding="utf-8").split())
        section = page.split("### When both layers claim one destination", 1)[1].split("###", 1)[0]
        self.assertIn(f"(`{slots.SIZE_EXACT}`)", section)
        self.assertIn("Two files of equal size are revisions", section)


class CrossReferenceSettlesBySlotAndSize(unittest.TestCase):
    """reading-reports.md said the cross-reference checks whether a profile's
    files "appear in the platform config", a by-name rule, while verify
    settles a file only at its slot or at a size the core accepts."""

    def test_the_page_states_the_rule_verify_reads(self):
        from resolve.entryscope import declaration_settles

        rom1 = {"name": "ROM1.BIN", "size": 32768, "validation": ["size"]}
        self.assertFalse(declaration_settles(rom1, "ROM1.BIN", {"ROM1.BIN": [(4096, "rom1.bin")]},
                                             dest="dosbox/ROM1.BIN"))
        self.assertTrue(declaration_settles(rom1, "ROM1.BIN", {"ROM1.BIN": [(32768, "rom1.bin")]},
                                            dest="dosbox/ROM1.BIN"))
        page = " ".join((ROOT / "wiki" / "reading-reports.md").read_text(encoding="utf-8").split())
        section = page.split("### Cross-reference section", 1)[1].split("###", 1)[0]
        self.assertIn("declaration_settles()", section)
        self.assertIn("A name alone is not enough", section)
        self.assertNotIn("appear in the platform config", section)


class RegionFreeRuleNamesWhereItDoesNotHold(unittest.TestCase):
    """advanced-usage.md said psxonpsp660.bin is declared [world] and always
    survives --region. PCSX ReARMed declares it [japan], and on the platforms
    where it is the only PlayStation core the filter drops it."""

    def test_every_platform_that_drops_a_named_file_is_named(self):
        from model.registry import list_registered_platforms
        from model.profiles import load_emulator_profiles
        from model.platforms import load_platform_config
        from model.region import WORLD
        from resolve.regions import platform_region_index

        section = _section(_page("advanced-usage.md"), "Region filtering")
        bullet = next(p for p in section.split("\n- ") if "Region-free" in p)
        files = re.findall(r"`([^`]+\.bin)`", bullet)
        self.assertTrue(files)
        profiles = load_emulator_profiles(str(ROOT / "emulators"))
        for platform in list_registered_platforms(str(ROOT / "platforms")):
            config = load_platform_config(platform, str(ROOT / "platforms"))
            index = platform_region_index(config, profiles)
            for name in files:
                entry = index.get(name)
                drops = bool(entry and entry["regions"] and WORLD not in entry["regions"]
                             and not entry["has_untagged"])
                if drops:
                    with self.subTest(platform=platform, file=name):
                        self.assertRegex(bullet, rf"(?i)\b{re.escape(platform)}\b")


if __name__ == "__main__":
    unittest.main()
