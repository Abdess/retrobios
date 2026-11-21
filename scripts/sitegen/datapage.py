"""The data page: what the site serves, and the fields of each document."""

from __future__ import annotations

import json
import re
import urllib.parse
from pathlib import Path

from model import siteinputs
from model.registry import load_platform_registry
from sitegen import markup, measurements as sitemeasurements
from sitegen.config import RELEASE_URL, REPO_URL, SITE_URL
from core.paths import REPO_ROOT
from core.sizes import size_text
from sitegen.install import platform_display
from sitegen.render import escape_tags


def _is_manifest(item: dict) -> bool:
    return item["url"].startswith("api/v1/manifests/")


def _is_target_list(item: dict) -> bool:
    return item["url"].startswith("api/v1/targets/")


def _is_setup_dat(item: dict) -> bool:
    return item["url"].startswith("downloads/dat/")


def _is_export_report(item: dict) -> bool:
    return item["url"].startswith("api/v1/exports/")


def _served_schemas() -> list[tuple[str, str]]:
    """(file name, title) of every schema api/v1/schemas/ serves, from the folder
    the export copies: the page linked 7 of 11."""
    return [
        (path.name, str(json.loads(path.read_text(encoding="utf-8")).get("title") or path.stem))
        for path in sorted((REPO_ROOT / "schemas").glob("*.schema.json"))
    ]


# A URL template written in prose (https://.../<ref>/<repo_path>): escaped,
# the autolinker made a link of it, &lt;ref> on screen and a 404 behind it.
_URL_TEMPLATE = re.compile(r"(?<!`)https?://[^\s`]*<[^\s`]*?(?=[.,;]?(?:\s|$))")


def _schema_field_rows(schema: dict, keys: tuple[str, ...]) -> list[str]:
    """One table row per field, its description read from the schema, so the
    page and the published contract say the same thing. A URL template is
    written as code."""
    props = schema.get("properties") or {}
    rows = []
    for key in keys:
        text = str((props.get(key) or {}).get("description") or "")
        if text:
            # Python before 3.12 refuses a backslash inside an f-string expression.
            described = escape_tags(_URL_TEMPLATE.sub(r"`\g<0>`", text))
            rows.append(f"| `{key}` | {described} |")
    return rows


def _other_fields(schema: dict, shown: tuple[str, ...]) -> list[str]:
    """The fields a short table leaves out, every one with its description."""
    rest = tuple(key for key in schema.get("properties") or {} if key not in shown)
    return ["| Field | Meaning |", "|-------|---------|", *_schema_field_rows(schema, rest)]


def _nested_fields(schema: dict, prefix: str = "") -> list[str]:
    """A table for every object below *schema*, at any depth, and one line
    per code where a field lists its codes' meanings (enumDescriptions).

    The top-level and `files` tables left 50 nested fields undescribed, all
    of `omitted_files` among them: a tool could not say why a file was not
    installed.
    """
    lines: list[str] = []
    for key, spec in (schema.get("properties") or {}).items():
        path = f"{prefix}{key}"
        codes = spec.get("enumDescriptions")
        if codes:
            lines.extend([f"Codes of `{path}`:", ""])
            lines.extend(f"- `{code}`: {text}" for code, text in zip(spec["enum"], codes))
            lines.append("")
        for label, child, child_path in (
            ("Each entry of", spec.get("items"), f"{path}[]"),
            ("Each value of", spec.get("additionalProperties"), f"{path}{{}}"),
            ("Fields of", spec, path),
        ):
            if not isinstance(child, dict) or not child.get("properties"):
                continue
            lines.extend([
                f"{label} `{path}`:", "",
                "| Field | Meaning |", "|-------|---------|",
                *_schema_field_rows(child, tuple(child["properties"])), "",
            ])
            lines.extend(_nested_fields(child, f"{child_path}."))
    return lines


# The manifest fields an integrator reads first, in the order they matter.
MANIFEST_TOP_FIELDS = ("platform", "version", "base_destination", "files",
                       "omitted_files", "pack_files", "core_names", "system_cores")
MANIFEST_FILE_FIELDS = ("dest", "sha1", "size", "repo_path", "release_asset", "cores",
                        "systems", "category", "alternatives")


def _short_sha256(item: dict, catalog: str) -> str:
    """A digest cell that fits its column: 12 characters linking the catalog
    that holds it, the whole value in the title. 64 characters pushed the
    table to 932 px in a 720 px column."""
    value = str(item["sha256"])
    return f'<a href="{catalog}"><code title="{value}">{value[:12]}</code></a>'


def _platforms_without_a_list(platforms_dir: Path | None = None) -> list[str]:
    """The names of the platforms whose registry says they keep no list."""
    platforms_dir = platforms_dir or siteinputs.current().platforms
    names = []
    for key, entry in sorted(load_platform_registry(str(platforms_dir)).items()):
        if entry.get("native_list") != "none":
            continue
        names.append(platform_display(key, str(platforms_dir)))
    return names


def _join_names(names: list[str]) -> str:
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + f" and {names[-1]}"


def generate_data_page(exports: list[dict], measurements_sqlite: Path | None = None) -> str:
    manifest_schema = json.loads(
        (REPO_ROOT / "schemas" / "install-manifest.schema.json").read_text(encoding="utf-8"))
    snippet = (REPO_ROOT / "scripts" / "check_platform_folder.py").read_text(encoding="utf-8")
    manifests = [item for item in exports if _is_manifest(item)]
    targets = [item for item in exports if _is_target_list(item)]
    no_list = _platforms_without_a_list()
    lines = [
        "---",
        "terms: manifest, schema, json schema, license, check a folder, "
        "check bios folder script, rate limit, api",
        "---",
        "",
        "# Data and API",
        "",
        "RetroBIOS publishes the same metadata used by its verifier, pack builder "
        "and website as versioned static files. No account or API key is required.",
        "",
        " ".join([
            markup.button("API catalog", "api/v1/catalog.json", primary=True),
            markup.button("SQLite snapshot", "downloads/retrobios.sqlite"),
            markup.button("Collection DAT", "downloads/retrobios.dat"),
        ]),
        "",
        f"**Licence:** the metadata is offered under the MIT terms of [LICENSE]({REPO_URL}/blob/main/LICENSE), "
        "which cover the scripts, tooling, schemas, documentation and metadata. "
        f"They never cover a BIOS or firmware file ([NOTICE]({REPO_URL}/blob/main/NOTICE)). "
        "`catalog.json` and the SQLite `metadata` table carry the same `license`.",
        "",
        "## Stable JSON endpoints",
        "",
        "Start at [`api/v1/index.json`](api/v1/index.json): it names the catalog, "
        "the two id indexes and the envelope schema.",
        "",
        "| Dataset | Endpoint | Schema | Size |",
        "|---------|----------|--------|-----:|",
    ]
    for item in exports:
        if (item["media_type"] != "application/json" or _is_manifest(item)
                or _is_target_list(item) or _is_export_report(item)):
            continue
        schema = (
            f"[JSON Schema](api/v1/{item['schema']})"
            if item.get("schema") else "-"
        )
        lines.append(
            f"| {item['title']} | [`{item['url']}`]({item['url']}) | "
            f"{schema} | {size_text(item['bytes'])} |"
        )
    lines.extend([
        "",
        "Every envelope carries `schema_version`, `kind` and `commit`, the revision "
        "of this repository the data was read at. Breaking changes use a new "
        "URL prefix (`/api/v2/`), and fields may only be added compatibly within v1. "
        "Each schema's `$id` is the address it is served at.",
        "",
        "Schemas:",
        "",
        *(f"- [`{name}`](api/v1/schemas/{name}): {title}" for name, title in _served_schemas()),
        "",
        "`database.json`, `stats.json`, `release.json` and the manifests are not "
        "envelopes. Their revision is the `commit` of `catalog.json` that lists "
        "their SHA256.",
        "",
        "One emulator profile without the whole list: "
        "`api/v1/emulators/<id>.json`, the envelope of `emulators.json` holding "
        "that one item, its `profile` valid against "
        "[`emulator.schema.json`](api/v1/schemas/emulator.schema.json). Each "
        "emulator page links its own. `api/v1/platforms/<id>.json` holds one "
        "platform of `platforms.json`, its `contract` valid against "
        "[`platform.schema.json`](api/v1/schemas/platform.schema.json) and its "
        "`registry` the install and scraper settings beside the list. "
        "`api/v1/systems/<slug>.json` holds the files of one system page by console. "
        "Each platform and system page links its own.",
        "",
        "By id: [`systems.json`](api/v1/systems.json) gives each system id a platform "
        "or a profile writes (`sony-playstation`) with its name, its manufacturer, the "
        "`url` of the section holding its files, the `api` document of that section "
        "and the files' SHA1. "
        "[`cores.json`](api/v1/cores.json) gives each core name the buildbot or a "
        "platform uses (`mednafen_psx`) the profile it designates (`beetle_psx`), "
        "whose document is `api/v1/emulators/<profile>.json`. A name two profiles "
        "claim (`pcsx2`) has one item per profile, and `preferred: true` marks the "
        "one a platform list naming that core gets: the profile with that very id, "
        "else the first id in alphabetical order.",
        "",
        "One hash without the whole list: `api/v1/lookup/<xx>.json`, where `<xx>` "
        "is the first two characters of the hash in lowercase, holds every SHA1, "
        "MD5, CRC32 and SHA256 starting with them. Each record names its `layer` "
        "(the collection, a member of a collection archive, a file that left the "
        "collection, a data directory, a platform's list or an emulator profile), "
        "the file `name`, the `url` of the page that shows it and, "
        "when one is known, the `system_name` the site gives its system. "
        "[Find or check a file](files/index.md) reads it.",
        "",
        "`catalog.json` lists the datasets, manifests, exports and downloads. It "
        "does not list these one-item documents, which hold no SHA256 of their own.",
        "",
        "In a browser, the SHA1 of a file the reader picks finds its records when "
        "the collection holds that file. A list naming a file the collection lacks "
        "is filed under its MD5 or CRC32 alone, and Web Crypto has no MD5: "
        "that page computes MD5 and CRC32 in script and looks "
        "up all four.",
        "",
        "```js",
        "// The records of the file a reader picked, by its SHA1.",
        "async function lookUp(file) {",
        "  const digest = await crypto.subtle.digest(\"SHA-1\", await file.arrayBuffer());",
        "  const sha1 = [...new Uint8Array(digest)]",
        "    .map((byte) => byte.toString(16).padStart(2, \"0\"))",
        "    .join(\"\");",
        f"  const base = \"{SITE_URL}api/v1/lookup/\";",
        "  const response = await fetch(`${base}${sha1.slice(0, 2)}.json`);",
        "  if (!response.ok) return [];",
        "  const shard = await response.json();",
        "  // layer: collection, archive-member, retired, data-directory, platform, emulator.",
        "  return shard.items.filter((item) => item.value === sha1);",
        "}",
        "```",
        "",
        "Two kinds of `url`:",
        "",
        "- In `catalog.json` and `index.json`, a `url` is relative to the document "
        "holding it, as RFC 3986 resolves it.",
        "- In the lookup shards, `file-locations.json` and `systems.json`, a `url` "
        f"is site-absolute (`/retrobios/systems/sony/#...`). Prefix "
        f"`{SITE_URL.removesuffix(urllib.parse.urlsplit(SITE_URL).path)}` for a full address.",
        "",
        "## Platform manifests",
        "",
        "A platform's list is what the setup checks. Its manifest is what the pack "
        "installs: the list's files plus every file the setup's cores load. "
        "`api/v1/manifests/<platform>.json` is the file `install.py` reads, byte "
        "for byte, valid against "
        "[`install-manifest.schema.json`](api/v1/schemas/install-manifest.schema.json). "
        "[`api/v1/release.json`](api/v1/release.json) records the packs of the latest "
        "release and the files each one holds.",
        "",
        "Manifests: " + ", ".join(
            f"[{item['url'].rsplit('/', 1)[-1].removesuffix('.json')}]({item['url']})"
            for item in manifests) + "." if manifests else "",
        "",
        "`api/v1/targets/<platform>.json` gives each hardware target of a platform "
        "the cores it runs, valid against "
        "[`target-manifest.schema.json`](api/v1/schemas/target-manifest.schema.json). "
        "`install.py --target` reads the same file. Like the manifests, they are "
        "copied byte for byte and are not envelopes.",
        "",
        "Target lists: " + ", ".join(
            f"[{item['url'].rsplit('/', 1)[-1].removesuffix('.json')}]({item['url']})"
            for item in targets) + "." if targets else "",
        "",
        "`api/v1/exports/<platform>.json` lists every change of a setup's "
        "[updated file](exports.md), the report that page is written from, copied "
        "byte for byte like the manifests.",
        "",
        "| Field | Meaning |",
        "|-------|---------|",
        *_schema_field_rows(manifest_schema, MANIFEST_TOP_FIELDS),
        "",
        "Each entry of `files`:",
        "",
        "| Field | Meaning |",
        "|-------|---------|",
        *_schema_field_rows(manifest_schema["$defs"]["file"], MANIFEST_FILE_FIELDS),
        "",
        *markup.details("note", "All fields", [
            "The manifest:",
            "",
            *_other_fields(manifest_schema, MANIFEST_TOP_FIELDS),
            "",
            "Each entry of `files`:",
            "",
            *_other_fields(manifest_schema["$defs"]["file"], MANIFEST_FILE_FIELDS),
            "",
            *_nested_fields(manifest_schema),
            *_nested_fields(manifest_schema["$defs"]["file"], "files[]."),
        ]),
        "## Check a folder for one platform",
        "",
        "The job most tools come for: is this BIOS folder what the platform checks? "
        "Read `api/v1/platforms/<id>.json` and apply the platform's own rules:",
        "",
        "- `verification_mode: existence`: a file at its `destination` passes.",
        "- An entry with no hash in the mode's field is checked on presence too.",
        "- `zipped_file` set: the md5 is that of this member inside the ZIP, never "
        "the ZIP's. Member names compare casefolded. A ZIP declared once per member "
        "appears once per member: Batocera lists 692 entries for 353 destinations.",
        "- An md5 shorter than 32 characters (Batocera) compares by its prefix. "
        "Recalbox writes several accepted md5 in one field, comma separated.",
        "- `zip_digest: composite` (Recalbox): the md5 of a ZIP is that of its members "
        "read in name order, never the archive's.",
        "- An entry with no `destination` (EmuDeck) names no file: the system "
        "passes when any file in the BIOS folder has one of its md5.",
        "- `hash_rule: size_and_any_hash` (RomM) wants the size and any one hash. "
        "The script below does not apply it.",
        *([f"- {_join_names(no_list)} have no list of their own (`native_list: none`). "
           "An empty list does not mean nothing is needed."] if no_list else []),
        "",
        "```python",
        snippet.rstrip("\n"),
        "```",
        "",
        "The script is [`scripts/check_platform_folder.py`]"
        f"({REPO_URL}/blob/main/scripts/check_platform_folder.py). A test runs it "
        "against the verifier on a sample folder, so the two give the same answer. "
        "It exits 1 when a file is wrong or missing. For an unknown platform it "
        "prints the known ones, and it names a folder that does not exist.",
        "",
        "`install.py --check` answers another question by default: whether the folder "
        "holds what the pack installs, the manifest above. With `--declared-only`, or "
        "from the `declared` event, `install.py --check` answers it too.",
        "",
        "## Bulk downloads",
        "",
        "| Export | Format | Size | SHA256 |",
        "|--------|--------|-----:|--------|",
    ])
    for item in exports:
        if item["media_type"] == "application/json" or _is_setup_dat(item):
            continue
        lines.append(
            f"| [{item['title']}]({item['url']}) | `{item['media_type']}` | "
            f"{size_text(item['bytes'])} | {_short_sha256(item, 'api/v1/catalog.json')} |"
        )
    lines.extend([
        "",
        "Each SHA256 is cut to 12 characters. Point at it for the whole value, or "
        "read it in [`catalog.json`](api/v1/catalog.json).",
        "",
        "The DAT is Logiqx XML, the format clrmamepro and RomVault read: one game "
        "per `bios/<Manufacturer>/<Console>/` folder of the collection, named "
        "`Manufacturer\\Console` so the tools look in that subfolder, each file a "
        "rom named by its path below that folder. It audits a copy of the "
        "collection's `bios/` tree, or rebuilds that layout from a reader's own dumps.",
        "",
        "A setup's DAT, `downloads/dat/<platform>.dat`, describes its BIOS folder "
        "once installed: one game named after the folder (`bios`, `system`), each "
        "file a rom named by its place below it, as its manifest lists it. It audits "
        "that folder with the same tools. Setup DATs: " + ", ".join(
            f"[{item['url'].rsplit('/', 1)[-1].removesuffix('.dat')}]({item['url']})"
            for item in exports if _is_setup_dat(item)) + ".",
        "",
        "The SQLite file contains indexed tables for content hashes, provenance "
        "catalog matches, platform declarations, emulator profiles and current "
        "gaps. It contains metadata only, never BIOS or firmware bytes.",
        "",
        "To find who accepts a hash, query `accepted_hashes` (or "
        "`accepted-hashes.csv`): one lowercase row per accepted value, per "
        "algorithm, for platform declarations and emulator profiles alike, "
        "indexed on `(algorithm, value)`. A ROM inside a MAME or FBNeo set "
        "has its own row, its `path` naming the archive and the member "
        "(`nmk004.zip/nmk004.bin`). The hash columns of `platform_files` "
        "and `emulator_files` keep each source's own form: a Recalbox md5 may "
        "list several revisions separated by commas, and an emulator field "
        "holding several accepted values is a JSON array.",
        "",
        "```sql",
        "SELECT layer, owner, name FROM accepted_hashes",
        "WHERE algorithm = 'md5' AND value = 'c87a52c277f7952b41c639fc7bf0a43b';",
        "```",
        "",
        "The gaps dataset carries both layers behind one `layer` column: "
        "`platform` rows are anomalies against a platform's own BIOS list, "
        "`emulator` rows are files a profiled core loads that no platform "
        "declares. The two answer different questions and are not comparable "
        "totals. Each row is listed once.",
        "",
        "`platform-files.csv` and the gaps add what the check found: `status` "
        "(`ok`, `untested`, `missing`), `category` (`bios`, `game_data`, "
        "`unread`), and for a held file `collection_path` and `resolved_sha1`, "
        "the collection file that answers the declaration. "
        "`provenance-wanted.csv` is the Wanted list of [Dump provenance]"
        "(provenance.md): each dump a catalog describes and the collection lacks.",
        "",
        "`platform-files.csv` and the `platform_files` table also carry the entry "
        "fields a check needs:",
        "",
        "- `zipped_file` set: the md5 is the md5 of that member inside the ZIP.",
        "- `zip_digest` is `composite` where the md5 of a ZIP covers its members.",
        "- `hash_match_mandatory` and `mandatory_declared` are Recalbox's flags.",
        "- `curated`, `shared_group` and `mirror_of` mark an entry the platform's "
        "own file does not carry.",
        "",
        *(sitemeasurements.data_page_section(measurements_sqlite)
          if measurements_sqlite and measurements_sqlite.is_file() else []),
        "## Hosting, rate limits and caching",
        "",
        "- Static files on GitHub Pages, read with a plain GET. No key, no account.",
        "- Any origin may read them (`Access-Control-Allow-Origin: *`), so a "
        "browser tool can call them directly.",
        "- Responses are cached for 10 minutes (`Cache-Control: max-age=600`). "
        "Send the `ETag` back in `If-None-Match` to skip an unchanged download.",
        "- GitHub may answer HTTP 429 to a client that sends too many requests, and "
        "a Pages site has a soft limit of 100 GB of traffic a month ([GitHub Pages "
        "limits](https://docs.github.com/en/pages/getting-started-with-github-pages/"
        "github-pages-limits)). Fetch the one shard or document a question needs.",
        "- The base is the project's address, "
        f"`{SITE_URL}api/v1/`. Compare `commit` to know whether two downloads differ.",
        "",
        "## Semantics and limits",
        "",
        "Treat four questions separately: content identity (hashes), presence in "
        "the collection, acceptance by a specific emulator, and catalog provenance. "
        "One does not imply the others. In particular, presence, a matching dump "
        "catalog, or emulator compatibility is not a statement about copyright, "
        "ownership, or redistribution rights.",
        "",
        f"The data can be newer than the [latest published pack]({RELEASE_URL}). "
        "A pack is published by hand, once every release check has passed.",
        "",
        "See the [data model](wiki/data-model.md), [verification modes]"
        "(wiki/verification-modes.md), and [methodology](wiki/architecture.md) "
        "before interpreting aggregate counts.",
        "",
    ])
    return "\n".join(lines)
