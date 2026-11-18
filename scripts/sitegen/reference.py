"""Contributing, not-found and data model pages."""

from __future__ import annotations

import json

from model.profiles import unique_emulator_profiles
from sitegen.home import next_block
from sitegen.readme import contributing_text


def generate_contributing() -> str:
    return contributing_text(
        lambda page: f"{page}.md", "# Contributing", "on this site"
    ) + "\n" + "\n".join(next_block([
        "[Profiling an emulator](wiki/profiling.md), the first task most "
        "contributions start from",
    ]))


# The end of a reference page: back to the index, or on to contributing.
def generate_not_found() -> str:
    """The page a stale link lands on. Pages have moved before (file cards
    refiled between manufacturers), so it offers the search, the two pages
    a visitor most often wants, and the list a moved page belongs to."""
    return "\n".join([
        "---",
        "search: exclude",
        "---",
        "",
        "# Page not found",
        "",
        '<p class="rb-lead">This address has no page. It may have moved since the link was written.</p>',
        "",
        '<p><button type="button" class="rb-notfound-search" data-rb-open-search>Search the site</button></p>',
        "",
        "- [Start here](index.md): what BIOS files are and how to install them",
        "- [Get the files](which-pack.md): the pack or the command for each device",
        "- Browse [platforms](platforms/index.md), [systems](systems/index.md) "
        "or [emulators](emulators/index.md)",
        "",
        '<div id="rb-notfound-hint" hidden></div>',
        "",
    ])


def reference_next() -> str:
    return "\n" + "\n".join(next_block([
        "[Reference index](wiki/index.md), every reference page in one list",
        "For contributors: [How to contribute](contributing.md)",
    ]))


# Wiki pages
# index, architecture, tools, profiling are maintained as wiki/ sources
# and copied verbatim by main(). Only data-model is generated dynamically.


def generate_wiki_data_model(db: dict, profiles: dict) -> str:
    """Generate data model documentation from actual database structure."""
    files_count = len(db.get("files", {}))
    by_md5 = len(db.get("indexes", {}).get("by_md5", {}))
    by_name = len(db.get("indexes", {}).get("by_name", {}))
    by_crc32 = len(db.get("indexes", {}).get("by_crc32", {}))
    by_path = len(db.get("indexes", {}).get("by_path_suffix", {}))
    by_sha256 = len(db.get("indexes", {}).get("by_sha256", {}))

    # A real entry with real values: the PlayStation BIOS v3.0 (A).
    sample_key = "0555c6fae8906f3f09baf5988f00e55f88e9f30b"
    files = db.get("files", {})
    sample: dict = files.get(sample_key) or next(iter(files.values()), {})
    lines = [
        "# Data model",
        "",
        "Three kinds of file hold everything this project knows. `database.json` "
        "lists every file the collection holds, keyed by its SHA1. A platform YAML "
        "copies the BIOS list a setup publishes. An emulator profile records what "
        "one emulator opens, read from its code. The sections below show the "
        "fields of each, with a real entry, to read the data or build on it.",
        "",
        "Example: `scph5501.bin` is one entry of `database.json` (key "
        "`0555c6fa...`), one entry of `platforms/batocera.yml` (its MD5) and one "
        "entry of `emulators/duckstation.yml` (its MD5, region and priority).",
        "",
        "## database.json",
        "",
        f"Primary key: SHA1. **{files_count}** file entries.",
        "",
        f"The entry of `{sample.get('name', '')}`:",
        "",
        "```json",
        *json.dumps(sample, indent=2, ensure_ascii=False).splitlines(),
        "```",
        "",
        "`provenance` maps each catalog that lists the file to the DAT and entry "
        "it was matched against. It is present only when the file matches a "
        "snapshot under `provenance/`. The join runs by SHA1 first, then by "
        "MD5 + size. See [dump provenance](../provenance.md).",
        "",
        "### Indexes",
        "",
        "| Index | Entries | Purpose |",
        "|-------|---------|---------|",
        f"| `by_md5` | {by_md5} | MD5 to SHA1 lookup (Batocera, Recalbox verification) |",
        f"| `by_name` | {by_name} | filename to SHA1 list (name-based resolution) |",
        f"| `by_crc32` | {by_crc32} | CRC32 to SHA1 lookup |",
        f"| `by_path_suffix` | {by_path} | relative path to SHA1 (regional variant disambiguation) |",
        f"| `by_sha256` | {by_sha256} | SHA256 to SHA1 lookup (emulator profile validation) |",
        "",
        "### File resolution order",
        "",
        "`resolve_local_file` finds the file an entry describes by its hashes "
        "first, then by its path, then by its name, and a filename or "
        "destination never overrides a declared hash. The steps and their "
        "return codes are written once, in "
        "[the file resolution chain](verification-modes.md#file-resolution-chain).",
        "",
        "## Platform YAML",
        "",
        "Scraped from upstream sources. Structure:",
        "",
        "```yaml",
        "platform: Batocera",
        "verification_mode: md5        # how the platform checks files",
        "hash_type: md5                # hash type in file entries",
        "base_destination: bios        # root directory for BIOS files",
        "systems:",
        "  system-id:",
        "    files:",
        "      - name: filename",
        "        destination: path/in/bios/dir",
        "        md5: expected_hash",
        "        sha1: expected_hash",
        "        required: true",
        "```",
        "",
        "Supports inheritance (`inherits: retroarch`) and shared groups",
        "(`includes: [group_name]` referencing `_shared.yml`).",
        "",
        "`base_destination` is the prefix the pack applies to every entry. It is",
        "empty when the upstream destinations already carry their own root, which",
        "is why the RetroDECK pack ships `bios/` and `roms/` at its top level.",
        "Core files then go under `core_destination` when the platform states one",
        "(`bios` for AmberELEC and EmuELEC, whose lists also name `neogeo/` and",
        "`ports/`), else under the root nearly every destination shares.",
        "",
        "## Emulator YAML",
        "",
        f"**{len(profiles)}** profile files, **{len(unique_emulator_profiles(profiles))}** "
        "distinct emulators once aliases are folded in. Source-verified from "
        "emulator code.",
        "",
        "See the [profiling guide](profiling.md) for the full field reference.",
        "",
        "## Static API and bulk exports",
        "",
        "The website publishes versioned JSON, CSV and SQLite metadata generated "
        "from these same structures. Start with the [Data and API](../data.md) "
        "catalog. Each downloadable artifact carries a SHA256 in "
        "`api/v1/catalog.json`.",
        "",
    ]
    return "\n".join(lines) + "\n"
