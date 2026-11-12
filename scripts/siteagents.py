"""What the site tells an AI agent about itself.

- ``llms.txt`` (https://llmstxt.org): the pages and data an agent should
  read first, in Markdown, at the site's root.
- ``skills/setup-bios/SKILL.md``: an Agent Skill that sets up a device's
  BIOS files with the fewest downloads.
- ``ard.json``: an Agentic Resource Discovery manifest
  (https://github.com/ards-project/ard-spec) listing that skill and the
  JSON API, linked from every page's head with ``rel="ard"``.

Both are written from the registry at each build, so a new platform or a
moved page cannot leave them stale. The WebMCP tools a page registers live
in website/src/scripts/agent-tools.ts.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from siteguides import PACKAGE_COMMAND

SITE = "https://abdess.github.io/retrobios/"
PUBLISHER = "abdess.github.io"
SH = "curl -fsSL https://abdess.github.io/retrobios/i | sh -s --"
PS = "& ([scriptblock]::Create((irm https://abdess.github.io/retrobios/i.ps1)))"
# What a folder put into a command may not hold, as agent-tools.ts refuses
# it: PowerShell also ends a single-quoted string on the typographic quotes.
REFUSED = "any quote, straight or typographic (' \" ‘ ’ ‚ ‛ “ ” „), a backtick or a control character"
QUOTING = (f"A folder goes in single quotes, attached to its option. One that holds {REFUSED}, "
           "or starts with `-`, is a question for the user, never a value to escape into the "
           "command. On a page of the site, the `device_setup_command` WebMCP tool writes the "
           "command and refuses such a folder.")

UVX = PACKAGE_COMMAND
# EVENT_SCHEMA of install.py, and the schema generate_event_schema.py writes
# from EVENT_KEYS, as the site publishes it. tests/test_site_agents.py holds
# both to install.py.
EVENT_SCHEMA = 1
EVENTS_SCHEMA_PATH = "api/v1/schemas/install-events.schema.json"
# Every code of the Exit status table of wiki/installer.md, in short.
EXIT_CODES = (
    (0, "everything asked for is installed or already in place"),
    (1, "a failure: a download, a file list or a folder that cannot be used"),
    (2, "nothing was done: an option refused, every file failed, or the user quit"),
    (3, "`--check` found files missing or wrong, nothing having failed"),
    (4, "`--find` read the hash and the list holds no one file for it"),
    (130, "stopped with Ctrl+C"),
    (141, "the output went to a reader that closed early"),
)

START_PAGES = (
    ("Which pack is needed", "which-pack/", "pick a device or setup, get the folder its BIOS files go in, "
                                            "one command that installs and checks them, or a ZIP pack"),
    ("First install", "wiki/first-install/", "the steps from nothing to a working BIOS folder"),
    ("What are BIOS files", "wiki/what-are-bios-files/", "why emulators need them and where they come from"),
    ("Troubleshooting", "wiki/troubleshooting/", "a file the emulator does not find or refuses"),
    ("Common questions", "wiki/faq/", "short answers"),
)

DATA = (
    ("API index", "api/v1/index.json", "every dataset of the JSON API, versioned"),
    ("Catalog", "api/v1/catalog.json", "each dataset, manifest, export and download with its size, SHA-256 and schema"),
    ("Emulators", "api/v1/emulators.json", "every emulator profile: the files it reads, required or not, "
                                           "their hashes and the source line that reads each. One document "
                                           "per emulator at api/v1/emulators/<id>.json"),
    ("Core names", "api/v1/cores.json", "each core name and alias, with the profile it designates"),
    ("Systems", "api/v1/systems.json", "each system id, its name and the section holding its files"),
    ("Platforms", "api/v1/platforms.json", "each setup (RetroArch, Batocera...), its BIOS folder and files"),
    ("Hash lookup", "api/v1/lookup/00.json", "what a hash (MD5, SHA-1, SHA-256, CRC32) designates, sharded "
                                             "by its first two hex characters: api/v1/lookup/<xx>.json"),
)

MORE = (
    ("Emulators", "emulators/", "one page per emulator"),
    ("Systems", "systems/", "one page per console maker, every file with its hashes"),
    ("Installer", "wiki/installer/", "every option of install.py"),
    ("What is counted", "wiki/privacy/", "the site's cookie-free counting"),
    ("Is it legal?", "wiki/legal/", "the project's position"),
    ("Contributing", "contributing/", "add a missing file or an emulator profile"),
)


def llms_txt(platforms: list[tuple[str, str]]) -> str:
    """The site's llms.txt. ``platforms`` lists (id, display name) of every
    registered setup, each with its page."""
    lines = [
        "# RetroBIOS",
        "",
        "> BIOS and firmware files for emulators, each checked against the emulator's source "
        "code: which files an emulator reads, whether it starts without them, where each one "
        "goes on every setup, their hashes, and an installer that puts them in place.",
        "",
        "Each emulator's files are read from its code, and most cite the file and line that "
        "read them. The files themselves are served by the GitHub repository "
        "(https://github.com/Abdess/retrobios) and its releases.",
        "",
        "## Answering a user",
        "",
        *(f"- {rule}" for rule in ANSWER_RULES),
        "",
        "## Setting up a device for its user",
        "",
        "Most people want to play now, with the fewest files. The installer does that in one "
        "command: it finds the setup and its BIOS folder, reads the games on the card, and with "
        "`--for-games --required-only` installs only the files those games cannot start "
        "without. `--yes` alone installs what the card's games need, optional files "
        "included, and `--all-files` the setup's whole list (gigabytes).",
        "",
        f"1. Preview, nothing written: `{SH} --for-games --required-only --dry-run`",
        f"2. Install, no questions: `{SH} --for-games --required-only --yes`",
        f"3. On Windows (PowerShell): `{PS} --for-games --required-only --yes`",
        "",
        "- Run it on the device itself (its terminal or SSH), or on a computer with the device's "
        "card plugged in. The installer recognises the handheld systems on the card, among them "
        "ArkOS, dArkOS, ArchR and UnofficialOS (R36S and its clones), muOS, KNULLI, ROCKNIX, "
        "AmberELEC, EmuELEC, Onion, spruceOS and MinUI. "
        "The [Linux handhelds page](" + SITE + "platforms/linux-handhelds/) maps each device "
        "to its system and folder.",
        "- From a computer, if the card is not found, name its BIOS folder: `--dest='<card>/bios'` "
        "(ArkOS and dArkOS: the `bios` folder of the EASYROMS part).",
        "- A games folder somewhere else: `--for-games='<folder>'`, one subfolder per system.",
        f"- {QUOTING}",
        "- Later, to see what is missing or wrong: `--check`. Machine-readable progress: "
        "`--events` (JSON lines, one per event, documented on the installer page).",
        "- A game the installer cannot identify gets every BIOS of its system, and the run names it.",
        f"- The same steps as an Agent Skill: [SKILL.md]({SITE}{SKILL_PATH}).",
        "",
        "## Driving the installer for a user",
        "",
        f"With Python 3.8 or newer, the installer is also a package: `{UVX} --for-games "
        f"--required-only --dry-run`, or `pipx run retrobios` with the same options.",
        "",
        "1. Plan: run it with `--dry-run --events`. Nothing is written, and standard output carries "
        f"one JSON object per line, event schema {EVENT_SCHEMA} "
        f"([JSON Schema]({SITE}{EVENTS_SCHEMA_PATH})): a `file` event per file with its "
        "`state`, `check` with the totals and `bytes_needed`, then `summary` with `pending`.",
        "2. Consent: show the user what will be installed, where, and the size, and ask.",
        "3. Act, only on a yes: the same command with `--yes` in place of `--dry-run`.",
        "",
        "- `--yes` asks nothing: use it in a run without a terminal. A run that needs an "
        "answer (two setups found, none found) stops and names the option to give.",
        "- The exit code, also the `code` of the last `end` event. An option refused at once "
        "writes no event at all:",
        *(f"  - `{code}`: {meaning}" for code, meaning in EXIT_CODES),
        "",
        "## Start",
        "",
        *(f"- [{title}]({SITE}{path}): {what}" for title, path, what in START_PAGES),
        "",
        "## Setups",
        "",
        *(f"- [{name}]({SITE}platforms/{pid}/): its BIOS folder and files" for pid, name in platforms),
        "",
        "## Data",
        "",
        *(f"- [{title}]({SITE}{path}): {what}" for title, path, what in DATA),
        "",
        "## Optional",
        "",
        *(f"- [{title}]({SITE}{path}): {what}" for title, path, what in MORE),
    ]
    return "\n".join(lines) + "\n"


# How an assistant answers from the site and not from memory: file names,
# folders and hashes change with each setup, and a guessed one is the
# answer that fails. The same rules end the skill.
ANSWER_RULES = (
    "Each Markdown copy, llms.txt and llms-full.txt name the commit and the date they "
    f"were built from. When a copy read earlier or found through a search engine names a "
    f"commit other than {SITE}version.json, fetch it again: the site changes with each commit.",
    "Answer from the pages and data, not from memory. Every page has a Markdown copy: add "
    "`index.md` to its address (https://abdess.github.io/retrobios/which-pack/index.md). "
    f"[llms-full.txt]({SITE}llms-full.txt) holds the guides and every setup's page in one file.",
    "Name files exactly as the pages write them: names are case-sensitive on most devices, and a renamed file is "
    "not found. Never invent a file name, a folder or a hash.",
    "The BIOS folder depends on the setup, and for RetroArch on the device: give the folder the "
    "setup's page names, under \"Where the files go\".",
    "To check a file the user has, compare its MD5 or SHA-1 with the file's card, or look the hash "
    f"up: {SITE}files/?hash=<value> (the page) or api/v1/lookup/<first two hex>.json (the data).",
    "Prefer the installer to a manual copy: it puts each file in its folder and checks its hash. "
    "Give the command the setup's page gives, with `--for-games --required-only` for the fewest files.",
    "Say where an answer comes from: link the source page.",
    "On a page of the site, the WebMCP tools answer from the data: setup_bios_files (folder and "
    "files of a setup), emulator_bios_files, lookup_bios_hash, device_setup_command, search_retrobios.",
    f"Whether sharing BIOS files is legal depends on the country: point to [Is it legal?]({SITE}wiki/legal/), "
    "do not give legal advice.",
)

SKILL_PATH = "skills/setup-bios/SKILL.md"
# The Agent Skills media type ARD names: Markdown with this profile.
SKILL_TYPE = 'text/markdown; profile="urn:air:agent-skills"'


def skill_md() -> str:
    """An Agent Skill (SKILL.md: YAML front matter, then instructions) that
    sets up a device's BIOS files with the fewest downloads."""
    return "\n".join([
        "---",
        "name: setup-bios",
        "description: Install the BIOS and firmware files a retrogaming device or computer needs "
        "(RetroArch, Batocera, EmuDeck, ArkOS, dArkOS, muOS, KNULLI, ROCKNIX and others), only "
        "what the games on its card need to start. Use when a user asks to set up emulators, "
        "a handheld (R36S, Miyoo, Anbernic), BIOS files or firmware.",
        "---",
        "",
        "# Set up BIOS files with RetroBIOS",
        "",
        "Most users want to play now, with the fewest files. Install only what the games on the "
        "card need, unless the user asks for everything.",
        "",
        "## Steps",
        "",
        "1. Ask where the games are: on the device itself (with its terminal or SSH), or on "
        "its card plugged into this computer.",
        f"2. Preview, nothing is written: `{SH} --for-games --required-only --dry-run` "
        f"(Windows PowerShell: `{PS} --for-games --required-only --dry-run`).",
        "3. Show the user the plan it prints: the setup found, the BIOS folder, the files and "
        "their size. Ask before going on if the setup or the folder is not the one expected.",
        "4. Install with the same command, `--yes` in place of `--dry-run`.",
        "5. Report the summary line. A game the installer could not identify got every BIOS of "
        "its system: say which.",
        "",
        "## When the setup or the card is not found",
        "",
        "- From a computer, name the card's BIOS folder: `--dest='<card>/bios'`. ArkOS and dArkOS "
        "keep it on the EASYROMS part.",
        "- Games outside the card: `--for-games='<folder>'`, one subfolder per system.",
        "- A setup not detected: `--platform=<name>`, a name exactly as `--list-platforms` prints "
        "it (letters, digits, `-` and `_`).",
        f"- {QUOTING}",
        "",
        "## Later",
        "",
        "- `--check` says what is missing or wrong, without downloading.",
        "- `--events` writes the run as JSON lines, for reading by a program.",
        "",
        "## Answering from the site",
        "",
        *(f"- {rule}" for rule in ANSWER_RULES),
        "",
        f"Every option: {SITE}wiki/installer/. Devices and their folders: "
        f"{SITE}platforms/linux-handhelds/. The site's guide for agents: {SITE}llms.txt.",
        "",
    ])


def ard_manifest() -> dict:
    """The ARD manifest: the setup skill and the JSON API, each with the
    questions it answers. llms.txt is found at the site root, as its
    convention says."""
    return {
        "entries": [
            {
                "identifier": f"urn:air:{PUBLISHER}:retrobios:setup-bios",
                "displayName": "Set up BIOS files with RetroBIOS",
                "type": SKILL_TYPE,
                "url": f"{SITE}{SKILL_PATH}",
                "description": "An agent skill that installs the BIOS files a device needs, only "
                               "what the games on its card need to start.",
                "representativeQueries": [
                    "install the minimum BIOS files for the games on an R36S running dArkOS",
                    "set up BIOS files for RetroArch on a Steam Deck",
                    "the emulator says BIOS missing, fix it",
                ],
                "capabilities": ["SetupBios"],
                "tags": ["bios", "firmware", "emulation", "retrogaming"],
            },
            {
                "identifier": f"urn:air:{PUBLISHER}:retrobios:api",
                "displayName": "RetroBIOS JSON API",
                "type": "application/json",
                "url": f"{SITE}api/v1/index.json",
                "description": "Versioned JSON datasets: emulator profiles, platforms, systems, core "
                               "names and a hash lookup.",
                "representativeQueries": [
                    "what file has the MD5 490f666e1afb15b7362b406ed1cea246",
                    "which files does the beetle_psx core read",
                    "where do PlayStation BIOS files go on Batocera",
                ],
                "capabilities": ["HashLookup", "EmulatorFiles", "PlatformFiles"],
                "tags": ["api", "json", "bios"],
            },
        ]
    }


# IndexNow: the key search engines read back from the site before they take
# a list of changed pages from it (scripts/indexnow.py). Public by design.
INDEXNOW_KEY = "23329654933fb67280e8e7ac749eb869"
INDEXNOW_FILE = "indexnow.txt"


def write(public: Path, platforms: list[tuple[str, str]],
          write_if_changed: Callable[[str, str], object]) -> None:
    write_if_changed(str(public / "llms.txt"), llms_txt(platforms))
    write_if_changed(str(public / INDEXNOW_FILE), INDEXNOW_KEY + "\n")
    (public / SKILL_PATH).parent.mkdir(parents=True, exist_ok=True)
    write_if_changed(str(public / SKILL_PATH), skill_md())
    write_if_changed(str(public / "ard.json"), json.dumps(ard_manifest(), indent=1) + "\n")
