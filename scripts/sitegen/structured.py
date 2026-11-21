"""Structured data and DAT files: schema.org records and Logiqx catalogs of the collection."""

from __future__ import annotations

import json
import re
import urllib.parse
from pathlib import Path

from model.collection import collection_paths
from model.systemnames import system_name
from sitegen import starlight as sitestarlight
from sitegen.cards import emulator_file_anchors
from sitegen.config import REPO_URL, SITE_NAME, SITE_URL
from core.paths import REPO_ROOT
from sitegen.descriptions import EMULATOR_SNIPPETS, NOTHING_TO_FETCH, PAGE_DATA, TITLE_NOUNS, title_noun
from sitegen.emulatorcards import snippet_noun
from sitegen.install import comes_with_app
from sitegen.lookup import data_member_digests, sorted_hash_values
from sitegen.render import card_anchor, system_page_map
from sitegen.write import write_if_changed


SYSTEM_PARTS_IN_FULL = 250


def collection_dat(db: dict, generated_at: str) -> str:
    """The collection as a Logiqx DAT, the format clrmamepro and RomVault read.

    One game per bios/<Manufacturer>/<Console>/ folder, named
    Manufacturer\\Console, each file a rom named by its path below that
    folder, subfolders joined with a backslash as Logiqx DATs write them. An auditor checking a BIOS tree against the
    collection had JSON, CSV and SQLite, and a converter to write.
    """
    games: dict[str, list[dict]] = {}
    files = db.get("files", {})
    # Every copy, not the one path the database keeps: an audit of bios/
    # read the 2,502 others as unknown files, and a fix moved them away
    # from the engines that read them by path.
    for sha1, paths in collection_paths(db).items():
        for path in sorted(paths):
            parts = path.split("/")
            folder = parts[1:3] if len(parts) > 3 else parts[1:2]
            # A backslash is how a Logiqx set name writes a subfolder: named
            # "Sony - PlayStation", the set was looked for beside Sony/, and an
            # audit of a copy of bios/ found 330 sets missing.
            games.setdefault("\\".join(folder), []).append(
                {**files[sha1], "_rom": "\\".join(parts[1 + len(folder):])}
            )
    return _logiqx(SITE_NAME, f"{SITE_NAME} collection ({sum(map(len, games.values()))} files)",
                   games, generated_at)


def write_platform_dats(folder: Path, db: dict, members: dict, generated_at: str) -> list[Path]:
    """downloads/dat/<platform>.dat for each install manifest."""
    folder.mkdir(parents=True, exist_ok=True)
    digests = data_member_digests(members)
    written = []
    for source in sorted((REPO_ROOT / "install").glob("*.json")):
        manifest = json.loads(source.read_text(encoding="utf-8"))
        path = folder / f"{source.stem}.dat"
        write_if_changed(str(path), platform_dat(manifest, db, digests, generated_at))
        written.append(path)
    return written


def platform_dat(manifest: dict, db: dict, member_digests: dict[str, dict[str, str]],
                 generated_at: str) -> str:
    """What one setup's BIOS folder holds once installed, as a Logiqx DAT.

    One game named after the folder (`bios`, `system`), each file a rom
    named by its place below it, as the install manifest writes it: the
    files of the setup's list and those its cores load, and the members of
    its data directories. A Batocera user auditing share/bios against the
    collection DAT met thousands of sets laid out by manufacturer.
    """
    files = db.get("files", {})
    roms: list[dict] = []
    for entry in manifest.get("files") or []:
        if entry.get("root") == "save":
            continue  # installed in the save directory, not this folder
        sha1 = str(entry.get("sha1", ""))
        roms.append({**files.get(sha1, {}), "sha1": sha1, "size": entry.get("size", 0),
                     "_rom": str(entry["dest"]).replace("/", "\\")})
    for tree in manifest.get("data_directories") or []:
        dest = str(tree.get("dest") or "").strip("/")
        for member, info in (tree.get("files") or {}).items():
            sha1 = str(info.get("sha1", ""))
            path = f"{dest}/{member}" if dest else member
            roms.append({**member_digests.get(sha1, {}), "sha1": sha1,
                         "size": info.get("size", 0), "_rom": path.replace("/", "\\")})
    folder = str(manifest.get("base_destination") or "bios").strip("/").rsplit("/", 1)[-1]
    name = f"{SITE_NAME} - {manifest.get('display_name') or manifest['platform']}"
    unique = list({rom["_rom"]: rom for rom in reversed(roms)}.values())
    return _logiqx(name, f"{name} ({len(unique)} files)", {folder: unique}, generated_at)


def _logiqx(name: str, description: str, games: dict[str, list[dict]], generated_at: str) -> str:
    """Games of roms as a Logiqx datafile, each rom's `_rom` its name."""
    import xml.etree.ElementTree as ET

    root = ET.Element("datafile")
    header = ET.SubElement(root, "header")
    version = generated_at[:10].replace("-", "")
    for tag, text in (
        ("name", name),
        ("description", description),
        ("version", version),
        ("date", generated_at[:10]),
        ("author", SITE_NAME),
        ("homepage", SITE_URL),
        ("url", REPO_URL),
    ):
        ET.SubElement(header, tag).text = text
    for game_name in sorted(games):
        game = ET.SubElement(root, "game", name=game_name)
        ET.SubElement(game, "description").text = game_name
        for entry in sorted(games[game_name], key=lambda e: e["_rom"]):
            attributes = {"name": entry["_rom"], "size": str(entry.get("size", 0))}
            for attribute, field in (("crc", "crc32"), ("md5", "md5"), ("sha1", "sha1")):
                if entry.get(field):
                    attributes[attribute] = str(entry[field]).lower()
            ET.SubElement(game, "rom", attributes)
    ET.indent(root, space="\t")
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE datafile PUBLIC "-//Logiqx//DTD ROM Management Datafile//EN" '
        '"http://www.logiqx.com/Dats/datafile.dtd">\n'
        + ET.tostring(root, encoding="unicode") + "\n"
    )


def system_structured_data(slug: str, consoles: dict[str, list]) -> dict:
    """A system page's files for a machine: each card as a CreativeWork.

    The pages that hold a card per file published a bare TechArticle with
    no file, hash or provenance, while emulator pages listed theirs.
    """
    parts = []
    for _console, entries in sorted(consoles.items()):
        for entry in entries:
            sha1 = str(entry.get("sha1") or "")
            part: dict = {"@type": "CreativeWork", "name": str(entry.get("name", ""))}
            if sha1:
                part["url"] = urllib.parse.urljoin(SITE_URL, f"systems/{slug}/#{card_anchor(sha1)}")
            identifiers = [
                f"{field}:{str(entry[field]).lower()}"
                for field in ("sha1", "md5", "crc32", "sha256") if entry.get(field)
            ]
            if identifiers:
                part["identifier"] = identifiers
            if entry.get("size"):
                part["contentSize"] = f"{entry['size']} B"
            citations = [
                f"{catalog}: {record.get('dat', '')} ({record.get('name', '')})"
                for catalog, record in sorted((entry.get("provenance") or {}).items())
                if isinstance(record, dict)
            ]
            if citations:
                part["citation"] = citations
            parts.append(part)
    if len(parts) > SYSTEM_PARTS_IN_FULL:
        # A page of cards carried up to 2.6 MB of JSON-LD (game-engines), a
        # quarter of its weight: past the cap a page lists its
        # catalogue-verified files and points at the full table.
        return {
            "hasPart": [part for part in parts if part.get("citation")],
            "isBasedOn": urllib.parse.urljoin(SITE_URL, "downloads/files.csv"),
        }
    return {"hasPart": parts} if parts else {}


def platform_structured_data(name: str, coverage: dict) -> dict:
    """A platform page's declarations for a machine reader.

    The page printed thousands of hashes while its JSON-LD named only the
    page: a crawler could not learn which md5 Batocera requires for a file.
    The software and its version are the subject, and each declared file, with
    the hashes the platform checks, is a part. Past SYSTEM_PARTS_IN_FULL the
    parts give way to the platform-files table, as system pages do.
    """
    config = coverage.get("config") or {}
    about: dict = {"@type": "SoftwareApplication", "name": str(coverage.get("platform", name))}
    if config.get("version"):
        about["softwareVersion"] = str(config["version"])
    if config.get("homepage"):
        about["url"] = str(config["homepage"])
    parts = []
    for system_id, system in sorted((config.get("systems") or {}).items()):
        for entry in system.get("files") or []:
            if not isinstance(entry, dict) or not entry.get("name"):
                continue
            part: dict = {
                "@type": "CreativeWork",
                "name": str(entry.get("destination") or entry["name"]),
                "url": urllib.parse.urljoin(SITE_URL, f"platforms/{name}/#{system_id}"),
            }
            identifiers = [
                f"{field}:{value}"
                for field in ("sha1", "md5", "crc32", "sha256")
                for value in sorted_hash_values(entry.get(field))
            ]
            if identifiers:
                part["identifier"] = identifiers
            parts.append(part)
    data: dict = {"about": about}
    if len(parts) > SYSTEM_PARTS_IN_FULL:
        data["isBasedOn"] = urllib.parse.urljoin(SITE_URL, "downloads/platform-files.csv")
    elif parts:
        data["hasPart"] = parts
    return data


def dataset_structured_data(exports: list[dict], db: dict) -> dict:
    """The data page as a schema.org Dataset a harvester can index.

    It was a Dataset named "Data & API" with no download, licence, date or
    creator, so Google Dataset Search and open-data catalogues had nothing
    to list. The exports are metadata this project authors: MIT, as the
    LICENSE's scope says.
    """
    data: dict = {
        "name": f"{SITE_NAME} collection data",
        "license": "https://opensource.org/licenses/MIT",
        "creator": {"@type": "Organization", "name": SITE_NAME, "url": REPO_URL},
        "distribution": [
            {
                "@type": "DataDownload",
                "name": item["title"],
                "contentUrl": urllib.parse.urljoin(SITE_URL, item["url"]),
                "encodingFormat": item["media_type"],
                "contentSize": f"{item['bytes']} B",
                "sha256": item["sha256"],
            }
            for item in exports
        ],
    }
    generated = str(db.get("generated_at") or "")[:10]
    if generated:
        data["dateModified"] = generated
    return data


def emulator_file_aliases(files: list[dict], anchors: list[str]) -> list[str]:
    """The plain file-<path> id each card also answers to, or "".

    A link cited as emulators/raze/#file-duke3d-grp must still land once the
    card is addressed by its hash: the first card of that path keeps the
    plain id, unless another card already is it.
    """
    taken = set(anchors)
    aliases = []
    for f, anchor in zip(files, anchors):
        base = "file-" + (
            re.sub(
                r"[^a-z0-9]+", "-",
                str(f.get("path") or f.get("standalone_path") or f.get("name", "")).lower(),
            ).strip("-") or "entry"
        )
        if base in taken or anchor == base:
            aliases.append("")
        else:
            taken.add(base)
            aliases.append(base)
    return aliases


# A commit id: hexadecimal with a letter and a digit, 7 to 40 long. A version
# that holds one (0.8.139-2-g25e1ee2fd5) names no release.
_COMMIT_ID = re.compile(
    r"(?<![0-9a-f])(?=[0-9a-f]*[a-f])(?=[0-9a-f]*[0-9])[0-9a-f]{7,40}(?![0-9a-f])", re.I)


def release_versions(profile: dict) -> dict[str, str]:
    """The `core_version` of a profile by build mode ("" when one covers
    every build), kept only where it names a release: a number and no
    commit id. A commit id of digits only reads as a number, so a run that
    starts one of the profile's own pins is one too (supermodel3's
    "0.3a-1481545-mm")."""
    pins = [str(value).casefold()
            for field in ("source_commit", "upstream_commit")
            for value in (profile[field].values() if isinstance(profile.get(field), dict)
                          else [profile.get(field)])
            if value]

    def names_a_commit(value: str) -> bool:
        return bool(_COMMIT_ID.search(value)) or any(
            pin.startswith(run) for run in re.findall(r"[0-9a-f]{7,40}", value.casefold())
            for pin in pins)

    stated = profile.get("core_version")
    pairs = stated.items() if isinstance(stated, dict) else [("", stated)]
    versions = {str(mode): str(value or "").strip() for mode, value in pairs}
    return {mode: value for mode, value in versions.items()
            if re.search(r"[0-9]", value) and not names_a_commit(value)}


def record_emulator_page(name: str, profile: dict) -> None:
    """What the title and the description of an emulator page read."""
    key = f"emulators/{name}.md"
    PAGE_DATA[key] = emulator_structured_data(profile)
    listed = [f for f in profile.get("files") or [] if isinstance(f, dict)]
    fetched = [f for f in listed if f.get("name") and not comes_with_app(f)]
    systems = profile.get("systems") or []
    first = systems[0] if systems else ""
    makers = [system_page_map[sys_id][0] for sys_id in systems if sys_id in system_page_map]
    if makers:
        sitestarlight.EMULATOR_CARDS[f"emulators/{name}"] = makers[0]
    else:
        sitestarlight.EMULATOR_CARDS.pop(f"emulators/{name}", None)
    # The first system's files first: "dreamcast bios" found Flycast's
    # page, whose required NAOMI archives came before dc_boot.bin.
    names: dict[str, str] = {}
    for f in sorted(fetched, key=lambda f: (f.get("system", first) != first,
                                            f.get("required") is not True)):
        base = Path(str(f["name"])).name
        names.setdefault(base.casefold(), base)
    firmware = [f for f in fetched if f.get("category", "bios") in ("bios", "bios_zip")]
    TITLE_NOUNS[key] = title_noun(str(f["name"]) for f in firmware)
    EMULATOR_SNIPPETS[key] = (
        # One console names an emulator of five systems, not BizHawk of 40.
        system_name(first) if 0 < len(systems) <= 5 else "",
        list(names.values()),
        len({Path(str(f["name"])).name.casefold() for f in fetched if f.get("required") is True}),
        snippet_noun(names.values(), len(firmware), len(fetched)),
    )
    if listed and all(comes_with_app(f) for f in listed):
        NOTHING_TO_FETCH.add(key)
    else:
        NOTHING_TO_FETCH.discard(key)


def emulator_structured_data(profile: dict) -> dict:
    """What an emulator page states, for a reader of its JSON-LD.

    The block said only the page name: a crawler could not learn which files
    the core loads, their hashes, the source read or when.
    """
    data: dict = {}
    # Every repository the profile reads. The source repository carries the
    # release the profile describes, never a commit id: a pin is no version.
    # The upstream of a port is another code base and states none.
    versions = release_versions(profile)
    about = []
    seen: set[str] = set()
    for field in ("source", "upstream"):
        urls = profile.get(field)
        for mode, url in (urls.items() if isinstance(urls, dict) else [("", urls)]):
            if not url or not str(url).startswith("http") or str(url) in seen:
                continue
            seen.add(str(url))
            entry = {
                "@type": "SoftwareSourceCode",
                "name": str(profile.get("emulator", "")),
                "codeRepository": str(url),
            }
            version = (versions.get(mode) or versions.get("")) if field == "source" else None
            if version:
                entry["version"] = version
            about.append(entry)
    if about:
        data["about"] = about[0] if len(about) == 1 else about
    if profile.get("profiled_date"):
        data["dateModified"] = str(profile["profiled_date"])
    parts = []
    files = [f for f in profile.get("files") or [] if isinstance(f, dict)]
    for f, anchor in zip(files, emulator_file_anchors(files)):
        if not f.get("name"):
            continue
        # One identifier per accepted value: "sha256:a,b,c,d" matched no
        # exact search (mesence's BS-X.bin).
        identifiers = [
            f"{field}:{value}"
            for field in ("sha1", "sha256", "md5", "crc32")
            for value in sorted_hash_values(f.get(field))
        ]
        part: dict[str, object] = {
            "@type": "CreativeWork",
            "name": str(f.get("path") or f["name"]),
            # The card's own anchor, as system and platform parts carry.
            "url": f"#{anchor}",
        }
        if identifiers:
            part["identifier"] = identifiers
        # An archive is identified by its members: MAME and FBNeo hash them,
        # never the ZIP, and 1 338 archive parts had no identifier at all.
        members = [
            {
                "@type": "CreativeWork",
                "name": str(member.get("name", "")),
                "identifier": [
                    f"{field}:{value}"
                    for field in ("sha1", "crc32")
                    for value in sorted_hash_values(member.get(field))
                ],
            }
            for member in f.get("contents") or []
            if isinstance(member, dict) and member.get("name")
            and (member.get("sha1") or member.get("crc32"))
        ]
        if members:
            part["hasPart"] = members
        parts.append(part)
    if len(parts) > SYSTEM_PARTS_IN_FULL:
        # MAME's 1,564 entries and their members were 614 KB of JSON-LD: past
        # the cap the members are left to the profile's JSON.
        for part in parts:
            part.pop("hasPart", None)
    if parts:
        data["hasPart"] = parts
    return data
