"""The file lookup: records of every copy, data member and retired file, in shards."""

from __future__ import annotations

import json
import re
import sys
import urllib.parse
import zipfile
from pathlib import Path

from core.hashing import parse_hash_list
from model import siteinputs
from model.collection import manufacturer_slug
from model.registry import load_versions
from model.systemnames import system_name
from packs.crossref import FileConsumers
from sitegen.cards import PROVENANCE_LABELS, emulator_card_anchor, emulator_file_anchors
from sitegen.config import SITE_URL
from core.paths import REPO_ROOT
from sitegen.render import code_span, slugify_anchor, card_page, emulator_card_page
from sitegen.write import write_if_changed


HASH_ALGORITHMS = ("sha1", "sha256", "md5", "crc32")


def sorted_hash_values(value: object) -> list[str]:
    """Every accepted value of one hash field, lowercase.

    A field holds one value, a list of accepted revisions, or (Recalbox) a
    comma-joined string: an exact lookup missed all but the first form.
    """
    return sorted(parse_hash_list(value))


def site_path(markdown_target: str) -> str:
    """A page link as generators write it (systems/sony.md#psx) as a
    site-absolute path (/retrobios/systems/sony/#psx), which resolves the same
    from any document that holds it."""
    page, _, anchor = markdown_target.partition("#")
    base = urllib.parse.urlsplit(SITE_URL).path
    page = page.removesuffix(".md")
    page = "" if page == "index" else page.removesuffix("/index") + "/"
    return f"{base}{page}" + (f"#{anchor}" if anchor else "")


# System pages


def generate_files_page() -> str:
    """Find a file by any of its hashes: files/?hash=<value>.

    site.js reads the one shard of api/v1/lookup/ the value names and lists
    every page that cites it. files/?sha1=<sha1> is the card's permanent
    address and opens the card directly.
    """
    return "\n".join([
        "---",
        "terms: check my dump, md5 check, verify bios file, check hash, "
        "is my bios correct, is my bios right",
        "---",
        "",
        "# Find or check a file",
        "",
        "Check a BIOS dump: paste its hash or choose the file.",
        "",
        "A hash is a fingerprint of a file's contents ([Glossary](../wiki/glossary.md)). "
        "Tools such as clrmamepro and RomVault print one, and so do emulator logs "
        "and the BIOS lists of setups.",
        "",
        "Paste it below, alone or in the line md5sum or certutil prints. The page "
        "shows the file in the collection that has it, the setups that list it and "
        "the emulators that check for it.",
        "",
        '<form class="rb-file-lookup" action="./" method="get">',
        '<label for="rb-hash">SHA1, MD5, CRC32 or SHA256</label> ',
        # No pattern: the line md5sum or certutil prints is taken whole, and
        # the page reads the hash out of it.
        '<input id="rb-hash" name="hash" size="66" autocomplete="off" spellcheck="false" '
        'required> ',
        '<button type="submit">Find</button>',
        "</form>",
        "",
        '<p id="rb-file-lookup-status" role="status"></p>',
        "",
        "To try it, paste `0555c6fae8906f3f09baf5988f00e55f88e9f30b`, the SHA1 of "
        "`scph5501.bin`, the PlayStation BIOS v3.0. "
        "To look a file up by its name, use the search at the top of the page.",
        "",
        "Have a file the collection lacks? [See if it is wanted](../wanted.md).",
        "",
        "## Permanent links",
        "",
        "A file's card lives on its manufacturer's page, and a file refiled "
        "between manufacturers moves with it. `files/?sha1=<sha1>` is the address "
        "that does not move: it opens the card wherever it is now. The link icon "
        "beside each card's name is that address. A file that left the "
        "collection keeps it: the page says when, and opens the card of the "
        "file in its place.",
        "",
        "## The index behind it",
        "",
        "The lookup reads one file of [`api/v1/lookup/`](../data.md), named by the "
        "first two characters of the hash: one of 256, never the whole index. "
        "[`api/v1/file-locations.json`](../api/v1/file-locations.json) lists every "
        "card by SHA1 in one file.",
        "",
    ])


def data_directory_members(install_dir: Path = REPO_ROOT / "install") -> dict[str, dict[str, dict]]:
    """Each data directory's files with their sha1 and size, as the install
    manifests record them for the installer to check."""
    members: dict[str, dict[str, dict]] = {}
    for path in sorted(install_dir.glob("*.json")):
        manifest = json.loads(path.read_text(encoding="utf-8"))
        for tree in manifest.get("data_directories") or []:
            members.setdefault(str(tree.get("ref", "")), {}).update(tree.get("files") or {})
    return members


def data_directory_revisions(data_dir: Path = REPO_ROOT / "data") -> dict[str, dict]:
    """The revision each data directory was fetched at, as refresh_data_dirs records it."""
    return load_versions(data_dir / ".versions.json")


_GIT_COMMIT = re.compile(r"[0-9a-f]{40}")
_GITHUB_REPO = re.compile(r"https://github\.com/([^/]+/[^/]+)/")


def data_directory_origin(entry: dict, fetched: dict) -> list[str]:
    """Where a data directory is fetched from, and the commit the packs hold.

    The URL is written with the `{version}` refresh_data_dirs substitutes:
    printed raw it led to a 404. A zip source records the server's ETag,
    which names no revision anyone can fetch, so only a git commit is shown.
    """
    lines = []
    url = str(entry.get("source_url") or "")
    if url:
        url = url.replace("{version}", str(entry.get("version", "master")))
        lines.append(f"Fetched from <{url}>")
    sha = str(fetched.get("sha", "")).strip('"')
    if _GIT_COMMIT.fullmatch(sha):
        repo = _GITHUB_REPO.match(url)
        commit = f"[{code_span(sha[:12])}](https://github.com/{repo.group(1)}/commit/{sha})" \
            if repo else code_span(sha)
        branch = str(fetched.get("version", ""))
        lines.append(f"Revision: {commit}" + (
            f", the head of `{branch}` when fetched" if branch and branch != sha else ""))
    return lines


def page_data_directories(name: str, profiles: dict) -> list[dict]:
    """The data directories an emulator page lists.

    Its own, then those of the aliases that point at it: an alias has no
    page, and the 90 FreeIntv overlays its profile declares were linked to
    emulators/freeintv_ts_overlay/, a page that does not exist.
    """
    trees = [t for t in profiles[name].get("data_directories") or [] if isinstance(t, dict)]
    refs = {str(t.get("ref", "")) for t in trees}
    for alias in sorted(profiles):
        profile = profiles[alias]
        if profile.get("type") != "alias" or profile.get("alias_of") != name:
            continue
        for tree in profile.get("data_directories") or []:
            ref = str(tree.get("ref", ""))
            if isinstance(tree, dict) and ref not in refs:
                refs.add(ref)
                trees.append(tree)
    return trees


def _data_member_owners(profiles: dict) -> dict[str, str]:
    """The emulator page that lists each data directory, the first by name.

    Only a profile that has a page can own one.
    """
    owners: dict[str, str] = {}
    for name in sorted(profiles):
        if profiles[name].get("type") == "alias" or profiles[name].get("role") == "test":
            continue
        for tree in page_data_directories(name, profiles):
            owners.setdefault(str(tree.get("ref", "")), name)
    return owners


def file_location_items(
    db: dict, profiles: dict | None = None, members: dict | None = None
) -> list[dict]:
    """Each held file's card, keyed by its sha1.

    A card lives on its manufacturer's page, and a file refiled between
    manufacturers (mt32_control.rom, Commodore to Roland) moved its link
    with it. files/?sha1= reads this list and goes to the card wherever it
    is now: the address cited depends on the content only. The url is
    site-absolute (/retrobios/systems/...): written from the site root, it
    resolved against the document holding it to a page that does not exist.
    """
    items = []
    for sha1, entry in sorted(db.get("files", {}).items()):
        parts = entry.get("path", "").split("/")
        if len(parts) < 3 or parts[0] != "bios":
            continue
        page = card_page(entry.get("path", ""), sha1)
        items.append({"sha1": sha1, "url": site_path(f"systems/{page}.md#sha1-{sha1[:12]}")})
    # A data directory's files are listed on the page of an emulator reading
    # the tree: 2,534 hashes the packs ship were found nowhere on the site.
    owners = _data_member_owners(profiles or {})
    known = {item["sha1"] for item in items}
    for ref, files in sorted((members or {}).items()):
        if ref not in owners:
            continue
        # A large tree is listed on pages of its own (data_tree_pages).
        page_of = {member: stem for stem, names in data_tree_pages(ref, files)
                   for member in names}
        for member, info in sorted(files.items()):
            sha1 = str(info.get("sha1", ""))
            if sha1 and sha1 not in known:
                known.add(sha1)
                page = page_of.get(member, owners[ref])
                items.append({"sha1": sha1,
                              "url": site_path(f"emulators/{page}.md#sha1-{sha1[:12]}")})
    return sorted(items, key=lambda item: item["sha1"])


LOOKUP_PREFIX = 2  # hex characters naming a lookup shard: 256 files


def _lookup_system_name(sys_id: str) -> str | None:
    """The system's name as every page prints it, None for an id the site
    cannot name. The Find a file page reads it, and never builds one."""
    try:
        return system_name(sys_id)
    except KeyError:
        return None


def _console_system_names(profiles: dict, coverages: dict) -> dict[tuple[str, str], str]:
    """(manufacturer slug, console folder) -> the name of the system whose
    own section that folder is: a collection file is named after the console
    it is filed under. A folder no id owns, or that two names own, is left out.
    """
    from model.systemnames import own_section
    from sitegen.render import system_ids

    found: dict[tuple[str, str], set[str]] = {}
    for sys_id in system_ids(profiles, [c["config"] for c in coverages.values()]):
        own = own_section(sys_id)
        if own is not None:
            found.setdefault((manufacturer_slug(own[0]), own[1]), set()).add(system_name(sys_id))
    return {key: next(iter(names)) for key, names in found.items() if len(names) == 1}


def data_member_digests(
    members: dict, data_registry: dict | None = None, root: Path = REPO_ROOT,
) -> dict[str, dict[str, str]]:
    """sha1 -> every hash the lookup takes, for each data directory member
    whose copy in the tree's local cache has the sha1 the manifest records.
    The manifests carry sha1 alone: the MD5 of Dolphin's ApprovedInis.json
    found nothing although the pack ships it."""
    from model.registry import load_data_dir_registry
    from core.hashing import compute_hashes

    if data_registry is None:
        data_registry = load_data_dir_registry(str(siteinputs.current().platforms))
    found: dict[str, dict[str, str]] = {}
    for ref, tree in sorted(members.items()):
        cache = (data_registry.get(ref) or {}).get("local_cache")
        if not cache:
            continue
        for member, info in sorted(tree.items()):
            sha1 = str(info.get("sha1", ""))
            path = root / cache / member
            if not sha1 or sha1 in found or not path.is_file():
                continue
            digests = compute_hashes(path, frozenset(HASH_ALGORITHMS))
            if digests.get("sha1") == sha1:
                found[sha1] = {algo: digests[algo].lower() for algo in HASH_ALGORITHMS}
    return found


def retired_records(retired: dict[str, dict], files: dict, locations: list[dict]) -> list[dict]:
    """A record for each hash of a file that left the collection.

    Its address (files/?sha1=, #sha1-<12>) was published and answered that
    no file the site knows has the hash, inviting a contribution of a file
    the collection held. The record says when it left, and leads to the
    card of the file holding its place, followed to the one held today.
    """
    cards = {item["sha1"]: item["url"] for item in locations}
    records: list[dict] = []
    for sha1, record in sorted(retired.items()):
        if sha1 in files:
            continue
        successor, seen = record.get("successor"), {sha1}
        while successor and successor not in files and successor not in seen:
            seen.add(successor)
            successor = (retired.get(successor) or {}).get("successor")
        url = cards.get(successor) if successor in files else None
        extra: dict[str, object] = {"left": str(record["left"])}
        if url:
            extra["successor"] = successor
        else:
            # The page its card was on: the reader lands among its neighbours.
            url = site_path(f"systems/{card_page(str(record.get('path', '')), sha1)}.md")
        for algorithm in HASH_ALGORITHMS:
            value = sha1 if algorithm == "sha1" else record.get(algorithm)
            records.extend({"value": one, "algorithm": algorithm, "layer": "retired",
                            "name": str(record.get("name", "")), "sha1": sha1,
                            "url": url, **extra} for one in sorted_hash_values(value))
    return records


def _archive_member_records(entry: dict, sha1: str, url: str,
                            root: Path = REPO_ROOT) -> list[dict]:
    """The CRC32 of each member of a collection archive, read from its
    central directory.

    A pasted CRC of a ROM the collection holds only inside a set (logica2.u2
    in a500.zip, 8484f426) found nothing: 26,014 of 33,403 members were in
    no record. The record leads to the archive's card and names it.
    """
    path = root / str(entry.get("path", ""))
    if path.suffix.lower() != ".zip" or not path.is_file():
        return []
    try:
        with zipfile.ZipFile(path) as archive:
            members = [(info.filename, info.CRC) for info in archive.infolist()
                       if not info.is_dir()]
    except (OSError, zipfile.BadZipFile) as exc:
        print(f"  WARNING: {path}: members unreadable ({exc})", file=sys.stderr)
        return []
    return [{"value": f"{crc:08x}", "algorithm": "crc32", "layer": "archive-member",
             "name": member.rsplit("/", 1)[-1], "archive": str(entry.get("name", "")),
             "sha1": sha1, "url": url}
            for member, crc in members]


def _collection_lookup_records(
    files: dict, named: dict, locations: list[dict], members: dict,
) -> list[dict]:
    """The collection's own files and the data directory members, each
    value leading to the file's card."""
    member_names = {
        str(info.get("sha1", "")): member.rsplit("/", 1)[-1]
        for tree in members.values() for member, info in sorted(tree.items())
    }
    member_digests = data_member_digests(members)
    records: list[dict] = []
    for item in locations:
        sha1 = item["sha1"]
        entry = files.get(sha1)
        if entry is None:
            # A data directory member: the manifests record its sha1, the
            # tree on disk the other three.
            digests = member_digests.get(sha1) or {"sha1": sha1}
            records.extend({"value": digests[algorithm], "algorithm": algorithm,
                            "layer": "data-directory", "name": member_names.get(sha1, ""),
                            "sha1": sha1, "url": item["url"]}
                           for algorithm in HASH_ALGORITHMS if algorithm in digests)
            continue
        parts = str(entry.get("path", "")).split("/")
        held_by = named.get((manufacturer_slug(parts[1]), parts[2])) if len(parts) > 3 else None
        for algorithm in HASH_ALGORITHMS:
            records.extend({
                "value": value, "algorithm": algorithm, "layer": "collection",
                "name": str(entry.get("name", "")), "sha1": sha1, "url": item["url"],
                **({"system_name": held_by} if held_by else {}),
            } for value in sorted_hash_values(entry.get(algorithm)))
        records += _archive_member_records(entry, sha1, item["url"])
    return records


def _platform_lookup_records(coverages: dict, consumers: FileConsumers | None) -> list[dict]:
    """A platform's declared values, each leading to the system section of
    its page."""
    records: list[dict] = []
    for key, coverage in sorted(coverages.items()):
        for system_id, system in sorted((coverage["config"].get("systems") or {}).items()):
            url = site_path(f"platforms/{key}.md#{system_id.replace(' ', '-')}")
            system_label = _lookup_system_name(system_id)
            for entry in system.get("files") or []:
                # A hash of a ROM inside the archive (zipped_file) designates
                # no collection file by itself: the archive holding it is the one.
                archive = (consumers.sha1_of(entry)
                           if consumers is not None and entry.get("zipped_file") else None)
                for algorithm in HASH_ALGORITHMS:
                    records.extend({
                        "value": value, "algorithm": algorithm, "layer": "platform",
                        "owner": key, "name": str(entry.get("name", "")), "url": url,
                        **({"system_name": system_label} if system_label else {}),
                        **({"sha1": archive} if archive else {}),
                    } for value in sorted_hash_values(entry.get(algorithm)))
    return records


def _emulator_lookup_records(profiles: dict) -> list[dict]:
    """A profile's declared values, each leading to the entry's card."""
    records: list[dict] = []
    for key, profile in sorted(profiles.items()):
        if profile.get("type") == "alias" or profile.get("role") == "test":
            continue
        entries = profile.get("files") or []
        own_systems = [str(s) for s in profile.get("systems") or []]
        for entry, anchor in zip(entries, emulator_file_anchors(entries)):
            url = site_path(f"emulators/{emulator_card_page(key, anchor)}.md#{anchor}")
            sys_id = str(entry.get("system") or "") or (
                own_systems[0] if len(own_systems) == 1 else "")
            entry_label = _lookup_system_name(sys_id) if sys_id else None
            holders = [(str(entry.get("name", "")), entry)] + [
                (str(member["name"]), member) for member in entry.get("contents") or []
                if isinstance(member, dict) and member.get("name")
            ]
            for name, holder in holders:
                for algorithm in HASH_ALGORITHMS:
                    records.extend({
                        "value": value, "algorithm": algorithm, "layer": "emulator",
                        "owner": key, "name": name, "url": url,
                        **({"system_name": entry_label} if entry_label else {}),
                    } for value in sorted_hash_values(holder.get(algorithm)))
    return records


def file_lookup_records(
    db: dict,
    coverages: dict,
    profiles: dict,
    locations: list[dict],
    members: dict | None = None,
    consumers: FileConsumers | None = None,
    retired: dict | None = None,
    wanted: list[dict] | None = None,
) -> list[dict]:
    """Every hash the site knows, one record per value, for files/?hash=.

    The collection's own files lead to their card, a platform's declared
    value to the system section of its page, a profile's to the entry's
    card, a wanted dump (``wanted``, the provenance-wanted.csv rows) to
    its catalog on the provenance page. The site search indexed these values as text, 4 MB of the 21 MB
    it made every visitor download: the lookup reads one shard instead.
    """
    files = db.get("files", {})
    named = _console_system_names(profiles, coverages)
    records = _collection_lookup_records(files, named, locations, members or {})
    records += _platform_lookup_records(coverages, consumers)
    records += _emulator_lookup_records(profiles)
    records += retired_records(retired or {}, files, locations)
    records += wanted_records(wanted or [])
    records += _held_under_every_hash(records, files, db.get("indexes") or {})
    for record in records:
        if record["layer"] in ("platform", "emulator"):
            record.setdefault("declared", record["algorithm"])
    if consumers is not None:
        records += _read_by_name(records, files, consumers)
    unique = {json.dumps(r, sort_keys=True): r for r in records}
    return sorted(unique.values(), key=lambda r: (
        r["value"], r["layer"], r.get("owner", ""), r["name"], r["url"]))


def wanted_records(rows: list[dict]) -> list[dict]:
    """A record under each hash of a dump a catalog lists and the collection
    lacks, from the rows of provenance-wanted.csv. A pasted hash of a
    wanted dump (Redump's ps2-dvd-212k.bin) answered that nothing the site
    knows has it, and never said the dump is wanted."""
    records = []
    for row in rows:
        label = PROVENANCE_LABELS.get(row["catalog"], row["catalog"])
        url = site_path(f"provenance.md#{slugify_anchor(label)}")
        for algorithm in ("sha1", "md5", "crc32"):
            value = str(row.get(algorithm) or "").lower()
            if value:
                records.append({"value": value, "algorithm": algorithm, "layer": "wanted",
                                "owner": label, "name": row["name"], "url": url})
    return records


def _read_by_name(records: list[dict], files: dict, consumers: FileConsumers) -> list[dict]:
    """The emulators the file's card names that no declared hash reached.

    The card counts every profile entry resolving to the file, by name
    included: scph5501.bin named 11 emulators on its card and 9 in the
    lookup, PCSX-ReARMed and PCSX1 reading it by name. Each is written under
    every hash of the file, `declared` saying no hash was.
    """
    reached = {(r["sha1"], r["owner"]) for r in records
               if r["layer"] == "emulator" and r.get("sha1")}
    added: list[dict] = []
    for sha1, emulators in sorted(consumers.emulators.items()):
        entry = files.get(sha1)
        if entry is None:
            continue
        for emulator in sorted(emulators):
            if (sha1, emulator) in reached:
                continue
            index = consumers.emulator_entries.get(sha1, {}).get(emulator)
            entries = consumers.emulator_files.get(emulator) or []
            if index is None or index >= len(entries):
                continue
            anchor = emulator_card_anchor(emulator, entries, index)
            url = site_path(f"emulators/{emulator_card_page(emulator, anchor)}.md#{anchor}")
            name = str(entries[index].get("name", ""))
            for algorithm in HASH_ALGORITHMS:
                added.extend({
                    "value": value, "algorithm": algorithm, "layer": "emulator",
                    "owner": emulator, "name": name, "url": url, "sha1": sha1,
                    "declared": "name",
                } for value in sorted_hash_values(entry.get(algorithm)))
    return added


def _collection_sha1(files: dict, indexes: dict, algorithm: str, value: str) -> str | None:
    """The collection file a declared value designates, None when none does."""
    if algorithm == "sha1":
        return value if value in files else None
    found = indexes.get(f"by_{algorithm}", {}).get(value)
    if isinstance(found, list):
        found = found[0] if len(found) == 1 else None
    return found if found in files else None


def _held_under_every_hash(records: list[dict], files: dict, indexes: dict) -> list[dict]:
    """A platform or emulator record whose value designates a collection
    file, written under the file's other hashes too.

    Batocera lists scph5501.bin by md5: pasted by its sha1, the file showed
    no setup at all. Each record now carries the file's sha1, and
    ``declared`` names the hash its owner wrote when the record is a copy.
    """
    copies: list[dict] = []
    for record in records:
        if record["layer"] not in ("platform", "emulator"):
            continue
        sha1 = record.get("sha1") or _collection_sha1(
            files, indexes, record["algorithm"], record["value"])
        if sha1 not in files:
            continue
        record["sha1"] = sha1
        for algorithm in HASH_ALGORITHMS:
            copies.extend({**record, "value": value, "algorithm": algorithm,
                           "declared": record["algorithm"]}
                          for value in sorted_hash_values(files[sha1].get(algorithm))
                          if value != record["value"])
    return copies


def write_lookup_shards(
    api: Path, records: list[dict], generated_at: str, commit: str = "",
) -> int:
    """One envelope per leading pair of hex characters, as the lookup asks.

    A value that is not hexadecimal (a typo in a profile) has no shard the
    lookup would read, and is left out. Returns the number of shards.
    """
    shards: dict[str, list[dict]] = {}
    for record in records:
        if re.fullmatch(r"[0-9a-f]{8,}", record["value"]):
            shards.setdefault(record["value"][:LOOKUP_PREFIX], []).append(record)
    folder = api / "lookup"
    folder.mkdir(parents=True, exist_ok=True)
    for prefix, items in sorted(shards.items()):
        write_if_changed(str(folder / f"{prefix}.json"), json.dumps({
            "schema_version": 1,
            "generated_at": generated_at,
            **({"commit": commit} if commit else {}),
            "kind": "file-lookup",
            "count": len(items),
            "items": items,
        }, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n")
    return len(shards)


# A data directory listing more files than this goes to pages of its own,
# this many files each: Dolphin's Sys tree put 2,164 rows and 16,900
# elements on the Dolphin page, read on a phone.
DATA_TREE_ROWS = 400
DATA_TREE_ROWS_PER_PAGE = 1_000


def data_tree_pages(ref: str, members: dict[str, dict]) -> list[tuple[str, list[str]]]:
    """The pages under emulators/ listing a large data directory, with the
    members each holds in name order, or none when the tree is listed on
    the pages of the emulators reading it."""
    if len(members) <= DATA_TREE_ROWS:
        return []
    names = sorted(members)
    stem = f"data-{slugify_anchor(ref)}"
    return [(stem + (f"-{n}" if n > 1 else ""), names[start:start + DATA_TREE_ROWS_PER_PAGE])
            for n, start in enumerate(range(0, len(names), DATA_TREE_ROWS_PER_PAGE), 1)]
