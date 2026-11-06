"""The measurements the site shows, from the records under measurements/.

The records are core probe runs, one append-only .jsonl per emulator with one
full record per line (measurement_records.py). From them the build writes,
never committed:

  public/data/measurements/index.json        the compact index the explorer and
                                             the emulator pages read, one item
                                             per emulator and subject
  public/downloads/measurements.sqlite       every record, normalised
  public/downloads/measurements/<emu>.sqlite one database per emulator

Three places read the index: the Proof lines of an emulator page (only the
records a profile's `evidence:` names, or one tied to an issue), the
Measurements explorer page and the host table of the methodology page. Runs
are made on demand, to settle a dispute or an issue, to back a correction
sent to a platform, or to smoke-test packs before a release: there is no
showcase of every run. A record links its line at the last commit that
touched measurements/. Benchmarks stay in the records and the SQLite files,
never on a page.
"""

from __future__ import annotations

import html
import json
import os
import re
import sqlite3
import sys
from dataclasses import dataclass
from pathlib import Path

import measurement_records as mr
import sitemarkup as markup
from artifacts import json_text, write_if_changed
from siterender import _escape_tags

ROOT = Path(__file__).resolve().parent.parent
REPO = "https://github.com/Abdess/retrobios"
EXPLORER_PAGE = "measurements.md"
METHOD_PAGE = "wiki/measurements.md"
HOSTS_MARKER = "<!-- measurements-hosts -->"
INDEX_PATH = Path("data") / "measurements" / "index.json"
SQLITE_PATH = Path("downloads") / "measurements.sqlite"
PER_EMULATOR_DIR = Path("downloads") / "measurements"
SQLITE_SCHEMA_VERSION = "3"
# Observables the variants table leaves out: one value per sampled frame.
BULKY_OBSERVABLES = ("frame_hashes",)
INDEX_SCHEMA_VERSION = 1
# What a maintainer saw in an issue's runs, by record subject.
OBSERVATIONS = Path("tests") / "campaign" / "observations.yml"
# A Proof line lists this many record links at most, else one link to the file.
MAX_RECORD_LINKS = 8


# --------------------------------------------------------------------------
# Index
# --------------------------------------------------------------------------

def host_summary(host: dict) -> str:
    parts = [host.get("cpu_model") or "unknown CPU"]
    if host.get("cpu_count"):
        parts.append(f"{host['cpu_count']} CPUs")
    parts.append(f"{host.get('machine', '')} Linux {host.get('kernel', '')}".strip()
                 if "Linux" in host.get("os", "") else host.get("os", ""))
    parts.append(f"Python {host.get('python', '')}")
    before, after = host.get("load_before"), host.get("load_after")
    if before and after:
        parts.append(f"load {before[0]} before, {after[0]} after")
    return ", ".join(part for part in parts if part)


def permalink(repo: str, commit: str, path: str, line: int | None = None) -> str:
    return f"{repo}/blob/{commit}/{path}" + (f"#L{line}" if line else "")


BOOTS_BUILTIN = "boots on built-in BIOS"


def shown_verdict(variant: dict) -> str:
    """A variant's verdict as the pages say it: a boot on the core's
    built-in BIOS is named so, never taken for the staged file's."""
    if variant["verdict"] == "boots" and variant.get("bios_used") == "builtin":
        return BOOTS_BUILTIN
    return variant["verdict"]


def verdicts_of(record: dict) -> list[dict]:
    """Each variant's boot verdict, from record version 4 on, and the BIOS
    it ran from version 5 on."""
    return [{"variant": v["label"], "verdict": shown_verdict(v), "bios_used": v.get("bios_used", "unknown"),
             "detail": (v.get("verdict_evidence") or {}).get("detail", ""),
             "staged": sorted(name for name, sha1 in (v.get("system_files") or {}).items() if sha1)}
            for v in record["variants"] if "verdict" in v]


def result_of(record: dict) -> tuple[str, str]:
    """The status and statement a page shows for a record.

    A run, or a check compared on the sampled frames, is shown by its boot
    verdicts: one verdict when every variant has it, else `mixed`, each
    variant named in the statement. A check on another observable keeps
    its comparison. A frame comparison recorded before the boot oracle
    shows `no verdict`: frames that differ prove nothing about a boot.
    """
    check = record.get("check") or {}
    result = check.get("result") or {}
    verdicts = verdicts_of(record)
    by_frames = record["kind"] == "run" or check.get("observable") == "frame_hashes"
    if verdicts and by_frames:
        values = {v["verdict"] for v in verdicts}
        status = values.pop() if len(values) == 1 else "mixed"
        if record["kind"] == "run":
            return status, verdicts[0]["detail"]
        return status, ". ".join(f"{v['variant']}: {v['verdict']}" for v in verdicts)
    if by_frames:
        return "no verdict", ("recorded before the boot oracle. Its frames were compared, which "
                              "settles nothing about a boot")
    return result.get("status") or "ran", result.get("statement") or ""


def opened(record: dict) -> str | None:
    """The staged name a check varied, when strace saw the core open it in
    every repetition of a variant that staged it."""
    name = (record.get("check") or {}).get("variable")
    if not isinstance(name, str):
        return None
    for variant in record["variants"]:
        reps = variant.get("repetitions") or []
        if (variant.get("system_files") or {}).get(name) and reps and all(
                any(f.get("path") == name for f in rep.get("files_opened") or ()) for rep in reps):
            return name
    return None


def load_observations(path: Path) -> dict[str, dict]:
    """Each record id or subject an observation covers, with its issue
    number and words."""
    import yaml  # noqa: PLC0415

    if not path.is_file():
        return {}
    out = {}
    for issue, entries in (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).items():
        number = ISSUE_SUBJECT.match(f"{issue}-")["number"]
        for entry in entries:
            for key in [*entry.get("records", ()), *entry.get("subjects", ())]:
                out[key] = {"issue": number, "said": entry["said"]}
    return out


def shown_of(record: dict) -> list | None:
    """What a record showed that a page can state: ["text", words] from
    its boot verdicts, ["opened", name] for a staged name strace saw the
    core open, or None."""
    verdicts = verdicts_of(record)
    if verdicts:
        return ["text", proof_result(verdicts)]
    name = opened(record)
    return ["opened", name] if name else None


def index_item(entry: mr.Stored, runs: int, source: dict, profiles: dict,
               system_names: dict[str, str], ancestry: set[str] | None = None,
               records: list[dict] | None = None) -> dict:
    record = entry.record
    profile = profiles.get(entry.emulator) or {}
    check = record.get("check") or {}
    core = record["core"]
    content = (record["inputs"].get("content") or {})
    return {
        "emulator": entry.emulator,
        "emulator_name": str(profile.get("emulator", entry.emulator)),
        "profiled": bool(profile),
        "systems": sorted(set(profile.get("systems") or [])),
        "system_names": [system_names.get(s) or s for s in sorted(set(profile.get("systems") or []))],
        "subject": record["subject"],
        "kind": record["kind"],
        "claim": check.get("claim"),
        "method": check.get("method"),
        "observable": check.get("observable"),
        "variable": check.get("variable"),
        "status": result_of(record)[0],
        "statement": result_of(record)[1],
        "verdicts": verdicts_of(record),
        "content": content.get("label"),
        "variants": len(record["variants"]),
        "repetitions": record["inputs"]["repetitions"],
        "flags": len(record["flags"]),
        "date": record["recorded_at"],
        "host": host_summary(record["host"]),
        "core": {
            "library": " ".join(filter(None, [core.get("library_name"), core.get("library_version")])),
            "file": core["file"], "sha256": core["sha256"], "repo": core.get("repo"),
            "commit": core.get("commit"), "build": core.get("build_command"),
        },
        "frontend_commit": record["frontend"].get("commit"),
        "id": record["id"],
        "runs": runs,
        "record_url": permalink(source["repo"], source["commit"], mr.records_path(entry.emulator), entry.line),
        "records": records if records is not None else [],
        "sqlite": f"downloads/measurements/{entry.emulator}.sqlite",
        "proves": proves(ancestry or {record["id"]}, profile),
    }


def build_index(stored: list[mr.Stored], source: dict | None, profiles: dict,
                system_names: dict[str, str] | None = None,
                observations: dict[str, dict] | None = None) -> dict:
    """One item per (emulator, subject): its latest record not superseded."""
    by_subject: dict[tuple[str, str], list[mr.Stored]] = {}
    live_ids = {r["id"] for r in mr.live(s.record for s in stored)}
    ancestors = lineage(stored)
    for entry in stored:
        # A benchmark only chooses between variants: it stays in the records.
        if entry.record["id"] in live_ids and entry.record["kind"] != "bench":
            by_subject.setdefault((entry.emulator, entry.record["subject"]), []).append(entry)
    items = []
    for key in sorted(by_subject):
        entries = by_subject[key]
        latest = max(entries, key=lambda s: (s.record["recorded_at"], s.line))
        profile = profiles.get(key[0]) or {}
        records = [{"url": permalink((source or {}).get("repo"), (source or {}).get("commit"),
                                     mr.records_path(s.emulator), s.line),
                    "proves": proves(ancestors.get(s.record["id"]) or {s.record["id"]}, profile),
                    "shown": shown_of(s.record),
                    "observed": (observations or {}).get(s.record["id"]) or (observations or {}).get(key[1])}
                   for s in sorted(entries, key=lambda s: s.line)]
        items.append(index_item(latest, len(entries), source or {}, profiles, system_names or {},
                                ancestors.get(latest.record["id"]), records))
    items.sort(key=lambda item: (item["emulator"], item["date"], item["subject"]))
    return {
        "schema_version": INDEX_SCHEMA_VERSION,
        "kind": "measurements",
        "repo": (source or {}).get("repo"),
        "commit": (source or {}).get("commit"),
        "records": len(stored),
        "count": len(items),
        "items": items,
    }


# --------------------------------------------------------------------------
# SQLite
# --------------------------------------------------------------------------

SCHEMA_SQL = """
    PRAGMA journal_mode = OFF;
    PRAGMA synchronous = OFF;
    CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE cores (
        sha256 TEXT PRIMARY KEY, file TEXT NOT NULL, repo TEXT, commit_sha TEXT,
        build_command TEXT, compiler TEXT, library_name TEXT, library_version TEXT
    );
    CREATE TABLE hosts (
        id INTEGER PRIMARY KEY, cpu_model TEXT, cpu_count INTEGER, os TEXT NOT NULL,
        kernel TEXT NOT NULL, machine TEXT NOT NULL, python TEXT NOT NULL
    );
    CREATE TABLE emulator_systems (
        emulator TEXT NOT NULL, system TEXT NOT NULL, PRIMARY KEY (emulator, system)
    );
    CREATE TABLE runs (
        id TEXT PRIMARY KEY, emulator TEXT NOT NULL, subject TEXT NOT NULL,
        kind TEXT NOT NULL, recorded_at TEXT NOT NULL, supersedes TEXT,
        superseded INTEGER NOT NULL, core_sha256 TEXT NOT NULL REFERENCES cores(sha256),
        host_id INTEGER NOT NULL REFERENCES hosts(id), load_before TEXT, load_after TEXT,
        max_load REAL, frontend_commit TEXT, script_sha256 TEXT NOT NULL,
        script_modified INTEGER, flags TEXT NOT NULL, record_url TEXT NOT NULL,
        line INTEGER NOT NULL,
        migrated_from_version INTEGER
    );
    CREATE TABLE inputs (
        run_id TEXT PRIMARY KEY REFERENCES runs(id), content_label TEXT, content_sha1 TEXT,
        content_size INTEGER, options TEXT NOT NULL, env TEXT NOT NULL, frames INTEGER NOT NULL,
        warmup INTEGER NOT NULL, repetitions INTEGER NOT NULL, presses TEXT NOT NULL,
        observables TEXT NOT NULL, frame_hash_every INTEGER NOT NULL, joypad_ports INTEGER NOT NULL
    );
    CREATE TABLE content_tracks (
        run_id TEXT NOT NULL REFERENCES runs(id), position INTEGER NOT NULL,
        file TEXT NOT NULL, sha1 TEXT NOT NULL, size INTEGER NOT NULL,
        PRIMARY KEY (run_id, position)
    );
    CREATE TABLE checks (
        run_id TEXT PRIMARY KEY REFERENCES runs(id), claim TEXT NOT NULL, method TEXT NOT NULL,
        observable TEXT NOT NULL, variable TEXT NOT NULL, status TEXT NOT NULL,
        statement TEXT NOT NULL
    );
    CREATE TABLE check_groups (
        run_id TEXT NOT NULL REFERENCES runs(id), position INTEGER NOT NULL,
        value TEXT, value_sha1 TEXT, variants TEXT NOT NULL, PRIMARY KEY (run_id, position)
    );
    CREATE TABLE variants (
        run_id TEXT NOT NULL REFERENCES runs(id), position INTEGER NOT NULL,
        label TEXT NOT NULL, repetitions INTEGER NOT NULL, loaded INTEGER NOT NULL,
        flags TEXT NOT NULL, observables TEXT NOT NULL, files_opened TEXT,
        files_probed_absent TEXT, tracing TEXT, verdict TEXT, verdict_evidence TEXT,
        PRIMARY KEY (run_id, position)
    );
    CREATE TABLE system_files (
        run_id TEXT NOT NULL REFERENCES runs(id), variant_position INTEGER NOT NULL,
        destination TEXT NOT NULL, sha1 TEXT,
        PRIMARY KEY (run_id, variant_position, destination)
    );
    CREATE TABLE benchmarks (
        run_id TEXT NOT NULL REFERENCES runs(id), metric TEXT NOT NULL,
        median REAL NOT NULL, mean REAL NOT NULL, stdev REAL NOT NULL,
        min REAL NOT NULL, max REAL NOT NULL, PRIMARY KEY (run_id, metric)
    );
    CREATE INDEX runs_emulator_idx ON runs(emulator, subject);
    CREATE INDEX runs_subject_idx ON runs(subject);
    CREATE INDEX emulator_systems_system_idx ON emulator_systems(system);
    CREATE INDEX checks_claim_idx ON checks(claim);
    CREATE INDEX system_files_sha1_idx ON system_files(sha1);
"""

TABLES = ("meta", "cores", "hosts", "emulator_systems", "runs", "inputs", "content_tracks",
          "checks", "check_groups", "variants", "system_files", "benchmarks")


def _host_key(host: dict) -> tuple:
    return tuple(json_text(host.get(k)) for k in ("cpu_model", "cpu_count", "os", "kernel",
                                                     "machine", "python"))


def write_sqlite(destination: Path, stored: list[mr.Stored], source: dict | None, profiles: dict,
                 scratch: Path) -> None:
    """A deterministic database of the records: sorted rows, no clock."""
    scratch.mkdir(parents=True, exist_ok=True)
    temp = scratch / f"{destination.stem}-{os.getpid()}.sqlite"
    temp.unlink(missing_ok=True)
    destination.parent.mkdir(parents=True, exist_ok=True)
    stored = sorted(stored, key=lambda s: (s.emulator, s.line))
    live_ids = {r["id"] for r in mr.live(s.record for s in stored)}
    hosts = {key: number for number, key in enumerate(sorted({_host_key(s.record["host"]) for s in stored}), 1)}
    connection = sqlite3.connect(temp)
    try:
        connection.executescript(SCHEMA_SQL)
        meta = {
            "schema_version": SQLITE_SCHEMA_VERSION,
            "record_version": str(mr.RECORD_VERSION),
            "measurements_repo": (source or {}).get("repo") or "",
            "measurements_commit": (source or {}).get("commit") or "",
            "license": "MIT",
            "scope": "core probe records, one per line of measurements/<emulator>.jsonl",
        }
        connection.executemany("INSERT INTO meta VALUES (?, ?)", sorted(meta.items()))
        cores = {s.record["core"]["sha256"]: s.record["core"] for s in stored}
        connection.executemany("INSERT INTO cores VALUES (?, ?, ?, ?, ?, ?, ?, ?)", [
            (sha, core["file"], json_text(core.get("repo")), json_text(core.get("commit")),
             json_text(core.get("build_command")), json_text(core.get("compiler")),
             json_text(core.get("library_name")), json_text(core.get("library_version")))
            for sha, core in sorted(cores.items())])
        connection.executemany("INSERT INTO hosts VALUES (?, ?, ?, ?, ?, ?, ?)", [
            (number, *key) for key, number in sorted(hosts.items(), key=lambda kv: kv[1])])
        emulators = sorted({s.emulator for s in stored})
        connection.executemany("INSERT INTO emulator_systems VALUES (?, ?)", [
            (emu, system) for emu in emulators
            for system in sorted(set((profiles.get(emu) or {}).get("systems") or []))])
        for entry in stored:
            _insert_run(connection, entry, source or {}, hosts, entry.record["id"] not in live_ids)
        connection.commit()
        connection.execute("VACUUM")
    finally:
        connection.close()
    os.replace(temp, destination)


def _insert_run(connection: sqlite3.Connection, entry: mr.Stored, source: dict,
                hosts: dict, superseded: bool) -> None:
    r = entry.record
    host, front, inputs = r["host"], r["frontend"], r["inputs"]
    rid = r["id"]
    connection.execute("INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (
        rid, entry.emulator, r["subject"], r["kind"], r["recorded_at"], r.get("supersedes"),
        int(superseded), r["core"]["sha256"], hosts[_host_key(host)],
        json_text(host.get("load_before")), json_text(host.get("load_after")), host.get("max_load"),
        front.get("commit"), front["script_sha256"],
        None if front.get("script_modified") is None else int(front["script_modified"]),
        json_text(r["flags"]),
        permalink(source.get("repo", ""), source.get("commit", ""), mr.records_path(entry.emulator), entry.line),
        entry.line, r.get("migrated_from_version")))
    content = inputs.get("content") or {}
    connection.execute("INSERT INTO inputs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (
        rid, content.get("label"), content.get("sha1"), content.get("size"),
        json_text(inputs["options"]), json_text(inputs["env"]), inputs["frames"], inputs["warmup"],
        inputs["repetitions"], json_text(inputs["presses"]), json_text(inputs["observables"]),
        inputs["frame_hash_every"], inputs["joypad_ports"]))
    connection.executemany("INSERT INTO content_tracks VALUES (?, ?, ?, ?, ?)", [
        (rid, position, track["file"], track["sha1"], track["size"])
        for position, track in enumerate(content.get("tracks") or [])])
    check = r.get("check")
    if check:
        result = check["result"]
        connection.execute("INSERT INTO checks VALUES (?, ?, ?, ?, ?, ?, ?)", (
            rid, check["claim"], check["method"], check["observable"], check["variable"],
            result["status"], result["statement"]))
        connection.executemany("INSERT INTO check_groups VALUES (?, ?, ?, ?, ?)", [
            (rid, position, json_text(group["value"]),
             mr.value_sha1(group["value"]) if isinstance(group["value"], (list, dict)) else None,
             json_text(group["variants"]))
            for position, group in enumerate(result["groups"])])
    for position, variant in enumerate(r["variants"]):
        reps = variant["repetitions"]
        first = reps[0]
        # The first repetition stands for the variant, its per-frame hashes left out.
        observables = {key: value for key, value in (first.get("observables") or {}).items()
                       if key not in BULKY_OBSERVABLES}
        connection.execute("INSERT INTO variants VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (
            rid, position, variant["label"], len(reps), int(all(rep.get("loaded") for rep in reps)),
            json_text(variant["flags"]), json_text(observables),
            json_text(first.get("files_opened")), json_text(first.get("files_probed_absent")),
            json_text(first.get("tracing")), variant.get("verdict"),
            json_text(variant.get("verdict_evidence")) if "verdict_evidence" in variant else None))
        connection.executemany("INSERT INTO system_files VALUES (?, ?, ?, ?)", [
            (rid, position, dest, sha1) for dest, sha1 in sorted(variant["system_files"].items())])
    for metric, stats in sorted((r.get("timing") or {}).items()):
        connection.execute("INSERT INTO benchmarks VALUES (?, ?, ?, ?, ?, ?, ?)", (
            rid, metric, stats["median"], stats["mean"], stats["stdev"], stats["min"], stats["max"]))


# --------------------------------------------------------------------------
# Building the site's files
# --------------------------------------------------------------------------

@dataclass
class Built:
    index: dict
    paths: list[Path]


def load_profiles(emulators_dir: Path) -> dict:
    from common import load_emulator_profiles  # noqa: PLC0415

    return load_emulator_profiles(str(emulators_dir), skip_aliases=False)


def records_commit(root: Path) -> str | None:
    """The commit the record links name, with a warning when the records on
    disk are not the ones it holds."""
    commit = mr.last_commit(root)
    if commit is None:
        print(f"WARNING: no commit holds {root / mr.RECORDS_DIR}: the record links "
              "lead nowhere until the records are committed.", file=sys.stderr)
        return None
    on_disk = {path: file.read_bytes() for path, file in mr.tree_files(root).items()}
    if mr.committed_files(root, commit) != on_disk:
        print(f"WARNING: {mr.RECORDS_DIR}/ differs from {commit[:12]}, the last commit that "
              "touched it: links to records added since lead nowhere until they are "
              "committed.", file=sys.stderr)
    return commit


def build(public: Path, root: Path = ROOT, emulators_dir: Path = ROOT / "emulators",
          scratch: Path = ROOT / "tmp" / "site", system_names: dict[str, str] | None = None,
          repo: str = REPO, commit: str | None = None) -> Built:
    """Write the index and the databases under the site's public folder.

    ``commit`` is the revision the record links name, by default the last
    commit that touched the records.
    """
    stored = mr.read_records(root)
    source = {"repo": repo, "commit": commit or (records_commit(root) if stored else None)}
    profiles = load_profiles(emulators_dir)
    index = build_index(stored, source, profiles, system_names, load_observations(root / OBSERVATIONS))
    paths = [public / INDEX_PATH]
    (public / INDEX_PATH).parent.mkdir(parents=True, exist_ok=True)
    write_if_changed(str(public / INDEX_PATH),
                     json.dumps(index, ensure_ascii=False, indent=1, sort_keys=True) + "\n")
    write_sqlite(public / SQLITE_PATH, stored, source, profiles, scratch)
    paths.append(public / SQLITE_PATH)
    for emulator in sorted({s.emulator for s in stored}):
        target = public / PER_EMULATOR_DIR / f"{emulator}.sqlite"
        write_sqlite(target, [s for s in stored if s.emulator == emulator], source, profiles, scratch)
        paths.append(target)
    return Built(index, paths)


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------

def by_emulator(index: dict) -> dict[str, list[dict]]:
    """Each emulator's items. A pack probe's run proves a pack, not the
    emulator's page."""
    out: dict[str, list[dict]] = {}
    for item in index.get("items", []):
        if not item["subject"].startswith(mr.PACK_SUBJECT_PREFIX):
            out.setdefault(item["emulator"], []).append(item)
    return out


ISSUE_SUBJECT = re.compile(r"^issue(?P<number>\d+)-")


VERDICT_WORDS = {"boots": "boots", "bios_error": "shows a BIOS error", "crash": "crashes",
                 "hang": "hangs", "unknown": "gives no verdict"}


def proof_result(verdicts: list[dict]) -> str:
    """What a record showed, in words, naming the BIOS each boot ran: a
    boot on the core's built-in BIOS is never the staged file's. A single
    run says what was staged, a check names each variant."""
    def said(verdict: dict) -> str:
        used = verdict.get("bios_used") or "unknown"
        if verdict["verdict"] == BOOTS_BUILTIN:
            return "boots on the core's built-in BIOS"
        if verdict["verdict"] == "boots" and used.startswith("staged:"):
            return f"boots on {used.removeprefix('staged:')}"
        return VERDICT_WORDS.get(verdict["verdict"], verdict["verdict"].replace("_", " "))
    if len(verdicts) == 1:
        staged = verdicts[0].get("staged") or []
        given = " and ".join(staged) if len(staged) < 3 else f"{', '.join(staged[:-1])} and {staged[-1]}"
        return f"with {given or 'no BIOS'}, it {said(verdicts[0])}"
    return ". ".join(f"{v['variant']}: {said(v)}" for v in verdicts)


def proof_claims(item: dict, record: dict) -> tuple[list[str], list | None]:
    """The claims one record of an item backs on its emulator's page, and
    what it showed. An issue observation is the claim and needs no more.
    No claim when the record shows nothing a page can state."""
    observed = record.get("observed")
    if observed:
        return [f"issue {observed['issue']}: {observed['said']}"], None
    shown = record.get("shown")
    if shown is None:
        return [], None
    if record.get("proves"):
        return record["proves"], shown
    issue = ISSUE_SUBJECT.match(item["subject"])
    if issue and shown[0] == "text":
        return [f"issue {issue['number']}"], shown
    return [], None


def _md(value: object) -> str:
    """Record text placed in a Markdown line: no span, link or tag out of it."""
    return _cell(value).translate(_MARKDOWN)


def _records(urls: list[str]) -> str:
    """The record links of one statement, escaped and safe targets only."""
    def place(url: str) -> tuple[str, int]:
        path, _, line = url.partition("#L")
        return path, int(line) if line.isdigit() else 0
    targets = sorted(dict.fromkeys(t for u in urls if (t := _href(u))), key=place)
    if not targets:
        return ""
    if len(targets) == 1:
        return f" ([record]({targets[0]}))"
    files = {t.split("#", 1)[0] for t in targets}
    if len(targets) > MAX_RECORD_LINKS and len(files) == 1:
        return f" ([{len(targets)} records]({files.pop()}))"
    return " (records " + ", ".join(f"[{n}]({t})" for n, t in enumerate(targets, 1)) + ")"


def proof_line(claim: str, shown: list[tuple[list | None, list[str]]]) -> str:
    """One line per claim, its records collapsed: the files strace saw
    opened in one list, each distinct result once with its records."""
    names: dict[str, list[str]] = {}
    texts: dict[str, list[str]] = {}
    bare: list[str] = []
    for what, urls in shown:
        if what is None:
            bare.extend(urls)
        elif what[0] == "opened":
            names.setdefault(what[1], []).extend(urls)
        else:
            texts.setdefault(what[1], []).extend(urls)
    parts = []
    if names:
        parts.append("the core opened " + ", ".join(_md(n) for n in names)
                     + _records([u for urls in names.values() for u in urls]))
    parts.extend(_md(text) + _records(urls) for text, urls in texts.items())
    if not parts:
        return f"- {_md(claim)}{_records(bare)}."
    return f"- {_md(claim)}: " + ". ".join(part[:1].upper() + part[1:] if n else part
                                          for n, part in enumerate(parts)) + "."


def proof_section(items: list[dict]) -> list[str]:
    """The Proof lines of an emulator page: only the claims of the page a
    run backs, one line per claim. Every other record stays on the
    Measurements page."""
    by_claim: dict[str, list] = {}
    for item in sorted(items, key=lambda i: i["subject"]):
        for record in item.get("records") or ():
            claims, what = proof_claims(item, record)
            for claim in claims:
                by_claim.setdefault(claim, []).append((what, [record["url"]]))
    if not by_claim:
        return []
    return ["## Proof", "",
            f"Real runs that back this page ([how they are made](../../{METHOD_PAGE.removesuffix('.md')}/)):",
            "", *(proof_line(claim, by_claim[claim]) for claim in sorted(by_claim)), ""]


def _text(value: object) -> str:
    """Record text as the page shows it. A semicolon joining two clauses
    ends a sentence on the site: the record keeps the words as written."""
    text = " ".join(str(value or "").split())
    text = re.sub(r";\s+(\w)", lambda m: ". " + m[1].upper(), text)
    return _escape_tags(text)


def _short(commit: str | None) -> str:
    return f"`{commit[:12]}`" if commit else "unknown"


def proves(record_ids: set[str], profile: dict) -> list[str]:
    """The profile fields a record is evidence for, as `field of file`. A
    record judged again stands for the ones it supersedes."""
    out = []
    for entry in profile.get("files") or ():
        for name, ids in sorted((entry.get("evidence") or {}).items()):
            if record_ids & set(ids):
                out.append(f"{name} of {entry.get('name')}")
    return out


def lineage(stored: list[mr.Stored]) -> dict[str, set[str]]:
    """Each record id with every id it supersedes, through the chain."""
    parent = {s.record["id"]: s.record.get("supersedes") for s in stored}
    out = {}
    for rid in parent:
        seen = {rid}
        node = parent[rid]
        while node and node not in seen:
            seen.add(node)
            node = parent.get(node)
        out[rid] = seen
    return out


# An MDX page reads a brace as the start of an expression, in text and in
# an attribute alike.
_BRACES = str.maketrans({"{": "&#123;", "}": "&#125;"})


def _attr(value: object) -> str:
    return html.escape(" ".join(str(value or "").split()), quote=True).translate(_BRACES)


def _cell(value: object) -> str:
    """Record text placed in raw HTML: escaped as text, never read as
    Markdown (a run's output is no markup), braces made inert for MDX. A
    semicolon joining two clauses ends a sentence, as on the rest of the
    site."""
    text = " ".join(str(value or "").split())
    text = re.sub(r";\s+(\w)", lambda m: ". " + m[1].upper(), text)
    return html.escape(text, quote=True).translate(_BRACES)


# The proof line is Markdown: a character that starts a span, a link or
# an image in a run's output stays a character.
_MARKDOWN = str.maketrans({c: f"&#{ord(c)};" for c in "`*_[]()~!|\\"})


_SAFE_HREF = re.compile(r"^(?:https?://[^\s\"'<>]+|/[^\s\"'<>]*|\.{0,2}/?[\w.~-][^\s\"'<>:]*)$")


def _href(url: object) -> str | None:
    """A link target from a record: http(s) or relative only, else none."""
    text = str(url or "")
    return _attr(text) if text and _SAFE_HREF.match(text) and not text.lower().startswith(
        ("javascript:", "data:", "vbscript:")) else None


def hosts_table(index: dict) -> list[str]:
    hosts: dict[str, int] = {}
    for item in index.get("items", []):
        # The load average differs per run: the computer is what comes before it.
        computer = item["host"].split(", load ")[0]
        hosts[computer] = hosts.get(computer, 0) + 1
    if not hosts:
        return ["No result is recorded yet.", ""]
    return [
        "| Computer | Tests |",
        "|----------|------:|",
        *(f"| {_text(host)} | {count} |" for host, count in sorted(hosts.items())),
        "",
    ]


def with_hosts(page: str, index: dict) -> str:
    """The methodology page with the computers the results ran on."""
    return page.replace(HOSTS_MARKER, "\n".join(hosts_table(index)).rstrip("\n"))


def generate_explorer_page(index: dict) -> str:
    commit = index.get("commit")
    repo = index.get("repo") or ""
    source = (f"[`measurements/`]({repo}/tree/{commit}/{mr.RECORDS_DIR}) at {_short(commit)}"
              if commit else f"`{mr.RECORDS_DIR}/` of this repository")
    return "\n".join([
        "# Measurements",
        "",
        f"Emulators run in real conditions: {index.get('records', 0)} records, "
        f"{index.get('count', 0)} tests, read from {source}. "
        f"[How they are made]({METHOD_PAGE}).",
        "",
        " ".join([
            markup.button("SQLite of every record", "downloads/measurements.sqlite", primary=True),
            markup.button("Index as JSON", "data/measurements/index.json"),
        ]),
        "",
        "Each row is the latest record of one test, with its verdict, the BIOS it ran, its "
        "method and the computer it ran on. Runs are made on demand: to settle a dispute or an "
        "issue, to back a correction sent to a platform, or to check the packs before a release. "
        "One SQLite file per emulator sits under `downloads/measurements/`.",
        "",
        "<MeasurementsExplorer />",
        "",
    ])


def sqlite_tables(path: Path) -> list[tuple[str, list[str]]]:
    """Each table of a database with its columns, in the order created."""
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        names = [row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY rowid")]
        return [(name, [row[1] for row in connection.execute(f"PRAGMA table_info({name})")])
                for name in names]
    finally:
        connection.close()


def data_page_section(path: Path) -> list[str]:
    """The Data page's description of measurements.sqlite."""
    return [
        "## Measurements",
        "",
        "[`measurements.sqlite`](downloads/measurements.sqlite) holds every core probe "
        f"record kept in [`{mr.RECORDS_DIR}/`]({REPO}/tree/main/{mr.RECORDS_DIR}), and "
        "`downloads/measurements/<emulator>.sqlite` the records of one emulator. The "
        f"[Measurements]({EXPLORER_PAGE}) page reads "
        "[`data/measurements/index.json`](data/measurements/index.json). A record line is "
        "valid against [`core-probe-record.schema.json`](api/v1/schemas/core-probe-record.schema.json).",
        "",
        "| Table | Columns |",
        "|-------|---------|",
        *(f"| `{name}` | {', '.join(f'`{c}`' for c in columns)} |" for name, columns in sqlite_tables(path)),
        "",
        "`meta` names the commit the record links point to and the record version. A list or object "
        "value is JSON text, an absent one empty. `runs.superseded` is 1 for a record a "
        "later one corrects.",
        "",
        "```sql",
        "SELECT r.emulator, c.claim, c.status, r.recorded_at, h.cpu_model",
        "FROM runs r JOIN checks c ON c.run_id = r.id JOIN hosts h ON h.id = r.host_id",
        "WHERE r.superseded = 0 ORDER BY r.recorded_at;",
        "```",
        "",
    ]
