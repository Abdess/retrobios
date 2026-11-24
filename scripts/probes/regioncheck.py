"""Each regional game under four BIOS sets: full, own region, other regions, pack."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterable
from pathlib import Path

from core.paths import DB_FILE, REPO_ROOT
from model.profiles import entry_system_ids
from core_probe import BUILTIN
from probes.content import Content, content_root, load_content, load_file, ready_folder
from probes.cores import cached_nightly
from probes.entries import entry_dest, held_file, regions_of
from probes.host import CONTENT_FILE, Unavailable, main_cache, run_when_idle
from resolve.entryscope import read_by_build


VARIANTS = ("full", "own", "others", "pack")
SUBJECT = re.compile(r"^region-(?P<core>[a-z0-9_]+)-(?P<game>[a-z0-9-]+)-(?P<variant>full|own|others|pack)$")
# The territory a test game names, as generate_pack --region takes it.
PACK_REGION = {"japan": "jp", "north-america": "us", "europe": "eu"}
REGION_WORDS = {"japan": "Japanese", "north-america": "US", "europe": "European"}


# --------------------------------------------------------------------------
# Pure rules
# --------------------------------------------------------------------------



def region_entries(profile: dict, system: str) -> list[dict]:
    """The BIOS entries of a system that a `region:` ties to territories."""
    return [
        entry for entry in profile.get("files") or ()
        if system in entry_system_ids(entry, profile)
        and regions_of(entry) and "world" not in regions_of(entry)
        and entry.get("category", "bios") == "bios" and read_by_build(entry, False)
    ]


def plan_variants(entries: Iterable[dict], region: str,
                  local: Callable[[dict], Path | None]) -> dict[str, dict[str, Path]]:
    """The staged files of `full`, `own` and `others`, dest -> file. An entry
    the collection does not hold is left out of every variant."""
    held = [(entry, path) for entry in entries if (path := local(entry))]
    full = {entry_dest(e): p for e, p in held}
    own = {entry_dest(e): p for e, p in held if region in regions_of(e)}
    others = {entry_dest(e): p for e, p in held if region not in regions_of(e)}
    return {"full": full, "own": own, "others": others}


def requested_plan(labels: Iterable[str], entries: Iterable[dict], region: str,
                   local: Callable[[dict], Path | None]) -> list[tuple[str, dict[str, Path] | None]]:
    """The requested variants in run order with their staged files. `pack`
    carries None: its files come from a generate_pack build."""
    staged = plan_variants(entries, region, local)
    return [(label, None if label == "pack" else staged[label]) for label in labels]


def subject(core: str, game: str, variant: str) -> str:
    words = re.findall(r"[a-z0-9]+", game.lower())
    return f"region-{core.lower().replace('-', '_')}-{'-'.join(words)[:60].strip('-')}-{variant}"


def opened(record: dict) -> set[str]:
    return {item["path"] for variant in record["variants"] for rep in variant["repetitions"]
            for item in rep.get("files_opened") or ()}


def frames(record: dict) -> list:
    rep = record["variants"][0]["repetitions"][0]
    return (rep.get("observables") or {}).get("frame_hashes") or []


def verdict(record: dict) -> str:
    return record["variants"][0].get("verdict") or "unknown"


def outcome(records: dict[str, dict], entries: list[dict], region: str) -> dict:
    """What the four records of one game on one core settle.

    `selected` is the regional file the core opened with every one staged.
    The `region:` claim is `confirmed` when every regional file it opened
    holds the game's region, `contradicted` when none does, `ambiguous`
    when it opened its own region's file and others too, `unread` when it
    opened none. Each variant's result is its oracle verdict. While no
    reference frame is known for the game, a variant that samples the same
    frames as the full run (`as_full`) boots, and one that does not stays
    without an answer: frames that differ never make a verdict.
    """
    by_dest = {entry_dest(e): e for e in entries}
    full = records.get("full")
    selected = sorted(opened(full) & set(by_dest)) if full else []
    if not full:
        claim = "unrun"
    elif not selected:
        claim = "unread"
    elif all(region in regions_of(by_dest[d]) for d in selected):
        claim = "confirmed"
    elif any(region in regions_of(by_dest[d]) for d in selected):
        # Opened every region's file, to hash them or to choose: the open
        # alone does not say which one the core runs.
        claim = "ambiguous"
    else:
        claim = "contradicted"
    results: dict[str, dict] = {}
    for label in VARIANTS:
        record = records.get(label)
        if not record:
            continue
        loaded = all(rep.get("loaded") for v in record["variants"] for rep in v["repetitions"])
        item = {"record": record["id"], "verdict": verdict(record), "loaded": loaded,
                "staged": sorted(record["variants"][0]["system_files"]),
                "bios_used": record["variants"][0].get("bios_used", "unknown")}
        if full and label != "full":
            item["as_full"] = loaded and frames(record) == frames(full)
        results[label] = item

    full_verdict = verdict(full) if full else None

    def boots(label: str) -> bool | None:
        item = results.get(label)
        if not item:
            return None
        if item["verdict"] != "unknown":
            return item["verdict"] == "boots"
        # No verdict: the interim rule. The same frames as the full run is a
        # boot, while the full run itself is not shown to fail. Other frames
        # say nothing: the US disc reaches its game on the Japanese and
        # European BIOS through another licence screen.
        if full_verdict in ("boots", "unknown") and item.get("as_full"):
            return True
        return None

    return {
        "region": region,
        "selected": [by_dest[d]["name"] for d in selected],
        "claim": claim,
        "variants": results,
        "own_boots": boots("own"),
        "others_boot": boots("others"),
        "pack_boots": boots("pack"),
        # The BIOS each ran, from its log: a boot is not the staged file's
        # until the log names it (core_probe.bios_used).
        "own_on": (results.get("own") or {}).get("bios_used", "unknown"),
        "others_on": (results.get("others") or {}).get("bios_used", "unknown"),
        "judged_by": "verdict" if full_verdict not in (None, "unknown") else "full_run_frames",
    }



def staged_name(used: str | None) -> str | None:
    """The file a bios_used names, or None."""
    return used.removeprefix("staged:") if used and used.startswith("staged:") else None


def sentence(game_region: str, result: dict) -> str:
    """The outcome in words, for the site. A boot is said to be another
    region's BIOS only when the core's log names that file: a core that
    refuses the staged files and runs its own BIOS (OpenBIOS, HLE) boots
    too, on that built-in BIOS."""
    word = REGION_WORDS.get(game_region, game_region)
    own, others = result.get("own_boots"), result.get("others_boot")
    if own is None:
        return f"The {word} game has no run with its own BIOS yet."
    if own and result.get("own_on") == BUILTIN:
        first = f"The {word} game boots on the core's built-in BIOS, its own BIOS file was refused"
    else:
        first = f"The {word} BIOS {'boots' if own else 'does not boot'} the {word} game"
    if others is None:
        return first + ". The other regions' BIOS have no verdict yet."
    if not others:
        return first + ", the other regions' BIOS do not."
    used = result.get("others_on")
    if used == BUILTIN:
        return first + ", and on its built-in BIOS with the others' files refused."
    name = staged_name(used)
    if name:
        return first + f", and so does {name}, another region's BIOS."
    return first + ", and with the others' files on a BIOS its log does not name."


# --------------------------------------------------------------------------
# Runs
# --------------------------------------------------------------------------

def nightly_core(core: str) -> tuple[Path, str]:
    """The buildbot nightly of a core, downloaded again when the buildbot
    replaced it, and its URL."""
    record = cached_nightly(core, main_cache() / "region" / "cores" / core)
    return Path(record["path"]), record["url"]


def pack_files(emulator: str, region: str, work: Path) -> dict[str, Path]:
    """The files generate_pack puts in the emulator's pack for one region,
    extracted, by their path in the pack."""
    from core.ziptools import safe_extract_zip

    out_dir = work / "pack"
    subprocess.run([sys.executable, str(REPO_ROOT / "scripts" / "generate_pack.py"), "--emulator", emulator,
                    "--region", PACK_REGION[region], "--output-dir", str(out_dir)],
                   cwd=REPO_ROOT, check=True, capture_output=True, text=True)
    zips = sorted(out_dir.glob("*.zip"))
    if len(zips) != 1:
        raise FileNotFoundError(f"{out_dir}: {len(zips)} packs, one expected")
    tree = work / "pack-tree"
    safe_extract_zip(str(zips[0]), str(tree))
    return {p.relative_to(tree).as_posix(): p for p in sorted(tree.rglob("*")) if p.is_file()
            and not p.name.upper().startswith("README")}


def local_resolver() -> Callable[[dict], Path | None]:
    from model.database import load_database

    db = load_database(str(REPO_ROOT / DB_FILE))
    return lambda entry: held_file(entry, db, REPO_ROOT)


def run(args: argparse.Namespace) -> int:
    from model.profiles import load_emulator_profiles

    profile = load_emulator_profiles(str(REPO_ROOT / "emulators"))[args.emulator]
    entries = region_entries(profile, args.system)
    if not entries:
        print(f"ERROR: {args.emulator} declares no regional BIOS for {args.system}", file=sys.stderr)
        return 2
    games = [g for g in load_content(CONTENT_FILE).get(args.system, []) if g.region in PACK_REGION]
    if not games:
        print(f"ERROR: content.yml has no regional game for {args.system}", file=sys.stderr)
        return 2
    core, url = (Path(args.core), args.core_artifact) if args.core else nightly_core(args.core_name)
    local = local_resolver()
    failures = 0
    root = Path(args.content_dir) if args.content_dir else content_root()
    for game in games:
        try:
            load = load_file(ready_folder(game, root)[0], game.load)
        except Unavailable as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            failures += 1
            continue
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as scratch:
            plan = requested_plan(args.variants or VARIANTS, entries, game.region, local)
            pack = (pack_files(args.emulator, game.region, Path(scratch))
                    if any(files is None for _, files in plan) else {})
            for label, staged in plan:
                argv = [sys.executable, str(REPO_ROOT / "scripts" / "core_probe.py"), "run",
                        "--core", str(core), "--content", str(load), "--content-label", game.name,
                        "--frames", str(game.frames),
                        "--frame-hash-every", str(game.frame_hash_every),
                        "--record", str(REPO_ROOT), "--emulator", args.emulator,
                        "--subject", subject(core.name.removesuffix("_libretro.so"), game.name, label),
                        "--require-sandbox", "--timeout", str(args.timeout)]
                if url:
                    argv += ["--core-artifact", url]
                for dest, src in sorted((pack if staged is None else staged).items()):
                    argv += ["--system-file", f"{dest}={src}"]
                proc = run_when_idle(argv, args.max_load_wait, timeout=args.timeout * 2 + 120)
                status = "recorded" if proc.returncode == 0 else f"exit {proc.returncode}"
                print(json.dumps({"game": game.name, "variant": label, "status": status,
                                  "error": proc.stderr.strip()[-400:] if proc.returncode else None}),
                      flush=True)
                failures += proc.returncode != 0
    return 1 if failures else 0


def collect(root: Path = REPO_ROOT, stored_records: list | None = None) -> list[dict]:
    """Every region outcome the records under measurements/ hold. A game
    listed under several systems (sega-megacd and mega-cd) is judged under
    the one whose profile ran it."""
    from model.profiles import load_emulator_profiles
    from model.measurements import live, read_records

    content: dict[str, list[tuple[str, Content]]] = {}
    for system, items in load_content(root / "campaign" / "content.yml").items():
        for item in items:
            content.setdefault(item.name, []).append((system, item))
    profiles = load_emulator_profiles(str(root / "emulators"))
    groups: dict[tuple[str, str, str], dict[str, dict]] = {}
    for stored in read_records(root) if stored_records is None else stored_records:
        match = SUBJECT.match(stored.record.get("subject", ""))
        label = ((stored.record.get("inputs") or {}).get("content") or {}).get("label")
        if not match or label not in content:
            continue
        key = (stored.emulator, match["core"], label)
        groups.setdefault(key, {})[match["variant"]] = stored.record
    out = []
    for (emulator, core, game), records in sorted(groups.items()):
        records = {k: v for k, v in records.items() if v["id"] in {r["id"] for r in live(records.values())}}
        profile = profiles.get(emulator, {})
        system, item = next(((s, i) for s, i in content[game] if s in (profile.get("systems") or ())),
                            content[game][0])
        entries = region_entries(profile, system)
        result = outcome(records, entries, item.region)
        out.append({"emulator": emulator, "core": core, "system": system, "game": game, **result,
                    "sentence": sentence(item.region, result)})
    return out
