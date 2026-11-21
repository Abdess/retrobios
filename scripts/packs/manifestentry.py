"""One file's manifest entry: where it is fetched, its hashes, the claims on it."""

from __future__ import annotations

import functools
import os
from collections.abc import Callable
from dataclasses import dataclass

from core.hashing import compute_hashes
from core.paths import declared_destination
from model.database import sha1_at
from model.declarations import OUTER_ROOTS, declared_root
from model.profiles import profile_names
from model.largefiles import asset_name, load_registered_paths, published_asset_name
from packs.executable import ships_executable
from packs.extras import (
    detect_extras_prefix,
    extra_system_ids,
    extra_full_destination,
    extra_region_key,
    save_manifest_dest,
)
from resolve.packfiles import resolve_file
from resolve.validation import validated_choice


# Manifest generation (JSON inventory for install.py)


@functools.cache
def _registered(repo_root: str) -> frozenset[str]:
    """The paths a repository's .gitignore registers as release assets, read
    by the parser the fetcher and the release check use, once per root."""
    return frozenset(load_registered_paths(os.path.join(repo_root, ".gitignore")))


def _is_release_asset(local_path: str, repo_root: str) -> bool:
    """Whether the installer fetches this file from the large-files release.

    The repository serves every committed file from its raw URL. Only the
    files kept out of git live as release assets, and .gitignore is the
    ledger of those. Size is not the criterion: a committed file over 50 MB
    is still served by the repository, and announcing it as a release asset
    sends the installer to an asset nobody uploaded.
    """
    return _repo_relative(local_path, repo_root) in _registered(repo_root)


def _repo_relative(local_path: str, repo_root: str) -> str:
    try:
        return os.path.relpath(local_path, repo_root)
    except ValueError:
        return ""


def _release_asset_name(local_path: str, repo_root: str) -> str:
    """The large-files asset install.py downloads for a gitignored file.

    The name GitHub serves, not the one uploaded: a space in the path came
    back as a 404 for an installer asking for it verbatim.
    """
    return published_asset_name(
        asset_name(_repo_relative(local_path, repo_root), sorted(_registered(repo_root)))
    )


def _get_repo_path(sha1: str, db: dict) -> str:
    """Get the repo path for a file by SHA1 lookup."""
    entry = db.get("files", {}).get(sha1, {})
    return entry.get("path", "")


# The hashes a manifest entry records, and each file's once verified.
_MANIFEST_HASHES = frozenset({"sha1", "sha256"})
_STABLE_HASHES: dict[tuple, dict] = {}


def _stable_hashes(local_path: str, db: dict) -> dict:
    """The file's hashes, held against the scan that built the database.

    A manifest entry is what every installer downloads and checks against.
    Under load this host has hashed a 252 MB DSi NAND to a sha1 no file
    holds, twice and the same way, so recomputing alone proves nothing: the
    database scanned the same path, and a manifest that disagrees with it is
    refused rather than published.
    """
    stat = os.stat(local_path)
    expected = sha1_at(db, local_path)
    # Keyed by what was checked, the sha1 this database expects there, never
    # by id(db): a database freed and replaced at the same address answered
    # with hashes verified against the first one.
    key = (os.path.normpath(local_path), stat.st_size, stat.st_mtime_ns, expected)
    known = _STABLE_HASHES.get(key)
    if known is not None:
        # Verified against the scan once: twelve manifests name a file up
        # to a dozen times, and rehashing it each time spent 163 s of 218.
        return known
    hashes = compute_hashes(local_path, _MANIFEST_HASHES)
    for _attempt in range(2):
        if expected is None or hashes["sha1"] == expected:
            _STABLE_HASHES[key] = hashes
            return hashes
        # Read from disk again: the cached digest is the one in doubt, and a
        # retry through the cache answered with it without a second read.
        hashes = compute_hashes(local_path, _MANIFEST_HASHES, cache=False)
    raise RuntimeError(
        f"{local_path}: sha1 {hashes['sha1']} contradicts the database scan "
        f"({expected}). Rehash the file or regenerate database.json"
    )


def manifest_entry(
    local_path: str | None,
    dest: str,
    cores: list[str] | None,
    db: dict,
    repo_root: str,
    selection_fields: dict,
) -> tuple[dict | None, int]:
    """The download record of a resolved file, and the size it occupies.

    The installer fetches by hash, so the entry records the copy this
    repository holds: an upstream hash carried by no local file resolves to
    no URL. An entry needs somewhere to be fetched from, and a file the
    database does not index (a data directory, a copy added since the last
    scan, a hash computed wrong) has neither a repo path nor a release
    asset. None then, so the caller records an omission instead of a dead
    entry that makes the installer refuse the whole manifest.
    `selection_fields` carries what the installer narrows on.
    """
    sha1 = ""
    sha256 = ""
    file_size = 0
    if local_path and os.path.exists(local_path):
        file_size = os.path.getsize(local_path)
        hashes = _stable_hashes(local_path, db)
        sha1 = hashes["sha1"]
        sha256 = hashes["sha256"]
    repo_path = _get_repo_path(sha1, db) if sha1 else ""
    is_release_asset = _is_release_asset(local_path or "", repo_root)
    if not repo_path and not is_release_asset:
        return None, file_size
    entry: dict = {
        "dest": dest,
        "sha1": sha1,
        "sha256": sha256,
        "size": file_size,
        "repo_path": repo_path,
        "cores": cores,
        **selection_fields,
    }
    if local_path and is_release_asset:
        entry["storage"] = "release"
        entry["release_asset"] = _release_asset_name(local_path, repo_root)
    # The installer writes what it downloads with the umask's mode, and the
    # pack writes the same file executable by the same rule.
    if local_path and ships_executable(local_path):
        entry["executable"] = True
    return entry, file_size


@dataclass(frozen=True)
class ClaimContext:
    """How a manifest resolves and judges the copy a core claim names."""

    db: dict
    bios_dir: str
    zip_contents: dict | None
    offline: bool | None
    required_only: bool
    validation_index: dict | None
    owners: dict | None
    repo_root: str
    data_registry: dict | None = None


def attach_claims(
    entry: dict,
    claims: list[dict],
    ctx: ClaimContext,
    dest: str,
    manifest_dest: str,
) -> None:
    """Every other core that reads this destination, in the order the builder
    meets them: a pack built without the earlier cores, or without the
    platform system that declares the file, carries the first remaining
    one's copy.

    A claim joins the copy just before it when the bytes agree and starts an
    alternative otherwise. It never joins an earlier copy, which would let it
    win over a core the builder tries first. Only a core's first claim can
    win: its later ones are reached only when that one is. A platform entry
    names no core, so its first claim always starts an alternative.
    """
    claimed = set(entry["cores"] or [])
    for claim in claims:
        claim_emu = claim.get("source_profile") or claim.get("source_emulator", "")
        if not claim_emu or claim_emu in claimed:
            continue
        claimed.add(claim_emu)
        if ctx.required_only and claim.get("required") is False:
            continue
        claim_path, claim_status = resolve_file(
            claim, ctx.db, ctx.bios_dir, ctx.zip_contents,
            dest_hint=claim.get("destination", ""),
            data_dir_registry=ctx.data_registry, offline=ctx.offline,
        )
        if claim_status in ("not_found", "external", "user_provided") or not claim_path:
            # Nothing held for this core: narrowed to it without the cores
            # served above, the slot is a file left out (installer replays it).
            entry.setdefault("absent_claims", []).append(
                _absent_claim(claim, claim_emu, claim_status)
            )
            continue
        claim_path, _ = validated_choice(
            claim, claim_path, ctx.db, ctx.validation_index or {}, ctx.bios_dir, None,
            claim.get("layout_path") or dest, ctx.owners,
        )
        copy, _size = manifest_entry(
            claim_path, manifest_dest, [claim_emu], ctx.db, ctx.repo_root, {}
        )
        if copy is None:
            continue
        alternatives = entry.setdefault("alternatives", [])
        last = alternatives[-1] if alternatives else entry
        if last["cores"] is not None and copy["sha1"] == last["sha1"]:
            if claim_emu not in last["cores"]:
                last["cores"].append(claim_emu)
            continue
        del copy["dest"]
        alternatives.append(copy)
    if not entry.get("alternatives"):
        entry.pop("alternatives", None)


def _absent_claim(claim: dict, claim_emu: str, claim_status: str) -> dict:
    """The omission a claim with nothing held stands for."""
    systems = extra_system_ids(claim)
    return {
        "name": str(claim.get("name") or ""),
        "system": systems[0] if systems else "",
        "required": bool(claim.get("required", True)),
        "reason": (
            claim_status
            if claim_status in ("not_found", "external", "user_provided")
            else "not_found"
        ),
        "cores": [claim_emu],
    }


def record_slot_choices(
    entry: dict,
    choices: list[tuple[str, str | None]],
    declarations: list[tuple[list[str], dict, str]],
    settle: Callable[[dict, str, str, str | None], tuple[str | None, str]],
    dest: str,
    db: dict,
    repo_root: str,
) -> None:
    """Record what a pack built for fewer cores serves at a platform destination.

    `slot_choices` lists, in the order slots decides, the cores whose claim
    settles the slot and the copy it serves, a choice without a copy leaving
    the platform's answer. `declared_choices` is the platform's answer by the
    declaring systems that remain, in the order the builder takes them.
    Nothing is recorded where every narrowing gets the entry's own copy.
    """

    def download(file_entry: dict, sys_id: str, override: str | None) -> dict | None:
        local_path, _status = settle(file_entry, sys_id, dest, override)
        if local_path is None:
            return None
        copy, _size = manifest_entry(local_path, dest, None, db, repo_root, {})
        if copy is None:
            return None
        return {k: v for k, v in copy.items() if k not in ("dest", "cores")}

    declared: list[dict] = []
    for systems, file_entry, sys_id in declarations:
        copy = download(file_entry, sys_id, None)
        if copy is None:
            # An omission is not a copy the installer can switch to.
            return
        if declared and declared[-1]["sha1"] == copy["sha1"]:
            declared[-1]["systems"].extend(systems)
        else:
            declared.append({**copy, "systems": list(systems)})
    _systems, first, first_sys = declarations[0]
    recorded: list[dict] = []
    seen: set[str] = set()
    for emulator, path in choices:
        if emulator in seen:
            continue
        seen.add(emulator)
        copy = {} if path is None else download(first, first_sys, path)
        if copy is None:
            return
        if recorded and recorded[-1].get("sha1") == copy.get("sha1"):
            recorded[-1]["cores"].append(emulator)
        else:
            recorded.append({**copy, "cores": [emulator]})
    while recorded and "sha1" not in recorded[-1]:
        recorded.pop()
    if not recorded and len(declared) == 1:
        return
    if recorded:
        entry["slot_choices"] = recorded
    entry["declared_choices"] = declared


def manifest_dest_of(full_dest: str, base_dest: str) -> str:
    """A pack destination as the manifest writes it, below base_destination."""
    if base_dest and full_dest.startswith(f"{base_dest}/"):
        return full_dest[len(base_dest) + 1:]
    return full_dest


def claim_platform_omission(held: dict | None, emulator: str) -> bool:
    """Record a core's claim on a destination the platform already omits.

    The platform's own omission stands while one of its declaring systems
    does. A pack built without them falls to the first core claiming the
    path, as for a file present. Overwriting the record lost the platform's
    claim: a target without that core dropped an omission its pack reports.
    """
    if held is None or held.get("cores") is not None:
        return False
    if emulator:
        claims = held.setdefault("alternatives", [])
        if {"cores": [emulator]} not in claims:
            claims.append({"cores": [emulator]})
    return True


def claim_cores(fe: dict) -> list[str]:
    """The cores an extra and the claims folded onto it name: an omission
    names every core reading the file, as a list built for one of them
    would."""
    names = {
        claim.get("source_profile") or claim.get("source_emulator", "")
        for claim in (fe, *fe.get("other_claims", []))
    }
    return sorted(name for name in names if name)


def record_absent(
    absent: list[dict],
    config: dict,
    base_dest: str,
    region_drops: set,
    required_only: bool,
    seen_destinations: set,
    omitted_by_destination: dict,
    record_omission: Callable[..., None],
) -> None:
    """A file a core needs that the collection does not hold is an omission.

    Left out of both lists, DevilutionX's diabdat.mpq and dhewm3's
    pak000-004 reached no safety notice: the installer said everything
    was verified and the game refused to start.
    """
    extras_pfx = detect_extras_prefix(config, base_dest)
    for fe in absent:
        if required_only and fe.get("required") is False:
            continue
        dest = declared_destination(fe)
        if not dest or (
            region_drops and extra_region_key(fe, declared_root(config)) in region_drops
        ):
            continue
        full_dest = extra_full_destination(fe, extras_pfx)
        if not full_dest or full_dest in seen_destinations:
            continue
        source_emu = fe.get("source_profile") or fe.get("source_emulator", "")
        held = omitted_by_destination.get(full_dest)
        if held is not None:
            # Another core reads the same missing file there (Raze and
            # EDuke32 both open NAPALM.GRP): one omission names them all.
            claimed = held.get("cores")
            if (held.get("reason") == "not_found" and claimed and source_emu
                    and source_emu not in claimed):
                held["cores"] = sorted([*claimed, source_emu])
            continue
        systems = extra_system_ids(fe)
        record_omission(
            full_dest, fe, systems[0] if systems else "", "not_found",
            [source_emu] if source_emu else [],
        )


# What a manifest's roms_directory and emulators_directory carry: the BIOS
# folder's name, for the roms root its place relative to the BIOS folder
# (romfolders roms_root.from_bios), and for emulator folders the places the
# launcher searches, the one a missing folder is created at, and the config
# file whose key moves a folder.
MANIFEST_OUTER_FIELDS = ("bios_folder", "from_bios", "searched", "default", "config")


def record_unplaceable(
    unplaceable: list[dict],
    record_omission: Callable[..., None],
    config: dict,
    profiles: dict[str, dict],
) -> None:
    """Held by the collection, nowhere to put it on this platform.

    Said in the manifest, where RomM's DOSBox Pure ROMs were simply absent.
    One place read by several cores is one omission naming them all.
    """
    # The emulator's own folder is the one the platform installs the name
    # it lists into: RetroPie puts amiberry 5.7.2 and 6.3.3, one per board,
    # both in $md_inst of its amiberry package.
    platform_names = {
        str(c) for key in ("cores", "standalone_cores")
        if isinstance(config.get(key), list) for c in config[key]
    }

    def folder(profile: str) -> str:
        names = set(profile_names(profile, profiles.get(profile) or {}))
        return min(names & platform_names, default=profile)

    grouped: dict[str, tuple[dict, list[str]]] = {}
    for u in unplaceable:
        where = u.get("path") or u.get("name", "")
        # The profile key, the name a target's core list and the
        # installer's narrowing match: the display name matched none.
        core = u.get("profile") or u.get("emulator", "")
        if u.get("unplaced"):
            key = f"emulator:{folder(core)}:{where}"
        elif u.get("root") in OUTER_ROOTS:
            key = f"{u['root']}:{where}"
        elif u.get("root") == "save":
            key = f"save:{save_manifest_dest(u)}"
        else:
            key = where
        held, cores = grouped.setdefault(key, (u, []))
        if core and core not in cores:
            cores.append(core)
        if u.get("required", True) and not held.get("required", True):
            grouped[key] = ({**held, "required": True}, cores)
    for key, (u, cores) in grouped.items():
        record_omission(
            # Keyed apart from the BIOS tree's paths, which a file read below
            # the save directory or in the emulator's folder can repeat.
            key, u, u.get("system") or "",
            u.get("unplaceable", "no_platform_slug"), sorted(cores),
        )
