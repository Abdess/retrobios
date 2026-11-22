"""A pack built from a list of hashes."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, TypedDict

from core.hashing import parse_hash_list
from core.options import reject_unknown
from model.platforms import load_platform_config
from model.profiles import load_emulator_profiles, select_emulator_profiles
from model.releaserecord import PACK_SUFFIX
from packs.archive import add_pack_member, writing_pack
from packs.naming import file_name_part, pack_narrowings, selection_digest
from packs.paths import platform_destination, resolve_destination, under_base
from resolve.packfiles import resolve_file, sha1_for_hash

if TYPE_CHECKING:
    from typing_extensions import Unpack


def _entry_for_file(candidates: list[dict], held: dict) -> dict:
    """The declaration a held file answers when several share its name.

    BBKEmu declares 8.BIN once per model. The last one won, and the A4980
    dump went to the A4988 folder. The declared hash decides, then the
    destination the collection's own path ends with, then the last one.
    """
    def declared(fe: dict, key: str) -> set[str]:
        return set(parse_hash_list(fe.get(key)))

    for fe in candidates:
        if any(
            str(held.get(key, "")).lower() in declared(fe, key)
            for key in ("sha1", "md5", "sha256", "crc32")
            if held.get(key)
        ):
            return fe
    held_path = str(held.get("path", "")).lower()
    for fe in candidates:
        tail = str(fe.get("path") or fe.get("destination") or "").lower()
        if tail and held_path.endswith("/" + tail):
            return fe
    return candidates[-1]


class Md5PackOptions(TypedDict, total=False):
    """The keyword options of generate_md5_pack: the layout to follow."""

    platform_name: str | None
    platforms_dir: str | None
    emulator_name: str | None
    emulators_dir: str | None
    standalone: bool


@dataclass(frozen=True)
class _Md5Settings:
    """Md5PackOptions with their defaults."""

    platform_name: str | None = None
    platforms_dir: str | None = None
    emulator_name: str | None = None
    emulators_dir: str | None = None
    standalone: bool = False


@dataclass(frozen=True)
class _Md5Layout:
    """Where a hash-selected pack puts each file: the declarations by
    lowercased name, the platform's base destination, and the pack's name."""

    index: dict[str, list[dict]]
    base_dest: str
    context_name: str


@dataclass
class Md5PackOutcome:
    """What a hash-selected pack holds: the archive (None when nothing was
    packed), the (name, hash) packed and held nowhere, and the hashes the
    database does not know."""

    requested: int
    zip_path: str | None = None
    packed: list[tuple[str, str]] = field(default_factory=list)
    not_in_repo: list[tuple[str, str]] = field(default_factory=list)
    not_in_db: list[str] = field(default_factory=list)


def _md5_layout(opts: _Md5Settings) -> _Md5Layout:
    """The platform or emulator layout a hash list is packed in.

    Raises ProfileSelectionError when the emulator named is refused.
    """
    platform_name = opts.platform_name
    platforms_dir = opts.platforms_dir
    emulator_name = opts.emulator_name
    emulators_dir = opts.emulators_dir
    plat_file_index: dict[str, list[dict]] = {}
    base_dest = ""
    plat_display = "Custom"
    if platform_name and platforms_dir:
        config = load_platform_config(platform_name, platforms_dir)
        base_dest = config.get("base_destination", "")
        plat_display = config.get("platform", platform_name)
        for system in config.get("systems", {}).values():
            for fe in system.get("files", []):
                plat_file_index.setdefault(fe.get("name", "").lower(), []).append(fe)

    emu_display = ""
    if emulator_name and emulators_dir:
        profiles = load_emulator_profiles(emulators_dir, skip_aliases=False)
        # The same gate as --emulator, unknown names included: a typo or a
        # buildbot name gave a generic pack in the layout of no emulator. A
        # core with no standalone build has no standalone layout either.
        (_name, profile), = select_emulator_profiles(
            [emulator_name], profiles, opts.standalone
        )
        emu_display = profile.get("emulator", emulator_name)
        for fe in profile.get("files", []):
            plat_file_index.setdefault(fe.get("name", "").lower(), []).append(fe)
            for alias in fe.get("aliases", []):
                plat_file_index.setdefault(alias.lower(), []).append(fe)

    context_name = plat_display if platform_name else (emu_display or "Custom")
    return _Md5Layout(plat_file_index, base_dest, context_name)


def _md5_pack_name(
    context_name: str, hashes: list[tuple[str, str]], opts: _Md5Settings,
) -> str:
    """The file name of a hash-selected pack."""
    # The selection mode is part of the name, as for --system: BizHawk is
    # both a platform and a profile display name, and the two layouts
    # (Firmware/ under the platform, the profile's paths under the core)
    # wrote one file, the second run replacing the first without a word.
    mode_part = (
        "_Emulator" if opts.emulator_name and not opts.platform_name else ""
    )
    # --standalone changes the destination layout, so a run with it must not
    # take the name of a run without it.
    custom_tags = "".join(
        tag
        for tag, _label in pack_narrowings(
            "full", None, None, False, False, standalone=opts.standalone
        )
    )
    # The hash list is what chooses the content: two lists under one name
    # overwrote each other in the same output directory.
    selection = selection_digest([f"{kind}:{value.lower()}" for kind, value in hashes])
    return f"{file_name_part(context_name, '_')}{mode_part}_Custom_{selection}{custom_tags}{PACK_SUFFIX}"


def _md5_destination(entry: dict, layout: _Md5Layout, opts: _Md5Settings) -> str:
    """Where a held file goes in a hash-selected pack."""
    name = entry.get("name", "")

    dest = name
    matched_fe = None
    if name.lower() in layout.index:
        matched_fe = _entry_for_file(layout.index[name.lower()], entry)

    if matched_fe:
        if opts.emulator_name:
            # Laid out as the emulator pack lays it out: its path and
            # its standalone_path, which --standalone has to reach.
            dest = resolve_destination(matched_fe, opts.standalone)
        else:
            # Where the platform pack and the installer put the declaration.
            _dest, full_dest = platform_destination(matched_fe, layout.base_dest)
            if full_dest:
                return full_dest

    base = layout.base_dest
    if base and dest != base and not dest.startswith(f"{base}/"):
        return under_base(dest, base)
    return dest


def generate_md5_pack(
    hashes: list[tuple[str, str]],
    db: dict,
    bios_dir: str,
    output_dir: str,
    zip_contents: dict | None = None,
    **options: Unpack[Md5PackOptions],
) -> Md5PackOutcome:
    """Build a pack from an explicit list of hashes with layout context.

    Raises ProfileSelectionError when the emulator named is refused.
    """
    files_db = db.get("files", {})
    if zip_contents is None:
        zip_contents = {}
    reject_unknown("generate_md5_pack", options, Md5PackOptions.__optional_keys__)
    opts = _Md5Settings(**options)
    layout = _md5_layout(opts)
    zip_path = os.path.join(output_dir, _md5_pack_name(layout.context_name, hashes, opts))
    os.makedirs(output_dir, exist_ok=True)

    outcome = Md5PackOutcome(len(hashes))
    packed, not_in_repo, not_in_db = outcome.packed, outcome.not_in_repo, outcome.not_in_db
    seen: set[str] = set()

    with writing_pack(zip_path) as zf:
        for hash_type, hash_val in hashes:
            sha1 = sha1_for_hash(hash_type, hash_val, db)
            if not sha1:
                not_in_db.append(hash_val)
                continue

            entry = files_db[sha1]
            name = entry.get("name", "")
            full_dest = _md5_destination(entry, layout, opts)
            if full_dest in seen:
                continue
            seen.add(full_dest)

            fe_for_resolve = {"name": name, "sha1": sha1, "md5": entry.get("md5", "")}
            local_path, status = resolve_file(
                fe_for_resolve, db, bios_dir, zip_contents
            )

            if status == "not_found" or not local_path:
                not_in_repo.append((name, hash_val))
                continue

            add_pack_member(zf, local_path, full_dest)
            packed.append((name, hash_val))

    if not packed:
        if os.path.exists(zip_path):
            os.unlink(zip_path)
    else:
        outcome.zip_path = zip_path
    return outcome
