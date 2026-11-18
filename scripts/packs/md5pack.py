"""A pack built from a list of hashes."""

from __future__ import annotations

import hashlib
import os
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING, TypedDict

from model.platforms import load_platform_config
from model.profiles import ProfileSelectionError, load_emulator_profiles, select_emulator_profiles
from packs.archive import _add_pack_member, _reject_unknown, _writing_pack
from packs.naming import _name_part, _narrowings
from packs.paths import _resolve_destination
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
        value = fe.get(key)
        values = value if isinstance(value, list) else str(value or "").split(",")
        return {str(v).strip().lower() for v in values if str(v).strip()}

    for fe in candidates:
        if any(
            str(held.get(key, "")).lower() in declared(fe, key)
            for key in ("sha1", "md5", "sha256", "crc32")
            if held.get(key)
        ):
            return fe
    held_paths = [str(held.get("path", ""))] + [str(p) for p in held.get("paths") or []]
    for fe in candidates:
        tail = str(fe.get("path") or fe.get("destination") or "").lower()
        if tail and any(path.lower().endswith("/" + tail) for path in held_paths):
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


def _md5_layout(opts: _Md5Settings) -> _Md5Layout | None:
    """The platform or emulator layout a hash list is packed in, or None
    when the emulator named is refused."""
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
        try:
            (_name, profile), = select_emulator_profiles(
                [emulator_name], profiles, opts.standalone
            )
        except ProfileSelectionError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return None
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
        for tag, _label in _narrowings(
            "full", None, None, False, False, standalone=opts.standalone
        )
    )
    # The hash list is what chooses the content: two lists under one name
    # overwrote each other in the same output directory.
    selection = hashlib.sha1(
        "\n".join(sorted(f"{kind}:{value.lower()}" for kind, value in hashes)).encode()
    ).hexdigest()[:8]
    return (
        f"{_name_part(context_name, '_')}{mode_part}_Custom_{selection}{custom_tags}"
        "_BIOS_Pack.zip"
    )


def _md5_destination(entry: dict, layout: _Md5Layout, opts: _Md5Settings) -> str:
    """Where a held file goes in a hash-selected pack."""
    name = entry.get("name", "")
    aliases = entry.get("aliases") or []
    paths = entry.get("paths") or []

    dest = name
    matched_fe = None
    for lookup_name in [name] + aliases:
        if lookup_name.lower() in layout.index:
            matched_fe = _entry_for_file(layout.index[lookup_name.lower()], entry)
            break

    if matched_fe:
        if opts.emulator_name:
            # Laid out as the emulator pack lays it out: its path and
            # its standalone_path, which --standalone has to reach.
            dest = _resolve_destination(matched_fe, opts.standalone)
        else:
            dest = matched_fe.get("destination", matched_fe.get("name", name))
    elif paths:
        dest = paths[0]

    if layout.base_dest and not dest.startswith(layout.base_dest):
        return f"{layout.base_dest}/{dest}"
    return dest


def generate_md5_pack(
    hashes: list[tuple[str, str]],
    db: dict,
    bios_dir: str,
    output_dir: str,
    zip_contents: dict | None = None,
    **options: Unpack[Md5PackOptions],
) -> str | None:
    """Build a pack from an explicit list of hashes with layout context."""
    files_db = db.get("files", {})
    if zip_contents is None:
        zip_contents = {}
    _reject_unknown("generate_md5_pack", options, Md5PackOptions.__optional_keys__)
    opts = _Md5Settings(**options)
    layout = _md5_layout(opts)
    if layout is None:
        return None
    zip_path = os.path.join(output_dir, _md5_pack_name(layout.context_name, hashes, opts))
    os.makedirs(output_dir, exist_ok=True)

    packed: list[tuple[str, str]] = []
    not_in_repo: list[tuple[str, str]] = []
    not_in_db: list[str] = []
    seen: set[str] = set()

    with _writing_pack(zip_path) as zf:
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

            _add_pack_member(zf, local_path, full_dest)
            packed.append((name, hash_val))

    total = len(hashes)
    print(f"\nPacked {len(packed)}/{total} requested files")
    for name, h in packed:
        print(f"  PACKED: {name} ({h[:16]}...)")
    for name, h in not_in_repo:
        print(f"  NOT IN REPO: {name} ({h[:16]}...)")
    for h in not_in_db:
        print(f"  NOT IN DB: {h}")

    if not packed:
        if os.path.exists(zip_path):
            os.unlink(zip_path)
        return None
    return zip_path
