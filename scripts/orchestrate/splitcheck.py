"""Step 5 on the --split parts: together they must be the full pack, path for path and byte for byte."""

from __future__ import annotations

import contextlib
import io
from collections.abc import Callable
from typing import TYPE_CHECKING

from core.paths import DB_FILE, EMULATORS_DIR, PLATFORMS_DIR
from orchestrate.compare import comparison_inputs
from orchestrate.labels import STEP_LABELS, step_title
from packs.archive import is_pack_note

if TYPE_CHECKING:
    from packs.archive import PackRecord


def split_differences(
    full: PackRecord, parts: dict[str, PackRecord], same_bytes: Callable[[str, str], bool],
) -> list[str]:
    """Where the --split parts of a pack, together, are not the full pack.

    A path in a part and not in the full pack, a path of the full pack in no
    part, and a path a part fills with other bytes than the full pack.
    """
    full_members = {m for m in full.members if not is_pack_note(m)}
    union = {
        m for record in parts.values() for m in record.members
        if not is_pack_note(m)
    }
    lines = [f"in a part, not in the full pack: {m}" for m in sorted(union - full_members)]
    lines += [f"in the full pack, in no part: {m}" for m in sorted(full_members - union)]
    lines += sorted({
        f"other bytes in {name}: {member}"
        for name, record in parts.items()
        for member, source in record.sources.items()
        if member in full.sources and not same_bytes(source, full.sources[member])
    })
    return lines


def check_split_packs(
    emulators_dir: str = EMULATORS_DIR, platforms_dir: str = PLATFORMS_DIR,
    db_path: str = DB_FILE,
) -> bool:
    """Build each platform's --split parts in memory and compare them with
    the full pack: the parts must add up to it, path for path and byte for
    byte. Each part is a pack of its own and used to settle its paths alone:
    RetroDECK's parts carried bios/SGB1.sfc as a file and as a directory,
    RetroBat's 21 openmsx/ twins of openMSX/ files. Offline, as every
    comparison of this step.
    """
    from packs import archive
    from packs import platformpack
    from resolve import packfiles as packresolve

    print(f"\n--- {step_title(STEP_LABELS['consistency'])}, split packs ---")
    db, zip_contents, profiles, registry, groups = comparison_inputs(
        db_path, emulators_dir, platforms_dir
    )
    all_ok = True
    with packresolve.offline():
        for _members, platform in groups:
            args = dict(
                emulators_dir=emulators_dir, zip_contents=zip_contents,
                data_registry=registry, emu_profiles=profiles, offline=True,
            )
            full = archive.PackRecord()
            parts: dict[str, archive.PackRecord] = {}
            with contextlib.redirect_stderr(io.StringIO()):
                platformpack.build_platform_pack(
                    platform, platforms_dir, db, "bios", "", record=full, **args,
                )
                platformpack.build_split_packs(
                    platform, platforms_dir, db, "bios", "", records=parts, **args,
                )
            lines = split_differences(full, parts, archive.same_bytes)
            if lines:
                all_ok = False
                print(f"  {platform} --split: {len(lines)} differences")
                print("\n".join(f"    {line}" for line in lines[:20]))
    print(f"  {len(groups)} split platform packs compared, "
          f"{'all equal' if all_ok else 'differences above'}")
    return all_ok
