"""Step 5 on the emulator and system packs, built in memory and compared with verify."""

from __future__ import annotations

import contextlib
import io

from core.paths import DB_FILE, EMULATORS_DIR, PLATFORMS_DIR
from model.profiles import reads_own_files
from orchestrate.compare import set_difference_lines
from orchestrate.labels import STEP_LABELS, step_title
from orchestrate.runner import at_repo_root
from orchestrate.narrowed import matrix_coverage

# The narrowings an emulator or system pack takes, compared by
# check_emulator_packs. A test holds this to the builder's parameters.
EMULATOR_NARROWINGS_COMPARED = frozenset({"standalone", "regions", "required_only"})


def emulator_variants(profiles: list[dict], full: bool) -> list[tuple[str, dict]]:
    """(label, builder arguments) of each narrowed emulator pack compared.

    --required-only always, and each region the profiles' files declare,
    sampled as check_narrowed_packs samples them unless *full*. A profile
    without a regional file has nothing --region could withdraw.
    """
    from model import region

    regions = sorted({
        r for profile in profiles for fe in profile.get("files") or []
        for r in region.normalize_declared(fe.get("region"))
    })
    variants: list[tuple[str, dict]] = [("", {}), (" --required-only", {"required_only": True})]
    variants += [
        (f" --region {regions[i]}", {"regions": [regions[i]]})
        for i in matrix_coverage(full, len(regions))
    ]
    return variants


@at_repo_root()
def check_emulator_packs(
    emulators_dir: str = EMULATORS_DIR, platforms_dir: str = PLATFORMS_DIR,
    db_path: str = DB_FILE, full: bool = False,
) -> bool:
    """Build every emulator and system pack in memory and compare it with verify.

    Each profile in each build it has (libretro, standalone), full and under
    each narrowing of emulator_variants: the paths the pack fills with the
    profile's files against the ones verify credits. The region and
    required-only rules are written twice, once per side, and only this
    comparison holds them together. No archive is written and no file read.
    """
    from packs import archive
    from packs import emulatorpack
    from resolve import packfiles as packresolve
    from packs import emulatorcheck
    from model.profiles import (
        ProfileSelectionError,
        load_emulator_profiles,
        profiles_for_systems,
    )
    from model.systems import norm_system_id
    from core.ziptools import build_zip_contents_index
    from model.database import load_database

    print(f"\n--- {step_title(STEP_LABELS['consistency'])}, emulator packs ---")
    db = load_database(db_path)
    zip_contents = build_zip_contents_index(db)
    profiles = load_emulator_profiles(emulators_dir, skip_aliases=False)

    def compare(names: list[str], standalone: bool, label: str, **narrowing: object) -> bool | None:
        """Whether the two sides agree, None when the profiles have no such build."""
        record = archive.PackRecord()
        # The pack is built offline: verify counts a release asset the cache
        # lacks the same way, missing, as the narrowed-pack step does.
        with packresolve.offline(), contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            try:
                report = emulatorcheck.verify_emulator(
                    names, emulators_dir, db, standalone, platforms_dir=platforms_dir,
                    **narrowing,
                )
            except ProfileSelectionError:
                return None
            emulatorpack.build_emulator_pack(
                names, emulators_dir, db, "bios", "", standalone,
                zip_contents=zip_contents, offline=True, platforms_dir=platforms_dir,
                record=record, **narrowing,
            )
        lines = set_difference_lines(
            label, set(report["pack_destinations"]), set(record.files)
        )
        if lines:
            print("\n".join(lines))
        return not lines

    all_ok = True
    compared = 0
    for name in sorted(profiles):
        if profiles[name].get("type") == "alias":
            continue  # selects the profile it names, compared under that name
        for standalone in (False, True):
            for tag, narrowing in emulator_variants([profiles[name]], full):
                label = f"{name}{' --standalone' if standalone else ''}{tag}"
                equal = compare([name], standalone, label, **narrowing)
                if equal is None:
                    break  # the selection does not depend on the narrowing
                compared += 1
                all_ok = equal and all_ok
    print(f"  {compared} emulator packs compared, {'all equal' if all_ok else 'differences above'}")
    # A system pack builds every profile of the system together: a placement
    # rule that only goes wrong when two profiles share a path (the bluemsx
    # tree beside msx-emu's files) never meets in a one-profile pack.
    systems = sorted({
        norm_system_id(str(sid))
        for profile in profiles.values()
        if reads_own_files(profile)
        for sid in profile.get("systems") or []
    })
    systems_ok = True
    compared = 0
    for sid in systems:
        for standalone in (False, True):
            matching = profiles_for_systems(profiles, [sid], standalone)
            if len(matching) < 2:
                continue
            for tag, narrowing in emulator_variants(
                [profiles[n] for n in matching if n in profiles], full
            ):
                label = f"--system {sid}{' --standalone' if standalone else ''}{tag}"
                equal = compare(matching, standalone, label, system_ids=[sid], **narrowing)
                if equal is None:
                    break
                compared += 1
                systems_ok = equal and systems_ok
    print(f"  {compared} system packs compared, "
          f"{'all equal' if systems_ok else 'differences above'}")
    return all_ok and systems_ok
