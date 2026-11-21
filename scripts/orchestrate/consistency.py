"""Step 5 on the full packs: verify's counts and paths against what the build wrote."""

from __future__ import annotations

import json
from pathlib import Path

from core.paths import PLATFORMS_DIR
from orchestrate import compare
from orchestrate.labels import STEP_LABELS, step_title
from packs.archive import is_pack_note
from packs.packcounts import read_pack_counts


def read_records(destinations_file: str, counts_file: str) -> tuple[dict, list[dict]] | None:
    """verify's records by registry id and the build's full packs, or None
    when either file cannot be read (the step that writes it failed)."""
    try:
        verify = json.loads(Path(destinations_file).read_text())
        packs = read_pack_counts(counts_file)
    except (OSError, ValueError) as exc:
        print(f"  unreadable counts ({exc})")
        return None
    if not isinstance(verify, dict):
        print(f"  unreadable counts ({destinations_file} holds no record per platform)")
        return None
    return verify, packs


def _platform_agrees(record: dict, pack: dict) -> bool:
    """One platform's verify record against the pack built for it, printed."""
    label, ok = record["label"], True
    if record["core_files"] != pack["core_files"]:
        # The cores' share: the base check passed RomM while verify
        # counted 412 core files and game data and the pack held 60.
        print(
            f"  {label}: MISMATCH core files verify "
            f"{record['core_files']} != pack {pack['core_files']}"
        )
        ok = False
    v_ok, v_total, p_ok, p_total = record["ok"], record["total"], pack["ok"], pack["total"]
    if v_total != p_total:
        print(f"  {label}: MISMATCH total verify {v_total} != pack {p_total}")
        return False
    if p_ok == v_ok:
        print(f"  {label}: verify {v_ok}/{v_total} == pack {p_ok}/{p_total} OK")
        return ok
    # Both ways are a disagreement. A pack exclusion never covers a file
    # verify counts OK: an existence platform ships a file whose hash
    # disagrees, and a hash platform's verify reports it untested, so the
    # counts can only differ by a defect.
    print(
        f"  {label}: MISMATCH pack {p_ok}/{p_total} OK "
        f"({pack['unsafe_excluded']} unsafe excluded) != verify {v_ok}/{v_total}"
    )
    return False


def compare_counts(verify: dict, packs: list[dict], released: set[str] | None = None) -> bool:
    """Each platform's verify record against the full pack built for it.

    Both sides are keyed by registry id: *verify* as verify.py --destinations
    writes it, *packs* as generate_pack.py --counts does. *released* holds
    the registry ids of the platforms with a release pack. verify judges
    every platform, the build only those: a platform outside it has no pack
    to compare, which is no failure.
    """
    all_ok = True
    if not verify or not packs:
        # Nothing read is nothing compared: a build that recorded no pack
        # would otherwise pass the check without a single platform in it.
        print(f"  parsed {len(verify)} verify and {len(packs)} pack results: nothing to compare")
        all_ok = False
    pack_of = {platform: pack for pack in packs for platform in pack["platforms"]}
    for pack in sorted(packs, key=lambda p: p["label"]):
        if not any(platform in verify for platform in pack["platforms"]):
            print(f"  {pack['label']}: pack with no verify result")
            all_ok = False
    for platform, record in sorted(verify.items(), key=lambda item: (item[1]["label"], item[0])):
        if platform in pack_of:
            all_ok = _platform_agrees(record, pack_of[platform]) and all_ok
        elif released is not None and platform not in released:
            print(f"  {record['label']}: {record['ok']}/{record['total']} "
                  "(no release pack, served by the installer)")
        else:
            print(f"  {record['label']}: MISSING pack: verify judged "
                  f"{record['ok']}/{record['total']} but the build wrote no pack for it")
            all_ok = False
    return all_ok


def check_consistency(
    destinations_file: str, counts_file: str, released: set[str] | None = None,
) -> bool:
    """Verify that check counts match between verify and pack for each platform."""
    print(f"\n--- {step_title(STEP_LABELS['consistency'])} ---")
    records = read_records(destinations_file, counts_file)
    all_ok = records is not None and compare_counts(*records, released)
    status = "OK" if all_ok else "FAILED"
    print(f"--- {step_title(STEP_LABELS['consistency'])}, counts: {status} ---")
    return all_ok


def check_pack_destinations(
    destinations_file: str, counts_file: str, platforms_dir: str = PLATFORMS_DIR,
) -> bool:
    """Compare the paths verify credits with the members of each archive.

    Equal counts hid a file credited on one side and another written on the
    other. The trees and the notes are the archive's own: a tree member is
    set aside when its path and size are the cached file's and verify does
    not credit the path.
    """
    import zipfile

    print(f"\n--- {step_title(STEP_LABELS['consistency'])}, destinations ---")
    records = read_records(destinations_file, counts_file)
    if records is None:
        return False
    credited_by, packs = records
    if not packs:
        print("  no archive in the pack counts")
        return False
    all_ok = True
    for pack in sorted(packs, key=lambda p: p["label"]):
        label = pack["label"]
        names = [platform for platform in pack["platforms"] if platform in credited_by]
        if not names:
            print(f"  {label}: no verify destinations")
            all_ok = False
            continue
        entry = credited_by[names[0]]
        credited = set(entry["pack_destinations"])
        trees = compare.tree_members(entry["platform"], platforms_dir)
        with zipfile.ZipFile(pack["archive"]) as zf:
            written = {
                info.filename for info in zf.infolist()
                if not info.is_dir()
                and not is_pack_note(info.filename)
                and not (
                    trees.get(info.filename) == info.file_size
                    and info.filename not in credited
                )
            }
        lines = compare.set_difference_lines(label, credited, written)
        if lines:
            print("\n".join(lines))
            all_ok = False
        else:
            print(f"  {label}: {len(credited)} paths, the same on both sides")
    return all_ok
