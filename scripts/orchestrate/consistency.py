"""Step 5 on the full packs: verify's counts and paths against what the build wrote."""

from __future__ import annotations

from pathlib import Path

from core.paths import PLATFORMS_DIR
from orchestrate import compare
from packs.archive import is_pack_note
from orchestrate.labels import STEP_LABELS, step_title
from orchestrate.reports import (
    match_key,
    parse_pack_counts,
    parse_pack_exclusions,
    parse_pack_extras,
    parse_pack_paths,
    parse_verify_counts,
    parse_verify_extras,
)


def check_consistency(
    verify_output: str, pack_output: str, released: set[str] | None = None,
) -> bool:
    """Verify that check counts match between verify and pack for each platform.

    *released* holds the identities of the platforms with a release pack
    (release_pack_keys). verify judges every platform, the build only those:
    a platform outside it has no pack to compare, which is no failure.
    """
    v = parse_verify_counts(verify_output)
    p = parse_pack_counts(pack_output)
    excluded = parse_pack_exclusions(pack_output)
    verify_extras = parse_verify_extras(verify_output)
    pack_extras = parse_pack_extras(pack_output)

    print(f"\n--- {step_title(STEP_LABELS['consistency'])} ---")
    all_ok = True
    if not v or not p:
        # Nothing parsed is nothing compared: a changed output format would
        # otherwise pass the check without a single platform in it.
        print(f"  parsed {len(v)} verify and {len(p)} pack results: nothing to compare")
        all_ok = False
    for p_label in sorted(p):
        if not any(match_key(p_label) & match_key(v_label) for v_label in v):
            print(f"  {p_label}: pack with no verify result")
            all_ok = False

    for v_label, (v_ok, v_total) in sorted(v.items()):
        # Match by normalized name overlap.  Platform display labels and
        # registry IDs legitimately differ in punctuation and spacing
        # (notably ``MiSTer FPGA`` vs ``misterfpga``).
        p_match = None
        v_names = match_key(v_label)
        for p_label in p:
            if v_names & match_key(p_label):
                p_match = p_label
                break

        if (
            p_match
            and p_match in pack_extras
            and v_label in verify_extras
            and verify_extras[v_label] != pack_extras[p_match]
        ):
            # The cores' share: the base check passed RomM while verify
            # counted 412 core files and game data and the pack held 60.
            print(
                f"  {v_label}: MISMATCH core files verify "
                f"{verify_extras[v_label]} != pack {pack_extras[p_match]}"
            )
            all_ok = False
        if p_match:
            p_ok, p_total = p[p_match]
            p_excluded = excluded.get(p_match, 0)
            if v_total != p_total:
                print(f"  {v_label}: MISMATCH total verify {v_total} != pack {p_total}")
                all_ok = False
            elif p_ok == v_ok:
                print(
                    f"  {v_label}: verify {v_ok}/{v_total} == pack {p_ok}/{p_total} OK"
                )
            else:
                # Both ways are a disagreement. A pack exclusion never covers
                # a file verify counts OK: an existence platform ships a file
                # whose hash disagrees, and a hash platform's verify reports
                # it untested, so the counts can only differ by a defect.
                print(
                    f"  {v_label}: MISMATCH pack {p_ok}/{p_total} OK "
                    f"({p_excluded} unsafe excluded) != verify {v_ok}/{v_total}"
                )
                all_ok = False
        elif released is not None and not (v_names & released):
            print(f"  {v_label}: {v_ok}/{v_total} (no release pack, served by the installer)")
        else:
            print(f"  {v_label}: MISSING pack: verify judged {v_ok}/{v_total} "
                  "but the build wrote no pack for it")
            all_ok = False

    status = "OK" if all_ok else "FAILED"
    print(f"--- {step_title(STEP_LABELS['consistency'])}, counts: {status} ---")
    return all_ok


def check_pack_destinations(
    destinations_file: str, pack_output: str, platforms_dir: str = PLATFORMS_DIR,
) -> bool:
    """Compare the paths verify credits with the members of each archive.

    Equal counts hid a file credited on one side and another written on the
    other. The trees and the notes are the archive's own: a tree member is
    set aside when its path and size are the cached file's and verify does
    not credit the path.
    """
    import json
    import zipfile

    print(f"\n--- {step_title(STEP_LABELS['consistency'])}, destinations ---")
    try:
        credited_by = json.loads(Path(destinations_file).read_text())
    except (OSError, ValueError) as exc:
        print(f"  no destinations from verify ({exc})")
        return False
    paths = parse_pack_paths(pack_output)
    if not paths:
        print("  no archive named in the pack output")
        return False
    all_ok = True
    for label, zip_path in sorted(paths.items()):
        names = [n for n in credited_by if match_key(n) & match_key(label)]
        if not names:
            print(f"  {label}: no verify destinations")
            all_ok = False
            continue
        entry = credited_by[names[0]]
        credited = set(entry["pack_destinations"])
        trees = compare.tree_members(entry["platform"], platforms_dir)
        with zipfile.ZipFile(zip_path) as zf:
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
