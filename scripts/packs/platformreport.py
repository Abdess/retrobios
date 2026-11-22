"""The lines a platform pack build prints: its counts, its notices and each file it could not serve."""

from __future__ import annotations

from typing import TYPE_CHECKING

from packs.datatrees import uncached_warning

if TYPE_CHECKING:
    from packs.platformpack import PlatformPackOutcome, SplitOutcome

_STATUS_LABELS = {"untested": "UNTESTED", "excluded": "EXCLUDED", "missing": "MISSING"}


def _print_pack_counts(outcome: PlatformPackOutcome) -> None:
    """Print the pack's counts line.

    The pipeline's consistency check reads the same counts as data
    (packs.packcounts), never this line.
    """
    statuses = list(outcome.file_status.values())
    files_ok = statuses.count("ok")
    files_untested = statuses.count("untested")
    files_excluded = statuses.count("excluded")
    files_miss = statuses.count("missing")

    parts = [f"{files_ok}/{len(statuses)} files OK"]
    if files_untested:
        parts.append(f"{files_untested} untested")
    if files_excluded:
        parts.append(f"{files_excluded} unsafe excluded")
    if files_miss:
        parts.append(f"{files_miss} missing")
    zip_path, total_files, core_count = outcome.zip_path, outcome.total_files, outcome.core_count
    mode = outcome.verification_mode
    if outcome.source == "platform":
        print(
            f"  {zip_path}: {total_files} files packed (platform baseline only), "
            f"{', '.join(parts)} [{mode}]"
        )
    elif outcome.source == "truth":
        print(
            f"  {zip_path}: {total_files} files packed (ground truth only), "
            f"{core_count} from emulator profiles [{mode}]"
        )
    else:
        tree_count = outcome.tree_count
        baseline = total_files - core_count - tree_count
        trees = f"{tree_count} in core data trees + " if tree_count else ""
        print(
            f"  {zip_path}: {total_files} files packed ({baseline} baseline + "
            f"{trees}{core_count} from cores), {', '.join(parts)} [{mode}]"
        )


def print_platform_pack(outcome: PlatformPackOutcome) -> None:
    """Print what build_platform_pack came to, or why it built nothing."""
    if outcome.refusal:
        print(f"  WARNING: {outcome.refusal}")
        return
    if outcome.slot_undecidable:
        print(
            f"  {len(outcome.slot_undecidable)} slot(s) with no declared order: "
            f"every candidate kept"
        )
    for ref_key, local_path in outcome.uncached:
        print(uncached_warning(ref_key, local_path))
    _print_pack_counts(outcome)
    for line in outcome.left_out:
        print(f"  {line}")
    for key, reason in sorted(outcome.file_reasons.items()):
        label = _STATUS_LABELS.get(outcome.file_status.get(key, ""), "DISCREPANCY")
        print(f"  {label}: {key}: {reason}")
    for note in sorted(outcome.core_discrepancies):
        print(f"  DISCREPANCY: {note}")


def print_split_packs(outcome: SplitOutcome) -> None:
    """Print the core game data a --split run left out, then each part."""
    for line in outcome.left_out:
        print(f"  {line}")
    for part in outcome.parts:
        print_platform_pack(part)
