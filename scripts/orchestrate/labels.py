"""The pipeline's steps in run order, and the titles the run prints for them."""

from __future__ import annotations

# Every step in run order, by its results key. The position and the total
# printed during the run come from this list: hand-written "N/8" labels
# counted 8 steps in a run of 24, and the eighth came before 8b. The summary
# prints the same labels the run printed, so a FAILED row is found in the
# log by its number.
STEP_LABELS: dict[str, str] = {
    "validate_schemas": "0 validate schemas",
    "generate_db": "1 generate database",
    "provenance": "1b provenance report",
    "romset_recipes": "1c romset recipes",
    "refresh_data": "2 refresh data directories",
    "mame_hashes": "2a refresh MAME hashes",
    "fbneo_hashes": "2a2 refresh FBNeo hashes",
    "check_buildbot": "2b check buildbot system",
    "check_release_assets": "2b2 check release assets",
    "generate_truth": "2c generate truth",
    "diff_truth": "2d diff truth",
    "export_native": "2e export native",
    "verify": "3 verify all platforms",
    "identity": "3a file identity",
    "slots": "3b slot arbitration",
    "generate_packs": "4 generate packs",
    "generate_manifests": "4b generate install manifests",
    "generate_target_manifests": "4c generate target manifests",
    "bundled_only": "4d copies only an emulator install provides",
    "games_index": "4e games index",
    "consistency": "5 consistency check",
    "pack_integrity": "6 pack integrity",
    "generate_readme": "7 generate readme",
    "generate_site": "8 generate site",
    "render_site": "8b render site",
}
_KEY_BY_LABEL = {label: key for key, label in STEP_LABELS.items()}


def step_number(key: str) -> str:
    """The number a step's progress lines carry ("2b2", "4d")."""
    return STEP_LABELS[key].split(" ", 1)[0]


def step_title(label: str) -> str:
    """What the run prints for a label: its name and its place in the run.

    A second command of one step ("2c generate truth (export model)") is
    printed as written.
    """
    key = _KEY_BY_LABEL.get(label)
    if key is None:
        return label
    return f"{label} [{list(STEP_LABELS).index(key) + 1}/{len(STEP_LABELS)}]"


def skip_notice(key: str, reason: str = "") -> None:
    """The line a step that does not run prints in place of its output."""
    because = f" ({reason})" if reason else ""
    print(f"\n--- {step_title(STEP_LABELS[key])}: SKIPPED{because} ---")
