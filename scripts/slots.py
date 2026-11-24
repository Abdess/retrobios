"""Who decides what goes at a destination.

A destination is a slot. Two layers can claim it: the platform YAML, scraped
from what the frontend declares, which can pin another file than the emulator
reads, and the emulator profile, read from the emulator's own source. Until this
module existed nothing compared the two: the builder resolves the platform
entry first and drops the profile entry on a bare filename match, so a profile
that names the right file for a slot could never win and never even be heard.

Claims are keyed by destination, folded to one case only where the platform's
filesystem folds it. Dolphin declares three IPL.bin separated only by their
path, and each is its own slot. A profile claim resting on a bare filename
proves nothing about content and contests no slot.

The pack builder, the install manifest and verify read slot_choices() through
pack_overrides(). arbitrate() states the same decision for one conflict and
feeds the report this module prints.
"""

from __future__ import annotations


from core.cli import add_repo_inputs
from model.cliargs import platform_arg, require_platform
from model.database import load_database
from model.profiles import load_emulator_profiles
from model.registry import list_registered_platforms, load_data_dir_registry
from model.targets import target_scope

from packs.slotreport import report_json, report_lines
from packs.slotscan import decide_platforms, scan_platforms


def main() -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Report destinations where an emulator profile contradicts "
        "the file a platform baseline would ship.",
    )
    parser.add_argument(
        "--platform", "-p", type=platform_arg,
        help="one platform instead of all",
    )
    add_repo_inputs(parser, "db", "platforms", "emulators")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument(
        "--target", "-t", help="judge only the cores a hardware target builds",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit 1 on any contested destination or destination declared twice; "
        "without it the run reports them and exits 0",
    )
    args = parser.parse_args()
    from model.cliargs import work_from_repo_root

    work_from_repo_root(args, parser, ["db", "platforms_dir", "emulators_dir"])

    import contextlib

    from packs.datadirs import hold_data_dirs

    # Claims resolve against data/: the trees stay put until the process
    # ends, which releases the hold.
    held = contextlib.ExitStack()
    data_registry = load_data_dir_registry(args.platforms_dir)
    hold_data_dirs(held, data_registry)

    db = load_database(args.db)
    profiles = load_emulator_profiles(args.emulators_dir)
    if args.platform:
        require_platform(args.platform, args.platforms_dir)
    names = (
        [args.platform]
        if args.platform
        else list_registered_platforms(args.platforms_dir)
    )
    target_cores, names = target_scope(
        names, args.target, args.platforms_dir, is_all=not args.platform
    )

    found, collided = scan_platforms(
        names, profiles, db, args.platforms_dir, target_cores, data_registry,
    )

    decided = decide_platforms(found, args.platforms_dir)
    if args.json:
        print(json.dumps(report_json(decided, collided), indent=2))
    else:
        for line in report_lines(decided, collided, args.strict):
            print(line)

    return 1 if ((found or collided) and args.strict) else 0


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
