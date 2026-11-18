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


from model.cliargs import platform_arg, require_platform
from model.database import load_database
from model.platforms import load_platform_config
from core.ziptools import build_zip_contents_index
from model.profiles import load_emulator_profiles
from model.registry import list_registered_platforms, load_data_dir_registry
from model.targets import build_target_cores_cache
from resolve.localfile import resolution_is_hash_exact
from resolve.standalone import standalone_set as platform_standalone_set

from packs.slots import ADDRESSEE, Claim, Conflict, Decision, arbitrate, find_conflicts
from resolve.collisions import Collision, find_collisions


def _pinned_elsewhere(claims: list[Claim], winner: str | None) -> set[str]:
    """Emulators that pin content the served file does not carry."""
    return {
        c.emulator for c in claims
        if c.emulator and c.local_path != winner and resolution_is_hash_exact(c.status)
    }


def format_decision(decision: Decision) -> str:
    """One line naming the contested slot, the winner and the ground for it."""
    conflict = decision.conflict
    if decision.serves_both:
        winner = decision.winner.local_path
        # A claim that only matched a path is answered by whatever file sits
        # there. Only one that pins content can be left wanting.
        pinned_elsewhere = _pinned_elsewhere(conflict.profile_claims, winner)
        served = sorted({
            c.emulator for c in conflict.profile_claims if c.emulator
        } - pinned_elsewhere)
        others = sorted(pinned_elsewhere)
        line = (
            f"{conflict.destination}: serve {winner} "
            f"({', '.join(served) or 'profile'}): the frontend only "
            "checks the path, so both are satisfied"
        )
        if others:
            # One path holds one file: an emulator pinning another is not served.
            line += f"; {', '.join(others)} expected another file"
        return line
    if decision.reason == ADDRESSEE:
        return (
            f"{conflict.destination}: serve {decision.winner.local_path}, "
            "the pack answers to the emulator"
        )
    rejected = ", ".join(
        f"{path}, the file {', '.join(emulators) or 'the profile'} reads"
        for path, emulators, _status in conflict.files_read()
    )
    return (
        f"{conflict.destination}: keep {decision.winner.local_path}, the frontend "
        f"verifies content and would reject {rejected}"
    )


def _collision_json(collision: Collision) -> dict:
    return {
        "destination": collision.destination,
        "resolved": list(collision.resolved),
        "shipped": collision.shipped,
        "declarations": [
            {"system": system, "name": entry.get("name", ""), "file": local}
            for system, (entry, local) in zip(collision.systems, collision.declarations)
        ],
    }


def format_collision(collision: Collision) -> str:
    """One line naming the destination, which system declares which file,
    and the one the pack ships there."""
    owners: dict[str, list[str]] = {}
    for system, (_entry, local) in zip(collision.systems, collision.declarations):
        if local and system not in owners.setdefault(local, []):
            owners[local].append(system)
    parts = [
        f"{path} ({', '.join(owners[path])}) "
        + ("packed" if path == collision.shipped else "left out")
        for path in collision.resolved
    ]
    return f"{collision.destination}: " + ", ".join(parts)


def format_conflict(conflict: Conflict) -> str:
    """One line per conflict, naming both answers and who gave them."""
    emus = ", ".join(conflict.emulators) or "profile"
    return (
        f"{conflict.destination}: pack ships {conflict.platform_claim.local_path} "
        f"({conflict.platform_claim.status}), {emus} says "
        f"{conflict.profile_claims[0].local_path} "
        f"({conflict.profile_claims[0].status})"
    )


def scan_platform(
    platform: str, profiles: dict, db: dict, platforms_dir: str = "platforms",
    target_cores: set[str] | None = None,
) -> list[Conflict]:
    """Conflicts on one platform, using the cores that platform actually runs."""
    from model.platforms import load_platform_config
    from resolve.cores import resolve_platform_cores

    config = load_platform_config(platform, platforms_dir)
    keys = resolve_platform_cores(config, profiles, target_cores=target_cores)
    relevant = {k: profiles[k] for k in keys if k in profiles}
    # The same evidence the builder and the verifier resolve with: without
    # the ZIP index and the data-directory registry the arbitration judged
    # with less than the tools that read its verdict.
    return find_conflicts(
        config,
        relevant,
        db,
        config.get("base_destination", ""),
        platform_standalone_set(config),
        build_zip_contents_index(db),
        load_data_dir_registry(platforms_dir),
    )


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
    parser.add_argument(
        "--db", default="database.json",
        help="database file to read (default: %(default)s)",
    )
    parser.add_argument(
        "--platforms-dir", default="platforms",
        help="platform YAML directory (default: %(default)s)",
    )
    parser.add_argument(
        "--emulators-dir", default="emulators",
        help="emulator profile directory (default: %(default)s)",
    )
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

    from model.registry import load_data_dir_registry
    from packs.datadirs import hold_data_dirs

    # Claims resolve against data/: the trees stay put until the process
    # ends, which releases the hold.
    held = contextlib.ExitStack()
    hold_data_dirs(held, load_data_dir_registry(args.platforms_dir))

    db = load_database(args.db)
    profiles = load_emulator_profiles(args.emulators_dir)
    if args.platform:
        require_platform(args.platform, args.platforms_dir)
    names = (
        [args.platform]
        if args.platform
        else list_registered_platforms(args.platforms_dir)
    )
    target_cores: dict[str, set[str] | None] = {}
    if args.target:
        try:
            target_cores, names = build_target_cores_cache(
                names, args.target, args.platforms_dir, is_all=not args.platform
            )
        except (FileNotFoundError, ValueError) as exc:
            parser.error(str(exc))

    found: dict[str, list[Conflict]] = {}
    collided: dict[str, list[Collision]] = {}
    for name in names:
        conflicts = scan_platform(
            name, profiles, db, args.platforms_dir, target_cores.get(name)
        )
        if conflicts:
            found[name] = conflicts
        collisions = find_collisions(
            load_platform_config(name, args.platforms_dir),
            db,
            build_zip_contents_index(db),
            load_data_dir_registry(args.platforms_dir),
        )
        if collisions:
            collided[name] = collisions

    if args.json:
        # --strict gates on collisions too, so a document that carries only
        # conflicts hands a consumer an empty answer and a non-zero exit.
        payload = {
            "conflicts": {
                platform: [
                    {
                        "destination": c.destination,
                        "ships": c.platform_claim.local_path,
                        "ships_evidence": c.platform_claim.status,
                        "emulators": c.emulators,
                        "expected": [
                            {"file": path, "evidence": status, "emulators": emulators}
                            for path, emulators, status in c.files_read()
                        ],
                    }
                    for c in conflicts
                ]
                for platform, conflicts in found.items()
            },
            "collisions": {
                platform: [_collision_json(c) for c in platform_collisions]
                for platform, platform_collisions in collided.items()
            },
        }
        print(json.dumps(payload, indent=2))
    else:
        fixable = 0
        for platform, conflicts in found.items():
            config = load_platform_config(platform, args.platforms_dir)
            mode = config.get("verification_mode", "existence")
            print(f"{platform}: {len(conflicts)} contradicted [{mode}]")
            for conflict in conflicts:
                decision = arbitrate(conflict, mode, rule=config.get("hash_rule", ""))
                fixable += decision.serves_both
                print(f"  {format_decision(decision)}")
        total = sum(len(c) for c in found.values())
        for platform, collisions in collided.items():
            print(f"{platform}: {len(collisions)} destinations declared twice")
            for collision in collisions:
                print(f"  {format_collision(collision)}")
        # The totals close the run, collisions counted: printed before that
        # section, they were not the last word and left it out.
        doubled = sum(len(c) for c in collided.values())
        print(
            f"\n{total} contested destinations. {fixable} the pack settles on "
            f"its own, {total - fixable} follow the platform's list. "
            f"{doubled} destinations declared twice."
        )
        if not args.strict and (total or doubled):
            print(
                "Reported, not failed: the remainder changes when the platform's "
                "list does, which no build can do. Use --strict to gate on them."
            )

    return 1 if ((found or collided) and args.strict) else 0


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
