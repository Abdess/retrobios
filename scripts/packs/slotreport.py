"""The slots report: one line per contested slot, its totals and its JSON form."""

from __future__ import annotations

from model.platforms import load_platform_config
from packs.slots import ADDRESSEE, Claim, Conflict, Decision, arbitrate
from resolve.collisions import Collision
from resolve.localfile import resolution_is_hash_exact
from resolve.nativemode import platform_mode


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


def report_json(
    found: dict[str, list[Conflict]], collided: dict[str, list[Collision]],
) -> dict:
    """The --json document: every contested slot and every doubled destination."""
    # --strict gates on collisions too, so a document that carries only
    # conflicts hands a consumer an empty answer and a non-zero exit.
    return {
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


def report_lines(
    found: dict[str, list[Conflict]], collided: dict[str, list[Collision]],
    platforms_dir: str, strict: bool,
) -> list[str]:
    """The text report: each decision with its ground, then the totals."""
    lines: list[str] = []
    fixable = 0
    for platform, conflicts in found.items():
        config = load_platform_config(platform, platforms_dir)
        mode = platform_mode(config)
        lines.append(f"{platform}: {len(conflicts)} contradicted [{mode}]")
        for conflict in conflicts:
            decision = arbitrate(conflict, mode, rule=config.get("hash_rule", ""))
            fixable += decision.serves_both
            lines.append(f"  {format_decision(decision)}")
    total = sum(len(c) for c in found.values())
    for platform, collisions in collided.items():
        lines.append(f"{platform}: {len(collisions)} destinations declared twice")
        lines.extend(f"  {format_collision(collision)}" for collision in collisions)
    # The totals close the run, collisions counted: printed before that
    # section, they were not the last word and left it out.
    doubled = sum(len(c) for c in collided.values())
    lines.append(
        f"\n{total} contested destinations. {fixable} the pack settles on "
        f"its own, {total - fixable} follow the platform's list. "
        f"{doubled} destinations declared twice."
    )
    if not strict and (total or doubled):
        lines.append(
            "Reported, not failed: the remainder changes when the platform's "
            "list does, which no build can do. Use --strict to gate on them."
        )
    return lines
