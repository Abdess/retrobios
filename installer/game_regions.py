"""Which BIOS regions the games on a card need, and when a rule keeps every region."""

from __future__ import annotations

from pathlib import Path

from installer.game_files import GameFacts, SystemData, _suffix
from installer.regions import WORLD_REGION, _region_comparable


def core_regions(facts: GameFacts, system_id: str, system: SystemData,
                 profile: str) -> frozenset | None:
    """The regions a game is proven to need under one core: the catalog's
    tag of the content matched, the region the core's own readers compute
    from its bytes, or both when they agree. None for no proof or for two
    proofs that disagree."""
    if facts.system != system_id:
        return None
    core = system.cores.get(profile) or {}
    header: frozenset | None = None
    order = [name for name in core.get("order") or [] if isinstance(name, str)]
    all_read = bool(order)
    for name in order:
        value = facts.readings.get(name)
        if value is None:
            all_read = False
            continue
        if isinstance(value, frozenset):
            header = value
            break
    otherwise = core.get("otherwise")
    if header is None and all_read and isinstance(otherwise, list) and otherwise:
        header = frozenset(str(region) for region in otherwise)
    proofs = [proof for proof in (facts.dat_regions, header) if proof]
    if not proofs:
        return None
    if len(proofs) == 2 and not any(_region_comparable(a, b)
                                    for a in proofs[0] for b in proofs[1]):
        return None
    return frozenset().union(*proofs)


# Cases of games/regions.yml a proven region does not settle whatever the
# game: device state (an option, a per-game setting) or the code itself.
_ALWAYS_WIDE = ("always", "option", "user-state")


def region_rule_keeps_all(rule: dict | None, games: list[GameFacts]) -> bool:
    """Whether the core keeps every region whatever its games prove: no rule
    read at its pin, or one of the cases games/regions.yml names (a region
    option, an override BIOS, a fallback across regions, a disc database)."""
    if not isinstance(rule, dict):
        return True
    for case in rule.get("keep_all_regions") or []:
        if not isinstance(case, dict):
            return True
        name, condition = case.get("case"), case.get("condition")
        if condition in _ALWAYS_WIDE:
            return True
        if name == "first-disc-region":
            if any(_suffix(game.path.name) == ".m3u" for game in games):
                return True
        elif name not in ("multi-area-disc", "gamecube-unknown-region", "saturn-kr-ipl"):
            return True
    return False


def needed_regions(rule: dict, proofs: list[frozenset | None]) -> frozenset | None:
    """The regions the games of one core prove, routed as the core routes
    them, None when one game proves none."""
    if not proofs or any(proof is None for proof in proofs):
        return None
    routes = rule.get("routes") or {}
    needed = frozenset(str(routes.get(region, region))
                       for proof in proofs for region in proof or ())
    wide = {str(case.get("case")) for case in rule.get("keep_all_regions") or []
            if isinstance(case, dict)}
    if "saturn-kr-ipl" in wide and needed & {"asia-ntsc", "south-korea"}:
        return None
    return needed


def keep_regions(dests: list[str], entries: dict[str, dict], needed: frozenset,
                 region_free: set[str]) -> list[str]:
    """The files of a set the proven regions keep: every file with no region
    tag, a world or region-free file, and those whose tag a needed region
    matches. A needed region no file matches keeps the whole set."""

    def regions(dest: str) -> list[str]:
        entry = entries.get(dest) or {}
        if Path(dest).name.casefold() in region_free:
            return []
        tags = [str(r) for r in entry.get("regions") or []]
        return [] if WORLD_REGION in tags else tags

    tagged = {dest: regions(dest) for dest in dests if regions(dest)}
    for region in needed:
        if not any(_region_comparable(region, tag) for tags in tagged.values() for tag in tags):
            return list(dests)
    return [dest for dest in dests
            if dest not in tagged
            or any(_region_comparable(region, tag) for region in needed for tag in tagged[dest])]


def _region_kept(files: list[str], games: list[GameFacts], entries: dict[str, dict],
                 system: str, info: SystemData,
                 profile: str) -> tuple[list[str], bool, frozenset | None]:
    """The files of a set the games' regions keep, whether every region is
    kept, and the regions it was narrowed to (None when not narrowed)."""
    rule = info.rules.get(profile)
    region_free = {str(name).casefold() for name in (rule or {}).get("region_free") or []}
    tagged = any((entries.get(dest) or {}).get("regions") for dest in files)
    if not tagged:
        return list(files), False, None
    if region_rule_keeps_all(rule, games):
        return list(files), True, None
    proofs = [core_regions(game, system, info, profile) for game in games]
    needed = needed_regions(rule or {}, proofs)
    if needed is None:
        for game, proof in zip(games, proofs):
            if proof is None and not game.reason:
                game.reason = ("not_read" if not game.read
                               else "not_recognised" if not game.recognised
                               else "region_unknown")
        return list(files), True, None
    kept = keep_regions(files, entries, needed, region_free)
    if len(kept) < len(files):
        return kept, False, needed
    return kept, True, None
