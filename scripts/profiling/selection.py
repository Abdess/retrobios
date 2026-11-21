"""The profiles a profile pass selects from its command line."""

from __future__ import annotations

import argparse
import sys

from core.cli import suggest_names
from model.profiles import ProfileSelectionError, is_emulator, resolve_profile_name
from model.systems import norm_system_id, system_index
from profiling.worktree import branch_profiles, project_base


def select_profiles(profiles: dict, args: argparse.Namespace) -> dict:
    """Profiles matching the selection flags."""
    if args.changed or args.added:
        base = args.base or project_base()
        names = branch_profiles(args.emulators_dir, base, args.added)
        selected = {name: profiles[name] for name in names if name in profiles}
        if not selected:
            verb = "adds" if args.added else "adds or edits"
            print(f"the branch {verb} no profile against {base}", file=sys.stderr)
        return selected
    if args.emulator:
        requested = [args.emulator] if isinstance(args.emulator, str) else args.emulator
        try:
            names = [
                resolve_profile_name(name, profiles, "python scripts/verify.py --list-emulators")
                for name in requested
            ]
        except ProfileSelectionError as exc:
            raise SystemExit(f"ERROR: {exc}") from None
        return {name: profiles[name] for name in dict.fromkeys(names)}

    # --system matches as verify.py --list-systems lists and --system selects:
    # by normalized id, so `saturn` reaches the profiles declaring sega-saturn.
    wanted_system = norm_system_id(args.system) if args.system else None
    selected = {}
    for name, profile in sorted(profiles.items()):
        if not is_emulator(profile):
            continue
        if wanted_system and wanted_system not in {
            norm_system_id(str(s)) for s in profile.get("systems") or []
        }:
            continue
        if args.type_ and profile.get("type") != args.type_:
            continue
        if args.stale_before:
            profiled = str(profile.get("profiled_date") or "")
            if not profiled or profiled >= args.stale_before:
                continue
        selected[name] = profile
        if args.limit and len(selected) >= args.limit:
            break
    if not selected:
        # A misspelt filter selected nothing and the run said nothing: it
        # read as "no profile of that system needs a re-read".
        filters = ", ".join(
            f"{flag} {value}" for flag, value in (
                ("--system", args.system), ("--type", args.type_),
                ("--stale-before", args.stale_before),
            ) if value
        )
        hint = ""
        if args.system:
            # Suggested from the spellings the named listing prints.
            systems = sorted(spelling for spelling, _ in system_index(profiles).values())
            hint = " " + suggest_names([args.system], systems, "python scripts/verify.py --list-systems")
        elif args.type_:
            kinds = sorted({str(p.get("type")) for p in profiles.values() if p.get("type")})
            hint = f" Types: {', '.join(kinds)}."
        raise SystemExit(f"ERROR: no profile matches {filters or 'the selection'}.{hint}")
    return selected


def version_selection(args: argparse.Namespace, profiles: dict) -> dict:
    """--all reaches the alias and test profiles too: each states a version."""
    if args.all and not (args.system or args.type_ or args.stale_before or args.limit):
        return dict(sorted(profiles.items()))
    return select_profiles(profiles, args)
