"""Which options the installer refuses beside each other, and why."""
from __future__ import annotations

import argparse
from collections.abc import Collection

from installer.invocation import LISTING_FLAGS, listings_given

# --source truth, named as one option among the others.
SOURCE_TRUTH = "--source=truth"


def given_options(args: argparse.Namespace) -> set[str]:
    """The options of a run that the combination rules read, by name."""
    given = {flag for flag, on in (
        ("--json", args.json), ("--find", bool(args.find)), ("--standalone", args.standalone),
        ("--emulator", args.emulator), ("--region", args.region),
        ("--one-per-slot", args.one_per_slot), ("--core", args.core), ("--system", args.system),
        ("--for-games", args.for_games is not None), ("--declared-only", args.declared_only),
        (SOURCE_TRUTH, args.source == "truth"), ("--tui", args.tui), ("--target", args.target),
        ("--installed-cores", args.installed_cores), ("--no-game-data", args.no_game_data),
        ("--all-files", args.all_files), ("--check", args.check), ("--events", args.events),
    ) if on}
    return given | set(listings_given(args))


def combination_refusals(given: Collection[str]) -> list[str]:
    """Every refusal the options given meet, in the order a run says them.
    --one-per-slot, --standalone, --source truth and --find are each held
    equal to the pack builder's own option, so a choice the builder refuses
    beside it is refused here."""
    def has(*flags: str) -> bool:
        return any(flag in given for flag in flags)

    listing = has(*(flag for flag, _attr in LISTING_FLAGS))
    truth = SOURCE_TRUTH in given
    find = "--find" in given
    rules = (
        (has("--json") and not find, "--json applies to --find"),
        (has("--standalone") and not has("--emulator"),
         "--standalone applies to --emulator: it picks that emulator's standalone build"),
        (has("--standalone") and has("--region", "--one-per-slot", "--core", "--system"),
         "--standalone installs each emulator's standalone build whole, which "
         "--region, --one-per-slot, --core and --system do not narrow"),
        (has("--one-per-slot") and has("--system", "--emulator", "--for-games"),
         "--one-per-slot decides each slot over the whole list, which --system, "
         "--emulator and --for-games narrow first"),
        (has("--one-per-slot") and has("--declared-only"),
         "--one-per-slot ranks the files cores load too, which --declared-only leaves out"),
        (truth and has("--system", "--core", "--emulator", "--region", "--one-per-slot",
                       "--for-games", "--declared-only", "--target", "--installed-cores",
                       "--no-game-data"),
         "--source truth installs what the emulator profiles prove is read, over "
         "the whole list: run it without other choices"),
        (truth and has("--tui"), "the full-screen interface has no choice for --source truth"),
        (find and (truth or has("--system", "--core", "--emulator", "--region", "--one-per-slot",
                                "--for-games", "--declared-only", "--no-game-data", "--target",
                                "--installed-cores", "--all-files", "--standalone")),
         "--find picks one file by its hash: run it without other choices"),
        (find and (listing or has("--check", "--tui")),
         "--find installs or names one file, not a listing, a check or the full screen"),
        (has("--json") and has("--events"), "--json and --events each write JSON on stdout"),
        (listing and (truth or has("--one-per-slot", "--standalone")),
         "a listing prints the whole list, which --one-per-slot, --standalone and "
         "--source do not narrow"),
    )
    return [reason for refused, reason in rules if refused]


def adds_refusal(option: str, given: Collection[str]) -> bool:
    """Whether the option, added to those given, meets a refusal they did not."""
    without = set(given) - {option}
    return bool(set(combination_refusals(without | {option}))
                - set(combination_refusals(without)))
