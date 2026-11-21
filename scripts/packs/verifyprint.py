"""A verify run's results printed, as text or JSON, then held to --strict."""

from __future__ import annotations

import argparse
import json

from packs.report import print_emulator_result, print_platform_result
from packs.strictgate import exit_if_strict_emulator
from packs.verifyoutput import json_details, write_pack_destinations
from packs.verifyplatforms import PlatformResults
from packs.verifysummary import overall_summary


def print_emulator_run(args: argparse.Namespace, result: dict) -> None:
    """An --emulator or --system result, as text or JSON, then the strict gate."""
    if args.json:
        result["details"] = json_details(result["details"], args.verbose)
        print(json.dumps(result, indent=2))
    else:
        print_emulator_result(result, verbose=args.verbose)
    exit_if_strict_emulator(args.strict, result)


def print_platform_results(args: argparse.Namespace, results: PlatformResults) -> None:
    group_results = results.group_results
    if not args.json:
        for result, group in group_results:
            print_platform_result(result, group, verbose=args.verbose)
            print()
        if len(group_results) > 1:
            print(overall_summary(group_results))

    if args.destinations:
        write_pack_destinations(args.destinations, results.groups, group_results)

    if args.json:
        for r in results.all_results.values():
            r["details"] = json_details(r["details"], args.verbose)
        print(json.dumps(results.all_results, indent=2))
