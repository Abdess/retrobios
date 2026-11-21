"""Load and check games/regions.yml and games/extras.yml against the profiles.

    python scripts/game_rules.py            # check, print a summary
    python scripts/game_rules.py --json     # the summary as JSON

Both files name profiles and the files those profiles declare. A rule is
only as good as that link: a profile renamed, a file dropped from it, a
region slug the vocabulary does not know, a citation at a revision the
profile is not pinned to, or a header trigger asking a reader of
games/headers.yml for a value it never returns, and the installer would act
on a rule nothing backs. Each of those is an error here.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from core.cli import add_repo_inputs
from games.inputs import EXTRAS_FILE, HEADERS_FILE, REGIONS_FILE, load_yaml
from games.rulecheck import check
from games.rulesummary import summary
from model.profiles import load_emulator_profiles


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.splitlines()[0])
    parser.add_argument("--regions", type=Path, default=REGIONS_FILE,
                        help=f"region rules to check (default {REGIONS_FILE})")
    parser.add_argument("--extras", type=Path, default=EXTRAS_FILE,
                        help=f"extra-file rules to check (default {EXTRAS_FILE})")
    parser.add_argument("--headers", type=Path, default=HEADERS_FILE,
                        help=f"header readers the triggers name (default {HEADERS_FILE})")
    add_repo_inputs(parser, "emulators")
    parser.add_argument("--json", action="store_true", help="print the summary as JSON")
    args = parser.parse_args()
    from model.cliargs import work_from_repo_root

    work_from_repo_root(args, parser, ["regions", "extras", "headers", "emulators_dir"])

    regions = load_yaml(args.regions)
    extras = load_yaml(args.extras)
    errors = check(regions, extras, load_emulator_profiles(args.emulators_dir), load_yaml(args.headers))
    info = summary(regions, extras)
    if args.json:
        print(json.dumps({**info, "errors": errors}, indent=2))
    else:
        print(
            f"Region rules: {info['region_cores']} cores over {info['region_systems']} systems, "
            f"{len(info['cases'])} cases in {len(info['case_entries'])} entries"
        )
        for row in info["case_entries"]:
            print(f"  {row['case']:26} {row['system']:20} {row['profile']:22} {row['condition']}")
        print(f"Per-game extras: {info['extras']} entries over {len(info['extra_systems'])} systems")
        for error in errors:
            print(f"ERROR {error}")
    return 1 if errors else 0


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
