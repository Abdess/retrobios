"""Scraper for Lakka per-device core availability.

Sources (libretro/Lakka-LibreELEC, at the latest Lakka release tag):
  - packages/lakka/libretro_cores/package.mk -- LIBRETRO_CORES, then the
    EXCLUDE_LIBRETRO_CORES each PROJECT/DEVICE and OPENGLES_SUPPORT add
  - projects/<PROJECT>/options and projects/<PROJECT>/devices/<DEVICE>/options
    -- OPENGLES, which config/graphic turns into OPENGLES_SUPPORT

A Lakka RPi1 image carries neither beetle_psx nor mupen64plus_next: without
a target list, its pack shipped their firmware anyway.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone

import yaml

from . import BaseTargetScraper
from ..base_scraper import fetch_bytes, github_headers

PLATFORM_NAME = "lakka"

REPO = "libretro/Lakka-LibreELEC"
RAW_BASE = "https://raw.githubusercontent.com/" + REPO + "/{tag}"
API_BASE = "https://api.github.com/repos/" + REPO
CORES_MK = "packages/lakka/libretro_cores/package.mk"

_IF_RE = re.compile(r"^(if|elif)\s+\[\s+(.*?)\s+\];?\s*(?:then)?\s*$")
_TEST_RE = re.compile(r'^(!\s+)?"\$\{?(\w+)\}?"\s*(=|!=)\s*"?([^"\s]*)"?$')
_SET_RE = re.compile(r"^\s*-([nz])\s+\"\$\{?(\w+)\}?\"\s*$")
_ASSIGN_RE = re.compile(r'^(\w+)(\+?=)"([^"]*)"\s*$')


class ShellSubsetError(RuntimeError):
    """A construct the evaluator does not read decided a value it needs."""


def _condition(text: str, env: dict[str, str]) -> bool | None:
    """`[ "${A}" = "x" -o "${B}" != "y" ]`, `-n`, `-z`. None when a clause
    tests a variable nothing has set and no other clause is true."""
    results: list[bool | None] = []
    for clause in re.split(r"\s+-o\s+", text):
        clause = clause.strip()
        test = _TEST_RE.match(clause)
        if test:
            negate, name, op, value = test.groups()
            if name not in env:
                results.append(None)
                continue
            outcome = (env[name] == value) == (op == "=")
            results.append(not outcome if negate else outcome)
            continue
        emptiness = _SET_RE.match(clause)
        if emptiness:
            kind, name = emptiness.groups()
            filled = bool(env.get(name, ""))
            results.append(filled if kind == "n" else not filled)
            continue
        results.append(None)
    if any(result is True for result in results):
        return True
    return None if None in results else False


# The variables this scraper reads. Set inside a case statement, which the
# evaluator does not follow, they stop the scrape. Anything else is skipped.
WATCHED = frozenset({"OPENGLES", "LIBRETRO_CORES", "EXCLUDE_LIBRETRO_CORES"})


def _expand(value: str, env: dict[str, str]) -> str:
    """${NAME} and $NAME from what is set so far. Unset expands to nothing."""
    return re.sub(
        r"\$\{(\w+)\}|\$(\w+)",
        lambda m: env.get(m.group(1) or m.group(2), ""),
        value,
    )


def evaluate(text: str, env: dict[str, str]) -> dict[str, str]:
    """Run the assignments and if/elif/else blocks of a LibreELEC options file.

    Commands are skipped, and so are loop bodies: the libretro_cores loops
    only reorder the list or remove the exclusions, which device_cores applies
    as a set difference. A watched variable set inside a case statement is
    ambiguous and stops the scrape rather than guess.
    """
    env = dict(env)
    lines = re.sub(r"\\\n", " ", text).splitlines()
    # One frame per open if: [parent state, branch taken, this branch's state],
    # each True, False, or None where a condition read an unknown variable.
    stack: list[list[bool | None]] = []
    case_depth = loop_depth = 0

    def state() -> bool | None:
        states = [frame[2] for frame in stack]
        if False in states:
            return False
        return None if None in states else True

    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if re.match(r"^case\b", line):
            case_depth += 1
            continue
        if line == "esac":
            case_depth -= 1
            continue
        if re.match(r"^(for|while)\b", line):
            loop_depth += 1
            continue
        if line == "done":
            loop_depth -= 1
            continue
        if loop_depth:
            continue
        branch = _IF_RE.match(line)
        if branch and branch.group(1) == "if":
            parent = state()
            go = False if parent is False else (
                None if parent is None else _condition(branch.group(2), env)
            )
            stack.append([parent, go, go])
            continue
        if branch and branch.group(1) == "elif":
            frame = stack[-1]
            if frame[0] is False or frame[1] is True:
                go = False
            elif frame[0] is None or frame[1] is None:
                go = None
            else:
                go = _condition(branch.group(2), env)
            frame[1] = True if go is True else (None if go is None else frame[1])
            frame[2] = go
            continue
        if line == "else":
            frame = stack[-1]
            if frame[0] is False or frame[1] is True:
                go = False
            elif frame[0] is None or frame[1] is None:
                go = None
            else:
                go = True
            frame[1], frame[2] = True, go
            continue
        if line == "fi":
            stack.pop()
            continue
        assign = _ASSIGN_RE.match(line)
        current = state()
        if not assign or current is False:
            continue
        name, op, value = assign.groups()
        if case_depth or current is None:
            if name in WATCHED:
                where = "a case statement" if case_depth else "an undecidable branch"
                raise ShellSubsetError(f"{name} assigned inside {where}")
            continue
        value = " ".join(_expand(value, env).split())
        env[name] = f"{env.get(name, '')} {value}".strip() if op == "+=" else value
    return env


def device_cores(cores_mk: str, env: dict[str, str]) -> list[str]:
    """The cores one PROJECT/DEVICE image builds."""
    result = evaluate(cores_mk, env)
    wanted = set(result.get("LIBRETRO_CORES", "").split())
    if not wanted:
        raise RuntimeError(f"no LIBRETRO_CORES in {CORES_MK}")
    return sorted(wanted - set(result.get("EXCLUDE_LIBRETRO_CORES", "").split()))


def device_arch(project: str, options: str) -> str:
    """The architecture Lakka builds a device for: aarch64 where its options
    list it, else arm. The Generic images are x86_64."""
    if project == "Generic":
        return "x86_64"
    return "aarch64" if re.search(r"^\s*aarch64\)", options, re.MULTILINE) else "arm"


class Scraper(BaseTargetScraper):
    """Per-device core lists from Lakka's libretro_cores package."""

    def __init__(self, url: str = "https://github.com/" + REPO) -> None:
        super().__init__(url=url)
        self.tag = ""
        self.paths: set[str] = set()

    def _raw(self, path: str) -> str:
        return fetch_bytes(f"{RAW_BASE.format(tag=self.tag)}/{path}").decode("utf-8")

    def _latest_tag(self) -> str:
        release = json.loads(fetch_bytes(f"{API_BASE}/releases/latest", headers=github_headers()))
        tag = release.get("tag_name") if isinstance(release, dict) else None
        if not tag:
            raise RuntimeError(f"{REPO} names no latest release")
        return tag

    def _devices(self) -> list[tuple[str, str]]:
        tree = json.loads(fetch_bytes(
            f"{API_BASE}/git/trees/{self.tag}?recursive=1", headers=github_headers()
        ))
        if tree.get("truncated"):
            raise RuntimeError(f"the {self.tag} tree listing is truncated")
        self.paths = {item.get("path", "") for item in tree.get("tree", [])}
        found = sorted({
            (match.group(1), match.group(2))
            for item in tree.get("tree", [])
            if (match := re.match(r"^projects/([^/]+)/devices/([^/]+)/options$", item.get("path", "")))
        })
        if not found:
            raise RuntimeError(f"no projects/*/devices/*/options at {self.tag}")
        return found

    def fetch_targets(self) -> dict:
        self.tag = self._latest_tag()
        cores_mk = self._raw(CORES_MK)
        targets: dict[str, dict] = {}
        for project, device in self._devices():
            # Qualcomm keeps its options per device only.
            project_path = f"projects/{project}/options"
            project_options = self._raw(project_path) if project_path in self.paths else ""
            device_options = self._raw(f"projects/{project}/devices/{device}/options")
            env = {"DISTRO": "Lakka", "PROJECT": project, "DEVICE": device}
            env["ARCH"] = device_arch(project, device_options)
            graphics = evaluate(device_options, evaluate(project_options, env))
            env["OPENGLES_SUPPORT"] = "no" if graphics.get("OPENGLES", "no") == "no" else "yes"
            cores = device_cores(cores_mk, env)
            targets[device.lower()] = {"architecture": env["ARCH"], "cores": cores}
            print(f"  {device.lower()} ({env['ARCH']}): {len(cores)} cores", file=sys.stderr)
        return {
            "platform": PLATFORM_NAME,
            "source": f"{self.url}/blob/{self.tag}/{CORES_MK}",
            "scraped_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "targets": targets,
        }


def main() -> None:
    parser = argparse.ArgumentParser(
        allow_abbrev=False, description="Scrape Lakka per-device cores"
    )
    parser.add_argument("--dry-run", action="store_true", help="Show target summary")
    parser.add_argument("--output", "-o", help="Output YAML file")
    args = parser.parse_args()

    scraper = Scraper()
    data = scraper.fetch_targets()
    if args.dry_run:
        for name, info in data["targets"].items():
            print(f"  {name} ({info['architecture']}): {len(info['cores'])} cores")
        return
    if args.output:
        scraper.write_output(data, args.output)
        print(f"Written to {args.output}")
        return
    print(yaml.dump(data, default_flow_style=False, sort_keys=False))


if __name__ == "__main__":
    main()
