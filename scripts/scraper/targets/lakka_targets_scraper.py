"""Scraper for Lakka per-device core availability.

Sources (libretro/Lakka-LibreELEC, at the release platforms/lakka.yml names):
  - packages/lakka/libretro_cores/package.mk -- LIBRETRO_CORES, then the
    EXCLUDE_LIBRETRO_CORES each PROJECT/DEVICE and OPENGLES_SUPPORT add
  - projects/<PROJECT>/options and projects/<PROJECT>/devices/<DEVICE>/options
    -- OPENGLES, which config/graphic turns into OPENGLES_SUPPORT

A Lakka RPi1 image carries neither beetle_psx nor mupen64plus_next: without
a target list, its pack shipped their firmware anyway.
"""

from __future__ import annotations

import re
import sys
from datetime import datetime, timezone

from . import BaseTargetScraper, target_cli
from ..base_scraper import fetch_text, github_tree

PLATFORM_NAME = "lakka"

REPO = "libretro/Lakka-LibreELEC"
RAW_BASE = "https://raw.githubusercontent.com/" + REPO + "/{tag}"
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


class _Evaluation:
    """The state of one evaluate() run over an options file."""

    def __init__(self, env: dict[str, str]) -> None:
        self.env = dict(env)
        # One frame per open if: [parent state, branch taken, this branch's state],
        # each True, False, or None where a condition read an unknown variable.
        self.stack: list[list[bool | None]] = []
        self.case_depth = self.loop_depth = 0

    def state(self) -> bool | None:
        states = [frame[2] for frame in self.stack]
        if False in states:
            return False
        return None if None in states else True

    def nesting(self, line: str) -> bool:
        """Follow case and loop nesting. True when the line is consumed."""
        if re.match(r"^case\b", line):
            self.case_depth += 1
            return True
        if line == "esac":
            self.case_depth -= 1
            return True
        if re.match(r"^(for|while)\b", line):
            self.loop_depth += 1
            return True
        if line == "done":
            self.loop_depth -= 1
            return True
        return bool(self.loop_depth)

    def branch(self, line: str) -> bool:
        """Follow if/elif/else/fi. True when the line is one of them."""
        go: bool | None
        branch = _IF_RE.match(line)
        if branch and branch.group(1) == "if":
            parent = self.state()
            go = False if parent is False else (
                None if parent is None else _condition(branch.group(2), self.env)
            )
            self.stack.append([parent, go, go])
            return True
        if branch and branch.group(1) == "elif":
            frame = self.stack[-1]
            if frame[0] is False or frame[1] is True:
                go = False
            elif frame[0] is None or frame[1] is None:
                go = None
            else:
                go = _condition(branch.group(2), self.env)
            frame[1] = True if go is True else (None if go is None else frame[1])
            frame[2] = go
            return True
        if line == "else":
            frame = self.stack[-1]
            if frame[0] is False or frame[1] is True:
                go = False
            elif frame[0] is None or frame[1] is None:
                go = None
            else:
                go = True
            frame[1], frame[2] = True, go
            return True
        if line == "fi":
            self.stack.pop()
            return True
        return False

    def assign(self, line: str) -> None:
        assign = _ASSIGN_RE.match(line)
        current = self.state()
        if not assign or current is False:
            return
        name, op, value = assign.groups()
        if self.case_depth or current is None:
            if name in WATCHED:
                where = "a case statement" if self.case_depth else "an undecidable branch"
                raise ShellSubsetError(f"{name} assigned inside {where}")
            return
        value = " ".join(_expand(value, self.env).split())
        env = self.env
        env[name] = f"{env.get(name, '')} {value}".strip() if op == "+=" else value


def evaluate(text: str, env: dict[str, str]) -> dict[str, str]:
    """Run the assignments and if/elif/else blocks of a LibreELEC options file.

    Commands are skipped, and so are loop bodies: the libretro_cores loops
    only reorder the list or remove the exclusions, which device_cores applies
    as a set difference. A watched variable set inside a case statement is
    ambiguous and stops the scrape rather than guess.
    """
    run = _Evaluation(env)
    for raw in re.sub(r"\\\n", " ", text).splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or run.nesting(line) or run.branch(line):
            continue
        run.assign(line)
    return run.env


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
        return fetch_text(f"{RAW_BASE.format(tag=self.tag)}/{path}")

    def _devices(self) -> list[tuple[str, str]]:
        tree = github_tree(REPO, self.tag)
        self.paths = {item["path"] for item in tree}
        found = sorted({
            (match.group(1), match.group(2))
            for item in tree
            if (match := re.match(r"^projects/([^/]+)/devices/([^/]+)/options$", item["path"]))
        })
        if not found:
            raise RuntimeError(f"no projects/*/devices/*/options at {self.tag}")
        return found

    def fetch_targets(self) -> dict:
        self.tag = self.pinned_version(PLATFORM_NAME)
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
    target_cli(Scraper, "Scrape Lakka per-device cores")


if __name__ == "__main__":
    main()
