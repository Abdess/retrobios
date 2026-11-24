"""MAME romset refs checked against the line that declares their own set."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

from core import upstream
from model.sources import source_yaml_file
from profiling.citations import collect_citations
from scraper.arcade.clex import blank_comments
from scraper.arcade.mame_parser import MACHINE_MACROS

# An optional role word names the repository the lines are in.
DRIVER_REF = re.compile(r"^(?:(source|upstream) )?(src/[\w./+-]+):(\d+)$")


@dataclass(frozen=True)
class Finding:
    set_name: str
    path: str
    cited: int
    declared: int
    role: str = ""

    def ref(self, line: int) -> str:
        return f"{self.role} {self.path}:{line}" if self.role else f"{self.path}:{line}"


def declares(line: str, set_name: str) -> bool:
    """Whether this line is the machine declaration of that set."""
    clean = blank_comments(line)
    match = MACHINE_MACROS.search(clean)
    if not match:
        return False
    args = clean[match.end():].split(",")
    return len(args) > 1 and args[1].strip() == set_name


def audit(
    name: str, emulators_dir: str, cache_dir: str, offline: bool
) -> tuple[list[Finding], int, int]:
    """Findings, plus counts of refs that agree and of unjudgeable ones."""
    document = source_yaml_file(os.path.join(emulators_dir, f"{name}.yml")) or {}
    trees = {
        role: (upstream.parse_repo(str(document.get(role) or "")),
               str(document.get(f"{role}_commit") or ""))
        for role in ("source", "upstream")
    }
    if trees["source"][0] is None or not trees["source"][1]:
        return [], 0, 0
    sources: dict[tuple[str, str], list[str] | None] = {}
    findings: list[Finding] = []
    agreed = unjudged = 0
    files = {id(entry) for entry in document.get("files", []) or []}
    for citation in collect_citations(document):
        entry = citation.entry
        if citation.kind != "ref" or entry is None or id(entry) not in files:
            continue
        entry_name = str(entry.get("name", ""))
        match = DRIVER_REF.match(citation.ref)
        if not (entry_name.endswith(".zip") and match):
            continue
        role, path, cited = match.group(1) or "", match.group(2), int(match.group(3))
        repo, pin = trees[role or "source"]
        if repo is None or not pin:
            unjudged += 1
            continue
        if (role, path) not in sources:
            sources[(role, path)] = upstream.fetch_file(repo, pin, path, cache_dir, offline)
        lines = sources[(role, path)]
        if lines is None:
            continue
        set_name = entry_name[:-4]
        if cited <= len(lines) and declares(lines[cited - 1], set_name):
            agreed += 1
            continue
        found = [i for i, line in enumerate(lines, 1) if declares(line, set_name)]
        if len(found) != 1:
            # None: a device set or a bare ROM_START. Several: the driver
            # declares the name twice and only a reader can choose.
            unjudged += 1
            continue
        findings.append(Finding(set_name, path, cited, found[0], role))
    return findings, agreed, unjudged


def rewrite(name: str, emulators_dir: str, findings: list[Finding]) -> int:
    """Point each ref at the declaration, one entry at a time."""
    path = os.path.join(emulators_dir, f"{name}.yml")
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    written = 0
    for finding in findings:
        anchor = f"- name: {finding.set_name}.zip"
        old = f'source_ref: "{finding.ref(finding.cited)}"'
        start = text.find(anchor)
        if start < 0:
            continue
        at = text.find(old, start)
        if at < 0:
            continue
        new = f'source_ref: "{finding.ref(finding.declared)}"'
        text = text[:at] + new + text[at + len(old):]
        written += 1
    if written:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
    return written
