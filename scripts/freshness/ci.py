"""The CI toolchain pins, the site's npm pins and the installer pin against their latest release."""

from __future__ import annotations

import json
import re

from core import upstream
from core.paths import REPO_ROOT
from installer_build import pins as installer_build_pins
from freshness.findings import INSTALLER_PIN, OK, SKIPPED, STALE, UNKNOWN, Finding


PYPI_URL = "https://pypi.org/pypi/{name}/json"
NPM_URL = "https://registry.npmjs.org/{name}/latest"
# The site's npm dependencies, pinned to exact versions and built by Deploy Site.
SITE_PACKAGE = REPO_ROOT / "website" / "package.json"


_PIN_RE = re.compile(
    r'"?([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?((?:[<>=!~]=?[^,"\s]+)(?:,[<>=!~]=?[^,"\s]+)*)?"?'
)
_USES_RE = re.compile(r"uses:\s*([\w.\-]+/[\w.\-]+)@([0-9a-f]{40})\s*(?:#\s*(\S+))?")


def parse_pip_pins(text: str) -> dict[str, str]:
    """Package -> specifier for every ``pip install`` line of a workflow."""
    pins: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if "pip install" not in stripped:
            continue
        args = stripped.split("pip install", 1)[1]
        for raw in re.findall(r'"[^"]+"|\S+', args):
            token = raw.strip('"')
            if token.startswith("-") or not token:
                continue
            match = _PIN_RE.fullmatch(token)
            if match:
                pins.setdefault(match.group(1).lower(), match.group(2) or "")
    return pins


def parse_action_pins(text: str) -> dict[str, tuple[str, str]]:
    """Action -> (pinned sha, commented tag) for every ``uses:`` line."""
    return {
        repo: (sha, tag or "") for repo, sha, tag in _USES_RE.findall(text)
    }


def _version_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", version))


_SPEC_CLAUSE = re.compile(r"([<>=!~]=?)\s*(.+)")
_SPEC_TESTS = {
    "==": lambda target, bound: target == bound,
    "!=": lambda target, bound: target != bound,
    ">=": lambda target, bound: target >= bound,
    ">": lambda target, bound: target > bound,
    "<=": lambda target, bound: target <= bound,
    "<": lambda target, bound: target < bound,
}


def specifier_allows(spec: str, version: str) -> bool:
    """Whether a pip specifier admits a version. Pre-releases are compared
    on their numeric parts, which is enough for the operators pip uses here."""
    target = _version_tuple(version)
    for clause in filter(None, (c.strip() for c in spec.split(","))):
        match = _SPEC_CLAUSE.fullmatch(clause)
        test = _SPEC_TESTS.get(match.group(1)) if match else None
        if match is None or test is None or not test(target, _version_tuple(match.group(2))):
            return False
    return True


def pypi_latest(name: str) -> str | None:
    payload = upstream.http_json(PYPI_URL.format(name=name))
    if not isinstance(payload, dict):
        return None
    info = payload.get("info") or {}
    return str(info.get("version") or "") or None


def parse_npm_pins(text: str) -> dict[str, str]:
    """Package -> the version a package.json names, dependencies of both kinds."""
    data = json.loads(text)
    pins: dict[str, str] = {}
    for key in ("dependencies", "devDependencies"):
        pins.update({str(k): str(v) for k, v in (data.get(key) or {}).items()})
    return pins


def npm_latest(name: str) -> str | None:
    payload = upstream.http_json(NPM_URL.format(name=name))
    if not isinstance(payload, dict):
        return None
    return str(payload.get("version") or "") or None


def _npm_findings() -> list[Finding]:
    """One row per site dependency: an exact pin is stale once npm's latest
    release is newer, since nothing else asks npm."""
    findings = []
    for name, pinned in sorted(parse_npm_pins(SITE_PACKAGE.read_text(encoding="utf-8")).items()):
        subject = f"npm:{name}"
        if not re.fullmatch(r"\d+(\.\d+)*", pinned):
            findings.append(Finding("ci", subject, UNKNOWN, local=pinned, detail="a range, not an exact pin"))
            continue
        try:
            latest = npm_latest(name)
        except upstream.UpstreamError as exc:
            findings.append(Finding("ci", subject, UNKNOWN, local=pinned, detail=str(exc)))
            continue
        if latest is None:
            findings.append(Finding("ci", subject, UNKNOWN, local=pinned, detail="not on npm"))
            continue
        newer = _version_tuple(latest) > _version_tuple(pinned)
        findings.append(
            Finding(
                "ci",
                subject,
                STALE if newer else OK,
                local=pinned,
                remote=latest,
                detail="a newer release is out" if newer else "",
            )
        )
    return findings


def check_ci(cache_dir: str, offline: bool) -> list[Finding]:
    findings = [_check_installer_pins()]
    workflows = sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml"))
    pins: dict[str, str] = {}
    actions: dict[str, tuple[str, str]] = {}
    for path in workflows:
        text = path.read_text(encoding="utf-8")
        for name, spec in parse_pip_pins(text).items():
            pins.setdefault(name, spec)
        actions.update(parse_action_pins(text))
    if offline:
        findings.append(Finding("ci", "workflow and site pins", SKIPPED, detail="offline"))
        return findings
    findings.extend(_npm_findings())
    for name, spec in sorted(pins.items()):
        try:
            latest = pypi_latest(name)
        except upstream.UpstreamError as exc:
            findings.append(Finding("ci", f"pypi:{name}", UNKNOWN, local=spec, detail=str(exc)))
            continue
        if latest is None:
            findings.append(Finding("ci", f"pypi:{name}", UNKNOWN, local=spec, detail="not on PyPI"))
            continue
        allowed = specifier_allows(spec, latest)
        findings.append(
            Finding(
                "ci",
                f"pypi:{name}",
                OK if allowed else STALE,
                local=spec or "unpinned",
                remote=latest,
                detail="latest admitted" if allowed else "latest release outside the pin",
            )
        )
    for action, (sha, tag) in sorted(actions.items()):
        repo = upstream.parse_repo(f"https://github.com/{action}")
        release = upstream.latest_release(repo, cache_dir, offline)
        if release is None:
            findings.append(Finding("ci", f"action:{action}", UNKNOWN, local=f"{sha[:8]} {tag}", detail="no release seen"))
            continue
        latest_sha = upstream.tag_commit(repo, release.tag, cache_dir, offline) or ""
        findings.append(
            Finding(
                "ci",
                f"action:{action}",
                OK if latest_sha == sha else STALE,
                local=f"{sha[:8]} {tag}".strip(),
                remote=f"{latest_sha[:8]} {release.tag}",
                detail="" if latest_sha == sha else f"{release.tag} released {release.date}",
            )
        )
    return findings


def _check_installer_pins() -> Finding:
    """The bootstraps pin install.py by SHA-256, so a stale pin refuses every install."""
    stale = installer_build_pins.stale_pins(REPO_ROOT)
    return Finding(
        "ci",
        INSTALLER_PIN,
        STALE if stale else OK,
        local=installer_build_pins.installer_sha256(REPO_ROOT)[:12],
        detail=(
            f"pin outdated in {', '.join(stale)}, {installer_build_pins.COMMAND} writes it"
            if stale else "install.sh and install.ps1 match"
        ),
    )
