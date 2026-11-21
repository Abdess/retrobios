"""What the campaign reports: check status, open findings, and their review."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from core.statefile import now_iso
from model import measurements as mr
from probes import rules
from probes.profileedit import write_fields
from probes.state import DONE, FAILED, PENDING

if TYPE_CHECKING:
    from probes.campaign import Campaign, Pass


# --------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------

def status_report(campaign: Campaign) -> dict:
    counts, reasons, failed = campaign.counts()
    runs = mr.read_campaign(campaign.paths.root, mr.CAMPAIGN_RUNS)
    per = {}
    for emulator, checks in sorted(campaign.state["checks"].items()):
        per[emulator] = {key: {k: v for k, v in entry.items() if k in ("status", "reason", "record", "at")}
                         for key, entry in sorted(checks.items())}
    return {"last_run": runs[-1] if runs else None, "counts": counts, "pending_reasons": reasons,
            "failed": failed, "emulators": per}


def pass_report(campaign: Campaign, current: Pass) -> dict:
    """The line a pass prints: its result, the check counts, its records and findings."""
    counts, _, _ = campaign.counts()
    report = {"result": current.result, "detail": current.detail, "counts": counts,
              "records": len(current.records), "findings": current.findings}
    if current.result == "refused":
        # autorun raises an alert from this key of a job's report.
        report["alert"] = current.detail
    return report


def render_status(report: dict) -> str:
    lines = []
    last = report["last_run"]
    if last:
        lines.append(f"last run {last['started_at']} to {last['ended_at']}: {last['result']}"
                     + (f" ({last['detail']})" if last["detail"] else ""))
    else:
        lines.append("no run yet")
    counts = report["counts"]
    lines.append(f"{counts.get(DONE, 0)} done, {counts.get(FAILED, 0)} failed, "
                 f"{counts.get(PENDING, 0)} pending")
    lines.extend(f"  pending {number:5}  {reason}"
                 for reason, number in sorted(report["pending_reasons"].items(), key=lambda kv: -kv[1]))
    lines.extend(f"  FAILED {item['emulator']} {item['check']}: {item['reason']}" for item in report["failed"])
    for emulator, checks in report["emulators"].items():
        ran = [k for k, v in checks.items() if v["status"] != PENDING]
        if ran:
            lines.append(f"{emulator}")
            for key in ran:
                entry = checks[key]
                lines.append(f"  {entry['status']:7} {key}" + (f"  {entry['record']}" if entry.get("record") else "")
                             + (f"  ({entry['reason']})" if entry.get("reason") else ""))
    return "\n".join(lines)


def open_findings(root: Path, everything: bool = False) -> list[dict]:
    latest: dict[str, dict] = {}
    for line in mr.read_campaign(root, mr.FINDINGS):
        latest[line["key"]] = line
    return [line for key, line in sorted(latest.items())
            if everything or line["status"] in ("open", "flagged")]


REVIEWED = ("applied", "rejected")


def review_finding(root: Path, key: str, status: str, reason: str,
                   updates: dict[str, object] | None = None, index: int | None = None) -> dict:
    """Close an open finding after reading the core's code.

    `applied` writes `updates` into the entry the finding names, through the
    same editor as the rule table, with the finding's record ids added as
    `evidence:` under its field. An applied finding with no update records a
    profile changed by hand. `rejected` keeps the profile as it is. Either
    way a line with the reason is appended to the findings."""
    if status not in REVIEWED:
        raise ValueError(f"status {status!r}: one of {', '.join(REVIEWED)}")
    if not reason.strip():
        raise ValueError("a review names its reason")
    latest = {line["key"]: line for line in mr.read_campaign(root, mr.FINDINGS)}
    finding = latest.get(key)
    if finding is None:
        raise ValueError(f"no finding {key}")
    if finding["status"] not in ("open", "flagged"):
        raise ValueError(f"{key} is {finding['status']}, not open")
    if updates and status != "applied":
        raise ValueError("only an applied review changes the profile")
    if updates:
        path = root / "emulators" / f"{finding['emulator']}.yml"
        entries = yaml.safe_load(path.read_text(encoding="utf-8")).get("files") or []
        matches = [i for i, entry in enumerate(entries) if entry.get("name") == finding["file"]]
        if index is not None:
            matches = [i for i in matches if i == index]
        if len(matches) != 1:
            raise ValueError(f"{finding['emulator']}: {len(matches)} entries named {finding['file']}"
                             + ("" if index is not None else ", pass --index"))
        entry = entries[matches[0]]
        verdict = rules.Verdict(finding["rule"], finding["field"], finding["run_shows"],
                                finding["statement"], tuple(finding["evidence"]))
        evidence = rules.merge_evidence(entry.get("evidence"), verdict)
        write_fields(path, matches[0], {**updates, "evidence": evidence})
    body = {key_: value for key_, value in finding.items() if key_ != "id"}
    line = mr.seal_line({**body, "found_at": now_iso(), "status": status, "reason": reason},
                        "found_at")
    with (root / mr.records_path(mr.FINDINGS)).open("a", encoding="utf-8") as handle:
        handle.write(mr.line_text(line) + "\n")
    return line
