"""The freshness report as text, its exit code and the refusal of an unknown area."""

from __future__ import annotations

from freshness.findings import AREAS, ERROR, STALE, STATUSES, UNKNOWN, Finding


def render(findings: list[Finding]) -> str:
    lines = []
    width = max((len(f.subject) for f in findings), default=10)
    width = min(width, 44)
    for area in AREAS:
        rows = [f for f in findings if f.area == area]
        if not rows:
            continue
        lines.append(f"\n[{area}]")
        # Columns are padded, never cut: the profile_sync row says in its
        # local and remote values what to re-read, and lost the end of it.
        local_width = min(max((len(f.local) for f in rows), default=0), 44)
        remote_width = min(max((len(f.remote) for f in rows), default=0), 44)
        # The arrow and the remote value, or as many blanks where a row has none.
        remote_span = 4 + remote_width if remote_width else 0
        for f in rows:
            cols = f"  {f.status:7} {f.subject:{width}}"
            if f.remote:
                cols += f"  {f.local:{local_width}} -> {f.remote:{remote_width}}"
            elif f.local or (f.detail and (local_width or remote_span)):
                # An arrow pointing at nothing read as a lost value. Empty
                # local and remote values still take their columns, or the
                # detail starts where the other rows show theirs.
                cols += f"  {f.local:{local_width}}" + " " * remote_span
            if f.detail:
                cols += f"  {f.detail}"
            lines.append(cols.rstrip())
    counts = {status: sum(1 for f in findings if f.status == status) for status in STATUSES}
    summary = ", ".join(f"{n} {status.lower()}" for status, n in counts.items() if n)
    lines.append(f"\nFRESHNESS: {summary}")
    if counts[STALE]:
        lines.append(
            "refresh_stale.py runs the refresher behind every stale row "
            "(--dry-run lists them first)"
        )
    if counts[UNKNOWN]:
        lines.append("an unknown row is an upstream that could not be read: not up to date")
    return "\n".join(lines)


def exit_code(findings: list[Finding]) -> int:
    """Zero only when every upstream asked answered and nothing is stale.

    An unknown row is an upstream that could not be read: a run without
    network gave 28 of them and exited 0, the answer of a fresh collection.
    """
    return 1 if any(f.status in (STALE, ERROR, UNKNOWN) for f in findings) else 0


def unknown_areas_message(unknown: list[str]) -> str:
    """The refusal of --only, naming the areas it accepts."""
    import difflib

    hints = [
        f"{name} (did you mean {close[0]}?)" if close else name
        for name in unknown
        for close in [difflib.get_close_matches(name, AREAS, n=1)]
    ]
    return f"unknown area: {', '.join(hints)}. Areas: {', '.join(AREAS)}"
