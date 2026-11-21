"""What differs between a published games-index document and the one rendered now."""

from __future__ import annotations

import json


def _sample(items: list[str], limit: int = 3) -> str:
    shown = ", ".join(items[:limit])
    return f"{shown}, +{len(items) - limit} more" if len(items) > limit else shown


def describe_change(old: str | None, new: str) -> list[str]:
    """What differs between a published document and the one render() makes.

    The documents are single-line JSON of up to 550 KB: STALE alone left a
    diff by hand to find that a manifest gained one file."""
    if old is None:
        return ["not written yet"]
    try:
        before, after = json.loads(old), json.loads(new)
    except ValueError:
        return ["the published file is not valid JSON"]
    if not (isinstance(before, dict) and isinstance(after, dict)):
        return ["document changed"]
    parts = []
    for key in sorted(set(before) | set(after)):
        a, b = before.get(key), after.get(key)
        if a == b:
            continue
        if isinstance(a, list) and isinstance(b, list):
            olds = {json.dumps(x, sort_keys=True) for x in a}
            news = {json.dumps(x, sort_keys=True) for x in b}
            added = sorted(news - olds)
            removed = sorted(olds - news)
            change = []
            if added:
                change.append(f"{len(added)} added ({_sample(added)})")
            if removed:
                change.append(f"{len(removed)} removed ({_sample(removed)})")
            parts.append(f"{key}: {', '.join(change) or 'reordered'}")
        elif isinstance(a, dict) and isinstance(b, dict):
            changed = sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))
            parts.append(f"{key}: {len(changed)} changed ({_sample(changed)})")
        else:
            parts.append(f"{key} changed" if key in before and key in after
                         else f"{key} {'added' if key in after else 'removed'}")
    return parts or ["formatting changed"]
