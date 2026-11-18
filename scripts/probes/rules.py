"""The campaign's fixed rule table: which verdicts settle which profile field.

Each rule is a pure function of verdicts read from core probe records (the
boot oracle of core_probe.py: boots, bios_error, crash, hang, unknown) and
a profile entry. It returns verdicts on profile fields. One with `apply` set
is settled by the table and written into the profile with the record ids as
`evidence:`. Any other goes to the review queue (measurements/findings.jsonl).

Three runs are compared for a file, all on the same content: `none` with no
BIOS at all, `present` with the file alone, and wrong files staged under its
name (zeros of its size, its first half, another region's dump).

  runs                                          field          settled
  none boots, the file changes the run          hle_fallback   true
  none fails, present boots                     required       true
                                                hle_fallback   false
  zeros refused, present boots                  validation     a content check
  zeros used, present boots                     validation     no content check
  half refused, zeros used                      validation     size
  half used                                     validation     no size check
  opens the staged file under another path      path           that path
  opens the staged file under another name      aliases        name added
  a staged file the content should use, never   -              flagged only
  read
  copies of one file that boot and fail         -              queued

"Fails" is bios_error, crash or hang. A wrong file is refused when the
core reports a BIOS error, when its log says it ran its built-in BIOS
(bios_used builtin), or when it boots without the BIOS screens the right
file shows. It is used when the log names the file it loaded. It is used when it
turns the run into a hang or a crash that the run without any file does not
show. Anything else settles nothing. A check the entry declares with
`on_mismatch: warn` is one the code only logs: a wrong file that runs
agrees with it. Of validation, the table writes only a
missing `size`. A contradicted content check goes to review: which hash a
core computes is read in its code.

Standard library only.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field

BOOTS = "boots"
BIOS_ERROR = "bios_error"
CRASH = "crash"
HANG = "hang"
UNKNOWN = "unknown"
FAILS = (BIOS_ERROR, CRASH, HANG)
REFUSED = "refused"
USED = "used"
CONTENT_CHECKS = ("md5", "sha1", "sha256", "crc32", "adler32", "signature")

# A field an entry leaves out reads as this value.
FIELD_DEFAULTS: dict[str, object] = {"hle_fallback": False, "path": None, "aliases": [],
                                     "validation": []}
SETTLED_FIELDS = ("required", "hle_fallback", "path", "aliases", "validation")


@dataclass(frozen=True)
class Run:
    """The verdict of one variant of a record: what a rule reads."""

    verdict: str
    record_id: str
    label: str
    stages: tuple[str, ...] = ()
    bios_used: str = "unknown"

    @property
    def shows_bios(self) -> bool:
        return "bios" in self.stages


@dataclass(frozen=True)
class Verdict:
    rule: str
    field: str
    value: object
    statement: str
    evidence: tuple[str, ...]
    apply: bool = False


@dataclass(frozen=True)
class Opened:
    """Where a run found the staged file opened."""

    dest: str
    record_id: str
    extra: dict = field(default_factory=dict)


def variant(record: dict, label: str) -> dict:
    for item in record.get("variants") or ():
        if item.get("label") == label:
            return item
    raise KeyError(f"record {record.get('id')}: no variant {label!r}")


def run_of(record: dict, label: str) -> Run:
    """A variant's verdict as a rule reads it. A record from before the
    oracle has none, and reads as unknown."""
    item = variant(record, label)
    evidence = item.get("verdict_evidence") or {}
    return Run(item.get("verdict", UNKNOWN), record["id"], label, tuple(evidence.get("stages") or ()),
               item.get("bios_used", "unknown"))


def ids(*runs: Run) -> tuple[str, ...]:
    return tuple(dict.fromkeys(run.record_id for run in runs))


def current(entry: dict, name: str) -> object:
    if name in entry:
        return entry[name]
    return FIELD_DEFAULTS.get(name)


def agrees(entry: dict, verdict: Verdict) -> bool:
    """True when the profile already says what the run showed."""
    if verdict.field == "aliases":
        shown = verdict.value if isinstance(verdict.value, (list, tuple)) else ()
        return set(shown) <= set(entry.get("aliases") or ())
    if verdict.field == "validation":
        return verdict.rule == "validation_agrees"
    return current(entry, verdict.field) == verdict.value


def read(none: Run, *runs: Run) -> bool:
    """True when the file changes the run: alone or as a wrong file, one
    variant ends otherwise than the run with no BIOS, or reaches other
    stages. A core can open a file without using it for this content (a
    scan that hashes every file of the folder)."""
    return any(run.verdict != none.verdict or run.stages != none.stages for run in runs if run)


def rule_need(none: Run, present: Run, entry: dict, used: bool = True) -> list[Verdict]:
    """No BIOS at all against the file alone: required and hle_fallback. A
    file the content never uses settles nothing."""
    name = entry["name"]
    if none.verdict == BOOTS and not used:
        return []
    if none.verdict == BOOTS:
        on = " on its built-in BIOS" if none.bios_used == "builtin" else ""
        out = [Verdict("boots_without_file", "hle_fallback", True,
                       f"the core boots the content{on} with no BIOS at all, {name} included",
                       ids(none), True)]
        if entry.get("required") is True:
            out.append(Verdict(
                "boots_without_file", "required", False,
                f"the profile says {name} is required, and the core boots without it. The table "
                f"settles hle_fallback from this run, not required", ids(none)))
        return out
    if none.verdict in FAILS and present.verdict == BOOTS:
        return [
            Verdict("fails_without_file", "required", True,
                    f"with no BIOS the run ends in {none.verdict}, with {name} alone it boots",
                    ids(none, present), True),
            Verdict("fails_without_file", "hle_fallback", False,
                    f"no stand-in for {name}: with no BIOS the run ends in {none.verdict}",
                    ids(none, present), True),
        ]
    return [Verdict("unsettled", "hle_fallback", None,
                    f"with no BIOS the run is {none.verdict} and with {name} alone {present.verdict}: "
                    f"no rule settles a field from that", ids(none, present))]


def file_use(wrong: Run, none: Run, present: Run) -> str | None:
    """Whether the core refused a wrong file or ran it, or None."""
    if present.verdict != BOOTS:
        return None
    if wrong.verdict == BIOS_ERROR:
        return REFUSED
    # The log names the BIOS the core ran: that settles it before any screen.
    if wrong.verdict == BOOTS and wrong.bios_used == "builtin":
        return REFUSED
    if wrong.verdict == BOOTS and wrong.bios_used.startswith("staged:"):
        return USED
    if wrong.verdict == BOOTS:
        if wrong.shows_bios:
            return USED
        return REFUSED if present.shows_bios else None
    if wrong.verdict in (HANG, CRASH) and none.verdict in (BOOTS, BIOS_ERROR):
        return USED
    return None


def declared_checks(entry: dict) -> tuple[set[str], bool]:
    """The checks the entry's validation names, and whether it is one list
    (a per-build dict is never edited by the table)."""
    value = entry.get("validation") or []
    if isinstance(value, dict):
        return {str(v) for items in value.values() for v in items or ()}, False
    return {str(v) for v in value}, True


def warned_checks(entry: dict, checks: set[str]) -> set[str]:
    """The declared checks whose failure the code only logs (`on_mismatch:
    warn`, for all of them or check by check): a wrong file still runs."""
    level = entry.get("on_mismatch")
    if level == "warn":
        return set(checks)
    if isinstance(level, dict):
        return {check for check, value in level.items() if value == "warn"} & checks
    return set()


def rule_validation(zeros: Run | None, half: Run | None, none: Run, present: Run,
                    entry: dict) -> Verdict | None:
    """Same-size and short wrong files against the right one: validation."""
    name = entry["name"]
    zeros_use = file_use(zeros, none, present) if zeros else None
    content = {REFUSED: True, USED: False}.get(zeros_use) if zeros_use else None
    half_use = file_use(half, none, present) if half else None
    size: bool | None = None
    if half_use == USED:
        size, content = False, False if content is None else content
    elif half_use == REFUSED and content is False:
        size = True
    if content is None and size is None:
        return None
    declared, editable = declared_checks(entry)
    enforced = declared - warned_checks(entry, declared)
    evidence = ids(*(run for run in (none, present, zeros, half) if run))
    said = sorted(declared)
    shown = []
    problems = []
    if content is not None:
        shown.append("checks the content" if content else "does not check the content")
        if content != bool(enforced & set(CONTENT_CHECKS)):
            problems.append("a same-size file of zeros is " + ("refused" if content else "run")
                            + f", the profile declares validation {said}")
    missing_size = size is True and "size" not in declared
    if size is not None:
        shown.append("checks the size" if size else "does not check the size")
        if size is False and "size" in enforced:
            problems.append(f"the first half of {name} is run, the profile declares a size check")
    statement = f"the core {' and '.join(shown)} of {name}"
    # What the runs show, for a finding beside what the profile says.
    checks = {"content": content, "size": size}
    if problems:
        return Verdict("validation_contradicted", "validation", checks,
                       f"{statement}: {'; '.join(problems)}", evidence)
    if missing_size:
        if not editable:
            return Verdict("validation_contradicted", "validation", checks,
                           f"{statement}: the per-build validation has no size check", evidence)
        value = [*(entry.get("validation") or []), "size"]
        return Verdict("validation_size_added", "validation", value,
                       f"{statement}: half of the file is refused while zeros of its size are run",
                       evidence, True)
    return Verdict("validation_agrees", "validation", entry.get("validation") or [], statement,
                   evidence, editable)


def rule_region(dump: Run, present: Run, entry: dict, game_region: str | None) -> str:
    """What the core did with another region's dump under this file's name."""
    return (f"{dump.label} staged as {entry['name']} with a {game_region or 'region-less'} game: "
            f"{dump.verdict}, {entry['name']} itself: {present.verdict}")


def rule_path(entry: dict, declared: str, opened: Opened) -> Verdict | None:
    """The core opened the file at another place under the system directory."""
    if opened.dest == declared:
        return None
    return Verdict("opened_under_other_path", "path", opened.dest,
                   f"the core opened {entry['name']} as {opened.dest}, the profile declares "
                   f"{declared}", (opened.record_id,), True)


def rule_alias(entry: dict, opened: Opened) -> Verdict | None:
    """The core opened the file under a name the entry does not declare."""
    name = opened.dest.rsplit("/", 1)[-1]
    known = [entry["name"], *(entry.get("aliases") or ())]
    if name in known:
        return None
    return Verdict("opened_other_name", "aliases", [*(entry.get("aliases") or ()), name],
                   f"the core opened {entry['name']} under the name {name}",
                   (opened.record_id,), True)


def rule_never_opened(entry: dict, record_ids: Sequence[str], content: str) -> Verdict:
    return Verdict("never_opened", "opened", False,
                   f"{entry['name']} was staged and the core never opened it while running "
                   f"{content}", tuple(record_ids))


def rule_variants(runs: Iterable[Run], entry: dict) -> Verdict | None:
    """Copies of one file whose verdicts differ: a pack choice to review."""
    runs = list(runs)
    if len({run.verdict for run in runs}) < 2:
        return None
    shown = ", ".join(f"{run.label} {run.verdict}" for run in runs)
    return Verdict("variant_changes_verdict", "variants", sorted(run.label for run in runs),
                   f"the copies of {entry['name']} do not boot alike: {shown}", ids(*runs))


def merge_evidence(existing: dict | None, verdict: Verdict,
                   keep: Callable[[str], bool] = lambda rid: True) -> dict:
    """The entry's evidence: map with the verdict's record ids added under its
    field. An id `keep` refuses is dropped from that field: a record from
    before the oracle no longer proves anything."""
    out = {key: list(value) for key, value in (existing or {}).items()}
    ids_ = [rid for rid in out.get(verdict.field, []) if keep(rid)]
    for rid in verdict.evidence:
        if rid not in ids_:
            ids_.append(rid)
    out[verdict.field] = ids_
    return {key: out[key] for key in sorted(out) if out[key]}
