"""The copy a platform declaration ships, settled once for the pack and the manifest."""

from __future__ import annotations

from dataclasses import dataclass

from resolve.nativemode import digest_algorithm, reads_file_contents
from resolve.packfiles import resolve_declaration
from resolve.validation import agnostic_substitute, baseline_verdict, validated_choice


@dataclass(frozen=True)
class Settlement:
    """What a platform declaration comes to.

    ``resolved`` is the copy the resolver (or a filename-agnostic core's
    substitute) found, ``path`` the copy shipped once the platform's cores
    have judged it. ``status`` is the frontend's verdict, ``refusal`` why a
    hash frontend rejects the copy, ``disagreement`` what a core says
    against a copy the frontend accepts. ``agnostic_dir`` is set when a
    substitute stands in for a file the collection does not hold.
    """

    resolved: str | None
    path: str | None
    status: str
    refusal: str | None = None
    disagreement: str | None = None
    agnostic_dir: str | None = None

    @property
    def ships(self) -> bool:
        """Whether a file is placed: found, local and not refused."""
        return self.refusal is None and self.status not in ("not_found", "external")


@dataclass(frozen=True)
class DeclarationJudge:
    """The rules a platform declaration is settled by: the collection, the
    frontend's verification mode and the cores the platform runs."""

    db: dict
    bios_dir: str
    zip_contents: dict
    data_registry: dict | None
    offline: bool | None
    verification_mode: str
    hash_rule: str
    profiles: dict[str, dict]
    validation_index: dict
    validation_owners: dict

    def verdict(self, file_entry: dict, local_path: str | None, status: str) -> tuple[str, str | None]:
        """The frontend's verdict on a copy, as baseline_verdict reads it."""
        return baseline_verdict(
            file_entry, local_path, status, self.verification_mode, self.hash_rule,
        )

    def settle(
        self, file_entry: dict, sys_id: str, dest: str, override: str | None,
    ) -> Settlement:
        """Resolve a declaration, substitute for it, judge it and let the
        cores choose the copy, in the order the pack and the installer share."""
        local_path, status = resolve_declaration(
            file_entry, self.db, self.bios_dir, self.zip_contents, self.data_registry,
            override, offline=self.offline,
        )
        agnostic_dir = None
        if status == "not_found" and not reads_file_contents(self.verification_mode):
            # A filename-agnostic core takes any image of its system,
            # renamed. Only an existence frontend accepts that.
            found = agnostic_substitute(file_entry, sys_id, self.db, self.profiles)
            if found and found[0]:
                local_path, agnostic_dir = found
                status = "agnostic_fallback"
        if status in ("not_found", "external"):
            return Settlement(local_path, local_path, status, agnostic_dir=agnostic_dir)
        # A member missing from a zipped_file archive, or a hash the
        # frontend rejects.
        status, refusal = self.verdict(file_entry, local_path, status)
        if refusal:
            return Settlement(local_path, local_path, status, refusal, agnostic_dir=agnostic_dir)
        # A frontend's own check can pass while a core it runs rejects the
        # file: a held variant both accept is shipped instead.
        chosen, disagreement = validated_choice(
            file_entry, local_path, self.db, self.validation_index, self.bios_dir,
            digest_algorithm(self.verification_mode), dest, self.validation_owners,
        )
        return Settlement(local_path, chosen, status, None, disagreement, agnostic_dir)
