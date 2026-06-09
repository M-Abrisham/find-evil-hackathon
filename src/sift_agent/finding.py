"""Finding — the single standard "evidence card" for the SIFT "Find Evil" agent.

Every assertion the forensic agent makes is recorded as one :class:`Finding`.
A Finding is a *court-vetted* evidence card: it states a claim, fixes its
status and a hash-reproducible confidence, and cites the raw tool output that
backs it via one or more :class:`ProvenanceRef` locators. Findings are written
to an append-only ledger and **hashed**, so their serialization MUST be
canonical and reproducible byte-for-byte.

Design contract (one-to-one with the component spec)
----------------------------------------------------
* ``confidence`` is a fixed-decimal **STRING** ``"0.00".."1.00"`` — never a
  float — so that hashing a Finding is stable across machines/Python builds.
* ``created_ts`` is host UTC ISO-8601 with a trailing ``Z`` (Zulu), the only
  canonical timestamp shape we hash.
* :meth:`Finding.validate` enforces every rule with an explicit, individually
  testable check and **raises** :class:`ValueError` on the first violation
  (fail-fast; see "Validation approach" below). It returns ``None`` on success.
* :meth:`Finding.to_dict` / :meth:`Finding.to_json` are CANONICAL-SAFE: sorted
  keys, ``ensure_ascii=True``, ints stay ints, enums serialize to their string
  value, ``confidence`` stays a fixed-decimal string, and there are **no**
  floats and no ``NaN``/``Infinity``. :meth:`Finding.from_dict` round-trips:
  ``to_json`` of a reconstructed Finding is byte-identical to the original.

Validation approach
-------------------
``validate()`` follows a single, documented convention: **fail-fast, raise**.
On the first rule violation it raises :class:`ValueError` with a clear,
specific message; on success it returns ``None``. It never returns a list of
errors and never silently passes. This keeps each rule individually testable:
a test triggers exactly one violation and asserts the raised message.

Standard library ONLY — no third-party imports (a Finding card must not depend
on ``na0s`` or anything external).
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Any

__all__ = [
    "Status",
    "EvidenceType",
    "ProvenanceRef",
    "Finding",
    "CONFIDENCE_RE",
    "CREATED_TS_RE",
]


# =============================================================================
# Enumerations
# =============================================================================
class Status(str, Enum):
    """Epistemic status of a Finding's claim.

    ``confirmed``             — backed by >=2 independent provenance sources.
    ``inferred``              — supported, but not independently corroborated.
    ``insufficient_evidence`` — not enough evidence to assert; never a "fact".
    ``rejected``              — actively disproven; never a "fact".

    Subclassing ``str`` makes the value JSON-serializable as its string form.
    """

    confirmed = "confirmed"
    inferred = "inferred"
    insufficient_evidence = "insufficient_evidence"
    rejected = "rejected"


class EvidenceType(str, Enum):
    """The forensic domain a piece of provenance comes from.

    ``disk``   — file-system artifacts (MFT, USN, registry, EVTX, plaso, …).
    ``memory`` — volatile memory (Volatility 3 process/handle/netscan, …).
    ``cross``  — a correlation that spans disk *and* memory.
    """

    disk = "disk"
    memory = "memory"
    cross = "cross"


# =============================================================================
# Confidence — a fixed-decimal STRING, NOT a float (hash-reproducible).
# =============================================================================
# Matches "0.00".."1.00": a leading 0 or 1, a dot, then exactly two digits.
# The numeric-range check below additionally rejects "1.01".."1.99".
# NB: anchored with \A..\Z (NOT ^..$). In Python ``$`` also matches just before
# a trailing newline, so "1.00\n" would slip through ^..$ and then Decimal()
# tolerates the trailing whitespace — two Findings asserting the same confidence
# would hash differently. \Z matches only the absolute end of the string.
CONFIDENCE_RE = re.compile(r"\A[01]\.[0-9]{2}\Z")

# Decimal bounds used ONLY for internal range validation. Confidence is always
# stored and emitted as the canonical two-decimal STRING; we never let it become
# a float (floats are not hash-stable across machines / Python builds).
_CONFIDENCE_MIN = Decimal("0.00")
_CONFIDENCE_MAX = Decimal("1.00")

# created_ts — host UTC ISO-8601 with a trailing 'Z'. Optional fractional
# seconds are allowed (e.g. "2026-06-08T21:40:03Z" or "...:03.123456Z"); a bare
# "+00:00" offset is intentionally NOT accepted — the canonical hashed form is Z.
# Anchored with \A..\Z (NOT ^..$) so a trailing newline ("...Z\n") cannot slip
# through — see the CONFIDENCE_RE note above. Because the match now guarantees a
# literal 'Z' at the absolute end, the ``[:-1]`` Z-strip in _validate_created_ts
# is safe.
CREATED_TS_RE = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\Z")


# =============================================================================
# ProvenanceRef — one citation into a captured receipt's output.
# =============================================================================
@dataclass
class ProvenanceRef:
    """A single, verifiable pointer to the raw output that backs a claim.

    Fields
    ------
    receipt_id : str
        Id of the captured tool receipt (ledger row) whose output is cited.
    tool : str
        The forensic tool that produced the output (``vol``, ``MFTECmd``, …).
    artifact_path : str
        The artifact the tool ran against / the captured output file.
    locator : str
        A *native* locator into that artifact — e.g. an MFT record number, an
        EVTX ``EventRecordID``, a USN ``LSN``, a plaso event UUID, or a
        registry key path. For ``memory`` evidence this MUST be the structured
        pid-tuple form ``"pid=..;ppid=..;create_time=..;offset=.."`` (a bare
        integer PID is rejected by :meth:`Finding.validate`).
    byte_range : list[int] | None
        ``[start, end]`` byte offsets into the receipt's captured output, or
        ``None``. When present it must be a pair of ints with
        ``0 <= start <= end``. Kept as a list of ints so it serializes
        canonically (no floats, no tuples).
    """

    receipt_id: str
    tool: str
    artifact_path: str
    locator: str
    byte_range: list[int] | None = None

    # ---- canonical (de)serialization ----------------------------------------
    def to_dict(self) -> dict[str, Any]:
        """Canonical dict for this ref (``byte_range`` stays list[int]|null)."""
        return {
            "receipt_id": self.receipt_id,
            "tool": self.tool,
            "artifact_path": self.artifact_path,
            "locator": self.locator,
            "byte_range": (
                None if self.byte_range is None else [int(self.byte_range[0]), int(self.byte_range[1])]
            ),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProvenanceRef:
        """Reconstruct a ProvenanceRef from its canonical dict."""
        br = data.get("byte_range")
        return cls(
            receipt_id=data["receipt_id"],
            tool=data["tool"],
            artifact_path=data["artifact_path"],
            locator=data["locator"],
            byte_range=(None if br is None else [int(br[0]), int(br[1])]),
        )


# =============================================================================
# Finding — the evidence card.
# =============================================================================
def _new_id() -> str:
    """Default id factory: a uuid4 hex string."""
    return uuid.uuid4().hex


def _utc_now_z() -> str:
    """Host UTC ISO-8601 with a ``Z`` suffix, e.g. ``2026-06-08T21:40:03Z``."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# Labelled components required in a MEMORY locator's structured pid-tuple.
_MEMORY_LOCATOR_KEYS = ("pid", "ppid", "create_time", "offset")


@dataclass
class Finding:
    """One forensic finding — the standard evidence card (see module docstring).

    Construction does NOT auto-validate; call :meth:`validate` explicitly (it
    raises :class:`ValueError` on the first rule violation, returns ``None`` on
    success). ``id`` and ``created_ts`` default-generate when not supplied.
    """

    # ---- required core ----
    claim: str
    status: Status
    confidence: str  # fixed-decimal string "0.00".."1.00" (NOT a float)
    evidence_type: EvidenceType

    # ---- provenance + verbatim evidence ----
    provenance: list[ProvenanceRef] = field(default_factory=list)
    extracted_literals: list[str] = field(default_factory=list)

    # ---- optional metadata ----
    attack_mapping: str | None = None
    step_id: str | None = None
    supersedes: str | None = None
    verifier_notes: str | None = None

    # ---- auto-generated identity / timestamp ----
    id: str = field(default_factory=_new_id)
    created_ts: str = field(default_factory=_utc_now_z)

    # =========================================================================
    # Validation — fail-fast, raise ValueError on the first violation.
    # Each rule is an explicit, individually-testable check.
    # =========================================================================
    def validate(self) -> None:
        """Enforce every Finding rule. Return ``None`` on success; else raise.

        Raises
        ------
        ValueError
            On the first rule violation, with a specific message.
        """
        # --- types: status / evidence_type must be the right enums ---------
        if not isinstance(self.status, Status):
            raise ValueError(f"status must be a Status enum, got {type(self.status).__name__}")
        if not isinstance(self.evidence_type, EvidenceType):
            raise ValueError(
                f"evidence_type must be an EvidenceType enum, got {type(self.evidence_type).__name__}"
            )

        # --- core string fields present -----------------------------------
        if not isinstance(self.claim, str) or self.claim == "":
            raise ValueError("claim must be a non-empty string")
        if not isinstance(self.id, str) or self.id == "":
            raise ValueError("id must be a non-empty string")
        if not isinstance(self.created_ts, str) or self.created_ts == "":
            raise ValueError("created_ts must be a non-empty string")

        # --- confidence: fixed-decimal STRING, not a float ----------------
        self._validate_confidence()

        # --- created_ts: host UTC ISO-8601 with a trailing 'Z' ------------
        self._validate_created_ts()

        # --- provenance must be a list ------------------------------------
        if not isinstance(self.provenance, list):
            raise ValueError("provenance must be a list of ProvenanceRef")

        # --- every ProvenanceRef must be well-formed ----------------------
        for i, ref in enumerate(self.provenance):
            self._validate_provenance_ref(ref, i)
            # MEMORY evidence: the locator MUST be the structured pid-tuple
            # ("pid=..;ppid=..;create_time=..;offset=.."), NEVER a bare PID.
            # NOTE: this keys off the Finding-level evidence_type (the spec's
            # ProvenanceRef has no per-ref evidence_type). A 'cross' Finding
            # that mixes a memory-origin ref with disk refs therefore does not
            # get that ref's locator structurally checked here — documented and
            # defensible given the data model; revisit only if a per-ref
            # evidence_type is added to ProvenanceRef.
            if self.evidence_type is EvidenceType.memory and not self.is_structured_memory_locator(
                ref.locator
            ):
                raise ValueError(
                    f"provenance[{i}].locator for memory evidence must be the "
                    "structured pid-tuple 'pid=..;ppid=..;create_time=..;offset=..', "
                    f"not a bare PID (got {ref.locator!r})"
                )

        # --- extracted_literals must be a list of strings -----------------
        if not isinstance(self.extracted_literals, list) or not all(
            isinstance(lit, str) for lit in self.extracted_literals
        ):
            raise ValueError("extracted_literals must be a list of strings")

        # --- optional metadata: str | None --------------------------------
        for name in ("attack_mapping", "step_id", "supersedes", "verifier_notes"):
            val = getattr(self, name)
            if val is not None and not isinstance(val, str):
                raise ValueError(f"{name} must be a string or None")

        # --- status-specific rules ----------------------------------------
        if self.status in (Status.confirmed, Status.inferred):
            # confirmed/inferred REQUIRE non-empty provenance AND literals.
            if len(self.provenance) == 0:
                raise ValueError(f"status={self.status.value} requires non-empty provenance")
            if len(self.extracted_literals) == 0:
                raise ValueError(
                    f"status={self.status.value} requires non-empty extracted_literals"
                )

        if self.status is Status.confirmed:
            # confirmed REQUIRES >=2 INDEPENDENT provenance sources.
            self._validate_confirmed_independence()

        # insufficient_evidence / rejected: accepted with weak/no provenance.
        # (They are never presented as fact; that is a consumer concern, not a
        # validation failure — see is_presentable_as_fact().)
        return None

    # ---- individual rule checks (each independently testable) ---------------
    def _validate_confidence(self) -> None:
        """confidence must be a fixed-decimal string in ``"0.00".."1.00"``.

        A ``bool`` is explicitly rejected (``bool`` is a subclass of ``int`` and
        would otherwise sneak past a naive check). Floats are rejected outright —
        coercing a float here is exactly how a non-reproducible value would leak
        into a hashed ledger. We use :class:`decimal.Decimal` ONLY to do the
        range comparison; the stored/emitted value stays the canonical string.
        """
        if isinstance(self.confidence, bool) or not isinstance(self.confidence, str):
            raise ValueError(
                f"confidence must be a fixed-decimal string, got {type(self.confidence).__name__}"
            )
        if CONFIDENCE_RE.match(self.confidence) is None:
            raise ValueError(
                f"confidence {self.confidence!r} is malformed; expected /^[01]\\.[0-9]{{2}}$/ "
                '("0.00".."1.00")'
            )
        # Range check via Decimal (exact, no float). The regex already pins the
        # shape to "[01].dd"; this additionally rejects "1.01".."1.99".
        try:
            dec = Decimal(self.confidence)
        except InvalidOperation:  # pragma: no cover - regex already guards shape
            raise ValueError(f"confidence {self.confidence!r} is not a valid decimal")
        if not (_CONFIDENCE_MIN <= dec <= _CONFIDENCE_MAX):
            raise ValueError(
                f"confidence {self.confidence!r} out of range; must be \"0.00\"..\"1.00\""
            )

    def _validate_created_ts(self) -> None:
        """created_ts must be host UTC ISO-8601 with a trailing ``Z``.

        The spec fixes this field as "host UTC ISO-8601 with Z" and it is hashed
        into the ledger, so we require the Zulu form (e.g.
        ``2026-06-08T21:40:03Z``, optional fractional seconds) and reject naive,
        offset (``+00:00``), or non-ISO strings. The shape regex is backed by a
        real ``strptime`` parse so impossible dates (month 13, day 32) are
        rejected too, not just mis-shaped ones.
        """
        if CREATED_TS_RE.match(self.created_ts) is None:
            raise ValueError(
                f"created_ts {self.created_ts!r} must be UTC ISO-8601 with a 'Z' "
                "suffix, e.g. '2026-06-08T21:40:03Z'"
            )
        # Strip the trailing 'Z' (regex-guaranteed) and any fractional seconds,
        # then parse to confirm the calendar/clock fields are real.
        core = self.created_ts[:-1].split(".")[0]
        try:
            datetime.strptime(core, "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            raise ValueError(
                f"created_ts {self.created_ts!r} is not a real UTC ISO-8601 timestamp"
            )

    @staticmethod
    def _validate_provenance_ref(ref: ProvenanceRef, index: int) -> None:
        """A ProvenanceRef must be well-formed (and memory-locator structured)."""
        if not isinstance(ref, ProvenanceRef):
            raise ValueError(f"provenance[{index}] must be a ProvenanceRef")
        # Required string fields present and non-empty.
        for name in ("receipt_id", "tool", "artifact_path", "locator"):
            val = getattr(ref, name)
            if not isinstance(val, str) or val == "":
                raise ValueError(
                    f"provenance[{index}].{name} must be a non-empty string"
                )
        # byte_range: null OR [int, int] with 0 <= start <= end.
        br = ref.byte_range
        if br is not None:
            if (
                not isinstance(br, list)
                or len(br) != 2
                or not all(isinstance(b, int) and not isinstance(b, bool) for b in br)
            ):
                raise ValueError(
                    f"provenance[{index}].byte_range must be null or a [int, int] pair"
                )
            start, end = br
            if not (0 <= start <= end):
                raise ValueError(
                    f"provenance[{index}].byte_range must satisfy 0 <= start <= end"
                )

    def _validate_confirmed_independence(self) -> None:
        """confirmed REQUIRES >=2 INDEPENDENT provenance sources.

        "Independent" means: among the provenance refs there exist at least two
        whose ``receipt_id`` values differ AND whose ``(artifact_path,
        evidence_type)`` source does not collapse to the same artifact — i.e.
        two sources that do not reduce to the same receipt or the same artifact.

        Concretely we require BOTH:
          * at least two DISTINCT ``receipt_id`` values, AND
          * at least two DISTINCT ``(artifact_path, evidence_type)`` sources.
        Two refs from the same receipt, or all refs from the same artifact, are
        therefore NOT independent and a confirmed Finding is rejected.

        Equivalence note: because every ref in a single Finding shares one
        ``evidence_type``, requiring (>=2 distinct receipt_id) AND (>=2 distinct
        (artifact_path, evidence_type)) is provably equivalent to "there exists
        a PAIR of refs that differ in BOTH receipt_id AND artifact_path" — a set
        with no such pair must collapse to one shared receipt or one shared
        artifact. The two-set formulation is used because it yields precise,
        separable error messages (which constraint failed) while being exactly
        as strict as the pairwise definition.
        """
        if len(self.provenance) < 2:
            raise ValueError(
                "status=confirmed requires >=2 independent provenance sources "
                f"(have {len(self.provenance)})"
            )
        distinct_receipts = {ref.receipt_id for ref in self.provenance}
        if len(distinct_receipts) < 2:
            raise ValueError(
                "status=confirmed requires >=2 INDEPENDENT provenance sources: "
                "all provenance refs share the same receipt_id"
            )
        distinct_artifacts = {
            (ref.artifact_path, self.evidence_type.value) for ref in self.provenance
        }
        if len(distinct_artifacts) < 2:
            raise ValueError(
                "status=confirmed requires >=2 INDEPENDENT provenance sources: "
                "all provenance refs collapse to the same artifact/evidence_type"
            )

    # =========================================================================
    # Memory-locator helper.
    # =========================================================================
    @staticmethod
    def is_structured_memory_locator(locator: str) -> bool:
        """True iff ``locator`` is the structured pid-tuple form for memory.

        Requires all of ``pid``, ``ppid``, ``create_time``, ``offset`` to be
        present as ``key=value`` components (``;``-separated, order-independent),
        each with a **non-empty** value. A bare integer PID (``"4711"``) or a
        partial tuple (missing ``offset``, say) is rejected.
        """
        if not isinstance(locator, str) or not locator:
            return False
        found: dict[str, str] = {}
        for part in locator.split(";"):
            key, sep, value = part.partition("=")
            if sep:
                found[key.strip()] = value.strip()
        return all(found.get(key) for key in _MEMORY_LOCATOR_KEYS)

    # =========================================================================
    # Presentation guard.
    # =========================================================================
    def is_presentable_as_fact(self) -> bool:
        """Only ``confirmed`` findings may be presented as established fact.

        ``insufficient_evidence`` / ``rejected`` (and ``inferred``) are valid
        Findings but MUST NOT be treated as confirmed fact.
        """
        return self.status is Status.confirmed

    # =========================================================================
    # Canonical serialization — sorted keys, no floats, ints stay ints.
    # =========================================================================
    def to_dict(self) -> dict[str, Any]:
        """Return a canonical, JSON-ready dict.

        Enums become their string value; ``confidence`` stays a fixed-decimal
        string; ``byte_range`` stays list[int]|null; nested provenance dicts are
        canonical. Key ordering is handled at JSON time via ``sort_keys=True``.
        """
        return {
            "id": self.id,
            "claim": self.claim,
            "status": self.status.value,
            "confidence": self.confidence,
            "evidence_type": self.evidence_type.value,
            "provenance": [ref.to_dict() for ref in self.provenance],
            "extracted_literals": list(self.extracted_literals),
            "attack_mapping": self.attack_mapping,
            "step_id": self.step_id,
            "supersedes": self.supersedes,
            "created_ts": self.created_ts,
            "verifier_notes": self.verifier_notes,
        }

    def to_json(self) -> str:
        """Canonical JSON string: sorted keys, ASCII-only, no NaN/Infinity.

        ``allow_nan=False`` guarantees we never emit ``NaN``/``Infinity``; since
        we carry no floats at all, the output is a stable, hashable byte string.
        """
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        """Reconstruct a Finding from its canonical dict (round-trip safe).

        ``from_dict(json.loads(f.to_json()))`` rebuilds an equal Finding whose
        ``to_json()`` is byte-identical to the original.
        """
        return cls(
            id=data["id"],
            claim=data["claim"],
            status=Status(data["status"]),
            confidence=data["confidence"],
            evidence_type=EvidenceType(data["evidence_type"]),
            provenance=[ProvenanceRef.from_dict(p) for p in data.get("provenance", [])],
            extracted_literals=list(data.get("extracted_literals", [])),
            attack_mapping=data.get("attack_mapping"),
            step_id=data.get("step_id"),
            supersedes=data.get("supersedes"),
            created_ts=data["created_ts"],
            verifier_notes=data.get("verifier_notes"),
        )

    @classmethod
    def from_json(cls, text: str) -> Finding:
        """Reconstruct a Finding from a canonical JSON string."""
        return cls.from_dict(json.loads(text))
