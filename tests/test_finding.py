"""Tests for the Finding evidence card (``sift_agent.finding``).

Covers the required cases from the component spec:
  1. a 2-source CONFIRMED Finding passes validate();
  2. a 1-source CONFIRMED Finding is REJECTED by validate();
  3. to_json() round-trips byte-identically (canonical).
Plus: confidence-string validation, confirmed-needs-literals, memory-locator
pid-tuple enforcement, two-confirmed-from-the-same-receipt rejected,
insufficient_evidence accepted, and canonical no-floats.

conftest.py already puts ``src/`` on sys.path.
"""

import json

import pytest

from sift_agent.finding import (
    CONFIDENCE_RE,
    CREATED_TS_RE,
    EvidenceType,
    Finding,
    ProvenanceRef,
    Status,
)


# =============================================================================
# Builders — keep each test focused on the one rule it exercises.
# =============================================================================
def _disk_ref(receipt_id="rcpt-mft-01", artifact_path="/cases/img/MFT.csv"):
    """A well-formed disk ProvenanceRef (native MFT-record locator)."""
    return ProvenanceRef(
        receipt_id=receipt_id,
        tool="MFTECmd",
        artifact_path=artifact_path,
        locator="MFT_record=237",
        byte_range=[0, 512],
    )


def _evtx_ref(receipt_id="rcpt-evtx-09", artifact_path="/cases/img/Security.evtx.csv"):
    """A second, independent well-formed disk ProvenanceRef (EVTX locator)."""
    return ProvenanceRef(
        receipt_id=receipt_id,
        tool="EvtxECmd",
        artifact_path=artifact_path,
        locator="EventRecordID=44871",
        byte_range=[1024, 2048],
    )


def _memory_ref(receipt_id="rcpt-vol-03"):
    """A well-formed MEMORY ProvenanceRef with a structured pid-tuple locator."""
    return ProvenanceRef(
        receipt_id=receipt_id,
        tool="vol windows.pslist",
        artifact_path="/cases/mem/win10.raw",
        locator="pid=4012;ppid=712;create_time=2020-11-13T14:02:11Z;offset=0xe000a1b2c000",
        byte_range=None,
    )


def _confirmed_two_source():
    """A confirmed Finding backed by two independent disk sources."""
    return Finding(
        claim="winrar.exe executed 2020-11-13T14:02:11Z",
        status=Status.confirmed,
        confidence="0.95",
        evidence_type=EvidenceType.disk,
        provenance=[_disk_ref(), _evtx_ref()],
        extracted_literals=[
            "C:\\Users\\jsmith\\Desktop\\winrar.exe",
            "2020-11-13T14:02:11Z",
        ],
        attack_mapping="T1204.002",
        step_id="step-07-program-execution",
        id="finding-0001",
        created_ts="2026-06-08T21:40:03Z",
    )


# =============================================================================
# 1. Required: a 2-source CONFIRMED Finding passes validate().
# =============================================================================
def test_two_source_confirmed_passes():
    f = _confirmed_two_source()
    assert f.validate() is None  # returns None on success
    assert f.is_presentable_as_fact() is True


# =============================================================================
# 2. Required: a 1-source CONFIRMED Finding is REJECTED.
# =============================================================================
def test_one_source_confirmed_rejected():
    f = Finding(
        claim="winrar.exe executed 2020-11-13T14:02:11Z",
        status=Status.confirmed,
        confidence="0.90",
        evidence_type=EvidenceType.disk,
        provenance=[_disk_ref()],  # only ONE source
        extracted_literals=["winrar.exe"],
    )
    with pytest.raises(ValueError, match=r">=2 independent provenance"):
        f.validate()


# =============================================================================
# 3. Required: to_json() round-trips byte-identically (canonical).
# =============================================================================
def test_to_json_roundtrip_byte_identical():
    f = _confirmed_two_source()
    f.validate()

    s1 = f.to_json()
    obj2 = Finding.from_dict(json.loads(s1))
    s2 = obj2.to_json()

    assert s1 == s2  # byte-identical
    obj2.validate()  # the reconstruction is itself valid

    # Canonical guarantees: sorted keys + ASCII-only.
    parsed = json.loads(s1)
    assert list(parsed.keys()) == sorted(parsed.keys())
    assert s1 == s1.encode("ascii").decode("ascii")


def test_from_json_roundtrip_byte_identical():
    """from_json(to_json(...)) also reconstructs a byte-identical Finding."""
    f = _confirmed_two_source()
    s1 = f.to_json()
    assert Finding.from_json(s1).to_json() == s1


def test_roundtrip_with_memory_and_nulls():
    """Round-trip a memory Finding carrying None metadata + null byte_range."""
    f = Finding(
        claim="malicious svchost masquerade in memory",
        status=Status.inferred,
        confidence="0.60",
        evidence_type=EvidenceType.memory,
        provenance=[_memory_ref()],
        extracted_literals=[
            "pid=4012;ppid=712;create_time=2020-11-13T14:02:11Z;offset=0xe000a1b2c000",
        ],
        attack_mapping=None,
        step_id=None,
        supersedes=None,
        verifier_notes=None,
        id="finding-mem-1",
        created_ts="2026-06-08T21:41:00Z",
    )
    f.validate()
    s1 = f.to_json()
    s2 = Finding.from_dict(json.loads(s1)).to_json()
    assert s1 == s2
    # null byte_range survives as JSON null, not a float or string.
    assert json.loads(s1)["provenance"][0]["byte_range"] is None


# =============================================================================
# confidence-string validation
# =============================================================================
@pytest.mark.parametrize("good", ["0.00", "0.01", "0.50", "0.99", "1.00"])
def test_confidence_valid_strings(good):
    assert CONFIDENCE_RE.match(good)
    f = _confirmed_two_source()
    f.confidence = good
    assert f.validate() is None


@pytest.mark.parametrize(
    "bad",
    ["1.01", "1.50", "1.99", "2.00", "0.5", "0.123", ".50", "1", "01.00", "0,50", "abc", ""],
)
def test_confidence_malformed_or_out_of_range_rejected(bad):
    f = _confirmed_two_source()
    f.confidence = bad
    with pytest.raises(ValueError, match=r"confidence"):
        f.validate()


def test_confidence_float_rejected():
    """A real float (not a string) must be rejected — it is not hash-stable."""
    f = _confirmed_two_source()
    f.confidence = 0.95  # type: ignore[assignment]
    with pytest.raises(ValueError, match=r"confidence must be a fixed-decimal string"):
        f.validate()


def test_confidence_bool_rejected():
    """A bool (subclass of int) must NOT sneak past the confidence check."""
    f = _confirmed_two_source()
    f.confidence = True  # type: ignore[assignment]
    with pytest.raises(ValueError, match=r"confidence must be a fixed-decimal string"):
        f.validate()


def test_confidence_boundaries_inclusive():
    """Both boundary strings "0.00" and "1.00" are accepted; "1.01" is not."""
    f = _confirmed_two_source()
    for ok in ("0.00", "1.00"):
        f.confidence = ok
        assert f.validate() is None
    f.confidence = "1.01"
    with pytest.raises(ValueError, match=r"confidence"):
        f.validate()


# =============================================================================
# confirmed/inferred require non-empty extracted_literals
# =============================================================================
def test_confirmed_needs_literals():
    f = _confirmed_two_source()
    f.extracted_literals = []
    with pytest.raises(ValueError, match=r"requires non-empty extracted_literals"):
        f.validate()


def test_inferred_needs_provenance_and_literals():
    f = Finding(
        claim="lateral movement suspected",
        status=Status.inferred,
        confidence="0.40",
        evidence_type=EvidenceType.disk,
        provenance=[],  # empty
        extracted_literals=[],
    )
    with pytest.raises(ValueError, match=r"requires non-empty provenance"):
        f.validate()


def test_inferred_with_provenance_but_no_literals_rejected():
    f = Finding(
        claim="lateral movement suspected",
        status=Status.inferred,
        confidence="0.40",
        evidence_type=EvidenceType.disk,
        provenance=[_disk_ref()],
        extracted_literals=[],  # empty literals
    )
    with pytest.raises(ValueError, match=r"requires non-empty extracted_literals"):
        f.validate()


# =============================================================================
# memory-locator pid-tuple enforcement
# =============================================================================
def test_memory_locator_must_be_structured_pid_tuple():
    """A bare integer PID for MEMORY evidence is rejected."""
    bad = ProvenanceRef(
        receipt_id="rcpt-vol-03",
        tool="vol windows.pslist",
        artifact_path="/cases/mem/win10.raw",
        locator="4012",  # bare PID — NOT the structured tuple
        byte_range=None,
    )
    f = Finding(
        claim="suspicious process in memory",
        status=Status.inferred,
        confidence="0.55",
        evidence_type=EvidenceType.memory,
        provenance=[bad],
        extracted_literals=["4012"],
    )
    with pytest.raises(ValueError, match=r"structured pid-tuple"):
        f.validate()


def test_memory_locator_partial_tuple_rejected():
    """A pid-tuple missing the 'offset' component is rejected for memory."""
    partial = ProvenanceRef(
        receipt_id="rcpt-vol-03",
        tool="vol windows.pslist",
        artifact_path="/cases/mem/win10.raw",
        locator="pid=4012;ppid=712;create_time=2020-11-13T14:02:11Z",  # no offset
        byte_range=None,
    )
    f = Finding(
        claim="suspicious process in memory",
        status=Status.inferred,
        confidence="0.55",
        evidence_type=EvidenceType.memory,
        provenance=[partial],
        extracted_literals=["pid=4012"],
    )
    with pytest.raises(ValueError, match=r"structured pid-tuple"):
        f.validate()


def test_memory_locator_empty_component_value_rejected():
    """A pid-tuple with an empty value (offset=) is rejected for memory."""
    empty_val = ProvenanceRef(
        receipt_id="rcpt-vol-03",
        tool="vol windows.pslist",
        artifact_path="/cases/mem/win10.raw",
        locator="pid=4012;ppid=712;create_time=2020-11-13T14:02:11Z;offset=",
        byte_range=None,
    )
    f = Finding(
        claim="suspicious process in memory",
        status=Status.inferred,
        confidence="0.55",
        evidence_type=EvidenceType.memory,
        provenance=[empty_val],
        extracted_literals=["pid=4012"],
    )
    with pytest.raises(ValueError, match=r"structured pid-tuple"):
        f.validate()


def test_memory_locator_structured_accepted():
    f = Finding(
        claim="suspicious process in memory",
        status=Status.inferred,
        confidence="0.55",
        evidence_type=EvidenceType.memory,
        provenance=[_memory_ref()],
        extracted_literals=["pid=4012;ppid=712;create_time=2020-11-13T14:02:11Z;offset=0xe000a1b2c000"],
    )
    assert f.validate() is None
    assert Finding.is_structured_memory_locator(_memory_ref().locator) is True
    assert Finding.is_structured_memory_locator("4012") is False


def test_memory_locator_order_independent():
    """The structured-locator detector is component-order-independent."""
    assert Finding.is_structured_memory_locator(
        "offset=0x0;create_time=t;ppid=2;pid=1"
    ) is True


def test_disk_evidence_does_not_require_pid_tuple():
    """A bare native locator is fine for DISK evidence (pid-tuple rule is memory-only)."""
    f = Finding(
        claim="file present on disk",
        status=Status.inferred,
        confidence="0.30",
        evidence_type=EvidenceType.disk,
        provenance=[_disk_ref()],  # locator="MFT_record=237"
        extracted_literals=["MFT_record=237"],
    )
    assert f.validate() is None


# =============================================================================
# two confirmed sources from the SAME receipt are rejected (not independent)
# =============================================================================
def test_two_confirmed_from_same_receipt_rejected():
    """Two refs with the same receipt_id do not constitute independent sources."""
    ref_a = _disk_ref(receipt_id="rcpt-shared", artifact_path="/cases/img/MFT.csv")
    ref_b = _evtx_ref(receipt_id="rcpt-shared", artifact_path="/cases/img/Security.evtx.csv")
    f = Finding(
        claim="winrar.exe executed",
        status=Status.confirmed,
        confidence="0.90",
        evidence_type=EvidenceType.disk,
        provenance=[ref_a, ref_b],
        extracted_literals=["winrar.exe"],
    )
    with pytest.raises(ValueError, match=r"same receipt_id"):
        f.validate()


def test_two_confirmed_from_same_artifact_rejected():
    """Two refs from distinct receipts but the SAME artifact are not independent."""
    ref_a = _disk_ref(receipt_id="rcpt-a", artifact_path="/cases/img/MFT.csv")
    ref_b = _disk_ref(receipt_id="rcpt-b", artifact_path="/cases/img/MFT.csv")
    f = Finding(
        claim="winrar.exe executed",
        status=Status.confirmed,
        confidence="0.90",
        evidence_type=EvidenceType.disk,
        provenance=[ref_a, ref_b],
        extracted_literals=["winrar.exe"],
    )
    with pytest.raises(ValueError, match=r"same artifact/evidence_type"):
        f.validate()


def test_three_refs_with_one_independent_pair_accepted():
    """A confirmed Finding with >2 refs passes iff a jointly-independent pair exists.

    refs: (r1,art1), (r1,art2), (r2,art1). The pair (r1,art2)/(r2,art1) differs
    in BOTH receipt and artifact, so this is valid. Verifies the two-set check
    is exactly as strict as the pairwise definition (no false rejection).
    """
    ref_a = _disk_ref(receipt_id="r1", artifact_path="/cases/img/MFT.csv")
    ref_b = _evtx_ref(receipt_id="r1", artifact_path="/cases/img/Security.evtx.csv")
    ref_c = _disk_ref(receipt_id="r2", artifact_path="/cases/img/MFT.csv")
    f = Finding(
        claim="winrar.exe executed",
        status=Status.confirmed,
        confidence="0.90",
        evidence_type=EvidenceType.disk,
        provenance=[ref_a, ref_b, ref_c],
        extracted_literals=["winrar.exe"],
    )
    assert f.validate() is None


# =============================================================================
# insufficient_evidence / rejected: accepted even with weak/no provenance,
# but never presentable as fact.
# =============================================================================
def test_insufficient_evidence_accepted_with_no_provenance():
    f = Finding(
        claim="possible anti-forensics; inconclusive",
        status=Status.insufficient_evidence,
        confidence="0.10",
        evidence_type=EvidenceType.disk,
        provenance=[],
        extracted_literals=[],
    )
    assert f.validate() is None
    assert f.is_presentable_as_fact() is False


def test_rejected_accepted_and_not_a_fact():
    f = Finding(
        claim="hypothesis disproven by timeline",
        status=Status.rejected,
        confidence="0.00",
        evidence_type=EvidenceType.cross,
        provenance=[],
        extracted_literals=[],
        supersedes="finding-0001",
    )
    assert f.validate() is None
    assert f.is_presentable_as_fact() is False


def test_inferred_is_not_presentable_as_fact():
    """Only confirmed is a fact; inferred (though valid) is not."""
    f = _confirmed_two_source()
    f.status = Status.inferred
    assert f.validate() is None
    assert f.is_presentable_as_fact() is False


# =============================================================================
# canonical: no floats anywhere in the serialized output; ints stay ints.
# =============================================================================
def test_canonical_no_floats():
    f = _confirmed_two_source()
    s = f.to_json()

    # Parsing back, confidence is a STRING and byte_range entries are ints.
    parsed = json.loads(s)
    assert isinstance(parsed["confidence"], str)
    for ref in parsed["provenance"]:
        br = ref["byte_range"]
        if br is not None:
            assert all(isinstance(b, int) and not isinstance(b, bool) for b in br)

    # No float literal anywhere in the canonical text.
    def _no_floats(obj):
        if isinstance(obj, float):
            raise AssertionError(f"float found in canonical output: {obj!r}")
        if isinstance(obj, dict):
            for v in obj.values():
                _no_floats(v)
        elif isinstance(obj, list):
            for v in obj:
                _no_floats(v)

    _no_floats(json.loads(s, parse_float=lambda x: (_ for _ in ()).throw(
        AssertionError(f"JSON contained a float token: {x}")
    )))


def test_to_json_rejects_nan_and_infinity_by_construction():
    """allow_nan=False is in force; confidence can never be NaN (it's a string)."""
    f = _confirmed_two_source()
    # Sanity: separators are compact and keys sorted (stable for hashing).
    s = f.to_json()
    assert ", " not in s and ": " not in s  # compact separators
    assert s.index('"claim"') < s.index('"confidence"') < s.index('"status"')


# =============================================================================
# defaults: id + created_ts auto-generate
# =============================================================================
def test_defaults_autogenerate_id_and_ts():
    f = Finding(
        claim="x",
        status=Status.inferred,
        confidence="0.30",
        evidence_type=EvidenceType.disk,
        provenance=[_disk_ref()],
        extracted_literals=["x"],
    )
    assert isinstance(f.id, str) and len(f.id) > 0
    # created_ts is host UTC ISO-8601 with a Z suffix.
    assert f.created_ts.endswith("Z")
    assert f.validate() is None


def test_distinct_findings_get_distinct_ids():
    a = Finding(claim="a", status=Status.inferred, confidence="0.30",
                evidence_type=EvidenceType.disk, provenance=[_disk_ref()],
                extracted_literals=["a"])
    b = Finding(claim="b", status=Status.inferred, confidence="0.30",
                evidence_type=EvidenceType.disk, provenance=[_disk_ref()],
                extracted_literals=["b"])
    assert a.id != b.id


# =============================================================================
# wrong-type guards on enums and provenance container
# =============================================================================
def test_status_must_be_enum():
    f = _confirmed_two_source()
    f.status = "confirmed"  # type: ignore[assignment]  (a bare str, not the enum)
    with pytest.raises(ValueError, match=r"status must be a Status enum"):
        f.validate()


def test_evidence_type_must_be_enum():
    f = _confirmed_two_source()
    f.evidence_type = "disk"  # type: ignore[assignment]
    with pytest.raises(ValueError, match=r"evidence_type must be an EvidenceType enum"):
        f.validate()


def test_provenance_entry_must_be_provenanceref():
    f = Finding(
        claim="x",
        status=Status.inferred,
        confidence="0.30",
        evidence_type=EvidenceType.disk,
        provenance=[{"receipt_id": "r"}],  # type: ignore[list-item]  a dict, not a ref
        extracted_literals=["x"],
    )
    with pytest.raises(ValueError, match=r"must be a ProvenanceRef"):
        f.validate()


@pytest.mark.parametrize("field_name", ["receipt_id", "tool", "artifact_path", "locator"])
def test_provenance_required_string_fields(field_name):
    ref = _disk_ref()
    setattr(ref, field_name, "")  # blank out one required field
    f = Finding(
        claim="x",
        status=Status.inferred,
        confidence="0.30",
        evidence_type=EvidenceType.disk,
        provenance=[ref],
        extracted_literals=["x"],
    )
    with pytest.raises(ValueError, match=field_name):
        f.validate()


# =============================================================================
# malformed byte_range rejected; well-formed boundary accepted
# =============================================================================
@pytest.mark.parametrize(
    "br",
    [[5, 1], [-1, 10], [0], [0, 1, 2], [0.0, 1.0], "0,1", [True, False]],
)
def test_byte_range_malformed_rejected(br):
    ref = ProvenanceRef(
        receipt_id="rcpt-a",
        tool="MFTECmd",
        artifact_path="/cases/img/MFT.csv",
        locator="MFT_record=1",
        byte_range=br,  # type: ignore[arg-type]
    )
    f = Finding(
        claim="x",
        status=Status.inferred,
        confidence="0.30",
        evidence_type=EvidenceType.disk,
        provenance=[ref],
        extracted_literals=["x"],
    )
    with pytest.raises(ValueError, match=r"byte_range"):
        f.validate()


def test_byte_range_zero_width_accepted():
    """start == end is allowed (0 <= start <= end)."""
    ref = ProvenanceRef(
        receipt_id="rcpt-a",
        tool="MFTECmd",
        artifact_path="/cases/img/MFT.csv",
        locator="MFT_record=1",
        byte_range=[10, 10],
    )
    f = Finding(
        claim="x",
        status=Status.inferred,
        confidence="0.30",
        evidence_type=EvidenceType.disk,
        provenance=[ref],
        extracted_literals=["x"],
    )
    assert f.validate() is None


# =============================================================================
# extracted_literals must be a list of strings
# =============================================================================
def test_extracted_literals_must_be_strings():
    f = _confirmed_two_source()
    f.extracted_literals = ["ok", 1234]  # type: ignore[list-item]
    with pytest.raises(ValueError, match=r"extracted_literals must be a list of strings"):
        f.validate()


# =============================================================================
# created_ts: host UTC ISO-8601 with a trailing 'Z' (the only canonical,
# hashable timestamp shape). Naive / offset / impossible dates are rejected.
# =============================================================================
@pytest.mark.parametrize(
    "good_ts",
    ["2026-06-08T21:40:03Z", "2026-06-08T21:40:03.123456Z", "2020-11-13T14:02:11Z"],
)
def test_created_ts_valid_iso_z_accepted(good_ts):
    assert CREATED_TS_RE.match(good_ts)
    f = _confirmed_two_source()
    f.created_ts = good_ts
    assert f.validate() is None


@pytest.mark.parametrize(
    "bad_ts",
    [
        "2026-06-08T21:40:03",        # no Z (naive)
        "2026-06-08T21:40:03+00:00",  # offset, not Zulu
        "2026-06-08 21:40:03Z",       # space instead of 'T'
        "2026-06-08T21:40:03z",       # lowercase z
        "06/08/2026",                 # not ISO at all
        "2026-13-08T00:00:00Z",       # impossible month (shape ok, strptime fails)
        "2026-06-31T00:00:00Z",       # impossible day
        "not-a-timestamp",
        "",                           # empty (caught by the non-empty guard)
    ],
)
def test_created_ts_malformed_or_non_zulu_rejected(bad_ts):
    f = _confirmed_two_source()
    f.created_ts = bad_ts
    with pytest.raises(ValueError, match=r"created_ts"):
        f.validate()


def test_default_created_ts_is_valid_iso_z():
    """The auto-generated created_ts passes its own validation."""
    f = Finding(
        claim="x",
        status=Status.inferred,
        confidence="0.30",
        evidence_type=EvidenceType.disk,
        provenance=[_disk_ref()],
        extracted_literals=["x"],
    )
    assert CREATED_TS_RE.match(f.created_ts)
    assert f.validate() is None


# =============================================================================
# REGRESSION (adversarial verify): the `$` regex anchor in Python also matches
# just before a trailing newline, so "1.00\n" / "...Z\n" used to slip past
# CONFIDENCE_RE / CREATED_TS_RE (and Decimal() tolerates trailing whitespace) —
# two Findings asserting the same value would then hash differently. Anchored
# with \A..\Z, these MUST now be rejected. See finding.py regex notes.
# =============================================================================
@pytest.mark.parametrize("bad", ["1.00\n", "0.50\n", "0.00\n", "0.95\n", "1.00\r\n"])
def test_confidence_trailing_newline_rejected(bad):
    assert CONFIDENCE_RE.match(bad) is None  # the regex itself rejects it
    f = _confirmed_two_source()
    f.confidence = bad
    with pytest.raises(ValueError, match=r"confidence"):
        f.validate()


@pytest.mark.parametrize(
    "bad",
    ["2026-06-08T21:40:03Z\n", "2026-06-08T21:40:03.5Z\n", "2026-06-08T21:40:03.123456Z\n"],
)
def test_created_ts_trailing_newline_rejected(bad):
    assert CREATED_TS_RE.match(bad) is None
    f = _confirmed_two_source()
    f.created_ts = bad
    with pytest.raises(ValueError, match=r"created_ts"):
        f.validate()
