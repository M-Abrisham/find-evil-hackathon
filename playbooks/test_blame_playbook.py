#!/usr/bin/env python3
"""Self-contained tests for blame_playbook.py (stdlib only; no network, no real cases).

Run:  python3 playbooks/test_blame_playbook.py
"""
from __future__ import annotations

import copy
import json
import pathlib
import sys
import tempfile
import types

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import blame_playbook as bp  # noqa: E402

CONTRACT_PB = """---
attack_type: data-exfiltration-insider
category_id: data-exfiltration-insider
name: Test
description: test
version: 2
maturity: draft
---

## Steps

- n: 3
  tool: |
    foo
  emits: [key_iocs]

- n: 5
  tool: |
    bar
  emits: [timeline_events, key_artifacts]
"""

NONCONTRACT_PB = """---
attack_type: ransomware-destructive
name: Test
maturity: draft
---

## Steps

1. **Do a thing.** prose only, no machine step, no version, no emits.
"""

EVAL_SCORE = {
    "case_id": "T-001",
    "classification": {"predicted_category": "malware", "truth_category": "data-exfiltration",
                       "category_match": False, "subtype_match": False},
    "evidence": {
        "false_positives": 1, "false_positive_rate": 0.2,
        "false_positive_findings": ["bogus claim"],
        "per_bucket": {"key_iocs": {"recall": 0.0}, "timeline_events": {"recall": 0.5}},
        "missed_evidence": {
            "key_iocs": ["the exfil server IP"],
            "timeline_events": ["the 02:14 archive creation"],
            "key_artifacts": [], "actor_accounts": [], "exfil_or_encryption_facts": [],
        },
    },
    "hallucination": {"unbacked_findings": 2, "hallucination_rate": 0.3,
                      "unbacked_list": [{"id": "f1", "claim": "made up"}]},
    "headline": {"category_match": False},
}

IOC_SCORE = {
    "cases": [{
        "case_id": "T-001", "verdict": "not_emitted", "verdict_expected": "MALICE",
        "fabrication_count": 1, "fabrications": [{"type": "email", "value": "x@y.z"}],
        "mitre_total": 3, "mitre_found": 1,
        "mitre_present": {"T1041": True, "T1048": False, "T1567": False},
        "failures": [{"type": "ip_address", "value": "10.0.0.9"}],
    }],
    "aggregate": {},
}

CLEAN_EVAL = {
    "case_id": "T-OK", "classification": {"category_match": True, "subtype_match": True},
    "evidence": {"false_positives": 0,
                 "missed_evidence": {b: [] for b in bp.SCORE_BUCKETS}, "per_bucket": {}},
    "hallucination": {"unbacked_findings": 0},
    "headline": {"category_match": True},
}

_PASS = 0
_FAIL = 0


def check(name: str, cond: bool, extra: str = ""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1
        print(f"  ok   {name}")
    else:
        _FAIL += 1
        print(f"  FAIL {name}  {extra}")


def write(d: pathlib.Path, name: str, obj) -> str:
    p = d / name
    if isinstance(obj, str):
        p.write_text(obj, encoding="utf-8")
    else:
        p.write_text(json.dumps(obj), encoding="utf-8")
    return str(p)


def args(**kw):
    base = dict(playbook=None, score=None, ioc_score=None, case_id="T-001", out="blame.json", dry_run=True)
    base.update(kw)
    return types.SimpleNamespace(**base)


def run():
    with tempfile.TemporaryDirectory() as td:
        d = pathlib.Path(td)
        pb_c = write(d, "contract.md", CONTRACT_PB)
        pb_n = write(d, "noncontract.md", NONCONTRACT_PB)
        ev = write(d, "score.json", EVAL_SCORE)
        ioc = write(d, "ioc.json", IOC_SCORE)
        clean = write(d, "clean.json", CLEAN_EVAL)

        # --- 1. both scorers + contract playbook ---
        print("[1] both scorers, contract playbook")
        b = bp.build_blame(args(playbook=pb_c, score=ev, ioc_score=ioc))
        w = b["worst_failure"]
        check("worst is verdict_absent", w["kind"] == "verdict_absent", str(w))
        check("worst severity 100", w["severity"] == 100)
        check("verdict routed to agent_config", w["route"] == "agent_config")
        kinds = [f["kind"] for f in b["ranked_failures"]]
        check("ranked order verdict>fabrication>hallucination>mitre",
              kinds[:4] == ["verdict_absent", "fabrication", "hallucination", "mitre_gap"], str(kinds))
        ta = {f["bucket"] for f in b["tune_actionable"]}
        check("tune_actionable = the two missed buckets", ta == {"key_iocs", "timeline_events"}, str(ta))
        kio = next(f for f in b["ranked_failures"] if f.get("bucket") == "key_iocs")
        check("key_iocs blamed to n=3", kio["blamed_steps"] == ["n=3"], str(kio["blamed_steps"]))
        check("key_iocs step-listed", kio["blame_type"] == "step-listed")
        tl = next(f for f in b["ranked_failures"] if f.get("bucket") == "timeline_events")
        check("timeline blamed to n=5", tl["blamed_steps"] == ["n=5"], str(tl["blamed_steps"]))
        check("tune_command present", b["tune_command"] is not None)
        check("tune_command targets tune_playbook",
              b["tune_command"][1].endswith("tune_playbook.py"), str(b["tune_command"]))
        check("contract_shaped True", b["diagnostics"]["playbook_contract_shaped"] is True)
        other = {f["kind"] for f in b["needs_other_fix"]}
        check("verdict+mitre+hallucination in needs_other_fix",
              {"verdict_absent", "mitre_gap", "hallucination"} <= other, str(other))
        check("no missed_evidence in needs_other_fix",
              all(f["kind"] != "missed_evidence" for f in b["needs_other_fix"]))

        # --- 2. non-contract playbook (no version, no emits) ---
        print("[2] both scorers, NON-contract playbook")
        b2 = bp.build_blame(args(playbook=pb_n, score=ev, ioc_score=ioc))
        check("contract_shaped False", b2["diagnostics"]["playbook_contract_shaped"] is False)
        check("tune_command suppressed", b2["tune_command"] is None)
        check("tune_blocked cites version", "version" in (b2["diagnostics"]["tune_blocked_reason"] or ""),
              str(b2["diagnostics"]["tune_blocked_reason"]))
        kio2 = next(f for f in b2["ranked_failures"] if f.get("bucket") == "key_iocs")
        check("missed bucket is author-gap (no emits)", kio2["blame_type"] == "author-gap"
              and kio2["blamed_steps"] == [], str(kio2))

        # --- 3. eval-only (no ioc): worst is the top eval-side failure ---
        print("[3] eval-only, contract playbook")
        b3 = bp.build_blame(args(playbook=pb_c, score=ev, ioc_score=None))
        check("eval-only worst is hallucination", b3["worst_failure"]["kind"] == "hallucination",
              str(b3["worst_failure"]["kind"]))
        check("eval-only ingested flags", b3["scores_ingested"] == {"eval_score": True, "ioc_score": False})
        check("eval-only tune_command present", b3["tune_command"] is not None)

        # --- 4. ioc-only ---
        print("[4] ioc-only, contract playbook")
        b4 = bp.build_blame(args(playbook=pb_c, score=None, ioc_score=ioc))
        check("ioc-only worst is verdict_absent", b4["worst_failure"]["kind"] == "verdict_absent")
        check("ioc-only no tune_command (no eval missed_evidence)", b4["tune_command"] is None)

        # --- 5. nothing to blame ---
        print("[5] clean eval score -> nothing to blame")
        b5 = bp.build_blame(args(playbook=pb_c, score=clean, ioc_score=None, case_id="T-OK"))
        check("zero failures", b5["failure_count"] == 0)
        check("no worst_failure", b5["worst_failure"] is None)

        # --- 6. anti-hallucination tripwire ---
        print("[6] provenance tripwire")
        b6 = bp.build_blame(args(playbook=pb_c, score=ev, ioc_score=ioc))
        check("clean blame passes provenance",
              bp.verify_provenance(b6, CONTRACT_PB, EVAL_SCORE, IOC_SCORE["cases"][0]) == [])
        check("clean blame marked provenance_verified",
              b6["diagnostics"]["provenance_verified"] is True)
        tam = copy.deepcopy(b6)
        mev = next(f for f in tam["ranked_failures"] if f.get("kind") == "missed_evidence")
        mev["items"].append("a finding the scorer never reported")
        mev["blamed_steps"].append("n=999")
        mit = next(f for f in tam["ranked_failures"] if f.get("kind") == "mitre_gap")
        mit["items"].append("T9999")
        probs = bp.verify_provenance(tam, CONTRACT_PB, EVAL_SCORE, IOC_SCORE["cases"][0])
        check("tripwire flags fabricated missed_item",
              any("fabricated missed_item" in p for p in probs), str(probs))
        check("tripwire flags nonexistent step", any("n=999" in p for p in probs), str(probs))
        check("tripwire flags fabricated mitre code",
              any("T9999" in p for p in probs), str(probs))

    print(f"\n{_PASS} passed, {_FAIL} failed")
    return 1 if _FAIL else 0


if __name__ == "__main__":
    sys.exit(run())
