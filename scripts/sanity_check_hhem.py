#!/usr/bin/env python3
"""Sanity-check the HHEM-2.1 over-reach gate on FORENSIC prose.

HHEM is trained on general-domain RAG text (AggreFact / RAGTruth), so before we
trust it as the entailment axis we prove it separates *supported* claims from
*over-reach* on forensic-tool output. Runs fully offline against the pinned,
cached model. If supported vs over-reach do NOT separate, this prints a clear
OUT-OF-DISTRIBUTION warning and recommends keeping the literal hard gate + the
LLM-judge fallback.
"""
from __future__ import annotations

import os
import sys

_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from sift_agent import over_reach  # noqa: E402

# A realistic Amcache (InventoryApplicationFile) row — PRESENCE, not execution.
AMCACHE = (
    "Amcache.hve  InventoryApplicationFile  "
    "Name: winrar.exe  "
    "FullPath: C:\\Program Files\\WinRAR\\winrar.exe  "
    "SHA1: 1a2b3c4d5e6f7081a2b3c4d5e6f7081a2b3c4d5e  "
    "LinkDate: 2019-02-13 11:04:33"
)

# A cited registry Run-key value (innocuous data) — the baseline over-reach.
REG_RUN = (
    "Registry  HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run  "
    "Value: OneDriveSetup  "
    "Data: C:\\Windows\\System32\\OneDriveSetup.exe /thfirstsetup  "
    "LastWrite: 2021-08-02 14:55:10Z"
)

# (label, expectation, premise, hypothesis)
CASES = [
    # --- the three required checks --------------------------------------------
    ("SUPPORTED   (presence)", "HIGH", AMCACHE,
     "winrar.exe is present in Amcache."),
    ("OVER-REACH  (execution)", "LOW", AMCACHE,
     "winrar.exe was executed."),
    ("BASELINE    (C2 leap)", "LOW", REG_RUN,
     "Therefore this registry value establishes C2 persistence."),
    # --- extra contrasts to show the axis is meaningful, not luck -------------
    ("SUPPORTED   (installed)", "HIGH", AMCACHE,
     "WinRAR is recorded in the Amcache application inventory."),
    ("SUPPORTED   (run value)", "HIGH", REG_RUN,
     "A Run key value named OneDriveSetup points to OneDriveSetup.exe."),
    ("OVER-REACH  (path lie)", "LOW", AMCACHE,
     "winrar.exe was installed in C:\\Temp\\malware."),
]


def main() -> int:
    info = over_reach.model_info()
    print("=== HHEM-2.1 over-reach gate — forensic sanity check ===")
    print(f"model     : {info['model']}  ({info['repo']}@{info['revision']})")
    print(f"offline   : {info['offline']}   cache: {info['cache_dir']}")
    print(f"available : {info['available']}   default threshold: {info['default_threshold']}")
    if not info["available"]:
        print("\nHHEM NOT AVAILABLE — run scripts/fetch_hhem.py once (online) first.")
        return 2

    thr = over_reach.default_threshold()
    print(f"\n{'case':<26}{'expect':<8}{'score':>8}  {'verdict':<10} claim")
    print("-" * 100)

    rows = []
    for label, expect, premise, hyp in CASES:
        score = over_reach.over_reach_score(premise, hyp)
        verdict = "supported" if score >= thr else "OVER-REACH"
        ok = (expect == "HIGH" and score >= thr) or (expect == "LOW" and score < thr)
        rows.append((label, expect, score, ok))
        print(f"{label:<26}{expect:<8}{score:>8.3f}  {verdict:<10} {'OK' if ok else 'MISS':<4} {hyp}")

    supported = [s for (_, e, s, _) in rows if e == "HIGH"]
    overreach = [s for (_, e, s, _) in rows if e == "LOW"]
    min_sup, max_over = min(supported), max(overreach)
    gap = min_sup - max_over
    all_ok = all(ok for (_, _, _, ok) in rows)

    print("-" * 100)
    print(f"supported scores : {[round(s,3) for s in supported]}  (min {min_sup:.3f})")
    print(f"over-reach scores: {[round(s,3) for s in overreach]}  (max {max_over:.3f})")
    print(f"separation gap (min_supported - max_overreach): {gap:+.3f}")
    print(f"threshold {thr:.2f} classifies every case correctly: {all_ok}")

    if all_ok and gap > 0:
        print("\nRESULT: supported vs over-reach SEPARATE CLEANLY on forensic prose. "
              "HHEM is fit as the entailment axis (literal hard gate still primary).")
        return 0
    print("\nRESULT: supported vs over-reach DO NOT separate cleanly — POSSIBLE "
          "OUT-OF-DISTRIBUTION behaviour on forensic text.\n"
          "RECOMMENDATION: keep the literal-receipt match as the hard gate and "
          "retain the LLM-judge entailment fallback; treat HHEM as advisory only "
          "and re-tune the threshold (Day 5).")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
