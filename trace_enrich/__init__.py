"""Protocol SIFT trace-enrichment package.

Post-run, measurement-only enrichment of a finished investigation's Braintrust
trace. Reads the trace + the raw-bash log + the case input + the report, applies
the static SKILL.md registry, and writes labels/scores BACK onto the existing
Braintrust spans (deep-merge via ``_is_merge``). It does NOT change how the agent
runs — this is "Fix A" (deterministic).

Public modules:
    registry    — tool -> skill / phase mapping (stdlib, no network).
    bashlog     — raw-bash log loader + per-call outcome classifier.
    provenance  — IOC -> tool/case-input provenance (reuses scoring/scorer.py).
    bt_client   — Braintrust read + per-span/root merge over urllib (BT_API_KEY).
    enrich      — the orchestrator + CLI (``python3 -m trace_enrich.enrich``).
"""
