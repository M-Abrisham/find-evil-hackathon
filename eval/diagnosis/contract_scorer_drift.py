#!/usr/bin/env python3
"""Contract <-> scorer DRIFT CHECK  (Rule-Change Diagnosis Protocol, tool #6).

``scorer.py`` HAND-MIRRORS two pieces of the deliverable contract:

  * ``VERDICT_CLASSES`` mirrors ``verdict.equivalence_classes`` in
    ``protocol-sift/contract/contract.yaml`` (the comment in both files literally
    says "keep the two in sync; Phase 6 unifies them").
  * ``_mitre_satisfied`` implements the one-directional parent<->sub credit rule
    that the contract states in prose under ``mitre.rules`` (a sub-technique
    entails its parent; a bare parent does NOT satisfy a specific sub; a sibling
    sub never stands in for another).

Because they are hand-mirrored, an edit to ``contract.yaml`` (vocabulary or
equivalence classes) that is NOT reflected in ``scorer.py`` — or vice versa —
silently makes the grader score against a STALE contract. If that happens during
a verdict/MITRE ablation lap, a measured rate delta could be a SCORER ARTIFACT,
not a real effect of the rule toggle (spec Stage 1.0 precondition / Stage 4.4
re-sync).

This tool re-derives the contract's intent from ``contract.yaml`` and compares it
to the live ``scorer.py`` mirror. On ANY divergence it prints a human-readable
diff and **exits non-zero** so a verdict/MITRE ablation lap (or CI) HARD-BLOCKS.

Checks performed
----------------
1. VERDICT-CLASS PARITY  — ``contract.verdict.equivalence_classes`` vs
   ``scorer.VERDICT_CLASSES``, compared under the SAME normalization the scorer
   applies at match time (``upper().replace("-", "_")``). Reports class-name
   drift and per-class member drift (added / removed tokens).
2. VOCABULARY COVERAGE  — every ``contract.verdict.vocabulary`` token must map to
   exactly one scorer class via ``scorer._verdict_class``. An uncovered vocab
   token means the agent may emit a contract-legal verdict that the scorer reads
   as ``not_emitted`` (silent false-negative verdict drift).
3. MITRE CREDIT-DIRECTION INVARIANTS  — behaviourally probes
   ``scorer._mitre_satisfied`` against the directional rules the contract states:
   exact match credited; GT-parent credited by a reported sub; GT-sub NOT
   credited by a bare reported parent; sibling sub never credits another sibling.
   A code edit that breaks the mirror (e.g. starts crediting parent->sub) trips
   this and blocks any MITRE lap.

stdlib-only by design (this is a HARD gate that must run anywhere, incl. a bare
CI box). The ``contract.yaml`` reader is a small, purpose-built parser for the
exact ``verdict.equivalence_classes`` / ``verdict.vocabulary`` block shapes — it
does NOT depend on PyYAML. If PyYAML happens to be importable it is used as a
cross-check, but it is never required.

Usage
-----
    python3 contract_scorer_drift.py \
        --contract /path/to/protocol-sift/contract/contract.yaml \
        --scorer-dir /path/to/contract-build/scoring

Exit codes:  0 = in sync (lap may proceed) · 2 = DRIFT (HARD-BLOCK) ·
             3 = could not load an input (treated as block — never silently pass).
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import re
import sys

_MODULE_NAME = "scorer_under_check"
from dataclasses import dataclass, field
from typing import Any


# =============================================================================
# Verdict-token normalization — MUST match scorer._verdict_class exactly:
#   token.strip().upper().replace("-", "_")
# Mirrored here (not imported) so the comparison is anchored to the documented
# contract semantics, not to whatever the scorer currently does; the scorer's
# own normaliser is exercised separately via the live _verdict_class probe.
# =============================================================================
def norm_verdict_token(tok: str) -> str:
    return tok.strip().upper().replace("-", "_")


def norm_class_members(members: Any) -> set[str]:
    return {norm_verdict_token(str(m)) for m in members}


# =============================================================================
# Minimal, purpose-built contract.yaml reader (stdlib-only).
#
# It parses ONLY the two blocks this gate needs, under the top-level `verdict:`
# mapping, both nested forms that appear in the contract:
#
#   verdict:
#     vocabulary:
#       - token: MALICE
#         meaning: ...
#       - token: NON_MALICE
#     equivalence_classes:
#       malicious:     [MALICE, MALICIOUS]
#       non_malicious: [NON_MALICE, NONMALICE, BENIGN]
#       inconclusive:  [INCONCLUSIVE, INDETERMINATE, UNKNOWN]
#
# Indentation-scoped so a later top-level key (`ioc:`, `mitre:`) ends the block.
# Inline-flow lists `[A, B, C]` and block "- item" lists are both handled.
# =============================================================================
_INLINE_LIST_RE = re.compile(r"^\[(.*)\]$")
_COMMENT_RE = re.compile(r"\s+#.*$")


def _strip_inline_comment(s: str) -> str:
    # Drop a trailing " # comment". Contract values here are bare tokens/lists
    # with no embedded '#', so this is safe for these blocks.
    return _COMMENT_RE.sub("", s)


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _split_flow_list(body: str) -> list[str]:
    return [p.strip() for p in body.split(",") if p.strip()]


@dataclass
class Contract:
    vocabulary: list[str] = field(default_factory=list)
    equivalence_classes: dict[str, list[str]] = field(default_factory=dict)


def parse_contract_yaml(path: str) -> Contract:
    """Extract verdict.vocabulary tokens + verdict.equivalence_classes from the
    contract YAML using a small indentation-aware reader (no PyYAML dependency)."""
    with open(path, encoding="utf-8") as fh:
        raw_lines = fh.readlines()

    # Keep lines that carry content; track indentation on the raw text.
    lines = [ln.rstrip("\n") for ln in raw_lines]

    c = Contract()

    # --- locate top-level `verdict:` and its indented body ------------------
    verdict_idx = None
    for i, ln in enumerate(lines):
        if _indent(ln) == 0 and ln.strip() == "verdict:":
            verdict_idx = i
            break
    if verdict_idx is None:
        raise ValueError(f"{path}: no top-level 'verdict:' mapping found")

    # Body = subsequent lines until the next indent-0 key (or EOF).
    body: list[str] = []
    for ln in lines[verdict_idx + 1 :]:
        if ln.strip() == "" or ln.lstrip().startswith("#"):
            body.append(ln)
            continue
        if _indent(ln) == 0:  # next top-level key ends the verdict block
            break
        body.append(ln)

    # Determine the indentation of verdict's direct children (e.g. 2 spaces).
    child_indents = [
        _indent(ln) for ln in body if ln.strip() and not ln.lstrip().startswith("#")
    ]
    if not child_indents:
        raise ValueError(f"{path}: empty 'verdict:' block")
    child_indent = min(child_indents)

    # --- walk the verdict children, capturing the two sub-blocks ------------
    i = 0
    n = len(body)
    while i < n:
        ln = body[i]
        stripped = ln.strip()
        if not stripped or stripped.startswith("#") or _indent(ln) != child_indent:
            i += 1
            continue
        key = stripped.split(":", 1)[0].strip()

        if key == "vocabulary":
            i += 1
            # block list of "- token: X" mappings (deeper indent than child)
            while i < n:
                cur = body[i]
                if cur.strip() == "" or cur.lstrip().startswith("#"):
                    i += 1
                    continue
                if _indent(cur) <= child_indent:
                    break
                m = re.match(r"-\s*token:\s*(.+)$", cur.strip())  # regex literal, not a secret  # leak-scan: allow secret.assignment
                if m:
                    tok = _strip_inline_comment(m.group(1)).strip().strip('"').strip("'")
                    if tok:
                        c.vocabulary.append(tok)
                i += 1
            continue

        if key == "equivalence_classes":
            i += 1
            while i < n:
                cur = body[i]
                if cur.strip() == "" or cur.lstrip().startswith("#"):
                    i += 1
                    continue
                if _indent(cur) <= child_indent:
                    break
                # "name: [A, B, C]"  (the contract uses inline-flow lists here)
                mm = re.match(r"([A-Za-z0-9_]+):\s*(.+)$", cur.strip())
                if mm:
                    cls_name = mm.group(1).strip()
                    val = _strip_inline_comment(mm.group(2)).strip()
                    flow = _INLINE_LIST_RE.match(val)
                    if flow:
                        members = _split_flow_list(flow.group(1))
                    else:
                        # tolerate a block list following the class name
                        members = []
                        j = i + 1
                        while j < n:
                            sub = body[j]
                            if sub.strip() == "" or sub.lstrip().startswith("#"):
                                j += 1
                                continue
                            if _indent(sub) <= _indent(cur):
                                break
                            sm = re.match(r"-\s*(.+)$", sub.strip())
                            if sm:
                                members.append(
                                    _strip_inline_comment(sm.group(1)).strip()
                                )
                            j += 1
                        i = j - 1
                    c.equivalence_classes[cls_name] = [
                        m.strip().strip('"').strip("'") for m in members
                    ]
                i += 1
            continue

        i += 1

    if not c.equivalence_classes:
        raise ValueError(
            f"{path}: verdict.equivalence_classes block not found or empty"
        )
    if not c.vocabulary:
        raise ValueError(f"{path}: verdict.vocabulary block not found or empty")
    return c


# =============================================================================
# Load the live scorer.py as a module (by path; stdlib-only).
# =============================================================================
def load_scorer(scorer_dir: str):
    path = os.path.join(scorer_dir, "scorer.py")
    if not os.path.isfile(path):
        raise FileNotFoundError(f"scorer.py not found at {path}")
    spec = importlib.util.spec_from_file_location(_MODULE_NAME, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load a module spec from {path}")
    mod = importlib.util.module_from_spec(spec)
    # Register before exec: scorer.py uses @dataclass, whose introspection does
    # sys.modules.get(cls.__module__).__dict__ — absent registration that is
    # None and the import crashes. (This is why a naive importlib load fails.)
    sys.modules[_MODULE_NAME] = mod
    try:
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
    except BaseException:
        sys.modules.pop(_MODULE_NAME, None)
        raise
    return mod


# =============================================================================
# The three drift checks. Each returns a list of human-readable problem strings
# (empty list == that check passed).
# =============================================================================
def check_verdict_classes(contract: Contract, scorer) -> list[str]:
    """Class names + per-class members must match under match-time normalization."""
    problems: list[str] = []

    c_classes = {
        name: norm_class_members(members)
        for name, members in contract.equivalence_classes.items()
    }
    s_classes = {
        name: norm_class_members(members)
        for name, members in scorer.VERDICT_CLASSES.items()
    }

    c_names, s_names = set(c_classes), set(s_classes)
    only_contract = c_names - s_names
    only_scorer = s_names - c_names
    if only_contract:
        problems.append(
            "verdict class(es) in contract.yaml but MISSING from scorer.VERDICT_CLASSES: "
            + ", ".join(sorted(only_contract))
        )
    if only_scorer:
        problems.append(
            "verdict class(es) in scorer.VERDICT_CLASSES but MISSING from contract.yaml: "
            + ", ".join(sorted(only_scorer))
        )

    for name in sorted(c_names & s_names):
        cm, sm = c_classes[name], s_classes[name]
        if cm != sm:
            added = sm - cm  # in scorer, not contract
            removed = cm - sm  # in contract, not scorer
            detail = []
            if removed:
                detail.append("only in contract: " + ", ".join(sorted(removed)))
            if added:
                detail.append("only in scorer: " + ", ".join(sorted(added)))
            problems.append(
                f"verdict class '{name}' MEMBER drift  ({'; '.join(detail)})"
            )
    return problems


def check_vocabulary_coverage(contract: Contract, scorer) -> list[str]:
    """Every contract vocabulary token must classify to a scorer class."""
    problems: list[str] = []
    for tok in contract.vocabulary:
        cls = scorer._verdict_class(tok)
        if cls is None:
            problems.append(
                f"contract verdict vocabulary token '{tok}' is NOT classifiable by "
                f"scorer._verdict_class (scorer would read it as not_emitted)"
            )
    return problems


# MITRE credit-direction truth table the contract's mitre.rules prose mandates.
# (gt_code, reported_set, expected_satisfied, why)
MITRE_INVARIANTS = [
    ("T1059", {"T1059"}, True, "exact technique match must be credited"),
    ("T1059.001", {"T1059.001"}, True, "exact sub-technique match must be credited"),
    ("T1567", {"T1567.002"}, True, "GT parent credited by a reported sub-technique"),
    ("T1567.002", {"T1567"}, False, "GT sub NOT credited by a bare reported parent"),
    ("T1585.001", {"T1585.002"}, False, "sibling sub must NOT credit another sibling"),
    ("T1059", {"T1003"}, False, "unrelated technique must not be credited"),
    ("T1059.001", {"T1059"}, False, "GT sub NOT credited by its bare parent"),
]


def check_mitre_credit_direction(scorer) -> list[str]:
    """Behaviourally verify scorer._mitre_satisfied matches the contract's
    one-directional parent<->sub credit rules."""
    problems: list[str] = []
    fn = getattr(scorer, "_mitre_satisfied", None)
    if fn is None:
        return ["scorer has no _mitre_satisfied — MITRE mirror cannot be verified"]
    for gt_code, reported, expected, why in MITRE_INVARIANTS:
        try:
            got = bool(fn(gt_code, set(reported)))
        except Exception as exc:  # a crash is itself drift/breakage
            problems.append(
                f"_mitre_satisfied({gt_code!r}, {sorted(reported)!r}) raised {exc!r}"
            )
            continue
        if got != expected:
            problems.append(
                f"MITRE credit drift: _mitre_satisfied({gt_code!r}, {sorted(reported)!r}) "
                f"= {got}, expected {expected} ({why})"
            )
    return problems


@dataclass
class DriftReport:
    verdict_class_problems: list[str]
    vocabulary_problems: list[str]
    mitre_problems: list[str]

    @property
    def in_sync(self) -> bool:
        return not (
            self.verdict_class_problems
            or self.vocabulary_problems
            or self.mitre_problems
        )

    def render(self) -> str:
        L = []
        L.append("=" * 78)
        L.append("CONTRACT <-> SCORER DRIFT CHECK  (Diagnosis Protocol tool #6)")
        L.append("=" * 78)

        def section(title: str, probs: list[str]) -> None:
            status = "OK" if not probs else "DRIFT"
            L.append(f"[{status}] {title}")
            for p in probs:
                L.append(f"    - {p}")

        section("1. verdict equivalence classes", self.verdict_class_problems)
        section("2. verdict vocabulary coverage", self.vocabulary_problems)
        section("3. MITRE credit-direction invariants", self.mitre_problems)
        L.append("-" * 78)
        if self.in_sync:
            L.append("RESULT: IN SYNC — contract and scorer mirror match. Lap may proceed.")
        else:
            L.append(
                "RESULT: DRIFT DETECTED — scorer.py no longer mirrors contract.yaml.\n"
                "        HARD-BLOCK: do NOT run a verdict/MITRE ablation lap until the\n"
                "        mirror is re-synced (Stage 4.4) and test_scorer.py passes."
            )
        L.append("=" * 78)
        return "\n".join(L)


def run_drift_check(contract_path: str, scorer_dir: str) -> DriftReport:
    contract = parse_contract_yaml(contract_path)
    scorer = load_scorer(scorer_dir)
    return DriftReport(
        verdict_class_problems=check_verdict_classes(contract, scorer),
        vocabulary_problems=check_vocabulary_coverage(contract, scorer),
        mitre_problems=check_mitre_credit_direction(scorer),
    )


# =============================================================================
# CLI.
# =============================================================================
def _default_contract() -> str:
    # repo-root-relative default when run from within the repo tree
    here = os.path.dirname(os.path.abspath(__file__))
    # eval/diagnosis/ -> repo root is two levels up
    root = os.path.dirname(os.path.dirname(here))
    return os.path.join(root, "protocol-sift", "contract", "contract.yaml")


def _default_scorer_dir() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(os.path.dirname(here))
    return os.path.join(root, "contract-build", "scoring")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="HARD-BLOCK gate: verify scorer.py still mirrors contract.yaml "
        "(verdict equivalence classes + vocabulary + MITRE credit direction)."
    )
    ap.add_argument("--contract", default=_default_contract(),
                    help="path to protocol-sift/contract/contract.yaml")
    ap.add_argument("--scorer-dir", default=_default_scorer_dir(),
                    help="dir holding scorer.py (contract-build/scoring)")
    ap.add_argument("--quiet", action="store_true",
                    help="print nothing on success (exit code only)")
    args = ap.parse_args(argv)

    try:
        report = run_drift_check(args.contract, args.scorer_dir)
    except Exception as exc:
        # Loading failure must BLOCK, never silently pass — a missing/garbled
        # input on a verdict/MITRE lap is exactly when we must stop.
        print(f"contract-scorer drift check: COULD NOT EVALUATE: {exc}", file=sys.stderr)
        return 3

    if not (args.quiet and report.in_sync):
        print(report.render())
    return 0 if report.in_sync else 2


if __name__ == "__main__":
    raise SystemExit(main())
