# Accuracy Report — Protocol SIFT

**System under test (SUT):** Protocol SIFT = Claude (`claude -p`, Opus) + the `protocol-sift/` config layer (the `global/CLAUDE.md` contract + five forensic `SKILL.md` files), running on a SANS SIFT Workstation.

**What this document is:** a self-assessment of the *accuracy* of the agent's findings and of the eval loop that grades it — false positives, missed artifacts, hallucinated claims found during testing, and the honest scope of every quantitative claim. For the "Find Evil" hackathon, **honesty is explicitly valued over perfection**, so this report leads with what is *not* yet proven as prominently as with what is.

**A note on the deliverable:** the product is the **eval-driven optimization loop** (`eval/`, `scoring/`, `scorers/`, `contract-build/`); the forensic agent is the proof the loop works. Accordingly, "accuracy" here means two things at once: the accuracy of the agent's forensic findings, and the trustworthiness of the *measurement* that grades them.

---

## 1. The Metric

The headline accuracy metric is **findable-recall plus a fabrication counter**, computed by deterministic Python (`scoring/scorer.py`, 52 tests). It is designed to be **structurally incapable of rewarding a hallucination**: an IOC is credited only if its exact value appears in the evidence the agent actually saw.

```
                 | {IOCs reported} ∩ {IOCs present in evidence} |
Findable Recall = ----------------------------------------------------
                        | {IOCs present in evidence} |

Fabrications    = | {IOC-tokens in report}  \  {tokens in evidence} |
```

Two properties matter for accuracy:

- **Un-gameable by construction.** Inventing a confident-sounding IOC cannot raise findable-recall (the token is not in evidence) and it *increases* the fabrication counter. The metric rewards truth, not confidence.
- **Input-scope honest.** "Findable" means findable *from the agent's actual input*. IOCs that exist in a case's ground truth but are absent from the evidence the agent was given are excluded from the recall denominator — they are a data-scope gap, not an agent miss, and the report says so explicitly (see §6).

The deterministic scorer is the **sole keep/revert signal** in the loop (`scoring/keep_or_revert.py`, `scoring/composite.py`). Any LLM judge is **advisory only** and stays OFF until validated against human labels (`eval/diagnosis/judge_validation.py`); an AI never grades its own work. This is the central architectural guardrail of the measurement: the optimizer *proposes*, the deterministic evaluator *disposes*, and the optimizer can only learn from a score it cannot fake.

---

## 2. Headline Result — with Honest Scope

We closed **one full optimization lap on the live system**. The loop's error analysis found the agent never emitted a structured verdict or a MITRE ATT&CK mapping; we changed exactly **one** artifact (the data-driven Deliverable Contract in the SUT's `global/CLAUDE.md`); we re-ran the same answer-keyed cases through the same launcher; and we re-scored with the *unchanged* deterministic scorer.

| Metric | Before | After (lap close) |
|---|---|---|
| Verdict emitted | 0 / 3 | **3 / 3** |
| Findable IOC recall (PRIMARY) | 100% | 100% — no regression |
| Fabrications | 0 | 0 — no regression |
| MITRE recall (exact-match vs. current key) | 0% | low single-digit, exact-match (see §4) |

**The only change** between before and after was the contract artifact deployed into the SUT; the scorer was identical across both runs.

### Honest scope caveats (read these as part of the result)

- **n = 3 cases.** The verdict delta (0-for-3 → 3-for-3) and 100% findable recall are over **three** answer-keyed cases. They are strong and human-validated, but this is **not** a large-sample accuracy claim.
- **A/B captured, not yet fully blind-scored.** The controlled bare-Claude-vs-Protocol-SIFT arms (`eval/run_blind.py`) have been *captured* but are **not yet fully blind-scored** with the statistical gate (`eval/diagnosis/aggregate_failures.py`: per-arm rate, Wilson interval, two-proportion z). Until that completes, the lap-1 deltas are an honest before/after on the same launcher, **not** a statistically-established A/B win. **STATUS: PENDING re-baseline.**
- **Human-in-the-curation-loop.** A person still approves each keep/revert by design. The *fully autonomous* loop (loop proposes and accepts its own non-regressing changes) is the next milestone, not a current claim.
- **MITRE exact-match numbers are lower bounds against a known-imperfect key.** See §4 — exact-string-match against a single key is the wrong instrument for MITRE, and the numbers should not be read as the agent's true MITRE accuracy.

---

## 3. Findings Accuracy — False Positives, Missed Artifacts, Hallucinations

### 3.1 Provenance discipline: CONFIRMED / INFERRED / UNCERTAIN

Every investigation report cites the artifact ID that produced each finding and uses a strict three-tier provenance scheme:

- **CONFIRMED (by artifact)** — the evidence directly asserts it. Crucially, this means *the artifact reports it*, not that the agent re-derived it from primary media. Where the graded cases supply only pre-extracted artifact summaries (no raw disk/memory/pcap), the agent deliberately caps certainty at "CONFIRMED (by artifact)" rather than claiming independent forensic verification — to avoid overstating certainty.
- **INFERRED** — reached by reasoning across artifacts, with strength noted (strong / weak).
- **FLAGGED / UNCERTAIN** — uncheckable from the evidence, internally inconsistent, or asserted only in case metadata.

### 3.2 Fabrications: 0 before, 0 after — and *why*

The fabrication counter was **0 before and 0 after** the lap. Reading the reports by hand shows this is earned, not accidental — the agent repeatedly stops short of claims the evidence does not support. Representative refusals (values redacted as they are answer-key-adjacent):

- One case **refuses to assert recovered-credential values** because the captured-traffic artifact summarizes destinations only and carries no credential payloads. It also **declines to build a timeline at all** because no artifact carries timestamps.
- One case **explicitly withholds two exfiltration channels named in the case *description*** because no artifact evidences them — and labels asserting them "a hallucination." This is notable because the ground-truth narrative implies those channels, yet the agent correctly refused to assert what its actual input did not support. (This is a deliberate *under*-claim relative to the key — see §5.)
- One case **declines to fold a secondary email identity into the device-bound attribution chain** because only one vector is forensically welded to the captured device.

These are negative findings (refusals), which is exactly where a confident-but-wrong agent produces false positives. The agent produced none in testing.

### 3.3 The vindicated attribution hedge (a self-correction / "clear the innocent" win)

In one case the agent graded its attribution chain link-by-link so confidence "does not silently inflate as the chain lengthens." It asserted **device + account attribution at HIGH confidence** but **capped PERSON attribution at MODERATE / INFERRED** — explicitly *not* declaring a named individual guilty — because the environment ran a **password-less, open WiFi network** that admits other people onto the same egress path.

This hedge was **vindicated by an independent blind re-investigation of the real raw packet capture** (a fresh agent, no access to the answer key or the Protocol SIFT result, investigating the actual evidence with real tools). The blind analyst independently concluded that the legal-name attribution is **not provable from the evidence** — only the accounts are. The agent's epistemic caution matched what the raw evidence actually supports. The eval loop is designed to *preserve* this behavior, not train it out: forcing a binary verdict on thin attribution evidence is recorded as a non-negotiable anti-pattern.

### 3.4 Data-quality bugs the human cross-check caught (honest misses in the *data*, not the agent)

A human read of the traces (Hamel's "look at your data") surfaced data-quality issues that a token scorer cannot see, and the reports correctly flagged them:

- A recurring **mislabel** where artifacts that are actually Windows activity were tagged as shell history. The agent flagged the mismatch rather than reasoning over the wrong premise.
- A **spelling fork** in one case's identity strings (one spelling used in prose, a different spelling used as the canonical IOC). The agent flagged the inconsistency.

Both issues were confirmed present in the source ground-truth keys. These are accuracy wins for the agent's flagging discipline and, simultaneously, honest defects in the eval *data* that the loop exposed.

---

## 4. MITRE Exact-Match Is the Wrong Instrument (and we did not cheat to fix it)

The MITRE ATT&CK recall numbers are **deliberately reported as low** and framed honestly rather than inflated.

**What we found.** Three competent analysts (the official-style key, Protocol SIFT, and an independent blind investigator working from the raw evidence) produced **three different, individually-defensible MITRE mappings with near-zero overlap** for the same behaviors. That is structural proof that exact-string-match against a *single* key cannot fairly measure MITRE accuracy. Reading the MITRE recall (low single-digit out of the key's total codes) as agent failure would be wrong, because, after adjudication:

- several of the key's codes were judged **flatly wrong** for the evidence (the agent correctly *omitted* them);
- a couple of the key's codes describe behavior **absent from the agent's actual input scope** (a data-scope gap, same shape as findable-recall); and
- the agent was assessed equal-or-better on the majority of in-scope codes, with one clear genuine slip.

So the honest denominator of *valid, in-scope* codes is meaningfully smaller than the raw key total, and the exact-match percentage understates real performance.

**What we refused to do.** We did **not** loosen the scorer until the agent's codes matched a flawed key — that is the Goodhart trap (manufacturing a higher number while degrading better reasoning). The agent is **never** nudged toward a known-bad key. The single scorer change we did make is principled: **crediting a parent technique when the agent reports a more specific sub-technique** (a sub-technique genuinely entails its parent). Reverse-direction and sibling credit are explicitly refused. A frozen ATT&CK id catalog (`scoring/gen_attack_ids.py`) additionally flags any fabricated technique code key-independently.

**STATUS: PENDING.** The corrected-and-locked-key MITRE re-baseline is **not yet complete**. The current MITRE figures should be read as **lower bounds against a known-imperfect key**, pending key-lock and the validated advisory judge. Any MITRE percentage in this submission is provisional until that re-baseline lands.

---

## 5. Honesty Wins — When the Eval Caught the Eval (and Itself)

These are the accuracy/integrity stories the project is most proud of, because each is a case of the system catching a *defect in its own foundations* rather than in the agent.

### 5.1 The eval caught the answer key being wrong

When the deterministic scorer reported a low MITRE score on a harassment case, we trusted the loop enough to suspect the **gold answer key**, not just the agent. An adversarial multi-agent adjudication, plus a **blind re-investigation of the real raw packet capture**, proved that one of the key's mapped techniques — a phishing **attachment** technique — was **factually impossible** for the evidence: the packets show the harassment was **plain web-form text with no attachment**. The agent had refused to emit that technique; the agent was right and the key was wrong. We **fixed and locked the key instead of degrading the agent**. (Honest refinement: the blind expert did map the broader phishing *parent* technique, so the agent's *total* refusal of any phishing technique was slightly over-conservative — but rejecting the *attachment* sub-technique was correct.)

This is the strongest accuracy claim in the report: a good eval must be willing to conclude the **ground truth** is wrong, not only the agent.

### 5.2 A contaminated control caught

The bare-Claude baseline arm of the A/B harness was accidentally fed the very config layer it was meant to *lack*, which would have silently understated the measured benefit of Protocol SIFT. The loop caught and fixed the contamination so the A/B comparison stays honest. (This is also why §2 marks the A/B as captured-but-pending-blind-score: we are deliberately not reporting an A/B win until the corrected control is re-run and scored.)

### 5.3 A real answer-key leak the gate caught

The red-team-hardened leak-scan gate (`scripts/leak_scan.py`, with `scripts/test_leak_scan.py` and the `scripts/redteam/` battery; `make leak-scan`) caught a **complete answer key hard-coded inside a report-generator** before it could reach the public repo. This is both a security win and an accuracy/integrity win: had it shipped, any subsequent "the agent found it" claim against that case would have been contaminated by an in-repo answer source. The gate is run before every commit (`make pre-submit` = leak-scan + verify-ledger).

---

## 6. Validation Gates — Done vs. Pending

The loop follows Hamel Husain's methodology (evaluate → debug → change; "look at your data"; AI judge stays OFF until validated). Honesty requires stating which validation gates are actually closed.

| Gate | What it requires | Status |
|---|---|---|
| Metric validated vs. human eyes | Cross-check scorer findable/found flags against an independent human read | **DONE** — 0 disagreements across the 3 cases; adversarial report-vs-key read found 0 over-claims / 0 hallucinations |
| Answer keys corrected + locked | Apply the adjudication (remove wrong codes, decide input-scope policy), then freeze for the rest of the event | **PENDING** — adjudication done; correction + freeze not yet applied |
| Advisory LLM judge validated | Judge must agree with human adjudication before it is trusted, and stays advisory w.r.t. keep/revert regardless | **PENDING** — labeled set exists (the per-case adjudications); judge not yet validated (`eval/diagnosis/judge_validation.py` is the gate) |
| Held-out anti-overfit case | Lock a held-out case before further optimizing | **PENDING** — not yet locked |
| A/B blind-scored with statistics | Run bare-vs-SIFT arms repeatedly, score blind, apply Wilson CI + 2-proportion z | **PENDING re-baseline** — runs captured, scoring not complete |

**The metric itself is validated** (0 human disagreements on n=3). The **fully autonomous, anti-overfit-guaranteed, statistically-established** loop is **not yet closed**. Both statements are true and are stated together on purpose.

---

## 7. Honest Limitations

1. **The three graded cases exercise the orchestrator and the report contract, not the forensic skills.** These cases supply **pre-extracted artifact summaries** rather than raw media, so the run is mostly Read + Bash + Write and the five forensic `SKILL.md` files (memory-analysis, plaso-timeline, sleuthkit, windows-artifacts, yara-hunting) **barely or never execute**. There is therefore **no graded accuracy claim about the forensic skills themselves yet.** A raw-evidence case (disk image / memory dump) is staged for this and is documented in `docs/DATASET.md` and `dataset/`, but a **graded lap on raw evidence has not yet been run**. **STATUS: PENDING.**

2. **n = 3 is a small sample.** The deltas are real, reproducible on the same launcher, and human-validated — but they are not a large-sample claim.

3. **MITRE exact-match has hit its honest ceiling** (see §4). Treat any MITRE percentage as a provisional lower bound against a known-imperfect, not-yet-locked key.

4. **The findable-IOC denominator is a scorer-defined, input-scope subset — not the full ground-truth key.** The keys contain more IOCs than the agent could possibly recover, because some are genuinely absent from the artifacts the agent received (full file paths, certain network/host identifiers, etc.). "100% findable recall" means 100% of the **findable-from-input** subset, not 100% of every IOC the case author knows. This is the honest framing of the primary metric, and it is the framing that keeps the metric un-gameable.

5. **A/B benefit is not yet statistically established** (see §2 and §6). The bare-vs-SIFT win is captured but not yet blind-scored.

---

## 8. Mapping to the Judging Criteria

| Criterion | Where addressed |
|---|---|
| Autonomous Execution Quality / self-correction | §5 (eval correcting the *key*; contaminated-control catch); §1, §6 (auto keep/revert with human gate) |
| IR Accuracy (confirmed-vs-inferred, flag hallucinations) | §1 (un-gameable metric); §3 (provenance discipline, 0 fabrications, vindicated hedge, data-quality flags) |
| Breadth / Depth | §3 (deep on 3 cases + blind raw-evidence re-investigation); §7.1 (raw-evidence depth = the named gap) |
| Constraint Implementation (architectural guardrails) | §1 (deterministic scorer = sole signal; judge advisory-only); §5.3 (leak-scan gate); §6 (held-out gate, pending) |
| Audit Trail Quality | §3 (per-finding artifact provenance); trace capture in `trace_enrich/` and `harness/` |
| Usability / Documentation | §2 before/after scoreboard; this report read alongside `README.md`, `docs/DATASET.md`, `docs/ASSERTION_CATALOG.md` |

---

## 9. Bottom Line

- The metric is **un-gameable by construction** and **human-validated to zero disagreements** (n=3).
- The agent held **0 fabrications** and **100% findable recall** while verdict accuracy went **0-for-3 → 3-for-3** off a **single** contract edit, **no regression**.
- The loop was rigorous enough to **catch its own ground truth being wrong**, to **catch a contaminated control**, and (via the gate) to **catch a real answer-key leak** before it shipped.
- And honestly: **n=3**, the **A/B is captured but not yet blind-scored (PENDING re-baseline)**, the **MITRE re-baseline / key-lock / held-out / judge-validation gates are PENDING**, the **forensic skills are not yet graded on raw evidence**, and a **human is still in the keep/revert loop by design.**

We believe stating the second list as plainly as the first is itself the point of an accuracy report.
