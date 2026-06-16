# Eval-Driven Optimization Loop — Project Story

## Inspiration

The FindEvil challenge asks you to make a digital-forensics agent better. Most teams reach straight for "better prompts." But Hamel Husain's writing on LLM evals makes a sharper point: **you cannot improve what you cannot measure, and the teams that win are the ones who iterate fastest through *evaluate → debug → change*.** His "virtuous cycle" puts **Eval & Curation** at the dead center of the wheel.

So we didn't set out to build a smarter forensic AI. We set out to build **the loop that makes one provably smarter** — and to apply Hamel's methodology end-to-end in a domain where being wrong is *dangerous*: a forensic analyst that bluffs can accuse an innocent person or miss a live compromise. That raised the bar for our eval: it had to reward **truth, not confidence**.

## What it does

> An **eval-driven optimization loop** that grades Protocol SIFT — a DFIR agent running unattended on a SANS SIFT Workstation — against answer-keyed cases, and improves its own context artifacts (its `CLAUDE.md` contract + `SKILL.md` skill files + supporting code) from the graded signal. Hamel's eval methodology, instantiated for forensics.

The loop is the product; the forensic agent is our proof it works. It runs on three levels and a curation hub:

- **Level 1 — an un-gameable grader.** Every run is scored automatically against the case's known answers. The headline metric credits a clue **only if its exact value appears in the evidence the agent actually saw**, so it is *structurally incapable of rewarding a hallucination*:
$$\text{Findable Recall} = \frac{\lvert\,\text{IOCs reported} \cap \text{IOCs present in evidence}\,\rvert}{\lvert\,\text{IOCs present in evidence}\,\rvert}, \qquad \text{Fabrications} = \bigl\lvert\,\{\text{IOC-tokens in report}\}\setminus\{\text{tokens in evidence}\}\,\bigr\rvert.$$
- **Level 2 — a human reads the data.** Traces of every step are captured; a human does error analysis on them to confirm the grade is honest. An AI "judge" exists but stays **OFF until it proves it agrees with human labels** — we never let an unvetted AI grade our AI.
- **Level 3 — proof, not luck.** The same cases run with our improvements **on** vs. a plain-Claude baseline with them **stripped out**, compared across repeated runs with real statistics so a gain is provably *ours*.
- **The curation hub.** Diagnose the root cause of a failure, change *one* thing, and keep it **only if the score rises with no regression** — every lap in a tamper-evident ledger.

What it improves: the agent's **prompting**, its **tool sequencing**, and its **self-correction routines** — with **no model retraining**.

## How we built it

The system under test is Protocol SIFT: Claude (`claude -p`, Opus) plus a config layer of a contract and five forensic skills, on a SANS SIFT Workstation. Around it we built:

- **Deterministic scorers** (stdlib Python, 52 tests green): findable-recall, a fabrication counter, verdict-class matching, and MITRE ATT&CK recall with parent-from-sub-technique credit — plus a key-independent check against a frozen 697-id ATT&CK catalog that flags fabricated technique codes.
- **Trace capture** (Braintrust OpenTelemetry) so a human can read every command, timing, and token cost.
- **A controlled A/B harness** in a sealed sandbox, running bare-vs-SIFT arms; we act on a *rate* across runs, using a Wilson score interval and a two-proportion test:
$$z = \frac{\hat{p}_{\text{SIFT}} - \hat{p}_{\text{bare}}}{\sqrt{\hat{p}\,(1-\hat{p})\left(\tfrac{1}{n_{\text{SIFT}}}+\tfrac{1}{n_{\text{bare}}}\right)}}\,.$$
- **A diagnosis + curation harness**: a rule-change protocol (never change off one mistake; triage *bad-case / tool-fail / skill-gap / prompt-rule / an-existing-rule-is-the-culprit*; single-rule ablation to implicate a rule; prefer edit/remove over add), a keep-or-revert gate, and a per-lap score ledger.
- **Architectural guardrails** (enforced by the system, not the prompt): evidence mounted **read-only**, a **sealed sandbox with outbound network blocked**, and a **command allow-list** that keeps destructive commands out of reach — plus a red-team-hardened **leak-scan gate** on commits.

Everything was built on the workstation itself, with answer keys kept off-box for blind isolation.

## Challenges we ran into

- **Goodhart's law.** A naive score rewards confident guessing. We had to design a metric that *cannot* credit an invented clue — hence findable-recall + the fabrication counter.
- **Validating the metric.** Hamel's hardest rule is "look at your data." We read every trace by hand; an independent cross-check found **zero disagreements** with the scorer (on $n=3$ cases).
- **The eval data itself was wrong.** When the scorer reported a low MITRE score, we trusted the loop enough to suspect the *gold answer key*. We ran a **blind re-investigation of the raw evidence** and proved the key was wrong (it labeled a plain web-form harassment case as a "spearphishing attachment" — there was no attachment), so we **fixed and locked the key instead of degrading the agent.**
- **A contaminated control.** Our baseline arm was accidentally fed the very config it was meant to lack; we caught and fixed it so the A/B comparison stays honest.
- **A real leak.** Our leak-scan gate caught a complete answer key hard-coded inside a report-generator before it could reach our public repo.

## Accomplishments that we're proud of

- A scoring metric that is **structurally incapable of rewarding a hallucination**, and human-validated to **zero disagreements**.
- **One full closed lap on the live system**: a single data-driven contract edit moved verdict accuracy **0-for-3 → 3-for-3** with **100% findable recall and 0 fabrications held**, no regression.
- The loop was rigorous enough to **catch the official answer key being wrong** — the eval catching the eval *data* lying.
- The agent it produced runs **autonomously start-to-finish**, self-corrects (it caught mislabeled evidence and cleared innocent names), and stays **conservative** where evidence is thin (it capped a person-attribution at "moderate" on an open, passwordless network instead of naming a culprit).

## What we learned

- **Iteration speed is the moat** — and you only get it once measurement is automatic and trustworthy.
- A metric you haven't checked against your own eyes is a **vanity number**; humans cannot be removed from evaluation.
- **The gold label can be wrong.** A good eval is rigorous enough to catch it.
- **Prompt-based guardrails lose; architectural ones win** — so we enforced evidence integrity outside the model.
- Being **honest about scope** ($n=3$, comparison captured-not-yet-scored, human-in-the-curation-loop) builds more trust than a polished overclaim.

## What's next for Eval-Driven Optimization Loop

- **Close the human out of the keep-or-revert step** — today a person approves each change by design; the next milestone is letting the loop propose and accept its own non-regressing changes automatically.
- **Blind-score the captured A/B runs** to turn $n=3$ results into a confident, repeatable win rate, and expand to a held-out raw-evidence case.
- **Wire the 24-topic playbook/cookbook** knowledge library into the five live skills.
- **Validate the AI judge** (TPR/TNR vs. human labels) so it can graduate from advisory to a trusted scorer.
- **Generalize beyond forensics** — the loop is domain-agnostic; any agent with answer-keyed cases can ride it.

## Testing instructions (for judges)

The whole pipeline is plain stdlib Python plus standard SANS SIFT Workstation tooling, driven by `make` targets. The deterministic scorers, the leak-scan gate, and all unit suites run on a clean checkout with no secrets; the live evidence and answer keys are deliberately **kept off-repo** (see note below).

**1. Clone the public repo**

```bash
git clone <this-repo-url>
cd <repo>
```

**2. Prerequisites**

- Python 3 (standard library only for the scorers and gates — no third-party install needed to run `make test`, `make leak-scan`, or `make validate`).
- For the live agent run: a SANS SIFT Workstation, the Claude CLI (`claude -p`, Opus), and the `protocol-sift/` config layer as the system-under-test.
- For trace capture only: a `BRAINTRUST_API_KEY`. Copy `.env.example` to `.env` and fill in the placeholder — never commit your real key. Trace capture is optional; scoring and gating do not require it.

**3. Run the deterministic suites and gates (no evidence required)**

```bash
make test           # all unittest suites (scoring/, trace_enrich/, scorers/)
make validate       # validate the dataset cases (dataset/validate_cases.py)
make leak-scan      # red-team-hardened secret / answer-key gate (run before EVERY commit)
make leak-scan-test # the scanner's own unit tests + red-team battery
make verify-ledger  # verify the score-ledger hash chain
make pre-submit     # leak-scan + verify-ledger (run before any public push)
```

**4. Run the eval / agent against the documented dataset**

```bash
make sync           # rsync the repo to the SIFT Workstation VM
make eval           # run the Braintrust eval on the VM
```

The blind A/B harness (bare-Claude vs. Protocol SIFT) lives in `eval/run_blind.py`; scoring (including the `--judge` gate) is `eval/score.py`, and the fail-closed parity gate is `eval/parity_check.py`. The diagnosis-protocol / curation tools run as operator-layer targets:

```bash
make aggregate                       # per-arm failure rate + Wilson CI + 2-proportion z
make judge-validate                  # judge TPR/TNR confusion matrix (gates score.py --judge)
make ablate                          # single-artifact ablation lap
make regression                      # monotonic guard-case non-regression gate
make validate-keys                   # build-time answer-key supportability gate
make check-contract-scorer-drift     # contract <-> scorer drift hard-block
make diagnosis-test                  # the diagnosis-harness unit tests
```

**Dataset documentation:** `dataset/` (cases.jsonl, evidence_inventory.md, manifest.txt, hashes.txt) and `docs/DATASET.md`. Architecture, assertion catalog, plan, and access notes are in `docs/`.

**Why the live evidence and answer keys are off-repo.** This is intentional, not an omission. Real case evidence and its gold answer keys are held off the public repository to preserve **blind isolation** — so a baseline arm can never be contaminated by the keys it is being graded against (a contamination bug we hit and fixed; see "Challenges"), and so the scorers stay honest. The repo therefore ships the **scoring method, harness, gates, and dataset manifests** rather than the secret IOC values. Judges run the agent against the documented dataset; the answer-keyed grading is reproducible against the off-repo keys following `docs/ACCESS.md` and `docs/DATASET.md`.

## Demo video

TODO: demo video (a <5-minute walkthrough will be recorded and linked here before final submission).
