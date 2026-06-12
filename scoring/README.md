# Deterministic IOC scorer (VIGIA DFIR cases)

Grades a Protocol SIFT investigation report against a case's `ground_truth.json`
using **exact-token matching only — no LLM judge**.

## Why findable-recall is the primary metric

The ground truth lists IOCs derived from the **full disk image**, but the agent
only sees the case file's artifact summaries. Rewarding IOCs that are absent from
the agent's input would train it to hallucinate — the exact failure this project
exists to fix. So the scorer splits every ground-truth IOC into **findable**
(its value appears in the agent's input) vs not, and the headline metric is:

```
findable_recall = found_findable / total_findable      # PRIMARY
```

`full_recall` over all IOCs is kept only as a diagnostic. A **fabrication**
penalty flags IOC-shaped tokens the report asserts that are not in the input.

## What it measures

| Output | Meaning |
| --- | --- |
| `findable_recall` | **PRIMARY** — recall over IOCs the agent could actually find |
| `fabrication_count` | email/hash/MAC/IPv4/SID tokens in the report, absent from input |
| `verdict` | `found` if the report states the GT verdict (e.g. `MALICE`), else `not_emitted` |
| `mitre_recall` | GT technique ids (e.g. `T1040`) present in the report text |
| `full_recall` | diagnostic only — recall over **all** GT IOCs |

## Matching rules

- **Clean** types (`email`, `file_hash`, `mac_address`, `ip_address`,
  `windows_sid`): regex-extract → normalise → set-compare. Only these are subject
  to the fabrication penalty.
- **Fuzzy** types (`file_path`, `hostname`, `username`): substring of the
  normalised GT value (usernames token-boundary-anchored).
- Normalisation is the *weakest correct form only* (never passes a wrong answer):
  email→lower; hash→lower+strip `0x`/spaces/colons; MAC→strip `:-.`+lower; IPv4
  exact (octets validated); SID→upper; path→`\`→`/` + drop trailing slash +
  case-insensitive; hostname/username→case-insensitive.
- **CIDR** ranges (`a.b.c.d/NN`) are a separate annotated class — never a host
  IOC. The network base address (e.g. `10.11.11.0` from `10.11.11.0/24`) is never
  extracted as a host IP and never counted as a fabrication (RFC 950/919: the
  all-zeros host field is the network id, not an assignable host).
- **username** is a weak/contextual indicator (PRISM benchmark excludes it;
  MISP/STIX treat it as contextual). It contributes only to the full-recall
  diagnostic, never to the headline or to fabrication.

## Layout

```
scoring/
  scorer.py          # the harness (stdlib only)
  test_scorer.py     # synthetic-fixture unit tests (stdlib unittest)
  data/              # gitignored — real case data is NEVER committed
    ground_truth/VIGIA-REAL-00{1,2,7}.json
    case_inputs/case{1,2,7}.json
    reports/VIGIA-REAL-00{1,2,7}_investigation_report.md
```

`data/` is gitignored on purpose: ground truth, case inputs, and reports are case
data and stay local (matching the repo's "never commit evidence/case data"
policy). Point the scorer at any data tree with `--data-dir`.

## Run

```bash
cd scoring
python3 -m unittest test_scorer -v     # tests (no data needed)
python3 scorer.py                       # score all 3 real cases
python3 scorer.py --case VIGIA-REAL-001 # one case
python3 scorer.py --json                # also emit full structured JSON
```
