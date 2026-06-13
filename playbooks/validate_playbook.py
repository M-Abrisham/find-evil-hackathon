#!/usr/bin/env python3
"""
Protocol SIFT — playbook linter (BUILD-TIME TOOLING ONLY — do NOT commit to the team repo).

Asserts a playbook .md implements the SHARED SCHEMA CONTRACT used by the factory, skillify.py,
tune_playbook.py and eval/run_blind.py:

frontmatter   category_id  (one of the 24 kebab ids in playbooks/factory/categories.txt)
              version      (int, starts 1)
              name, description (description = the load trigger; skillify.py reuses it)
              variables    {image_path, mount_root, case_out, ntfs_offset_sectors, time_window}
                           — each with a `default` AND a derive-via note
              sub_types    [strings from the taxonomy]   ·   validated_on: [] (eval loop fills)
sections      "Step 0 — evidence inventory & access bootstrap" (mandatory, BEFORE Steps),
              Steps (n = 1..N ascending), a NUMBERED Linux branch (L1..Ln, same step shape),
              Failure modes (mode + guard), append-only Tuning log,
              Quick path containing a timeline-first move,
              the CLOSE-GATE INVARIANT block (verbatim sentinel + per-modality sweep)
steps         fields IN ORDER: n, precondition (optional), tool, expect, check, falsify,
              on_result {expect_met, falsify_met, neither}, emits [score buckets],
              serves [sub-types ⊆ frontmatter sub_types],
              provenance {receipt_id, artifact, offset_or_row, literal_cited}
tool lines    use #{variables} ONLY — literal /evidence, /mnt/c and "..." are BANNED
pivots        every pivot target (Pivots section AND inside on_result) is a legal
              category id or SELF
emits         every value one of the eval/score.py buckets:
              key_artifacts|key_iocs|timeline_events|actor_accounts|exfil_or_encryption_facts

STDLIB ONLY. Exit 0 = every file passes; exit 1 = errors (readable list printed).

Usage:
    python3 playbooks/validate_playbook.py playbooks/<category>.md [more.md ...]
    python3 playbooks/validate_playbook.py --selftest     # embedded valid + invalid sample
"""
from __future__ import annotations

import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# The 24 legal category ids — loaded from playbooks/factory/categories.txt (single source of
# truth for the factory); the embedded fallback mirrors it so the linter works standalone.
# ---------------------------------------------------------------------------
FALLBACK_CATEGORY_IDS = [
    "insider-threat-data-theft", "web-server-compromise", "memory-forensics",
    "malware-analysis-triage", "ransomware-destructive", "windows-execution-artifacts",
    "windows-event-logs", "windows-registry-persistence", "browser-email-documents",
    "network-forensics", "file-recovery-carving", "disk-filesystem",
    "attack-lifecycle-hunting", "cloud-identity-saas", "cloud-iaas-control-plane",
    "containers-supply-chain", "steganography-data-hiding", "virtualization-mobile",
    "active-directory-domain", "targeted-intrusion-apt", "acquisition-custody",
    "linux-host-forensics", "macos-forensics", "threat-hunting-ioc-sweeps",
]

# eval/score.py rubric buckets — the only legal `emits:` values.
SCORE_BUCKETS = [
    "key_artifacts", "key_iocs", "timeline_events", "actor_accounts",
    "exfil_or_encryption_facts",
]

REQUIRED_VARIABLES = ["image_path", "mount_root", "case_out", "ntfs_offset_sectors", "time_window"]

# Step block fields, in contract order. `precondition` is the only optional one.
STEP_FIELD_ORDER = ["n", "precondition", "tool", "expect", "check", "falsify",
                    "on_result", "emits", "serves", "provenance"]
STEP_REQUIRED = [f for f in STEP_FIELD_ORDER if f != "precondition"]
ON_RESULT_KEYS = ["expect_met", "falsify_met", "neither"]
PROVENANCE_KEYS = ["receipt_id", "artifact", "offset_or_row", "literal_cited"]

# Verbatim sentinel of the close-gate invariant (must appear character-for-character).
CLOSE_GATE_SENTINEL = "Quick-path success does NOT waive the Done gate"
# Per-modality sweep tokens that must appear inside the invariant's section (case-insensitive).
CLOSE_GATE_TOKENS = ["disk", "memory", "event log", "registry", "email", "browser",
                     "cloud-sync", "ioc", "timeline"]

BANNED_TOOL_LITERALS = [
    ("/evidence", r"/evidence\b"),
    ("/mnt/c", r"/mnt/c\b"),
    ('"..."', r"\.\.\.|…"),
]

VAR_REF_RE = re.compile(r"#\{([A-Za-z0-9_]+)\}")


def load_category_ids() -> list[str]:
    p = HERE / "factory" / "categories.txt"
    ids: list[str] = []
    if p.exists():
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            ids.append(line.split("|", 1)[0].strip())
    return ids or FALLBACK_CATEGORY_IDS


# ---------------------------------------------------------------------------
# Minimal YAML-subset parser for the frontmatter (stdlib only — no PyYAML on purpose).
# Supports: scalars, inline [lists] / {maps}, and indentation-nested maps/lists.
# ---------------------------------------------------------------------------
def _split_top(s: str, sep: str = ",") -> list[str]:
    out, cur, depth, q = [], [], 0, ""
    for ch in s:
        if q:
            cur.append(ch)
            if ch == q:
                q = ""
            continue
        if ch in "\"'":
            q = ch
            cur.append(ch)
            continue
        if ch in "[{(":
            depth += 1
        elif ch in "]})":
            depth -= 1
        if ch == sep and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        out.append("".join(cur))
    return [p.strip() for p in out if p.strip()]


def _scalar(s: str):
    s = s.strip()
    if s.startswith("[") and s.endswith("]"):
        inner = s[1:-1].strip()
        return [_scalar(x) for x in _split_top(inner)] if inner else []
    if s.startswith("{") and s.endswith("}"):
        d = {}
        for part in _split_top(s[1:-1]):
            k, _, v = part.partition(":")
            d[k.strip()] = _scalar(v)
        return d
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        return s[1:-1]
    if re.fullmatch(r"-?\d+", s):
        return int(s)
    return s


def parse_simple_yaml(text: str) -> dict:
    root: dict = {}
    stack: list[tuple[int, object]] = [(-1, root)]
    pending: tuple[int, dict, str] | None = None     # (indent, parent_dict, key)
    for raw in text.splitlines():
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        content = raw.strip()
        if pending is not None:
            p_indent, p_parent, p_key = pending
            if indent > p_indent:
                container: object = [] if content.startswith("- ") or content == "-" else {}
                p_parent[p_key] = container
                stack.append((p_indent, container))
            else:
                p_parent[p_key] = ""
            pending = None
        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        if content.startswith("- "):
            if isinstance(parent, list):
                parent.append(_scalar(content[2:]))
            continue
        if ":" in content and isinstance(parent, dict):
            key, _, val = content.partition(":")
            key, val = key.strip(), val.strip()
            val = re.sub(r"\s+#.*$", "", val)        # drop inline comments
            if val == "":
                pending = (indent, parent, key)
            else:
                parent[key] = _scalar(val)
    if pending is not None:
        pending[1][pending[2]] = ""
    return root


def split_frontmatter(text: str) -> tuple[str | None, str]:
    """Returns (frontmatter_text or None, body)."""
    lines = text.splitlines()
    i = 0
    while i < len(lines) and not lines[i].strip():
        i += 1
    if i >= len(lines) or lines[i].strip() != "---":
        return None, text
    for j in range(i + 1, len(lines)):
        if lines[j].strip() == "---":
            return "\n".join(lines[i + 1:j]), "\n".join(lines[j + 1:])
    return None, text


# ---------------------------------------------------------------------------
# Body parsing: sections (fence-aware) and step blocks.
# ---------------------------------------------------------------------------
def split_sections(body: str) -> list[tuple[str, str]]:
    """[(heading_text, content)] in document order; index 0 is the pre-heading preamble ('').
    Headings are `##`..`####` at column 0 (single `#` is skipped: bash comments in code samples
    look like `# ...`, and real playbooks may carry stray unpaired ``` fences, so no fence-tracking)."""
    sections: list[tuple[str, str]] = []
    cur_head, cur_lines = "", []
    for line in body.splitlines():
        m = re.match(r"^(#{2,4})\s+(.*?)\s*$", line)
        if m:
            sections.append((cur_head, "\n".join(cur_lines)))
            cur_head, cur_lines = m.group(2), []
        else:
            cur_lines.append(line)
    sections.append((cur_head, "\n".join(cur_lines)))
    return sections


def find_section(sections: list[tuple[str, str]], pattern: str) -> tuple[int, str, str] | None:
    for idx, (h, c) in enumerate(sections):
        if h and re.search(pattern, h, re.I):
            return idx, h, c
    return None


def parse_steps(section_text: str) -> list[dict]:
    """Parse `- n: X` step blocks; indented `field: value` lines; deeper lines = continuations."""
    steps: list[dict] = []
    cur: dict | None = None
    cur_field: str | None = None
    for line in section_text.splitlines():
        m = re.match(r"^\s*-\s+n:\s*(.+?)\s*$", line)
        if m:
            n_val = re.sub(r"\s+#.*$", "", m.group(1)).strip()
            cur = {"n": n_val, "_order": ["n"]}
            steps.append(cur)
            cur_field = "n"
            continue
        if cur is None:
            continue
        if line.strip() and not line[:1].isspace():
            cur, cur_field = None, None              # dedented prose ends the block
            continue
        m = re.match(r"^\s+([a-z_]+):\s*(.*)$", line)
        if m and m.group(1) in STEP_FIELD_ORDER:
            cur_field = m.group(1)
            cur["_order"].append(cur_field)
            cur[cur_field] = m.group(2).strip()
            continue
        if line.strip() and cur_field:               # wrapped continuation line
            cur[cur_field] = (str(cur.get(cur_field, "")) + " " + line.strip()).strip()
    return steps


PIVOT_IN_BRANCH_RE = re.compile(r"\bpivot\b[\s:→>-]*`?([A-Za-z0-9][A-Za-z0-9_-]*)`?", re.I)


# ---------------------------------------------------------------------------
# The linter.
# ---------------------------------------------------------------------------
def lint_text(text: str, name: str, ids: list[str] | None = None) -> tuple[list[str], list[str]]:
    """Returns (errors, warnings)."""
    ids = ids or load_category_ids()
    legal_pivots = set(ids) | {"SELF"}
    errors: list[str] = []
    warnings: list[str] = []

    def err(where: str, msg: str) -> None:
        errors.append(f"[{where}] {msg}")

    def warn(where: str, msg: str) -> None:
        warnings.append(f"[{where}] {msg}")

    fm_text, body = split_frontmatter(text)
    if fm_text is None:
        err("frontmatter", "missing YAML frontmatter block (--- ... ---)")
        fm: dict = {}
    else:
        fm = parse_simple_yaml(fm_text)

    # ---- frontmatter contract -------------------------------------------------------------
    for key in ("name", "description"):
        if not str(fm.get(key, "")).strip():
            err("frontmatter", f"{key} missing/empty")
    cat = fm.get("category_id")
    if not cat:
        err("frontmatter", "category_id missing")
    elif cat not in ids:
        err("frontmatter", f"category_id {cat!r} is not one of the 24 legal ids "
                           f"(see playbooks/factory/categories.txt)")
    version = fm.get("version")
    if not isinstance(version, int):
        err("frontmatter", f"version must be an int (starts 1); got {version!r}")
    elif version < 1:
        err("frontmatter", f"version must be >= 1; got {version}")

    variables = fm.get("variables")
    declared_vars: set[str] = set()
    if not isinstance(variables, dict) or not variables:
        err("frontmatter", "variables block missing or not a map")
    else:
        declared_vars = set(variables.keys())
        for v in REQUIRED_VARIABLES:
            spec = variables.get(v)
            if spec is None:
                err("frontmatter", f"variables.{v} missing (contract requires "
                                   f"{{{', '.join(REQUIRED_VARIABLES)}}})")
                continue
            if not isinstance(spec, dict):
                err("frontmatter", f"variables.{v} must be a map with default + derive-via note")
                continue
            if "default" not in spec or str(spec.get("default", "")).strip() == "":
                err("frontmatter", f"variables.{v}: `default` missing/empty")
            derive_keys = [k for k in spec if "derive" in k.lower()]
            if not derive_keys or all(not str(spec[k]).strip() for k in derive_keys):
                err("frontmatter", f"variables.{v}: derive-via note missing/empty")

    sub_types = fm.get("sub_types")
    sub_types_ok = isinstance(sub_types, list) and sub_types \
        and all(isinstance(s, str) and s.strip() for s in sub_types)
    if not sub_types_ok:
        err("frontmatter", "sub_types must be a non-empty list of taxonomy sub-type strings")

    if "validated_on" not in fm:
        err("frontmatter", "validated_on missing (must exist; [] until the eval loop fills it)")
    elif not isinstance(fm.get("validated_on"), list):
        err("frontmatter", "validated_on must be a list")

    # ---- required sections ----------------------------------------------------------------
    sections = split_sections(body)
    sec_step0 = find_section(sections, r"\bstep\s*0\b")
    sec_steps = find_section(sections, r"\bsteps\b")
    sec_linux = find_section(sections, r"\blinux\b")
    sec_fail = find_section(sections, r"\bfailure\s+modes?\b")
    sec_tune = find_section(sections, r"\btuning\s+log\b")
    sec_quick = find_section(sections, r"\bquick\s+path\b")
    sec_pivots = find_section(sections, r"\bpivots?\b")

    if sec_step0 is None:
        err("sections", 'missing required section "Step 0 — evidence inventory & access bootstrap"')
    if sec_steps is None:
        err("sections", 'missing required section "Steps"')
    if sec_step0 and sec_steps and sec_step0[0] > sec_steps[0]:
        err("sections", "Step 0 must come BEFORE the Steps section (it is the mandatory first step)")
    if sec_linux is None:
        err("sections", "missing required NUMBERED Linux branch section (L1..Ln)")
    if sec_fail is None:
        err("sections", 'missing required section "Failure modes"')
    elif not (re.search(r"\bmode\b", sec_fail[2], re.I) and re.search(r"\bguard\b", sec_fail[2], re.I)):
        err("sections", "Failure modes section has no {mode, guard} entries")
    if sec_tune is None:
        err("sections", 'missing required append-only "Tuning log" section')
    if sec_quick is None:
        err("sections", 'missing required "Quick path" section')
    elif "timeline" not in sec_quick[2].lower():
        err("sections", "Quick path has no timeline-first move (close-gate invariant requires one)")

    # ---- close-gate invariant ---------------------------------------------------------------
    if CLOSE_GATE_SENTINEL not in body:
        err("close-gate", f'CLOSE-GATE INVARIANT missing — verbatim sentinel not found: '
                          f'"{CLOSE_GATE_SENTINEL}"')
    else:
        holder = next(((h, c) for h, c in sections if CLOSE_GATE_SENTINEL in c), None)
        blob = ((holder[0] + "\n" + holder[1]) if holder else body).lower()
        for tok in CLOSE_GATE_TOKENS:
            if tok not in blob:
                err("close-gate", f"invariant block does not sweep modality/requirement: {tok!r}")

    # ---- step blocks ------------------------------------------------------------------------
    def check_step(step: dict, where: str) -> None:
        for f in STEP_REQUIRED:
            if f not in step or str(step.get(f, "")).strip() == "":
                err(where, f"missing required field `{f}`")
        order = [f for f in step.get("_order", []) if f in STEP_FIELD_ORDER]
        idxs = [STEP_FIELD_ORDER.index(f) for f in order]
        if idxs != sorted(idxs):
            err(where, f"fields out of contract order (must be {', '.join(STEP_FIELD_ORDER)}); "
                       f"got {', '.join(order)}")
        if len(set(order)) != len(order):
            err(where, "duplicate fields in step block")

        tool = str(step.get("tool", ""))
        if tool.strip():
            for label, pat in BANNED_TOOL_LITERALS:
                if re.search(pat, tool):
                    err(where, f"tool line contains BANNED literal {label} — use #{{variables}}")
            if not VAR_REF_RE.search(tool):
                err(where, "tool line uses no #{variable} — literal example invocations are banned")
        for f in ("tool", "check", "precondition"):
            for ref in VAR_REF_RE.findall(str(step.get(f, ""))):
                if declared_vars and ref not in declared_vars:
                    err(where, f"{f} references undeclared variable #{{{ref}}}")

        on_result = step.get("on_result")
        if isinstance(on_result, str):
            on_result = _scalar(on_result)
        if isinstance(on_result, dict):
            for k in ON_RESULT_KEYS:
                if k not in on_result or not str(on_result.get(k, "")).strip():
                    err(where, f"on_result missing branch `{k}`")
            for branch, v in on_result.items():
                for tgt in PIVOT_IN_BRANCH_RE.findall(str(v)):
                    if tgt not in legal_pivots:
                        err(where, f"on_result.{branch} pivots to illegal target {tgt!r} "
                                   f"(must be a 24-category id or SELF)")
        elif "on_result" in step:
            err(where, "on_result is not a {expect_met, falsify_met, neither} map")

        emits = step.get("emits")
        if isinstance(emits, str):
            emits = _scalar(emits)
        if isinstance(emits, list):
            for e in emits:
                if e not in SCORE_BUCKETS:
                    err(where, f"emits value {e!r} is not a score bucket "
                               f"({'|'.join(SCORE_BUCKETS)})")
        elif "emits" in step:
            err(where, "emits is not a list")

        serves = step.get("serves")
        if isinstance(serves, str):
            serves = _scalar(serves)
        if isinstance(serves, list):
            if sub_types_ok:
                for s in serves:
                    if s not in sub_types:
                        err(where, f"serves value {s!r} not in frontmatter sub_types")
        elif "serves" in step:
            err(where, "serves is not a list")

        prov = step.get("provenance")
        if isinstance(prov, str):
            prov = _scalar(prov)
        if isinstance(prov, dict):
            for k in PROVENANCE_KEYS:
                if k not in prov or not str(prov.get(k, "")).strip():
                    err(where, f"provenance missing `{k}`")
        elif "provenance" in step:
            err(where, "provenance is not a {receipt_id, artifact, offset_or_row, literal_cited} map")

        if "check" in step and str(step.get("check", "")).strip() \
                and "#{" not in str(step["check"]):
            warn(where, "check does not reference a captured receipt under a #{variable} "
                        "(e.g. #{case_out}/receipts/...)")

    if sec_step0:
        s0 = parse_steps(sec_step0[2])
        if not s0:
            err("step 0", "Step 0 section contains no `- n: 0` step block")
        else:
            if str(s0[0].get("n")) != "0":
                err("step 0", f"first step in Step 0 section must be n: 0; got n: {s0[0].get('n')!r}")
            for st in s0:
                check_step(st, f"step 0 n={st.get('n')}")

    if sec_steps:
        main = parse_steps(sec_steps[2])
        if not main:
            err("steps", "Steps section contains no step blocks")
        ns: list[int] = []
        for st in main:
            where = f"step n={st.get('n')}"
            if not re.fullmatch(r"\d+", str(st.get("n", ""))):
                err(where, "main Steps n must be an integer (Linux branch uses L1..Ln)")
            else:
                ns.append(int(st["n"]))
            check_step(st, where)
        if ns and ns != sorted(set(ns)):
            err("steps", f"step numbers must be unique and ascending; got {ns}")
        if ns and ns[0] != 1:
            warn("steps", f"main Steps usually start at n: 1; got {ns[0]}")

    if sec_linux:
        lx = parse_steps(sec_linux[2])
        if not lx:
            err("linux branch", "Linux branch has no numbered L-steps (`- n: L1` ...)")
        lns: list[int] = []
        for st in lx:
            where = f"linux step n={st.get('n')}"
            m = re.fullmatch(r"L(\d+)", str(st.get("n", "")))
            if not m:
                err(where, "Linux branch step numbers must be L1..Ln")
            else:
                lns.append(int(m.group(1)))
            check_step(st, where)
        if lns and lns != sorted(set(lns)):
            err("linux branch", f"L-step numbers must be unique and ascending; got L{lns}")

    # ---- pivots section ---------------------------------------------------------------------
    if sec_pivots:
        for line in sec_pivots[2].splitlines():
            m = re.match(r"^\s*-?\s*`?(on[_a-z0-9]*)`?\s*:\s*(.+?)\s*$", line, re.I)
            if not m:
                continue
            tgt = m.group(2).strip().strip("`").split()[0].rstrip(".,;")
            if tgt not in legal_pivots:
                err("pivots", f"{m.group(1)} targets {tgt!r} — not a 24-category id or SELF")
    else:
        warn("pivots", "no Pivots section found (lead-to-lead graph recommended)")

    return errors, warnings


def lint_file(path: pathlib.Path, ids: list[str]) -> tuple[list[str], list[str]]:
    return lint_text(path.read_text(encoding="utf-8", errors="replace"), str(path), ids)


# ---------------------------------------------------------------------------
# Embedded selftest samples (tiny but contract-complete / contract-broken).
# ---------------------------------------------------------------------------
VALID_SAMPLE = '''---
attack_type: ransomware-destructive
category_id: ransomware-destructive
name: Ransomware / Destructive (selftest sample)
description: Load when many files are suddenly renamed/unreadable and a ransom note appears.
os_coverage: [windows, linux]
version: 1
variables:
  image_path:
    default: /cases/demo/disk.E01
    derive_via: first *.E01/*.dd/*.raw found under the case evidence drop point
  mount_root:
    default: /cases/demo/mount
    derive_via: where Step 0 mounts the file system read-only (ewfmount + mount -o ro,loop)
  case_out:
    default: /cases/demo/out
    derive_via: scratch output dir created by Step 0 — NEVER inside the evidence mount
  ntfs_offset_sectors:
    default: 2048
    derive_via: NTFS partition start sector read from the mmls receipt in Step 0
  time_window:
    default: 1970-01-01..2099-12-31
    derive_via: narrow to the burst window after the first timeline pass
sub_types: [mass-encryption, recovery-inhibition]
validated_on: []
---

## In one line
A program scrambles files, deletes backups, and leaves a ransom note.

## Quick path (the 90% case)
1. Timeline-first: bound the incident — build a quick timeline of file-change bursts inside #{time_window}.
2. Confirm encryption is real (entropy), find the ransom note, check shadow copies.
3. Pin execution + entry on the same timeline.

## Step 0 — evidence inventory & access bootstrap
- n: 0
  tool: mkdir -p "#{case_out}/receipts" && ls -la "#{image_path}" | tee "#{case_out}/receipts/R0.txt" && mmls "#{image_path}" | tee -a "#{case_out}/receipts/R0.txt"
  expect: evidence enumerated; partition table lists an NTFS partition (record start sector as ntfs_offset_sectors)
  check: grep -qi "NTFS" "#{case_out}/receipts/R0.txt"
  falsify: nothing at the evidence drop point, or no recognizable partition table
  on_result: {expect_met: goto 1, falsify_met: HALT — wrong evidence path, neither: ewfmount then retry}
  emits: []
  serves: [mass-encryption]
  provenance: {receipt_id: R0, artifact: evidence drop point, offset_or_row: mmls table, literal_cited: NTFS partition row}

## Steps (executable — decision-driven)
- n: 1
  precondition: os == windows; exists #{case_out}/receipts/R0.txt
  tool: MFTECmd -f "#{mount_root}/C/$MFT" --csv "#{case_out}" --csvf mft.csv | tee "#{case_out}/receipts/R1.txt"
  expect: a burst of renames to ONE new extension inside #{time_window}
  check: test -s "#{case_out}/mft.csv"
  falsify: file changes are gradual and match normal use — no burst
  on_result: {expect_met: goto 2, falsify_met: pivot disk-filesystem, neither: abstain and dig in $UsnJrnl}
  emits: [key_artifacts, timeline_events]
  serves: [mass-encryption]
  provenance: {receipt_id: R1, artifact: $MFT, offset_or_row: mft.csv row of first renamed file, literal_cited: the new extension string}
- n: 2
  tool: vshadowinfo -o #{ntfs_offset_sectors} "#{image_path}" | tee "#{case_out}/receipts/R2.txt"
  expect: zero surviving shadow copies after the encryption window
  check: grep -qi "Number of stores" "#{case_out}/receipts/R2.txt"
  falsify: shadow copies survive and predate the burst — recovery not inhibited
  on_result: {expect_met: commit recovery-inhibition finding, falsify_met: pivot SELF, neither: abstain}
  emits: [exfil_or_encryption_facts]
  serves: [recovery-inhibition]
  provenance: {receipt_id: R2, artifact: volume shadow store, offset_or_row: vshadowinfo header, literal_cited: Number of stores line}

## Linux branch (L1..Ln)
- n: L1
  tool: fls -r -o #{ntfs_offset_sectors} "#{image_path}" | tee "#{case_out}/receipts/RL1.txt"
  expect: mass same-second metadata changes across user data paths
  check: test -s "#{case_out}/receipts/RL1.txt"
  falsify: no mass-change window in file-system metadata
  on_result: {expect_met: goto L2, falsify_met: pivot linux-host-forensics, neither: abstain}
  emits: [timeline_events]
  serves: [mass-encryption]
  provenance: {receipt_id: RL1, artifact: file system metadata, offset_or_row: fls listing line, literal_cited: changed path line}
- n: L2
  tool: srch_strings -a "#{image_path}" | grep -i -m 20 "decrypt" | tee "#{case_out}/receipts/RL2.txt"
  expect: ransom-note wording present on the raw image
  check: grep -qi "decrypt" "#{case_out}/receipts/RL2.txt"
  falsify: no ransom wording anywhere on the image
  on_result: {expect_met: commit, falsify_met: pivot SELF, neither: abstain}
  emits: [key_iocs]
  serves: [mass-encryption]
  provenance: {receipt_id: RL2, artifact: raw image strings, offset_or_row: srch_strings byte offset, literal_cited: ransom wording line}

## Failure modes
- mode: entropy misread — densityscout LOW density means encrypted (semantics are inverted vs intuition)
  guard: compare a known-plaintext control file's density before concluding
- mode: quick path exits before browser/email/cloud modalities are swept
  guard: the CLOSE-GATE INVARIANT below — quick-path success does not waive it

## CLOSE-GATE INVARIANT (copied verbatim into every playbook)
Before closing, sweep EVERY present modality: disk FS, memory, event logs, registry,
email stores, browser profiles, cloud-sync clients. Pivot every IOC found. Build the
timeline. Quick-path success does NOT waive the Done gate. The quick path includes a
timeline-first move.

## Pivots (lead-to-lead graph)
on_rdp_entry: windows-event-logs
on_phishing_lure: browser-email-documents
on_unclear_origin: SELF

## Tuning log (append-only)
(one line per agent-only tuning iteration: date | case_id | bucket missed | delta applied)
'''

INVALID_SAMPLE = '''---
attack_type: bogus
category_id: not-a-real-category
name: Broken selftest sample
version: one
variables:
  image_path:
    default: /evidence/HOST01.E01
  mount_root:
    default: /mnt/c
    derive_via: x
  case_out:
    default: /tmp/out
    derive_via: x
  time_window:
    default: all
    derive_via: x
sub_types: [mass-encryption]
validated_on: []
---

## Quick path
1. Just run the obvious tool.

## Steps
- n: 1
  tool: MFTECmd -f /evidence/HOST01.E01 --csv ...
  expect: stuff
  falsify: other stuff
  check: test -s "#{undeclared_var}/x.csv"
  on_result: {expect_met: goto 2, falsify_met: pivot nowhere-land}
  emits: [key_artifacts, bogus_bucket]
  serves: [usb-exfil]
  provenance: {receipt_id: R1, artifact: $MFT}

## Pivots
on_x: unknown-category-id
'''


def selftest() -> int:
    ids = load_category_ids()
    ok = True

    v_errs, v_warns = lint_text(VALID_SAMPLE, "<valid-sample>", ids)
    print(f"valid sample   : {len(v_errs)} errors, {len(v_warns)} warnings")
    for e in v_errs:
        print(f"  UNEXPECTED ERROR: {e}")
    if v_errs:
        ok = False

    i_errs, _ = lint_text(INVALID_SAMPLE, "<invalid-sample>", ids)
    print(f"invalid sample : {len(i_errs)} errors (expected many)")
    expected_substrings = [
        "category_id 'not-a-real-category'",       # bad category
        "version must be an int",                   # version: one
        "variables.image_path: derive-via",         # missing derive note
        "variables.ntfs_offset_sectors missing",    # missing required variable
        "description missing",                      # no description
        "Step 0",                                   # missing Step 0 section
        "Linux branch",                             # missing Linux branch
        "Failure modes",                            # missing failure modes
        "Tuning log",                               # missing tuning log
        "timeline-first",                           # quick path without timeline move
        "CLOSE-GATE INVARIANT missing",             # missing invariant sentinel
        "BANNED literal /evidence",                 # literal path in tool
        'BANNED literal "..."',                     # ellipsis in tool
        "fields out of contract order",             # falsify before check
        "on_result missing branch `neither`",       # incomplete on_result
        "pivots to illegal target 'nowhere-land'",  # bad pivot in on_result
        "emits value 'bogus_bucket'",               # bad emits bucket
        "serves value 'usb-exfil'",                 # serves not in sub_types
        "provenance missing `offset_or_row`",       # incomplete provenance
        "undeclared variable #{undeclared_var}",    # undeclared var ref
        "targets 'unknown-category-id'",            # bad pivot in Pivots section
    ]
    joined = "\n".join(i_errs)
    for s in expected_substrings:
        if s not in joined:
            print(f"  MISSING EXPECTED ERROR containing: {s!r}")
            ok = False

    print("SELFTEST " + ("PASS" if ok else "FAIL"))
    if not ok:
        print("--- invalid-sample errors were ---")
        for e in i_errs:
            print(f"  {e}")
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if argv[0] == "--selftest":
        return selftest()
    ids = load_category_ids()
    if len(ids) != 24:
        print(f"WARN: category id list has {len(ids)} entries (expected 24)", file=sys.stderr)
    rc = 0
    for arg in argv:
        p = pathlib.Path(arg)
        if not p.is_file():
            print(f"{arg}: FAIL — file not found")
            rc = 1
            continue
        errs, warns = lint_file(p, ids)
        status = "PASS" if not errs else f"FAIL ({len(errs)} errors)"
        print(f"{arg}: {status}" + (f", {len(warns)} warnings" if warns else ""))
        for e in errs:
            print(f"  ERROR {e}")
        for w in warns:
            print(f"  warn  {w}")
        if errs:
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
