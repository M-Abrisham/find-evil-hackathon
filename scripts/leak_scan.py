#!/usr/bin/env python3
"""Generic, data-driven, layered leak scanner for the find-evil-hackathon repo.

Replaces the brittle hardcoded-grep gate. Catches leaks by CATEGORY, not by us
having enumerated remembered strings. Stdlib-only Python 3.10 (matches
scoring/scorer.py style: argparse + re + dataclass, no third-party deps).

A "check" emits zero or more Findings. The scanner walks INPUT UNITS, runs every
check on each, applies the allowlist filter, then reports + sets an exit code:

  0  no BLOCK findings (WARN may be present and printed)
  1  >=1 BLOCK finding (the gate FAILS the commit/CI)
  2  usage / IO / git error

Layering: STRUCTURED checks (precise regex / extension / literal) run FIRST and
are authoritative. The ENTROPY check is a FALLBACK only (a real AWS key scores
~3.68 bits/char, below a safe entropy threshold, so entropy alone would MISS it;
the AKIA structured regex is what catches it).
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import math
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from typing import Iterable

# ----------------------------------------------------------------------------
# 0. CORE MODEL
# ----------------------------------------------------------------------------

BLOCK = "BLOCK"
WARN = "WARN"


@dataclass
class Finding:
    file: str
    line: int  # 1-based; 0 for whole-file / path checks
    category: str
    check_id: str
    severity: str
    redacted: str
    match_len: int
    col: int = 0
    suppressed: bool = False
    suppress_reason: str = ""

    def fingerprint(self) -> str:
        h = hashlib.sha1()
        h.update(("%s|%s|%s" % (self.file, self.check_id, self.redacted)).encode("utf-8"))
        return h.hexdigest()


# ----------------------------------------------------------------------------
# Entropy
# ----------------------------------------------------------------------------

def shannon(s: str) -> float:
    """Shannon entropy in bits/char. shannon('') == 0.0."""
    if not s:
        return 0.0
    n = len(s)
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


# ----------------------------------------------------------------------------
# 6(a)/6(b). GLOBAL ALLOWLIST — verdict vocab + MITRE codes are LEGIT rule text
# ----------------------------------------------------------------------------

VERDICT_VOCAB = frozenset({
    "MALICE", "NON_MALICE", "INCONCLUSIVE", "INSUFFICIENT_EVIDENCE",
})
MITRE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def is_globally_allowlisted(snippet: str) -> bool:
    """Belt-and-suspenders: drop any candidate finding whose raw token is a
    verdict-vocab word (exact) or a MITRE code (regex). So a future looser regex
    can't regress these protected strings."""
    tok = snippet.strip()
    if tok in VERDICT_VOCAB:
        return True
    if MITRE_RE.match(tok):
        return True
    return False


# ----------------------------------------------------------------------------
# 1. SECRETS (BLOCK) category="secret"
# ----------------------------------------------------------------------------

RE_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----")
RE_AWS = re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AKIB)[0-9A-Z]{16}\b")
RE_GITHUB = re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b")
RE_GITHUB_PAT = re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")
RE_GITLAB = re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")
RE_SLACK_TOKEN = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")
RE_SLACK_HOOK = re.compile(
    r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+")
RE_GOOGLE_API = re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")
RE_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
RE_SK = re.compile(r"\bsk-[A-Za-z0-9]{24,}\b")

RE_ASSIGNMENT = re.compile(
    r"\b(api[_-]?key|secret[_-]?key|secret|password|passwd|pwd|access[_-]?token|"
    r"auth[_-]?token|token|bearer|client[_-]?secret|private[_-]?key)\b"
    r"\s*[:=]\s*[\"']?([^\s\"']{8,})",
    re.IGNORECASE,
)
RE_DOTENV_LINE = re.compile(r"^\s*([A-Z][A-Z0-9_]{2,})\s*=\s*(.+)$")
PLACEHOLDER_RE = re.compile(
    r"^(?:<[^>]+>|\{\{?[^}]+\}?\}|x{3,}|\*{3,}|\.{3,}|changeme|example|placeholder|"
    r"your[_-]?\w+|dummy|redacted|none|null|true|false|todo|fixme|sample|test|"
    r"foo|bar|baz)$",
    re.IGNORECASE,
)

# fallback entropy token: charset restricted to secret-ish alphabet.
# NOTE: this charset includes '/', '_' and '-', so the greedy match will span
# across path separators / identifier joints — e.g. it eats
# "REPO_DIR/analysis-scripts/generate_pdf_report" as ONE 45-char "token" whose
# whole-string Shannon entropy clears 4.0. Such a token is NOT a secret; it is a
# filesystem path / env identifier / dotted module path. The FP-class-1 guards
# below (_is_path_shaped / _is_env_identifier / _is_dotted_module /
# _contiguous_secret_run) strip that structure off and require a genuine
# contiguous high-entropy RANDOM run before BLOCKing.
RE_ENTROPY_TOKEN = re.compile(r"[A-Za-z0-9+/=_-]{20,}")
RE_GIT_SHA = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")
RE_UUID4 = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")

# A "contiguous secret run" = a maximal run with NO path/identifier separators
# ('/', '~', '_', '-', '.'), i.e. the shape a real opaque key/blob takes
# (AKIA..., a base64 blob, sk-... after the dash). Splitting an entropy token on
# those separators and keeping only the longest piece removes path/env structure
# before we judge randomness.
RE_SECRET_RUN_SPLIT = re.compile(r"[/~_.\-]+")
# ALLCAPS_UNDERSCORE env / shell identifier, e.g. SCRIPT_DIR, CLAUDE_DIR, PATH.
RE_ENV_IDENTIFIER = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$|^[A-Z]{2,}$")
# dotted.module.path or file.ext.with.dots — segments joined by '.' only.
RE_DOTTED_MODULE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$")
# a path-ish segment: a short-ish alnum word, the dictionary-ish shape that
# filesystem / module / url segments take (letters dominate, low-ish entropy).
_WORDY_SEG = re.compile(r"^[A-Za-z][A-Za-z0-9]*$")


def _longest_secret_run(tok: str) -> str:
    """Strip path/identifier separators ('/ ~ _ . -') and return the longest
    remaining CONTIGUOUS run — the only part that could be opaque secret
    material. 'REPO_DIR/analysis-scripts/generate_pdf_report' -> 'generate'."""
    pieces = [p for p in RE_SECRET_RUN_SPLIT.split(tok) if p]
    if not pieces:
        return ""
    return max(pieces, key=len)


def _is_path_shaped(tok: str) -> bool:
    """True for filesystem / URL paths and env-identifier-joined paths: contains
    '/' or '~' (or is otherwise separator-joined) AND breaks into MULTIPLE
    dictionary-ish (wordy / env-id) segments rather than one opaque blob."""
    if "/" not in tok and "~" not in tok:
        return False
    segs = [s for s in RE_SECRET_RUN_SPLIT.split(tok) if s]
    if len(segs) < 2:
        return False
    wordy = sum(1 for s in segs
                if _WORDY_SEG.match(s) or RE_ENV_IDENTIFIER.match(s))
    # the vast majority of segments look like words/identifiers (a path), not a
    # single high-entropy chunk hiding among slashes.
    return wordy >= max(2, (len(segs) + 1) // 2)


def _is_env_identifier(tok: str) -> bool:
    """ALLCAPS_UNDERSCORE env / shell identifier (SCRIPT_DIR, CLAUDE_DIR)."""
    return bool(RE_ENV_IDENTIFIER.match(tok))


def _is_dotted_module(tok: str) -> bool:
    """dotted.module.path / file.name.ext — segments joined only by '.'."""
    if "." not in tok or "/" in tok:
        return False
    return bool(RE_DOTTED_MODULE.match(tok))


def _is_structural_token(tok: str) -> bool:
    """FP-class-1 gate: tok is a path / env-id / dotted-module (NOT a secret)
    UNLESS, after stripping path/identifier structure, a long contiguous random
    run survives (a real key embedded in a path still BLOCKs)."""
    if not (_is_path_shaped(tok) or _is_env_identifier(tok)
            or _is_dotted_module(tok)):
        return False
    run = _longest_secret_run(tok)
    # a genuinely opaque embedded secret (>=20 contiguous chars, high entropy)
    # is NOT exempted — only structural/dictionary-ish material is.
    if len(run) >= 20 and shannon(run) >= 4.0:
        return False
    return True


def _plausible_secret_value(value: str) -> bool:
    """Plausibility gate (sec 1.9): suppress docs/placeholders."""
    if len(value) < 8:
        return False
    if PLACEHOLDER_RE.match(value):
        return False
    has_digit = any(c.isdigit() for c in value)
    has_upper = any(c.isupper() for c in value)
    has_symbol = any(not c.isalnum() for c in value)
    if not (has_digit or has_upper or has_symbol):
        # plain lowercase word: only plausible if long
        if len(value) < 16:
            return False
    if shannon(value) < 2.5:
        return False
    return True


def check_secrets(path: str, lines: list[str]) -> Iterable[Finding]:
    in_key_block = False
    for idx, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n")

        m = RE_PRIVATE_KEY.search(line)
        if m:
            in_key_block = True
            yield _mk(path, idx, "secret", "secret.private_key", BLOCK,
                      _redact_secret(m.group(0)), len(m.group(0)), m.start())
            continue
        if in_key_block:
            if "-----END" in line and "PRIVATE KEY" in line:
                in_key_block = False
            # redact the body: emit nothing per line (block already reported)
            continue

        for rx, cid in (
            (RE_AWS, "secret.aws_akia"),
            (RE_GITHUB, "secret.github"),
            (RE_GITHUB_PAT, "secret.github"),
            (RE_GITLAB, "secret.gitlab"),
            (RE_SLACK_TOKEN, "secret.slack"),
            (RE_SLACK_HOOK, "secret.slack"),
            (RE_GOOGLE_API, "secret.google_api"),
            (RE_JWT, "secret.jwt"),
            (RE_SK, "secret.braintrust"),
        ):
            for m in rx.finditer(line):
                tok = m.group(0)
                if is_globally_allowlisted(tok):
                    continue
                yield _mk(path, idx, "secret", cid, BLOCK,
                          _redact_secret(tok), len(tok), m.start())

        # 1.9 generic assignment
        for m in RE_ASSIGNMENT.finditer(line):
            value = m.group(2)
            if is_globally_allowlisted(value):
                continue
            if PLACEHOLDER_RE.match(value):
                yield _mk(path, idx, "secret", "secret.assignment", WARN,
                          _redact_secret(value), len(value), m.start(2))
            elif _plausible_secret_value(value):
                yield _mk(path, idx, "secret", "secret.assignment", BLOCK,
                          _redact_secret(value), len(value), m.start(2))


def check_dotenv(path: str, lines: list[str]) -> Iterable[Finding]:
    base = os.path.basename(path).lower()
    is_env = bool(re.search(r"(^|/)\.env(\.[\w.-]+)?$", path.replace(os.sep, "/"), re.I)) \
        or base == ".env" or base.endswith(".env")
    if not is_env:
        return
    for idx, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n")
        if line.lstrip().startswith("#"):
            continue
        m = RE_DOTENV_LINE.match(line)
        if not m:
            continue
        value = m.group(2).strip().strip('"').strip("'")
        if is_globally_allowlisted(value):
            continue
        if not _plausible_secret_value(value):
            continue
        if len(value) >= 20 or shannon(value) >= 3.5:
            yield _mk(path, idx, "secret", "secret.dotenv", BLOCK,
                      _redact_secret(value), len(value), m.start(2))
        else:
            yield _mk(path, idx, "secret", "secret.dotenv", WARN,
                      _redact_secret(value), len(value), m.start(2))


def check_entropy(path: str, lines: list[str], already: set[tuple[int, str]]) -> Iterable[Finding]:
    """FALLBACK only: high-entropy opaque token not caught by structured checks.

    FP class 1: the entropy charset spans '/', '_', '-' and so greedily joins
    path / env-identifier / dotted-module segments into one long token whose
    WHOLE-STRING entropy spuriously clears 4.0. We therefore (a) exempt tokens
    that are path-shaped / ALLCAPS_UNDERSCORE env identifiers / dotted module
    paths, and (b) require the longest CONTIGUOUS run (after stripping path /
    identifier separators) to itself be a high-entropy 20+ char chunk — that
    contiguous run is what a real AWS key / base64 blob / sk- key looks like.
    """
    for idx, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n")
        for m in RE_ENTROPY_TOKEN.finditer(line):
            tok = m.group(0)
            if len(tok) < 20:
                continue
            if (idx, tok) in already:
                continue
            if is_globally_allowlisted(tok):
                continue
            # benign-shape exemptions -> WARN, not BLOCK
            if RE_GIT_SHA.match(tok) or RE_UUID4.match(tok):
                if shannon(tok) >= 4.0:
                    yield _mk(path, idx, "secret", "secret.entropy", WARN,
                              _redact_secret(tok), len(tok), m.start())
                continue
            # FP class 1: path / env-identifier / dotted-module structural token.
            if _is_structural_token(tok):
                continue
            # require a CONTIGUOUS high-entropy random run, not just a high
            # whole-token entropy inflated by separator-joined word segments.
            run = _longest_secret_run(tok)
            if len(run) < 20 or shannon(run) < 4.0:
                continue
            yield _mk(path, idx, "secret", "secret.entropy", BLOCK,
                      _redact_secret(run), len(run), m.start())


# ----------------------------------------------------------------------------
# 1.12 DE-OBFUSCATION PRE-PASS (BLOCK) check_id="secret.deobfuscated"
# ----------------------------------------------------------------------------
#
# Splitting a secret across string literals defeats every per-token check:
#
#     key_part_1 = "AKIAZZ"          # <20 chars, low entropy
#     key_part_2 = "4FAKE7EXAMPLE9"  # <20 chars, low entropy
#     full = key_part_1 + key_part_2 # the *reassembled* AKIAZZ4FAKE7EXAMPLE9 is a valid AWS key  # fake example key in detection doc. # leak-scan: allow secret.aws_akia
#
#     token = ("Zk9x2Lm7" "Qp4Rt8Nv" "Wc3Yb6Hd")  # 3x 8-char chunks, each entropy ~3.0
#
# This pre-pass reconstructs candidate secrets two ways, then re-runs the
# structured + entropy secret checks over the synthetic joins:
#   (A) variable-assignment resolution: map `name = "literal"`, then expand any
#       `a + b [+ c...]` expression of those names/literals into the joined value.
#   (B) adjacent-literal joining: any run of >=2 quoted string literals that are
#       adjacent on one line or on consecutive lines (Python implicit/`+` concat)
#       is joined into a synthetic line.
# A WARN is also emitted on the multi-literal concat chain itself when it sits
# near a key-ish variable name, even if the join is sub-threshold, so reviewers
# see the obfuscation attempt.

# a single quoted literal: '...' or "..." (no escaped-quote handling needed for
# secret material, which never contains quotes)
RE_STR_LITERAL = re.compile(r"""(['"])([^'"]*)\1""")
# an identifier = expression assignment
RE_ASSIGN_LHS = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$")
KEYISH_VAR_RE = re.compile(
    r"(?i)(key|token|secret|passw|pwd|cred|api|auth|bearer|akia|aws|part|chunk|"
    r"frag|seg|piece|full|joined|combined)")
# concatenation expression: only identifiers, string literals, '+' and whitespace
RE_CONCAT_EXPR = re.compile(r"""^\s*(?:[A-Za-z_][A-Za-z0-9_]*|['"][^'"]*['"])"""
                            r"""(?:\s*\+\s*(?:[A-Za-z_][A-Za-z0-9_]*|['"][^'"]*['"]))+\s*$""")


def _literals_on_line(line: str) -> list[str]:
    return [m.group(2) for m in RE_STR_LITERAL.finditer(line)]


def deobfuscate(lines: list[str]) -> list[tuple[int, str, bool]]:
    """Return synthetic (line_no, reassembled_text, key_ish) joins worth
    re-scanning.

    line_no is the 1-based line of the first contributing literal (for
    reporting). key_ish is True when the join is anchored to a key-ish variable
    name (key_part_1, token, secret, ...), which gates the sub-threshold WARN.
    Only joins of >=2 literals are returned.
    """
    out: list[tuple[int, str, bool]] = []
    var_value: dict[str, str] = {}   # name -> single-literal value
    var_line: dict[str, int] = {}

    n = len(lines)
    raw = [ln.rstrip("\n") for ln in lines]

    # --- pass A: record simple `name = "literal"` assignments, expand concats ---
    for idx, line in enumerate(raw, start=1):
        m = RE_ASSIGN_LHS.match(line)
        if not m:
            continue
        lhs_name = m.group(1)
        rhs = m.group(2)
        stripped = rhs.strip()
        # a pure single-literal RHS:  name = "AKIAZZ"
        sm = RE_STR_LITERAL.fullmatch(stripped)
        if sm:
            var_value[lhs_name] = sm.group(2)
            var_line[lhs_name] = idx
            continue
        # a concat-expression RHS:  full = key_part_1 + key_part_2 [+ "x"]
        if RE_CONCAT_EXPR.match(rhs):
            joined = []
            first_line = idx
            ok = True
            key_ish = bool(KEYISH_VAR_RE.search(lhs_name))
            for tok in re.split(r"\s*\+\s*", stripped):
                tok = tok.strip()
                lm = RE_STR_LITERAL.fullmatch(tok)
                if lm:
                    joined.append(lm.group(2))
                elif tok in var_value:
                    joined.append(var_value[tok])
                    first_line = min(first_line, var_line.get(tok, idx))
                    if KEYISH_VAR_RE.search(tok):
                        key_ish = True
                else:
                    ok = False
                    break
            if ok and len(joined) >= 2:
                out.append((first_line, "".join(joined), key_ish))

    # --- pass B: adjacent / consecutive quoted-literal runs (implicit concat) ---
    i = 0
    while i < n:
        line = raw[i]
        lits = _literals_on_line(line)
        # same-line run of >=2 literals (e.g.  x = "AB" "CD" "EF"  or "AB"+"CD")
        if len(lits) >= 2 and _is_literal_chain_line(line):
            mlhs = RE_ASSIGN_LHS.match(line)
            key_ish = bool(mlhs and KEYISH_VAR_RE.search(mlhs.group(1)))
            out.append((i + 1, "".join(lits), key_ish))
        # consecutive-line run: lines whose non-literal content is only
        # whitespace / a single trailing '+' / paren scaffolding
        if len(lits) == 1 and _is_bare_literal_line(line):
            run = [lits[0]]
            start = i
            key_ish = False
            mlhs = RE_ASSIGN_LHS.match(line)
            if mlhs and KEYISH_VAR_RE.search(mlhs.group(1)):
                key_ish = True
            # an assignment opener on the PREVIOUS line e.g.  token = (
            if i > 0:
                prev = RE_ASSIGN_LHS.match(raw[i - 1])
                if prev and KEYISH_VAR_RE.search(prev.group(1)) and "(" in raw[i - 1]:
                    key_ish = True
            j = i + 1
            while j < n:
                njits = _literals_on_line(raw[j])
                if len(njits) == 1 and _is_bare_literal_line(raw[j]):
                    run.append(njits[0])
                    j += 1
                else:
                    break
            if len(run) >= 2:
                out.append((start + 1, "".join(run), key_ish))
            i = j
            continue
        i += 1
    return out


def _is_literal_chain_line(line: str) -> bool:
    """True if, after removing the string literals, only concat scaffolding
    remains (a single optional ``name =`` LHS plus ``+``/parens/whitespace) —
    i.e. the literals form a concatenation chain rather than e.g. a dict / call
    with distinct comma-separated args."""
    skel = RE_STR_LITERAL.sub("", line)               # drop the literals
    skel = re.sub(r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*", "", skel)  # drop one LHS
    return re.fullmatch(r"[\s+()]*", skel or "") is not None


def _is_bare_literal_line(line: str) -> bool:
    """True for a line that is essentially one string literal plus optional
    assignment LHS / opening paren / trailing '+' / closing paren scaffolding."""
    skel = RE_STR_LITERAL.sub("\x00", line)
    skel = re.sub(r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*", "", skel)  # name =
    skel = skel.replace("\x00", "")
    return re.fullmatch(r"[\s+()]*", skel or "") is not None


def check_deobfuscated_secrets(path: str, lines: list[str],
                               already: set[tuple[int, str]]) -> Iterable[Finding]:
    """Re-run structured + entropy secret checks over de-obfuscated joins."""
    seen: set[str] = set()
    for line_no, joined, key_ish in deobfuscate(lines):
        if not joined or joined in seen:
            continue
        seen.add(joined)
        if is_globally_allowlisted(joined):
            continue
        fired = False
        # structured secret regexes over the reassembled token
        for rx, cid in (
            (RE_AWS, "secret.aws_akia"),
            (RE_GITHUB, "secret.github"),
            (RE_GITHUB_PAT, "secret.github"),
            (RE_GITLAB, "secret.gitlab"),
            (RE_SLACK_TOKEN, "secret.slack"),
            (RE_GOOGLE_API, "secret.google_api"),
            (RE_JWT, "secret.jwt"),
            (RE_SK, "secret.braintrust"),
        ):
            for m in rx.finditer(joined):
                tok = m.group(0)
                if (line_no, tok) in already:
                    continue
                fired = True
                yield _mk(path, line_no, "secret", "secret.deobfuscated", BLOCK,
                          _redact_secret(tok), len(tok), 0)
        if fired:
            continue
        # entropy fallback: only a CONTIGUOUS secret-charset run (no spaces /
        # punctuation) counts — so a join of English/SQL words (which contain
        # spaces and thus yields no 20+ secret-charset token) can never BLOCK,
        # but a reassembled opaque token like Zk9x2Lm7Qp4Rt8NvWc3Yb6Hd does.  # synthetic token in detection doc. # leak-scan: allow secret.entropy
        block_token = None
        for tm in RE_ENTROPY_TOKEN.finditer(joined):
            sub = tm.group(0)
            if len(sub) < 20:
                continue
            if RE_GIT_SHA.match(sub) or RE_UUID4.match(sub):
                continue
            if shannon(sub) >= 4.0:
                block_token = sub
                break
        if block_token is not None:
            yield _mk(path, line_no, "secret", "secret.deobfuscated", BLOCK,
                      _redact_secret(block_token), len(block_token), 0)
        elif key_ish and re.fullmatch(r"[A-Za-z0-9+/=_-]+", joined) \
                and 12 <= len(joined) < 20 and shannon(joined) >= 3.0:
            # sub-threshold but a key-ish, space-free opaque concat chain —
            # surface the obfuscation attempt so a reviewer eyeballs it.
            yield _mk(path, line_no, "secret", "secret.deobfuscated", WARN,
                      _redact_secret(joined), len(joined), 0)


# ----------------------------------------------------------------------------
# 2. EVIDENCE / BINARY (BLOCK) category="evidence"
# ----------------------------------------------------------------------------

RE_EVIDENCE_EXT = re.compile(
    r"(?i)\.(e01|s01|l01|ex01|dd|raw|img|001|aff4?|vhdx?|vdi|qcow2|vmdk|mem|vmem|"
    r"vmsn|vmss|dmp|lime|core|pcapng?|cap|evtx?|hiberfil)$")
EVIDENCE_STEMS = re.compile(
    r"(?i)\.(e01|s01|l01|ex01|dd|raw|img|001|aff4?|vhdx?|vdi|qcow2|vmdk|mem|vmem|"
    r"vmsn|vmss|dmp|lime|core|pcapng?|cap|evtx?|hiberfil)\."
    r"(gz|zip|7z|tar|tgz)$")
RE_ARCHIVE = re.compile(r"(?i)\.(zip|gz|7z|tar|tgz)$")

MAGIC = [
    (b"EVF\x09\x0d\x0a\xff\x00", "EVF/E01"),
    (b"\xd4\xc3\xb2\xa1", "PCAP"),
    (b"\xa1\xb2\xc3\xd4", "PCAP"),
    (b"\x0a\x0d\x0d\x0a", "PCAPNG"),
    (b"ElfFile\x00", "EVTX"),
    (b"KDMV", "VMDK"),
    (b"# Disk Descriptor", "VMDK"),
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE"),
    (b"SQLite format 3\x00", "SQLite"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPG"),
    (b"\x1f\x8b", "GZIP"),
    (b"PK\x03\x04", "ZIP"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
]

TEXT_BYTES = set(range(0x20, 0x7F)) | {0x09, 0x0a, 0x0d, 0x0c}


def sniff_binary(head: bytes) -> tuple[bool, str]:
    """Return (is_binary, magic_label)."""
    if not head:
        return False, ""
    for sig, label in MAGIC:
        if head.startswith(sig):
            return True, label
    if b"\x00" in head:
        return True, "NUL"
    nontext = sum(1 for b in head if b not in TEXT_BYTES)
    if nontext / len(head) > 0.30:
        return True, "nontext>30%"
    return False, ""


def check_evidence_path(path: str, size: int, head: bytes, max_bytes: int) -> Iterable[Finding]:
    posix = path.replace(os.sep, "/")
    # 2.1 extension blocklist
    if RE_EVIDENCE_EXT.search(posix):
        yield _mk(path, 0, "evidence", "evidence.extension", BLOCK,
                  "<evidence-extension:%s>" % posix.rsplit(".", 1)[-1], 0)
    elif EVIDENCE_STEMS.search(posix):
        yield _mk(path, 0, "evidence", "evidence.extension", BLOCK,
                  "<archived-evidence:%s>" % posix.rsplit("/", 1)[-1], 0)
    # 2.2 binary-content sniff
    is_bin, label = sniff_binary(head)
    if is_bin:
        yield _mk(path, 0, "evidence", "evidence.binary_content", BLOCK,
                  "<binary:%s>" % label, len(head))
    # 2.3 oversize
    if size > max_bytes:
        yield _mk(path, 0, "evidence", "evidence.oversize", BLOCK,
                  "<%d bytes > %d>" % (size, max_bytes), size)


# ----------------------------------------------------------------------------
# 3. FORBIDDEN PATHS / NAMES (BLOCK) category="forbidden_path"
# ----------------------------------------------------------------------------

FORBIDDEN_PATH_RULES = [
    ("backup", re.compile(r"(?i)(\.bak(\.[\w-]+)?$|~$|\.orig$|\.swp$)")),
    ("local_settings", re.compile(
        r"(?i)((^|/)settings\.local\.json$|(^|/)\.claude/settings\.local\.json$)")),
    ("secret_name", re.compile(r"(?i)(^|/)[^/]*secret[^/]*$")),
    ("seed_files", re.compile(r"(?i)(^|/)seed_files?(/|$)")),
    ("answer_key", re.compile(
        r"(?i)(answer[_-]?key|ground[_-]?truth|solution|writeup|walkthrough|"
        r"cheat[_-]?sheet|/key\.txt$|^key\.txt$)")),
    ("nested_git", re.compile(r"(?i)(^|/)\.git/")),
]


def check_forbidden_path(path: str) -> Iterable[Finding]:
    posix = path.replace(os.sep, "/")
    for rule, rx in FORBIDDEN_PATH_RULES:
        if rx.search(posix):
            yield _mk(path, 0, "forbidden_path", "forbidden_path.%s" % rule, BLOCK,
                      "<%s:%s>" % (rule, posix), 0)


# ----------------------------------------------------------------------------
# 4. CASE-ANSWER LEAK (BLOCK) category="answer_leak"
# ----------------------------------------------------------------------------

# DEFAULT forbidden-literal set: NON-SENSITIVE structural markers only.
# MUST NOT contain real answer values (blind-isolation rule).
DEFAULT_FORBIDDEN_LITERALS = [
    "ground_truth.json",  # this IS the forbidden-literal we search for. # leak-scan: allow answer_leak.literal
]
MIN_LITERAL_LEN = 4


def compile_literals(literals: Iterable[str]) -> list[tuple[str, re.Pattern]]:
    out = []
    for lit in literals:
        lit = lit.strip()
        if not lit or lit.startswith("#"):
            continue
        if len(lit) < MIN_LITERAL_LEN:
            sys.stderr.write(
                "leak-scan: WARN skipping too-short forbidden literal (len<%d)\n"
                % MIN_LITERAL_LEN)
            continue
        # whitespace-normalize multi-word literals
        norm = re.escape(lit)
        norm = re.sub(r"(\\?\s)+", r"\\s+", norm)
        pat = re.compile(r"(?<![\w-])" + norm + r"(?![\w-])", re.IGNORECASE)
        out.append((lit, pat))
    return out


def check_answer_leak(path: str, lines: list[str],
                      compiled: list[tuple[str, re.Pattern]]) -> Iterable[Finding]:
    for idx, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n")
        for lit, pat in compiled:
            m = pat.search(line)
            if m:
                yield _mk(path, idx, "answer_leak", "answer_leak.literal", BLOCK,
                          _redact_secret(m.group(0)), len(m.group(0)), m.start())


# ----------------------------------------------------------------------------
# 5. GENERIC INDICATORS (WARN) category="indicator"
# ----------------------------------------------------------------------------

import ipaddress  # noqa: E402

RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_HASH = re.compile(r"\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{64}\b")
RE_MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
RE_B64 = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")
RE_GIT_CTX = re.compile(r"(?i)\b(commit|tree|blob|parent)\b")

DOC_NETS = [ipaddress.ip_network(n) for n in
            ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
RFC1918 = [ipaddress.ip_network(n) for n in
           ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def _ip_excluded(ip: ipaddress.IPv4Address) -> bool:
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return True
    if ip == ipaddress.ip_address("255.255.255.255"):
        return True
    for net in DOC_NETS:
        if ip in net:
            return True
    # all-zeros host of a /NN is the network id — but we only have bare IPs here;
    # the .0 / .255 conventional network/broadcast bases:
    last = int(str(ip).split(".")[-1])
    if last == 0:
        return True
    return False


def check_indicators(path: str, lines: list[str], warn_rfc1918: bool) -> Iterable[Finding]:
    for idx, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n")
        # 5.1 IPv4
        for m in RE_IPV4.finditer(line):
            tok = m.group(0)
            try:
                ip = ipaddress.ip_address(tok)
            except ValueError:
                continue
            if not isinstance(ip, ipaddress.IPv4Address):
                continue
            if _ip_excluded(ip):
                continue
            is_priv = any(ip in n for n in RFC1918)
            if is_priv and not warn_rfc1918:
                continue
            tag = "private" if is_priv else "public"
            yield _mk(path, idx, "indicator", "indicator.ipv4", WARN,
                      "%s (%s)" % (tok, tag), len(tok), m.start())
        # 5.2 hashes
        for m in RE_HASH.finditer(line):
            tok = m.group(0)
            if len(tok) in (40, 64) and RE_GIT_CTX.search(line):
                continue
            if len(tok) in (40, 64) and re.match(r"^[+-]?[0-9a-f]{40}\s", line):
                continue
            yield _mk(path, idx, "indicator", "indicator.hash", WARN,
                      tok, len(tok), m.start())
        # 5.3 MAC
        for m in RE_MAC.finditer(line):
            tok = m.group(0)
            norm = tok.lower().replace("-", ":")
            if norm in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                continue
            yield _mk(path, idx, "indicator", "indicator.mac", WARN,
                      tok, len(tok), m.start())
        # 5.4 base64 blob (not already a structured secret)
        for m in RE_B64.finditer(line):
            tok = m.group(0)
            if RE_JWT.search(tok) or RE_AWS.search(tok):
                continue
            if shannon(tok) < 3.5:
                continue
            yield _mk(path, idx, "indicator", "indicator.base64", WARN,
                      tok[:8] + "...", len(tok), m.start())


def check_archive_path(path: str) -> Iterable[Finding]:
    posix = path.replace(os.sep, "/")
    if RE_ARCHIVE.search(posix) and not EVIDENCE_STEMS.search(posix) \
            and not RE_EVIDENCE_EXT.search(posix):
        yield _mk(path, 0, "indicator", "indicator.archive", WARN,
                  "<uninspected archive:%s>" % posix.rsplit("/", 1)[-1], 0)


# ----------------------------------------------------------------------------
# 4b. CASE-ANSWER DISCLOSURE (BLOCK) check_id="answer_leak.disclosure"
# ----------------------------------------------------------------------------
#
# Individually a public attacker IP, a malware name, and a 64-hex "SHA256 answer"
# are each only WARN-worthy indicators. But a *report-shaped* file that
# CO-LOCATES them is disclosing the case answer and must BLOCK. Two triggers:
#
#   (1) an answer-shaped 64-hex hash near answer/verdict keywords
#       ("SHA256 answer", "IOC", "attacker", "malware", a MALICE/NON_MALICE
#       verdict), OR
#   (2) a cluster within the file of a public (non-doc, non-RFC1918) IP +
#       a 64-hex hash + a named binary (e.g. FakeRansom.exe).
#
# Scope: applies to documentation/report-style files (*.md/.markdown/.txt/.rst
# /.adoc and any file whose path looks like a report/incident/finding), where
# answer disclosure is the realistic leak. Code/config files keep their existing
# per-token WARNs (a 64-hex constant in source is usually a real digest).

RE_HEX64 = re.compile(r"\b[0-9a-fA-F]{64}\b")
# FP class 2: well-known EMPTY/ZERO digests are textbook forensic constants
# (the hash of a zero-byte file). They appear in YARA-rule examples, checksum
# docs, and teaching prose — never a case-specific answer. Allowlist them so a
# lone textbook hash can NEVER be the case-specific value in a disclosure
# cluster. Lowercased for case-insensitive membership testing.
WELL_KNOWN_EMPTY_HASHES = frozenset({
    "d41d8cd98f00b204e9800998ecf8427e",                                  # MD5("")
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",                          # SHA1("")
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA256("")
    # zero / all-same trivial fills frequently used as placeholders in docs
    "0" * 32, "0" * 40, "0" * 64,
})


def _is_well_known_hash(tok: str) -> bool:
    return tok.lower() in WELL_KNOWN_EMPTY_HASHES


def _real_case_hex64(lines: list[str]) -> tuple[int, str]:
    """Return (1-based line, hash) of the FIRST 64-hex hash that is NOT a
    well-known empty/textbook constant; (0, "") if none. A genuine case answer
    needs a real, case-specific digest — a textbook empty hash does not count."""
    for idx, raw in enumerate(lines, start=1):
        for m in RE_HEX64.finditer(raw):
            if not _is_well_known_hash(m.group(0)):
                return idx, m.group(0)
    return 0, ""


RE_NAMED_BINARY = re.compile(
    r"(?i)\b[\w.-]+\.(?:exe|dll|sys|scr|bat|ps1|vbs|js|jar|elf|bin|app|dmg|"
    r"so|ko|hta|lnk|msi)\b")
# Generic OS / built-in / dual-use binaries named in RULE PROSE and guidance
# (anti-hallucination text routinely lists these as PRESUMED-LEGIT examples).
# A disclosure cluster must rest on a SPECIFIC named sample, not these.
GENERIC_BINARY_NAMES = frozenset({
    # core OS processes
    "svchost.exe", "powershell.exe", "powershell_ise.exe", "cmd.exe",
    "explorer.exe", "lsass.exe", "services.exe", "winlogon.exe", "csrss.exe",
    "smss.exe", "wininit.exe", "conhost.exe", "taskhost.exe", "taskhostw.exe",
    "dllhost.exe", "spoolsv.exe", "lsm.exe", "fontdrvhost.exe", "dwm.exe",
    "sihost.exe", "ctfmon.exe", "searchindexer.exe", "runtimebroker.exe",
    # built-in admin / LOLBin tooling routinely named in DFIR guidance prose
    "rundll32.exe", "regsvr32.exe", "wmic.exe", "mshta.exe", "msiexec.exe",
    "certutil.exe", "net.exe", "net1.exe", "at.exe", "schtasks.exe",
    "bitsadmin.exe", "wscript.exe", "cscript.exe", "reg.exe", "sc.exe",
    "tasklist.exe", "taskkill.exe", "whoami.exe", "ipconfig.exe", "netsh.exe",
    "nltest.exe", "ping.exe", "arp.exe", "route.exe", "nbtstat.exe",
    "psexec.exe", "procdump.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
    "msbuild.exe", "control.exe", "forfiles.exe", "wuauclt.exe", "vssadmin.exe",
    "wbadmin.exe", "bcdedit.exe", "fltmc.exe", "fsutil.exe", "esentutl.exe",
    "notepad.exe", "calc.exe", "mmc.exe", "eventvwr.exe", "regedit.exe",
    # ubiquitous system DLLs
    "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll", "gdi32.dll",
    "advapi32.dll", "ole32.dll", "shell32.dll", "ws2_32.dll", "msvcrt.dll",
})


def _specific_named_binary(text: str) -> str | None:
    """Return the first named binary that is NOT a generic OS/dual-use process,
    i.e. a plausibly case-specific sample (FakeRansom.exe, Evil.dll). None if
    every match is a generic built-in mentioned in guidance prose."""
    for m in RE_NAMED_BINARY.finditer(text):
        if m.group(0).lower() not in GENERIC_BINARY_NAMES:
            return m.group(0)
    return None


# Well-known benign public IPs (public resolvers / connectivity-test targets)
# that routinely appear in GUIDANCE PROSE ("ping 8.8.8.8 to test connectivity")
# and must NOT count as a case-specific attacker IP in a disclosure cluster.
BENIGN_PUBLIC_IPS = frozenset({
    "8.8.8.8", "8.8.4.4", "8.4.4.8",          # Google DNS
    "1.1.1.1", "1.0.0.1",                       # Cloudflare DNS
    "9.9.9.9",                                  # Quad9
    "208.67.222.222", "208.67.220.220",         # OpenDNS
})


def _has_case_specific_public_ip(indicators: list[Finding]) -> bool:
    """A public-IP indicator that is NOT a well-known benign resolver/test IP —
    i.e. a plausibly case-specific attacker IP for disclosure-cluster purposes."""
    for f in indicators:
        if f.check_id != "indicator.ipv4" or "(public)" not in f.redacted:
            continue
        ip = f.redacted.split()[0]
        if ip not in BENIGN_PUBLIC_IPS:
            return True
    return False
# STRONG answer/verdict-disclosure vocabulary. Deliberately EXCLUDES the generic
# hash-algorithm words (sha256/md5/hash/digest), which legitimately appear in a
# README checksum/verification note and must NOT by themselves escalate.
ANSWER_KEYWORD_RE = re.compile(
    r"(?i)\b(answer|verdict|ground[\s_-]?truth|attacker|adversary|"
    r"malware|ransom(?:ware)?|payload|dropper|implant|beacon|c2|"
    r"command[\s-]?and[\s-]?control|ioc|indicator[\s-]?of[\s-]?compromise|"
    r"compromise(?:d)?|exfil(?:tration)?|lateral[\s-]?movement|"
    r"the\s+flag|culprit|perpetrator)\b")
# checksum / verification context that EXEMPTS an otherwise-bare hash mention
RE_CHECKSUM_CTX = re.compile(
    r"(?i)\b(checksum|verify|verification|digest|fingerprint|release|tarball|"
    r"download|integrity|signature|sign(?:ed|ing)?|gpg|pgp)\b")
VERDICT_TOKEN_RE = re.compile(r"\b(MALICE|NON_MALICE|INCONCLUSIVE|INSUFFICIENT_EVIDENCE)\b")
RE_REPORTISH_NAME = re.compile(
    r"(?i)(report|incident|finding|writeup|write[\s_-]?up|analysis|summary|"
    r"conclusion|verdict|answer)")
RE_DOC_EXT = re.compile(r"(?i)\.(md|markdown|txt|rst|adoc|asciidoc|text)$")


def _is_doc_like(posix: str) -> bool:
    base = posix.rsplit("/", 1)[-1]
    return bool(RE_DOC_EXT.search(base) or RE_REPORTISH_NAME.search(posix))


def check_case_disclosure(path: str, lines: list[str],
                          indicators: list[Finding]) -> Iterable[Finding]:
    """File-level escalation: report-style answer disclosure -> BLOCK.

    FP class 2: do NOT fire on generic RULE PROSE (anti-hallucination guidance,
    YARA-rule examples) or on a LONE textbook hash. A genuine disclosure needs a
    case-specific value CLUSTER — a SPECIFIC non-textbook digest and/or a public
    (non-doc) IP and/or a SPECIFIC named sample binary co-located. Well-known
    empty/zero hashes and generic OS/dual-use binary names never count toward the
    cluster; verdict-vocab words alone (which legitimately appear as defined
    terms in rule prose) never escalate by themselves.
    """
    posix = path.replace(os.sep, "/")
    if not _is_doc_like(posix):
        return
    text = "\n".join(ln.rstrip("\n") for ln in lines)

    # a CASE-SPECIFIC 64-hex hash (textbook empty/zero hashes excluded)
    hash_line, _case_hash = _real_case_hex64(lines)

    has_answer_kw = bool(ANSWER_KEYWORD_RE.search(text))
    has_verdict_tok = bool(VERDICT_TOKEN_RE.search(text))
    has_checksum_ctx = bool(RE_CHECKSUM_CTX.search(text))

    # a CASE-SPECIFIC public IP (well-known benign resolvers / connectivity-test
    # targets like 8.8.8.8, mentioned in guidance prose, do NOT count)
    has_public_ip = _has_case_specific_public_ip(indicators)
    # a SPECIFIC sample binary (generic OS/dual-use processes do NOT count)
    has_named_binary = _specific_named_binary(text) is not None

    fired = False
    line_no = hash_line or 1

    # trigger (1): a case-specific 64-hex hash + STRONG answer/verdict vocab.
    # A bare checksum/release note (sha256 of a tarball) lacks the strong vocab
    # (sha256/md5/hash are intentionally NOT in ANSWER_KEYWORD_RE), so it never
    # reaches here. As extra insurance, a hash that sits ONLY in checksum context
    # with no corroborating disclosure signal (public IP / named binary) is held
    # to the verdict-token bar, not the looser keyword bar.
    if hash_line and has_answer_kw and not (
            has_checksum_ctx and not has_verdict_tok
            and not has_public_ip and not has_named_binary):
        fired = True
    # trigger (1a): a case-specific hash + a corroborating cluster signal (public
    # IP or a SPECIFIC sample binary). A lone hash next to a verdict-vocab word
    # is no longer enough; it must co-locate with another case-specific value.
    elif hash_line and has_verdict_tok and (has_public_ip or has_named_binary):
        fired = True
    # trigger (2): public IP + case-specific hash + specific named binary cluster
    elif hash_line and has_public_ip and has_named_binary:
        fired = True
    # trigger (1b): verdict token co-located with a SPECIFIC named sample binary
    # (or a public IP) in a report-named file — a disclosed verdict + a concrete
    # case artifact IS the case answer. The SPECIFIC-binary filter is what kills
    # the FP: generic rule prose (a verdict-vocab term plus a built-in process
    # name like svchost.exe in a skills/*-analysis/ path) yields
    # has_named_binary=False and so no longer trips this.
    elif has_verdict_tok and (has_named_binary or has_public_ip) \
            and RE_REPORTISH_NAME.search(posix):
        fired = True
        line_no = next((i for i, ln in enumerate(lines, 1)
                        if VERDICT_TOKEN_RE.search(ln)), 1)

    if fired:
        yield _mk(path, line_no, "answer_leak", "answer_leak.disclosure", BLOCK,
                  "<case-answer-disclosure:%s>" % posix.rsplit("/", 1)[-1], 0)


# ----------------------------------------------------------------------------
# Redaction (sec 8)
# ----------------------------------------------------------------------------

def _redact_secret(tok: str) -> str:
    lead = tok[:4]
    stars = "*" * min(max(len(tok) - 4, 0), 12)
    return lead + stars


def _mk(file, line, category, check_id, severity, redacted, match_len, col=0):
    return Finding(file=file, line=line, category=category, check_id=check_id,
                   severity=severity, redacted=redacted, match_len=match_len, col=col)


# ----------------------------------------------------------------------------
# 6.1/6.2 Allowlists
# ----------------------------------------------------------------------------

RE_INLINE_ALLOW = re.compile(
    r"(?:#|//|<!--)\s*leak-scan:\s*allow(?:\s+([A-Za-z0-9_.,\s-]+?))?\s*(?:-->)?\s*$"
    r"|leak-scan:allow\s*$")


def inline_allow_for_line(line: str) -> tuple[bool, set[str]]:
    """Return (has_allow, set_of_scoped_check_ids). Empty set => allow ALL."""
    m = RE_INLINE_ALLOW.search(line)
    if not m:
        return False, set()
    scope = m.group(1) if m.lastindex else None
    if not scope:
        return True, set()
    ids = {s.strip() for s in re.split(r"[,\s]+", scope) if s.strip()}
    # filter to things that look like check_ids (contain a dot) else treat as all
    ids = {i for i in ids if "." in i}
    return True, ids


@dataclass
class IgnoreRules:
    whole_file: list[str] = field(default_factory=list)
    scoped: list[tuple[str, set[str]]] = field(default_factory=list)

    def file_ignored(self, relpath: str) -> bool:
        for glob in self.whole_file:
            if fnmatch.fnmatch(relpath, glob) or fnmatch.fnmatch(relpath, glob.rstrip("/") + "/*"):
                return True
        return False

    def scoped_checks(self, relpath: str) -> set[str]:
        out: set[str] = set()
        for glob, ids in self.scoped:
            if fnmatch.fnmatch(relpath, glob) or fnmatch.fnmatch(relpath, glob.rstrip("/") + "/*"):
                out |= ids
        return out


def load_ignore(root: str) -> IgnoreRules:
    rules = IgnoreRules()
    # discover up-tree from root
    candidate = os.path.join(root, ".leakscanignore")
    if not os.path.isfile(candidate):
        return rules
    with open(candidate, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "::" in line:
                glob, ids = line.split("::", 1)
                idset = {s.strip() for s in re.split(r"[,\s]+", ids) if s.strip()}
                rules.scoped.append((glob.strip(), idset))
            else:
                rules.whole_file.append(line)
    return rules


# ----------------------------------------------------------------------------
# 7. INPUT MODES & SCAN UNIT
# ----------------------------------------------------------------------------

def git(args: list[str], root: str) -> str:
    res = subprocess.run(["git"] + args, cwd=root, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError("git %s failed: %s" % (" ".join(args), res.stderr.strip()))
    return res.stdout


def discover_root(explicit: str | None) -> str:
    if explicit:
        return os.path.abspath(explicit)
    try:
        out = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                             capture_output=True, text=True)
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except Exception:
        pass
    return os.getcwd()


def iter_paths_recursive(paths: list[str], root: str) -> Iterable[str]:
    for p in paths:
        if os.path.isdir(p):
            for dirpath, dirnames, filenames in os.walk(p):
                # skip the repo's own top-level .git
                if os.path.abspath(dirpath) == os.path.join(root, ".git"):
                    dirnames[:] = []
                    continue
                # do not descend into top-level .git
                if ".git" in dirnames and os.path.abspath(dirpath) == os.path.abspath(root):
                    dirnames.remove(".git")
                for fn in filenames:
                    yield os.path.join(dirpath, fn)
        elif os.path.isfile(p):
            yield p


def read_head(path: str, n: int = 8192) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(n)
    except OSError:
        return b""


def read_lines(path: str) -> list[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.readlines()
    except OSError:
        return []


# ----------------------------------------------------------------------------
# Scan driver
# ----------------------------------------------------------------------------

def scan_unit(relpath: str, abspath: str, *, size: int, head: bytes,
              lines: list[str] | None, is_binary: bool,
              compiled_literals: list[tuple[str, re.Pattern]],
              max_bytes: int, warn_rfc1918: bool) -> list[Finding]:
    findings: list[Finding] = []
    # path-level checks (always run)
    findings.extend(check_evidence_path(relpath, size, head, max_bytes))
    findings.extend(check_forbidden_path(relpath))
    findings.extend(check_archive_path(relpath))
    if is_binary or lines is None:
        return findings
    # line-level content checks
    sec = list(check_secrets(relpath, lines))
    findings.extend(sec)
    findings.extend(check_dotenv(relpath, lines))
    already = {(f.line, _unredact_hint(f)) for f in sec}
    # entropy fallback: pass tokens already matched per line
    matched_per_line: set[tuple[int, str]] = set()
    for idx, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n")
        for rx in (RE_AWS, RE_GITHUB, RE_GITHUB_PAT, RE_GITLAB, RE_SLACK_TOKEN,
                   RE_GOOGLE_API, RE_JWT, RE_SK):
            for m in rx.finditer(line):
                matched_per_line.add((idx, m.group(0)))
    findings.extend(check_entropy(relpath, lines, matched_per_line))
    findings.extend(check_deobfuscated_secrets(relpath, lines, matched_per_line))
    findings.extend(check_answer_leak(relpath, lines, compiled_literals))
    indicators = list(check_indicators(relpath, lines, warn_rfc1918))
    findings.extend(indicators)
    findings.extend(check_case_disclosure(relpath, lines, indicators))
    return findings


def _unredact_hint(f: Finding) -> str:
    return f.redacted


def apply_allowlists(findings: list[Finding], lines: list[str] | None,
                     relpath: str, ignore: IgnoreRules) -> None:
    scoped = ignore.scoped_checks(relpath)
    for f in findings:
        # file-scoped check exemptions
        if f.check_id in scoped or any(
                f.check_id.startswith(s) for s in scoped if s.endswith(".")):
            f.suppressed = True
            f.suppress_reason = "leakscanignore-scoped"
            continue
        # inline allow
        if lines is not None and 1 <= f.line <= len(lines):
            has_allow, ids = inline_allow_for_line(lines[f.line - 1])
            if has_allow and (not ids or f.check_id in ids):
                f.suppressed = True
                f.suppress_reason = "inline"


def run_scan(args) -> int:
    root = discover_root(args.root)
    ignore = load_ignore(root)

    # forbidden literals
    literals = list(DEFAULT_FORBIDDEN_LITERALS)
    forbidden_files_abs = set()
    for ff in (args.forbidden_file or []):
        ffabs = os.path.abspath(ff)
        forbidden_files_abs.add(ffabs)
        try:
            with open(ff, "r", encoding="utf-8", errors="replace") as fh:
                for raw in fh:
                    literals.append(raw.rstrip("\n"))
        except OSError as e:
            sys.stderr.write("leak-scan: ERROR cannot read --forbidden-file %s: %s\n" % (ff, e))
            return 2
    compiled_literals = compile_literals(literals)

    # build file list per mode
    try:
        file_list = collect_files(args, root)
    except RuntimeError as e:
        sys.stderr.write("leak-scan: ERROR %s\n" % e)
        return 2

    baseline = set()
    if args.baseline:
        try:
            with open(args.baseline, "r", encoding="utf-8") as fh:
                baseline = set(json.load(fh))
        except OSError as e:
            sys.stderr.write("leak-scan: ERROR cannot read --baseline: %s\n" % e)
            return 2

    all_findings: list[Finding] = []
    files_scanned = 0
    for abspath in file_list:
        if not os.path.isfile(abspath):
            continue
        relpath = os.path.relpath(abspath, root).replace(os.sep, "/")
        # always skip top-level .git
        if relpath == ".git" or relpath.startswith(".git/"):
            continue
        # whole-file ignore (but never ignore a --forbidden-file input that sits in tree)
        if ignore.file_ignored(relpath) and os.path.abspath(abspath) not in forbidden_files_abs:
            continue
        files_scanned += 1
        size = os.path.getsize(abspath)
        head = read_head(abspath)
        is_bin, _ = sniff_binary(head)
        lines = None if is_bin else read_lines(abspath)
        findings = scan_unit(relpath, abspath, size=size, head=head, lines=lines,
                             is_binary=is_bin, compiled_literals=compiled_literals,
                             max_bytes=args.max_bytes, warn_rfc1918=args.warn_rfc1918)
        # forbidden-file inputs auto-allowlisted so they can't self-flag
        if os.path.abspath(abspath) in forbidden_files_abs:
            findings = []
        apply_allowlists(findings, lines, relpath, ignore)
        # baseline ignore
        for f in findings:
            if f.fingerprint() in baseline:
                f.suppressed = True
                f.suppress_reason = "baseline"
        all_findings.extend(findings)

    return report(all_findings, files_scanned, args.format)


def collect_files(args, root: str) -> list[str]:
    if args.files:
        return [os.path.abspath(f) for f in args.files]
    if args.paths:
        return list(iter_paths_recursive([os.path.abspath(p) for p in args.paths], root))
    if args.range:
        out = git(["diff", "--name-only", args.range], root)
        return [os.path.join(root, p) for p in out.splitlines() if p.strip()]
    # default: --staged
    out = git(["diff", "--cached", "--name-only", "--diff-filter=ACMR"], root)
    return [os.path.join(root, p) for p in out.splitlines() if p.strip()]


# ----------------------------------------------------------------------------
# 8. OUTPUT / 9. EXIT CODES
# ----------------------------------------------------------------------------

def report(findings: list[Finding], files_scanned: int, fmt: str) -> int:
    active = [f for f in findings if not f.suppressed]
    suppressed = [f for f in findings if f.suppressed]
    blocks = [f for f in active if f.severity == BLOCK]
    warns = [f for f in active if f.severity == WARN]
    exit_code = 1 if blocks else 0

    if fmt == "json":
        objs = []
        for f in findings:
            d = asdict(f)
            d.pop("suppress_reason", None)
            objs.append(d)
        objs.append({"summary": {
            "block": len(blocks), "warn": len(warns),
            "suppressed": len(suppressed), "files": files_scanned,
            "exit": exit_code,
        }})
        print(json.dumps(objs, indent=2))
        return exit_code

    # text
    for f in blocks:
        print("BLOCK  %s/%s  %s:%d:%d  %s" % (
            f.category, f.check_id, f.file, f.line, f.col, f.redacted))
    for f in warns:
        print("WARN   %s/%s  %s:%d:%d  %s" % (
            f.category, f.check_id, f.file, f.line, f.col, f.redacted))
    print("Summary: %d BLOCK, %d WARN, %d suppressed across %d files." % (
        len(blocks), len(warns), len(suppressed), files_scanned))
    return exit_code


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="leak_scan.py",
        description="Generic, layered leak scanner for the find-evil-hackathon repo.")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--staged", action="store_true",
                      help="scan git staged changes (default)")
    mode.add_argument("--range", metavar="A..B",
                      help="scan files changed in a commit range")
    mode.add_argument("--files", nargs="+", metavar="F",
                      help="scan an explicit list of files")
    p.add_argument("paths", nargs="*", help="positional: files/dirs to scan (recursive)")
    p.add_argument("--forbidden-file", action="append", metavar="PATH",
                   help="load extra answer-leak literals at runtime (repeatable)")
    p.add_argument("--max-bytes", type=int, default=5_000_000,
                   help="oversize-file BLOCK threshold (default 5MB)")
    p.add_argument("--no-warn-rfc1918", dest="warn_rfc1918", action="store_false",
                   default=True, help="suppress RFC1918 private-IP WARNings")
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.add_argument("--baseline", metavar="FILE",
                   help="JSON list of accepted finding fingerprints to ignore")
    p.add_argument("--root", metavar="DIR",
                   help="repo root for relative paths / ignore discovery")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run_scan(args)
    except RuntimeError as e:
        sys.stderr.write("leak-scan: ERROR %s\n" % e)
        return 2


if __name__ == "__main__":
    sys.exit(main())
