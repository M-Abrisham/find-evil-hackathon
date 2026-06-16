"""keep_or_revert.py — the decider (roadmap 8.5).

Three jobs:
  1. decide(baseline_agg, post_agg) -> (decision, reason, deltas)
       thin delegation to composite.compare (the shared gated-dims core).
  2. revert(playbook_path, *, versions_dir=None, use_git_fallback=True)
       the REVERT EXECUTOR. Snapshot-restore PRIMARY (byte-for-byte file copy,
       deterministic, no git) + orphan-clean (delete v<new>.diff / v<new>.trace.json)
       + KEEP the snapshot + git-restore FALLBACK only when the snapshot is
       missing/corrupt AND the dir is a real work-tree AND the file is tracked,
       else HARD-FAIL LOUDLY (never half-revert and report success). Idempotent.
       Layout MATCHES playbooks/tune_playbook.py.
  3. hedge_format_intact(text) -> bool
       born-safe G-HEDGE-IMMUT format guard.
  4. argparse CLI: --baseline @f --post @f [--versions-dir P --category C --apply].
       exit 0 == KEEP, nonzero == REVERT; prints decision JSON; --apply runs revert.

FLAT sibling imports (scoring/ has no __init__.py): import composite, import scorer.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from typing import Any

import composite  # flat sibling import

# scorer is imported lazily inside helpers that need verdict/hedge primitives so the
# pure decision path (decide/compare) never pays for it.

# Frontmatter version line — same shape tune_playbook.bump_version matches.
_VERSION_RE = re.compile(r"^version:\s*(\d+)\s*$", re.M)


# =============================================================================
# 1. Decision (delegates to composite.compare).
# =============================================================================
def decide(baseline_agg, post_agg, *, eps_recall=0.0):
    """(decision, reason, deltas). Pure delegation to composite.compare."""
    return composite.compare(baseline_agg, post_agg, eps_recall=eps_recall)


# =============================================================================
# 2. Hedge-format guard (G-HEDGE-IMMUT).
# =============================================================================
# VERDICT: <TOKEN> — act: <LEVEL>, attribution: <LEVEL>
_HEDGE_VERDICT_RE = re.compile(
    r"VERDICT:\s*\*{0,2}\s*"
    r"(MALICE|NON_MALICE|INCONCLUSIVE)\b"
    r"[^\n]*?\bact:\s*(HIGH|MODERATE|LOW)\b"
    r"[^\n]*?\battribution:\s*(HIGH|MODERATE|LOW)\b",
    re.IGNORECASE,
)
# "never collapse to an unqualified yes/no" style clause.
_NO_COLLAPSE_RE = re.compile(
    r"never\s+collapse[^\n]*?unqualified[^\n]*?(yes\s*/\s*no|yes/no|yes\s+or\s+no)",
    re.IGNORECASE | re.DOTALL,
)
# "INCONCLUSIVE ... correct answer" clause (INCONCLUSIVE is a first-class correct answer).
_INCONCLUSIVE_OK_RE = re.compile(
    r"INCONCLUSIVE[^\n]*?correct\s+answer",
    re.IGNORECASE | re.DOTALL,
)


def hedge_format_intact(text):
    """True iff ``text`` carries all three born-safe hedge invariants:

      (a) a well-formed ``VERDICT: <TOKEN> — act: <LEVEL>, attribution: <LEVEL>`` line
          (TOKEN in MALICE/NON_MALICE/INCONCLUSIVE, LEVEL in HIGH/MODERATE/LOW),
      (b) a "never collapse to an unqualified yes/no" style clause, and
      (c) an "INCONCLUSIVE ... correct answer" clause (INCONCLUSIVE first-class).

    Any removed/mutated invariant => False.
    """
    if not isinstance(text, str):
        return False
    return bool(
        _HEDGE_VERDICT_RE.search(text)
        and _NO_COLLAPSE_RE.search(text)
        and _INCONCLUSIVE_OK_RE.search(text)
    )


# =============================================================================
# 3. Revert executor (snapshot-restore + orphan-clean + git fallback + hard-fail).
# =============================================================================
class RevertError(RuntimeError):
    """Raised when a revert cannot be performed safely (hard-fail-loud)."""


def _read_text(path):
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _fm_scalar(text, key):
    """Minimal frontmatter scalar reader — mirrors tune_playbook.fm_scalar enough to
    resolve category_id (category_id OR attack_type OR stem)."""
    lines = text.splitlines()
    i = 0
    while i < len(lines) and not lines[i].strip():
        i += 1
    if i >= len(lines) or lines[i].strip() != "---":
        return ""
    end = None
    for j in range(i + 1, len(lines)):
        if lines[j].strip() == "---":
            end = j
            break
    if end is None:
        return ""
    fm = "\n".join(lines[i + 1:end])
    m = re.search(rf"^{re.escape(key)}:\s*(.+?)\s*$", fm, re.M)
    if not m:
        return ""
    v = re.sub(r"\s+#.*$", "", m.group(1)).strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1]
    return v


def _resolve_category_id(playbook_path, text):
    """category_id = frontmatter category_id OR attack_type OR playbook stem
    (matches tune_playbook.py exactly)."""
    cat = _fm_scalar(text, "category_id") or _fm_scalar(text, "attack_type")
    if cat:
        return cat
    return os.path.splitext(os.path.basename(playbook_path))[0]


def _live_version(text):
    """Integer ``version:`` from the live frontmatter, or None if absent."""
    m = _VERSION_RE.search(text)
    return int(m.group(1)) if m else None


def _git_tracked_and_worktree(playbook_path):
    """(is_worktree, is_tracked) for ``playbook_path`` — both must hold for git fallback."""
    d = os.path.dirname(os.path.abspath(playbook_path)) or "."
    try:
        wt = subprocess.run(
            ["git", "-C", d, "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True,
        )
        if wt.returncode != 0 or wt.stdout.strip() != "true":
            return False, False
        ls = subprocess.run(
            ["git", "-C", d, "ls-files", "--error-unmatch", os.path.abspath(playbook_path)],
            capture_output=True, text=True,
        )
        return True, (ls.returncode == 0)
    except (OSError, FileNotFoundError):
        return False, False


def _delete_orphans(versions_dir, cat, v_new):
    """DELETE versions/<cat>/v<v_new>.diff and v<v_new>.trace.json (same unlink in BOTH
    primary and fallback paths). Returns the list actually removed. Idempotent."""
    removed = []
    cat_dir = os.path.join(versions_dir, cat)
    for suffix in (f"v{v_new}.diff", f"v{v_new}.trace.json"):
        p = os.path.join(cat_dir, suffix)
        if os.path.exists(p):
            os.remove(p)
            removed.append(p)
    return removed


def revert(playbook_path, *, versions_dir=None, use_git_fallback=True):
    """Revert the LATEST tune of ``playbook_path``.

    PRIMARY  : copy versions/<cat>/v<v_new-1>.md BYTE-FOR-BYTE over the playbook
               (reverses version bump + appended step + tuning-log line at once),
               then DELETE the v<v_new>.diff / v<v_new>.trace.json orphans, KEEP the
               v<v_new-1>.md snapshot.
    FALLBACK : ``git restore`` the file ONLY if the snapshot is missing/corrupt AND the
               dir is a real work-tree AND the file is tracked. Orphans still unlinked.
    HARD-FAIL: otherwise raise RevertError LOUDLY — never half-revert + report success.
    IDEMPOTENT: if the live version's snapshot is already in place (orphans gone), no-op.

    ``versions_dir`` overrides the default ``<playbook_dir>/versions``.
    Returns a dict describing what was done.
    """
    playbook_path = os.path.abspath(playbook_path)
    if not os.path.isfile(playbook_path):
        raise RevertError(f"playbook not found: {playbook_path}")

    text = _read_text(playbook_path)
    v_new = _live_version(text)
    if v_new is None:
        raise RevertError(
            f"no integer 'version:' in frontmatter of {playbook_path} — not contract-shaped; refusing"
        )

    cat = _resolve_category_id(playbook_path, text)
    base_versions = versions_dir or os.path.join(os.path.dirname(playbook_path), "versions")
    cat_dir = os.path.join(base_versions, cat)
    snapshot = os.path.join(cat_dir, f"v{v_new - 1}.md")

    snapshot_ok = os.path.isfile(snapshot) and os.path.getsize(snapshot) > 0

    if snapshot_ok:
        # PRIMARY: byte-for-byte restore from the pre-tune snapshot.
        with open(snapshot, "rb") as src, open(playbook_path, "wb") as dst:
            dst.write(src.read())
        removed = _delete_orphans(base_versions, cat, v_new)
        return {
            "method": "snapshot",
            "playbook": playbook_path,
            "restored_from": snapshot,
            "category_id": cat,
            "v_new": v_new,
            "v_restored": v_new - 1,
            "orphans_deleted": removed,
            "snapshot_kept": snapshot,
        }

    # snapshot missing/corrupt -> git fallback (guarded) or HARD-FAIL.
    if use_git_fallback:
        is_wt, tracked = _git_tracked_and_worktree(playbook_path)
        if is_wt and tracked:
            d = os.path.dirname(playbook_path) or "."
            r = subprocess.run(
                ["git", "-C", d, "restore", "--", playbook_path],
                capture_output=True, text=True,
            )
            if r.returncode != 0:
                raise RevertError(
                    f"git restore FAILED for {playbook_path} (snapshot {snapshot} missing/corrupt): "
                    f"{r.stderr.strip()}"
                )
            removed = _delete_orphans(base_versions, cat, v_new)
            return {
                "method": "git",
                "playbook": playbook_path,
                "restored_from": "git HEAD",
                "category_id": cat,
                "v_new": v_new,
                "orphans_deleted": removed,
                "snapshot_kept": snapshot if os.path.isfile(snapshot) else None,
            }

    raise RevertError(
        f"cannot revert {playbook_path}: snapshot {snapshot} missing/corrupt and git fallback "
        f"unavailable (not a tracked file in a work-tree, or fallback disabled). "
        f"Refusing to half-revert."
    )


# =============================================================================
# 4. CLI.
# =============================================================================
def _load_json_arg(val):
    """A CLI value of the form ``@path`` loads JSON from ``path``; otherwise parse the
    literal as JSON."""
    if val.startswith("@"):
        with open(val[1:], "r", encoding="utf-8") as fh:
            return json.load(fh)
    return json.loads(val)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="keep_or_revert.py",
        description="Decide KEEP/REVERT over the 4 gated dims; optionally execute the revert.",
    )
    ap.add_argument("--baseline", required=True,
                    help="baseline aggregate JSON, or @path.json")
    ap.add_argument("--post", required=True,
                    help="post-change aggregate JSON, or @path.json")
    ap.add_argument("--eps-recall", type=float, default=0.0,
                    help="float-recall tolerance (default 0.0)")
    ap.add_argument("--playbook", default=None,
                    help="playbook .md to revert when --apply and decision==REVERT")
    ap.add_argument("--versions-dir", default=None,
                    help="override <playbook_dir>/versions for the snapshot lookup")
    ap.add_argument("--category", default=None,
                    help="(reserved) explicit category_id; default resolves from frontmatter")
    ap.add_argument("--apply", action="store_true",
                    help="if decision==REVERT, run revert(--playbook)")
    ap.add_argument("--no-git-fallback", action="store_true",
                    help="disable the git-restore fallback (snapshot-only)")
    args = ap.parse_args(argv)

    baseline = _load_json_arg(args.baseline)
    post = _load_json_arg(args.post)
    decision, reason, deltas = decide(baseline, post, eps_recall=args.eps_recall)

    out = {"decision": decision, "reason": reason, "deltas": deltas}

    if args.apply and decision == "REVERT":
        if not args.playbook:
            out["revert_error"] = "--apply with REVERT requires --playbook"
            print(json.dumps(out, indent=2, ensure_ascii=False))
            return 2
        try:
            out["revert"] = revert(
                args.playbook,
                versions_dir=args.versions_dir,
                use_git_fallback=not args.no_git_fallback,
            )
        except RevertError as e:
            out["revert_error"] = str(e)
            print(json.dumps(out, indent=2, ensure_ascii=False))
            return 3

    print(json.dumps(out, indent=2, ensure_ascii=False))
    # exit 0 == KEEP, nonzero == REVERT.
    return 0 if decision == "KEEP" else 1


if __name__ == "__main__":
    sys.exit(main())
