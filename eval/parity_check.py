#!/usr/bin/env python3
"""Protocol SIFT — playground/production PARITY gate (pre-flight for every eval round).

THE REQUIREMENT (user, 2026-06-12): the playground must be the SIFT workstation —
same environment, same access, with the REAL Protocol SIFT running inside it — so
every measured failure is real and every kept improvement is truly needed.

WHAT GUARANTEES PARITY TODAY (audited 2026-06-12):
  * the playground IS the workstation: /cases/playground lives on sift-vm itself;
  * `claude -p` auto-loads the user config layer (~/.claude/CLAUDE.md + skills/)
    — that layer IS Protocol SIFT, identical for eval and real investigations;
  * run_blind.py unsets ANTHROPIC_API_KEY (subscription auth, like production);
  * the ONLY intended delta is run_blind's --append-system-prompt eval scaffold
    (case prompt + findings.json output format) — additive, documented.

WHAT THIS SCRIPT DOES:
  1. HARD CHECKS (exit 1 = do not run the eval):
       - running on the expected host (default: siftworkstation)
       - ~/.claude/CLAUDE.md exists (else the run is bare Claude, not Protocol SIFT)
       - ~/.claude/skills/ exists and is non-empty
       - ANTHROPIC_API_KEY is NOT set (would silently switch auth away from prod's)
  2. WARNINGS (printed, run allowed):
       - settings.json missing the sandbox layer (PreToolUse hook / egress
         allow-list) — known Phase-0.1 gap; warn until deployed
  3. FINGERPRINT: writes parity_manifest.json — host, claude version, sha256 of
     CLAUDE.md / settings.json / every skill file, model envs. Save one per run.
  4. --diff A.json B.json: compare two manifests. Enforces the ONE-CHANGE-PER-LAP
     rule mechanically: a clean improvement lap shows exactly the intended
     artifact changed and nothing else.

stdlib-only. Usage:
    python3 parity_check.py                    # gate + write parity_manifest.json
    python3 parity_check.py --out run42.json   # fingerprint to a custom path
    python3 parity_check.py --diff before.json after.json
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import pathlib
import socket
import subprocess
import sys

EXPECTED_HOST = os.environ.get("PARITY_EXPECTED_HOST", "siftworkstation")


def _sha(path: pathlib.Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()[:16]
    except OSError:
        return "MISSING"


def _claude_version() -> str:
    try:
        r = subprocess.run(["claude", "--version"], capture_output=True,
                           text=True, timeout=20)
        return (r.stdout or r.stderr).strip().splitlines()[0] if (r.stdout or r.stderr) else "unknown"
    except Exception:
        return "NOT-FOUND"


def build_manifest(home: pathlib.Path | None = None) -> dict:
    home = home or pathlib.Path.home()
    claude_home = home / ".claude"
    skills_dir = claude_home / "skills"

    skills: dict = {}
    if skills_dir.is_dir():
        for sk in sorted(p for p in skills_dir.iterdir() if p.is_dir()):
            md = sk / "SKILL.md"
            skills[sk.name] = _sha(md) if md.exists() else _sha_dir_head(sk)

    return {
        "ts": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": socket.gethostname(),
        "user": os.environ.get("USER", ""),
        "claude_version": _claude_version(),
        "artifacts": {
            "CLAUDE.md": _sha(claude_home / "CLAUDE.md"),
            "settings.json": _sha(claude_home / "settings.json"),
            **{f"skill:{k}": v for k, v in skills.items()},
        },
        "env": {
            "BLIND_MODEL": os.environ.get("BLIND_MODEL", "(default: opus)"),
            "TUNE_MODEL": os.environ.get("TUNE_MODEL", "(default: fable)"),
            "ANTHROPIC_API_KEY_set": "ANTHROPIC_API_KEY" in os.environ,
        },
    }


def _sha_dir_head(d: pathlib.Path) -> str:
    """Stable-ish hash for a skill dir without SKILL.md: hash of sorted filenames."""
    names = "\n".join(sorted(p.name for p in d.iterdir()))
    return hashlib.sha256(names.encode()).hexdigest()[:16]


def gate(manifest: dict, home: pathlib.Path | None = None) -> tuple[list, list]:
    """Return (hard_failures, warnings)."""
    home = home or pathlib.Path.home()
    claude_home = home / ".claude"
    hard: list = []
    warn: list = []

    if manifest["host"] != EXPECTED_HOST:
        hard.append(f"not on the SIFT workstation: host={manifest['host']!r}, "
                    f"expected {EXPECTED_HOST!r} (set PARITY_EXPECTED_HOST to override)")
    if manifest["artifacts"]["CLAUDE.md"] == "MISSING":
        hard.append("~/.claude/CLAUDE.md missing — the run would be bare Claude, NOT Protocol SIFT")
    n_skills = sum(1 for k in manifest["artifacts"] if k.startswith("skill:"))
    if n_skills == 0:
        hard.append("~/.claude/skills/ empty or missing — the forensic skill layer is not deployed")
    if manifest["env"]["ANTHROPIC_API_KEY_set"]:
        hard.append("ANTHROPIC_API_KEY is set — would silently override subscription auth; unset it")

    settings = claude_home / "settings.json"
    try:
        s = settings.read_text(encoding="utf-8")
        if "PreToolUse" not in s or "validate_cmd" not in s:
            warn.append("sandbox layer not in live settings.json (no PreToolUse/validate_cmd hook) "
                        "— Phase 0.1 gap; eval and prod are still IDENTICAL, just both unguarded")
        if "allowedDomains" not in s:
            warn.append("no egress allow-list in live settings.json — Phase 0.1/0.6 gap")
    except OSError:
        warn.append("settings.json unreadable — cannot verify sandbox layer")

    return hard, warn


def diff_manifests(a: dict, b: dict) -> dict:
    """What changed between two runs' environments (the one-change-per-lap check)."""
    out: dict = {"changed_artifacts": {}, "changed_env": {}, "host_changed": None,
                 "claude_version_changed": None}
    if a["host"] != b["host"]:
        out["host_changed"] = [a["host"], b["host"]]
    if a["claude_version"] != b["claude_version"]:
        out["claude_version_changed"] = [a["claude_version"], b["claude_version"]]
    keys = set(a["artifacts"]) | set(b["artifacts"])
    for k in sorted(keys):
        va, vb = a["artifacts"].get(k, "ABSENT"), b["artifacts"].get(k, "ABSENT")
        if va != vb:
            out["changed_artifacts"][k] = [va, vb]
    for k in sorted(set(a["env"]) | set(b["env"])):
        va, vb = a["env"].get(k), b["env"].get(k)
        if va != vb:
            out["changed_env"][k] = [va, vb]
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Playground/production parity gate + fingerprint.")
    ap.add_argument("--out", default="parity_manifest.json")
    ap.add_argument("--diff", nargs=2, metavar=("BEFORE", "AFTER"),
                    help="compare two manifests instead of gating")
    args = ap.parse_args()

    if args.diff:
        a = json.loads(pathlib.Path(args.diff[0]).read_text(encoding="utf-8"))
        b = json.loads(pathlib.Path(args.diff[1]).read_text(encoding="utf-8"))
        d = diff_manifests(a, b)
        print(json.dumps(d, indent=2))
        n = len(d["changed_artifacts"])
        if d["host_changed"] or d["claude_version_changed"]:
            print("\nPARITY BROKEN between runs (host/claude changed) — comparison invalid.",
                  file=sys.stderr)
            return 1
        print(f"\n{n} artifact(s) changed between runs. One-change-per-lap rule: "
              f"{'OK' if n <= 1 else 'VIOLATED — attribute the score delta to nothing'}")
        return 0 if n <= 1 else 1

    m = build_manifest()
    hard, warn = gate(m)
    pathlib.Path(args.out).write_text(json.dumps(m, indent=2) + "\n", encoding="utf-8")

    print(f"parity manifest -> {args.out}")
    print(f"  host={m['host']}  claude={m['claude_version']}")
    print(f"  CLAUDE.md={m['artifacts']['CLAUDE.md']}  settings={m['artifacts']['settings.json']}  "
          f"skills={sum(1 for k in m['artifacts'] if k.startswith('skill:'))}")
    for w in warn:
        print(f"  WARN: {w}")
    if hard:
        for h in hard:
            print(f"  FAIL: {h}", file=sys.stderr)
        print("PARITY GATE FAILED — do not run the eval round.", file=sys.stderr)
        return 1
    print("PARITY GATE OK — this run IS Protocol SIFT on the real workstation.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
