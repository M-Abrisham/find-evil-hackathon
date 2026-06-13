#!/usr/bin/env python3
"""Render the Deliverable Contract from contract/contract.yaml into:

  - contract/DELIVERABLE_CONTRACT.md   standalone, human-readable
  - global/CLAUDE.md                   injected between generated markers

contract.yaml is the SINGLE SOURCE OF TRUTH. Never hand-edit the rendered prose.
Idempotent: re-running replaces the block between the markers in global/CLAUDE.md.

Run from anywhere:  python3 contract/render_contract.py
"""
from __future__ import annotations

import os
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
YAML_SRC = os.path.join(HERE, "contract.yaml")
STANDALONE = os.path.join(HERE, "DELIVERABLE_CONTRACT.md")
CLAUDE_MD = os.path.join(ROOT, "global", "CLAUDE.md")

START = ("<!-- DELIVERABLE-CONTRACT:START "
         "(generated from contract/contract.yaml — do not edit by hand) -->")
END = "<!-- DELIVERABLE-CONTRACT:END -->"


def render(c: dict) -> str:
    v, ioc, mit = c["verdict"], c["ioc"], c["mitre"]
    L: list[str] = []
    L += ["## Deliverable Contract (REQUIRED in every report)", ""]
    L += ["Every investigation report MUST end with the three sections below, in this "
          "order. They are machine-graded — emit them exactly. They ADD to (never "
          "replace) the CONFIRMED / INFERRED / UNCERTAIN reasoning already required, "
          "and you must still never assert anything the evidence does not support.", ""]

    # 1. Verdict
    toks = " / ".join(f"`{t['token']}`" for t in v["vocabulary"])
    dims = v["dimensions"]
    L += ["### 1. Verdict (last section of the report)", ""]
    L += [f"End the report with a one-word verdict **token** — one of {toks} — qualified "
          f"by confidence per dimension ({', '.join(dims)}). "
          f"Levels: {', '.join(v['confidence_levels'])}.", ""]
    L += [f"- {t['token']} — {t['meaning']}" for t in v["vocabulary"]]
    L += ["", "Format:", "```"]
    L += [f"VERDICT: <TOKEN> — {', '.join(d + ': <LEVEL>' for d in dims)}",
          "<one sentence justifying it, citing artifacts>", "```"]
    L += ["Example: `VERDICT: MALICE — act: HIGH, attribution: MODERATE`", ""]
    L += [f"- {r}" for r in v["rules"]]
    L += [""]

    # 2. IOC table
    L += ["### 2. Indicators of Compromise (IOC table)", ""]
    L += [f"List every indicator in one table with columns "
          f"**{' | '.join(ioc['columns'])}**. "
          f"Confidence is one of {', '.join(ioc['confidence_vocab'])}.", ""]
    L += ["| " + " | ".join(ioc["columns"]) + " |",
          "|" + "|".join("---" for _ in ioc["columns"]) + "|",
          "| <type> | <value> | <CONFIRMED\\|INFERRED\\|UNCERTAIN> |", ""]
    L += ["Allowed `Type` values (write `Value` in the form shown):"]
    L += [f"- `{t['type']}` — {t['value_form']}" for t in ioc["types"]]
    L += [""]
    L += [f"- {r}" for r in ioc["rules"]]
    L += [""]

    # 3. MITRE
    L += ["### 3. MITRE ATT&CK mapping", ""]
    L += [f"Map observed techniques in one table — columns "
          f"**{' | '.join(mit['columns'])}**. Framework: {mit['framework']}. "
          f"Code format: {mit['code_format']}.", ""]
    L += ["| " + " | ".join(mit["columns"]) + " |",
          "|" + "|".join("---" for _ in mit["columns"]) + "|",
          "| <technique name> | T#### | <ART-id / tool output> |", ""]
    L += [f"- {r}" for r in mit["rules"]]
    L += [""]
    return "\n".join(L).rstrip() + "\n"


def inject(path: str, block: str) -> str:
    with open(path) as f:
        txt = f.read()
    generated = f"{START}\n\n{block}\n{END}"
    if START in txt and END in txt:
        pre = txt[: txt.index(START)]
        post = txt[txt.index(END) + len(END):]
        new = pre + generated + post
        mode = "replaced"
    else:
        new = txt.rstrip() + "\n\n---\n\n" + generated + "\n"
        mode = "appended"
    with open(path, "w") as f:
        f.write(new)
    return mode


def main() -> None:
    with open(YAML_SRC) as f:
        c = yaml.safe_load(f)
    block = render(c)
    with open(STANDALONE, "w") as f:
        f.write(block)
    mode = inject(CLAUDE_MD, block)
    print(f"[render] wrote {STANDALONE}")
    print(f"[render] {mode} contract block in {CLAUDE_MD}")


if __name__ == "__main__":
    main()
