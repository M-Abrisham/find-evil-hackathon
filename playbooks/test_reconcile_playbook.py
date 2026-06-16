#!/usr/bin/env python3
"""Self-contained tests for reconcile_playbook.py (stdlib only).

Run:  python3 playbooks/test_reconcile_playbook.py
"""
from __future__ import annotations

import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import reconcile_playbook as rp  # noqa: E402

MATRIX = """\
# OS-Coverage Matrix

## A) THE MATRIX (pivoted by OS)
| Artifact | Tool | Status |
|----------|------|--------|
| $MFT | MFTECmd | C |

## B) FALSE-CLAIMS TABLE (source asserted it; box doesn't actually have it)
| Tool | Asserting source(s) | Proof of absence/failure |
|------|---------------------|--------------------------|
| **PECmd** (Prefetch) | footnote | NOT FOUND. Prefetch covered instead by plaso `prefetch`. |
| **SrumECmd** (SRUM) | footnote | NOT FOUND. SRUM covered instead by plaso `srum`. |
| **yara (CLI)** | CLAUDE.md | NOT FOUND — only `python3-yara` library. |
| **vss_carver** | taxonomy | NOT FOUND. Use `vshadowmount`/`vshadowinfo` instead. |
| **Zeek** | footnote | NOT FOUND (P8). |

## C) TRUE GAPS
nothing here
"""

# Names PECmd inside a `tool: |` block -> executable, but has a substitute -> NOT blocking.
PB_SUB = """\
---
attack_type: x
---
## Steps
- n: 1
  tool: |
    PECmd -d /mnt/prefetch
"""

# Names Zeek inside a `tool:` block -> executable, NO substitute -> BLOCKING.
PB_BLOCK = """\
---
attack_type: y
---
## Steps
- n: 1
  tool: |
    zeek -r capture.pcap
"""

# Only substitutes named -> zero hits (precision: plaso prefetch != PECmd, python3-yara/yarac != yara CLI).
PB_CLEAN = """\
---
attack_type: z
---
## Steps
- n: 1
  tool: |
    plaso prefetch ; python3-yara scan ; yarac rules.yar
"""

# Names PECmd only in PROSE -> reported but NOT blocking.
PB_PROSE = """\
---
attack_type: w
---
## Notes
Unlike PECmd, this box uses plaso prefetch instead.
"""

_P = _F = 0


def check(name, cond, extra=""):
    global _P, _F
    if cond:
        _P += 1
        print(f"  ok   {name}")
    else:
        _F += 1
        print(f"  FAIL {name}  {extra}")


def run():
    absent = rp.parse_false_claims(MATRIX)
    check("parsed pecmd/yara/vss_carver/zeek", {"pecmd", "yara", "vss_carver", "zeek"} <= set(absent), str(set(absent)))
    matchers = rp.build_matchers(absent)
    check("pecmd has substitute", "prefetch" in (matchers["pecmd"][2] or ""), str(matchers["pecmd"][2]))
    check("zeek has NO substitute", matchers["zeek"][2] in (None, ""), str(matchers["zeek"][2]))

    def scan(pb):
        return rp.scan_playbook(pb, matchers)

    print("[1] PECmd in tool: block (has substitute)")
    h = scan(PB_SUB)
    pe = [x for x in h if x["token"] == "pecmd"]
    check("PECmd hit found", len(pe) == 1, str(h))
    check("PECmd hit is executable", pe and pe[0]["context"] == "executable", str(pe))
    check("PECmd hit NOT blocking (has sub)", pe and pe[0]["blocking"] is False, str(pe))
    check("PECmd status = needs_substitution", pe and pe[0]["status"] == "needs_substitution", str(pe))

    print("[2] Zeek in tool: block (no substitute) -> blocking")
    h2 = scan(PB_BLOCK)
    ze = [x for x in h2 if x["token"] == "zeek"]
    check("Zeek hit is executable", ze and ze[0]["context"] == "executable", str(ze))
    check("Zeek hit IS blocking", ze and ze[0]["blocking"] is True, str(ze))

    print("[3] only substitutes named -> precision: zero hits")
    h3 = scan(PB_CLEAN)
    check("no PECmd from 'plaso prefetch'", not any(x["token"] == "pecmd" for x in h3), str(h3))
    check("no yara from python3-yara/yarac", not any(x["token"] == "yara" for x in h3), str(h3))
    check("clean playbook has zero hits", h3 == [], str(h3))

    print("[4] prose mention -> reported, not blocking")
    h4 = scan(PB_PROSE)
    pe4 = [x for x in h4 if x["token"] == "pecmd"]
    check("prose PECmd reported", len(pe4) == 1, str(h4))
    check("prose PECmd context=prose", pe4 and pe4[0]["context"] == "prose", str(pe4))
    check("prose PECmd NOT blocking", pe4 and pe4[0]["blocking"] is False, str(pe4))

    print("[6] token-boundary precision (path-qualified / slash-joined / files)")
    BND_HIT = ("---\na: b\n---\n## Steps\n- n: 1\n  tool: |\n"
               "    /usr/local/bin/yara -r r.yar ; /opt/zt/PECmd.exe -d X ; note PECmd/SrumECmd\n")
    hh = scan(BND_HIT)
    check("path-qualified /usr/local/bin/yara matches", any(x["token"] == "yara" for x in hh), str(hh))
    check("path-qualified /opt/zt/PECmd.exe matches", any(x["token"] == "pecmd" for x in hh), str(hh))
    check("slash-joined SrumECmd matches", any(x["token"] == "srumecmd" for x in hh), str(hh))
    check("path-qualified hits are executable",
          all(x["context"] == "executable" for x in hh if x["token"] in ("yara", "pecmd", "srumecmd")), str(hh))
    BND_FILE = ("---\na: b\n---\n## Steps\n- n: 1\n  tool: |\n"
                "    grep evil rules.yara ; cat python3-yara.txt ; yarac rules.yar\n")
    hf = scan(BND_FILE)
    check("rules.yara file does NOT match yara CLI", not any(x["token"] == "yara" for x in hf), str(hf))

    print("[5] reconcile_one gate verdicts")
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        d = pathlib.Path(td)
        (d / "block.md").write_text(PB_BLOCK, encoding="utf-8")
        (d / "clean.md").write_text(PB_CLEAN, encoding="utf-8")
        (d / "sub.md").write_text(PB_SUB, encoding="utf-8")
        rb = rp.reconcile_one(d / "block.md", matchers)
        rc = rp.reconcile_one(d / "clean.md", matchers)
        rs = rp.reconcile_one(d / "sub.md", matchers)
        check("blocking playbook FAILS gate", rb["passes_gate"] is False, str(rb))
        check("clean playbook PASSES + fully reconciled",
              rc["passes_gate"] is True and rc["fully_reconciled"] is True, str(rc))
        check("substitute-only playbook PASSES gate but NOT fully reconciled",
              rs["passes_gate"] is True and rs["fully_reconciled"] is False, str(rs))
        check("substitute-only lists 1 substitution to apply",
              rs["needs_substitution_hits"] == 1 and any("PECmd" in s for s in rs["substitutions_to_apply"]),
              str(rs["substitutions_to_apply"]))

    print(f"\n{_P} passed, {_F} failed")
    return 1 if _F else 0


if __name__ == "__main__":
    sys.exit(run())
