#!/usr/bin/env python3
"""OFFLINE, ONE-TIME generator for scorer.VALID_MITRE_IDS — NOT imported at runtime.

The scorer ships a frozen `VALID_MITRE_IDS` literal so it has no network/runtime
dependency. Regenerate it ONLY on an intentional ATT&CK version bump:

    curl -sSL -o enterprise-attack.json \
      https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
    python3 gen_attack_ids.py enterprise-attack.json > ids.txt   # paste into scorer.py

Pinned source: MITRE ATT&CK Enterprise STIX bundle (mitre/cti). We keep the
non-deprecated, non-revoked attack-pattern external_ids (Txxxx / Txxxx.yyy).
Key-independent by construction: the set is a superset of every answer-key code.
"""
import json
import sys


def extract_ids(bundle_path: str) -> list[str]:
    bundle = json.load(open(bundle_path, encoding="utf-8"))
    ids: set[str] = set()
    for o in bundle.get("objects", []):
        if o.get("type") != "attack-pattern":
            continue
        if o.get("x_mitre_deprecated") or o.get("revoked"):
            continue
        for ref in o.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                eid = ref.get("external_id", "")
                if eid.startswith("T"):
                    ids.add(eid.upper())
    return sorted(ids)


if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else "enterprise-attack.json"
    ids = extract_ids(src)
    print(f"# {len(ids)} valid Enterprise technique ids", file=sys.stderr)
    q = [f'"{i}"' for i in ids]
    for k in range(0, len(q), 8):
        print("    " + ", ".join(q[k:k + 8]) + ",")
