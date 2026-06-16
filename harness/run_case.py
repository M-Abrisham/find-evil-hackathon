"""
Drive `claude -p --output-format stream-json` on sift-vm for a single eval case.
Returns a RunResult with report, tool_calls, audit_log, manifest, and hashes.
"""

import json
import subprocess
import dataclasses
from typing import Optional
from harness.parse_stream import parse_stream

VM = "ubuntu@10.104.28.103"
EVIDENCE_ROOT = "/home/ubuntu/Downloads"
HASHDEEP_KEY = "~/protocol-sift-evals/hashes.txt"


@dataclasses.dataclass
class RunResult:
    report: str
    tool_calls: list
    audit_log: Optional[str]
    manifest: Optional[str]
    hashes_ok: Optional[bool]


def run_case(case: dict) -> RunResult:
    # TODO: build prompt from case record
    prompt = case["prompt"]
    case_dir = case["case_dir"]

    cmd = [
        "ssh", VM,
        f"cd {case_dir} && claude -p {json.dumps(prompt)} --output-format stream-json"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    stream_lines = result.stdout.splitlines()

    report, tool_calls = parse_stream(stream_lines)

    # Collect audit log
    audit_cmd = ["ssh", VM, f"cat {case_dir}/forensic_audit.log 2>/dev/null"]
    audit_result = subprocess.run(audit_cmd, capture_output=True, text=True)
    audit_log = audit_result.stdout or None

    # Post-run manifest
    manifest_cmd = ["ssh", VM, f"find {EVIDENCE_ROOT} -type f | sort"]
    manifest_result = subprocess.run(manifest_cmd, capture_output=True, text=True)
    manifest = manifest_result.stdout or None

    # Hashdeep integrity check
    hashdeep_cmd = [
        "ssh", VM,
        f"hashdeep -a -k {HASHDEEP_KEY} -r {EVIDENCE_ROOT} 2>/dev/null; echo $?"
    ]
    hashdeep_result = subprocess.run(hashdeep_cmd, capture_output=True, text=True)
    lines = hashdeep_result.stdout.strip().splitlines()
    hashes_ok = lines[-1] == "0" if lines else None

    return RunResult(
        report=report,
        tool_calls=tool_calls,
        audit_log=audit_log,
        manifest=manifest,
        hashes_ok=hashes_ok,
    )
