#!/usr/bin/env python3
"""R6 - ADVERSARIAL unittest suite for the hash-chained command ledger.

BUILD-TIME TOOLING ONLY (Protocol SIFT). STDLIB ONLY. Sibling-import design:
run from the sift-runner dir so ledger_hook / verify_ledger import.

    python3 -m unittest -v test_ledger_adversarial
    # or
    python3 test_ledger_adversarial.py

This file is a SECOND, deliberately hostile suite that sits alongside the
author's test_ledger.py. It does NOT modify any existing file. It is engineered
to break the chain auditor (verify_ledger.py) and the custody hook
(ledger_hook.py) on their hardest edges:

  * CHAIN attacks that preserve PER-LINE plausibility but break linkage:
      - early-entry mutation that is then PARTIALLY re-signed (only that line),
        forcing the break to surface at the DOWNSTREAM link, not the edit site.
      - middle-line deletion, two-line reorder, full reverse.
      - a forged appended tail line with a wrong prev_hash.
      - a swap whose seq fields are MASKED to look contiguous (must still trip
        because seq is inside the hashed body).
  * The GENESIS anchor: a fully re-signed chain with a forged head must STILL
    be caught (the one anchor an unkeyed attacker cannot re-sign away).
  * The KNOWN cryptographic limitation: a full from-scratch re-sign (no MAC key)
    is undetectable -> we ASSERT that limitation explicitly so a future MAC
    upgrade visibly flips these expectations.
  * Reporting fidelity: first_broken_index is the EARLIEST concrete index even
    when a None-index problem (EMPTY) coexists with indexed ones.
  * Whitespace / CRLF / interspersed-blank tolerance on otherwise-clean chains.
  * Exit-code contract on main(): 0 intact, 1 tampered, 2 not-found/usage; and
    the hook main() ALWAYS returns 0 (non-blocking) on hostile stdin.

Every fixture is synthetic and written to a throwaway temp dir. Nothing touches
~/.claude or any live config.

NOTE on scope: the orchestrator prompt also references "R4 report-contract" and
"R8 contract-block" verifiers. Those modules are NOT among the three R6 files
under test here (ledger_hook.py / verify_ledger.py / test_ledger.py), so they
are out of scope for this file; this suite targets R6 only.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ledger_hook as lh  # noqa: E402
import verify_ledger as vl  # noqa: E402


COMPACT = dict(sort_keys=True, separators=(",", ":"))


def make_event(command, tool="Bash", output="out", session="s"):
    return {
        "session_id": session,
        "tool_name": tool,
        "tool_input": {"command": command} if tool == "Bash" else {"path": command},
        "tool_response": output,
    }


def dumps(rec):
    return json.dumps(rec, **COMPACT)


def rehash(rec, prev_hash=None):
    """Re-sign a single entry in place (attacker with no MAC key can do this)."""
    if prev_hash is not None:
        rec["prev_hash"] = prev_hash
    rec["entry_hash"] = lh.compute_entry_hash(rec["prev_hash"], rec)
    return rec


class AdvBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sift-ledger-adv-")
        self.ledger = os.path.join(self.tmp, "custody.jsonl")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def append_many(self, commands):
        return [lh.append_entry(self.ledger, make_event(c)) for c in commands]

    def lines(self):
        with open(self.ledger, "r", encoding="utf-8") as fh:
            return [ln for ln in fh.read().splitlines() if ln.strip()]

    def recs(self):
        return [json.loads(l) for l in self.lines()]

    def write_lines(self, lines):
        with open(self.ledger, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")

    def write_recs(self, recs):
        self.write_lines([dumps(r) for r in recs])


# --------------------------------------------------------------------------- #
# CHAIN attacks: per-line plausible, chain broken.
# --------------------------------------------------------------------------- #
class TestChainAttacks(AdvBase):
    def test_clean_chain_verifies_ok(self):
        """Control: a freshly written multi-entry chain is intact (exit 0)."""
        self.append_many(["mmls disk.E01", "fls -r disk.E01", "icat disk.E01 9"])
        res = vl.verify_file(self.ledger)
        self.assertTrue(res.ok, msg=vl.format_report(res))
        self.assertIsNone(res.first_broken_index)
        self.assertEqual(vl.main(["--ledger", self.ledger]), 0)

    def test_early_mutation_partial_resign_breaks_downstream(self):
        """Hardest realistic tamper: edit entry 1's command, re-sign ONLY entry 1.

        Entry 1 then passes its OWN self-integrity check (it was honestly
        re-hashed), so the lie does NOT surface at index 1 as MUTATION. It
        surfaces at index 2 as BROKEN_LINK, because entry 2's stored prev_hash
        still points at entry 1's ORIGINAL hash. The chain still detects the
        tamper; we pin the exact index it reports so a regression in the
        'continue scanning after break' logic is caught.
        """
        self.append_many(["a", "b", "c", "d"])
        recs = self.recs()
        recs[1]["command"] = "rm -rf /evidence"
        rehash(recs[1])  # only entry 1 re-signed, prev_hash unchanged
        self.write_recs(recs)

        res = vl.verify_file(self.ledger)
        self.assertFalse(res.ok)
        self.assertEqual(res.first_broken_index, 2,
                         msg="partial re-sign should break the DOWNSTREAM link")
        self.assertIn("BROKEN_LINK", {p["kind"] for p in res.problems})

    def test_early_mutation_no_resign_breaks_at_edit_site(self):
        """Same edit but WITHOUT re-signing: caught as MUTATION at the edit site."""
        self.append_many(["a", "b", "c", "d"])
        recs = self.recs()
        recs[1]["command"] = "rm -rf /evidence"  # leave stale entry_hash
        self.write_recs(recs)
        res = vl.verify_file(self.ledger)
        self.assertFalse(res.ok)
        self.assertEqual(res.first_broken_index, 1)
        self.assertIn("MUTATION", {p["kind"] for p in res.problems})

    def test_delete_middle_line(self):
        self.append_many(["a", "b", "c", "d", "e"])
        lines = self.lines()
        del lines[2]
        self.write_lines(lines)
        res = vl.verify_file(self.ledger)
        self.assertFalse(res.ok)
        self.assertEqual(res.first_broken_index, 2)
        self.assertTrue({"BROKEN_LINK", "BAD_SEQ"} & {p["kind"] for p in res.problems})

    def test_reorder_two_adjacent_lines(self):
        self.append_many(["a", "b", "c", "d"])
        lines = self.lines()
        lines[1], lines[2] = lines[2], lines[1]
        self.write_lines(lines)
        res = vl.verify_file(self.ledger)
        self.assertFalse(res.ok)
        self.assertEqual(res.first_broken_index, 1)

    def test_reorder_with_masked_seq_still_caught(self):
        """Swap entries 1<->2 AND rewrite their seq to look contiguous (1,2).

        seq masking is not enough: seq is part of the hashed body, so the
        rewritten seq makes entry_hash recompute fail (MUTATION) at index 1.
        This proves seq is bound into the digest, not merely range-checked.
        """
        self.append_many(["a", "b", "c", "d"])
        recs = self.recs()
        recs[1], recs[2] = recs[2], recs[1]
        recs[1]["seq"], recs[2]["seq"] = 1, 2  # mask the seq evidence
        self.write_recs(recs)
        res = vl.verify_file(self.ledger)
        self.assertFalse(res.ok)
        self.assertEqual(res.first_broken_index, 1)
        kinds = {p["kind"] for p in res.problems}
        self.assertTrue({"MUTATION", "BROKEN_LINK"} & kinds)

    def test_appended_forged_tail_wrong_prev(self):
        """Attacker appends an honest-looking, self-consistent line with a
        bogus prev_hash. Caught as BROKEN_LINK exactly at the new tail index."""
        self.append_many(["a", "b", "c"])
        lines = self.lines()
        forged = lh.build_entry(make_event("exfil --all"), prev_hash="00" * 32, seq=3)
        lines.append(dumps(forged))
        self.write_lines(lines)
        res = vl.verify_file(self.ledger)
        self.assertFalse(res.ok)
        self.assertEqual(res.first_broken_index, 3)
        self.assertIn("BROKEN_LINK", {p["kind"] for p in res.problems})

    def test_appended_tail_correct_link_wrong_seq(self):
        """Attacker links the forged tail correctly but fumbles seq -> BAD_SEQ."""
        self.append_many(["a", "b", "c"])
        recs = self.recs()
        forged = lh.build_entry(make_event("exfil"), prev_hash=recs[-1]["entry_hash"],
                                seq=99)
        recs.append(forged)
        self.write_recs(recs)
        res = vl.verify_file(self.ledger)
        self.assertFalse(res.ok)
        self.assertEqual(res.first_broken_index, 3)
        self.assertIn("BAD_SEQ", {p["kind"] for p in res.problems})

    def test_full_reverse(self):
        self.append_many(["a", "b", "c"])
        lines = self.lines()
        lines.reverse()
        self.write_lines(lines)
        res = vl.verify_file(self.ledger)
        self.assertFalse(res.ok)
        self.assertEqual(res.first_broken_index, 0)

    def test_extra_unknown_field_is_mutation(self):
        """An attacker-appended field NOT in REQUIRED_FIELDS still changes the
        canonical body (compute_entry_hash only strips 'entry_hash'), so it is
        caught as MUTATION. Pins that the hash covers the WHOLE body."""
        self.append_many(["a", "b"])
        recs = self.recs()
        recs[0]["attacker_note"] = "planted"
        self.write_recs(recs)
        res = vl.verify_file(self.ledger)
        self.assertFalse(res.ok)
        self.assertEqual(res.first_broken_index, 0)
        self.assertIn("MUTATION", {p["kind"] for p in res.problems})

    def test_output_len_lie_without_resign(self):
        """Forging output_len (without re-signing) is a body mutation -> caught."""
        self.append_many(["a", "b"])
        recs = self.recs()
        recs[0]["output_len"] = 999999
        self.write_recs(recs)
        res = vl.verify_file(self.ledger)
        self.assertFalse(res.ok)
        self.assertEqual(res.first_broken_index, 0)
        self.assertIn("MUTATION", {p["kind"] for p in res.problems})


# --------------------------------------------------------------------------- #
# The GENESIS anchor + the documented no-MAC limitation.
# --------------------------------------------------------------------------- #
class TestGenesisAnchorAndLimits(AdvBase):
    def test_forged_head_fully_resigned_still_caught_by_genesis(self):
        """Attacker rewrites entry 0's prev_hash to a forged value and re-signs
        the ENTIRE downstream chain so every link + self-integrity check passes.
        The only thing they cannot forge is the GENESIS anchor: entry 0's
        prev_hash != 'GENESIS' must trip BAD_GENESIS at index 0."""
        self.append_many(["a", "b", "c"])
        recs = self.recs()
        rehash(recs[0], prev_hash="FORGEDHEAD")
        prev = recs[0]["entry_hash"]
        for i in range(1, len(recs)):
            rehash(recs[i], prev_hash=prev)
            prev = recs[i]["entry_hash"]
        self.write_recs(recs)
        res = vl.verify_file(self.ledger)
        self.assertFalse(res.ok)
        self.assertEqual(res.first_broken_index, 0)
        self.assertIn("BAD_GENESIS", {p["kind"] for p in res.problems})

    def test_genesis_prev_tamper_no_resign(self):
        """prev_hash of entry 0 changed but not re-signed -> both BAD_GENESIS
        and MUTATION fire, break pinned at 0."""
        self.append_many(["a", "b"])
        recs = self.recs()
        recs[0]["prev_hash"] = "NOTGENESIS"
        self.write_recs(recs)
        res = vl.verify_file(self.ledger)
        self.assertFalse(res.ok)
        self.assertEqual(res.first_broken_index, 0)
        kinds = {p["kind"] for p in res.problems}
        self.assertIn("BAD_GENESIS", kinds)
        self.assertIn("MUTATION", kinds)

    def test_known_limitation_full_from_scratch_resign_undetectable(self):
        """DOCUMENTED LIMITATION (no MAC/secret key): if an attacker mutates an
        early entry and then rebuilds the ENTIRE chain from that point with
        correct GENESIS anchoring, the result is a cryptographically valid chain
        and verifies OK. This is by design for an unkeyed hash chain; we assert
        it explicitly so a future keyed-MAC upgrade visibly flips this test."""
        self.append_many(["a", "b", "c", "d"])
        recs = self.recs()
        recs[1]["command"] = "rm -rf /evidence"
        # Rebuild the whole chain from entry 1 onward, keeping entry 0 genuine.
        prev = recs[0]["entry_hash"]
        for i in range(1, len(recs)):
            rehash(recs[i], prev_hash=prev)
            prev = recs[i]["entry_hash"]
        self.write_recs(recs)
        res = vl.verify_file(self.ledger)
        self.assertTrue(res.ok,
                        msg="unkeyed chain CANNOT detect a full re-sign; if this "
                            "now fails, a MAC was added -> update this assertion")
        self.assertEqual(vl.main(["--ledger", self.ledger]), 0)

    def test_forged_single_fresh_genesis_entry_verifies_ok(self):
        """A from-scratch single entry (correct GENESIS) is indistinguishable
        from a real one without a key -> verifies OK (same limitation)."""
        e = lh.build_entry(make_event("totally legit"), lh.GENESIS, 0)
        self.write_recs([e])
        res = vl.verify_file(self.ledger)
        self.assertTrue(res.ok, msg=vl.format_report(res))


# --------------------------------------------------------------------------- #
# Structural corruption: JSON, required fields, non-object.
# --------------------------------------------------------------------------- #
class TestStructuralCorruption(AdvBase):
    def test_corrupt_json_mid_chain(self):
        self.append_many(["a", "b", "c"])
        lines = self.lines()
        lines[1] = "{ not valid json"
        self.write_lines(lines)
        res = vl.verify_file(self.ledger)
        self.assertFalse(res.ok)
        self.assertEqual(res.first_broken_index, 1)
        self.assertIn("CORRUPT_JSON", {p["kind"] for p in res.problems})

    def test_json_array_not_object(self):
        self.append_many(["a", "b"])
        lines = self.lines()
        lines[1] = json.dumps([1, 2, 3])  # valid JSON, wrong shape
        self.write_lines(lines)
        res = vl.verify_file(self.ledger)
        self.assertFalse(res.ok)
        self.assertEqual(res.first_broken_index, 1)
        self.assertIn("CORRUPT_JSON", {p["kind"] for p in res.problems})

    def test_missing_required_field(self):
        self.append_many(["a", "b"])
        recs = self.recs()
        del recs[1]["entry_hash"]  # drop a required field
        self.write_recs(recs)
        res = vl.verify_file(self.ledger)
        self.assertFalse(res.ok)
        self.assertEqual(res.first_broken_index, 1)
        self.assertIn("MISSING_FIELDS", {p["kind"] for p in res.problems})

    def test_missing_field_stops_scan_cleanly(self):
        """A missing-field line breaks the loop; verifier must not crash and the
        break index is pinned at that line."""
        self.append_many(["a", "b", "c"])
        recs = self.recs()
        del recs[0]["seq"]
        self.write_recs(recs)
        res = vl.verify_file(self.ledger)
        self.assertFalse(res.ok)
        self.assertEqual(res.first_broken_index, 0)


# --------------------------------------------------------------------------- #
# Empty / whitespace / CRLF tolerance.
# --------------------------------------------------------------------------- #
class TestWhitespaceAndEmpty(AdvBase):
    def test_empty_file_flagged_by_default(self):
        open(self.ledger, "w").close()
        res = vl.verify_file(self.ledger)
        self.assertFalse(res.ok)
        self.assertIn("EMPTY", {p["kind"] for p in res.problems})
        self.assertIsNone(res.first_broken_index)

    def test_empty_file_ok_with_allow_empty(self):
        open(self.ledger, "w").close()
        res = vl.verify_file(self.ledger, allow_empty=True)
        self.assertTrue(res.ok)

    def test_whitespace_only_lines_count_zero(self):
        res = vl.verify_lines(["", "   ", "\t", "\n"])
        self.assertFalse(res.ok)
        self.assertEqual(res.count, 0)
        self.assertIn("EMPTY", {p["kind"] for p in res.problems})

    def test_leading_trailing_whitespace_and_cr_tolerated(self):
        """A genuinely intact chain decorated with leading/trailing spaces and
        a trailing CR (CRLF artifact) must STILL verify OK (lines are stripped)."""
        self.append_many(["a", "b", "c"])
        raw = self.lines()
        dirty = ["   " + raw[0] + "   ", raw[1] + "\r", "\t" + raw[2]]
        res = vl.verify_lines(dirty)
        self.assertTrue(res.ok, msg=vl.format_report(res))
        self.assertEqual(res.count, 3)

    def test_interspersed_blank_lines_skipped(self):
        self.append_many(["a", "b", "c"])
        raw = self.lines()
        spaced = [raw[0], "", "   ", raw[1], "", raw[2], ""]
        res = vl.verify_lines(spaced)
        self.assertTrue(res.ok, msg=vl.format_report(res))
        self.assertEqual(res.count, 3)


# --------------------------------------------------------------------------- #
# VerifyResult.add() reporting fidelity.
# --------------------------------------------------------------------------- #
class TestResultReporting(unittest.TestCase):
    def test_first_broken_index_is_min_concrete_index(self):
        r = vl.VerifyResult()
        r.add(None, "EMPTY", "none-index first")
        r.add(5, "MUTATION", "high")
        r.add(2, "BROKEN_LINK", "low")
        self.assertEqual(r.first_broken_index, 2)

    def test_none_index_alone_keeps_first_broken_none(self):
        r = vl.VerifyResult()
        r.add(None, "EMPTY", "x")
        self.assertIsNone(r.first_broken_index)

    def test_as_dict_shape(self):
        r = vl.VerifyResult()
        r.add(3, "MUTATION", "d")
        d = r.as_dict()
        self.assertEqual(set(d), {"ok", "count", "first_broken_index", "problems"})
        self.assertEqual(d["first_broken_index"], 3)


# --------------------------------------------------------------------------- #
# CLI exit-code contract.
# --------------------------------------------------------------------------- #
class TestExitCodes(AdvBase):
    def test_exit_zero_on_clean(self):
        self.append_many(["a", "b"])
        self.assertEqual(vl.main(["--ledger", self.ledger]), 0)

    def test_exit_one_on_tamper(self):
        self.append_many(["a", "b"])
        recs = self.recs()
        recs[0]["tool"] = "Tampered"
        self.write_recs(recs)
        self.assertEqual(vl.main(["--ledger", self.ledger]), 1)

    def test_exit_two_on_missing_file(self):
        missing = os.path.join(self.tmp, "does-not-exist.jsonl")
        self.assertEqual(vl.main(["--ledger", missing]), 2)

    def test_exit_two_on_help(self):
        self.assertEqual(vl.main(["--help"]), 2)

    def test_json_output_flag_reports_first_broken_index(self):
        self.append_many(["a", "b", "c"])
        recs = self.recs()
        recs[1]["command"] = "evil"
        self.write_recs(recs)
        # Capture stdout to confirm machine-readable report carries the index.
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            rc = vl.main(["--ledger", self.ledger, "--json"])
        finally:
            sys.stdout = old
        self.assertEqual(rc, 1)
        payload = json.loads(buf.getvalue())
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["first_broken_index"], 1)
        self.assertEqual(payload["path"], os.path.abspath(self.ledger))


# --------------------------------------------------------------------------- #
# Hook entrypoint stays non-blocking on hostile stdin (ALWAYS exit 0).
# --------------------------------------------------------------------------- #
class TestHookNonBlocking(AdvBase):
    def _run(self, payload):
        return lh.main(argv=["--ledger", self.ledger], stdin=io.StringIO(payload))

    def test_garbage_stdin_returns_zero_no_file(self):
        self.assertEqual(self._run("{ not json at all"), 0)
        self.assertFalse(os.path.exists(self.ledger))

    def test_empty_stdin_returns_zero_no_file(self):
        self.assertEqual(self._run(""), 0)
        self.assertFalse(os.path.exists(self.ledger))

    def test_json_but_not_a_tool_event_ignored(self):
        self.assertEqual(self._run(json.dumps({"hook_event_name": "SessionStart"})), 0)
        self.assertFalse(os.path.exists(self.ledger))

    def test_json_array_payload_non_fatal(self):
        """A JSON array (not a dict) must not crash the hook; exit 0, no write."""
        self.assertEqual(self._run(json.dumps([1, 2, 3])), 0)
        self.assertFalse(os.path.exists(self.ledger))

    def test_json_null_payload_non_fatal(self):
        self.assertEqual(self._run("null"), 0)
        self.assertFalse(os.path.exists(self.ledger))

    def test_tool_event_with_no_input_still_logs(self):
        """A tool event missing tool_input must still produce a valid chained
        entry (command becomes empty string), not crash."""
        ev = {"session_id": "s", "tool_name": "Bash", "tool_response": "x"}
        self.assertEqual(self._run(json.dumps(ev)), 0)
        res = vl.verify_file(self.ledger)
        self.assertTrue(res.ok, msg=vl.format_report(res))
        self.assertEqual(res.count, 1)

    def test_hook_then_verify_end_to_end_chain(self):
        """Drive several events through the real hook main() and verify the
        resulting on-disk chain is intact."""
        for c in ["mmls disk.E01", "fls -r disk.E01", "icat disk.E01 9"]:
            self.assertEqual(self._run(json.dumps(make_event(c))), 0)
        res = vl.verify_file(self.ledger)
        self.assertTrue(res.ok, msg=vl.format_report(res))
        self.assertEqual(res.count, 3)


# --------------------------------------------------------------------------- #
# Unicode / large-output hashing robustness in the hook.
# --------------------------------------------------------------------------- #
class TestHashRobustness(AdvBase):
    def test_unicode_output_roundtrips_and_verifies(self):
        ev = make_event("strings file", output="évil—payload \U0001f480 ￿")
        lh.append_entry(self.ledger, ev)
        res = vl.verify_file(self.ledger)
        self.assertTrue(res.ok, msg=vl.format_report(res))
        rec = self.recs()[0]
        # output_len is the UTF-8 byte length, not the char count.
        self.assertEqual(rec["output_len"],
                         len("évil—payload \U0001f480 ￿".encode("utf-8")))

    def test_dict_tool_response_hashed_canonically(self):
        ev = {
            "session_id": "s",
            "tool_name": "Read",
            "tool_input": {"file_path": "/evidence/notes.txt"},
            "tool_response": {"content": "secret body"},
        }
        lh.append_entry(self.ledger, ev)
        res = vl.verify_file(self.ledger)
        self.assertTrue(res.ok)
        self.assertIn("notes.txt", self.recs()[0]["command"])

    def test_empty_output_is_valid_entry(self):
        ev = make_event("true", output="")
        lh.append_entry(self.ledger, ev)
        rec = self.recs()[0]
        self.assertEqual(rec["output_len"], 0)
        self.assertEqual(rec["output_sha256"],
                         lh.sha256_hex(b""))
        self.assertTrue(vl.verify_file(self.ledger).ok)


if __name__ == "__main__":
    unittest.main(verbosity=2)
