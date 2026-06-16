#!/usr/bin/env python3
"""R6 - unittest suite for the hash-chained command ledger.

STDLIB ONLY. Run from the sift-runner dir so the sibling modules import:

    python3 -m unittest -v test_ledger
    # or
    python3 test_ledger.py

Covers the required scenarios:
  * append several entries -> verify OK
  * mutate one line        -> verify DETECTS (and reports the index)
  * delete a line          -> verify DETECTS
  * reorder lines          -> verify DETECTS
plus: insertion, empty ledger, single entry, the genesis link, the end-to-end
PostToolUse hook driven via stdin, and path resolution precedence.

Synthetic fixtures only; every ledger is written to a fresh temp dir and torn
down. Nothing touches ~/.claude or any live config.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ledger_hook as lh  # noqa: E402
import verify_ledger as vl  # noqa: E402


def make_event(command, tool="Bash", output="some stdout", session="sess-1"):
    """Synthetic PostToolUse hook event."""
    return {
        "session_id": session,
        "tool_name": tool,
        "tool_input": {"command": command} if tool == "Bash" else {"path": command},
        "tool_response": output,
    }


class LedgerTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sift-ledger-test-")
        self.ledger = os.path.join(self.tmp, "custody.jsonl")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def append_many(self, commands):
        """Append one entry per command; return the list of written entries."""
        written = []
        for c in commands:
            written.append(lh.append_entry(self.ledger, make_event(c)))
        return written

    def read_lines(self):
        with open(self.ledger, "r", encoding="utf-8") as fh:
            return [ln for ln in fh.read().splitlines() if ln.strip()]

    def write_lines(self, lines):
        with open(self.ledger, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")


class TestAppendAndVerifyOK(LedgerTestBase):
    def test_several_entries_verify_ok(self):
        entries = self.append_many([
            "mmls /evidence/disk.E01",
            "fls -r -o 2048 /evidence/disk.E01",
            "icat -o 2048 /evidence/disk.E01 12345",
            "mactime -b bodyfile 2024-01-01",
        ])
        # seqs are contiguous, chain links are correct.
        self.assertEqual([e["seq"] for e in entries], [0, 1, 2, 3])
        self.assertEqual(entries[0]["prev_hash"], lh.GENESIS)
        for i in range(1, len(entries)):
            self.assertEqual(entries[i]["prev_hash"], entries[i - 1]["entry_hash"])

        res = vl.verify_file(self.ledger)
        self.assertTrue(res.ok, msg=vl.format_report(res))
        self.assertEqual(res.count, 4)
        self.assertIsNone(res.first_broken_index)
        self.assertEqual(res.problems, [])

    def test_single_entry_ok(self):
        self.append_many(["ls -la /evidence"])
        res = vl.verify_file(self.ledger)
        self.assertTrue(res.ok, msg=vl.format_report(res))
        self.assertEqual(res.count, 1)

    def test_cli_main_returns_zero_on_clean(self):
        self.append_many(["mmls disk.E01", "fsstat disk.E01"])
        rc = vl.main(["--ledger", self.ledger])
        self.assertEqual(rc, 0)


class TestMutationDetected(LedgerTestBase):
    def test_mutate_command_field_detected(self):
        self.append_many(["mmls disk.E01", "fls -r disk.E01", "icat disk.E01 99"])
        lines = self.read_lines()

        # Tamper with entry index 1: rewrite the command but leave hashes intact.
        rec = json.loads(lines[1])
        rec["command"] = "rm -rf /evidence"  # attacker swaps what was really run
        lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        self.write_lines(lines)

        res = vl.verify_file(self.ledger)
        self.assertFalse(res.ok)
        self.assertEqual(res.first_broken_index, 1)
        kinds = {p["kind"] for p in res.problems}
        self.assertIn("MUTATION", kinds)

    def test_mutate_output_hash_detected(self):
        self.append_many(["clamscan /evidence", "exiftool a.jpg"])
        lines = self.read_lines()
        rec = json.loads(lines[0])
        rec["output_sha256"] = "0" * 64  # forge the recorded output digest
        lines[0] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        self.write_lines(lines)

        res = vl.verify_file(self.ledger)
        self.assertFalse(res.ok)
        self.assertEqual(res.first_broken_index, 0)

    def test_main_exit_code_one_on_mutation(self):
        self.append_many(["mmls disk.E01", "fls disk.E01"])
        lines = self.read_lines()
        rec = json.loads(lines[1])
        rec["tool"] = "Tampered"
        lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        self.write_lines(lines)
        rc = vl.main(["--ledger", self.ledger])
        self.assertEqual(rc, 1)


class TestDeletionDetected(LedgerTestBase):
    def test_delete_middle_line_detected(self):
        self.append_many(["a-cmd", "b-cmd", "c-cmd", "d-cmd"])
        lines = self.read_lines()
        del lines[2]  # remove the 3rd entry (seq=2)
        self.write_lines(lines)

        res = vl.verify_file(self.ledger)
        self.assertFalse(res.ok)
        # After deletion, the line now at index 2 (old seq=3) breaks linkage+seq.
        self.assertEqual(res.first_broken_index, 2)
        kinds = {p["kind"] for p in res.problems}
        self.assertTrue({"BROKEN_LINK", "BAD_SEQ"} & kinds)

    def test_delete_head_detected(self):
        self.append_many(["a-cmd", "b-cmd", "c-cmd"])
        lines = self.read_lines()
        del lines[0]  # remove genesis-linked head
        self.write_lines(lines)

        res = vl.verify_file(self.ledger)
        self.assertFalse(res.ok)
        self.assertEqual(res.first_broken_index, 0)
        kinds = {p["kind"] for p in res.problems}
        self.assertIn("BAD_GENESIS", kinds)


class TestReorderDetected(LedgerTestBase):
    def test_swap_two_lines_detected(self):
        self.append_many(["a-cmd", "b-cmd", "c-cmd", "d-cmd"])
        lines = self.read_lines()
        lines[1], lines[2] = lines[2], lines[1]  # swap entries 1 and 2
        self.write_lines(lines)

        res = vl.verify_file(self.ledger)
        self.assertFalse(res.ok)
        # The first position whose content no longer matches expectations is 1.
        self.assertEqual(res.first_broken_index, 1)
        kinds = {p["kind"] for p in res.problems}
        self.assertTrue({"BROKEN_LINK", "BAD_SEQ"} & kinds)

    def test_full_reverse_detected(self):
        self.append_many(["a", "b", "c"])
        lines = self.read_lines()
        lines.reverse()
        self.write_lines(lines)
        res = vl.verify_file(self.ledger)
        self.assertFalse(res.ok)
        self.assertEqual(res.first_broken_index, 0)


class TestInsertionDetected(LedgerTestBase):
    def test_insert_forged_line_detected(self):
        self.append_many(["a-cmd", "b-cmd", "c-cmd"])
        lines = self.read_lines()
        # Forge a plausible entry and splice it in at index 1. Even if the
        # attacker self-consistently hashes it, it can't match the real chain.
        forged = lh.build_entry(make_event("evil --steal"), prev_hash="deadbeef",
                                seq=1)
        forged_line = json.dumps(forged, sort_keys=True, separators=(",", ":"))
        lines.insert(1, forged_line)
        self.write_lines(lines)

        res = vl.verify_file(self.ledger)
        self.assertFalse(res.ok)
        self.assertEqual(res.first_broken_index, 1)

    def test_duplicate_line_detected(self):
        self.append_many(["a-cmd", "b-cmd"])
        lines = self.read_lines()
        lines.insert(1, lines[0])  # duplicate the head
        self.write_lines(lines)
        res = vl.verify_file(self.ledger)
        self.assertFalse(res.ok)
        self.assertEqual(res.first_broken_index, 1)


class TestEmptyAndEdgeCases(LedgerTestBase):
    def test_empty_ledger_flagged_by_default(self):
        self.write_lines([])  # writes just a newline -> no entries
        # Actually write a truly empty file:
        open(self.ledger, "w").close()
        res = vl.verify_file(self.ledger)
        self.assertFalse(res.ok)
        kinds = {p["kind"] for p in res.problems}
        self.assertIn("EMPTY", kinds)

    def test_empty_ledger_ok_with_allow_empty(self):
        open(self.ledger, "w").close()
        res = vl.verify_file(self.ledger, allow_empty=True)
        self.assertTrue(res.ok)

    def test_corrupt_json_detected(self):
        self.append_many(["a-cmd", "b-cmd"])
        lines = self.read_lines()
        lines[1] = "{ this is not json"
        self.write_lines(lines)
        res = vl.verify_file(self.ledger)
        self.assertFalse(res.ok)
        self.assertEqual(res.first_broken_index, 1)


class TestHashPrimitives(unittest.TestCase):
    def test_entry_hash_is_deterministic(self):
        ev = make_event("mmls x")
        e1 = lh.build_entry(ev, lh.GENESIS, 0,
                            now=_fixed_dt(), receipt_id="rid-1")
        e2 = lh.build_entry(ev, lh.GENESIS, 0,
                            now=_fixed_dt(), receipt_id="rid-1")
        self.assertEqual(e1["entry_hash"], e2["entry_hash"])

    def test_entry_hash_changes_with_prev(self):
        ev = make_event("mmls x")
        e1 = lh.build_entry(ev, lh.GENESIS, 0, now=_fixed_dt(), receipt_id="r")
        e2 = lh.build_entry(ev, "otherprev", 0, now=_fixed_dt(), receipt_id="r")
        self.assertNotEqual(e1["entry_hash"], e2["entry_hash"])

    def test_compute_entry_hash_ignores_existing_entry_hash(self):
        ev = make_event("ls")
        e = lh.build_entry(ev, lh.GENESIS, 0)
        h_with = lh.compute_entry_hash(lh.GENESIS, e)
        e2 = dict(e)
        e2["entry_hash"] = "garbage"
        h_without = lh.compute_entry_hash(lh.GENESIS, e2)
        self.assertEqual(h_with, h_without)
        self.assertEqual(h_with, e["entry_hash"])


class TestHookEntrypoint(LedgerTestBase):
    def test_main_appends_chained_entries_via_stdin(self):
        events = [make_event("mmls disk.E01"),
                  make_event("fls -r disk.E01"),
                  make_event("grep evil /tmp/out", tool="Bash")]
        for ev in events:
            stdin = io.StringIO(json.dumps(ev))
            rc = lh.main(argv=["--ledger", self.ledger], stdin=stdin)
            self.assertEqual(rc, 0)

        res = vl.verify_file(self.ledger)
        self.assertTrue(res.ok, msg=vl.format_report(res))
        self.assertEqual(res.count, 3)

    def test_main_non_bash_tool_recorded(self):
        ev = {
            "session_id": "s",
            "tool_name": "Read",
            "tool_input": {"file_path": "/evidence/notes.txt"},
            "tool_response": {"content": "file body here"},
        }
        rc = lh.main(argv=["--ledger", self.ledger], stdin=io.StringIO(json.dumps(ev)))
        self.assertEqual(rc, 0)
        recs = [json.loads(l) for l in self.read_lines()]
        self.assertEqual(recs[0]["tool"], "Read")
        self.assertIn("notes.txt", recs[0]["command"])

    def test_main_empty_stdin_is_noop(self):
        rc = lh.main(argv=["--ledger", self.ledger], stdin=io.StringIO(""))
        self.assertEqual(rc, 0)
        self.assertFalse(os.path.exists(self.ledger))

    def test_main_garbage_stdin_non_fatal(self):
        rc = lh.main(argv=["--ledger", self.ledger], stdin=io.StringIO("{bad json"))
        self.assertEqual(rc, 0)  # must NOT block the agent run
        self.assertFalse(os.path.exists(self.ledger))

    def test_main_non_tool_event_ignored(self):
        ev = {"session_id": "s", "hook_event_name": "SessionStart"}
        rc = lh.main(argv=["--ledger", self.ledger], stdin=io.StringIO(json.dumps(ev)))
        self.assertEqual(rc, 0)
        self.assertFalse(os.path.exists(self.ledger))


class TestPathResolution(unittest.TestCase):
    def test_arg_beats_env_and_default(self):
        p = lh.resolve_ledger_path("/tmp/explicit.jsonl", env="/env/path.jsonl")
        self.assertEqual(p, os.path.abspath("/tmp/explicit.jsonl"))

    def test_env_beats_default(self):
        p = lh.resolve_ledger_path(None, env="/env/path.jsonl")
        self.assertEqual(p, os.path.abspath("/env/path.jsonl"))

    def test_default_is_outside_project(self):
        p = lh.resolve_ledger_path(None, env="")
        self.assertTrue(p.endswith(os.path.join(".sift-custody", "command_ledger.jsonl")))
        # default lives under the home dir, not the agent's project tree.
        self.assertTrue(p.startswith(os.path.expanduser("~")))


def _fixed_dt():
    from datetime import datetime, timezone
    return datetime(2026, 6, 14, 12, 0, 0, tzinfo=timezone.utc)


if __name__ == "__main__":
    unittest.main(verbosity=2)
