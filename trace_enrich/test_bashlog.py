#!/usr/bin/env python3
"""Unit tests for trace_enrich.bashlog (stdlib unittest, no third-party deps).

Fixtures are synthetic JSONL strings built to mirror the REAL bash_raw schema
verified on the SIFT VM (2026-06-12): top-level ``tool_use_id``/``session_id``/
``command``/``stdout``/``stderr``/``ts`` plus a nested ``tool_response`` with
``stdout``/``stderr``/``interrupted``/``noOutputExpected`` and optional
``persistedOutputPath``/``persistedOutputSize``. Crucially the real schema has
**no exit_code/returncode**, so the "missing-exit-code" case below is in fact
the *normal* shape, and outcome must be derived without one.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

import bashlog


def _entry(
    tool_use_id="toolu_X",
    command="echo hi",
    stdout="hi\n",
    stderr="",
    interrupted=False,
    no_output_expected=False,
    persisted_path=None,
    persisted_size=None,
    session_id="sess-1",
    ts="2026-06-12T04:00:00Z",
):
    """Build one raw log object in the real schema (no exit code field)."""
    tr = {
        "stdout": stdout,
        "stderr": stderr,
        "interrupted": interrupted,
        "isImage": False,
        "noOutputExpected": no_output_expected,
    }
    if persisted_path is not None:
        tr["persistedOutputPath"] = persisted_path
    if persisted_size is not None:
        tr["persistedOutputSize"] = persisted_size
    return {
        "ts": ts,
        "session_id": session_id,
        "tool_use_id": tool_use_id,
        "cwd": "/home/ubuntu/find-evil/baseline/protocol-sift",
        "transcript_path": "/home/ubuntu/.claude/projects/x/sess-1.jsonl",
        "command": command,
        "description": "desc",
        "stdout": stdout,
        "stderr": stderr,
        "tool_response": tr,
    }


def _write_jsonl(objs):
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        for o in objs:
            fh.write(json.dumps(o) + "\n")
    return path


class OutcomeTests(unittest.TestCase):
    def test_ok(self):
        e = _entry(stdout="total 76\ndrwx...\n")
        self.assertEqual(bashlog.outcome(e), bashlog.OK)

    def test_empty_blank_stdout(self):
        # Succeeded (no error signal) but produced no stdout -> returned-nothing.
        e = _entry(command="fls -r img.E01", stdout="", stderr="")
        self.assertEqual(bashlog.outcome(e), bashlog.EMPTY)

    def test_empty_whitespace_only_stdout(self):
        e = _entry(stdout="   \n\t  \n")
        self.assertEqual(bashlog.outcome(e), bashlog.EMPTY)

    def test_empty_but_no_output_expected_is_ok(self):
        # `mkdir` etc.: hook flags noOutputExpected -> not a returned-nothing.
        e = _entry(command="mkdir -p reports", stdout="", no_output_expected=True)
        self.assertEqual(bashlog.outcome(e), bashlog.OK)

    def test_errored_via_stderr_not_found(self):
        e = _entry(
            command="fls /no/such.E01",
            stdout="",
            stderr="fls: cannot open /no/such.E01: No such file or directory\n",
        )
        self.assertEqual(bashlog.outcome(e), bashlog.ERRORED)

    def test_errored_command_not_found(self):
        e = _entry(
            command="vol3 -f mem.raw",
            stdout="",
            stderr="bash: vol3: command not found\n",
        )
        self.assertEqual(bashlog.outcome(e), bashlog.ERRORED)

    def test_errored_python_traceback(self):
        e = _entry(
            command="vol.py -f mem.raw windows.pslist",
            stdout="",
            stderr="Traceback (most recent call last):\n  ...\nValueError: bad header\n",
        )
        self.assertEqual(bashlog.outcome(e), bashlog.ERRORED)

    def test_errored_when_interrupted_even_with_stdout(self):
        # Timeout/kill: interrupted flag wins regardless of partial stdout.
        e = _entry(command="yara -r rules/ /", stdout="partial...\n", interrupted=True)
        self.assertEqual(bashlog.outcome(e), bashlog.ERRORED)

    def test_benign_stderr_with_stdout_is_ok(self):
        # Many forensic tools print progress/notices to stderr on success.
        e = _entry(
            command="tsk_recover -e img.E01 out/",
            stdout="Files Recovered: 412\n",
            stderr="Recovering files...\n100%\n",
        )
        self.assertEqual(bashlog.outcome(e), bashlog.OK)

    def test_missing_exit_code_is_the_norm(self):
        # The real schema has NO exit code; classification must not depend on
        # one. A plain successful call with output is still `ok`.
        e = _entry(command="mmls img.E01", stdout="Offset Sectors ...\n")
        self.assertNotIn("exit_code", e)
        self.assertNotIn("returncode", e)
        self.assertEqual(bashlog.outcome(e), bashlog.OK)

    def test_blank_stdout_but_persisted_output_is_ok(self):
        # Inline stdout blank but output was persisted to disk -> not empty.
        e = _entry(
            command="seq 1 30000",
            stdout="",
            persisted_path="/tmp/does-not-matter.txt",
            persisted_size=168894,
        )
        self.assertEqual(bashlog.outcome(e), bashlog.OK)


class StderrHeuristicTests(unittest.TestCase):
    def test_clear_errors_match(self):
        for s in [
            "bash: foo: command not found",
            "ls: cannot access 'x': No such file or directory",
            "Permission denied",
            "icat: Invalid argument",
            "Segmentation fault (core dumped)",
            "yara: error: rule file not found",
            "fatal: not a git repository",
        ]:
            self.assertTrue(bashlog.stderr_looks_like_error(s), s)

    def test_benign_stderr_does_not_match(self):
        for s in [
            "",
            "   ",
            "Recovering files...\n100%",
            "Loading profile Win10x64",
            "Scanning... done",
        ]:
            self.assertFalse(bashlog.stderr_looks_like_error(s), s)


class LoadTests(unittest.TestCase):
    def test_load_keys_by_tool_use_id_and_surfaces_fields(self):
        objs = [
            _entry(tool_use_id="toolu_A", command="mmls img.E01", stdout="Offset...\n"),
            _entry(tool_use_id="toolu_B", command="fls img.E01", stdout="", stderr="fls: cannot open: No such file or directory\n"),
        ]
        path = _write_jsonl(objs)
        try:
            log = bashlog.load_bash_log(path)
        finally:
            os.unlink(path)
        self.assertEqual(set(log), {"toolu_A", "toolu_B"})
        self.assertEqual(log["toolu_A"]["outcome"], bashlog.OK)
        self.assertEqual(log["toolu_B"]["outcome"], bashlog.ERRORED)
        self.assertEqual(log["toolu_A"]["command"], "mmls img.E01")
        self.assertEqual(log["toolu_A"]["session_id"], "sess-1")
        self.assertIn("raw", log["toolu_A"])

    def test_load_skips_blank_and_malformed_lines(self):
        fd, path = tempfile.mkstemp(suffix=".jsonl")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n")
            fh.write(json.dumps(_entry(tool_use_id="toolu_OK", stdout="ok\n")) + "\n")
            fh.write("{not valid json\n")  # partial/truncated final line
            fh.write("   \n")
        try:
            log = bashlog.load_bash_log(path)
        finally:
            os.unlink(path)
        self.assertEqual(set(log), {"toolu_OK"})

    def test_load_drops_entries_without_tool_use_id(self):
        obj = _entry()
        obj.pop("tool_use_id")
        path = _write_jsonl([obj])
        try:
            log = bashlog.load_bash_log(path)
        finally:
            os.unlink(path)
        self.assertEqual(log, {})

    def test_duplicate_tool_use_id_last_wins(self):
        objs = [
            _entry(tool_use_id="toolu_D", stdout="first\n"),
            _entry(tool_use_id="toolu_D", stdout="second\n"),
        ]
        path = _write_jsonl(objs)
        try:
            log = bashlog.load_bash_log(path)
        finally:
            os.unlink(path)
        self.assertEqual(log["toolu_D"]["stdout"], "second\n")


class GetStdoutTests(unittest.TestCase):
    def test_inline_stdout(self):
        path = _write_jsonl([_entry(tool_use_id="toolu_S", stdout="line1\nline2\n")])
        try:
            log = bashlog.load_bash_log(path)
        finally:
            os.unlink(path)
        self.assertEqual(bashlog.get_stdout(log, "toolu_S"), "line1\nline2\n")

    def test_unknown_id_returns_empty(self):
        self.assertEqual(bashlog.get_stdout({}, "toolu_missing"), "")

    def test_read_persisted_returns_full_file(self):
        # Build a persisted file larger than the truncated inline stdout.
        full = "X" * 5000
        pfd, ppath = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(pfd, "w", encoding="utf-8") as fh:
            fh.write(full)
        try:
            path = _write_jsonl([
                _entry(
                    tool_use_id="toolu_P",
                    stdout="X" * 100,  # truncated inline
                    persisted_path=ppath,
                    persisted_size=5000,
                )
            ])
            log = bashlog.load_bash_log(path)
            os.unlink(path)
            # default: inline (truncated)
            self.assertEqual(len(bashlog.get_stdout(log, "toolu_P")), 100)
            # opt-in: full persisted output
            self.assertEqual(
                bashlog.get_stdout(log, "toolu_P", read_persisted=True), full
            )
        finally:
            os.unlink(ppath)

    def test_read_persisted_falls_back_when_file_missing(self):
        path = _write_jsonl([
            _entry(
                tool_use_id="toolu_M",
                stdout="inline-only\n",
                persisted_path="/no/such/persisted/file.txt",
                persisted_size=999999,
            )
        ])
        try:
            log = bashlog.load_bash_log(path)
        finally:
            os.unlink(path)
        self.assertEqual(
            bashlog.get_stdout(log, "toolu_M", read_persisted=True), "inline-only\n"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
