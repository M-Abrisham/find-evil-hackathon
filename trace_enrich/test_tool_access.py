#!/usr/bin/env python3
"""Unit tests for trace_enrich.tool_access (stdlib unittest, no third-party deps).

Signatures mirror REAL failure modes documented for this SIFT box:
  * PECmd / vss_carver absent            -> command-not-found  (matrix §B)
  * mac_apt broken (kaitaistruct)        -> broken-import      (matrix §B, P5)
  * Wireshark invoked headless           -> gui-no-display     (worklist GUI rule)
  * sandbox egress block                 -> network-blocked    (sift-runner sandbox)
"""

from __future__ import annotations

import unittest

import tool_access
import enrich


class TestClassify(unittest.TestCase):
    def test_command_not_found_bash(self):
        out = tool_access.classify("bash: line 1: PECmd: command not found", "", "PECmd -f C:/pf")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["reason"], "command-not-found")
        self.assertEqual(out[0]["token"], "PECmd")

    def test_command_not_found_sh_style(self):
        out = tool_access.classify("sh: 1: vss_carver: not found", "", "vss_carver -i img")
        self.assertEqual(out[0]["reason"], "command-not-found")
        self.assertEqual(out[0]["token"], "vss_carver")

    def test_broken_import_mac_apt(self):
        stderr = ("Traceback (most recent call last):\n"
                  "  File \"/usr/local/bin/mac_apt.py\", line 23, in <module>\n"
                  "ModuleNotFoundError: No module named 'kaitaistruct'")
        out = tool_access.classify(stderr, "", "mac_apt.py -i image.E01 ALL")
        reasons = {f["reason"] for f in out}
        self.assertIn("broken-import", reasons)
        toks = {f["token"] for f in out}
        self.assertIn("kaitaistruct", toks)

    def test_gui_no_display_wireshark(self):
        stderr = "qt.qpa.xcb: could not connect to display\nqt.qpa.plugin: Could not load the Qt platform plugin"
        out = tool_access.classify(stderr, "", "wireshark -r capture.pcap")
        self.assertTrue(any(f["reason"] == "gui-no-display" for f in out))
        # token falls back to the command's headline token
        self.assertTrue(any(f["token"] for f in out))

    def test_network_blocked(self):
        out = tool_access.classify("curl: (6) Could not resolve host: intel.example.com", "",
                                   "machinae 1.2.3.4")
        self.assertEqual(out[0]["reason"], "network-blocked")

    def test_exec_permission(self):
        out = tool_access.classify("bash: /opt/tools/parser: Permission denied", "",
                                   "/opt/tools/parser -h")
        self.assertEqual(out[0]["reason"], "exec-permission")
        self.assertEqual(out[0]["token"], "parser")

    def test_missing_shared_library(self):
        out = tool_access.classify(
            "vol: error while loading shared libraries: libfoo.so.1: cannot open shared object file",
            "", "vol -f mem.raw windows.pslist")
        self.assertEqual(out[0]["reason"], "missing-library")
        self.assertEqual(out[0]["token"], "vol")

    def test_clean_run_no_failures(self):
        self.assertEqual(tool_access.classify("", "MFT parsed: 120000 records", "MFTECmd -f $MFT"), [])

    def test_ordinary_tool_error_is_not_access_failure(self):
        # Tool ran fine but errored on the evidence -> NOT an access failure.
        out = tool_access.classify("Error: unable to parse record 5512: corrupt header", "",
                                   "EvtxECmd -f Security.evtx")
        self.assertEqual(out, [])

    def test_dedup_repeated_signature(self):
        stderr = "bash: PECmd: command not found\nbash: PECmd: command not found"
        out = tool_access.classify(stderr, "", "PECmd; PECmd")
        self.assertEqual(len(out), 1)

    def test_label_fields_tags(self):
        failures = tool_access.classify("bash: PECmd: command not found", "", "PECmd")
        lab = tool_access.label_fields(failures)
        self.assertIn("tool_unavailable:PECmd", lab["tags"])
        self.assertIn("access_fail:command-not-found", lab["tags"])
        self.assertTrue(lab["enrich"]["tool_access"]["unavailable"])

    def test_label_fields_empty(self):
        lab = tool_access.label_fields([])
        self.assertEqual(lab["tags"], [])
        self.assertEqual(lab["enrich"], {})


def _span(tuid="toolu_1", command="PECmd -f C:/pf"):
    return {"span_id": "s1", "tool_use_id": tuid, "tool_name": "Bash",
            "command": command, "success": False, "name": "claude_code.tool"}


def _bash_entry(stderr, command="PECmd -f C:/pf", stdout=""):
    return {"command": command, "stdout": stdout, "stderr": stderr,
            "interrupted": False, "no_output_expected": False,
            "persisted_output_path": None, "persisted_output_size": None,
            "tool_use_id": "toolu_1", "session_id": "s", "ts": "t",
            "raw": {"tool_response": {"interrupted": False}}}


class TestEnrichIntegration(unittest.TestCase):
    def test_span_gets_tool_unavailable_tag(self):
        log = {"toolu_1": _bash_entry("bash: PECmd: command not found")}
        label = enrich._label_tool_span(_span(), log)
        self.assertIn("tool_unavailable:PECmd", label["tags"])
        ta = label["metadata"]["enrich"]["tool_access"]
        self.assertTrue(ta["unavailable"])
        self.assertEqual(ta["failures"][0]["reason"], "command-not-found")
        # outcome still errored (refines, never replaces)
        self.assertEqual(label["metadata"]["enrich"]["outcome"], "errored")

    def test_clean_span_has_no_access_block(self):
        log = {"toolu_1": _bash_entry("", command="MFTECmd -f $MFT", stdout="ok\n")}
        label = enrich._label_tool_span(_span(command="MFTECmd -f $MFT"), log)
        self.assertNotIn("tool_access", label["metadata"]["enrich"])
        self.assertFalse(any(t.startswith("tool_unavailable") for t in label["tags"]))

    def test_root_rollup_and_tag(self):
        trace = {"root_span_id": "r" * 32,
                 "root_span": {"span_id": "root1", "metadata": {}},
                 "tool_spans": [_span()], "session_id": "s", "n_spans": 2}
        log = {"toolu_1": _bash_entry("bash: PECmd: command not found")}
        plan = enrich.build_plan(trace=trace, bash_log=log, report_text="",
                                 case_input_text="", case_id="T-1")
        tu = plan.root_metadata["rollup"]["tool_unavailable"]
        self.assertEqual(tu[0]["token"], "PECmd")
        self.assertEqual(tu[0]["count"], 1)
        self.assertIn("has_tool_unavailable", plan.root_tags)

    def test_root_rollup_empty_when_clean(self):
        trace = {"root_span_id": "r" * 32,
                 "root_span": {"span_id": "root1", "metadata": {}},
                 "tool_spans": [_span(command="MFTECmd -f $MFT")],
                 "session_id": "s", "n_spans": 2}
        log = {"toolu_1": _bash_entry("", command="MFTECmd -f $MFT", stdout="ok\n")}
        plan = enrich.build_plan(trace=trace, bash_log=log, report_text="",
                                 case_input_text="", case_id="T-1")
        self.assertEqual(plan.root_metadata["rollup"]["tool_unavailable"], [])
        self.assertNotIn("has_tool_unavailable", plan.root_tags)


if __name__ == "__main__":
    unittest.main(verbosity=2)
