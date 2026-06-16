#!/usr/bin/env python3
"""Tests for IOC -> tool provenance (trace_enrich/provenance.py).

Stdlib ``unittest`` only. Every fixture is synthetic inline text, so the suite
is self-contained and never touches the real, gitignored case data.

Run:  python3 -m unittest trace_enrich.test_provenance -v
  or: cd trace_enrich && python3 -m unittest test_provenance -v
"""

import os
import sys
import unittest

# Make the package importable whether run as a module or from inside the dir.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import provenance  # noqa: E402


def _rec(records, value):
    """The single provenance record whose normalised ioc equals ``value``."""
    matches = [r for r in records if r["ioc"] == value]
    assert len(matches) == 1, f"expected 1 record for {value!r}, got {len(matches)}"
    return matches[0]


# ---------------------------------------------------------------------------
# extract_iocs — delegates to scorer; clean kinds only, normalised, deduped.
# ---------------------------------------------------------------------------
class TestExtractIocs(unittest.TestCase):
    def test_extracts_and_normalises_clean_kinds(self):
        report = (
            "email Mr.Evil@Yahoo.COM, md5 0xAEE4FCD9301C03B3B054623CA261959A, "
            "ip 192.168.1.111, mac 00-10-A4-93-3E-09, sid s-1-5-21-3"
        )
        iocs = provenance.extract_iocs(report)
        pairs = {(i["kind"], i["value"]) for i in iocs}
        self.assertIn(("email", "mr.evil@yahoo.com"), pairs)
        self.assertIn(("hash", "aee4fcd9301c03b3b054623ca261959a"), pairs)
        self.assertIn(("ipv4", "192.168.1.111"), pairs)
        self.assertIn(("mac", "0010a4933e09"), pairs)
        self.assertIn(("sid", "S-1-5-21-3"), pairs)

    def test_dedup_and_no_cidr_base_as_host(self):
        # The CIDR base 10.11.11.0 must NOT appear as an extracted host IP.
        report = "subnet 10.11.11.0/24 host 10.11.11.128 and again 10.11.11.128"
        iocs = provenance.extract_iocs(report)
        ips = [i["value"] for i in iocs if i["kind"] == "ipv4"]
        self.assertEqual(ips, ["10.11.11.128"])  # deduped, base excluded
        self.assertNotIn("10.11.11.0", ips)


# ---------------------------------------------------------------------------
# Required test 1 — IOC sourced from a tool stdout -> tool:<id>, not fabricated.
# ---------------------------------------------------------------------------
class TestIocFromToolStdout(unittest.TestCase):
    def test_ioc_in_tool_stdout_is_attributed_to_that_tool(self):
        report = "Report cites exfil to 203.0.113.5."
        tool_stdouts = {"toolu_ABC": "icat output ... 203.0.113.5 ... done"}
        recs = provenance.provenance(report, tool_stdouts, case_input_text="")
        r = _rec(recs, "203.0.113.5")
        self.assertEqual(r["source"], "tool:toolu_ABC")
        self.assertEqual(r["tool_sources"], ["tool:toolu_ABC"])
        self.assertFalse(r["candidate_fabrication"])

    def test_first_tool_in_log_order_wins_but_all_recorded(self):
        report = "hash aee4fcd9301c03b3b054623ca261959a"
        h = "aee4fcd9301c03b3b054623ca261959a"
        # Insertion order is log order: t1 before t2.
        tool_stdouts = {"t1": f"yara hit {h}", "t2": f"also {h.upper()}"}
        recs = provenance.provenance(report, tool_stdouts, case_input_text="")
        r = _rec(recs, h)
        self.assertEqual(r["source"], "tool:t1")  # first match
        self.assertEqual(r["tool_sources"], ["tool:t1", "tool:t2"])  # all matches
        self.assertFalse(r["candidate_fabrication"])


# ---------------------------------------------------------------------------
# Required test 2 — IOC only in the case input -> "case_input", NOT fabricated.
# This is the critical guardrail.
# ---------------------------------------------------------------------------
class TestIocOnlyInCaseInput(unittest.TestCase):
    def test_case_input_only_is_not_flagged(self):
        report = "The malicious address is 9.9.9.9."
        # No tool emitted it; it is present in the case input the agent Read.
        recs = provenance.provenance(
            report,
            tool_stdouts={"t1": "unrelated tool output"},
            case_input_text="artifact summary mentions 9.9.9.9 in the case file",
        )
        r = _rec(recs, "9.9.9.9")
        self.assertEqual(r["source"], "case_input")
        self.assertTrue(r["in_case_input"])
        self.assertEqual(r["tool_sources"], [])
        # GUARDRAIL: present in case_input -> never a candidate fabrication.
        self.assertFalse(r["candidate_fabrication"])

    def test_tool_takes_precedence_over_case_input(self):
        report = "ip 10.0.0.5"
        recs = provenance.provenance(
            report,
            tool_stdouts={"t1": "fls listing shows 10.0.0.5"},
            case_input_text="case file also has 10.0.0.5",
        )
        r = _rec(recs, "10.0.0.5")
        self.assertEqual(r["source"], "tool:t1")  # tool wins
        self.assertTrue(r["in_case_input"])        # but input membership still recorded
        self.assertFalse(r["candidate_fabrication"])


# ---------------------------------------------------------------------------
# Required test 3 — IOC in NEITHER tools nor input -> flagged fabrication.
# ---------------------------------------------------------------------------
class TestIocInNeither(unittest.TestCase):
    def test_absent_from_both_is_candidate_fabrication(self):
        report = "Attacker also used 203.0.113.5 (asserted, unsupported)."
        recs = provenance.provenance(
            report,
            tool_stdouts={"t1": "no ips here", "t2": "nothing relevant"},
            case_input_text="case file has only 10.0.0.5",
        )
        r = _rec(recs, "203.0.113.5")
        self.assertIsNone(r["source"])
        self.assertFalse(r["in_case_input"])
        self.assertEqual(r["tool_sources"], [])
        self.assertTrue(r["candidate_fabrication"])

    def test_only_none_source_is_flagged(self):
        # Three IOCs: one from a tool, one from input, one from neither.
        report = "tool ip 1.1.1.1, input ip 2.2.2.2, ghost ip 3.3.3.3"
        recs = provenance.provenance(
            report,
            tool_stdouts={"t1": "scan saw 1.1.1.1"},
            case_input_text="the case file lists 2.2.2.2",
        )
        flagged = {r["ioc"] for r in recs if r["candidate_fabrication"]}
        self.assertEqual(flagged, {"3.3.3.3"})  # exactly the neither one


# ---------------------------------------------------------------------------
# Required test 4 — normalisation edges: hash case-insensitivity, IP exactness.
# Provenance must match across format variants (delegated to scorer normalisers).
# ---------------------------------------------------------------------------
class TestNormalisationEdges(unittest.TestCase):
    def test_hash_case_insensitive_match_to_tool(self):
        h = "aee4fcd9301c03b3b054623ca261959a"
        # Report has UPPER + 0x; tool stdout has lower. Must still attribute.
        report = f"MD5 0x{h.upper()}"
        recs = provenance.provenance(
            report, tool_stdouts={"t1": f"computed md5 {h}"}, case_input_text=""
        )
        r = _rec(recs, h)  # normalised to lower, 0x stripped
        self.assertEqual(r["source"], "tool:t1")
        self.assertFalse(r["candidate_fabrication"])

    def test_mac_separator_variant_matches(self):
        report = "MAC 00:10:A4:93:3E:09"
        recs = provenance.provenance(
            report, tool_stdouts={"t1": "iface 00-10-a4-93-3e-09"}, case_input_text=""
        )
        r = _rec(recs, "0010a4933e09")
        self.assertEqual(r["source"], "tool:t1")

    def test_ip_is_exact_no_near_miss(self):
        # 192.168.1.11 in tool stdout must NOT source 192.168.1.111 in report.
        report = "address 192.168.1.111"
        recs = provenance.provenance(
            report,
            tool_stdouts={"t1": "gateway 192.168.1.11 only"},
            case_input_text="",
        )
        r = _rec(recs, "192.168.1.111")
        self.assertIsNone(r["source"])               # no substring near-miss
        self.assertTrue(r["candidate_fabrication"])  # genuinely unsupported


# ---------------------------------------------------------------------------
# build_source_index — parallel, per-kind normalised sets.
# ---------------------------------------------------------------------------
class TestBuildSourceIndex(unittest.TestCase):
    def test_index_is_parallel_and_normalised(self):
        idx = provenance.build_source_index(["ip 8.8.8.8", "md5 ABCDEF" + "0" * 26])
        self.assertEqual(len(idx), 2)
        self.assertIn("8.8.8.8", idx[0]["ipv4"])
        self.assertIn("abcdef" + "0" * 26, idx[1]["hash"])  # lowercased

    def test_handles_none_and_empty_sources(self):
        idx = provenance.build_source_index([None, ""])  # type: ignore[list-item]
        self.assertEqual(idx[0]["ipv4"], set())
        self.assertEqual(idx[1]["hash"], set())


# ---------------------------------------------------------------------------
# provenance_summary — rollup counts for the root span.
# ---------------------------------------------------------------------------
class TestProvenanceSummary(unittest.TestCase):
    def test_summary_counts(self):
        report = "tool 1.1.1.1, input 2.2.2.2, ghost 3.3.3.3"
        recs = provenance.provenance(
            report,
            tool_stdouts={"t1": "saw 1.1.1.1"},
            case_input_text="lists 2.2.2.2",
        )
        s = provenance.provenance_summary(recs)
        self.assertEqual(s["iocs_total"], 3)
        self.assertEqual(s["iocs_from_tool"], 1)
        self.assertEqual(s["iocs_from_case_input"], 1)
        self.assertEqual(s["candidate_fabrication_count"], 1)
        self.assertEqual(
            s["candidate_fabrications"], [{"kind": "ipv4", "value": "3.3.3.3"}]
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
