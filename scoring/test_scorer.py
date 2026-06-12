#!/usr/bin/env python3
"""Tests for the deterministic IOC scorer.

Stdlib ``unittest`` only. Every fixture is synthetic (small inline strings) so
the suite is self-contained and never touches the real, gitignored case data.

Run:  python3 -m unittest test_scorer -v
"""

import unittest

import scorer


def gt(verdict="MALICE", ttps=None, iocs=None):
    return {"verdict": verdict, "mitre_ttps": ttps or [], "key_iocs": iocs or []}


def ioc(t, v):
    return {"type": t, "value": v}


class TestNormalisers(unittest.TestCase):
    def test_email_lowercase(self):
        self.assertEqual(scorer.normalize("email", "Mr.Evil@Yahoo.COM"), "mr.evil@yahoo.com")

    def test_hash_strips_0x_spaces_colons_and_lowercases(self):
        self.assertEqual(
            scorer.normalize("hash", "0xAEE4FCD9301C03B3B054623CA261959A"),
            "aee4fcd9301c03b3b054623ca261959a",
        )
        self.assertEqual(scorer.normalize("hash", "AE:E4:FC d9"), "aee4fcd9")

    def test_mac_strips_separators_and_lowercases(self):
        for form in ("00:10:A4:93:3E:09", "00-10-a4-93-3e-09", "0010.A493.3E09"):
            self.assertEqual(scorer.normalize("mac", form), "0010a4933e09")

    def test_ipv4_exact(self):
        self.assertEqual(scorer.normalize("ipv4", " 192.168.1.111 "), "192.168.1.111")

    def test_sid_uppercased(self):
        self.assertEqual(scorer.normalize("sid", "s-1-5-21-3"), "S-1-5-21-3")

    def test_path_backslash_to_slash_trailing_and_case(self):
        self.assertEqual(
            scorer.normalize("path", "C:\\Program Files\\mIRC\\"),
            "c:/program files/mirc",
        )


class TestExtractors(unittest.TestCase):
    def test_ipv4_octets_validated(self):
        self.assertIn("2.0.0.16", scorer.extract_tokens("Firefox 2.0.0.16 here", "ipv4"))
        self.assertEqual(scorer.extract_tokens("not an ip 999.1.1.1", "ipv4"), set())

    def test_hash_len_discrimination(self):
        md5 = "a" * 32
        sha1 = "b" * 40
        sha256 = "c" * 64
        toks = scorer.extract_tokens(f"{md5} {sha1} {sha256}", "hash")
        self.assertEqual(toks, {md5, sha1, sha256})

    def test_cidr_base_not_extracted_as_host_ip(self):
        text = "subnet 10.11.11.0/24 with hosts 10.11.11.128 and 10.11.11.129"
        self.assertEqual(scorer.extract_cidrs(text), ["10.11.11.0/24"])
        ips = scorer.extract_tokens(text, "ipv4")
        self.assertEqual(ips, {"10.11.11.128", "10.11.11.129"})
        self.assertNotIn("10.11.11.0", ips)  # base address is never a host token

    def test_mitre_parent_and_subtechnique_are_independent(self):
        toks = scorer.extract_mitre("see T1595.001 and T1040")
        self.assertEqual(toks, {"T1595.001", "T1040"})
        self.assertNotIn("T1595", toks)  # parent not implied by a sub-technique


# ---------------------------------------------------------------------------
# Required test 1 — findable IOC mentioned in report -> found (counts).
# ---------------------------------------------------------------------------
class TestFindableFound(unittest.TestCase):
    def test_findable_and_in_report_counts_toward_findable_recall(self):
        g = gt(iocs=[ioc("email", "a@b.com")])
        res = scorer.score_case("C", g, input_text="evidence a@b.com seen", report_text="report cites a@b.com")
        rec = res.iocs[0]
        self.assertTrue(rec.findable)
        self.assertTrue(rec.found_in_report)
        self.assertEqual(res.findable_recall, 1.0)
        self.assertEqual((res.found_findable, res.total_findable), (1, 1))


# ---------------------------------------------------------------------------
# Required test 2 — non-findable GT IOC appearing in report does NOT count
# toward findable_recall AND is flagged as fabrication.
# ---------------------------------------------------------------------------
class TestNonFindableInReport(unittest.TestCase):
    def test_not_counted_and_flagged_fabricated(self):
        g = gt(iocs=[ioc("email", "a@b.com"), ioc("ip_address", "9.9.9.9")])
        # input has only the email; report asserts BOTH the email and a disk-only IP.
        res = scorer.score_case(
            "C", g,
            input_text="evidence a@b.com only",
            report_text="report cites a@b.com and also 9.9.9.9",
        )
        ip_rec = next(r for r in res.iocs if r.type == "ip_address")
        self.assertFalse(ip_rec.findable)
        self.assertTrue(ip_rec.found_in_report)
        # 9.9.9.9 must NOT inflate the headline: denominator is the 1 findable email.
        self.assertEqual((res.found_findable, res.total_findable), (1, 1))
        self.assertEqual(res.findable_recall, 1.0)
        # ...and it IS flagged as fabricated.
        self.assertIn({"type": "ipv4", "value": "9.9.9.9"}, res.fabrications)
        self.assertEqual(res.fabrication_count, 1)
        # it still appears in the full-recall diagnostic (found 2 of 2 listed).
        self.assertEqual((res.found_total, res.total_iocs), (2, 2))


# ---------------------------------------------------------------------------
# Required test 3 — format variants pass (upper hash, dashed MAC, fwd-slash path).
# ---------------------------------------------------------------------------
class TestFormatVariants(unittest.TestCase):
    def test_uppercased_hash_matches(self):
        h = "aee4fcd9301c03b3b054623ca261959a"
        res = scorer.score_case("C", gt(iocs=[ioc("file_hash", h)]),
                                input_text=f"md5 {h}", report_text=f"MD5 {h.upper()}")
        self.assertTrue(res.iocs[0].found_in_report)

    def test_mac_with_dashes_matches(self):
        res = scorer.score_case("C", gt(iocs=[ioc("mac_address", "00:10:a4:93:3e:09")]),
                                input_text="mac 00:10:a4:93:3e:09",
                                report_text="MAC 00-10-A4-93-3E-09")
        self.assertTrue(res.iocs[0].found_in_report)

    def test_path_with_forward_slashes_matches(self):
        res = scorer.score_case("C", gt(iocs=[ioc("file_path", "C:\\Program Files\\mIRC\\mirc.ini")]),
                                input_text="file C:\\Program Files\\mIRC\\mirc.ini",
                                report_text="path C:/Program Files/mIRC/mirc.ini")
        self.assertTrue(res.iocs[0].found_in_report)


# ---------------------------------------------------------------------------
# Required test 4 — report asserts an IP not in the input -> flagged fabricated.
# Plus the CIDR base-address must NOT be flagged.
# ---------------------------------------------------------------------------
class TestFabrication(unittest.TestCase):
    def test_report_ip_absent_from_input_is_fabricated(self):
        fabs, cidrs = scorer.find_fabrications(
            report_text="exfil to 203.0.113.5 observed",
            input_text="only 10.0.0.5 appears here",
        )
        self.assertIn({"type": "ipv4", "value": "203.0.113.5"}, fabs)

    def test_cidr_base_is_not_a_fabrication(self):
        fabs, cidrs = scorer.find_fabrications(
            report_text="hosts sit on 10.11.11.0/24",
            input_text="host 10.11.11.128 and 10.11.11.129",
        )
        self.assertEqual([f for f in fabs if f["type"] == "ipv4"], [])  # no .0 host flagged
        self.assertEqual(cidrs[0]["value"], "10.11.11.0/24")
        self.assertEqual(cidrs[0]["covers_input_hosts"], ["10.11.11.128", "10.11.11.129"])

    def test_reformatted_present_token_is_not_fabricated(self):
        # An uppercased hash that IS in the input must not be flagged.
        h = "aee4fcd9301c03b3b054623ca261959a"
        fabs, _ = scorer.find_fabrications(report_text=f"MD5 {h.upper()}", input_text=f"md5 {h}")
        self.assertEqual(fabs, [])


# ---------------------------------------------------------------------------
# Required test 5 — verdict present / absent -> found / not_emitted.
# ---------------------------------------------------------------------------
class TestVerdict(unittest.TestCase):
    def test_verdict_present(self):
        self.assertEqual(scorer.verdict_status("Final verdict: MALICE.", "MALICE"), "found")
        self.assertEqual(scorer.verdict_status("we judge this malice", "MALICE"), "found")  # case-insensitive

    def test_verdict_absent_is_not_emitted(self):
        self.assertEqual(scorer.verdict_status("the activity is malicious", "MALICE"), "not_emitted")
        self.assertEqual(scorer.verdict_status("no categorical label here", "MALICE"), "not_emitted")


# ---------------------------------------------------------------------------
# username — fuzzy, diagnostic-only, never fabrication.
# ---------------------------------------------------------------------------
class TestUsername(unittest.TestCase):
    def test_username_fuzzy_diagnostic_only_not_in_findable_when_absent_from_input(self):
        g = gt(iocs=[ioc("username", "mrevil2000")])
        # not in input -> not findable; appears in report -> counts only in full-recall.
        res = scorer.score_case("C", g, input_text="no such name", report_text="alias mrevil2000")
        self.assertFalse(res.iocs[0].findable)
        self.assertTrue(res.iocs[0].found_in_report)
        self.assertIsNone(res.findable_recall)  # 0 findable -> headline is n/a
        self.assertEqual((res.found_total, res.total_iocs), (1, 1))
        # usernames are never fabrications (only email/hash/MAC/IPv4/SID are).
        self.assertEqual(res.fabrications, [])

    def test_username_token_boundary_anchored(self):
        # "mrevil" must not match inside "mrevilrulez".
        res = scorer.score_case("C", gt(iocs=[ioc("username", "mrevil")]),
                                input_text="x", report_text="nick mrevilrulez")
        self.assertFalse(res.iocs[0].found_in_report)


# ---------------------------------------------------------------------------
# MITRE recall over ground-truth technique ids.
# ---------------------------------------------------------------------------
class TestMitre(unittest.TestCase):
    def test_partial_recall(self):
        present, found, total = scorer.mitre_recall("we saw T1040 only", ["T1040", "T1595.001"])
        self.assertEqual((found, total), (1, 2))
        self.assertTrue(present["T1040"])
        self.assertFalse(present["T1595.001"])

    def test_zero_when_no_codes_in_report(self):
        present, found, total = scorer.mitre_recall("prose with no technique codes", ["T1048", "T1567"])
        self.assertEqual((found, total), (0, 2))


if __name__ == "__main__":
    unittest.main(verbosity=2)
