#!/usr/bin/env python3
"""Tests for the generic leak scanner.

Stdlib ``unittest`` only. EVERY fixture is FAKE/synthetic (small inline strings
and temp files) so the suite is self-contained and NEVER touches real answer keys
or real secrets (blind-isolation rule).

Run:  python3 -m unittest test_leak_scan -v
"""

import os
import tempfile
import unittest

import leak_scan as ls


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

class Args:
    """Minimal args object matching what run_scan expects."""
    def __init__(self, **kw):
        self.staged = False
        self.range = None
        self.files = None
        self.paths = []
        self.forbidden_file = None
        self.max_bytes = 5_000_000
        self.warn_rfc1918 = True
        self.format = "json"
        self.baseline = None
        self.root = None
        for k, v in kw.items():
            setattr(self, k, v)


def scan_text(content, fname="probe.txt", **argkw):
    """Write content to a temp dir, scan it via --files, return list[Finding]."""
    d = tempfile.mkdtemp()
    path = os.path.join(d, fname)
    os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(fname) else None
    mode = "wb" if isinstance(content, bytes) else "w"
    with open(path, mode) as fh:
        fh.write(content)
    lines = None
    head = ls.read_head(path)
    is_bin, _ = ls.sniff_binary(head)
    if not is_bin:
        lines = ls.read_lines(path)
    compiled = ls.compile_literals(argkw.get("literals", list(ls.DEFAULT_FORBIDDEN_LITERALS)))
    findings = ls.scan_unit(
        fname, path, size=os.path.getsize(path), head=head, lines=lines,
        is_binary=is_bin, compiled_literals=compiled,
        max_bytes=argkw.get("max_bytes", 5_000_000),
        warn_rfc1918=argkw.get("warn_rfc1918", True))
    return findings


def active(findings):
    return [f for f in findings if not f.suppressed]


def has_block(findings, check_id=None):
    for f in active(findings):
        if f.severity == ls.BLOCK and (check_id is None or f.check_id == check_id):
            return True
    return False


def has_any_finding(findings):
    return len(active(findings)) > 0


# ===========================================================================
# 1. SECRETS — POSITIVE (must BLOCK)
# ===========================================================================

class TestSecretsPositive(unittest.TestCase):
    def test_aws_akia(self):
        self.assertTrue(has_block(scan_text("key = AKIAIOSFODNN7EXAMPLE\n"),
                                  "secret.aws_akia"))

    def test_github_token(self):
        tok = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
        self.assertTrue(has_block(scan_text("token: %s\n" % tok), "secret.github"))

    def test_github_pat(self):
        tok = "github_pat_" + "A" * 30
        self.assertTrue(has_block(scan_text("%s\n" % tok), "secret.github"))

    def test_gitlab(self):
        self.assertTrue(has_block(scan_text(("glpat-" "ABCDabcd1234" "ABCDabcd\n")),
                                  "secret.gitlab"))

    def test_slack_token(self):
        self.assertTrue(has_block(scan_text("xoxb-1234567890-FAKEfake\n"),
                                  "secret.slack"))

    def test_slack_webhook(self):
        url = "https://hooks.slack.com/services/TFAKE000/BFAKE000/abcDEF123456"
        self.assertTrue(has_block(scan_text(url + "\n"), "secret.slack"))

    def test_google_api(self):
        tok = "AIza" + "Bc1" + "D" * 32
        self.assertTrue(has_block(scan_text(tok + "\n"), "secret.google_api"))

    def test_jwt(self):
        jwt = "eyJhbGciOiJIUzI1Niwfake.eyJzdWIiOiIxMjM0NTfake.SflKxwRJSMeKKF2QTfake"
        self.assertTrue(has_block(scan_text(jwt + "\n"), "secret.jwt"))

    def test_sk_braintrust(self):
        tok = "sk-" + "Ab12Cd34Ef56Gh78Ij90Kl12"
        self.assertTrue(has_block(scan_text("BT_API_KEY=%s\n" % tok)))

    def test_private_key_block(self):
        body = ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
                "b3BlbnNzaC1rZXktdjEAAAAfakefakefakefakefake\n"
                "-----END OPENSSH PRIVATE KEY-----\n")
        self.assertTrue(has_block(scan_text(body), "secret.private_key"))

    def test_assignment_random_value(self):
        self.assertTrue(has_block(scan_text('api_key="Xy7zQ2w9Lm4Vb8nR"\n'),
                                  "secret.assignment"))

    def test_dotenv_long_value(self):
        c = "SECRET_TOKEN=Zq9Xy7zQ2w9Lm4Vb8nR0Kp3Tj\n"
        self.assertTrue(has_block(scan_text(c, fname=".env"), "secret.dotenv"))

    def test_high_entropy_b64(self):
        # synthetic high-entropy base64 blob, not matched by structured checks
        blob = "dGhpc2lzYVZlcnlSYW5kb21CYXNlNjRTdHJpbmdXaXRoSGlnaEVudHJvcHk5OQ=="
        f = scan_text(blob + "\n")
        self.assertTrue(has_block(f, "secret.entropy"))


# ===========================================================================
# 1b. DE-OBFUSCATED / SPLIT SECRETS — POSITIVE (red-team regression lock)
# ===========================================================================
#
# A secret split across string literals must be caught by CONTENT, regardless of
# filename. These reproduce the red-team misses (block_split_secret.py,
# block_split_concat.py, block_concat_only.txt). All values are FAKE.

class TestDeobfuscatedSecrets(unittest.TestCase):
    def test_split_akia_via_var_concat(self):
        # full = key_part_1 + key_part_2  reassembles a valid FAKE AKIA key
        c = ('key_part_1 = "AKIAZZ"\n'
             'key_part_2 = "4FAKE7EXAMPLE9"\n'
             'full = key_part_1 + key_part_2\n')
        self.assertTrue(has_block(scan_text(c, fname="thing.py"),
                                  "secret.deobfuscated"))

    def test_split_akia_benign_filename(self):
        # IDENTICAL content under a benign filename must STILL block on content
        c = ('key_part_1 = "AKIAZZ"\n'
             'key_part_2 = "4FAKE7EXAMPLE9"\n'
             'full = key_part_1 + key_part_2\n')
        self.assertTrue(has_block(scan_text(c, fname="utils.py"),
                                  "secret.deobfuscated"))

    def test_same_line_concat_only(self):
        # the two-literal same-line / cross-var case in a plain .txt
        c = ('a = "AKIAZZ"\nb = "4FAKE7EXAMPLE9"\nc = a + b\n')
        self.assertTrue(has_block(scan_text(c, fname="note.txt"),
                                  "secret.deobfuscated"))

    def test_split_entropy_token_implicit_concat(self):
        # token = ( "Zk9x2Lm7" "Qp4Rt8Nv" "Wc3Yb6Hd" )  -> 24-char entropy >=4.0
        c = ('token = (\n    "Zk9x2Lm7"\n    "Qp4Rt8Nv"\n    "Wc3Yb6Hd"\n)\n')
        self.assertTrue(has_block(scan_text(c, fname="cfg.py"),
                                  "secret.deobfuscated"))

    def test_split_github_token(self):
        body = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
        c = ('p1 = "ghp_"\np2 = "%s"\ntok = p1 + p2\n' % body)
        self.assertTrue(has_block(scan_text(c, fname="auth.py"),
                                  "secret.deobfuscated"))

    # ---- FP traps: benign multi-literal concatenation must stay CLEAN ----
    def test_sql_multiline_concat_clean(self):
        c = ('query = (\n    "SELECT id, name "\n    "FROM users "\n'
             '    "WHERE active = 1"\n)\n')
        self.assertFalse(has_block(scan_text(c, fname="db.py")))

    def test_help_text_concat_clean(self):
        c = ('msg = (\n    "Usage: tool --input FILE "\n'
             '    "Run the scorer over a corpus "\n)\n')
        self.assertFalse(has_block(scan_text(c, fname="cli.py")))

    def test_i18n_message_concat_clean(self):
        c = ('GREETING = (\n  "Hello and welcome "\n  "to the application "\n)\n')
        self.assertFalse(has_block(scan_text(c, fname="messages.py")))

    def test_version_string_concat_clean(self):
        c = 'v = "1.2." "3-rc1"\n'
        self.assertFalse(has_block(scan_text(c, fname="version.py")))


# ===========================================================================
# 2. EVIDENCE — POSITIVE
# ===========================================================================

class TestEvidencePositive(unittest.TestCase):
    def test_disk_e01(self):
        self.assertTrue(has_block(scan_text("x\n", fname="image.E01"),
                                  "evidence.extension"))

    def test_mem_vmem(self):
        self.assertTrue(has_block(scan_text("x\n", fname="dump.vmem"),
                                  "evidence.extension"))

    def test_pcapng(self):
        self.assertTrue(has_block(scan_text("x\n", fname="capture.pcapng"),
                                  "evidence.extension"))

    def test_archived_evidence_stem(self):
        self.assertTrue(has_block(scan_text("x\n", fname="disk.dd.gz"),
                                  "evidence.extension"))

    def test_mislabeled_binary_nul(self):
        # named .txt but contains NUL bytes -> binary_content BLOCK
        data = b"hello\x00\x00\x00world\x00binary\x00garbage"
        self.assertTrue(has_block(scan_text(data, fname="notes.txt"),
                                  "evidence.binary_content"))

    def test_oversize(self):
        big = "A" * 100  # tiny content but we lower the threshold
        f = scan_text(big + "\n", max_bytes=10)
        self.assertTrue(has_block(f, "evidence.oversize"))


# ===========================================================================
# 3. FORBIDDEN PATHS — POSITIVE
# ===========================================================================

class TestForbiddenPathPositive(unittest.TestCase):
    def test_settings_local(self):
        self.assertTrue(has_block(scan_text("{}\n", fname="settings.local.json"),
                                  "forbidden_path.local_settings"))

    def test_bak(self):
        self.assertTrue(has_block(scan_text("x\n", fname="notes.bak"),
                                  "forbidden_path.backup"))

    def test_seed_files(self):
        self.assertTrue(has_block(scan_text("x\n", fname="seed_files/x.txt"),
                                  "forbidden_path.seed_files"))

    def test_secret_name(self):
        self.assertTrue(has_block(scan_text("k: v\n", fname="secrets.yaml"),
                                  "forbidden_path.secret_name"))

    def test_answer_key_name(self):
        self.assertTrue(has_block(scan_text("x\n", fname="solution_writeup.md"),
                                  "forbidden_path.answer_key"))

    def test_nested_git(self):
        self.assertTrue(has_block(scan_text("ref\n", fname="vendor/.git/HEAD"),
                                  "forbidden_path.nested_git"))


# ===========================================================================
# 4. ANSWER LEAK — POSITIVE (FAKE literal via --forbidden-file)
# ===========================================================================

class TestAnswerLeak(unittest.TestCase):
    def test_fake_forbidden_literal(self):
        # FAKE answer string — never a real answer key
        fake_answer = "FAKE-CASE-ANSWER-zztop-9000"
        content = "The report concluded with %s in the body.\n" % fake_answer
        f = scan_text(content, literals=[fake_answer])
        self.assertTrue(has_block(f, "answer_leak.literal"))

    def test_word_boundary_no_substring_fp(self):
        # literal 'admin' must NOT fire inside 'administrator'
        f = scan_text("the administrator account\n", literals=["admin"])
        self.assertFalse(has_block(f, "answer_leak.literal"))

    def test_too_short_literal_skipped(self):
        compiled = ls.compile_literals(["ab"])  # below MIN_LITERAL_LEN
        self.assertEqual(compiled, [])

    def test_answer_redacted(self):
        fake_answer = "FAKE-SECRET-FLAG-abcd1234"
        f = scan_text("flag: %s\n" % fake_answer, literals=[fake_answer])
        leak = [x for x in active(f) if x.check_id == "answer_leak.literal"]
        self.assertTrue(leak)
        self.assertNotIn(fake_answer, leak[0].redacted)


# ===========================================================================
# 4b. CASE-ANSWER DISCLOSURE — POSITIVE (red-team regression lock)
# ===========================================================================
#
# A report-style file that CO-LOCATES an attacker IP + malware name + a
# 64-hex "SHA256 answer" discloses the case answer and must BLOCK, even though
# each indicator alone is only WARN. All values are FAKE/synthetic.

FAKE_HEX64 = "ab12cd34" * 8  # 64 hex chars, FAKE


class TestCaseDisclosure(unittest.TestCase):
    def test_fake_incident_report_blocks(self):
        c = ("# Incident Report (SYNTHETIC)\n"
             "The attacker connected from 198.18.7.42 (fake public IP).\n"
             "Dropped malware: FakeRansom.exe (synthetic sample name).\n"
             "SHA256 answer: %s\n" % FAKE_HEX64)
        self.assertTrue(has_block(scan_text(c, fname="block_report.md"),
                                  "answer_leak.disclosure"))

    def test_hash_plus_answer_keyword_blocks(self):
        c = "The IOC for the attacker is %s\n" % FAKE_HEX64
        self.assertTrue(has_block(scan_text(c, fname="finding.md"),
                                  "answer_leak.disclosure"))

    def test_verdict_plus_binary_in_report_blocks(self):
        c = ("# Analysis Report\n"
             "Verdict: MALICE. The dropper Evil.exe was executed.\n")
        self.assertTrue(has_block(scan_text(c, fname="report.md"),
                                  "answer_leak.disclosure"))

    # ---- FP traps: legit docs must stay CLEAN ----
    def test_release_checksum_readme_clean(self):
        # a real release sha256 + the word 'hash' must NOT block
        c = "To verify, compare the sha256 hash: %s of the release tarball.\n" % ("a" * 64)
        self.assertFalse(has_block(scan_text(c, fname="README.md")))

    def test_plain_digest_note_clean(self):
        c = "The file digest is %s per the reproducible build.\n" % ("b" * 64)
        self.assertFalse(has_block(scan_text(c, fname="NOTES.md")))

    def test_empty_incident_template_clean(self):
        # report-named, strong vocab, but NO actual hash present
        c = ("# Incident Report\nAttacker IP: TBD\nMalware: TBD\nSHA256: TBD\n")
        self.assertFalse(has_block(scan_text(c, fname="report.md")))

    def test_verdict_prose_no_binary_clean(self):
        c = "The verdict is MALICE for this finding.\n"
        self.assertFalse(has_block(scan_text(c, fname="verdict.md")))

    def test_named_binary_table_no_cluster_clean(self):
        c = "| tool.exe | does x |\n| util.dll | does y |\n"
        self.assertFalse(has_block(scan_text(c, fname="tools.md")))

    def test_hash_constant_in_code_not_doc_clean(self):
        # a .py file is not doc-like: a SHA constant + 'hash' must not disclosure-block
        c = 'EXPECTED_SHA = "%s"  # expected hash\n' % ("a" * 64)
        self.assertFalse(has_block(scan_text(c, fname="test_x.py"),
                                   "answer_leak.disclosure"))


# ===========================================================================
# 5. INDICATORS — WARN behavior
# ===========================================================================

class TestIndicators(unittest.TestCase):
    def test_public_ip_warns_not_blocks(self):
        f = scan_text("connect to 8.8.4.4 now\n")
        self.assertFalse(has_block(f))
        self.assertTrue(any(x.check_id == "indicator.ipv4" and x.severity == ls.WARN
                            for x in active(f)))

    def test_rfc5737_doc_ip_excluded(self):
        f = scan_text("test host 203.0.113.5 here\n")
        self.assertFalse(any(x.check_id == "indicator.ipv4" for x in active(f)))

    def test_loopback_excluded(self):
        f = scan_text("127.0.0.1 localhost\n")
        self.assertFalse(any(x.check_id == "indicator.ipv4" for x in active(f)))

    def test_rfc1918_suppressed_with_flag(self):
        f = scan_text("gw 10.1.2.3\n", warn_rfc1918=False)
        self.assertFalse(any(x.check_id == "indicator.ipv4" for x in active(f)))

    def test_mac_warns(self):
        f = scan_text("mac 00:11:22:33:44:55\n")
        self.assertTrue(any(x.check_id == "indicator.mac" for x in active(f)))
        self.assertFalse(has_block(f))

    def test_archive_warn(self):
        f = scan_text("x\n", fname="bundle.zip")
        # a .zip writes 'x\n' which is not binary; path check fires WARN
        self.assertTrue(any(x.check_id == "indicator.archive" for x in active(f)))


# ===========================================================================
# 6. FALSE-POSITIVE TRAPS (must stay CLEAN — exit 0, often ZERO findings)
# ===========================================================================

class TestFalsePositiveTraps(unittest.TestCase):
    def test_verdict_vocab_clean(self):
        for w in ("MALICE", "NON_MALICE", "INCONCLUSIVE", "INSUFFICIENT_EVIDENCE"):
            f = scan_text("verdict: %s\n" % w)
            self.assertFalse(has_any_finding(f), "vocab %s should be clean" % w)

    def test_mitre_codes_clean(self):
        for code in ("T1040", "T1003.001"):
            f = scan_text("technique %s observed\n" % code)
            self.assertFalse(has_any_finding(f), "mitre %s should be clean" % code)

    def test_english_prose_clean(self):
        for s in ("password reset email", "the token bucket algorithm"):
            f = scan_text(s + "\n")
            self.assertFalse(has_block(f), "prose '%s' should not BLOCK" % s)

    def test_placeholder_secret_not_block(self):
        for s in ("secret: <value>\n", "password: changeme\n", "api_key: your_key_here\n"):
            f = scan_text(s)
            self.assertFalse(has_block(f), "placeholder '%s' should not BLOCK" % s.strip())

    def test_git_sha_line_not_block(self):
        sha = "a" * 40
        f = scan_text("commit %s\n" % sha)
        self.assertFalse(has_block(f))

    def test_uuid4_not_block(self):
        f = scan_text("id: 123e4567-e89b-42d3-a456-426614174000\n")
        self.assertFalse(has_block(f))

    def test_insufficient_evidence_entropy_below_threshold(self):
        # documented: INSUFFICIENT_EVIDENCE entropy ~3.21 < 4.0
        self.assertLess(ls.shannon("INSUFFICIENT_EVIDENCE"), 4.0)

    def test_aws_example_entropy_below_threshold(self):
        # documented: AKIAIOSFODNN7EXAMPLE entropy ~3.68 < 4.0 -> entropy MISSES it
        self.assertLess(ls.shannon("AKIAIOSFODNN7EXAMPLE"), 4.0)


# ===========================================================================
# Allowlist mechanisms (sec 6.1 / 6.2)
# ===========================================================================

class TestAllowlists(unittest.TestCase):
    def test_inline_allow_all(self):
        c = "key = AKIAIOSFODNN7EXAMPLE  # leak-scan: allow\n"
        d = tempfile.mkdtemp()
        path = os.path.join(d, "a.txt")
        with open(path, "w") as fh:
            fh.write(c)
        lines = ls.read_lines(path)
        findings = ls.scan_unit("a.txt", path, size=os.path.getsize(path),
                                head=ls.read_head(path), lines=lines, is_binary=False,
                                compiled_literals=[], max_bytes=5_000_000,
                                warn_rfc1918=True)
        ls.apply_allowlists(findings, lines, "a.txt", ls.IgnoreRules())
        self.assertFalse(has_block(findings))
        self.assertTrue(any(f.suppressed for f in findings))

    def test_inline_allow_scoped(self):
        # scope allows only aws_akia; a co-located github token would still block
        c = "k = AKIAIOSFODNN7EXAMPLE  # leak-scan: allow secret.aws_akia\n"
        d = tempfile.mkdtemp()
        path = os.path.join(d, "b.txt")
        with open(path, "w") as fh:
            fh.write(c)
        lines = ls.read_lines(path)
        findings = ls.scan_unit("b.txt", path, size=os.path.getsize(path),
                                head=ls.read_head(path), lines=lines, is_binary=False,
                                compiled_literals=[], max_bytes=5_000_000,
                                warn_rfc1918=True)
        ls.apply_allowlists(findings, lines, "b.txt", ls.IgnoreRules())
        akia = [f for f in findings if f.check_id == "secret.aws_akia"]
        self.assertTrue(akia and akia[0].suppressed)

    def test_leakscanignore_whole_file(self):
        rules = ls.IgnoreRules(whole_file=["dataset/answer_key_denylist.txt"])
        self.assertTrue(rules.file_ignored("dataset/answer_key_denylist.txt"))
        self.assertFalse(rules.file_ignored("dataset/other.txt"))

    def test_leakscanignore_scoped(self):
        rules = ls.IgnoreRules(scoped=[("fixtures/*", {"evidence.extension"})])
        self.assertIn("evidence.extension", rules.scoped_checks("fixtures/disk.E01"))
        self.assertEqual(set(), rules.scoped_checks("src/main.py"))


# ===========================================================================
# Denylist-file FP (sec 3 / 11): named like answer key but allowlisted
# ===========================================================================

class TestDenylistFileFP(unittest.TestCase):
    def test_answer_key_denylist_name_blocks_unless_allowlisted(self):
        # by NAME it trips answer_key rule
        f = scan_text("# header only, no answers\n", fname="answer_key_denylist.txt")
        self.assertTrue(has_block(f, "forbidden_path.answer_key"))
        # but the shipped ignore allowlists it by exact path
        rules = ls.IgnoreRules(whole_file=["dataset/answer_key_denylist.txt"])
        self.assertTrue(rules.file_ignored("dataset/answer_key_denylist.txt"))


# ===========================================================================
# Entropy fallback math (sec 1.11 validated thresholds)
# ===========================================================================

class TestEntropyMath(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(ls.shannon(""), 0.0)

    def test_high_entropy_b64_above_4(self):
        blob = "dGhpc2lzYVZlcnlSYW5kb21CYXNlNjRTdHJpbmdXaXRoSGlnaEVudHJvcHk5OQ"
        self.assertGreaterEqual(ls.shannon(blob), 4.0)

    def test_normal_english_token_below_4(self):
        # The entropy fallback only scans single delimited TOKENS, never whole
        # sentences. Documented grounded cases: a single English word/token and
        # the verdict vocab both sit below the 4.0 BLOCK threshold.
        for tok in ("INSUFFICIENT_EVIDENCE", "administrator", "configuration"):
            self.assertLess(ls.shannon(tok), 4.0, "%s should be < 4.0 bits/char" % tok)


# ===========================================================================
# Exit-code integration via report()
# ===========================================================================

class TestExitCodes(unittest.TestCase):
    def test_block_exits_1(self):
        f = scan_text("key = AKIAIOSFODNN7EXAMPLE\n")
        code = ls.report(f, 1, "text")
        self.assertEqual(code, 1)

    def test_clean_exits_0(self):
        f = scan_text("verdict: MALICE technique T1040\n")
        code = ls.report(f, 1, "text")
        self.assertEqual(code, 0)

    def test_warn_only_exits_0(self):
        f = scan_text("server 8.8.4.4\n")
        code = ls.report(f, 1, "text")
        self.assertEqual(code, 0)


# ===========================================================================
# FP CLASS 1 — entropy on PATH / ENV-IDENTIFIER / DOTTED-MODULE tokens
# ===========================================================================
#
# The entropy charset spans '/', '_', '-', so the greedy match joins path /
# identifier segments into one long token whose WHOLE-STRING entropy clears 4.0.
# Those structural tokens must NOT BLOCK; a genuine contiguous random run still
# must. (Reproduces the live-SUT FPs in install.sh + skills/*/SKILL.md.)

class TestEntropyPathFP(unittest.TestCase):
    def _entropy_block(self, content, fname="probe.txt"):
        return has_block(scan_text(content, fname=fname), "secret.entropy")

    # ---- path-shaped tokens: NO block ----
    def test_filesystem_path_clean(self):
        self.assertFalse(self._entropy_block(
            "dotnet /opt/zimmermantools/MFTECmd.dll\n", fname="SKILL.md"))

    def test_home_tilde_path_clean(self):
        self.assertFalse(self._entropy_block(
            "see ~/.claude/skills/plaso-timeline/SKILL.md for details\n",
            fname="SKILL.md"))

    def test_url_path_clean(self):
        self.assertFalse(self._entropy_block(
            "https://github.com/Neo23x0/signature-base\n", fname="SKILL.md"))

    def test_env_identifier_joined_path_clean(self):
        # the exact install.sh shape: $SCRIPT_DIR/global/... and $REPO_DIR/...
        c = ('if [[ -f "$SCRIPT_DIR/global/CLAUDE.md" ]]; then\n'
             'src="$REPO_DIR/analysis-scripts/generate_pdf_report.py"\n')
        self.assertFalse(self._entropy_block(c, fname="install.sh"))

    def test_evtx_channel_name_clean(self):
        self.assertFalse(self._entropy_block(
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager"
            "%4Operational.evtx\n", fname="SKILL.md"))

    # ---- ALLCAPS_UNDERSCORE env identifiers: NO block ----
    def test_env_identifier_token_clean(self):
        for tok in ("SCRIPT_DIR", "CLAUDE_DIR", "REPO_DIR",
                    "LONG_ENV_IDENTIFIER_NAME_HERE"):
            self.assertFalse(self._entropy_block(tok + "\n"),
                             "%s should not entropy-block" % tok)

    def test_env_identifier_helpers(self):
        self.assertTrue(ls._is_env_identifier("SCRIPT_DIR"))
        self.assertTrue(ls._is_env_identifier("CLAUDE_DIR"))
        self.assertFalse(ls._is_env_identifier("Zk9x2Lm7Qp4Rt8Nv"))

    # ---- dotted.module.paths: NO block ----
    def test_dotted_module_path_clean(self):
        self.assertFalse(self._entropy_block(
            "import volatility3.framework.plugins.windows.malfind.here\n",
            fname="x.py"))

    def test_dotted_module_helper(self):
        self.assertTrue(ls._is_dotted_module("a.b.c.d.e.f.module.path"))
        self.assertFalse(ls._is_dotted_module("/opt/foo/bar"))

    # ---- real secrets EMBEDDED in path-shaped tokens still BLOCK ----
    def test_real_secret_in_path_still_blocks(self):
        # a genuine high-entropy 20+ contiguous run sitting in a path is NOT
        # exempted by the structural guard.
        blob = "Zk9xQ2Lm7Wp4Rt8NvWc3Yb6HdAb12Cd34Ef"  # contiguous, entropy>=4
        self.assertTrue(self._entropy_block("/var/cache/%s\n" % blob))

    def test_high_entropy_blob_still_blocks(self):
        blob = "dGhpc2lzYVZlcnlSYW5kb21CYXNlNjRTdHJpbmdXaXRoSGlnaEVudHJvcHk5OQ"
        self.assertTrue(self._entropy_block(blob + "\n"))

    def test_structural_token_helper(self):
        self.assertTrue(ls._is_structural_token("REPO_DIR/analysis-scripts/gen"))
        self.assertTrue(ls._is_structural_token("/opt/zimmermantools/MFTECmd"))
        # a path that hides a real opaque run is NOT structural-exempt
        self.assertFalse(ls._is_structural_token(
            "/x/dGhpc2lzYVZlcnlSYW5kb21CYXNlNjRTdHJpbmc"))


# ===========================================================================
# FP CLASS 2 — textbook empty hashes + anti-hallucination RULE PROSE
# ===========================================================================
#
# The empty-file MD5/SHA1/SHA256 are textbook forensic constants (YARA-rule
# examples, teaching prose) and must be allowlisted. Disclosure must require a
# GENUINE case-specific value cluster, never generic prose or a lone textbook
# hash. (Reproduces the live-SUT FPs in skills/yara-hunting/ + memory-analysis/.)

EMPTY_MD5 = "d41d8cd98f00b204e9800998ecf8427e"
EMPTY_SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class TestEmptyHashAndProseFP(unittest.TestCase):
    def test_empty_hashes_allowlisted(self):
        for h in (EMPTY_MD5, EMPTY_SHA1, EMPTY_SHA256):
            self.assertTrue(ls._is_well_known_hash(h), "%s should be well-known" % h)
            self.assertTrue(ls._is_well_known_hash(h.upper()))

    def test_yara_rule_textbook_hashes_clean(self):
        # the exact yara-hunting SKILL.md shape: empty MD5 + empty SHA256 in a
        # YARA condition example, near the word 'hash' / 'malware'.
        c = ('rule Empty {\n'
             '  condition:\n'
             '    hash.md5(0, filesize) == "%s" or\n'
             '    hash.sha256(0, filesize) == "%s"\n'
             '}\n' % (EMPTY_MD5, EMPTY_SHA256))
        self.assertFalse(has_block(scan_text(c, fname="skills/yara-hunting/SKILL.md"),
                                   "answer_leak.disclosure"))

    def test_lone_textbook_hash_with_keyword_clean(self):
        # a lone empty/textbook hash next to an answer keyword must NOT disclose
        c = "The malware sample's MD5 is %s (empty-file hash).\n" % EMPTY_MD5
        self.assertFalse(has_block(scan_text(c, fname="finding.md"),
                                   "answer_leak.disclosure"))

    def test_anti_hallucination_prose_clean(self):
        # the memory-analysis SKILL.md anti-hallucination block: rule prose +
        # verdict vocab + generic OS/dual-use binaries + a benign test IP.
        c = ("### Evidentiary discipline (anti-hallucination)\n"
             "- Empty output is NOT a clean system. An empty result means "
             "INSUFFICIENT_EVIDENCE, not NON_MALICE.\n"
             "- Dual-use is presumed legitimate: powershell.exe, svchost.exe, "
             "wmic.exe, certutil.exe, net.exe, rundll32.exe.\n"
             "- A malfind hit is a LEAD, not MALICE.\n"
             "- Test connectivity with ping 8.8.8.8 before concluding.\n")
        # note the directory name contains 'analysis' (reportish) on purpose
        self.assertFalse(has_block(
            scan_text(c, fname="skills/memory-analysis/SKILL.md"),
            "answer_leak.disclosure"))

    def test_generic_binary_helpers(self):
        self.assertIsNone(ls._specific_named_binary(
            "svchost.exe net.exe certutil.exe powershell.exe"))
        self.assertEqual("FakeRansom.exe",
                         ls._specific_named_binary("dropped FakeRansom.exe"))

    def test_benign_public_ip_not_clustered(self):
        # 8.8.8.8 in prose must not count as a case-specific attacker IP
        finds = [ls._mk("x", 1, "indicator", "indicator.ipv4", ls.WARN,
                        "8.8.8.8 (public)", 7)]
        self.assertFalse(ls._has_case_specific_public_ip(finds))
        finds2 = [ls._mk("x", 1, "indicator", "indicator.ipv4", ls.WARN,
                         "198.18.7.42 (public)", 11)]
        self.assertTrue(ls._has_case_specific_public_ip(finds2))

    # ---- the must-BLOCK genuine cluster (textbook-exclusion must not regress) ----
    def test_genuine_case_hash_still_discloses(self):
        # a REAL (non-textbook) hash + answer keyword still BLOCKs
        real = "ab12cd34" * 8
        c = "The IOC for the attacker is %s\n" % real
        self.assertTrue(has_block(scan_text(c, fname="finding.md"),
                                  "answer_leak.disclosure"))

    def test_genuine_specific_binary_cluster_still_discloses(self):
        c = ("# Incident Report\nVerdict: MALICE. Dropper FakeRansom.exe from "
             "198.18.7.42.\n")
        self.assertTrue(has_block(scan_text(c, fname="report.md"),
                                  "answer_leak.disclosure"))


# ===========================================================================
# FP CLASS 3 — .leakscanignore exempts the scanner's OWN test fixtures
# ===========================================================================
#
# scripts/test_leak_scan.py and redteam/** contain FAKE secrets BY DESIGN, so a
# --staged/--root self-scan self-flags them. The shipped .leakscanignore whole-
# file exempts them.

class TestSelfFixtureExemption(unittest.TestCase):
    def test_test_file_whole_file_exempt(self):
        rules = ls.IgnoreRules(whole_file=["test_leak_scan.py", "redteam/**",
                                           "scripts/test_leak_scan.py",
                                           "scripts/redteam/**"])
        self.assertTrue(rules.file_ignored("test_leak_scan.py"))
        self.assertTrue(rules.file_ignored("scripts/test_leak_scan.py"))

    def test_redteam_dir_glob_exempt(self):
        rules = ls.IgnoreRules(whole_file=["redteam/**", "scripts/redteam/**"])
        self.assertTrue(rules.file_ignored("redteam/block_aws.txt"))
        self.assertTrue(rules.file_ignored("redteam/sub/deep_fixture.py"))
        self.assertTrue(rules.file_ignored("scripts/redteam/block_split_secret.py"))

    def test_non_fixture_not_exempt(self):
        rules = ls.IgnoreRules(whole_file=["test_leak_scan.py", "redteam/**"])
        # leak_scan.py itself must STILL be scanned (never blind the scanner)
        self.assertFalse(rules.file_ignored("leak_scan.py"))
        self.assertFalse(rules.file_ignored("scripts/leak_scan.py"))
        self.assertFalse(rules.file_ignored("src/app.py"))

    def test_load_ignore_parses_shipped_file(self):
        # write the shipped .leakscanignore body and confirm load_ignore reads it
        body = ("# comment\ntest_leak_scan.py\nredteam/**\n"
                "scripts/test_leak_scan.py\nscripts/redteam/**\n")
        d = tempfile.mkdtemp()
        with open(os.path.join(d, ".leakscanignore"), "w") as fh:
            fh.write(body)
        rules = ls.load_ignore(d)
        self.assertIn("test_leak_scan.py", rules.whole_file)
        self.assertIn("redteam/**", rules.whole_file)
        self.assertTrue(rules.file_ignored("redteam/block_aws.txt"))

    def test_fixture_with_fake_secret_exempted_end_to_end(self):
        # a fixture file that WOULD block (fake AWS key) is suppressed when its
        # path is whole-file ignored.
        d = tempfile.mkdtemp()
        sub = os.path.join(d, "redteam")
        os.makedirs(sub)
        fpath = os.path.join(sub, "block_aws.txt")
        with open(fpath, "w") as fh:
            fh.write("key = AKIAIOSFODNN7EXAMPLE\n")
        with open(os.path.join(d, ".leakscanignore"), "w") as fh:
            fh.write("redteam/**\n")

        class A(Args):
            pass
        a = A(files=[fpath], root=d, format="text")
        code = ls.run_scan(a)
        self.assertEqual(code, 0, "ignored fixture must not BLOCK (exit 0)")


if __name__ == "__main__":
    unittest.main()
