#!/usr/bin/env python3
"""Unit tests for ablation_runner.sh + the parity_check.py --expect N flag.

stdlib-only (unittest + subprocess + tempfile). SYNTHETIC fixtures ONLY — no real
cases, keys, ground-truth, or live ~/.claude is ever touched. Every external command
the runner shells out to (parity / make / run_batch / score / aggregate) is replaced
by a stub script the test writes into a tmpdir and injects via the ABLATE_*_CMD env
vars, so the lap runs with NO sudo, NO ssh, NO config mutation.

Run:  python3 -m unittest test_ablation_runner -v
"""
import json
import os
import pathlib
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest

HERE = pathlib.Path(__file__).resolve().parent
RUNNER = HERE / "ablation_runner.sh"
# parity_check.py is the canonical in-place file one dir up (eval/parity_check.py),
# patched with the --expect N flag; we keep NO duplicate copy in eval/diagnosis/.
PARITY = HERE.parent / "parity_check.py"
FIX = HERE / "fixtures"


def _write_exec(path: pathlib.Path, body: str) -> None:
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def run_parity_diff(before, after, expect=None):
    """Invoke the patched parity_check.py --diff [--expect N]; return (rc, stdout, stderr)."""
    cmd = ["python3", str(PARITY), "--diff", str(before), str(after)]
    if expect is not None:
        cmd += ["--expect", str(expect)]
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


class ParityExpectFlag(unittest.TestCase):
    """The NEW --expect N flag on parity_check.py --diff (Stage 4.2 group-ablation gate)."""

    def test_legacy_one_change_passes(self):
        # No --expect -> legacy <=1 rule. One artifact changed -> PASS.
        rc, out, err = run_parity_diff(FIX / "before.json", FIX / "after_one_change.json")
        self.assertEqual(rc, 0, err)
        self.assertIn("one-change-per-lap", out)
        d = json.loads(out.split("\n\n")[0])  # the JSON block precedes the summary line
        self.assertEqual(len(d["changed_artifacts"]), 1)

    def test_legacy_two_change_violates(self):
        # No --expect -> two artifacts changed -> legacy rule VIOLATED (rc 1).
        rc, out, err = run_parity_diff(FIX / "before.json", FIX / "after_two_change.json")
        self.assertEqual(rc, 1)
        self.assertIn("VIOLATED", out)

    def test_legacy_no_change_passes(self):
        # Legacy <=1 means 0 changes also passes (preserved behaviour).
        rc, out, err = run_parity_diff(FIX / "before.json", FIX / "after_no_change.json")
        self.assertEqual(rc, 0, err)

    def test_expect_1_exact_passes(self):
        rc, out, err = run_parity_diff(FIX / "before.json", FIX / "after_one_change.json", expect=1)
        self.assertEqual(rc, 0, err)
        self.assertIn("changed == 1", out)

    def test_expect_1_rejects_zero(self):
        # --expect 1 is EXACT: zero changes must now FAIL (legacy would have passed).
        rc, out, err = run_parity_diff(FIX / "before.json", FIX / "after_no_change.json", expect=1)
        self.assertEqual(rc, 1)
        self.assertIn("VIOLATED", out)

    def test_expect_2_group_ablation_passes(self):
        rc, out, err = run_parity_diff(FIX / "before.json", FIX / "after_two_change.json", expect=2)
        self.assertEqual(rc, 0, err)
        self.assertIn("changed == 2", out)

    def test_expect_2_rejects_one(self):
        rc, out, err = run_parity_diff(FIX / "before.json", FIX / "after_one_change.json", expect=2)
        self.assertEqual(rc, 1)

    def test_host_drift_hard_fails_regardless_of_expect(self):
        rc, out, err = run_parity_diff(FIX / "before.json", FIX / "after_host_drift.json", expect=1)
        self.assertEqual(rc, 1)
        self.assertIn("PARITY BROKEN", err)

    def test_version_drift_hard_fails(self):
        rc, out, err = run_parity_diff(FIX / "before.json", FIX / "after_version_drift.json", expect=1)
        self.assertEqual(rc, 1)
        self.assertIn("PARITY BROKEN", err)

    def test_negative_expect_rejected(self):
        rc, out, err = run_parity_diff(FIX / "before.json", FIX / "after_one_change.json", expect=-1)
        self.assertEqual(rc, 1)


class AblationLapHarness(unittest.TestCase):
    """Drive the real ablation_runner.sh with injected STUB tools (no sudo/ssh/config)."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="ablate-test-"))
        self.bin = self.tmp / "bin"; self.bin.mkdir()
        self.work = self.tmp / "work"
        # A toggle marker file: TOGGLE writes it, RESTORE removes it -> proves idempotent restore.
        self.toggle_marker = self.tmp / "toggle.applied"
        # state files the stubs touch, so assertions can confirm each step ran
        self.state = self.tmp / "state"; self.state.mkdir()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ---- stub factories ----------------------------------------------------
    def _parity_stub(self, after_fixture="after_one_change.json"):
        """A fake parity: --out copies a fixture as the snapshot; --diff delegates to the
        REAL patched parity_check.py over fixtures so the gate logic is genuinely exercised.
        Each distinct after_fixture gets its OWN stub file so overrides never collide with
        the eagerly-evaluated default."""
        body = textwrap.dedent("""\
            #!/usr/bin/env bash
            set -e
            if [ "$1" = "--out" ]; then
              OUT="$2"
              if [ ! -f "{state}/before_done" ]; then
                cp "{fix}/before.json" "$OUT"; touch "{state}/before_done"
              else
                cp "{fix}/{after}" "$OUT"; touch "{state}/after_done"
              fi
              echo "PARITY GATE OK (stub)"; exit 0
            fi
            if [ "$1" = "--diff" ]; then
              exec python3 "{parity}" "$@"
            fi
            echo "stub parity: unhandled $*" >&2; exit 9
            """).format(state=self.state, fix=FIX, after=after_fixture, parity=PARITY)
        p = self.bin / ("parity_%s.sh" % after_fixture.replace(".json", ""))
        _write_exec(p, body); return "bash %s" % p

    def _make_stub(self, fail=False):
        rc = 1 if fail else 0
        body = textwrap.dedent("""\
            #!/usr/bin/env bash
            echo "make stub: $*" >> "{state}/make.log"
            exit {rc}
            """).format(state=self.state, rc=rc)
        p = self.bin / ("make_%d.sh" % rc); _write_exec(p, body); return "bash %s" % p

    def _runner_stub(self, fail=False):
        rc = 1 if fail else 0
        body = textwrap.dedent("""\
            #!/usr/bin/env bash
            echo "run_batch stub: $*" >> "{state}/run_batch.log"
            exit {rc}
            """).format(state=self.state, rc=rc)
        p = self.bin / ("run_batch_%d.sh" % rc); _write_exec(p, body); return "bash %s" % p

    def _score_stub(self):
        # writes a synthetic per-round score JSON into ABLATE_SCORES_DIR
        body = textwrap.dedent("""\
            #!/usr/bin/env bash
            set -e
            mkdir -p "$ABLATE_SCORES_DIR"
            printf '{"case_id":"%s","headline":{"category_match":false}}' "$ABLATE_CASE_ID" \\
              > "$ABLATE_SCORES_DIR/${ABLATE_CASE_ID}_${ABLATE_ARM}_round-1.score.json"
            echo scored >> "$ABLATE_SCORES_DIR/scored.log"
            """)
        p = self.bin / "score.sh"; _write_exec(p, body); return "bash %s" % p

    def _aggregate_stub(self):
        # emulates aggregate_failures.py: reads --scores-dir, writes --out with arms f/n
        body = textwrap.dedent("""\
            #!/usr/bin/env bash
            set -e
            OUT=""; SD=""
            while [ $# -gt 0 ]; do case "$1" in
              --out) OUT="$2"; shift;; --scores-dir) SD="$2"; shift;; esac; shift; done
            N=$(ls "$SD"/*.score.json 2>/dev/null | wc -l)
            printf '{"arms":{"sift":{"f":1,"n":%s},"bare":{"f":1,"n":%s}}}\\n' "$N" "$N" > "$OUT"
            """)
        p = self.bin / "aggregate.sh"; _write_exec(p, body); return "bash %s" % p

    def _toggle_cmd(self):
        return "touch %s" % self.toggle_marker

    def _restore_cmd(self):
        return "rm -f %s" % self.toggle_marker

    def _base_env(self, **over):
        # NOTE: build defaults LAZILY so an override is never clobbered by an
        # eagerly-evaluated default writing the same stub file.
        env = dict(os.environ)
        env["ABLATE_PARITY_CMD"] = over.pop("parity") if "parity" in over else self._parity_stub()
        env["ABLATE_MAKE_CMD"] = over.pop("make") if "make" in over else self._make_stub()
        env["ABLATE_RUNNER_CMD"] = over.pop("runner") if "runner" in over else self._runner_stub()
        env["ABLATE_AGGREGATE_CMD"] = over.pop("aggregate") if "aggregate" in over else self._aggregate_stub()
        sc = over.pop("score") if "score" in over else self._score_stub()
        if sc is not None:
            env["ABLATE_SCORE_CMD"] = sc
        env.update(over)
        return env

    def _run(self, args, env):
        return subprocess.run(["bash", str(RUNNER), *args], capture_output=True, text=True, env=env)

    def _common_args(self, **kw):
        a = ["--rule", kw.get("rule", "R-DUALUSE-01"),
             "--case-id", kw.get("case", "synthetic-case-01"),
             "--case", kw.get("path", str(self.tmp / "fake-evidence")),
             "--toggle", self._toggle_cmd(),
             "--restore", self._restore_cmd(),
             "--lane", kw.get("lane", "contract"),
             "--arm", kw.get("arm", "both"),
             "--rounds", str(kw.get("rounds", 5)),
             "--workdir", str(self.work)]
        if "expect" in kw:
            a += ["--expect", str(kw["expect"])]
        if kw.get("dry_run"):
            a += ["--dry-run"]
        return a

    # ---- NORMAL: full clean lap (parity==1) --------------------------------
    def test_normal_clean_lap_full_pipeline(self):
        (self.tmp / "fake-evidence").mkdir()
        env = self._base_env()
        r = self._run(self._common_args(), env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("parity diff OK", r.stderr)
        self.assertTrue((self.state / "run_batch.log").exists())
        self.assertTrue((self.work / "scores" / "scored.log").exists())
        self.assertTrue((self.work / "aggregate.json").exists())
        agg = json.loads((self.work / "aggregate.json").read_text())
        self.assertIn("sift", agg["arms"])
        rec = json.loads((self.work / "lap.json").read_text())
        self.assertEqual(rec["rule"], "R-DUALUSE-01")
        self.assertEqual(rec["expect"], 1)
        self.assertFalse(rec["dry_run"])
        self.assertFalse(self.toggle_marker.exists(), "lane was not restored")

    # ---- EDGE: dry-run stops after parity gate, still restores -------------
    def test_dry_run_stops_after_parity_and_restores(self):
        env = self._base_env()
        r = self._run(self._common_args(dry_run=True), env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("DRY RUN", r.stderr)
        self.assertFalse((self.state / "run_batch.log").exists(), "dry-run must not run the sealed batch")
        self.assertFalse(self.toggle_marker.exists())
        rec = json.loads((self.work / "lap.json").read_text())
        self.assertTrue(rec["dry_run"])

    # ---- EDGE: group ablation --expect 2 with two changes ------------------
    def test_group_ablation_expect_2(self):
        (self.tmp / "fake-evidence").mkdir()
        env = self._base_env(parity=self._parity_stub(after_fixture="after_two_change.json"))
        r = self._run(self._common_args(expect=2, dry_run=True), env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("expected 2", r.stderr)

    # ---- FAILURE: parity --diff finds 2 changes but expect=1 -> ABORT ------
    def test_unexpected_second_change_aborts_and_restores(self):
        env = self._base_env(parity=self._parity_stub(after_fixture="after_two_change.json"))
        r = self._run(self._common_args(dry_run=True), env)  # default expect=1
        self.assertEqual(r.returncode, 1)
        self.assertIn("parity --diff FAILED", r.stderr)
        self.assertFalse(self.toggle_marker.exists(), "abort path must still restore the lane")

    # ---- FAILURE: host drift between snapshots -> ABORT --------------------
    def test_host_drift_aborts(self):
        env = self._base_env(parity=self._parity_stub(after_fixture="after_host_drift.json"))
        r = self._run(self._common_args(dry_run=True), env)
        self.assertEqual(r.returncode, 1)
        self.assertFalse(self.toggle_marker.exists())

    # ---- FAILURE: make/sync fails after toggle -> ABORT + restore ----------
    def test_make_sync_failure_aborts_and_restores(self):
        env = self._base_env(make=self._make_stub(fail=True))
        r = self._run(self._common_args(dry_run=True), env)
        self.assertEqual(r.returncode, 1)
        self.assertIn("make", r.stderr.lower())
        self.assertFalse(self.toggle_marker.exists(), "failed deploy must still restore the lane")

    # ---- FAILURE: missing required arg -------------------------------------
    def test_missing_toggle_arg_usage_error(self):
        env = self._base_env()
        r = subprocess.run(["bash", str(RUNNER), "--rule", "X", "--case-id", "Y"],
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 2)
        self.assertIn("missing --toggle", r.stderr)

    # ---- FAILURE: bad --lane value -----------------------------------------
    def test_bad_lane_rejected(self):
        env = self._base_env()
        r = self._run(["--rule", "X", "--case-id", "Y", "--toggle", "true", "--lane", "bogus",
                       "--workdir", str(self.work)], env)
        self.assertEqual(r.returncode, 1)
        self.assertIn("--lane must be", r.stderr)

    # ---- EDGE: aggregator absent (tool #1 not wired) -> warn, not crash ----
    def test_aggregator_absent_is_a_warning(self):
        (self.tmp / "fake-evidence").mkdir()
        env = self._base_env(aggregate="bash -c 'exit 127'")  # simulate missing aggregator
        r = self._run(self._common_args(), env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("aggregator returned nonzero", r.stderr)
        self.assertFalse(self.toggle_marker.exists())

    # ---- USE-CASE: realistic Branch-F confirmation, prose lane, with baseline delta
    def test_usecase_branch_f_confirmation_with_baseline_delta(self):
        """Realistic Stage-4 scenario: a SIFT-WORSE triage flag (Stage 1.6) pointed at the
        dual-use-presumed-legitimate clause. The operator REMOVES that one clause (prose lane
        -> make sync) and confirms via a clean single-artifact ablation whether the failure
        rate drops vs the recorded baseline."""
        (self.tmp / "fake-evidence").mkdir()
        baseline = self.tmp / "baseline_aggregate.json"
        baseline.write_text(json.dumps({"arms": {"sift": {"f": 12, "n": 20}, "bare": {"f": 4, "n": 20}}}))
        env = self._base_env()
        args = ["--rule", "R-VERDICT-DUALUSE-PRESUMED-LEGIT",
                "--case-id", "adversarial-malicious-looking-benign-07",
                "--case", str(self.tmp / "fake-evidence"),
                "--toggle", self._toggle_cmd(),
                "--restore", self._restore_cmd(),
                "--lane", "prose",            # prose bullet -> make sync only
                "--arm", "both",
                "--rounds", "20",             # DECISION tier
                "--baseline", str(baseline),
                "--workdir", str(self.work)]
        r = self._run(args, env)
        self.assertEqual(r.returncode, 0, r.stderr)
        # prose lane uses make sync (not render) — confirm via the make stub log
        make_log = (self.state / "make.log").read_text()
        self.assertIn("sync", make_log)
        self.assertNotIn("render", make_log)
        # the rate-delta report ran against the baseline
        self.assertIn("baseline 12/20", r.stderr)
        self.assertIn("KEEP iff", r.stderr)   # the Stage 4.3 decision reminder
        rec = json.loads((self.work / "lap.json").read_text())
        self.assertEqual(rec["lane"], "prose")
        self.assertEqual(rec["rounds"], 20)
        self.assertTrue(pathlib.Path(rec["parity_before"]).exists())
        self.assertTrue(pathlib.Path(rec["parity_diff"]).exists())
        self.assertFalse(self.toggle_marker.exists())


if __name__ == "__main__":
    unittest.main()
