"""Tests for keep_or_revert.py — decide() delegation, the REVERT executor, the CLI.

Run from inside scoring/:  python3 -m unittest test_keep_or_revert -v
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

import composite
import keep_or_revert as kor


HERE = os.path.dirname(os.path.abspath(__file__))


def base_agg():
    return {
        "cases": 2,
        "fabrication_count_total": 0,
        "findable_recall_micro": 1.0,
        "findable_found": 2,
        "findable_total": 2,
        "full_recall_micro": 1.0,
        "full_found": 2,
        "full_total": 2,
        "invalid_mitre_total": 0,
        "mitre_emitted_total": 0,
        "mitre_found": 1,
        "mitre_grounded_total": 0,
        "mitre_precision_micro": None,
        "mitre_recall_micro": 0.5,
        "mitre_total": 2,
        "verdicts_emitted": 1,
    }


def _playbook_text(version, category_id="cat_x", extra_steps=()):
    """A contract-shaped playbook: frontmatter with version + category_id, a Steps
    section, and a Tuning log section. ``extra_steps`` simulate appended tune steps."""
    steps = "\n".join(f"- step {s}" for s in extra_steps)
    if steps:
        steps = "\n" + steps
    return (
        "---\n"
        f"category_id: {category_id}\n"
        f"version: {version}\n"
        "---\n\n"
        "## Steps\n"
        "- step base{0}\n\n"
        "## Tuning log\n"
        "- 2026-06-15 | seed | initial\n"
    ).format(steps)


class _PbFixture:
    """A synthetic playbook tree mirroring tune_playbook.py's layout.

    <root>/pb.md                          live playbook at `version`
    <root>/versions/<cat>/v<old>.md       byte-for-byte pre-tune snapshot
    <root>/versions/<cat>/v<new>.diff      orphan to delete on revert
    <root>/versions/<cat>/v<new>.trace.json orphan to delete on revert
    """

    def __init__(self, root, category_id="cat_x"):
        self.root = root
        self.cat = category_id
        self.pb = os.path.join(root, "pb.md")
        self.versions = os.path.join(root, "versions")
        self.cat_dir = os.path.join(self.versions, category_id)
        os.makedirs(self.cat_dir, exist_ok=True)

    def tune(self, v_old, v_new, snapshot_steps=(), live_steps=None):
        """Write the snapshot v_old.md (pre-tune), the live pb.md at v_new (post-tune),
        and the v_new.diff / v_new.trace.json orphans."""
        snap_text = _playbook_text(v_old, self.cat, snapshot_steps)
        with open(os.path.join(self.cat_dir, f"v{v_old}.md"), "w", encoding="utf-8") as fh:
            fh.write(snap_text)
        if live_steps is None:
            live_steps = tuple(snapshot_steps) + (f"tuned-to-{v_new}",)
        live_text = _playbook_text(v_new, self.cat, live_steps)
        with open(self.pb, "w", encoding="utf-8") as fh:
            fh.write(live_text)
        with open(os.path.join(self.cat_dir, f"v{v_new}.diff"), "w", encoding="utf-8") as fh:
            fh.write(f"--- a/v{v_old}.md\n+++ b/v{v_new}.md\n+ tuned-to-{v_new}\n")
        with open(os.path.join(self.cat_dir, f"v{v_new}.trace.json"), "w", encoding="utf-8") as fh:
            json.dump({"v_new": v_new}, fh)
        return snap_text, live_text

    def snap(self, v):
        return os.path.join(self.cat_dir, f"v{v}.md")

    def diff(self, v):
        return os.path.join(self.cat_dir, f"v{v}.diff")

    def trace(self, v):
        return os.path.join(self.cat_dir, f"v{v}.trace.json")


class DecideDelegationTests(unittest.TestCase):
    def test_decide_matches_compare(self):
        b = base_agg()
        p = dict(b)
        p["mitre_recall_micro"] = 1.0
        p["mitre_found"] = 2
        self.assertEqual(kor.decide(b, p), composite.compare(b, p))

    def test_decide_keep_and_revert(self):
        b = base_agg()
        keep = dict(b); keep["mitre_recall_micro"] = 1.0
        rev = dict(b); rev["fabrication_count_total"] = 1
        self.assertEqual(kor.decide(b, keep)[0], "KEEP")
        self.assertEqual(kor.decide(b, rev)[0], "REVERT")


class RevertExecutorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="kor_revert_")
        self.fx = _PbFixture(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_snapshot_restore_byte_for_byte(self):
        snap_text, live_text = self.fx.tune(1, 2)
        self.assertNotEqual(snap_text, live_text)
        res = kor.revert(self.fx.pb)
        self.assertEqual(res["method"], "snapshot")
        with open(self.fx.pb, "r", encoding="utf-8") as fh:
            self.assertEqual(fh.read(), snap_text)  # byte-for-byte
        # orphans deleted
        self.assertFalse(os.path.exists(self.fx.diff(2)))
        self.assertFalse(os.path.exists(self.fx.trace(2)))
        # snapshot KEPT
        self.assertTrue(os.path.isfile(self.fx.snap(1)))

    def test_revert_is_idempotent(self):
        snap_text, _ = self.fx.tune(1, 2)
        kor.revert(self.fx.pb)
        # second revert: live version is now 1, snapshot would be v0.md (absent) => the
        # orphans for v2 are already gone; with no v0 snapshot and no git, it must HARD-FAIL
        # OR no-op. Per spec "idempotent (orphans already gone => no-op)" applies when the
        # restored state's snapshot is in place. Here the restored file is v1 (no v0
        # snapshot), so a second revert should hard-fail loudly rather than corrupt.
        with self.assertRaises(kor.RevertError):
            kor.revert(self.fx.pb, use_git_fallback=False)
        # file is unchanged by the failed attempt
        with open(self.fx.pb, "r", encoding="utf-8") as fh:
            self.assertEqual(fh.read(), snap_text)

    def test_idempotent_noop_when_orphans_already_gone(self):
        """If the snapshot is in place AND orphans already deleted, re-running revert is a
        clean no-op (restores the same bytes, deletes nothing)."""
        snap_text, _ = self.fx.tune(1, 2)
        kor.revert(self.fx.pb)            # now pb==v1, orphans gone
        # Re-create the v1 snapshot scenario: pretend we are at v2 again but orphans gone.
        # Simulate by re-tuning then deleting orphans before the second revert.
        self.fx.tune(1, 2)
        os.remove(self.fx.diff(2))
        os.remove(self.fx.trace(2))
        res = kor.revert(self.fx.pb)
        self.assertEqual(res["orphans_deleted"], [])  # nothing to delete
        with open(self.fx.pb, "r", encoding="utf-8") as fh:
            self.assertEqual(fh.read(), snap_text)

    def test_multi_tune_reverts_only_latest(self):
        """v1->v2->v3: a single revert restores v2 (not v1) and clears ONLY v3 orphans."""
        # build v1 snapshot, v2 snapshot, live v3 + v3 orphans
        self.fx.tune(1, 2)                       # writes v1.md snapshot + (transient v2)
        v2_text, v3_text = self.fx.tune(2, 3, snapshot_steps=("tuned-to-2",))
        # v2 orphans (diff/trace) may exist from the first tune; that's fine.
        res = kor.revert(self.fx.pb)
        self.assertEqual(res["v_restored"], 2)
        with open(self.fx.pb, "r", encoding="utf-8") as fh:
            self.assertEqual(fh.read(), v2_text)   # restored to v2, NOT v1
        self.assertFalse(os.path.exists(self.fx.diff(3)))
        self.assertFalse(os.path.exists(self.fx.trace(3)))
        # v1 snapshot still present (we only reverted the latest)
        self.assertTrue(os.path.isfile(self.fx.snap(1)))

    def test_category_resolves_from_attack_type(self):
        """When category_id is absent, attack_type drives the versions/<cat> dir."""
        cat = "phishing"
        cat_dir = os.path.join(self.fx.versions, cat)
        os.makedirs(cat_dir, exist_ok=True)
        snap_text = (
            "---\nattack_type: phishing\nversion: 1\n---\n\n## Steps\n- s\n"
        )
        with open(os.path.join(cat_dir, "v1.md"), "w", encoding="utf-8") as fh:
            fh.write(snap_text)
        live_text = (
            "---\nattack_type: phishing\nversion: 2\n---\n\n## Steps\n- s\n- t\n"
        )
        with open(self.fx.pb, "w", encoding="utf-8") as fh:
            fh.write(live_text)
        with open(os.path.join(cat_dir, "v2.diff"), "w") as fh:
            fh.write("x")
        with open(os.path.join(cat_dir, "v2.trace.json"), "w") as fh:
            fh.write("{}")
        res = kor.revert(self.fx.pb)
        self.assertEqual(res["category_id"], cat)
        with open(self.fx.pb, "r", encoding="utf-8") as fh:
            self.assertEqual(fh.read(), snap_text)

    def test_missing_snapshot_no_git_hard_fails(self):
        """Snapshot missing + git fallback off => HARD-FAIL, file untouched (never half-revert)."""
        live_text = _playbook_text(2, self.fx.cat, ("tuned-to-2",))
        with open(self.fx.pb, "w", encoding="utf-8") as fh:
            fh.write(live_text)
        # no v1.md snapshot written
        with self.assertRaises(kor.RevertError):
            kor.revert(self.fx.pb, use_git_fallback=False)
        with open(self.fx.pb, "r", encoding="utf-8") as fh:
            self.assertEqual(fh.read(), live_text)  # untouched

    def test_no_version_hard_fails(self):
        with open(self.fx.pb, "w", encoding="utf-8") as fh:
            fh.write("---\ncategory_id: x\n---\n\n## Steps\n- s\n")
        with self.assertRaises(kor.RevertError):
            kor.revert(self.fx.pb)

    def test_corrupt_empty_snapshot_no_git_hard_fails(self):
        """A zero-byte snapshot is treated as corrupt -> fallback/hard-fail, not restored."""
        self.fx.tune(1, 2)
        open(self.fx.snap(1), "w").close()  # truncate snapshot to 0 bytes
        with open(self.fx.pb, "r", encoding="utf-8") as fh:
            live_before = fh.read()
        with self.assertRaises(kor.RevertError):
            kor.revert(self.fx.pb, use_git_fallback=False)
        with open(self.fx.pb, "r", encoding="utf-8") as fh:
            self.assertEqual(fh.read(), live_before)

    def test_git_fallback_restores_when_snapshot_missing(self):
        """Snapshot missing but the file is git-tracked in a real work-tree => git restore."""
        repo = tempfile.mkdtemp(prefix="kor_git_")
        try:
            env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
                       GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
            subprocess.run(["git", "-C", repo, "init", "-q"], check=True, env=env)
            pb = os.path.join(repo, "pb.md")
            committed = _playbook_text(1, "cat_x", ())
            with open(pb, "w", encoding="utf-8") as fh:
                fh.write(committed)
            subprocess.run(["git", "-C", repo, "add", "pb.md"], check=True, env=env)
            subprocess.run(["git", "-C", repo, "commit", "-q", "-m", "v1"], check=True, env=env)
            # simulate a tune that bumped version to 2 but with NO snapshot present
            tuned = _playbook_text(2, "cat_x", ("tuned-to-2",))
            with open(pb, "w", encoding="utf-8") as fh:
                fh.write(tuned)
            res = kor.revert(pb)  # snapshot absent -> git fallback
            self.assertEqual(res["method"], "git")
            with open(pb, "r", encoding="utf-8") as fh:
                self.assertEqual(fh.read(), committed)
        finally:
            shutil.rmtree(repo, ignore_errors=True)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="kor_cli_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, name, obj):
        p = os.path.join(self.tmp, name)
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(obj, fh)
        return p

    def _run(self, args):
        return subprocess.run(
            [sys.executable, os.path.join(HERE, "keep_or_revert.py"), *args],
            capture_output=True, text=True, cwd=HERE,
        )

    def test_cli_keep_exit_zero(self):
        b = base_agg()
        p = dict(b); p["mitre_recall_micro"] = 1.0; p["mitre_found"] = 2
        bp = self._write("b.json", b); pp = self._write("p.json", p)
        r = self._run(["--baseline", f"@{bp}", "--post", f"@{pp}"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["decision"], "KEEP")

    def test_cli_revert_exit_nonzero(self):
        b = base_agg()
        p = dict(b); p["fabrication_count_total"] = 1
        bp = self._write("b.json", b); pp = self._write("p.json", p)
        r = self._run(["--baseline", f"@{bp}", "--post", f"@{pp}"])
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(json.loads(r.stdout)["decision"], "REVERT")

    def test_cli_apply_runs_revert(self):
        root = os.path.join(self.tmp, "pbtree")
        os.makedirs(root, exist_ok=True)
        fx = _PbFixture(root)
        snap_text, _ = fx.tune(1, 2)
        b = base_agg()
        p = dict(b); p["fabrication_count_total"] = 1  # REVERT
        bp = self._write("b.json", b); pp = self._write("p.json", p)
        r = self._run(["--baseline", f"@{bp}", "--post", f"@{pp}",
                       "--apply", "--playbook", fx.pb])
        self.assertNotEqual(r.returncode, 0)  # REVERT exit
        out = json.loads(r.stdout)
        self.assertEqual(out["decision"], "REVERT")
        self.assertEqual(out["revert"]["method"], "snapshot")
        with open(fx.pb, "r", encoding="utf-8") as fh:
            self.assertEqual(fh.read(), snap_text)


if __name__ == "__main__":
    unittest.main()
