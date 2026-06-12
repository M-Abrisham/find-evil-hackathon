#!/usr/bin/env python3
"""Unit tests for trace_enrich.registry — the deterministic tool->skill/phase map.

Run:
    python3 -m unittest trace_enrich.test_registry
    python3 -m unittest discover -s trace_enrich -p 'test_*.py'
"""

from __future__ import annotations

import os
import sys
import unittest

# Allow running both as a module ("python3 -m unittest trace_enrich.test_registry")
# and directly ("python3 trace_enrich/test_registry.py").
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:  # package-style import
    from trace_enrich import registry  # type: ignore
except Exception:  # pragma: no cover - fallback for direct/dir invocation
    import registry  # type: ignore


SH = registry.SHARED
UNK = registry.UNKNOWN
OTH = registry.OTHER


class TestSkillFor(unittest.TestCase):
    def test_sleuthkit_bare(self):
        for t in ("fls", "icat", "mmls", "fsstat", "ils", "blkls", "blkcat",
                  "tsk_recover", "mactime", "img_stat", "istat", "ffind",
                  "ewfinfo", "ewfverify", "ewfmount", "photorec"):
            self.assertEqual(registry.skill_for(t), "sleuthkit", t)

    def test_plaso_py_suffix(self):
        self.assertEqual(registry.skill_for("log2timeline.py"), "plaso-timeline")
        self.assertEqual(registry.skill_for("psort.py"), "plaso-timeline")
        self.assertEqual(registry.skill_for("pinfo.py"), "plaso-timeline")
        self.assertEqual(registry.skill_for("psteal.py"), "plaso-timeline")
        self.assertEqual(registry.skill_for("image_export.py"), "plaso-timeline")
        # bare (no suffix) still resolves
        self.assertEqual(registry.skill_for("log2timeline"), "plaso-timeline")

    def test_memory_vol_variants(self):
        self.assertEqual(registry.skill_for("vol.py"), "memory-analysis")
        self.assertEqual(registry.skill_for("/opt/volatility3-2.20.0/vol.py"),
                         "memory-analysis")
        self.assertEqual(registry.skill_for("volatility"), "memory-analysis")
        self.assertEqual(registry.skill_for("baseline.py"), "memory-analysis")
        self.assertEqual(registry.skill_for("/opt/memory-baseliner/baseline.py"),
                         "memory-analysis")

    def test_windows_ezt_dll_and_bare(self):
        # bare name, .dll path, and case variants all -> windows-artifacts
        self.assertEqual(registry.skill_for("EvtxECmd"), "windows-artifacts")
        self.assertEqual(
            registry.skill_for("/opt/zimmermantools/EvtxeCmd/EvtxECmd.dll"),
            "windows-artifacts",
        )
        self.assertEqual(
            registry.skill_for("/opt/zimmermantools/RECmd/RECmd.dll"),
            "windows-artifacts",
        )
        for t in ("PECmd", "AppCompatCacheParser", "AmcacheParser", "MFTECmd",
                  "JLECmd", "LECmd", "WxTCmd", "SBECmd", "RBCmd", "bstrings",
                  "SrumECmd", "SQLECmd"):
            self.assertEqual(registry.skill_for(t), "windows-artifacts", t)

    def test_windows_star_ecmd_pattern(self):
        # *ECmd family resolves regardless of the path it's invoked from
        self.assertEqual(registry.skill_for("MFTECmd.dll"), "windows-artifacts")
        self.assertEqual(registry.skill_for("SrumECmd.dll"), "windows-artifacts")

    def test_yara(self):
        self.assertEqual(registry.skill_for("yara"), "yara-hunting")
        self.assertEqual(registry.skill_for("yarac"), "yara-hunting")
        self.assertEqual(registry.skill_for("/usr/local/bin/yara"), "yara-hunting")

    def test_ambiguous_to_shared(self):
        for t in ("strings", "file", "exiftool", "bulk_extractor", "grep",
                  "cat", "ls", "mkdir", "cp", "find", "md5sum", "tee", "awk"):
            self.assertEqual(registry.skill_for(t), SH, t)

    def test_unknown_to_unknown(self):
        self.assertEqual(registry.skill_for("definitely_not_a_tool"), UNK)
        self.assertEqual(registry.skill_for(""), UNK)
        self.assertEqual(registry.skill_for("   "), UNK)


class TestPhaseFor(unittest.TestCase):
    def test_discovery(self):
        for t in ("fls", "mmls", "fsstat", "img_stat", "pinfo.py", "ewfinfo",
                  "ils", "log2timeline.py"):
            self.assertEqual(registry.phase_for(t), "discovery", t)

    def test_extract(self):
        for t in ("icat", "tsk_recover", "image_export.py", "blkls", "blkcat",
                  "photorec", "bulk_extractor"):
            self.assertEqual(registry.phase_for(t), "extract", t)

    def test_analyze(self):
        for t in ("vol.py", "yara", "EvtxECmd", "RECmd", "MFTECmd", "mactime",
                  "baseline.py", "bstrings"):
            self.assertEqual(registry.phase_for(t), "analyze", t)

    def test_report(self):
        for t in ("psort.py", "psteal.py", "generate_pdf_report.py",
                  "TimelineExplorer"):
            self.assertEqual(registry.phase_for(t), "report", t)

    def test_unknown_phase_is_other(self):
        self.assertEqual(registry.phase_for("definitely_not_a_tool"), OTH)
        self.assertEqual(registry.phase_for("grep"), OTH)  # shared, no phase
        self.assertEqual(registry.phase_for(""), OTH)

    def test_fls_bodyfile_still_discovery(self):
        # `fls -m /` is discovery as a tool even though it feeds a timeline.
        self.assertEqual(registry.phase_for("fls"), "discovery")


class TestSplitCommand(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(registry.split_command(""), [])
        self.assertEqual(registry.split_command("   "), [])

    def test_single_simple(self):
        self.assertEqual(registry.split_command("fls -r /mnt/ewf/ewf1"), ["fls"])

    def test_sudo_prefix(self):
        self.assertEqual(registry.split_command("sudo fls -r /mnt/ewf/ewf1"),
                         ["fls"])

    def test_sudo_flag_with_value(self):
        # sudo -u root <tool> must still reach the tool
        self.assertEqual(registry.split_command("sudo -u root mmls /img"),
                         ["mmls"])
        self.assertEqual(registry.split_command("sudo -E fsstat /img"),
                         ["fsstat"])

    def test_python3_prefix(self):
        self.assertEqual(
            registry.split_command("python3 /opt/volatility3-2.20.0/vol.py -f mem.img windows.pslist"),
            ["vol"],
        )

    def test_dotnet_prefix(self):
        self.assertEqual(
            registry.split_command(
                "dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll -d ./exports/evtx/"
            ),
            ["evtxecmd"],
        )

    def test_wine_prefix(self):
        self.assertEqual(
            registry.split_command(
                "wine /opt/zimmermantools/TimelineExplorer/TimelineExplorer.exe"
            ),
            ["timelineexplorer"],
        )

    def test_env_assignment_prefix(self):
        # leading VAR=value assignments are stripped
        self.assertEqual(
            registry.split_command("OFFSET=2048 sudo fls -o 2048 /img"),
            ["fls"],
        )

    def test_pipeline_pipe(self):
        self.assertEqual(
            registry.split_command("fls -r /img | grep evil | icat /img 5"),
            ["fls", "grep", "icat"],
        )

    def test_pipeline_and(self):
        self.assertEqual(
            registry.split_command("mmls /img && fsstat /img"),
            ["mmls", "fsstat"],
        )

    def test_pipeline_semicolon(self):
        self.assertEqual(
            registry.split_command("mkdir ./exports ; tsk_recover /img ./exports"),
            ["mkdir", "tsk_recover"],
        )

    def test_pipeline_or(self):
        self.assertEqual(
            registry.split_command("icat /img 11 > $J || icat /img 11-128-4 > $J"),
            ["icat", "icat"],
        )

    def test_compound_mixed(self):
        # fls | icat && yara  (the canonical example from the spec)
        self.assertEqual(
            registry.split_command("fls /img | icat /img 5 && yara rules.yar f"),
            ["fls", "icat", "yara"],
        )

    def test_command_substitution(self):
        # OFFSET=$(( 2048 * 512 )) — arithmetic has no tool; the surrounding
        # mount call is shared-but-real.
        toks = registry.split_command("OFFSET=$(( 2048 * 512 )) sudo mount -o ro /img /mnt")
        self.assertEqual(toks, ["mount"])

    def test_command_substitution_inner_tool(self):
        # $(fls ...) inner tool should surface as its own token
        toks = registry.split_command("diff <(fls /img | sort) baseline.txt")
        # fls and sort should appear; diff is the outer (unknown) tool
        self.assertIn("fls", toks)
        self.assertIn("sort", toks)

    def test_redirect_does_not_become_tool(self):
        toks = registry.split_command("fls -m / /img > ./analysis/bodyfile.txt")
        self.assertEqual(toks, ["fls"])


class TestToolsIn(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(
            registry.tools_in("sudo fls -r /mnt/ewf/ewf1"),
            [{"token": "fls", "skill": "sleuthkit", "phase": "discovery"}],
        )

    def test_compound_each_tagged(self):
        got = registry.tools_in(
            "fls /img | icat /img 5 && yara rules.yar f"
        )
        self.assertEqual(
            got,
            [
                {"token": "fls", "skill": "sleuthkit", "phase": "discovery"},
                {"token": "icat", "skill": "sleuthkit", "phase": "extract"},
                {"token": "yara", "skill": "yara-hunting", "phase": "analyze"},
            ],
        )

    def test_cross_skill_pipeline(self):
        # vol -> shared grep: skill changes, grep is shared/other
        got = registry.tools_in(
            "python3 /opt/volatility3-2.20.0/vol.py -f m.img windows.netscan | grep -v 127.0.0.1"
        )
        self.assertEqual(got[0]["skill"], "memory-analysis")
        self.assertEqual(got[0]["phase"], "analyze")
        self.assertEqual(got[1]["token"], "grep")
        self.assertEqual(got[1]["skill"], SH)
        self.assertEqual(got[1]["phase"], OTH)

    def test_dotnet_ezt_tagged(self):
        got = registry.tools_in(
            "dotnet /opt/zimmermantools/RECmd/RECmd.dll -f NTUSER.DAT --bn k.reb"
        )
        self.assertEqual(
            got,
            [{"token": "recmd", "skill": "windows-artifacts", "phase": "analyze"}],
        )

    def test_unknown_tool_in_pipeline(self):
        got = registry.tools_in("frobnicate /img | fls /img")
        self.assertEqual(got[0],
                         {"token": "frobnicate", "skill": UNK, "phase": OTH})
        self.assertEqual(got[1]["skill"], "sleuthkit")

    def test_empty_command(self):
        self.assertEqual(registry.tools_in(""), [])

    def test_plaso_report_phase(self):
        got = registry.tools_in(
            "psort.py -o l2tcsv -w out.csv case.plaso"
        )
        self.assertEqual(got[0]["skill"], "plaso-timeline")
        self.assertEqual(got[0]["phase"], "report")


class TestConsistency(unittest.TestCase):
    """Every tool that has a phase must also have a skill (no orphan phases),
    and every skill-mapped (non-shared) forensic tool should resolve cleanly."""

    def test_every_phase_token_has_skill(self):
        for tok in registry.TOOL_TO_PHASE:
            self.assertIn(tok, registry.TOOL_TO_SKILL,
                          f"{tok} has a phase but no skill mapping")

    def test_skill_values_are_valid(self):
        valid = set(registry.SKILLS) | {SH}
        for tok, skill in registry.TOOL_TO_SKILL.items():
            self.assertIn(skill, valid, f"{tok} -> {skill} not a valid skill")

    def test_phase_values_are_valid(self):
        valid = {"discovery", "extract", "analyze", "report"}
        for tok, phase in registry.TOOL_TO_PHASE.items():
            self.assertIn(phase, valid, f"{tok} -> {phase} not a valid phase")


if __name__ == "__main__":
    unittest.main(verbosity=2)
