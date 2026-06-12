# Evidence Inventory

Generated from `find /home/ubuntu/Downloads -type f -printf "%s\t%p\n"` and
`file(1)` per file on sift-vm (read-only). Total files: 43.

Feature mapping key:
- **memory-analysis**: `.raw/.mem/.vmem/.dmp/.lime`, or large files `file(1)` calls "data"
- **sleuthkit**: `.E01/.dd/.img`, anything `file(1)` identifies as a disk/partition image
- **windows-artifacts**: `.evtx`, `$MFT`, hives (`SAM/SYSTEM/SOFTWARE/SECURITY/NTUSER.DAT`), `.pf`, `.lnk`, jumplists
- **plaso-timeline**: any disk image or artifact directory (overlaps with sleuthkit)
- **yara-hunting**: any file tree (broadest scope)

---

## SRL-2015/

| File | Size | file(1) output | Artifact class | Feature(s) |
|------|------|----------------|----------------|------------|
| win2008R2-controller-10.3.58.4.zip | 17.5 GB | Zip archive data, store | Compressed VM (contents unknown) | TODO-human |
| win7-32-nromanoff-10.3.58.5.zip | 15.9 GB | Zip archive data, store | Compressed VM (contents unknown) | TODO-human |
| win7-64-nfury-10.3.58.6.zip | 14.3 GB | Zip archive data, store | Compressed VM (contents unknown) | TODO-human |
| xp-tdungan-10.3.58.7.zip | 12.1 GB | Zip archive data, store | Compressed VM (contents unknown) | TODO-human |

**File count:** 4 | **Total size:** ~59.7 GB | **Subdirectories:** none

**Artifact classes present (uncompressed/directly accessible):** none — all files are sealed ZIP archives with `store` compression. Names suggest Windows VM snapshots (Server 2008 R2, Win7 x86/x64, XP). Contents (disk images, memory dumps) unconfirmed without extraction.

**Feature coverage:**
- memory-analysis: **ABSENT** (no uncompressed .raw/.mem/.vmem) — TODO-human: unzip and check for memory captures
- sleuthkit: **ABSENT** (no .E01/.dd/.img) — TODO-human: unzip and check for disk images
- windows-artifacts: **ABSENT** (no standalone .evtx/$MFT/hive/.pf/.lnk)
- plaso-timeline: **ABSENT** (no accessible disk image)
- yara-hunting: PRESENT — ZIP files are scannable; contents TBD

---

## SRL-2018/

### SRL-2018/SRL-2018/ (memory archives)

| File | Size | file(1) output | Artifact class | Feature(s) |
|------|------|----------------|----------------|------------|
| base-admin-memory.7z | 1.0 GB | 7-zip archive data, v0.4 | Compressed memory dump | memory-analysis |
| base-av-memory.7z | 2.1 GB | 7-zip archive data, v0.4 | Compressed memory dump | memory-analysis |
| base-dc-memory.7z | 0.8 GB | 7-zip archive data, v0.4 | Compressed memory dump | memory-analysis |
| base-elf-memory.7z | 0.7 GB | 7-zip archive data, v0.4 | Compressed memory dump | memory-analysis |
| base-file-memory.7z | 0.3 GB | 7-zip archive data, v0.4 | Compressed memory dump | memory-analysis |
| base-file-snapshot5.7z | 0.8 GB | 7-zip archive data, v0.4 | Compressed memory dump | memory-analysis |
| base-hunt-memory.7z | 1.1 GB | 7-zip archive data, v0.4 | Compressed memory dump | memory-analysis |
| base-mail-memory.7z | 2.7 GB | 7-zip archive data, v0.4 | Compressed memory dump | memory-analysis |
| base-rd-02-memory.7z | 0.9 GB | 7-zip archive data, v0.4 | Compressed memory dump | memory-analysis |
| base-rd-03-memory.7z | 0.9 GB | 7-zip archive data, v0.4 | Compressed memory dump | memory-analysis |
| base-rd-04-memory.7z | 1.0 GB | 7-zip archive data, v0.4 | Compressed memory dump | memory-analysis |
| base-rd-05-memory.7z | 0.5 GB | 7-zip archive data, v0.4 | Compressed memory dump | memory-analysis |
| base-rd-06-memory.7z | 0.6 GB | 7-zip archive data, v0.4 | Compressed memory dump | memory-analysis |
| base-rd01-memory.7z | 0.8 GB | 7-zip archive data, v0.4 | Compressed memory dump | memory-analysis |
| base-sp-memory.7z | 1.0 GB | 7-zip archive data, v0.4 | Compressed memory dump | memory-analysis |
| base-wkstn-01-mem.zip | 1.2 GB | Zip archive data, deflate | Compressed memory dump | memory-analysis |
| base-wkstn-01-memory.7z | 1.0 GB | 7-zip archive data, v0.4 | Compressed memory dump | memory-analysis |
| base-wkstn-02-memory.7z | 1.0 GB | 7-zip archive data, v0.4 | Compressed memory dump | memory-analysis |
| base-wkstn-03-memory.7z | 0.9 GB | 7-zip archive data, v0.4 | Compressed memory dump | memory-analysis |
| base-wkstn-04-memory.7z | 0.9 GB | 7-zip archive data, v0.4 | Compressed memory dump | memory-analysis |
| base-wkstn-05-memory.7z | 0.6 GB | 7-zip archive data, v0.4 | Compressed memory dump | memory-analysis |
| base-wkstn-06-memory.7z | 0.5 GB | 7-zip archive data, v0.4 | Compressed memory dump | memory-analysis |
| unkown/base-file-snapshot5.7z | 0.3 GB | 7-zip archive data, v0.4 | Compressed memory dump (duplicate) | memory-analysis |

### SRL-2018/ (disk images + log)

| File | Size | file(1) output | Artifact class | Feature(s) |
|------|------|----------------|----------------|------------|
| base-dc-cdrive.E01 | 11.5 GB | EWF/Expert Witness/EnCase image file format | Disk image (Windows C:) | sleuthkit, windows-artifacts, plaso-timeline |
| base-file-cdrive.E01 | 15.3 GB | EWF/Expert Witness/EnCase image file format | Disk image (Windows C:) | sleuthkit, windows-artifacts, plaso-timeline |
| base-rd-01-cdrive.E01 | 16.6 GB | EWF/Expert Witness/EnCase image file format | Disk image (Windows C:) | sleuthkit, windows-artifacts, plaso-timeline |
| base-rd-02-cdrive.E01 | 16.0 GB | EWF/Expert Witness/EnCase image file format | Disk image (Windows C:) | sleuthkit, windows-artifacts, plaso-timeline |
| base-wkstn-01-c-drive.E01 | 15.8 GB | EWF/Expert Witness/EnCase image file format | Disk image (Windows C:) | sleuthkit, windows-artifacts, plaso-timeline |
| base-wkstn-05-cdrive.E01 | 13.8 GB | EWF/Expert Witness/EnCase image file format | Disk image (Windows C:) | sleuthkit, windows-artifacts, plaso-timeline |
| dmz-ftp-cdrive.E01 | 11.9 GB | EWF/Expert Witness/EnCase image file format | Disk image (Windows C:) | sleuthkit, windows-artifacts, plaso-timeline |
| analysis/forensic_audit.log | 372 B | ASCII text | Audit log | — |

**File count:** 31 | **Total size:** ~123 GB

**Feature coverage:**
- memory-analysis: PRESENT — 22 compressed memory images (7z/zip); require extraction before vol3 analysis
- sleuthkit: PRESENT — 7 EWF disk images
- windows-artifacts: PRESENT — 7 EWF disk images (contain NTFS volumes with evtx, MFT, hives, prefetch)
- plaso-timeline: PRESENT — 7 EWF disk images
- yara-hunting: PRESENT — any of the above

---

## Standard-Forensic-Case-2/

| File | Size | file(1) output | Artifact class | Feature(s) |
|------|------|----------------|----------------|------------|
| VANKO.zip | 40.7 GB | Zip archive data, store | Compressed case (contents unknown) | TODO-human |
| Vanko Student Scenario_D01_01.docx | 23 KB | Microsoft Word 2007+ | Scenario document | — |

**File count:** 2 | **Total size:** ~40.7 GB

**Artifact classes present (directly accessible):** none — single sealed ZIP (store compression). Contents unconfirmed without extraction. The docx is a student scenario document.

**Feature coverage:**
- memory-analysis: **ABSENT** (no .raw/.mem/.vmem outside archive) — TODO-human: inspect VANKO.zip contents
- sleuthkit: **ABSENT** (no .E01/.dd/.img outside archive)
- windows-artifacts: **ABSENT** (no standalone .evtx/$MFT/hive/.pf/.lnk)
- plaso-timeline: **ABSENT** (no accessible disk image)
- yara-hunting: PRESENT — ZIP file is scannable

---

## Standard-Forensic_Case/

| File | Size | file(1) output | Artifact class | Feature(s) |
|------|------|----------------|----------------|------------|
| ROCBA-BACKGROUND.pptx | 38 MB | Microsoft PowerPoint 2007+ | Case briefing | — |
| Rocba-Memory.zip | 5.3 GB | Zip archive data, deflate | Compressed memory dump (outer wrapper) | memory-analysis |
| Rocba-Memory/Rocba-Memory.7z | 5.3 GB | 7-zip archive data, v0.4 | Compressed memory dump (inner) | memory-analysis |
| **Rocba-Memory/Rocba-Memory.raw** | **17.7 GB** | **data** | **Memory image (uncompressed) — see note** | **memory-analysis** |
| rocba-cdrive.e01 | 22.1 GB | EWF/Expert Witness/EnCase image file format | Disk image (Windows C:) | sleuthkit, windows-artifacts, plaso-timeline |
| analysis/forensic_audit.log | 31 B | ASCII text | Audit log | — |

**File count:** 6 | **Total size:** ~50.5 GB

**Note on Rocba-Memory.raw:** `file(1)` returns "data" (no recognised magic). At 17.7 GB, the size matches 16 GB RAM + metadata overhead typical of a full Windows memory capture. Path components ("Rocba-Memory/") strongly indicate memory. Classification: **memory-analysis**. TODO-human: confirm by running `vol.py windows.info` against this image before eval execution.

**Feature coverage:**
- memory-analysis: PRESENT — Rocba-Memory.raw (uncompressed, directly usable)
- sleuthkit: PRESENT — rocba-cdrive.e01 (EWF format confirmed)
- windows-artifacts: PRESENT — rocba-cdrive.e01 (contains NTFS volume)
- plaso-timeline: PRESENT — rocba-cdrive.e01
- yara-hunting: PRESENT — Rocba-Memory.raw and rocba-cdrive.e01

---

## Feature Coverage Summary

| Feature | Folders with artifacts | Best uncompressed artifact |
|---------|----------------------|---------------------------|
| memory-analysis | SRL-2018 (compressed), Standard-Forensic_Case (uncompressed) | `Standard-Forensic_Case/Rocba-Memory/Rocba-Memory.raw` |
| sleuthkit | SRL-2018, Standard-Forensic_Case | Any .E01 in SRL-2018 |
| windows-artifacts | SRL-2018 (via E01), Standard-Forensic_Case (via e01) | Any .E01 in SRL-2018 |
| plaso-timeline | SRL-2018, Standard-Forensic_Case | Any .E01 in SRL-2018 |
| yara-hunting | All four folders | Any accessible file tree |

**Folders with ZERO directly accessible artifacts for most features:** SRL-2015, Standard-Forensic-Case-2 (both limited to sealed archives). No feature has zero matching artifacts across all folders — the above two folders are absent-scenario targets only.

**TODO-human items:**
1. Confirm `Standard-Forensic_Case/Rocba-Memory/Rocba-Memory.raw` is a valid memory image (`vol.py windows.info`).
2. Inspect `SRL-2015/` ZIP contents — may contain disk images and/or memory dumps for future cases.
3. Inspect `Standard-Forensic-Case-2/VANKO.zip` contents — 40.7 GB store-compressed archive, contents unverified.
4. `SRL-2018/SRL-2018/unkown/base-file-snapshot5.7z` is a duplicate of `SRL-2018/SRL-2018/base-file-snapshot5.7z` (same filename, size 297 MB vs 812 MB — sizes differ, may be a partial copy). TODO-human: verify.
