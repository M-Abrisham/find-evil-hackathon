---
attack_type: windows-execution-artifacts
category_id: windows-execution-artifacts
name: Windows Artifacts — Execution & User Activity
description: prove what programs ran and what the user did (amcache, shimcache, prefetch, srum, lnk, jump lists, shellbags)
version: 1
os_coverage: [windows, linux, macos, cloud]
sub_types_covered: 8
sub_types:
  - Prefetch execution
  - Amcache program presence
  - ShimCache/AppCompat presence
  - SRUM resource usage
  - LNK/JumpLists file access
  - ShellBags folder access
  - RecycleBin deletions
  - UserAssist execution
validated_on: []
maturity: draft
variables:
  image_path:
    default: /cases/CASE/evidence/disk.E01
    derive: "Step 0 — first disk-evidence image (E01/dd/raw/vmdk) enumerated under the evidence directory named in the case brief"
  mount_root:
    default: /cases/CASE/mount
    derive: "Step 0 — directory where the file system is mounted READ-ONLY (or where icat-extracted artifacts land when mounting fails)"
  case_out:
    default: /cases/CASE/out
    derive: "Step 0 — writable case output directory from the case brief; Step 0 creates #{case_out}/receipts/ and #{case_out}/extracted/"
  ntfs_offset_sectors:
    default: 0
    derive: "Step 0 — start sector of the relevant partition from `mmls #{image_path}` (largest NTFS partition unless the brief says otherwise)"
  time_window:
    default: 1970-01-01..2099-12-31
    derive: "case brief if it names one; else first confirmed execution/access timestamp ±48h once a step pins one — then re-scope wide sweeps to it"
---

## In one line
Windows quietly keeps records of which programs ran and which files and folders a person opened — even after the program is deleted and the files are gone. This playbook reads those records to prove *what executed* and *what the user touched*, and when.

## Use this when (triggers)
- You need to prove a specific program (a tool, a malware sample, `cmd.exe`, an archiver) actually **ran** on this host — not just sat on disk.
- You need to show a user **opened a file or browsed a folder** — including files on a USB stick or network share that are no longer present.
- A binary is gone but you suspect it executed: ask "did it leave a Prefetch, Amcache, UserAssist, or SRUM trace?"
- You're scoping data theft / staging and need the *human-activity* layer (recent files, jump lists, shellbags, recycle bin) under one timeline.
- Another playbook found a suspicious path/hash and you need to answer "was it run, by whom, how often, and when first/last?"

## Quick path (the 90% case)
1. **Timeline-first.** Build a quick super-timeline of the execution/activity artifacts so the story is anchored before you commit to it: `log2timeline.py` with the prefetch/amcache/srum/winreg/lnk/recycle_bin parsers, then `psort.py -o l2tcsv` filtered to `#{time_window}`. (This is the mandatory timeline move; the close-gate invariant still applies in full afterward.)
2. **Prove execution.** Parse Prefetch with plaso `prefetch` (run count + first/last-run times) and UserAssist/BAM with `RECmd`. These are the two strongest "it RAN" sources on this box — Prefetch gives run *count* and *times*; UserAssist gives the user who ran it.
3. **Corroborate presence + scope.** `AmcacheParser` (binary on disk + SHA-1, presence only), `AppCompatCacheParser` (ShimCache presence/order), and plaso `srum` + `esedbexport` (per-app run + network bytes over ~30–60 days — great for exfil-by-app).
4. **Prove user activity.** `LECmd`/`JLECmd` (files opened, incl. removable/network targets + source host/VSN), `SBECmd` (folders browsed, incl. deleted/removable), `RBCmd` (what was deleted, original path + time).
5. **Pin who + when.** Tie each execution/access to a user profile and a clock, and confirm two sources agree before you call it a fact.

If Prefetch run-count + UserAssist + Amcache SHA-1 all name the same binary on one timeline → you've proven execution. Otherwise drop into the full Steps below.

## How it unfolds (the story)
Someone — an intruder on stolen credentials, an insider, or an automated payload — runs a program on a Windows host and uses the machine: opens files, plugs in a USB stick, browses folders, deletes evidence. Windows records all of this for its own performance/UX reasons (Prefetch to speed up launches, SRUM for resource metering, UserAssist/JumpLists/ShellBags/RecentDocs for the Start menu and Explorer). The actor usually does **not** clean these — they're obscure and spread across the file system and registry. Reading them reconstructs the execution-and-activity layer of the intrusion even when the binaries and files themselves are long gone.

## Theories to test (and how to rule each out)
| Theory (who / why) | If true, you'd find… | Rule it out if… |
|---|---|---|
| **External-targeted (hands-on intruder ran tooling)** — attacker executed recon/credential/archiver tools interactively | Prefetch run-counts for non-baseline tools (`*.pf` for tools never installed); UserAssist entries under a compromised account; SRUM network bytes for an unexpected process; LNK/JumpList opens of staged files | Only OS/installed-app Prefetch+UserAssist; no foreign binaries in Amcache; SRUM network profile matches the user's baseline |
| **External-commodity (malware auto-ran)** — a dropper executed once, no human steering | A single Prefetch with run-count 1 from `%TEMP%`/`\ProgramData\`/`\Users\Public\`; Amcache SHA-1 of an unknown PE; no interactive UserAssist for it | No `%TEMP%`/public-path execution artifact; the binary appears in Amcache but has no Prefetch/UserAssist run trace at all |
| **Insider (trusted user took data)** — a real account opened, copied, and deleted files | UserAssist of an archiver/file tool by the real user; LNK/JumpLists pointing at sensitive shares; ShellBags showing removable/network folders browsed; RecycleBin deletions of the originals; SRUM bytes to a sync client | No removable/network ShellBags or LNK; recent-file activity matches the user's normal duties; no archiver/exfil-tool execution |
| **Other-insider (compromised legit account)** — outsider driving a real user's profile | Same profile shows execution/activity at anomalous hours or from a tool the user never uses; LNK source host/VSN ≠ this machine | Activity hours, tools, and removable-media VSNs all match the genuine user's pattern |
| **Innocent / benign (NOT an attack)** — legitimate admin/IT or normal use produced the artifacts | Execution/activity all maps to installed software, scheduled maintenance, IT tooling, or the user's job; no foreign binary, no odd path, no removable exfil | A foreign binary from a temp/public path RAN (Prefetch run-count ≥1 + UserAssist/Amcache SHA-1) and touched sensitive data → benign cause refuted |

*(≥1 benign + ≥1 malicious, each actively refuted. Map every attacker type — insider · other-insider · external-commodity · external-targeted · supply-chain · innocent — before closing.)*

## Evidence → Tool → What it reveals (per OS)
| Evidence | SIFT tool | What it tells you *for this attack* | OS |
|---|---|---|---|
| Prefetch `*.pf` (`\Windows\Prefetch`) | plaso `prefetch` (log2timeline parser; **PECmd is absent on this box**) | Program **execution**: run count + up to last-8 run times + files/dirs it referenced → strongest "it ran, this often, at these times" | Windows |
| `Amcache.hve` | `AmcacheParser` | Binary **present on disk** + SHA-1 + PE compile time → identity/hashing (⚠ presence/inventory, **not** proof it executed) | Windows |
| ShimCache / AppCompatCache (SYSTEM hive) | `AppCompatCacheParser` | File **present on disk** with path/size/last-mod, in insertion order (⚠ NOT execution on Win8/10/11 — the execution bit was reliable only on XP/2003/Vista/7) | Windows |
| SRUM `SRUDB.dat` | plaso `srum` + `esedbexport` (**SrumECmd is absent on this box**) | Per-app **execution + network bytes** over ~30–60 days → which app ran and how much it sent/received (exfil-by-app) | Windows |
| LNK shortcuts `*.lnk` | `LECmd` | A **file was accessed**: target path, the source volume serial + host MAC, target MAC times (incl. removable/network media) | Windows |
| Jump Lists (`*.automaticDestinations-ms`) | `JLECmd` | Per-application **file-open history** and app usage (which app opened which file, repeatedly) | Windows |
| ShellBags (UsrClass.dat / NTUSER.DAT) | `SBECmd` | **Folders browsed** in Explorer — including ZIP, removable and deleted folders the user navigated | Windows |
| RecycleBin `$I` files | `RBCmd` | **Deletions**: original full path, size, and delete time → what the user/actor removed and when | Windows |
| Windows 10 Timeline `ActivitiesCache.db` | `WxTCmd` | App/file usage + focus duration (⚠ roaming — check the device field before claiming *local* execution) | Windows |
| UserAssist / BAM / DAM (NTUSER.DAT / SYSTEM) | `RECmd` (Kroll batch) / `rip.pl` | **Which user ran which GUI program**, and BAM/DAM last-run per executable → execution attributed to an account | Windows |
| RecentFileCache.bcf (Win7-era) | `RecentFileCacheParser` | **New-program execution** on pre-Amcache Windows 7 | Windows |
| `$MFT` (for path/inode + MACB of artifacts) | `MFTECmd` / `fls`/`istat` (TSK) | Locate/extract the hive & artifact files; MACB of `*.pf`/hives; $SI-vs-$FN timestomp on a suspect binary | Windows |
| Whole image / hive strings | `bstrings` / `srch_strings` | Indicator extraction (paths, GUIDs, URLs) when a structured parser drifts | Windows/Linux |
| Super-timeline | `log2timeline.py` + `psort.py` | One fused chronology of execution + user-activity artifacts | all |
| Linux execution/login records | `fls`/`mactime`, plaso `bash_history`/`utmp` | The Linux equivalent of "what ran / who logged in" (no Prefetch/registry on Linux — see Linux branch) | Linux |

*Every tool above is in the RUN-VERIFIED list. PECmd and SrumECmd are NOT — Prefetch and SRUM are covered by plaso here. macOS/cloud differences are in Cross-OS notes.*

## Step 0 — evidence inventory & access bootstrap

- n: 0
  tool: |
    ls -la "#{image_path}" | tee "#{case_out}/receipts/00.txt" && mmls "#{image_path}" | tee -a "#{case_out}/receipts/00.txt" ; fsstat -o #{ntfs_offset_sectors} "#{image_path}" 2>&1 | tee -a "#{case_out}/receipts/00.txt" ; mkdir -p "#{case_out}/receipts" "#{case_out}/extracted" ; ls "#{mount_root}" 2>&1 | tee -a "#{case_out}/receipts/00.txt"
  expect: every evidence file classified; #{image_path}, #{mount_root}, #{ntfs_offset_sectors}, #{case_out} bound; mmls shows an NTFS partition and read-only access to the file system is proven (mount listing or icat-extracted artifacts exist)
  check: |
    test -r "#{mount_root}" -o -n "$(ls "#{case_out}/extracted" 2>/dev/null)"
  falsify: evidence dir empty/unreadable, or no supported image format found, or no NTFS partition in mmls
  on_result: {expect_met: goto 1, falsify_met: STOP — report acquisition/access failure; pivot acquisition-custody, neither: try the icat-extract fallback (fls/icat the Prefetch dir + hives into #{case_out}/extracted) — if that also fails treat as falsify_met}
  emits: [key_artifacts]
  serves: [Prefetch execution, Amcache program presence, ShimCache/AppCompat presence, SRUM resource usage, LNK/JumpLists file access, ShellBags folder access, RecycleBin deletions, UserAssist execution]
  provenance: {receipt_id: 00, artifact: evidence directory listing, offset_or_row: full listing + mmls table, literal_cited: image filename + NTFS partition row}

## Steps (executable — decision-driven)

- n: 1
  precondition: "os == windows; test -r #{mount_root}"
  tool: |
    log2timeline.py --parsers "prefetch,amcache,srum,winreg,lnk,recycle_bin" "#{case_out}/exec.plaso" "#{mount_root}" 2>&1 | tee "#{case_out}/receipts/01.txt" && psort.py -o l2tcsv -w "#{case_out}/exec_timeline.csv" "#{case_out}/exec.plaso" 2>&1 | tee -a "#{case_out}/receipts/01.txt"
  expect: a fused CSV of execution + user-activity events; events cluster in #{time_window}; the suspect binary/file appears with a timestamp you can anchor the rest of the case to
  check: |
    test -s "#{case_out}/exec_timeline.csv" && grep -qiE "prefetch|amcache|srum|userassist|lnk|recycle" "#{case_out}/exec_timeline.csv"
  falsify: log2timeline parses zero execution/activity events (no Prefetch, Amcache, SRUM, registry, LNK, or RecycleBin entries anywhere)
  on_result: {expect_met: anchor #{time_window} to the earliest suspect event then goto 2, falsify_met: artifacts may be wiped or this is a non-Windows image — pivot disk-filesystem to confirm the FS then return, neither: re-run with pinfo.py to confirm which parsers fired; widen #{time_window} and re-psort}
  emits: [timeline_events]
  serves: [Prefetch execution, Amcache program presence, SRUM resource usage, LNK/JumpLists file access, RecycleBin deletions, UserAssist execution]
  provenance: {receipt_id: 01, artifact: super-timeline (plaso), offset_or_row: exec_timeline.csv rows in time_window, literal_cited: earliest suspect execution/activity row}

- n: 2
  precondition: "os == windows"
  tool: |
    log2timeline.py --parsers "prefetch" "#{case_out}/pf.plaso" "#{mount_root}" 2>&1 | tee "#{case_out}/receipts/02.txt" && psort.py -o l2tcsv -w "#{case_out}/prefetch.csv" "#{case_out}/pf.plaso" 2>&1 | tee -a "#{case_out}/receipts/02.txt"
  expect: one or more Prefetch entries for the suspect program with a run count >= 1 and a last-run time inside #{time_window}; referenced-files list shows what it touched — PROOF it executed
  check: |
    test -s "#{case_out}/prefetch.csv" && grep -qiE "\.pf|run count|prefetch" "#{case_out}/prefetch.csv"
  falsify: no Prefetch entry for the suspect binary (Prefetch disabled, on SSD-tuned/server SKU, or the .pf was deleted), or run count is 0
  on_result: {expect_met: execution PROVEN for that binary; record run-count + last-run then goto 3, falsify_met: do not conclude "never ran" from missing Prefetch — fall through to UserAssist/Amcache/SRUM (steps 3-6) before deciding; if all execution sources are empty pivot disk-filesystem to confirm the binary even exists, neither: extract the Prefetch dir with TSK (fls/icat into #{case_out}/extracted) and re-parse}
  emits: [key_artifacts, timeline_events]
  serves: [Prefetch execution]
  provenance: {receipt_id: 02, artifact: Prefetch *.pf, offset_or_row: prefetch.csv row for the binary, literal_cited: binary name + run count + last-run timestamp}

- n: 3
  precondition: "os == windows"
  tool: |
    dotnet /opt/zimmermantools/RECmd/RECmd.dll --bn /opt/zimmermantools/RECmd/BatchExamples/Kroll_Batch.reb -d "#{mount_root}" --csv "#{case_out}" --csvf userassist.csv 2>&1 | tee "#{case_out}/receipts/03.txt"
  expect: a UserAssist (and/or BAM/DAM) entry naming the suspect executable under a specific user profile, with a last-execution time and (UserAssist) a run counter — execution ATTRIBUTED to an account
  check: |
    test -s "#{case_out}/userassist.csv" && grep -qiE "userassist|bam|dam|run count|last.?executed" "#{case_out}/userassist.csv"
  falsify: no UserAssist/BAM/DAM row for the suspect binary under any profile (it ran as a service/non-interactively, or the NTUSER/SYSTEM hive is missing)
  on_result: {expect_met: bind the executing account into the case then goto 4, falsify_met: GUI/user-attributed execution not shown — corroborate execution from Prefetch (step 2) + Amcache SHA-1 (step 4); if a service ran it pivot windows-event-logs for 4688/7045, neither: replay registry transaction logs with rla then re-run RECmd or fall back to rip.pl -p userassist on the NTUSER hive}
  emits: [actor_accounts, key_artifacts]
  serves: [UserAssist execution]
  provenance: {receipt_id: 03, artifact: NTUSER.DAT (UserAssist) / SYSTEM (BAM/DAM), offset_or_row: userassist.csv row, literal_cited: user + executable path + last-run time}

- n: 4
  precondition: "os == windows"
  tool: |
    AmcacheParser -f "#{mount_root}/Windows/AppCompat/Programs/Amcache.hve" --csv "#{case_out}" --csvf amcache.csv 2>&1 | tee "#{case_out}/receipts/04.txt"
  expect: an Amcache entry for the suspect binary giving its SHA-1, full path, and PE compile time — a hashable identity to pivot through threat-intel and other modalities
  check: |
    test -s "#{case_out}/amcache.csv" && grep -qiE "sha1|sha-1|[0-9a-f]{40}" "#{case_out}/amcache.csv"
  falsify: the binary is absent from Amcache entirely (never present on disk under that path, or Amcache.hve missing)
  on_result: {expect_met: record the SHA-1 as a key IOC and pivot SELF to re-scope every artifact to that hash then goto 5, falsify_met: presence not shown in Amcache — rely on Prefetch (step 2) + ShimCache (step 5) and record the gap; do not treat absence as "the file never existed", neither: confirm the Amcache.hve path with fls; replay its transaction log with rla and re-parse}
  emits: [key_iocs, key_artifacts]
  serves: [Amcache program presence]
  provenance: {receipt_id: 04, artifact: Amcache.hve, offset_or_row: amcache.csv row, literal_cited: SHA-1 + executable path}

- n: 5
  precondition: "os == windows"
  tool: |
    AppCompatCacheParser -f "#{mount_root}/Windows/System32/config/SYSTEM" --csv "#{case_out}" --csvf shimcache.csv 2>&1 | tee "#{case_out}/receipts/05.txt"
  expect: a ShimCache (AppCompatCache) row for the suspect binary — path, last-modified, and insertion order — corroborating the file was present on disk
  check: |
    test -s "#{case_out}/shimcache.csv" && grep -qiE "appcompat|shimcache|last.?mod|cache.?entry" "#{case_out}/shimcache.csv"
  falsify: the binary is absent from ShimCache (SYSTEM hive missing, or the entry aged out)
  on_result: {expect_met: corroborate presence/order with Amcache (step 4) and the timeline (step 1) then goto 6, falsify_met: presence-via-ShimCache not shown — note that ShimCache is presence-only on Win8+ anyway; lean on Prefetch+Amcache then goto 6, neither: replay the SYSTEM transaction logs with rla then re-run AppCompatCacheParser}
  emits: [key_artifacts]
  serves: [ShimCache/AppCompat presence]
  provenance: {receipt_id: 05, artifact: ShimCache (SYSTEM hive AppCompatCache), offset_or_row: shimcache.csv row, literal_cited: binary path + last-modified}

- n: 6
  precondition: "os == windows"
  tool: |
    log2timeline.py --parsers "srum" "#{case_out}/srum.plaso" "#{mount_root}/Windows/System32/sru/SRUDB.dat" 2>&1 | tee "#{case_out}/receipts/06.txt" && psort.py -o l2tcsv -w "#{case_out}/srum.csv" "#{case_out}/srum.plaso" 2>&1 | tee -a "#{case_out}/receipts/06.txt" ; esedbexport -t "#{case_out}/extracted/srudb" "#{mount_root}/Windows/System32/sru/SRUDB.dat" 2>&1 | tee -a "#{case_out}/receipts/06.txt"
  expect: SRUM rows for the suspect application showing it ran and how many network bytes it sent/received over the recorded window — confirms execution AND flags exfil-by-app
  check: |
    test -s "#{case_out}/srum.csv" && grep -qiE "srum|network|bytes.?sent|bytes.?recv|application.?resource" "#{case_out}/srum.csv"
  falsify: no SRUM entry for the application (SRUDB.dat absent, SRUM disabled, or activity predates the ~30–60 day window)
  on_result: {expect_met: record per-app run + bytes; if bytes-sent is large pivot insider-threat-data-theft else goto 7, falsify_met: SRUM unavailable — execution still rests on Prefetch+UserAssist; record the SRUM gap and goto 7, neither: parse the esedbexport table dump under #{case_out}/extracted manually for the SruDbIdMapTable app id then re-check}
  emits: [exfil_or_encryption_facts, timeline_events]
  serves: [SRUM resource usage]
  provenance: {receipt_id: 06, artifact: SRUM SRUDB.dat, offset_or_row: srum.csv row for the app, literal_cited: app name + bytes-sent/recv + timestamp}

- n: 7
  precondition: "os == windows"
  tool: |
    LECmd -d "#{mount_root}/Users" --csv "#{case_out}" --csvf lnk.csv 2>&1 | tee "#{case_out}/receipts/07.txt" && JLECmd -d "#{mount_root}/Users" --csv "#{case_out}" --csvf jumplists.csv 2>&1 | tee -a "#{case_out}/receipts/07.txt"
  expect: LNK/JumpList entries showing files the user OPENED — target path, source volume serial number + host MAC (catches removable/network media) and target MAC times inside #{time_window}
  check: |
    test -s "#{case_out}/lnk.csv" && grep -qiE "target|local.?path|volume.?serial|\.lnk|jump" "#{case_out}/lnk.csv"
  falsify: no LNK/JumpList opens of sensitive/removable/network targets (only OS-default shortcuts), or no recent-file activity at all
  on_result: {expect_met: record the opened files + any foreign volume serial then goto 8, falsify_met: no file-access evidence here — fall through to ShellBags (step 8) and RecycleBin (step 9); if a removable volume serial appears pivot insider-threat-data-theft, neither: widen to all user profiles under #{mount_root} and re-run LECmd/JLECmd recursively}
  emits: [key_artifacts, timeline_events]
  serves: [LNK/JumpLists file access]
  provenance: {receipt_id: 07, artifact: LNK *.lnk / Jump Lists, offset_or_row: lnk.csv / jumplists.csv row, literal_cited: target path + volume serial + access time}

- n: 8
  precondition: "os == windows"
  tool: |
    SBECmd -d "#{mount_root}/Users" --csv "#{case_out}" --csvf shellbags.csv 2>&1 | tee "#{case_out}/receipts/08.txt"
  expect: ShellBags rows proving the user BROWSED specific folders — including removable drives, network shares, ZIP archives, and folders since deleted — with first/last interaction times
  check: |
    test -s "#{case_out}/shellbags.csv" && grep -qiE "shellbag|bagmru|absolute.?path|first.?interacted|last.?interacted" "#{case_out}/shellbags.csv"
  falsify: ShellBags show only default/profile folders — no removable, network, archive, or deleted-folder navigation
  on_result: {expect_met: record folder-knowledge (esp. removable/network paths) then goto 9, falsify_met: no anomalous folder access — note it and goto 9; benign-use theory gains weight, neither: parse both UsrClass.dat and NTUSER.DAT for every user with SBECmd -d and re-check}
  emits: [key_artifacts, timeline_events]
  serves: [ShellBags folder access]
  provenance: {receipt_id: 08, artifact: ShellBags (UsrClass.dat / NTUSER.DAT), offset_or_row: shellbags.csv row, literal_cited: folder absolute path + last-interacted time}

- n: 9
  precondition: "os == windows"
  tool: |
    RBCmd -d "#{mount_root}" --csv "#{case_out}" --csvf recyclebin.csv 2>&1 | tee "#{case_out}/receipts/09.txt"
  expect: RecycleBin $I entries listing files DELETED by a user — original full path, size, and delete time — naming what was removed (staged copies, tools, sensitive data) and when
  check: |
    test -s "#{case_out}/recyclebin.csv" && grep -qiE "deleted|original.?path|file.?size|\\\$I" "#{case_out}/recyclebin.csv"
  falsify: RecycleBin empty or holds only ordinary user clutter — no deletion of staged/sensitive/tooling files near #{time_window}
  on_result: {expect_met: record deletions as IOCs and cross them against the timeline then goto 10, falsify_met: no relevant deletions — note absence and goto 10; if the bin was emptied near #{time_window} treat the emptiness as an anti-forensics finding, neither: carve $I records from unallocated with the RecycleBin path under #{mount_root} and re-run RBCmd}
  emits: [key_iocs, timeline_events]
  serves: [RecycleBin deletions]
  provenance: {receipt_id: 09, artifact: RecycleBin $I, offset_or_row: recyclebin.csv row, literal_cited: original path + delete time}

- n: 10
  precondition: "os == windows"
  tool: |
    psort.py -o l2tcsv -w "#{case_out}/exec_story.csv" "#{case_out}/exec.plaso" 2>&1 | tee "#{case_out}/receipts/10.txt" && pinfo.py "#{case_out}/exec.plaso" 2>&1 | tee -a "#{case_out}/receipts/10.txt"
  expect: a single ordered story — presence (Amcache/ShimCache) → execution (Prefetch run-count + UserAssist) → resource/network use (SRUM) → file/folder activity (LNK/JumpList/ShellBags) → deletion (RecycleBin) — internally consistent across #{time_window}
  check: |
    test -s "#{case_out}/exec_story.csv" && grep -qiE "prefetch|userassist|amcache|srum|lnk|recycle" "#{case_out}/exec_story.csv"
  falsify: the ordering is impossible (e.g. file access before the program that opened it ran) OR there is an unexplained multi-hour gap that breaks the chain
  on_result: {expect_met: COMMIT the execution + user-activity conclusion with a confidence label and the two-source pairs satisfied, falsify_met: re-open the Theories table — a contradiction means a wrong assumption; pivot SELF with the corrected #{time_window}, neither: run pinfo.py to confirm every parser fired and re-filter the timeline then re-adjudicate}
  emits: [timeline_events]
  serves: [Prefetch execution, Amcache program presence, SRUM resource usage, LNK/JumpLists file access, ShellBags folder access, RecycleBin deletions, UserAssist execution]
  provenance: {receipt_id: 10, artifact: fused execution timeline (plaso), offset_or_row: exec_story.csv ordered rows, literal_cited: ordered presence→execution→activity→deletion chain}

## Linux branch (L1..Ln) — REQUIRED, numbered, same step shape
*The execution/user-activity registry artifacts (Prefetch, Amcache, ShimCache, SRUM, UserAssist, ShellBags, JumpLists, RecycleBin) are Windows-only — they do not exist on Linux. The branch still exists to machine-confirm the OS and route to the Linux-native equivalents.*

- n: L1
  precondition: "os == linux"
  tool: |
    fsstat -o #{ntfs_offset_sectors} "#{image_path}" 2>&1 | tee "#{case_out}/receipts/L01.txt" ; fls -o #{ntfs_offset_sectors} "#{image_path}" 2>&1 | grep -iE "etc|var|home" | tee -a "#{case_out}/receipts/L01.txt"
  expect: fsstat reports an ext/xfs file system (not NTFS) — confirms this is a Linux image, so the Windows execution artifacts genuinely do not apply here
  check: |
    grep -qiE "ext[234]|xfs|file system type" "#{case_out}/receipts/L01.txt"
  falsify: fsstat reports NTFS — this is NOT Linux; the Windows branch (steps 1-10) applies and this branch is inapplicable
  on_result: {expect_met: Windows-only artifacts confirmed absent because the FS is Linux; goto L2 for the Linux-native execution/activity equivalents, falsify_met: return to the Windows branch (step 1) — image is NTFS not Linux, neither: run disktype/img_stat to settle the FS family then re-check}
  emits: [key_artifacts]
  serves: [Prefetch execution]
  provenance: {receipt_id: L01, artifact: file system superblock, offset_or_row: fsstat header, literal_cited: "File System Type" line (ext/xfs vs NTFS)}

- n: L2
  precondition: "os == linux"
  tool: |
    log2timeline.py --parsers "bash_history,zsh_extended_history,utmp,syslog" "#{case_out}/linux_exec.plaso" "#{image_path}" 2>&1 | tee "#{case_out}/receipts/L02.txt" && psort.py -o l2tcsv -w "#{case_out}/linux_exec.csv" "#{case_out}/linux_exec.plaso" 2>&1 | tee -a "#{case_out}/receipts/L02.txt"
  expect: the Linux execution/user-activity equivalent — shell-history commands (what was run), utmp logins (who logged in), and syslog/sudo lines — clustered in #{time_window}, standing in for Windows Prefetch/UserAssist
  check: |
    test -s "#{case_out}/linux_exec.csv" && grep -qiE "bash_history|zsh|utmp|sudo|syslog|COMMAND" "#{case_out}/linux_exec.csv"
  falsify: no shell history, no utmp logins, and no syslog command/sudo lines — execution/activity layer is empty or wiped on this Linux image
  on_result: {expect_met: record the Linux execution/login evidence; corroborate with fls/mactime on each binary MACB, falsify_met: history/logs may be cleared — pivot linux-host-forensics for persistence/log-tamper analysis, neither: add the filestat/dpkg parsers and re-run log2timeline then re-check}
  emits: [timeline_events, actor_accounts]
  serves: [UserAssist execution]
  provenance: {receipt_id: L02, artifact: bash/zsh history + utmp + syslog, offset_or_row: linux_exec.csv rows, literal_cited: command line / login user + timestamp}

## Corroboration (two-source rule)
`required_sources: 2`
`pairs:`
- `[ Prefetch run-count + last-run (step 2) ↔ UserAssist/BAM execution (step 3) ]`
- `[ Amcache SHA-1 / path (step 4) ↔ ShimCache presence/order (step 5) ]`
- `[ Prefetch/UserAssist execution ↔ SRUM per-app run + bytes (step 6) ]`
- `[ LNK target + volume serial (step 7) ↔ ShellBags folder browsed (step 8) ]`
- `[ RecycleBin deleted original path (step 9) ↔ LNK/JumpList prior open of the same file (step 7) ]`
- `[ Any single execution artifact ↔ its position on the fused timeline (steps 1/10) ]`

One hit is a *lead*; promote to *fact* only when its paired source agrees.

## Don't get fooled (red flags & anti-forensics)
- **Amcache and ShimCache are PRESENCE, not EXECUTION** on modern Windows (post-Lagny; Win8/10/11). A hash in Amcache or a row in ShimCache means the file *was on disk*, not that it *ran*. Only Prefetch run-count, UserAssist/BAM, and SRUM prove execution here. Guard: never write "executed" off Amcache/ShimCache alone — require a run-count source.
- **No Prefetch ≠ never ran.** Prefetch is disabled on many servers and some SSD-tuned hosts, and a single `.pf` is trivially deleted. Guard: when Prefetch is empty, corroborate execution from UserAssist + SRUM before concluding, and record the absence as a finding.
- **Deleted/emptied artifact dirs are themselves findings.** An emptied Prefetch folder, a wiped UserAssist, an emptied RecycleBin right before `#{time_window}`, or a missing SRUDB.dat all point at anti-forensics — report the gap, don't read silence as innocence.
- **Timestomp on the binary.** A suspect executable's `$SI` times can be forged; compare `$SI` vs `$FN` with `istat`/`MFTECmd` and trust the harder-to-forge `$FN` and the Prefetch/timeline order over `$SI`.
- **WxT/Windows-Timeline roams.** `ActivitiesCache.db` can carry activity that happened on a *different* device synced to this account — check the device field before claiming local execution. `⚠️verify` any WxT-only claim.
- **LNK/ShellBags prove access/knowledge, not content.** A LNK proves a file was *opened* and a ShellBag proves a folder was *browsed* — neither proves the user read or took the contents. State the distinction.
- **Tool-output drift.** EZ Tools / plaso column headers shift across versions; a `check:` that greps a header can exit 2. Guard: on exit 2, adjudicate from the prose `expect`/`falsify` against the receipt and cap confidence at `inferred`.

## Failure modes
```
- mode: evidence-access failure — image won't mount / wrong offset / unsupported format
  guard: Step 0 fallback chain — ewfmount/loop-mount RO at offset=#{ntfs_offset_sectors}*512; if that fails, TSK fls/icat-extract the Prefetch dir + hives + SRUDB.dat into #{case_out}/extracted; record absence as a finding
- mode: primary-artifact-absent — Prefetch disabled/deleted, or SRUDB.dat/Amcache.hve missing
  guard: name the secondary source and use it (Prefetch→UserAssist+SRUM; Amcache→ShimCache+Prefetch); record the absence explicitly, never read it as "did not run"
- mode: tool-output drift — EZ Tools/plaso header or label changed so a check literal no longer matches (check exits 2)
  guard: adjudicate exit-2 from prose expect/falsify against the receipt, label the outcome `inferred`, never silently pass
- mode: registry hive dirty (pending transaction logs) so RECmd/AppCompatCacheParser parse stale/partial data
  guard: replay logs with rla into a clean hive first, then re-parse; or cross-check with rip.pl
- mode: PECmd/SrumECmd reflex — agent reaches for the EZ Tools Prefetch/SRUM parsers that are ABSENT on this box
  guard: Prefetch = plaso `prefetch`; SRUM = plaso `srum` + `esedbexport` — the reconcile gate blocks any tool: line naming PECmd/SrumECmd
```
Minimum set every playbook covers: evidence-access failure (Step 0 fallback chain) · primary-artifact-absent (absence recorded, secondary source named) · tool-output drift (`check` exits 2 → prose adjudication, never silent pass).

## Confidence labeling (observation → inference → conclusion)
- **confirmed:** direct receipt verbatim + ≥2 independent sources agree + no unrefuted counter — e.g. Prefetch run-count + UserAssist + Amcache SHA-1 all name one binary on one timeline → "it executed".
- **inferred:** grounded but single-source/interpretive (incl. every `check`-exit-2 adjudication) — e.g. Amcache presence alone, ShimCache alone, or a WxT roaming-suspect row → hedged + tagged `⚠️verify`.
- **insufficient_evidence:** precondition unmet (hive missing, Prefetch disabled, SRUDB absent) or sources conflict → abstain; state what's missing, do NOT guess.

<!-- BEGIN CLOSE-GATE INVARIANT — copy this block into every playbook VERBATIM, including these markers. Do not edit, summarize, or reflow; the linter byte-compares it against _TEMPLATE.md. -->
## Close-gate invariant (Done = may not be declared until ALL are true)
- [ ] **Per-modality sweep** — every modality PRESENT in the evidence was processed, and every ABSENT one was recorded as absent (absence is a finding): disk file system · memory · event logs · registry · email stores · browser profiles · cloud-sync clients.
- [ ] **Every IOC pivoted** — each hash, path, filename, IP/domain, account, extension, and mutex found was pivoted back through the other modalities and the timeline.
- [ ] **Timeline built** — a case timeline exists and the committed story is consistent with it (entry → action → impact ordering holds, no unexplained gaps).
- [ ] **Anti-forensics checked** — cleared logs, timestomp, gaps, emptied artifact dirs: each ruled out or recorded as a finding.
- [ ] **Every theory closed** — each row of "Theories to test" is refuted with a receipt or carried forward with a confidence label.

**Quick-path success does NOT waive the Done gate.** The quick path exists to find the thread fast; this gate exists to guarantee nothing present went unread. The quick path itself must include a timeline-first move before any story is committed.
<!-- END CLOSE-GATE INVARIANT -->

## Cross-OS notes
- **Windows:** the home turf — richest execution+activity density (Prefetch, Amcache, ShimCache, SRUM, UserAssist/BAM, LNK/JumpLists, ShellBags, RecycleBin, WxT). Remember PECmd/SrumECmd are absent here — Prefetch and SRUM run through plaso.
- **Linux:** see the numbered Linux branch — no registry/Prefetch/SRUM; "what ran" comes from shell history (plaso `bash_history`/`zsh_extended_history`), "who logged in" from utmp (plaso `utmp`), and binary MACB from fls/mactime.
- **macOS:** execution/usage equivalents are KnowledgeC.db (per-app usage/duration) and the unified logs — but on THIS box `mac_apt` is broken and there is no `.tracev3` parser, so KnowledgeC is reachable only via raw `sqlite3`/SQLECmd and unified logs not at all. `⚠️verify` any macOS execution claim; FSEvents/Spotlight/Safari do work via plaso. Treat macOS as a known gap, not "no activity."
- **Cloud:** "execution" has no on-disk artifact; the analogue is control-plane/audit logs (who invoked what) — out of scope for this artifact playbook; route to cloud-identity-saas or cloud-iaas-control-plane from exported logs.

## Real-case notes (non-obvious things to look for)
- **Prefetch's last-EIGHT run times are the high-signal field, not just "last run."** A `.pf` stores up to eight execution timestamps plus the total run count, so a single Prefetch file can show repeated use across days — enough to distinguish a one-shot dropper (count 1) from hands-on tooling (count many). Pull the full run-time list, not only the most-recent, when reconstructing operator activity. `[SANS FOR500 Prefetch guidance · high]`
- **UserAssist values are ROT13-encoded** — a raw hive read looks like garbage; the parser decodes the program name and run counter. If you ever grep a raw NTUSER.DAT for a program name and find nothing, that's expected — use `RECmd`/`rip.pl` (which decode it) before concluding the program is absent. `[SANS FOR500 / RegRipper userassist plugin · high]`
- **ShimCache/AppCompatCache stopped being an execution artifact after Windows 7.** The old "InsertFlag = executed" bit was reliable only on XP/2003/Vista/7; on Win8/10/11 a ShimCache row means the file was *present/last-modified*, full stop. Investigators citing the SANS poster's old "Program Execution" label for ShimCache on a Win10 host are over-claiming. `[Mandiant ShimCache research; matrix §A.1 caveat · high]`
- **Amcache lost its "execution" meaning too (post-Lagny).** Amcache.hve is a clean inventory of binaries+SHA-1+compile-time, but presence in it is NOT proof of execution on modern builds — it indexes files that were merely *present*. Its real power here is the SHA-1 for hash-pivoting, plus PE compile time. `[matrix §A.1 AmcacheParser caveat; community Amcache research · high]`
- **SRUM is the underused exfil witness.** SRUDB.dat keeps ~30–60 days of per-application bytes-sent/received and run time. An app that shouldn't talk to the network showing large bytes-sent in SRUM is a strong exfil-by-app lead even when packet capture is long gone — pivot it to insider-threat-data-theft. `[SANS FOR500 SRUM coverage; matrix §A.1 · high]`
- **LNK and JumpLists carry the SOURCE host's identity, not just the target.** A LNK embeds the volume serial number and (often) the NetBIOS/MAC of the machine where the target lived — so a shortcut on this host can prove a file was opened *from a USB stick or a different machine*, and tie removable media across hosts by VSN. `[SANS FOR500 LNK/JumpList analysis · high]`
- **ShellBags survive folder deletion.** Because ShellBags record Explorer *navigation*, a folder that was browsed and then deleted (or lived on a since-removed USB drive) still leaves a ShellBag entry — making them a way to prove knowledge of folders that no longer exist on the disk. `[SANS FOR500 ShellBags; matrix §A.1 · high]`

## ATT&CK mapping
- T1204 · Execution · User Execution (a user ran the program — UserAssist/Prefetch) — steps 2,3
- T1059 · Execution · Command and Scripting Interpreter (interpreter execution traces in Prefetch/Amcache) — steps 2,4
- T1057 · Discovery · Process Discovery (recon tooling identified via execution artifacts)
- T1083 · Discovery · File and Directory Discovery (folder browsing via ShellBags/LNK) — steps 7,8
- T1005 · Collection · Data from Local System (file opens/staging via LNK/JumpLists) — step 7
- T1074 · Collection · Data Staged (staged copies later deleted — RecycleBin) — step 9
- T1052 / T1091 · Exfiltration/Lateral · Exfil over / replication via removable media (foreign volume serial in LNK/ShellBags) — steps 7,8
- T1070.004 · Defense Evasion · File Deletion (emptied Prefetch/RecycleBin, deleted .pf) — steps 2,9
- T1070.006 · Defense Evasion · Timestomp (suspect-binary $SI vs $FN) — Don't get fooled
- T1012 · Discovery · Query Registry (execution/activity living in NTUSER/SYSTEM/UsrClass hives)

## Pivots (lead-to-lead graph)
- on_service_or_4688_execution: windows-event-logs — a service/non-interactive run shows in 4688/7045, not UserAssist
- on_persistence_run_key_or_service: windows-registry-persistence — an executed binary referenced by a Run key/Service
- on_foreign_volume_serial_or_large_srum_bytes: insider-threat-data-theft — removable-media open or exfil-by-app
- on_binary_hash_needs_triage: malware-analysis-triage — Amcache SHA-1 of an unknown PE to analyze
- on_browser_or_mail_activity: browser-email-documents — user-activity layer extends into downloads/phishing
- on_full_intrusion_reconstruction: attack-lifecycle-hunting — fold this execution layer into the whole ATT&CK timeline
- on_linux_image: linux-host-forensics — image proved non-Windows in the Linux branch
- on_new_ioc_rescope: SELF — a new hash/path/account/volume-serial re-enter with it bound into #{time_window}

## Jargon decoder
- **Prefetch (`.pf`):** files Windows writes to speed up program launches; each records how many times and (up to the last eight) when a program ran — **proof of execution**.
- **Amcache.hve:** a registry-style inventory of programs that were present on disk, with each binary's SHA-1 and PE compile time — **presence/identity, not proof it ran** on modern Windows.
- **ShimCache / AppCompatCache:** a list in the SYSTEM hive of executables seen on disk (path, last-modified, order) — **presence, not execution** on Win8+.
- **SRUM (SRUDB.dat):** the System Resource Usage Monitor database — per-application run time and network bytes over ~30–60 days; great for "which app sent how much data."
- **UserAssist:** an NTUSER.DAT record (ROT13-encoded) of GUI programs a specific user ran, with a counter and last-run time — **execution attributed to a user**.
- **BAM / DAM:** Background/Desktop Activity Moderator keys recording last-run-per-executable — another execution source.
- **LNK / shortcut:** a `.lnk` pointer to a file that was opened; stores the target path plus the source volume serial and host identity — **proof a file was accessed**, incl. from removable/network media.
- **Jump List:** Windows' per-application "recent files" list (`*.automaticDestinations-ms`) — which app opened which file.
- **ShellBags:** registry records of folders browsed in Explorer — proves a folder was **navigated**, even if it's since deleted or was on a removed USB drive.
- **RecycleBin `$I`:** the metadata file for a deleted item — its original full path, size, and delete time.
- **WxT / Windows Timeline (`ActivitiesCache.db`):** an app/file usage log with focus duration — but it **roams** between a user's devices, so it isn't automatically *local*.
- **MACB / $SI vs $FN:** the four file timestamps (Modified, Accessed, Changed, Born) and the two timestamp sets in an MFT record; `$SI` is easy to forge, `$FN` harder — disagreement hints at **timestomp**.
- **Volume Serial Number (VSN):** a number stamped into a file system, embedded in LNK/JumpLists — used to tie a file (or a USB stick) back to the volume it lived on.
- **ROT13:** a trivial letter-rotation "encoding" (not encryption) that UserAssist uses on program names — the parser decodes it for you.
- **rla / transaction log:** the tool that replays a registry hive's pending-changes log (.LOG1/.LOG2) into a clean hive before parsing, so you don't read stale data.
- **plaso / log2timeline / psort:** the super-timeline engine — `log2timeline.py` collects events from many parsers into a `.plaso` store, `psort.py` sorts/filters/exports them (used here for Prefetch/SRUM because PECmd/SrumECmd are absent).
- **esedbexport:** dumps tables out of an ESE database (like SRUDB.dat) when a structured parser can't reach a field.

## Tuning log (append-only — the eval loop writes here; humans never edit rows)
| date | case_id | bucket missed | delta applied |
|---|---|---|---|
