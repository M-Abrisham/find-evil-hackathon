---
attack_type: targeted-intrusion-apt
category_id: targeted-intrusion-apt
name: Targeted Intrusion / APT & Specialized
description: long-dwell targeted attacks with advanced tradecraft and anti-forensics
version: 1
os_coverage: [windows, linux, macos, cloud]
sub_types_covered: 6
sub_types:
  - long-dwell-persistence
  - anti-forensics-timestomp-si-vs-fn
  - anti-forensics-log-clear-and-secure-delete
  - living-off-the-land-binaries-lolbins
  - staged-collection-and-exfiltration
  - supply-chain-or-implant-and-defense-evasion-tradecraft
validated_on: []
maturity: draft
variables:
  image_path:
    default: /cases/active/evidence/disk.E01
    derive: "Step 0 — first disk-evidence image (E01/dd/raw/vmdk) enumerated under the evidence directory named in the case brief"
  mount_root:
    default: /cases/active/mount
    derive: "Step 0 — directory where the file system is mounted READ-ONLY (or where icat-extracted artifacts land when mounting fails)"
  case_out:
    default: /cases/active/out
    derive: "Step 0 — writable case output directory from the case brief; Step 0 creates #{case_out}/receipts/ and #{case_out}/extracted/"
  ntfs_offset_sectors:
    default: 0
    derive: "Step 0 — start sector of the relevant partition from `mmls #{image_path}` (largest NTFS partition unless the brief says otherwise)"
  time_window:
    default: 1970-01-01..2099-12-31
    derive: "case brief if it names one; else first confirmed malicious timestamp plus/minus 48h once a step pins one — then re-scope wide sweeps to it"
---

## In one line
A patient, skilled attacker quietly lives inside a network for weeks or months, hiding with normal-looking system tools, faking file dates, and wiping the logs that would expose them — this playbook reconstructs that long, deliberately-erased story from what they could not fully clean.

## Use this when (triggers)
- The intrusion looks **old and deliberate**: signs of access stretching back weeks/months, not a smash-and-grab — and a real adversary, not commodity malware.
- **Logs are clean but the host is not.** Event logs were cleared (1102/104), truncated, or have suspicious gaps, yet other artifacts show activity in those "empty" windows.
- **File dates do not add up.** A suspect binary claims a creation date years ago or matching a system file (timestomp), or its `$SI` and `$FN` MACB times disagree.
- The tooling is **all built-in**: `powershell`, `wmic`, `rundll32`, `certutil`, `bitsadmin`, `regsvr32`, `mshta`, `wevtutil`, `vssadmin`, `fsutil`, `cipher /w` — "living-off-the-land," few or no dropped EXEs.
- Data was **staged then shipped out**: a RAR/7z/ZIP archive in a temp/public folder, split files, or odd outbound transfer, often long after initial access.
- You suspect a **supply-chain implant** (a trusted updater/DLL behaving oddly) or a hands-on operator who cleans up after each session.

## Quick path (the 90% case)
1. **Timeline-first, and build it from sources the attacker could not edit.** Render `$MFT` + `$UsnJrnl:$J` with `MFTECmd`, then fold the disk, registry, and surviving event logs into one super-timeline with `log2timeline.py` + `psort.py`. `$SI` times lie under timestomp — the `$J` change journal, `$FN` times, and `EventRecordID` sequence do not. Skim the whole window before committing to a story.
2. **Find the erased windows.** Look for log clears (Security 1102 / System 104), `EventRecordID` breaks, and multi-hour gaps where the timeline goes silent but `$J`/registry still show writes. Each gap is a finding and brackets where to dig deeper.
3. **Catch the date-fakers.** Compare `$SI` vs `$FN` MACB per suspect file with `MFTECmd`/`istat`; a `$SI` older than `$FN`, or a sub-second-zeroed time, is timestomp. Trust `$J` USN order over the on-disk timestamp.
4. **Hunt the living-off-the-land tradecraft.** Sweep registry execution (UserAssist/BAM/DAM via `RECmd`/`rip.pl`) and surviving 4688/4104 for built-in binaries run with attacker arguments (encoded PowerShell, `certutil -urlcache`, `bitsadmin /transfer`, `wmic process call create`), and persistence that survives reboots (services, tasks, Run keys, WMI consumers).
5. **Corroborate every lead in a second source** (registry plus disk, or memory plus disk) and only then commit. One cleared-log gap or one odd timestamp is a lead, not the case.

If a long-dwell foothold, a timestomp/log-clear cover-up, LOLBin tradecraft, and (if present) a staged archive all line up on the tamper-resistant timeline with a corroborating second source → you have the spine of the case. Otherwise drop into the full Steps.

## How it unfolds (the story)
A targeted operator gets in once — a phished credential, an exploited edge service, or a poisoned trusted update — and then settles in for the long haul, blending into normal admin activity with built-in Windows tools rather than noisy malware. Over days to months they quietly establish redundant persistence (a service, a scheduled task, a Run key, a WMI event consumer), move laterally, and stage what they want into an archive. Throughout, they practice anti-forensics: backdating file times to match system files (timestomp), clearing or truncating the very logs that record them, and secure-deleting their tools after each session. The case is reconstructed not from what they left in the obvious places, but from the journal, metadata, and cross-artifact timeline they could not fully erase.

## Theories to test (and how to rule each out)
| Theory (who / why) | If true, you'd find… | Rule it out if… |
|---|---|---|
| **External-targeted (hands-on APT operator, long dwell)** | First-access weeks/months before discovery; redundant persistence; LOLBin tradecraft; periodic log clears (1102) and timestomped tools; a late staged archive | Earliest malicious artifact is recent and isolated; no persistence redundancy; no anti-forensics; activity looks automated/commodity |
| **Supply-chain / trusted-implant** | A signed/trusted updater or DLL with an anomalous child process or odd load path; the same implant/hash on many hosts; persistence parented by a legitimate updater | The suspect binary is a user-dropped file on this host only; no trusted-updater parent; hash/path unique to one box |
| **Insider with admin (deliberate cleanup)** | Local interactive (type 2) admin sessions; tools run from a user profile; `wevtutil cl`/`cipher /w`/`fsutil usn deletejournal` by a real account during business hours | Access originates remotely from outside, or the credentials were proven stolen → reclassify external-targeted/other-insider |
| **Other-insider (compromised legit account / stolen creds)** | A valid account logging on from an unusual host/hour, then LOLBin activity and selective log clearing under that identity; impossible-travel vs its baseline | Logon source, host and hours match the account's own pattern; no anomalous origin or out-of-character tooling |
| **External-commodity (noisy, NOT targeted)** | Off-the-shelf RAT/loader with packed EXEs, AV hits, public C2, no patient cleanup, short dwell | Dwell is long, tradecraft is hand-driven and tidy, tooling is built-in not dropped, logs were deliberately curated → reclassify external-targeted |
| **Innocent / benign (NOT an attack)** | Backup/imaging software that legitimately touches many files; sanctioned log rotation/GPO clearing; an admin using `bitsadmin`/`certutil` for real ops; archive made by a known job — all by expected accounts in business hours | A sanctioned change-control record explains the clear/archive/tooling AND the account+source+timing are expected → benign cause confirmed; reclassify |

*(at least one benign + at least one malicious, each ACTIVELY refuted. Attacker types mapped: insider · other-insider · external-commodity · external-targeted · supply-chain · innocent.)*

## Evidence → Tool → What it reveals (per OS)
| Evidence | SIFT tool | What it tells you *for this attack* | OS |
|---|---|---|---|
| `$MFT` ($SI vs $FN MACB, create/mod times) | `MFTECmd` / `istat` / `analyzeMFT` | Timestomp detection — `$SI` (forgeable) vs `$FN` (harder) disagreement, zeroed sub-seconds, dates matching system files; on-disk presence of LOLBin/staged files | Windows |
| `$UsnJrnl:$J` change journal | `MFTECmd` / `usn.py` | The tamper-resistant order of file create/rename/delete — recovers prior existence of secure-deleted tools and the true sequence when `$SI` is faked | Windows |
| `Security.evtx` / `System.evtx` (1102 / 104 clears, 4688, 4624, EventRecordID) | `EvtxECmd` / `evtxexport` / `evtx_dump.py` | Log-clearing events, surviving execution/logon records, and `EventRecordID` breaks / time gaps that reveal silent tampering | Windows |
| NTUSER.DAT / SYSTEM / SOFTWARE / Amcache.hve | `RECmd` / `rip.pl` / `AmcacheParser` | LOLBin execution (UserAssist/BAM/DAM), redundant persistence (Run keys, Services, WMI), and inventory of tools present (Amcache = inference only) | Windows |
| `pagefile.sys` / `hiberfil.sys` / unallocated | `page-brute` / `bulk_extractor` / `srch_strings` | In-memory spill of encoded commands, C2 indicators, and tool strings that the operator secure-deleted from the file system | Windows/Linux |
| RAM image (if captured) | `vol` (Volatility 3) | Live injected/hollowed processes (`malfind`), hidden services (`svcscan`), network residue (`netscan`), and in-memory ShimCache (`shimcachemem`) not yet flushed to disk | Windows/Linux* |
| Suspect binaries / DLLs / staged archives | `ssdeep` / `densityscout` / `clamscan` / `pe-scanner` / `exiftool` | Fuzzy-hash match to known-good/known-bad (the Memory-Baseliner substitute), packing/entropy, AV signature, PE anomalies, and authoring metadata on the implant | all |
| Staged collection (RAR/7z/ZIP in temp/public) | `MFTECmd` ($J) / `bulk_extractor` / `srch_strings` | The archive's create time, contents listing fragments, and the exfil window — staging that long postdates initial access | all |
| All artifacts fused | `log2timeline.py` + `psort.py` (+ `pinfo.py`) | One long-dwell chronology that survives `$SI` lies — anchored to `$J`/EventRecordID order, exposing the erased windows | all |
| Image-wide indicator sweep | `bulk_extractor` / `bstrings` / `srch_strings` | Emails, URLs, IPs and command fragments spilled outside the curated logs — the operator's residue | all |
| Linux journal / shell history / persistence | `fls`/`mactime`, `log2timeline.py` (syslog/utmp/journal), `srch_strings` | SSH logons, sudo, cron/systemd persistence, cleared `/var/log` and truncated history — the Linux equivalents | Linux |

*Linux memory analysis in `vol` needs a matching ISF symbol pack — `⚠️verify` availability before relying on it; none ship on this box.

## Step 0 — evidence inventory & access bootstrap
- n: 0
  tool: |
    mkdir -p "#{case_out}/receipts" "#{case_out}/extracted" && ls -laR "#{mount_root}" > "#{case_out}/receipts/00.txt" 2>&1 ; img_stat "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; mmls "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; fsstat -o #{ntfs_offset_sectors} "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; find "#{mount_root}" -maxdepth 4 -iname "*.evtx" -o -iname "Amcache.hve" -o -iname "pagefile.sys" >> "#{case_out}/receipts/00.txt" 2>&1
  expect: every evidence file classified; #{image_path}, #{mount_root}, #{ntfs_offset_sectors}, #{case_out} bound; read-only access proven; the $MFT, winevt\Logs *.evtx, registry hives, pagefile/hiberfil, and any memory image are enumerated, or their absence is recorded as a finding
  check: |
    test -r "#{mount_root}" -o -n "$(ls "#{case_out}/extracted" 2>/dev/null)"
  falsify: evidence dir empty/unreadable, or no supported image format found, or no file system for fsstat
  on_result: {expect_met: goto 1, falsify_met: STOP — report acquisition/access failure; pivot acquisition-custody, neither: try the icat-extract fallback (fls to find the $MFT/winevt\Logs inodes, icat each into #{case_out}/extracted); if that also fails, treat as falsify_met}
  emits: [key_artifacts]
  serves: [long-dwell-persistence, anti-forensics-timestomp-si-vs-fn, anti-forensics-log-clear-and-secure-delete, living-off-the-land-binaries-lolbins, staged-collection-and-exfiltration, supply-chain-or-implant-and-defense-evasion-tradecraft]
  provenance: {receipt_id: 00, artifact: evidence directory listing + $MFT/EVTX/hive enumeration, offset_or_row: full listing, literal_cited: image filename + hash line}

## Steps (executable — decision-driven)
- n: 1
  precondition: "os == windows; test -r #{mount_root}"
  tool: |
    dotnet /opt/zimmermantools/MFTECmd.dll -f "#{mount_root}/\$MFT" --csv "#{case_out}" --csvf mft.csv > "#{case_out}/receipts/01.txt" 2>&1 ; dotnet /opt/zimmermantools/MFTECmd.dll -f "#{mount_root}/\$Extend/\$UsnJrnl:\$J" --csv "#{case_out}" --csvf usnj.csv >> "#{case_out}/receipts/01.txt" 2>&1
  expect: a parsed $MFT (#{case_out}/mft.csv) with both SI and FN MACB columns and a parsed $J change journal (#{case_out}/usnj.csv) — the tamper-resistant timeline spine for every later step, covering the full dwell window not just #{time_window}
  check: |
    test -s "#{case_out}/mft.csv" && grep -qiE "FileName|Created0x10|SI_FN|LastModified" "#{case_out}/mft.csv"
  falsify: no $MFT parseable (image unmountable or NTFS absent), or $J deleted/zeroed (fsutil usn deletejournal — itself an anti-forensics finding)
  on_result: {expect_met: goto 2, falsify_met: if $J is absent record the journal-wipe as an anti-forensics finding and rely on $MFT + super-timeline; if $MFT is absent fall back to fls/tsk_gettimes bodyfile then mactime, and pivot disk-filesystem, neither: re-run MFTECmd against the icat-extracted $MFT in #{case_out}/extracted; if NTFS is absent this may be a Linux image — go to the Linux branch}
  emits: [timeline_events, key_artifacts]
  serves: [long-dwell-persistence, anti-forensics-timestomp-si-vs-fn]
  provenance: {receipt_id: 01, artifact: $MFT + $UsnJrnl:$J, offset_or_row: mft.csv header + row count, literal_cited: MFTECmd processed-record count line}

- n: 2
  precondition: "exists #{case_out}/events.csv == false; test -r #{mount_root}"
  tool: |
    dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll -d "#{mount_root}" --csv "#{case_out}" --csvf events.csv > "#{case_out}/receipts/02.txt" 2>&1 ; grep -E ",1102,|,104,|,1100,|,4719," "#{case_out}/events.csv" >> "#{case_out}/receipts/02.txt" 2>&1
  expect: a normalized event CSV (#{case_out}/events.csv); within it a Security 1102 audit-log-cleared and/or System 104 event-log-cleared near the dwell window, or a 1100 service-shutdown / 4719 audit-policy change — a deliberate cover-up timestamp that brackets an erased window
  check: |
    test -s "#{case_out}/events.csv" && grep -qE ",1102,|,104,|,1100,|,4719," "#{case_out}/receipts/02.txt"
  falsify: events.csv built but NO clear/audit-change event anywhere — the logs were not cleared via a logged mechanism (still test EventRecordID continuity in step 3 for SILENT tampering)
  on_result: {expect_met: record each clear/shutdown timestamp as a high-signal anti-forensics finding; bracket the erased window into #{time_window}; goto 3, falsify_met: no logged clear — proceed to EventRecordID gap analysis at goto 3; do not conclude the logs are intact yet, neither: if no .evtx parsed fall back to evtxexport / evtx_dump.py per file into #{case_out}/extracted and grep for the clear EIDs; if logs are absent record absence as a finding}
  emits: [key_artifacts, timeline_events]
  serves: [anti-forensics-log-clear-and-secure-delete]
  provenance: {receipt_id: 02, artifact: Security.evtx / System.evtx, offset_or_row: events.csv 1102/104/1100/4719 rows, literal_cited: the audit-log-cleared event message + timestamp}

- n: 3
  precondition: "exists #{case_out}/events.csv"
  tool: |
    awk -F',' 'NR>1{print $0}' "#{case_out}/events.csv" | sort -t',' -k1 > "#{case_out}/receipts/03.txt" 2>&1 ; for f in $(find "#{mount_root}" -iname "Security.evtx" -o -iname "System.evtx" 2>/dev/null); do dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll -f "$f" --csv "#{case_out}" --csvf "$(basename "$f").rec.csv" >> "#{case_out}/receipts/03.txt" 2>&1 ; done
  expect: per-file EventRecordID is monotonically increasing with no break, OR a break/jump in EventRecordID plus a multi-hour TimeCreated gap that straddles activity seen in $J/registry — a SILENT clear that fired no 1102/104, which is itself a finding
  check: |
    test -s "#{case_out}/receipts/03.txt" && ls "#{case_out}"/*.rec.csv >/dev/null 2>&1
  falsify: EventRecordID is continuous and no time gap overlaps $J/registry write activity — the surviving event logs are intact across the window
  on_result: {expect_met: record any EventRecordID break or unexplained gap as silent-tampering; correlate the gap against usnj.csv writes; goto 4, falsify_met: record logs-continuous and lean on them as a trustworthy source for the window; goto 4, neither: inspect EventRecordID min/max per .rec.csv and compare gap boundaries to usnj.csv timestamps; cap at inferred if ambiguous}
  emits: [timeline_events, key_artifacts]
  serves: [anti-forensics-log-clear-and-secure-delete]
  provenance: {receipt_id: 03, artifact: Security.evtx / System.evtx per-file, offset_or_row: per-file EventRecordID min/max + gap boundaries, literal_cited: the record-id break or the gap start/end timestamps}

- n: 4
  precondition: "exists #{case_out}/mft.csv"
  tool: |
    grep -iE "\\\\Users\\\\|\\\\ProgramData\\\\|\\\\Temp\\\\|\\\\PerfLogs\\\\|\\\\Public\\\\" "#{case_out}/mft.csv" > "#{case_out}/receipts/04.txt" 2>&1 ; awk -F',' 'NR==1 || $0 ~ /\.exe|\.dll|\.ps1|\.bat|\.scr/' "#{case_out}/mft.csv" | head -n 5000 >> "#{case_out}/receipts/04.txt" 2>&1
  expect: at least one suspect file whose $SI Created/Modified is OLDER than its $FN Created (back-dating), or whose timestamps are zeroed to whole seconds, or whose $SI date matches a system binary while it lives in a user/temp path — classic timestomp on an implant or LOLBin drop
  check: |
    test -s "#{case_out}/receipts/04.txt"
  falsify: every suspect file shows $SI and $FN MACB in agreement with normal sub-second precision and a create time consistent with the $J order — no timestomp evidenced
  on_result: {expect_met: record the timestomped path + the SI/FN discrepancy as an IOC; confirm true order from usnj.csv; goto 5, falsify_met: record no-timestomp-found; still treat $J order as authoritative over $SI; goto 5, neither: run istat against the specific inode to dump full $SI vs $FN MACB and re-judge; widen #{time_window} if the suspect file falls outside it}
  emits: [key_iocs, timeline_events]
  serves: [anti-forensics-timestomp-si-vs-fn]
  provenance: {receipt_id: 04, artifact: $MFT $SI vs $FN MACB, offset_or_row: mft.csv suspect-file row, literal_cited: the SI-Created vs FN-Created timestamp pair}

- n: 5
  precondition: "exists #{case_out}/usnj.csv"
  tool: |
    grep -iE "FileDelete|RenameOld|RenameNew|Close|DataExtend" "#{case_out}/usnj.csv" > "#{case_out}/receipts/05.txt" 2>&1 ; grep -iE "\.rar|\.7z|\.zip|\.cab|\.tmp|\.exe|\.dll|\.ps1" "#{case_out}/usnj.csv" >> "#{case_out}/receipts/05.txt" 2>&1
  expect: $J reason codes showing files CREATED then DELETED inside the dwell window (secure-deleted tooling), and/or rename masquerade (a tool renamed to look benign) — the prior existence of artifacts now gone, recoverable in order even though $SI was faked or the file was wiped
  check: |
    grep -qiE "FileDelete|RenameOld|RenameNew" "#{case_out}/receipts/05.txt"
  falsify: no create-then-delete and no rename pattern in $J across the window — no evidence of secure-deletion or masquerade via the change journal
  on_result: {expect_met: record each deleted/renamed tool name + its $J timestamps as an IOC; attempt content recovery with tsk_recover/icat for any inode still allocated; goto 6, falsify_met: record no-journal-deletions; proceed to LOLBin execution at goto 6, neither: re-parse $J with usn.py for a second reading; if $J is short/wrapped note the retention limit and rely on $MFT slack/INDX}
  emits: [key_iocs, timeline_events]
  serves: [anti-forensics-log-clear-and-secure-delete]
  provenance: {receipt_id: 05, artifact: $UsnJrnl:$J reason codes, offset_or_row: usnj.csv delete/rename rows, literal_cited: the filename + FileDelete/RenameOld reason + USN timestamp}

- n: 6
  precondition: "os == windows; test -r #{mount_root}"
  tool: |
    dotnet /opt/zimmermantools/RECmd/RECmd.dll --bn /opt/zimmermantools/RECmd/BatchExamples/Kroll_Batch.reb -d "#{mount_root}" --csv "#{case_out}" --csvf reg.csv > "#{case_out}/receipts/06.txt" 2>&1 ; grep -iE "powershell|cmd\.exe|wmic|rundll32|regsvr32|mshta|certutil|bitsadmin|cscript|wscript|wevtutil|vssadmin|cipher|fsutil" "#{case_out}/reg.csv" >> "#{case_out}/receipts/06.txt" 2>&1
  expect: registry execution traces (UserAssist/BAM/DAM) and persistence (Run keys, Services, WMI) naming built-in binaries run with attacker-style arguments — encoded PowerShell, certutil -urlcache, bitsadmin /transfer, rundll32 of a non-standard DLL, wmic process call create, or wevtutil/vssadmin/cipher used to destroy evidence
  check: |
    test -s "#{case_out}/reg.csv" && grep -qiE "powershell|rundll32|certutil|bitsadmin|wmic|regsvr32|mshta|wevtutil|vssadmin|cipher" "#{case_out}/receipts/06.txt"
  falsify: no LOLBin appears in any registry execution/persistence source — execution evidence may be off-registry (check 4688/4104 in step 7) before concluding none
  on_result: {expect_met: record each LOLBin path + command line as an IOC; map persistence redundancy (count of independent autoruns); goto 7, falsify_met: record no-LOLBin-in-registry; corroborate execution via surviving 4688/4104 at goto 7; pivot windows-registry-persistence if persistence is suspected but unparsed, neither: run rip.pl -f userassist / -f services against the specific NTUSER/SYSTEM hive and re-check; run rla first if hives need transaction-log replay}
  emits: [key_iocs, actor_accounts]
  serves: [living-off-the-land-binaries-lolbins, long-dwell-persistence]
  provenance: {receipt_id: 06, artifact: NTUSER/SYSTEM/SOFTWARE hives (UserAssist/BAM/Run/Services), offset_or_row: reg.csv execution/persistence row, literal_cited: the built-in binary path + its command-line arguments}

- n: 7
  precondition: "exists #{case_out}/events.csv"
  tool: |
    grep -E ",4688," "#{case_out}/events.csv" > "#{case_out}/receipts/07.txt" 2>&1 ; grep -E ",4104,|,4103," "#{case_out}/events.csv" >> "#{case_out}/receipts/07.txt" 2>&1 ; grep -iE "EncodedCommand|FromBase64|DownloadString|IEX|-nop|-w hidden|urlcache|/transfer|process call create" "#{case_out}/events.csv" >> "#{case_out}/receipts/07.txt" 2>&1
  expect: surviving 4688 process-creation and/or 4104 PowerShell script-block rows that record the LOLBin command lines from step 6 — encoded/obfuscated PowerShell, download cradles, or built-in transfer tools — the same paths/arguments seen in the registry, giving a second independent source for execution
  check: |
    grep -qiE ",4688,|,4104,|EncodedCommand|DownloadString|urlcache|/transfer" "#{case_out}/receipts/07.txt"
  falsify: no 4688 and no 4104 (process/script-block auditing was off, common against a careful operator) — execution must be carried by registry (step 6) + disk (step 4) alone
  on_result: {expect_met: promote the LOLBin execution to confirmed (registry + event-log agreement); goto 8, falsify_met: keep execution at inferred from registry/disk; record the auditing gap as itself an evasion finding; goto 8, neither: parse the PowerShell Operational log per-file with EvtxECmd -f and re-check; pagefile spill may still hold the decoded command — see step 8}
  emits: [key_iocs, timeline_events]
  serves: [living-off-the-land-binaries-lolbins, supply-chain-or-implant-and-defense-evasion-tradecraft]
  provenance: {receipt_id: 07, artifact: Security.evtx 4688 / PowerShell Operational 4104, offset_or_row: events.csv 4688/4104 rows, literal_cited: the NewProcessName + CommandLine (or decoded script block) string}

- n: 8
  precondition: "test -r #{mount_root}"
  tool: |
    page-brute -f "#{mount_root}/pagefile.sys" -o "#{case_out}/pagebrute" > "#{case_out}/receipts/08.txt" 2>&1 ; bulk_extractor -o "#{case_out}/bulk" "#{image_path}" >> "#{case_out}/receipts/08.txt" 2>&1 ; srch_strings -a "#{mount_root}/pagefile.sys" 2>/dev/null | grep -iE "http://|https://|EncodedCommand|DownloadString|\.onion|certutil|bitsadmin" | head -n 200 >> "#{case_out}/receipts/08.txt" 2>&1
  expect: in-memory spill (pagefile/unallocated) of decoded commands, C2 URLs/IPs/domains, or tool strings that the operator secure-deleted from the file system — recovering what steps 5–7 lost to anti-forensics, including bulk_extractor email/url/domain features
  check: |
    test -d "#{case_out}/bulk" && { test -s "#{case_out}/receipts/08.txt" || ls "#{case_out}/bulk"/*.txt >/dev/null 2>&1 ; }
  falsify: no recoverable command/C2/tool strings in pagefile or unallocated — the spill sources are empty or were also wiped (cipher /w over free space is itself a finding)
  on_result: {expect_met: record recovered C2 indicators + decoded commands as IOCs; cross-check the URLs/IPs against the timeline window; goto 9, falsify_met: record no-spill-recovered; if free space looks zeroed note possible cipher /w wiping as an anti-forensics finding; goto 9, neither: run bulk_extractor scanners individually (email, url) and re-read its feature files; if pagefile is absent note it and continue}
  emits: [key_iocs, exfil_or_encryption_facts]
  serves: [living-off-the-land-binaries-lolbins, staged-collection-and-exfiltration]
  provenance: {receipt_id: 08, artifact: pagefile.sys + unallocated (bulk_extractor features), offset_or_row: page-brute hit / bulk_extractor url.txt line, literal_cited: the recovered C2 URL/IP or decoded command string}

- n: 9
  precondition: "exists #{case_out}/usnj.csv"
  tool: |
    grep -iE "\.rar|\.7z|\.zip|\.cab|\.gz|\.tar|\.001" "#{case_out}/mft.csv" > "#{case_out}/receipts/09.txt" 2>&1 ; grep -iE "\.rar|\.7z|\.zip|\.cab" "#{case_out}/usnj.csv" >> "#{case_out}/receipts/09.txt" 2>&1 ; for a in $(find "#{mount_root}" -maxdepth 6 -iname "*.rar" -o -iname "*.7z" -o -iname "*.zip" 2>/dev/null | head -n 50); do ssdeep "$a" >> "#{case_out}/receipts/09.txt" 2>&1 ; densityscout "$a" >> "#{case_out}/receipts/09.txt" 2>&1 ; done
  expect: a staged archive (RAR/7z/ZIP/split .001) in a temp/public/profile path whose $J/$MFT create time long POSTDATES initial access — the collection bundle; ssdeep fuzzy-hash and densityscout entropy confirm it is a packed/compressed container ready for exfil
  check: |
    grep -qiE "\.rar|\.7z|\.zip|\.cab|\.001" "#{case_out}/receipts/09.txt"
  falsify: no staging archive anywhere on disk or in $J — collection may have streamed straight out (check step 8 C2/exfil indicators) or this intrusion did not exfiltrate via local staging
  on_result: {expect_met: record the archive path + create time + the gap from initial access as an exfil fact; recover/list contents where the inode survives; goto 10, falsify_met: record no-local-staging; lean on step 8 network/spill indicators for the exfil channel; goto 10, neither: carve archive signatures from unallocated with bulk_extractor/photorec in batch mode and re-check; widen #{time_window} to the full dwell}
  emits: [exfil_or_encryption_facts, key_iocs]
  serves: [staged-collection-and-exfiltration]
  provenance: {receipt_id: 09, artifact: $MFT/$J archive entries + on-disk archive, offset_or_row: mft.csv/usnj.csv archive row + ssdeep line, literal_cited: the archive filename + create time + ssdeep/density value}

- n: 10
  precondition: "exists #{case_out}/mft.csv"
  tool: |
    log2timeline.py --status_view none "#{case_out}/case.plaso" "#{mount_root}" > "#{case_out}/receipts/10.txt" 2>&1 ; psort.py -o l2tcsv "#{case_out}/case.plaso" > "#{case_out}/super.csv" 2>> "#{case_out}/receipts/10.txt" ; pinfo.py "#{case_out}/case.plaso" >> "#{case_out}/receipts/10.txt" 2>&1
  expect: a fused super-timeline anchored to $J/$MFT/EventRecordID order (NOT host $SI) that places first-access → persistence → LOLBin execution → log-clear/timestomp → staged exfil across the full dwell window, with the erased windows from steps 2–3 visibly bracketed and no contradiction
  check: |
    test -s "#{case_out}/super.csv" && grep -qiE "usnjrnl|winevtx|filestat|mft" "#{case_out}/super.csv"
  falsify: the ordering is internally impossible (e.g. exfil precedes any access) OR a multi-hour gap is unaccounted for by any clear/timestomp finding — host time is poisoned or a source is missing
  on_result: {expect_met: COMMIT the long-dwell narrative with a confidence label; close per the gate, falsify_met: re-open the Theories table; anchor strictly to $J USN order and EventRecordID rather than $SI/host time, then rebuild, neither: run pinfo.py to confirm the usnjrnl/winevtx parsers ran; re-filter psort.py to the full dwell window and re-check}
  emits: [timeline_events]
  serves: [long-dwell-persistence, supply-chain-or-implant-and-defense-evasion-tradecraft]
  provenance: {receipt_id: 10, artifact: case.plaso super-timeline, offset_or_row: super.csv ordered rows, literal_cited: the ordered access→persistence→execution→clear→exfil chain}

## Linux branch (L1..Ln) — REQUIRED, numbered, same step shape
- n: L1
  precondition: "os == linux"
  tool: |
    fsstat -o #{ntfs_offset_sectors} "#{image_path}" > "#{case_out}/receipts/L01.txt" 2>&1 ; find "#{mount_root}/var/log" -maxdepth 2 -type f 2>/dev/null >> "#{case_out}/receipts/L01.txt" ; ls -la "#{mount_root}/var/log/journal" >> "#{case_out}/receipts/L01.txt" 2>&1 ; for h in "#{mount_root}/root/.bash_history" "#{mount_root}/home"/*/.bash_history ; do ls -la "$h" >> "#{case_out}/receipts/L01.txt" 2>&1 ; done
  expect: this image is Linux (ext/xfs fsstat, /var/log present) — Windows $MFT/EVTX do not exist; the dwell evidence lives in syslog/journal, wtmp/btmp, cron/systemd units, and shell histories, and the anti-forensics tell is a TRUNCATED or zero-length auth.log/bash_history (size 0 = wiped, itself a finding)
  check: |
    test -d "#{mount_root}/var/log" -o -n "$(grep -iE 'ext[234]|xfs' "#{case_out}/receipts/L01.txt" 2>/dev/null)"
  falsify: fsstat reports NTFS and a Windows\System32\winevt\Logs tree exists — this is Windows, not Linux; run the main Windows Steps 1–10 instead
  on_result: {expect_met: goto L2, falsify_met: this is Windows — return to the main branch at step 1, neither: confirm OS family from the Step 0 fsstat/disktype receipt; if still ambiguous treat as Windows and run the main branch}
  emits: [key_artifacts]
  serves: [anti-forensics-log-clear-and-secure-delete, long-dwell-persistence]
  provenance: {receipt_id: L01, artifact: file system + /var/log + history listing, offset_or_row: fsstat header + dir listing, literal_cited: ext/xfs FS type or a zero-length auth.log/bash_history line}

- n: L2
  precondition: "os == linux"
  tool: |
    log2timeline.py --status_view none "#{case_out}/linux.plaso" "#{mount_root}/var/log" > "#{case_out}/receipts/L02.txt" 2>&1 ; psort.py -o l2tcsv "#{case_out}/linux.plaso" > "#{case_out}/linux_super.csv" 2>> "#{case_out}/receipts/L02.txt" ; srch_strings "#{mount_root}/var/log/auth.log" 2>/dev/null | grep -iE "accepted|failed password|sudo|new session" >> "#{case_out}/receipts/L02.txt" 2>&1 ; ls -la "#{mount_root}/etc/cron.d" "#{mount_root}/etc/systemd/system" >> "#{case_out}/receipts/L02.txt" 2>&1
  expect: SSH Accepted/Failed logons and sudo escalation in the journal/auth.log, long-dwell persistence as cron.d entries or systemd units pointing at scripts, and gaps/truncation where logs were cleared — ordered in the super-timeline; LOLBin equivalents (curl/wget/python/base64 in history) name the living-off-the-land tooling
  check: |
    test -s "#{case_out}/linux_super.csv" -o -s "#{case_out}/receipts/L02.txt"
  falsify: /var/log empty or wiped and histories truncated with NO surviving cron/systemd persistence — either a non-Linux image or total log destruction (record the wipe as an anti-forensics finding)
  on_result: {expect_met: record account + source IP + persistence unit + LOLBin commands; commit with a confidence label, falsify_met: record the log-wipe as a finding; carve deleted log/history fragments with srch_strings/bulk_extractor over unallocated; pivot linux-host-forensics, neither: widen #{time_window}; parse journald binary logs under /var/log/journal via log2timeline and re-render}
  emits: [actor_accounts, timeline_events]
  serves: [long-dwell-persistence, living-off-the-land-binaries-lolbins, anti-forensics-log-clear-and-secure-delete]
  provenance: {receipt_id: L02, artifact: /var/log journal+auth.log + cron.d/systemd, offset_or_row: linux_super.csv rows / grep hits, literal_cited: the Accepted/Failed logon line + source IP or the persistence unit path}

## Corroboration (two-source rule)
`required_sources: 2` · `pairs:`
- `[ $SI vs $FN timestomp (step 4) ↔ the true create/rename order in $UsnJrnl:$J (step 5) ]`
- `[ logged clear 1102/104 (step 2) ↔ EventRecordID break / time gap (step 3) ]`
- `[ LOLBin in registry UserAssist/BAM (step 6) ↔ surviving 4688/4104 execution (step 7) ]`
- `[ decoded command / C2 from pagefile spill (step 8) ↔ the LOLBin command line in registry/event log (steps 6/7) ]`
- `[ staged archive on disk (step 9) ↔ its $J create time + ssdeep/entropy (step 9) and the exfil window (step 8) ]`
- `[ persistence redundancy in registry (step 6) ↔ the install event / binary $MFT create time (steps 1/2) ]`
- `[ per-step findings ↔ the fused super-timeline order anchored to $J/EventRecordID (step 10) ]`

One hit is a *lead*; promote to *fact* only when its paired source agrees.

## Don't get fooled (red flags & anti-forensics)
- **Cleared logs are evidence, not absence.** A 1102/104 near the dwell window proves a deliberate operator; the empty stretch is the finding. Anchor everything else to it and dig in the bracketed window with non-log sources.
- **Silent clears fire no 1102.** A careful operator stops the EventLog service, disables auditing (4719), or exports-and-deletes — no clear event. Test **EventRecordID continuity** per file and compare time gaps to `$J`/registry write activity; a break with concurrent writes is tampering.
- **Timestomp poisons `$SI`, not `$J`.** `$SI` MACB is trivially backdated (often to match a system file, or zeroed to whole seconds); `$FN` is harder and the `$UsnJrnl:$J` USN order is authoritative. When dates fight, trust the journal and `$FN`.
- **Living-off-the-land means no malware to find.** Built-in `powershell`/`certutil`/`bitsadmin`/`rundll32`/`wmic` are not IOCs by name — the *arguments* are (encoded blobs, `-urlcache`, `/transfer`, non-standard DLLs). Auditing being OFF does NOT mean nothing ran; corroborate off-log.
- **Secure-deletion erases content, not the journal entry.** `$J` keeps create/rename/delete reason codes after the file is gone; `cipher /w` and `sdelete` wipe content but the prior existence and order survive in `$J`/`$MFT` slack/INDX.
- **`fsutil usn deletejournal` and a zeroed pagefile are themselves findings.** A missing change journal or a wiped free space is anti-forensics, not "nothing here" — record the absence.
- **Long dwell hides redundant persistence.** Find ALL autoruns (service + task + Run key + WMI consumer), not the first; APTs keep backups. One found foothold is not the whole foothold.
- **Host time can be poisoned.** If the timeline is internally impossible, anchor to monotonic `EventRecordID` and `$J` USN sequence, never to `$SI`/host clock. **Missing evidence is itself a finding.**

## Failure modes
```
- mode: evidence-access failure — the disk won't mount or the $MFT/winevt\Logs is unreadable
  guard: Step 0 fallback chain — ewfmount/loop RO, else TSK fls/icat the $MFT and .evtx inodes into #{case_out}/extracted; if all fail, record acquisition failure and pivot acquisition-custody
- mode: primary-artifact-absent — $UsnJrnl:$J deleted (fsutil usn deletejournal), Security/System.evtx cleared, or pagefile zeroed
  guard: record the absence as an anti-forensics finding (it IS evidence); fall back to $MFT slack/INDX (INDXParse.py), surviving Operational logs, and the super-timeline; name registry/$MFT as the secondary source and pivot windows-registry-persistence
- mode: tool-output drift — MFTECmd/EvtxECmd CSV column or map names change, or a comma-in-field breaks a grep literal so check exits 2
  guard: on check exit 2, adjudicate from the prose expect/falsify against the receipt, cap confidence at inferred; fall back to raw evtxexport/evtx_dump.py XML or analyzeMFT and grep directly, never silently pass
- mode: timestomp fools $SI-keyed timelines — a backdated tool sorts to the wrong place
  guard: anchor the timeline to $J USN order and $FN; flag any $SI/$FN disagreement and re-sort by journal sequence
- mode: living-off-the-land + auditing off — no 4688/4104 and no dropped EXE to find
  guard: do not infer "nothing ran"; corroborate execution via registry UserAssist/BAM (RECmd/rip.pl), pagefile spill (page-brute), and memory (vol) and report the auditing gap explicitly
- mode: no memory baseline parser on this box (Memory Baseliner absent)
  guard: substitute ssdeep fuzzy-hash against a known-good/known-bad corpus plus densityscout entropy and vol malfind/svcscan/netscan — never claim a baseline-diff that cannot be run
```
Minimum set every playbook covers: evidence-access failure (Step 0 fallback chain) · primary-artifact-absent (absence recorded, secondary source named) · tool-output drift (`check` exits 2 → prose adjudication, never silent pass).

## Confidence labeling (observation → inference → conclusion)
- **confirmed:** direct receipt verbatim (e.g. the $J FileDelete row, the 4104 decoded block) + ≥2 independent sources agree (e.g. registry execution + event log, or disk + memory) + no unrefuted counter-theory.
- **inferred:** grounded but single-source/interpretive — e.g. a timestomp read from $SI/$FN alone, an EventRecordID gap read as a silent clear, Amcache presence read as execution, or BAM coverage on newer Win10/11 unverified → hedge and tag `⚠️verify`. Every `check`-exit-2 adjudication lands here at best.
- **insufficient_evidence:** precondition unmet ($J deleted, logs cleared, no RAM image, auditing off) or sources conflict → abstain; state what is missing, do not guess.

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
- **Windows:** fully covered above — the tamper-resistant spine is `$MFT`/`$UsnJrnl:$J` plus `EventRecordID` continuity, with registry (UserAssist/BAM/Services/WMI) and pagefile spill recovering what anti-forensics erased.
- **Linux/ESXi:** no `$MFT`/EVTX — see the numbered Linux branch (L1–L2). Equivalents: `auth.log`/`secure` and the systemd journal (logons/sudo), `wtmp`/`btmp`, `cron.d`/systemd units (long-dwell persistence), and shell histories. Anti-forensics shows as truncated/zeroed logs and histories. Auditd `audit.log` has **no parser** on this box — read it as text (`srch_strings`/grep for `type=EXECVE`), `⚠️verify`.
- **macOS:** no `$MFT`/EVTX — persistence lives in LaunchAgents/Daemons plists and login items; logon/exec in the Unified Log (`.tracev3`). This box has **no working Unified-Log parser** and `mac_apt` is broken (`⚠️verify` — degraded), so an empty unified-log result ≠ "no activity." Use `log2timeline.py` for plist/FSEvents/ASL/utmpx where it works and `sqlite3` in batch for KnowledgeC/TCC; treat findings as lead-only. Pivot macos-forensics.
- **Cloud:** no host `$MFT`/EVTX — the analog is the identity/control-plane audit log (sign-in/CloudTrail), where APT tradecraft shows as token/OAuth abuse and audit-log deletion. This box has **no dedicated cloud-log parser** (`⚠️verify`); investigate from *exported* JSON already on disk with `bulk_extractor`/`srch_strings`/`jq` — lead-only until validated off-box. Pivot cloud-identity-saas.

## Real-case notes (non-obvious things to look for)
- **A cleared Security log with NO 1102 is the loud finding.** Sophisticated operators stop the EventLog service or disable auditing rather than fire `wevtutil cl`, so there is no clear-event — but the **EventRecordID sequence breaks** and a **TimeCreated gap** appears that overlaps file-system writes in `$J`. Always test record-ID continuity, not just for a 1102/104. `[SANS FOR508 / general DFIR practice · high]`
- **Timestomp usually backdates `$SI` to a round or system-file time but leaves `$FN` and `$J` intact.** A `$SI` Created earlier than `$FN` Created, or sub-seconds zeroed to `.000000`, on a file living in a user/temp path is a strong timestomp tell; the `$UsnJrnl:$J` USN order gives the real sequence. `[MITRE T1070.006 / Zimmerman MFTECmd guidance · high]`
- **Living-off-the-land leaves argument IOCs, not binary IOCs.** `certutil -urlcache -f <url>`, `bitsadmin /transfer`, `rundll32` of a non-standard DLL, `mshta` of a remote `.hta`, `wmic process call create`, and base64/`-EncodedCommand` PowerShell are the signal — the binaries themselves are signed Microsoft tools. `[MITRE T1218 / T1059.001 / LOLBAS · high]`
- **Secure-deleted tooling survives in the change journal.** `$UsnJrnl:$J` keeps `FileCreate`→`FileDelete` reason codes and the original name even after `sdelete`/`cipher /w`, and `$MFT` slack/INDX (`INDXParse.py`) can hold the directory entry — prior existence is provable when the file is gone. `[SANS FOR508 USN guidance · high]`
- **Staging long postdates initial access.** APT collection is often bundled into a password-protected RAR/7z split archive in `%TEMP%`/`\Users\Public\` days or weeks after entry; the gap between first-access and archive create time is itself diagnostic of dwell. `[MITRE T1560.001 · high]`
- **Pagefile/unallocated spill defeats secure deletion of commands.** Decoded PowerShell, C2 URLs, and tool strings the operator wiped from disk frequently remain in `pagefile.sys` and unallocated clusters — recover with `page-brute`/`bulk_extractor` when on-disk artifacts are clean. `[general DFIR memory-spill practice · med]`
- **Distrust host time around anti-forensics.** Operators time work for off-hours and some manipulate the clock; if the timeline is internally impossible, anchor to monotonic `EventRecordID` and `$J` USN sequence rather than `$SI`/host time. `⚠️verify any timeline keyed purely to host clock.` `[general DFIR anti-forensics practice · med]`

## ATT&CK mapping
- T1078 · Valid Accounts · long-dwell access via stolen/valid creds — steps 6/7
- T1543.003 · Persistence · Windows Service · redundant service autorun — step 6
- T1053.005 · Persistence · Scheduled Task — step 6
- T1547.001 · Persistence · Registry Run Keys / Startup — step 6
- T1546.003 · Persistence · WMI Event Subscription — step 6
- T1218 · Defense Evasion · System Binary Proxy Execution (rundll32/regsvr32/mshta) — steps 6/7
- T1059.001 · Execution · PowerShell (encoded / download cradle) — step 7
- T1105 · Command and Control · Ingress Tool Transfer (certutil -urlcache / bitsadmin /transfer) — steps 6/7/8
- T1070.001 · Defense Evasion · Clear Windows Event Logs · 1102 / 104 — steps 2/3
- T1070.006 · Defense Evasion · Timestomp · $SI vs $FN — step 4
- T1070.004 · Defense Evasion · File Deletion (secure-delete) · $J FileDelete — step 5
- T1485 · Impact / Anti-forensics · Data Destruction · cipher /w over free space — steps 5/8
- T1562.002 · Defense Evasion · Disable Windows Event Logging · 1100 / 4719 — steps 2/3
- T1560.001 · Collection · Archive Collected Data via Utility (RAR/7z) — step 9
- T1195 · Initial Access · Supply Chain Compromise (trusted-implant theory) — steps 7/10

## Pivots (lead-to-lead graph)
- `on_persistence_in_registry (step 6 service/task/run/WMI): windows-registry-persistence — confirm the redundant autoruns in the hive`
- `on_lolbin_execution (step 6/7 built-in binary + arguments): malware-analysis-triage — triage the encoded payload / non-standard DLL the LOLBin pulled`
- `on_log_clear_or_gap (step 2/3 1102/104/record-id break): SELF — re-enter with the clearing timestamp bound into #{time_window} to bracket what was hidden`
- `on_credential_or_domain_movement (step 6/7 lateral creds): active-directory-domain — domain credential theft and the DC side of long-dwell movement`
- `on_full_intrusion_reconstruction (step 10 super-timeline): attack-lifecycle-hunting — map the dwell chronology end-to-end onto ATT&CK`
- `on_staged_archive (step 9 RAR/7z/ZIP): insider-threat-data-theft — trace the collection/exfil channel for the staged data`
- `on_c2_in_pagefile (step 8 recovered URL/IP): network-forensics — run the C2 indicators against any captured PCAP/flow`
- `on_memory_image_present (step 0 RAM captured): memory-forensics — malfind/svcscan/netscan for the live implant`
- `on_evidence_unmountable (step 0/1): acquisition-custody — re-acquire or prove the collection gap`

## Jargon decoder
- **APT (Advanced Persistent Threat):** a skilled, patient, usually well-resourced attacker who stays hidden inside a network for a long time (long dwell) to pursue a specific goal.
- **Long dwell:** the weeks-to-months an attacker remains undetected between first access and discovery.
- **Anti-forensics:** deliberate steps to destroy or fake evidence — clearing logs, faking file dates, secure-deleting tools.
- **Timestomp:** backdating or zeroing a file's timestamps to hide when it really appeared.
- **$MFT / $SI vs $FN:** NTFS Master File Table; each file record has two timestamp sets — `$SI` (StandardInformation, easy to forge) and `$FN` (FileName, harder). Disagreement hints at timestomp.
- **$UsnJrnl:$J (change journal):** NTFS's running log of file create/rename/delete operations — tamper-resistant order that survives even when a file is secure-deleted or its `$SI` is faked.
- **EventRecordID:** a per-file counter in an EVTX log that increases by one per event; a break in the sequence = log tampering even with no explicit clear-event.
- **1102 / 104:** "the audit log was cleared" (Security) / "the event log was cleared" (System) — classic anti-forensics.
- **LOLBin / living-off-the-land:** using built-in, signed operating-system tools (`powershell`, `certutil`, `bitsadmin`, `rundll32`, `wmic`, `mshta`) for attacker purposes, so there is no malware file to find — only suspicious *arguments*.
- **UserAssist / BAM / DAM:** registry traces of programs a user/system actually ran — execution evidence used to corroborate a LOLBin.
- **WMI event consumer:** a stealthy persistence method that runs a command when a system condition fires, with no file on disk and no Run key.
- **Secure delete (cipher /w, sdelete):** overwriting a file's content so it cannot be recovered — but the `$J` entry and `$MFT` slack often still prove it existed.
- **Staging / staged archive:** bundling stolen data into a (often password-protected, split) RAR/7z/ZIP before sending it out — a collection step that usually long postdates initial access.
- **ssdeep (fuzzy hash):** a similarity hash that matches near-identical files — here, the substitute for an absent memory baseliner, comparing suspects to a known-good/known-bad corpus.
- **densityscout / entropy:** a measure of randomness; high entropy means packed/encrypted/compressed content (an archive or a packed implant).
- **page-brute / pagefile spill:** scanning `pagefile.sys` for in-memory data that spilled to disk — recovers commands/C2 the operator wiped from the file system.
- **Super-timeline:** one merged chronology across many artifacts, built with `log2timeline.py` + `psort.py`; anchored here to `$J`/EventRecordID, not host time.
- **Supply-chain / implant:** compromising a trusted vendor's update or component so the malicious code arrives signed and trusted.
- **wtmp / btmp / auth.log (Linux):** the logon / bad-logon / SSH-auth logs — the Linux analogs of Windows logon events.

## Tuning log (append-only — the eval loop writes here; humans never edit rows)
| date | case_id | bucket missed | delta applied |
|---|---|---|---|
