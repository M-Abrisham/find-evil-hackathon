---
attack_type: disk-filesystem
category_id: disk-filesystem
name: Endpoint / Disk & File System
description: file-system structures (MFT, partitions, deleted and hidden data) on disk images
version: 1
os_coverage: [windows, linux, macos, cloud]
sub_types_covered: 9
sub_types:
  - mft-record-analysis
  - partition-layout-and-lost-partitions
  - deleted-file-recovery
  - alternate-data-streams
  - slack-and-unallocated-space
  - timestomp-detection-si-vs-fn
  - hidden-or-encrypted-volumes
  - usnjrnl-change-journal
  - logfile-transactions
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
    derive: "case brief if it names one; else first confirmed malicious timestamp ±48h once a step pins one — then re-scope wide sweeps to it"
---

## In one line
A disk image is a frozen snapshot of every file, every deleted file, and every leftover scrap on a computer's storage. This playbook reads the file system's own bookkeeping — the master index of files, the partition map, the change journals, and the space the operating system thinks is empty — to find what was hidden, deleted, back-dated, or stashed in a place ordinary tools never look.

## Use this when (triggers)
- You have a **disk image** (E01/dd/raw/vmdk) and need to know what files exist, **what was deleted**, and when — independent of any application log.
- A file's timestamps look **wrong or back-dated** (a "new" malware binary claiming a creation date from years ago) — classic **timestomp**, which the file system records twice and one copy is hard to forge.
- Data may be **hidden** — in an **Alternate Data Stream** (a file riding piggyback on another file), in **slack** or **unallocated** space, in a **deleted-but-not-overwritten** file, or behind a **hidden/encrypted partition** the partition table doesn't advertise.
- The **partition layout** is suspicious — a wiped or lost partition, an unexpected gap, a second OS or a hidden volume.
- You need a **file-system timeline** (created/modified/accessed/changed for every file) to anchor the whole case, or to prove a file **existed before it was deleted** via the change journal.
- Application logs are gone or untrustworthy and you must fall back to the **lowest-level evidence on the box**: the file system itself.

## Quick path (the 90% case)
1. **Timeline-first.** Build a file-system timeline before any story: parse `$MFT` (and `$J`) with `MFTECmd` sorted by time, OR build a bodyfile with `fls -m`/`tsk_gettimes` and render it with `mactime`. Skim it inside `#{time_window}` — the order of *file created → file modified → file deleted → space reused* is the case. (Fold into a super-timeline with `log2timeline.py` + `psort.py` if cross-artifact context is needed.)
2. **Map the disk.** Run `mmls #{image_path}` for the partition layout and `fsstat` per partition for the file-system type and Volume Serial Number; flag any **unallocated gap** between partitions (a lost/hidden volume) and run `sigfind` for a boot signature inside the gap.
3. **Recover the deleted.** `fls -rd` lists deleted names; `ils` finds orphaned metadata `fls` misses; `icat` pulls back the content of a deleted inode for hashing; `usnjls`/`usn.py` proves a file **existed and was deleted** even when its content is gone.
4. **Catch the hiding.** Compare `$SI` vs `$FN` timestamps with `MFTECmd`/`istat` for **timestomp**; enumerate **Alternate Data Streams** in the `$MFT` (extra `$DATA` attributes) and `icat` them by `inode-128-N`; carve **slack/unallocated** with `blkls`/`tsk_recover` and attribute hits back with `ifind`.
5. **Corroborate.** A file's `$MFT` create time and its `$UsnJrnl` create/delete record are two independent file-system sources; a recovered binary's hash should match what other modalities (event logs, registry execution traces) reference. One layer is a lead, not a fact.

If the timeline, the partition map, the deleted-file recovery, and the hiding-checks all line up with a corroborating second source → you're mostly done. Otherwise drop into the full Steps.

## How it unfolds (the story)
An actor (or a careless insider) writes data to disk, then tries to make it disappear: they delete files (which only unlinks them — the content lingers in unallocated space until overwritten), back-date a dropped binary's timestamps so it blends into the OS install, tuck a second payload into an Alternate Data Stream so directory listings never show it, or hide a whole volume the partition table doesn't advertise. The file system, however, keeps its own redundant bookkeeping — the `$MFT` records two timestamp sets, the `$UsnJrnl` logs every create/rename/delete, the `$LogFile` journals transactions, and "freed" clusters keep their bytes — so the original truth is recoverable from the disk image long after the application-level evidence is gone.

## Theories to test (and how to rule each out)
| Theory (who / why) | If true, you'd find… | Rule it out if… |
|---|---|---|
| **External-targeted (intruder hiding tooling on disk)** | a dropped binary with `$SI` back-dated but `$FN` recent (timestomp); an ADS payload; the binary in `\Users\Public\`/`%TEMP%`/`\ProgramData\`; a `$J` create record minutes before a delete | every executable's `$SI`/`$FN` agree, no ADS beyond `Zone.Identifier`, no recently-created binary in user-writable dirs, no suspicious `$J` create→delete burst |
| **Insider (authorized user exfiltrating then wiping)** | deleted archives/documents recoverable from unallocated; `$J` records of files created then deleted; a hidden/encrypted container; staging folder remnants in slack | no deleted user-data of value, `$J` shows only routine churn, no hidden volume, unallocated carving yields nothing relevant |
| **Anti-forensics / evidence destruction** | a wiped or lost partition (`mmls` gap + `sigfind` boot sig), a truncated `$UsnJrnl`/`$LogFile`, mass same-second `$SI` overwrite (timestomp tool), `tsk_recover` returning zero-byte/overwritten clusters | partition table is intact and accounts for all space, journals are continuous, timestamps vary naturally, deleted content recovers cleanly |
| **Hidden/encrypted data store** | an unmounted partition with high entropy / no recognizable FS (`fsstat` fails), a BitLocker/LUKS signature, a large opaque file, a partition the OS never mounted | every partition `fsstat`-identifies as a normal FS, no encrypted-container signatures, no unexplained large opaque region |
| **Supply-chain / legitimate-tool artifact** | the "suspicious" file is a signed vendor binary in `\Program Files\`, ADS is a benign `Zone.Identifier` (Mark-of-the-Web), the deleted files are installer temp, the extra partition is a vendor recovery/EFI partition | path + signing + a sanctioned source explain it AND timestamps are internally consistent → benign; reclassify |
| **Innocent / benign (NOT an attack)** | deleted files are browser cache / recycle churn, ADS is `Zone.Identifier`/`favicon`, the "lost" partition is the OEM recovery or MSR partition, timestamps reflect normal install/update | a documented OEM/recovery/EFI layout and ordinary user deletion fully explain every finding; no payload, no hiding intent |

*(≥1 benign + ≥1 malicious, each ACTIVELY refuted. Attacker types mapped: insider · other-insider · external-commodity · external-targeted · supply-chain · innocent.)*

## Evidence → Tool → What it reveals (per OS)
| Evidence | SIFT tool | What it tells you *for this attack* | OS |
|---|---|---|---|
| `$MFT` (every file record: `$SI`/`$FN` MACB, runlist, ADS `$DATA` attrs) | `MFTECmd` / `analyzeMFT` / `istat` | File existence + full timeline; **timestomp** ($SI vs $FN disagreement); Alternate Data Streams (extra $DATA); resident/non-resident data location | Windows (NTFS) |
| `$UsnJrnl:$J` change journal | `usnjls` / `usn.py` (`MFTECmd` also parses `$J`) | File **create/rename/delete history** — proves a deleted file once existed and when it was removed, catches rename-masquerade | Windows (NTFS) |
| `$LogFile` transactions | `jls` / `jcat` (`MFTECmd` parses `$LogFile`) | Recent FS transactions just before capture; corroborates a $J create/delete when the journal wrapped | Windows (NTFS) |
| `$Boot` / boot sector + superblock | `fsstat` | FS type & geometry; **Volume Serial Number** (correlates to LNK/USB leads); cluster size for slack math | Windows/Linux |
| Partition table (MBR/GPT) | `mmls` / `sigfind` | Partition **layout**, offsets to feed `-o`, and **unallocated gaps = lost/hidden volumes**; `sigfind` finds a boot signature in a wiped region | all |
| Directory entries / deleted names | `fls -rd` / `ffind` / `ifind` | Deleted file **names** and the inode↔name binding; recovers names `ils` can't | Windows/Linux |
| Orphaned / deleted metadata | `ils` / `istat` | Deleted **inodes** with no directory entry (orphans) and their MACB/runlist | Windows/Linux |
| Deleted/ADS **content** | `icat` (`-s` for slack; `inode-128-N` for an ADS) / `tsk_recover` | Pulls back recoverable bytes for **hashing/triage**; bulk-recovers unallocated | Windows/Linux |
| Unallocated & slack space | `blkls -e` / `blkstat` / `tsk_recover` / `bulk_extractor` | Raw freed clusters for carving; `ifind` ties a hit back to its owning inode | all |
| INDX directory index (incl. slack) | `INDXParse.py` | Proof a file **existed inside a folder** even after deletion (slack INDX entries) | Windows (NTFS) |
| Volume Shadow Copies | `vshadowinfo` / `vshadowmount` | **Historical** point-in-time states of the same FS — recovers a file before it was altered/deleted | Windows |
| All artifacts fused | `log2timeline.py` + `psort.py` (+ `pinfo.py`) | One chronology placing create → modify → delete → space-reuse in order | all |
| Image-wide string/feature sweep | `bstrings` / `srch_strings` / `bulk_extractor` | Paths, URLs, account names spilled into slack/unallocated outside any file | all |
| Linux ext/xfs metadata + journal | `fls`/`ils`/`icat`, `jls`, `mactime`, `log2timeline.py` | Deleted-inode recovery, ext3/4 journal transactions — the Linux equivalent of $MFT/$UsnJrnl work | Linux |

*BitLocker/LUKS unlocking on this box: `bdemount` (BitLocker FUSE) is NOT in the run-verified list — `⚠️verify` before relying on it; treat an encrypted volume as a recorded finding and unlock off-box, or recover historical plaintext via `vshadowmount` where shadow copies predate encryption.*

## Step 0 — evidence inventory & access bootstrap
- n: 0
  tool: |
    mkdir -p "#{case_out}/receipts" "#{case_out}/extracted" && ls -laR "#{mount_root}" > "#{case_out}/receipts/00.txt" 2>&1 ; img_stat "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; mmls "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; fsstat -o #{ntfs_offset_sectors} "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; fls -o #{ntfs_offset_sectors} "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1
  expect: every evidence file classified; #{image_path}, #{mount_root}, #{ntfs_offset_sectors}, #{case_out} bound; read-only access proven; mmls lists the partitions with offsets, fsstat names the FS type + Volume Serial Number, and a root listing confirms the file system is readable — or absence/unreadability is recorded as a finding
  check: |
    test -r "#{mount_root}" -o -n "$(ls "#{case_out}/extracted" 2>/dev/null)" -o -s "#{case_out}/receipts/00.txt"
  falsify: evidence dir empty/unreadable, or no supported image format found by img_stat, or mmls/fsstat report no recognizable partition or file system
  on_result: {expect_met: goto 1, falsify_met: STOP — report acquisition/access failure; pivot acquisition-custody, neither: try the icat-extract fallback (fls to find target inodes, icat $MFT/$UsnJrnl into #{case_out}/extracted); if that also fails, treat as falsify_met}
  emits: [key_artifacts]
  serves: [mft-record-analysis, partition-layout-and-lost-partitions, deleted-file-recovery, alternate-data-streams, slack-and-unallocated-space, timestomp-detection-si-vs-fn, hidden-or-encrypted-volumes, usnjrnl-change-journal, logfile-transactions]
  provenance: {receipt_id: 00, artifact: evidence directory listing + mmls/fsstat output, offset_or_row: full listing + partition table, literal_cited: image filename + FS type + Volume Serial Number}

## Steps (executable — decision-driven)
- n: 1
  precondition: "test -s #{case_out}/receipts/00.txt"
  tool: |
    mmls "#{image_path}" > "#{case_out}/receipts/01.txt" 2>&1 ; for off in $(mmls "#{image_path}" 2>/dev/null | grep -iE "ntfs|fat|ext|xfs|hfs|0x07|basic data" | awk '{print $3}' | sed 's/^0*//;s/^$/0/'); do fsstat -o "$off" "#{image_path}" >> "#{case_out}/receipts/01.txt" 2>&1 ; done ; sigfind "#{image_path}" >> "#{case_out}/receipts/01.txt" 2>&1
  expect: every partition accounted for, each fsstat-identified as a known FS; any UNALLOCATED gap large enough to hold a volume is flagged, and sigfind reports a boot signature (0x55AA at a sector boundary) INSIDE a supposedly-empty gap — evidence of a lost/hidden partition
  check: |
    grep -qiE "File System Type|NTFS|FAT|Ext|XFS|HFS" "#{case_out}/receipts/01.txt"
  falsify: the partition table cleanly accounts for all sectors with no unexplained gap, and sigfind finds no boot signature in any unallocated region — no lost/hidden volume at the partition layer
  on_result: {expect_met: record partition layout + any lost-volume offset; goto 2, falsify_met: record "partition layout intact, no hidden volume"; goto 2, neither: run fsstat/sigfind directly on the suspect gap offset; if a volume is encrypted (no recognizable FS, high entropy) record it as hidden-or-encrypted-volumes and note bdemount is ⚠️verify}
  emits: [key_artifacts]
  serves: [partition-layout-and-lost-partitions, hidden-or-encrypted-volumes]
  provenance: {receipt_id: 01, artifact: MBR/GPT partition table + boot sectors, offset_or_row: mmls rows + sigfind hits, literal_cited: partition start sector + FS type or the 0x55AA signature offset}

- n: 2
  precondition: "test -r #{mount_root}"
  tool: |
    dotnet /opt/zimmermantools/MFTECmd.dll -f "#{mount_root}/\$MFT" --csv "#{case_out}" --csvf mft.csv > "#{case_out}/receipts/02.txt" 2>&1 ; dotnet /opt/zimmermantools/MFTECmd.dll -f "#{mount_root}/\$Boot" --csv "#{case_out}" --csvf boot.csv >> "#{case_out}/receipts/02.txt" 2>&1
  expect: a normalized #{case_out}/mft.csv with one row per file record carrying Created/Modified/Accessed/Changed for BOTH $SI (0x10) and $FN (0x30), the parent path, and per-stream $DATA rows — the master artifact every later step filters; row count roughly matches the file count
  check: |
    test -s "#{case_out}/mft.csv" && grep -qiE "FileName|Created0x10|SI<FN|InUse" "#{case_out}/mft.csv"
  falsify: $MFT absent/unreadable at #{mount_root} (not mounted, or extraction failed), or MFTECmd errors on every record (corrupt $MFT)
  on_result: {expect_met: goto 3, falsify_met: icat $MFT by inode 0 into #{case_out}/extracted and re-run MFTECmd -f on it; if still unreadable fall back to analyzeMFT, then to fls -rm bodyfile + mactime for at least a name/time timeline, neither: re-run MFTECmd on the extracted copy; if maps differ adjudicate from the raw csv columns}
  emits: [key_artifacts, timeline_events]
  serves: [mft-record-analysis]
  provenance: {receipt_id: 02, artifact: $MFT (+ $Boot), offset_or_row: mft.csv header + row count, literal_cited: MFTECmd processed-record count line}

- n: 3
  precondition: "test -s #{case_out}/mft.csv"
  tool: |
    fls -rm C -o #{ntfs_offset_sectors} "#{image_path}" > "#{case_out}/bodyfile.txt" 2>"#{case_out}/receipts/03.txt" ; mactime -b "#{case_out}/bodyfile.txt" -d > "#{case_out}/timeline.csv" 2>>"#{case_out}/receipts/03.txt" ; head -n 50 "#{case_out}/timeline.csv" >> "#{case_out}/receipts/03.txt" 2>&1
  expect: a sorted MACB file-system timeline (#{case_out}/timeline.csv) covering allocated AND deleted entries; inside #{time_window} the create→modify→delete ordering is coherent, with any burst of same-second activity (mass create/delete, or a timestomp run) standing out
  check: |
    test -s "#{case_out}/timeline.csv" && grep -qiE ",m\.\.\.|,\.a\.\.|,\.\.c\.|,\.\.\.b|macb|MACB" "#{case_out}/timeline.csv"
  falsify: the timeline is empty (no FS metadata recovered) or shows only smooth, expected churn with no burst, no deleted entries, and no same-second timestamp cluster
  on_result: {expect_met: bracket the suspicious window; narrow #{time_window} to it; goto 4, falsify_met: record "FS timeline shows no anomalous burst"; continue to the deleted/ADS/timestomp checks anyway at goto 4, neither: widen #{time_window}; rebuild from tsk_gettimes if fls missed orphans, then re-render with mactime}
  emits: [timeline_events]
  serves: [mft-record-analysis, slack-and-unallocated-space]
  provenance: {receipt_id: 03, artifact: fls bodyfile → mactime timeline, offset_or_row: timeline.csv ordered rows, literal_cited: the burst/same-second MACB row}

- n: 4
  precondition: "test -s #{case_out}/mft.csv"
  tool: |
    awk -F',' 'NR==1 || tolower($0) ~ /(deleted|in ?use.*false|free)/' "#{case_out}/mft.csv" > "#{case_out}/receipts/04.txt" 2>&1 ; fls -rd -o #{ntfs_offset_sectors} "#{image_path}" >> "#{case_out}/receipts/04.txt" 2>&1 ; ils -o #{ntfs_offset_sectors} "#{image_path}" >> "#{case_out}/receipts/04.txt" 2>&1 ; tsk_recover -o #{ntfs_offset_sectors} "#{image_path}" "#{case_out}/extracted" >> "#{case_out}/receipts/04.txt" 2>&1
  expect: deleted files of interest — names from fls -rd, orphan inodes from ils, and recovered content under #{case_out}/extracted via tsk_recover — ideally deleted archives/documents/executables inside #{time_window}; each recoverable inode can be hashed and pivoted
  check: |
    grep -qiE "^\s*[r-]/[r-]\s+\*|in.?use.*false|deleted" "#{case_out}/receipts/04.txt" || test -n "$(ls "#{case_out}/extracted" 2>/dev/null)"
  falsify: no deleted entries in fls -rd / ils, and tsk_recover returns nothing or only zero-byte/overwritten stubs — no recoverable deleted data
  on_result: {expect_met: hash each recovered file; record paths + hashes as IOCs; goto 5, falsify_met: record "no recoverable deleted files"; the clusters may be overwritten (anti-forensics) — note it and proceed to carving at goto 6, neither: icat the specific orphan inodes from ils into #{case_out}/extracted and hash them; check $UsnJrnl (step 7) for prior existence}
  emits: [key_artifacts, key_iocs]
  serves: [deleted-file-recovery]
  provenance: {receipt_id: 04, artifact: $MFT deleted records + fls/ils + recovered files, offset_or_row: receipts/04.txt deleted rows / extracted/ listing, literal_cited: deleted filename + inode + recovered-file hash}

- n: 5
  precondition: "test -s #{case_out}/mft.csv"
  tool: |
    awk -F',' 'NR==1 || ($0 ~ /\$DATA/ && tolower($0) !~ /zone\.identifier/ && $0 ~ /:/)' "#{case_out}/mft.csv" > "#{case_out}/receipts/05.txt" 2>&1 ; grep -iE "ADS|:[A-Za-z0-9_]+(,|$)|Alternate" "#{case_out}/mft.csv" >> "#{case_out}/receipts/05.txt" 2>&1
  expect: Alternate Data Streams beyond the benign Zone.Identifier (Mark-of-the-Web) — a host file carrying an EXTRA named $DATA stream (e.g. file.txt:hidden.exe), often an executable or script tucked behind an innocuous-looking file; record the host inode and stream name so it can be extracted by icat as inode-128-N
  check: |
    grep -qiE "\$DATA|:[A-Za-z0-9_]+" "#{case_out}/receipts/05.txt" && ! grep -qiE "^\s*$" "#{case_out}/receipts/05.txt"
  falsify: every multi-$DATA record is a benign Zone.Identifier or :favicon stream, no executable/script content hidden in an ADS
  on_result: {expect_met: icat the ADS by inode-128-N into #{case_out}/extracted and hash it; record as IOC; goto 6, falsify_met: record that only the benign Zone.Identifier stream is present; goto 6, neither: list the host file streams with istat and icat each named stream; if the stream looks packed flag for malware-analysis-triage}
  emits: [key_iocs]
  serves: [alternate-data-streams]
  provenance: {receipt_id: 05, artifact: $MFT $DATA attributes, offset_or_row: mft.csv ADS rows, literal_cited: host filename + extra stream name (file:stream)}

- n: 6
  precondition: "test -s #{case_out}/receipts/00.txt"
  tool: |
    blkls -e -o #{ntfs_offset_sectors} "#{image_path}" > "#{case_out}/unalloc.bin" 2>"#{case_out}/receipts/06.txt" ; bulk_extractor -o "#{case_out}/bulk" "#{case_out}/unalloc.bin" >> "#{case_out}/receipts/06.txt" 2>&1 ; srch_strings -t d "#{case_out}/unalloc.bin" 2>/dev/null | grep -iE "http|\.exe|\.ps1|password|BEGIN |-----" | head -n 200 >> "#{case_out}/receipts/06.txt" 2>&1
  expect: indicators living OUTSIDE any allocated file — in slack/unallocated space: URLs, command fragments, credentials, key material, or carved file headers; bulk_extractor feature files (url, email, etc.) plus string hits inside #{time_window}; a hit can be tied back to its owning inode with ifind for attribution
  check: |
    test -s "#{case_out}/unalloc.bin" && { test -d "#{case_out}/bulk" || grep -qiE "http|\.exe|\.ps1|password|BEGIN " "#{case_out}/receipts/06.txt"; }
  falsify: unallocated space carves to nothing relevant — no indicator strings, no carved payloads, no feature hits inside #{time_window}
  on_result: {expect_met: record carved indicators; ifind any cluster of interest → inode → ffind name; goto 7, falsify_met: record "unallocated yields nothing relevant"; goto 7, neither: re-run bulk_extractor over the whole image (not just unalloc) and re-check; widen the string filter}
  emits: [key_iocs, key_artifacts]
  serves: [slack-and-unallocated-space]
  provenance: {receipt_id: 06, artifact: unallocated/slack space (blkls) + carved features, offset_or_row: srch_strings byte offset / bulk_extractor feature row, literal_cited: the carved URL/path/credential string}

- n: 7
  precondition: "test -r #{mount_root}"
  tool: |
    /opt/usnparser/bin/usn.py -f "#{mount_root}/\$Extend/\$UsnJrnl:\$J" -o "#{case_out}/usnjrnl.csv" > "#{case_out}/receipts/07.txt" 2>&1 ; usnjls -o #{ntfs_offset_sectors} "#{image_path}" >> "#{case_out}/receipts/07.txt" 2>&1 ; jls -o #{ntfs_offset_sectors} "#{image_path}" >> "#{case_out}/receipts/07.txt" 2>&1
  expect: $UsnJrnl:$J change-journal records proving a file of interest was CREATED then DELETED (FILE_CREATE / DATA_OVERWRITE / RENAME_OLD_NAME / FILE_DELETE reason codes) inside #{time_window} — prior existence of a now-gone file, and rename-masquerade (a sensitive name renamed to look benign); $LogFile (jls) corroborates when the journal wrapped
  check: |
    test -s "#{case_out}/usnjrnl.csv" || grep -qiE "USN_REASON|FILE_CREATE|FILE_DELETE|RENAME|CLOSE" "#{case_out}/receipts/07.txt"
  falsify: $UsnJrnl is absent/truncated (fsutil usn deletejournal — itself anti-forensics) and $LogFile shows nothing — no change-journal evidence of the file's lifecycle
  on_result: {expect_met: record the file create/rename/delete timeline as events; tie to the recovered inode from step 4; goto 8, falsify_met: record the journal absence/truncation AS a finding (deletion of $J is anti-forensics); rely on $MFT/$LogFile and pivot SELF with the gap window bound, neither: parse $J via MFTECmd -f on the extracted $J copy and re-check; correlate reason codes with the mft.csv delete time}
  emits: [timeline_events, key_iocs]
  serves: [usnjrnl-change-journal, logfile-transactions]
  provenance: {receipt_id: 07, artifact: $UsnJrnl:$J + $LogFile, offset_or_row: usnjrnl.csv rows / usnjls reason codes, literal_cited: filename + USN reason code (FILE_CREATE/FILE_DELETE/RENAME) + timestamp}

- n: 8
  precondition: "test -s #{case_out}/mft.csv"
  tool: |
    awk -F',' 'NR==1 || tolower($0) ~ /si<fn|true/ ' "#{case_out}/mft.csv" > "#{case_out}/receipts/08.txt" 2>&1 ; grep -iE "SI<FN|Timestomp|0x10|0x30" "#{case_out}/mft.csv" | head -n 200 >> "#{case_out}/receipts/08.txt" 2>&1
  expect: timestomp — records where the $SI (0x10) Created precedes or mismatches the $FN (0x30) Created, or where $SI has a zeroed sub-second/round timestamp while $FN looks natural; MFTECmd flags this (SI<FN column). A back-dated dropper (e.g. a 2009 create date on a binary whose $FN is recent and whose $J create is recent) is the signature
  check: |
    grep -qiE "SI<FN.*(true|yes)|timestomp" "#{case_out}/receipts/08.txt" || grep -qiE "0x30" "#{case_out}/receipts/08.txt"
  falsify: for every file of interest $SI and $FN timestamps agree (or differ only in the normal $FN-lags-$SI way) — no timestomp evidence; the file's dates are internally consistent with its $J create record
  on_result: {expect_met: record the back-dated file as a high-signal IOC; trust $FN/$J order over $SI; goto 9, falsify_met: record "no timestomp on files of interest"; goto 9, neither: istat the specific inode to read both attribute timestamps directly and compare against the $J create time from step 7}
  emits: [key_iocs, timeline_events]
  serves: [timestomp-detection-si-vs-fn]
  provenance: {receipt_id: 08, artifact: $MFT $SI vs $FN timestamps, offset_or_row: mft.csv SI<FN row, literal_cited: filename + $SI Created0x10 vs $FN Created0x30 mismatch}

- n: 9
  precondition: "test -s #{case_out}/mft.csv"
  tool: |
    log2timeline.py --status_view none "#{case_out}/fs.plaso" "#{image_path}" > "#{case_out}/receipts/09.txt" 2>&1 ; psort.py -o l2tcsv "#{case_out}/fs.plaso" > "#{case_out}/super.csv" 2>> "#{case_out}/receipts/09.txt" ; pinfo.py "#{case_out}/fs.plaso" >> "#{case_out}/receipts/09.txt" 2>&1 ; vshadowinfo "#{image_path}" >> "#{case_out}/receipts/09.txt" 2>&1
  expect: a fused super-timeline (filestat + journal parsers) placing file create → modify → ADS write → delete → space-reuse in coherent order inside #{time_window}, with the $MFT/$J/$LogFile findings cross-checked; vshadowinfo reports any Volume Shadow Copies holding a historical (pre-tamper) state to recover from
  check: |
    test -s "#{case_out}/super.csv" && grep -qiE "filestat|NTFS|USN|\$MFT|MFT" "#{case_out}/super.csv"
  falsify: the super-timeline is internally impossible (a file modified before it was created, or a delete with no prior create) with no journal/shadow explanation — points to clock manipulation or wholesale metadata tampering
  on_result: {expect_met: COMMIT the conclusion with a confidence label; close per the gate, falsify_met: re-open the Theories table; anchor to $UsnJrnl USN sequence order rather than $SI host time; recover the clean state from a shadow copy via vshadowmount, neither: run pinfo.py to confirm the filestat/usnjrnl parsers ran; re-filter psort.py to #{time_window} and re-check}
  emits: [timeline_events]
  serves: [mft-record-analysis, usnjrnl-change-journal, deleted-file-recovery]
  provenance: {receipt_id: 09, artifact: fs.plaso super-timeline + VSS catalog, offset_or_row: super.csv ordered rows / vshadowinfo store count, literal_cited: ordered create→modify→delete chain / Number of shadow stores}

## Linux branch (L1..Ln) — REQUIRED, numbered, same step shape
- n: L1
  precondition: "os == linux"
  tool: |
    fsstat -o #{ntfs_offset_sectors} "#{image_path}" > "#{case_out}/receipts/L01.txt" 2>&1 ; mmls "#{image_path}" >> "#{case_out}/receipts/L01.txt" 2>&1 ; fls -o #{ntfs_offset_sectors} "#{image_path}" >> "#{case_out}/receipts/L01.txt" 2>&1
  expect: this image is Linux (ext2/3/4 or xfs per fsstat) — there is NO NTFS $MFT/$UsnJrnl here; the equivalents are the inode table (fls/ils/istat), the ext3/4 journal ($jls), and there are no $SI/$FN dual timestamps (ext4 has crtime/mtime/atime/ctime — single set, so timestomp detection differs)
  check: |
    grep -qiE "ext[234]|xfs|File System Type: Ext|File System Type: XFS" "#{case_out}/receipts/L01.txt"
  falsify: fsstat reports NTFS and a $MFT exists — this is Windows, not Linux; run the main Steps 1–9, not this branch
  on_result: {expect_met: goto L2, falsify_met: this is Windows — run the main branch (Steps 1–9); Linux-only because the $MFT/$UsnJrnl path does not apply, neither: confirm FS family from the Step 0 fsstat receipt; if still ambiguous treat as Windows and run the main branch}
  emits: [key_artifacts]
  serves: [partition-layout-and-lost-partitions, mft-record-analysis]
  provenance: {receipt_id: L01, artifact: fsstat superblock + mmls, offset_or_row: fsstat FS-type header, literal_cited: "ext/xfs FS type (Linux-confirmed)"}

- n: L2
  precondition: "os == linux"
  tool: |
    fls -rd -o #{ntfs_offset_sectors} "#{image_path}" > "#{case_out}/receipts/L02.txt" 2>&1 ; ils -o #{ntfs_offset_sectors} "#{image_path}" >> "#{case_out}/receipts/L02.txt" 2>&1 ; tsk_recover -o #{ntfs_offset_sectors} "#{image_path}" "#{case_out}/extracted" >> "#{case_out}/receipts/L02.txt" 2>&1 ; jls -o #{ntfs_offset_sectors} "#{image_path}" >> "#{case_out}/receipts/L02.txt" 2>&1
  expect: deleted inodes recovered (fls -rd names, ils orphans, tsk_recover content into #{case_out}/extracted) and ext3/4 journal transactions (jls) showing recent file operations — the Linux analog of the deleted-file + $UsnJrnl work; deleted scripts/binaries/archives of interest inside #{time_window}
  check: |
    test -n "$(ls "#{case_out}/extracted" 2>/dev/null)" || grep -qiE "\*|deleted|free" "#{case_out}/receipts/L02.txt"
  falsify: no deleted inodes recoverable (clusters overwritten or securely wiped) and the journal shows nothing of interest — record the wipe as a finding
  on_result: {expect_met: hash recovered files; build the timeline with fls -rm + mactime; commit with a confidence label, falsify_met: record the wipe/overwrite as an anti-forensics finding; carve unallocated with blkls + bulk_extractor; pivot linux-host-forensics, neither: widen #{time_window}; icat specific orphan inodes from ils and hash them}
  emits: [key_artifacts, key_iocs]
  serves: [deleted-file-recovery, slack-and-unallocated-space, logfile-transactions]
  provenance: {receipt_id: L02, artifact: ext inode table + ext journal + recovered files, offset_or_row: receipts/L02.txt deleted rows / extracted/ listing, literal_cited: deleted inode + filename + recovered-file hash}

## Corroboration (two-source rule)
`required_sources: 2` · `pairs:`
- `[ $MFT create time (step 2) ↔ $UsnJrnl FILE_CREATE record (step 7) ]`
- `[ deleted name via fls -rd (step 4) ↔ recovered content via tsk_recover/icat + its hash (step 4/9) ]`
- `[ $SI vs $FN timestomp flag (step 8) ↔ the $J create timestamp that exposes the back-date (step 7) ]`
- `[ ADS extra $DATA in $MFT (step 5) ↔ the icat-extracted stream content + hash (step 5) ]`
- `[ lost-partition mmls gap (step 1) ↔ sigfind boot signature inside that gap (step 1) ]`
- `[ carved unallocated indicator (step 6) ↔ ifind→inode→ffind name binding (step 6) ]`
- `[ FS metadata chronology (step 3) ↔ fused super-timeline + shadow-copy state (step 9) ]`

One hit is a *lead*; promote to *fact* only when its paired source agrees.

## Don't get fooled (red flags & anti-forensics)
- **Deletion is not destruction.** A "deleted" file is only unlinked — its content sits in unallocated space until a new write reuses the clusters. Always carve (`blkls`/`tsk_recover`) and check `$UsnJrnl` before concluding a file is gone. **Missing evidence is itself a finding.**
- **Timestomp forges $SI, not $FN.** Tools that back-date a file rewrite the `$STANDARD_INFORMATION` (0x10) times that Explorer shows, but the `$FILE_NAME` (0x30) times only update on rename/move — so `$SI < $FN`, a zeroed sub-second, or a round timestamp betrays the forgery. Trust `$FN` and the `$J` create record over `$SI`.
- **A wiped/lost partition hides in plain sight.** `mmls` may show an "unallocated" gap that actually holds a deleted partition; run `sigfind` for the `0x55AA` boot signature inside the gap, and `fsstat` at the suspected offset. A gap that exactly fits a volume is a red flag.
- **Alternate Data Streams are invisible to `dir`/`ls`.** A payload in `file.txt:evil.exe` never appears in a normal listing or in most copies. Only the `$MFT` (extra `$DATA` attribute) or `icat inode-128-N` reveals it — but most ADS are the benign `Zone.Identifier` (Mark-of-the-Web); don't cry wolf on those.
- **`$UsnJrnl`/`$LogFile` can be deleted or wrap fast.** `fsutil usn deletejournal` is anti-forensics — a truncated or absent `$J` is itself a finding, not "no activity." The `$LogFile` wraps in minutes-to-hours, so its silence proves nothing about older events.
- **`tsk_recover` returning zero-byte stubs ≠ "nothing was there."** Overwritten clusters yield empty or partial files; that pattern can indicate deliberate wiping (sdelete/cipher). Cross-check `$UsnJrnl` for the file's prior existence.
- **Reallocated `$MFT` entries lie about names.** An inode can be reused; confirm a deleted name with `ffind`/`ifind` rather than trusting a single `istat` listing.
- **Encrypted volumes look like noise.** A partition `fsstat` can't identify, with high entropy and no FS signature, may be BitLocker/LUKS — record it as a hidden/encrypted-volume finding; `bdemount` is `⚠️verify` on this box, so unlock off-box or recover plaintext from a pre-encryption shadow copy.
- **Clock manipulation poisons host time.** If the FS timeline is internally impossible, anchor to the monotonic `$UsnJrnl` USN sequence numbers (and `$LogFile` LSNs) rather than `$SI` timestamps.

## Failure modes
```
- mode: evidence-access failure — the disk won't mount or $MFT/$UsnJrnl is unreadable at #{mount_root}
  guard: Step 0 fallback chain — ewfmount/loop RO, else TSK fls/icat the $MFT/$UsnJrnl inodes into #{case_out}/extracted and parse the extracted copy; if all fail, record acquisition failure and pivot acquisition-custody
- mode: primary-artifact-absent — $MFT or $UsnJrnl missing, truncated, or zero-length (corrupt, never collected, or deleted by fsutil)
  guard: record the absence as a finding (journal deletion IS anti-forensics evidence); name the secondary sources ($LogFile via jls, fls/ils metadata, $MFT residue, shadow copies, carved unallocated) and pivot file-recovery-carving / acquisition-custody
- mode: tool-output drift — MFTECmd CSV column names change (SI<FN renamed) or a comma-in-field breaks an awk/grep literal so check exits 2
  guard: on check exit 2, adjudicate from the prose expect/falsify against the receipt, cap confidence at inferred; fall back to istat/analyzeMFT and read the raw $SI/$FN attributes directly, never silently pass
- mode: overwritten clusters — tsk_recover yields zero-byte/partial files (clusters reused or wiped)
  guard: do not infer "nothing was deleted"; corroborate prior existence via $UsnJrnl FILE_CREATE/FILE_DELETE and INDX slack (INDXParse.py); record the overwrite/wipe pattern as a finding
- mode: encrypted/hidden volume — a partition fsstat cannot identify (BitLocker/LUKS) blocks file-system analysis
  guard: record the encrypted volume as a finding; bdemount is ⚠️verify here so unlock off-box, or recover a pre-encryption state from a Volume Shadow Copy (vshadowmount); do not claim the volume is empty
```
Minimum set every playbook covers: evidence-access failure (Step 0 fallback chain) · primary-artifact-absent (absence recorded, secondary source named) · tool-output drift (`check` exits 2 → prose adjudication, never silent pass).

## Confidence labeling (observation → inference → conclusion)
- **confirmed:** direct receipt verbatim (e.g. the `$MFT` row + the recovered file's hash) + ≥2 independent sources agree ($MFT + $UsnJrnl, or recovered content + carved string) + no unrefuted counter-theory.
- **inferred:** grounded but single-source/interpretive — e.g. a `$SI<$FN` flag with no corroborating `$J` create yet, an orphan inode with no recoverable name, or an ADS not yet extracted → hedge and tag `⚠️verify`. Every `check`-exit-2 adjudication lands here at best.
- **insufficient_evidence:** precondition unmet (`$MFT` absent; journal deleted; clusters overwritten; volume encrypted) or sources conflict → abstain; state what's missing, do not guess.

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
- **Windows (NTFS):** fully covered above — `$MFT` (with dual `$SI`/`$FN` timestamps), `$UsnJrnl:$J`, `$LogFile`, INDX, and ADS make NTFS the richest file system for this attack type.
- **Linux/ESXi (ext/xfs):** see the numbered Linux branch (L1–L2). No `$MFT`/`$UsnJrnl`; the inode table (`fls`/`ils`/`istat`), the ext3/4 journal (`jls`), and `tsk_recover` carry deleted-file recovery. ext4 keeps a single timestamp set (crtime/mtime/atime/ctime) — there is no `$SI`-vs-`$FN` split, so timestomp detection relies on journal/superblock cross-checks and is weaker. xfs has no SIFT-native deep-recovery parser beyond TSK — `⚠️verify` for xfs-specific recovery.
- **macOS (APFS/HFS+):** TSK reads HFS+; APFS deep analysis on this box is degraded (`mac_apt` is flagged absent/broken — `⚠️verify`), so treat APFS file-system findings as lead-only and mount/parse off-box. Pivot macos-forensics.
- **Cloud / virtualized disks:** a VMDK/VHDX is just a container — `mmls`/`fsstat`/TSK work once it's exposed as a raw device. There is no cloud-native "file system" beyond the guest's; investigate the guest image with this playbook and the control-plane separately.

## Real-case notes (non-obvious things to look for)
- **The strongest timestomp tell is a $SI sub-second of all zeros.** Many timestomp tools (and the classic `SetMACE`/`timestomp` lineage) set `$SI` Created with a zeroed 100-ns fraction while a legitimately-created file has a noisy sub-second value; compare against `$FN` (which they usually leave alone) and the `$J` create record. `[SANS FOR508 / Windows timestamp forensics · high]`
- **$UsnJrnl survives the file it describes.** Even after a file is deleted and its `$MFT` entry reused, the `$UsnJrnl:$J` retains FILE_CREATE → FILE_DELETE reason codes naming it — often the only proof a now-vanished tool ever ran on the host. Always parse `$J` when execution looks empty. `[Microsoft USN docs / MITRE T1070.004 · high]`
- **Alternate Data Streams hide whole executables, not just Mark-of-the-Web.** While most ADS are benign `Zone.Identifier`, attackers stash payloads in `legit.txt:payload.exe` that never show in `dir`; the `$MFT` extra `$DATA` attribute and `icat inode-128-N` are the only reliable reveals. `[MITRE T1564.004 · high]`
- **A "lost" partition in an mmls gap can hold an entire second OS or a staging volume.** Wiping the partition table (not the data) leaves the volume invisible to the OS but intact on disk; `sigfind` for `0x55AA`/FS signatures inside the unallocated gap, then `fsstat` at that offset, recovers it. `[TSK partition-recovery practice · med]`
- **INDX slack proves a file was IN a folder even after total deletion.** Directory index records ($I30) retain "slack" entries for files removed from the folder; `INDXParse.py` over the folder's `$I30` recovers names/sizes/timestamps the `$MFT` no longer holds. `[INDXParse / NTFS INDX research · med]`
- **Volume Shadow Copies are a time machine for tampered files.** When a file was altered or deleted after a VSS snapshot, `vshadowinfo`/`vshadowmount` expose the pre-tamper state — recover the original from the shadow store rather than trusting the live FS. `[Microsoft VSS / SANS FOR508 · high]`
- **Distrust host time around destructive activity.** Wipers and clock-rollback attacks make `$SI` MACB times unreliable; anchor the timeline to the monotonic `$UsnJrnl` USN sequence and `$LogFile` LSN ordering, which an attacker rarely rewrites consistently. `⚠️verify any timeline keyed purely to $SI host time.` `[general DFIR anti-forensics practice · med]`

## ATT&CK mapping
- T1070.004 · Defense Evasion · Indicator Removal: File Deletion · deleted files recovered from unallocated / proven via $UsnJrnl — steps 4/7
- T1070.006 · Defense Evasion · Indicator Removal: Timestomp · $SI vs $FN mismatch in the $MFT — step 8
- T1564.004 · Defense Evasion · Hide Artifacts: NTFS Alternate Data Streams · extra $DATA attribute in the $MFT — step 5
- T1564.001 · Defense Evasion · Hide Artifacts: Hidden Files and Directories · hidden volume / unmounted partition — step 1
- T1027 · Defense Evasion · Obfuscated/Hidden Information · payload stashed in slack/ADS/encrypted volume — steps 5/6
- T1485 · Impact · Data Destruction · wiped partition / overwritten clusters (tsk_recover stubs) — steps 1/4
- T1561.002 · Impact · Disk Structure Wipe · cleared partition table / boot sector recovered via sigfind — step 1
- T1006 · Defense Evasion · Direct Volume Access · raw-block reads (blkls/icat) bypassing the FS — step 6
- T1490 · Impact · Inhibit System Recovery · note if Volume Shadow Copies were deleted (vshadowinfo store count) — step 9

## Pivots (lead-to-lead graph)
- `on_recovered_executable (step 4/5 recovered binary or ADS payload): malware-analysis-triage — triage the dropped/hidden payload's hash and behavior`
- `on_deleted_userdata_recovered (step 4 archives/documents from unallocated): insider-threat-data-theft — establish staging/exfil of the recovered data`
- `on_journal_or_partition_wiped (step 1/7 truncated $J / cleared partition table): acquisition-custody — re-acquire and prove the destruction/collection gap`
- `on_timestomp_or_journal_lifecycle (step 7/8 $J create/delete + $SI<$FN): windows-execution-artifacts — corroborate the binary's execution off the file system`
- `on_carved_indicator (step 6 carved unallocated URL/path/cred): file-recovery-carving — exhaustively carve and reduce the unallocated set`
- `on_encrypted_or_hidden_volume (step 1 unidentifiable partition): steganography-data-hiding — pursue the hidden/encrypted container`
- `on_shadow_copy_available (step 9 vshadowinfo stores present): SELF — re-enter against the shadow-copy FS with #{image_path}/#{ntfs_offset_sectors} rebound to the snapshot`
- `on_disk_unmountable_or_image_corrupt (step 0): acquisition-custody — verify the image integrity and re-acquire`

## Jargon decoder
- **Disk image:** a byte-for-byte copy of a storage device (`.E01` compressed/EWF, `.dd`/`.raw` flat, `.vmdk` VM disk) — the frozen evidence this playbook reads.
- **$MFT (Master File Table):** NTFS's master index — one record per file/dir holding names, timestamps, and where the content lives.
- **$SI vs $FN:** the two timestamp sets in an `$MFT` record — `$STANDARD_INFORMATION` (0x10, what Explorer shows, easy to forge) and `$FILE_NAME` (0x30, updated on rename/move, harder to forge). Disagreement = **timestomp**.
- **MACB:** the four file timestamps — **M**odified, **A**ccessed, **C**hanged (metadata), **B**orn (created).
- **$UsnJrnl:$J:** the NTFS **change journal** — a log of every file create/rename/delete with a reason code; proves a deleted file once existed.
- **$LogFile:** NTFS's **transaction journal** for crash recovery — records low-level metadata operations; corroborates the change journal when it wrapped.
- **Timestomp:** back-dating/altering a file's timestamps to hide when it really arrived.
- **ADS (Alternate Data Stream):** a hidden extra content stream attached to a file (`file.txt:hidden.exe`) — invisible to normal listings; `Zone.Identifier` is the benign Mark-of-the-Web one.
- **Slack space:** the leftover bytes between a file's real end and its last allocated cluster — can hold fragments of a previously-deleted file.
- **Unallocated space:** clusters the FS marks free — where deleted-file content lingers until overwritten.
- **Inode:** the file system's internal file record (the Linux/TSK analog of an `$MFT` entry).
- **Orphan inode:** a deleted metadata record with no directory entry pointing to it — recoverable with `ils`.
- **Carving:** recovering files from raw bytes by their headers/footers, ignoring the file system (`tsk_recover`, `blkls`, `bulk_extractor`).
- **Partition table (MBR/GPT):** the map of where each volume starts/ends; a **gap** can hide a lost/deleted partition.
- **Volume Serial Number (VSN):** an FS identifier from `fsstat`; correlates a disk to LNK/USB artifacts (not the hardware serial).
- **Volume Shadow Copy (VSS):** Windows point-in-time snapshots of a volume — a time machine for files altered/deleted after the snapshot.
- **INDX ($I30):** the on-disk directory **index**; its slack retains entries for files removed from the folder.
- **Super-timeline:** one merged chronology across many artifacts, built with `log2timeline.py` + `psort.py`.

## Tuning log (append-only — the eval loop writes here; humans never edit rows)
| date | case_id | bucket missed | delta applied |
|---|---|---|---|
