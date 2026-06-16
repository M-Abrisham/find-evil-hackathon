---
attack_type: file-recovery-carving
category_id: file-recovery-carving
name: File Recovery, Carving & Data Reduction
description: recover deleted files, carve unallocated space, reduce large evidence sets to what matters
version: 1
os_coverage: [windows, linux, macos, cloud]
sub_types_covered: 10
sub_types:
  - deleted-file-recovery-via-mft
  - deleted-file-recovery-orphan-inode
  - header-footer-carving-from-unallocated
  - signature-carving-photorec
  - slack-space-carving
  - email-store-carving
  - sqlite-record-carving
  - data-reduction-hash-dedup
  - data-reduction-known-good-filtering
  - recovered-from-recycle-bin
validated_on: []
maturity: draft
variables:
  image_path:
    default: /cases/active/evidence/disk.E01
    derive: "Step 0 — first disk-evidence image (E01/dd/raw/vmdk) enumerated under the evidence directory named in the case brief"
  mount_root:
    default: /cases/active/mount
    derive: "Step 0 — directory where the file system is mounted READ-ONLY (or where icat/tsk_recover-extracted artifacts land when mounting fails)"
  case_out:
    default: /cases/active/out
    derive: "Step 0 — writable case output directory from the case brief; Step 0 creates #{case_out}/receipts/ and #{case_out}/extracted/"
  ntfs_offset_sectors:
    default: 0
    derive: "Step 0 — start sector of the relevant partition from `mmls #{image_path}` (largest data partition unless the brief says otherwise); the byte offset is this × the sector size"
  time_window:
    default: 1970-01-01..2099-12-31
    derive: "case brief if it names one; else first confirmed malicious/deletion timestamp ±48h once a step pins one — then re-scope wide sweeps to it"
---

## In one line
Someone deleted, hid, or buried data — this playbook gets it back. It un-deletes files the file system still half-remembers, rebuilds files from raw disk fragments when the file system has forgotten them entirely, and then shrinks a huge pile of recovered junk down to the handful of files that actually matter.

## Use this when (triggers)
- A file you need was **deleted** — the brief mentions wiping, "the user emptied it," or an artifact that should exist is missing from the live file system.
- You see signs of **anti-forensics**: an emptied Recycle Bin, a cleared temp/download folder, a reformatted or repartitioned volume.
- The file system is **damaged, reformatted, or unmountable** but the disk still has data on it (carving works with no file system at all).
- You have a **mountain of recovered/loose files** (a carve dumped thousands) and need to reduce it to known-bad / unknown / interesting by hash and file type.
- You need to prove a file **once existed** even though its name and content are gone — via MFT/USN/INDX remnants or a carved fragment in slack/unallocated.
- An **email store or SQLite database** (mailbox, browser history, chat) was deleted or had records purged and you need the rows back.

## Quick path (the 90% case)
1. **Timeline-first.** Build a file-system timeline of deletions BEFORE carving blind: `fls -rd` (deleted entries only) → bodyfile → `mactime`, or `MFTECmd`/`analyzeMFT` over `$MFT` sorted by time, and read `$UsnJrnl:$J` (`usnjls`) for the delete/rename history. Scope to `#{time_window}`. The order *what existed → when it was deleted → what overwrote it* is the case; carving without it produces an un-attributable file dump.
2. **Recover the easy wins.** `tsk_recover` pulls back deleted+allocated files the file system still indexes; `RBCmd` reads `$I` Recycle-Bin records (original path + delete time). These keep names and paths — always try them before signature carving.
3. **Carve what the FS forgot.** Extract unallocated with `blkls -e`, then carve it by file signature with `foremost`/`scalpel` (header/footer) or `photorec` (batch `/cmd`, signature) — these recover content with NO names or paths.
4. **Pull features & hidden rows.** `bulk_extractor` sweeps the whole image for emails/URLs/CCNs/search terms (file-system-independent); `sqlite-carver` recovers deleted rows from SQLite freelists; check file **slack** (`icat -s`) for fragments hiding behind live files.
5. **Reduce the pile.** Hash everything (`md5deep`/`sha256deep -r`), dedup, and split known-good vs unknown vs known-bad with `hfind`/`sorter` against a hash DB — so a human reviews dozens, not thousands. `densityscout` flags high-entropy (packed/encrypted) carved blobs worth a closer look.

If a deleted file is recovered with a name and a timeline-consistent deletion event, and its hash/content corroborates the lead → you're mostly done. Otherwise drop into the full Steps.

## How it unfolds (the story)
A file that mattered gets deleted — by an insider clearing tracks, by malware self-deleting, or by an emptied Recycle Bin — but deletion on disk only un-links: the file system marks the clusters free while the bytes linger until overwritten. The MFT entry, the USN journal, and folder INDX slack often still name the file and its delete time even after the data is partially gone, and the data itself survives in unallocated space or in the slack behind smaller live files. Recovery walks from most-context-to-least: first the file-system metadata (names, paths, times via `tsk_recover`/`RBCmd`/`$J`), then raw signature carving of unallocated (content only, no names), then feature/record extraction; finally the flood of recovered files is reduced by hash and type so the investigation focuses on what's actually evidentiary.

## Theories to test (and how to rule each out)
| Theory (who / why) | If true, you'd find… | Rule it out if… |
|---|---|---|
| **Insider destroying evidence (data theft cover-up)** | A burst of deletions of sensitive files in `#{time_window}` recorded in `$UsnJrnl:$J`; emptied Recycle Bin `$I` records with original paths in a sensitive directory; recovered files whose content is the stolen data | Deletions are routine/scattered with no sensitive cluster; `$J` shows normal app churn (temp/cache) only; no recoverable sensitive content |
| **Malware self-deletion (dropper cleaned up)** | A deleted executable recoverable from unallocated/MFT whose carve matches a malware signature (`clamscan`) or high entropy (`densityscout`); `$J` delete event right after the execution timestamp | The deleted item is a benign installer/temp; no execution artifact precedes the delete; carved binary is signed/known-good in the hash DB |
| **Reformat / repartition to destroy data** | `mmls` shows a fresh/altered partition layout; `fsstat` format date inside `#{time_window}`; but `photorec`/`foremost` still carve intact files from the "empty" volume (format ≠ wipe) | A full-disk wipe pass ran (carving yields only zeros / no signatures across unallocated); `densityscout` shows uniform high entropy = overwritten, not formatted |
| **Other-insider / account misuse (someone else deleted it)** | Recovered Recycle-Bin `$I` whose SID/user folder is NOT the suspected account; `$J` reason codes tied to a different session/time | The deletion SID and session match the suspected account's own activity baseline |
| **Supply-chain / automated cleanup (uninstaller/updater)** | Deletions whose paths and timing match a known installer/updater run; recovered files are vendor binaries; matching events in execution logs | Deleted files are user documents/exfil staging, not program files; no updater/uninstaller process preceded the deletion |
| **Innocent / benign (NOT an attack)** | Deletions are ordinary temp/cache/browser churn; emptied Recycle Bin from a sanctioned cleanup; nothing sensitive recoverable; all inside business-as-usual | A clear, sanctioned cleanup/retention action explains the deletions AND nothing of evidentiary value is recovered → benign cause confirmed; reclassify |

*(≥1 benign + ≥1 malicious, each ACTIVELY refuted. Attacker types mapped: insider · other-insider · external-commodity · external-targeted · supply-chain · innocent.)*

## Evidence → Tool → What it reveals (per OS)
| Evidence | SIFT tool | What it tells you *for this attack* | OS |
|---|---|---|---|
| `$MFT` deleted/orphan entries | `MFTECmd` / `analyzeMFT` / `fls -rd` / `ils` | A deleted file's name, path, size, MAC times, and whether its clusters are still resident — the highest-context recovery (names survive) | Windows |
| `$UsnJrnl:$J` change journal | `usnjls` / `usn.py` | Prior existence of now-deleted files: create/delete/rename reason codes with timestamps — proves a file existed and *when* it was deleted even if content is gone | Windows |
| Folder INDX (`$I30`) incl. slack | `INDXParse.py` / `MFTINDX.py` | Deleted-file-in-a-folder proof: slack INDX entries name files removed from a directory listing | Windows |
| Recycle Bin `$I` / `INFO2` | `RBCmd` | Original full path, original size, and exact delete time of a recycled file (then recover the `$R` content) | Windows |
| Deleted-but-indexed files (any FS) | `tsk_recover` | Bulk un-delete of files the file system still references — keeps original names/paths | all |
| Unallocated space (raw blocks) | `blkls -e` then `foremost` / `scalpel` / `photorec` | Content recovery from clusters the FS freed — header/footer or signature carving; NO names/paths recovered | all |
| File **slack** (tail of a cluster behind a live file) | `icat -s` / `blkls` (slack) | Fragments of a *previous* file hiding behind a current one — small but high-signal remnants | all |
| Whole image, FS-independent | `bulk_extractor` | Emails, URLs, credit-card numbers, search terms, and other features pulled from anywhere on the image including unallocated and compressed regions | all |
| SQLite DB freelist / unallocated pages | `sqlite-carver` | Deleted rows (browser history, chat, mailbox tables) recovered from a database's free pages | all |
| PST/OST mailbox + carved mail | `pffexport` / `bulk_extractor` (email feature) / `photorec` | Recovered email items and addresses from a deleted or partial mailbox store | Windows/all |
| Big pile of recovered files | `md5deep` / `sha256deep` / `hfind` / `sorter` | Data reduction: dedup by hash, drop known-good (NSRL), flag known-bad — turns thousands of carved files into a short review list | all |
| Carved binary blobs | `densityscout` / `clamscan` / `pe-carver` | Triage of recovered executables: entropy (packed/encrypted), AV signature hits, and embedded/dropped PE extraction | all |
| Recovered file metadata | `exiftool` | Authoring/device/GPS/timestamps inside a recovered document or image — attribution of the un-deleted file | all |
| `$LogFile` (NTFS journal) | `jls` / `jcat` | Very-recent file operations just before capture (short retention) — corroborates a deletion seen in `$J` | Windows |

*PhotoRec and TestDisk are interactive TUIs; the `tool:` lines below use only their non-interactive batch forms (`photorec /log /d ... /cmd <dev> options`). No GUI is used anywhere in this playbook.*

## Step 0 — evidence inventory & access bootstrap
- n: 0
  tool: |
    mkdir -p "#{case_out}/receipts" "#{case_out}/extracted" "#{case_out}/carve" && ls -laR "#{mount_root}" > "#{case_out}/receipts/00.txt" 2>&1 ; img_stat "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; mmls "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; fsstat -o #{ntfs_offset_sectors} "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1
  expect: every evidence file classified; #{image_path}, #{mount_root}, #{ntfs_offset_sectors}, #{case_out} bound; read-only access proven; the partition table (mmls), container format (img_stat), and file-system geometry (fsstat — cluster size, total/free clusters) recorded so later carving/recovery can address the right volume, or their absence is recorded
  check: |
    test -r "#{mount_root}" -o -n "$(ls "#{case_out}/extracted" 2>/dev/null)" || test -s "#{case_out}/receipts/00.txt"
  falsify: evidence dir empty/unreadable, or no supported image format found by img_stat, or mmls/fsstat report no usable partition
  on_result: {expect_met: goto 1, falsify_met: STOP — report acquisition/access failure; pivot acquisition-custody, neither: try the TSK fallback (fls/icat the needed inodes, or tsk_recover into #{case_out}/extracted) and proceed off-image; if that also fails, treat as falsify_met}
  emits: [key_artifacts]
  serves: [deleted-file-recovery-via-mft, deleted-file-recovery-orphan-inode, header-footer-carving-from-unallocated, signature-carving-photorec, slack-space-carving, email-store-carving, sqlite-record-carving, data-reduction-hash-dedup, data-reduction-known-good-filtering, recovered-from-recycle-bin]
  provenance: {receipt_id: 00, artifact: evidence directory listing + mmls/fsstat output, offset_or_row: full listing, literal_cited: image filename + partition start sector + cluster size}

## Steps (executable — decision-driven)
- n: 1
  precondition: "test -s #{case_out}/receipts/00.txt"
  tool: |
    fls -o #{ntfs_offset_sectors} -rpd "#{image_path}" > "#{case_out}/receipts/01.txt" 2>&1 ; fls -o #{ntfs_offset_sectors} -rm / "#{image_path}" > "#{case_out}/bodyfile" 2>>"#{case_out}/receipts/01.txt" ; mactime -b "#{case_out}/bodyfile" -d > "#{case_out}/fs_timeline.csv" 2>>"#{case_out}/receipts/01.txt"
  expect: a list of DELETED directory entries (fls -rpd marks them with `*`) plus a full MACB timeline (#{case_out}/fs_timeline.csv) — the deletion story, with names and delete times, scoped to #{time_window}; this is the timeline-first artifact every later recovery step is attributed against
  check: |
    test -s "#{case_out}/fs_timeline.csv" && grep -qE "^\*|\(deleted\)|, *deleted" "#{case_out}/receipts/01.txt"
  falsify: fls finds no deleted entries at all (file system intact/overwritten or wrong offset) — recovery must rely on raw carving (steps 5–6) since metadata gives no names
  on_result: {expect_met: record deleted names + delete times; goto 2, falsify_met: no metadata-level deletions — skip name-based recovery and go straight to carving at goto 5; if fls errored on the offset re-derive #{ntfs_offset_sectors} from mmls, neither: widen #{time_window}; try fls without -d to confirm the volume parses, then re-run}
  emits: [timeline_events, key_artifacts]
  serves: [deleted-file-recovery-via-mft, deleted-file-recovery-orphan-inode]
  provenance: {receipt_id: 01, artifact: file-system metadata ($MFT / directory entries), offset_or_row: fls deleted rows + fs_timeline.csv, literal_cited: deleted filename + delete timestamp}

- n: 2
  precondition: "test -s #{case_out}/receipts/00.txt"
  tool: |
    usnjls -o #{ntfs_offset_sectors} "#{image_path}" > "#{case_out}/usnjrnl.txt" 2>"#{case_out}/receipts/02.txt" ; grep -iE "DELETE|RENAME|FILE_CREATE|CLOSE" "#{case_out}/usnjrnl.txt" > "#{case_out}/receipts/02.txt" 2>&1 ; ils -o #{ntfs_offset_sectors} "#{image_path}" >> "#{case_out}/receipts/02.txt" 2>&1
  expect: $UsnJrnl:$J reason codes (FILE_DELETE / RENAME_OLD_NAME / FILE_CREATE) naming files that existed and were deleted/renamed inside #{time_window} — prior-existence proof even when the content is overwritten; plus ils orphan/deleted inode metadata fls missed
  check: |
    grep -qiE "DELETE|RENAME|deleted" "#{case_out}/receipts/02.txt"
  falsify: $J is absent, wrapped (short retention), or shows only routine temp/cache churn with no sensitive or attacker-relevant filenames — no journal evidence of the deletion of interest
  on_result: {expect_met: record prior-existence filenames + reason codes + timestamps as IOCs; goto 3, falsify_met: note $J gives no evidence (wrapped/absent); rely on MFT/INDX (steps 1/3) and carving; if the journal wrapped, record that as an anti-forensics-adjacent gap, neither: re-run usnjls with the correct -o offset; if $J truly absent, fall back to jls on $LogFile for very-recent ops}
  emits: [timeline_events, key_iocs]
  serves: [deleted-file-recovery-via-mft, deleted-file-recovery-orphan-inode]
  provenance: {receipt_id: 02, artifact: "$UsnJrnl:$J change journal + ils inode table", offset_or_row: usnjrnl.txt reason-code rows, literal_cited: "filename + FILE_DELETE/RENAME reason + USN timestamp"}

- n: 3
  precondition: "test -s #{case_out}/receipts/00.txt"
  tool: |
    tsk_recover -o #{ntfs_offset_sectors} "#{image_path}" "#{case_out}/extracted" > "#{case_out}/receipts/03.txt" 2>&1 ; ls -laR "#{case_out}/extracted" >> "#{case_out}/receipts/03.txt" 2>&1
  expect: tsk_recover writes back the deleted (and, with no flag, allocated) files the file system still references INTO #{case_out}/extracted, preserving original names and directory structure — the highest-fidelity recovery; the deleted files named in steps 1–2 should appear here
  check: |
    test -n "$(ls -A "#{case_out}/extracted" 2>/dev/null)" && grep -qiE "Files Recovered|recovered|[0-9]+ file" "#{case_out}/receipts/03.txt"
  falsify: tsk_recover recovers nothing (clusters reallocated/overwritten, or the FS index is destroyed) — named recovery failed; the bytes may still be carvable raw
  on_result: {expect_met: hash + review the recovered files then goto 4; pivot insider-threat-data-theft when the recovered content is stolen/staged data, falsify_met: metadata recovery exhausted — proceed to raw carving (step 5/6) which needs no FS index, neither: re-run tsk_recover with the correct -o offset; if the volume is exFAT/ext re-confirm fsstat type then retry}
  emits: [key_artifacts]
  serves: [deleted-file-recovery-via-mft, deleted-file-recovery-orphan-inode]
  provenance: {receipt_id: 03, artifact: deleted files referenced by the file system, offset_or_row: tsk_recover recovered-file count line, literal_cited: "recovered filename + original path"}

- n: 4
  precondition: "test -r #{mount_root}"
  tool: |
    find "#{mount_root}" -ipath "*/\$Recycle.Bin/*" \( -iname '$I*' -o -iname 'INFO2' \) > "#{case_out}/recyclebin_files.txt" 2>/dev/null ; while read -r f; do dotnet /opt/zimmermantools/RBCmd.dll -f "$f" --csv "#{case_out}" --csvf recyclebin.csv ; done < "#{case_out}/recyclebin_files.txt" > "#{case_out}/receipts/04.txt" 2>&1 ; test -s "#{case_out}/recyclebin.csv" && cat "#{case_out}/recyclebin.csv" >> "#{case_out}/receipts/04.txt"
  expect: RBCmd parses the Recycle-Bin $I (Vista+) / INFO2 (XP) records and yields, per recycled file, the ORIGINAL full path, original size, the deleting SID/user, and the exact delete timestamp — proving who deleted what and when; the matching $R file holds the recoverable content
  check: |
    test -s "#{case_out}/recyclebin.csv" || grep -qiE "FileName|DeletedOn|SourceName" "#{case_out}/receipts/04.txt"
  falsify: no $I/INFO2 records (Recycle Bin never used, or it was emptied AND the $I records themselves deleted) — recycle-path attribution unavailable
  on_result: {expect_met: record original path + delete time + SID as a high-context finding; recover the paired $R content via icat/tsk_recover; goto 5, falsify_met: emptied/absent Recycle Bin is itself a finding (anti-forensics) — note it and rely on $J (step 2) + carving; pivot insider-threat-data-theft if a user emptied it to cover data theft, neither: the $I records may themselves be deleted — carve them back from unallocated in step 5/6 (they are tiny fixed-format records), then re-parse with RBCmd}
  emits: [key_artifacts, actor_accounts]
  serves: [recovered-from-recycle-bin]
  provenance: {receipt_id: 04, artifact: "Recycle Bin $I / INFO2 records", offset_or_row: recyclebin.csv rows, literal_cited: "original path + DeletedOn timestamp + SID"}

- n: 5
  precondition: "test -s #{case_out}/receipts/00.txt"
  tool: |
    blkls -e -o #{ntfs_offset_sectors} "#{image_path}" > "#{case_out}/unallocated.dd" 2>"#{case_out}/receipts/05.txt" ; ls -la "#{case_out}/unallocated.dd" >> "#{case_out}/receipts/05.txt" 2>&1 ; foremost -i "#{case_out}/unallocated.dd" -o "#{case_out}/carve/foremost" -T >> "#{case_out}/receipts/05.txt" 2>&1 ; cat "#{case_out}/carve/foremost"*/audit.txt >> "#{case_out}/receipts/05.txt" 2>&1
  expect: blkls -e extracts the volume's unallocated (and slack) data units into one stream (#{case_out}/unallocated.dd), then foremost header/footer-carves recoverable files (jpg/pdf/docx/zip/exe…) OUT of it into #{case_out}/carve/ with an audit.txt manifest — content recovered with NO original names or paths
  check: |
    test -s "#{case_out}/unallocated.dd" && grep -qiE "Num.*Name|files? extracted|[0-9]+ FILES EXTRACTED|: *[0-9]+ KB" "#{case_out}/receipts/05.txt"
  falsify: foremost extracts zero files from unallocated (clusters zeroed/overwritten = wiped, not just deleted), OR blkls produces a zero-length stream (no unallocated space / wrong offset)
  on_result: {expect_met: catalogue carved files by type; pass them into the data-reduction step 8; goto 6, falsify_met: a zeroed/empty unallocated region suggests a genuine wipe — record that as a finding (anti-forensics) and confirm with densityscout in step 8, neither: re-run blkls with the correct -o offset; if foremost finds nothing try the broader signature set in step 6 (photorec) before concluding a wipe}
  emits: [key_artifacts]
  serves: [header-footer-carving-from-unallocated, slack-space-carving]
  provenance: {receipt_id: 05, artifact: unallocated/slack data units (blkls), offset_or_row: foremost audit.txt entries, literal_cited: "carved file type + byte offset + size from audit.txt"}

- n: 6
  precondition: "test -s #{case_out}/unallocated.dd"
  tool: |
    photorec /log /d "#{case_out}/carve/photorec" /cmd "#{case_out}/unallocated.dd" partition_none,options,mode_ext2,paranoid,keep_corrupted_file,search > "#{case_out}/receipts/06.txt" 2>&1 ; ls -laR "#{case_out}/carve/photorec" >> "#{case_out}/receipts/06.txt" 2>&1 ; scalpel -c /etc/scalpel/scalpel.conf -o "#{case_out}/carve/scalpel" "#{case_out}/unallocated.dd" >> "#{case_out}/receipts/06.txt" 2>&1
  expect: photorec in NON-INTERACTIVE batch mode (/log /d output /cmd <device> <options>) signature-carves a broader file-type set than foremost — recovering files foremost's header/footer rules miss (e.g. fragmented or less-common formats) — into #{case_out}/carve/photorec; scalpel provides a second header/footer engine as cross-check
  check: |
    test -n "$(find "#{case_out}/carve/photorec" -type f 2>/dev/null | head -1)" || grep -qiE "recup_dir|files? saved|Pass [0-9]" "#{case_out}/receipts/06.txt"
  falsify: photorec AND scalpel both recover nothing beyond what foremost found, OR they error (corrupt input / unreadable device) — signature carving adds nothing here
  on_result: {expect_met: merge photorec/scalpel output with the foremost set; de-duplicate before review; goto 7, falsify_met: signature carving exhausted; if nothing carved anywhere then strengthen the wipe finding from step 5, neither: photorec batch syntax drifts across builds — if /cmd errored then confirm the device path and re-run with a minimal options string (search only); never fall back to the interactive TUI}
  emits: [key_artifacts]
  serves: [signature-carving-photorec, header-footer-carving-from-unallocated]
  provenance: {receipt_id: 06, artifact: signature-carved files (photorec/scalpel), offset_or_row: recup_dir listing / scalpel audit, literal_cited: "carved filename + detected file type"}

- n: 7
  precondition: "test -s #{case_out}/receipts/00.txt"
  tool: |
    bulk_extractor -o "#{case_out}/bulk" "#{image_path}" > "#{case_out}/receipts/07.txt" 2>&1 ; ls -la "#{case_out}/bulk" >> "#{case_out}/receipts/07.txt" 2>&1 ; for db in $(find "#{mount_root}" -iname "*.sqlite" -o -iname "*.db" 2>/dev/null); do /opt/sqlite-carver/bin/sqlite-carver -f "$db" >> "#{case_out}/receipts/07.txt" 2>&1 ; done
  expect: bulk_extractor sweeps the WHOLE image (FS-independent) and writes feature files — email.txt, url.txt, ccn.txt, telephone.txt, domain.txt — pulling indicators out of unallocated, slack, and compressed regions; sqlite-carver recovers deleted ROWS from any SQLite DB freelist (browser history, chat, mailbox tables) — the email/SQLite carving lane
  check: |
    test -s "#{case_out}/bulk/email.txt" -o -s "#{case_out}/bulk/url.txt" -o -s "#{case_out}/bulk/report.xml" || grep -qiE "recovered|row|record|feature" "#{case_out}/receipts/07.txt"
  falsify: bulk_extractor produces only empty feature files AND no SQLite rows are recovered — no email/URL/record features survive on the image
  on_result: {expect_met: record recovered addresses/URLs/rows as IOCs; pivot browser-email-documents for mailbox/history follow-up; goto 8, falsify_met: no features/rows — note the absence; if a known mailbox/DB exists but yields nothing it may be wiped, record that, neither: re-run bulk_extractor scoped to #{case_out}/unallocated.dd if the full image is too large/slow; re-target sqlite-carver at the specific DB path}
  emits: [key_iocs, exfil_or_encryption_facts]
  serves: [email-store-carving, sqlite-record-carving]
  provenance: {receipt_id: 07, artifact: bulk_extractor feature files + SQLite freelist, offset_or_row: email.txt/url.txt lines + carved rows, literal_cited: "recovered email address / URL / SQLite row value"}

- n: 8
  precondition: "test -n \"$(ls -A #{case_out}/extracted #{case_out}/carve 2>/dev/null)\""
  tool: |
    sha256deep -r "#{case_out}/extracted" "#{case_out}/carve" > "#{case_out}/hashes.txt" 2>"#{case_out}/receipts/08.txt" ; sort "#{case_out}/hashes.txt" | uniq -w 64 -d > "#{case_out}/dupes.txt" 2>>"#{case_out}/receipts/08.txt" ; densityscout -p 0.1 -o "#{case_out}/density.txt" "#{case_out}/carve" >> "#{case_out}/receipts/08.txt" 2>&1 ; clamscan -r --infected "#{case_out}/extracted" "#{case_out}/carve" >> "#{case_out}/receipts/08.txt" 2>&1
  expect: DATA REDUCTION — sha256deep hashes every recovered/carved file so duplicates collapse (uniq on the 64-char hash), densityscout flags high-entropy (packed/encrypted) blobs worth a human look, and clamscan tags known-bad; the result is a short triage list (known-bad + unknown-high-entropy) instead of a thousand-file dump. If a known-hash DB is available, hfind/sorter drops NSRL known-good
  check: |
    test -s "#{case_out}/hashes.txt" && grep -qE "[a-f0-9]{64}" "#{case_out}/hashes.txt"
  falsify: nothing to reduce (no files recovered in steps 3/5/6) — data-reduction has no input; OR every recovered file is unique known-good (nothing of interest survives)
  on_result: {expect_met: hand the reduced known-bad/unknown list forward as the evidentiary set; goto 9, falsify_met: if no recovered files exist, recovery itself failed — revisit whether the data was wiped (step 5 finding) vs wrong volume/offset, neither: if sha256deep errored on a path, re-run per-subdirectory; if no hash DB is present for known-good filtering, note that reduction is dedup-only and proceed}
  emits: [key_artifacts, key_iocs]
  serves: [data-reduction-hash-dedup, data-reduction-known-good-filtering]
  provenance: {receipt_id: 08, artifact: recovered/carved file set, offset_or_row: hashes.txt + density.txt + clamscan hits, literal_cited: "SHA-256 + filename + density/clamscan verdict"}

- n: 9
  precondition: "test -s #{case_out}/hashes.txt"
  tool: |
    for f in $(find "#{case_out}/extracted" "#{case_out}/carve" -type f 2>/dev/null | head -500); do exiftool "$f" >> "#{case_out}/recovered_meta.txt" 2>>"#{case_out}/receipts/09.txt" ; done ; grep -iE "Create Date|Modify Date|Author|GPS|Camera|Producer|Software" "#{case_out}/recovered_meta.txt" > "#{case_out}/receipts/09.txt" 2>&1
  expect: exiftool reads embedded metadata (authoring app/author, device, GPS, internal create/modify times) from the reduced set of recovered documents/images — attributing the un-deleted file to a person/device/time and corroborating the deletion timeline from step 1/2 with an independent (in-file) timestamp source (two-source rule)
  check: |
    grep -qiE "Create Date|Modify Date|Author|GPS|Producer|Software" "#{case_out}/receipts/09.txt"
  falsify: recovered files carry no usable embedded metadata (stripped, or formats without metadata) — no in-file attribution available; the recovery stands on file-system timeline alone
  on_result: {expect_met: corroborate the recovered file origin/time against the fs_timeline; COMMIT findings with confidence labels; close per the gate, falsify_met: record that recovered content lacks embedded metadata; keep findings at single-source (fs timeline only) and label inferred, neither: widen the exiftool sweep beyond the first 500 files if a specific recovered file of interest was missed; re-target it directly}
  emits: [key_artifacts, timeline_events]
  serves: [data-reduction-known-good-filtering, deleted-file-recovery-via-mft]
  provenance: {receipt_id: 09, artifact: recovered file embedded metadata, offset_or_row: recovered_meta.txt fields, literal_cited: "in-file Create Date / Author / GPS string"}

## Linux branch (L1..Ln) — REQUIRED, numbered, same step shape
- n: L1
  precondition: "os == linux"
  tool: |
    fsstat -o #{ntfs_offset_sectors} "#{image_path}" > "#{case_out}/receipts/L01.txt" 2>&1 ; ls "#{mount_root}/var" "#{mount_root}/home" "#{mount_root}/etc" >> "#{case_out}/receipts/L01.txt" 2>&1
  expect: this image is Linux/Unix (ext2/3/4 or xfs reported by fsstat, /var//home//etc present) — NTFS-specific recovery ($MFT, $UsnJrnl:$J, $I30, Recycle Bin, RBCmd) does NOT apply; on ext the analogs are deleted-inode recovery (ils/icat — though ext3/4 zero block pointers on delete, limiting metadata recovery), the same blkls→foremost/photorec carving, and journal review. Records "NTFS-metadata recovery skipped because <reason: ext/xfs has no MFT/USN/Recycle-Bin>"
  check: |
    test -d "#{mount_root}/etc" || grep -iE "ext[234]|xfs|File System Type" "#{case_out}/receipts/L01.txt" | grep -qiE "ext|xfs"
  falsify: fsstat reports NTFS and a Windows\System32 / $MFT tree exists — this is Windows, not Linux; run the main Windows Steps 1–9 instead
  on_result: {expect_met: goto L2, falsify_met: this is Windows — run the main branch (steps 1–9), not this Linux branch, neither: confirm OS family from the Step 0 fsstat receipt; if still ambiguous, attempt both blkls-carving (FS-agnostic) and treat NTFS-only steps as precondition_unmet}
  emits: [key_artifacts]
  serves: [deleted-file-recovery-orphan-inode]
  provenance: {receipt_id: L01, artifact: file-system type + top-level dir listing, offset_or_row: fsstat header + dir listing, literal_cited: "ext/xfs FS type (Linux-confirmed, NTFS-metadata recovery N/A)"}

- n: L2
  precondition: "os == linux"
  tool: |
    ils -o #{ntfs_offset_sectors} "#{image_path}" > "#{case_out}/receipts/L02.txt" 2>&1 ; blkls -e -o #{ntfs_offset_sectors} "#{image_path}" > "#{case_out}/unallocated.dd" 2>>"#{case_out}/receipts/L02.txt" ; foremost -i "#{case_out}/unallocated.dd" -o "#{case_out}/carve/foremost_lx" -T >> "#{case_out}/receipts/L02.txt" 2>&1 ; photorec /log /d "#{case_out}/carve/photorec_lx" /cmd "#{case_out}/unallocated.dd" partition_none,options,mode_ext2,paranoid,keep_corrupted_file,search >> "#{case_out}/receipts/L02.txt" 2>&1 ; sha256deep -r "#{case_out}/carve" >> "#{case_out}/receipts/L02.txt" 2>&1
  expect: on Linux, ils lists deleted inodes (limited on ext3/4 because block pointers are zeroed at delete), then the SAME FS-agnostic carving recovers content — blkls -e extracts unallocated, foremost header/footer-carves and photorec (batch /cmd) signature-carves it; sha256deep then dedups for data reduction, inside #{time_window}
  check: |
    test -s "#{case_out}/unallocated.dd" && ( test -n "$(find "#{case_out}/carve/foremost_lx" "#{case_out}/carve/photorec_lx" -type f 2>/dev/null | head -1)" || grep -qiE "files? extracted|recup_dir|EXTRACTED" "#{case_out}/receipts/L02.txt" )
  falsify: blkls yields no unallocated and carving recovers nothing (volume wiped/zeroed or wrong offset), and ils shows no recoverable deleted inodes — Linux recovery fails; record the wipe/gap as a finding
  on_result: {expect_met: hash + reduce the carved set; commit with confidence label, falsify_met: record the wipe/empty-unallocated as a finding; pivot linux-host-forensics for log/persistence context around the deletion, neither: re-derive #{ntfs_offset_sectors} from mmls and retry; if photorec /cmd drifts, re-run with a minimal search-only options string — never the interactive TUI}
  emits: [key_artifacts, timeline_events]
  serves: [deleted-file-recovery-orphan-inode, header-footer-carving-from-unallocated, signature-carving-photorec, data-reduction-hash-dedup]
  provenance: {receipt_id: L02, artifact: ext/xfs deleted inodes + unallocated carve, offset_or_row: ils rows + foremost/photorec output, literal_cited: "deleted inode number / carved file type + offset"}

## Corroboration (two-source rule)
`required_sources: 2` · `pairs:`
- `[ deleted filename in $MFT/fls (step 1) ↔ FILE_DELETE reason in $UsnJrnl:$J (step 2) ]`
- `[ tsk_recover named file (step 3) ↔ same path in Recycle-Bin $I record (step 4) or in the fls deletion timeline (step 1) ]`
- `[ Recycle-Bin $I original path + delete time (step 4) ↔ $J delete event at the same timestamp (step 2) ]`
- `[ foremost-carved content (step 5) ↔ photorec/scalpel carve of the same region (step 6) — two carving engines agree the file is real, not a false header ]`
- `[ carved file SHA-256 (step 8) ↔ a hash-DB known-good/known-bad verdict (hfind/sorter) or a clamscan signature hit (step 8) ]`
- `[ recovered file's file-system delete time (step 1) ↔ its in-file exiftool Create/Modify date (step 9) ]`
- `[ bulk_extractor email/URL feature (step 7) ↔ the same indicator inside a tsk_recover/carve-recovered file (steps 3/5/6) ]`

One hit is a *lead*; promote to *fact* only when its paired source agrees.

## Don't get fooled (red flags & anti-forensics)
- **Deleted ≠ wiped.** A deleted file's clusters are merely marked free; the bytes survive until overwritten. Conversely, if carving yields only zeros across unallocated, that is a *wipe* — a deliberate finding, not "nothing was there." Confirm with `densityscout` (uniform high entropy = overwritten).
- **Carving has no provenance.** `foremost`/`photorec`/`scalpel` recover CONTENT with NO name, path, owner, or timestamp. Never attribute a carved file to a user without tying it back via `ifind` (data-unit → inode) or a matching $MFT/$J entry. A carved file is a lead, not a fact, until anchored.
- **False-positive carves.** Header/footer carving fits a template over raw bytes; it produces corrupt or bogus "files" when a real header sits over unrelated data, and fragmented files come back truncated. Cross-check with a second engine (step 6) and open/validate before trusting.
- **Emptied Recycle Bin / cleared temp is a finding.** Absence of `$I` records where you'd expect them, or a `$J` showing a deletion burst, is evidence of cover-up — record the absence, don't ignore it.
- **Timestomp survives into recovery.** A recovered file's $SI MAC times may be forged; trust $FN (compare with `istat`/`MFTECmd`), the $J/USN sequence, and the in-file exiftool timestamps over $SI.
- **$UsnJrnl wraps fast.** The change journal has short retention and `fsutil usn deletejournal` is itself anti-forensics; a missing/short $J is a gap to record, not proof nothing happened.
- **MFT entries get reallocated.** A deleted file's MFT record may be reused by a newer file — the name you recover may not match the clusters. Confirm name↔content with `ifind`/`ffind` before binding a carved blob to a deleted name.
- **Slack hides remnants.** A small live file leaves the tail of a previously larger file in cluster slack (`icat -s`); these fragments are small but high-signal — don't skip slack when unallocated comes back zeroed. **Missing evidence is itself a finding.**

## Failure modes
```
- mode: evidence-access failure — the disk won't mount or the volume is unreadable
  guard: Step 0 fallback chain — ewfmount/loop RO; if mounting fails, work directly off #{image_path} with TSK (fls/icat/tsk_recover/blkls all take -o offset and read the raw image, no mount needed); if all fail, record acquisition failure and pivot acquisition-custody
- mode: primary-artifact-absent — no $MFT/$UsnJrnl deleted entries (FS intact/overwritten, or ext3/4 zeroed block pointers)
  guard: record the absence; fall straight through to FS-agnostic carving (blkls → foremost/photorec/scalpel) which needs no file-system metadata; name bulk_extractor as the whole-image secondary source
- mode: tool-output drift — foremost audit.txt / photorec recup_dir / RBCmd CSV column names change so a check literal misses
  guard: on check exit 2, adjudicate from the prose expect/falsify against the receipt and cap confidence at inferred; verify recovery by counting files under the output dir (find -type f) rather than trusting a banner string; never silently pass
- mode: false-positive / truncated carves — header/footer carving emits corrupt or fragmented "files"
  guard: cross-validate with a second engine (foremost vs photorec/scalpel), open/validate before trusting, and tie each carve back to an inode via ifind; flag entropy outliers with densityscout
- mode: full-disk wipe — carving returns only zeros, recovery is genuinely impossible
  guard: do NOT report "no evidence"; report the WIPE as the finding (densityscout uniform high-entropy / all-zero unallocated), and pivot to logs/timeline for who ran the wiper
- mode: interactive-TUI trap — photorec/testdisk default to a menu UI a headless agent cannot drive
  guard: ALWAYS use the non-interactive batch form (photorec /log /d <out> /cmd <device> <options>); never launch the bare TUI; if /cmd syntax drifts, simplify the options string, do not fall back to the menu
```
Minimum set every playbook covers: evidence-access failure (Step 0 fallback chain) · primary-artifact-absent (absence recorded, secondary source named) · tool-output drift (`check` exits 2 → prose adjudication, never silent pass).

## Confidence labeling (observation → inference → conclusion)
- **confirmed:** direct receipt verbatim (e.g. the recovered file + its $J FILE_DELETE row) + ≥2 independent sources agree (e.g. $MFT name + $J delete time, or two carving engines + a hash-DB verdict) + no unrefuted counter-theory.
- **inferred:** grounded but single-source/interpretive — e.g. a carved file with no inode anchor, a deletion seen only in fls with no $J corroboration, or a check-exit-2 adjudication → hedge and tag `⚠️verify`. A carved blob with no provenance lands here at best until `ifind`-anchored.
- **insufficient_evidence:** precondition unmet (volume wiped; $J wrapped; no recovered files to reduce) or sources conflict → abstain; state what's missing (and whether it points to a wipe), do not guess.

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
- **Windows:** fully covered above — NTFS gives the richest recovery context ($MFT deleted entries, $UsnJrnl:$J prior-existence, $I30 INDX slack, Recycle-Bin $I), then FS-agnostic carving of unallocated/slack, then hash-based data reduction.
- **Linux/ESXi:** see the numbered branch (L1–L2). No MFT/USN/Recycle-Bin; on ext3/4 the inode block pointers are zeroed at delete so metadata recovery is weak — lean on `blkls`→`foremost`/`photorec` carving (FS-agnostic) and `bulk_extractor`. `ext4magic`/`extundelete` are NOT on this box (`⚠️verify` — do not name them in an executable line); recovery is carving-first on Linux.
- **macOS:** APFS/HFS+ — TSK reads HFS+ but APFS support is limited; deleted-file recovery on APFS is unreliable here. Carving (`blkls`/`foremost`/`photorec`/`bulk_extractor`) is FS-agnostic and works on the raw image regardless. `mac_apt` is **broken on this box** (`⚠️verify` — degraded), so do not rely on it for recovery; pivot macos-forensics only for surviving live artifacts.
- **Cloud:** there is no "unallocated space" to carve in a SaaS export; recovery means restoring soft-deleted objects from versioning/recycle features in the *exported* logs/snapshots. Carve only the on-disk artifacts already collected. Pivot cloud-identity-saas / cloud-iaas-control-plane for the control-plane delete/restore record.

## Real-case notes (non-obvious things to look for)
- **The $UsnJrnl:$J is the deletion goldmine even when content is gone.** It records FILE_DELETE/RENAME reason codes with filenames and timestamps long after the data is overwritten — proving a sensitive file *existed and was deleted at a specific time*, which is often the whole point in an insider/data-theft case. Always parse `$J` before concluding "no evidence of the file." `[SANS FOR500/FOR508 · high]`
- **Recycle-Bin $I records survive an "empty."** Emptying the Recycle Bin deletes the $R (content) and $I (metadata) files, but the $I records — tiny, fixed-format — frequently carve back from unallocated, restoring the original path, size, and exact delete time. An emptied bin is not a dead end. `[RBCmd / SANS DFIR · high]`
- **Format is not wipe.** A "quick format" rewrites only the file-system metadata, leaving the file data intact in what is now unallocated — `photorec`/`foremost` routinely recover thousands of intact files from a freshly formatted volume. Treat a recent `fsstat` format date plus successful carving as reformat-to-hide, not destruction. `[TestDisk/PhotoRec docs · high]`
- **Carved files have NO provenance — anchor them or they are noise.** A carved JPEG is just bytes that matched a JPEG header; tie it to an owning inode with `ifind` (data unit → inode) before attributing it to a user or a time, or the "recovery" is unattributable. This is the single most common over-claim in carving. `[TSK ifind / general DFIR practice · high]`
- **bulk_extractor finds indicators the file system hid.** Because it is signature-driven and FS-independent, it pulls emails, URLs, and credit-card numbers out of unallocated, slack, swap, and even compressed/zlib regions that a file-walk never sees — run it on the whole image, not just the live tree, when chasing exfil or C2 indicators. `[bulk_extractor docs / DFIR practice · high]`
- **Slack space is the quiet remnant store.** When a large file is deleted and a smaller one reuses its first cluster, the tail of the old file lingers in the new file's slack (`icat -s`); these fragments are small but can carry passwords, command lines, or document fragments missed everywhere else. Check slack when unallocated comes back zeroed. `[SANS FOR500 file-slack · med]`
- **densityscout's low-density reading is the trap.** densityscout reports DENSITY, not entropy directly — a *low* density score means *high* disorder (packed/encrypted), which is the opposite of intuition. Calibrate against a known-plaintext control before flagging a carved blob as encrypted. `[densityscout semantics · med]`

## ATT&CK mapping
- T1070.004 · Defense Evasion · Indicator Removal: File Deletion · the deletion this playbook recovers from (fls/$J/tsk_recover) — steps 1/2/3
- T1485 · Impact · Data Destruction · mass deletion / wipe detected via empty-zeroed unallocated — steps 5/6
- T1561 · Impact · Disk Wipe (format/repartition) · fsstat format date + carving still recovering = reformat-to-hide — steps 5/6
- T1070.001 · Defense Evasion · Clear Windows Event Logs (adjacent) · emptied Recycle Bin / cleared artifact dirs as cover-up — step 4
- T1070.006 · Defense Evasion · Timestomp · forged $SI on a recovered file, caught $SI vs $FN / exiftool — steps 1/9
- T1074 · Collection · Data Staged · recovered files reveal a staging directory of collected/exfil data — steps 3/7
- T1565.001 · Impact · Stored Data Manipulation · deleted/altered SQLite rows recovered from the freelist — step 7
- T1530 · Collection · Data from Cloud Storage Object (cross-OS note) · soft-deleted cloud objects restored from versioning — cross-OS

## Pivots (lead-to-lead graph)
- `on_recovered_sensitive_data (step 3/7 recovered exfil/staged content): insider-threat-data-theft — the recovered files ARE the stolen/staged data`
- `on_recovered_executable (step 5/6/8 carved PE + clamscan/density hit): malware-analysis-triage — triage the recovered dropper/payload`
- `on_wipe_or_mass_deletion (step 5 zeroed unallocated / step 1 deletion burst): ransomware-destructive — destructive wiper context`
- `on_deleted_mailbox_or_history (step 7 carved email/SQLite rows): browser-email-documents — reconstruct the mailbox/history`
- `on_emptied_recycle_bin (step 4 absent $I / $J delete burst): insider-threat-data-theft — cover-up of data theft`
- `on_mft_usn_anomaly (step 1/2 timestomp / orphan inode): disk-filesystem — deeper file-system structure analysis`
- `on_unmountable_or_wiped_volume (step 0/5): acquisition-custody — re-acquire or prove the destruction gap`
- `on_new_ioc_from_carve (step 7/8 recovered hash/path/address): SELF — re-enter with the recovered IOC bound into #{time_window} to find related deletions`

## Jargon decoder
- **Unallocated space:** clusters the file system has marked free; deleted file data lingers here until overwritten — the main carving target.
- **Slack space:** the unused tail of the last cluster of a file; can hold fragments of a *previous*, larger file (`icat -s`).
- **Carving:** rebuilding files from raw bytes by recognizing file signatures (headers/footers), with NO help from the file system — so no names, paths, or timestamps come back.
- **Header/footer carving:** `foremost`/`scalpel` style — find a known start marker and end marker and extract everything between; fast but breaks on fragmented files.
- **Signature carving:** `photorec` style — recognize a file by its internal structure across a broad type library; recovers more types, still nameless.
- **$MFT (Master File Table):** NTFS's index of every file; a deleted file's record (with name, times, cluster runlist) often survives until reused.
- **$UsnJrnl:$J (Update Sequence Number journal):** NTFS change journal — records create/delete/rename of files with timestamps; proves a now-gone file once existed and when it was deleted.
- **INDX / $I30:** the B-tree index of a directory's contents; slack in it names files that were removed from the folder.
- **Recycle Bin $I / $R:** Vista+ pairs — `$I` holds the deleted file's metadata (original path, size, delete time), `$R` holds the content; `INFO2` is the XP equivalent.
- **Orphan inode:** a deleted file-system metadata entry (inode/MFT record) whose name link is gone — `ils` finds these where a directory walk (`fls`) can't.
- **tsk_recover:** TSK's bulk un-delete — writes back files the file system still references, keeping names/paths.
- **blkls -e:** extracts every data unit including unallocated/slack into one stream, ready to feed a carver.
- **bulk_extractor:** a feature scanner that pulls emails/URLs/CCNs/etc. out of an entire image regardless of file system, including unallocated and compressed regions.
- **ifind / ffind:** reverse maps — `ifind` ties a data unit (a carved sector) to its owning inode; `ffind` ties an inode to its filename — the way to give a carved blob provenance.
- **Data reduction:** shrinking a huge recovered set to what matters — dedup by hash (`sha256deep`), drop known-good (NSRL via `hfind`/`sorter`), flag known-bad (`clamscan`) and high-entropy (`densityscout`).
- **densityscout:** an entropy/density triage tool — *low* density = *high* disorder = likely packed/encrypted (counter-intuitive).
- **Wipe vs delete:** delete only un-links (data recoverable); a wipe overwrites the bytes (carving returns zeros) — the all-zero result is itself a finding.

## Tuning log (append-only — the eval loop writes here; humans never edit rows)
| date | case_id | bucket missed | delta applied |
|---|---|---|---|
</content>
</invoke>
