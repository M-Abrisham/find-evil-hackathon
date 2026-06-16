---
attack_type: insider-threat-data-theft
category_id: insider-threat-data-theft
name: Insider Threat, Fraud & Data Theft
description: a trusted insider steals or leaks data (USB, cloud sync, webmail, printing) or commits fraud
version: 1
os_coverage: [windows, linux, macos, cloud]
sub_types_covered: 10
sub_types:
  - usb-mass-storage-exfil
  - cloud-sync-webmail-exfil
  - printing-exfil
  - staging-then-archive-before-transfer
  - bulk-copy-before-resignation
  - financial-record-fraud-tampering
  - unauthorized-database-access
  - photo-screenshot-exfil
  - deletion-to-cover-tracks
  - unauthorized-file-folder-access
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
    derive: "case brief if it names one (often the notice-to-last-day window); else first confirmed staging/USB/upload timestamp ±48h once a step pins one — then re-scope wide sweeps to it"
---

## In one line
Someone who is allowed inside — an employee, contractor, or admin — takes company data out the side door (a USB stick, a personal cloud or webmail account, the printer) or quietly edits records to commit fraud, instead of doing their actual job with that access.

## Use this when (triggers)
- A person is **leaving or was just let go** (resignation, termination, a dispute) and you need to know what they took on the way out.
- A **USB stick or external drive** was plugged in around a sensitive window, and you want to know what was copied to it and whether the device is personal.
- The user **opened a lot of sensitive files** (project folders, customer lists, source code, finance models) and then an **archive** (.zip/.7z/.rar) appeared shortly after — classic stage-then-pack.
- **Personal cloud or webmail** (a Drive/Dropbox/Mega/personal-Gmail tab, an rclone/OneDrive client) shows uploads or large attachments leaving the host.
- A pile of files was **printed** right before someone left, or **photos/screenshots** of a screen were taken to dodge data-loss tools.
- **Financial or database records were changed** in a way that benefits the user, or look tampered (back-dated entries, deleted rows, edited ledgers).
- Files or whole staging folders were **deleted to cover tracks** — and you want to prove what was there.

## Quick path (the 90% case)
1. **Timeline-first.** Build a quick file-system timeline of the user's data and staging paths inside `#{time_window}` — `MFTECmd` on `$MFT` and `$J` (USN change journal) sorted by time, or an `fls` bodyfile through `mactime`. Skim it BEFORE committing to a story: the order **open files → pack archive → device-in / upload / print → delete** is the case.
2. **Find the door.** Was it USB (registry `USBSTOR`/`MountedDevices` + the device's first-insertion time, via `RECmd`/`usbdeviceforensics`), cloud/webmail (browser history + a cloud-client SQLite, via `SQLECmd`/`hindsight.py`), or printing? Pin which exfil channel was used and when.
3. **Find what moved.** `LECmd`/`JLECmd` (LNK + JumpLists) and `SBECmd` (ShellBags) name the exact files and folders the user touched; `$J` (`MFTECmd`/`usn.py`) shows the archive being created, copied, renamed, or deleted.
4. **Find the cleanup.** `RBCmd` (Recycle Bin) and `$J` delete records show files/staging folders removed afterward — deletion is itself a finding, not an absence.
5. **Corroborate every channel claim with a second source.** A USB serial in the registry should match an `setupapi`/LNK volume serial; a "file appeared on E:" claim should match a `$J` FileCreate; an upload claim in history should match a cloud-client DB row. One artifact is a lead, not a fact.

If file-access, an archive, a chosen channel (USB/cloud/print), and (often) a cleanup all line up on one timeline with a corroborating second source → you are mostly done. Otherwise drop into the full Steps.

## How it unfolds (the story)
A trusted insider with legitimate read access spots data worth taking and reviews it through the normal file browser, leaving LNK/JumpList/ShellBag access traces. They **stage** it — copy the targets into a temp folder and **pack** them into a (often password-protected) `.zip`/`.7z`/`.rar`, which the `$MFT`/`$J` records as a fresh large file. Then they **move it out**: copy to a personal USB device they physically unplug, upload it to a personal cloud or webmail account, or print/screenshot it to beat data-loss tooling. A fraud-minded insider instead edits ledgers, database rows, or financial records in place. To cover tracks they delete the archive and staging folder — but the `$UsnJrnl`, Recycle Bin, and registry device history usually preserve the act of deletion and the channel used.

## Theories to test (and how to rule each out)
| Theory (who / why) | If true, you'd find… | Rule it out if… |
|---|---|---|
| **Insider data theft (departing/disgruntled employee)** | Sensitive-file access clustered in #{time_window}; a new archive right after; a personal USB first-inserted in the window OR a personal-cloud/webmail upload; deletion of the archive/staging folder afterward | No file-access cluster, no archive/copy, no personal channel, no off-hours pattern — only sanctioned corporate activity |
| **Insider fraud (records/finance tampering, not bulk exfil)** | Financial spreadsheets/DB files edited (changed $SI/$FN times, edited author in metadata), back-dated or deleted rows, ledger files in Recent/JumpLists, no bulk copy at all | The records are unchanged or every edit traces to a sanctioned business process and an authorized account |
| **Other-insider (compromised/borrowed legit account, not the named user)** | The user account active from an unusual host/hour, or an explicit-credential (4648) run-as, while the named user proves an alibi; the channel opened under that session | Logon source, workstation, and hours match the user's own baseline; the user was provably present and active |
| **Malware-driven exfil (implant copies data to C2/staging, NOT a human insider)** | Bulk copy by a SYSTEM/service account, archive built by `rundll32`/`wmiexec`/a service, persistence (service/task/run-key) created in the window, network to non-business IPs | The archive was built interactively (a user-launched 7-Zip/Explorer copy), the channel is a manual GUI upload/USB, the pacing is human not machine-rapid → reclassify to insider |
| **Sanctioned admin / IT operation** | Bulk copy or USB by IT during a backup/migration, a corporate-issued device (VID/PID/serial on the asset list), uploads to a managed @company tenant, with a change record | No change record, the device serial is unknown/personal, the destination is a personal account, or the actor is not in IT |
| **Innocent / benign (NOT an attack)** | Routine business-hours file use, a corporate USB matching the asset list, a sync to an approved company tenant, an email to a distribution list, no archive, no secrecy (plain names, no password) | A sanctioned record explains the device/upload/print AND the account+source+hours are expected → benign cause confirmed; reclassify |

*(≥1 benign + ≥1 malicious, each ACTIVELY refuted. Attacker types mapped: insider · other-insider · external-commodity (n/a — covered as malware-driven) · external-targeted (n/a) · supply-chain (sanctioned-admin/RMM) · innocent.)*

## Evidence → Tool → What it reveals (per OS)
| Evidence | SIFT tool | What it tells you *for this attack* | OS |
|---|---|---|---|
| `SYSTEM` hive `USBSTOR` / `MountedDevices` / `USB` + `NTUSER` MountPoints2 (device VID/PID/serial, friendly name, first-insertion) | `RECmd` (Kroll_Batch) / `rip.pl` / `usbdeviceforensics` | A removable device was physically attached in #{time_window}; a VID/PID/serial that is NOT on the corporate asset list (a personal device) is a strong theft link | Windows |
| `setupapi.dev.log` (first-install timestamp of a removable device) | `srch_strings` / `bstrings` | Independent first-insertion time for the USB device — corroborates the registry USBSTOR time | Windows |
| LNK shortcuts + JumpLists (target path, volume serial, drive letter, MAC times) | `LECmd` / `JLECmd` | Which sensitive files the insider opened and from/to which volume — and a LNK whose volume serial is the USB ties the file to the device | Windows |
| ShellBags (UsrClass.dat / NTUSER) — folders browsed incl. removable & deleted | `SBECmd` | The user browsed a sensitive folder (or a folder ON the USB / on an external drive) even if no file opened | Windows |
| `$MFT` + `$UsnJrnl:$J` (USN change journal) | `MFTECmd` / `analyzeMFT` / `usn.py` | The archive/staging file being created, copied, renamed, and DELETED; $SI vs $FN timestomp on a tampered record; bulk same-window file copies | Windows |
| Recycle Bin `$I`/`$R` (original path, size, delete time) | `RBCmd` | The insider deleted the archive or staging folder to cover tracks — with its original name, size and delete time | Windows |
| Browser history/downloads + cloud-client SQLite (Drive/Dropbox/OneDrive/Backup-and-Sync, webmail tabs) | `SQLECmd` / `hindsight.py` / `sqlite-carver` | Uploads to a personal cloud/webmail, searches for "upload"/"file transfer", a sync client's recorded file list and account — the cloud/webmail channel | Windows/Linux |
| Recovered SQLite freelist/unallocated (deleted history rows) | `sqlite-carver` | Deleted browser/cloud-client rows the user tried to wipe — the upload they thought was gone | all |
| `Security.evtx` 4663/4656/4660/4658 (object access on the sensitive files / DB), 4624/4648 (who, from where), 4688 (7z/rar/rclone/robocopy ran) | `EvtxECmd` / `evtxexport` | If object-access auditing was on: who touched the file/DB, when; the compression/copy tool that ran with its command line (e.g. a `-p` password flag) | Windows |
| Printing — `Microsoft-Windows-PrintService%4Operational.evtx` (307 doc printed: doc name, user, pages, printer) + spool `.SHD`/`.SPL` | `EvtxECmd` / `srch_strings` | What documents were printed, by whom, just before departure — the printing channel | Windows |
| Document/photo metadata (author, device, GPS, original timestamps) | `exiftool` | Fraud: a financial doc's author/edit-time was changed; photo-exfil: phone-camera EXIF on screenshots of a screen | all |
| Image-wide feature sweep: email addresses, URLs, credit-card/PII, search terms | `bulk_extractor` / `srch_strings` | External/personal email addresses, upload URLs, and PII that left in pagefile/unallocated outside the parsed artifacts | all |
| Known-bad / archive content triage | `clamscan` / `densityscout` | A staging tool/binary flagged, or a high-entropy (encrypted) archive a password protected — a packed-data lead | all |
| RAM image (if captured) | `vol` (Volatility 3) | A live rclone/7z/browser-upload process, mapped removable volume, or clipboard/handle traces not yet flushed to disk | Windows/Linux* |
| Linux: `/var/log` (auth/journal), bash history, `~/.gvfs`/mounts, mail spool, cloud-client dirs | `fls`/`mactime`, `log2timeline.py`, `srch_strings`, `SQLECmd` | The Linux equivalents — USB mount messages, `scp`/`rsync`/`rclone` in history, mail to external addresses, a synced cloud folder | Linux |

*Linux memory analysis in `vol` needs a matching symbol table — ⚠️verify availability before relying on it.*

## Step 0 — evidence inventory & access bootstrap
- n: 0
  tool: |
    mkdir -p "#{case_out}/receipts" "#{case_out}/extracted" && ls -laR "#{mount_root}" > "#{case_out}/receipts/00.txt" 2>&1 ; img_stat "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; mmls "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; fsstat -o #{ntfs_offset_sectors} "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; find "#{mount_root}" \( -iname "*.lnk" -o -iname "*.automaticDestinations-ms" -o -iname "UsrClass.dat" -o -iname "SYSTEM" -o -iname "NTUSER.DAT" -o -iname "\$MFT" -o -iname "History" -o -iname "places.sqlite" \) >> "#{case_out}/receipts/00.txt" 2>&1
  expect: every evidence file classified; #{image_path}, #{mount_root}, #{ntfs_offset_sectors}, #{case_out} bound; read-only access proven; the user-activity artifacts (LNK/JumpLists/ShellBags, SYSTEM/NTUSER hives, $MFT, browser DBs) enumerated, or their absence recorded as a finding
  check: |
    test -r "#{mount_root}" -o -n "$(ls "#{case_out}/extracted" 2>/dev/null)"
  falsify: evidence dir empty/unreadable, or no supported image format found, or no NTFS partition for fsstat
  on_result: {expect_met: goto 1, falsify_met: STOP — report acquisition/access failure; pivot acquisition-custody, neither: try the icat-extract fallback (fls to find the artifact inodes, icat each into #{case_out}/extracted); if that also fails treat as falsify_met}
  emits: [key_artifacts]
  serves: [usb-mass-storage-exfil, cloud-sync-webmail-exfil, printing-exfil, staging-then-archive-before-transfer, bulk-copy-before-resignation, financial-record-fraud-tampering, unauthorized-database-access, photo-screenshot-exfil, deletion-to-cover-tracks, unauthorized-file-folder-access]
  provenance: {receipt_id: 00, artifact: evidence directory listing + artifact enumeration, offset_or_row: full listing, literal_cited: image filename + artifact file list}

## Steps (executable — decision-driven)
- n: 1
  precondition: "os == windows; test -r #{mount_root}"
  tool: |
    dotnet /opt/zimmermantools/MFTECmd.dll -f "#{mount_root}/\$MFT" --csv "#{case_out}" --csvf mft.csv > "#{case_out}/receipts/01.txt" 2>&1 ; dotnet /opt/zimmermantools/MFTECmd.dll -f "#{mount_root}/\$Extend/\$UsnJrnl:\$J" --csv "#{case_out}" --csvf usn.csv >> "#{case_out}/receipts/01.txt" 2>&1
  expect: a $MFT CSV and a $J (USN) CSV — the timeline-first artifacts; sorting $J by time inside #{time_window} should surface a cluster of FileCreate/RenameNewName/DataExtend on the user data + staging paths and, ideally, one new large .zip/.7z/.rar archive
  check: |
    test -s "#{case_out}/mft.csv" && test -s "#{case_out}/usn.csv"
  falsify: no $MFT/$J parsed (image not NTFS, or journal absent/wrapped), OR no file-activity cluster anywhere in #{time_window}
  on_result: {expect_met: goto 2, falsify_met: if $J is absent fall back to analyzeMFT/usn.py over the extracted journal, and to fls -m bodyfile + mactime for a file-system timeline; if no NTFS this may be Linux — go to L1, neither: widen #{time_window} and re-sort; record absence of any activity cluster as a finding}
  emits: [timeline_events]
  serves: [staging-then-archive-before-transfer, bulk-copy-before-resignation, deletion-to-cover-tracks]
  provenance: {receipt_id: 01, artifact: $MFT + $UsnJrnl:$J, offset_or_row: usn.csv rows in #{time_window}, literal_cited: archive filename + USN reason (FileCreate/Rename/Close)}

- n: 2
  precondition: "exists #{case_out}/mft.csv"
  tool: |
    for f in $(find "#{mount_root}" -iname "*.lnk" 2>/dev/null); do dotnet /opt/zimmermantools/LECmd.dll -f "$f" >> "#{case_out}/receipts/02.txt" 2>&1 ; done ; dotnet /opt/zimmermantools/JLECmd.dll -d "#{mount_root}" --csv "#{case_out}" --csvf jumplists.csv >> "#{case_out}/receipts/02.txt" 2>&1 ; dotnet /opt/zimmermantools/SBECmd.dll -d "#{mount_root}" --csv "#{case_out}" >> "#{case_out}/receipts/02.txt" 2>&1
  expect: LNK/JumpList rows naming the sensitive files the user opened (project/finance/customer paths) with access times that PRECEDE the archive from step 1; and/or ShellBags showing the user browsed those folders or a folder on a removable/external volume — the access-then-stage intent chain
  check: |
    test -s "#{case_out}/jumplists.csv" || grep -qiE "Source File|Target.*(\\\\Users\\\\|\\.xlsx|\\.docx|\\.zip|\\.7z|\\.csv)" "#{case_out}/receipts/02.txt"
  falsify: no LNK/JumpList/ShellBag references to sensitive files in #{time_window} — no evidenced file-access by this user (intent not shown here)
  on_result: {expect_met: record the accessed file paths + any volume serial; goto 3, falsify_met: record "no file-access trace"; the theft may be DB/print/fraud not file-open — goto 5 and goto 6, neither: parse each JumpList/LNK individually with -f and re-check; widen #{time_window}}
  emits: [key_artifacts, timeline_events]
  serves: [unauthorized-file-folder-access, bulk-copy-before-resignation, staging-then-archive-before-transfer]
  provenance: {receipt_id: 02, artifact: LNK / JumpList / ShellBags, offset_or_row: jumplists.csv row / LECmd target line, literal_cited: sensitive file path + volume serial}

- n: 3
  precondition: "exists #{case_out}/receipts/00.txt; test -r #{mount_root}"
  tool: |
    dotnet /opt/zimmermantools/RECmd/RECmd.dll --bn /opt/zimmermantools/RECmd/BatchExamples/Kroll_Batch.reb -d "#{mount_root}" --csv "#{case_out}" --csvf usb_reg.csv > "#{case_out}/receipts/03.txt" 2>&1 ; /opt/usbdeviceforensics/bin/usbdeviceforensics -r "#{mount_root}" >> "#{case_out}/receipts/03.txt" 2>&1 ; srch_strings "#{mount_root}/Windows/INF/setupapi.dev.log" 2>/dev/null | grep -iE "USBSTOR|Disk&Ven|Section start" >> "#{case_out}/receipts/03.txt" 2>&1
  expect: a USBSTOR/MountedDevices entry for a removable device with a VID/PID/serial and friendly name, first-inserted inside #{time_window}; a serial that is NOT on the corporate asset list (a personal device) and whose volume serial matches a step-2 LNK is a strong USB-exfil link
  check: |
    grep -qiE "USBSTOR|MountedDevices|Disk&Ven|VID_|PID_|VEN_" "#{case_out}/receipts/03.txt" || test -s "#{case_out}/usb_reg.csv"
  falsify: no removable-device history in the hives AND no setupapi USBSTOR section in #{time_window} — USB was not the channel (or this host never had one attached)
  on_result: {expect_met: record device serial + first-insertion time as an IOC; goto 4, falsify_met: USB not used; go to 4 to test the cloud/webmail channel instead, neither: run rip.pl -r against the SYSTEM hive (usbstor/mountdev plugins) and re-check; correlate the friendly name with the step-2 LNK volume serial}
  emits: [key_iocs, actor_accounts, timeline_events]
  serves: [usb-mass-storage-exfil]
  provenance: {receipt_id: 03, artifact: SYSTEM/NTUSER hive USBSTOR + setupapi.dev.log, offset_or_row: usb_reg.csv row / setupapi Section start, literal_cited: device VID/PID/serial + first-insertion timestamp}

- n: 4
  precondition: "exists #{case_out}/receipts/00.txt; test -r #{mount_root}"
  tool: |
    dotnet /opt/zimmermantools/SQLECmd/SQLECmd.dll -d "#{mount_root}" --csv "#{case_out}" > "#{case_out}/receipts/04.txt" 2>&1 ; for h in $(find "#{mount_root}" -iname "History" -path "*Chrom*" -o -iname "History" -path "*Edge*" 2>/dev/null | xargs -I{} dirname {} | sort -u); do /opt/pyhindsight/bin/hindsight.py -i "$h" -o "#{case_out}/extracted/hindsight_$(basename $(dirname "$h"))" >> "#{case_out}/receipts/04.txt" 2>&1 ; done ; find "#{mount_root}" -iname "places.sqlite" -exec /opt/sqlite-carver/bin/sqlite-carver -f {} \; >> "#{case_out}/receipts/04.txt" 2>&1
  expect: browser history/downloads or a cloud-client SQLite (Drive/Dropbox/OneDrive sync DB) showing an upload to a PERSONAL cloud/webmail account, searches for "upload"/"file transfer"/a cloud provider, or a sync-client recorded file list + account — the cloud/webmail channel, timed in #{time_window}; carved freelist rows may recover history the user deleted
  check: |
    grep -qiE "drive\.google|dropbox|mega\.nz|wetransfer|onedrive|mail\.google|outlook\.|upload|webmail" "#{case_out}/receipts/04.txt" || ls "#{case_out}"/*Chrome*.csv "#{case_out}"/*WebHistory*.csv 2>/dev/null
  falsify: no personal-cloud/webmail/upload URL in history, no cloud-client DB, no recovered upload row — the cloud/webmail channel is not evidenced
  on_result: {expect_met: record the destination account/URL + upload time as an IOC; goto 5, falsify_met: cloud/webmail not used; if neither USB (step 3) nor cloud is present, test printing/fraud at goto 6, neither: carve deleted rows with sqlite-carver over the History/places.sqlite freelist; bulk_extractor the image for email/URL features and re-check}
  emits: [key_iocs, actor_accounts, timeline_events]
  serves: [cloud-sync-webmail-exfil]
  provenance: {receipt_id: 04, artifact: browser History/downloads + cloud-client SQLite, offset_or_row: SQLECmd/hindsight CSV row, literal_cited: personal-cloud/webmail destination URL or account + upload timestamp}

- n: 5
  precondition: "exists #{case_out}/mft.csv"
  tool: |
    dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll -d "#{mount_root}" --csv "#{case_out}" --csvf events.csv > "#{case_out}/receipts/05.txt" 2>&1 ; grep -E ",4663,|,4656,|,4660,|,4658,|,4688,|,4624,|,4648," "#{case_out}/events.csv" >> "#{case_out}/receipts/05.txt" 2>&1 ; grep -iE "7z|rar\.exe|rclone|robocopy|xcopy|WinSCP|powershell.*Compress" "#{case_out}/events.csv" >> "#{case_out}/receipts/05.txt" 2>&1
  expect: with auditing on — 4663/4656/4660 object-access on the sensitive files or a DB file (read/handle/delete), tying the user account to the data; and/or 4688 process-creation for a compression/copy/exfil tool (7z, rar, rclone, robocopy, WinSCP, Compress-Archive) with its command line, launched by the user in #{time_window}
  check: |
    grep -qiE ",4663,|,4656,|,4660,|,4688,|7z|rclone|robocopy|rar" "#{case_out}/receipts/05.txt"
  falsify: no object-access or process-creation events (auditing off — common) and no exfil-tool command line — execution/access not evidenced IN the logs
  on_result: {expect_met: record the tool command line / accessed-object + account as IOCs; goto 6, falsify_met: auditing likely off; corroborate the tool off-log via $MFT/$J (step 1) and AmcacheParser/RECmd UserAssist; pivot windows-execution-artifacts, neither: parse Security.evtx per-file with -f and re-check; for database access hunt app-layer audit/query logs and 4663 handles on the DB file}
  emits: [key_iocs, actor_accounts, timeline_events]
  serves: [unauthorized-database-access, staging-then-archive-before-transfer, bulk-copy-before-resignation]
  provenance: {receipt_id: 05, artifact: Security.evtx (4663/4656/4688), offset_or_row: events.csv object-access/4688 row, literal_cited: tool command line or accessed-object path + account}

- n: 6
  precondition: "exists #{case_out}/events.csv"
  tool: |
    grep -E ",307," "#{case_out}/events.csv" > "#{case_out}/receipts/06.txt" 2>&1 ; grep -iE "PrintService|spool|\.SHD|\.SPL" "#{case_out}/events.csv" >> "#{case_out}/receipts/06.txt" 2>&1 ; for d in $(find "#{mount_root}" -ipath "*spool/PRINTERS*" -type d 2>/dev/null); do srch_strings -f "$d"/* 2>/dev/null >> "#{case_out}/receipts/06.txt" ; done ; find "#{mount_root}" \( -iname "*.xlsx" -o -iname "*.docx" -o -iname "*.jpg" -o -iname "*.png" \) -newermt "$(echo #{time_window} | cut -d. -f1)" -exec exiftool -Author -ModifyDate -Make -GPSPosition {} \; >> "#{case_out}/receipts/06.txt" 2>&1
  expect: PrintService Operational 307 rows (document name, user, pages, printer) for sensitive docs printed near departure, or spool .SHD/.SPL remnants; OR exiftool showing a finance doc whose Author/ModifyDate was altered (fraud) or a screenshot/photo carrying phone-camera Make/GPS (photo-exfil) — the print/photo/fraud channels
  check: |
    grep -qiE ",307,|PrintService|\.SHD|\.SPL|Author|Make|ModifyDate" "#{case_out}/receipts/06.txt"
  falsify: no print events/spool remnants AND no metadata anomaly on the documents/photos — these channels are not evidenced
  on_result: {expect_met: record printed-doc names / tampered-metadata as findings; goto 7, falsify_met: record "no print/photo/fraud-metadata channel"; goto 7, neither: parse PrintService%4Operational.evtx per-file with -f; widen the metadata sweep to all user-doc paths and re-check}
  emits: [key_artifacts, exfil_or_encryption_facts, timeline_events]
  serves: [printing-exfil, photo-screenshot-exfil, financial-record-fraud-tampering]
  provenance: {receipt_id: 06, artifact: PrintService Operational.evtx / spool / document metadata, offset_or_row: events.csv 307 row / exiftool field, literal_cited: printed document name + user, or altered Author/ModifyDate}

- n: 7
  precondition: "exists #{case_out}/mft.csv"
  tool: |
    find "#{mount_root}" -ipath "*\$Recycle.Bin*" -iname "\$I*" -exec dotnet /opt/zimmermantools/RBCmd.dll -f {} --csv "#{case_out}" --csvf recyclebin.csv \; > "#{case_out}/receipts/07.txt" 2>&1 ; grep -iE "FileDelete|RenameOldName|\.zip|\.7z|\.rar" "#{case_out}/usn.csv" >> "#{case_out}/receipts/07.txt" 2>&1 ; /opt/usnparser/bin/usn.py -f "#{mount_root}/\$Extend/\$UsnJrnl:\$J" -o "#{case_out}/extracted/usn_full" >> "#{case_out}/receipts/07.txt" 2>&1
  expect: Recycle Bin $I rows OR $J FileDelete/RenameOldName entries showing the archive or the staging folder was DELETED shortly after the copy/upload — the cleanup; the original path/size/delete-time prove what was removed even though the file is gone
  check: |
    test -s "#{case_out}/recyclebin.csv" || grep -qiE "FileDelete|RenameOldName" "#{case_out}/receipts/07.txt"
  falsify: no deletion of the archive/staging files in #{time_window} (the data may still be live on disk — recover and hash it) — no track-covering evidenced
  on_result: {expect_met: record the deleted archive/path + delete-time as a finding; goto 8, falsify_met: record "no deletion"; if the archive is still live, icat/tsk_recover it and hash for the report; goto 8, neither: run analyzeMFT for $SI vs $FN timestomp on the archive record; recover deleted INDX entries and re-check}
  emits: [key_artifacts, exfil_or_encryption_facts, timeline_events]
  serves: [deletion-to-cover-tracks, staging-then-archive-before-transfer]
  provenance: {receipt_id: 07, artifact: $Recycle.Bin $I + $UsnJrnl:$J, offset_or_row: recyclebin.csv row / usn.csv FileDelete row, literal_cited: deleted archive original path + size + delete timestamp}

- n: 8
  precondition: "exists #{case_out}/mft.csv"
  tool: |
    log2timeline.py --status_view none "#{case_out}/insider.plaso" "#{mount_root}" > "#{case_out}/receipts/08.txt" 2>&1 ; psort.py -o l2tcsv "#{case_out}/insider.plaso" > "#{case_out}/super.csv" 2>> "#{case_out}/receipts/08.txt" ; bulk_extractor -o "#{case_out}/extracted/bulk" "#{image_path}" >> "#{case_out}/receipts/08.txt" 2>&1 ; pinfo.py "#{case_out}/insider.plaso" >> "#{case_out}/receipts/08.txt" 2>&1
  expect: a fused super-timeline placing file-access (LNK/ShellBag) → archive create ($J) → channel (USB first-insert / cloud upload / print 307) → deletion ($I/$J) in a coherent order with no unexplained gap; and bulk_extractor email.txt/url.txt confirming the external/personal destination address outside the parsed artifacts, all inside #{time_window}
  check: |
    test -s "#{case_out}/super.csv" && grep -qiE "lnk|usnjrnl|olecf|sqlite|winreg|prefetch|file_entry" "#{case_out}/super.csv"
  falsify: ordering is impossible (e.g. archive created before any file-access, or upload before the archive exists) OR an unexplained gap that no deletion/clock event accounts for
  on_result: {expect_met: COMMIT the conclusion with a confidence label; close per the gate, falsify_met: re-open the Theories table; the inversion may mean clock manipulation or a missed step — anchor to $J USN sequence numbers instead of host time, neither: run pinfo.py to confirm the lnk/winreg/sqlite parsers ran; re-filter psort.py to #{time_window} and re-check}
  emits: [timeline_events, key_iocs]
  serves: [usb-mass-storage-exfil, cloud-sync-webmail-exfil, staging-then-archive-before-transfer, deletion-to-cover-tracks]
  provenance: {receipt_id: 08, artifact: super-timeline + bulk_extractor features, offset_or_row: super.csv ordered rows / bulk email.txt, literal_cited: ordered access→archive→channel→delete chain + external destination address}

## Linux branch (L1..Ln) — REQUIRED, numbered, same step shape
- n: L1
  precondition: "os == linux"
  tool: |
    fsstat -o #{ntfs_offset_sectors} "#{image_path}" > "#{case_out}/receipts/L01.txt" 2>&1 ; find "#{mount_root}/home" -maxdepth 3 \( -iname ".bash_history" -o -iname "places.sqlite" -o -ipath "*Dropbox*" -o -ipath "*rclone*" -o -ipath "*OneDrive*" \) 2>/dev/null >> "#{case_out}/receipts/L01.txt" ; ls "#{mount_root}/var/log" >> "#{case_out}/receipts/L01.txt" 2>&1
  expect: this image is Linux (ext/xfs fsstat, /home + /var/log present) — Windows USBSTOR/LNK/Recycle.Bin do NOT exist here; insider exfil instead lives in shell history (scp/rsync/rclone/curl-upload), USB mount messages in the journal/dmesg, mail spool, and synced cloud-client dirs under the user home
  check: |
    test -d "#{mount_root}/home" -o -n "$(grep -iE 'ext[234]|xfs' "#{case_out}/receipts/L01.txt" 2>/dev/null)"
  falsify: fsstat reports NTFS and a Windows\System32 tree exists — this is Windows, not Linux; the main branch applies (return to Step 1)
  on_result: {expect_met: goto L2, falsify_met: this is Windows — run the main Windows Steps 1-8 not this branch, neither: confirm OS family from the Step 0 fsstat/disktype receipt; if still ambiguous treat as Windows and run the main branch}
  emits: [key_artifacts]
  serves: [usb-mass-storage-exfil, unauthorized-file-folder-access]
  provenance: {receipt_id: L01, artifact: file system + /home + /var/log listing, offset_or_row: fsstat header + dir listing, literal_cited: ext/xfs FS type or /home present (Linux-confirmed)}

- n: L2
  precondition: "os == linux"
  tool: |
    log2timeline.py --status_view none "#{case_out}/linux.plaso" "#{mount_root}" > "#{case_out}/receipts/L02.txt" 2>&1 ; psort.py -o l2tcsv "#{case_out}/linux.plaso" > "#{case_out}/linux_super.csv" 2>> "#{case_out}/receipts/L02.txt" ; for h in $(find "#{mount_root}/home" -maxdepth 3 -iname ".bash_history" -o -iname ".zsh_history" 2>/dev/null); do srch_strings "$h" | grep -iE "scp|rsync|rclone|curl.*upload|tar .*c|zip |7z |mail|sftp|dd if=" >> "#{case_out}/receipts/L02.txt" ; done ; srch_strings "#{mount_root}/var/log/syslog" 2>/dev/null | grep -iE "usb-storage|sd[a-z].*Attached|Mounted" >> "#{case_out}/receipts/L02.txt" 2>&1 ; bulk_extractor -o "#{case_out}/extracted/bulk_lx" "#{image_path}" >> "#{case_out}/receipts/L02.txt" 2>&1
  expect: shell history showing staging+exfil commands (tar/zip then scp/rsync/rclone/curl-upload/sftp, or mail to an external address), USB-storage attach/mount lines in syslog/journal (=USB channel), a synced cloud-client folder, and bulk_extractor email/url features confirming the external destination — ordered in the super-timeline inside #{time_window}
  check: |
    test -s "#{case_out}/linux_super.csv" || grep -qiE "scp|rsync|rclone|usb-storage|Mounted|curl" "#{case_out}/receipts/L02.txt"
  falsify: /var/log empty or history wiped (auth.log/bash_history truncated to zero) — Linux anti-forensics; record the gap as a finding and carve deleted fragments
  on_result: {expect_met: record account + exfil command + destination + USB mount; commit with confidence label, falsify_met: record log/history-wipe as a finding; carve deleted log/history fragments with srch_strings/bulk_extractor over unallocated; pivot linux-host-forensics, neither: widen #{time_window}; parse journald under /var/log/journal via log2timeline and re-render}
  emits: [actor_accounts, key_iocs, timeline_events]
  serves: [usb-mass-storage-exfil, cloud-sync-webmail-exfil, staging-then-archive-before-transfer, deletion-to-cover-tracks]
  provenance: {receipt_id: L02, artifact: bash/zsh history + syslog/journal + cloud-client dir, offset_or_row: linux_super.csv rows / history grep hits, literal_cited: exfil command line + destination address/host + USB mount line}

## Corroboration (two-source rule)
`required_sources: 2` · `pairs:`
- `[ USBSTOR/MountedDevices device serial (step 3) ↔ setupapi.dev.log first-install OR a LNK volume serial (step 3/2) ]`
- `[ archive create in $J (step 1) ↔ the archive's $MFT $SI create time / on-disk presence (step 1) ]`
- `[ file-access LNK/JumpList (step 2) ↔ Security 4663 object-access on the same file (step 5) ]`
- `[ cloud/webmail upload URL in history (step 4) ↔ a cloud-client SQLite file-list row OR a bulk_extractor email/url feature (step 4/8) ]`
- `[ printed-doc 307 (step 6) ↔ a spool .SHD/.SPL remnant OR a LNK to the same document (step 6/2) ]`
- `[ archive deletion in $J/$I (step 7) ↔ the archive's prior existence in $MFT/$J create record (step 1/7) ]`
- `[ per-artifact timeline ↔ fused super-timeline order (step 8) ]`

One hit is a *lead*; promote to *fact* only when its paired source agrees.

## Don't get fooled (red flags & anti-forensics)
- **Deletion is a finding, not an absence.** An archive or staging folder that is GONE is evidence of cover-up — the Recycle Bin `$I`, `$UsnJrnl` FileDelete, and INDX slack preserve the original name, size and delete time. Never read "no archive on disk" as "nothing was taken."
- **A USB serial in the registry is a lead, not proof of copy.** USBSTOR proves a device was *attached*, not that THIS data went onto it. Tie the device to the data via a LNK whose volume serial = the USB's, a ShellBag of a folder on that volume, or a `$J` copy to its drive letter.
- **Object-access auditing (4663) is usually OFF.** No 4663/4656 does NOT mean the file was untouched. Pivot to LNK/JumpLists, ShellBags, and `$J` — report the auditing gap, never assume.
- **Cloud/webmail leaves little on the host.** A browser-tab upload may leave only a history URL and a cache fragment; the bytes go straight to the provider. Carve deleted history rows (`sqlite-carver`), sweep the image for the destination email/URL (`bulk_extractor`), and treat the cloud-side log as the second source (request it).
- **Timestomp on the staged/tampered file.** A fraud edit or a staged archive may show a backdated `$SI` time; compare `$SI` vs `$FN` with `MFTECmd`/`analyzeMFT` and trust `$J` USN sequence order over host time.
- **Corporate vs personal device/account is the whole case.** A managed USB on the asset list or a sync to the company tenant is benign; the theft signal is a *personal* device serial or a *personal* cloud/webmail account. Always classify the device/account before calling it exfil.
- **Encrypted/password-protected archive hides its contents.** A high-entropy `.7z`/`.zip` (flag with `densityscout`) you cannot open still proves staging — record the archive name/size/time as a finding and seek the password or the source files.
- **Wiped history/clock tricks.** A cleared browser DB, an emptied Recycle Bin, or a manipulated clock are themselves findings; anchor the timeline to `$UsnJrnl` USN sequence numbers (monotonic) rather than host clock. **Missing evidence is itself a finding.**

## Failure modes
```
- mode: evidence-access failure — the disk will not mount or the user profile is unreadable
  guard: Step 0 fallback chain — ewfmount/loop RO, else TSK fls/icat the hive/$MFT/$J/LNK inodes into #{case_out}/extracted; if all fail record acquisition failure and pivot acquisition-custody
- mode: primary-artifact-absent — $UsnJrnl wrapped/absent, no LNK/JumpLists, browser DB missing (cleared or never collected)
  guard: record the absence as a finding (a wiped $J/history IS evidence of cover-up); name the secondary sources ($MFT, ShellBags, Recycle Bin, registry USBSTOR, bulk_extractor) and pivot disk-filesystem / browser-email-documents
- mode: tool-output drift — EvtxECmd/SQLECmd/MFTECmd map or CSV column names change, or a comma-in-field breaks a grep literal so check exits 2
  guard: on check exit 2, adjudicate from the prose expect/falsify against the receipt, cap confidence at inferred; fall back to raw evtxexport / analyzeMFT / sqlite-carver and grep directly, never silently pass
- mode: auditing disabled — no 4663/4688 because object-access/process auditing GPO was off
  guard: do not infer "nothing happened"; corroborate off-log via LNK/JumpLists, ShellBags, $J, RECmd UserAssist/Amcache, and report the auditing gap explicitly
- mode: cloud-only exfil — the bytes left via a browser tab and almost nothing is on the host
  guard: carve deleted history rows (sqlite-carver), bulk_extractor the image for the destination email/URL, and request the cloud/webmail provider-side audit log as the second source — record host-side as lead-only
```
Minimum set every playbook covers: evidence-access failure (Step 0 fallback chain) · primary-artifact-absent (absence recorded, secondary source named) · tool-output drift (`check` exits 2 → prose adjudication, never silent pass).

## Confidence labeling (observation → inference → conclusion)
- **confirmed:** direct receipt verbatim (e.g. the USBSTOR serial row, the `$J` archive-create line) + ≥2 independent sources agree (registry + LNK volume serial, or history URL + cloud-client DB) + no unrefuted counter-theory.
- **inferred:** grounded but single-source/interpretive — e.g. a USBSTOR entry with no LNK/volume-serial tie, a history URL with no second source, a `$SI`/`$FN` gap read as timestomp, or RECmd BAM/USB coverage on newer Win10/11 unverified → hedge and tag `⚠️verify`. Every `check`-exit-2 adjudication lands here at best.
- **insufficient_evidence:** precondition unmet (hives absent; auditing off; browser DB cleared; no RAM image) or sources conflict → abstain; state what is missing, do not guess.

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
- **Windows:** fully covered above — registry USBSTOR + LNK/JumpLists/ShellBags + `$MFT`/`$J` + Recycle Bin + browser/cloud SQLite + PrintService are the richest insider-exfil sources.
- **Linux/ESXi:** no USBSTOR/LNK/Recycle.Bin — see the numbered Linux branch (L1–L2). Equivalents: shell history (`scp`/`rsync`/`rclone`/`curl` upload = the exfil command), `/var/log/syslog` + journald `usb-storage`/mount lines (= USB attach), the mail spool (`/var/mail`, `pffexport` only for PST), synced cloud-client dirs under `$HOME`, and `auth.log`/`sudo` for who. `bash_history`/`auth.log` wiped is itself a finding.
- **macOS:** no registry — USB history lives in IORegistry/`KnowledgeC`/system logs, file access in `~/Library` Recent items and `.DS_Store`/Spotlight, cloud sync in the client plists/DBs. This box's `mac_apt` is broken (`⚠️verify` — degraded); use `log2timeline.py` for plist/FSEvents/Safari and raw `sqlite3`/`SQLECmd` on KnowledgeC/QuarantineEvents. Treat findings as lead-only and pivot macos-forensics.
- **Cloud:** the upload's other half lives provider-side — Drive/Dropbox/OneDrive admin logs, Gmail/Exchange message-trace, the SaaS audit log. No host artifact proves what the provider received; request the provider-side audit log as the authoritative second source. Pivot cloud-identity-saas.

## Real-case notes (non-obvious things to look for)
- **The volume serial in a LNK is the bridge from a file to a USB.** A recent-file LNK records the target's **volume serial number**; when that serial equals the removable device's volume serial (registry `MountedDevices` / the drive's `$Boot` VSN), you have tied a specific sensitive file to a specific personal USB — far stronger than "a device was attached." `[SANS FOR500 USB/LNK correlation · high]`
- **Stage-then-archive leaves a tell even after deletion.** Insiders commonly copy targets into a temp folder and pack a password-protected `.7z`/`.zip`; even after they delete it, the `$UsnJrnl` FileCreate→Close→FileDelete sequence and an INDX slack entry in the parent folder preserve the archive's name, size and lifetime. Always read `$J` for the deleted archive, not just the live `$MFT`. `[MITRE T1560 / general DFIR practice · high]`
- **Cloud-tab exfil hides from host artifacts but not from the carve.** A drag-and-drop upload to a personal Drive/Dropbox tab may leave only a history URL and a cache thumbnail; the destination account and filenames often survive in the browser-cache, pagefile, and unallocated — sweep with `bulk_extractor` (email/url) and carve the History freelist. The decisive proof is usually the provider-side log, which must be requested. `[MITRE T1567.002 · high]`
- **Print and photo are the data-loss-tool bypass.** When DLP blocks USB and cloud, insiders print sensitive docs (PrintService Operational **307** logs the document name + user + pages) or photograph the screen with a phone (EXIF `Make`/GPS on the resulting image). Check the print Operational log and image metadata when the obvious channels look clean. `[MITRE T1052 / DLP-bypass tradecraft · med]`
- **Fraud is an in-place edit, not a copy.** Records/finance tampering shows as a changed `$SI`/`$FN` on a ledger or DB file, an altered author/edit-time in document metadata (`exiftool`), or deleted DB rows recoverable from SQLite freelist — there may be NO exfil at all. Don't only hunt for archives; test the integrity of the records themselves. `[MITRE T1565 · med]`
- **Distrust host time around the cleanup.** Insiders may delete artifacts and some manipulate the clock; if the timeline is internally impossible, anchor to the monotonic `$UsnJrnl` **USN sequence numbers** and `$LogFile` order rather than `$SI` timestamps. `⚠️verify any timeline keyed purely to host clock.` `[general DFIR anti-forensics practice · med]`

## ATT&CK mapping
- T1052.001 · Exfiltration · Exfiltration over USB · USBSTOR first-insertion + LNK volume-serial tie — step 3
- T1567.002 · Exfiltration · Exfil to Cloud Storage · personal Drive/Dropbox/Mega upload in browser/cloud-client — step 4
- T1567 · Exfiltration · Exfiltration Over Web Service · webmail/file-transfer-site upload — step 4
- T1560.001 · Collection · Archive via Utility · 7z/rar/Compress-Archive staging archive — steps 1/5
- T1119 · Collection · Automated/bulk Collection · bulk copy of project/customer files before resignation — steps 1/2
- T1005 · Collection · Data from Local System · LNK/JumpList/ShellBag access to sensitive files — step 2
- T1213 · Collection · Data from Information Repositories · unauthorized database/file-share access (4663) — step 5
- T1052 · Exfiltration · Exfiltration Over Physical Medium · printing sensitive docs (PrintService 307) — step 6
- T1565.001 · Impact · Stored Data Manipulation · finance/ledger/DB record tampering (fraud) — step 6
- T1070.004 · Defense Evasion · File Deletion · archive/staging-folder deletion to cover tracks — step 7
- T1070.006 · Defense Evasion · Timestomp · $SI vs $FN on the staged/tampered file — steps 1/7
- T1078 · Initial Access/Privilege · Valid Accounts · the insider's own legitimate logon (4624/4648) — step 5

## Pivots (lead-to-lead graph)
- `on_usb_device_found (step 3 USBSTOR serial): windows-execution-artifacts — corroborate the file→device tie via LNK/JumpLists/ShellBags volume serial`
- `on_cloud_or_webmail_upload (step 4 personal upload): cloud-identity-saas — pull the provider-side Drive/Gmail/Dropbox audit log as the authoritative second source`
- `on_browser_upload_or_phish (step 4 history/download): browser-email-documents — deep-dive the browser/email artifacts for the destination and any lure`
- `on_exfil_tool_or_archive (step 1/5 7z/rar/rclone): malware-analysis-triage — triage the staging/exfil binary if its provenance is unclear`
- `on_object_access_or_db (step 5 4663/4624): windows-event-logs — full logon/object-access reconstruction for who-from-where`
- `on_deleted_or_carved_data (step 7 deleted archive): file-recovery-carving — recover and hash the deleted archive/staging files`
- `on_record_or_db_tampering (step 6 metadata/$SI anomaly): disk-filesystem — confirm the in-place edit and timestomp at the file-system layer`
- `on_cleanup_or_clock_gap (step 7/8 deletion or impossible timeline): SELF — re-enter with the cleanup timestamp bound into #{time_window} to bracket what was hidden`
- `on_evidence_unmountable (step 0/1): acquisition-custody — re-acquire or prove the collection gap`

## Jargon decoder
- **Insider:** a person with legitimate access — employee, contractor, admin — who abuses it, rather than an outside hacker breaking in.
- **Exfiltration (exfil):** moving data OUT of the organization (to USB, cloud, webmail, print).
- **Staging:** gathering the target files into one place (a temp folder) before packing/moving them.
- **Archive:** a single packed file (`.zip`/`.7z`/`.rar`) holding many files, often password-protected.
- **USBSTOR / MountedDevices:** registry keys that record every USB mass-storage device ever attached — its vendor/product ID, serial, friendly name and first-insertion time.
- **VID/PID/serial:** a USB device's Vendor ID, Product ID, and unique serial — the fingerprint that says "this exact stick", and whether it is corporate or personal.
- **Volume serial number (VSN):** a number stamped on a formatted volume; it appears in LNK files and lets you tie a recent-file shortcut to the specific drive/USB it lived on.
- **LNK / JumpList:** Windows shortcut and per-app recent-file records — they show which files the user opened and from which drive.
- **ShellBags:** registry traces of which folders a user browsed in Explorer — including folders on removable or now-deleted drives.
- **$MFT / $SI vs $FN:** NTFS Master File Table / the two timestamp sets in a file record; `$SI` is easy to forge, `$FN` harder — disagreement hints at **timestomp**.
- **$UsnJrnl:$J (USN change journal):** NTFS's running list of every file create/rename/delete — it preserves the act of deletion (and the deleted file's name) even after the file is gone.
- **Recycle Bin $I/$R:** the `$I` index file (original path, size, delete time) and `$R` data of a Recycle-Bin-deleted file — proof of what was deleted and when.
- **Cloud-sync client:** a desktop app (Drive/Dropbox/OneDrive) that mirrors files to a personal cloud account — its SQLite DB lists what it synced.
- **Webmail:** browser-based email (personal Gmail/Outlook) used to attach and send data out, bypassing the corporate mail server.
- **PrintService 307:** the Windows PrintService Operational event that logs a document being printed — name, user, pages, printer.
- **Timestomp:** forging a file's timestamps to hide when it was created/edited.
- **Super-timeline:** one merged chronology across many artifacts, built with `log2timeline.py` + `psort.py`.
- **bulk_extractor:** a tool that sweeps a whole image for features — email addresses, URLs, credit-card numbers — independent of the file system.

## Tuning log (append-only — the eval loop writes here; humans never edit rows)
| date | case_id | bucket missed | delta applied |
|---|---|---|---|
