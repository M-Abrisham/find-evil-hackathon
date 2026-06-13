---
attack_type: ransomware-destructive
category_id: ransomware-destructive
name: Impact, Ransomware & Destructive Attacks
description: mass encryption, ransom notes, wipers and sabotage: prove what ran, what was hit, what is recoverable
version: 1
os_coverage: [windows, linux, macos, cloud]
sub_types_covered: 7
sub_types:
  - mass-file-encryption-extension-change
  - ransom-note-drop
  - vss-shadow-copy-deletion
  - wiper-mbr-boot-destruction
  - double-extortion-staging-exfil
  - service-backup-sabotage
  - recoverable-data-assessment
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
    derive: "case brief if it names one; else the first confirmed encryption-burst timestamp ±48h once a step pins T0 — then re-scope wide sweeps to it"
---

## In one line
A program — run by an outsider who broke in, or by an insider — scrambles your files so you cannot open them, deletes the system's built-in backups so you cannot roll back, and usually leaves a note demanding payment. "Destructive" variants may not even hold a key: they just wreck the data.

## Use this when (triggers)
- A flood of files changed at almost the same moment, many now ending in the same odd extension (e.g. `.lockbit`, `.encrypted`, `.<8-random-chars>`).
- Text/HTML files named like `HOW_TO_DECRYPT`, `RECOVER-FILES`, `!!!READ_ME!!!`, `*_readme.txt` appear across many folders.
- Shadow copies / Windows backups are gone, or "System Restore" / "Previous Versions" is empty.
- Users cannot open documents; apps report "file corrupt"; servers (including ESXi/VM hosts) went offline.
- Security tooling was disabled or its logs were cleared right before the outage.
- A host will not boot at all (a blank or garbage boot screen) — a possible MBR/boot-record wiper rather than a file encryptor.

## Quick path (the 90% case)
1. **Timeline-first.** Build the encryption-burst timeline BEFORE committing to a story: parse `$MFT` + `$UsnJrnl:$J` with `MFTECmd` (sort by time) and skim for a **spike** of files gaining ONE new extension inside a short window; or fold the image into a super-timeline with `log2timeline.py` + `psort.py` scoped to `#{time_window}`. The order *entry → execution → shadow deletion → mass encryption → note* is the case.
2. **Confirm and size the encryption.** Look in the `$MFT`/`$J` for hundreds-to-thousands of rename/extension-change events clustered in minutes; sample a few recovered files through `densityscout` — truly encrypted files look like random noise (high density). Beware: intermittent encryptors leave low-density regions.
3. **Find the ransom note and read it.** `fls`/`icat`/`srch_strings` locate and extract `HOW_TO_DECRYPT`-style files; the note text + the new extension usually name the ransomware family. NO note + mass destruction → suspect a wiper, not an encryptor.
4. **Check what was destroyed for recovery.** `vshadowinfo` to see whether any Volume Shadow Copies survive or were deleted; `EvtxECmd` over `Security.evtx`/`System.evtx` for `vssadmin Delete Shadows`, `wbadmin delete catalog`, or `bcdedit recoveryenabled No` (4688 / 524).
5. **Pin execution + entry, then assess recoverable data.** `EvtxECmd` Security 4688 + `RECmd`/`rip.pl` (UserAssist/BAM) to find the encryptor binary; 4624 type 10 (RDP) or `pffexport` of a mailbox for the entry vector; `vshadowmount` any surviving store + `tsk_recover`/`photorec` to estimate what can still be recovered.

If the quick path names a family, a deletion command, an execution time, an entry point, and a recoverable-data verdict that all line up on one timeline → you are mostly done. Otherwise drop into the full Steps. **Quick-path success does not close the case — the Close-gate invariant still applies in full.**

## How it unfolds (the story)
An actor gets onto the host — commonly a brute-forced or stolen Remote-Desktop login, a phishing attachment, or a vulnerable internet-facing service. Hands-on-keyboard intruders look around, steal credentials, and often copy data out ("double extortion") before doing damage. They disable defenses, stop databases/backup services, and delete shadow copies and backup catalogs so recovery is impossible, then run the encryptor, which walks the disk renaming and scrambling files and dropping a ransom note in every folder. Finally they may clear logs and delete the change journal to slow you down. Commodity/automated ransomware compresses all of this into one self-contained run; a wiper skips the key entirely and overwrites data or the boot record outright.

## Theories to test (and how to rule each out)
| Theory (who / why) | If true, you'd find… | Rule it out if… |
|---|---|---|
| **External-targeted (human-operated / RaaS affiliate)** — broke in via RDP/VPN, moved laterally, then deployed | Remote logon (4624 type 10) before execution; recon/credential tools; shadow-copy deletion commands; data staged/exfiltrated first; note names a known family | No remote-access events, no deletion commands, no lateral movement, a single self-contained binary |
| **External-commodity (automated/phishing dropper)** — malware ran itself, no human steering | Phishing attachment / drive-by; one binary that both deletes shadows and encrypts; no interactive logon | No malicious email/download; evidence of an interactive RDP session and manual commands instead |
| **Insider (disgruntled employee/admin)** — deliberately ran a wiper/ransomware locally | Local interactive logon (4624 type 2) by a real account; binary launched from a user profile; possibly NO real decryption (pure destruction); access to admin tooling | The account used was logged in remotely from an external IP, or credentials were proven stolen → reclassify other-insider |
| **Other-insider (compromised legit account)** — outsider using a real user's stolen creds | Valid account logs in from an unusual IP/time; impossible-travel; same account triggers execution | Logon source and behavior match the real user's baseline; no anomalous source/time |
| **Supply-chain (poisoned update / MSP tool)** — ransomware pushed through trusted software | Encryptor dropped by a software-update/RMM process; same binary hits many hosts simultaneously; signed-but-malicious component | Binary arrived by email/RDP on this host only; no trusted-updater parent process in 4688 |
| **Innocent / benign (NOT an attack)** — bulk encryption (BitLocker/EFS rollout), backup/sync software renaming files, disk corruption, or `cipher /w` cleanup | Files unreadable but **no ransom note**, extensions unchanged or expected, change driven by a known service, `$UsnJrnl` shows orderly ops by a trusted process | Ransom note present + new uniform extension + high-density contents + shadow-copy deletion commands → benign cause refuted |

*(≥1 benign + ≥1 malicious, each ACTIVELY refuted. Attacker types mapped: insider · other-insider · external-commodity · external-targeted · supply-chain · innocent.)*

## Evidence → Tool → What it reveals (per OS)
| Evidence | SIFT tool | What it tells you *for this attack* | OS |
|---|---|---|---|
| `$MFT` (Master File Table) | `MFTECmd` / `analyzeMFT` | The burst of files renamed to a new extension, ransom-note files, and their MACB times → **encryption scope + start time**; `$SI` vs `$FN` timestomp on the encryptor | Windows |
| `$UsnJrnl:$J` (USN change journal) | `MFTECmd` (`-f $J`) / `usn.py` / `usnjls` | Exact ordered sequence of mass RENAME / FILE_CREATE / DATA_EXTEND + note creation → **timeline of the encryption run**; a `$J` that ends abruptly = `fsutil usn deletejournal` anti-forensics | Windows |
| Recovered file contents | `densityscout` | High density = genuinely encrypted (not just renamed) → confirms damage is real (⚠ intermittent encryptors leave low-density regions — see step 5) | Windows/Linux/macOS |
| Volume Shadow Copies | `vshadowinfo` / `vshadowmount` | Whether automatic backups still exist or were destroyed → **recoverability + Inhibit-Recovery proof**; mount survivors to estimate recoverable data | Windows |
| `Security.evtx` (4688 process creation, 4624/4625 logons, 1102 cleared, 4724/4725/4647) | `EvtxECmd` / `evtxexport` | The encryptor launching, `vssadmin/wbadmin/bcdedit` deletion commands, RDP entry, password-reset/logoff lockout bursts, log clearing (note: `evtxexport` is a raw export with NO EID labels — grep the XML; `EvtxECmd` adds EID maps) | Windows |
| `System.evtx` (7045 service install, 524 catalog deleted, 7036/7034 service state, 104 cleared) | `EvtxECmd` / `evtxexport` | Persistence service, backup-catalog destruction, DB/AV service-stop sabotage, whole-log clearing | Windows |
| `Microsoft-Windows-WMI-Activity%4Operational.evtx` (5857/5858/5861) | `EvtxECmd` | `wmic shadowcopy delete` and WMI-driven deletion that fires NO 4688 — check this when process-creation looks empty | Windows |
| NTUSER.DAT / SYSTEM / SOFTWARE hives | `RECmd` / `rip.pl` | UserAssist & BAM/DAM (programs a user/system ran), Run keys/Services (persistence), USB history → off-log execution corroboration | Windows |
| `Amcache.hve` | `AmcacheParser` / `amcache.py` | Presence/SHA-1 of the encryptor binary on disk (⚠ inventory, **not** proof it ran) | Windows |
| Disk head / partition table | `mmls` / `sigfind` | A lost or overwritten MBR/boot record at the disk head = a **wiper**, not an encryptor — `sigfind` for the `55AA` boot signature | Windows/Linux |
| Carved ransomware-family signatures | `python3-yara` (via `page-brute` / `pe-scanner`) | A YARA-rule match to a known family on the encryptor binary, a dumped region, or pagefile (no `yara` CLI on this box — the library backs page-brute/pe-scanner) | all |
| Mailbox `*.pst`/`*.ost` | `pffexport` / `pffinfo` | A phishing attachment/lure as the entry vector | Windows |
| Browser history | `hindsight.py` | Malicious download / payment-site visits (⚠ Chrome/Chromium only on this box) | Windows/Linux/macOS |
| RAM image (if captured) | `vol` (Volatility 3) | Live encryptor process, command line, injected code, handles to the files being encrypted, keys still in memory | Windows/Linux* |
| `pagefile.sys` / swap | `page-brute` (`python3-yara`) | Family-rule IOCs spilled from memory to disk | Windows/Linux |
| Whole image (FS-independent) | `bulk_extractor` / `srch_strings` | `.onion`/payment URLs, emails, contact IDs scattered across the disk (incl. in slack/unallocated) | all |
| Staged/archived data before T0 | `MFTECmd` / `bulk_extractor` / `fls` | Large archives (`.7z`/`.zip`/`.rar`) created just before encryption = **double-extortion staging** | all |
| ext3/4 filesystem + journal | `fls`/`fsstat`/`mactime`, `jls` | Linux/ESXi mass-modification timeline + recent journal transactions (no registry/USN on Linux) | Linux |
| macOS artifacts (FSEvents etc.) | `log2timeline.py` (plist/fseventsd) | macOS file-activity & user history (the box's `mac_apt` is broken — route around it) | macOS |
| AV signature match | `clamscan` | Known-ransomware identification (misses novel families) | all |
| Super-timeline | `log2timeline.py` + `psort.py` (+ `pinfo.py`) | One fused chronology across all artifacts | all |

*Linux memory analysis in `vol` needs a matching symbol table — ⚠️verify availability before relying on it.*

## Step 0 — evidence inventory & access bootstrap
- n: 0
  tool: |
    mkdir -p "#{case_out}/receipts" "#{case_out}/extracted" && ls -laR "#{mount_root}" > "#{case_out}/receipts/00.txt" 2>&1 ; img_stat "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; mmls "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; fsstat -o #{ntfs_offset_sectors} "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; find "#{mount_root}" \( -iname "*.evtx" -o -iname "\$MFT" -o -iname "*readme*" -o -iname "*decrypt*" \) >> "#{case_out}/receipts/00.txt" 2>&1
  expect: every evidence file classified; #{image_path}, #{mount_root}, #{ntfs_offset_sectors}, #{case_out} bound; read-only access proven; the NTFS file system, the winevt Logs directory, and any obvious ransom-note files are enumerated, or their absence is recorded
  check: |
    test -r "#{mount_root}" -o -n "$(ls "#{case_out}/extracted" 2>/dev/null)"
  falsify: evidence dir empty/unreadable, or no supported image format found, or no NTFS partition for fsstat
  on_result: {expect_met: goto 1, falsify_met: STOP — report acquisition/access failure; pivot acquisition-custody, neither: try the icat-extract fallback (fls to find the inodes of $MFT/$J/winevt Logs/notes, icat each into #{case_out}/extracted); if that also fails treat as falsify_met}
  emits: [key_artifacts]
  serves: [mass-file-encryption-extension-change, ransom-note-drop, vss-shadow-copy-deletion, wiper-mbr-boot-destruction, double-extortion-staging-exfil, service-backup-sabotage, recoverable-data-assessment]
  provenance: {receipt_id: 00, artifact: evidence directory listing + NTFS/winevt enumeration, offset_or_row: full listing, literal_cited: image filename + hash line}

## Steps (executable — decision-driven)
- n: 1
  precondition: "os == windows; test -r #{mount_root}"
  tool: |
    dotnet /opt/zimmermantools/MFTECmd.dll -f "#{mount_root}/\$MFT" --csv "#{case_out}" --csvf mft.csv > "#{case_out}/receipts/01.txt" 2>&1 ; awk -F, "NR>1{n=split(\$0,a,\".\"); e=a[n]; print e}" "#{case_out}/mft.csv" 2>/dev/null | sort | uniq -c | sort -rn | head -n 25 >> "#{case_out}/receipts/01.txt" 2>&1
  expect: hundreds-to-thousands of FileName rows sharing ONE new extension (e.g. .lockbit / .<8rand>) with Created0x10 timestamps clustered inside a single short window (minutes) — the encryption-burst spike; record that window as T0..T1
  check: |
    test -s "#{case_out}/mft.csv"
  falsify: no extension clustering; file extensions unchanged; changes spread evenly over days (normal use, not a burst)
  on_result: {expect_met: record the new extension + the T0..T1 window; goto 2, falsify_met: not mass-encryption — re-test the benign/wiper theories (goto 4 for a boot-record wiper) and pivot disk-filesystem, neither: re-parse with /opt/analyzemft/bin/analyzemft into #{case_out}/amft.csv and re-check the extension histogram}
  emits: [key_artifacts, timeline_events]
  serves: [mass-file-encryption-extension-change]
  provenance: {receipt_id: 01, artifact: $MFT, offset_or_row: mft.csv rows sharing the new extension, literal_cited: count of files with .<X> created T0..T1}

- n: 2
  precondition: "exists #{case_out}/mft.csv"
  tool: |
    /opt/usnparser/bin/usn.py -f "#{mount_root}/\$Extend/\$UsnJrnl:\$J" -o "#{case_out}/usn.csv" > "#{case_out}/receipts/02.txt" 2>&1 ; usnjls -o #{ntfs_offset_sectors} "#{image_path}" >> "#{case_out}/receipts/02.txt" 2>&1 ; grep -iE "RENAME_NEW_NAME|RENAME_OLD_NAME|FILE_CREATE|DATA_EXTEND|CLOSE" "#{case_out}/usn.csv" 2>/dev/null | head -n 200 >> "#{case_out}/receipts/02.txt" 2>&1
  expect: a dense ordered run of RENAME_OLD_NAME + RENAME_NEW_NAME / FILE_CREATE / DATA_EXTEND for .<X> files AND FILE_CREATE for the ransom-note files, all inside T0..T1 — the second, independent source for the burst (two-source rule with step 1)
  check: |
    test -s "#{case_out}/usn.csv" && grep -qiE "RENAME_NEW_NAME|FILE_CREATE|DATA_EXTEND" "#{case_out}/receipts/02.txt"
  falsify: no such burst in the journal; OR the journal is absent/wrapped/truncated right before T0 (a $J that ends abruptly = fsutil usn deletejournal anti-forensics — itself a finding)
  on_result: {expect_met: lock the encryption window T0..T1 from two sources; goto 3, falsify_met: record journal-destroyed/wrapped as an anti-forensics finding; lean on $MFT (step 1) + the super-timeline (step 10); goto 3, neither: re-run usnjls at the correct -o offset; widen #{time_window} by ±30 min and re-grep}
  emits: [timeline_events, key_artifacts]
  serves: [mass-file-encryption-extension-change]
  provenance: {receipt_id: 02, artifact: $UsnJrnl:$J, offset_or_row: usn.csv RENAME/CREATE rows, literal_cited: n RENAME_NEW_NAME .<X> at <ts>}

- n: 3
  precondition: "exists #{case_out}/mft.csv"
  tool: |
    fls -rp -o #{ntfs_offset_sectors} "#{image_path}" 2>/dev/null | grep -iE "decrypt|recover|read.?me|restore|how.?to|_readme|unlock" > "#{case_out}/receipts/03.txt" 2>&1 ; mkdir -p "#{case_out}/be" && bulk_extractor -o "#{case_out}/be" "#{image_path}" >> "#{case_out}/receipts/03.txt" 2>&1 ; srch_strings -a "#{case_out}/be/url.txt" 2>/dev/null | grep -iE "\.onion|decrypt|bitcoin|protonmail|qtox|session" | head -n 40 >> "#{case_out}/receipts/03.txt" 2>&1
  expect: ransom-note files repeated across many directories whose contents carry a payment demand / .onion URL / contact ID / family branding — the note + new extension usually name the family
  check: |
    grep -qiE "decrypt|recover|read.?me|restore|how.?to|_readme|\.onion" "#{case_out}/receipts/03.txt"
  falsify: NO note anywhere on disk after a full fls listing + bulk_extractor URL sweep — mass destruction with no demand points to a wiper, not an encryptor
  on_result: {expect_met: record the family + note IOCs (.onion / contact ID / extension); goto 4, falsify_met: NO-NOTE — carry the wiper hypothesis (T1485) forward and prioritise the boot-record/MBR check at goto 4; pivot malware-analysis-triage to triage the destructive binary, neither: icat the most-repeated candidate note inode and read it; widen the grep to family-specific keywords}
  emits: [key_iocs]
  serves: [ransom-note-drop, wiper-mbr-boot-destruction]
  provenance: {receipt_id: 03, artifact: ransom-note file + bulk_extractor url.txt, offset_or_row: fls path row / srch_strings byte offset, literal_cited: verbatim demand or .onion address}

- n: 4
  precondition: "exists #{case_out}/mft.csv"
  tool: |
    mmls "#{image_path}" > "#{case_out}/receipts/04.txt" 2>&1 ; sigfind 0x55AA "#{image_path}" 2>/dev/null | head -n 20 >> "#{case_out}/receipts/04.txt" 2>&1 ; find "#{mount_root}/Windows/System32/Drivers" -maxdepth 1 -type f 2>/dev/null | grep -iE "drdisk|eldos|rawdisk|elrawdsk" >> "#{case_out}/receipts/04.txt" 2>&1
  expect: distinguish wiper from encryptor — an intact partition table + boot signature at sector 0 means the damage is file-level (encryptor); a missing/overwritten MBR at the disk head, or a third-party raw-disk driver (drdisk/elrawdsk) in System32 Drivers, means a boot/sector wiper (T1485/T1561)
  check: |
    grep -qiE "0x000000000000|55AA|Boot Sector|drdisk|rawdisk|elrawdsk|DOS Partition|GUID Partition" "#{case_out}/receipts/04.txt"
  falsify: a clean GPT/MBR partition table and a normal 55AA boot signature at sector 0, no raw-disk driver — destruction is file-level encryption only, NOT a boot wiper
  on_result: {expect_met: classify encryptor-vs-wiper; record any raw-disk driver as a high-signal execution artifact; goto 5, falsify_met: confirm pure file-encryption (no boot destruction); goto 5, neither: re-run sigfind across the first sectors; if the partition table is gone treat the head as overwritten (wiper) and record it}
  emits: [key_artifacts, exfil_or_encryption_facts]
  serves: [wiper-mbr-boot-destruction]
  provenance: {receipt_id: 04, artifact: disk head / partition table / System32 Drivers, offset_or_row: mmls table + sigfind hits, literal_cited: boot-signature status or raw-disk driver filename}

- n: 5
  precondition: "exists #{case_out}/mft.csv"
  tool: |
    for i in $(fls -rp -o #{ntfs_offset_sectors} "#{image_path}" 2>/dev/null | grep -iE "\.lock|\.encrypt|\.crypt|\.[a-z0-9]{6,8}$" | grep -oE "[0-9]+-128-[0-9]+" | head -n 5); do icat -o #{ntfs_offset_sectors} "#{image_path}" "$i" > "#{case_out}/extracted/sample_$i.bin" 2>/dev/null ; done ; densityscout "#{case_out}/extracted/"*.bin > "#{case_out}/receipts/05.txt" 2>&1 ; /opt/page-brute/bin/page-brute -f "#{case_out}/extracted" -o "#{case_out}/receipts" >> "#{case_out}/receipts/05.txt" 2>&1
  expect: encrypted samples show density at/near maximum (densityscout flags high entropy), and/or a python3-yara family rule fires via page-brute on a sample — confirming the damage is real whole-file encryption, not a bare rename
  check: |
    test -s "#{case_out}/receipts/05.txt" && grep -qiE "0\.[6-9]|1\.0|match|rule|density" "#{case_out}/receipts/05.txt"
  falsify: sample density is LOW and the file-format header/structure is fully intact across the whole file (renamed/untouched, not whole-file encrypted) — and no family rule fires
  on_result: {expect_met: damage confirmed real (high entropy / family match); goto 6, falsify_met: do NOT conclude untouched on low density alone — intermittent encryptors (BlackCat/Play/Royal) leave low-density regions, so re-check the file-header structure and the $MFT mod-time clustering from step 1 before reclassifying benign; pivot malware-analysis-triage, neither: sample more files of different sizes; if page-brute cannot load a rule set run densityscout alone and adjudicate from the prose}
  emits: [exfil_or_encryption_facts, key_iocs]
  serves: [mass-file-encryption-extension-change, recoverable-data-assessment]
  provenance: {receipt_id: 05, artifact: sample .<X> files, offset_or_row: densityscout output line / page-brute match line, literal_cited: density value (high) or matched rule name}

- n: 6
  precondition: "exists #{case_out}/mft.csv"
  tool: |
    vshadowinfo "#{image_path}" > "#{case_out}/receipts/06.txt" 2>&1 ; vshadowinfo -o #{ntfs_offset_sectors} "#{image_path}" >> "#{case_out}/receipts/06.txt" 2>&1 ; dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll -d "#{mount_root}" --csv "#{case_out}" --csvf events.csv >> "#{case_out}/receipts/06.txt" 2>&1 ; grep -iE "vssadmin|Delete Shadows|wbadmin|bcdedit|recoveryenabled|shadowcopy delete|,524,|,5857,|,5858," "#{case_out}/events.csv" 2>/dev/null | head -n 40 >> "#{case_out}/receipts/06.txt" 2>&1
  expect: vshadowinfo shows 0 stores OR the newest store predates T0; AND a 4688 (or WMI 5857/5858, or System 524) carrying one of vssadmin Delete Shadows /all /quiet | wbadmin delete catalog | bcdedit recoveryenabled No | wmic shadowcopy delete — the Inhibit-Recovery core
  check: |
    grep -qiE "vssadmin|Delete Shadows|wbadmin|bcdedit|recoveryenabled|shadowcopy delete|,524," "#{case_out}/receipts/06.txt"
  falsify: shadow copies are present and dated AFTER T0, AND no deletion command appears in 4688 / System 524 / WMI 5857-5858 — recovery is NOT inhibited
  on_result: {expect_met: record recovery-inhibition CONFIRMED with the exact command string; goto 7, falsify_met: recovery POSSIBLE — note surviving stores and proceed to the recoverable-data assessment at goto 9, neither: re-run vshadowinfo at the correct -o offset; check the WMI-Activity Operational log for wmic-driven deletion that fires no 4688}
  emits: [exfil_or_encryption_facts, key_iocs]
  serves: [vss-shadow-copy-deletion, service-backup-sabotage]
  provenance: {receipt_id: 06, artifact: VSS catalog + Security/System.evtx, offset_or_row: vshadowinfo store count + 4688/524 row, literal_cited: 0 stores or vssadmin Delete Shadows /all /quiet string}

- n: 7
  precondition: "exists #{case_out}/events.csv"
  tool: |
    grep -E ",4688," "#{case_out}/events.csv" > "#{case_out}/receipts/07.txt" 2>&1 ; grep -iE "Users.Public|ProgramData|Temp|PerfLogs|AppData.Local.Temp|\.exe" "#{case_out}/receipts/07.txt" | head -n 40 >> "#{case_out}/receipts/07.txt" 2>&1 ; dotnet /opt/zimmermantools/RECmd/RECmd.dll --bn /opt/zimmermantools/RECmd/BatchExamples/Kroll_Batch.reb -d "#{mount_root}" --csv "#{case_out}" --csvf reg.csv >> "#{case_out}/receipts/07.txt" 2>&1
  expect: a 4688 NewProcessName from a suspicious path (Users Public / ProgramData / Temp / PerfLogs) launched at or before T0, and the SAME binary present in UserAssist or BAM/DAM (reg.csv) — execution proved from two independent sources
  check: |
    grep -qE ",4688," "#{case_out}/receipts/07.txt" || test -s "#{case_out}/reg.csv"
  falsify: no 4688 (process auditing off) AND no UserAssist/BAM entry for any unusual binary — execution is not directly evidenced in the log or the hive
  on_result: {expect_met: encryptor binary identified; record path + hash + launch time; goto 8, falsify_met: fall back to weak inference — AmcacheParser on Amcache.hve (presence + SHA1 only, NOT execution) and the memory check at goto 8; pivot windows-execution-artifacts, neither: run rip.pl -r against the specific NTUSER.DAT for userassist and SYSTEM for services, then re-check}
  emits: [key_iocs, actor_accounts, timeline_events]
  serves: [mass-file-encryption-extension-change, service-backup-sabotage]
  provenance: {receipt_id: 07, artifact: Security.evtx / NTUSER.DAT BAM-UserAssist, offset_or_row: 4688 row / reg.csv UserAssist row, literal_cited: full path of encryptor.exe at <ts>}

- n: 8
  precondition: "exists #{case_out}/events.csv"
  tool: |
    grep -E ",7045,|,7036,|,7034," "#{case_out}/events.csv" > "#{case_out}/receipts/08.txt" 2>&1 ; grep -iE "sql|veeam|backup|exec|sophos|defender|mssql|vss|sqlwriter|stop" "#{case_out}/receipts/08.txt" | head -n 40 >> "#{case_out}/receipts/08.txt" 2>&1 ; grep -E ",4724,|,4725,|,4647," "#{case_out}/events.csv" 2>/dev/null | head -n 40 >> "#{case_out}/receipts/08.txt" 2>&1
  expect: a 7045 service install whose ImagePath is the encryptor/loader path from step 7, AND/OR 7036/7034 service-stop events for database/backup/AV services right before T0 (sabotage to free locked files), AND/OR a clustered burst of 4724/4725 password resets + 4647 logoffs locking out responders just before encryption
  check: |
    grep -qiE ",7045,|,7036,|,7034,|,4724,|,4725,|,4647," "#{case_out}/receipts/08.txt"
  falsify: no service install, no DB/backup/AV service-stop, no password-change/logoff burst near T0 — no service/backup sabotage on this host (ransomware that runs once with no persistence is common, not disqualifying)
  on_result: {expect_met: record service/backup sabotage + any persistence service as IOCs; goto 9, falsify_met: record run-once, no sabotage/persistence; goto 9, neither: parse the System and Security logs per-file with EvtxECmd -f and re-check the service-state and account-management events}
  emits: [key_iocs, actor_accounts, timeline_events]
  serves: [service-backup-sabotage]
  provenance: {receipt_id: 08, artifact: System.evtx / Security.evtx, offset_or_row: 7045/7036 row or 4724/4725/4647 rows, literal_cited: service ImagePath or password-reset/logoff burst string}

- n: 9
  precondition: "exists #{case_out}/mft.csv"
  tool: |
    mkdir -p "#{case_out}/extracted/vss" "#{case_out}/extracted/recover" && vshadowmount -o #{ntfs_offset_sectors} "#{image_path}" "#{case_out}/extracted/vss" > "#{case_out}/receipts/09.txt" 2>&1 ; ls -la "#{case_out}/extracted/vss" >> "#{case_out}/receipts/09.txt" 2>&1 ; tsk_recover -o #{ntfs_offset_sectors} "#{image_path}" "#{case_out}/extracted/recover" >> "#{case_out}/receipts/09.txt" 2>&1 ; ls "#{case_out}/extracted/recover" | head -n 40 >> "#{case_out}/receipts/09.txt" 2>&1
  expect: a recoverable-data verdict — surviving shadow stores mount as vss1/vss2 devices holding pre-encryption copies, and/or tsk_recover pulls back deleted originals; for intermittent encryptors the partially-touched files may still carve via photorec/foremost — quantify what is recoverable
  check: |
    test -n "$(ls "#{case_out}/extracted/vss" 2>/dev/null)" -o -n "$(ls "#{case_out}/extracted/recover" 2>/dev/null)"
  falsify: zero shadow stores mount (all deleted at step 6) AND tsk_recover returns nothing salvageable AND the originals were overwritten in place — recovery is NOT possible from this image
  on_result: {expect_met: record the recoverable-data estimate (which originals survive in VSS / unallocated); goto 10, falsify_met: record recovery-not-possible (shadows deleted + originals overwritten) as the verdict; pivot file-recovery-carving for a deeper carve attempt; goto 10, neither: re-run vshadowmount at the correct offset; if no VSS, run photorec/foremost over unallocated to estimate carve yield}
  emits: [exfil_or_encryption_facts, key_artifacts]
  serves: [recoverable-data-assessment]
  provenance: {receipt_id: 09, artifact: mounted VSS store + tsk_recover output, offset_or_row: vss device list / recovered-file count, literal_cited: count of recoverable originals or zero-recoverable verdict}

- n: 10
  precondition: "exists #{case_out}/events.csv"
  tool: |
    grep -E ",4624,|,4625," "#{case_out}/events.csv" > "#{case_out}/receipts/10.txt" 2>&1 ; grep -iE "LogonType.*1[0]|Type 10|Type 3" "#{case_out}/receipts/10.txt" | head -n 30 >> "#{case_out}/receipts/10.txt" 2>&1 ; fls -rp -o #{ntfs_offset_sectors} "#{image_path}" 2>/dev/null | grep -iE "\.7z|\.zip|\.rar|\.tar|rclone|mega|filezilla|winscp" | head -n 30 >> "#{case_out}/receipts/10.txt" 2>&1
  expect: a 4624 type 10 (RDP) or type 3 (network) logon from an external/unexpected IP shortly before the execution in step 7 (entry vector), AND/OR large archives (.7z/.zip/.rar) or exfil tooling (rclone/mega/winscp) created just before T0 — double-extortion staging before the encryption
  check: |
    grep -qiE ",4624,|,4625,|\.7z|\.zip|\.rar|rclone|mega|winscp" "#{case_out}/receipts/10.txt"
  falsify: no remote logon AND no phishing artifact AND no staged archives/exfil tooling — entry was local/insider (type 2) or the host is a secondary (binary pushed in laterally)
  on_result: {expect_met: record entry vector + any data-staging as IOCs; goto 11, falsify_met: consider lateral movement (secondary host) or supply-chain (trusted-updater parent in step 7); review 4624 type 2 for an insider; goto 11, neither: pffexport the user mailbox for a phishing lure; check VPN/RDP TerminalServices Operational logs and widen #{time_window}}
  emits: [actor_accounts, key_iocs, exfil_or_encryption_facts]
  serves: [double-extortion-staging-exfil]
  provenance: {receipt_id: 10, artifact: Security.evtx / staged archives in $MFT, offset_or_row: 4624 row / archive path row, literal_cited: LogonType 10 src <IP> user <acct> or staged archive name + create time}

- n: 11
  precondition: "exists #{case_out}/events.csv"
  tool: |
    grep -E ",1102,|,104," "#{case_out}/events.csv" > "#{case_out}/receipts/11.txt" 2>&1 ; grep -E ",4719,|,1100,|,5001," "#{case_out}/events.csv" 2>/dev/null >> "#{case_out}/receipts/11.txt" 2>&1 ; for i in $(grep -iE "\.exe" "#{case_out}/receipts/07.txt" 2>/dev/null | grep -oE "[0-9]+-128-[0-9]+" | head -n 3); do istat -o #{ntfs_offset_sectors} "#{image_path}" "$i" >> "#{case_out}/receipts/11.txt" 2>&1 ; done
  expect: a 1102 (Security cleared) / 104 (System cleared) near T0 — proving a deliberate operator; OR a 4719 audit-policy change / 1100 service shutdown / Defender 5001 protection-disabled; OR $FN timestamps OLDER/inconsistent vs $SI on the encryptor (timestomp); OR the $J ending abruptly (step 2) — each is anti-forensics, and the absence is itself a finding
  check: |
    grep -qiE ",1102,|,104,|,4719,|,1100,|,5001,|Timestomp|\$FILE_NAME" "#{case_out}/receipts/11.txt"
  falsify: logs are continuous across T0, $SI and $FN agree on the encryptor, the journal is intact — no anti-forensics observed on this host
  on_result: {expect_met: record anti-forensics (clearing/timestomp/journal-delete) as a high-signal finding; goto 12, falsify_met: record no anti-forensics observed; goto 12, neither: check the Defender Operational log for 5001 and compare $SI vs $FN with MFTECmd on the encryptor; goto 12}
  emits: [key_artifacts, timeline_events]
  serves: [service-backup-sabotage, wiper-mbr-boot-destruction]
  provenance: {receipt_id: 11, artifact: Security/System.evtx + $MFT, offset_or_row: 1102/104 row or istat $FN block, literal_cited: Event 1102 at <ts> or $FN-vs-$SI delta}

- n: 12
  precondition: "exists #{case_out}/mft.csv"
  tool: |
    if ls "#{mount_root}"/*.raw "#{mount_root}"/*.mem "#{mount_root}"/*.vmem "#{mount_root}"/*.lime >/dev/null 2>&1; then for m in "#{mount_root}"/*.raw "#{mount_root}"/*.mem "#{mount_root}"/*.vmem "#{mount_root}"/*.lime; do vol -f "$m" windows.pslist > "#{case_out}/receipts/12.txt" 2>&1 ; vol -f "$m" windows.cmdline >> "#{case_out}/receipts/12.txt" 2>&1 ; vol -f "$m" windows.malfind >> "#{case_out}/receipts/12.txt" 2>&1 ; done ; else echo "no memory image present — recording absence" > "#{case_out}/receipts/12.txt" ; fi
  expect: if a RAM image exists, the encryptor PID is still resident with a command line matching step 7, a malfind RWX injected region, or open handles to the files being encrypted and key material in process memory — live corroboration of execution
  check: |
    test -s "#{case_out}/receipts/12.txt" && grep -qiE "pslist|cmdline|malfind|no memory image" "#{case_out}/receipts/12.txt"
  falsify: no RAM image available (record memory as insufficient_evidence — absence noted), OR no process/injection matching the encryptor
  on_result: {expect_met: corroborate execution + capture live IOCs (PID, cmdline, key bytes); goto 13, falsify_met: mark memory modality insufficient_evidence (no image) and record the absence; goto 13, neither: confirm the .raw/.mem path from Step 0; if a memory image exists but vol errors, note the symbol/profile gap and continue}
  emits: [key_iocs, actor_accounts]
  serves: [mass-file-encryption-extension-change]
  provenance: {receipt_id: 12, artifact: memory image, offset_or_row: pslist/cmdline row, literal_cited: PID <n> + encryptor command line}

- n: 13
  precondition: "exists #{case_out}/mft.csv"
  tool: |
    log2timeline.py --status_view none "#{case_out}/host.plaso" "#{mount_root}" > "#{case_out}/receipts/13.txt" 2>&1 ; psort.py -o l2tcsv "#{case_out}/host.plaso" > "#{case_out}/super.csv" 2>> "#{case_out}/receipts/13.txt" ; pinfo.py "#{case_out}/host.plaso" >> "#{case_out}/receipts/13.txt" 2>&1
  expect: one fused chronology placing entry (step 10) → execution (step 7) → service/backup sabotage + shadow deletion (steps 6/8) → mass encryption (steps 1/2) → ransom note (step 3) in a coherent order with no contradicting gaps, inside #{time_window}
  check: |
    test -s "#{case_out}/super.csv" && grep -qiE "usnjrnl|mft|winevtx|evtx|filestat" "#{case_out}/super.csv"
  falsify: the ordering is impossible (e.g. encryption precedes any logon/access) OR an unexplained multi-hour gap that no clearing event accounts for
  on_result: {expect_met: COMMIT the conclusion with a confidence label; close per the gate, falsify_met: re-open the Theories table; a gap/inversion may indicate clock manipulation or a wiped journal — anchor to $UsnJrnl / $LogFile sequence order instead of host time, neither: run pinfo.py to confirm the mft/usnjrnl/winevtx parsers ran; re-filter psort.py to #{time_window} and re-check}
  emits: [timeline_events]
  serves: [mass-file-encryption-extension-change, vss-shadow-copy-deletion, ransom-note-drop]
  provenance: {receipt_id: 13, artifact: host.plaso super-timeline, offset_or_row: super.csv ordered rows, literal_cited: ordered entry to encryption to note chain T0..T1}

## Linux branch (L1..Ln) — REQUIRED, numbered, same step shape
- n: L1
  precondition: "os == linux"
  tool: |
    fsstat -o #{ntfs_offset_sectors} "#{image_path}" > "#{case_out}/receipts/L01.txt" 2>&1 ; fls -r -m / -o #{ntfs_offset_sectors} "#{image_path}" > "#{case_out}/bodyfile" 2>>"#{case_out}/receipts/L01.txt" ; mactime -b "#{case_out}/bodyfile" -d 2>/dev/null | grep -iE "\.lock|\.encrypt|\.crypt|\.args|\.basic|README|RESTORE" | head -n 60 >> "#{case_out}/receipts/L01.txt" 2>&1 ; jls -o #{ntfs_offset_sectors} "#{image_path}" 2>/dev/null | head -n 30 >> "#{case_out}/receipts/L01.txt" 2>&1
  expect: this image is Linux/ESXi (ext/xfs fsstat) — no registry, no $UsnJrnl, no EVTX; the mass-modification burst shows as a same-window cluster of ext4 metadata changes (mactime) across user/VM data paths, with the ext3/4 journal (jls) holding the most-recent transactions; ESXi families (ESXiArgs/.args) target -flat.vmdk/.vmx config files
  check: |
    test -d "#{mount_root}/var/log" -o -n "$(grep -iE 'ext[234]|xfs' "#{case_out}/receipts/L01.txt" 2>/dev/null)"
  falsify: fsstat reports NTFS and a Windows winevt Logs tree exists — this is Windows, not Linux; the main Windows branch applies (return to step 1)
  on_result: {expect_met: record the Linux/ESXi burst window + new extension; goto L2, falsify_met: this is Windows — run the main Windows Steps 1-13 not this branch, neither: confirm OS family from the Step 0 fsstat/disktype receipt; if ambiguous treat as Windows and run the main branch}
  emits: [key_artifacts, timeline_events]
  serves: [mass-file-encryption-extension-change]
  provenance: {receipt_id: L01, artifact: ext4 file system + journal, offset_or_row: mactime burst rows / jls transactions, literal_cited: cluster of .<X> modifications at <ts>}

- n: L2
  precondition: "os == linux"
  tool: |
    for i in $(fls -rp -o #{ntfs_offset_sectors} "#{image_path}" 2>/dev/null | grep -iE "\.lock|\.encrypt|\.args|\.crypt" | grep -oE "[0-9]+" | head -n 5); do icat -o #{ntfs_offset_sectors} "#{image_path}" "$i" > "#{case_out}/extracted/lsample_$i.bin" 2>/dev/null ; done ; densityscout "#{case_out}/extracted/"l*.bin > "#{case_out}/receipts/L02.txt" 2>&1 ; /opt/page-brute/bin/page-brute -f "#{case_out}/extracted" -o "#{case_out}/receipts" >> "#{case_out}/receipts/L02.txt" 2>&1 ; srch_strings -a "#{mount_root}/var/log/auth.log" 2>/dev/null | grep -iE "Accepted (password|publickey)|Failed password|sudo" | head -n 30 >> "#{case_out}/receipts/L02.txt" 2>&1 ; fls -rp -o #{ntfs_offset_sectors} "#{image_path}" 2>/dev/null | grep -iE "README|RESTORE|decrypt|recover|\.onion" | head -n 20 >> "#{case_out}/receipts/L02.txt" 2>&1
  expect: encrypted samples read as high density (and/or a python3-yara family rule fires via page-brute), the ransom note (README/RESTORE files) is present, and auth.log shows the SSH entry (Accepted password/publickey = the logon, Failed password = brute force) and sudo escalation — confirming a real Linux/ESXi encryption event with its entry vector
  check: |
    test -s "#{case_out}/receipts/L02.txt" && grep -qiE "0\.[6-9]|1\.0|match|rule|Accepted|README|RESTORE|decrypt|\.onion" "#{case_out}/receipts/L02.txt"
  falsify: density is LOW with intact file headers AND no ransom note AND no anomalous SSH logon — no Linux encryption event evidenced (or auth.log was wiped/truncated, itself a finding)
  on_result: {expect_met: commit the Linux/ESXi encryption finding with account + source IP + family; close per the gate, falsify_met: record any auth.log wipe/gap as a finding; carve deleted log fragments and note files with srch_strings/foremost over unallocated; pivot linux-host-forensics, neither: widen #{time_window}; check the systemd journal under /var/log/journal via log2timeline.py and re-render}
  emits: [exfil_or_encryption_facts, actor_accounts, key_iocs]
  serves: [mass-file-encryption-extension-change, ransom-note-drop, double-extortion-staging-exfil]
  provenance: {receipt_id: L02, artifact: ext4 samples + /var/log/auth.log + ransom note, offset_or_row: densityscout line / auth.log grep hit / note path, literal_cited: density value + Accepted password line + source IP}

## Corroboration (two-source rule)
`required_sources: 2` · `pairs:`
- `[ MFT extension burst (step 1) ↔ $UsnJrnl rename/create burst (step 2) ]`
- `[ MFT/UsnJrnl scope (steps 1/2) ↔ densityscout high-density / python3-yara family match (step 5) ]`
- `[ vshadowinfo missing/old stores (step 6) ↔ Security 4688 / WMI 5857 / System 524 vssadmin-wbadmin-bcdedit command (step 6) ]`
- `[ Security 4688 execution (step 7) ↔ UserAssist/BAM entry in reg.csv (step 7) ]`
- `[ Entry logon 4624 (step 10) ↔ timeline proximity to execution in super.csv (step 13) ]`
- `[ Disk-based binary (Amcache/MFT, step 7) ↔ in-memory process (vol, step 12) ]`
- `[ Recoverable-data estimate (step 9 VSS/tsk_recover) ↔ shadow-deletion status (step 6) ]`

One hit is a *lead*; promote to *fact* only when its paired source agrees.

## Don't get fooled (red flags & anti-forensics)
- **Cleared event logs (Security 1102 / System 104).** A clearing event *at* T0 is itself evidence of a deliberate human operator — do not read the silence as "nothing happened." Treat the gap as a finding and anchor everything else to it.
- **Timestomp on the encryptor.** `$SI` file times may look normal while `$FN` times are older/inconsistent; always compare both with `istat`/`MFTECmd` and trust the harder-to-forge `$FN` and the `$UsnJrnl` order over `$SI`.
- **Deleted change journal.** `fsutil usn deletejournal` wipes `$J`; a journal that ends abruptly right before the destructive event is itself a finding — fall back to `$MFT` + the super-timeline and say the journal is gone.
- **Shadow copies gone.** Usually this is the *attack* (Inhibit Recovery), occasionally anti-forensics — corroborate with the deletion command (step 6) before labeling.
- **No ransom note but mass destruction = a wiper masquerading as ransomware.** Reclassify (T1485/T1561); do NOT assume a key exists. Check the boot record / partition head (step 4).
- **Partial/intermittent encryption beats an entropy-only check.** A touched file can still read as low density (BlackCat/Play/Royal, ESXiArgs encrypt only a fraction). Never clear a file on low density alone — confirm via header structure + `$MFT` mod-time clustering (step 5).
- **`wmic`-driven shadow deletion fires NO 4688.** When process-creation looks empty, check the WMI-Activity Operational log (5857/5858) and System 524 — the deletion still left a trail.
- **Emptied/disabled execution artifacts.** This box has **no Prefetch parser (PECmd absent) and no SRUM parser (SrumECmd absent)** — execution proof must come from 4688 + UserAssist/BAM (`RECmd`/`rip.pl`) + Amcache presence (inventory only); a gap there is reported, not guessed. **Missing evidence is itself a finding.**
- **Benign mimics.** A legit BitLocker/EFS rollout, backup/sync software, or `cipher /w` can make files unreadable — refuted by the absence of a ransom note, unchanged/expected extensions, and orderly `$UsnJrnl` ops by a trusted process.

## Failure modes
```
- mode: evidence-access failure — the disk will not mount or the NTFS volume is unreadable
  guard: Step 0 fallback chain — ewfmount/loop RO, else TSK fls/icat the $MFT/$J/winevt-Logs/ransom-note inodes into #{case_out}/extracted; if all fail, record acquisition failure and pivot acquisition-custody
- mode: primary-artifact-absent — $MFT, $UsnJrnl, or the Security/System EVTX is missing, empty, or wrapped (cleared/never collected/journal-deleted)
  guard: record the absence as a finding (a wiped $J or cleared log IS evidence); name the secondary sources ($MFT vs $J, registry UserAssist/BAM, super-timeline, memory) and pivot disk-filesystem / windows-event-logs
- mode: tool-output drift — MFTECmd/EvtxECmd CSV column names change, or a comma-in-field breaks a grep literal so check exits 2
  guard: on check exit 2, adjudicate from the prose expect/falsify against the receipt and cap confidence at inferred; fall back to analyzemft / evtxexport raw export and grep the field directly, never silently pass
- mode: intermittent/partial encryption reads as low entropy — densityscout under-flags a genuinely damaged file
  guard: never clear a file on low density alone; confirm via file-header structure and $SI/$FN mod-time clustering in the $MFT (step 5); a low-density touched file is still impact
- mode: wiper mistaken for an encryptor (or vice versa) — no note found, or an overwritten MBR
  guard: step 4 checks the partition head/boot signature (mmls/sigfind) and System32 Drivers for a raw-disk driver; NO-NOTE branches to the wiper hypothesis (T1485), never assumes a recoverable key
- mode: wmic/PowerShell shadow deletion leaves no 4688 — Inhibit-Recovery looks absent
  guard: step 6 also greps WMI-Activity 5857/5858 and System 524; vshadowinfo showing zero stores pre-encryption corroborates intent even without the command line
```
Minimum set every playbook covers: evidence-access failure (Step 0 fallback chain) · primary-artifact-absent (absence recorded, secondary source named) · tool-output drift (`check` exits 2 → prose adjudication, never silent pass).

## Confidence labeling (observation → inference → conclusion)
- **confirmed:** direct receipt verbatim + ≥2 independent paired sources agree + no unrefuted counter-theory (e.g. `$MFT` burst + `$UsnJrnl` burst + densityscout = "files were encrypted at T0").
- **inferred:** grounded but single-source/interpretive — e.g. Amcache shows the binary on disk (presence only, **not** execution), an entropy reading on an intermittent encryptor, a `$J` gap read as `deletejournal`, or BAM coverage on newer Win10/11 unverified → hedge and tag `⚠️verify`. Every `check`-exit-2 adjudication lands here at best.
- **insufficient_evidence:** precondition unmet (no RAM image; process auditing off; journal deleted; logs cleared) or sources conflict → abstain; state what is missing, do not guess.

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
- **Windows:** fully covered above — best artifact density: `$MFT`, `$UsnJrnl`, VSS, EVTX, registry.
- **Linux/ESXi:** see the numbered Linux branch (L1–L2). No registry, no `$UsnJrnl`, no EVTX. Use `fsstat`/`fls -m bodyfile` + `mactime` to find the mass-modification burst on ext4; `jls` for the ext3/4 journal; `densityscout`/`python3-yara`-via-`page-brute` to confirm encryption; `srch_strings`/`bulk_extractor` over `/var/log/auth.log` (SSH "Accepted password/publickey" = entry) and shell history. ESXi families (ESXiArgs) target small `.vmx`/descriptor files and leave the multi-GB `-flat.vmdk` largely intact — carve those with `photorec`/`foremost`. `vol` for Linux RAM **only if** a matching symbol table is available — `⚠️verify`.
- **macOS (APFS):** TSK 4.11.1 here has limited/no APFS support — `⚠️verify` before relying on `fls`/`fsstat` against APFS. The box's `mac_apt` is **broken** (route around it); use `log2timeline.py` for FSEvents/plist where it works. Confirm encryption with `densityscout`; carve notes with `photorec`. Treat findings as lead-only.
- **Cloud (object-store / KMS-abuse ransomware):** this box has **no dedicated cloud forensic parser** — say so to the requester. Investigate from *exported* CloudTrail/audit logs already on disk by grepping with `srch_strings`/`bstrings` for `DeleteObject`, `PutObject`, `ScheduleKeyDeletion`, `DisableKey` bursts — `⚠️verify`, lead-only until validated with native cloud tooling off-box. Pivot cloud-iaas-control-plane.

## Real-case notes (non-obvious things to look for)
- **"Ransomware" that is actually a wiper hides in the recovery path, not the ransom note.** NotPetya overwrote the first ~25 sectors / MBR with no saved copy and encrypted the MFT irreversibly, then self-cleaned with `wevtutil cl Setup & System & Security & Application` plus `fsutil usn deletejournal /D C:`. Investigative tell: a USN `$J` that ends abruptly right before the destructive event is itself a finding — check `$J` continuity (`MFTECmd -f $J` or `usn.py`) and look for a lost/overwritten partition table at the disk head (`mmls`, then `sigfind` for the 55AA boot signature). It also dropped a one-time blank-named `schtasks` task running `shutdown.exe /r /f` 10–60 min out. `[CrowdStrike / LogRhythm / Carbon Black NotPetya analyses · high]`
- **Destruction can be conditional — a clean peer host does not mean it was not hit.** NotPetya ran full encrypt + MBR wipe + log/journal clearing only when specific AV products were absent; AV-present hosts took a lesser path. Do not infer "not targeted" from "not destroyed" — compare installed-AV inventory across hosts before scoping. `[LogRhythm / SecurityScientist NotPetya analyses · med]`
- **On ESXi, the multi-GB `-flat.vmdk` is often the surviving evidence, not collateral.** ESXiArgs encrypted small VM config/descriptor files with 1MB-on/1MB-off intermittent encryption (skip size scaling up to GBs on large files), leaving flat disk data largely intact and VMs reconstructable from descriptors — until a second wave moved to ~50% coverage to kill recovery. Do not write off `-flat.vmdk` as destroyed; carve/inspect them (`photorec`/`foremost`/`scalpel` on an exported datastore image). `[Rapid7 / CISA AA23-039A / CloudSEK · high]`
- **Intermittent/partial encryption defeats entropy-only triage.** BlackCat, Play, and Royal encrypt only a percentage or every-Nth chunk, so a touched file can still read as normal/low density — "looks clean on an entropy sweep" ≠ untouched. Confirm impact via file-format/header structure and `$SI`/`$FN` modification clustering in the `$MFT` (`MFTECmd`, `analyzeMFT`), not an entropy heuristic. `[SentinelOne Labs · high; arXiv 2510.15133 ⚠️verify]`
- **Some crews lock out responders instead of deleting shadow copies.** LockerGoga at Norsk Hydro changed every admin password to a hardcoded string and forced logoff mid-incident; initial access was a weaponized email from a *trusted customer* account with months of dwell. Hunt for mass password-change + forced-logoff bursts (Security EID 4724/4725 and 4647) tightly clustered just before encryption — parse with `evtxexport` / `EvtxECmd`. `[SentinelOne / Dragos / Microsoft Source · high]`
- **Distrust the system clock around the detonation.** Destructive actors time it for off-hours to maximize pre-discovery spread (Shamoon fired Thursday 20:45, the start of the Saudi weekend), and Shamoon's signed Eldos RawDisk driver (`drdisk.sys` in `System32\Drivers`) rolled the system clock back to stay inside its temp-license window — poisoning any timeline keyed to host time. Anchor the timeline to `$LogFile`/journal sequence numbers (`jls`, `usnjls`) instead, and treat a third-party signed raw-disk-access driver in `System32\Drivers` as a strong execution artifact. `[Securelist / Unit 42 Shamoon 2 · high]`
- **Embedded "actor fingerprints" may be planted — corroborate spread, not authorship.** Olympic Destroyer carried a forged file header engineered for a near-100% match to known Lazarus code plus layered false flags, alongside hardcoded harvested credentials it used to self-propagate. Do not attribute from binary similarity; trace the real credential-reuse and lateral-movement trail (logon types, `$MFT`/service-creation artifacts) as ground truth. `[Securelist / Kaspersky VB2018 · high]`
- **Anti-recovery commands leave a trail even after the shadows are gone.** `vssadmin delete shadows /all /quiet` and `bcdedit /set {default} recoveryenabled No` surface as 4688 process-creation, but `wmic`-driven deletion may show *no* 4688 and instead fire WMI-Activity Operational 5857/5858 — so check the WMI operational log when process-creation looks empty. A VSS catalog showing zero remaining copies (`vshadowinfo`) immediately pre-encryption corroborates destructive intent even when the copies are unrecoverable. `[MITRE CAR (vssadmin delete shadows) ⚠️verify exact ID / Elastic / detection.fyi · high]`

## ATT&CK mapping
- T1486 · Impact · Data Encrypted for Impact (the core encryption) — steps 1/2/5
- T1490 · Impact · Inhibit System Recovery (vssadmin/wbadmin/bcdedit delete shadows) — step 6
- T1485 · Impact · Data Destruction (wiper / no-key variant) — steps 3 NO-NOTE / 4
- T1561.002 · Impact · Disk Wipe — Disk Structure Wipe (MBR/boot-record overwrite) — step 4
- T1489 · Impact · Service Stop (kill DBs/AV/backup before encrypt) — step 8
- T1657 · Impact · Financial Theft (ransom demand / double extortion) — steps 3/10
- T1562.001 · Defense Evasion · Impair Defenses — Disable/Modify Tools (Defender off, EID 5001) — step 11
- T1070.001 · Defense Evasion · Clear Windows Event Logs (1102/104) — step 11
- T1070.004 · Defense Evasion · File Deletion / `fsutil usn deletejournal` (change-journal destruction) — steps 2/11
- T1078 · Initial Access/Persistence · Valid Accounts (stolen creds) — step 10
- T1133 · Initial Access · External Remote Services (RDP/VPN) — step 10
- T1021.001 · Lateral Movement · Remote Desktop Protocol — step 10
- T1566 · Initial Access · Phishing — step 10
- T1059 · Execution · Command and Scripting Interpreter (deletion/sabotage commands) — steps 6/8
- T1543.003 · Persistence · Create or Modify System Process — Windows Service (7045) — step 8
- T1547.001 · Persistence · Registry Run Keys / Startup Folder — step 7
- T1083 · Discovery · File and Directory Discovery (the encryptor enumerating files) — step 1
- T1567 · Exfiltration · Exfiltration Over Web Service (double-extortion staging) — step 10

## Pivots (lead-to-lead graph)
- `on_rdp_or_network_entry (step 10 type 10/3): active-directory-domain — credential/Kerberos abuse and the domain side of how they got in`
- `on_local_interactive_entry (step 10 type 2 by a real account): insider-threat-data-theft — a deliberate insider running the destructive binary locally`
- `on_phishing_attachment (step 10 mailbox lure): browser-email-documents — triage the phishing email and malicious attachment`
- `on_trusted_updater_parent (step 7 4688 parent is an RMM/updater): containers-supply-chain — a poisoned update or build pipeline pushed the encryptor`
- `on_encryptor_binary_identified (step 7 path/hash): malware-analysis-triage — static/behavioral triage of the encryptor or wiper`
- `on_no_ransom_note_or_wiped_mbr (step 3/4): SELF — re-enter with the wiper hypothesis bound and the destruction window in #{time_window}`
- `on_data_staged_before_T0 (step 10 large archives / rclone): insider-threat-data-theft — double-extortion data theft before the encryption`
- `on_secondary_host_no_entry (step 10 binary pushed in laterally): attack-lifecycle-hunting — reconstruct the multi-host deployment chain`
- `on_logs_or_journal_destroyed (step 2/11): windows-event-logs — bracket what the clearing/journal-delete hid`
- `on_recovery_possible (step 9 surviving VSS / carvable originals): file-recovery-carving — recover the pre-encryption data`
- `on_image_unmountable (step 0): acquisition-custody — re-acquire or prove the collection gap`

## Jargon decoder
- **$MFT (Master File Table):** NTFS's master index — one record per file with names, sizes, timestamps, and where the data lives.
- **MACB times:** the four timestamps on a file — Modified, Accessed, Changed (metadata), Born (created).
- **$SI vs $FN:** two timestamp sets in an MFT record; `$STANDARD_INFORMATION` ($SI) is easy to forge, `$FILE_NAME` ($FN) is harder — disagreement hints at **timestomp**.
- **Timestomp:** faking a file's timestamps to hide when it really arrived/changed.
- **$UsnJrnl / USN change journal ($J):** a running log of every file create/rename/write — lets you reconstruct the exact order of the encryption run; `fsutil usn deletejournal` destroys it.
- **Encryption burst / spike:** the short window in which thousands of files are renamed/extension-changed at once — the signature of a running encryptor.
- **Volume Shadow Copy (VSS) / shadow copy:** Windows' automatic point-in-time backups; deleting them is how ransomware blocks rollback.
- **vssadmin / wbadmin / bcdedit:** built-in Windows commands abused to delete shadow copies/backup catalogs and turn off recovery.
- **Ransom note:** the text/HTML file dropped in folders with payment instructions and a contact (often a `.onion` address).
- **Wiper:** malware that destroys data (or the boot record/MBR) outright with no recoverable key — "ransomware" with no real decryption.
- **MBR / boot record:** the first sector(s) of a disk that tell it how to boot; overwriting them bricks the machine (a structural wipe).
- **Double extortion:** stealing data *and* encrypting it, threatening to leak if unpaid — look for large archives staged just before encryption.
- **Entropy / density (densityscout):** a measure of randomness; encrypted data looks near-perfectly random, ordinary files do not (but partial encryptors leave low-density regions — see step 5).
- **Intermittent / partial encryption:** encrypting only a fraction of each file (every-Nth chunk) for speed — defeats an entropy-only check.
- **EVTX / EID:** Windows Event Log files / the numeric Event ID inside them (e.g. 4688 = a process started).
- **4688:** process-creation event (records the program path and command line) — needs process auditing enabled.
- **4624 type 10 / type 2 / type 3:** a successful logon; type 10 = Remote Desktop, type 2 = local interactive, type 3 = network.
- **4724 / 4725 / 4647:** password reset / account disabled / user-initiated logoff — clustered together they can be a responder lock-out.
- **1102 / 104:** "audit log was cleared" (Security) / "event log was cleared" (System) — classic anti-forensics.
- **524 / 5857 / 5858:** backup-catalog-deleted (System) / WMI-Activity provider load / WMI operation — where `wmic`-driven shadow deletion shows up when there is no 4688.
- **7045 / 7036 / 7034:** a new service was installed / a service changed state / a service crashed — persistence and DB/backup-service sabotage.
- **UserAssist / BAM / DAM:** registry traces of programs a user/system actually ran (execution evidence).
- **Amcache / ShimCache (AppCompatCache):** registry/hive records of programs *present on disk* — **presence/inventory, not proof of execution** on modern Windows.
- **Prefetch / SRUM:** Windows execution-history artifacts — **no parser exists on this SIFT build** (PECmd/SrumECmd absent), so do not rely on them here.
- **python3-yara:** the YARA pattern-matching library (run via `page-brute`/`pe-scanner`) used to match ransomware-family signatures — there is **no `yara` CLI** on this box.
- **vshadowmount / vshadowinfo:** libvshadow tools that list and mount Volume Shadow Copies read-only (the substitute for the absent `vss_carver` on this box).
- **tsk_recover / photorec / foremost:** TSK and carving tools that pull back deleted/overwritten originals to estimate recoverable data.
- **PST/OST:** Outlook mailbox files (`pffexport` reads them) — checked for a phishing lure.
- **Bodyfile / super-timeline:** an intermediate timeline format (`fls`/`mactime`) / a merged chronology across many artifacts (`log2timeline`/`psort`).
- **RaaS / affiliate:** Ransomware-as-a-Service — affiliates rent the malware and keep most of the ransom.
- **`-flat.vmdk` (ESXi):** the raw, multi-GB virtual disk data file; often survives an ESXi config-file encryptor and is carvable.

## Tuning log (append-only — the eval loop writes here; humans never edit rows)
| date | case_id | bucket missed | delta applied |
|---|---|---|---|
