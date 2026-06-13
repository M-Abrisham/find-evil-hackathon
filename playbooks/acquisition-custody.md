---
attack_type: acquisition-custody
category_id: acquisition-custody
name: Acquisition, Custody & Cross-Platform Synthesis
description: forensically sound imaging, verification, chain of custody and cross-evidence synthesis
version: 1
os_coverage: [windows, linux, macos, cloud]
sub_types_covered: 13
sub_types:
  - e01-forensic-imaging
  - raw-dd-imaging
  - failing-media-recovery-imaging
  - stored-vs-computed-hash-verification
  - chain-of-custody-acquisition-metadata
  - write-blocking-read-only-access-proof
  - partition-volume-mapping
  - vss-shadow-copy-enumeration
  - vss-shadow-copy-mount
  - multi-image-correlation
  - cross-os-super-timeline-synthesis
  - recovery-from-acquisition-failure
  - per-modality-evidence-inventory
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
This playbook proves the evidence is trustworthy — that the copy of the disk is a faithful, unaltered duplicate, that nobody wrote to it, and that you have an unbroken record of who held it — and then it weaves several pieces of evidence (multiple disks, shadow copies, different operating systems) into one consistent story.

## Use this when (triggers)
- You are handed an evidence image (E01, raw/dd, vmdk) and must **prove its integrity** before you trust a single finding from it — the stored acquisition hash must match a freshly computed one.
- You need an **unbroken chain of custody**: who acquired it, when, with what tool and settings, and that the working copy equals the original.
- You must show every analysis touched the evidence **read-only** (no write to the original) — the forensic-soundness requirement.
- The case has **more than one evidence item** (several disks, a disk plus its Volume Shadow Copies, Windows + Linux hosts) and you must **correlate them on one timeline**.
- An acquisition **failed or is suspect** — a truncated image, a bad-sector read, a hash mismatch — and you must recover what you can and record the gap honestly.
- You must **enumerate and mount Volume Shadow Copies** to recover earlier states of the same volume.

## Quick path (the 90% case)
1. **Inventory + integrity first.** Enumerate every evidence file, read its acquisition metadata (`ewfinfo`), and run `ewfverify` (E01) or recompute the hash with `sha256deep` (raw) — the stored hash MUST equal the computed one before anything downstream is trusted.
2. **Prove read-only access.** Mount the image with `ewfmount` (FUSE, read-only) or loop-mount raw read-only; map partitions with `mmls`/`fsstat`. Never write to the evidence.
3. **Timeline-first.** Fold every mounted evidence item into ONE super-timeline with `log2timeline.py` + `psort.py` (render with `psort.py -o l2tcsv`) and skim it inside `#{time_window}` BEFORE committing to any cross-evidence story — the ordering of events across images is the synthesis.
4. **Enumerate shadow copies.** `vshadowinfo` lists historical Volume Shadow Copies; `vshadowmount` exposes each as a raw device so an earlier state can be folded into the same timeline.
5. **Correlate across items.** Tie a file/hash/account seen on one image to its appearance on another image, its shadow copy, or the other OS — one item is a lead, the cross-evidence agreement is the fact.

If integrity verifies, access is read-only, and one fused timeline tells a consistent multi-evidence story → you are mostly done. Otherwise drop into the full Steps.

## How it unfolds (the story)
A responder acquires evidence — ideally with a write-blocker, imaging the disk to E01 with inline hashing (`ewfacquire`/`dc3dd`) so the tool records the hash at capture time. Later an analyst must prove that the working copy is bit-identical to what was seized (recompute and compare the hash), that the acquisition metadata names a real acquirer and time, and that every read since was read-only. When a case spans several items — two laptops, a server plus its shadow copies, a Windows box and a Linux box — the analyst fuses them into a single chronology so events that span machines line up. The whole point is trust: a finding from an unverified or writable image is worthless in a report, and a story told from one image alone misses the cross-evidence corroboration.

## Theories to test (and how to rule each out)
| Theory (who / why) | If true, you'd find… | Rule it out if… |
|---|---|---|
| **Sound acquisition (benign — the evidence is trustworthy)** | `ewfverify` reports stored hash == computed hash; `ewfinfo` carries a coherent acquirer/date/tool; mount is read-only; no write events on the original | The stored and computed hashes disagree, metadata is blank/contradictory, or write access to the original is shown → integrity is broken, reclassify |
| **Tampered / altered evidence (malicious — someone modified the copy)** | A hash mismatch between stored and recomputed; a modified timestamp on the image container; an image whose internal $MFT/superblock times postdate the recorded acquisition time | Hashes match exactly, acquisition metadata is internally consistent, and no post-acquisition modification is evidenced → not tampered |
| **Acquisition failure / corruption (innocent — bad media or a botched image)** | `ewfverify` errors on bad chunks; a truncated/short image (size below the partition table extent); `ddrescue` mapfile shows unread regions; partial files on recovery | The image verifies clean end-to-end, sizes are consistent, and no read-error map exists → acquisition was complete |
| **Hidden earlier state in shadow copies (the real evidence is in a VSS snapshot)** | `vshadowinfo` lists stores predating the incident; a file deleted on the live volume is present in a mounted shadow copy with an earlier timestamp | `vshadowinfo` lists zero stores, or every store postdates the incident and shows nothing the live volume lacks → no recoverable earlier state |
| **Single-evidence tunnel vision (incomplete — only one item was analyzed)** | An IOC seen on image A also appears on image B, a shadow copy, or the other-OS host, changing the story; a multi-host timeline shows a hop the single image hid | Every other evidence item is genuinely empty of the IOC after a full sweep, and the timeline is coherent from one item alone → single-item conclusion stands |
| **Wrong-evidence / chain-of-custody break (process error, possibly malicious)** | `ewfinfo` acquirer/serial does not match the case brief; the image hash is absent from the custody record; two items the brief calls distinct share an identical hash (duplicate/mislabeled) | Acquisition metadata, serial, and hash match the custody record exactly and each item is distinct → custody intact |

*(≥1 benign + ≥1 malicious, each ACTIVELY refuted. Attacker types mapped: insider · other-insider · external-commodity · external-targeted · supply-chain · innocent.)*

## Evidence → Tool → What it reveals (per OS)
| Evidence | SIFT tool | What it tells you *for this attack* | OS |
|---|---|---|---|
| E01 acquisition metadata (acquirer, date, tool, stored MD5/SHA) | `ewfinfo` | Chain-of-custody header — who/when/with-what, plus the hash recorded at capture time to verify against | all |
| E01 stored vs computed hash | `ewfverify` | Integrity proof — recomputes the image hash and compares it to the one stored at acquisition | all |
| Raw/dd image content | `sha256deep` / `md5deep` | Integrity for raw images that carry no internal hash — recompute and compare to the custody record | all |
| Image container format / sector size | `img_stat` | Acquisition format sanity (E01/raw/split) and sector size to translate partition offsets | all |
| Partition table (MBR/GPT) | `mmls` | Volume-mapping — partition offsets to mount the right volume read-only; flags unallocated gaps | all |
| Filesystem superblock / boot sector | `fsstat` | FS identification + Volume Serial Number (a cross-evidence correlation lead); confirms the offset is right | all |
| E01 → raw read-only device | `ewfmount` | Read-only (FUSE) access — proves analysis never wrote to the evidence | all |
| Failing-media image + read-error map | `ddrescue` | Recovery imaging of bad media; the mapfile records exactly which regions were unread (the gap, honestly) | all |
| Sound acquisition with inline hash | `ewfacquire` / `dc3dd` / `dcfldd` | Forensically sound capture with the hash computed during imaging (capture-time integrity) | all |
| Format conversion (E01 ↔ raw) | `ewfexport` | Produce a raw working copy from E01 (or re-image) without touching the original | all |
| Directory/metadata extraction when mount fails | `fls` / `icat` | Read-only TSK extraction of specific artifacts into `#{case_out}/extracted` — the mount fallback | all |
| Volume Shadow Copy catalog | `vshadowinfo` | Enumerate historical snapshots — earlier states of the same volume exist (point-in-time recovery lead) | Windows |
| VSS stores → raw devices | `vshadowmount` | Mount each shadow copy read-only so an earlier state can be hashed, mounted, and timelined | Windows |
| All items fused | `log2timeline.py` + `psort.py` (+ `pinfo.py`) | ONE chronology across every image/shadow-copy/OS — the cross-evidence synthesis | all |
| Image-wide feature sweep | `bulk_extractor` / `srch_strings` | Account names, IPs, and identifiers spilled across items to seed cross-evidence correlation | all |
| Linux ext/xfs superblock + /var/log | `fsstat`, `fls`/`mactime`, `log2timeline.py` | The Linux item's identity and its events to fold into the same cross-OS timeline | Linux |

## Step 0 — evidence inventory & access bootstrap
- n: 0
  tool: |
    mkdir -p "#{case_out}/receipts" "#{case_out}/extracted" && ls -laR "#{mount_root}" > "#{case_out}/receipts/00.txt" 2>&1 ; ls -la "$(dirname "#{image_path}")" >> "#{case_out}/receipts/00.txt" 2>&1 ; img_stat "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; ewfinfo "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; mmls "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; fsstat -o #{ntfs_offset_sectors} "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1
  expect: every evidence file classified (disk image E01/dd/raw/vmdk, memory, pcap, log export, mailbox, browser profile); #{image_path}, #{mount_root}, #{ntfs_offset_sectors}, #{case_out} bound; read-only access proven; absent modalities recorded as absent
  check: |
    test -r "#{mount_root}" -o -n "$(ls "#{case_out}/extracted" 2>/dev/null)"
  falsify: evidence dir empty/unreadable, or no supported image format found, or no readable partition for fsstat
  on_result: {expect_met: goto 1, falsify_met: STOP — report acquisition/access failure; pivot SELF, neither: try the icat-extract fallback (fls to find the target inodes, icat each artifact into #{case_out}/extracted); if that also fails, treat as falsify_met}
  emits: [key_artifacts]
  serves: [per-modality-evidence-inventory, partition-volume-mapping, write-blocking-read-only-access-proof, chain-of-custody-acquisition-metadata, e01-forensic-imaging, raw-dd-imaging, failing-media-recovery-imaging, stored-vs-computed-hash-verification, vss-shadow-copy-enumeration, vss-shadow-copy-mount, multi-image-correlation, cross-os-super-timeline-synthesis, recovery-from-acquisition-failure]
  provenance: {receipt_id: 00, artifact: evidence directory listing + ewfinfo header, offset_or_row: full listing, literal_cited: image filename plus acquisition hash line}

## Steps (executable — decision-driven)
- n: 1
  precondition: "test -r #{image_path}"
  tool: |
    ewfinfo "#{image_path}" > "#{case_out}/receipts/01.txt" 2>&1 ; img_stat "#{image_path}" >> "#{case_out}/receipts/01.txt" 2>&1
  expect: an acquisition header naming an acquirer, an acquisition date, the imaging tool/version, and a stored hash (MD5 and/or SHA) — the chain-of-custody record captured when the image was made, to compare against the case brief
  check: |
    grep -qiE "MD5|SHA|hash|acquisit|acquir" "#{case_out}/receipts/01.txt"
  falsify: ewfinfo reports no acquisition metadata and no stored hash (a raw/dd image carries none), OR the acquirer/date contradicts the custody record in the case brief
  on_result: {expect_met: record acquirer/date/tool/stored-hash; goto 2, falsify_met: if the image is raw/dd with no internal header note that and rely on the external custody record plus a recomputed hash at step 2; if metadata contradicts the brief flag a custody break and continue, neither: re-run ewfinfo on each split segment (E01/E02...); for raw images record that integrity rests on the external custody hash}
  emits: [key_artifacts]
  serves: [chain-of-custody-acquisition-metadata, e01-forensic-imaging]
  provenance: {receipt_id: 01, artifact: E01 acquisition header, offset_or_row: ewfinfo Acquiry information block, literal_cited: acquirer plus acquisition date plus stored hash string}

- n: 2
  precondition: "test -r #{image_path}"
  tool: |
    ewfverify "#{image_path}" > "#{case_out}/receipts/02.txt" 2>&1 ; sha256deep "#{image_path}" >> "#{case_out}/receipts/02.txt" 2>&1
  expect: ewfverify reports the stored hash and the freshly computed hash are IDENTICAL (integrity verified); for a raw image, sha256deep produces a hash that equals the value in the external custody record — the working copy is a faithful duplicate
  check: |
    grep -qiE "verif|match|success|hash" "#{case_out}/receipts/02.txt" && ! grep -qiE "mismatch|MISMATCH|fail|FAILED|differ|bad checksum" "#{case_out}/receipts/02.txt"
  falsify: ewfverify reports a hash MISMATCH, a read error on a chunk, or the recomputed raw-image hash differs from the custody record — integrity is broken; the evidence may be altered, truncated, or corrupt
  on_result: {expect_met: mark integrity VERIFIED with the matching hash; goto 3, falsify_met: STOP trusting downstream findings from this image; record the integrity break as a high-signal finding; if read errors caused it attempt recovery imaging at step 8; pivot SELF, neither: recompute with md5deep as a second algorithm and re-compare to the custody record; if ewfverify cannot run treat as falsify_met}
  emits: [exfil_or_encryption_facts, key_artifacts]
  serves: [stored-vs-computed-hash-verification, e01-forensic-imaging, raw-dd-imaging]
  provenance: {receipt_id: 02, artifact: E01 stored vs computed hash, offset_or_row: ewfverify result line, literal_cited: stored hash equals computed hash line}

- n: 3
  precondition: "test -r #{image_path}"
  tool: |
    ewfmount "#{image_path}" "#{mount_root}" > "#{case_out}/receipts/03.txt" 2>&1 ; ls -la "#{mount_root}" >> "#{case_out}/receipts/03.txt" 2>&1 ; mount >> "#{case_out}/receipts/03.txt" 2>&1
  expect: ewfmount exposes the E01 as a raw device under #{mount_root} mounted READ-ONLY (FUSE ro), so every later read is non-destructive — the write-blocking/forensic-soundness proof; the raw device (ewf1) is listed and no rw mount of the evidence appears
  check: |
    test -e "#{mount_root}/ewf1" -o -d "#{mount_root}" && ! grep -qiE "#{mount_root}.*\brw\b" "#{case_out}/receipts/03.txt"
  falsify: the mount is read-write, ewfmount fails, or the device is not exposed — read-only access is NOT proven and analysis could alter the evidence
  on_result: {expect_met: record read-only access PROVEN; goto 4, falsify_met: do NOT analyze a writable mount; fall back to TSK read-only extraction (fls/icat into #{case_out}/extracted) which never opens the image rw, then continue, neither: re-mount with explicit read-only options or use ewfexport to a separate raw working copy and loop-mount that read-only}
  emits: [key_artifacts]
  serves: [write-blocking-read-only-access-proof]
  provenance: {receipt_id: 03, artifact: ewfmount FUSE device, offset_or_row: mount table line for #{mount_root}, literal_cited: read-only mount option string for the evidence device}

- n: 4
  precondition: "test -r #{image_path}"
  tool: |
    mmls "#{image_path}" > "#{case_out}/receipts/04.txt" 2>&1 ; fsstat -o #{ntfs_offset_sectors} "#{image_path}" >> "#{case_out}/receipts/04.txt" 2>&1
  expect: mmls prints the partition table with each partition start sector (confirming #{ntfs_offset_sectors} for the volume of interest) and flags unallocated gaps; fsstat identifies the file system and yields the Volume Serial Number — a value reusable to correlate this volume across other evidence
  check: |
    grep -qiE "slot|start|length|Allocated|Unallocated|File System Type|Volume Serial" "#{case_out}/receipts/04.txt"
  falsify: mmls finds no recognizable partition table (wiped/encrypted) OR fsstat reports no file system at #{ntfs_offset_sectors} — the volume cannot be mapped at this offset
  on_result: {expect_met: record partition map plus Volume Serial Number; goto 5, falsify_met: run mmls again to read the correct start sector, or use sigfind to locate a lost partition signature; if the volume is encrypted record that and continue with what is mappable, neither: try common offsets and confirm with fsstat; record an unallocated-only image as a finding}
  emits: [key_artifacts]
  serves: [partition-volume-mapping]
  provenance: {receipt_id: 04, artifact: partition table plus FS superblock, offset_or_row: mmls slot row plus fsstat header, literal_cited: partition start sector plus Volume Serial Number string}

- n: 5
  precondition: "test -r #{image_path}"
  tool: |
    vshadowinfo "#{image_path}" > "#{case_out}/receipts/05.txt" 2>&1 ; vshadowinfo -o #{ntfs_offset_sectors} "#{image_path}" >> "#{case_out}/receipts/05.txt" 2>&1
  expect: vshadowinfo lists one or more Volume Shadow Copy stores with their creation times — historical snapshots of this volume exist; a store predating the incident window is a recovery opportunity (deleted/overwritten files may survive there)
  check: |
    grep -qiE "store|shadow|Number of stores|Creation time" "#{case_out}/receipts/05.txt"
  falsify: vshadowinfo reports zero stores (no VSS on this volume, or shadows were deleted — itself a finding), OR every store postdates the incident and holds nothing the live volume lacks
  on_result: {expect_met: record the store count and creation times; goto 6, falsify_met: record absence of shadow copies as a finding (deletion can be anti-forensics); continue to the timeline at goto 7, neither: re-run vshadowinfo at the correct partition offset from step 4; if VSS metadata is partial record what is readable and continue}
  emits: [key_artifacts, timeline_events]
  serves: [vss-shadow-copy-enumeration]
  provenance: {receipt_id: 05, artifact: VSS catalog, offset_or_row: vshadowinfo Number-of-stores line, literal_cited: store count plus earliest creation time string}

- n: 6
  precondition: "exists #{case_out}/receipts/05.txt"
  tool: |
    mkdir -p "#{case_out}/extracted/vss" && vshadowmount -o #{ntfs_offset_sectors} "#{image_path}" "#{case_out}/extracted/vss" > "#{case_out}/receipts/06.txt" 2>&1 ; ls -la "#{case_out}/extracted/vss" >> "#{case_out}/receipts/06.txt" 2>&1
  expect: vshadowmount exposes each shadow store as a raw device (vss1, vss2...) under #{case_out}/extracted/vss, read-only — each can now be hashed, mounted, and folded into the timeline so an earlier state of a file is recoverable and comparable to the live volume
  check: |
    ls "#{case_out}/extracted/vss" 2>/dev/null | grep -qiE "vss" || grep -qiE "vss" "#{case_out}/receipts/06.txt"
  falsify: vshadowmount exposes no device (no stores to mount, or the offset is wrong), so no earlier state can be accessed for comparison
  on_result: {expect_met: record the mounted shadow devices; goto 7, falsify_met: if step 5 listed zero stores this is expected — record no earlier state available and continue, neither: re-run vshadowmount at the partition offset from step 4; if FUSE mounting is unavailable note the limitation and proceed with the live volume only}
  emits: [key_artifacts, timeline_events]
  serves: [vss-shadow-copy-mount]
  provenance: {receipt_id: 06, artifact: mounted VSS raw devices, offset_or_row: vss device listing, literal_cited: mounted shadow device name plus store creation time}

- n: 7
  precondition: "test -r #{mount_root}"
  tool: |
    log2timeline.py --status_view none "#{case_out}/super.plaso" "#{mount_root}" > "#{case_out}/receipts/07.txt" 2>&1 ; psort.py -o l2tcsv "#{case_out}/super.plaso" > "#{case_out}/super.csv" 2>> "#{case_out}/receipts/07.txt" ; pinfo.py "#{case_out}/super.plaso" >> "#{case_out}/receipts/07.txt" 2>&1
  expect: a fused super-timeline (#{case_out}/super.csv) spanning the live volume and the mounted shadow copies, ordered inside #{time_window} — this is the cross-evidence synthesis: events from multiple sources placed on one consistent chronology with no unexplained gap
  check: |
    test -s "#{case_out}/super.csv" && grep -qiE "datetime|MACB|source|timestamp_desc" "#{case_out}/super.csv"
  falsify: log2timeline.py parses nothing (empty mount), OR the rendered timeline is internally impossible (an event predates the acquisition of its own source) — a synthesis or clock problem
  on_result: {expect_met: keep the fused timeline as the synthesis backbone; goto 8, falsify_met: re-scope log2timeline.py to the specific artifact paths and re-render; if times are impossible anchor to filesystem sequence rather than host clock and record the clock anomaly, neither: run pinfo.py to confirm which parsers ran; re-filter psort.py to #{time_window} and re-check}
  emits: [timeline_events]
  serves: [cross-os-super-timeline-synthesis, multi-image-correlation, vss-shadow-copy-mount]
  provenance: {receipt_id: 07, artifact: super.plaso fused timeline, offset_or_row: super.csv ordered rows, literal_cited: ordered cross-source event chain inside the time window}

- n: 8
  precondition: "exists #{case_out}/super.csv"
  tool: |
    bulk_extractor -o "#{case_out}/extracted/be" "#{image_path}" > "#{case_out}/receipts/08.txt" 2>&1 ; srch_strings "#{image_path}" 2>/dev/null | grep -m 50 -iE "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" >> "#{case_out}/receipts/08.txt" 2>&1
  expect: identifiers (accounts, emails, IPs, hostnames) extracted from this image that ALSO appear on another evidence item, a shadow copy, or the other-OS host — a shared identifier ties items together; the same value on two independent items is the cross-evidence corroboration the synthesis needs
  check: |
    test -d "#{case_out}/extracted/be" -o -s "#{case_out}/receipts/08.txt"
  falsify: no identifier from this image appears on any other evidence item after a full sweep — the items are genuinely unrelated, or only one item was provided
  on_result: {expect_met: record each shared identifier as a correlation IOC and place it on the timeline; close per the gate, falsify_met: record that the items share no correlating identifier (a single-item conclusion then stands, labeled accordingly); close per the gate, neither: widen the sweep with bulk_extractor over unallocated and re-compare; if only one item exists note that and label the conclusion single-source}
  emits: [key_iocs, actor_accounts]
  serves: [multi-image-correlation]
  provenance: {receipt_id: 08, artifact: bulk_extractor feature files plus image strings, offset_or_row: feature file row / strings offset, literal_cited: the shared identifier value seen on two items}

## Linux branch (L1..Ln) — REQUIRED, numbered, same step shape
- n: L1
  precondition: "os == linux"
  tool: |
    img_stat "#{image_path}" > "#{case_out}/receipts/L01.txt" 2>&1 ; fsstat -o #{ntfs_offset_sectors} "#{image_path}" >> "#{case_out}/receipts/L01.txt" 2>&1 ; ewfinfo "#{image_path}" >> "#{case_out}/receipts/L01.txt" 2>&1 ; sha256deep "#{image_path}" >> "#{case_out}/receipts/L01.txt" 2>&1
  expect: this image is a Linux/ESXi item (fsstat reports ext2/3/4 or xfs) — acquisition and integrity work identically (ewfinfo metadata, ewfverify/sha256deep hash) but there are NO Volume Shadow Copies here; the cross-OS goal is to fold this Linux item onto the SAME timeline as the Windows items
  check: |
    grep -qiE "ext[234]|xfs|Linux" "#{case_out}/receipts/L01.txt"
  falsify: fsstat reports NTFS and a Windows volume layout — this is a Windows item; run the main Steps including VSS enumeration (return to Step 1)
  on_result: {expect_met: confirm Linux item; verify its hash exactly as on Windows; goto L2, falsify_met: this is Windows — run the main Steps 1-8 including VSS, not this branch, neither: confirm the FS family from the Step 0 fsstat receipt; if still ambiguous treat as Windows and run the main branch}
  emits: [key_artifacts]
  serves: [raw-dd-imaging, stored-vs-computed-hash-verification, partition-volume-mapping]
  provenance: {receipt_id: L01, artifact: Linux FS superblock plus ewfinfo header, offset_or_row: fsstat File System Type line, literal_cited: ext/xfs FS type plus computed image hash}

- n: L2
  precondition: "os == linux"
  tool: |
    log2timeline.py --status_view none "#{case_out}/linux.plaso" "#{mount_root}" > "#{case_out}/receipts/L02.txt" 2>&1 ; psort.py -o l2tcsv "#{case_out}/linux.plaso" > "#{case_out}/linux_super.csv" 2>> "#{case_out}/receipts/L02.txt" ; pinfo.py "#{case_out}/linux.plaso" >> "#{case_out}/receipts/L02.txt" 2>&1
  expect: a Linux super-timeline (filesystem MACB, syslog/auth, journal, utmp) rendered inside #{time_window}, ready to MERGE with the Windows super.csv from step 7 so a cross-OS sequence (for example an actor moving from a Windows host to a Linux host) lines up on one chronology
  check: |
    test -s "#{case_out}/linux_super.csv" -o -s "#{case_out}/receipts/L02.txt"
  falsify: /var/log is empty or the mount yielded nothing to parse — the Linux item cannot contribute events; record the gap rather than assuming the actor never touched this host
  on_result: {expect_met: merge linux_super.csv with the Windows super.csv on shared identifiers/timestamps; commit the cross-OS synthesis with a confidence label, falsify_met: record the empty/wiped Linux logs as a finding; carve deleted log fragments with srch_strings over unallocated; pivot linux-host-forensics, neither: widen #{time_window}; confirm parsers with pinfo.py and re-render psort.py}
  emits: [timeline_events, actor_accounts]
  serves: [cross-os-super-timeline-synthesis, multi-image-correlation]
  provenance: {receipt_id: L02, artifact: Linux /var/log plus filesystem timeline, offset_or_row: linux_super.csv rows, literal_cited: shared timestamp or account bridging the Windows and Linux timelines}

## Corroboration (two-source rule)
`required_sources: 2` · `pairs:`
- `[ ewfinfo stored hash (step 1) ↔ ewfverify/sha256deep computed hash (step 2) ]`
- `[ stored-vs-computed hash match (step 2) ↔ the external custody-record hash in the case brief ]`
- `[ ewfmount read-only device (step 3) ↔ the absence of any rw mount of the evidence in the mount table (step 3) ]`
- `[ mmls partition start sector (step 4) ↔ fsstat reporting a valid FS at that offset (step 4) ]`
- `[ vshadowinfo store list (step 5) ↔ vshadowmount exposing the same stores as devices (step 6) ]`
- `[ an identifier on image A (step 8) ↔ the same identifier on image B / a shadow copy / the Linux host (step 8 / L2) ]`
- `[ Windows super-timeline order (step 7) ↔ the merged Linux timeline order (L2) ]`

One hit is a *lead*; promote to *fact* only when its paired source agrees.

## Don't get fooled (red flags & anti-forensics)
- **A hash match proves integrity, not innocence.** It proves the working copy equals what was acquired — not that the acquired disk was unaltered before seizure. Keep the two questions separate.
- **A missing internal hash is normal for raw/dd images.** `ewfinfo`/`ewfverify` only work on EWF. For raw images integrity rests on the EXTERNAL custody hash recomputed with `sha256deep` — absence of an internal hash is not a red flag, but absence of ANY custody hash is.
- **Read-write mounts silently corrupt evidence.** Always confirm the mount is read-only; a single journal replay on an rw mount changes the hash. If you cannot prove read-only, extract read-only with TSK (`fls`/`icat`) instead and never analyze the rw mount.
- **Deleted shadow copies are a finding, not an absence.** `vssadmin delete shadows` is a common anti-forensic step; zero VSS stores on a system that should have them is itself evidence — record it, do not shrug.
- **A truncated or short image hides data past the cutoff.** Compare the image size to the partition table extent from `mmls`; an image smaller than the last partition end was cut short. A `ddrescue` mapfile shows exactly which regions were never read.
- **Timestomp and clock skew poison cross-evidence timelines.** When merging items, an event that predates the acquisition of its own source, or two hosts whose clocks disagree, will break the synthesis — anchor to filesystem/journal sequence numbers and record the skew rather than trusting host time. **Missing evidence is itself a finding.**
- **Duplicate or mislabeled evidence.** Two items the brief calls distinct that share an identical image hash are the same disk mislabeled — a custody error that invalidates "two independent sources."

## Failure modes
```
- mode: evidence-access failure — the image will not mount, ewfmount fails, or the file system is unreadable
  guard: Step 0 / step 3 fallback chain — ewfmount RO, else ewfexport to a raw working copy and loop-mount RO, else TSK fls/icat the specific artifacts into #{case_out}/extracted; if all fail, record acquisition/access failure and pivot SELF
- mode: primary-artifact-absent — no acquisition metadata (raw/dd image) or no custody hash to verify against
  guard: record the absence; for raw images recompute with sha256deep and compare to the EXTERNAL custody record named in the brief; if no custody hash exists at all, record integrity as unestablished and label every downstream finding inferred
- mode: tool-output drift — ewfverify/ewfinfo/vshadowinfo wording or psort column names change so a check literal misses
  guard: on check exit 2, adjudicate from the prose expect/falsify against the receipt, cap confidence at inferred; recompute the hash with a second tool (md5deep) and re-compare; never silently pass
- mode: hash mismatch / integrity break — stored and computed hashes differ
  guard: STOP trusting downstream findings; record the break as a high-signal finding; if read errors caused it attempt ddrescue recovery imaging (step 8 path) and re-verify the recovered copy; pivot SELF
- mode: VSS deleted or absent — vshadowinfo reports zero stores
  guard: record the absence as a finding (possible anti-forensics); proceed with the live volume; do not assume there was never an earlier state
- mode: multi-evidence clock skew — two items whose clocks disagree break the merged timeline
  guard: anchor the synthesis to filesystem/journal sequence rather than host time; record the measured skew and re-align before committing the cross-evidence story
```
Minimum set every playbook covers: evidence-access failure (Step 0 fallback chain) · primary-artifact-absent (absence recorded, secondary source named) · tool-output drift (`check` exits 2 → prose adjudication, never silent pass).

## Confidence labeling (observation → inference → conclusion)
- **confirmed:** direct receipt verbatim (e.g. ewfverify "stored == computed") + ≥2 independent sources agree (stored hash + recomputed hash + custody record; or an identifier on two items) + no unrefuted counter.
- **inferred:** grounded but single-source/interpretive — e.g. a raw image verified only against a single external hash, a read-only mount inferred from options rather than a write-attempt test, or a VSS-absence read as deletion → hedge and tag `⚠️verify`. Every `check`-exit-2 adjudication lands here at best.
- **insufficient_evidence:** precondition unmet (no custody hash, image won't mount, only one item provided) or sources conflict → abstain; state what is missing, do not guess.

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
- **Windows:** fully covered above — E01/raw acquisition, hash verification, read-only mount, partition mapping, and the VSS enumeration/mount path (steps 5–6) that exists only on Windows volumes.
- **Linux/ESXi:** see the numbered Linux branch (L1–L2). Acquisition and integrity are identical (`ewfinfo`/`ewfverify`/`sha256deep`, `mmls`/`fsstat` on ext/xfs), but there are **no Volume Shadow Copies** — the earlier-state recovery comes from filesystem journals and backups instead. The cross-OS payoff is merging the Linux super-timeline with the Windows one.
- **macOS:** acquisition and hashing are identical (`ewfacquire`/`dc3dd`, `ewfverify`/`sha256deep`, `mmls`/`fsstat` on APFS/HFS+). There are no VSS; the earlier-state analog is APFS snapshots and Time Machine, and the rich macOS log parser is **broken on this box** (`⚠️verify` — `mac_apt` does not run), so timeline coverage for macOS-specific logs is degraded; fold what `log2timeline.py` parses (plist/FSEvents/ASL) onto the same chronology and label macOS findings lead-only.
- **Cloud:** no disk to image — the "acquisition" is an EXPORT of control-plane/audit logs already on disk. Verify the export's integrity with `sha256deep` against the provider's stated hash, then fold the exported JSON onto the timeline via `log2timeline.py` cloud parsers where supported. Pivot cloud-identity-saas / cloud-iaas-control-plane.

## Real-case notes (non-obvious things to look for)
- **Verify BEFORE you analyze, every time.** A report finding sourced from an image whose hash was never checked is challengeable in court; the discipline is to run `ewfverify` (or recompute) and record the match as the first analytical act, not an afterthought. `[SANS FOR500/FOR508 acquisition canon · high]`
- **Raw/dd images carry no internal hash — the custody record IS the integrity baseline.** Unlike E01, a raw image has nothing to verify against internally; if the external custody hash was never recorded, integrity cannot be established and findings must be labeled accordingly. `[general DFIR acquisition practice · high]`
- **Deleted Volume Shadow Copies are a frequent anti-forensic tell.** Ransomware and hands-on intruders routinely run `vssadmin delete shadows` to block rollback; a system that should have shadows but `vshadowinfo` shows zero is a finding in itself, and surviving shadows often hold pre-encryption / pre-deletion copies of key files. `[MITRE T1490 inhibit-system-recovery context · high]`
- **Shadow copies preserve earlier states the live volume lost.** Mounting a VSS store with `vshadowmount` and timelining it can recover a file (or an earlier version of a registry hive / log) that was deleted or overwritten on the live volume — a primary reason to enumerate VSS in any multi-evidence case. `[libvshadow / SANS VSS analysis · high]`
- **Cross-evidence correlation turns leads into facts.** The same account, IP, or file hash appearing on two independently acquired items (or on a host and its shadow copy) is far stronger than either alone; `bulk_extractor` feature files across items are an efficient way to find the shared identifiers to anchor the merged timeline. `[general DFIR multi-evidence synthesis · med]`
- **Clock skew between items silently breaks merged timelines.** Two hosts acquired in the same case can have clocks minutes-to-hours apart; merging their timelines naively misorders events. Measure the offset (a shared, externally timestamped event helps) and re-align, or anchor to sequence numbers, before committing a cross-host story. `[general DFIR timeline practice · med]`
- **`ddrescue` mapfiles are the honest record of a failed read.** When media is failing, the mapfile records exactly which sectors were never recovered — so the gap is documented rather than silently presented as complete evidence. `[GNU ddrescue / acquisition practice · med]`

## ATT&CK mapping
- T1490 · Impact · Inhibit System Recovery · deleted Volume Shadow Copies (vshadowinfo shows zero stores) — step 5
- T1070 · Defense Evasion · Indicator Removal · evidence tampering / deleted shadows / wiped logs detected during integrity and VSS checks — steps 2/5
- T1070.006 · Defense Evasion · Timestomp · timestamp anomalies surfaced when merging cross-evidence timelines (event predates its source's acquisition) — step 7
- T1485 · Impact · Data Destruction · truncated/short image or wiped volume detected against the mmls extent — steps 2/4
- T1006 · Defense Evasion · Direct Volume Access · read-only volume/shadow access via ewfmount/vshadowmount for non-destructive analysis — steps 3/6

## Pivots (lead-to-lead graph)
- `on_integrity_break_or_hash_mismatch (step 2): SELF — re-acquire or recovery-image, then re-verify the recovered copy before any analysis`
- `on_deleted_shadow_copies (step 5 zero stores): ransomware-destructive — VSS deletion is a recovery-inhibition signal`
- `on_recovered_shadow_state (step 6 mounted store): disk-filesystem — analyze the earlier file-system state recovered from the shadow copy`
- `on_cross_host_correlation (step 8 / L2 shared identifier): attack-lifecycle-hunting — reconstruct the multi-host intrusion the merged timeline reveals`
- `on_linux_log_wipe (step L2): linux-host-forensics — carve and analyze the wiped Linux logs`
- `on_cloud_export_only (cross-OS notes): cloud-identity-saas — verify and analyze the exported cloud audit logs`
- `on_unmountable_or_corrupt_image (step 0/3): SELF — exhaust the recovery-imaging and read-only-extraction fallbacks`

## Jargon decoder
- **E01 / EWF:** the Expert Witness Format — a forensic image container (`.E01`) that stores the disk contents PLUS acquisition metadata and a hash computed at capture time.
- **raw / dd image:** a bit-for-bit copy with no container and no internal metadata or hash — integrity rests entirely on an external custody record.
- **chain of custody:** the documented record of who held the evidence and when, and proof the working copy equals the original — without it a finding is challengeable.
- **stored vs computed hash:** the hash recorded when the image was made versus one recomputed now; they must be identical for the copy to be trusted.
- **`ewfinfo` / `ewfverify`:** read the E01 acquisition metadata / recompute and compare the E01 hash (integrity proof).
- **`sha256deep` / `md5deep`:** recursive hashing tools — recompute an image or file hash to compare against a custody record.
- **`ewfmount`:** exposes an E01 as a read-only raw device (FUSE) so analysis never writes to the evidence.
- **write-blocking / read-only access:** the forensic-soundness rule that nothing may write to the original evidence; a read-only mount or read-only extraction proves it.
- **`mmls` / `fsstat`:** read the partition table (start sectors, gaps) / identify the file system and its Volume Serial Number — volume mapping.
- **Volume Serial Number (VSN):** a per-volume ID from the file-system superblock — a handy value to correlate the same volume across evidence items.
- **VSS / Volume Shadow Copy:** Windows point-in-time snapshots of a volume; earlier states of files survive in them. `vshadowinfo` lists them, `vshadowmount` mounts them read-only.
- **super-timeline:** one merged chronology built across many artifacts (and many evidence items) with `log2timeline.py` + `psort.py` — the cross-evidence synthesis.
- **`ddrescue` mapfile:** the record of which sectors were read or unread when imaging failing media — the honest map of an incomplete acquisition.
- **clock skew:** the offset between two hosts' clocks; left uncorrected it misorders events when timelines are merged.

## Tuning log (append-only — the eval loop writes here; humans never edit rows)
| date | case_id | bucket missed | delta applied |
|---|---|---|---|
