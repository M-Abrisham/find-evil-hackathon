---
attack_type: virtualization-mobile
category_id: virtualization-mobile
name: Virtualization & Mobile/Embedded
description: virtual-machine disk and memory artifacts plus Android/iOS device triage
version: 1
os_coverage: [windows, linux, macos, cloud]
sub_types_covered: 10
sub_types:
  - vm-disk-vmdk-analysis
  - vm-disk-vhdi-analysis
  - vm-memory-vmem-analysis
  - vm-snapshot-artifacts
  - android-backup-image-triage
  - android-app-db-and-log-analysis
  - ios-backup-triage
  - mobile-spyware-indicators-mvt
  - embedded-iot-firmware-image
  - guest-host-escape-and-shared-folder-residue
validated_on: []
maturity: draft
variables:
  image_path:
    default: /cases/active/evidence/guest.vmdk
    derive: "Step 0 — first disk-evidence image (E01/dd/raw/vmdk/vhdi, or a mobile backup/image) enumerated under the evidence directory named in the case brief"
  mount_root:
    default: /cases/active/mount
    derive: "Step 0 — directory where the VM guest file system (or the unpacked mobile backup) is mounted READ-ONLY, or where icat-extracted artifacts land when mounting fails"
  case_out:
    default: /cases/active/out
    derive: "Step 0 — writable case output directory from the case brief; Step 0 creates #{case_out}/receipts/ and #{case_out}/extracted/"
  ntfs_offset_sectors:
    default: 0
    derive: "Step 0 — start sector of the relevant guest partition from `mmls #{image_path}` (largest data partition unless the brief says otherwise)"
  time_window:
    default: 1970-01-01..2099-12-31
    derive: "case brief if it names one; else first confirmed malicious timestamp plus-or-minus 48h once a step pins one — then re-scope wide sweeps to it"
---

## In one line
Sometimes the evidence is not a normal computer disk: it is a virtual machine packaged as a file (a guest disk and its frozen memory), or it is a phone (an Android or iOS backup), or it is a small device like a router or camera. This playbook unpacks those containers safely and then runs the ordinary disk-and-memory investigation inside them, plus phone-specific spyware checks.

## Use this when (triggers)
- The evidence is a **virtual-machine disk** — a `.vmdk` (VMware) or `.vhdi`/`.vhd`/`.vhdx` (Hyper-V/Virtual PC) file — rather than a raw `.dd`/`.E01` of a physical disk.
- A captured VM **memory** file is present (`.vmem`, alongside `.vmsn`/`.vmss` snapshot files) and you want process/injection/network evidence from RAM.
- You have **VM snapshots** and need to know what changed between point-in-time states, or whether a snapshot was reverted to hide activity.
- The evidence is a **phone backup or image** — an Android backup/`.ab`/filesystem dump or an **iTunes/Finder iOS backup** — and you need app activity, messages, or a spyware verdict.
- There are signs of **mobile spyware/stalkerware** (Pegasus-class or commodity) and you want an IOC-driven triage with MVT.
- The evidence is an **embedded/IoT firmware image** (router, camera, appliance) and you need to find implants, hardcoded creds, or tampering.
- You suspect a **guest-to-host escape** or abuse of **shared folders / clipboard / drag-drop** between a VM and its host.

## Quick path (the 90% case)
1. **Open the container read-only, then timeline-first.** For a VM disk, point `mmls`/`fsstat` straight at the `.vmdk`/`.vhdi` file (TSK reads the raw extent) or mount it read-only with `imount`; for a mobile backup, unpack it under `#{mount_root}`. Then build a timeline of the guest file system BEFORE any story: `fls -r -m` bodyfile then `mactime`, or fold the guest into `log2timeline.py` + `psort.py`. Skim inside `#{time_window}`.
2. **If a `.vmem` is present, read RAM first.** Run `vol` (Volatility 3) over the `.vmem` for rogue processes, injection, services, and network residue — the snapshot froze live state the disk never wrote.
3. **For a phone, run MVT.** `mvt-ios` over an iOS backup or `mvt-android` over an Android backup/image with a STIX2 IOC feed — it flags known spyware traces (malicious domains, processes, config profiles) and dumps the app databases to inspect.
4. **Read the app/system databases.** Parse SQLite app DBs (messaging, browser, call/SMS) with `SQLECmd`; carve deleted rows with `sqlite-carver`. On a VM guest, run the ordinary Windows/Linux artifact steps inside the mounted file system.
5. **Corroborate every lead twice.** A malicious domain in an MVT hit must also appear in an app DB or a network artifact; a rogue process in `.vmem` must also show on the guest disk (`$MFT`/`fls`). One source is a lead, not a fact.

If the timeline, a memory or MVT hit, and a corroborating database row all line up inside `#{time_window}`, you are mostly done. Otherwise drop into the full Steps.

## How it unfolds (the story)
An investigator is handed a container, not a bare disk: a virtual machine (guest disk plus frozen memory and snapshots) or a phone backup. For a VM, the attacker lived inside the guest exactly as on a physical host — dropped tools, persistence, lateral movement — and the snapshot may have frozen a process the disk never flushed; sometimes the attacker reverted a snapshot to erase tracks, or abused a shared folder to cross into the host. For a phone, commodity stalkerware or a targeted implant landed via a malicious link or config profile, then quietly exfiltrated messages and location; the traces survive in app SQLite databases, system logs, and (for iOS) the backup manifest. The whole sequence is reconstructable by unpacking the container read-only, building a timeline, and running the ordinary disk/memory steps plus phone-specific spyware checks.

## Theories to test (and how to rule each out)
| Theory (who / why) | If true, you'd find… | Rule it out if… |
|---|---|---|
| **External-targeted (mobile implant / spyware)** | An MVT detection against the IOC feed — a malicious domain, a rogue process name, a suspicious configuration profile or shortcut — corroborated by the same domain in an app DB or DNS/network artifact, inside #{time_window} | MVT returns zero detections AND no anomalous domain/process appears in the app DBs or logs; device records match a clean baseline |
| **External-commodity (stalkerware on the phone)** | A side-loaded app with location/SMS/mic permissions, an unfamiliar package in the Android package list or an iOS profile, persistence that survives reboot, traffic to a commodity monitoring service | No side-loaded monitoring app; permissions and installed-package list match expected apps; no unexplained background data |
| **External-targeted (attacker inside the VM guest)** | Guest-disk persistence (service/Run key/cron) and dropped tooling on the `$MFT`/`fls` timeline, AND a matching rogue process / injection in the `.vmem` snapshot, AND the guest file system mounted from the `.vmdk`/`.vhdi` cleanly | The guest disk and `.vmem` are both clean — no persistence, no injected process, no out-of-baseline binary in #{time_window} |
| **Insider / anti-forensics (snapshot reverted to hide activity)** | A snapshot chain whose timestamps show a revert straddling the incident, guest file-system timestamps that jump backward, or a `.vmem`/disk mismatch (memory shows a process the current disk lacks) | Snapshot chain is monotonic with no revert; disk and memory agree; no backward time jump in the guest timeline |
| **Guest-to-host escape / shared-folder pivot** | Shared-folder residue, clipboard/drag-drop artifacts, or a guest tool reaching a host path; the same dropped file present on both guest and host evidence | No shared-folder/clipboard artifacts and no file crossing the guest/host boundary; the guest is fully isolated |
| **Innocent / benign (NOT an attack)** | A legitimately provisioned VM or a routine encrypted phone backup; installed apps, services, and profiles are all expected, signed, and inside business use; no MVT hit, no out-of-baseline persistence | A sanctioned provisioning/MDM record explains every app/profile/service AND no spyware/persistence/injection is evidenced → benign cause confirmed; reclassify |

*(at least 1 benign + at least 1 malicious, each ACTIVELY refuted. Attacker types mapped: insider · other-insider · external-commodity · external-targeted · supply-chain · innocent.)*

## Evidence → Tool → What it reveals (per OS)
| Evidence | SIFT tool | What it tells you *for this attack* | OS |
|---|---|---|---|
| VM guest disk `.vmdk` / `.vhdi` / raw extent | `mmls` / `fsstat` / `fls` / `icat` / `istat` (TSK) | Partition layout and guest file system read straight from the VM disk file; file existence, deleted names, per-file MACB inside the guest | all |
| VM guest disk, orchestrated mount | `imount` (/opt/imagemounter) | Read-only mount of the guest volume so every later artifact step runs against `#{mount_root}` (auto-handles ewf/aff/xmount-backed containers) | all |
| VM memory `.vmem` (with `.vmsn`/`.vmss` snapshot) | `vol` (Volatility 3) | Rogue/hidden processes, code injection, loaded drivers, services (`svcscan`), and network residue frozen in the snapshot's RAM | Windows/Linux* |
| VM snapshot/descriptor files (`.vmsn`, `.vmsd`, descriptor `.vmdk`) | `srch_strings` / `bstrings` / `exiftool` | Snapshot chain, revert evidence, and parent-disk pointers — whether a snapshot was reverted to hide activity | all |
| Android backup/image — app SQLite DBs (SMS, calls, messaging, browser) | `SQLECmd` / `sqlite-carver` | App activity and deleted rows: messages, call/SMS history, browser visits, downloads | Android |
| Android backup/image — spyware/IOC triage | `mvt-android` | Detections against a STIX2 IOC feed: malicious domains, rogue packages/processes, persistence — mobile compromise verdict | Android |
| iOS backup (`Manifest.db`, app domains) | `mvt-ios` | Backup-wide spyware triage (malicious domains, processes, profiles, shortcuts) plus a decoded view of the backup's app data | iOS |
| iOS/macOS app DBs (KnowledgeC, messages, Safari) | `SQLECmd` / `sqlite-carver` | Per-app pattern-of-life, messages, and browsing pulled from the backup's SQLite stores; deleted-row recovery | iOS/macOS |
| Embedded/IoT firmware image | `mmls` / `fls` / `srch_strings` / `bstrings` / `densityscout` / `clamscan` / `pe-scanner` | Implants, hardcoded credentials, encoded/packed payloads, and known-malware hits inside a router/camera/appliance image | embedded |
| Any guest/backup — keyword & feature sweep | `bulk_extractor` / `srch_strings` | Emails, URLs, IPs, and search terms spilled across the container regardless of file system | all |
| Any guest/backup — fused timeline | `log2timeline.py` + `psort.py` (+ `pinfo.py`) | One chronology placing unpack → execution → exfil/persistence in order inside #{time_window} | all |
| iOS Unified Log / macOS-style enrichment | `mac_apt.py` | Would parse KnowledgeC/Unified Log — but mac_apt is BROKEN on this box (kaitaistruct/import failure) — route around it with `SQLECmd`/`sqlite-carver` and plaso; `⚠️verify` | iOS/macOS |

*Linux/Android memory analysis in `vol` needs a matching ISF symbol pack — `⚠️verify` availability before relying on it. The vmdk/vhdi/qemu-img native parsers (`vmdkmount`/`vhdimount`/`qemu-img`) are NOT confirmed on this box — TSK reads the raw extent directly and `imount` orchestrates the mount; `⚠️verify` any native libvmdk/libvhdi/qemu-img call before use.*

## Step 0 — evidence inventory & access bootstrap
- n: 0
  tool: |
    mkdir -p "#{case_out}/receipts" "#{case_out}/extracted" && ls -laR "#{mount_root}" > "#{case_out}/receipts/00.txt" 2>&1 ; ls -laR "$(dirname "#{image_path}")" >> "#{case_out}/receipts/00.txt" 2>&1 ; img_stat "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; mmls "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; fsstat -o #{ntfs_offset_sectors} "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; find "$(dirname "#{image_path}")" -iname "*.vmem" -o -iname "*.vmsn" -o -iname "*.vmsd" -o -iname "*.vmdk" -o -iname "*.vhdi" -o -iname "*.ab" -o -iname "Manifest.db" >> "#{case_out}/receipts/00.txt" 2>&1
  expect: every evidence file classified (VM disk vmdk/vhdi · VM memory vmem · snapshot vmsn/vmsd · Android backup/image · iOS backup Manifest.db · embedded image); #{image_path}, #{mount_root}, #{ntfs_offset_sectors}, #{case_out} bound; read-only access proven; container type and OS family of the guest/phone recorded, or absence recorded as a finding
  check: |
    test -r "#{mount_root}" -o -n "$(ls "#{case_out}/extracted" 2>/dev/null)"
  falsify: evidence dir empty/unreadable, or no supported container found (no vmdk/vhdi/vmem/Android-backup/iOS-Manifest and no raw image)
  on_result: {expect_met: goto 1, falsify_met: STOP — report acquisition/access failure; pivot acquisition-custody, neither: try the icat-extract fallback (fls to find the guest artifact inodes, icat each into #{case_out}/extracted); if that also fails, treat as falsify_met}
  emits: [key_artifacts]
  serves: [vm-disk-vmdk-analysis, vm-disk-vhdi-analysis, vm-memory-vmem-analysis, vm-snapshot-artifacts, android-backup-image-triage, android-app-db-and-log-analysis, ios-backup-triage, mobile-spyware-indicators-mvt, embedded-iot-firmware-image, guest-host-escape-and-shared-folder-residue]
  provenance: {receipt_id: 00, artifact: evidence directory listing + container enumeration, offset_or_row: full listing, literal_cited: image filename + container type + hash line}

## Steps (executable — decision-driven)
- n: 1
  precondition: "test -r #{mount_root}"
  tool: |
    /opt/imagemounter/bin/imount "#{image_path}" > "#{case_out}/receipts/01.txt" 2>&1 ; fsstat -o #{ntfs_offset_sectors} "#{image_path}" >> "#{case_out}/receipts/01.txt" 2>&1 ; fls -r -m / -o #{ntfs_offset_sectors} "#{image_path}" > "#{case_out}/extracted/guest_body.txt" 2>> "#{case_out}/receipts/01.txt" ; mactime -b "#{case_out}/extracted/guest_body.txt" -d > "#{case_out}/guest_timeline.csv" 2>> "#{case_out}/receipts/01.txt"
  expect: the VM guest disk opens read-only — fsstat names the guest file system (NTFS/ext/xfs) from the .vmdk/.vhdi raw extent, fls walks the guest tree, and a guest MACB timeline (#{case_out}/guest_timeline.csv) covers #{time_window} — the timeline-first artifact every later step filters
  check: |
    test -s "#{case_out}/guest_timeline.csv" || test -s "#{case_out}/extracted/guest_body.txt"
  falsify: the .vmdk is a sparse/split descriptor whose extents are missing, or the volume is encrypted/unreadable — no guest file system parses from this container
  on_result: {expect_met: goto 2, falsify_met: if the descriptor points at missing extents collect them; if encrypted record the locked-volume finding and pivot acquisition-custody, neither: try imount RO mount of #{mount_root} then fls against the mounted device; if still blocked icat-extract the key artifacts into #{case_out}/extracted}
  emits: [timeline_events]
  serves: [vm-disk-vmdk-analysis, vm-disk-vhdi-analysis]
  provenance: {receipt_id: 01, artifact: VM guest disk (vmdk/vhdi) raw extent, offset_or_row: fsstat header + guest_timeline.csv row count, literal_cited: guest file-system type + first/last MACB timestamp}

- n: 2
  precondition: "test -n #{ntfs_offset_sectors}"
  tool: |
    find "$(dirname "#{image_path}")" -iname "*.vmem" > "#{case_out}/receipts/02.txt" 2>&1 ; for m in $(find "$(dirname "#{image_path}")" -iname "*.vmem"); do vol -f "$m" windows.pslist >> "#{case_out}/receipts/02.txt" 2>&1 ; vol -f "$m" windows.malfind >> "#{case_out}/receipts/02.txt" 2>&1 ; vol -f "$m" windows.svcscan >> "#{case_out}/receipts/02.txt" 2>&1 ; vol -f "$m" windows.netscan >> "#{case_out}/receipts/02.txt" 2>&1 ; done
  expect: if a .vmem snapshot exists, vol lists guest processes (pslist), flags injected/hollowed regions (malfind), enumerates services (svcscan) and network residue (netscan) — naming a rogue process, an injected PID, or a C2 connection frozen in the snapshot RAM that the disk may never have written
  check: |
    grep -qiE "PID|Offset|malfind|Service|TCP|UDP" "#{case_out}/receipts/02.txt"
  falsify: no .vmem present (disk-only evidence), OR vol runs clean — no injection, no rogue process, no out-of-baseline service or connection in the snapshot
  on_result: {expect_met: record rogue PID/injected region/connection as IOCs; goto 3, falsify_met: record no .vmem or clean memory and lean on the disk timeline; pivot memory-forensics if a RAM lead needs deeper plugins, neither: if the image is a Linux/Android guest the windows.* plugins will not apply — try linux.* with a matching ISF symbol pack and verify availability; else carry forward disk-only}
  emits: [key_iocs, timeline_events]
  serves: [vm-memory-vmem-analysis]
  provenance: {receipt_id: 02, artifact: VM memory .vmem snapshot, offset_or_row: pslist/malfind row, literal_cited: rogue process name + PID or injected region address}

- n: 3
  precondition: "test -r #{mount_root}"
  tool: |
    find "$(dirname "#{image_path}")" -iname "*.vmsn" -o -iname "*.vmsd" -o -iname "*.vmss" > "#{case_out}/receipts/03.txt" 2>&1 ; for s in $(find "$(dirname "#{image_path}")" -iname "*.vmsd" -o -iname "*.vmsn"); do exiftool "$s" >> "#{case_out}/receipts/03.txt" 2>&1 ; srch_strings "$s" 2>/dev/null | grep -iE "snapshot|parentCID|createTimeHigh|displayName" >> "#{case_out}/receipts/03.txt" 2>&1 ; done
  expect: snapshot metadata (.vmsd chain, .vmsn state) names the snapshot list, parent-CID links and create times — revealing whether a snapshot was REVERTED across #{time_window} (a revert erases later guest activity) or whether the current disk is a child of a hidden parent; a backward time jump in the guest timeline corroborates a revert
  check: |
    grep -qiE "snapshot|parentCID|createTime|displayName|numSnapshots" "#{case_out}/receipts/03.txt"
  falsify: no snapshot files present, OR the .vmsd chain is monotonic with no revert and the guest timeline shows no backward jump — no snapshot anti-forensics
  on_result: {expect_met: record the revert/parent-chain as an anti-forensics finding; goto 4, falsify_met: record no snapshot tampering; goto 4, neither: compare snapshot create times against the guest_timeline.csv min/max from step 1 for a backward jump; if ambiguous label inferred and goto 4}
  emits: [key_artifacts, timeline_events]
  serves: [vm-snapshot-artifacts]
  provenance: {receipt_id: 03, artifact: VM snapshot descriptor (.vmsd/.vmsn), offset_or_row: snapshot chain entry, literal_cited: snapshot displayName + createTime or parentCID link}

- n: 4
  precondition: "test -r #{mount_root}"
  tool: |
    find "$(dirname "#{image_path}")" -iname "Manifest.db" > "#{case_out}/receipts/04.txt" 2>&1 ; for b in $(find "$(dirname "#{image_path}")" -iname "Manifest.db" -exec dirname {} \;); do /opt/mvt/bin/mvt-ios check-backup --output "#{case_out}/extracted/mvt_ios" "$b" >> "#{case_out}/receipts/04.txt" 2>&1 ; done ; ls -la "#{case_out}/extracted/mvt_ios" >> "#{case_out}/receipts/04.txt" 2>&1
  expect: if an iOS backup is present (a Manifest.db with app-domain dirs), mvt-ios check-backup runs the spyware modules and writes per-module JSON under #{case_out}/extracted/mvt_ios — flagging malicious domains, suspicious processes, rogue configuration profiles or shortcuts; a non-empty detections/timeline JSON is the iOS spyware lead
  check: |
    test -n "$(ls "#{case_out}/extracted/mvt_ios" 2>/dev/null)" || grep -qiE "Manifest.db|detected|timeline|module" "#{case_out}/receipts/04.txt"
  falsify: no iOS backup present (Android-only or VM evidence), OR mvt-ios runs but every module reports zero detections — no iOS spyware indicator in this backup
  on_result: {expect_met: record each detection (domain/process/profile) as an IOC; goto 6, falsify_met: record no iOS backup or zero detections; goto 5 for Android or goto 6, neither: re-run mvt-ios with an updated STIX2 IOC feed (detections need IOCs loaded); if no feed, parse the app DBs directly at step 6 and label inferred}
  emits: [key_iocs, actor_accounts]
  serves: [ios-backup-triage, mobile-spyware-indicators-mvt]
  provenance: {receipt_id: 04, artifact: iOS backup (Manifest.db + app domains), offset_or_row: mvt-ios module JSON row, literal_cited: detected domain/process/profile string}

- n: 5
  precondition: "test -r #{mount_root}"
  tool: |
    find "$(dirname "#{image_path}")" -iname "*.ab" > "#{case_out}/receipts/05.txt" 2>&1 ; /opt/mvt/bin/mvt-android check-backup --output "#{case_out}/extracted/mvt_android" "#{mount_root}" >> "#{case_out}/receipts/05.txt" 2>&1 ; /opt/mvt/bin/mvt-android check-bugreport --output "#{case_out}/extracted/mvt_android" "#{mount_root}" >> "#{case_out}/receipts/05.txt" 2>&1 ; ls -la "#{case_out}/extracted/mvt_android" >> "#{case_out}/receipts/05.txt" 2>&1
  expect: if an Android backup/image is present, mvt-android runs over the unpacked backup or bugreport and flags side-loaded packages, malicious domains, rogue processes, or risky permission grants against the IOC feed — a non-empty detection or the installed-package list naming an unexpected monitoring app is the Android compromise lead
  check: |
    test -n "$(ls "#{case_out}/extracted/mvt_android" 2>/dev/null)" || grep -qiE "package|detected|permission|module|domain" "#{case_out}/receipts/05.txt"
  falsify: no Android backup/image present (iOS-only or VM evidence), OR mvt-android runs but reports no side-loaded app, no malicious domain, and no risky permission — no Android compromise indicator
  on_result: {expect_met: record the package/domain/permission as IOCs; goto 6, falsify_met: record no Android backup or clean result; goto 6, neither: re-run with an updated STIX2 IOC feed; if the backup is a raw filesystem dump rather than an .ab, parse its app DBs directly at step 6 and label inferred}
  emits: [key_iocs, actor_accounts]
  serves: [android-backup-image-triage, mobile-spyware-indicators-mvt]
  provenance: {receipt_id: 05, artifact: Android backup/image (.ab or filesystem dump), offset_or_row: mvt-android module JSON / package list row, literal_cited: side-loaded package name or detected domain string}

- n: 6
  precondition: "test -r #{mount_root}"
  tool: |
    dotnet /opt/zimmermantools/SQLECmd/SQLECmd.dll -d "#{mount_root}" --csv "#{case_out}" --csvf appdb.csv > "#{case_out}/receipts/06.txt" 2>&1 ; for db in $(find "#{mount_root}" -iname "*.db" -o -iname "*.sqlite" -o -iname "*.sqlitedb" 2>/dev/null | head -n 50); do /opt/sqlite-carver/bin/sqlite-carver -f "$db" >> "#{case_out}/receipts/06.txt" 2>&1 ; done
  expect: app SQLite databases (messaging/SMS/call/browser/contacts) parse via SQLECmd into #{case_out}/appdb.csv, and sqlite-carver recovers deleted rows from the freelist/unallocated — messages, call/SMS history, browser visits, or a contact/URL that matches an MVT IOC from steps 4/5
  check: |
    test -s "#{case_out}/appdb.csv" || grep -qiE "record|row|recovered|table" "#{case_out}/receipts/06.txt"
  falsify: no app SQLite DBs in the mounted backup/guest (or SQLECmd has no map for them) AND sqlite-carver recovers nothing — no recoverable app activity here
  on_result: {expect_met: record the message/visit/contact rows; cross-check against MVT IOCs; goto 7, falsify_met: record no app-DB activity; lean on MVT detections and the timeline; pivot browser-email-documents if browser stores need deeper parsing, neither: if SQLECmd lacks a map for an app DB, dump its schema and tables with sqlite-carver and read the raw rows; label inferred}
  emits: [key_artifacts, timeline_events, actor_accounts]
  serves: [android-app-db-and-log-analysis, ios-backup-triage]
  provenance: {receipt_id: 06, artifact: app SQLite DB (messaging/call/browser), offset_or_row: appdb.csv row / carved freelist record, literal_cited: message body / URL / contact string}

- n: 7
  precondition: "test -r #{mount_root}"
  tool: |
    for img in $(find "$(dirname "#{image_path}")" -iname "*.bin" -o -iname "*.img" -o -iname "firmware*" 2>/dev/null | head -n 20); do srch_strings "$img" 2>/dev/null | grep -iE "password|passwd|root:|admin|http://|https://|ssh-rsa" >> "#{case_out}/receipts/07.txt" 2>&1 ; densityscout "$img" >> "#{case_out}/receipts/07.txt" 2>&1 ; done ; clamscan -r --infected "#{mount_root}" >> "#{case_out}/receipts/07.txt" 2>&1 ; bulk_extractor -o "#{case_out}/extracted/be_features" "#{image_path}" >> "#{case_out}/receipts/07.txt" 2>&1
  expect: for an embedded/IoT firmware image, srch_strings surfaces hardcoded credentials and C2 URLs, densityscout flags packed/encrypted regions, clamscan hits known implants, and bulk_extractor pulls emails/URLs/IPs from the whole container — an implant or backdoor credential inside the device image
  check: |
    grep -qiE "password|passwd|root:|http|FOUND|Infected" "#{case_out}/receipts/07.txt" || test -n "$(ls "#{case_out}/extracted/be_features" 2>/dev/null)"
  falsify: no firmware/embedded image present (VM or mobile evidence only), OR the strings/entropy/AV sweep finds no hardcoded cred, no implant signature, and no anomalous C2 URL
  on_result: {expect_met: record the hardcoded cred/implant/URL as IOCs; goto 8, falsify_met: record no embedded-image finding; goto 8, neither: if the image is a packed/encrypted firmware blob carve it with foremost/photorec and re-run strings/densityscout on the carved parts; label inferred}
  emits: [key_iocs, exfil_or_encryption_facts]
  serves: [embedded-iot-firmware-image]
  provenance: {receipt_id: 07, artifact: embedded/IoT firmware image, offset_or_row: srch_strings byte offset / clamscan hit line, literal_cited: hardcoded credential or implant signature string}

- n: 8
  precondition: "test -r #{mount_root}"
  tool: |
    find "#{mount_root}" -ipath "*shared*folder*" -o -ipath "*vmware*shared*" -o -ipath "*hgfs*" > "#{case_out}/receipts/08.txt" 2>&1 ; srch_strings "#{image_path}" 2>/dev/null | grep -iE "vmware-shared|\\\\\\\\vmware-host|hgfs|VBoxSharedFolders|clipboard|drag.?drop" >> "#{case_out}/receipts/08.txt" 2>&1 ; bstrings -f "#{image_path}" --lr "vmware-host|hgfs|VBoxSharedFolders" >> "#{case_out}/receipts/08.txt" 2>&1
  expect: shared-folder mount points (VMware hgfs / VBoxSharedFolders) or clipboard/drag-drop residue in the guest — evidence that a file or command crossed the guest/host boundary; a dropped file present on BOTH the guest and the host evidence proves a pivot toward escape
  check: |
    grep -qiE "hgfs|vmware-shared|vmware-host|VBoxSharedFolders|clipboard|drag" "#{case_out}/receipts/08.txt"
  falsify: no shared-folder mount, no clipboard/drag-drop residue, and no guest file crossing to a host path — the guest is isolated, no escape/shared-folder pivot
  on_result: {expect_met: record the shared-folder/boundary-crossing file as an IOC; goto 9, falsify_met: record guest isolation, no escape evidenced; goto 9, neither: search the host evidence (if provided) for the same file hash; if no host evidence available label inferred and goto 9}
  emits: [key_iocs, key_artifacts]
  serves: [guest-host-escape-and-shared-folder-residue]
  provenance: {receipt_id: 08, artifact: guest shared-folder / clipboard residue, offset_or_row: srch_strings/bstrings hit, literal_cited: shared-folder mount path or crossed-file name}

- n: 9
  precondition: "test -r #{mount_root}"
  tool: |
    log2timeline.py --status_view none "#{case_out}/vm.plaso" "#{mount_root}" > "#{case_out}/receipts/09.txt" 2>&1 ; psort.py -o l2tcsv "#{case_out}/vm.plaso" > "#{case_out}/super.csv" 2>> "#{case_out}/receipts/09.txt" ; pinfo.py "#{case_out}/vm.plaso" >> "#{case_out}/receipts/09.txt" 2>&1
  expect: a fused super-timeline placing unpack/mount → execution or app install → spyware/persistence → exfil in a coherent order inside #{time_window}, merging the guest file system, app DBs and any recovered artifacts — the MVT/.vmem leads land on the same chronology as the disk
  check: |
    test -s "#{case_out}/super.csv" && grep -qiE "sqlite|filestat|plaso|fs:stat" "#{case_out}/super.csv"
  falsify: ordering is impossible (e.g. exfil precedes any install/access) OR an unexplained multi-hour gap that no snapshot revert accounts for
  on_result: {expect_met: COMMIT the conclusion with a confidence label; close per the gate, falsify_met: re-open the Theories table; a gap/inversion may indicate a snapshot revert or clock tampering — anchor to artifact sequence not host time, neither: run pinfo.py to confirm the parsers ran; re-filter psort.py to #{time_window} and re-check}
  emits: [timeline_events]
  serves: [vm-disk-vmdk-analysis, android-app-db-and-log-analysis, ios-backup-triage, mobile-spyware-indicators-mvt]
  provenance: {receipt_id: 09, artifact: vm.plaso super-timeline, offset_or_row: super.csv ordered rows, literal_cited: ordered unpack to exfil chain}

## Linux branch (L1..Ln) — REQUIRED, numbered, same step shape
- n: L1
  precondition: "os == linux"
  tool: |
    fsstat -o #{ntfs_offset_sectors} "#{image_path}" > "#{case_out}/receipts/L01.txt" 2>&1 ; find "#{mount_root}" -maxdepth 3 -ipath "*/etc/machine-id" -o -ipath "*/var/lib/docker*" -o -ipath "*/etc/pve*" 2>/dev/null >> "#{case_out}/receipts/L01.txt" ; ls "#{mount_root}/var/log" >> "#{case_out}/receipts/L01.txt" 2>&1
  expect: this guest/host is Linux or an ESXi/Proxmox hypervisor (ext/xfs fsstat, /var/log present, or /etc/pve for Proxmox) — the VM container still opens via TSK/imount, but the guest-internal artifacts are Linux (auth.log, journal, cron/systemd) rather than Windows EVTX/registry; record Linux-only because the guest file system is ext/xfs
  check: |
    test -d "#{mount_root}/var/log" -o -n "$(grep -iE 'ext[234]|xfs' "#{case_out}/receipts/L01.txt" 2>/dev/null)"
  falsify: fsstat reports NTFS and a Windows\System32 tree exists in the guest — this is a Windows guest; run the main Steps 1-9 not this branch
  on_result: {expect_met: goto L2, falsify_met: this is a Windows guest — run the main Windows Steps 1-9, neither: confirm guest OS family from the Step 0 fsstat/disktype receipt; if still ambiguous treat as Windows and run the main branch}
  emits: [key_artifacts]
  serves: [vm-disk-vmdk-analysis, vm-disk-vhdi-analysis]
  provenance: {receipt_id: L01, artifact: guest file system + /var/log listing, offset_or_row: fsstat header + dir listing, literal_cited: ext/xfs FS type or /var/log present (Linux-confirmed)}

- n: L2
  precondition: "os == linux"
  tool: |
    log2timeline.py --status_view none "#{case_out}/linux.plaso" "#{mount_root}/var/log" > "#{case_out}/receipts/L02.txt" 2>&1 ; psort.py -o l2tcsv "#{case_out}/linux.plaso" > "#{case_out}/linux_super.csv" 2>> "#{case_out}/receipts/L02.txt" ; srch_strings "#{mount_root}/var/log/auth.log" 2>/dev/null | grep -iE "accepted|failed password|sudo|new session" >> "#{case_out}/receipts/L02.txt" 2>&1 ; find "#{mount_root}" -ipath "*/var/lib/docker/overlay2*" -maxdepth 6 -type d 2>/dev/null | head >> "#{case_out}/receipts/L02.txt" 2>&1
  expect: inside the Linux guest/hypervisor, SSH logons (accepted/failed password), sudo escalation, systemd/cron persistence, and — on a container host — docker overlay2 layers naming a poisoned image or escaped container, ordered in the super-timeline inside #{time_window}
  check: |
    test -s "#{case_out}/linux_super.csv" -o -s "#{case_out}/receipts/L02.txt"
  falsify: /var/log empty or wiped (auth.log truncated to zero) and no overlay2 layers — Linux anti-forensics; record the gap as a finding
  on_result: {expect_met: record account + source IP + persistence/container artifact; commit with confidence label, falsify_met: record log-wipe/gap as a finding; carve deleted log fragments with srch_strings over unallocated; pivot linux-host-forensics, neither: widen #{time_window}; parse journald under /var/log/journal via log2timeline and re-render; if a container host pivot containers-supply-chain}
  emits: [actor_accounts, timeline_events]
  serves: [vm-disk-vmdk-analysis, guest-host-escape-and-shared-folder-residue]
  provenance: {receipt_id: L02, artifact: Linux guest /var/log + docker overlay2, offset_or_row: linux_super.csv rows / grep hits, literal_cited: Accepted/Failed password line + source IP or overlay2 layer path}

## Corroboration (two-source rule)
`required_sources: 2` · `pairs:`
- `[ rogue process in .vmem (step 2) ↔ the same binary on the guest disk $MFT/fls timeline (step 1) ]`
- `[ snapshot revert in .vmsd (step 3) ↔ a backward time jump in guest_timeline.csv (step 1/3) ]`
- `[ mvt-ios detection (step 4) ↔ the same domain/contact in an app SQLite DB (step 6) ]`
- `[ mvt-android side-loaded package or domain (step 5) ↔ the package/URL in the app DBs or network features (step 6/7) ]`
- `[ app-DB message/visit (step 6) ↔ the fused super-timeline order (step 9) ]`
- `[ hardcoded firmware credential/implant (step 7) ↔ a clamscan/known-bad hash or a matching network feature (step 7) ]`
- `[ shared-folder/boundary-crossing file (step 8) ↔ the same file hash present on the host evidence (step 8) ]`

One hit is a *lead*; promote to *fact* only when its paired source agrees.

## Don't get fooled (red flags & anti-forensics)
- **A reverted snapshot erases the disk story, not the memory.** A revert rolls the guest disk back to an earlier point — later activity vanishes from the file system but may survive in a `.vmem`/`.vmss` captured after it. Check the `.vmsd` chain and trust the memory snapshot and any backward time jump over the current disk state.
- **VM disk timestamps are the GUEST clock, and it can be wrong.** A guest with a manipulated clock, or a disk restored from a snapshot, produces an internally impossible timeline. Anchor to artifact sequence (USN/journal/record IDs) rather than guest host-time when the order looks wrong.
- **Encrypted phone backups look empty.** An iOS backup encrypted with an unknown password yields no readable app DBs — that is a locked-evidence finding, not "clean." Record the encryption and pursue the key/passcode rather than concluding nothing happened.
- **MVT with NO IOC feed reports zero detections — that is not a clean verdict.** `mvt-ios`/`mvt-android` only flag what its STIX2 feed knows; an empty result with no feed loaded means "untested," not "uninfected." Always confirm a feed was loaded before reading a null result as benign.
- **mac_apt is BROKEN on this box.** Any iOS/macOS enrichment that depends on `mac_apt.py` (KnowledgeC/Unified Log deep parsing) will fail silently — an empty mac_apt result does NOT mean no activity. Route around it with `SQLECmd`/`sqlite-carver` and plaso, and tag `⚠️verify`.
- **Native vmdk/vhdi/qemu-img parsers are unconfirmed here.** Do not assume `vmdkmount`/`vhdimount`/`qemu-img convert` exist on this box. Read the VM disk via TSK on the raw extent or via `imount`; `⚠️verify` any native libvmdk/libvhdi/qemu-img call before relying on it.
- **A side-loaded app can be benign.** Not every unfamiliar package is spyware — corroborate with its permissions, network destinations, and an IOC match before calling it malicious. **Missing evidence is itself a finding.**
- **A descriptor `.vmdk` is a pointer, not the data.** A small `.vmdk` text descriptor references separate extent files; if the extents are missing the disk will not parse. Collect the whole VM directory, not just the descriptor.

## Failure modes
```
- mode: evidence-access failure — the VM container or mobile backup will not open (vmdk descriptor missing extents, encrypted volume/backup, unreadable mount)
  guard: Step 0/1 fallback chain — imount RO, else TSK fls/icat the guest artifact inodes into #{case_out}/extracted; if encrypted record the locked-evidence finding and pivot acquisition-custody
- mode: primary-artifact-absent — no .vmem (disk-only VM), no iOS Manifest.db, no Android backup, or no app DBs present
  guard: record the absence as a finding; name the secondary source (guest disk timeline, the other-OS MVT module, the fused super-timeline) and continue — never read absence as clean
- mode: tool-output drift — vol plugin names change, SQLECmd map/column names shift, or MVT JSON layout changes so a check literal misses
  guard: on check exit 2, adjudicate from the prose expect/falsify against the receipt, cap confidence at inferred; fall back to raw srch_strings/sqlite-carver over the same store, never silently pass
- mode: MVT with no IOC feed — mvt-ios/mvt-android returns zero detections only because no STIX2 feed was loaded
  guard: confirm a feed was loaded before reading a null result as benign; if no feed, parse the app DBs directly and label the result inferred/untested
- mode: wrong-OS memory plugins — windows.* vol plugins run against a Linux/Android .vmem and yield nothing
  guard: confirm the guest OS from Step 0; switch to linux.* plugins with a matching ISF symbol pack (⚠️verify availability) before concluding the memory is clean
- mode: mac_apt broken — iOS/macOS enrichment via mac_apt.py fails to import
  guard: route around it with SQLECmd/sqlite-carver and plaso; tag the gap ⚠️verify and treat the mac_apt result as degraded, not absent
```
Minimum set every playbook covers: evidence-access failure (Step 0 fallback chain) · primary-artifact-absent (absence recorded, secondary source named) · tool-output drift (`check` exits 2 → prose adjudication, never silent pass).

## Confidence labeling (observation → inference → conclusion)
- **confirmed:** direct receipt verbatim (e.g. an MVT detection JSON row or a .vmem malfind PID) + at least 2 independent sources agree (memory + disk, or MVT + app DB) + no unrefuted counter-theory.
- **inferred:** grounded but single-source/interpretive — an MVT hit with no app-DB corroboration yet, a snapshot revert read from chain metadata alone, a wrong-OS vol run, or any `check`-exit-2 adjudication → hedge and tag `⚠️verify`.
- **insufficient_evidence:** precondition unmet (no .vmem; encrypted backup; no IOC feed; mac_apt broken) or sources conflict → abstain; state what is missing, do not guess.

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
- **Windows guest:** fully covered above — once the `.vmdk`/`.vhdi` opens read-only, the guest is investigated exactly like a physical Windows host (registry, EVTX, $MFT) plus the `.vmem` snapshot for RAM.
- **Linux guest / ESXi / Proxmox:** see the numbered Linux branch (L1-L2) — the container opens the same way, but guest-internal artifacts are auth.log/journal/cron/systemd and (on a container host) docker overlay2 layers; no EVTX/registry.
- **macOS guest / iOS backup:** app DBs and the iOS backup parse via `SQLECmd`/`sqlite-carver` and `mvt-ios`; the Unified Log and KnowledgeC deep-enrichment via `mac_apt.py` is **BROKEN on this box** (`⚠️verify` — degraded), so an empty mac_apt result is not "no activity." Pivot macos-forensics for deeper macOS guest analysis.
- **Cloud-hosted VM:** a cloud VM disk exported as `.vmdk`/`.vhd` opens identically here; the control-plane side (who created/exported the VM, snapshot API calls) lives in cloud audit logs, not the disk — pivot cloud-iaas-control-plane for that half.
- **Native VM parsers:** `vmdkmount`/`vhdimount`/`qemu-img` are NOT confirmed on this box; TSK on the raw extent and `imount` are the run-verified path. `⚠️verify` any native libvmdk/libvhdi/qemu-img use.

## Real-case notes (non-obvious things to look for)
- **Pegasus/targeted iOS implants leave traces MVT was built to catch.** Amnesty International's Mobile Verification Toolkit was created from real Pegasus cases; iOS detections cluster in `DataUsage`/`netusage` process names, malicious domains in Safari history and `cache.db`, and anomalous configuration profiles. A single rogue process name correlated to a known-bad domain is the canonical hit. `[Amnesty International MVT methodology / general DFIR practice · high]`
- **Commodity Android stalkerware hides as a renamed system app with broad permissions.** Look for a side-loaded package (not from the official store) holding SMS/location/mic/accessibility permissions and READ_SMS/RECORD_AUDIO grants, often with a generic name; the installed-package list plus permission grants in the backup is the tell. `[general mobile-forensics practice · med]`
- **A reverted VM snapshot is a classic anti-forensic move and is visible in the `.vmsd` chain.** When the current disk looks too clean for the alleged activity, the `.vmsd` snapshot descriptor and `.vmsn` state files reveal whether a revert rolled back the guest; a `.vmem`/`.vmss` captured after the revert can still hold the erased process. `[general virtualization-forensics practice · med]`
- **The `.vmem` snapshot is RAM the disk never wrote.** A snapshot taken while malware ran freezes injected code, decrypted strings, and live C2 sockets that no on-disk artifact records — `vol` malfind/netscan over the `.vmem` recovers what a disk-only exam misses. `[Volatility documentation / general practice · high]`
- **Shared folders and clipboard are the VM escape breadcrumb.** VMware `hgfs`/`\\vmware-host\Shared Folders` and VirtualBox `VBoxSharedFolders` mounts, plus clipboard/drag-drop residue, are where a file or command crosses guest↔host — the first place to look when a guest compromise might have reached the host. `[MITRE T1611 / general practice · med]`
- **Encrypted iOS backups need the passcode/key before app DBs read.** A backup encrypted in iTunes/Finder yields nothing without the password; treat the empty parse as locked-evidence, not absence, and pursue the key. `[Apple backup documentation / general practice · high]`

## ATT&CK mapping
- T1611 · Privilege Escalation · Escape to Host · guest-to-host via shared folder / hypervisor abuse — step 8
- T1610 · Defense Evasion/Execution · Deploy Container · poisoned image / escaped container on a Linux VM host — step L2
- T1055 · Defense Evasion/Privilege Escalation · Process Injection · malfind-flagged injected region in the .vmem snapshot — step 2
- T1070.004 · Defense Evasion · File Deletion / artifact removal · snapshot revert erasing guest disk activity — step 3
- T1474 · Initial Access (Mobile) · Supply Chain Compromise · side-loaded/poisoned mobile app — step 5
- T1636 · Collection (Mobile) · Protected User Data · spyware reading SMS/call/contacts/location from app DBs — steps 4/5/6
- T1426 · Discovery (Mobile) · System Information Discovery · stalkerware enumerating device/permissions — step 5
- T1646 · Exfiltration (Mobile) · Exfiltration Over C2 Channel · mobile implant beaconing to a malicious domain — steps 4/5
- T1552.001 · Credential Access · Credentials In Files · hardcoded credential in an embedded/IoT firmware image — step 7
- T1542 · Persistence/Defense Evasion · Pre-OS Boot · implant embedded in device firmware — step 7
- T1078 · Defense Evasion/Persistence · Valid Accounts · stolen credential reused inside the VM guest — step 1

## Pivots (lead-to-lead graph)
- `on_vmem_rogue_process (step 2 malfind/netscan PID): memory-forensics — deeper RAM analysis of the injected process and its network residue`
- `on_guest_persistence (step 1/L2 service/Run key/cron): windows-registry-persistence — confirm the guest autorun in its hive`
- `on_mobile_spyware_detection (step 4/5 MVT hit): malware-analysis-triage — triage the implant/side-loaded package binary`
- `on_app_db_browser_activity (step 6 visits/downloads): browser-email-documents — deeper browser/email store parsing`
- `on_embedded_implant (step 7 hardcoded cred/implant): malware-analysis-triage — analyze the firmware payload`
- `on_container_host_overlay2 (step L2 docker layers): containers-supply-chain — investigate the poisoned image / escaped container`
- `on_cloud_exported_vm (cloud VM disk): cloud-iaas-control-plane — who created/exported/snapshotted the VM in the control plane`
- `on_macos_guest_or_ios_deep (step 6 mac_apt-degraded): macos-forensics — deeper macOS/iOS guest analysis around the broken mac_apt`
- `on_locked_or_unmountable_container (step 0/1): acquisition-custody — re-acquire or prove the collection/encryption gap`
- `on_snapshot_revert_timeframe (step 3 revert window): SELF — re-enter with the pre-revert timestamp bound into #{time_window} to bracket what was hidden`

## Jargon decoder
- **VM (virtual machine):** a whole computer running as files on a host — a guest disk plus its memory and settings.
- **.vmdk / .vhdi (.vhd/.vhdx):** the virtual disk file formats — VMware uses `.vmdk`, Hyper-V/Virtual PC use `.vhd`/`.vhdx` (libvhdi reads them); each holds a guest file system inside.
- **raw extent:** the actual data portion of a virtual disk that TSK can read directly, as opposed to the small text **descriptor** that just points at it.
- **.vmem / .vmss / .vmsn / .vmsd:** a VMware memory dump (`.vmem`), suspend state (`.vmss`), snapshot state (`.vmsn`), and the snapshot-chain descriptor (`.vmsd`).
- **snapshot:** a saved point-in-time state of a VM; **reverting** to an older snapshot rolls the disk back and can erase later activity (an anti-forensic move).
- **guest / host:** the VM is the **guest**; the physical machine running it is the **host**. A **guest-to-host escape** breaks out of the VM into the host.
- **shared folder / hgfs:** a directory shared between guest and host (VMware `hgfs` / `\\vmware-host`, VirtualBox `VBoxSharedFolders`) — a path for files to cross the boundary.
- **iOS backup / Manifest.db:** an iTunes/Finder backup of an iPhone; `Manifest.db` is its index of every backed-up file and app domain.
- **Android backup (.ab) / image:** an `adb backup` archive or a filesystem dump of an Android device holding app data.
- **MVT (Mobile Verification Toolkit):** `mvt-ios`/`mvt-android` — Amnesty International's spyware-triage tool that checks a backup against a STIX2 IOC feed.
- **STIX2 IOC feed:** a standard threat-intel file of indicators (domains, processes, hashes) that MVT matches against the device — without it, MVT detections are empty.
- **stalkerware / spyware:** monitoring software (commodity stalkerware or a targeted implant like Pegasus) that reads messages, location, and audio.
- **configuration profile (iOS):** a settings package that can silently route traffic or grant access — a stealth persistence/spyware vector on iOS.
- **app SQLite DB:** the per-app databases (messages, calls, browser, contacts) stored as SQLite files; **deleted rows** can be carved from the freelist/unallocated.
- **embedded / IoT firmware image:** the software image of a small device (router, camera) — searched for implants and hardcoded credentials.
- **ISF symbol pack:** the per-kernel symbol table Volatility 3 needs to parse a Linux/Android memory image; absent here without building it.
- **super-timeline:** one merged chronology across many artifacts, built with `log2timeline.py` + `psort.py`.

## Tuning log (append-only — the eval loop writes here; humans never edit rows)
| date | case_id | bucket missed | delta applied |
|---|---|---|---|
