---
attack_type: attack-lifecycle-hunting
category_id: attack-lifecycle-hunting
name: Attack-Lifecycle Hunting (ATT&CK)
description: reconstruct the full intrusion timeline across artifacts and map it to ATT&CK tactics
version: 1
os_coverage: [windows, linux, macos, cloud]
sub_types_covered: 15
sub_types:
  - initial-access-phishing-or-exploit-landing
  - execution-dropper-or-interpreter-run
  - persistence-service-task-runkey-wmi
  - privilege-escalation-token-or-admin-assignment
  - defense-evasion-log-clear-or-timestomp
  - credential-access-lsass-or-hive-dump
  - discovery-recon-host-and-network
  - lateral-movement-rdp-smb-network-logon
  - collection-staging-archive-of-data
  - command-and-control-beacon-or-cradle
  - exfiltration-over-c2-or-web-or-removable
  - impact-ransomware-or-wiper-or-destruction
  - timeline-correlation-cross-artifact
  - dwell-time-first-to-last-attacker-action
  - anti-forensics-gap-or-tamper-detection
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
A break-in is rarely one event — it is a chain: the attacker gets in, runs something, digs in so a reboot won't evict them, grabs more power, looks around, hops to other machines, steals data, and sometimes burns the place down on the way out. This playbook is the SYNTHESIS playbook: it fuses every artifact family on the box into ONE chronological story and tags each step with its ATT&CK tactic, so you can say not just "malware was here" but "here is the whole intrusion, start to finish, in order."

## Use this when (triggers)
- You have **multiple unconnected leads** (a weird logon here, a strange service there, an odd file somewhere) and need to know whether they are ONE intrusion and in what order they happened.
- A single-artifact playbook (event logs, registry, execution, etc.) found something real and you now need the **full lifecycle** around it — how they got in, what they did next, and where it ended.
- The brief asks for an **ATT&CK-mapped narrative** or a **dwell-time** estimate (first to last attacker action), not just one IOC.
- You suspect a **multi-host** or **long-dwell** compromise and need a cross-artifact timeline to find gaps the attacker tried to hide.
- You need to be sure **nothing present went unread** before declaring the case closed — this playbook's close-gate is the per-modality sweep.

## Quick path (the 90% case)
1. **Timeline-first — build the super-timeline.** Fuse everything into one chronology with `log2timeline.py` then `psort.py` (and `pinfo.py` to confirm which parsers ran). If a full super-timeline is too slow, build a fast filesystem timeline first with `fls` → `mactime` (bodyfile) or `MFTECmd` sorted by time. Skim it inside `#{time_window}` BEFORE committing to any story — the ORDER of access → execution → persistence → escalation → lateral → collection → exfil/impact is the case.
2. **Pin the earliest attacker action (initial access / execution).** Find the first anomalous event — a phishing-dropped file, a web-server hit, a first-seen binary in `\Users\`/`\ProgramData\`/`/tmp`. Anchor `#{time_window}` to it ±48h.
3. **Walk the chain forward, one tactic at a time.** Persistence (`7045` service / `4698` task / Run key via `RECmd`/`rip.pl` / cron-systemd), privilege (`4672`/`4648` or sudo), discovery, lateral movement (`4624` type 3/10), collection (staged archives), C2 (beacon strings in memory/pagefile), exfil/impact (large reads, ransom note, mass rename).
4. **Corroborate every node on a SECOND source.** A logon (event log) must agree with a registry/$MFT/memory trace; a service install must agree with the on-disk binary's create time. One line is a lead, not a fact.
5. **Detect anti-forensics.** Cleared logs (`1102`/`104`), `$SI`-vs-`$FN` timestomp (`MFTECmd`), gaps, emptied artifact dirs — each is a finding, not silence.

If access → execution → persistence → escalation → lateral → collection → exfil/impact line up on one timeline with a corroborating second source at each node → you have the lifecycle. Otherwise drop into the full Steps.

## How it unfolds (the story)
An actor lands on the first host — a phishing attachment or link, an exploited internet-facing service, or stolen credentials over RDP/VPN. They run a dropper or an interpreter (PowerShell/cmd/bash), then nail down persistence (a service, a scheduled task, a Run key, a WMI subscription, or a cron/systemd unit) so a reboot won't evict them. They escalate to admin, do quick recon, dump credentials, and hop to other machines using those creds (network/RDP logons, remote service installs). On the target machines they stage and archive the data they want, beacon to a command-and-control server, and exfiltrate over that channel, the web, or removable media — and some finish with ransomware or a wiper. The whole arc is reconstructable because each phase leaves a different artifact family, and fused on one timeline they tell the story in order.

## Theories to test (and how to rule each out)
| Theory (who / why) | If true, you'd find… | Rule it out if… |
|---|---|---|
| **External-targeted (hands-on APT, full lifecycle)** | a coherent ordered chain: initial access → execution → persistence → priv-esc → discovery → cred-access → lateral → collection → C2 → exfil/impact, spanning days/weeks, with anti-forensics (cleared logs, timestomp) | the leads do NOT chain — no ordered progression, no persistence, no lateral movement, no C2/exfil; the "intrusion" is one isolated event |
| **External-commodity (smash-and-grab / ransomware crew)** | fast chain (hours): access → execution → quick persistence → mass-encryption/impact with a ransom note, little discovery or lateral movement, noisy not stealthy | no impact stage, no ransom note, no mass file-change burst; the activity is slow, targeted, and data-focused not destructive |
| **Other-insider (compromised legit account / stolen creds)** | a valid account driving the chain from an unusual source/hour; lateral movement using its creds; no dropper-style initial access (they already had a way in) | the account's source, workstation and hours match its own baseline and no creds were proven stolen → reclassify innocent or insider |
| **Insider (authorized user acting maliciously)** | local interactive access by a real account, no external initial-access vector, collection/exfil of data they were entitled to touch but not to take (USB/cloud/webmail), little or no persistence or lateral movement | access came from outside or creds were proven stolen → reclassify other-insider; OR data movement was sanctioned → innocent |
| **Supply-chain / RMM abuse** | the "first" malicious binary is delivered by a trusted updater/RMM agent; the same persistence lands on MANY hosts simultaneously; parent process is a signed updater | persistence is a user-dropped binary on THIS host only, no trusted-updater parent, no fleet-wide simultaneity |
| **Innocent / benign (NOT an attack)** | the chain dissolves on inspection: a "service" is a signed vendor MSI, a "logon" is an expected admin, a "clear" is sanctioned log rotation, a "big transfer" is a backup job — all in business hours by expected accounts with change-control records | a sanctioned change-control record explains each node AND accounts/sources/hours are all expected → benign; close as no-incident |

*(≥1 benign + ≥1 malicious, each ACTIVELY refuted. Attacker types mapped: insider · other-insider · external-commodity · external-targeted · supply-chain · innocent.)*

## Evidence → Tool → What it reveals (per OS)
| Evidence | SIFT tool | What it tells you *for this attack* | OS |
|---|---|---|---|
| ALL artifacts fused into one chronology | `log2timeline.py` + `psort.py` (+ `pinfo.py`) | the SYNTHESIS backbone — places initial-access → execution → persistence → priv-esc → lateral → collection → exfil/impact in order across every parser | all |
| `$MFT` / `$UsnJrnl:$J` / `$Boot` | `MFTECmd` | first-seen create time of attacker binaries (initial access/execution anchor), staged-archive creation (collection), mass-rename burst (impact), `$SI`-vs-`$FN` timestomp (defense evasion) | Windows |
| filesystem MAC timeline (deleted names too) | `fls` → `mactime` (bodyfile), `tsk_gettimes` | a fast filesystem timeline for the quick path and a cross-check on `$MFT` order; recovers deleted attacker-file names | all |
| `Security.evtx`/`System.evtx` + Operational logs | `EvtxECmd` (`evtxexport`/`evtx_dump.py` raw fallback) | logons (access/lateral 4624 type 2/3/10, 4625), privilege (4672/4648), persistence (7045 service / 4698 task), execution (4688), clearing (1102/104) — the human-action spine of the timeline | Windows |
| SOFTWARE/SYSTEM/NTUSER hives | `RECmd` / `rip.pl` | execution (UserAssist/BAM/DAM), persistence (Run keys, Services), USB attach (collection/exfil over removable) — the off-log corroboration for execution and persistence | Windows |
| `Amcache.hve` | `AmcacheParser` / `amcache.py` | first-seen app/driver inventory + SHA1 — a presence/first-execution INFERENCE anchor (⚠ NOT proof of execution post-Lagny) | Windows |
| ShimCache (AppCompatCache in SYSTEM) | `AppCompatCacheParser` | a binary's path/size/last-mod was present on disk — presence ordering, NOT execution on Win8+ (⚠ execution bit only reliable XP/2003/Vista/7) | Windows |
| `*.lnk` / Jump Lists / ShellBags | `LECmd` / `JLECmd` / `SBECmd` | files and folders the actor accessed (discovery/collection), volume serials linking to removable media (exfil) | Windows |
| RAM image (if captured) | `vol` (Volatility 3) | live rogue processes, injected code, the C2 socket (`netscan`), service/persistence (`svcscan`), in-memory ShimCache not yet flushed — execution/persistence/C2 evidence that never touched disk | Windows/Linux* |
| `pagefile.sys` / swap | `page-brute` (YARA via python3-yara) | in-memory spill of C2 domains, encoded commands, credentials — covert-channel and cradle indicators carved from paged-out RAM | Windows/Linux |
| whole image, FS-independent | `bulk_extractor` | emails, URLs, IPs, credit-card numbers, search terms spilled across the image — C2 domains and exfil targets even with no live FS | all |
| any binary/PE pulled from the chain | `pe-scanner` (PE + entropy + python3-yara), `densityscout`, `clamscan` | packing/anomaly and known-malware triage on the dropper/payload found at any lifecycle node | all |
| Linux logs / cron / systemd / journal | `fls`/`mactime`, `log2timeline.py` (syslog/utmp/journal), `srch_strings` | SSH logons (access/lateral), sudo (priv-esc), cron/systemd units (persistence), bash history & staged tarballs (collection/exfil) — the Linux lifecycle | Linux |

*Linux memory analysis in `vol` needs a matching symbol table — ⚠️verify availability before relying on it. There is no PECmd/SrumECmd on this box, so Prefetch/SRUM execution proof is absent — execution evidence comes from UserAssist/BAM (RECmd/rip.pl), 4688 (EvtxECmd), and weak Amcache inference.*

## Step 0 — evidence inventory & access bootstrap
- n: 0
  tool: |
    mkdir -p "#{case_out}/receipts" "#{case_out}/extracted" && ls -laR "#{mount_root}" > "#{case_out}/receipts/00.txt" 2>&1 ; img_stat "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; mmls "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; fsstat -o #{ntfs_offset_sectors} "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; find "#{mount_root}" -maxdepth 4 -iname "*.evtx" -o -iname "*.hve" -o -iname "\$MFT" -o -iname "pagefile.sys" >> "#{case_out}/receipts/00.txt" 2>&1 ; ls "#{mount_root}" >> "#{case_out}/receipts/00.txt" 2>&1
  expect: every evidence file classified (disk image / memory / pcap / logs); #{image_path}, #{mount_root}, #{ntfs_offset_sectors}, #{case_out} bound; read-only access proven; the lifecycle modalities present are enumerated (winevt\Logs .evtx, registry hives, $MFT, pagefile, and on Linux /var/log) OR their absence is recorded as a finding
  check: |
    test -r "#{mount_root}" -o -n "$(ls "#{case_out}/extracted" 2>/dev/null)"
  falsify: evidence dir empty/unreadable, or no supported image format found, or no partition for fsstat
  on_result: {expect_met: goto 1, falsify_met: STOP — report acquisition/access failure; pivot acquisition-custody, neither: try the icat-extract fallback (fls to find the winevt\Logs/hive/$MFT inodes, icat each into #{case_out}/extracted); if that also fails, treat as falsify_met}
  emits: [key_artifacts]
  serves: [initial-access-phishing-or-exploit-landing, execution-dropper-or-interpreter-run, persistence-service-task-runkey-wmi, privilege-escalation-token-or-admin-assignment, defense-evasion-log-clear-or-timestomp, credential-access-lsass-or-hive-dump, discovery-recon-host-and-network, lateral-movement-rdp-smb-network-logon, collection-staging-archive-of-data, command-and-control-beacon-or-cradle, exfiltration-over-c2-or-web-or-removable, impact-ransomware-or-wiper-or-destruction, timeline-correlation-cross-artifact, dwell-time-first-to-last-attacker-action, anti-forensics-gap-or-tamper-detection]
  provenance: {receipt_id: 00, artifact: evidence directory listing + modality enumeration, offset_or_row: full listing, literal_cited: image filename + present-modality list}

## Steps (executable — decision-driven)
- n: 1
  precondition: "os == windows; test -r #{mount_root}"
  tool: |
    log2timeline.py --status_view none "#{case_out}/case.plaso" "#{mount_root}" > "#{case_out}/receipts/01.txt" 2>&1 ; psort.py -o l2tcsv "#{case_out}/case.plaso" > "#{case_out}/super.csv" 2>> "#{case_out}/receipts/01.txt" ; pinfo.py "#{case_out}/case.plaso" >> "#{case_out}/receipts/01.txt" 2>&1
  expect: a single fused super-timeline (#{case_out}/super.csv) with rows from many parsers (winevtx, filestat/mft, registry, prefetch, lnk, browser) — the SYNTHESIS backbone every later step filters; pinfo confirms the parsers that ran
  check: |
    test -s "#{case_out}/super.csv" && grep -qiE "winevtx|filestat|mft|registry|lnk" "#{case_out}/super.csv"
  falsify: log2timeline parsed nothing (no recognizable artifacts), or psort produced an empty CSV — the image has no parseable lifecycle artifacts here
  on_result: {expect_met: goto 2, falsify_met: build the fast fallback timeline (fls -m bodyfile then mactime; or MFTECmd sorted by time) and proceed on that; if even the filesystem is unreadable pivot disk-filesystem, neither: re-run psort.py scoped to #{time_window}; run pinfo.py to see which parsers fired and re-run log2timeline on the specific artifact dir that failed}
  emits: [timeline_events]
  serves: [timeline-correlation-cross-artifact]
  provenance: {receipt_id: 01, artifact: case.plaso super-timeline, offset_or_row: super.csv header + row count, literal_cited: pinfo parser list line}

- n: 2
  precondition: "exists #{case_out}/super.csv"
  tool: |
    dotnet /opt/zimmermantools/MFTECmd.dll -f "#{mount_root}" --csv "#{case_out}" --csvf mft.csv > "#{case_out}/receipts/02.txt" 2>&1 ; awk -F',' 'NR==1 || $0 ~ /Users|ProgramData|Temp|PerfLogs|Public/' "#{case_out}/mft.csv" | head -200 >> "#{case_out}/receipts/02.txt" 2>&1
  expect: the EARLIEST attacker-controlled file on disk — a first-seen binary/script under \Users\ \ProgramData\ %TEMP% \PerfLogs\ \Public\ whose $MFT Created0x10 time pins INITIAL ACCESS / first execution; this becomes the anchor for #{time_window} (±48h)
  check: |
    test -s "#{case_out}/mft.csv" && grep -qiE "Users|ProgramData|Temp|PerfLogs|Public" "#{case_out}/receipts/02.txt"
  falsify: no suspicious first-seen file in those paths inside any plausible window — initial access may be credential-only (no dropped file) or via a living-off-the-land binary already present
  on_result: {expect_met: record the file path + create time as the initial-access anchor; set #{time_window}; goto 3, falsify_met: initial access is likely creds-only or LOLBin — lean on logon evidence (step 4) and registry execution (step 5) for the anchor; goto 4, neither: widen the path filter and re-scan; cross-check against the super.csv filestat rows for the same window}
  emits: [key_artifacts, timeline_events]
  serves: [initial-access-phishing-or-exploit-landing, execution-dropper-or-interpreter-run, dwell-time-first-to-last-attacker-action]
  provenance: {receipt_id: 02, artifact: $MFT, offset_or_row: mft.csv first-seen row, literal_cited: file path + Created0x10 timestamp}

- n: 3
  precondition: "exists #{case_out}/mft.csv"
  tool: |
    dotnet /opt/zimmermantools/MFTECmd.dll -f "#{mount_root}" --csv "#{case_out}" --csvf mftj.csv >> "#{case_out}/receipts/03.txt" 2>&1 ; awk -F',' 'NR==1 || ($0 ~ /\.(7z|zip|rar|tar|gz|cab|7zip)/ || $0 ~ /\.(locked|crypt|encrypted|onion|enc)/)' "#{case_out}/mft.csv" | head -200 > "#{case_out}/receipts/03.txt" 2>&1
  expect: COLLECTION/IMPACT file-system signal — a staged archive (.7z/.zip/.rar/.tar.gz) created in #{time_window} (data being bundled for exfil), OR a mass-rename burst to ONE new extension (.locked/.crypt) = ransomware impact; $SI-vs-$FN disagreement on attacker files = timestomp (defense evasion)
  check: |
    grep -qiE "\.(7z|zip|rar|tar|gz|cab)|\.(locked|crypt|encrypted|enc)" "#{case_out}/receipts/03.txt"
  falsify: no staged archive and no mass-rename burst in #{time_window} — no filesystem-visible collection or destructive impact on this host
  on_result: {expect_met: record archive path (collection) or new extension (impact) as an IOC; if mass-encryption pivot ransomware-destructive, falsify_met: record "no filesystem collection/impact here"; continue the chain at goto 4, neither: parse $UsnJrnl:$J (MFTECmd over the live image) to recover rename/create history the live $MFT no longer shows; re-scope #{time_window}}
  emits: [exfil_or_encryption_facts, key_iocs]
  serves: [collection-staging-archive-of-data, impact-ransomware-or-wiper-or-destruction, defense-evasion-log-clear-or-timestomp]
  provenance: {receipt_id: 03, artifact: $MFT / $UsnJrnl:$J, offset_or_row: mft.csv archive/renamed row, literal_cited: archive name or new extension string}

- n: 4
  precondition: "os == windows; test -r #{mount_root}"
  tool: |
    dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll -d "#{mount_root}" --csv "#{case_out}" --csvf events.csv > "#{case_out}/receipts/04.txt" 2>&1 ; grep -E ",4624,|,4625,|,4672,|,4648,|,4688,|,7045,|,4698,|,1102,|,104," "#{case_out}/events.csv" | head -400 >> "#{case_out}/receipts/04.txt" 2>&1
  expect: the human-action spine — 4624 logons with LogonType (2 console / 3 network / 10 RDP) + source IP marking ACCESS and LATERAL movement; 4625 failure bursts (brute force); 4672/4648 PRIV-ESC; 4688 EXECUTION (path + command line if audited); 7045/4698 PERSISTENCE; 1102/104 LOG CLEARING (defense evasion) — all placed in #{time_window}
  check: |
    test -s "#{case_out}/events.csv" && grep -qE ",4624,|,4688,|,7045,|,4698,|,1102," "#{case_out}/events.csv"
  falsify: no Security/System events at all (auditing off or logs cleared/absent) — record the absence as a finding and rely on the timeline + registry for the human-action spine
  on_result: {expect_met: tag each event to its ATT&CK tactic and slot it into the timeline; goto 5, falsify_met: fall back to raw export (evtxexport / evtx_dump.py per file into #{case_out}/extracted then grep the EventID XML); if logs are truly absent record it and pivot windows-event-logs, neither: re-run EvtxECmd -f on the specific Security.evtx/System.evtx; widen #{time_window}}
  emits: [actor_accounts, timeline_events]
  serves: [initial-access-phishing-or-exploit-landing, execution-dropper-or-interpreter-run, persistence-service-task-runkey-wmi, privilege-escalation-token-or-admin-assignment, lateral-movement-rdp-smb-network-logon, defense-evasion-log-clear-or-timestomp]
  provenance: {receipt_id: 04, artifact: Security.evtx / System.evtx, offset_or_row: events.csv 4624/4688/7045/1102 rows, literal_cited: EventId + account + LogonType/ImagePath/CommandLine string}

- n: 5
  precondition: "os == windows; test -r #{mount_root}"
  tool: |
    dotnet /opt/zimmermantools/RECmd/RECmd.dll --bn /opt/zimmermantools/RECmd/BatchExamples/Kroll_Batch.reb -d "#{mount_root}" --csv "#{case_out}" --csvf reg.csv > "#{case_out}/receipts/05.txt" 2>&1 ; grep -iE "userassist|bam|dam|run|services|usbstor" "#{case_out}/reg.csv" | head -300 >> "#{case_out}/receipts/05.txt" 2>&1
  expect: registry corroboration across the chain — UserAssist/BAM/DAM rows naming the binaries that RAN (execution, the off-log proof for a 4688); Run-key/Services rows = the PERSISTENCE the 7045/4698 installed; USBSTOR rows = removable-media attach (collection/exfil); each path should match a node already on the timeline
  check: |
    test -s "#{case_out}/reg.csv" && grep -qiE "userassist|bam|run|services|usbstor" "#{case_out}/receipts/05.txt"
  falsify: the timeline's execution/persistence paths appear in NO registry source — those nodes are single-source (hold at inferred) and the registry adds no corroboration here
  on_result: {expect_met: promote each corroborated node toward confirmed (two-source); goto 6, falsify_met: keep those nodes at inferred/single-source; run rip.pl -r against the specific SYSTEM/SOFTWARE/NTUSER hive for run/services/userassist and re-check; pivot windows-registry-persistence, neither: run rla first to replay transaction logs (.LOG1/2) then re-run RECmd on the normalized hive}
  emits: [key_iocs, actor_accounts]
  serves: [execution-dropper-or-interpreter-run, persistence-service-task-runkey-wmi, privilege-escalation-token-or-admin-assignment, exfiltration-over-c2-or-web-or-removable]
  provenance: {receipt_id: 05, artifact: SOFTWARE/SYSTEM/NTUSER hive, offset_or_row: reg.csv UserAssist/Run/Services/USBSTOR row, literal_cited: matching path + key value string}

- n: 6
  precondition: "exists #{case_out}/super.csv; test -r #{mount_root}"
  tool: |
    for h in $(find "#{mount_root}" -maxdepth 5 -iname "Amcache.hve" 2>/dev/null); do dotnet /opt/zimmermantools/AmcacheParser.dll -f "$h" --csv "#{case_out}" --csvf amcache.csv >> "#{case_out}/receipts/06.txt" 2>&1 ; done ; for s in $(find "#{mount_root}" -maxdepth 6 -ipath "*System32/config/SYSTEM" 2>/dev/null); do dotnet /opt/zimmermantools/AppCompatCacheParser.dll -f "$s" --csv "#{case_out}" --csvf shimcache.csv >> "#{case_out}/receipts/06.txt" 2>&1 ; done ; for l in $(find "#{mount_root}" -maxdepth 8 -iname "*.lnk" 2>/dev/null | head -50); do dotnet /opt/zimmermantools/LECmd.dll -f "$l" >> "#{case_out}/receipts/06.txt" 2>&1 ; done
  expect: presence/first-seen ordering and access trail — Amcache SHA1+first-seen and ShimCache path/last-mod place attacker binaries on disk at a time (presence ordering, NOT execution proof on Win8+); LNK target paths/volume serials show files/folders the actor opened (DISCOVERY) and removable-media access (collection/exfil)
  check: |
    test -s "#{case_out}/amcache.csv" -o -s "#{case_out}/shimcache.csv" -o -s "#{case_out}/receipts/06.txt"
  falsify: Amcache/ShimCache/LNK name none of the timeline's attacker paths — these inventory sources add nothing here (record it; do NOT treat Amcache/ShimCache presence as execution proof anyway)
  on_result: {expect_met: add presence-ordering + access nodes to the timeline (tagged inference-only for Amcache/ShimCache); goto 7, falsify_met: record "no inventory/access corroboration"; goto 7, neither: re-run AmcacheParser/AppCompatCacheParser pointing at the icat-extracted hive in #{case_out}/extracted; pivot windows-execution-artifacts}
  emits: [key_artifacts, timeline_events]
  serves: [execution-dropper-or-interpreter-run, discovery-recon-host-and-network, collection-staging-archive-of-data]
  provenance: {receipt_id: 06, artifact: Amcache.hve / ShimCache (SYSTEM) / *.lnk, offset_or_row: amcache.csv SHA1 row / shimcache.csv path row / LECmd target line, literal_cited: binary path + SHA1 / LNK target path}

- n: 7
  precondition: "exists #{case_out}/super.csv"
  tool: |
    if ls "#{mount_root}"/*.raw "#{mount_root}"/*.mem "#{mount_root}"/*.vmem "#{mount_root}"/*.lime >/dev/null 2>&1; then for m in "#{mount_root}"/*.raw "#{mount_root}"/*.mem "#{mount_root}"/*.vmem "#{mount_root}"/*.lime; do vol -f "$m" windows.netscan > "#{case_out}/receipts/07.txt" 2>&1 ; vol -f "$m" windows.pslist >> "#{case_out}/receipts/07.txt" 2>&1 ; vol -f "$m" windows.svcscan >> "#{case_out}/receipts/07.txt" 2>&1 ; done ; else find "#{mount_root}" -iname "pagefile.sys" -exec /opt/page-brute/bin/page-brute -f {} \; >> "#{case_out}/receipts/07.txt" 2>&1 ; fi
  expect: COMMAND-AND-CONTROL + live-execution evidence — vol windows.netscan shows the C2 socket/remote IP, pslist/svcscan show the rogue process and persistence service not flushed to disk; if no RAM image, page-brute (python3-yara over pagefile.sys) carves C2 domains / encoded cradles / credential spill from paged-out memory
  check: |
    test -s "#{case_out}/receipts/07.txt"
  falsify: no memory image AND pagefile is absent/empty — no volatile C2/execution evidence available; the C2 stage rests on disk/network artifacts only
  on_result: {expect_met: record the remote IP/domain + rogue PID as C2 IOCs; correlate them back through the timeline; goto 8, falsify_met: record "no volatile evidence"; look for C2 in browser/proxy logs and bulk_extractor URLs at step 8; pivot network-forensics if a pcap exists, neither: confirm the memory profile/symbols matched (vol needs them); for Linux memory ⚠️verify the symbol table before trusting an empty result}
  emits: [key_iocs, timeline_events]
  serves: [command-and-control-beacon-or-cradle, execution-dropper-or-interpreter-run, persistence-service-task-runkey-wmi]
  provenance: {receipt_id: 07, artifact: memory image / pagefile.sys, offset_or_row: netscan row / page-brute YARA hit, literal_cited: remote IP:port or carried C2 domain string}

- n: 8
  precondition: "exists #{case_out}/super.csv"
  tool: |
    bulk_extractor -o "#{case_out}/bulk" "#{image_path}" > "#{case_out}/receipts/08.txt" 2>&1 ; grep -hiE "http|\.onion|[0-9]{1,3}(\.[0-9]{1,3}){3}" "#{case_out}/bulk/url.txt" "#{case_out}/bulk/domain.txt" 2>/dev/null | head -200 >> "#{case_out}/receipts/08.txt" 2>&1 ; cat "#{case_out}/bulk/ccn.txt" "#{case_out}/bulk/email.txt" 2>/dev/null | head -100 >> "#{case_out}/receipts/08.txt" 2>&1
  expect: EXFIL/C2 targets carved image-wide regardless of FS — URLs/domains/IPs (C2 servers, upload endpoints), email addresses and credit-card/PII features (the data class taken); a recurring external IP/domain that also appears in step 7 memory = the confirmed C2/exfil channel
  check: |
    test -d "#{case_out}/bulk" && test -s "#{case_out}/receipts/08.txt"
  falsify: no external URL/domain/IP or PII features anywhere on the image — no carved C2/exfil indicators (the channel may be encrypted/removable and invisible to feature carving)
  on_result: {expect_met: record C2/exfil domains+IPs and the data class as IOCs; cross-check against step 7; goto 9, falsify_met: record "no carved exfil features"; if removable-media exfil is suspected lean on USBSTOR (step 5) + LNK volume serials (step 6); pivot insider-threat-data-theft, neither: re-run bulk_extractor on the memory image too; grep the specific feature file (telephone/json) the case needs}
  emits: [key_iocs, exfil_or_encryption_facts]
  serves: [command-and-control-beacon-or-cradle, exfiltration-over-c2-or-web-or-removable, collection-staging-archive-of-data]
  provenance: {receipt_id: 08, artifact: bulk_extractor feature files (url/domain/ccn/email), offset_or_row: feature file line + image byte offset, literal_cited: C2/exfil domain or PII feature string}

- n: 9
  precondition: "exists #{case_out}/super.csv"
  tool: |
    grep -E ",1102,|,104,|,4719,|,1100," "#{case_out}/events.csv" > "#{case_out}/receipts/09.txt" 2>&1 ; awk -F',' 'NR==1 || $0 ~ /timestomp|0x10|0x30/' "#{case_out}/mft.csv" | head -100 >> "#{case_out}/receipts/09.txt" 2>&1 ; psort.py -o l2tcsv "#{case_out}/case.plaso" 2>/dev/null | awk -F',' 'NR>1{print $1}' | sort -u | head -50 >> "#{case_out}/receipts/09.txt" 2>&1
  expect: ANTI-FORENSICS + the FUSED narrative — a 1102/104 log clear or 4719/1100 audit-disable near the activity; $SI-vs-$FN timestomp on attacker files; AND the full ordered chain (access → execution → persistence → priv-esc → discovery → cred-access → lateral → collection → C2 → exfil/impact) holding on one timeline with no unexplained gap; first-to-last attacker action = the dwell time
  check: |
    test -s "#{case_out}/receipts/09.txt" && test -s "#{case_out}/super.csv"
  falsify: the chain does NOT order coherently (e.g. exfil before any access) OR an unexplained multi-hour gap that no clearing event accounts for — the story is incomplete or host time is poisoned
  on_result: {expect_met: COMMIT the ATT&CK-mapped lifecycle narrative with a confidence label per node; compute dwell time; close per the gate, falsify_met: re-open the Theories table; a gap/inversion may be clock manipulation or missing logs — anchor ordering to EventRecordID / USN sequence not host time; pivot targeted-intrusion-apt if anti-forensics is heavy, neither: re-render psort.py scoped to #{time_window}; fill gaps from registry/$J/memory before committing}
  emits: [timeline_events, key_artifacts]
  serves: [defense-evasion-log-clear-or-timestomp, anti-forensics-gap-or-tamper-detection, timeline-correlation-cross-artifact, dwell-time-first-to-last-attacker-action]
  provenance: {receipt_id: 09, artifact: events.csv + mft.csv + case.plaso, offset_or_row: 1102/104 row or $SI/$FN mismatch + ordered super.csv chain, literal_cited: clear-event string or the ordered access→exfil/impact chain}

## Linux branch (L1..Ln) — REQUIRED, numbered, same step shape
- n: L1
  precondition: "os == linux"
  tool: |
    fsstat -o #{ntfs_offset_sectors} "#{image_path}" > "#{case_out}/receipts/L01.txt" 2>&1 ; find "#{mount_root}/var/log" -maxdepth 2 -type f 2>/dev/null >> "#{case_out}/receipts/L01.txt" ; ls "#{mount_root}/etc/cron.d" "#{mount_root}/etc/systemd/system" "#{mount_root}/var/log/journal" >> "#{case_out}/receipts/L01.txt" 2>&1
  expect: this image is Linux/ESXi (ext/xfs fsstat, /var/log present) — Windows EVTX/registry/Amcache do NOT exist here; the lifecycle lives in auth.log/secure (access/lateral), the systemd journal, wtmp/btmp, cron/systemd units (persistence), bash_history & staged tarballs (collection/exfil)
  check: |
    test -d "#{mount_root}/var/log" -o -n "$(grep -iE 'ext[234]|xfs' "#{case_out}/receipts/L01.txt" 2>/dev/null)"
  falsify: fsstat reports NTFS and a Windows\System32 tree exists — this is Windows, not Linux; run the main Windows Steps 1–9 instead
  on_result: {expect_met: goto L2, falsify_met: this is Windows — run the main branch (Steps 1–9) not this branch, neither: confirm OS family from the Step 0 fsstat/disktype receipt; if still ambiguous treat as Windows and run the main branch}
  emits: [key_artifacts]
  serves: [timeline-correlation-cross-artifact]
  provenance: {receipt_id: L01, artifact: file system + /var/log + cron/systemd listing, offset_or_row: fsstat header + dir listing, literal_cited: ext/xfs FS type or /var/log present (Linux-confirmed)}

- n: L2
  precondition: "os == linux"
  tool: |
    log2timeline.py --status_view none "#{case_out}/linux.plaso" "#{mount_root}/var/log" > "#{case_out}/receipts/L02.txt" 2>&1 ; psort.py -o l2tcsv "#{case_out}/linux.plaso" > "#{case_out}/linux_super.csv" 2>> "#{case_out}/receipts/L02.txt" ; srch_strings "#{mount_root}/var/log/auth.log" 2>/dev/null | grep -iE "accepted|failed password|sudo|new session" >> "#{case_out}/receipts/L02.txt" 2>&1
  expect: the Linux human-action spine ordered in the super-timeline — SSH "Accepted" (access/lateral) and "Failed password" bursts (brute force), sudo/su (priv-esc), inside #{time_window}; the journal adds service starts and the order to fuse with the rest of the chain
  check: |
    test -s "#{case_out}/linux_super.csv" -o -s "#{case_out}/receipts/L02.txt"
  falsify: /var/log empty or wiped (auth.log truncated to zero) — Linux anti-forensics; record the gap as a finding (no parser substitutes for deleted text logs)
  on_result: {expect_met: goto L3, falsify_met: record log-wipe/gap as a finding; carve deleted log fragments with srch_strings/bulk_extractor over unallocated; pivot linux-host-forensics, neither: widen #{time_window}; parse journald binary logs under /var/log/journal via log2timeline and re-render}
  emits: [actor_accounts, timeline_events]
  serves: [initial-access-phishing-or-exploit-landing, privilege-escalation-token-or-admin-assignment, lateral-movement-rdp-smb-network-logon, anti-forensics-gap-or-tamper-detection]
  provenance: {receipt_id: L02, artifact: /var/log/auth.log + systemd journal, offset_or_row: linux_super.csv rows / grep hits, literal_cited: Accepted/Failed password line + source IP}

- n: L3
  precondition: "os == linux"
  tool: |
    find "#{mount_root}/etc/cron.d" "#{mount_root}/etc/cron.daily" "#{mount_root}/var/spool/cron" "#{mount_root}/etc/systemd/system" -type f 2>/dev/null > "#{case_out}/receipts/L03.txt" 2>&1 ; find "#{mount_root}/root" "#{mount_root}/home" -maxdepth 3 \( -iname ".bash_history" -o -iname "*.tar" -o -iname "*.tar.gz" -o -iname "*.tgz" -o -iname "*.zip" \) 2>/dev/null >> "#{case_out}/receipts/L03.txt" 2>&1 ; find "#{mount_root}" -iname "pagefile.sys" -o -iname "swapfile" -exec /opt/page-brute/bin/page-brute -f {} \; >> "#{case_out}/receipts/L03.txt" 2>&1
  expect: PERSISTENCE + COLLECTION/C2 on Linux — attacker cron jobs / systemd units (persistence), staged tarballs/zips in /root or /home and suspicious bash_history commands (collection/exfil: curl/scp/wget to an external host), and any C2 strings carved from swap; tie each to the L2 logon window to complete the chain
  check: |
    test -s "#{case_out}/receipts/L03.txt"
  falsify: no attacker cron/systemd unit, no staged archive, no exfil command in history, no swap C2 strings — no persistence/collection/C2 evidenced on this Linux host
  on_result: {expect_met: COMMIT the Linux ATT&CK lifecycle with confidence labels; compute dwell time; close per the gate, falsify_met: record "no Linux persistence/collection"; rely on L2 logon evidence alone and label the chain single-source/inferred; pivot linux-host-forensics, neither: bulk_extractor the raw image for exfil URLs/IPs and re-check; widen #{time_window}}
  emits: [key_iocs, exfil_or_encryption_facts]
  serves: [persistence-service-task-runkey-wmi, collection-staging-archive-of-data, command-and-control-beacon-or-cradle, exfiltration-over-c2-or-web-or-removable]
  provenance: {receipt_id: L03, artifact: cron/systemd units + bash_history + staged archive + swap, offset_or_row: cron/unit file path / history line / archive name, literal_cited: cron line or exfil command or archive path string}

## Corroboration (two-source rule)
`required_sources: 2` · `pairs:`
- `[ initial-access first-seen file $MFT (step 2) ↔ super-timeline filestat/registry row for the same path/time (step 1) ]`
- `[ execution 4688 (step 4) ↔ UserAssist/BAM execution trace via RECmd/rip.pl (step 5) ]`
- `[ persistence 7045/4698 (step 4) ↔ Services/Run key in the hive (step 5) AND the binary's $MFT create time (step 2) ]`
- `[ logon/lateral 4624 type 3/10 (step 4) ↔ source-host network logon OR memory netscan session (step 7) ]`
- `[ C2 remote IP/domain in memory netscan (step 7) ↔ bulk_extractor url/domain feature for the same indicator (step 8) ]`
- `[ collection staged archive $MFT (step 3) ↔ USBSTOR/LNK removable access (step 5/6) for exfil ]`
- `[ anti-forensics 1102/104 clear (step 9) ↔ super-timeline gap / $SI-vs-$FN timestomp (step 9) ]`
- `[ Linux SSH logon auth.log (L2) ↔ cron/systemd persistence unit + staged tarball (L3) ]`

One hit is a *lead*; promote to *fact* only when its paired source agrees.

## Don't get fooled (red flags & anti-forensics)
- **Unconnected leads are not yet an intrusion.** A weird logon, a stray service and an odd file may be three coincidences. The lifecycle claim requires them to ORDER coherently on one timeline — build the super-timeline first, then test the ordering. Don't narrate a chain the timeline doesn't support.
- **Cleared logs (1102 / 104) are evidence, not absence.** A clearing event near the activity proves a deliberate operator — anchor the rest of the chain to it. A multi-hour gap with no clear-event (EventLog service stopped, auditing disabled via 4719) is silent tampering; anchor ordering to EventRecordID / USN sequence, not host time.
- **Amcache and ShimCache are NOT execution proof on modern Windows.** Post-Lagny, Amcache presence ≠ execution; ShimCache's execution bit is reliable only on XP/2003/Vista/7. Use them for presence/first-seen ORDERING, and get execution proof from UserAssist/BAM (RECmd/rip.pl) or 4688. There is no PECmd/SrumECmd on this box — do not claim a Prefetch/SRUM-based execution count.
- **Process-creation auditing (4688) and PowerShell logging are OFF by default.** No 4688/4104 does NOT mean nothing ran. Pivot to registry execution and $MFT; report the gap, never assume.
- **Timestomp breaks the timeline.** The dropped binary may show a backdated $SI time; compare $SI vs $FN with MFTECmd and trust $FN / journal / USN order. If the timeline is internally impossible, host time is suspect.
- **bulk_extractor and page-brute carve features, not facts.** A carved URL/IP is a lead until corroborated by a live process (memory netscan) or a connection log. A YARA hit in pagefile means a string was in RAM, not that THIS process used it.
- **Dwell-time depends on the EARLIEST true attacker action.** If you anchor on the first event you happened to find rather than the actual initial access, the dwell estimate is wrong. Push the anchor back until the prior history is clean. **Missing evidence is itself a finding.**

## Failure modes
```
- mode: evidence-access failure — the disk won't mount or the artifact tree is unreadable
  guard: Step 0 fallback chain — ewfmount/loop RO, else TSK fls/icat the .evtx/hive/$MFT inodes into #{case_out}/extracted; if all fail, record acquisition failure and pivot acquisition-custody
- mode: primary-artifact-absent — no super-timeline parses (log2timeline finds nothing) or a whole modality (logs / registry / memory) is missing
  guard: record the absence as a finding; build the fast fallback (fls -m bodyfile + mactime, or MFTECmd sorted) and name the secondary sources for each missing modality (registry for execution, $J for file history, bulk_extractor for C2) — never narrate a chain past a gap silently
- mode: tool-output drift — EvtxECmd/MFTECmd/RECmd CSV columns change or a comma-in-field breaks a grep/awk literal so check exits 2
  guard: on check exit 2, adjudicate from the prose expect/falsify against the receipt, cap confidence at inferred; fall back to raw evtxexport / evtx_dump.py XML or amcache.py/rip.pl, never silently pass
- mode: memory profile/symbol mismatch — vol returns empty because the symbols did not match the image
  guard: confirm the profile matched before trusting an empty result; for Linux memory ⚠️verify the symbol table; if memory is unusable carve C2 from pagefile (page-brute) and bulk_extractor instead
- mode: clock manipulation / timestomp — the fused timeline orders impossibly
  guard: anchor ordering to monotonic EventRecordID / USN sequence numbers and $FN times rather than host TimeCreated; flag the clock anomaly as a finding
```
Minimum set every playbook covers: evidence-access failure (Step 0 fallback chain) · primary-artifact-absent (absence recorded, secondary source named) · tool-output drift (`check` exits 2 → prose adjudication, never silent pass).

## Confidence labeling (observation → inference → conclusion)
- **confirmed:** direct receipt verbatim at a node (e.g. the 4624 row, the $MFT create time) + ≥2 independent sources agree (event log + registry/$MFT/memory) + the node orders coherently on the timeline + no unrefuted counter-theory.
- **inferred:** grounded but single-source/interpretive — e.g. an Amcache/ShimCache presence read as execution (it is NOT — hold here), a 7045 with no registry/$MFT corroboration yet, a carved bulk_extractor URL with no live-process match, a timeline gap read as clearing → hedge and tag `⚠️verify`. Every `check`-exit-2 adjudication lands here at best.
- **insufficient_evidence:** precondition unmet (a modality absent, auditing off, no RAM image) or the chain does not order coherently → abstain; state what's missing, do not guess a lifecycle stage.

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
- **Windows:** fully covered above — the super-timeline fuses EVTX (human actions), registry (execution/persistence), $MFT/$J (file lifecycle), memory (C2/live process) and carved features (exfil targets) into one ATT&CK-mapped chain.
- **Linux/ESXi:** no EVTX/registry/Amcache — see the numbered Linux branch (L1–L3). Equivalents: `auth.log`/`secure` (logon/lateral), the systemd journal, `wtmp`/`btmp`, `sudo` (priv-esc), cron/systemd units (persistence), `bash_history` + staged tarballs (collection/exfil). Auditd `audit.log` has no parser here — read as text (`srch_strings`/grep for `type=EXECVE`), `⚠️verify`.
- **macOS:** no EVTX — the lifecycle lives in plists/login-items (persistence), `fseventsd` (file lifecycle), the Unified Log (logon/exec) and BSM audit. This box has **no working Unified-Log parser** (`⚠️verify` — degraded), so an empty unified-log result ≠ "no activity." Use `log2timeline.py` for plist/fseventsd/utmpx where it works; treat findings as lead-only and pivot macos-forensics.
- **Cloud:** no host disk — the lifecycle analog is the identity/control-plane audit trail (sign-in → role-assignment → resource-create → data-access → log-deletion). This box has **no dedicated cloud-log parser** (`⚠️verify`); investigate from *exported* JSON already on disk by grepping with `bulk_extractor`/`srch_strings`, lead-only until validated off-box. Pivot cloud-identity-saas or cloud-iaas-control-plane.

## Real-case notes (non-obvious things to look for)
- **The super-timeline IS the synthesis; build it before you theorize.** Most lifecycle errors come from narrating a chain the timeline doesn't support. `log2timeline.py` over-collects — render with `psort.py` scoped to the window and confirm with `pinfo.py` which parsers actually fired; a missing parser is a silent blind spot, not "nothing there." `[SANS FOR508 super-timeline practice · high]`
- **Initial access is often credential-only — no dropped file.** Targeted intruders frequently enter with stolen creds over RDP/VPN, leaving NO malware on disk at entry; the earliest artifact is then a logon, not a file. Don't anchor dwell-time on the first binary you find — push back to the first anomalous logon. `[MITRE T1078 Valid Accounts · high]`
- **PsExec-style lateral movement drops a transient service on the TARGET.** A 7045 with an ImagePath in `%TEMP%`/`\Users\Public\` plus a 4624 type 3 + 4672 moments before is the lateral hop; correlate BOTH hosts' logs, and the matching outbound logon on the source host. `[MITRE T1021.002 / T1569.002 · high]`
- **Collection shows up as a staged archive before exfil.** A large `.7z`/`.rar`/`.zip` created under a user or temp path shortly before an outbound transfer is the classic stage-then-exfil pattern; its `$MFT` create time brackets the collection window. `[MITRE T1560 Archive Collected Data · high]`
- **C2 frequently lives only in volatile memory.** Beaconing implants may leave nothing persistent on disk; `vol windows.netscan` recovers the live socket and remote IP, and `page-brute` (python3-yara) carves the C2 domain/encoded cradle from `pagefile.sys` when no RAM image was captured. `[MITRE T1071 / general DFIR practice · med]`
- **Sophisticated operators clear logs WITHOUT a 1102.** They stop the EventLog service or disable auditing, so there is no clear-event — but the **EventRecordID sequence breaks** and a **TimeCreated gap** appears. Test record-ID continuity per file and treat the gap as the anti-forensics finding. `[SANS FOR508 / general DFIR anti-forensics · high]`
- **Distrust host time across the whole chain.** Actors time intrusions for off-hours and some manipulate the clock; if the fused order is internally impossible, anchor to monotonic EventRecordID within each EVTX file and USN/journal sequence numbers rather than TimeCreated. `⚠️verify any timeline keyed purely to host clock.` `[general DFIR anti-forensics practice · med]`

## ATT&CK mapping
- TA0001 / T1566 · Initial Access · Phishing — dropped attachment/link first-seen on disk (step 2) — and T1190 Exploit Public-Facing Application / T1078 Valid Accounts (creds-only entry)
- T1078 · Initial Access/Defense Evasion/Lateral · Valid Accounts · 4624 logon with stolen creds — steps 2/4
- T1190 · Initial Access · Exploit Public-Facing Application · first-seen webshell/payload on an internet-facing host — step 2
- T1204 · Execution · User Execution · the dropped file run by the user — steps 2/4
- T1059.001 / T1059.003 / T1059.004 · Execution · PowerShell / cmd / Unix shell · 4688 command line, bash_history — steps 4/L3
- T1543.003 · Persistence/Priv-Esc · Windows Service · 7045 + Services hive — steps 4/5
- T1053.005 · Persistence/Execution · Scheduled Task · 4698 / TaskScheduler Operational — step 4
- T1547.001 · Persistence · Registry Run Keys · Run key via RECmd — step 5
- T1546.003 · Persistence · WMI Event Subscription · WMI-Activity Operational — step 4
- T1053.003 · Persistence · Cron · attacker cron job — step L3
- T1543.002 · Persistence · systemd Service · attacker systemd unit — step L3
- T1134 / T1548 · Privilege Escalation · Token Manipulation / sudo · 4672/4648, sudo — steps 4/5/L2
- T1070.001 · Defense Evasion · Clear Windows Event Logs · 1102 (Security) / 104 (System) — step 9
- T1562.002 · Defense Evasion · Disable Windows Event Logging · 1100 / 4719 — step 9
- T1070.006 · Defense Evasion · Timestomp · $SI vs $FN on attacker files — steps 3/9
- T1003 · Credential Access · OS Credential Dumping · LSASS/hive access (memory/registry traces) — steps 5/7
- T1087 / T1083 · Discovery · Account / File-and-Directory Discovery · LNK/ShellBag access trail — step 6
- T1021.001 / T1021.002 · Lateral Movement · RDP / SMB Admin Shares · 4624 type 10/3 + 7045 on target — steps 4/7
- T1560 · Collection · Archive Collected Data · staged .7z/.zip/.tar.gz in $MFT — steps 3/L3
- T1071 · Command and Control · Application Layer Protocol · memory netscan socket + carved C2 domain — steps 7/8
- T1041 / T1567 / T1052 · Exfiltration · Over C2 / Web Service / Removable Media · bulk_extractor URLs, USBSTOR/LNK volume serials — steps 5/6/8
- T1486 · Impact · Data Encrypted for Impact · mass-rename burst + ransom note — step 3
- T1485 · Impact · Data Destruction · wiper-driven mass deletion — step 3

## Pivots (lead-to-lead graph)
- `on_initial_access_phishing_or_maldoc (step 2): browser-email-documents — triage the phishing email / malicious document that delivered the dropper`
- `on_first_seen_payload_binary (step 2/6): malware-analysis-triage — static/behavioral triage of the dropped executable`
- `on_execution_or_persistence_in_registry (step 5): windows-registry-persistence — confirm the autorun/service in the hive`
- `on_execution_trace_off_log (step 5/6): windows-execution-artifacts — corroborate via UserAssist/BAM/LNK/Jump Lists`
- `on_event_log_chain (step 4): windows-event-logs — deep-dive the logon/service/clearing events`
- `on_lateral_or_credential_movement (step 4 type 3/10 + 4672): active-directory-domain — domain credential theft / Kerberos abuse and the multi-host hop chain`
- `on_c2_socket_or_beacon (step 7/8): network-forensics — analyze the C2 channel in any captured pcap/flow`
- `on_volatile_only_evidence (step 7): memory-forensics — full memory triage for injection/rootkit/C2`
- `on_staged_archive_or_removable_exfil (step 3/5/8): insider-threat-data-theft — prove the data-theft/exfil path`
- `on_mass_encryption_or_wiper (step 3): ransomware-destructive — scope encryption/impact and recoverability`
- `on_heavy_anti_forensics_long_dwell (step 9): targeted-intrusion-apt — APT tradecraft and deep anti-forensics`
- `on_log_clear_or_unexplained_gap (step 9): SELF — re-enter with the clearing timestamp bound into #{time_window} to bracket what was hidden`
- `on_evidence_unmountable (step 0/1): acquisition-custody — re-acquire or prove the collection gap`

## Jargon decoder
- **Lifecycle / kill chain:** the ordered phases of an intrusion (initial access → execution → persistence → privilege escalation → defense evasion → credential access → discovery → lateral movement → collection → command-and-control → exfiltration → impact).
- **ATT&CK / T-code / tactic:** MITRE's catalog of attacker techniques; a `T####` is one technique, a tactic is the goal it serves (e.g. Persistence). This playbook tags each timeline node with its T-code.
- **Super-timeline:** one merged chronology across many artifacts, built with `log2timeline.py` (collect) + `psort.py` (render) + `pinfo.py` (which parsers ran).
- **Bodyfile / mactime:** a `fls`-produced intermediate listing of MAC times; `mactime` turns it into a readable filesystem timeline (the fast-path alternative to a full super-timeline).
- **$MFT / $SI vs $FN:** the NTFS Master File Table and the two timestamp sets in a file record; `$SI` is easy to forge, `$FN` harder — disagreement hints at **timestomp**.
- **$UsnJrnl:$J (USN journal):** the NTFS change journal — records file create/rename/delete history even for files no longer present.
- **EVTX / EID / LogonType:** Windows event-log file / numeric event type (4624 = logon) / how the logon happened (2 console, 3 network, 10 RDP).
- **UserAssist / BAM / DAM:** registry traces of programs a user/system actually ran — execution evidence and the off-log corroboration for a 4688.
- **Amcache / ShimCache (AppCompatCache):** registry inventories of binaries seen on disk — PRESENCE/first-seen evidence, NOT execution proof on modern Windows.
- **Prefetch / SRUM:** Windows execution/resource artifacts — **no parser on this box** (no PECmd/SrumECmd); not used here.
- **netscan / pslist / svcscan:** Volatility 3 plugins listing live network sockets / processes / services from a RAM image.
- **page-brute:** a YARA-over-pagefile carver (uses the python3-yara library, since there is no `yara` CLI on this box) — finds strings that were in RAM and spilled to swap.
- **bulk_extractor:** a filesystem-independent feature carver — pulls URLs, domains, IPs, emails, credit-card numbers and search terms from anywhere on the image.
- **C2 (command-and-control):** the attacker's remote server the implant talks to; the beacon/cradle is how it phones home.
- **Dwell time:** the elapsed time from the first attacker action (initial access) to the last — a key incident metric.
- **wtmp / btmp / auth.log (Linux):** the logon / bad-logon / SSH-auth logs — the Linux analogs of 4624/4625.
- **fseventsd / Unified Log (macOS):** the file-change journal / system log — the macOS analogs of $J and EVTX.

## Tuning log (append-only — the eval loop writes here; humans never edit rows)
| date | case_id | bucket missed | delta applied |
|---|---|---|---|
