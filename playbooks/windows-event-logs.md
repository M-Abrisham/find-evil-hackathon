---
attack_type: windows-event-logs
category_id: windows-event-logs
name: Windows Event Logs (EVTX/ETW)
description: logons, lateral movement, service installs, scheduled tasks, and log clearing read from Windows event logs
version: 1
os_coverage: [windows, linux, macos, cloud]
sub_types_covered: 15
sub_types:
  - successful-logon-4624
  - failed-logon-4625
  - special-privileges-logon-4672
  - rdp-interactive-logon-4624-type-10
  - network-logon-4624-type-3
  - explicit-credential-logon-4648
  - process-creation-4688
  - service-install-7045
  - scheduled-task-created-4698
  - scheduled-task-action-taskscheduler-operational
  - security-log-cleared-1102
  - system-log-cleared-104
  - account-lockout-and-management-4720-4724-4725-4732
  - powershell-scriptblock-4104
  - wmi-activity-operational-5857-5858-5861
validated_on: []
maturity: draft
variables:
  image_path:
    default: /cases/active/evidence/disk.E01
    derive: "Step 0 — first disk-evidence image (E01/dd/raw/vmdk) enumerated under the evidence directory named in the case brief"
  mount_root:
    default: /cases/active/mount
    derive: "Step 0 — directory where the file system is mounted READ-ONLY (or where icat-extracted .evtx files land when mounting fails)"
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
Windows keeps a running diary of who logged in, what programs started, which services and scheduled tasks were installed, and when someone wiped that diary. This playbook reads those diary files (the event logs) to prove who did what, when, and from where.

## Use this when (triggers)
- You need to know **who logged on** to a host, from where, and how (console, Remote Desktop, over the network, or with explicit credentials).
- There are signs of **lateral movement** — the same account or workstation hopping between machines, or network logons (type 3) from internal hosts.
- A **new service** or a **scheduled task** appeared and you want to know when it was installed and by whom (classic persistence).
- A program ran and you want the **process-creation** record (path + command line) with a timestamp.
- The **logs themselves were cleared** (a sudden gap, a "log was cleared" event), or audit settings changed — anti-forensics that is itself a finding.
- You need a precise **timeline** anchored to attacker-controlled host activity (PowerShell, WMI, account changes).

## Quick path (the 90% case)
1. **Timeline-first.** Pull every `.evtx` from `#{mount_root}` and render them into one sorted CSV with `EvtxECmd` (or fold them into a super-timeline with `log2timeline.py` + `psort.py`). Skim it inside `#{time_window}` BEFORE committing to any story — the order of logon → service/task install → execution → log clear is the case.
2. **Find the entry.** In the Security log look for `4624` (logon) — note the **LogonType** (2 console, 3 network, 10 RDP) and source IP/workstation — and the `4625` failure bursts that precede a brute-forced success.
3. **Find the foothold.** System `7045` (service installed) and Security `4698` / Task-Scheduler Operational (scheduled task created) name the persistence; Security `4688` (process creation) gives the binary path + command line if process auditing was on.
4. **Find the cover-up.** Security `1102` and System `104` are "log was cleared" — and a **gap** with no events is itself the finding. Cross-check the EVTX `EventRecordID` sequence for a discontinuity.
5. **Corroborate execution off the log.** A 4688/7045 path should also appear in registry execution/persistence traces (`RECmd`/`rip.pl` — UserAssist/BAM, Run keys, Services) and on disk (`MFTECmd`). One log line is a lead, not a fact.

If logons, a persistence install, an execution, and (if present) a clearing event all line up on one timeline with a corroborating second source → you're mostly done. Otherwise drop into the full Steps.

## How it unfolds (the story)
An actor reaches the host — often a Remote-Desktop logon (4624 type 10) after a spray of failures (4625), a network logon (type 3) using stolen credentials moving laterally from another box, or an explicit-credential run-as (4648). They escalate (a 4672 "special privileges" logon assigns admin rights), then nail down persistence by installing a service (7045) or a scheduled task (4698 / Task-Scheduler Operational 106/200), and run their tooling (4688 process creation; 4104 PowerShell script blocks; WMI-Activity 5857/5861). To slow responders they may clear the Security log (1102) or whole logs (104), disable auditing, or stop the event-log service — leaving a tell-tale gap. The whole sequence is reconstructable from the logs plus a corroborating artifact.

## Theories to test (and how to rule each out)
| Theory (who / why) | If true, you'd find… | Rule it out if… |
|---|---|---|
| **External-targeted (hands-on intruder via RDP/VPN)** | 4625 failure burst then a 4624 **type 10** from an external/unexpected IP; 4672 admin assignment; 7045/4698 persistence and 4688 tooling shortly after; possibly 1102 clear | No remote logon, no failure burst, no persistence install, no post-logon execution cluster |
| **Other-insider (compromised legit account / stolen creds)** | Valid account 4624 from an unusual IP/workstation or odd hour; 4648 explicit-credential use; same account fires 4688/7045; impossible-travel vs prior logons | Logon source, workstation and hours match the account's own baseline; no anomalous origin |
| **Insider (authorized admin acting maliciously)** | 4624 **type 2** local interactive by a real admin; 4672; tools launched from a user profile; account-management events (4720/4732) granting self rights | Account was logged on remotely from outside, or its credentials were proven stolen → reclassify other-insider |
| **Lateral movement (this host is a hop)** | Inbound 4624 **type 3** (network) or 4648 from another INTERNAL host; service created remotely (7045) by SYSTEM right after; matching logon on the source host's logs | Logon originates at the console (type 2) with no upstream network logon; no peer-host corroboration |
| **Supply-chain / RMM abuse** | 7045 service or 4698 task whose ImagePath/Action is an updater/RMM agent; same binary/task lands on many hosts simultaneously; parent process is a trusted updater | Persistence path is a user-dropped binary on this host only; no trusted-updater parent in 4688 |
| **Innocent / benign (NOT an attack)** | 4624 type 5 service logons, scheduled tasks created by Windows Update/SCCM, a 7045 from a signed vendor MSI, a 1102 from a sanctioned log-rotation/GPO; all inside business hours by expected accounts | A clear, sanctioned change-control record explains the service/task/clear AND the account+source are expected → benign cause confirmed; reclassify |

*(≥1 benign + ≥1 malicious, each ACTIVELY refuted. Attacker types mapped: insider · other-insider · external-commodity · external-targeted · supply-chain · innocent.)*

## Evidence → Tool → What it reveals (per OS)
| Evidence | SIFT tool | What it tells you *for this attack* | OS |
|---|---|---|---|
| `Security.evtx` (4624/4625/4672/4648 logons, 4688 process, 1102 cleared, 4720+ account mgmt) | `EvtxECmd` / `evtxexport` / `evtx_dump.py` | Who logged on, from where, with what privilege; what ran; whether the audit log was wiped (note: `evtxexport`/`evtx_dump.py` are raw exports with NO Event-ID labels — grep the XML; `EvtxECmd` adds EID maps) | Windows |
| `System.evtx` (7045 service install, 104 log cleared, 7034/7036 service state, 6005/6006 boot/shutdown) | `EvtxECmd` / `evtxexport` | New service persistence, whole-log clearing, the event-log service stopping (a clearing tell), uptime gaps | Windows |
| `Microsoft-Windows-TaskScheduler%4Operational.evtx` (106 created, 140 updated, 200/201 ran) | `EvtxECmd` | Scheduled-task persistence: created, modified, and each execution with the action path | Windows |
| `Microsoft-Windows-PowerShell%4Operational.evtx` (4104 script block, 4103 pipeline) | `EvtxECmd` | Deobfuscated PowerShell that ran (download cradles, encoded commands) | Windows |
| `Microsoft-Windows-WMI-Activity%4Operational.evtx` (5857/5858/5861) | `EvtxECmd` | WMI event-consumer persistence and provider load — a stealthy execution/persistence path | Windows |
| `Microsoft-Windows-TerminalServices-*%4Operational.evtx` (1149, 21/24/25) | `EvtxECmd` | RDP session connect/auth/reconnect detail to corroborate a 4624 type 10 | Windows |
| EVTX `EventRecordID` sequence (per file) | `EvtxECmd` / `evtx_dump.py` | A break in the monotonically increasing record IDs / a time gap = log tampering even without an explicit 1102/104 | Windows |
| NTUSER.DAT / SYSTEM / SOFTWARE hives | `RECmd` / `rip.pl` | UserAssist & BAM/DAM (programs a user ran), Run keys & Services (the persistence the 7045 installed) — corroborates execution off the log | Windows |
| `$MFT` / `$UsnJrnl:$J` | `MFTECmd` | The service/task binary's create time and on-disk presence; $SI/$FN timestomp on it | Windows |
| All artifacts fused | `log2timeline.py` + `psort.py` (+ `pinfo.py`) | One chronology that places logon → persistence → execution → clearing in order | all |
| RAM image (if captured) | `vol` (Volatility 3) | Live process matching a 4688/7045, service list (`svcscan`), and ETW/in-memory traces not yet flushed | Windows/Linux* |
| Image-wide string sweep | `bstrings` / `srch_strings` / `bulk_extractor` | Account names, IPs, and command fragments spilled outside the EVTX (e.g. in pagefile) | all |
| Linux auth/journal logs (no EVTX on Linux) | `fls`/`mactime`, `log2timeline.py` (syslog/utmp/journal), `srch_strings` | SSH "Accepted"/"Failed" logons, sudo, systemd-unit/cron persistence — the Linux equivalent of these events | Linux |

*Linux memory analysis in `vol` needs a matching symbol table — ⚠️verify availability before relying on it.*

## Step 0 — evidence inventory & access bootstrap
- n: 0
  tool: |
    mkdir -p "#{case_out}/receipts" "#{case_out}/extracted" && ls -laR "#{mount_root}" > "#{case_out}/receipts/00.txt" 2>&1 ; img_stat "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; mmls "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; fsstat -o #{ntfs_offset_sectors} "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; find "#{mount_root}" -iname "*.evtx" >> "#{case_out}/receipts/00.txt" 2>&1
  expect: every evidence file classified; #{image_path}, #{mount_root}, #{ntfs_offset_sectors}, #{case_out} bound; read-only access proven; the winevt\Logs directory and its .evtx files (Security/System/Application + Operational logs) are enumerated, or their absence is recorded
  check: |
    test -r "#{mount_root}" -o -n "$(ls "#{case_out}/extracted" 2>/dev/null)"
  falsify: evidence dir empty/unreadable, or no supported image format found, or no NTFS partition for fsstat
  on_result: {expect_met: goto 1, falsify_met: STOP — report acquisition/access failure; pivot acquisition-custody, neither: try the icat-extract fallback (fls to find winevt\Logs inodes, icat each .evtx into #{case_out}/extracted); if that also fails, treat as falsify_met}
  emits: [key_artifacts]
  serves: [successful-logon-4624, failed-logon-4625, special-privileges-logon-4672, rdp-interactive-logon-4624-type-10, network-logon-4624-type-3, explicit-credential-logon-4648, process-creation-4688, service-install-7045, scheduled-task-created-4698, scheduled-task-action-taskscheduler-operational, security-log-cleared-1102, system-log-cleared-104, account-lockout-and-management-4720-4724-4725-4732, powershell-scriptblock-4104, wmi-activity-operational-5857-5858-5861]
  provenance: {receipt_id: 00, artifact: evidence directory listing + winevt\Logs enumeration, offset_or_row: full listing, literal_cited: image filename + .evtx file list}

## Steps (executable — decision-driven)
- n: 1
  precondition: "os == windows; test -r #{mount_root}"
  tool: |
    dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll -d "#{mount_root}" --csv "#{case_out}" --csvf events.csv > "#{case_out}/receipts/01.txt" 2>&1
  expect: a single normalized CSV (#{case_out}/events.csv) covering Security/System/Application + Operational logs, with EventId, TimeCreated, Channel, MapDescription columns populated — the timeline-first artifact every later step filters
  check: |
    test -s "#{case_out}/events.csv" && grep -qiE "EventId|TimeCreated" "#{case_out}/events.csv"
  falsify: no .evtx found to parse, or EvtxECmd errors on every file (corrupt/locked logs)
  on_result: {expect_met: goto 2, falsify_met: fall back to raw export — evtxexport / evtx_dump.py per file into #{case_out}/extracted then grep the XML; if logs are absent record absence as a finding and pivot disk-filesystem, neither: re-run EvtxECmd per-file with -f on the specific Security.evtx/System.evtx; if maps are missing use evtxexport raw and grep EID strings}
  emits: [timeline_events]
  serves: [successful-logon-4624, failed-logon-4625, process-creation-4688, service-install-7045, scheduled-task-created-4698, security-log-cleared-1102, system-log-cleared-104]
  provenance: {receipt_id: 01, artifact: winevt\Logs\*.evtx, offset_or_row: events.csv header + row count, literal_cited: EvtxECmd processed-file count line}

- n: 2
  precondition: "exists #{case_out}/events.csv"
  tool: |
    grep -E ",4624," "#{case_out}/events.csv" > "#{case_out}/receipts/02.txt" 2>&1 ; grep -E ",4625," "#{case_out}/events.csv" >> "#{case_out}/receipts/02.txt" 2>&1
  expect: 4624 logon rows whose payload names LogonType (2 console / 3 network / 10 RDP), the account, and an IpAddress/WorkstationName; ideally a 4625 failure burst from one source preceding a 4624 success from that same source — a brute-force-then-in pattern, inside #{time_window}
  check: |
    grep -qE ",4624," "#{case_out}/receipts/02.txt"
  falsify: no 4624 at all (logon auditing off, or logs cleared), OR only expected type-5 service / scheduled-baseline logons by known accounts from known sources
  on_result: {expect_met: record account + source IP/workstation + LogonType; goto 3, falsify_met: if logon auditing is off or the Security log is empty note the gap and lean on 4648/RDP-Operational/registry — pivot active-directory-domain if this is a domain credential pattern, neither: widen #{time_window}; parse RDP TerminalServices Operational (1149/21/25) to recover the session another way}
  emits: [actor_accounts, timeline_events]
  serves: [successful-logon-4624, failed-logon-4625, rdp-interactive-logon-4624-type-10, network-logon-4624-type-3]
  provenance: {receipt_id: 02, artifact: Security.evtx, offset_or_row: events.csv 4624/4625 rows, literal_cited: LogonType + account + IpAddress string}

- n: 3
  precondition: "exists #{case_out}/events.csv"
  tool: |
    grep -E ",4672," "#{case_out}/events.csv" > "#{case_out}/receipts/03.txt" 2>&1 ; grep -E ",4648," "#{case_out}/events.csv" >> "#{case_out}/receipts/03.txt" 2>&1 ; grep -E ",4720,|,4724,|,4725,|,4732," "#{case_out}/events.csv" >> "#{case_out}/receipts/03.txt" 2>&1
  expect: 4672 "special privileges assigned" for the actor account near its logon (privileged session); 4648 explicit-credential (run-as) logons; account-management events (4720 created / 4724 password reset / 4725 disabled / 4732 added to admin group) showing privilege/persistence on the account itself
  check: |
    grep -qE ",4672,|,4648,|,4720,|,4724,|,4725,|,4732," "#{case_out}/receipts/03.txt"
  falsify: no 4672 for the actor (unprivileged session) AND no account-management events — escalation/credential abuse not evidenced here
  on_result: {expect_met: flag privileged/credential abuse; goto 4, falsify_met: record "no privilege escalation in the log"; continue to persistence at goto 4, neither: correlate with 4688 token/parent (step 5) and registry SAM/Groups; if domain accounts pivot active-directory-domain}
  emits: [actor_accounts, timeline_events]
  serves: [special-privileges-logon-4672, explicit-credential-logon-4648, account-lockout-and-management-4720-4724-4725-4732]
  provenance: {receipt_id: 03, artifact: Security.evtx, offset_or_row: events.csv 4672/4648/47xx rows, literal_cited: account + privilege/group string}

- n: 4
  precondition: "exists #{case_out}/events.csv"
  tool: |
    grep -E ",7045," "#{case_out}/events.csv" > "#{case_out}/receipts/04.txt" 2>&1 ; grep -E ",4698,|,4702," "#{case_out}/events.csv" >> "#{case_out}/receipts/04.txt" 2>&1 ; grep -E ",106,|,140,|,200,|,201," "#{case_out}/events.csv" >> "#{case_out}/receipts/04.txt" 2>&1
  expect: a System 7045 "service was installed" with a ServiceName + ImagePath in a suspicious location (\Users\, \ProgramData\, %TEMP%, \PerfLogs\) timed near the actor's logon; and/or a 4698/Task-Scheduler-Operational 106 "task created" whose Action launches a script/binary, with 200/201 showing it ran
  check: |
    grep -qE ",7045,|,4698,|,4702,|,106,|,200," "#{case_out}/receipts/04.txt"
  falsify: no 7045 service install AND no 4698/106 task create in #{time_window} — no event-logged persistence on this host
  on_result: {expect_met: record ServiceName/ImagePath or task Action as an IOC; goto 5, falsify_met: record "no event-logged persistence"; check registry Run/Services directly via RECmd/rip.pl then goto 5 — pivot windows-registry-persistence if the hive shows persistence the log missed, neither: parse the TaskScheduler Operational log per-file (EvtxECmd -f) and re-check; widen #{time_window}}
  emits: [key_iocs, timeline_events]
  serves: [service-install-7045, scheduled-task-created-4698, scheduled-task-action-taskscheduler-operational]
  provenance: {receipt_id: 04, artifact: System.evtx / TaskScheduler Operational.evtx, offset_or_row: events.csv 7045/4698/106 rows, literal_cited: ServiceName + ImagePath / task Action string}

- n: 5
  precondition: "exists #{case_out}/events.csv"
  tool: |
    grep -E ",4688," "#{case_out}/events.csv" > "#{case_out}/receipts/05.txt" 2>&1 ; grep -E ",4104,|,4103," "#{case_out}/events.csv" >> "#{case_out}/receipts/05.txt" 2>&1 ; grep -E ",5857,|,5858,|,5861," "#{case_out}/events.csv" >> "#{case_out}/receipts/05.txt" 2>&1
  expect: 4688 process-creation rows with NewProcessName + CommandLine (and ParentProcessName) for the tooling launched after the logon — ideally the same path as the 7045 ImagePath / 4698 Action; and/or 4104 PowerShell script blocks (encoded/download cradles); and/or WMI-Activity 5857/5861 consumer persistence
  check: |
    grep -qE ",4688,|,4104,|,5857,|,5861," "#{case_out}/receipts/05.txt"
  falsify: no 4688 (process-creation auditing off — common), no 4104 (script-block logging off), no WMI Operational events — execution not evidenced IN the logs
  on_result: {expect_met: record binary path + command line as IOCs; goto 6, falsify_met: process auditing likely off — corroborate execution off-log via RECmd/rip.pl UserAssist/BAM and MFTECmd on the 7045/4698 path (step 7) then goto 6; pivot windows-execution-artifacts, neither: parse the PowerShell/WMI Operational logs per-file and re-check; widen #{time_window}}
  emits: [key_iocs, timeline_events]
  serves: [process-creation-4688, powershell-scriptblock-4104, wmi-activity-operational-5857-5858-5861]
  provenance: {receipt_id: 05, artifact: Security.evtx / PowerShell Operational.evtx / WMI Operational.evtx, offset_or_row: events.csv 4688/4104/5857 rows, literal_cited: NewProcessName + CommandLine string}

- n: 6
  precondition: "exists #{case_out}/events.csv"
  tool: |
    grep -E ",1102," "#{case_out}/events.csv" > "#{case_out}/receipts/06.txt" 2>&1 ; grep -E ",104," "#{case_out}/events.csv" >> "#{case_out}/receipts/06.txt" 2>&1 ; grep -E ",1100,|,4719,|,7035,|,7036," "#{case_out}/events.csv" >> "#{case_out}/receipts/06.txt" 2>&1 ; for f in $(find "#{mount_root}" -iname "Security.evtx" -o -iname "System.evtx"); do dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll -f "$f" --csv "#{case_out}" --csvf "$(basename "$f").records.csv" >> "#{case_out}/receipts/06.txt" 2>&1 ; done
  expect: a 1102 "audit log was cleared" or System 104 "event log was cleared" near the actor activity; OR a 4719 audit-policy-change / 1100 event-service-shutdown; OR — even with NO clearing event — a break in EventRecordID continuity or a multi-hour TimeCreated gap straddling #{time_window} (silent tampering)
  check: |
    grep -qE ",1102,|,104,|,4719,|,1100," "#{case_out}/receipts/06.txt"
  falsify: logs are continuous across #{time_window} (monotonic EventRecordID, no gap), no clear/audit-change event — no anti-forensics on the event logs
  on_result: {expect_met: record log-clearing/tampering as a high-signal finding (deliberate operator); goto 7, falsify_met: record "logs continuous, no clearing"; goto 7, neither: inspect EventRecordID min/max per file in the .records.csv and flag any discontinuity as a finding; goto 7}
  emits: [key_artifacts, timeline_events]
  serves: [security-log-cleared-1102, system-log-cleared-104]
  provenance: {receipt_id: 06, artifact: Security.evtx / System.evtx, offset_or_row: events.csv 1102/104 rows or EventRecordID gap, literal_cited: "the cleared/security event message string or the record-id break"}

- n: 7
  precondition: "exists #{case_out}/events.csv; test -r #{mount_root}"
  tool: |
    dotnet /opt/zimmermantools/RECmd/RECmd.dll --bn /opt/zimmermantools/RECmd/BatchExamples/Kroll_Batch.reb -d "#{mount_root}" --csv "#{case_out}" --csvf reg.csv > "#{case_out}/receipts/07.txt" 2>&1 ; dotnet /opt/zimmermantools/MFTECmd.dll -f "#{mount_root}" --csv "#{case_out}" --csvf mft.csv >> "#{case_out}/receipts/07.txt" 2>&1
  expect: the service/task/process path from steps 4–5 ALSO appears in a registry source (UserAssist/BAM/DAM execution, a Run key, or the Services hive) and/or in the $MFT with a create time consistent with the logon window — a second, independent source for the event-log claim (two-source rule)
  check: |
    test -s "#{case_out}/reg.csv" -o -s "#{case_out}/mft.csv"
  falsify: the binary/task path appears in NO registry execution/persistence source AND is absent from the $MFT — the event-log line stands alone (single-source, hold at inferred)
  on_result: {expect_met: promote the corroborated finding to confirmed; goto 8, falsify_met: keep the finding at inferred/single-source; note the missing corroboration; goto 8, neither: run rip.pl -r against the specific SYSTEM/SOFTWARE/NTUSER hive for services/run/userassist and re-check; pivot windows-registry-persistence}
  emits: [key_artifacts, key_iocs]
  serves: [service-install-7045, process-creation-4688, scheduled-task-created-4698]
  provenance: {receipt_id: 07, artifact: SYSTEM/SOFTWARE/NTUSER hive + $MFT, offset_or_row: reg.csv key row / mft.csv create-time row, literal_cited: "matching path + UserAssist/Service value or $MFT Created0x10"}

- n: 8
  precondition: "exists #{case_out}/events.csv"
  tool: |
    log2timeline.py --status_view none "#{case_out}/events.plaso" "#{mount_root}" > "#{case_out}/receipts/08.txt" 2>&1 ; psort.py -o l2tcsv "#{case_out}/events.plaso" > "#{case_out}/super.csv" 2>> "#{case_out}/receipts/08.txt" ; pinfo.py "#{case_out}/events.plaso" >> "#{case_out}/receipts/08.txt" 2>&1
  expect: a fused super-timeline placing entry (4624/4625) → privilege (4672/4648) → persistence (7045/4698) → execution (4688/4104) → clearing (1102/104) in a coherent order with no unexplained gap, inside #{time_window}
  check: |
    test -s "#{case_out}/super.csv" && grep -qiE "winevtx|evtx" "#{case_out}/super.csv"
  falsify: ordering is impossible (e.g. execution precedes any logon) OR an unexplained multi-hour gap that no clearing event accounts for
  on_result: {expect_met: COMMIT the conclusion with a confidence label; close per the gate, falsify_met: re-open the Theories table; the gap/inversion may indicate clock manipulation or missing logs — anchor to EventRecordID order instead of host time, neither: run pinfo.py to confirm the winevtx parser ran; re-filter psort.py to #{time_window} and re-check}
  emits: [timeline_events]
  serves: [successful-logon-4624, service-install-7045, process-creation-4688, security-log-cleared-1102]
  provenance: {receipt_id: 08, artifact: events.plaso super-timeline, offset_or_row: super.csv ordered rows, literal_cited: "ordered logon→persistence→execution→clear chain"}

## Linux branch (L1..Ln) — REQUIRED, numbered, same step shape
- n: L1
  precondition: "os == linux"
  tool: |
    fsstat -o #{ntfs_offset_sectors} "#{image_path}" > "#{case_out}/receipts/L01.txt" 2>&1 ; find "#{mount_root}/var/log" -maxdepth 2 -type f 2>/dev/null >> "#{case_out}/receipts/L01.txt" ; ls "#{mount_root}/var/log/journal" >> "#{case_out}/receipts/L01.txt" 2>&1
  expect: this image is Linux (ext/xfs fsstat, /var/log present) — Windows EVTX/ETW do NOT exist here; the equivalent events live in auth.log/secure (SSH logons), the systemd journal, wtmp/btmp, and cron/systemd units
  check: |
    test -d "#{mount_root}/var/log" -o -n "$(grep -iE 'ext[234]|xfs' "#{case_out}/receipts/L01.txt" 2>/dev/null)"
  falsify: fsstat reports NTFS and a Windows\System32\winevt\Logs tree exists — this is Windows, not Linux; the EVTX path applies (return to Step 1)
  on_result: {expect_met: goto L2, falsify_met: this is Windows — run the main Windows Steps 1–8 not this branch, neither: confirm OS family from Step 0 fsstat/disktype receipt; if still ambiguous treat as Windows and run the main branch}
  emits: [key_artifacts]
  serves: [successful-logon-4624, failed-logon-4625]
  provenance: {receipt_id: L01, artifact: file system + /var/log listing, offset_or_row: fsstat header + dir listing, literal_cited: "ext/xfs FS type or /var/log present (Linux-confirmed)"}

- n: L2
  precondition: "os == linux"
  tool: |
    log2timeline.py --status_view none "#{case_out}/linux.plaso" "#{mount_root}/var/log" > "#{case_out}/receipts/L02.txt" 2>&1 ; psort.py -o l2tcsv "#{case_out}/linux.plaso" > "#{case_out}/linux_super.csv" 2>> "#{case_out}/receipts/L02.txt" ; srch_strings "#{mount_root}/var/log/auth.log" 2>/dev/null | grep -iE "accepted|failed password|sudo|new session" >> "#{case_out}/receipts/L02.txt" 2>&1
  expect: SSH "Accepted password/publickey" (logon = 4624 analog) and "Failed password" bursts (=4625), sudo escalation (=4672/4648), plus systemd-unit/cron additions (=7045/4698 persistence analog) and any wtmp/btmp logon records — ordered in the super-timeline inside #{time_window}
  check: |
    test -s "#{case_out}/linux_super.csv" -o -s "#{case_out}/receipts/L02.txt"
  falsify: /var/log empty or wiped (auth.log truncated to zero) — Linux anti-forensics; record the gap as a finding (no parser substitutes for deleted text logs)
  on_result: {expect_met: record account + source IP + persistence unit; commit with confidence label, falsify_met: record log-wipe/gap as a finding; carve deleted log fragments with srch_strings/bstrings over unallocated; pivot linux-host-forensics, neither: widen #{time_window}; check journald binary logs under /var/log/journal via log2timeline and re-render}
  emits: [actor_accounts, timeline_events]
  serves: [successful-logon-4624, failed-logon-4625, service-install-7045]
  provenance: {receipt_id: L02, artifact: /var/log/auth.log + journal, offset_or_row: linux_super.csv rows / grep hits, literal_cited: "Accepted/Failed password line + source IP"}

## Corroboration (two-source rule)
`required_sources: 2` · `pairs:`
- `[ Security 4624 logon (step 2) ↔ TerminalServices/RDP Operational 1149/21 OR source-host network logon (step 2/lateral) ]`
- `[ 4625 failure burst (step 2) ↔ the following 4624 success from the same source IP (step 2) ]`
- `[ System 7045 service install (step 4) ↔ Services hive / Run key via RECmd-rip.pl (step 7) ]`
- `[ 4698/106 scheduled task (step 4) ↔ the task Action binary's $MFT create time (step 7) ]`
- `[ Security 4688 execution (step 5) ↔ UserAssist/BAM execution trace (step 7) ]`
- `[ 1102/104 clearing (step 6) ↔ EventRecordID discontinuity / TimeCreated gap (step 6) ]`
- `[ event-log chronology (step 1) ↔ fused super-timeline order (step 8) ]`

One hit is a *lead*; promote to *fact* only when its paired source agrees.

## Don't get fooled (red flags & anti-forensics)
- **Cleared logs (1102 / 104) are evidence, not absence.** A clearing event near the activity proves a deliberate operator — don't read the silence as "nothing happened." Treat the gap itself as a finding and anchor everything else to it.
- **Silent tampering with no 1102.** An attacker can stop the EventLog service, disable auditing (4719 audit-policy-change), or export-and-delete without firing 1102. Check **EventRecordID continuity** and **TimeCreated gaps** per file — a non-monotonic record ID or an unexplained hour-long gap is tampering even with no explicit clear event.
- **Process-creation auditing is OFF by default.** No 4688 does NOT mean nothing ran. Pivot to registry UserAssist/BAM (RECmd/rip.pl) and $MFT; report the gap, never assume.
- **Command-line capture is a separate GPO.** A 4688 may exist with an EMPTY command line if `ProcessCreationIncludeCmdLine` was off — don't conclude "ran with no arguments."
- **LogonType matters more than the account.** A 4624 by a valid admin from an external IP via **type 10** (RDP) or **type 3** (network) is very different from **type 2** (console). Always read the type and source, not just the username.
- **4634/4647 logoff and 4624 type 5 service logons are noise** that inflate counts — filter to interactive/network/RDP before claiming a session.
- **Timestomp on the persistence binary.** The 7045 ImagePath file may show a backdated $SI time; compare $SI vs $FN with MFTECmd and trust EventRecordID/journal order over host time.
- **Wiper/clock tricks poison host time.** If the timeline is internally impossible, anchor to EventRecordID sequence (monotonic within a file) rather than TimeCreated. **Missing evidence is itself a finding.**

## Failure modes
```
- mode: evidence-access failure — the disk won't mount or winevt\Logs is unreadable
  guard: Step 0 fallback chain — ewfmount/loop RO, else TSK fls/icat the .evtx inodes into #{case_out}/extracted; if all fail, record acquisition failure and pivot acquisition-custody
- mode: primary-artifact-absent — Security.evtx/System.evtx missing, empty, or zero-length (cleared or never collected)
  guard: record the absence as a finding (it IS evidence of clearing); name the secondary sources (registry UserAssist/BAM, $MFT, RDP/PowerShell Operational logs, super-timeline) and pivot windows-registry-persistence / windows-execution-artifacts
- mode: tool-output drift — EvtxECmd map/CSV column names change, or a comma-in-field breaks a grep literal so check exits 2
  guard: on check exit 2, adjudicate from the prose expect/falsify against the receipt, cap confidence at inferred; fall back to raw evtxexport / evtx_dump.py XML and grep the EventID/<Data Name=...> directly, never silently pass
- mode: corrupt/locked EVTX — EvtxECmd errors on a file (dirty log, partial write)
  guard: re-run with -f per file; if still corrupt, evtxexport the raw chunks and parse what survives; note the corrupt file and its record range as a finding
- mode: auditing disabled — no 4688/4104/4624 because the relevant GPO was off
  guard: do not infer "nothing happened"; corroborate off-log (registry, $MFT, memory svcscan) and report the auditing gap explicitly
```
Minimum set every playbook covers: evidence-access failure (Step 0 fallback chain) · primary-artifact-absent (absence recorded, secondary source named) · tool-output drift (`check` exits 2 → prose adjudication, never silent pass).

## Confidence labeling (observation → inference → conclusion)
- **confirmed:** direct receipt verbatim (e.g. the 4624 row) + ≥2 independent sources agree (event log + registry/$MFT or RDP-Operational) + no unrefuted counter-theory.
- **inferred:** grounded but single-source/interpretive — e.g. a 7045 with no registry/$MFT corroboration yet, an EventRecordID gap read as clearing, or BAM coverage on newer Win10/11 unverified → hedge and tag `⚠️verify`. Every `check`-exit-2 adjudication lands here at best.
- **insufficient_evidence:** precondition unmet (logs absent; auditing off; no RAM image) or sources conflict → abstain; state what's missing, do not guess.

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
- **Windows:** fully covered above — EVTX is the richest source for logon/lateral/persistence/clearing, with ETW Operational channels (TaskScheduler/PowerShell/WMI/TerminalServices) adding detail.
- **Linux/ESXi:** no EVTX or ETW — see the numbered Linux branch (L1–L2). Equivalents: `auth.log`/`secure` (SSH logons = 4624/4625), `sudo` (=4672/4648), the systemd journal under `/var/log/journal` (parse with `log2timeline.py`), `wtmp`/`btmp` (logon/bad-logon records), and cron/systemd units (=7045/4698 persistence). Auditd `audit.log` has no parser on this box — read it as text (`srch_strings`/grep for `type=EXECVE`), `⚠️verify`.
- **macOS:** no EVTX — logons/auth live in the Apple System Log and the Unified Log (`.tracev3`). This box has **no working Unified-Log parser** (`⚠️verify` — degraded), so an empty unified-log result ≠ "no activity." Use `log2timeline.py` for ASL/utmpx/plist where it works; treat findings as lead-only.
- **Cloud:** no host EVTX — the analog is the identity/control-plane audit log (sign-in/audit, CloudTrail). This box has **no dedicated cloud-log parser** (`⚠️verify`); investigate from *exported* JSON already on disk by grepping with `bstrings`/`srch_strings` for sign-in/role-assignment/log-deletion events — lead-only until validated off-box. Pivot cloud-identity-saas.

## Real-case notes (non-obvious things to look for)
- **A cleared Security log with NO 1102 is the loud finding.** Sophisticated operators stop the EventLog service or disable auditing rather than fire `wevtutil cl`, so there is no clear-event — but the **EventRecordID sequence breaks** and a **TimeCreated gap** appears. Always test record-ID continuity per file, not just for a 1102/104. `[SANS FOR508 / general DFIR practice · high]`
- **Type 3 network logons are the lateral-movement breadcrumb.** Inbound 4624 **type 3** (and 4672 right after) from another internal host, with a matching outbound logon on the source machine, traces the hop chain; pass-the-hash/over-pass-the-hash often show NTLM auth on type 3 with a mismatch between the named account and the workstation. Correlate both hosts' Security logs, not one. `[Microsoft logon-type docs / MITRE T1021 · high]`
- **7045 is per-host and easy to miss on the DC vs the victim.** PsExec-style lateral movement drops a transient service (e.g. `PSEXESVC`) that fires 7045 on the *target*; the matching 4624 type 3 + 4672 appears moments before. A 7045 with an ImagePath in `%TEMP%`/`\Users\Public\` or a random-named service is high-signal. `[MITRE T1569.002 / T1543.003 · high]`
- **Scheduled-task persistence hides in the Operational log, not just Security 4698.** `Microsoft-Windows-TaskScheduler%4Operational` events 106 (created), 140 (updated), 200/201 (action ran) survive even when Security task-auditing is off, and a blank-named or single-run task launching `powershell`/`cmd` is a classic foothold. `[MITRE T1053.005 · high]`
- **PowerShell 4104 script blocks can be reassembled even when the attacker used `-EncodedCommand`.** Script-block logging records the decoded block; long base64 or download cradles (`IEX (New-Object Net.WebClient).DownloadString`) show up verbatim. Absence of 4104 just means the logging GPO was off — not that PowerShell wasn't used. `[Microsoft PowerShell logging docs / MITRE T1059.001 · high]`
- **WMI event-consumer persistence is invisible to logon/process logs.** A `__EventFilter` + `CommandLineEventConsumer` binding fires WMI-Activity Operational 5861 (consumer registered) and 5857/5858 (provider load/operation) — check this Operational log when execution looks empty but persistence is suspected. `[MITRE T1546.003 · high]`
- **Distrust host time around destructive activity.** Actors time intrusions for off-hours and some manipulate the system clock; if the timeline is internally impossible, anchor to the monotonic **EventRecordID** within each EVTX file and to journal/USN sequence numbers rather than TimeCreated. `⚠️verify any timeline keyed purely to host clock.` `[general DFIR anti-forensics practice · med]`

## ATT&CK mapping
- T1078 · Valid Accounts · 4624 logon with stolen/valid creds — step 2
- T1021.001 · Lateral Movement · Remote Desktop Protocol · 4624 type 10 + RDP Operational 1149 — step 2
- T1021.002 · Lateral Movement · SMB/Windows Admin Shares · 4624 type 3 + 7045 on target — steps 2/4
- T1110 · Credential Access · Brute Force · 4625 failure burst → 4624 success — step 2
- T1134 · Privilege Escalation · Access Token Manipulation · 4672 special privileges / 4648 explicit creds — step 3
- T1098 / T1136 · Persistence · Account Manipulation / Create Account · 4720/4724/4732 — step 3
- T1543.003 · Persistence · Windows Service · 7045 service install — step 4
- T1053.005 · Persistence/Execution · Scheduled Task · 4698 / TaskScheduler Operational 106/200 — step 4
- T1569.002 · Execution · Service Execution (PsExec) · 7045 + 4688 — steps 4/5
- T1059.001 · Execution · PowerShell · 4104/4103 script block + pipeline — step 5
- T1546.003 · Persistence · WMI Event Subscription · WMI-Activity 5861/5857 — step 5
- T1070.001 · Defense Evasion · Clear Windows Event Logs · 1102 (Security) / 104 (System) — step 6
- T1562.002 · Defense Evasion · Disable Windows Event Logging · 1100 service shutdown / 4719 audit-policy change — step 6
- T1070.006 · Defense Evasion · Timestomp · $SI vs $FN on the persistence binary — step 7

## Pivots (lead-to-lead graph)
- `on_rdp_or_network_logon (step 2 type 10/3): active-directory-domain — credential/Kerberos abuse and the domain side of lateral movement`
- `on_lateral_movement_from_peer (step 2/4 inbound type 3 + 7045): attack-lifecycle-hunting — reconstruct the multi-host hop chain`
- `on_credential_or_account_change (step 3 4648/4720/4732): active-directory-domain — domain credential theft / privilege grant`
- `on_service_or_run_key_persistence (step 4/7 7045 / Services hive): windows-registry-persistence — confirm the autorun in the hive`
- `on_process_execution (step 5 4688 path): windows-execution-artifacts — corroborate via UserAssist/BAM/LNK`
- `on_log_clear_or_gap (step 6 1102/104/record-id break): SELF — re-enter with the clearing timestamp bound into #{time_window} to bracket what was hidden`
- `on_powershell_or_wmi_payload (step 5 4104/5861): malware-analysis-triage — triage the dropped/encoded payload`
- `on_logs_absent_or_unmountable (step 0/1): acquisition-custody — re-acquire or prove the collection gap`

## Jargon decoder
- **EVTX:** the on-disk Windows Event Log file format (`Security.evtx`, `System.evtx`, and the per-feature `*%4Operational.evtx` logs).
- **ETW (Event Tracing for Windows):** the live tracing system that feeds the Operational logs (PowerShell, WMI, TaskScheduler) — richer than the classic Security/System logs.
- **EID (Event ID):** the numeric type of an event (e.g. 4624 = a successful logon).
- **4624 / 4625:** a successful / failed logon.
- **LogonType:** how the logon happened — **2** console (sitting at the machine), **3** network (SMB/share access), **5** service, **10** Remote Desktop. Read this, not just the username.
- **4672:** "special privileges assigned" — an admin/privileged session was created.
- **4648:** a logon using explicitly supplied credentials (run-as / `runas /user:`), common in lateral movement.
- **4688:** process creation — records the program path and (if the GPO is on) the command line. Needs process-auditing enabled.
- **7045:** a new Windows **service** was installed (records ServiceName + ImagePath) — a top persistence signal.
- **4698 / TaskScheduler 106:** a **scheduled task** was created; 200/201 record it running.
- **4104 / 4103:** PowerShell script-block / pipeline logging — captures the (decoded) commands that ran.
- **5857 / 5858 / 5861:** WMI-Activity Operational events — WMI provider load/operation and event-consumer (persistence) registration.
- **1102 / 104:** "the audit log was cleared" (Security) / "the event log was cleared" (System) — classic anti-forensics.
- **1100 / 4719:** the event-log service shut down / the audit policy was changed — quieter ways to blind logging without a 1102.
- **EventRecordID:** a per-file counter that increases by one for every event written; a break in the sequence = tampering even with no clear-event.
- **UserAssist / BAM / DAM:** registry traces of programs a user/system actually ran (execution evidence) — the off-log corroboration for a 4688.
- **$MFT / $SI vs $FN:** NTFS Master File Table / the two timestamp sets in a file record; $SI is easy to forge, $FN harder — disagreement hints at **timestomp**.
- **Super-timeline:** one merged chronology across many artifacts, built with `log2timeline.py` + `psort.py`.
- **wtmp / btmp / auth.log (Linux):** the logon / bad-logon / SSH-auth logs — the Linux analogs of 4624/4625.

## Tuning log (append-only — the eval loop writes here; humans never edit rows)
| date | case_id | bucket missed | delta applied |
|---|---|---|---|
