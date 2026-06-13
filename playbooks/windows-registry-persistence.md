---
attack_type: windows-registry-persistence
category_id: windows-registry-persistence
name: Windows Registry & Persistence
description: autoruns, Run keys, services, and other persistence mechanisms hiding in registry hives
version: 1
os_coverage: [windows, linux, macos, cloud]
sub_types_covered: 9
sub_types:
  - Run/RunOnce keys
  - Windows services persistence
  - scheduled-task registry persistence
  - WMI event-subscription persistence
  - AppInit_DLLs / IFEO image-hijack persistence
  - COM hijacking
  - Winlogon/Shell/Userinit persistence
  - UserAssist execution evidence
  - ShimCache (AppCompatCache) execution evidence
validated_on: []
maturity: draft
variables:
  image_path:
    default: UNSET-bind-in-step0
    derive: "Step 0 — first disk-evidence image (E01/dd/raw/vmdk) enumerated under the evidence directory named in the case brief"
  mount_root:
    default: UNSET-bind-in-step0
    derive: "Step 0 — directory where the file system is mounted READ-ONLY (or where icat-extracted hives land when mounting fails)"
  case_out:
    default: UNSET-bind-in-step0
    derive: "Step 0 — writable case output directory from the case brief; Step 0 creates #{case_out}/receipts/ and #{case_out}/extracted/"
  ntfs_offset_sectors:
    default: 0
    derive: "Step 0 — start sector of the relevant partition from `mmls #{image_path}` (largest NTFS partition unless the brief says otherwise)"
  time_window:
    default: whole-image-until-narrowed
    derive: "case brief if it names one; else first confirmed malicious timestamp ±48h once a step pins one — then re-scope wide sweeps to it"
---

## In one line
After someone breaks into a Windows machine, they want to survive a reboot. They plant a tiny instruction in the registry (Windows' big settings database) — "every time this computer starts, also run my program." This playbook finds those hidden "auto-start" instructions and proves which one belongs to the attacker.

## Use this when (triggers)
- A suspicious program keeps coming back after reboot, or runs at logon/boot with no obvious reason.
- You found malware on disk and now need to know HOW it keeps running (its persistence foothold).
- An autoruns/EDR alert names a Run key, a new service, an odd scheduled task, or a WMI consumer.
- A binary lives in a weird path (`\ProgramData\`, `\Users\Public\`, `%TEMP%`, `\PerfLogs\`) and you need to tie it to a start-up mechanism.
- You need to know what already ran on the box (UserAssist / ShimCache) to date the foothold.
- A service or DLL with a legitimate-looking name points at an unsigned binary in a user-writable folder.

## Quick path (the 90% case)
1. **Bootstrap + timeline-first.** Run Step 0 to mount read-only and bind variables. Then build a registry-anchored timeline: parse the hives' key LastWrite times with `RECmd` (Kroll_Batch) and sort the output by time — this `timeline-first` move tells you *when* persistence keys were last touched, before you commit to any story. Cross-check with the `$MFT` (`MFTECmd`) timeline of when the pointed-to binaries appeared.
2. **Sweep the classic auto-starts.** `RECmd` with the bundled batch over SOFTWARE + the per-user `NTUSER.DAT` covers Run/RunOnce, Services, Winlogon, AppInit_DLLs, IFEO, COM (`rip.pl` is the fallback). Flag any value whose target is an unsigned binary in a user-writable path or whose key LastWrite sits inside #{time_window}.
3. **Corroborate the foothold actually fires.** A registry pointer is a *claim* of persistence; confirm it with a second source — Service install `7045` / Scheduled-Task `106/200` / WMI `5861` in the EVTX (`EvtxECmd`), and execution evidence (UserAssist / BAM, ShimCache) that the binary really ran.
4. **Date it and tie it to entry.** Use the key LastWrite + binary MACB + first-execution time to place the foothold on the case timeline relative to initial access.

If a Run key / service / task / WMI consumer points at an unsigned binary, its key LastWrite lands in the incident window, AND a 7045/106/5861 or execution artifact corroborates it → foothold identified. Otherwise drop into the full Steps below. **Quick-path success does not close the case — the close-gate invariant still applies.**

## How it unfolds (the story)
An attacker gets code running on the host (phishing, exploited service, stolen RDP creds). To survive reboots and logoffs they write an auto-start instruction into the registry: a value under a Run key, a new service whose `ImagePath` points at their loader, a scheduled task (which leaves a registry footprint plus task XML), a WMI event subscription that fires their script on a trigger, or a stealthier hijack (IFEO debugger, AppInit_DLLs, COM CLSID redirect, Winlogon Shell/Userinit edit). Each method leaves a registry key with a LastWrite time and a pointer to a payload — and the payload, once it runs, leaves execution evidence (UserAssist, BAM/DAM, ShimCache). The investigation walks pointer → payload → execution → time, and refutes the benign explanations for each.

## Theories to test (and how to rule each out)
| Theory (who / why) | If true, you'd find… | Rule it out if… |
|---|---|---|
| **External-targeted (hands-on intruder planting a foothold)** — broke in, then installed persistence to keep access | A Run/Service/Task/WMI entry pointing at a binary in a non-standard, user-writable path; key LastWrite clustered with other intrusion events; the binary present in Amcache/ShimCache and executed (UserAssist/BAM) | The auto-start target is a signed vendor binary in `\Program Files\`/`\Windows\`, key LastWrite predates the incident, and the program is a known installed app |
| **External-commodity (malware self-installed its own persistence)** — dropper wrote a Run key / service for itself | A single binary that both ran and wrote its own Run key/service; classic stealth path (`\AppData\Roaming\`, `\ProgramData\`); often a randomly-named value | No malware on disk; the auto-start points only at legitimate installed software with valid signatures |
| **Insider / admin (deliberately planted a backdoor)** — a real account created a service/task to keep covert access | New service/task created interactively by a real admin account; ImagePath = script/LOLBin; possibly a benign-looking name masking a remote-access tool | The entry was created by a trusted management/deployment process (SCCM/GPO/RMM) consistent with this account's baseline duties |
| **Other-insider (compromised legit account used to persist)** — outsider using stolen creds wrote the persistence | Persistence written during a logon from an unusual IP/time (impossible-travel); same account creates service/task right after an anomalous logon | The creating logon matches the real user's baseline source/time and no anomalous session precedes the key write |
| **Supply-chain (poisoned installer/update wrote the auto-start)** — trusted updater planted the foothold | Persistence written by a software-update/RMM parent; same value appears on many hosts at once; signed-but-malicious component | The entry arrived only on this host via an interactive session, with no trusted-updater parent |
| **Innocent / benign (NOT an attack)** — a legitimate app, driver, or admin tool's normal auto-start | Run value / service / task / WMI consumer for known software (AV, backup agent, GPU driver, vendor updater), signed, in a standard path, key LastWrite tied to install/update | Target is unsigned in a user-writable path, value name is random, key LastWrite lands inside the incident window, and no installer/update event explains it → benign cause refuted |

*(≥1 benign + ≥1 malicious, each actively refuted. Map every attacker type before closing: insider · other-insider · external-commodity · external-targeted · supply-chain · innocent.)*

## Evidence → Tool → What it reveals (per OS)
| Evidence | SIFT tool | What it tells you *for this attack* | OS |
|---|---|---|---|
| SOFTWARE hive (Run/RunOnce, Winlogon, AppInit_DLLs, IFEO, COM, services map) | `RECmd` / `rip.pl` | The system-wide auto-start values + their key LastWrite times → the persistence pointer and when it was set | Windows |
| `NTUSER.DAT` (per-user Run/RunOnce, UserAssist) | `RECmd` / `rip.pl` | Per-user auto-start AND UserAssist (programs that user actually ran) → ties foothold to a user | Windows |
| `UsrClass.dat` (per-user COM, `Software\Classes`) | `RECmd` / `rip.pl` | Per-user COM hijack / CLSID redirect persistence | Windows |
| SYSTEM hive (`Services`, ControlSet) | `RECmd` / `rip.pl` | New/modified service entries (`ImagePath`, `Start`, `ServiceDll`) → service-based persistence | Windows |
| SYSTEM hive (AppCompatCache) | `AppCompatCacheParser` | ShimCache: a binary was PRESENT on disk (path/size/last-mod) — presence, not execution on Win8+ (⚠ see Don't get fooled) | Windows |
| `Amcache.hve` | `AmcacheParser` / `amcache.py` | Inventory + SHA-1 of the persistence binary on disk (⚠ inventory, **not** proof it ran) | Windows |
| Registry transaction logs (`.LOG1/.LOG2`) | `rla` | Replays pending changes into a clean hive so the latest persistence write is visible (run BEFORE RECmd/rip.pl) | Windows |
| `Security.evtx` (4688 process creation, 4624 logon) | `EvtxECmd` / `evtxexport` | The persistence-creating process + the session/account that created it (note: `evtxexport` is a raw export, no EID labels — grep the XML; `EvtxECmd` adds EID maps) | Windows |
| `System.evtx` (7045 service install, 7040 start-type change) | `EvtxECmd` / `evtxexport` | A new service was installed / a service set to auto-start → second source for service persistence | Windows |
| `Microsoft-Windows-TaskScheduler/Operational.evtx` (106/140/200) | `EvtxECmd` / `evtxexport` | A scheduled task was registered/updated and what action it runs → scheduled-task persistence | Windows |
| `Microsoft-Windows-WMI-Activity/Operational.evtx` (5857/5858/5861) | `EvtxECmd` / `evtxexport` | A permanent WMI event consumer/filter was created → WMI persistence (the OBJECTS.DATA / CIM source) | Windows |
| `$MFT` (Master File Table) | `MFTECmd` / `analyzeMFT` | When the pointed-to binary/script/task XML appeared on disk; `$SI` vs `$FN` timestomp on the loader | Windows |
| Scheduled-task XML under `\Windows\System32\Tasks\` | `fls` + `icat` / `srch_strings` | The task's Action (command line) and trigger when no Task EVTX survives | Windows |
| WMI repository `OBJECTS.DATA` (CIM) | `srch_strings` / `bstrings` | Strings of the consumer's `ScriptText`/`CommandLineTemplate` when EVTX is gone (⚠ no native CIM parser here — strings only, `⚠️verify`) | Windows |
| RAM image | `vol` (Volatility 3 `windows.registry.printkey`, `svcscan`, `registry.userassist`) | Live registry keys (incl. keys not yet flushed to disk), running services, in-memory ShimCache | Windows |
| Run-key / service values in raw image | `bulk_extractor` | FS-independent recovery of registry-value/path strings from unallocated space | all |
| Linux auto-starts (cron/systemd) — see Linux branch | `fls`/`mactime`, `srch_strings` | Linux persistence is files, not registry (no registry exists on Linux) | Linux |
| macOS LaunchAgents/Daemons, login items | `fls`/`mactime`, `srch_strings`, `exiftool` | macOS persistence is plists, not registry (⚠ `mac_apt` broken on this box — use TSK + strings; `⚠️verify`) | macOS |

*(every tool above is in the RUN-VERIFIED list; ShimCache/Amcache rows are tagged presence-not-execution per the matrix.)*

## Step 0 — evidence inventory & access bootstrap

- n: 0
  tool: |
    mkdir -p "#{case_out}/receipts" "#{case_out}/extracted" && ls -laR "#{image_path}" 2>&1 | tee "#{case_out}/receipts/00.txt"; mmls "#{image_path}" 2>&1 | tee -a "#{case_out}/receipts/00.txt"; img_stat "#{image_path}" 2>&1 | tee -a "#{case_out}/receipts/00.txt"; fsstat -o "#{ntfs_offset_sectors}" "#{image_path}" 2>&1 | tee -a "#{case_out}/receipts/00.txt"; mount -o ro,loop,offset=$(( #{ntfs_offset_sectors} * 512 )) "#{image_path}" "#{mount_root}" 2>&1 | tee -a "#{case_out}/receipts/00.txt" || fls -rp -o "#{ntfs_offset_sectors}" "#{image_path}" 2>&1 | tee -a "#{case_out}/receipts/00.txt"
  expect: every evidence file classified; an NTFS partition listed by mmls and confirmed "File System Type: NTFS" by fsstat; #{image_path}, #{mount_root}, #{ntfs_offset_sectors}, #{case_out} bound; read-only access proven (mount readable OR fls listing captured)
  check: |
    test -r "#{mount_root}" -o -n "$(ls "#{case_out}/extracted" 2>/dev/null)" && grep -qi "NTFS" "#{case_out}/receipts/00.txt"
  falsify: evidence dir empty/unreadable, or no supported image format, or no NTFS partition found (registry persistence is Windows-only — a non-NTFS-only image routes to the Linux/macOS branch)
  on_result: {expect_met: goto 1, falsify_met: STOP — report acquisition/access failure; pivot acquisition-custody, neither: try the fls/icat extract fallback into #{case_out}/extracted; if that also fails treat as falsify_met}
  emits: [key_artifacts]
  serves: [Run/RunOnce keys, Windows services persistence, scheduled-task registry persistence, WMI event-subscription persistence, AppInit_DLLs / IFEO image-hijack persistence, COM hijacking, Winlogon/Shell/Userinit persistence, UserAssist execution evidence, ShimCache (AppCompatCache) execution evidence]
  provenance: {receipt_id: 00, artifact: evidence directory listing, offset_or_row: full listing + mmls/fsstat header, literal_cited: image filename + File System Type NTFS}

## Steps (executable — decision-driven)

- n: 1
  precondition: "os == windows; test -r #{mount_root}"
  tool: |
    find "#{mount_root}" -iname "*.LOG1" -o -iname "*.LOG2" 2>/dev/null | tee "#{case_out}/receipts/01.txt"; for h in SYSTEM SOFTWARE SAM SECURITY; do dotnet /opt/zimmermantools/rla.dll -f "#{mount_root}/Windows/System32/config/$h" --out "#{case_out}/extracted" 2>&1 | tee -a "#{case_out}/receipts/01.txt"; done
  expect: rla replays the .LOG1/.LOG2 transaction logs into clean, dirty-flag-cleared hives in #{case_out}/extracted so the LATEST persistence write is visible; receipt shows "Updated hive" / written output paths
  check: |
    test -n "$(ls "#{case_out}/extracted"/*SOFTWARE* "#{case_out}/extracted"/*SYSTEM* 2>/dev/null)" || grep -qiE "updated|written|processed" "#{case_out}/receipts/01.txt"
  falsify: hives have no transaction logs and rla reports nothing to apply (hive already clean — fine, parse the originals); OR config dir absent (no Windows install on this volume)
  on_result: {expect_met: goto 2, falsify_met: parse the original hives in place at #{mount_root} (clean hive) and goto 2, neither: icat-extract the config hives into #{case_out}/extracted then run rla there then goto 2}
  emits: [key_artifacts]
  serves: [Run/RunOnce keys, Windows services persistence, AppInit_DLLs / IFEO image-hijack persistence, COM hijacking, Winlogon/Shell/Userinit persistence]
  provenance: {receipt_id: 01, artifact: registry transaction logs, offset_or_row: rla output line, literal_cited: cleaned-hive output path}

- n: 2
  precondition: "os == windows"
  tool: |
    dotnet /opt/zimmermantools/RECmd/RECmd.dll --bn /opt/zimmermantools/RECmd/BatchExamples/RECmd_Batch_MC.reb -d "#{mount_root}/Windows/System32/config" --csv "#{case_out}" --csvf reg_system_sw.csv 2>&1 | tee "#{case_out}/receipts/02.txt"
  expect: a Run/RunOnce value, Winlogon Shell/Userinit edit, AppInit_DLLs entry, or IFEO Debugger value whose data points at a binary in a user-writable/non-standard path (\ProgramData\, \Users\Public\, \AppData\, %TEMP%, \PerfLogs\) and whose key LastWrite falls inside #{time_window}
  check: |
    test -s "#{case_out}/reg_system_sw.csv" && grep -qiE "run|runonce|winlogon|appinit|image file execution options|userinit|shell" "#{case_out}/reg_system_sw.csv"
  falsify: every auto-start value resolves to a signed binary in \Program Files\ or \Windows\, all key LastWrites predate the incident window, and value names match known installed software
  on_result: {expect_met: record key path + value name + target binary + LastWrite then goto 3, falsify_met: no SOFTWARE/Winlogon/IFEO/AppInit foothold — goto 3 to test service & task & WMI persistence, neither: re-parse with rip.pl -r the SOFTWARE hive -f software (profiles run / appinitdlls / imagefileexecoptions) and re-check}
  emits: [key_artifacts, key_iocs]
  serves: [Run/RunOnce keys, AppInit_DLLs / IFEO image-hijack persistence, Winlogon/Shell/Userinit persistence]
  provenance: {receipt_id: 02, artifact: SOFTWARE hive, offset_or_row: reg_system_sw.csv Run/Winlogon/IFEO row, literal_cited: value name + target path + LastWrite}

- n: 3
  precondition: "os == windows"
  tool: |
    dotnet /opt/zimmermantools/RECmd/RECmd.dll --bn /opt/zimmermantools/RECmd/BatchExamples/RECmd_Batch_MC.reb -d "#{mount_root}/Windows/System32/config/SYSTEM" --csv "#{case_out}" --csvf reg_services.csv 2>&1 | tee "#{case_out}/receipts/03.txt"
  expect: a service key whose ImagePath/ServiceDll points at a non-standard path or LOLBin, Start==2 (auto), Type kernel/user-mode, with a key LastWrite inside #{time_window} — i.e. a service created for persistence
  check: |
    test -s "#{case_out}/reg_services.csv" && grep -qiE "imagepath|servicedll|\\\\services\\\\" "#{case_out}/reg_services.csv"
  falsify: every service ImagePath is a signed vendor/OS binary in \Windows\ or \Program Files\, no service LastWrite lands in the incident window, and no new service name is unfamiliar
  on_result: {expect_met: record service name + ImagePath + LastWrite then corroborate with 7045 in step 6 then goto 4, falsify_met: no service-based persistence — goto 4 to test scheduled-task and WMI persistence, neither: re-parse with rip.pl -r the SYSTEM hive -f system (profile services) and re-check}
  emits: [key_artifacts, key_iocs]
  serves: [Windows services persistence]
  provenance: {receipt_id: 03, artifact: SYSTEM hive Services, offset_or_row: reg_services.csv service row, literal_cited: service name + ImagePath + LastWrite}

- n: 4
  precondition: "os == windows"
  tool: |
    for u in "#{mount_root}"/Users/*; do dotnet /opt/zimmermantools/RECmd/RECmd.dll --bn /opt/zimmermantools/RECmd/BatchExamples/RECmd_Batch_MC.reb -d "$u" --csv "#{case_out}" --csvf "reg_user_$(basename "$u").csv" 2>&1 | tee -a "#{case_out}/receipts/04.txt"; done
  expect: per-user persistence — a Run/RunOnce value in NTUSER.DAT or a COM CLSID redirect (InprocServer32/LocalServer32) in UsrClass.dat pointing at an attacker DLL/EXE — AND a matching UserAssist entry showing that user actually executed the payload
  check: |
    ls "#{case_out}"/reg_user_*.csv >/dev/null 2>&1 && grep -qiEh "run|runonce|userassist|inprocserver32|localserver32|clsid" "#{case_out}"/reg_user_*.csv
  falsify: no per-user Run value, no hijacked CLSID, and UserAssist shows only normal user apps — per-user persistence absent
  on_result: {expect_met: record per-user foothold + the user account then goto 5, falsify_met: no per-user/COM persistence — goto 5, neither: re-parse a specific user with rip.pl -r the NTUSER.DAT -f ntuser (profiles run / userassist) and the UsrClass.dat -p comdlg32 and re-check}
  emits: [key_artifacts, actor_accounts]
  serves: [Run/RunOnce keys, COM hijacking, UserAssist execution evidence]
  provenance: {receipt_id: 04, artifact: NTUSER.DAT / UsrClass.dat, offset_or_row: reg_user_*.csv Run/CLSID/UserAssist row, literal_cited: value/CLSID + target + user SID}

- n: 5
  precondition: "os == windows"
  tool: |
    dotnet /opt/zimmermantools/AppCompatCacheParser/AppCompatCacheParser.dll -f "#{mount_root}/Windows/System32/config/SYSTEM" --csv "#{case_out}" --csvf shimcache.csv 2>&1 | tee "#{case_out}/receipts/05.txt"; dotnet /opt/zimmermantools/AmcacheParser.dll -f "#{mount_root}/Windows/AppCompat/Programs/Amcache.hve" --csv "#{case_out}" --csvf amcache.csv 2>&1 | tee -a "#{case_out}/receipts/05.txt"
  expect: the persistence target binary (from steps 2-4) appears in ShimCache (present on disk, path/last-mod) AND/OR Amcache (SHA-1 + first-seen) — corroborating the payload existed on disk; SHA-1 captured for IOC pivot
  check: |
    test -s "#{case_out}/shimcache.csv" -o -s "#{case_out}/amcache.csv"
  falsify: the persistence target is NOT in ShimCache or Amcache (binary may be deleted/never cached) — record absence as a finding, lean on $MFT + EVTX
  on_result: {expect_met: record SHA-1 + on-disk path then correlate the hash across the timeline then goto 6, falsify_met: record payload-not-in-ShimCache/Amcache then recover the binary via icat for hashing if its inode is known then goto 6, neither: re-run AmcacheParser with the legacy amcache.py /opt/amcache/bin/amcache.py against the same hive and re-check}
  emits: [key_artifacts, key_iocs]
  serves: [ShimCache (AppCompatCache) execution evidence, UserAssist execution evidence]
  provenance: {receipt_id: 05, artifact: AppCompatCache / Amcache.hve, offset_or_row: shimcache.csv or amcache.csv row, literal_cited: binary path + SHA-1}

- n: 6
  precondition: "os == windows; test -r #{mount_root}/Windows/System32/winevt/Logs"
  tool: |
    dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll -d "#{mount_root}/Windows/System32/winevt/Logs" --csv "#{case_out}" --csvf evtx_persist.csv 2>&1 | tee "#{case_out}/receipts/06.txt"
  expect: a second, independent source for the registry foothold — System 7045 (service installed) matching the ImagePath from step 3, OR Security 4688 of the process that wrote the key, OR a 4624 logon for the creating session — within #{time_window}
  check: |
    test -s "#{case_out}/evtx_persist.csv" && grep -qiE "7045|4688|4624|7040" "#{case_out}/evtx_persist.csv"
  falsify: no 7045/4688/7040 corroborates the registry entry (audit may be off, or System log rolled) — registry remains single-source until corroborated elsewhere
  on_result: {expect_met: corroboration achieved (two-source rule) then goto 7, falsify_met: record EVTX gap as a finding then fall back to execution evidence (step 5 UserAssist/Amcache) + $MFT timing then goto 7, neither: re-export the single log with evtxexport the System.evtx and grep the XML for ServiceName/7045 then goto 7}
  emits: [timeline_events, actor_accounts]
  serves: [Windows services persistence, Run/RunOnce keys]
  provenance: {receipt_id: 06, artifact: System.evtx / Security.evtx, offset_or_row: evtx_persist.csv 7045/4688 row, literal_cited: ServiceName/ImagePath or NewProcessName + time}

- n: 7
  precondition: "os == windows; test -r #{mount_root}/Windows/System32/winevt/Logs"
  tool: |
    grep -hiE "106|140|200|201" "#{case_out}/evtx_persist.csv" 2>/dev/null | tee "#{case_out}/receipts/07.txt"; find "#{mount_root}/Windows/System32/Tasks" -type f 2>/dev/null | tee -a "#{case_out}/receipts/07.txt"; srch_strings "#{mount_root}/Windows/System32/Tasks"/* 2>/dev/null | grep -iE "\\.exe|\\.dll|\\.ps1|\\.vbs|cmd|powershell" | tee -a "#{case_out}/receipts/07.txt"
  expect: TaskScheduler/Operational 106 (task registered) or 200/201 (action run) inside #{time_window}, OR a task XML under \System32\Tasks\ whose <Command>/<Arguments> launch a non-standard binary/script — scheduled-task persistence
  check: |
    test -s "#{case_out}/receipts/07.txt" && grep -qiE "106|200|\\.exe|\\.ps1|powershell|cmd" "#{case_out}/receipts/07.txt"
  falsify: no task-registration event and every task XML is a signed Microsoft/vendor maintenance task — no scheduled-task persistence
  on_result: {expect_met: record task name + action command then goto 8, falsify_met: no scheduled-task persistence — goto 8 to test WMI, neither: icat-extract the specific task XML by inode and srch_strings it for the Action command then goto 8}
  emits: [key_artifacts, timeline_events]
  serves: [scheduled-task registry persistence]
  provenance: {receipt_id: 07, artifact: TaskScheduler Operational.evtx / Tasks XML, offset_or_row: receipt 07 task row, literal_cited: task name + Command/Arguments}

- n: 8
  precondition: "os == windows"
  tool: |
    grep -hiE "5857|5858|5861" "#{case_out}/evtx_persist.csv" 2>/dev/null | tee "#{case_out}/receipts/08.txt"; srch_strings "#{mount_root}/Windows/System32/wbem/Repository/OBJECTS.DATA" 2>/dev/null | grep -iE "eventconsumer|commandlinetemplate|scripttext|activescript|__eventfilter|powershell|\\.exe|\\.vbs" | tee -a "#{case_out}/receipts/08.txt"
  expect: WMI-Activity/Operational 5861 (permanent event consumer registered) inside #{time_window}, OR strings in the CIM repository OBJECTS.DATA showing an ActiveScript/CommandLine EventConsumer bound to an __EventFilter — WMI event-subscription persistence (⚠ no native CIM parser on this box; strings are lead-only, ⚠️verify)
  check: |
    test -s "#{case_out}/receipts/08.txt" && grep -qiE "5861|eventconsumer|commandlinetemplate|scripttext|__eventfilter" "#{case_out}/receipts/08.txt"
  falsify: no 5861 event and no consumer/filter strings in OBJECTS.DATA — no WMI persistence
  on_result: {expect_met: record consumer name + ScriptText/CommandLine + binding then goto 9, falsify_met: no WMI persistence — goto 9, neither: re-export with evtxexport the WMI-Activity Operational.evtx and grep the XML for OperationId 5861 then goto 9}
  emits: [key_artifacts, key_iocs]
  serves: [WMI event-subscription persistence]
  provenance: {receipt_id: 08, artifact: WMI-Activity Operational.evtx / OBJECTS.DATA, offset_or_row: receipt 08 5861/consumer row, literal_cited: consumer name + ScriptText/CommandLineTemplate}

- n: 9
  precondition: "os == windows"
  tool: |
    dotnet /opt/zimmermantools/MFTECmd.dll -f "#{mount_root}/\$MFT" --csv "#{case_out}" --csvf mft.csv 2>&1 | tee "#{case_out}/receipts/09.txt"
  expect: the persistence target binary/script/task-XML appears in the $MFT with a Created0x10 timestamp inside #{time_window}, and $SI vs $FN times are consistent — dating when the foothold was planted; a $SI-much-newer-than-$FN delta = timestomp on the loader
  check: |
    test -s "#{case_out}/mft.csv"
  falsify: the target file is absent from the $MFT (deleted with MFT entry reused) OR its Created time long predates the incident and matches a legitimate install — not attacker-planted
  on_result: {expect_met: pin foothold-planted time then goto 10, falsify_met: record loader-not-in-$MFT-or-pre-dates-incident then rely on registry LastWrite + EVTX for timing then goto 10, neither: re-parse $MFT with analyzemft /opt/analyzemft/bin/analyzemft -f the $MFT -o "#{case_out}/amft.csv" and re-check}
  emits: [timeline_events, key_artifacts]
  serves: [Windows services persistence, Run/RunOnce keys, scheduled-task registry persistence]
  provenance: {receipt_id: 09, artifact: $MFT, offset_or_row: mft.csv row for the loader path, literal_cited: filename + Created0x10 + $SI/$FN delta}

- n: 10
  precondition: "os == windows"
  tool: |
    bulk_extractor -o "#{case_out}/be" "#{image_path}" 2>&1 | tee "#{case_out}/receipts/10.txt"; grep -riE "currentversion\\\\run|\\\\services\\\\|inprocserver32|eventconsumer" "#{case_out}/be" 2>/dev/null | tee -a "#{case_out}/receipts/10.txt"
  expect: anti-forensics / hidden-foothold sweep — bulk_extractor recovers registry-value and path strings from unallocated space, surfacing a Run/Services/COM/WMI persistence pointer that was DELETED from the live hive (a key removed after planting is itself a finding)
  check: |
    test -d "#{case_out}/be" && test -n "$(ls "#{case_out}/be" 2>/dev/null)"
  falsify: no deleted-persistence strings recovered, live hives are internally consistent, no key was removed — no hidden/erased foothold
  on_result: {expect_met: record recovered/deleted persistence as a finding then correlate the IOC across modalities then goto 11, falsify_met: note no-erased-persistence-recovered then goto 11, neither: widen the sweep — srch_strings the raw image for the CurrentVersion Run path and re-check}
  emits: [key_iocs, key_artifacts]
  serves: [Run/RunOnce keys, Windows services persistence, COM hijacking, WMI event-subscription persistence]
  provenance: {receipt_id: 10, artifact: bulk_extractor features over raw image, offset_or_row: be feature line, literal_cited: recovered registry path/value string}

- n: 11
  precondition: "test -n \"#{image_path}\""
  tool: |
    if ls "#{case_out}"/*.mem "#{image_path%.E01}.mem" >/dev/null 2>&1; then vol -f "$(ls "#{case_out}"/*.mem 2>/dev/null | head -1)" windows.registry.printkey --key "Software\\Microsoft\\Windows\\CurrentVersion\\Run" 2>&1 | tee "#{case_out}/receipts/11.txt"; vol -f "$(ls "#{case_out}"/*.mem 2>/dev/null | head -1)" windows.svcscan 2>&1 | tee -a "#{case_out}/receipts/11.txt"; else echo "no memory image present — registry-only case" | tee "#{case_out}/receipts/11.txt"; fi
  expect: if RAM was captured — windows.registry.printkey shows a Run value (incl. keys not yet flushed to the on-disk hive) and windows.svcscan shows a running service matching the on-disk foothold, confirming it is LIVE and active
  check: |
    test -s "#{case_out}/receipts/11.txt"
  falsify: no memory image available (registry-only case), OR printkey/svcscan show no foothold matching the disk findings — memory neither confirms nor adds
  on_result: {expect_met: corroborate live persistence + capture in-memory IOCs then goto 12, falsify_met: mark memory insufficient_evidence (registry-only case) then goto 12, neither: try vol -f the memory image windows.registry.userassist and re-check; if no RAM goto 12}
  emits: [key_artifacts, timeline_events]
  serves: [Run/RunOnce keys, Windows services persistence]
  provenance: {receipt_id: 11, artifact: RAM image, offset_or_row: printkey/svcscan output row, literal_cited: live Run value or running service name}

- n: 12
  precondition: "os == windows"
  tool: |
    log2timeline.py --storage-file "#{case_out}/persist.plaso" "#{image_path}" 2>&1 | tee "#{case_out}/receipts/12.txt"; psort.py -o l2tcsv "#{case_out}/persist.plaso" -w "#{case_out}/super.csv" 2>&1 | tee -a "#{case_out}/receipts/12.txt"
  expect: a fused timeline where entry (logon/exploit) → loader-on-disk (step 9) → persistence-key-write (steps 2-4) → install event (step 6/7/8) → first execution (step 5 UserAssist/BAM) form a coherent ordered chain with no unexplained gap
  check: |
    test -s "#{case_out}/super.csv" || grep -qiE "processing completed|parsers" "#{case_out}/receipts/12.txt"
  falsify: ordering is impossible (e.g. the key write precedes the loader ever existing on disk), OR a multi-hour gap separates loader and persistence with no explanation
  on_result: {expect_met: COMMIT the foothold conclusion with a confidence label, falsify_met: re-open the Theories table — the inconsistency means the wrong entry was attributed so pivot SELF with the corrected IOC, neither: run pinfo.py "#{case_out}/persist.plaso" to confirm parsers ran then re-filter to #{time_window} and re-check}
  emits: [timeline_events, key_artifacts]
  serves: [Run/RunOnce keys, Windows services persistence, scheduled-task registry persistence, WMI event-subscription persistence, COM hijacking, Winlogon/Shell/Userinit persistence, AppInit_DLLs / IFEO image-hijack persistence, UserAssist execution evidence, ShimCache (AppCompatCache) execution evidence]
  provenance: {receipt_id: 12, artifact: persist.plaso super-timeline, offset_or_row: super.csv ordered rows, literal_cited: ordered entry→loader→key-write→install→execution events}

## Linux branch (L1..Ln) — REQUIRED, numbered, same step shape

- n: L1
  precondition: "os == linux"
  tool: |
    fsstat -o "#{ntfs_offset_sectors}" "#{image_path}" 2>&1 | tee "#{case_out}/receipts/L01.txt"; fls -rp -o "#{ntfs_offset_sectors}" "#{image_path}" 2>&1 | grep -iE "/etc/cron|/etc/systemd|/lib/systemd|rc.local|\\.bashrc|\\.profile|/etc/init|ld.so.preload|\\.ssh/authorized_keys" | tee -a "#{case_out}/receipts/L01.txt"
  expect: this is a Linux/ext volume (no Windows registry exists) — persistence lives in files: cron (/etc/cron*, crontab), systemd units (/etc/systemd, /lib/systemd), rc.local, shell rc files, /etc/init, ld.so.preload, and authorized_keys; fls lists those paths for inspection
  check: |
    grep -qiE "ext|xfs|btrfs" "#{case_out}/receipts/L01.txt" && grep -qiE "cron|systemd|rc.local|bashrc|authorized_keys|ld.so.preload" "#{case_out}/receipts/L01.txt"
  falsify: fsstat reports NTFS (this is actually a Windows image — return to the Windows Steps), OR none of the Linux persistence paths exist
  on_result: {expect_met: goto L2, falsify_met: if NTFS go run the Windows Steps (n 1..12) else record no-Linux-persistence-paths-present, neither: widen the fls filter to all of /etc and /home and re-check}
  emits: [key_artifacts]
  serves: [Windows services persistence, scheduled-task registry persistence]
  provenance: {receipt_id: L01, artifact: ext/xfs file system, offset_or_row: fls listing line, literal_cited: persistence file path (cron/systemd/authorized_keys)}

- n: L2
  precondition: "os == linux"
  tool: |
    for f in $(fls -rp -o "#{ntfs_offset_sectors}" "#{image_path}" 2>/dev/null | grep -iE "cron|systemd|rc.local|ld.so.preload" | awk '{print $2}'); do echo "== inode $f =="; icat -o "#{ntfs_offset_sectors}" "#{image_path}" "${f%:}" 2>/dev/null | srch_strings | grep -iE "/tmp/|/dev/shm/|curl|wget|nc |bash -i|/var/tmp/|base64"; done 2>&1 | tee "#{case_out}/receipts/L02.txt"
  expect: a cron entry / systemd unit / rc.local / ld.so.preload whose content launches a suspicious command (reverse shell, curl|bash, a binary in /tmp /dev/shm /var/tmp) — the Linux equivalent of the registry foothold
  check: |
    grep -qiE "/tmp/|/dev/shm/|curl|wget|bash -i|/var/tmp/|base64|nc " "#{case_out}/receipts/L02.txt"
  falsify: every cron/systemd/rc entry runs a packaged, signed-by-the-distro binary in a standard path — benign system automation, no Linux persistence
  on_result: {expect_met: record the persistence file + command then build the mactime timeline around it then commit with confidence label, falsify_met: no Linux persistence — pivot linux-host-forensics for broader host triage, neither: extract the suspect unit fully with icat and read it; if still unclear pivot linux-host-forensics}
  emits: [key_artifacts, key_iocs, timeline_events]
  serves: [Windows services persistence]
  provenance: {receipt_id: L02, artifact: cron/systemd unit / rc.local, offset_or_row: icat content line, literal_cited: the suspicious command string}

## Corroboration (two-source rule)
`required_sources: 2`
`pairs:`
- `[ Registry Run/Winlogon/IFEO value (step 2) ↔ binary present in ShimCache/Amcache (step 5) ]`
- `[ Service key ImagePath (step 3) ↔ System 7045 service-install event (step 6) ]`
- `[ Per-user Run value (step 4) ↔ UserAssist execution of the same binary (step 4/5) ]`
- `[ Scheduled-task XML Action (step 7) ↔ TaskScheduler 106/200 event (step 7) ]`
- `[ WMI consumer in OBJECTS.DATA (step 8) ↔ WMI-Activity 5861 event (step 8) ]`
- `[ Registry key LastWrite (steps 2-4) ↔ loader Created0x10 in $MFT (step 9) and timeline order (step 12) ]`
- `[ On-disk foothold ↔ live service/key in memory (step 11 vol svcscan/printkey) ]`

One hit is a *lead*; promote to *fact* only when its paired source agrees.

## Don't get fooled (red flags & anti-forensics)
- **Registry LastWrite is per-KEY, not per-VALUE.** A key's LastWrite updates when *any* value under it changes — a legit later write can mask the attacker's earlier one. Corroborate timing with the loader's `$MFT` Created time and EVTX, never on LastWrite alone.
- **Deleted persistence still leaves a trail.** A Run value/service removed after planting won't show in the live hive — recover it from unallocated space (`bulk_extractor`, step 10) and from registry transaction logs (`rla`, step 1). **Missing evidence is itself a finding.**
- **ShimCache and Amcache are PRESENCE, not execution.** On Win8/10/11 the ShimCache execution flag is gone and Amcache is an inventory — they prove the binary was *on disk*, not that it *ran*. Execution proof must come from UserAssist/BAM (RECmd/rip.pl) and Security 4688. **This box has no Prefetch (PECmd) or SRUM (SrumECmd) parser** — don't lean on them.
- **Timestomp on the loader** ($SI looks old/normal, $FN is inconsistent): compare both with `istat`/`MFTECmd`; trust $FN and the registry LastWrite/EVTX order over $SI.
- **IFEO "Debugger" is a double-edged key.** A `Debugger` value under Image File Execution Options redirects/hijacks a target EXE (e.g. `sethc.exe`→`cmd.exe`) — but IFEO is also used legitimately by debuggers/Application Verifier. Confirm the Debugger target is an attacker binary, not a dev tool.
- **COM hijack hides in plain CLSIDs.** A redirected `InprocServer32` under `HKCU\Software\Classes\CLSID\` (per-user, in `UsrClass.dat`) overrides the machine entry without admin rights — easy to miss if you only parse SOFTWARE. Always parse `UsrClass.dat` too.
- **WMI persistence has no native parser here.** OBJECTS.DATA strings are *leads only* (`⚠️verify`) — confirm with WMI-Activity 5861 EVTX; if both are gone, say so, don't guess.
- **Cleared event logs** (Security 1102 / System 104) around the key-write window = a deliberate operator hiding the install — read the silence as a finding, not as "nothing happened."
- **Benign mimics:** AV/backup/GPU-driver/vendor-updater auto-starts look exactly like persistence — signed binary, standard path, LastWrite tied to install/update. Refute the malicious theory only after checking signature, path, and whether an install/update event explains the LastWrite.

## Failure modes
```
- mode: evidence-access failure — image won't mount, wrong offset, or hives locked/unreadable
  guard: Step 0 fallback chain — ewfmount/loop-mount RO, then icat-extract the config hives into #{case_out}/extracted; record access failure as a finding, never analyze a guessed path
- mode: primary-artifact-absent — the SOFTWARE/SYSTEM/NTUSER hive or the EVTX logs are missing or rolled
  guard: parse whatever hives survive; recover deleted persistence from unallocated (bulk_extractor) and transaction logs (rla); name the secondary source (ShimCache/Amcache/$MFT) and record the absence as a finding
- mode: tool-output drift — RECmd batch-file/CSV column names change, or a check literal (7045/106/5861) no longer matches the EVTX map output
  guard: check exits 2 → adjudicate from the prose expect/falsify against the receipt, cap confidence at inferred; fall back rip.pl (registry) / evtxexport raw XML (events) and re-grep
- mode: dirty hive — latest write sits only in the .LOG1/.LOG2 and not in the hive
  guard: step 1 runs rla FIRST to replay transaction logs; if skipped, the newest persistence key may be invisible
- mode: WMI/scheduled-task without a parser — no native CIM/Task-XML parser on this box
  guard: srch_strings/bstrings over OBJECTS.DATA and Tasks XML as LEAD-ONLY (⚠️verify), corroborate with 5861/106 EVTX; if both absent, abstain
```
Minimum set every playbook covers: evidence-access failure (Step 0 fallback chain) · primary-artifact-absent (absence recorded, secondary source named) · tool-output drift (`check` exits 2 → prose adjudication, never silent pass).

## Confidence labeling (observation → inference → conclusion)
- **confirmed:** direct receipt verbatim + ≥2 independent sources agree + no unrefuted counter — e.g. registry Run value (step 2) + ShimCache presence (step 5) + 7045/4688 (step 6) + loader $MFT time (step 9) all line up.
- **inferred:** grounded but single-source/interpretive (incl. every `check`-exit-2 adjudication, every Amcache/ShimCache presence-only claim, every OBJECTS.DATA strings hit) → hedged + tagged `⚠️verify`.
- **insufficient_evidence:** precondition unmet (no RAM image; audit off; hive/EVTX missing) or sources conflict → abstain; state what is missing, do not guess.

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
- **Windows:** fully covered above — the registry is the persistence backbone (Run/RunOnce, Services, Winlogon, AppInit/IFEO, COM, WMI, scheduled-task footprint), corroborated by EVTX, execution artifacts, and $MFT.
- **Linux:** has no registry — persistence is files (cron, systemd units, rc.local, shell rc, ld.so.preload, authorized_keys). Covered by the numbered Linux branch (L1..L2): `fls`/`mactime` to find and time the files, `icat`+`srch_strings` to read them. `vol` for Linux RAM needs a matching ISF symbol pack — `⚠️verify` before relying on it.
- **macOS:** persistence is plists — LaunchAgents/LaunchDaemons (`/Library/LaunchAgents`, `~/Library/LaunchAgents`), login items, and config profiles. `mac_apt` is **broken on this box** (`⚠️verify`); use TSK (`fls`/`icat`) + `srch_strings`/`exiftool` over the plist paths, and carve with `photorec` if a plist was deleted.
- **Cloud:** "persistence" maps to identity/control-plane footholds (OAuth grants, IAM roles, lambda triggers) — not a disk registry. SIFT here has no native cloud parser; investigate from *exported* logs with `jq`/`bstrings` and pivot to `cloud-identity-saas` / `cloud-iaas-control-plane`. `⚠️verify`.

## Real-case notes (non-obvious things to look for)
- **WMI event subscriptions are the stealthiest registry-adjacent persistence — and the hardest to parse here.** A `__EventFilter` + `CommandLineEventConsumer`/`ActiveScriptEventConsumer` + `__FilterToConsumerBinding` in the CIM repository fires a payload on a trigger (logon, time, process start) with NO Run key or service to find. This box has no native CIM parser, so OBJECTS.DATA must be read with `srch_strings`/`bstrings` (lead-only) and confirmed via WMI-Activity/Operational `5861`. Where you'd look: `\Windows\System32\wbem\Repository\OBJECTS.DATA`. `[MITRE T1546.003 / Mandiant WMI persistence research · high; OBJECTS.DATA strings-only here ⚠️verify]`
- **IFEO and "GlobalFlag" enable a silent debugger-launch persistence.** A `Debugger` value under `Image File Execution Options\<target.exe>` makes Windows launch the attacker's binary whenever the target runs; the "accessibility" variant hijacks `sethc.exe`/`utilman.exe` for a pre-logon SYSTEM shell. GlobalFlag + SilentProcessExit keys achieve a launch-on-exit variant. Check `HKLM\SOFTWARE\...\Image File Execution Options` for any subkey with a `Debugger` value pointing outside `\Windows\`. `[MITRE T1546.012 / T1546.008 · high]`
- **COM hijacking favors the per-user hive precisely because it dodges admin and SOFTWARE-only parsing.** Redirecting a frequently-loaded CLSID's `InprocServer32` under `HKCU\Software\Classes\CLSID\{...}` (which lives in `UsrClass.dat`, not NTUSER.DAT) loads the attacker DLL into legitimate processes with no elevation. A responder parsing only SOFTWARE/SYSTEM misses it entirely — always parse `UsrClass.dat`. `[MITRE T1546.015 · high]`
- **A service can persist via ServiceDll (svchost) instead of ImagePath.** Netwalker-style and many APT loaders register under a shared `svchost` group with a `Parameters\ServiceDll` pointing at the malicious DLL, so the service's `ImagePath` is the legitimate `svchost.exe` — the malice is one key deeper. Inspect `Services\<name>\Parameters\ServiceDll`, not just `ImagePath`. `[MITRE T1543.003 / T1574.002 · high]`
- **Run-key value names are often randomized or impersonate Microsoft.** Commodity loaders write values named like `Windows Update`, `MicrosoftEdgeUpdate`, or a random GUID, pointing at `\AppData\Roaming\` or `\ProgramData\`. The tell is path + signature, not the name — a "Windows Update" value pointing at `%APPDATA%` is the foothold. `[MITRE T1547.001 · high]`
- **Persistence written by a trusted updater/RMM looks identical to supply-chain on one host.** If the persistence-creating parent (Security 4688) is a signed update/RMM process AND the same value lands on many hosts simultaneously, weigh supply-chain over a single-host intrusion before attributing. `[general DFIR tradecraft ⚠️verify]`

## ATT&CK mapping
- T1547.001 · Persistence · Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder — steps 2, 4
- T1543.003 · Persistence · Create or Modify System Process: Windows Service — steps 3, 6
- T1053.005 · Persistence · Scheduled Task/Job: Scheduled Task — step 7
- T1546.003 · Persistence · Event Triggered Execution: WMI Event Subscription — step 8
- T1546.012 · Persistence · Event Triggered Execution: Image File Execution Options Injection — step 2
- T1546.010 · Persistence · Event Triggered Execution: AppInit DLLs — step 2
- T1546.008 · Persistence · Event Triggered Execution: Accessibility Features (sethc/utilman via IFEO) — step 2
- T1546.015 · Persistence · Event Triggered Execution: Component Object Model Hijacking — step 4
- T1547.004 · Persistence · Boot or Logon Autostart Execution: Winlogon Helper DLL (Shell/Userinit) — step 2
- T1574.002 · Persistence/Privilege Escalation · Hijack Execution Flow: DLL Side-Loading (ServiceDll) — step 3
- T1112 · Defense Evasion · Modify Registry — steps 2-4, 10
- T1070.001 · Defense Evasion · Clear Windows Event Logs (1102/104 near key-write) — step 6
- T1012 · Discovery · Query Registry (responder + attacker) — steps 2-4
- T1204 · Execution · User Execution (payload first-run, UserAssist) — steps 4, 5

## Pivots (lead-to-lead graph)
- `on_service_install_event: windows-event-logs — corroborate the 7045/4688 around the service key`
- `on_userassist_or_shimcache_execution: windows-execution-artifacts — pin what ran and when from execution artifacts`
- `on_loader_binary_recovered: malware-analysis-triage — triage the persistence payload (hash/strings/packing)`
- `on_creating_account_anomalous: active-directory-domain — chase the account/credential that wrote the persistence`
- `on_remote_logon_before_keywrite: insider-threat-data-theft — assess what the foothold enabled (data access/theft)`
- `on_persistence_is_a_foothold_for_encryptor: ransomware-destructive — the persistence served a destructive payload`
- `on_linux_cron_systemd_foothold: linux-host-forensics — broader Linux host triage`
- `on_reconstruct_full_intrusion: attack-lifecycle-hunting — place the foothold in the full ATT&CK chain`
- `on_new_ioc_same_host: SELF — re-enter with the new binary/hash/path bound into #{variables}/#{time_window}`

## Jargon decoder
- **Registry / hive:** Windows' central settings database; a *hive* is one physical file of it (SYSTEM, SOFTWARE, NTUSER.DAT per user, UsrClass.dat per user, SAM, SECURITY).
- **Persistence:** any mechanism that re-launches the attacker's code after a reboot or logon.
- **Run / RunOnce key:** registry keys (`...\CurrentVersion\Run`) whose values each name a program to launch at logon/boot.
- **Service:** a background program Windows starts at boot; persistence sets a service's `ImagePath`/`ServiceDll` to the attacker binary.
- **ServiceDll:** a DLL loaded by a shared `svchost.exe` service — malice can hide here while `ImagePath` stays legitimate.
- **Scheduled task:** a job Windows runs on a trigger; leaves a registry footprint plus an XML under `\System32\Tasks\`.
- **WMI event subscription:** a filter→consumer→binding trio in the CIM repository that runs a payload on an event trigger (fileless-ish persistence).
- **AppInit_DLLs:** a registry list of DLLs loaded into nearly every GUI process — abused to inject a malicious DLL everywhere.
- **IFEO (Image File Execution Options):** registry keys meant for debugging; a `Debugger` value hijacks what runs when a named EXE launches.
- **COM hijacking:** redirecting a COM object's `InprocServer32`/`LocalServer32` CLSID to an attacker DLL so legit apps load it.
- **Winlogon Shell / Userinit:** registry values defining what runs at logon; editing them inserts attacker code into the logon path.
- **Key LastWrite:** the timestamp of the most recent change to a registry KEY (per-key, not per-value) — the registry's equivalent of a file mtime.
- **UserAssist:** an NTUSER.DAT record of GUI programs a user actually launched (execution evidence).
- **BAM / DAM:** Background/Desktop Activity Moderator registry records of programs that ran (execution evidence).
- **ShimCache (AppCompatCache):** a SYSTEM-hive record of programs *present on disk* — presence, NOT execution on modern Windows.
- **Amcache.hve:** a hive inventorying programs/drivers seen on disk, with SHA-1 — presence/inventory, not proof of execution.
- **Transaction logs (.LOG1/.LOG2) / `rla`:** a hive's pending-changes journal / the tool that replays it into a clean hive before parsing.
- **EVTX / EID:** Windows Event Log files / the numeric Event ID inside (7045 = service installed, 106 = task registered, 5861 = WMI consumer, 4688 = process started, 4624 = logon).
- **$MFT / $SI / $FN / timestomp:** NTFS master file index / its easy-to-forge ($SI) and harder-to-forge ($FN) timestamp sets / faking timestamps to hide arrival.
- **Prefetch / SRUM:** Windows execution-history artifacts — **no parser on this SIFT build** (PECmd/SrumECmd absent), so not relied on here.
- **CIM repository / OBJECTS.DATA:** the file backing WMI; read with `srch_strings` here (no native CIM parser on this box).
- **Super-timeline / bodyfile:** a merged chronology across many artifacts (`log2timeline`/`psort`) / an intermediate timeline format (`fls`/`mactime`).

## Tuning log (append-only — the eval loop writes here; humans never edit rows)
| date | case_id | bucket missed | delta applied |
|---|---|---|---|
