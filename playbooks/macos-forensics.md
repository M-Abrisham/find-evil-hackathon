---
attack_type: macos-forensics
category_id: macos-forensics
name: macOS Forensics
description: macOS plists, fseventsd, unified logs, login items and persistence
version: 1
os_coverage: [windows, linux, macos, cloud]
sub_types_covered: 8
sub_types:
  - launchagent-launchdaemon-persistence
  - login-items-persistence
  - tcc-privacy-grant-abuse
  - quarantine-gatekeeper-bypass-evidence
  - fsevents-file-activity-timeline
  - knowledgec-user-activity
  - safari-browser-artifacts
  - unified-log-analysis-offbox
validated_on: []
maturity: draft
variables:
  image_path:
    default: /cases/active/evidence/disk.E01
    derive: "Step 0 — first disk-evidence image (E01/dd/raw/vmdk) enumerated under the evidence directory named in the case brief"
  mount_root:
    default: /cases/active/mount
    derive: "Step 0 — directory where the APFS/HFS+ file system is mounted READ-ONLY (or where TSK-extracted artifacts land when mounting fails)"
  case_out:
    default: /cases/active/out
    derive: "Step 0 — writable case output directory from the case brief; Step 0 creates #{case_out}/receipts/ and #{case_out}/extracted/"
  ntfs_offset_sectors:
    default: 0
    derive: "Step 0 — start sector of the relevant partition from `mmls #{image_path}` (the APFS container / HFS+ partition on a Mac image, despite the NTFS-flavored name)"
  time_window:
    default: 1970-01-01..2099-12-31
    derive: "case brief if it names one; else first confirmed malicious timestamp plus-or-minus 48h once a step pins one — then re-scope wide sweeps to it"
---

## In one line
A Mac keeps its own diaries — small XML/binary settings files (plists), a file-activity log (fseventsd), a privacy-permission database (TCC), a download-origin tag (Quarantine), and a user-activity database (KnowledgeC). This playbook reads those Mac-specific diaries to prove what auto-started, what got permission to spy, where a file was downloaded from, and what the user actually did.

## Use this when (triggers)
- The evidence is a **Mac** (APFS or HFS+ file system, a `/System/Library/CoreServices/SystemVersion.plist`, `/Users/<name>/Library/` trees) rather than Windows or plain Linux.
- You suspect **auto-start persistence**: a LaunchAgent / LaunchDaemon plist, a login item, or a config-profile that re-launches a binary at boot or login.
- A program quietly got **privacy permissions** (camera, mic, full-disk, screen recording, accessibility) — possible **TCC** abuse to spy or to automate the GUI.
- You need to know where a file **came from** — was the **Quarantine / Gatekeeper** download tag stripped to bypass the "are you sure?" prompt?
- You need a **file-activity timeline** of creates/renames/deletes from **fseventsd**, or a **user-activity** record (app launches, focus, device usage) from **KnowledgeC**.
- You need **Safari** history/downloads, or the modern **Unified Log** — noting up front that the Unified Log (`.tracev3`) has NO working parser on this box and must be handed off.

## Quick path (the 90% case)
1. **Timeline-first.** Fold the whole mounted volume into one super-timeline with `log2timeline.py` then render with `psort.py` (its plist / fseventsd / utmpx / Safari / bsm parsers cover the Mac artifacts that work on this box). Skim it inside `#{time_window}` BEFORE committing to a story — the order of download-tag → permission-grant → persistence-install → first-run is the case. (mac_apt is BROKEN on this box — ModuleNotFoundError kaitaistruct — so route around it entirely; never call it.)
2. **Find the foothold.** Enumerate every persistence plist with `log2timeline.py` plist parser over `LaunchAgents`/`LaunchDaemons` (system, user, and `/Library/`), login items, and config profiles; a plist whose `ProgramArguments` points into `/tmp`, `/Users/Shared`, a dotfile, or a curl/bash one-liner is the lead.
3. **Find the privacy abuse.** Read `TCC.db` with `sqlite3` (mac_apt cannot) — a non-Apple binary holding `kTCCServiceScreenCapture`, `kTCCServiceMicrophone`, `kTCCServiceAccessibility`, or `kTCCServiceSystemPolicyAllFiles` is spyware-shaped.
4. **Find the origin.** Read `QuarantineEventsV2` (LSQuarantine) with `sqlite3` for the download URL/agent of the suspect binary; a missing quarantine xattr on a downloaded executable is a Gatekeeper-bypass tell.
5. **Corroborate user activity + execution.** Cross the persistence/TCC binary against `KnowledgeC.db` (app-launch/focus via `sqlite3`) and the fseventsd timeline (file create time). One artifact is a lead, not a fact.

If a download-origin, a permission grant, a persistence plist, and a first-run all line up on one timeline with a corroborating second source → you're mostly done. Otherwise drop into the full Steps. (The Unified Log, the richest modern source, can NOT be parsed here — flag it for off-box handoff and never read its silence as "nothing happened".)

## How it unfolds (the story)
An actor lands a Mac binary — a fake installer, a trojanized app, or a malicious script delivered by phishing. To run it past Gatekeeper they strip or never set the Quarantine download tag (`com.apple.quarantine`), or they trick the user through the right-click "Open" bypass. Once running it asks for — or silently grants itself via an Accessibility/automation chain — TCC privacy permissions (screen recording, mic, full-disk access) to surveil. For persistence it writes a LaunchAgent/LaunchDaemon plist or a login item so it relaunches at every login/boot. Each of these touches leaves a trace: the Quarantine database, the TCC database, the persistence plist, the fseventsd file-activity stream, and KnowledgeC user-activity — and the whole sequence is reconstructable from those plus the Unified Log handed off-box.

## Theories to test (and how to rule each out)
| Theory (who / why) | If true, you'd find… | Rule it out if… |
|---|---|---|
| **External-targeted (Mac malware / stealer foothold)** | a binary in `/tmp`, `/Users/Shared`, or a hidden dotfile with a LaunchAgent/Daemon plist; a stripped Quarantine tag or a download URL in `QuarantineEventsV2`; a self-granted TCC permission; first-run in KnowledgeC right after install | no non-Apple persistence plist, no anomalous TCC grant, every executable carries a normal `com.apple.quarantine` tag from a known vendor |
| **External-commodity (adware / PUP installer)** | a signed-but-unwanted helper LaunchAgent (e.g. a "search" or "update" agent), a Safari extension, browser-redirect config — noisy, often vendor-named | the agent maps to a sanctioned MDM/vendor profile and the user knowingly installed it; no privacy-surveillance TCC grant |
| **Insider (authorized user exfiltrating / hiding data)** | KnowledgeC/Spotlight showing access to sensitive files, USB/AirDrop activity, a Safari upload to webmail/cloud; persistence absent; full-disk TCC granted to a legit tool by the real user | activity matches the user's normal role and hours; no concealment, no anomalous off-host transfer |
| **Supply-chain / MDM-pushed (managed agent)** | a LaunchDaemon and config profile installed by `mdmclient`/an MDM payload landing on many hosts at once; a trusted parent; profile in `/var/db/ConfigurationProfiles` | the daemon is a user-dropped binary on this host only with no MDM/profile provenance → reclassify external |
| **Innocent / benign (NOT an attack)** | Apple-signed LaunchAgents/Daemons in `/System/Library/`, TCC grants the user clicked through for real apps (Zoom mic, screenshot tool), normal Quarantine tags, login items the user added | a clear sanctioned reason explains the agent/grant/login-item AND the binary is Apple- or known-vendor-signed and expected → benign, reclassify |

*(at least 1 benign + at least 1 malicious, each ACTIVELY refuted. Attacker types mapped: insider · other-insider · external-commodity · external-targeted · supply-chain · innocent.)*

## Evidence → Tool → What it reveals (per OS)
| Evidence | SIFT tool | What it tells you *for this attack* | OS |
|---|---|---|---|
| LaunchAgents / LaunchDaemons plists (`/System/Library/`, `/Library/`, `~/Library/LaunchAgents`) | `log2timeline.py` plist parser + `psort.py`; `plutil` if present else `srch_strings` | The auto-start persistence: Label, ProgramArguments path, RunAtLoad/KeepAlive — a non-Apple binary in a user/temp path is the foothold | macOS |
| Login items / `backgrounditems.btm` / `com.apple.loginitems` plist | `log2timeline.py` plist parser; `srch_strings` on the plist | Per-user auto-launch at login — a second persistence class beyond launchd | macOS |
| `TCC.db` (`/Library/Application Support/com.apple.TCC/` and per-user) | `sqlite3` (mac_apt is BROKEN here — use sqlite3) | Which app got which privacy permission (screen/mic/camera/accessibility/full-disk) and when — surveillance/automation abuse | macOS |
| `QuarantineEventsV2` / `com.apple.quarantine` xattr (LSQuarantine) | `sqlite3` on the DB; `srch_strings`/`fls` for the xattr presence | Download origin URL + agent of a dropped file; a MISSING tag on a downloaded executable = Gatekeeper-bypass evidence | macOS |
| `fseventsd` (`/.fseventsd/`) | `log2timeline.py` fseventsd parser + `psort.py` | A file-activity timeline (create/rename/delete) — places the dropper/payload write even if the file was later deleted | macOS |
| `KnowledgeC.db` (`~/Library/Application Support/Knowledge/`) | `sqlite3` (mac_apt is BROKEN here) | User activity: app launch / focus / in-focus duration / device usage — first-run and use of the suspect binary | macOS |
| Safari `History.db` / `Downloads.plist` (`~/Library/Safari/`) | `sqlite3` on History.db; `log2timeline.py` for the plist | Browsing + download history — the delivery URL and what was fetched | macOS |
| Spotlight `store.db` / `.store.db` | `log2timeline.py` (Spotlight parser) + `psort.py` | Metadata index of files seen (names/paths/kinds) — corroborates a dropped file's existence and path | macOS |
| ASL `*.asl` + `utmpx` (`/var/log/asl/`, `/var/run/utmpx`) | `log2timeline.py` (asl/utmpx parsers) + `psort.py` | Legacy syslog + console-logon records (who logged in at the console) — the pre-Unified-Log auth trail | macOS |
| APFS container layout / file metadata | `fsapfsinfo` (libfsapfs); `fls`/`istat`/`icat` (TSK over APFS) | Volume/snapshot layout and per-file MAC times; recover a deleted dropper by inode when mounting fails | macOS |
| Unified Log (`.tracev3` under `/var/db/diagnostics/`) | NONE on this box — `log collect` / UnifiedLogReader OFF-BOX handoff (`⚠️verify`) | The richest modern log (process exec, network, auth) — but NO parser here; collect and parse on a macOS host or with UnifiedLogReader off-box | macOS |
| Image-wide string sweep | `bstrings` / `srch_strings` / `bulk_extractor` | URLs, plist Labels, paths, and command fragments spilled outside the structured artifacts | all |

*The Unified Log is a TRUE GAP on this box (mac_apt broken, no UnifiedLogReader, `log` is macOS-only) — treat any empty unified-log result as DEGRADED, never as "no activity". `⚠️verify` off-box.*

## Step 0 — evidence inventory & access bootstrap
- n: 0
  tool: |
    mkdir -p "#{case_out}/receipts" "#{case_out}/extracted" && ls -laR "#{mount_root}" > "#{case_out}/receipts/00.txt" 2>&1 ; img_stat "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; mmls "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; fsstat -o #{ntfs_offset_sectors} "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; fsapfsinfo "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; find "#{mount_root}" -maxdepth 3 -iname "SystemVersion.plist" -o -iname "*.fseventsd" >> "#{case_out}/receipts/00.txt" 2>&1
  expect: every evidence file classified; #{image_path}, #{mount_root}, #{ntfs_offset_sectors}, #{case_out} bound; read-only access proven; an APFS/HFS+ Mac volume confirmed (SystemVersion.plist, /Users, /.fseventsd present) or its absence recorded
  check: |
    test -r "#{mount_root}" -o -n "$(ls "#{case_out}/extracted" 2>/dev/null)"
  falsify: evidence dir empty/unreadable, or no supported image format found, or no APFS/HFS+ Mac volume present
  on_result: {expect_met: goto 1, falsify_met: STOP — report acquisition/access failure; pivot acquisition-custody, neither: try the TSK fallback (fls to find the Library/.fseventsd inodes, icat each artifact into #{case_out}/extracted); if that also fails treat as falsify_met}
  emits: [key_artifacts]
  serves: [launchagent-launchdaemon-persistence, login-items-persistence, tcc-privacy-grant-abuse, quarantine-gatekeeper-bypass-evidence, fsevents-file-activity-timeline, knowledgec-user-activity, safari-browser-artifacts, unified-log-analysis-offbox]
  provenance: {receipt_id: 00, artifact: evidence directory listing + Mac-volume enumeration, offset_or_row: full listing, literal_cited: image filename + SystemVersion.plist/.fseventsd presence}

## Steps (executable — decision-driven)
- n: 1
  precondition: "os == macos; test -r #{mount_root}"
  tool: |
    log2timeline.py --status_view none "#{case_out}/macos.plaso" "#{mount_root}" > "#{case_out}/receipts/01.txt" 2>&1 ; psort.py -o l2tcsv "#{case_out}/macos.plaso" > "#{case_out}/super.csv" 2>> "#{case_out}/receipts/01.txt" ; pinfo.py "#{case_out}/macos.plaso" >> "#{case_out}/receipts/01.txt" 2>&1
  expect: a fused super-timeline (#{case_out}/super.csv) whose pinfo confirms the plist, fseventsd, macos_securityd/utmpx, spotlight and safari parsers ran — the timeline-first artifact every later step filters inside #{time_window}
  check: |
    test -s "#{case_out}/super.csv" && grep -qiE "plist|fseventsd|spotlight|safari|utmpx" "#{case_out}/super.csv"
  falsify: log2timeline produced no events, or pinfo shows no Mac parsers ran (wrong OS image, or the volume failed to mount)
  on_result: {expect_met: goto 2, falsify_met: confirm OS family from Step 0 fsstat/fsapfsinfo; if this is not a Mac image run the Linux branch or pivot disk-filesystem, neither: re-run log2timeline scoped to specific dirs (Library, .fseventsd) and re-render psort.py; if mount is partial fall back to TSK extraction into #{case_out}/extracted}
  emits: [timeline_events]
  serves: [fsevents-file-activity-timeline, safari-browser-artifacts]
  provenance: {receipt_id: 01, artifact: mounted Mac volume (plist/fseventsd/spotlight/safari/utmpx), offset_or_row: super.csv header + pinfo parser list, literal_cited: pinfo parser names line}

- n: 2
  precondition: "exists #{case_out}/super.csv"
  tool: |
    find "#{mount_root}" -path "*LaunchAgents*" -o -path "*LaunchDaemons*" -o -iname "*loginitems*" -o -iname "backgrounditems.btm" > "#{case_out}/receipts/02.txt" 2>&1 ; grep -iE "LaunchAgents|LaunchDaemons|loginitems|backgrounditems|com.apple.loginitems" "#{case_out}/super.csv" >> "#{case_out}/receipts/02.txt" 2>&1 ; for p in $(find "#{mount_root}" -path "*LaunchAgents*" -name "*.plist" -o -path "*LaunchDaemons*" -name "*.plist" 2>/dev/null); do echo "=== $p ===" >> "#{case_out}/receipts/02.txt" ; srch_strings "$p" >> "#{case_out}/receipts/02.txt" 2>&1 ; done
  expect: a LaunchAgent/LaunchDaemon plist or login item whose ProgramArguments/Program path points to a non-Apple binary in a suspicious location (/tmp, /Users/Shared, /private/var, a hidden dotfile, or a curl/bash one-liner), with RunAtLoad/KeepAlive set — the persistence foothold
  check: |
    grep -qiE "/tmp/|/Users/Shared/|/private/var/|RunAtLoad|ProgramArguments|KeepAlive|curl|/bin/sh|/bin/bash" "#{case_out}/receipts/02.txt"
  falsify: every persistence plist resolves to an Apple-signed binary under /System/Library or a known-vendor/MDM path — no anomalous auto-start
  on_result: {expect_met: record the plist Label + binary path as an IOC; goto 3, falsify_met: record "no anomalous launchd/login-item persistence"; continue to TCC at goto 3, neither: widen #{time_window}; parse each plist individually (plutil if present else srch_strings) and re-check; check config profiles under /var/db/ConfigurationProfiles}
  emits: [key_iocs, key_artifacts]
  serves: [launchagent-launchdaemon-persistence, login-items-persistence]
  provenance: {receipt_id: 02, artifact: LaunchAgents/LaunchDaemons/loginitems plists, offset_or_row: receipt block per plist, literal_cited: Label + ProgramArguments binary path}

- n: 3
  precondition: "exists #{case_out}/super.csv; test -r #{mount_root}"
  tool: |
    for db in $(find "#{mount_root}" -iname "TCC.db" 2>/dev/null); do echo "=== $db ===" >> "#{case_out}/receipts/03.txt" ; sqlite3 -readonly "$db" "SELECT service, client, auth_value, auth_reason, last_modified FROM access ORDER BY last_modified;" >> "#{case_out}/receipts/03.txt" 2>&1 ; done
  expect: a TCC.db `access` row granting a non-Apple client a high-power privacy service — kTCCServiceScreenCapture, kTCCServiceMicrophone, kTCCServiceCamera, kTCCServiceAccessibility, or kTCCServiceSystemPolicyAllFiles (full-disk) — with an auth_value of 2 (allowed), timed near the persistence install
  check: |
    grep -qiE "kTCCServiceScreenCapture|kTCCServiceMicrophone|kTCCServiceCamera|kTCCServiceAccessibility|kTCCServiceSystemPolicyAllFiles|kTCCServicePostEvent" "#{case_out}/receipts/03.txt"
  falsify: every TCC grant maps to an Apple or known-vendor app the real user clicked through (Zoom mic, a screenshot tool) — no surveillance-shaped grant to the suspect binary
  on_result: {expect_met: record the client + service as a privacy-abuse IOC; goto 4, falsify_met: record "no anomalous TCC privacy grant"; continue to Quarantine at goto 4, neither: read the per-user TCC.db under each ~/Library/Application Support/com.apple.TCC; if TCC.db absent record absence and lean on the persistence + KnowledgeC evidence}
  emits: [key_iocs, actor_accounts]
  serves: [tcc-privacy-grant-abuse]
  provenance: {receipt_id: 03, artifact: TCC.db access table, offset_or_row: access row, literal_cited: service + client bundle id + auth_value}

- n: 4
  precondition: "exists #{case_out}/super.csv; test -r #{mount_root}"
  tool: |
    for q in $(find "#{mount_root}" -iname "*QuarantineEventsV2*" 2>/dev/null); do echo "=== $q ===" >> "#{case_out}/receipts/04.txt" ; sqlite3 -readonly "$q" "SELECT LSQuarantineTimeStamp, LSQuarantineAgentName, LSQuarantineDataURLString, LSQuarantineOriginURLString FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp;" >> "#{case_out}/receipts/04.txt" 2>&1 ; done ; fls -r -o #{ntfs_offset_sectors} "#{image_path}" 2>/dev/null | grep -iE "com.apple.quarantine" >> "#{case_out}/receipts/04.txt" 2>&1
  expect: a QuarantineEventsV2 row giving the download URL + agent (browser/curl) for the suspect binary; OR — the high-signal case — a downloaded executable that has NO com.apple.quarantine xattr at all (tag stripped to bypass Gatekeeper), inside #{time_window}
  check: |
    grep -qiE "LSQuarantineDataURLString|LSQuarantineOriginURLString|http|com.apple.quarantine" "#{case_out}/receipts/04.txt"
  falsify: the suspect binary carries a normal quarantine tag from a sanctioned source (App Store / known vendor) and the URL is legitimate — no Gatekeeper bypass
  on_result: {expect_met: record the download URL/agent (or the stripped-tag fact) as an IOC; goto 5, falsify_met: record "download origin legitimate, quarantine intact"; continue to fseventsd at goto 5, neither: if QuarantineEventsV2 is absent record absence; cross-check Safari Downloads.plist/History.db (step 6) for the delivery URL}
  emits: [key_iocs, exfil_or_encryption_facts]
  serves: [quarantine-gatekeeper-bypass-evidence]
  provenance: {receipt_id: 04, artifact: QuarantineEventsV2 LSQuarantineEvent table / quarantine xattr, offset_or_row: LSQuarantineEvent row, literal_cited: download URL + agent name or missing-tag note}

- n: 5
  precondition: "exists #{case_out}/super.csv"
  tool: |
    grep -iE "fseventsd" "#{case_out}/super.csv" > "#{case_out}/receipts/05.txt" 2>&1 ; grep -iE "/tmp/|/Users/Shared/|LaunchAgents|LaunchDaemons|.plist" "#{case_out}/super.csv" >> "#{case_out}/receipts/05.txt" 2>&1
  expect: fseventsd events placing the dropper/payload write (create/rename) and the persistence plist creation in #{time_window} — the file-activity timeline that pins WHEN the foothold landed, even if the file was later deleted
  check: |
    grep -qiE "fseventsd|Created|Renamed|.plist" "#{case_out}/receipts/05.txt"
  falsify: no fseventsd create/rename for the suspect path in #{time_window}, and the persistence plist's filesystem create time is outside the incident window — the foothold did not land here/then
  on_result: {expect_met: record the create time as a timeline anchor; goto 6, falsify_met: record "no fseventsd corroboration in window"; widen #{time_window} and re-check, neither: parse /.fseventsd directly via log2timeline scoped to it; fall back to fls/istat MAC times on the plist inode for the create time}
  emits: [timeline_events]
  serves: [fsevents-file-activity-timeline]
  provenance: {receipt_id: 05, artifact: fseventsd file-activity stream, offset_or_row: super.csv fseventsd rows, literal_cited: Created/Renamed event for the dropper/plist path}

- n: 6
  precondition: "exists #{case_out}/super.csv; test -r #{mount_root}"
  tool: |
    for k in $(find "#{mount_root}" -iname "KnowledgeC.db" 2>/dev/null); do echo "=== $k ===" >> "#{case_out}/receipts/06.txt" ; sqlite3 -readonly "$k" "SELECT ZOBJECT.ZSTREAMNAME, ZOBJECT.ZVALUESTRING, datetime(ZOBJECT.ZSTARTDATE+978307200,'unixepoch') FROM ZOBJECT WHERE ZSTREAMNAME LIKE '%app%' ORDER BY ZOBJECT.ZSTARTDATE;" >> "#{case_out}/receipts/06.txt" 2>&1 ; done ; for h in $(find "#{mount_root}" -path "*Safari*" -iname "History.db" 2>/dev/null); do echo "=== $h ===" >> "#{case_out}/receipts/06.txt" ; sqlite3 -readonly "$h" "SELECT datetime(visit_time+978307200,'unixepoch'), url FROM history_visits JOIN history_items ON history_items.id=history_visits.history_item ORDER BY visit_time;" >> "#{case_out}/receipts/06.txt" 2>&1 ; done
  expect: a KnowledgeC ZOBJECT app-launch/focus row for the suspect bundle id right after install (first-run), AND/OR a Safari history/download row showing the delivery URL — user-activity + browser corroboration of the foothold
  check: |
    grep -qiE "com.apple.knowledge|ZVALUESTRING|/app/usage|http|app/inFocus|app/activity" "#{case_out}/receipts/06.txt"
  falsify: KnowledgeC has no launch/focus record for the suspect binary AND Safari shows no related download/visit — no user-activity or browser trace of it
  on_result: {expect_met: record first-run time + delivery URL; goto 7, falsify_met: record "no KnowledgeC/Safari corroboration (single-source persistence)"; goto 7, neither: query KnowledgeC /app/inFocus and device-usage streams; check Chrome/Chromium history via the browser playbook; widen #{time_window}}
  emits: [key_iocs, actor_accounts, timeline_events]
  serves: [knowledgec-user-activity, safari-browser-artifacts]
  provenance: {receipt_id: 06, artifact: KnowledgeC ZOBJECT / Safari History.db, offset_or_row: ZOBJECT row / history_visits row, literal_cited: bundle id + start time or visited URL}

- n: 7
  precondition: "exists #{case_out}/super.csv"
  tool: |
    echo "UNIFIED LOG OFF-BOX HANDOFF — .tracev3 has NO parser on this box" > "#{case_out}/receipts/07.txt" 2>&1 ; find "#{mount_root}" -path "*var/db/diagnostics*" -iname "*.tracev3" >> "#{case_out}/receipts/07.txt" 2>&1 ; grep -iE "plist|fseventsd|spotlight|safari|utmpx|TCC|Quarantine|KnowledgeC|LaunchAgent|LaunchDaemon" "#{case_out}/super.csv" | sort > "#{case_out}/receipts/07_super_sorted.txt" 2>> "#{case_out}/receipts/07.txt" ; head -50 "#{case_out}/receipts/07_super_sorted.txt" >> "#{case_out}/receipts/07.txt" 2>&1
  expect: the .tracev3 Unified Log files are ENUMERATED and recorded as present-but-unparseable (off-box handoff named), AND the cross-artifact order download-origin → TCC grant → persistence plist → first-run holds coherently on the sorted super-timeline inside #{time_window}, with no unexplained gap
  check: |
    test -s "#{case_out}/receipts/07_super_sorted.txt" && grep -qiE "plist|fseventsd|TCC|Quarantine|KnowledgeC|LaunchAgent" "#{case_out}/receipts/07_super_sorted.txt"
  falsify: the cross-artifact ordering is impossible (e.g. first-run precedes the download), OR an unexplained multi-hour gap that no anti-forensics accounts for — the story does not hold
  on_result: {expect_met: COMMIT the conclusion with a confidence label; flag the Unified Log for off-box parsing (log collect / UnifiedLogReader) before final close; close per the gate, falsify_met: re-open the Theories table; a gap/inversion may indicate clock manipulation or a deleted artifact — anchor to fseventsd/USN-equivalent order over host time, neither: re-render psort.py scoped to #{time_window}; confirm the parser set via pinfo.py and re-check}
  emits: [timeline_events, key_artifacts]
  serves: [unified-log-analysis-offbox]
  provenance: {receipt_id: 07, artifact: super-timeline order + .tracev3 enumeration, offset_or_row: 07_super_sorted.txt ordered rows, literal_cited: ordered origin→TCC→persistence→run chain + tracev3 filenames}

## Linux branch (L1..Ln) — REQUIRED, numbered, same step shape
- n: L1
  precondition: "os == linux"
  tool: |
    fsstat -o #{ntfs_offset_sectors} "#{image_path}" > "#{case_out}/receipts/L01.txt" 2>&1 ; find "#{mount_root}" -maxdepth 2 -iname "SystemVersion.plist" -o -path "*System/Library/CoreServices*" >> "#{case_out}/receipts/L01.txt" 2>&1 ; ls "#{mount_root}/etc/os-release" "#{mount_root}/var/log" >> "#{case_out}/receipts/L01.txt" 2>&1
  expect: this image is NOT macOS (no APFS/HFS+, no SystemVersion.plist, no /Users/<name>/Library Mac tree) — macOS plists/fseventsd/TCC/KnowledgeC/Unified-Log artifacts do NOT exist here; record "macOS-only because this evidence is not an Apple system" and route to the Linux/Windows playbook
  check: |
    test -f "#{mount_root}/etc/os-release" -o -n "$(grep -iE 'ext[234]|xfs' "#{case_out}/receipts/L01.txt" 2>/dev/null)"
  falsify: fsstat reports APFS/HFS+ and a SystemVersion.plist / Mac Library tree exists — this IS macOS; return to the main Steps 1–7, this branch does not apply
  on_result: {expect_met: record "macOS-only category — evidence is Linux, not an Apple system"; goto L2, falsify_met: this is macOS — run the main macOS Steps 1–7 not this branch, neither: confirm OS family from the Step 0 fsstat/fsapfsinfo receipt; if still ambiguous treat as non-macOS and stop this playbook}
  emits: [key_artifacts]
  serves: [unified-log-analysis-offbox]
  provenance: {receipt_id: L01, artifact: fsstat + OS-marker file listing, offset_or_row: fsstat header + os-release presence, literal_cited: ext/xfs FS type or /etc/os-release present (non-macOS confirmed)}

- n: L2
  precondition: "os == linux"
  tool: |
    log2timeline.py --status_view none "#{case_out}/linux.plaso" "#{mount_root}/var/log" > "#{case_out}/receipts/L02.txt" 2>&1 ; psort.py -o l2tcsv "#{case_out}/linux.plaso" > "#{case_out}/linux_super.csv" 2>> "#{case_out}/receipts/L02.txt" ; srch_strings "#{mount_root}/var/log/auth.log" 2>/dev/null | grep -iE "accepted|failed password|sudo|cron" >> "#{case_out}/receipts/L02.txt" 2>&1
  expect: because macOS artifacts are absent, the Linux equivalents stand in — SSH logons in auth.log (the macOS console/utmpx analog), systemd-unit/cron persistence (the LaunchDaemon analog), and a /var/log super-timeline — recorded as the cross-platform handoff, NOT as macOS evidence
  check: |
    test -s "#{case_out}/linux_super.csv" -o -s "#{case_out}/receipts/L02.txt"
  falsify: /var/log empty or wiped (auth.log truncated to zero) — Linux anti-forensics; record the gap as a finding
  on_result: {expect_met: record the Linux persistence/logon equivalents; hand off to the Linux playbook, falsify_met: record log-wipe/gap as a finding; carve deleted log fragments with srch_strings over unallocated; pivot linux-host-forensics, neither: widen #{time_window}; check journald under /var/log/journal via log2timeline and re-render}
  emits: [actor_accounts, timeline_events]
  serves: [launchagent-launchdaemon-persistence]
  provenance: {receipt_id: L02, artifact: /var/log/auth.log + journal, offset_or_row: linux_super.csv rows / grep hits, literal_cited: Accepted/Failed password line + source IP}

## Corroboration (two-source rule)
`required_sources: 2` · `pairs:`
- `[ LaunchAgent/Daemon plist (step 2) ↔ fseventsd plist-create time / TSK istat MAC time (step 5) ]`
- `[ TCC privacy grant (step 3) ↔ the same client bundle id as a persistence binary (step 2) ]`
- `[ QuarantineEventsV2 download URL (step 4) ↔ Safari History.db / Downloads visit (step 6) ]`
- `[ persistence binary path (step 2) ↔ KnowledgeC first-run app-launch (step 6) ]`
- `[ stripped com.apple.quarantine xattr (step 4) ↔ fseventsd create of that file (step 5) ]`
- `[ cross-artifact chronology (step 1) ↔ sorted super-timeline order (step 7) ]`

One hit is a *lead*; promote to *fact* only when its paired source agrees.

## Don't get fooled (red flags & anti-forensics)
- **mac_apt is BROKEN on this box.** An empty mac_apt result is a tool failure (ModuleNotFoundError kaitaistruct), NOT evidence of absence — never run it and never read its silence as "clean". Route every macOS artifact through plaso (FSEvents/plist/ASL/Spotlight/Safari/utmpx) or `sqlite3` (TCC/KnowledgeC/Quarantine).
- **The Unified Log can NOT be parsed here.** `.tracev3` has no on-box parser; an empty unified-log result is DEGRADED, not "no activity". Enumerate the files and hand them off (`log collect` / UnifiedLogReader) on a macOS host — `⚠️verify`. Do not close the case on its silence.
- **A missing quarantine tag is itself a finding.** Attackers strip `com.apple.quarantine` (or never set it) to skip Gatekeeper's prompt. A downloaded executable with NO quarantine xattr is a bypass signal — absence is evidence here.
- **TCC grants can be forged or inherited.** A binary that holds Accessibility can grant itself further TCC permissions and drive the GUI; read the `auth_reason` and the client path, and distrust a grant whose client lives in /tmp or a dotfile even if auth_value=2.
- **Plist timestomp / launchd relocation.** A persistence plist's filesystem time can be backdated; trust the fseventsd create event and the inode $FN-equivalent MAC times over the plist's own mtime. Persistence also hides in config profiles (`/var/db/ConfigurationProfiles`), `emond`, and periodic scripts — check beyond LaunchAgents.
- **Deleted droppers.** A binary run-then-deleted leaves no file but DOES leave an fseventsd create/delete pair, a KnowledgeC launch, a TCC/Quarantine row, and a Spotlight remnant. Missing file ≠ no execution.
- **APFS snapshots hide prior states.** A clean live volume may have a snapshot holding the deleted dropper; enumerate snapshots with `fsapfsinfo` and don't assume the mounted state is the whole story. **Missing evidence is itself a finding.**

## Failure modes
```
- mode: evidence-access failure — the APFS/HFS+ volume won't mount or the Library tree is unreadable
  guard: Step 0 fallback chain — ewfmount/loop RO, else TSK fls/icat the TCC.db/KnowledgeC.db/plist/.fseventsd inodes into #{case_out}/extracted; if all fail record acquisition failure and pivot acquisition-custody
- mode: primary-artifact-absent — TCC.db / KnowledgeC.db / QuarantineEventsV2 / persistence plist missing or empty
  guard: record the absence as a finding (a stripped quarantine tag or absent persistence is itself evidence); name the secondary sources (fseventsd timeline, Spotlight, Safari, super-timeline) and corroborate there
- mode: tool-output drift — a plaso parser name or a sqlite3 column (ZOBJECT/LSQuarantineEvent schema) changes so a check literal misses
  guard: on check exit 2 adjudicate from the prose expect/falsify against the receipt, cap confidence at inferred; `.schema` the DB with sqlite3 to recover the real column names, never silently pass
- mode: mac_apt invoked by reflex — it is BROKEN here (kaitaistruct) and returns empty
  guard: NEVER place mac_apt in an executable line; route KnowledgeC/TCC/Quarantine via sqlite3 and FSEvents/plist/ASL/Spotlight/Safari/utmpx via plaso; an empty mac_apt result is a tool failure, not absence
- mode: Unified Log unparseable — .tracev3 has no on-box parser
  guard: enumerate the .tracev3 files, record present-but-unparsed, and flag the off-box handoff (log collect / UnifiedLogReader on a macOS host); `⚠️verify`; do not read its silence as "no activity"
```
Minimum set every playbook covers: evidence-access failure (Step 0 fallback chain) · primary-artifact-absent (absence recorded, secondary source named) · tool-output drift (`check` exits 2 → prose adjudication, never silent pass).

## Confidence labeling (observation → inference → conclusion)
- **confirmed:** direct receipt verbatim (e.g. the TCC `access` row or the plist ProgramArguments) + at least 2 independent sources agree (persistence plist + fseventsd create + KnowledgeC launch, or Quarantine URL + Safari history) + no unrefuted counter-theory.
- **inferred:** grounded but single-source/interpretive — e.g. a persistence plist with no fseventsd/KnowledgeC corroboration yet, a TCC grant read as abuse without a matching binary, or anything keyed to a degraded/absent Unified Log → hedge and tag `⚠️verify`. Every `check`-exit-2 adjudication lands here at best.
- **insufficient_evidence:** precondition unmet (volume won't mount; TCC.db/KnowledgeC.db absent; Unified Log unparseable and not handed off) or sources conflict → abstain; state what's missing, do not guess.

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
- **macOS:** fully covered above — plists (launchd/login-item persistence), TCC.db (privacy abuse), QuarantineEventsV2 (download origin / Gatekeeper bypass), fseventsd (file-activity timeline), KnowledgeC.db (user activity), Safari (browser), Spotlight/ASL/utmpx (metadata + legacy auth). mac_apt is BROKEN (route around it); the Unified Log is an off-box handoff.
- **Windows:** these Mac artifacts do not exist — the analogs are EVTX event logs, the registry (Run keys/services for persistence), Amcache/ShimCache, and `$MFT`/`$UsnJrnl`. Investigate via the Windows playbooks, not this one.
- **Linux/ESXi:** no plists/TCC/launchd — see the numbered Linux branch (L1–L2). Equivalents: `auth.log`/`secure` (the console/utmpx analog), systemd units and cron (the LaunchDaemon analog), the journal under `/var/log/journal`. Hand off to `linux-host-forensics`.
- **Cloud:** not applicable directly — if the Mac is enrolled in an MDM/cloud identity, the management side (config-profile push, device sign-in) lives in the cloud audit logs; investigate there via `cloud-identity-saas`.

## Real-case notes (non-obvious things to look for)
- **A stripped `com.apple.quarantine` tag is the loud Gatekeeper-bypass tell.** Real Mac malware (and the right-click "Open" trick) drops an executable with NO quarantine xattr so Gatekeeper never prompts; the QuarantineEventsV2 row may also be deleted. Test for the *absence* of the tag on downloaded binaries, not just for a bad URL. `[Apple Gatekeeper docs / MITRE T1553.001 · high]`
- **TCC abuse via Accessibility is the privilege-escalation pivot.** Malware that gets `kTCCServiceAccessibility` can drive the GUI and grant itself further TCC permissions (screen recording, full-disk) without another user click; an Accessibility grant to a non-Apple binary in a user/temp path is high-signal. `[Apple TCC / MITRE T1548 · med]`
- **LaunchAgents vs LaunchDaemons tells you the privilege.** A `~/Library/LaunchAgents` plist runs as the user at login; a `/Library/LaunchDaemons` plist runs as root at boot — the latter implies the actor already had admin. A blank/spoofed `Label` mimicking `com.apple.*` is a classic disguise. `[MITRE T1543.001 / T1543.004 · high]`
- **fseventsd survives the file it describes.** Even after a dropper is deleted, `/.fseventsd` retains the create/rename/delete events, so the file-activity timeline can prove a payload existed and when — pair it with Spotlight remnants. `[macOS DFIR practice · med]`
- **KnowledgeC is the macOS "what the user did" goldmine.** `ZOBJECT` rows record app launches, in-focus duration, and device usage with Apple-epoch timestamps (add 978307200 to convert) — it pins first-run of a malicious app even when nothing else logged it. `[macOS DFIR practice · med]`
- **The Unified Log holds the richest exec/network/auth trail but is unreadable on this box.** `.tracev3` needs a macOS host or UnifiedLogReader off-box; an empty result here means "not parsed", never "nothing happened" — always enumerate and hand off. `⚠️verify any conclusion that depends on it.` `[OS-Coverage-Matrix §C macOS gap · high]`
- **Persistence hides beyond LaunchAgents.** Config profiles (`/var/db/ConfigurationProfiles`), `emond` rules, periodic scripts, login/logout hooks, and a malicious Safari extension are all auto-start vectors a LaunchAgents-only sweep misses. `[MITRE T1543 / T1176 · med]`

## ATT&CK mapping
- T1547.011 · Persistence · Boot or Logon Autostart — Plist Modification · LaunchAgent/Daemon ProgramArguments — step 2
- T1543.001 · Persistence · Launch Agent · `~/Library/LaunchAgents` plist with RunAtLoad — step 2
- T1543.004 · Persistence · Launch Daemon · `/Library/LaunchDaemons` plist running as root — step 2
- T1547.015 · Persistence · Login Items · backgrounditems.btm / com.apple.loginitems — step 2
- T1548.006 · Privilege Escalation · TCC Manipulation · self-granted privacy permission via Accessibility — step 3
- T1113 · Collection · Screen Capture · kTCCServiceScreenCapture grant — step 3
- T1123 · Collection · Audio Capture · kTCCServiceMicrophone grant — step 3
- T1553.001 · Defense Evasion · Gatekeeper Bypass · stripped com.apple.quarantine xattr — step 4
- T1189 / T1204.002 · Initial Access / Execution · Drive-by / Malicious File · download URL in QuarantineEventsV2 + Safari history — steps 4/6
- T1070.006 · Defense Evasion · Timestomp · backdated plist mtime vs fseventsd create — steps 2/5
- T1547 · Persistence · Boot/Logon Autostart (config profiles, emond, periodic, login hooks) — Real-case notes
- T1176 · Persistence · Browser Extension · malicious Safari extension — Real-case notes

## Pivots (lead-to-lead graph)
- `on_launchd_or_loginitem_persistence (step 2 plist path): windows-registry-persistence — the cross-OS autorun analog; confirm the persistence class and parent`
- `on_tcc_privacy_grant (step 3 surveillance service): malware-analysis-triage — triage the binary that holds the camera/mic/screen permission`
- `on_download_origin_or_gatekeeper_bypass (step 4 URL / stripped tag): browser-email-documents — chase the delivery URL, phishing lure, and download chain`
- `on_safari_or_knowledgec_activity (step 6 visit / app-launch): browser-email-documents — full browser history/download corroboration`
- `on_deleted_dropper_or_snapshot (step 5 fseventsd create with no live file): file-recovery-carving — recover the payload from unallocated / an APFS snapshot`
- `on_unified_log_handoff_needed (step 7 .tracev3 present-unparsed): acquisition-custody — re-acquire / collect the Unified Log on a macOS host for off-box parsing`
- `on_managed_or_mdm_persistence (step 2 MDM/config-profile daemon): cloud-identity-saas — the cloud/management side of the pushed agent`
- `on_unclear_origin_or_new_ioc (any step): SELF — re-enter with the new path/URL/bundle-id bound into #{time_window}`

## Jargon decoder
- **plist (property list):** a macOS settings file (XML or binary) storing app/system config — including auto-start definitions.
- **LaunchAgent / LaunchDaemon:** launchd auto-start configs; an **Agent** runs as the logged-in user at login, a **Daemon** runs as root at boot — the top macOS persistence mechanism.
- **launchd:** the macOS init/service manager that reads those plists and starts the programs.
- **login item / backgrounditems.btm:** per-user programs set to auto-launch at login — a second persistence class.
- **TCC (Transparency, Consent & Control):** the macOS privacy system; `TCC.db` records which app got which permission (camera, mic, screen recording, accessibility, full-disk access).
- **TCC service strings:** e.g. `kTCCServiceScreenCapture` (screen recording), `kTCCServiceMicrophone`, `kTCCServiceCamera`, `kTCCServiceAccessibility` (drive the GUI), `kTCCServiceSystemPolicyAllFiles` (full-disk access).
- **Quarantine / `com.apple.quarantine`:** the extended attribute Gatekeeper sets on downloaded files; **QuarantineEventsV2 / LSQuarantine** is the database of download origins. A missing tag = a Gatekeeper-bypass tell.
- **Gatekeeper:** the macOS gate that prompts/blocks unsigned or unquarantined downloads before they run.
- **fseventsd:** the macOS file-system-events daemon; `/.fseventsd` is a coarse log of file create/rename/delete activity — survives the files it describes.
- **KnowledgeC.db:** a SQLite database of user activity (app launches, in-focus time, device usage); `ZOBJECT` is its main table, timestamps are Apple-epoch (add 978307200 for Unix time).
- **Unified Log / `.tracev3`:** the modern macOS log (process/network/auth) in binary `.tracev3` files under `/var/db/diagnostics/` — NO parser on this box, an off-box handoff.
- **Spotlight `store.db`:** the macOS metadata index of files seen on the volume — corroborates a file's existence/path.
- **ASL / utmpx:** the legacy Apple System Log and the console-logon record — the pre-Unified-Log auth trail.
- **APFS / HFS+:** the modern / legacy Mac file systems; APFS supports **snapshots** that can hide a deleted dropper's prior state.
- **xattr (extended attribute):** out-of-band metadata on a file (where `com.apple.quarantine` lives).
- **MDM / config profile:** Mobile Device Management push and its `/var/db/ConfigurationProfiles` payloads — a managed (and abusable) persistence/control path.

## Tuning log (append-only — the eval loop writes here; humans never edit rows)
| date | case_id | bucket missed | delta applied |
|---|---|---|---|
