---
attack_type: active-directory-domain
category_id: active-directory-domain
name: Active Directory & Domain
description: "domain compromise: credential theft, Kerberos abuse, NTDS extraction and domain-controller artifacts"
version: 1
os_coverage: [windows, linux, macos, cloud]
sub_types_covered: 8
sub_types:
  - kerberoasting-service-ticket-4769
  - asrep-roasting-preauth-disabled-4768
  - golden-silver-ticket-anomalous-4768-4624
  - dcsync-directory-replication-4662
  - ntds-dit-theft-domain-controller
  - pass-the-hash-ntlm-4624-type3-4776
  - gpo-abuse-directory-service-changes-5136
  - domain-controller-persistence-account-acl
validated_on: []
maturity: draft
variables:
  image_path:
    default: /cases/active/evidence/dc.E01
    derive: "Step 0 — first disk-evidence image (E01/dd/raw/vmdk) enumerated under the evidence directory named in the case brief; prefer the domain-controller image when several hosts are present"
  mount_root:
    default: /cases/active/mount
    derive: "Step 0 — directory where the file system is mounted READ-ONLY (or where icat-extracted hives/.evtx/NTDS.dit land when mounting fails)"
  case_out:
    default: /cases/active/out
    derive: "Step 0 — writable case output directory from the case brief; Step 0 creates #{case_out}/receipts/ and #{case_out}/extracted/"
  ntfs_offset_sectors:
    default: 0
    derive: "Step 0 — start sector of the relevant partition from `mmls #{image_path}` (largest NTFS partition unless the brief says otherwise)"
  time_window:
    default: 1970-01-01..2099-12-31
    derive: "case brief if it names one; else first confirmed malicious timestamp plus-or-minus 48h once a step pins one — then re-scope wide sweeps to it"
---

## In one line
The attacker goes after the keys to the kingdom — the central account database that every machine in a Windows network trusts. They steal passwords and the special tickets that grant access, then mint their own master keys so they can walk into any computer as anyone. This playbook reads the domain controller's logs, registry, and account database to prove they did it.

## Use this when (triggers)
- The evidence is (or includes) a **domain controller** — you see `NTDS.dit`, the `winevt\Logs` Security log is huge, or the host name ends in `DC`.
- A flood of **Kerberos service-ticket requests** (`4769`) for many accounts at once, especially with weak/legacy encryption — the signature of **Kerberoasting**.
- **Ticket-granting (`4768`) requests with pre-authentication disabled**, or `4768`/`4624` logons whose lifetimes or accounts look impossible (a logon for an account that does not exist, or a ticket valid for years) — **AS-REP roasting** or a forged **Golden/Silver ticket**.
- **Directory-replication** activity (`4662` with the DS-Replication-Get-Changes GUID) from a host or account that is **not a domain controller** — **DCSync** credential theft.
- Signs the **password database itself was copied** — a fresh `NTDS.dit`/`SYSTEM` hive in a staging folder, a Volume Shadow Copy created by hand, or `ntdsutil`/`vssadmin` execution traces.
- **NTLM network logons** (`4624` type 3 with `NTLM` package, or `4776` validations) reusing one account across many hosts — **Pass-the-Hash** lateral movement.
- A **Group Policy Object changed** (`5136` directory-service object modification) adding a startup script, a scheduled task, or a new admin — **GPO abuse** for mass persistence.
- New **domain admins, delegated rights, or AdminSDHolder/ACL changes** appearing on the DC — domain persistence.

## Quick path (the 90% case)
1. **Timeline-first.** Pull every `.evtx` from `#{mount_root}` (Security, System, Directory-Service) and render one sorted CSV with `EvtxECmd` (or fold the whole DC into a super-timeline with `log2timeline.py` + `psort.py`). Skim it inside `#{time_window}` BEFORE committing to a story — the order of Kerberos abuse → replication/NTDS theft → forged-ticket reuse is the case.
2. **Find the Kerberos abuse.** Grep the events CSV for `4769` bursts (Kerberoasting — many service tickets, watch `TicketEncryptionType 0x17` RC4) and `4768` with pre-auth disabled (AS-REP roast). Note the requesting account and source IP.
3. **Find the credential dump.** Look for `4662` with the replication-changes GUID from a non-DC source (DCSync), and on disk for a copied `NTDS.dit` + `SYSTEM` hive (the password database and its boot key). If `NTDS.dit` is present, dump its tables with `esedbexport` — but reconstruct accounts/hashes OFF-BOX (see Step 7; no on-box tool does it).
4. **Find the forged-ticket reuse and persistence.** `4624`/`4672` logons with impossible lifetimes or for non-existent accounts (Golden/Silver ticket); `4776`/type-3 NTLM reuse (Pass-the-Hash); `5136` GPO edits; new domain admins / ACL changes.
5. **Corroborate off the log.** Any tool path (ntdsutil, mimikatz-style binary, a staged dit) should also appear in registry execution/persistence (`RECmd` UserAssist/BAM, Run/Services) and on disk (`MFTECmd` $MFT/$J). One log line is a lead, not a fact.

If Kerberos abuse, a credential-theft act (replication or NTDS copy), and forged-ticket/PtH reuse all line up on one timeline with a corroborating second source → you have the chain. Otherwise drop into the full Steps.

## How it unfolds (the story)
An attacker who already holds one domain account asks the domain controller for service tickets in bulk and cracks the weak ones offline (Kerberoasting), or pulls password hashes for accounts that never required pre-authentication (AS-REP roasting). With admin on the DC they either impersonate a second domain controller and ask it to replicate every secret (DCSync), or copy the on-disk account database `NTDS.dit` together with the `SYSTEM` hive that holds its boot key. From those secrets they forge their own Kerberos tickets — a Golden ticket (signed with the `krbtgt` key, good for any account) or a Silver ticket (for one service) — and reuse stolen hashes directly (Pass-the-Hash). To stay, they edit a Group Policy Object that runs on every domain machine, or grant themselves domain-admin and replication rights. The whole chain is reconstructable from the DC's Security and Directory-Service logs plus the on-disk NTDS database and registry.

## Theories to test (and how to rule each out)
| Theory (who / why) | If true, you'd find… | Rule it out if… |
|---|---|---|
| **External-targeted (hands-on intruder, post-foothold)** | A `4769` Kerberoast burst then `4662` replication from a non-DC host, an `NTDS.dit`+`SYSTEM` copy in a staging dir, later `4624`/`4672` logons with impossible ticket lifetimes (Golden ticket) | No bulk `4769`, no replication from a non-DC, no staged credential database, no anomalous-lifetime logon — the DC shows only routine Kerberos and real DC-to-DC replication |
| **Other-insider (compromised admin account / stolen creds)** | A valid admin account does the `4662` replication or copies the dit from an unusual workstation/hour; `4776`/type-3 NTLM reuse of that account across many hosts (Pass-the-Hash) | The replication source IS a legitimate domain controller, and the admin account acts only from its own baseline host/hours with no hash-reuse spread |
| **Insider (authorized Domain Admin acting maliciously)** | A real Domain Admin runs `ntdsutil`/`vssadmin` to snapshot `NTDS.dit` interactively (`4688`/UserAssist), grants self rights (`4732`/`5136` ACL change) — all from the console | A sanctioned change-control record explains the snapshot/backup AND no exfil of the dit follows → benign admin action; reclassify |
| **Lateral movement via stolen Kerberos/NTLM (this DC is a hop or target)** | Inbound `4624` type 3 with `NTLM` from an internal host, a Silver ticket for a service on this host, a service created remotely (`7045`) right after a forged-ticket logon | Logons originate at the console (type 2) by expected admins; no NTLM reuse, no anomalous ticket, no peer-host corroboration |
| **Supply-chain / RMM / backup software (benign automation that looks like theft)** | A backup agent or RMM tool reads `NTDS.dit` via a scheduled VSS snapshot; replication-like reads tied to a signed updater parent; identical task on many DCs | The reader is a signed, scheduled backup/updater AND there is a change-control record AND no credential database leaves the host → benign |
| **Innocent / benign (NOT an attack)** | Normal DC-to-DC `4662` replication between real DCs, routine `4769` for live services inside business hours, a sanctioned GPO edit (`5136`) by a known admin, a vendor backup reading the dit | Every replication peer is a real DC, every `4769`/`4768` is for a real account from an expected source, the GPO/ACL change has a change ticket, and no credential store was copied off → benign cause confirmed; reclassify |

*(at least 1 benign + at least 1 malicious, each ACTIVELY refuted. Attacker types mapped: insider · other-insider · external-commodity · external-targeted · supply-chain · innocent.)*

## Evidence → Tool → What it reveals (per OS)
| Evidence | SIFT tool | What it tells you *for this attack* | OS |
|---|---|---|---|
| `Security.evtx` (`4769` service ticket, `4768` TGT, `4776` NTLM validation, `4624`/`4672` logon, `4662` object access, `5136` DS change, `4720`/`4732` account/group) | `EvtxECmd` / `evtxexport` / `evtx_dump.py` | The Kerberos and NTLM events on the DC: Kerberoasting (`4769` RC4 burst), AS-REP roast (`4768` no-preauth), DCSync (`4662` replication GUID), forged-ticket reuse, GPO/account changes (raw `evtxexport`/`evtx_dump.py` carry NO Event-ID labels — grep the XML; `EvtxECmd` adds maps) | Windows |
| `Directory Service.evtx` / `Microsoft-Windows-DirectoryServices-*%4Operational` (`1644` expensive search, replication events) | `EvtxECmd` / `evtxexport` | LDAP/replication activity on the DC — corroborates a `4662` replication read and abnormal directory queries | Windows |
| `System.evtx` (`7045` service install, `104` log cleared, `7036` service state) | `EvtxECmd` | A transient service used to run the credential-dump tool (PsExec-style), or whole-log clearing to hide it | Windows |
| `NTDS.dit` (the Active Directory ESE database) + `SYSTEM` hive (its boot key) | `esedbexport` (libesedb-tools) dumps the `datatable` and `link_table`; `MFTECmd` for its on-disk MAC times | Proof the password database is present/was copied, and the raw account/secret tables — but **account & hash reconstruction is OFF-BOX** (no secretsdump/impacket/NTDSXtract on this box) | Windows |
| `SYSTEM` / `SECURITY` / `SAM` / `SOFTWARE` hives | `RECmd` / `rip.pl` | The DC boot key paired with the dit; Run/Services persistence; UserAssist/BAM showing `ntdsutil`/dump-tool execution; ACL/AdminSDHolder traces | Windows |
| `$MFT` / `$UsnJrnl:$J` | `MFTECmd` | Create/copy time of a staged `NTDS.dit`/`SYSTEM`, the dump-tool binary's on-disk presence, `$SI` vs `$FN` timestomp on it, and the change-journal record of the copy | Windows |
| RAM image of the DC (if captured) | `vol` (Volatility 3) — `lsass` / `handles` / `pslist` / `svcscan` | A live credential-dumping process touching `lsass`, an open handle to `NTDS.dit`, or a tool process not yet on disk | Windows |
| All artifacts fused | `log2timeline.py` + `psort.py` (+ `pinfo.py`) | One chronology placing Kerberos abuse → replication/NTDS theft → forged-ticket reuse → persistence in order | all |
| Image-wide / pagefile string sweep | `bstrings` / `srch_strings` / `bulk_extractor` / `page-brute` | Account names, ticket/hash fragments, `krbtgt`, or tool command lines spilled outside the logs (e.g. in pagefile.sys) | all |
| Linux/Samba-AD DC logs (no EVTX) | `fls`/`mactime`, `log2timeline.py` (syslog/journal), `srch_strings` | A Samba AD-DC stores its database under `sam.ldb`/`private/`; Kerberos/auth traces live in `/var/log/samba` and the journal — the Linux equivalent | Linux |

*Linux memory analysis in `vol` needs a matching symbol table — ⚠️verify availability before relying on it.*

## Step 0 — evidence inventory & access bootstrap
- n: 0
  tool: |
    mkdir -p "#{case_out}/receipts" "#{case_out}/extracted" && ls -laR "#{mount_root}" > "#{case_out}/receipts/00.txt" 2>&1 ; img_stat "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; mmls "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; fsstat -o #{ntfs_offset_sectors} "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; find "#{mount_root}" -iname "*.evtx" -o -iname "ntds.dit" -o -iname "SYSTEM" >> "#{case_out}/receipts/00.txt" 2>&1
  expect: every evidence file classified; #{image_path}, #{mount_root}, #{ntfs_offset_sectors}, #{case_out} bound; read-only access proven; the winevt\Logs directory plus the NTDS\ntds.dit and config\SYSTEM hive are enumerated (confirming a domain controller), or their absence is recorded as a finding
  check: |
    test -r "#{mount_root}" -o -n "$(ls "#{case_out}/extracted" 2>/dev/null)"
  falsify: evidence dir empty/unreadable, or no supported image format found, or no NTFS partition for fsstat
  on_result: {expect_met: goto 1, falsify_met: STOP — report acquisition/access failure; pivot acquisition-custody, neither: try the icat-extract fallback (fls to find winevt\Logs and NTDS\ntds.dit inodes, icat each into #{case_out}/extracted); if that also fails, treat as falsify_met}
  emits: [key_artifacts]
  serves: [kerberoasting-service-ticket-4769, asrep-roasting-preauth-disabled-4768, golden-silver-ticket-anomalous-4768-4624, dcsync-directory-replication-4662, ntds-dit-theft-domain-controller, pass-the-hash-ntlm-4624-type3-4776, gpo-abuse-directory-service-changes-5136, domain-controller-persistence-account-acl]
  provenance: {receipt_id: 00, artifact: evidence directory listing + winevt/NTDS enumeration, offset_or_row: full listing, literal_cited: image filename plus ntds.dit and .evtx file list}

## Steps (executable — decision-driven)
- n: 1
  precondition: "os == windows; test -r #{mount_root}"
  tool: |
    dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll -d "#{mount_root}" --csv "#{case_out}" --csvf events.csv > "#{case_out}/receipts/01.txt" 2>&1
  expect: a single normalized CSV (#{case_out}/events.csv) covering Security/System/Directory-Service logs, with EventId, TimeCreated, Channel, MapDescription columns populated — the timeline-first artifact every later step filters
  check: |
    test -s "#{case_out}/events.csv" && grep -qiE "EventId|TimeCreated" "#{case_out}/events.csv"
  falsify: no .evtx found to parse, or EvtxECmd errors on every file (corrupt/locked logs)
  on_result: {expect_met: goto 2, falsify_met: fall back to raw export — evtxexport / evtx_dump.py per file into #{case_out}/extracted then grep the XML; if logs are absent record absence as a finding and pivot windows-event-logs, neither: re-run EvtxECmd per-file with -f on the specific Security.evtx; if maps are missing use evtxexport raw and grep EID strings}
  emits: [timeline_events]
  serves: [kerberoasting-service-ticket-4769, asrep-roasting-preauth-disabled-4768, dcsync-directory-replication-4662, pass-the-hash-ntlm-4624-type3-4776, gpo-abuse-directory-service-changes-5136]
  provenance: {receipt_id: 01, artifact: winevt/Logs/*.evtx, offset_or_row: events.csv header plus row count, literal_cited: EvtxECmd processed-file count line}

- n: 2
  precondition: "exists #{case_out}/events.csv"
  tool: |
    grep -E ",4769," "#{case_out}/events.csv" > "#{case_out}/receipts/02.txt" 2>&1 ; grep -E ",4768," "#{case_out}/events.csv" >> "#{case_out}/receipts/02.txt" 2>&1
  expect: a burst of 4769 service-ticket requests for many service accounts in a short window (Kerberoasting), ideally with TicketEncryptionType 0x17 (RC4 — crackable) from one client IP; and/or 4768 TGT requests with PreAuthType 0 (pre-authentication disabled — AS-REP roastable), inside #{time_window}
  check: |
    grep -qE ",4769,|,4768," "#{case_out}/receipts/02.txt"
  falsify: only a handful of 4769 for live services from expected hosts and no 4768 with pre-auth disabled — routine Kerberos, no roasting pattern
  on_result: {expect_met: record requesting account plus client IP plus ServiceName/EncryptionType as IOCs; goto 3, falsify_met: record "no Kerberos roasting in the log"; continue to replication/NTDS at goto 4, neither: widen #{time_window}; re-parse the Security log per-file (EvtxECmd -f) and re-check the encryption-type field}
  emits: [key_iocs, actor_accounts, timeline_events]
  serves: [kerberoasting-service-ticket-4769, asrep-roasting-preauth-disabled-4768]
  provenance: {receipt_id: 02, artifact: Security.evtx, offset_or_row: events.csv 4769/4768 rows, literal_cited: ServiceName plus TicketEncryptionType plus client IP string}

- n: 3
  precondition: "exists #{case_out}/events.csv"
  tool: |
    grep -E ",4624," "#{case_out}/events.csv" > "#{case_out}/receipts/03.txt" 2>&1 ; grep -E ",4672," "#{case_out}/events.csv" >> "#{case_out}/receipts/03.txt" 2>&1 ; grep -E ",4776," "#{case_out}/events.csv" >> "#{case_out}/receipts/03.txt" 2>&1
  expect: 4624 type-3 network logons whose AuthenticationPackage is NTLM reusing one account across many hosts (Pass-the-Hash), or 4776 NTLM credential validations on the DC for that account; and/or 4624/4672 logons with an impossible session (an account that should not exist, or a ticket lifetime far beyond policy) that betrays a forged Golden/Silver ticket
  check: |
    grep -qE ",4624,|,4672,|,4776," "#{case_out}/receipts/03.txt"
  falsify: every 4624 is a console/Kerberos logon by an expected account from an expected host, no NTLM reuse spread and no anomalous lifetime — no PtH or forged-ticket reuse evidenced in the log
  on_result: {expect_met: flag PtH / forged-ticket reuse; record account plus source IP plus package as IOCs; goto 4, falsify_met: record "no NTLM reuse or anomalous ticket"; goto 4, neither: correlate logon times against the 4769/4768 window; check ticket lifetime vs domain policy; if domain-wide reuse, keep at inferred and goto 4}
  emits: [actor_accounts, key_iocs, timeline_events]
  serves: [pass-the-hash-ntlm-4624-type3-4776, golden-silver-ticket-anomalous-4768-4624]
  provenance: {receipt_id: 03, artifact: Security.evtx, offset_or_row: events.csv 4624/4672/4776 rows, literal_cited: account plus AuthenticationPackage plus IpAddress string}

- n: 4
  precondition: "exists #{case_out}/events.csv"
  tool: |
    grep -E ",4662," "#{case_out}/events.csv" > "#{case_out}/receipts/04.txt" 2>&1 ; grep -iE "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c" "#{case_out}/events.csv" >> "#{case_out}/receipts/04.txt" 2>&1
  expect: a 4662 directory-object-access event carrying a DS-Replication-Get-Changes property GUID (1131f6aa- / 1131f6ad- / 89e95b76- for the All/Filtered/Secrets replication right) requested by an ACCOUNT or from a SOURCE that is not a legitimate domain controller — the on-the-wire signature of DCSync credential theft
  check: |
    grep -qiE ",4662,|1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c" "#{case_out}/receipts/04.txt"
  falsify: every 4662 replication-GUID access is by a real domain-controller computer account between known DCs — routine AD replication, not DCSync
  on_result: {expect_met: record the requesting account plus source as a high-signal DCSync IOC; goto 5, falsify_met: record "replication is DC-to-DC only, no DCSync"; check on-disk NTDS theft instead at goto 5, neither: cross-check the requesting account against the DC computer-account list; parse Directory-Service.evtx per-file for replication context; keep at inferred and goto 5}
  emits: [key_iocs, actor_accounts, timeline_events]
  serves: [dcsync-directory-replication-4662]
  provenance: {receipt_id: 04, artifact: Security.evtx, offset_or_row: events.csv 4662 rows with replication GUID, literal_cited: DS-Replication-Get-Changes GUID plus requesting account string}

- n: 5
  precondition: "exists #{case_out}/events.csv; test -r #{mount_root}"
  tool: |
    dotnet /opt/zimmermantools/MFTECmd.dll -f "#{mount_root}" --csv "#{case_out}" --csvf mft.csv > "#{case_out}/receipts/05.txt" 2>&1 ; grep -iE "ntds\.dit|/SYSTEM,|ntdsutil|vssadmin|\.bak|IFM" "#{case_out}/mft.csv" >> "#{case_out}/receipts/05.txt" 2>&1
  expect: in the $MFT a copy of ntds.dit and/or a SYSTEM hive in a non-default staging location (\Temp, \Users, \ProgramData, a .bak/IFM export dir) with a Created0x10 time inside #{time_window}, and/or traces of ntdsutil/vssadmin (the snapshot-and-copy method) — evidence the credential database was staged for theft
  check: |
    grep -qiE "ntds\.dit|ntdsutil|vssadmin" "#{case_out}/mft.csv" "#{case_out}/receipts/05.txt"
  falsify: ntds.dit exists ONLY at its default path \Windows\NTDS\ntds.dit with no staged copy and no ntdsutil/vssadmin trace — no on-disk credential-database theft staged
  on_result: {expect_met: record the staged dit/SYSTEM path plus create time as a high-signal IOC; goto 6, falsify_met: record "NTDS.dit only at default path, no staging"; corroborate via registry execution at goto 7, neither: query $UsnJrnl via MFTECmd -f on the $J for a recent ntds.dit copy/rename; widen #{time_window}; goto 6}
  emits: [key_artifacts, key_iocs, timeline_events]
  serves: [ntds-dit-theft-domain-controller]
  provenance: {receipt_id: 05, artifact: $MFT / $UsnJrnl:$J, offset_or_row: mft.csv ntds.dit/SYSTEM row, literal_cited: staged ntds.dit path plus Created0x10 timestamp}

- n: 6
  precondition: "exists #{case_out}/mft.csv; test -r #{mount_root}"
  tool: |
    NTDS=$(find "#{mount_root}" -iname "ntds.dit" | head -n1) ; if [ -n "$NTDS" ]; then /usr/bin/esedbexport -t "#{case_out}/extracted/ntds" "$NTDS" > "#{case_out}/receipts/06.txt" 2>&1 ; else echo "no ntds.dit found under #{mount_root}" > "#{case_out}/receipts/06.txt" ; fi ; ls -laR "#{case_out}/extracted" >> "#{case_out}/receipts/06.txt" 2>&1
  expect: esedbexport dumps the AD ESE database tables to #{case_out}/extracted — most importantly datatable (the account objects) and link_table (group memberships/links); their presence proves the raw secret store was recovered. The on-disk dump is the evidence; account/hash RECONSTRUCTION is performed OFF-BOX (no secretsdump/impacket/NTDSXtract on this host — see the handoff in Step 7)
  check: |
    ls "#{case_out}/extracted"/ntds.export/*datatable* >/dev/null 2>&1 || grep -qiE "datatable|link_table|table:" "#{case_out}/receipts/06.txt"
  falsify: esedbexport errors (the dit is corrupt, encrypted, or not an ESE database) OR no ntds.dit exists to dump — no on-box NTDS table recovery possible
  on_result: {expect_met: record datatable+link_table export as the NTDS evidence; package them for the OFF-BOX hash-reconstruction handoff; goto 7, falsify_met: record "ntds.dit absent or unparseable"; lean on the 4662 DCSync path (step 4) and registry traces (step 7); pivot acquisition-custody if the dit is corrupt, neither: re-run esedbexport on the staged copy found in step 5; if the database is dirty, note it and carry the partial export forward; goto 7}
  emits: [key_artifacts, exfil_or_encryption_facts]
  serves: [ntds-dit-theft-domain-controller]
  provenance: {receipt_id: 06, artifact: NTDS.dit ESE database, offset_or_row: esedbexport table listing, literal_cited: datatable and link_table export filenames}

- n: 7
  precondition: "exists #{case_out}/events.csv; test -r #{mount_root}"
  tool: |
    dotnet /opt/zimmermantools/RECmd/RECmd.dll --bn /opt/zimmermantools/RECmd/BatchExamples/Kroll_Batch.reb -d "#{mount_root}" --csv "#{case_out}" --csvf reg.csv > "#{case_out}/receipts/07.txt" 2>&1 ; grep -E ",5136,|,4720,|,4732,|,4728,|,4756," "#{case_out}/events.csv" >> "#{case_out}/receipts/07.txt" 2>&1
  expect: a 5136 directory-service-object change editing a GPO (a new startup script, scheduled task, or restricted-group admin) and/or account-management events (4720 create / 4732/4728/4756 added to Domain Admins / Administrators / Enterprise Admins) granting domain persistence; AND the staged-dit / dump-tool path from steps 5-6 ALSO appearing in a registry execution/persistence source (UserAssist/BAM, Run key, Services) — a second, independent source (two-source rule)
  check: |
    test -s "#{case_out}/reg.csv" && grep -qiE "userassist|bam|services|run|,5136,|,4732,|,4728,|,4756," "#{case_out}/reg.csv" "#{case_out}/receipts/07.txt"
  falsify: no 5136 GPO edit, no privileged group addition, AND the dump-tool/dit path appears in NO registry execution/persistence source — domain persistence not evidenced and the on-disk claim stands single-source
  on_result: {expect_met: promote the corroborated finding to confirmed; record the GPO/admin-grant as a persistence IOC; goto 8, falsify_met: keep the NTDS/Kerberos finding at inferred/single-source; note the missing corroboration; pivot windows-registry-persistence, neither: run rip.pl -r against the specific SYSTEM/SOFTWARE/NTUSER hive for services/run/userassist and re-check; goto 8}
  emits: [key_artifacts, actor_accounts, key_iocs]
  serves: [gpo-abuse-directory-service-changes-5136, domain-controller-persistence-account-acl]
  provenance: {receipt_id: 07, artifact: SYSTEM/SOFTWARE/NTUSER hive + Security.evtx, offset_or_row: reg.csv key row / events.csv 5136/4732 rows, literal_cited: GPO/group-change value or UserAssist execution row}

- n: 8
  precondition: "exists #{case_out}/events.csv"
  tool: |
    log2timeline.py --status_view none "#{case_out}/dc.plaso" "#{mount_root}" > "#{case_out}/receipts/08.txt" 2>&1 ; psort.py -o l2tcsv "#{case_out}/dc.plaso" > "#{case_out}/super.csv" 2>> "#{case_out}/receipts/08.txt" ; pinfo.py "#{case_out}/dc.plaso" >> "#{case_out}/receipts/08.txt" 2>&1
  expect: a fused super-timeline placing Kerberos abuse (4769/4768) → credential theft (4662 replication or the ntds.dit copy) → forged-ticket/PtH reuse (4624/4672/4776) → persistence (5136/4732) in a coherent order with no unexplained gap, inside #{time_window}
  check: |
    test -s "#{case_out}/super.csv" && grep -qiE "winevtx|evtx|ntds" "#{case_out}/super.csv"
  falsify: ordering is impossible (e.g. a forged-ticket logon precedes any credential theft) OR an unexplained multi-hour gap that no log-clear event accounts for
  on_result: {expect_met: COMMIT the conclusion with a confidence label; close per the gate, falsify_met: re-open the Theories table; the gap/inversion may indicate clock manipulation or cleared logs — anchor to EventRecordID order instead of host time, neither: run pinfo.py to confirm the winevtx parser ran; re-filter psort.py to #{time_window} and re-check}
  emits: [timeline_events]
  serves: [kerberoasting-service-ticket-4769, dcsync-directory-replication-4662, ntds-dit-theft-domain-controller, golden-silver-ticket-anomalous-4768-4624]
  provenance: {receipt_id: 08, artifact: dc.plaso super-timeline, offset_or_row: super.csv ordered rows, literal_cited: ordered Kerberos-to-theft-to-reuse-to-persistence chain}

## Linux branch (L1..Ln) — REQUIRED, numbered, same step shape
- n: L1
  precondition: "os == linux"
  tool: |
    fsstat -o #{ntfs_offset_sectors} "#{image_path}" > "#{case_out}/receipts/L01.txt" 2>&1 ; find "#{mount_root}/var/lib/samba" "#{mount_root}/var/log/samba" -maxdepth 3 2>/dev/null >> "#{case_out}/receipts/L01.txt" ; find "#{mount_root}" -iname "sam.ldb" -o -iname "secrets.ldb" 2>/dev/null >> "#{case_out}/receipts/L01.txt" 2>&1
  expect: this image is Linux (ext/xfs fsstat, /var present) — Windows EVTX and NTDS.dit do NOT exist here; a Samba Active-Directory DC stores the equivalent under /var/lib/samba (sam.ldb, secrets.ldb) and logs Kerberos/auth under /var/log/samba and the journal. Record whether this is a Samba AD-DC or a non-domain Linux host
  check: |
    test -d "#{mount_root}/var/lib/samba" -o -n "$(grep -iE 'ext[234]|xfs' "#{case_out}/receipts/L01.txt" 2>/dev/null)"
  falsify: fsstat reports NTFS and a Windows\NTDS\ntds.dit tree exists — this is a Windows DC, not Linux; the main Windows Steps apply (return to Step 1)
  on_result: {expect_met: goto L2, falsify_met: this is Windows — run the main Windows Steps 1-8 not this branch, neither: confirm OS family from the Step 0 fsstat/disktype receipt; if still ambiguous treat as Windows and run the main branch}
  emits: [key_artifacts]
  serves: [ntds-dit-theft-domain-controller, dcsync-directory-replication-4662]
  provenance: {receipt_id: L01, artifact: file system + /var/lib/samba listing, offset_or_row: fsstat header + dir listing, literal_cited: ext/xfs FS type or sam.ldb present (Linux Samba-AD or non-domain)}

- n: L2
  precondition: "os == linux"
  tool: |
    log2timeline.py --status_view none "#{case_out}/linux.plaso" "#{mount_root}/var/log" > "#{case_out}/receipts/L02.txt" 2>&1 ; psort.py -o l2tcsv "#{case_out}/linux.plaso" > "#{case_out}/linux_super.csv" 2>> "#{case_out}/receipts/L02.txt" ; srch_strings "#{mount_root}/var/lib/samba/private/sam.ldb" 2>/dev/null | grep -iE "krbtgt|unicodePwd|supplementalCredentials|adminCount" >> "#{case_out}/receipts/L02.txt" 2>&1
  expect: on a Samba AD-DC, the sam.ldb database holds the domain secrets (krbtgt, unicodePwd, supplementalCredentials) — its theft is the NTDS.dit analog; /var/log/samba and the journal carry Kerberos TGS/AS requests (Kerberoast/AS-REP analog), and replication/DRS reads (DCSync analog) — ordered in the super-timeline inside #{time_window}
  check: |
    test -s "#{case_out}/linux_super.csv" -o -s "#{case_out}/receipts/L02.txt"
  falsify: /var/lib/samba is absent or empty AND /var/log holds no Kerberos/DRS records — this Linux host is not a domain controller; record that as a finding
  on_result: {expect_met: record the secrets-database path + account + replication source; the hash reconstruction is OFF-BOX (no on-box credential-rebuild tool); commit with a confidence label, falsify_met: record "not a Samba AD-DC, no domain secrets here"; pivot linux-host-forensics, neither: widen #{time_window}; parse journald binary logs under /var/log/journal via log2timeline and re-render}
  emits: [actor_accounts, key_iocs, timeline_events]
  serves: [ntds-dit-theft-domain-controller, kerberoasting-service-ticket-4769, dcsync-directory-replication-4662]
  provenance: {receipt_id: L02, artifact: /var/lib/samba/private/sam.ldb + /var/log/samba, offset_or_row: linux_super.csv rows / grep hits, literal_cited: krbtgt/supplementalCredentials attribute or Kerberos request line}

## Corroboration (two-source rule)
`required_sources: 2` · `pairs:`
- `[ 4769 Kerberoast burst (step 2) ↔ the cracked service account later authenticating from a new host (step 3) ]`
- `[ 4662 replication-GUID read (step 4) ↔ requesting account NOT in the DC computer-account list (step 4/7) ]`
- `[ staged ntds.dit in $MFT (step 5) ↔ esedbexport datatable/link_table dump succeeding (step 6) ]`
- `[ ntds.dit/SYSTEM copy (step 5) ↔ ntdsutil/vssadmin UserAssist/BAM execution trace (step 7) ]`
- `[ 5136 GPO edit / 4732 admin grant (step 7) ↔ the GPO file or Services/Run hive value (step 7) ]`
- `[ event-log chronology (step 1) ↔ fused super-timeline order (step 8) ]`

One hit is a *lead*; promote to *fact* only when its paired source agrees.

## Don't get fooled (red flags & anti-forensics)
- **Real DC-to-DC replication looks like DCSync.** Legitimate domain controllers replicate constantly, firing `4662` with the same DS-Replication-Get-Changes GUID. The discriminator is the SOURCE: a real DC computer account vs a user/workstation account. Always check the requesting account against the known DC list before calling DCSync.
- **A Golden ticket leaves almost nothing on the DC.** Once forged with the `krbtgt` key, a Golden ticket needs no `4768` (TGT request) — the attacker skips the DC for issuance. The tell is downstream: `4624`/`4769` with a ticket lifetime far beyond domain policy, or for an account that does not exist in AD. Distrust ticket-issuance silence; hunt the reuse.
- **`NTDS.dit` at its default path is normal — a COPY is the finding.** Every DC has `\Windows\NTDS\ntds.dit`. What matters is a *second* copy in `\Temp`/`\Users`/an IFM export dir, or a hand-made Volume Shadow Copy, plus the `SYSTEM` hive copied alongside it (you need both to extract secrets).
- **Hash reconstruction is OFF-BOX here.** This SIFT box has `esedbexport` (dumps the ESE tables) but NO `secretsdump`/`impacket`/`NTDSXtract` to turn `datatable`+`link_table`+`SYSTEM` into usernames and NT hashes. Do NOT claim on-box credential recovery — export the tables and hand off (Step 7 note). Naming those tools in a runnable step is a fabrication.
- **RC4 (`0x17`) Kerberos tickets are the Kerberoast tell, but not proof alone.** Some legacy services genuinely use RC4. A *burst* of `4769` for many SPNs from one client in seconds is the pattern; a single RC4 ticket for a real service is noise.
- **Cleared logs / silent gaps.** A `1102` (Security cleared) or `104` (System cleared) near the activity, OR a break in `EventRecordID` continuity / a `TimeCreated` gap with no clear-event, is anti-forensics — treat the gap itself as a finding and anchor to record-ID order.
- **Timestomp on the staged dit / dump tool.** The copied `NTDS.dit` or the dump binary may show a backdated `$SI` time; compare `$SI` vs `$FN` with `MFTECmd` and trust `$UsnJrnl`/`EventRecordID` order over host time.
- **Distrust host time around the intrusion.** If the timeline is internally impossible, anchor to the monotonic `EventRecordID` within each EVTX file and to USN sequence numbers rather than `TimeCreated`. **Missing evidence is itself a finding.**

## Failure modes
```
- mode: evidence-access failure — the disk won't mount or winevt\Logs / NTDS\ntds.dit is unreadable
  guard: Step 0 fallback chain — ewfmount/loop RO, else TSK fls/icat the .evtx and ntds.dit inodes into #{case_out}/extracted; if all fail, record acquisition failure and pivot acquisition-custody
- mode: primary-artifact-absent — Security.evtx/Directory-Service.evtx or NTDS.dit missing, empty, or zero-length (cleared, never collected, or this is not a DC)
  guard: record the absence as a finding; name the secondary sources (Directory-Service Operational log, registry UserAssist/BAM, $MFT/$J, super-timeline) and pivot windows-event-logs / windows-registry-persistence
- mode: tool-output drift — EvtxECmd map/CSV column names change, or a comma-in-field breaks a grep literal so check exits 2
  guard: on check exit 2, adjudicate from the prose expect/falsify against the receipt, cap confidence at inferred; fall back to raw evtxexport / evtx_dump.py XML and grep the EventID and replication-GUID directly, never silently pass
- mode: NTDS.dit unparseable / no on-box hash reconstruction — esedbexport errors on a dirty/encrypted dit, or the tables export but no secretsdump/impacket/NTDSXtract exists to rebuild users+hashes
  guard: note the dirty database; carry the partial datatable/link_table export forward; perform credential reconstruction OFF-BOX (impacket on another host) — never claim on-box hash recovery
- mode: DCSync false positive — real DC-to-DC replication mistaken for theft
  guard: check the requesting account against the DC computer-account list; only call DCSync when the replication right is exercised by a non-DC principal
```
Minimum set every playbook covers: evidence-access failure (Step 0 fallback chain) · primary-artifact-absent (absence recorded, secondary source named) · tool-output drift (`check` exits 2 → prose adjudication, never silent pass).

## Confidence labeling (observation → inference → conclusion)
- **confirmed:** direct receipt verbatim (e.g. the `4662` replication-GUID row, or the `esedbexport` datatable dump) + at least 2 independent sources agree (event log + on-disk dit/$MFT or registry execution) + no unrefuted counter-theory.
- **inferred:** grounded but single-source/interpretive — e.g. a `4769` RC4 burst with no later use, a staged `ntds.dit` with no execution trace yet, an anomalous ticket lifetime read as a Golden ticket, or BAM coverage on newer Win10/11 unverified → hedge and tag `⚠️verify`. Every `check`-exit-2 adjudication lands here at best.
- **insufficient_evidence:** precondition unmet (logs absent; not a DC; no RAM image; dit corrupt) or sources conflict → abstain; state what's missing, do not guess.

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
- **Windows:** fully covered above — a domain controller's Security and Directory-Service EVTX, the on-disk `NTDS.dit`+`SYSTEM`, and the registry are the richest sources for Kerberos abuse, DCSync, NTDS theft, and persistence.
- **Linux/ESXi:** no EVTX or `NTDS.dit` — see the numbered Linux branch (L1–L2). A **Samba AD-DC** is the equivalent: the domain database is `sam.ldb`/`secrets.ldb` under `/var/lib/samba/private`, Kerberos and replication (DRS) activity is logged under `/var/log/samba` and the journal (parse with `log2timeline.py`). The hash-reconstruction step is OFF-BOX there too. A non-domain Linux host has no AD analog — record that and pivot `linux-host-forensics`.
- **macOS:** macOS clients can be AD-bound but are not domain controllers — there is no `NTDS.dit`. Kerberos tickets live in the credential cache and the Unified Log records auth; this box has **no working Unified-Log parser** (`⚠️verify` — degraded), so treat any macOS finding as lead-only. Windows-DC-centric otherwise.
- **Cloud:** the cloud analog is the identity provider (Entra ID / Azure AD, Okta) — there is no on-disk `NTDS.dit`; "Golden ticket" maps to a forged SAML token / Golden SAML, and "DCSync" maps to directory-export API abuse. This box has **no dedicated cloud-identity parser** (`⚠️verify`); investigate from *exported* sign-in/audit JSON already on disk by grepping with `bstrings`/`srch_strings`. Pivot `cloud-identity-saas`.

## Real-case notes (non-obvious things to look for)
- **DCSync needs no malware on the DC — it is a legitimate protocol abused.** The attacker, from any host, asks a DC to replicate secrets using the `DRSGetNCChanges` call; the only host-side trace is `4662` with the DS-Replication-Get-Changes GUID requested by a non-DC principal. Mimikatz `lsadump::dcsync` and impacket `secretsdump -just-dc` both leave this exact event. Check the requesting account, not just the event. `[MITRE T1003.006 / Microsoft 4662 docs · high]`
- **Kerberoasting is account-agnostic — any domain user can do it.** A single low-privilege account requesting `4769` service tickets for every SPN in the domain, with `TicketEncryptionType 0x17` (RC4) so the tickets crack offline, is the signature. The DC sees only normal-looking ticket requests, so the *burst rate and encryption type* are the discriminators, not the account's privilege. `[MITRE T1558.003 · high]`
- **AS-REP roasting targets accounts with "do not require Kerberos pre-authentication" set.** Those accounts return an AS-REP encrypted with the user's key (`4768` with `PreAuthType 0`), crackable offline — no prior foothold needed beyond knowing the username. Hunt the pre-auth-disabled flag. `[MITRE T1558.004 · high]`
- **Golden vs Silver ticket differ in what they forge.** A Golden ticket is a forged TGT signed with the `krbtgt` account's hash — total domain access, survives password resets of every account except `krbtgt` itself (reset `krbtgt` TWICE to revoke). A Silver ticket forges a service ticket (TGS) for ONE service with that service account's hash — quieter, never touches the DC for issuance. Both show up as logons with anomalous ticket lifetimes or non-existent accounts. `[MITRE T1558.001 / T1558.002 · high]`
- **NTDS.dit theft via `ntdsutil "IFM"` or a VSS snapshot is the on-disk path.** `ntdsutil ac i ntds ifm create full <dir>` writes a clean `ntds.dit` + `SYSTEM` to a folder — look for that pair in a staging directory with matching create times. `vssadmin create shadow` then a copy out of the shadow is the other common method; both can be spotted in `$MFT`/`$UsnJrnl` and UserAssist. `[MITRE T1003.003 · high]`
- **You need the `SYSTEM` hive AND the dit together.** The account secrets in `NTDS.dit` are encrypted with the Password Encryption Key, which is itself protected by the DC's boot key stored in the `SYSTEM` registry hive. A `ntds.dit` copied without a matching `SYSTEM` is far less useful — seeing both staged together strongly implies a complete credential-theft attempt. `[Microsoft AD internals / general DFIR practice · high]`
- **Distrust host time around credential theft.** Actors time DC intrusions for off-hours and may manipulate the clock; if the timeline is internally impossible, anchor to the monotonic `EventRecordID` within each EVTX file and to USN sequence numbers rather than `TimeCreated`. `⚠️verify any timeline keyed purely to host clock.` `[general DFIR anti-forensics practice · med]`

## ATT&CK mapping
- T1558.003 · Credential Access · Kerberoasting · `4769` RC4 service-ticket burst — step 2
- T1558.004 · Credential Access · AS-REP Roasting · `4768` with pre-auth disabled — step 2
- T1558.001 · Credential Access · Golden Ticket · forged TGT, anomalous `4624`/`4769` lifetime — steps 3/8
- T1558.002 · Credential Access · Silver Ticket · forged TGS for one service — step 3
- T1003.006 · Credential Access · DCSync · `4662` DS-Replication-Get-Changes from a non-DC — step 4
- T1003.003 · Credential Access · NTDS · `ntds.dit` + `SYSTEM` copy / `ntdsutil` IFM / VSS — steps 5/6
- T1550.002 · Lateral Movement / Defense Evasion · Pass-the-Hash · `4624` type 3 NTLM / `4776` reuse — step 3
- T1484.001 · Privilege Escalation / Persistence · Group Policy Modification · `5136` GPO object change — step 7
- T1098 · Persistence · Account Manipulation · `5136` ACL / AdminSDHolder change — step 7
- T1078.002 · Persistence / Privilege Escalation · Domain Accounts · `4732`/`4728`/`4756` add to admin group — step 7
- T1070.001 · Defense Evasion · Clear Windows Event Logs · `1102` (Security) / `104` (System) — Don't-get-fooled / step 8 gap check

## Pivots (lead-to-lead graph)
- `on_kerberoast_or_asrep (step 2 4769/4768): malware-analysis-triage — triage the offline cracking tool / dropped payload once the cracked account is used`
- `on_pth_or_forged_ticket_reuse (step 3 type-3 NTLM / anomalous lifetime): windows-event-logs — trace the reuse logons across the other hosts' Security logs`
- `on_dcsync_replication (step 4 4662 GUID): SELF — re-enter with the requesting account bound into #{time_window} to bracket what it pulled`
- `on_ntds_or_dump_tool_execution (step 5/7 ntds.dit copy / ntdsutil): windows-execution-artifacts — corroborate via UserAssist/BAM/LNK on the dump tool`
- `on_gpo_or_admin_grant_persistence (step 7 5136 / Services hive): windows-registry-persistence — confirm the autorun/admin grant in the hive`
- `on_credential_database_exfil (step 6 datatable/link_table export): insider-threat-data-theft — trace how the dumped secrets left the environment`
- `on_lateral_movement_chain (step 3/8 multi-host reuse): attack-lifecycle-hunting — reconstruct the full multi-host intrusion timeline`
- `on_logs_absent_or_unmountable (step 0/1): acquisition-custody — re-acquire or prove the collection gap`

## Jargon decoder
- **Active Directory (AD):** the central directory every Windows domain machine trusts for accounts, groups, and policy.
- **Domain Controller (DC):** a server that runs AD and holds the master account database.
- **NTDS.dit:** the on-disk AD database file (an ESE/Jet database) holding every account and its password secrets. Lives at `\Windows\NTDS\ntds.dit`.
- **ESE database / `datatable` / `link_table`:** the table format `NTDS.dit` uses; `datatable` holds account objects, `link_table` holds group memberships/links. `esedbexport` dumps these raw tables.
- **SYSTEM hive / boot key:** the registry hive holding the key needed to decrypt the secrets inside `NTDS.dit` — you need both the dit and SYSTEM to recover hashes.
- **Kerberos:** the default Windows authentication protocol — issues tickets instead of sending passwords.
- **TGT / TGS:** Ticket-Granting Ticket (your master ticket, event `4768`) and the per-service Ticket-Granting Service ticket (event `4769`).
- **Kerberoasting:** requesting many service tickets (`4769`) to crack the service-account passwords offline; RC4 (`0x17`) tickets crack fastest.
- **AS-REP roasting:** abusing accounts with Kerberos pre-authentication disabled (`4768` `PreAuthType 0`) to get a crackable response without a password.
- **Golden ticket:** a forged TGT signed with the `krbtgt` account's hash — grants access as any account, domain-wide.
- **Silver ticket:** a forged service ticket (TGS) for one service, signed with that service account's hash — quieter, skips the DC.
- **krbtgt:** the special account whose hash signs every Kerberos ticket; stealing it enables Golden tickets.
- **DCSync:** abusing the directory-replication protocol (`DRSGetNCChanges`) to make a DC hand over secrets; appears as `4662` with the DS-Replication-Get-Changes GUID.
- **Pass-the-Hash (PtH):** authenticating with a stolen NTLM password hash instead of the plaintext — shows as NTLM `4624` type 3 / `4776`.
- **GPO (Group Policy Object):** centrally-managed policy pushed to domain machines; editing one (`5136`) can run code or grant rights everywhere.
- **AdminSDHolder / ACL:** the template and access-control entries that protect privileged accounts; tampering grants stealthy persistence.
- **$MFT / $SI vs $FN:** NTFS Master File Table / the two timestamp sets in a file record; `$SI` is easy to forge, `$FN` harder — disagreement hints at **timestomp**.
- **EventRecordID:** a per-file counter that increases by one for every event written; a break in the sequence = tampering even with no clear-event.
- **Super-timeline:** one merged chronology across many artifacts, built with `log2timeline.py` + `psort.py`.
- **Samba AD-DC / sam.ldb (Linux):** the Linux/Samba equivalent of a domain controller and its `NTDS.dit` — the database is `sam.ldb`/`secrets.ldb` under `/var/lib/samba`.

## Tuning log (append-only — the eval loop writes here; humans never edit rows)
| date | case_id | bucket missed | delta applied |
|---|---|---|---|
