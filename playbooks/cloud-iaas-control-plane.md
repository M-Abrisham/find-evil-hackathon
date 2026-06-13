---
attack_type: cloud-iaas-control-plane
category_id: cloud-iaas-control-plane
name: Cloud IaaS Control-Plane & Data
description: AWS/Azure/GCP control-plane abuse, rogue resources and cloud data exposure from exported logs
version: 1
os_coverage: [windows, linux, macos, cloud]
sub_types_covered: 18
sub_types:
  - rogue-iam-user-created
  - rogue-iam-role-created
  - rogue-access-key-created
  - login-profile-or-password-set-for-persistence
  - mfa-device-deregistered-or-disabled
  - snapshot-or-ami-shared-or-copied-cross-account
  - ebs-snapshot-made-public
  - s3-bucket-policy-or-acl-made-public
  - blob-or-bucket-storage-exposed-public
  - s3-object-mass-download-exfil
  - security-group-or-firewall-opened
  - cloudtrail-or-logging-disabled-or-deleted
  - guardduty-or-config-detector-disabled
  - cryptomining-instance-spin-up
  - control-plane-persistence-lambda-or-eventbridge
  - cross-account-assume-role-abuse
  - kms-key-policy-or-grant-tampered
  - resource-mass-deletion-or-destruction
validated_on: []
maturity: draft
variables:
  image_path:
    default: /cases/active/evidence/cloudtrail-export
    derive: "Step 0 — the exported cloud-log tree (CloudTrail JSON.gz, Azure Activity JSON, GCP Cloud Audit JSON) enumerated under the evidence directory named in the case brief; NOT a disk image — this playbook is INGEST-ONLY from already-exported logs and never touches a live cloud account"
  mount_root:
    default: /cases/active/evidence/cloudtrail-export
    derive: "Step 0 — directory holding the decompressed/readable exported log files; for cloud logs this equals the export tree (no file system mount needed), or where icat-extracted log files land if the export was itself carried on a seized disk image"
  case_out:
    default: /cases/active/out
    derive: "Step 0 — writable case output directory from the case brief; Step 0 creates #{case_out}/receipts/ and #{case_out}/extracted/"
  ntfs_offset_sectors:
    default: 0
    derive: "Step 0 — start sector of the partition from `mmls #{image_path}` ONLY IF the export was delivered inside a seized disk image; for a plain exported-log tree this stays 0 (unused)"
  time_window:
    default: 1970-01-01..2099-12-31
    derive: "case brief if it names one; else first confirmed malicious eventTime in the logs plus or minus 48h once a step pins one — then re-scope wide sweeps to it"
---

## In one line
Someone with stolen cloud keys or a hijacked console session quietly reconfigures the cloud account itself — making new admin users, copying disk images out, opening storage to the public, turning off the audit log — and we read the cloud account's own change-log (the exported audit trail) to prove who did what, when, and from which IP.

## Use this when (triggers)
- You have an **exported cloud audit log** (AWS CloudTrail JSON.gz, Azure Activity/Monitor JSON, or GCP Cloud Audit Logs JSON) and need to know whether the control plane was abused — NOT a disk image of an instance.
- A **new IAM user, role, or access key** appeared, an MFA device was removed, or a console login-profile was set on a service account (persistence).
- A **snapshot or AMI/image was shared or copied to an unknown account**, or an EBS snapshot / storage bucket was **made public** (data exfil via the control plane).
- A **security group / firewall rule was opened** to 0.0.0.0/0, or a fleet of **new compute instances** spun up in odd regions (cryptomining).
- **CloudTrail / Activity logging / GuardDuty / Config was disabled, deleted, or stopped** — the cloud equivalent of clearing the event log.
- A login or API call shows **impossible travel**, an unfamiliar source IP, or an unexpected `assumed-role` / cross-account principal.

## Quick path (the 90% case)
1. **Timeline-first.** Fold the exported logs into one sorted chronology with `log2timeline.py` (the `aws_cloudtrail_log` / `azure_activity_log` / `gcp_log` parsers) + `psort.py` into a CSV, and in parallel flatten the raw JSON with `jq` into one event-per-line stream sorted by `eventTime`. Skim it inside `#{time_window}` BEFORE committing to a story — the order of credential-creation then resource-abuse then logging-disable is the case.
2. **Find the actor.** Pull the distinct `userIdentity` (ARN / principalId / UPN), `sourceIPAddress`, and `userAgent` per event with `jq`; flag any `assumed-role`, `root`, brand-new access key, or an IP/userAgent outside the account baseline.
3. **Find the abuse.** Grep the flattened stream for the high-signal `eventName`s: `CreateUser`/`CreateAccessKey`/`AttachUserPolicy` (rogue identity), `ModifySnapshotAttribute`/`ShareSnapshot`/`CreateImage` (image exfil), `PutBucketPolicy`/`PutBucketAcl`/`PutBucketPublicAccessBlock` (public exposure), `AuthorizeSecurityGroupIngress` (firewall open), `RunInstances` (mining).
4. **Find the cover-up.** `StopLogging`/`DeleteTrail`/`PutEventSelectors` (CloudTrail off), `DeleteDetector`/`DeleteFlowLogs`, an Activity-log diagnostic-setting deletion, or a **gap** in event continuity — disabling logging is itself the finding.
5. **Corroborate.** Tie each control-plane event to a second source: the resulting resource state in a second export, the `requestParameters`/`responseElements` of the same call, or a paired identity-log sign-in. One log line is a lead, not a fact.

If credential-creation, a resource-abuse call, and (if present) a logging-disable all line up on one timeline from one actor principal with a corroborating second field, you are mostly done. Otherwise drop into the full Steps.

## How it unfolds (the story)
An actor obtains a credential — a leaked long-term access key in a public repo, a phished console session, or an over-permissioned `assumed-role` — and authenticates to the cloud control plane from an unfamiliar IP. They lock in persistence by minting a new IAM user/role and a fresh access key (or setting a login-profile on a machine identity, or deregistering MFA), then monetize or exfiltrate: copying disk snapshots/AMIs to an attacker account, flipping a storage bucket to public, opening a security group, or launching a fleet of large instances to mine. To slow responders they stop or delete the audit trail and disable threat-detection. Every one of those moves is an API call that the cloud platform recorded in the audit log we exported — so the whole chain is reconstructable from the log plus the resource-state it produced.

## Theories to test (and how to rule each out)
| Theory (who / why) | If true, you'd find… | Rule it out if… |
|---|---|---|
| **External-commodity (leaked key → automated abuse)** | A long-term access key authenticating from a hosting/VPN ASN; within minutes `RunInstances` of large GPU/compute types in many regions, or mass `CreateAccessKey`; scripted userAgent (aws-cli, boto, an SDK) | The key only made read-only calls from a known corporate IP; no resource creation; userAgent and region match the account baseline |
| **External-targeted (hands-on intruder)** | A console or `assumed-role` session from an unexpected IP; deliberate sequence — recon (List*/Describe*), persistence (CreateUser/CreateAccessKey), then snapshot share or bucket-public, then StopLogging; low-and-slow, business-hours-blending | All privileged calls trace to known admins from known IPs with change-tickets; no logging-disable; no cross-account share |
| **Other-insider (compromised legit principal)** | A valid employee principal performing out-of-character control-plane changes from an unusual IP/device or odd hour; impossible travel vs the same principal's prior events | Source IP, userAgent, and hours match that principal's own baseline; the change has a sanctioned ticket |
| **Insider (authorized admin acting maliciously)** | A real admin principal sharing a snapshot to a personal account, making a bucket public, or creating a backdoor key — from inside, no stolen-cred evidence | The action is covered by an approved change/break-glass record AND the destination/grantee is an organization-owned account → benign; reclassify |
| **Supply-chain / automation abuse (CI-CD or RMM role)** | A pipeline/automation role (Terraform, a deploy role, an RMM/SaaS integration) making the change; same principal touches many accounts; parent is a known automation userAgent | The automation role is scoped and the change matches its declared IaC plan / pipeline run id; no human session behind it |
| **Innocent / benign (NOT an attack)** | `RunInstances`/`AuthorizeSecurityGroupIngress`/`PutBucketPolicy` by autoscaling, a sanctioned deploy, or a backup job sharing snapshots to an org backup account; logging changes from an approved config refactor; all by expected principals in business hours | A clear change-control/IaC record explains every flagged call AND principal+source+region are expected → benign cause confirmed; reclassify |

*(at least one benign + at least one malicious, each ACTIVELY refuted. Attacker types mapped: insider · other-insider · external-commodity · external-targeted · supply-chain · innocent.)*

## Evidence → Tool → What it reveals (per OS)
| Evidence | SIFT tool | What it tells you *for this attack* | OS |
|---|---|---|---|
| AWS CloudTrail records (`*.json.gz` under `AWSLogs/.../CloudTrail/`) | `log2timeline.py` (`aws_cloudtrail_log` parser) + `psort.py` | Every control-plane API call with eventName, userIdentity, sourceIPAddress, eventTime — the master record of identity/resource/logging changes | cloud |
| Same CloudTrail JSON, raw | `jq` over the decompressed `Records[]` | Field-precise extraction: distinct principals, IPs, userAgents; filter by eventName; pull requestParameters/responseElements verbatim | cloud |
| Azure Activity / Monitor log export (JSON) | `log2timeline.py` (`azure_activity_log` parser) + `psort.py`; `jq` | operationName (e.g. role assignment, NSG rule write, key-vault access), caller (UPN), callerIpAddress — the Azure analog of CloudTrail | cloud |
| GCP Cloud Audit Logs export (JSON) | `log2timeline.py` (`gcp_log` parser) + `psort.py`; `jq` | protoPayload.methodName, authenticationInfo.principalEmail, requestMetadata.callerIp — the GCP analog | cloud |
| Plaso storage metadata | `pinfo.py` | Which cloud parser actually ran and how many events it produced — proves the log type was recognized, not silently skipped | cloud |
| The flattened event stream (case output) | `aws` CLI (read-only, run against the LOCAL exported JSON, never a live account) | Parse/validate CloudTrail JSON shape offline and re-emit normalized fields; sanity-check the export before grepping | cloud |
| Any export carried on a seized disk image | `mmls` / `fls` / `icat` (TSK) | Locate and extract the exported `.json`/`.json.gz` log files off the image into #{case_out}/extracted when the logs arrived inside an E01/dd | cloud |
| Raw log tree, string sweep | `srch_strings` / `bulk_extractor` | Recover IPs, ARNs, bucket names, and access-key IDs that survive in truncated/partial log fragments or in unallocated space of a carrying image | cloud |
| Exported logs as text | `bstrings` | Regex-pull access-key IDs (AKIA…/ASIA…), ARNs, and URLs from the export when JSON is malformed and `jq` refuses to parse | cloud |

*This box has the `aws` CLI but NOT `az` (Azure CLI) or the Google Cloud SDK, and NOT `pandas`. Azure/GCP logs are analyzed via `log2timeline.py` cloud parsers + `jq` only. All analysis is INGEST-ONLY on EXPORTED logs — no command in any Step authenticates to or queries a live cloud account.*

## Step 0 — evidence inventory & access bootstrap
- n: 0
  tool: |
    mkdir -p "#{case_out}/receipts" "#{case_out}/extracted" && ls -laR "#{mount_root}" > "#{case_out}/receipts/00.txt" 2>&1 ; find "#{mount_root}" -type f \( -iname "*.json" -o -iname "*.json.gz" -o -iname "*.gz" \) > "#{case_out}/receipts/00.txt.filelist" 2>&1 ; find "#{mount_root}" -type f -iname "*.json.gz" -exec gzip -t {} \; >> "#{case_out}/receipts/00.txt" 2>&1 ; img_stat "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; mmls "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1
  expect: every evidence file classified; #{image_path}/#{mount_root}/#{case_out} bound; the export tree is enumerated and at least one CloudTrail/Azure-Activity/GCP-audit JSON or JSON.gz is present and readable (gzip -t passes); absence of any cloud-log export is itself recorded
  check: |
    test -s "#{case_out}/receipts/00.txt.filelist" -o -n "$(ls "#{case_out}/extracted" 2>/dev/null)"
  falsify: evidence dir empty/unreadable, or NO json/json.gz cloud-log export found anywhere (this playbook needs exported logs, not a bare disk image)
  on_result: {expect_met: goto 1, falsify_met: STOP — report evidence-access failure; if the export is sealed inside a disk image use mmls/fls/icat to extract the json files into #{case_out}/extracted then retry; if no cloud log exists at all pivot acquisition-custody, neither: try the icat-extract fallback (fls to find the AWSLogs/Activity json inodes, icat each into #{case_out}/extracted); if that also fails treat as falsify_met}
  emits: [key_artifacts]
  serves: [rogue-iam-user-created, rogue-iam-role-created, rogue-access-key-created, login-profile-or-password-set-for-persistence, mfa-device-deregistered-or-disabled, snapshot-or-ami-shared-or-copied-cross-account, ebs-snapshot-made-public, s3-bucket-policy-or-acl-made-public, blob-or-bucket-storage-exposed-public, s3-object-mass-download-exfil, security-group-or-firewall-opened, cloudtrail-or-logging-disabled-or-deleted, guardduty-or-config-detector-disabled, cryptomining-instance-spin-up, control-plane-persistence-lambda-or-eventbridge, cross-account-assume-role-abuse, kms-key-policy-or-grant-tampered, resource-mass-deletion-or-destruction]
  provenance: {receipt_id: 00, artifact: evidence directory listing + cloud-log file enumeration, offset_or_row: full listing, literal_cited: first CloudTrail/Activity/GCP json filename + gzip-test result}

## Steps (executable — decision-driven)
- n: 1
  precondition: "exists #{case_out}/receipts/00.txt.filelist"
  tool: |
    log2timeline.py --status_view none --parsers "aws_cloudtrail_log,azure_activity_log,gcp_log" "#{case_out}/cloud.plaso" "#{mount_root}" > "#{case_out}/receipts/01.txt" 2>&1 ; psort.py -o l2tcsv "#{case_out}/cloud.plaso" > "#{case_out}/cloud_timeline.csv" 2>> "#{case_out}/receipts/01.txt" ; pinfo.py "#{case_out}/cloud.plaso" >> "#{case_out}/receipts/01.txt" 2>&1
  expect: a single sorted CSV (#{case_out}/cloud_timeline.csv) of control-plane events with eventTime, eventName/operationName, the principal, and sourceIPAddress — the timeline-first artifact every later step filters; pinfo confirms a cloud parser ran with a non-zero event count
  check: |
    test -s "#{case_out}/cloud_timeline.csv" && grep -qiE "cloudtrail|azure|gcp|eventName|operationName|methodName" "#{case_out}/cloud_timeline.csv"
  falsify: plaso recognized no cloud-log records (event count zero), or every file failed to parse (wrong format / corrupt export)
  on_result: {expect_met: goto 2, falsify_met: fall back to the raw jq stream in step 2 directly; if the export is not JSON at all record absence and pivot cloud-identity-saas for the identity-log angle, neither: re-run log2timeline.py without --parsers to auto-detect; if pinfo still shows zero cloud events treat the export as unrecognized and lean on the jq/bstrings raw path in steps 2 and 8}
  emits: [timeline_events]
  serves: [rogue-iam-user-created, snapshot-or-ami-shared-or-copied-cross-account, s3-bucket-policy-or-acl-made-public, security-group-or-firewall-opened, cloudtrail-or-logging-disabled-or-deleted]
  provenance: {receipt_id: 01, artifact: exported cloud audit logs, offset_or_row: cloud_timeline.csv header + pinfo event count, literal_cited: pinfo cloud-parser name + event-count line}

- n: 2
  precondition: "exists #{case_out}/receipts/00.txt.filelist"
  tool: |
    find "#{mount_root}" "#{case_out}/extracted" -type f -iname "*.json.gz" -exec sh -c 'gzip -dc "$1"' _ {} \; > "#{case_out}/ct_raw.json" 2>> "#{case_out}/receipts/02.txt" ; find "#{mount_root}" "#{case_out}/extracted" -type f -iname "*.json" ! -iname "*.gz" -exec cat {} \; >> "#{case_out}/ct_raw.json" 2>> "#{case_out}/receipts/02.txt" ; jq -r '(.Records // .value // .)[]? | [(.eventTime // .time // .timestamp), (.eventName // .operationName.value // .protoPayload.methodName // .operationName), ((.userIdentity.arn) // (.userIdentity.principalId) // .caller // .protoPayload.authenticationInfo.principalEmail // .identity), (.sourceIPAddress // .callerIpAddress // .protoPayload.requestMetadata.callerIp), (.userAgent // .protoPayload.requestMetadata.callerSuppliedUserAgent)] | @tsv' "#{case_out}/ct_raw.json" > "#{case_out}/events.tsv" 2> "#{case_out}/receipts/02.txt" ; sort "#{case_out}/events.tsv" | tee -a "#{case_out}/receipts/02.txt" | wc -l >> "#{case_out}/receipts/02.txt"
  expect: a flattened tab-separated stream (#{case_out}/events.tsv) of time / eventName / principal / sourceIP / userAgent per API call, sortable by time — the field-precise backbone for every grep below; row count greater than zero
  check: |
    test -s "#{case_out}/events.tsv" && grep -cqE "." "#{case_out}/events.tsv"
  falsify: jq errors on every file (malformed JSON), or the stream is empty — no parseable records to flatten
  on_result: {expect_met: goto 3, falsify_met: the export is not valid CloudTrail/Activity/GCP JSON — recover fields with bstrings/srch_strings (step 8) and continue lead-only; record the malformed export as a finding, neither: run jq with a per-record try/catch over single files to isolate the bad file; parse the survivors and note which files were unreadable}
  emits: [actor_accounts, timeline_events]
  serves: [rogue-access-key-created, cross-account-assume-role-abuse]
  provenance: {receipt_id: 02, artifact: decompressed CloudTrail/Activity/GCP Records, offset_or_row: events.tsv rows, literal_cited: eventTime + eventName + principal + sourceIP tuple}

- n: 3
  precondition: "exists #{case_out}/events.tsv"
  tool: |
    cut -f3,4,5 "#{case_out}/events.tsv" | sort | uniq -c | sort -rn > "#{case_out}/receipts/03.txt" 2>&1 ; jq -r '(.Records // .value // .)[]? | select((.userIdentity.type // "") == "AssumedRole" or ((.userIdentity.arn // "") | test("assumed-role|:root"))) | [(.eventTime), (.eventName), (.userIdentity.arn // .userIdentity.principalId), (.sourceIPAddress), (.userIdentity.sessionContext.sessionIssuer.arn // "")] | @tsv' "#{case_out}/ct_raw.json" >> "#{case_out}/receipts/03.txt" 2>&1
  expect: a per-principal/IP/userAgent frequency table; one or more principals whose sourceIPAddress is an unfamiliar/hosting ASN or whose userAgent is a scripted SDK (aws-cli, Boto, python-requests); and any AssumedRole or :root principal — flag cross-account assume-role and root usage
  check: |
    test -s "#{case_out}/receipts/03.txt" && grep -qiE "assumed-role|:root|aws-cli|boto|python-requests|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" "#{case_out}/receipts/03.txt"
  falsify: every principal/IP/userAgent matches the known account baseline (corporate egress IPs, expected admins, sanctioned automation) — no anomalous actor surface
  on_result: {expect_met: record the suspect principal ARN + sourceIP + userAgent as actor IOCs; goto 4, falsify_met: record no anomalous actor in the control-plane log; continue to resource abuse at goto 4 in case a known principal was hijacked, neither: widen #{time_window}; correlate the principal against the identity/sign-in log and pivot cloud-identity-saas if the credential compromise lives in the identity layer}
  emits: [actor_accounts, key_iocs]
  serves: [cross-account-assume-role-abuse, rogue-access-key-created]
  provenance: {receipt_id: 03, artifact: events.tsv + userIdentity records, offset_or_row: uniq-count table rows + AssumedRole rows, literal_cited: suspect principal ARN + sourceIP + userAgent}

- n: 4
  precondition: "exists #{case_out}/ct_raw.json"
  tool: |
    jq -r '(.Records // .value // .)[]? | select((.eventName // .operationName.value // .operationName // "") | test("CreateUser|CreateAccessKey|CreateLoginProfile|UpdateLoginProfile|AttachUserPolicy|AttachRolePolicy|PutUserPolicy|CreateRole|UpdateAssumeRolePolicy|DeactivateMFADevice|DeleteVirtualMFADevice|microsoft.authorization/roleassignments/write|setIamPolicy"; "i")) | [(.eventTime // .time), (.eventName // .operationName.value // .operationName // .protoPayload.methodName), (.userIdentity.arn // .caller // .protoPayload.authenticationInfo.principalEmail), (.sourceIPAddress // .callerIpAddress), ((.requestParameters // .properties // .protoPayload.request) | tostring)] | @tsv' "#{case_out}/ct_raw.json" > "#{case_out}/receipts/04.txt" 2>&1
  expect: identity-persistence calls — CreateUser/CreateAccessKey/CreateLoginProfile/AttachUserPolicy granting admin, UpdateAssumeRolePolicy widening a trust policy, or DeactivateMFADevice/DeleteVirtualMFADevice removing MFA (Azure roleAssignments write / GCP setIamPolicy analogs) — by the suspect principal inside #{time_window}; capture the new user/key name and the policy/ARN from requestParameters
  check: |
    grep -qiE "CreateUser|CreateAccessKey|CreateLoginProfile|AttachUserPolicy|UpdateAssumeRolePolicy|DeactivateMFADevice|DeleteVirtualMFADevice|roleassignments|setIamPolicy" "#{case_out}/receipts/04.txt"
  falsify: no identity-creation, no policy-attach, and no MFA-removal in #{time_window} — no event-logged identity persistence on this account
  on_result: {expect_met: record the new IAM user/role/access-key name + attached policy ARN as IOCs; goto 5, falsify_met: record no identity persistence in the control-plane log; the actor may persist via a resource (Lambda/EventBridge) instead — goto 7 then return; pivot cloud-identity-saas if the persistence is in the identity provider, neither: re-run the filter with the Azure/GCP operationName spellings for this provider; widen #{time_window}}
  emits: [actor_accounts, key_iocs]
  serves: [rogue-iam-user-created, rogue-iam-role-created, rogue-access-key-created, login-profile-or-password-set-for-persistence, mfa-device-deregistered-or-disabled]
  provenance: {receipt_id: 04, artifact: CloudTrail IAM events, offset_or_row: receipt 04 matched rows, literal_cited: CreateAccessKey/CreateUser eventName + new principal name from requestParameters}

- n: 5
  precondition: "exists #{case_out}/ct_raw.json"
  tool: |
    jq -r '(.Records // .value // .)[]? | select((.eventName // .operationName.value // .operationName // "") | test("ModifySnapshotAttribute|ModifyImageAttribute|SharedSnapshotCopyInitiated|CopySnapshot|CreateImage|CopyImage|PutBucketPolicy|PutBucketAcl|PutBucketPublicAccessBlock|DeletePublicAccessBlock|PutObjectAcl|setIamPolicy.*storage|microsoft.storage/storageaccounts/.*write"; "i")) | [(.eventTime // .time), (.eventName // .operationName.value // .operationName // .protoPayload.methodName), (.userIdentity.arn // .caller // .protoPayload.authenticationInfo.principalEmail), (.sourceIPAddress // .callerIpAddress), ((.requestParameters // .properties) | tostring)] | @tsv' "#{case_out}/ct_raw.json" > "#{case_out}/receipts/05.txt" 2>&1 ; grep -ioE "[0-9]{12}" "#{case_out}/receipts/05.txt" | sort -u >> "#{case_out}/receipts/05.txt"
  expect: data-exposure calls — ModifySnapshotAttribute/ModifyImageAttribute adding a foreign account or group=all (snapshot/AMI shared cross-account or made public), CopySnapshot to another account, or PutBucketPolicy/PutBucketAcl/DeletePublicAccessBlock opening storage to the public — with the grantee account id (a 12-digit AWS account number not your own) or a Principal of "*" captured from requestParameters
  check: |
    grep -qiE "ModifySnapshotAttribute|ModifyImageAttribute|CopySnapshot|CreateImage|PutBucketPolicy|PutBucketAcl|DeletePublicAccessBlock|PutObjectAcl" "#{case_out}/receipts/05.txt"
  falsify: no snapshot/AMI share-or-copy and no bucket/ACL-public call in #{time_window} — no control-plane data exposure evidenced
  on_result: {expect_met: record the snapshot/AMI/image id + grantee account id (or Principal star) and bucket name as exfil facts; goto 6, falsify_met: record no control-plane data exposure; check for object-level mass download (GetObject volume) before clearing this theory; goto 6, neither: re-run with the Azure storageAccounts/GCP storage method spellings; widen #{time_window}; if a bucket went public confirm against the resulting bucket-policy state}
  emits: [exfil_or_encryption_facts, key_iocs]
  serves: [snapshot-or-ami-shared-or-copied-cross-account, ebs-snapshot-made-public, s3-bucket-policy-or-acl-made-public, blob-or-bucket-storage-exposed-public]
  provenance: {receipt_id: 05, artifact: CloudTrail EC2/S3 events, offset_or_row: receipt 05 matched rows + 12-digit account ids, literal_cited: ModifySnapshotAttribute grantee account id or PutBucketPolicy Principal star}

- n: 6
  precondition: "exists #{case_out}/ct_raw.json"
  tool: |
    jq -r '(.Records // .value // .)[]? | select((.eventName // .operationName.value // .operationName // "") | test("AuthorizeSecurityGroupIngress|RevokeSecurityGroupEgress|ModifyInstanceAttribute|RunInstances|networkSecurityGroups/securityRules/write|compute.firewalls.insert|compute.instances.insert"; "i")) | [(.eventTime // .time), (.eventName // .operationName.value // .operationName // .protoPayload.methodName), (.awsRegion // .location // ""), (.userIdentity.arn // .caller // .protoPayload.authenticationInfo.principalEmail), ((.requestParameters // .properties) | tostring)] | @tsv' "#{case_out}/ct_raw.json" > "#{case_out}/receipts/06.txt" 2>&1 ; grep -ioE "RunInstances" "#{case_out}/receipts/06.txt" | wc -l >> "#{case_out}/receipts/06.txt" ; grep -ioE "0\.0\.0\.0/0|::/0" "#{case_out}/receipts/06.txt" | sort -u >> "#{case_out}/receipts/06.txt"
  expect: network/compute abuse — AuthorizeSecurityGroupIngress opening a port to 0.0.0.0/0 (firewall open), and/or a burst of RunInstances of large/GPU instance types across many awsRegions (cryptomining spin-up) inside #{time_window}; capture the CIDR opened, the port, and the instance count/types from requestParameters
  check: |
    grep -qiE "AuthorizeSecurityGroupIngress|RunInstances|securityRules/write|firewalls.insert|instances.insert|0\.0\.0\.0/0" "#{case_out}/receipts/06.txt"
  falsify: no ingress-open to a wide CIDR and no anomalous RunInstances burst — no firewall-open or mining spin-up evidenced
  on_result: {expect_met: record the opened CIDR/port and the new instance ids/types/regions as IOCs; goto 7, falsify_met: record no network/compute abuse; continue to logging-disable at goto 7, neither: re-run with the Azure NSG / GCP firewall method spellings; widen #{time_window}; correlate RunInstances regions against the account baseline regions}
  emits: [key_iocs, timeline_events]
  serves: [security-group-or-firewall-opened, cryptomining-instance-spin-up]
  provenance: {receipt_id: 06, artifact: CloudTrail EC2/network events, offset_or_row: receipt 06 matched rows + RunInstances count, literal_cited: AuthorizeSecurityGroupIngress 0.0.0.0/0 CIDR or RunInstances instance-type+region}

- n: 7
  precondition: "exists #{case_out}/ct_raw.json"
  tool: |
    jq -r '(.Records // .value // .)[]? | select((.eventName // .operationName.value // .operationName // "") | test("StopLogging|DeleteTrail|UpdateTrail|PutEventSelectors|DeleteDetector|UpdateDetector|DeleteFlowLogs|StopConfigurationRecorder|DeleteConfigurationRecorder|CreateFunction|UpdateFunctionCode|PutRule|PutTargets|PutKeyPolicy|CreateGrant|ScheduleKeyDeletion|microsoft.insights/diagnosticsettings/delete|google.logging.*Delete"; "i")) | [(.eventTime // .time), (.eventName // .operationName.value // .operationName // .protoPayload.methodName), (.userIdentity.arn // .caller // .protoPayload.authenticationInfo.principalEmail), (.sourceIPAddress // .callerIpAddress), ((.requestParameters // .properties) | tostring)] | @tsv' "#{case_out}/ct_raw.json" > "#{case_out}/receipts/07.txt" 2>&1
  expect: defense-evasion and control-plane-persistence calls — StopLogging/DeleteTrail/PutEventSelectors (CloudTrail off), DeleteDetector/DeleteFlowLogs/StopConfigurationRecorder (detection off), an Azure diagnosticSettings delete; and/or persistence via CreateFunction/UpdateFunctionCode + PutRule/PutTargets (Lambda triggered by EventBridge) or PutKeyPolicy/CreateGrant/ScheduleKeyDeletion (KMS tamper) inside #{time_window}
  check: |
    grep -qiE "StopLogging|DeleteTrail|PutEventSelectors|DeleteDetector|DeleteFlowLogs|StopConfigurationRecorder|CreateFunction|UpdateFunctionCode|PutRule|PutKeyPolicy|CreateGrant|ScheduleKeyDeletion|diagnosticsettings/delete" "#{case_out}/receipts/07.txt"
  falsify: no logging-disable, no detector-delete, and no Lambda/EventBridge/KMS persistence call — no event-logged cover-up or control-plane persistence
  on_result: {expect_met: record logging-disable/persistence as a high-signal finding (deliberate operator); goto 8, falsify_met: record logs continuous, no clearing; check the event-continuity gap in step 8 anyway; goto 8, neither: re-run with the Azure/GCP logging-delete method spellings; inspect for a TIME GAP in cloud_timeline.csv that no StopLogging accounts for and flag it as silent tampering; goto 8}
  emits: [key_artifacts, timeline_events]
  serves: [cloudtrail-or-logging-disabled-or-deleted, guardduty-or-config-detector-disabled, control-plane-persistence-lambda-or-eventbridge, kms-key-policy-or-grant-tampered]
  provenance: {receipt_id: 07, artifact: CloudTrail management events, offset_or_row: receipt 07 matched rows, literal_cited: StopLogging/DeleteTrail eventName + trail name or CreateFunction function name}

- n: 8
  precondition: "exists #{case_out}/events.tsv"
  tool: |
    jq -r '(.Records // .value // .)[]? | select((.eventName // .operationName.value // .operationName // "") | test("DeleteUser|DeleteAccessKey|TerminateInstances|DeleteBucket|DeleteDBInstance|DeleteSnapshot|DeleteObject|compute.instances.delete|storage.buckets.delete"; "i")) | [(.eventTime // .time), (.eventName // .operationName.value // .operationName // .protoPayload.methodName), (.userIdentity.arn // .caller // .protoPayload.authenticationInfo.principalEmail)] | @tsv' "#{case_out}/ct_raw.json" > "#{case_out}/receipts/08.txt" 2>&1 ; sort -k1 "#{case_out}/events.tsv" | awk -F"\t" "NR==1{print;prev=\$1} NR>1{print} END{print NR\" total events\"}" >> "#{case_out}/receipts/08.txt" 2>&1 ; bstrings -f "#{case_out}/ct_raw.json" --lr "AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}" >> "#{case_out}/receipts/08.txt" 2>&1
  expect: a fused review — destructive calls (DeleteUser/TerminateInstances/DeleteBucket/DeleteSnapshot = mass deletion) if present; the full time-ordered event list confirming entry then identity-persistence then resource-abuse then logging-disable order with no unexplained gap; and any long-term access-key id (AKIA/ASIA) recovered by bstrings as a hard IOC, inside #{time_window}
  check: |
    test -s "#{case_out}/receipts/08.txt" && grep -qiE "total events|AKIA|ASIA|Delete|Terminate" "#{case_out}/receipts/08.txt"
  falsify: ordering is impossible (resource-abuse precedes any authenticated principal) OR an unexplained gap that no StopLogging/DeleteTrail accounts for — clock skew or missing log segments
  on_result: {expect_met: COMMIT the conclusion with a confidence label; close per the gate, falsify_met: re-open the Theories table; an inversion or gap may mean missing log segments or a second unlogged credential path — anchor to the cloud-provider eventTime sequence and note the gap as a finding, neither: confirm the cloud parser ran via pinfo; re-filter the timeline to #{time_window}; if bstrings found a key id not seen in events.tsv the export is incomplete — record it}
  emits: [exfil_or_encryption_facts, timeline_events]
  serves: [resource-mass-deletion-or-destruction, s3-object-mass-download-exfil, rogue-access-key-created]
  provenance: {receipt_id: 08, artifact: CloudTrail destructive events + fused timeline + recovered key ids, offset_or_row: receipt 08 ordered rows + AKIA/ASIA hits, literal_cited: ordered entry-persistence-abuse-coverup chain or recovered AKIA key id}

## Linux branch (L1..Ln) — REQUIRED, numbered, same step shape
- n: L1
  precondition: "os == linux"
  tool: |
    fsstat -o #{ntfs_offset_sectors} "#{image_path}" > "#{case_out}/receipts/L01.txt" 2>&1 ; find "#{mount_root}" -maxdepth 4 -type d \( -iname "AWSLogs" -o -iname "CloudTrail" -o -iname "insights" \) >> "#{case_out}/receipts/L01.txt" 2>&1 ; find "#{mount_root}" -type f \( -iname "*.json" -o -iname "*.json.gz" \) >> "#{case_out}/receipts/L01.txt" 2>&1
  expect: this evidence is an EXPORTED CLOUD-LOG tree (or a Linux disk image carrying one), NOT live cloud — the cloud-iaas control-plane case is analyzed entirely from exported JSON; confirm the export files exist on this (possibly Linux) host and record cloud-only because the control plane has no on-host Windows/Linux equivalent artifact, only its exported audit log
  check: |
    test -n "$(find "#{mount_root}" -type f \( -iname "*.json" -o -iname "*.json.gz" \) 2>/dev/null)" -o -n "$(grep -iE "ext[234]|xfs" "#{case_out}/receipts/L01.txt" 2>/dev/null)"
  falsify: no json/json.gz export anywhere AND the file system is not Linux — wrong evidence type for this playbook; the control-plane log was never exported
  on_result: {expect_met: goto L2, falsify_met: record cloud-log export absent; pivot acquisition-custody to obtain the CloudTrail/Activity/GCP export, neither: confirm evidence type from Step 0; if a disk image icat-extract any AWSLogs json into #{case_out}/extracted and run L2 against that}
  emits: [key_artifacts]
  serves: [cloudtrail-or-logging-disabled-or-deleted]
  provenance: {receipt_id: L01, artifact: file system + export-tree listing, offset_or_row: fsstat header + AWSLogs/json listing, literal_cited: AWSLogs/CloudTrail dir or json export present (cloud-only confirmed)}

- n: L2
  precondition: "os == linux"
  tool: |
    log2timeline.py --status_view none --parsers "aws_cloudtrail_log,azure_activity_log,gcp_log" "#{case_out}/cloud_linux.plaso" "#{mount_root}" > "#{case_out}/receipts/L02.txt" 2>&1 ; psort.py -o l2tcsv "#{case_out}/cloud_linux.plaso" > "#{case_out}/cloud_linux_timeline.csv" 2>> "#{case_out}/receipts/L02.txt" ; srch_strings "#{case_out}/cloud_linux_timeline.csv" 2>/dev/null | grep -iE "StopLogging|DeleteTrail|CreateAccessKey|ModifySnapshotAttribute|PutBucketPolicy|AuthorizeSecurityGroupIngress|RunInstances" >> "#{case_out}/receipts/L02.txt" 2>&1
  expect: the same control-plane chronology built from the export on a Linux host — log2timeline cloud parsers render the CloudTrail/Activity/GCP events into a CSV, and the high-signal eventNames (StopLogging, CreateAccessKey, ModifySnapshotAttribute, PutBucketPolicy, AuthorizeSecurityGroupIngress, RunInstances) appear, ordered inside #{time_window}
  check: |
    test -s "#{case_out}/cloud_linux_timeline.csv" -o -s "#{case_out}/receipts/L02.txt"
  falsify: the export tree is empty or unparseable on this host (truncated/zero-length json) — record the gap as a finding; no parser substitutes for missing exported log text
  on_result: {expect_met: record actor principal + sourceIP + the abuse eventNames; commit with a confidence label, falsify_met: record export-gap/truncation as a finding; recover fields from unallocated with srch_strings/bstrings over the carrying image; pivot acquisition-custody, neither: widen #{time_window}; re-run log2timeline without --parsers to auto-detect the export format and re-render}
  emits: [actor_accounts, timeline_events]
  serves: [cloudtrail-or-logging-disabled-or-deleted, rogue-access-key-created, snapshot-or-ami-shared-or-copied-cross-account]
  provenance: {receipt_id: L02, artifact: exported cloud audit logs on Linux host, offset_or_row: cloud_linux_timeline.csv rows + grep hits, literal_cited: high-signal eventName + principal + sourceIP line}

## Corroboration (two-source rule)
`required_sources: 2` · `pairs:`
- `[ control-plane eventName (jq, step 4-7) ↔ the plaso super-timeline placement of that same event (step 1) ]`
- `[ CreateAccessKey/CreateUser (step 4) ↔ the new principal later AUTHENTICATING in events.tsv as a distinct userIdentity (step 2/3) ]`
- `[ ModifySnapshotAttribute grantee account id (step 5) ↔ the responseElements/resulting share-state in the same record, or a second export of snapshot attributes ]`
- `[ AuthorizeSecurityGroupIngress 0.0.0.0/0 (step 6) ↔ the RunInstances that uses that security group / the resulting instance state (step 6) ]`
- `[ StopLogging/DeleteTrail (step 7) ↔ the event-continuity GAP it produces in cloud_timeline.csv (step 8) ]`
- `[ recovered AKIA/ASIA key id (step 8) ↔ the CreateAccessKey responseElements that minted it (step 4) ]`

One hit is a *lead*; promote to *fact* only when its paired source agrees.

## Don't get fooled (red flags & anti-forensics)
- **A disabled trail is evidence, not absence.** StopLogging/DeleteTrail/PutEventSelectors near the activity proves a deliberate operator — do not read the post-disable silence as nothing happened. Treat the gap itself as a finding and anchor everything else to it.
- **Silent gaps with no StopLogging.** An attacker who controls a region can simply act where no trail is configured, or delete only specific log files from the S3/storage export. Test event-continuity per account/region in cloud_timeline.csv — an unexplained time gap is tampering even with no explicit StopLogging.
- **`assumed-role` hides the human.** A CloudTrail record may show a role ARN, not the person; read `userIdentity.sessionContext.sessionIssuer` and the source IP/userAgent, and correlate to who assumed the role — the role name alone is not the actor.
- **Eventual-consistency and multi-region duplication.** The same logical action can appear multiple times or out of strict order across regions; de-duplicate by `eventID` and anchor ordering to `eventTime`, not file order, before claiming a sequence.
- **`errorCode` matters.** A CreateUser/PutBucketPolicy record with `errorCode: AccessDenied` is an ATTEMPT, not a success — filter on successful calls before committing an exposure finding, and treat the denied attempts as recon/intent signal.
- **Public is not always malicious; org-internal share is not always benign.** A bucket policy `Principal: "*"` may be an intended static-site; a snapshot shared to a 12-digit account may be a sanctioned backup account — confirm the grantee/Principal against the org's own account list and change-control, both ways.
- **userAgent and IP can be spoofed/proxied.** A corporate-looking userAgent or an IP inside a VPN range proves little alone; weight the eventName sequence and the new-principal authentication over a single network field.
- **Missing evidence is itself a finding.** An export that starts after the incident, or a single-region trail when the abuse was multi-region, is a collection gap — record it; do not read absence as innocence.

## Failure modes
```
- mode: evidence-access failure — the export tree is unreadable, or the logs are sealed inside a seized disk image and not yet extracted
  guard: Step 0 fallback chain — gzip -t to test archives, then mmls/fls/icat the AWSLogs/Activity json inodes into #{case_out}/extracted; if no cloud log exists at all, record acquisition failure and pivot acquisition-custody
- mode: primary-artifact-absent — no CloudTrail/Activity/GCP export present, or the trail was disabled before the incident so the key calls were never recorded
  guard: record the absence/disable as a finding (it IS evidence of a logging gap or a pre-incident StopLogging); name the secondary sources (the identity/sign-in log, resulting resource state, bstrings-recovered key ids) and pivot cloud-identity-saas
- mode: tool-output drift — CloudTrail/Activity/GCP JSON field names differ by provider/schema version, or a plaso cloud-parser name changes, so a jq path or a check literal misses
  guard: on check exit 2, adjudicate from the prose expect/falsify against the receipt, cap confidence at inferred; the jq filters already fall back across .Records/.value/. and eventName/operationName/methodName spellings; if still empty, bstrings/srch_strings the raw json for the eventName/ARN literal, never silently pass
- mode: malformed/truncated JSON — jq errors on a file (partial export, mixed gzip)
  guard: run jq per-file with try/catch to isolate the bad file, parse the survivors, and recover fields from the broken file with bstrings/srch_strings; note the unreadable file and its byte range as a finding
- mode: plaso recognizes zero cloud events — the export format is unrecognized or not JSON
  guard: re-run log2timeline.py without --parsers to auto-detect; if pinfo still shows zero, treat the export as unrecognized and drive the whole case from the jq/bstrings raw path; record the parser miss
```
Minimum set every playbook covers: evidence-access failure (Step 0 fallback chain) · primary-artifact-absent (absence recorded, secondary source named) · tool-output drift (`check` exits 2 → prose adjudication, never silent pass).

## Confidence labeling (observation → inference → conclusion)
- **confirmed:** direct receipt verbatim (the exact eventName + principal + sourceIP row) + ≥2 independent sources agree (the API call AND its resulting resource state / a paired authentication / the super-timeline placement) + no unrefuted counter-theory.
- **inferred:** grounded but single-source/interpretive — e.g. a StopLogging with no corroborating gap analysis yet, an event-continuity gap read as tampering, an `assumed-role` attributed to a person without the sessionIssuer trace, or a provider operationName spelling matched only loosely → hedge and tag `⚠️verify`. Every `check`-exit-2 adjudication lands here at best.
- **insufficient_evidence:** precondition unmet (no export; trail disabled before the window; only a partial single-region export) or sources conflict → abstain; state what is missing, do not guess.

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
- **Cloud (the native case):** there is no on-host artifact for control-plane abuse — the only record is the cloud provider's own audit log, exported as JSON. This playbook is INGEST-ONLY on those exports and never authenticates to a live account. AWS = CloudTrail; Azure = Activity/Monitor log; GCP = Cloud Audit Logs. The `aws` CLI is present (used read-only against the LOCAL export); `az` (Azure CLI) and the Google Cloud SDK are NOT on this box, and `pandas` is absent — Azure/GCP are handled with `log2timeline.py` cloud parsers + `jq` instead.
- **Windows / Linux / macOS hosts:** these are not where the control-plane evidence lives. A seized host may CARRY the export (e.g. an analyst's download, a SIEM forwarder's spool) — in that case use `mmls`/`fls`/`icat` (or the Linux branch L1–L2) to extract the json off the image into `#{case_out}/extracted` and then run the same cloud Steps. The host disk may also hold the LEAKED CREDENTIAL (a `~/.aws/credentials`, a config file, a build secret) that the actor used — that is a pivot to the host-forensics categories, not part of this playbook.
- **Linux:** see the numbered branch (L1–L2) — same cloud parsers, run on a Linux host that holds the export.

## Real-case notes (non-obvious things to look for)
- **A leaked long-term key is the classic entry.** AKIA-prefixed keys committed to public GitHub/CI logs are scraped within minutes; the abuse signature is `GetCallerIdentity` then a rapid `RunInstances` of expensive GPU types across every region. Filter RunInstances by region count and instance type, not just presence. `[AWS abuse / general DFIR practice · high]`
- **StopLogging is loud but partial trail-tampering is louder.** Sophisticated actors avoid `StopLogging` (it is itself logged) and instead delete individual log objects from the S3 bucket, or operate in a region with no trail configured. Test for a per-region/per-account event-continuity gap, not just a StopLogging event. `[MITRE T1562.008 · high]`
- **`ModifySnapshotAttribute` is the quiet exfil.** Sharing an EBS snapshot or AMI to an attacker-controlled 12-digit account ID (or `group=all` to make it public) copies whole disks out without ever touching the data plane — check the `createVolumePermission`/`launchPermission` add value for a foreign account id. `[MITRE T1537 · high]`
- **`assumed-role` chains obscure attribution.** A single compromised role can be assumed repeatedly; the human is in `sessionContext.sessionIssuer` and the original `sourceIPAddress`, not the role ARN. Pivot every role back to who assumed it and from where. `[MITRE T1078.004 · high]`
- **`ConsoleLogin` with no MFA and `errorMessage` patterns matter.** A `ConsoleLogin` success from a new IP with `MFAUsed: No`, or a burst of `ConsoleLogin` failures, marks a hijacked human session distinct from a leaked programmatic key. `[MITRE T1078.004 · med]`
- **EventBridge + Lambda is stealth persistence.** A `CreateFunction` plus `PutRule`/`PutTargets` wiring a Lambda to fire on a schedule or on an IAM event is a control-plane backdoor that survives credential rotation — look for it when identity persistence (step 4) looks clean but access keeps recurring. `[MITRE T1546 · med]`
- **Denied attempts are intent.** A wall of `errorCode: AccessDenied` on `CreateUser`/`AttachUserPolicy`/`PutBucketPolicy` is reconnaissance/privilege-probing — it shows what the actor WANTED even where they failed; correlate it with the calls that later succeeded. `[general DFIR practice · med]`

## ATT&CK mapping
- T1078.004 · Initial Access/Persistence · Valid Accounts: Cloud Accounts · leaked key / hijacked session authenticating — steps 2/3
- T1136.003 · Persistence · Create Account: Cloud Account · CreateUser — step 4
- T1098.001 · Persistence · Account Manipulation: Additional Cloud Credentials · CreateAccessKey / CreateLoginProfile — step 4
- T1098.003 · Privilege Escalation · Account Manipulation: Additional Cloud Roles · AttachUserPolicy / UpdateAssumeRolePolicy — step 4
- T1556.006 · Defense Evasion · Modify Authentication Process: MFA · DeactivateMFADevice / DeleteVirtualMFADevice — step 4
- T1537 · Exfiltration · Transfer Data to Cloud Account · ModifySnapshotAttribute / CopySnapshot / CreateImage share — step 5
- T1530 · Collection · Data from Cloud Storage · PutBucketPolicy / PutBucketAcl public exposure + object download — steps 5/8
- T1580 · Discovery · Cloud Infrastructure Discovery · List*/Describe* recon preceding abuse — step 3
- T1562.008 · Defense Evasion · Impair Defenses: Disable or Modify Cloud Logs · StopLogging / DeleteTrail / PutEventSelectors / DeleteFlowLogs — step 7
- T1562.001 · Defense Evasion · Impair Defenses: Disable or Modify Tools · DeleteDetector / StopConfigurationRecorder (GuardDuty/Config) — step 7
- T1496 · Impact · Resource Hijacking · RunInstances cryptomining spin-up — step 6
- T1190 / T1599 · Defense Evasion · AuthorizeSecurityGroupIngress 0.0.0.0/0 firewall open — step 6
- T1546 · Persistence · Event Triggered Execution · CreateFunction + PutRule/PutTargets (Lambda/EventBridge) — step 7
- T1485 · Impact · Data Destruction · TerminateInstances / DeleteBucket / DeleteSnapshot mass deletion — step 8

## Pivots (lead-to-lead graph)
- `on_compromised_principal (step 2/3 suspect principal + sourceIP): cloud-identity-saas — chase the credential/token compromise in the identity provider and SaaS sign-in logs`
- `on_leaked_credential_on_host (step 3/cross-OS .aws-credentials): insider-threat-data-theft — find how the key left the org / who exfiltrated it`
- `on_image_or_snapshot_exfil (step 5 ModifySnapshotAttribute): SELF — re-enter with the grantee account id and the snapshot id bound into #{time_window} to bracket the whole exfil window`
- `on_cryptomining_or_payload (step 6 RunInstances userdata): malware-analysis-triage — triage the instance user-data / dropped miner payload`
- `on_lambda_or_eventbridge_persistence (step 7 CreateFunction): containers-supply-chain — inspect the function code / build artifact for a poisoned dependency`
- `on_logging_disabled_or_gap (step 7/8 StopLogging or continuity gap): SELF — re-enter with the disable timestamp bound into #{time_window} to bracket what the gap hid`
- `on_export_absent_or_unparseable (step 0/1): acquisition-custody — re-acquire the CloudTrail/Activity/GCP export or prove the collection gap`

## Jargon decoder
- **Control plane:** the cloud account's management layer — the APIs that create/modify/delete resources and identities (as opposed to the data plane, the actual data inside the resources).
- **CloudTrail:** AWS's audit log of every control-plane API call (eventName, who, when, from where), delivered as `*.json.gz` files in an S3 bucket — the primary evidence here.
- **Azure Activity log / GCP Cloud Audit Logs:** the Azure and GCP equivalents of CloudTrail (operationName / methodName, caller, callerIp).
- **userIdentity / principal / ARN:** who made the call — a user, role, or service. An **ARN** (Amazon Resource Name) uniquely names it; **principalEmail** is the GCP form, **UPN** the Azure form.
- **assumed-role:** a temporary credential obtained by assuming an IAM role; the record shows the role, and the real actor is in `sessionContext.sessionIssuer` + the source IP.
- **access key (AKIA/ASIA):** a long-term (AKIA) or temporary (ASIA) AWS programmatic credential id — a hard IOC when found in logs or recovered from strings.
- **IAM:** Identity and Access Management — where users, roles, policies, and keys live; `CreateUser`/`CreateAccessKey`/`AttachUserPolicy` are the persistence calls.
- **MFA:** multi-factor authentication; `DeactivateMFADevice`/`DeleteVirtualMFADevice` removing it is a persistence/evasion move.
- **EBS snapshot / AMI:** a point-in-time copy of a disk volume / a bootable machine image; `ModifySnapshotAttribute`/`CreateImage`/`CopySnapshot` can share or copy whole disks to another account.
- **Security group:** a cloud firewall on an instance/VPC; `AuthorizeSecurityGroupIngress` to `0.0.0.0/0` opens a port to the whole internet.
- **RunInstances:** the API that launches compute instances; a burst of large/GPU types across many regions is the cryptomining signature.
- **StopLogging / DeleteTrail / PutEventSelectors:** the CloudTrail calls that turn off, delete, or narrow the audit log — the cloud analog of clearing the event log.
- **GuardDuty / Config:** AWS threat-detection and configuration-recording services; `DeleteDetector`/`StopConfigurationRecorder` blinds them.
- **Lambda / EventBridge:** serverless function + the event-rule engine that triggers it; `CreateFunction` + `PutRule`/`PutTargets` is a control-plane backdoor.
- **KMS:** Key Management Service; `PutKeyPolicy`/`CreateGrant`/`ScheduleKeyDeletion` tampers with who can use/destroy encryption keys.
- **eventTime / eventID:** the timestamp and unique id of a single record — anchor ordering to eventTime and de-duplicate on eventID, never trust file order.
- **errorCode / AccessDenied:** a field marking a FAILED call — a denied attempt is intent/recon, not a successful action.
- **jq:** a command-line JSON processor — used here to flatten and field-extract the exported logs (the on-box substitute for the absent `pandas`).
- **log2timeline.py / psort.py:** Plaso's super-timeline builder and renderer; its `aws_cloudtrail_log` / `azure_activity_log` / `gcp_log` parsers ingest the exports into one chronology.

## Tuning log (append-only — the eval loop writes here; humans never edit rows)
| date | case_id | bucket missed | delta applied |
|---|---|---|---|
