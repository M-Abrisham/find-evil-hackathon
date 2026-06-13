---
attack_type: cloud-identity-saas
category_id: cloud-identity-saas
name: Cloud Identity & SaaS
description: compromised cloud accounts, token/OAuth abuse and SaaS audit-log investigation
version: 1
os_coverage: [windows, linux, macos, cloud]
sub_types_covered: 15
sub_types:
  - oauth-token-theft-and-replay
  - access-token-or-refresh-token-abuse
  - impossible-travel-logon-anomaly
  - mfa-fatigue-push-bombing
  - mfa-bypass-or-method-registration
  - mailbox-rule-exfiltration
  - mail-forwarding-rule-abuse
  - app-consent-illicit-grant
  - federation-or-saml-trust-abuse
  - golden-saml-signing-cert-abuse
  - saas-data-access-anomaly
  - service-principal-or-app-credential-abuse
  - conditional-access-policy-tamper
  - admin-role-assignment-elevation
  - audit-logging-disablement
validated_on: []
maturity: draft
variables:
  image_path:
    default: /cases/active/evidence/logs.E01
    derive: "Step 0 — first disk-evidence image (E01/dd/raw/vmdk) enumerated under the evidence directory named in the case brief; for this playbook it usually holds the EXPORTED cloud audit-log files (CloudTrail/UAL/Workspace JSON), not a live tenant"
  mount_root:
    default: /cases/active/mount
    derive: "Step 0 — directory where the file system is mounted READ-ONLY (or where icat-extracted JSON/CSV log exports land when mounting fails)"
  case_out:
    default: /cases/active/out
    derive: "Step 0 — writable case output directory from the case brief; Step 0 creates #{case_out}/receipts/ and #{case_out}/extracted/"
  ntfs_offset_sectors:
    default: 0
    derive: "Step 0 — start sector of the relevant partition from `mmls #{image_path}` (largest data partition unless the brief says otherwise); 0 when the export is a loose file tree, not a disk image"
  time_window:
    default: 1970-01-01..2099-12-31
    derive: "case brief if it names one; else first confirmed malicious sign-in/grant timestamp plus or minus 48h once a step pins one — then re-scope wide sweeps to it"
---

## In one line
Someone got into a cloud account or SaaS app — by stealing a session token, tricking a user into approving a malicious app, or bombing them with login prompts — and the only witness is the audit log the cloud kept. This playbook reads those EXPORTED logs to prove who got in, how, and what they did.

## Use this when (triggers)
- A user reports **logins they did not make**, prompts they did not approve (MFA push spam), or a password/MFA reset they did not request.
- The same account appears to **sign in from two far-apart places** within minutes (impossible travel), or from an unexpected country/IP/ASN.
- A **new mail rule** silently forwards or deletes mail, or a **new OAuth app** suddenly has broad permission to read mail/files (consent grant).
- An **admin role**, a **service principal / app credential**, or a **federation/SAML trust** was changed, or **audit logging was turned off**.
- You have **exported cloud audit logs** on disk (AWS CloudTrail JSON, Microsoft 365 Unified Audit Log, Google Workspace admin/login JSON) and need to reconstruct an identity compromise from them. There is **NO live tenant access here** — `az`, `gcloud`, and any tenant API are absent; this playbook analyses the exports only.

## Quick path (the 90% case)
1. **Timeline-first.** Fold the exported logs into one sorted view: `log2timeline.py` + `psort.py` for formats it parses (`aws_cloudtrail`, `azure_activity`, and other JSON-line parsers it carries), and for the rest normalise each JSON export to one-line-per-event with `jq` and sort by timestamp. Skim inside `#{time_window}` BEFORE committing to a story — sign-in then MFA-change then rule/consent then data-access is the case.
2. **Find the entry.** Pull the suspect account's sign-in events; read the **source IP / ASN / country**, the **client/user-agent**, and whether the **token was a fresh interactive auth or a replayed session** (no matching interactive sign-in = token replay). Two sign-ins too far apart in time to travel = impossible travel.
3. **Find the foothold.** Look for **MFA method registered/changed**, an **OAuth app consent grant** (Consent to application / `AuthorizationCode`/`oauth` grants), a **service-principal credential add**, or a **federation/SAML trust change** — these are how the attacker keeps access after the password changes.
4. **Find the impact.** Look for a **mailbox forwarding/inbox rule**, **bulk file/mail access**, **admin-role assignment**, and **audit-logging disablement** — the exfil and the cover-up.
5. **Corroborate every claim with a second source.** A sign-in IP should also appear on the token/consent event or in the data-access log; one log line is a lead, not a fact. Build the fused timeline last and confirm entry then foothold then impact order holds.

If a suspicious sign-in, a persistence grant (MFA/OAuth/SP/federation), and an impact event (rule/data/role) all line up on one timeline with a corroborating second source → you are mostly done. Otherwise drop into the full Steps.

## How it unfolds (the story)
An actor obtains a credential or a live session — phished password, an AiTM proxy that steals the session cookie/token, or a stolen refresh token — and signs in, often from a hosting/VPN ASN that does not match the user. To survive a password reset they entrench: register their own MFA method, get a user to consent to a malicious OAuth app (which keeps a refresh token of its own), add a credential to a service principal, or tamper with the federation/SAML trust so they can mint their own tokens. Then they act on the goal: a hidden mailbox forwarding rule to exfiltrate mail, bulk download of files, an admin-role grant, and — to slow responders — turning audit logging off or weakening conditional-access. The entire sequence is reconstructable from the exported audit logs plus a corroborating second event.

## Theories to test (and how to rule each out)
| Theory (who / why) | If true, you'd find… | Rule it out if… |
|---|---|---|
| **External-targeted (AiTM / token theft)** | A sign-in from a hosting/VPN ASN with a session that has NO matching interactive auth (replayed token), then an MFA-method add or OAuth grant minutes later, then a mail rule / data access | Every session traces to a matching interactive auth from the user normal IP/device; no token-only sign-in; no post-sign-in persistence event |
| **External-commodity (password spray / MFA fatigue)** | A burst of failed sign-ins across many accounts, then one success preceded by repeated MFA push denials then an approve (push bombing); generic source IPs | Single account only, no push-denial burst, no spray pattern across the tenant; success matches the user own device |
| **Other-insider (stolen creds, legitimate-looking)** | Valid account signs in from an unusual country/ASN or odd hour; impossible-travel against its own baseline; same account adds a rule/consent | Source IP, ASN, country and hours match the account own historical baseline; no anomalous origin |
| **Insider (authorized admin acting maliciously)** | A real admin grants itself a role, adds an OAuth app, or disables audit logging from an EXPECTED device/IP — but with no change-ticket and outside normal duties | A sanctioned change-control record explains the role/app/logging change AND the device+source are the admin own → benign or reclassify |
| **Supply-chain / third-party app abuse** | A vendor/integration service principal or OAuth app, granted broad scopes earlier, suddenly reads mail/files at scale or from a new IP; the same app appears across many tenants | The app scopes and access match its documented, sanctioned integration behaviour and source; no scope/behaviour change |
| **Innocent / benign (NOT an attack)** | Sign-in from a known corporate VPN egress that looks foreign; a forwarding rule the user set themselves; an OAuth app on the approved list; an admin role granted via the normal JML process inside business hours | A clear sanctioned record explains the sign-in origin, rule, app, or role AND the account+source are expected → benign cause confirmed; reclassify |

*(at least 1 benign + at least 1 malicious, each ACTIVELY refuted. Attacker types mapped: insider · other-insider · external-commodity · external-targeted · supply-chain · innocent.)*

## Evidence → Tool → What it reveals (per OS)
| Evidence | SIFT tool | What it tells you *for this attack* | OS |
|---|---|---|---|
| AWS CloudTrail export (`*.json`/`*.json.gz` `Records[]`) | `log2timeline.py` (`aws_cloudtrail`) + `psort.py`; `jq` | `eventName` (ConsoleLogin, AssumeRole, CreateAccessKey, GetFederationToken), `sourceIPAddress`, `userIdentity`, `userAgent`, `errorCode` — who called what API, from where, success/fail | cloud |
| Microsoft 365 Unified Audit Log export (JSON/CSV; `AuditData` blob) | `jq`; `log2timeline.py` where the JSON-line parser applies | `Operation` (UserLoggedIn, Add-MailboxPermission, New-InboxRule, Set-Mailbox forwarding, Consent to application, Add service principal credentials, Set-AdminAuditLogConfig), `ClientIP`, `UserId` | cloud |
| Entra/Azure AD sign-in + audit export (JSON) | `jq`; `log2timeline.py` (`azure_activity` where present) | interactive vs non-interactive sign-in, `ipAddress`/`location`, `appDisplayName`, conditional-access result, MFA method, risk state; audit log: role assignment, app consent, CA policy change | cloud |
| Google Workspace admin/login audit export (JSON `items[]`) | `jq` | `login`/`admin` events: suspicious login, OAuth token grant, 2SV change, role grant, forwarding/delegation change, source IP | cloud |
| Local SaaS-client SQLite (Teams/Slack/OneDrive/Outlook cache on a seized endpoint) | `SQLECmd` (map library); `sqlite3` (scriptable, read-only queries) | client-side artifacts of the same account: cached tokens, recent files, sync history corroborating server-side access | windows/macos |
| Any export, format-agnostic IOC sweep | `srch_strings`; `bstrings` | account names, IPs, app IDs, consent URLs, tenant/cert thumbprints spilled in logs or in pagefile/unallocated when the structured parse fails | all |
| All exports fused | `log2timeline.py` + `psort.py` (+ `pinfo.py`) | one chronology placing sign-in → MFA/OAuth/SP/federation persistence → rule/data/role impact in order | all |
| Exported host disk (if the seized box holds the export) | `fls` / `icat` / `mmls` / `fsstat` | locate, prove read-only access to, and extract the log-export files; recover deleted exports | all |

*This box has NO dedicated Entra/Workspace audit-log parser and NO live-tenant CLI (`az`/`gcloud` absent) — `⚠️verify` any reliance on a structured cloud parser and fall back to `jq` over the exported JSON, which is the primary method here.*

## Step 0 — evidence inventory & access bootstrap
- n: 0
  tool: |
    mkdir -p "#{case_out}/receipts" "#{case_out}/extracted" && ls -laR "#{mount_root}" > "#{case_out}/receipts/00.txt" 2>&1 ; img_stat "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; mmls "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; fsstat -o #{ntfs_offset_sectors} "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; find "#{mount_root}" -type f \( -iname "*.json" -o -iname "*.json.gz" -o -iname "*.csv" -o -iname "*cloudtrail*" -o -iname "*audit*" \) >> "#{case_out}/receipts/00.txt" 2>&1
  expect: every evidence file classified; #{image_path}, #{mount_root}, #{ntfs_offset_sectors}, #{case_out} bound; read-only access proven; the exported cloud audit-log files (CloudTrail/UAL/Workspace JSON or CSV) are enumerated, or their absence is recorded as a finding
  check: |
    test -r "#{mount_root}" -o -n "$(ls "#{case_out}/extracted" 2>/dev/null)"
  falsify: evidence dir empty/unreadable, or no supported image format found, or no JSON/CSV log export present anywhere
  on_result: {expect_met: goto 1, falsify_met: STOP — report acquisition/access failure; pivot acquisition-custody, neither: try the icat-extract fallback (fls to find the export-file inodes, icat each into #{case_out}/extracted); if that also fails, treat as falsify_met}
  emits: [key_artifacts]
  serves: [oauth-token-theft-and-replay, access-token-or-refresh-token-abuse, impossible-travel-logon-anomaly, mfa-fatigue-push-bombing, mfa-bypass-or-method-registration, mailbox-rule-exfiltration, mail-forwarding-rule-abuse, app-consent-illicit-grant, federation-or-saml-trust-abuse, golden-saml-signing-cert-abuse, saas-data-access-anomaly, service-principal-or-app-credential-abuse, conditional-access-policy-tamper, admin-role-assignment-elevation, audit-logging-disablement]
  provenance: {receipt_id: 00, artifact: evidence directory listing + log-export enumeration, offset_or_row: full listing, literal_cited: image filename + the export-file names}

## Steps (executable — decision-driven)
- n: 1
  precondition: "test -r #{mount_root}"
  tool: |
    log2timeline.py --status_view none --parsers "aws_cloudtrail,azure_activity,json,jsonl" "#{case_out}/cloud.plaso" "#{mount_root}" > "#{case_out}/receipts/01.txt" 2>&1 ; psort.py -o l2tcsv "#{case_out}/cloud.plaso" > "#{case_out}/cloud_super.csv" 2>> "#{case_out}/receipts/01.txt" ; pinfo.py "#{case_out}/cloud.plaso" >> "#{case_out}/receipts/01.txt" 2>&1 ; find "#{mount_root}" -type f \( -iname "*.json" -o -iname "*.json.gz" \) -exec sh -c 'zcat -f "$1" | jq -c "(.Records[]? // .records[]? // .value[]? // .items[]? // .)" 2>/dev/null' _ {} \; > "#{case_out}/events.ndjson" 2>> "#{case_out}/receipts/01.txt"
  expect: a fused super-timeline (#{case_out}/cloud_super.csv) for parsed formats AND a normalized one-event-per-line #{case_out}/events.ndjson covering every JSON export — the timeline-first artifact every later step filters with jq/grep
  check: |
    test -s "#{case_out}/events.ndjson" -o -s "#{case_out}/cloud_super.csv"
  falsify: no JSON/CSV export parses (all empty/corrupt) AND log2timeline produced no cloud events — there is no machine-readable audit log to analyse
  on_result: {expect_met: goto 2, falsify_met: fall back to a raw string sweep — srch_strings/bstrings over the export files and grep for sign-in/grant/rule keywords; if no log export exists at all record absence as a finding and pivot acquisition-custody, neither: re-run jq per-file on the specific export whose schema differs (top-level array vs Records[] vs items[]) and append to events.ndjson}
  emits: [timeline_events]
  serves: [impossible-travel-logon-anomaly, oauth-token-theft-and-replay, saas-data-access-anomaly]
  provenance: {receipt_id: 01, artifact: exported cloud audit logs, offset_or_row: events.ndjson line count + cloud_super.csv header, literal_cited: pinfo parser list + first normalized event line}

- n: 2
  precondition: "exists #{case_out}/events.ndjson"
  tool: |
    jq -rc 'select((.eventName? // .Operation? // .name? // (.eventType?|tostring)) | test("(?i)login|signin|loggedin|consolelogin|assumerole|getfederationtoken")) | [(.eventTime? // .CreationTime? // .time? // .id.time?), (.sourceIPAddress? // .ClientIP? // .ipAddress? // .ipAddress), (.userIdentity?.arn? // .UserId? // .userPrincipalName? // .actor?.email?), (.userAgent? // .clientAppUsed? // .appDisplayName?), (.errorCode? // .ResultStatus? // .status?.errorCode?)] | @tsv' "#{case_out}/events.ndjson" > "#{case_out}/receipts/02.txt" 2>&1 ; sort "#{case_out}/receipts/02.txt" | awk -F'\t' '{print $3"\t"$2"\t"$1}' | sort -u >> "#{case_out}/receipts/02.txt"
  expect: sign-in/console-login rows naming the account, the source IP/ASN/country and the client/user-agent; two successful sign-ins for one account too far apart in time to travel (impossible travel), OR sign-ins from a hosting/VPN ASN unlike the user baseline, inside #{time_window}
  check: |
    test -s "#{case_out}/receipts/02.txt" && grep -qiE "login|signin|loggedin|consolelogin|assumerole" "#{case_out}/receipts/02.txt"
  falsify: every sign-in for the account comes from its known baseline IP range/country/device, no two are geographically impossible, and no hosting/VPN ASN appears — origin is normal
  on_result: {expect_met: record account + source IP/ASN/country + client; goto 3, falsify_met: record no anomalous logon origin; check token-replay (step 3) before clearing the account, neither: widen #{time_window}; re-run with the export-specific IP/time field names; correlate against the user historical baseline if provided}
  emits: [actor_accounts, key_iocs, timeline_events]
  serves: [impossible-travel-logon-anomaly, saas-data-access-anomaly]
  provenance: {receipt_id: 02, artifact: sign-in/login audit events, offset_or_row: receipts/02.txt tsv rows, literal_cited: account + sourceIP + userAgent string}

- n: 3
  precondition: "exists #{case_out}/events.ndjson"
  tool: |
    jq -rc 'select((.eventName? // .Operation? // (.eventType?|tostring)) | test("(?i)token|oauth|refresh|getfederationtoken|assumerole|noninteractive")) or ((.clientAppUsed?? // "") | test("(?i)browser|mobile")|not) | [(.eventTime? // .CreationTime? // .time?), (.eventName? // .Operation? // .eventType?), (.sourceIPAddress? // .ClientIP? // .ipAddress?), (.userIdentity?.type? // .UserId? // .userPrincipalName?), ((.additionalEventData?.MFAUsed?) // (.authenticationRequirement?) // (.status?.authenticationDetails?))] | @tsv' "#{case_out}/events.ndjson" > "#{case_out}/receipts/03.txt" 2>&1
  expect: at least one session/token event with NO matching interactive auth (a replayed session token), or a non-interactive sign-in where MFA was satisfied by token/claim not a fresh challenge, or an STS AssumeRole/GetFederationToken minting derived credentials — token theft/replay, inside #{time_window}
  check: |
    grep -qiE "token|oauth|refresh|federationtoken|assumerole|noninteractive" "#{case_out}/receipts/03.txt"
  falsify: every session for the account maps to a fresh interactive auth with MFA actually challenged from the user device — no token replay or derived-credential minting
  on_result: {expect_met: flag token/refresh-token replay; goto 4, falsify_met: record no token replay; continue to persistence at goto 4, neither: correlate sign-in event ids to their parent interactive auth; if STS chains appear pivot cloud-iaas-control-plane for the derived-credential blast radius}
  emits: [key_iocs, actor_accounts, timeline_events]
  serves: [oauth-token-theft-and-replay, access-token-or-refresh-token-abuse]
  provenance: {receipt_id: 03, artifact: token/non-interactive sign-in + STS events, offset_or_row: receipts/03.txt rows, literal_cited: token/AssumeRole event name + actor string}

- n: 4
  precondition: "exists #{case_out}/events.ndjson"
  tool: |
    jq -rc 'select((.Operation? // .eventName? // .name? // (.eventType?|tostring)) | test("(?i)mfa|strongauth|securityinfo|registered.*device|authenticationmethod|update.*user.*method")) | [(.CreationTime? // .eventTime? // .time?), (.Operation? // .eventName? // .eventType?), (.UserId? // .userPrincipalName? // .actor?.email?), (.ClientIP? // .ipAddress? // .sourceIPAddress?), (.ModifiedProperties? // .targetResources? // .parameters?)] | @tsv' "#{case_out}/events.ndjson" > "#{case_out}/receipts/04.txt" 2>&1 ; grep -ciE "mfa|strongauth|authenticationmethod|securityinfo" "#{case_out}/receipts/04.txt" >> "#{case_out}/receipts/04.txt" 2>&1
  expect: an MFA method or strong-auth/security-info change for the actor account near the suspicious sign-in (attacker registering their own authenticator/phone), and/or a push-bombing pattern (many MFA challenge denials then one approve) — MFA bypass / method registration / fatigue, inside #{time_window}
  check: |
    grep -qiE "mfa|strongauth|securityinfo|authenticationmethod" "#{case_out}/receipts/04.txt"
  falsify: no MFA-method or security-info change for the account in #{time_window}, and no repeated-deny-then-approve burst — MFA was not tampered with here
  on_result: {expect_met: record the new MFA method/device as an IOC; goto 5, falsify_met: record no MFA tampering; continue to consent/credential at goto 5, neither: re-grep for the export-specific method-change operation name; check the sign-in log for repeated MFA-denied results preceding a success (push bombing)}
  emits: [key_iocs, timeline_events]
  serves: [mfa-bypass-or-method-registration, mfa-fatigue-push-bombing]
  provenance: {receipt_id: 04, artifact: MFA/security-info audit events, offset_or_row: receipts/04.txt rows, literal_cited: method-change operation + account string}

- n: 5
  precondition: "exists #{case_out}/events.ndjson"
  tool: |
    jq -rc 'select((.Operation? // .eventName? // .name? // (.eventType?|tostring)) | test("(?i)consent.*application|add.*delegat|add.*oauth|add.*service.?principal|add.*credential|add.*key|authorize.*token|admin.?consent")) | [(.CreationTime? // .eventTime? // .time?), (.Operation? // .eventName? // .eventType?), (.UserId? // .userPrincipalName? // .userIdentity?.arn?), (.ClientIP? // .ipAddress? // .sourceIPAddress?), (.ModifiedProperties? // .targetResources? // .ObjectId? // .parameters?)] | @tsv' "#{case_out}/events.ndjson" > "#{case_out}/receipts/05.txt" 2>&1
  expect: a Consent-to-application / admin-consent grant for a new or unexpected OAuth app with broad mail/file scopes, OR a service-principal credential/key add (the app gets its own refresh token/secret), OR a new access key on the identity — the attacker persistence that survives a password reset, inside #{time_window}
  check: |
    grep -qiE "consent|oauth|serviceprincipal|service principal|add.*credential|createaccesskey|add.*key" "#{case_out}/receipts/05.txt"
  falsify: no app consent, no service-principal/app credential add, and no new access key in #{time_window} — no OAuth/app persistence here
  on_result: {expect_met: record the app id / service-principal / key id as an IOC; goto 6, falsify_met: record no app/credential persistence; continue to federation at goto 6, neither: re-grep with the export-specific operation name; for AWS check CreateAccessKey/CreateUser; pivot cloud-iaas-control-plane if a new IAM principal/key was minted}
  emits: [key_iocs, timeline_events]
  serves: [app-consent-illicit-grant, service-principal-or-app-credential-abuse, access-token-or-refresh-token-abuse]
  provenance: {receipt_id: 05, artifact: consent/service-principal/credential audit events, offset_or_row: receipts/05.txt rows, literal_cited: app/service-principal id + scope string}

- n: 6
  precondition: "exists #{case_out}/events.ndjson"
  tool: |
    jq -rc 'select((.Operation? // .eventName? // .name? // (.eventType?|tostring)) | test("(?i)federation|domain.*federat|saml|trust|signing.?cert|token.?signing|set.?domainauthentication|updateidentityprovider")) | [(.CreationTime? // .eventTime? // .time?), (.Operation? // .eventName? // .eventType?), (.UserId? // .userPrincipalName? // .userIdentity?.arn?), (.ClientIP? // .ipAddress? // .sourceIPAddress?), (.ModifiedProperties? // .targetResources? // .parameters?)] | @tsv' "#{case_out}/events.ndjson" > "#{case_out}/receipts/06.txt" 2>&1
  expect: a federation/SAML trust change — a new federated domain, an updated identity provider, or a token-signing/issuer change — letting the attacker mint their own valid tokens (golden-SAML-style), inside #{time_window}
  check: |
    grep -qiE "federation|federat|saml|trust|signing|identityprovider|domainauthentication" "#{case_out}/receipts/06.txt"
  falsify: no federation/SAML/trust or signing-certificate change in #{time_window} — no trust-abuse persistence here
  on_result: {expect_met: record the federated domain / signing-cert change as a high-signal IOC; goto 7, falsify_met: record no federation/trust change; continue to impact at goto 7, neither: re-grep with the export-specific operation name; if a signing cert or IdP changed treat as confirmed-on-receipt and pivot active-directory-domain for the on-prem ADFS side}
  emits: [key_iocs, timeline_events]
  serves: [federation-or-saml-trust-abuse, golden-saml-signing-cert-abuse]
  provenance: {receipt_id: 06, artifact: federation/SAML audit events, offset_or_row: receipts/06.txt rows, literal_cited: federated domain / signing-cert change string}

- n: 7
  precondition: "exists #{case_out}/events.ndjson"
  tool: |
    jq -rc 'select((.Operation? // .eventName? // .name? // (.eventType?|tostring)) | test("(?i)new.?inboxrule|set.?inboxrule|new.?transportrule|set.?mailbox|forward|deleg|mailitemsaccessed|filedownload|filepreview|searchqueryperformed")) | [(.CreationTime? // .eventTime? // .time?), (.Operation? // .eventName?), (.UserId? // .userPrincipalName?), (.ClientIP? // .ipAddress? // .sourceIPAddress?), (.Parameters? // .ModifiedProperties? // .ObjectId?)] | @tsv' "#{case_out}/events.ndjson" > "#{case_out}/receipts/07.txt" 2>&1 ; grep -ciE "inboxrule|forward|mailitemsaccessed|filedownload" "#{case_out}/receipts/07.txt" >> "#{case_out}/receipts/07.txt" 2>&1
  expect: a New-InboxRule / Set-Mailbox forwarding / delegate add that quietly forwards or hides mail, and/or bulk MailItemsAccessed / FileDownloaded / search-query activity reading data at scale — the exfiltration, inside #{time_window}
  check: |
    grep -qiE "inboxrule|forward|deleg|mailitemsaccessed|filedownload|filepreview|searchquery" "#{case_out}/receipts/07.txt"
  falsify: no new mail rule/forwarding/delegate and no bulk data-access events for the account in #{time_window} — no log-evidenced exfiltration on this account
  on_result: {expect_met: record the rule/forward target + accessed-data scope as exfil facts; goto 8, falsify_met: record no log-evidenced exfil; check the local SaaS-client SQLite (step 9) for client-side sync; goto 8, neither: re-grep with the export-specific operation name; correlate the access burst IP to the step-2 sign-in IP}
  emits: [exfil_or_encryption_facts, key_iocs, timeline_events]
  serves: [mailbox-rule-exfiltration, mail-forwarding-rule-abuse, saas-data-access-anomaly]
  provenance: {receipt_id: 07, artifact: mailbox-rule / data-access audit events, offset_or_row: receipts/07.txt rows, literal_cited: inbox-rule forward target / MailItemsAccessed count string}

- n: 8
  precondition: "exists #{case_out}/events.ndjson"
  tool: |
    jq -rc 'select((.Operation? // .eventName? // .name? // (.eventType?|tostring)) | test("(?i)add.*role|roleassignment|memberadd|set.?adminauditlog|set.?conditionalaccess|update.*policy|stoplogging|disable.*audit|stopdeliverysync")) | [(.CreationTime? // .eventTime? // .time?), (.Operation? // .eventName?), (.UserId? // .userPrincipalName? // .userIdentity?.arn?), (.ClientIP? // .ipAddress? // .sourceIPAddress?), (.ModifiedProperties? // .targetResources? // .parameters?)] | @tsv' "#{case_out}/events.ndjson" > "#{case_out}/receipts/08.txt" 2>&1
  expect: an admin-role assignment to the actor (privilege elevation), a conditional-access policy weakened/removed, or audit logging disabled (Set-AdminAuditLogConfig off / StopLogging) near the activity — escalation and cover-up, inside #{time_window}
  check: |
    grep -qiE "role|memberadd|adminauditlog|conditionalaccess|disable|stoplogging|update.*policy" "#{case_out}/receipts/08.txt"
  falsify: no role assignment, no conditional-access change, and no audit-logging disablement in #{time_window} — no escalation/cover-up logged
  on_result: {expect_met: record the role grant / CA change / logging-off as high-signal findings; goto 9, falsify_met: record no escalation/cover-up; goto 9, neither: re-grep with export-specific names; a gap in event continuity with no explicit disable event is itself a finding — note it and goto 9}
  emits: [key_artifacts, actor_accounts, timeline_events]
  serves: [admin-role-assignment-elevation, conditional-access-policy-tamper, audit-logging-disablement]
  provenance: {receipt_id: 08, artifact: role/CA/audit-config events, offset_or_row: receipts/08.txt rows, literal_cited: role-add / CA-policy / logging-disable string}

- n: 9
  precondition: "exists #{case_out}/events.ndjson; test -r #{mount_root}"
  tool: |
    dotnet /opt/zimmermantools/SQLECmd/SQLECmd.dll -d "#{mount_root}" --csv "#{case_out}" --csvf saas_sqlite.csv > "#{case_out}/receipts/09.txt" 2>&1 ; for db in $(find "#{mount_root}" -type f \( -iname "*.sqlite" -o -iname "*.db" \) 2>/dev/null); do echo "== $db ==" >> "#{case_out}/receipts/09.txt" ; sqlite3 -readonly "$db" ".tables" >> "#{case_out}/receipts/09.txt" 2>&1 ; done
  expect: a local SaaS-client SQLite (Teams/Slack/OneDrive/Outlook cache) for the same account shows client-side traces — cached files, sync history, or a token store — that corroborate the server-side access from steps 2/7 (two-source rule)
  check: |
    test -s "#{case_out}/saas_sqlite.csv" -o -s "#{case_out}/receipts/09.txt"
  falsify: no local SaaS-client database present, OR the client artifacts contradict the audit log (different account/device) — server-side claim stands single-source, hold at inferred
  on_result: {expect_met: promote the corroborated finding to confirmed; goto 10, falsify_met: keep the finding at inferred/single-source; note the missing corroboration; goto 10, neither: run sqlite3 -readonly with a targeted SELECT on the specific cache table and re-check; if no endpoint was seized record client-side corroboration as unavailable}
  emits: [key_artifacts, actor_accounts]
  serves: [saas-data-access-anomaly, access-token-or-refresh-token-abuse]
  provenance: {receipt_id: 09, artifact: local SaaS-client SQLite cache, offset_or_row: saas_sqlite.csv row / sqlite3 .tables output, literal_cited: cached account/file/token row}

- n: 10
  precondition: "exists #{case_out}/events.ndjson"
  tool: |
    sort -t$'\t' -k1,1 "#{case_out}/receipts/02.txt" "#{case_out}/receipts/03.txt" "#{case_out}/receipts/04.txt" "#{case_out}/receipts/05.txt" "#{case_out}/receipts/06.txt" "#{case_out}/receipts/07.txt" "#{case_out}/receipts/08.txt" > "#{case_out}/identity_timeline.tsv" 2>> "#{case_out}/receipts/10.txt" ; wc -l "#{case_out}/identity_timeline.tsv" >> "#{case_out}/receipts/10.txt" 2>&1 ; head -n 200 "#{case_out}/identity_timeline.tsv" >> "#{case_out}/receipts/10.txt" 2>&1
  expect: a fused identity timeline placing entry (sign-in/impossible-travel) → persistence (token/MFA/OAuth/SP/federation) → impact (rule/data/role/logging-off) in a coherent order with no unexplained gap, inside #{time_window}
  check: |
    test -s "#{case_out}/identity_timeline.tsv" && grep -qiE "login|signin|consent|inboxrule|role|federation|token" "#{case_out}/identity_timeline.tsv"
  falsify: ordering is impossible (e.g. a mail rule or data exfil precedes ANY sign-in) OR an unexplained gap that an audit-logging-disable event accounts for (cover-up) — re-open the theories
  on_result: {expect_met: COMMIT the conclusion with a confidence label; close per the gate, falsify_met: re-open the Theories table; a gap may be log-disablement (step 8) or a missing export — anchor to event time order and name the missing source, neither: re-sort with the export native timestamp field; confirm via pinfo.py that the cloud parsers ran; re-filter to #{time_window} and re-check}
  emits: [timeline_events]
  serves: [impossible-travel-logon-anomaly, app-consent-illicit-grant, mailbox-rule-exfiltration, admin-role-assignment-elevation]
  provenance: {receipt_id: 10, artifact: fused identity timeline, offset_or_row: identity_timeline.tsv ordered rows, literal_cited: ordered sign-in→persistence→impact chain}

## Linux branch (L1..Ln) — REQUIRED, numbered, same step shape
- n: L1
  precondition: "os == linux"
  tool: |
    fsstat -o #{ntfs_offset_sectors} "#{image_path}" > "#{case_out}/receipts/L01.txt" 2>&1 ; find "#{mount_root}" -type f \( -iname "*.json" -o -iname "*.json.gz" -o -iname "*cloudtrail*" -o -iname "*audit*" \) 2>/dev/null >> "#{case_out}/receipts/L01.txt"
  expect: this is a cloud-log investigation, not a host-OS one — the evidence is EXPORTED audit-log files (CloudTrail/UAL/Workspace JSON), so the analysis is OS-agnostic; this branch records cloud-only because the artifact is a tenant audit-log export with NO host EVTX/syslog equivalent, and confirms the export files are present under #{mount_root} regardless of the carrier file system (Linux/ext or NTFS)
  check: |
    test -n "$(find "#{mount_root}" -type f \( -iname "*.json" -o -iname "*.json.gz" -o -iname "*cloudtrail*" \) 2>/dev/null | head -1)" -o -s "#{case_out}/receipts/L01.txt"
  falsify: no JSON/CSV cloud-log export anywhere under #{mount_root} — there is nothing for this cloud playbook to analyse on this image
  on_result: {expect_met: run the main Steps 1-10 against the exports (they are carrier-OS-agnostic); goto L2, falsify_met: no cloud export here — record cloud-only-because-tenant-audit-log absence and pivot acquisition-custody, neither: confirm carrier OS family from Step 0 fsstat receipt; if exports exist run the main branch regardless of carrier file system}
  emits: [key_artifacts]
  serves: [impossible-travel-logon-anomaly, saas-data-access-anomaly]
  provenance: {receipt_id: L01, artifact: file system + export-file listing, offset_or_row: fsstat header + find listing, literal_cited: cloud-only-because-tenant-audit-log + export filename}

- n: L2
  precondition: "os == linux"
  tool: |
    find "#{mount_root}" -type f \( -iname "*.json" -o -iname "*.json.gz" \) -exec sh -c 'zcat -f "$1" | jq -c "(.Records[]? // .records[]? // .items[]? // .)" 2>/dev/null' _ {} \; > "#{case_out}/events.ndjson" 2>> "#{case_out}/receipts/L02.txt" ; srch_strings "#{case_out}/events.ndjson" 2>/dev/null | grep -iE "consolelogin|signin|loggedin|consent|inboxrule|assumerole|federation" | head -n 50 >> "#{case_out}/receipts/L02.txt" 2>&1
  expect: the same exported cloud audit events normalize to #{case_out}/events.ndjson on this image too — sign-in, AssumeRole/consent, inbox-rule and federation keywords are recoverable, so the main Steps 2-10 jq filters apply unchanged; a Linux carrier file system does not change the cloud analysis
  check: |
    test -s "#{case_out}/events.ndjson" -o -s "#{case_out}/receipts/L02.txt"
  falsify: the export files are present but contain no recognizable cloud audit schema (not CloudTrail/UAL/Workspace) — wrong export type; record and re-scope
  on_result: {expect_met: proceed into the main Steps 2-10 with events.ndjson bound; commit with confidence label, falsify_met: record wrong-export-type; carve any deleted JSON with srch_strings/bstrings over unallocated and pivot file-recovery-carving, neither: widen the find globs to the export-specific extension; if still empty treat as falsify_met}
  emits: [timeline_events, key_iocs]
  serves: [oauth-token-theft-and-replay, impossible-travel-logon-anomaly]
  provenance: {receipt_id: L02, artifact: normalized cloud events on a Linux-carrier image, offset_or_row: events.ndjson line count + grep hits, literal_cited: ConsoleLogin/Consent/AssumeRole keyword line}

## Corroboration (two-source rule)
`required_sources: 2` · `pairs:`
- `[ suspicious sign-in IP/ASN (step 2) ↔ the same IP on the token/consent/data-access event (step 3/5/7) ]`
- `[ token-replay / non-interactive auth (step 3) ↔ absence of a matching interactive auth in the sign-in log (step 2) ]`
- `[ MFA-method add (step 4) ↔ the sign-in immediately preceding it from the attacker IP (step 2) ]`
- `[ OAuth consent / service-principal credential (step 5) ↔ later token-only access by that app id (step 3/7) ]`
- `[ federation/SAML trust change (step 6) ↔ subsequent token-minted sign-ins bypassing MFA (step 2/3) ]`
- `[ mailbox-rule / bulk data access (step 7) ↔ the local SaaS-client SQLite sync/cache (step 9) ]`
- `[ audit-config disable / role grant (step 8) ↔ a continuity gap or the fused-timeline order (step 10) ]`

One hit is a *lead*; promote to *fact* only when its paired source agrees.

## Don't get fooled (red flags & anti-forensics)
- **Audit logging turned off is the loud finding.** Set-AdminAuditLogConfig off, StopLogging, or a sudden export gap with no events near the activity means a deliberate operator — read the silence as a finding, not as nothing-happened, and bracket what was hidden by the surrounding events.
- **Token replay leaves no interactive auth.** An AiTM session reuses a stolen cookie/refresh token, so there is a session/non-interactive sign-in with NO matching fresh challenge. Never treat a successful sign-in as benign just because MFA shows satisfied — confirm a real interactive challenge from the user device.
- **Corporate VPN egress can look foreign.** A sign-in from a known VPN/proxy ASN is not impossible travel — baseline the user known egress IPs before calling an origin malicious.
- **A forwarding rule may be the user own.** New-InboxRule/forwarding is benign if the user set it; confirm the actor, the source IP, and the absence of a sanctioned change before calling it exfil.
- **OAuth consent hides in plain sight.** A Consent-to-application with broad mail/file scopes from an unknown app is high-signal even with no failed sign-ins — the app keeps its own refresh token, so revoking the password does nothing. Always check consent grants even when the sign-in looks clean.
- **Federation/SAML and signing-cert changes are catastrophic and quiet.** A changed token-signing certificate or a new federated domain lets the attacker mint valid tokens forever (golden-SAML pattern); one audit line is enough to escalate to high-signal and pivot to the on-prem identity provider.
- **Export gaps and clock skew poison the timeline.** Exports can be partial (a time range omitted) or carry mixed time zones. If the order is internally impossible, anchor to the native event timestamp and to event sequence/id, name the missing export range, and treat the gap itself as a finding. **Missing evidence is itself a finding.**

## Failure modes
```
- mode: evidence-access failure — the disk/export won't mount or the log directory is unreadable
  guard: Step 0 fallback chain — ewfmount/loop RO, else TSK fls/icat the export-file inodes into #{case_out}/extracted; if all fail, record acquisition failure and pivot acquisition-custody
- mode: primary-artifact-absent — no audit-log export was collected, or the relevant log type/time range is missing (logging was off, or only a partial export pulled)
  guard: record the absence/gap as a finding (it may itself be audit-logging-disablement); name the secondary sources (local SaaS-client SQLite, string sweep over unallocated, the surrounding events that bracket the gap) and pivot acquisition-custody to re-pull the full range
- mode: tool-output drift — a different tenant/export schema renames fields (Records[] vs items[] vs value[]; eventName vs Operation), or a jq filter returns empty so a check exits 2
  guard: on check exit 2, adjudicate from the prose expect/falsify against the receipt, cap confidence at inferred; re-run the per-file jq with the export-specific field names, and fall back to srch_strings/bstrings keyword sweep over the raw export, never silently pass
- mode: NO live-tenant access — az/gcloud/tenant API absent, so nothing can be pulled fresh from the cloud
  guard: this is INGEST-ONLY by design — analyse the EXPORTED logs already on disk; if a needed log was never exported, record it as an evidence-collection gap and request the export, do not fabricate tenant calls
- mode: structured cloud parser missing/partial — log2timeline lacks an Entra/Workspace parser, or the aws_cloudtrail/azure_activity parser version drifts
  guard: do not depend on it — the jq normalization to events.ndjson is the primary path; use pinfo.py to confirm which parsers ran and tag any parser reliance `⚠️verify`
```
Minimum set every playbook covers: evidence-access failure (Step 0 fallback chain) · primary-artifact-absent (absence recorded, secondary source named) · tool-output drift (`check` exits 2 → prose adjudication, never silent pass).

## Confidence labeling (observation → inference → conclusion)
- **confirmed:** direct receipt verbatim (e.g. the ConsoleLogin/Consent row) + at least 2 independent sources agree (sign-in log + token/consent/data event, or audit log + local SaaS-client SQLite) + no unrefuted counter-theory.
- **inferred:** grounded but single-source/interpretive — e.g. a sign-in from an unusual ASN with no corroborating persistence event yet, an export gap read as logging-disablement, or reliance on a cloud parser whose version is unverified → hedge and tag `⚠️verify`. Every `check`-exit-2 adjudication lands here at best.
- **insufficient_evidence:** precondition unmet (no export collected; only a partial time range; no endpoint seized for client-side corroboration) or sources conflict → abstain; state what is missing, do not guess.

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
- **Cloud (primary):** this playbook is cloud-native — the evidence is EXPORTED tenant audit logs (AWS CloudTrail, Microsoft 365 Unified Audit Log, Entra/Azure AD sign-in & audit, Google Workspace admin/login), not a host OS. There is **NO live-tenant access on this box** (`az`/`gcloud` and any tenant API are absent), so the whole investigation is INGEST-ONLY over the exports already on disk, normalized with `jq` and (where a parser exists) `log2timeline.py`.
- **Windows / macOS:** relevant only as the **carrier** of the export files and as the host of a **local SaaS-client SQLite** (Teams/Slack/OneDrive/Outlook cache) — parse those with `SQLECmd`/`sqlite3` for client-side corroboration (step 9). The carrier OS does not change the cloud analysis.
- **Linux/ESXi:** see the numbered Linux branch (L1–L2). A Linux carrier file system is just a different container for the same JSON exports; the `jq` normalization and main Steps apply unchanged.
- **No host EVTX/syslog equivalent:** unlike on-host playbooks, the authoritative record here is the cloud provider audit log. If it was never exported (or only partially), that gap is the finding — there is no on-host log that substitutes for the tenant audit trail.

## Real-case notes (non-obvious things to look for)
- **AiTM phishing defeats MFA by stealing the session, not the password.** Adversary-in-the-middle proxies (e.g. the Storm-0558/large-scale AiTM pattern) capture the post-MFA session cookie; the audit log then shows a successful sign-in with MFA satisfied but NO fresh interactive challenge from the user device, often from a hosting ASN. Always test whether a session traces to a real interactive auth. `[CISA/Microsoft AiTM advisories · high]`
- **The first thing many BEC actors do is add a hidden inbox rule.** A New-InboxRule that forwards to an external address or moves mail to RSS/Archive and marks it read is the classic business-email-compromise tell; it survives a password reset and is invisible to the user. Check New-InboxRule/Set-Mailbox forwarding immediately on any suspected mailbox takeover. `[MITRE T1114.003 / FBI BEC guidance · high]`
- **Illicit OAuth consent is password-reset-proof persistence.** A user (or admin) consents to a malicious app with `Mail.Read`/`Files.Read.All`; the app holds its own refresh token, so rotating the password changes nothing. Hunt Consent-to-application and admin-consent grants even when sign-ins look clean. `[MITRE T1528 / T1098.003 · high]`
- **Golden SAML / federation-trust abuse mints tokens that bypass MFA entirely.** Stealing or changing the token-signing certificate (the Solorigate/UNC2452 tradecraft) lets the attacker forge SAML tokens for any user; the audit tell is a federation/IdP/signing-cert change with later sign-ins that never hit MFA. One such audit line warrants escalation to the on-prem ADFS side. `[MITRE T1606.002 / CISA AA21 · high]`
- **CloudTrail GetFederationToken / AssumeRole chains hide the real actor.** In AWS, a compromised key calling `GetFederationToken` or chained `AssumeRole` produces derived credentials under a new principal name, masking the origin; follow the `sharedEventID`/`userIdentity` chain back to the first principal. `[MITRE T1550 / AWS IR guidance · med]`
- **MFA fatigue is visible as a deny-burst then a single approve.** Push-bombing shows repeated MFA-denied results for one account in minutes, ending in one approve immediately followed by an MFA-method add (the attacker enrolling their own) — the two together are near-conclusive. `[MITRE T1621 · med]`
- **Disabling audit logging is itself the evidence.** Set-AdminAuditLogConfig off (or a unified-audit-log disable) right before the impact window is a deliberate cover-up; the absence of events after it is a finding, and the events just before it bracket the activity. `[MITRE T1562.008 · med]`

## ATT&CK mapping
- T1078.004 · Defense Evasion/Persistence · Valid Accounts: Cloud Accounts · suspicious sign-in with valid creds — step 2
- T1110.003 · Credential Access · Password Spraying · failed-sign-in burst then success — step 2
- T1621 · Credential Access · Multi-Factor Authentication Request Generation (MFA fatigue) · deny-burst then approve — step 4
- T1556.006 · Credential Access/Defense Evasion · Modify Authentication Process: MFA · MFA-method registration/change — step 4
- T1550.001 · Defense Evasion/Lateral Movement · Use Alternate Authentication Material: Application Access Token — step 3
- T1550.004 · Defense Evasion/Lateral Movement · Web Session Cookie (AiTM token replay) — step 3
- T1528 · Credential Access · Steal Application Access Token · OAuth refresh-token theft — steps 3/5
- T1098.001 · Persistence · Account Manipulation: Additional Cloud Credentials · service-principal credential/key add — step 5
- T1098.003 · Persistence · Account Manipulation: Additional Cloud Roles · admin-role assignment — step 8
- T1098.002 · Persistence · Account Manipulation: Additional Email Delegate Permissions · mailbox delegate/forwarding — step 7
- T1566.002 · Initial Access · Phishing: Spearphishing Link (AiTM consent/credential capture) — entry context
- T1606.002 · Credential Access · Forge Web Credentials: SAML Tokens (golden SAML) · signing-cert/federation change — step 6
- T1114.003 · Collection · Email Collection: Email Forwarding Rule · New-InboxRule forwarding — step 7
- T1530 · Collection · Data from Cloud Storage · bulk file access/download — step 7
- T1562.008 · Defense Evasion · Impair Defenses: Disable Cloud Logs · audit-logging disablement — step 8

## Pivots (lead-to-lead graph)
- `on_sts_or_derived_credentials (step 3/5 AssumeRole/GetFederationToken/new access key): cloud-iaas-control-plane — chase the control-plane blast radius of the minted credentials`
- `on_federation_or_saml_change (step 6 signing-cert/IdP): active-directory-domain — the on-prem ADFS/identity-provider side of golden SAML`
- `on_oauth_consent_or_app_credential (step 5 consent/service-principal): SELF — re-enter with the malicious app id bound into #{time_window} to trace its independent token use`
- `on_mailbox_or_data_exfil (step 7 inbox-rule/MailItemsAccessed): browser-email-documents — pull the mail/document content and phishing lure off the seized mailbox/client`
- `on_local_client_corroboration_needed (step 9 SaaS-client SQLite): browser-email-documents — parse the endpoint browser/email/cloud-sync artifacts for the same account`
- `on_logging_disabled_or_gap (step 8/10 audit-config off / continuity gap): SELF — re-enter with the gap window bound into #{time_window} to bracket what was hidden`
- `on_export_absent_or_unmountable (step 0/1): acquisition-custody — re-pull the full audit-log export or prove the collection gap`
- `on_dropped_payload_or_malicious_app_binary (step 5/7 a downloaded tool or app): malware-analysis-triage — triage the dropped/encoded payload`

## Jargon decoder
- **Audit log / UAL:** the cloud provider running diary of every action (sign-in, rule change, role grant). Microsoft 365 calls it the **Unified Audit Log (UAL)**; AWS calls it **CloudTrail**; Google calls it the **admin/login audit**.
- **CloudTrail:** AWS audit log; JSON records under `Records[]` with `eventName`, `sourceIPAddress`, `userIdentity`, `userAgent`.
- **Entra ID (Azure AD):** Microsoft cloud identity service; its **sign-in logs** and **audit logs** record logons, MFA, app consent, role and policy changes.
- **OAuth consent / app consent:** a user or admin granting a third-party app permission (scopes) to read mail/files on their behalf; the app then holds its own **refresh token**.
- **Access token / refresh token:** short-lived proof of a session / long-lived credential that mints new access tokens; a stolen refresh token survives a password reset.
- **Token replay (AiTM):** reusing a stolen session cookie/token so MFA shows satisfied with no fresh challenge — adversary-in-the-middle.
- **Service principal:** the identity of an app/automation in the tenant; adding a **credential/secret** to one is a stealthy persistence path.
- **Federation / SAML / token-signing certificate:** the trust that lets an external identity provider issue valid tenant tokens; changing the signing cert or a federated domain enables **golden SAML** (forged tokens that bypass MFA).
- **Conditional access (CA):** Entra policy that gates sign-in by device/location/risk; weakening or removing it is a defense-evasion move.
- **Impossible travel:** two sign-ins for one account from locations too far apart to travel between in the elapsed time.
- **MFA fatigue / push bombing:** spamming approval prompts until the user approves one out of annoyance.
- **New-InboxRule / forwarding rule:** an Exchange/Outlook rule that auto-forwards, deletes, or hides mail — the classic BEC exfiltration channel.
- **MailItemsAccessed / FileDownloaded:** UAL operations recording mail/file access at scale — the data-access fingerprint.
- **STS / AssumeRole / GetFederationToken (AWS):** the Security Token Service mints temporary derived credentials under a new principal name, masking the original caller.
- **NDJSON / events.ndjson:** newline-delimited JSON — one event per line, the normalized form `jq` produces so every later step can filter the same file.
- **Super-timeline:** one merged chronology across many artifacts, built with `log2timeline.py` + `psort.py`.

## Tuning log (append-only — the eval loop writes here; humans never edit rows)
| date | case_id | bucket missed | delta applied |
|---|---|---|---|
