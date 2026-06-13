---
attack_type: browser-email-documents
category_id: browser-email-documents
name: Browser, Email & Document Forensics
description: browsing history, downloads, phishing email and malicious document analysis
version: 1
os_coverage: [windows, linux, macos, cloud]
sub_types_covered: 18
sub_types:
  - browser-history-visits
  - browser-cache-artifacts
  - browser-downloads-list
  - browser-cookies-sessions
  - browser-autofill-form-data
  - browser-typed-urls-search-terms
  - browser-deleted-history-carving
  - email-headers-routing-analysis
  - email-attachments-extraction-pst-ost
  - phishing-lure-link-analysis
  - email-deleted-recovered-items
  - malicious-document-pdf-triage
  - malicious-document-office-ole-structure
  - embedded-object-macro-presence
  - document-embedded-javascript-action
  - document-authoring-metadata-provenance
  - download-provenance-mark-of-the-web
  - credential-harvest-page-evidence
validated_on: []
maturity: draft
variables:
  image_path:
    default: /cases/active/evidence/disk.E01
    derive: "Step 0 — first disk-evidence image (E01/dd/raw/vmdk) enumerated under the evidence directory named in the case brief"
  mount_root:
    default: /cases/active/mount
    derive: "Step 0 — directory where the file system is mounted READ-ONLY (or where icat-extracted browser profiles / mailboxes / documents land when mounting fails)"
  case_out:
    default: /cases/active/out
    derive: "Step 0 — writable case output directory from the case brief; Step 0 creates #{case_out}/receipts/ and #{case_out}/extracted/"
  ntfs_offset_sectors:
    default: 0
    derive: "Step 0 — start sector of the relevant partition from `mmls #{image_path}` (largest NTFS/data partition unless the brief says otherwise)"
  time_window:
    default: 1970-01-01..2099-12-31
    derive: "case brief if it names one; else first confirmed malicious timestamp ±48h once a step pins one (a download, a phishing email receipt, a document open) — then re-scope wide sweeps to it"
---

## In one line
This is how a user got attacked through their web browser, their email, or a booby-trapped document. The browser keeps a diary of every page visited and file downloaded; the mailbox keeps every email with its true sender route hidden in the headers; and an "innocent" PDF or Office file can carry a hidden script that runs the moment it opens. This playbook reads those three sources to prove how the lure arrived, what was clicked, what was downloaded, and what the malicious file did.

## Use this when (triggers)
- A user reports (or you suspect) a **phishing email** — you need the real sender, the true link behind the display text, and whether an attachment was opened.
- A **download** kicked off the incident — you want the source URL, the referring page, and the exact time the file hit disk.
- A **PDF or Office document** is suspected of dropping malware — you need to know if it carries JavaScript, an auto-open action, an embedded object, or a macro (presence — see depth caveat below).
- You need a user's **browsing history / search terms / typed URLs** to place them on a watering-hole or credential-harvest page, or to show data exfiltration via webmail/cloud upload.
- Cookies/sessions, autofill, or saved form data may show **account takeover** or what the user typed into a fake login page.
- History looks **deleted/cleared** and you need to carve the visits back out of the SQLite freelist.

## Quick path (the 90% case)
1. **Timeline-first.** Before any story, fold the browser, mail, and document artifacts into one chronology: render the browser profile with `hindsight.py` (Chrome/Chromium) and/or `SQLECmd` over the profile dir, and fold the whole mount into a super-timeline with `log2timeline.py` + `psort.py`. Skim it inside `#{time_window}` — the order of *email received → link clicked / download → document opened → payload executed* IS the case.
2. **Find the lure.** Export the mailbox with `pffexport` (PST/OST). Read the **Received:** header chain (real origin vs the From: display), the **Reply-To** mismatch, and pull every attachment out to disk.
3. **Triage the download / attachment.** For a PDF run `pdfid.py` then `pdf-parser.py` (look for `/OpenAction`, `/JS`, `/Launch`, `/EmbeddedFile`); for an Office file inspect the **OLE structure** with `olefile` (presence of a macro stream / embedded object — NOT deep macro de-obfuscation, see caveat). Pull authoring metadata with `exiftool`.
4. **Pin the download in the browser.** In the browser history DB the `downloads` table gives the **source URL + referrer + target path + start time**; cross-check the file's **Mark-of-the-Web** (`Zone.Identifier` ADS on NTFS) for the same URL.
5. **Recover what was deleted.** If history/items look wiped, carve the SQLite freelist with `sqlite-carver` and recover deleted mailbox items from the PST with `pffexport`; absence is itself a finding.

If the email's true sender, the clicked link / download URL, the document's malicious indicator, and the on-disk payload all line up on one timeline with a corroborating second source → you're mostly done. Otherwise drop into the full Steps.

## How it unfolds (the story)
A targeted user receives an email whose visible **From** looks trusted but whose **Received** chain and **Reply-To** point elsewhere; the body carries a link whose display text masks the real URL, or an attachment (a PDF/Office doc or a zipped script). The user clicks — the browser records the visit and, if a file came down, a `downloads` row with the source URL and a referrer, and the OS tags the file with a Mark-of-the-Web. Or the user opens the attachment: a PDF with an `/OpenAction`+`/JS` runs script on open, or an Office document's embedded macro/object fetches a second-stage payload. From there the dropped binary executes and the intrusion proper begins — but the browser/mail/document layer is where the *entry* is proven: who lured them, what they clicked, and what the malicious file was built to do.

## Theories to test (and how to rule each out)
| Theory (who / why) | If true, you'd find… | Rule it out if… |
|---|---|---|
| **External-targeted (spear-phish with malicious attachment)** | A mailbox item whose Received chain ≠ the From domain, a Reply-To mismatch, an attachment whose PDF/OLE structure shows `/OpenAction`+`/JS` or a macro/embedded-object stream; the attachment's $MFT create time just before payload execution | No anomalous mail routing AND every attachment is structurally benign (no JS/action/macro/embedded object) AND no post-open execution cluster |
| **External-commodity (drive-by / malvertising download)** | A browser `downloads` row pointing at an unexpected/typosquatted URL with a referrer from an ad/redirect chain, a Mark-of-the-Web Zone.Identifier naming that URL, the file landing in `\Downloads\` then executing | The download URL is a known-good vendor/CDN, no redirect-chain referrer, and the file was never executed (no execution artifact) |
| **Credential-harvest (fake login page, no malware)** | History/typed-URL hits on a look-alike domain, a form-submission/autofill entry or cookie for that domain, often no download at all | No look-alike domain in history, no autofill/cookie for an off-brand login host, MFA/session not abused |
| **Insider (deliberate webmail/cloud exfiltration)** | Browser history showing personal webmail/cloud-upload sessions, large outbound uploads, downloads of sensitive files renamed, history selectively cleared around the act | Browsing is routine business use, no upload/exfil session, no selective history deletion |
| **Supply-chain (trusted-sender account compromised)** | A genuinely-authenticated email (Received chain matches a real partner domain) but carrying a malicious link/doc — the *sender* was compromised upstream | The link/doc is benign, or the sending account shows no compromise and the content is expected business traffic |
| **Innocent / benign (NOT an attack)** | A legitimate vendor email + signed installer download, a PDF with a benign form/JS for field calculation, autofill/cookies from normal use, history "gaps" explained by a sanctioned cache-clear or new profile | A clear sanctioned explanation (known vendor, signed file, routine cache hygiene) AND no malicious structure in any document AND no anomalous mail routing → benign cause confirmed; reclassify |

*(≥1 benign + ≥1 malicious, each ACTIVELY refuted. Attacker types mapped: insider · other-insider · external-commodity · external-targeted · supply-chain · innocent.)*

## Evidence → Tool → What it reveals (per OS)
| Evidence | SIFT tool | What it tells you *for this attack* | OS |
|---|---|---|---|
| Chrome/Chromium/Edge profile (`History`, `Cookies`, `Web Data`, `Login Data`, Cache) | `hindsight.py` | Visits, search terms, typed URLs, the `downloads` table (source URL + referrer + target + time), cookies/sessions, autofill — the spine of browser activity | Windows/Linux/macOS |
| Any browser/app SQLite DB (Chrome/Firefox/Safari history, `Web Data`, `Cookies`) | `SQLECmd` (map library) / `sqlite3` (scriptable) | Parses the on-disk SQLite tables into CSV (visits/downloads/autofill) for browsers whose maps exist; raw `sqlite3` queries any schema directly | all |
| Deleted SQLite rows (cleared history, removed downloads) | `sqlite-carver` | Recovers deleted records from the SQLite freelist/unallocated pages — history a user "cleared" is often still there | all |
| PST/OST mailbox store | `pffinfo` (structure) / `pffexport` (items) | Mailbox layout, then every email/attachment/contact extracted to disk — headers, bodies, and attachments for routing and lure analysis | Windows (Outlook) |
| Exported email files (`.eml`/`.msg`/items from pffexport) | `srch_strings` / `bstrings` (header/IOC extraction) | The Received chain, Reply-To, SPF/DKIM result lines, and the true URL behind a display link | all |
| Suspect PDF | `pdfid.py` then `pdf-parser.py` | Keyword counts (`/OpenAction`, `/JS`, `/JavaScript`, `/Launch`, `/EmbeddedFile`) then the actual object/stream content — malicious-PDF triage and JS/action extraction | all |
| Suspect Office document (OLE/CFB `.doc/.xls/.ppt`) | `olefile` (python3-olefile) | The OLE/CFB **structure** — presence of a `Macros`/`VBA` stream or an embedded `\x01Ole10Native` object (macro/object PRESENCE, not de-obfuscated macro source — see caveat) | all |
| Any document (PDF/Office/image) authoring metadata | `exiftool` | Author, Creator/Producer tool, create/modify timestamps, template, GPS — provenance/attribution of the document | all |
| Embedded/dropped PE inside a document stream or download | `pe-carver` | Carves an embedded/dropped PE out of a stream for separate triage (the second-stage payload) | all |
| Downloaded file's Mark-of-the-Web (`:Zone.Identifier` ADS) | `icat` (`<inode>-128-N` ADS) / `srch_strings` | The originating URL and zone the OS stamped on a downloaded file — independent corroboration of the browser `downloads` URL | Windows (NTFS) |
| Java `.idx` download cache (legacy applet/JWS) | `idx-parser` | Download provenance for Java-applet delivery — historic exploit vector | all |
| All artifacts fused | `log2timeline.py` + `psort.py` (+ `pinfo.py`) | One chronology placing email received → link/download → document open → payload write/execute in order | all |
| Image-wide feature sweep (URLs, emails spilled outside the DBs) | `bulk_extractor` / `srch_strings` | URLs, email addresses, and search terms recoverable from unallocated/pagefile even when the browser DB is gone | all |
| Firefox/Safari profile on Linux/macOS (`places.sqlite`, `History.db`) | `sqlite3` / `SQLECmd` | The non-Chromium browsers' history/downloads — `hindsight.py` is Chrome/Chromium-only, so query these with raw SQL | Linux/macOS |

*`hindsight.py` is Chrome/Chromium/Edge-Chromium only; for Firefox/Safari use `sqlite3`/`SQLECmd`. `olefile` reveals OLE structure and macro/object PRESENCE only — there is NO macro de-obfuscator on this box (oletools/olevba/oledump are ABSENT), so deep macro decoding is `⚠️verify` / off-box.*

## Step 0 — evidence inventory & access bootstrap
- n: 0
  tool: |
    mkdir -p "#{case_out}/receipts" "#{case_out}/extracted" && ls -laR "#{mount_root}" > "#{case_out}/receipts/00.txt" 2>&1 ; img_stat "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; mmls "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; fsstat -o #{ntfs_offset_sectors} "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; find "#{mount_root}" \( -iname "History" -o -iname "places.sqlite" -o -iname "*.pst" -o -iname "*.ost" -o -iname "*.pdf" -o -iname "*.doc" -o -iname "*.docx" -o -iname "*.xls" -o -iname "*.xlsx" \) >> "#{case_out}/receipts/00.txt" 2>&1
  expect: every evidence file classified; #{image_path}, #{mount_root}, #{ntfs_offset_sectors}, #{case_out} bound; read-only access proven; browser profile dirs (Chrome/Edge/Firefox), PST/OST mailbox stores, and candidate documents (PDF/Office) are enumerated, or their absence is recorded as a finding
  check: |
    test -r "#{mount_root}" -o -n "$(ls "#{case_out}/extracted" 2>/dev/null)"
  falsify: evidence dir empty/unreadable, or no supported image format found, or no file system for fsstat
  on_result: {expect_met: goto 1, falsify_met: STOP — report acquisition/access failure; pivot acquisition-custody, neither: try the icat-extract fallback (fls to find the browser-profile / PST / document inodes, icat each into #{case_out}/extracted); if that also fails, treat as falsify_met}
  emits: [key_artifacts]
  serves: [browser-history-visits, browser-cache-artifacts, browser-downloads-list, browser-cookies-sessions, browser-autofill-form-data, browser-typed-urls-search-terms, browser-deleted-history-carving, email-headers-routing-analysis, email-attachments-extraction-pst-ost, phishing-lure-link-analysis, email-deleted-recovered-items, malicious-document-pdf-triage, malicious-document-office-ole-structure, embedded-object-macro-presence, document-embedded-javascript-action, document-authoring-metadata-provenance, download-provenance-mark-of-the-web, credential-harvest-page-evidence]
  provenance: {receipt_id: 00, artifact: evidence directory listing + profile/mailbox/document enumeration, offset_or_row: full listing, literal_cited: image filename + browser-profile / PST / document path list}

## Steps (executable — decision-driven)
- n: 1
  precondition: "test -r #{mount_root}"
  tool: |
    PROF="$(find "#{mount_root}" -type d \( -ipath "*Chrome/User Data/Default*" -o -ipath "*Edge/User Data/Default*" -o -ipath "*Chromium/*Default*" \) 2>/dev/null | head -1)" ; /opt/pyhindsight/bin/hindsight.py -i "$PROF" -o "#{case_out}/hindsight" -f sqlite -b Chrome > "#{case_out}/receipts/01.txt" 2>&1 ; ls -la "#{case_out}/hindsight"* >> "#{case_out}/receipts/01.txt" 2>&1
  expect: a parsed browser-activity output (#{case_out}/hindsight*) covering visits, search terms, the downloads table (source URL + referrer + target + time), cookies and autofill — the timeline-first browser spine every later step filters, inside #{time_window}
  check: |
    test -s "#{case_out}/receipts/01.txt" && grep -qiE "hindsight|URL|download|visit|Writing" "#{case_out}/receipts/01.txt"
  falsify: no Chrome/Chromium/Edge profile found to parse (profile dir absent), OR hindsight.py errors on every input (locked/corrupt DB)
  on_result: {expect_met: goto 2, falsify_met: this host may use Firefox/Safari (hindsight.py is Chromium-only) — parse places.sqlite/History.db with sqlite3/SQLECmd (Linux branch L2) instead; if NO browser profile exists at all, record absence and pivot disk-filesystem, neither: re-point -i at the specific profile dir; if the DB is locked, copy it to #{case_out}/extracted and run sqlite3 directly}
  emits: [timeline_events, key_artifacts]
  serves: [browser-history-visits, browser-downloads-list, browser-cookies-sessions, browser-typed-urls-search-terms, browser-cache-artifacts]
  provenance: {receipt_id: 01, artifact: Chrome/Edge profile (History/Cookies/Web Data/Login Data), offset_or_row: hindsight output row count, literal_cited: hindsight processed-profile / record-count line}

- n: 2
  precondition: "exists #{case_out}/receipts/01.txt"
  tool: |
    DL="$(find "#{case_out}/hindsight" -type f 2>/dev/null | head -1)" ; HIST="$(find "#{mount_root}" -type f -iname "History" -ipath "*User Data*" 2>/dev/null | head -1)" ; { grep -iE "download|\.exe|\.zip|\.js|\.scr|\.iso|\.dmg|\.lnk" "$DL" 2>/dev/null ; sqlite3 -readonly "$HIST" "SELECT target_path,tab_url,referrer,start_time FROM downloads;" 2>/dev/null ; } > "#{case_out}/receipts/02.txt" 2>&1
  expect: one or more download rows naming a source URL + referrer + on-disk target path + start time — ideally a file with a risky extension (.exe/.scr/.js/.iso/.lnk) from an unexpected/typosquatted host or an ad/redirect referrer, inside #{time_window}
  check: |
    grep -qiE "http|\.exe|\.zip|\.js|\.scr|\.iso|\.lnk|/downloads/" "#{case_out}/receipts/02.txt"
  falsify: no download rows at all (no file came down via the browser), OR every download is a known-good vendor/CDN URL with a benign extension
  on_result: {expect_met: record the download URL + referrer + target path as IOCs; goto 3, falsify_met: record "no malicious browser download"; the entry may be email-borne — goto 5 (mailbox), neither: query the History downloads/downloads_url_chains tables directly with sqlite3 for the full redirect chain; widen #{time_window}}
  emits: [key_iocs, timeline_events]
  serves: [browser-downloads-list, download-provenance-mark-of-the-web]
  provenance: {receipt_id: 02, artifact: Chrome History downloads table / hindsight downloads, offset_or_row: receipts/02.txt download row, literal_cited: tab_url + target_path string}

- n: 3
  precondition: "exists #{case_out}/receipts/02.txt"
  tool: |
    DLDIR="$(find "#{mount_root}" -type d -ipath "*Downloads*" 2>/dev/null | head -1)" ; find "$DLDIR" -type f 2>/dev/null | while read -r f ; do echo "== $f ==" ; srch_strings -- "$f:Zone.Identifier" 2>/dev/null ; srch_strings "$f" 2>/dev/null | grep -iE "ZoneId|HostUrl|ReferrerUrl" ; done > "#{case_out}/receipts/03.txt" 2>&1 ; find "#{mount_root}" -iname "*.Identifier" >> "#{case_out}/receipts/03.txt" 2>&1
  expect: a Mark-of-the-Web (`Zone.Identifier` ADS / .Identifier file) on the downloaded file carrying ZoneId=3 (Internet) and a HostUrl/ReferrerUrl that MATCHES the browser downloads URL from step 2 — independent corroboration that this file came from the web and from where
  check: |
    grep -qiE "ZoneId|HostUrl|ReferrerUrl|Zone.Identifier" "#{case_out}/receipts/03.txt"
  falsify: the downloaded file has NO Zone.Identifier (MOTW stripped, or filesystem is not NTFS so no ADS), OR the HostUrl disagrees with the browser download URL (two different sources — investigate the conflict)
  on_result: {expect_met: corroborate the download URL (two-source rule met — browser DB + MOTW); goto 4, falsify_met: note MOTW absent/stripped (anti-forensics or non-NTFS); rely on the browser DB + super-timeline alone and hold at inferred; goto 4, neither: address the ADS explicitly via TSK (icat #{image_path} as <inode>-128-N) if srch_strings missed it; goto 4}
  emits: [key_iocs, key_artifacts]
  serves: [download-provenance-mark-of-the-web, browser-downloads-list]
  provenance: {receipt_id: 03, artifact: downloaded file :Zone.Identifier ADS, offset_or_row: receipts/03.txt ZoneId/HostUrl line, literal_cited: HostUrl/ReferrerUrl string}

- n: 4
  precondition: "exists #{case_out}/receipts/01.txt"
  tool: |
    grep -iE "deleted|freelist|unalloc|recovered|record" "#{case_out}/receipts/01.txt" > "#{case_out}/receipts/04.txt" 2>&1 ; HIST="$(find "#{mount_root}" -type f -iname "History" -ipath "*User Data*" 2>/dev/null | head -1)" ; if [ -n "$HIST" ] ; then cp "$HIST" "#{case_out}/extracted/History.copy" ; /opt/sqlite-carver/bin/sqlite-carver -f "#{case_out}/extracted/History.copy" >> "#{case_out}/receipts/04.txt" 2>&1 ; fi
  expect: deleted browser rows recovered from the SQLite freelist/unallocated pages — visits or downloads the user "cleared" but that survive in slack; OR a clean confirmation that no rows were deleted (history is intact)
  check: |
    test -s "#{case_out}/receipts/04.txt"
  falsify: sqlite-carver finds no freelist remnants AND the live tables are intact — history was not cleared/deleted (no carving needed)
  on_result: {expect_met: fold recovered visits/downloads into the timeline; if history was cleared, record the deletion as an anti-forensics finding; goto 5, falsify_met: record "history intact, nothing deleted"; goto 5, neither: run bulk_extractor over the profile dir to recover URLs from unallocated as a second carve; goto 5}
  emits: [timeline_events, key_artifacts]
  serves: [browser-deleted-history-carving, browser-history-visits]
  provenance: {receipt_id: 04, artifact: Chrome History SQLite freelist/unallocated, offset_or_row: sqlite-carver recovered-record line, literal_cited: recovered URL/timestamp string}

- n: 5
  precondition: "test -r #{mount_root}"
  tool: |
    PST="$(find "#{mount_root}" \( -iname "*.pst" -o -iname "*.ost" \) 2>/dev/null | head -1)" ; pffinfo "$PST" > "#{case_out}/receipts/05.txt" 2>&1 ; pffexport -t "#{case_out}/extracted/mailbox" "$PST" >> "#{case_out}/receipts/05.txt" 2>&1 ; ls -laR "#{case_out}/extracted/mailbox"* >> "#{case_out}/receipts/05.txt" 2>&1
  expect: pffinfo reports a valid PST/OST and pffexport writes message items + attachments under #{case_out}/extracted/mailbox — the mailbox content (headers, bodies, attachments) is now on disk for routing and lure analysis
  check: |
    test -s "#{case_out}/receipts/05.txt" && grep -qiE "libpff|Message|Folder|Attachment|Exported|Number of" "#{case_out}/receipts/05.txt"
  falsify: no PST/OST present on the image (web-only mail, or mailbox not collected) — no Outlook store to analyze; OR pffexport errors on a corrupt/encrypted store
  on_result: {expect_met: goto 6, falsify_met: mail may be webmail-only — fall back to the browser history/cookies for the webmail session (steps 1-2) and record the absent local store; if a mailbox was expected but absent record absence and pivot disk-filesystem, neither: re-run pffexport per-folder; if the OST is orphaned/encrypted note it and carve message fragments with bulk_extractor/srch_strings over the store}
  emits: [key_artifacts]
  serves: [email-attachments-extraction-pst-ost, email-deleted-recovered-items]
  provenance: {receipt_id: 05, artifact: PST/OST mailbox store, offset_or_row: pffinfo header + pffexport item count, literal_cited: pffinfo message/folder count line}

- n: 6
  precondition: "exists #{case_out}/receipts/05.txt"
  tool: |
    grep -rhiE "^Received:|^Reply-To:|^Return-Path:|^From:|^Authentication-Results:|spf=|dkim=|dmarc=" "#{case_out}/extracted/mailbox" 2>/dev/null > "#{case_out}/receipts/06.txt" 2>&1 ; grep -rhoiE "https?://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]+" "#{case_out}/extracted/mailbox" 2>/dev/null | sort -u >> "#{case_out}/receipts/06.txt" 2>&1
  expect: a Received: chain whose true originating server/domain does NOT match the From: display domain, and/or a Reply-To/Return-Path mismatch, and/or spf=fail/dkim=fail; plus the real URLs in the body — the link the display text masked (the phishing lure)
  check: |
    grep -qiE "Received:|Reply-To:|Return-Path:|spf=|dkim=|https?://" "#{case_out}/receipts/06.txt"
  falsify: the Received chain, From, Reply-To and Return-Path all agree with a legitimate sender AND SPF/DKIM pass AND the body URLs are benign/expected — no phishing routing or lure here
  on_result: {expect_met: record the spoofed sender + true origin + lure URL as IOCs; goto 7, falsify_met: mail routing is clean — the email is likely legitimate (or the sending account was compromised upstream per the supply-chain theory); check attachments anyway at goto 7, neither: re-extract headers per message (some clients fold long Received lines); resolve the lure URL redirect chain against the browser history downloads_url_chains}
  emits: [key_iocs, actor_accounts]
  serves: [email-headers-routing-analysis, phishing-lure-link-analysis, credential-harvest-page-evidence]
  provenance: {receipt_id: 06, artifact: exported email headers + body, offset_or_row: receipts/06.txt Received/Reply-To/URL line, literal_cited: originating server domain + masked URL string}

- n: 7
  precondition: "exists #{case_out}/receipts/05.txt"
  tool: |
    find "#{case_out}/extracted/mailbox" "#{mount_root}" -type f -iname "*.pdf" 2>/dev/null | head -50 | while read -r f ; do echo "== $f ==" ; pdfid.py "$f" 2>/dev/null ; done > "#{case_out}/receipts/07.txt" 2>&1 ; SUS="$(grep -B20 -iE "/OpenAction +[1-9]|/JS +[1-9]|/JavaScript +[1-9]|/Launch +[1-9]|/EmbeddedFile +[1-9]" "#{case_out}/receipts/07.txt" | grep "== " | tail -1 | sed 's/== //; s/ ==//')" ; if [ -n "$SUS" ] ; then pdf-parser.py --search JavaScript "$SUS" >> "#{case_out}/receipts/07.txt" 2>&1 ; pdf-parser.py --type /OpenAction "$SUS" >> "#{case_out}/receipts/07.txt" 2>&1 ; fi
  expect: a PDF whose pdfid.py counts show /OpenAction or /AA (auto-run on open) together with /JS or /JavaScript (script present) and/or /Launch (run external) or /EmbeddedFile (carried payload); pdf-parser.py then shows the actual JavaScript / action object — a malicious-PDF indicator
  check: |
    grep -qiE "/OpenAction +[1-9]|/JS +[1-9]|/JavaScript +[1-9]|/Launch +[1-9]|/EmbeddedFile +[1-9]|/AA +[1-9]" "#{case_out}/receipts/07.txt"
  falsify: every PDF shows ZERO for /OpenAction, /JS, /JavaScript, /Launch, /AA and /EmbeddedFile — no auto-action, no script, no embedded payload (PDFs are structurally benign)
  on_result: {expect_met: record the PDF + its action/JS as an IOC; extract any /EmbeddedFile payload with pdf-parser.py for goto 9; goto 8, falsify_met: PDFs benign — check Office documents at goto 8, neither: re-run pdf-parser.py with --object on the /OpenAction object to read its target; if streams are compressed use pdf-parser.py --filter to inflate}
  emits: [key_iocs, key_artifacts]
  serves: [malicious-document-pdf-triage, document-embedded-javascript-action]
  provenance: {receipt_id: 07, artifact: suspect PDF, offset_or_row: pdfid.py keyword-count line, literal_cited: /OpenAction + /JS count + JavaScript object string}

- n: 8
  precondition: "exists #{case_out}/receipts/05.txt"
  tool: |
    find "#{case_out}/extracted/mailbox" "#{mount_root}" -type f \( -iname "*.doc" -o -iname "*.xls" -o -iname "*.ppt" -o -iname "*.docm" -o -iname "*.xlsm" \) 2>/dev/null | head -50 | while read -r f ; do echo "== $f ==" ; python3 -c "import olefile,sys; p=sys.argv[1]; print('NOT_OLE') if not olefile.isOleFile(p) else [print(s) for s in olefile.OleFileIO(p).listdir()]" "$f" 2>/dev/null ; done > "#{case_out}/receipts/08.txt" 2>&1 ; find "#{case_out}/extracted/mailbox" "#{mount_root}" -type f \( -iname "*.pdf" -o -iname "*.doc*" -o -iname "*.xls*" \) 2>/dev/null | head -50 | xargs -r exiftool -Author -Creator -Producer -CreateDate -ModifyDate -Company -Template >> "#{case_out}/receipts/08.txt" 2>&1
  expect: an OLE/CFB Office file whose stream listing contains a `Macros`/`VBA`/`_VBA_PROJECT` stream (macro PRESENT) or an `\x01Ole10Native`/embedded-object stream (embedded object PRESENT) — macro/object PRESENCE, NOT decoded macro source; plus exiftool authoring metadata (suspect Author/Producer/template) for provenance
  check: |
    grep -qiE "VBA|Macros|_VBA_PROJECT|Ole10Native|ObjectPool|Author|Producer|Create Date" "#{case_out}/receipts/08.txt"
  falsify: no Office file carries a macro/VBA stream or an embedded-object stream (structurally benign documents) AND authoring metadata is unremarkable
  on_result: {expect_met: record macro/embedded-object PRESENCE + authoring metadata as a finding (flag macro-extraction DEPTH ⚠️verify — no de-obfuscator on box; decode off-box); goto 9, falsify_met: documents benign — the entry was likely the browser download (steps 2-3) or a non-document lure; goto 9, neither: confirm the file really is OLE/CFB (olefile.isOleFile); modern .docx/.xlsm are ZIP — unzip and inspect word/vbaProject.bin presence instead}
  emits: [key_iocs, key_artifacts]
  serves: [malicious-document-office-ole-structure, embedded-object-macro-presence, document-authoring-metadata-provenance]
  provenance: {receipt_id: 08, artifact: suspect Office OLE/CFB document, offset_or_row: receipts/08.txt stream-listing / exiftool field, literal_cited: VBA/Macros stream name + Author/Producer string}

- n: 9
  precondition: "exists #{case_out}/receipts/07.txt"
  tool: |
    mkdir -p "#{case_out}/extracted/carved" ; find "#{case_out}/extracted/mailbox" "#{mount_root}/Users" -type f \( -iname "*.pdf" -o -iname "*.doc" -o -iname "*.xls" -o -iname "*.rtf" \) 2>/dev/null | head -50 | while read -r f ; do /opt/pe-carver/bin/pe-carver -f "$f" -o "#{case_out}/extracted/carved/$(basename "$f").pe" >> "#{case_out}/receipts/09.txt" 2>&1 ; done ; ls -la "#{case_out}/extracted/carved" >> "#{case_out}/receipts/09.txt" 2>&1 ; for p in "#{case_out}/extracted/carved/"* ; do [ -s "$p" ] && { echo "== $p ==" >> "#{case_out}/receipts/09.txt" ; densityscout "$p" >> "#{case_out}/receipts/09.txt" 2>&1 ; sha256deep "$p" >> "#{case_out}/receipts/09.txt" 2>&1 ; } ; done
  expect: an embedded/dropped PE carved out of a document or download stream (the second-stage payload) with a SHA-256 to pivot, and/or a high-density (packed/encrypted) blob inside a doc — the actual malware the lure delivered
  check: |
    test -s "#{case_out}/receipts/09.txt" && grep -qiE "PE|MZ|carved|density|[0-9a-f]{64}" "#{case_out}/receipts/09.txt"
  falsify: no embedded PE in any document/download AND no high-density payload blob — the lure carried script/links only, not a bundled binary
  on_result: {expect_met: record the carved payload SHA-256 as an IOC; pivot malware-analysis-triage for static/behavioral triage; goto 10, falsify_met: record "no bundled binary payload"; the payload (if any) was fetched at runtime by the JS/macro — pivot network-forensics for the second-stage fetch; goto 10, neither: re-run pe-carver on the raw download from step 2; if the payload is a script not a PE, hash the script itself with sha256deep}
  emits: [key_iocs, exfil_or_encryption_facts]
  serves: [embedded-object-macro-presence, document-embedded-javascript-action]
  provenance: {receipt_id: 09, artifact: carved embedded PE / packed blob, offset_or_row: receipts/09.txt sha256deep line, literal_cited: SHA-256 of the carved payload}

- n: 10
  precondition: "test -r #{mount_root}"
  tool: |
    log2timeline.py --status_view none "#{case_out}/web.plaso" "#{mount_root}" > "#{case_out}/receipts/10.txt" 2>&1 ; psort.py -o l2tcsv "#{case_out}/web.plaso" > "#{case_out}/super.csv" 2>> "#{case_out}/receipts/10.txt" ; pinfo.py "#{case_out}/web.plaso" >> "#{case_out}/receipts/10.txt" 2>&1
  expect: a fused super-timeline placing email received → link clicked / file downloaded → document opened → payload written/executed in a coherent order with no unexplained gap, inside #{time_window} — the browser/mail/document chain as one chronology
  check: |
    test -s "#{case_out}/super.csv" && grep -qiE "chrome|firefox|msie|webhist|pst|pff|pdf|olecf|download" "#{case_out}/super.csv"
  falsify: ordering is impossible (e.g. the document open precedes the email arrival) OR an unexplained gap that no cache-clear/history-deletion accounts for — clock manipulation or missing artifacts
  on_result: {expect_met: COMMIT the entry-vector conclusion with a confidence label; close per the gate, falsify_met: re-open the Theories table; anchor to the browser DB visit_time / mail delivery time rather than file MAC times if host clock looks manipulated, neither: run pinfo.py to confirm the webhist/pff/pdf parsers ran; re-filter psort.py to #{time_window} and re-check}
  emits: [timeline_events]
  serves: [browser-history-visits, email-headers-routing-analysis, malicious-document-pdf-triage, download-provenance-mark-of-the-web]
  provenance: {receipt_id: 10, artifact: web.plaso super-timeline, offset_or_row: super.csv ordered rows, literal_cited: ordered email→download→document-open→payload chain}

## Linux branch (L1..Ln) — REQUIRED, numbered, same step shape
- n: L1
  precondition: "os == linux"
  tool: |
    fsstat -o #{ntfs_offset_sectors} "#{image_path}" > "#{case_out}/receipts/L01.txt" 2>&1 ; find "#{mount_root}/home" -maxdepth 5 -type d \( -ipath "*.mozilla/firefox*" -o -ipath "*google-chrome*" -o -ipath "*chromium*" \) 2>/dev/null >> "#{case_out}/receipts/L01.txt" ; find "#{mount_root}/home" -iname "places.sqlite" -o -iname "History" 2>/dev/null >> "#{case_out}/receipts/L01.txt" 2>&1
  expect: this image is Linux (ext/xfs fsstat, /home present) — browser profiles live under ~/.mozilla/firefox (Firefox places.sqlite) and ~/.config/google-chrome|chromium (Chrome History); mail is typically Thunderbird/mbox or webmail, NOT a Windows PST
  check: |
    test -d "#{mount_root}/home" -o -n "$(grep -iE 'ext[234]|xfs' "#{case_out}/receipts/L01.txt" 2>/dev/null)"
  falsify: fsstat reports NTFS and a Users\...\AppData\...\Chrome tree exists — this is Windows, not Linux; the main Windows Steps apply (return to Step 1)
  on_result: {expect_met: goto L2, falsify_met: this is Windows — run the main Steps 1-10 not this branch, neither: confirm OS family from the Step 0 fsstat/disktype receipt; if still ambiguous treat as Windows and run the main branch}
  emits: [key_artifacts]
  serves: [browser-history-visits, browser-cache-artifacts]
  provenance: {receipt_id: L01, artifact: file system + ~ browser-profile listing, offset_or_row: fsstat header + dir listing, literal_cited: ext/xfs FS type or .mozilla/firefox profile path}

- n: L2
  precondition: "os == linux"
  tool: |
    FF="$(find "#{mount_root}/home" -iname "places.sqlite" 2>/dev/null | head -1)" ; CR="$(find "#{mount_root}/home" -type f -iname "History" -ipath "*chrom*" 2>/dev/null | head -1)" ; { [ -n "$FF" ] && { cp "$FF" "#{case_out}/extracted/places.copy" ; sqlite3 -readonly "#{case_out}/extracted/places.copy" "SELECT url,title,visit_count,last_visit_date FROM moz_places ORDER BY last_visit_date DESC LIMIT 200; SELECT content,url FROM moz_annos JOIN moz_places ON moz_annos.place_id=moz_places.id WHERE content LIKE 'http%';" ; } ; [ -n "$CR" ] && { cp "$CR" "#{case_out}/extracted/chist.copy" ; sqlite3 -readonly "#{case_out}/extracted/chist.copy" "SELECT target_path,tab_url,referrer,start_time FROM downloads; SELECT url,title FROM urls ORDER BY last_visit_time DESC LIMIT 200;" ; } ; } > "#{case_out}/receipts/L02.txt" 2>&1
  expect: Firefox moz_places visits + download annotations and/or Chrome urls/downloads rows showing the visited URLs, search terms, and any download source URL/referrer/target — the Linux browser-history equivalent of steps 1-2, inside #{time_window}
  check: |
    test -s "#{case_out}/receipts/L02.txt" && grep -qiE "http|\.exe|\.sh|\.elf|/downloads/|visit" "#{case_out}/receipts/L02.txt"
  falsify: no Firefox/Chrome profile DB on the image, or the DBs are empty/cleared — no browser activity recorded (carve the freelist with sqlite-carver before concluding absence)
  on_result: {expect_met: record visited/download URLs as IOCs; carry into the timeline at L3, falsify_met: record absence; carve deleted rows with sqlite-carver over the copied DBs; if still empty pivot disk-filesystem, neither: widen #{time_window}; query moz_historyvisits / downloads_url_chains for the full referrer chain}
  emits: [actor_accounts, timeline_events]
  serves: [browser-history-visits, browser-downloads-list, browser-typed-urls-search-terms, browser-deleted-history-carving]
  provenance: {receipt_id: L02, artifact: places.sqlite / Chrome History on Linux, offset_or_row: receipts/L02.txt URL/download row, literal_cited: visited URL or download tab_url string}

- n: L3
  precondition: "os == linux"
  tool: |
    find "#{mount_root}/home" "#{mount_root}/tmp" -type f \( -iname "*.pdf" -o -iname "*.doc" -o -iname "*.xls" -o -iname "*.eml" \) 2>/dev/null | head -50 | while read -r f ; do echo "== $f ==" ; pdfid.py "$f" 2>/dev/null ; python3 -c "import olefile,sys; p=sys.argv[1]; print('NOT_OLE') if not olefile.isOleFile(p) else [print(s) for s in olefile.OleFileIO(p).listdir()]" "$f" 2>/dev/null ; done > "#{case_out}/receipts/L03.txt" 2>&1 ; find "#{mount_root}/home" "#{mount_root}/tmp" -type f \( -iname "*.pdf" -o -iname "*.doc*" \) 2>/dev/null | head -50 | xargs -r exiftool -Author -Producer -CreateDate >> "#{case_out}/receipts/L03.txt" 2>&1
  expect: a downloaded/mailed document under ~ or /tmp whose PDF keywords show /OpenAction+/JS or whose OLE listing shows a Macros/VBA stream (macro/action PRESENCE — NOT decoded source, ⚠️verify depth), plus exiftool authoring metadata — the Linux document-triage equivalent of steps 7-8
  check: |
    grep -qiE "/OpenAction +[1-9]|/JS +[1-9]|/JavaScript +[1-9]|VBA|Macros|Ole10Native|Author|Producer" "#{case_out}/receipts/L03.txt"
  falsify: every document is structurally benign (no PDF action/JS, no OLE macro/object stream) and metadata is unremarkable — no malicious document on the Linux host
  on_result: {expect_met: record the document indicator + authoring metadata as a finding (macro depth ⚠️verify — decode off-box); commit with a confidence label, falsify_met: record "documents benign"; the Linux entry was likely a browser download (L2) or a script — pivot malware-analysis-triage, neither: confirm OLE vs ZIP (modern Office is ZIP); unzip .docx/.xlsm and check for word/vbaProject.bin}
  emits: [key_iocs, key_artifacts]
  serves: [malicious-document-pdf-triage, malicious-document-office-ole-structure, embedded-object-macro-presence, document-embedded-javascript-action, document-authoring-metadata-provenance]
  provenance: {receipt_id: L03, artifact: suspect PDF/Office doc on Linux, offset_or_row: receipts/L03.txt keyword/stream/metadata line, literal_cited: /OpenAction+/JS count or VBA stream name or Author string}

## Corroboration (two-source rule)
`required_sources: 2` · `pairs:`
- `[ browser downloads URL (step 2) ↔ the file's Mark-of-the-Web Zone.Identifier HostUrl (step 3) ]`
- `[ phishing email lure URL (step 6) ↔ the matching browser visit/download for that URL (steps 1-2) ]`
- `[ email Received-chain true origin (step 6) ↔ Reply-To/Return-Path/SPF-DKIM result (step 6) ]`
- `[ PDF /OpenAction+/JS indicator (step 7) ↔ the extracted JavaScript object content (step 7 pdf-parser.py) ]`
- `[ Office macro/embedded-object stream PRESENCE (step 8) ↔ a carved embedded PE / second-stage fetch (step 9) ]`
- `[ document authoring metadata (step 8 exiftool) ↔ the document's $MFT create time / mailbox receive time (steps 0/5) ]`
- `[ browser/mail/document chronology (steps 1-8) ↔ the fused super-timeline order (step 10) ]`

One hit is a *lead*; promote to *fact* only when its paired source agrees.

## Don't get fooled (red flags & anti-forensics)
- **Cleared history is evidence, not absence.** A user who "cleared browsing data" often leaves the rows in the SQLite freelist — carve with `sqlite-carver` before concluding nothing was visited. An empty `History` with a recent file-modified time is itself a finding (deliberate deletion).
- **The From: header lies; the Received chain doesn't (easily).** Read the *bottom* (earliest) Received hop for the true origin, the Reply-To/Return-Path for where replies actually go, and the Authentication-Results (spf=/dkim=/dmarc=) — a pretty display name proves nothing.
- **Display text masks the real link.** `Click here` can point anywhere; always extract the underlying `href`/URL from the body, not the visible text, and resolve its redirect chain.
- **pdfid.py counts are a triage lead, not a verdict.** A PDF can carry benign JavaScript (form-field math). `/OpenAction`+`/JS` together, or `/Launch`/`/EmbeddedFile`, raise suspicion — but confirm by reading the actual object with `pdf-parser.py`. Counts ≠ malicious.
- **Macro DEPTH is limited on this box.** `olefile` proves a macro/VBA stream is PRESENT; it does NOT de-obfuscate the macro source (oletools/olevba/oledump are ABSENT). Report "macro present" and decode the VBA off-box — never claim "the macro does X" from structure alone. `⚠️verify`.
- **Modern Office is a ZIP, not OLE.** `.docx`/`.xlsm`/`.pptx` are ZIP packages — `olefile.isOleFile` returns false for them; unzip and look for `word/vbaProject.bin` (an OLE blob) instead of expecting a top-level OLE file.
- **Mark-of-the-Web can be stripped.** A downloaded file with NO `Zone.Identifier` may have had MOTW removed (extracted from an archive, or deliberately cleared) — absence is a lead toward anti-forensics, not proof the file is local.
- **Timestamps lie; visit/receive times are sturdier.** Browser `visit_time`/`last_visit_date` and mail delivery times are harder to forge than file MAC times; if the timeline is internally impossible, anchor to the DB/mail times. **Missing evidence is itself a finding.**
- **OST without Outlook, webmail-only mailboxes.** No PST on the image doesn't mean no mail — the user may use webmail (find it in browser history/cookies) or an orphaned OST; record the absent local store explicitly.

## Failure modes
```
- mode: evidence-access failure — the disk won't mount or the browser profile / PST / documents are unreadable
  guard: Step 0 fallback chain — ewfmount/loop RO, else TSK fls/icat the profile/PST/document inodes into #{case_out}/extracted; if all fail, record acquisition failure and pivot acquisition-custody
- mode: primary-artifact-absent — no browser profile, no PST/OST, or no documents on the image (cleared, or never collected)
  guard: record the absence as a finding; name the secondary sources (webmail in browser history/cookies, super-timeline webhist parser, bulk_extractor URL/email carve from unallocated) and pivot disk-filesystem
- mode: tool-output drift — hindsight/SQLECmd column names change, or a comma/quote in a field breaks a grep/sqlite literal so check exits 2
  guard: on check exit 2, adjudicate from the prose expect/falsify against the receipt, cap confidence at inferred; fall back to raw sqlite3 over the copied DB and grep the URL/timestamp directly, never silently pass
- mode: locked/WAL browser DB — hindsight.py/sqlite errors because the DB is in use or has an uncommitted -wal
  guard: copy History/History-wal/History-shm together into #{case_out}/extracted and query the copy; if WAL must be folded, open read-only and let SQLite checkpoint into the copy
- mode: macro de-obfuscation needed but no de-obfuscator on box (oletools ABSENT)
  guard: report macro/VBA stream PRESENCE only (olefile structure), tag the decode depth ⚠️verify, and hand the vbaProject.bin off-box for decoding — do NOT claim macro behavior from structure
- mode: encrypted/password-protected document or PST — olefile/pffexport cannot read content
  guard: record the encryption as a finding (it is itself signal); note it under exfil_or_encryption_facts; attempt password recovery off-box, do not fabricate content
```
Minimum set every playbook covers: evidence-access failure (Step 0 fallback chain) · primary-artifact-absent (absence recorded, secondary source named) · tool-output drift (`check` exits 2 → prose adjudication, never silent pass).

## Confidence labeling (observation → inference → conclusion)
- **confirmed:** direct receipt verbatim (e.g. the downloads-table row, the Received-chain line, the /OpenAction+/JS count) + ≥2 independent sources agree (browser DB + MOTW; email header + browser visit; PDF count + extracted JS object) + no unrefuted counter-theory.
- **inferred:** grounded but single-source/interpretive — e.g. a download URL with no MOTW corroboration, a macro/VBA stream whose behavior is unread (no de-obfuscator), a carved freelist row, or any `check`-exit-2 adjudication → hedge and tag `⚠️verify`.
- **insufficient_evidence:** precondition unmet (no browser profile / no mailbox / DB encrypted) or sources conflict → abstain; state what's missing, do not guess.

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
- **Windows:** fully covered above — Chrome/Edge profiles under `Users\...\AppData\Local`, Outlook PST/OST stores, documents in `Downloads`/`Documents`/email attachments; NTFS adds the `:Zone.Identifier` Mark-of-the-Web ADS for download provenance.
- **Linux/ESXi:** see the numbered Linux branch (L1–L3). Browser profiles live under `~/.mozilla/firefox` (Firefox `places.sqlite`) and `~/.config/google-chrome`|`chromium` (`History`); mail is Thunderbird/mbox or webmail, not PST; no NTFS ADS so MOTW is absent (download provenance comes from the browser DB + super-timeline only). `hindsight.py` still works on a Linux-resident Chrome profile.
- **macOS:** Safari history is `~/Library/Safari/History.db` and Chrome lives under `~/Library/Application Support/Google/Chrome` — query Safari with `sqlite3`/`SQLECmd`, Chrome with `hindsight.py`; download provenance is the `com.apple.quarantine` extended attribute (the macOS MOTW analog) and the `QuarantineEventsV2` DB — read these with `sqlite3` (mac_apt is broken on this box, so an empty mac_apt result ≠ absence; `⚠️verify`). Apple Mail is `.emlx` under `~/Library/Mail`.
- **Cloud:** webmail (Gmail/O365) and cloud storage leave their trace in the *browser* (history/cookies/cache) on the endpoint, plus any exported provider audit log. This box has no dedicated cloud/webmail-audit parser — grep exported JSON with `bstrings`/`srch_strings` for the message/login/upload events (`⚠️verify`, lead-only) and pivot cloud-identity-saas.

## Real-case notes (non-obvious things to look for)
- **The download `tab_url` vs `referrer` split is the redirect story.** Chrome's `downloads` table (and `downloads_url_chains`) records both the final source URL and the referring page; a benign-looking final CDN URL with an ad/redirect referrer is the malvertising fingerprint. Always pull the chain, not just the last hop. `[Chrome forensics / general DFIR practice · high]`
- **Read the EARLIEST Received hop, not the latest.** Received headers stack newest-on-top; the *bottom* hop is where the mail truly originated. Spoofers control the From: and can forge upper Received lines, but the receiving server's own Received stamp (and the Authentication-Results spf/dkim) is added by infrastructure they don't control. `[email header analysis / MITRE T1566.001 · high]`
- **`/OpenAction` or `/AA` is what makes a malicious PDF auto-run.** `/JS` alone may be benign form math; it's the pairing with an automatic action (`/OpenAction`, `/AA`) — or a `/Launch` to spawn a process, or an `/EmbeddedFile` payload — that turns a PDF into a weapon. pdfid.py surfaces the counts; pdf-parser.py reads the object. `[Didier Stevens PDF tools / MITRE T1204.002 · high]`
- **Macro maldocs hide the code, but the STREAM is always there.** Even heavily obfuscated VBA leaves a `Macros`/`VBA`/`_VBA_PROJECT` stream in the OLE container (or a `word/vbaProject.bin` in a ZIP-based `.docm`). `olefile` proves presence; the actual de-obfuscation needs an off-box decoder (oletools is ABSENT here — `⚠️verify`). `[MITRE T1059.005 / T1137 · high]`
- **Mark-of-the-Web is the OS's own download receipt.** The NTFS `:Zone.Identifier` ADS records `ZoneId=3` and frequently `HostUrl`/`ReferrerUrl` — an independent witness to the browser's download URL. Its ABSENCE on a file that the browser says it downloaded is an anti-forensics lead. `[MOTW / MITRE T1553.005 · high]`
- **Cleared history is rarely gone.** SQLite marks deleted rows free but doesn't zero them; `sqlite-carver` recovers visits/downloads from freelist pages, and `bulk_extractor` recovers URLs from cache/unallocated even after a profile is deleted. Treat a too-clean history as suspicious, not exculpatory. `[SQLite freelist recovery / general DFIR practice · med]`
- **Document authoring metadata fingerprints the kit.** `exiftool` Author/Company/Template and the Producer/Creator tool string often tie a maldoc to a builder or a reused template across a campaign — a cheap attribution lead that survives even when the payload is gone. `[exiftool / document provenance · med]`

## ATT&CK mapping
- T1566.001 · Initial Access · Phishing: Spearphishing Attachment · malicious PDF/Office attachment from the PST/OST — steps 5-8
- T1566.002 · Initial Access · Phishing: Spearphishing Link · masked lure URL in the email body → browser visit/download — steps 2/6
- T1204.001 · Execution · User Execution: Malicious Link · the user clicks the lure and the browser records the visit/download — steps 1-2
- T1204.002 · Execution · User Execution: Malicious File · the user opens the PDF/Office attachment — steps 7-8
- T1059.005 · Execution · Visual Basic · Office macro PRESENT in the OLE/VBA stream (depth ⚠️verify) — step 8
- T1137 · Persistence · Office Application Startup · macro/template-based document persistence (structure-level) — step 8
- T1027 · Defense Evasion · Obfuscated/Compressed Files · obfuscated PDF JS / packed embedded payload (density) — steps 7/9
- T1140 · Defense Evasion · Deobfuscate/Decode Files · the doc/JS decodes a second stage (decode depth ⚠️verify, off-box) — steps 7/9
- T1553.005 · Defense Evasion · Subvert Trust Controls: Mark-of-the-Web Bypass · MOTW stripped/absent on a downloaded payload — step 3
- T1070 · Defense Evasion · Indicator Removal · cleared browser history / deleted mailbox items — steps 4/5
- T1114.001 · Collection · Local Email Collection · reading/exfiltration from the local PST/OST mailbox — step 5
- T1567 · Exfiltration · Exfiltration Over Web Service · webmail/cloud-upload sessions in browser history (insider theory) — steps 1-2

## Pivots (lead-to-lead graph)
- `on_malicious_payload_carved (step 9 carved PE / packed blob): malware-analysis-triage — static/behavioral triage of the dropped second stage`
- `on_runtime_second_stage_fetch (step 7/9 JS/macro that downloads at run-time): network-forensics — find the C2/stager fetch on the wire`
- `on_payload_execution (step 9/10 the dropped binary ran): windows-execution-artifacts — corroborate execution via UserAssist/BAM/Prefetch/LNK`
- `on_webmail_or_cloud_session (step 1-2 webmail/cloud-upload in history): cloud-identity-saas — pull the provider sign-in/audit log for the account`
- `on_history_or_mailbox_cleared (step 4/5 deleted rows/items): SELF — re-enter with the deletion timestamp bound into #{time_window} to bracket what was hidden`
- `on_browser_profile_or_mailbox_absent (step 0/1/5): disk-filesystem — recover the profile/PST from unallocated or prove the collection gap`
- `on_unmountable_or_unacquired_evidence (step 0): acquisition-custody — re-acquire or prove the collection gap`
- `on_credential_harvest_page (step 6 fake-login lure + browser form/cookie): active-directory-domain — check whether the harvested domain credential was then used`

## Jargon decoder
- **Browser profile:** the per-user folder where a browser stores its data — `History`, `Cookies`, `Web Data` (autofill), `Login Data`, and the cache. These are SQLite databases.
- **SQLite:** the small embedded database format browsers use for history/downloads/cookies; deleted rows linger in its "freelist" and can be carved back.
- **downloads table / tab_url / referrer:** the browser's record of each download — the source URL it came from (`tab_url`), the page that linked to it (`referrer`), where it was saved, and when.
- **Mark-of-the-Web (MOTW) / Zone.Identifier:** a hidden NTFS Alternate Data Stream the OS stamps on a downloaded file recording it came from the Internet (`ZoneId=3`) and often the source URL — an independent witness to the browser's download record.
- **ADS (Alternate Data Stream):** an extra, normally-invisible stream attached to an NTFS file (`file:Zone.Identifier`); MOTW lives here.
- **PST / OST:** Outlook's mailbox database files — `.pst` (archive) / `.ost` (cached Exchange copy) — holding emails, contacts, and attachments.
- **Received chain:** the stack of `Received:` headers each mail server adds; the earliest (bottom) hop is the true origin, hard for a spoofer to forge.
- **Reply-To / Return-Path:** where replies and bounces actually go — a mismatch with the visible From: is a phishing tell.
- **SPF / DKIM / DMARC:** email-authentication results (in `Authentication-Results:`); a `fail` is a spoofing/forgery signal.
- **OLE / CFB:** the "Compound File Binary" container format of legacy Office (`.doc/.xls/.ppt`); it holds named streams including macros and embedded objects.
- **VBA / macro stream:** the embedded code in an Office document (`Macros`/`_VBA_PROJECT`/`vbaProject.bin`); its PRESENCE is detectable here, but full decoding needs an off-box tool.
- **/OpenAction · /AA · /JS · /Launch · /EmbeddedFile:** PDF keywords — auto-run-on-open, additional-actions, JavaScript, run-external-program, and a carried file payload; the malicious-PDF tells.
- **embedded object (`\x01Ole10Native`):** a file packaged inside a document (an OLE-packaged executable/script) — a way to smuggle a payload.
- **authoring metadata:** the Author/Company/Producer/template fields inside a document (read by `exiftool`) — useful for attribution.
- **places.sqlite / moz_places:** Firefox's history database and its visits table — the Firefox analog of Chrome's `History`/`urls`.
- **super-timeline:** one merged chronology across many artifacts, built with `log2timeline.py` + `psort.py`.
- **freelist carving:** recovering deleted SQLite rows from pages the database marked free but did not overwrite.

## Tuning log (append-only — the eval loop writes here; humans never edit rows)
| date | case_id | bucket missed | delta applied |
|---|---|---|---|
