---
attack_type: threat-hunting-ioc-sweeps
category_id: threat-hunting-ioc-sweeps
name: Threat Hunting & IOC Sweeps
description: proactive YARA, hash and IOC sweeps across collected evidence
version: 1
os_coverage: [windows, linux, macos, cloud]
sub_types_covered: 6
sub_types:
  - yara-rule-sweep-disk-and-memory
  - hash-set-ioc-match
  - fuzzy-hash-variant-hunting
  - registry-ioc-sweep
  - known-good-nsrl-data-reduction
  - ioc-expand-across-modalities
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
    derive: "Step 0 — writable case output directory from the case brief; Step 0 creates #{case_out}/receipts/, #{case_out}/extracted/, #{case_out}/ioc/ (the IOC input set: rules.yar, hashes.txt, indicators.txt) and #{case_out}/nsrl/ (NSRL known-good DB if provided)"
  ntfs_offset_sectors:
    default: 0
    derive: "Step 0 — start sector of the relevant partition from `mmls #{image_path}` (largest NTFS partition unless the brief says otherwise)"
  time_window:
    default: 1970-01-01..2099-12-31
    derive: "case brief if it names one; else first confirmed malicious timestamp ±48h once a step pins one — then re-scope wide sweeps to it"
---

## In one line
You are handed a list of known-bad things — file fingerprints, YARA rules, suspicious paths, IP addresses, account names — and you sweep every piece of collected evidence for them, then chase each hit back through all the other evidence to see how far it spread.

## Use this when (triggers)
- Threat intel arrived (a YARA rule pack, a hash blocklist, an OpenIOC/STIX bundle, a list of bad IPs/domains/filenames) and you must check whether THIS evidence is affected — a proactive sweep, not a single suspicious lead.
- A sibling host in the same incident was confirmed compromised and you are sweeping the rest of the fleet's images for the same indicators.
- You have a huge evidence set and need to **reduce** it: hide millions of known-good operating-system files (NSRL) so only the unknown/known-bad files remain to look at.
- One indicator was found (a hash, a path, a mutex string) and you need to **expand** it — find every other place that indicator or its variants appear across disk, memory, registry, logs, browser and email.
- You suspect a known malware family but the exact sample mutated — you want to catch variants by rule and by fuzzy/structural similarity, not just by exact hash.

## Quick path (the 90% case)
1. **Timeline-first.** Before sweeping, build a quick file-system timeline (`fls` bodyfile → `mactime`, or `MFTECmd` sorted by time) and skim it inside `#{time_window}` so each IOC hit can be placed in order the moment it lands — a hit with no time context is a lead, not a finding.
2. **Stage the IOC input set.** Confirm the rules, hash set and indicator list are present under `#{case_out}/ioc/` (`rules.yar`, `hashes.txt`, `indicators.txt`); validate any OpenIOC/STIX bundle with `iocdump` and flatten it into those flat files. No input set means nothing to sweep — record that and stop.
3. **Reduce, then sweep hashes.** Hash every file with `sha256deep`/`md5deep`, filter out NSRL known-good with `hfind`/`sorter`, then match the survivors against the bad-hash set (`sha256deep -m`). Exact hits are high-signal.
4. **Sweep rules + strings.** Run the YARA rules recursively over the mounted file system and over the pagefile/swap with `page-brute` (yara-python), and pull string/feature indicators with `bulk_extractor` and `srch_strings`/`bstrings`.
5. **Expand every hit across modalities** — take each hash/path/filename/IP/mutex and re-sweep registry (`RECmd`), `$MFT`/`$UsnJrnl` (`MFTECmd`), event logs, browser and email, and place each on the timeline.

If the hash, rule and string sweeps all converge on the same files/paths and you have placed them on the timeline with a second corroborating source → you are mostly done. Otherwise drop into the full Steps. **Quick-path success does NOT close the case** — the close-gate invariant below still applies in full.

## How it unfolds (the story)
Threat hunting here is the mirror image of a normal investigation: instead of starting from a symptom and finding the indicators, you start WITH the indicators and find where they landed. An analyst feeds in a curated set (rules, hashes, names, network indicators), reduces the evidence by hiding everything provably benign, then sweeps the remainder by exact hash, by rule pattern, by fuzzy/structural similarity, and by raw string. Each hit is then expanded — pushed back through every other evidence type and onto the timeline — so a single matched file becomes a mapped footprint (where it was dropped, when it ran, what it touched, where else it spread).

## Theories to test (and how to rule each out)
| Theory (who / why) | If true, you'd find… | Rule it out if… |
|---|---|---|
| **External-targeted (the intel matches — this host is compromised)** | Exact bad-hash matches and/or YARA rule hits on real files inside #{time_window}; the matched path also shows in registry/$MFT/timeline; the IOC expands to more artifacts | Zero exact-hash hits AND every YARA hit is in unallocated/cache only with no live file, no registry/timeline corroboration |
| **External-commodity (generic family caught by a broad rule)** | A YARA hit on a widely-reused packer/loader string but no targeting; the file is a known commodity sample by hash | The rule is signature-precise to a named campaign and the matched file is unique to this host, not a generic crimeware stub |
| **Variant of a known sample (mutated to dodge exact hash)** | NO exact-hash match but a YARA rule hit and high fuzzy/structural similarity to a known-bad reference; same imports/sections via pe-scanner | Similarity is low and the rule hit is a single common string (e.g. a Windows API name) shared by benign software |
| **Innocent / benign (the indicator is a false positive)** | A hash or filename that matches the IOC list but the file is NSRL known-good, vendor-signed, or a legitimate admin tool used in-policy | The file is NSRL/known-good OR signed by a trusted vendor AND its presence is explained by sanctioned software → false positive, reclassify benign |
| **Stale / poisoned intel (the IOC set itself is wrong)** | The rule pack throws hits on core OS binaries; an IP indicator resolves to a CDN; the hash list contains known-good hashes | Cross-checking a sample of hits shows the indicators are over-broad or mislabeled → flag the intel set, do not call the host compromised |
| **Insider staging (bad files placed by a trusted user, not malware delivery)** | IOC-matched tooling under a single user profile, copied (not downloaded), no exploit/delivery trace, access tied to that account | Delivery/exploitation evidence exists (download, exploit, remote drop) tying the files to an external actor → reclassify external |

*(≥1 benign + ≥1 malicious, each ACTIVELY refuted. Attacker types mapped: insider · other-insider · external-commodity · external-targeted · supply-chain · innocent.)*

## Evidence → Tool → What it reveals (per OS)
| Evidence | SIFT tool | What it tells you *for this attack* | OS |
|---|---|---|---|
| Mounted file system (every file) | `sha256deep` / `md5deep` (`-r`, `-m`/`-x` against the bad-hash set) | Exact known-bad hash matches; with the inverse filter, every file that is NOT on the bad list | all |
| NSRL / known-good hash DB | `hfind` (index then lookup) / `sorter` | Data reduction — hides millions of known-good OS files so only unknown/known-bad files remain to triage | all |
| Mounted file system (content) | `page-brute` + the YARA rule pack (`/opt/page-brute`, yara-python) | YARA rule hits across files and across pagefile/swap blocks — catches variants exact hashes miss | all |
| `pagefile.sys` / swap | `page-brute -f` with the rules | In-memory spill IOC discovery — strings/rules of code that ran but left no clean on-disk file | Windows/Linux |
| Suspect PE (a hash/rule hit) | `pe-scanner` (yara-python + entropy) / `densityscout` / `clamscan` | Structural/entropy similarity to a known-bad reference (variant hunting) and a packed-binary lead; AV-signature confirmation | all |
| Whole raw image | `bulk_extractor` / `srch_strings` / `bstrings` | URL/IP/email/CCN/GUID feature indicators FS-independently — catches indicators in slack/unallocated the FS sweep misses | all |
| Registry hives (SYSTEM/SOFTWARE/NTUSER/USRCLASS) | `RECmd` (Kroll batch) / `rip.pl` | Registry IOC sweep — a matched filename/path/GUID in Run keys, Services, UserAssist/BAM, ShellBags (where the IOC persisted/ran) | Windows |
| `$MFT` / `$UsnJrnl:$J` | `MFTECmd` / `fls` / `usn.py` | Where a matched filename/path exists or once existed on disk, with create/rename times to place it on the timeline | Windows |
| OpenIOC / STIX intel bundle | `iocdump` / `stix-validator` | Validates and renders the IOC input set so it can be flattened into the flat sweep files (NOT an evidence parser) | all |
| All artifacts fused | `log2timeline.py` + `psort.py` | One chronology onto which every IOC hit is placed (drop → run → spread ordering) | all |
| RAM image (if captured) | `vol` (Volatility 3) | Live processes/handles/strings matching an IOC; in-memory matches for code with no clean disk file (NO baseline tool on this box — manual triage only) | all |
| IOC enrichment (reputation of a hash/IP/domain) | OFF-BOX — `machinae` is present but broken AND needs internet (sandbox blocks egress); enrich on a connected host | — |

*Memory Baseliner is ABSENT on this box — there is NO automated good/bad memory baseline; memory IOC matching is manual via `vol` + `page-brute`. The `yara` CLI is ABSENT — all YARA sweeps run through `page-brute`/`pe-scanner` (yara-python). `ssdeep`/`hashdeep` are NOT confirmed on this box (`⚠️verify`) — fuzzy-hash variant hunting falls back to `densityscout`/`pe-scanner` structural similarity plus exact-hash clustering.*

## Step 0 — evidence inventory & access bootstrap
- n: 0
  tool: |
    mkdir -p "#{case_out}/receipts" "#{case_out}/extracted" "#{case_out}/ioc" "#{case_out}/nsrl" && ls -laR "#{mount_root}" > "#{case_out}/receipts/00.txt" 2>&1 ; img_stat "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; mmls "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; fsstat -o #{ntfs_offset_sectors} "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; ls -la "#{case_out}/ioc" "#{case_out}/nsrl" >> "#{case_out}/receipts/00.txt" 2>&1
  expect: every evidence file classified; #{image_path}, #{mount_root}, #{ntfs_offset_sectors}, #{case_out} bound; read-only access proven; the IOC input set under #{case_out}/ioc (rules.yar, hashes.txt, indicators.txt) and any NSRL DB under #{case_out}/nsrl are enumerated, or their absence is recorded as a finding
  check: |
    test -r "#{mount_root}" -o -n "$(ls "#{case_out}/extracted" 2>/dev/null)"
  falsify: evidence dir empty/unreadable, or no supported image format found, or no NTFS partition for fsstat
  on_result: {expect_met: goto 1, falsify_met: STOP — report acquisition/access failure; pivot acquisition-custody, neither: try the icat-extract fallback (fls to find target inodes, icat each into #{case_out}/extracted); if that also fails, treat as falsify_met}
  emits: [key_artifacts]
  serves: [yara-rule-sweep-disk-and-memory, hash-set-ioc-match, fuzzy-hash-variant-hunting, registry-ioc-sweep, known-good-nsrl-data-reduction, ioc-expand-across-modalities]
  provenance: {receipt_id: 00, artifact: evidence directory listing + IOC input set enumeration, offset_or_row: full listing, literal_cited: image filename + ioc/ file list}

## Steps (executable — decision-driven)
- n: 1
  tool: |
    ls -la "#{case_out}/ioc" > "#{case_out}/receipts/01.txt" 2>&1 ; for f in "#{case_out}/ioc"/*.ioc "#{case_out}/ioc"/*.xml ; do test -f "$f" && /opt/ioc_writer/bin/iocdump "$f" >> "#{case_out}/receipts/01.txt" 2>&1 ; done ; head -n 5 "#{case_out}/ioc/rules.yar" "#{case_out}/ioc/hashes.txt" "#{case_out}/ioc/indicators.txt" >> "#{case_out}/receipts/01.txt" 2>&1
  expect: a usable IOC input set is staged — rules.yar (YARA rules), hashes.txt (bad-hash list), indicators.txt (paths/filenames/IPs/domains/mutexes); any OpenIOC/STIX bundle rendered by iocdump and flattened into those flat files
  check: |
    test -s "#{case_out}/ioc/rules.yar" -o -s "#{case_out}/ioc/hashes.txt" -o -s "#{case_out}/ioc/indicators.txt"
  falsify: the ioc/ directory is empty or holds no usable rules/hashes/indicators — there is nothing to sweep for
  on_result: {expect_met: record which IOC types are present; goto 2, falsify_met: STOP — no IOC input set; report the gap (a sweep needs indicators) and request the intel from the case brief, neither: render any OpenIOC/STIX with iocdump and flatten it into rules.yar/hashes.txt/indicators.txt then re-check}
  emits: [key_iocs]
  serves: [yara-rule-sweep-disk-and-memory, hash-set-ioc-match, ioc-expand-across-modalities]
  provenance: {receipt_id: 01, artifact: IOC input set under ioc/, offset_or_row: ls listing + iocdump output, literal_cited: rules.yar/hashes.txt/indicators.txt first lines}

- n: 2
  tool: |
    fls -r -m / -o #{ntfs_offset_sectors} "#{image_path}" > "#{case_out}/bodyfile.txt" 2>"#{case_out}/receipts/02.txt" ; mactime -b "#{case_out}/bodyfile.txt" -d -y > "#{case_out}/timeline.csv" 2>>"#{case_out}/receipts/02.txt" ; wc -l "#{case_out}/timeline.csv" >> "#{case_out}/receipts/02.txt" 2>&1
  expect: a file-system timeline (#{case_out}/timeline.csv) exists so every later IOC hit can be placed in order inside #{time_window} — timeline-first before any sweep result is committed
  check: |
    test -s "#{case_out}/timeline.csv"
  falsify: fls/mactime produce no timeline (image unreadable at this offset, or no supported file system)
  on_result: {expect_met: goto 3, falsify_met: rebuild timeline another way — MFTECmd on the $MFT into timeline.csv, or log2timeline.py + psort.py; if all fail record the gap and pivot disk-filesystem, neither: re-run fls with the correct #{ntfs_offset_sectors} from the Step 0 mmls receipt}
  emits: [timeline_events]
  serves: [ioc-expand-across-modalities]
  provenance: {receipt_id: 02, artifact: file system metadata, offset_or_row: bodyfile to timeline.csv row count, literal_cited: mactime header + line count}

- n: 3
  precondition: "test -r #{mount_root}"
  tool: |
    sha256deep -r -l "#{mount_root}" > "#{case_out}/hashes_all.txt" 2>"#{case_out}/receipts/03.txt" ; wc -l "#{case_out}/hashes_all.txt" >> "#{case_out}/receipts/03.txt" 2>&1
  expect: a recursive SHA-256 inventory of every file under #{mount_root} (#{case_out}/hashes_all.txt) — the substrate for both known-good reduction and bad-hash matching
  check: |
    test -s "#{case_out}/hashes_all.txt"
  falsify: the mount is unreadable or empty so no hashes are produced
  on_result: {expect_met: goto 4, falsify_met: hash the icat-extracted artifacts under #{case_out}/extracted instead (sha256deep -r); if nothing hashes, record the access gap and pivot acquisition-custody, neither: re-mount read-only per Step 0 and re-run, or md5deep -r as a fallback hash}
  emits: [key_artifacts]
  serves: [hash-set-ioc-match, known-good-nsrl-data-reduction]
  provenance: {receipt_id: 03, artifact: mounted file system, offset_or_row: hashes_all.txt line count, literal_cited: total file/hash count line}

- n: 4
  precondition: "exists #{case_out}/hashes_all.txt"
  tool: |
    if [ -s "#{case_out}/nsrl/NSRLFile.txt" ]; then hfind -i nsrl-sha1 "#{case_out}/nsrl/NSRLFile.txt" > "#{case_out}/receipts/04.txt" 2>&1 ; fi ; sorter -h -s -m / -o #{ntfs_offset_sectors} -d "#{case_out}/sorter" "#{image_path}" >> "#{case_out}/receipts/04.txt" 2>&1 ; ls -la "#{case_out}/sorter" >> "#{case_out}/receipts/04.txt" 2>&1
  expect: known-good (NSRL) files are identified and set aside so the survivors are the unknown/known-bad set to triage — sorter writes category files and an alerts/known-bad list; data reduction achieved
  check: |
    test -d "#{case_out}/sorter" -o -s "#{case_out}/receipts/04.txt"
  falsify: no NSRL DB is provided AND sorter cannot reduce the set — every file stays in scope (reduction not achieved, not an error)
  on_result: {expect_met: carry the reduced survivor set forward; goto 5, falsify_met: proceed WITHOUT reduction — sweep the full hash inventory in step 5 and note that no known-good filtering was applied, neither: index the NSRL DB first with hfind -i then re-run; if the DB format is unknown skip reduction and continue}
  emits: [key_artifacts]
  serves: [known-good-nsrl-data-reduction]
  provenance: {receipt_id: 04, artifact: NSRL hash DB + sorter categories, offset_or_row: sorter output dir listing, literal_cited: known-good count or sorter alert summary line}

- n: 5
  precondition: "exists #{case_out}/hashes_all.txt; exists #{case_out}/ioc/hashes.txt"
  tool: |
    sha256deep -r -m "#{case_out}/ioc/hashes.txt" "#{mount_root}" > "#{case_out}/hash_hits.txt" 2>"#{case_out}/receipts/05.txt" ; md5deep -r -m "#{case_out}/ioc/hashes.txt" "#{mount_root}" >> "#{case_out}/hash_hits.txt" 2>>"#{case_out}/receipts/05.txt" ; wc -l "#{case_out}/hash_hits.txt" >> "#{case_out}/receipts/05.txt" 2>&1 ; cat "#{case_out}/hash_hits.txt" >> "#{case_out}/receipts/05.txt" 2>&1
  expect: one or more files whose SHA-256 (or MD5) exactly matches the bad-hash set — each matched path is a high-signal known-bad IOC to expand across modalities and place on the timeline
  check: |
    test -s "#{case_out}/hash_hits.txt"
  falsify: zero exact-hash matches against the bad-hash set across the whole file system — the supplied bad hashes are not present as live files here
  on_result: {expect_met: record each matched path + hash as an IOC; goto 6, falsify_met: record "no exact-hash hits"; the family may have mutated — continue to the rule-pattern and fuzzy/structural sweeps (steps 6-7) which catch variants, neither: confirm hashes.txt format matches the deep tool (one hash per line); re-run with md5deep if the list is MD5}
  emits: [key_iocs, key_artifacts]
  serves: [hash-set-ioc-match]
  provenance: {receipt_id: 05, artifact: mounted file system vs bad-hash set, offset_or_row: hash_hits.txt matched rows, literal_cited: matched file path + hash string}

- n: 6
  precondition: "exists #{case_out}/ioc/rules.yar; test -r #{mount_root}"
  tool: |
    /opt/page-brute/bin/page-brute -f "#{mount_root}" -r "#{case_out}/ioc/rules.yar" -o "#{case_out}/yara_fs" > "#{case_out}/receipts/06.txt" 2>&1 ; for pf in $(find "#{mount_root}" -maxdepth 2 -iname "pagefile.sys" -o -iname "swapfile.sys" 2>/dev/null); do /opt/page-brute/bin/page-brute -f "$pf" -r "#{case_out}/ioc/rules.yar" -o "#{case_out}/yara_page" >> "#{case_out}/receipts/06.txt" 2>&1 ; done ; grep -riE "match|hit|rule" "#{case_out}/receipts/06.txt" | head -n 50 >> "#{case_out}/receipts/06.txt" 2>&1
  expect: YARA rule hits naming a rule and an offset/file across the file system and the pagefile/swap — catches code that mutated past its exact hash or spilled into memory with no clean on-disk file
  check: |
    grep -qiE "match|hit|\\brule\\b" "#{case_out}/receipts/06.txt"
  falsify: the rule pack throws zero matches anywhere on disk or in the pagefile/swap
  on_result: {expect_met: record each rule name + matched file/offset as an IOC; goto 7, falsify_met: record "no rule-pattern hits"; if exact-hash hits also came back empty the indicators may be absent or the intel stale — note it and continue to string/feature sweep at goto 8, neither: confirm rules.yar compiles (a broken rule aborts the run); split the pack and re-run; fall back to srch_strings for the literal rule strings}
  emits: [key_iocs, key_artifacts]
  serves: [yara-rule-sweep-disk-and-memory]
  provenance: {receipt_id: 06, artifact: file system + pagefile via page-brute (yara-python), offset_or_row: page-brute match line, literal_cited: matched rule name + file/offset string}

- n: 7
  precondition: "exists #{case_out}/hash_hits.txt -o exists #{case_out}/yara_fs"
  tool: |
    for f in $(grep -oaE "/[^ ]+" "#{case_out}/hash_hits.txt" 2>/dev/null | sort -u | head -n 50); do test -f "$f" && /opt/pe-scanner/bin/pe-scanner -f "$f" >> "#{case_out}/receipts/07.txt" 2>&1 ; done ; find "#{mount_root}" -type f \( -iname "*.exe" -o -iname "*.dll" -o -iname "*.sys" \) -print0 2>/dev/null | xargs -0 -r densityscout >> "#{case_out}/receipts/07.txt" 2>&1 ; clamscan -r -i "#{mount_root}" >> "#{case_out}/receipts/07.txt" 2>&1
  expect: variant hunting — pe-scanner reports PE section/import structure and entropy similar to a known-bad reference; densityscout flags packed/encrypted binaries (a variant lead); clamscan confirms any sample matching an AV signature
  check: |
    grep -qiE "entropy|section|FOUND|density|packed" "#{case_out}/receipts/07.txt"
  falsify: matched/suspect files show normal entropy, ordinary PE structure and no AV signature — no structural variant signal
  on_result: {expect_met: cluster structurally-similar files as candidate variants of the same family; goto 8, falsify_met: record "no structural/AV variant signal"; rely on the exact-hash and rule hits only and continue to goto 8, neither: ssdeep fuzzy hashing is not confirmed on this box (verify off-box); use densityscout entropy buckets and pe-scanner import sets to group candidates manually}
  emits: [key_artifacts, key_iocs]
  serves: [fuzzy-hash-variant-hunting]
  provenance: {receipt_id: 07, artifact: suspect PE files, offset_or_row: pe-scanner/densityscout per-file line, literal_cited: entropy/section value or clamscan FOUND line}

- n: 8
  precondition: "test -r #{mount_root}"
  tool: |
    bulk_extractor -o "#{case_out}/bulk" "#{image_path}" > "#{case_out}/receipts/08.txt" 2>&1 ; while read -r ind; do test -n "$ind" && grep -rsaF "$ind" "#{case_out}/bulk" >> "#{case_out}/receipts/08.txt" 2>&1 ; done < "#{case_out}/ioc/indicators.txt" ; srch_strings -a "#{image_path}" 2>/dev/null | grep -aFf "#{case_out}/ioc/indicators.txt" | head -n 100 >> "#{case_out}/receipts/08.txt" 2>&1
  expect: feature/string IOC hits — an indicator from indicators.txt (URL, IP, domain, filename, mutex) appears in bulk_extractor feature files or in the raw-image strings, including in slack/unallocated the FS sweep cannot reach
  check: |
    test -d "#{case_out}/bulk" && grep -qaFf "#{case_out}/ioc/indicators.txt" "#{case_out}/receipts/08.txt"
  falsify: none of the string/network indicators appear anywhere in the image features or strings
  on_result: {expect_met: record each matched indicator + where it appeared as an IOC; goto 9, falsify_met: record "no string/feature indicator hits"; the network/string indicators are absent from this image and continue to goto 9, neither: confirm indicators.txt is one indicator per line; re-grep bulk_extractor url/domain/email feature files directly}
  emits: [key_iocs]
  serves: [ioc-expand-across-modalities]
  provenance: {receipt_id: 08, artifact: raw image features + strings, offset_or_row: bulk_extractor feature file line / strings byte offset, literal_cited: matched indicator string}

- n: 9
  precondition: "test -r #{mount_root}"
  tool: |
    dotnet /opt/zimmermantools/RECmd/RECmd.dll --bn /opt/zimmermantools/RECmd/BatchExamples/Kroll_Batch.reb -d "#{mount_root}" --csv "#{case_out}" --csvf reg.csv > "#{case_out}/receipts/09.txt" 2>&1 ; grep -aiFf "#{case_out}/ioc/indicators.txt" "#{case_out}/reg.csv" >> "#{case_out}/receipts/09.txt" 2>&1 ; dotnet /opt/zimmermantools/MFTECmd.dll -f "#{mount_root}" --csv "#{case_out}" --csvf mft.csv >> "#{case_out}/receipts/09.txt" 2>&1 ; grep -aiFf "#{case_out}/ioc/indicators.txt" "#{case_out}/mft.csv" >> "#{case_out}/receipts/09.txt" 2>&1
  expect: registry/$MFT IOC sweep — a matched filename/path/GUID from the indicator set appears in a Run key, Service, UserAssist/BAM or ShellBag (RECmd) and/or in the $MFT with create/rename times, showing where the IOC persisted, ran and lives on disk
  check: |
    test -s "#{case_out}/reg.csv" -o -s "#{case_out}/mft.csv"
  falsify: the indicators appear in NO registry source AND are absent from the $MFT — the IOC has no registry/file-system footprint on this host
  on_result: {expect_met: place each registry/$MFT hit on timeline.csv; goto 10, falsify_met: record "no registry/MFT footprint"; rely on the disk/memory hits and continue to goto 10 — pivot windows-registry-persistence if a persistence value is suspected but the batch missed it, neither: run rip.pl -r against the specific SYSTEM/SOFTWARE/NTUSER hive for the indicator and re-check}
  emits: [key_artifacts, key_iocs, timeline_events]
  serves: [registry-ioc-sweep, ioc-expand-across-modalities]
  provenance: {receipt_id: 09, artifact: SYSTEM/SOFTWARE/NTUSER hives + $MFT, offset_or_row: reg.csv key row / mft.csv path row, literal_cited: matched filename/path/GUID + key or create-time string}

- n: 10
  precondition: "exists #{case_out}/timeline.csv"
  tool: |
    log2timeline.py --status_view none "#{case_out}/sweep.plaso" "#{mount_root}" > "#{case_out}/receipts/10.txt" 2>&1 ; psort.py -o l2tcsv "#{case_out}/sweep.plaso" > "#{case_out}/super.csv" 2>>"#{case_out}/receipts/10.txt" ; for ind in $(cat "#{case_out}/ioc/indicators.txt" 2>/dev/null); do grep -aF "$ind" "#{case_out}/super.csv" ; done | head -n 200 >> "#{case_out}/receipts/10.txt" 2>&1
  expect: every IOC hit (hash, rule, string, registry/$MFT) is placed on one fused super-timeline inside #{time_window} in a coherent drop → run → spread order, and each indicator has been expanded back through the other modalities (close-gate: every IOC pivoted)
  check: |
    test -s "#{case_out}/super.csv" && grep -qaFf "#{case_out}/ioc/indicators.txt" "#{case_out}/receipts/10.txt"
  falsify: no IOC lands on the timeline, or the ordering is impossible (spread before drop) — the hits do not cohere into one footprint
  on_result: {expect_met: COMMIT the swept-footprint conclusion with a confidence label; close per the gate, falsify_met: re-open the Theories table; an impossible order may mean timestomp or stale intel — anchor to $MFT/$UsnJrnl sequence over host time, neither: run pinfo.py to confirm the parsers ran; re-filter psort.py to #{time_window} and re-grep the indicators}
  emits: [timeline_events, key_iocs]
  serves: [ioc-expand-across-modalities]
  provenance: {receipt_id: 10, artifact: fused super-timeline, offset_or_row: super.csv ordered rows matching indicators, literal_cited: ordered IOC drop to spread chain}

## Linux branch (L1..Ln) — REQUIRED, numbered, same step shape
- n: L1
  precondition: "os == linux"
  tool: |
    fsstat -o #{ntfs_offset_sectors} "#{image_path}" > "#{case_out}/receipts/L01.txt" 2>&1 ; find "#{mount_root}" -maxdepth 2 \( -name "etc" -o -name "var" -o -name "home" \) -type d 2>/dev/null >> "#{case_out}/receipts/L01.txt" ; ls -la "#{case_out}/ioc" >> "#{case_out}/receipts/L01.txt" 2>&1
  expect: this image is Linux (ext/xfs fsstat; /etc, /var, /home present) — the IOC sweep is OS-agnostic, but the swap target is swapfile/partition (not pagefile.sys) and persistence lives in cron/systemd units, not the registry
  check: |
    test -d "#{mount_root}/etc" -o -n "$(grep -iE 'ext[234]|xfs' "#{case_out}/receipts/L01.txt" 2>/dev/null)"
  falsify: fsstat reports NTFS and a Windows\System32 tree exists — this is Windows, not Linux; run the main Windows Steps 1-10
  on_result: {expect_met: goto L2, falsify_met: this is Windows — run the main branch (Steps 1-10) not this branch, neither: confirm OS family from the Step 0 fsstat/disktype receipt; if still ambiguous treat as Windows and run the main branch}
  emits: [key_artifacts]
  serves: [known-good-nsrl-data-reduction, ioc-expand-across-modalities]
  provenance: {receipt_id: L01, artifact: file system + top-level dir listing, offset_or_row: fsstat header + dir listing, literal_cited: ext/xfs FS type or /etc present (Linux-confirmed)}

- n: L2
  precondition: "os == linux; exists #{case_out}/ioc/hashes.txt"
  tool: |
    sha256deep -r -m "#{case_out}/ioc/hashes.txt" "#{mount_root}" > "#{case_out}/hash_hits_linux.txt" 2>"#{case_out}/receipts/L02.txt" ; wc -l "#{case_out}/hash_hits_linux.txt" >> "#{case_out}/receipts/L02.txt" 2>&1 ; cat "#{case_out}/hash_hits_linux.txt" >> "#{case_out}/receipts/L02.txt" 2>&1
  expect: exact bad-hash matches across the Linux file system — each matched path (often under /tmp, /var/tmp, /dev/shm, a home dir, or a writable web root) is a high-signal known-bad IOC
  check: |
    test -s "#{case_out}/hash_hits_linux.txt"
  falsify: zero exact-hash matches across the Linux file system — the supplied bad hashes are not present as live files here
  on_result: {expect_met: record each matched path + hash; goto L3, falsify_met: record "no exact-hash hits"; the sample may have mutated — continue to the rule-pattern/string sweep at goto L3, neither: confirm hashes.txt format (one hash per line); re-run with md5deep if the list is MD5}
  emits: [key_iocs, key_artifacts]
  serves: [hash-set-ioc-match]
  provenance: {receipt_id: L02, artifact: Linux file system vs bad-hash set, offset_or_row: hash_hits_linux.txt matched rows, literal_cited: matched file path + hash string}

- n: L3
  precondition: "os == linux; exists #{case_out}/ioc/rules.yar"
  tool: |
    /opt/page-brute/bin/page-brute -f "#{mount_root}" -r "#{case_out}/ioc/rules.yar" -o "#{case_out}/yara_fs_linux" > "#{case_out}/receipts/L03.txt" 2>&1 ; for sw in $(find "#{mount_root}" -maxdepth 2 -iname "swapfile" -o -iname "swap.img" 2>/dev/null); do /opt/page-brute/bin/page-brute -f "$sw" -r "#{case_out}/ioc/rules.yar" -o "#{case_out}/yara_swap_linux" >> "#{case_out}/receipts/L03.txt" 2>&1 ; done ; bulk_extractor -o "#{case_out}/bulk_linux" "#{image_path}" >> "#{case_out}/receipts/L03.txt" 2>&1 ; grep -aiFf "#{case_out}/ioc/indicators.txt" "#{case_out}/receipts/L03.txt" >> "#{case_out}/receipts/L03.txt" 2>&1
  expect: YARA rule hits across the Linux file system and swap, plus string/network indicator hits in bulk_extractor features — variant and indicator coverage equivalent to the Windows disk+memory+string sweeps
  check: |
    grep -qiE "match|hit|\\brule\\b" "#{case_out}/receipts/L03.txt"
  falsify: the rule pack and indicator list throw zero matches anywhere on the Linux file system, swap or image features
  on_result: {expect_met: record each rule/indicator hit; place on timeline and expand; commit with a confidence label, falsify_met: record "no rule-pattern/indicator hits on Linux"; sweep cron/systemd unit paths and /var/log text for the indicators with srch_strings; pivot linux-host-forensics, neither: confirm rules.yar compiles; split the pack and re-run; fall back to srch_strings for the literal rule strings}
  emits: [key_iocs, key_artifacts, timeline_events]
  serves: [yara-rule-sweep-disk-and-memory, ioc-expand-across-modalities]
  provenance: {receipt_id: L03, artifact: Linux file system + swap + image features, offset_or_row: page-brute match line / bulk_extractor feature line, literal_cited: matched rule name or indicator string}

## Corroboration (two-source rule)
`required_sources: 2` · `pairs:`
- `[ exact bad-hash match (step 5) ↔ the same path in the $MFT with a create time (step 9) ]`
- `[ YARA rule hit on a file (step 6) ↔ that file also matching a bad hash OR showing high pe-scanner/densityscout structural similarity (step 7) ]`
- `[ registry IOC hit — Run key/Service/UserAssist (step 9) ↔ the referenced binary present on disk + on the timeline (steps 5/9/10) ]`
- `[ string/network indicator in image features (step 8) ↔ the same indicator in a parsed artifact — registry, browser, email or log (step 9/10) ]`
- `[ any single-modality IOC hit ↔ its placement on the fused super-timeline in a coherent order (step 10) ]`
- `[ a candidate variant by structure (step 7) ↔ a YARA rule hit naming the family (step 6) ]`

One hit is a *lead*; promote to *fact* only when its paired source agrees.

## Don't get fooled (red flags & anti-forensics)
- **A hash hit on a known-good file is a false positive, not a compromise.** Always run the NSRL/known-good reduction first; a file that matches a bad-hash list AND the NSRL is a poisoned or mislabeled IOC — flag the intel, do not call the host owned.
- **No exact-hash hit does NOT mean clean.** Variants mutate past their hash; that is exactly why the YARA, structural (pe-scanner/densityscout) and string sweeps exist. Absence of an exact match is a lead to widen the rule sweep, never a clearance.
- **A YARA hit in unallocated/cache with no live file** can be a stale download fragment or a deleted sample — corroborate with the $MFT/$UsnJrnl (did it ever exist as a real file?) before treating it as an active implant.
- **Over-broad rules throw false positives on core OS binaries.** If a rule lights up dozens of signed Windows/Linux system files, suspect the rule, not the host — sample-verify a few hits and quarantine the rule.
- **Stale/poisoned intel.** Bad hashes that are actually known-good, IPs that are CDNs/cloud, filenames that are generic — cross-check a sample of hits against NSRL/signing before reporting; bad intel produces a confident-but-wrong verdict.
- **Timestomp on a matched file** backdates its $SI time so it falls outside #{time_window} and your sweep misses it on the timeline. Compare $SI vs $FN with MFTECmd and trust $UsnJrnl/journal order over host time. **Missing evidence is itself a finding.**
- **An emptied IOC input set is a silent no-op.** If rules.yar/hashes.txt/indicators.txt are empty, the sweep "passes" while finding nothing — Step 1 guards this; an empty input set is a gap to report, not a clean result.

## Failure modes
```
- mode: evidence-access failure — the disk will not mount or #{mount_root} is unreadable
  guard: Step 0 fallback chain — ewfmount/loop RO, else TSK fls/icat the target inodes into #{case_out}/extracted and sweep those; if all fail, record acquisition failure and pivot acquisition-custody
- mode: primary-artifact-absent — no IOC input set staged (empty rules.yar/hashes.txt/indicators.txt) so there is nothing to sweep for
  guard: Step 1 records the absence as a finding (a sweep needs indicators) and STOPS to request the intel; never report "clean" off an empty input set
- mode: tool-output drift — page-brute/RECmd/deep-tool CSV or match-line wording changes so a grep literal in a check exits 2
  guard: on check exit 2, adjudicate from the prose expect/falsify against the receipt, cap confidence at inferred; re-grep the raw feature/match files directly, never silently pass
- mode: yara CLI absent — a step that tried to call `yara` would fail
  guard: all YARA sweeps run through page-brute / pe-scanner (yara-python 4.3.1); the bare yara binary is never invoked
- mode: NSRL/known-good DB missing — no reduction, every file stays in scope
  guard: step 4 proceeds without reduction and notes it; the full hash inventory is still swept — reduction is an optimization, not a gate
- mode: fuzzy-hash tool unconfirmed — ssdeep/hashdeep are not verified on this box
  guard: fall back to densityscout entropy buckets + pe-scanner import/section similarity for variant clustering; verify ssdeep off-box before relying on a fuzzy score
- mode: IOC enrichment needs internet — machinae is broken and the sandbox blocks egress
  guard: never put enrichment in an on-box executable step; flatten the intel in, sweep on-box, enrich a hash/IP/domain off-box on a connected host
```
Minimum set every playbook covers: evidence-access failure (Step 0 fallback chain) · primary-artifact-absent (absence recorded, secondary source named) · tool-output drift (`check` exits 2 → prose adjudication, never silent pass).

## Confidence labeling (observation → inference → conclusion)
- **confirmed:** direct receipt verbatim (e.g. an exact bad-hash match row) + ≥2 independent sources agree (hash + $MFT/timeline, or YARA + structural similarity, or registry + on-disk binary) + no unrefuted counter-theory.
- **inferred:** grounded but single-source/interpretive — a YARA hit with no exact-hash or $MFT corroboration, a structural-similarity cluster with no rule naming the family, an indicator in unallocated only → hedge and tag `⚠️verify`. Every `check`-exit-2 adjudication lands here at best.
- **insufficient_evidence:** precondition unmet (no IOC input set; mount unreadable; no RAM image) or sources conflict → abstain; state what is missing, do not guess.

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
- **Windows:** fully covered above — hash/NSRL reduction, YARA via page-brute (disk + pagefile.sys), structural variant hunting (pe-scanner/densityscout), string/feature sweep (bulk_extractor), and registry/$MFT IOC sweep (RECmd/MFTECmd).
- **Linux/ESXi:** see the numbered Linux branch (L1–L3). The sweep is OS-agnostic for hashes/rules/strings; swap is swapfile/partition not pagefile.sys, and persistence references live in cron/systemd units and `/var/log` text rather than the registry — sweep those paths with `srch_strings`/grep against the indicator list.
- **macOS:** the hash, YARA (page-brute), structural (densityscout) and string (bulk_extractor/srch_strings) sweeps apply unchanged; persistence references live in LaunchAgents/LaunchDaemons plists and the Unified Log. The on-box `mac_apt` parser is BROKEN (`⚠️verify` — degraded) so deep macOS artifact parsing is unavailable; sweep plists/logs as text and treat findings as lead-only.
- **Cloud:** no host file system — the sweep target is *exported* identity/control-plane logs already on disk; grep them with `bstrings`/`srch_strings` for the IP/domain/account indicators (no dedicated cloud-log parser on this box, `⚠️verify`). Pivot cloud-identity-saas. IOC reputation enrichment (`machinae`) is OFF-BOX — the sandbox blocks egress.

## Real-case notes (non-obvious things to look for)
- **Reduce before you sweep, or you drown.** On a full disk the overwhelming majority of files are known-good OS/application binaries; running NSRL (`hfind`/`sorter`) known-good filtering first turns a multi-hour, false-positive-heavy sweep into a focused one over the unknown survivors. `[SANS FOR500/FOR508 data-reduction practice · high]`
- **YARA over the pagefile/swap catches what disk misses.** Code that ran and exited, or that was injected and never written cleanly to disk, leaves strings in `pagefile.sys`/swap; `page-brute` runs the rule pack over those blocks and routinely surfaces family strings absent from any on-disk file. `[page-brute design / memory-spill practice · med]`
- **Exact hashes age out fast; rules and structure age slower.** Operators recompile or repack to break the hash while keeping code/strings stable — so a clean exact-hash sweep with a positive YARA or pe-scanner structural hit is the variant signature, not a contradiction. `[MITRE T1027 / T1036 · high]`
- **The IOC set itself is a hypothesis, not ground truth.** Public/aggregated feeds carry mislabeled hashes (known-good marked bad), CDN IPs, and over-broad filenames; a rule pack that lights up signed system binaries is the tell. Sample-verify hits against NSRL/signing before any verdict. `[threat-intel quality practice · high]`
- **Expand every hit, do not stop at the first match.** A single matched dropper expands — via `$UsnJrnl`, registry Run/Services, prefetch-equivalents and the browser/email that delivered it — into the full footprint; a sweep that reports one file and stops has not done threat hunting. `[ATT&CK-driven hunting practice · high]`
- **Timestomp hides a matched file from a time-scoped sweep.** A backdated `$SI` pushes a real implant outside `#{time_window}`; compare `$SI` vs `$FN` (MFTECmd) and trust `$UsnJrnl`/journal order — a sweep keyed only to host time will silently miss it. `⚠️verify any timeline keyed purely to host clock.` `[MITRE T1070.006 · high]`

## ATT&CK mapping
- T1027 · Defense Evasion · Obfuscated/packed Files (variants dodge exact hash) — steps 6/7
- T1036 · Defense Evasion · Masquerading (renamed/relocated known-bad binaries) — steps 5/9
- T1070.006 · Defense Evasion · Timestomp (matched file backdated out of the window) — steps 9/10
- T1059 · Execution · Command/Scripting payloads caught by rule/string sweep — steps 6/8
- T1547 · Persistence · Boot/Logon Autostart (a matched binary in a Run key/Service) — step 9
- T1057 · Discovery · Process residue matched in pagefile/memory strings — step 6
- T1105 · Command and Control · Ingress tool transfer (matched dropper hash on disk) — step 5
- T1071 · Command and Control · Application-layer protocol (bad IP/domain indicator in features) — step 8

## Pivots (lead-to-lead graph)
- `on_exact_hash_hit (step 5 matched bad hash): malware-analysis-triage — statically/behaviorally triage the matched sample`
- `on_yara_or_variant_hit (step 6/7 rule/structural match): malware-analysis-triage — confirm the family and pull behavior`
- `on_registry_persistence_hit (step 9 Run key/Service): windows-registry-persistence — confirm the autorun in the hive`
- `on_memory_string_hit (step 6 pagefile/swap): memory-forensics — analyze the matching live process in the RAM image`
- `on_network_indicator_hit (step 8 bad IP/domain): network-forensics — corroborate the C2 channel in PCAP/flow`
- `on_new_indicator_expanded (step 10 a fresh hash/path/IP discovered): SELF — re-enter with the new indicator bound into #{case_out}/ioc and #{time_window}`
- `on_evidence_unmountable (step 0): acquisition-custody — re-acquire or prove the collection gap`
- `on_full_intrusion_emerges (step 10 multi-stage footprint): attack-lifecycle-hunting — reconstruct the end-to-end ATT&CK timeline`

## Jargon decoder
- **IOC (Indicator of Compromise):** a concrete piece of known-bad — a file hash, filename, path, IP/domain, mutex, registry value — that you sweep evidence for.
- **YARA rule:** a pattern (strings + conditions) that matches files or memory by content, so it catches variants that an exact hash would miss. On this box YARA runs via `page-brute`/`pe-scanner` (the yara-python library), NOT a `yara` CLI.
- **Hash set / bad-hash list:** a list of SHA-256/MD5 fingerprints of known-bad files; matching evidence hashes against it finds exact copies.
- **NSRL (National Software Reference Library):** a huge database of hashes of known-good software; using it to HIDE benign files is "known-good reduction" — the single biggest time-saver in a sweep.
- **Known-good reduction / data reduction:** filtering out provably benign files (via NSRL/`hfind`/`sorter`) so only unknown/known-bad files remain to examine.
- **Fuzzy / structural similarity:** catching mutated variants by how *similar* a file is (entropy via `densityscout`, PE sections/imports via `pe-scanner`) rather than by exact hash. (`ssdeep` fuzzy hashing is not confirmed on this box.)
- **Pagefile / swap:** the on-disk file Windows/Linux use as overflow RAM; code that ran can leave strings there even with no clean on-disk file — `page-brute` sweeps it with the rule pack.
- **bulk_extractor features:** indicators (URLs, IPs, emails, GUIDs, credit-card numbers) carved from the whole raw image independently of the file system, including from slack/unallocated space.
- **Expand / cross-modality:** taking one IOC hit and re-sweeping every OTHER evidence type (registry, $MFT, logs, browser, email, memory) plus the timeline, so a single match becomes a full footprint.
- **$MFT / $UsnJrnl ($J):** NTFS Master File Table / change journal — where a matched filename/path lives or once lived, with create/rename times to place it on the timeline.
- **Super-timeline:** one merged chronology across many artifacts, built with `log2timeline.py` + `psort.py`, onto which every IOC hit is placed.
- **OpenIOC / STIX:** standard formats for packaging threat intel; `iocdump`/`stix-validator` render/validate them so they can be flattened into the flat sweep files.

## Tuning log (append-only — the eval loop writes here; humans never edit rows)
| date | case_id | bucket missed | delta applied |
|---|---|---|---|
