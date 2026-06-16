---
attack_type: steganography-data-hiding
category_id: steganography-data-hiding
name: Steganography, Data-Hiding & Encryption
description: payloads hidden in media, encrypted containers and covert data channels
version: 1
os_coverage: [windows, linux, macos, cloud]
sub_types_covered: 6
sub_types:
  - lsb-media-steganography-entropy-metadata-detection
  - appended-data-after-file-eof
  - encrypted-container-identification-bitlocker-veracrypt-luks
  - alternate-data-stream-hiding
  - covert-channel-carrier-artifact
  - carved-hidden-payload-signature-match
validated_on: []
maturity: draft
variables:
  image_path:
    default: /cases/active/evidence/disk.E01
    derive: "Step 0 — first disk-evidence image (E01/dd/raw/vmdk) enumerated under the evidence directory named in the case brief"
  mount_root:
    default: /cases/active/mount
    derive: "Step 0 — directory where the file system is mounted READ-ONLY (or where icat-extracted media/container files land when mounting fails)"
  case_out:
    default: /cases/active/out
    derive: "Step 0 — writable case output directory from the case brief; Step 0 creates #{case_out}/receipts/ and #{case_out}/extracted/"
  ntfs_offset_sectors:
    default: 0
    derive: "Step 0 — start sector of the relevant partition from `mmls #{image_path}` (largest NTFS partition unless the brief says otherwise)"
  time_window:
    default: 1970-01-01..2099-12-31
    derive: "case brief if it names one; else first confirmed hiding/encryption timestamp ±48h once a step pins one — then re-scope wide sweeps to it"
---

## In one line
Someone hid data in plain sight — a secret tucked inside an innocent picture or audio file, extra bytes glued onto the end of a normal file, a second hidden stream behind a visible file, or a whole locked container that looks like random junk. This playbook finds the hiding place and the lock; it does not promise to crack open every hidden message.

## Use this when (triggers)
- A media file (image/audio/video) is **oddly large** for what it shows, or its **entropy is unusually high/flat** — a sign of packed/encrypted data riding inside it.
- A file's **real content disagrees with its extension or its declared size** — bytes appended **after the normal end-of-file** marker.
- You find a large file that is **almost pure randomness** and matches no known type — a possible **encrypted container** (BitLocker / VeraCrypt / LUKS).
- An NTFS file has a hidden **Alternate Data Stream** (a second, invisible stream of bytes behind a visible file).
- Metadata is **stripped, contradictory, or carries an unexpected tool tag** (an `exiftool` smell), or a known stego/crypto utility appears in execution traces.
- You suspect **covert exfiltration** where the carrier (an image, a DNS-looking blob, a base64 wall) is the smuggling vehicle.

## Quick path (the 90% case)
1. **Timeline-first.** Build a file-system timeline (`fls` bodyfile → `mactime`, or `MFTECmd` sorted by time) across `#{mount_root}` and skim it inside `#{time_window}` BEFORE committing to a story — when the suspect media/container was written, and what ran just before it, is the case.
2. **Triage by entropy.** Run `densityscout` over media and large unknown files; the highest-entropy outliers (near-random) are your encrypted-container and embedded-payload candidates. Entropy is a lead, not a verdict.
3. **Read the metadata.** Run `exiftool` on the suspect media — a size that dwarfs the pixel dimensions, a missing/contradictory camera tag, or a tool/software tag is a hiding tell.
4. **Look past end-of-file.** Carve the suspect file with `foremost` / `bulk_extractor` and check whether a second file (ZIP/PE/JPEG) lives **after** the carrier's normal EOF — appended-data is the most common, most findable hiding method.
5. **Hash and pivot.** Hash candidates with `sha256deep`; check ADS on NTFS via `MFTECmd`; scan carved payloads with `python3-yara` (via `page-brute` rules). One signal is a lead — corroborate before you call it hidden data.

If entropy outlier + metadata smell + appended-or-carved payload (or an identified encrypted container) all line up on the timeline → you have detected data-hiding. **Detection is the scope here; general extraction of a steganographic message is NOT promised** (see the tooling note below). Otherwise drop into the full Steps.

## How it unfolds (the story)
An actor takes data they want to move or keep secret and wraps it so it does not look like data: they embed it in the low-order bits of an image or audio file (LSB steganography), they staple a ZIP or executable onto the tail of a JPEG so the image still opens but the archive rides along after the end-of-file marker, they drop the whole secret into an encrypted container (BitLocker/VeraCrypt/LUKS) that reads as featureless randomness, or they tuck a second invisible Alternate Data Stream behind an ordinary NTFS file. The carrier moves through email, cloud sync, or USB looking innocent. Forensically the hiding leaves tells — abnormal entropy, a size that does not match the visible content, metadata that was stripped or tagged by a hiding tool, bytes past EOF, an extra `$DATA` stream, or a container signature with no file system inside.

## Theories to test (and how to rule each out)
| Theory (who / why) | If true, you'd find… | Rule it out if… |
|---|---|---|
| **Insider exfiltration via stego carrier** | A user-created image/audio whose entropy and size far exceed its visible content; appended ZIP/archive past EOF; the file then copied to USB / uploaded / mailed near its creation time | Entropy and size match a normal photo, no trailing data past EOF, and the file never moved to any removable/cloud/mail path |
| **Encrypted container hiding a data hoard** | A large near-random file with a VeraCrypt/LUKS/BitLocker signature (or NO file-system signature at all), no recognizable internal structure, created/mounted around the suspect activity | The high-entropy file is a known compressed/media format with a valid internal structure (a real ZIP/MP4), or a benign full-disk-encryption volume expected on this host |
| **ADS used to stash a payload or script** | An NTFS file carrying a second `$DATA` stream (e.g. report.docx:hidden) whose content is a PE, script, or archive — invisible in a normal directory listing | No file has more than its primary unnamed `$DATA` stream; the only streams present are benign Zone.Identifier marks |
| **External-targeted covert channel (C2/exfil carrier)** | A stego/crypto utility in execution traces, base64/hex walls or fake-DNS blobs in strings, repeated near-identical carriers leaving the host on a schedule | No hiding/crypto tooling ran, no encoded-data carriers, and outbound carriers are absent from network/cloud/mail artifacts |
| **Supply-chain / tooling artifact (NOT malicious)** | High entropy and odd metadata explained by a legitimate packer, DRM, or a vendor that ships encrypted assets; the same signature on many hosts from a signed installer | A sanctioned application/installer accounts for the encrypted asset AND no user-data hiding or exfil path is present → benign, reclassify |
| **Innocent / benign (NOT an attack)** | High entropy from ordinary compression/encryption a user legitimately uses (a password manager vault, a normal ZIP, full-disk encryption); metadata stripped by a benign editor; expected accounts, business hours | A clear sanctioned-use record explains the container/compression AND there is no hidden payload, no appended data, no covert movement → benign cause confirmed |

*(≥1 benign + ≥1 malicious, each ACTIVELY refuted. Attacker types mapped: insider · other-insider · external-commodity · external-targeted · supply-chain · innocent.)*

## Evidence → Tool → What it reveals (per OS)
| Evidence | SIFT tool | What it tells you *for this attack* | OS |
|---|---|---|---|
| Suspect media / large unknown files (entropy) | `densityscout` | Near-random density flags an embedded payload, encrypted container, or packed carrier — the entropy triage that finds candidates | all |
| Media/document metadata (EXIF/XMP/authoring) | `exiftool` | Size-vs-dimensions mismatch, stripped/contradictory tags, a stego/editor tool tag, GPS/author provenance — the metadata hiding tell | all |
| Carrier file body past its normal EOF | `foremost` / `photorec` / `scalpel` | A second file (ZIP/PE/JPEG) carved out **after** the carrier's footer = appended-data hiding (the most findable method) | all |
| Whole image — features, encoded blobs, container sigs | `bulk_extractor` | Base64/hex walls, emails/URLs, and feature spills that mark a covert channel or container; FS-independent so it works on raw/unallocated | all |
| Printable strings in a carrier / container | `srch_strings` / `bstrings` | VeraCrypt/LUKS/BitLocker signature words, `PK`/`MZ` headers riding inside, encoded payload fragments | all |
| `$MFT` multiple `$DATA` attributes (NTFS ADS) | `MFTECmd` | A file with more than its primary unnamed `$DATA` stream = an Alternate Data Stream hiding a payload | Windows |
| The hidden ADS content itself | `icat` (address as inum-typ-id, e.g. the named `$DATA` attribute) | Recovers the bytes of the named stream for hashing/signature match | Windows |
| Carved/extracted payload signature match | `python3-yara` (via `page-brute` rules) / `clamscan` | Whether the carved hidden bytes match a known PE/script/malware/archive signature | all |
| Hashes of carriers/payloads | `sha256deep` / `md5deep` (+ `hfind`/`sorter`) | Known-bad/known-good identity; lets you pivot the payload across modalities and hosts | all |
| Embedded PE inside a stream/carrier | `pe-carver` / `pe-scanner` / `packerid.py` | Pulls a dropped PE out of a carrier and flags packing/anomalies | all |
| File-system / $J timeline of the carrier | `fls`+`mactime` / `MFTECmd` ($J) | When the carrier was written, renamed, or moved — ties hiding to user action and to exfil | all |
| Encrypted-container presence in shadow copies | `vshadowinfo` / `vshadowmount` | A container that existed in a prior volume state but was deleted/wiped from the live FS | Windows |
| Pagefile / swap spill (keys, plaintext fragments) | `page-brute` (`python3-yara`) / `srch_strings` | In-memory spill of a passphrase, container header, or plaintext that briefly existed | all |

**Tooling note (scope — read before relying on extraction):** This box has **NO general steganography-extraction toolchain**. `steghide`, `zsteg`, `stegseek`, `stegdetect`, and `stegsolve` are **ABSENT**; `outguess` is named in the category brief but is **not in the run-verified tool list** (`⚠️verify` — treat as absent and use only by hand if a later check confirms it). `ent`, `binwalk`, `ssdeep`, and `openssl` are likewise **not run-verified here** (`⚠️verify`). Therefore this playbook **DETECTS** data-hiding via entropy (`densityscout`), metadata (`exiftool`), appended-data carving (`foremost`/`bulk_extractor`/`srch_strings`), ADS enumeration (`MFTECmd`/`icat`), and carved-payload signature matching (`python3-yara` via `page-brute`); it does **NOT** promise to extract an arbitrary LSB-embedded message. Encrypted containers are **identified**, not decrypted.

## Step 0 — evidence inventory & access bootstrap
- n: 0
  tool: |
    mkdir -p "#{case_out}/receipts" "#{case_out}/extracted" && ls -laR "#{mount_root}" > "#{case_out}/receipts/00.txt" 2>&1 ; img_stat "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; mmls "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; fsstat -o #{ntfs_offset_sectors} "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; find "#{mount_root}" -type f \( -iname "*.jpg" -o -iname "*.jpeg" -o -iname "*.png" -o -iname "*.bmp" -o -iname "*.gif" -o -iname "*.wav" -o -iname "*.mp3" -o -iname "*.mp4" -o -iname "*.vc" -o -iname "*.hc" -o -iname "*.dmg" \) >> "#{case_out}/receipts/00.txt" 2>&1
  expect: every evidence file classified; #{image_path}, #{mount_root}, #{ntfs_offset_sectors}, #{case_out} bound; read-only access proven; media files and large unknown/container candidates are enumerated, or their absence is recorded (absence is a finding)
  check: |
    test -r "#{mount_root}" -o -n "$(ls "#{case_out}/extracted" 2>/dev/null)"
  falsify: evidence dir empty/unreadable, or no supported image format found, or no partition for fsstat
  on_result: {expect_met: goto 1, falsify_met: STOP — report acquisition/access failure; pivot acquisition-custody, neither: try the icat-extract fallback (fls to find media/container inodes, icat each into #{case_out}/extracted); if that also fails treat as falsify_met}
  emits: [key_artifacts]
  serves: [lsb-media-steganography-entropy-metadata-detection, appended-data-after-file-eof, encrypted-container-identification-bitlocker-veracrypt-luks, alternate-data-stream-hiding, covert-channel-carrier-artifact, carved-hidden-payload-signature-match]
  provenance: {receipt_id: 00, artifact: evidence directory listing + media/container enumeration, offset_or_row: full listing, literal_cited: image filename + media/container file list}

## Steps (executable — decision-driven)
- n: 1
  precondition: "test -r #{mount_root}"
  tool: |
    fls -rp -o #{ntfs_offset_sectors} -m / "#{image_path}" > "#{case_out}/bodyfile" 2>"#{case_out}/receipts/01.txt" ; mactime -b "#{case_out}/bodyfile" -d > "#{case_out}/timeline.csv" 2>>"#{case_out}/receipts/01.txt" ; grep -iE "\.(jpg|jpeg|png|bmp|gif|wav|mp3|mp4|vc|hc|dmg|tc)" "#{case_out}/timeline.csv" >> "#{case_out}/receipts/01.txt" 2>&1
  expect: a file-system timeline (#{case_out}/timeline.csv) exists; the suspect media/container creation/rename/move events fall inside #{time_window}, ideally just after whatever process or download produced them — the timeline-first anchor for the whole case
  check: |
    test -s "#{case_out}/timeline.csv"
  falsify: no media or container-candidate files appear anywhere in the timeline, OR the file system is empty/unreadable so no bodyfile can be built
  on_result: {expect_met: record the carrier creation window; goto 2, falsify_met: record absence of carriers as a finding; sweep unallocated with bulk_extractor (step 6) before concluding nothing is hidden, neither: rebuild the bodyfile with tsk_gettimes if fls produced no rows; widen #{time_window}}
  emits: [timeline_events]
  serves: [lsb-media-steganography-entropy-metadata-detection, appended-data-after-file-eof, encrypted-container-identification-bitlocker-veracrypt-luks]
  provenance: {receipt_id: 01, artifact: file system metadata, offset_or_row: timeline.csv carrier rows, literal_cited: carrier filename + MACB timestamp}

- n: 2
  precondition: "test -r #{mount_root}"
  tool: |
    find "#{mount_root}" -type f \( -iname "*.jpg" -o -iname "*.jpeg" -o -iname "*.png" -o -iname "*.bmp" -o -iname "*.gif" -o -iname "*.wav" -o -iname "*.mp3" -o -iname "*.mp4" -o -size +20M \) -print0 2>/dev/null | xargs -0 densityscout > "#{case_out}/receipts/02.txt" 2>&1
  expect: densityscout density scores for media and large files; the LOW-density (near-random, high-entropy) outliers are embedded-payload / encrypted-container / packed-carrier candidates — note densityscout reports LOW density for high-entropy data, the inverse of intuition
  check: |
    test -s "#{case_out}/receipts/02.txt"
  falsify: every candidate scores as ordinary structured data (no near-random outlier) — no entropy signature of hidden/encrypted payload among the enumerated files
  on_result: {expect_met: shortlist the highest-entropy files; goto 3, falsify_met: record no entropy outlier; an LSB-only stego payload may not raise whole-file entropy — still run metadata (step 3) and EOF carving (step 4) before clearing, neither: re-run densityscout per-file on the largest media; if it errors fall back to a strings/byte-histogram review via srch_strings}
  emits: [key_artifacts]
  serves: [lsb-media-steganography-entropy-metadata-detection, encrypted-container-identification-bitlocker-veracrypt-luks, covert-channel-carrier-artifact]
  provenance: {receipt_id: 02, artifact: media/large files, offset_or_row: densityscout score line, literal_cited: filename + density score}

- n: 3
  precondition: "test -r #{mount_root}"
  tool: |
    find "#{mount_root}" -type f \( -iname "*.jpg" -o -iname "*.jpeg" -o -iname "*.png" -o -iname "*.bmp" -o -iname "*.gif" -o -iname "*.wav" -o -iname "*.mp3" -o -iname "*.mp4" -o -iname "*.tiff" \) -print0 2>/dev/null | xargs -0 exiftool -FileSize -ImageWidth -ImageHeight -Software -Comment -Make -Model -CreateDate -ModifyDate > "#{case_out}/receipts/03.txt" 2>&1
  expect: exiftool fields where FileSize is grossly larger than ImageWidth x ImageHeight implies, OR Make/Model/Software is missing/contradictory, OR a Comment/Software tag names a hiding/editor tool — the metadata smell of an embedded payload or a re-authored carrier
  check: |
    grep -qiE "File Size|Image Width|Software|Comment" "#{case_out}/receipts/03.txt"
  falsify: metadata is internally consistent for every carrier (size matches dimensions, camera tags intact, no tool/editor tag) — no metadata hiding tell
  on_result: {expect_met: flag the metadata-anomalous carriers; goto 4, falsify_met: record metadata clean; absence of metadata is itself suspicious for a stripped carrier — continue to EOF carving (step 4), neither: re-run exiftool with -a -u -g1 to dump all groups including unknown tags; compare against a known-clean sibling photo}
  emits: [key_artifacts, key_iocs]
  serves: [lsb-media-steganography-entropy-metadata-detection, covert-channel-carrier-artifact]
  provenance: {receipt_id: 03, artifact: media metadata, offset_or_row: exiftool field line, literal_cited: FileSize vs dimensions or tool/Software tag string}

- n: 4
  precondition: "test -r #{mount_root}"
  tool: |
    mkdir -p "#{case_out}/extracted/carved" && find "#{mount_root}" -type f \( -iname "*.jpg" -o -iname "*.jpeg" -o -iname "*.png" -o -iname "*.gif" -o -iname "*.bmp" \) 2>/dev/null | while read -r f; do foremost -i "$f" -o "#{case_out}/extracted/carved/$(basename "$f").d" >> "#{case_out}/receipts/04.txt" 2>&1 ; srch_strings -t d "$f" 2>/dev/null | grep -iE "PK\x03\x04|Rar!|7z|MZ|VeraCrypt|-----BEGIN" >> "#{case_out}/receipts/04.txt" 2>&1 ; done
  expect: foremost carves a SECOND file (ZIP/RAR/7z/PE/JPEG) out of a carrier whose footer should have ended it, AND/OR srch_strings shows an archive/PE/PEM signature living past the carrier image footer — bytes after end-of-file are the classic, most findable hiding method
  check: |
    test -s "#{case_out}/receipts/04.txt" && grep -qiE "PK|Rar!|7z|MZ|BEGIN|files? extracted|FOUND" "#{case_out}/receipts/04.txt"
  falsify: foremost carves nothing beyond the carrier itself AND no archive/PE/PEM signature appears past the image footer — no appended-data hiding in these carriers
  on_result: {expect_met: record the appended/embedded payload as an IOC; goto 5, falsify_met: record no appended data; the carrier may still hide LSB data (not entropy/EOF-detectable here) — note that limitation and continue, neither: re-carve with photorec/scalpel against the raw carrier bytes; if a footer offset is known carve from there with bulk_extractor}
  emits: [key_iocs, exfil_or_encryption_facts]
  serves: [appended-data-after-file-eof, carved-hidden-payload-signature-match]
  provenance: {receipt_id: 04, artifact: carrier file body, offset_or_row: srch_strings byte offset of the trailing signature, literal_cited: the PK/MZ/Rar!/PEM signature past EOF}

- n: 5
  precondition: "exists #{case_out}/extracted/carved"
  tool: |
    /opt/page-brute/bin/page-brute -f "#{case_out}/extracted/carved" -o "#{case_out}/receipts" >> "#{case_out}/receipts/05.txt" 2>&1 ; clamscan -r "#{case_out}/extracted/carved" >> "#{case_out}/receipts/05.txt" 2>&1 ; sha256deep -r "#{case_out}/extracted/carved" >> "#{case_out}/receipts/05.txt" 2>&1
  expect: a carved payload matches a python3-yara rule (via page-brute) or a clamscan signature (a PE, script, archive, or known malware), and sha256deep gives a hash to pivot — the carved hidden bytes are identified, not merely present
  check: |
    grep -qiE "FOUND|matched|rule|[0-9a-f]{64}" "#{case_out}/receipts/05.txt"
  falsify: no carved payload matches any python3-yara rule or clamscan signature and the bytes are unstructured noise — the carved data is not an identifiable payload (could be benign or an LSB-only message this box cannot extract)
  on_result: {expect_met: record the payload hash + signature as IOCs; goto 6, falsify_met: keep the carved bytes as an unidentified-data finding at inferred; do not over-claim extraction, neither: re-scan a single carved file with pe-scanner/packerid.py to test for a packed PE; if structureless, label insufficient_evidence}
  emits: [key_iocs, exfil_or_encryption_facts]
  serves: [carved-hidden-payload-signature-match, covert-channel-carrier-artifact]
  provenance: {receipt_id: 05, artifact: carved payload, offset_or_row: page-brute/clamscan match line or sha256deep hash row, literal_cited: rule/signature name + SHA-256}

- n: 6
  precondition: "test -r #{mount_root}"
  tool: |
    find "#{mount_root}" -type f -size +50M -print0 2>/dev/null | xargs -0 -I{} sh -c 'srch_strings -t d "{}" 2>/dev/null | grep -iE "VeraCrypt|TrueCrypt|LUKS|-FVE-FS-|BitLocker|cryptsetup" && echo "HIT {}"' > "#{case_out}/receipts/06.txt" 2>&1 ; find "#{mount_root}" -type f -size +50M -print0 2>/dev/null | xargs -0 densityscout >> "#{case_out}/receipts/06.txt" 2>&1
  expect: a large file carrying a LUKS magic, BitLocker -FVE-FS- signature, or VeraCrypt/TrueCrypt marker — OR a large file with NO recognizable signature at all but near-random density — is an encrypted-container candidate (identified, not decrypted on this box)
  check: |
    grep -qiE "VeraCrypt|TrueCrypt|LUKS|FVE-FS|BitLocker|HIT " "#{case_out}/receipts/06.txt"
  falsify: every large file resolves to a known structured format (real ZIP/MP4/VM disk with valid internal layout) — no encrypted-container signature and no featureless near-random blob
  on_result: {expect_met: record the container file + signature as an exfil/encryption fact; goto 7, falsify_met: record no encrypted container; a wiped or deleted container may survive only in shadow copies — check step 7, neither: a signatureless near-random large file is still a container candidate at inferred; hash it with sha256deep and carry it forward labeled inferred}
  emits: [exfil_or_encryption_facts, key_artifacts]
  serves: [encrypted-container-identification-bitlocker-veracrypt-luks, covert-channel-carrier-artifact]
  provenance: {receipt_id: 06, artifact: large file body, offset_or_row: srch_strings signature offset or densityscout score, literal_cited: LUKS/FVE-FS/VeraCrypt signature or near-random density score}

- n: 7
  precondition: "os == windows; test -r #{mount_root}"
  tool: |
    dotnet /opt/zimmermantools/MFTECmd.dll -f "#{mount_root}" --csv "#{case_out}" --csvf mft.csv > "#{case_out}/receipts/07.txt" 2>&1 ; grep -iE "ADS|:.*DATA|Zone.Identifier" "#{case_out}/mft.csv" >> "#{case_out}/receipts/07.txt" 2>&1
  expect: MFTECmd flags one or more files with a NAMED $DATA attribute beyond the primary unnamed stream (an Alternate Data Stream) — e.g. report.docx:payload — where the stream is NOT a benign Zone.Identifier; the named stream hides a payload behind a visible file
  check: |
    test -s "#{case_out}/mft.csv" && grep -qiE "ADS|:.*DATA" "#{case_out}/receipts/07.txt"
  falsify: the only named streams present are Zone.Identifier (download marks) — no payload-bearing Alternate Data Stream on this NTFS volume
  on_result: {expect_met: record the ADS-bearing file + stream name; recover the stream content with icat addressed as inum-typ-id and hash/scan it (loop to step 5); goto 8, falsify_met: record no payload ADS (only Zone.Identifier); goto 8, neither: re-parse with MFTECmd per-record on the suspect inode; confirm the named $DATA size is non-zero before claiming a hidden stream}
  emits: [key_iocs, key_artifacts]
  serves: [alternate-data-stream-hiding, carved-hidden-payload-signature-match]
  provenance: {receipt_id: 07, artifact: $MFT $DATA attributes, offset_or_row: mft.csv ADS row, literal_cited: file:streamname + stream size}

- n: 8
  precondition: "test -r #{mount_root}"
  tool: |
    bulk_extractor -o "#{case_out}/extracted/bulk" "#{image_path}" > "#{case_out}/receipts/08.txt" 2>&1 ; grep -riE "base64|VeraCrypt|LUKS|BEGIN (PGP|RSA|CERT)|stegano|steghide|outguess" "#{case_out}/extracted/bulk" >> "#{case_out}/receipts/08.txt" 2>&1
  expect: bulk_extractor surfaces base64/hex walls, PEM/PGP blocks, container signature words, or a hiding-tool name spilled across the raw image and unallocated — covert-channel carriers and tool traces the file-level steps missed, FS-independent
  check: |
    test -d "#{case_out}/extracted/bulk" && test -n "$(ls "#{case_out}/extracted/bulk" 2>/dev/null)"
  falsify: bulk_extractor produces no encoded-data, no container signature, and no hiding-tool string anywhere on the image — no image-wide covert-channel or tooling residue
  on_result: {expect_met: correlate the spilled IOCs back to the carrier/container from earlier steps; goto 9, falsify_met: record no image-wide hiding residue; the case rests on the file-level findings, neither: re-run bulk_extractor with the email/base64 scanners only; grep the feature files (url.txt, base64.txt) directly}
  emits: [key_iocs, key_artifacts]
  serves: [covert-channel-carrier-artifact, carved-hidden-payload-signature-match]
  provenance: {receipt_id: 08, artifact: bulk_extractor feature files, offset_or_row: feature file + image offset, literal_cited: encoded-blob / signature / tool-name string}

- n: 9
  precondition: "exists #{case_out}/timeline.csv"
  tool: |
    grep -iE "\.(jpg|jpeg|png|wav|mp3|mp4|vc|hc|dmg|tc|zip|rar)|VeraCrypt|LUKS|FVE-FS|:.*DATA" "#{case_out}/timeline.csv" > "#{case_out}/receipts/09.txt" 2>&1 ; tail -n +1 "#{case_out}/mft.csv" 2>/dev/null | grep -iE "ADS|:.*DATA" >> "#{case_out}/receipts/09.txt" 2>&1
  expect: the carrier/container/ADS findings line up on ONE timeline — created or modified inside #{time_window}, ideally right after a download/tool run and right before a copy to USB / cloud / mail — a coherent hide-then-move chain with no unexplained gap
  check: |
    test -s "#{case_out}/receipts/09.txt"
  falsify: the hiding artifacts cannot be placed in a coherent order (e.g. the appended payload predates the carrier), or an unexplained gap straddles the activity — the story is not yet consistent
  on_result: {expect_met: COMMIT the data-hiding conclusion with a confidence label; close per the gate, falsify_met: re-open the Theories table; a timestomped carrier or wiped log may explain the gap — compare $SI vs $FN via MFTECmd and anchor to $J sequence over host time, neither: widen #{time_window}; fold the carrier/container events into the bodyfile timeline and re-check ordering}
  emits: [timeline_events, exfil_or_encryption_facts]
  serves: [lsb-media-steganography-entropy-metadata-detection, appended-data-after-file-eof, encrypted-container-identification-bitlocker-veracrypt-luks, alternate-data-stream-hiding]
  provenance: {receipt_id: 09, artifact: case timeline + $MFT, offset_or_row: timeline.csv carrier/container/ADS rows, literal_cited: ordered hide-then-move chain timestamps}

## Linux branch (L1..Ln) — REQUIRED, numbered, same step shape
- n: L1
  precondition: "os == linux"
  tool: |
    fsstat -o #{ntfs_offset_sectors} "#{image_path}" > "#{case_out}/receipts/L01.txt" 2>&1 ; find "#{mount_root}" -maxdepth 3 -type f \( -iname "*.luks" -o -iname "*.img" -o -iname "*.vc" -o -iname "*.hc" \) >> "#{case_out}/receipts/L01.txt" 2>&1 ; ls -la "#{mount_root}/home" >> "#{case_out}/receipts/L01.txt" 2>&1
  expect: this image is Linux (ext/xfs fsstat, /home present) — NTFS Alternate Data Streams do NOT exist here; on Linux the equivalents are LUKS containers, appended-data carriers, and high-entropy files under user homes, detected by the same entropy/metadata/carving methods
  check: |
    test -d "#{mount_root}/home" -o -n "$(grep -iE 'ext[234]|xfs' "#{case_out}/receipts/L01.txt" 2>/dev/null)"
  falsify: fsstat reports NTFS and a Windows\System32 tree exists — this is Windows, not Linux; the ADS-bearing main branch applies (return to Step 1)
  on_result: {expect_met: goto L2, falsify_met: this is Windows — run the main Windows Steps 1-9 not this branch, neither: confirm OS family from the Step 0 fsstat/disktype receipt; if still ambiguous treat as Windows and run the main branch}
  emits: [key_artifacts]
  serves: [encrypted-container-identification-bitlocker-veracrypt-luks, alternate-data-stream-hiding]
  provenance: {receipt_id: L01, artifact: file system + /home listing, offset_or_row: fsstat header + dir listing, literal_cited: ext/xfs FS type or LUKS/container filename (Linux-confirmed)}

- n: L2
  precondition: "os == linux"
  tool: |
    find "#{mount_root}/home" "#{mount_root}/tmp" "#{mount_root}/var/tmp" -type f \( -size +20M -o -iname "*.jpg" -o -iname "*.png" -o -iname "*.wav" \) -print0 2>/dev/null | xargs -0 densityscout > "#{case_out}/receipts/L02.txt" 2>&1 ; find "#{mount_root}/home" -type f -size +20M -print0 2>/dev/null | xargs -0 -I{} sh -c 'srch_strings -t d "{}" 2>/dev/null | grep -iE "LUKS|VeraCrypt|-----BEGIN" && echo "HIT {}"' >> "#{case_out}/receipts/L02.txt" 2>&1
  expect: near-random densityscout outliers under user homes/tmp (embedded-payload or encrypted-container candidates) and/or a LUKS/VeraCrypt/PEM signature in a large file — the Linux data-hiding tells, found inside #{time_window}
  check: |
    test -s "#{case_out}/receipts/L02.txt"
  falsify: no entropy outlier and no container/PEM signature anywhere under the user data paths — no Linux data-hiding evidence in these trees
  on_result: {expect_met: shortlist candidates and carve/scan them (reuse main steps 4-5 on the extracted files); commit with a confidence label, falsify_met: record absence; sweep unallocated with bulk_extractor over the raw image before concluding; pivot linux-host-forensics for persistence/exec context, neither: widen #{time_window}; carve deleted carriers from unallocated with foremost over the raw image and re-test entropy}
  emits: [key_artifacts, exfil_or_encryption_facts]
  serves: [encrypted-container-identification-bitlocker-veracrypt-luks, lsb-media-steganography-entropy-metadata-detection, appended-data-after-file-eof]
  provenance: {receipt_id: L02, artifact: /home + /tmp files, offset_or_row: densityscout score / srch_strings signature offset, literal_cited: density score or LUKS/VeraCrypt/PEM signature line}

## Corroboration (two-source rule)
`required_sources: 2` · `pairs:`
- `[ entropy outlier (step 2 densityscout) ↔ metadata size-vs-dimensions mismatch (step 3 exiftool) ]`
- `[ appended-data signature past EOF (step 4 srch_strings) ↔ a carved second file (step 4 foremost) ]`
- `[ carved payload (step 4) ↔ a python3-yara/clamscan signature + SHA-256 (step 5) ]`
- `[ encrypted-container signature (step 6 srch_strings) ↔ near-random density of the same file (step 2/6 densityscout) ]`
- `[ ADS named $DATA stream (step 7 MFTECmd) ↔ the recovered stream content scanned (step 5 via icat) ]`
- `[ image-wide encoded-blob / tool-name spill (step 8 bulk_extractor) ↔ the file-level carrier/container it points to (steps 2-7) ]`
- `[ carrier creation/move (step 1/9 timeline) ↔ the same file's $MFT $SI/$FN times (step 7) ]`

One hit is a *lead*; promote to *fact* only when its paired source agrees.

## Don't get fooled (red flags & anti-forensics)
- **High entropy is a lead, not proof.** A near-random file may be a perfectly legitimate ZIP, video, password-manager vault, or full-disk-encryption volume. Confirm a hiding/container *signature* or an internal-structure mismatch before calling it hidden data — `densityscout` LOW density alone is only a candidate.
- **densityscout density is INVERTED vs intuition.** LOW density score = HIGH entropy (near-random) = the candidate. Read the scale before triaging, or you will chase the wrong files.
- **LSB steganography may NOT raise whole-file entropy.** A small message in the low-order bits of a large image can leave entropy near-normal. No entropy outlier does NOT clear a carrier — still check metadata, EOF carving, and (where a tool exists) bit-plane analysis. This box cannot extract arbitrary LSB messages (`⚠️verify` any LSB-extraction claim).
- **Metadata is editable — and so is its absence.** A stripped EXIF block is itself suspicious (a re-authored carrier), but a present tag can be forged. Treat a tool/editor tag as a lead and corroborate with entropy/EOF, never as a verdict.
- **ADS hides in the listing, not in the bytes.** A normal `ls`/Explorer view never shows a named `$DATA` stream — you only see it in the `$MFT`. Do not conclude "no hidden stream" from a directory listing; read the MFT. **Zone.Identifier streams are benign** download marks — do not over-report them.
- **Bytes past EOF survive normal viewing.** An appended ZIP/PE rides along while the image still opens — the carrier looks 100% normal. Always carve/inspect past the carrier footer, never trust that "the file opens fine."
- **Timestomp on the carrier.** A backdated carrier hides the hide-then-move chain. Compare `$SI` vs `$FN` with `MFTECmd` and anchor ordering to the `$UsnJrnl:$J` sequence over host time.
- **A deleted/wiped container can survive in shadow copies or unallocated.** Absence on the live FS is not absence — check `vshadowinfo`/`vshadowmount` and carve unallocated. **Missing evidence is itself a finding.**
- **Extraction tooling is absent here.** Do not claim a stego message was extracted when only entropy/metadata/EOF detection ran — say "data-hiding detected," not "message recovered," unless a verified extraction actually produced bytes.

## Failure modes
```
- mode: evidence-access failure — the disk won't mount or the media/container files are unreadable
  guard: Step 0 fallback chain — ewfmount/loop RO, else TSK fls/icat the media/container inodes into #{case_out}/extracted; if all fail, record acquisition failure and pivot acquisition-custody
- mode: primary-artifact-absent — no media/carrier/container present (or all carved/deleted)
  guard: record the absence as a finding; sweep unallocated and the raw image with bulk_extractor/foremost and check shadow copies (vshadowinfo) before concluding nothing is hidden; name the secondary sources
- mode: tool-output drift — densityscout density scale, exiftool field labels, or MFTECmd column names change so a check literal misses
  guard: on check exit 2, adjudicate from the prose expect/falsify against the receipt, cap confidence at inferred; re-run per-file and grep the raw output, never silently pass
- mode: entropy false-positive — a benign ZIP/video/FDE volume reads as near-random
  guard: require a container/appended-data SIGNATURE or an internal-structure mismatch (two-source rule) before calling hidden data; compare against a known-good sibling file
- mode: extraction-capability gap — an LSB-embedded message cannot be extracted (no steghide/zsteg/stegseek/stegdetect/stegsolve; outguess unverified)
  guard: detect-and-flag, do not over-claim; label the carrier as a data-hiding candidate at inferred and record that extraction needs an off-box tool (⚠️verify)
- mode: ADS false-positive — Zone.Identifier streams flagged as hidden payloads
  guard: exclude Zone.Identifier; require a named non-Zone $DATA stream with non-zero size before reporting an ADS payload
```
Minimum set every playbook covers: evidence-access failure (Step 0 fallback chain) · primary-artifact-absent (absence recorded, secondary source named) · tool-output drift (`check` exits 2 → prose adjudication, never silent pass).

## Confidence labeling (observation → inference → conclusion)
- **confirmed:** direct receipt verbatim (e.g. the carved PK/MZ signature past EOF or the LUKS magic) + ≥2 independent sources agree (entropy + signature, or signature + carved file, or ADS row + recovered stream) + no unrefuted benign explanation.
- **inferred:** grounded but single-source/interpretive — a near-random file with no signature yet, an entropy outlier with no carved payload, a metadata smell alone, or any `check`-exit-2 adjudication → hedge and tag `⚠️verify`. An LSB carrier this box cannot extract caps here.
- **insufficient_evidence:** precondition unmet (no media/container present; FS unreadable) or sources conflict (entropy high but signature benign) → abstain; state what is missing, do not guess.

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
- **Windows:** fully covered above — NTFS adds Alternate Data Streams (read the `$MFT` for named `$DATA`), and deleted containers may survive in Volume Shadow Copies (`vshadowinfo`/`vshadowmount`). Entropy/metadata/EOF detection applies the same as everywhere.
- **Linux/ESXi:** no ADS — see the numbered Linux branch (L1–L2). Equivalents: LUKS containers (LUKS magic via `srch_strings`), appended-data carriers, and high-entropy files under `/home`, `/tmp`, `/var/tmp`. `cryptsetup`/`openssl` are NOT run-verified here (`⚠️verify`) — identify the container by signature and entropy, do not attempt to open it on-box.
- **macOS:** carriers live in user homes and DMGs; encrypted disk images (`.dmg`/`.sparsebundle`) read as high-entropy and carry a recognizable header in `srch_strings`. The Unified-Log/`mac_apt`-family enrichment is degraded on this box (`⚠️verify`), so rely on entropy/metadata/signature detection of the carrier files themselves; treat findings as lead-only until validated off-box.
- **Cloud:** the carrier is what was uploaded/synced — investigate from *exported* storage objects and audit logs already on disk by grepping with `bulk_extractor`/`srch_strings` for encoded blobs and container signatures; lead-only until validated off-box. Pivot cloud-identity-saas for the upload/sync account.

## Real-case notes (non-obvious things to look for)
- **Appended-data is the most common and most findable method.** A ZIP or RAR stapled after a JPEG footer (the image still renders, the archive still extracts) is the workhorse of casual data-hiding; carve past the carrier footer and look for a `PK`/`Rar!`/`7z` signature where the image should have ended. `[general DFIR / file-format practice · high]`
- **VeraCrypt/TrueCrypt volumes are deliberately featureless.** A real encrypted container has NO usable header signature in its default mode and reads as uniform randomness — so a large file that is near-random AND matches no known type is itself the lead. A plausibly-deniable hidden volume inside it is invisible by design (`⚠️verify` any claim of a hidden volume). `[VeraCrypt design docs / DFIR practice · med]`
- **LUKS and BitLocker DO carry a header signature.** LUKS starts with the `LUKS` magic and BitLocker volumes carry the `-FVE-FS-` marker — `srch_strings` over the raw blob identifies the container type even when you cannot open it. `[on-disk format references · high]`
- **Alternate Data Streams hide where directory listings cannot show them.** A payload in `file.txt:secret` is invisible to `ls`/Explorer and only appears in the `$MFT`'s named `$DATA` attributes; classic abuse stashes a PE or PowerShell script behind a benign-looking document. Exclude the benign `Zone.Identifier` mark before reporting. `[MITRE T1564.004 · high]`
- **LSB steganography can hide under the entropy radar.** A small message in the least-significant bits of a large photo barely moves whole-file entropy, so an entropy-only sweep can miss it — corroborate with metadata, size-vs-dimensions, and (off-box) bit-plane analysis. This box has no LSB extractor, so an LSB carrier is detected-and-flagged, never decoded here (`⚠️verify`). `[steganalysis literature · med]`
- **The hiding tool sometimes leaves its own fingerprint.** A stego/crypto utility name spilled in `bulk_extractor` strings, in a `Software`/`Comment` EXIF tag, or in execution traces, is a strong lead even before the payload is found — pivot to execution artifacts to confirm the tool ran. `[DFIR practice · med]`

## ATT&CK mapping
- T1027.003 · Defense Evasion · Obfuscated Files or Information: Steganography · payload embedded in media — steps 2/3/4
- T1027 · Defense Evasion · Obfuscated/Encrypted Files or Information · high-entropy container / encoded carrier — steps 2/6/8
- T1564.004 · Defense Evasion · Hide Artifacts: NTFS File Attributes (Alternate Data Streams) · named $DATA stream — step 7
- T1564.001 · Defense Evasion · Hide Artifacts: Hidden Files and Directories · payload appended past EOF / hidden in a carrier — step 4
- T1560.001 · Collection · Archive Collected Data via Utility · ZIP/RAR appended to a carrier before exfil — steps 4/9
- T1486 / T1565 · Impact · Data Encrypted / Data Manipulation · encrypted container hiding a data hoard — step 6
- T1041 / T1567 · Exfiltration · Exfiltration Over C2 / Web Service · the carrier moved off-host — steps 8/9
- T1070.006 · Defense Evasion · Timestomp · backdated carrier hiding the hide-then-move chain — steps 7/9

## Pivots (lead-to-lead graph)
- `on_carrier_moved_to_usb_or_cloud (step 9 carrier copied out): insider-threat-data-theft — the exfil path that moved the hidden carrier`
- `on_carved_payload_is_malware (step 5 python3-yara/clamscan match): malware-analysis-triage — triage the recovered hidden binary`
- `on_encrypted_container_identified (step 6 LUKS/VeraCrypt/BitLocker): acquisition-custody — preserve and attempt key recovery off-box`
- `on_covert_channel_carrier_outbound (step 8 encoded carrier leaving the host): network-forensics — trace the smuggling channel on the wire`
- `on_hiding_tool_executed (step 8 stego/crypto tool name in strings): windows-execution-artifacts — confirm the tool ran and when`
- `on_carrier_in_email_or_browser (step 8/9 carrier in a mailbox/download): browser-email-documents — the delivery/exfil vehicle`
- `on_new_carrier_or_timestomp (step 9 gap/inconsistency): SELF — re-enter with the new carrier or the corrected window bound into #{time_window}`
- `on_evidence_unmountable (step 0): acquisition-custody — re-acquire or prove the collection gap`

## Jargon decoder
- **Steganography:** hiding data inside an innocent-looking carrier (image/audio/video) so the existence of the secret is concealed, not just its content.
- **LSB (least-significant-bit) steganography:** hiding a message in the lowest bits of each pixel/sample so the carrier looks unchanged to the eye/ear.
- **Carrier:** the innocent file that secretly transports hidden data.
- **Entropy / density:** a measure of randomness; encrypted or compressed data is near-random (high entropy). `densityscout` reports this as a LOW density score — the inverse of intuition.
- **Appended data / past EOF:** extra bytes glued onto a file AFTER its normal end-of-file marker; the file still opens normally while the extra payload rides along.
- **EOF (end-of-file):** the footer/marker that normally ends a file's content; data after it is "appended."
- **Encrypted container:** a file (BitLocker/VeraCrypt/LUKS) that holds an encrypted file system, readable only with the key; on disk it looks like featureless randomness.
- **BitLocker / VeraCrypt / TrueCrypt / LUKS:** full-volume or file-container encryption systems; LUKS and BitLocker carry on-disk header signatures, VeraCrypt/TrueCrypt deliberately do not.
- **ADS (Alternate Data Stream):** an extra, named `$DATA` stream behind a visible NTFS file (e.g. `report.docx:hidden`) — invisible in a normal directory listing, visible in the `$MFT`.
- **Zone.Identifier:** a benign ADS Windows adds to mark a downloaded file's origin — not a hidden payload.
- **$DATA attribute / $MFT:** the NTFS Master File Table record's content stream(s); a file with more than one named `$DATA` is carrying an ADS.
- **Covert channel:** a smuggling path that disguises data as something else (an image, a base64 wall, fake DNS) to move it past defenses.
- **Carving:** recovering files/payloads by their header/footer signatures without relying on the file system (`foremost`/`photorec`/`scalpel`).
- **python3-yara / YARA-rule:** signature rules (run via the `page-brute` library on this box) that match known payload/malware patterns; there is no standalone `yara` CLI here.
- **PK / MZ / Rar! signatures:** the first bytes that identify a ZIP (`PK`), a Windows executable (`MZ`), or a RAR archive — finding one past a carrier's EOF reveals an appended payload.
- **Timestomp:** forging a file's timestamps to hide when it was created/moved; caught by comparing `$SI` vs `$FN` in the `$MFT`.

## Tuning log (append-only — the eval loop writes here; humans never edit rows)
| date | case_id | bucket missed | delta applied |
|---|---|---|---|
