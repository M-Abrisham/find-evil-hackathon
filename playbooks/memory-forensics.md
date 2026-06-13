---
attack_type: memory-forensics
category_id: memory-forensics
name: Memory (RAM) Forensics
description: triage a captured memory image for rogue processes, injected code, rootkits and network residue
version: 1
os_coverage: [windows, linux, macos, cloud]
sub_types_covered: 14
sub_types:
  - hidden-rogue-process-psscan-vs-pslist
  - process-tree-anomaly-pstree
  - code-injection-malfind
  - unlinked-dll-ldrmodules
  - hooked-ssdt-idt-callbacks
  - network-residue-netscan
  - process-command-line-cmdline
  - registry-in-memory-printkey
  - credentials-in-lsass
  - packed-injected-region-yara
  - kernel-rootkit-modules
  - handle-anomalies
  - loaded-dll-list-dlllist
  - service-persistence-in-memory-svcscan
validated_on: []
maturity: draft
variables:
  image_path:
    default: /cases/active/evidence/memory.raw
    derive: "Step 0 — first MEMORY-evidence image (.raw/.lime/.mem/.vmem/.dmp/hiberfil.sys) enumerated under the evidence directory named in the case brief; falls back to the first disk image (E01/dd/raw/vmdk) for the pagefile/disk corroboration steps"
  mount_root:
    default: /cases/active/mount
    derive: "Step 0 — directory where a companion DISK image is mounted READ-ONLY (or where icat-extracted artifacts such as pagefile.sys land when mounting fails); empty when only a RAM image was acquired"
  case_out:
    default: /cases/active/out
    derive: "Step 0 — writable case output directory from the case brief; Step 0 creates #{case_out}/receipts/ and #{case_out}/extracted/"
  ntfs_offset_sectors:
    default: 0
    derive: "Step 0 — start sector of the relevant partition from `mmls` on the companion disk image (largest NTFS partition unless the brief says otherwise); 0 when no disk image is present"
  time_window:
    default: 1970-01-01..2099-12-31
    derive: "case brief if it names one; else the memory image's acquisition time (a RAM image is one instant) and the first confirmed-malicious timestamp once a step pins one — then re-scope wide sweeps to it"
---

## In one line
RAM is the only place an attacker's program is fully unmasked — running, decrypted, talking to its server. This playbook reads a frozen snapshot of memory to find programs that are hiding, code injected into innocent programs, drivers that shouldn't be there, and network connections that exist nowhere on disk.

## Use this when (triggers)
- You have a **memory image** (`.raw`, `.lime`, `.mem`, `.vmem`, a crash `.dmp`, or `hiberfil.sys`) and need to know what was actually running.
- Disk artifacts hint at something that **left no file** — fileless malware, a process with no on-disk binary, code that runs only in memory.
- You suspect **process hiding** (a process the live machine never showed), **code injection** into a normal process (browser, `explorer.exe`, `lsass.exe`), or a **kernel rootkit** (a malicious driver).
- You need the **command line / network connections** of a process that the disk can't give you, or **credentials** sitting in `lsass.exe`.
- Disk and logs disagree and you need the ground truth of **what the OS itself believed was running** at capture time.

## Quick path (the 90% case)
1. **Timeline-first.** Establish the one instant this image represents, then build the process/network spine that anchors every later finding: run `vol` `pstree` and `netscan` and skim them inside `#{time_window}` BEFORE committing to a story. Process-creation times in `pslist` give you the in-image timeline; fold them (and the companion disk `$MFT`/`$UsnJrnl` if present) into one chronology with `log2timeline.py` + `psort.py` before you decide anything.
2. **Find the rogue process.** Diff `psscan` (carves process structures, sees hidden/exited ones) against `pslist` (the live linked list). A process in `psscan` but missing from `pslist` is hidden. Read `pstree` for an impossible parent (e.g. `services.exe`-less `lsass.exe`, `cmd.exe` under a browser).
3. **Find the injection.** Run `malfind` (executable private memory with no backing file = injected code) and `ldrmodules` (a DLL mapped but unlinked from all three load lists = stealth). Dump the suspect region and scan it with `page-brute` (python3-yara rules) and `pe-scanner`.
4. **Find the network residue.** `netscan` lists sockets/connections carved from memory; pull the foreign IPs/ports and the owning PID, and corroborate with `bulk_extractor` net/pcap features carved from the raw image.
5. **Corroborate off-memory.** Every PID/path/IP from memory must reappear in a second source: the companion disk `$MFT`/registry (`MFTECmd`/`RECmd`/`rip.pl`), the `pagefile.sys` spill (`page-brute`/`srch_strings`), or the timeline. One Volatility line is a lead, not a fact.

If a rogue/injected process, its command line, its network residue, and a corroborating second source all line up on one timeline → you're mostly done. Otherwise drop into the full Steps.

## How it unfolds (the story)
An actor gets code running in memory — a dropped binary, a fileless loader, or a payload injected into a trusted process so nothing suspicious shows on disk. They hide it (unlink the process from the kernel's list, or run only inside `explorer.exe`/`svchost.exe`/`lsass.exe`), establish a channel to a command-and-control server, and may load a malicious driver to hook the OS and stay invisible. They harvest credentials from `lsass.exe` to move laterally. A memory capture freezes all of this — the decrypted code, the live sockets, the command lines, the loaded drivers — because RAM is where the malware must un-hide itself to actually run.

## Theories to test (and how to rule each out)
| Theory (who / why) | If true, you'd find… | Rule it out if… |
|---|---|---|
| **External-targeted (hands-on intruder, fileless/injected implant)** | a process in `psscan` absent from `pslist`, or `malfind` executable private memory in a trusted process; `netscan` foreign C2 IP owned by that PID; `cmdline` showing a loader/encoded command | every process is linked and backed by an on-disk image; `malfind` hits are all known JIT (browser/.NET) regions; no foreign network residue |
| **External-commodity (commodity RAT / packed dropper)** | a packed region (high entropy, no imports) that `pe-scanner`/`page-brute` flags; a child `cmd.exe`/`powershell.exe` under an odd parent; a beaconing socket in `netscan` | the binary is signed and on disk, density is normal, and the parent/child tree matches expected app behavior |
| **Kernel rootkit (driver hiding processes/connections)** | a module in `modules`/`modscan` with no on-disk driver file, SSDT/IDT/callback hooks (`ssdt`/`callbacks`), or `psscan` finding processes `pslist` cannot see | the module list matches signed Microsoft/vendor drivers, no unbacked module, `psscan` and `pslist` agree |
| **Credential theft (lsass harvesting)** | foreign handles into `lsass.exe`, a non-standard process reading lsass, or cleartext-credential strings in the lsass region | only `wininit.exe`-parented `lsass.exe` exists, no foreign opener, and the brief shows no lateral movement |
| **Insider (authorized admin / legitimate tooling)** | the "suspicious" process is a known admin/EDR/RMM agent, injection is a documented security-product hook, the network peer is an internal management host | the tool is sanctioned by change-control AND its parent, path, signer and peer are all expected → benign cause confirmed; reclassify |
| **Innocent / benign (NOT an attack)** | `malfind` noise from .NET/JIT/Just-In-Time browser pages, a normal `svchost.exe` tree, an EDR driver in `modules`, expected outbound 443 to a CDN | the flagged region/process/driver/connection each maps to a documented legitimate cause and nothing else corroborates malice → benign |

*(≥1 benign + ≥1 malicious, each ACTIVELY refuted. Attacker types mapped: insider · other-insider · external-commodity · external-targeted · supply-chain · innocent.)*

## Evidence → Tool → What it reveals (per OS)
| Evidence | SIFT tool | What it tells you *for this attack* | OS |
|---|---|---|---|
| RAM image — process linked-list | `vol` (`pslist`) | The processes the OS *admits* are running, with PID/PPID/create time — the live view a rootkit can lie about | Windows |
| RAM image — carved process structures | `vol` (`psscan`) | Hidden/terminated processes recovered from `_EPROCESS` pool tags; a `psscan`-only process = unlinked/hidden | Windows |
| RAM image — process ancestry | `vol` (`pstree`) | Parent-child anomalies (cmd under a browser, lsass not under wininit) — the tell of injection/spawning | Windows |
| RAM image — private executable memory | `vol` (`malfind`) | Injected/unbacked executable regions (RWX private pages, no mapped file, MZ/shellcode) — code injection | Windows |
| RAM image — module load lists | `vol` (`ldrmodules`, `dlllist`) | A DLL present in VAD but unlinked from Load/Init/Mem lists = stealth-loaded; the full module set per process | Windows |
| RAM image — kernel modules / hooks | `vol` (`modules`, `modscan`, `ssdt`, `callbacks`) | Unbacked/hidden drivers and SSDT/IDT/notify-routine hooks — kernel rootkit | Windows |
| RAM image — network endpoints | `vol` (`netscan`) | TCP/UDP endpoints carved from memory with owning PID — live/recent C2 and lateral connections | Windows |
| RAM image — process command lines | `vol` (`cmdline`) | The exact command line each process launched with (encoded PowerShell, loader args) — execution proof in memory | Windows |
| RAM image — registry in memory | `vol` (`printkey`, `hivelist`) | Run keys/Services/values resident in memory (persistence not yet flushed to the disk hive) | Windows |
| RAM image — handles | `vol` (`handles`) | A process holding a foreign handle into `lsass.exe` (cred theft) or a hidden mutex/event (malware singleton) | Windows |
| RAM image — suspect region content | `page-brute`, `pe-scanner`, `densityscout` | YARA-rule (python3-yara) and entropy/PE-anomaly triage of a dumped region — packed/injected payload identity | Windows/Linux |
| RAM image — feature carve | `bulk_extractor` | Emails/URLs/IPs and `net`/`pcap` packet residue carved straight from the raw image, file-system-independent | all |
| RAM image — raw strings | `srch_strings`, `bstrings` | C2 domains, command fragments, credential strings spilled in unstructured memory | all |
| `pagefile.sys` / swap (companion disk) | `page-brute` | In-memory pages that were swapped to disk — IOC discovery when the region isn't in the RAM image anymore | Windows/Linux |
| Companion disk `$MFT` / registry | `MFTECmd`, `RECmd`, `rip.pl` | Whether a memory-only process/path/persistence ALSO exists on disk — the two-source corroboration | Windows |
| Companion disk super-timeline | `log2timeline.py` + `psort.py` | Fuses in-image process-create times with on-disk create/exec times into one chronology | all |
| Linux/macOS RAM image | `vol` (`linux.*` / `mac.*`) | Same questions on *nix — BUT each needs a matching ISF symbol pack (0 bundled) — see the Linux branch and `⚠️verify` | Linux/macOS |

*Volatility 3 `linux.*`/`mac.*` plugins need a per-kernel ISF symbol pack and ZERO are bundled on this box — gate those steps and `⚠️verify` before relying on them. `aeskeyfind`/`rsakeyfind` (disk/crypto-key recovery from RAM) are NOT installed here — mentioned only as where-to-look, `⚠️verify`.*

## Step 0 — evidence inventory & access bootstrap
- n: 0
  tool: |
    mkdir -p "#{case_out}/receipts" "#{case_out}/extracted" && ls -laR "#{case_out}/.." > "#{case_out}/receipts/00.txt" 2>&1 ; file "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; vol -f "#{image_path}" windows.info >> "#{case_out}/receipts/00.txt" 2>&1 ; ls -laR "#{mount_root}" >> "#{case_out}/receipts/00.txt" 2>&1 ; mmls "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1
  expect: every evidence file classified (memory image vs disk image vs pcap vs logs); #{image_path} bound to the RAM image; #{mount_root}/#{ntfs_offset_sectors} bound if a companion disk image exists; vol windows.info names the OS/build/profile so later plugins resolve symbols; read access to the image proven
  check: |
    test -s "#{image_path}" && grep -qiE "Kernel Base|NtBuildLab|Is64Bit|major|Suggested Profile|symbol" "#{case_out}/receipts/00.txt"
  falsify: evidence dir empty/unreadable, OR no memory image present, OR vol windows.info errors with no symbols (wrong/corrupt image, or a Linux/macOS image whose ISF pack is absent)
  on_result: {expect_met: goto 1, falsify_met: STOP — report acquisition/access failure; if the image is Linux/macOS go to the Linux branch; pivot acquisition-custody, neither: try vol windows.kdbgscan / banners.Banners to recover the profile; if the image is not Windows go to the Linux branch}
  emits: [key_artifacts]
  serves: [hidden-rogue-process-psscan-vs-pslist, process-tree-anomaly-pstree, code-injection-malfind, unlinked-dll-ldrmodules, hooked-ssdt-idt-callbacks, network-residue-netscan, process-command-line-cmdline, registry-in-memory-printkey, credentials-in-lsass, packed-injected-region-yara, kernel-rootkit-modules, handle-anomalies, loaded-dll-list-dlllist, service-persistence-in-memory-svcscan]
  provenance: {receipt_id: 00, artifact: evidence directory listing + vol windows.info, offset_or_row: full listing, literal_cited: image filename + Kernel Base/NtBuildLab line}

## Steps (executable — decision-driven)
- n: 1
  precondition: "os == windows"
  tool: |
    vol -f "#{image_path}" windows.pstree > "#{case_out}/pstree.txt" 2>"#{case_out}/receipts/01.txt" ; cat "#{case_out}/pstree.txt" >> "#{case_out}/receipts/01.txt" ; vol -f "#{image_path}" windows.pslist > "#{case_out}/pslist.txt" 2>>"#{case_out}/receipts/01.txt" ; cat "#{case_out}/pslist.txt" >> "#{case_out}/receipts/01.txt"
  expect: a process tree and list with PID/PPID/create-time — the timeline-first spine; look for an impossible parent (cmd.exe or powershell.exe under a browser, lsass.exe not under wininit.exe) or a process whose create time sits inside #{time_window} and has no legitimate parent
  check: |
    test -s "#{case_out}/pslist.txt" && grep -qiE "PID|PPID|System|wininit" "#{case_out}/receipts/01.txt"
  falsify: the tree is fully expected (every parent legitimate, every binary a known Windows/vendor path) and no process create-time falls in the suspicious window
  on_result: {expect_met: record the suspect PID + parent + create time; goto 2, falsify_met: note a clean process tree; still run step 2 because hiding evades pslist by design, neither: re-run with windows.pslist and windows.pstree separately; if symbols are partial run windows.kdbgscan first then retry}
  emits: [timeline_events, actor_accounts]
  serves: [process-tree-anomaly-pstree]
  provenance: {receipt_id: 01, artifact: RAM image process tree, offset_or_row: pstree.txt row for the suspect PID, literal_cited: the PID + image name + parent on that row}

- n: 2
  precondition: "exists #{case_out}/pslist.txt"
  tool: |
    vol -f "#{image_path}" windows.psscan > "#{case_out}/psscan.txt" 2>"#{case_out}/receipts/02.txt" ; cat "#{case_out}/psscan.txt" >> "#{case_out}/receipts/02.txt" ; awk -F'\t' 'NR>1{print $1}' "#{case_out}/psscan.txt" | sort -u > "#{case_out}/psscan_pids.txt" 2>>"#{case_out}/receipts/02.txt" ; awk -F'\t' 'NR>1{print $1}' "#{case_out}/pslist.txt" | sort -u > "#{case_out}/pslist_pids.txt" 2>>"#{case_out}/receipts/02.txt" ; comm -23 "#{case_out}/psscan_pids.txt" "#{case_out}/pslist_pids.txt" >> "#{case_out}/receipts/02.txt" 2>&1
  expect: psscan carves _EPROCESS structures (incl. unlinked/exited); a PID present in psscan but ABSENT from pslist is a hidden or recently-exited process — a hidden-process finding (substitutes the absent Memory Baseliner diff with a psscan-vs-pslist self-diff plus a known-good name comparison)
  check: |
    test -s "#{case_out}/psscan.txt" && grep -qiE "PID|Offset|ImageFileName" "#{case_out}/receipts/02.txt"
  falsify: psscan and pslist list the same PIDs (no unlinked process), and every psscan-only entry is a normally-exited benign process with a known image name
  on_result: {expect_met: record the hidden PID + offset + image name as a key IOC; goto 3, falsify_met: record no hidden process; continue to injection at goto 3, neither: dump the candidate with windows.dumpfiles or windows.memmap and compare its image name against known-good Windows binaries via hfind/sha256deep; if still unclear hold at inferred}
  emits: [key_iocs, key_artifacts]
  serves: [hidden-rogue-process-psscan-vs-pslist]
  provenance: {receipt_id: 02, artifact: RAM image carved _EPROCESS pool, offset_or_row: psscan.txt row / comm-23 diff line, literal_cited: the psscan-only PID + physical offset + ImageFileName}

- n: 3
  precondition: "os == windows"
  tool: |
    vol -f "#{image_path}" windows.malfind --dump --dump-dir "#{case_out}/extracted" > "#{case_out}/malfind.txt" 2>"#{case_out}/receipts/03.txt" ; cat "#{case_out}/malfind.txt" >> "#{case_out}/receipts/03.txt" ; vol -f "#{image_path}" windows.ldrmodules >> "#{case_out}/receipts/03.txt" 2>&1
  expect: malfind shows executable PRIVATE memory with no mapped file (RWX, an MZ header or shellcode disassembly) inside a process — injected code; ldrmodules shows a DLL present in the VAD but False in InLoad/InInit/InMem — an unlinked/stealth DLL; the dumped region lands in #{case_out}/extracted for scanning
  check: |
    test -s "#{case_out}/malfind.txt" && grep -qiE "Process|Vad|PAGE_EXECUTE|MZ|Disasm|VadS" "#{case_out}/receipts/03.txt"
  falsify: every malfind hit is a known JIT/.NET region in a browser/runtime AND ldrmodules shows all DLLs linked in all three lists — no injection or unlinked module
  on_result: {expect_met: record the injected PID + region base + the dumped file path as IOCs; goto 4, falsify_met: record no injection; if a rogue process was found in step 2 still dump and scan it at goto 4, neither: re-run windows.malfind for the specific suspect PID and windows.vadinfo; treat JIT-looking hits as inferred until step 4 scan resolves them}
  emits: [key_iocs, key_artifacts]
  serves: [code-injection-malfind, unlinked-dll-ldrmodules]
  provenance: {receipt_id: 03, artifact: RAM image VAD / private memory, offset_or_row: malfind.txt region header / ldrmodules row, literal_cited: the PID + VAD base address + protection (and InLoad/InInit/InMem False)}

- n: 4
  precondition: "exists #{case_out}/extracted"
  tool: |
    /opt/page-brute/bin/page-brute -f "#{image_path}" -o "#{case_out}/extracted/pagebrute" > "#{case_out}/receipts/04.txt" 2>&1 ; for f in "#{case_out}/extracted"/*.dmp "#{case_out}/extracted"/*.exe "#{case_out}/extracted"/*.bin ; do test -f "$f" && /opt/pe-scanner/bin/pe-scanner -f "$f" >> "#{case_out}/receipts/04.txt" 2>&1 ; densityscout "$f" >> "#{case_out}/receipts/04.txt" 2>&1 ; done ; clamscan -r "#{case_out}/extracted" >> "#{case_out}/receipts/04.txt" 2>&1
  expect: a python3-yara rule hit from page-brute on the raw image or a dumped region, OR pe-scanner/densityscout flagging a packed/anomalous PE (high entropy, no imports, suspicious sections), OR a clamscan signature match — confirming the dumped region is a real payload, not JIT noise
  check: |
    grep -qiE "match|rule|packed|entropy|density|FOUND|section|anomal" "#{case_out}/receipts/04.txt"
  falsify: no python3-yara rule fires, density is normal (not packed), pe-scanner reports a clean/normal PE, and clamscan finds nothing — the dumped region is benign, reclassify the malfind hit as JIT/noise
  on_result: {expect_met: confirm the region is malicious; record the rule name + sha256 as a key IOC; goto 5, falsify_met: drop the injection theory for this region; pivot malware-analysis-triage only if a separate suspect binary remains, neither: dump a wider region with windows.memmap --dump for the PID and re-scan; if rules are sparse fall back to srch_strings over the dump for C2/credential strings}
  emits: [key_iocs, exfil_or_encryption_facts]
  serves: [packed-injected-region-yara]
  provenance: {receipt_id: 04, artifact: dumped memory region + page-brute scan, offset_or_row: page-brute/pe-scanner match line, literal_cited: the rule name or packer/entropy verdict + the dumped file sha256}

- n: 5
  precondition: "os == windows"
  tool: |
    vol -f "#{image_path}" windows.netscan > "#{case_out}/netscan.txt" 2>"#{case_out}/receipts/05.txt" ; cat "#{case_out}/netscan.txt" >> "#{case_out}/receipts/05.txt" ; bulk_extractor -o "#{case_out}/extracted/bulk" "#{image_path}" >> "#{case_out}/receipts/05.txt" 2>&1
  expect: netscan lists TCP/UDP endpoints carved from memory with the owning PID and foreign IP/port — a connection from the suspect PID (steps 2-4) to an external/unexpected address is C2 or lateral movement; bulk_extractor net/pcap and url features corroborate the same IPs/domains from the raw bytes
  check: |
    test -s "#{case_out}/netscan.txt" && grep -qiE "TCP|UDP|ESTABLISHED|LISTENING|:[0-9]" "#{case_out}/receipts/05.txt"
  falsify: every endpoint is a known-good local/service connection (loopback, expected update/CDN host) with a legitimate owning process; no foreign address tied to the suspect PID
  on_result: {expect_met: record the foreign IP/port + owning PID as a key IOC; goto 6, falsify_met: record no malicious network residue; continue to command line at goto 6, neither: parse bulk_extractor packets.pcap and ip.txt for endpoints netscan missed; widen #{time_window}; pivot network-forensics if a pcap is in evidence}
  emits: [key_iocs, exfil_or_encryption_facts, timeline_events]
  serves: [network-residue-netscan]
  provenance: {receipt_id: 05, artifact: RAM image socket/connection pool, offset_or_row: netscan.txt row for the suspect PID, literal_cited: the foreign IP:port + ESTABLISHED/owner PID string}

- n: 6
  precondition: "os == windows"
  tool: |
    vol -f "#{image_path}" windows.cmdline > "#{case_out}/cmdline.txt" 2>"#{case_out}/receipts/06.txt" ; cat "#{case_out}/cmdline.txt" >> "#{case_out}/receipts/06.txt" ; vol -f "#{image_path}" windows.dlllist >> "#{case_out}/receipts/06.txt" 2>&1
  expect: cmdline gives the exact launch command for the suspect PID — an encoded PowerShell (-enc/-e), a download cradle, a loader path, or a binary running from %TEMP%/\Users\Public\; dlllist shows the full module set so a maliciously-loaded DLL (path in a writable/temp dir) is visible
  check: |
    test -s "#{case_out}/cmdline.txt" && grep -qiE "Process|Args|CommandLine|\\\\|/" "#{case_out}/receipts/06.txt"
  falsify: the suspect PID command line is a normal, expected invocation from a normal path and dlllist shows only signed system/vendor DLLs — execution looks benign
  on_result: {expect_met: record the command line + any temp-path DLL as IOCs; goto 7, falsify_met: record a benign command line; continue to persistence/handles at goto 7, neither: if cmdline is empty for the PID read the PEB via windows.pslist verbose / windows.envars and corroborate from srch_strings over the dumped region}
  emits: [key_iocs, timeline_events]
  serves: [process-command-line-cmdline, loaded-dll-list-dlllist]
  provenance: {receipt_id: 06, artifact: RAM image PEB command line + module list, offset_or_row: cmdline.txt row for the suspect PID, literal_cited: the exact CommandLine string and any temp-path DLL}

- n: 7
  precondition: "os == windows"
  tool: |
    vol -f "#{image_path}" windows.svcscan > "#{case_out}/svcscan.txt" 2>"#{case_out}/receipts/07.txt" ; cat "#{case_out}/svcscan.txt" >> "#{case_out}/receipts/07.txt" ; vol -f "#{image_path}" windows.registry.printkey --key "Microsoft\\Windows\\CurrentVersion\\Run" >> "#{case_out}/receipts/07.txt" 2>&1 ; vol -f "#{image_path}" windows.registry.printkey --key "ControlSet001\\Services" >> "#{case_out}/receipts/07.txt" 2>&1
  expect: svcscan lists services resident in memory (a service whose binary path is in a temp/user dir or that runs the suspect binary = persistence); printkey shows in-memory Run-key/Services values, including persistence written to memory but not yet flushed to the disk hive — registry-in-memory evidence
  check: |
    test -s "#{case_out}/svcscan.txt" && grep -qiE "Service|Name|State|Start|Key|Value|REG_" "#{case_out}/receipts/07.txt"
  falsify: every service and Run-key value is a known-good signed entry pointing at a legitimate path; no persistence references the suspect binary
  on_result: {expect_met: record the service name / Run-key value + ImagePath as a key IOC; goto 8, falsify_met: record no in-memory persistence; continue to handles at goto 8, neither: try alternate printkey keys (RunOnce, Services per-control-set) and corroborate against the disk SOFTWARE/SYSTEM hive via RECmd/rip.pl; pivot windows-registry-persistence}
  emits: [key_iocs, key_artifacts]
  serves: [service-persistence-in-memory-svcscan, registry-in-memory-printkey]
  provenance: {receipt_id: 07, artifact: RAM image service table + in-memory registry, offset_or_row: svcscan.txt row / printkey value, literal_cited: the service Name + binary path or the Run value name + data}

- n: 8
  precondition: "os == windows"
  tool: |
    vol -f "#{image_path}" windows.handles > "#{case_out}/handles.txt" 2>"#{case_out}/receipts/08.txt" ; grep -iE "lsass|Process|Token|Mutant|Event" "#{case_out}/handles.txt" >> "#{case_out}/receipts/08.txt" 2>&1 ; vol -f "#{image_path}" windows.modules >> "#{case_out}/receipts/08.txt" 2>&1 ; vol -f "#{image_path}" windows.ssdt >> "#{case_out}/receipts/08.txt" 2>&1 ; vol -f "#{image_path}" windows.callbacks >> "#{case_out}/receipts/08.txt" 2>&1
  expect: a foreign process holding a Process/Token handle into lsass.exe (credential theft); a named Mutant a malware singleton uses; AND in the kernel layer a module in modules/modscan with no backing driver file or an SSDT/IDT/callback entry pointing outside a signed driver — a kernel rootkit hook
  check: |
    test -s "#{case_out}/handles.txt" && grep -qiE "lsass|Mutant|Module|SSDT|Callback|Driver" "#{case_out}/receipts/08.txt"
  falsify: only wininit-parented processes open lsass, mutants are all standard, every kernel module is a signed Microsoft/vendor driver, and SSDT/callbacks resolve to known drivers — no cred-theft handle and no rootkit hook
  on_result: {expect_met: record the lsass opener PID / hooked module as a key IOC; goto 9, falsify_met: record no handle anomaly and no rootkit; goto 9, neither: cross-check the suspect module against the disk driver path via MFTECmd and known-good hashes (hfind/sha256deep); cap at inferred if the driver cannot be resolved}
  emits: [key_iocs, actor_accounts]
  serves: [handle-anomalies, credentials-in-lsass, kernel-rootkit-modules, hooked-ssdt-idt-callbacks]
  provenance: {receipt_id: 08, artifact: RAM image handle table + kernel module/SSDT/callback tables, offset_or_row: handles.txt lsass row / modules row / ssdt row, literal_cited: the opener PID + lsass handle, or the unbacked module / hooked SSDT entry}

- n: 9
  precondition: "exists #{case_out}/pslist.txt"
  tool: |
    log2timeline.py --status_view none "#{case_out}/mem.plaso" "#{mount_root}" > "#{case_out}/receipts/09.txt" 2>&1 ; psort.py -o l2tcsv "#{case_out}/mem.plaso" > "#{case_out}/super.csv" 2>>"#{case_out}/receipts/09.txt" ; awk -F'\t' 'NR>1{print $1" "$2" CREATE"}' "#{case_out}/pslist.txt" >> "#{case_out}/super.csv" 2>>"#{case_out}/receipts/09.txt" ; test -f "#{mount_root}/pagefile.sys" && /opt/page-brute/bin/page-brute -f "#{mount_root}/pagefile.sys" -o "#{case_out}/extracted/pf" >> "#{case_out}/receipts/09.txt" 2>&1
  expect: the in-image process-create times plus the companion-disk super-timeline place entry (process spawn) before action (injection/network/persistence) in a coherent order inside #{time_window}; the suspect path/IP/persistence ALSO appears on disk ($MFT create time, registry hive) or in the pagefile spill — the two-source corroboration that promotes the finding to confirmed
  check: |
    test -s "#{case_out}/super.csv" || test -s "#{case_out}/receipts/09.txt"
  falsify: the ordering is impossible (action precedes process spawn — clock/anti-forensics) OR the memory finding appears in NO second source (no disk $MFT/registry/pagefile trace) — hold at inferred, single-source
  on_result: {expect_met: COMMIT the conclusion with a confidence label; close per the gate, falsify_met: keep the finding at inferred; the disagreement may be a memory-only fileless implant — record that explicitly and re-open the Theories table, neither: if no disk image is present state the single-source limit; corroborate what you can from the pagefile/bulk_extractor and label inferred}
  emits: [timeline_events, key_artifacts]
  serves: [hidden-rogue-process-psscan-vs-pslist, code-injection-malfind, network-residue-netscan]
  provenance: {receipt_id: 09, artifact: fused process-create + disk super-timeline + pagefile spill, offset_or_row: super.csv ordered rows, literal_cited: the ordered spawn to injection to network chain and the matching disk/pagefile row}

## Linux branch (L1..Ln) — REQUIRED, numbered, same step shape
- n: L1
  precondition: "os == linux"
  tool: |
    file "#{image_path}" > "#{case_out}/receipts/L01.txt" 2>&1 ; vol -f "#{image_path}" banners.Banners >> "#{case_out}/receipts/L01.txt" 2>&1 ; ls /opt/volatility3/volatility3/symbols/linux >> "#{case_out}/receipts/L01.txt" 2>&1 ; ls /opt/volatility3/symbols/linux >> "#{case_out}/receipts/L01.txt" 2>&1
  expect: this is a Linux RAM image (a LiME/.lime/.raw with Linux kernel banners); banners.Banners recovers the exact kernel version string — BUT Volatility3 linux.* needs a matching ISF symbol pack and ZERO are bundled on this box, so record the precondition gate (Linux-image-only because the kernel banner identifies Linux) before any linux.* plugin
  check: |
    grep -qiE "Linux version|banner|\\.json\\.xz|\\.json|ELF|LiME" "#{case_out}/receipts/L01.txt"
  falsify: banners.Banners finds a Windows/macOS image (no Linux kernel banner) — this is not a Linux memory image; return to Step 0 and run the Windows branch (or the macOS notes)
  on_result: {expect_met: goto L2, falsify_met: not a Linux image — run the Windows Steps 1-9, neither: confirm the image type from the Step 0 file/windows.info receipt; if still ambiguous treat as Windows and run the main branch}
  emits: [key_artifacts]
  serves: [kernel-rootkit-modules, hidden-rogue-process-psscan-vs-pslist]
  provenance: {receipt_id: L01, artifact: Linux RAM image kernel banner + symbol-pack listing, offset_or_row: banners.Banners output + symbols dir listing, literal_cited: the Linux kernel version banner string (and whether a matching ISF .json is present)}

- n: L2
  precondition: "os == linux"
  tool: |
    vol -f "#{image_path}" linux.pslist.PsList > "#{case_out}/linux_pslist.txt" 2>"#{case_out}/receipts/L02.txt" ; cat "#{case_out}/linux_pslist.txt" >> "#{case_out}/receipts/L02.txt" ; vol -f "#{image_path}" linux.pstree.PsTree >> "#{case_out}/receipts/L02.txt" 2>&1 ; vol -f "#{image_path}" linux.malfind.Malfind >> "#{case_out}/receipts/L02.txt" 2>&1 ; vol -f "#{image_path}" linux.check_syscall.Check_syscall >> "#{case_out}/receipts/L02.txt" 2>&1 ; bulk_extractor -o "#{case_out}/extracted/linbulk" "#{image_path}" >> "#{case_out}/receipts/L02.txt" 2>&1
  expect: with a matching ISF pack, linux.pslist/pstree show rogue/orphaned processes, linux.malfind shows injected executable mappings, and linux.check_syscall reveals a hooked syscall table (kernel rootkit); bulk_extractor carves C2 IPs/URLs from the raw image even when no symbol pack exists — so net residue is still recoverable
  check: |
    grep -qiE "PID|COMM|Offset|TASK|syscall|http|[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+" "#{case_out}/receipts/L02.txt"
  falsify: linux.* plugins all error with no symbols (no ISF pack built — expected on this box) AND bulk_extractor finds no network/IOC features — Linux memory parsing is gated and nothing carved
  on_result: {expect_met: record the rogue process / hooked syscall / carved C2 IP; commit with a confidence label, falsify_met: record the ISF symbol-pack gap as a finding; rely on bulk_extractor/srch_strings carving and pivot linux-host-forensics for on-disk corroboration, neither: build the ISF pack off-box (dwarf2json + matching debug kernel) and re-run; until then label findings inferred and use the carve}
  emits: [key_iocs, timeline_events]
  serves: [hidden-rogue-process-psscan-vs-pslist, code-injection-malfind, kernel-rootkit-modules, network-residue-netscan]
  provenance: {receipt_id: L02, artifact: Linux RAM image process/syscall tables + bulk_extractor carve, offset_or_row: linux_pslist.txt row / check_syscall row / bulk url.txt line, literal_cited: the rogue COMM+PID or hooked syscall entry or carved C2 IP}

## Corroboration (two-source rule)
`required_sources: 2` · `pairs:`
- `[ psscan-only hidden process (step 2) ↔ disk $MFT / known-good name comparison via hfind-sha256deep (step 9) ]`
- `[ malfind injected region (step 3) ↔ page-brute/pe-scanner YARA-rule or packer verdict on the dump (step 4) ]`
- `[ netscan foreign endpoint (step 5) ↔ bulk_extractor net/pcap feature for the same IP (step 5) ]`
- `[ cmdline loader/encoded command (step 6) ↔ srch_strings over the dumped region / disk execution trace (step 4/9) ]`
- `[ svcscan/printkey in-memory persistence (step 7) ↔ disk SOFTWARE/SYSTEM hive via RECmd/rip.pl (step 9) ]`
- `[ lsass-handle / rootkit module (step 8) ↔ disk driver path + known-good hash (step 8/9) ]`
- `[ in-image process-create time (step 1/9) ↔ disk $MFT create time / pagefile spill (step 9) ]`

One hit is a *lead*; promote to *fact* only when its paired source agrees.

## Don't get fooled (red flags & anti-forensics)
- **`malfind` is noisy.** .NET, Java, browser JIT and some legitimate security products create RWX private pages that look injected. A `malfind` hit is a *lead* — confirm with a YARA-rule (python3-yara via page-brute) hit, a real MZ/shellcode, or a packer verdict before calling it injection.
- **`pslist` lies; `psscan` is the check.** A rootkit unlinks the process from the active list, so `pslist` looks clean. Always run `psscan` and diff — but remember a `psscan`-only entry can also be a normally-exited process, so confirm the image name and look for the unlink, not just the absence.
- **No Memory Baseliner on this box.** There is no automated known-good baseline-diff tool here — substitute the `psscan`-vs-`pslist` self-diff plus a known-good image-name/hash comparison (`hfind`/`sha256deep` against an NSRL/known set). Do NOT claim a baseline diff that was not run.
- **A RAM image is one instant.** It captures the moment of acquisition only — a connection that closed or a process that exited seconds earlier may survive only as a carved (`psscan`/`netscan`) remnant or in the pagefile. Absence in `pslist` is not absence in history.
- **Smear / inconsistent capture.** Memory acquired on a live, busy system is not atomic — structures can be half-updated, so a single odd field is not proof. Corroborate across plugins (a hidden process should also show in handles/netscan/cmdline) before committing.
- **Kernel hooks can be legitimate.** EDR and some drivers hook the SSDT/callbacks too. Resolve every hook/module to its owning driver and signer before calling it a rootkit. **Missing evidence (an unbacked module, a gap) is itself a finding.**
- **Timestomp/clock tricks poison process-create times.** If the in-image timeline is internally impossible, anchor to plugin cross-agreement and the disk `$MFT`/`$UsnJrnl` order rather than the lone create time.
- **Linux/macOS without a symbol pack = no structured output.** A `linux.*`/`mac.*` plugin that returns nothing because the ISF pack is missing is NOT a clean result — record the gate, fall back to `bulk_extractor`/`srch_strings` carving, and label inferred.

## Failure modes
```
- mode: evidence-access failure — the memory image is unreadable, truncated, or no image is present
  guard: Step 0 proves read access and runs vol windows.info; if the image is corrupt/truncated try windows.kdbgscan/banners.Banners; if no memory image exists record the absence and pivot acquisition-custody
- mode: primary-artifact-absent — vol cannot resolve symbols (wrong/unknown build) so plugins error
  guard: run windows.kdbgscan / banners.Banners to recover the profile/banner; if the image is Linux/macOS go to the Linux branch and gate on the ISF symbol pack; record the absence as a finding and lean on bulk_extractor/srch_strings carving
- mode: tool-output drift — a Volatility3 plugin renames or its column layout changes so a check literal/awk field breaks
  guard: on check exit 2, adjudicate from the prose expect/falsify against the receipt, cap confidence at inferred; re-run the plugin and read the raw receipt, never silently pass
- mode: malfind false positives — JIT/.NET/EDR RWX regions look injected
  guard: never commit on malfind alone; require a page-brute YARA-rule hit, a real MZ/shellcode, a packer/entropy verdict, or a corroborating netscan/handle before calling injection
- mode: Linux/macOS ISF symbol pack absent — linux.*/mac.* return empty
  guard: precondition-gate those steps; an empty result is NOT absence — record the gate, build the ISF off-box, and carve with bulk_extractor/srch_strings meanwhile
- mode: single-source memory finding — a fileless implant exists only in RAM
  guard: state the single-source limit explicitly, corroborate from the pagefile spill where possible, and label the finding inferred (do not silently promote to confirmed)
```
Minimum set every playbook covers: evidence-access failure (Step 0 fallback chain) · primary-artifact-absent (absence recorded, secondary source named) · tool-output drift (`check` exits 2 → prose adjudication, never silent pass).

## Confidence labeling (observation → inference → conclusion)
- **confirmed:** direct receipt verbatim (e.g. the psscan-only PID, the malfind region) + ≥2 independent sources agree (memory plugin + a YARA-rule/disk/pagefile corroboration) + no unrefuted counter-theory.
- **inferred:** grounded but single-source/interpretive — a memory-only fileless finding with no disk trace, a malfind hit not yet scanned, a Linux/macOS result without an ISF pack, or any `check`-exit-2 adjudication → hedge and tag `⚠️verify`.
- **insufficient_evidence:** precondition unmet (no memory image; symbols unresolved; no companion disk for corroboration) or sources conflict → abstain; state what is missing, do not guess.

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
- **Windows:** fully covered above — Volatility 3 `windows.*` is the richest source: `pslist`/`psscan`/`pstree` for hidden/rogue processes, `malfind`/`ldrmodules` for injection, `modules`/`ssdt`/`callbacks` for rootkits, `netscan` for network residue, `cmdline`/`dlllist`/`svcscan`/`handles`/`registry.printkey` for execution, persistence and credential context.
- **Linux/ESXi:** see the numbered Linux branch (L1–L2). The plugins exist (`linux.pslist`, `linux.pstree`, `linux.malfind`, `linux.check_syscall`, `linux.lsmod`, `linux.netstat`) BUT need a per-kernel ISF symbol pack and **ZERO are bundled** — gate on the pack, build it off-box (`dwarf2json` + the target's debug kernel), and meanwhile carve with `bulk_extractor`/`srch_strings`. `⚠️verify` any structured Linux memory finding before relying on it.
- **macOS:** the same Volatility 3 `mac.*` plugins (`mac.pslist`, `mac.malfind`, `mac.netstat`) exist but face the **identical 0-symbol-pack gate** as Linux — treat as gated/`⚠️verify`, carve from the raw image, and corroborate against on-disk macOS artifacts. Pivot macos-forensics for the disk side.
- **Cloud:** there is rarely a raw RAM image of a managed cloud host; the analog is a VM `.vmem`/snapshot pulled from the hypervisor — treat it as a Windows/Linux image and run the matching branch. Pivot virtualization-mobile for the VM-disk/snapshot handling.

## Real-case notes (non-obvious things to look for)
- **A `psscan`-only process is the classic rootkit tell, but verify the unlink.** DKOM rootkits unlink `_EPROCESS` from the active list so `pslist` is clean while `psscan` (pool-tag carve) still finds it; a `psscan`-only entry that is NOT a normally-exited benign process, especially with a masqueraded name (`scvhost.exe`, `lsass.exe` with the wrong parent), is high-signal. `[Volatility documentation / MITRE T1014 · high]`
- **`malfind` plus an empty `ldrmodules` link triad is the injection signature.** Process-hollowing and reflective-DLL injection leave executable private memory (`malfind`) and a module that is in the VAD but unlinked from InLoad/InInit/InMem (`ldrmodules`) — the pair together is far stronger than either alone. `[MITRE T1055.001 / T1055.012 · high]`
- **`netscan` recovers connections the live `netstat` never showed.** Carved socket structures include closed/recent connections and the owning PID, surfacing C2 beacons and lateral SMB/RDP that a point-in-time live tool missed. Correlate the foreign IP back to the injected/hidden PID. `[Volatility netscan documentation / MITRE T1071 · high]`
- **Credential theft shows as a foreign handle into `lsass.exe`.** A non-`wininit`-parented or unexpected process holding a Process/Token handle into `lsass.exe` (or a `lsass` memory dump on disk) is the in-memory tell of credential harvesting that precedes lateral movement. `[MITRE T1003.001 · high]`
- **Kernel hooks are not automatically malicious.** `ssdt`/`callbacks` hooks and extra `modules` entries are also created by EDR/AV/virtualization drivers; always resolve the hook target to its owning driver and signer before calling a rootkit, and compare the module against the on-disk signed driver. `[Volatility malware analysis practice · med]`
- **In-memory persistence can precede the disk hive.** A Run-key/Service value set just before capture may live in the in-memory registry (`printkey`/`svcscan`) but not yet be flushed to the on-disk SOFTWARE/SYSTEM hive — the memory image can show persistence the disk does not. `[Volatility registry-in-memory practice · med]`
- **Disk-encryption / RSA keys can be recovered from RAM, but no tool here does it.** `aeskeyfind`/`rsakeyfind` (the canonical RAM key-recovery tools) are **NOT installed on this box** — note where to look (the key-schedule patterns in the raw image) but do not claim recovery; `⚠️verify` / run off-box. `[general DFIR practice · med]`

## ATT&CK mapping
- T1055 · Defense Evasion / Privilege Escalation · Process Injection · malfind executable private memory — step 3
- T1055.001 · Process Injection · DLL Injection · malfind + ldrmodules unlinked DLL — step 3
- T1055.012 · Process Injection · Process Hollowing · malfind + pstree parent anomaly — steps 1/3
- T1014 · Defense Evasion · Rootkit · psscan-only hidden process / unbacked kernel module — steps 2/8
- T1620 · Defense Evasion · Reflective Code Loading · injected region with no backing file — step 3
- T1003.001 · Credential Access · LSASS Memory · foreign handle into lsass.exe — step 8
- T1071 · Command and Control · Application Layer Protocol · netscan foreign endpoint — step 5
- T1059.001 · Execution · PowerShell · encoded command line in cmdline — step 6
- T1543.003 · Persistence · Windows Service · svcscan in-memory malicious service — step 7
- T1547.001 · Persistence · Run Keys · in-memory printkey Run value — step 7
- T1564 · Defense Evasion · Hide Artifacts · DKOM-unlinked process / unlinked DLL — steps 2/3
- T1547.006 · Persistence · Kernel Modules and Extensions · unbacked driver / Linux check_syscall hook — steps 8/L2

## Pivots (lead-to-lead graph)
- `on_dumped_payload (step 3/4 dumped injected region): malware-analysis-triage — statically and behaviorally triage the extracted binary`
- `on_network_residue (step 5 netscan foreign IP): network-forensics — analyze the C2 channel/beaconing if a pcap is in evidence`
- `on_in_memory_persistence (step 7 svcscan/printkey Run/Service): windows-registry-persistence — confirm the autorun in the on-disk hive`
- `on_lsass_credential_theft (step 8 foreign lsass handle): active-directory-domain — chase the harvested credentials and lateral movement`
- `on_disk_corroboration_needed (step 9 path/persistence on disk): disk-filesystem — pin the create time and on-disk presence of the memory artifact`
- `on_memory_only_fileless (step 9 no disk trace): targeted-intrusion-apt — long-dwell fileless tradecraft needs the broader intrusion hunt`
- `on_full_intrusion_reconstruction (step 9 ordered chain): attack-lifecycle-hunting — fuse memory with disk/logs across the kill chain`
- `on_no_or_unreadable_image (step 0): acquisition-custody — re-acquire or prove the collection gap`
- `on_linux_or_macos_image (step 0 / L1): linux-host-forensics — the on-disk Linux side while the ISF pack is built`
- `on_unresolved_after_memory (step 9): SELF — re-enter with the new IOC (IP/PID-path/hash) bound into #{time_window}`

## Jargon decoder
- **RAM image / memory image:** a byte-for-byte copy of a machine's volatile memory at one instant (`.raw`, `.lime`, `.mem`, `.vmem`, a crash `.dmp`, or `hiberfil.sys`).
- **Volatility 3 (`vol`):** the memory-analysis framework; each `plugin` answers one question (processes, network, injection, drivers…).
- **`pslist` vs `psscan`:** `pslist` walks the OS's live process list (a rootkit can edit it); `psscan` carves process structures from raw memory by pool tag (it still finds hidden/exited ones). A `psscan`-only process is hidden.
- **`pstree`:** the process tree (who launched whom) — an impossible parent/child is a tell.
- **`malfind`:** finds executable PRIVATE memory with no file behind it — the signature of injected code/shellcode.
- **`ldrmodules`:** checks whether a loaded DLL is linked in all three module lists; missing from them = stealth-loaded.
- **VAD (Virtual Address Descriptor):** the OS's map of a process's memory regions; `malfind`/`ldrmodules` read it.
- **RWX / private executable memory:** a region that is readable+writable+executable and not backed by a file — normal code is not RWX; injected code often is.
- **`netscan`:** carves network sockets/connections (with owning PID) from memory, including recently-closed ones.
- **`cmdline`:** the exact command line a process was launched with (from its PEB).
- **`dlllist` / `svcscan` / `handles`:** the loaded modules / the service table / the open handles of processes in memory.
- **`printkey` / `hivelist`:** registry keys/values resident in memory (persistence may be here before it reaches the disk hive).
- **DKOM (Direct Kernel Object Manipulation):** a rootkit technique that edits kernel structures (e.g. unlinks a process) to hide.
- **SSDT / IDT / callbacks:** kernel dispatch/interrupt tables and notification routines; a hook here pointing outside a signed driver is a rootkit sign.
- **`lsass.exe`:** the Windows process that holds credentials in memory — a foreign handle into it = credential theft.
- **ISF symbol pack:** the per-kernel symbol table Volatility 3 needs to parse a Linux/macOS image; none are bundled here, so those plugins are gated.
- **`pagefile.sys` / swap:** disk space the OS uses to spill memory pages — in-memory IOCs can survive here after they leave RAM.
- **page-brute / pe-scanner:** SIFT tools that scan memory pages / dumped PEs using the python3-yara library and entropy/PE heuristics.

## Tuning log (append-only — the eval loop writes here; humans never edit rows)
| date | case_id | bucket missed | delta applied |
|---|---|---|---|
