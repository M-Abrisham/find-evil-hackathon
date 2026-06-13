---
attack_type: network-forensics
category_id: network-forensics
name: Network Forensics
description: PCAP and flow analysis: beaconing, C2 channels, lateral movement and exfiltration over the wire
version: 1
os_coverage: [windows, linux, macos, cloud]
sub_types_covered: 10
sub_types:
  - c2-beaconing-detection-in-flows
  - dns-tunneling
  - plaintext-credential-capture
  - data-exfil-over-the-wire
  - lateral-movement-smb-rdp-in-pcap
  - malware-download-reconstruction
  - tls-metadata-ja3-style-via-ssldump
  - cleartext-c2-protocol-in-payload
  - file-carving-from-pcap
  - passive-os-fingerprinting-of-endpoints
validated_on: []
maturity: draft
variables:
  image_path:
    default: /cases/active/evidence/capture.pcap
    derive: "Step 0 — first network-capture file (pcap/pcapng/cap) enumerated under the evidence directory named in the case brief; if only a disk image is present, the pcap is the one carved/exported from it"
  mount_root:
    default: /cases/active/mount
    derive: "Step 0 — directory where the evidence is staged READ-ONLY (the disk file system mounted, or the directory holding the read-only pcap[s] when there is no disk image)"
  case_out:
    default: /cases/active/out
    derive: "Step 0 — writable case output directory from the case brief; Step 0 creates #{case_out}/receipts/ and #{case_out}/extracted/"
  ntfs_offset_sectors:
    default: 0
    derive: "Step 0 — start sector of the relevant partition from `mmls #{image_path}` IF a disk image is in evidence (to recover host-side network artifacts/pcaps); 0 when the evidence is a standalone capture"
  time_window:
    default: 1970-01-01..2099-12-31
    derive: "case brief if it names one; else the first confirmed-malicious connection time ±48h once a step pins one — then re-scope wide sweeps to it with a tcpdump BPF time/host filter"
---

## In one line
Network forensics reads the recording of what crossed the wire — who talked to whom, on what port, how often, and what was actually said or moved — to prove a malware check-in (beacon), a remote-control channel (C2), an account hopping between machines, or data being stolen.

## Use this when (triggers)
- You have a **packet capture** (`.pcap`/`.pcapng`) or NetFlow/flow export and need to find evil in it.
- An endpoint is suspected of **calling home** on a regular heartbeat (beaconing) — same destination hit at a fixed interval.
- You suspect a **C2 channel**: a long-lived or odd-protocol connection to an external host, or commands/files riding **DNS** (lots of long, unique subdomain lookups = DNS tunneling).
- **Credentials may have crossed in the clear** (FTP/HTTP/Telnet/SMTP/POP/IMAP basic-auth) and you want to capture them.
- You need to prove **data exfiltration over the wire** — a large outbound transfer, an upload to webmail/cloud, or a file carved straight out of the capture.
- **Lateral movement** shows on the wire — SMB (445) / RDP (3389) sessions between internal hosts.
- A host **downloaded a payload** and you want to reconstruct the file from the HTTP stream and hash it.
- You want **TLS metadata** (SNI/cert/cipher, JA3-style handshake shape) on an encrypted channel you cannot decrypt.

## Quick path (the 90% case)
**Box limitation (read first):** this SIFT box has **no full protocol dissector on the CLI** — `wireshark` is GUI-only and `tshark`, `zeek`, `suricata` and `NetworkMiner` are ABSENT. Deep dissection here = `tcpdump` BPF filters + `tcpflow`/`tcpick` stream reassembly + `ngrep` payload search + `nfdump` flows (via `nfpcapd`) + `bulk_extractor`/`tcpxtract` carving + `ssldump` TLS metadata. Plan around that.
1. **Timeline-first.** Convert the capture to flows and build a time-ordered talker/connection list BEFORE committing to a story: `nfpcapd` the pcap into `nfcapd` files, then `nfdump` sorted by time and by bytes. This is the timeline this whole playbook filters — entry → beacon → C2 → exfil ordering is the case. (A full super-timeline still applies at close-gate.)
2. **Find the beacon.** In the `nfdump` output look for one external 5-tuple hit at a **fixed interval** with small, near-constant byte counts — the heartbeat of a beacon. Note the dst IP/port.
3. **Find the channel content.** Reassemble that conversation with `tcpflow` and grep the streams; `ngrep` the pcap for cleartext C2 / creds / known IOCs; for DNS tunneling, `tcpdump` UDP/TCP 53 and look for many long, high-entropy unique subdomains.
4. **Find the exfil / the download.** `tcpxtract` and `bulk_extractor` carve files moved over the wire; reconstruct an HTTP download from the `tcpflow` stream and hash it; a large outbound byte total in `nfdump` is the exfil signal.
5. **Corroborate.** Pair every wire finding with a second source — the `tcpflow` stream content behind a flow row, host-side disk/registry/log artifacts for the same IP/domain/file, or `ssldump` TLS metadata behind an encrypted flow. One flow row is a lead, not a fact.

If a beacon/C2, its content (or TLS metadata), and an exfil/download all line up on the flow timeline with a corroborating second source → you're mostly done. Otherwise drop into the full Steps.

## How it unfolds (the story)
An implant lands on a host and **beacons** out to its controller on a schedule — a small, regular check-in to an external IP or domain (often over 443, or smuggled inside DNS lookups). The operator answers, opening a **C2** channel they use to run commands and stage tooling; sometimes the protocol is cleartext (HTTP, IRC, raw TCP) and the commands are readable, sometimes it is wrapped in TLS and only the metadata (SNI, certificate, cipher/JA3 shape) is visible. From the beachhead they **move laterally** over SMB (445) or RDP (3389) to other internal hosts, and finally **exfiltrate** data — a bulk outbound transfer, an upload to webmail/cloud storage, or files pushed straight over the wire — which shows as a large outbound byte count and as carvable file content inside the capture.

## Theories to test (and how to rule each out)
| Theory (who / why) | If true, you'd find… | Rule it out if… |
|---|---|---|
| **External-targeted (hands-on C2 operator)** | A regular beacon to an external IP/domain, then a longer interactive C2 session (cleartext commands in the stream, or sustained TLS to an odd host); tooling downloaded; data staged and pushed out | No periodic external connection; the only outbound traffic is to known CDNs/update servers on expected ports inside business patterns |
| **External-commodity (off-the-shelf malware / loader)** | Beacon to a known-bad IP/domain (IOC match), a malware download over plain HTTP (carvable EXE/DLL), DNS to a DGA-looking domain | The "beacon" is a software updater/telemetry endpoint with a signed CDN cert and a documented purpose; no payload carved |
| **Other-insider (compromised legit account moving laterally)** | Inbound/outbound SMB(445)/RDP(3389) between internal hosts at odd hours, plaintext or NTLM auth on the wire, the same account hopping host-to-host | The 445/3389 sessions match known admin/backup hosts and hours; no anomalous source and no external leg |
| **Insider (authorized user exfiltrating)** | A large outbound transfer to personal webmail/cloud, files carvable from the upload stream, no external C2 at all | The transfer is to a sanctioned corporate destination during business hours with a change-control/IT record; volume matches normal use |
| **Supply-chain / RMM-channel abuse** | C2 riding a trusted remote-management/updater channel (expected port, expected vendor SNI) but at anomalous frequency or volume, or to a look-alike domain | The channel is the genuine signed vendor endpoint at its normal cadence with a matching host-side agent — benign |
| **Innocent / benign (NOT an attack)** | "Periodic" traffic that is NTP/DNS/OCSP/telemetry/keepalives; "exfil" that is a backup or sync job; plaintext "creds" that are anonymous/public | A clear sanctioned purpose explains the destination, port, cadence AND volume, and the endpoint/cert is expected → benign; reclassify |

*(≥1 benign + ≥1 malicious, each ACTIVELY refuted. Attacker types mapped: insider · other-insider · external-commodity · external-targeted · supply-chain · innocent.)*

## Evidence → Tool → What it reveals (per OS)
| Evidence | SIFT tool | What it tells you *for this attack* | OS |
|---|---|---|---|
| pcap/pcapng capture (any host/port) | `tcpdump -r` (BPF filters) | Which hosts/ports/protocols are present; time/host-bounded slices; packet-level confirmation of a flow | all |
| Capture → NetFlow records | `nfpcapd` (pcap→nfcapd) then `nfdump` | Top talkers, bytes per 5-tuple, and **beacon periodicity** (fixed-interval small check-ins) — the flow timeline | all |
| Per-connection statistics | `tcptrace` | Connection durations, byte counts each way, retransmits — confirms a long-lived C2 vs a one-shot | all |
| TCP conversation reassembly | `tcpflow -r -o` / `tcpick -r` | The actual session content: typed commands, transferred files, **cleartext credentials** | all |
| Payload pattern / IOC search across the capture | `ngrep -I` | Keyword/IOC hits inside packet payloads ("grep for a pcap") — C2 strings, USER/PASS, Host: headers | all |
| DNS traffic | `tcpdump -r` (port 53) + `ngrep -I` | **DNS tunneling**: many long, high-entropy, unique subdomains to one authoritative server; TXT/NULL abuse | all |
| Files moved over the wire | `tcpxtract -f` / `bulk_extractor` (pcap) | Carved files/images/archives (exfil or malware download) reconstructed from payloads; emails/URLs/CCNs features | all |
| HTTP download stream | `tcpflow -r -o` then hash the carved body | Reconstructs the downloaded payload to hash and triage (malware-download-reconstruction) | all |
| TLS/SSL handshakes | `ssldump -r` | SNI/server name, certificate, cipher suite, handshake shape (JA3-style) on channels you cannot decrypt | all |
| Endpoint OS fingerprint | `p0f -r` | What OS/stack each endpoint runs (offline, from SYN/SYN-ACK) — flags an unexpected device | all |
| Raw payload strings (last resort) | `srch_strings` / `bstrings` | Indicators (URLs, IPs, domains, command fragments) when structured parsing fails | all |
| Host-side pcap/net artifacts on a disk image | `fls`/`icat`, `mmls`, `fsstat` | Locate and extract `.pcap`/`.pcapng` (or browser/download history) FROM a disk image when no standalone capture was provided | Windows/Linux/macOS |

*No full L7 dissector is on the CLI here (`tshark`/`zeek`/`suricata`/`NetworkMiner` ABSENT, `wireshark` GUI-only) — every "reveals" above is achieved with the tcpdump/tcpflow/ngrep/nfdump/bulk_extractor/ssldump stack, not a protocol-aware parser. `⚠️verify` any claim that would need deep dissection.*

## Step 0 — evidence inventory & access bootstrap
- n: 0
  tool: |
    mkdir -p "#{case_out}/receipts" "#{case_out}/extracted" && ls -laR "#{mount_root}" > "#{case_out}/receipts/00.txt" 2>&1 ; find "#{mount_root}" -type f \( -iname "*.pcap" -o -iname "*.pcapng" -o -iname "*.cap" \) >> "#{case_out}/receipts/00.txt" 2>&1 ; img_stat "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; mmls "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; fsstat -o #{ntfs_offset_sectors} "#{image_path}" >> "#{case_out}/receipts/00.txt" 2>&1 ; tcpdump -r "#{image_path}" -c 1 -nn >> "#{case_out}/receipts/00.txt" 2>&1
  expect: every evidence file classified; #{image_path}, #{mount_root}, #{case_out} bound and read-only access proven; the capture file(s) are enumerated (or, if only a disk image is present, mmls/fsstat bind #{ntfs_offset_sectors} so a host-side pcap can be extracted), and tcpdump reads at least one packet from the bound capture
  check: |
    test -r "#{image_path}" -o -n "$(find "#{mount_root}" -iname '*.pcap*' 2>/dev/null)" -o -n "$(ls "#{case_out}/extracted" 2>/dev/null)"
  falsify: evidence dir empty/unreadable, no pcap/pcapng/cap present AND no disk image to carve one from, or tcpdump cannot read the file as a capture (wrong/corrupt format)
  on_result: {expect_met: goto 1, falsify_met: STOP — report acquisition/access failure; pivot acquisition-custody, neither: if a disk image is present but no standalone capture, use fls/icat to extract any *.pcap from the file system into #{case_out}/extracted and rebind #{image_path}; if that also fails, treat as falsify_met}
  emits: [key_artifacts]
  serves: [c2-beaconing-detection-in-flows, dns-tunneling, plaintext-credential-capture, data-exfil-over-the-wire, lateral-movement-smb-rdp-in-pcap, malware-download-reconstruction, tls-metadata-ja3-style-via-ssldump, cleartext-c2-protocol-in-payload, file-carving-from-pcap, passive-os-fingerprinting-of-endpoints]
  provenance: {receipt_id: 00, artifact: evidence directory listing + capture enumeration, offset_or_row: full listing, literal_cited: capture filename + first tcpdump packet line}

## Steps (executable — decision-driven)
- n: 1
  precondition: "test -r #{image_path}"
  tool: |
    nfpcapd -r "#{image_path}" -l "#{case_out}/extracted" > "#{case_out}/receipts/01.txt" 2>&1 ; nfdump -R "#{case_out}/extracted" -o long -s record/bytes >> "#{case_out}/receipts/01.txt" 2>&1 ; nfdump -R "#{case_out}/extracted" -s srcip/bytes -s dstip/bytes >> "#{case_out}/receipts/01.txt" 2>&1
  expect: nfcapd flow files written under #{case_out}/extracted and an nfdump table of 5-tuples with byte counts and timestamps — the timeline-first flow view; top-talker and per-destination byte rankings name the external hosts worth chasing
  check: |
    test -s "#{case_out}/receipts/01.txt" && grep -qiE "flows|bytes|Proto|Date first seen" "#{case_out}/receipts/01.txt"
  falsify: nfpcapd produces no flow records (empty or unreadable capture) and tcpdump in Step 0 also read nothing — there is no usable traffic to analyse
  on_result: {expect_met: goto 2, falsify_met: fall back to raw packet read — tcpdump -r -nn -q to list conversations directly; if the capture is truly empty record the absence as a finding and pivot acquisition-custody, neither: re-run nfdump with -o extended on the nfcapd dir; if nfpcapd is unavailable derive talkers from tcpdump -nn -q host/port counts instead}
  emits: [timeline_events, key_artifacts]
  serves: [c2-beaconing-detection-in-flows, data-exfil-over-the-wire, lateral-movement-smb-rdp-in-pcap]
  provenance: {receipt_id: 01, artifact: NetFlow records from the capture, offset_or_row: nfdump top-talker rows, literal_cited: dstip + byte-count + first-seen timestamp row}

- n: 2
  precondition: "exists #{case_out}/receipts/01.txt"
  tool: |
    nfdump -R "#{case_out}/extracted" -o "fmt:%ts %td %sa %da %dp %pr %pkt %byt" -s dstip/flows > "#{case_out}/receipts/02.txt" 2>&1 ; nfdump -R "#{case_out}/extracted" -o "fmt:%ts %sa %da %dp %byt" "not net 10.0.0.0/8 and not net 172.16.0.0/12 and not net 192.168.0.0/16" >> "#{case_out}/receipts/02.txt" 2>&1
  expect: one external destination 5-tuple hit at a near-fixed inter-arrival interval with small, near-constant byte/packet counts — a beacon heartbeat; the regular cadence (not the volume) is the tell, visible by sorting the external-only flows by destination and time
  check: |
    grep -qE "([0-9]{1,3}\.){3}[0-9]{1,3}" "#{case_out}/receipts/02.txt"
  falsify: no external destination is contacted repeatedly at a regular interval — every external flow is one-shot or matches a known CDN/update/NTP/OCSP endpoint with a documented purpose (benign-periodic)
  on_result: {expect_met: record the beacon dst IP/port + interval as IOCs; goto 3, falsify_met: record "no beacon periodicity in flows"; pursue exfil (step 6) and lateral movement (step 7) instead, neither: widen #{time_window}; compute inter-arrival deltas per dst with tcptrace per-connection stats and re-judge; an updater can mimic a beacon — verify the cert/SNI in step 8 before clearing}
  emits: [key_iocs, timeline_events]
  serves: [c2-beaconing-detection-in-flows]
  provenance: {receipt_id: 02, artifact: NetFlow per-destination flow table, offset_or_row: repeating dstip rows with even timestamp spacing, literal_cited: dstip:dport + the recurring inter-arrival interval}

- n: 3
  precondition: "exists #{case_out}/receipts/01.txt"
  tool: |
    tcpdump -r "#{image_path}" -nn -c 2000 'udp port 53 or tcp port 53' > "#{case_out}/receipts/03.txt" 2>&1 ; ngrep -I "#{image_path}" -W byline -q '' 'port 53' 2>>"#{case_out}/receipts/03.txt" | grep -aoE "[A-Za-z0-9._-]+" | awk '{ if (length($0) > 40) print }' >> "#{case_out}/receipts/03.txt" 2>&1
  expect: DNS tunneling — many long (>40 char), high-entropy, UNIQUE subdomain labels all under one parent/authoritative domain, and/or heavy TXT/NULL/CNAME query volume to a single server; the volume and label length, not normal A-record lookups, are the tell
  check: |
    grep -qaE "[A-Za-z0-9]{40,}" "#{case_out}/receipts/03.txt"
  falsify: DNS is ordinary — short cacheable A/AAAA lookups to normal resolvers/CDNs, low query rate, no long random labels and no abnormal TXT/NULL volume
  on_result: {expect_met: record the tunneling parent domain + resolver as IOCs; goto 4, falsify_met: record "no DNS tunneling"; continue to cleartext C2 at goto 4, neither: extract just the QNAME field with ngrep -W byline and measure label length/uniqueness distribution; widen #{time_window}; some CDNs use long hashed labels — verify uniqueness rate before concluding}
  emits: [key_iocs, timeline_events]
  serves: [dns-tunneling]
  provenance: {receipt_id: 03, artifact: DNS packets in the capture, offset_or_row: tcpdump/ngrep QNAME lines, literal_cited: the long high-entropy subdomain string + parent domain}

- n: 4
  precondition: "exists #{case_out}/receipts/01.txt"
  tool: |
    mkdir -p "#{case_out}/extracted/flows" && tcpflow -r "#{image_path}" -o "#{case_out}/extracted/flows" > "#{case_out}/receipts/04.txt" 2>&1 ; ngrep -I "#{image_path}" -W byline -q -i 'IEX|powershell|cmd.exe|/bin/sh|whoami|NICK |JOIN |PRIVMSG|User-Agent|cobalt|meterpreter' 'tcp' >> "#{case_out}/receipts/04.txt" 2>&1
  expect: a cleartext C2 protocol in the reassembled streams or ngrep payload hits — readable commands (whoami, powershell/cmd, shell), an IRC/HTTP control channel, an odd/empty User-Agent, or a known framework string — on the same dst found in step 2
  check: |
    grep -qaiE "powershell|cmd\.exe|/bin/sh|whoami|PRIVMSG|User-Agent|meterpreter|cobalt" "#{case_out}/receipts/04.txt"
  falsify: the channel carries no readable commands — it is fully encrypted (TLS) or the protocol is opaque; cleartext C2 is not evidenced (move to TLS metadata in step 8)
  on_result: {expect_met: record the C2 command strings + dst as IOCs; goto 5, falsify_met: the channel is likely encrypted — characterise it via ssldump in step 8; goto 5, neither: grep the per-flow files under #{case_out}/extracted/flows directly for the beacon dst's port; widen the ngrep pattern; pivot malware-analysis-triage if a payload string appears}
  emits: [key_iocs, timeline_events]
  serves: [cleartext-c2-protocol-in-payload]
  provenance: {receipt_id: 04, artifact: reassembled TCP streams (tcpflow) + ngrep payload hits, offset_or_row: the matching stream file / ngrep line, literal_cited: the readable C2 command or control-protocol string}

- n: 5
  precondition: "exists #{case_out}/receipts/01.txt"
  tool: |
    ngrep -I "#{image_path}" -W byline -q -i 'USER |PASS |AUTH LOGIN|Authorization: Basic|password=|pwd=|LOGIN ' 'tcp port 21 or tcp port 23 or tcp port 25 or tcp port 80 or tcp port 110 or tcp port 143' > "#{case_out}/receipts/05.txt" 2>&1 ; grep -aiERl "USER |PASS |Authorization: Basic" "#{case_out}/extracted/flows" >> "#{case_out}/receipts/05.txt" 2>&1
  expect: plaintext credentials on the wire — FTP USER/PASS (21), Telnet (23), SMTP/POP/IMAP AUTH LOGIN (25/110/143), or HTTP Basic "Authorization: Basic <base64>" / form password= fields (80) — captured verbatim or as a base64 blob to decode
  check: |
    grep -qaiE "USER |PASS |Authorization: Basic|password=|AUTH LOGIN" "#{case_out}/receipts/05.txt"
  falsify: no cleartext auth — all login traffic is over TLS (443/465/993/995) so credentials never appear in the clear; nothing to capture here
  on_result: {expect_met: record the captured account(s) as actor_accounts (note base64 needs decoding); goto 6, falsify_met: record "no plaintext credentials (auth was encrypted)"; goto 6, neither: reassemble the specific auth flow with tcpflow and read the stream file directly; check non-standard ports for the same patterns}
  emits: [actor_accounts, key_iocs]
  serves: [plaintext-credential-capture]
  provenance: {receipt_id: 05, artifact: cleartext auth packets / reassembled flow, offset_or_row: ngrep USER/PASS/Authorization line, literal_cited: the username + password (or base64 Authorization string)}

- n: 6
  precondition: "exists #{case_out}/receipts/01.txt"
  tool: |
    bulk_extractor -o "#{case_out}/extracted/be" "#{image_path}" > "#{case_out}/receipts/06.txt" 2>&1 ; tcpxtract -f "#{image_path}" -o "#{case_out}/extracted/carve" >> "#{case_out}/receipts/06.txt" 2>&1 ; nfdump -R "#{case_out}/extracted" -o "fmt:%ts %sa %da %dp %byt" -A srcip -O bytes "not net 10.0.0.0/8 and not net 172.16.0.0/12 and not net 192.168.0.0/16" >> "#{case_out}/receipts/06.txt" 2>&1
  expect: data exfil / malware download — bulk_extractor/tcpxtract carve file content (EXE/DLL/ZIP/images/office docs) out of the payloads AND nfdump shows a large outbound byte total from an internal src to one external dst; carved bodies can be hashed and triaged
  check: |
    test -n "$(ls "#{case_out}/extracted/be" 2>/dev/null)" -o -n "$(ls "#{case_out}/extracted/carve" 2>/dev/null)"
  falsify: no files carve out and no outbound transfer stands above normal volume — neither an exfil push nor a payload download is evidenced in this capture
  on_result: {expect_met: record carved file paths/hashes + the exfil 5-tuple+byte total as IOCs/exfil facts; goto 7, falsify_met: record "no carvable transfer / no bulk outbound"; goto 7, neither: reconstruct the suspect HTTP transfer from the tcpflow stream (step 4 dir) and hash the body manually; check chunked/segmented transfers a signature-carver misses}
  emits: [exfil_or_encryption_facts, key_iocs]
  serves: [data-exfil-over-the-wire, malware-download-reconstruction, file-carving-from-pcap]
  provenance: {receipt_id: 06, artifact: carved files (bulk_extractor/tcpxtract) + outbound flow totals, offset_or_row: carved file feature line / nfdump outbound byte row, literal_cited: carved filename+hash or the src→dst byte total}

- n: 7
  precondition: "exists #{case_out}/receipts/01.txt"
  tool: |
    nfdump -R "#{case_out}/extracted" -o "fmt:%ts %td %sa %da %dp %pr %byt" "port 445 or port 3389 or port 139 or port 5985 or port 5986" > "#{case_out}/receipts/07.txt" 2>&1 ; ngrep -I "#{image_path}" -W byline -q -i 'SMB|NTLMSSP|\\\\IPC\\$|ADMIN\\$|rdp' 'tcp port 445 or tcp port 3389 or tcp port 139' >> "#{case_out}/receipts/07.txt" 2>&1
  expect: lateral movement on the wire — SMB(445/139), RDP(3389), or WinRM(5985/5986) sessions between INTERNAL hosts, with SMB tree-connects to ADMIN$/IPC$ or NTLMSSP auth and/or RDP setup; an internal-to-internal admin-share/remote-desktop session at an odd hour is the breadcrumb
  check: |
    grep -qaiE "445|3389|139|5985|SMB|NTLMSSP|ADMIN\\\$|IPC\\\$" "#{case_out}/receipts/07.txt"
  falsify: no internal-to-internal 445/3389/5985 sessions — or the only such sessions are known admin/backup hosts at expected times; no lateral movement evidenced
  on_result: {expect_met: record the src/dst host pair + share/protocol as IOCs; goto 8, falsify_met: record "no lateral movement in capture"; goto 8, neither: reassemble the SMB/RDP flow with tcpflow to read the tree-connect/auth; correlate host-side with the event-log/AD playbooks; pivot active-directory-domain if NTLM/Kerberos auth is on the wire}
  emits: [key_iocs, timeline_events]
  serves: [lateral-movement-smb-rdp-in-pcap]
  provenance: {receipt_id: 07, artifact: SMB/RDP/WinRM flows + payloads, offset_or_row: nfdump 445/3389 rows / ngrep SMB-tree line, literal_cited: src→dst host pair + the share name or NTLMSSP/RDP marker}

- n: 8
  precondition: "exists #{case_out}/receipts/01.txt"
  tool: |
    ssldump -r "#{image_path}" -n > "#{case_out}/receipts/08.txt" 2>&1 ; p0f -r "#{image_path}" -o "#{case_out}/extracted/p0f.log" >> "#{case_out}/receipts/08.txt" 2>&1
  expect: TLS metadata + endpoint fingerprints for any channel you cannot decrypt — ssldump yields the ServerName(SNI)/certificate subject+issuer/cipher and the handshake shape (a JA3-style signature), and p0f names each endpoint's OS/stack; a self-signed/odd cert or a rare handshake on the beacon dst is high-signal
  check: |
    grep -qiE "ServerHello|ClientHello|Certificate|cipher|Version" "#{case_out}/receipts/08.txt"
  falsify: there is no TLS in the capture (everything was cleartext, already handled) OR ssldump reports only ordinary handshakes to expected, well-known signed endpoints — no anomalous encrypted channel
  on_result: {expect_met: record SNI/cert/cipher (JA3-style) for the beacon/C2 dst as IOCs; goto 9, falsify_met: record "TLS metadata ordinary / no TLS present"; goto 9, neither: re-run ssldump on a host/port-filtered slice (tcpdump -w a sub-pcap of the beacon dst first); a benign updater also uses TLS — match SNI+cert against the vendor before clearing; ⚠️verify any JA3-style claim by hand}
  emits: [key_iocs, key_artifacts]
  serves: [tls-metadata-ja3-style-via-ssldump, passive-os-fingerprinting-of-endpoints]
  provenance: {receipt_id: 08, artifact: TLS handshakes (ssldump) + p0f fingerprints, offset_or_row: ssldump ServerHello/Certificate lines / p0f host line, literal_cited: the SNI + certificate subject/issuer + cipher suite}

- n: 9
  precondition: "exists #{case_out}/receipts/01.txt"
  tool: |
    nfdump -R "#{case_out}/extracted" -o "fmt:%ts %td %sa %da %dp %pr %byt" -O tstart > "#{case_out}/super.csv" 2>"#{case_out}/receipts/09.txt" ; tcptrace -l "#{image_path}" >> "#{case_out}/receipts/09.txt" 2>&1
  expect: a fused chronological flow timeline (nfdump sorted by start time, plus tcptrace per-connection durations/bytes) that places beacon → C2/content → lateral movement → exfil/download in a coherent order inside #{time_window} with no unexplained gap, anchoring the committed story
  check: |
    test -s "#{case_out}/super.csv" && grep -qE "([0-9]{1,3}\.){3}[0-9]{1,3}" "#{case_out}/super.csv"
  falsify: the ordering is impossible (e.g. exfil before any inbound/beacon connection) OR an unexplained capture gap that no rollover/rotation accounts for — the capture may be partial or the clock unreliable
  on_result: {expect_met: COMMIT the conclusion with a confidence label; close per the gate, falsify_met: re-open the Theories table; a gap may mean a truncated capture or rotated pcap not collected — anchor to flow start-times and tcptrace sequence, pivot acquisition-custody for the missing segment, neither: re-render nfdump filtered to #{time_window}; confirm tcptrace parsed connections; if the capture spans rotated files, merge them and re-sort}
  emits: [timeline_events]
  serves: [c2-beaconing-detection-in-flows, data-exfil-over-the-wire, lateral-movement-smb-rdp-in-pcap]
  provenance: {receipt_id: 09, artifact: fused flow timeline (nfdump) + tcptrace stats, offset_or_row: super.csv ordered rows, literal_cited: ordered beacon→C2→lateral→exfil chain}

## Linux branch (L1..Ln) — REQUIRED, numbered, same step shape
- n: L1
  precondition: "os == linux"
  tool: |
    tcpdump -r "#{image_path}" -c 1 -nn > "#{case_out}/receipts/L01.txt" 2>&1 ; fsstat -o #{ntfs_offset_sectors} "#{image_path}" >> "#{case_out}/receipts/L01.txt" 2>&1 ; find "#{mount_root}" -type f \( -iname "*.pcap" -o -iname "*.pcapng" \) 2>/dev/null >> "#{case_out}/receipts/L01.txt" 2>&1
  expect: network forensics is OS-agnostic at the wire — the SAME tcpdump/tcpflow/ngrep/nfdump/ssldump stack runs whether the capture came from a Windows, Linux or macOS host; this step confirms the evidence reads as a capture (or, on a Linux disk image, locates host-side pcaps under /var or a user dir) so the main Steps 1–9 apply unchanged
  check: |
    grep -qaiE "IP |IP6 |ARP|tcp|udp|ethertype" "#{case_out}/receipts/L01.txt" || test -n "$(grep -aiE '\.pcap' "#{case_out}/receipts/L01.txt" 2>/dev/null)"
  falsify: tcpdump cannot read #{image_path} as a capture AND no host-side pcap is found on the file system — there is no network evidence to analyse on this Linux source
  on_result: {expect_met: run the main Steps 1–9 against the bound capture (the analysis is identical across OSes), falsify_met: no capture present — pivot linux-host-forensics for host-side connection logs (syslog/journal, /var/log, ss/netstat state) instead, neither: carve a pcap from unallocated with bulk_extractor (it accepts disk images) and re-bind #{image_path}; if none surfaces treat as falsify_met}
  emits: [key_artifacts]
  serves: [c2-beaconing-detection-in-flows, data-exfil-over-the-wire]
  provenance: {receipt_id: L01, artifact: capture readability + host-side pcap search, offset_or_row: first tcpdump packet line / pcap path, literal_cited: "the first packet line or the located .pcap path (capture-confirmed, OS-agnostic)"}

- n: L2
  precondition: "os == linux"
  tool: |
    ngrep -I "#{image_path}" -W byline -q -i 'Accepted|Failed password|sshd|sudo|wget |curl |nc ' 'tcp' > "#{case_out}/receipts/L02.txt" 2>&1 ; nfdump -R "#{case_out}/extracted" -o "fmt:%ts %sa %da %dp %byt" "port 22" >> "#{case_out}/receipts/L02.txt" 2>&1
  expect: Linux-typical wire artifacts — SSH (22) sessions to/from the host (the lateral-movement and remote-access analog), and cleartext download cradles (wget/curl/nc) pulling a payload — correlated with the flow timeline inside #{time_window}; SSH content is encrypted so judge it from flows/metadata, but the fetch cradles and any cleartext service auth are readable
  check: |
    grep -qaiE "wget |curl |nc |port 22|:22 |sshd|Accepted" "#{case_out}/receipts/L02.txt"
  falsify: no SSH flows and no cleartext fetch cradles on the wire — the Linux host shows no remote-access or download activity in this capture
  on_result: {expect_met: record the SSH peer/download URL as IOCs; fold into the main timeline (step 9) and commit with a confidence label, falsify_met: record "no SSH/download activity on the wire"; rely on the main Steps 1-9 beacon/exfil findings, neither: reassemble port-22/80 flows with tcpflow; SSH payload is opaque so pivot linux-host-forensics for the host-side auth.log/journal to confirm the session}
  emits: [actor_accounts, key_iocs, timeline_events]
  serves: [lateral-movement-smb-rdp-in-pcap, malware-download-reconstruction]
  provenance: {receipt_id: L02, artifact: SSH/HTTP flows + cleartext cradles, offset_or_row: ngrep cradle line / nfdump port-22 row, literal_cited: the wget/curl URL or the SSH peer 5-tuple}

## Corroboration (two-source rule)
`required_sources: 2` · `pairs:`
- `[ nfdump beacon periodicity (step 2) ↔ tcpflow stream content OR ssldump TLS metadata on that same dst (step 4/8) ]`
- `[ DNS-tunneling long labels (step 3) ↔ the matching flow volume/cadence to that resolver in nfdump (step 1/2) ]`
- `[ ngrep cleartext C2 string (step 4) ↔ the nfdump flow that carried it (step 1/2) ]`
- `[ plaintext credential capture (step 5) ↔ the reassembled auth flow file under #{case_out}/extracted/flows (step 4/5) ]`
- `[ carved exfil file (step 6) ↔ the large outbound byte total in nfdump for the same src→dst (step 6) ]`
- `[ SMB/RDP lateral flow (step 7) ↔ host-side event-log/AD artifact for the same host pair (pivot) ]`
- `[ ssldump SNI/cert (step 8) ↔ the beacon dst IP from nfdump (step 2) ]`
- `[ per-step flow rows ↔ the fused flow timeline order (step 9) ]`

One hit is a *lead*; promote to *fact* only when its paired source agrees.

## Don't get fooled (red flags & anti-forensics)
- **No CLI dissector here — do not claim deep-decode you cannot run.** `wireshark` is GUI-only and `tshark`/`zeek`/`suricata`/`NetworkMiner` are ABSENT. Anything that would need true L7 dissection is `⚠️verify` and must be backed by what `tcpdump`/`tcpflow`/`ngrep`/`nfdump`/`ssldump` actually show.
- **A "beacon" can be a benign updater/telemetry/NTP/OCSP heartbeat.** Regular cadence alone is not evil. Verify the destination, port, cert/SNI (step 8) and a documented purpose before you commit — an EDR/updater check-in looks exactly like a beacon in flows.
- **Encrypted ≠ safe to ignore.** If the C2 stream is TLS you get no cleartext, but the SNI, certificate (self-signed/odd issuer), cipher and JA3-style handshake are still evidence — never write "encrypted, nothing to see."
- **DNS over a CDN can show long labels too.** Long hashed subdomains exist legitimately; the tunneling tell is **high uniqueness + volume + TXT/NULL abuse to one server**, not label length alone. Measure the uniqueness rate before concluding.
- **Carved files lack provenance.** A signature-carver (`tcpxtract`/`bulk_extractor`) recovers bytes but not which flow/direction they came from — tie a carved file back to its `tcpflow` stream and the nfdump 5-tuple before calling it exfil vs download.
- **Private-IP/RFC1918 noise inflates "talkers."** Filter to external (or to the host pair under suspicion) before ranking; internal broadcast/mDNS/ARP is not C2.
- **A truncated or rotated capture is a gap, not an absence.** Missing time = the capture may be partial; treat the gap as a finding and pivot to re-acquire (acquisition-custody), do not read silence as "nothing happened." **Missing evidence is itself a finding.**
- **Capture clock vs host clock.** Pcap timestamps come from the capturing sensor, not the endpoints — if you correlate to host artifacts, account for sensor/endpoint clock skew rather than assuming they agree.

## Failure modes
```
- mode: evidence-access failure — no standalone capture, or the disk image won't mount to reach a host-side pcap
  guard: Step 0 fallback chain — read the capture directly with tcpdump; if only a disk image exists, fls/icat (or bulk_extractor over the image) to extract a *.pcap into #{case_out}/extracted and rebind #{image_path}; if all fail, record acquisition failure and pivot acquisition-custody
- mode: primary-artifact-absent — the capture is empty, truncated, or contains no traffic for the window of interest
  guard: record the absence/gap as a finding (a truncated capture is itself evidence); name the secondary sources (host-side connection logs, browser/download history, the next rotated pcap) and pivot acquisition-custody / linux-host-forensics
- mode: tool-output drift — nfdump format strings or ssldump/ngrep field labels change so a check literal stops matching (exit 2)
  guard: on check exit 2, adjudicate from the prose expect/falsify against the receipt, cap confidence at inferred; re-render nfdump with a simpler -o long, fall back to tcpdump -nn raw read, never silently pass
- mode: no CLI dissector — a finding would need full L7 protocol decode (tshark/zeek/suricata) that this box lacks
  guard: do NOT name an absent tool in a tool: line; reconstruct what you can with tcpflow/ngrep/ssldump, tag the deep-decode claim ⚠️verify, and record the dissection gap explicitly
- mode: fully-encrypted channel — the C2/exfil is TLS so no payload is readable
  guard: pivot to ssldump TLS metadata (SNI/cert/cipher/JA3-style) + nfdump flow shape + p0f; report content as unrecoverable-without-keys, not as absent
- mode: signature-carve miss — a file split/chunked across packets isn't recovered by tcpxtract/bulk_extractor
  guard: reconstruct the transfer from the tcpflow per-flow stream and hash the body manually; note the carver limitation as a finding
```
Minimum set every playbook covers: evidence-access failure (Step 0 fallback chain) · primary-artifact-absent (absence recorded, secondary source named) · tool-output drift (`check` exits 2 → prose adjudication, never silent pass).

## Confidence labeling (observation → inference → conclusion)
- **confirmed:** direct receipt verbatim (e.g. the nfdump beacon rows + the tcpflow stream content or ssldump SNI for the same dst) + ≥2 independent sources agree (flow + payload/metadata, or wire + host-side artifact) + no unrefuted counter-theory.
- **inferred:** grounded but single-source/interpretive — e.g. a regular flow read as a beacon with no payload/cert confirmation yet, a long-label DNS pattern not yet uniqueness-tested, or a JA3-style claim made by hand without a dissector → hedge and tag `⚠️verify`. Every `check`-exit-2 adjudication lands here at best.
- **insufficient_evidence:** precondition unmet (no capture; capture truncated past the window; channel encrypted and no keys) or sources conflict → abstain; state what's missing, do not guess.

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
- **OS-agnostic at the wire:** the capture analysis (Steps 1–9) is identical regardless of which OS generated the traffic — the same `tcpdump`/`tcpflow`/`ngrep`/`nfdump`/`ssldump`/`bulk_extractor` stack applies to Windows, Linux, macOS and cloud captures. What differs is which protocols/ports you weight (SMB/RDP/WinRM on Windows; SSH/scp/rsync on Linux/macOS; API/HTTPS to cloud control planes).
- **Windows hosts:** weight SMB(445/139), RDP(3389), WinRM(5985/5986), NetBIOS, and NTLMSSP/Kerberos on the wire for lateral movement (step 7).
- **Linux/ESXi/macOS hosts:** weight SSH(22), scp/sftp, rsync, and cleartext fetch cradles (wget/curl/nc) — see the numbered Linux branch (L1–L2). SSH payload is encrypted, so judge it from flow shape and pivot host-side for auth confirmation.
- **Cloud:** captured traffic to a cloud control plane is HTTPS — only `ssldump` metadata (SNI to `*.amazonaws.com`/`*.azure.com`/`*.googleapis.com`, cert, cipher) is visible on the wire; the real audit lives in exported control-plane logs. Investigate those off the capture and pivot cloud-iaas-control-plane / cloud-identity-saas.
- **No CLI L7 dissector on any OS here** — `wireshark` GUI-only; `tshark`/`zeek`/`suricata`/`NetworkMiner` absent. `⚠️verify` any conclusion that would require them.

## Real-case notes (non-obvious things to look for)
- **Beacons hide in cadence, not volume.** Many C2 frameworks (Cobalt Strike, common RATs) check in on a fixed sleep interval with tiny, near-constant payloads; the periodicity in `nfdump` flows is the tell, and jitter settings spread the interval — measure inter-arrival deltas, don't expect a perfectly even clock. `[MITRE T1071 / T1573 · high]`
- **DNS tunneling is the firewall bypass of choice.** When direct egress is blocked, implants smuggle C2/data inside DNS queries — long, base32/base64-looking, unique subdomains under one attacker domain, often with TXT/NULL/CNAME answers. High unique-label volume to a single authoritative server is the signature, visible with `tcpdump`/`ngrep` on port 53. `[MITRE T1071.004 / T1048 · high]`
- **Cleartext creds still cross the wire more than expected.** FTP, Telnet, SMTP/POP/IMAP basic auth, and HTTP Basic (`Authorization: Basic <base64>`) hand you usernames and passwords verbatim in `ngrep`/`tcpflow` — always sweep the legacy plaintext ports before assuming everything is TLS. `[MITRE T1040 · high]`
- **Exfil often rides a "normal" service.** Stolen data is pushed to webmail, paste sites, or cloud storage over ordinary 443, or staged as an archive and uploaded — the signal is an anomalous outbound **byte total** to one external dst, plus a carvable archive/file in the payload, not an exotic port. `[MITRE T1567 / T1041 · high]`
- **TLS metadata fingerprints the malware even without decryption.** The handshake shape (a JA3-style client signature), a self-signed or default/placeholder certificate, and an unusual SNI on the beacon destination are strong leads from `ssldump` alone — encrypted does not mean opaque. `⚠️verify` any JA3-style claim computed by hand (no JA3 tool on box). `[MITRE T1573 / Salesforce JA3 concept · med]`
- **A carved file is bytes without a story.** `tcpxtract`/`bulk_extractor` recover content but not the flow or direction; always re-bind a carved EXE/archive to its `tcpflow` stream and the `nfdump` 5-tuple to prove it was a download (inbound) vs an exfil (outbound). `[general network-forensics practice · med]`
- **Trust the sensor clock, not the endpoints.** Pcap timestamps are stamped by the capture point; when you stitch wire events to host artifacts, reconcile sensor-vs-host clock skew rather than assuming a shared clock — and a rotated/truncated capture is a gap to re-acquire, not proof of silence. `⚠️verify any timeline that assumes capture and host clocks agree.` `[general DFIR practice · med]`

## ATT&CK mapping
- T1071.001 · Command and Control · Web Protocols (HTTP/S C2) · cleartext C2 in ngrep/tcpflow or TLS metadata via ssldump — steps 4/8
- T1071.004 · Command and Control · DNS · DNS tunneling long unique subdomains — step 3
- T1573 · Command and Control · Encrypted Channel · TLS handshake/SNI/cert metadata via ssldump — step 8
- T1095 · Command and Control · Non-Application Layer Protocol · raw-TCP/odd-port C2 in flows — steps 2/4
- T1008 · Command and Control · Fallback Channels · multiple beacon destinations / interval changes in flows — step 2
- T1105 · Command and Control · Ingress Tool Transfer · malware download reconstructed/carved from the capture — step 6
- T1040 · Credential Access / Discovery · Network Sniffing · plaintext credential capture on the wire — step 5
- T1021.002 · Lateral Movement · SMB/Windows Admin Shares · 445/139 ADMIN$/IPC$ sessions in pcap — step 7
- T1021.001 · Lateral Movement · Remote Desktop Protocol · 3389 RDP sessions in pcap — step 7
- T1021.006 · Lateral Movement · Windows Remote Management · 5985/5986 WinRM in pcap — step 7
- T1041 · Exfiltration · Exfiltration Over C2 Channel · data pushed out the same C2 dst — step 6
- T1048 · Exfiltration · Exfiltration Over Alternative Protocol · exfil over DNS/cleartext/non-C2 service — steps 3/6
- T1567 · Exfiltration · Exfiltration Over Web Service · upload to webmail/cloud/paste over 443 — step 6
- T1046 · Discovery · Network Service Discovery · scan/sweep patterns (many dst ports/hosts from one src) in flows — steps 1/2

## Pivots (lead-to-lead graph)
- `on_malware_download_or_payload (step 6 carved EXE/DLL/archive): malware-analysis-triage — statically/behaviorally triage the carved payload`
- `on_smb_rdp_winrm_lateral (step 7 internal host pair): active-directory-domain — credential/Kerberos abuse and the domain side of the hop`
- `on_credential_on_the_wire (step 5 USER/PASS/NTLMSSP): active-directory-domain — chase the captured account into the domain`
- `on_ioc_ip_or_domain_found (step 2/3/8 beacon dst / tunneling domain / SNI): SELF — re-enter with the IOC bound into #{time_window} to bracket every session to it`
- `on_host_side_correlation_needed (step 7/8 / Linux L2): windows-event-logs — confirm the same connection in the host's event logs`
- `on_linux_host_correlation_needed (Linux L2 SSH/cradle): linux-host-forensics — confirm the session in auth.log/journal and find host-side persistence`
- `on_cloud_destination (step 8 cloud SNI): cloud-iaas-control-plane — pull the control-plane audit log the wire only hints at`
- `on_exfil_to_webmail_or_cloud (step 6 outbound upload): cloud-identity-saas — investigate the SaaS/webmail account that received the data`
- `on_capture_truncated_or_absent (step 0/1/9 gap): acquisition-custody — re-acquire the missing capture segment / prove the collection gap`
- `on_files_carved_need_recovery (step 6 partial carve): file-recovery-carving — deeper carving/repair of the recovered payload`

## Jargon decoder
- **pcap / pcapng:** the file format that stores a packet capture (a recording of network traffic). `.cap` is an older variant.
- **BPF filter:** the Berkeley Packet Filter expression syntax (`host x.x.x.x`, `port 53`, `tcp`) that `tcpdump` uses to slice a capture down to what you care about.
- **5-tuple:** the five fields that identify a network conversation — source IP, source port, destination IP, destination port, protocol.
- **NetFlow / flow:** a summary record of a conversation (the 5-tuple + byte/packet counts + start/end time) instead of every packet — the fast way to see top talkers and beacon timing. Built here with `nfpcapd` and read with `nfdump`.
- **beacon / beaconing:** an implant's regular check-in to its controller — a small, fixed-interval connection. The cadence is the tell.
- **C2 (command and control):** the channel an attacker uses to send commands to and receive data from an implant.
- **jitter:** random variation added to a beacon's sleep interval so the check-ins aren't perfectly even (anti-detection).
- **DNS tunneling:** smuggling C2 traffic or stolen data inside DNS queries/answers (long, unique, encoded subdomains) to bypass egress controls.
- **DGA (domain generation algorithm):** malware that computes many random-looking domain names to find its live C2 — DGA domains look like gibberish.
- **SNI (Server Name Indication):** the hostname a TLS client asks for, sent in the clear during the handshake — readable even on an encrypted channel.
- **JA3 / JA3-style:** a fingerprint computed from the fields/order of a TLS ClientHello, used to identify the client software (incl. malware) without decrypting. No JA3 tool is on this box — any JA3-style claim here is by-hand and `⚠️verify`.
- **stream reassembly:** stitching the packets of one TCP conversation back into the byte stream that actually crossed (the file/commands), done here with `tcpflow`/`tcpick`.
- **carving (from pcap):** recovering whole files (by their header/footer signatures) out of packet payloads, done with `tcpxtract`/`bulk_extractor`.
- **plaintext credentials:** usernames/passwords sent without encryption (FTP, Telnet, HTTP Basic, legacy mail auth) — readable straight off the wire.
- **NTLMSSP:** the Windows NTLM authentication exchange seen on the wire (e.g. inside SMB) — its presence on a lateral session is a credential-use marker.
- **SMB / RDP / WinRM:** Windows file-share (445/139), Remote Desktop (3389), and remote-management (5985/5986) protocols — the usual lateral-movement channels.
- **p0f / passive OS fingerprinting:** identifying an endpoint's operating system from the shape of its TCP handshake, without sending it anything.
- **exfiltration:** stealing data out of the network — seen as a large outbound transfer and/or a file carvable from the upload.

## Tuning log (append-only — the eval loop writes here; humans never edit rows)
| date | case_id | bucket missed | delta applied |
|---|---|---|---|
